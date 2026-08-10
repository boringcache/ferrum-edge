use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use ferrum_edge::proxy::netns_capture::{
    DirectoryCaptureSource, PodCaptureSource, PodCaptureSourceIps, PodCaptureTarget,
};
use ferrum_edge::proxy::netns_udp_capture::{NetnsUdpCleanupBackend, NetnsUdpCleanupManager};
use ferrum_edge::proxy::udp_placement_migration::{
    UdpMigrationFailureReason, UdpMigrationPhase, UdpPlacement, UdpPlacementDecision,
    UdpPlacementRequest, clear_registry_sync_marker, prepare_placement,
    publish_registry_sync_marker_for_pods,
};

struct MutableSource(Mutex<Vec<PodCaptureTarget>>);

impl PodCaptureSource for MutableSource {
    fn list_targets(&self) -> Vec<PodCaptureTarget> {
        self.0.lock().expect("source lock").clone()
    }
}

struct PartialCleanupBackend {
    fail_once: Mutex<HashSet<u64>>,
    cleaned: Mutex<Vec<u64>>,
}

impl NetnsUdpCleanupBackend for PartialCleanupBackend {
    fn netns_key(&self, target: &PodCaptureTarget) -> Result<u64, String> {
        target
            .cgroup_path
            .trim_start_matches("/cg/")
            .parse()
            .map_err(|_| "fixture netns is invalid".to_string())
    }

    fn cleanup_udp_capture(&self, _target: &PodCaptureTarget, expected_netns: u64) -> bool {
        if self
            .fail_once
            .lock()
            .expect("failure lock")
            .remove(&expected_netns)
        {
            return false;
        }
        self.cleaned
            .lock()
            .expect("cleaned lock")
            .push(expected_netns);
        true
    }
}

fn pod_target(uid: &str, netns: u64) -> PodCaptureTarget {
    PodCaptureTarget {
        pod_uid: uid.to_string(),
        cgroup_path: format!("/cg/{netns}"),
        source_identity: None,
        source_ips: PodCaptureSourceIps::default(),
    }
}

fn stable(target: UdpPlacement) -> UdpPlacementRequest {
    UdpPlacementRequest {
        phase: UdpMigrationPhase::Stable,
        target,
        generation: None,
        from: None,
        to: None,
    }
}

fn transition(
    phase: UdpMigrationPhase,
    generation: &str,
    from: UdpPlacement,
    to: UdpPlacement,
) -> UdpPlacementRequest {
    UdpPlacementRequest {
        phase,
        target: to,
        generation: Some(generation.to_string()),
        from: Some(from),
        to: Some(to),
    }
}

fn cleanup_context(
    registry: &std::path::Path,
    request: &UdpPlacementRequest,
) -> ferrum_edge::proxy::udp_placement_migration::UdpMigrationContext {
    match prepare_placement(registry, request).expect("cleanup phase is admitted") {
        UdpPlacementDecision::RunCleanup(context) => context,
        UdpPlacementDecision::RunStable => panic!("cleanup must not run a producer"),
    }
}

#[test]
fn direct_pod_to_host_flip_is_rejected_before_host_producer_admission() {
    let registry = tempfile::tempdir().expect("registry");
    assert!(matches!(
        prepare_placement(registry.path(), &stable(UdpPlacement::PodNetns)),
        Ok(UdpPlacementDecision::RunStable)
    ));

    let error = prepare_placement(registry.path(), &stable(UdpPlacement::HostNetns))
        .err()
        .expect("unsafe direct flip must fail");
    assert!(error.contains("unsafe one-step"));
}

#[test]
fn legacy_or_fresh_host_placement_requires_explicit_cleanup_proof() {
    let registry = tempfile::tempdir().expect("registry");
    let error = prepare_placement(registry.path(), &stable(UdpPlacement::HostNetns))
        .err()
        .expect("host bootstrap without predecessor proof must fail");
    assert!(error.contains("no durable predecessor proof"));
}

#[test]
fn pod_to_host_cleanup_resumes_and_finalize_requires_durable_completion() {
    let registry = tempfile::tempdir().expect("registry");
    prepare_placement(registry.path(), &stable(UdpPlacement::PodNetns))
        .expect("pod placement bootstrap");
    let cleanup = transition(
        UdpMigrationPhase::Cleanup,
        "rollout-42",
        UdpPlacement::PodNetns,
        UdpPlacement::HostNetns,
    );
    let first = cleanup_context(registry.path(), &cleanup);
    let resumed = cleanup_context(registry.path(), &cleanup);
    assert_eq!(first.generation(), resumed.generation());

    let finalize = transition(
        UdpMigrationPhase::Finalize,
        "rollout-42",
        UdpPlacement::PodNetns,
        UdpPlacement::HostNetns,
    );
    assert!(prepare_placement(registry.path(), &finalize).is_err());
    resumed
        .mark_cleanup_complete()
        .expect("publish cleanup proof");
    let completed_restart = cleanup_context(registry.path(), &cleanup);
    assert_eq!(completed_restart.generation(), "rollout-42");
    assert!(matches!(
        prepare_placement(registry.path(), &finalize),
        Ok(UdpPlacementDecision::RunStable)
    ));
    assert!(matches!(
        prepare_placement(registry.path(), &finalize),
        Ok(UdpPlacementDecision::RunStable)
    ));
    assert!(matches!(
        prepare_placement(registry.path(), &stable(UdpPlacement::HostNetns)),
        Ok(UdpPlacementDecision::RunStable)
    ));
}

#[test]
fn crash_leftover_temporary_files_do_not_block_exact_tuple_resume() {
    let registry = tempfile::tempdir().expect("registry");
    prepare_placement(registry.path(), &stable(UdpPlacement::PodNetns))
        .expect("bootstrap placement");
    std::fs::write(
        registry
            .path()
            .join(".udp-placement-state-v1.json.tmp.crashed"),
        b"incomplete",
    )
    .expect("crash leftover");
    let cleanup = transition(
        UdpMigrationPhase::Cleanup,
        "crash-resume",
        UdpPlacement::PodNetns,
        UdpPlacement::HostNetns,
    );
    let context = cleanup_context(registry.path(), &cleanup);
    assert_eq!(context.generation(), "crash-resume");
    assert!(context.cleanup_pod_netns());
    assert!(!context.cleanup_host_netns());
}

#[test]
fn malformed_or_non_regular_durable_state_fails_closed() {
    let registry = tempfile::tempdir().expect("registry");
    std::fs::create_dir(registry.path().join(".udp-placement-state-v1.json"))
        .expect("non-regular state fixture");
    let error = prepare_placement(registry.path(), &stable(UdpPlacement::PodNetns))
        .err()
        .expect("non-regular state must not be guessed");
    assert!(error.contains("securely open"));
}

#[test]
fn pre_contract_cleanup_retires_both_domains_and_persists_that_scope() {
    let registry = tempfile::tempdir().expect("registry");
    let cleanup = transition(
        UdpMigrationPhase::Cleanup,
        "legacy-host-pod",
        UdpPlacement::HostNetns,
        UdpPlacement::PodNetns,
    );
    let first = cleanup_context(registry.path(), &cleanup);
    assert!(first.cleanup_pod_netns());
    assert!(first.cleanup_host_netns());
    let resumed = cleanup_context(registry.path(), &cleanup);
    assert!(resumed.cleanup_pod_netns());
    assert!(resumed.cleanup_host_netns());
}

#[test]
fn host_to_pod_cleanup_and_finalize_are_symmetric() {
    let registry = tempfile::tempdir().expect("registry");
    let bootstrap_cleanup = transition(
        UdpMigrationPhase::Cleanup,
        "host-bootstrap",
        UdpPlacement::PodNetns,
        UdpPlacement::HostNetns,
    );
    let context = cleanup_context(registry.path(), &bootstrap_cleanup);
    context
        .mark_cleanup_complete()
        .expect("host bootstrap proof");
    prepare_placement(
        registry.path(),
        &transition(
            UdpMigrationPhase::Finalize,
            "host-bootstrap",
            UdpPlacement::PodNetns,
            UdpPlacement::HostNetns,
        ),
    )
    .expect("host bootstrap finalize");

    let reverse = transition(
        UdpMigrationPhase::Cleanup,
        "reverse-7",
        UdpPlacement::HostNetns,
        UdpPlacement::PodNetns,
    );
    let context = cleanup_context(registry.path(), &reverse);
    assert!(prepare_placement(registry.path(), &stable(UdpPlacement::PodNetns)).is_err());
    context.mark_cleanup_complete().expect("host cleanup proof");
    prepare_placement(
        registry.path(),
        &transition(
            UdpMigrationPhase::Finalize,
            "reverse-7",
            UdpPlacement::HostNetns,
            UdpPlacement::PodNetns,
        ),
    )
    .expect("reverse finalize");
}

#[test]
fn enabled_disabled_transitions_also_require_cleanup_and_finalize() {
    for (from, to, generation) in [
        (
            UdpPlacement::PodNetns,
            UdpPlacement::Disabled,
            "disable-pod",
        ),
        (
            UdpPlacement::Disabled,
            UdpPlacement::HostNetns,
            "enable-host",
        ),
        (
            UdpPlacement::HostNetns,
            UdpPlacement::Disabled,
            "disable-host",
        ),
        (UdpPlacement::Disabled, UdpPlacement::PodNetns, "enable-pod"),
    ] {
        let registry = tempfile::tempdir().expect("registry");
        if from == UdpPlacement::HostNetns {
            let bootstrap = cleanup_context(
                registry.path(),
                &transition(
                    UdpMigrationPhase::Cleanup,
                    "bootstrap-host",
                    UdpPlacement::PodNetns,
                    UdpPlacement::HostNetns,
                ),
            );
            bootstrap.mark_cleanup_complete().expect("bootstrap proof");
            prepare_placement(
                registry.path(),
                &transition(
                    UdpMigrationPhase::Finalize,
                    "bootstrap-host",
                    UdpPlacement::PodNetns,
                    UdpPlacement::HostNetns,
                ),
            )
            .expect("bootstrap finalize");
        } else {
            prepare_placement(registry.path(), &stable(from)).expect("bootstrap placement");
        }
        assert!(prepare_placement(registry.path(), &stable(to)).is_err());
        let context = cleanup_context(
            registry.path(),
            &transition(UdpMigrationPhase::Cleanup, generation, from, to),
        );
        context.mark_cleanup_complete().expect("cleanup proof");
        prepare_placement(
            registry.path(),
            &transition(UdpMigrationPhase::Finalize, generation, from, to),
        )
        .expect("finalize transition");
        assert!(matches!(
            prepare_placement(registry.path(), &stable(to)),
            Ok(UdpPlacementDecision::RunStable)
        ));
    }
}

#[test]
fn interrupted_cleanup_rejects_stale_generation_and_predecessor() {
    let registry = tempfile::tempdir().expect("registry");
    prepare_placement(registry.path(), &stable(UdpPlacement::PodNetns))
        .expect("bootstrap placement");
    cleanup_context(
        registry.path(),
        &transition(
            UdpMigrationPhase::Cleanup,
            "owned-generation",
            UdpPlacement::PodNetns,
            UdpPlacement::HostNetns,
        ),
    );
    assert!(
        prepare_placement(
            registry.path(),
            &transition(
                UdpMigrationPhase::Cleanup,
                "stale-generation",
                UdpPlacement::PodNetns,
                UdpPlacement::HostNetns,
            ),
        )
        .is_err()
    );
    assert!(
        prepare_placement(
            registry.path(),
            &transition(
                UdpMigrationPhase::Finalize,
                "owned-generation",
                UdpPlacement::HostNetns,
                UdpPlacement::PodNetns,
            ),
        )
        .is_err()
    );
}

#[test]
fn registry_relist_ack_is_bound_to_generation_and_retracted_on_restart() {
    let registry = tempfile::tempdir().expect("registry");
    let context = cleanup_context(
        registry.path(),
        &transition(
            UdpMigrationPhase::Cleanup,
            "generation-a",
            UdpPlacement::PodNetns,
            UdpPlacement::HostNetns,
        ),
    );
    assert!(!context.registry_is_synchronized());
    assert_eq!(
        publish_registry_sync_marker_for_pods(registry.path(), "generation-b", &HashSet::new(),),
        Ok(true)
    );
    assert!(!context.registry_is_synchronized());
    assert_eq!(
        publish_registry_sync_marker_for_pods(registry.path(), "generation-a", &HashSet::new(),),
        Ok(true)
    );
    assert!(context.registry_is_synchronized());
    clear_registry_sync_marker(registry.path()).expect("restart retraction");
    assert!(!context.registry_is_synchronized());
}

#[test]
fn registry_relist_ack_requires_every_expected_pod_entry() {
    let registry = tempfile::tempdir().expect("registry");
    let expected = HashSet::from(["pod-a".to_string(), "pod-b".to_string()]);
    std::fs::write(registry.path().join("pod-a"), b"/cg/1\n").expect("first pod entry");
    assert_eq!(
        publish_registry_sync_marker_for_pods(registry.path(), "generation-a", &expected),
        Ok(false)
    );
    assert!(!registry.path().join(".udp-registry-synced").exists());

    std::fs::write(registry.path().join("pod-b"), b"/cg/2\n").expect("second pod entry");
    assert_eq!(
        publish_registry_sync_marker_for_pods(registry.path(), "generation-a", &expected),
        Ok(true)
    );
    assert!(registry.path().join(".udp-registry-synced").is_file());
}

#[tokio::test]
async fn partial_pod_cleanup_retries_and_pod_churn_invalidates_completion_snapshot() {
    let source = Arc::new(MutableSource(Mutex::new(vec![
        pod_target("pod-a", 1),
        pod_target("pod-b", 2),
    ])));
    let backend = PartialCleanupBackend {
        fail_once: Mutex::new(HashSet::from([2])),
        cleaned: Mutex::new(Vec::new()),
    };
    let mut manager =
        NetnsUdpCleanupManager::new(source.clone(), backend, std::time::Duration::from_secs(2));

    let partial = manager.migration_cleanup_once().await;
    assert_eq!(partial.outstanding, 1);
    assert_eq!(
        partial.failure_reason,
        Some(UdpMigrationFailureReason::PodCleanupFailed)
    );
    let complete = manager.migration_cleanup_once().await;
    assert_eq!(complete.outstanding, 0);
    assert_eq!(complete.failure_reason, None);

    source
        .0
        .lock()
        .expect("source lock")
        .push(pod_target("pod-c", 3));
    let churned = manager.migration_cleanup_once().await;
    assert_eq!(churned.outstanding, 0);
    assert_ne!(
        churned.registry_fingerprint, complete.registry_fingerprint,
        "the supervisor's repeated-pass proof must restart when a pod appears"
    );
}

#[tokio::test]
async fn malformed_registry_entry_blocks_migration_cleanup_proof() {
    let registry = tempfile::tempdir().expect("registry");
    std::fs::write(registry.path().join("pod-a"), b"").expect("malformed entry");
    let source = DirectoryCaptureSource::new(registry.path());
    assert!(source.list_targets().is_empty());
    assert!(source.list_targets_for_migration().is_err());
    let source = Arc::new(source);
    let backend = PartialCleanupBackend {
        fail_once: Mutex::new(HashSet::new()),
        cleaned: Mutex::new(Vec::new()),
    };
    let mut manager =
        NetnsUdpCleanupManager::new(source, backend, std::time::Duration::from_secs(2));

    let blocked = manager.migration_cleanup_once().await;
    assert_eq!(blocked.outstanding, 1);
    assert_eq!(
        blocked.failure_reason,
        Some(UdpMigrationFailureReason::RegistryNotSynchronized)
    );
    std::fs::write(registry.path().join("pod-a"), b"/cg/1\n").expect("repaired entry");
    let complete = manager.migration_cleanup_once().await;
    assert_eq!(complete.outstanding, 0);
    assert_eq!(complete.failure_reason, None);
}

#[tokio::test]
async fn stale_gate_ack_cannot_authorize_migration_cleanup() {
    let source = Arc::new(MutableSource(Mutex::new(vec![pod_target("pod-a", 1)])));
    let backend = PartialCleanupBackend {
        fail_once: Mutex::new(HashSet::new()),
        cleaned: Mutex::new(Vec::new()),
    };
    let registry = tempfile::tempdir().expect("registry");
    let ready_dir = registry.path().join(".udp-ready");
    let ack_dir = registry.path().join(".udp-not-ready");
    std::fs::create_dir_all(&ready_dir).expect("ready dir");
    std::fs::create_dir_all(&ack_dir).expect("ack dir");
    std::fs::write(ready_dir.join("pod-a"), b"").expect("ready marker");
    std::fs::write(ack_dir.join("pod-a"), b"stale").expect("stale ack");
    let mut manager =
        NetnsUdpCleanupManager::new(source, backend, std::time::Duration::from_secs(2))
            .with_ready_dir(Some(ready_dir));

    let blocked = manager.migration_cleanup_once().await;
    assert_eq!(blocked.outstanding, 1);
    assert_eq!(
        blocked.failure_reason,
        Some(UdpMigrationFailureReason::GateAcknowledgementMissing)
    );
    assert!(!ack_dir.join("pod-a").exists());
    std::fs::write(ack_dir.join("pod-a"), b"").expect("fresh ack");
    let complete = manager.migration_cleanup_once().await;
    assert_eq!(complete.outstanding, 0);
    assert_eq!(complete.failure_reason, None);
}
