use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use ferrum_edge::proxy::netns_capture::{
    DirectoryCaptureSource, PodCaptureSource, PodCaptureSourceIps, PodCaptureTarget,
};
use ferrum_edge::proxy::netns_udp_capture::{NetnsUdpCleanupBackend, NetnsUdpCleanupManager};
use ferrum_edge::proxy::udp_placement_migration::{
    UdpAdoptionProof, UdpCleanupProofWindow, UdpMigrationFailureReason, UdpMigrationPhase,
    UdpNodeIdentity, UdpPlacement, UdpPlacementDecision, UdpPlacementRequest, UdpRegistrySyncProof,
    clear_registry_sync_marker, prepare_placement, publish_node_identity_for,
    publish_registry_sync_marker_for_pods, retract_node_identity,
};

/// Node identity is supplied EXPLICITLY in these tests rather than resolved
/// from the process environment, so every proof assertion is deterministic and
/// no test can race another over a shared env var or `/proc` read.
const NODE_A: &str = "11111111-1111-4111-8111-111111111111";
const NODE_B: &str = "22222222-2222-4222-8222-222222222222";
const BOOT_1: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const BOOT_2: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const PROOF_GENERATION: &str = "host-netns-stable";

fn identity(node_uid: &str, boot_id: &str) -> UdpNodeIdentity {
    UdpNodeIdentity::new(node_uid, boot_id).expect("valid node identity")
}

/// Write the node-scoped attestation the privileged preflight publishes. The
/// preflight itself needs a live pod-netns/iptables environment, so these
/// deterministic tests exercise the RUNTIME BOUNDARY that consumes the artifact
/// with the exact on-disk shape the preflight writes.
fn write_node_attestation(
    registry: &std::path::Path,
    file: &str,
    node: &UdpNodeIdentity,
    target: UdpPlacement,
    generation: &str,
) {
    let document = serde_json::json!({
        "version": 1,
        "node": {"node_uid": node.node_uid, "boot_id": node.boot_id},
        "target": target.as_str(),
        "generation": generation,
    });
    std::fs::write(
        registry.join(file),
        serde_json::to_vec(&document).expect("encode attestation"),
    )
    .expect("write attestation");
}

fn age_crash_temp(path: &std::path::Path) {
    let old = std::time::SystemTime::now()
        .checked_sub(std::time::Duration::from_secs(2 * 60 * 60))
        .expect("old timestamp");
    std::fs::File::options()
        .write(true)
        .open(path)
        .expect("open crash temp")
        .set_times(std::fs::FileTimes::new().set_modified(old))
        .expect("age crash temp");
}

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
        established: None,
        node: None,
        node_proof_generation: None,
    }
}

/// A release-level attestation with NO node-specific provenance. This is the
/// shape a bare `FERRUM_MESH_CAPTURE_UDP_PLACEMENT_ESTABLISHED=<target>` from a
/// client-render pipeline produces, and it must authorize nothing.
fn stable_attested(target: UdpPlacement, established: UdpPlacement) -> UdpPlacementRequest {
    UdpPlacementRequest {
        established: Some(established),
        ..stable(target)
    }
}

/// The Helm/GitOps-equivalent shape: release desired state PLUS this node's
/// identity and the release's node-proof generation.
fn stable_attested_on_node(
    target: UdpPlacement,
    established: UdpPlacement,
    node: &UdpNodeIdentity,
) -> UdpPlacementRequest {
    UdpPlacementRequest {
        node: Some(node.clone()),
        node_proof_generation: Some(PROOF_GENERATION.to_string()),
        ..stable_attested(target, established)
    }
}

fn stable_on_node(target: UdpPlacement, node: &UdpNodeIdentity) -> UdpPlacementRequest {
    UdpPlacementRequest {
        node: Some(node.clone()),
        node_proof_generation: Some(PROOF_GENERATION.to_string()),
        ..stable(target)
    }
}

/// Attach this node's identity to any request, exactly as the runtime does once
/// `FERRUM_K8S_NODE_UID` or the node-agent's published identity is resolvable.
/// A record that was written WITH an identity may only be read back by a
/// process that can still resolve one, so every migration phase acting on such
/// a record carries this.
fn on_node(request: UdpPlacementRequest, node: &UdpNodeIdentity) -> UdpPlacementRequest {
    UdpPlacementRequest {
        node: Some(node.clone()),
        node_proof_generation: Some(PROOF_GENERATION.to_string()),
        ..request
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
        established: None,
        node: None,
        node_proof_generation: None,
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

fn publish_registry_proof(
    context: &ferrum_edge::proxy::udp_placement_migration::UdpMigrationContext,
) -> UdpRegistrySyncProof {
    assert_eq!(
        publish_registry_sync_marker_for_pods(
            context.registry_dir(),
            context.generation(),
            &HashSet::new(),
        ),
        Ok(true)
    );
    context
        .registry_sync_proof()
        .expect("current registry publication proof")
}

fn complete_cleanup(context: &ferrum_edge::proxy::udp_placement_migration::UdpMigrationContext) {
    let proof = publish_registry_proof(context);
    context
        .mark_cleanup_complete(&proof)
        .expect("publish cleanup proof");
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
fn a_release_only_attestation_never_admits_a_recordless_same_boot_node() {
    // The pre-contract node from issue #3809: it stayed booted with live
    // workloads whose pod netns still redirect UDP to the retired predecessor
    // listener, and it missed both migration releases. The release ConfigMap
    // names no node, no incarnation, and no per-node cleanup result, so it
    // looks exactly like a rebooted node — and must authorize nothing.
    let registry = tempfile::tempdir().expect("registry");
    let error = prepare_placement(
        registry.path(),
        &stable_attested(UdpPlacement::HostNetns, UdpPlacement::HostNetns),
    )
    .err()
    .expect("release-only attestation must not admit a recordless node");
    assert!(error.contains("no node identity"), "{error}");
    assert_eq!(
        ferrum_edge::proxy::udp_placement_migration::snapshot().failure_reason,
        UdpMigrationFailureReason::NodeProofMissing
    );

    // Supplying node identity is still not proof: nothing on this node attests
    // that predecessor state was retired here.
    let node = identity(NODE_A, BOOT_1);
    let error = prepare_placement(
        registry.path(),
        &stable_attested_on_node(UdpPlacement::HostNetns, UdpPlacement::HostNetns, &node),
    )
    .err()
    .expect("a node with no cleanup attestation must be refused");
    assert!(
        error.contains("no node-specific cleanup attestation"),
        "{error}"
    );
    assert_eq!(
        ferrum_edge::proxy::udp_placement_migration::snapshot().failure_reason,
        UdpMigrationFailureReason::MigrationRequired
    );
    // Nothing was written, so the refusal is repeatable rather than a one-shot
    // that a restart could walk past.
    assert!(
        !registry
            .path()
            .join(".udp-placement-state-v1.json")
            .exists()
    );
}

#[test]
fn explicit_node_cleanup_proof_permits_the_host_placement() {
    let registry = tempfile::tempdir().expect("registry");
    let node = identity(NODE_A, BOOT_1);
    write_node_attestation(
        registry.path(),
        ".udp-node-cleanup-proof-v1.json",
        &node,
        UdpPlacement::HostNetns,
        PROOF_GENERATION,
    );
    assert!(matches!(
        prepare_placement(
            registry.path(),
            &stable_attested_on_node(UdpPlacement::HostNetns, UdpPlacement::HostNetns, &node),
        ),
        Ok(UdpPlacementDecision::RunStable)
    ));
    let snapshot = ferrum_edge::proxy::udp_placement_migration::snapshot();
    assert_eq!(snapshot.adoption_proof, UdpAdoptionProof::NodeCleanup);
    assert!(snapshot.established_adoption);
    // The adoption is durable: a later restart resumes its own record.
    assert!(matches!(
        prepare_placement(
            registry.path(),
            &stable_on_node(UdpPlacement::HostNetns, &node)
        ),
        Ok(UdpPlacementDecision::RunStable)
    ));
}

#[test]
fn an_operator_exemption_is_node_bound_and_distinguishes_a_decommissioned_node() {
    let registry = tempfile::tempdir().expect("registry");
    let node = identity(NODE_A, BOOT_1);
    write_node_attestation(
        registry.path(),
        ".udp-placement-node-exempt",
        &node,
        UdpPlacement::HostNetns,
        PROOF_GENERATION,
    );
    assert!(matches!(
        prepare_placement(
            registry.path(),
            &stable_attested_on_node(UdpPlacement::HostNetns, UdpPlacement::HostNetns, &node),
        ),
        Ok(UdpPlacementDecision::RunStable)
    ));
    assert_eq!(
        ferrum_edge::proxy::udp_placement_migration::snapshot().adoption_proof,
        UdpAdoptionProof::OperatorExempt
    );
}

#[test]
fn the_same_node_uid_after_a_reboot_adopts_but_a_reused_node_name_cannot() {
    // A persistent registry path keeps the durable record across a reboot. A
    // changed boot id proves every predecessor pod netns died with the previous
    // incarnation, so adoption is sound and is reported as `new_boot`.
    let registry = tempfile::tempdir().expect("registry");
    let first_boot = identity(NODE_A, BOOT_1);
    write_node_attestation(
        registry.path(),
        ".udp-node-cleanup-proof-v1.json",
        &first_boot,
        UdpPlacement::HostNetns,
        PROOF_GENERATION,
    );
    prepare_placement(
        registry.path(),
        &stable_attested_on_node(
            UdpPlacement::HostNetns,
            UdpPlacement::HostNetns,
            &first_boot,
        ),
    )
    .expect("first-boot adoption");

    let second_boot = identity(NODE_A, BOOT_2);
    assert!(matches!(
        prepare_placement(
            registry.path(),
            &stable_on_node(UdpPlacement::HostNetns, &second_boot),
        ),
        Ok(UdpPlacementDecision::RunStable)
    ));
    assert_eq!(
        ferrum_edge::proxy::udp_placement_migration::snapshot().adoption_proof,
        UdpAdoptionProof::NewBoot
    );

    // The SAME node name rebuilt as a different machine carries a different
    // Kubernetes node UID and can never inherit that record.
    let other_machine = identity(NODE_B, BOOT_2);
    let error = prepare_placement(
        registry.path(),
        &stable_on_node(UdpPlacement::HostNetns, &other_machine),
    )
    .err()
    .expect("a different node UID must not inherit durable ownership");
    assert!(error.contains("different Kubernetes node UID"), "{error}");
    assert_eq!(
        ferrum_edge::proxy::udp_placement_migration::snapshot().failure_reason,
        UdpMigrationFailureReason::NodeIdentityMismatch
    );
}

#[test]
fn an_identity_bound_record_fails_closed_when_current_node_identity_is_unknown() {
    // The node-UID comparison is a boundary only while BOTH sides exist. If the
    // node-agent loses `nodes: get` (or the API server is unreachable) and no
    // FERRUM_K8S_NODE_UID was supplied, a restored/reused registry directory
    // carrying an identity-bound record would otherwise be trusted verbatim —
    // exactly the node-name-reuse inheritance the binding exists to refuse.
    let registry = tempfile::tempdir().expect("registry");
    let node = identity(NODE_A, BOOT_1);
    write_node_attestation(
        registry.path(),
        ".udp-node-cleanup-proof-v1.json",
        &node,
        UdpPlacement::HostNetns,
        PROOF_GENERATION,
    );
    prepare_placement(
        registry.path(),
        &stable_attested_on_node(UdpPlacement::HostNetns, UdpPlacement::HostNetns, &node),
    )
    .expect("identity-bound adoption");

    // Every phase refuses, including the migration phases that would otherwise
    // adopt the record as a predecessor claim.
    for request in [
        stable(UdpPlacement::HostNetns),
        stable_attested(UdpPlacement::HostNetns, UdpPlacement::HostNetns),
        transition(
            UdpMigrationPhase::Cleanup,
            "unresolved-1",
            UdpPlacement::HostNetns,
            UdpPlacement::PodNetns,
        ),
        transition(
            UdpMigrationPhase::Finalize,
            "unresolved-1",
            UdpPlacement::HostNetns,
            UdpPlacement::PodNetns,
        ),
    ] {
        let error = prepare_placement(registry.path(), &request)
            .err()
            .expect("an identity-bound record must not be trusted without current identity");
        assert!(
            error.contains("current identity could not be resolved"),
            "{error}"
        );
        assert_eq!(
            ferrum_edge::proxy::udp_placement_migration::snapshot().failure_reason,
            UdpMigrationFailureReason::NodeIdentityUnresolved
        );
    }

    // A foreign node UID stays the harder mismatch refusal in every phase.
    let other_machine = identity(NODE_B, BOOT_1);
    for request in [
        stable_on_node(UdpPlacement::HostNetns, &other_machine),
        on_node(
            transition(
                UdpMigrationPhase::Cleanup,
                "unresolved-1",
                UdpPlacement::HostNetns,
                UdpPlacement::PodNetns,
            ),
            &other_machine,
        ),
        on_node(
            transition(
                UdpMigrationPhase::Finalize,
                "unresolved-1",
                UdpPlacement::HostNetns,
                UdpPlacement::PodNetns,
            ),
            &other_machine,
        ),
    ] {
        let error = prepare_placement(registry.path(), &request)
            .err()
            .expect("a foreign node UID must never inherit durable ownership");
        assert!(error.contains("different Kubernetes node UID"), "{error}");
        assert_eq!(
            ferrum_edge::proxy::udp_placement_migration::snapshot().failure_reason,
            UdpMigrationFailureReason::NodeIdentityMismatch
        );
    }

    // No refusal mutated anything: the owning node still resumes its record.
    assert!(matches!(
        prepare_placement(
            registry.path(),
            &stable_on_node(UdpPlacement::HostNetns, &node)
        ),
        Ok(UdpPlacementDecision::RunStable)
    ));
}

#[test]
fn an_unbound_durable_record_never_adopts_a_producer_placement() {
    // A durable record naming NO owning node UID proves nothing about which
    // machine established the placement it describes. That is the shape a
    // pre-#3809 record has, and also the shape a registry directory copied
    // between machines or reattached under a recycled node name presents — so
    // it must not start a producer merely by existing, with or without a
    // resolvable current identity (a missing identity is not a way past it).
    for node in [None, Some(identity(NODE_A, BOOT_1))] {
        let registry = tempfile::tempdir().expect("registry");
        write_unbound_state(registry.path(), UdpPlacement::PodNetns);
        let request = UdpPlacementRequest {
            node: node.clone(),
            node_proof_generation: node.as_ref().map(|_| PROOF_GENERATION.to_string()),
            ..stable(UdpPlacement::PodNetns)
        };
        let error = prepare_placement(registry.path(), &request)
            .err()
            .expect("unbound durable ownership must not adopt a producer");
        assert!(error.contains("names no owning Kubernetes node UID"), "{error}");
        assert!(error.contains("cleanup then finalize"), "{error}");
    }

    // `disabled` owns no producer and carries no traffic, so it is the one
    // placement an unbound record may still carry — and the first start that
    // CAN resolve an identity binds it, so the boundary applies from then on.
    let registry = tempfile::tempdir().expect("registry");
    write_unbound_state(registry.path(), UdpPlacement::Disabled);
    assert!(matches!(
        prepare_placement(registry.path(), &stable(UdpPlacement::Disabled)),
        Ok(UdpPlacementDecision::RunStable)
    ));
    let node = identity(NODE_A, BOOT_1);
    assert!(matches!(
        prepare_placement(
            registry.path(),
            &stable_on_node(UdpPlacement::Disabled, &node)
        ),
        Ok(UdpPlacementDecision::RunStable)
    ));
    let error = prepare_placement(registry.path(), &stable(UdpPlacement::Disabled))
        .err()
        .expect("the bound record is identity-bound from here on");
    assert!(
        error.contains("current identity could not be resolved"),
        "{error}"
    );
}

#[test]
fn unbound_durable_ownership_recovers_only_through_cleanup_and_finalize() {
    // The supported recovery: an explicit cleanup migration retires the exact
    // Ferrum-owned predecessor state on this node, and finalize binds this
    // node's identity to the record it leaves behind. Only then does the
    // placement start.
    let registry = tempfile::tempdir().expect("registry");
    write_unbound_state(registry.path(), UdpPlacement::PodNetns);
    let node = identity(NODE_A, BOOT_1);

    let cleanup = on_node(
        transition(
            UdpMigrationPhase::Cleanup,
            "unbound-recovery",
            UdpPlacement::PodNetns,
            UdpPlacement::HostNetns,
        ),
        &node,
    );
    let context = cleanup_context(registry.path(), &cleanup);
    complete_cleanup(&context);
    assert!(matches!(
        prepare_placement(
            registry.path(),
            &on_node(
                transition(
                    UdpMigrationPhase::Finalize,
                    "unbound-recovery",
                    UdpPlacement::PodNetns,
                    UdpPlacement::HostNetns,
                ),
                &node,
            ),
        ),
        Ok(UdpPlacementDecision::RunStable)
    ));

    // The recovered record is this node's own ownership from here on: it starts
    // without any node attestation, and it is refused for any other node.
    assert!(matches!(
        prepare_placement(
            registry.path(),
            &stable_on_node(UdpPlacement::HostNetns, &node)
        ),
        Ok(UdpPlacementDecision::RunStable)
    ));
    let error = prepare_placement(
        registry.path(),
        &stable_on_node(UdpPlacement::HostNetns, &identity(NODE_B, BOOT_1)),
    )
    .err()
    .expect("the recovered record is bound to the node that proved the cleanup");
    assert!(error.contains("different Kubernetes node UID"), "{error}");
}

/// The exact on-disk shape of ownership that names no node: a pre-#3809 record,
/// a restored backup, or a registry directory reattached under a reused node
/// name. Written directly so the refusal is decided by the record's CONTENT and
/// never by how this process happened to create it.
fn write_unbound_state(registry: &std::path::Path, active: UdpPlacement) {
    let document = serde_json::json!({
        "version": 1,
        "active": active.as_str(),
        "pending": null,
        "completed": null,
    });
    std::fs::write(
        registry.join(".udp-placement-state-v1.json"),
        serde_json::to_vec(&document).expect("encode durable state"),
    )
    .expect("write unbound durable state");
}

#[test]
fn a_stale_same_boot_node_identity_publication_would_inherit_the_predecessor_proof() {
    // The hazard the retraction closes, stated as a live fact: a publication
    // left by a PREVIOUS Kubernetes Node object on this same boot resolves —
    // its boot id IS the current incarnation's — and its UID matches the
    // predecessor's node-cleanup proof, so the host producer starts.
    let registry = tempfile::tempdir().expect("registry");
    let predecessor = identity(NODE_A, BOOT_1);
    publish_node_identity_for(registry.path(), &predecessor).expect("predecessor publication");
    write_node_attestation(
        registry.path(),
        ".udp-node-cleanup-proof-v1.json",
        &predecessor,
        UdpPlacement::HostNetns,
        PROOF_GENERATION,
    );

    let resolved = UdpNodeIdentity::resolve_published(registry.path(), BOOT_1);
    assert_eq!(resolved.as_ref(), Some(&predecessor));
    let request = UdpPlacementRequest {
        node: resolved,
        node_proof_generation: Some(PROOF_GENERATION.to_string()),
        ..stable_attested(UdpPlacement::HostNetns, UdpPlacement::HostNetns)
    };
    assert!(matches!(
        prepare_placement(registry.path(), &request),
        Ok(UdpPlacementDecision::RunStable)
    ));
}

#[test]
fn retracting_the_publication_leaves_no_stale_identity_authorizing_adoption() {
    // The publisher retracts BEFORE anything that can fail, and again after a
    // failure, so a lookup/publication failure leaves NO identity rather than
    // the predecessor Node object's UID.
    let registry = tempfile::tempdir().expect("registry");
    let predecessor = identity(NODE_A, BOOT_1);
    let identity_file = registry.path().join(".node-identity-v1.json");
    publish_node_identity_for(registry.path(), &predecessor).expect("predecessor publication");
    write_node_attestation(
        registry.path(),
        ".udp-node-cleanup-proof-v1.json",
        &predecessor,
        UdpPlacement::HostNetns,
        PROOF_GENERATION,
    );

    retract_node_identity(registry.path()).expect("retraction");
    assert!(
        !identity_file.exists(),
        "the exact publication must be gone, not merely superseded"
    );
    assert_eq!(
        UdpNodeIdentity::resolve_published(registry.path(), BOOT_1),
        None
    );
    // Retraction is idempotent, so the post-failure re-assertion is safe.
    retract_node_identity(registry.path()).expect("idempotent retraction");

    // With no identity resolved, the predecessor's proof authorizes nothing.
    let error = prepare_placement(
        registry.path(),
        &stable_attested(UdpPlacement::HostNetns, UdpPlacement::HostNetns),
    )
    .err()
    .expect("a retracted identity must not adopt the host producer");
    assert!(error.contains("no node identity"), "{error}");

    // The replacement Node object publishes its OWN UID, which the predecessor
    // proof cannot satisfy.
    let replacement = identity(NODE_B, BOOT_1);
    publish_node_identity_for(registry.path(), &replacement).expect("replacement publication");
    let resolved = UdpNodeIdentity::resolve_published(registry.path(), BOOT_1);
    assert_eq!(resolved.as_ref(), Some(&replacement));
    let request = UdpPlacementRequest {
        node: resolved,
        node_proof_generation: Some(PROOF_GENERATION.to_string()),
        ..stable_attested(UdpPlacement::HostNetns, UdpPlacement::HostNetns)
    };
    let error = prepare_placement(registry.path(), &request)
        .err()
        .expect("a recreated node must not inherit the predecessor's proof");
    assert!(error.contains("different Kubernetes node UID"), "{error}");
}

#[cfg(unix)]
#[test]
fn identity_retraction_is_narrow_and_does_not_follow_symlinks() {
    use std::os::unix::fs::symlink;

    let registry = tempfile::tempdir().expect("registry");
    let published = registry.path().join(".node-identity-v1.json");
    let outside = registry.path().join("outside-target");
    std::fs::write(&outside, b"must survive").expect("symlink target");
    symlink(&outside, &published).expect("symlinked identity");
    let neighbour = registry.path().join(".udp-node-cleanup-proof-v1.json");
    std::fs::write(&neighbour, b"neighbour").expect("neighbouring artifact");

    retract_node_identity(registry.path()).expect("symlinked publication is retracted");
    assert!(
        published.symlink_metadata().is_err(),
        "the link itself must be unlinked"
    );
    assert_eq!(
        std::fs::read(&outside).expect("symlink target survives"),
        b"must survive"
    );
    assert!(
        neighbour.exists(),
        "retraction must touch only the identity publication"
    );

    // A crash-left or hostile entry of another type is retracted, not skipped.
    std::fs::create_dir(&published).expect("directory at the publication path");
    retract_node_identity(registry.path()).expect("directory publication is retracted");
    assert!(!published.exists());
}

#[test]
fn a_node_attestation_from_another_node_or_boot_or_generation_is_refused() {
    let node = identity(NODE_A, BOOT_1);

    // Another machine's proof, copied onto this node.
    let registry = tempfile::tempdir().expect("registry");
    write_node_attestation(
        registry.path(),
        ".udp-node-cleanup-proof-v1.json",
        &identity(NODE_B, BOOT_1),
        UdpPlacement::HostNetns,
        PROOF_GENERATION,
    );
    let error = prepare_placement(
        registry.path(),
        &stable_attested_on_node(UdpPlacement::HostNetns, UdpPlacement::HostNetns, &node),
    )
    .err()
    .expect("another node's attestation must be refused");
    assert!(error.contains("different Kubernetes node UID"), "{error}");

    // This node's proof, but from an earlier incarnation: a same-boot
    // pre-contract node could have installed predecessor rules since.
    let registry = tempfile::tempdir().expect("registry");
    write_node_attestation(
        registry.path(),
        ".udp-node-cleanup-proof-v1.json",
        &identity(NODE_A, BOOT_2),
        UdpPlacement::HostNetns,
        PROOF_GENERATION,
    );
    let error = prepare_placement(
        registry.path(),
        &stable_attested_on_node(UdpPlacement::HostNetns, UdpPlacement::HostNetns, &node),
    )
    .err()
    .expect("an earlier incarnation's attestation must be refused");
    assert!(error.contains("earlier boot"), "{error}");

    // A superseded node-proof generation: the migration moved on.
    let registry = tempfile::tempdir().expect("registry");
    write_node_attestation(
        registry.path(),
        ".udp-node-cleanup-proof-v1.json",
        &node,
        UdpPlacement::HostNetns,
        "stale-generation",
    );
    let error = prepare_placement(
        registry.path(),
        &stable_attested_on_node(UdpPlacement::HostNetns, UdpPlacement::HostNetns, &node),
    )
    .err()
    .expect("a stale node-proof generation must be refused");
    assert!(
        error.contains("superseded node-proof generation"),
        "{error}"
    );
    assert_eq!(
        ferrum_edge::proxy::udp_placement_migration::snapshot().failure_reason,
        UdpMigrationFailureReason::GenerationMismatch
    );

    // A proof for a different incoming placement proves nothing about this one.
    let registry = tempfile::tempdir().expect("registry");
    write_node_attestation(
        registry.path(),
        ".udp-node-cleanup-proof-v1.json",
        &node,
        UdpPlacement::PodNetns,
        PROOF_GENERATION,
    );
    let error = prepare_placement(
        registry.path(),
        &stable_attested_on_node(UdpPlacement::HostNetns, UdpPlacement::HostNetns, &node),
    )
    .err()
    .expect("a proof for another placement must be refused");
    assert!(error.contains("different incoming placement"), "{error}");
}

#[test]
fn malformed_or_unreadable_node_proof_fails_closed() {
    let node = identity(NODE_A, BOOT_1);
    for body in [
        &b"{"[..],
        &b"{\"version\":2,\"node\":{\"node_uid\":\"a\",\"boot_id\":\"b\"},\"target\":\"host-netns\",\"generation\":\"g\"}"[..],
        &vec![b'x'; 4096][..],
    ] {
        let registry = tempfile::tempdir().expect("registry");
        std::fs::write(
            registry.path().join(".udp-node-cleanup-proof-v1.json"),
            body,
        )
        .expect("write hostile attestation");
        let error = prepare_placement(
            registry.path(),
            &stable_attested_on_node(UdpPlacement::HostNetns, UdpPlacement::HostNetns, &node),
        )
        .err()
        .expect("unreadable or malformed proof must fail closed");
        assert!(error.contains("node-specific"), "{error}");
        assert!(
            !registry
                .path()
                .join(".udp-placement-state-v1.json")
                .exists()
        );
    }
}

#[test]
fn a_release_without_a_node_proof_generation_cannot_bind_any_proof() {
    let registry = tempfile::tempdir().expect("registry");
    let node = identity(NODE_A, BOOT_1);
    write_node_attestation(
        registry.path(),
        ".udp-node-cleanup-proof-v1.json",
        &node,
        UdpPlacement::HostNetns,
        PROOF_GENERATION,
    );
    let request = UdpPlacementRequest {
        node: Some(node),
        node_proof_generation: None,
        ..stable_attested(UdpPlacement::HostNetns, UdpPlacement::HostNetns)
    };
    let error = prepare_placement(registry.path(), &request)
        .err()
        .expect("a release with no node-proof generation must refuse");
    assert!(error.contains("no node-proof generation"), "{error}");
}

#[test]
fn a_cleanup_complete_node_that_missed_finalize_still_resumes_through_finalize() {
    // Node-specific proof is additive to the existing generation-safe
    // resumption, never a replacement for it: a node that persisted cleanup
    // completion and then lost its finalize release must still refuse `stable`
    // and finalize on the exact same tuple.
    let registry = tempfile::tempdir().expect("registry");
    let node = identity(NODE_A, BOOT_1);
    prepare_placement(
        registry.path(),
        &stable_on_node(UdpPlacement::PodNetns, &node),
    )
    .expect("pod placement bootstrap");
    let cleanup = on_node(
        transition(
            UdpMigrationPhase::Cleanup,
            "resume-1",
            UdpPlacement::PodNetns,
            UdpPlacement::HostNetns,
        ),
        &node,
    );
    let context = cleanup_context(registry.path(), &cleanup);
    complete_cleanup(&context);

    let error = prepare_placement(
        registry.path(),
        &stable_on_node(UdpPlacement::HostNetns, &node),
    )
    .err()
    .expect("a cleanup-complete node must not start stable");
    assert!(error.contains("phase=finalize"), "{error}");

    let finalize = on_node(
        transition(
            UdpMigrationPhase::Finalize,
            "resume-1",
            UdpPlacement::PodNetns,
            UdpPlacement::HostNetns,
        ),
        &node,
    );
    assert!(matches!(
        prepare_placement(registry.path(), &finalize),
        Ok(UdpPlacementDecision::RunStable)
    ));
    // The finalized record is this node's own proof from here on: no node
    // attestation is consulted, because the record is present.
    assert!(matches!(
        prepare_placement(
            registry.path(),
            &stable_on_node(UdpPlacement::HostNetns, &node)
        ),
        Ok(UdpPlacementDecision::RunStable)
    ));
}

#[test]
fn established_attestation_cannot_authorize_an_in_place_flip_or_a_mismatch() {
    let registry = tempfile::tempdir().expect("registry");
    prepare_placement(registry.path(), &stable(UdpPlacement::PodNetns))
        .expect("pod placement bootstrap");
    // A PRESENT durable record is never overridden by the attestation.
    let error = prepare_placement(
        registry.path(),
        &stable_attested(UdpPlacement::HostNetns, UdpPlacement::HostNetns),
    )
    .err()
    .expect("attested in-place flip must still fail");
    assert!(error.contains("unsafe one-step"));

    // An attestation naming a different placement proves nothing about this one.
    let fresh = tempfile::tempdir().expect("fresh registry");
    let error = prepare_placement(
        fresh.path(),
        &stable_attested(UdpPlacement::HostNetns, UdpPlacement::PodNetns),
    )
    .err()
    .expect("mismatched attestation must fail");
    assert!(error.contains("no durable predecessor proof"));
}

#[test]
fn quarantine_tombstone_refuses_attested_adoption_until_finalize_clears_it() {
    let registry = tempfile::tempdir().expect("registry");
    std::fs::write(registry.path().join(".udp-placement-quarantined"), b"")
        .expect("quarantine tombstone");
    let attested = stable_attested(UdpPlacement::HostNetns, UdpPlacement::HostNetns);
    let error = prepare_placement(registry.path(), &attested)
        .err()
        .expect("quarantined ownership must refuse adoption");
    assert!(error.contains("quarantined"));
    // Every placement is refused, not just the attested host one: the operator
    // quarantined ownership precisely because it is unknown.
    let error = prepare_placement(registry.path(), &stable(UdpPlacement::PodNetns))
        .err()
        .expect("quarantined ownership must refuse any absent-state bootstrap");
    assert!(error.contains("quarantined"));

    // Only a proven cleanup/finalize pair clears the quarantine.
    let cleanup = transition(
        UdpMigrationPhase::Cleanup,
        "repair-1",
        UdpPlacement::PodNetns,
        UdpPlacement::HostNetns,
    );
    let context = cleanup_context(registry.path(), &cleanup);
    complete_cleanup(&context);
    assert!(matches!(
        prepare_placement(
            registry.path(),
            &transition(
                UdpMigrationPhase::Finalize,
                "repair-1",
                UdpPlacement::PodNetns,
                UdpPlacement::HostNetns,
            ),
        ),
        Ok(UdpPlacementDecision::RunStable)
    ));
    assert!(
        !registry.path().join(".udp-placement-quarantined").exists(),
        "finalize proof must clear the quarantine tombstone"
    );

    // Model a crash or transient removal failure after the durable finalize
    // state was written. An idempotent finalize retry must retry its cleanup
    // side effect instead of returning early and stranding the marker.
    std::fs::create_dir(registry.path().join(".udp-placement-quarantined"))
        .expect("empty directory tombstone");
    assert!(matches!(
        prepare_placement(
            registry.path(),
            &transition(
                UdpMigrationPhase::Finalize,
                "repair-1",
                UdpPlacement::PodNetns,
                UdpPlacement::HostNetns,
            ),
        ),
        Ok(UdpPlacementDecision::RunStable)
    ));
    assert!(
        !registry.path().join(".udp-placement-quarantined").exists(),
        "idempotent finalize must retry safe tombstone removal"
    );
}

#[test]
fn pod_to_host_cleanup_resumes_and_finalize_requires_durable_completion() {
    let registry = tempfile::tempdir().expect("registry");
    // Ownership of a producer placement is identity-bound end to end, so every
    // phase of this rollout carries the same node identity.
    let node = identity(NODE_A, BOOT_1);
    prepare_placement(
        registry.path(),
        &stable_on_node(UdpPlacement::PodNetns, &node),
    )
    .expect("pod placement bootstrap");
    let cleanup = on_node(
        transition(
            UdpMigrationPhase::Cleanup,
            "rollout-42",
            UdpPlacement::PodNetns,
            UdpPlacement::HostNetns,
        ),
        &node,
    );
    let first = cleanup_context(registry.path(), &cleanup);
    let resumed = cleanup_context(registry.path(), &cleanup);
    assert_eq!(first.generation(), resumed.generation());

    let finalize = on_node(
        transition(
            UdpMigrationPhase::Finalize,
            "rollout-42",
            UdpPlacement::PodNetns,
            UdpPlacement::HostNetns,
        ),
        &node,
    );
    assert!(prepare_placement(registry.path(), &finalize).is_err());
    complete_cleanup(&resumed);
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
        prepare_placement(
            registry.path(),
            &stable_on_node(UdpPlacement::HostNetns, &node)
        ),
        Ok(UdpPlacementDecision::RunStable)
    ));
}

#[test]
fn crash_leftover_temporary_files_do_not_block_exact_tuple_resume() {
    let registry = tempfile::tempdir().expect("registry");
    prepare_placement(registry.path(), &stable(UdpPlacement::PodNetns))
        .expect("bootstrap placement");
    let crashed_temp = registry
        .path()
        .join(".udp-placement-state-v1.json.tmp.crashed");
    std::fs::write(&crashed_temp, b"incomplete").expect("crash leftover");
    age_crash_temp(&crashed_temp);
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
    assert!(
        !crashed_temp.exists(),
        "the next state publication must reap an owned exact-prefix crash temp"
    );
}

#[test]
fn marker_publication_reaps_only_owned_exact_prefix_temporary_files() {
    let registry = tempfile::tempdir().expect("registry");
    let owned = registry.path().join(".udp-registry-synced.tmp.crashed");
    let fresh = registry.path().join(".udp-registry-synced.tmp.active");
    let foreign_prefix = registry.path().join(".udp-registry-synced.other");
    std::fs::write(&owned, b"partial").expect("owned temp");
    age_crash_temp(&owned);
    std::fs::write(&fresh, b"in progress").expect("fresh temp");
    std::fs::write(&foreign_prefix, b"foreign").expect("foreign file");

    assert_eq!(
        publish_registry_sync_marker_for_pods(registry.path(), "temp-reap", &HashSet::new(),),
        Ok(true)
    );
    assert!(!owned.exists());
    assert!(fresh.exists());
    assert!(foreign_prefix.exists());
}

#[cfg(unix)]
#[test]
fn marker_temp_reaper_refuses_symlinks_and_directories() {
    use std::os::unix::fs::symlink;

    let registry = tempfile::tempdir().expect("registry");
    let foreign = registry.path().join("foreign-target");
    let symlink_temp = registry.path().join(".udp-registry-synced.tmp.symlink");
    let directory_temp = registry.path().join(".udp-registry-synced.tmp.directory");
    std::fs::write(&foreign, b"foreign").expect("foreign target");
    symlink(&foreign, &symlink_temp).expect("symlink temp");
    std::fs::create_dir(&directory_temp).expect("directory temp");

    assert_eq!(
        publish_registry_sync_marker_for_pods(registry.path(), "temp-reap-safe", &HashSet::new(),),
        Ok(true)
    );
    assert!(symlink_temp.symlink_metadata().is_ok());
    assert!(directory_temp.is_dir());
    assert_eq!(
        std::fs::read(&foreign).expect("foreign survives"),
        b"foreign"
    );
}

#[test]
fn malformed_or_non_regular_durable_state_fails_closed() {
    let registry = tempfile::tempdir().expect("registry");
    let state = registry.path().join(".udp-placement-state-v1.json");
    std::fs::create_dir(&state).expect("non-regular state fixture");
    let error = prepare_placement(registry.path(), &stable(UdpPlacement::PodNetns))
        .err()
        .expect("non-regular state must not be guessed");
    assert!(error.contains("securely open"));

    std::fs::remove_dir(&state).expect("remove non-regular state");
    std::fs::write(&state, b"{\"version\":1").expect("truncated state fixture");
    let error = prepare_placement(registry.path(), &stable(UdpPlacement::PodNetns))
        .err()
        .expect("truncated state must not be guessed");
    assert!(error.contains("malformed"));

    std::fs::write(
        &state,
        br#"{"version":2,"active":"pod-netns","pending":null,"completed":null}"#,
    )
    .expect("unsupported state fixture");
    let error = prepare_placement(registry.path(), &stable(UdpPlacement::PodNetns))
        .err()
        .expect("unsupported state must not be guessed");
    assert!(error.contains("unsupported version"));
}

#[test]
fn semantically_inconsistent_durable_state_fails_closed() {
    let registry = tempfile::tempdir().expect("registry");
    let state = registry.path().join(".udp-placement-state-v1.json");
    std::fs::write(
        state,
        br#"{"version":1,"active":"pod-netns","pending":null,"completed":{"generation":"completed-host","from":"pod-netns","to":"host-netns"}}"#,
    )
    .expect("inconsistent state fixture");

    let error = prepare_placement(registry.path(), &stable(UdpPlacement::PodNetns))
        .err()
        .expect("inconsistent completed ownership must not admit a producer");
    assert!(error.contains("inconsistent completed ownership"));
}

#[cfg(unix)]
#[test]
fn linked_durable_state_is_rejected_without_guessing_ownership() {
    let registry = tempfile::tempdir().expect("registry");
    let source = registry.path().join("state-source");
    let state = registry.path().join(".udp-placement-state-v1.json");
    std::fs::write(
        &source,
        br#"{"version":1,"active":"pod-netns","pending":null,"completed":null}"#,
    )
    .expect("linked state source");
    std::fs::hard_link(&source, &state).expect("hard-linked state fixture");

    let error = prepare_placement(registry.path(), &stable(UdpPlacement::PodNetns))
        .err()
        .expect("multiply-linked state must not be guessed");
    assert!(error.contains("singly linked"));
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
    complete_cleanup(&context);
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
    complete_cleanup(&context);
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
        // Ownership of a producer placement is identity-bound end to end, so
        // every phase in this rollout carries the same node identity.
        let node = identity(NODE_A, BOOT_1);
        if from == UdpPlacement::HostNetns {
            let bootstrap = cleanup_context(
                registry.path(),
                &on_node(
                    transition(
                        UdpMigrationPhase::Cleanup,
                        "bootstrap-host",
                        UdpPlacement::PodNetns,
                        UdpPlacement::HostNetns,
                    ),
                    &node,
                ),
            );
            complete_cleanup(&bootstrap);
            prepare_placement(
                registry.path(),
                &on_node(
                    transition(
                        UdpMigrationPhase::Finalize,
                        "bootstrap-host",
                        UdpPlacement::PodNetns,
                        UdpPlacement::HostNetns,
                    ),
                    &node,
                ),
            )
            .expect("bootstrap finalize");
        } else {
            prepare_placement(registry.path(), &stable_on_node(from, &node))
                .expect("bootstrap placement");
        }
        assert!(prepare_placement(registry.path(), &stable_on_node(to, &node)).is_err());
        let context = cleanup_context(
            registry.path(),
            &on_node(
                transition(UdpMigrationPhase::Cleanup, generation, from, to),
                &node,
            ),
        );
        complete_cleanup(&context);
        prepare_placement(
            registry.path(),
            &on_node(
                transition(UdpMigrationPhase::Finalize, generation, from, to),
                &node,
            ),
        )
        .expect("finalize transition");
        assert!(matches!(
            prepare_placement(registry.path(), &stable_on_node(to, &node)),
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
fn completed_generation_cannot_authorize_a_later_cleanup_transition() {
    let registry = tempfile::tempdir().expect("registry");
    prepare_placement(registry.path(), &stable(UdpPlacement::PodNetns))
        .expect("bootstrap placement");
    let first = transition(
        UdpMigrationPhase::Cleanup,
        "generation-once",
        UdpPlacement::PodNetns,
        UdpPlacement::HostNetns,
    );
    complete_cleanup(&cleanup_context(registry.path(), &first));
    prepare_placement(
        registry.path(),
        &transition(
            UdpMigrationPhase::Finalize,
            "generation-once",
            UdpPlacement::PodNetns,
            UdpPlacement::HostNetns,
        ),
    )
    .expect("first finalize");

    let error = prepare_placement(
        registry.path(),
        &transition(
            UdpMigrationPhase::Cleanup,
            "generation-once",
            UdpPlacement::HostNetns,
            UdpPlacement::PodNetns,
        ),
    )
    .err()
    .expect("a completed generation must not bind a later registry proof");
    assert!(error.contains("already completed"));
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
    assert!(context.registry_sync_proof().is_none());
    assert_eq!(
        publish_registry_sync_marker_for_pods(registry.path(), "generation-b", &HashSet::new(),),
        Ok(true)
    );
    assert!(context.registry_sync_proof().is_none());
    assert_eq!(
        publish_registry_sync_marker_for_pods(registry.path(), "generation-a", &HashSet::new(),),
        Ok(true)
    );
    assert!(context.registry_sync_proof().is_some());
    clear_registry_sync_marker(registry.path()).expect("restart retraction");
    assert!(context.registry_sync_proof().is_none());
}

#[test]
fn same_generation_registry_republication_has_a_distinct_proof() {
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
    let first = publish_registry_proof(&context);
    let second = publish_registry_proof(&context);
    assert!(
        first != second,
        "each publication must identify a new registry snapshot even for the same generation"
    );
}

#[test]
fn registry_proof_change_resets_repeated_passes_and_blocks_finalize() {
    let registry = tempfile::tempdir().expect("registry");
    prepare_placement(registry.path(), &stable(UdpPlacement::PodNetns))
        .expect("bootstrap placement");
    let cleanup = transition(
        UdpMigrationPhase::Cleanup,
        "generation-a",
        UdpPlacement::PodNetns,
        UdpPlacement::HostNetns,
    );
    let context = cleanup_context(registry.path(), &cleanup);
    let first_proof = publish_registry_proof(&context);
    let mut window = UdpCleanupProofWindow::new(true, true);
    let first_pass = window.observe_pass(
        Some(first_proof.clone()),
        Some(first_proof.clone()),
        true,
        Some(7),
    );
    assert!(!first_pass.host_complete());
    assert!(!first_pass.pod_complete());

    let replacement_proof = publish_registry_proof(&context);
    let changed_pass = window.observe_pass(
        Some(first_proof.clone()),
        Some(replacement_proof.clone()),
        true,
        Some(7),
    );
    assert!(!changed_pass.proof_is_valid());
    let first_replacement_pass = window.observe_pass(
        Some(replacement_proof.clone()),
        Some(replacement_proof),
        true,
        Some(7),
    );
    assert!(!first_replacement_pass.host_complete());
    assert!(!first_replacement_pass.pod_complete());
    assert!(context.mark_cleanup_complete(&first_proof).is_err());

    let finalize = transition(
        UdpMigrationPhase::Finalize,
        "generation-a",
        UdpPlacement::PodNetns,
        UdpPlacement::HostNetns,
    );
    assert!(prepare_placement(registry.path(), &finalize).is_err());
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

#[test]
fn the_node_preflight_retires_both_placements_for_ipv4_and_ipv6() {
    // A recordless node cannot know which placement ran here before, so it must
    // not guess: the preflight context declares the conservative `disabled`
    // predecessor, which reaps BOTH ownership domains.
    let registry = tempfile::tempdir().expect("registry");
    let context =
        ferrum_edge::proxy::udp_placement_migration::UdpMigrationContext::for_node_preflight(
            registry.path(),
            UdpPlacement::HostNetns,
            identity(NODE_A, BOOT_1),
            PROOF_GENERATION,
        )
        .expect("node preflight context");
    assert!(context.is_node_preflight());
    assert!(
        context.cleanup_pod_netns(),
        "pod-netns ownership must be reaped"
    );
    assert!(
        context.cleanup_host_netns(),
        "host-netns ownership must be reaped"
    );
    assert_eq!(context.to(), UdpPlacement::HostNetns);
    assert_eq!(context.generation(), PROOF_GENERATION);

    // Both the pod-netns and the host-netns retirement scripts delete the exact
    // Ferrum-owned objects in BOTH address families, and neither flushes a
    // table nor matches a chain by pattern.
    let pod = ferrum_edge::capture::IptablesPlan::udp_teardown_script(true);
    let host = ferrum_edge::capture::IptablesPlan::host_udp_teardown_script();
    for script in [&pod, &host] {
        assert!(script.contains("iptables"), "{script}");
        // Ownership safety: every chain flush/delete names a Ferrum-owned
        // chain. A bare table flush would take a co-resident CNI's rules down
        // with it, so it must never appear.
        for line in script.lines() {
            for token in ["-F", "-X"] {
                if let Some(rest) = line.split(token).nth(1) {
                    let chain = rest.split_whitespace().next().unwrap_or("");
                    assert!(
                        chain.starts_with("FERRUM_MESH_UDP"),
                        "{token} must name a Ferrum-owned chain, got {chain:?} in {line}"
                    );
                }
            }
        }
    }
    assert!(
        pod.contains("ip6tables"),
        "pod teardown must cover IPv6: {pod}"
    );
    assert!(
        host.contains("ip6tables"),
        "host teardown must cover IPv6: {host}"
    );

    // A `disabled` target has no incoming placement to prove, so it is refused
    // rather than publishing a vacuous attestation.
    assert!(
        ferrum_edge::proxy::udp_placement_migration::UdpMigrationContext::for_node_preflight(
            registry.path(),
            UdpPlacement::Disabled,
            identity(NODE_A, BOOT_1),
            PROOF_GENERATION,
        )
        .is_err()
    );
}
