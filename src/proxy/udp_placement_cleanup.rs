//! Shared Ambient UDP predecessor-retirement supervisor.
//!
//! One loop serves BOTH consumers so their ownership rules cannot drift:
//!
//! * the explicit `cleanup` migration phase run by the mesh data plane, and
//! * the privileged node preflight (`ferrum-edge ambient-udp-preflight`, issue
//!   #3809) that an ambiguous recordless node must complete before the
//!   unprivileged steady-state host producer is allowed to start.
//!
//! The loop only ever deletes state it can prove Ferrum owns: the exact
//! `FERRUM_MESH_UDP_*` chains/jumps and the exact Ferrum-owned policy rule and
//! route, for IPv4 and IPv6 alike, in the host namespace and inside every pod
//! network namespace the node-agent registry enumerates. It never flushes a
//! table, never removes a chain by pattern, and never touches a co-resident
//! CNI's or service mesh's state.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tracing::{info, warn};

use super::netns_capture::PodCaptureSource;
use super::udp_placement_migration::{
    UdpCleanupProofWindow, UdpMigrationContext, UdpMigrationFailureReason, UdpMigrationStatusPhase,
    clear_failure, set_failure, set_phase,
};

/// Why the supervisor returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpCleanupOutcome {
    /// Completion proof was published durably (placement cleanup) or as this
    /// node incarnation's cleanup attestation (node preflight).
    Complete,
    /// The caller's shutdown signal fired first. Nothing was published.
    ShuttingDown,
    /// The caller's deadline elapsed before the retirement could be proven
    /// complete under one continuous registry publication.
    DeadlineElapsed,
}

/// Run predecessor retirement until it is provably complete.
///
/// `deadline` bounds only the *caller*: the one-shot preflight needs to fail
/// the init container rather than block pod creation forever, while the mesh
/// data-plane cleanup phase deliberately retries indefinitely (its readiness
/// stays false and an operator drives the rollout).
pub async fn run_udp_placement_cleanup(
    context: UdpMigrationContext,
    source: Arc<dyn PodCaptureSource>,
    mut shutdown: watch::Receiver<bool>,
    deadline: Option<tokio::time::Instant>,
) -> UdpCleanupOutcome {
    let ready_dir = context.registry_dir().join(".udp-ready");
    let mut pod_cleanup = context.cleanup_pod_netns().then(|| {
        super::netns_udp_capture::NetnsUdpCleanupManager::new(
            source,
            super::netns_udp_capture::ProxyNetnsUdpCleanupBackend::new(true),
            Duration::from_secs(2),
        )
        .with_ready_dir(Some(ready_dir.clone()))
    });
    let mut host_recovery = context
        .cleanup_host_netns()
        .then(|| super::host_udp_capture::HostUdpStaleGenerationRecovery::new(Some(ready_dir)));
    let mut proof_window =
        UdpCleanupProofWindow::new(context.cleanup_pod_netns(), context.cleanup_host_netns());
    let mut ticker = tokio::time::interval(Duration::from_secs(2));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await;

    loop {
        if *shutdown.borrow() {
            return UdpCleanupOutcome::ShuttingDown;
        }
        if deadline.is_some_and(|deadline| tokio::time::Instant::now() >= deadline) {
            return UdpCleanupOutcome::DeadlineElapsed;
        }
        if let Some(proof_before) = context.registry_sync_proof() {
            let mut host_pass_complete = host_recovery.is_none();
            let mut host_outstanding = 0;
            let mut failure_reason = None;
            if let Some(recovery) = host_recovery.as_mut() {
                if super::host_udp_capture::recover_and_reap_once(recovery).await {
                    host_pass_complete = true;
                } else {
                    host_pass_complete = false;
                    failure_reason = Some(if recovery.outstanding() == 0 {
                        UdpMigrationFailureReason::HostCleanupFailed
                    } else {
                        UdpMigrationFailureReason::GateAcknowledgementMissing
                    });
                }
                host_outstanding = recovery.outstanding();
            }

            let mut pod_complete_fingerprint = None;
            let mut pod_outstanding = 0;
            if let Some(manager) = pod_cleanup.as_mut() {
                let progress = manager.migration_cleanup_once().await;
                pod_outstanding = progress.outstanding;
                if let Some(reason) = progress.failure_reason {
                    failure_reason = Some(reason);
                } else if progress.outstanding == 0 {
                    pod_complete_fingerprint = Some(progress.registry_fingerprint);
                }
            }

            // The node agent gives every publication a fresh identity after
            // retracting the marker for a post-relist mutation. Count this pass
            // only when that exact identity spans all cleanup work, so a
            // clear/mutate/republish ABA cycle cannot preserve prior progress.
            let proof_progress = proof_window.observe_pass(
                Some(proof_before),
                context.registry_sync_proof(),
                host_pass_complete,
                pod_complete_fingerprint,
            );
            if !proof_progress.proof_is_valid() {
                set_phase(UdpMigrationStatusPhase::WaitingForRegistry, 0);
                set_failure(UdpMigrationFailureReason::RegistryNotSynchronized);
                ticker.tick().await;
                continue;
            }

            let outstanding = host_outstanding.saturating_add(pod_outstanding);
            let phase =
                if failure_reason == Some(UdpMigrationFailureReason::GateAcknowledgementMissing) {
                    UdpMigrationStatusPhase::WaitingForGateAck
                } else if !proof_progress.pod_complete() {
                    UdpMigrationStatusPhase::CleaningPodNetns
                } else {
                    UdpMigrationStatusPhase::CleaningHostNetns
                };
            set_phase(phase, outstanding);
            if let Some(reason) = failure_reason {
                set_failure(reason);
            } else {
                clear_failure();
            }

            if let Some(proof) = proof_progress.completion_proof() {
                match context.mark_cleanup_complete(proof) {
                    Ok(()) => {
                        set_phase(UdpMigrationStatusPhase::CleanupComplete, 0);
                        clear_failure();
                        if context.is_node_preflight() {
                            info!(
                                placement = context.to().as_str(),
                                "Ambient UDP node preflight retired both predecessor placements and published this node incarnation's cleanup attestation"
                            );
                        } else {
                            info!(
                                from = context.from().as_str(),
                                to = context.to().as_str(),
                                "Ambient UDP predecessor cleanup is durably complete; phase=finalize with the same generation is now permitted"
                            );
                        }
                        return UdpCleanupOutcome::Complete;
                    }
                    Err(error) => {
                        proof_window.invalidate();
                        set_failure(UdpMigrationFailureReason::StatePersistenceFailed);
                        warn!(
                            %error,
                            "Ambient UDP cleanup completed but proof publication failed; retrying"
                        );
                    }
                }
            }
        } else {
            proof_window.invalidate();
            set_phase(UdpMigrationStatusPhase::WaitingForRegistry, 0);
            set_failure(UdpMigrationFailureReason::RegistryNotSynchronized);
        }

        tokio::select! {
            _ = ticker.tick() => {}
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return UdpCleanupOutcome::ShuttingDown;
                }
            }
        }
    }
}
