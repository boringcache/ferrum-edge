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
//! `FERRUM_MESH_UDP_*` chains/jumps, the exact `FERRUM_UDP_FAIL_CLOSED_{A,B}`
//! pod-netns guard chains, and the exact Ferrum-owned policy rule and route,
//! for IPv4 and IPv6 alike, in the host namespace and inside every pod
//! network namespace the node-agent registry enumerates. It never flushes a
//! table, never removes a chain by pattern, and never touches a co-resident
//! CNI's or service mesh's state.

use std::future::pending;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tracing::{error, info, warn};

use super::host_udp_capture::HostUdpRecoverOnce;
use super::netns_capture::PodCaptureSource;
use super::owned_shell::{self, OwnedShellError};
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

/// Host-namespace Ferrum UDP teardown used by one supervisor pass.
///
/// Production runs the exact-name dual-stack host teardown script. Tests inject
/// a stalled command to prove the preflight deadline owns subprocess lifetime
/// and never publishes attestation after timeout.
pub trait HostUdpCleanupReaper: Send {
    fn reap_host_udp_state(
        &mut self,
        deadline: Option<std::time::Instant>,
    ) -> Result<(), OwnedShellError>;
}

/// Production host reap: exact Ferrum-owned host-netns UDP objects, IPv4 and IPv6.
pub struct ProductionHostUdpCleanupReaper;

impl HostUdpCleanupReaper for ProductionHostUdpCleanupReaper {
    fn reap_host_udp_state(
        &mut self,
        deadline: Option<std::time::Instant>,
    ) -> Result<(), OwnedShellError> {
        super::host_udp_capture::reap_stale_host_udp_state(deadline)
    }
}

/// Run predecessor retirement until it is provably complete.
///
/// `deadline` bounds only the *caller*: the one-shot preflight needs to fail
/// the init container rather than block pod creation forever, while the mesh
/// data-plane cleanup phase deliberately retries indefinitely (its readiness
/// stays false and an operator drives the rollout). The deadline is converted
/// to a wall-clock instant and threaded into every synchronous `sh`/iptables/ip
/// child so a hung command cannot freeze the current-thread runtime past it.
/// A deadline result never reports completion, and a publication that raced the
/// ceiling is withheld (retracted or invalidated) so no usable node-cleanup
/// attestation remains.
pub async fn run_udp_placement_cleanup(
    context: UdpMigrationContext,
    source: Arc<dyn PodCaptureSource>,
    shutdown: watch::Receiver<bool>,
    deadline: Option<tokio::time::Instant>,
) -> UdpCleanupOutcome {
    run_udp_placement_cleanup_with_host_reaper(
        context,
        source,
        shutdown,
        deadline,
        ProductionHostUdpCleanupReaper,
    )
    .await
}

/// Same supervisor as [`run_udp_placement_cleanup`], with an injectable host
/// reap so deadline ownership can be proven without a live iptables fixture.
pub async fn run_udp_placement_cleanup_with_host_reaper<R: HostUdpCleanupReaper>(
    context: UdpMigrationContext,
    source: Arc<dyn PodCaptureSource>,
    mut shutdown: watch::Receiver<bool>,
    deadline: Option<tokio::time::Instant>,
    mut host_reaper: R,
) -> UdpCleanupOutcome {
    let std_deadline = deadline.map(owned_shell::std_deadline_from_tokio);
    let ready_dir = context.registry_dir().join(".udp-ready");
    // Only the node preflight overrides this; the mesh data plane's cleanup
    // phase runs in the steady-state pod and keeps its own `/proc`.
    let target_proc_root = context.target_proc_root().map(Path::to_path_buf);
    let mut pod_cleanup = context.cleanup_pod_netns().then(|| {
        super::netns_udp_capture::NetnsUdpCleanupManager::new(
            source,
            super::netns_udp_capture::ProxyNetnsUdpCleanupBackend::new(true)
                .with_target_proc_root(target_proc_root),
            Duration::from_secs(2),
        )
        .with_ready_dir(Some(ready_dir.clone()))
        .with_deadline(std_deadline)
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
        if owned_shell::deadline_elapsed(std_deadline) {
            return fail_closed_on_deadline(&context);
        }
        if let Some(proof_before) = context.registry_sync_proof() {
            let mut host_pass_complete = host_recovery.is_none();
            let mut host_outstanding = 0;
            let mut failure_reason = None;
            if let Some(recovery) = host_recovery.as_mut() {
                match super::host_udp_capture::recover_and_reap_until(
                    recovery,
                    std_deadline,
                    &mut |deadline| host_reaper.reap_host_udp_state(deadline),
                )
                .await
                {
                    HostUdpRecoverOnce::Reaped => host_pass_complete = true,
                    HostUdpRecoverOnce::Incomplete => {
                        host_pass_complete = false;
                        failure_reason = Some(if recovery.outstanding() == 0 {
                            UdpMigrationFailureReason::HostCleanupFailed
                        } else {
                            UdpMigrationFailureReason::GateAcknowledgementMissing
                        });
                    }
                    HostUdpRecoverOnce::DeadlineElapsed => {
                        return fail_closed_on_deadline(&context);
                    }
                }
                host_outstanding = recovery.outstanding();
            }

            let mut pod_complete_fingerprint = None;
            let mut pod_outstanding = 0;
            if let Some(manager) = pod_cleanup.as_mut() {
                let progress = manager.migration_cleanup_once().await;
                if progress.deadline_elapsed {
                    return fail_closed_on_deadline(&context);
                }
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
                if let Some(outcome) =
                    wait_for_next_pass(&mut ticker, &mut shutdown, std_deadline).await
                {
                    return deadline_aware_outcome(&context, outcome);
                }
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
                if owned_shell::deadline_elapsed(std_deadline) {
                    return fail_closed_on_deadline(&context);
                }
                match context.mark_cleanup_complete(proof) {
                    Ok(()) => {
                        if owned_shell::deadline_elapsed(std_deadline) {
                            // A write that raced the deadline is not a published
                            // success: withhold any newly visible proof and fail
                            // closed so the caller never reports completion after
                            // timeout. Retraction failure is reported, never
                            // claimed as a successful cleanup of the attestation.
                            return fail_closed_on_deadline(&context);
                        }
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

        if let Some(outcome) = wait_for_next_pass(&mut ticker, &mut shutdown, std_deadline).await {
            return deadline_aware_outcome(&context, outcome);
        }
    }
}

fn deadline_aware_outcome(
    context: &UdpMigrationContext,
    outcome: UdpCleanupOutcome,
) -> UdpCleanupOutcome {
    if outcome == UdpCleanupOutcome::DeadlineElapsed {
        fail_closed_on_deadline(context)
    } else {
        outcome
    }
}

/// A deadline result must not leave a usable node-cleanup attestation behind,
/// including when publication raced the ceiling. Always fail closed as
/// `DeadlineElapsed` (never `Complete`); report retraction/invalidation
/// failure instead of claiming the proof was removed.
fn fail_closed_on_deadline(context: &UdpMigrationContext) -> UdpCleanupOutcome {
    if context.is_node_preflight()
        && let Err(error) =
            super::udp_placement_migration::withhold_node_cleanup_proof_after_deadline(
                context.registry_dir(),
            )
    {
        error!(
            %error,
            "Ambient UDP preflight deadline elapsed; cleanup attestation could not be retracted cleanly"
        );
    }
    UdpCleanupOutcome::DeadlineElapsed
}

/// Wait for the next retry tick, shutdown, or the wall-clock deadline.
async fn wait_for_next_pass(
    ticker: &mut tokio::time::Interval,
    shutdown: &mut watch::Receiver<bool>,
    deadline: Option<std::time::Instant>,
) -> Option<UdpCleanupOutcome> {
    tokio::select! {
        _ = ticker.tick() => None,
        changed = shutdown.changed() => {
            if changed.is_err() || *shutdown.borrow() {
                Some(UdpCleanupOutcome::ShuttingDown)
            } else {
                None
            }
        }
        _ = async {
            match owned_shell::remaining(deadline) {
                Some(remaining) => tokio::time::sleep(remaining).await,
                None => pending().await,
            }
        } => Some(UdpCleanupOutcome::DeadlineElapsed),
    }
}
