//! NodeWaypoint UDP/DTLS **Service-path steering** (issue #3286).
//!
//! # The gap this closes
//!
//! Issue #3286's listeners are host-netns wildcard UDP/DTLS sockets, one per
//! in-mesh Service port. Materializing them makes the authorization *mechanism*
//! reachable, but nothing makes ORDINARY traffic reach it. Trace what a workload
//! actually does:
//!
//! 1. It resolves `svc.ns.svc.cluster.local` and sends a datagram to
//!    `<ClusterIP>:<port>`.
//! 2. The datagram leaves the pod netns and enters the host namespace on that
//!    pod's host-side veth. `cgroup/connect4`/`connect6` do NOT touch it — the
//!    outbound capture listener is TCP-only, so those hooks deliberately skip
//!    `SOCK_DGRAM` and the destination stays the ClusterIP.
//! 3. tc ingress on that veth sees a destination that is not an enrolled pod IP
//!    and passes it on.
//! 4. `nat PREROUTING` / kube-proxy DNATs the ClusterIP to a backing
//!    `podIP:targetPort` and the datagram is FORWARDED to that pod's veth.
//! 5. tc egress on the destination pod's veth finds an enrolled destination and
//!    an unmarked, non-DNS datagram — and DROPS it.
//!
//! So the Service path is not merely a bypass of the waypoint; with the relay
//! auth mark configured it is a black hole. Only a direct dial to a *node*
//! address ever reached the materialized listener.
//!
//! # The steering, in one sentence
//!
//! On each enrolled pod's host-side interface, exempt that pod's datagrams to a
//! materialized Service `(ClusterIP, port)` from conntrack, mark them, and route
//! marked datagrams to a `local` table — so the datagram is delivered to the
//! waypoint's own socket **with its original destination still in the IP
//! header**, before kube-proxy can DNAT it.
//!
//! See `crate::capture::node_waypoint_udp_steer_setup_script` for the exact rule
//! shape and why each element is required. The properties that matter here:
//!
//! * **Evidence is preserved, not synthesized.** Nothing is rewritten, so the
//!   source address is still the pod's, the ingress interface is still the pod's
//!   veth, and `IP_PKTINFO`/`IPV6_PKTINFO` reports the ClusterIP as the local
//!   address. That is precisely the evidence
//!   [`crate::proxy::node_waypoint_udp_identity`] already attributes from, and
//!   the reply source the UDP session pins.
//! * **Service identity is part of the match.** Rules are scoped
//!   `-d <ClusterIP> --dport <port>`, never by port alone: a workload's datagram
//!   to an unrelated off-cluster host that happens to share a port number is not
//!   steered, and a materialized listener can only ever receive the Service it
//!   was materialized for (one service per port is already enforced at
//!   materialization — two claimants refuse BOTH).
//! * **No recursion.** The match is `-i <pod veth>` in `PREROUTING`. The
//!   waypoint's own relay dials and replies are locally generated and traverse
//!   `OUTPUT`, which is never hooked, so they are structurally incapable of
//!   being steered back into the waypoint.
//! * **No plaintext lane.** When steering is absent (never published, refused,
//!   or torn down) the datagram takes the pre-existing path and is dropped by
//!   the pod-veth guard. Losing steering loses the service, it does not open an
//!   unauthorized one.
//! * **The direct-pod guard is untouched.** No rule here admits anything to a
//!   pod; steering only diverts traffic to a local socket.
//!
//! # Ownership and lifecycle
//!
//! The desired destination set is published by mesh config apply
//! ([`publish_plan`], from `materialize_node_waypoint_udp_listeners`) and the
//! interface set comes from the same registry reconcile that publishes source
//! attribution, so steering and attribution can never disagree about which pods
//! exist. [`NodeWaypointUdpSteering::reconcile`] applies the pair only when it
//! CHANGED, tears the datapath down whenever either half is empty, and tears it
//! down on drop (task abort or panic included) so a dead reconcile loop cannot
//! leave marked-but-unserved destinations installed.
//!
//! Linux-only. Everywhere else [`NodeWaypointUdpSteering`] is inert and
//! `steering_supported()` is false, which is also why the mesh startup path
//! keeps its fail-closed UDP/DTLS suppression off Linux.

use std::sync::Arc;
use std::sync::Mutex;

use arc_swap::ArcSwap;
use tracing::{debug, info, warn};

use crate::capture::NodeWaypointUdpSteerDestination;

/// The steered Service destinations one mesh generation asks for.
///
/// Deliberately a whole-plan replacement: a generation is applied or it is not,
/// so the datapath never mixes one generation's destinations with another's.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NodeWaypointUdpSteerPlan {
    /// Sorted, deduplicated `(ClusterIP, port)` pairs, one per materialized
    /// listener address. Empty means "steer nothing" — which is a valid, fully
    /// fail-closed posture, not an error.
    pub destinations: Vec<NodeWaypointUdpSteerDestination>,
    /// Whether a generation has been published at all. An unpublished plan and
    /// an empty published plan are the same datapath posture (nothing steered),
    /// but only the latter is a positive statement, so they are distinguished in
    /// diagnostics.
    pub published: bool,
}

/// Process-wide published steering plan.
///
/// ONE writer — mesh config apply, which is already serialized — and readers on
/// the reconcile loop. A shared `ArcSwap` rather than a threaded handle because
/// the producer (`prepare_normalized_gateway_config_for_mesh`) is a pure
/// config-normalization function reached from several apply paths and carries no
/// runtime state; giving it one would mean threading a handle through every
/// caller and every test fixture for a value only the steering loop reads.
static PUBLISHED_PLAN: std::sync::LazyLock<ArcSwap<NodeWaypointUdpSteerPlan>> =
    std::sync::LazyLock::new(|| ArcSwap::from_pointee(NodeWaypointUdpSteerPlan::default()));

/// Publish the steered destination set for the generation being applied.
pub fn publish_plan(destinations: Vec<NodeWaypointUdpSteerDestination>) {
    let mut destinations = destinations;
    destinations.sort_unstable();
    destinations.dedup();
    PUBLISHED_PLAN.store(Arc::new(NodeWaypointUdpSteerPlan {
        destinations,
        published: true,
    }));
}

/// The currently published plan. An unpublished plan steers nothing.
pub fn published_plan() -> Arc<NodeWaypointUdpSteerPlan> {
    PUBLISHED_PLAN.load_full()
}

/// Retract the published plan. Used when a topology/feature switch means no
/// NodeWaypoint UDP listener may exist any more, so the next reconcile tears the
/// datapath down instead of holding the last-good generation.
#[allow(dead_code)] // Retraction seam for the disabled path and external tests.
pub fn retract_plan() {
    PUBLISHED_PLAN.store(Arc::new(NodeWaypointUdpSteerPlan::default()));
}

/// Whether the steering datapath can exist on this platform at all.
pub const fn steering_supported() -> bool {
    cfg!(target_os = "linux")
}

/// Effects the steering reconcile performs, behind a trait so the reconcile
/// logic is testable without root, `iptables`, or a live node.
pub trait NodeWaypointUdpSteerBackend: Send + Sync + 'static {
    /// Run one rendered `sh -c` script in the process's OWN (host) network
    /// namespace.
    fn run_script(&self, script: &str) -> Result<(), String>;
}

/// Production backend: runs the rendered script in the process's own namespace.
/// No `setns` anywhere — a NodeWaypoint proxy is `hostNetwork: true`, which is
/// exactly why the interface is a valid direction discriminator.
pub struct HostNamespaceSteerBackend;

impl NodeWaypointUdpSteerBackend for HostNamespaceSteerBackend {
    #[cfg(target_os = "linux")]
    fn run_script(&self, script: &str) -> Result<(), String> {
        let output = std::process::Command::new("sh")
            .arg("-c")
            .arg(script)
            .output()
            .map_err(|error| format!("failed to run the steering script: {error}"))?;
        if output.status.success() {
            return Ok(());
        }
        // stderr can only contain iptables/ip diagnostics about Ferrum-owned
        // objects; no secret, peer, or registry value reaches this script.
        Err(format!(
            "steering script exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }

    #[cfg(not(target_os = "linux"))]
    fn run_script(&self, _script: &str) -> Result<(), String> {
        Err("NodeWaypoint UDP Service steering is Linux-only".to_string())
    }
}

/// What one reconcile pass decided, for diagnostics and tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SteerReconcileOutcome {
    /// The desired state equals the applied state; nothing was run.
    Unchanged,
    /// Steering rules were installed or rebuilt.
    Applied,
    /// The datapath was torn down (nothing to steer, or a failed apply).
    Removed,
    /// The plan could not be rendered or applied. The datapath is left torn
    /// down, so the Service path fails closed rather than half-steered.
    Failed,
}

/// The applied generation, so a reconcile that changes nothing runs no command.
#[derive(Debug, Default, PartialEq, Eq)]
struct AppliedSteering {
    ifaces: Vec<String>,
    destinations: Vec<NodeWaypointUdpSteerDestination>,
}

/// Reconciles the NodeWaypoint Service-steering datapath.
pub struct NodeWaypointUdpSteering {
    backend: Arc<dyn NodeWaypointUdpSteerBackend>,
    /// `None` = nothing installed. Guarded by a plain `Mutex` because it is
    /// touched once per registry poll (seconds), never on a datagram path.
    applied: Mutex<Option<AppliedSteering>>,
}

impl NodeWaypointUdpSteering {
    pub fn new(backend: Arc<dyn NodeWaypointUdpSteerBackend>) -> Self {
        Self {
            backend,
            applied: Mutex::new(None),
        }
    }

    /// Reconcile the datapath against `ifaces` (this pass's attributable
    /// enrolled pods) and the published destination plan.
    ///
    /// A poisoned lock is treated as "nothing known to be applied" and forces a
    /// teardown: guessing that the previous generation is still installed is the
    /// one answer that could leave marked-but-unserved destinations behind.
    pub fn reconcile(&self, ifaces: &[String]) -> SteerReconcileOutcome {
        let plan = published_plan();
        self.reconcile_with(ifaces, &plan.destinations)
    }

    /// [`Self::reconcile`] against an explicit destination set. The published
    /// plan is a process-wide value, so tests drive this form instead of racing
    /// every other test that applies a mesh generation.
    pub fn reconcile_with(
        &self,
        ifaces: &[String],
        destinations: &[NodeWaypointUdpSteerDestination],
    ) -> SteerReconcileOutcome {
        let desired = AppliedSteering {
            ifaces: ifaces.to_vec(),
            destinations: destinations.to_vec(),
        };

        let mut applied = match self.applied.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                let mut guard = poisoned.into_inner();
                *guard = None;
                guard
            }
        };

        if desired.ifaces.is_empty() || desired.destinations.is_empty() {
            if applied.is_none() {
                return SteerReconcileOutcome::Unchanged;
            }
            self.tear_down(&mut applied);
            return SteerReconcileOutcome::Removed;
        }

        if applied.as_ref() == Some(&desired) {
            return SteerReconcileOutcome::Unchanged;
        }

        let script = match crate::capture::node_waypoint_udp_steer_setup_script(
            &desired.ifaces,
            &desired.destinations,
        ) {
            Ok(Some(script)) => script,
            Ok(None) => {
                self.tear_down(&mut applied);
                return SteerReconcileOutcome::Removed;
            }
            Err(error) => {
                warn!(
                    interfaces = desired.ifaces.len(),
                    destinations = desired.destinations.len(),
                    error = %error,
                    "NodeWaypoint UDP Service steering plan refused; the Service path stays \
                     unsteered (and therefore fails closed at the pod-veth guard) rather than \
                     installing a partial ruleset"
                );
                self.tear_down(&mut applied);
                return SteerReconcileOutcome::Failed;
            }
        };

        // Reap the previous generation before installing the new one. Both
        // chains are flushed and repopulated behind stable jumps, so this is
        // belt-and-braces for the case where the previous generation used an
        // address family the new one does not.
        if applied.is_some() {
            let _ = self
                .backend
                .run_script(&crate::capture::node_waypoint_udp_steer_teardown_script());
        }

        match self.backend.run_script(&script) {
            Ok(()) => {
                info!(
                    interfaces = desired.ifaces.len(),
                    destinations = desired.destinations.len(),
                    "NodeWaypoint UDP/DTLS Service steering installed; enrolled workloads reach \
                     their Service ClusterIP through the materialized listener with the original \
                     destination, source address, and ingress interface intact"
                );
                *applied = Some(desired);
                SteerReconcileOutcome::Applied
            }
            Err(error) => {
                warn!(
                    error = %error,
                    "NodeWaypoint UDP Service steering could not be installed; removing every \
                     Ferrum-owned steering object so no destination is marked without a serving \
                     socket"
                );
                self.tear_down(&mut applied);
                SteerReconcileOutcome::Failed
            }
        }
    }

    /// Remove every Ferrum-owned steering object and forget the applied
    /// generation. Best-effort by construction: the teardown script tolerates
    /// missing objects, and a failure is reported rather than retried inline
    /// (the next reconcile retries).
    fn tear_down(&self, applied: &mut Option<AppliedSteering>) {
        if let Err(error) = self
            .backend
            .run_script(&crate::capture::node_waypoint_udp_steer_teardown_script())
        {
            warn!(
                error = %error,
                "NodeWaypoint UDP Service steering teardown reported an error; it will be retried \
                 on the next reconcile"
            );
        } else {
            debug!("NodeWaypoint UDP Service steering datapath removed");
        }
        *applied = None;
    }

    /// Unconditional teardown, for shutdown and for the retraction guard.
    pub fn shutdown(&self) {
        let mut applied = match self.applied.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if applied.is_none() {
            // Still run the teardown once: a previous process generation's
            // objects survive this process, and they are exactly the
            // marked-without-a-socket state that must not outlive it.
            self.tear_down(&mut applied);
            return;
        }
        self.tear_down(&mut applied);
    }
}

impl Drop for NodeWaypointUdpSteering {
    fn drop(&mut self) {
        // Task abort and panic both drop the owner, so this is the last line of
        // defence against leaving destinations steered at a socket that no
        // longer exists.
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::sync::Mutex as StdMutex;

    struct RecordingBackend {
        scripts: StdMutex<Vec<String>>,
        fail: bool,
    }

    impl NodeWaypointUdpSteerBackend for RecordingBackend {
        fn run_script(&self, script: &str) -> Result<(), String> {
            self.scripts
                .lock()
                .expect("recording backend lock")
                .push(script.to_string());
            if self.fail {
                Err("boom".to_string())
            } else {
                Ok(())
            }
        }
    }

    fn destination(ip: &str, port: u16) -> NodeWaypointUdpSteerDestination {
        NodeWaypointUdpSteerDestination {
            ip: ip.parse::<IpAddr>().expect("destination address"),
            port,
        }
    }

    /// The two postures that must never install a half-datapath:
    ///
    /// * either half of the pair empty (no enrolled pod, or no materialized
    ///   Service) installs NOTHING — marking a destination with no attributable
    ///   source, or with no serving socket, is a black hole that looks
    ///   configured;
    /// * a failed apply leaves the datapath TORN DOWN by exact name.
    ///
    /// Driven through `reconcile_with` so it never touches the process-wide
    /// published plan that every mesh config-apply test also writes.
    #[test]
    fn steering_never_leaves_a_half_installed_datapath() {
        let one = vec![destination("10.96.0.10", 5300)];
        let quiet = Arc::new(RecordingBackend {
            scripts: StdMutex::new(Vec::new()),
            fail: false,
        });
        let steering = NodeWaypointUdpSteering::new(quiet.clone());
        assert_eq!(
            steering.reconcile_with(&["veth0".to_string()], &[]),
            SteerReconcileOutcome::Unchanged,
            "no materialized Service steers nothing"
        );
        assert_eq!(
            steering.reconcile_with(&[], &one),
            SteerReconcileOutcome::Unchanged,
            "no enrolled interface steers nothing"
        );
        assert!(
            quiet
                .scripts
                .lock()
                .expect("recording backend lock")
                .is_empty(),
            "neither posture may run a command"
        );
        std::mem::forget(steering);

        let failing = Arc::new(RecordingBackend {
            scripts: StdMutex::new(Vec::new()),
            fail: true,
        });
        let steering = NodeWaypointUdpSteering::new(failing.clone());
        assert_eq!(
            steering.reconcile_with(&["veth0".to_string()], &one),
            SteerReconcileOutcome::Failed
        );
        {
            let scripts = failing.scripts.lock().expect("recording backend lock");
            assert!(
                scripts
                    .last()
                    .expect("a teardown ran")
                    .contains("-D PREROUTING"),
                "a failed apply must be followed by the exact-name teardown"
            );
        }
        std::mem::forget(steering);
    }
}
