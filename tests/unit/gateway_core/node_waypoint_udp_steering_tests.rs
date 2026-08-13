//! NodeWaypoint UDP/DTLS Service-path steering contracts (issue #3286).
//!
//! The steering datapath installs kernel objects that OUTLIVE the process that
//! installed them, and it decides which enrolled interfaces have their Service
//! traffic diverted to a materialized listener. Both properties fail silently
//! when they fail, so they are pinned here rather than left to the live gate:
//!
//! * a crashed predecessor's rules are reaped on this process's FIRST pass,
//!   even when this generation steers nothing;
//! * a later quiet poll runs no command at all;
//! * a failed apply leaves the datapath torn down by exact name, and the whole
//!   plan is retried on the next reconcile;
//! * the emitted command ORDER never marks a datagram under a destination
//!   generation whose notrack / local-delivery prerequisites are not installed;
//! * a published address family that cannot be installed fails the WHOLE apply
//!   instead of being silently skipped.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use ferrum_edge::capture::{
    NodeWaypointUdpSteerDestination, node_waypoint_udp_steer_setup_script,
    node_waypoint_udp_steer_teardown_script,
};
use ferrum_edge::proxy::node_waypoint_udp_steering::{
    NodeWaypointUdpSteerBackend, NodeWaypointUdpSteering, SteerReconcileOutcome,
};

/// Records every script the reconcile runs, and can fail on demand.
struct RecordingBackend {
    scripts: Mutex<Vec<String>>,
    fail_setup: bool,
}

impl RecordingBackend {
    fn new(fail_setup: bool) -> Arc<Self> {
        Arc::new(Self {
            scripts: Mutex::new(Vec::new()),
            fail_setup,
        })
    }

    fn scripts(&self) -> Vec<String> {
        self.scripts.lock().expect("recording backend lock").clone()
    }

    fn take(&self) -> Vec<String> {
        std::mem::take(&mut *self.scripts.lock().expect("recording backend lock"))
    }
}

impl NodeWaypointUdpSteerBackend for RecordingBackend {
    fn run_script(&self, script: &str) -> Result<(), String> {
        self.scripts
            .lock()
            .expect("recording backend lock")
            .push(script.to_string());
        // Only a SETUP script can fail here; the teardown is the recovery path
        // and must be observed to run.
        if self.fail_setup && script.contains("--set-xmark") {
            return Err("boom".to_string());
        }
        Ok(())
    }
}

fn destination(ip: &str, port: u16) -> NodeWaypointUdpSteerDestination {
    NodeWaypointUdpSteerDestination {
        ip: ip.parse::<IpAddr>().expect("destination address"),
        port,
    }
}

fn is_teardown(script: &str) -> bool {
    script.contains("-D PREROUTING")
}

/// A `Drop` on `NodeWaypointUdpSteering` runs one final teardown, which would
/// pollute the recorded script list of a test that asserts on totals. Leak the
/// object deliberately instead of asserting around that final call.
fn forget(steering: NodeWaypointUdpSteering) {
    std::mem::forget(steering);
}

// ── First-pass reaping ─────────────────────────────────────────────────────

/// The regression this exists for: Ferrum-owned chains, `ip rule`s, and routes
/// survive the process that installed them. A process that starts after a crash
/// and computes an EMPTY plan must still reap them on its first pass — the old
/// `applied.is_none() => Unchanged` short-circuit left a crashed predecessor's
/// destinations marked and locally delivered to a socket that no longer exists,
/// for the whole life of the new process.
#[test]
fn the_first_reconcile_reaps_a_previous_process_even_with_an_empty_plan() {
    let backend = RecordingBackend::new(false);
    let steering = NodeWaypointUdpSteering::new(backend.clone());

    assert_eq!(
        steering.reconcile_with(&["veth0".to_string()], &[]),
        SteerReconcileOutcome::Removed,
        "an empty destination plan on the FIRST pass must still tear the node down"
    );
    let scripts = backend.take();
    assert_eq!(scripts.len(), 1, "exactly one teardown, not a setup");
    assert!(
        is_teardown(&scripts[0]),
        "the first pass must run the exact-name teardown: {}",
        scripts[0]
    );
    assert_eq!(
        scripts[0],
        node_waypoint_udp_steer_teardown_script(),
        "the reaped objects are named exactly, never matched by pattern"
    );
    forget(steering);
}

/// The other empty half — no attributable interface — is the same posture and
/// must reap on the first pass too.
#[test]
fn the_first_reconcile_reaps_when_no_interface_is_attributable() {
    let backend = RecordingBackend::new(false);
    let steering = NodeWaypointUdpSteering::new(backend.clone());

    assert_eq!(
        steering.reconcile_with(&[], &[destination("10.96.0.10", 5300)]),
        SteerReconcileOutcome::Removed
    );
    let scripts = backend.take();
    assert_eq!(scripts.len(), 1);
    assert!(is_teardown(&scripts[0]));
    forget(steering);
}

/// …and having reaped once, every later quiet poll must run NOTHING. Otherwise
/// the fix would trade a stale-rule leak for an `iptables` invocation on every
/// registry poll for the life of the process.
#[test]
fn later_empty_reconciles_are_idempotent_and_run_no_command() {
    let backend = RecordingBackend::new(false);
    let steering = NodeWaypointUdpSteering::new(backend.clone());

    assert_eq!(
        steering.reconcile_with(&[], &[]),
        SteerReconcileOutcome::Removed
    );
    assert_eq!(backend.take().len(), 1, "the first pass reaps");

    for _ in 0..5 {
        assert_eq!(
            steering.reconcile_with(&[], &[]),
            SteerReconcileOutcome::Unchanged
        );
    }
    assert!(
        backend.scripts().is_empty(),
        "a quiet poll after a proven teardown must run no command"
    );
    forget(steering);
}

/// An unchanged NON-empty generation is likewise a no-op after it is applied.
#[test]
fn an_unchanged_generation_runs_no_command_after_it_is_applied() {
    let backend = RecordingBackend::new(false);
    let steering = NodeWaypointUdpSteering::new(backend.clone());
    let ifaces = vec!["veth0".to_string()];
    let destinations = vec![destination("10.96.0.10", 5300)];

    assert_eq!(
        steering.reconcile_with(&ifaces, &destinations),
        SteerReconcileOutcome::Applied
    );
    let first = backend.take();
    assert_eq!(
        first.len(),
        2,
        "the first apply reaps a possible predecessor, then installs"
    );
    assert!(is_teardown(&first[0]));
    assert!(!is_teardown(&first[1]));

    for _ in 0..3 {
        assert_eq!(
            steering.reconcile_with(&ifaces, &destinations),
            SteerReconcileOutcome::Unchanged
        );
    }
    assert!(backend.scripts().is_empty());
    forget(steering);
}

/// A failed apply must leave the datapath torn down by exact name AND must not
/// record the plan as applied, so the next reconcile retries the whole thing
/// rather than reporting a black hole as steady state.
#[test]
fn a_failed_apply_tears_down_and_is_retried_on_the_next_reconcile() {
    let backend = RecordingBackend::new(true);
    let steering = NodeWaypointUdpSteering::new(backend.clone());
    let ifaces = vec!["veth0".to_string()];
    let destinations = vec![destination("10.96.0.10", 5300)];

    assert_eq!(
        steering.reconcile_with(&ifaces, &destinations),
        SteerReconcileOutcome::Failed
    );
    let first = backend.take();
    assert!(
        is_teardown(first.last().expect("a teardown ran")),
        "a failed apply must be followed by the exact-name teardown"
    );

    assert_eq!(
        steering.reconcile_with(&ifaces, &destinations),
        SteerReconcileOutcome::Failed,
        "the identical plan must be attempted again, not reported Unchanged"
    );
    assert!(
        backend.scripts().iter().any(|s| !is_teardown(s)),
        "the retry must actually re-run the setup script"
    );
    forget(steering);
}

// ── Emitted command order and fail-closed family handling ──────────────────

fn setup_script(ifaces: &[&str], destinations: &[NodeWaypointUdpSteerDestination]) -> String {
    let ifaces: Vec<String> = ifaces.iter().map(|iface| (*iface).to_string()).collect();
    node_waypoint_udp_steer_setup_script(&ifaces, destinations)
        .expect("the plan must render")
        .expect("a non-empty plan must produce a script")
}

fn line_index(script: &str, predicate: impl Fn(&str) -> bool) -> usize {
    script
        .lines()
        .position(predicate)
        .unwrap_or_else(|| panic!("expected line not found in script:\n{script}"))
}

/// The update-order contract (issue #3286 root review). During a generation
/// change the OLD mangle mark rules must stop matching BEFORE the raw notrack
/// chain is repopulated. Otherwise a datagram to an old-generation destination
/// is still marked while its conntrack exemption is already gone: `nat
/// PREROUTING` DNATs it to a backing pod and the surviving mark then delivers
/// THAT rewritten datagram locally — cross-generation, wrong-destination
/// admission. A brief unsteered (fail-closed) window is the acceptable trade.
#[test]
fn marking_stops_before_the_notrack_prerequisites_are_replaced() {
    let script = setup_script(&["veth0"], &[destination("10.96.0.10", 5300)]);

    let mangle_flush = line_index(&script, |line| {
        line.contains("-t mangle") && line.contains("-F FERRUM_NW_UDP_STEER")
    });
    let raw_flush = line_index(&script, |line| {
        line.contains("-t raw") && line.contains("-F FERRUM_NW_UDP_NOTRACK")
    });
    let notrack_rule = line_index(&script, |line| line.contains("-j CT --notrack"));
    let mark_rule = line_index(&script, |line| line.contains("-j MARK --set-xmark"));
    let mangle_jump = line_index(&script, |line| {
        line.contains("-t mangle") && line.contains("-A PREROUTING -p udp -j FERRUM_NW_UDP_STEER")
    });

    assert!(
        mangle_flush < raw_flush,
        "the mark chain must be emptied before the notrack chain is flushed:\n{script}"
    );
    assert!(
        notrack_rule < mark_rule,
        "every destination's conntrack exemption must precede its mark rule:\n{script}"
    );
    assert!(
        mark_rule < mangle_jump,
        "the mark rules must exist before the mangle jump makes them observable:\n{script}"
    );
}

/// Local delivery must exist before anything can be marked: a mark with no
/// `fwmark` rule and no `local` route is a black hole rather than a steer.
#[test]
fn local_delivery_routing_precedes_every_mark_rule() {
    let script = setup_script(&["veth0"], &[destination("10.96.0.10", 5300)]);
    let rule_add = line_index(&script, |line| line.contains("ip rule add priority"));
    let route_add = line_index(&script, |line| line.contains("route add local 0.0.0.0/0"));
    let mark_rule = line_index(&script, |line| line.contains("-j MARK --set-xmark"));
    assert!(rule_add < mark_rule && route_add < mark_rule, "\n{script}");
}

/// A published address family is installed COMPLETELY or the apply fails. The
/// earlier shape wrapped the IPv6 half in `if command -v ip6tables; ... else
/// echo ...; fi`, which exits 0 — so a node without `ip6tables` recorded the
/// whole plan as applied and silently black-holed every IPv6 Service datagram,
/// forever, with no retry.
#[test]
fn a_missing_family_binary_fails_the_whole_apply_rather_than_being_skipped() {
    let script = setup_script(
        &["veth0"],
        &[
            destination("10.96.0.10", 5300),
            destination("fd00::10", 5300),
        ],
    );
    assert!(
        script.starts_with("set -e\n"),
        "the script must abort on the first failing command:\n{script}"
    );
    assert!(
        script.contains("command -v ip6tables >/dev/null 2>&1 || {"),
        "a published IPv6 destination must hard-require ip6tables:\n{script}"
    );
    assert!(
        !script.contains("else"),
        "no best-effort arm may survive: a skipped family is a silent black hole:\n{script}"
    );
    assert!(
        script.contains("command -v iptables >/dev/null 2>&1 || {"),
        "the IPv4 family carries the same guard:\n{script}"
    );
}

/// An IPv4-only plan must not require `ip6tables`: only PUBLISHED families are
/// mandatory, so an IPv6-less node keeps working.
#[test]
fn an_ipv4_only_plan_does_not_require_ip6tables() {
    let script = setup_script(&["veth0"], &[destination("10.96.0.10", 5300)]);
    assert!(
        !script.contains("ip6tables"),
        "an unpublished family must emit nothing at all:\n{script}"
    );
}

/// Every rule is scoped by BOTH the ingress interface and the exact Service
/// address+port. Port-only scoping would steer a workload's traffic to an
/// unrelated off-cluster host that happens to share the port number.
#[test]
fn every_rule_is_scoped_by_interface_and_exact_service_address() {
    let script = setup_script(&["veth0"], &[destination("10.96.0.10", 5300)]);
    for line in script
        .lines()
        .filter(|line| line.contains("-j CT --notrack") || line.contains("-j MARK --set-xmark"))
    {
        assert!(line.contains("-i veth0"), "unscoped interface: {line}");
        assert!(
            line.contains("-d 10.96.0.10/32"),
            "unscoped destination: {line}"
        );
        assert!(line.contains("--dport 5300"), "unscoped port: {line}");
    }
}

/// Bound destinations are instance-owned. Setting them applies immediately
/// against the supplied interfaces; clearing them tears the datapath down.
#[test]
fn set_bound_destinations_applies_immediately_and_empty_tears_down() {
    let backend = RecordingBackend::new(false);
    let steering = NodeWaypointUdpSteering::new(backend.clone());
    let ifaces = vec!["veth0".to_string()];
    let destinations = vec![destination("10.96.0.10", 5300)];

    assert_eq!(
        steering.set_bound_destinations(destinations.clone(), Some(&ifaces)),
        SteerReconcileOutcome::Applied
    );
    assert_eq!(steering.bound_destinations(), destinations);
    let first = backend.take();
    assert!(is_teardown(&first[0]));
    assert!(!is_teardown(&first[1]));

    assert_eq!(
        steering.set_bound_destinations(Vec::new(), Some(&ifaces)),
        SteerReconcileOutcome::Removed
    );
    assert!(steering.bound_destinations().is_empty());
    let second = backend.take();
    assert_eq!(second.len(), 1);
    assert!(is_teardown(&second[0]));
    forget(steering);
}

/// A bind-loss retraction of one port must not keep that destination marked.
#[test]
fn retract_port_drops_only_that_destination() {
    let backend = RecordingBackend::new(false);
    let steering = NodeWaypointUdpSteering::new(backend.clone());
    let ifaces = vec!["veth0".to_string()];
    steering.set_bound_destinations(
        vec![
            destination("10.96.0.10", 5300),
            destination("10.96.0.11", 5301),
        ],
        Some(&ifaces),
    );
    backend.take();

    assert_eq!(steering.retract_port(5300), SteerReconcileOutcome::Applied);
    assert_eq!(
        steering.bound_destinations(),
        vec![destination("10.96.0.11", 5301)]
    );
    forget(steering);
}

// ── Serialized latest-state machine (issue #3286 exact-head review) ────────

/// Blocks the next non-teardown script so a later event can be queued behind
/// the in-flight reconcile. Destination/interface updates hold the same mutex
/// across the component write and this backend call, so the queued event
/// always observes the latest combined state.
struct ArmedBarrierBackend {
    scripts: Mutex<Vec<String>>,
    arm: Mutex<Option<(Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>>,
}

impl ArmedBarrierBackend {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            scripts: Mutex::new(Vec::new()),
            arm: Mutex::new(None),
        })
    }

    fn arm(&self) -> (Arc<std::sync::Barrier>, Arc<std::sync::Barrier>) {
        let entered = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        *self.arm.lock().expect("arm lock") = Some((entered.clone(), release.clone()));
        (entered, release)
    }
}

impl NodeWaypointUdpSteerBackend for ArmedBarrierBackend {
    fn run_script(&self, script: &str) -> Result<(), String> {
        self.scripts
            .lock()
            .expect("recording backend lock")
            .push(script.to_string());
        if is_teardown(script) {
            return Ok(());
        }
        if let Some((entered, release)) = self.arm.lock().expect("arm lock").take() {
            entered.wait();
            release.wait();
        }
        Ok(())
    }
}

/// Plan B is in-flight (component stored, backend blocked). Plan C is the
/// later logical event. C must own the installed plan; B must not install
/// after C has already been published.
#[test]
fn later_bound_destination_update_owns_the_installed_plan() {
    let backend = ArmedBarrierBackend::new();
    let steering = Arc::new(NodeWaypointUdpSteering::new(backend.clone()));
    let ifaces = vec!["veth0".to_string()];
    let plan_b = vec![destination("10.96.0.10", 5300)];
    let plan_c = vec![destination("10.96.0.11", 5301)];

    let (entered, release) = backend.arm();
    let steering_b = steering.clone();
    let ifaces_b = ifaces.clone();
    let plan_b_thread = plan_b.clone();
    let handle_b = std::thread::spawn(move || {
        steering_b.set_bound_destinations(plan_b_thread, Some(&ifaces_b))
    });
    entered.wait();

    let steering_c = steering.clone();
    let ifaces_c = ifaces.clone();
    let plan_c_thread = plan_c.clone();
    let handle_c = std::thread::spawn(move || {
        steering_c.set_bound_destinations(plan_c_thread, Some(&ifaces_c))
    });

    release.wait();
    handle_b.join().expect("plan B thread");
    handle_c.join().expect("plan C thread");

    assert_eq!(
        steering.bound_destinations(),
        plan_c,
        "the later logical event must own the installed plan"
    );
    std::mem::forget(steering);
}

/// A retract that races a later full-plan update must filter the LATEST
/// desired set, not a stale snapshot taken before the full plan was stored.
/// Full plan adds 5302 while 5300+5301 are already applied; retract drops
/// 5300. Legal finals: the full plan (retract ran first) or 5301+5302
/// (retract ran last). `[5301]` alone is the stale-load bug.
#[test]
fn retract_filters_the_latest_desired_set_not_a_stale_snapshot() {
    let backend = ArmedBarrierBackend::new();
    let steering = Arc::new(NodeWaypointUdpSteering::new(backend.clone()));
    let ifaces = vec!["veth0".to_string()];
    let initial = vec![
        destination("10.96.0.10", 5300),
        destination("10.96.0.11", 5301),
    ];
    let full = vec![
        destination("10.96.0.10", 5300),
        destination("10.96.0.11", 5301),
        destination("10.96.0.12", 5302),
    ];
    let retract_after_full = vec![
        destination("10.96.0.11", 5301),
        destination("10.96.0.12", 5302),
    ];

    assert_eq!(
        steering.set_bound_destinations(initial, Some(&ifaces)),
        SteerReconcileOutcome::Applied
    );

    let (entered, release) = backend.arm();
    let steering_full = steering.clone();
    let ifaces_full = ifaces.clone();
    let full_thread = full.clone();
    let handle_full = std::thread::spawn(move || {
        steering_full.set_bound_destinations(full_thread, Some(&ifaces_full))
    });
    entered.wait();

    let steering_retract = steering.clone();
    let handle_retract = std::thread::spawn(move || steering_retract.retract_port(5300));

    release.wait();
    handle_full.join().expect("full-plan thread");
    handle_retract.join().expect("retract thread");

    assert_eq!(
        steering.bound_destinations(),
        retract_after_full,
        "retract queued behind the full plan must drop 5300 from the latest set, keeping 5302"
    );
    std::mem::forget(steering);
}

/// The other retract/full order: retract is in-flight, then the full plan is
/// the later event and must own the installed plan (including 5300).
#[test]
fn later_full_plan_owns_the_installed_plan_over_an_in_flight_retract() {
    let backend = ArmedBarrierBackend::new();
    let steering = Arc::new(NodeWaypointUdpSteering::new(backend.clone()));
    let ifaces = vec!["veth0".to_string()];
    let initial = vec![
        destination("10.96.0.10", 5300),
        destination("10.96.0.11", 5301),
    ];
    let full = vec![
        destination("10.96.0.10", 5300),
        destination("10.96.0.11", 5301),
        destination("10.96.0.12", 5302),
    ];

    assert_eq!(
        steering.set_bound_destinations(initial, Some(&ifaces)),
        SteerReconcileOutcome::Applied
    );

    let (entered, release) = backend.arm();
    let steering_retract = steering.clone();
    let handle_retract = std::thread::spawn(move || steering_retract.retract_port(5300));
    entered.wait();

    let steering_full = steering.clone();
    let ifaces_full = ifaces.clone();
    let full_thread = full.clone();
    let handle_full = std::thread::spawn(move || {
        steering_full.set_bound_destinations(full_thread, Some(&ifaces_full))
    });

    release.wait();
    handle_retract.join().expect("retract thread");
    handle_full.join().expect("full-plan thread");

    assert_eq!(
        steering.bound_destinations(),
        full,
        "the later full-plan event must own the installed plan"
    );
    std::mem::forget(steering);
}

// ── Reply-source authorization lifecycle (issue #3286) ─────────────────────
//
// Steering preserves the Service ClusterIP as the datagram's local address, so
// the listener's reply is source-pinned to it — and a ClusterIP is never a
// configured node IP, so `tc_inbound` drops that reply unless the exact
// `(address, port)` pair is authorized. The rules and the authorization are
// therefore two halves of ONE datapath, and the order they move in is the
// contract: authorize before steering, withdraw after un-steering, and tear the
// whole generation down if either half fails.

/// Records reply-source publications on the SAME log as the scripts, so
/// ordering between the two halves is observable as one sequence.
struct RecordingPublisher {
    log: Arc<Mutex<Vec<String>>>,
    fail: Arc<std::sync::atomic::AtomicBool>,
}

impl ferrum_edge::proxy::node_waypoint_udp_reply_source::NodeWaypointUdpReplySourcePublisher
    for RecordingPublisher
{
    fn publish(&self, sources: &[NodeWaypointUdpSteerDestination]) -> Result<(), String> {
        let entry = if sources.is_empty() {
            "publish:withdraw".to_string()
        } else {
            format!("publish:{}", sources.len())
        };
        if self.fail.load(std::sync::atomic::Ordering::SeqCst) {
            self.log
                .lock()
                .expect("publisher log")
                .push(format!("{entry}:failed"));
            return Err("injected reply-source publication failure".to_string());
        }
        self.log.lock().expect("publisher log").push(entry);
        Ok(())
    }
}

/// Runs scripts onto a shared log so publications and scripts interleave.
struct SharedLogBackend {
    log: Arc<Mutex<Vec<String>>>,
}

impl NodeWaypointUdpSteerBackend for SharedLogBackend {
    fn run_script(&self, script: &str) -> Result<(), String> {
        let entry = if is_teardown(script) {
            "script:teardown"
        } else {
            "script:setup"
        };
        self.log.lock().expect("backend log").push(entry.to_string());
        Ok(())
    }
}

fn shared_log_steering(
    fail_publish: bool,
) -> (
    NodeWaypointUdpSteering,
    Arc<Mutex<Vec<String>>>,
    Arc<std::sync::atomic::AtomicBool>,
) {
    let log = Arc::new(Mutex::new(Vec::new()));
    let fail = Arc::new(std::sync::atomic::AtomicBool::new(fail_publish));
    let steering = NodeWaypointUdpSteering::new(Arc::new(SharedLogBackend { log: log.clone() }))
        .with_reply_source_publisher(Arc::new(RecordingPublisher {
            log: log.clone(),
            fail: fail.clone(),
        }));
    (steering, log, fail)
}

fn entries(log: &Arc<Mutex<Vec<String>>>) -> Vec<String> {
    log.lock().expect("shared log").clone()
}

/// The apply order. A reply source must be authorized BEFORE the rules that
/// send datagrams at it exist; the reverse order opens a window on every new
/// generation in which a workload's datagram reaches the listener and the
/// listener's reply is dropped by this node's own pod-veth guard.
#[test]
fn a_generation_authorizes_its_reply_sources_before_it_steers_anything() {
    let (steering, log, _fail) = shared_log_steering(false);

    assert_eq!(
        steering.reconcile_with(
            &["veth0".to_string()],
            &[destination("10.96.0.10", 5300), destination("fd00::a", 5300)],
        ),
        SteerReconcileOutcome::Applied
    );

    assert_eq!(
        entries(&log),
        vec![
            // First pass still reaps a predecessor, which withdraws first.
            "script:teardown".to_string(),
            "publish:withdraw".to_string(),
            // Then authorize, and only then steer.
            "publish:2".to_string(),
            "script:setup".to_string(),
        ],
        "reply sources must be authorized before the steering rules are installed"
    );
    forget(steering);
}

/// The teardown order is the mirror image: the rules go first, so nothing is
/// steered at an address whose authorization is about to disappear.
#[test]
fn a_teardown_unsteers_before_it_withdraws_authorization() {
    let (steering, log, _fail) = shared_log_steering(false);
    let ifaces = vec!["veth0".to_string()];

    assert_eq!(
        steering.reconcile_with(&ifaces, &[destination("10.96.0.10", 5300)]),
        SteerReconcileOutcome::Applied
    );
    log.lock().expect("shared log").clear();

    // Withdrawing the last destination is the ordinary listener-stop path.
    assert_eq!(
        steering.reconcile_with(&ifaces, &[]),
        SteerReconcileOutcome::Removed
    );
    assert_eq!(
        entries(&log),
        vec!["script:teardown".to_string(), "publish:withdraw".to_string()],
        "the steering rules must be removed before the authorization they relied on"
    );
    forget(steering);
}

/// A publication that cannot be applied fails the WHOLE generation closed: no
/// steering rules are installed, so the Service path stays on its pre-existing
/// fail-closed posture (dropped at the pod-veth guard) rather than becoming a
/// steered black hole.
#[test]
fn a_failed_authorization_refuses_the_generation_and_steers_nothing() {
    let (steering, log, _fail) = shared_log_steering(true);

    assert_eq!(
        steering.reconcile_with(&["veth0".to_string()], &[destination("10.96.0.10", 5300)]),
        SteerReconcileOutcome::Failed
    );
    let recorded = entries(&log);
    assert!(
        !recorded.iter().any(|entry| entry == "script:setup"),
        "no steering rule may be installed for a generation whose reply sources \
         could not be authorized: {recorded:?}"
    );
    assert!(
        recorded.iter().any(|entry| entry.ends_with(":failed")),
        "the failure must be observed: {recorded:?}"
    );
    forget(steering);
}

/// A failed WITHDRAWAL is never recorded as done. Without this, one transient
/// I/O error would leave a revoked ClusterIP authorized for the life of the
/// process, because the quiet-poll short-circuit would report `Unchanged`
/// forever.
#[test]
fn a_failed_withdrawal_is_retried_rather_than_settled() {
    let (steering, log, fail) = shared_log_steering(false);
    let ifaces = vec!["veth0".to_string()];

    assert_eq!(
        steering.reconcile_with(&ifaces, &[destination("10.96.0.10", 5300)]),
        SteerReconcileOutcome::Applied
    );

    // The listener stops while the claim directory is unwritable.
    fail.store(true, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        steering.reconcile_with(&ifaces, &[]),
        SteerReconcileOutcome::Removed
    );
    log.lock().expect("shared log").clear();

    // Still failing: the next quiet poll must RE-attempt the withdrawal instead
    // of settling on `Unchanged`.
    assert_eq!(
        steering.reconcile_with(&ifaces, &[]),
        SteerReconcileOutcome::Removed
    );
    assert!(
        entries(&log)
            .iter()
            .any(|entry| entry.starts_with("publish:withdraw")),
        "an unproven withdrawal must be retried on the next reconcile"
    );

    // Once it succeeds, the loop settles and stops issuing commands.
    fail.store(false, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        steering.reconcile_with(&ifaces, &[]),
        SteerReconcileOutcome::Removed
    );
    log.lock().expect("shared log").clear();
    assert_eq!(
        steering.reconcile_with(&ifaces, &[]),
        SteerReconcileOutcome::Unchanged
    );
    assert!(
        entries(&log).is_empty(),
        "a settled empty plan must run no command at all"
    );
    forget(steering);
}

/// A quiet poll on an UNCHANGED serving generation must not re-publish either —
/// the reply-source set is part of the applied generation, not a per-poll write.
#[test]
fn an_unchanged_generation_republishes_nothing() {
    let (steering, log, _fail) = shared_log_steering(false);
    let ifaces = vec!["veth0".to_string()];
    let destinations = [destination("10.96.0.10", 5300)];

    assert_eq!(
        steering.reconcile_with(&ifaces, &destinations),
        SteerReconcileOutcome::Applied
    );
    log.lock().expect("shared log").clear();
    assert_eq!(
        steering.reconcile_with(&ifaces, &destinations),
        SteerReconcileOutcome::Unchanged
    );
    assert!(entries(&log).is_empty());
    forget(steering);
}

/// Shutdown must withdraw the authorization, not just the rules: a proxy that
/// exits leaving a ClusterIP admissible has left the guard permanently weaker
/// than it found it.
#[test]
fn shutdown_withdraws_every_authorized_reply_source() {
    let (steering, log, _fail) = shared_log_steering(false);

    assert_eq!(
        steering.reconcile_with(&["veth0".to_string()], &[destination("10.96.0.10", 5300)]),
        SteerReconcileOutcome::Applied
    );
    log.lock().expect("shared log").clear();

    steering.shutdown();
    assert_eq!(
        entries(&log),
        vec!["script:teardown".to_string(), "publish:withdraw".to_string()],
        "shutdown must un-steer and then withdraw every authorization"
    );
    forget(steering);
}
