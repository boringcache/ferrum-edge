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
        .position(|line| predicate(line))
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

    assert_eq!(
        steering.retract_port(5300),
        SteerReconcileOutcome::Applied
    );
    assert_eq!(
        steering.bound_destinations(),
        vec![destination("10.96.0.11", 5301)]
    );
    forget(steering);
}
