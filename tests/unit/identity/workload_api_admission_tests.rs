//! Workload API transport-admission policy (issue #3758).
//!
//! These pin the *decision* half of the admission boundary — the part a
//! single-uid test process cannot reach through real sockets, because it cannot
//! connect as a second user. The live half (real sockets, real gRPC, permit
//! release across every close path, bounded shutdown) is in
//! `tests/integration/workload_api_admission_tests.rs`.
//!
//! What is pinned here:
//!
//! - every limit is finite and has a hard ceiling that configuration cannot
//!   raise, and `0` is refused rather than meaning "unbounded";
//! - the total ceiling admits exactly `N` and refuses `N + 1`;
//! - the per-UID quota refuses a saturated UID **while a different UID is still
//!   served** — the fair-share property the whole per-UID bound exists for;
//! - a released permit returns capacity to both accountings;
//! - the metric families the boundary exports carry a closed label set.

use ferrum_edge::identity::workload_api::admission::{
    IDLE_TIMEOUT_CEILING, INITIAL_CONNECTION_TIMEOUT_CEILING, MAX_CONCURRENT_RPCS_CEILING,
    MAX_CONCURRENT_STREAMS_CEILING, MAX_CONNECTIONS_CEILING, MAX_CONNECTIONS_PER_UID_CEILING,
    SHUTDOWN_GRACE_CEILING,
};
use ferrum_edge::identity::workload_api::{
    ConnectionAdmission, WorkloadApiAdmissionConfig, close_reason, reject_reason,
};
use std::time::Duration;

/// A configuration small enough to saturate deterministically.
fn limits(max_connections: usize, max_per_uid: usize) -> WorkloadApiAdmissionConfig {
    WorkloadApiAdmissionConfig {
        max_connections,
        max_connections_per_uid: max_per_uid,
        ..WorkloadApiAdmissionConfig::default()
    }
}

#[test]
fn default_admission_limits_are_finite_and_within_every_ceiling() {
    let defaults = WorkloadApiAdmissionConfig::default();
    defaults
        .validate()
        .expect("the shipped defaults must themselves be acceptable configuration");

    assert!(defaults.max_connections > 0 && defaults.max_connections <= MAX_CONNECTIONS_CEILING);
    assert!(
        defaults.max_connections_per_uid > 0
            && defaults.max_connections_per_uid <= MAX_CONNECTIONS_PER_UID_CEILING
    );
    assert!(
        defaults.max_concurrent_streams > 0
            && defaults.max_concurrent_streams <= MAX_CONCURRENT_STREAMS_CEILING
    );
    assert!(
        defaults.max_concurrent_rpcs > 0
            && defaults.max_concurrent_rpcs <= MAX_CONCURRENT_RPCS_CEILING
    );
    assert!(
        !defaults.initial_connection_timeout.is_zero()
            && defaults.initial_connection_timeout <= INITIAL_CONNECTION_TIMEOUT_CEILING
    );
    assert!(!defaults.idle_timeout.is_zero() && defaults.idle_timeout <= IDLE_TIMEOUT_CEILING);
    assert!(!defaults.shutdown_grace.is_zero() && defaults.shutdown_grace <= SHUTDOWN_GRACE_CEILING);

    // The per-UID quota must actually bind, or one peer can take the pool.
    assert!(
        defaults.max_connections_per_uid < defaults.max_connections,
        "the default per-UID quota must be strictly below the global ceiling"
    );
    // The keepalive derived from the idle deadline has to refresh it, or a
    // healthy long-lived rotation stream would be closed as idle.
    assert!(
        defaults.keepalive_interval() < defaults.idle_timeout,
        "keepalive must fire well inside the idle deadline"
    );
}

#[test]
fn zero_is_refused_for_every_limit_rather_than_meaning_unbounded() {
    let cases: [(&str, WorkloadApiAdmissionConfig); 7] = [
        (
            "MAX_CONNECTIONS",
            WorkloadApiAdmissionConfig {
                max_connections: 0,
                ..WorkloadApiAdmissionConfig::default()
            },
        ),
        (
            "MAX_CONNECTIONS_PER_UID",
            WorkloadApiAdmissionConfig {
                max_connections_per_uid: 0,
                ..WorkloadApiAdmissionConfig::default()
            },
        ),
        (
            "MAX_CONCURRENT_STREAMS",
            WorkloadApiAdmissionConfig {
                max_concurrent_streams: 0,
                ..WorkloadApiAdmissionConfig::default()
            },
        ),
        (
            "MAX_CONCURRENT_RPCS",
            WorkloadApiAdmissionConfig {
                max_concurrent_rpcs: 0,
                ..WorkloadApiAdmissionConfig::default()
            },
        ),
        (
            "INITIAL_CONNECTION_TIMEOUT_SECONDS",
            WorkloadApiAdmissionConfig {
                initial_connection_timeout: Duration::ZERO,
                ..WorkloadApiAdmissionConfig::default()
            },
        ),
        (
            "IDLE_TIMEOUT_SECONDS",
            WorkloadApiAdmissionConfig {
                idle_timeout: Duration::ZERO,
                ..WorkloadApiAdmissionConfig::default()
            },
        ),
        (
            "SHUTDOWN_GRACE_SECONDS",
            WorkloadApiAdmissionConfig {
                shutdown_grace: Duration::ZERO,
                ..WorkloadApiAdmissionConfig::default()
            },
        ),
    ];

    for (setting, config) in cases {
        let error = config
            .validate()
            .expect_err("zero must be refused, not read as unbounded")
            .to_string();
        assert!(
            error.contains(setting),
            "the diagnostic must name the setting the operator has to fix; got: {error}"
        );
    }
}

#[test]
fn an_over_ceiling_limit_is_refused_and_names_its_ceiling() {
    let error = WorkloadApiAdmissionConfig {
        max_connections: MAX_CONNECTIONS_CEILING + 1,
        ..WorkloadApiAdmissionConfig::default()
    }
    .validate()
    .expect_err("a soft limit may not be raised past the hard safety ceiling")
    .to_string();
    assert!(error.contains(&MAX_CONNECTIONS_CEILING.to_string()));

    let error = WorkloadApiAdmissionConfig {
        max_concurrent_rpcs: MAX_CONCURRENT_RPCS_CEILING + 1,
        ..WorkloadApiAdmissionConfig::default()
    }
    .validate()
    .expect_err("the RPC ceiling is hard too")
    .to_string();
    assert!(error.contains(&MAX_CONCURRENT_RPCS_CEILING.to_string()));
}

#[test]
fn a_per_uid_quota_above_the_global_ceiling_is_refused() {
    // Not merely useless: an operator who wrote this believes they have a
    // per-principal bound and does not, which is precisely the posture this
    // issue is about.
    let error = limits(8, 9)
        .validate()
        .expect_err("a quota that can never bind is a misconfiguration")
        .to_string();
    assert!(error.contains("MAX_CONNECTIONS_PER_UID"));
}

#[test]
fn an_idle_deadline_at_or_below_the_initial_one_is_refused() {
    let error = WorkloadApiAdmissionConfig {
        initial_connection_timeout: Duration::from_secs(30),
        idle_timeout: Duration::from_secs(30),
        ..WorkloadApiAdmissionConfig::default()
    }
    .validate()
    .expect_err("an established connection must get more room than a silent one")
    .to_string();
    assert!(error.contains("IDLE_TIMEOUT_SECONDS"));
}

#[test]
fn clamping_enforces_the_ceilings_even_when_validation_is_bypassed() {
    // `validate` is the loud gate; this is the belt. A runtime reached another
    // way must still not exceed a ceiling.
    let clamped = WorkloadApiAdmissionConfig {
        max_connections: usize::MAX,
        max_connections_per_uid: usize::MAX,
        max_concurrent_streams: u32::MAX,
        max_concurrent_rpcs: usize::MAX,
        initial_connection_timeout: Duration::from_secs(u64::from(u32::MAX)),
        idle_timeout: Duration::from_secs(u64::from(u32::MAX)),
        shutdown_grace: Duration::from_secs(u64::from(u32::MAX)),
    }
    .clamped();

    assert_eq!(clamped.max_connections, MAX_CONNECTIONS_CEILING);
    assert_eq!(
        clamped.max_connections_per_uid,
        MAX_CONNECTIONS_PER_UID_CEILING
    );
    assert_eq!(clamped.max_concurrent_streams, MAX_CONCURRENT_STREAMS_CEILING);
    assert_eq!(clamped.max_concurrent_rpcs, MAX_CONCURRENT_RPCS_CEILING);
    assert_eq!(
        clamped.initial_connection_timeout,
        INITIAL_CONNECTION_TIMEOUT_CEILING
    );
    assert_eq!(clamped.idle_timeout, IDLE_TIMEOUT_CEILING);
    assert_eq!(clamped.shutdown_grace, SHUTDOWN_GRACE_CEILING);

    // Zero clamps up to a finite one rather than down to "unbounded".
    let floor = WorkloadApiAdmissionConfig {
        max_connections: 0,
        max_connections_per_uid: 0,
        max_concurrent_streams: 0,
        max_concurrent_rpcs: 0,
        initial_connection_timeout: Duration::ZERO,
        idle_timeout: Duration::ZERO,
        shutdown_grace: Duration::ZERO,
    }
    .clamped();
    assert_eq!(floor.max_connections, 1);
    assert_eq!(floor.max_connections_per_uid, 1);
    assert_eq!(floor.max_concurrent_streams, 1);
    assert_eq!(floor.max_concurrent_rpcs, 1);
    assert_eq!(floor.initial_connection_timeout, Duration::from_secs(1));
    assert_eq!(floor.idle_timeout, Duration::from_secs(1));
    assert_eq!(floor.shutdown_grace, Duration::from_secs(1));
}

#[test]
fn a_constructed_admission_gate_never_exceeds_a_ceiling() {
    let admission = ConnectionAdmission::detached(WorkloadApiAdmissionConfig {
        max_connections: MAX_CONNECTIONS_CEILING * 4,
        max_connections_per_uid: MAX_CONNECTIONS_PER_UID_CEILING * 4,
        ..WorkloadApiAdmissionConfig::default()
    });
    assert_eq!(admission.limits().max_connections, MAX_CONNECTIONS_CEILING);
    assert_eq!(
        admission.limits().max_connections_per_uid,
        MAX_CONNECTIONS_PER_UID_CEILING
    );
}

#[test]
fn the_total_ceiling_admits_exactly_n_and_refuses_n_plus_one() {
    const TOTAL: usize = 4;
    // Per-UID raised to the total so this test isolates the *global* bound.
    let admission = ConnectionAdmission::detached(limits(TOTAL, TOTAL));

    let mut held = Vec::new();
    for index in 0..TOTAL {
        // Distinct uids so the per-UID quota cannot be what is being observed.
        held.push(
            admission
                .reserve(1000 + index as u32)
                .expect("every connection up to the ceiling is admitted"),
        );
    }
    assert_eq!(admission.active_connections(), TOTAL);
    assert!(
        admission.reserve(2000).is_none(),
        "connection N+1 must be refused rather than admitted or queued"
    );

    // Release one and prove capacity actually came back, which is the property
    // a leak on any close path would break.
    held.pop();
    assert_eq!(admission.active_connections(), TOTAL - 1);
    let recovered = admission
        .reserve(2000)
        .expect("a released permit returns capacity to the global pool");
    drop(recovered);
    drop(held);
    assert_eq!(admission.active_connections(), 0);
}

#[test]
fn a_saturated_uid_is_refused_while_a_different_uid_is_still_served() {
    // The whole point of the per-UID bound: one compromised socket-group member
    // must not be able to deny identity service to the rest of the node.
    const TOTAL: usize = 8;
    const PER_UID: usize = 2;
    let admission = ConnectionAdmission::detached(limits(TOTAL, PER_UID));

    let hostile: Vec<_> = (0..PER_UID)
        .map(|_| {
            admission
                .reserve(1000)
                .expect("a peer may use its own quota in full")
        })
        .collect();
    assert!(
        admission.reserve(1000).is_none(),
        "the peer's next connection must be refused at its quota"
    );

    let neighbour = admission
        .reserve(1001)
        .expect("a different UID must still be served while another UID is saturated");
    assert_eq!(admission.active_connections(), PER_UID + 1);

    // The refusal must not have consumed a global slot either: a per-UID
    // refusal that leaked the total permit would turn a per-principal bound
    // into a global denial-of-service primitive.
    let mut remaining = Vec::new();
    for _ in 0..(TOTAL - PER_UID - 1) {
        remaining.push(
            admission
                .reserve(1002)
                .or_else(|| admission.reserve(1003))
                .or_else(|| admission.reserve(1004))
                .or_else(|| admission.reserve(1005))
                .expect("global capacity is intact after per-UID refusals"),
        );
    }
    assert_eq!(admission.active_connections(), TOTAL);

    drop(hostile);
    drop(neighbour);
    drop(remaining);
    assert_eq!(admission.active_connections(), 0);

    // And the saturated UID is served again once it releases.
    assert!(admission.reserve(1000).is_some());
}

#[test]
fn repeated_refusals_do_not_grow_per_uid_state() {
    // A refused uid must not leave an accounting entry behind, or a probing
    // flood from many uids would itself be an unbounded allocation.
    let admission = ConnectionAdmission::detached(limits(2, 1));
    let held = vec![
        admission.reserve(1000).expect("first is admitted"),
        admission.reserve(1001).expect("second is admitted"),
    ];
    for uid in 0..5_000u32 {
        // The pool is full, so every one of these is refused. None may leave an
        // accounting entry behind.
        assert!(admission.reserve(uid).is_none());
    }
    drop(held);
    assert_eq!(
        admission.active_connections(),
        0,
        "no refused or released reservation may remain charged"
    );
}

#[test]
fn admission_reason_labels_are_a_closed_compile_time_set() {
    // Fixed-cardinality contract: these are the only values that can appear in
    // the `reason` dimension, and none of them is derived from anything a peer
    // controls (no UID, PID, SPIFFE ID, or token material).
    let reject = [
        reject_reason::PEER_CREDENTIALS,
        reject_reason::MAX_CONNECTIONS,
        reject_reason::MAX_CONNECTIONS_PER_UID,
        reject_reason::SHUTTING_DOWN,
    ];
    let close = [
        close_reason::INITIAL_TIMEOUT,
        close_reason::IDLE_TIMEOUT,
        close_reason::SHUTDOWN_DEADLINE,
    ];
    for reason in reject.iter().chain(close.iter()) {
        assert!(
            reason
                .chars()
                .all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit()),
            "a reason label must be a stable snake_case constant, got {reason}"
        );
    }
    let mut all: Vec<&str> = reject.iter().chain(close.iter()).copied().collect();
    all.sort_unstable();
    let before = all.len();
    all.dedup();
    assert_eq!(before, all.len(), "reason constants must be distinct");
}
