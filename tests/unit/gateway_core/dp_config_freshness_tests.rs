//! Bounded DP last-known-good configuration age (issue #3726).
//!
//! Every test drives a non-publishing [`DpConfigFreshness`] from an explicit
//! monotonic epoch, so the whole state machine is deterministic: no sleeps, no
//! wall clock, and no dependence on the process-global admission gate that only
//! the installed DP tracker writes.

use std::time::{Duration, Instant};

use ferrum_edge::dp_config_freshness::{
    CP_RECONNECT_GRACE, DpConfigFreshness, FreshnessReason, StaleAction,
};

const MAX_STALE: Duration = Duration::from_secs(600);

/// Fixed monotonic base plus a helper for "t seconds after start".
fn epoch() -> Instant {
    Instant::now()
}

fn at(epoch: Instant, seconds: u64) -> Instant {
    epoch + Duration::from_secs(seconds)
}

/// A tracker that has already accepted a snapshot at t=0 and lost every CP at
/// t=0 — the total-outage shape used by most threshold assertions.
fn applied_then_disconnected(epoch: Instant, action: StaleAction) -> DpConfigFreshness {
    let freshness = DpConfigFreshness::new_at(epoch, MAX_STALE, action);
    freshness.record_cp_connected();
    freshness.record_snapshot_applied_at(epoch);
    freshness.record_cp_disconnected_at(epoch);
    freshness
}

#[test]
fn ready_before_the_threshold_and_stale_exactly_at_it() {
    let epoch = epoch();
    let freshness = applied_then_disconnected(epoch, StaleAction::FailClosed);

    let just_before = freshness.evaluate_at(at(epoch, 599));
    assert!(!just_before.stale, "must stay fresh one second before the bound");
    assert!(!just_before.new_traffic_blocked);
    assert_eq!(just_before.reason, FreshnessReason::CpDisconnected.as_str());
    assert_eq!(just_before.snapshot_age_seconds, 599);

    let at_threshold = freshness.evaluate_at(at(epoch, 600));
    assert!(at_threshold.stale, "must go stale at the bound itself");
    assert!(at_threshold.new_traffic_blocked);
    assert_eq!(at_threshold.reason, FreshnessReason::SnapshotStale.as_str());
    assert_eq!(at_threshold.stale_transitions_total, 1);
}

#[test]
fn heartbeats_reconnects_rejections_and_apply_failures_do_not_reset_the_age() {
    let epoch = epoch();
    let freshness = applied_then_disconnected(epoch, StaleAction::FailClosed);

    // Everything short of an applied snapshot: repeated failover attempts
    // (which the DP records once per unreachable CP URL), a refused payload,
    // and a snapshot that was admitted and then failed to apply. No heartbeat
    // hook exists at all — heartbeat frames never reach this module.
    for second in [30, 120, 300, 599] {
        freshness.record_cp_disconnected_at(at(epoch, second));
    }
    freshness.record_snapshot_rejected();
    freshness.record_snapshot_apply_failed();

    let snapshot = freshness.evaluate_at(at(epoch, 600));
    assert!(
        snapshot.stale,
        "none of those events may push the boundary out"
    );
    assert_eq!(snapshot.snapshot_age_seconds, 600);
    assert_eq!(snapshot.rejected_total, 1);
    assert_eq!(snapshot.apply_failed_total, 1);
    assert_eq!(snapshot.applied_total, 1, "no new snapshot was applied");
}

#[test]
fn reconnecting_alone_does_not_clear_a_raised_stale_state() {
    let epoch = epoch();
    let freshness = applied_then_disconnected(epoch, StaleAction::FailClosed);
    assert!(freshness.evaluate_at(at(epoch, 600)).stale);

    // Transport is back and the CP even sends payloads — but every one of them
    // is refused or fails to apply. Recovery must not happen.
    freshness.record_cp_connected();
    freshness.record_snapshot_rejected();
    freshness.record_snapshot_apply_failed();

    let snapshot = freshness.evaluate_at(at(epoch, 601));
    assert!(snapshot.stale, "recovery requires an APPLIED snapshot");
    assert!(snapshot.new_traffic_blocked);
    assert!(snapshot.cp_connected);
    assert_eq!(snapshot.reason, FreshnessReason::SnapshotStale.as_str());
}

#[test]
fn an_applied_snapshot_resets_the_age_and_restores_admission() {
    let epoch = epoch();
    let freshness = applied_then_disconnected(epoch, StaleAction::FailClosed);
    assert!(freshness.evaluate_at(at(epoch, 600)).stale);

    freshness.record_cp_connected();
    freshness.record_snapshot_applied_at(at(epoch, 610));

    let snapshot = freshness.evaluate_at(at(epoch, 611));
    assert!(!snapshot.stale, "an applied snapshot clears the sticky flag");
    assert!(!snapshot.new_traffic_blocked);
    assert_eq!(snapshot.snapshot_age_seconds, 1);
    assert_eq!(snapshot.reason, FreshnessReason::Ok.as_str());
    assert_eq!(snapshot.applied_total, 2);
    assert_eq!(
        snapshot.stale_transitions_total, 1,
        "the earlier transition stays counted"
    );
}

#[test]
fn losing_one_cp_while_another_stays_authoritative_is_not_stale() {
    let epoch = epoch();
    let freshness = DpConfigFreshness::new_at(epoch, MAX_STALE, StaleAction::FailClosed);
    freshness.record_cp_connected();
    freshness.record_snapshot_applied_at(epoch);

    // Primary drops far past the bound; the DP fails over to a fallback that
    // applies a snapshot. The config is quiet afterwards, so the age keeps
    // growing well beyond the bound while connected — which is not staleness.
    freshness.record_cp_disconnected_at(at(epoch, 700));
    freshness.record_cp_connected();
    freshness.record_snapshot_applied_at(at(epoch, 701));

    let snapshot = freshness.evaluate_at(at(epoch, 5_000));
    assert!(
        !snapshot.stale,
        "a connected DP is still receiving revocations"
    );
    assert!(!snapshot.new_traffic_blocked);
    assert_eq!(snapshot.cp_disconnected_seconds, 0);
    assert_eq!(snapshot.snapshot_age_seconds, 4_299);
    assert_eq!(snapshot.reason, FreshnessReason::Ok.as_str());
}

#[test]
fn a_routine_reconnect_does_not_trip_an_already_aged_snapshot() {
    let epoch = epoch();
    let freshness = DpConfigFreshness::new_at(epoch, MAX_STALE, StaleAction::FailClosed);
    freshness.record_cp_connected();
    freshness.record_snapshot_applied_at(epoch);

    // Quiet config: the snapshot is already older than the bound when a CP
    // restart drops the stream for a second. The grace keeps the fleet serving.
    freshness.record_cp_disconnected_at(at(epoch, 5_000));
    let during_blip = freshness.evaluate_at(at(epoch, 5_001));
    assert!(!during_blip.stale, "a sub-grace reconnect must not fail closed");
    assert!(!during_blip.new_traffic_blocked);

    // The same outage, once it outlives the grace, does trip.
    let after_grace = freshness.evaluate_at(at(epoch, 5_000) + CP_RECONNECT_GRACE);
    assert!(after_grace.stale);
    assert!(after_grace.cp_disconnected_seconds >= CP_RECONNECT_GRACE.as_secs());
}

#[test]
fn repeated_failover_attempts_do_not_restart_the_outage_window() {
    let epoch = epoch();
    let freshness = DpConfigFreshness::new_at(epoch, MAX_STALE, StaleAction::FailClosed);
    freshness.record_cp_connected();
    freshness.record_snapshot_applied_at(epoch);

    // Every CP URL is unreachable, so the DP records a disconnect per attempt.
    // If each attempt restarted the outage stamp, the grace would never expire.
    for second in 600..640 {
        freshness.record_cp_disconnected_at(at(epoch, second));
    }

    let snapshot = freshness.evaluate_at(at(epoch, 640));
    assert!(snapshot.stale);
    assert_eq!(snapshot.cp_disconnected_seconds, 40);
}

#[test]
fn readiness_only_degrades_readiness_without_blocking_traffic() {
    let epoch = epoch();
    let freshness = applied_then_disconnected(epoch, StaleAction::ReadinessOnly);

    let snapshot = freshness.evaluate_at(at(epoch, 600));
    assert!(snapshot.stale, "readiness still degrades");
    assert!(
        !snapshot.new_traffic_blocked,
        "the compatibility mode keeps admitting new traffic"
    );
    assert_eq!(snapshot.stale_action, "readiness_only");
}

#[test]
fn startup_without_any_snapshot_is_bounded_from_process_start() {
    let epoch = epoch();
    let freshness = DpConfigFreshness::new_at(epoch, MAX_STALE, StaleAction::FailClosed);

    let before = freshness.evaluate_at(at(epoch, 599));
    assert!(!before.stale);
    assert!(!before.applied_snapshot);
    assert_eq!(before.reason, FreshnessReason::AwaitingFirstSnapshot.as_str());
    assert_eq!(before.snapshot_age_seconds, 599);

    let after = freshness.evaluate_at(at(epoch, 600));
    assert!(
        after.stale,
        "a DP that never reached a CP is bounded by the same rule"
    );
    assert!(after.new_traffic_blocked);
}

#[test]
fn a_disabled_bound_never_goes_stale() {
    let epoch = epoch();
    let freshness = DpConfigFreshness::new_at(epoch, Duration::ZERO, StaleAction::FailClosed);
    freshness.record_cp_connected();
    freshness.record_snapshot_applied_at(epoch);
    freshness.record_cp_disconnected_at(at(epoch, 1));

    assert!(!freshness.enabled());
    let snapshot = freshness.evaluate_at(at(epoch, 10_000_000));
    assert!(!snapshot.stale, "0 is the documented unbounded opt-in");
    assert!(!snapshot.new_traffic_blocked);
    assert_eq!(snapshot.max_stale_seconds, 0);
}

#[test]
fn the_reconnect_grace_never_widens_a_small_configured_bound() {
    let epoch = epoch();
    let freshness =
        DpConfigFreshness::new_at(epoch, Duration::from_secs(5), StaleAction::FailClosed);
    freshness.record_cp_connected();
    freshness.record_snapshot_applied_at(epoch);
    freshness.record_cp_disconnected_at(epoch);

    assert_eq!(freshness.reconnect_grace(), Duration::from_secs(5));
    assert!(!freshness.evaluate_at(at(epoch, 4)).stale);
    assert!(freshness.evaluate_at(at(epoch, 5)).stale);
}

#[test]
fn reason_labels_distinguish_the_four_operator_states() {
    let epoch = epoch();
    let freshness = DpConfigFreshness::new_at(epoch, MAX_STALE, StaleAction::FailClosed);
    freshness.record_cp_connected();
    freshness.record_snapshot_applied_at(epoch);
    assert_eq!(
        freshness.evaluate_at(at(epoch, 1)).reason,
        FreshnessReason::Ok.as_str()
    );

    freshness.record_snapshot_rejected();
    assert_eq!(
        freshness.evaluate_at(at(epoch, 2)).reason,
        FreshnessReason::SnapshotRejected.as_str()
    );

    freshness.record_snapshot_apply_failed();
    assert_eq!(
        freshness.evaluate_at(at(epoch, 3)).reason,
        FreshnessReason::SnapshotApplyFailed.as_str()
    );

    freshness.record_cp_disconnected_at(at(epoch, 4));
    assert_eq!(
        freshness.evaluate_at(at(epoch, 5)).reason,
        FreshnessReason::CpDisconnected.as_str(),
        "losing the CP outranks the last payload outcome"
    );

    assert_eq!(
        freshness.evaluate_at(at(epoch, 600)).reason,
        FreshnessReason::SnapshotStale.as_str(),
        "staleness outranks everything else"
    );
}

#[test]
fn an_age_that_predates_the_epoch_cannot_underflow() {
    // Build the tracker with an epoch in the future of `base` rather than
    // subtracting from an `Instant` (which panics below the clock's origin).
    let base = Instant::now();
    let epoch = base + Duration::from_secs(60);
    let freshness = applied_then_disconnected(epoch, StaleAction::FailClosed);

    // A monotonic clock cannot actually run backwards, but the arithmetic must
    // saturate rather than wrap if a caller ever hands back an earlier instant.
    let snapshot = freshness.evaluate_at(base);
    assert_eq!(snapshot.snapshot_age_seconds, 0);
    assert!(!snapshot.stale);
}

#[test]
fn stale_action_parsing_is_closed_and_fails_closed() {
    assert_eq!(
        StaleAction::parse("fail_closed").expect("fail_closed"),
        StaleAction::FailClosed
    );
    assert_eq!(
        StaleAction::parse("  FAIL-CLOSED  ").expect("case/dash insensitive"),
        StaleAction::FailClosed
    );
    assert_eq!(
        StaleAction::parse("readiness_only").expect("readiness_only"),
        StaleAction::ReadinessOnly
    );
    assert_eq!(StaleAction::FailClosed.as_str(), "fail_closed");
    assert_eq!(StaleAction::ReadinessOnly.as_str(), "readiness_only");

    let err = StaleAction::parse("allow").expect_err("unknown values must be rejected");
    assert!(err.contains("FERRUM_DP_CONFIG_STALE_ACTION"));
    assert!(StaleAction::parse("").is_err());
}

#[test]
fn the_snapshot_projection_carries_no_unbounded_identifiers() {
    let epoch = epoch();
    let freshness = applied_then_disconnected(epoch, StaleAction::FailClosed);
    let snapshot = freshness.evaluate_at(at(epoch, 600));

    let value = serde_json::to_value(&snapshot).expect("serializable");
    let object = value.as_object().expect("object");
    // Every field is a boolean, a number, or one of the two closed label sets.
    for (key, field) in object {
        let closed_label = matches!(key.as_str(), "reason" | "stale_action");
        assert!(
            field.is_boolean() || field.is_number() || closed_label,
            "unexpected free-form field `{key}` in the DP freshness projection"
        );
    }
    assert!(
        ["ok", "awaiting_first_snapshot", "cp_disconnected", "snapshot_stale",
         "snapshot_rejected", "snapshot_apply_failed"]
            .contains(&snapshot.reason)
    );
    assert!(["fail_closed", "readiness_only"].contains(&snapshot.stale_action));
}
