//! Unit coverage for CP-side mesh slice drift tracking (issue #3265).

use chrono::{Duration, TimeZone, Utc};
use ferrum_edge::grpc::mesh_slice_drift::{
    MESH_SLICE_DRIFT_MAX_ENTRIES, MESH_SLICE_DRIFT_MAX_REASON_CHARS, MeshSliceConvergenceState,
    MeshSliceDriftAdmitError, MeshSliceDriftRegistry, sanitize_reason,
};

#[test]
fn desired_sent_ack_converges_and_drift_flags_clear() {
    let registry = MeshSliceDriftRegistry::new();
    let connected_at = Utc.with_ymd_and_hms(2026, 8, 2, 12, 0, 0).unwrap();
    registry
        .open_session("dp-a", "ferrum", connected_at, Some("v1"))
        .expect("open");
    registry
        .record_sent("dp-a", connected_at, "v1", connected_at)
        .expect("sent");
    registry
        .record_status("dp-a", "v1", None, connected_at + Duration::seconds(1))
        .expect("ack");

    let snap = registry.snapshot();
    assert_eq!(snap.summary.tracked, 1);
    assert_eq!(snap.summary.converged, 1);
    let entry = &snap.data_planes[0];
    assert_eq!(entry.convergence, MeshSliceConvergenceState::Converged);
    assert!(!entry.drift.desired_vs_sent);
    assert!(!entry.drift.desired_vs_acknowledged);
    assert!(!entry.drift.sent_vs_acknowledged);
}

#[test]
fn desired_ahead_of_ack_marks_drifted() {
    let registry = MeshSliceDriftRegistry::new();
    let connected_at = Utc.with_ymd_and_hms(2026, 8, 2, 12, 0, 0).unwrap();
    registry
        .open_session("dp-a", "ferrum", connected_at, Some("v1"))
        .unwrap();
    registry
        .record_sent("dp-a", connected_at, "v1", connected_at)
        .unwrap();
    registry
        .record_status("dp-a", "v1", None, connected_at)
        .unwrap();
    registry.set_desired_for_namespace("ferrum", "v2", connected_at + Duration::seconds(5));

    let entry = &registry.snapshot().data_planes[0];
    assert_eq!(entry.convergence, MeshSliceConvergenceState::Drifted);
    assert!(entry.drift.desired_vs_sent);
    assert!(entry.drift.desired_vs_acknowledged);
}

#[test]
fn nack_reason_is_sanitized_and_marks_rejecting() {
    let registry = MeshSliceDriftRegistry::new();
    let connected_at = Utc.with_ymd_and_hms(2026, 8, 2, 12, 0, 0).unwrap();
    registry
        .open_session("dp-a", "ferrum", connected_at, Some("v1"))
        .unwrap();
    let raw = format!(
        "bad\nslice{}",
        "x".repeat(MESH_SLICE_DRIFT_MAX_REASON_CHARS + 8)
    );
    registry
        .record_status("dp-a", "v1", Some(&raw), connected_at)
        .unwrap();

    let entry = &registry.snapshot().data_planes[0];
    assert_eq!(entry.convergence, MeshSliceConvergenceState::Rejecting);
    let rejected = entry.rejected.as_ref().expect("rejected");
    assert!(!rejected.reason.contains('\n'));
    assert!(rejected.reason.contains("(truncated)"));
    assert_eq!(sanitize_reason("\u{0000}"), "unspecified");
}

#[test]
fn replacement_session_and_stale_disconnect_are_generation_safe() {
    let registry = MeshSliceDriftRegistry::new();
    let first = Utc.with_ymd_and_hms(2026, 8, 2, 12, 0, 0).unwrap();
    let second = Utc.with_ymd_and_hms(2026, 8, 2, 12, 0, 1).unwrap();
    registry
        .open_session("dp-a", "ferrum", first, Some("v1"))
        .unwrap();
    registry
        .open_session("dp-a", "ferrum", second, Some("v2"))
        .unwrap();
    registry.mark_disconnected("dp-a", first);
    assert!(registry.snapshot().data_planes[0].connected);

    registry
        .record_sent("dp-a", first, "v-stale", second)
        .unwrap();
    assert_eq!(
        registry.snapshot().data_planes[0]
            .sent
            .as_ref()
            .map(|s| s.version.as_str()),
        None
    );

    registry.record_sent("dp-a", second, "v2", second).unwrap();
    assert_eq!(
        registry.snapshot().data_planes[0]
            .sent
            .as_ref()
            .map(|s| s.version.as_str()),
        Some("v2")
    );
}

#[test]
fn disconnect_retention_and_reap() {
    let registry = MeshSliceDriftRegistry::new();
    let connected_at = Utc.with_ymd_and_hms(2026, 8, 2, 12, 0, 0).unwrap();
    registry
        .open_session("dp-a", "ferrum", connected_at, Some("v1"))
        .unwrap();
    registry.mark_disconnected("dp-a", connected_at);
    assert_eq!(
        registry.snapshot().data_planes[0].convergence,
        MeshSliceConvergenceState::Disconnected
    );

    let removed = registry.reap_expired(
        connected_at + Duration::seconds(301),
        Duration::seconds(300),
    );
    assert_eq!(removed, 1);
    assert!(registry.is_empty());
}

#[test]
fn multiple_dps_and_cardinality_cap() {
    let registry = MeshSliceDriftRegistry::new();
    let base = Utc.with_ymd_and_hms(2026, 8, 2, 12, 0, 0).unwrap();
    for i in 0..3 {
        registry
            .open_session(&format!("dp-{i}"), "ferrum", base, Some("v1"))
            .unwrap();
    }
    assert_eq!(registry.snapshot().summary.tracked, 3);

    // Fill to the hard cap with connected sessions (no disconnected victims).
    for i in 3..MESH_SLICE_DRIFT_MAX_ENTRIES {
        let at = base + Duration::seconds(i as i64);
        registry
            .open_session(&format!("fill-{i}"), "ferrum", at, Some("v1"))
            .unwrap();
    }
    let err = registry
        .open_session("overflow", "ferrum", base + Duration::hours(1), Some("v9"))
        .expect_err("full connected registry");
    assert_eq!(err, MeshSliceDriftAdmitError::CardinalityExceeded);

    // Disconnect one row; the next insert should evict that victim.
    registry.mark_disconnected("dp-0", base);
    registry
        .open_session("recovered", "ferrum", base + Duration::hours(2), Some("v9"))
        .expect("evict disconnected");
    assert!(
        registry
            .snapshot()
            .data_planes
            .iter()
            .any(|e| e.node_id == "recovered")
    );
}

#[test]
fn malformed_status_fails_closed_with_field_diagnostics() {
    let registry = MeshSliceDriftRegistry::new();
    let err = registry
        .record_status("missing", "", None, Utc::now())
        .expect_err("empty version");
    assert_eq!(err, MeshSliceDriftAdmitError::EmptyVersion);
    assert_eq!(err.field_name(), "version");

    let err = registry
        .record_status("missing", "v1", None, Utc::now())
        .expect_err("unknown");
    assert_eq!(err, MeshSliceDriftAdmitError::UnknownNode);
    assert_eq!(err.field_name(), "node_id");
}

#[test]
fn reload_updates_desired_for_partitioned_dp() {
    let registry = MeshSliceDriftRegistry::new();
    let connected_at = Utc.with_ymd_and_hms(2026, 8, 2, 12, 0, 0).unwrap();
    registry
        .open_session("dp-a", "ferrum", connected_at, Some("v1"))
        .unwrap();
    registry
        .record_sent("dp-a", connected_at, "v1", connected_at)
        .unwrap();
    registry
        .record_status("dp-a", "v1", None, connected_at)
        .unwrap();
    registry.mark_disconnected("dp-a", connected_at);
    registry.set_desired_all("v-deleted", connected_at + Duration::seconds(10));

    let entry = &registry.snapshot().data_planes[0];
    assert_eq!(
        entry.desired.as_ref().map(|d| d.version.as_str()),
        Some("v-deleted")
    );
    assert_eq!(entry.convergence, MeshSliceConvergenceState::Disconnected);
    assert!(entry.drift.desired_vs_acknowledged);
}
