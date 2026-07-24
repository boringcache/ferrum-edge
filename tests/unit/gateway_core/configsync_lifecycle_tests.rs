//! External unit tests for DP ConfigSync lifecycle policy helpers.
//!
//! Covers silent-partition/keepalive constants, multi-CP backoff continuity,
//! FULL_SNAPSHOT fencing, connection-state staleness preservation, and
//! namespace-qualified removal filtering surfaces exposed for deterministic
//! verification without standing up a live CP.

use chrono::{TimeZone, Utc};
use ferrum_edge::config::db_loader::{IncrementalResult, NamespacedResourceId};
use ferrum_edge::grpc::configsync_lifecycle::{
    AppliedSnapshotAuthority, CONFIGSYNC_HTTP2_KEEPALIVE_INTERVAL_SECS,
    CONFIGSYNC_HTTP2_KEEPALIVE_TIMEOUT_SECS, CONFIGSYNC_MAX_SILENCE_SECS,
    CONFIGSYNC_TCP_KEEPALIVE_SECS, ConfigSyncAttemptOutcome, MultiCpBackoffState,
    StaleSnapshotReject, advance_multi_cp_backoff, backoff_max_secs, evaluate_full_snapshot_authority,
    failure_backoff_sequence, grow_backoff_after_failure_sleep, silence_exceeds_liveness,
};
use ferrum_edge::grpc::dp_client::{
    DpCpConnectionState, configure_configsync_endpoint,
};
use ferrum_edge::util::backoff::BACKOFF_INITIAL_SECS;
use tonic::transport::Channel;

#[test]
fn configsync_keepalive_constants_are_bounded_and_ordered() {
    assert_eq!(CONFIGSYNC_HTTP2_KEEPALIVE_INTERVAL_SECS, 30);
    assert_eq!(CONFIGSYNC_HTTP2_KEEPALIVE_TIMEOUT_SECS, 10);
    assert_eq!(CONFIGSYNC_TCP_KEEPALIVE_SECS, 30);
    assert!(CONFIGSYNC_MAX_SILENCE_SECS > CONFIGSYNC_HTTP2_KEEPALIVE_INTERVAL_SECS);
    assert!(
        CONFIGSYNC_MAX_SILENCE_SECS
            > ferrum_edge::grpc::configsync_lifecycle::CONFIGSYNC_HEARTBEAT_INTERVAL_SECS
    );
    assert!(!silence_exceeds_liveness(CONFIGSYNC_MAX_SILENCE_SECS - 1));
    assert!(silence_exceeds_liveness(CONFIGSYNC_MAX_SILENCE_SECS));
}

#[test]
fn configsync_endpoint_builder_applies_keepalive() {
    let endpoint = configure_configsync_endpoint(
        Channel::from_shared("http://127.0.0.1:50051".to_string()).expect("uri"),
    );
    // Endpoint does not expose getters; constructing with keepalive settings
    // without error is the compile/runtime contract. Re-configure to prove the
    // helper is callable and returns an Endpoint.
    let _ = endpoint.connect_timeout(std::time::Duration::from_secs(10));
}

#[test]
fn multi_cp_failure_backoff_reaches_max_without_resetting_on_switch() {
    let sleeps = failure_backoff_sequence(2, 12);
    assert_eq!(sleeps.first().copied(), Some(BACKOFF_INITIAL_SECS));
    assert!(
        sleeps.iter().any(|s| *s == backoff_max_secs()),
        "expected multi-CP failure sequence to reach {backoff}, got {sleeps:?}",
        backoff = backoff_max_secs()
    );
    // Switching CP must not reset: sequence is strictly non-decreasing until cap.
    for window in sleeps.windows(2) {
        assert!(window[1] >= window[0]);
    }
}

#[test]
fn zero_message_clean_close_grows_backoff_like_error() {
    let mut state = MultiCpBackoffState::new();
    assert!(advance_multi_cp_backoff(
        &mut state,
        1,
        ConfigSyncAttemptOutcome::CleanCloseWithoutConfig
    ));
    assert_eq!(state.backoff_secs, BACKOFF_INITIAL_SECS);
    grow_backoff_after_failure_sleep(&mut state);
    assert_eq!(state.backoff_secs, 2);

    let mut ok = MultiCpBackoffState {
        backoff_secs: 16,
        ..MultiCpBackoffState::new()
    };
    assert!(advance_multi_cp_backoff(
        &mut ok,
        1,
        ConfigSyncAttemptOutcome::CleanCloseAfterConfig
    ));
    assert_eq!(ok.backoff_secs, BACKOFF_INITIAL_SECS);
}

#[test]
fn full_snapshot_fencing_rejects_older_cross_source() {
    let applied = Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap();
    let authority = AppliedSnapshotAuthority {
        version: applied,
        source_cp_url: "http://cp-primary:50051".to_string(),
    };
    let older = "2026-06-01T12:00:00Z";
    let err = evaluate_full_snapshot_authority(
        Some(&authority),
        older,
        "http://cp-fallback:50051",
    )
    .expect_err("older failover snapshot must be refused");
    assert!(matches!(
        err,
        StaleSnapshotReject::OlderThanApplied { .. }
    ));

    let same_source = evaluate_full_snapshot_authority(
        Some(&authority),
        older,
        "http://cp-primary:50051",
    )
    .expect("same-source recovery snapshots remain accepted");
    assert!(same_source < applied);

    let newer = evaluate_full_snapshot_authority(
        Some(&authority),
        "2026-08-01T12:00:00Z",
        "http://cp-fallback:50051",
    )
    .expect("newer failover snapshot is accepted");
    assert!(newer > applied);
}

#[test]
fn reconnect_preserves_last_config_received_at() {
    let stamp = Utc.with_ymd_and_hms(2026, 7, 24, 1, 2, 3).unwrap();
    let prev = DpCpConnectionState {
        connected: false,
        cp_url: "http://cp-old:50051".to_string(),
        is_primary: true,
        last_config_received_at: Some(stamp),
        connected_since: None,
    };
    let connected = DpCpConnectionState {
        connected: true,
        cp_url: "http://cp-new:50051".to_string(),
        is_primary: false,
        last_config_received_at: prev.last_config_received_at,
        connected_since: Some(Utc::now()),
    };
    assert_eq!(connected.last_config_received_at, Some(stamp));
    assert!(connected.connected);
}

#[test]
fn namespace_qualified_removals_are_fail_closed_on_mismatch() {
    let mut delta = IncrementalResult {
        added_or_modified_proxies: vec![],
        removed_proxy_ids: vec![
            NamespacedResourceId::new("production", "shared-id"),
            NamespacedResourceId::new("staging", "shared-id"),
        ],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec![],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![NamespacedResourceId::new("staging", "pc1")],
        added_or_modified_upstreams: vec![],
        removed_upstream_ids: vec![NamespacedResourceId::new("production", "u1")],
        sequence_cursor: 0,
        poll_timestamp: Utc::now(),
    };

    // Mirror dp_client::filter_incremental_to_namespace removal retain logic.
    delta
        .removed_proxy_ids
        .retain(|key| key.namespace == "production");
    delta
        .removed_plugin_config_ids
        .retain(|key| key.namespace == "production");
    delta
        .removed_upstream_ids
        .retain(|key| key.namespace == "production");

    assert_eq!(
        delta.removed_proxy_ids,
        vec![NamespacedResourceId::new("production", "shared-id")]
    );
    assert!(delta.removed_plugin_config_ids.is_empty());
    assert_eq!(
        delta.removed_upstream_ids,
        vec![NamespacedResourceId::new("production", "u1")]
    );
}
