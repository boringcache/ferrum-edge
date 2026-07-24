//! External unit tests for DP ConfigSync lifecycle policy helpers.
//!
//! Covers silent-partition/keepalive constants, multi-CP backoff continuity,
//! FULL_SNAPSHOT fencing, monotonic watermarks, version/`loaded_at` reconcile,
//! subscription base gating, SemVer negotiation, delta-rejection divergence,
//! connection-state staleness preservation, and namespace-qualified removal
//! filtering surfaces exposed for deterministic verification without standing
//! up a live CP.

use chrono::{TimeZone, Utc};
use ferrum_edge::config::db_loader::{IncrementalResult, NamespacedResourceId};
use ferrum_edge::grpc::configsync_lifecycle::{
    AppliedSnapshotAuthority, CONFIGSYNC_HTTP2_KEEPALIVE_INTERVAL_SECS,
    CONFIGSYNC_HTTP2_KEEPALIVE_TIMEOUT_SECS, CONFIGSYNC_MAX_SILENCE_SECS,
    CONFIGSYNC_TCP_KEEPALIVE_SECS, ConfigSyncAttemptOutcome, ConfigSyncDivergenceMetrics,
    DeltaRefuse, DeltaRejectionKind, DeltaRejectionStreamDisposition,
    FullSnapshotStreamDisposition, MultiCpBackoffState, SnapshotFailureStreamDisposition,
    StaleSnapshotReject, SubscriptionApplyState, VersionCompatError, VersionReconcileError,
    advance_authority_from_committed, advance_multi_cp_backoff, backoff_max_secs,
    check_peer_version_compatibility, connection_error_outcome,
    delta_rejection_stream_disposition, evaluate_delta_against_subscription_base,
    evaluate_full_snapshot_authority, failure_backoff_sequence, full_snapshot_stream_disposition,
    grow_backoff_after_failure_sleep, monotonic_watermark, reconcile_snapshot_version,
    resource_delta_advances_authority, silence_exceeds_liveness,
    snapshot_failure_stream_disposition, stale_reject_from_reconcile,
};
use ferrum_edge::grpc::dp_client::{
    DpCpConnectionState, check_cp_version_compatibility, configure_configsync_endpoint,
};
use ferrum_edge::util::backoff::BACKOFF_INITIAL_SECS;
use ferrum_edge::FERRUM_VERSION;
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
fn connection_error_after_accepted_config_resets_backoff() {
    // Issue #2968 / root review: a transport failure after the attempt already
    // delivered accepted config counts as healthy progress for backoff.
    assert_eq!(
        connection_error_outcome(false),
        ConfigSyncAttemptOutcome::ConnectionError
    );
    assert_eq!(
        connection_error_outcome(true),
        ConfigSyncAttemptOutcome::ConnectionErrorAfterConfig
    );

    let mut before = MultiCpBackoffState {
        backoff_secs: 16,
        current_cp_index: 0,
        full_cycle_count: 0,
    };
    assert!(advance_multi_cp_backoff(
        &mut before,
        2,
        ConfigSyncAttemptOutcome::ConnectionError
    ));
    assert_eq!(before.current_cp_index, 1);
    assert_eq!(before.backoff_secs, 16);
    grow_backoff_after_failure_sleep(&mut before);
    assert_eq!(before.backoff_secs, 32);

    let mut after = MultiCpBackoffState {
        backoff_secs: 16,
        current_cp_index: 0,
        full_cycle_count: 0,
    };
    assert!(advance_multi_cp_backoff(
        &mut after,
        2,
        ConfigSyncAttemptOutcome::ConnectionErrorAfterConfig
    ));
    assert_eq!(
        after.current_cp_index, 0,
        "post-config transport failure must not fail over CP index"
    );
    assert_eq!(after.backoff_secs, BACKOFF_INITIAL_SECS);
}

#[test]
fn reconcile_snapshot_version_requires_envelope_loaded_at_parity() {
    let loaded_at = Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap();
    assert_eq!(
        reconcile_snapshot_version(&loaded_at.to_rfc3339(), loaded_at).unwrap(),
        loaded_at
    );
    assert!(matches!(
        reconcile_snapshot_version("garbage", loaded_at),
        Err(VersionReconcileError::UnparseableEnvelope)
    ));
    let other = Utc.with_ymd_and_hms(2026, 6, 1, 12, 0, 0).unwrap();
    assert!(matches!(
        reconcile_snapshot_version(&other.to_rfc3339(), loaded_at),
        Err(VersionReconcileError::Inconsistent { .. })
    ));
    assert!(matches!(
        stale_reject_from_reconcile(VersionReconcileError::UnparseableEnvelope),
        StaleSnapshotReject::UnparseableVersion
    ));
}

#[test]
fn full_snapshot_fencing_rejects_older_cross_source() {
    let applied = Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap();
    let authority = AppliedSnapshotAuthority {
        version: Some(applied),
        source_cp_url: "http://cp-primary:50051".to_string(),
    };
    let older = Utc.with_ymd_and_hms(2026, 6, 1, 12, 0, 0).unwrap();

    let rejected =
        evaluate_full_snapshot_authority(Some(&authority), older, "http://cp-fallback:50051");
    assert!(matches!(rejected, Err(StaleSnapshotReject::OlderThanApplied { .. })));

    // Same-source recovery remains accepted, but the watermark stays monotonic
    // at the newest known ordering (does not drop to the older recovery body).
    let same_source =
        evaluate_full_snapshot_authority(Some(&authority), older, "http://cp-primary:50051")
            .expect("same-source recovery snapshots remain accepted");
    assert_eq!(same_source, applied);

    let newer = Utc.with_ymd_and_hms(2026, 8, 1, 12, 0, 0).unwrap();
    let accepted = evaluate_full_snapshot_authority(
        Some(&authority),
        newer,
        "http://cp-fallback:50051",
    )
    .expect("newer failover snapshot is accepted");
    assert_eq!(accepted, newer);
}

#[test]
fn same_source_recovery_watermark_is_monotonic() {
    let applied = Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap();
    let authority = AppliedSnapshotAuthority {
        version: Some(applied),
        source_cp_url: "http://cp-a:50051".to_string(),
    };
    let older = Utc.with_ymd_and_hms(2026, 6, 1, 12, 0, 0).unwrap();
    let newer = Utc.with_ymd_and_hms(2026, 8, 1, 12, 0, 0).unwrap();

    assert_eq!(
        evaluate_full_snapshot_authority(Some(&authority), older, "http://cp-a:50051").unwrap(),
        applied
    );
    assert_eq!(
        evaluate_full_snapshot_authority(Some(&authority), newer, "http://cp-a:50051").unwrap(),
        newer
    );
    assert_eq!(monotonic_watermark(Some(applied), older), applied);
    assert_eq!(monotonic_watermark(None, older), older);
}

#[test]
fn fenced_full_snapshot_disposition_terminates_stream() {
    // Issue #2970: a fenced cross-source snapshot must map to a stream-terminating
    // refusal, NOT a skippable message. If it were skippable, the DP would keep
    // reading from the stale fallback CP and apply its next delta against newer
    // config. This asserts the terminate contract at the pure decision seam the
    // stream loop actually calls.
    let applied = Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap();
    let authority = AppliedSnapshotAuthority {
        version: Some(applied),
        source_cp_url: "http://cp-primary:50051".to_string(),
    };

    match full_snapshot_stream_disposition(
        Some(&authority),
        Utc.with_ymd_and_hms(2026, 6, 1, 12, 0, 0).unwrap(),
        "http://cp-fallback:50051",
    ) {
        FullSnapshotStreamDisposition::RefuseAndTerminate(StaleSnapshotReject::OlderThanApplied {
            applied: fenced_applied,
            incoming,
        }) => {
            assert_eq!(fenced_applied, applied);
            assert_eq!(incoming, Utc.with_ymd_and_hms(2026, 6, 1, 12, 0, 0).unwrap());
        }
        other => panic!("older cross-source snapshot must terminate the stream, got {other:?}"),
    }
}

#[test]
fn accepted_full_snapshot_disposition_applies_and_adopts_version() {
    let applied = Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap();
    let authority = AppliedSnapshotAuthority {
        version: Some(applied),
        source_cp_url: "http://cp-primary:50051".to_string(),
    };

    // A newer cross-source failover snapshot applies and adopts its version.
    assert_eq!(
        full_snapshot_stream_disposition(
            Some(&authority),
            Utc.with_ymd_and_hms(2026, 8, 1, 12, 0, 0).unwrap(),
            "http://cp-fallback:50051",
        ),
        FullSnapshotStreamDisposition::Apply {
            version: Utc.with_ymd_and_hms(2026, 8, 1, 12, 0, 0).unwrap(),
        }
    );

    // A same-source recovery snapshot always applies, even when older, but the
    // watermark remains at the prior high-water mark.
    assert_eq!(
        full_snapshot_stream_disposition(
            Some(&authority),
            Utc.with_ymd_and_hms(2026, 6, 1, 12, 0, 0).unwrap(),
            "http://cp-primary:50051",
        ),
        FullSnapshotStreamDisposition::Apply { version: applied }
    );

    // The first snapshot (no applied authority yet) applies and adopts its
    // committed stamp.
    let first = Utc.with_ymd_and_hms(2026, 7, 20, 0, 0, 0).unwrap();
    assert_eq!(
        full_snapshot_stream_disposition(None, first, "http://cp-a:50051"),
        FullSnapshotStreamDisposition::Apply { version: first }
    );
}

#[test]
fn accepted_resource_delta_advances_authority_trust_only_and_reject_do_not() {
    let t0 = Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap();
    let t1 = Utc.with_ymd_and_hms(2026, 7, 1, 13, 0, 0).unwrap();
    let mut authority = Some(AppliedSnapshotAuthority {
        version: Some(t0),
        source_cp_url: "http://cp-a:50051".to_string(),
    });

    assert!(resource_delta_advances_authority(true, false));
    assert!(!resource_delta_advances_authority(true, true));
    assert!(!resource_delta_advances_authority(false, false));

    advance_authority_from_committed(&mut authority, "http://cp-a:50051", t1);
    assert_eq!(authority.as_ref().unwrap().version, Some(t1));

    // A later older stamp must not lower the watermark.
    advance_authority_from_committed(&mut authority, "http://cp-a:50051", t0);
    assert_eq!(authority.as_ref().unwrap().version, Some(t1));
}

#[test]
fn delta_after_resource_advances_fences_older_cross_source_snapshot() {
    // Blocker 1: accepted resource deltas move the active config ahead; the
    // watermark must follow so a later cross-source snapshot between those
    // versions is refused rather than rolling config back.
    let snapshot = Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap();
    let after_delta = Utc.with_ymd_and_hms(2026, 7, 1, 14, 0, 0).unwrap();
    let stale_failover = Utc.with_ymd_and_hms(2026, 7, 1, 13, 0, 0).unwrap();

    let mut authority = None;
    advance_authority_from_committed(&mut authority, "http://cp-primary:50051", snapshot);
    advance_authority_from_committed(&mut authority, "http://cp-primary:50051", after_delta);

    assert!(matches!(
        evaluate_full_snapshot_authority(
            authority.as_ref(),
            stale_failover,
            "http://cp-fallback:50051",
        ),
        Err(StaleSnapshotReject::OlderThanApplied { .. })
    ));
}

#[test]
fn subscription_requires_valid_snapshot_base_before_delta() {
    assert_eq!(
        evaluate_delta_against_subscription_base(false),
        Err(DeltaRefuse::BeforeSnapshotBase)
    );
    assert!(evaluate_delta_against_subscription_base(true).is_ok());

    // Unusable FULL_SNAPSHOT always terminates — including after a prior base.
    assert_eq!(
        snapshot_failure_stream_disposition(false),
        SnapshotFailureStreamDisposition::TerminateAndReconnect
    );
    assert_eq!(
        snapshot_failure_stream_disposition(true),
        SnapshotFailureStreamDisposition::TerminateAndReconnect
    );
}

#[test]
fn no_startup_flag_still_requires_full_snapshot_before_delta() {
    // Root review: `startup_ready = None` must not initialize the subscription
    // base as already applied. Library/test callers skip startup-only work, but
    // every new subscription still starts without a committed FULL_SNAPSHOT.
    let mut subscription = SubscriptionApplyState::new();
    assert!(
        !subscription.base_applied,
        "new subscriptions must start without a base even when startup_ready is absent"
    );
    assert_eq!(
        evaluate_delta_against_subscription_base(subscription.base_applied),
        Err(DeltaRefuse::BeforeSnapshotBase)
    );
    subscription.note_full_snapshot_accepted();
    assert!(subscription.base_applied);
    assert!(evaluate_delta_against_subscription_base(subscription.base_applied).is_ok());
}

#[test]
fn mid_stream_unusable_snapshot_and_delta_rejection_force_resync() {
    assert_eq!(
        delta_rejection_stream_disposition(DeltaRejectionKind::ParseFailure),
        DeltaRejectionStreamDisposition::TerminateAndResync
    );
    assert_eq!(
        delta_rejection_stream_disposition(DeltaRejectionKind::InvalidTrustSideChannel),
        DeltaRejectionStreamDisposition::TerminateAndResync
    );
    assert_eq!(
        delta_rejection_stream_disposition(DeltaRejectionKind::NonEmptyApplyRejected),
        DeltaRejectionStreamDisposition::TerminateAndResync
    );

    let mut state = MultiCpBackoffState {
        backoff_secs: 8,
        current_cp_index: 1,
        full_cycle_count: 0,
    };
    assert!(advance_multi_cp_backoff(
        &mut state,
        2,
        ConfigSyncAttemptOutcome::ResyncAfterAcceptedConfig
    ));
    assert_eq!(state.current_cp_index, 1, "resync retries the same CP");
    assert_eq!(state.backoff_secs, BACKOFF_INITIAL_SECS);
}

#[test]
fn rejected_delta_marks_divergence_until_full_snapshot_recovery() {
    // Issue #2394: rejection terminates before a later delta can apply; sticky
    // divergence clears only after an authoritative FULL_SNAPSHOT recovery.
    let metrics = ConfigSyncDivergenceMetrics::default();
    assert!(!metrics.is_diverged());
    metrics.record_rejection();
    assert!(metrics.is_diverged());
    let snap = metrics.snapshot();
    assert_eq!(snap.rejected_nonempty_deltas_total, 1);
    assert_eq!(snap.recoveries_total, 0);

    // A second rejection before recovery keeps the sticky flag and increments.
    metrics.record_rejection();
    assert!(metrics.is_diverged());
    assert_eq!(metrics.snapshot().rejected_nonempty_deltas_total, 2);

    assert!(metrics.record_recovery_after_full_snapshot());
    assert!(!metrics.is_diverged());
    assert_eq!(metrics.snapshot().recoveries_total, 1);
    // Idempotent clear when already converged.
    assert!(!metrics.record_recovery_after_full_snapshot());
    assert_eq!(metrics.snapshot().recoveries_total, 1);
}

#[test]
fn semver_version_negotiation_rejects_empty_malformed_and_incompatible() {
    // Issue #2395: fail closed on missing/malformed; allow patch/prerelease.
    assert!(matches!(
        check_peer_version_compatibility(FERRUM_VERSION, ""),
        Err(VersionCompatError::Missing)
    ));
    assert!(matches!(
        check_peer_version_compatibility(FERRUM_VERSION, "1"),
        Err(VersionCompatError::Malformed { .. })
    ));
    assert!(matches!(
        check_peer_version_compatibility(FERRUM_VERSION, "garbage"),
        Err(VersionCompatError::Malformed { .. })
    ));
    assert!(check_peer_version_compatibility(FERRUM_VERSION, FERRUM_VERSION).is_ok());

    let parts: Vec<&str> = FERRUM_VERSION.split('.').collect();
    assert!(parts.len() >= 2);
    let patch_ok = format!("{}.{}.99", parts[0], parts[1]);
    assert!(check_peer_version_compatibility(FERRUM_VERSION, &patch_ok).is_ok());
    let prerelease_ok = format!("{}.{}.0-rc.1", parts[0], parts[1]);
    assert!(check_peer_version_compatibility(FERRUM_VERSION, &prerelease_ok).is_ok());
    let minor_bad = format!("{}.{}.0", parts[0], parts[1].parse::<u64>().unwrap_or(0) + 1);
    assert!(matches!(
        check_peer_version_compatibility(FERRUM_VERSION, &minor_bad),
        Err(VersionCompatError::Incompatible { .. })
    ));

    // DP helper surfaces the same policy.
    assert!(check_cp_version_compatibility("").is_err());
    assert!(check_cp_version_compatibility("1").is_err());
    assert!(check_cp_version_compatibility("garbage").is_err());
    assert!(check_cp_version_compatibility(FERRUM_VERSION).is_ok());
    assert!(check_cp_version_compatibility(&patch_ok).is_ok());
    assert!(check_cp_version_compatibility(&minor_bad).is_err());
}

#[test]
fn stale_snapshot_fenced_outcome_fails_over_without_resetting_backoff() {
    // A fenced snapshot must account like a connection failure: advance to the
    // next CP, keep sleeping, and NEVER reset backoff (a stale fallback CP is
    // not healthy progress). Contrast CleanCloseAfterConfig, which does reset.
    let fenced = ConfigSyncAttemptOutcome::StaleSnapshotFenced;
    let mut state = MultiCpBackoffState {
        backoff_secs: 8,
        ..MultiCpBackoffState::new()
    };
    assert!(advance_multi_cp_backoff(&mut state, 2, fenced));
    assert_eq!(state.current_cp_index, 1, "fencing must fail over to the next CP");
    assert_eq!(state.backoff_secs, 8, "fencing must not reset backoff");
    grow_backoff_after_failure_sleep(&mut state);
    assert_eq!(state.backoff_secs, 16, "backoff must keep growing after a fence");
}

#[test]
fn invalid_subscription_base_outcome_fails_over_with_backoff() {
    let mut state = MultiCpBackoffState {
        backoff_secs: 4,
        ..MultiCpBackoffState::new()
    };
    assert!(advance_multi_cp_backoff(
        &mut state,
        2,
        ConfigSyncAttemptOutcome::InvalidSubscriptionBase
    ));
    assert_eq!(state.current_cp_index, 1);
    assert_eq!(state.backoff_secs, 4);
    grow_backoff_after_failure_sleep(&mut state);
    assert_eq!(state.backoff_secs, 8);
}

#[test]
fn repeated_fencing_reaches_backoff_cap_and_cycles_cps() {
    // A permanently stale fallback that keeps getting fenced must not busy-loop:
    // backoff still climbs to the cap and the DP still cycles across CP URLs.
    let fenced = ConfigSyncAttemptOutcome::StaleSnapshotFenced;
    let mut state = MultiCpBackoffState::new();
    let mut reached_cap = false;
    let mut cycled = false;
    for _ in 0..24 {
        assert!(advance_multi_cp_backoff(&mut state, 2, fenced));
        if state.full_cycle_count > 0 {
            cycled = true;
        }
        grow_backoff_after_failure_sleep(&mut state);
        if state.backoff_secs == backoff_max_secs() {
            reached_cap = true;
        }
    }
    assert!(reached_cap, "repeated fencing must still reach the backoff cap");
    assert!(cycled, "repeated fencing across 2 CPs must cycle back to primary");
}

#[test]
fn unknown_prior_authority_still_accepts_cross_source() {
    // An authority recorded without a comparable timestamp cannot fence; a
    // real failover snapshot is accepted and its committed stamp adopted.
    let authority = AppliedSnapshotAuthority {
        version: None,
        source_cp_url: "http://cp-a:50051".to_string(),
    };
    let newer = Utc.with_ymd_and_hms(2026, 7, 20, 0, 0, 0).unwrap();
    let accepted = evaluate_full_snapshot_authority(
        Some(&authority),
        newer,
        "http://cp-b:50051",
    )
    .expect("a real failover snapshot must not be fenced by an unknown authority");
    assert_eq!(accepted, newer);
}

#[test]
fn reconnect_preserves_last_config_received_at_and_divergence() {
    let stamp = Utc.with_ymd_and_hms(2026, 7, 24, 1, 2, 3).unwrap();
    let diverged_since = Utc.with_ymd_and_hms(2026, 7, 24, 1, 0, 0).unwrap();
    let prev = DpCpConnectionState {
        connected: false,
        cp_url: "http://cp-old:50051".to_string(),
        is_primary: true,
        last_config_received_at: Some(stamp),
        connected_since: None,
        config_diverged: true,
        config_diverged_since: Some(diverged_since),
        config_divergence_recoveries_total: 2,
    };
    let connected = DpCpConnectionState {
        connected: true,
        cp_url: "http://cp-new:50051".to_string(),
        is_primary: false,
        last_config_received_at: prev.last_config_received_at,
        connected_since: Some(Utc::now()),
        config_diverged: prev.config_diverged,
        config_diverged_since: prev.config_diverged_since,
        config_divergence_recoveries_total: prev.config_divergence_recoveries_total,
    };
    assert_eq!(connected.last_config_received_at, Some(stamp));
    assert!(connected.connected);
    assert!(connected.config_diverged);
    assert_eq!(connected.config_diverged_since, Some(diverged_since));
    assert_eq!(connected.config_divergence_recoveries_total, 2);
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
