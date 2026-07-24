//! Pure helpers for DP ConfigSync stream lifecycle policy.
//!
//! Kept free of gRPC/runtime I/O so unit tests can exercise silent-partition
//! thresholds, multi-CP backoff continuity, FULL_SNAPSHOT fencing, freshness
//! watermark monotonicity, subscription base gating, and connection-state
//! staleness preservation without standing up a CP.

use chrono::{DateTime, Utc};

use crate::util::backoff::{BACKOFF_INITIAL_SECS, BACKOFF_MAX_SECS, next_backoff_secs};

/// HTTP/2 PING interval on the DP→CP ConfigSync channel.
pub const CONFIGSYNC_HTTP2_KEEPALIVE_INTERVAL_SECS: u64 = 30;
/// HTTP/2 PING ack timeout on the DP→CP ConfigSync channel.
pub const CONFIGSYNC_HTTP2_KEEPALIVE_TIMEOUT_SECS: u64 = 10;
/// TCP keepalive idle probe interval for ConfigSync sockets.
pub const CONFIGSYNC_TCP_KEEPALIVE_SECS: u64 = 30;
/// CP application-level ConfigSync heartbeat interval.
pub const CONFIGSYNC_HEARTBEAT_INTERVAL_SECS: u64 = 60;
/// Reconnect when no ConfigSync message (including heartbeat) arrives within
/// this bound. Sized above the application heartbeat so healthy idle streams
/// are not treated as dead.
pub const CONFIGSYNC_MAX_SILENCE_SECS: u64 = 150;

/// Authoritative freshness watermark already established by this DP.
///
/// `version` is the monotonic high-water mark used to fence cross-source
/// FULL_SNAPSHOTs. It tracks committed GatewayConfig / accepted resource-delta
/// timestamps and never decreases on same-source recovery. It is `None` only
/// when an older authority was recorded without a comparable timestamp (should
/// not arise for newly committed applies that always carry `loaded_at`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedSnapshotAuthority {
    pub version: Option<DateTime<Utc>>,
    pub source_cp_url: String,
}

/// Why an envelope version failed to reconcile with committed config freshness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionReconcileError {
    /// `ConfigUpdate.version` was not a parseable RFC3339 timestamp.
    UnparseableEnvelope,
    /// Envelope timestamp disagrees with the parsed snapshot's `loaded_at`.
    Inconsistent {
        envelope: DateTime<Utc>,
        loaded_at: DateTime<Utc>,
    },
}

/// Why a FULL_SNAPSHOT was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StaleSnapshotReject {
    /// Envelope/`loaded_at` could not be ordered safely; fail closed.
    UnparseableVersion,
    /// Envelope version disagreed with the snapshot body's `loaded_at`.
    InconsistentVersion {
        envelope: DateTime<Utc>,
        loaded_at: DateTime<Utc>,
    },
    /// A failover snapshot is older than the applied authority.
    OlderThanApplied {
        applied: DateTime<Utc>,
        incoming: DateTime<Utc>,
    },
}

/// Reconcile `ConfigUpdate.version` against the parsed snapshot's `loaded_at`.
///
/// Freshness must describe the committed GatewayConfig body, not an arbitrary
/// envelope string. On success returns the committed `loaded_at` (never a
/// fabricated timestamp). Inconsistent or unparseable inputs fail closed.
pub fn reconcile_snapshot_version(
    envelope_version: &str,
    loaded_at: DateTime<Utc>,
) -> Result<DateTime<Utc>, VersionReconcileError> {
    // Prefer exact CP stamp parity (`loaded_at.to_rfc3339()`), then accept
    // equivalent RFC3339 encodings of the same instant.
    if envelope_version == loaded_at.to_rfc3339() {
        return Ok(loaded_at);
    }
    let Some(envelope) = DateTime::parse_from_rfc3339(envelope_version)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
    else {
        return Err(VersionReconcileError::UnparseableEnvelope);
    };
    if envelope != loaded_at {
        return Err(VersionReconcileError::Inconsistent {
            envelope,
            loaded_at,
        });
    }
    Ok(loaded_at)
}

/// Monotonic max of an optional prior watermark and a newly committed stamp.
pub fn monotonic_watermark(
    prior: Option<DateTime<Utc>>,
    committed: DateTime<Utc>,
) -> DateTime<Utc> {
    match prior {
        Some(prev) if prev > committed => prev,
        _ => committed,
    }
}

/// Advance (or establish) freshness authority from a timestamp actually
/// committed into active config (full snapshot `loaded_at` or accepted
/// resource-delta `poll_timestamp` / resulting `loaded_at`).
///
/// The watermark is monotonic: same-source recovery that intentionally applies
/// an older body still keeps the highest known ordering for later cross-source
/// fencing. Source URL is always updated to the committing CP.
pub fn advance_authority_from_committed(
    authority: &mut Option<AppliedSnapshotAuthority>,
    source_cp_url: &str,
    committed: DateTime<Utc>,
) {
    match authority {
        Some(existing) => {
            existing.version = Some(monotonic_watermark(existing.version, committed));
            existing.source_cp_url = source_cp_url.to_string();
        }
        None => {
            *authority = Some(AppliedSnapshotAuthority {
                version: Some(committed),
                source_cp_url: source_cp_url.to_string(),
            });
        }
    }
}

/// True when an accepted non-empty resource delta should advance freshness.
///
/// Rejected deltas and empty / trust-only side-channel updates must not.
pub fn resource_delta_advances_authority(accepted: bool, was_empty: bool) -> bool {
    accepted && !was_empty
}

/// Decide whether an incoming FULL_SNAPSHOT may replace the active config.
///
/// `incoming_committed` must already be the reconciled snapshot `loaded_at`
/// (see [`reconcile_snapshot_version`]). Returns the watermark to record after
/// a successful apply (monotonic vs any prior authority).
///
/// Rules:
/// - Same-source snapshots are always accepted (reconnect / recovery). The
///   recorded watermark stays monotonic even when the recovery body is older.
/// - Cross-source failover snapshots are fenced when a parseable applied
///   authority exists and the incoming committed stamp is strictly older.
/// - With no applied authority (first snapshot) or an authority whose own
///   version is unknown, there is nothing to fence against, so the snapshot is
///   accepted and its committed stamp adopted.
pub fn evaluate_full_snapshot_authority(
    authority: Option<&AppliedSnapshotAuthority>,
    incoming_committed: DateTime<Utc>,
    source_cp_url: &str,
) -> Result<DateTime<Utc>, StaleSnapshotReject> {
    let Some(authority) = authority else {
        return Ok(incoming_committed);
    };

    if authority.source_cp_url == source_cp_url {
        return Ok(monotonic_watermark(
            authority.version,
            incoming_committed,
        ));
    }

    let Some(applied) = authority.version else {
        return Ok(incoming_committed);
    };

    if incoming_committed < applied {
        return Err(StaleSnapshotReject::OlderThanApplied {
            applied,
            incoming: incoming_committed,
        });
    }

    Ok(incoming_committed)
}

/// How the ConfigSync stream must react to an incoming FULL_SNAPSHOT.
///
/// A fenced (older or unorderable cross-source) snapshot must **terminate** the
/// stream, not merely be skipped on a stream that keeps reading. Continuing
/// would let the same stale fallback CP's next DELTA apply against newer
/// config (issue #2970).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FullSnapshotStreamDisposition {
    /// Apply the snapshot; adopt `version` as the new applied watermark once
    /// the apply succeeds.
    Apply { version: DateTime<Utc> },
    /// Refuse the snapshot and terminate the stream so no later message from
    /// the same source can apply; the outer loop fails over with backoff.
    RefuseAndTerminate(StaleSnapshotReject),
}

/// Decide how the ConfigSync stream must react after version reconciliation.
pub fn full_snapshot_stream_disposition(
    authority: Option<&AppliedSnapshotAuthority>,
    incoming_committed: DateTime<Utc>,
    source_cp_url: &str,
) -> FullSnapshotStreamDisposition {
    match evaluate_full_snapshot_authority(authority, incoming_committed, source_cp_url) {
        Ok(version) => FullSnapshotStreamDisposition::Apply { version },
        Err(reject) => FullSnapshotStreamDisposition::RefuseAndTerminate(reject),
    }
}

/// Map a reconcile failure onto the stream-terminating refusal enum.
pub fn stale_reject_from_reconcile(err: VersionReconcileError) -> StaleSnapshotReject {
    match err {
        VersionReconcileError::UnparseableEnvelope => StaleSnapshotReject::UnparseableVersion,
        VersionReconcileError::Inconsistent {
            envelope,
            loaded_at,
        } => StaleSnapshotReject::InconsistentVersion {
            envelope,
            loaded_at,
        },
    }
}

/// How the stream must react when a FULL_SNAPSHOT fails parse/validate/apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotFailureStreamDisposition {
    /// No valid base yet on this subscription — terminate and fail over with
    /// accumulating backoff so a later DELTA cannot apply against an unrelated
    /// old base.
    TerminateAndFailover,
    /// A valid base was already committed on this subscription — keep serving
    /// it and continue reading (e.g. a mid-stream recovery snapshot that fails
    /// validation does not tear down the healthy stream).
    ContinueKeepingBase,
}

/// Decide stream reaction for a refused/invalid/unusable FULL_SNAPSHOT.
pub fn snapshot_failure_stream_disposition(
    subscription_base_applied: bool,
) -> SnapshotFailureStreamDisposition {
    if subscription_base_applied {
        SnapshotFailureStreamDisposition::ContinueKeepingBase
    } else {
        SnapshotFailureStreamDisposition::TerminateAndFailover
    }
}

/// Why a DELTA was refused before any apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeltaRefuse {
    /// No valid FULL_SNAPSHOT base has been committed on this subscription yet.
    BeforeSnapshotBase,
}

/// Each new subscription must accept exactly a valid FULL_SNAPSHOT base before
/// any DELTA can apply. A pre-snapshot DELTA must terminate without applying.
pub fn evaluate_delta_against_subscription_base(
    subscription_base_applied: bool,
) -> Result<(), DeltaRefuse> {
    if subscription_base_applied {
        Ok(())
    } else {
        Err(DeltaRefuse::BeforeSnapshotBase)
    }
}

/// Multi-CP reconnect backoff state. Backoff follows the failure sequence and
/// is not reset merely because the selected CP index changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiCpBackoffState {
    pub backoff_secs: u64,
    pub current_cp_index: usize,
    pub full_cycle_count: u32,
}

impl MultiCpBackoffState {
    pub fn new() -> Self {
        Self {
            backoff_secs: BACKOFF_INITIAL_SECS,
            current_cp_index: 0,
            full_cycle_count: 0,
        }
    }
}

impl Default for MultiCpBackoffState {
    fn default() -> Self {
        Self::new()
    }
}

/// Outcome of one ConfigSync stream attempt for backoff accounting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigSyncAttemptOutcome {
    /// Transport/RPC failure while connecting or reading.
    ConnectionError,
    /// Stream ended cleanly after delivering at least one config message.
    CleanCloseAfterConfig,
    /// Stream accepted Subscribe then ended without a config message.
    CleanCloseWithoutConfig,
    /// Operator-driven disconnect (primary retry / TLS reload). Not a failure.
    IntentionalDisconnect,
    /// A cross-source FULL_SNAPSHOT was fenced as stale/unorderable, so the DP
    /// refused the stream before any delta from it could apply. Treated exactly
    /// like a connection failure for failover/backoff accounting: advance to the
    /// next CP and keep accumulating backoff. It must never reset backoff — a
    /// stale fallback CP is not healthy progress (issue #2970).
    StaleSnapshotFenced,
    /// The subscription never established a valid FULL_SNAPSHOT base (malformed,
    /// inconsistent, rejected, or a pre-snapshot DELTA). Fail over with
    /// accumulating backoff; never treat as delivered config.
    InvalidSubscriptionBase,
}

/// Advance multi-CP index/backoff after one attempt.
///
/// Returns whether the caller should sleep before the next attempt.
pub fn advance_multi_cp_backoff(
    state: &mut MultiCpBackoffState,
    cp_count: usize,
    outcome: ConfigSyncAttemptOutcome,
) -> bool {
    match outcome {
        ConfigSyncAttemptOutcome::IntentionalDisconnect => {
            state.backoff_secs = BACKOFF_INITIAL_SECS;
            false
        }
        ConfigSyncAttemptOutcome::CleanCloseAfterConfig => {
            state.backoff_secs = BACKOFF_INITIAL_SECS;
            true
        }
        ConfigSyncAttemptOutcome::ConnectionError
        | ConfigSyncAttemptOutcome::CleanCloseWithoutConfig
        | ConfigSyncAttemptOutcome::StaleSnapshotFenced
        | ConfigSyncAttemptOutcome::InvalidSubscriptionBase => {
            if cp_count > 1 {
                let next_index = (state.current_cp_index + 1) % cp_count;
                if next_index == 0 {
                    state.full_cycle_count = state.full_cycle_count.saturating_add(1);
                }
                state.current_cp_index = next_index;
            }
            // Sleep with the current backoff, then grow for the next failure.
            // Callers sleep first, then invoke `grow_backoff_after_sleep`.
            true
        }
    }
}

/// Grow backoff after a failure sleep. No-op after successful/intentional paths
/// that already reset `backoff_secs`.
pub fn grow_backoff_after_failure_sleep(state: &mut MultiCpBackoffState) {
    state.backoff_secs = next_backoff_secs(state.backoff_secs, true);
}

/// Deterministic failure-sleep sequence for continuously failing CPs.
///
/// Used by tests to prove N≥2 dead CPs still reach [`BACKOFF_MAX_SECS`].
pub fn failure_backoff_sequence(cp_count: usize, attempts: usize) -> Vec<u64> {
    let mut state = MultiCpBackoffState::new();
    let mut sleeps = Vec::with_capacity(attempts);
    for _ in 0..attempts {
        let should_sleep = advance_multi_cp_backoff(
            &mut state,
            cp_count,
            ConfigSyncAttemptOutcome::ConnectionError,
        );
        if should_sleep {
            sleeps.push(state.backoff_secs);
            grow_backoff_after_failure_sleep(&mut state);
        }
    }
    sleeps
}

/// True when a silence interval exceeds the ConfigSync liveness bound.
pub fn silence_exceeds_liveness(silence_secs: u64) -> bool {
    silence_secs >= CONFIGSYNC_MAX_SILENCE_SECS
}

/// Cap used by tests/docs — exported so callers can assert the documented max.
pub fn backoff_max_secs() -> u64 {
    BACKOFF_MAX_SECS
}
