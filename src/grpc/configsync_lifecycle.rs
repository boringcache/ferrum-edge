//! Pure helpers for DP ConfigSync stream lifecycle policy.
//!
//! Kept free of gRPC/runtime I/O so unit tests can exercise silent-partition
//! thresholds, multi-CP backoff continuity, FULL_SNAPSHOT fencing, and
//! connection-state staleness preservation without standing up a CP.

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

/// Authoritative FULL_SNAPSHOT already applied by this DP.
///
/// `version` is `None` when the applied snapshot carried a non-RFC3339 version
/// string: we still record the source, but we deliberately do not invent a
/// timestamp, because a fabricated "now" would fence out every later — and
/// genuinely newer — failover snapshot forever.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedSnapshotAuthority {
    pub version: Option<DateTime<Utc>>,
    pub source_cp_url: String,
}

/// Why a FULL_SNAPSHOT was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StaleSnapshotReject {
    /// A failover snapshot's version could not be parsed, so freshness against
    /// a known-good applied authority cannot be proven; fail closed.
    UnparseableVersion,
    /// A failover snapshot is older than the applied authority.
    OlderThanApplied { applied: DateTime<Utc>, incoming: DateTime<Utc> },
}

/// Decide whether an incoming FULL_SNAPSHOT may replace the active config.
///
/// Returns the version to record as the new applied authority on accept
/// (`None` when the accepted snapshot's version was unparseable — never a
/// fabricated timestamp).
///
/// Rules:
/// - Same-source snapshots are always accepted (reconnect / recovery). The
///   recorded version keeps the newest known ordering; an unparseable resend
///   does not erase a prior parseable authority.
/// - Cross-source failover snapshots are fenced only when there is a parseable
///   applied authority to compare against and the incoming version is strictly
///   older. An unparseable incoming version against a known-good authority
///   fails closed ([`StaleSnapshotReject::UnparseableVersion`]) rather than
///   inventing a timestamp.
/// - With no applied authority (first snapshot) or an authority whose own
///   version is unknown, there is nothing to fence against, so the snapshot is
///   accepted and its (possibly unknown) version adopted.
pub fn evaluate_full_snapshot_authority(
    authority: Option<&AppliedSnapshotAuthority>,
    incoming_version: &str,
    source_cp_url: &str,
) -> Result<Option<DateTime<Utc>>, StaleSnapshotReject> {
    let parsed = DateTime::parse_from_rfc3339(incoming_version)
        .map(|dt| dt.with_timezone(&Utc))
        .ok();

    let Some(authority) = authority else {
        // First applied snapshot establishes the authority. Record only a real
        // parsed version; never fabricate `Utc::now()`.
        return Ok(parsed);
    };

    if authority.source_cp_url == source_cp_url {
        // Same source: always accept. Prefer the newly parsed version but keep
        // the prior authority version if this resend was unparseable, so we do
        // not lose ordering that later cross-source fencing depends on.
        return Ok(parsed.or(authority.version));
    }

    // Cross-source failover: fence only when a comparable applied authority
    // version exists.
    let Some(applied) = authority.version else {
        // No parseable ordering authority to fence against — we cannot prove
        // the incoming snapshot is stale, so accept and adopt its version.
        return Ok(parsed);
    };

    let Some(incoming) = parsed else {
        // Known-good authority vs. unparseable failover version: fail closed
        // instead of inventing a timestamp that could roll config back or
        // fence forever.
        return Err(StaleSnapshotReject::UnparseableVersion);
    };

    if incoming < applied {
        return Err(StaleSnapshotReject::OlderThanApplied { applied, incoming });
    }

    Ok(Some(incoming))
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
        | ConfigSyncAttemptOutcome::CleanCloseWithoutConfig => {
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
