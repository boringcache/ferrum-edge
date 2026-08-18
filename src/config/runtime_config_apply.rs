//! In-process read-your-write apply for database-mode admin mutations (issue #3926).
//!
//! Successful config-database writes must not return 2xx until the same
//! authoritative poll-loop reload that periodic ticks use has accepted a
//! generation covering the captured `config_changes` watermark — or until a
//! truthful failure is known (validation rejection / timeout / sequence
//! unavailable).
//!
//! This type is a coordinator, not a second apply path:
//! - It never builds a partial snapshot, never holds a DB transaction, and
//!   never rebuilds caches itself.
//! - Admin writers capture a covering watermark from the pinned write
//!   topology after persist, release that pin, then wait on the durable
//!   sequence the poll loop publishes after `apply_incremental` /
//!   `update_config`.
//! - Concurrent writers coalesce onto one reload: each waits for the covering
//!   watermark captured under its pin (see [`PreparedLiveApply`]), and a
//!   single poll that advances past both watermarks unblocks both waiters.
//! - External writers keep using the periodic / change-stream backstop; they
//!   are not delayed by this wait, and an in-flight admin-triggered poll still
//!   applies any rows they committed.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::watch;
use tokio::time::{Instant, timeout};

use crate::config::config_change_watch::ConfigChangeWakeSignal;

/// Bound on how long a database-mode admin mutation waits for the poll loop
/// to publish the committed generation. Cache rebuilds share this budget.
pub const ADMIN_WRITE_LIVE_APPLY_TIMEOUT: Duration = Duration::from_secs(30);

/// Why a committed mutation is not live. Closed static labels for OpenAPI /
/// JSON `reason` — never a resource id, namespace, or driver error string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveApplyFailure {
    /// The poll loop loaded a covering sequence and rejected the candidate.
    ConfigRejected,
    /// The wait budget elapsed before an accepted generation covered the write.
    Timeout,
    /// The covering sequence could not be read from the pinned topology after persist.
    SequenceUnavailable,
}

/// Covering `config_changes` watermark captured under a write-topology pin
/// after a durable mutation (issue #3926).
///
/// Persistence APIs do not cheaply return the mutation's exact assigned
/// sequence from the existing admission transaction, so handlers read
/// `latest_change_sequence` while the pin (and a still-held namespace
/// admission guard, when available) is live. That value is `MAX(sequence)`
/// on the pinned topology and may include a later concurrent same-namespace
/// writer. Waiting for it is conservative: `accepted >= covering` still
/// implies this mutation is live. It is not this waiter's exact committed
/// row unless no concurrent writer committed in between.
///
/// Capture this **before** releasing topology / namespace pins. Await it
/// **after** those pins drop so a poll or reconnect needed to make progress
/// is not blocked. Never re-query `latest_change_sequence` after release:
/// a failover can publish a different pool whose watermark is `<= accepted`
/// and would yield a false 2xx.
#[derive(Debug, Clone)]
#[must_use = "captured covering sequence must be awaited after releasing topology pins"]
pub struct PreparedLiveApply {
    covering: PreparedLiveApplyCovering,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PreparedLiveApplyCovering {
    /// No poll-loop coordinator, or the write targeted a namespace this process
    /// does not serve.
    Noop,
    Sequence(u64),
}

impl PreparedLiveApply {
    pub fn noop() -> Self {
        Self {
            covering: PreparedLiveApplyCovering::Noop,
        }
    }

    pub fn from_covering_sequence(sequence: u64) -> Self {
        Self {
            covering: PreparedLiveApplyCovering::Sequence(sequence),
        }
    }

    pub fn is_noop(&self) -> bool {
        matches!(self.covering, PreparedLiveApplyCovering::Noop)
    }

    /// Covering watermark to wait for, if this process serves the write.
    pub fn covering_sequence(&self) -> Option<u64> {
        match self.covering {
            PreparedLiveApplyCovering::Noop => None,
            PreparedLiveApplyCovering::Sequence(sequence) => Some(sequence),
        }
    }
}

impl LiveApplyFailure {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConfigRejected => "config_rejected",
            Self::Timeout => "reload_timeout",
            Self::SequenceUnavailable => "sequence_unavailable",
        }
    }

    pub fn error_message(self) -> &'static str {
        match self {
            Self::ConfigRejected => {
                "Configuration was committed but is not live: runtime reload rejected the candidate"
            }
            Self::Timeout => {
                "Configuration was committed but is not live: runtime reload did not apply in time"
            }
            Self::SequenceUnavailable => {
                "Configuration was committed but live-apply status could not be determined"
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ApplySnapshot {
    accepted: u64,
    rejected_through: u64,
}

/// Process-local coordinator shared by the database-mode poll loop and admin
/// write handlers.
pub struct RuntimeConfigApply {
    namespace: String,
    timeout: Duration,
    wake: Arc<ConfigChangeWakeSignal>,
    snapshot: watch::Sender<ApplySnapshot>,
    waiter_count: AtomicUsize,
    max_waiting: AtomicU64,
}

impl RuntimeConfigApply {
    pub fn new(namespace: impl Into<String>, accepted_sequence: u64) -> Self {
        Self::with_timeout(namespace, accepted_sequence, ADMIN_WRITE_LIVE_APPLY_TIMEOUT)
    }

    pub fn with_timeout(
        namespace: impl Into<String>,
        accepted_sequence: u64,
        timeout: Duration,
    ) -> Self {
        let (snapshot, _) = watch::channel(ApplySnapshot {
            accepted: accepted_sequence,
            rejected_through: 0,
        });
        Self {
            namespace: namespace.into(),
            timeout,
            wake: Arc::new(ConfigChangeWakeSignal::new()),
            snapshot,
            waiter_count: AtomicUsize::new(0),
            max_waiting: AtomicU64::new(0),
        }
    }

    pub fn serves_namespace(&self, namespace: &str) -> bool {
        self.namespace == namespace
    }

    pub fn wake_signal(&self) -> Arc<ConfigChangeWakeSignal> {
        Arc::clone(&self.wake)
    }

    pub fn accepted_sequence(&self) -> u64 {
        self.snapshot.borrow().accepted
    }

    pub fn waiter_count(&self) -> usize {
        self.waiter_count.load(Ordering::Acquire)
    }

    /// Publish that the poll loop accepted a generation covering `sequence`.
    pub fn record_accepted(&self, sequence: u64) {
        self.snapshot.send_modify(|snap| {
            if sequence > snap.accepted {
                snap.accepted = sequence;
            }
        });
    }

    /// Publish that a completed poll attempted `sequence` and rejected it.
    /// Waiters whose covering sequence is `<= sequence` fail closed.
    pub fn record_rejected(&self, sequence: u64) {
        self.snapshot.send_modify(|snap| {
            if sequence > snap.rejected_through {
                snap.rejected_through = sequence;
            }
        });
    }

    /// Re-arm an immediate poll when admin waiters are still blocked on a
    /// sequence this tick did not accept. Consumed permits must not leave
    /// waiters parked on the periodic interval.
    pub fn nudge_if_waiters_pending(&self) {
        if self.waiter_count.load(Ordering::Acquire) == 0 {
            return;
        }
        let waiting = self.max_waiting.load(Ordering::Acquire);
        let accepted = self.snapshot.borrow().accepted;
        if accepted < waiting {
            self.wake.signal_immediate();
        }
    }

    /// Wait until the poll loop has accepted a generation covering `sequence`
    /// or a truthful failure is known. `sequence` must already have been
    /// captured under the write-topology pin; this method never reads the
    /// database. Signals an immediate coalesced wake so the wait does not sit
    /// on `FERRUM_DB_POLL_INTERVAL`.
    pub async fn await_committed(&self, sequence: u64) -> Result<(), LiveApplyFailure> {
        if self.accepted_sequence() >= sequence {
            return Ok(());
        }

        self.max_waiting.fetch_max(sequence, Ordering::AcqRel);
        self.waiter_count.fetch_add(1, Ordering::AcqRel);
        struct WaiterGuard<'a>(&'a RuntimeConfigApply);
        impl Drop for WaiterGuard<'_> {
            fn drop(&mut self) {
                self.0.waiter_count.fetch_sub(1, Ordering::AcqRel);
            }
        }
        let _guard = WaiterGuard(self);

        self.wake.signal_immediate();

        let mut rx = self.snapshot.subscribe();
        let deadline = Instant::now() + self.timeout;
        loop {
            {
                let snap = *rx.borrow();
                if snap.accepted >= sequence {
                    return Ok(());
                }
                if snap.rejected_through >= sequence {
                    return Err(LiveApplyFailure::ConfigRejected);
                }
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(LiveApplyFailure::Timeout);
            }
            match timeout(remaining, rx.changed()).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => return Err(LiveApplyFailure::Timeout),
                Err(_) => return Err(LiveApplyFailure::Timeout),
            }
        }
    }
}
