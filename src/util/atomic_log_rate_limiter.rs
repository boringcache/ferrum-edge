//! Lock-free rate limiter for hot-path diagnostic warnings.
//!
//! Mirrors [`LogRateLimiter`](super::accept_backoff::LogRateLimiter) semantics
//! without mutexes: emits the first event immediately, then at most one summary
//! per window carrying how many events were suppressed since the last emit. The
//! event that triggers an emit is logged and is never counted as suppressed.
//!
//! Suppressed counts saturate at [`u64::MAX`] and never wrap. Between emits the
//! count is monotonic; concurrent losers of the emit
//! [`compare_exchange`](std::sync::atomic::AtomicU64::compare_exchange) fold
//! their event into `suppressed` instead of emitting a spurious zero-suppressed
//! line. Callers composing multiple limiters must roll back an emit claim when
//! a partner gate denies emission so neither scope loses accounting.

use std::sync::atomic::{AtomicU64, Ordering};

/// Sentinel for "no emit yet" in [`AtomicLogRateLimiter::last_emit_ms`].
const UNSET_MS: u64 = u64::MAX;

/// Default emit window: at most one summary line per second.
pub const DEFAULT_ATOMIC_LOG_RATE_LIMIT_WINDOW_MS: u64 = 1_000;

/// A successful emit-window claim before a composed gate commits or rolls back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EmitClaim {
    pub(crate) previous_last_emit_ms: u64,
    pub(crate) suppressed: u64,
}

/// Bounds the rate of a repeated log line without locks.
#[derive(Debug)]
pub struct AtomicLogRateLimiter {
    last_emit_ms: AtomicU64,
    suppressed: AtomicU64,
    window_ms: u64,
}

#[inline]
fn fetch_add_saturating(counter: &AtomicU64, delta: u64) {
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        let next = current.saturating_add(delta);
        match counter.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

impl AtomicLogRateLimiter {
    /// Create a limiter with [`DEFAULT_ATOMIC_LOG_RATE_LIMIT_WINDOW_MS`].
    pub const fn new() -> Self {
        Self::with_window_ms(DEFAULT_ATOMIC_LOG_RATE_LIMIT_WINDOW_MS)
    }

    /// Create a limiter with a custom window (millis).
    pub const fn with_window_ms(window_ms: u64) -> Self {
        Self {
            last_emit_ms: AtomicU64::new(UNSET_MS),
            suppressed: AtomicU64::new(0),
            window_ms,
        }
    }

    /// Record an event at `now_ms` (monotonic millis).
    ///
    /// Returns an [`EmitClaim`] when this scope would emit now. The caller must
    /// either log and leave the claim committed, or call
    /// [`rollback_emit_claim`](Self::rollback_emit_claim) when a composed gate
    /// denies emission so the triggering event is folded back into
    /// `suppressed` without losing accounting.
    #[inline]
    pub(crate) fn on_event(&self, now_ms: u64) -> Option<EmitClaim> {
        let last_ms = self.last_emit_ms.load(Ordering::Relaxed);
        if last_ms != UNSET_MS && now_ms.saturating_sub(last_ms) < self.window_ms {
            fetch_add_saturating(&self.suppressed, 1);
            return None;
        }

        if self
            .last_emit_ms
            .compare_exchange(last_ms, now_ms, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            Some(EmitClaim {
                previous_last_emit_ms: last_ms,
                suppressed: self.suppressed.swap(0, Ordering::Relaxed),
            })
        } else {
            fetch_add_saturating(&self.suppressed, 1);
            None
        }
    }

    /// Undo a claim from [`on_event`](Self::on_event) when a partner gate denied
    /// emission. The triggering event is folded into `suppressed`; a rolled
    /// back first emit anchors the window at `now_ms` without logging.
    #[inline]
    pub(crate) fn rollback_emit_claim(&self, claim: &EmitClaim, now_ms: u64) {
        self.suppressed
            .store(claim.suppressed.saturating_add(1), Ordering::Relaxed);
        if claim.previous_last_emit_ms == UNSET_MS {
            self.last_emit_ms.store(now_ms, Ordering::Relaxed);
        } else {
            self.last_emit_ms
                .store(claim.previous_last_emit_ms, Ordering::Relaxed);
        }
    }

    /// Compose per-instance and process-wide scopes: record every rejection at
    /// both, emit only when both admit, and roll back neither scope's aggregate
    /// when the partner gate denies.
    #[inline]
    pub(crate) fn dual_gate_emit(
        instance: &Self,
        global: &Self,
        now_ms: u64,
    ) -> Option<(u64, u64)> {
        let instance_claim = instance.on_event(now_ms);
        let global_claim = global.on_event(now_ms);
        match (&instance_claim, &global_claim) {
            (Some(instance), Some(global)) => Some((instance.suppressed, global.suppressed)),
            (Some(instance), None) => {
                instance.rollback_emit_claim(instance, now_ms);
                None
            }
            (None, Some(global)) => {
                global.rollback_emit_claim(global, now_ms);
                None
            }
            (None, None) => None,
        }
    }

    /// Clear state for isolated unit tests.
    #[doc(hidden)]
    pub fn reset_for_test(&self) {
        self.last_emit_ms.store(UNSET_MS, Ordering::Relaxed);
        self.suppressed.store(0, Ordering::Relaxed);
    }

    /// Observed suppressed-event accumulator. Test-only.
    #[doc(hidden)]
    pub fn suppressed_count_for_test(&self) -> u64 {
        self.suppressed.load(Ordering::Relaxed)
    }

    /// Seed limiter state for external regressions. Test-only.
    #[doc(hidden)]
    pub fn seed_for_test(&self, last_emit_ms: u64, suppressed: u64) {
        self.last_emit_ms.store(last_emit_ms, Ordering::Relaxed);
        self.suppressed.store(suppressed, Ordering::Relaxed);
    }
}
