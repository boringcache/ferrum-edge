//! Lock-free rate limiter for hot-path diagnostic warnings.
//!
//! Mirrors [`LogRateLimiter`](super::accept_backoff::LogRateLimiter) semantics
//! without mutexes: emits the first event immediately, then at most one summary
//! per window carrying how many events were suppressed since the last emit. The
//! event that triggers an emit is logged and is never counted as suppressed.
//!
//! Ordering: all atomics use [`Ordering::Relaxed`]. Suppressed counts are
//! monotonic between emits and may be slightly low under concurrent winners of
//! the emit [`compare_exchange`](std::sync::atomic::AtomicU64::compare_exchange);
//! losing threads fold their event into `suppressed` instead of emitting a
//! spurious zero-suppressed line.

use std::sync::atomic::{AtomicU64, Ordering};

/// Sentinel for "no emit yet" in [`AtomicLogRateLimiter::last_emit_ms`].
const UNSET_MS: u64 = u64::MAX;

/// Default emit window: at most one summary line per second.
pub const DEFAULT_ATOMIC_LOG_RATE_LIMIT_WINDOW_MS: u64 = 1_000;

/// Bounds the rate of a repeated log line without locks.
#[derive(Debug)]
pub struct AtomicLogRateLimiter {
    last_emit_ms: AtomicU64,
    suppressed: AtomicU64,
    window_ms: u64,
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
    /// Returns `Some(suppressed)` when the caller should log now — `suppressed`
    /// is the number of events dropped since the previous emit (`0` for the
    /// first ever emit) — and `None` when the caller should stay silent.
    #[inline]
    pub fn on_event(&self, now_ms: u64) -> Option<u64> {
        let last_ms = self.last_emit_ms.load(Ordering::Relaxed);
        if last_ms != UNSET_MS && now_ms.saturating_sub(last_ms) < self.window_ms {
            self.suppressed.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        if self
            .last_emit_ms
            .compare_exchange(last_ms, now_ms, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            Some(self.suppressed.swap(0, Ordering::Relaxed))
        } else {
            self.suppressed.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    /// Clear state for isolated unit tests.
    #[doc(hidden)]
    pub fn reset_for_test(&self) {
        self.last_emit_ms.store(UNSET_MS, Ordering::Relaxed);
        self.suppressed.store(0, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_event_emits_with_zero_suppressed() {
        let limiter = AtomicLogRateLimiter::new();
        assert_eq!(limiter.on_event(0), Some(0));
    }

    #[test]
    fn suppresses_within_window_then_summarizes() {
        let limiter = AtomicLogRateLimiter::new();
        assert_eq!(limiter.on_event(0), Some(0));
        for t in [1, 100, 500, 999] {
            assert_eq!(limiter.on_event(t), None);
        }
        assert_eq!(limiter.on_event(1_000), Some(4));
        assert_eq!(limiter.on_event(1_001), None);
        assert_eq!(limiter.on_event(2_000), Some(1));
    }

    #[test]
    fn non_advancing_clock_suppresses_after_first() {
        let limiter = AtomicLogRateLimiter::new();
        assert_eq!(limiter.on_event(42), Some(0));
        for _ in 0..1_000 {
            assert_eq!(limiter.on_event(42), None);
        }
    }

    #[test]
    fn suppressed_count_saturates() {
        let limiter = AtomicLogRateLimiter {
            last_emit_ms: AtomicU64::new(0),
            suppressed: AtomicU64::new(u64::MAX),
            window_ms: DEFAULT_ATOMIC_LOG_RATE_LIMIT_WINDOW_MS,
        };
        assert_eq!(limiter.on_event(10), None);
        assert_eq!(
            limiter.suppressed.load(Ordering::Relaxed),
            u64::MAX,
            "saturating add must not wrap"
        );
        assert_eq!(
            limiter.on_event(DEFAULT_ATOMIC_LOG_RATE_LIMIT_WINDOW_MS),
            Some(u64::MAX)
        );
    }
}
