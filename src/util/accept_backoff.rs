//! Bounded backoff for connection-accept loops.
//!
//! Under file-descriptor exhaustion (`EMFILE`/`ENFILE`) `accept()` fails
//! **without** consuming the pending connection and **without** clearing the
//! socket's read-readiness, so the listener's `accept()` arm re-fires
//! immediately — a CPU + log busy-loop that persists until the descriptor table
//! drains. This helper tracks consecutive failures and yields a bounded sleep
//! once they repeat, then is reset on the next successful accept.
//!
//! Progress-making error kinds (`ConnectionAborted`, `ConnectionReset`,
//! `Interrupted`) consume the backlog entry / are benign, so they do **not**
//! count toward the streak and never produce a backoff. That keeps a connection
//! abort/reset flood at full accept throughput while still throttling the
//! fd-exhaustion busy-loop (`EMFILE`/`ENFILE` map to none of those kinds).
//!
//! The decision logic is intentionally a small pure value so it can be unit
//! tested without provoking real fd exhaustion, and adopted by every accept
//! loop (data-plane proxy/TCP, admin, CP gRPC, injector, mesh DNS TCP, CNI) in
//! one place.

use std::io;
use std::time::Duration;

/// Default emit window for [`LogRateLimiter`]: at most one summary line per
/// second per accept loop.
const LOG_RATE_LIMIT_WINDOW_MS: u64 = 1_000;

/// Bounds the rate of a repeated log line to one emit per window, independent
/// of [`AcceptBackoff`].
///
/// `AcceptBackoff` only sleeps on fd-exhaustion-class errors, so an
/// abort/reset flood (which makes progress and is intentionally *not* backed
/// off) can still emit one error log per accept — pegging the log pipeline.
/// This limiter caps that: it emits the **first** occurrence immediately, then
/// at most one summary per window that carries how many were suppressed since
/// the last emit. The current event that triggers an emit is itself logged and
/// is never counted as suppressed.
///
/// The decision is a small pure value: [`on_event`](Self::on_event) takes the
/// current monotonic time in millis as a parameter (callers pass
/// [`crate::socket_opts::monotonic_now_ms`]) so it is unit-testable with
/// synthetic timestamps and never sleeps.
#[derive(Debug)]
pub struct LogRateLimiter {
    /// Monotonic-ms of the last emit, or `None` before the first event.
    last_emit_ms: Option<u64>,
    /// Events suppressed since the last emit.
    suppressed: u64,
    /// Emit window in millis.
    window_ms: u64,
}

impl Default for LogRateLimiter {
    fn default() -> Self {
        // Delegate to `new` so the window is the 1s default and never `0`
        // (a derived `Default` would zero `window_ms`, making every event emit).
        Self::new()
    }
}

impl LogRateLimiter {
    /// Create a limiter with the default 1s window.
    pub fn new() -> Self {
        Self {
            last_emit_ms: None,
            suppressed: 0,
            window_ms: LOG_RATE_LIMIT_WINDOW_MS,
        }
    }

    /// Record an event at `now_ms` (monotonic millis).
    ///
    /// Returns `Some(suppressed)` when the caller should log now — `suppressed`
    /// is the number of events dropped since the previous emit (`0` for the
    /// first ever emit) — and `None` when the caller should stay silent and
    /// just let the event be counted toward the next summary.
    ///
    /// An event emits when it is the first one seen or when a full window has
    /// elapsed since the last emit; otherwise it is suppressed and counted.
    #[inline]
    pub fn on_event(&mut self, now_ms: u64) -> Option<u64> {
        let should_emit = match self.last_emit_ms {
            None => true,
            // `saturating_sub` guards against a monotonic clock that does not
            // advance between calls (coarse resolution): the difference is then
            // 0 and the event is suppressed, never spuriously emitted.
            Some(last) => now_ms.saturating_sub(last) >= self.window_ms,
        };
        if should_emit {
            let suppressed = self.suppressed;
            self.suppressed = 0;
            self.last_emit_ms = Some(now_ms);
            Some(suppressed)
        } else {
            self.suppressed = self.suppressed.saturating_add(1);
            None
        }
    }
}

/// Per-accept-loop backoff state. Construct once outside the loop with
/// [`AcceptBackoff::new`], call [`on_success`](Self::on_success) after a
/// successful `accept()`, and [`on_error`](Self::on_error) on the error arm.
#[derive(Debug, Default)]
pub struct AcceptBackoff {
    consecutive: u32,
}

impl AcceptBackoff {
    /// Create a fresh backoff with a zero failure streak.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a successful accept; clears the consecutive-failure streak.
    #[inline]
    pub fn on_success(&mut self) {
        self.consecutive = 0;
    }

    /// Record an accept error and return how long to sleep before the next
    /// `accept()`, or `None` to retry immediately.
    ///
    /// fd-exhaustion-class errors are the only ones that busy-loop without
    /// making progress, so progress-making kinds (`ConnectionAborted`,
    /// `ConnectionReset`, `Interrupted`) do not increment the streak and never
    /// back off. A single isolated error of any other kind also does not sleep;
    /// only a *repeated* run does, with the delay growing 20ms→100ms and capped
    /// at 100ms.
    #[inline]
    pub fn on_error(&mut self, kind: io::ErrorKind) -> Option<Duration> {
        if matches!(
            kind,
            io::ErrorKind::ConnectionAborted
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::Interrupted
        ) {
            return None;
        }
        self.consecutive = self.consecutive.saturating_add(1);
        // The first repeat (streak == 2) is the first to sleep, so a single
        // isolated transient error incurs no added latency. 10ms * streak,
        // capped at 100ms; `as u64` before the multiply is overflow-safe.
        if self.consecutive > 1 {
            Some(Duration::from_millis(
                (self.consecutive as u64 * 10).min(100),
            ))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_error_does_not_sleep_then_grows_and_caps() {
        let mut b = AcceptBackoff::new();
        // A single isolated error: no backoff.
        assert_eq!(b.on_error(io::ErrorKind::Other), None);
        // First repeat sleeps 20ms, then 30ms, 40ms...
        assert_eq!(
            b.on_error(io::ErrorKind::Other),
            Some(Duration::from_millis(20))
        );
        assert_eq!(
            b.on_error(io::ErrorKind::Other),
            Some(Duration::from_millis(30))
        );
        // ...capped at 100ms.
        for _ in 0..50 {
            b.on_error(io::ErrorKind::Other);
        }
        assert_eq!(
            b.on_error(io::ErrorKind::Other),
            Some(Duration::from_millis(100))
        );
    }

    #[test]
    fn success_resets_the_streak() {
        let mut b = AcceptBackoff::new();
        b.on_error(io::ErrorKind::Other);
        b.on_error(io::ErrorKind::Other); // streak == 2
        b.on_success();
        // Back to a single error: no backoff.
        assert_eq!(b.on_error(io::ErrorKind::Other), None);
    }

    #[test]
    fn progress_making_errors_never_back_off_or_count() {
        let mut b = AcceptBackoff::new();
        for _ in 0..100 {
            assert_eq!(b.on_error(io::ErrorKind::ConnectionAborted), None);
            assert_eq!(b.on_error(io::ErrorKind::ConnectionReset), None);
            assert_eq!(b.on_error(io::ErrorKind::Interrupted), None);
        }
        // The streak was never touched, so a subsequent fd-exhaustion-class
        // error still starts clean (no backoff on its first occurrence).
        assert_eq!(b.on_error(io::ErrorKind::Other), None);
    }

    #[test]
    fn saturates_without_panicking() {
        let mut b = AcceptBackoff {
            consecutive: u32::MAX,
        };
        // saturating_add keeps it at u32::MAX; the sleep stays capped at 100ms.
        assert_eq!(
            b.on_error(io::ErrorKind::Other),
            Some(Duration::from_millis(100))
        );
    }

    #[test]
    fn log_limiter_first_event_emits_with_zero_suppressed() {
        let mut l = LogRateLimiter::new();
        assert_eq!(l.on_event(0), Some(0));
    }

    #[test]
    fn log_limiter_suppresses_within_window_then_summarizes() {
        let mut l = LogRateLimiter::new();
        // First event at t=0 emits immediately with nothing suppressed.
        assert_eq!(l.on_event(0), Some(0));
        // Everything inside the 1s window is suppressed and counted.
        for t in [1, 100, 500, 999] {
            assert_eq!(l.on_event(t), None);
        }
        // The first event at/after the window boundary emits a summary that
        // carries the four suppressed events, then the count resets.
        assert_eq!(l.on_event(1_000), Some(4));
        // A fresh window starts: counting restarts from zero.
        assert_eq!(l.on_event(1_001), None);
        assert_eq!(l.on_event(2_000), Some(1));
    }

    #[test]
    fn log_limiter_window_boundary_is_inclusive() {
        let mut l = LogRateLimiter::new();
        assert_eq!(l.on_event(0), Some(0));
        // Exactly one window later (>=) emits; one ms short suppresses.
        assert_eq!(l.on_event(999), None);
        assert_eq!(l.on_event(1_000), Some(1));
    }

    #[test]
    fn log_limiter_non_advancing_clock_suppresses_after_first() {
        // Coarse/non-advancing monotonic clock: the same timestamp must not
        // re-emit (saturating_sub yields 0, which is below the window).
        let mut l = LogRateLimiter::new();
        assert_eq!(l.on_event(42), Some(0));
        for _ in 0..1_000 {
            assert_eq!(l.on_event(42), None);
        }
    }

    #[test]
    fn log_limiter_suppressed_count_saturates() {
        let mut l = LogRateLimiter {
            last_emit_ms: Some(0),
            suppressed: u64::MAX,
            window_ms: LOG_RATE_LIMIT_WINDOW_MS,
        };
        // Counting past u64::MAX stays pinned; no panic.
        assert_eq!(l.on_event(10), None);
        assert_eq!(l.suppressed, u64::MAX);
        // The next windowed emit reports the saturated count and resets.
        assert_eq!(l.on_event(LOG_RATE_LIMIT_WINDOW_MS), Some(u64::MAX));
        assert_eq!(l.on_event(LOG_RATE_LIMIT_WINDOW_MS + 1), None);
    }
}
