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
}
