//! Pre-request admission bound for data-plane HTTP/1.1 and HTTP/2 frontends.
//!
//! Hyper's HTTP/1 `header_read_timeout` cannot see two windows on the auto
//! (H1-or-H2) builder:
//!
//! * the version sniff — a peer that completes TCP accept (or the frontend TLS
//!   handshake) and sends nothing never reaches the HTTP/1 timer
//! * an HTTP/2 connection that exchanges SETTINGS / window updates, or opens a
//!   `HEADERS`/`CONTINUATION` block, and then goes silent before any request
//!   is delivered to the service
//!
//! This flag is set at service entry, which is after a complete request head
//! has been delivered and after frontend TLS admission has finished. Idle
//! keep-alive *after* that first request is intentionally not closed: applying
//! the 10s `FERRUM_HTTP_HEADER_READ_TIMEOUT_SECONDS` default as an idle bound
//! would drop legitimate long-lived HTTP/2, gRPC, and browser connections.
//! Admin listeners keep their stricter between-request watchdog; this helper
//! is proxy-frontend only (issue #4152).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// Per-connection "has the frontend HTTP service been invoked?" flag.
pub(crate) struct FrontendAdmission {
    dispatched: AtomicBool,
}

impl FrontendAdmission {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            dispatched: AtomicBool::new(false),
        })
    }

    /// Record that a complete request head reached the service.
    pub(crate) fn mark(&self) {
        self.dispatched.store(true, Ordering::Release);
    }

    fn has_dispatched(&self) -> bool {
        self.dispatched.load(Ordering::Acquire)
    }

    /// Resolves only when `timeout_seconds` elapses with no request delivered.
    ///
    /// `0` disables the bound and never resolves, matching
    /// `FERRUM_FRONTEND_TLS_HANDSHAKE_TIMEOUT_SECONDS=0` and the HTTP/1
    /// `header_read_timeout` opt-out.
    pub(crate) async fn wait_pre_request_deadline(&self, timeout_seconds: u64) {
        if timeout_seconds == 0 {
            std::future::pending::<()>().await;
        } else {
            tokio::time::sleep(Duration::from_secs(timeout_seconds)).await;
            if self.has_dispatched() {
                // First request arrived inside the window. Do not fire again: idle
                // keep-alive after admission is out of scope for this bound.
                std::future::pending::<()>().await;
            }
        }
    }
}
