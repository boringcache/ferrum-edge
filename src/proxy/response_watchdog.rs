//! Gateway-owned cancellation for authenticated H1/H2 streaming responses
//! (issue #3815).
//!
//! # Why a body adapter alone cannot enforce an authorization deadline
//!
//! [`TotalDeadlineBody`](crate::proxy::body) fires only when hyper polls the
//! response body, and hyper does not always poll it:
//!
//! * **HTTP/2.** hyper's `PipeToSendStream` reserves stream send capacity and
//!   awaits `SendStream::poll_capacity` *before* it polls the body. A client
//!   that advertises `SETTINGS_INITIAL_WINDOW_SIZE: 0` — or that simply stops
//!   issuing `WINDOW_UPDATE` — parks that pipe for as long as it likes, and no
//!   timer living inside the body can be observed while it is parked.
//! * **HTTP/1.1.** the dispatcher flushes a connection that can no longer buffer
//!   before it polls the body, so a client that stops reading parks the write
//!   and the body is never polled either.
//!
//! Both are client-controlled, so a body-only bound is not an enforceable
//! authorization lifetime: the credential expires, and the admitted stream and
//! everything it holds survive at the client's discretion. This mirrors exactly
//! the reason the request direction needs
//! [`upload_pump`](crate::proxy::upload_pump).
//!
//! # What this module guarantees
//!
//! Two gateway-owned mechanisms, armed from the same absolute plan and settled
//! through the same once-only latch:
//!
//! 1. **Upstream cancellation.** The backend response body lives in a shared
//!    slot. At the deadline a task the GATEWAY schedules takes the body out of
//!    that slot and drops it. From that instant the gateway reads no further
//!    byte from the backend, and the backend stream, its pooled connection, and
//!    every guard rooted in that body are released — regardless of what hyper is
//!    parked on.
//!
//! 2. **Transport close.** Dropping the upstream does not release what the
//!    RESPONSE body still owns: the request guard, the per-IP guard,
//!    circuit-breaker / load-balancer accounting, backend-admission permits, and
//!    the deferred transaction logger all live in `ProxyBody`, which hyper owns.
//!    If the downstream still has not drained the terminal a bounded grace after
//!    the deadline, the watchdog asks the connection task to close this client
//!    connection. hyper then drops the response body, which releases all of the
//!    above exactly once through the ordinary `Drop` path, and the client
//!    observes a protocol-visible termination: a `GOAWAY` followed by a close on
//!    HTTP/2, and a chunked or SSE body that ends without its terminating chunk
//!    on HTTP/1.1.
//!
//! # Cost, and why the common case pays almost nothing
//!
//! A client that IS draining reaches `TotalDeadlineBody`'s own timer on its next
//! poll: that wrapper takes the inner body (dropping this adapter, which aborts
//! the watchdog) and emits the protocol-correct terminal — `grpc-status: 16`
//! trailers, the bounded gRPC-Web frame, or a deterministic transport error for
//! plain HTTP/SSE. The transport close is never reached. The steady-state cost
//! is therefore one `Sleep` and one `Arc<Mutex<_>>` lock per polled frame, on
//! **authenticated streaming responses only**; an unauthenticated response never
//! constructs this adapter at all.
//!
//! # Deliberate trade-off: HTTP/2 connection scope
//!
//! HTTP/2 gives a server no way to reset ONE stream from outside hyper: the
//! `h2::SendStream` is owned by the parked pipe. The transport close is
//! therefore connection-scoped, and sibling streams on the same connection end
//! with it. It is preceded by `graceful_shutdown` (a `GOAWAY`, then a bounded
//! settle window in which sibling streams can still complete), and it is only
//! ever reached for a connection that is demonstrably refusing to drain an
//! already-expired authenticated stream. Leaving that stream parked instead
//! would let a hostile client retain a request slot, a per-IP slot, an admission
//! permit, and a load-balancer connection indefinitely — which is the thing this
//! contract exists to prevent.
//!
//! # Redaction
//!
//! The only string this module can publish is a compiled-in literal. No expiry
//! instant, claim, subject, certificate field, provider, route, or backend
//! target reaches it.

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body::Frame;

use crate::proxy::auth_lifetime::{
    AuthorizationConnectionCloser, StreamAuthDeadline, StreamAuthProtocolFamily,
    StreamAuthTerminationLatch,
};
use crate::proxy::body::ProxyBodyError;

/// How long after the authorization deadline the gateway waits for the
/// downstream to drain the protocol-correct terminal before closing the client
/// connection.
///
/// Long enough to absorb ordinary scheduling jitter on a loaded runner — a
/// client that is merely slow gets its `grpc-status: 16` trailers, its bounded
/// gRPC-Web frame, or its deterministic body error, and the connection survives.
/// Short enough that "terminated within a bounded grace at the validated
/// deadline" stays true for a client that is not draining at all.
pub(crate) const TRANSPORT_CLOSE_GRACE: Duration = Duration::from_secs(2);

/// Fixed terminal for the residual case where this adapter is polled after the
/// watchdog released the backend body but before the wrapper outside it has
/// observed its own timer.
///
/// Deliberately an error rather than a clean end of stream: a client must be
/// able to tell an authorization termination from a complete response.
const RELEASED_MESSAGE: &str =
    "authenticated stream terminated: authorization lifetime elapsed, upstream released";

/// Aborts the watchdog when the response body is dropped, so no watchdog can
/// outlive the body it guards.
struct AbortWatchdogOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortWatchdogOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

type SharedUpstream<B> = Arc<Mutex<Option<B>>>;

fn lock_upstream<B>(slot: &SharedUpstream<B>) -> std::sync::MutexGuard<'_, Option<B>> {
    // The lock is held only across one inner `poll_frame`, which is the single
    // place a panic could poison it. Recovering the guard keeps a poisoned lock
    // from turning into a second panic on the proxy path; the slot's contents
    // are still a valid `Option<B>` either way.
    slot.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A streaming response body whose upstream can be released by the gateway at
/// the admitted credential's authorization deadline, without the downstream
/// transport polling anything.
pub struct AuthorizationCancellableBody<B> {
    upstream: SharedUpstream<B>,
    /// Set once this body reached a terminal state of its own (clean end,
    /// upstream error, or the released terminal). Shared with the watchdog,
    /// which uses it to skip the transport close for a response that already
    /// finished.
    settled: Arc<AtomicBool>,
    /// Local mirror of `settled` for the "already done, return `None`" fast
    /// path. Not shared, so no atomic load per poll after completion.
    finished: bool,
    /// Held only for its `Drop`.
    _watchdog: AbortWatchdogOnDrop,
}

impl<B> AuthorizationCancellableBody<B>
where
    B: http_body::Body<Data = Bytes, Error = ProxyBodyError> + Send + Unpin + 'static,
{
    /// Install the watchdog over `inner`.
    ///
    /// `fired` is the same flag `TotalDeadlineBody` publishes, so a body that
    /// the downstream never polled still classifies as an authorization
    /// termination — health-neutral, with the bounded class — when `ProxyBody`
    /// is finally dropped by the transport close.
    ///
    /// `closer` is the client connection's close signal. `None` on frontends
    /// that own their own writes and already bound them (the native HTTP/3
    /// relays), where a transport close would be both unnecessary and wrong.
    pub(crate) fn new(
        inner: B,
        deadline: StreamAuthDeadline,
        family: StreamAuthProtocolFamily,
        latch: StreamAuthTerminationLatch,
        fired: Arc<AtomicBool>,
        closer: Option<AuthorizationConnectionCloser>,
    ) -> Self {
        let upstream: SharedUpstream<B> = Arc::new(Mutex::new(Some(inner)));
        let watchdog_upstream = Arc::clone(&upstream);
        let settled = Arc::new(AtomicBool::new(false));
        let watchdog_settled = Arc::clone(&settled);
        let handle = tokio::spawn(async move {
            // Absolute and armed once. Relayed DATA, SSE events, and gRPC
            // messages never refresh it, and this task is scheduled by the
            // gateway, so it runs while the downstream transport is parked.
            tokio::time::sleep_until(deadline.at).await;

            // A response that already reached its own terminal — a clean end of
            // stream, or an upstream error — is not an authorization
            // termination, however long the transport then holds the finished
            // body. Checking before anything is recorded is what keeps the
            // fixed-cardinality counter, the shared latch, and the `fired`
            // classification flag free of completed responses.
            if watchdog_settled.load(Ordering::Acquire) {
                return;
            }

            // Release the backend body FIRST. This is the security-critical
            // step: from here the gateway reads no further protected byte and
            // the upstream stream, pooled connection, and body-rooted guards are
            // gone, whatever the downstream is doing.
            let released = lock_upstream(&watchdog_upstream).take();
            drop(released);
            fired.store(true, Ordering::Release);
            // ONE latch, shared with the adapter outside this body, so the two
            // mechanisms record exactly one termination for the stream no
            // matter which of them fires first.
            latch.record_once(deadline.termination, family);

            let Some(closer) = closer else {
                return;
            };
            // Give the downstream a bounded chance to drain the
            // protocol-correct terminal on its own. A body that does so is
            // dropped, which aborts this task before the sleep completes.
            tokio::time::sleep(TRANSPORT_CLOSE_GRACE).await;
            if !watchdog_settled.load(Ordering::Acquire) {
                closer.request_close();
            }
        });
        Self {
            upstream,
            settled,
            finished: false,
            _watchdog: AbortWatchdogOnDrop(handle),
        }
    }

    fn settle(&mut self) {
        self.finished = true;
        self.settled.store(true, Ordering::Release);
    }
}

impl<B> http_body::Body for AuthorizationCancellableBody<B>
where
    B: http_body::Body<Data = Bytes, Error = ProxyBodyError> + Send + Unpin + 'static,
{
    type Data = Bytes;
    type Error = ProxyBodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        if this.finished {
            return Poll::Ready(None);
        }
        let mut guard = lock_upstream(&this.upstream);
        let Some(inner) = guard.as_mut() else {
            drop(guard);
            this.settle();
            return Poll::Ready(Some(Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                RELEASED_MESSAGE,
            )) as ProxyBodyError)));
        };
        match Pin::new(inner).poll_frame(cx) {
            Poll::Ready(None) => {
                *guard = None;
                drop(guard);
                this.settle();
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(error))) => {
                *guard = None;
                drop(guard);
                this.settle();
                Poll::Ready(Some(Err(error)))
            }
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        if self.finished {
            return true;
        }
        // A RELEASED slot is deliberately NOT an end of stream: reporting one
        // would let the transport finish the response cleanly, which is exactly
        // the outcome an authorization termination must be distinguishable from.
        match lock_upstream(&self.upstream).as_ref() {
            Some(inner) => inner.is_end_stream(),
            None => false,
        }
    }

    fn size_hint(&self) -> http_body::SizeHint {
        if self.finished {
            return http_body::SizeHint::with_exact(0);
        }
        match lock_upstream(&self.upstream).as_ref() {
            Some(inner) => inner.size_hint(),
            // Released, but not finished: the remaining length is unknown, not
            // zero. `SizeHint::default()` is what keeps a transport from
            // reconstructing a `Content-Length` for bytes that will never come.
            None => http_body::SizeHint::default(),
        }
    }
}

impl<B> AuthorizationCancellableBody<B> {
    /// Whether the watchdog has released the upstream body. Reached through
    /// `crate::_test_support` so an external test can prove the release happens
    /// while the transport is polling nothing.
    #[allow(dead_code)]
    pub fn upstream_released(&self) -> bool {
        lock_upstream(&self.upstream).is_none()
    }
}
