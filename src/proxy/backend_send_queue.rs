//! Post-EOS backend send-queue drain bound for `backend_write_timeout_ms`
//! (issue #4411).
//!
//! # The gap this closes
//!
//! [`crate::proxy::upload_pump`] bounds the *pre*-EOS half of a backend write:
//! its idle arm fires while the transport has stopped taking frames from the
//! bridge. Once the last frame has crossed that bridge the pump completes, and
//! from that instant the gateway has no application-level receipt that the
//! backend ever read a byte — HTTP has no request-side acknowledgement. A
//! backend that `accept()`s and never calls `recv()` therefore left the request
//! sitting in the response-header wait until `backend_read_timeout_ms` (30 s by
//! default) or the client gave up, even with an 800 ms write watermark
//! configured.
//!
//! # What the kernel does know
//!
//! The local send queue. A peer that never reads fills its socket receive
//! buffer; Linux receive-buffer autotuning grows only on application reads, so
//! for a peer that never calls `recv()` the advertised window stays near the
//! initial ~128 KiB. Every byte of the upload beyond that window is parked in
//! the gateway's OWN send queue — unsent, or sent and unacked — for the life of
//! the connection. [`crate::socket_opts::socket_send_queue_bytes`] reads that
//! depth directly (`SIOCOUTQ` on Linux, `SO_NWRITE` on macOS).
//!
//! Sampling it after EOS turns "the backend is not consuming the upload" into a
//! monotonic transport observation rather than a timing heuristic: the depth of
//! a draining connection strictly decreases, and the depth of a stalled one
//! does not.
//!
//! # Residual, deliberately not approximated
//!
//! A body the peer's kernel fully accepted (depth reaches 0) is invisible to
//! this bound and stays governed by `backend_read_timeout_ms`, exactly as
//! before — which is the right answer, because the gateway's write genuinely
//! completed. In practice that is any upload smaller than the peer's receive
//! buffer. Platforms with no send-queue query (Windows) keep the read bound
//! too. Both are documented next to `backend_write_timeout_ms` in
//! `docs/configuration.md`.
//!
//! # Multiplexed transports
//!
//! On a pooled HTTP/2 connection the send queue is shared by every stream on
//! it, so a non-zero depth is not by itself attributable to this request. A
//! depth that never *decreases* is: a connection whose send queue makes no
//! progress at all is making no progress for any stream on it, this one
//! included. The bound is therefore stated on progress, never on depth.

use std::sync::Arc;
use std::time::Duration;

use crate::socket_opts::monotonic_now_ms;

/// Longest gap between two send-queue samples.
///
/// The cadence is `min(100 ms, write_timeout / 4)`: at least four observations
/// inside one watermark, so a stall verdict is never reached on a single
/// reading, and never coarser than 100 ms for a long watermark.
const MAX_SAMPLE_INTERVAL_MS: u64 = 100;

/// Sampling cadence for one configured `backend_write_timeout_ms`.
pub(crate) fn sample_interval(write_timeout_ms: u64) -> Duration {
    let quarter = write_timeout_ms / 4;
    let interval = if quarter < MAX_SAMPLE_INTERVAL_MS {
        quarter
    } else {
        MAX_SAMPLE_INTERVAL_MS
    };
    // Never zero: a sub-4ms watermark would otherwise spin the sampler.
    Duration::from_millis(if interval == 0 { 1 } else { interval })
}

/// A duplicated handle on one backend socket, usable for send-queue sampling
/// after the transport that owns the socket has stopped handing it to us.
///
/// The fd is `dup`ed rather than borrowed on purpose. A raw fd number that the
/// owning transport has closed can be recycled by any later socket in the
/// process, and sampling a recycled number would read an unrelated
/// connection's send queue. Duplicating keeps the file description alive for
/// exactly as long as a handle exists, so a sample is always about the socket
/// it was taken from or fails outright.
///
/// Lifetime: one handle is created per pooled backend connection and dropped
/// with the pool entry, and the request path only ever clones the `Arc` for the
/// duration of one response-header wait, so the duplicate never outlives the
/// connection it describes.
pub struct BackendSocketHandle {
    #[cfg(unix)]
    fd: std::os::fd::OwnedFd,
}

impl std::fmt::Debug for BackendSocketHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BackendSocketHandle")
            .finish_non_exhaustive()
    }
}

impl BackendSocketHandle {
    /// Duplicate `stream`'s descriptor for later sampling.
    ///
    /// `None` when the platform has no send-queue query, or when the duplicate
    /// cannot be made (fd exhaustion) — in both cases the drain bound stays
    /// disarmed and the read timeout governs, which is the pre-#4411 behaviour.
    #[cfg(unix)]
    pub fn duplicate_from(stream: &tokio::net::TcpStream) -> Option<Arc<Self>> {
        if !crate::socket_opts::send_queue_probe_supported() {
            return None;
        }
        use std::os::fd::AsFd;
        let fd = stream.as_fd().try_clone_to_owned().ok()?;
        Some(Arc::new(Self { fd }))
    }

    #[cfg(not(unix))]
    pub fn duplicate_from(_stream: &tokio::net::TcpStream) -> Option<Arc<Self>> {
        None
    }

    /// Current send-queue depth in bytes, or `None` when the kernel refuses to
    /// answer (closed socket, unsupported platform).
    #[cfg(unix)]
    pub fn send_queue_bytes(&self) -> Option<u64> {
        use std::os::fd::AsRawFd;
        crate::socket_opts::socket_send_queue_bytes(self.fd.as_raw_fd()).ok()
    }

    #[cfg(not(unix))]
    pub fn send_queue_bytes(&self) -> Option<u64> {
        None
    }
}

/// Where a dispatcher publishes the backend socket for the request it is about
/// to send, so the upload pump can sample it after EOS.
///
/// Write-once and lock-free: the dispatcher fills it immediately before
/// `send_request`, which is strictly before any body frame can cross the
/// bridge, so the pump either sees the socket for the whole drain or sees
/// nothing at all and stays disarmed.
pub(crate) type BackendSocketSlot = Arc<std::sync::OnceLock<Arc<BackendSocketHandle>>>;

/// What one send-queue observation says about the backend's consumption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SendQueueVerdict {
    /// The peer's kernel has accepted every byte. Nothing is left to bound; the
    /// response-header wait belongs to `backend_read_timeout_ms` from here.
    Drained,
    /// The queue is shrinking, or the watermark has not elapsed yet.
    Progressing,
    /// Non-zero and not strictly smaller than the best depth seen, for at least
    /// `backend_write_timeout_ms`.
    Stalled,
}

/// The progress rule for the post-EOS drain, kept separate from the syscall and
/// the timer so it can be proven directly (issue #4411).
///
/// Progress means **strictly decreasing** depth. The floor is a low-water mark
/// and is never raised, so a depth that oscillates upward and returns to the
/// same value has made no progress: an upload that keeps being re-queued
/// without the peer ever accepting more of it is exactly the stall this bounds.
#[derive(Debug)]
pub(crate) struct SendQueueProgress {
    /// Lowest non-zero depth observed so far; `u64::MAX` until the first
    /// observation establishes it.
    floor: u64,
    /// Monotonic milliseconds at the last strict decrease, or at the start of
    /// the watch when there has not been one.
    last_progress_ms: u64,
    timeout_ms: u64,
}

impl SendQueueProgress {
    pub(crate) fn new(now_ms: u64, timeout_ms: u64) -> Self {
        Self {
            floor: u64::MAX,
            last_progress_ms: now_ms,
            timeout_ms,
        }
    }

    /// Fold one observation into the rule.
    pub(crate) fn observe(&mut self, depth: u64, now_ms: u64) -> SendQueueVerdict {
        if depth == 0 {
            return SendQueueVerdict::Drained;
        }
        if depth < self.floor {
            // The FIRST observation only establishes the floor; it must not
            // also restart the clock, or the watermark would always be charged
            // one sampling interval late.
            if self.floor != u64::MAX {
                self.last_progress_ms = now_ms;
            }
            self.floor = depth;
            return SendQueueVerdict::Progressing;
        }
        if self.timeout_ms > 0 && now_ms.saturating_sub(self.last_progress_ms) >= self.timeout_ms {
            SendQueueVerdict::Stalled
        } else {
            SendQueueVerdict::Progressing
        }
    }
}

/// Watch one backend socket's send queue drain, resolving `true` only on a
/// stall.
///
/// Resolves `false` — and stops sampling — as soon as the queue drains or the
/// kernel stops answering for this socket, so a healthy request pays at most a
/// handful of `ioctl`s and no allocation per sample.
pub(crate) async fn await_send_queue_stall(
    socket: &BackendSocketHandle,
    write_timeout_ms: u64,
) -> bool {
    if write_timeout_ms == 0 {
        return false;
    }
    let interval = sample_interval(write_timeout_ms);
    let mut progress = SendQueueProgress::new(monotonic_now_ms(), write_timeout_ms);
    loop {
        tokio::time::sleep(interval).await;
        let Some(depth) = socket.send_queue_bytes() else {
            // The socket is gone or the kernel refuses to answer. Fail open:
            // the remaining bounds (`backend_read_timeout_ms`, the client
            // deadline) still apply, and inventing a stall from a failed probe
            // would 504 healthy traffic.
            return false;
        };
        match progress.observe(depth, monotonic_now_ms()) {
            SendQueueVerdict::Drained => return false,
            SendQueueVerdict::Progressing => {}
            SendQueueVerdict::Stalled => return true,
        }
    }
}
