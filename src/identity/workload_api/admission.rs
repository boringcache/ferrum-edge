//! Transport admission for the SPIFFE Workload API listener (issue #3758).
//!
//! The Workload API socket is a *local* trust boundary: anything permitted to
//! connect may attempt attestation. That authorizes an identity **request** — it
//! must not also grant one workload the ability to deny identity service to
//! every other workload sharing the node. Without a bound at the transport, a
//! process with socket access can hold arbitrarily many idle Unix connections,
//! open arbitrarily many HTTP/2 streams on each, and drive arbitrarily many
//! concurrent RPC producers. The per-RPC rotation protections
//! ([`super::latest_wins`], the entitlement recheck) all begin *after* an RPC has
//! been admitted, so none of them cover that shape.
//!
//! ## Where the bound is applied
//!
//! Admission runs **before the accepted socket is yielded to tonic**, so a
//! refused connection never allocates an HTTP/2 connection, a service clone, or
//! a producer task:
//!
//! 1. **Kernel peer credentials first.** `SO_PEERCRED` is read off the accepted
//!    socket ([`ConnectionAdmission::admit`]). It is kernel-attested and cannot
//!    be spoofed by the caller, unlike anything in gRPC metadata, and it is the
//!    only trustworthy key for a per-principal quota. A socket whose credentials
//!    cannot be read is **refused** — fail-closed, because an unattributable
//!    connection cannot be charged to any quota.
//! 2. **Total connections**, then **per-UID connections**. Both are
//!    non-blocking: `try_acquire` / a bounded counter, never a wait. A caller
//!    over either limit is shed immediately by closing the socket, so no
//!    backlog of would-be connections accumulates behind the ceiling. The
//!    per-UID quota is what keeps one compromised member of the socket group
//!    from consuming the whole global pool — the total limit alone is a
//!    single shared resource and is exactly what a flood exhausts first.
//! 3. The admitted socket is wrapped in [`AdmittedUnixStream`], which **owns**
//!    the permit. Release is therefore tied to the connection object's lifetime
//!    rather than to any particular code path: a clean close, a transport
//!    error, a handshake that never completes, a cancelled task, and a panic
//!    unwind all drop the wrapper and all release the permit.
//!
//! HTTP/2 stream and service-wide RPC ceilings are applied on top of that, in
//! [`super::listener`] (`max_concurrent_streams` + a per-connection concurrency
//! limit with load shedding) and in [`super::server`] (a service-wide RPC permit
//! taken at the top of every RPC, before attestation, CA work, or any spawned
//! producer). Both reject rather than queue.
//!
//! ## Lifetime bounds
//!
//! Two deadlines are enforced by a per-connection watchdog:
//!
//! - the **initial** deadline runs from admission until the first byte is read.
//!   A peer that connects and then says nothing is the cheapest possible flood,
//!   and it is the shape a per-request timeout cannot see;
//! - the **idle** deadline runs from the last byte *read from the peer*. Reads,
//!   not writes, are the liveness evidence: the server's own HTTP/2 keepalive
//!   PINGs are writes, so counting writes would make the deadline unreachable.
//!   A live peer answers those PINGs with PING ACKs — which are reads — so a
//!   deliberately long-lived `FetchX509SVID` stream that is byte-idle at the
//!   application level still refreshes the deadline, while a peer that has
//!   stopped participating does not. [`super::listener`] derives the keepalive
//!   interval from the idle deadline so that relationship always holds.
//!
//! Expiry, and the forced close at the end of shutdown, are delivered by
//! flipping a flag on shared per-connection state and waking the parked I/O
//! waker. The next `poll_read`/`poll_write` then fails with
//! `ConnectionAborted`, which ends the connection deterministically from
//! *inside* the transport rather than depending on tonic's per-connection tasks
//! being reachable from outside (they are detached, and aborting the accept loop
//! does not disturb them).
//!
//! ## Ceilings
//!
//! Every limit has a finite default *and* a hard ceiling. The ceilings are
//! enforced twice: [`WorkloadApiAdmissionConfig::validate`] refuses an
//! over-ceiling value loudly at configuration time, and
//! [`WorkloadApiAdmissionConfig::clamped`] — applied by the admission
//! constructor — clamps whatever it is handed, so a value that reaches the
//! runtime through some other path still cannot raise the ceiling. `0` is not a
//! "disabled" spelling for any of them: an unbounded Workload API transport is
//! the defect this module exists to remove.
//!
//! ## Metrics
//!
//! Counters and gauges are **fixed-cardinality**: an aggregate active-connection
//! gauge, and rejection/close counters keyed only by a closed set of
//! `&'static str` reasons. Peer UID, PID, SPIFFE ID, and token material are
//! attacker-influenced or credential-adjacent and are never metric labels; the
//! per-rejection detail stays in `debug!` logs, which are off by default and so
//! cannot themselves be flooded into a disk-exhaustion primitive.

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::task::AtomicWaker;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio::time::Instant;
use tokio_stream::Stream;
use tracing::{debug, warn};

use crate::plugins::mesh::prometheus_helpers as mesh_metrics;

use super::listener::WorkloadApiListenerError;

/// Default number of simultaneously accepted Workload API connections.
///
/// A node's workloads hold one Workload API connection each in the steady
/// state, so this is generous for a single node while still being a finite,
/// pre-allocated bound on file descriptors and HTTP/2 connection state.
pub const DEFAULT_MAX_CONNECTIONS: usize = 256;

/// Hard ceiling on total connections. An operator may raise the soft limit up to
/// here and no further.
pub const MAX_CONNECTIONS_CEILING: usize = 4096;

/// Default per-peer-UID connection quota.
///
/// Sized so a normal workload (one connection, plus reconnect overlap and a few
/// sidecar helpers sharing a uid) is never affected, while a single uid cannot
/// approach [`DEFAULT_MAX_CONNECTIONS`].
pub const DEFAULT_MAX_CONNECTIONS_PER_UID: usize = 32;

/// Hard ceiling on the per-UID quota.
pub const MAX_CONNECTIONS_PER_UID_CEILING: usize = 1024;

/// Default HTTP/2 `SETTINGS_MAX_CONCURRENT_STREAMS` advertised per connection.
///
/// The Workload API has five RPCs and a workload keeps at most a handful of
/// them open; the headroom absorbs rotation overlap without admitting a
/// stream-fanout flood.
pub const DEFAULT_MAX_CONCURRENT_STREAMS: u32 = 64;

/// Hard ceiling on per-connection HTTP/2 streams.
pub const MAX_CONCURRENT_STREAMS_CEILING: u32 = 1024;

/// Default service-wide ceiling on concurrently admitted RPCs.
pub const DEFAULT_MAX_CONCURRENT_RPCS: usize = 512;

/// Hard ceiling on service-wide concurrent RPCs.
pub const MAX_CONCURRENT_RPCS_CEILING: usize = 8192;

/// Default deadline from admission to the first byte read from the peer.
pub const DEFAULT_INITIAL_CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

/// Hard ceiling on the initial-connection deadline.
pub const INITIAL_CONNECTION_TIMEOUT_CEILING: Duration = Duration::from_secs(300);

/// Default deadline since the last byte read from the peer.
///
/// Comfortably above the keepalive interval derived from it, so an established
/// long-lived stream is refreshed by PING ACKs rather than closed.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(900);

/// Hard ceiling on the idle deadline.
pub const IDLE_TIMEOUT_CEILING: Duration = Duration::from_secs(86_400);

/// Default bounded graceful-drain deadline at shutdown.
pub const DEFAULT_SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

/// Hard ceiling on the graceful-drain deadline.
pub const SHUTDOWN_GRACE_CEILING: Duration = Duration::from_secs(300);

/// How long the serve future is given to finish *after* connections have been
/// force-closed, before it is abandoned entirely.
///
/// Not operator-configurable: it bounds only the interval between "every live
/// connection has been made to fail" and "the transport noticed", which is a
/// property of the runtime rather than of the deployment.
pub const FORCE_CLOSE_SETTLE: Duration = Duration::from_secs(5);

/// Longest a watchdog sleeps between deadline checks.
///
/// The deadline itself is evaluated against a monotonic clock, so this only
/// bounds detection latency, never accuracy.
const WATCHDOG_MAX_TICK: Duration = Duration::from_secs(1);

/// Shortest watchdog tick, so a very small configured deadline cannot turn the
/// watchdog into a busy loop.
const WATCHDOG_MIN_TICK: Duration = Duration::from_millis(25);

/// How long the accept loop pauses after a resource-exhaustion accept error.
///
/// `EMFILE`/`ENFILE`/`ENOBUFS` persist until a descriptor is released, and
/// retrying immediately would spin a runtime worker at full speed for as long as
/// the condition lasted.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(50);

/// Rejection reasons. A closed set of `&'static str`, so the metric dimension
/// they key is fixed regardless of what any caller does.
pub mod reject_reason {
    /// `SO_PEERCRED` could not be read, so the connection cannot be charged to
    /// any principal's quota.
    pub const PEER_CREDENTIALS: &str = "peer_credentials";
    /// The total connection ceiling is saturated.
    pub const MAX_CONNECTIONS: &str = "max_connections";
    /// The peer UID is at its per-UID quota.
    pub const MAX_CONNECTIONS_PER_UID: &str = "max_connections_per_uid";
    /// The listener has stopped admitting because shutdown was requested.
    pub const SHUTTING_DOWN: &str = "shutting_down";
}

/// Reasons the listener itself closed an established connection.
pub mod close_reason {
    /// No first byte arrived before the initial-connection deadline.
    pub const INITIAL_TIMEOUT: &str = "initial_timeout";
    /// No byte was read from the peer before the idle deadline.
    pub const IDLE_TIMEOUT: &str = "idle_timeout";
    /// The bounded graceful-drain deadline expired at shutdown.
    pub const SHUTDOWN_DEADLINE: &str = "shutdown_deadline";
}

/// Operator-facing transport admission limits for the Workload API listener.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadApiAdmissionConfig {
    /// Simultaneously accepted connections across all peers.
    pub max_connections: usize,
    /// Simultaneously accepted connections per kernel-attested peer UID.
    pub max_connections_per_uid: usize,
    /// HTTP/2 `SETTINGS_MAX_CONCURRENT_STREAMS` advertised per connection, and
    /// the per-connection request concurrency limit paired with load shedding.
    pub max_concurrent_streams: u32,
    /// Service-wide concurrently admitted RPCs.
    pub max_concurrent_rpcs: usize,
    /// Deadline from admission to the first byte read from the peer.
    pub initial_connection_timeout: Duration,
    /// Deadline since the last byte read from the peer.
    pub idle_timeout: Duration,
    /// Bounded graceful-drain deadline at shutdown.
    pub shutdown_grace: Duration,
}

impl Default for WorkloadApiAdmissionConfig {
    fn default() -> Self {
        Self {
            max_connections: DEFAULT_MAX_CONNECTIONS,
            max_connections_per_uid: DEFAULT_MAX_CONNECTIONS_PER_UID,
            max_concurrent_streams: DEFAULT_MAX_CONCURRENT_STREAMS,
            max_concurrent_rpcs: DEFAULT_MAX_CONCURRENT_RPCS,
            initial_connection_timeout: DEFAULT_INITIAL_CONNECTION_TIMEOUT,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            shutdown_grace: DEFAULT_SHUTDOWN_GRACE,
        }
    }
}

impl WorkloadApiAdmissionConfig {
    /// Build from the parsed `FERRUM_MESH_WORKLOAD_API_*` admission settings.
    ///
    /// Deliberately a plain constructor with no validation: `validate` is the
    /// single place a value is judged, so `EnvConfig::validate` and mesh startup
    /// cannot disagree about what is acceptable.
    pub fn from_settings(
        max_connections: usize,
        max_connections_per_uid: usize,
        max_concurrent_streams: u32,
        max_concurrent_rpcs: usize,
        initial_connection_timeout_seconds: u64,
        idle_timeout_seconds: u64,
        shutdown_grace_seconds: u64,
    ) -> Self {
        Self {
            max_connections,
            max_connections_per_uid,
            max_concurrent_streams,
            max_concurrent_rpcs,
            initial_connection_timeout: Duration::from_secs(initial_connection_timeout_seconds),
            idle_timeout: Duration::from_secs(idle_timeout_seconds),
            shutdown_grace: Duration::from_secs(shutdown_grace_seconds),
        }
    }

    /// Refuse a configuration that is unbounded, over a hard ceiling, or
    /// internally contradictory.
    ///
    /// Refusal rather than silent clamping: a limit an operator set and a limit
    /// the process enforces must be the same number, or the deployment's
    /// documented posture is not the one running. [`Self::clamped`] still
    /// applies the ceilings defensively at construction, so the two together
    /// give a loud failure *and* an enforced bound.
    pub fn validate(&self) -> Result<(), WorkloadApiListenerError> {
        check_range(
            "FERRUM_MESH_WORKLOAD_API_MAX_CONNECTIONS",
            self.max_connections,
            MAX_CONNECTIONS_CEILING,
        )?;
        check_range(
            "FERRUM_MESH_WORKLOAD_API_MAX_CONNECTIONS_PER_UID",
            self.max_connections_per_uid,
            MAX_CONNECTIONS_PER_UID_CEILING,
        )?;
        check_range(
            "FERRUM_MESH_WORKLOAD_API_MAX_CONCURRENT_STREAMS",
            self.max_concurrent_streams as usize,
            MAX_CONCURRENT_STREAMS_CEILING as usize,
        )?;
        check_range(
            "FERRUM_MESH_WORKLOAD_API_MAX_CONCURRENT_RPCS",
            self.max_concurrent_rpcs,
            MAX_CONCURRENT_RPCS_CEILING,
        )?;
        check_duration(
            "FERRUM_MESH_WORKLOAD_API_INITIAL_CONNECTION_TIMEOUT_SECONDS",
            self.initial_connection_timeout,
            INITIAL_CONNECTION_TIMEOUT_CEILING,
        )?;
        check_duration(
            "FERRUM_MESH_WORKLOAD_API_IDLE_TIMEOUT_SECONDS",
            self.idle_timeout,
            IDLE_TIMEOUT_CEILING,
        )?;
        check_duration(
            "FERRUM_MESH_WORKLOAD_API_SHUTDOWN_GRACE_SECONDS",
            self.shutdown_grace,
            SHUTDOWN_GRACE_CEILING,
        )?;

        // A per-UID quota above the global ceiling is not an error the operator
        // would notice at runtime — it simply never binds — so it is reported as
        // the misconfiguration it is rather than silently ignored.
        if self.max_connections_per_uid > self.max_connections {
            return Err(WorkloadApiListenerError::Admission(format!(
                "FERRUM_MESH_WORKLOAD_API_MAX_CONNECTIONS_PER_UID ({}) exceeds \
                 FERRUM_MESH_WORKLOAD_API_MAX_CONNECTIONS ({}), so the per-UID quota can never \
                 bind and one peer may take the whole pool",
                self.max_connections_per_uid, self.max_connections
            )));
        }
        if self.idle_timeout <= self.initial_connection_timeout {
            return Err(WorkloadApiListenerError::Admission(format!(
                "FERRUM_MESH_WORKLOAD_API_IDLE_TIMEOUT_SECONDS ({}s) must be greater than \
                 FERRUM_MESH_WORKLOAD_API_INITIAL_CONNECTION_TIMEOUT_SECONDS ({}s); an idle \
                 deadline at or below the initial one closes established connections on the \
                 same schedule as connections that never spoke",
                self.idle_timeout.as_secs(),
                self.initial_connection_timeout.as_secs()
            )));
        }
        Ok(())
    }

    /// This configuration with every hard ceiling applied.
    ///
    /// The runtime belt to `validate`'s braces: whatever the admission layer is
    /// handed, it enforces at most the ceiling. A zero is raised to one for the
    /// same reason — the admission layer has no representation for "unbounded".
    pub fn clamped(&self) -> Self {
        Self {
            max_connections: self.max_connections.clamp(1, MAX_CONNECTIONS_CEILING),
            max_connections_per_uid: self
                .max_connections_per_uid
                .clamp(1, MAX_CONNECTIONS_PER_UID_CEILING),
            max_concurrent_streams: self
                .max_concurrent_streams
                .clamp(1, MAX_CONCURRENT_STREAMS_CEILING),
            max_concurrent_rpcs: self
                .max_concurrent_rpcs
                .clamp(1, MAX_CONCURRENT_RPCS_CEILING),
            initial_connection_timeout: clamp_duration(
                self.initial_connection_timeout,
                INITIAL_CONNECTION_TIMEOUT_CEILING,
            ),
            idle_timeout: clamp_duration(self.idle_timeout, IDLE_TIMEOUT_CEILING),
            shutdown_grace: clamp_duration(self.shutdown_grace, SHUTDOWN_GRACE_CEILING),
        }
    }

    /// HTTP/2 keepalive interval derived from the idle deadline.
    ///
    /// A third of the deadline, so a responsive peer refreshes it twice over
    /// before it can expire, floored so a small deadline does not turn into a
    /// ping storm.
    pub fn keepalive_interval(&self) -> Duration {
        let derived = self.idle_timeout / 3;
        derived.max(Duration::from_secs(1))
    }

    /// How long a keepalive PING may go unanswered before HTTP/2 closes the
    /// connection itself. Kept strictly below the idle deadline so the protocol
    /// notices a dead peer at least as early as the watchdog does.
    pub fn keepalive_timeout(&self) -> Duration {
        self.keepalive_interval()
            .min(Duration::from_secs(20))
            .max(Duration::from_secs(1))
    }
}

fn clamp_duration(value: Duration, ceiling: Duration) -> Duration {
    value.clamp(Duration::from_secs(1), ceiling)
}

fn check_range(
    setting: &str,
    value: usize,
    ceiling: usize,
) -> Result<(), WorkloadApiListenerError> {
    if value == 0 {
        return Err(WorkloadApiListenerError::Admission(format!(
            "{setting} must be at least 1; `0` is not a disabled spelling, because an unbounded \
             Workload API transport lets one local process deny identity issuance to every other \
             workload on the node"
        )));
    }
    if value > ceiling {
        return Err(WorkloadApiListenerError::Admission(format!(
            "{setting} ({value}) exceeds the hard safety ceiling of {ceiling}"
        )));
    }
    Ok(())
}

fn check_duration(
    setting: &str,
    value: Duration,
    ceiling: Duration,
) -> Result<(), WorkloadApiListenerError> {
    check_range(setting, value.as_secs() as usize, ceiling.as_secs() as usize)
}

/// Shared per-connection state the watchdog and the I/O wrapper both hold.
#[derive(Debug)]
struct ConnectionActivity {
    /// Set once the connection has been force-closed. Every subsequent I/O poll
    /// fails, which is what actually ends the connection.
    closed: AtomicBool,
    /// Whether any byte has ever been read from the peer. Selects which of the
    /// two deadlines applies.
    saw_first_read: AtomicBool,
    /// Milliseconds, on the shared monotonic base, of the last read from the
    /// peer (or of admission, before the first read).
    last_read_millis: AtomicU64,
    /// Monotonic base for `last_read_millis`.
    base: Instant,
    read_waker: AtomicWaker,
    write_waker: AtomicWaker,
}

impl ConnectionActivity {
    fn new() -> Self {
        Self {
            closed: AtomicBool::new(false),
            saw_first_read: AtomicBool::new(false),
            last_read_millis: AtomicU64::new(0),
            base: Instant::now(),
            read_waker: AtomicWaker::new(),
            write_waker: AtomicWaker::new(),
        }
    }

    fn mark_read(&self) {
        let elapsed = self.base.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
        self.last_read_millis.store(elapsed, Ordering::Relaxed);
        self.saw_first_read.store(true, Ordering::Relaxed);
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Flip the flag and wake whichever half is parked, so the close is observed
    /// on the next poll rather than whenever the peer happens to write next.
    fn force_close(&self) -> bool {
        if self.closed.swap(true, Ordering::AcqRel) {
            return false;
        }
        self.read_waker.wake();
        self.write_waker.wake();
        true
    }

    /// Time since the last read from the peer.
    fn since_last_read(&self) -> Duration {
        let last = Duration::from_millis(self.last_read_millis.load(Ordering::Relaxed));
        self.base.elapsed().saturating_sub(last)
    }

    fn saw_first_read(&self) -> bool {
        self.saw_first_read.load(Ordering::Relaxed)
    }
}

/// The permit an admitted connection owns for its exact lifetime.
///
/// Both halves of the accounting are released in `Drop`, which is the whole
/// point: there is no close path — clean, error, cancelled, or panicking — that
/// can return the connection object to the allocator without also returning its
/// capacity.
#[derive(Debug)]
pub struct ConnectionPermit {
    _total: OwnedSemaphorePermit,
    per_uid: Arc<Mutex<HashMap<u32, usize>>>,
    uid: u32,
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        release_uid(&self.per_uid, self.uid);
        mesh_metrics::decrement_workload_api_active_connections();
    }
}

fn release_uid(per_uid: &Arc<Mutex<HashMap<u32, usize>>>, uid: u32) {
    // A poisoned lock would mean a panic inside the few statements below, none
    // of which can panic; recovering the guard keeps a single unrelated panic
    // from wedging admission for the whole process.
    let mut guard = match per_uid.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    if let Some(count) = guard.get_mut(&uid) {
        *count = count.saturating_sub(1);
        // Removed at zero so the map is bounded by *live* peers rather than by
        // every uid that has ever connected.
        if *count == 0 {
            guard.remove(&uid);
        }
    }
}

/// The service-wide RPC permit, held for an RPC's full lifetime — including a
/// streaming RPC's response stream, which is where a Workload API caller
/// actually consumes resources.
#[derive(Debug)]
pub struct RpcPermit {
    _permit: OwnedSemaphorePermit,
}

impl RpcPermit {
    /// Take ownership of an acquired service-wide RPC permit and count it.
    ///
    /// The gauge is moved here, next to the `Drop` that decrements it, so the
    /// two can never be applied on different paths.
    pub fn new(permit: OwnedSemaphorePermit) -> Self {
        mesh_metrics::increment_workload_api_active_rpcs();
        Self { _permit: permit }
    }
}

impl Drop for RpcPermit {
    fn drop(&mut self) {
        mesh_metrics::decrement_workload_api_active_rpcs();
    }
}

/// A response stream that keeps its RPC permit alive until the stream ends or is
/// dropped.
///
/// Attaching the permit to the *stream* rather than to the RPC method's future
/// is deliberate: `fetch_x509svid` returns as soon as the first response is
/// staged, while the resources the caller is actually holding — the producer
/// task, the rotation subscription, the pending private-key slot — live for as
/// long as the stream does.
pub struct PermitStream<S> {
    inner: Pin<Box<S>>,
    _permit: Option<RpcPermit>,
}

impl<S> PermitStream<S> {
    pub fn new(inner: S, permit: Option<RpcPermit>) -> Self {
        Self {
            inner: Box::pin(inner),
            _permit: permit,
        }
    }
}

impl<S: Stream> Stream for PermitStream<S> {
    type Item = S::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // `Pin<Box<S>>` and `Option<RpcPermit>` are both `Unpin`, so the wrapper
        // is too and the projection is trivially sound.
        self.get_mut().inner.as_mut().poll_next(cx)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

/// Non-blocking connection admission shared by the accept loop.
#[derive(Clone)]
pub struct ConnectionAdmission {
    limits: WorkloadApiAdmissionConfig,
    total: Arc<Semaphore>,
    per_uid: Arc<Mutex<HashMap<u32, usize>>>,
    force_close: watch::Receiver<bool>,
}

impl std::fmt::Debug for ConnectionAdmission {
    /// Limits and live occupancy only. Never the per-UID map: a peer UID is a
    /// principal identifier and does not belong in a diagnostic rendering any
    /// more than it belongs in a metric label.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionAdmission")
            .field("limits", &self.limits)
            .field("available", &self.total.available_permits())
            .finish_non_exhaustive()
    }
}

impl ConnectionAdmission {
    /// Build an admission gate. The limits are [`WorkloadApiAdmissionConfig::clamped`]
    /// on the way in, so no caller can construct one that exceeds a ceiling.
    pub fn new(limits: WorkloadApiAdmissionConfig, force_close: watch::Receiver<bool>) -> Self {
        let limits = limits.clamped();
        Self {
            total: Arc::new(Semaphore::new(limits.max_connections)),
            per_uid: Arc::new(Mutex::new(HashMap::new())),
            limits,
            force_close,
        }
    }

    /// Build an admission gate with no force-close channel attached.
    ///
    /// For callers (and tests) that exercise the accounting policy without a
    /// listener lifecycle. The returned gate never force-closes on shutdown
    /// because nothing will ever signal it.
    pub fn detached(limits: WorkloadApiAdmissionConfig) -> Self {
        let (_tx, rx) = watch::channel(false);
        Self::new(limits, rx)
    }

    /// The effective (clamped) limits this gate enforces.
    pub fn limits(&self) -> &WorkloadApiAdmissionConfig {
        &self.limits
    }

    /// Connections currently admitted.
    pub fn active_connections(&self) -> usize {
        self.limits
            .max_connections
            .saturating_sub(self.total.available_permits())
    }

    /// Reserve capacity for one connection from `uid`, or return `None` when
    /// either ceiling is saturated.
    ///
    /// Never waits. A caller over the limit is told so immediately and the
    /// socket is closed, so there is no queue of would-be connections holding
    /// descriptors behind the ceiling — the queue *is* the resource exhaustion
    /// this exists to prevent.
    ///
    /// Public so the *policy* — total ceiling, per-UID quota, fair availability
    /// to a second UID, release on drop — can be exercised directly, which a
    /// single-uid test process cannot do through real sockets.
    pub fn reserve(&self, uid: u32) -> Option<ConnectionPermit> {
        let total = match Arc::clone(&self.total).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                mesh_metrics::increment_workload_api_connection_rejected(
                    reject_reason::MAX_CONNECTIONS,
                );
                debug!(
                    peer_uid = uid,
                    limit = self.limits.max_connections,
                    "SPIFFE Workload API connection refused: total connection ceiling saturated"
                );
                return None;
            }
        };

        {
            let mut guard = match self.per_uid.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            let current = guard.get(&uid).copied().unwrap_or(0);
            if current >= self.limits.max_connections_per_uid {
                // `total` is dropped with this scope, so a per-UID refusal does
                // not leak a global slot. No entry is created for a refused uid
                // either, so a probing flood cannot grow the map.
                drop(guard);
                mesh_metrics::increment_workload_api_connection_rejected(
                    reject_reason::MAX_CONNECTIONS_PER_UID,
                );
                debug!(
                    peer_uid = uid,
                    limit = self.limits.max_connections_per_uid,
                    "SPIFFE Workload API connection refused: peer UID is at its connection quota"
                );
                return None;
            }
            guard.insert(uid, current + 1);
        }

        mesh_metrics::increment_workload_api_active_connections();
        Some(ConnectionPermit {
            _total: total,
            per_uid: Arc::clone(&self.per_uid),
            uid,
        })
    }

    /// Admit an accepted socket, or refuse it and close it.
    ///
    /// Runs entirely before the socket is handed to tonic, so a refused peer
    /// costs one `accept(2)` and one `close(2)` and never an HTTP/2 connection,
    /// a service clone, or a producer task.
    #[cfg(unix)]
    pub fn admit(&self, stream: tokio::net::UnixStream) -> Option<AdmittedUnixStream> {
        let uid = match stream.peer_cred() {
            Ok(cred) => cred.uid(),
            Err(error) => {
                // Fail closed. An unattributable connection cannot be charged to
                // a quota, so admitting it would be a hole in the per-UID bound
                // rather than a lenient default.
                mesh_metrics::increment_workload_api_connection_rejected(
                    reject_reason::PEER_CREDENTIALS,
                );
                warn!(
                    error = %error,
                    "SPIFFE Workload API connection refused: kernel peer credentials unavailable"
                );
                return None;
            }
        };
        let permit = self.reserve(uid)?;
        let activity = Arc::new(ConnectionActivity::new());
        spawn_connection_watchdog(
            Arc::downgrade(&activity),
            self.limits.clone(),
            self.force_close.clone(),
        );
        Some(AdmittedUnixStream {
            inner: stream,
            activity,
            _permit: permit,
        })
    }
}

/// Watch a single connection's deadlines and the listener's force-close signal.
///
/// Holds only a [`Weak`] reference, so the task ends by itself once tonic drops
/// the connection — the connection's lifetime owns the watchdog, not the other
/// way round, and the number of live watchdogs is bounded by the connection
/// ceiling.
fn spawn_connection_watchdog(
    activity: Weak<ConnectionActivity>,
    limits: WorkloadApiAdmissionConfig,
    mut force_close: watch::Receiver<bool>,
) {
    let tick = limits
        .initial_connection_timeout
        .min(limits.idle_timeout)
        .max(WATCHDOG_MIN_TICK * 4)
        / 4;
    let tick = tick.clamp(WATCHDOG_MIN_TICK, WATCHDOG_MAX_TICK);

    tokio::spawn(async move {
        loop {
            let forced = tokio::select! {
                _ = tokio::time::sleep(tick) => false,
                changed = force_close.changed() => {
                    // A closed channel means the listener is gone; treat it like
                    // the force-close it precedes rather than parking forever.
                    changed.is_err() || *force_close.borrow()
                }
            };
            let Some(activity) = activity.upgrade() else {
                return;
            };
            if activity.is_closed() {
                return;
            }
            if forced {
                if activity.force_close() {
                    mesh_metrics::increment_workload_api_connection_closed(
                        close_reason::SHUTDOWN_DEADLINE,
                    );
                }
                return;
            }
            let (deadline, reason) = if activity.saw_first_read() {
                (limits.idle_timeout, close_reason::IDLE_TIMEOUT)
            } else {
                (
                    limits.initial_connection_timeout,
                    close_reason::INITIAL_TIMEOUT,
                )
            };
            if activity.since_last_read() >= deadline {
                if activity.force_close() {
                    mesh_metrics::increment_workload_api_connection_closed(reason);
                    debug!(
                        reason,
                        deadline_secs = deadline.as_secs(),
                        "SPIFFE Workload API connection closed on its transport deadline"
                    );
                }
                return;
            }
        }
    });
}

/// An accepted Workload API connection that owns its admission permit.
///
/// The permit is a private field with no accessor precisely so it cannot be
/// separated from the connection: dropping the stream is the only way to end
/// the connection, and it is therefore also the only way to release capacity.
#[cfg(unix)]
pub struct AdmittedUnixStream {
    inner: tokio::net::UnixStream,
    activity: Arc<ConnectionActivity>,
    _permit: ConnectionPermit,
}

#[cfg(unix)]
impl std::fmt::Debug for AdmittedUnixStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdmittedUnixStream").finish_non_exhaustive()
    }
}

#[cfg(unix)]
fn aborted() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "SPIFFE Workload API connection closed by the listener's transport admission policy",
    )
}

#[cfg(unix)]
impl tokio::io::AsyncRead for AdmittedUnixStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.activity.is_closed() {
            return Poll::Ready(Err(aborted()));
        }
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                if buf.filled().len() > before {
                    this.activity.mark_read();
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => {
                this.activity.read_waker.register(cx.waker());
                // Re-checked after registering: a force-close that landed
                // between the check above and the registration would otherwise
                // have woken nobody and the connection would park until the peer
                // spoke again — which, for the idle peer this deadline exists
                // for, is never.
                if this.activity.is_closed() {
                    return Poll::Ready(Err(aborted()));
                }
                Poll::Pending
            }
        }
    }
}

#[cfg(unix)]
impl tokio::io::AsyncWrite for AdmittedUnixStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.activity.is_closed() {
            return Poll::Ready(Err(aborted()));
        }
        match Pin::new(&mut this.inner).poll_write(cx, buf) {
            Poll::Pending => {
                this.activity.write_waker.register(cx.waker());
                if this.activity.is_closed() {
                    return Poll::Ready(Err(aborted()));
                }
                Poll::Pending
            }
            other => other,
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.activity.is_closed() {
            return Poll::Ready(Err(aborted()));
        }
        match Pin::new(&mut this.inner).poll_write_vectored(cx, bufs) {
            Poll::Pending => {
                this.activity.write_waker.register(cx.waker());
                if this.activity.is_closed() {
                    return Poll::Ready(Err(aborted()));
                }
                Poll::Pending
            }
            other => other,
        }
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.activity.is_closed() {
            return Poll::Ready(Err(aborted()));
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.activity.is_closed() {
            // Already torn down; report success so the caller's shutdown path
            // completes rather than looping on an error it cannot act on.
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

/// Preserve the kernel-attested peer credentials tonic exposes to the service.
///
/// Delegated to the wrapped `UnixStream` rather than reconstructed: `PeerInfo`
/// extraction and every `SO_PEERCRED` attestor read `UdsConnectInfo`, so the
/// admission wrapper must be transparent to them or it would silently disable
/// peer-credential attestation.
#[cfg(unix)]
impl tonic::transport::server::Connected for AdmittedUnixStream {
    type ConnectInfo = tonic::transport::server::UdsConnectInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        self.inner.connect_info()
    }
}

/// The accept loop, as a stream of admitted connections.
///
/// Yields only admitted connections — a refused or failed accept never becomes
/// a stream item, so the transport below it cannot observe an error it would
/// react to by tearing down the listener.
///
/// Ends immediately when `stop` flips, so shutdown stops admission at once
/// rather than admitting one more connection per accept the runtime happens to
/// have already completed.
#[cfg(unix)]
pub fn admission_stream(
    listener: tokio::net::UnixListener,
    admission: ConnectionAdmission,
    stop: watch::Receiver<bool>,
) -> impl Stream<Item = Result<AdmittedUnixStream, io::Error>> + Send {
    struct AcceptState {
        listener: tokio::net::UnixListener,
        admission: ConnectionAdmission,
        stop: watch::Receiver<bool>,
    }

    futures_util::stream::unfold(
        AcceptState {
            listener,
            admission,
            stop,
        },
        |mut state| async move {
            loop {
                if *state.stop.borrow() {
                    return None;
                }
                let accepted = tokio::select! {
                    biased;
                    _ = wait_until_set(&mut state.stop) => return None,
                    accepted = state.listener.accept() => accepted,
                };
                match accepted {
                    Ok((stream, _addr)) => {
                        if *state.stop.borrow() {
                            // Shutdown was requested while this accept was in
                            // flight. Admission stops at that instant rather
                            // than one connection later, so the bounded drain
                            // never has to cover a peer taken on after the
                            // listener was told to stop.
                            mesh_metrics::increment_workload_api_connection_rejected(
                                reject_reason::SHUTTING_DOWN,
                            );
                            drop(stream);
                            return None;
                        }
                        if let Some(admitted) = state.admission.admit(stream) {
                            return Some((Ok(admitted), state));
                        }
                        // Refused: the socket is dropped here, so the peer sees
                        // an immediate EOF instead of a connection that lingers.
                    }
                    Err(error) => {
                        warn!(
                            error = %error,
                            "SPIFFE Workload API accept failed"
                        );
                        if is_resource_exhaustion(&error) {
                            // Retrying a descriptor exhaustion immediately would
                            // spin a worker at full speed until something else
                            // released a descriptor.
                            tokio::time::sleep(ACCEPT_BACKOFF).await;
                        }
                    }
                }
            }
        },
    )
}

/// Whether an `accept(2)` failure is a resource exhaustion that will persist
/// until something unrelated releases capacity.
#[cfg(unix)]
fn is_resource_exhaustion(error: &io::Error) -> bool {
    let Some(code) = error.raw_os_error() else {
        return false;
    };
    code == libc::EMFILE || code == libc::ENFILE || code == libc::ENOBUFS || code == libc::ENOMEM
}

/// Resolve once a `watch::Sender<bool>` has published `true`, or once the sender
/// is gone.
pub(crate) async fn wait_until_set(rx: &mut watch::Receiver<bool>) {
    while !*rx.borrow() {
        if rx.changed().await.is_err() {
            return;
        }
    }
}
