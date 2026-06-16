//! Mesh UDP TPROXY capture listener (F3 §3.3 Stage 3).
//!
//! Stage 2 (`src/capture/mod.rs`) emits the flag-gated, default-off netfilter
//! `TPROXY` rules that divert a captured pod's UDP egress to a transparent
//! local socket WITHOUT rewriting the destination. This module is the consuming
//! listener: it binds that socket (`IP_TRANSPARENT` + `IP_RECVORIGDSTADDR` /
//! `IPV6_RECVORIGDSTADDR`), drains datagrams via `recvmmsg`, recovers each
//! datagram's ORIGINAL destination from the per-datagram cmsg (NOT
//! `SO_ORIGINAL_DST`, which is TCP/conntrack-only), and keys a lightweight
//! session by `(client SocketAddr, orig-dst SocketAddr)`.
//!
//! **Stage 3 is capture → DROP, intentionally inert.** For now a captured
//! datagram whose orig-dst would route to mesh egress is DROPPED with a debug
//! log — the egress relay (forwarding the datagram over the topology's mesh
//! transport to the destination workload) is Stage 4. This stage exercises the
//! listener, the `IP_TRANSPARENT` bind, the cmsg orig-dst extraction, and the
//! session keying, all gated behind `FERRUM_MESH_CAPTURE_UDP_ENABLED`
//! (default-off) so there is no behavior change when the flag is off.
//!
//! **DoS bounds** are reused from the plain UDP proxy (`udp_proxy.rs`): a
//! bounded session map (`FERRUM_UDP_MAX_SESSIONS`), an idle-expiry sweep
//! (`FERRUM_UDP_CLEANUP_INTERVAL_SECONDS`), and the adaptive recvmmsg batch
//! cap (`FERRUM_UDP_RECVMMSG_BATCH_SIZE`) keep a spoofed-source flood from
//! growing memory or starving the runtime.
//!
//! Linux-only (`IP_TRANSPARENT` + recvmsg cmsg). Non-Linux is a stub that logs
//! and returns immediately.

#[cfg(target_os = "linux")]
use std::net::SocketAddr;
use std::net::SocketAddr as StdSocketAddr;

use tokio::sync::watch;

/// Idle timeout for a captured UDP session, in milliseconds. Stage 3 only
/// tracks sessions for DoS accounting (no backend leg yet), so a fixed bound
/// mirroring the plain-UDP default (60s) is sufficient; Stage 4's egress relay
/// will adopt the per-proxy `udp_idle_timeout_seconds`.
#[cfg(target_os = "linux")]
const CAPTURE_SESSION_IDLE_TIMEOUT_MS: u64 = 60_000;

/// Configuration for the mesh UDP capture listener.
pub struct MeshUdpCaptureConfig {
    /// Address+port to bind. The port is the Stage-2 TPROXY listener port
    /// (`FERRUM_MESH_CAPTURE_UDP_PORT`, default 15011).
    pub addr: StdSocketAddr,
    /// Shared proxy state — threaded in for Stage 4 so the listener can consult
    /// the `mesh_udp_egress` route table, LB-select a workload, gate on the
    /// gateway SVID + HBONE capability, and open the datagram-over-HBONE tunnel.
    /// (Stage 3 dropped captured datagrams and needed no state; this is the
    /// enabling refactor.)
    pub state: std::sync::Arc<super::ProxyState>,
    /// Per-listener shutdown receiver (config-driven removal).
    pub shutdown: watch::Receiver<bool>,
    /// Gateway-wide shutdown receiver (SIGTERM/SIGINT). When `Some`, the recv
    /// loop exits as soon as either this OR `shutdown` fires.
    pub global_shutdown: Option<watch::Receiver<bool>>,
    /// Max concurrent captured sessions (`FERRUM_UDP_MAX_SESSIONS`).
    pub max_sessions: usize,
    /// Idle-session cleanup interval in seconds (`FERRUM_UDP_CLEANUP_INTERVAL_SECONDS`).
    pub cleanup_interval_seconds: u64,
    /// Datagrams per `recvmmsg` syscall (`FERRUM_UDP_RECVMMSG_BATCH_SIZE`).
    pub recvmmsg_batch_size: usize,
    /// DashMap shard count for the session map (`FERRUM_POOL_SHARD_AMOUNT`).
    pub session_shard_amount: usize,
    /// Signalled once the listener has bound and is ready to accept.
    pub started_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

/// Session key: a captured flow is identified by the client's source address
/// and the datagram's original (pre-TPROXY) destination. Two pods dialing the
/// same upstream, or one pod dialing two upstreams, are distinct sessions.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CaptureSessionKey {
    pub client: SocketAddr,
    pub orig_dst: SocketAddr,
}

/// Whether `e` indicates IPv6 is unavailable on this host (so the dual-stack
/// `[::]` capture bind may safely fall back to the v4 wildcard). True ONLY for
/// "address family not supported" / "cannot assign requested address" /
/// "protocol not supported" — NOT for a real conflict like `EADDRINUSE`, which
/// must surface so IPv6 UDP is never silently left black-holed behind a v4-only
/// listener while `ip6tables` still diverts it to this port.
#[cfg(target_os = "linux")]
fn is_ipv6_unavailable_error(e: &anyhow::Error) -> bool {
    e.downcast_ref::<std::io::Error>().is_some_and(|io_err| {
        matches!(
            io_err.raw_os_error(),
            Some(libc::EAFNOSUPPORT) | Some(libc::EADDRNOTAVAIL) | Some(libc::EPROTONOSUPPORT)
        ) || io_err.kind() == std::io::ErrorKind::AddrNotAvailable
    })
}

/// Start the mesh UDP capture listener (Linux).
///
/// Binds a transparent UDP socket on `cfg.addr`, enables per-datagram orig-dst
/// recovery, and drains datagrams in a `recvmmsg` loop. Each captured datagram
/// is keyed into a bounded session map and then DROPPED (Stage 3 has no egress
/// relay). The listener runs until either shutdown channel fires.
#[cfg(target_os = "linux")]
pub async fn start_mesh_udp_capture_listener(
    cfg: MeshUdpCaptureConfig,
) -> Result<(), anyhow::Error> {
    use std::net::{IpAddr, Ipv4Addr};
    use std::os::fd::AsRawFd;
    use std::sync::Arc;
    use std::sync::atomic::AtomicU64;
    use tokio::net::UdpSocket;
    use tracing::{info, warn};

    let MeshUdpCaptureConfig {
        addr,
        state,
        shutdown,
        global_shutdown,
        max_sessions,
        cleanup_interval_seconds,
        recvmmsg_batch_size,
        session_shard_amount,
        started_tx,
    } = cfg;

    // Build a bound transparent capture socket on `bind_addr`. Factored into a
    // closure so the preferred dual-stack `[::]` bind can fall back to the v4
    // wildcard on hosts without IPv6 (codex r3 P2). Sets IP_TRANSPARENT /
    // IP_RECVORIGDSTADDR BEFORE binding (socket2 gives SO_REUSEADDR + the raw fd
    // without binding twice); returns the bound std socket + which orig-dst
    // families were enabled.
    let build_bound_socket =
        |bind_addr: SocketAddr| -> Result<(std::net::UdpSocket, bool, bool), anyhow::Error> {
            let domain = match bind_addr.ip() {
                IpAddr::V4(_) => socket2::Domain::IPV4,
                IpAddr::V6(_) => socket2::Domain::IPV6,
            };
            let socket =
                socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
            // TPROXY delivery requires SO_REUSEADDR so the transparent socket can
            // claim the marked datagrams alongside the kernel's normal routing.
            socket.set_reuse_address(true)?;
            socket.set_nonblocking(true)?;

            let fd = socket.as_raw_fd();
            // IP_TRANSPARENT: accept datagrams whose dst is not local to this host
            // (the captured pod's real service:port, un-rewritten by TPROXY).
            // Fatal if it fails — without transparency the socket can't receive
            // the captured traffic at all, so a half-bound listener would
            // silently black-hole.
            match bind_addr.ip() {
                IpAddr::V4(_) => crate::socket_opts::set_ip_transparent(fd)?,
                IpAddr::V6(_) => {
                    // Dual-stack `[::]`: disable V6ONLY so this one socket also
                    // receives v4-mapped datagrams, and set BOTH transparencies
                    // so v4-mapped and native-v6 captured traffic are both
                    // claimed (codex r3 P2).
                    socket.set_only_v6(false)?;
                    crate::socket_opts::set_ipv6_transparent(fd)?;
                    // Best-effort v4 transparency for v4-mapped datagrams on `::`.
                    let _ = crate::socket_opts::set_ip_transparent(fd);
                }
            }
            // IP(v6)_RECVORIGDSTADDR: surface each datagram's original destination
            // as a cmsg (TPROXY does not rewrite it). Request both variants so a
            // dual-stack listener recovers orig-dst regardless of family.
            let v4_origdst = crate::socket_opts::set_ip_recvorigdstaddr(fd).is_ok();
            let v6_origdst = crate::socket_opts::set_ipv6_recvorigdstaddr(fd).is_ok();
            if !v4_origdst && !v6_origdst {
                // Without orig-dst recovery a captured datagram cannot be routed
                // to its real destination, so refuse rather than bind a listener
                // that can only drop-without-knowing-where. (Stage 3 drops anyway,
                // but Stage 4 relies on this; failing here surfaces a bad kernel
                // early.)
                return Err(anyhow::anyhow!(
                    "mesh UDP capture: IP_RECVORIGDSTADDR setsockopt failed on both v4 and v6 (kernel lacks orig-dst recovery)"
                ));
            }

            socket.bind(&bind_addr.into())?;
            Ok((socket.into(), v4_origdst, v6_origdst))
        };

    // Prefer the dual-stack `[::]` bind so one transparent socket captures both
    // v4-mapped and v6 datagrams; fall back to the v4 wildcard ONLY when IPv6 is
    // genuinely unavailable on this host (codex r4). Falling back on ANY error
    // (e.g. the port is already owned by a v6-only socket, EADDRINUSE) would
    // report the listener "started" on v4 while ip6tables still diverts IPv6 UDP
    // to this port with no working v6 listener — blackholing v6 while the pod
    // looks ready. So a non-IPv6-availability error is returned, not masked.
    let (std_socket, addr, v4_origdst, v6_origdst) = match build_bound_socket(addr) {
        Ok((s, v4, v6)) => (s, addr, v4, v6),
        Err(e) if addr.ip().is_ipv6() && is_ipv6_unavailable_error(&e) => {
            let v4_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), addr.port());
            warn!(
                requested = %addr,
                fallback = %v4_addr,
                "Mesh UDP capture: IPv6 unavailable for dual-stack [::] bind ({e}); falling back to v4 wildcard (IPv6 UDP capture unavailable on this host)"
            );
            let (s, v4, v6) = build_bound_socket(v4_addr)?;
            (s, v4_addr, v4, v6)
        }
        Err(e) => return Err(e),
    };
    let frontend_socket = Arc::new(UdpSocket::from_std(std_socket)?);

    let session_shard_amount = crate::util::sharding::pool_shard_amount(session_shard_amount);
    // Bounded session map keyed by (client, orig-dst). Kernel-provided keys, so
    // ahash (non-cryptographic) is fine — speed wins on the per-datagram lookup.
    let sessions: Arc<dashmap::DashMap<CaptureSessionKey, CaptureSession, ahash::RandomState>> =
        Arc::new(dashmap::DashMap::with_hasher_and_shard_amount(
            ahash::RandomState::default(),
            session_shard_amount,
        ));
    // Cheap atomic session count for the per-datagram cap check. The spoofed-
    // source flood path hits a map miss for every new (client, orig-dst), so the
    // cap MUST NOT call `DashMap::len()` there (it walks/locks every shard —
    // exactly what the cap defends against). Mirror the plain UDP proxy's
    // `active_sessions` atomic: bumped on insert, decremented as the idle sweep
    // reaps (codex r3 P2).
    let active_sessions = Arc::new(AtomicU64::new(0));

    if let Some(tx) = started_tx {
        let _ = tx.send(());
    }
    info!(
        addr = %addr,
        v4_origdst,
        v6_origdst,
        "Mesh UDP capture listener started (capture→datagram-over-HBONE egress; Ambient only)"
    );

    // Idle-session sweep — reaps captured sessions whose last datagram is older
    // than the idle timeout, so a spoofed-source flood ages out instead of
    // accumulating. Mirrors `udp_proxy::spawn_session_cleanup`'s identity-aware
    // expiry, simplified (no backend leg / plugins in Stage 3).
    spawn_capture_session_cleanup(
        sessions.clone(),
        active_sessions.clone(),
        shutdown.clone(),
        cleanup_interval_seconds,
    );

    let mut shutdown_rx = shutdown;
    let mut global_shutdown_rx = global_shutdown;
    // `true`: this listener enables `IP_RECVORIGDSTADDR` and keys sessions on
    // the captured orig-dst, so it opts into per-datagram orig-dst cmsg parsing.
    let mut recv_batch = super::udp_batch::RecvMmsgBatch::new(recvmmsg_batch_size, true);

    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    info!(addr = %addr, "Mesh UDP capture listener shutting down");
                    break;
                }
            }
            changed = async {
                match global_shutdown_rx.as_mut() {
                    Some(rx) => rx.changed().await,
                    // No global channel: never resolves so the other arms drive.
                    None => std::future::pending().await,
                }
            } => {
                if changed.is_ok() && global_shutdown_rx.as_ref().is_some_and(|rx| *rx.borrow()) {
                    info!(addr = %addr, "Mesh UDP capture listener shutting down (gateway shutdown)");
                    break;
                }
            }
            ready = frontend_socket.readable() => {
                if let Err(e) = ready {
                    warn!(addr = %addr, "Mesh UDP capture readable error: {}", e);
                    continue;
                }
                // ALWAYS recvmmsg here (unlike udp_proxy, which has a recv_from
                // primary path): the original destination rides the cmsg, which
                // tokio's recv_from cannot surface, so every datagram must go
                // through the cmsg-aware recvmmsg path.
                let fd = frontend_socket.as_raw_fd();
                let mut total_drained: usize = 0;
                let cap = recv_batch.capacity();
                'drain: loop {
                    match frontend_socket.try_io(tokio::io::Interest::READABLE, || {
                        recv_batch.recv(fd, cap)
                    }) {
                        Ok(n) if n > 0 => {
                            for i in 0..n {
                                let (data, client) = recv_batch.datagram(i);
                                let orig_dst = recv_batch.orig_dst(i);
                                let gro = recv_batch.gro_segment_size(i);
                                // GRO may coalesce many datagrams into one buffer;
                                // frame EACH segment separately (a coalesced
                                // superblock is N datagrams, not one — risk #8).
                                match gro {
                                    Some(seg) if (seg as usize) < data.len() => {
                                        for chunk in data.chunks(seg as usize) {
                                            handle_captured_datagram(
                                                &sessions,
                                                &active_sessions,
                                                &state,
                                                client,
                                                orig_dst,
                                                chunk,
                                                max_sessions,
                                            );
                                        }
                                    }
                                    _ => {
                                        handle_captured_datagram(
                                            &sessions,
                                            &active_sessions,
                                            &state,
                                            client,
                                            orig_dst,
                                            data,
                                            max_sessions,
                                        );
                                    }
                                }
                            }
                            total_drained += n;
                            // Bound the per-wakeup drain so one busy socket can't
                            // starve shutdown/other tasks.
                            if total_drained >= cap.saturating_mul(16) {
                                break 'drain;
                            }
                        }
                        _ => break 'drain, // WouldBlock or error — socket drained
                    }
                }
            }
        }
    }
    Ok(())
}

/// Bounded depth of a per-session egress channel. Captured datagrams are
/// queued here from the (synchronous, hot-path-light) recv loop and drained by
/// the async egress task that frames + writes them onto the HBONE tunnel. A
/// full channel DROPS the datagram (UDP-appropriate backpressure — UDP gives no
/// delivery guarantee, and blocking the bounded recv-loop drain would let one
/// slow session starve every other captured flow). Sized generously so a brief
/// tunnel-dial stall (the channel buffers datagrams until the tunnel is ready)
/// does not shed a normal burst.
#[cfg(target_os = "linux")]
const EGRESS_CHANNEL_DEPTH: usize = 1024;

/// Per-(client, orig-dst) capture session (Stage 4). `last_activity` is
/// monotonic millis from [`crate::socket_opts::monotonic_now_ms`] (never goes
/// backwards under NTP slew, so idle expiry always fires). `tx` hands captured
/// datagram payloads to the per-session egress task; when the session is reaped
/// (idle sweep) or the map entry is replaced, dropping `tx` closes the channel,
/// which ends the egress task and tears the tunnel down (its `poll_shutdown`
/// sends the h2 end-stream).
#[cfg(target_os = "linux")]
struct CaptureSession {
    last_activity: u64,
    /// Egress channel to the per-session task. `None` for a session whose
    /// orig-dst matched no routable `mesh_udp_egress` entry — but such flows are
    /// never inserted (they drop without a session), so in practice this is
    /// always `Some` for a live session. Kept as `Option` only so the unit
    /// tests can exercise the keying/cap logic without a live tunnel.
    tx: Option<tokio::sync::mpsc::Sender<bytes::Bytes>>,
}

/// Record a captured datagram against its session and forward it toward mesh
/// egress (Stage 4).
///
/// On a NEW `(client, orig-dst)` flow this consults the `mesh_udp_egress` route
/// table; only a routable (`Relay`) destination admits a session (under the
/// `max_sessions` cap) and spawns the per-session egress task. A non-routable
/// orig-dst (no match, or a declared-but-`CloseNotRoutable` pair) DROPS the
/// datagram WITHOUT creating a session — fail closed, never guessed, and never
/// holding a slot for un-routable traffic. An EXISTING flow refreshes its
/// `last_activity` and enqueues the payload (drop-on-full).
///
/// Returns `true` if the datagram was accounted (existing or newly admitted),
/// `false` if it was dropped (no orig-dst, not routable, cap reached, or the
/// egress channel was full) — exposed for unit testing the keying/cap logic.
#[cfg(target_os = "linux")]
fn handle_captured_datagram(
    sessions: &std::sync::Arc<
        dashmap::DashMap<CaptureSessionKey, CaptureSession, ahash::RandomState>,
    >,
    active_sessions: &std::sync::Arc<std::sync::atomic::AtomicU64>,
    state: &std::sync::Arc<super::ProxyState>,
    client: SocketAddr,
    orig_dst: Option<SocketAddr>,
    data: &[u8],
    max_sessions: usize,
) -> bool {
    use tracing::debug;

    let Some(orig_dst) = orig_dst else {
        // No orig-dst cmsg ⇒ we cannot tell where the pod dialed, so there is
        // nothing to route and nothing meaningful to key on. Drop.
        debug!(
            client = %client,
            size = data.len(),
            "Mesh UDP capture: dropping datagram with no original destination cmsg"
        );
        return false;
    };

    let key = CaptureSessionKey { client, orig_dst };

    // Routability is resolved ONCE per (potentially new) flow via a closure so
    // the cap/keying bookkeeping (`admit_or_refresh_session`) stays a pure,
    // unit-testable function: it only evaluates the closure on the Vacant path
    // (an existing flow already proved routable when it was admitted). A
    // captured datagram whose orig-dst matches no declared `(VIP, UDP port)`
    // pair — or matches a declared-but-`CloseNotRoutable` pair — drops here,
    // holding no slot and spawning no task (fail closed, never guessed).
    let resolve_entry = || {
        let epoch = state.request_epoch.load();
        match epoch.route_table.mesh_udp_egress_decision(orig_dst) {
            Some(crate::router_cache::MeshTcpEgressDecision::Relay(entry)) => Some(entry.clone()),
            _ => None,
        }
    };

    match admit_or_refresh_session(
        sessions,
        active_sessions,
        key,
        data,
        max_sessions,
        resolve_entry,
    ) {
        SessionAdmission::Refreshed => true,
        SessionAdmission::Admitted { entry, rx } => {
            // Spawn the per-session egress task (tunnel dial + return path); the
            // session's `tx` (already inserted by the bookkeeping above) feeds it.
            spawn_udp_egress_session(
                state.clone(),
                sessions.clone(),
                active_sessions.clone(),
                key,
                entry,
                rx,
            );
            true
        }
        SessionAdmission::Dropped => false,
    }
}

/// Outcome of [`admit_or_refresh_session`].
#[cfg(target_os = "linux")]
enum SessionAdmission {
    /// An existing flow's session was refreshed and the datagram enqueued
    /// (or dropped-on-full, which still counts as "accounted" for the flow).
    Refreshed,
    /// A NEW routable flow was admitted: the caller must spawn the egress task
    /// driven by `rx`, relaying to `entry`'s LB-selected workload.
    Admitted {
        entry: std::sync::Arc<crate::router_cache::MeshTcpEgressEntry>,
        rx: tokio::sync::mpsc::Receiver<bytes::Bytes>,
    },
    /// The datagram was dropped (not routable, or the session cap was reached).
    Dropped,
}

/// Pure cap/keying bookkeeping for one captured datagram, factored out of
/// [`handle_captured_datagram`] so it is unit-testable without a live
/// `ProxyState`/tunnel. Refreshes-or-admits the `(client, orig-dst)` session
/// under `max_sessions` using a SINGLE DashMap `entry()` guard:
///
/// - Occupied flow → refresh `last_activity`, enqueue the payload (drop-on-full),
///   return [`SessionAdmission::Refreshed`].
/// - Vacant flow → evaluate `resolve_entry` (the routability gate); on `None`
///   drop without holding a slot; on `Some(entry)` reserve a slot via the cheap
///   `active_sessions` atomic (NOT `DashMap::len()`, which walks/locks every
///   shard on the per-datagram flood path the cap defends against), insert the
///   session with a fresh channel, enqueue the first datagram, and return
///   [`SessionAdmission::Admitted`] with the receiver for the caller to drive.
///
/// Only the atomic (never another `sessions.*` op) is touched while the entry
/// guard is held, so this cannot self-deadlock the way a nested `len()` did.
#[cfg(target_os = "linux")]
fn admit_or_refresh_session<F>(
    sessions: &dashmap::DashMap<CaptureSessionKey, CaptureSession, ahash::RandomState>,
    active_sessions: &std::sync::atomic::AtomicU64,
    key: CaptureSessionKey,
    data: &[u8],
    max_sessions: usize,
    resolve_entry: F,
) -> SessionAdmission
where
    F: FnOnce() -> Option<std::sync::Arc<crate::router_cache::MeshTcpEgressEntry>>,
{
    use dashmap::mapref::entry::Entry;
    use std::sync::atomic::Ordering;
    use tracing::debug;

    let now = crate::socket_opts::monotonic_now_ms();
    match sessions.entry(key) {
        Entry::Occupied(mut occupied) => {
            let session = occupied.get_mut();
            session.last_activity = now;
            if let Some(tx) = session.tx.as_ref() {
                // Drop-on-full: UDP backpressure is "drop", and we must never
                // block the bounded recv-loop drain.
                if tx.try_send(bytes::Bytes::copy_from_slice(data)).is_err() {
                    debug!(
                        client = %key.client,
                        orig_dst = %key.orig_dst,
                        "Mesh UDP capture: egress channel full or closed; dropping datagram"
                    );
                }
            }
            SessionAdmission::Refreshed
        }
        Entry::Vacant(vacant) => {
            // Routability gate BEFORE reserving a slot.
            let Some(entry) = resolve_entry() else {
                debug!(
                    client = %key.client,
                    orig_dst = %key.orig_dst,
                    "Mesh UDP capture: captured datagram is not a routable mesh UDP destination; \
                     dropping"
                );
                return SessionAdmission::Dropped;
            };

            // Reserve a slot atomically; hand it back and shed if over the cap.
            let prev = active_sessions.fetch_add(1, Ordering::Relaxed);
            if prev >= max_sessions as u64 {
                active_sessions.fetch_sub(1, Ordering::Relaxed);
                debug!(
                    client = %key.client,
                    orig_dst = %key.orig_dst,
                    "Mesh UDP capture: session cap reached, dropping datagram from new flow"
                );
                return SessionAdmission::Dropped;
            }

            let (tx, rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(EGRESS_CHANNEL_DEPTH);
            // The bounded channel was just created with depth >= 1 and `rx` is
            // alive (returned below), so this enqueue of the first datagram
            // cannot fail.
            let _ = tx.try_send(bytes::Bytes::copy_from_slice(data));
            vacant.insert(CaptureSession {
                last_activity: now,
                tx: Some(tx),
            });
            SessionAdmission::Admitted { entry, rx }
        }
    }
}

/// Spawn the per-session UDP egress task: open a `udp`-marked datagram-over-HBONE
/// tunnel to the LB-selected workload, frame + write captured datagrams onto it,
/// and (return path) read framed replies back off it and send them to the client
/// SOURCED FROM the captured original destination so the pod sees replies from
/// the VIP:port it dialed.
///
/// All the fail-closed gates from the raw-TCP egress path apply (LB selection,
/// gateway SVID present, HBONE capability proven, pinned-peer identity intact);
/// any gate failure logs and ends the session (the recv loop already created the
/// map entry, so it is cleaned up by the idle sweep — the channel just goes
/// undrained and fills, which drop-on-full handles harmlessly).
#[cfg(target_os = "linux")]
fn spawn_udp_egress_session(
    state: std::sync::Arc<super::ProxyState>,
    sessions: std::sync::Arc<
        dashmap::DashMap<CaptureSessionKey, CaptureSession, ahash::RandomState>,
    >,
    active_sessions: std::sync::Arc<std::sync::atomic::AtomicU64>,
    key: CaptureSessionKey,
    entry: std::sync::Arc<crate::router_cache::MeshTcpEgressEntry>,
    rx: tokio::sync::mpsc::Receiver<bytes::Bytes>,
) {
    tokio::spawn(async move {
        run_udp_egress_session(&state, &entry, key, rx).await;
        // Session teardown: remove the map entry and decrement the live count so
        // a finished/failed flow frees its slot immediately (the idle sweep is a
        // backstop for sessions whose task is still alive but quiescent).
        if sessions.remove(&key).is_some() {
            active_sessions.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        }
    });
}

/// Body of the per-session egress task. Returns when the session ends (client
/// idle, tunnel closed, or a fail-closed gate tripped). Never panics.
#[cfg(target_os = "linux")]
async fn run_udp_egress_session(
    state: &std::sync::Arc<super::ProxyState>,
    entry: &std::sync::Arc<crate::router_cache::MeshTcpEgressEntry>,
    key: CaptureSessionKey,
    mut rx: tokio::sync::mpsc::Receiver<bytes::Bytes>,
) {
    use crate::load_balancer::LoadBalancerCache;
    use tracing::{debug, warn};

    let proxy = entry.relay_proxy.as_ref();
    let epoch = state.request_epoch.load();

    // ── Fail-closed egress gates (mirrors handle_mesh_tcp_egress) ──────────
    let Some(selection) = LoadBalancerCache::select_target_from(
        &epoch.load_balancer,
        &entry.upstream_id,
        &proxy.id,
        None,
    ) else {
        warn!(
            service = %entry.service_fqdn,
            orig_dst = %key.orig_dst,
            "Mesh UDP egress has no selectable workload target; ending session"
        );
        return;
    };
    let target = selection.target;

    if state.gateway_svid_bundle.load().is_none() {
        warn!(
            service = %entry.service_fqdn,
            "Mesh UDP egress requires a loaded gateway SVID; ending session"
        );
        return;
    }

    // UDP egress is Ambient-only: the materializer stamps `mesh.hbone` (Sidecar
    // UDP is deferred), so a target must carry the HBONE tag.
    if !crate::proxy::hbone_pool::target_hbone_enabled(&target) {
        warn!(
            service = %entry.service_fqdn,
            target_host = %target.host,
            "Mesh UDP egress target is not HBONE-tagged (Sidecar UDP egress is not supported); \
             ending session"
        );
        return;
    }
    // HBONE capability must be proven (the enrollment pass + widened probe gate
    // keep these records alive; the dispatch gate fails closed until proven).
    if !state
        .backend_capabilities
        .get(proxy, Some(&target))
        .is_some_and(|record| record.hbone.is_supported())
    {
        debug!(
            service = %entry.service_fqdn,
            target_host = %target.host,
            target_port = target.port,
            "Mesh UDP egress target has no proven HBONE capability yet; ending session \
             (retry after the next capability refresh)"
        );
        return;
    }
    // Pinned peer identity: present-but-corrupt fails closed.
    let expected_peer = match crate::proxy::hbone_pool::target_expected_peer_spiffe(&target) {
        Ok(peer) => peer,
        Err(err) => {
            warn!(
                service = %entry.service_fqdn,
                target_host = %target.host,
                error = %err,
                "Mesh UDP egress target carries a corrupt pinned identity; refusing dial"
            );
            return;
        }
    };
    let hbone_port = crate::proxy::hbone_pool::target_hbone_port(&target);

    // ── Open the udp-marked datagram-over-HBONE tunnel ─────────────────────
    let tunnel = match state
        .hbone_pool
        .get_datagram_tunnel(
            proxy,
            &target.host,
            hbone_port,
            &target.host,
            target.port,
            expected_peer.as_ref(),
        )
        .await
    {
        Ok(tunnel) => tunnel,
        Err(err) => {
            warn!(
                service = %entry.service_fqdn,
                target_host = %target.host,
                target_port = target.port,
                error = %err,
                "Mesh UDP egress datagram tunnel failed; ending session"
            );
            return;
        }
    };

    // ── Return-path socket: a transparent UDP socket bound NON-LOCALLY to the
    // captured original destination so replies to the pod appear sourced from
    // the VIP:port it dialed (IP_TRANSPARENT lets us bind a non-local addr;
    // the reply's source IP AND port then come from this bind). Risk #1. ──────
    let reply_socket = match build_transparent_reply_socket(key.orig_dst) {
        Ok(sock) => std::sync::Arc::new(sock),
        Err(e) => {
            warn!(
                service = %entry.service_fqdn,
                orig_dst = %key.orig_dst,
                error = %e,
                "Mesh UDP egress could not bind a transparent reply socket; ending session \
                 (replies must be sourced from the captured destination)"
            );
            return;
        }
    };

    debug!(
        service = %entry.service_fqdn,
        orig_dst = %key.orig_dst,
        client = %key.client,
        target_host = %target.host,
        target_port = target.port,
        "Mesh UDP egress session established (datagram-over-HBONE)"
    );

    let (mut tunnel_read, mut tunnel_write) = tokio::io::split(tunnel);
    let idle = udp_session_idle_timeout(proxy);

    // Return path: read framed datagrams off the tunnel and reply to the client
    // from the transparent socket. Runs concurrently with the egress loop.
    let return_client = key.client;
    let return_socket = reply_socket.clone();
    let return_path = async move {
        let mut buf = bytes::BytesMut::with_capacity(super::mesh_udp_frame::MAX_FRAME_PAYLOAD);
        loop {
            match super::mesh_udp_frame::read_datagram(&mut tunnel_read, &mut buf).await {
                Ok(Some(payload)) => {
                    // Best-effort reply; a send error (client gone) ends the
                    // return path, which tears the session down.
                    if let Err(e) = return_socket.send_to(&payload, return_client).await {
                        debug!(
                            client = %return_client,
                            error = %e,
                            "Mesh UDP egress: reply send to client failed; ending return path"
                        );
                        break;
                    }
                }
                Ok(None) => break, // tunnel half-closed
                Err(_) => break,   // tunnel read error
            }
        }
    };

    // Egress loop: drain captured datagrams, frame each, write onto the tunnel.
    // An idle timeout (no captured datagram within the window) ends the session.
    let egress_loop = async move {
        use tokio::io::AsyncWriteExt;
        let mut frame =
            bytes::BytesMut::with_capacity(2 + super::mesh_udp_frame::MAX_FRAME_PAYLOAD);
        loop {
            let next = match idle {
                Some(d) => match tokio::time::timeout(d, rx.recv()).await {
                    Ok(v) => v,
                    Err(_) => {
                        debug!("Mesh UDP egress: session idle timeout; ending");
                        None
                    }
                },
                None => rx.recv().await,
            };
            let Some(payload) = next else { break };
            frame.clear();
            if super::mesh_udp_frame::encode_datagram(&mut frame, &payload).is_err() {
                // A captured datagram cannot exceed MAX_FRAME_PAYLOAD, so this is
                // unreachable for real traffic; skip rather than tear down.
                continue;
            }
            if let Err(e) = tunnel_write.write_all(&frame).await {
                debug!(error = %e, "Mesh UDP egress: tunnel write failed; ending session");
                break;
            }
        }
        // Half-close the tunnel write side (h2 end-stream) on the way out.
        let _ = tunnel_write.shutdown().await;
    };

    // Either side completing ends the session.
    tokio::select! {
        _ = return_path => {}
        _ = egress_loop => {}
    }
}

/// Build a transparent UDP socket bound (non-locally) to `orig_dst` so replies
/// to the captured client carry `orig_dst` as their source address AND port.
/// `IP_TRANSPARENT` (Linux, needs `CAP_NET_ADMIN`) is what permits binding to a
/// non-local address; `SO_REUSEADDR` mirrors the capture socket so multiple
/// sessions to the same VIP:port coexist. This is the TPROXY return-path
/// pattern: the kernel emits replies from the bound transparent address rather
/// than the host's own IP.
#[cfg(target_os = "linux")]
fn build_transparent_reply_socket(
    orig_dst: SocketAddr,
) -> Result<tokio::net::UdpSocket, anyhow::Error> {
    use std::net::IpAddr;
    use std::os::fd::AsRawFd;

    let domain = match orig_dst.ip() {
        IpAddr::V4(_) => socket2::Domain::IPV4,
        IpAddr::V6(_) => socket2::Domain::IPV6,
    };
    let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    let fd = socket.as_raw_fd();
    match orig_dst.ip() {
        IpAddr::V4(_) => crate::socket_opts::set_ip_transparent(fd)?,
        IpAddr::V6(_) => crate::socket_opts::set_ipv6_transparent(fd)?,
    }
    // Bind to the captured original destination (the VIP:port the pod dialed).
    // IP_TRANSPARENT makes this non-local bind succeed; replies sent on this
    // socket then originate from orig_dst.
    socket.bind(&orig_dst.into())?;
    Ok(tokio::net::UdpSocket::from_std(socket.into())?)
}

/// Resolve the per-session idle timeout for an egress session from the relay
/// proxy's `udp_idle_timeout_seconds` (the materialized relay proxy carries the
/// repo's stream-proxy default). `0` disables the idle timeout.
#[cfg(target_os = "linux")]
fn udp_session_idle_timeout(proxy: &crate::config::types::Proxy) -> Option<std::time::Duration> {
    let secs = proxy.udp_idle_timeout_seconds;
    (secs > 0).then(|| std::time::Duration::from_secs(secs))
}

/// Spawn the idle-session sweep for the capture listener. Removes sessions
/// whose `last_activity` is older than [`CAPTURE_SESSION_IDLE_TIMEOUT_MS`] on a
/// fixed interval; exits when the per-listener shutdown fires.
#[cfg(target_os = "linux")]
fn spawn_capture_session_cleanup(
    sessions: std::sync::Arc<
        dashmap::DashMap<CaptureSessionKey, CaptureSession, ahash::RandomState>,
    >,
    active_sessions: std::sync::Arc<std::sync::atomic::AtomicU64>,
    mut shutdown: watch::Receiver<bool>,
    cleanup_interval_seconds: u64,
) {
    use std::sync::atomic::Ordering;
    use std::time::Duration;
    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(Duration::from_secs(cleanup_interval_seconds.max(1)));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let now = crate::socket_opts::monotonic_now_ms();
                    // Count reaped sessions so the `active_sessions` cap counter
                    // stays in lockstep with the map. `retain`'s closure is
                    // `FnMut` (called sequentially across shards), so a plain
                    // accumulator is safe; one `fetch_sub` after keeps it lock-free.
                    let mut reaped: u64 = 0;
                    sessions.retain(|_, session| {
                        let keep = now.saturating_sub(session.last_activity)
                            <= CAPTURE_SESSION_IDLE_TIMEOUT_MS;
                        if !keep {
                            reaped += 1;
                        }
                        keep
                    });
                    if reaped > 0 {
                        active_sessions.fetch_sub(reaped, Ordering::Relaxed);
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        break;
                    }
                }
            }
        }
    });
}

/// Non-Linux stub. `IP_TRANSPARENT` and recvmsg cmsg orig-dst recovery are
/// Linux-only; mesh UDP capture is unsupported elsewhere, so the listener logs
/// and returns immediately (the flag is default-off, so this is never reached
/// in a supported deployment).
#[cfg(not(target_os = "linux"))]
pub async fn start_mesh_udp_capture_listener(
    cfg: MeshUdpCaptureConfig,
) -> Result<(), anyhow::Error> {
    // Touch the Stage-4 fields so the non-Linux build doesn't flag them dead
    // (their only real consumer is the Linux listener / egress path).
    let _ = &cfg.state;
    let _ = cfg.max_sessions;
    let _ = cfg.cleanup_interval_seconds;
    let _ = cfg.recvmmsg_batch_size;
    let _ = cfg.session_shard_amount;
    let _ = cfg.shutdown;
    let _ = cfg.global_shutdown;
    // Fire the startup-ready signal before returning: mesh startup's
    // `wait_for_start_signals()` blocks on this listener's `started_tx` even on
    // non-Linux, so dropping the sender unsent would fail startup with a closed
    // oneshot instead of behaving as the documented no-op (codex r1 P3). Mirror
    // the other listener stubs and signal ready, then return.
    if let Some(tx) = cfg.started_tx {
        let _ = tx.send(());
    }
    tracing::warn!(
        addr = %cfg.addr,
        "Mesh UDP capture listener is Linux-only (IP_TRANSPARENT + recvmsg cmsg); not starting"
    );
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    /// Build a test session map sized via the same hot-path helper the
    /// listener uses ([`crate::util::sharding::pool_shard_amount`]). Pass `0`
    /// to auto-size (the production default, which floors at 64); an explicit
    /// override of `1` is invalid for DashMap (it asserts `shard_amount > 1`),
    /// so callers must use `0` or a value the helper rounds up to >= 2.
    fn new_sessions(
        shards: usize,
    ) -> dashmap::DashMap<CaptureSessionKey, CaptureSession, ahash::RandomState> {
        dashmap::DashMap::with_hasher_and_shard_amount(
            ahash::RandomState::default(),
            crate::util::sharding::pool_shard_amount(shards),
        )
    }

    /// A minimal routable egress entry for the keying/cap tests (no live tunnel
    /// is dialed — `admit_or_refresh_session` only stores the entry/channel).
    fn fake_entry() -> std::sync::Arc<crate::router_cache::MeshTcpEgressEntry> {
        let proxy = crate::modes::mesh::mesh_outbound_udp_relay_proxy(
            "default",
            "dns",
            53,
            "__mesh-out-udp-upstream-default-dns-53",
        );
        std::sync::Arc::new(crate::router_cache::MeshTcpEgressEntry {
            upstream_id: "__mesh-out-udp-upstream-default-dns-53".to_string(),
            relay_proxy: std::sync::Arc::new(proxy),
            service_fqdn: "dns.default.svc.cluster.local".to_string(),
        })
    }

    /// `resolve_entry` closure that always routes (returns a fake entry).
    fn routable() -> Option<std::sync::Arc<crate::router_cache::MeshTcpEgressEntry>> {
        Some(fake_entry())
    }

    /// `resolve_entry` closure that never routes (no declared mesh UDP dest).
    fn unroutable() -> Option<std::sync::Arc<crate::router_cache::MeshTcpEgressEntry>> {
        None
    }

    fn key(client: &str, dst: &str) -> CaptureSessionKey {
        CaptureSessionKey {
            client: client.parse().unwrap(),
            orig_dst: dst.parse().unwrap(),
        }
    }

    #[test]
    fn unroutable_destination_is_dropped_without_a_slot() {
        // A captured datagram whose orig-dst matches no mesh UDP destination is
        // dropped: no session, no slot consumed (fail closed).
        let sessions = new_sessions(0);
        let active = std::sync::atomic::AtomicU64::new(0);
        let outcome = admit_or_refresh_session(
            &sessions,
            &active,
            key("10.0.0.5:40000", "1.1.1.1:53"),
            b"q",
            1000,
            unroutable,
        );
        assert!(matches!(outcome, SessionAdmission::Dropped));
        assert_eq!(sessions.len(), 0);
        assert_eq!(active.load(std::sync::atomic::Ordering::Relaxed), 0);
    }

    #[test]
    fn session_keyed_by_client_and_origdst() {
        let sessions = new_sessions(0);
        let active = std::sync::atomic::AtomicU64::new(0);
        // Hold the receivers so refreshes' channel sends don't fail (irrelevant
        // to the keying assertions, but keeps the sessions' channels open).
        let mut keepalive = Vec::new();

        // Same client, two distinct destinations ⇒ two sessions.
        for dst in ["10.96.0.10:53", "10.96.0.11:53"] {
            match admit_or_refresh_session(
                &sessions,
                &active,
                key("10.0.0.5:40000", dst),
                b"x",
                1000,
                routable,
            ) {
                SessionAdmission::Admitted { rx, .. } => keepalive.push(rx),
                other => panic!("expected Admitted, got {}", admission_name(&other)),
            }
        }
        assert_eq!(sessions.len(), 2);

        // A second datagram on an existing (client, dst) flow refreshes — no new
        // session.
        let outcome = admit_or_refresh_session(
            &sessions,
            &active,
            key("10.0.0.5:40000", "10.96.0.10:53"),
            b"x",
            1000,
            routable,
        );
        assert!(matches!(outcome, SessionAdmission::Refreshed));
        assert_eq!(sessions.len(), 2);

        // A different client to the same dst is a distinct session.
        match admit_or_refresh_session(
            &sessions,
            &active,
            key("10.0.0.6:50000", "10.96.0.10:53"),
            b"x",
            1000,
            routable,
        ) {
            SessionAdmission::Admitted { rx, .. } => keepalive.push(rx),
            other => panic!("expected Admitted, got {}", admission_name(&other)),
        }
        assert_eq!(sessions.len(), 3);
    }

    #[test]
    fn first_datagram_new_session_does_not_deadlock() {
        // Regression for codex r1 P1: admitting a fresh flow must not re-enter
        // the DashMap (`len()`) while an entry guard is held — a plain return
        // here is the proof it no longer nests map ops under a guard.
        let sessions = new_sessions(0);
        let active = std::sync::atomic::AtomicU64::new(0);
        let outcome = admit_or_refresh_session(
            &sessions,
            &active,
            key("10.0.0.5:40000", "10.96.0.10:53"),
            b"x",
            64,
            routable,
        );
        assert!(matches!(outcome, SessionAdmission::Admitted { .. }));
        assert_eq!(sessions.len(), 1);
    }

    #[test]
    fn session_cap_sheds_new_flows_but_serves_existing() {
        let sessions = new_sessions(0);
        let active = std::sync::atomic::AtomicU64::new(0);

        // Cap of 1: first new flow admitted.
        let first = admit_or_refresh_session(
            &sessions,
            &active,
            key("10.0.0.5:40000", "10.96.0.10:53"),
            b"x",
            1,
            routable,
        );
        let _rx = match first {
            SessionAdmission::Admitted { rx, .. } => rx,
            other => panic!("expected Admitted, got {}", admission_name(&other)),
        };
        assert_eq!(sessions.len(), 1);

        // Second NEW flow is shed at the cap.
        let second = admit_or_refresh_session(
            &sessions,
            &active,
            key("10.0.0.6:40000", "10.96.0.10:53"),
            b"x",
            1,
            routable,
        );
        assert!(matches!(second, SessionAdmission::Dropped));
        assert_eq!(sessions.len(), 1);

        // The already-admitted flow is still served (refresh), even at the cap.
        let refreshed = admit_or_refresh_session(
            &sessions,
            &active,
            key("10.0.0.5:40000", "10.96.0.10:53"),
            b"x",
            1,
            routable,
        );
        assert!(matches!(refreshed, SessionAdmission::Refreshed));
        assert_eq!(sessions.len(), 1);
    }

    fn admission_name(a: &SessionAdmission) -> &'static str {
        match a {
            SessionAdmission::Refreshed => "Refreshed",
            SessionAdmission::Admitted { .. } => "Admitted",
            SessionAdmission::Dropped => "Dropped",
        }
    }
}
