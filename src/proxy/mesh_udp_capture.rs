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
        "Mesh UDP capture listener started (capture→drop; egress is Stage 4)"
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
                                let data_len = data.len();
                                let orig_dst = recv_batch.orig_dst(i);
                                handle_captured_datagram(
                                    &sessions,
                                    &active_sessions,
                                    client,
                                    orig_dst,
                                    data_len,
                                    max_sessions,
                                );
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

/// Per-(client, orig-dst) capture session. Stage 3 holds no backend leg — it
/// exists only so the listener can bound concurrent flows and age them out for
/// DoS resistance. `last_activity` is monotonic millis from
/// [`crate::socket_opts::monotonic_now_ms`] (never goes backwards under NTP
/// slew, so idle expiry always fires).
#[cfg(target_os = "linux")]
struct CaptureSession {
    last_activity: u64,
}

/// Record a captured datagram against its session, then DROP it (Stage 3).
///
/// Inserts/refreshes the `(client, orig-dst)` session under the
/// `max_sessions` cap and logs the drop at `debug!`. A datagram from a NEW flow
/// once the cap is reached is dropped without inserting (cheap flood shield);
/// an existing flow is always refreshed (it already holds a slot). Returns
/// `true` if the datagram was accounted (existing or newly admitted), `false`
/// if it was shed at the cap — exposed for unit testing the keying/cap logic.
#[cfg(target_os = "linux")]
fn handle_captured_datagram(
    sessions: &dashmap::DashMap<CaptureSessionKey, CaptureSession, ahash::RandomState>,
    active_sessions: &std::sync::atomic::AtomicU64,
    client: SocketAddr,
    orig_dst: Option<SocketAddr>,
    data_len: usize,
    max_sessions: usize,
) -> bool {
    use dashmap::mapref::entry::Entry;
    use std::sync::atomic::Ordering;
    use tracing::debug;

    let Some(orig_dst) = orig_dst else {
        // No orig-dst cmsg ⇒ we cannot tell where the pod dialed, so there is
        // nothing to route in Stage 4 and nothing meaningful to key on. Drop.
        debug!(
            client = %client,
            size = data_len,
            "Mesh UDP capture: dropping datagram with no original destination cmsg"
        );
        return false;
    };

    let key = CaptureSessionKey { client, orig_dst };
    let now = crate::socket_opts::monotonic_now_ms();
    // A single `entry()` guard refreshes-or-admits without re-entering the map.
    // An Occupied flow already holds a slot, so it is always refreshed (even at
    // the cap). A Vacant flow reserves a slot via the cheap `active_sessions`
    // atomic — NOT `DashMap::len()`, which walks/locks every shard on the exact
    // per-datagram flood path the cap defends against (codex r3 P2) — and is
    // inserted only when under the cap. Only the atomic (never another
    // `sessions.*` op) is touched while the entry guard is held, so this cannot
    // self-deadlock the way a nested `len()` did (codex r1 P1).
    match sessions.entry(key) {
        Entry::Occupied(mut occupied) => {
            occupied.get_mut().last_activity = now;
        }
        Entry::Vacant(vacant) => {
            // Reserve a slot atomically; hand it back and shed if over the cap
            // (mirrors `udp_proxy`'s `active_sessions` admit-or-shed).
            let prev = active_sessions.fetch_add(1, Ordering::Relaxed);
            if prev >= max_sessions as u64 {
                active_sessions.fetch_sub(1, Ordering::Relaxed);
                debug!(
                    client = %client,
                    orig_dst = %orig_dst,
                    "Mesh UDP capture: session cap reached, dropping datagram from new flow"
                );
                return false;
            }
            vacant.insert(CaptureSession { last_activity: now });
        }
    }
    let admitted = true;

    // Stage 3: capture → DROP. Egress relay (forward over the mesh transport to
    // `orig_dst`'s workload) is Stage 4.
    debug!(
        client = %client,
        orig_dst = %orig_dst,
        size = data_len,
        "Mesh UDP capture: captured datagram (Stage 3 drop; egress is Stage 4)"
    );
    admitted
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

    #[test]
    fn datagram_without_origdst_is_dropped_unaccounted() {
        let sessions = new_sessions(0);
        let active = std::sync::atomic::AtomicU64::new(0);
        let client: SocketAddr = "10.0.0.5:40000".parse().unwrap();
        // No orig-dst ⇒ dropped, not accounted, no session created.
        assert!(!handle_captured_datagram(
            &sessions, &active, client, None, 32, 1000
        ));
        assert_eq!(sessions.len(), 0);
        assert_eq!(active.load(std::sync::atomic::Ordering::Relaxed), 0);
    }

    #[test]
    fn session_keyed_by_client_and_origdst() {
        let sessions = new_sessions(0);
        let active = std::sync::atomic::AtomicU64::new(0);
        let client: SocketAddr = "10.0.0.5:40000".parse().unwrap();
        let dst_a: SocketAddr = "10.96.0.10:53".parse().unwrap();
        let dst_b: SocketAddr = "10.96.0.11:53".parse().unwrap();

        // Same client, two distinct destinations ⇒ two sessions.
        assert!(handle_captured_datagram(
            &sessions,
            &active,
            client,
            Some(dst_a),
            16,
            1000
        ));
        assert!(handle_captured_datagram(
            &sessions,
            &active,
            client,
            Some(dst_b),
            16,
            1000
        ));
        assert_eq!(sessions.len(), 2);

        // A second datagram on the same (client, dst_a) flow refreshes the
        // existing session — does NOT create a third.
        assert!(handle_captured_datagram(
            &sessions,
            &active,
            client,
            Some(dst_a),
            16,
            1000
        ));
        assert_eq!(sessions.len(), 2);

        // A different client to dst_a is a distinct session.
        let client2: SocketAddr = "10.0.0.6:50000".parse().unwrap();
        assert!(handle_captured_datagram(
            &sessions,
            &active,
            client2,
            Some(dst_a),
            16,
            1000
        ));
        assert_eq!(sessions.len(), 3);
    }

    #[test]
    fn first_datagram_new_session_does_not_deadlock() {
        // Regression for codex r1 P1: the first datagram for a fresh
        // (client, orig-dst) must admit a session WITHOUT re-entering the
        // DashMap (`len()`) while an entry guard is held — otherwise this call
        // self-deadlocks and the test hangs. A plain return here is the proof
        // it no longer nests map ops under a guard.
        let sessions = new_sessions(0);
        let active = std::sync::atomic::AtomicU64::new(0);
        let client: SocketAddr = "10.0.0.5:40000".parse().unwrap();
        let dst: SocketAddr = "10.96.0.10:53".parse().unwrap();
        // Cap well above 1 so the new flow is admitted via the count-then-insert
        // path (the exact path that previously held a guard across `len()`).
        assert!(handle_captured_datagram(
            &sessions,
            &active,
            client,
            Some(dst),
            64,
            1000
        ));
        assert_eq!(sessions.len(), 1);
    }

    #[test]
    fn session_cap_sheds_new_flows_but_serves_existing() {
        let sessions = new_sessions(0);
        let active = std::sync::atomic::AtomicU64::new(0);
        let dst: SocketAddr = "10.96.0.10:53".parse().unwrap();
        let client_a: SocketAddr = "10.0.0.5:40000".parse().unwrap();
        let client_b: SocketAddr = "10.0.0.6:40000".parse().unwrap();

        // Cap of 1: first new flow admitted.
        assert!(handle_captured_datagram(
            &sessions,
            &active,
            client_a,
            Some(dst),
            8,
            1
        ));
        assert_eq!(sessions.len(), 1);

        // Second NEW flow is shed at the cap.
        assert!(!handle_captured_datagram(
            &sessions,
            &active,
            client_b,
            Some(dst),
            8,
            1
        ));
        assert_eq!(sessions.len(), 1);

        // The already-admitted flow is still served (refresh), even at the cap.
        assert!(handle_captured_datagram(
            &sessions,
            &active,
            client_a,
            Some(dst),
            8,
            1
        ));
        assert_eq!(sessions.len(), 1);
    }
}
