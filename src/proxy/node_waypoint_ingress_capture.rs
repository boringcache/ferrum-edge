//! NodeWaypoint transparent inbound **capture** listener (issue #3287).
//!
//! The node-agent's `ferrum_tc_ingress_redirect` classifier steers inbound TCP
//! for an enrolled `podIP:appPort` into this listener with `bpf_sk_assign()`.
//! Nothing is NAT-ed: the packet still carries the workload's real destination,
//! which is exactly why this socket must be bound `IP_TRANSPARENT` — the
//! accepted socket's *local* address is a workload address that is not
//! configured on this host, and only a transparent socket may bind/reply from
//! it.
//!
//! # Why this is not the HBONE listener
//!
//! The HBONE listener (`:15008`) terminates authenticated HTTP/2 CONNECT over
//! verified mesh mTLS. What arrives here is ordinary application traffic —
//! plaintext HTTP, Redis, Postgres, or the application's own TLS — and
//! `IP_TRANSPARENT` preserves addresses, it does not transform a payload.
//! Steering captured bytes at HBONE would attempt a mesh TLS handshake on
//! application data and fail. So this is a distinct protocol boundary with its
//! own port, its own accept loop, and **no TLS termination at all**.
//!
//! # Gates, in order
//!
//! 1. **Captured-ness.** The recovered original destination must be a real
//!    off-listener address. A direct dial to the capture port itself resolves
//!    to the listener's own address and is refused — this listener is not a
//!    general-purpose relay anyone on the node may address.
//! 2. **PeerAuthentication.** The live posture for the recovered *app port*
//!    (`ProxyState::mesh_inbound_tls_policy`, the same table the mesh inbound
//!    TLS selector reads) must admit plaintext. Under `STRICT` it does not, so
//!    direct plaintext is refused and the peer must come over authenticated
//!    mesh transport (HBONE) instead. This is the whole reason the redirect can
//!    be enabled without weakening STRICT.
//! 3. **Ownership.** The destination must be a slice-declared in-mesh workload
//!    address+port — the same open-relay guard the inbound HBONE relay uses, so
//!    an operator cannot turn this socket into a proxy to arbitrary hosts.
//! 4. **Authorization.** The relay hands off to
//!    [`crate::proxy::mesh_tcp_inbound::handle_mesh_tcp_inbound`], which runs
//!    the L4 `on_stream_connect` chain (including the mesh-injected
//!    `__mesh_authz`) with the captured **app** port as the authorization
//!    destination, then relays byte-for-byte and emits the disconnect summary.
//!
//! The backend dial carries `SO_MARK = NODE_WAYPOINT_INBOUND_AUTH_MARK`, so the
//! pod-veth `ferrum_tc_inbound` guard admits it as an authorized relay dial and
//! `ferrum_tc_ingress_redirect` bypasses it as already-relayed instead of
//! steering it back here in a loop.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpListener;
use tracing::{debug, info};

use super::ProxyState;
use crate::modes::mesh::config::MtlsMode;

/// Accept backlog for the capture listener. Matches the value the generic proxy
/// listener uses for mesh listeners.
const CAPTURE_BACKLOG: i32 = 1024;

/// Bind the transparent capture socket and serve until shutdown.
///
/// Bind failure is returned as an error, never swallowed: the caller records it
/// as a listener startup failure, which fails readiness. That is the fail-closed
/// half of the contract — if the redirect is armed in the kernel but this socket
/// never comes up, every in-scope packet is dropped by the classifier, so the
/// proxy must not report itself healthy.
pub async fn start_listener(
    addr: SocketAddr,
    state: ProxyState,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    started_tx: Option<tokio::sync::oneshot::Sender<()>>,
) -> Result<(), anyhow::Error> {
    crate::modes::mesh::validate_ingress_capture_addr(addr).map_err(|e| anyhow::anyhow!(e))?;

    // Shared once for the lifetime of the listener, matching every other
    // listener entry point: they take `ProxyState` by value and refcount it
    // here so each accepted connection clones an `Arc`, not the struct.
    let state = Arc::new(state);

    // `transparent = true` is passed only here. A transparent socket may bind
    // and source non-local addresses, so the capability stays scoped to the one
    // listener that provably needs it rather than being switched on process-wide.
    let listener: TcpListener = super::create_proxy_socket(
        addr,
        CAPTURE_BACKLOG,
        None,
        // No SO_REUSEPORT: a single accept loop keeps `bpf_sk_assign`'s wildcard
        // listener lookup unambiguous (the kernel would otherwise pick a
        // reuseport group member by hash, which is fine for delivery but makes
        // the live datapath test non-deterministic for no throughput gain — the
        // capture path is per-pod inbound, not a fan-in edge listener).
        false,
        true,
    )
    .map_err(|e| {
        anyhow::anyhow!(
            "failed to bind the NodeWaypoint transparent inbound capture listener on {addr}: {e}. \
             The eBPF tc ingress redirect steers captured inbound traffic at this port, so \
             without it every enrolled pod's inbound traffic is dropped fail-closed. Ensure the \
             container has NET_ADMIN (IP_TRANSPARENT) and the port is free."
        )
    })?;

    info!(
        %addr,
        "NodeWaypoint transparent inbound capture listener bound; the eBPF tc ingress redirect \
         steers captured podIP:appPort traffic here"
    );
    if let Some(tx) = started_tx {
        let _ = tx.send(());
    }

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, remote_addr)) => {
                        let state = Arc::clone(&state);
                        tokio::spawn(async move {
                            // Counted for graceful drain like every other
                            // accepted connection.
                            let _conn_guard =
                                crate::overload::ConnectionGuard::new(&state.overload);
                            handle_captured_connection(stream, remote_addr, addr, &state).await;
                        });
                    }
                    Err(e) => {
                        debug!(%addr, error = %e, "Capture listener accept failed");
                    }
                }
            }
            _ = shutdown_rx.changed() => {
                info!(%addr, "NodeWaypoint transparent inbound capture listener shutting down");
                return Ok(());
            }
        }
    }
}

/// The original destination of a captured connection.
///
/// Read from `getsockname()`, **not** `SO_ORIGINAL_DST`: the redirect performs
/// no NAT, so there is no conntrack entry to consult — the socket's local
/// address already is the workload's `podIP:appPort`.
fn captured_original_dst(
    stream: &tokio::net::TcpStream,
    listen_addr: SocketAddr,
) -> Option<SocketAddr> {
    let local = stream.local_addr().ok()?;
    if local.port() == 0 {
        return None;
    }
    // A direct dial to the capture port lands on the listener's own address
    // family/port with a local host address; only a *captured* connection
    // carries a foreign destination. Refuse anything whose port is the capture
    // port — that connection was addressed to this listener, not redirected to
    // it, and it carries no original destination to relay to.
    if local.port() == listen_addr.port() {
        return None;
    }
    if local.ip().is_unspecified() || local.ip().is_loopback() {
        return None;
    }
    Some(local)
}

/// The live PeerAuthentication posture for a captured app port.
///
/// Reads the same `modes_by_port` / `default_mode` table the mesh inbound TLS
/// selector uses, so the redirect can never admit plaintext on a port the mesh
/// considers STRICT. One `ArcSwap` load per accepted connection, off the
/// request path.
fn captured_plaintext_admitted(state: &ProxyState, app_port: u16) -> (bool, MtlsMode) {
    let policy = state.mesh_inbound_tls_policy.load();
    let mode = policy
        .modes_by_port
        .get(&app_port)
        .copied()
        .unwrap_or(policy.default_mode);
    (super::mtls_mode_accepts_plaintext(mode), mode)
}

async fn handle_captured_connection(
    stream: tokio::net::TcpStream,
    remote_addr: SocketAddr,
    listen_addr: SocketAddr,
    state: &Arc<ProxyState>,
) {
    let Some(orig_dst) = captured_original_dst(&stream, listen_addr) else {
        debug!(
            client_ip = %remote_addr.ip(),
            %listen_addr,
            "Refusing a connection on the NodeWaypoint capture listener that carries no captured \
             original destination; this listener only serves eBPF-redirected traffic"
        );
        drop(stream);
        return;
    };

    let (plaintext_admitted, mode) = captured_plaintext_admitted(state, orig_dst.port());
    if !plaintext_admitted {
        // STRICT (or DISABLE) for this app port. Direct plaintext is exactly
        // what PeerAuthentication forbids there, so the connection is closed;
        // the peer must arrive over authenticated mesh transport instead. This
        // is a policy outcome, not an error, so it stays at debug with no
        // request-derived content beyond the peer IP.
        debug!(
            client_ip = %remote_addr.ip(),
            app_port = orig_dst.port(),
            ?mode,
            "Refusing captured direct plaintext: the PeerAuthentication posture for this app port \
             requires verified mesh transport"
        );
        drop(stream);
        return;
    }

    let epoch = state.request_epoch.load();
    let Some(entry) = super::build_node_waypoint_capture_relay_entry(orig_dst, &epoch) else {
        debug!(
            client_ip = %remote_addr.ip(),
            %orig_dst,
            "Refusing a captured connection whose original destination is not a slice-declared \
             in-mesh workload address and port"
        );
        drop(stream);
        return;
    };

    // Hand off to the shared captured-inbound relay: L4 authorization chain on
    // the captured app port, marked backend dial, byte-for-byte relay, and the
    // stream disconnect/transaction lifecycle.
    super::mesh_tcp_inbound::handle_mesh_tcp_inbound(
        stream,
        remote_addr,
        state,
        &epoch,
        &entry,
        orig_dst,
    )
    .await;
}

#[cfg(test)]
mod tests {
    #[test]
    fn only_a_wildcard_capture_address_is_accepted() {
        // `bpf_sk_assign` resolves the listener with a wildcard socket lookup,
        // so a specific-IP bind is invisible to the classifier and every
        // captured packet would be dropped fail-closed.
        assert!(
            crate::modes::mesh::validate_ingress_capture_addr("0.0.0.0:15006".parse().unwrap())
                .is_ok()
        );
        assert!(
            crate::modes::mesh::validate_ingress_capture_addr("[::]:15006".parse().unwrap())
                .is_ok()
        );
        let err =
            crate::modes::mesh::validate_ingress_capture_addr("10.0.0.5:15006".parse().unwrap())
                .unwrap_err();
        assert!(err.contains("wildcard"), "{err}");
        let err = crate::modes::mesh::validate_ingress_capture_addr("0.0.0.0:0".parse().unwrap())
            .unwrap_err();
        assert!(err.contains("non-zero port"), "{err}");
    }
}
