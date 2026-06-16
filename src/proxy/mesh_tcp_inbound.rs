//! Local raw-TCP Sidecar inbound relay.
//!
//! When Sidecar inbound TLS is disabled or absent in permissive mode, the
//! inbound listener can receive REDIRECT-captured plaintext TCP for local
//! stream-family app ports. Those bytes are not HTTP, so the accept loop routes
//! them here before Hyper parsing and relays directly to the prepared loopback
//! backend selected by the captured original-destination port.

use std::sync::Arc;

use tokio::net::TcpStream;
use tracing::{debug, warn};

use super::{ProxyState, tcp_proxy};
use crate::router_cache::MeshTcpInboundEntry;

pub(crate) async fn handle_mesh_tcp_inbound(
    client_stream: TcpStream,
    remote_addr: std::net::SocketAddr,
    state: &Arc<ProxyState>,
    entry: &Arc<MeshTcpInboundEntry>,
    orig_dst: std::net::SocketAddr,
) {
    let proxy = entry.relay_proxy.as_ref();
    let connect = TcpStream::connect(entry.backend_addr);
    let backend_stream = if proxy.backend_connect_timeout_ms == 0 {
        connect.await
    } else {
        match tokio::time::timeout(
            std::time::Duration::from_millis(proxy.backend_connect_timeout_ms),
            connect,
        )
        .await
        {
            Ok(result) => result,
            Err(_) => {
                warn!(
                    service = %entry.service_fqdn,
                    orig_dst = %orig_dst,
                    backend = %entry.backend_addr,
                    client_ip = %remote_addr.ip(),
                    "Sidecar raw-TCP inbound loopback connect timed out; closing captured connection"
                );
                return;
            }
        }
    };
    let backend_stream = match backend_stream {
        Ok(stream) => stream,
        Err(error) => {
            warn!(
                service = %entry.service_fqdn,
                orig_dst = %orig_dst,
                backend = %entry.backend_addr,
                client_ip = %remote_addr.ip(),
                error = %error,
                "Sidecar raw-TCP inbound loopback connect failed; closing captured connection"
            );
            return;
        }
    };

    debug!(
        service = %entry.service_fqdn,
        orig_dst = %orig_dst,
        backend = %entry.backend_addr,
        client_ip = %remote_addr.ip(),
        "Relaying captured sidecar raw-TCP inbound connection to loopback app"
    );
    let buffer_size = state.adaptive_buffer.get_buffer_size(&proxy.id);
    let result = tcp_proxy::bidirectional_copy_for_relay(
        client_stream,
        backend_stream,
        super::hbone_proxy::proxy_idle_timeout(proxy, &state.env_config),
        super::hbone_proxy::proxy_half_close_cap(&state.env_config),
        super::hbone_proxy::backend_read_timeout(proxy),
        super::hbone_proxy::backend_write_timeout(proxy),
        buffer_size,
    )
    .await;
    state.adaptive_buffer.record_connection(
        &proxy.id,
        result
            .bytes_client_to_backend
            .saturating_add(result.bytes_backend_to_client),
    );
    if let Some((direction, class, side, message)) = result.first_failure.as_ref() {
        warn!(
            service = %entry.service_fqdn,
            proxy_id = %proxy.id,
            direction = ?direction,
            io_side = ?side,
            error_class = %class,
            error = %message,
            bytes_in = result.bytes_client_to_backend,
            bytes_out = result.bytes_backend_to_client,
            "Sidecar raw-TCP inbound relay failed"
        );
    } else {
        debug!(
            service = %entry.service_fqdn,
            bytes_in = result.bytes_client_to_backend,
            bytes_out = result.bytes_backend_to_client,
            "Sidecar raw-TCP inbound relay completed"
        );
    }
}
