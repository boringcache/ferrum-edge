//! Local raw-TCP Sidecar inbound relay.
//!
//! When Sidecar inbound TLS is disabled or absent in permissive mode, the
//! inbound listener can receive REDIRECT-captured plaintext TCP for local
//! stream-family app ports. Those bytes are not HTTP, so the accept loop routes
//! them here before Hyper parsing and relays directly to the prepared loopback
//! backend selected by the captured original-destination port.
//!
//! L4 policy (TCP `AuthorizationPolicy` / fault / rate-limit stream hooks) is
//! enforced HERE, before connecting to loopback: this captured plaintext stream
//! is itself the destination-side policy point (unlike mesh egress, which is
//! authorized by the destination's inbound CONNECT). The `on_stream_connect`
//! chain runs with the captured APP port as the stream destination so a
//! `destination.port`-scoped DENY targeting e.g. the Redis port is evaluated; a
//! `Reject` closes the connection without ever relaying to the app.

use std::sync::Arc;

use tokio::net::TcpStream;
use tracing::{debug, warn};

use super::{ProxyState, tcp_proxy};
use crate::consumer_index::ConsumerIndex;
use crate::modes::mesh::MeshTrafficDirection;
use crate::plugins::{PluginResult, ProxyProtocol, StreamConnectionContext};
use crate::request_epoch::RequestEpoch;
use crate::router_cache::MeshTcpInboundEntry;

pub(crate) async fn handle_mesh_tcp_inbound(
    client_stream: TcpStream,
    remote_addr: std::net::SocketAddr,
    state: &Arc<ProxyState>,
    epoch: &RequestEpoch,
    entry: &Arc<MeshTcpInboundEntry>,
    orig_dst: std::net::SocketAddr,
) {
    let proxy = entry.relay_proxy.as_ref();
    // The captured app/container port (== `orig_dst.port()`, the loopback
    // backend port) is the L4 authorization destination, NOT the shared
    // `:15006` capture-listener port. `mesh_authz`'s stream path reads
    // `ctx.listen_port`, so stamping the app port here lets a port-scoped
    // AuthorizationPolicy DENY on the real service port be enforced.
    let app_port = proxy.backend_port;
    let client_ip = remote_addr.ip().to_string();

    // Run the L4 stream plugin chain (mesh `on_stream_connect` hooks: authz,
    // fault, rate-limit) BEFORE dialing loopback. The synthesized relay proxy
    // is never in `config.proxies`, so the plugin cache resolves the GLOBAL
    // TCP-protocol chain via its global fallback — which carries the
    // mesh-injected `__mesh_authz` global. A `Reject` closes the captured
    // connection (drop) instead of relaying to the app.
    let plugins = epoch
        .plugin_cache
        .get_plugins_for_protocol(&proxy.id, ProxyProtocol::Tcp);
    if !plugins.is_empty() {
        let consumer_index = Arc::new(ConsumerIndex::from_inner(Arc::clone(&epoch.consumer_index)));
        let mut stream_ctx = StreamConnectionContext {
            client_ip: client_ip.clone(),
            proxy_id: proxy.id.clone(),
            proxy_name: proxy.name.clone(),
            // Authorize on the captured app port, not the capture listener.
            listen_port: app_port,
            backend_scheme: proxy.effective_scheme(),
            consumer_index,
            identified_consumer: None,
            authenticated_identity: None,
            auth_method: None,
            metadata: None,
            tls_client_cert_der: None,
            tls_client_cert_chain_der: None,
            sni_hostname: None,
            // Captured plaintext Sidecar inbound is, by direction, inbound mesh
            // traffic — so `mesh_authz` treats `listen_port` as the inbound
            // destination port (parity with the materialized HTTP inbound path).
            mesh_direction: Some(MeshTrafficDirection::Inbound),
            // Sidecar topology never installs the node-waypoint resolver, so the
            // per-pod scope is absent and `mesh_authz` evaluates mesh-wide +
            // namespace/selector policies against the connection identity.
            node_waypoint_policy_scope: None,
            first_bytes: None,
            first_bytes_kind: None,
        };
        for plugin in plugins.iter() {
            if let PluginResult::Reject { .. } = plugin.on_stream_connect(&mut stream_ctx).await {
                debug!(
                    service = %entry.service_fqdn,
                    orig_dst = %orig_dst,
                    app_port,
                    client_ip = %client_ip,
                    "Sidecar raw-TCP inbound connection rejected by stream policy; closing \
                     captured connection without relaying to loopback"
                );
                return;
            }
        }
    }

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
                    client_ip = %client_ip,
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
                client_ip = %client_ip,
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
        client_ip = %client_ip,
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
