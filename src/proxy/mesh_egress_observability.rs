//! Workload-metrics lifecycle for captured L4 mesh egress.
//!
//! These handlers bypass the ordinary stream proxy, so they invoke only the
//! observability plugin by name. Destination-side mesh policy remains the sole
//! authorization point; no authn/authz plugin is run a second time here.

use std::sync::Arc;

use crate::consumer_index::ConsumerIndex;
use crate::modes::mesh::MeshTrafficDirection;
use crate::plugins::{
    Direction, DisconnectCause, Plugin, PluginResult, ProxyProtocol, StreamConnectionContext,
    StreamTransactionSummary,
};
use crate::request_epoch::RequestEpoch;
use crate::retry::ErrorClass;

const WORKLOAD_METRICS_PLUGIN: &str = "workload_metrics";

pub(crate) struct CapturedMeshEgressLifecycle {
    plugins: Vec<Arc<dyn Plugin>>,
    stream_ctx: Option<StreamConnectionContext>,
    namespace: String,
    proxy_id: String,
    proxy_name: Option<String>,
    client_ip: String,
    backend_target: String,
    protocol: String,
    connected_wall_at: chrono::DateTime<chrono::Utc>,
    connected_at: std::time::Instant,
    bytes_sent: u64,
    bytes_received: u64,
    connection_error: Option<String>,
    error_class: Option<ErrorClass>,
    disconnect_direction: Option<Direction>,
    disconnect_cause: Option<DisconnectCause>,
}

impl CapturedMeshEgressLifecycle {
    pub(crate) async fn start(
        epoch: &RequestEpoch,
        proxy: &crate::config::types::Proxy,
        protocol: ProxyProtocol,
        client_ip: std::net::IpAddr,
        destination_service: &str,
        destination_port: u16,
    ) -> Option<Self> {
        let plugins: Vec<_> = epoch
            .plugin_cache
            .get_plugins_for_protocol(&proxy.id, protocol)
            .iter()
            .filter(|plugin| plugin.name() == WORKLOAD_METRICS_PLUGIN)
            .cloned()
            .collect();
        if plugins.is_empty() {
            return None;
        }

        let client_ip = client_ip.to_string();
        let mut stream_ctx = StreamConnectionContext {
            client_ip: client_ip.clone(),
            direct_client_ip: client_ip.clone(),
            proxy_id: proxy.id.clone(),
            proxy_name: Some(destination_service.to_string()),
            listen_port: destination_port,
            backend_scheme: proxy.effective_scheme(),
            consumer_index: Arc::new(ConsumerIndex::from_inner(Arc::clone(&epoch.consumer_index))),
            identified_consumer: None,
            authenticated_identity: None,
            auth_method: None,
            metadata: None,
            tls_client_cert_der: None,
            tls_client_cert_chain_der: None,
            sni_hostname: None,
            mesh_direction: Some(MeshTrafficDirection::Outbound),
            node_waypoint_policy_scope: None,
            first_bytes: None,
            first_bytes_kind: None,
        };
        let mut rejected = false;
        for plugin in &plugins {
            if matches!(
                plugin.on_stream_connect(&mut stream_ctx).await,
                PluginResult::Reject { .. }
            ) {
                rejected = true;
                break;
            }
        }
        stream_ctx.insert_metadata(
            "mesh.connection_security_policy".to_string(),
            "mutual_tls".to_string(),
        );
        stream_ctx.insert_metadata(
            "mesh.destination.namespace".to_string(),
            proxy.namespace.clone(),
        );
        stream_ctx.insert_metadata(
            "mesh.destination.workload".to_string(),
            destination_service.to_string(),
        );
        stream_ctx.insert_metadata(
            "mesh.destination.app".to_string(),
            destination_service.to_string(),
        );
        stream_ctx.insert_metadata(
            "mesh.destination.service".to_string(),
            destination_service.to_string(),
        );

        Some(Self {
            plugins,
            stream_ctx: Some(stream_ctx),
            namespace: proxy.namespace.clone(),
            proxy_id: proxy.id.clone(),
            proxy_name: Some(destination_service.to_string()),
            client_ip,
            backend_target: destination_service.to_string(),
            protocol: match protocol {
                ProxyProtocol::Udp => "udp",
                _ => "tcp",
            }
            .to_string(),
            connected_wall_at: chrono::Utc::now(),
            connected_at: std::time::Instant::now(),
            bytes_sent: 0,
            bytes_received: 0,
            connection_error: Some(
                if rejected {
                    "workload metrics rejected captured mesh egress lifecycle"
                } else {
                    "captured mesh egress setup failed"
                }
                .to_string(),
            ),
            error_class: Some(ErrorClass::ConnectionPoolError),
            disconnect_direction: Some(Direction::ClientToBackend),
            disconnect_cause: Some(DisconnectCause::BackendError),
        })
    }

    pub(crate) fn set_target(&mut self, target: &crate::config::types::UpstreamTarget) {
        self.backend_target = format!("{}:{}", target.host, target.port);
        if let Some(identity) = target
            .tags
            .get(crate::proxy::hbone_pool::MESH_SPIFFE_ID_TAG)
            && let Some(metadata) = self
                .stream_ctx
                .as_mut()
                .and_then(|ctx| ctx.metadata.as_mut())
        {
            metadata.insert("mesh.destination.principal".to_string(), identity.clone());
        }
    }

    pub(crate) fn complete_tcp(&mut self, result: &crate::proxy::tcp_proxy::StreamCopyResult) {
        self.bytes_sent = result.bytes_client_to_backend;
        self.bytes_received = result.bytes_backend_to_client;
        match result.first_failure.as_ref() {
            Some((direction, class, side, message)) => {
                self.connection_error = Some(message.clone());
                self.error_class = Some(*class);
                self.disconnect_direction = Some(*direction);
                self.disconnect_cause = Some(
                    crate::proxy::tcp_proxy::disconnect_cause_for_failure(*direction, class, *side),
                );
            }
            None => self.complete_gracefully(),
        }
    }

    pub(crate) fn complete_udp(
        &mut self,
        bytes_sent: u64,
        bytes_received: u64,
        outcome: CapturedUdpOutcome,
    ) {
        self.bytes_sent = bytes_sent;
        self.bytes_received = bytes_received;
        match outcome {
            CapturedUdpOutcome::IdleTimeout => {
                self.connection_error = Some("captured mesh UDP session idle timeout".to_string());
                self.error_class = Some(ErrorClass::ReadWriteTimeout);
                self.disconnect_direction = None;
                self.disconnect_cause = Some(DisconnectCause::IdleTimeout);
            }
            CapturedUdpOutcome::ReturnPathEnded => {
                self.connection_error = Some("captured mesh UDP return path ended".to_string());
                self.error_class = Some(ErrorClass::ConnectionClosed);
                self.disconnect_direction = Some(Direction::BackendToClient);
                self.disconnect_cause = Some(DisconnectCause::BackendError);
            }
            CapturedUdpOutcome::EgressPathEnded => {
                self.connection_error = Some("captured mesh UDP egress path ended".to_string());
                self.error_class = Some(ErrorClass::RequestError);
                self.disconnect_direction = Some(Direction::ClientToBackend);
                self.disconnect_cause = Some(DisconnectCause::BackendError);
            }
            CapturedUdpOutcome::ProducerShutdown => self.complete_gracefully(),
        }
    }

    fn complete_gracefully(&mut self) {
        self.connection_error = None;
        self.error_class = None;
        self.disconnect_direction = None;
        self.disconnect_cause = Some(DisconnectCause::GracefulShutdown);
    }

    fn take_summary(&mut self) -> Option<StreamTransactionSummary> {
        let mut stream_ctx = self.stream_ctx.take()?;
        Some(StreamTransactionSummary {
            namespace: self.namespace.clone(),
            proxy_id: self.proxy_id.clone(),
            proxy_name: self.proxy_name.clone(),
            client_ip: self.client_ip.clone(),
            consumer_username: stream_ctx.effective_identity().map(str::to_owned),
            auth_method: stream_ctx.auth_method,
            backend_target: self.backend_target.clone(),
            backend_resolved_ip: None,
            protocol: self.protocol.clone(),
            listen_port: stream_ctx.listen_port,
            duration_ms: self.connected_at.elapsed().as_secs_f64() * 1000.0,
            bytes_sent: self.bytes_sent,
            bytes_received: self.bytes_received,
            connection_error: self.connection_error.clone(),
            error_class: self.error_class,
            disconnect_direction: self.disconnect_direction,
            disconnect_cause: self.disconnect_cause,
            timestamp_connected: self.connected_wall_at.to_rfc3339(),
            timestamp_disconnected: chrono::Utc::now().to_rfc3339(),
            sni_hostname: stream_ctx.sni_hostname.clone(),
            metadata: stream_ctx.take_metadata(),
        })
    }
}

impl Drop for CapturedMeshEgressLifecycle {
    fn drop(&mut self) {
        let Some(summary) = self.take_summary() else {
            return;
        };
        let plugins = std::mem::take(&mut self.plugins);
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            tracing::warn!(
                plugin = WORKLOAD_METRICS_PLUGIN,
                "captured mesh egress ended outside a Tokio runtime; span lifecycle was dropped"
            );
            return;
        };
        runtime.spawn(async move {
            for plugin in plugins {
                plugin.on_stream_disconnect(&summary).await;
            }
        });
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CapturedUdpOutcome {
    ReturnPathEnded,
    EgressPathEnded,
    IdleTimeout,
    ProducerShutdown,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::BackendScheme;
    use std::sync::Mutex;

    struct SummaryCapture {
        tx: Mutex<Option<tokio::sync::oneshot::Sender<StreamTransactionSummary>>>,
    }

    #[async_trait::async_trait]
    impl Plugin for SummaryCapture {
        fn name(&self) -> &str {
            "summary_capture"
        }

        async fn on_stream_disconnect(&self, summary: &StreamTransactionSummary) {
            let tx = self.tx.lock().expect("summary sender mutex").take();
            if let Some(tx) = tx {
                let _ = tx.send(summary.clone());
            }
        }
    }

    fn stream_context() -> StreamConnectionContext {
        StreamConnectionContext {
            client_ip: "10.0.0.2".to_string(),
            direct_client_ip: "10.0.0.2".to_string(),
            proxy_id: "mesh-egress".to_string(),
            proxy_name: Some("orders.default.svc.cluster.local".to_string()),
            listen_port: 5432,
            backend_scheme: BackendScheme::Tcp,
            consumer_index: Arc::new(ConsumerIndex::new(&[])),
            identified_consumer: None,
            authenticated_identity: None,
            auth_method: None,
            metadata: Some(std::collections::HashMap::from([(
                "mesh.direction".to_string(),
                "outbound".to_string(),
            )])),
            tls_client_cert_der: None,
            tls_client_cert_chain_der: None,
            sni_hostname: None,
            mesh_direction: Some(MeshTrafficDirection::Outbound),
            node_waypoint_policy_scope: None,
            first_bytes: None,
            first_bytes_kind: None,
        }
    }

    #[tokio::test]
    async fn drop_finalizes_captured_session_once_with_completion_state() {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let plugin: Arc<dyn Plugin> = Arc::new(SummaryCapture {
            tx: Mutex::new(Some(tx)),
        });
        let mut lifecycle = CapturedMeshEgressLifecycle {
            plugins: vec![plugin],
            stream_ctx: Some(stream_context()),
            namespace: "default".to_string(),
            proxy_id: "mesh-egress".to_string(),
            proxy_name: Some("orders.default.svc.cluster.local".to_string()),
            client_ip: "10.0.0.2".to_string(),
            backend_target: "10.0.0.8:5432".to_string(),
            protocol: "tcp".to_string(),
            connected_wall_at: chrono::Utc::now(),
            connected_at: std::time::Instant::now(),
            bytes_sent: 0,
            bytes_received: 0,
            connection_error: Some("setup failed".to_string()),
            error_class: Some(ErrorClass::ConnectionPoolError),
            disconnect_direction: Some(Direction::ClientToBackend),
            disconnect_cause: Some(DisconnectCause::BackendError),
        };
        lifecycle.complete_tcp(&crate::proxy::tcp_proxy::StreamCopyResult {
            bytes_client_to_backend: 42,
            bytes_backend_to_client: 84,
            first_failure: None,
        });

        drop(lifecycle);
        let summary = tokio::time::timeout(std::time::Duration::from_secs(1), rx)
            .await
            .expect("disconnect callback timeout")
            .expect("disconnect summary");

        assert_eq!(summary.bytes_sent, 42);
        assert_eq!(summary.bytes_received, 84);
        assert_eq!(summary.protocol, "tcp");
        assert_eq!(
            summary.disconnect_cause,
            Some(DisconnectCause::GracefulShutdown)
        );
        assert!(summary.connection_error.is_none());
    }
}
