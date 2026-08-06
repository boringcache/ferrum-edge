//! Focused coverage for Istio Telemetry metric families added for #3256:
//! REQUEST_SIZE / RESPONSE_SIZE, TCP connection/byte counters, and gRPC
//! message counters. Asserts values and disable/reload lifecycle, not mere
//! series presence.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use ferrum_edge::plugins::mesh::prometheus_helpers::{
    GrpcLengthPrefixedScanner, count_grpc_length_prefixed_messages,
};
use ferrum_edge::plugins::mesh::workload_metrics::WorkloadMetrics;
use ferrum_edge::plugins::prometheus_metrics::MetricsRegistry;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext, StreamTransactionSummary};
use serde_json::json;

fn mesh_http_summary(
    bytes_sent: u64,
    bytes_received: u64,
) -> ferrum_edge::plugins::TransactionSummary {
    ferrum_edge::plugins::TransactionSummary {
        proxy_id: Some("orders".into()),
        proxy_name: Some("orders".into()),
        response_status_code: 200,
        latency_total_ms: 12.0,
        body_completed: true,
        bytes_sent,
        bytes_received,
        metadata: HashMap::from([
            ("mesh.source.workload".into(), "frontend".into()),
            ("mesh.source.namespace".into(), "default".into()),
            (
                "mesh.source.principal".into(),
                "spiffe://cluster.local/ns/default/sa/frontend".into(),
            ),
            ("mesh.source.app".into(), "frontend".into()),
            ("mesh.source.service".into(), "frontend".into()),
            ("mesh.destination.workload".into(), "orders".into()),
            ("mesh.destination.namespace".into(), "default".into()),
            (
                "mesh.destination.principal".into(),
                "spiffe://cluster.local/ns/default/sa/orders".into(),
            ),
            ("mesh.destination.app".into(), "orders".into()),
            ("mesh.destination.service".into(), "orders".into()),
            ("mesh.request_protocol".into(), "http".into()),
            ("mesh.response_flags".into(), "-".into()),
            (
                "mesh.connection_security_policy".into(),
                "mutual_tls".into(),
            ),
        ]),
        ..Default::default()
    }
}

#[test]
fn request_and_response_size_histograms_record_authoritative_byte_values() {
    let registry = MetricsRegistry::new();
    registry.record(&mesh_http_summary(100, 250));
    registry.record(&mesh_http_summary(100, 250));
    let output = registry.render_uncached();

    assert!(
        output.contains("ferrum_mesh_request_bytes_count{"),
        "request size series missing:\n{output}"
    );
    assert!(
        output.contains("ferrum_mesh_response_bytes_count{"),
        "response size series missing:\n{output}"
    );
    assert!(
        output
            .lines()
            .any(|line| line.starts_with("ferrum_mesh_request_bytes_sum{")
                && line.ends_with(" 200.00")),
        "request size sum must be 100+100:\n{output}"
    );
    assert!(
        output
            .lines()
            .any(|line| line.starts_with("ferrum_mesh_response_bytes_sum{")
                && line.ends_with(" 500.00")),
        "response size sum must be 250+250:\n{output}"
    );
    assert!(
        output.lines().any(
            |line| line.starts_with("ferrum_mesh_request_bytes_count{") && line.ends_with(" 2")
        ),
        "request size count must be 2:\n{output}"
    );
}

#[tokio::test]
async fn request_size_disable_suppresses_histogram_updates() {
    let plugin = WorkloadMetrics::new(&json!({
        "namespace": "default",
        "workload_spiffe_id": "spiffe://cluster.local/ns/default/sa/frontend",
        "labels": {"app": "frontend"},
        "metrics": {
            "disabled_metrics": ["REQUEST_SIZE"]
        }
    }))
    .expect("plugin");
    let mut ctx = RequestContext::new("10.0.0.1".into(), "GET".into(), "/".into());
    let mut headers = HashMap::new();
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));

    let mut summary = mesh_http_summary(64, 128);
    summary.metadata.extend(ctx.metadata);
    let registry = MetricsRegistry::new();
    registry.record(&summary);
    let output = registry.render_uncached();
    assert!(
        !output.contains("ferrum_mesh_request_bytes_"),
        "disabled REQUEST_SIZE must not record:\n{output}"
    );
    assert!(
        output.contains("ferrum_mesh_response_bytes_count{"),
        "RESPONSE_SIZE must still record when only REQUEST_SIZE is disabled:\n{output}"
    );
}

#[tokio::test]
async fn reload_clears_disable_and_resumes_request_size_recording() {
    let disabled = WorkloadMetrics::new(&json!({
        "metrics": {"disabled_metrics": ["REQUEST_SIZE", "RESPONSE_SIZE"]}
    }))
    .expect("disabled plugin");
    let enabled = WorkloadMetrics::new(&json!({
        "metrics": {"disabled_metrics": []}
    }))
    .expect("enabled plugin");

    let mut ctx = RequestContext::new("10.0.0.1".into(), "GET".into(), "/".into());
    let mut headers = HashMap::new();
    disabled.before_proxy(&mut ctx, &mut headers).await;
    let mut summary = mesh_http_summary(10, 20);
    summary.metadata.extend(ctx.metadata.clone());
    let registry = MetricsRegistry::new();
    registry.record(&summary);
    assert!(
        !registry
            .render_uncached()
            .contains("ferrum_mesh_request_bytes_")
    );

    // Simulate Telemetry delete/reload: a new plugin instance without disables.
    ctx.metadata.remove("mesh.metrics.disabled");
    enabled.before_proxy(&mut ctx, &mut headers).await;
    let mut resumed = mesh_http_summary(11, 22);
    resumed.metadata.extend(ctx.metadata);
    registry.record(&resumed);
    let output = registry.render_uncached();
    assert!(
        output.contains("ferrum_mesh_request_bytes_count{"),
        "re-enabled REQUEST_SIZE must resume:\n{output}"
    );
    assert!(
        output.contains("ferrum_mesh_response_bytes_count{"),
        "re-enabled RESPONSE_SIZE must resume:\n{output}"
    );
}

#[test]
fn tcp_opened_closed_and_bytes_follow_connect_disconnect_lifecycle() {
    let registry = MetricsRegistry::new();
    let metadata = HashMap::from([
        ("mesh.source.workload".into(), "frontend".into()),
        ("mesh.source.namespace".into(), "default".into()),
        (
            "mesh.source.principal".into(),
            "spiffe://cluster.local/ns/default/sa/frontend".into(),
        ),
        ("mesh.source.app".into(), "frontend".into()),
        ("mesh.source.service".into(), "frontend".into()),
        ("mesh.destination.workload".into(), "db".into()),
        ("mesh.destination.namespace".into(), "default".into()),
        (
            "mesh.destination.principal".into(),
            "spiffe://cluster.local/ns/default/sa/db".into(),
        ),
        ("mesh.destination.app".into(), "db".into()),
        ("mesh.destination.service".into(), "db".into()),
        ("mesh.request_protocol".into(), "tcp".into()),
        ("mesh.response_flags".into(), "-".into()),
        (
            "mesh.connection_security_policy".into(),
            "mutual_tls".into(),
        ),
    ]);

    registry.record_mesh_tcp_opened(&metadata, "db", Some("db"));
    let after_open = registry.render_uncached();
    assert!(
        after_open.lines().any(|line| line
            .starts_with("ferrum_mesh_tcp_connections_opened_total{")
            && line.ends_with(" 1")),
        "opened must increment on connect:\n{after_open}"
    );
    assert!(
        !after_open.contains("ferrum_mesh_tcp_connections_closed_total{"),
        "closed must not increment before disconnect:\n{after_open}"
    );

    let summary = StreamTransactionSummary {
        namespace: "default".into(),
        proxy_id: "db".into(),
        proxy_name: Some("db".into()),
        client_ip: "10.0.0.1".into(),
        consumer_username: None,
        auth_method: None,
        backend_target: "10.0.0.9:5432".into(),
        backend_resolved_ip: None,
        protocol: "tcp".into(),
        listen_port: 15001,
        duration_ms: 40.0,
        bytes_sent: 700,
        bytes_received: 900,
        connection_error: None,
        error_class: None,
        disconnect_direction: None,
        disconnect_cause: None,
        timestamp_connected: "2026-08-05T00:00:00Z".into(),
        timestamp_disconnected: "2026-08-05T00:00:01Z".into(),
        sni_hostname: None,
        metadata: metadata.clone(),
        proxy_lifecycle_generation: None,
    };
    registry.record_stream(&summary);
    let after_close = registry.render_uncached();
    assert!(
        after_close.lines().any(|line| line
            .starts_with("ferrum_mesh_tcp_connections_closed_total{")
            && line.ends_with(" 1")),
        "closed must increment on disconnect:\n{after_close}"
    );
    // Direction contract: Ferrum's gateway-perspective convention, matching
    // `StreamTransactionSummary.bytes_sent` / `bytes_received` and
    // `ferrum_api_bytes_{sent,received}_total`. `sent` is client->backend and
    // `received` is backend->client. Istio names `istio_tcp_sent_bytes_total`
    // the other way round, so do not "fix" this by swapping the two arms —
    // that would contradict every other Ferrum byte counter. The rendered HELP
    // text states the direction and is pinned by the metric-contract test.
    assert!(
        after_close
            .lines()
            .any(|line| line.starts_with("ferrum_mesh_tcp_sent_bytes_total{")
                && line.ends_with(" 700")),
        "sent bytes must equal stream bytes_sent (client->backend):\n{after_close}"
    );
    assert!(
        after_close.lines().any(
            |line| line.starts_with("ferrum_mesh_tcp_received_bytes_total{")
                && line.ends_with(" 900")
        ),
        "received bytes must equal stream bytes_received (backend->client):\n{after_close}"
    );
    assert!(
        after_close.contains("sent client->backend on closed connections."),
        "sent-bytes HELP must state the gateway-perspective direction:\n{after_close}"
    );
    assert!(
        after_close.contains("received backend->client on closed connections."),
        "received-bytes HELP must state the gateway-perspective direction:\n{after_close}"
    );
}

#[test]
fn grpc_message_counters_use_authoritative_frame_counts() {
    let registry = MetricsRegistry::new();
    let mut summary = mesh_http_summary(15, 25);
    summary
        .metadata
        .insert("mesh.request_protocol".into(), "grpc".into());
    // Two request frames (5+0 + 5+5) and three response frames.
    summary.grpc_request_messages = 2;
    summary.grpc_response_messages = 3;
    registry.record(&summary);
    let output = registry.render_uncached();
    assert!(
        output.lines().any(
            |line| line.starts_with("ferrum_mesh_request_messages_total{") && line.ends_with(" 2")
        ),
        "request messages must be 2:\n{output}"
    );
    assert!(
        output.lines().any(
            |line| line.starts_with("ferrum_mesh_response_messages_total{") && line.ends_with(" 3")
        ),
        "response messages must be 3:\n{output}"
    );
}

#[test]
fn grpc_length_prefixed_scanner_counts_spanning_frames() {
    let counter = Arc::new(AtomicU64::new(0));
    let mut scanner = GrpcLengthPrefixedScanner::default();
    // One empty message (5-byte header) split across two writes, then a
    // 3-byte payload message.
    scanner.push(&[0, 0, 0, 0], &counter);
    assert_eq!(counter.load(Ordering::Relaxed), 0);
    scanner.push(&[0], &counter);
    assert_eq!(counter.load(Ordering::Relaxed), 1);
    scanner.push(&[0, 0, 0, 0, 3, 1, 2, 3], &counter);
    assert_eq!(counter.load(Ordering::Relaxed), 2);
    assert_eq!(
        count_grpc_length_prefixed_messages(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 1, 2, 3]),
        2
    );
}

#[test]
fn complete_grpc_message_count_uses_fetch_max_not_additive_retry() {
    use ferrum_edge::plugins::mesh::prometheus_helpers::{
        metadata_observes_grpc_messages, record_complete_grpc_message_count,
    };

    let mut metadata = HashMap::new();
    metadata.insert("request_protocol".into(), "grpc".into());
    assert!(metadata_observes_grpc_messages(&metadata));
    metadata.insert("request_protocol".into(), "http".into());
    assert!(!metadata_observes_grpc_messages(&metadata));

    let counter = Arc::new(AtomicU64::new(0));
    let body = [0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 1, 2, 3]; // two messages
    record_complete_grpc_message_count(&counter, &body);
    record_complete_grpc_message_count(&counter, &body); // retry re-observe
    assert_eq!(counter.load(Ordering::Relaxed), 2);

    // Hostile declared length must not count or panic.
    let hostile = [0, 0xff, 0xff, 0xff, 0xff, 1];
    assert_eq!(count_grpc_length_prefixed_messages(&hostile), 0);
    record_complete_grpc_message_count(&counter, &hostile);
    assert_eq!(counter.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn tcp_sent_bytes_tag_override_and_disable_are_honored() {
    let plugin = WorkloadMetrics::new(&json!({
        "namespace": "default",
        "workload_spiffe_id": "spiffe://cluster.local/ns/default/sa/frontend",
        "labels": {"app": "frontend"},
        "metrics": {
            "disabled_metrics": ["TCP_OPENED_CONNECTIONS"],
            "tag_overrides": [{
                "metric": "TCP_SENT_BYTES",
                "name": "source_workload",
                "operation": {"type": "set", "value": "edge"}
            }, {
                "metric": "TCP_SENT_BYTES",
                "name": "response_code",
                "operation": {"type": "set", "value": "synthetic"}
            }]
        }
    }))
    .expect("plugin");
    let mut ctx = RequestContext::new("10.0.0.1".into(), "GET".into(), "/".into());
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut metadata = ctx.metadata.clone();
    metadata.insert("mesh.request_protocol".into(), "tcp".into());
    // Ensure identity labels exist for key construction.
    metadata
        .entry("mesh.source.workload".into())
        .or_insert_with(|| "frontend".into());
    metadata
        .entry("mesh.source.namespace".into())
        .or_insert_with(|| "default".into());
    metadata
        .entry("mesh.source.principal".into())
        .or_insert_with(|| "spiffe://cluster.local/ns/default/sa/frontend".into());
    metadata
        .entry("mesh.source.app".into())
        .or_insert_with(|| "frontend".into());
    metadata
        .entry("mesh.source.service".into())
        .or_insert_with(|| "frontend".into());
    metadata
        .entry("mesh.destination.workload".into())
        .or_insert_with(|| "db".into());
    metadata
        .entry("mesh.destination.namespace".into())
        .or_insert_with(|| "default".into());
    metadata
        .entry("mesh.destination.principal".into())
        .or_insert_with(|| "spiffe://cluster.local/ns/default/sa/db".into());
    metadata
        .entry("mesh.destination.app".into())
        .or_insert_with(|| "db".into());
    metadata
        .entry("mesh.destination.service".into())
        .or_insert_with(|| "db".into());
    metadata
        .entry("mesh.response_flags".into())
        .or_insert_with(|| "-".into());
    metadata
        .entry("mesh.connection_security_policy".into())
        .or_insert_with(|| "mutual_tls".into());

    let registry = MetricsRegistry::new();
    registry.record_mesh_tcp_opened(&metadata, "db", Some("db"));
    assert!(
        !registry
            .render_uncached()
            .contains("ferrum_mesh_tcp_connections_opened_total{"),
        "disabled TCP_OPENED_CONNECTIONS must not record"
    );

    let summary = StreamTransactionSummary {
        namespace: "default".into(),
        proxy_id: "db".into(),
        proxy_name: Some("db".into()),
        client_ip: "10.0.0.1".into(),
        consumer_username: None,
        auth_method: None,
        backend_target: "10.0.0.9:5432".into(),
        backend_resolved_ip: None,
        protocol: "tcp".into(),
        listen_port: 15001,
        duration_ms: 10.0,
        bytes_sent: 42,
        bytes_received: 7,
        connection_error: None,
        error_class: None,
        disconnect_direction: None,
        disconnect_cause: None,
        timestamp_connected: "2026-08-05T00:00:00Z".into(),
        timestamp_disconnected: "2026-08-05T00:00:01Z".into(),
        sni_hostname: None,
        metadata,
        proxy_lifecycle_generation: None,
    };
    registry.record_stream(&summary);
    let output = registry.render_uncached();
    assert!(
        output
            .lines()
            .any(|line| line.starts_with("ferrum_mesh_tcp_sent_bytes_total{")
                && line.contains("source_workload=\"edge\"")
                && line.ends_with(" 42")),
        "override-scoped sent bytes must keep value 42:\n{output}"
    );
    assert!(
        output
            .lines()
            .filter(|line| line.starts_with("ferrum_mesh_tcp_sent_bytes_total{"))
            .all(|line| !line.contains("response_code=")),
        "TCP families must not gain an HTTP response_code dimension:\n{output}"
    );
}
