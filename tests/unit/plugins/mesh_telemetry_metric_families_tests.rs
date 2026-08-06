//! Focused coverage for Istio Telemetry metric families added for #3256:
//! REQUEST_SIZE / RESPONSE_SIZE, TCP connection/byte counters, and gRPC
//! message counters. Asserts values and disable/reload lifecycle, not mere
//! series presence.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use ferrum_edge::config::types::BackendScheme;
use ferrum_edge::plugins::mesh::prometheus_helpers::{
    GrpcLengthPrefixedScanner, count_grpc_length_prefixed_messages,
};
use ferrum_edge::plugins::mesh::workload_metrics::WorkloadMetrics;
use ferrum_edge::plugins::prometheus_metrics::MetricsRegistry;
use ferrum_edge::plugins::{
    Plugin, PluginResult, RequestContext, StreamConnectionContext, StreamTransactionSummary,
};
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
    let mut metadata = HashMap::from([
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

    registry.record_mesh_tcp_admitted(&mut metadata, "db", Some("db"));
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
    // Direction contract: these mesh families implement Istio Telemetry's
    // canonical TCP_SENT_BYTES=response and TCP_RECEIVED_BYTES=request
    // semantics. StreamTransactionSummary uses Ferrum's gateway-perspective
    // field names, so the producer intentionally maps bytes_received to sent
    // and bytes_sent to received. General Ferrum transaction/API counters keep
    // their existing gateway-perspective convention.
    assert!(
        after_close
            .lines()
            .any(|line| line.starts_with("ferrum_mesh_tcp_sent_bytes_total{")
                && line.ends_with(" 900")),
        "TCP_SENT_BYTES must equal response bytes (backend->client):\n{after_close}"
    );
    assert!(
        after_close.lines().any(
            |line| line.starts_with("ferrum_mesh_tcp_received_bytes_total{")
                && line.ends_with(" 700")
        ),
        "TCP_RECEIVED_BYTES must equal request bytes (client->backend):\n{after_close}"
    );
    assert!(
        after_close.contains("response bytes sent backend->client on closed connections."),
        "sent-bytes HELP must state the Istio response direction:\n{after_close}"
    );
    assert!(
        after_close.contains("request bytes received client->backend on closed connections."),
        "received-bytes HELP must state the Istio request direction:\n{after_close}"
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
    registry.record_mesh_tcp_admitted(&mut metadata, "db", Some("db"));
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
                && line.ends_with(" 7")),
        "override-scoped TCP_SENT_BYTES must keep the response-byte value 7:\n{output}"
    );
    assert!(
        output
            .lines()
            .filter(|line| line.starts_with("ferrum_mesh_tcp_sent_bytes_total{"))
            .all(|line| !line.contains("response_code=")),
        "TCP families must not gain an HTTP response_code dimension:\n{output}"
    );
}

// ---------------------------------------------------------------------------
// Mesh TCP opened/closed lifecycle is owned by the ACCEPT PATH, not by the
// `workload_metrics` hook. Ferrum permits several effective `workload_metrics`
// instances per proxy, and every one of them runs `on_stream_connect` over
// metadata that later instances still change, so an increment from the hook
// counted one connection once per instance under intermediate policy. The
// accept path instead calls `record_mesh_tcp_admitted` once, after the whole
// chain accepted, and that call is what stamps the admission marker gating the
// closed/byte half.
// ---------------------------------------------------------------------------

const ADMITTED_MARKER: &str =
    ferrum_edge::plugins::mesh::prometheus_helpers::MESH_TCP_STREAM_ADMITTED_METADATA;

fn mesh_stream_ctx() -> StreamConnectionContext {
    StreamConnectionContext::new(
        "10.0.0.1".to_string(),
        "10.0.0.1".to_string(),
        "db".to_string(),
        Some("db".to_string()),
        5432,
        BackendScheme::Tcp,
        Arc::new(ferrum_edge::ConsumerIndex::new(&[])),
    )
}

fn workload_metrics_instance(metrics: serde_json::Value) -> WorkloadMetrics {
    WorkloadMetrics::new(&json!({
        "namespace": "default",
        "workload_spiffe_id": "spiffe://cluster.local/ns/default/sa/frontend",
        "labels": {"app": "frontend"},
        "metrics": metrics,
    }))
    .expect("workload_metrics instance")
}

fn stream_summary_from(metadata: HashMap<String, String>) -> StreamTransactionSummary {
    StreamTransactionSummary {
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
        duration_ms: 25.0,
        bytes_sent: 300,
        bytes_received: 500,
        connection_error: None,
        error_class: None,
        disconnect_direction: None,
        disconnect_cause: None,
        timestamp_connected: "2026-08-05T00:00:00Z".into(),
        timestamp_disconnected: "2026-08-05T00:00:01Z".into(),
        sni_hostname: None,
        metadata,
        proxy_lifecycle_generation: None,
    }
}

fn series_lines<'a>(output: &'a str, family: &str) -> Vec<&'a str> {
    let prefix = format!("{family}{{");
    output
        .lines()
        .filter(|line| line.starts_with(&prefix))
        .collect()
}

#[tokio::test]
async fn multiple_workload_metrics_applications_record_one_tcp_opened_under_final_policy() {
    // Two effective instances both stamp the connection. The second one owns
    // the final TCP_OPENED_CONNECTIONS tag policy.
    let first = workload_metrics_instance(json!({}));
    let second = workload_metrics_instance(json!({
        "tag_overrides": [{
            "metric": "TCP_OPENED_CONNECTIONS",
            "name": "source_workload",
            "operation": {"type": "set", "value": "edge"}
        }]
    }));

    let mut ctx = mesh_stream_ctx();
    assert!(matches!(
        first.on_stream_connect(&mut ctx).await,
        PluginResult::Continue
    ));
    assert!(matches!(
        second.on_stream_connect(&mut ctx).await,
        PluginResult::Continue
    ));

    let registry = MetricsRegistry::new();
    registry.record_mesh_tcp_admitted(
        ctx.metadata.as_mut().expect("mesh stream metadata"),
        "db",
        Some("db"),
    );

    let after_open = registry.render_uncached();
    let opened = series_lines(&after_open, "ferrum_mesh_tcp_connections_opened_total");
    assert_eq!(
        opened.len(),
        1,
        "two effective workload_metrics instances must not open two series:\n{after_open}"
    );
    assert!(
        opened[0].ends_with(" 1"),
        "one connection must be one opened increment:\n{after_open}"
    );
    assert!(
        opened[0].contains("source_workload=\"edge\""),
        "opened must carry the FINAL instance's tag policy:\n{after_open}"
    );
    assert!(
        !opened[0].contains("response_code="),
        "Istio TCP series carry no response_code:\n{after_open}"
    );

    // The disconnect half stays balanced: one open, one close.
    let metadata = ctx.metadata.clone().expect("mesh stream metadata");
    registry.record_stream(&stream_summary_from(metadata));
    let after_close = registry.render_uncached();
    assert_eq!(
        series_lines(&after_close, "ferrum_mesh_tcp_connections_opened_total").len(),
        1,
        "disconnect must not add an opened series:\n{after_close}"
    );
    let closed = series_lines(&after_close, "ferrum_mesh_tcp_connections_closed_total");
    assert_eq!(closed.len(), 1, "one close expected:\n{after_close}");
    assert!(
        closed[0].ends_with(" 1"),
        "open/close lifecycle must stay balanced:\n{after_close}"
    );
}

#[tokio::test]
async fn disabled_final_tcp_opened_policy_records_no_opened_but_keeps_closed() {
    let plugin = workload_metrics_instance(json!({
        "disabled_metrics": ["TCP_OPENED_CONNECTIONS"]
    }));
    let mut ctx = mesh_stream_ctx();
    plugin.on_stream_connect(&mut ctx).await;

    let registry = MetricsRegistry::new();
    registry.record_mesh_tcp_admitted(
        ctx.metadata.as_mut().expect("mesh stream metadata"),
        "db",
        Some("db"),
    );
    let after_open = registry.render_uncached();
    assert!(
        series_lines(&after_open, "ferrum_mesh_tcp_connections_opened_total").is_empty(),
        "a disabled final TCP_OPENED_CONNECTIONS policy must record nothing:\n{after_open}"
    );

    // Disabling opened is per-family: the connection was still admitted, so the
    // closed/byte families keep reporting.
    let metadata = ctx.metadata.clone().expect("mesh stream metadata");
    registry.record_stream(&stream_summary_from(metadata));
    let after_close = registry.render_uncached();
    assert_eq!(
        series_lines(&after_close, "ferrum_mesh_tcp_connections_closed_total").len(),
        1,
        "disabling opened must not suppress closed:\n{after_close}"
    );
}

#[tokio::test]
async fn rejected_stream_chain_records_no_tcp_lifecycle() {
    // `workload_metrics` ran and stamped mesh identity metadata, but a later
    // plugin in the chain rejected the stream, so the accept path never calls
    // `record_mesh_tcp_admitted`. Neither half of the lifecycle may appear —
    // counting only the close would unbalance the counters forever.
    let plugin = workload_metrics_instance(json!({}));
    let mut ctx = mesh_stream_ctx();
    plugin.on_stream_connect(&mut ctx).await;

    let registry = MetricsRegistry::new();
    let mut metadata = ctx.metadata.clone().expect("mesh stream metadata");
    let mut summary = stream_summary_from(metadata.clone());
    summary.bytes_sent = 0;
    summary.bytes_received = 0;
    registry.record_stream(&summary);

    let output = registry.render_uncached();
    for family in [
        "ferrum_mesh_tcp_connections_opened_total",
        "ferrum_mesh_tcp_connections_closed_total",
        "ferrum_mesh_tcp_sent_bytes_total",
        "ferrum_mesh_tcp_received_bytes_total",
    ] {
        assert!(
            series_lines(&output, family).is_empty(),
            "a rejected stream chain must not record {family}:\n{output}"
        );
    }

    // Only admission arms the lifecycle.
    registry.record_mesh_tcp_admitted(&mut metadata, "db", Some("db"));
    let after_admit = registry.render_uncached();
    assert_eq!(
        series_lines(&after_admit, "ferrum_mesh_tcp_connections_opened_total").len(),
        1,
        "admission must record the opened counter:\n{after_admit}"
    );
}

#[tokio::test]
async fn mesh_tcp_admission_is_recorded_at_most_once_per_connection() {
    let plugin = workload_metrics_instance(json!({}));
    let mut ctx = mesh_stream_ctx();
    plugin.on_stream_connect(&mut ctx).await;
    let metadata = ctx.metadata.as_mut().expect("mesh stream metadata");

    let registry = MetricsRegistry::new();
    registry.record_mesh_tcp_admitted(metadata, "db", Some("db"));
    registry.record_mesh_tcp_admitted(metadata, "db", Some("db"));

    let output = registry.render_uncached();
    let opened = series_lines(&output, "ferrum_mesh_tcp_connections_opened_total");
    assert_eq!(opened.len(), 1, "one series expected:\n{output}");
    assert!(
        opened[0].ends_with(" 1"),
        "a second admission call must not double count one connection:\n{output}"
    );
}

#[tokio::test]
async fn udp_stream_admission_records_no_tcp_series() {
    // UDP/DTLS must never be misclassified as a mesh TCP connection.
    let plugin = workload_metrics_instance(json!({}));
    let mut ctx = StreamConnectionContext::new(
        "10.0.0.1".to_string(),
        "10.0.0.1".to_string(),
        "dns".to_string(),
        Some("dns".to_string()),
        53,
        BackendScheme::Udp,
        Arc::new(ferrum_edge::ConsumerIndex::new(&[])),
    );
    plugin.on_stream_connect(&mut ctx).await;

    let registry = MetricsRegistry::new();
    let metadata = ctx.metadata.as_mut().expect("mesh stream metadata");
    registry.record_mesh_tcp_admitted(metadata, "dns", Some("dns"));
    assert!(
        !metadata.contains_key(ADMITTED_MARKER),
        "a UDP stream must not be stamped as an admitted mesh TCP connection"
    );

    let mut summary = stream_summary_from(ctx.metadata.clone().expect("metadata"));
    summary.protocol = "udp".into();
    registry.record_stream(&summary);

    let output = registry.render_uncached();
    for family in [
        "ferrum_mesh_tcp_connections_opened_total",
        "ferrum_mesh_tcp_connections_closed_total",
        "ferrum_mesh_tcp_sent_bytes_total",
        "ferrum_mesh_tcp_received_bytes_total",
    ] {
        assert!(
            series_lines(&output, family).is_empty(),
            "UDP must not populate {family}:\n{output}"
        );
    }
}
