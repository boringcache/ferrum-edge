//! Optional real-broker exercises for `kafka_logging`.
//!
//! These tests are ignored by default. Set `FERRUM_TEST_KAFKA_BOOTSTRAP` to a
//! reachable `host:port` (for example a local Redpanda/Kafka listener) and run:
//!
//! ```text
//! cargo test --test integration_tests kafka_logging_broker -- --ignored --nocapture
//! ```
//!
//! Hosted CI does not currently provision a Kafka broker for this filter; the
//! deterministic unit suite covers admission, delivery accounting, CRL
//! fail-closed behavior, budgets, unknown keys, and owned finalize.

use std::collections::HashMap;
use std::time::Duration;

use chrono::Utc;
use ferrum_edge::plugins::kafka_logging::KafkaLogging;
use ferrum_edge::plugins::utils::PluginHttpClient;
use ferrum_edge::plugins::{Plugin, TransactionSummary};
use serde_json::json;
use tokio::time::sleep;

fn bootstrap() -> Option<String> {
    std::env::var("FERRUM_TEST_KAFKA_BOOTSTRAP")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn summary() -> TransactionSummary {
    TransactionSummary {
        namespace: "ferrum".to_string(),
        timestamp_received: Utc::now().to_rfc3339(),
        client_ip: "203.0.113.10".to_string(),
        consumer_username: None,
        auth_method: None,
        http_method: "GET".to_string(),
        request_path: "/kafka-broker-test".to_string(),
        proxy_id: Some("kafka-broker-proxy".to_string()),
        proxy_name: Some("Kafka Broker Proxy".to_string()),
        backend_target: Some("http://127.0.0.1:9/".to_string()),
        backend_resolved_ip: Some("127.0.0.1".to_string()),
        response_status_code: 200,
        latency_total_ms: 1.0,
        latency_gateway_processing_ms: 0.0,
        latency_backend_ttfb_ms: 0.0,
        latency_backend_total_ms: 0.0,
        latency_plugin_execution_ms: 0.0,
        latency_plugin_external_io_ms: 0.0,
        latency_gateway_overhead_ms: 0.0,
        request_user_agent: Some("kafka-broker-test".to_string()),
        response_streamed: false,
        client_disconnected: false,
        error_class: None,
        body_error_class: None,
        body_completed: true,
        bytes_sent: 0,
        bytes_received: 0,
        mirror: false,
        metadata: HashMap::new(),
        ai_usage_export: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires FERRUM_TEST_KAFKA_BOOTSTRAP real broker"]
async fn kafka_logging_broker_delivers_and_finalizes() {
    let Some(bootstrap) = bootstrap() else {
        eprintln!("SKIP: set FERRUM_TEST_KAFKA_BOOTSTRAP to exercise real broker delivery");
        return;
    };
    let topic =
        std::env::var("FERRUM_TEST_KAFKA_TOPIC").unwrap_or_else(|_| "ferrum-access-logs".to_string());
    let plugin = KafkaLogging::new(
        &json!({
            "broker_list": bootstrap,
            "topic": topic,
            "acks": "all",
            "message_timeout_ms": 10_000,
            "flush_timeout_seconds": 10,
            "security_protocol": "plaintext"
        }),
        &PluginHttpClient::default(),
    )
    .expect("construct kafka_logging against real broker");

    plugin.log(&summary()).await;
    // Allow librdkafka delivery callback to fire.
    sleep(Duration::from_secs(3)).await;
    let mid = plugin.snapshot();
    assert!(
        mid.admitted_total >= 1,
        "expected local admission against real broker, got {mid:?}"
    );
    assert!(
        mid.delivered_total >= 1 || mid.delivery_failed_total >= 1,
        "expected terminal delivery callback against real broker, got {mid:?}"
    );

    plugin.finalize().await;
    let end = plugin.snapshot();
    assert!(end.finalized);
}
