//! Tests for stdout_logging plugin

use ferrum_edge::plugins::{
    Plugin, PluginResult, ProxyProtocol, StreamTransactionSummary, stdout_logging::StdoutLogging,
    validate_plugin_config,
};
use serde_json::json;
use std::collections::HashMap;

use super::plugin_utils::{create_test_context, create_test_transaction_summary};

#[tokio::test]
async fn test_stdout_logging_plugin_creation() {
    let config = json!({});
    let plugin = StdoutLogging::new(&config).unwrap();
    assert_eq!(plugin.name(), "stdout_logging");
    assert_eq!(plugin.priority(), 9000);
    assert_eq!(
        plugin.supported_protocols(),
        &[
            ProxyProtocol::Http,
            ProxyProtocol::Grpc,
            ProxyProtocol::WebSocket,
            ProxyProtocol::Tcp,
            ProxyProtocol::Udp,
        ]
    );
    assert!(!plugin.is_auth_plugin());
    assert!(!plugin.requires_request_body_buffering());
    assert!(!plugin.requires_response_body_buffering());
}

#[tokio::test]
async fn test_stdout_logging_plugin_lifecycle() {
    let config = json!({});
    let plugin = StdoutLogging::new(&config).unwrap();
    let mut ctx = create_test_context();

    // Test all lifecycle phases
    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));

    let consumer_index = ferrum_edge::ConsumerIndex::new(&[]);
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert!(matches!(result, PluginResult::Continue));

    let result = plugin.authorize(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));

    let mut headers = std::collections::HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));

    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_stdout_logging_plugin_logging() {
    let config = json!({});
    let plugin = StdoutLogging::new(&config).unwrap();

    let summary = create_test_transaction_summary();

    // Should not panic when logging
    plugin.log(&summary).await;
}

#[test]
fn test_stdout_logging_rejects_unknown_outer_and_nested_keys() {
    for (config, path) in [
        (
            json!({"filters": {"errors_only": true}}),
            "stdout_logging.filters",
        ),
        (json!({"log_level": "info"}), "stdout_logging.log_level"),
        (
            json!({"filter": {"error_only": true}}),
            "stdout_logging.filter.error_only",
        ),
        (
            json!({"filter": {"min_latency_msec": 10}}),
            "stdout_logging.filter.min_latency_msec",
        ),
    ] {
        let error = StdoutLogging::new(&config)
            .err()
            .expect("unknown key must fail");
        assert!(error.contains(path), "expected {path} in {error}");
    }
}

#[test]
fn test_stdout_logging_accepts_null_config_as_defaults() {
    let plugin =
        StdoutLogging::new(&serde_json::Value::Null).expect("null config should use defaults");
    assert_eq!(plugin.name(), "stdout_logging");
    assert_eq!(plugin.priority(), 9000);
}

#[test]
fn test_stdout_logging_rejects_non_object_config() {
    let err = StdoutLogging::new(&json!("bad")).err().unwrap();
    assert!(err.contains("config must be an object"), "got: {err}");
}

#[test]
fn test_shared_validation_rejects_invalid_stdout_logging_config() {
    let err = validate_plugin_config("stdout_logging", &json!({"filter": "errors"}))
        .expect_err("shared plugin validation must reject a non-object filter");
    assert_eq!(err, "stdout_logging: filter must be an object");
}

#[test]
fn test_shared_validation_preserves_null_defaults() {
    for config in [serde_json::Value::Null, json!({"filter": null})] {
        validate_plugin_config("stdout_logging", &config)
            .expect("shared validation must preserve null defaults");
    }
}

#[test]
fn test_shared_validation_rejects_unknown_stdout_logging_keys() {
    for (config, path) in [
        (
            json!({"include_metadata": false}),
            "stdout_logging.include_metadata",
        ),
        (
            json!({"filter": {"error_only": true}}),
            "stdout_logging.filter.error_only",
        ),
    ] {
        let error = validate_plugin_config("stdout_logging", &config)
            .expect_err("shared validation must reject unknown keys");
        assert!(error.contains(path), "expected {path} in {error}");
    }
}

#[test]
fn test_errors_only_uses_authoritative_terminal_failure_predicate() {
    let plugin = StdoutLogging::new(&json!({"filter": {"errors_only": true}})).unwrap();
    let mut summary = create_test_transaction_summary();
    summary.body_completed = true;
    assert!(!plugin.should_log_transaction(&summary));

    summary.body_error_class = Some(ferrum_edge::retry::ErrorClass::ConnectionReset);
    assert!(plugin.should_log_transaction(&summary));
    summary.body_error_class = None;

    summary.response_streamed = true;
    summary.body_completed = false;
    assert!(plugin.should_log_transaction(&summary));
    summary.response_streamed = false;
    summary.body_completed = true;

    summary.client_disconnected = true;
    assert!(plugin.should_log_transaction(&summary));
    summary.client_disconnected = false;

    summary
        .metadata
        .insert("grpc_status".to_string(), "0".to_string());
    assert!(!plugin.should_log_transaction(&summary));
    summary
        .metadata
        .insert("grpc_status".to_string(), "14".to_string());
    assert!(plugin.should_log_transaction(&summary));

    summary.metadata.remove("grpc_status");
    summary
        .metadata
        .insert("mirror_error".to_string(), "connection refused".to_string());
    assert!(plugin.should_log_transaction(&summary));
}

#[test]
fn test_terminal_grpc_status_is_stable_across_buffered_streamed_h2_h3_and_rejection_shapes() {
    let plugin = StdoutLogging::new(&json!({"filter": {"errors_only": true}})).unwrap();
    for (case, streamed, body_completed, status, rejection, expected_failure) in [
        ("buffered_h2_ok", false, true, Some("0"), false, false),
        ("buffered_h2_error", false, true, Some("7"), false, true),
        ("streamed_h2_ok", true, true, Some("0"), false, false),
        ("streamed_h2_error", true, true, Some("14"), false, true),
        ("native_h3_ok", true, true, Some("0"), false, false),
        ("native_h3_error", true, true, Some("13"), false, true),
        ("missing_terminal", true, true, None, false, true),
        ("malformed_terminal", true, true, Some("bad"), false, true),
        ("gateway_rejection", false, true, Some("16"), true, true),
    ] {
        let mut summary = create_test_transaction_summary();
        summary.response_status_code = 200;
        summary.response_streamed = streamed;
        summary.body_completed = body_completed;
        summary
            .metadata
            .insert("request_protocol".to_string(), "grpc".to_string());
        if let Some(status) = status {
            summary
                .metadata
                .insert("grpc_status".to_string(), status.to_string());
        }
        if rejection {
            summary
                .metadata
                .insert("rejection_phase".to_string(), "authorize".to_string());
        }

        assert_eq!(
            plugin.should_log_transaction(&summary),
            expected_failure,
            "{case}"
        );
        let json = serde_json::to_value(&summary).unwrap();
        let expected_status = status.map_or(2, |value| value.parse::<u32>().unwrap_or(u32::MAX));
        assert_eq!(json["grpc_status"], expected_status, "{case}");
        assert_eq!(json["response_status_code"], 200, "{case}");
    }
}

#[tokio::test]
async fn test_stdout_logging_stream_disconnect() {
    let plugin = StdoutLogging::new(&json!({})).unwrap();
    let summary = StreamTransactionSummary {
        namespace: "ferrum".to_string(),
        proxy_id: "tcp-proxy-1".to_string(),
        proxy_lifecycle_generation: None,
        proxy_name: Some("TCP Test".to_string()),
        client_ip: "127.0.0.1".to_string(),
        consumer_username: None,
        auth_method: None,
        backend_target: "127.0.0.1:9000".to_string(),
        backend_resolved_ip: None,
        protocol: "tcp".to_string(),
        listen_port: 8080,
        duration_ms: 15.0,
        bytes_sent: 128,
        bytes_received: 256,
        connection_error: None,
        error_class: None,
        disconnect_direction: None,
        disconnect_cause: None,
        timestamp_connected: "2025-01-01T00:00:00Z".to_string(),
        timestamp_disconnected: "2025-01-01T00:00:01Z".to_string(),
        sni_hostname: None,
        metadata: HashMap::new(),
    };

    plugin.on_stream_disconnect(&summary).await;
}
