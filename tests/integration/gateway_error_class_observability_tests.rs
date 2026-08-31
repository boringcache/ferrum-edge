//! One HTTP observability vocabulary for `X-Gateway-Error`, access logs, and
//! `ferrum_requests_total{error_class}` (issues #4396, #4399, #4397).

use std::collections::HashMap;
use std::sync::Arc;

use ferrum_edge::_test_support::x_gateway_error_for_backend_failure_for_test;
use ferrum_edge::plugins::TransactionSummary;
use ferrum_edge::plugins::prometheus_metrics::{CounterKey, MetricsRegistry};
use ferrum_edge::retry::{
    ErrorClass, HTTP_OBSERVABILITY_ERROR_CLASSES, OBS_BACKEND_ERROR, OBS_BACKEND_TIMEOUT,
    OBS_CIRCUIT_BREAKER_OPEN, OBS_CONCURRENCY_LIMIT, OBS_CONFIG_STALE, OBS_CONNECTION_FAILURE,
    OBS_OVERLOAD, http_log_error_class, http_metrics_error_class,
    intern_http_observability_error_class,
};

fn http_summary(status: u16, class: Option<ErrorClass>, phase: Option<&str>) -> TransactionSummary {
    let mut metadata = HashMap::new();
    if let Some(phase) = phase {
        metadata.insert("rejection_phase".to_string(), phase.to_string());
    }
    TransactionSummary {
        plugin_trigger_decisions: Default::default(),
        namespace: "ferrum".to_string(),
        timestamp_received: "2026-08-31T00:00:00Z".to_string(),
        client_ip: "127.0.0.1".to_string(),
        consumer_username: None,
        auth_method: None,
        http_method: "GET".to_string(),
        request_path: "/test".to_string(),
        proxy_id: Some("obs-corr".to_string()),
        proxy_name: Some("obs".to_string()),
        backend_target: Some("http://127.0.0.1:9".to_string()),
        backend_resolved_ip: None,
        response_status_code: status,
        latency_total_ms: 1.0,
        latency_gateway_processing_ms: 1.0,
        latency_backend_ttfb_ms: 0.0,
        latency_backend_total_ms: 0.0,
        latency_plugin_execution_ms: 0.0,
        latency_plugin_external_io_ms: 0.0,
        latency_gateway_overhead_ms: 1.0,
        request_user_agent: None,
        response_streamed: false,
        client_disconnected: false,
        error_class: class,
        body_error_class: None,
        body_completed: false,
        bytes_sent: 0,
        bytes_received: 0,
        grpc_request_messages: 0,
        grpc_response_messages: 0,
        mirror: false,
        metadata,
        ai_usage_export: None,
        proxy_lifecycle_generation: None,
    }
}

#[test]
fn header_log_and_metrics_share_one_http_vocabulary() {
    let cases: &[(&str, u16, Option<ErrorClass>, Option<&str>, Option<bool>)] = &[
        (
            OBS_CONNECTION_FAILURE,
            502,
            Some(ErrorClass::ConnectionRefused),
            None,
            Some(true),
        ),
        (
            OBS_BACKEND_TIMEOUT,
            504,
            Some(ErrorClass::ReadWriteTimeout),
            None,
            Some(false),
        ),
        (OBS_BACKEND_ERROR, 503, None, None, Some(false)),
        (
            OBS_CIRCUIT_BREAKER_OPEN,
            503,
            None,
            Some("circuit_breaker_open"),
            None,
        ),
        (OBS_OVERLOAD, 503, None, Some("overload"), None),
        (OBS_CONFIG_STALE, 503, None, Some("config_stale"), None),
        (
            OBS_CONCURRENCY_LIMIT,
            503,
            None,
            Some("adaptive_concurrency"),
            None,
        ),
    ];

    let registry = MetricsRegistry::new();
    for (token, status, class, phase, connection_error) in cases {
        if let Some(connection_error) = connection_error {
            assert_eq!(
                x_gateway_error_for_backend_failure_for_test(*connection_error, *status),
                Some(*token),
                "header token for {token}"
            );
        }
        assert_eq!(
            http_metrics_error_class(*class, *status, *phase),
            Some(*token),
            "metrics token for {token}"
        );
        assert_eq!(
            http_log_error_class(*class, *status, *phase),
            Some(*token),
            "log token for {token}"
        );
        let summary = http_summary(*status, *class, *phase);
        assert_eq!(summary.serialized_error_class(), Some(*token));
        assert_eq!(summary.metrics_error_class_label(), Some(*token));
        registry.record(&summary);
        assert!(
            registry.request_counter.contains_key(&CounterKey {
                proxy_id: Arc::from("obs-corr"),
                method: "GET",
                status_code: *status,
                grpc_status: None,
                error_class: Some(*token),
            }),
            "ferrum_requests_total must carry error_class={token}"
        );
    }

    let ok = http_summary(200, None, None);
    registry.record(&ok);
    assert!(registry.request_counter.contains_key(&CounterKey {
        proxy_id: Arc::from("obs-corr"),
        method: "GET",
        status_code: 200,
        grpc_status: None,
        error_class: None,
    }));
    let output = registry.render_uncached();
    assert!(
        !output.contains(r#"status_code="200",error_class="#),
        "2xx must omit error_class: {output}"
    );
}

#[test]
fn http_observability_cardinality_is_closed() {
    assert_eq!(HTTP_OBSERVABILITY_ERROR_CLASSES.len(), 7);
    let mut seen = std::collections::HashSet::new();
    for token in HTTP_OBSERVABILITY_ERROR_CLASSES {
        assert!(seen.insert(*token), "duplicate HTTP token {token}");
        assert_eq!(intern_http_observability_error_class(token), Some(*token));
    }
    assert!(intern_http_observability_error_class("backend_down").is_none());
    assert!(intern_http_observability_error_class("Service overloaded").is_none());
    assert_eq!(ErrorClass::ALL.len(), 19);
    let mut class_seen = std::collections::HashSet::new();
    for class in ErrorClass::ALL {
        assert!(
            class_seen.insert(class.as_str()),
            "duplicate ErrorClass {}",
            class.as_str()
        );
    }
}

#[test]
fn gateway_authored_5xx_sites_set_the_new_tokens() {
    let proxy = include_str!("../../src/proxy/mod.rs");
    assert!(proxy.contains("X_GATEWAY_ERROR_OVERLOAD"));
    assert!(proxy.contains("X_GATEWAY_ERROR_CONFIG_STALE"));
    assert!(proxy.contains("build_response_with_gateway_error("));

    let h3 = include_str!("../../src/http3/server.rs");
    assert!(h3.contains("overload_reject_headers()"));
    assert!(h3.contains("config_stale_reject_headers()"));

    let ac = include_str!("../../src/plugins/adaptive_concurrency.rs");
    assert!(ac.contains("OBS_CONCURRENCY_LIMIT"));
    assert!(ac.contains("\"x-gateway-error\""));
}
