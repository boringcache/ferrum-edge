use std::sync::Arc;
use std::time::Duration;

use ferrum_edge::adaptive_concurrency::{
    AdaptiveConcurrencyConfig, AdaptiveConcurrencyKeyBy, AdaptiveConcurrencyLimiter,
};
use ferrum_edge::config::types::Proxy;
use ferrum_edge::plugins::adaptive_concurrency::AdaptiveConcurrency;
use ferrum_edge::plugins::{
    BackendAdmissionContext, BackendAdmissionDecision, BackendAdmissionOutcome,
    BackendAdmissionPermit, Plugin, PluginHttpClient, ProxyProtocol, RequestContext,
};
use ferrum_edge::retry::ErrorClass;
use serde_json::json;

fn proxy() -> Proxy {
    serde_json::from_value(json!({
        "id": "proxy-1",
        "namespace": "default",
        "backend_host": "backend.local",
        "backend_port": 8080
    }))
    .expect("minimal proxy should deserialize")
}

fn limiter_config(initial_limit: u64) -> Arc<AdaptiveConcurrencyConfig> {
    Arc::new(AdaptiveConcurrencyConfig {
        key_by: AdaptiveConcurrencyKeyBy::Proxy,
        min_limit: 1,
        initial_limit,
        max_limit: initial_limit.max(1),
        min_samples: 1,
        target_latency_multiplier: 1.5,
        decrease_ratio: 0.5,
        increase_step: 1,
        shadow_mode: false,
        expose_headers: false,
    })
}

#[test]
fn adaptive_concurrency_rejects_when_limit_is_full_and_releases_on_drop() {
    let plugin = AdaptiveConcurrency::new(
        &json!({
            "initial_limit": 1,
            "max_limit": 1
        }),
        PluginHttpClient::default(),
    )
    .expect("config should be valid");
    let proxy = proxy();
    let ctx = RequestContext::new("192.0.2.10".to_string(), "GET".to_string(), "/".to_string());
    let admission = BackendAdmissionContext {
        proxy: &proxy,
        upstream_target: None,
        protocol: ProxyProtocol::Http,
    };

    let first = match plugin.try_backend_admission(&ctx, &admission) {
        BackendAdmissionDecision::Admit(permit) => permit,
        _ => panic!("first request should be admitted"),
    };

    match plugin.try_backend_admission(&ctx, &admission) {
        BackendAdmissionDecision::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 503);
            assert_eq!(body, br#"{"error":"Upstream concurrency limit reached"}"#);
        }
        _ => panic!("second concurrent request should be rejected"),
    }

    drop(first);

    match plugin.try_backend_admission(&ctx, &admission) {
        BackendAdmissionDecision::Admit(_) => {}
        _ => panic!("slot should be released when the permit drops"),
    }
}

#[test]
fn adaptive_concurrency_records_failure_by_shrinking_limit() {
    let proxy = proxy();
    let limiter = AdaptiveConcurrencyLimiter::new(16);
    let config = limiter_config(4);
    let permit = limiter
        .try_acquire(&proxy, None, Arc::clone(&config))
        .expect("request should be admitted");

    permit.record_backend_outcome(BackendAdmissionOutcome {
        response_status: 503,
        connection_error: false,
        error_class: None,
        backend_elapsed: Duration::from_millis(5),
    });

    let snapshot = limiter
        .snapshot(&proxy, None, AdaptiveConcurrencyKeyBy::Proxy)
        .expect("state should exist after acquire");
    assert_eq!(snapshot.limit, 2);
    assert_eq!(snapshot.in_flight, 1);

    drop(permit);

    let snapshot = limiter
        .snapshot(&proxy, None, AdaptiveConcurrencyKeyBy::Proxy)
        .expect("state should still exist after release");
    assert_eq!(snapshot.in_flight, 0);
}

#[test]
fn adaptive_concurrency_ignores_client_disconnect_samples() {
    let proxy = proxy();
    let limiter = AdaptiveConcurrencyLimiter::new(16);
    let config = limiter_config(4);
    let permit = limiter
        .try_acquire(&proxy, None, Arc::clone(&config))
        .expect("request should be admitted");

    permit.record_backend_outcome(BackendAdmissionOutcome {
        response_status: 499,
        connection_error: true,
        error_class: Some(ErrorClass::ClientDisconnect),
        backend_elapsed: Duration::from_millis(50),
    });

    let snapshot = limiter
        .snapshot(&proxy, None, AdaptiveConcurrencyKeyBy::Proxy)
        .expect("state should exist after acquire");
    assert_eq!(snapshot.limit, 4);
    assert_eq!(snapshot.samples, 0);
}

#[test]
fn adaptive_concurrency_supports_http_family_backend_admission() {
    let plugin = AdaptiveConcurrency::new(&json!({}), PluginHttpClient::default())
        .expect("default config should be valid");

    assert!(plugin.is_backend_admission_plugin());
    assert!(plugin.supported_protocols().contains(&ProxyProtocol::Http));
    assert!(plugin.supported_protocols().contains(&ProxyProtocol::Grpc));
    assert!(
        plugin
            .supported_protocols()
            .contains(&ProxyProtocol::WebSocket)
    );
    assert!(!plugin.supported_protocols().contains(&ProxyProtocol::Tcp));
}

#[test]
fn adaptive_concurrency_validates_bounds() {
    let err = match AdaptiveConcurrency::new(
        &json!({
            "min_limit": 4,
            "initial_limit": 2,
            "max_limit": 8
        }),
        PluginHttpClient::default(),
    ) {
        Ok(_) => panic!("invalid bounds should be rejected"),
        Err(err) => err,
    };
    assert!(err.contains("initial_limit"));

    let err = match AdaptiveConcurrency::new(
        &json!({
            "key_by": "consumer"
        }),
        PluginHttpClient::default(),
    ) {
        Ok(_) => panic!("unsupported key_by should be rejected"),
        Err(err) => err,
    };
    assert!(err.contains("unsupported key_by"));
}
