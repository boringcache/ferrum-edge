use std::sync::Arc;
use std::time::Duration;

use ferrum_edge::adaptive_concurrency::{
    AdaptiveConcurrencyConfig, AdaptiveConcurrencyKeyBy, AdaptiveConcurrencyLimiter,
};
use ferrum_edge::config::types::{Proxy, UpstreamTarget};
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
        max_tracked_keys: 10_000,
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

fn growth_config(initial_limit: u64, max_limit: u64) -> Arc<AdaptiveConcurrencyConfig> {
    Arc::new(AdaptiveConcurrencyConfig {
        key_by: AdaptiveConcurrencyKeyBy::Proxy,
        max_tracked_keys: 10_000,
        min_limit: 1,
        initial_limit,
        max_limit,
        min_samples: 1,
        target_latency_multiplier: 1.5,
        decrease_ratio: 0.5,
        increase_step: 1,
        shadow_mode: false,
        expose_headers: false,
    })
}

fn target(host: &str, port: u16) -> UpstreamTarget {
    UpstreamTarget {
        host: host.to_string(),
        port,
        weight: 1,
        tags: Default::default(),
        locality: None,
        path: None,
    }
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
fn adaptive_concurrency_caps_tracked_target_keys() {
    let proxy = proxy();
    let limiter = AdaptiveConcurrencyLimiter::new(16);
    let config = Arc::new(AdaptiveConcurrencyConfig {
        key_by: AdaptiveConcurrencyKeyBy::Backend,
        max_tracked_keys: 1,
        min_limit: 1,
        initial_limit: 2,
        max_limit: 2,
        min_samples: 1,
        target_latency_multiplier: 1.5,
        decrease_ratio: 0.5,
        increase_step: 1,
        shadow_mode: false,
        expose_headers: false,
    });
    let first_target = target("a1.example.com", 8080);
    let second_target = target("a2.example.com", 8080);

    let first = limiter
        .try_acquire(&proxy, Some(&first_target), Arc::clone(&config))
        .expect("first distinct backend key should be admitted");
    let same_key = limiter
        .try_acquire(&proxy, Some(&first_target), Arc::clone(&config))
        .expect("existing backend key should not consume another tracked-key slot");
    let rejected = match limiter.try_acquire(&proxy, Some(&second_target), Arc::clone(&config)) {
        Ok(_) => panic!("new backend key should be rejected when cap is exhausted"),
        Err(rejected) => rejected,
    };

    assert_eq!(rejected.limit, 1);
    assert_eq!(limiter.tracked_keys_count(), 1);

    drop(first);
    drop(same_key);
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

#[test]
fn adaptive_concurrency_ignores_request_body_too_large_samples() {
    let proxy = proxy();
    let limiter = AdaptiveConcurrencyLimiter::new(16);
    let config = limiter_config(4);
    let permit = limiter
        .try_acquire(&proxy, None, Arc::clone(&config))
        .expect("request should be admitted");

    // An oversized *client* upload surfaces as a gateway 413
    // (`RequestBodyTooLarge`): it is the request's fault, not the backend's, so
    // it must neither grow nor shrink the limit and must not record a sample.
    permit.record_backend_outcome(BackendAdmissionOutcome {
        response_status: 413,
        connection_error: false,
        error_class: Some(ErrorClass::RequestBodyTooLarge),
        backend_elapsed: Duration::from_millis(50),
    });

    let snapshot = limiter
        .snapshot(&proxy, None, AdaptiveConcurrencyKeyBy::Proxy)
        .expect("state should exist after acquire");
    assert_eq!(snapshot.limit, 4);
    assert_eq!(snapshot.samples, 0);

    drop(permit);
}

#[test]
fn adaptive_concurrency_shrinks_on_oversized_backend_response() {
    let proxy = proxy();
    let limiter = AdaptiveConcurrencyLimiter::new(16);
    let config = limiter_config(4);
    let permit = limiter
        .try_acquire(&proxy, None, Arc::clone(&config))
        .expect("request should be admitted");

    // A backend response that overflows the configured max body size is a
    // backend fault even though the status line (200) looked healthy before the
    // overflow was detected: it must shrink the limit, not be counted as a fast
    // success. Mirrors the gateway sending a 502 to the client.
    permit.record_backend_outcome(BackendAdmissionOutcome {
        response_status: 200,
        connection_error: false,
        error_class: Some(ErrorClass::ResponseBodyTooLarge),
        backend_elapsed: Duration::from_millis(5),
    });

    let snapshot = limiter
        .snapshot(&proxy, None, AdaptiveConcurrencyKeyBy::Proxy)
        .expect("state should exist after acquire");
    assert_eq!(snapshot.limit, 2);
    assert_eq!(snapshot.samples, 0);

    drop(permit);
}

#[test]
fn adaptive_concurrency_completed_success_grows_limit_at_capacity() {
    let proxy = proxy();
    let limiter = AdaptiveConcurrencyLimiter::new(16);
    let config = growth_config(1, 4);
    let permit = limiter
        .try_acquire(&proxy, None, Arc::clone(&config))
        .expect("request should be admitted");

    // in_flight == limit == 1: a completed, fast success probes for more
    // capacity and grows the limit (standard additive increase). This is the
    // baseline that the WebSocket holding path below must NOT trigger.
    permit.record_backend_outcome(BackendAdmissionOutcome {
        response_status: 200,
        connection_error: false,
        error_class: None,
        backend_elapsed: Duration::from_millis(1),
    });

    let snapshot = limiter
        .snapshot(&proxy, None, AdaptiveConcurrencyKeyBy::Proxy)
        .expect("state should exist after acquire");
    assert_eq!(
        snapshot.limit, 2,
        "a completed success at capacity grows the limit"
    );

    drop(permit);
}

#[test]
fn adaptive_concurrency_held_session_success_does_not_grow_limit() {
    let proxy = proxy();
    let limiter = AdaptiveConcurrencyLimiter::new(16);
    let config = growth_config(1, 4);
    let permit = limiter
        .try_acquire(&proxy, None, Arc::clone(&config))
        .expect("request should be admitted");

    // A WebSocket handshake records its outcome while the session's permit is
    // still held (in_flight stays 1 == limit). Growing here would ratchet the
    // limit up on every concurrent session and defeat the in-flight session
    // cap, so the holding variant records the latency sample but must NOT grow
    // the limit. Contrast with `..._completed_success_grows_limit_at_capacity`,
    // which uses the identical config and does grow.
    permit.record_backend_outcome_holding(BackendAdmissionOutcome {
        response_status: 200,
        connection_error: false,
        error_class: None,
        backend_elapsed: Duration::from_millis(1),
    });

    let snapshot = limiter
        .snapshot(&proxy, None, AdaptiveConcurrencyKeyBy::Proxy)
        .expect("state should exist after acquire");
    assert_eq!(
        snapshot.limit, 1,
        "a held (long-lived session) success must not grow the limit"
    );
    assert_eq!(
        snapshot.samples, 1,
        "the handshake latency sample is still recorded"
    );

    drop(permit);
}
