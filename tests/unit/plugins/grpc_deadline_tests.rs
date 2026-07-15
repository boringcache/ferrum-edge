use ferrum_edge::plugins::{
    GRPC_ONLY_PROTOCOLS, Plugin, PluginResult, RequestContext, create_plugin,
    normalize_response_body_for_inspection, priority,
};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

use super::plugin_utils::{assert_continue, assert_reject, create_test_context};

#[test]
fn h3_grpc_web_requests_load_grpc_policy_plugins() {
    use ferrum_edge::_test_support::h3_plugin_protocol_for_request_for_test;
    use ferrum_edge::config::types::HttpFlavor;
    use ferrum_edge::plugins::ProxyProtocol;

    assert_eq!(
        h3_plugin_protocol_for_request_for_test(HttpFlavor::Plain, true),
        ProxyProtocol::Grpc
    );
    assert_eq!(
        h3_plugin_protocol_for_request_for_test(HttpFlavor::Plain, false),
        ProxyProtocol::Http
    );
}

#[tokio::test]
async fn streaming_grpc_web_deadline_emits_encoded_status_before_backend_data() {
    use bytes::Bytes;
    use ferrum_edge::_test_support::{
        GRPC_FRAME_TRAILER, parse_grpc_frames, proxy_body_streaming_for_test,
        proxy_body_with_client_grpc_deadline_for_test,
    };
    use ferrum_edge::proxy::body::ProxyBodyError;
    use futures_util::stream;
    use http_body::{Body, Frame};
    use http_body_util::{BodyExt, StreamBody};

    let inner = StreamBody::new(stream::pending::<Result<Frame<Bytes>, ProxyBodyError>>());
    let body = proxy_body_streaming_for_test(Box::pin(inner));
    let deadline = tokio::time::Instant::now()
        .checked_sub(std::time::Duration::from_secs(1))
        .expect("one second before now is representable");
    let mut body = proxy_body_with_client_grpc_deadline_for_test(
        body,
        deadline,
        Some("application/grpc-web+proto"),
    );

    let frame = body
        .frame()
        .await
        .expect("deadline must emit a terminal frame")
        .expect("terminal deadline frame must be readable");
    let data = frame
        .data_ref()
        .expect("gRPC-Web terminal status is encoded as DATA");
    let frames = parse_grpc_frames(data);
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].0, GRPC_FRAME_TRAILER);
    assert!(
        frames[0]
            .1
            .windows(b"grpc-status: 4".len())
            .any(|window| window == b"grpc-status: 4")
    );
    assert!(Body::is_end_stream(&body));
}

#[test]
fn buffered_h3_committed_deadline_preserves_binary_text_and_native_framing() {
    use base64::Engine as _;
    use ferrum_edge::_test_support::{
        GRPC_FRAME_TRAILER, h3_buffered_grpc_deadline_replacement_for_test, parse_grpc_frames,
    };

    for content_type in [
        "application/grpc-web+proto",
        "application/grpc-web-text+proto",
    ] {
        let response =
            h3_buffered_grpc_deadline_replacement_for_test(Some(content_type));
        assert_eq!(response.http_status, http::StatusCode::OK);
        assert_eq!(
            response.headers.get("content-type").map(String::as_str),
            Some(content_type)
        );
        assert_eq!(
            response.headers.get("x-grpc-web").map(String::as_str),
            Some("1")
        );
        assert!(response.headers.contains_key("access-control-expose-headers"));
        assert!(!response.headers.contains_key("grpc-status"));
        assert!(!response.headers.contains_key("grpc-message"));

        let decoded = if content_type.contains("-text") {
            base64::engine::general_purpose::STANDARD
                .decode(&response.body)
                .expect("text gRPC-Web deadline body must be valid base64")
        } else {
            response.body.clone()
        };
        let frames = parse_grpc_frames(&decoded);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].0, GRPC_FRAME_TRAILER);
        assert!(
            frames[0]
                .1
                .windows(b"grpc-status: 4".len())
                .any(|window| window == b"grpc-status: 4")
        );
        assert!(
            frames[0]
                .1
                .windows(b"grpc-message: Deadline exceeded at gateway".len())
                .any(|window| window == b"grpc-message: Deadline exceeded at gateway")
        );
        assert_eq!(response.grpc_status, Some(4));
        assert_eq!(
            response.grpc_message.as_deref(),
            Some("Deadline exceeded at gateway")
        );
    }

    let native = h3_buffered_grpc_deadline_replacement_for_test(None);
    assert_eq!(native.http_status, http::StatusCode::OK);
    assert_eq!(
        native.headers.get("content-type").map(String::as_str),
        Some("application/grpc")
    );
    assert_eq!(
        native.headers.get("grpc-status").map(String::as_str),
        Some("4")
    );
    assert_eq!(
        native.headers.get("grpc-message").map(String::as_str),
        Some("Deadline exceeded at gateway")
    );
    assert!(native.body.is_empty());
}

#[test]
fn retry_backoff_deadline_response_is_request_aware_for_grpc_web() {
    use base64::Engine as _;
    use ferrum_edge::_test_support::{
        GRPC_FRAME_TRAILER, client_grpc_deadline_response_for_request_for_test,
        parse_grpc_frames,
    };
    use ferrum_edge::retry::ErrorClass;

    for content_type in [
        "application/grpc-web+proto",
        "application/grpc-web-text+proto",
    ] {
        let response = client_grpc_deadline_response_for_request_for_test(content_type);
        assert_eq!(response.status_code, 200);
        assert!(!response.connection_error);
        assert_eq!(response.error_class, Some(ErrorClass::ClientDisconnect));
        assert_eq!(
            response.headers.get("content-type").map(String::as_str),
            Some(content_type)
        );
        assert!(!response.headers.contains_key("grpc-status"));

        let decoded = if content_type.contains("-text") {
            base64::engine::general_purpose::STANDARD
                .decode(&response.body)
                .expect("text gRPC-Web retry deadline body must be valid base64")
        } else {
            response.body
        };
        let frames = parse_grpc_frames(&decoded);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].0, GRPC_FRAME_TRAILER);
        assert!(
            frames[0]
                .1
                .windows(b"grpc-status: 4".len())
                .any(|window| window == b"grpc-status: 4")
        );
    }

    let native = client_grpc_deadline_response_for_request_for_test("application/grpc");
    assert_eq!(
        native.headers.get("content-type").map(String::as_str),
        Some("application/grpc")
    );
    assert_eq!(
        native.headers.get("grpc-status").map(String::as_str),
        Some("4")
    );
    assert!(native.body.is_empty());
    assert_eq!(native.error_class, Some(ErrorClass::ClientDisconnect));
}

#[test]
fn remaining_duration_rounds_up_to_the_next_wire_millisecond() {
    use ferrum_edge::_test_support::grpc_deadline_duration_millis_ceil_saturating_for_test;
    use std::time::Duration;

    assert_eq!(
        grpc_deadline_duration_millis_ceil_saturating_for_test(Duration::ZERO),
        None
    );
    assert_eq!(
        grpc_deadline_duration_millis_ceil_saturating_for_test(Duration::from_nanos(1)),
        Some(1)
    );
    assert_eq!(
        grpc_deadline_duration_millis_ceil_saturating_for_test(Duration::from_nanos(999_999)),
        Some(1)
    );
    assert_eq!(
        grpc_deadline_duration_millis_ceil_saturating_for_test(Duration::from_nanos(1_000_001)),
        Some(2)
    );
}

fn create_grpc_context_with_timeout(timeout: Option<&str>) -> ferrum_edge::plugins::RequestContext {
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.path = "/my.Service/MyMethod".to_string();
    ctx.headers
        .insert("content-type".to_string(), "application/grpc".to_string());
    if let Some(t) = timeout {
        ctx.headers
            .insert("grpc-timeout".to_string(), t.to_string());
    }
    ctx
}

struct StalledResponseNormalizer;

#[async_trait::async_trait]
impl Plugin for StalledResponseNormalizer {
    fn name(&self) -> &str {
        "stalled_response_normalizer"
    }

    async fn normalize_response_body_with_context(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        _body: &[u8],
        _content_type: Option<&str>,
        _response_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        std::future::pending().await
    }
}

#[tokio::test]
async fn response_normalizer_deadline_replaces_buffered_grpc_response() {
    let deadline_plugin = create_plugin("grpc_deadline", &json!({ "default_deadline_ms": 1 }))
        .unwrap()
        .unwrap();
    let plugins: Vec<Arc<dyn Plugin>> = vec![deadline_plugin, Arc::new(StalledResponseNormalizer)];
    let mut ctx = create_grpc_context_with_timeout(None);
    assert_continue(
        ferrum_edge::plugins::grpc_deadline::prepare_request_deadline(&plugins, &mut ctx),
    );
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    let mut headers = HashMap::from([
        ("content-type".to_string(), "application/json".to_string()),
        ("x-backend".to_string(), "discard-me".to_string()),
    ]);
    let mut body = b"backend response".to_vec();

    let normalized =
        normalize_response_body_for_inspection(&plugins, &mut ctx, 200, &mut headers, &mut body)
            .await;

    assert!(normalized);
    assert_eq!(headers.len(), 3);
    assert_eq!(headers.get("grpc-status").map(String::as_str), Some("4"));
    assert_eq!(
        headers.get("grpc-message").map(String::as_str),
        Some("Deadline exceeded at gateway")
    );
    assert!(body.is_empty());
    assert_eq!(
        ctx.metadata.get("grpc_status").map(String::as_str),
        Some("4")
    );
}

// ── Plugin creation ──

#[test]
fn test_plugin_creation() {
    let config = json!({
        "max_deadline_ms": 30000
    });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();
    assert_eq!(plugin.name(), "grpc_deadline");
    assert_eq!(plugin.priority(), priority::GRPC_DEADLINE);
}

#[test]
fn test_in_available_plugins() {
    let plugins = ferrum_edge::plugins::available_plugins();
    assert!(plugins.contains(&"grpc_deadline"));
}

#[test]
fn test_supported_protocols() {
    let config = json!({ "max_deadline_ms": 30000 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();
    assert_eq!(plugin.supported_protocols(), GRPC_ONLY_PROTOCOLS);
}

#[test]
fn test_modifies_request_headers() {
    let config = json!({ "max_deadline_ms": 30000 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();
    assert!(plugin.modifies_request_headers());
}

// ── Constructor validation ─────────────────────────────────────────

#[test]
fn test_non_object_config_rejected() {
    let err = create_plugin("grpc_deadline", &json!("bad"))
        .err()
        .expect("non-object config should be rejected");
    assert!(err.contains("config must be an object"), "got: {err}");
}

#[test]
fn test_empty_config_rejected() {
    // Plugin with no rules would be a no-op — must be rejected per CLAUDE.md
    let err = create_plugin("grpc_deadline", &json!({}))
        .err()
        .expect("empty config should be rejected");
    assert!(err.contains("no rules configured"), "got: {err}");
}

#[test]
fn test_invalid_field_types_rejected() {
    for (config, expected) in [
        (
            json!({ "max_deadline_ms": "30000" }),
            "'max_deadline_ms' must be an unsigned integer",
        ),
        (
            json!({ "default_deadline_ms": -1 }),
            "'default_deadline_ms' must be an unsigned integer",
        ),
        (
            json!({ "subtract_gateway_processing": "true" }),
            "'subtract_gateway_processing' must be a boolean",
        ),
        (
            json!({ "reject_no_deadline": 1 }),
            "'reject_no_deadline' must be a boolean",
        ),
    ] {
        let err = create_plugin("grpc_deadline", &config)
            .err()
            .expect("invalid field shape should be rejected");
        assert!(err.contains(expected), "expected {expected}, got: {err}");
    }
}

#[test]
fn test_unknown_and_null_fields_are_rejected() {
    for (config, expected) in [
        (
            json!({"max_deadline_ms": 30000, "reject_no_deadine": true}),
            "config.reject_no_deadine",
        ),
        (json!({"MAX_DEADLINE_MS": 30000}), "config.MAX_DEADLINE_MS"),
        (
            json!({"max_deadline_ms": null}),
            "must be an unsigned integer",
        ),
        (json!({"reject_no_deadline": null}), "must be a boolean"),
        (
            json!({"max_deadline_ms": 30000, "unexpected": {"nested": true}}),
            "config.unexpected",
        ),
    ] {
        let error = create_plugin("grpc_deadline", &config)
            .err()
            .expect("strict grpc_deadline config should reject the fixture");
        assert!(error.contains(expected), "expected {expected}, got {error}");
    }
}

#[test]
fn test_zero_max_deadline_rejected() {
    let err = create_plugin("grpc_deadline", &json!({ "max_deadline_ms": 0 }))
        .err()
        .expect("max_deadline_ms=0 should be rejected");
    assert!(err.contains("greater than zero"), "got: {err}");
}

#[test]
fn test_zero_default_deadline_rejected() {
    let err = create_plugin("grpc_deadline", &json!({ "default_deadline_ms": 0 }))
        .err()
        .expect("default_deadline_ms=0 should be rejected");
    assert!(err.contains("greater than zero"), "got: {err}");
}

#[test]
fn test_default_exceeds_max_rejected() {
    let err = create_plugin(
        "grpc_deadline",
        &json!({ "default_deadline_ms": 60000, "max_deadline_ms": 5000 }),
    )
    .err()
    .expect("default exceeding max should be rejected");
    assert!(err.contains("cannot exceed"), "got: {err}");
}

// Each of the four rule fields is a legitimate standalone config:
//   - `max_deadline_ms`: caps incoming deadlines
//   - `default_deadline_ms`: injects a deadline when missing
//   - `reject_no_deadline`: rejects missing-deadline requests
//   - `subtract_gateway_processing`: adjusts existing deadlines by gateway
//     processing time (useful for clients that already send `grpc-timeout`)
#[test]
fn test_subtract_gateway_processing_alone_accepted() {
    // Subtracting gateway processing from client-supplied deadlines is a
    // meaningful rule on its own for deployments where clients reliably send
    // grpc-timeout. Rejecting this config would disable a useful standalone
    // rule.
    let result = create_plugin(
        "grpc_deadline",
        &json!({ "subtract_gateway_processing": true }),
    );
    assert!(result.is_ok(), "subtract_gateway_processing alone is valid");
}

#[test]
fn test_subtract_gateway_processing_with_max_accepted() {
    let result = create_plugin(
        "grpc_deadline",
        &json!({
            "subtract_gateway_processing": true,
            "max_deadline_ms": 30000
        }),
    );
    assert!(result.is_ok());
}

#[test]
fn test_reject_no_deadline_alone_accepted() {
    let result = create_plugin("grpc_deadline", &json!({ "reject_no_deadline": true }));
    assert!(result.is_ok());
}

#[test]
fn test_false_only_rules_are_rejected_as_noop() {
    let error = create_plugin(
        "grpc_deadline",
        &json!({
            "subtract_gateway_processing": false,
            "reject_no_deadline": false
        }),
    )
    .err()
    .expect("false-only rules are a no-op");
    assert!(error.contains("no rules configured"), "got: {error}");
}

// ── grpc-timeout parsing ──

#[tokio::test]
async fn test_parse_hours() {
    let config = json!({ "max_deadline_ms": 999999999 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(Some("2H"));
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "2H".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    // 2 hours = 7,200,000 ms
    assert_eq!(
        ctx.metadata.get("grpc_original_deadline_ms").unwrap(),
        "7200000"
    );
    assert_eq!(headers.get("grpc-timeout").unwrap(), "7200000m");
}

#[tokio::test]
async fn test_parse_minutes() {
    let config = json!({ "max_deadline_ms": 999999999 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(Some("5M"));
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "5M".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    assert_eq!(
        ctx.metadata.get("grpc_original_deadline_ms").unwrap(),
        "300000"
    );
}

#[tokio::test]
async fn test_parse_seconds() {
    let config = json!({ "max_deadline_ms": 999999999 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(Some("30S"));
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "30S".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    assert_eq!(
        ctx.metadata.get("grpc_original_deadline_ms").unwrap(),
        "30000"
    );
}

#[tokio::test]
async fn test_parse_milliseconds() {
    let config = json!({ "max_deadline_ms": 999999999 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(Some("5000m"));
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "5000m".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    assert_eq!(
        ctx.metadata.get("grpc_original_deadline_ms").unwrap(),
        "5000"
    );
    assert_eq!(headers.get("grpc-timeout").unwrap(), "5000m");
}

#[tokio::test]
async fn test_parse_microseconds() {
    let config = json!({ "max_deadline_ms": 999999999 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(Some("5000000u"));
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "5000000u".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    // 5,000,000 us = 5,000 ms
    assert_eq!(
        ctx.metadata.get("grpc_original_deadline_ms").unwrap(),
        "5000"
    );
}

#[tokio::test]
async fn test_parse_nanoseconds() {
    let config = json!({ "max_deadline_ms": 999999999 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(Some("10000000n"));
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "10000000n".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    // 10,000,000 ns = 10 ms
    assert_eq!(ctx.metadata.get("grpc_original_deadline_ms").unwrap(), "10");
}

#[tokio::test]
async fn test_zero_timeouts_are_missing_and_positive_submillisecond_rounds_up() {
    let plugin = create_plugin("grpc_deadline", &json!({"reject_no_deadline": true}))
        .unwrap()
        .unwrap();

    for timeout in ["0H", "0M", "0S", "0m", "0u", "0n"] {
        let mut ctx = create_grpc_context_with_timeout(Some(timeout));
        let mut headers = HashMap::from([("grpc-timeout".to_string(), timeout.to_string())]);
        assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
    }

    for timeout in ["1u", "1n"] {
        let mut ctx = create_grpc_context_with_timeout(Some(timeout));
        let mut headers = HashMap::from([("grpc-timeout".to_string(), timeout.to_string())]);
        assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
        assert_eq!(headers.get("grpc-timeout").unwrap(), "1m");
        assert_eq!(ctx.metadata.get("grpc_original_deadline_ms").unwrap(), "1");
    }
}

#[tokio::test]
async fn test_timeout_header_matching_is_case_insensitive_and_rewrites_canonically() {
    let plugin = create_plugin("grpc_deadline", &json!({"max_deadline_ms": 5000}))
        .unwrap()
        .unwrap();
    let mut ctx = create_test_context();
    let mut headers = HashMap::from([("Grpc-Timeout".to_string(), "10S".to_string())]);

    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(
        headers.get("grpc-timeout").map(String::as_str),
        Some("5000m")
    );
    assert_eq!(
        headers
            .keys()
            .filter(|name| name.eq_ignore_ascii_case("grpc-timeout"))
            .count(),
        1
    );
}

#[tokio::test]
async fn test_multiple_instances_share_one_absolute_deadline() {
    let first = create_plugin(
        "grpc_deadline",
        &json!({"subtract_gateway_processing": true}),
    )
    .unwrap()
    .unwrap();
    let second = create_plugin("grpc_deadline", &json!({"max_deadline_ms": 10000}))
        .unwrap()
        .unwrap();
    let plugins = vec![first, second];
    let mut ctx = create_grpc_context_with_timeout(Some("10S"));
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    assert_continue(
        ferrum_edge::plugins::grpc_deadline::prepare_request_deadline(&plugins, &mut ctx),
    );
    let absolute = ctx
        .grpc_deadline_at()
        .expect("valid timeout establishes an absolute deadline");
    let mut headers = HashMap::from([("grpc-timeout".to_string(), "10S".to_string())]);
    assert_continue(plugins[0].before_proxy(&mut ctx, &mut headers).await);
    let first_forwarded: u64 = headers["grpc-timeout"]
        .strip_suffix('m')
        .expect("millisecond timeout")
        .parse()
        .expect("numeric timeout");
    assert_continue(plugins[1].before_proxy(&mut ctx, &mut headers).await);
    let second_forwarded: u64 = headers["grpc-timeout"]
        .strip_suffix('m')
        .expect("millisecond timeout")
        .parse()
        .expect("numeric timeout");

    assert_eq!(ctx.grpc_deadline_at(), Some(absolute));
    assert!((5_000..=10_000).contains(&first_forwarded));
    assert!(
        second_forwarded <= first_forwarded && first_forwarded - second_forwarded <= 50,
        "a later instance may observe clock progress but must not deduct the original pre-plugin delay again: first={first_forwarded}, second={second_forwarded}"
    );
}

#[tokio::test]
async fn test_preflight_deadline_cancels_request_plugin_work_with_status_four() {
    let plugin = create_plugin("grpc_deadline", &json!({"default_deadline_ms": 1}))
        .unwrap()
        .unwrap();
    let plugins = vec![plugin];
    let mut ctx = create_grpc_context_with_timeout(None);
    assert_continue(
        ferrum_edge::plugins::grpc_deadline::prepare_request_deadline(&plugins, &mut ctx),
    );
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    let result = ferrum_edge::plugins::await_request_plugin_deadline(
        ctx.grpc_deadline_at(),
        std::future::pending(),
    )
    .await;
    match result {
        PluginResult::Reject {
            status_code,
            headers,
            ..
        } => {
            assert_eq!(status_code, 200);
            assert_eq!(headers.get("grpc-status").map(String::as_str), Some("4"));
        }
        other => panic!("expired preflight must cancel plugin work: {other:?}"),
    }
}

// ── Default deadline injection ──

#[tokio::test]
async fn test_default_deadline_injected_when_missing() {
    let config = json!({ "default_deadline_ms": 5000 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(None);
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    assert_eq!(headers.get("grpc-timeout").unwrap(), "5000m");
    assert_eq!(
        ctx.metadata.get("grpc_adjusted_deadline_ms").unwrap(),
        "5000"
    );
}

#[tokio::test]
async fn test_default_deadline_not_used_when_present() {
    let config = json!({
        "default_deadline_ms": 5000,
        "max_deadline_ms": 999999999
    });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(Some("10000m"));
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "10000m".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    // Should use the client's timeout, not the default
    assert_eq!(
        ctx.metadata.get("grpc_adjusted_deadline_ms").unwrap(),
        "10000"
    );
}

// ── Max deadline capping ──

#[tokio::test]
async fn test_max_deadline_caps_high_timeout() {
    let config = json!({ "max_deadline_ms": 30000 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(Some("60S")); // 60,000 ms
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "60S".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    // Should be capped to 30,000 ms
    assert_eq!(
        ctx.metadata.get("grpc_adjusted_deadline_ms").unwrap(),
        "30000"
    );
    assert_eq!(headers.get("grpc-timeout").unwrap(), "30000m");
}

#[tokio::test]
async fn test_max_deadline_does_not_increase_low_timeout() {
    let config = json!({ "max_deadline_ms": 30000 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(Some("5000m")); // 5,000 ms
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "5000m".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    // Should stay at 5,000 ms (under the cap)
    assert_eq!(
        ctx.metadata.get("grpc_adjusted_deadline_ms").unwrap(),
        "5000"
    );
}

// ── reject_no_deadline ──

#[tokio::test]
async fn test_reject_no_deadline_rejects_missing() {
    let config = json!({ "reject_no_deadline": true });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(None);
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

#[tokio::test]
async fn test_reject_no_deadline_allows_present() {
    let config = json!({
        "reject_no_deadline": true,
        "max_deadline_ms": 999999999
    });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(Some("5000m"));
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "5000m".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

// ── subtract_gateway_processing ──

#[tokio::test]
async fn test_subtract_gateway_processing() {
    let config = json!({
        "default_deadline_ms": 60000,
        "subtract_gateway_processing": true
    });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(None);
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    // The adjusted deadline should be <= default_deadline_ms (some processing time subtracted)
    let adjusted: u64 = ctx
        .metadata
        .get("grpc_adjusted_deadline_ms")
        .unwrap()
        .parse()
        .unwrap();
    assert!(adjusted <= 60000);
    assert!(adjusted > 0);
}

#[tokio::test]
async fn test_subtract_gateway_processing_deadline_exceeded() {
    let config = json!({
        "default_deadline_ms": 1,
        "subtract_gateway_processing": true
    });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(None);
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;

    // The 1ms receipt-anchored deadline elapsed before the hook ran.
    match result {
        PluginResult::Reject {
            status_code,
            headers,
            ..
        } => {
            assert_eq!(status_code, 200); // gRPC trailers-only response
            assert_eq!(headers.get("grpc-status").unwrap(), "4"); // DEADLINE_EXCEEDED
            assert!(headers.contains_key("grpc-message"));
        }
        _ => panic!("Expected Reject with DEADLINE_EXCEEDED"),
    }
}

// ── Combined config ──

#[tokio::test]
async fn test_combined_default_and_max() {
    // default == max: default applies, no cap needed
    let config = json!({
        "default_deadline_ms": 30000,
        "max_deadline_ms": 30000
    });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    // No timeout provided: default (30000) gets used; cap is identical so no change
    let mut ctx = create_grpc_context_with_timeout(None);
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    assert_eq!(
        ctx.metadata.get("grpc_adjusted_deadline_ms").unwrap(),
        "30000"
    );

    // A larger client-supplied timeout still gets capped
    let mut ctx2 = create_grpc_context_with_timeout(Some("60S"));
    let mut headers2 = HashMap::new();
    headers2.insert("grpc-timeout".to_string(), "60S".to_string());
    plugin.before_proxy(&mut ctx2, &mut headers2).await;
    assert_eq!(
        ctx2.metadata.get("grpc_adjusted_deadline_ms").unwrap(),
        "30000"
    );
}

// ── Empty config passes through ──

#[tokio::test]
async fn test_minimal_config_passes_through() {
    // With max_deadline_ms set, but client timeout below cap, the value passes through.
    let config = json!({ "max_deadline_ms": 999_999_999 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(Some("5000m"));
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "5000m".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    // Should still set the header (pass through the parsed value)
    assert_eq!(headers.get("grpc-timeout").unwrap(), "5000m");
}

#[tokio::test]
async fn test_modified_timeout_header_takes_precedence_over_original_request() {
    let config = json!({ "max_deadline_ms": 999999999 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(Some("60S"));
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "60S".to_string());
    headers.insert("grpc-timeout".to_string(), "5000m".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    assert_eq!(
        ctx.metadata.get("grpc_original_deadline_ms").unwrap(),
        "5000"
    );
    assert_eq!(headers.get("grpc-timeout").unwrap(), "5000m");
}

#[tokio::test]
async fn test_minimal_config_no_timeout_passes() {
    // With only max_deadline_ms, a request with no timeout passes through unchanged
    // (no default to inject, no rejection rule).
    let config = json!({ "max_deadline_ms": 30_000 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(None);
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    // No timeout to set
    assert!(!headers.contains_key("grpc-timeout"));
}

// ── Invalid timeout header ──

#[tokio::test]
async fn test_invalid_timeout_treated_as_missing() {
    let config = json!({ "default_deadline_ms": 5000 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(Some("invalid"));
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "invalid".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    // Should fall back to default
    assert_eq!(
        ctx.metadata.get("grpc_adjusted_deadline_ms").unwrap(),
        "5000"
    );
}

// ── Rejection body format ──

#[tokio::test]
async fn test_reject_no_deadline_body_format() {
    let config = json!({ "reject_no_deadline": true });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(None);
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;

    match result {
        PluginResult::Reject {
            status_code,
            body,
            headers,
        } => {
            assert_eq!(status_code, 400);
            let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert!(parsed.get("error").is_some());
            assert_eq!(headers.get("content-type").unwrap(), "application/grpc");
        }
        _ => panic!("Expected Reject"),
    }
}

// ── reject_no_deadline takes precedence over default_deadline_ms ──

#[tokio::test]
async fn test_reject_no_deadline_wins_over_default() {
    let config = json!({
        "reject_no_deadline": true,
        "default_deadline_ms": 5000
    });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(None);
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;

    // Should reject despite default being configured — reject_no_deadline takes precedence
    assert_reject(result, Some(400));
}

// ── Empty string timeout ──

#[tokio::test]
async fn test_empty_string_timeout_treated_as_missing() {
    let config = json!({ "default_deadline_ms": 3000 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(Some(""));
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    // Empty string can't be parsed, falls back to default
    assert_eq!(
        ctx.metadata.get("grpc_adjusted_deadline_ms").unwrap(),
        "3000"
    );
}

// ── Very large timeout values (overflow protection) ──

#[tokio::test]
async fn test_more_than_eight_timeout_digits_is_ignored_without_default() {
    let config = json!({ "max_deadline_ms": 999999999 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(Some("999999999H"));
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "999999999H".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    assert!(!ctx.metadata.contains_key("grpc_original_deadline_ms"));
    assert!(!ctx.metadata.contains_key("grpc_adjusted_deadline_ms"));
    assert_eq!(headers.get("grpc-timeout").unwrap(), "999999999H");
}

// ── subtract_gateway_processing + max_deadline_ms combined ──

#[tokio::test]
async fn test_subtract_after_max_cap() {
    let config = json!({
        "max_deadline_ms": 5000,
        "subtract_gateway_processing": true
    });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    // Client sends 60s, capped to 5s, then processing time subtracted
    let mut ctx = create_grpc_context_with_timeout(Some("60S"));
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "60S".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    let adjusted: u64 = ctx
        .metadata
        .get("grpc_adjusted_deadline_ms")
        .unwrap()
        .parse()
        .unwrap();
    // Should be capped to 5000 then subtracted — must be <= 5000
    assert!(adjusted <= 5000);
    assert!(adjusted > 0);
}

// ── Single-character unit only (no multi-char units) ──

#[tokio::test]
async fn test_multi_char_unit_rejected() {
    let config = json!({ "default_deadline_ms": 1000 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    // "ms" is not a valid gRPC timeout unit — only single-char units
    let mut ctx = create_grpc_context_with_timeout(Some("5000ms"));
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "5000ms".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    // "5000ms" fails to parse (last char 's', digits "5000m" fails u64 parse)
    // Falls back to default
    assert_eq!(
        ctx.metadata.get("grpc_adjusted_deadline_ms").unwrap(),
        "1000"
    );
}

// ── Robustness against malformed inputs ──

#[tokio::test]
async fn test_non_ascii_timeout_does_not_panic() {
    // Previously the parser used str::split_at(len-1) which panics on a
    // non-char-boundary. Multi-byte UTF-8 in the timeout must be rejected
    // (treated as missing) rather than crashing the worker.
    let config = json!({ "default_deadline_ms": 1000 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(Some("5η"));
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "5η".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    // Malformed value falls back to default
    assert_eq!(
        ctx.metadata.get("grpc_adjusted_deadline_ms").unwrap(),
        "1000"
    );
}

#[tokio::test]
async fn test_non_digit_value_treated_as_missing() {
    let config = json!({ "default_deadline_ms": 2000 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(Some("abcS"));
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "abcS".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    assert_eq!(
        ctx.metadata.get("grpc_adjusted_deadline_ms").unwrap(),
        "2000"
    );
}

// ── Metadata tracking ──

#[tokio::test]
async fn test_original_and_adjusted_metadata() {
    let config = json!({ "max_deadline_ms": 10000 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(Some("30S")); // 30,000 ms
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "30S".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    assert_eq!(
        ctx.metadata.get("grpc_original_deadline_ms").unwrap(),
        "30000"
    );
    assert_eq!(
        ctx.metadata.get("grpc_adjusted_deadline_ms").unwrap(),
        "10000"
    );
}
