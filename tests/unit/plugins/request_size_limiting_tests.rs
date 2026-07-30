//! Tests for request_size_limiting plugin

use ferrum_edge::plugins::request_size_limiting::RequestSizeLimiting;
use ferrum_edge::plugins::{HTTP_GRPC_PROTOCOLS, Plugin, PluginResult, RequestContext, priority};
use serde_json::json;
use std::collections::HashMap;

fn make_ctx(method: &str, path: &str) -> RequestContext {
    RequestContext::new(
        "127.0.0.1".to_string(),
        method.to_string(),
        path.to_string(),
    )
}

// === Plugin creation ===

#[tokio::test]
async fn test_creation_defaults() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    assert_eq!(plugin.name(), "request_size_limiting");
    assert_eq!(plugin.priority(), priority::REQUEST_SIZE_LIMITING);
    assert_eq!(plugin.supported_protocols(), HTTP_GRPC_PROTOCOLS);
    assert!(!plugin.is_auth_plugin());
    assert!(!plugin.modifies_request_headers());
    assert!(!plugin.modifies_request_body());
    assert!(!plugin.requires_request_body_buffering());
    assert!(!plugin.requires_response_body_buffering());
}

#[tokio::test]
async fn test_zero_max_bytes_returns_error() {
    // Empty config defaults max_bytes to 0, which is now rejected at construction time
    let result = RequestSizeLimiting::new(&json!({}));
    assert!(
        result.is_err(),
        "Expected error when max_bytes is zero/missing"
    );
}

#[test]
fn test_non_object_config_returns_error() {
    let result = RequestSizeLimiting::new(&json!("bad"));
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("config must be an object"));
}

#[test]
fn test_invalid_max_bytes_type_returns_error() {
    let result = RequestSizeLimiting::new(&json!({"max_bytes": "1024"}));
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("max_bytes"));
}

// === Content-Length fast path ===

#[tokio::test]
async fn test_content_length_under_limit_passes() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let mut ctx = make_ctx("POST", "/api");
    ctx.headers
        .insert("content-length".to_string(), "512".to_string());

    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_content_length_at_limit_passes() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let mut ctx = make_ctx("POST", "/api");
    ctx.headers
        .insert("content-length".to_string(), "1024".to_string());

    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_content_length_over_limit_rejects_413() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let mut ctx = make_ctx("POST", "/api");
    ctx.headers
        .insert("content-length".to_string(), "1025".to_string());

    match plugin.on_request_received(&mut ctx).await {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 413);
            assert!(body.contains("Request body too large"));
            assert!(body.contains("1024"));
        }
        _ => panic!("Expected Reject"),
    }
}

#[tokio::test]
async fn test_no_content_length_header_passes() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let mut ctx = make_ctx("POST", "/api");
    // No content-length header

    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_invalid_content_length_header_fails_closed() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let mut ctx = make_ctx("POST", "/api");
    ctx.headers
        .insert("content-length".to_string(), "not-a-number".to_string());

    match plugin.on_request_received(&mut ctx).await {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 400),
        other => panic!("Expected 400 Reject, got {other:?}"),
    }
}

#[tokio::test]
async fn test_large_content_length_rejects() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 1048576})).unwrap(); // 1 MiB
    let mut ctx = make_ctx("PUT", "/upload");
    ctx.headers
        .insert("content-length".to_string(), "10485760".to_string()); // 10 MiB

    match plugin.on_request_received(&mut ctx).await {
        PluginResult::Reject { status_code, .. } => {
            assert_eq!(status_code, 413);
        }
        _ => panic!("Expected Reject"),
    }
}

// === Buffered body check in before_proxy ===

#[tokio::test]
async fn test_buffered_body_under_limit_passes() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 100})).unwrap();
    let mut ctx = make_ctx("POST", "/api");
    ctx.metadata
        .insert("request_body".to_string(), "short body".to_string());

    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_buffered_body_over_limit_rejects() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 10})).unwrap();
    let mut ctx = make_ctx("POST", "/api");
    ctx.metadata.insert(
        "request_body".to_string(),
        "this body is definitely longer than 10 bytes".to_string(),
    );

    let mut headers = HashMap::new();
    match plugin.before_proxy(&mut ctx, &mut headers).await {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 413);
            assert!(body.contains("Request body too large"));
        }
        _ => panic!("Expected Reject"),
    }
}

#[tokio::test]
async fn test_buffered_binary_body_size_metadata_over_limit_rejects() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 10})).unwrap();
    let mut ctx = make_ctx("POST", "/api");
    ctx.metadata
        .insert("request_body_size_bytes".to_string(), "11".to_string());

    let mut headers = HashMap::new();
    match plugin.before_proxy(&mut ctx, &mut headers).await {
        PluginResult::Reject { status_code, .. } => {
            assert_eq!(status_code, 413);
        }
        _ => panic!("Expected Reject"),
    }
}

#[tokio::test]
async fn test_no_buffered_body_passes() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 10})).unwrap();
    let mut ctx = make_ctx("POST", "/api");
    // No request_body in metadata

    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_final_request_body_under_limit_passes() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 10})).unwrap();
    let headers = HashMap::new();

    let result = plugin.on_final_request_body(&headers, b"1234567890").await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_final_request_body_over_limit_rejects() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 10})).unwrap();
    let headers = HashMap::new();

    match plugin.on_final_request_body(&headers, b"12345678901").await {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 413);
            assert!(body.contains("Request body too large"));
        }
        _ => panic!("Expected Reject"),
    }
}

// === Protocol support ===

#[tokio::test]
async fn test_supports_http_and_grpc() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let protocols = plugin.supported_protocols();
    assert!(protocols.contains(&ferrum_edge::plugins::ProxyProtocol::Http));
    assert!(protocols.contains(&ferrum_edge::plugins::ProxyProtocol::Grpc));
    assert!(!protocols.contains(&ferrum_edge::plugins::ProxyProtocol::WebSocket));
}

// === GET requests with Content-Length (unusual but valid) ===

#[tokio::test]
async fn test_get_request_with_oversized_content_length_rejects() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 100})).unwrap();
    let mut ctx = make_ctx("GET", "/api");
    ctx.headers
        .insert("content-length".to_string(), "200".to_string());

    match plugin.on_request_received(&mut ctx).await {
        PluginResult::Reject { status_code, .. } => {
            assert_eq!(status_code, 413);
        }
        _ => panic!("Expected Reject"),
    }
}

// === Response body JSON format ===

#[tokio::test]
async fn test_rejection_body_is_valid_json() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 10})).unwrap();
    let mut ctx = make_ctx("POST", "/api");
    ctx.headers
        .insert("content-length".to_string(), "100".to_string());

    match plugin.on_request_received(&mut ctx).await {
        PluginResult::Reject { body, .. } => {
            let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(parsed["error"], "Request body too large");
            assert_eq!(parsed["limit"], 10);
        }
        _ => panic!("Expected Reject"),
    }
}

// === Route ceiling publication (GHSA-xrfj-852f-645j) ===

/// The plugin must publish its ceiling to the proxy core, otherwise an
/// unbuffered H1/H2, H3, or streaming-gRPC upload is only bounded by the
/// generally larger global limit — and by nothing at all when the global limit
/// is disabled. The hooks below can only see a declared `Content-Length` or a
/// body some *other* plugin happened to buffer.
#[test]
fn enforced_request_body_limit_publishes_the_configured_ceiling() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    assert_eq!(plugin.enforced_request_body_limit(), Some(1024));
    // It is a request-side policy only.
    assert_eq!(plugin.enforced_response_body_limit(), None);
}

/// Publication must not silently force body buffering: the ceiling is enforced
/// by the streaming adapters, so a streaming upload stays streaming.
#[test]
fn publishing_a_ceiling_does_not_force_request_body_buffering() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    assert!(!plugin.requires_request_body_buffering());
}

// === Repeated / ambiguous Content-Length (GHSA-xrfj-852f-645j) ===

/// A standards-valid repeated identical `Content-Length` arrives comma-folded in
/// the plugin-facing header map. Parsing the whole folded list as one integer
/// used to fail, which read as "no declared length" and skipped this reject.
#[tokio::test]
async fn test_repeated_identical_content_length_over_limit_rejects_413() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let mut ctx = make_ctx("POST", "/api");
    ctx.headers
        .insert("content-length".to_string(), "2048, 2048".to_string());

    match plugin.on_request_received(&mut ctx).await {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 413),
        other => panic!("Expected 413 Reject, got {other:?}"),
    }
}

/// Exact boundary still passes when every folded member agrees.
#[tokio::test]
async fn test_repeated_identical_content_length_at_boundary_passes() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let mut ctx = make_ctx("POST", "/api");
    ctx.headers
        .insert("content-length".to_string(), "1024, 1024".to_string());

    assert!(matches!(
        plugin.on_request_received(&mut ctx).await,
        PluginResult::Continue
    ));
}

/// A declared length the gateway cannot reduce to one value fails closed: it is
/// refused as a bad request rather than forwarded as "unknown length".
#[tokio::test]
async fn test_ambiguous_content_length_fails_closed_with_400() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    for value in ["2048, 4096", "+2048", "2048,,2048"] {
        let mut ctx = make_ctx("POST", "/api");
        ctx.headers
            .insert("content-length".to_string(), value.to_string());

        match plugin.on_request_received(&mut ctx).await {
            PluginResult::Reject {
                status_code, body, ..
            } => {
                assert_eq!(status_code, 400, "{value:?} must fail closed");
                let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
                assert_eq!(parsed["error"], "Request Content-Length is ambiguous");
            }
            other => panic!("Expected 400 Reject for {value:?}, got {other:?}"),
        }
    }
}

/// A chunked / unknown-length upload has no declared length: the fast path must
/// stay quiet and leave enforcement to the streaming adapter.
#[tokio::test]
async fn test_unknown_length_request_passes_the_header_fast_path() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let mut ctx = make_ctx("POST", "/api");
    ctx.headers
        .insert("transfer-encoding".to_string(), "chunked".to_string());

    assert!(matches!(
        plugin.on_request_received(&mut ctx).await,
        PluginResult::Continue
    ));
}

/// Post-transform enforcement is preserved: a body that expands past the
/// ceiling after request transforms is still refused.
#[tokio::test]
async fn test_final_request_body_over_limit_still_rejects_after_transforms() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 8})).unwrap();
    let headers = HashMap::new();

    assert!(matches!(
        plugin.on_final_request_body(&headers, b"12345678").await,
        PluginResult::Continue
    ));
    match plugin.on_final_request_body(&headers, b"123456789").await {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 413),
        other => panic!("Expected 413 Reject, got {other:?}"),
    }
}
