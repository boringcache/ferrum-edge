//! Tests for the CORS plugin

use ferrum_edge::plugins::cors::CorsPlugin;
use ferrum_edge::plugins::{HTTP_GRPC_PROTOCOLS, Plugin, PluginResult, RequestContext, priority};
use serde_json::json;
use std::collections::HashMap;

fn make_ctx() -> RequestContext {
    RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/test".to_string(),
    )
}

fn make_preflight_ctx(origin: &str, method: &str) -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "OPTIONS".to_string(),
        "/test".to_string(),
    );
    ctx.headers.insert("origin".to_string(), origin.to_string());
    ctx.headers.insert(
        "access-control-request-method".to_string(),
        method.to_string(),
    );
    ctx
}

fn make_cors_ctx(method: &str, origin: &str) -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        method.to_string(),
        "/test".to_string(),
    );
    ctx.headers.insert("origin".to_string(), origin.to_string());
    ctx
}

// ── Config parsing ───────────────────────────────────────────────────

#[tokio::test]
async fn test_cors_plugin_creation_defaults() {
    let plugin = CorsPlugin::new(&json!({})).unwrap();
    assert_eq!(plugin.name(), "cors");
    assert_eq!(plugin.priority(), priority::CORS);
    assert_eq!(plugin.priority(), 100);
    assert_eq!(plugin.supported_protocols(), HTTP_GRPC_PROTOCOLS);
    assert!(!plugin.modifies_request_headers());
    assert!(plugin.applies_after_proxy_on_reject());
    assert!(!plugin.is_auth_plugin());
}

#[test]
fn test_constructor_rejects_non_array_allowed_origins() {
    let err = CorsPlugin::new(&json!({
        "allowed_origins": "https://example.com"
    }))
    .err()
    .expect("allowed_origins must reject non-array values");

    assert!(err.contains("allowed_origins"), "got: {err}");
}

#[test]
fn test_constructor_rejects_empty_allowed_origins() {
    let err = CorsPlugin::new(&json!({
        "allowed_origins": []
    }))
    .err()
    .expect("empty allowed_origins must be rejected");

    assert!(err.contains("at least one origin"), "got: {err}");
}

#[test]
fn test_constructor_rejects_non_string_origin_entry() {
    let err = CorsPlugin::new(&json!({
        "allowed_origins": [42]
    }))
    .err()
    .expect("non-string origin entries must be rejected");

    assert!(err.contains("entries must be strings"), "got: {err}");
}

#[test]
fn test_constructor_rejects_malformed_exact_origin() {
    let err = CorsPlugin::new(&json!({
        "allowed_origins": ["example.com"]
    }))
    .err()
    .expect("exact origins without scheme must be rejected");

    assert!(err.contains("invalid origin"), "got: {err}");
}

#[test]
fn test_constructor_rejects_exact_origin_with_empty_authority() {
    let err = CorsPlugin::new(&json!({
        "allowed_origins": ["https:///example.com"]
    }))
    .err()
    .expect("empty authority exact origin must be rejected");

    assert!(err.contains("hostname"), "got: {err}");
}

#[test]
fn test_constructor_rejects_exact_origin_with_path() {
    let err = CorsPlugin::new(&json!({
        "allowed_origins": ["https://example.com/api"]
    }))
    .err()
    .expect("origins with path must be rejected");

    assert!(err.contains("without path"), "got: {err}");
}

#[test]
fn test_constructor_rejects_malformed_wildcard_origin() {
    let err = CorsPlugin::new(&json!({
        "allowed_origins": ["*example.com"]
    }))
    .err()
    .expect("wildcard origins without dot must be rejected");

    assert!(err.contains("*.example.com"), "got: {err}");
}

#[test]
fn test_constructor_rejects_invalid_method() {
    let err = CorsPlugin::new(&json!({
        "allowed_methods": ["GET", "BAD METHOD"]
    }))
    .err()
    .expect("invalid method tokens must be rejected");

    assert!(err.contains("invalid HTTP method"), "got: {err}");
}

#[test]
fn test_constructor_rejects_empty_allowed_methods() {
    let err = CorsPlugin::new(&json!({
        "allowed_methods": []
    }))
    .err()
    .expect("empty allowed_methods must be rejected");

    assert!(err.contains("allowed_methods"), "got: {err}");
}

#[test]
fn test_constructor_rejects_invalid_header_name() {
    let err = CorsPlugin::new(&json!({
        "allowed_headers": ["Content-Type", "Bad Header"]
    }))
    .err()
    .expect("invalid allowed header names must be rejected");

    assert!(err.contains("invalid HTTP header name"), "got: {err}");
}

#[test]
fn test_constructor_rejects_non_bool_allow_credentials() {
    let err = CorsPlugin::new(&json!({
        "allow_credentials": "true"
    }))
    .err()
    .expect("non-bool allow_credentials must be rejected");

    assert!(err.contains("allow_credentials"), "got: {err}");
}

#[test]
fn test_constructor_rejects_non_integer_max_age() {
    let err = CorsPlugin::new(&json!({
        "max_age": -1
    }))
    .err()
    .expect("negative max_age must be rejected");

    assert!(err.contains("max_age"), "got: {err}");
}

#[tokio::test]
async fn test_cors_plugin_credentials_wildcard_conflict() {
    // allow_credentials with wildcard origins should disable credentials
    let plugin = CorsPlugin::new(&json!({
        "allow_credentials": true
    }))
    .unwrap();

    // Verify via preflight: should NOT include access-control-allow-credentials
    let mut ctx = make_preflight_ctx("https://example.com", "GET");
    let result = plugin.on_request_received(&mut ctx).await;
    match result {
        PluginResult::Reject { headers, .. } => {
            assert!(!headers.contains_key("access-control-allow-credentials"));
            assert_eq!(
                headers.get("access-control-allow-origin").unwrap(),
                "*",
                "Should use wildcard since credentials was forced off"
            );
        }
        _ => panic!("Expected Reject for preflight"),
    }
}

#[tokio::test]
async fn test_cors_plugin_credentials_with_specific_origins() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["https://app.example.com"],
        "allow_credentials": true
    }))
    .unwrap();

    let mut ctx = make_preflight_ctx("https://app.example.com", "GET");
    let result = plugin.on_request_received(&mut ctx).await;
    match result {
        PluginResult::Reject { headers, .. } => {
            assert_eq!(
                headers.get("access-control-allow-credentials").unwrap(),
                "true"
            );
            assert_eq!(
                headers.get("access-control-allow-origin").unwrap(),
                "https://app.example.com"
            );
        }
        _ => panic!("Expected Reject for preflight"),
    }
}

// ── Preflight tests (on_request_received) ────────────────────────────

#[tokio::test]
async fn test_preflight_with_allowed_origin() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["https://example.com"]
    }))
    .unwrap();

    let mut ctx = make_preflight_ctx("https://example.com", "GET");
    let result = plugin.on_request_received(&mut ctx).await;
    match result {
        PluginResult::Reject {
            status_code,
            body,
            headers,
        } => {
            assert_eq!(status_code, 204);
            assert!(body.is_empty());
            assert_eq!(
                headers.get("access-control-allow-origin").unwrap(),
                "https://example.com"
            );
        }
        _ => panic!("Expected Reject for preflight"),
    }
}

#[tokio::test]
async fn test_preflight_with_disallowed_origin() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["https://example.com"]
    }))
    .unwrap();

    let mut ctx = make_preflight_ctx("https://evil.com", "GET");
    let result = plugin.on_request_received(&mut ctx).await;
    match result {
        PluginResult::Reject {
            status_code,
            body,
            headers,
        } => {
            assert_eq!(status_code, 403);
            assert_eq!(body, "CORS origin not allowed");
            // No CORS headers should be present for disallowed origin
            assert!(!headers.contains_key("access-control-allow-origin"));
        }
        _ => panic!("Expected Reject for preflight"),
    }
}

#[tokio::test]
async fn test_preflight_with_wildcard_origins() {
    let plugin = CorsPlugin::new(&json!({})).unwrap();

    let mut ctx = make_preflight_ctx("https://anything.example.com", "POST");
    let result = plugin.on_request_received(&mut ctx).await;
    match result {
        PluginResult::Reject { headers, .. } => {
            assert_eq!(headers.get("access-control-allow-origin").unwrap(), "*");
        }
        _ => panic!("Expected Reject for preflight"),
    }
}

#[tokio::test]
async fn test_preflight_includes_methods_and_headers() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_methods": ["GET", "POST"],
        "allowed_headers": ["Authorization", "Content-Type"]
    }))
    .unwrap();

    let mut ctx = make_preflight_ctx("https://example.com", "GET");
    let result = plugin.on_request_received(&mut ctx).await;
    match result {
        PluginResult::Reject { headers, .. } => {
            assert_eq!(
                headers.get("access-control-allow-methods").unwrap(),
                "GET, POST"
            );
            assert_eq!(
                headers.get("access-control-allow-headers").unwrap(),
                "Authorization, Content-Type"
            );
        }
        _ => panic!("Expected Reject for preflight"),
    }
}

#[tokio::test]
async fn test_preflight_includes_max_age() {
    let plugin = CorsPlugin::new(&json!({
        "max_age": 3600
    }))
    .unwrap();

    let mut ctx = make_preflight_ctx("https://example.com", "GET");
    let result = plugin.on_request_received(&mut ctx).await;
    match result {
        PluginResult::Reject { headers, .. } => {
            assert_eq!(headers.get("access-control-max-age").unwrap(), "3600");
        }
        _ => panic!("Expected Reject for preflight"),
    }
}

#[tokio::test]
async fn test_preflight_continue_passes_through() {
    let plugin = CorsPlugin::new(&json!({
        "preflight_continue": true
    }))
    .unwrap();

    let mut ctx = make_preflight_ctx("https://example.com", "GET");
    let result = plugin.on_request_received(&mut ctx).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "preflight_continue should pass through"
    );
    // Origin should be stashed in metadata for after_proxy
    assert_eq!(
        ctx.metadata.get("cors_origin").unwrap(),
        "https://example.com"
    );
}

#[tokio::test]
async fn test_preflight_disallowed_method() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_methods": ["GET", "POST"]
    }))
    .unwrap();

    let mut ctx = make_preflight_ctx("https://example.com", "DELETE");
    let result = plugin.on_request_received(&mut ctx).await;
    match result {
        PluginResult::Reject {
            status_code,
            body,
            headers,
        } => {
            assert_eq!(status_code, 403);
            assert_eq!(body, "CORS method not allowed: DELETE");
            assert!(
                !headers.contains_key("access-control-allow-origin"),
                "No CORS headers for disallowed method"
            );
        }
        _ => panic!("Expected Reject for preflight"),
    }
}

#[tokio::test]
async fn test_non_options_with_origin_passes_through() {
    let plugin = CorsPlugin::new(&json!({})).unwrap();

    let mut ctx = make_cors_ctx("GET", "https://example.com");
    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata.get("cors_origin").unwrap(),
        "https://example.com"
    );
}

#[tokio::test]
async fn test_non_preflight_disallowed_origin_returns_403() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["https://example.com"]
    }))
    .unwrap();

    let mut ctx = make_cors_ctx("GET", "https://evil.com");
    let result = plugin.on_request_received(&mut ctx).await;
    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 403);
            assert_eq!(body, "CORS origin not allowed");
        }
        _ => panic!("Expected 403 Reject for disallowed origin on non-preflight request"),
    }
}

#[tokio::test]
async fn test_options_without_request_method_header_disallowed_origin_returns_403() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["https://example.com"]
    }))
    .unwrap();

    // OPTIONS with Origin but WITHOUT Access-Control-Request-Method = not a preflight
    // Disallowed origin should still get rejected
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "OPTIONS".to_string(),
        "/test".to_string(),
    );
    ctx.headers
        .insert("origin".to_string(), "https://evil.com".to_string());

    let result = plugin.on_request_received(&mut ctx).await;
    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 403);
            assert_eq!(body, "CORS origin not allowed");
        }
        _ => panic!("Expected 403 Reject for disallowed origin"),
    }
}

#[tokio::test]
async fn test_options_without_request_method_header_allowed_origin_passes_through() {
    let plugin = CorsPlugin::new(&json!({})).unwrap();

    // OPTIONS with Origin but WITHOUT Access-Control-Request-Method = not a preflight
    // Allowed origin should pass through
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "OPTIONS".to_string(),
        "/test".to_string(),
    );
    ctx.headers
        .insert("origin".to_string(), "https://example.com".to_string());

    let result = plugin.on_request_received(&mut ctx).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "OPTIONS without Access-Control-Request-Method with allowed origin should pass through"
    );
}

// ── Actual CORS response tests (after_proxy) ─────────────────────────

#[tokio::test]
async fn test_actual_cors_request_adds_headers() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["https://example.com"]
    }))
    .unwrap();

    // Simulate on_request_received setting metadata
    let mut ctx = make_cors_ctx("GET", "https://example.com");
    let _ = plugin.on_request_received(&mut ctx).await;

    let mut response_headers: HashMap<String, String> = HashMap::new();
    let result = plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        response_headers.get("access-control-allow-origin").unwrap(),
        "https://example.com"
    );
    assert_eq!(response_headers.get("vary").unwrap(), "Origin");
}

#[tokio::test]
async fn test_actual_cors_request_with_credentials() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["https://example.com"],
        "allow_credentials": true
    }))
    .unwrap();

    let mut ctx = make_cors_ctx("GET", "https://example.com");
    let _ = plugin.on_request_received(&mut ctx).await;

    let mut response_headers: HashMap<String, String> = HashMap::new();
    let _ = plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    assert_eq!(
        response_headers
            .get("access-control-allow-credentials")
            .unwrap(),
        "true"
    );
}

#[tokio::test]
async fn test_actual_cors_request_with_exposed_headers() {
    let plugin = CorsPlugin::new(&json!({
        "exposed_headers": ["X-Request-ID", "X-RateLimit-Remaining"]
    }))
    .unwrap();

    let mut ctx = make_cors_ctx("GET", "https://example.com");
    let _ = plugin.on_request_received(&mut ctx).await;

    let mut response_headers: HashMap<String, String> = HashMap::new();
    let _ = plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    assert_eq!(
        response_headers
            .get("access-control-expose-headers")
            .unwrap(),
        "X-Request-ID, X-RateLimit-Remaining"
    );
}

#[tokio::test]
async fn test_non_cors_request_no_headers_added() {
    let plugin = CorsPlugin::new(&json!({})).unwrap();

    // No Origin header
    let mut ctx = make_ctx();
    let _ = plugin.on_request_received(&mut ctx).await;

    let mut response_headers: HashMap<String, String> = HashMap::new();
    let _ = plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    assert!(
        !response_headers.contains_key("access-control-allow-origin"),
        "No CORS headers without Origin"
    );
}

#[tokio::test]
async fn test_after_proxy_removes_backend_access_control_headers_when_origin_not_approved() {
    let plugin = CorsPlugin::new(&json!({
        "preflight_continue": true,
        "allowed_origins": ["https://trusted.example"]
    }))
    .unwrap();

    let mut ctx = make_cors_ctx("GET", "https://evil.example");
    let _ = plugin.on_request_received(&mut ctx).await;

    let mut response_headers: HashMap<String, String> = HashMap::from([
        ("access-control-allow-origin".to_string(), "*".to_string()),
        (
            "access-control-allow-credentials".to_string(),
            "true".to_string(),
        ),
        ("x-test".to_string(), "ok".to_string()),
    ]);

    let _ = plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;

    assert!(!response_headers.contains_key("access-control-allow-origin"));
    assert!(!response_headers.contains_key("access-control-allow-credentials"));
    assert_eq!(
        response_headers.get("x-test").map(String::as_str),
        Some("ok")
    );
}

// ── Vary header tests ────────────────────────────────────────────────

#[tokio::test]
async fn test_vary_header_set_for_specific_origins() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["https://example.com"]
    }))
    .unwrap();

    let mut ctx = make_cors_ctx("GET", "https://example.com");
    let _ = plugin.on_request_received(&mut ctx).await;

    let mut response_headers: HashMap<String, String> = HashMap::new();
    let _ = plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    assert_eq!(response_headers.get("vary").unwrap(), "Origin");
}

#[tokio::test]
async fn test_vary_header_set_for_wildcard() {
    let plugin = CorsPlugin::new(&json!({})).unwrap();

    let mut ctx = make_cors_ctx("GET", "https://example.com");
    let _ = plugin.on_request_received(&mut ctx).await;

    let mut response_headers: HashMap<String, String> = HashMap::new();
    let _ = plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    assert_eq!(response_headers.get("vary").unwrap(), "Origin");
}

// ── Edge case tests ──────────────────────────────────────────────────

#[tokio::test]
async fn test_empty_origin_header_returns_403() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["https://example.com"]
    }))
    .unwrap();

    let mut ctx = make_cors_ctx("GET", "");
    let result = plugin.on_request_received(&mut ctx).await;
    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 403);
            assert_eq!(body, "CORS origin not allowed");
        }
        _ => panic!("Expected 403 Reject for empty origin"),
    }
}

#[tokio::test]
async fn test_case_sensitivity_of_origins() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["https://example.com"]
    }))
    .unwrap();

    // Origins are compared case-insensitively — mismatched case should be allowed
    let mut ctx = make_cors_ctx("GET", "https://Example.com");
    let result = plugin.on_request_received(&mut ctx).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "Expected Continue for case-mismatched origin (case-insensitive comparison)"
    );
    assert_eq!(
        ctx.metadata.get("cors_origin").map(|s| s.as_str()),
        Some("https://Example.com"),
    );
}

#[tokio::test]
async fn test_multiple_origins_in_config() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["https://app.example.com", "https://admin.example.com"]
    }))
    .unwrap();

    // First origin — allowed
    let mut ctx1 = make_cors_ctx("GET", "https://app.example.com");
    let result1 = plugin.on_request_received(&mut ctx1).await;
    assert!(matches!(result1, PluginResult::Continue));
    assert_eq!(
        ctx1.metadata.get("cors_origin").unwrap(),
        "https://app.example.com"
    );

    // Second origin — allowed
    let mut ctx2 = make_cors_ctx("GET", "https://admin.example.com");
    let result2 = plugin.on_request_received(&mut ctx2).await;
    assert!(matches!(result2, PluginResult::Continue));
    assert_eq!(
        ctx2.metadata.get("cors_origin").unwrap(),
        "https://admin.example.com"
    );

    // Third (not allowed) — should return 403
    let mut ctx3 = make_cors_ctx("GET", "https://evil.com");
    let result3 = plugin.on_request_received(&mut ctx3).await;
    match result3 {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 403);
            assert_eq!(body, "CORS origin not allowed");
        }
        _ => panic!("Expected 403 Reject for disallowed origin"),
    }
}

// ── Wildcard subdomain origin tests ─────────────────────────────────

#[tokio::test]
async fn test_wildcard_subdomain_origin_matches() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["*.company.com"]
    }))
    .unwrap();

    let mut ctx = make_cors_ctx("GET", "https://app.company.com");
    let result = plugin.on_request_received(&mut ctx).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "*.company.com should match https://app.company.com"
    );
    assert_eq!(
        ctx.metadata.get("cors_origin").unwrap(),
        "https://app.company.com"
    );
}

#[tokio::test]
async fn test_wildcard_subdomain_deep_subdomain_matches() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["*.company.com"]
    }))
    .unwrap();

    let mut ctx = make_cors_ctx("GET", "https://deep.sub.company.com");
    let result = plugin.on_request_received(&mut ctx).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "*.company.com should match https://deep.sub.company.com"
    );
}

#[tokio::test]
async fn test_wildcard_subdomain_rejects_non_match() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["*.company.com"]
    }))
    .unwrap();

    let mut ctx = make_cors_ctx("GET", "https://evil.com");
    let result = plugin.on_request_received(&mut ctx).await;
    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 403);
            assert_eq!(body, "CORS origin not allowed");
        }
        _ => panic!("Expected 403 Reject for non-matching origin"),
    }
}

#[tokio::test]
async fn test_wildcard_subdomain_does_not_match_bare_domain() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["*.company.com"]
    }))
    .unwrap();

    // "company.com" has no subdomain prefix, so it should NOT match "*.company.com"
    let mut ctx = make_cors_ctx("GET", "https://company.com");
    let result = plugin.on_request_received(&mut ctx).await;
    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 403);
            assert_eq!(body, "CORS origin not allowed");
        }
        _ => panic!("Expected 403 Reject — bare domain should not match wildcard subdomain"),
    }
}

#[tokio::test]
async fn test_wildcard_subdomain_case_insensitive() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["*.Company.Com"]
    }))
    .unwrap();

    let mut ctx = make_cors_ctx("GET", "https://APP.COMPANY.COM");
    let result = plugin.on_request_received(&mut ctx).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "Wildcard subdomain matching should be case-insensitive"
    );
}

// Regression for finding #51: wildcard-subdomain matching must enforce the
// same http(s) scheme allow-list as exact-origin matching. A non-http scheme
// (e.g. `ftp://`) that suffix-matches the host must NOT be allowed/reflected.
#[tokio::test]
async fn test_wildcard_subdomain_rejects_non_http_scheme() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["*.company.com"]
    }))
    .unwrap();

    let mut ctx = make_cors_ctx("GET", "ftp://app.company.com");
    let result = plugin.on_request_received(&mut ctx).await;
    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 403);
            assert_eq!(body, "CORS origin not allowed");
        }
        _ => panic!("Expected 403 Reject — non-http scheme must not match wildcard subdomain"),
    }
    assert!(!ctx.metadata.contains_key("cors_origin"));
}

// No-regression guard for finding #51: `http://` (not just `https://`) must
// still match a wildcard-subdomain rule.
#[tokio::test]
async fn test_wildcard_subdomain_allows_plain_http_scheme() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["*.company.com"]
    }))
    .unwrap();

    let mut ctx = make_cors_ctx("GET", "http://app.company.com");
    let result = plugin.on_request_received(&mut ctx).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "*.company.com should match http://app.company.com"
    );
    assert_eq!(
        ctx.metadata.get("cors_origin").unwrap(),
        "http://app.company.com"
    );
}

#[tokio::test]
async fn test_mixed_exact_and_wildcard_origins() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["https://exact.com", "*.company.com"]
    }))
    .unwrap();

    // Exact match
    let mut ctx1 = make_cors_ctx("GET", "https://exact.com");
    let result1 = plugin.on_request_received(&mut ctx1).await;
    assert!(
        matches!(result1, PluginResult::Continue),
        "Exact origin should match"
    );

    // Wildcard subdomain match
    let mut ctx2 = make_cors_ctx("GET", "https://app.company.com");
    let result2 = plugin.on_request_received(&mut ctx2).await;
    assert!(
        matches!(result2, PluginResult::Continue),
        "Wildcard subdomain should match"
    );

    // Neither
    let mut ctx3 = make_cors_ctx("GET", "https://evil.com");
    let result3 = plugin.on_request_received(&mut ctx3).await;
    assert!(
        matches!(
            result3,
            PluginResult::Reject {
                status_code: 403,
                ..
            }
        ),
        "Unmatched origin should be rejected"
    );
}

#[tokio::test]
async fn test_star_in_list_with_other_origins_becomes_wildcard() {
    // If "*" appears anywhere in the list, treat the whole config as Wildcard
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["*", "https://specific.com"]
    }))
    .unwrap();

    let mut ctx = make_cors_ctx("GET", "https://anything.example.com");
    let result = plugin.on_request_received(&mut ctx).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "\"*\" in list should make all origins allowed"
    );
}

#[tokio::test]
async fn test_wildcard_subdomain_preflight() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["*.company.com"]
    }))
    .unwrap();

    let mut ctx = make_preflight_ctx("https://app.company.com", "POST");
    let result = plugin.on_request_received(&mut ctx).await;
    match result {
        PluginResult::Reject {
            status_code,
            headers,
            ..
        } => {
            assert_eq!(status_code, 204);
            assert_eq!(
                headers.get("access-control-allow-origin").unwrap(),
                "https://app.company.com",
                "Preflight should reflect the actual origin, not the pattern"
            );
        }
        _ => panic!("Expected 204 Reject for approved preflight"),
    }
}

#[tokio::test]
async fn test_wildcard_subdomain_reflects_origin_in_response() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["*.company.com"]
    }))
    .unwrap();

    let mut ctx = make_cors_ctx("GET", "https://app.company.com");
    let _ = plugin.on_request_received(&mut ctx).await;

    let mut response_headers: HashMap<String, String> = HashMap::new();
    let _ = plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    assert_eq!(
        response_headers.get("access-control-allow-origin").unwrap(),
        "https://app.company.com",
        "Response should reflect the actual matched origin, not the wildcard pattern"
    );
}

#[tokio::test]
async fn test_wildcard_subdomain_with_port() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["*.company.com"]
    }))
    .unwrap();

    let mut ctx = make_cors_ctx("GET", "https://app.company.com:8443");
    let result = plugin.on_request_received(&mut ctx).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "*.company.com should match https://app.company.com:8443"
    );
}

// ── Vary header merge — preserves backend Vary while adding Origin ───
//
// Regression: previously `after_proxy` blindly inserted `Vary: Origin`,
// clobbering any backend Vary value (e.g., compression's
// `Vary: Accept-Encoding`). That broke downstream caches.

#[tokio::test]
async fn test_vary_header_merges_with_existing_backend_vary() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["https://example.com"]
    }))
    .unwrap();

    let mut ctx = make_cors_ctx("GET", "https://example.com");
    let _ = plugin.on_request_received(&mut ctx).await;

    let mut response_headers: HashMap<String, String> = HashMap::new();
    response_headers.insert("vary".to_string(), "Accept-Encoding".to_string());
    let _ = plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    let vary = response_headers.get("vary").unwrap();
    assert!(
        vary.contains("Accept-Encoding"),
        "merged Vary must preserve backend Accept-Encoding, got: {}",
        vary
    );
    assert!(
        vary.to_ascii_lowercase().contains("origin"),
        "merged Vary must include Origin, got: {}",
        vary
    );
}

#[tokio::test]
async fn test_vary_header_origin_already_present_not_duplicated() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["https://example.com"]
    }))
    .unwrap();

    let mut ctx = make_cors_ctx("GET", "https://example.com");
    let _ = plugin.on_request_received(&mut ctx).await;

    let mut response_headers: HashMap<String, String> = HashMap::new();
    response_headers.insert("vary".to_string(), "origin, Accept-Language".to_string());
    let _ = plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    let vary = response_headers.get("vary").unwrap();
    // Case-insensitive match — should not duplicate
    let origin_count = vary
        .split(',')
        .filter(|tok| tok.trim().eq_ignore_ascii_case("Origin"))
        .count();
    assert_eq!(
        origin_count, 1,
        "Origin already present (case-insensitive) must not be duplicated, got: {}",
        vary
    );
    assert!(
        vary.contains("Accept-Language"),
        "other tokens must be preserved"
    );
}

#[tokio::test]
async fn test_vary_header_wildcard_preserved_origin_redundant() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["https://example.com"]
    }))
    .unwrap();

    let mut ctx = make_cors_ctx("GET", "https://example.com");
    let _ = plugin.on_request_received(&mut ctx).await;

    let mut response_headers: HashMap<String, String> = HashMap::new();
    // Vary: * means "any header" — adding Origin would be redundant per RFC 9110.
    response_headers.insert("vary".to_string(), "*".to_string());
    let _ = plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    assert_eq!(
        response_headers.get("vary").unwrap(),
        "*",
        "Vary: * must be preserved (Origin would be redundant)"
    );
}

#[tokio::test]
async fn test_after_proxy_rejection_with_cors_origin_strips_stale_headers() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["https://example.com"],
        "allow_credentials": false
    }))
    .unwrap();

    let mut ctx = make_cors_ctx("GET", "https://example.com");
    let _ = plugin.on_request_received(&mut ctx).await;
    ctx.metadata
        .insert("ferrum:rejection_response".to_string(), "true".to_string());

    let mut response_headers: HashMap<String, String> = HashMap::new();
    response_headers.insert(
        "access-control-allow-credentials".to_string(),
        "true".to_string(),
    );
    response_headers.insert(
        "access-control-expose-headers".to_string(),
        "x-secret".to_string(),
    );

    let _ = plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;

    assert_eq!(
        response_headers.get("access-control-allow-origin"),
        Some(&"https://example.com".to_string())
    );
    assert!(!response_headers.contains_key("access-control-allow-credentials"));
    assert!(!response_headers.contains_key("access-control-expose-headers"));
}

// ── Istio StringMatch object origin matchers (exact / prefix / regex) ────────
//
// These back the VirtualService `corsPolicy` `prefix`/`regex` origin
// projection: a `corsPolicy.allowOrigins[]` StringMatch entry is emitted into
// `allowed_origins` as `{exact|prefix|regex}`, and the plugin reflects a
// matching Origin into `Access-Control-Allow-Origin` and 403s a non-match.

#[tokio::test]
async fn test_object_exact_origin_matches_and_reflects() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": [{"exact": "https://app.example.com"}]
    }))
    .unwrap();

    let mut ctx = make_cors_ctx("GET", "https://app.example.com");
    let result = plugin.on_request_received(&mut ctx).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "{{exact}} matcher should match the same origin string"
    );

    let mut response_headers: HashMap<String, String> = HashMap::new();
    let _ = plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    assert_eq!(
        response_headers.get("access-control-allow-origin").unwrap(),
        "https://app.example.com",
        "a matched origin is reflected verbatim"
    );
}

#[tokio::test]
async fn test_prefix_origin_matches_and_reflects() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": [{"prefix": "https://app."}]
    }))
    .unwrap();

    // Matching origin: starts with the literal prefix → reflected.
    let mut ctx = make_cors_ctx("GET", "https://app.example.com");
    let result = plugin.on_request_received(&mut ctx).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "prefix matcher should admit an origin that starts with the prefix"
    );
    let mut response_headers: HashMap<String, String> = HashMap::new();
    let _ = plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    assert_eq!(
        response_headers.get("access-control-allow-origin").unwrap(),
        "https://app.example.com",
    );
}

#[tokio::test]
async fn test_prefix_origin_rejects_non_match() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": [{"prefix": "https://app."}]
    }))
    .unwrap();

    let mut ctx = make_cors_ctx("GET", "https://evil.example.com");
    let result = plugin.on_request_received(&mut ctx).await;
    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 403);
            assert_eq!(body, "CORS origin not allowed");
        }
        _ => panic!("Expected 403 Reject — origin without the prefix must not match"),
    }
    assert!(!ctx.metadata.contains_key("cors_origin"));
}

#[tokio::test]
async fn test_regex_origin_full_match_reflects() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": [{"regex": "https://.*\\.example\\.com"}]
    }))
    .unwrap();

    let mut ctx = make_cors_ctx("GET", "https://sub.example.com");
    let result = plugin.on_request_received(&mut ctx).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "regex matcher should admit a fully-matching origin"
    );
    let mut response_headers: HashMap<String, String> = HashMap::new();
    let _ = plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    assert_eq!(
        response_headers.get("access-control-allow-origin").unwrap(),
        "https://sub.example.com",
    );
}

#[tokio::test]
async fn test_regex_origin_rejects_non_match() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": [{"regex": "https://.*\\.example\\.com"}]
    }))
    .unwrap();

    let mut ctx = make_cors_ctx("GET", "https://sub.evil.com");
    let result = plugin.on_request_received(&mut ctx).await;
    match result {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        _ => panic!("Expected 403 Reject — origin not matching the regex"),
    }
}

#[tokio::test]
async fn test_regex_origin_requires_full_match_not_substring() {
    // Istio `StringMatch.regex` is a FULL match. A pattern that matches only a
    // substring of the Origin must NOT admit it (no implicit `.*` on the ends),
    // so a trailing-garbage origin is rejected even though the prefix matches.
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": [{"regex": "https://app\\.example\\.com"}]
    }))
    .unwrap();

    let mut ctx = make_cors_ctx("GET", "https://app.example.com.evil.com");
    let result = plugin.on_request_received(&mut ctx).await;
    match result {
        PluginResult::Reject { status_code, .. } => assert_eq!(
            status_code, 403,
            "regex must full-match; a suffix-extended origin must be rejected"
        ),
        _ => panic!("Expected 403 Reject — regex is a full match, not a substring search"),
    }
}

#[tokio::test]
async fn test_regex_origin_alternation_full_match_accepts_later_branch() {
    // Regression for the anchored-vs-first-find bug: with a top-level
    // alternation whose FIRST branch is a strict prefix of the Origin, an
    // unanchored `find` returns the shorter leading match and the full-length
    // check rejects the Origin — even though a LATER branch matches the whole
    // string. Anchoring the compiled pattern (`^(?:...)$`) makes `is_match`
    // try every branch, so the Origin is correctly admitted.
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": [{"regex": "https://app|https://app\\.example\\.com"}]
    }))
    .unwrap();

    let mut ctx = make_cors_ctx("GET", "https://app.example.com");
    assert!(
        matches!(
            plugin.on_request_received(&mut ctx).await,
            PluginResult::Continue
        ),
        "a later alternation branch fully matching the Origin must admit it"
    );
}

#[tokio::test]
async fn test_mixed_string_and_object_origin_matchers() {
    // Plain-string and object matchers can be mixed in one `allowed_origins`.
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": [
            "https://exact.example.com",
            {"prefix": "https://app."},
            {"regex": "https://.*\\.api\\.example\\.com"}
        ]
    }))
    .unwrap();

    for origin in [
        "https://exact.example.com",
        "https://app.anything.com",
        "https://v2.api.example.com",
    ] {
        let mut ctx = make_cors_ctx("GET", origin);
        let result = plugin.on_request_received(&mut ctx).await;
        assert!(
            matches!(result, PluginResult::Continue),
            "origin {origin} should match one of the mixed matchers"
        );
    }

    let mut ctx = make_cors_ctx("GET", "https://nope.com");
    match plugin.on_request_received(&mut ctx).await {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        _ => panic!("Expected 403 Reject for an origin matching none of the matchers"),
    }
}

#[tokio::test]
async fn test_preflight_with_prefix_origin_emits_cors_headers() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": [{"prefix": "https://app."}],
        "allowed_methods": ["GET", "POST"]
    }))
    .unwrap();

    let mut ctx = make_preflight_ctx("https://app.example.com", "POST");
    match plugin.on_request_received(&mut ctx).await {
        PluginResult::Reject {
            status_code,
            headers,
            ..
        } => {
            assert_eq!(status_code, 204);
            assert_eq!(
                headers.get("access-control-allow-origin").unwrap(),
                "https://app.example.com",
            );
        }
        _ => panic!("Expected 204 preflight approval for a prefix-matched origin"),
    }
}

#[test]
fn test_constructor_rejects_uncompilable_regex_origin() {
    let err = CorsPlugin::new(&json!({
        "allowed_origins": [{"regex": "https://(example"}]
    }))
    .err()
    .expect("an un-compilable regex origin must be rejected at config time");
    assert!(err.contains("regex matcher"), "got: {err}");
}

#[test]
fn test_constructor_rejects_empty_prefix_origin() {
    // An empty prefix would match every origin — reject it rather than create
    // an accidental allow-all policy.
    let err = CorsPlugin::new(&json!({
        "allowed_origins": [{"prefix": ""}]
    }))
    .err()
    .expect("an empty prefix origin must be rejected");
    assert!(err.contains("prefix matcher"), "got: {err}");
}

#[test]
fn test_constructor_rejects_multi_key_origin_matcher() {
    let err = CorsPlugin::new(&json!({
        "allowed_origins": [{"prefix": "https://app.", "regex": "https://.*"}]
    }))
    .err()
    .expect("an object matcher with two keys must be rejected");
    assert!(err.contains("exactly one"), "got: {err}");
}

#[test]
fn test_constructor_rejects_object_matcher_with_non_string_extra_key() {
    // Regression: a recognized key with a NON-string value (here `regex`)
    // alongside a valid string key must NOT be silently dropped, leaving a bare
    // prefix matcher — the StringMatch contract is exactly one well-typed key.
    let err = CorsPlugin::new(&json!({
        "allowed_origins": [{"prefix": "https://app.", "regex": 123}]
    }))
    .err()
    .expect("an object matcher with an extra (non-string) key must be rejected");
    assert!(err.contains("exactly one"), "got: {err}");
}

#[test]
fn test_constructor_rejects_object_matcher_with_unknown_key() {
    // An unknown key must be rejected rather than ignored while a sibling valid
    // key is honored.
    let err = CorsPlugin::new(&json!({
        "allowed_origins": [{"prefix": "https://app.", "bogus": "x"}]
    }))
    .err()
    .expect("an object matcher with an unknown key must be rejected");
    assert!(err.contains("exactly one"), "got: {err}");
}

#[test]
fn test_constructor_rejects_empty_object_origin_matcher() {
    let err = CorsPlugin::new(&json!({
        "allowed_origins": [{}]
    }))
    .err()
    .expect("an object matcher with no exact/prefix/regex must be rejected");
    assert!(
        err.contains("exact") && err.contains("prefix") && err.contains("regex"),
        "got: {err}"
    );
}
