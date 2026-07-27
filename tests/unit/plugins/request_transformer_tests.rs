//! Tests for request_transformer plugin

use ferrum_edge::plugins::{
    HTTP_GRPC_PROTOCOLS, Plugin, RequestContext, priority, request_transformer::RequestTransformer,
};
use serde_json::json;
use std::collections::HashMap;

use super::plugin_utils::normalize_compressed_request_for_plugin_test;

fn make_ctx() -> RequestContext {
    RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/test".to_string(),
    )
}

#[tokio::test]
async fn test_request_transformer_creation() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-Test", "value": "test"}
        ]
    }))
    .unwrap();
    assert_eq!(plugin.name(), "request_transformer");
    assert_eq!(plugin.priority(), priority::REQUEST_TRANSFORMER);
    assert_eq!(plugin.supported_protocols(), HTTP_GRPC_PROTOCOLS);
    assert!(plugin.modifies_request_headers());
    assert!(!plugin.modifies_request_body());
    assert!(!plugin.is_auth_plugin());
}

#[tokio::test]
async fn test_request_transformer_add_header() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-Custom", "value": "custom-value"}
        ]
    }))
    .unwrap();

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));
    assert_eq!(headers.get("x-custom").unwrap(), "custom-value");
}

#[tokio::test]
async fn test_request_transformer_remove_header() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "remove", "target": "header", "key": "X-Remove-Me"}
        ]
    }))
    .unwrap();

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();
    headers.insert("x-remove-me".to_string(), "should-be-removed".to_string());
    headers.insert("x-keep-me".to_string(), "should-remain".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));
    assert!(!headers.contains_key("x-remove-me"));
    assert!(headers.contains_key("x-keep-me"));
}

#[tokio::test]
async fn test_request_transformer_update_header() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "update", "target": "header", "key": "X-Existing", "value": "new-value"}
        ]
    }))
    .unwrap();

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();
    headers.insert("x-existing".to_string(), "old-value".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));
    assert_eq!(headers.get("x-existing").unwrap(), "new-value");
}

#[tokio::test]
async fn test_request_transformer_add_query_param() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "query", "key": "version", "value": "v2"}
        ]
    }))
    .unwrap();

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));
    assert_eq!(ctx.query_params.get("version").unwrap(), "v2");
}

#[tokio::test]
async fn test_query_transform_marks_metadata_for_raw_query_consumers() {
    // Mirror of `QUERY_PARAMS_TRANSFORMED_METADATA_KEY` (pub(crate) in proxy).
    // Raw-query consumers (serverless_function) fail closed on this marker.
    const QUERY_PARAMS_TRANSFORMED_METADATA_KEY: &str = "ferrum:query_params_transformed";

    // A query rule that actually mutates the decoded map sets the marker.
    let mutating = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "remove", "target": "query", "key": "token"}
        ]
    }))
    .unwrap();
    let mut ctx = make_ctx();
    ctx.query_params
        .insert("token".to_string(), "secret".to_string());
    let mut headers: HashMap<String, String> = HashMap::new();
    let _ = mutating.before_proxy(&mut ctx, &mut headers).await;
    assert!(
        ctx.metadata
            .contains_key(QUERY_PARAMS_TRANSFORMED_METADATA_KEY),
        "an applied query transform must mark metadata for raw-query consumers"
    );

    // A query rule that no-ops (nothing to remove) must NOT set the marker, so a
    // safe raw-query composition is not needlessly rejected.
    let noop = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "remove", "target": "query", "key": "absent"}
        ]
    }))
    .unwrap();
    let mut noop_ctx = make_ctx();
    noop_ctx
        .query_params
        .insert("keep".to_string(), "value".to_string());
    let mut noop_headers: HashMap<String, String> = HashMap::new();
    let _ = noop.before_proxy(&mut noop_ctx, &mut noop_headers).await;
    assert!(
        !noop_ctx
            .metadata
            .contains_key(QUERY_PARAMS_TRANSFORMED_METADATA_KEY),
        "a no-op query rule must not mark a query transform"
    );

    // A header-only transform must not set the query-transform marker.
    let header_only = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-Test", "value": "1"}
        ]
    }))
    .unwrap();
    let mut header_ctx = make_ctx();
    let mut header_headers: HashMap<String, String> = HashMap::new();
    let _ = header_only
        .before_proxy(&mut header_ctx, &mut header_headers)
        .await;
    assert!(
        !header_ctx
            .metadata
            .contains_key(QUERY_PARAMS_TRANSFORMED_METADATA_KEY),
        "a header-only transform must not mark a query transform"
    );
}

#[tokio::test]
async fn test_request_transformer_remove_query_param() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "remove", "target": "query", "key": "secret"}
        ]
    }))
    .unwrap();

    let mut ctx = make_ctx();
    ctx.query_params
        .insert("secret".to_string(), "should-be-removed".to_string());
    ctx.query_params
        .insert("keep".to_string(), "should-remain".to_string());
    let mut headers: HashMap<String, String> = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));
    assert!(!ctx.query_params.contains_key("secret"));
    assert!(ctx.query_params.contains_key("keep"));
}

#[tokio::test]
async fn test_request_transformer_update_query_param() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "update", "target": "query", "key": "page", "value": "2"}
        ]
    }))
    .unwrap();

    let mut ctx = make_ctx();
    ctx.query_params.insert("page".to_string(), "1".to_string());
    let mut headers: HashMap<String, String> = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));
    assert_eq!(ctx.query_params.get("page").unwrap(), "2");
}

#[tokio::test]
async fn test_request_transformer_multiple_rules() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-Added", "value": "yes"},
            {"operation": "remove", "target": "header", "key": "X-Removed"},
            {"operation": "add", "target": "query", "key": "added_param", "value": "true"},
            {"operation": "remove", "target": "query", "key": "removed_param"}
        ]
    }))
    .unwrap();

    let mut ctx = make_ctx();
    ctx.query_params
        .insert("removed_param".to_string(), "gone".to_string());
    let mut headers: HashMap<String, String> = HashMap::new();
    headers.insert("x-removed".to_string(), "gone".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));
    assert_eq!(headers.get("x-added").unwrap(), "yes");
    assert!(!headers.contains_key("x-removed"));
    assert_eq!(ctx.query_params.get("added_param").unwrap(), "true");
    assert!(!ctx.query_params.contains_key("removed_param"));
}

#[tokio::test]
async fn test_request_transformer_empty_rules() {
    let result = RequestTransformer::new(&json!({"rules": []}));
    let err = result.err().expect("expected error for empty rules");
    assert!(err.contains("no 'rules' configured"), "got: {err}");
}

#[tokio::test]
async fn test_request_transformer_no_config() {
    let result = RequestTransformer::new(&json!({}));
    let err = result.err().expect("expected error for no config");
    assert!(err.contains("no 'rules' configured"), "got: {err}");
}

#[tokio::test]
async fn test_request_transformer_rejects_invalid_rules_container_shapes() {
    for config in [
        json!("bad"),
        json!({"rules": "not-array"}),
        json!({"rules": [42]}),
    ] {
        let err = RequestTransformer::new(&config)
            .err()
            .expect("expected invalid config to be rejected");
        assert!(
            err.contains("config must be an object")
                || err.contains("'rules' must be an array")
                || err.contains("rule must be an object"),
            "unexpected error for {config:?}: {err}"
        );
    }
}

#[tokio::test]
async fn test_request_transformer_add_without_value_rejected() {
    let err = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-NoValue"}
        ]
    }))
    .err()
    .expect("expected error for add without value");
    assert!(err.contains("requires a 'value'"), "got: {err}");
}

#[tokio::test]
async fn test_request_transformer_unknown_operation_rejected() {
    let err = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "delete", "target": "header", "key": "X-Test", "value": "val"}
        ]
    }))
    .err()
    .expect("expected error for unknown operation");
    assert!(err.contains("unknown operation"), "got: {err}");
}

#[tokio::test]
async fn test_request_transformer_body_rules_not_applied_in_before_proxy() {
    // Body rules are applied via transform_request_body, not before_proxy
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "body", "key": "field", "value": "val"}
        ]
    }))
    .unwrap();

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));
    // Body rules are handled separately, headers should be untouched
    assert!(headers.is_empty());
}

#[tokio::test]
async fn test_request_transformer_unknown_target_rejected() {
    let err = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "cookie", "key": "field", "value": "val"}
        ]
    }))
    .err()
    .expect("expected error for unknown target");
    assert!(err.contains("unknown target"), "got: {err}");
}

#[tokio::test]
async fn test_request_transformer_rename_header() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "rename", "target": "header", "key": "X-Old-Name", "new_key": "X-New-Name"}
        ]
    })).unwrap();

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();
    headers.insert("x-old-name".to_string(), "the-value".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));
    assert!(!headers.contains_key("x-old-name"));
    assert_eq!(headers.get("x-new-name").unwrap(), "the-value");
}

#[tokio::test]
async fn test_request_transformer_rename_header_nonexistent() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "rename", "target": "header", "key": "X-Does-Not-Exist", "new_key": "X-New-Name"}
        ]
    })).unwrap();

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));
    assert!(!headers.contains_key("x-new-name"));
    assert!(!headers.contains_key("x-does-not-exist"));
}

#[tokio::test]
async fn test_request_transformer_rename_query_param() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "rename", "target": "query", "key": "old_key", "new_key": "new_key"}
        ]
    }))
    .unwrap();

    let mut ctx = make_ctx();
    ctx.query_params
        .insert("old_key".to_string(), "the-value".to_string());
    let mut headers: HashMap<String, String> = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));
    assert!(!ctx.query_params.contains_key("old_key"));
    assert_eq!(ctx.query_params.get("new_key").unwrap(), "the-value");
}

#[tokio::test]
async fn test_request_transformer_rename_query_param_nonexistent() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "rename", "target": "query", "key": "missing_key", "new_key": "new_key"}
        ]
    }))
    .unwrap();

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));
    assert!(!ctx.query_params.contains_key("missing_key"));
    assert!(!ctx.query_params.contains_key("new_key"));
}

#[tokio::test]
async fn test_request_transformer_rename_without_new_key_rejected() {
    let err = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "rename", "target": "header", "key": "X-Old-Name"}
        ]
    }))
    .err()
    .expect("expected error for rename without new_key");
    assert!(err.contains("requires a 'new_key'"), "got: {err}");
}

#[tokio::test]
async fn test_rename_array_index_rejected_at_construction() {
    // Rename rules targeting array indices are ambiguous (move? swap?
    // overwrite?) and previously caused silent data loss when both sides
    // pointed at the same array. They must be rejected at plugin construction
    // so the misconfiguration surfaces as an HTTP 400 (admin API) or startup
    // failure (file mode) instead of corrupting user data at runtime.
    let err = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "rename", "target": "body", "key": "items.0", "new_key": "items.1"}
        ]
    }))
    .err()
    .expect("expected error for rename with array indices");
    assert!(err.contains("does not support array indices"), "got: {err}");
}

#[tokio::test]
async fn test_request_transformer_header_key_pre_lowercased() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-UPPER-CASE", "value": "lowered"}
        ]
    }))
    .unwrap();

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));
    // Key should be stored as lowercase due to pre-lowercasing at config time
    assert_eq!(headers.get("x-upper-case").unwrap(), "lowered");
    assert!(!headers.contains_key("X-UPPER-CASE"));
}

// ── Body transformation tests ──────────────────────────────────────────────

#[tokio::test]
async fn test_request_transformer_body_add_field() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "body", "key": "version", "value": "v2"}
        ]
    }))
    .unwrap();

    assert!(plugin.modifies_request_body());

    let body = br#"{"name":"Alice"}"#;
    let result = plugin
        .transform_request_body(body, Some("application/json"), &HashMap::new())
        .await;
    let transformed: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    assert_eq!(transformed["name"], "Alice");
    assert_eq!(transformed["version"], "v2");
}

#[tokio::test]
async fn configured_decompression_exposes_plaintext_before_request_transforms() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {
                "operation": "remove",
                "target": "body",
                "key": "credentials.api_key"
            }
        ]
    }))
    .unwrap();
    let plaintext = br#"{"credentials":{"api_key":"secret","region":"us"}}"#;

    for encoding in ["gzip", "br"] {
        let (mut ctx, headers, body) = normalize_compressed_request_for_plugin_test(
            "application/json",
            "/transform",
            encoding,
            plaintext,
        )
        .await;
        let transformed = plugin
            .transform_request_body_with_context(
                &mut ctx,
                &body,
                Some("application/json"),
                &headers,
            )
            .await
            .expect("decoded JSON rule must transform the request body");
        let transformed: serde_json::Value = serde_json::from_slice(&transformed).unwrap();
        assert!(transformed["credentials"].get("api_key").is_none());
        assert_eq!(transformed["credentials"]["region"], "us");
    }
}

#[tokio::test]
async fn test_request_transformer_body_add_nested_field() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "body", "key": "user.role", "value": "admin"}
        ]
    }))
    .unwrap();

    let body = br#"{"user":{"name":"Alice"}}"#;
    let result = plugin
        .transform_request_body(body, Some("application/json"), &HashMap::new())
        .await;
    let transformed: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    assert_eq!(transformed["user"]["name"], "Alice");
    assert_eq!(transformed["user"]["role"], "admin");
}

#[tokio::test]
async fn test_request_transformer_body_add_does_not_overwrite() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "body", "key": "name", "value": "Bob"}
        ]
    }))
    .unwrap();

    let body = br#"{"name":"Alice"}"#;
    let result = plugin
        .transform_request_body(body, Some("application/json"), &HashMap::new())
        .await;
    // "add" should not overwrite existing field
    assert!(result.is_none());
}

#[tokio::test]
async fn test_request_transformer_body_update_field() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "update", "target": "body", "key": "status", "value": "active"}
        ]
    }))
    .unwrap();

    let body = br#"{"status":"pending"}"#;
    let result = plugin
        .transform_request_body(body, Some("application/json"), &HashMap::new())
        .await;
    let transformed: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    assert_eq!(transformed["status"], "active");
}

#[tokio::test]
async fn test_request_transformer_body_update_nested_field() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "update", "target": "body", "key": "user.address.city", "value": "NYC"}
        ]
    }))
    .unwrap();

    let body = br#"{"user":{"address":{"city":"LA","zip":"90001"}}}"#;
    let result = plugin
        .transform_request_body(body, Some("application/json"), &HashMap::new())
        .await;
    let transformed: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    assert_eq!(transformed["user"]["address"]["city"], "NYC");
    assert_eq!(transformed["user"]["address"]["zip"], "90001");
}

#[tokio::test]
async fn test_request_transformer_body_remove_field() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "remove", "target": "body", "key": "internal_id"}
        ]
    }))
    .unwrap();

    let body = br#"{"name":"Alice","internal_id":"secret123"}"#;
    let result = plugin
        .transform_request_body(body, Some("application/json"), &HashMap::new())
        .await;
    let transformed: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    assert_eq!(transformed["name"], "Alice");
    assert!(transformed.get("internal_id").is_none());
}

#[tokio::test]
async fn test_request_transformer_body_remove_nested_field() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "remove", "target": "body", "key": "user.password"}
        ]
    }))
    .unwrap();

    let body = br#"{"user":{"name":"Alice","password":"secret"}}"#;
    let result = plugin
        .transform_request_body(body, Some("application/json"), &HashMap::new())
        .await;
    let transformed: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    assert_eq!(transformed["user"]["name"], "Alice");
    assert!(transformed["user"].get("password").is_none());
}

#[tokio::test]
async fn test_request_transformer_body_rename_field() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "rename", "target": "body", "key": "first_name", "new_key": "given_name"}
        ]
    }))
    .unwrap();

    let body = br#"{"first_name":"Alice","age":30}"#;
    let result = plugin
        .transform_request_body(body, Some("application/json"), &HashMap::new())
        .await;
    let transformed: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    assert_eq!(transformed["given_name"], "Alice");
    assert!(transformed.get("first_name").is_none());
    assert_eq!(transformed["age"], 30);
}

#[tokio::test]
async fn test_request_transformer_body_rename_nested_field() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "rename", "target": "body", "key": "user.old_field", "new_key": "user.new_field"}
        ]
    })).unwrap();

    let body = br#"{"user":{"old_field":"data","other":"keep"}}"#;
    let result = plugin
        .transform_request_body(body, Some("application/json"), &HashMap::new())
        .await;
    let transformed: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    assert_eq!(transformed["user"]["new_field"], "data");
    assert!(transformed["user"].get("old_field").is_none());
    assert_eq!(transformed["user"]["other"], "keep");
}

#[tokio::test]
async fn test_request_transformer_body_rename_across_nesting_levels() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "rename", "target": "body", "key": "nested.deep.value", "new_key": "flat_value"}
        ]
    })).unwrap();

    let body = br#"{"nested":{"deep":{"value":"found"}}}"#;
    let result = plugin
        .transform_request_body(body, Some("application/json"), &HashMap::new())
        .await;
    let transformed: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    assert_eq!(transformed["flat_value"], "found");
    assert!(transformed["nested"]["deep"].get("value").is_none());
}

#[tokio::test]
async fn test_request_transformer_body_multiple_rules() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "rename", "target": "body", "key": "old_name", "new_key": "new_name"},
            {"operation": "remove", "target": "body", "key": "secret"},
            {"operation": "add", "target": "body", "key": "version", "value": "2"},
            {"operation": "update", "target": "body", "key": "status", "value": "processed"}
        ]
    }))
    .unwrap();

    let body = br#"{"old_name":"Alice","secret":"hidden","status":"pending"}"#;
    let result = plugin
        .transform_request_body(body, Some("application/json"), &HashMap::new())
        .await;
    let transformed: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    assert_eq!(transformed["new_name"], "Alice");
    assert!(transformed.get("old_name").is_none());
    assert!(transformed.get("secret").is_none());
    assert_eq!(transformed["version"], 2);
    assert_eq!(transformed["status"], "processed");
}

#[tokio::test]
async fn test_request_transformer_body_mixed_header_and_body_rules() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-Custom", "value": "yes"},
            {"operation": "rename", "target": "body", "key": "old_field", "new_key": "new_field"},
            {"operation": "remove", "target": "query", "key": "debug"}
        ]
    }))
    .unwrap();

    assert!(plugin.modifies_request_body());

    // Test header/query rules via before_proxy
    let mut ctx = make_ctx();
    ctx.query_params
        .insert("debug".to_string(), "true".to_string());
    let mut headers: HashMap<String, String> = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));
    assert_eq!(headers.get("x-custom").unwrap(), "yes");
    assert!(!ctx.query_params.contains_key("debug"));

    // Test body rules via transform_request_body
    let body = br#"{"old_field":"data"}"#;
    let body_result = plugin
        .transform_request_body(body, Some("application/json"), &HashMap::new())
        .await;
    let transformed: serde_json::Value = serde_json::from_slice(&body_result.unwrap()).unwrap();
    assert_eq!(transformed["new_field"], "data");
}

#[tokio::test]
async fn test_request_transformer_body_non_json_content_type_skipped() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "body", "key": "field", "value": "val"}
        ]
    }))
    .unwrap();

    let body = b"<xml>not json</xml>";
    let result = plugin
        .transform_request_body(body, Some("application/xml"), &HashMap::new())
        .await;
    assert!(result.is_none());
}

#[tokio::test]
async fn test_request_transformer_body_invalid_json_skipped() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "body", "key": "field", "value": "val"}
        ]
    }))
    .unwrap();

    let body = b"this is not json";
    let result = plugin
        .transform_request_body(body, Some("application/json"), &HashMap::new())
        .await;
    assert!(result.is_none());
}

#[tokio::test]
async fn test_request_transformer_body_empty_body_skipped() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "body", "key": "field", "value": "val"}
        ]
    }))
    .unwrap();

    let result = plugin
        .transform_request_body(b"", Some("application/json"), &HashMap::new())
        .await;
    assert!(result.is_none());
}

#[tokio::test]
async fn test_request_transformer_body_no_body_rules_returns_false() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-Custom", "value": "val"}
        ]
    }))
    .unwrap();

    assert!(!plugin.modifies_request_body());
}

#[tokio::test]
async fn test_request_transformer_body_deeply_nested_three_levels() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "update", "target": "body", "key": "a.b.c.d", "value": "deep_value"}
        ]
    }))
    .unwrap();

    let body = br#"{"a":{"b":{"c":{"d":"old"}}}}"#;
    let result = plugin
        .transform_request_body(body, Some("application/json"), &HashMap::new())
        .await;
    let transformed: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    assert_eq!(transformed["a"]["b"]["c"]["d"], "deep_value");
}

#[tokio::test]
async fn test_request_transformer_body_add_creates_intermediate_objects() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "body", "key": "new.nested.field", "value": "created"}
        ]
    }))
    .unwrap();

    let body = br#"{"existing":"keep"}"#;
    let result = plugin
        .transform_request_body(body, Some("application/json"), &HashMap::new())
        .await;
    let transformed: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    assert_eq!(transformed["existing"], "keep");
    assert_eq!(transformed["new"]["nested"]["field"], "created");
}

#[tokio::test]
async fn test_request_transformer_body_numeric_value() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "body", "key": "count", "value": "42"}
        ]
    }))
    .unwrap();

    let body = br#"{}"#;
    let result = plugin
        .transform_request_body(body, Some("application/json"), &HashMap::new())
        .await;
    let transformed: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    // "42" string is parsed as number 42
    assert_eq!(transformed["count"], 42);
}

#[tokio::test]
async fn test_request_transformer_body_boolean_value() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "body", "key": "active", "value": "true"}
        ]
    }))
    .unwrap();

    let body = br#"{}"#;
    let result = plugin
        .transform_request_body(body, Some("application/json"), &HashMap::new())
        .await;
    let transformed: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    assert_eq!(transformed["active"], true);
}

#[tokio::test]
async fn test_request_transformer_body_rename_nonexistent_is_noop() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "rename", "target": "body", "key": "missing", "new_key": "present"}
        ]
    }))
    .unwrap();

    let body = br#"{"name":"Alice"}"#;
    let result = plugin
        .transform_request_body(body, Some("application/json"), &HashMap::new())
        .await;
    // No field was renamed, so no modification — returns None
    assert!(result.is_none());
}

// ── New behaviour: config validation & hot-path fast-path ─────────────────

#[tokio::test]
async fn test_request_transformer_modifies_request_headers_false_for_query_only() {
    // With only query rules, modifies_request_headers() must be false so the
    // handler can skip cloning ctx.headers.
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "query", "key": "v", "value": "1"}
        ]
    }))
    .unwrap();
    assert!(!plugin.modifies_request_headers());
    assert!(!plugin.modifies_request_body());
}

#[tokio::test]
async fn test_request_transformer_modifies_request_headers_false_for_body_only() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "body", "key": "v", "value": "1"}
        ]
    }))
    .unwrap();
    assert!(!plugin.modifies_request_headers());
    assert!(plugin.modifies_request_body());
}

#[tokio::test]
async fn test_request_transformer_modifies_request_headers_true_for_header_rule() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-A", "value": "1"}
        ]
    }))
    .unwrap();
    assert!(plugin.modifies_request_headers());
}

#[tokio::test]
async fn test_request_transformer_rejects_crlf_in_header_value() {
    let err = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-Bad", "value": "ok\r\nX-Inject: evil"}
        ]
    }))
    .err()
    .expect("expected error for CRLF in header value");
    assert!(err.contains("CR or LF"), "got: {err}");
}

#[tokio::test]
async fn test_request_transformer_rejects_body_rule_without_value() {
    let err = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "body", "key": "field"}
        ]
    }))
    .err()
    .expect("expected error for body add without value");
    assert!(err.contains("requires a 'value'"), "got: {err}");
}

#[tokio::test]
async fn test_request_transformer_rejects_body_rule_without_new_key() {
    let err = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "rename", "target": "body", "key": "old"}
        ]
    }))
    .err()
    .expect("expected error for body rename without new_key");
    assert!(err.contains("requires a 'new_key'"), "got: {err}");
}

#[tokio::test]
async fn test_request_transformer_body_array_index() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "update", "target": "body", "key": "items.0.name", "value": "updated"}
        ]
    }))
    .unwrap();
    let body = br#"{"items":[{"name":"a"},{"name":"b"}]}"#;
    let out = plugin
        .transform_request_body(body, Some("application/json"), &HashMap::new())
        .await
        .unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(parsed["items"][0]["name"], "updated");
    assert_eq!(parsed["items"][1]["name"], "b");
}

#[tokio::test]
async fn test_request_transformer_body_dot_escape_in_key() {
    // Key contains a literal dot — escaped as `\.` in the rule key.
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "update", "target": "body", "key": "weird\\.key", "value": "v"}
        ]
    }))
    .unwrap();
    let body = br#"{"weird.key":"old"}"#;
    let out = plugin
        .transform_request_body(body, Some("application/json"), &HashMap::new())
        .await
        .unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(parsed["weird.key"], "v");
}

// ── Strict type validation for config fields ──────────────────────────────

#[tokio::test]
async fn test_request_transformer_rejects_non_string_target() {
    // A numeric/boolean/object target must fail config load, not silently
    // coerce to "header".
    let err = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": 0, "key": "X", "value": "v"}
        ]
    }))
    .err()
    .expect("expected error for non-string target");
    assert!(err.contains("'target' must be a string"), "got: {err}");
}

#[tokio::test]
async fn test_request_transformer_rejects_non_string_operation() {
    let err = RequestTransformer::new(&json!({
        "rules": [
            {"operation": 42, "target": "header", "key": "X", "value": "v"}
        ]
    }))
    .err()
    .expect("expected error for non-string operation");
    assert!(err.contains("'operation' must be a string"), "got: {err}");
}

#[tokio::test]
async fn test_request_transformer_rejects_non_string_key() {
    let err = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": 123, "value": "v"}
        ]
    }))
    .err()
    .expect("expected error for non-string key");
    assert!(err.contains("'key' must be a string"), "got: {err}");
}

#[tokio::test]
async fn test_request_transformer_rejects_invalid_header_key() {
    for key in ["bad header", "x:bad", "x/bad", "x\nbad"] {
        let err = RequestTransformer::new(&json!({
            "rules": [
                {"operation": "add", "target": "header", "key": key, "value": "v"}
            ]
        }))
        .err()
        .unwrap_or_else(|| panic!("expected invalid header key to be rejected: {key:?}"));
        assert!(err.contains("valid HTTP header name"), "got: {err}");
    }
}

#[tokio::test]
async fn test_request_transformer_rejects_non_string_value() {
    let err = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-Count", "value": 42}
        ]
    }))
    .err()
    .expect("expected error for non-string header value");
    assert!(err.contains("'value' must be a string"), "got: {err}");
}

#[tokio::test]
async fn test_request_transformer_rejects_non_string_new_key() {
    let err = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "rename", "target": "header", "key": "X-Old", "new_key": 7}
        ]
    }))
    .err()
    .expect("expected error for non-string new_key");
    assert!(err.contains("'new_key' must be a string"), "got: {err}");
}

#[tokio::test]
async fn test_request_transformer_rejects_invalid_header_new_key() {
    let err = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "rename", "target": "header", "key": "X-Old", "new_key": "bad header"}
        ]
    }))
    .err()
    .expect("expected invalid header new_key to be rejected");
    assert!(err.contains("valid HTTP header name"), "got: {err}");
}

// ── JSON null value preservation on body rules ───────────────────────────

#[tokio::test]
async fn test_request_transformer_body_add_null_value() {
    // Explicit JSON null is a legitimate value — `value: null` on an `add`
    // rule must insert a JSON null into the body (not be treated as "missing
    // value" and reject the config at load time).
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "body", "key": "optional_field", "value": null}
        ]
    }))
    .unwrap();

    let body = br#"{"name":"Alice"}"#;
    let out = plugin
        .transform_request_body(body, Some("application/json"), &HashMap::new())
        .await
        .expect("body should be modified");
    let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert!(parsed["optional_field"].is_null());
    assert_eq!(parsed["name"], "Alice");
}

#[tokio::test]
async fn test_request_transformer_body_update_null_value() {
    // `value: null` on an `update` rule must set the target field to null.
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "update", "target": "body", "key": "status", "value": null}
        ]
    }))
    .unwrap();

    let body = br#"{"status":"active"}"#;
    let out = plugin
        .transform_request_body(body, Some("application/json"), &HashMap::new())
        .await
        .expect("body should be modified");
    let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert!(parsed["status"].is_null());
}

#[tokio::test]
async fn test_request_transformer_rejects_non_string_body_target() {
    // Non-string target must be rejected even for what would be body rules,
    // via the shared `parse_body_rules` validator.
    let err = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": true, "key": "f", "value": "v"}
        ]
    }))
    .err()
    .expect("expected error for non-string target");
    assert!(err.contains("'target' must be a string"), "got: {err}");
}

#[tokio::test]
async fn test_request_transformer_rejects_null_target() {
    // Explicit `"target": null` must fail config load; silently coercing null
    // would mask misconfiguration (typos, broken templating, etc.).
    let err = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": null, "key": "X", "value": "v"}
        ]
    }))
    .err()
    .expect("expected error for null target");
    assert!(err.contains("'target' must be a string"), "got: {err}");
}

#[tokio::test]
async fn test_request_transformer_rejects_missing_target() {
    let err = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "key": "X", "value": "v"}
        ]
    }))
    .err()
    .expect("expected error for missing target");
    assert!(err.contains("'target' is required"), "got: {err}");
}

// ── Route-level transform overrides (`apply_route_overrides`) ──────────────
//
// `mesh_route_dispatch` publishes per-rule Arcs onto
// `ctx.route_override_request_transform`. The transformer plugin always
// consumes them at the end of `before_proxy`. When the proxy has no
// operator-configured `request_transformer`, the K8s VirtualService
// translator auto-emits an instance with `apply_route_overrides: true` and
// no static rules; that instance must still be valid and must declare
// `modifies_request_headers() == true` so the dispatcher clones headers.

use ferrum_edge::plugins::utils::route_header_transform::{
    RawRouteHeaderTransformRule, parse_route_header_transforms,
};
use std::sync::Arc;

#[tokio::test]
async fn test_request_transformer_apply_route_overrides_accepts_empty_rules() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [],
        "apply_route_overrides": true,
    }))
    .expect("apply_route_overrides=true allows zero static rules");
    assert!(
        plugin.modifies_request_headers(),
        "apply_route_overrides=true must declare modifies_request_headers so the dispatcher clones headers"
    );
}

#[tokio::test]
async fn test_request_transformer_empty_rules_without_opt_in_still_errors() {
    let err = RequestTransformer::new(&json!({
        "rules": [],
    }))
    .err()
    .expect("zero rules without apply_route_overrides must error");
    assert!(err.contains("no 'rules' configured"), "got: {err}");
}

#[tokio::test]
async fn test_request_transformer_route_override_applies_after_static_rules() {
    // Static rule sets X-Trace=static; route-level override sets
    // X-Trace=route. Per the documented precedence (static first, then
    // per-rule), the route override must win.
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "update", "target": "header", "key": "X-Trace", "value": "static"}
        ]
    }))
    .unwrap();

    let raw: Vec<RawRouteHeaderTransformRule> = serde_json::from_value(json!([
        {"operation": "update", "target": "header", "key": "X-Trace", "value": "route"}
    ]))
    .unwrap();
    let route_rules = Arc::new(parse_route_header_transforms(&raw, "route_override").unwrap());

    let mut ctx = make_ctx();
    ctx.route_override_request_transform = Some(route_rules);
    let mut headers: HashMap<String, String> = HashMap::new();
    let _ = plugin.before_proxy(&mut ctx, &mut headers).await;

    assert_eq!(headers.get("x-trace").map(String::as_str), Some("route"));
    // Plugin must consume the Arc so a subsequent transformer instance in
    // the chain does not re-apply the same list.
    assert!(ctx.route_override_request_transform.is_none());
}

#[tokio::test]
async fn test_request_transformer_apply_route_overrides_no_static_rules_applies_overrides() {
    // The translator's auto-emitted instance: no static rules, only
    // consumes per-context overrides.
    let plugin = RequestTransformer::new(&json!({
        "rules": [],
        "apply_route_overrides": true,
    }))
    .unwrap();

    let raw: Vec<RawRouteHeaderTransformRule> = serde_json::from_value(json!([
        {"operation": "update", "target": "header", "key": "X-Api-Version", "value": "v1"},
        {"operation": "remove", "target": "header", "key": "X-Debug"},
    ]))
    .unwrap();
    let route_rules = Arc::new(parse_route_header_transforms(&raw, "route_override").unwrap());

    let mut ctx = make_ctx();
    ctx.route_override_request_transform = Some(route_rules);
    let mut headers: HashMap<String, String> = HashMap::new();
    headers.insert("x-debug".to_string(), "yes".to_string());

    let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_eq!(headers.get("x-api-version").map(String::as_str), Some("v1"));
    assert!(!headers.contains_key("x-debug"));
}

#[tokio::test]
async fn test_request_transformer_route_override_absent_is_no_op() {
    // Static rules continue to apply when no per-context override is
    // published — this is the steady-state path on every other request.
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "update", "target": "header", "key": "X-Static", "value": "1"}
        ]
    }))
    .unwrap();
    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();
    let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_eq!(headers.get("x-static").map(String::as_str), Some("1"));
}

#[tokio::test]
async fn test_request_transformer_apply_route_overrides_invalid_type_rejected() {
    let err = RequestTransformer::new(&json!({
        "rules": [],
        "apply_route_overrides": "yes",
    }))
    .err()
    .expect("non-boolean apply_route_overrides must error");
    assert!(err.contains("must be a boolean"), "got: {err}");
}

// === GAP-3E: RTDS overlay gate ===

#[tokio::test]
async fn test_request_transformer_runtime_overlay_scope_accepted() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-Always", "value": "yes"}
        ],
        "runtime_overlay_scope": "internal",
        "default_enabled": true
    }))
    .unwrap();
    assert_eq!(plugin.name(), "request_transformer");
}

#[tokio::test]
async fn test_request_transformer_rejects_empty_runtime_overlay_scope() {
    let err = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-Always", "value": "yes"}
        ],
        "runtime_overlay_scope": "   "
    }))
    .err()
    .unwrap();
    assert!(err.contains("runtime_overlay_scope"));
}

#[tokio::test]
async fn test_request_transformer_rejects_non_bool_default_enabled() {
    let err = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-Always", "value": "yes"}
        ],
        "runtime_overlay_scope": "internal",
        "default_enabled": "true"
    }))
    .err()
    .unwrap();
    assert!(err.contains("default_enabled"));
}

#[test]
fn test_request_transformer_overlay_gate_parsing() {
    use ferrum_edge::modes::mesh::config::{MeshRuntimeOverlay, RuntimeValue};
    use ferrum_edge::plugins::request_transformer::runtime_overlay;

    let _guard = ferrum_edge::modes::mesh::runtime_overlay_consumers::test_lock();
    runtime_overlay::reset_for_test();

    let mut fields = HashMap::new();
    fields.insert(
        "ferrum.request_transformer.public.enabled".to_string(),
        RuntimeValue::Bool(false),
    );
    fields.insert(
        "ferrum.request_transformer.internal.enabled".to_string(),
        RuntimeValue::Bool(true),
    );
    fields.insert(
        "ferrum.request_transformer.bad.enabled".to_string(),
        RuntimeValue::Number(1.0),
    );
    fields.insert(
        "ferrum.request_transformer..enabled".to_string(),
        RuntimeValue::Bool(true),
    );

    runtime_overlay::apply_overlay(&MeshRuntimeOverlay { fields });
    let snap = runtime_overlay::current_gates();
    assert_eq!(snap.gate("public"), Some(false));
    assert_eq!(snap.gate("internal"), Some(true));
    assert_eq!(snap.gate("bad"), None);
    assert_eq!(snap.gate(""), None);
    assert_eq!(snap.gate("missing"), None);

    runtime_overlay::apply_overlay(&MeshRuntimeOverlay::default());
    assert_eq!(runtime_overlay::current_gates().gate("public"), None);
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn test_request_transformer_overlay_gate_observable_end_to_end() {
    // Single test that walks every overlay-gate behaviour serially to
    // avoid racing the process-global `request_transformer::runtime_overlay`
    // ArcSwap from parallel test cases.
    use ferrum_edge::modes::mesh::config::{MeshRuntimeOverlay, RuntimeValue};
    use ferrum_edge::plugins::request_transformer::runtime_overlay;
    let _guard = ferrum_edge::modes::mesh::runtime_overlay_consumers::test_lock();

    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-Gated", "value": "yes"}
        ],
        "runtime_overlay_scope": "gated",
        "default_enabled": true
    }))
    .unwrap();

    // ── Case 1: overlay missing → fallback default_enabled=true applies the rule.
    runtime_overlay::reset_for_test();
    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));
    assert_eq!(headers.get("x-gated").map(String::as_str), Some("yes"));

    // ── Case 2: overlay says enabled=false → rule short-circuited.
    let mut fields = HashMap::new();
    fields.insert(
        "ferrum.request_transformer.gated.enabled".to_string(),
        RuntimeValue::Bool(false),
    );
    runtime_overlay::apply_overlay(&MeshRuntimeOverlay { fields });
    let mut headers: HashMap<String, String> = HashMap::new();
    plugin.before_proxy(&mut make_ctx(), &mut headers).await;
    assert!(
        !headers.contains_key("x-gated"),
        "overlay=false must suppress the rule"
    );

    // ── Case 3: overlay says enabled=true → rule applies.
    let mut fields = HashMap::new();
    fields.insert(
        "ferrum.request_transformer.gated.enabled".to_string(),
        RuntimeValue::Bool(true),
    );
    runtime_overlay::apply_overlay(&MeshRuntimeOverlay { fields });
    let mut headers: HashMap<String, String> = HashMap::new();
    plugin.before_proxy(&mut make_ctx(), &mut headers).await;
    assert_eq!(headers.get("x-gated").map(String::as_str), Some("yes"));

    // ── Case 4: plugin without a scope ignores the overlay entirely.
    runtime_overlay::reset_for_test();
    let no_scope_plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-Plain", "value": "v"}
        ]
    }))
    .unwrap();
    let mut fields = HashMap::new();
    fields.insert(
        "ferrum.request_transformer.gated.enabled".to_string(),
        RuntimeValue::Bool(false),
    );
    runtime_overlay::apply_overlay(&MeshRuntimeOverlay { fields });
    let mut headers: HashMap<String, String> = HashMap::new();
    no_scope_plugin
        .before_proxy(&mut make_ctx(), &mut headers)
        .await;
    assert_eq!(
        headers.get("x-plain").map(String::as_str),
        Some("v"),
        "plugins without runtime_overlay_scope must always apply rules"
    );

    // ── Case 5: default_enabled=false combined with missing overlay
    //           suppresses rules until the overlay flips them on.
    runtime_overlay::reset_for_test();
    let pessimistic_plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-Pess", "value": "v"}
        ],
        "runtime_overlay_scope": "pessimistic",
        "default_enabled": false
    }))
    .unwrap();
    let mut headers: HashMap<String, String> = HashMap::new();
    pessimistic_plugin
        .before_proxy(&mut make_ctx(), &mut headers)
        .await;
    assert!(
        !headers.contains_key("x-pess"),
        "default_enabled=false must suppress when overlay missing"
    );

    let mut fields = HashMap::new();
    fields.insert(
        "ferrum.request_transformer.pessimistic.enabled".to_string(),
        RuntimeValue::Bool(true),
    );
    runtime_overlay::apply_overlay(&MeshRuntimeOverlay { fields });
    let mut headers: HashMap<String, String> = HashMap::new();
    pessimistic_plugin
        .before_proxy(&mut make_ctx(), &mut headers)
        .await;
    assert_eq!(headers.get("x-pess").map(String::as_str), Some("v"));

    runtime_overlay::reset_for_test();
}

// ── Issue #2374: unknown keys, operation-exact fields, HeaderValue admission ──

#[tokio::test]
async fn test_request_transformer_rejects_unknown_top_level_key() {
    let err = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-Color", "value": "blue"}
        ],
        "runtime_overlay_scpoe": "internal"
    }))
    .err()
    .expect("expected error for unknown top-level key");
    assert!(err.contains("unknown config key"), "got: {err}");
    assert!(err.contains("runtime_overlay_scpoe"), "got: {err}");
    assert!(err.contains("under 'config'"), "got: {err}");
}

#[tokio::test]
async fn test_request_transformer_rejects_unknown_header_rule_key() {
    let err = RequestTransformer::new(&json!({
        "rules": [
            {
                "operation": "update",
                "target": "header",
                "key": "X-Color",
                "value": "blue",
                "vaule": "green"
            }
        ]
    }))
    .err()
    .expect("expected error for unknown header rule key");
    assert!(err.contains("unknown config key"), "got: {err}");
    assert!(err.contains("vaule"), "got: {err}");
    assert!(err.contains("config.rules[0]"), "got: {err}");
}

#[tokio::test]
async fn test_request_transformer_rejects_unknown_query_and_body_rule_keys() {
    let query_err = RequestTransformer::new(&json!({
        "rules": [
            {
                "operation": "add",
                "target": "query",
                "key": "color",
                "value": "blue",
                "typo_key": 1
            }
        ]
    }))
    .err()
    .expect("expected error for unknown query rule key");
    assert!(query_err.contains("typo_key"), "got: {query_err}");
    assert!(query_err.contains("config.rules[0]"), "got: {query_err}");

    let body_err = RequestTransformer::new(&json!({
        "rules": [
            {
                "operation": "add",
                "target": "body",
                "key": "enabled",
                "value": true,
                "extra_field": 1
            }
        ]
    }))
    .err()
    .expect("expected error for unknown body rule key");
    assert!(body_err.contains("extra_field"), "got: {body_err}");
    assert!(body_err.contains("config.rules[0]"), "got: {body_err}");
}

#[tokio::test]
async fn test_request_transformer_rejects_incompatible_header_and_query_fields() {
    for (rule, needle) in [
        (
            json!({
                "operation": "add",
                "target": "header",
                "key": "X-Color",
                "value": "blue",
                "new_key": "X-Ignored"
            }),
            "'new_key' must not be set for header 'add'",
        ),
        (
            json!({
                "operation": "update",
                "target": "header",
                "key": "X-Color",
                "value": "blue",
                "new_key": "X-Ignored"
            }),
            "'new_key' must not be set for header 'update'",
        ),
        (
            json!({
                "operation": "rename",
                "target": "header",
                "key": "X-Old",
                "new_key": "X-New",
                "value": "ignored"
            }),
            "'value' must not be set for header 'rename'",
        ),
        (
            json!({
                "operation": "remove",
                "target": "header",
                "key": "X-Color",
                "value": "ignored"
            }),
            "'value' must not be set for header 'remove'",
        ),
        (
            json!({
                "operation": "remove",
                "target": "header",
                "key": "X-Color",
                "new_key": "X-Ignored"
            }),
            "'new_key' must not be set for header 'remove'",
        ),
        (
            json!({
                "operation": "add",
                "target": "query",
                "key": "color",
                "value": "blue",
                "new_key": "ignored"
            }),
            "'new_key' must not be set for query 'add'",
        ),
        (
            json!({
                "operation": "update",
                "target": "query",
                "key": "color",
                "value": "blue",
                "new_key": "ignored"
            }),
            "'new_key' must not be set for query 'update'",
        ),
        (
            json!({
                "operation": "rename",
                "target": "query",
                "key": "old",
                "new_key": "new",
                "value": "ignored"
            }),
            "'value' must not be set for query 'rename'",
        ),
        (
            json!({
                "operation": "remove",
                "target": "query",
                "key": "color",
                "value": "ignored"
            }),
            "'value' must not be set for query 'remove'",
        ),
        (
            json!({
                "operation": "remove",
                "target": "query",
                "key": "color",
                "new_key": "ignored"
            }),
            "'new_key' must not be set for query 'remove'",
        ),
        (
            json!({
                "operation": "add",
                "target": "header",
                "key": "X-Color",
                "value": "blue",
                "new_key": null
            }),
            "'new_key' must not be set for header 'add'",
        ),
        (
            json!({
                "operation": "rename",
                "target": "header",
                "key": "X-Old",
                "new_key": "X-New",
                "value": null
            }),
            "'value' must not be set for header 'rename'",
        ),
        (
            json!({
                "operation": "remove",
                "target": "header",
                "key": "X-Color",
                "value": null
            }),
            "'value' must not be set for header 'remove'",
        ),
        (
            json!({
                "operation": "remove",
                "target": "header",
                "key": "X-Color",
                "new_key": null
            }),
            "'new_key' must not be set for header 'remove'",
        ),
        (
            json!({
                "operation": "add",
                "target": "query",
                "key": "color",
                "value": "blue",
                "new_key": null
            }),
            "'new_key' must not be set for query 'add'",
        ),
        (
            json!({
                "operation": "rename",
                "target": "query",
                "key": "old",
                "new_key": "new",
                "value": null
            }),
            "'value' must not be set for query 'rename'",
        ),
        (
            json!({
                "operation": "remove",
                "target": "query",
                "key": "color",
                "value": null
            }),
            "'value' must not be set for query 'remove'",
        ),
        (
            json!({
                "operation": "remove",
                "target": "query",
                "key": "color",
                "new_key": null
            }),
            "'new_key' must not be set for query 'remove'",
        ),
    ] {
        let err = RequestTransformer::new(&json!({ "rules": [rule] }))
            .err()
            .expect("expected incompatible field rejection");
        assert!(
            err.contains(needle),
            "expected needle {needle:?}, got: {err}"
        );
    }
}

#[tokio::test]
async fn test_request_transformer_rejects_forbidden_header_control_bytes() {
    for (label, value) in [
        ("NUL", "ok\u{0000}bad"),
        ("SOH", "ok\u{0001}bad"),
        ("BEL", "ok\u{0007}bad"),
        ("DEL", "ok\u{007f}bad"),
    ] {
        let err = RequestTransformer::new(&json!({
            "rules": [
                {"operation": "update", "target": "header", "key": "X-Color", "value": value}
            ]
        }))
        .err()
        .unwrap_or_else(|| panic!("expected HeaderValue rejection for {label}"));
        assert!(err.contains("valid HTTP HeaderValue"), "{label}: got {err}");
    }
}

#[tokio::test]
async fn test_request_transformer_accepts_valid_header_value_edge_cases() {
    for value in [
        "",
        " ",
        "\t",
        "plain",
        "a b",
        "tab\there",
        "café",
        "!#$%&'*+-.^_`|~",
    ] {
        let plugin = RequestTransformer::new(&json!({
            "rules": [
                {"operation": "add", "target": "header", "key": "X-Edge", "value": value}
            ]
        }));
        if let Err(error) = plugin {
            panic!("valid HeaderValue edge case rejected: {value:?} -> {error}");
        }
    }
}

#[tokio::test]
async fn test_request_transformer_accepted_values_pass_backend_adapter_gates() {
    // Outbound Hyper / native H3 / reqwest adapters all parse outbound header
    // values through `HeaderValue::from_str` (or the same http type). Values
    // admitted by construction must therefore succeed on every adapter gate.
    let values = [
        "plain",
        "a b",
        "tab\there",
        "café",
        "!#$%&'*+-.^_`|~",
        "",
        " ",
    ];
    for value in values {
        RequestTransformer::new(&json!({
            "rules": [
                {"operation": "update", "target": "header", "key": "X-Parity", "value": value}
            ]
        }))
        .unwrap_or_else(|e| panic!("construction rejected {value:?}: {e}"));

        assert!(
            http::HeaderValue::from_str(value).is_ok(),
            "http HeaderValue rejected admitted value {value:?}"
        );
        assert!(
            hyper::header::HeaderValue::from_str(value).is_ok(),
            "hyper HeaderValue rejected admitted value {value:?}"
        );
        assert!(
            reqwest::header::HeaderValue::from_str(value).is_ok(),
            "reqwest HeaderValue rejected admitted value {value:?}"
        );
    }
}

#[tokio::test]
async fn test_request_transformer_route_level_rejects_invalid_control_values() {
    // Route-level transforms share the same HeaderValue + CR/LF admission gate.
    let crlf: Vec<RawRouteHeaderTransformRule> = serde_json::from_value(json!([
        {"operation": "update", "target": "header", "key": "X-Bad", "value": "a\r\nInjected: 1"}
    ]))
    .unwrap();
    let crlf_err = parse_route_header_transforms(&crlf, "route_override").unwrap_err();
    assert!(crlf_err.contains("CR or LF"), "got: {crlf_err}");

    let nul: Vec<RawRouteHeaderTransformRule> = serde_json::from_value(json!([
        {"operation": "add", "target": "header", "key": "X-Bad", "value": "ok\u{0000}bad"}
    ]))
    .unwrap();
    let nul_err = parse_route_header_transforms(&nul, "route_override").unwrap_err();
    assert!(nul_err.contains("valid HTTP HeaderValue"), "got: {nul_err}");
}

#[tokio::test]
async fn test_request_transformer_route_level_accepted_value_applies() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [],
        "apply_route_overrides": true,
    }))
    .unwrap();

    let raw: Vec<RawRouteHeaderTransformRule> = serde_json::from_value(json!([
        {"operation": "update", "target": "header", "key": "X-Route", "value": "tab\there"}
    ]))
    .unwrap();
    let route_rules = Arc::new(parse_route_header_transforms(&raw, "route_override").unwrap());

    let mut ctx = make_ctx();
    ctx.route_override_request_transform = Some(route_rules);
    let mut headers: HashMap<String, String> = HashMap::new();
    let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_eq!(
        headers.get("x-route").map(String::as_str),
        Some("tab\there")
    );
}

// ── Header mutation tracing must never emit configured values ─────────────

use std::future::Future;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone, Default)]
struct SharedLogWriter(Arc<Mutex<Vec<u8>>>);

impl Write for SharedLogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for SharedLogWriter {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

async fn capture_debug_logs<F, Fut>(operation: F) -> String
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = ()>,
{
    let writer = SharedLogWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(writer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    operation().await;
    String::from_utf8(writer.0.lock().unwrap().clone()).unwrap()
}

fn assert_secret_absent_from_logs(logs: &str, secret: &str) {
    assert!(
        !logs.contains(secret),
        "configured header value must not appear in tracing output: {secret:?}\nlogs:\n{logs}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn test_request_transformer_header_mutations_never_log_configured_values() {
    let cases = [
        (
            "add",
            json!({"operation": "add", "target": "header", "key": "Authorization", "value": "Bearer backend-token-never-log"}),
            HashMap::new(),
            "authorization",
            "Bearer backend-token-never-log",
        ),
        (
            "update",
            json!({"operation": "update", "target": "header", "key": "Set-Cookie", "value": "session=opaque-cookie-never-log"}),
            HashMap::from([("set-cookie".to_string(), "old=discard".to_string())]),
            "set-cookie",
            "session=opaque-cookie-never-log",
        ),
        (
            "api-key add",
            json!({"operation": "add", "target": "header", "key": "X-Api-Key", "value": "api-key-secret-never-log"}),
            HashMap::new(),
            "x-api-key",
            "api-key-secret-never-log",
        ),
        (
            "signature update",
            json!({"operation": "update", "target": "header", "key": "X-Signature", "value": "sha256=sig-never-log"}),
            HashMap::new(),
            "x-signature",
            "sha256=sig-never-log",
        ),
        (
            "custom add",
            json!({"operation": "add", "target": "header", "key": "X-Tenant-Credential", "value": "arbitrary-custom-never-log"}),
            HashMap::new(),
            "x-tenant-credential",
            "arbitrary-custom-never-log",
        ),
    ];

    for (label, rule, mut seed_headers, expected_key, secret) in cases {
        let plugin = RequestTransformer::new(&json!({ "rules": [rule] })).unwrap();
        let logs = capture_debug_logs(|| async {
            let mut ctx = make_ctx();
            let mut headers = std::mem::take(&mut seed_headers);
            let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
            assert_eq!(
                headers.get(expected_key).map(String::as_str),
                Some(secret),
                "{label}: header mutation must still apply"
            );
        })
        .await;
        assert_secret_absent_from_logs(&logs, secret);
        assert!(
            logs.contains("request_transformer:"),
            "{label}: expected transformer debug event, got:\n{logs}"
        );
    }

    // Remove only logs the header name; still exercise it with a sensitive key.
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "remove", "target": "header", "key": "Authorization"}
        ]
    }))
    .unwrap();
    let logs = capture_debug_logs(|| async {
        let mut ctx = make_ctx();
        let mut headers = HashMap::from([(
            "authorization".to_string(),
            "Bearer existing-token-never-log".to_string(),
        )]);
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(!headers.contains_key("authorization"));
    })
    .await;
    assert_secret_absent_from_logs(&logs, "Bearer existing-token-never-log");
    assert!(
        logs.contains("request_transformer: removed header authorization"),
        "remove should still emit a name-only diagnostic"
    );
}
