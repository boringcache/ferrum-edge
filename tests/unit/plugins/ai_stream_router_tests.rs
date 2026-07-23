//! Unit tests for the `ai_stream_router` plugin.

use super::plugin_utils::create_test_proxy;
use ferrum_edge::config::types::{BackendScheme, BackendTlsConfig};
use ferrum_edge::plugins::ai_federation::AiFederation;
use ferrum_edge::plugins::ai_stream_router::AiStreamRouter;
use ferrum_edge::plugins::{
    HTTP_ONLY_PROTOCOLS, Plugin, PluginHttpClient, PluginResult, RequestContext,
    ResponseStreamAction, ResponseStreamInspector, ResponseStreamInspectorStage,
    chain_response_stream_inspectors, priority, validate_plugin_config,
};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn http_client() -> PluginHttpClient {
    PluginHttpClient::default()
}

fn build(config: Value) -> AiStreamRouter {
    AiStreamRouter::new(&config, http_client()).expect("config should be valid")
}

fn openai_and_anthropic_config() -> Value {
    json!({
        "enabled": true,
        "providers": [
            {
                "name": "openai",
                "provider_type": "openai",
                "endpoint": "https://api.openai.com/v1/chat/completions",
                "api_key": "sk-openai-secret",
                "model_patterns": ["gpt-*", "o*"],
                "priority": 1
            },
            {
                "name": "anthropic",
                "provider_type": "anthropic",
                "endpoint": "https://api.anthropic.com/v1/messages",
                "api_key": "sk-ant-secret",
                "model_patterns": ["claude-*"],
                "priority": 2,
                "anthropic_version": "2023-06-01"
            }
        ]
    })
}

fn json_headers() -> HashMap<String, String> {
    let mut h = HashMap::new();
    h.insert("content-type".to_string(), "application/json".to_string());
    h
}

fn post_ctx(body: &Value) -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/v1/chat/completions".to_string(),
    );
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx.metadata.insert(
        "request_body".to_string(),
        serde_json::to_string(body).unwrap(),
    );
    ctx
}

async fn run_federation_final_body(
    plugin: &AiFederation,
    ctx: &mut RequestContext,
    headers: &HashMap<String, String>,
) -> PluginResult {
    let body = ctx
        .metadata
        .get("request_body")
        .cloned()
        .unwrap_or_default();
    plugin
        .on_final_request_body_with_context(ctx, headers, body.as_bytes())
        .await
}

fn reject_status(r: &PluginResult) -> Option<u16> {
    match r {
        PluginResult::Reject { status_code, .. } => Some(*status_code),
        PluginResult::RejectBinary { status_code, .. } => Some(*status_code),
        PluginResult::Continue => None,
    }
}

fn forwarded(action: ResponseStreamAction) -> Vec<u8> {
    match action {
        ResponseStreamAction::Forward(b) => b.to_vec(),
        ResponseStreamAction::Terminate(b) => b.map(|b| b.to_vec()).unwrap_or_default(),
    }
}

/// Test guardrail that cuts if provider-native Anthropic framing reaches it.
/// Its default stage is `Inspect`, so the chain must move a normalizer supplied
/// later in the vector ahead of it.
struct RejectProviderNative {
    saw_normalized: Arc<AtomicBool>,
}

#[async_trait::async_trait]
impl ResponseStreamInspector for RejectProviderNative {
    async fn on_chunk(&mut self, chunk: &[u8]) -> ResponseStreamAction {
        if chunk
            .windows(b"chat.completion.chunk".len())
            .any(|window| window == b"chat.completion.chunk")
        {
            self.saw_normalized.store(true, Ordering::SeqCst);
        }
        if chunk
            .windows(b"content_block_delta".len())
            .any(|window| window == b"content_block_delta")
        {
            ResponseStreamAction::Terminate(None)
        } else {
            ResponseStreamAction::Forward(bytes::Bytes::copy_from_slice(chunk))
        }
    }
}

/// Replace the time-based `"created":<n>` field with a fixed value so two
/// separately-timed normalizer runs are comparable.
fn strip_created(s: &str) -> String {
    const KEY: &str = "\"created\":";
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(idx) = rest.find(KEY) {
        out.push_str(&rest[..idx]);
        out.push_str("\"created\":0");
        rest = &rest[idx + KEY.len()..];
        let skip = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        rest = &rest[skip..];
    }
    out.push_str(rest);
    out
}

// ---------------------------------------------------------------------------
// Config validation
// ---------------------------------------------------------------------------

#[test]
fn test_valid_config_parses() {
    let plugin = build(openai_and_anthropic_config());
    assert_eq!(plugin.name(), "ai_stream_router");
    assert_eq!(plugin.priority(), priority::AI_STREAM_ROUTER);
    assert_eq!(plugin.priority(), 2984);
    assert_eq!(plugin.supported_protocols(), HTTP_ONLY_PROTOCOLS);
    assert!(plugin.requires_request_body_before_before_proxy());
    assert!(plugin.modifies_request_headers());
    assert!(plugin.modifies_request_body());
    assert!(plugin.needs_final_request_body_context());
    // An anthropic provider with normalization on wires the response-stream hook.
    assert!(plugin.requires_response_stream_hooks());
}

#[test]
fn test_config_must_be_object() {
    let err = AiStreamRouter::new(&json!([]), http_client())
        .err()
        .unwrap();
    assert!(err.contains("must be an object"), "{err}");
}

#[test]
fn test_config_rejects_empty_providers() {
    let err = AiStreamRouter::new(&json!({ "providers": [] }), http_client())
        .err()
        .unwrap();
    assert!(err.contains("must not be empty"), "{err}");
}

#[test]
fn test_config_rejects_missing_providers() {
    let err = AiStreamRouter::new(&json!({ "enabled": true }), http_client())
        .err()
        .unwrap();
    assert!(err.contains("providers"), "{err}");
}

#[test]
fn test_shared_validation_rejects_invalid_ai_stream_router_config() {
    let err = validate_plugin_config("ai_stream_router", &json!({"enabled": true}))
        .expect_err("shared plugin validation must require a providers array");
    assert_eq!(
        err,
        "ai_stream_router: 'providers' must be a non-empty array"
    );
}

#[test]
fn test_config_rejects_unknown_provider_type() {
    let cfg = json!({
        "providers": [{
            "name": "p", "provider_type": "cohere",
            "endpoint": "https://x.example.com/v1", "api_key": "k",
            "model_patterns": ["*"]
        }]
    });
    let err = AiStreamRouter::new(&cfg, http_client()).err().unwrap();
    assert!(err.contains("unknown provider_type"), "{err}");
}

#[test]
fn test_config_rejects_duplicate_provider_names() {
    let cfg = json!({
        "providers": [
            {"name": "dup", "provider_type": "openai", "endpoint": "https://a.example.com/v1", "api_key": "k", "model_patterns": ["gpt-*"]},
            {"name": "dup", "provider_type": "anthropic", "endpoint": "https://b.example.com/v1", "api_key": "k", "model_patterns": ["claude-*"]}
        ]
    });
    let err = AiStreamRouter::new(&cfg, http_client()).err().unwrap();
    assert!(err.contains("duplicate provider name"), "{err}");
}

#[test]
fn test_config_rejects_malformed_endpoint() {
    let cfg = json!({
        "providers": [{
            "name": "p", "provider_type": "openai",
            "endpoint": "not-a-url", "api_key": "k", "model_patterns": ["gpt-*"]
        }]
    });
    let err = AiStreamRouter::new(&cfg, http_client()).err().unwrap();
    assert!(
        err.contains("invalid endpoint") || err.contains("no host"),
        "{err}"
    );
}

#[test]
fn test_config_rejects_plaintext_endpoint_by_default() {
    let cfg = json!({
        "providers": [{
            "name": "p", "provider_type": "openai",
            "endpoint": "http://api.example.com/v1", "api_key": "k", "model_patterns": ["gpt-*"]
        }]
    });
    let err = AiStreamRouter::new(&cfg, http_client()).err().unwrap();
    assert!(err.contains("http://"), "{err}");
}

#[test]
fn test_config_allows_plaintext_endpoint_with_optin() {
    let cfg = json!({
        "providers": [{
            "name": "p", "provider_type": "openai",
            "endpoint": "http://api.example.com/v1", "api_key": "k",
            "model_patterns": ["gpt-*"], "allow_plaintext": true
        }]
    });
    assert!(AiStreamRouter::new(&cfg, http_client()).is_ok());
}

#[test]
fn test_config_requires_non_empty_model_patterns() {
    let cfg = json!({
        "providers": [{
            "name": "p", "provider_type": "openai",
            "endpoint": "https://a.example.com/v1", "api_key": "k", "model_patterns": []
        }]
    });
    let err = AiStreamRouter::new(&cfg, http_client()).err().unwrap();
    assert!(err.contains("model_patterns"), "{err}");
}

#[test]
fn test_config_rejects_zero_priority() {
    let cfg = json!({
        "providers": [{
            "name": "p", "provider_type": "openai",
            "endpoint": "https://a.example.com/v1", "api_key": "k",
            "model_patterns": ["gpt-*"], "priority": 0
        }]
    });
    let err = AiStreamRouter::new(&cfg, http_client()).err().unwrap();
    assert!(err.contains("positive"), "{err}");
}

#[test]
fn test_config_rejects_missing_api_key() {
    let cfg = json!({
        "providers": [{
            "name": "p", "provider_type": "openai",
            "endpoint": "https://a.example.com/v1", "model_patterns": ["gpt-*"]
        }]
    });
    let err = AiStreamRouter::new(&cfg, http_client()).err().unwrap();
    assert!(err.contains("api_key"), "{err}");
}

#[test]
fn test_config_google_gemini_not_yet_implemented() {
    let cfg = json!({
        "providers": [{
            "name": "gemini", "provider_type": "google_gemini",
            "endpoint": "https://generativelanguage.googleapis.com/v1beta/models/{model}:streamGenerateContent",
            "api_key": "k", "model_patterns": ["gemini-*"]
        }]
    });
    let err = AiStreamRouter::new(&cfg, http_client()).err().unwrap();
    assert!(err.contains("not yet implemented"), "{err}");
}

#[test]
fn test_config_rejects_ambiguous_federation_fields() {
    for field in [
        "stream",
        "streaming",
        "fallback_enabled",
        "fallback_on_status_codes",
    ] {
        let cfg = json!({
            field: true,
            "providers": [{"name": "p", "provider_type": "openai", "endpoint": "https://a.example.com/v1", "api_key": "k", "model_patterns": ["gpt-*"]}]
        });
        let err = AiStreamRouter::new(&cfg, http_client()).err().unwrap();
        assert!(
            err.contains(field) && err.contains("unsupported field"),
            "field {field}: {err}"
        );
    }
}

fn valid_provider() -> Value {
    json!({
        "name": "p",
        "provider_type": "openai",
        "endpoint": "https://a.example.com/v1/chat/completions",
        "api_key": "k",
        "model_patterns": ["gpt-*"]
    })
}

#[test]
fn test_config_rejects_unknown_root_keys_with_path_and_suggestion() {
    let mut cfg = json!({
        "enabeld": false,
        "providers": [valid_provider()]
    });
    let err = AiStreamRouter::new(&cfg, http_client()).err().unwrap();
    assert!(
        err.contains("unknown configuration key")
            && err.contains("'config.enabeld'")
            && err.contains("did you mean 'enabled'"),
        "{err}"
    );

    // Misspelled enablement must not silently leave the router enabled.
    assert!(
        validate_plugin_config("ai_stream_router", &cfg).is_err(),
        "shared admission must reject enablement typos"
    );

    cfg = json!({
        "fail_on_missing_mode": false,
        "inject_usage_option": false,
        "normalize_response_strem": false,
        "providers": [valid_provider()]
    });
    let err = AiStreamRouter::new(&cfg, http_client()).err().unwrap();
    assert!(err.contains("'config.fail_on_missing_mode'"), "{err}");
    assert!(err.contains("'config.inject_usage_option'"), "{err}");
    assert!(err.contains("'config.normalize_response_strem'"), "{err}");
    assert!(
        err.contains("did you mean 'fail_on_missing_model'")
            || err.contains("did you mean 'inject_usage_options'")
            || err.contains("did you mean 'normalize_response_stream'"),
        "{err}"
    );
}

#[test]
fn test_config_rejects_unknown_provider_and_fallback_keys() {
    let cfg = json!({
        "providers": [{
            "name": "p",
            "provider_type": "openai",
            "endpoint": "https://a.example.com/v1/chat/completions",
            "api_key": "k",
            "model_patterns": ["gpt-*"],
            "inherit_backend_tl": true,
            "allow_plaintex": true
        }]
    });
    let err = AiStreamRouter::new(&cfg, http_client()).err().unwrap();
    assert!(
        err.contains("'config.providers[0].allow_plaintex'"),
        "{err}"
    );
    assert!(
        err.contains("'config.providers[0].inherit_backend_tl'"),
        "{err}"
    );
    assert!(
        err.contains("did you mean 'allow_plaintext'")
            || err.contains("did you mean 'inherit_backend_tls'"),
        "{err}"
    );

    let cfg = json!({
        "providers": [valid_provider()],
        "fallback": {
            "enabled": true,
            "on_connect_erro": false,
            "max_attemps": 3
        }
    });
    let err = AiStreamRouter::new(&cfg, http_client()).err().unwrap();
    assert!(err.contains("'config.fallback.on_connect_erro'"), "{err}");
    assert!(err.contains("'config.fallback.max_attemps'"), "{err}");
    assert!(
        err.contains("did you mean 'on_connect_error'")
            || err.contains("did you mean 'max_attempts'"),
        "{err}"
    );
}

#[test]
fn test_shared_admission_and_failure_policy_for_unknown_keys() {
    use ferrum_edge::plugins::{PluginFailurePolicy, plugin_failure_policy};

    let err = validate_plugin_config(
        "ai_stream_router",
        &json!({
            "enabeld": false,
            "providers": [valid_provider()]
        }),
    )
    .expect_err("shared plugin validation must reject unknown keys");
    assert!(
        err.contains("'config.enabeld'") && err.contains("did you mean 'enabled'"),
        "{err}"
    );
    assert_eq!(
        plugin_failure_policy("ai_stream_router"),
        Some(PluginFailurePolicy::FailClosed)
    );
}

#[test]
fn test_disabled_plugin_does_not_wire_hooks() {
    let mut cfg = openai_and_anthropic_config();
    cfg["enabled"] = json!(false);
    let plugin = build(cfg);
    assert!(!plugin.requires_response_stream_hooks());
    assert!(!plugin.modifies_request_headers());
}

// ---------------------------------------------------------------------------
// before_proxy claim / pass-through
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_non_streaming_request_continues() {
    let plugin = build(openai_and_anthropic_config());
    let body = json!({"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]});
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    let res = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(res, PluginResult::Continue));
    // Not claimed → no route override, no coordination marker.
    assert!(ctx.route_override_backend_host.is_none());
    assert!(!ctx.metadata.contains_key("ai_stream_router_claimed"));
}

#[tokio::test]
async fn test_non_post_continues() {
    let plugin = build(openai_and_anthropic_config());
    let body = json!({"model": "gpt-4o", "stream": true, "messages": []});
    let mut ctx = post_ctx(&body);
    ctx.method = "GET".to_string();
    let mut headers = json_headers();
    let res = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(res, PluginResult::Continue));
    assert!(ctx.route_override_backend_host.is_none());
}

#[tokio::test]
async fn test_streaming_missing_model_rejects_by_default() {
    let plugin = build(openai_and_anthropic_config());
    let body = json!({"stream": true, "messages": [{"role": "user", "content": "hi"}]});
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    let res = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_eq!(reject_status(&res), Some(400));
}

#[tokio::test]
async fn test_streaming_missing_model_continues_when_opted_out() {
    let mut cfg = openai_and_anthropic_config();
    cfg["fail_on_missing_model"] = json!(false);
    let plugin = build(cfg);
    let body = json!({"stream": true, "messages": []});
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    let res = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(res, PluginResult::Continue));
    assert_eq!(
        ctx.metadata
            .get("ai_stream_router_pass_through")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        ctx.metadata.get("ai_request_streaming").map(String::as_str),
        Some("true")
    );
}

#[tokio::test]
async fn test_no_matching_provider_rejects_by_default() {
    let plugin = build(openai_and_anthropic_config());
    let body = json!({"model": "llama-3", "stream": true, "messages": []});
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    let res = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_eq!(reject_status(&res), Some(404));
}

#[tokio::test]
async fn test_no_matching_provider_continues_when_opted_out() {
    let mut cfg = openai_and_anthropic_config();
    cfg["fail_on_no_matching_provider"] = json!(false);
    let plugin = build(cfg);
    let body = json!({"model": "llama-3", "stream": true, "messages": []});
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    let res = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(res, PluginResult::Continue));
    assert_eq!(
        ctx.metadata
            .get("ai_stream_router_pass_through")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        ctx.metadata.get("ai_request_streaming").map(String::as_str),
        Some("true")
    );
}

#[tokio::test]
async fn test_model_selection_picks_lowest_priority_value() {
    // Two providers both match "gpt-4o"; the lower priority value wins.
    let cfg = json!({
        "providers": [
            {"name": "secondary", "provider_type": "openai", "endpoint": "https://b.example.com/v1", "api_key": "k2", "model_patterns": ["gpt-*"], "priority": 5},
            {"name": "primary", "provider_type": "openai", "endpoint": "https://a.example.com/v1", "api_key": "k1", "model_patterns": ["gpt-4*"], "priority": 1}
        ]
    });
    let plugin = build(cfg);
    let body = json!({"model": "gpt-4o", "stream": true, "messages": []});
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    let res = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(res, PluginResult::Continue));
    assert_eq!(
        ctx.metadata
            .get("ai_stream_router.provider")
            .map(String::as_str),
        Some("primary")
    );
    assert_eq!(
        ctx.route_override_backend_host.as_deref(),
        Some("a.example.com")
    );
}

#[tokio::test]
async fn test_route_override_and_metadata_set_for_openai() {
    let plugin = build(openai_and_anthropic_config());
    let body = json!({"model": "gpt-4o", "stream": true, "messages": []});
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    let res = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(res, PluginResult::Continue));

    assert!(matches!(
        ctx.route_override_backend_scheme,
        Some(BackendScheme::Https)
    ));
    assert_eq!(
        ctx.route_override_backend_host.as_deref(),
        Some("api.openai.com")
    );
    assert_eq!(ctx.route_override_backend_port, Some(443));
    assert_eq!(
        ctx.route_override_path.as_deref(),
        Some("/v1/chat/completions")
    );
    assert!(ctx.route_override_path_is_absolute);
    assert_eq!(
        ctx.route_override_authority.as_deref(),
        Some("api.openai.com")
    );
    assert!(ctx.route_override_resolved_tls.is_some());

    // Provider auth injected, host set.
    assert_eq!(
        headers.get("authorization").map(String::as_str),
        Some("Bearer sk-openai-secret")
    );
    assert_eq!(
        headers.get("host").map(String::as_str),
        Some("api.openai.com")
    );

    // Metadata contract.
    assert_eq!(
        ctx.metadata
            .get("ai_stream_router.enabled")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        ctx.metadata
            .get("ai_stream_router.claimed")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        ctx.metadata
            .get("ai_stream_router_claimed")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        ctx.metadata
            .get("ai_stream_router.provider")
            .map(String::as_str),
        Some("openai")
    );
    assert_eq!(
        ctx.metadata
            .get("ai_stream_router.provider_type")
            .map(String::as_str),
        Some("openai")
    );
    assert_eq!(
        ctx.metadata
            .get("ai_stream_router.model")
            .map(String::as_str),
        Some("gpt-4o")
    );
    // OpenAI passthrough is not normalized.
    assert_eq!(
        ctx.metadata
            .get("ai_stream_router.normalized_response_stream")
            .map(String::as_str),
        Some("false")
    );
    assert_eq!(
        ctx.metadata
            .get("ai_stream_router.fallback_attempts")
            .map(String::as_str),
        Some("0")
    );
}

#[tokio::test]
async fn test_client_credentials_are_not_leaked() {
    let plugin = build(openai_and_anthropic_config());
    let body = json!({"model": "claude-3-5-sonnet", "stream": true, "messages": []});
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    // Client sends its own credentials — these must be stripped.
    headers.insert(
        "authorization".to_string(),
        "Bearer CLIENT-SECRET".to_string(),
    );
    headers.insert("x-api-key".to_string(), "CLIENT-KEY".to_string());
    headers.insert(
        "openai-organization".to_string(),
        "org-attacker".to_string(),
    );
    headers.insert("openai-project".to_string(), "proj-attacker".to_string());
    headers.insert("openai-beta".to_string(), "assistants=v2".to_string());
    headers.insert("anthropic-beta".to_string(), "tools-2024-04-04".to_string());

    let res = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(res, PluginResult::Continue));

    // Anthropic uses x-api-key; the client Authorization must be gone entirely.
    assert!(
        !headers.contains_key("authorization"),
        "client Authorization leaked"
    );
    assert_eq!(
        headers.get("x-api-key").map(String::as_str),
        Some("sk-ant-secret")
    );
    assert_ne!(
        headers.get("x-api-key").map(String::as_str),
        Some("CLIENT-KEY")
    );
    assert_eq!(
        headers.get("anthropic-version").map(String::as_str),
        Some("2023-06-01")
    );
    assert!(!headers.contains_key("openai-organization"));
    assert!(!headers.contains_key("openai-project"));
    assert!(!headers.contains_key("openai-beta"));
    assert!(!headers.contains_key("anthropic-beta"));
}

// ---------------------------------------------------------------------------
// Request body transformation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_openai_body_injects_include_usage_when_enabled() {
    let plugin = build(openai_and_anthropic_config());
    let body =
        json!({"model": "gpt-4o", "stream": true, "messages": [{"role": "user", "content": "hi"}]});
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let raw = serde_json::to_vec(&body).unwrap();
    let out = plugin
        .transform_request_body_with_context(&mut ctx, &raw, Some("application/json"), &headers)
        .await
        .expect("openai body should be rewritten to inject usage");
    let parsed: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(parsed["stream_options"]["include_usage"], json!(true));
}

#[tokio::test]
async fn test_openai_body_not_rewritten_when_injection_disabled() {
    let mut cfg = openai_and_anthropic_config();
    cfg["inject_usage_options"] = json!(false);
    let plugin = build(cfg);
    let body = json!({"model": "gpt-4o", "stream": true, "messages": []});
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let raw = serde_json::to_vec(&body).unwrap();
    let out = plugin
        .transform_request_body_with_context(&mut ctx, &raw, Some("application/json"), &headers)
        .await;
    assert!(out.is_none(), "openai body should pass through unchanged");
}

#[tokio::test]
async fn test_anthropic_body_translation() {
    let plugin = build(openai_and_anthropic_config());
    let body = json!({
        "model": "claude-3-5-sonnet",
        "stream": true,
        "max_tokens": 256,
        "temperature": 0.5,
        "messages": [
            {"role": "system", "content": "You are helpful."},
            {"role": "user", "content": "Hello"},
            {"role": "assistant", "content": "Hi there"},
            {"role": "user", "content": [{"type": "text", "text": "How are you?"}]}
        ]
    });
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let raw = serde_json::to_vec(&body).unwrap();
    let out = plugin
        .transform_request_body_with_context(&mut ctx, &raw, Some("application/json"), &headers)
        .await
        .expect("anthropic body should be translated");
    let parsed: Value = serde_json::from_slice(&out).unwrap();

    assert_eq!(parsed["model"], json!("claude-3-5-sonnet"));
    assert_eq!(parsed["max_tokens"], json!(256));
    assert_eq!(parsed["temperature"], json!(0.5));
    assert_eq!(parsed["stream"], json!(true));
    assert_eq!(parsed["system"], json!("You are helpful."));

    let messages = parsed["messages"].as_array().unwrap();
    // System is lifted out; only user/assistant remain.
    assert_eq!(messages.len(), 3);
    assert_eq!(messages[0]["role"], json!("user"));
    assert_eq!(messages[0]["content"], json!("Hello"));
    assert_eq!(messages[1]["role"], json!("assistant"));
    assert_eq!(messages[1]["content"], json!("Hi there"));
    // Array-of-text content is flattened to a string.
    assert_eq!(messages[2]["content"], json!("How are you?"));
}

#[tokio::test]
async fn test_anthropic_tools_translation() {
    let plugin = build(openai_and_anthropic_config());
    let body = json!({
        "model": "claude-3-5-sonnet",
        "stream": true,
        "messages": [{"role": "user", "content": "weather?"}],
        "tools": [{
            "type": "function",
            "function": {
                "name": "get_weather",
                "description": "Get weather",
                "parameters": {"type": "object", "properties": {"location": {"type": "string"}}}
            }
        }],
        "tool_choice": "auto"
    });
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let raw = serde_json::to_vec(&body).unwrap();
    let out = plugin
        .transform_request_body_with_context(&mut ctx, &raw, Some("application/json"), &headers)
        .await
        .unwrap();
    let parsed: Value = serde_json::from_slice(&out).unwrap();
    let tools = parsed["tools"].as_array().unwrap();
    assert_eq!(tools[0]["name"], json!("get_weather"));
    assert_eq!(tools[0]["description"], json!("Get weather"));
    assert_eq!(tools[0]["input_schema"]["type"], json!("object"));
    assert_eq!(parsed["tool_choice"], json!({"type": "auto"}));
}

#[tokio::test]
async fn test_transform_skips_unclaimed_request() {
    let plugin = build(openai_and_anthropic_config());
    // No before_proxy run → no claimed metadata.
    let mut ctx = RequestContext::new("127.0.0.1".into(), "POST".into(), "/".into());
    let raw = br#"{"model":"gpt-4o","stream":true}"#;
    let out = plugin
        .transform_request_body_with_context(
            &mut ctx,
            raw,
            Some("application/json"),
            &json_headers(),
        )
        .await;
    assert!(out.is_none());
}

// ---------------------------------------------------------------------------
// Response-stream normalization
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_forces_reqwest_dispatch_only_for_normalized_requests() {
    let plugin = build(openai_and_anthropic_config());

    // Anthropic (normalized) → forces reqwest dispatch.
    let claude = json!({"model": "claude-3-5-sonnet", "stream": true, "messages": []});
    let mut ctx = post_ctx(&claude);
    let mut headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_eq!(
        ctx.metadata
            .get("ai_stream_router.normalized_response_stream")
            .map(String::as_str),
        Some("true")
    );
    assert!(plugin.forces_reqwest_dispatch(&ctx));

    // OpenAI passthrough → no forcing.
    let gpt = json!({"model": "gpt-4o", "stream": true, "messages": []});
    let mut ctx2 = post_ctx(&gpt);
    let mut headers2 = json_headers();
    plugin.before_proxy(&mut ctx2, &mut headers2).await;
    assert!(!plugin.forces_reqwest_dispatch(&ctx2));
}

#[tokio::test]
async fn test_inspector_gating() {
    let plugin = build(openai_and_anthropic_config());
    let claude = json!({"model": "claude-3-5-sonnet", "stream": true, "messages": []});
    let mut ctx = post_ctx(&claude);
    let mut headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    // 2xx event-stream → inspector present.
    assert!(
        plugin
            .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
            .is_some()
    );
    // Non-2xx → none (error envelope reaches client untouched).
    assert!(
        plugin
            .response_stream_inspector(&ctx, 500, Some("text/event-stream"))
            .is_none()
    );
    // Non-SSE → none.
    assert!(
        plugin
            .response_stream_inspector(&ctx, 200, Some("application/json"))
            .is_none()
    );

    // OpenAI passthrough → no inspector even for a 2xx event-stream.
    let gpt = json!({"model": "gpt-4o", "stream": true, "messages": []});
    let mut ctx2 = post_ctx(&gpt);
    let mut headers2 = json_headers();
    plugin.before_proxy(&mut ctx2, &mut headers2).await;
    assert!(
        plugin
            .response_stream_inspector(&ctx2, 200, Some("text/event-stream"))
            .is_none()
    );
}

#[tokio::test]
async fn test_stream_normalizer_stage_precedes_policy_inspection() {
    let plugin = build(openai_and_anthropic_config());
    let claude = json!({"model": "claude-3-5-sonnet", "stream": true, "messages": []});
    let mut ctx = post_ctx(&claude);
    let mut headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let normalizer = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("normalizer");
    assert_eq!(normalizer.stage(), ResponseStreamInspectorStage::Normalize);

    // Deliberately supply the policy inspector first. Stage ordering must still
    // normalize before it, without hard-coding plugin names or changing
    // request-side priority semantics.
    let saw_normalized = Arc::new(AtomicBool::new(false));
    let mut chain = chain_response_stream_inspectors(vec![
        Box::new(RejectProviderNative {
            saw_normalized: Arc::clone(&saw_normalized),
        }),
        normalizer,
    ])
    .expect("chained inspectors");
    let output = match chain.on_chunk(ANTHROPIC_SSE.as_bytes()).await {
        ResponseStreamAction::Forward(output) | ResponseStreamAction::Terminate(Some(output)) => {
            output
        }
        ResponseStreamAction::Terminate(None) => {
            panic!("normalizer terminated without releasing OpenAI SSE")
        }
    };
    let output = String::from_utf8(output.to_vec()).expect("normalized UTF-8 SSE");
    assert!(output.contains("chat.completion.chunk"));
    assert!(!output.contains("content_block_delta"));
    assert!(
        saw_normalized.load(Ordering::SeqCst),
        "the downstream policy inspector must receive the normalizer's terminal window"
    );
}

const ANTHROPIC_SSE: &str = concat!(
    "event: message_start\n",
    "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_123\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-3-5-sonnet\",\"content\":[],\"stop_reason\":null,\"usage\":{\"input_tokens\":10,\"output_tokens\":1}}}\n\n",
    "event: content_block_start\n",
    "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
    "event: ping\n",
    "data: {\"type\":\"ping\"}\n\n",
    "event: content_block_delta\n",
    "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}\n\n",
    "event: content_block_delta\n",
    "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\" world\"}}\n\n",
    "event: content_block_stop\n",
    "data: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
    "event: message_delta\n",
    "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":5}}\n\n",
    "event: message_stop\n",
    "data: {\"type\":\"message_stop\"}\n\n",
);

async fn run_normalizer(chunk_size: usize) -> String {
    let plugin = build(openai_and_anthropic_config());
    let claude = json!({"model": "claude-3-5-sonnet", "stream": true, "messages": []});
    let mut ctx = post_ctx(&claude);
    let mut headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    let mut inspector: Box<dyn ResponseStreamInspector> = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector should be created");

    let mut collected = Vec::new();
    for chunk in ANTHROPIC_SSE.as_bytes().chunks(chunk_size) {
        collected.extend_from_slice(&forwarded(inspector.on_chunk(chunk).await));
    }
    collected.extend_from_slice(&forwarded(inspector.on_end().await));
    String::from_utf8(collected).unwrap()
}

#[tokio::test]
async fn test_anthropic_sse_normalized_to_openai_chunks() {
    let out = run_normalizer(4096).await;

    assert!(
        out.contains("chat.completion.chunk"),
        "missing chunk object: {out}"
    );
    assert!(
        out.contains("\"role\":\"assistant\""),
        "missing role delta: {out}"
    );
    assert!(
        out.contains("\"content\":\"Hello\""),
        "missing first content: {out}"
    );
    assert!(
        out.contains("\"content\":\" world\""),
        "missing second content: {out}"
    );
    assert!(
        out.contains("\"finish_reason\":\"stop\""),
        "missing finish reason: {out}"
    );
    assert!(
        out.contains("\"prompt_tokens\":10"),
        "missing prompt tokens: {out}"
    );
    assert!(
        out.contains("\"completion_tokens\":5"),
        "missing completion tokens: {out}"
    );
    assert!(
        out.contains("\"total_tokens\":15"),
        "missing total tokens: {out}"
    );
    assert!(
        out.trim_end().ends_with("data: [DONE]"),
        "missing DONE terminator: {out}"
    );

    // Every emitted data line (except [DONE]) must be valid JSON.
    for line in out.lines() {
        if let Some(rest) = line.strip_prefix("data: ") {
            if rest == "[DONE]" {
                continue;
            }
            serde_json::from_str::<Value>(rest)
                .unwrap_or_else(|e| panic!("emitted non-JSON SSE data line `{rest}`: {e}"));
        }
    }
}

#[tokio::test]
async fn test_anthropic_sse_robust_to_chunk_splits() {
    // A tiny chunk size forces mid-event and mid-line boundaries.
    let split = run_normalizer(7).await;
    let whole = run_normalizer(4096).await;
    // Identical output (modulo the time-based `created` field) regardless of how
    // the provider stream is chunked.
    assert_eq!(
        strip_created(&split),
        strip_created(&whole),
        "normalizer output must be chunk-boundary independent"
    );
    assert!(split.contains("\"content\":\"Hello\""));
    assert!(split.trim_end().ends_with("data: [DONE]"));
}

#[tokio::test]
async fn test_buffered_anthropic_sse_is_normalized_too() {
    let plugin = build(openai_and_anthropic_config());
    let claude = json!({"model": "claude-3-5-sonnet", "stream": true, "messages": []});
    let mut ctx = post_ctx(&claude);
    let mut headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let buffered = plugin
        .normalize_response_body_with_context(
            &mut ctx,
            200,
            ANTHROPIC_SSE.as_bytes(),
            Some("text/event-stream"),
            &HashMap::new(),
        )
        .await
        .expect("buffered Anthropic SSE should be normalized");
    let buffered = String::from_utf8(buffered).unwrap();
    let streamed = run_normalizer(4096).await;

    assert_eq!(strip_created(&buffered), strip_created(&streamed));
    assert!(buffered.contains("chat.completion.chunk"));
    assert!(buffered.trim_end().ends_with("data: [DONE]"));

    assert!(
        plugin
            .normalize_response_body_with_context(
                &mut ctx,
                500,
                ANTHROPIC_SSE.as_bytes(),
                Some("text/event-stream"),
                &HashMap::new(),
            )
            .await
            .is_none(),
        "provider error streams must stay untouched"
    );
}

// ---------------------------------------------------------------------------
// Claim-time markers, header hygiene, endpoint URL handling
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_claim_sets_shared_streaming_marker() {
    let plugin = build(openai_and_anthropic_config());
    let body = json!({"model": "gpt-4o", "stream": true, "messages": []});
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_eq!(
        ctx.metadata.get("ai_request_streaming").map(String::as_str),
        Some("true"),
        "claimed stream:true requests must set the shared streaming marker for response plugins"
    );

    // Unclaimed (non-streaming) requests must NOT set it.
    let non_streaming = json!({"model": "gpt-4o", "messages": []});
    let mut ctx2 = post_ctx(&non_streaming);
    let mut headers2 = json_headers();
    plugin.before_proxy(&mut ctx2, &mut headers2).await;
    assert!(!ctx2.metadata.contains_key("ai_request_streaming"));
}

#[tokio::test]
async fn test_claim_suppresses_consumer_identity_header_injection() {
    let plugin = build(openai_and_anthropic_config());
    let body = json!({"model": "gpt-4o", "stream": true, "messages": []});
    let mut ctx = post_ctx(&body);
    // Simulate an auth plugin having resolved a principal earlier.
    ctx.authenticated_identity = Some("internal-alice".to_string());
    assert_eq!(ctx.backend_consumer_username(), Some("internal-alice"));

    let mut headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    assert_eq!(
        ctx.metadata
            .get("suppress_backend_consumer_identity_headers")
            .map(String::as_str),
        Some("true")
    );
    // The proxy's injection sites read these accessors — both must go dark so
    // x-consumer-* never reaches the third-party provider.
    assert_eq!(
        ctx.backend_consumer_username(),
        None,
        "identity header injection must be suppressed for provider-routed requests"
    );
    assert_eq!(ctx.backend_consumer_custom_id(), None);
    // The principal itself stays resolved for rate limiting / logging.
    assert_eq!(ctx.effective_identity(), Some("internal-alice"));
}

#[tokio::test]
async fn test_cookie_and_proxy_authorization_stripped() {
    let plugin = build(openai_and_anthropic_config());
    let body = json!({"model": "gpt-4o", "stream": true, "messages": []});
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    headers.insert("cookie".to_string(), "session=SECRET".to_string());
    headers.insert("proxy-authorization".to_string(), "Basic AAAA".to_string());
    plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(
        !headers.contains_key("cookie"),
        "session cookie leaked to provider"
    );
    assert!(!headers.contains_key("proxy-authorization"));
}

fn azure_style_config() -> Value {
    json!({
        "providers": [{
            "name": "azure",
            "provider_type": "openai_compatible",
            "endpoint": "https://azure.example.com/openai/deployments/gpt/chat/completions?api-version=2024-02-01",
            "api_key": "sk-azure",
            "model_patterns": ["gpt-*"]
        }]
    })
}

#[tokio::test]
async fn test_endpoint_query_preserved_without_client_query() {
    let plugin = build(azure_style_config());
    let body = json!({"model": "gpt-4o", "stream": true, "messages": []});
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_eq!(
        ctx.route_override_path.as_deref(),
        Some("/openai/deployments/gpt/chat/completions?api-version=2024-02-01")
    );
    // No client query → nothing to strip.
    assert!(
        !ctx.metadata
            .keys()
            .any(|k| k.starts_with("auth.strip_query_param."))
    );
}

#[tokio::test]
async fn test_endpoint_query_merged_with_client_query() {
    let plugin = build(azure_style_config());
    let body = json!({"model": "gpt-4o", "stream": true, "messages": []});
    let mut ctx = post_ctx(&body);
    ctx.set_raw_query_string("foo=bar&baz=1".to_string());
    let mut headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    // Endpoint query first, client query appended with '&' — never a second '?'.
    assert_eq!(
        ctx.route_override_path.as_deref(),
        Some("/openai/deployments/gpt/chat/completions?api-version=2024-02-01&foo=bar&baz=1")
    );
    // Every client param is marked consumed so dispatch does not re-append it.
    assert_eq!(
        ctx.metadata
            .get("auth.strip_query_param.foo")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        ctx.metadata
            .get("auth.strip_query_param.baz")
            .map(String::as_str),
        Some("true")
    );
}

#[tokio::test]
async fn test_endpoint_query_omits_previously_stripped_client_credentials() {
    let plugin = build(azure_style_config());
    let body = json!({"model": "gpt-4o", "stream": true, "messages": []});
    let mut ctx = post_ctx(&body);
    ctx.set_raw_query_string("foo=bar&access_token=secret".to_string());
    ctx.metadata.insert(
        "auth.strip_query_param.access_token".to_string(),
        "true".to_string(),
    );
    let mut headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_eq!(
        ctx.route_override_path.as_deref(),
        Some("/openai/deployments/gpt/chat/completions?api-version=2024-02-01&foo=bar")
    );
    assert!(
        !ctx.route_override_path
            .as_deref()
            .unwrap()
            .contains("secret"),
        "query credentials marked for strip must not be folded into the provider override path"
    );
}

#[tokio::test]
async fn test_endpoint_query_drops_client_duplicate_provider_params() {
    let plugin = build(azure_style_config());
    let body = json!({"model": "gpt-4o", "stream": true, "messages": []});
    let mut ctx = post_ctx(&body);
    ctx.set_raw_query_string("api-version=preview&foo=bar".to_string());
    let mut headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_eq!(
        ctx.route_override_path.as_deref(),
        Some("/openai/deployments/gpt/chat/completions?api-version=2024-02-01&foo=bar")
    );
    assert_eq!(
        ctx.metadata
            .get("auth.strip_query_param.api-version")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        ctx.metadata
            .get("auth.strip_query_param.foo")
            .map(String::as_str),
        Some("true")
    );
}

#[tokio::test]
async fn test_plain_endpoint_keeps_client_query_forwarding_untouched() {
    let plugin = build(openai_and_anthropic_config());
    let body = json!({"model": "gpt-4o", "stream": true, "messages": []});
    let mut ctx = post_ctx(&body);
    ctx.set_raw_query_string("foo=bar".to_string());
    let mut headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    // No endpoint query → the dispatch path appends the client query normally.
    assert_eq!(
        ctx.route_override_path.as_deref(),
        Some("/v1/chat/completions")
    );
    assert!(
        !ctx.metadata
            .keys()
            .any(|k| k.starts_with("auth.strip_query_param."))
    );
}

#[tokio::test]
async fn test_ipv6_endpoint_authority_is_bracketed() {
    let cfg = json!({
        "providers": [{
            "name": "local6",
            "provider_type": "openai_compatible",
            "endpoint": "https://[::1]:8443/v1/chat/completions",
            "api_key": "sk-local",
            "model_patterns": ["gpt-*"]
        }]
    });
    let plugin = build(cfg);
    let body = json!({"model": "gpt-4o", "stream": true, "messages": []});
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    // Backend host stays bare (the URL builder brackets it); authority/Host
    // must be bracketed.
    assert_eq!(ctx.route_override_backend_host.as_deref(), Some("::1"));
    assert_eq!(ctx.route_override_backend_port, Some(8443));
    assert_eq!(ctx.route_override_authority.as_deref(), Some("[::1]:8443"));
    assert_eq!(headers.get("host").map(String::as_str), Some("[::1]:8443"));
}

#[tokio::test]
async fn test_ipv6_endpoint_default_port_authority() {
    let cfg = json!({
        "providers": [{
            "name": "local6",
            "provider_type": "openai_compatible",
            "endpoint": "https://[::1]/v1/chat/completions",
            "api_key": "sk-local",
            "model_patterns": ["gpt-*"]
        }]
    });
    let plugin = build(cfg);
    let body = json!({"model": "gpt-4o", "stream": true, "messages": []});
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_eq!(ctx.route_override_authority.as_deref(), Some("[::1]"));
}

#[tokio::test]
async fn test_backend_tls_default_and_inherit() {
    // Default: HTTPS providers get default public-CA verification.
    let plugin = build(openai_and_anthropic_config());
    let body = json!({"model": "gpt-4o", "stream": true, "messages": []});
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(ctx.route_override_resolved_tls.is_some());

    // inherit_backend_tls: true carries the proxy's own resolved backend TLS
    // (custom CA / SNI / mTLS), including TLS projected from an upstream.
    let cfg = json!({
        "providers": [{
            "name": "internal",
            "provider_type": "openai_compatible",
            "endpoint": "https://llm.internal.example.com/v1/chat/completions",
            "api_key": "sk-internal",
            "model_patterns": ["gpt-*"],
            "inherit_backend_tls": true
        }]
    });
    let plugin2 = build(cfg);
    let mut ctx2 = post_ctx(&body);
    let inherited_tls = BackendTlsConfig {
        client_cert_path: Some("/certs/client.pem".to_string()),
        client_key_path: Some("/certs/client.key".to_string()),
        server_ca_cert_path: Some("/certs/ca.pem".to_string()),
        verify_server_cert: true,
        sni: Some("llm.internal.example.com".to_string()),
        san_allow_list: vec!["llm.internal.example.com".to_string()],
        san_allow_list_key_digest: Some("digest".to_string()),
    };
    let mut proxy = create_test_proxy();
    proxy.resolved_tls = inherited_tls.clone();
    ctx2.matched_proxy = Some(Arc::new(proxy));
    let mut headers2 = json_headers();
    plugin2.before_proxy(&mut ctx2, &mut headers2).await;
    assert_eq!(
        ctx2.metadata
            .get("ai_stream_router.claimed")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(ctx2.route_override_resolved_tls, Some(inherited_tls));
}

// ---------------------------------------------------------------------------
// Normalizer carry bound
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_normalizer_terminates_on_oversized_sse_event() {
    let plugin = build(openai_and_anthropic_config());
    let claude = json!({"model": "claude-3-5-sonnet", "stream": true, "messages": []});
    let mut ctx = post_ctx(&claude);
    let mut headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    let mut inspector: Box<dyn ResponseStreamInspector> = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .unwrap();

    // One giant never-terminated event: no blank-line boundary ever arrives.
    let filler = vec![b'a'; 64 * 1024];
    let mut terminated = None;
    // 1 MiB cap / 64 KiB chunks → must terminate well within 20 chunks.
    for i in 0..20 {
        match inspector.on_chunk(&filler).await {
            ResponseStreamAction::Forward(bytes) => {
                assert!(
                    bytes.is_empty(),
                    "no complete event exists; nothing should be forwarded (chunk {i})"
                );
            }
            ResponseStreamAction::Terminate(bytes) => {
                terminated = Some(bytes);
                break;
            }
        }
    }
    let final_bytes = terminated
        .expect("oversized unterminated SSE event must terminate the stream")
        .expect("termination must carry a client-facing SSE error payload");
    let text = String::from_utf8(final_bytes.to_vec()).unwrap();
    assert!(text.contains("upstream_error"), "{text}");
    assert!(text.contains("oversized"), "{text}");
    assert!(text.trim_end().ends_with("data: [DONE]"), "{text}");

    // After termination the inspector keeps the stream closed without
    // emitting the terminal payload a second time.
    let after = inspector.on_chunk(b"data: {}\n\n").await;
    match after {
        ResponseStreamAction::Terminate(None) => {}
        ResponseStreamAction::Terminate(Some(_)) => panic!("must not emit terminal bytes twice"),
        ResponseStreamAction::Forward(_) => panic!("terminated inspector must remain closed"),
    }
}

// ---------------------------------------------------------------------------
// Composition with ai_federation
// ---------------------------------------------------------------------------

fn ai_federation_openai() -> AiFederation {
    let cfg = json!({
        "providers": [{
            "name": "openai", "provider_type": "openai",
            "api_key": "sk-fed", "model_patterns": ["gpt-*", "claude-*"]
        }]
    });
    AiFederation::new(&cfg, http_client()).unwrap()
}

#[tokio::test]
async fn test_ai_federation_rejects_streaming_without_marker() {
    // Baseline: ai_federation still rejects stream:true it would otherwise route.
    let fed = ai_federation_openai();
    let body =
        json!({"model": "gpt-4o", "stream": true, "messages": [{"role": "user", "content": "hi"}]});
    let mut ctx = post_ctx(&body);
    let headers = json_headers();
    let res = run_federation_final_body(&fed, &mut ctx, &headers).await;
    assert_eq!(reject_status(&res), Some(501));
}

#[tokio::test]
async fn test_ai_federation_defers_to_claimed_stream_router_request() {
    // With the coordination marker set, ai_federation immediately continues so
    // ai_stream_router owns the streaming request.
    let fed = ai_federation_openai();
    let body =
        json!({"model": "gpt-4o", "stream": true, "messages": [{"role": "user", "content": "hi"}]});
    let mut ctx = post_ctx(&body);
    ctx.metadata
        .insert("ai_stream_router_claimed".to_string(), "true".to_string());
    let headers = json_headers();
    let res = run_federation_final_body(&fed, &mut ctx, &headers).await;
    assert!(
        matches!(res, PluginResult::Continue),
        "ai_federation should defer to ai_stream_router"
    );
}

#[tokio::test]
async fn test_ai_federation_defers_to_stream_router_pass_through() {
    let fed = ai_federation_openai();
    let body = json!({"model": "gpt-unknown", "stream": true, "messages": [{"role": "user", "content": "hi"}]});
    let mut ctx = post_ctx(&body);
    ctx.metadata.insert(
        "ai_stream_router_pass_through".to_string(),
        "true".to_string(),
    );
    let headers = json_headers();
    let res = run_federation_final_body(&fed, &mut ctx, &headers).await;
    assert!(
        matches!(res, PluginResult::Continue),
        "ai_federation should defer to explicit ai_stream_router pass-through"
    );
}

#[tokio::test]
async fn test_end_to_end_composition_streaming_vs_non_streaming() {
    // stream:true → claimed by ai_stream_router; the same request then continues
    // through ai_federation which defers.
    let router = build(openai_and_anthropic_config());
    let fed = ai_federation_openai();

    let streaming =
        json!({"model": "gpt-4o", "stream": true, "messages": [{"role": "user", "content": "hi"}]});
    let mut ctx = post_ctx(&streaming);
    let mut headers = json_headers();
    assert!(matches!(
        router.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert_eq!(
        ctx.metadata
            .get("ai_stream_router_claimed")
            .map(String::as_str),
        Some("true")
    );
    assert!(matches!(
        run_federation_final_body(&fed, &mut ctx, &headers).await,
        PluginResult::Continue
    ));

    // stream:false → NOT claimed by ai_stream_router and therefore remains
    // eligible for ai_federation's later final-body phase.
    let non_streaming = json!({"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]});
    let mut ctx2 = post_ctx(&non_streaming);
    let mut headers2 = json_headers();
    assert!(matches!(
        router.before_proxy(&mut ctx2, &mut headers2).await,
        PluginResult::Continue
    ));
    assert!(!ctx2.metadata.contains_key("ai_stream_router_claimed"));
}

// ---------------------------------------------------------------------------
// #2272 — Anthropic terminal-state failure posture
// ---------------------------------------------------------------------------

const ANTHROPIC_PARTIAL_SSE: &str = concat!(
    "event: message_start\n",
    "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_partial\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-3-5-sonnet\",\"content\":[],\"stop_reason\":null,\"usage\":{\"input_tokens\":3,\"output_tokens\":1}}}\n\n",
    "event: content_block_delta\n",
    "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"cut short\"}}\n\n",
);

async fn run_sse(body: &str) -> (String, bool) {
    let plugin = build(openai_and_anthropic_config());
    let claude = json!({"model": "claude-3-5-sonnet", "stream": true, "messages": [{"role":"user","content":"hi"}]});
    let mut ctx = post_ctx(&claude);
    let mut headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    let mut collected = Vec::new();
    let mut terminated = false;
    match inspector.on_chunk(body.as_bytes()).await {
        ResponseStreamAction::Forward(bytes) => collected.extend_from_slice(&bytes),
        ResponseStreamAction::Terminate(bytes) => {
            terminated = true;
            if let Some(bytes) = bytes {
                collected.extend_from_slice(&bytes);
            }
        }
    }
    if !terminated {
        match inspector.on_end().await {
            ResponseStreamAction::Forward(bytes) => collected.extend_from_slice(&bytes),
            ResponseStreamAction::Terminate(bytes) => {
                terminated = true;
                if let Some(bytes) = bytes {
                    collected.extend_from_slice(&bytes);
                }
            }
        }
    }
    (String::from_utf8(collected).unwrap(), terminated)
}

#[tokio::test]
async fn test_premature_anthropic_eof_is_upstream_error_not_success() {
    let (out, terminated) = run_sse(ANTHROPIC_PARTIAL_SSE).await;
    assert!(terminated);
    assert!(out.contains("\"type\":\"upstream_error\""));
    assert!(out.contains("before message_stop"));
    assert!(out.contains("cut short"));
    assert!(out.trim_end().ends_with("data: [DONE]"));
    // Exactly one DONE sentinel.
    assert_eq!(out.matches("data: [DONE]").count(), 1);
}

#[tokio::test]
async fn test_anthropic_message_stop_without_start_is_protocol_error() {
    let (out, terminated) = run_sse("data: {\"type\":\"message_stop\"}\n\n").await;
    assert!(terminated);
    assert!(out.contains("before message_start"));
    assert!(out.contains("upstream_error"));
    assert_eq!(out.matches("data: [DONE]").count(), 1);
}

#[tokio::test]
async fn test_malformed_complete_sse_event_fails_closed() {
    let body = concat!(
        "event: message_start\n",
        "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_bad\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-3-5-sonnet\",\"content\":[],\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\n",
        "event: content_block_delta\n",
        "data: {not-json\n\n",
    );
    let (out, terminated) = run_sse(body).await;
    assert!(terminated);
    assert!(out.contains("\"type\":\"upstream_error\""));
    assert!(out.contains("malformed SSE JSON"));
    assert_eq!(out.matches("data: [DONE]").count(), 1);
}

#[tokio::test]
async fn test_explicit_anthropic_error_event_terminates_once() {
    let body = concat!(
        "event: message_start\n",
        "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_err\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-3-5-sonnet\",\"content\":[],\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\n",
        "event: error\n",
        "data: {\"type\":\"error\",\"error\":{\"type\":\"api_error\",\"message\":\"provider blew up\"}}\n\n",
    );
    let (out, terminated) = run_sse(body).await;
    assert!(terminated);
    assert!(out.contains("provider blew up"));
    assert!(out.contains("\"type\":\"upstream_error\""));
    assert_eq!(out.matches("data: [DONE]").count(), 1);
}

#[tokio::test]
async fn test_unknown_anthropic_sse_events_are_forward_compatible() {
    let body = concat!(
        "event: message_start\n",
        "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_unk\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-3-5-sonnet\",\"content\":[],\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\n",
        "event: future_event\n",
        "data: {\"type\":\"future_event\",\"payload\":true}\n\n",
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"ok\"}}\n\n",
        "event: message_delta\n",
        "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":1}}\n\n",
        "event: message_stop\n",
        "data: {\"type\":\"message_stop\"}\n\n",
    );
    let (out, terminated) = run_sse(body).await;
    assert!(terminated);
    assert!(out.contains("\"content\":\"ok\""));
    assert!(out.contains("\"finish_reason\":\"stop\""));
    assert!(!out.contains("upstream_error"));
    assert_eq!(out.matches("data: [DONE]").count(), 1);
}

#[tokio::test]
async fn test_message_stop_terminates_without_waiting_for_extra_eof_bytes() {
    let plugin = build(openai_and_anthropic_config());
    let claude = json!({"model": "claude-3-5-sonnet", "stream": true, "messages": [{"role":"user","content":"hi"}]});
    let mut ctx = post_ctx(&claude);
    let mut headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    let first = inspector.on_chunk(ANTHROPIC_SSE.as_bytes()).await;
    match first {
        ResponseStreamAction::Terminate(Some(bytes)) => {
            let out = String::from_utf8(bytes.to_vec()).unwrap();
            assert!(out.trim_end().ends_with("data: [DONE]"));
        }
        other => panic!("message_stop must Terminate the inspector driver: {other:?}"),
    }
    // Exactly-once: a later on_end must not emit a second DONE.
    let trailing = forwarded(inspector.on_end().await);
    assert!(trailing.is_empty());
}

// ---------------------------------------------------------------------------
// #2274 — Accept-Encoding / Content-Encoding identity handling
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_normalized_claim_requests_identity_encoding() {
    let plugin = build(openai_and_anthropic_config());
    let body = json!({"model": "claude-3-5-sonnet", "stream": true, "messages": [{"role":"user","content":"hi"}]});
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    headers.insert("accept-encoding".to_string(), "gzip, br".to_string());
    headers.insert("Accept-Encoding".to_string(), "deflate".to_string());
    plugin.before_proxy(&mut ctx, &mut headers).await;
    let values: Vec<_> = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("accept-encoding"))
        .map(|(_, value)| value.as_str())
        .collect();
    assert_eq!(
        values,
        vec!["identity"],
        "normalized Anthropic claims must replace every client variant with identity"
    );
}

#[tokio::test]
async fn test_openai_passthrough_keeps_accept_encoding() {
    let plugin = build(openai_and_anthropic_config());
    let body =
        json!({"model": "gpt-4o", "stream": true, "messages": [{"role":"user","content":"hi"}]});
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    headers.insert("accept-encoding".to_string(), "gzip".to_string());
    plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_eq!(
        headers.get("accept-encoding").map(String::as_str),
        Some("gzip")
    );
}

fn gzip_bytes(plain: &[u8]) -> Vec<u8> {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(plain).unwrap();
    encoder.finish().unwrap()
}

fn brotli_bytes(plain: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut encoder = brotli::CompressorWriter::new(&mut out, 4096, 5, 22);
        std::io::Write::write_all(&mut encoder, plain).unwrap();
    }
    out
}

#[tokio::test]
async fn test_gzip_encoded_streamed_anthropic_sse_is_normalized() {
    let plugin = build(openai_and_anthropic_config());
    let claude = json!({"model": "claude-3-5-sonnet", "stream": true, "messages": [{"role":"user","content":"hi"}]});
    let mut ctx = post_ctx(&claude);
    let mut req_headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut req_headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "text/event-stream".to_string());
    resp_headers.insert("content-encoding".to_string(), "gzip".to_string());
    resp_headers.insert("vary".to_string(), "Accept-Encoding, Origin".to_string());
    let after = plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert!(matches!(after, PluginResult::Continue));
    assert!(!resp_headers.contains_key("content-encoding"));
    assert_eq!(resp_headers.get("vary").map(String::as_str), Some("Origin"));
    assert_eq!(
        ctx.metadata
            .get("ai_stream_router.provider_content_encoding")
            .map(String::as_str),
        Some("gzip")
    );

    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("decoding inspector");
    let encoded = gzip_bytes(ANTHROPIC_SSE.as_bytes());
    let mut collected = forwarded(inspector.on_chunk(&encoded).await);
    collected.extend_from_slice(&forwarded(inspector.on_end().await));
    let out = String::from_utf8(collected).unwrap();
    assert!(out.contains("\"content\":\"Hello\""));
    assert!(out.trim_end().ends_with("data: [DONE]"));
    assert!(!out.contains("upstream_error"));
}

#[tokio::test]
async fn test_gzip_streaming_decode_rejects_expansion_over_limit() {
    let plugin = build(openai_and_anthropic_config());
    let claude = json!({"model": "claude-3-5-sonnet", "stream": true, "messages": [{"role":"user","content":"hi"}]});
    let mut ctx = post_ctx(&claude);
    let mut req_headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut req_headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "text/event-stream".to_string());
    resp_headers.insert("content-encoding".to_string(), "gzip".to_string());
    assert!(matches!(
        plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await,
        PluginResult::Continue
    ));

    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("bounded decoding inspector");
    let oversized = vec![b'x'; 8 * 1024 * 1024 + 1];
    let encoded = gzip_bytes(&oversized);
    let mut collected = forwarded(inspector.on_chunk(&encoded).await);
    collected.extend_from_slice(&forwarded(inspector.on_end().await));
    let out = String::from_utf8(collected).unwrap();
    assert!(out.contains("upstream_error"));
    assert!(out.contains("decoded content exceeds"));
    assert_eq!(out.matches("data: [DONE]").count(), 1);
}

#[tokio::test]
async fn test_brotli_encoded_buffered_anthropic_sse_is_normalized() {
    let plugin = build(openai_and_anthropic_config());
    let claude = json!({"model": "claude-3-5-sonnet", "stream": true, "messages": [{"role":"user","content":"hi"}]});
    let mut ctx = post_ctx(&claude);
    let mut req_headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut req_headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "text/event-stream".to_string());
    resp_headers.insert("content-encoding".to_string(), "br".to_string());
    assert!(matches!(
        plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await,
        PluginResult::Continue
    ));

    let encoded = brotli_bytes(ANTHROPIC_SSE.as_bytes());
    let buffered = plugin
        .normalize_response_body_with_context(
            &mut ctx,
            200,
            &encoded,
            Some("text/event-stream"),
            &resp_headers,
        )
        .await
        .expect("buffered decode+normalize");
    let out = String::from_utf8(buffered).unwrap();
    assert!(out.contains("chat.completion.chunk"));
    assert!(out.contains("\"content\":\"Hello\""));
    assert!(out.trim_end().ends_with("data: [DONE]"));
}

#[tokio::test]
async fn test_unsupported_content_encoding_is_rejected() {
    let plugin = build(openai_and_anthropic_config());
    let claude = json!({"model": "claude-3-5-sonnet", "stream": true, "messages": [{"role":"user","content":"hi"}]});
    for encoding in ["zstd", "gzip,", "gzip; q=1", "gzip, br"] {
        let mut ctx = post_ctx(&claude);
        let mut req_headers = json_headers();
        plugin.before_proxy(&mut ctx, &mut req_headers).await;

        let mut resp_headers = HashMap::new();
        resp_headers.insert("content-type".to_string(), "text/event-stream".to_string());
        resp_headers.insert("content-encoding".to_string(), encoding.to_string());
        let reject = plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
        assert_eq!(
            reject_status(&reject),
            Some(502),
            "{encoding} must fail closed"
        );
    }
}

#[tokio::test]
async fn test_case_variant_duplicate_content_encoding_is_rejected() {
    let plugin = build(openai_and_anthropic_config());
    let claude = json!({"model": "claude-3-5-sonnet", "stream": true, "messages": [{"role":"user","content":"hi"}]});
    let mut ctx = post_ctx(&claude);
    let mut req_headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut req_headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "text/event-stream".to_string());
    resp_headers.insert("content-encoding".to_string(), "identity".to_string());
    resp_headers.insert("Content-Encoding".to_string(), "gzip".to_string());
    assert_eq!(
        reject_status(&plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await),
        Some(502)
    );
}

#[tokio::test]
async fn test_identity_provider_content_encoding_repairs_rewritten_representation_headers() {
    let plugin = build(openai_and_anthropic_config());
    let claude = json!({"model": "claude-3-5-sonnet", "stream": true, "messages": [{"role":"user","content":"hi"}]});

    for encoding in [None, Some("identity")] {
        let mut ctx = post_ctx(&claude);
        let mut req_headers = json_headers();
        plugin.before_proxy(&mut ctx, &mut req_headers).await;

        let mut resp_headers = HashMap::new();
        resp_headers.insert("content-type".to_string(), "text/event-stream".to_string());
        resp_headers.insert("Content-Length".to_string(), "999".to_string());
        resp_headers.insert("ETag".to_string(), "\"provider\"".to_string());
        resp_headers.insert("Digest".to_string(), "sha-256=provider".to_string());
        resp_headers.insert("vary".to_string(), "Accept-Encoding, Origin".to_string());
        resp_headers.insert("Vary".to_string(), "origin, X-Trace".to_string());
        if let Some(encoding) = encoding {
            resp_headers.insert("Content-Encoding".to_string(), encoding.to_string());
        }
        assert!(matches!(
            plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await,
            PluginResult::Continue
        ));
        assert!(
            !ctx.metadata
                .contains_key("ai_stream_router.provider_content_encoding")
        );
        for invalidated in ["content-encoding", "content-length", "etag", "digest"] {
            assert!(
                !resp_headers
                    .keys()
                    .any(|name| name.eq_ignore_ascii_case(invalidated)),
                "{invalidated} must be removed after identity SSE normalization"
            );
        }
        let vary_values: Vec<_> = resp_headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("vary"))
            .map(|(_, value)| value.as_str())
            .collect();
        assert_eq!(vary_values.len(), 1);
        let vary_tokens: Vec<_> = vary_values[0]
            .split(',')
            .map(|token| token.trim().to_ascii_lowercase())
            .collect();
        assert_eq!(vary_tokens.len(), 2);
        assert!(vary_tokens.iter().any(|token| token == "origin"));
        assert!(vary_tokens.iter().any(|token| token == "x-trace"));
    }
}

// ---------------------------------------------------------------------------
// #2280 — tool-call / tool-result history translation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_anthropic_tool_history_round_trip_translation() {
    let plugin = build(openai_and_anthropic_config());
    let body = json!({
        "model": "claude-3-5-sonnet",
        "stream": true,
        "messages": [
            {"role": "user", "content": "weather in Paris?"},
            {
                "role": "assistant",
                "content": "Let me check.",
                "tool_calls": [{
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "get_weather", "arguments": "{\"location\":\"Paris\"}"}
                }]
            },
            {"role": "tool", "tool_call_id": "call_1", "content": "22C and sunny"},
            {"role": "user", "content": "thanks"}
        ]
    });
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    let raw = serde_json::to_vec(&body).unwrap();
    let out = plugin
        .transform_request_body_with_context(&mut ctx, &raw, Some("application/json"), &headers)
        .await
        .expect("translated");
    let parsed: Value = serde_json::from_slice(&out).unwrap();
    let messages = parsed["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 4);
    assert_eq!(messages[0]["role"], json!("user"));
    assert_eq!(messages[1]["role"], json!("assistant"));
    let assistant_blocks = messages[1]["content"].as_array().unwrap();
    assert_eq!(assistant_blocks[0]["type"], json!("text"));
    assert_eq!(assistant_blocks[0]["text"], json!("Let me check."));
    assert_eq!(assistant_blocks[1]["type"], json!("tool_use"));
    assert_eq!(assistant_blocks[1]["id"], json!("call_1"));
    assert_eq!(assistant_blocks[1]["name"], json!("get_weather"));
    assert_eq!(assistant_blocks[1]["input"]["location"], json!("Paris"));
    assert_eq!(messages[2]["role"], json!("user"));
    let tool_results = messages[2]["content"].as_array().unwrap();
    assert_eq!(tool_results[0]["type"], json!("tool_result"));
    assert_eq!(tool_results[0]["tool_use_id"], json!("call_1"));
    assert_eq!(tool_results[0]["content"], json!("22C and sunny"));
    assert_eq!(messages[3]["content"], json!("thanks"));
}

#[tokio::test]
async fn test_anthropic_parallel_tool_calls_and_results_preserve_order() {
    let plugin = build(openai_and_anthropic_config());
    let body = json!({
        "model": "claude-3-5-sonnet",
        "stream": true,
        "messages": [
            {"role": "user", "content": "multi"},
            {
                "role": "assistant",
                "content": null,
                "tool_calls": [
                    {"id": "call_a", "type": "function", "function": {"name": "alpha", "arguments": "{}"}},
                    {"id": "call_b", "type": "function", "function": {"name": "beta", "arguments": "{\"x\":1}"}}
                ]
            },
            {"role": "tool", "tool_call_id": "call_a", "content": "A"},
            {"role": "tool", "tool_call_id": "call_b", "content": "B", "is_error": true}
        ]
    });
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    let raw = serde_json::to_vec(&body).unwrap();
    let parsed: Value = serde_json::from_slice(
        &plugin
            .transform_request_body_with_context(&mut ctx, &raw, Some("application/json"), &headers)
            .await
            .unwrap(),
    )
    .unwrap();
    let assistant = parsed["messages"][1]["content"].as_array().unwrap();
    assert_eq!(assistant[0]["id"], json!("call_a"));
    assert_eq!(assistant[1]["id"], json!("call_b"));
    let results = parsed["messages"][2]["content"].as_array().unwrap();
    assert_eq!(results.len(), 2);
    assert_eq!(results[0]["tool_use_id"], json!("call_a"));
    assert_eq!(results[1]["tool_use_id"], json!("call_b"));
    assert_eq!(results[1]["is_error"], json!(true));
}

#[tokio::test]
async fn test_null_tool_call_fields_are_treated_as_absent() {
    let plugin = build(openai_and_anthropic_config());
    let body = json!({
        "model": "claude-3-5-sonnet",
        "stream": true,
        "messages": [
            {"role": "user", "content": "hi"},
            {
                "role": "assistant",
                "content": "done",
                "tool_calls": null,
                "function_call": null
            }
        ]
    });
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    let raw = serde_json::to_vec(&body).unwrap();
    let translated: Value = serde_json::from_slice(
        &plugin
            .transform_request_body_with_context(&mut ctx, &raw, Some("application/json"), &headers)
            .await
            .expect("translated"),
    )
    .unwrap();
    assert_eq!(translated["messages"][1]["content"], json!("done"));
}

#[tokio::test]
async fn test_malformed_tool_history_rejects_with_400() {
    let plugin = build(openai_and_anthropic_config());

    let orphaned = json!({
        "model": "claude-3-5-sonnet",
        "stream": true,
        "messages": [
            {"role": "user", "content": "hi"},
            {"role": "tool", "tool_call_id": "missing", "content": "x"}
        ]
    });
    let mut ctx = post_ctx(&orphaned);
    let mut headers = json_headers();
    assert_eq!(
        reject_status(&plugin.before_proxy(&mut ctx, &mut headers).await),
        Some(400)
    );

    let bad_args = json!({
        "model": "claude-3-5-sonnet",
        "stream": true,
        "messages": [
            {"role": "user", "content": "hi"},
            {
                "role": "assistant",
                "content": null,
                "tool_calls": [{
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "get_weather", "arguments": "not-json"}
                }]
            }
        ]
    });
    let mut ctx2 = post_ctx(&bad_args);
    let mut headers2 = json_headers();
    assert_eq!(
        reject_status(&plugin.before_proxy(&mut ctx2, &mut headers2).await),
        Some(400)
    );

    let missing_result = json!({
        "model": "claude-3-5-sonnet",
        "stream": true,
        "messages": [
            {"role": "user", "content": "hi"},
            {
                "role": "assistant",
                "content": null,
                "tool_calls": [{
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "get_weather", "arguments": "{}"}
                }]
            },
            {"role": "user", "content": "continue without a result"}
        ]
    });
    let mut ctx3 = post_ctx(&missing_result);
    let mut headers3 = json_headers();
    assert_eq!(
        reject_status(&plugin.before_proxy(&mut ctx3, &mut headers3).await),
        Some(400)
    );

    let duplicate_result = json!({
        "model": "claude-3-5-sonnet",
        "stream": true,
        "messages": [
            {"role": "user", "content": "hi"},
            {
                "role": "assistant",
                "content": null,
                "tool_calls": [{
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "get_weather", "arguments": "{}"}
                }]
            },
            {"role": "tool", "tool_call_id": "call_1", "content": "first"},
            {"role": "tool", "tool_call_id": "call_1", "content": "duplicate"}
        ]
    });
    let mut ctx4 = post_ctx(&duplicate_result);
    let mut headers4 = json_headers();
    assert_eq!(
        reject_status(&plugin.before_proxy(&mut ctx4, &mut headers4).await),
        Some(400)
    );
}

#[tokio::test]
async fn test_anthropic_translation_rejects_each_malformed_tool_history_shape() {
    let plugin = build(openai_and_anthropic_config());
    let invalid_requests = vec![
        (
            "missing messages",
            json!({"model": "claude-3-5-sonnet", "stream": true}),
        ),
        (
            "non-object message",
            json!({"model": "claude-3-5-sonnet", "stream": true, "messages": ["bad"]}),
        ),
        (
            "missing role",
            json!({"model": "claude-3-5-sonnet", "stream": true, "messages": [{"content": "bad"}]}),
        ),
        (
            "unsupported role",
            json!({"model": "claude-3-5-sonnet", "stream": true, "messages": [{"role": "critic", "content": "bad"}]}),
        ),
        (
            "non-text user content",
            json!({"model": "claude-3-5-sonnet", "stream": true, "messages": [{"role": "user", "content": 42}]}),
        ),
        (
            "legacy function call",
            json!({"model": "claude-3-5-sonnet", "stream": true, "messages": [{"role": "assistant", "content": "calling", "function_call": {"name": "run", "arguments": "{}"}}]}),
        ),
        (
            "empty tool call list",
            json!({"model": "claude-3-5-sonnet", "stream": true, "messages": [{"role": "assistant", "content": null, "tool_calls": []}]}),
        ),
        (
            "non-array tool calls",
            json!({"model": "claude-3-5-sonnet", "stream": true, "messages": [{"role": "assistant", "content": null, "tool_calls": {}}]}),
        ),
        (
            "non-object tool call",
            json!({"model": "claude-3-5-sonnet", "stream": true, "messages": [{"role": "assistant", "content": null, "tool_calls": [7]}]}),
        ),
        (
            "non-function tool call",
            json!({"model": "claude-3-5-sonnet", "stream": true, "messages": [{"role": "assistant", "content": null, "tool_calls": [{"id": "call_1", "type": "custom", "function": {"name": "run", "arguments": "{}"}}]}]}),
        ),
        (
            "missing tool call id",
            json!({"model": "claude-3-5-sonnet", "stream": true, "messages": [{"role": "assistant", "content": null, "tool_calls": [{"type": "function", "function": {"name": "run", "arguments": "{}"}}]}]}),
        ),
        (
            "missing function object",
            json!({"model": "claude-3-5-sonnet", "stream": true, "messages": [{"role": "assistant", "content": null, "tool_calls": [{"id": "call_1", "type": "function"}]}]}),
        ),
        (
            "invalid function name",
            json!({"model": "claude-3-5-sonnet", "stream": true, "messages": [{"role": "assistant", "content": null, "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "not valid!", "arguments": "{}"}}]}]}),
        ),
        (
            "non-string arguments",
            json!({"model": "claude-3-5-sonnet", "stream": true, "messages": [{"role": "assistant", "content": null, "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "run", "arguments": {}}}]}]}),
        ),
        (
            "non-object encoded arguments",
            json!({"model": "claude-3-5-sonnet", "stream": true, "messages": [{"role": "assistant", "content": null, "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "run", "arguments": "[]"}}]}]}),
        ),
        (
            "tool calls on user message",
            json!({"model": "claude-3-5-sonnet", "stream": true, "messages": [{"role": "user", "content": "bad", "tool_calls": []}]}),
        ),
        (
            "repeated tool call id",
            json!({
                "model": "claude-3-5-sonnet",
                "stream": true,
                "messages": [{
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [
                        {"id": "same", "type": "function", "function": {"name": "first", "arguments": "{}"}},
                        {"id": "same", "type": "function", "function": {"name": "second", "arguments": "{}"}}
                    ]
                }]
            }),
        ),
        (
            "missing final tool result",
            json!({"model": "claude-3-5-sonnet", "stream": true, "messages": [{"role": "assistant", "content": null, "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "run", "arguments": "{}"}}]}]}),
        ),
        (
            "object tool result content",
            json!({
                "model": "claude-3-5-sonnet",
                "stream": true,
                "messages": [
                    {"role": "assistant", "content": null, "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "run", "arguments": "{}"}}]},
                    {"role": "tool", "tool_call_id": "call_1", "content": {}}
                ]
            }),
        ),
        (
            "non-text tool result part",
            json!({
                "model": "claude-3-5-sonnet",
                "stream": true,
                "messages": [
                    {"role": "assistant", "content": null, "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "run", "arguments": "{}"}}]},
                    {"role": "tool", "tool_call_id": "call_1", "content": [{"type": "image", "text": "bad"}]}
                ]
            }),
        ),
        (
            "missing tool result text",
            json!({
                "model": "claude-3-5-sonnet",
                "stream": true,
                "messages": [
                    {"role": "assistant", "content": null, "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "run", "arguments": "{}"}}]},
                    {"role": "tool", "tool_call_id": "call_1", "content": [{"type": "text"}]}
                ]
            }),
        ),
        (
            "empty assistant content",
            json!({"model": "claude-3-5-sonnet", "stream": true, "messages": [{"role": "assistant", "content": ""}]}),
        ),
    ];

    for (label, body) in invalid_requests {
        let mut ctx = post_ctx(&body);
        let mut headers = json_headers();
        assert_eq!(
            reject_status(&plugin.before_proxy(&mut ctx, &mut headers).await),
            Some(400),
            "{label} must fail closed"
        );
    }
}

#[tokio::test]
async fn test_anthropic_late_translation_failure_is_rejected_before_dispatch() {
    let plugin = build(openai_and_anthropic_config());
    let body = json!({
        "model": "claude-3-5-sonnet",
        "stream": true,
        "messages": [{"role": "user", "content": "hi"}]
    });
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));

    assert!(
        plugin
            .transform_request_body_with_context(
                &mut ctx,
                b"{",
                Some("application/json"),
                &headers,
            )
            .await
            .is_none()
    );
    assert_eq!(
        reject_status(
            &plugin
                .on_final_request_body_with_context(&mut ctx, &headers, b"{")
                .await
        ),
        Some(400)
    );
}
