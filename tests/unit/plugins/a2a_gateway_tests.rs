use bytes::Bytes;
use ferrum_edge::plugins::{
    HTTP_GRPC_PROTOCOLS, Plugin, PluginResult, RequestContext, ResponseStreamAction, create_plugin,
    create_response_stream_inspector,
    utils::metadata_redaction::is_sensitive_metadata_key_with_extras,
};
use ferrum_edge::proxy::deferred_log::BodyOutcome;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;

fn plugin(config: Value) -> std::sync::Arc<dyn ferrum_edge::plugins::Plugin> {
    create_plugin("a2a_gateway", &config)
        .expect("a2a_gateway config should be valid")
        .expect("a2a_gateway should be registered")
}

fn jsonrpc_ctx(body: Value) -> (RequestContext, HashMap<String, String>) {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/a2a".to_string(),
    );
    ctx.request_body_bytes = Some(Bytes::from(body.to_string()));
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    let headers = HashMap::from([
        ("content-type".to_string(), "application/json".to_string()),
        ("accept-encoding".to_string(), "gzip".to_string()),
    ]);
    (ctx, headers)
}

fn jsonrpc_ctx_with_raw_body(body: String) -> (RequestContext, HashMap<String, String>) {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/a2a".to_string(),
    );
    ctx.request_body_bytes = Some(Bytes::from(body));
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    let headers = HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    (ctx, headers)
}

fn rest_ctx(method: &str, path: &str) -> (RequestContext, HashMap<String, String>) {
    (
        RequestContext::new(
            "127.0.0.1".to_string(),
            method.to_string(),
            path.to_string(),
        ),
        HashMap::new(),
    )
}

fn grpc_ctx(rpc: &str, content_type: &str) -> (RequestContext, HashMap<String, String>) {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        format!("/lf.a2a.v1.A2AService/{rpc}"),
    );
    ctx.headers
        .insert("content-type".to_string(), content_type.to_string());
    let headers = ctx.headers.clone();
    (ctx, headers)
}

#[test]
fn a2a_gateway_registers_with_http_and_grpc_protocols() {
    let plugin = plugin(json!({}));
    assert_eq!(plugin.name(), "a2a_gateway");
    assert_eq!(plugin.supported_protocols(), HTTP_GRPC_PROTOCOLS);
    assert!(ferrum_edge::plugins::available_plugins().contains(&"a2a_gateway"));
}

#[tokio::test]
async fn jsonrpc_request_emits_metadata_and_strips_accept_encoding() {
    let plugin = plugin(json!({}));
    let (mut ctx, mut headers) = jsonrpc_ctx(json!({
        "jsonrpc": "2.0",
        "id": "req-1",
        "method": "message/send",
        "params": {
            "taskId": "task-1"
        }
    }));

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata.get("a2a.binding").map(String::as_str),
        Some("jsonrpc")
    );
    assert_eq!(
        ctx.metadata.get("a2a.method").map(String::as_str),
        Some("message/send")
    );
    assert_eq!(
        ctx.metadata.get("a2a.task_id").map(String::as_str),
        Some("task-1")
    );
    assert!(!headers.contains_key("accept-encoding"));
}

#[tokio::test]
async fn jsonrpc_policy_deny_preserves_request_id() {
    let plugin = plugin(json!({
        "policy": {
            "methods": {
                "message/send": {"action": "deny"}
            }
        }
    }));
    let (mut ctx, mut headers) = jsonrpc_ctx(json!({
        "jsonrpc": "2.0",
        "id": "req-2",
        "method": "message/send"
    }));

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    let PluginResult::Reject {
        status_code, body, ..
    } = result
    else {
        panic!("policy deny should reject");
    };
    assert_eq!(status_code, 200);
    let body: Value = serde_json::from_str(&body).expect("body should be JSON");
    assert_eq!(body["id"], "req-2");
    assert_eq!(body["error"]["data"]["gateway"], "a2a_gateway");
}

#[tokio::test]
async fn jsonrpc_batch_policy_deny_rejects_denied_member() {
    let plugin = plugin(json!({
        "policy": {
            "methods": {
                "message/send": {"action": "deny"}
            }
        }
    }));
    let (mut ctx, mut headers) = jsonrpc_ctx(json!([
        {
            "jsonrpc": "2.0",
            "id": "req-allowed",
            "method": "tasks/get"
        },
        {
            "jsonrpc": "2.0",
            "id": "req-denied",
            "method": "message/send"
        }
    ]));

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    let PluginResult::Reject {
        status_code, body, ..
    } = result
    else {
        panic!("batch containing a denied JSON-RPC method should reject");
    };
    assert_eq!(status_code, 200);
    let body: Value = serde_json::from_str(&body).expect("body should be JSON");
    let response = body
        .as_array()
        .and_then(|responses| responses.first())
        .expect("batch denial should be wrapped in a JSON-RPC batch response");
    assert_eq!(response["id"], "req-denied");
    assert_eq!(response["error"]["data"]["method"], "message/send");
    assert_eq!(
        ctx.metadata.get("a2a.policy_decision").map(String::as_str),
        Some("deny")
    );
}

#[tokio::test]
async fn jsonrpc_batch_policy_deny_rejects_uninspectable_member() {
    let plugin = plugin(json!({
        "policy": {
            "methods": {
                "message/send": {"action": "deny"}
            }
        }
    }));
    let (mut ctx, mut headers) = jsonrpc_ctx(json!([
        {
            "jsonrpc": "2.0",
            "id": "req-allowed",
            "method": "tasks/get"
        },
        "not-an-envelope"
    ]));

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    let PluginResult::Reject {
        status_code, body, ..
    } = result
    else {
        panic!("uninspectable batch with method policy should reject");
    };
    assert_eq!(status_code, 200);
    let body: Value = serde_json::from_str(&body).expect("body should be JSON");
    let response = body
        .as_array()
        .and_then(|responses| responses.first())
        .expect("uninspectable batch should be wrapped in a JSON-RPC batch response");
    assert!(response["id"].is_null());
    assert_eq!(response["error"]["data"]["method"], "unknown");
    assert_eq!(
        ctx.metadata.get("a2a.error").map(String::as_str),
        Some("request_body_uninspectable")
    );
}

#[tokio::test]
async fn jsonrpc_single_method_without_version_fails_closed_when_policy_denies() {
    // A single (non-batch) body that carries a JSON-RPC `method` but omits a
    // valid `jsonrpc: "2.0"` envelope must not slip past a deny policy by being
    // treated as "not A2A". It fails closed exactly as a batch member would.
    let plugin = plugin(json!({
        "policy": {
            "methods": {
                "message/send": {"action": "deny"}
            }
        }
    }));
    let (mut ctx, mut headers) = jsonrpc_ctx(json!({
        "id": "req-malformed",
        "method": "message/send"
    }));

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    let PluginResult::Reject {
        status_code, body, ..
    } = result
    else {
        panic!(
            "single method-bearing body with a malformed envelope should reject under a deny policy"
        );
    };
    assert_eq!(status_code, 200);
    let body: Value = serde_json::from_str(&body).expect("body should be JSON");
    // A single (non-batch) denial is a bare object, not a batch array.
    assert!(!body.is_array());
    assert_eq!(body["error"]["data"]["method"], "unknown");
    assert_eq!(
        ctx.metadata.get("a2a.error").map(String::as_str),
        Some("request_body_uninspectable")
    );
}

#[tokio::test]
async fn jsonrpc_single_body_without_method_passes_through_under_deny_policy() {
    // A body with no JSON-RPC `method` is not a method call; it must keep
    // passing through even when a deny policy exists, so the single-object
    // fail-closed path does not over-block non-A2A JSON.
    let plugin = plugin(json!({
        "policy": {
            "methods": {
                "message/send": {"action": "deny"}
            }
        }
    }));
    let (mut ctx, mut headers) = jsonrpc_ctx(json!({ "foo": "bar" }));

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "a method-less body must not be denied by the single-object fail-closed path"
    );
}

#[tokio::test]
async fn jsonrpc_pascalcase_method_is_detected_and_policy_normalized() {
    let plugin = plugin(json!({
        "policy": {
            "methods": {
                "SendMessage": {"action": "deny"}
            }
        }
    }));
    let (mut ctx, mut headers) = jsonrpc_ctx(json!({
        "jsonrpc": "2.0",
        "id": "req-pascal",
        "method": "SendMessage",
        "params": {
            "id": "task-1"
        }
    }));

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    let PluginResult::Reject { body, .. } = result else {
        panic!("PascalCase JSON-RPC method should be denied by normalized policy");
    };
    let body: Value = serde_json::from_str(&body).expect("body should be JSON");
    assert_eq!(body["error"]["data"]["method"], "message/send");
    assert_eq!(
        ctx.metadata.get("a2a.method").map(String::as_str),
        Some("message/send")
    );
}

#[tokio::test]
async fn jsonrpc_detection_accepts_case_insensitive_json_suffix() {
    let plugin = plugin(json!({}));
    let (mut ctx, mut headers) = jsonrpc_ctx(json!({
        "jsonrpc": "2.0",
        "id": "req-json-suffix",
        "method": "SendMessage"
    }));
    ctx.headers.insert(
        "content-type".to_string(),
        "application/A2A+JSON".to_string(),
    );
    headers.insert(
        "content-type".to_string(),
        "application/A2A+JSON".to_string(),
    );

    assert!(plugin.should_buffer_request_body(&ctx));
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata.get("a2a.method").map(String::as_str),
        Some("message/send")
    );
}

#[tokio::test]
async fn rest_agent_card_response_rewrites_gateway_urls() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/agents/planner/.well-known/agent-card.json".to_string(),
    );
    let mut request_headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut request_headers).await;
    assert!(matches!(result, PluginResult::Continue));

    let mut response_headers =
        HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    let body = json!({
        "protocolVersion": "0.3.0",
        "name": "planner",
        "description": "planning agent",
        "preferredTransport": "GRPC",
        "url": "https://planner.internal/grpc",
        "agentCardUrl": "https://planner.internal/.well-known/agent-card.json",
        "signatures": [{"protected": "eyJhbGciOiJFUzI1NiJ9", "signature": "stale"}],
        "additionalInterfaces": [
            {"transport": "JSONRPC", "url": "https://planner.internal/a2a"},
            {"transport": "GRPC", "url": "https://planner.internal/grpc"}
        ]
    })
    .to_string();

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, body.as_bytes())
        .await;
    let PluginResult::Reject {
        status_code, body, ..
    } = result
    else {
        panic!("agent card rewrite should replace response body");
    };
    assert_eq!(status_code, 200);
    let body: Value = serde_json::from_str(&body).expect("body should be JSON");
    assert_eq!(body["url"], "https://planner.internal/grpc");
    assert_eq!(
        body["additionalInterfaces"][0]["url"],
        "https://gateway.example.com/a2a"
    );
    assert_eq!(
        body["additionalInterfaces"][1]["url"],
        "https://planner.internal/grpc"
    );
    assert_eq!(
        body["agentCardUrl"],
        "https://gateway.example.com/agents/planner/.well-known/agent-card.json"
    );
    assert!(body.get("signatures").is_none());
}

#[tokio::test]
async fn grpc_a2a_method_is_detected_without_request_buffering() {
    let plugin = plugin(json!({}));
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/lf.a2a.v1.A2AService/SendStreamingMessage".to_string(),
    );
    ctx.headers
        .insert("content-type".to_string(), "application/grpc".to_string());
    let mut headers = ctx.headers.clone();

    assert!(!plugin.should_buffer_request_body(&ctx));
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata.get("a2a.binding").map(String::as_str),
        Some("grpc")
    );
    assert_eq!(
        ctx.metadata.get("a2a.method").map(String::as_str),
        Some("message/stream")
    );
    assert_eq!(
        ctx.metadata.get("a2a.streaming").map(String::as_str),
        Some("true")
    );
    assert!(!plugin.should_buffer_response_body(&ctx));
    assert!(!plugin.forces_reqwest_dispatch(&ctx));
}

#[tokio::test]
async fn jsonrpc_agent_card_response_rewrites_gateway_urls() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let (mut ctx, mut headers) = jsonrpc_ctx(json!({
        "jsonrpc": "2.0",
        "id": "req-card",
        "method": "GetExtendedAgentCard",
        "params": {}
    }));

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(plugin.should_buffer_response_body(&ctx));

    let mut response_headers =
        HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    let body = json!({
        "jsonrpc": "2.0",
        "id": "req-card",
        "result": {
            "name": "planner",
            "description": "planning agent",
            "signatures": [{"protected": "eyJhbGciOiJFUzI1NiJ9", "signature": "stale"}],
            "supported_interfaces": [
                {
                    "protocol_binding": "JSONRPC",
                    "protocol_version": "0.3",
                    "url": "https://planner.internal/a2a"
                },
                {
                    "protocol_binding": "GRPC",
                    "protocol_version": "0.3",
                    "url": "https://planner.internal/grpc"
                }
            ]
        }
    })
    .to_string();

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, body.as_bytes())
        .await;
    let PluginResult::Reject { body, .. } = result else {
        panic!("JSON-RPC agent card rewrite should replace response body");
    };
    let body: Value = serde_json::from_str(&body).expect("body should be JSON");
    let result = &body["result"];
    assert!(result.get("url").is_none());
    assert_eq!(
        result["supported_interfaces"][0]["url"],
        "https://gateway.example.com/a2a"
    );
    assert_eq!(
        result["supported_interfaces"][1]["url"],
        "https://planner.internal/grpc"
    );
    assert!(result.get("signatures").is_none());
}

#[tokio::test]
async fn agent_card_rewrite_still_runs_when_metadata_is_disabled() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        },
        "observability": {
            "emit_metadata": false
        }
    }));
    let (mut ctx, mut request_headers) =
        rest_ctx("GET", "/agents/planner/.well-known/agent-card.json");

    let result = plugin.before_proxy(&mut ctx, &mut request_headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(ctx.metadata.is_empty());
    assert!(plugin.should_buffer_response_body(&ctx));

    let mut response_headers =
        HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    let body = json!({
        "protocolVersion": "0.3.0",
        "name": "planner",
        "url": "https://planner.internal/a2a"
    })
    .to_string();

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, body.as_bytes())
        .await;
    let PluginResult::Reject { body, .. } = result else {
        panic!("agent card rewrite should replace response body");
    };
    let body: Value = serde_json::from_str(&body).expect("body should be JSON");
    assert_eq!(body["url"], "https://gateway.example.com/a2a");
    assert!(ctx.metadata.is_empty());
}

#[tokio::test]
async fn non_agent_card_response_shape_is_not_rewritten() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let (mut ctx, mut request_headers) = rest_ctx("GET", "/a2a/v1/tasks/task-1");

    let result = plugin.before_proxy(&mut ctx, &mut request_headers).await;
    assert!(matches!(result, PluginResult::Continue));

    let mut response_headers =
        HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    let body = json!({
        "protocolVersion": "0.3.0",
        "name": "task-shaped-custom-payload",
        "url": "https://backend.example.com/not-an-agent-card",
        "id": "task-1"
    })
    .to_string();

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, body.as_bytes())
        .await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn invalid_forwarded_origin_does_not_rewrite_agent_card() {
    let plugin = plugin(json!({
        "discovery": {
            "trust_forwarded_headers": true
        }
    }));
    let (mut ctx, mut request_headers) =
        rest_ctx("GET", "/agents/planner/.well-known/agent-card.json");
    ctx.headers
        .insert("x-forwarded-proto".to_string(), "javascript".to_string());
    ctx.headers
        .insert("host".to_string(), "gateway.example.com".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut request_headers).await;
    assert!(matches!(result, PluginResult::Continue));

    let mut response_headers =
        HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    let body = json!({
        "protocolVersion": "0.3.0",
        "name": "planner",
        "url": "https://planner.internal/a2a"
    })
    .to_string();

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, body.as_bytes())
        .await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn response_host_is_not_used_for_agent_card_public_rewrite() {
    let plugin = plugin(json!({
        "discovery": {
            "trust_forwarded_headers": true
        }
    }));
    let (mut ctx, mut request_headers) =
        rest_ctx("GET", "/agents/planner/.well-known/agent-card.json");

    let result = plugin.before_proxy(&mut ctx, &mut request_headers).await;
    assert!(matches!(result, PluginResult::Continue));

    let mut response_headers = HashMap::from([
        ("content-type".to_string(), "application/json".to_string()),
        ("host".to_string(), "backend.example.com".to_string()),
    ]);
    let body = json!({
        "protocolVersion": "0.3.0",
        "name": "planner",
        "url": "https://planner.internal/a2a"
    })
    .to_string();

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, body.as_bytes())
        .await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn trusted_forwarded_origin_rewrites_agent_card_url() {
    let plugin = plugin(json!({
        "discovery": {
            "trust_forwarded_headers": true
        }
    }));
    let (mut ctx, mut request_headers) =
        rest_ctx("GET", "/agents/planner/.well-known/agent-card.json");
    ctx.headers
        .insert("x-forwarded-proto".to_string(), "https".to_string());
    ctx.headers.insert(
        "x-forwarded-host".to_string(),
        "gateway.example.com".to_string(),
    );

    let result = plugin.before_proxy(&mut ctx, &mut request_headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(plugin.should_buffer_response_body(&ctx));

    let mut response_headers =
        HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    let body = json!({
        "protocolVersion": "0.3.0",
        "name": "planner",
        "url": "https://planner.internal/a2a"
    })
    .to_string();

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, body.as_bytes())
        .await;
    let PluginResult::Reject { body, .. } = result else {
        panic!("trusted forwarded origin should rewrite the agent card");
    };
    let body: Value = serde_json::from_str(&body).expect("body should be JSON");
    assert_eq!(body["url"], "https://gateway.example.com/a2a");
}

#[tokio::test]
async fn trusted_host_header_rewrites_agent_card_url_without_forwarded_host() {
    let plugin = plugin(json!({
        "discovery": {
            "trust_forwarded_headers": true
        }
    }));
    let (mut ctx, mut request_headers) =
        rest_ctx("GET", "/agents/planner/.well-known/agent-card.json");
    ctx.headers
        .insert("x-forwarded-proto".to_string(), "https".to_string());
    ctx.headers
        .insert("host".to_string(), "gateway.example.com".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut request_headers).await;
    assert!(matches!(result, PluginResult::Continue));

    let mut response_headers =
        HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    let body = json!({
        "protocolVersion": "0.3.0",
        "name": "planner",
        "url": "https://planner.internal/a2a"
    })
    .to_string();

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, body.as_bytes())
        .await;
    let PluginResult::Reject { body, .. } = result else {
        panic!("trusted host header should rewrite the agent card");
    };
    let body: Value = serde_json::from_str(&body).expect("body should be JSON");
    assert_eq!(body["url"], "https://gateway.example.com/a2a");
}

#[tokio::test]
async fn agent_card_rewrite_strips_stale_body_coupled_headers() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let (mut ctx, mut request_headers) =
        rest_ctx("GET", "/agents/planner/.well-known/agent-card.json");

    let result = plugin.before_proxy(&mut ctx, &mut request_headers).await;
    assert!(matches!(result, PluginResult::Continue));

    // Mixed-case header names exercise the case-insensitive strip.
    let mut response_headers = HashMap::from([
        ("content-type".to_string(), "application/json".to_string()),
        ("Content-Length".to_string(), "128".to_string()),
        ("Content-Encoding".to_string(), "gzip".to_string()),
        ("ETag".to_string(), "\"abc123\"".to_string()),
        (
            "Last-Modified".to_string(),
            "Wed, 21 Oct 2026 07:28:00 GMT".to_string(),
        ),
        (
            "Content-Digest".to_string(),
            "sha-256=:deadbeef:".to_string(),
        ),
        ("Cache-Control".to_string(), "max-age=300".to_string()),
    ]);
    let body = json!({
        "protocolVersion": "0.3.0",
        "name": "planner",
        "url": "https://planner.internal/a2a"
    })
    .to_string();

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, body.as_bytes())
        .await;
    let PluginResult::Reject { headers, body, .. } = result else {
        panic!("agent card rewrite should replace response body");
    };
    let rewritten: Value = serde_json::from_str(&body).expect("body should be JSON");
    assert_eq!(rewritten["url"], "https://gateway.example.com/a2a");

    // Validators, integrity digests, and the content encoding describe the
    // backend body and no longer match the re-serialized (uncompressed) card,
    // so they must be dropped on rewrite.
    for stale in [
        "content-length",
        "content-encoding",
        "etag",
        "last-modified",
        "content-digest",
    ] {
        assert!(
            !headers.keys().any(|key| key.eq_ignore_ascii_case(stale)),
            "expected {stale} to be stripped after rewrite, got {headers:?}"
        );
    }
    // Headers unrelated to the body are preserved, and content-type is normalized.
    assert!(
        headers
            .keys()
            .any(|key| key.eq_ignore_ascii_case("cache-control"))
    );
    assert_eq!(
        headers.get("content-type").map(String::as_str),
        Some("application/json")
    );
}

#[tokio::test]
async fn oversized_jsonrpc_body_fails_closed_when_policy_can_deny() {
    let plugin = plugin(json!({
        "detection": {
            "max_request_body_size": 16
        },
        "policy": {
            "methods": {
                "message/send": {"action": "deny"}
            }
        }
    }));
    let body = json!({
        "jsonrpc": "2.0",
        "id": "req-oversized",
        "method": "message/send",
        "params": {"padding": "this body is intentionally too large"}
    })
    .to_string();
    let (mut ctx, mut headers) = jsonrpc_ctx_with_raw_body(body);

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    let PluginResult::Reject {
        status_code, body, ..
    } = result
    else {
        panic!("oversized policy candidate should reject");
    };
    assert_eq!(status_code, 413);
    let body: Value = serde_json::from_str(&body).expect("body should be JSON");
    assert_eq!(body["error"]["data"]["method"], "unknown");
    assert_eq!(
        ctx.metadata.get("a2a.policy_decision").map(String::as_str),
        Some("deny")
    );
}

#[tokio::test]
async fn oversized_jsonrpc_body_continues_when_policy_cannot_deny() {
    let plugin = plugin(json!({
        "detection": {
            "max_request_body_size": 16
        }
    }));
    let body = json!({
        "jsonrpc": "2.0",
        "id": "req-oversized",
        "method": "message/send",
        "params": {"padding": "this body is intentionally too large"}
    })
    .to_string();
    let (mut ctx, mut headers) = jsonrpc_ctx_with_raw_body(body);

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(!ctx.metadata.contains_key("a2a.enabled"));
}

#[tokio::test]
async fn unknown_jsonrpc_method_is_denied_when_unknown_policy_denies() {
    let cases = [
        (
            json!({"policy": {"default_action": "deny"}}),
            "default deny should reject unknown JSON-RPC methods",
        ),
        (
            json!({"policy": {"methods": {"unknown": {"action": "deny"}}}}),
            "explicit unknown deny should reject unknown JSON-RPC methods",
        ),
    ];

    for (config, label) in cases {
        let plugin = plugin(config);
        let (mut ctx, mut headers) = jsonrpc_ctx(json!({
            "jsonrpc": "2.0",
            "id": "req-custom-method",
            "method": "FutureCustomMethod"
        }));

        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        let PluginResult::Reject {
            status_code, body, ..
        } = result
        else {
            panic!("{label}");
        };
        assert_eq!(status_code, 200, "{label}");
        let body: Value = serde_json::from_str(&body).expect("body should be JSON");
        assert_eq!(body["error"]["data"]["method"], "unknown", "{label}");
        assert_eq!(
            ctx.metadata.get("a2a.policy_decision").map(String::as_str),
            Some("deny"),
            "{label}"
        );
    }
}

#[tokio::test]
async fn rest_detection_is_scoped_to_configured_endpoint_path() {
    let plugin = plugin(json!({
        "policy": {
            "default_action": "deny"
        }
    }));
    let (mut unrelated_ctx, mut unrelated_headers) = rest_ctx("GET", "/api/v1/tasks/task-1");
    let result = plugin
        .before_proxy(&mut unrelated_ctx, &mut unrelated_headers)
        .await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(!unrelated_ctx.metadata.contains_key("a2a.enabled"));

    let (mut a2a_ctx, mut a2a_headers) = rest_ctx("GET", "/a2a/tasks/task-1");
    let result = plugin.before_proxy(&mut a2a_ctx, &mut a2a_headers).await;
    assert!(matches!(
        result,
        PluginResult::Reject {
            status_code: 403,
            ..
        }
    ));
}

#[tokio::test]
async fn rest_post_tasks_is_not_classified_as_list_tasks() {
    let plugin = plugin(json!({
        "policy": {
            "default_action": "deny"
        }
    }));
    let (mut ctx, mut headers) = rest_ctx("POST", "/a2a/v1/tasks");

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(!ctx.metadata.contains_key("a2a.enabled"));
}

#[tokio::test]
async fn rest_operation_table_emits_expected_metadata() {
    let cases = [
        ("POST", "/a2a/message:send", "message/send", None, "false"),
        (
            "POST",
            "/a2a/acme/message:stream",
            "message/stream",
            None,
            "true",
        ),
        ("GET", "/a2a/tasks", "tasks/list", None, "false"),
        (
            "GET",
            "/a2a/acme/tasks/task-1",
            "tasks/get",
            Some("task-1"),
            "false",
        ),
        (
            "POST",
            "/a2a/v1/message:send",
            "message/send",
            None,
            "false",
        ),
        (
            "POST",
            "/a2a/v1/message:stream",
            "message/stream",
            None,
            "true",
        ),
        ("GET", "/a2a/v1/tasks", "tasks/list", None, "false"),
        (
            "GET",
            "/a2a/v1/tasks/task-1",
            "tasks/get",
            Some("task-1"),
            "false",
        ),
        (
            "POST",
            "/a2a/v1/tasks/task-1:cancel",
            "tasks/cancel",
            Some("task-1"),
            "false",
        ),
        (
            "GET",
            "/a2a/v1/tasks/task-1:subscribe",
            "tasks/resubscribe",
            Some("task-1"),
            "true",
        ),
        (
            "POST",
            "/a2a/v1/tasks/task-1:subscribe",
            "tasks/resubscribe",
            Some("task-1"),
            "true",
        ),
        (
            "GET",
            "/a2a/v1/tasks/task-1/pushNotificationConfigs",
            "tasks/pushNotificationConfig/list",
            Some("task-1"),
            "false",
        ),
        (
            "POST",
            "/a2a/v1/tasks/task-1/pushNotificationConfigs",
            "tasks/pushNotificationConfig/set",
            Some("task-1"),
            "false",
        ),
        (
            "GET",
            "/a2a/v1/tasks/task-1/pushNotificationConfigs/config-1",
            "tasks/pushNotificationConfig/get",
            Some("task-1"),
            "false",
        ),
        (
            "DELETE",
            "/a2a/v1/tasks/task-1/pushNotificationConfigs/config-1",
            "tasks/pushNotificationConfig/delete",
            Some("task-1"),
            "false",
        ),
    ];

    for (method, path, expected_method, expected_task_id, expected_streaming) in cases {
        let plugin = plugin(json!({}));
        let (mut ctx, mut headers) = rest_ctx(method, path);
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(
            matches!(result, PluginResult::Continue),
            "{method} {path} should continue"
        );
        assert_eq!(
            ctx.metadata.get("a2a.method").map(String::as_str),
            Some(expected_method),
            "{method} {path}"
        );
        assert_eq!(
            ctx.metadata.get("a2a.task_id").map(String::as_str),
            expected_task_id,
            "{method} {path}"
        );
        assert_eq!(
            ctx.metadata.get("a2a.streaming").map(String::as_str),
            Some(expected_streaming),
            "{method} {path}"
        );
    }

    let plugin = plugin(json!({}));
    let (mut ctx, mut headers) = rest_ctx("GET", "/a2a/tasks/task-1/child");
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(!ctx.metadata.contains_key("a2a.enabled"));
}

#[tokio::test]
async fn grpc_standard_push_rpc_names_are_detected() {
    let cases = [
        (
            "CreateTaskPushNotification",
            "tasks/pushNotificationConfig/set",
        ),
        (
            "GetTaskPushNotification",
            "tasks/pushNotificationConfig/get",
        ),
        (
            "ListTaskPushNotification",
            "tasks/pushNotificationConfig/list",
        ),
        (
            "ListTaskPushNotificationConfigs",
            "tasks/pushNotificationConfig/list",
        ),
        (
            "DeleteTaskPushNotification",
            "tasks/pushNotificationConfig/delete",
        ),
    ];

    for (rpc, expected_method) in cases {
        let plugin = plugin(json!({}));
        let (mut ctx, mut headers) = grpc_ctx(rpc, "application/grpc");
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(matches!(result, PluginResult::Continue), "{rpc}");
        assert_eq!(
            ctx.metadata.get("a2a.method").map(String::as_str),
            Some(expected_method),
            "{rpc}"
        );
    }
}

#[tokio::test]
async fn grpc_get_agent_card_maps_to_authenticated_card() {
    let plugin = plugin(json!({
        "policy": {
            "methods": {
                "agent/getAuthenticatedExtendedCard": {"action": "deny"}
            }
        }
    }));
    let (mut ctx, mut headers) = grpc_ctx("GetAgentCard", "application/grpc");

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        PluginResult::Reject {
            status_code: 403,
            ..
        }
    ));
    assert_eq!(
        ctx.metadata.get("a2a.method").map(String::as_str),
        Some("agent/getAuthenticatedExtendedCard")
    );
}

#[tokio::test]
async fn grpc_get_agent_card_denied_via_pascalcase_policy_alias() {
    // The PascalCase `GetAgentCard` policy key must normalize to the same method
    // the gRPC binding detects (agent/getAuthenticatedExtendedCard); otherwise a
    // `GetAgentCard: deny` rule silently fails to block the gRPC card RPC.
    let plugin = plugin(json!({
        "policy": {
            "methods": {
                "GetAgentCard": {"action": "deny"}
            }
        }
    }));
    let (mut ctx, mut headers) = grpc_ctx("GetAgentCard", "application/grpc");

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        PluginResult::Reject {
            status_code: 403,
            ..
        }
    ));
    assert_eq!(
        ctx.metadata.get("a2a.method").map(String::as_str),
        Some("agent/getAuthenticatedExtendedCard")
    );
}

fn encode_proto_varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn encode_proto_string(field: u32, value: &str, out: &mut Vec<u8>) {
    encode_proto_varint(u64::from(field) << 3 | 2, out);
    encode_proto_varint(value.len() as u64, out);
    out.extend_from_slice(value.as_bytes());
}

fn encode_proto_bytes(field: u32, value: &[u8], out: &mut Vec<u8>) {
    encode_proto_varint(u64::from(field) << 3 | 2, out);
    encode_proto_varint(value.len() as u64, out);
    out.extend_from_slice(value);
}

fn encode_proto_varint_field(field: u32, value: u64, out: &mut Vec<u8>) {
    encode_proto_varint(u64::from(field) << 3, out);
    encode_proto_varint(value, out);
}

fn encode_proto_fixed64_field(field: u32, value: u64, out: &mut Vec<u8>) {
    encode_proto_varint(u64::from(field) << 3 | 1, out);
    out.extend_from_slice(&value.to_le_bytes());
}

fn encode_proto_fixed32_field(field: u32, value: u32, out: &mut Vec<u8>) {
    encode_proto_varint(u64::from(field) << 3 | 5, out);
    out.extend_from_slice(&value.to_le_bytes());
}

/// Minimal Agent Card with identity + endpoint fields; optional extras appended.
fn encode_minimal_agent_card(
    name: &str,
    description: &str,
    url: &str,
    extras: impl FnOnce(&mut Vec<u8>),
) -> Vec<u8> {
    let mut out = Vec::new();
    encode_proto_string(1, name, &mut out);
    encode_proto_string(2, description, &mut out);
    encode_proto_string(3, url, &mut out);
    extras(&mut out);
    out
}

async fn detect_grpc_agent_card(
    plugin: &std::sync::Arc<dyn ferrum_edge::plugins::Plugin>,
    rpc: &str,
) -> RequestContext {
    let (mut ctx, mut headers) = grpc_ctx(rpc, "application/grpc");
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    ctx
}

fn assert_grpc_rewrite_reject(result: PluginResult, diagnostic: &str, metadata: Option<&str>) {
    let PluginResult::Reject {
        status_code,
        headers,
        ..
    } = result
    else {
        panic!("expected gRPC Agent Card rewrite reject for {diagnostic}");
    };
    assert_eq!(status_code, 500);
    assert_eq!(headers.get("grpc-status").map(String::as_str), Some("13"));
    assert_eq!(
        headers.get("grpc-message").map(String::as_str),
        Some(diagnostic)
    );
    if let Some(metadata) = metadata {
        assert_eq!(metadata, diagnostic);
    }
}

fn encode_agent_interface(url: &str, transport: &str) -> Vec<u8> {
    let mut out = Vec::new();
    encode_proto_string(1, url, &mut out);
    encode_proto_string(2, transport, &mut out);
    out
}

fn encode_agent_card_signature(protected: &str, signature: &str) -> Vec<u8> {
    let mut out = Vec::new();
    encode_proto_string(1, protected, &mut out);
    encode_proto_string(2, signature, &mut out);
    out
}

fn encode_a2a_03_agent_card(
    name: &str,
    description: &str,
    url: &str,
    preferred_transport: &str,
    interfaces: &[(&str, &str)],
    protocol_version: &str,
    with_signature: bool,
) -> Vec<u8> {
    let mut out = Vec::new();
    encode_proto_string(1, name, &mut out);
    encode_proto_string(2, description, &mut out);
    encode_proto_string(3, url, &mut out);
    encode_proto_string(14, preferred_transport, &mut out);
    for (interface_url, transport) in interfaces {
        encode_proto_bytes(
            15,
            &encode_agent_interface(interface_url, transport),
            &mut out,
        );
    }
    encode_proto_string(16, protocol_version, &mut out);
    if with_signature {
        encode_proto_bytes(
            17,
            &encode_agent_card_signature("eyJhbGciOiJFUzI1NiJ9", "stale"),
            &mut out,
        );
    }
    out
}

fn frame_grpc_message(message: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(5 + message.len());
    frame.push(0);
    frame.extend_from_slice(&(message.len() as u32).to_be_bytes());
    frame.extend_from_slice(message);
    frame
}

fn proto_string_field(message: &[u8], target: u32) -> Option<String> {
    let mut buf = message;
    while !buf.is_empty() {
        let mut key = 0u64;
        for shift in (0..64).step_by(7) {
            let byte = *buf.first()?;
            buf = &buf[1..];
            key |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                break;
            }
        }
        let field = (key >> 3) as u32;
        let wire = (key & 0x07) as u8;
        match wire {
            0 => {
                for shift in (0..64).step_by(7) {
                    let byte = *buf.first()?;
                    buf = &buf[1..];
                    if byte & 0x80 == 0 {
                        let _ = shift;
                        break;
                    }
                }
            }
            1 => {
                if buf.len() < 8 {
                    return None;
                }
                buf = &buf[8..];
            }
            2 => {
                let mut len = 0usize;
                for shift in (0..64).step_by(7) {
                    let byte = *buf.first()?;
                    buf = &buf[1..];
                    len |= usize::from(byte & 0x7f) << shift;
                    if byte & 0x80 == 0 {
                        break;
                    }
                }
                if buf.len() < len {
                    return None;
                }
                let (value, rest) = buf.split_at(len);
                buf = rest;
                if field == target {
                    return std::str::from_utf8(value).ok().map(str::to_owned);
                }
            }
            5 => {
                if buf.len() < 4 {
                    return None;
                }
                buf = &buf[4..];
            }
            _ => return None,
        }
    }
    None
}

fn proto_has_field(message: &[u8], target: u32) -> bool {
    let mut buf = message;
    while !buf.is_empty() {
        let mut key = 0u64;
        for shift in (0..64).step_by(7) {
            let Some(&byte) = buf.first() else {
                return false;
            };
            buf = &buf[1..];
            key |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                let _ = shift;
                break;
            }
        }
        let field = (key >> 3) as u32;
        let wire = (key & 0x07) as u8;
        let len = match wire {
            0 => {
                for _ in 0..10 {
                    let Some(&byte) = buf.first() else {
                        return false;
                    };
                    buf = &buf[1..];
                    if byte & 0x80 == 0 {
                        break;
                    }
                }
                0
            }
            1 => 8,
            2 => {
                let mut len = 0usize;
                for shift in (0..64).step_by(7) {
                    let Some(&byte) = buf.first() else {
                        return false;
                    };
                    buf = &buf[1..];
                    len |= usize::from(byte & 0x7f) << shift;
                    if byte & 0x80 == 0 {
                        break;
                    }
                }
                len
            }
            5 => 4,
            _ => return false,
        };
        if wire != 0 {
            if buf.len() < len {
                return false;
            }
            buf = &buf[len..];
        }
        if field == target {
            return true;
        }
    }
    false
}

fn proto_repeated_messages(message: &[u8], target: u32) -> Vec<Vec<u8>> {
    let mut found = Vec::new();
    let mut buf = message;
    while !buf.is_empty() {
        let mut key = 0u64;
        for shift in (0..64).step_by(7) {
            let Some(&byte) = buf.first() else {
                return found;
            };
            buf = &buf[1..];
            key |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                break;
            }
        }
        let field = (key >> 3) as u32;
        let wire = (key & 0x07) as u8;
        match wire {
            0 => {
                for _ in 0..10 {
                    let Some(&byte) = buf.first() else {
                        return found;
                    };
                    buf = &buf[1..];
                    if byte & 0x80 == 0 {
                        break;
                    }
                }
            }
            1 => {
                if buf.len() < 8 {
                    return found;
                }
                buf = &buf[8..];
            }
            2 => {
                let mut len = 0usize;
                for shift in (0..64).step_by(7) {
                    let Some(&byte) = buf.first() else {
                        return found;
                    };
                    buf = &buf[1..];
                    len |= usize::from(byte & 0x7f) << shift;
                    if byte & 0x80 == 0 {
                        break;
                    }
                }
                if buf.len() < len {
                    return found;
                }
                let (value, rest) = buf.split_at(len);
                buf = rest;
                if field == target {
                    found.push(value.to_vec());
                }
            }
            5 => {
                if buf.len() < 4 {
                    return found;
                }
                buf = &buf[4..];
            }
            _ => return found,
        }
    }
    found
}

#[tokio::test]
async fn grpc_agent_card_response_rewrites_jsonrpc_urls() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let (mut ctx, mut headers) = grpc_ctx("GetExtendedAgentCard", "application/grpc");
    headers.insert("grpc-accept-encoding".to_string(), "gzip".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(plugin.should_buffer_response_body(&ctx));
    assert!(!headers.contains_key("grpc-accept-encoding"));

    let card = encode_a2a_03_agent_card(
        "planner",
        "planning agent",
        "https://planner.internal/grpc",
        "GRPC",
        &[
            ("https://planner.internal/a2a", "JSONRPC"),
            ("https://planner.internal/grpc", "GRPC"),
        ],
        "0.3.0",
        true,
    );
    let body = frame_grpc_message(&card);
    let mut response_headers =
        HashMap::from([("content-type".to_string(), "application/grpc".to_string())]);
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, &body)
        .await;
    assert!(matches!(result, PluginResult::Continue));
    let rewritten = plugin
        .transform_response_body_with_context(
            &mut ctx,
            &body,
            Some("application/grpc"),
            &response_headers,
        )
        .await
        .expect("rewritten grpc agent card frame");
    assert_eq!(rewritten[0], 0);
    let msg_len =
        u32::from_be_bytes([rewritten[1], rewritten[2], rewritten[3], rewritten[4]]) as usize;
    assert_eq!(rewritten.len(), 5 + msg_len);
    let message = &rewritten[5..];
    assert_eq!(
        proto_string_field(message, 3).as_deref(),
        Some("https://planner.internal/grpc")
    );
    let interfaces = proto_repeated_messages(message, 15);
    assert_eq!(interfaces.len(), 2);
    assert_eq!(
        proto_string_field(&interfaces[0], 1).as_deref(),
        Some("https://gateway.example.com/a2a")
    );
    assert_eq!(
        proto_string_field(&interfaces[1], 1).as_deref(),
        Some("https://planner.internal/grpc")
    );
    assert!(!proto_has_field(message, 17));
    plugin.on_response_body_transformed(&mut ctx, &mut response_headers);
    assert!(!response_headers.contains_key("content-length"));
    assert!(!response_headers.contains_key("grpc-encoding"));
}

#[tokio::test]
async fn grpc_agent_card_unsupported_version_fails_closed() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let (mut ctx, mut headers) = grpc_ctx("GetAgentCard", "application/grpc");
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));

    let card = encode_a2a_03_agent_card(
        "planner",
        "planning agent",
        "https://planner.internal/a2a",
        "JSONRPC",
        &[("https://planner.internal/a2a", "JSONRPC")],
        "1.0.0",
        true,
    );
    let body = frame_grpc_message(&card);
    let mut response_headers =
        HashMap::from([("content-type".to_string(), "application/grpc".to_string())]);
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, &body)
        .await;
    let PluginResult::Reject {
        status_code,
        headers: reject_headers,
        ..
    } = result
    else {
        panic!("unsupported protobuf version must fail closed");
    };
    assert_eq!(status_code, 500);
    assert_eq!(
        reject_headers.get("grpc-status").map(String::as_str),
        Some("13")
    );
    assert_eq!(
        reject_headers.get("grpc-message").map(String::as_str),
        Some("unsupported_agent_card_protobuf_version")
    );
    assert_eq!(
        ctx.metadata.get("a2a.error").map(String::as_str),
        Some("unsupported_agent_card_protobuf_version")
    );
}

#[tokio::test]
async fn grpc_agent_card_malformed_frame_fails_closed() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let (mut ctx, mut headers) = grpc_ctx("GetExtendedAgentCard", "application/grpc");
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    let mut response_headers =
        HashMap::from([("content-type".to_string(), "application/grpc".to_string())]);
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, &[0x00, 0x00, 0x00])
        .await;
    assert!(matches!(
        result,
        PluginResult::Reject {
            status_code: 500,
            ..
        }
    ));
    assert_eq!(
        ctx.metadata.get("a2a.error").map(String::as_str),
        Some("agent_card_grpc_frame_malformed")
    );
}

#[tokio::test]
async fn grpc_agent_card_without_public_base_is_not_rewritten() {
    let plugin = plugin(json!({
        "discovery": {
            "rewrite_agent_card_urls": true,
            "trust_forwarded_headers": false
        }
    }));
    let (mut ctx, mut headers) = grpc_ctx("GetExtendedAgentCard", "application/grpc");
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    let card = encode_a2a_03_agent_card(
        "planner",
        "planning agent",
        "https://planner.internal/a2a",
        "JSONRPC",
        &[("https://planner.internal/a2a", "JSONRPC")],
        "0.3.0",
        true,
    );
    let body = frame_grpc_message(&card);
    let mut response_headers =
        HashMap::from([("content-type".to_string(), "application/grpc".to_string())]);
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, &body)
        .await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(
        plugin
            .transform_response_body_with_context(
                &mut ctx,
                &body,
                Some("application/grpc"),
                &response_headers,
            )
            .await
            .is_none()
    );
}

#[tokio::test]
async fn grpc_agent_card_preferred_jsonrpc_url_is_rewritten() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let (mut ctx, mut headers) = grpc_ctx("GetExtendedAgentCard", "application/grpc");
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    let card = encode_a2a_03_agent_card(
        "planner",
        "planning agent",
        "https://planner.internal/a2a",
        "JSONRPC",
        &[],
        "0.3.0",
        true,
    );
    let body = frame_grpc_message(&card);
    let mut response_headers =
        HashMap::from([("content-type".to_string(), "application/grpc".to_string())]);
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut response_headers, &body)
            .await,
        PluginResult::Continue
    ));
    let rewritten = plugin
        .transform_response_body_with_context(
            &mut ctx,
            &body,
            Some("application/grpc"),
            &response_headers,
        )
        .await
        .expect("preferred jsonrpc url should rewrite");
    let message = &rewritten[5..];
    assert_eq!(
        proto_string_field(message, 3).as_deref(),
        Some("https://gateway.example.com/a2a")
    );
    assert!(!proto_has_field(message, 17));
}

#[tokio::test]
async fn grpc_agent_card_empty_body_is_trailers_only_passthrough() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetAgentCard").await;
    let mut response_headers =
        HashMap::from([("content-type".to_string(), "application/grpc".to_string())]);
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, &[])
        .await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(
        plugin
            .transform_response_body_with_context(
                &mut ctx,
                &[],
                Some("application/grpc"),
                &response_headers,
            )
            .await
            .is_none()
    );
}

#[tokio::test]
async fn grpc_agent_card_non_ok_status_skips_rewrite() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetExtendedAgentCard").await;
    let card = encode_a2a_03_agent_card(
        "planner",
        "planning agent",
        "https://planner.internal/a2a",
        "JSONRPC",
        &[("https://planner.internal/a2a", "JSONRPC")],
        "0.3.0",
        true,
    );
    let body = frame_grpc_message(&card);
    let mut response_headers = HashMap::from([
        ("content-type".to_string(), "application/grpc".to_string()),
        ("grpc-status".to_string(), "14".to_string()),
    ]);
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, &body)
        .await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(
        plugin
            .transform_response_body_with_context(
                &mut ctx,
                &body,
                Some("application/grpc"),
                &response_headers,
            )
            .await
            .is_none(),
        "non-OK grpc-status must not rewrite an Agent Card frame"
    );
}

#[tokio::test]
async fn grpc_agent_card_compressed_frame_fails_closed() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetAgentCard").await;
    let mut compressed = frame_grpc_message(b"not-a-card");
    compressed[0] = 1; // gRPC compression flag
    let mut response_headers =
        HashMap::from([("content-type".to_string(), "application/grpc".to_string())]);
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, &compressed)
        .await;
    assert_grpc_rewrite_reject(
        result,
        "agent_card_grpc_encoding_unsupported",
        ctx.metadata.get("a2a.error").map(String::as_str),
    );
}

#[tokio::test]
async fn grpc_agent_card_grpc_encoding_header_fails_closed() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetExtendedAgentCard").await;
    let card = encode_a2a_03_agent_card(
        "planner",
        "planning agent",
        "https://planner.internal/a2a",
        "JSONRPC",
        &[("https://planner.internal/a2a", "JSONRPC")],
        "0.3.0",
        false,
    );
    let body = frame_grpc_message(&card);
    let mut response_headers = HashMap::from([
        ("content-type".to_string(), "application/grpc".to_string()),
        ("grpc-encoding".to_string(), "gzip".to_string()),
    ]);
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, &body)
        .await;
    assert_grpc_rewrite_reject(
        result,
        "agent_card_grpc_encoding_unsupported",
        ctx.metadata.get("a2a.error").map(String::as_str),
    );
}

#[tokio::test]
async fn grpc_agent_card_length_prefix_mismatch_fails_closed() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetAgentCard").await;
    // Claims 10 payload bytes but only carries 3.
    let body = vec![0, 0, 0, 0, 10, 1, 2, 3];
    let mut response_headers =
        HashMap::from([("content-type".to_string(), "application/grpc".to_string())]);
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, &body)
        .await;
    assert_grpc_rewrite_reject(
        result,
        "agent_card_grpc_frame_malformed",
        ctx.metadata.get("a2a.error").map(String::as_str),
    );
}

#[tokio::test]
async fn grpc_agent_card_unrecognized_protobuf_shape_fails_closed() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetAgentCard").await;
    // Valid unary frame, but missing Agent Card identity/endpoint fields.
    let mut message = Vec::new();
    encode_proto_string(99, "not-an-agent-card", &mut message);
    let body = frame_grpc_message(&message);
    let mut response_headers =
        HashMap::from([("content-type".to_string(), "application/grpc".to_string())]);
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, &body)
        .await;
    assert_grpc_rewrite_reject(
        result,
        "agent_card_protobuf_shape_unrecognized",
        ctx.metadata.get("a2a.error").map(String::as_str),
    );
}

#[tokio::test]
async fn grpc_agent_card_truncated_protobuf_fails_closed() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetAgentCard").await;
    // Length-delimited field claiming more bytes than remain.
    let message = vec![0x0a, 0x05, 0x61, 0x62]; // field 1, len 5, only 2 bytes
    let body = frame_grpc_message(&message);
    let mut response_headers =
        HashMap::from([("content-type".to_string(), "application/grpc".to_string())]);
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, &body)
        .await;
    assert_grpc_rewrite_reject(
        result,
        "agent_card_protobuf_shape_unrecognized",
        ctx.metadata.get("a2a.error").map(String::as_str),
    );
}

#[tokio::test]
async fn grpc_agent_card_invalid_field_number_fails_closed() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetAgentCard").await;
    // Protobuf key with field number 0 is illegal.
    let message = vec![0x02, 0x01, 0x61]; // field 0, wire LEN, one byte
    let body = frame_grpc_message(&message);
    let mut response_headers =
        HashMap::from([("content-type".to_string(), "application/grpc".to_string())]);
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, &body)
        .await;
    assert_grpc_rewrite_reject(
        result,
        "agent_card_protobuf_shape_unrecognized",
        ctx.metadata.get("a2a.error").map(String::as_str),
    );
}

#[tokio::test]
async fn grpc_agent_card_unsupported_wire_type_fails_closed() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetAgentCard").await;
    // Wire type 3 (start-group) is unsupported.
    let message = vec![0x0b]; // field 1, wire 3
    let body = frame_grpc_message(&message);
    let mut response_headers =
        HashMap::from([("content-type".to_string(), "application/grpc".to_string())]);
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, &body)
        .await;
    assert_grpc_rewrite_reject(
        result,
        "agent_card_protobuf_shape_unrecognized",
        ctx.metadata.get("a2a.error").map(String::as_str),
    );
}

#[tokio::test]
async fn grpc_agent_card_protocol_version_wire_mismatch_fails_closed() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetAgentCard").await;
    let card = encode_minimal_agent_card(
        "planner",
        "planning agent",
        "https://planner.internal/a2a",
        |out| {
            encode_proto_string(14, "JSONRPC", out);
            // Field 16 must be LEN-wire string; force a varint mismatch.
            encode_proto_varint_field(16, 1, out);
        },
    );
    let body = frame_grpc_message(&card);
    let mut response_headers =
        HashMap::from([("content-type".to_string(), "application/grpc".to_string())]);
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, &body)
        .await;
    assert_grpc_rewrite_reject(
        result,
        "agent_card_protobuf_field_wire_mismatch",
        ctx.metadata.get("a2a.error").map(String::as_str),
    );
}

#[tokio::test]
async fn grpc_agent_card_missing_protocol_version_still_rewrites_for_03_config() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetExtendedAgentCard").await;
    // Omit field 16: empty version is accepted when config is A2A 0.3.x.
    let card = encode_minimal_agent_card(
        "planner",
        "planning agent",
        "https://planner.internal/a2a",
        |out| {
            encode_proto_string(14, "JSONRPC", out);
        },
    );
    let body = frame_grpc_message(&card);
    let mut response_headers =
        HashMap::from([("content-type".to_string(), "application/grpc".to_string())]);
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut response_headers, &body)
            .await,
        PluginResult::Continue
    ));
    let rewritten = plugin
        .transform_response_body_with_context(
            &mut ctx,
            &body,
            Some("application/grpc"),
            &response_headers,
        )
        .await
        .expect("empty protocol_version should rewrite under 0.3 config");
    assert_eq!(
        proto_string_field(&rewritten[5..], 3).as_deref(),
        Some("https://gateway.example.com/a2a")
    );
}

#[tokio::test]
async fn grpc_agent_card_grpc_only_urls_need_no_mutation() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetExtendedAgentCard").await;
    let card = encode_a2a_03_agent_card(
        "planner",
        "planning agent",
        "https://planner.internal/grpc",
        "GRPC",
        &[("https://planner.internal/grpc", "GRPC")],
        "0.3.0",
        true,
    );
    let body = frame_grpc_message(&card);
    let mut response_headers =
        HashMap::from([("content-type".to_string(), "application/grpc".to_string())]);
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut response_headers, &body)
            .await,
        PluginResult::Continue
    ));
    assert!(
        plugin
            .transform_response_body_with_context(
                &mut ctx,
                &body,
                Some("application/grpc"),
                &response_headers,
            )
            .await
            .is_none(),
        "GRPC-only cards must leave the upstream frame untouched"
    );
}

#[tokio::test]
async fn grpc_agent_card_preserves_matching_jsonrpc_url_when_interface_changes() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetExtendedAgentCard").await;
    // Preferred URL already public; only the additional interface needs rewrite.
    let card = encode_a2a_03_agent_card(
        "planner",
        "planning agent",
        "https://gateway.example.com/a2a",
        "JSONRPC",
        &[("https://planner.internal/a2a", "JSONRPC")],
        "0.3.0",
        true,
    );
    let body = frame_grpc_message(&card);
    let mut response_headers =
        HashMap::from([("content-type".to_string(), "application/grpc".to_string())]);
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut response_headers, &body)
            .await,
        PluginResult::Continue
    ));
    let rewritten = plugin
        .transform_response_body_with_context(
            &mut ctx,
            &body,
            Some("application/grpc"),
            &response_headers,
        )
        .await
        .expect("interface rewrite should still produce a frame");
    let message = &rewritten[5..];
    assert_eq!(
        proto_string_field(message, 3).as_deref(),
        Some("https://gateway.example.com/a2a")
    );
    let interfaces = proto_repeated_messages(message, 15);
    assert_eq!(interfaces.len(), 1);
    assert_eq!(
        proto_string_field(&interfaces[0], 1).as_deref(),
        Some("https://gateway.example.com/a2a")
    );
    assert!(!proto_has_field(message, 17));
}

#[tokio::test]
async fn grpc_agent_card_preserves_matching_interface_url_when_card_url_changes() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetExtendedAgentCard").await;
    let card = encode_a2a_03_agent_card(
        "planner",
        "planning agent",
        "https://planner.internal/a2a",
        "JSONRPC",
        &[("https://gateway.example.com/a2a", "JSONRPC")],
        "0.3.0",
        false,
    );
    let body = frame_grpc_message(&card);
    let mut response_headers =
        HashMap::from([("content-type".to_string(), "application/grpc".to_string())]);
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut response_headers, &body)
            .await,
        PluginResult::Continue
    ));
    let rewritten = plugin
        .transform_response_body_with_context(
            &mut ctx,
            &body,
            Some("application/grpc"),
            &response_headers,
        )
        .await
        .expect("card url rewrite should still produce a frame");
    let message = &rewritten[5..];
    assert_eq!(
        proto_string_field(message, 3).as_deref(),
        Some("https://gateway.example.com/a2a")
    );
    let interfaces = proto_repeated_messages(message, 15);
    assert_eq!(
        proto_string_field(&interfaces[0], 1).as_deref(),
        Some("https://gateway.example.com/a2a")
    );
}

#[tokio::test]
async fn grpc_agent_card_empty_preferred_transport_rewrites_url() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetExtendedAgentCard").await;
    let card = encode_minimal_agent_card(
        "planner",
        "planning agent",
        "https://planner.internal/a2a",
        |out| {
            // No preferred_transport field => treat as rewritable.
            encode_proto_bytes(
                15,
                &encode_agent_interface("https://planner.internal/a2a", ""),
                out,
            );
            encode_proto_string(16, "0.3.0", out);
        },
    );
    let body = frame_grpc_message(&card);
    let mut response_headers =
        HashMap::from([("content-type".to_string(), "application/grpc".to_string())]);
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut response_headers, &body)
            .await,
        PluginResult::Continue
    ));
    let rewritten = plugin
        .transform_response_body_with_context(
            &mut ctx,
            &body,
            Some("application/grpc"),
            &response_headers,
        )
        .await
        .expect("empty preferred transport should rewrite");
    let message = &rewritten[5..];
    assert_eq!(
        proto_string_field(message, 3).as_deref(),
        Some("https://gateway.example.com/a2a")
    );
    let interfaces = proto_repeated_messages(message, 15);
    assert_eq!(
        proto_string_field(&interfaces[0], 1).as_deref(),
        Some("https://gateway.example.com/a2a")
    );
}

#[tokio::test]
async fn grpc_agent_card_rewrite_preserves_unknown_scalar_wire_types() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetExtendedAgentCard").await;
    let card = encode_minimal_agent_card(
        "planner",
        "planning agent",
        "https://planner.internal/a2a",
        |out| {
            encode_proto_string(14, "JSONRPC", out);
            encode_proto_string(16, "0.3.0", out);
            // Unknown fields across varint / 64-bit / 32-bit wires must round-trip.
            encode_proto_varint_field(50, 42, out);
            encode_proto_fixed64_field(51, 0x1122_3344_5566_7788, out);
            encode_proto_fixed32_field(52, 0xaabb_ccdd, out);
        },
    );
    let body = frame_grpc_message(&card);
    let mut response_headers =
        HashMap::from([("content-type".to_string(), "application/grpc".to_string())]);
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut response_headers, &body)
            .await,
        PluginResult::Continue
    ));
    let rewritten = plugin
        .transform_response_body_with_context(
            &mut ctx,
            &body,
            Some("application/grpc"),
            &response_headers,
        )
        .await
        .expect("scalar unknown fields must not block rewrite");
    let message = &rewritten[5..];
    assert_eq!(
        proto_string_field(message, 3).as_deref(),
        Some("https://gateway.example.com/a2a")
    );
    assert!(proto_has_field(message, 50));
    assert!(proto_has_field(message, 51));
    assert!(proto_has_field(message, 52));
}

#[tokio::test]
async fn grpc_agent_card_unlimited_response_ceiling_still_rewrites() {
    use ferrum_edge::_test_support::take_buffered_response_capacity_refusal_pending_for_test;

    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetExtendedAgentCard").await;
    // 0 means unlimited on the effective limit; the rewriter must fold via
    // retained_response_body_ceiling or BoundedResponseBodySink refuses writes.
    ctx.max_response_body_size_bytes = 0;
    let card = encode_a2a_03_agent_card(
        "planner",
        "planning agent",
        "https://planner.internal/a2a",
        "JSONRPC",
        &[("https://planner.internal/a2a", "JSONRPC")],
        "0.3.0",
        true,
    );
    let body = frame_grpc_message(&card);
    let mut response_headers =
        HashMap::from([("content-type".to_string(), "application/grpc".to_string())]);
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut response_headers, &body)
            .await,
        PluginResult::Continue
    ));
    let rewritten = plugin
        .transform_response_body_with_context(
            &mut ctx,
            &body,
            Some("application/grpc"),
            &response_headers,
        )
        .await
        .expect("unlimited effective limit must still permit Agent Card rewrite");
    assert_eq!(
        proto_string_field(&rewritten[5..], 3).as_deref(),
        Some("https://gateway.example.com/a2a")
    );
    assert!(
        !take_buffered_response_capacity_refusal_pending_for_test(&mut ctx),
        "successful unlimited-ceiling rewrite must not mark capacity refusal"
    );
}

#[tokio::test]
async fn grpc_agent_card_tight_response_ceiling_refuses_rewrite() {
    use ferrum_edge::_test_support::take_buffered_response_capacity_refusal_pending_for_test;

    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetExtendedAgentCard").await;
    let card = encode_a2a_03_agent_card(
        "planner",
        "planning agent",
        "https://planner.internal/a2a",
        "JSONRPC",
        &[("https://planner.internal/a2a", "JSONRPC")],
        "0.3.0",
        true,
    );
    let body = frame_grpc_message(&card);
    // Far below any rewritten frame size.
    ctx.max_response_body_size_bytes = 8;
    let mut response_headers =
        HashMap::from([("content-type".to_string(), "application/grpc".to_string())]);
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut response_headers, &body)
            .await,
        PluginResult::Continue
    ));
    assert!(
        plugin
            .transform_response_body_with_context(
                &mut ctx,
                &body,
                Some("application/grpc"),
                &response_headers,
            )
            .await
            .is_none(),
        "over-ceiling Agent Card rewrite must return None"
    );
    assert!(
        take_buffered_response_capacity_refusal_pending_for_test(&mut ctx),
        "over-ceiling rewrite must mark the pending capacity refusal"
    );
}

#[tokio::test]
async fn grpc_agent_card_transform_failure_rejects_on_final_body() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetExtendedAgentCard").await;
    let card = encode_a2a_03_agent_card(
        "planner",
        "planning agent",
        "https://planner.internal/a2a",
        "JSONRPC",
        &[("https://planner.internal/a2a", "JSONRPC")],
        "0.3.0",
        false,
    );
    let body = frame_grpc_message(&card);
    let mut response_headers =
        HashMap::from([("content-type".to_string(), "application/grpc".to_string())]);
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut response_headers, &body)
            .await,
        PluginResult::Continue
    ));
    // Staging validated an uncompressed card; transform later sees compression.
    response_headers.insert("grpc-encoding".to_string(), "gzip".to_string());
    assert!(
        plugin
            .transform_response_body_with_context(
                &mut ctx,
                &body,
                Some("application/grpc"),
                &response_headers,
            )
            .await
            .is_none()
    );
    assert_eq!(
        ctx.metadata.get("a2a.error").map(String::as_str),
        Some("agent_card_grpc_encoding_unsupported")
    );
    let final_result = plugin
        .on_final_response_body(&mut ctx, 200, &response_headers, &body)
        .await;
    assert_grpc_rewrite_reject(final_result, "agent_card_grpc_encoding_unsupported", None);
}

#[tokio::test]
async fn grpc_agent_card_truncated_fixed64_field_fails_closed() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetAgentCard").await;
    let mut message = encode_minimal_agent_card(
        "planner",
        "planning agent",
        "https://planner.internal/a2a",
        |_| {},
    );
    // 64-bit wire value truncated to 3 bytes.
    encode_proto_varint(u64::from(51u32) << 3 | 1, &mut message);
    message.extend_from_slice(&[1, 2, 3]);
    let body = frame_grpc_message(&message);
    let mut response_headers =
        HashMap::from([("content-type".to_string(), "application/grpc".to_string())]);
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, &body)
        .await;
    assert_grpc_rewrite_reject(
        result,
        "agent_card_protobuf_shape_unrecognized",
        ctx.metadata.get("a2a.error").map(String::as_str),
    );
}

#[tokio::test]
async fn grpc_agent_card_truncated_fixed32_field_fails_closed() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetAgentCard").await;
    let mut message = encode_minimal_agent_card(
        "planner",
        "planning agent",
        "https://planner.internal/a2a",
        |_| {},
    );
    encode_proto_varint(u64::from(52u32) << 3 | 5, &mut message);
    message.extend_from_slice(&[1, 2]); // need 4
    let body = frame_grpc_message(&message);
    let mut response_headers =
        HashMap::from([("content-type".to_string(), "application/grpc".to_string())]);
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, &body)
        .await;
    assert_grpc_rewrite_reject(
        result,
        "agent_card_protobuf_shape_unrecognized",
        ctx.metadata.get("a2a.error").map(String::as_str),
    );
}

#[tokio::test]
async fn grpc_agent_card_varint_overflow_fails_closed() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetAgentCard").await;
    // Ten continuation bytes overflow the varint decoder.
    let message = vec![0xff; 10];
    let body = frame_grpc_message(&message);
    let mut response_headers =
        HashMap::from([("content-type".to_string(), "application/grpc".to_string())]);
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, &body)
        .await;
    assert_grpc_rewrite_reject(
        result,
        "agent_card_protobuf_shape_unrecognized",
        ctx.metadata.get("a2a.error").map(String::as_str),
    );
}

#[tokio::test]
async fn grpc_agent_card_truncated_varint_fails_closed() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetAgentCard").await;
    // Continuation bit set with no following byte.
    let message = vec![0x80];
    let body = frame_grpc_message(&message);
    let mut response_headers =
        HashMap::from([("content-type".to_string(), "application/grpc".to_string())]);
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, &body)
        .await;
    assert_grpc_rewrite_reject(
        result,
        "agent_card_protobuf_shape_unrecognized",
        ctx.metadata.get("a2a.error").map(String::as_str),
    );
}

#[tokio::test]
async fn grpc_agent_card_identity_grpc_encoding_is_accepted() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetExtendedAgentCard").await;
    let card = encode_a2a_03_agent_card(
        "planner",
        "planning agent",
        "https://planner.internal/a2a",
        "JSONRPC",
        &[],
        "0.3.0",
        false,
    );
    let body = frame_grpc_message(&card);
    let mut response_headers = HashMap::from([
        ("content-type".to_string(), "application/grpc".to_string()),
        ("grpc-encoding".to_string(), "identity".to_string()),
    ]);
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut response_headers, &body)
            .await,
        PluginResult::Continue
    ));
    let rewritten = plugin
        .transform_response_body_with_context(
            &mut ctx,
            &body,
            Some("application/grpc"),
            &response_headers,
        )
        .await
        .expect("identity grpc-encoding must still rewrite");
    assert_eq!(
        proto_string_field(&rewritten[5..], 3).as_deref(),
        Some("https://gateway.example.com/a2a")
    );
}

#[tokio::test]
async fn grpc_agent_card_transform_sees_late_shape_and_version_failures() {
    let plugin = plugin(json!({
        "discovery": {
            "public_base_url": "https://gateway.example.com"
        }
    }));
    let mut ctx = detect_grpc_agent_card(&plugin, "GetExtendedAgentCard").await;
    let valid = encode_a2a_03_agent_card(
        "planner",
        "planning agent",
        "https://planner.internal/a2a",
        "JSONRPC",
        &[],
        "0.3.0",
        false,
    );
    let valid_body = frame_grpc_message(&valid);
    let mut response_headers =
        HashMap::from([("content-type".to_string(), "application/grpc".to_string())]);
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut response_headers, &valid_body)
            .await,
        PluginResult::Continue
    ));

    let mut unrecognized = Vec::new();
    encode_proto_string(99, "not-a-card", &mut unrecognized);
    assert!(
        plugin
            .transform_response_body_with_context(
                &mut ctx,
                &frame_grpc_message(&unrecognized),
                Some("application/grpc"),
                &response_headers,
            )
            .await
            .is_none()
    );
    assert_eq!(
        ctx.metadata.get("a2a.error").map(String::as_str),
        Some("agent_card_protobuf_shape_unrecognized")
    );
    // Clear the pending transform diagnostic so the version case is isolated.
    let _ = plugin
        .on_final_response_body(&mut ctx, 200, &response_headers, &valid_body)
        .await;

    let unsupported = encode_a2a_03_agent_card(
        "planner",
        "planning agent",
        "https://planner.internal/a2a",
        "JSONRPC",
        &[],
        "1.0.0",
        false,
    );
    assert!(
        plugin
            .transform_response_body_with_context(
                &mut ctx,
                &frame_grpc_message(&unsupported),
                Some("application/grpc"),
                &response_headers,
            )
            .await
            .is_none()
    );
    assert_eq!(
        ctx.metadata.get("a2a.error").map(String::as_str),
        Some("unsupported_agent_card_protobuf_version")
    );
    let final_result = plugin
        .on_final_response_body(&mut ctx, 200, &response_headers, &valid_body)
        .await;
    assert_grpc_rewrite_reject(
        final_result,
        "unsupported_agent_card_protobuf_version",
        None,
    );
}

#[tokio::test]
async fn grpc_web_content_type_is_not_detected_as_native_grpc() {
    let plugin = plugin(json!({}));
    let (mut ctx, mut headers) = grpc_ctx("SendMessage", "application/grpc-web+proto");

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(!ctx.metadata.contains_key("a2a.enabled"));
}

#[tokio::test]
async fn grpc_policy_deny_returns_reject_for_proxy_normalization() {
    let plugin = plugin(json!({
        "policy": {
            "methods": {
                "message/send": {"action": "deny"}
            }
        }
    }));
    let (mut ctx, mut headers) = grpc_ctx("SendMessage", "application/grpc");

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        PluginResult::Reject {
            status_code: 403,
            ..
        }
    ));
}

#[tokio::test]
async fn task_id_metadata_uses_known_a2a_locations_only() {
    let plugin = plugin(json!({}));
    let (mut ctx, mut headers) = jsonrpc_ctx(json!({
        "jsonrpc": "2.0",
        "id": "req-4",
        "method": "message/send",
        "params": {
            "message": {
                "parts": [
                    {"id": "part-id", "name": "part-name"}
                ]
            }
        }
    }));

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(!ctx.metadata.contains_key("a2a.task_id"));

    let mut response_headers =
        HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    let body = json!({
        "jsonrpc": "2.0",
        "id": "req-4",
        "result": [
            {"id": "task-from-list"}
        ]
    })
    .to_string();
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, body.as_bytes())
        .await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(!ctx.metadata.contains_key("a2a.task_id"));
}

#[tokio::test]
async fn task_id_metadata_uses_nested_message_task_id() {
    let plugin = plugin(json!({}));
    let (mut ctx, mut headers) = jsonrpc_ctx(json!({
        "jsonrpc": "2.0",
        "id": "req-nested-task",
        "method": "message/send",
        "params": {
            "message": {
                "taskId": "task-1",
                "parts": [
                    {"id": "part-id"}
                ]
            }
        }
    }));

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata.get("a2a.task_id").map(String::as_str),
        Some("task-1")
    );
}

#[tokio::test]
async fn response_metadata_normalizes_task_state() {
    let plugin = plugin(json!({}));
    let (mut ctx, mut headers) = jsonrpc_ctx(json!({
        "jsonrpc": "2.0",
        "id": "req-5",
        "method": "tasks/get",
        "params": {"id": "task-1"}
    }));
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));

    let mut response_headers =
        HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    let body = json!({
        "jsonrpc": "2.0",
        "id": "req-5",
        "result": {
            "id": "task-1",
            "status": {
                "state": "TASK_STATE_CANCELLED"
            }
        }
    })
    .to_string();
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, body.as_bytes())
        .await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata.get("a2a.task_state").map(String::as_str),
        Some("canceled")
    );
}

#[tokio::test]
async fn streaming_jsonrpc_does_not_force_response_buffering() {
    let plugin = plugin(json!({}));
    let (mut ctx, mut headers) = jsonrpc_ctx(json!({
        "jsonrpc": "2.0",
        "id": "req-3",
        "method": "message/stream"
    }));

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(!plugin.should_buffer_response_body(&ctx));
    assert!(!plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("text/event-stream"),
        200,
        &headers
    ));
}

#[tokio::test]
async fn retry_marked_sse_response_is_released_while_json_stays_buffered() {
    let plugin = plugin(json!({}));
    let (mut ctx, mut headers) = jsonrpc_ctx(json!({
        "jsonrpc": "2.0",
        "id": "req-retry",
        "method": "message/send",
        "params": {}
    }));

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));

    // Classified non-streaming: the pre-flight decision buffers, and the
    // plugin must advertise the retry release so retry-enabled dispatch
    // keeps a header-first transport instead of committing to collection.
    assert!(plugin.should_buffer_response_body(&ctx));
    assert!(plugin.may_release_response_body_under_retries(&ctx));

    // Backend unexpectedly answers with SSE: released under retries, exactly
    // matching the non-retry content-type escape hatch.
    let sse_headers = HashMap::from([(
        "content-type".to_string(),
        "text/event-stream; charset=utf-8".to_string(),
    )]);
    assert!(plugin.should_release_response_body_under_retries(&ctx, 200, &sse_headers));
    assert!(!plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("text/event-stream; charset=utf-8"),
        200,
        &sse_headers,
    ));

    // JSON responses stay buffered on both paths so metadata extraction,
    // agent-card rewriting, and retry replay keep working.
    let json_headers =
        HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    assert!(!plugin.should_release_response_body_under_retries(&ctx, 200, &json_headers));
    assert!(plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("application/json"),
        200,
        &json_headers,
    ));

    // Non-JSON, non-SSE responses also stay buffered under retries: the
    // non-retry path buffers them for `a2a.response_body_size` and payload
    // metadata, and the retry release must never be broader than that.
    let text_headers = HashMap::from([("content-type".to_string(), "text/plain".to_string())]);
    assert!(!plugin.should_release_response_body_under_retries(&ctx, 200, &text_headers));
    assert!(!plugin.should_release_response_body_under_retries(&ctx, 200, &HashMap::new()));
}

#[tokio::test]
async fn retry_release_is_not_advertised_without_an_active_buffering_decision() {
    let plugin = plugin(json!({}));
    let sse_headers =
        HashMap::from([("content-type".to_string(), "text/event-stream".to_string())]);

    // Streaming-classified request: the plugin is not an active buffering
    // plugin, so it must not advertise the retry release either.
    let (mut ctx, mut headers) = jsonrpc_ctx(json!({
        "jsonrpc": "2.0",
        "id": "req-stream",
        "method": "message/stream"
    }));
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(!plugin.should_buffer_response_body(&ctx));
    assert!(!plugin.may_release_response_body_under_retries(&ctx));
    assert!(!plugin.should_release_response_body_under_retries(&ctx, 200, &sse_headers));

    // Undetected request: same.
    let undetected_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/unrelated".to_string(),
    );
    assert!(!plugin.may_release_response_body_under_retries(&undetected_ctx));
    assert!(!plugin.should_release_response_body_under_retries(&undetected_ctx, 200, &sse_headers));

    // Native gRPC A2A request: capture is HTTP-only, so no retry release.
    let (mut grpc_ctx, mut grpc_headers) = grpc_ctx("SendMessage", "application/grpc");
    let result = plugin.before_proxy(&mut grpc_ctx, &mut grpc_headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(!plugin.should_buffer_response_body(&grpc_ctx));
    assert!(!plugin.may_release_response_body_under_retries(&grpc_ctx));
}

#[tokio::test]
async fn streaming_jsonrpc_inspector_extracts_multichunk_sse_terminal_metadata() {
    let plugin = plugin(json!({}));
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::clone(&plugin)];
    let (mut ctx, mut headers) = jsonrpc_ctx(json!({
        "jsonrpc": "2.0",
        "id": "req-stream",
        "method": "message/stream"
    }));
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(plugin.requires_response_stream_hooks());
    assert!(plugin.forces_reqwest_dispatch(&ctx));

    let mut inspector = create_response_stream_inspector(
        &plugins,
        &mut ctx,
        200,
        Some("text/event-stream; charset=utf-8"),
    )
    .expect("detected 2xx A2A SSE response should attach an inspector");
    let chunks: &[&[u8]] = &[
        b"data: {\"jsonrpc\":\"2.0\",\"result\":{\"taskId\":\"task-9\",\"contextId\":\"ctx-4\",\"status\":{\"state\":\"working\"}}}\n\nda",
        b"ta: {\"jsonrpc\":\"2.0\",\"result\":{\"taskId\":\"task-9\",\"contextId\":\"ctx-4\",\"status\":{\"state\":\"TASK_STATE_",
        b"COMPLETED\"},\"final\":true}}\r",
        b"\n\r\n",
    ];
    for chunk in chunks {
        let action = inspector.on_chunk(chunk).await;
        let ResponseStreamAction::Forward(forwarded) = action else {
            panic!("observe-only A2A inspector must never terminate a stream");
        };
        assert_eq!(forwarded.as_ref(), *chunk);
    }
    let end = inspector.on_end().await;
    assert!(matches!(end, ResponseStreamAction::Forward(ref bytes) if bytes.is_empty()));
    plugin
        .on_response_stream_terminated(&mut ctx, 200, &BodyOutcome::success(0))
        .await;

    assert_eq!(
        ctx.metadata.get("a2a.stream_events").map(String::as_str),
        Some("2")
    );
    assert_eq!(
        ctx.metadata.get("a2a.task_id").map(String::as_str),
        Some("task-9")
    );
    assert_eq!(
        ctx.metadata.get("a2a.context_id").map(String::as_str),
        Some("ctx-4")
    );
    assert_eq!(
        ctx.metadata.get("a2a.task_state").map(String::as_str),
        Some("completed")
    );

    let extras = vec![
        "a2a.task_id".to_string(),
        "a2a.context_id".to_string(),
        "a2a.task_state".to_string(),
    ];
    for key in ["a2a.task_id", "a2a.context_id", "a2a.task_state"] {
        assert!(
            is_sensitive_metadata_key_with_extras(key, &extras),
            "central metadata serialization must redact {key}"
        );
    }
}

#[tokio::test]
async fn streaming_jsonrpc_termination_before_inspector_end_does_not_emit_metadata() {
    let plugin = plugin(json!({}));
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::clone(&plugin)];
    let (mut ctx, mut headers) = jsonrpc_ctx(json!({
        "jsonrpc": "2.0",
        "id": "req-stream",
        "method": "message/stream"
    }));
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));

    let mut inspector =
        create_response_stream_inspector(&plugins, &mut ctx, 200, Some("text/event-stream"))
            .expect("detected 2xx A2A SSE response should attach an inspector");
    let chunk = b"data: {\"result\":{\"taskId\":\"task-9\"}}\n\n";
    assert!(matches!(
        inspector.on_chunk(chunk).await,
        ResponseStreamAction::Forward(_)
    ));

    plugin
        .on_response_stream_terminated(&mut ctx, 200, &BodyOutcome::client_disconnect(0))
        .await;
    assert!(!ctx.metadata.contains_key("a2a.stream_events"));
    assert!(!ctx.metadata.contains_key("a2a.task_id"));

    let end = inspector.on_end().await;
    assert!(matches!(end, ResponseStreamAction::Forward(ref bytes) if bytes.is_empty()));
}

#[tokio::test]
async fn streaming_jsonrpc_observation_omits_absent_optional_metadata() {
    let plugin = plugin(json!({}));
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::clone(&plugin)];
    let (mut ctx, mut headers) = jsonrpc_ctx(json!({
        "jsonrpc": "2.0",
        "id": "req-stream",
        "method": "message/stream"
    }));
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));

    let mut inspector =
        create_response_stream_inspector(&plugins, &mut ctx, 200, Some("text/event-stream"))
            .expect("detected 2xx A2A SSE response should attach an inspector");
    let chunk = b"data: {\"jsonrpc\":\"2.0\",\"result\":{}}\n\n";
    assert!(matches!(
        inspector.on_chunk(chunk).await,
        ResponseStreamAction::Forward(_)
    ));
    let end = inspector.on_end().await;
    assert!(matches!(end, ResponseStreamAction::Forward(ref bytes) if bytes.is_empty()));

    plugin
        .on_response_stream_terminated(&mut ctx, 200, &BodyOutcome::success(chunk.len() as u64))
        .await;
    assert_eq!(
        ctx.metadata.get("a2a.stream_events").map(String::as_str),
        Some("1")
    );
    for key in ["a2a.task_id", "a2a.context_id", "a2a.task_state"] {
        assert!(!ctx.metadata.contains_key(key));
    }
}

#[tokio::test]
async fn streaming_termination_is_a_noop_when_metadata_is_disabled() {
    let plugin = plugin(json!({
        "observability": {"emit_metadata": false}
    }));
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/a2a".to_string(),
    );

    plugin
        .on_response_stream_terminated(&mut ctx, 200, &BodyOutcome::success(0))
        .await;
    assert!(ctx.metadata.is_empty());
}

#[tokio::test]
async fn streaming_jsonrpc_inspector_forwards_incomplete_event_without_holding() {
    let plugin = plugin(json!({}));
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::clone(&plugin)];
    let (mut ctx, mut headers) = jsonrpc_ctx(json!({
        "jsonrpc": "2.0",
        "id": "req-stream",
        "method": "message/stream"
    }));
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));

    let mut inspector =
        create_response_stream_inspector(&plugins, &mut ctx, 206, Some("TEXT/EVENT-STREAM"))
            .expect("detected 2xx A2A SSE response should attach an inspector");
    let partial = b"data: {\"result\":{\"status\":{\"state\":\"work";
    let action = inspector.on_chunk(partial).await;
    let ResponseStreamAction::Forward(forwarded) = action else {
        panic!("observe-only A2A inspector must never terminate a stream");
    };
    assert_eq!(forwarded.as_ref(), partial);
    let end = inspector.on_end().await;
    assert!(matches!(end, ResponseStreamAction::Forward(ref bytes) if bytes.is_empty()));

    assert!(
        plugin
            .response_stream_inspector(&ctx, 500, Some("text/event-stream"))
            .is_none()
    );
    assert!(
        plugin
            .response_stream_inspector(&ctx, 200, Some("application/json"))
            .is_none()
    );
}

#[test]
fn invalid_grpc_service_is_rejected() {
    let result = create_plugin(
        "a2a_gateway",
        &json!({
            "endpoint": {
                "grpc_services": ["not valid"]
            }
        }),
    );
    let err = match result {
        Ok(_) => panic!("invalid service should reject config"),
        Err(err) => err,
    };
    assert!(err.contains("endpoint.grpc_services"));
}

#[test]
fn invalid_a2a_gateway_configs_are_rejected() {
    let cases = [
        (
            json!({"mode": "active_gateway"}),
            "mode",
            "non-transparent mode should reject",
        ),
        (
            json!({"endpoint": {"path": "a2a"}}),
            "endpoint.path",
            "endpoint path must be absolute",
        ),
        (
            json!({"endpoint": {"protocol_versions": []}}),
            "endpoint.protocol_versions",
            "protocol versions cannot be empty",
        ),
        (
            json!({"endpoint": {"grpc_services": ["lf.a2a.v1.A2AService", "lf.a2a.v1.A2AService"]}}),
            "duplicate endpoint.grpc_services",
            "duplicate gRPC services should reject",
        ),
        (
            json!({"detection": {"bindings": []}}),
            "detection.bindings",
            "bindings cannot be empty",
        ),
        (
            json!({"detection": {"version_header": "not a header"}}),
            "detection.version_header",
            "version header must be a valid header name",
        ),
        (
            json!({"discovery": {"public_base_url": "ftp://agents.example.com"}}),
            "discovery.public_base_url scheme",
            "public base scheme must be HTTP-family",
        ),
        (
            json!({"discovery": {"public_base_url": "https://agents.example.com?a=b"}}),
            "discovery.public_base_url must not contain query",
            "public base cannot carry query",
        ),
        (
            json!({"discovery": {"public_base_url": "https://user:pass@agents.example.com"}}),
            "discovery.public_base_url must not contain credentials",
            "public base cannot carry credentials",
        ),
        (
            json!({"observability": {"max_payload_size": 0}}),
            "observability.max_payload_size",
            "payload size must be positive",
        ),
    ];

    for (config, expected, label) in cases {
        let result = create_plugin("a2a_gateway", &config);
        let err = match result {
            Ok(_) => panic!("{label}"),
            Err(err) => err,
        };
        assert!(
            err.contains(expected),
            "{label}: expected {expected:?} in {err:?}"
        );
    }
}
