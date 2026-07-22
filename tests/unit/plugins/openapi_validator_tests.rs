use ferrum_edge::plugins::{
    HTTP_ONLY_PROTOCOLS, Plugin, PluginResult, RequestContext, openapi_validator::OpenapiValidator,
    priority,
};
use flate2::{Compression, write::GzEncoder};
use serde_json::json;
use std::collections::HashMap;
use std::io::Write as _;

use super::plugin_utils::{assert_continue, assert_reject};

fn gzip_bytes(body: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(body).unwrap();
    encoder.finish().unwrap()
}

fn brotli_bytes(body: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::new();
    let mut input = body;
    brotli::BrotliCompress(
        &mut input,
        &mut encoded,
        &brotli::enc::BrotliEncoderParams::default(),
    )
    .unwrap();
    encoded
}

fn encoding_headers(encoding: &str) -> HashMap<String, String> {
    let mut headers = json_headers();
    headers.insert("content-encoding".to_string(), encoding.to_string());
    headers
}

fn request_error(ctx: &RequestContext) -> Option<&str> {
    ctx.metadata
        .get("openapi_validator.request_error")
        .map(String::as_str)
}

fn response_error(ctx: &RequestContext) -> Option<&str> {
    ctx.metadata
        .get("openapi_validator.response_error")
        .map(String::as_str)
}

fn validator_config(mode: &str) -> serde_json::Value {
    json!({
        "enforcement_mode": mode,
        "schema_draft": "draft7",
        "operations": [{
            "method": "POST",
            "path_template": "/items",
            "path_regex": "^/items$",
            "request_required": true,
            "request_body": {
                "content": {
                    "application/json": {
                        "type": "object",
                        "required": ["name"],
                        "properties": {
                            "name": {"type": "string"}
                        }
                    }
                }
            },
            "responses": {
                "200": {
                    "application/json": {
                        "type": "object",
                        "required": ["ok"],
                        "properties": {"ok": {"type": "boolean"}}
                    }
                },
                "default": {
                    "application/json": {
                        "type": "object",
                        "required": ["error"],
                        "properties": {"error": {"type": "string"}}
                    }
                }
            }
        }]
    })
}

fn json_headers() -> HashMap<String, String> {
    HashMap::from([("content-type".to_string(), "application/json".to_string())])
}

fn content_type_headers(content_type: &str) -> HashMap<String, String> {
    HashMap::from([("content-type".to_string(), content_type.to_string())])
}

fn post_ctx(path: &str) -> RequestContext {
    let mut ctx = RequestContext::new("127.0.0.1".into(), "POST".into(), path.into());
    ctx.headers = json_headers();
    ctx
}

#[test]
fn metadata_and_protocol_scope() {
    let plugin = OpenapiValidator::new(&validator_config("block")).unwrap();
    assert_eq!(plugin.name(), "openapi_validator");
    assert_eq!(plugin.priority(), priority::OPENAPI_VALIDATOR);
    assert_eq!(plugin.supported_protocols(), HTTP_ONLY_PROTOCOLS);
    assert!(plugin.requires_request_body_buffering());
    assert!(plugin.requires_response_body_buffering());
    assert!(plugin.needs_final_request_body_context());
}

#[test]
fn invalid_configs_are_rejected() {
    for config in [
        json!("bad"),
        json!({}),
        json!({"operations": []}),
        json!({"enforcement_mode": "monitor", "operations": []}),
        json!({"operations": [{"method": "GET", "path_template": "/x", "path_regex": "["}]}),
        json!({
            "operations": [{
                "method": "POST",
                "path_template": "/x",
                "path_regex": "^/x$",
                "request_body_required": "true"
            }]
        }),
        json!({
            "operations": [{
                "method": "POST",
                "path_template": "/x",
                "path_regex": "^/x$",
                "request_body": {"content": {"application/json": {"type": "not-a-type"}}}
            }]
        }),
    ] {
        assert!(
            OpenapiValidator::new(&config).is_err(),
            "config should fail: {config:?}"
        );
    }
}

#[tokio::test]
async fn disabled_mode_skips_matching_and_buffering() {
    let plugin = OpenapiValidator::new(&validator_config("disabled")).unwrap();
    let mut ctx = post_ctx("/missing");
    let mut headers = json_headers();

    assert!(!plugin.requires_request_body_buffering());
    assert!(!plugin.requires_response_body_buffering());
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(
        ctx.metadata
            .get("openapi_validator.mode")
            .map(String::as_str),
        Some("disabled")
    );
}

#[tokio::test]
async fn request_validation_blocks_or_logs_by_mode() {
    let plugin = OpenapiValidator::new(&validator_config("block")).unwrap();
    let mut ctx = post_ctx("/items");
    assert!(plugin.should_buffer_request_body(&ctx));
    assert_reject(
        plugin
            .on_final_request_body_with_context(&mut ctx, &json_headers(), br#"{"id":1}"#)
            .await,
        Some(400),
    );
    assert_eq!(
        ctx.metadata
            .get("openapi_validator.action")
            .map(String::as_str),
        Some("rejected_request")
    );

    let plugin = OpenapiValidator::new(&validator_config("log_only")).unwrap();
    let mut ctx = post_ctx("/items");
    assert_continue(
        plugin
            .on_final_request_body_with_context(&mut ctx, &json_headers(), br#"{"id":1}"#)
            .await,
    );
    assert_eq!(
        ctx.metadata
            .get("openapi_validator.action")
            .map(String::as_str),
        Some("logged_request_mismatch")
    );
}

#[tokio::test]
async fn delete_request_with_schema_buffers_and_validates_body() {
    let plugin = OpenapiValidator::new(&json!({
        "enforcement_mode": "block",
        "operations": [{
            "method": "DELETE",
            "path_template": "/items",
            "path_regex": "^/items$",
            "request_required": true,
            "request_body": {
                "content": {
                    "application/json": {
                        "type": "object",
                        "required": ["id"],
                        "properties": {
                            "id": {"type": "string"}
                        }
                    }
                }
            }
        }]
    }))
    .unwrap();
    let mut ctx = RequestContext::new("127.0.0.1".into(), "DELETE".into(), "/items".into());
    ctx.headers = json_headers();
    assert!(plugin.should_buffer_request_body(&ctx));
    assert_reject(
        plugin
            .on_final_request_body_with_context(&mut ctx, &json_headers(), br#"{}"#)
            .await,
        Some(400),
    );
}

#[tokio::test]
async fn valid_request_and_gzip_body_continue() {
    let plugin = OpenapiValidator::new(&validator_config("block")).unwrap();
    let mut ctx = post_ctx("/items");
    let headers = encoding_headers("gzip");
    let body = gzip_bytes(br#"{"name":"book"}"#);

    assert_continue(
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, &body)
            .await,
    );
}

#[tokio::test]
async fn unknown_operation_is_rejected_before_proxy() {
    let plugin = OpenapiValidator::new(&validator_config("block")).unwrap();
    let mut ctx = post_ctx("/missing");
    let mut headers = json_headers();

    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
    assert_eq!(
        ctx.metadata
            .get("openapi_validator.request_error")
            .map(String::as_str),
        Some("No OpenAPI operation matched POST /missing")
    );
}

#[tokio::test]
async fn literal_path_beats_parameter_path() {
    let plugin = OpenapiValidator::new(&json!({
        "operations": [
            {"method": "GET", "path_template": "/users/{id}", "path_regex": "^/users/[^/]+$"},
            {"method": "GET", "path_template": "/users/me", "path_regex": "^/users/me$"}
        ]
    }))
    .unwrap();
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/users/me".into());
    let mut headers = HashMap::new();

    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(
        ctx.metadata
            .get("openapi_validator.matched_operation")
            .map(String::as_str),
        Some("GET /users/me")
    );
    assert!(
        !ctx.metadata.keys().any(|key| key
            .starts_with("openapi_validator.matched_operation_method.")
            || key.starts_with("openapi_validator.matched_operation_index.")),
        "internal operation cache keys must not be exposed in metadata: {:?}",
        ctx.metadata
    );
}

#[tokio::test]
async fn bypass_header_skips_buffering_and_validation() {
    let config = json!({
        "schema_draft": "draft7",
        "bypass": {"header_present": {"x-bypass-validator": null}},
        "operations": [{
            "method": "POST",
            "path_template": "/items",
            "path_regex": "^/items$",
            "request_body": {"content": {"application/json": {"type": "object"}}}
        }]
    });
    let plugin = OpenapiValidator::new(&config).unwrap();
    let mut ctx = post_ctx("/items");
    ctx.headers
        .insert("x-bypass-validator".to_string(), "1".to_string());
    let mut headers = ctx.headers.clone();

    assert!(!plugin.should_buffer_request_body(&ctx));
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(
        ctx.metadata
            .get("openapi_validator.skip_reason")
            .map(String::as_str),
        Some("bypass_header")
    );
    assert!(
        !ctx.metadata
            .keys()
            .any(|key| key.starts_with("openapi_validator.skip_reason.")),
        "internal skip cache keys must not be exposed in metadata: {:?}",
        ctx.metadata
    );
}

#[tokio::test]
async fn bypass_header_uses_before_proxy_headers_when_ctx_headers_are_moved() {
    let config = json!({
        "schema_draft": "draft7",
        "bypass": {"header_present": {"x-bypass-validator": null}},
        "operations": [{
            "method": "POST",
            "path_template": "/items",
            "path_regex": "^/items$",
            "request_body": {"content": {"application/json": {"type": "object"}}},
            "responses": {"200": {"application/json": {"type": "object"}}}
        }]
    });
    let plugin = OpenapiValidator::new(&config).unwrap();
    let mut ctx = post_ctx("/missing");
    ctx.headers
        .insert("x-bypass-validator".to_string(), "1".to_string());
    let mut headers = std::mem::take(&mut ctx.headers);

    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(
        ctx.metadata
            .get("openapi_validator.skip_reason")
            .map(String::as_str),
        Some("bypass_header")
    );
    assert!(!plugin.should_buffer_response_body(&ctx));
}

#[tokio::test]
async fn response_validation_uses_default_and_strict_missing_schema() {
    let plugin = OpenapiValidator::new(&validator_config("block")).unwrap();
    let mut ctx = post_ctx("/items");
    assert!(plugin.should_buffer_response_body(&ctx));

    assert_reject(
        plugin
            .on_final_response_body(&mut ctx, 200, &json_headers(), br#"{"ok":"yes"}"#)
            .await,
        Some(502),
    );

    let mut ctx = post_ctx("/items");
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 404, &json_headers(), br#"{"error":"missing"}"#)
            .await,
    );

    let strict = OpenapiValidator::new(&json!({
        "fail_on_missing_response_schema": true,
        "operations": [{
            "method": "POST",
            "path_template": "/items",
            "path_regex": "^/items$",
            "responses": {"200": {"application/json": {"type": "object"}}}
        }]
    }))
    .unwrap();
    let mut ctx = post_ctx("/items");
    let result = strict
        .on_final_response_body(&mut ctx, 201, &json_headers(), br#"{}"#)
        .await;
    assert!(matches!(
        result,
        PluginResult::Reject {
            status_code: 502,
            ..
        }
    ));
}

#[tokio::test]
async fn response_sse_intent_is_conservative_and_genuine_stream_fails_closed() {
    let plugin = OpenapiValidator::new(&validator_config("block")).unwrap();
    let mut ctx = post_ctx("/items");
    ctx.headers
        .insert("accept".to_string(), "text/event-stream".to_string());
    assert!(plugin.should_buffer_response_body(&ctx));

    let mut response_headers = content_type_headers("text/event-stream");
    assert!(plugin.may_release_response_body_under_retries(&ctx));
    assert!(plugin.should_release_response_body_under_retries(&ctx, 200, &response_headers));
    assert!(
        plugin.should_release_response_body_before_content_type_rewrite(
            &ctx,
            200,
            &response_headers,
        )
    );
    let json_profile_headers = content_type_headers("application/json; profile=event-stream");
    assert!(!plugin.should_release_response_body_under_retries(&ctx, 200, &json_profile_headers,));
    assert!(
        !plugin.should_release_response_body_before_content_type_rewrite(
            &ctx,
            200,
            &json_profile_headers,
        )
    );
    assert!(!plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("text/event-stream"),
        200,
        &response_headers,
    ));
    assert!(plugin.should_buffer_response_body_for_content_type(&ctx, None, 200, &HashMap::new(),));
    assert!(plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("application/json; profile=event-stream"),
        200,
        &HashMap::new(),
    ));
    assert_reject(
        plugin
            .after_proxy(&mut ctx, 200, &mut response_headers)
            .await,
        Some(502),
    );
    assert_eq!(
        ctx.metadata
            .get("openapi_validator.action")
            .map(String::as_str),
        Some("rejected_response")
    );

    let log_only = OpenapiValidator::new(&validator_config("log_only")).unwrap();
    let mut log_ctx = post_ctx("/items");
    let mut log_headers = content_type_headers("text/event-stream");
    assert_continue(
        log_only
            .after_proxy(&mut log_ctx, 200, &mut log_headers)
            .await,
    );
    assert_eq!(
        log_ctx
            .metadata
            .get("openapi_validator.action")
            .map(String::as_str),
        Some("logged_response_mismatch")
    );
}

#[tokio::test]
async fn xml_request_validation_honors_xml_metadata() {
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/orders",
            "path_regex": "^/orders$",
            "request_body": {
                "content": {
                    "application/xml": {
                        "type": "object",
                        "xml": {"name": "order"},
                        "required": ["id", "quantity"],
                        "additionalProperties": false,
                        "properties": {
                            "id": {"type": "string", "xml": {"attribute": true}},
                            "quantity": {"type": "integer", "xml": {"name": "qty"}}
                        }
                    }
                }
            }
        }]
    }))
    .unwrap();
    let mut ctx = post_ctx("/orders");
    ctx.headers = content_type_headers("application/xml");
    let headers = ctx.headers.clone();

    assert!(plugin.should_buffer_request_body(&ctx));
    assert_continue(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &headers,
                br#"<order id="A-1"><qty>3</qty></order>"#,
            )
            .await,
    );

    let mut ctx = post_ctx("/orders");
    ctx.headers = content_type_headers("application/xml");
    assert_reject(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &content_type_headers("application/xml"),
                br#"<order><qty>bad</qty></order>"#,
            )
            .await,
        Some(400),
    );
    let mut ctx = post_ctx("/orders");
    ctx.headers = content_type_headers("application/xml");
    assert_reject(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &content_type_headers("application/xml"),
                br#"<order id="A-1" extra="nope"><qty>3</qty></order>"#,
            )
            .await,
        Some(400),
    );

    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/docs",
            "path_regex": "^/docs$",
            "request_body": {
                "content": {
                    "application/xml": {
                        "type": "object",
                        "xml": {"name": "doc"},
                        "properties": {
                            "body": {"type": "string"}
                        }
                    }
                }
            }
        }]
    }))
    .unwrap();
    let mut ctx = post_ctx("/docs");
    ctx.headers = content_type_headers("application/xml");
    assert_continue(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &content_type_headers("application/xml"),
                br#"<doc><body><![CDATA[<!doctype html>]]></body></doc>"#,
            )
            .await,
    );
}

#[tokio::test]
async fn urlencoded_request_validation_converts_fields_to_schema_types() {
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/login",
            "path_regex": "^/login$",
            "request_body": {
                "content": {
                    "application/x-www-form-urlencoded": {
                        "type": "object",
                        "required": ["username", "remember"],
                        "properties": {
                            "username": {"type": "string", "minLength": 3},
                            "remember": {"type": "boolean"}
                        }
                    }
                }
            }
        }]
    }))
    .unwrap();
    let mut ctx = post_ctx("/login");
    ctx.headers = content_type_headers("application/x-www-form-urlencoded");

    assert!(plugin.should_buffer_request_body(&ctx));
    assert_continue(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &content_type_headers("application/x-www-form-urlencoded"),
                b"username=alice&remember=on",
            )
            .await,
    );

    let mut ctx = post_ctx("/login");
    ctx.headers = content_type_headers("application/x-www-form-urlencoded");
    assert_reject(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &content_type_headers("application/x-www-form-urlencoded"),
                b"username=al&remember=maybe",
            )
            .await,
        Some(400),
    );
}

#[tokio::test]
async fn multipart_request_validation_checks_fields_and_file_metadata() {
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/upload",
            "path_regex": "^/upload$",
            "request_body": {
                "content": {
                    "multipart/form-data": {
                        "type": "object",
                        "required": ["title", "file"],
                        "properties": {
                            "title": {"type": "string"},
                            "file": {
                                "type": "object",
                                "required": ["filename", "content_type", "size"],
                                "properties": {
                                    "filename": {"type": "string", "const": "a.txt"},
                                    "content_type": {"type": "string", "const": "text/plain"},
                                    "size": {"type": "integer", "minimum": 5}
                                }
                            }
                        }
                    }
                }
            }
        }]
    }))
    .unwrap();
    let body = concat!(
        "--abc\r\n",
        "Content-Disposition: form-data; name=\"title\"\r\n\r\n",
        "Upload\r\n",
        "--abc\r\n",
        "Content-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\n",
        "Content-Type: text/plain\r\n\r\n",
        "hello\r\n",
        "--abc--\r\n"
    );
    let mut ctx = post_ctx("/upload");
    ctx.headers = content_type_headers("multipart/form-data; boundary=abc");

    assert!(plugin.should_buffer_request_body(&ctx));
    assert_continue(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &content_type_headers("multipart/form-data; boundary=abc"),
                body.as_bytes(),
            )
            .await,
    );

    let bad_body = body.replace("filename=\"a.txt\"", "filename=\"b.txt\"");
    let mut ctx = post_ctx("/upload");
    ctx.headers = content_type_headers("multipart/form-data; boundary=abc");
    assert_reject(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &content_type_headers("multipart/form-data; boundary=abc"),
                bad_body.as_bytes(),
            )
            .await,
        Some(400),
    );
}

#[tokio::test]
async fn text_and_binary_response_validation_use_matching_schema_rules() {
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/download",
            "path_regex": "^/download$",
            "responses": {
                "200": {
                    "text/plain": {"type": "string", "pattern": "^ok:"},
                    "application/octet-stream": {"type": "string", "format": "binary", "minLength": 3, "maxLength": 3},
                    "application/pdf": {"type": "string", "format": "binary", "minLength": 4, "maxLength": 4}
                },
                "4XX": {
                    "application/json": {"type": "object", "required": ["error"]}
                }
            }
        }]
    }))
    .unwrap();
    let mut ctx = post_ctx("/download");

    assert_continue(
        plugin
            .on_final_response_body(
                &mut ctx,
                200,
                &content_type_headers("text/plain"),
                b"ok: ready",
            )
            .await,
    );
    let mut ctx = post_ctx("/download");
    assert_reject(
        plugin
            .on_final_response_body(&mut ctx, 200, &content_type_headers("text/plain"), b"bad")
            .await,
        Some(502),
    );
    let mut ctx = post_ctx("/download");
    assert_continue(
        plugin
            .on_final_response_body(
                &mut ctx,
                200,
                &content_type_headers("application/octet-stream"),
                &[0, 159, 255],
            )
            .await,
    );
    let mut ctx = post_ctx("/download");
    assert_continue(
        plugin
            .on_final_response_body(
                &mut ctx,
                200,
                &content_type_headers("application/pdf"),
                &[0, 159, 255, 42],
            )
            .await,
    );
    let mut ctx = post_ctx("/download");
    assert_reject(
        plugin
            .on_final_response_body(
                &mut ctx,
                200,
                &content_type_headers("application/pdf"),
                &[0, 159, 255, 42, 100],
            )
            .await,
        Some(502),
    );
    let mut ctx = post_ctx("/download");
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 404, &json_headers(), br#"{"error":"missing"}"#)
            .await,
    );
}

// Finding #17: two openapi_validator instances on the same request share
// ctx.metadata. Before the per-instance cache keys, the instance that marks its
// matched operation FIRST would have its (method, index) overwritten by a
// sibling and then resolve the sibling's index against its OWN differently
// ordered entry vector -- validating the request against the wrong operation
// schema. This test reproduces that ordering: instance A matches `/items` at
// sorted index 1 (because the more-specific `/items/extra` sorts first), while
// instance B matches `/items` at index 0. With the bug, A's body phase reads
// B's index 0 and validates against A's `/items/extra` schema (requires "z"),
// rejecting a body that is valid for `/items` (requires "a").
#[tokio::test]
async fn sibling_instances_do_not_cross_apply_operation_schemas() {
    let instance_a = OpenapiValidator::new(&json!({
        "operations": [
            {
                "method": "POST",
                "path_template": "/items/extra",
                "path_regex": "^/items/extra$",
                "request_required": true,
                "request_body": {
                    "content": {"application/json": {
                        "type": "object",
                        "required": ["z"],
                        "properties": {"z": {"type": "string"}}
                    }}
                }
            },
            {
                "method": "POST",
                "path_template": "/items",
                "path_regex": "^/items$",
                "request_required": true,
                "request_body": {
                    "content": {"application/json": {
                        "type": "object",
                        "required": ["a"],
                        "properties": {"a": {"type": "string"}}
                    }}
                }
            }
        ]
    }))
    .unwrap();
    let instance_b = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/items",
            "path_regex": "^/items$",
            "request_required": true,
            "request_body": {
                "content": {"application/json": {
                    "type": "object",
                    "required": ["b"],
                    "properties": {"b": {"type": "string"}}
                }}
            }
        }]
    }))
    .unwrap();

    // Production order: every instance's before_proxy runs before any body
    // phase. A marks first, then B overwrites the shared (legacy) keys.
    let mut ctx = post_ctx("/items");
    let mut headers = json_headers();
    assert_continue(instance_a.before_proxy(&mut ctx, &mut headers).await);
    assert_continue(instance_b.before_proxy(&mut ctx, &mut headers).await);

    // Body valid for A's `/items` operation ("a"), invalid for `/items/extra`
    // ("z"). A must validate against its own matched operation and continue.
    assert_continue(
        instance_a
            .on_final_request_body_with_context(&mut ctx, &json_headers(), br#"{"a":"ok"}"#)
            .await,
    );
}

// Finding #17 (bypass facet): cached_bypass_reason must read a per-instance key.
// A sibling that bypasses the request must not cause a non-bypassing instance to
// silently skip its own validation.
#[tokio::test]
async fn sibling_bypass_does_not_skip_other_instance_validation() {
    let bypassing = OpenapiValidator::new(&json!({
        "bypass": {"paths": ["^/items$"]},
        "operations": [{
            "method": "POST",
            "path_template": "/items",
            "path_regex": "^/items$",
            "request_body": {"content": {"application/json": {"type": "object"}}}
        }]
    }))
    .unwrap();
    let enforcing = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/items",
            "path_regex": "^/items$",
            "request_required": true,
            "request_body": {
                "content": {"application/json": {
                    "type": "object",
                    "required": ["a"],
                    "properties": {"a": {"type": "string"}}
                }}
            }
        }]
    }))
    .unwrap();

    let mut ctx = post_ctx("/items");
    let mut headers = json_headers();
    // The bypassing instance runs first and records its skip reason.
    assert_continue(bypassing.before_proxy(&mut ctx, &mut headers).await);
    // The enforcing instance must still reject a body missing the required "a".
    assert_reject(
        enforcing
            .on_final_request_body_with_context(&mut ctx, &json_headers(), br#"{}"#)
            .await,
        Some(400),
    );
}

// Finding #89: operator-supplied path_regex must be anchored so a loose pattern
// cannot substring-match an unintended superstring path.
#[tokio::test]
async fn unanchored_operator_path_regex_does_not_substring_match() {
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "GET",
            "path_template": "/users/{id}",
            "path_regex": "/users/[0-9]+"
        }]
    }))
    .unwrap();

    // Legitimate full-path request still matches.
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/users/1".into());
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);

    // Superstring path must NOT match -> unknown operation -> reject.
    let mut ctx = RequestContext::new(
        "127.0.0.1".into(),
        "GET".into(),
        "/admin/users/1/secret".into(),
    );
    let mut headers = HashMap::new();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

// Finding #89 (alternation): a top-level alternation must be wrapped as
// `^(?:a|b)$` so every branch is anchored. A bare `^a|b$` would leave the `/b`
// branch suffix-anchored only, wrongly matching `/zzz/b`.
#[tokio::test]
async fn alternation_path_regex_anchors_every_branch() {
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "GET",
            "path_template": "/a",
            "path_regex": "/a|/b"
        }]
    }))
    .unwrap();

    // Both alternation branches match when they are the whole path.
    for path in ["/a", "/b"] {
        let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), path.into());
        let mut headers = HashMap::new();
        assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    }

    // A path that merely ends with `/b` must NOT match (would match a bare
    // `^a|b$`). Unknown operation -> reject.
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/zzz/b".into());
    let mut headers = HashMap::new();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

// Finding #88: skipping the multipart `content` copy must stay
// outcome-preserving. A schema that validates `content` -- here via `required`
// plus a `pattern` constraint -- must still see the materialized content and
// enforce it.
#[tokio::test]
async fn multipart_content_validation_preserved_when_schema_requires_it() {
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/upload",
            "path_regex": "^/upload$",
            "request_body": {
                "content": {
                    "multipart/form-data": {
                        "type": "object",
                        "required": ["doc"],
                        "properties": {
                            "doc": {
                                "type": "object",
                                "required": ["content", "size"],
                                "properties": {
                                    "content": {"type": "string", "pattern": "^ok:"},
                                    "size": {"type": "integer"}
                                }
                            }
                        }
                    }
                }
            }
        }]
    }))
    .unwrap();
    let valid = concat!(
        "--abc\r\n",
        "Content-Disposition: form-data; name=\"doc\"\r\n\r\n",
        "ok: ready\r\n",
        "--abc--\r\n"
    );
    let mut ctx = post_ctx("/upload");
    ctx.headers = content_type_headers("multipart/form-data; boundary=abc");
    assert_continue(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &content_type_headers("multipart/form-data; boundary=abc"),
                valid.as_bytes(),
            )
            .await,
    );

    let invalid = valid.replace("ok: ready", "nope");
    let mut ctx = post_ctx("/upload");
    ctx.headers = content_type_headers("multipart/form-data; boundary=abc");
    assert_reject(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &content_type_headers("multipart/form-data; boundary=abc"),
                invalid.as_bytes(),
            )
            .await,
        Some(400),
    );
}

#[tokio::test]
async fn content_encoding_identity_and_single_codings_validate() {
    let plugin = OpenapiValidator::new(&validator_config("block")).unwrap();
    let plaintext = br#"{"name":"book"}"#;
    let response_plain = br#"{"ok":true}"#;

    for encoding in ["identity", "Identity", " identity "] {
        let mut ctx = post_ctx("/items");
        assert_continue(
            plugin
                .on_final_request_body_with_context(
                    &mut ctx,
                    &encoding_headers(encoding),
                    plaintext,
                )
                .await,
        );
        let mut ctx = post_ctx("/items");
        assert_continue(
            plugin
                .on_final_response_body(&mut ctx, 200, &encoding_headers(encoding), response_plain)
                .await,
        );
    }

    for (encoding, body) in [
        ("gzip", gzip_bytes(plaintext)),
        ("GZIP", gzip_bytes(plaintext)),
        ("br", brotli_bytes(plaintext)),
        ("BR", brotli_bytes(plaintext)),
    ] {
        let mut ctx = post_ctx("/items");
        assert_continue(
            plugin
                .on_final_request_body_with_context(&mut ctx, &encoding_headers(encoding), &body)
                .await,
        );
    }

    for (encoding, body) in [
        ("gzip", gzip_bytes(response_plain)),
        ("br", brotli_bytes(response_plain)),
    ] {
        let mut ctx = post_ctx("/items");
        assert_continue(
            plugin
                .on_final_response_body(&mut ctx, 200, &encoding_headers(encoding), &body)
                .await,
        );
    }
}

#[tokio::test]
async fn content_encoding_chains_decode_in_reverse_application_order() {
    let plugin = OpenapiValidator::new(&validator_config("block")).unwrap();
    let plaintext = br#"{"name":"book"}"#;
    let response_plain = br#"{"ok":true}"#;

    // Application order for `gzip, br` is gzip then brotli; undo br first.
    let gzip_then_br = brotli_bytes(&gzip_bytes(plaintext));
    let br_then_gzip = gzip_bytes(&brotli_bytes(plaintext));
    for (encoding, body) in [
        ("gzip, br", gzip_then_br.clone()),
        ("gzip,br", gzip_then_br.clone()),
        (" GZIP , BR ", gzip_then_br.clone()),
        ("br, gzip", br_then_gzip.clone()),
        ("BR,GZIP", br_then_gzip.clone()),
    ] {
        let mut ctx = post_ctx("/items");
        assert_continue(
            plugin
                .on_final_request_body_with_context(&mut ctx, &encoding_headers(encoding), &body)
                .await,
        );
    }

    let response_gzip_then_br = brotli_bytes(&gzip_bytes(response_plain));
    let response_br_then_gzip = gzip_bytes(&brotli_bytes(response_plain));
    for (encoding, body) in [
        ("gzip, br", response_gzip_then_br.as_slice()),
        ("br, gzip", response_br_then_gzip.as_slice()),
    ] {
        let mut ctx = post_ctx("/items");
        assert_continue(
            plugin
                .on_final_response_body(&mut ctx, 200, &encoding_headers(encoding), body)
                .await,
        );
    }

    // Wrong outer coding for the same bytes must fail closed (no partial decode).
    let mut ctx = post_ctx("/items");
    assert_reject(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &encoding_headers("br, gzip"),
                &gzip_then_br,
            )
            .await,
        Some(400),
    );
    let error = request_error(&ctx).unwrap_or_default();
    assert!(
        error.contains("decompression failed")
            || error.contains("truncated")
            || error.contains("trailing"),
        "wrong chain order must surface a decode error, got {error:?}"
    );
}

#[tokio::test]
async fn content_encoding_malformed_unsupported_and_corrupt_fail_closed() {
    let plugin = OpenapiValidator::new(&validator_config("block")).unwrap();
    let plaintext = br#"{"name":"book"}"#;

    for encoding in [",", "gzip,", ",br", "gzip,,br", " , ", "gzip;q=1.0"] {
        let mut ctx = post_ctx("/items");
        assert_reject(
            plugin
                .on_final_request_body_with_context(
                    &mut ctx,
                    &encoding_headers(encoding),
                    plaintext,
                )
                .await,
            Some(400),
        );
        let error = request_error(&ctx).unwrap_or_default();
        assert!(
            error.contains("empty coding")
                || error.contains("not a valid HTTP token")
                || error.contains("unsupported parameters"),
            "malformed `{encoding}` must be clear, got {error:?}"
        );
    }

    let mut ctx = post_ctx("/items");
    assert_reject(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &encoding_headers("gzip foo"),
                plaintext,
            )
            .await,
        Some(400),
    );
    assert!(
        request_error(&ctx)
            .unwrap_or_default()
            .contains("not a valid HTTP token"),
        "non-token member must be rejected clearly, got {:?}",
        request_error(&ctx)
    );

    let mut ctx = post_ctx("/items");
    assert_reject(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &encoding_headers("deflate"),
                plaintext,
            )
            .await,
        Some(400),
    );
    assert_eq!(
        request_error(&ctx),
        Some("unsupported content-encoding 'deflate'")
    );

    let mut ctx = post_ctx("/items");
    assert_reject(
        plugin
            .on_final_response_body(
                &mut ctx,
                200,
                &encoding_headers("zstd"),
                br#"{"ok":true}"#,
            )
            .await,
        Some(502),
    );
    assert_eq!(
        response_error(&ctx),
        Some("unsupported content-encoding 'zstd'")
    );

    // Corrupt outer layer of a gzip,br chain.
    let mut corrupt_outer = brotli_bytes(&gzip_bytes(plaintext));
    if let Some(last) = corrupt_outer.last_mut() {
        *last ^= 0xff;
    }
    let mut ctx = post_ctx("/items");
    assert_reject(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &encoding_headers("gzip, br"),
                &corrupt_outer,
            )
            .await,
        Some(400),
    );
    assert!(
        request_error(&ctx).is_some_and(|error| error.contains("brotli")),
        "corrupt outer brotli must fail, got {:?}",
        request_error(&ctx)
    );

    // Corrupt inner gzip while outer brotli framing stays valid: encode garbage
    // as brotli so the outer unwrap succeeds and the inner gzip fails.
    let corrupt_inner = brotli_bytes(b"not-gzip-payload");
    let mut ctx = post_ctx("/items");
    assert_reject(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &encoding_headers("gzip, br"),
                &corrupt_inner,
            )
            .await,
        Some(400),
    );
    assert!(
        request_error(&ctx).is_some_and(|error| error.contains("gzip")),
        "corrupt inner gzip must fail after outer decode, got {:?}",
        request_error(&ctx)
    );

    // Corrupt single-layer bodies still fail closed on both sides.
    let mut ctx = post_ctx("/items");
    assert_reject(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &encoding_headers("gzip"),
                b"not-gzip",
            )
            .await,
        Some(400),
    );
    let mut ctx = post_ctx("/items");
    assert_reject(
        plugin
            .on_final_response_body(&mut ctx, 200, &encoding_headers("br"), b"not-brotli")
            .await,
        Some(502),
    );
}

#[tokio::test]
async fn content_encoding_respects_max_body_bytes_on_raw_and_each_layer() {
    let plugin = OpenapiValidator::new(&json!({
        "enforcement_mode": "block",
        "schema_draft": "draft7",
        "max_body_bytes": 64,
        "operations": [{
            "method": "POST",
            "path_template": "/items",
            "path_regex": "^/items$",
            "request_required": true,
            "request_body": {
                "content": {
                    "application/json": {
                        "type": "object",
                        "required": ["name"],
                        "properties": {
                            "name": {"type": "string"}
                        }
                    }
                }
            },
            "responses": {
                "200": {
                    "application/json": {
                        "type": "object",
                        "required": ["ok"],
                        "properties": {"ok": {"type": "boolean"}}
                    }
                }
            }
        }]
    }))
    .unwrap();

    let exact = format!(r#"{{"name":"{}"}}"#, "n".repeat(53));
    assert_eq!(exact.len(), 64);
    let mut ctx = post_ctx("/items");
    assert_continue(
        plugin
            .on_final_request_body_with_context(&mut ctx, &json_headers(), exact.as_bytes())
            .await,
    );

    let oversized_raw = vec![b'a'; 65];
    let mut ctx = post_ctx("/items");
    assert_reject(
        plugin
            .on_final_request_body_with_context(&mut ctx, &json_headers(), &oversized_raw)
            .await,
        Some(400),
    );
    assert_eq!(
        request_error(&ctx),
        Some("Body exceeds max_body_bytes of 64 bytes")
    );

    // Highly compressible payload: wire size stays under the raw ceiling, but
    // the identity representation exceeds max_body_bytes after decoding.
    let large_json = format!(r#"{{"name":"{}"}}"#, "n".repeat(512));
    assert!(large_json.len() > 64);
    let gzip_large = gzip_bytes(large_json.as_bytes());
    assert!(
        gzip_large.len() <= 64,
        "gzip fixture must fit under raw max, got {}",
        gzip_large.len()
    );
    let mut ctx = post_ctx("/items");
    assert_reject(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &encoding_headers("gzip"),
                &gzip_large,
            )
            .await,
        Some(400),
    );
    assert!(
        request_error(&ctx)
            .unwrap_or_default()
            .contains("exceeds 64 bytes"),
        "single-layer expansion must honor max_body_bytes, got {:?}",
        request_error(&ctx)
    );

    // Chained expansion: outer layer may be small, but an intermediate/final
    // layer above max_body_bytes must still fail closed.
    let chained = brotli_bytes(&gzip_bytes(large_json.as_bytes()));
    assert!(
        chained.len() <= 64,
        "chained fixture must fit under raw max, got {}",
        chained.len()
    );
    let mut ctx = post_ctx("/items");
    assert_reject(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &encoding_headers("gzip, br"),
                &chained,
            )
            .await,
        Some(400),
    );
    assert!(
        request_error(&ctx)
            .unwrap_or_default()
            .contains("exceeds 64 bytes"),
        "chained expansion must honor max_body_bytes per layer, got {:?}",
        request_error(&ctx)
    );

    let response_large = format!(r#"{{"ok":true,"pad":"{}"}}"#, "p".repeat(512));
    let response_gzip = gzip_bytes(response_large.as_bytes());
    assert!(
        response_gzip.len() <= 64,
        "response gzip fixture must fit under raw max, got {}",
        response_gzip.len()
    );
    let mut ctx = post_ctx("/items");
    assert_reject(
        plugin
            .on_final_response_body(
                &mut ctx,
                200,
                &encoding_headers("gzip"),
                &response_gzip,
            )
            .await,
        Some(502),
    );
    assert!(
        response_error(&ctx)
            .unwrap_or_default()
            .contains("exceeds 64 bytes"),
        "response expansion must honor max_body_bytes, got {:?}",
        response_error(&ctx)
    );
}
