//! Cross-module registration and validation contract for
//! `ai_transcript_audit` native gRPC capture (issue #3304).

use ferrum_edge::plugins::{ProxyProtocol, create_plugin, validate_plugin_config};
use serde_json::json;

fn grpc_descriptor_path() -> String {
    format!(
        "{}/tests/fixtures/test_validator.bin",
        env!("CARGO_MANIFEST_DIR")
    )
}

#[test]
fn grpc_enrollment_extends_protocols_through_shared_registration() {
    let plugin = create_plugin(
        "ai_transcript_audit",
        &json!({
            "sink": {
                "type": "http",
                "endpoint_url": "https://audit.example.com/v1/transcripts"
            },
            "grpc": {
                "descriptor_path": grpc_descriptor_path(),
                "methods": {
                    "/test.Greeter/SayHello": {
                        "request_type": "test.HelloRequest",
                        "response_type": "test.HelloResponse"
                    }
                }
            }
        }),
    )
    .expect("valid ai_transcript_audit grpc config")
    .expect("built-in plugin is registered");

    let protocols = plugin.supported_protocols();
    assert!(protocols.contains(&ProxyProtocol::Http));
    assert!(protocols.contains(&ProxyProtocol::Grpc));
    assert!(plugin.requires_request_body_buffering());
    assert!(plugin.requires_response_body_buffering());
}

#[test]
fn shared_validation_is_shape_only_for_missing_descriptor() {
    let result = validate_plugin_config(
        "ai_transcript_audit",
        &json!({
            "sink": {
                "type": "http",
                "endpoint_url": "https://audit.example.com/v1/transcripts"
            },
            "grpc": {
                "descriptor_path": "/nonexistent/descriptor.bin",
                "methods": {
                    "/test.Greeter/SayHello": {
                        "request_type": "test.HelloRequest",
                        "response_type": "test.HelloResponse"
                    }
                }
            }
        }),
    );
    assert!(
        result.is_ok(),
        "Admin/CP shared validation must not require the node-local descriptor: {result:?}"
    );
}

#[test]
fn shared_validation_rejects_unknown_grpc_keys_and_empty_methods() {
    let unknown = validate_plugin_config(
        "ai_transcript_audit",
        &json!({
            "sink": {
                "type": "http",
                "endpoint_url": "https://audit.example.com/v1/transcripts"
            },
            "grpc": {
                "descriptor_path": "/tmp/x.bin",
                "unexpected": true,
                "methods": {
                    "/test.Greeter/SayHello": {"response_type": "test.HelloResponse"}
                }
            }
        }),
    )
    .expect_err("unknown grpc key must fail closed");
    assert!(
        unknown.contains("unexpected") || unknown.contains("allowed keys"),
        "got: {unknown}"
    );

    let empty_methods = validate_plugin_config(
        "ai_transcript_audit",
        &json!({
            "sink": {
                "type": "http",
                "endpoint_url": "https://audit.example.com/v1/transcripts"
            },
            "grpc": {
                "descriptor_path": "/tmp/x.bin",
                "methods": {}
            }
        }),
    )
    .expect_err("empty methods must fail closed");
    assert!(empty_methods.contains("methods"), "got: {empty_methods}");
}

/// The per-request buffering gate is what decides whether a native gRPC request
/// can ever reach a final request-body hook: the native-gRPC dispatch branch
/// selects the fully-streaming fast path when no plugin asked to buffer, and no
/// final-body hook runs there. Because the buffering decision is made before
/// `on_backend_path_resolved` republishes the backend-effective
/// `grpc_full_method`, an enrolled instance must buffer every native gRPC
/// request — otherwise a client path that only becomes enrolled after
/// listen-path stripping is pinned to the streaming path and silently escapes
/// capture. Instances with no `grpc` block, and ordinary HTTP requests, keep
/// their existing fast paths.
#[test]
fn grpc_request_body_buffer_gate_is_conservative_before_routing() {
    use ferrum_edge::_test_support::set_request_http_flavor_for_test;
    use ferrum_edge::HttpFlavor;
    use ferrum_edge::plugins::RequestContext;

    let grpc_ctx = |path: &str| {
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "POST".to_string(),
            path.to_string(),
        );
        set_request_http_flavor_for_test(&mut ctx, HttpFlavor::Grpc);
        ctx.headers
            .insert("content-type".to_string(), "application/grpc".to_string());
        ctx
    };

    let enrolled_instance = create_plugin(
        "ai_transcript_audit",
        &json!({
            "sink": {
                "type": "http",
                "endpoint_url": "https://audit.example.com/v1/transcripts"
            },
            "grpc": {
                "descriptor_path": grpc_descriptor_path(),
                "methods": {
                    "/test.Greeter/SayHello": {
                        "request_type": "test.HelloRequest",
                        "response_type": "test.HelloResponse"
                    }
                }
            }
        }),
    )
    .expect("valid ai_transcript_audit grpc config")
    .expect("built-in plugin is registered");

    assert!(
        enrolled_instance.should_buffer_request_body(&grpc_ctx("/test.Greeter/SayHello")),
        "an enrolled client-path method must buffer"
    );
    assert!(
        enrolled_instance.should_buffer_request_body(&grpc_ctx("/prefix/test.Greeter/SayHello")),
        "a client path that is not yet a parseable method must still buffer: the \
         backend-effective method can enroll it after listen-path stripping"
    );
    assert!(
        enrolled_instance.should_buffer_request_body(&grpc_ctx("/test.Greeter/Other")),
        "enrollment is not decidable before backend-path resolution, so the gate \
         must be conservative for every native gRPC method"
    );

    // Ordinary HTTP on the same instance is unchanged: only a JSON POST buffers.
    let mut http_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/v1/chat".to_string(),
    );
    http_ctx
        .headers
        .insert("content-type".to_string(), "text/plain".to_string());
    assert!(!enrolled_instance.should_buffer_request_body(&http_ctx));

    let http_only_instance = create_plugin(
        "ai_transcript_audit",
        &json!({
            "sink": {
                "type": "http",
                "endpoint_url": "https://audit.example.com/v1/transcripts"
            }
        }),
    )
    .expect("valid http-only config")
    .expect("registered");
    assert!(
        !http_only_instance.should_buffer_request_body(&grpc_ctx("/test.Greeter/SayHello")),
        "an instance without a grpc block must never buffer native gRPC"
    );
}

/// The operator-facing frame budgets are bounded at shared admission, so an
/// over-budget policy is refused before it can reach any node.
#[test]
fn grpc_frame_budgets_are_bounded_through_shared_validation() {
    use ferrum_edge::plugins::ai_transcript_audit::{
        HARD_MAX_GRPC_MAX_MESSAGE_BYTES, HARD_MAX_GRPC_MAX_MESSAGES,
    };

    let config = |field: &str, value: usize| {
        let mut config = json!({
            "sink": {
                "type": "http",
                "endpoint_url": "https://audit.example.com/v1/transcripts"
            },
            "grpc": {
                "descriptor_path": "/tmp/x.bin",
                "methods": {
                    "/test.Greeter/SayHello": {"request_type": "test.HelloRequest"}
                }
            }
        });
        config["grpc"][field] = json!(value);
        config
    };

    for (field, hard_max) in [
        ("max_message_bytes", HARD_MAX_GRPC_MAX_MESSAGE_BYTES),
        ("max_messages", HARD_MAX_GRPC_MAX_MESSAGES),
    ] {
        assert!(
            validate_plugin_config("ai_transcript_audit", &config(field, hard_max)).is_ok(),
            "'grpc.{field}' must accept exactly {hard_max}"
        );
        let error = validate_plugin_config("ai_transcript_audit", &config(field, hard_max + 1))
            .expect_err("above the deployment hard maximum must fail closed");
        assert!(
            error.contains(field) && error.contains(&hard_max.to_string()),
            "the diagnostic must name the field and its ceiling: {error}"
        );
    }
}

#[test]
fn http_only_registration_unchanged_without_grpc_block() {
    let plugin = create_plugin(
        "ai_transcript_audit",
        &json!({
            "sink": {
                "type": "http",
                "endpoint_url": "https://audit.example.com/v1/transcripts"
            }
        }),
    )
    .expect("valid http-only config")
    .expect("registered");
    assert_eq!(plugin.supported_protocols(), &[ProxyProtocol::Http]);
}
