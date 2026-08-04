//! Cross-module registration and validation contract for
//! `ai_transcript_audit` native gRPC capture (issue #3304).

use ferrum_edge::plugins::{
    ProxyProtocol, create_plugin, validate_plugin_config,
};
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
    assert!(
        empty_methods.contains("methods"),
        "got: {empty_methods}"
    );
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
