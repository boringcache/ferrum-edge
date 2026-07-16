//! Tests for ws_message_size_limiting plugin configuration and parser policy.

use ferrum_edge::plugins::ws_message_size_limiting::WsMessageSizeLimiting;
use ferrum_edge::plugins::{
    Plugin, ProxyProtocol, WS_ONLY_PROTOCOLS, WebSocketFrameDirection, priority,
};
use serde_json::json;
use tokio_tungstenite::tungstenite::protocol::Message;

#[test]
fn test_creation_defaults_to_four_frame_reassembly_window() {
    let plugin = WsMessageSizeLimiting::new(&json!({"max_frame_bytes": 1024})).unwrap();
    assert_eq!(plugin.name(), "ws_message_size_limiting");
    assert_eq!(plugin.priority(), priority::WS_MESSAGE_SIZE_LIMITING);
    assert!(!plugin.is_auth_plugin());
    assert!(!plugin.modifies_request_headers());
    assert!(!plugin.modifies_request_body());
    assert!(!plugin.requires_request_body_buffering());
    assert!(!plugin.requires_response_body_buffering());

    let limits = plugin.websocket_size_limits().expect("parser limits");
    assert_eq!(limits.max_frame_bytes, 1024);
    assert_eq!(limits.max_message_bytes, 4096);
    assert_eq!(limits.close_reason.as_ref(), "Message too large");
}

#[test]
fn test_explicit_reassembled_message_limit() {
    let plugin = WsMessageSizeLimiting::new(&json!({
        "max_frame_bytes": 1024,
        "max_message_bytes": 8192,
        "close_reason": "proxy payload ceiling"
    }))
    .unwrap();
    let limits = plugin.websocket_size_limits().expect("parser limits");
    assert_eq!(limits.max_frame_bytes, 1024);
    assert_eq!(limits.max_message_bytes, 8192);
    assert_eq!(limits.close_reason.as_ref(), "proxy payload ceiling");
}

#[test]
fn test_supported_protocols_and_frame_parser_opt_in() {
    let plugin = WsMessageSizeLimiting::new(&json!({"max_frame_bytes": 1024})).unwrap();
    let protocols = plugin.supported_protocols();
    assert_eq!(protocols, WS_ONLY_PROTOCOLS);
    assert!(protocols.contains(&ProxyProtocol::WebSocket));
    assert!(!protocols.contains(&ProxyProtocol::Http));
    assert!(!protocols.contains(&ProxyProtocol::Grpc));
    assert!(!protocols.contains(&ProxyProtocol::Tcp));
    assert!(!protocols.contains(&ProxyProtocol::Udp));
    assert!(plugin.requires_ws_frame_hooks());
}

#[test]
fn test_invalid_configuration_is_rejected() {
    for config in [
        json!("bad"),
        json!({}),
        json!({"max_frame_bytes": 0}),
        json!({"max_frame_bytes": 1024, "max_message_bytes": 0}),
        json!({"max_frame_bytes": 1024, "max_message_bytes": 512}),
        json!({"max_frame_bytes": 1024, "close_reason": 123}),
    ] {
        assert!(
            WsMessageSizeLimiting::new(&config).is_err(),
            "configuration should fail: {config}"
        );
    }
}

#[test]
fn test_close_reason_is_truncated_on_utf8_boundary() {
    let plugin = WsMessageSizeLimiting::new(&json!({
        "max_frame_bytes": 5,
        "close_reason": "🙂".repeat(40)
    }))
    .unwrap();
    let limits = plugin.websocket_size_limits().expect("parser limits");
    assert!(limits.close_reason.len() <= 123);
    assert!(std::str::from_utf8(limits.close_reason.as_bytes()).is_ok());
}

#[tokio::test]
async fn test_reassembled_message_is_not_mistaken_for_one_frame() {
    let plugin = WsMessageSizeLimiting::new(&json!({
        "max_frame_bytes": 64,
        "max_message_bytes": 256
    }))
    .unwrap();
    let reassembled = Message::Binary(vec![0; 128].into());

    // `on_ws_frame` receives tungstenite messages after continuation
    // reassembly. Actual frame enforcement belongs to the parser-level policy,
    // so a valid 2x64-byte fragmented message must not be rejected here.
    assert!(
        plugin
            .on_ws_frame(
                "test-proxy",
                1,
                WebSocketFrameDirection::ClientToBackend,
                &reassembled,
            )
            .await
            .is_none()
    );
}
