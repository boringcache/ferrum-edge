//! Tests for ws_frame_logging plugin

use std::sync::{Arc, Mutex};

use ferrum_edge::plugins::correlation_id::CorrelationId;
use ferrum_edge::plugins::ws_frame_logging::WsFrameLogging;
use ferrum_edge::plugins::{
    Plugin, ProxyProtocol, WS_ONLY_PROTOCOLS, WebSocketFrameDirection, WsDisconnectContext,
};
use serde_json::json;
use tokio_tungstenite::tungstenite::protocol::Message;
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;

#[derive(Clone, Debug, Default)]
struct CapturedWsLog {
    preview: Option<String>,
    event: Option<String>,
    correlation_id: Option<String>,
}

#[derive(Clone, Default)]
struct WsLogCapture {
    events: Arc<Mutex<Vec<CapturedWsLog>>>,
}

impl WsLogCapture {
    fn layer(&self) -> WsLogCaptureLayer {
        WsLogCaptureLayer {
            events: Arc::clone(&self.events),
        }
    }

    fn events(&self) -> Vec<CapturedWsLog> {
        self.events.lock().unwrap().clone()
    }

    fn previews(&self) -> Vec<String> {
        self.events()
            .into_iter()
            .filter_map(|event| event.preview)
            .collect()
    }
}

struct WsLogCaptureLayer {
    events: Arc<Mutex<Vec<CapturedWsLog>>>,
}

impl<S> tracing_subscriber::Layer<S> for WsLogCaptureLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        if event.metadata().target() != "ws_frame_log" {
            return;
        }

        let mut visitor = WsLogVisitor::default();
        event.record(&mut visitor);
        self.events.lock().unwrap().push(CapturedWsLog {
            preview: visitor.preview,
            event: visitor.event,
            correlation_id: visitor.correlation_id,
        });
    }
}

#[derive(Default)]
struct WsLogVisitor {
    preview: Option<String>,
    event: Option<String>,
    correlation_id: Option<String>,
}

impl tracing::field::Visit for WsLogVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "preview" {
            self.preview = Some(value.to_string());
        } else if field.name() == "event" {
            self.event = Some(value.to_string());
        } else if field.name() == "correlation_id" {
            self.correlation_id = Some(value.to_string());
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "preview" {
            self.preview = Some(format!("{value:?}").trim_matches('"').to_string());
        } else if field.name() == "event" {
            self.event = Some(format!("{value:?}").trim_matches('"').to_string());
        } else if field.name() == "correlation_id" {
            self.correlation_id = Some(format!("{value:?}").trim_matches('"').to_string());
        }
    }
}

fn preview_plugin(preview_bytes: u64) -> WsFrameLogging {
    WsFrameLogging::new(&json!({
        "include_payload_preview": true,
        "payload_preview_bytes": preview_bytes,
    }))
    .expect("valid config")
}

fn install_ws_log_capture(capture: &WsLogCapture) -> tracing::subscriber::DefaultGuard {
    let subscriber = tracing_subscriber::registry().with(capture.layer());
    tracing::subscriber::set_default(subscriber)
}

async fn log_frame(plugin: &WsFrameLogging, connection_id: u64, message: &Message) {
    plugin
        .on_ws_frame(
            "test-proxy",
            connection_id,
            WebSocketFrameDirection::ClientToBackend,
            message,
        )
        .await;
}

fn assert_fingerprint_shape(preview: &str, len: usize) {
    let len_suffix = format!(" len={len}");
    assert!(preview.starts_with("hmac-sha256:"), "got: {preview}");
    assert!(preview.ends_with(&len_suffix), "got: {preview}");

    let digest = preview
        .strip_prefix("hmac-sha256:")
        .and_then(|value| value.strip_suffix(&len_suffix))
        .expect("fingerprint digest segment");
    let hex_part = digest.strip_suffix('+').unwrap_or(digest);
    assert_eq!(hex_part.len(), 12, "expected 12 hex chars, got: {hex_part}");
    assert!(
        hex_part.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "non-hex chars in fingerprint: {hex_part}"
    );
}

// === Plugin creation and metadata ===

#[test]
fn test_creation_defaults() {
    let plugin = WsFrameLogging::new(&json!({})).unwrap();
    assert_eq!(plugin.name(), "ws_frame_logging");
    assert_eq!(plugin.priority(), 9050);
}

// === Config validation ===

#[test]
fn test_creation_rejects_unknown_log_level() {
    let result = WsFrameLogging::new(&json!({"log_level": "warn"}));
    assert!(result.is_err());
    let msg = result.err().unwrap();
    assert!(msg.contains("log_level"), "msg: {msg}");
    assert!(msg.contains("warn"), "msg: {msg}");
}

#[test]
fn test_creation_rejects_non_object_config() {
    let result = WsFrameLogging::new(&json!("not-an-object"));
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("JSON object"));
}

#[test]
fn test_creation_rejects_uppercase_log_level() {
    // Per plugin-validation rules, exact-match lowercase only.
    let result = WsFrameLogging::new(&json!({"log_level": "INFO"}));
    assert!(result.is_err());
}

#[test]
fn test_creation_rejects_non_string_log_level() {
    let result = WsFrameLogging::new(&json!({"log_level": 1}));
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("log_level"));
}

#[test]
fn test_creation_accepts_valid_log_levels() {
    for level in ["trace", "debug", "info"] {
        WsFrameLogging::new(&json!({"log_level": level})).unwrap_or_else(|e| {
            panic!("expected '{level}' to be accepted but got: {e}");
        });
    }
}

#[test]
fn test_creation_rejects_non_bool_include_payload_preview() {
    let result = WsFrameLogging::new(&json!({"include_payload_preview": "yes"}));
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("include_payload_preview"));
}

#[test]
fn test_creation_rejects_non_bool_log_ping_pong() {
    let result = WsFrameLogging::new(&json!({"log_ping_pong": 1}));
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("log_ping_pong"));
}

#[test]
fn test_creation_rejects_non_integer_payload_preview_bytes() {
    let result = WsFrameLogging::new(&json!({"payload_preview_bytes": "128"}));
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("payload_preview_bytes"));
}

#[test]
fn test_supported_protocols_websocket_only() {
    let plugin = WsFrameLogging::new(&json!({})).unwrap();
    let protocols = plugin.supported_protocols();
    assert_eq!(protocols, WS_ONLY_PROTOCOLS);
    assert!(protocols.contains(&ProxyProtocol::WebSocket));
    assert!(!protocols.contains(&ProxyProtocol::Http));
    assert!(!protocols.contains(&ProxyProtocol::Grpc));
    assert!(!protocols.contains(&ProxyProtocol::Tcp));
    assert!(!protocols.contains(&ProxyProtocol::Udp));
}

#[test]
fn test_requires_ws_frame_hooks() {
    let plugin = WsFrameLogging::new(&json!({})).unwrap();
    assert!(plugin.requires_ws_frame_hooks());
}

#[tokio::test]
async fn correlation_id_composition_reaches_generated_and_preserved_disconnect_logs() {
    let capture = WsLogCapture::default();
    let _guard = install_ws_log_capture(&capture);
    let correlation = CorrelationId::new(&json!({})).expect("valid correlation config");
    let external_correlation = CorrelationId::new(&json!({
        "header_name": "x-external-correlation-id"
    }))
    .expect("valid external correlation config");
    let logger = WsFrameLogging::new(&json!({})).expect("valid WebSocket logger config");

    for inbound in [None, Some("ws-preserved-id")] {
        let mut request_ctx = super::plugin_utils::create_test_context();
        if let Some(inbound) = inbound {
            request_ctx
                .headers
                .insert("x-request-id".to_string(), inbound.to_string());
        }
        request_ctx.headers.insert(
            "x-external-correlation-id".to_string(),
            "attacker-controlled-alias".to_string(),
        );
        correlation.on_request_received(&mut request_ctx).await;
        external_correlation
            .on_request_received(&mut request_ctx)
            .await;
        let expected = request_ctx
            .metadata
            .get(ferrum_edge::plugins::REQUEST_ID_METADATA_KEY)
            .expect("canonical request ID")
            .clone();
        assert_ne!(expected, "attacker-controlled-alias");

        logger
            .on_ws_disconnect(&WsDisconnectContext {
                namespace: "ferrum".to_string(),
                proxy_id: "ws-proxy".to_string(),
                proxy_name: Some("websocket".to_string()),
                client_ip: "127.0.0.1".to_string(),
                backend_target: "ws://127.0.0.1:9001/socket".to_string(),
                listen_port: 8000,
                duration_ms: 1.0,
                frames_client_to_backend: 1,
                frames_backend_to_client: 1,
                bytes_client_to_backend: 4,
                bytes_backend_to_client: 4,
                direction: None,
                io_side: None,
                error_class: None,
                consumer_username: None,
                auth_method: None,
                metadata: request_ctx.metadata.clone(),
            })
            .await;

        let event = capture
            .events()
            .into_iter()
            .rev()
            .find(|event| event.event.as_deref() == Some("disconnect"))
            .expect("disconnect log event");
        assert_eq!(event.correlation_id.as_deref(), Some(expected.as_str()));
        if inbound.is_none() {
            assert!(uuid::Uuid::parse_str(&expected).is_ok());
        }
    }
}

// === on_ws_frame always returns None (never transforms) ===

#[tokio::test]
async fn test_text_frame_passthrough() {
    let plugin = WsFrameLogging::new(&json!({})).unwrap();
    let msg = Message::Text("hello world".into());
    let result = plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
    assert!(
        result.is_none(),
        "ws_frame_logging must never transform frames"
    );
}

#[tokio::test]
async fn test_binary_frame_passthrough() {
    let plugin = WsFrameLogging::new(&json!({})).unwrap();
    let msg = Message::Binary(vec![1, 2, 3, 4, 5].into());
    let result = plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
    assert!(result.is_none());
}

#[tokio::test]
async fn test_backend_to_client_passthrough() {
    let plugin = WsFrameLogging::new(&json!({})).unwrap();
    let msg = Message::Text("response data".into());
    let result = plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::BackendToClient,
            &msg,
        )
        .await;
    assert!(result.is_none());
}

// === Ping/Pong logging control ===

#[tokio::test]
async fn test_ping_skipped_by_default() {
    let plugin = WsFrameLogging::new(&json!({})).unwrap();
    let msg = Message::Ping(vec![1, 2, 3].into());
    // Should still return None (passthrough), just doesn't log
    let result = plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
    assert!(result.is_none());
}

#[tokio::test]
async fn test_pong_skipped_by_default() {
    let plugin = WsFrameLogging::new(&json!({})).unwrap();
    let msg = Message::Pong(vec![1, 2, 3].into());
    let result = plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
    assert!(result.is_none());
}

#[tokio::test]
async fn test_ping_logged_when_enabled() {
    let plugin = WsFrameLogging::new(&json!({"log_ping_pong": true})).unwrap();
    let msg = Message::Ping(vec![1, 2, 3].into());
    // Still returns None — logging is a side effect
    let result = plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
    assert!(result.is_none());
}

// === Config variations ===

#[tokio::test]
async fn test_with_payload_preview_enabled() {
    let plugin =
        WsFrameLogging::new(&json!({"include_payload_preview": true, "payload_preview_bytes": 10}))
            .unwrap();
    let msg = Message::Text("this is a longer message that should be truncated".into());
    let result = plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
    assert!(result.is_none());
}

#[tokio::test]
async fn test_binary_payload_preview() {
    let plugin =
        WsFrameLogging::new(&json!({"include_payload_preview": true, "payload_preview_bytes": 4}))
            .unwrap();
    let msg = Message::Binary(vec![0xDE, 0xAD, 0xBE, 0xEF, 0xFF].into());
    let result = plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
    assert!(result.is_none());
}

#[tokio::test]
async fn test_log_level_debug() {
    let plugin = WsFrameLogging::new(&json!({"log_level": "debug"})).unwrap();
    let msg = Message::Text("test".into());
    let result = plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
    assert!(result.is_none());
}

#[tokio::test]
async fn test_log_level_trace() {
    let plugin = WsFrameLogging::new(&json!({"log_level": "trace"})).unwrap();
    let msg = Message::Text("test".into());
    let result = plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
    assert!(result.is_none());
}

// === Different connection IDs ===

#[tokio::test]
async fn test_different_connection_ids_all_passthrough() {
    let plugin = WsFrameLogging::new(&json!({})).unwrap();
    let msg = Message::Text("test".into());

    for conn_id in 0..5 {
        let result = plugin
            .on_ws_frame(
                "test-proxy",
                conn_id,
                WebSocketFrameDirection::ClientToBackend,
                &msg,
            )
            .await;
        assert!(result.is_none());
    }
}

// === UTF-8 payload fingerprinting ===

#[tokio::test]
async fn test_payload_preview_truncates_at_utf8_boundary() {
    // "héllo" is 6 bytes: h(1) é(2) l(1) l(1) o(1)
    // With payload_preview_bytes=3, the hashed byte prefix lands on a UTF-8 boundary.
    // The fingerprint path must not interpret the prefix as text or panic.
    let plugin =
        WsFrameLogging::new(&json!({"include_payload_preview": true, "payload_preview_bytes": 3}))
            .unwrap();
    let msg = Message::Text("héllo".into());
    // Should not panic even though earlier raw-preview logic had to slice text.
    let result = plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
    assert!(result.is_none());
}

#[tokio::test]
async fn test_payload_preview_with_4byte_emoji() {
    // The emoji is 4 bytes. A 2-byte fingerprint budget cuts through it, which
    // is safe because the preview hashes bytes instead of slicing a string.
    let plugin =
        WsFrameLogging::new(&json!({"include_payload_preview": true, "payload_preview_bytes": 2}))
            .unwrap();
    let msg = Message::Text("🦀hello".into());
    let result = plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
    assert!(result.is_none());
}

#[tokio::test]
async fn test_payload_preview_exact_char_boundary() {
    // "abc" is 3 bytes. With preview_bytes=3, the full text is hashed.
    let plugin =
        WsFrameLogging::new(&json!({"include_payload_preview": true, "payload_preview_bytes": 3}))
            .unwrap();
    let msg = Message::Text("abc".into());
    let result = plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
    assert!(result.is_none());
}

#[test]
fn test_payload_preview_bytes_zero_rejected_when_preview_enabled() {
    let err =
        WsFrameLogging::new(&json!({"include_payload_preview": true, "payload_preview_bytes": 0}))
            .err()
            .expect("zero-byte payload fingerprints must be rejected");
    assert!(err.contains("payload_preview_bytes"), "got: {err}");
}

#[tokio::test]
async fn test_payload_preview_bytes_clamped_to_max() {
    // Very large payload_preview_bytes should be clamped (not cause OOM)
    let plugin = WsFrameLogging::new(
        &json!({"include_payload_preview": true, "payload_preview_bytes": 999999999}),
    )
    .unwrap();
    let msg = Message::Binary(vec![0xAB; 100].into());
    let result = plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
    assert!(result.is_none());
}

#[tokio::test]
async fn test_payload_preview_all_multibyte_chars() {
    // All 2-byte characters: "ñ" = 2 bytes each. "ñññ" = 6 bytes.
    // With preview_bytes=5, the hashed byte prefix cuts through the final char.
    let plugin =
        WsFrameLogging::new(&json!({"include_payload_preview": true, "payload_preview_bytes": 5}))
            .unwrap();
    let msg = Message::Text("ñññ".into());
    let result = plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
    assert!(result.is_none());
}

// === Empty frames ===

#[tokio::test]
async fn test_empty_text_frame() {
    let plugin = WsFrameLogging::new(&json!({"include_payload_preview": true})).unwrap();
    let msg = Message::Text(String::new().into());
    let result = plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
    assert!(result.is_none());
}

#[tokio::test]
async fn test_empty_binary_frame() {
    let plugin = WsFrameLogging::new(&json!({"include_payload_preview": true})).unwrap();
    let msg = Message::Binary(vec![].into());
    let result = plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
    assert!(result.is_none());
}

// === Payload fingerprint logging ===

#[tokio::test(flavor = "current_thread")]
async fn test_text_payload_preview_logs_fingerprint_without_raw_payload() {
    let capture = WsLogCapture::default();
    let _guard = install_ws_log_capture(&capture);
    let plugin = preview_plugin(4096);
    let secret = "Bearer sk-live-supersecret-token-AKIA1234567890";
    let raw = format!("{{\"type\":\"connection_init\",\"Authorization\":\"{secret}\"}}");

    log_frame(&plugin, 1, &Message::Text(raw.clone().into())).await;

    let previews = capture.previews();
    assert_eq!(previews.len(), 1, "expected one preview log");
    let preview = &previews[0];
    assert_fingerprint_shape(preview, raw.len());
    for leaked in [
        secret,
        "supersecret",
        "Bearer",
        "Authorization",
        "connection_init",
        raw.as_str(),
    ] {
        assert!(
            !preview.contains(leaked),
            "preview leaked sensitive content {leaked:?}: {preview}"
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn test_binary_payload_preview_logs_fingerprint_without_raw_hex() {
    let capture = WsLogCapture::default();
    let _guard = install_ws_log_capture(&capture);
    let plugin = preview_plugin(4096);
    let payload: Vec<u8> = vec![0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe];

    log_frame(&plugin, 1, &Message::Binary(payload.clone().into())).await;

    let previews = capture.previews();
    assert_eq!(previews.len(), 1, "expected one preview log");
    let preview = &previews[0];
    assert_fingerprint_shape(preview, payload.len());
    assert!(
        !preview.contains("deadbeefcafe"),
        "binary payload hex leaked: {preview}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn test_payload_preview_correlates_within_plugin_instance() {
    let capture = WsLogCapture::default();
    let _guard = install_ws_log_capture(&capture);
    let plugin = preview_plugin(4096);

    log_frame(&plugin, 1, &Message::Text("hello world".into())).await;
    log_frame(&plugin, 2, &Message::Text("hello world".into())).await;
    log_frame(&plugin, 3, &Message::Text("different".into())).await;

    let previews = capture.previews();
    assert_eq!(previews.len(), 3, "expected three preview logs");
    assert_eq!(
        previews[0], previews[1],
        "identical payloads must share a fingerprint"
    );
    assert_ne!(
        previews[0], previews[2],
        "different payloads must not share a fingerprint"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn test_payload_preview_key_differs_between_plugin_instances() {
    let capture = WsLogCapture::default();
    let _guard = install_ws_log_capture(&capture);
    let first = preview_plugin(4096);
    let second = preview_plugin(4096);
    let payload = Message::Text("{\"type\":\"connection_init\",\"password\":\"guessable\"}".into());

    log_frame(&first, 1, &payload).await;
    log_frame(&second, 2, &payload).await;

    let previews = capture.previews();
    assert_eq!(previews.len(), 2, "expected two preview logs");
    assert_ne!(
        previews[0], previews[1],
        "same payload should not be confirmable across plugin keys"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn test_truncated_payload_preview_is_flagged_and_reports_full_len() {
    let capture = WsLogCapture::default();
    let _guard = install_ws_log_capture(&capture);
    let plugin = preview_plugin(8);
    let raw = "0123456789abcdef";

    log_frame(&plugin, 1, &Message::Text(raw.into())).await;
    log_frame(&plugin, 2, &Message::Text("12345678".into())).await;

    let previews = capture.previews();
    assert_eq!(previews.len(), 2, "expected two preview logs");
    assert_fingerprint_shape(&previews[0], raw.len());
    assert!(
        previews[0].contains("+ len=16"),
        "truncated digest must carry a '+' marker, got: {}",
        previews[0]
    );
    assert!(
        !previews[0].contains(raw),
        "raw content leaked: {}",
        previews[0]
    );
    assert_fingerprint_shape(&previews[1], 8);
    assert!(
        !previews[1].contains('+'),
        "non-truncated digest must not carry '+': {}",
        previews[1]
    );
}

#[tokio::test(flavor = "current_thread")]
async fn test_payload_preview_omitted_when_disabled_or_control_frame() {
    let capture = WsLogCapture::default();
    let _guard = install_ws_log_capture(&capture);
    let disabled = WsFrameLogging::new(&json!({})).expect("valid config");
    let control = WsFrameLogging::new(&json!({
        "include_payload_preview": true,
        "log_ping_pong": true,
    }))
    .expect("valid config");

    log_frame(&disabled, 1, &Message::Text("anything".into())).await;
    log_frame(&control, 2, &Message::Ping(vec![1, 2].into())).await;
    log_frame(&control, 3, &Message::Pong(vec![3, 4].into())).await;
    log_frame(&control, 4, &Message::Close(None)).await;

    let events = capture.events();
    assert_eq!(events.len(), 4, "expected four ws_frame_log events");
    assert!(
        events.iter().all(|event| event.preview.is_none()),
        "preview should be omitted for disabled previews and control frames: {events:?}"
    );
}
