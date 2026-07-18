use ferrum_edge::plugins::{
    GRPC_ONLY_PROTOCOLS, Plugin, PluginResult, RequestContext, create_plugin,
    normalize_response_body_for_inspection, priority,
};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

use super::plugin_utils::{assert_continue, assert_reject, create_test_context};

#[test]
fn h3_grpc_web_requests_keep_the_http_protocol_key() {
    use ferrum_edge::_test_support::h3_plugin_protocol_for_request_for_test;
    use ferrum_edge::config::types::HttpFlavor;
    use ferrum_edge::plugins::ProxyProtocol;

    assert_eq!(
        h3_plugin_protocol_for_request_for_test(HttpFlavor::Plain, true),
        ProxyProtocol::Http
    );
    assert_eq!(
        h3_plugin_protocol_for_request_for_test(HttpFlavor::Plain, false),
        ProxyProtocol::Http
    );
}

#[tokio::test]
async fn streaming_grpc_web_deadline_emits_encoded_status_before_backend_data() {
    use bytes::Bytes;
    use ferrum_edge::_test_support::{
        GRPC_FRAME_TRAILER, parse_grpc_frames, proxy_body_streaming_for_test,
        proxy_body_with_client_grpc_deadline_for_test,
    };
    use ferrum_edge::proxy::body::ProxyBodyError;
    use futures_util::stream;
    use http_body::{Body, Frame};
    use http_body_util::{BodyExt, StreamBody};

    let inner = StreamBody::new(stream::pending::<Result<Frame<Bytes>, ProxyBodyError>>());
    let body = proxy_body_streaming_for_test(Box::pin(inner));
    let deadline = tokio::time::Instant::now()
        .checked_sub(std::time::Duration::from_secs(1))
        .expect("one second before now is representable");
    let mut body = proxy_body_with_client_grpc_deadline_for_test(
        body,
        deadline,
        Some("application/grpc-web+proto"),
    );

    let frame = body
        .frame()
        .await
        .expect("deadline must emit a terminal frame")
        .expect("terminal deadline frame must be readable");
    let data = frame
        .data_ref()
        .expect("gRPC-Web terminal status is encoded as DATA");
    let frames = parse_grpc_frames(data);
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].0, GRPC_FRAME_TRAILER);
    assert!(
        frames[0]
            .1
            .windows(b"grpc-status: 4".len())
            .any(|window| window == b"grpc-status: 4")
    );
    assert!(Body::is_end_stream(&body));
}

#[test]
fn buffered_h3_committed_deadline_preserves_binary_text_and_native_framing() {
    use base64::Engine as _;
    use ferrum_edge::_test_support::{
        GRPC_FRAME_TRAILER, h3_buffered_grpc_deadline_replacement_for_test, parse_grpc_frames,
    };

    for content_type in [
        "application/grpc-web+proto",
        "application/grpc-web-text+proto",
    ] {
        let response = h3_buffered_grpc_deadline_replacement_for_test(Some(content_type));
        assert_eq!(response.http_status, http::StatusCode::OK);
        assert_eq!(
            response.headers.get("content-type").map(String::as_str),
            Some(content_type)
        );
        assert_eq!(
            response.headers.get("x-grpc-web").map(String::as_str),
            Some("1")
        );
        assert!(
            response
                .headers
                .contains_key("access-control-expose-headers")
        );
        assert_eq!(
            response.headers.get("x-correlation-id").map(String::as_str),
            Some("request-123")
        );
        assert_eq!(
            response.headers.get("vary").map(String::as_str),
            Some("Origin")
        );
        for backend_only in ["tracestate", "x-backend-secret", "set-cookie"] {
            assert!(!response.headers.contains_key(backend_only));
        }
        assert!(!response.headers.contains_key("grpc-status"));
        assert!(!response.headers.contains_key("grpc-message"));

        let decoded = if content_type.contains("-text") {
            base64::engine::general_purpose::STANDARD
                .decode(&response.body)
                .expect("text gRPC-Web deadline body must be valid base64")
        } else {
            response.body.clone()
        };
        let frames = parse_grpc_frames(&decoded);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].0, GRPC_FRAME_TRAILER);
        assert!(
            frames[0]
                .1
                .windows(b"grpc-status: 4".len())
                .any(|window| window == b"grpc-status: 4")
        );
        assert!(
            frames[0]
                .1
                .windows(b"grpc-message: Deadline exceeded at gateway".len())
                .any(|window| window == b"grpc-message: Deadline exceeded at gateway")
        );
        assert_eq!(response.grpc_status, Some(4));
        assert_eq!(
            response.grpc_message.as_deref(),
            Some("Deadline exceeded at gateway")
        );
    }

    let native = h3_buffered_grpc_deadline_replacement_for_test(None);
    assert_eq!(native.http_status, http::StatusCode::OK);
    assert_eq!(
        native.headers.get("content-type").map(String::as_str),
        Some("application/grpc")
    );
    assert_eq!(
        native.headers.get("grpc-status").map(String::as_str),
        Some("4")
    );
    assert_eq!(
        native.headers.get("grpc-message").map(String::as_str),
        Some("Deadline exceeded at gateway")
    );
    assert_eq!(
        native.headers.get("x-correlation-id").map(String::as_str),
        Some("request-123")
    );
    assert_eq!(
        native.headers.get("vary").map(String::as_str),
        Some("Origin")
    );
    for backend_only in ["tracestate", "x-backend-secret", "set-cookie"] {
        assert!(!native.headers.contains_key(backend_only));
    }
    assert!(native.body.is_empty());
}

#[test]
fn retry_backoff_deadline_response_is_request_aware_for_grpc_web() {
    use base64::Engine as _;
    use ferrum_edge::_test_support::{
        GRPC_FRAME_TRAILER, client_grpc_deadline_response_for_request_for_test, parse_grpc_frames,
    };
    use ferrum_edge::retry::ErrorClass;

    for content_type in [
        "application/grpc-web+proto",
        "application/grpc-web-text+proto",
    ] {
        let response = client_grpc_deadline_response_for_request_for_test(content_type);
        assert_eq!(response.status_code, 200);
        assert!(!response.connection_error);
        assert_eq!(response.error_class, Some(ErrorClass::ClientDisconnect));
        assert_eq!(
            response.headers.get("content-type").map(String::as_str),
            Some(content_type)
        );
        assert!(!response.headers.contains_key("grpc-status"));

        let decoded = if content_type.contains("-text") {
            base64::engine::general_purpose::STANDARD
                .decode(&response.body)
                .expect("text gRPC-Web retry deadline body must be valid base64")
        } else {
            response.body
        };
        let frames = parse_grpc_frames(&decoded);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].0, GRPC_FRAME_TRAILER);
        assert!(
            frames[0]
                .1
                .windows(b"grpc-status: 4".len())
                .any(|window| window == b"grpc-status: 4")
        );
    }

    let native = client_grpc_deadline_response_for_request_for_test("application/grpc");
    assert_eq!(
        native.headers.get("content-type").map(String::as_str),
        Some("application/grpc")
    );
    assert_eq!(
        native.headers.get("grpc-status").map(String::as_str),
        Some("4")
    );
    assert!(native.body.is_empty());
    assert_eq!(native.error_class, Some(ErrorClass::ClientDisconnect));
}

#[test]
fn remaining_duration_rounds_up_to_the_next_wire_millisecond() {
    use ferrum_edge::_test_support::grpc_deadline_duration_millis_ceil_saturating_for_test;
    use std::time::Duration;

    assert_eq!(
        grpc_deadline_duration_millis_ceil_saturating_for_test(Duration::ZERO),
        None
    );
    assert_eq!(
        grpc_deadline_duration_millis_ceil_saturating_for_test(Duration::from_nanos(1)),
        Some(1)
    );
    assert_eq!(
        grpc_deadline_duration_millis_ceil_saturating_for_test(Duration::from_nanos(999_999)),
        Some(1)
    );
    assert_eq!(
        grpc_deadline_duration_millis_ceil_saturating_for_test(Duration::from_nanos(1_000_001)),
        Some(2)
    );
}

fn create_grpc_context_with_timeout(timeout: Option<&str>) -> ferrum_edge::plugins::RequestContext {
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.path = "/my.Service/MyMethod".to_string();
    ctx.headers
        .insert("content-type".to_string(), "application/grpc".to_string());
    if let Some(t) = timeout {
        ctx.headers
            .insert("grpc-timeout".to_string(), t.to_string());
    }
    ctx
}

#[test]
fn grpc_timeout_metadata_is_not_populated_without_deadline_policy() {
    let mut ctx = create_grpc_context_with_timeout(Some("250m"));

    assert_continue(ferrum_edge::plugins::grpc_deadline::prepare_request_deadline(&[], &mut ctx));

    assert!(
        ctx.grpc_deadline_at().is_some(),
        "the client RPC ceiling remains active without a policy plugin"
    );
    assert!(!ctx.metadata.contains_key("grpc_original_deadline_ms"));
    assert!(!ctx.metadata.contains_key("grpc_adjusted_deadline_ms"));
}

struct StalledResponseNormalizer;

#[async_trait::async_trait]
impl Plugin for StalledResponseNormalizer {
    fn name(&self) -> &str {
        "stalled_response_normalizer"
    }

    async fn normalize_response_body_with_context(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        _body: &[u8],
        _content_type: Option<&str>,
        _response_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        std::future::pending().await
    }
}

struct StalledResponseTransformer;

#[async_trait::async_trait]
impl Plugin for StalledResponseTransformer {
    fn name(&self) -> &str {
        "stalled_response_transformer"
    }

    async fn transform_response_body_with_context(
        &self,
        _ctx: &mut RequestContext,
        _body: &[u8],
        _content_type: Option<&str>,
        _response_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        std::future::pending().await
    }
}

struct TrustedResponseHeaderDecorator {
    headers: HashMap<String, String>,
}

#[async_trait::async_trait]
impl Plugin for TrustedResponseHeaderDecorator {
    fn name(&self) -> &str {
        "trusted_response_header_decorator"
    }

    async fn after_proxy(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        response_headers.extend(self.headers.clone());
        PluginResult::Continue
    }
}

struct SlowRejectDecorator {
    name: &'static str,
    delay: std::time::Duration,
    calls: Arc<std::sync::atomic::AtomicUsize>,
    completed: Arc<std::sync::atomic::AtomicUsize>,
    completion: Arc<tokio::sync::Notify>,
}

struct ImmediateRejectHeaderDecorator;

#[async_trait::async_trait]
impl Plugin for ImmediateRejectHeaderDecorator {
    fn name(&self) -> &str {
        "immediate_reject_header_decorator"
    }

    fn applies_after_proxy_on_reject(&self) -> bool {
        true
    }

    async fn after_proxy(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        response_headers.insert("x-before-deadline".to_string(), "trusted".to_string());
        PluginResult::Continue
    }
}

#[async_trait::async_trait]
impl Plugin for SlowRejectDecorator {
    fn name(&self) -> &str {
        self.name
    }

    fn applies_after_proxy_on_reject(&self) -> bool {
        true
    }

    async fn after_proxy(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        tokio::time::sleep(self.delay).await;
        response_headers.insert(format!("x-{}-complete", self.name), "true".to_string());
        self.completed
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.completion.notify_one();
        PluginResult::Continue
    }
}

struct StalledAfterProxyDecorator;

#[async_trait::async_trait]
impl Plugin for StalledAfterProxyDecorator {
    fn name(&self) -> &str {
        "stalled_after_proxy_decorator"
    }

    async fn after_proxy(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        _response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        std::future::pending().await
    }
}

struct StalledContextFreeBodyTransformer;

#[async_trait::async_trait]
impl Plugin for StalledContextFreeBodyTransformer {
    fn name(&self) -> &str {
        "stalled_context_free_body_transformer"
    }

    fn modifies_request_body(&self) -> bool {
        true
    }

    async fn transform_request_body(
        &self,
        _body: &[u8],
        _content_type: Option<&str>,
        _headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        std::future::pending().await
    }
}

#[tokio::test]
async fn rejection_hook_deadline_selects_terminal_status_and_finishes_cleanup_once() {
    use ferrum_edge::_test_support::{
        finalize_plugin_rejection_parts_for_test, gateway_deadline_response_selected_for_test,
        set_grpc_deadline_budget_for_test,
    };

    let calls = (0..2)
        .map(|_| Arc::new(std::sync::atomic::AtomicUsize::new(0)))
        .collect::<Vec<_>>();
    let completed = (0..2)
        .map(|_| Arc::new(std::sync::atomic::AtomicUsize::new(0)))
        .collect::<Vec<_>>();
    let completion = (0..2)
        .map(|_| Arc::new(tokio::sync::Notify::new()))
        .collect::<Vec<_>>();
    let plugins: Vec<Arc<dyn Plugin>> = vec![
        Arc::new(SlowRejectDecorator {
            name: "slow-cleanup",
            delay: std::time::Duration::from_millis(20),
            calls: Arc::clone(&calls[0]),
            completed: Arc::clone(&completed[0]),
            completion: Arc::clone(&completion[0]),
        }),
        Arc::new(SlowRejectDecorator {
            name: "later-decorator",
            delay: std::time::Duration::ZERO,
            calls: Arc::clone(&calls[1]),
            completed: Arc::clone(&completed[1]),
            completion: Arc::clone(&completion[1]),
        }),
    ];
    let mut ctx = create_grpc_context_with_timeout(None);
    set_grpc_deadline_budget_for_test(&mut ctx, Some(1));

    let (status, body, headers) = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        finalize_plugin_rejection_parts_for_test(
            &plugins,
            &mut ctx,
            429,
            b"rate limited".to_vec(),
            HashMap::from([(
                "access-control-allow-origin".to_string(),
                "https://browser.example".to_string(),
            )]),
        ),
    )
    .await
    .expect("cleanup must finish without reusing the expired deadline");

    assert_eq!(status, 200);
    assert!(body.is_empty());
    assert_eq!(headers.get("grpc-status").map(String::as_str), Some("4"));
    assert_eq!(
        headers.get("grpc-message").map(String::as_str),
        Some("Deadline exceeded at gateway")
    );
    assert_eq!(
        headers
            .get("access-control-allow-origin")
            .map(String::as_str),
        Some("https://browser.example")
    );
    assert!(!headers.contains_key("x-slow-cleanup-complete"));
    assert!(!headers.contains_key("x-later-decorator-complete"));
    assert!(gateway_deadline_response_selected_for_test(&ctx));

    tokio::time::timeout(std::time::Duration::from_secs(2), completion[1].notified())
        .await
        .expect("detached rejection cleanup must continue in plugin order");
    for count in calls.iter().chain(completed.iter()) {
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn rejection_mid_hook_deadline_preserves_completed_decorator() {
    use ferrum_edge::_test_support::{
        finalize_plugin_rejection_for_test, set_grpc_deadline_budget_for_test,
    };

    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let completed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let completion = Arc::new(tokio::sync::Notify::new());
    let plugins: Vec<Arc<dyn Plugin>> = vec![
        Arc::new(ImmediateRejectHeaderDecorator),
        Arc::new(SlowRejectDecorator {
            name: "pending-after-decorator",
            delay: std::time::Duration::from_millis(20),
            calls: Arc::clone(&calls),
            completed: Arc::clone(&completed),
            completion: Arc::clone(&completion),
        }),
    ];
    let mut ctx = create_grpc_context_with_timeout(None);
    set_grpc_deadline_budget_for_test(&mut ctx, Some(10));

    let (status, body, headers) = finalize_plugin_rejection_for_test(
        &plugins,
        &mut ctx,
        503,
        b"discarded rejection".to_vec(),
        HashMap::new(),
    )
    .await;

    assert_eq!(status, 200);
    assert!(body.is_empty());
    assert_eq!(headers.get("grpc-status").map(String::as_str), Some("4"));
    assert_eq!(
        headers.get("x-before-deadline").map(String::as_str),
        Some("trusted"),
        "a completed non-replacing decorator must survive later hook expiry"
    );
    assert!(!headers.contains_key("x-pending-after-decorator-complete"));
    tokio::time::timeout(std::time::Duration::from_secs(2), completion.notified())
        .await
        .expect("pending decorator must finish on detached cleanup state");
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(completed.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn context_free_final_body_timeout_marks_authoritative_deadline_provenance() {
    use ferrum_edge::_test_support::{
        gateway_deadline_response_selected_for_test,
        run_context_free_final_request_body_hooks_for_test, set_grpc_deadline_budget_for_test,
    };

    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(StalledContextFreeBodyTransformer)];
    let mut ctx = create_grpc_context_with_timeout(None);
    set_grpc_deadline_budget_for_test(&mut ctx, Some(5));
    let result = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        run_context_free_final_request_body_hooks_for_test(
            &plugins,
            &mut ctx,
            &HashMap::new(),
            b"transformed body",
        ),
    )
    .await
    .expect("context-free body hook must stop at the absolute RPC deadline");

    match result {
        PluginResult::Reject {
            status_code,
            headers,
            ..
        } => {
            assert_eq!(status_code, 200);
            assert_eq!(headers.get("grpc-status").map(String::as_str), Some("4"));
        }
        other => panic!("expected terminal deadline rejection, got {other:?}"),
    }
    assert!(gateway_deadline_response_selected_for_test(&ctx));
}

#[test]
fn deadline_replacement_preserves_safe_decorators_and_strips_conflicting_fields() {
    use base64::Engine as _;
    use ferrum_edge::_test_support::{
        GRPC_FRAME_TRAILER, buffered_grpc_deadline_replacement_for_test, parse_grpc_frames,
    };

    for content_type in [None, Some("application/grpc-web-text+proto")] {
        let response = buffered_grpc_deadline_replacement_for_test(
            content_type,
            HashMap::from([
                (
                    "traceparent".to_string(),
                    "00-backendbackendbackendbackendbacken-backendbackendba-01".to_string(),
                ),
                ("set-cookie".to_string(), "session=renewed".to_string()),
                (
                    "authorization".to_string(),
                    "Bearer backend-secret".to_string(),
                ),
                ("x-internal-token".to_string(), "backend-secret".to_string()),
                ("Vary".to_string(), "Accept-Encoding, Origin".to_string()),
                ("content-length".to_string(), "999".to_string()),
                ("content-encoding".to_string(), "gzip".to_string()),
                ("transfer-encoding".to_string(), "chunked".to_string()),
                ("grpc-status".to_string(), "13".to_string()),
                ("grpc-message".to_string(), "backend failure".to_string()),
                ("grpc-status-details-bin".to_string(), "stale".to_string()),
            ]),
            HashMap::from([
                (
                    "access-control-allow-origin".to_string(),
                    "https://browser.example".to_string(),
                ),
                ("x-correlation-id".to_string(), "request-123".to_string()),
                (
                    "traceparent".to_string(),
                    "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01".to_string(),
                ),
                (
                    "strict-transport-security".to_string(),
                    "max-age=31536000".to_string(),
                ),
            ]),
            b"discarded backend body".to_vec(),
        );

        assert_eq!(response.http_status, http::StatusCode::OK);
        for (name, value) in [
            ("access-control-allow-origin", "https://browser.example"),
            ("x-correlation-id", "request-123"),
            (
                "traceparent",
                "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01",
            ),
            ("strict-transport-security", "max-age=31536000"),
        ] {
            assert_eq!(response.headers.get(name).map(String::as_str), Some(value));
        }
        assert_eq!(
            response.headers.get("vary").map(String::as_str),
            Some("Origin")
        );
        assert!(!response.headers.contains_key("content-encoding"));
        assert!(!response.headers.contains_key("transfer-encoding"));
        assert!(!response.headers.contains_key("grpc-status-details-bin"));
        assert!(!response.headers.contains_key("set-cookie"));
        assert!(!response.headers.contains_key("authorization"));
        assert!(!response.headers.contains_key("x-internal-token"));

        if let Some(content_type) = content_type {
            assert_eq!(
                response.headers.get("content-type").map(String::as_str),
                Some(content_type)
            );
            assert!(!response.headers.contains_key("grpc-status"));
            assert_eq!(
                response
                    .headers
                    .get("content-length")
                    .and_then(|value| value.parse::<usize>().ok()),
                Some(response.body.len())
            );
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(&response.body)
                .expect("text gRPC-Web deadline body must be base64");
            let frames = parse_grpc_frames(&decoded);
            assert_eq!(frames.len(), 1);
            assert_eq!(frames[0].0, GRPC_FRAME_TRAILER);
            assert!(
                frames[0]
                    .1
                    .windows(14)
                    .any(|window| window == b"grpc-status: 4")
            );
        } else {
            assert_eq!(
                response.headers.get("grpc-status").map(String::as_str),
                Some("4")
            );
            assert!(!response.headers.contains_key("content-length"));
            assert!(response.body.is_empty());
        }
    }
}

struct CommittedHookProbe {
    calls: Arc<std::sync::atomic::AtomicUsize>,
    observed_grpc_statuses: Arc<std::sync::Mutex<Vec<Option<String>>>>,
    release: Option<Arc<tokio::sync::Notify>>,
    completion: Arc<tokio::sync::Notify>,
}

#[async_trait::async_trait]
impl Plugin for CommittedHookProbe {
    fn name(&self) -> &str {
        "committed_hook_probe"
    }

    fn requires_response_committed_hook(&self) -> bool {
        true
    }

    async fn on_response_committed(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &HashMap<String, String>,
        _body: &[u8],
    ) {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.observed_grpc_statuses
            .lock()
            .expect("probe observations lock")
            .push(response_headers.get("grpc-status").cloned());
        if let Some(release) = &self.release {
            release.notified().await;
        }
        self.completion.notify_one();
    }
}

#[tokio::test]
async fn committed_deadline_replacement_runs_remaining_hooks_exactly_once() {
    use ferrum_edge::_test_support::{
        run_deadline_bounded_response_committed_hooks_for_test, set_grpc_deadline_budget_for_test,
    };

    let calls = (0..3)
        .map(|_| Arc::new(std::sync::atomic::AtomicUsize::new(0)))
        .collect::<Vec<_>>();
    let observed = (0..3)
        .map(|_| Arc::new(std::sync::Mutex::new(Vec::new())))
        .collect::<Vec<_>>();
    let stalled_release = Arc::new(tokio::sync::Notify::new());
    let completion = (0..3)
        .map(|_| Arc::new(tokio::sync::Notify::new()))
        .collect::<Vec<_>>();
    let plugins: Vec<Arc<dyn Plugin>> = (0..3)
        .map(|index| {
            Arc::new(CommittedHookProbe {
                calls: Arc::clone(&calls[index]),
                observed_grpc_statuses: Arc::clone(&observed[index]),
                release: (index == 1).then(|| Arc::clone(&stalled_release)),
                completion: Arc::clone(&completion[index]),
            }) as Arc<dyn Plugin>
        })
        .collect();
    let mut ctx = create_grpc_context_with_timeout(None);
    set_grpc_deadline_budget_for_test(&mut ctx, Some(50));
    let mut status = 200;
    let mut headers = HashMap::from([
        ("content-type".to_string(), "application/grpc".to_string()),
        ("x-backend".to_string(), "present".to_string()),
    ]);
    let mut body = b"backend response".to_vec();

    assert!(
        run_deadline_bounded_response_committed_hooks_for_test(
            &plugins,
            &mut ctx,
            &mut status,
            &mut headers,
            &mut body,
        )
        .await
    );

    assert_eq!(status, 200);
    assert_eq!(headers.get("grpc-status").map(String::as_str), Some("4"));
    assert!(body.is_empty());
    assert_eq!(calls[0].load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(calls[1].load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(calls[2].load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(
        observed[0].lock().expect("first probe lock").as_slice(),
        &[None]
    );
    assert_eq!(
        observed[1].lock().expect("second probe lock").as_slice(),
        &[None]
    );
    assert!(observed[2].lock().expect("third probe lock").is_empty());

    stalled_release.notify_waiters();
    tokio::time::timeout(std::time::Duration::from_secs(2), completion[2].notified())
        .await
        .expect("detached committed observers must continue in plugin order");
    for call_count in &calls {
        assert_eq!(call_count.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
    assert_eq!(
        observed[2].lock().expect("third probe lock").as_slice(),
        &[Some("4".to_string())]
    );
}

#[tokio::test]
async fn response_transform_deadline_replaces_native_and_grpc_web_responses() {
    use base64::Engine as _;
    use ferrum_edge::_test_support::{
        GRPC_FRAME_TRAILER, parse_grpc_frames, set_grpc_deadline_budget_for_test,
        transform_buffered_response_body_with_deadline_for_test,
    };

    for content_type in [
        None,
        Some("application/grpc-web+proto"),
        Some("application/grpc-web-text+proto"),
    ] {
        let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(StalledResponseTransformer)];
        let mut ctx = create_grpc_context_with_timeout(None);
        set_grpc_deadline_budget_for_test(&mut ctx, Some(10));
        let mut status = 200;
        let mut headers = HashMap::from([
            ("content-type".to_string(), "application/grpc".to_string()),
            ("content-length".to_string(), "16".to_string()),
        ]);
        let mut body = b"backend response".to_vec();

        assert!(
            transform_buffered_response_body_with_deadline_for_test(
                &plugins,
                &mut ctx,
                &mut status,
                &mut headers,
                &mut body,
                content_type,
            )
            .await
        );
        assert_eq!(status, 200);

        if let Some(content_type) = content_type {
            assert_eq!(
                headers.get("content-type").map(String::as_str),
                Some(content_type)
            );
            assert!(!headers.contains_key("grpc-status"));
            let decoded = if content_type.contains("-text") {
                base64::engine::general_purpose::STANDARD
                    .decode(&body)
                    .expect("text gRPC-Web deadline body must be base64")
            } else {
                body
            };
            let frames = parse_grpc_frames(&decoded);
            assert_eq!(frames.len(), 1);
            assert_eq!(frames[0].0, GRPC_FRAME_TRAILER);
            assert!(
                frames[0]
                    .1
                    .windows(b"grpc-status: 4".len())
                    .any(|window| window == b"grpc-status: 4")
            );
        } else {
            assert_eq!(headers.get("grpc-status").map(String::as_str), Some("4"));
            assert!(body.is_empty());
        }
    }
}

#[tokio::test]
async fn buffered_deadline_keeps_only_provenance_owned_gateway_headers() {
    use base64::Engine as _;
    use ferrum_edge::_test_support::{
        GRPC_FRAME_TRAILER, parse_grpc_frames, run_after_proxy_hooks_for_test,
        set_grpc_deadline_budget_for_test,
        transform_buffered_response_body_with_deadline_and_policy_for_test,
    };

    for (correlation_config, correlation_name) in [
        (json!({}), "x-request-id"),
        (
            json!({ "header_name": "x-custom-request-id" }),
            "x-custom-request-id",
        ),
    ] {
        for grpc_web_content_type in [
            None,
            Some("application/grpc-web+proto"),
            Some("application/grpc-web-text+proto"),
        ] {
            let correlation = create_plugin("correlation_id", &correlation_config)
                .unwrap()
                .unwrap();
            let security = create_plugin(
                "security_headers",
                &json!({ "set": { "x-policy-exact": "gateway-policy" } }),
            )
            .unwrap()
            .unwrap();
            let decorator: Arc<dyn Plugin> = Arc::new(TrustedResponseHeaderDecorator {
                headers: HashMap::from([(
                    "x-trusted-decorator".to_string(),
                    "gateway-output".to_string(),
                )]),
            });
            let after_proxy_plugins =
                vec![Arc::clone(&correlation), Arc::clone(&security), decorator];
            let initial_policy_plugins = vec![Arc::clone(&security)];
            let transform_plugins: Vec<Arc<dyn Plugin>> =
                vec![Arc::new(StalledResponseTransformer)];
            let mut ctx = create_grpc_context_with_timeout(None);
            ctx.headers.insert(
                correlation_name.to_string(),
                "client-request-id".to_string(),
            );
            assert_continue(correlation.on_request_received(&mut ctx).await);
            set_grpc_deadline_budget_for_test(&mut ctx, Some(1_000));

            let mut headers = HashMap::from([
                ("content-type".to_string(), "application/grpc".to_string()),
                (
                    correlation_name.to_string(),
                    "client-request-id".to_string(),
                ),
                ("tracestate".to_string(), "backend=spoof".to_string()),
                (
                    "traceparent".to_string(),
                    "00-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-cccccccccccccccc-01".to_string(),
                ),
                (
                    "access-control-allow-origin".to_string(),
                    "https://backend.example".to_string(),
                ),
                (
                    "strict-transport-security".to_string(),
                    "max-age=backend".to_string(),
                ),
                (
                    "x-internal-secret".to_string(),
                    "backend-secret".to_string(),
                ),
                ("authorization".to_string(), "Bearer backend".to_string()),
                ("cookie".to_string(), "request=secret".to_string()),
                ("set-cookie".to_string(), "session=secret".to_string()),
                (
                    "proxy-authenticate".to_string(),
                    "Basic realm=backend".to_string(),
                ),
                (
                    "www-authenticate".to_string(),
                    "Bearer realm=backend".to_string(),
                ),
                ("x-policy-exact".to_string(), "gateway-policy".to_string()),
                (
                    "x-trusted-decorator".to_string(),
                    "backend-spoof".to_string(),
                ),
                ("vary".to_string(), "Accept-Encoding, Origin".to_string()),
            ]);
            assert!(
                !run_after_proxy_hooks_for_test(&after_proxy_plugins, &mut ctx, 200, &mut headers,)
                    .await,
                "trusted decorators must not reject the buffered response"
            );
            set_grpc_deadline_budget_for_test(&mut ctx, Some(0));
            let mut status = 200;
            let mut body = b"discarded backend response".to_vec();

            assert!(
                transform_buffered_response_body_with_deadline_and_policy_for_test(
                    &transform_plugins,
                    &mut ctx,
                    &mut status,
                    &mut headers,
                    &mut body,
                    grpc_web_content_type,
                    &initial_policy_plugins,
                )
                .await
            );
            assert_eq!(status, 200);
            assert_eq!(
                headers.get(correlation_name).map(String::as_str),
                Some("client-request-id"),
                "configured correlation ownership must survive an exact backend spoof"
            );
            assert_eq!(
                headers.get("x-trusted-decorator").map(String::as_str),
                Some("gateway-output")
            );
            assert_eq!(
                headers.get("x-policy-exact").map(String::as_str),
                Some("gateway-policy"),
                "deterministic initial policy must be replayed after sanitization"
            );
            assert_eq!(headers.get("vary").map(String::as_str), Some("Origin"));
            for backend_only in [
                "tracestate",
                "traceparent",
                "access-control-allow-origin",
                "strict-transport-security",
                "x-internal-secret",
                "authorization",
                "cookie",
                "set-cookie",
                "proxy-authenticate",
                "www-authenticate",
            ] {
                assert!(
                    !headers.contains_key(backend_only),
                    "backend-only field {backend_only} must not cross deadline replacement"
                );
            }

            if let Some(content_type) = grpc_web_content_type {
                assert_eq!(
                    headers.get("content-type").map(String::as_str),
                    Some(content_type)
                );
                assert!(!headers.contains_key("grpc-status"));
                let decoded = if content_type.contains("-text") {
                    base64::engine::general_purpose::STANDARD
                        .decode(&body)
                        .expect("text gRPC-Web deadline body must be base64")
                } else {
                    body
                };
                let frames = parse_grpc_frames(&decoded);
                assert_eq!(frames.len(), 1);
                assert_eq!(frames[0].0, GRPC_FRAME_TRAILER);
                assert!(
                    frames[0]
                        .1
                        .windows(b"grpc-status: 4".len())
                        .any(|window| window == b"grpc-status: 4")
                );
            } else {
                assert_eq!(headers.get("grpc-status").map(String::as_str), Some("4"));
                assert!(body.is_empty());
            }
        }
    }
}

#[test]
fn deadline_replacement_preserves_gateway_authored_set_cookie() {
    use ferrum_edge::_test_support::buffered_grpc_deadline_replacement_for_test;

    for content_type in [None, Some("application/grpc-web+proto")] {
        let response = buffered_grpc_deadline_replacement_for_test(
            content_type,
            HashMap::from([
                ("content-type".to_string(), "application/grpc".to_string()),
                // A backend-supplied cookie the gateway never re-authors must
                // still be dropped: it never enters gateway provenance.
                ("set-cookie".to_string(), "backend=stale".to_string()),
                ("x-backend-secret".to_string(), "leak".to_string()),
            ]),
            HashMap::from([
                // Gateway-authored session refresh (e.g. `oidc_relying_party`
                // rotating the session cookie on its reject path). The client
                // must receive this even on a terminal DEADLINE_EXCEEDED.
                (
                    "set-cookie".to_string(),
                    "session=refreshed; HttpOnly; Path=/".to_string(),
                ),
                ("x-correlation-id".to_string(), "request-123".to_string()),
            ]),
            b"discarded backend body".to_vec(),
        );

        assert_eq!(response.http_status, http::StatusCode::OK);
        assert_eq!(
            response.headers.get("set-cookie").map(String::as_str),
            Some("session=refreshed; HttpOnly; Path=/"),
            "a gateway-authored session cookie must survive the deadline rebuild"
        );
        assert_eq!(
            response.headers.get("x-correlation-id").map(String::as_str),
            Some("request-123")
        );
        assert!(
            !response.headers.contains_key("x-backend-secret"),
            "backend-only fields must never cross deadline replacement"
        );
    }
}

/// A trusted response decorator that APPENDS its gateway cookie onto any
/// existing `Set-Cookie`, exactly as `oidc_relying_party::after_proxy` does when
/// it rotates a session on a response that already carries a backend cookie.
struct SessionCookieAppendingDecorator {
    cookie: &'static str,
}

#[async_trait::async_trait]
impl Plugin for SessionCookieAppendingDecorator {
    fn name(&self) -> &str {
        "session_cookie_appending_decorator"
    }

    async fn after_proxy(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        response_headers
            .entry("set-cookie".to_string())
            .and_modify(|existing| {
                existing.push('\n');
                existing.push_str(self.cookie);
            })
            .or_insert_with(|| self.cookie.to_string());
        PluginResult::Continue
    }
}

/// A committed-response observer that never completes, used to drive the RPC
/// deadline to expiry inside the response-committed phase.
struct StalledCommittedHook;

#[async_trait::async_trait]
impl Plugin for StalledCommittedHook {
    fn name(&self) -> &str {
        "stalled_committed_hook"
    }

    fn requires_response_committed_hook(&self) -> bool {
        true
    }

    async fn on_response_committed(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        _response_headers: &HashMap<String, String>,
        _body: &[u8],
    ) {
        std::future::pending().await
    }
}

/// A non-replacing reject-path decorator that completes synchronously, writing
/// one gateway header. Used to exercise a CHAIN of owned-hook clone/adopt cycles
/// before a later hook exhausts the deadline.
struct CompletingRejectDecorator {
    name: &'static str,
    header: &'static str,
    value: &'static str,
}

#[async_trait::async_trait]
impl Plugin for CompletingRejectDecorator {
    fn name(&self) -> &str {
        self.name
    }

    fn applies_after_proxy_on_reject(&self) -> bool {
        true
    }

    async fn after_proxy(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        response_headers.insert(self.header.to_string(), self.value.to_string());
        PluginResult::Continue
    }
}

/// Finding 4: when a trusted hook (`oidc_relying_party`) appends its gateway
/// session cookie onto the backend's existing `Set-Cookie`, only the
/// gateway-authored cookie line may cross a terminal deadline rebuild; the
/// backend cookie must be stripped.
#[tokio::test]
async fn deadline_replacement_strips_backend_cookie_when_gateway_appends_session() {
    use ferrum_edge::_test_support::{
        run_after_proxy_hooks_reject_for_test, set_grpc_deadline_budget_for_test,
    };

    let plugins: Vec<Arc<dyn Plugin>> = vec![
        Arc::new(SessionCookieAppendingDecorator {
            cookie: "ferrum_session=refreshed; HttpOnly; Path=/",
        }),
        Arc::new(StalledAfterProxyDecorator),
    ];

    let mut ctx = create_grpc_context_with_timeout(None);
    set_grpc_deadline_budget_for_test(&mut ctx, Some(0));

    let mut headers = HashMap::from([
        ("content-type".to_string(), "application/grpc".to_string()),
        (
            "set-cookie".to_string(),
            "backend_sid=leak; Path=/".to_string(),
        ),
    ]);

    let (status, body, headers) =
        run_after_proxy_hooks_reject_for_test(&plugins, &mut ctx, 200, &mut headers)
            .await
            .expect("a stalled after_proxy hook must terminate as a deadline rejection");

    assert_eq!(status, 200);
    assert!(body.is_empty());
    assert_eq!(headers.get("grpc-status").map(String::as_str), Some("4"));
    assert_eq!(
        headers.get("set-cookie").map(String::as_str),
        Some("ferrum_session=refreshed; HttpOnly; Path=/"),
        "only the gateway-authored session cookie may cross a deadline rebuild"
    );
    assert!(
        !headers
            .get("set-cookie")
            .is_some_and(|value| value.contains("backend_sid")),
        "a backend-supplied cookie must never ride the DEADLINE_EXCEEDED response"
    );
}

/// Finding 1: the sticky-session affinity cookie injected by proxy core (not by
/// a plugin mutation) must survive a later response-committed hook exhausting
/// the RPC deadline so the client stays pinned; a co-present backend cookie is
/// still stripped.
#[tokio::test]
async fn deadline_replacement_preserves_injected_sticky_cookie_and_strips_backend() {
    use ferrum_edge::_test_support::{
        record_deadline_owned_response_headers_for_test, run_after_proxy_hooks_for_test,
        run_deadline_bounded_response_committed_hooks_for_test, set_grpc_deadline_budget_for_test,
    };

    let no_plugins: Vec<Arc<dyn Plugin>> = vec![];
    let committed: Vec<Arc<dyn Plugin>> = vec![Arc::new(StalledCommittedHook)];

    let mut ctx = create_grpc_context_with_timeout(None);
    set_grpc_deadline_budget_for_test(&mut ctx, Some(1_000));

    // Backend response carries its own cookie; provenance captures it as the
    // backend baseline before any gateway output.
    let mut headers = HashMap::from([
        ("content-type".to_string(), "application/grpc".to_string()),
        (
            "set-cookie".to_string(),
            "backend_sid=leak; Path=/".to_string(),
        ),
    ]);
    assert!(
        !run_after_proxy_hooks_for_test(&no_plugins, &mut ctx, 200, &mut headers).await,
        "seeding backend provenance must not reject the response"
    );

    // Proxy core injects the sticky-affinity cookie (append) and records it as
    // gateway-owned, exactly as the gRPC / committed-hook path does.
    headers
        .entry("set-cookie".to_string())
        .and_modify(|existing| {
            existing.push('\n');
            existing.push_str("ferrum_affinity=target-a; Path=/");
        })
        .or_insert_with(|| "ferrum_affinity=target-a; Path=/".to_string());
    record_deadline_owned_response_headers_for_test(
        &mut ctx,
        &["set-cookie".to_string()],
        &headers,
    );

    // A committed-response hook then exhausts the RPC deadline.
    set_grpc_deadline_budget_for_test(&mut ctx, Some(0));
    let mut status = 200;
    let mut body = b"discarded backend response".to_vec();
    assert!(
        run_deadline_bounded_response_committed_hooks_for_test(
            &committed,
            &mut ctx,
            &mut status,
            &mut headers,
            &mut body,
        )
        .await
    );

    assert_eq!(status, 200);
    assert_eq!(headers.get("grpc-status").map(String::as_str), Some("4"));
    assert_eq!(
        headers.get("set-cookie").map(String::as_str),
        Some("ferrum_affinity=target-a; Path=/"),
        "the injected sticky-affinity cookie must survive a committed-hook deadline"
    );
    assert!(
        !headers
            .get("set-cookie")
            .is_some_and(|value| value.contains("backend_sid")),
        "the backend cookie present at injection must not cross the deadline rebuild"
    );
}

/// Finding 2: `workload_metrics` echoing the gateway `traceparent` from metadata
/// owns that header, so an exact backend echo (invisible to mutation tracking)
/// still preserves the mesh trace context across a gRPC deadline rebuild.
#[tokio::test]
async fn deadline_replacement_preserves_workload_metrics_traceparent_on_exact_backend_echo() {
    use ferrum_edge::_test_support::{
        run_after_proxy_hooks_for_test, set_grpc_deadline_budget_for_test,
        transform_buffered_response_body_with_deadline_for_test,
    };

    let workload_metrics = create_plugin("workload_metrics", &json!({}))
        .unwrap()
        .unwrap();
    let after_proxy_plugins = vec![Arc::clone(&workload_metrics)];
    let transform_plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(StalledResponseTransformer)];

    let gateway_trace = "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01";

    let mut ctx = create_grpc_context_with_timeout(None);
    // The gateway trace context lives in metadata; workload_metrics echoes it in
    // after_proxy exactly like otel_tracing.
    ctx.metadata
        .insert("traceparent".to_string(), gateway_trace.to_string());
    set_grpc_deadline_budget_for_test(&mut ctx, Some(1_000));

    // The backend already echoed the identical traceparent, so mutation tracking
    // alone cannot see the gateway write.
    let mut headers = HashMap::from([
        ("content-type".to_string(), "application/grpc".to_string()),
        ("traceparent".to_string(), gateway_trace.to_string()),
    ]);
    assert!(
        !run_after_proxy_hooks_for_test(&after_proxy_plugins, &mut ctx, 200, &mut headers).await,
        "workload_metrics after_proxy must not reject the response"
    );

    set_grpc_deadline_budget_for_test(&mut ctx, Some(0));
    let mut status = 200;
    let mut body = b"discarded backend response".to_vec();
    assert!(
        transform_buffered_response_body_with_deadline_for_test(
            &transform_plugins,
            &mut ctx,
            &mut status,
            &mut headers,
            &mut body,
            None,
        )
        .await
    );

    assert_eq!(status, 200);
    assert_eq!(
        headers.get("traceparent").map(String::as_str),
        Some(gateway_trace),
        "workload_metrics must own its echoed traceparent so the mesh deadline response keeps trace context"
    );
    assert_eq!(headers.get("grpc-status").map(String::as_str), Some("4"));
    assert!(body.is_empty());
}

/// Finding 3 (regression lock): a chain of completing decorators run through the
/// owned-hook clone/adopt path under an active deadline; every adopted context
/// must retain the previously recorded gateway output before a later hook
/// exhausts the deadline.
#[tokio::test]
async fn owned_hook_clone_adopt_chain_preserves_all_recorded_decorators() {
    use ferrum_edge::_test_support::{
        finalize_plugin_rejection_for_test, set_grpc_deadline_budget_for_test,
    };

    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let completed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let completion = Arc::new(tokio::sync::Notify::new());
    let plugins: Vec<Arc<dyn Plugin>> = vec![
        Arc::new(CompletingRejectDecorator {
            name: "first-reject-decorator",
            header: "x-first-decorator",
            value: "first",
        }),
        Arc::new(CompletingRejectDecorator {
            name: "second-reject-decorator",
            header: "x-second-decorator",
            value: "second",
        }),
        Arc::new(SlowRejectDecorator {
            name: "pending-after-decorator",
            delay: std::time::Duration::from_millis(20),
            calls: Arc::clone(&calls),
            completed: Arc::clone(&completed),
            completion: Arc::clone(&completion),
        }),
    ];
    let mut ctx = create_grpc_context_with_timeout(None);
    set_grpc_deadline_budget_for_test(&mut ctx, Some(10));

    let (status, body, headers) = finalize_plugin_rejection_for_test(
        &plugins,
        &mut ctx,
        503,
        b"discarded rejection".to_vec(),
        HashMap::new(),
    )
    .await;

    assert_eq!(status, 200);
    assert!(body.is_empty());
    assert_eq!(headers.get("grpc-status").map(String::as_str), Some("4"));
    assert_eq!(
        headers.get("x-first-decorator").map(String::as_str),
        Some("first"),
        "the first adopted owned-hook decoration must survive the chain"
    );
    assert_eq!(
        headers.get("x-second-decorator").map(String::as_str),
        Some("second"),
        "a later adopted owned-hook context must keep the earlier recorded output"
    );
    tokio::time::timeout(std::time::Duration::from_secs(2), completion.notified())
        .await
        .expect("pending decorator must finish on detached cleanup state");
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(completed.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[test]
fn deadline_replacement_regenerates_canonical_grpc_web_framing_header() {
    use ferrum_edge::_test_support::buffered_grpc_deadline_replacement_for_test;

    for content_type in [
        "application/grpc-web+proto",
        "application/grpc-web-text+proto",
    ] {
        let response = buffered_grpc_deadline_replacement_for_test(
            Some(content_type),
            HashMap::from([("content-type".to_string(), "application/grpc".to_string())]),
            HashMap::from([
                // A completed gateway hook must not be able to override the
                // canonical gRPC-Web framing marker on the terminal response.
                ("x-grpc-web".to_string(), "0".to_string()),
                ("x-correlation-id".to_string(), "request-123".to_string()),
            ]),
            b"discarded backend body".to_vec(),
        );

        assert_eq!(response.http_status, http::StatusCode::OK);
        assert_eq!(
            response.headers.get("x-grpc-web").map(String::as_str),
            Some("1"),
            "canonical gRPC-Web framing must survive a gateway hook writing x-grpc-web"
        );
        assert_eq!(
            response.headers.get("x-correlation-id").map(String::as_str),
            Some("request-123"),
            "non-framing gateway decorations still survive alongside regenerated framing"
        );
    }
}

#[tokio::test]
async fn deadline_replacement_keeps_exact_value_response_transformer_writes() {
    use ferrum_edge::_test_support::{
        run_after_proxy_hooks_for_test, set_grpc_deadline_budget_for_test,
        transform_buffered_response_body_with_deadline_for_test,
    };
    use ferrum_edge::plugins::utils::route_header_transform::{
        RawRouteHeaderTransformRule, parse_route_header_transforms,
    };

    for grpc_web_content_type in [None, Some("application/grpc-web+proto")] {
        let response_transformer = create_plugin(
            "response_transformer",
            &json!({
                "rules": [{
                    "operation": "update",
                    "target": "header",
                    "key": "x-rt-exact",
                    "value": "gateway-value"
                }]
            }),
        )
        .unwrap()
        .unwrap();
        let after_proxy_plugins = vec![response_transformer];
        let transform_plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(StalledResponseTransformer)];

        let route_rules = parse_route_header_transforms(
            &[RawRouteHeaderTransformRule {
                operation: "update".to_string(),
                target: "header".to_string(),
                key: "x-route-exact".to_string(),
                value: Some("route-value".to_string()),
            }],
            "route_override",
        )
        .unwrap();

        let mut ctx = create_grpc_context_with_timeout(None);
        set_grpc_deadline_budget_for_test(&mut ctx, Some(1_000));
        ctx.route_override_response_transform = Some(Arc::new(route_rules));

        // The backend pre-populates BOTH decorations with the exact value the
        // trusted `update` writes, so mutation tracking alone cannot see the
        // gateway write and would drop it without ownership recording.
        let mut headers = HashMap::from([
            ("content-type".to_string(), "application/grpc".to_string()),
            ("x-rt-exact".to_string(), "gateway-value".to_string()),
            ("x-route-exact".to_string(), "route-value".to_string()),
        ]);
        assert!(
            !run_after_proxy_hooks_for_test(&after_proxy_plugins, &mut ctx, 200, &mut headers)
                .await,
            "response transformer must not reject the buffered response"
        );

        set_grpc_deadline_budget_for_test(&mut ctx, Some(0));
        let mut status = 200;
        let mut body = b"discarded backend response".to_vec();
        assert!(
            transform_buffered_response_body_with_deadline_for_test(
                &transform_plugins,
                &mut ctx,
                &mut status,
                &mut headers,
                &mut body,
                grpc_web_content_type,
            )
            .await
        );
        assert_eq!(status, 200);
        assert_eq!(
            headers.get("x-rt-exact").map(String::as_str),
            Some("gateway-value"),
            "an exact-value static `update` write must survive the deadline rebuild"
        );
        assert_eq!(
            headers.get("x-route-exact").map(String::as_str),
            Some("route-value"),
            "an exact-value route-override `update` write must survive the deadline rebuild"
        );
    }
}

#[tokio::test]
async fn buffered_after_proxy_deadline_preserves_completed_decorators_on_rejection() {
    use ferrum_edge::_test_support::{
        run_after_proxy_hooks_reject_for_test, set_grpc_deadline_budget_for_test,
    };

    let correlation = create_plugin("correlation_id", &json!({}))
        .unwrap()
        .unwrap();
    let decorator: Arc<dyn Plugin> = Arc::new(TrustedResponseHeaderDecorator {
        headers: HashMap::from([(
            "x-completed-decorator".to_string(),
            "gateway-output".to_string(),
        )]),
    });
    // correlation (owns its echoed id) and a non-replacing decorator both
    // complete, then a later after_proxy hook exhausts the RPC deadline.
    let plugins = vec![
        Arc::clone(&correlation),
        decorator,
        Arc::new(StalledAfterProxyDecorator) as Arc<dyn Plugin>,
    ];

    let mut ctx = create_grpc_context_with_timeout(None);
    ctx.headers
        .insert("x-request-id".to_string(), "client-request-id".to_string());
    assert_continue(correlation.on_request_received(&mut ctx).await);
    set_grpc_deadline_budget_for_test(&mut ctx, Some(0));

    let mut headers = HashMap::from([
        ("content-type".to_string(), "application/grpc".to_string()),
        ("x-backend-secret".to_string(), "leak".to_string()),
    ]);

    let (status, body, headers) =
        run_after_proxy_hooks_reject_for_test(&plugins, &mut ctx, 200, &mut headers)
            .await
            .expect("a stalled after_proxy hook must terminate as a deadline rejection");

    assert_eq!(status, 200);
    assert!(body.is_empty());
    assert_eq!(headers.get("grpc-status").map(String::as_str), Some("4"));
    assert_eq!(
        headers.get("grpc-message").map(String::as_str),
        Some("Deadline exceeded at gateway")
    );
    // A completed non-replacing decorator does not re-run on the reject path,
    // so its output can survive the terminal deadline rejection only through
    // the provenance recorded on the buffered path.
    assert_eq!(
        headers.get("x-completed-decorator").map(String::as_str),
        Some("gateway-output"),
        "a completed decorator must survive a later after_proxy hook's deadline expiry"
    );
    assert_eq!(
        headers.get("x-request-id").map(String::as_str),
        Some("client-request-id"),
        "a completed owning decorator must survive the terminal deadline rejection"
    );
    assert!(
        !headers.contains_key("x-backend-secret"),
        "backend-only fields must never cross deadline replacement"
    );
}

#[tokio::test]
async fn buffered_deadline_strips_gateway_authored_cache_and_representation_headers() {
    use ferrum_edge::_test_support::{
        run_after_proxy_hooks_for_test, set_grpc_deadline_budget_for_test,
        transform_buffered_response_body_with_deadline_for_test,
    };

    let stale_headers = [
        ("accept-ranges", "bytes"),
        ("age", "120"),
        ("cache-control", "public, max-age=3600"),
        ("cdn-cache-control", "max-age=3600"),
        ("content-language", "en-US"),
        ("content-location", "/discarded-representation"),
        ("digest", "sha-256=stale"),
        ("expires", "Wed, 01 Jan 2030 00:00:00 GMT"),
        ("grpc-accept-encoding", "gzip"),
        ("grpc-encoding", "gzip"),
        ("pragma", "cache"),
        ("retry-after", "120"),
        ("surrogate-control", "max-age=3600"),
        ("warning", "110 stale"),
    ];
    let mut rules = stale_headers
        .iter()
        .map(|(key, value)| {
            json!({
                "operation": "add",
                "target": "header",
                "key": key,
                "value": value
            })
        })
        .collect::<Vec<_>>();
    rules.push(json!({
        "operation": "add",
        "target": "header",
        "key": "x-transformer-decoration",
        "value": "retained"
    }));
    let response_transformer = create_plugin("response_transformer", &json!({ "rules": rules }))
        .unwrap()
        .unwrap();
    let after_proxy_plugins = vec![response_transformer];
    let transform_plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(StalledResponseTransformer)];

    for grpc_web_content_type in [
        None,
        Some("application/grpc-web+proto"),
        Some("application/grpc-web-text+proto"),
    ] {
        let mut ctx = create_grpc_context_with_timeout(None);
        set_grpc_deadline_budget_for_test(&mut ctx, Some(1_000));
        let mut headers = HashMap::from([
            ("content-type".to_string(), "application/grpc".to_string()),
            ("vary".to_string(), "Accept-Encoding, Origin".to_string()),
        ]);
        assert!(
            !run_after_proxy_hooks_for_test(&after_proxy_plugins, &mut ctx, 200, &mut headers,)
                .await,
            "response transformer must not reject the backend response"
        );
        for (name, value) in stale_headers {
            assert_eq!(
                headers.get(name).map(String::as_str),
                Some(value),
                "response transformer did not author {name} before replacement"
            );
        }

        set_grpc_deadline_budget_for_test(&mut ctx, Some(0));
        let mut status = 200;
        let mut body = b"discarded backend response".to_vec();
        assert!(
            transform_buffered_response_body_with_deadline_for_test(
                &transform_plugins,
                &mut ctx,
                &mut status,
                &mut headers,
                &mut body,
                grpc_web_content_type,
            )
            .await
        );
        assert_eq!(status, 200);
        assert_eq!(
            headers.get("x-transformer-decoration").map(String::as_str),
            Some("retained"),
            "ordinary provenance-owned decoration must survive"
        );
        assert_eq!(headers.get("vary").map(String::as_str), Some("Origin"));
        for (name, _) in stale_headers {
            assert!(
                !headers.contains_key(name),
                "terminal deadline response retained gateway-authored {name}"
            );
        }
        if let Some(content_type) = grpc_web_content_type {
            assert_eq!(
                headers.get("content-type").map(String::as_str),
                Some(content_type)
            );
            assert_eq!(headers.get("x-grpc-web").map(String::as_str), Some("1"));
            assert!(!headers.contains_key("grpc-status"));
        } else {
            assert_eq!(headers.get("grpc-status").map(String::as_str), Some("4"));
            assert!(body.is_empty());
        }
    }
}

#[tokio::test]
async fn buffered_deadline_uses_private_state_for_multiple_correlation_instances() {
    use ferrum_edge::_test_support::{
        run_after_proxy_hooks_for_test, set_grpc_deadline_budget_for_test,
        transform_buffered_response_body_with_deadline_for_test,
    };

    let default = create_plugin("correlation_id", &json!({}))
        .unwrap()
        .unwrap();
    let custom = create_plugin(
        "correlation_id",
        &json!({ "header_name": "x-custom-request-id" }),
    )
    .unwrap()
    .unwrap();
    let echo_disabled = create_plugin(
        "correlation_id",
        &json!({
            "header_name": "x-disabled-request-id",
            "echo_downstream": false
        }),
    )
    .unwrap()
    .unwrap();
    let unexecuted = create_plugin(
        "correlation_id",
        &json!({ "header_name": "x-unexecuted-request-id" }),
    )
    .unwrap()
    .unwrap();
    let after_proxy_plugins = vec![
        Arc::clone(&default),
        Arc::clone(&custom),
        Arc::clone(&echo_disabled),
        unexecuted,
    ];

    for grpc_web_content_type in [
        None,
        Some("application/grpc-web+proto"),
        Some("application/grpc-web-text+proto"),
    ] {
        let mut ctx = create_grpc_context_with_timeout(None);
        for (name, value) in [
            ("x-request-id", "default-request-id"),
            ("x-custom-request-id", "custom-request-id"),
            ("x-disabled-request-id", "disabled-request-id"),
        ] {
            ctx.headers.insert(name.to_string(), value.to_string());
        }
        for correlation in [&default, &custom, &echo_disabled] {
            assert_continue(correlation.on_request_received(&mut ctx).await);
        }

        // Public metadata is a mutable compatibility projection. Ownership of
        // the exact-value echoes must remain tied to each instance's private
        // request lifecycle state even if another plugin removes that view.
        ctx.metadata.retain(|name, _| {
            name != "request_id" && !name.starts_with("correlation_id.instance.")
        });
        set_grpc_deadline_budget_for_test(&mut ctx, Some(1_000));

        let mut headers = HashMap::from([
            ("content-type".to_string(), "application/grpc".to_string()),
            ("x-request-id".to_string(), "default-request-id".to_string()),
            (
                "x-custom-request-id".to_string(),
                "custom-request-id".to_string(),
            ),
            (
                "x-disabled-request-id".to_string(),
                "disabled-request-id".to_string(),
            ),
            (
                "x-unexecuted-request-id".to_string(),
                "unexecuted-request-id".to_string(),
            ),
        ]);
        assert!(
            !run_after_proxy_hooks_for_test(&after_proxy_plugins, &mut ctx, 200, &mut headers)
                .await
        );
        set_grpc_deadline_budget_for_test(&mut ctx, Some(0));
        let mut status = 200;
        let mut body = b"discarded backend response".to_vec();
        let transform_plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(StalledResponseTransformer)];

        assert!(
            transform_buffered_response_body_with_deadline_for_test(
                &transform_plugins,
                &mut ctx,
                &mut status,
                &mut headers,
                &mut body,
                grpc_web_content_type,
            )
            .await
        );
        assert_eq!(status, 200);
        assert_eq!(
            headers.get("x-request-id").map(String::as_str),
            Some("default-request-id")
        );
        assert_eq!(
            headers.get("x-custom-request-id").map(String::as_str),
            Some("custom-request-id")
        );
        assert!(!headers.contains_key("x-disabled-request-id"));
        assert!(!headers.contains_key("x-unexecuted-request-id"));
        if let Some(content_type) = grpc_web_content_type {
            assert_eq!(
                headers.get("content-type").map(String::as_str),
                Some(content_type)
            );
            assert_eq!(headers.get("x-grpc-web").map(String::as_str), Some("1"));
            assert!(!headers.contains_key("grpc-status"));
        } else {
            assert_eq!(headers.get("grpc-status").map(String::as_str), Some("4"));
            assert!(body.is_empty());
        }
    }
}

#[tokio::test]
async fn response_normalizer_deadline_replaces_buffered_grpc_response() {
    use ferrum_edge::_test_support::{
        run_after_proxy_hooks_for_test, set_grpc_deadline_budget_for_test,
    };

    let deadline_plugin = create_plugin("grpc_deadline", &json!({ "default_deadline_ms": 1_000 }))
        .unwrap()
        .unwrap();
    let correlation_plugin = create_plugin(
        "correlation_id",
        &json!({ "header_name": "x-correlation-id" }),
    )
    .unwrap()
    .unwrap();
    let plugins: Vec<Arc<dyn Plugin>> = vec![
        Arc::clone(&deadline_plugin),
        Arc::clone(&correlation_plugin),
        Arc::new(StalledResponseNormalizer),
    ];
    let mut ctx = create_grpc_context_with_timeout(None);
    ctx.headers
        .insert("x-correlation-id".to_string(), "request-123".to_string());
    assert_continue(correlation_plugin.on_request_received(&mut ctx).await);
    assert_continue(
        ferrum_edge::plugins::grpc_deadline::prepare_request_deadline(&plugins, &mut ctx),
    );
    let mut headers = HashMap::from([
        ("content-type".to_string(), "application/json".to_string()),
        ("x-correlation-id".to_string(), "backend-spoof".to_string()),
    ]);
    assert!(
        !run_after_proxy_hooks_for_test(&plugins, &mut ctx, 200, &mut headers).await,
        "correlation decoration must not reject the backend response"
    );
    set_grpc_deadline_budget_for_test(&mut ctx, Some(0));
    let mut body = b"backend response".to_vec();

    let normalized = normalize_response_body_for_inspection(
        &plugins,
        &mut ctx,
        200,
        &mut headers,
        &mut body,
        &[],
    )
    .await;

    assert!(normalized);
    assert_eq!(
        headers.get("x-correlation-id").map(String::as_str),
        Some("request-123")
    );
    assert_eq!(headers.get("grpc-status").map(String::as_str), Some("4"));
    assert_eq!(
        headers.get("grpc-message").map(String::as_str),
        Some("Deadline exceeded at gateway")
    );
    assert!(body.is_empty());
    assert_eq!(
        ctx.metadata.get("grpc_status").map(String::as_str),
        Some("4")
    );
}

#[tokio::test]
async fn response_normalizer_deadline_preserves_grpc_web_framing() {
    use base64::Engine as _;
    use ferrum_edge::_test_support::{
        GRPC_FRAME_TRAILER, parse_grpc_frames, run_after_proxy_hooks_for_test,
        set_grpc_deadline_budget_for_test,
    };

    for content_type in [
        "application/grpc-web+proto",
        "application/grpc-web-text+proto",
    ] {
        let deadline_plugin =
            create_plugin("grpc_deadline", &json!({ "default_deadline_ms": 1_000 }))
                .unwrap()
                .unwrap();
        let grpc_web_plugin = create_plugin("grpc_web", &json!({})).unwrap().unwrap();
        let plugins: Vec<Arc<dyn Plugin>> = vec![
            Arc::clone(&deadline_plugin),
            Arc::new(TrustedResponseHeaderDecorator {
                headers: HashMap::from([(
                    "access-control-allow-origin".to_string(),
                    "https://browser.example".to_string(),
                )]),
            }),
            Arc::new(StalledResponseNormalizer),
        ];
        let mut ctx = create_grpc_context_with_timeout(None);
        ctx.headers
            .insert("content-type".to_string(), content_type.to_string());
        assert_continue(grpc_web_plugin.on_request_received(&mut ctx).await);
        assert_continue(
            ferrum_edge::plugins::grpc_deadline::prepare_request_deadline(
                &[deadline_plugin],
                &mut ctx,
            ),
        );
        let mut headers = HashMap::from([
            ("content-type".to_string(), "application/grpc".to_string()),
            (
                "access-control-allow-origin".to_string(),
                "https://backend-spoof.example".to_string(),
            ),
        ]);
        assert!(
            !run_after_proxy_hooks_for_test(&plugins, &mut ctx, 200, &mut headers).await,
            "trusted response decoration must not reject"
        );
        set_grpc_deadline_budget_for_test(&mut ctx, Some(0));
        let mut body = b"backend response".to_vec();

        assert!(
            normalize_response_body_for_inspection(
                &plugins,
                &mut ctx,
                200,
                &mut headers,
                &mut body,
                &[],
            )
            .await
        );
        assert_eq!(
            headers.get("content-type").map(String::as_str),
            Some(content_type)
        );
        assert_eq!(headers.get("x-grpc-web").map(String::as_str), Some("1"));
        assert_eq!(
            headers
                .get("access-control-allow-origin")
                .map(String::as_str),
            Some("https://browser.example")
        );
        assert!(headers.contains_key("access-control-expose-headers"));
        assert!(!headers.contains_key("grpc-status"));
        assert!(!headers.contains_key("grpc-message"));
        let expected_length = body.len().to_string();
        assert_eq!(headers.get("content-length"), Some(&expected_length));

        let decoded = if content_type.contains("-text") {
            base64::engine::general_purpose::STANDARD
                .decode(&body)
                .expect("text gRPC-Web deadline body must be base64")
        } else {
            body
        };
        let frames = parse_grpc_frames(&decoded);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].0, GRPC_FRAME_TRAILER);
        assert!(
            frames[0]
                .1
                .windows(b"grpc-status: 4".len())
                .any(|window| window == b"grpc-status: 4")
        );
    }
}

// ── Plugin creation ──

#[test]
fn test_plugin_creation() {
    let config = json!({
        "max_deadline_ms": 30000
    });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();
    assert_eq!(plugin.name(), "grpc_deadline");
    assert_eq!(plugin.priority(), priority::GRPC_DEADLINE);
    assert!(plugin.defer_before_proxy_until_backend_path_resolved());
}

#[test]
fn test_in_available_plugins() {
    let plugins = ferrum_edge::plugins::available_plugins();
    assert!(plugins.contains(&"grpc_deadline"));
}

#[test]
fn test_supported_protocols() {
    let config = json!({ "max_deadline_ms": 30000 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();
    assert_eq!(plugin.supported_protocols(), GRPC_ONLY_PROTOCOLS);
}

#[test]
fn test_modifies_request_headers() {
    let config = json!({ "max_deadline_ms": 30000 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();
    assert!(plugin.modifies_request_headers());
}

// ── Constructor validation ─────────────────────────────────────────

#[test]
fn test_non_object_config_rejected() {
    let err = create_plugin("grpc_deadline", &json!("bad"))
        .err()
        .expect("non-object config should be rejected");
    assert!(err.contains("config must be an object"), "got: {err}");
}

#[test]
fn test_empty_config_rejected() {
    // Plugin with no rules would be a no-op — must be rejected per CLAUDE.md
    let err = create_plugin("grpc_deadline", &json!({}))
        .err()
        .expect("empty config should be rejected");
    assert!(err.contains("no rules configured"), "got: {err}");
}

#[test]
fn test_invalid_field_types_rejected() {
    for (config, expected) in [
        (
            json!({ "max_deadline_ms": "30000" }),
            "'max_deadline_ms' must be an unsigned integer",
        ),
        (
            json!({ "default_deadline_ms": -1 }),
            "'default_deadline_ms' must be an unsigned integer",
        ),
        (
            json!({ "subtract_gateway_processing": "true" }),
            "'subtract_gateway_processing' must be a boolean",
        ),
        (
            json!({ "reject_no_deadline": 1 }),
            "'reject_no_deadline' must be a boolean",
        ),
    ] {
        let err = create_plugin("grpc_deadline", &config)
            .err()
            .expect("invalid field shape should be rejected");
        assert!(err.contains(expected), "expected {expected}, got: {err}");
    }
}

#[test]
fn test_unknown_and_null_fields_are_rejected() {
    for (config, expected) in [
        (
            json!({"max_deadline_ms": 30000, "reject_no_deadine": true}),
            "config.reject_no_deadine",
        ),
        (json!({"MAX_DEADLINE_MS": 30000}), "config.MAX_DEADLINE_MS"),
        (
            json!({"max_deadline_ms": null}),
            "must be an unsigned integer",
        ),
        (json!({"reject_no_deadline": null}), "must be a boolean"),
        (
            json!({"max_deadline_ms": 30000, "unexpected": {"nested": true}}),
            "config.unexpected",
        ),
    ] {
        let error = create_plugin("grpc_deadline", &config)
            .err()
            .expect("strict grpc_deadline config should reject the fixture");
        assert!(error.contains(expected), "expected {expected}, got {error}");
    }
}

#[test]
fn test_zero_max_deadline_rejected() {
    let err = create_plugin("grpc_deadline", &json!({ "max_deadline_ms": 0 }))
        .err()
        .expect("max_deadline_ms=0 should be rejected");
    assert!(err.contains("greater than zero"), "got: {err}");
}

#[test]
fn test_zero_default_deadline_rejected() {
    let err = create_plugin("grpc_deadline", &json!({ "default_deadline_ms": 0 }))
        .err()
        .expect("default_deadline_ms=0 should be rejected");
    assert!(err.contains("greater than zero"), "got: {err}");
}

#[test]
fn test_default_exceeds_max_rejected() {
    let err = create_plugin(
        "grpc_deadline",
        &json!({ "default_deadline_ms": 60000, "max_deadline_ms": 5000 }),
    )
    .err()
    .expect("default exceeding max should be rejected");
    assert!(err.contains("cannot exceed"), "got: {err}");
}

// Each of the four rule fields is a legitimate standalone config:
//   - `max_deadline_ms`: caps incoming deadlines
//   - `default_deadline_ms`: injects a deadline when missing
//   - `reject_no_deadline`: rejects missing-deadline requests
//   - `subtract_gateway_processing`: adjusts existing deadlines by gateway
//     processing time (useful for clients that already send `grpc-timeout`)
#[test]
fn test_subtract_gateway_processing_alone_accepted() {
    // Subtracting gateway processing from client-supplied deadlines is a
    // meaningful rule on its own for deployments where clients reliably send
    // grpc-timeout. Rejecting this config would disable a useful standalone
    // rule.
    let result = create_plugin(
        "grpc_deadline",
        &json!({ "subtract_gateway_processing": true }),
    );
    assert!(result.is_ok(), "subtract_gateway_processing alone is valid");
}

#[test]
fn test_subtract_gateway_processing_with_max_accepted() {
    let result = create_plugin(
        "grpc_deadline",
        &json!({
            "subtract_gateway_processing": true,
            "max_deadline_ms": 30000
        }),
    );
    assert!(result.is_ok());
}

#[test]
fn test_reject_no_deadline_alone_accepted() {
    let result = create_plugin("grpc_deadline", &json!({ "reject_no_deadline": true }));
    assert!(result.is_ok());
}

#[test]
fn test_false_only_rules_are_rejected_as_noop() {
    let error = create_plugin(
        "grpc_deadline",
        &json!({
            "subtract_gateway_processing": false,
            "reject_no_deadline": false
        }),
    )
    .err()
    .expect("false-only rules are a no-op");
    assert!(error.contains("no rules configured"), "got: {error}");
}

// ── grpc-timeout parsing ──

#[tokio::test]
async fn test_parse_hours() {
    let config = json!({ "max_deadline_ms": 999999999 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(Some("2H"));
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "2H".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    // 2 hours = 7,200,000 ms
    assert_eq!(
        ctx.metadata.get("grpc_original_deadline_ms").unwrap(),
        "7200000"
    );
    assert_eq!(headers.get("grpc-timeout").unwrap(), "7200000m");
}

#[tokio::test]
async fn test_parse_minutes() {
    let config = json!({ "max_deadline_ms": 999999999 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(Some("5M"));
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "5M".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    assert_eq!(
        ctx.metadata.get("grpc_original_deadline_ms").unwrap(),
        "300000"
    );
}

#[tokio::test]
async fn test_parse_seconds() {
    let config = json!({ "max_deadline_ms": 999999999 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(Some("30S"));
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "30S".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    assert_eq!(
        ctx.metadata.get("grpc_original_deadline_ms").unwrap(),
        "30000"
    );
}

#[tokio::test]
async fn test_parse_milliseconds() {
    let config = json!({ "max_deadline_ms": 999999999 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(Some("5000m"));
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "5000m".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    assert_eq!(
        ctx.metadata.get("grpc_original_deadline_ms").unwrap(),
        "5000"
    );
    assert_eq!(headers.get("grpc-timeout").unwrap(), "5000m");
}

#[tokio::test]
async fn test_parse_microseconds() {
    let config = json!({ "max_deadline_ms": 999999999 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(Some("5000000u"));
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "5000000u".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    // 5,000,000 us = 5,000 ms
    assert_eq!(
        ctx.metadata.get("grpc_original_deadline_ms").unwrap(),
        "5000"
    );
}

#[tokio::test]
async fn test_parse_nanoseconds() {
    let config = json!({ "max_deadline_ms": 999999999 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(Some("10000000n"));
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "10000000n".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    // 10,000,000 ns = 10 ms
    assert_eq!(ctx.metadata.get("grpc_original_deadline_ms").unwrap(), "10");
}

#[tokio::test]
async fn test_zero_timeouts_are_missing_and_positive_submillisecond_rounds_up() {
    let plugin = create_plugin("grpc_deadline", &json!({"reject_no_deadline": true}))
        .unwrap()
        .unwrap();

    for timeout in ["0H", "0M", "0S", "0m", "0u", "0n"] {
        let mut ctx = create_grpc_context_with_timeout(Some(timeout));
        let mut headers = HashMap::from([("grpc-timeout".to_string(), timeout.to_string())]);
        assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
    }

    for timeout in ["1u", "1n"] {
        let mut ctx = create_grpc_context_with_timeout(Some(timeout));
        let mut headers = HashMap::from([("grpc-timeout".to_string(), timeout.to_string())]);
        assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
        assert_eq!(headers.get("grpc-timeout").unwrap(), "1m");
        assert_eq!(ctx.metadata.get("grpc_original_deadline_ms").unwrap(), "1");
    }
}

#[tokio::test]
async fn test_timeout_header_matching_is_case_insensitive_and_rewrites_canonically() {
    let plugin = create_plugin("grpc_deadline", &json!({"max_deadline_ms": 5000}))
        .unwrap()
        .unwrap();
    let mut ctx = create_test_context();
    let mut headers = HashMap::from([("Grpc-Timeout".to_string(), "10S".to_string())]);

    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(
        headers.get("grpc-timeout").map(String::as_str),
        Some("5000m")
    );
    assert_eq!(
        headers
            .keys()
            .filter(|name| name.eq_ignore_ascii_case("grpc-timeout"))
            .count(),
        1
    );
}

#[tokio::test]
async fn test_multiple_instances_share_one_absolute_deadline() {
    let first = create_plugin(
        "grpc_deadline",
        &json!({"subtract_gateway_processing": true}),
    )
    .unwrap()
    .unwrap();
    let second = create_plugin("grpc_deadline", &json!({"max_deadline_ms": 10000}))
        .unwrap()
        .unwrap();
    let plugins = vec![first, second];
    let mut ctx = create_grpc_context_with_timeout(Some("10S"));
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    assert_continue(
        ferrum_edge::plugins::grpc_deadline::prepare_request_deadline(&plugins, &mut ctx),
    );
    let absolute = ctx
        .grpc_deadline_at()
        .expect("valid timeout establishes an absolute deadline");
    let mut headers = HashMap::from([("grpc-timeout".to_string(), "10S".to_string())]);
    assert_continue(plugins[0].before_proxy(&mut ctx, &mut headers).await);
    let first_forwarded: u64 = headers["grpc-timeout"]
        .strip_suffix('m')
        .expect("millisecond timeout")
        .parse()
        .expect("numeric timeout");
    assert_continue(plugins[1].before_proxy(&mut ctx, &mut headers).await);
    let second_forwarded: u64 = headers["grpc-timeout"]
        .strip_suffix('m')
        .expect("millisecond timeout")
        .parse()
        .expect("numeric timeout");

    assert_eq!(ctx.grpc_deadline_at(), Some(absolute));
    assert!((5_000..=10_000).contains(&first_forwarded));
    assert!(
        second_forwarded <= first_forwarded && first_forwarded - second_forwarded <= 50,
        "a later instance may observe clock progress but must not deduct the original pre-plugin delay again: first={first_forwarded}, second={second_forwarded}"
    );
}

#[test]
fn test_composed_reject_no_deadline_checks_original_header_before_default() {
    let default = create_plugin("grpc_deadline", &json!({"default_deadline_ms": 5000}))
        .unwrap()
        .unwrap();
    let required = create_plugin("grpc_deadline", &json!({"reject_no_deadline": true}))
        .unwrap()
        .unwrap();
    let plugins = vec![default, required];

    for timeout in [None, Some("0m"), Some("invalid")] {
        let mut ctx = create_grpc_context_with_timeout(timeout);
        assert_reject(
            ferrum_edge::plugins::grpc_deadline::prepare_request_deadline(&plugins, &mut ctx),
            Some(400),
        );
    }

    let mut ctx = create_grpc_context_with_timeout(Some("2S"));
    assert_continue(
        ferrum_edge::plugins::grpc_deadline::prepare_request_deadline(&plugins, &mut ctx),
    );
}

#[tokio::test]
async fn test_preflight_deadline_cancels_request_plugin_work_with_status_four() {
    let plugin = create_plugin("grpc_deadline", &json!({"default_deadline_ms": 1}))
        .unwrap()
        .unwrap();
    let plugins = vec![plugin];
    let mut ctx = create_grpc_context_with_timeout(None);
    assert_continue(
        ferrum_edge::plugins::grpc_deadline::prepare_request_deadline(&plugins, &mut ctx),
    );
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    let result = ferrum_edge::_test_support::await_request_plugin_deadline_for_test(
        ctx.grpc_deadline_at(),
        std::future::pending(),
    )
    .await;
    match result {
        PluginResult::Reject {
            status_code,
            headers,
            ..
        } => {
            assert_eq!(status_code, 200);
            assert_eq!(headers.get("grpc-status").map(String::as_str), Some("4"));
        }
        other => panic!("expired preflight must cancel plugin work: {other:?}"),
    }
}

// ── Default deadline injection ──

#[tokio::test]
async fn test_default_deadline_injected_when_missing() {
    let config = json!({ "default_deadline_ms": 5000 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(None);
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    assert_eq!(headers.get("grpc-timeout").unwrap(), "5000m");
    assert_eq!(
        ctx.metadata.get("grpc_adjusted_deadline_ms").unwrap(),
        "5000"
    );
}

#[tokio::test]
async fn test_default_deadline_not_used_when_present() {
    let config = json!({
        "default_deadline_ms": 5000,
        "max_deadline_ms": 999999999
    });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(Some("10000m"));
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "10000m".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    // Should use the client's timeout, not the default
    assert_eq!(
        ctx.metadata.get("grpc_adjusted_deadline_ms").unwrap(),
        "10000"
    );
}

// ── Max deadline capping ──

#[tokio::test]
async fn test_max_deadline_caps_high_timeout() {
    let config = json!({ "max_deadline_ms": 30000 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(Some("60S")); // 60,000 ms
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "60S".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    // Should be capped to 30,000 ms
    assert_eq!(
        ctx.metadata.get("grpc_adjusted_deadline_ms").unwrap(),
        "30000"
    );
    assert_eq!(headers.get("grpc-timeout").unwrap(), "30000m");
}

#[tokio::test]
async fn test_max_deadline_does_not_increase_low_timeout() {
    let config = json!({ "max_deadline_ms": 30000 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(Some("5000m")); // 5,000 ms
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "5000m".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    // Should stay at 5,000 ms (under the cap)
    assert_eq!(
        ctx.metadata.get("grpc_adjusted_deadline_ms").unwrap(),
        "5000"
    );
}

// ── reject_no_deadline ──

#[tokio::test]
async fn test_reject_no_deadline_rejects_missing() {
    let config = json!({ "reject_no_deadline": true });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(None);
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

#[tokio::test]
async fn test_reject_no_deadline_allows_present() {
    let config = json!({
        "reject_no_deadline": true,
        "max_deadline_ms": 999999999
    });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(Some("5000m"));
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "5000m".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

// ── subtract_gateway_processing ──

#[tokio::test]
async fn test_subtract_gateway_processing() {
    let config = json!({
        "default_deadline_ms": 60000,
        "subtract_gateway_processing": true
    });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(None);
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    // The adjusted deadline should be <= default_deadline_ms (some processing time subtracted)
    let adjusted: u64 = ctx
        .metadata
        .get("grpc_adjusted_deadline_ms")
        .unwrap()
        .parse()
        .unwrap();
    assert!(adjusted <= 60000);
    assert!(adjusted > 0);
}

#[tokio::test]
async fn test_subtract_gateway_processing_deadline_exceeded() {
    let config = json!({
        "default_deadline_ms": 1,
        "subtract_gateway_processing": true
    });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(None);
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;

    // The 1ms receipt-anchored deadline elapsed before the hook ran.
    match result {
        PluginResult::Reject {
            status_code,
            headers,
            ..
        } => {
            assert_eq!(status_code, 200); // gRPC trailers-only response
            assert_eq!(headers.get("grpc-status").unwrap(), "4"); // DEADLINE_EXCEEDED
            assert!(headers.contains_key("grpc-message"));
        }
        _ => panic!("Expected Reject with DEADLINE_EXCEEDED"),
    }
}

// ── Combined config ──

#[tokio::test]
async fn test_combined_default_and_max() {
    // default == max: default applies, no cap needed
    let config = json!({
        "default_deadline_ms": 30000,
        "max_deadline_ms": 30000
    });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    // No timeout provided: default (30000) gets used; cap is identical so no change
    let mut ctx = create_grpc_context_with_timeout(None);
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    assert_eq!(
        ctx.metadata.get("grpc_adjusted_deadline_ms").unwrap(),
        "30000"
    );

    // A larger client-supplied timeout still gets capped
    let mut ctx2 = create_grpc_context_with_timeout(Some("60S"));
    let mut headers2 = HashMap::new();
    headers2.insert("grpc-timeout".to_string(), "60S".to_string());
    plugin.before_proxy(&mut ctx2, &mut headers2).await;
    assert_eq!(
        ctx2.metadata.get("grpc_adjusted_deadline_ms").unwrap(),
        "30000"
    );
}

// ── Empty config passes through ──

#[tokio::test]
async fn test_minimal_config_passes_through() {
    // With max_deadline_ms set, but client timeout below cap, the value passes through.
    let config = json!({ "max_deadline_ms": 999_999_999 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(Some("5000m"));
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "5000m".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    // Should still set the header (pass through the parsed value)
    assert_eq!(headers.get("grpc-timeout").unwrap(), "5000m");
}

#[tokio::test]
async fn test_modified_timeout_header_takes_precedence_over_original_request() {
    let config = json!({ "max_deadline_ms": 999999999 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(Some("60S"));
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "60S".to_string());
    headers.insert("grpc-timeout".to_string(), "5000m".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    assert_eq!(
        ctx.metadata.get("grpc_original_deadline_ms").unwrap(),
        "5000"
    );
    assert_eq!(headers.get("grpc-timeout").unwrap(), "5000m");
}

#[tokio::test]
async fn test_minimal_config_no_timeout_passes() {
    // With only max_deadline_ms, a request with no timeout passes through unchanged
    // (no default to inject, no rejection rule).
    let config = json!({ "max_deadline_ms": 30_000 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(None);
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    // No timeout to set
    assert!(!headers.contains_key("grpc-timeout"));
}

// ── Invalid timeout header ──

#[tokio::test]
async fn test_invalid_timeout_treated_as_missing() {
    let config = json!({ "default_deadline_ms": 5000 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(Some("invalid"));
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "invalid".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    // Should fall back to default
    assert_eq!(
        ctx.metadata.get("grpc_adjusted_deadline_ms").unwrap(),
        "5000"
    );
}

// ── Rejection body format ──

#[tokio::test]
async fn test_reject_no_deadline_body_format() {
    let config = json!({ "reject_no_deadline": true });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(None);
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;

    match result {
        PluginResult::Reject {
            status_code,
            body,
            headers,
        } => {
            assert_eq!(status_code, 400);
            let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert!(parsed.get("error").is_some());
            assert_eq!(headers.get("content-type").unwrap(), "application/grpc");
        }
        _ => panic!("Expected Reject"),
    }
}

// ── reject_no_deadline takes precedence over default_deadline_ms ──

#[tokio::test]
async fn test_reject_no_deadline_wins_over_default() {
    let config = json!({
        "reject_no_deadline": true,
        "default_deadline_ms": 5000
    });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(None);
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;

    // Should reject despite default being configured — reject_no_deadline takes precedence
    assert_reject(result, Some(400));
}

// ── Empty string timeout ──

#[tokio::test]
async fn test_empty_string_timeout_treated_as_missing() {
    let config = json!({ "default_deadline_ms": 3000 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(Some(""));
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    // Empty string can't be parsed, falls back to default
    assert_eq!(
        ctx.metadata.get("grpc_adjusted_deadline_ms").unwrap(),
        "3000"
    );
}

// ── Very large timeout values (overflow protection) ──

#[tokio::test]
async fn test_more_than_eight_timeout_digits_is_ignored_without_default() {
    let config = json!({ "max_deadline_ms": 999999999 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(Some("999999999H"));
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "999999999H".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    assert!(!ctx.metadata.contains_key("grpc_original_deadline_ms"));
    assert!(!ctx.metadata.contains_key("grpc_adjusted_deadline_ms"));
    assert_eq!(headers.get("grpc-timeout").unwrap(), "999999999H");
}

// ── subtract_gateway_processing + max_deadline_ms combined ──

#[tokio::test]
async fn test_subtract_after_max_cap() {
    let config = json!({
        "max_deadline_ms": 5000,
        "subtract_gateway_processing": true
    });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    // Client sends 60s, capped to 5s, then processing time subtracted
    let mut ctx = create_grpc_context_with_timeout(Some("60S"));
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "60S".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    let adjusted: u64 = ctx
        .metadata
        .get("grpc_adjusted_deadline_ms")
        .unwrap()
        .parse()
        .unwrap();
    // Should be capped to 5000 then subtracted — must be <= 5000
    assert!(adjusted <= 5000);
    assert!(adjusted > 0);
}

// ── Single-character unit only (no multi-char units) ──

#[tokio::test]
async fn test_multi_char_unit_rejected() {
    let config = json!({ "default_deadline_ms": 1000 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    // "ms" is not a valid gRPC timeout unit — only single-char units
    let mut ctx = create_grpc_context_with_timeout(Some("5000ms"));
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "5000ms".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    // "5000ms" fails to parse (last char 's', digits "5000m" fails u64 parse)
    // Falls back to default
    assert_eq!(
        ctx.metadata.get("grpc_adjusted_deadline_ms").unwrap(),
        "1000"
    );
}

// ── Robustness against malformed inputs ──

#[tokio::test]
async fn test_non_ascii_timeout_does_not_panic() {
    // Previously the parser used str::split_at(len-1) which panics on a
    // non-char-boundary. Multi-byte UTF-8 in the timeout must be rejected
    // (treated as missing) rather than crashing the worker.
    let config = json!({ "default_deadline_ms": 1000 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(Some("5η"));
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "5η".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    // Malformed value falls back to default
    assert_eq!(
        ctx.metadata.get("grpc_adjusted_deadline_ms").unwrap(),
        "1000"
    );
}

#[tokio::test]
async fn test_non_digit_value_treated_as_missing() {
    let config = json!({ "default_deadline_ms": 2000 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(Some("abcS"));
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "abcS".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    assert_eq!(
        ctx.metadata.get("grpc_adjusted_deadline_ms").unwrap(),
        "2000"
    );
}

// ── Metadata tracking ──

#[tokio::test]
async fn test_original_and_adjusted_metadata() {
    let config = json!({ "max_deadline_ms": 10000 });
    let plugin = create_plugin("grpc_deadline", &config).unwrap().unwrap();

    let mut ctx = create_grpc_context_with_timeout(Some("30S")); // 30,000 ms
    let mut headers = HashMap::new();
    headers.insert("grpc-timeout".to_string(), "30S".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    assert_eq!(
        ctx.metadata.get("grpc_original_deadline_ms").unwrap(),
        "30000"
    );
    assert_eq!(
        ctx.metadata.get("grpc_adjusted_deadline_ms").unwrap(),
        "10000"
    );
}
