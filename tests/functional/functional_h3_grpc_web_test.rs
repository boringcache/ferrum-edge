//! End-to-end regressions for HTTP/3 gRPC-Web request classification.
//!
//! The shared wire classifier intentionally leaves `application/grpc-web*`
//! as plain HTTP so the grpc_web plugin owns body translation. The H3 server
//! must nevertheless promote the request to effective gRPC for method policy,
//! early reject shaping, and plugin selection. Backend transport is promoted
//! only after the grpc_web plugin stamps its trusted translation marker;
//! plugin-free deployments retain their original pass-through transport.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use bytes::Bytes;
use http::{Method, StatusCode};
use serde_json::{Value, json};
use tokio::net::TcpListener;

use crate::scaffolding::backends::{
    GrpcStep, MatchRpc, ScriptedGrpcBackend, ScriptedTlsBackend, TcpStep, TlsConfig,
};
use crate::scaffolding::certs::TestCa;
use crate::scaffolding::clients::{GetOptions, Http3Client, Http3Response};
use crate::scaffolding::harness::GatewayHarness;
use crate::scaffolding::ports::{reserve_port, unbound_port};

fn grpc_frame(message: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(message.len() + 5);
    framed.push(0);
    framed.extend_from_slice(&(message.len() as u32).to_be_bytes());
    framed.extend_from_slice(message);
    framed
}

fn grpc_web_frames(body: &[u8]) -> Vec<(u8, &[u8])> {
    let mut frames = Vec::new();
    let mut remaining = body;
    while remaining.len() >= 5 {
        let flag = remaining[0];
        let len =
            u32::from_be_bytes([remaining[1], remaining[2], remaining[3], remaining[4]]) as usize;
        if remaining.len() < 5 + len {
            break;
        }
        frames.push((flag, &remaining[5..5 + len]));
        remaining = &remaining[5 + len..];
    }
    frames
}

fn assert_grpc_web_error(response: &Http3Response, grpc_status: &str, expected_content_type: &str) {
    assert_eq!(
        response.status,
        StatusCode::OK,
        "gRPC-Web errors ride HTTP 200"
    );
    assert_eq!(
        response
            .headers
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some(expected_content_type)
    );
    assert!(
        response.body_error.is_none(),
        "unexpected H3 body error: {:?}",
        response.body_error
    );
    assert!(
        response.trailers.is_none(),
        "gRPC-Web must not emit native H3 trailers"
    );
    assert!(
        !response.headers.contains_key("grpc-status")
            && !response.headers.contains_key("grpc-message"),
        "terminal gRPC-Web metadata must remain in the body trailer frame"
    );
    let decoded_body;
    let wire_body = if expected_content_type.starts_with("application/grpc-web-text") {
        decoded_body = BASE64
            .decode(&response.body_bytes)
            .expect("decode gRPC-Web text response");
        decoded_body.as_slice()
    } else {
        response.body_bytes.as_ref()
    };
    let trailer_payload = grpc_web_frames(wire_body)
        .into_iter()
        .find_map(|(flag, payload)| (flag == 0x80).then_some(payload))
        .unwrap_or_else(|| {
            panic!(
                "missing gRPC-Web trailer frame in {:?}",
                response.body_bytes
            )
        });
    let trailer_text = String::from_utf8_lossy(trailer_payload);
    assert!(
        trailer_text.contains(&format!("grpc-status: {grpc_status}\r\n")),
        "unexpected gRPC-Web trailer payload: {trailer_text}"
    );
}

fn write_frontend_certs(scratch: &std::path::Path) -> (String, String) {
    let ca = TestCa::new("h3-grpc-web-gateway").expect("gateway CA");
    let (cert, key) = ca.valid().expect("gateway leaf");
    let cert_path = scratch.join("gateway.cert.pem");
    let key_path = scratch.join("gateway.key.pem");
    std::fs::write(&cert_path, cert).expect("write gateway cert");
    std::fs::write(&key_path, key).expect("write gateway key");
    (
        cert_path.to_string_lossy().into_owned(),
        key_path.to_string_lossy().into_owned(),
    )
}

async fn spawn_h3_gateway(config: Value) -> (GatewayHarness, u16, tempfile::TempDir) {
    let yaml = serde_yaml::to_string(&config).expect("serialize H3 gRPC-Web config");
    let mut last_error = String::new();
    for _ in 0..5 {
        let reservation = reserve_port().await.expect("reserve H3 listener port");
        let https_port = reservation.port;
        drop(reservation);

        let scratch = tempfile::tempdir().expect("gateway scratch dir");
        let (cert_path, key_path) = write_frontend_certs(scratch.path());
        match GatewayHarness::builder()
            .file_config(yaml.clone())
            .log_level("warn")
            .capture_output()
            .max_attempts(1)
            .env("FERRUM_ENABLE_HTTP3", "true")
            .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
            .env("FERRUM_FRONTEND_TLS_CERT_PATH", cert_path)
            .env("FERRUM_FRONTEND_TLS_KEY_PATH", key_path)
            .env("FERRUM_TLS_NO_VERIFY", "true")
            .env("FERRUM_POOL_WARMUP_ENABLED", "false")
            .spawn()
            .await
        {
            Ok(harness) => return (harness, https_port, scratch),
            Err(error) => last_error = error.to_string(),
        }
    }
    panic!("failed to spawn H3 gRPC-Web gateway after retries: {last_error}");
}

async fn request_with_retry(client: &Http3Client, url: &str, options: GetOptions) -> Http3Response {
    request_with_retry_and_attempts(client, url, options).await.0
}

async fn request_with_retry_and_attempts(
    client: &Http3Client,
    url: &str,
    options: GetOptions,
) -> (Http3Response, u32) {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut attempts = 0_u32;
    loop {
        attempts += 1;
        match client.get_with_options(url, options.clone()).await {
            Ok(response) => return (response, attempts),
            Err(error) if Instant::now() < deadline => {
                let _ = error;
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
            Err(error) => panic!("H3 request never completed: {error}"),
        }
    }
}

fn reject_config(backend_port: u16) -> Value {
    let proxy = |id: &str, path: &str, plugin_ids: &[&str]| {
        json!({
            "id": id,
            "listen_path": path,
            "backend_scheme": "https",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": true,
            "backend_connect_timeout_ms": 500,
            "backend_read_timeout_ms": 1000,
            "backend_write_timeout_ms": 1000,
            "backend_tls_verify_server_cert": false,
            "plugins": plugin_ids
                .iter()
                .map(|plugin_config_id| json!({"plugin_config_id": plugin_config_id}))
                .collect::<Vec<_>>(),
        })
    };
    json!({
        "version": "1",
        "proxies": [
            proxy(
                "h3-grpc-web-received",
                "/received",
                &["grpc-web-received", "grpc-web-cors", "received-reject"],
            ),
            proxy(
                "h3-grpc-web-authenticate",
                "/authenticate",
                &["grpc-web-authenticate", "authenticate-reject"],
            ),
            proxy(
                "h3-grpc-web-authorize",
                "/authorize",
                &["grpc-web-authorize", "authorize-reject"],
            ),
            proxy(
                "h3-grpc-web-method-before-deadline",
                "/method-policy",
                &[
                    "grpc-web-method-policy",
                    "grpc-method-policy",
                    "grpc-method-deadline",
                ],
            ),
            proxy(
                "h3-grpc-web-deadline-only",
                "/deadline-only",
                &["grpc-web-deadline-only", "grpc-deadline-only"],
            ),
        ],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [
            {
                "id": "grpc-web-received",
                "plugin_name": "grpc_web",
                "scope": "proxy",
                "proxy_id": "h3-grpc-web-received",
                "enabled": true,
                "config": {},
            },
            {
                "id": "grpc-web-cors",
                "plugin_name": "cors",
                "scope": "proxy",
                "proxy_id": "h3-grpc-web-received",
                "enabled": true,
                "config": {"allowed_origins": ["https://app.example"]},
            },
            {
                "id": "received-reject",
                "plugin_name": "request_termination",
                "scope": "proxy",
                "proxy_id": "h3-grpc-web-received",
                "enabled": true,
                "config": {
                    "status_code": 418,
                    "content_type": "application/json",
                    "message": "received phase rejected",
                },
            },
            {
                "id": "grpc-web-authenticate",
                "plugin_name": "grpc_web",
                "scope": "proxy",
                "proxy_id": "h3-grpc-web-authenticate",
                "enabled": true,
                "config": {},
            },
            {
                "id": "authenticate-reject",
                "plugin_name": "basic_auth",
                "scope": "proxy",
                "proxy_id": "h3-grpc-web-authenticate",
                "enabled": true,
                "config": {},
            },
            {
                "id": "grpc-web-authorize",
                "plugin_name": "grpc_web",
                "scope": "proxy",
                "proxy_id": "h3-grpc-web-authorize",
                "enabled": true,
                "config": {},
            },
            {
                "id": "authorize-reject",
                "plugin_name": "access_control",
                "scope": "proxy",
                "proxy_id": "h3-grpc-web-authorize",
                "enabled": true,
                "config": {"allowed_consumers": ["allowed-user"]},
            },
            {
                "id": "grpc-web-method-policy",
                "plugin_name": "grpc_web",
                "scope": "proxy",
                "proxy_id": "h3-grpc-web-method-before-deadline",
                "enabled": true,
                "config": {},
            },
            {
                "id": "grpc-method-policy",
                "plugin_name": "grpc_method_router",
                "scope": "proxy",
                "proxy_id": "h3-grpc-web-method-before-deadline",
                "enabled": true,
                "config": {"deny_methods": ["pkg.Service/Denied"]},
            },
            {
                "id": "grpc-method-deadline",
                "plugin_name": "grpc_deadline",
                "scope": "proxy",
                "proxy_id": "h3-grpc-web-method-before-deadline",
                "enabled": true,
                "config": {"reject_no_deadline": true},
            },
            {
                "id": "grpc-web-deadline-only",
                "plugin_name": "grpc_web",
                "scope": "proxy",
                "proxy_id": "h3-grpc-web-deadline-only",
                "enabled": true,
                "config": {},
            },
            {
                "id": "grpc-deadline-only",
                "plugin_name": "grpc_deadline",
                "scope": "proxy",
                "proxy_id": "h3-grpc-web-deadline-only",
                "enabled": true,
                "config": {"reject_no_deadline": true},
            },
        ],
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_grpc_web_rejects_and_negative_controls_use_client_wire_flavor() {
    let backend_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind reject sentinel backend");
    let backend_port = backend_listener.local_addr().expect("backend addr").port();
    let backend_hits = Arc::new(AtomicUsize::new(0));
    let backend_hits_task = Arc::clone(&backend_hits);
    let backend_task = tokio::spawn(async move {
        while let Ok((stream, _)) = backend_listener.accept().await {
            backend_hits_task.fetch_add(1, Ordering::Relaxed);
            drop(stream);
        }
    });

    let (_gateway, https_port, _scratch) = spawn_h3_gateway(reject_config(backend_port)).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let backend_connections_before_requests = backend_hits.load(Ordering::Relaxed);
    let client = Http3Client::insecure().expect("H3 client");
    let grpc_web = |method| {
        GetOptions::default()
            .method(method)
            .header("content-type", "application/grpc-web+proto")
            .body(Bytes::from(grpc_frame(b"ping")))
    };

    let non_post = request_with_retry(
        &client,
        &format!("https://127.0.0.1:{https_port}/received/echo.Echo/Unary"),
        grpc_web(Method::GET),
    )
    .await;
    assert_grpc_web_error(&non_post, "3", "application/grpc-web+proto");

    let received = request_with_retry(
        &client,
        &format!("https://127.0.0.1:{https_port}/received/echo.Echo/Unary"),
        grpc_web(Method::POST).header("origin", "https://app.example"),
    )
    .await;
    assert_grpc_web_error(&received, "13", "application/grpc-web+proto");
    assert_eq!(
        received
            .headers
            .get("access-control-allow-origin")
            .and_then(|value| value.to_str().ok()),
        Some("https://app.example")
    );

    let disallowed_origin = request_with_retry(
        &client,
        &format!("https://127.0.0.1:{https_port}/received/echo.Echo/Unary"),
        grpc_web(Method::POST).header("origin", "https://blocked.example"),
    )
    .await;
    assert_grpc_web_error(&disallowed_origin, "7", "application/grpc-web+proto");
    assert!(
        !disallowed_origin
            .headers
            .contains_key("access-control-allow-origin")
    );

    let authenticate = request_with_retry(
        &client,
        &format!("https://127.0.0.1:{https_port}/authenticate/echo.Echo/Unary"),
        GetOptions::default()
            .method(Method::POST)
            .header("content-type", "application/grpc-web-text+proto")
            .body(Bytes::from(BASE64.encode(grpc_frame(b"ping")))),
    )
    .await;
    assert_grpc_web_error(&authenticate, "16", "application/grpc-web-text+proto");

    let authorize = request_with_retry(
        &client,
        &format!("https://127.0.0.1:{https_port}/authorize/echo.Echo/Unary"),
        grpc_web(Method::POST),
    )
    .await;
    assert_grpc_web_error(&authorize, "16", "application/grpc-web+proto");

    let method_policy = request_with_retry(
        &client,
        &format!("https://127.0.0.1:{https_port}/method-policy/pkg.Service/Denied"),
        grpc_web(Method::POST).header("grpc-timeout", "5S"),
    )
    .await;
    assert_grpc_web_error(&method_policy, "7", "application/grpc-web+proto");

    let deadline_only = request_with_retry(
        &client,
        &format!("https://127.0.0.1:{https_port}/deadline-only/pkg.Service/Allowed"),
        grpc_web(Method::POST),
    )
    .await;
    assert_grpc_web_error(&deadline_only, "3", "application/grpc-web+proto");

    let native_method_policy = request_with_retry(
        &client,
        &format!("https://127.0.0.1:{https_port}/method-policy/pkg.Service/Denied"),
        GetOptions::default()
            .method(Method::POST)
            .header("content-type", "application/grpc")
            .header("grpc-timeout", "5S")
            .body(Bytes::from(grpc_frame(b"ping"))),
    )
    .await;
    assert_eq!(native_method_policy.status, StatusCode::OK);
    assert_eq!(native_method_policy.grpc_status(), Some(7));
    assert!(native_method_policy.body_bytes.is_empty());
    assert!(native_method_policy.trailers.is_none());

    // Negative control: the same received-phase reject remains ordinary HTTP
    // for an unrelated content type.
    let plain = request_with_retry(
        &client,
        &format!("https://127.0.0.1:{https_port}/received/plain"),
        GetOptions::default().header("content-type", "application/json"),
    )
    .await;
    assert_eq!(plain.status, StatusCode::IM_A_TEAPOT);
    assert_eq!(
        plain
            .headers
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
    assert!(plain.body_text().contains("received phase rejected"));

    // Negative control: native gRPC keeps native trailers-only rejection
    // shaping and never acquires a gRPC-Web body frame.
    let native_grpc = request_with_retry(
        &client,
        &format!("https://127.0.0.1:{https_port}/received/echo.Echo/Unary"),
        GetOptions::default()
            .method(Method::POST)
            .header("content-type", "application/grpc")
            .body(Bytes::from(grpc_frame(b"ping"))),
    )
    .await;
    assert_eq!(native_grpc.status, StatusCode::OK);
    assert_eq!(
        native_grpc
            .headers
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/grpc")
    );
    assert!(native_grpc.body_bytes.is_empty());
    assert_eq!(native_grpc.grpc_status(), Some(13));
    assert!(native_grpc.trailers.is_none());

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        backend_hits.load(Ordering::Relaxed),
        backend_connections_before_requests,
        "method and plugin rejects must not create a backend connection"
    );
    backend_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_grpc_web_without_translation_plugin_keeps_plain_backend_transport() {
    let backend_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind pass-through backend");
    let backend_port = backend_listener.local_addr().expect("backend addr").port();
    let backend_ca = TestCa::new("h3-grpc-web-pass-through").expect("backend CA");
    let (backend_cert, backend_key) = backend_ca.valid().expect("backend leaf");
    let backend = ScriptedTlsBackend::builder(
        backend_listener,
        TlsConfig::new(backend_cert, backend_key).with_alpn(vec![b"http/1.1".to_vec()]),
    )
    .step(TcpStep::ReadUntil(b"\r\n\r\n".to_vec()))
    .step(TcpStep::Write(
        b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 12\r\nconnection: close\r\n\r\npass-through"
            .to_vec(),
    ))
    .step(TcpStep::Drop)
    .spawn()
    .expect("spawn pass-through backend");
    let unavailable_port = unbound_port()
        .await
        .expect("reserve unavailable backend port");

    let config = json!({
        "version": "1",
        "proxies": [
            {
                "id": "h3-grpc-web-pass-through",
                "listen_path": "/pass-through",
                "backend_scheme": "https",
                "backend_host": "127.0.0.1",
                "backend_port": backend_port,
                "strip_listen_path": true,
                "backend_connect_timeout_ms": 2000,
                "backend_read_timeout_ms": 5000,
                "backend_write_timeout_ms": 5000,
                "backend_tls_verify_server_cert": false,
                "plugins": [],
            },
            {
                "id": "h3-grpc-web-pass-through-policy",
                "listen_path": "/denied",
                "backend_scheme": "https",
                "backend_host": "127.0.0.1",
                "backend_port": backend_port,
                "strip_listen_path": true,
                "backend_connect_timeout_ms": 2000,
                "backend_read_timeout_ms": 5000,
                "backend_write_timeout_ms": 5000,
                "backend_tls_verify_server_cert": false,
                "plugins": [{"plugin_config_id": "pass-through-method-policy"}],
            },
            {
                "id": "h3-grpc-web-pass-through-unavailable",
                "listen_path": "/unavailable",
                "backend_scheme": "https",
                "backend_host": "127.0.0.1",
                "backend_port": unavailable_port,
                "strip_listen_path": true,
                "backend_connect_timeout_ms": 500,
                "backend_read_timeout_ms": 1000,
                "backend_write_timeout_ms": 1000,
                "backend_tls_verify_server_cert": false,
                "plugins": [],
            },
        ],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [{
            "id": "pass-through-method-policy",
            "plugin_name": "grpc_method_router",
            "scope": "proxy",
            "proxy_id": "h3-grpc-web-pass-through-policy",
            "enabled": true,
            "config": {"deny_methods": ["echo.Echo/Unary"]},
        }],
    });
    let (_gateway, https_port, _scratch) = spawn_h3_gateway(config).await;
    let client = Http3Client::insecure().expect("H3 client");
    let request = || {
        GetOptions::default()
            .method(Method::POST)
            .header("content-type", "application/grpc-web+proto")
            .body(Bytes::from(grpc_frame(b"ping")))
    };

    let pass_through = request_with_retry(
        &client,
        &format!("https://127.0.0.1:{https_port}/pass-through/echo.Echo/Unary"),
        request(),
    )
    .await;
    assert_eq!(pass_through.status, StatusCode::OK);
    assert_eq!(
        pass_through
            .headers
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("text/plain")
    );
    assert_eq!(pass_through.body_bytes.as_ref(), b"pass-through");
    tokio::time::sleep(Duration::from_millis(100)).await;
    let pass_through_connections = backend.accepted_connections();
    assert!(
        pass_through_connections >= 1,
        "the pass-through request must reach the ordinary HTTP backend"
    );

    let denied = request_with_retry(
        &client,
        &format!("https://127.0.0.1:{https_port}/denied/echo.Echo/Unary"),
        request(),
    )
    .await;
    assert_grpc_web_error(&denied, "7", "application/grpc-web+proto");

    let unavailable = request_with_retry(
        &client,
        &format!("https://127.0.0.1:{https_port}/unavailable/echo.Echo/Unary"),
        request(),
    )
    .await;
    assert_grpc_web_error(&unavailable, "14", "application/grpc-web+proto");

    tokio::time::sleep(Duration::from_millis(100)).await;
    let step_errors = backend.step_errors().await;
    assert!(
        step_errors
            .iter()
            .all(|error| error.contains("peer closed connection without sending TLS close_notify")),
        "unexpected pass-through backend script errors: {step_errors:?}"
    );
    assert_eq!(backend.accepted_connections(), pass_through_connections);
    assert_eq!(backend.handshakes_completed(), pass_through_connections);
    let negotiated_alpn = backend.last_alpn().await;
    assert!(
        negotiated_alpn.is_none() || negotiated_alpn.as_deref() == Some(b"http/1.1".as_slice()),
        "unexpected pass-through backend ALPN: {negotiated_alpn:?}"
    );
    let received = String::from_utf8_lossy(&backend.received_bytes().await).to_ascii_lowercase();
    assert!(received.starts_with("post /echo.echo/unary http/1.1\r\n"));
    assert!(received.contains("content-type: application/grpc-web+proto\r\n"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn streaming_h3_grpc_web_deadline_cancels_withheld_backend_headers() {
    let backend_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind stalled pass-through backend");
    let backend_port = backend_listener.local_addr().expect("backend addr").port();
    let backend_ca = TestCa::new("h3-grpc-web-deadline-stall").expect("backend CA");
    let (backend_cert, backend_key) = backend_ca.valid().expect("backend leaf");
    let backend = ScriptedTlsBackend::builder(
        backend_listener,
        TlsConfig::new(backend_cert, backend_key).with_alpn(vec![b"http/1.1".to_vec()]),
    )
    .step(TcpStep::ReadUntil(b"\r\n\r\n".to_vec()))
    .step(TcpStep::Sleep(Duration::from_secs(10)))
    .step(TcpStep::Drop)
    .spawn()
    .expect("spawn stalled pass-through backend");

    let config = json!({
        "version": "1",
        "proxies": [{
            "id": "h3-grpc-web-deadline-stall",
            "listen_path": "/deadline-stall",
            "backend_scheme": "https",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": true,
            "backend_connect_timeout_ms": 2000,
            "backend_read_timeout_ms": 5000,
            "backend_write_timeout_ms": 5000,
            "backend_tls_verify_server_cert": false,
            "plugins": [{"plugin_config_id": "grpc-deadline-stall"}],
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [{
            "id": "grpc-deadline-stall",
            "plugin_name": "grpc_deadline",
            "scope": "proxy",
            "proxy_id": "h3-grpc-web-deadline-stall",
            "enabled": true,
            "config": {"max_deadline_ms": 1000},
        }],
    });
    let (_gateway, https_port, _scratch) = spawn_h3_gateway(config).await;
    let client = Http3Client::insecure().expect("H3 client");
    let started_at = Instant::now();
    let (response, request_attempts) = request_with_retry_and_attempts(
        &client,
        &format!("https://127.0.0.1:{https_port}/deadline-stall/echo.Echo/Unary"),
        GetOptions::default()
            .method(Method::POST)
            .header("content-type", "application/grpc-web+proto")
            .header("grpc-timeout", "100m")
            .body(Bytes::from(grpc_frame(b"ping"))),
    )
    .await;

    assert_grpc_web_error(&response, "4", "application/grpc-web+proto");
    assert!(
        started_at.elapsed() < Duration::from_secs(3),
        "the absolute RPC deadline must win before the five-second backend read timeout"
    );
    let backend_connections = backend.accepted_connections();
    assert!(
        backend_connections >= 1,
        "the withheld-response-header backend path must be reached"
    );
    assert!(
        backend_connections <= request_attempts,
        "streaming dispatch must dial the backend at most once per client request attempt: \
         {backend_connections} backend connections for {request_attempts} client attempts"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_grpc_web_success_uses_grpc_backend_and_preserves_trailer_frame() {
    let backend_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind gRPC backend");
    let backend_port = backend_listener.local_addr().expect("backend addr").port();
    let backend_ca = TestCa::new("h3-grpc-web-backend").expect("backend CA");
    let (backend_cert, backend_key) = backend_ca.valid().expect("backend leaf");
    let backend = ScriptedGrpcBackend::builder_tls(backend_listener, &backend_cert, &backend_key)
        .expect("backend TLS")
        .step(GrpcStep::AcceptRpc(MatchRpc::custom(|request| {
            request.method == "POST"
                && request.path == "/echo.Echo/Unary"
                && request.header("content-type") == Some("application/grpc")
        })))
        .step(GrpcStep::SendInitialHeaders)
        .step(GrpcStep::RespondMessage(Bytes::from_static(b"pong")))
        .step(GrpcStep::RespondStatus {
            code: 0,
            message: "",
        })
        .spawn()
        .expect("spawn gRPC backend");

    let config = json!({
        "version": "1",
        "proxies": [{
            "id": "h3-grpc-web-success",
            "listen_path": "/success",
            "backend_scheme": "https",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": true,
            "backend_connect_timeout_ms": 2000,
            "backend_read_timeout_ms": 5000,
            "backend_write_timeout_ms": 5000,
            "backend_tls_verify_server_cert": false,
            "plugins": [{"plugin_config_id": "grpc-web-success"}],
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [{
            "id": "grpc-web-success",
            "plugin_name": "grpc_web",
            "scope": "proxy",
            "proxy_id": "h3-grpc-web-success",
            "enabled": true,
            "config": {},
        }],
    });
    let (_gateway, https_port, _scratch) = spawn_h3_gateway(config).await;
    let client = Http3Client::insecure().expect("H3 client");
    let response = request_with_retry(
        &client,
        &format!("https://127.0.0.1:{https_port}/success/echo.Echo/Unary"),
        GetOptions::default()
            .method(Method::POST)
            .header("content-type", "application/grpc-web+proto")
            .body(Bytes::from(grpc_frame(b"ping"))),
    )
    .await;

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(
        response
            .headers
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/grpc-web+proto")
    );
    assert!(
        response.trailers.is_none(),
        "gRPC-Web must not leak native H3 trailers"
    );
    let frames = grpc_web_frames(&response.body_bytes);
    assert_eq!(
        frames.first().map(|(flag, body)| (*flag, *body)),
        Some((0, b"pong".as_slice()))
    );
    let trailer_payload = frames
        .iter()
        .find_map(|(flag, payload)| (*flag == 0x80).then_some(*payload))
        .expect("successful gRPC-Web response trailer frame");
    assert!(
        String::from_utf8_lossy(trailer_payload).contains("grpc-status: 0\r\n"),
        "success status must be embedded in the gRPC-Web trailer frame"
    );

    backend.assert_no_matcher_mismatches().await;
    backend.assert_no_step_errors().await;
    let requests = backend.received_streams().await;
    assert_eq!(
        requests.len(),
        1,
        "exactly one native gRPC backend request expected"
    );
    assert_eq!(requests[0].body, grpc_frame(b"ping"));
}
