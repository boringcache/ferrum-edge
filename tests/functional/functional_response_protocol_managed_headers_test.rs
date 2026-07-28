//! GHSA-xvr4-5p3r-h7cw: protocol-managed response headers cannot survive the
//! final H1/H2/H3 client-wire boundary after response plugins run.
//!
//! Covers construction rejection for `response_transformer` / `response_mock`,
//! final-boundary strip of hop-by-hop and Connection-listed fields on ordinary
//! upstream responses, Content-Length repair on buffered bodies, and the
//! already-fixed correlation-id echo behavior on ordinary responses.

use crate::common::TestGateway;
use crate::common::protocol_managed_response_headers::PROTOCOL_MANAGED_RESPONSE_DESTINATIONS;
use crate::scaffolding::clients::{GetOptions, Http3Client, Http3Response};

use http::{Method, StatusCode, header};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::sleep;

fn build_config(backend_port: u16) -> String {
    format!(
        r#"version: "1"
proxies:
  - id: "proto-managed"
    listen_path: "/api"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true
    pool_enable_http2: true
    plugins:
      - plugin_config_id: "corr"
      - plugin_config_id: "xform"
      - plugin_config_id: "mock"

consumers: []
plugin_configs:
  - id: "corr"
    plugin_name: correlation_id
    scope: proxy
    proxy_id: "proto-managed"
    enabled: true
    config:
      header_name: x-request-id
      echo_downstream: true
  - id: "xform"
    plugin_name: response_transformer
    scope: proxy
    proxy_id: "proto-managed"
    enabled: true
    config:
      rules:
        - operation: add
          target: header
          key: x-gateway
          value: "1"
        - operation: remove
          target: header
          key: x-backend-only
  - id: "mock"
    plugin_name: response_mock
    scope: proxy
    proxy_id: "proto-managed"
    enabled: true
    config:
      passthrough_on_no_match: true
      rules:
        - path: /mocked
          status_code: 200
          headers:
            content-type: text/plain
            x-mock: "yes"
          body: "mock-body"
"#
    )
}

async fn start_scripted_backend(hits: Arc<AtomicUsize>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind backend");
    let port = listener.local_addr().expect("addr").port();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            hits.fetch_add(1, Ordering::SeqCst);
            let mut buf = [0u8; 4096];
            let _ = socket.read(&mut buf).await;
            let body = b"hello";
            let response = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: text/plain\r\n\
                 Content-Length: {}\r\n\
                 Connection: close, x-smuggled\r\n\
                 x-smuggled: leak\r\n\
                 Keep-Alive: timeout=5\r\n\
                 Proxy-Authenticate: Basic\r\n\
                 Upgrade: h2c\r\n\
                 x-backend-only: gone\r\n\
                 \r\n",
                body.len()
            );
            let _ = socket.write_all(response.as_bytes()).await;
            let _ = socket.write_all(body).await;
        }
    });
    port
}

async fn h3_request_until_ready(client: &Http3Client, url: &str, method: Method) -> Http3Response {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match client
            .get_with_options(url, GetOptions::default().method(method.clone()))
            .await
        {
            Ok(response) => return response,
            Err(error) if Instant::now() < deadline => {
                let _ = error;
                sleep(Duration::from_millis(100)).await;
            }
            Err(error) => panic!("H3 {method} {url} did not complete: {error}"),
        }
    }
}

async fn spawn_gateway(backend_port: u16) -> (TestGateway, u16) {
    const MAX_ATTEMPTS: usize = 5;
    let mut last_error = String::new();

    for _ in 0..MAX_ATTEMPTS {
        let reservation = match TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(error) => {
                last_error = error.to_string();
                sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        let https_port = match reservation.local_addr() {
            Ok(address) => address.port(),
            Err(error) => {
                last_error = error.to_string();
                sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        drop(reservation);

        let result = TestGateway::builder()
            .mode_file(build_config(backend_port))
            .log_level("warn")
            .max_attempts(1)
            .env("FERRUM_ENABLE_HTTP3", "true")
            .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
            .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
            .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
            .env("FERRUM_POOL_WARMUP_ENABLED", "false")
            .spawn()
            .await;
        match result {
            Ok(gateway) => return (gateway, https_port),
            Err(error) => {
                last_error = error.to_string();
                sleep(Duration::from_millis(200)).await;
            }
        }
    }

    panic!("failed to spawn gateway: {last_error}");
}

fn assert_no_protocol_managed(headers: &http::HeaderMap, label: &str) {
    for name in PROTOCOL_MANAGED_RESPONSE_DESTINATIONS {
        if *name == "content-length" {
            continue;
        }
        assert!(
            headers.get(*name).is_none(),
            "{label}: protocol-managed `{name}` must not reach the client"
        );
    }
    assert!(
        headers.get("x-smuggled").is_none(),
        "{label}: Connection-listed extension must be stripped"
    );
}

#[tokio::test]
#[ignore]
async fn functional_protocol_managed_response_headers_h1_h2_h3() {
    let hits = Arc::new(AtomicUsize::new(0));
    let backend_port = start_scripted_backend(Arc::clone(&hits)).await;
    let (mut gateway, https_port) = spawn_gateway(backend_port).await;
    gateway
        .wait_for_proxy_port(Duration::from_secs(10))
        .await
        .expect("proxy port ready");
    let echo_url = gateway.proxy_url("/api/echo");
    let mocked_url = gateway.proxy_url("/api/mocked");

    // --- Ordinary upstream via transformer (H1) ---
    let h1 = reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("h1 client");
    let h1_resp = h1.get(&echo_url).send().await.expect("H1 ordinary");
    assert_eq!(h1_resp.status(), StatusCode::OK);
    assert_eq!(
        h1_resp
            .headers()
            .get("x-gateway")
            .and_then(|v| v.to_str().ok()),
        Some("1")
    );
    assert!(h1_resp.headers().get("x-backend-only").is_none());
    assert_no_protocol_managed(h1_resp.headers(), "H1 ordinary");
    assert_eq!(
        h1_resp
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok()),
        Some("5")
    );
    let corr = h1_resp
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .expect("correlation echo on ordinary H1")
        .to_string();
    assert!(!corr.is_empty());
    assert_eq!(h1_resp.bytes().await.expect("body").as_ref(), b"hello");

    // --- Synthetic mock (H1) ---
    let mock = h1.get(&mocked_url).send().await.expect("H1 mock");
    assert_eq!(mock.status(), StatusCode::OK);
    assert_eq!(
        mock.headers().get("x-mock").and_then(|v| v.to_str().ok()),
        Some("yes")
    );
    assert_no_protocol_managed(mock.headers(), "H1 mock");
    assert_eq!(
        mock.headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok()),
        Some("9")
    );
    assert!(
        mock.headers().get("x-request-id").is_some(),
        "correlation echo on mock reject path"
    );
    assert_eq!(
        mock.bytes().await.expect("mock body").as_ref(),
        b"mock-body"
    );

    // --- H2 (h2c prior knowledge on the plaintext proxy port) ---
    let h2 = reqwest::Client::builder()
        .http2_prior_knowledge()
        .no_proxy()
        .build()
        .expect("h2 client");
    let h2_resp = h2.get(&echo_url).send().await.expect("H2 ordinary");
    assert_eq!(h2_resp.version(), reqwest::Version::HTTP_2);
    assert_eq!(h2_resp.status(), StatusCode::OK);
    assert_no_protocol_managed(h2_resp.headers(), "H2 ordinary");
    assert_eq!(
        h2_resp
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok()),
        Some("5")
    );
    assert!(h2_resp.headers().get("x-request-id").is_some());

    let h2_mock = h2.get(&mocked_url).send().await.expect("H2 mock");
    assert_eq!(h2_mock.status(), StatusCode::OK);
    assert_no_protocol_managed(h2_mock.headers(), "H2 mock");
    assert_eq!(
        h2_mock
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok()),
        Some("9")
    );

    // --- H3 ---
    let h3 = Http3Client::insecure().expect("h3 client");
    let h3_echo = format!("https://localhost:{https_port}/api/echo");
    let h3_mocked = format!("https://localhost:{https_port}/api/mocked");
    let h3_resp = h3_request_until_ready(&h3, &h3_echo, Method::GET).await;
    assert_eq!(h3_resp.status, StatusCode::OK);
    assert_no_protocol_managed(&h3_resp.headers, "H3 ordinary");
    assert_eq!(
        h3_resp
            .headers
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok()),
        Some("5")
    );
    assert!(h3_resp.headers.get("x-request-id").is_some());

    let h3_mock = h3_request_until_ready(&h3, &h3_mocked, Method::GET).await;
    assert_eq!(h3_mock.status, StatusCode::OK);
    assert_no_protocol_managed(&h3_mock.headers, "H3 mock");
    assert_eq!(
        h3_mock
            .headers
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok()),
        Some("9")
    );

    assert!(
        hits.load(Ordering::SeqCst) >= 2,
        "ordinary paths should have reached the scripted backend"
    );
}
