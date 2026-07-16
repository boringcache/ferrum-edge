//! Hosted-only H1/H2/H3 lifecycle coverage for the shipped custom plugin.
//!
//! Run: `cargo build --bin ferrum-edge && cargo test --test functional_tests functional_example_plugin -- --ignored --nocapture`

use crate::common::TestGateway;
use crate::scaffolding::clients::{GetOptions, Http3Client};

use http::{HeaderMap, Method, StatusCode};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::sleep;

struct HeaderEchoBackend {
    port: u16,
    hits: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl HeaderEchoBackend {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind example backend");
        let port = listener.local_addr().expect("example backend addr").port();
        let hits = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(serve_header_echo(listener, Arc::clone(&hits)));
        sleep(Duration::from_millis(100)).await;
        Self { port, hits, task }
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

impl Drop for HeaderEchoBackend {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve_header_echo(listener: TcpListener, hits: Arc<AtomicUsize>) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            continue;
        };
        let hits = Arc::clone(&hits);
        tokio::spawn(async move {
            let mut request = Vec::with_capacity(2048);
            let mut chunk = [0u8; 1024];
            loop {
                let read =
                    tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk)).await;
                let Ok(Ok(read)) = read else {
                    return;
                };
                if read == 0 {
                    return;
                }
                request.extend_from_slice(&chunk[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
                if request.len() > 32 * 1024 {
                    return;
                }
            }

            let request = String::from_utf8_lossy(&request);
            let observed = request.lines().find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("x-custom-gateway")
                    .then(|| value.trim())
            });
            hits.fetch_add(1, Ordering::SeqCst);
            let observed = observed.unwrap_or("missing");
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\nX-Backend-Observed: {observed}\r\nConnection: close\r\n\r\nok"
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
    }
}

fn build_config(backend_port: u16) -> String {
    format!(
        r#"version: "1"
proxies:
  - id: "global-example-route"
    listen_path: "/global-example"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: false
    pool_enable_http2: false
    allowed_methods: ["GET"]
  - id: "scoped-example-route"
    listen_path: "/scoped-example"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: false
    pool_enable_http2: false
    allowed_methods: ["GET"]
    plugins:
      - plugin_config_id: "scoped-example"
consumers: []
plugin_configs:
  - id: "global-example"
    plugin_name: example_plugin
    scope: global
    enabled: true
    config:
      header_value: "global-value"
  - id: "scoped-example"
    plugin_name: example_plugin
    scope: proxy
    proxy_id: "scoped-example-route"
    enabled: true
    config:
      header_value: "scoped-value"
"#
    )
}

fn assert_matched_headers(headers: &HeaderMap, expected: &str) {
    assert_eq!(
        headers
            .get("x-backend-observed")
            .and_then(|value| value.to_str().ok()),
        Some(expected),
        "before_proxy request header must reach the backend"
    );
    assert_eq!(
        headers
            .get("x-custom-gateway")
            .and_then(|value| value.to_str().ok()),
        Some(expected),
        "after_proxy response header must reach the client"
    );
}

fn assert_early_response_has_no_example_header(headers: &HeaderMap) {
    assert!(
        !headers.contains_key("x-custom-gateway"),
        "404/405 must return before global or scoped example hooks"
    );
    assert!(
        !headers.contains_key("x-backend-observed"),
        "404/405 must not reach the backend"
    );
}

#[ignore]
#[tokio::test]
async fn functional_example_plugin_h1_h2_matched_404_and_405_contract() {
    let backend = HeaderEchoBackend::start().await;
    let mut gateway = TestGateway::builder()
        .mode_file(build_config(backend.port))
        .log_level("warn")
        .spawn()
        .await
        .expect("start H1/H2 example gateway");
    gateway
        .wait_for_proxy_port(Duration::from_secs(10))
        .await
        .expect("example proxy port ready");

    let h1 = reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("H1 client");
    for (path, expected) in [
        ("/global-example/ok", "global-value"),
        ("/scoped-example/ok", "scoped-value"),
    ] {
        let response = h1
            .get(gateway.proxy_url(path))
            .send()
            .await
            .expect("H1 matched request");
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_matched_headers(response.headers(), expected);
    }
    let h1_miss = h1
        .get(gateway.proxy_url("/unmatched-example"))
        .send()
        .await
        .expect("H1 route miss");
    assert_eq!(h1_miss.status(), reqwest::StatusCode::NOT_FOUND);
    assert_early_response_has_no_example_header(h1_miss.headers());
    let h1_method = h1
        .post(gateway.proxy_url("/global-example/blocked"))
        .send()
        .await
        .expect("H1 method rejection");
    assert_eq!(h1_method.status(), reqwest::StatusCode::METHOD_NOT_ALLOWED);
    assert_early_response_has_no_example_header(h1_method.headers());

    let h2 = reqwest::Client::builder()
        .http2_prior_knowledge()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("H2 client");
    for (path, expected) in [
        ("/global-example/ok", "global-value"),
        ("/scoped-example/ok", "scoped-value"),
    ] {
        let response = h2
            .get(gateway.proxy_url(path))
            .send()
            .await
            .expect("H2 matched request");
        assert_eq!(response.version(), reqwest::Version::HTTP_2);
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_matched_headers(response.headers(), expected);
    }
    let h2_miss = h2
        .get(gateway.proxy_url("/unmatched-example"))
        .send()
        .await
        .expect("H2 route miss");
    assert_eq!(h2_miss.version(), reqwest::Version::HTTP_2);
    assert_eq!(h2_miss.status(), reqwest::StatusCode::NOT_FOUND);
    assert_early_response_has_no_example_header(h2_miss.headers());
    let h2_method = h2
        .post(gateway.proxy_url("/scoped-example/blocked"))
        .send()
        .await
        .expect("H2 method rejection");
    assert_eq!(h2_method.version(), reqwest::Version::HTTP_2);
    assert_eq!(h2_method.status(), reqwest::StatusCode::METHOD_NOT_ALLOWED);
    assert_early_response_has_no_example_header(h2_method.headers());

    assert_eq!(
        backend.hits(),
        4,
        "only matched H1/H2 requests reach backend"
    );
    gateway.shutdown();
}

#[ignore]
#[tokio::test]
async fn functional_example_plugin_h3_matched_404_and_405_contract() {
    let backend = HeaderEchoBackend::start().await;
    let https_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve example H3 port");
    let https_port = https_listener.local_addr().expect("example H3 addr").port();
    drop(https_listener);

    let mut gateway = TestGateway::builder()
        .mode_file(build_config(backend.port))
        .log_level("warn")
        .env("FERRUM_ENABLE_HTTP3", "true")
        .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
        .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
        .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
        .spawn()
        .await
        .expect("start H3 example gateway");

    let client = Http3Client::insecure().expect("H3 client");
    let first_url = format!("https://localhost:{https_port}/global-example/ok");
    let deadline = Instant::now() + Duration::from_secs(10);
    let first = loop {
        match client.get(&first_url).await {
            Ok(response) => break response,
            Err(error) if Instant::now() < deadline => {
                let _ = error;
                sleep(Duration::from_millis(100)).await;
            }
            Err(error) => panic!("H3 example request did not complete: {error}"),
        }
    };
    assert_eq!(first.status, StatusCode::OK);
    assert_matched_headers(&first.headers, "global-value");

    let scoped = client
        .get(&format!("https://localhost:{https_port}/scoped-example/ok"))
        .await
        .expect("H3 scoped matched request");
    assert_eq!(scoped.status, StatusCode::OK);
    assert_matched_headers(&scoped.headers, "scoped-value");

    let miss = client
        .get(&format!("https://localhost:{https_port}/unmatched-example"))
        .await
        .expect("H3 route miss");
    assert_eq!(miss.status, StatusCode::NOT_FOUND);
    assert_early_response_has_no_example_header(&miss.headers);

    let method = client
        .get_with_options(
            &format!("https://localhost:{https_port}/global-example/blocked"),
            GetOptions::default().method(Method::POST),
        )
        .await
        .expect("H3 method rejection");
    assert_eq!(method.status, StatusCode::METHOD_NOT_ALLOWED);
    assert_early_response_has_no_example_header(&method.headers);

    assert_eq!(backend.hits(), 2, "only matched H3 requests reach backend");
    gateway.shutdown();
}
