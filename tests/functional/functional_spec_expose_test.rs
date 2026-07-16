//! End-to-end `spec_expose` coverage across HTTP/1.1, HTTP/2, and HTTP/3.

use crate::common::TestGateway;
use crate::scaffolding::clients::{GetOptions, Http3Client, Http3Response};

use http::{HeaderMap, Method, StatusCode};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::sleep;

const SPEC_BODY: &str = "openapi: 3.1.0\ninfo:\n  title: Ferrum\n";

struct StaticServer {
    port: u16,
    hits: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl StaticServer {
    async fn start(body: &'static str, content_type: &'static str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind static server");
        let port = listener.local_addr().expect("static server addr").port();
        let hits = Arc::new(AtomicUsize::new(0));
        let task_hits = Arc::clone(&hits);
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    continue;
                };
                let hits = Arc::clone(&task_hits);
                tokio::spawn(async move {
                    let mut request = vec![0_u8; 8_192];
                    let Ok(Ok(read)) =
                        tokio::time::timeout(Duration::from_secs(5), stream.read(&mut request))
                            .await
                    else {
                        return;
                    };
                    if read == 0 {
                        return;
                    }
                    hits.fetch_add(1, Ordering::SeqCst);
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });

        Self { port, hits, task }
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

impl Drop for StaticServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn build_config(backend_port: u16, spec_origin_port: u16) -> String {
    format!(
        r#"version: "1"
proxies:
  - id: "spec-trailing-prefix"
    listen_path: "/api/"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: false
    pool_enable_http2: false
    allowed_methods: [GET, HEAD]
  - id: "spec-head-blocked"
    listen_path: "/blocked/"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: false
    pool_enable_http2: false
    allowed_methods: [GET]

consumers: []
plugin_configs:
  - id: "spec-expose-global"
    plugin_name: spec_expose
    scope: global
    enabled: true
    config:
      spec_url: "http://127.0.0.1:{spec_origin_port}/private/openapi.yaml?token=signed"
      cache_ttl_seconds: 60
"#
    )
}

fn assert_spec_metadata(headers: &HeaderMap) {
    assert_eq!(
        headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/yaml")
    );
    assert_eq!(
        headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok()),
        Some(SPEC_BODY.len())
    );
    assert_eq!(
        headers
            .get("x-content-type-options")
            .and_then(|value| value.to_str().ok()),
        Some("nosniff")
    );
}

async fn h3_request_until_ready(
    client: &Http3Client,
    url: &str,
    method: Method,
) -> Http3Response {
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

#[ignore]
#[tokio::test]
async fn functional_spec_expose_get_head_path_and_method_contract_across_http_versions() {
    let origin = StaticServer::start(SPEC_BODY, "application/yaml").await;
    let backend = StaticServer::start("ordinary backend", "text/plain").await;

    let https_reservation = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve HTTPS port");
    let https_port = https_reservation
        .local_addr()
        .expect("HTTPS reservation addr")
        .port();
    drop(https_reservation);

    let mut gateway = TestGateway::builder()
        .mode_file(build_config(backend.port, origin.port))
        .log_level("warn")
        .env("FERRUM_ENABLE_HTTP3", "true")
        .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
        .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
        .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
        .spawn()
        .await
        .expect("start spec_expose gateway");
    gateway
        .wait_for_proxy_port(Duration::from_secs(10))
        .await
        .expect("proxy port ready");

    let h1 = reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("H1 client");
    let canonical = gateway.proxy_url("/api/specz?download=true");

    // HEAD on a cold cache performs the same origin GET as the representation,
    // but returns metadata only.
    let h1_head = h1.head(&canonical).send().await.expect("H1 HEAD");
    assert_eq!(h1_head.status(), reqwest::StatusCode::OK);
    assert_spec_metadata(h1_head.headers());
    assert!(h1_head.bytes().await.expect("H1 HEAD body").is_empty());
    assert_eq!(origin.hits(), 1);
    assert_eq!(backend.hits(), 0);

    let h1_get = h1.get(&canonical).send().await.expect("H1 GET");
    assert_eq!(h1_get.status(), reqwest::StatusCode::OK);
    assert_spec_metadata(h1_get.headers());
    assert_eq!(h1_get.text().await.expect("H1 GET body"), SPEC_BODY);
    assert_eq!(origin.hits(), 1, "GET should reuse the HEAD-populated cache");

    // The double-slash alias is deliberately ordinary backend traffic.
    let alias = h1
        .get(gateway.proxy_url("/api//specz"))
        .send()
        .await
        .expect("H1 double-slash alias");
    assert_eq!(alias.text().await.expect("alias body"), "ordinary backend");
    assert_eq!(backend.hits(), 1);

    // Encoded separators do not become the plugin-owned resource.
    let encoded = h1
        .get(gateway.proxy_url("/api%2Fspecz"))
        .send()
        .await
        .expect("H1 encoded separator");
    assert_ne!(encoded.text().await.expect("encoded body"), SPEC_BODY);
    assert_eq!(origin.hits(), 1);

    // Route method admission runs before the plugin and can exclude HEAD.
    let blocked = h1
        .head(gateway.proxy_url("/blocked/specz"))
        .send()
        .await
        .expect("H1 blocked HEAD");
    assert_eq!(blocked.status(), reqwest::StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(origin.hits(), 1);
    assert_eq!(backend.hits(), 1);

    let h2 = reqwest::Client::builder()
        .http2_prior_knowledge()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("h2c client");
    let h2_get = h2.get(&canonical).send().await.expect("H2 GET");
    assert_eq!(h2_get.version(), reqwest::Version::HTTP_2);
    assert_spec_metadata(h2_get.headers());
    assert_eq!(h2_get.text().await.expect("H2 GET body"), SPEC_BODY);
    let h2_head = h2.head(&canonical).send().await.expect("H2 HEAD");
    assert_eq!(h2_head.version(), reqwest::Version::HTTP_2);
    assert_spec_metadata(h2_head.headers());
    assert!(h2_head.bytes().await.expect("H2 HEAD body").is_empty());

    let h3 = Http3Client::insecure().expect("H3 client");
    let h3_url = format!("https://localhost:{https_port}/api/specz?download=true");
    let h3_get = h3_request_until_ready(&h3, &h3_url, Method::GET).await;
    assert_eq!(h3_get.status, StatusCode::OK);
    assert_spec_metadata(&h3_get.headers);
    assert_eq!(h3_get.body_text(), SPEC_BODY);
    let h3_head = h3_request_until_ready(&h3, &h3_url, Method::HEAD).await;
    assert_eq!(h3_head.status, StatusCode::OK);
    assert_spec_metadata(&h3_head.headers);
    assert!(h3_head.body_bytes.is_empty());

    let h3_blocked_url = format!("https://localhost:{https_port}/blocked/specz");
    let h3_blocked = h3_request_until_ready(&h3, &h3_blocked_url, Method::HEAD).await;
    assert_eq!(h3_blocked.status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(origin.hits(), 1);
    assert_eq!(backend.hits(), 1);

    gateway.shutdown();
}
