//! Backend-observed `request_transformer` query mutations across H1/H2/H3.
//!
//! GHSA-33pw-39ww-qppq: query rules must change the primary backend
//! request-target (and the co-located mirror) rather than only the lossy
//! plugin context map.

use crate::common::TestGateway;
use crate::scaffolding::clients::{GetOptions, Http3Client};

use bytes::Bytes;
use http::{Method, StatusCode};
use http_body_util::{BodyExt, Empty};
use hyper::Request;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

const INBOUND_QUERY: &str = "access_token=secret&tag=red&tag=blue&page=1&flag&keep=1";
const EXPECTED_QUERY: &str = "tag=green&tag=green&page=2&flag&keep=1&version=v2";

#[ignore]
#[tokio::test]
async fn request_transformer_query_rules_reach_primary_and_mirror_on_h1_h2_h3() {
    let mut harness = TransformerQueryHarness::spawn().await;

    for protocol in ["HTTP/1.1", "HTTP/2", "HTTP/3"] {
        harness.reset_captures();
        let status = match protocol {
            "HTTP/1.1" => http1_get(&harness).await,
            "HTTP/2" => h2_get(&harness).await,
            "HTTP/3" => h3_get(&harness).await,
            _ => unreachable!(),
        };
        assert_eq!(status, StatusCode::OK, "{protocol} client request failed");

        let (primary, mirror) = harness
            .wait_for_both_targets(Duration::from_secs(5))
            .await
            .unwrap_or_else(|| panic!("{protocol}: timed out waiting for primary and mirror"));

        assert_eq!(
            primary, mirror,
            "{protocol}: primary and mirror request-targets must match\n  primary={primary}\n  mirror={mirror}"
        );
        assert!(
            primary.contains(&format!("?{EXPECTED_QUERY}")),
            "{protocol}: backend must observe transformed query\n  got={primary}\n  expected substring=?{EXPECTED_QUERY}"
        );
        assert!(
            !primary.contains("access_token"),
            "{protocol}: removed credential must not reach backend: {primary}"
        );
    }

    harness.shutdown();
}

#[ignore]
#[tokio::test]
async fn request_transformer_query_survives_retry_on_h1() {
    let mut harness = TransformerRetryHarness::spawn().await;
    let status = http1_get_retry(&harness).await;
    assert_eq!(
        status.as_u16(),
        500,
        "status retries should exhaust with 500"
    );

    let targets = harness
        .wait_for_attempts(3, Duration::from_secs(5))
        .await
        .expect("timed out waiting for retry attempts");
    assert_eq!(
        targets.len(),
        3,
        "expected 1 original + 2 retries on /resource: {targets:?}"
    );
    for (idx, target) in targets.iter().enumerate() {
        assert!(
            target.contains(&format!("?{EXPECTED_QUERY}")),
            "attempt {idx} must reuse transformed query: {target}"
        );
        assert!(
            !target.contains("access_token"),
            "attempt {idx} must not resurrect removed credential: {target}"
        );
    }
    harness.shutdown();
}

struct CapturingBackend {
    port: u16,
    targets: Arc<Mutex<Vec<String>>>,
    notify: Arc<Notify>,
    handle: Option<JoinHandle<()>>,
}

impl CapturingBackend {
    async fn spawn() -> Self {
        Self::spawn_with_status(false).await
    }

    async fn spawn_failing() -> Self {
        Self::spawn_with_status(true).await
    }

    async fn spawn_with_status(fail_all: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind capture backend");
        let port = listener.local_addr().expect("local addr").port();
        let targets = Arc::new(Mutex::new(Vec::new()));
        let notify = Arc::new(Notify::new());
        let targets_task = targets.clone();
        let notify_task = notify.clone();
        let handle = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((mut stream, _)) => {
                        let targets = targets_task.clone();
                        let notify = notify_task.clone();
                        tokio::spawn(async move {
                            let mut buf = Vec::new();
                            let mut chunk = [0u8; 4096];
                            loop {
                                match stream.read(&mut chunk).await {
                                    Ok(0) => break,
                                    Ok(n) => {
                                        buf.extend_from_slice(&chunk[..n]);
                                        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                                            break;
                                        }
                                    }
                                    Err(_) => return,
                                }
                            }
                            let head = String::from_utf8_lossy(&buf);
                            let request_line = head.lines().next().unwrap_or("");
                            let target = request_line
                                .split_whitespace()
                                .nth(1)
                                .unwrap_or("")
                                .to_string();
                            targets.lock().expect("targets lock").push(target);
                            notify.notify_waiters();
                            let response = if fail_all {
                                b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                                    as &[u8]
                            } else {
                                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                            };
                            let _ = stream.write_all(response).await;
                            let _ = stream.shutdown().await;
                        });
                    }
                    Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
                }
            }
        });
        Self {
            port,
            targets,
            notify,
            handle: Some(handle),
        }
    }

    fn targets(&self) -> Vec<String> {
        self.targets.lock().expect("targets lock").clone()
    }

    fn clear(&self) {
        self.targets.lock().expect("targets lock").clear();
    }

    fn abort(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

impl Drop for CapturingBackend {
    fn drop(&mut self) {
        self.abort();
    }
}

struct TransformerQueryHarness {
    gateway: TestGateway,
    primary: CapturingBackend,
    mirror: CapturingBackend,
    https_port: u16,
}

impl TransformerQueryHarness {
    async fn spawn() -> Self {
        let primary = CapturingBackend::spawn().await;
        let mirror = CapturingBackend::spawn().await;
        let https_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("reserve https port");
        let https_port = https_listener.local_addr().expect("https addr").port();
        drop(https_listener);

        let gateway = TestGateway::builder()
            .mode_file(transformer_query_config(primary.port, mirror.port))
            .log_level("warn")
            .env("FERRUM_ENABLE_HTTP3", "true")
            .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
            .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
            .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
            .env("FERRUM_POOL_WARMUP_ENABLED", "false")
            .spawn()
            .await
            .expect("start transformer query gateway");
        gateway
            .wait_for_proxy_port(Duration::from_secs(5))
            .await
            .expect("proxy port ready");

        Self {
            gateway,
            primary,
            mirror,
            https_port,
        }
    }

    fn reset_captures(&self) {
        self.primary.clear();
        self.mirror.clear();
    }

    async fn wait_for_both_targets(&self, timeout: Duration) -> Option<(String, String)> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let primary = self.primary.targets();
            let mirror = self.mirror.targets();
            if let (Some(p), Some(m)) = (primary.first(), mirror.first()) {
                return Some((p.clone(), m.clone()));
            }
            if tokio::time::Instant::now() >= deadline {
                return None;
            }
            tokio::select! {
                _ = self.primary.notify.notified() => {}
                _ = self.mirror.notify.notified() => {}
                _ = tokio::time::sleep(Duration::from_millis(50)) => {}
            }
        }
    }

    fn http1_url(&self) -> String {
        self.gateway
            .proxy_url(&format!("/resource?{INBOUND_QUERY}"))
    }

    fn h2_uri(&self) -> String {
        format!(
            "http://127.0.0.1:{}/resource?{INBOUND_QUERY}",
            self.gateway.proxy_port
        )
    }

    fn h3_url(&self) -> String {
        format!(
            "https://localhost:{}/resource?{INBOUND_QUERY}",
            self.https_port
        )
    }

    fn shutdown(&mut self) {
        self.gateway.shutdown();
        self.primary.abort();
        self.mirror.abort();
    }
}

struct TransformerRetryHarness {
    gateway: TestGateway,
    backend: CapturingBackend,
}

impl TransformerRetryHarness {
    async fn spawn() -> Self {
        let backend = CapturingBackend::spawn_failing().await;
        let gateway = TestGateway::builder()
            .mode_file(transformer_retry_config(backend.port))
            .log_level("warn")
            .env("FERRUM_POOL_WARMUP_ENABLED", "false")
            .spawn()
            .await
            .expect("start transformer retry gateway");
        gateway
            .wait_for_proxy_port(Duration::from_secs(5))
            .await
            .expect("proxy port ready");

        Self { gateway, backend }
    }

    async fn wait_for_attempts(&self, count: usize, timeout: Duration) -> Option<Vec<String>> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            // Ignore unrelated backend health/probe traffic (for example "*")
            // so the retry count only covers the /resource requests under test.
            let targets: Vec<String> = self
                .backend
                .targets()
                .into_iter()
                .filter(|target| target.starts_with("/resource"))
                .collect();
            if targets.len() >= count {
                return Some(targets);
            }
            if tokio::time::Instant::now() >= deadline {
                return None;
            }
            tokio::select! {
                _ = self.backend.notify.notified() => {}
                _ = tokio::time::sleep(Duration::from_millis(50)) => {}
            }
        }
    }

    fn http1_url(&self) -> String {
        self.gateway
            .proxy_url(&format!("/resource?{INBOUND_QUERY}"))
    }

    fn shutdown(&mut self) {
        self.gateway.shutdown();
        self.backend.abort();
    }
}

fn transformer_rules() -> serde_json::Value {
    serde_json::json!([
        {"operation": "remove", "target": "query", "key": "access_token"},
        {"operation": "update", "target": "query", "key": "tag", "value": "green"},
        {"operation": "update", "target": "query", "key": "page", "value": "2"},
        {"operation": "add", "target": "query", "key": "version", "value": "v2"}
    ])
}

fn transformer_query_config(primary_port: u16, mirror_port: u16) -> String {
    let config = serde_json::json!({
        "version": "1",
        "proxies": [{
            "id": "transformer-query",
            "listen_path": "/",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": primary_port,
            "strip_listen_path": false,
            "pool_enable_http2": false,
            "plugins": [
                {"plugin_config_id": "transformer-query-plugin"},
                {"plugin_config_id": "mirror-query-plugin"}
            ]
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [
            {
                "id": "transformer-query-plugin",
                "plugin_name": "request_transformer",
                "scope": "proxy",
                "proxy_id": "transformer-query",
                "enabled": true,
                "config": { "rules": transformer_rules() }
            },
            {
                "id": "mirror-query-plugin",
                "plugin_name": "request_mirror",
                "scope": "proxy",
                "proxy_id": "transformer-query",
                "enabled": true,
                "config": {
                    "mirror_host": "127.0.0.1",
                    "mirror_port": mirror_port,
                    "mirror_protocol": "http",
                    "percentage": 100.0,
                    "mirror_request_body": false
                }
            }
        ]
    });
    serde_yaml::to_string(&config).expect("serialize transformer query config")
}

fn transformer_retry_config(backend_port: u16) -> String {
    let config = serde_json::json!({
        "version": "1",
        "proxies": [{
            "id": "transformer-retry",
            "listen_path": "/",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": false,
            "retry": {
                "max_retries": 2,
                "retryable_status_codes": [500],
                "retryable_methods": ["GET"],
                "backoff_strategy": "fixed",
                "backoff_base_ms": 20
            },
            "plugins": [{"plugin_config_id": "transformer-retry-plugin"}]
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [{
            "id": "transformer-retry-plugin",
            "plugin_name": "request_transformer",
            "scope": "proxy",
            "proxy_id": "transformer-retry",
            "enabled": true,
            "config": { "rules": transformer_rules() }
        }]
    });
    serde_yaml::to_string(&config).expect("serialize transformer retry config")
}

async fn http1_get(harness: &TransformerQueryHarness) -> StatusCode {
    let client = reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("http1 client");
    client
        .get(harness.http1_url())
        .send()
        .await
        .expect("http1 request")
        .status()
}

async fn http1_get_retry(harness: &TransformerRetryHarness) -> StatusCode {
    let client = reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("http1 client");
    client
        .get(harness.http1_url())
        .send()
        .await
        .expect("http1 retry request")
        .status()
}

async fn h2_get(harness: &TransformerQueryHarness) -> StatusCode {
    let stream = TcpStream::connect(("127.0.0.1", harness.gateway.proxy_port))
        .await
        .expect("connect h2c");
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
        .await
        .expect("h2 handshake");
    let conn_task = tokio::spawn(async move {
        let _ = conn.await;
    });
    let request = Request::builder()
        .uri(harness.h2_uri())
        .body(Empty::<Bytes>::new())
        .expect("build h2 request");
    let response = sender.send_request(request).await.expect("send h2 request");
    let status = response.status();
    let _ = response
        .into_body()
        .collect()
        .await
        .expect("collect h2 body");
    drop(sender);
    conn_task.abort();
    status
}

async fn h3_get(harness: &TransformerQueryHarness) -> StatusCode {
    let client = Http3Client::insecure().expect("h3 client");
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        match client
            .get_with_options(&harness.h3_url(), GetOptions::default().method(Method::GET))
            .await
        {
            Ok(response) => return response.status,
            Err(_) if std::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(error) => panic!("H3 transformer query request did not complete: {error}"),
        }
    }
}
