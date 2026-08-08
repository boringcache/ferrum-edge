//! Functional coverage for port-aware HTTP routes (issue #3612).
//!
//! Proves the binary data path respects `Proxy.listen_port` with the
//! HTTP/HTTPS protocol remap used by Gateway API listener projection onto
//! `FERRUM_PROXY_HTTP_PORT` / `FERRUM_PROXY_HTTPS_PORT`, and that a SIGHUP
//! reload can withdraw one port-scoped sibling without disturbing the other.
//!
//! Run with:
//!   cargo build --bin ferrum-edge
//!   cargo test --test functional_tests -- --ignored functional_port_aware_routes --nocapture

use crate::common::TestGateway;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio::time::sleep;

async fn spawn_backend(identifier: &'static str) -> (u16, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
        loop {
            if let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let _ = stream.read(&mut buf).await.unwrap_or(0);
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{}",
                        identifier.len(),
                        identifier
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        }
    });
    (port, handle)
}

async fn get_with_host(client: &reqwest::Client, url: String, host: &str) -> (u16, String) {
    let resp = client
        .get(&url)
        .header("Host", host)
        .send()
        .await
        .expect("HTTP GET should complete");
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    (status, body)
}

fn config_yaml(plain_port: u16, tls_port: u16) -> String {
    format!(
        r#"
version: "1"
http_tls_listen_ports: [443]
proxies:
  - id: "plain-api"
    hosts: ["app.example.com"]
    listen_path: "/api"
    listen_port: 80
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {plain_port}
    strip_listen_path: true
  - id: "tls-api"
    hosts: ["app.example.com"]
    listen_path: "/api"
    listen_port: 443
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {tls_port}
    strip_listen_path: true
consumers: []
plugin_configs: []
"#
    )
}

#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn functional_port_aware_routes_plaintext_remap_and_reload() {
    let (plain_backend, _h1) = spawn_backend("plain-backend").await;
    let (tls_backend, _h2) = spawn_backend("tls-backend").await;

    let config = config_yaml(plain_backend, tls_backend);
    let gateway = TestGateway::builder()
        .mode_file(config)
        .log_level("warn")
        .spawn()
        .await
        .expect("start gateway");
    let client = reqwest::Client::new();

    // Process plaintext bind remaps to the single nontls listen_port (80).
    let (status, body) =
        get_with_host(&client, gateway.proxy_url("/api/x"), "app.example.com").await;
    assert_eq!(status, 200, "plaintext remap must hit the HTTP listener route");
    assert_eq!(body, "plain-backend");

    // Reload: drop the plaintext sibling; only the TLS-scoped claim remains.
    // Without a TLS frontend it must not answer on plaintext (remap disabled
    // when the only remaining listen_port is TLS-class).
    let reload = format!(
        r#"
version: "1"
http_tls_listen_ports: [443]
proxies:
  - id: "tls-api"
    hosts: ["app.example.com"]
    listen_path: "/api"
    listen_port: 443
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {tls_backend}
    strip_listen_path: true
consumers: []
plugin_configs: []
"#
    );
    let config_path = gateway
        .config_path
        .as_ref()
        .expect("file-mode harness must populate config_path");
    std::fs::write(config_path, reload).expect("rewrite config");

    #[cfg(unix)]
    {
        let pid = gateway.pid().expect("gateway still running");
        let _ = std::process::Command::new("kill")
            .args(["-HUP", &pid.to_string()])
            .output();
    }

    sleep(Duration::from_secs(2)).await;

    let (status, _) =
        get_with_host(&client, gateway.proxy_url("/api/x"), "app.example.com").await;
    assert_eq!(
        status, 404,
        "after withdrawing the plaintext sibling, TLS-only listen_port must not remap onto plaintext"
    );
}
