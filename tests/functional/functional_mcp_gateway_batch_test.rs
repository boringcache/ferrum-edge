//! Functional coverage for mcp_gateway JSON-RPC batch admission on the live
//! proxy path (transparent mode forwards admitted batches; empty batches are
//! rejected before upstream).
//!
//! Run with:
//! `cargo build --bin ferrum-edge && cargo test --test functional_tests functional_mcp_gateway_batch -- --ignored`

use serde_json::{Value, json};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::sleep;

use crate::common::TestGateway;

async fn start_mcp_echo_server_on(listener: TcpListener) {
    loop {
        if let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]);
                let body = request
                    .split("\r\n\r\n")
                    .nth(1)
                    .unwrap_or("[]")
                    .trim_end_matches('\0');
                // Echo the JSON-RPC body so tests can assert transparent batch
                // forwarding preserved the array order/ids.
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    }
}

async fn start_gateway_with_mcp(backend_port: u16) -> TestGateway {
    let config = format!(
        r#"
version: "1"
proxies:
  - id: "mcp-batch"
    listen_path: "/mcp"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: false
    upstream_id: "mcp-batch-upstream"
    plugins:
      - plugin_config_id: "mcp-gw"

consumers: []
upstreams:
  - id: "mcp-batch-upstream"
    algorithm: round_robin
    targets:
      - host: "127.0.0.1"
        port: {backend_port}
        weight: 1

plugin_configs:
  - id: "mcp-gw"
    plugin_name: "mcp_gateway"
    scope: "proxy"
    proxy_id: "mcp-batch"
    enabled: true
    config:
      mode: transparent_proxy
      endpoint:
        path: /mcp
        protocol_versions: ["2025-03-26", "2025-11-25"]
      servers:
        tools:
          upstream_url: http://127.0.0.1:{backend_port}/mcp
          namespace: tools
      validation:
        max_batch_items: 8
        max_batch_bytes: 65536
        max_batch_item_bytes: 8192
"#
    );

    TestGateway::builder()
        .mode_file(config)
        .env("FERRUM_POOL_WARMUP_ENABLED", "false")
        .spawn()
        .await
        .expect("start mcp_gateway batch gateway")
}

#[tokio::test]
#[ignore]
async fn functional_mcp_gateway_batch_empty_rejected_before_upstream() {
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    tokio::spawn(start_mcp_echo_server_on(backend_listener));

    let gateway = start_gateway_with_mcp(backend_port).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(gateway.proxy_url("/mcp"))
        .header("content-type", "application/json")
        .body("[]")
        .send()
        .await
        .expect("empty batch request");
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body.is_object(),
        "empty batch must be a single Response object"
    );
    assert_eq!(body["error"]["code"], -32600);
    assert_eq!(body["error"]["message"], "Invalid Request");
}

#[tokio::test]
#[ignore]
async fn functional_mcp_gateway_batch_transparent_forwards_ordered_array() {
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    tokio::spawn(start_mcp_echo_server_on(backend_listener));

    let gateway = start_gateway_with_mcp(backend_port).await;
    let client = reqwest::Client::new();
    let batch = json!([
        { "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {} },
        { "jsonrpc": "2.0", "id": 2, "method": "ping", "params": {} }
    ]);
    let resp = client
        .post(gateway.proxy_url("/mcp"))
        .header("content-type", "application/json")
        .timeout(Duration::from_secs(5))
        .json(&batch)
        .send()
        .await
        .expect("batch request");
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let responses = body
        .as_array()
        .expect("transparent mode must forward the batch array to upstream");
    assert_eq!(responses.len(), 2);
    assert_eq!(responses[0]["id"], 1);
    assert_eq!(responses[1]["id"], 2);
    // Keep the gateway handle alive through assertions.
    sleep(Duration::from_millis(10)).await;
    drop(gateway);
}
