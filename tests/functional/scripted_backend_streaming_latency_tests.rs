//! Issue #2532 — streamed terminal latency contract.
//!
//! Slow-backend and slow-client streaming responses must not report unknown
//! concurrent body/client lifetime as gateway processing or gateway overhead.
//! Coverage matrix (clean completion + client disconnect):
//! - HTTP/1.1 frontend
//! - HTTP/2 frontend (h2c prior knowledge)
//! - native HTTP/3 frontend (QUIC listener → `src/http3/server.rs`)
//! - streamed gRPC (h2c)
//!
//! Run with:
//!   cargo build --bin ferrum-edge &&
//!   cargo test --test functional_tests scripted_backend_streaming_latency -- --ignored --nocapture

#![allow(clippy::bool_assert_comparison)]

use crate::scaffolding::backends::{
    GrpcStep, H2Step, HttpStep, MatchHeaders, MatchRpc, RequestMatcher, ScriptedGrpcBackend,
    ScriptedH2Backend, ScriptedHttp1Backend,
};
use crate::scaffolding::certs::TestCa;
use crate::scaffolding::clients::{GetOptions, GrpcClient, Http2Client, Http3Client};
use crate::scaffolding::harness::GatewayHarness;
use crate::scaffolding::ports::reserve_port;
use bytes::Bytes;
use http::Request;
use reqwest::StatusCode;
use serde_json::json;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const BODY_DELAY: Duration = Duration::from_millis(400);
const STREAM_UNKNOWN: f64 = -1.0;
/// Large enough to create real downstream backpressure when the client stops
/// reading (TCP / H2 / QUIC windows fill). Tiny already-buffered bodies are
/// not a valid slow-client fixture.
const SLOW_CLIENT_PAYLOAD_BYTES: usize = 512 * 1024;

#[derive(Clone, Copy)]
enum Pace {
    SlowBackend,
    SlowClient,
}

#[derive(Clone, Copy)]
enum Outcome {
    Complete,
    Disconnect,
}

impl Pace {
    fn as_str(self) -> &'static str {
        match self {
            Pace::SlowBackend => "slow-backend",
            Pace::SlowClient => "slow-client",
        }
    }
}

impl Outcome {
    fn as_str(self) -> &'static str {
        match self {
            Outcome::Complete => "complete",
            Outcome::Disconnect => "disconnect",
        }
    }

    fn expect_disconnect(self) -> bool {
        matches!(self, Outcome::Disconnect)
    }
}

fn scenario_marker(protocol: &str, pace: Pace, outcome: Outcome) -> String {
    format!("{protocol}-{}-{}", pace.as_str(), outcome.as_str())
}

fn scenario_path(protocol: &str, pace: Pace, outcome: Outcome) -> String {
    format!("/api/{}", scenario_marker(protocol, pace, outcome))
}

fn logging_proxy_config(
    backend_port: u16,
    proxy_id: &str,
    listen_path: &str,
    extra_proxy_fields: serde_json::Value,
) -> String {
    let mut proxy = json!({
        "id": proxy_id,
        "listen_path": listen_path,
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": backend_port,
        "strip_listen_path": true,
        "backend_connect_timeout_ms": 2000,
        "backend_read_timeout_ms": 15000,
        "backend_write_timeout_ms": 15000,
        "response_body_mode": "stream",
    });
    if let Some(obj) = extra_proxy_fields.as_object() {
        for (k, v) in obj {
            proxy[k] = v.clone();
        }
    }
    let config = json!({
        "version": "1",
        "proxies": [proxy],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [{
            "id": "stream-latency-logger",
            "plugin_name": "stdout_logging",
            "scope": "global",
            "enabled": true,
            "config": {},
        }],
    });
    serde_yaml::to_string(&config).expect("serialize yaml")
}

fn extract_f64_field(text: &str, field: &str) -> Option<f64> {
    for sep in ["\":", "\\\":"] {
        let needle = format!("{field}{sep}");
        if let Some(pos) = text.find(&needle) {
            let tail = text[pos + needle.len()..].trim_start();
            let end = tail
                .find(|c: char| !(c.is_ascii_digit() || c == '.' || c == '-' || c == 'e'))
                .unwrap_or(tail.len());
            if let Ok(v) = tail[..end].parse::<f64>() {
                return Some(v);
            }
        }
    }
    None
}

fn extract_bool_field(text: &str, field: &str) -> Option<bool> {
    for sep in ["\":", "\\\":"] {
        let needle = format!("{field}{sep}");
        if let Some(pos) = text.find(&needle) {
            let tail = text[pos + needle.len()..].trim_start();
            if tail.starts_with("true") {
                return Some(true);
            }
            if tail.starts_with("false") {
                return Some(false);
            }
        }
    }
    None
}

/// Select the intended transaction summary by unique path/proxy marker.
/// Do not take the first similarly-named field from unrelated probe/startup lines.
fn find_summary_for_marker<'a>(logs: &'a str, marker: &str) -> Option<&'a str> {
    let path_needle = format!("\"request_path\":\"/api/{marker}");
    let path_needle_esc = format!("\\\"request_path\\\":\\\"/api/{marker}");
    for line in logs.lines() {
        let matches_marker = line.contains(&path_needle)
            || line.contains(&path_needle_esc)
            || line.contains(marker);
        if matches_marker
            && line.contains("latency_gateway_overhead_ms")
            && (line.contains("\"response_streamed\":true")
                || line.contains("\\\"response_streamed\\\":true")
                || line.contains("response_streamed\":true")
                || line.contains("response_streamed\\\":true"))
        {
            return Some(line);
        }
    }
    // Fallback: multi-line / concatenated capture without clean newlines.
    if let Some(pos) = logs.find(marker) {
        let window_start = pos.saturating_sub(200);
        let window = &logs[window_start..];
        if window.contains("latency_gateway_overhead_ms") {
            return Some(window);
        }
    }
    None
}

fn assert_streamed_unknown_gateway_contract(scenario: &str, summary: &str, expect_disconnect: bool) {
    let streamed = extract_bool_field(summary, "response_streamed").unwrap_or(false);
    assert!(
        streamed,
        "{scenario}: expected response_streamed=true; summary:\n{summary}"
    );

    let backend_total = extract_f64_field(summary, "latency_backend_total_ms")
        .unwrap_or_else(|| panic!("{scenario}: latency_backend_total_ms missing"));
    let gateway_processing = extract_f64_field(summary, "latency_gateway_processing_ms")
        .unwrap_or_else(|| panic!("{scenario}: latency_gateway_processing_ms missing"));
    let gateway_overhead = extract_f64_field(summary, "latency_gateway_overhead_ms")
        .unwrap_or_else(|| panic!("{scenario}: latency_gateway_overhead_ms missing"));
    let total = extract_f64_field(summary, "latency_total_ms")
        .unwrap_or_else(|| panic!("{scenario}: latency_total_ms missing"));
    let ttfb = extract_f64_field(summary, "latency_backend_ttfb_ms")
        .unwrap_or_else(|| panic!("{scenario}: latency_backend_ttfb_ms missing"));

    assert_eq!(
        backend_total, STREAM_UNKNOWN,
        "{scenario}: streaming backend total must stay unknown; summary:\n{summary}"
    );
    assert_eq!(
        gateway_processing, STREAM_UNKNOWN,
        "{scenario}: gateway processing must not absorb streamed body lifetime; summary:\n{summary}"
    );
    assert_eq!(
        gateway_overhead, STREAM_UNKNOWN,
        "{scenario}: gateway overhead must not absorb streamed body lifetime; summary:\n{summary}"
    );
    assert!(
        total >= BODY_DELAY.as_secs_f64() * 1000.0 * 0.5,
        "{scenario}: total should reflect streamed lifetime (>= ~half the injected delay); total={total}; summary:\n{summary}"
    );
    assert!(
        ttfb >= 0.0 && ttfb < BODY_DELAY.as_secs_f64() * 1000.0,
        "{scenario}: TTFB should remain a first-byte observation (got {ttfb}); summary:\n{summary}"
    );

    if expect_disconnect {
        assert_eq!(
            extract_bool_field(summary, "client_disconnected"),
            Some(true),
            "{scenario}: expected client_disconnected; summary:\n{summary}"
        );
    } else {
        assert_eq!(
            extract_bool_field(summary, "body_completed"),
            Some(true),
            "{scenario}: expected body_completed; summary:\n{summary}"
        );
    }
}

async fn wait_for_marked_summary(harness: &GatewayHarness, marker: &str) -> String {
    harness
        .wait_for_log_contains(
            &|logs: &str| find_summary_for_marker(logs, marker).is_some(),
            Duration::from_secs(12),
        )
        .await
}

fn large_payload() -> Vec<u8> {
    vec![b'x'; SLOW_CLIENT_PAYLOAD_BYTES]
}

fn gateway_http_port(harness: &GatewayHarness) -> u16 {
    harness
        .proxy_base_url()
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
        .expect("gateway port")
}

fn write_frontend_certs(scratch: &std::path::Path) -> (String, String) {
    let ca = TestCa::new("stream-latency-h3-frontend").expect("ca");
    let (cert, key) = ca.valid().expect("leaf");
    let cert_path = scratch.join("gw.cert.pem");
    let key_path = scratch.join("gw.key.pem");
    std::fs::write(&cert_path, &cert).expect("write cert");
    std::fs::write(&key_path, &key).expect("write key");
    (
        cert_path.to_string_lossy().into_owned(),
        key_path.to_string_lossy().into_owned(),
    )
}

async fn spawn_native_h3_logging_gateway(
    backend_port: u16,
    proxy_id: &str,
) -> (GatewayHarness, u16) {
    let mut last_err = String::new();
    for _ in 0..5 {
        let reservation = reserve_port().await.expect("reserve https port");
        let https_port = reservation.port;
        drop(reservation);

        let scratch = tempfile::tempdir().expect("scratch");
        let (cert_path, key_path) = write_frontend_certs(scratch.path());
        let yaml = logging_proxy_config(backend_port, proxy_id, "/api", json!({}));

        match GatewayHarness::builder()
            .file_config(yaml)
            .log_level("info")
            .capture_output()
            .env("RUST_LOG", "info")
            .env("FERRUM_ENABLE_HTTP3", "true")
            .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
            .env("FERRUM_FRONTEND_TLS_CERT_PATH", cert_path)
            .env("FERRUM_FRONTEND_TLS_KEY_PATH", key_path)
            .env("FERRUM_TLS_NO_VERIFY", "true")
            .env("FERRUM_POOL_WARMUP_ENABLED", "false")
            .spawn()
            .await
        {
            Ok(harness) => {
                Box::leak(Box::new(scratch));
                return (harness, https_port);
            }
            Err(e) => last_err = e.to_string(),
        }
    }
    panic!("failed to spawn native H3 logging gateway after retries: {last_err}");
}

fn spawn_http1_scripted(
    listener: tokio::net::TcpListener,
    pace: Pace,
    outcome: Outcome,
) -> ScriptedHttp1Backend {
    let mut builder = ScriptedHttp1Backend::builder(listener)
        .step(HttpStep::ExpectRequest(RequestMatcher::any()))
        .step(HttpStep::RespondStatus {
            status: 200,
            reason: "OK".into(),
        })
        .step(HttpStep::RespondHeader {
            name: "Transfer-Encoding".into(),
            value: "chunked".into(),
        })
        .step(HttpStep::RespondHeader {
            name: "Content-Type".into(),
            value: "application/octet-stream".into(),
        })
        .step(HttpStep::RespondHeader {
            name: "Connection".into(),
            value: "close".into(),
        });

    match pace {
        Pace::SlowBackend => {
            let stall = if outcome.expect_disconnect() {
                Duration::from_secs(5)
            } else {
                BODY_DELAY
            };
            builder = builder
                .step(HttpStep::RespondBodyChunk(b"5\r\nhello\r\n".to_vec()))
                .step(HttpStep::Sleep(stall))
                .step(HttpStep::RespondBodyChunk(b"5\r\nworld\r\n".to_vec()))
                .step(HttpStep::RespondBodyChunk(b"0\r\n\r\n".to_vec()))
                .step(HttpStep::RespondBodyEnd);
        }
        Pace::SlowClient => {
            let body = large_payload();
            let chunk_header = format!("{:x}\r\n", body.len());
            let mut framed = Vec::with_capacity(chunk_header.len() + body.len() + 7);
            framed.extend_from_slice(chunk_header.as_bytes());
            framed.extend_from_slice(&body);
            framed.extend_from_slice(b"\r\n0\r\n\r\n");
            builder = builder
                .step(HttpStep::RespondBodyChunk(framed))
                .step(HttpStep::RespondBodyEnd);
        }
    }

    builder.spawn().expect("spawn http1 backend")
}

fn spawn_h2_scripted(
    listener: tokio::net::TcpListener,
    pace: Pace,
    outcome: Outcome,
) -> ScriptedH2Backend {
    let mut builder = ScriptedH2Backend::builder_plain(listener)
        .step(H2Step::ExpectHeaders(MatchHeaders::any()))
        .step(H2Step::DrainRequestBody)
        .step(H2Step::RespondHeaders(vec![
            (":status", "200".into()),
            ("content-type", "application/octet-stream".into()),
        ]));

    match pace {
        Pace::SlowBackend => {
            let stall = if outcome.expect_disconnect() {
                Duration::from_secs(5)
            } else {
                BODY_DELAY
            };
            builder = builder
                .step(H2Step::RespondData {
                    data: Bytes::from_static(b"ping"),
                    end_stream: false,
                })
                .step(H2Step::Sleep(stall))
                .step(H2Step::RespondData {
                    data: Bytes::from_static(b"pong"),
                    end_stream: true,
                });
        }
        Pace::SlowClient => {
            builder = builder.step(H2Step::RespondData {
                data: Bytes::from(large_payload()),
                end_stream: true,
            });
        }
    }

    builder.spawn().expect("spawn h2 backend")
}

fn spawn_grpc_scripted(
    listener: tokio::net::TcpListener,
    pace: Pace,
    outcome: Outcome,
) -> ScriptedGrpcBackend {
    let mut builder = ScriptedGrpcBackend::builder_plain(listener)
        .step(GrpcStep::AcceptRpc(MatchRpc::any()))
        .step(GrpcStep::SendInitialHeaders);

    match pace {
        Pace::SlowBackend => {
            let stall = if outcome.expect_disconnect() {
                Duration::from_secs(5)
            } else {
                BODY_DELAY
            };
            builder = builder
                .step(GrpcStep::RespondMessage(Bytes::from_static(b"a")))
                .step(GrpcStep::Sleep(stall))
                .step(GrpcStep::RespondStatus {
                    code: 0,
                    message: "",
                });
        }
        Pace::SlowClient => {
            builder = builder
                .step(GrpcStep::RespondMessage(Bytes::from(large_payload())))
                .step(GrpcStep::RespondStatus {
                    code: 0,
                    message: "",
                });
        }
    }

    builder.spawn().expect("spawn grpc backend")
}

async fn h1_drive(
    harness: &GatewayHarness,
    path: &str,
    pace: Pace,
    outcome: Outcome,
) {
    let url = harness.proxy_url(path);
    match (pace, outcome) {
        (Pace::SlowBackend, Outcome::Complete) => {
            let client = harness.http_client().expect("client");
            let resp = client.get(&url).await.expect("response");
            assert_eq!(resp.status, StatusCode::OK);
            assert!(resp.body_text().contains("hello"));
            assert!(resp.body_text().contains("world"));
        }
        (Pace::SlowBackend, Outcome::Disconnect) => {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_millis(250))
                .build()
                .expect("client");
            let _ = client.get(&url).send().await;
        }
        (Pace::SlowClient, outcome) => {
            h1_slow_client_raw(&url, outcome).await;
        }
    }
}

async fn h1_slow_client_raw(url: &str, outcome: Outcome) {
    let parsed: http::Uri = url.parse().expect("url");
    let host = parsed.host().unwrap_or("127.0.0.1");
    let port = parsed.port_u16().expect("port");
    let path = parsed
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");

    let mut stream = TcpStream::connect((host, port))
        .await
        .expect("connect gateway");
    let _ = stream.set_nodelay(true);
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await.expect("write req");

    let mut buf = vec![0u8; 16 * 1024];
    let mut collected = Vec::new();
    // Read response headers + an initial body slice so the gateway has begun
    // streaming, then stop reading to create TCP backpressure.
    loop {
        let n = stream.read(&mut buf).await.expect("read");
        assert!(n > 0, "unexpected EOF before headers");
        collected.extend_from_slice(&buf[..n]);
        if collected.windows(4).any(|w| w == b"\r\n\r\n") && collected.len() > 64 {
            break;
        }
        assert!(
            collected.len() < SLOW_CLIENT_PAYLOAD_BYTES,
            "headers never arrived"
        );
    }

    tokio::time::sleep(BODY_DELAY).await;

    match outcome {
        Outcome::Disconnect => {
            // Drop without draining — gateway should observe client disconnect.
            drop(stream);
        }
        Outcome::Complete => {
            loop {
                let n = stream.read(&mut buf).await.expect("drain");
                if n == 0 {
                    break;
                }
                collected.extend_from_slice(&buf[..n]);
            }
            assert!(
                collected.len() > SLOW_CLIENT_PAYLOAD_BYTES / 2,
                "expected large streamed body, got {} bytes",
                collected.len()
            );
        }
    }
}

async fn h2_drive(harness: &GatewayHarness, path: &str, pace: Pace, outcome: Outcome) {
    let port = gateway_http_port(harness);
    let url = format!("http://127.0.0.1:{port}{path}");
    match (pace, outcome) {
        (Pace::SlowBackend, Outcome::Complete) => {
            let client = Http2Client::h2c_prior_knowledge().expect("h2c client");
            let resp = client.get(&url).await.expect("h2 response");
            assert_eq!(resp.status, StatusCode::OK);
        }
        (Pace::SlowBackend, Outcome::Disconnect) => {
            h2_live_stream(&url, /*slow_read=*/ false, Outcome::Disconnect).await;
        }
        (Pace::SlowClient, outcome) => {
            h2_live_stream(&url, /*slow_read=*/ true, outcome).await;
        }
    }
}

async fn h2_live_stream(url: &str, slow_read: bool, outcome: Outcome) {
    use h2::client as h2_client;

    let parsed: http::Uri = url.parse().expect("url");
    let host = parsed.host().unwrap_or("127.0.0.1").to_string();
    let port = parsed.port_u16().expect("port");
    let stream = TcpStream::connect((host.as_str(), port))
        .await
        .expect("connect h2c");
    let _ = stream.set_nodelay(true);
    let (mut send_req, connection) = h2_client::handshake(stream)
        .await
        .expect("h2 handshake");
    let conn_task = tokio::spawn(connection);

    let request = Request::builder()
        .method("GET")
        .uri(url)
        .body(())
        .expect("build request");
    let (response_fut, _) = send_req
        .send_request(request, true)
        .expect("send_request");
    let response = tokio::time::timeout(Duration::from_secs(20), response_fut)
        .await
        .expect("response timeout")
        .expect("response error");
    assert_eq!(response.status(), http::StatusCode::OK);
    let (_parts, mut body_stream) = response.into_parts();

    let first = tokio::time::timeout(Duration::from_secs(10), body_stream.data())
        .await
        .expect("first frame timeout")
        .expect("first frame missing")
        .expect("first frame error");
    if !slow_read {
        let _ = body_stream.flow_control().release_capacity(first.len());
    }

    if slow_read {
        // Withhold WINDOW_UPDATE so stream-level flow control creates real
        // downstream backpressure for the large slow-client payload.
        tokio::time::sleep(BODY_DELAY).await;
    } else {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    match outcome {
        Outcome::Disconnect => {
            drop(body_stream);
            drop(send_req);
            conn_task.abort();
        }
        Outcome::Complete => {
            if slow_read {
                let _ = body_stream.flow_control().release_capacity(first.len());
            }
            loop {
                match body_stream.data().await {
                    Some(Ok(chunk)) => {
                        let _ = body_stream.flow_control().release_capacity(chunk.len());
                    }
                    Some(Err(_)) | None => break,
                }
            }
            drop(send_req);
            conn_task.abort();
        }
    }
}

async fn h3_drive(
    https_port: u16,
    path: &str,
    pace: Pace,
    outcome: Outcome,
) {
    let client = Http3Client::insecure().expect("h3 client");
    let url = format!("https://127.0.0.1:{https_port}{path}");
    let deadline = std::time::Instant::now() + Duration::from_secs(20);

    match (pace, outcome) {
        (Pace::SlowBackend, Outcome::Complete) => {
            let resp = loop {
                match client.get(&url).await {
                    Ok(r) => break r,
                    Err(e) => {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "h3 get never succeeded: {e}"
                        );
                        tokio::time::sleep(Duration::from_millis(150)).await;
                    }
                }
            };
            assert_eq!(resp.status, http::StatusCode::OK);
        }
        (Pace::SlowBackend, Outcome::Disconnect) | (Pace::SlowClient, _) => {
            let mut stream = loop {
                match client
                    .open_response_stream(&url, GetOptions::default())
                    .await
                {
                    Ok(s) => break s,
                    Err(e) => {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "open_response_stream never succeeded: {e}"
                        );
                        tokio::time::sleep(Duration::from_millis(150)).await;
                    }
                }
            };
            let (status, _headers) = stream.recv_response().await.expect("recv response");
            assert_eq!(status, http::StatusCode::OK);
            let first = stream.recv_data().await.expect("first data");
            assert!(first.is_some(), "expected first body chunk");

            if matches!(pace, Pace::SlowClient) {
                tokio::time::sleep(BODY_DELAY).await;
            } else {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }

            match outcome {
                Outcome::Disconnect => {
                    drop(stream);
                }
                Outcome::Complete => {
                    let _ = stream.drain_body().await.expect("drain body");
                }
            }
        }
    }
}

async fn grpc_drive(harness: &GatewayHarness, path: &str, pace: Pace, outcome: Outcome) {
    let port = gateway_http_port(harness);
    match (pace, outcome) {
        (Pace::SlowBackend, Outcome::Complete) => {
            let client = GrpcClient::h2c(format!("127.0.0.1:{port}"));
            let resp = client
                .unary(path, Bytes::from_static(b"x"))
                .await
                .expect("grpc response");
            assert_eq!(resp.http_status, 200);
        }
        (Pace::SlowBackend, Outcome::Disconnect) | (Pace::SlowClient, _) => {
            grpc_live_stream(port, path, matches!(pace, Pace::SlowClient), outcome).await;
        }
    }
}

async fn grpc_live_stream(port: u16, path: &str, slow_read: bool, outcome: Outcome) {
    use h2::client as h2_client;
    use http::HeaderMap;

    let stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect grpc h2c");
    let _ = stream.set_nodelay(true);
    let (mut send_req, connection) = h2_client::handshake(stream).await.expect("h2 handshake");
    let conn_task = tokio::spawn(connection);

    let request = Request::builder()
        .method("POST")
        .uri(format!("http://127.0.0.1:{port}{path}"))
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(())
        .expect("build grpc request");
    let (response_fut, mut req_body) = send_req.send_request(request, false).expect("send_request");
    let mut framed = bytes::BytesMut::with_capacity(6);
    framed.extend_from_slice(&[0, 0, 0, 0, 1, b'x']);
    req_body
        .send_data(framed.freeze(), true)
        .expect("send grpc data");

    let response = tokio::time::timeout(Duration::from_secs(20), response_fut)
        .await
        .expect("response timeout")
        .expect("response error");
    assert_eq!(response.status().as_u16(), 200);
    let (_parts, mut body_stream) = response.into_parts();

    let first = tokio::time::timeout(Duration::from_secs(10), body_stream.data())
        .await
        .expect("first frame timeout")
        .expect("first frame missing")
        .expect("first frame error");
    // Intentionally do NOT release capacity yet on the slow-client path so the
    // stream window creates real backpressure.
    if !slow_read {
        let _ = body_stream.flow_control().release_capacity(first.len());
    }

    if slow_read {
        tokio::time::sleep(BODY_DELAY).await;
    } else {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    match outcome {
        Outcome::Disconnect => {
            drop(body_stream);
            drop(send_req);
            conn_task.abort();
        }
        Outcome::Complete => {
            if slow_read {
                let _ = body_stream.flow_control().release_capacity(first.len());
            }
            loop {
                match body_stream.data().await {
                    Some(Ok(chunk)) => {
                        let _ = body_stream.flow_control().release_capacity(chunk.len());
                    }
                    Some(Err(_)) | None => break,
                }
            }
            let _: Option<HeaderMap> = body_stream.trailers().await.ok().flatten();
            drop(send_req);
            conn_task.abort();
        }
    }
}

async fn run_http_family(
    protocol: &str,
    pace: Pace,
    outcome: Outcome,
    use_h2_backend: bool,
) {
    let marker = scenario_marker(protocol, pace, outcome);
    let path = scenario_path(protocol, pace, outcome);
    let backend_res = reserve_port().await.expect("backend port");
    let backend_port = backend_res.port;
    let listener = backend_res.into_listener();
    // Keep the chosen scripted backend alive for the whole scenario.
    enum LiveBackend {
        H1(ScriptedHttp1Backend),
        H2(ScriptedH2Backend),
    }
    let _backend = if use_h2_backend {
        LiveBackend::H2(spawn_h2_scripted(listener, pace, outcome))
    } else {
        LiveBackend::H1(spawn_http1_scripted(listener, pace, outcome))
    };

    let proxy_id = format!("stream-latency-{marker}");
    let harness = GatewayHarness::builder()
        .file_config(logging_proxy_config(
            backend_port,
            &proxy_id,
            "/api",
            json!({}),
        ))
        .log_level("info")
        .env("RUST_LOG", "info")
        .env("FERRUM_POOL_WARMUP_ENABLED", "false")
        .capture_output()
        .spawn()
        .await
        .expect("spawn gateway");

    match protocol {
        "h1" => h1_drive(&harness, &path, pace, outcome).await,
        "h2" => h2_drive(&harness, &path, pace, outcome).await,
        other => panic!("unexpected protocol {other}"),
    }

    let logs = wait_for_marked_summary(&harness, &marker).await;
    let summary = find_summary_for_marker(&logs, &marker).unwrap_or_else(|| {
        panic!("{marker}: missing marked streamed summary; logs:\n{logs}")
    });
    assert_streamed_unknown_gateway_contract(&marker, summary, outcome.expect_disconnect());
}

async fn run_native_h3(pace: Pace, outcome: Outcome) {
    let marker = scenario_marker("h3", pace, outcome);
    let path = scenario_path("h3", pace, outcome);
    let backend_res = reserve_port().await.expect("backend port");
    let backend_port = backend_res.port;
    let _backend = spawn_http1_scripted(backend_res.into_listener(), pace, outcome);

    let proxy_id = format!("stream-latency-{marker}");
    let (harness, https_port) = spawn_native_h3_logging_gateway(backend_port, &proxy_id).await;

    h3_drive(https_port, &path, pace, outcome).await;

    let logs = wait_for_marked_summary(&harness, &marker).await;
    let summary = find_summary_for_marker(&logs, &marker).unwrap_or_else(|| {
        panic!("{marker}: missing marked streamed summary; logs:\n{logs}")
    });
    assert_streamed_unknown_gateway_contract(&marker, summary, outcome.expect_disconnect());
}

async fn run_grpc(pace: Pace, outcome: Outcome) {
    let marker = scenario_marker("grpc", pace, outcome);
    // gRPC paths are method paths; keep the unique marker in the service path.
    let path = format!("/grpc/{marker}.Service/Get");
    let backend_res = reserve_port().await.expect("backend port");
    let backend_port = backend_res.port;
    let _backend = spawn_grpc_scripted(backend_res.into_listener(), pace, outcome);

    let proxy_id = format!("stream-latency-{marker}");
    let harness = GatewayHarness::builder()
        .file_config(logging_proxy_config(
            backend_port,
            &proxy_id,
            "/grpc",
            json!({}),
        ))
        .log_level("info")
        .env("RUST_LOG", "info")
        .env("FERRUM_POOL_WARMUP_ENABLED", "false")
        .capture_output()
        .spawn()
        .await
        .expect("spawn gateway");

    grpc_drive(&harness, &path, pace, outcome).await;

    let logs = wait_for_marked_summary(&harness, &marker).await;
    let summary = find_summary_for_marker(&logs, &marker).unwrap_or_else(|| {
        panic!("{marker}: missing marked streamed summary; logs:\n{logs}")
    });
    assert_streamed_unknown_gateway_contract(&marker, summary, outcome.expect_disconnect());
}

// ── HTTP/1.1 ──────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h1_slow_backend_stream_completion_keeps_gateway_sentinel() {
    run_http_family("h1", Pace::SlowBackend, Outcome::Complete, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h1_slow_backend_stream_disconnect_keeps_gateway_sentinel() {
    run_http_family("h1", Pace::SlowBackend, Outcome::Disconnect, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h1_slow_client_stream_completion_keeps_gateway_sentinel() {
    run_http_family("h1", Pace::SlowClient, Outcome::Complete, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h1_slow_client_stream_disconnect_keeps_gateway_sentinel() {
    run_http_family("h1", Pace::SlowClient, Outcome::Disconnect, false).await;
}

// ── HTTP/2 frontend ───────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h2_slow_backend_stream_completion_keeps_gateway_sentinel() {
    run_http_family("h2", Pace::SlowBackend, Outcome::Complete, true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h2_slow_backend_stream_disconnect_keeps_gateway_sentinel() {
    run_http_family("h2", Pace::SlowBackend, Outcome::Disconnect, true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h2_slow_client_stream_completion_keeps_gateway_sentinel() {
    run_http_family("h2", Pace::SlowClient, Outcome::Complete, true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h2_slow_client_stream_disconnect_keeps_gateway_sentinel() {
    run_http_family("h2", Pace::SlowClient, Outcome::Disconnect, true).await;
}

// ── Native HTTP/3 frontend ────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_slow_backend_stream_completion_keeps_gateway_sentinel() {
    run_native_h3(Pace::SlowBackend, Outcome::Complete).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_slow_backend_stream_disconnect_keeps_gateway_sentinel() {
    run_native_h3(Pace::SlowBackend, Outcome::Disconnect).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_slow_client_stream_completion_keeps_gateway_sentinel() {
    run_native_h3(Pace::SlowClient, Outcome::Complete).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_slow_client_stream_disconnect_keeps_gateway_sentinel() {
    run_native_h3(Pace::SlowClient, Outcome::Disconnect).await;
}

// ── Streamed gRPC ─────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn grpc_slow_backend_stream_completion_keeps_gateway_sentinel() {
    run_grpc(Pace::SlowBackend, Outcome::Complete).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn grpc_slow_backend_stream_disconnect_keeps_gateway_sentinel() {
    run_grpc(Pace::SlowBackend, Outcome::Disconnect).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn grpc_slow_client_stream_completion_keeps_gateway_sentinel() {
    run_grpc(Pace::SlowClient, Outcome::Complete).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn grpc_slow_client_stream_disconnect_keeps_gateway_sentinel() {
    run_grpc(Pace::SlowClient, Outcome::Disconnect).await;
}
