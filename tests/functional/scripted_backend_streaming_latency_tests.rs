//! Issue #2532 — streamed terminal latency contract.
//!
//! Slow-backend and slow-client streaming responses must not report unknown
//! concurrent body/client lifetime as gateway processing or gateway overhead.
//! Assertions prefer sentinel ownership (`-1.0`) over timing-only checks.
//!
//! Run with:
//!   cargo build --bin ferrum-edge &&
//!   cargo test --test functional_tests scripted_backend_streaming_latency -- --ignored --nocapture

#![allow(clippy::bool_assert_comparison)]

use crate::scaffolding::backends::{
    GrpcStep, H2Step, H3Step, H3TlsConfig, HttpStep, MatchHeaders, MatchRpc, RequestMatcher,
    ScriptedGrpcBackend, ScriptedH2Backend, ScriptedH3Backend, ScriptedHttp1Backend, TcpStep,
    TlsConfig,
};
use crate::scaffolding::certs::TestCa;
use crate::scaffolding::clients::GrpcClient;
use crate::scaffolding::harness::GatewayHarness;
use crate::scaffolding::ports::{reserve_colocated_tcp_udp, reserve_port};
use bytes::Bytes;
use reqwest::StatusCode;
use serde_json::json;
use std::time::Duration;

const BODY_DELAY: Duration = Duration::from_millis(400);
const STREAM_UNKNOWN: f64 = -1.0;

fn logging_proxy_config(backend_port: u16, extra_proxy_fields: serde_json::Value) -> String {
    let mut proxy = json!({
        "id": "scripted",
        "listen_path": "/api",
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": backend_port,
        "strip_listen_path": true,
        "backend_connect_timeout_ms": 2000,
        "backend_read_timeout_ms": 10000,
        "backend_write_timeout_ms": 10000,
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

fn extract_f64_field(logs: &str, field: &str) -> Option<f64> {
    for sep in ["\":", "\\\":"] {
        let needle = format!("{field}{sep}");
        if let Some(pos) = logs.find(&needle) {
            let tail = logs[pos + needle.len()..].trim_start();
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

fn extract_bool_field(logs: &str, field: &str) -> Option<bool> {
    for sep in ["\":", "\\\":"] {
        let needle = format!("{field}{sep}");
        if let Some(pos) = logs.find(&needle) {
            let tail = logs[pos + needle.len()..].trim_start();
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

fn assert_streamed_unknown_gateway_contract(logs: &str, expect_disconnect: bool) {
    let streamed = extract_bool_field(logs, "response_streamed").unwrap_or(false);
    assert!(streamed, "expected response_streamed=true; logs:\n{logs}");

    let backend_total = extract_f64_field(logs, "latency_backend_total_ms")
        .expect("latency_backend_total_ms missing");
    let gateway_processing = extract_f64_field(logs, "latency_gateway_processing_ms")
        .expect("latency_gateway_processing_ms missing");
    let gateway_overhead = extract_f64_field(logs, "latency_gateway_overhead_ms")
        .expect("latency_gateway_overhead_ms missing");
    let total = extract_f64_field(logs, "latency_total_ms").expect("latency_total_ms missing");
    let ttfb =
        extract_f64_field(logs, "latency_backend_ttfb_ms").expect("latency_backend_ttfb_ms missing");

    assert_eq!(
        backend_total, STREAM_UNKNOWN,
        "streaming backend total must stay unknown; logs:\n{logs}"
    );
    assert_eq!(
        gateway_processing, STREAM_UNKNOWN,
        "gateway processing must not absorb streamed body lifetime; logs:\n{logs}"
    );
    assert_eq!(
        gateway_overhead, STREAM_UNKNOWN,
        "gateway overhead must not absorb streamed body lifetime; logs:\n{logs}"
    );
    assert!(
        total >= BODY_DELAY.as_secs_f64() * 1000.0 * 0.5,
        "total should reflect streamed lifetime (>= ~half the injected delay); total={total}; logs:\n{logs}"
    );
    assert!(
        ttfb >= 0.0 && ttfb < BODY_DELAY.as_secs_f64() * 1000.0,
        "TTFB should remain a first-byte observation (got {ttfb}); logs:\n{logs}"
    );

    if expect_disconnect {
        assert_eq!(
            extract_bool_field(logs, "client_disconnected"),
            Some(true),
            "expected client_disconnected; logs:\n{logs}"
        );
    }
}

async fn wait_for_streamed_summary(harness: &GatewayHarness) -> String {
    harness
        .wait_for_log_contains(
            &|logs: &str| {
                extract_bool_field(logs, "response_streamed") == Some(true)
                    && extract_f64_field(logs, "latency_gateway_overhead_ms").is_some()
            },
            Duration::from_secs(8),
        )
        .await
}

// ── HTTP/1.1 ──────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h1_slow_backend_stream_completion_keeps_gateway_sentinel() {
    let backend_res = reserve_port().await.expect("backend port");
    let backend_port = backend_res.port;
    let _backend = ScriptedHttp1Backend::builder(backend_res.into_listener())
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
            value: "text/plain".into(),
        })
        .step(HttpStep::RespondHeader {
            name: "Connection".into(),
            value: "close".into(),
        })
        .step(HttpStep::RespondBodyChunk(b"4\r\nping\r\n".to_vec()))
        .step(HttpStep::Sleep(BODY_DELAY))
        .step(HttpStep::RespondBodyChunk(b"4\r\npong\r\n".to_vec()))
        .step(HttpStep::RespondBodyChunk(b"0\r\n\r\n".to_vec()))
        .step(HttpStep::RespondBodyEnd)
        .spawn()
        .expect("spawn http backend");

    let harness = GatewayHarness::builder()
        .file_config(logging_proxy_config(backend_port, json!({})))
        .log_level("info")
        .env("RUST_LOG", "info")
        .capture_output()
        .spawn()
        .await
        .expect("spawn gateway");

    let client = harness.http_client().expect("client");
    let resp = client
        .get(&harness.proxy_url("/api/stream"))
        .await
        .expect("response");
    assert_eq!(resp.status, StatusCode::OK);
    assert!(resp.body_text().contains("ping"));
    assert!(resp.body_text().contains("pong"));

    let logs = wait_for_streamed_summary(&harness).await;
    assert_streamed_unknown_gateway_contract(&logs, false);
    assert_eq!(extract_bool_field(&logs, "body_completed"), Some(true));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h1_slow_backend_stream_disconnect_keeps_gateway_sentinel() {
    let backend_res = reserve_port().await.expect("backend port");
    let backend_port = backend_res.port;
    let _backend = ScriptedHttp1Backend::builder(backend_res.into_listener())
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
            name: "Connection".into(),
            value: "close".into(),
        })
        .step(HttpStep::RespondBodyChunk(b"4\r\nping\r\n".to_vec()))
        .step(HttpStep::Sleep(Duration::from_secs(5)))
        .step(HttpStep::RespondBodyChunk(b"4\r\npong\r\n".to_vec()))
        .step(HttpStep::RespondBodyChunk(b"0\r\n\r\n".to_vec()))
        .step(HttpStep::RespondBodyEnd)
        .spawn()
        .expect("spawn http backend");

    let harness = GatewayHarness::builder()
        .file_config(logging_proxy_config(backend_port, json!({})))
        .log_level("info")
        .env("RUST_LOG", "info")
        .capture_output()
        .spawn()
        .await
        .expect("spawn gateway");

    let url = harness.proxy_url("/api/stream");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(250))
        .build()
        .expect("client");
    let _ = client.get(&url).send().await;

    let logs = wait_for_streamed_summary(&harness).await;
    assert_streamed_unknown_gateway_contract(&logs, true);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h1_slow_client_stream_completion_keeps_gateway_sentinel() {
    let backend_res = reserve_port().await.expect("backend port");
    let backend_port = backend_res.port;
    let _backend = ScriptedHttp1Backend::builder(backend_res.into_listener())
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
            name: "Connection".into(),
            value: "close".into(),
        })
        .step(HttpStep::RespondBodyChunk(b"4\r\nping\r\n".to_vec()))
        .step(HttpStep::RespondBodyChunk(b"4\r\npong\r\n".to_vec()))
        .step(HttpStep::RespondBodyChunk(b"0\r\n\r\n".to_vec()))
        .step(HttpStep::RespondBodyEnd)
        .spawn()
        .expect("spawn http backend");

    let harness = GatewayHarness::builder()
        .file_config(logging_proxy_config(backend_port, json!({})))
        .log_level("info")
        .env("RUST_LOG", "info")
        .capture_output()
        .spawn()
        .await
        .expect("spawn gateway");

    let url = harness.proxy_url("/api/stream");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("client");
    let mut response = client.get(&url).send().await.expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let mut saw_bytes = false;
    while let Some(chunk) = response.chunk().await.expect("chunk") {
        if !chunk.is_empty() {
            saw_bytes = true;
            tokio::time::sleep(BODY_DELAY).await;
        }
    }
    assert!(saw_bytes, "expected body bytes");

    let logs = wait_for_streamed_summary(&harness).await;
    assert_streamed_unknown_gateway_contract(&logs, false);
}

// ── HTTP/2 ────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h2_slow_backend_stream_completion_keeps_gateway_sentinel() {
    let backend_res = reserve_port().await.expect("backend port");
    let backend_port = backend_res.port;
    let _backend = ScriptedH2Backend::builder_plain(backend_res.into_listener())
        .step(H2Step::ExpectHeaders(MatchHeaders::any()))
        .step(H2Step::DrainRequestBody)
        .step(H2Step::RespondHeaders(vec![
            (":status", "200".into()),
            ("content-type", "text/plain".into()),
        ]))
        .step(H2Step::RespondData {
            data: Bytes::from_static(b"ping"),
            end_stream: false,
        })
        .step(H2Step::Sleep(BODY_DELAY))
        .step(H2Step::RespondData {
            data: Bytes::from_static(b"pong"),
            end_stream: true,
        })
        .spawn()
        .expect("spawn h2 backend");

    let harness = GatewayHarness::builder()
        .file_config(logging_proxy_config(backend_port, json!({})))
        .log_level("info")
        .env("RUST_LOG", "info")
        .capture_output()
        .spawn()
        .await
        .expect("spawn gateway");

    let client = harness.http_client().expect("client");
    let resp = client
        .get(&harness.proxy_url("/api/stream"))
        .await
        .expect("response");
    assert_eq!(resp.status, StatusCode::OK);

    let logs = wait_for_streamed_summary(&harness).await;
    assert_streamed_unknown_gateway_contract(&logs, false);
}

// ── HTTP/3 (H1 frontend → native H3 backend via capability registry) ──────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_slow_backend_stream_completion_keeps_gateway_sentinel() {
    let ca = TestCa::new("stream-latency-h3").expect("ca");
    let (cert, key) = ca.valid().expect("leaf");
    let (tcp_res, udp_res) = reserve_colocated_tcp_udp()
        .await
        .expect("colocated tcp/udp");
    let backend_port = tcp_res.port;

    // TLS sidecar so non-H3 probes still succeed while the QUIC listener
    // serves the slow streamed body.
    let _tcp_backend = crate::scaffolding::ScriptedTlsBackend::builder(
        tcp_res.into_listener(),
        TlsConfig::new(cert.clone(), key.clone())
            .with_alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
    )
    .step(TcpStep::ReadUntil(b"\r\n\r\n".to_vec()))
    .step(TcpStep::Write(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec(),
    ))
    .step(TcpStep::Drop)
    .spawn()
    .expect("spawn TLS sidecar");

    let _h3_backend =
        ScriptedH3Backend::builder(udp_res.into_socket(), H3TlsConfig::new(cert, key))
            .step(H3Step::AcceptHandshake)
            .step(H3Step::AcceptStream)
            .step(H3Step::RespondHeaders(vec![
                (":status", "200".into()),
                ("content-type", "text/plain".into()),
            ]))
            .step(H3Step::RespondData(Bytes::from_static(b"ping")))
            .step(H3Step::StallFor(BODY_DELAY))
            .step(H3Step::RespondData(Bytes::from_static(b"pong")))
            .step(H3Step::RespondTrailers(vec![]))
            .spawn()
            .expect("spawn h3 backend");

    let yaml = logging_proxy_config(
        backend_port,
        json!({
            "backend_scheme": "https",
            "backend_tls_verify_server_cert": false,
        }),
    );
    let harness = GatewayHarness::builder()
        .file_config(yaml)
        .pool_warmup_enabled(true)
        .env("FERRUM_TLS_NO_VERIFY", "true")
        .log_level("info")
        .env("RUST_LOG", "info")
        .capture_output()
        .spawn()
        .await
        .expect("spawn gateway");

    let client = harness.http_client().expect("client");
    let resp = client
        .get(&harness.proxy_url("/api/stream"))
        .await
        .expect("response");
    assert_eq!(resp.status, StatusCode::OK);

    let logs = wait_for_streamed_summary(&harness).await;
    assert_streamed_unknown_gateway_contract(&logs, false);
}

// ── gRPC ──────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn grpc_slow_backend_stream_completion_keeps_gateway_sentinel() {
    let backend_res = reserve_port().await.expect("backend port");
    let backend_port = backend_res.port;
    let _backend = ScriptedGrpcBackend::builder_plain(backend_res.into_listener())
        .step(GrpcStep::AcceptRpc(MatchRpc::any()))
        .step(GrpcStep::SendInitialHeaders)
        .step(GrpcStep::RespondMessage(Bytes::from_static(b"a")))
        .step(GrpcStep::Sleep(BODY_DELAY))
        .step(GrpcStep::RespondStatus {
            code: 0,
            message: "",
        })
        .spawn()
        .expect("spawn grpc backend");

    let yaml = logging_proxy_config(
        backend_port,
        json!({
            "id": "scripted-grpc",
            "listen_path": "/grpc",
            "strip_listen_path": true,
        }),
    );
    let harness = GatewayHarness::builder()
        .file_config(yaml)
        .log_level("info")
        .env("RUST_LOG", "info")
        .capture_output()
        .spawn()
        .await
        .expect("spawn gateway");

    let gw_port = harness
        .proxy_base_url()
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
        .expect("gateway port");
    let client = GrpcClient::h2c(format!("127.0.0.1:{gw_port}"));
    let resp = client
        .unary("/grpc/demo.Service/Get", Bytes::from_static(b"x"))
        .await
        .expect("grpc response");
    assert_eq!(resp.http_status, 200);

    let logs = wait_for_streamed_summary(&harness).await;
    assert_streamed_unknown_gateway_contract(&logs, false);
}
