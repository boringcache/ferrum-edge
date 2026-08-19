//! In-process HTTP-family backend timeout enforcement (#4055 / #4057).
//!
//! `#4055` — a backend that accepts and never reads must surface a 504 write
//! timeout near `backend_write_timeout_ms`, not hang until the client gives up.
//! `#4057` — an SSE/chunked stall *after* headers must wait out
//! `backend_read_timeout_ms` (idle-between-frames) instead of tearing the
//! stream down immediately as `request_error`. Header-only stalls already 504
//! (`tests/integration/scripted_backend_smoke_tests.rs`, closed #3922).
//!
//! Protocol-path coverage beyond H1 lives in the scripted-backend functional
//! suite (`scripted_backend_tests.rs`, `scripted_backend_h2_tests.rs`,
//! `scripted_backend_h3_tests.rs`).

use crate::scaffolding::backends::{HttpStep, ScriptedHttp1Backend, ScriptedTcpBackend, TcpStep};
use crate::scaffolding::file_mode_yaml_for_backend_with;
use crate::scaffolding::harness::GatewayHarness;
use crate::scaffolding::ports::reserve_port;
use futures_util::StreamExt;
use serde_json::json;
use std::time::{Duration, Instant};

const WRITE_TIMEOUT_MS: u64 = 800;
const READ_TIMEOUT_MS: u64 = 800;
const UPLOAD_STALL_BYTES: usize = 2 * 1024 * 1024;
const SSE_FIRST_EVENT: &[u8] = b"data: hello\r\n\n";

fn assert_timeout_envelope(elapsed: Duration, timeout_ms: u64) {
    let expected = Duration::from_millis(timeout_ms);
    let floor = expected.saturating_sub(Duration::from_millis(200));
    let ceiling = expected + Duration::from_millis(1500);
    assert!(
        elapsed >= floor,
        "timed out too fast: {elapsed:?} < floor {floor:?} (timeout was {timeout_ms}ms)"
    );
    assert!(
        elapsed <= ceiling,
        "timed out too slowly: {elapsed:?} > ceiling {ceiling:?} (timeout was {timeout_ms}ms)"
    );
}

fn gateway_error_header(headers: &reqwest::header::HeaderMap) -> Option<&str> {
    headers.get("x-gateway-error").and_then(|v| v.to_str().ok())
}

fn timeout_overrides(read_ms: u64, write_ms: u64) -> serde_json::Value {
    json!({
        "backend_read_timeout_ms": read_ms,
        "backend_write_timeout_ms": write_ms,
    })
}

// #4055: backend accepts and never reads. `HttpStep::ExpectRequest` would
// drain the POST, so the fixture is raw TCP Accept (implicit) + Sleep.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn in_process_backend_write_timeout_maps_to_504_backend_timeout() {
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let _backend = ScriptedTcpBackend::builder(reservation.into_listener())
        .step(TcpStep::Sleep(Duration::from_secs(30)))
        .spawn()
        .expect("spawn");

    let yaml =
        file_mode_yaml_for_backend_with(backend_port, timeout_overrides(8_000, WRITE_TIMEOUT_MS));
    let harness = GatewayHarness::builder()
        .mode_in_process()
        .file_config(yaml)
        .spawn()
        .await
        .expect("spawn gateway");

    let client = harness.http_client().expect("client");
    let started = Instant::now();
    let resp = client
        .as_reqwest()
        .post(harness.proxy_url("/api/twrite"))
        .header("content-type", "application/octet-stream")
        .body(vec![b'x'; UPLOAD_STALL_BYTES])
        .send()
        .await
        .expect("gateway returns a response");
    let elapsed = started.elapsed();
    let status = resp.status();
    let header = gateway_error_header(resp.headers()).map(str::to_owned);
    let body = resp.text().await.expect("body");

    assert_eq!(
        status,
        reqwest::StatusCode::GATEWAY_TIMEOUT,
        "live backend write timeout must be 504, got {status} body={body}"
    );
    assert_eq!(
        header.as_deref(),
        Some("backend_timeout"),
        "timeout must carry X-Gateway-Error=backend_timeout, body={body}"
    );
    assert_eq!(
        body, r#"{"error":"Backend timeout"}"#,
        "timeout body must be timeout-specific"
    );
    assert_timeout_envelope(elapsed, WRITE_TIMEOUT_MS);
}

// Companion: `backend_write_timeout_ms: 0` leaves the upload unbounded, so a
// never-read backend must not 504 at the 800ms watermark.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn in_process_backend_write_timeout_zero_does_not_504() {
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let _backend = ScriptedTcpBackend::builder(reservation.into_listener())
        .step(TcpStep::Sleep(Duration::from_secs(30)))
        .spawn()
        .expect("spawn");

    let yaml = file_mode_yaml_for_backend_with(backend_port, timeout_overrides(8_000, 0));
    let harness = GatewayHarness::builder()
        .mode_in_process()
        .file_config(yaml)
        .spawn()
        .await
        .expect("spawn gateway");

    let client = harness.http_client().expect("client");
    let started = Instant::now();
    let result = tokio::time::timeout(
        Duration::from_millis(1_500),
        client
            .as_reqwest()
            .post(harness.proxy_url("/api/twrite"))
            .header("content-type", "application/octet-stream")
            .body(vec![b'x'; UPLOAD_STALL_BYTES])
            .send(),
    )
    .await;
    let elapsed = started.elapsed();

    match result {
        Err(_) => {
            assert!(
                elapsed >= Duration::from_millis(1_300),
                "zero write timeout must not 504 at the 800ms watermark; \
                 client gave up at {elapsed:?}"
            );
        }
        Ok(Ok(resp)) => {
            assert_ne!(
                resp.status(),
                reqwest::StatusCode::GATEWAY_TIMEOUT,
                "backend_write_timeout_ms=0 must not produce a 504"
            );
        }
        Ok(Err(err)) => {
            panic!("unexpected client error under write-timeout=0: {err}");
        }
    }
}

// #4057: headers + one SSE event + stall. Client sees 200 and the first
// event; the body then aborts near `backend_read_timeout_ms`. A 504 is
// impossible once headers are committed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn in_process_sse_stall_after_first_event_idles_until_read_timeout() {
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let _backend = ScriptedHttp1Backend::builder(reservation.into_listener())
        .step(HttpStep::RespondStatus {
            status: 200,
            reason: "OK".into(),
        })
        .step(HttpStep::RespondHeader {
            name: "Content-Type".into(),
            value: "text/event-stream".into(),
        })
        .step(HttpStep::RespondBodyChunk(SSE_FIRST_EVENT.to_vec()))
        .step(HttpStep::Sleep(Duration::from_secs(30)))
        .spawn()
        .expect("spawn");

    let yaml =
        file_mode_yaml_for_backend_with(backend_port, timeout_overrides(READ_TIMEOUT_MS, 5_000));
    let harness = GatewayHarness::builder()
        .mode_in_process()
        .file_config(yaml)
        .spawn()
        .await
        .expect("spawn gateway");

    let client = harness.http_client().expect("client");
    let started = Instant::now();
    let resp = client
        .as_reqwest()
        .get(harness.proxy_url("/api/ssestall"))
        .header("accept", "text/event-stream")
        .send()
        .await
        .expect("headers");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "committed SSE headers must be 200, not a 504"
    );
    let mut stream = resp.bytes_stream();
    let first = tokio::time::timeout(Duration::from_secs(2), stream.next())
        .await
        .expect("first SSE event bounded")
        .expect("first SSE event present")
        .expect("first SSE event readable");
    assert!(
        first
            .windows(SSE_FIRST_EVENT.len())
            .any(|w| w == SSE_FIRST_EVENT)
            || first
                .windows(b"data: hello".len())
                .any(|w| w == b"data: hello"),
        "first event missing from {:?}; elapsed={:?}",
        first,
        started.elapsed()
    );

    let stall_started = Instant::now();
    let rest = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(item) = stream.next().await {
            item?;
        }
        Ok::<(), reqwest::Error>(())
    })
    .await;
    let stall_elapsed = stall_started.elapsed();
    match rest {
        Ok(Ok(())) => panic!(
            "SSE stall closed cleanly instead of aborting as a read timeout; \
             stall_elapsed={stall_elapsed:?}"
        ),
        Ok(Err(_)) | Err(_) => {
            assert_timeout_envelope(stall_elapsed, READ_TIMEOUT_MS);
        }
    }
}

// Slow-but-progressing SSE must keep the idle watermark fresh. Gaps of 200ms
// under an 800ms read timeout must complete, not be killed as idle.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn in_process_progressing_sse_is_not_killed_by_idle_read_timeout() {
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let body = b"data: a\n\ndata: b\n\ndata: c\n\n".to_vec();
    let _backend = ScriptedHttp1Backend::builder(reservation.into_listener())
        .step(HttpStep::TrickleBody {
            status: 200,
            reason: "OK".into(),
            headers: vec![("Content-Type".into(), "text/event-stream".into())],
            body,
            chunk_size: 8,
            pause: Duration::from_millis(200),
        })
        .spawn()
        .expect("spawn");

    let yaml =
        file_mode_yaml_for_backend_with(backend_port, timeout_overrides(READ_TIMEOUT_MS, 5_000));
    let harness = GatewayHarness::builder()
        .mode_in_process()
        .file_config(yaml)
        .spawn()
        .await
        .expect("spawn gateway");

    let client = harness.http_client().expect("client");
    let resp = client
        .as_reqwest()
        .get(harness.proxy_url("/api/ssetrickle"))
        .header("accept", "text/event-stream")
        .send()
        .await
        .expect("headers");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let bytes = resp.bytes().await.expect("progressing SSE must complete");
    let text = String::from_utf8_lossy(&bytes);
    assert!(
        text.contains("data: a") && text.contains("data: c"),
        "progressing SSE body truncated: {text:?}"
    );
}

// `backend_read_timeout_ms: 0` disables the idle bound: after the first
// event the stream must still be open at 1.5s (the 800ms watermark).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn in_process_sse_read_timeout_zero_stays_open_past_watermark() {
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let _backend = ScriptedHttp1Backend::builder(reservation.into_listener())
        .step(HttpStep::RespondStatus {
            status: 200,
            reason: "OK".into(),
        })
        .step(HttpStep::RespondHeader {
            name: "Content-Type".into(),
            value: "text/event-stream".into(),
        })
        .step(HttpStep::RespondBodyChunk(SSE_FIRST_EVENT.to_vec()))
        .step(HttpStep::Sleep(Duration::from_secs(30)))
        .spawn()
        .expect("spawn");

    let yaml = file_mode_yaml_for_backend_with(backend_port, timeout_overrides(0, 5_000));
    let harness = GatewayHarness::builder()
        .mode_in_process()
        .file_config(yaml)
        .spawn()
        .await
        .expect("spawn gateway");

    let client = harness.http_client().expect("client");
    let resp = client
        .as_reqwest()
        .get(harness.proxy_url("/api/ssestall"))
        .header("accept", "text/event-stream")
        .send()
        .await
        .expect("headers");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let mut stream = resp.bytes_stream();
    let first = tokio::time::timeout(Duration::from_secs(2), stream.next())
        .await
        .expect("first SSE event bounded")
        .expect("first SSE event present")
        .expect("first SSE event readable");
    assert!(
        first
            .windows(b"data: hello".len())
            .any(|w| w == b"data: hello"),
        "first event missing from {first:?}"
    );

    let next = tokio::time::timeout(Duration::from_millis(1_500), stream.next()).await;
    assert!(
        next.is_err(),
        "backend_read_timeout_ms=0 must keep the SSE stream open past 800ms; \
         got {next:?}"
    );
}
