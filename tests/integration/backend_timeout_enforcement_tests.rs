//! In-process HTTP-family backend timeout enforcement (#4055 / #4057 / #4411).
//!
//! `#4055` — a backend that accepts and never reads must surface a 504 write
//! timeout near `backend_write_timeout_ms`, not hang until the client gives up.
//! `#4411` — the same watermark bounds transport write progress AFTER a clean
//! end of stream too: the local send queue is sampled while the response-header
//! wait runs, and a queue that is non-empty and never shrinks is a write stall.
//! `#4057` — an SSE/chunked stall *after* headers must wait out
//! `backend_read_timeout_ms` (idle-between-frames) instead of tearing the
//! stream down immediately as `request_error`. Header-only stalls already 504
//! (`tests/integration/scripted_backend_smoke_tests.rs`, closed #3922).
//!
//! Protocol-path coverage beyond H1 lives in the scripted-backend functional
//! suite (`scripted_backend_tests.rs`, `scripted_backend_h2_tests.rs`,
//! `scripted_backend_h3_tests.rs`).

use crate::scaffolding::backends::{
    HttpStep, RequestMatcher, ScriptedHttp1Backend, ScriptedTcpBackend, TcpStep,
};
use crate::scaffolding::file_mode_yaml_for_backend_with;
use crate::scaffolding::harness::GatewayHarness;
use crate::scaffolding::ports::reserve_port;
use futures_util::StreamExt;
use serde_json::json;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const WRITE_TIMEOUT_MS: u64 = 800;
const READ_TIMEOUT_MS: u64 = 800;
// Pin the listener before accept so the backend cannot autotune a large receive
// window. The upload remains larger than ordinary sender buffers, guaranteeing
// that a backend which never reads eventually backpressures the upload pump.
const BACKEND_RECEIVE_BUFFER_BYTES: usize = 1024;
const UPLOAD_STALL_BYTES: usize = 8 * 1024 * 1024;
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

fn timeout_overrides(read_ms: u64, write_ms: u64) -> serde_json::Value {
    json!({
        "backend_read_timeout_ms": read_ms,
        "backend_write_timeout_ms": write_ms,
    })
}

fn gateway_error_header(headers: &reqwest::header::HeaderMap) -> Option<&str> {
    headers.get("x-gateway-error").and_then(|v| v.to_str().ok())
}

async fn raw_h1_upload_response(harness: &GatewayHarness) -> (String, Duration) {
    let url = reqwest::Url::parse(harness.proxy_base_url()).expect("proxy URL");
    let port = url.port().expect("proxy URL has explicit port");
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect to proxy");
    let request_head = format!(
        "POST /api/twrite HTTP/1.1\r\n\
         Host: 127.0.0.1\r\n\
         Content-Type: application/octet-stream\r\n\
         Content-Length: {UPLOAD_STALL_BYTES}\r\n\
         Connection: close\r\n\r\n"
    );
    let started = Instant::now();
    stream
        .write_all(request_head.as_bytes())
        .await
        .expect("write request head");
    let (mut reader, mut writer) = stream.into_split();
    let upload = tokio::spawn(async move {
        let chunk = vec![b'x'; 64 * 1024];
        let mut remaining = UPLOAD_STALL_BYTES;
        while remaining > 0 {
            let len = remaining.min(chunk.len());
            writer.write_all(&chunk[..len]).await?;
            remaining -= len;
        }
        std::io::Result::Ok(())
    });

    let mut response = Vec::new();
    let read_result =
        tokio::time::timeout(Duration::from_secs(5), reader.read_to_end(&mut response))
            .await
            .expect("gateway response completed within five seconds");
    upload.abort();
    if let Err(err) = read_result {
        assert!(
            !response.is_empty(),
            "gateway closed without a response: {err}"
        );
    }
    (
        String::from_utf8(response).expect("HTTP/1 response is UTF-8"),
        started.elapsed(),
    )
}

// #4055: backend accepts and never reads. `HttpStep::ExpectRequest` would
// drain the POST, so the fixture is raw TCP Accept (implicit) + Sleep.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn in_process_backend_write_timeout_maps_to_504_backend_timeout() {
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let _backend = ScriptedTcpBackend::builder(reservation.into_listener())
        .receive_buffer_size(BACKEND_RECEIVE_BUFFER_BYTES)
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

    let (response, elapsed) = raw_h1_upload_response(&harness).await;
    let (headers, body) = response
        .split_once("\r\n\r\n")
        .expect("HTTP/1 response has a header terminator");
    assert!(
        headers.starts_with("HTTP/1.1 504 "),
        "live backend write timeout must be 504, got {response:?}"
    );
    assert!(
        headers
            .to_ascii_lowercase()
            .contains("\r\nx-gateway-error: backend_timeout"),
        "timeout must carry X-Gateway-Error=backend_timeout, got {response:?}"
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
        .receive_buffer_size(BACKEND_RECEIVE_BUFFER_BYTES)
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

// #4055, buffered dispatch. `retry` forces `stream_request_body = false`, so
// the upload is collected into memory and handed to reqwest as one buffer —
// the arm that had no body adapter and therefore no watermark at all. The
// contract is the same: a backend that accepts and never reads must 504 near
// `backend_write_timeout_ms`, not run on to a much longer
// `backend_read_timeout_ms`.
//
// `ReadWriteTimeout` reached the wire, so `connection_error` is false and the
// retry loop does not replay it; the elapsed time is one watermark.
fn buffered_timeout_overrides(read_ms: u64, write_ms: u64) -> serde_json::Value {
    json!({
        "backend_read_timeout_ms": read_ms,
        "backend_write_timeout_ms": write_ms,
        "retry": {
            "max_retries": 1,
            "retryable_status_codes": [],
            "retry_on_connect_failure": true,
            "backoff": {
                "fixed": {"delay_ms": 1}
            },
        },
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn in_process_buffered_backend_write_timeout_maps_to_504_backend_timeout() {
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let _backend = ScriptedTcpBackend::builder(reservation.into_listener())
        .receive_buffer_size(BACKEND_RECEIVE_BUFFER_BYTES)
        .step(TcpStep::Sleep(Duration::from_secs(30)))
        .spawn()
        .expect("spawn");

    let yaml = file_mode_yaml_for_backend_with(
        backend_port,
        buffered_timeout_overrides(8_000, WRITE_TIMEOUT_MS),
    );
    let harness = GatewayHarness::builder()
        .mode_in_process()
        .file_config(yaml)
        .spawn()
        .await
        .expect("spawn gateway");

    // Retry forces gateway-side body collection before dispatch. The streaming
    // arm uses `raw_h1_upload_response` so the upload stays live while the
    // backend write watermark fires; reading concurrently during collection
    // here closes the frontend with no HTTP block (hosted CI: empty EOF at
    // split_once). Reqwest finishes the client upload before awaiting headers,
    // which matches how a buffered dispatch actually reaches the backend.
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
        "buffered upload write timeout must be 504, got {status} body={body}"
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

// Companion opt-out on the buffered arm: `backend_write_timeout_ms: 0` keeps
// the reusable-`Bytes` path, so a never-read backend must not 504 at 800ms.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn in_process_buffered_backend_write_timeout_zero_does_not_504() {
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let _backend = ScriptedTcpBackend::builder(reservation.into_listener())
        .receive_buffer_size(BACKEND_RECEIVE_BUFFER_BYTES)
        .step(TcpStep::Sleep(Duration::from_secs(30)))
        .spawn()
        .expect("spawn");

    let yaml = file_mode_yaml_for_backend_with(backend_port, buffered_timeout_overrides(8_000, 0));
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
                "buffered backend_write_timeout_ms=0 must not produce a 504"
            );
        }
        Ok(Err(err)) => {
            panic!("unexpected client error under buffered write-timeout=0: {err}");
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
        .step(HttpStep::ExpectRequest(RequestMatcher::any()))
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
        .step(HttpStep::ExpectRequest(RequestMatcher::any()))
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

// #4411 regression guard, ported from the closed
// `claude/issue-4411-backend-write-timeout` branch: a slow-but-genuinely-
// progressing upload must still return 200 under an 800ms write bound. The
// post-EOS drain bound is stated on strictly decreasing send-queue depth
// precisely so this case can never be misread as a stall.
const PROGRESSING_UPLOAD_BYTES: usize = 256 * 1024;
const PROGRESSING_READ_CHUNK: usize = 32 * 1024;

fn progressing_upload_script(body_len: usize) -> Vec<TcpStep> {
    let mut steps = vec![TcpStep::ReadUntil(b"\r\n\r\n".to_vec())];
    let mut remaining = body_len;
    while remaining > 0 {
        steps.push(TcpStep::Sleep(Duration::from_millis(200)));
        let n = remaining.min(PROGRESSING_READ_CHUNK);
        steps.push(TcpStep::ReadExact(n));
        remaining -= n;
    }
    steps.push(TcpStep::Write(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec(),
    ));
    steps
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn in_process_progressing_upload_is_not_killed_by_idle_write_timeout() {
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let mut backend = ScriptedTcpBackend::builder(reservation.into_listener())
        .receive_buffer_size(BACKEND_RECEIVE_BUFFER_BYTES);
    for step in progressing_upload_script(PROGRESSING_UPLOAD_BYTES) {
        backend = backend.step(step);
    }
    let _backend = backend.spawn().expect("spawn");

    let yaml =
        file_mode_yaml_for_backend_with(backend_port, timeout_overrides(8_000, WRITE_TIMEOUT_MS));
    let harness = GatewayHarness::builder()
        .mode_in_process()
        .file_config(yaml)
        .spawn()
        .await
        .expect("spawn gateway");

    let client = harness.http_client().expect("client");
    let response = client
        .as_reqwest()
        .post(harness.proxy_url("/api/twrite"))
        .header("content-type", "application/octet-stream")
        .header("expect", "")
        .body(vec![b'x'; PROGRESSING_UPLOAD_BYTES])
        .send()
        .await
        .expect("gateway returns a response");
    let status = response.status();
    let header = gateway_error_header(response.headers()).map(str::to_owned);
    let body = response.text().await.expect("body");
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "slow-but-progressing upload must not 504, got {status} \
         x-gateway-error={header:?} body={body}"
    );
    assert_eq!(body, "ok");
}

// ── #4411: the post-EOS send-queue drain bound, against a live socket ────────
//
// Once the request body has reached a clean end of stream the upload pump's
// pre-EOS idle arm can never fire again, and HTTP offers no request-side
// receipt that the backend read anything. The kernel's send-queue depth is the
// remaining evidence. These prove the mechanism end to end on a real
// connection: the syscall, the sampling cadence, and the progress rule
// together, rather than the rule alone (`tests/unit/gateway_core/
// backend_send_queue_tests.rs`).

const DRAIN_WATERMARK_MS: u64 = 400;
// Comfortably larger than any default socket send buffer, so a peer that never
// reads leaves the remainder parked in the gateway's own send queue.
const DRAIN_PROBE_UPLOAD_BYTES: usize = 8 * 1024 * 1024;

/// Fill `stream`'s send queue as far as the kernel will take it, returning the
/// bytes accepted. Stops at the first `WouldBlock`, which is exactly the state
/// a stalled backend leaves the gateway in.
async fn fill_send_queue(stream: &TcpStream, total: usize) -> usize {
    let chunk = vec![b'x'; 64 * 1024];
    let mut written = 0;
    while written < total {
        match stream.try_write(&chunk[..chunk.len().min(total - written)]) {
            Ok(0) => break,
            Ok(n) => written += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(_) => break,
        }
    }
    written
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn send_queue_drain_watch_terminates_a_peer_that_never_reads() {
    if !ferrum_edge::_test_support::send_queue_probe_supported() {
        // Windows and anything else without a send-queue query keeps
        // `backend_read_timeout_ms` as the only bound; documented in
        // `docs/configuration.md` next to `backend_write_timeout_ms`.
        return;
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind never-reading peer");
    let addr = listener.local_addr().expect("local addr");
    // Accept and then never call `recv()` — the #4411 backend exactly.
    let peer = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("accept");
        tokio::time::sleep(Duration::from_secs(30)).await;
        drop(socket);
    });

    let stream = TcpStream::connect(addr).await.expect("connect");
    let written = fill_send_queue(&stream, DRAIN_PROBE_UPLOAD_BYTES).await;
    assert!(
        written > 0,
        "the kernel must accept some of the upload before backpressuring"
    );

    let started = Instant::now();
    let stalled =
        ferrum_edge::_test_support::await_backend_send_queue_stall(&stream, DRAIN_WATERMARK_MS)
            .await
            .expect("a duplicated socket handle on a supported platform");
    let elapsed = started.elapsed();
    assert!(
        stalled,
        "a send queue that never drains must be charged to the write watermark"
    );
    assert!(
        elapsed >= Duration::from_millis(DRAIN_WATERMARK_MS.saturating_sub(100)),
        "the stall must not fire early: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "the stall must fire near the watermark, not at a later bound: {elapsed:?}"
    );
    peer.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn send_queue_drain_watch_lets_a_reading_peer_finish() {
    if !ferrum_edge::_test_support::send_queue_probe_supported() {
        return;
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind reading peer");
    let addr = listener.local_addr().expect("local addr");
    let peer = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut sink = vec![0u8; 64 * 1024];
        // Slow but genuinely progressing: each read strictly decreases the
        // sender's queue, so the watch must never terminate it even though the
        // whole transfer takes far longer than the watermark.
        loop {
            match socket.read(&mut sink).await {
                Ok(0) | Err(_) => break,
                Ok(_) => tokio::time::sleep(Duration::from_millis(20)).await,
            }
        }
    });

    let stream = TcpStream::connect(addr).await.expect("connect");
    let written = fill_send_queue(&stream, DRAIN_PROBE_UPLOAD_BYTES).await;
    assert!(written > 0, "the kernel must accept some of the upload");

    let stalled =
        ferrum_edge::_test_support::await_backend_send_queue_stall(&stream, DRAIN_WATERMARK_MS)
            .await
            .expect("a duplicated socket handle on a supported platform");
    assert!(
        !stalled,
        "a peer that keeps reading must never be charged a write timeout"
    );
    peer.abort();
}
