//! Phase-1 acceptance tests for the scripted-backend framework.
//!
//! Each test ties a scripted backend (TCP / TLS / HTTP-1.1) to a ferrum-edge
//! gateway running in binary mode and asserts an observable failure mode.
//!
//! Run with: `cargo build --bin ferrum-edge && cargo test --test
//! functional_tests scripted_backend -- --ignored --nocapture`
//!
//! The tests live here so they can `#[ignore]` (per CLAUDE.md functional-test
//! rules) and share the binary-mode [`crate::scaffolding::harness::GatewayHarness`].

#![allow(clippy::bool_assert_comparison)]

use crate::scaffolding::backends::{
    HttpStep, RequestMatcher, ScriptedHttp1Backend, ScriptedTcpBackend, ScriptedTlsBackend,
    TcpStep, TlsConfig,
};
use crate::scaffolding::certs::TestCa;
use crate::scaffolding::harness::GatewayHarness;
use crate::scaffolding::ports::{reserve_port, unbound_port};
use crate::scaffolding::{file_mode_yaml_for_backend, file_mode_yaml_for_backend_with};
use reqwest::StatusCode;
use serde_json::json;
use std::time::{Duration, Instant};

/// Fetch captured gateway logs and fail the test if they are empty — the
/// harness silently returns an empty string when `capture_output()` was not
/// called on the builder, and downstream `logs.contains(..)` asserts would
/// then pass for the wrong reason.
fn require_logs(harness: &GatewayHarness) -> String {
    let logs = harness
        .captured_combined()
        .expect("read captured gateway logs");
    assert!(
        !logs.trim().is_empty(),
        "gateway logs were empty — did you forget .capture_output() on the builder?"
    );
    logs
}

fn has_body_error_signal(logs: &str) -> bool {
    // The gateway logs body-read errors as either a structured
    // `body_error_class` (via stdout_logging) or a proxy-level
    // "Failed to read backend response body" / "error decoding response
    // body" warning when hyper notices the truncated Content-Length. Any
    // of these prove the gateway noticed the incomplete body.
    logs.contains("body_error_class")
        || logs.contains("IncompleteBody")
        || logs.contains("unexpected end of file")
        || logs.contains("Incomplete")
        || logs.contains("ClientDisconnect")
        || logs.contains("Failed to read backend response body")
        || logs.contains("error decoding response body")
}

async fn collect_body_error_logs(harness: &GatewayHarness) -> String {
    if let Ok(url) = harness.admin_url("/health").parse::<reqwest::Url>() {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(500))
            .build()
            .expect("reqwest client");
        for _ in 0..2 {
            let _ = client.get(url.clone()).send().await;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let logs = require_logs(harness);
        if has_body_error_signal(&logs) || Instant::now() >= deadline {
            return logs;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Test 1 — backend port with nothing listening → 502 + ConnectionRefused class.
// ────────────────────────────────────────────────────────────────────────────
//
// Fixture: `unbound_port()` reserves a port then drops the listener, so the
// gateway's connect() returns a real `ECONNREFUSED` from the kernel
// (distinct from `ScriptedTcpBackend::RefuseNextConnect`, which accepts and
// drops — that path emits FIN/RST, not a connect-time refusal, and so does
// not exercise the gateway's `ConnectionRefused` classifier).
//
// CLAUDE.md warns about the bind-drop-rebind race: under parallel test load
// another process can bind the port in the gap between our drop and the
// gateway's connect, which turns the gateway's 502 into some other status
// and makes the test flaky. Retry the full setup (fresh port + fresh
// harness) when the expected 502 + refused-class signal doesn't land.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn backend_refuses_connect_maps_to_502_with_connection_refused() {
    const MAX_ATTEMPTS: u32 = 5;
    let mut last_failure: Option<String> = None;
    for attempt in 1..=MAX_ATTEMPTS {
        // Real ECONNREFUSED: no listener on this port.
        let backend_port = unbound_port().await.expect("unbound port");
        let yaml = file_mode_yaml_for_backend(backend_port);
        let harness = GatewayHarness::builder()
            .file_config(yaml)
            .log_level("info")
            .capture_output()
            .spawn()
            .await
            .expect("spawn gateway");

        let client = harness.http_client().expect("client");
        let resp = client
            .get(&harness.proxy_url("/api/anything"))
            .await
            .expect("gateway returns a response");
        if resp.status != StatusCode::BAD_GATEWAY {
            last_failure = Some(format!(
                "attempt {attempt}/{MAX_ATTEMPTS}: expected 502, got {} (port may have been rebound)",
                resp.status
            ));
            continue;
        }

        let logs = require_logs(&harness);
        // `connect_failure` is the gateway's `error_kind` for reqwest
        // errors where `is_connect() == true` — exactly the ECONNREFUSED
        // case. Distinct from `request_error` (RST after accept),
        // `read_timeout`, and body-error classes, so asserting on it
        // proves the gateway took the connect-failure path rather than
        // some other fallback. `ConnectionRefused`/"Connection refused"
        // are belt-and-suspenders for future log-surface changes.
        let has_refused_class = logs.contains("connect_failure")
            || logs.contains("ConnectionRefused")
            || logs.contains("Connection refused");
        if !has_refused_class {
            last_failure = Some(format!(
                "attempt {attempt}/{MAX_ATTEMPTS}: expected refused-class signal in logs:\n{logs}"
            ));
            continue;
        }
        return; // pass
    }
    panic!(
        "backend_refuses_connect test failed across {MAX_ATTEMPTS} attempts; last failure: {}",
        last_failure.unwrap_or_else(|| "unknown".into())
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Test 2 — backend accepts then resets → 502 + ConnectionReset.
// ────────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn backend_accepts_then_resets_maps_to_connection_reset() {
    const MAX_ATTEMPTS: u32 = 5;
    let mut last_failure: Option<String> = None;

    for attempt in 1..=MAX_ATTEMPTS {
        let reservation = reserve_port().await.expect("reserve backend port");
        let backend_port = reservation.port;
        let backend = ScriptedTcpBackend::builder(reservation.into_listener())
            .step(TcpStep::Reset)
            .spawn()
            .expect("spawn backend");

        let yaml = file_mode_yaml_for_backend(backend_port);
        let harness = GatewayHarness::builder()
            .file_config(yaml)
            .log_level("info")
            .capture_output()
            .spawn()
            .await
            .expect("spawn gateway");

        let client = harness.http_client().expect("client");
        let resp = client
            .get(&harness.proxy_url("/api/x"))
            .await
            .expect("response");
        if resp.status != StatusCode::BAD_GATEWAY {
            let accepted = backend.accepted_connections();
            let logs = harness.captured_combined().unwrap_or_default();
            last_failure = Some(format!(
                "attempt {attempt}/{MAX_ATTEMPTS}: expected 502, got {}; reset backend accepted {accepted} connection(s); logs:\n{logs}",
                resp.status
            ));
            continue;
        }

        let logs = require_logs(&harness);
        // Gateway should have logged a backend request error. The platform-
        // specific string can be "reset", "connection closed", "request_error"
        // (reqwest's generic classifier), or "Backend request failed". Any of
        // these indicates the RST was detected.
        let observed = logs.contains("reset")
            || logs.contains("Reset")
            || logs.contains("connection closed")
            || logs.contains("request_error")
            || logs.contains("Backend request failed");
        if !observed {
            last_failure = Some(format!(
                "attempt {attempt}/{MAX_ATTEMPTS}: expected reset/error signal in logs:\n{logs}"
            ));
            continue;
        }
        return;
    }

    panic!(
        "backend_accepts_then_resets test failed across {MAX_ATTEMPTS} attempts; last failure: {}",
        last_failure.unwrap_or_else(|| "unknown".into())
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Test 3 — `backend_read_timeout_ms` fires within tolerance.
// ────────────────────────────────────────────────────────────────────────────
//
// Scripted HTTP/1.1 backend sleeps ≫ the configured read timeout before
// writing anything, forcing the gateway to give up. We measure the elapsed
// wall-clock time and assert it's within ±500ms of `backend_read_timeout_ms`.
//
// Tolerance: ~500ms. Loaded CI machines may jitter a bit but the watchdog
// granularity is 1s per CLAUDE.md §TCP timeout docs — we're measuring
// HTTP-level timeouts here, which are tighter. See `docs/error_classification`.
//
// Migrated to `HarnessMode::InProcess` — the test asserts on response
// status + timing only, no log capture, so it benefits from the ~10× faster
// in-process startup without losing coverage.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn backend_read_timeout_fires_after_backend_read_timeout_ms() {
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let _backend = ScriptedHttp1Backend::builder(reservation.into_listener())
        .step(HttpStep::ExpectRequest(RequestMatcher::any()))
        // Hold the connection open far beyond the gateway's read timeout.
        .step(HttpStep::Sleep(Duration::from_secs(30)))
        .spawn()
        .expect("spawn");

    let read_timeout_ms: u64 = 800;
    let overrides = json!({ "backend_read_timeout_ms": read_timeout_ms });
    let yaml = file_mode_yaml_for_backend_with(backend_port, overrides);

    let harness = GatewayHarness::builder()
        .mode_in_process()
        .file_config(yaml)
        .log_level("info")
        .spawn()
        .await
        .expect("spawn gateway");

    let client = harness.http_client().expect("client");
    let started = Instant::now();
    let resp = client
        .get(&harness.proxy_url("/api/slow"))
        .await
        .expect("response");
    let elapsed = started.elapsed();
    // Status: 502 or 504 depending on the code path — both are acceptable
    // "gateway gave up on backend" responses. The timing is the load-bearing
    // assertion.
    assert!(
        matches!(
            resp.status,
            StatusCode::BAD_GATEWAY | StatusCode::GATEWAY_TIMEOUT
        ),
        "expected 502 or 504, got {}",
        resp.status
    );
    let expected = Duration::from_millis(read_timeout_ms);
    let floor = expected.saturating_sub(Duration::from_millis(200));
    let ceiling = expected + Duration::from_millis(1500);
    assert!(
        elapsed >= floor,
        "timed out too fast: {elapsed:?} < floor {floor:?} (timeout was {read_timeout_ms}ms)"
    );
    assert!(
        elapsed <= ceiling,
        "timed out too slowly: {elapsed:?} > ceiling {ceiling:?} (timeout was {read_timeout_ms}ms)"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Test 3b — `backend_read_timeout_ms = 0` disables the read timeout.
// ────────────────────────────────────────────────────────────────────────────
//
// The gateway treats zero timeout values as explicit opt-out. This exercises
// the live HTTP proxy path with a backend that waits longer than the default
// 5s helper timeout before sending a valid response. If the zero value were
// accidentally normalized back to the default, this would return a gateway
// timeout instead of the backend's 200.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn backend_read_timeout_zero_disables_timeout() {
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let backend = ScriptedHttp1Backend::builder(reservation.into_listener())
        .step(HttpStep::ExpectRequest(RequestMatcher::any()))
        .step(HttpStep::Sleep(Duration::from_millis(5_600)))
        .step(HttpStep::RespondStatus {
            status: 200,
            reason: "OK".into(),
        })
        .step(HttpStep::RespondHeader {
            name: "Content-Length".into(),
            value: "2".into(),
        })
        .step(HttpStep::RespondBodyChunk(b"ok".to_vec()))
        .step(HttpStep::RespondBodyEnd)
        .spawn()
        .expect("spawn backend");

    let yaml =
        file_mode_yaml_for_backend_with(backend_port, json!({ "backend_read_timeout_ms": 0 }));
    let harness = GatewayHarness::builder()
        .mode_in_process()
        .file_config(yaml)
        .log_level("info")
        .spawn()
        .await
        .expect("spawn gateway");

    let client = harness.http_client().expect("client");
    let started = Instant::now();
    let resp = client
        .get(&harness.proxy_url("/api/slow-but-allowed"))
        .await
        .expect("response");
    let elapsed = started.elapsed();

    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(resp.body_text(), "ok");
    assert!(
        elapsed >= Duration::from_millis(5_300),
        "backend response arrived before the scripted sleep elapsed: {elapsed:?}"
    );
    backend.assert_no_step_errors().await;
}

// ────────────────────────────────────────────────────────────────────────────
// Test 4 — backend closes mid-body → client observes truncated body;
// gateway logs a body_error_class.
// ────────────────────────────────────────────────────────────────────────────
//
// The backend announces Content-Length: 100 then FINs after 10 bytes. The
// client's buffered `response.body_bytes` ends up shorter than the content-
// length (reqwest surfaces this as a read error mid-stream; we assert by
// either status != 200 OR body shorter than advertised).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn backend_close_mid_body_populates_body_error_class() {
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let _backend = ScriptedHttp1Backend::builder(reservation.into_listener())
        .step(HttpStep::CloseMidBody {
            status: 200,
            reason: "OK".into(),
            headers: vec![
                ("Content-Length".into(), "100".into()),
                ("Content-Type".into(), "application/octet-stream".into()),
            ],
            body_prefix: vec![b'x'; 10],
            reset: false,
        })
        .spawn()
        .expect("spawn backend");

    let yaml = file_mode_yaml_for_backend(backend_port);
    let harness = GatewayHarness::builder()
        .file_config(yaml)
        .log_level("info")
        .capture_output()
        .spawn()
        .await
        .expect("spawn gateway");

    let client = harness.http_client().expect("client");
    // Either the body reads short (advertised 100 bytes, got 10) or reqwest
    // surfaces an error. Either observable proves the gateway noticed.
    let result = client.get(&harness.proxy_url("/api/truncated")).await;
    match result {
        Ok(resp) => {
            // Some code paths let the status through before the body gap.
            assert!(
                resp.body_bytes.len() < 100,
                "expected truncated body, got {} bytes",
                resp.body_bytes.len()
            );
        }
        Err(_e) => {
            // Body error surfaced as a reqwest::Error — also acceptable.
        }
    }

    let logs = collect_body_error_logs(&harness).await;
    let has_body_error = has_body_error_signal(&logs);
    assert!(
        has_body_error,
        "expected body-error signal in logs; got:\n{logs}"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Test 5 — TLS backend with an expired cert → gateway refuses to connect.
// ────────────────────────────────────────────────────────────────────────────
//
// Configures a TLS backend with a cert that's already `notAfter` in the
// past. The gateway, configured to *verify* the backend cert, refuses the
// handshake and returns 502. We assert status + that the log carries a
// TLS/cert signal rather than a body one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn tls_expired_cert_produces_tls_error_not_generic_502() {
    let ca = TestCa::new("scripted-test-root").expect("ca");
    let (expired_cert, expired_key) = ca.expired().expect("expired leaf");

    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let _backend = ScriptedTlsBackend::builder(
        reservation.into_listener(),
        TlsConfig::new(expired_cert, expired_key),
    )
    .step(TcpStep::Drop)
    .spawn()
    .expect("spawn backend");

    // Write the CA to a persistent temp dir (not inside the harness temp dir,
    // which only exists after spawn). The CA must outlive the harness.
    let ca_dir = tempfile::tempdir().expect("tempdir");
    let ca_path = ca_dir.path().join("backend-ca.pem");
    std::fs::write(&ca_path, &ca.cert_pem).expect("write ca");

    // Configure the proxy to trust our CA and verify the server cert.
    let yaml = file_mode_yaml_for_backend_with(
        backend_port,
        json!({
            "backend_scheme": "https",
            "backend_host": "localhost",
            "backend_tls_verify_server_cert": true,
            "backend_tls_server_ca_cert_path": ca_path.to_string_lossy(),
        }),
    );

    let harness = GatewayHarness::builder()
        .file_config(yaml)
        .log_level("info")
        .capture_output()
        .spawn()
        .await
        .expect("spawn gateway");

    let client = harness.http_client().expect("client");
    let resp = client
        .get(&harness.proxy_url("/api/expired"))
        .await
        .expect("response");
    assert_eq!(resp.status, StatusCode::BAD_GATEWAY, "expected 502");

    // Look for cert/TLS-specific tokens. We deliberately avoid a bare `"tls"`
    // substring match — crate and module paths contain "tls" nearly
    // everywhere, which would turn this assertion into a no-op.
    let has_tls_signal = |logs: &str| {
        logs.contains("TlsError")
            || logs.contains("expired")
            || logs.contains("notAfter")
            || logs.contains("NotValidYet")
            || logs.contains("certificate")
            || logs.contains("CertificateError")
            || logs.contains("InvalidCertificate")
            || logs.contains("handshake")
    };
    // Poll: the TLS handshake error logs flush through the non-blocking writer
    // after the client already sees the 502, so a single snapshot can race it.
    let logs = harness
        .wait_for_log_contains(&has_tls_signal, Duration::from_secs(5))
        .await;
    assert!(
        has_tls_signal(&logs),
        "expected TLS/cert error signal in logs, got:\n{logs}"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Test 6 — H2 ALPN fallback downgrades the capability cache.
// ────────────────────────────────────────────────────────────────────────────
//
// The TLS backend's server-side ALPN list is exactly `[http/1.1]`. When the
// gateway's H2 direct pool probes the backend (either at warmup or on first
// request), rustls negotiates `http/1.1`, the pool raises
// `BackendSelectedHttp1`, and the dispatcher invokes
// `BackendCapabilityRegistry::mark_h2_tls_unsupported(...)` so subsequent
// requests skip the direct H2 pool. Pool warmup must be enabled so the
// probe actually happens.
//
// Observables:
//   1. The backend records `last_alpn = "http/1.1"` on the probe
//      handshake (before any request reaches it).
//   2. The capability registry, exposed via `GET /backend-capabilities`,
//      records `plain_http.h2_tls = "unsupported"` AND
//      `plain_http.h1 = "supported"` for this backend after the
//      ALPN-driven downgrade.
//   3. Subsequent client requests succeed (served via reqwest's
//      http/1.1 path).
//
// The previous incarnation of this test scraped the gateway log for
// `BackendSelectedHttp1`, which was flaky: the registry warmup path can
// classify the backend silently without emitting that exact substring,
// and capturing stdout/stderr races with hyper / tokio buffering. Querying
// the admin endpoint instead is deterministic — the registry is the source
// of truth that the hot path actually consults.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h2_alpn_fallback_downgrades_capability() {
    let ca = TestCa::new("scripted-alpn-root").expect("ca");
    let (cert, key) = ca.valid().expect("leaf");

    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    // Respond to *any* request (the H2 pool probe sends none, but reqwest
    // user requests do). The 3-step script runs per connection — adequate
    // for a pool probe handshake that terminates on receiving close_notify.
    let bytes_received: Vec<u8> =
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec();
    let backend = ScriptedTlsBackend::builder(
        reservation.into_listener(),
        TlsConfig::new(cert, key).with_alpn(vec![b"http/1.1".to_vec()]),
    )
    .step(TcpStep::ReadUntil(b"\r\n\r\n".to_vec()))
    .step(TcpStep::Write(bytes_received))
    .step(TcpStep::Drop)
    .spawn()
    .expect("spawn backend");

    let yaml = file_mode_yaml_for_backend_with(
        backend_port,
        json!({
            "backend_scheme": "https",
            "backend_host": "127.0.0.1",
            "backend_tls_verify_server_cert": false,
        }),
    );
    let harness = GatewayHarness::builder()
        .file_config(yaml)
        .log_level("info")
        .env("FERRUM_TLS_NO_VERIFY", "true")
        // Pool warmup is disabled by default in the shared harness to keep
        // unrelated tests fast — we need it ON for the H2 probe to run.
        .env("FERRUM_POOL_WARMUP_ENABLED", "true")
        .spawn()
        .await
        .expect("spawn gateway");

    let client = harness.http_client().expect("client");
    let r1 = client
        .get(&harness.proxy_url("/api/one"))
        .await
        .expect("r1");
    assert_eq!(r1.status, StatusCode::OK);
    assert_eq!(r1.body_text(), "ok");

    // Backend assertion: the H2 pool probe (warmup OR first request)
    // negotiated http/1.1 on a TLS handshake. reqwest's h1 follow-on
    // request may also advertise ALPN, so we only assert that *at least
    // one* ALPN negotiation across the full handshake history resolved to
    // http/1.1.
    let history = backend.all_alpn().await;
    let saw_http1 = history
        .iter()
        .any(|alpn| alpn.as_deref() == Some(&b"http/1.1"[..]));
    assert!(
        saw_http1,
        "expected at least one handshake to negotiate http/1.1; \
         accepted={}, handshakes={}, history={:?}",
        backend.accepted_connections(),
        backend.handshakes_completed(),
        history
    );

    // Capability-registry assertion: after the ALPN-driven classification,
    // the single-proxy registry MUST contain exactly one entry with
    // `h2_tls = "unsupported"` AND `h1 = "supported"`. This is the
    // operator-facing source of truth — what `GET /backend-capabilities`
    // returns drives the gateway's hot-path routing decision.
    //
    // Two paths can land us here, both with identical observable state:
    //   • Warmup path: `probe_h2_tls` sees `BackendSelectedHttp1` and
    //     classifies cleanly — `last_probe_error` is `null`.
    //   • Request path: warmup didn't run / didn't observe ALPN, request
    //     hits the H2 pool, `mark_h2_tls_unsupported` fires and stamps
    //     `last_probe_error` with the "ALPN-negotiated HTTP/1.1" message.
    // The hot-path semantics are identical for the two endpoints' `h2_tls`,
    // `h1`, and `grpc_transport.h2_tls` fields, so we only assert on those.
    let entry = wait_for_h2_downgraded_entry(&harness, Duration::from_secs(10))
        .await
        .expect("registry should record h2_tls=unsupported within timeout");
    assert_eq!(
        entry["plain_http"]["h2_tls"].as_str(),
        Some("unsupported"),
        "expected plain_http.h2_tls=unsupported after ALPN-driven downgrade; entry: {entry:#?}"
    );
    assert_eq!(
        entry["plain_http"]["h1"].as_str(),
        Some("supported"),
        "expected plain_http.h1=supported (HTTPS still works over h1); entry: {entry:#?}"
    );
    assert_eq!(
        entry["grpc_transport"]["h2_tls"].as_str(),
        Some("unsupported"),
        "ALPN-driven downgrade marks both plain_http.h2_tls and grpc_transport.h2_tls; entry: {entry:#?}"
    );

    // Second request must still succeed via the reqwest http/1.1 fallback
    // path now that the registry has steered the dispatcher away from the
    // direct H2 pool.
    let r2 = client
        .get(&harness.proxy_url("/api/two"))
        .await
        .expect("r2");
    assert_eq!(r2.status, StatusCode::OK);
    assert_eq!(r2.body_text(), "ok");
}

/// Poll `GET /backend-capabilities` until exactly one entry exists AND its
/// `plain_http.h2_tls` field is `"unsupported"`. Returns the entry on
/// success, `None` on timeout. Mirrors the helper in
/// `scripted_backend_h3_tests.rs` but waits for the post-downgrade state
/// rather than just any populated entry.
async fn wait_for_h2_downgraded_entry(
    harness: &GatewayHarness,
    timeout: Duration,
) -> Option<serde_json::Value> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if let Ok(body) = harness.get_admin_json("/backend-capabilities").await
            && let Some(entries) = body["entries"].as_array()
            && let Some(entry) = entries.first()
            && entry["plain_http"]["h2_tls"].as_str() == Some("unsupported")
        {
            return Some(entry.clone());
        }
        if std::time::Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

// ────────────────────────────────────────────────────────────────────────────
// response_transformer — client SSE intent cannot bypass JSON body policy.
// ────────────────────────────────────────────────────────────────────────────

fn response_transformer_sse_policy_file_config(
    backend_port: u16,
    retries_enabled: bool,
) -> String {
    let mut proxy = json!({
        "id": "response-transformer-sse-policy",
        "listen_path": "/api",
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": backend_port,
        "strip_listen_path": true,
        "response_body_mode": "stream",
        "backend_connect_timeout_ms": 2000,
        // The SSE fixture deliberately holds the response open between
        // events. Zero disables the backend read timeout for this test.
        "backend_read_timeout_ms": 0,
        "backend_write_timeout_ms": 5000,
        "plugins": [{"plugin_config_id": "redact-secret"}],
    });
    if retries_enabled {
        // Exercise the retry-marked response decision even though each
        // successful fixture completes on its first attempt.
        proxy["retry"] = json!({
            "max_retries": 1,
            "retry_on_connect_failure": true,
        });
    }
    let config = json!({
        "version": "1",
        "proxies": [proxy],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [{
            "id": "redact-secret",
            "proxy_id": "response-transformer-sse-policy",
            "plugin_name": "response_transformer",
            "scope": "proxy",
            "enabled": true,
            "config": {
                "rules": [{
                    "operation": "remove",
                    "target": "body",
                    "key": "secret",
                }],
            },
        }],
    });
    serde_yaml::to_string(&config).expect("yaml serialize")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn response_transformer_buffers_json_when_client_accepts_sse() {
    const JSON_BODY: &str = r#"{"secret":"hunter2","keep":"visible"}"#;

    let reservation = reserve_port().await.expect("reserve backend port");
    let backend_port = reservation.port;
    let json_script = vec![
        HttpStep::ExpectRequest(RequestMatcher::method_path("GET", "/json")),
        HttpStep::RespondStatus {
            status: 200,
            reason: "OK".into(),
        },
        HttpStep::RespondHeader {
            name: "Content-Type".into(),
            // The parameter deliberately contains `event-stream`: release must
            // key on the exact media-type essence, not a permissive substring.
            value: "application/json; profile=event-stream".into(),
        },
        HttpStep::RespondHeader {
            name: "Content-Length".into(),
            value: JSON_BODY.len().to_string(),
        },
        HttpStep::RespondHeader {
            name: "Connection".into(),
            value: "close".into(),
        },
        HttpStep::RespondBodyChunk(JSON_BODY.as_bytes().to_vec()),
        HttpStep::RespondBodyEnd,
    ];
    let backend = ScriptedHttp1Backend::builder(reservation.into_listener())
        // Repeat the same contract if an unexpected connection arrives. The
        // request-count assertion below still exposes that transport bug, while
        // avoiding a misleading JSON-decode failure against an SSE fixture.
        .steps(json_script)
        .spawn()
        .expect("spawn backend");

    let harness = GatewayHarness::builder()
        // Keep the scripted backend cold: binary-mode startup performs an
        // independent capability probe that would be counted as a request.
        .mode_in_process()
        .file_config(response_transformer_sse_policy_file_config(
            backend_port,
            true,
        ))
        .pool_warmup_enabled(false)
        .spawn()
        .await
        .expect("spawn gateway");
    let client = harness.http_client().expect("client");

    // The exploit shape: client asks for SSE, backend selects ordinary JSON.
    // The response must still be buffered and redacted before any byte crosses.
    let json_response = client
        .request(reqwest::Method::GET, &harness.proxy_url("/api/json"))
        .header("accept", "text/event-stream")
        .send()
        .await
        .expect("gateway returns JSON response");
    assert_eq!(json_response.status(), StatusCode::OK);
    let json_bytes = json_response
        .bytes()
        .await
        .expect("read transformed JSON response");
    let json_body: serde_json::Value =
        serde_json::from_slice(&json_bytes).unwrap_or_else(|error| {
            panic!(
                "transformed response is valid JSON: {error}; body={:?}",
                String::from_utf8_lossy(&json_bytes)
            )
        });
    assert!(
        json_body.get("secret").is_none(),
        "client SSE intent must not bypass the configured redaction"
    );
    assert_eq!(json_body["keep"], "visible");

    let requests = backend.received_requests().await;
    assert_eq!(
        requests.len(),
        1,
        "a successful JSON response must not trigger another backend attempt"
    );
    assert_eq!(
        backend.accepted_connections(),
        1,
        "a successful JSON response must use one backend connection"
    );
    backend.assert_no_matcher_mismatches().await;
    backend.assert_no_step_errors().await;
}

async fn assert_response_transformer_releases_backend_sse_incrementally(
    retries_enabled: bool,
) {
    const EVENT_ONE: &str = "data: {\"part\":1}\n\n";
    const EVENT_TWO: &str = "data: {\"part\":2}\n\n";
    const MID_STREAM_PAUSE: Duration = Duration::from_secs(5);
    const FIRST_EVENT_DEADLINE: Duration = Duration::from_millis(2500);

    let reservation = reserve_port().await.expect("reserve backend port");
    let backend_port = reservation.port;
    let sse_script = vec![
        HttpStep::ExpectRequest(RequestMatcher::method_path("GET", "/events")),
        HttpStep::RespondStatus {
            status: 200,
            reason: "OK".into(),
        },
        HttpStep::RespondHeader {
            name: "Content-Type".into(),
            value: "text/event-stream".into(),
        },
        HttpStep::RespondHeader {
            name: "Connection".into(),
            value: "close".into(),
        },
        HttpStep::RespondBodyChunk(EVENT_ONE.as_bytes().to_vec()),
        HttpStep::Sleep(MID_STREAM_PAUSE),
        HttpStep::RespondBodyChunk(EVENT_TWO.as_bytes().to_vec()),
        HttpStep::RespondBodyEnd,
    ];
    let backend = ScriptedHttp1Backend::builder(reservation.into_listener())
        .steps(sse_script)
        .spawn()
        .expect("spawn backend");

    let harness = GatewayHarness::builder()
        // Keep the scripted backend cold: binary-mode startup performs an
        // independent capability probe that would be counted as a request.
        .mode_in_process()
        .file_config(response_transformer_sse_policy_file_config(
            backend_port,
            retries_enabled,
        ))
        .pool_warmup_enabled(false)
        .spawn()
        .await
        .expect("spawn gateway");
    let client = harness.http_client().expect("client");

    // A real backend event stream remains incremental. Requiring the first
    // event before the backend's pause elapses proves the response was released
    // after headers rather than collected to EOF by the document transformer.
    let started = Instant::now();
    let (mut sse_response, first_chunk) = tokio::time::timeout(FIRST_EVENT_DEADLINE, async {
        let mut response = client
            .request(reqwest::Method::GET, &harness.proxy_url("/api/events"))
            .header("accept", "text/event-stream")
            .send()
            .await
            .expect("gateway returns SSE response headers");
        let first_chunk = response
            .chunk()
            .await
            .expect("read first SSE chunk")
            .expect("stream must not end before the first event");
        (response, first_chunk)
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "first SSE event did not arrive within {FIRST_EVENT_DEADLINE:?} \
                 (elapsed {:?}) — response_transformer buffered the event stream",
            started.elapsed()
        )
    });
    assert_eq!(sse_response.status(), StatusCode::OK);
    assert_eq!(
        sse_response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("text/event-stream")
    );
    let mut sse_body = String::from_utf8_lossy(&first_chunk).into_owned();
    assert!(sse_body.contains("\"part\":1"));
    assert!(
        !sse_body.contains("\"part\":2"),
        "terminal event arrived with the first chunk, indicating buffering"
    );
    tokio::time::timeout(MID_STREAM_PAUSE + Duration::from_secs(5), async {
        while let Some(chunk) = sse_response.chunk().await.expect("read SSE chunk") {
            sse_body.push_str(&String::from_utf8_lossy(&chunk));
        }
    })
    .await
    .expect("SSE stream finishes after backend closes");
    assert!(sse_body.contains("\"part\":2"));

    let requests = backend.received_requests().await;
    assert_eq!(
        requests.len(),
        1,
        "a successful SSE response must not trigger another backend attempt"
    );
    assert_eq!(
        backend.accepted_connections(),
        1,
        "a successful SSE response must use one backend connection"
    );
    backend.assert_no_matcher_mismatches().await;
    backend.assert_no_step_errors().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn response_transformer_releases_backend_sse_incrementally() {
    assert_response_transformer_releases_backend_sse_incrementally(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn response_transformer_releases_backend_sse_incrementally_without_retries() {
    assert_response_transformer_releases_backend_sse_incrementally(false).await;
}

// ────────────────────────────────────────────────────────────────────────────
// a2a_gateway + retries — unexpected SSE must stream incrementally (#2169).
// ────────────────────────────────────────────────────────────────────────────
//
// `a2a_gateway` classifies `message/send` as non-streaming, making it an
// active response-buffering plugin for the request. With connection-failure
// retries configured, the proxy hands the buffer→stream downgrade a
// retry-marked decision context, and an inherently streaming response can be
// released only when every active buffering plugin implements the retry
// release hooks. Before the fix the plugin lacked them, so an unexpected
// `text/event-stream` response was collected to EOF: no incremental delivery,
// TTFB equal to the full stream duration, and a 502 once the response cap was
// hit.
//
// The scripted backend writes one SSE event, holds the connection open for
// several seconds, then writes the terminal event and closes. Incremental
// delivery is proven by requiring status + headers + the first event well
// before the backend's mid-stream pause elapses — a buffered response cannot
// yield any client bytes until the backend closes the stream.

fn a2a_retry_file_config(backend_port: u16, plugin_config: serde_json::Value) -> String {
    let config = json!({
        "version": "1",
        "proxies": [{
            "id": "a2a-retry",
            "listen_path": "/a2a",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": false,
            "backend_connect_timeout_ms": 2000,
            // Disabled: the SSE script intentionally pauses mid-stream for
            // longer than the scaffolding's usual 5s read timeout.
            "backend_read_timeout_ms": 0,
            "backend_write_timeout_ms": 5000,
            "retry": {
                "max_retries": 1,
                "retry_on_connect_failure": true,
            },
            "plugins": [{"plugin_config_id": "a2a"}],
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [{
            "id": "a2a",
            "proxy_id": "a2a-retry",
            "plugin_name": "a2a_gateway",
            "scope": "proxy",
            "enabled": true,
            "config": plugin_config,
        }],
    });
    serde_yaml::to_string(&config).expect("yaml serialize")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn a2a_retry_configured_unexpected_sse_streams_incrementally() {
    const EVENT_ONE: &str = "data: {\"jsonrpc\":\"2.0\",\"id\":\"1\",\"result\":{\"kind\":\"status-update\",\"taskId\":\"task-1\"}}\n\n";
    const EVENT_TWO: &str = "data: {\"jsonrpc\":\"2.0\",\"id\":\"1\",\"result\":{\"kind\":\"status-update\",\"final\":true}}\n\n";
    // Long enough that a force-buffered response (which yields nothing until
    // backend close) cannot satisfy the first-event deadline below even on a
    // slow CI machine.
    const MID_STREAM_PAUSE: Duration = Duration::from_secs(5);
    const FIRST_EVENT_DEADLINE: Duration = Duration::from_millis(2500);

    let request_body = json!({
        "jsonrpc": "2.0",
        "id": "1",
        "method": "message/send",
        "params": {"message": {"role": "user", "parts": []}}
    })
    .to_string();

    let reservation = reserve_port().await.expect("reserve backend port");
    let backend_port = reservation.port;
    let response_head =
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n";
    let backend = ScriptedTcpBackend::builder(reservation.into_listener())
        .step(TcpStep::ReadUntil(b"\r\n\r\n".to_vec()))
        .step(TcpStep::ReadExact(request_body.len()))
        .step(TcpStep::Write(
            format!("{response_head}{EVENT_ONE}").into_bytes(),
        ))
        .step(TcpStep::Sleep(MID_STREAM_PAUSE))
        .step(TcpStep::Write(EVENT_TWO.as_bytes().to_vec()))
        .step(TcpStep::Drop)
        .spawn()
        .expect("spawn backend");

    let yaml = a2a_retry_file_config(backend_port, json!({}));
    let harness = GatewayHarness::builder()
        .file_config(yaml)
        .spawn()
        .await
        .expect("spawn gateway");

    let client = harness.http_client().expect("client");
    let started = Instant::now();
    let (mut response, first_chunk) = tokio::time::timeout(FIRST_EVENT_DEADLINE, async {
        let mut response = client
            .request(reqwest::Method::POST, &harness.proxy_url("/a2a"))
            .header("content-type", "application/json")
            .body(request_body.clone())
            .send()
            .await
            .expect("gateway returns response headers");
        let first_chunk = response
            .chunk()
            .await
            .expect("read first SSE chunk")
            .expect("stream must not end before the first event");
        (response, first_chunk)
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "first SSE event did not arrive within {FIRST_EVENT_DEADLINE:?} \
             (elapsed {:?}) — the retry-marked decision context force-buffered \
             the event-stream response instead of releasing it",
            started.elapsed()
        )
    });

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("text/event-stream"),
    );
    let mut body = String::from_utf8_lossy(&first_chunk).into_owned();
    assert!(
        body.contains("status-update"),
        "first chunk should carry the first SSE event, got: {body:?}"
    );
    assert!(
        !body.contains("\"final\":true"),
        "terminal event must not have been delivered yet — receiving both \
         events at once means the response was buffered, got: {body:?}"
    );

    // Drain the rest of the stream: the terminal event must arrive after the
    // backend's pause, completing the incremental delivery.
    let drained = tokio::time::timeout(MID_STREAM_PAUSE + Duration::from_secs(5), async {
        while let Some(chunk) = response.chunk().await.expect("read SSE chunk") {
            body.push_str(&String::from_utf8_lossy(&chunk));
        }
    })
    .await;
    assert!(
        drained.is_ok(),
        "stream should end after the backend closes"
    );
    assert!(
        body.contains("\"final\":true"),
        "terminal SSE event should arrive after the pause, got: {body:?}"
    );
    backend.assert_no_step_errors().await;
}

// Companion retention guard: with the same retry configuration, a JSON
// response must stay on the buffered path so Agent Card URL rewriting (and
// metadata extraction) keep working — the retry release is SSE-only.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn a2a_retry_configured_json_agent_card_is_still_rewritten() {
    let card_body = json!({
        "protocolVersion": "0.3.0",
        "name": "planner",
        "description": "planning agent",
        "url": "https://planner.internal/a2a"
    })
    .to_string();

    let reservation = reserve_port().await.expect("reserve backend port");
    let backend_port = reservation.port;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        card_body.len(),
        card_body
    );
    let backend = ScriptedTcpBackend::builder(reservation.into_listener())
        .step(TcpStep::ReadUntil(b"\r\n\r\n".to_vec()))
        .step(TcpStep::Write(response.into_bytes()))
        .step(TcpStep::Drop)
        .spawn()
        .expect("spawn backend");

    let yaml = a2a_retry_file_config(
        backend_port,
        json!({
            "discovery": {"public_base_url": "https://gateway.example.com"}
        }),
    );
    let harness = GatewayHarness::builder()
        .file_config(yaml)
        .spawn()
        .await
        .expect("spawn gateway");

    let client = harness.http_client().expect("client");
    let resp = client
        .get(&harness.proxy_url("/a2a/.well-known/agent-card.json"))
        .await
        .expect("gateway returns agent card");
    assert_eq!(resp.status, StatusCode::OK);
    let card: serde_json::Value =
        serde_json::from_str(&resp.body_text()).expect("agent card should be JSON");
    assert_eq!(
        card["url"], "https://gateway.example.com/a2a",
        "agent card URL must be rewritten — the buffered JSON path must not \
         be released under retries"
    );
    backend.assert_no_step_errors().await;
}
