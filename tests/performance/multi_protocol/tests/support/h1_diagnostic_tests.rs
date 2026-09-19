use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use multi_protocol_perf::h1_diagnostic::{
    CLOCK_DOMAIN, Diagnostic, DiagnosticBody, Drivers, MAX_CONNECTIONS, MAX_SNAPSHOTS, MAX_WORKERS,
};
use multi_protocol_perf::metrics::BenchMetrics;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

use super::port_registry::TestSocket;
use super::proto_bench::h1_diagnostic_test_run;

const ECHO: [u8; 4] = [0xab, 0xca, 0xe9, 0x08];

#[derive(Clone, Copy)]
enum Reply {
    Clean,
    TruncatedLength,
    TruncatedChunk,
    InvalidHeaders,
    DelayedWarmup,
    StalledDrain,
}

async fn read_request(stream: &mut (impl AsyncRead + Unpin)) {
    let mut headers = Vec::new();
    while !headers.ends_with(b"\r\n\r\n") {
        headers.push(stream.read_u8().await.unwrap());
        assert!(headers.len() < 8192);
    }
    let mut body = [0; 4];
    stream.read_exact(&mut body).await.unwrap();
    assert_eq!(body, ECHO);
}

async fn respond(mut stream: impl AsyncRead + AsyncWrite + Unpin, reply: Reply) {
    if matches!(reply, Reply::Clean) {
        let service = hyper::service::service_fn(
            |request: hyper::Request<hyper::body::Incoming>| async move {
                let bytes = request.into_body().collect().await.unwrap().to_bytes();
                assert_eq!(bytes.as_ref(), ECHO);
                Ok::<_, std::convert::Infallible>(
                    hyper::Response::builder()
                        .header("set-cookie", "synthetic-secret-must-not-be-retained")
                        .body(Full::new(bytes))
                        .unwrap(),
                )
            },
        );
        // Only client-side completion/retirement is under test here.
        let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
            .await;
        return;
    }
    read_request(&mut stream).await;
    if matches!(reply, Reply::InvalidHeaders) {
        stream.write_all(b"NOT-HTTP\r\n\r\n").await.unwrap();
    } else if matches!(reply, Reply::TruncatedChunk) {
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n")
            .await
            .unwrap();
        stream.write_all(&ECHO[..2]).await.unwrap();
    } else {
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n")
            .await
            .unwrap();
        stream.write_all(&ECHO[..2]).await.unwrap();
        stream.flush().await.unwrap();
        if !matches!(reply, Reply::TruncatedLength) {
            if matches!(reply, Reply::DelayedWarmup) {
                tokio::time::sleep(Duration::from_secs(11)).await;
            }
            stream.write_all(&ECHO[2..]).await.unwrap();
            stream.flush().await.unwrap();
            if matches!(reply, Reply::StalledDrain) {
                read_request(&mut stream).await;
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n")
                    .await
                    .unwrap();
                stream.write_all(&ECHO[..2]).await.unwrap();
                stream.flush().await.unwrap();
            }
            // Client closure, not a fixture timer, releases this wait.
            let mut byte = [0];
            match stream.read(&mut byte).await {
                Ok(0) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::UnexpectedEof
                    ) => {}
                other => panic!("expected client transport retirement, got {other:?}"),
            }
        }
    }
    // Hyper driver completion does not promise a TLS close_notify handshake.
    let _ = stream.shutdown().await;
}

async fn run(reply: Reply, tls: bool, enabled: bool, seconds: u64) -> BenchMetrics {
    tokio::time::timeout(Duration::from_secs(45), async {
        let provider = rustls::crypto::ring::default_provider();
        let _ = rustls::crypto::CryptoProvider::install_default(provider);
        let listener = TcpListener::bind_test("127.0.0.1:0").await.unwrap();
        let target = format!(
            "{}://{}/echo",
            if tls { "https" } else { "http" },
            listener.local_addr().unwrap()
        );
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            if tls {
                let cert =
                    rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
                let key =
                    rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
                let mut config = rustls::ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(vec![cert.cert.der().clone()], key.into())
                    .unwrap();
                config.alpn_protocols = vec![b"http/1.1".to_vec()];
                let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
                respond(acceptor.accept(socket).await.unwrap(), reply).await;
            } else {
                respond(socket, reply).await;
            }
        });
        let result = h1_diagnostic_test_run(target, enabled, seconds).await;
        server.await.unwrap();
        result
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn clean_plain_and_tls_echo_preserve_opt_in_off_semantics_and_retirement() {
    for tls in [false, true] {
        for enabled in [false, true] {
            let metrics = run(Reply::Clean, tls, enabled, 1).await;
            assert_eq!(metrics.warmup_requests, 1);
            assert!(metrics.total_requests > 0);
            assert_eq!(metrics.total_errors, 0);
            assert_eq!(
                metrics.observed.as_ref().unwrap().admissions,
                metrics.total_requests + metrics.drain_requests
            );
            let completions =
                metrics.warmup_requests + metrics.total_requests + metrics.drain_requests;
            let phases = metrics.phases.unwrap();
            if !enabled {
                assert!(phases.h1_diagnostic.is_none());
                assert!(
                    serde_json::to_value(&phases)
                        .unwrap()
                        .get("h1_diagnostic")
                        .is_none()
                );
                continue;
            }
            let report = phases.h1_diagnostic.unwrap();
            assert_eq!(report.clock_domain, CLOCK_DOMAIN);
            let snapshot = report.snapshots.last().unwrap();
            let worker = &snapshot.workers[0];
            assert_eq!(worker.completions, completions);
            assert_eq!(worker.bodies_admitted, completions);
            assert!(
                !serde_json::to_string(&report)
                    .unwrap()
                    .contains("synthetic-secret")
            );
            assert_eq!(worker.request.body_bytes, 4);
            assert_eq!(worker.request.response_bytes, 4);
            assert!(worker.request.body_end.is_some());
            assert!(worker.request.response_end.is_some());
            assert_eq!(worker.request.validated, Some(true));
            assert_eq!(worker.request.status, Some(200));
            assert_eq!(worker.request.content_length, Some(4));
            assert_eq!(worker.request.version, Some("HTTP/1.1"));
            assert!(snapshot.connections[0].local.is_some());
            assert!(snapshot.connections[0].peer.is_some());
            let retirement = report.retirement.unwrap();
            assert_eq!(retirement.started, 1);
            assert_eq!(retirement.completed_ok, 1);
            assert_eq!(
                retirement.completed_error + retirement.cancelled + retirement.panicked,
                0
            );
            assert!(!retirement.timed_out);
        }
    }
}

#[tokio::test]
async fn truncated_and_invalid_responses_cannot_manufacture_eof_or_success() {
    for reply in [
        Reply::TruncatedLength,
        Reply::TruncatedChunk,
        Reply::InvalidHeaders,
    ] {
        let metrics = run(reply, false, true, 0).await;
        assert_eq!(metrics.warmup_requests, 0);
        assert_eq!(metrics.total_errors, 1);
        let report = metrics.phases.unwrap().h1_diagnostic.unwrap();
        let worker = &report.snapshots.last().unwrap().workers[0];
        assert_eq!(worker.completions, 0);
        assert!(worker.request.response_end.is_none());
        assert!(worker.request.completion.is_none());
        assert!(worker.request.error_class.is_some());
        assert!(worker.request.error_at.is_some());
        if !matches!(reply, Reply::InvalidHeaders) {
            assert_eq!(worker.request.response_bytes, 2);
            assert_eq!(worker.request.status, Some(200));
        }
        let retirement = report.retirement.unwrap();
        if matches!(reply, Reply::InvalidHeaders) {
            assert_eq!(retirement.completed_error, 1);
            assert_eq!(worker.request.error_class, Some("http_parse"));
        }
        assert_eq!(
            retirement.started,
            retirement.completed_ok + retirement.completed_error
        );
        assert!(!retirement.timed_out);
    }
}

#[tokio::test]
async fn delayed_warmup_snapshot_uses_existing_single_warmup_and_named_phase_clock() {
    let metrics = run(Reply::DelayedWarmup, true, true, 0).await;
    assert_eq!(metrics.warmup_requests, 1);
    let report = metrics.phases.unwrap().h1_diagnostic.unwrap();
    let snapshot = report
        .snapshots
        .iter()
        .find(|s| s.reason == "delayed_warmup")
        .unwrap();
    assert_eq!(snapshot.clock_domain, CLOCK_DOMAIN);
    assert_eq!(snapshot.at.phase, "warmup");
    assert!(snapshot.at.phase_us >= 10_000_000);
    let worker = &snapshot.workers[0];
    assert_eq!(worker.stage, "response_body");
    assert_eq!(worker.request.response_bytes, 2);
    assert!(worker.request.response_end.is_none());
    assert_eq!(report.snapshots.last().unwrap().workers[0].requests_offered, 1);
}

#[tokio::test]
async fn actual_pre_abort_snapshot_retains_blocked_await_and_cancelled_worker_counters() {
    // This deliberately exercises the unchanged real 30-second drain bound.
    let metrics = run(Reply::StalledDrain, false, true, 1).await;
    assert_eq!(metrics.total_errors, 1);
    let phases = metrics.phases.unwrap();
    assert!(phases.timed_out);
    assert!(phases.drain_secs >= 30.0);
    let report = phases.h1_diagnostic.unwrap();
    let before = report
        .snapshots
        .iter()
        .find(|s| s.reason == "drain_pre_abort")
        .unwrap();
    let after = report
        .snapshots
        .iter()
        .find(|s| s.reason == "request_drain_complete")
        .unwrap();
    let worker = &before.workers[0];
    assert_eq!(worker.stage, "response_body");
    assert_eq!(worker.lifecycle, "running");
    assert_eq!(worker.requests_offered, 2);
    assert_eq!(worker.completions, 1); // Warmup survives lost local BenchMetrics.
    assert_eq!(worker.bodies_admitted, 2);
    assert_eq!(worker.request.response_bytes, 2);
    assert!(worker.request.response_end.is_none());
    assert!(worker.request.completion.is_none());
    assert_eq!(worker.request.id, after.workers[0].request.id);
    assert_eq!(after.workers[0].stage, "response_body");
    assert_eq!(after.workers[0].lifecycle, "dropped_without_return");
}

#[tokio::test]
async fn retirement_timeout_is_separate_from_request_completion_and_connection_guard() {
    let diagnostic = Diagnostic::new(true);
    let mut trace = diagnostic.worker(0);
    let observation = trace.observation.request();
    let id = observation.socket(None, None);
    let connections = multi_protocol_perf::phases::Phases::new(Duration::ZERO).connections();
    let guard = connections.opened();
    let drivers = Drivers::default();
    drivers
        .spawn(&diagnostic, id, async move {
            let _guard = guard;
            std::future::pending::<Result<(), hyper::Error>>().await
        })
        .unwrap();
    DiagnosticBody::new(
        Full::new(Bytes::from_static(&ECHO)),
        observation.clone(),
        false,
    )
    .collect()
    .await
    .unwrap();
    observation.complete(true);
    trace.returned(true);
    diagnostic.snapshot("request_drain_complete");
    drivers.retire(&diagnostic, Duration::from_millis(5)).await;
    let report = diagnostic.report().unwrap();
    let retirement = report.retirement.unwrap();
    assert_eq!(retirement.completed_ok, 0);
    assert_eq!(retirement.cancelled, 1);
    assert_eq!(retirement.abort_requested, 1);
    assert!(retirement.timed_out);
    assert_eq!(retirement.unreaped_after_abort, 0);
    let final_state = report.snapshots.last().unwrap();
    assert_eq!(final_state.workers[0].completions, 1);
    assert_eq!(final_state.workers[0].request.validated, Some(true));
    assert_eq!(final_state.connections[0].driver, "dropped_without_result");
}

#[tokio::test]
async fn bounded_capture_loss_and_stale_body_updates_are_explicit() {
    let diagnostic = Diagnostic::new(true);
    let trace = diagnostic.worker(0);
    let old = trace.observation.request();
    let current = trace.observation.request();
    DiagnosticBody::new(Full::new(Bytes::from_static(&ECHO)), old, false)
        .collect()
        .await
        .unwrap();
    current.stage("send_request");
    for id in 1..=MAX_WORKERS {
        diagnostic.worker(id);
    }
    for _ in 0..=MAX_CONNECTIONS {
        current.socket(None, None);
    }
    for _ in 0..=MAX_SNAPSHOTS {
        diagnostic.snapshot("capacity_test");
    }
    let report = diagnostic.report().unwrap();
    assert_eq!(report.loss.workers, 1);
    assert_eq!(report.loss.connections, 1);
    assert_eq!(report.loss.snapshots, 1);
    assert!(report.loss.updates > 0);
    assert_eq!(report.snapshots.len(), MAX_SNAPSHOTS);
    assert_eq!(report.snapshots[0].workers.len(), MAX_WORKERS);
    assert_eq!(report.snapshots[0].connections.len(), MAX_CONNECTIONS);
    assert_eq!(report.snapshots[0].workers[0].request.response_bytes, 0);
    assert!(report.snapshots[0].workers[0].request.response_end.is_none());
    assert!(serde_json::to_vec(&report).unwrap().len() < 4 * 1024 * 1024);
}

#[tokio::test]
async fn live_driver_capacity_and_panics_are_never_clean_retirements() {
    let diagnostic = Diagnostic::new(true);
    let trace = diagnostic.worker(0);
    let drivers = Drivers::default();
    for _ in 0..MAX_CONNECTIONS {
        let id = trace.observation.socket(None, None);
        drivers
            .spawn(&diagnostic, id, std::future::pending())
            .unwrap();
    }
    assert!(
        drivers
            .spawn(&diagnostic, 9999, std::future::pending())
            .is_err()
    );
    drivers.retire(&diagnostic, Duration::ZERO).await;
    let report = diagnostic.report().unwrap();
    let retirement = report.retirement.unwrap();
    assert_eq!(retirement.started, MAX_CONNECTIONS as u64);
    assert_eq!(retirement.capacity_rejections, 1);
    assert_eq!(retirement.completed_ok, 0);
    assert_eq!(retirement.cancelled, MAX_CONNECTIONS as u64);
    assert_eq!(retirement.unreaped_after_abort, 0);

    let diagnostic = Diagnostic::new(true);
    let trace = diagnostic.worker(0);
    let id = trace.observation.socket(None, None);
    let drivers = Drivers::default();
    drivers
        .spawn(&diagnostic, id, async { panic!("driver panic fixture") })
        .unwrap();
    drivers.retire(&diagnostic, Duration::from_secs(1)).await;
    let report = diagnostic.report().unwrap();
    assert_eq!(report.retirement.unwrap().panicked, 1);
    assert_eq!(
        report.snapshots[0].connections[0].driver,
        "dropped_without_result"
    );
}

#[test]
fn phase_relative_time_uses_deadline_without_relabeling_host_time() {
    let diagnostic = Diagnostic::new(true);
    let now = Instant::now();
    diagnostic.phase("measurement", now, Some(now));
    diagnostic.snapshot("deadline");
    let report = diagnostic.report().unwrap();
    assert_eq!(report.snapshots[0].at.phase, "drain");
    assert_eq!(report.clock_domain, CLOCK_DOMAIN);
    assert!(Diagnostic::new(false).report().is_none());
}
