use std::error::Error;
use std::fmt;
use std::time::Duration;

use multi_protocol_perf::h2_observation::{
    MAX_CHAIN_BYTES, MAX_EVENTS, Observer, classify, error_chain, escaped_snippet,
};
use multi_protocol_perf::metrics::BenchMetrics;
use multi_protocol_perf::phases::{PhaseReport, TransportEvent};

#[derive(Debug)]
struct Cycle;

impl fmt::Display for Cycle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("cyclic\nerror")
    }
}

impl Error for Cycle {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self)
    }
}

#[test]
fn source_cycles_large_messages_and_control_bytes_are_bounded() {
    let chain = error_chain(&Cycle);
    assert!(chain.ends_with("[depth limit]"));
    assert!(!chain.contains('\n'));
    let large = std::io::Error::other("\n\"\0".repeat(100_000));
    assert!(error_chain(&large).len() <= MAX_CHAIN_BYTES);
    assert!(error_chain(&large).ends_with("[truncated]"));
    let snippet = escaped_snippet(&[b'\n'; 1000]);
    assert_eq!(snippet, "\\n".repeat(200));
}

#[test]
fn bounded_event_storage_preserves_aggregate_errors_and_physical_identity() {
    let observer = Observer::new(true, "test", false);
    let first = observer.connection_id();
    let second = observer.connection_id();
    assert_ne!(first, second);
    let error = h2::Error::from(h2::Reason::ENHANCE_YOUR_CALM);
    let mut metrics = BenchMetrics::new();
    for _ in 0..MAX_EVENTS + 10 {
        observer.record(second, Some(200), Some(3), "unary_echo_error", Some(&error));
        metrics.record_error();
    }
    let mut phases = PhaseReport::default();
    observer.attach(&mut phases);
    assert_eq!(metrics.total_errors, (MAX_EVENTS + 10) as u64);
    assert_eq!(phases.transport_errors_total, MAX_EVENTS + 10);
    assert_eq!(phases.transport_events.len(), MAX_EVENTS);
    assert_eq!(phases.transport_events_suppressed, 10);
    let event = &phases.transport_events[0];
    assert_eq!(event.connection_id, second);
    assert_eq!(event.worker_id, Some(200));
    assert_eq!(event.h2_reason, Some(11), "{event:?}");
    assert_eq!(event.h2_kind.as_deref(), Some("other"));
    assert_eq!(event.h2_initiator.as_deref(), Some("unknown"));
}

#[test]
fn phase_attribution_uses_monotonic_boundaries_even_if_wall_clock_moves_backwards() {
    let mut report = PhaseReport {
        warmup_start_monotonic_secs: Some(2.0),
        measurement_start_monotonic_secs: Some(4.0),
        measurement_secs: 10.0,
        drain_start_monotonic_secs: Some(14.5),
        transport_close_start_monotonic_secs: Some(16.0),
        ..PhaseReport::default()
    };
    report.set_transport_events(
        [16.0, 14.0, 4.0, 2.0, 1.0]
            .into_iter()
            .map(|at| TransportEvent {
                monotonic_secs: Some(at),
                unix_secs: 100.0 - at,
                ..TransportEvent::default()
            })
            .collect(),
    );
    let phases: Vec<_> = report
        .transport_events
        .iter()
        .map(|event| event.phase.as_str())
        .collect();
    assert_eq!(
        phases,
        ["setup", "warmup", "measurement", "drain", "transport_close"]
    );
}

#[tokio::test]
async fn remote_reset_and_goaway_remain_distinct_typed_events() {
    for reset in [true, false] {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (client_io, server_io) = tokio::io::duplex(65_536);
            let server = tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};

                // Keep the peer readable while the client processes the frame.
                // Closing an h2 server after abrupt shutdown can race the
                // client SETTINGS ACK and surface an I/O error instead.
                let mut peer = server_io;
                let mut preface = [0_u8; 24];
                peer.read_exact(&mut preface).await.unwrap();
                assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
                peer.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).await.unwrap();
                loop {
                    let mut header = [0_u8; 9];
                    peer.read_exact(&mut header).await.unwrap();
                    let length = (usize::from(header[0]) << 16)
                        | (usize::from(header[1]) << 8)
                        | usize::from(header[2]);
                    let mut payload = vec![0_u8; length];
                    peer.read_exact(&mut payload).await.unwrap();
                    if header[3] == 1 {
                        assert_eq!(&header[5..], &[0, 0, 0, 1]);
                        break;
                    }
                }
                if reset {
                    // RST_STREAM, stream 1, ENHANCE_YOUR_CALM.
                    peer.write_all(&[0, 0, 4, 3, 0, 0, 0, 0, 1, 0, 0, 0, 11])
                        .await
                        .unwrap();
                } else {
                    // GOAWAY, last processed stream 0, ENHANCE_YOUR_CALM.
                    peer.write_all(&[0, 0, 8, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 11])
                        .await
                        .unwrap();
                }
                let mut buffer = [0_u8; 1024];
                while matches!(peer.read(&mut buffer).await, Ok(n) if n > 0) {}
            });
            let (mut sender, connection) = h2::client::handshake(client_io).await.unwrap();
            let driver = tokio::spawn(connection);
            let request = http::Request::builder()
                .uri("https://localhost/echo")
                .body(())
                .unwrap();
            let (response, _) = sender.send_request(request, true).unwrap();
            let error = response.await.unwrap_err();
            let mut event = TransportEvent::new(1, "error", error_chain(&error));
            classify(&error, &mut event);
            assert_eq!(event.h2_reason, Some(11), "{event:?}");
            assert_eq!(
                event.h2_kind.as_deref(),
                Some(if reset { "reset" } else { "goaway" })
            );
            assert_eq!(event.h2_initiator.as_deref(), Some("remote"));
            drop(sender);
            driver.abort();
            let _ = driver.await;
            server.abort();
            let _ = server.await;
        })
        .await
        .unwrap();
    }
}
