use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use multi_protocol_perf::phases::Phases;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};

#[derive(Clone, Copy)]
enum Shutdown {
    Complete,
    Error,
    Timeout,
}

struct ShutdownStream {
    inner: DuplexStream,
    shutdown: Shutdown,
}

impl AsyncRead for ShutdownStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for ShutdownStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.shutdown {
            Shutdown::Complete => Pin::new(&mut self.inner).poll_shutdown(cx),
            Shutdown::Error => Poll::Ready(Err(std::io::Error::other("close failed"))),
            Shutdown::Timeout => Poll::Pending,
        }
    }
}

#[tokio::test]
async fn tcp_and_tls_shutdown_timeouts_remain_diagnostic_after_measured_echoes() {
    // Both run_tcp branches use this same worker. Inject a stalled AsyncWrite
    // shutdown so the test does not depend on OS socket buffers or TLS timing.
    for label in ["TCP", "TCP+TLS"] {
        let mut phases = Phases::new(Duration::from_millis(100));
        let mut workers = Vec::new();
        let mut peers = Vec::new();
        for shutdown in [Shutdown::Complete, Shutdown::Error, Shutdown::Timeout] {
            let (client, mut server) = tokio::io::duplex(64);
            peers.push(tokio::spawn(async move {
                let mut buffer = [0; 64];
                loop {
                    let n = server.read(&mut buffer).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    server.write_all(&buffer[..n]).await.unwrap();
                }
            }));
            let metrics = phases.worker();
            let connections = phases.connections();
            workers.push(tokio::spawn(async move {
                let metrics = super::tcp_echo(
                    ShutdownStream {
                        inner: client,
                        shutdown,
                    },
                    vec![42; 64],
                    metrics,
                    connections,
                    label,
                )
                .await?;
                assert!(metrics.total_requests > 0);
                assert_eq!(metrics.total_errors, 0);
                assert_eq!(
                    metrics.transport_close_timed_out,
                    matches!(shutdown, Shutdown::Timeout),
                );
                Ok(metrics)
            }));
        }
        let combined = tokio::time::timeout(Duration::from_secs(10), phases.finish(workers))
            .await
            .unwrap();
        for peer in peers {
            peer.await.unwrap();
        }
        assert_eq!(combined.total_errors, 0);
        assert_eq!(combined.warmup_requests, 3);
        assert!(combined.total_requests > 0);
        assert_eq!(combined.total_bytes, combined.total_requests * 64);
        let phases = combined.phases.as_ref().unwrap();
        assert!(!phases.timed_out);
        assert!(phases.transport_close_timed_out);
        let report = serde_json::to_value(combined.to_json_report(label, "test", 3, 1)).unwrap();
        assert_eq!(report["total_errors"], 0);
        assert_eq!(report["phases"]["transport_close_timed_out"], true);
    }
}
