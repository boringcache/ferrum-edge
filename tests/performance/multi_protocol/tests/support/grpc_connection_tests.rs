use std::sync::Arc;
use std::time::Duration;

use multi_protocol_perf::h2_observation::Observer;
use multi_protocol_perf::phases::{PhaseReport, Phases};
use multi_protocol_perf::transport::{GrpcConnectionIdentity, GrpcConnector};
use tokio::net::TcpListener;
use tonic::codegen::Service;

use super::port_registry::TestSocket;

const BOUND: Duration = Duration::from_secs(5);
const CHANNEL_ID: usize = 7;

fn connector() -> GrpcConnector {
    GrpcConnector {
        connections: Phases::new(Duration::from_secs(1)).connections(),
        observer: Observer::new(true, "client_grpc", false),
        channel_id: CHANNEL_ID,
        current_connection: Arc::new(GrpcConnectionIdentity::default()),
    }
}

async fn listener() -> (TcpListener, http::Uri) {
    let listener = TcpListener::bind_test("127.0.0.1:0").await.unwrap();
    let uri = format!("http://{}", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    (listener, uri)
}

#[tokio::test]
async fn socket_retirement_cannot_clear_a_newer_physical_identity() {
    tokio::time::timeout(BOUND, async {
        let (listener, uri) = listener().await;
        let mut connector = connector();
        let identity = connector.current_connection.clone();
        let first = connector.call(uri.clone()).await.unwrap();
        let (_first_peer, _) = listener.accept().await.unwrap();
        let first_id = identity.snapshot();
        assert_ne!(first_id, 0);
        assert_eq!(identity.connection_id_since(first_id), first_id);

        let mut cloned = connector.clone();
        let connecting = cloned.call(uri);
        assert_eq!(identity.snapshot(), 0, "invalidate before polling connect");
        let second = connecting.await.unwrap();
        let (_second_peer, _) = listener.accept().await.unwrap();
        let second_id = identity.snapshot();
        assert_ne!(second_id, 0);
        assert_ne!(second_id, first_id);
        assert_eq!(identity.connection_id_since(first_id), 0);
        drop(first);
        assert_eq!(identity.connection_id_since(second_id), second_id);
        drop(second);
        assert_eq!(identity.snapshot(), 0);

        let mut report = PhaseReport::default();
        connector.observer.attach(&mut report);
        let events: Vec<_> = report
            .transport_events
            .iter()
            .map(|event| {
                assert_eq!(event.channel_id, Some(CHANNEL_ID));
                (event.event.as_str(), event.connection_id)
            })
            .collect();
        assert_eq!(
            events,
            [
                ("socket_opened", first_id),
                ("socket_opened", second_id),
                ("socket_dropped", first_id),
                ("socket_dropped", second_id),
            ]
        );
        assert_eq!(report.transport_errors_total, 0);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn cancelled_and_failed_attempts_do_not_restore_the_previous_socket() {
    tokio::time::timeout(BOUND, async {
        let (listener, uri) = listener().await;
        let mut connector = connector();
        let identity = connector.current_connection.clone();
        let first = connector.call(uri.clone()).await.unwrap();
        let (_first_peer, _) = listener.accept().await.unwrap();
        let first_id = identity.snapshot();
        assert_ne!(first_id, 0);

        // Cancellation before the first poll must still invalidate the old IO.
        let cancelled = connector.call(uri.clone());
        assert_eq!(identity.snapshot(), 0);
        drop(cancelled);
        assert_eq!(identity.connection_id_since(first_id), 0);

        let second = connector.call(uri).await.unwrap();
        let (_second_peer, _) = listener.accept().await.unwrap();
        let second_id = identity.snapshot();
        assert_ne!(second_id, 0);
        // A malformed target fails inside the real Connections service.
        let failed = connector.call("/missing-authority".parse().unwrap());
        assert_eq!(identity.snapshot(), 0);
        assert_eq!(
            failed.await.err().unwrap().kind(),
            std::io::ErrorKind::InvalidInput
        );
        assert_eq!(identity.connection_id_since(second_id), 0);
        drop(first);
        drop(second);
        assert_eq!(identity.snapshot(), 0);

        let mut report = PhaseReport::default();
        connector.observer.attach(&mut report);
        assert_eq!(
            report.transport_events_total, 4,
            "only real sockets counted"
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn superseded_connect_futures_cannot_publish_or_clear_newer_identity() {
    tokio::time::timeout(BOUND, async {
        let (listener, uri) = listener().await;
        let mut connector = connector();
        let identity = connector.current_connection.clone();
        let mut cloned = connector.clone();

        // Poll order differs from invocation order across connector clones.
        let older = connector.call(uri.clone());
        let newer = cloned.call(uri.clone()).await.unwrap();
        let (_newer_peer, _) = listener.accept().await.unwrap();
        let newer_id = identity.snapshot();
        assert_ne!(newer_id, 0);
        let older = older.await.unwrap();
        let (_older_peer, _) = listener.accept().await.unwrap();
        assert_eq!(identity.connection_id_since(newer_id), newer_id);
        drop(older);
        assert_eq!(identity.snapshot(), newer_id);

        // Even a cancelled newer attempt must fence an older late success.
        let older = connector.call(uri.clone());
        let cancelled = cloned.call(uri.clone());
        drop(cancelled);
        let older = older.await.unwrap();
        let (_cancelled_peer, _) = listener.accept().await.unwrap();
        assert_eq!(identity.snapshot(), 0);
        drop(older);

        // Likewise when the newer future completed with an error.
        let older = connector.call(uri.clone());
        assert!(
            cloned
                .call("/missing-authority".parse().unwrap())
                .await
                .is_err()
        );
        let older = older.await.unwrap();
        let (_failed_peer, _) = listener.accept().await.unwrap();
        assert_eq!(identity.snapshot(), 0);
        drop(older);

        // Failure/cancellation of superseded futures cannot clear recovery.
        let failed = connector.call("/missing-authority".parse().unwrap());
        let cancelled = connector.call(uri.clone());
        let recovered = cloned.call(uri).await.unwrap();
        let (_recovered_peer, _) = listener.accept().await.unwrap();
        let recovered_id = identity.snapshot();
        assert_ne!(recovered_id, 0);
        assert!(failed.await.is_err());
        drop(cancelled);
        drop(newer);
        assert_eq!(identity.connection_id_since(recovered_id), recovered_id);
        drop(recovered);
        assert_eq!(identity.snapshot(), 0);

        let mut report = PhaseReport::default();
        connector.observer.attach(&mut report);
        assert_eq!(report.transport_events_total, 10, "five TCP sockets");
    })
    .await
    .unwrap();
}

// A held, bound-but-not-listening socket reliably refuses connects on the
// Linux hosted gate. Darwin can black-hole this fixture instead.
#[cfg(target_os = "linux")]
mod tonic_reconnect {
    use std::convert::Infallible;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll};

    use http_body_util::{BodyExt, StreamBody};
    use hyper::body::Frame;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use multi_protocol_perf::transport::{CountedIo, ObservedChannel};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
    use tokio::net::TcpSocket;
    use tokio::sync::{mpsc, oneshot};
    use tokio::task::JoinSet;

    use super::super::proto_bench::bench_proto::{
        EchoRequest, bench_service_client::BenchServiceClient,
    };
    use super::*;

    #[derive(Debug, PartialEq)]
    enum Event {
        SocketDropped,
        ConnectFailed(std::io::ErrorKind),
    }

    struct DropSignal(mpsc::Sender<Event>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            let _ = self.0.try_send(Event::SocketDropped);
        }
    }

    struct SignalledIo {
        // Field drop order makes the signal a barrier AFTER CountedIo retires.
        inner: CountedIo,
        _dropped: DropSignal,
    }

    impl AsyncRead for SignalledIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for SignalledIo {
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

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    #[derive(Clone)]
    struct ProbedConnector {
        inner: GrpcConnector,
        attempts: Arc<AtomicUsize>,
        refused_uri: http::Uri,
        events: mpsc::Sender<Event>,
    }

    impl Service<http::Uri> for ProbedConnector {
        type Response = TokioIo<SignalledIo>;
        type Error = std::io::Error;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            self.inner.poll_ready(cx)
        }

        fn call(&mut self, uri: http::Uri) -> Self::Future {
            // Keep the refused destination reserved throughout the test, rather
            // than releasing/rebinding the server port and racing other tests.
            let target = if self.attempts.fetch_add(1, Ordering::Relaxed) == 0 {
                uri
            } else {
                self.refused_uri.clone()
            };
            let connect = self.inner.call(target);
            let events = self.events.clone();
            Box::pin(async move {
                match connect.await {
                    Ok(io) => Ok(TokioIo::new(SignalledIo {
                        inner: io.into_inner(),
                        _dropped: DropSignal(events),
                    })),
                    Err(error) => {
                        events.try_send(Event::ConnectFailed(error.kind())).unwrap();
                        Err(error)
                    }
                }
            })
        }
    }

    #[tokio::test]
    async fn cancelling_tonic_connect_during_tls_retires_the_owned_socket() {
        tokio::time::timeout(BOUND, async {
            let (listener, _) = listener().await;
            let endpoint = tonic::transport::Endpoint::from_shared(format!(
                "https://{}",
                listener.local_addr().unwrap()
            ))
            .unwrap()
            .tls_config(tonic::transport::ClientTlsConfig::new().domain_name("localhost"))
            .unwrap();
            let connector = connector();
            let identity = connector.current_connection.clone();
            let observer = connector.observer.clone();
            let mut connect = JoinSet::new();
            connect.spawn(async move { endpoint.connect_with_connector(connector).await });
            let (mut peer, _) = listener.accept().await.unwrap();
            // Receiving the ClientHello proves TCP connected and the real
            // Tonic TLS future owns CountedIo. Keep TLS pending without sleeps.
            let mut record_header = [0; 5];
            peer.read_exact(&mut record_header).await.unwrap();
            assert_eq!(record_header[0], 22, "TLS handshake record");
            let connected = identity.snapshot();
            assert_ne!(connected, 0);
            connect.abort_all();
            assert!(
                connect
                    .join_next()
                    .await
                    .unwrap()
                    .unwrap_err()
                    .is_cancelled()
            );
            assert_eq!(identity.snapshot(), 0);
            assert_eq!(identity.connection_id_since(connected), 0);

            let mut report = PhaseReport::default();
            observer.attach(&mut report);
            assert_eq!(report.transport_events_total, 2);
            assert_eq!(report.transport_events[0].event, "socket_opened");
            assert_eq!(report.transport_events[1].event, "socket_dropped");
            for event in &report.transport_events {
                assert_eq!(event.channel_id, Some(CHANNEL_ID));
                assert_eq!(event.connection_id, connected);
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn tonic_refused_reconnect_keeps_channel_but_has_no_physical_identity() {
        tokio::time::timeout(BOUND, async {
            let (listener, uri) = listener().await;
            let refused = TcpSocket::bind_test("127.0.0.1:0").unwrap();
            let refused_uri = format!("http://{}", refused.local_addr().unwrap())
                .parse()
                .unwrap();
            let (close, closed) = oneshot::channel();
            let mut server = JoinSet::new();
            server.spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let echo = hyper::service::service_fn(
                    |request: http::Request<hyper::body::Incoming>| async {
                        assert_eq!(request.uri().path(), "/bench.BenchService/UnaryEcho");
                        let body = request.into_body().collect().await.unwrap().to_bytes();
                        // EchoRequest and EchoResponse both use protobuf field 1
                        // for payload. Preserve the complete gRPC message framing.
                        let mut trailers = http::HeaderMap::new();
                        trailers.insert("grpc-status", http::HeaderValue::from_static("0"));
                        let frames = [
                            Ok::<_, Infallible>(Frame::data(body)),
                            Ok(Frame::trailers(trailers)),
                        ];
                        Ok::<_, Infallible>(
                            http::Response::builder()
                                .header("content-type", "application/grpc")
                                .body(StreamBody::new(futures_util::stream::iter(frames)))
                                .unwrap(),
                        )
                    },
                );
                let connection = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), echo);
                tokio::pin!(connection);
                tokio::select! {
                    result = &mut connection => panic!("server closed before signal: {result:?}"),
                    result = closed => result.unwrap(),
                }
                // Own and drop the actual H2 connection, not just an accept
                // task whose Tonic server drivers would remain detached.
            });

            let connector = connector();
            let identity = connector.current_connection.clone();
            let observer = connector.observer.clone();
            let attempts = Arc::new(AtomicUsize::new(0));
            let (events, mut received) = mpsc::channel(8);
            let channel = tonic::transport::Endpoint::from_shared(uri.to_string())
                .unwrap()
                .connect_with_connector(ProbedConnector {
                    inner: connector,
                    attempts: attempts.clone(),
                    refused_uri,
                    events,
                })
                .await
                .unwrap();
            let mut client = BenchServiceClient::new(ObservedChannel {
                inner: channel,
                admission: None,
            });
            let first_id = identity.snapshot();
            assert_ne!(first_id, 0);
            let response = client
                .unary_echo(EchoRequest {
                    payload: b"physical identity".to_vec(),
                })
                .await
                .unwrap();
            assert_eq!(response.into_inner().payload, b"physical identity");
            assert_eq!(identity.connection_id_since(first_id), first_id);
            assert_eq!(attempts.load(Ordering::Relaxed), 1);

            close.send(()).unwrap();
            server.join_next().await.unwrap().unwrap();
            assert_eq!(received.recv().await, Some(Event::SocketDropped));
            assert_eq!(identity.snapshot(), 0, "retired transport is unknown");
            assert_eq!(identity.connection_id_since(first_id), 0);

            let before = identity.snapshot();
            let error = client
                .unary_echo(EchoRequest { payload: vec![1] })
                .await
                .unwrap_err();
            assert_eq!(error.code(), tonic::Code::Unavailable);
            assert_eq!(
                received.recv().await,
                Some(Event::ConnectFailed(std::io::ErrorKind::ConnectionRefused))
            );
            assert!(attempts.load(Ordering::Relaxed) >= 2);
            observer.record(
                identity.connection_id_since(before),
                Some(3),
                Some(CHANNEL_ID),
                "unary_echo_error",
                Some(&error),
            );
            let mut report = PhaseReport::default();
            observer.attach(&mut report);
            assert_eq!(report.transport_events_total, 3);
            assert_eq!(report.transport_errors_total, 1);
            let failure = report.transport_events.last().unwrap();
            assert_eq!(failure.event, "unary_echo_error");
            assert_eq!(failure.channel_id, Some(CHANNEL_ID));
            assert_eq!(failure.worker_id, Some(3));
            assert_eq!(failure.connection_id, 0);
            assert_eq!(identity.snapshot(), 0);
            drop(client);
            drop(refused);
        })
        .await
        .unwrap();
    }
}
