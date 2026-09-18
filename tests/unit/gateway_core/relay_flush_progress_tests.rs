//! Flush progress for the shared relay copy loop
//! ([issue #5588](https://github.com/ferrum-edge/ferrum-edge/issues/5588),
//! section 3; `docs/benchmark_audit_2026_09_17.md`).
//!
//! `src/proxy/tcp_proxy.rs::poll_copy_direction` used to accept bytes into the
//! writer, return to polling the reader, and park there without flushing. That
//! is only safe for a writer that hands everything straight to the transport.
//! A buffering writer keeps the bytes: `tokio::io::BufWriter` copies them into
//! its own buffer, and `tokio-rustls`' `poll_write` returns `Ok(n)` for
//! plaintext whose ciphertext it could not push (`common::Stream::poll_write`'s
//! `(n, would_block)` arm). For a request/response protocol the peer that owes
//! the relay its next read is then waiting on bytes nothing will send — the
//! WSS/large-payload timeout shape the audit was chasing. Tokio's own
//! `CopyBuffer::poll_copy` flushes when the read side is pending for exactly
//! this reason.
//!
//! Every test here drives the PRODUCTION relay through `_test_support`, not a
//! re-typed copy of the loop:
//!
//! * `bidirectional_copy_for_test_with_timeouts` — userspace TCP/TLS and
//!   WebSocket tunnel mode (`bidirectional_copy_for_relay`);
//! * `bidirectional_copy_for_fenced_relay_for_test` — the HBONE HTTP/2 CONNECT
//!   byte tunnel, under the mesh admission fence's revocation bound;
//! * `bidirectional_copy_with_authorization_for_test` — the authorization
//!   lifetime bound.
//!
//! The structural sibling inventory lives in `shared_invariant_parity_tests.rs`
//! (`every_tunnelled_relay_path_shares_one_flushing_byte_pump`).

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use ferrum_edge::_test_support::{
    StreamIoSide, bidirectional_copy_for_fenced_relay_for_test,
    bidirectional_copy_for_test_with_timeouts, bidirectional_copy_with_authorization_for_test,
};
use ferrum_edge::plugins::Direction;
use ferrum_edge::retry::ErrorClass;
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufWriter, DuplexStream, ReadBuf,
};

/// Long enough that no assertion below can pass because a relay bound fired
/// instead of the flush.
const RELAY_IDLE_TIMEOUT: Option<Duration> = Some(Duration::from_secs(300));
const RELAY_HALF_CLOSE_CAP: Option<Duration> = Some(Duration::from_secs(300));

/// How long a delivery may take before the relay is considered deadlocked. The
/// unfixed loop never delivers at all, so this only has to exceed scheduling
/// noise.
const DELIVERY_WINDOW: Duration = Duration::from_secs(5);

const RELAY_BUFFER: usize = 8 * 1024;
const PEER_BUFFER: usize = 64 * 1024;

const REQUEST: &[u8] = b"GET /relay HTTP/1.1\r\nHost: flush-progress\r\n\r\n";
const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// Transparent `AsyncRead`/`AsyncWrite` wrapper that counts `poll_flush` calls.
///
/// Wrapping a real `BufWriter` rather than re-implementing one keeps the
/// buffering semantics authentic while making the relay's flush cadence
/// observable: the relay must owe at most one flush per accepted batch, never
/// one per byte.
struct FlushCounting<S> {
    inner: S,
    flushes: Arc<AtomicUsize>,
}

impl<S> FlushCounting<S> {
    fn new(inner: S, flushes: Arc<AtomicUsize>) -> Self {
        Self { inner, flushes }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for FlushCounting<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for FlushCounting<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.flushes.fetch_add(1, Ordering::SeqCst);
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// A writer that accepts every byte and never lets go of one: `poll_flush`
/// stays `Pending` forever. Models a TLS writer whose transport has stopped
/// draining, so the relay owes a flush it cannot complete.
struct AcceptsButNeverFlushes;

impl AsyncRead for AcceptsButNeverFlushes {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWrite for AcceptsButNeverFlushes {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

const FLUSH_FAILURE_TEXT: &str = "simulated transport abort during flush";

/// A writer that accepts every byte and then fails the flush. The failure is
/// raised by the flush, not by a write, so it must still be attributed to the
/// write side of the direction that owed it.
struct AcceptsThenFailsFlush;

impl AsyncRead for AcceptsThenFailsFlush {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWrite for AcceptsThenFailsFlush {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let failure = io::Error::new(io::ErrorKind::ConnectionAborted, FLUSH_FAILURE_TEXT);
        Poll::Ready(Err(failure))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// A duplex leg whose write half is buffered — the minimal reproduction of the
/// defect, and the shape the audit's extracted-function fixture used.
fn buffered_leg(capacity: usize) -> (BufWriter<DuplexStream>, DuplexStream) {
    let (near, far) = tokio::io::duplex(capacity);
    (BufWriter::with_capacity(capacity, near), far)
}

// ---------------------------------------------------------------------------
// The defect: bytes accepted by a buffering writer while the reader is pending
// ---------------------------------------------------------------------------

/// Regression for the audit's finding. The relay accepts the whole request into
/// a buffering backend writer and then parks on a client that is still open and
/// simply has nothing more to say. Before the fix the request sat in the
/// writer's buffer and the backend never saw a byte.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_buffered_backend_writer_is_flushed_while_the_client_reader_is_pending() {
    let (client, mut client_peer) = tokio::io::duplex(PEER_BUFFER);
    let (backend, mut backend_peer) = buffered_leg(PEER_BUFFER);

    client_peer
        .write_all(REQUEST)
        .await
        .expect("client request");

    let relay = tokio::spawn(bidirectional_copy_for_test_with_timeouts(
        client,
        backend,
        RELAY_IDLE_TIMEOUT,
        RELAY_HALF_CLOSE_CAP,
        None,
        None,
        RELAY_BUFFER,
    ));

    let mut seen = vec![0u8; REQUEST.len()];
    tokio::time::timeout(DELIVERY_WINDOW, backend_peer.read_exact(&mut seen))
        .await
        .expect("the relay must flush a buffering writer while its reader is pending")
        .expect("backend read");
    assert_eq!(seen, REQUEST, "the backend must see the request verbatim");

    // Only now let both peers go, so the delivery above cannot be credited to
    // the half-close flush inside `poll_shutdown`.
    drop(client_peer);
    drop(backend_peer);
    let result = tokio::time::timeout(DELIVERY_WINDOW, relay)
        .await
        .expect("the relay must finish once both peers close")
        .expect("relay task");
    assert!(
        result.first_failure.is_none(),
        "a flushed relay that both peers closed cleanly must report no failure, got {:?}",
        result.first_failure
    );
    assert_eq!(result.bytes_client_to_backend, REQUEST.len() as u64);
}

/// The same defect in the other direction: the backend answers and the client
/// leg is the buffering writer. Fixing one direction and leaving the other is
/// the sibling shape `.claude/rules/testing.md` calls out.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_buffered_client_writer_is_flushed_while_the_backend_reader_is_pending() {
    let (client, mut client_peer) = buffered_leg(PEER_BUFFER);
    let (backend, mut backend_peer) = tokio::io::duplex(PEER_BUFFER);

    backend_peer.write_all(RESPONSE).await.expect("response");

    let relay = tokio::spawn(bidirectional_copy_for_test_with_timeouts(
        client,
        backend,
        RELAY_IDLE_TIMEOUT,
        RELAY_HALF_CLOSE_CAP,
        None,
        None,
        RELAY_BUFFER,
    ));

    let mut seen = vec![0u8; RESPONSE.len()];
    tokio::time::timeout(DELIVERY_WINDOW, client_peer.read_exact(&mut seen))
        .await
        .expect("the backend→client direction must flush its buffering writer too")
        .expect("client read");
    assert_eq!(seen, RESPONSE, "the client must see the response verbatim");

    drop(client_peer);
    drop(backend_peer);
    let result = tokio::time::timeout(DELIVERY_WINDOW, relay)
        .await
        .expect("the relay must finish once both peers close")
        .expect("relay task");
    assert_eq!(result.bytes_backend_to_client, RESPONSE.len() as u64);
}

/// The HBONE HTTP/2 CONNECT byte tunnel runs the same copy loop through
/// `bidirectional_copy_for_fenced_relay`. Exercise it the same way, so the
/// sibling the audit named is covered behaviorally and not only structurally.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_fenced_h2_byte_tunnel_relay_flushes_a_buffering_writer_too() {
    let (client, mut client_peer) = tokio::io::duplex(PEER_BUFFER);
    let (backend, mut backend_peer) = buffered_leg(PEER_BUFFER);

    client_peer
        .write_all(REQUEST)
        .await
        .expect("client request");

    let relay = tokio::spawn(bidirectional_copy_for_fenced_relay_for_test(
        client,
        backend,
        RELAY_IDLE_TIMEOUT,
        RELAY_HALF_CLOSE_CAP,
        None,
        None,
        RELAY_BUFFER,
        None,
    ));

    let mut seen = vec![0u8; REQUEST.len()];
    tokio::time::timeout(DELIVERY_WINDOW, backend_peer.read_exact(&mut seen))
        .await
        .expect("the fenced HBONE relay must flush a buffering writer as well")
        .expect("tunnel read");
    assert_eq!(seen, REQUEST);

    drop(client_peer);
    drop(backend_peer);
    let result = tokio::time::timeout(DELIVERY_WINDOW, relay)
        .await
        .expect("the fenced relay must finish once both peers close")
        .expect("relay task");
    assert_eq!(result.bytes_client_to_backend, REQUEST.len() as u64);
}

/// Real rustls backpressure, which is what tracker #5588 section 3 asks for.
///
/// The TLS transport window is deliberately smaller than one encrypted record
/// of the relayed payload, so `tokio-rustls` accepts the whole plaintext and
/// keeps the ciphertext it could not push. The far peer holds a partial record
/// it cannot decrypt, which is precisely the state in which the unfixed relay
/// parked on a still-open client and neither side ever moved again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rustls_writer_holding_ciphertext_is_flushed_while_the_reader_is_pending() {
    // Smaller than the ~8 KiB record the payload below produces, so the first
    // `write_io` fills it and rustls retains the remainder.
    const TLS_TRANSPORT_WINDOW: usize = 4 * 1024;
    const PAYLOAD_LEN: usize = 8 * 1024;

    let (server_config, client_config) = test_tls_configs();
    let (client_io, server_io) = tokio::io::duplex(TLS_TRANSPORT_WINDOW);

    let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
    let server_handshake = tokio::spawn(async move {
        let accepted = acceptor.accept(server_io).await;
        accepted.expect("server handshake")
    });
    let connector = tokio_rustls::TlsConnector::from(client_config);
    let host = "localhost".to_string();
    let name = rustls::pki_types::ServerName::try_from(host).expect("server name");
    let connect = connector.connect(name, client_io);
    let tls_backend = connect.await.expect("client handshake");
    let mut tls_peer = server_handshake.await.expect("server handshake task");

    let payload = vec![0x5au8; PAYLOAD_LEN];
    let (client, mut client_peer) = tokio::io::duplex(PEER_BUFFER);
    client_peer.write_all(&payload).await.expect("payload");

    let relay = tokio::spawn(bidirectional_copy_for_test_with_timeouts(
        client,
        tls_backend,
        RELAY_IDLE_TIMEOUT,
        RELAY_HALF_CLOSE_CAP,
        None,
        None,
        RELAY_BUFFER,
    ));

    let mut seen = vec![0u8; PAYLOAD_LEN];
    tokio::time::timeout(DELIVERY_WINDOW, tls_peer.read_exact(&mut seen))
        .await
        .expect("rustls kept the ciphertext; the relay must flush it, not park")
        .expect("TLS peer read");
    assert_eq!(seen, payload, "the TLS peer must see the payload verbatim");

    // Close both legs so the relay can complete; the TLS peer's transport going
    // away is what ends the backend→client half.
    drop(tls_peer);
    drop(client_peer);
    let result = tokio::time::timeout(DELIVERY_WINDOW, relay)
        .await
        .expect("the relay must finish once both legs close")
        .expect("relay task");
    assert_eq!(result.bytes_client_to_backend, PAYLOAD_LEN as u64);
}

fn test_tls_configs() -> (Arc<rustls::ServerConfig>, Arc<rustls::ClientConfig>) {
    let ecdsa = &rcgen::PKCS_ECDSA_P256_SHA256;
    let key = rcgen::KeyPair::generate_for(ecdsa).expect("leaf key");
    let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("params");
    let cert = params.self_signed(&key).expect("self-signed leaf");

    let certs = rustls_pemfile::certs(&mut cert.pem().as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .expect("parse test leaf certificate");
    let private_key = rustls_pemfile::private_key(&mut key.serialize_pem().as_bytes())
        .expect("parse test leaf key")
        .expect("test leaf key present");

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let server = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("test TLS protocol versions")
        .with_no_client_auth()
        .with_single_cert(certs, private_key)
        .expect("test TLS server config");
    let client = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("test TLS protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(ferrum_edge::tls::NoVerifier))
        .with_no_client_auth();

    (Arc::new(server), Arc::new(client))
}

// ---------------------------------------------------------------------------
// Cost: one flush per accepted batch, never one per byte
// ---------------------------------------------------------------------------

/// The flush is owed once per batch the writer accepted, and the debt is
/// cleared when it completes. An unbuffered writer's `poll_flush` is a no-op,
/// so this is also what keeps the plain-TCP hot path syscall-free.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_accepted_batch_owes_exactly_one_flush() {
    let flushes = Arc::new(AtomicUsize::new(0));
    let (client, mut client_peer) = tokio::io::duplex(PEER_BUFFER);
    let (buffered, mut backend_peer) = buffered_leg(PEER_BUFFER);
    let backend = FlushCounting::new(buffered, Arc::clone(&flushes));

    client_peer
        .write_all(REQUEST)
        .await
        .expect("client request");

    let relay = tokio::spawn(bidirectional_copy_for_test_with_timeouts(
        client,
        backend,
        RELAY_IDLE_TIMEOUT,
        RELAY_HALF_CLOSE_CAP,
        None,
        None,
        RELAY_BUFFER,
    ));

    let mut first = vec![0u8; REQUEST.len()];
    tokio::time::timeout(DELIVERY_WINDOW, backend_peer.read_exact(&mut first))
        .await
        .expect("the buffered request must be flushed")
        .expect("backend read");
    assert_eq!(
        flushes.load(Ordering::SeqCst),
        1,
        "one accepted batch must owe exactly one flush, not one per byte"
    );

    // A second batch: the writer accepts again, so the relay owes one more
    // flush and no more than one. Reading the batch back proves that flush
    // already completed, so the count cannot still be racing upward.
    client_peer.write_all(RESPONSE).await.expect("second batch");
    let mut second = vec![0u8; RESPONSE.len()];
    tokio::time::timeout(DELIVERY_WINDOW, backend_peer.read_exact(&mut second))
        .await
        .expect("the second buffered batch must be flushed")
        .expect("backend read");
    assert_eq!(
        flushes.load(Ordering::SeqCst),
        2,
        "a completed flush clears the debt; only a new batch re-owes one"
    );

    drop(client_peer);
    drop(backend_peer);
    let _ = tokio::time::timeout(DELIVERY_WINDOW, relay).await;
}

// ---------------------------------------------------------------------------
// Preserved: half-close in both directions, and byte attribution
// ---------------------------------------------------------------------------

/// A client that half-closes its write side must still get its buffered
/// request delivered — `poll_shutdown` implies a flush — and the backend's
/// reply must still reach the client through the Phase 2 half-close drain.
/// Both per-direction counters must be exact.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn half_close_delivers_buffered_bytes_in_both_directions_with_exact_counters() {
    let (client, mut client_peer) = tokio::io::duplex(PEER_BUFFER);
    let (backend, mut backend_peer) = buffered_leg(PEER_BUFFER);

    client_peer
        .write_all(REQUEST)
        .await
        .expect("client request");
    client_peer.shutdown().await.expect("client half-close");

    let relay = tokio::spawn(bidirectional_copy_for_test_with_timeouts(
        client,
        backend,
        RELAY_IDLE_TIMEOUT,
        RELAY_HALF_CLOSE_CAP,
        None,
        None,
        RELAY_BUFFER,
    ));

    let backend_side = tokio::spawn(async move {
        let mut received = Vec::new();
        backend_peer
            .read_to_end(&mut received)
            .await
            .expect("backend read up to the relay half-close");
        backend_peer.write_all(RESPONSE).await.expect("response");
        backend_peer.shutdown().await.expect("backend half-close");
        received
    });

    let mut delivered = Vec::new();
    tokio::time::timeout(DELIVERY_WINDOW, client_peer.read_to_end(&mut delivered))
        .await
        .expect("the half-close drain must deliver the backend response")
        .expect("client read");
    let received = tokio::time::timeout(DELIVERY_WINDOW, backend_side)
        .await
        .expect("the backend fixture must finish")
        .expect("backend task");

    assert_eq!(
        received, REQUEST,
        "the half-closing client's buffered request must arrive intact"
    );
    assert_eq!(
        delivered, RESPONSE,
        "the backend reply must arrive intact through the half-close drain"
    );

    let result = tokio::time::timeout(DELIVERY_WINDOW, relay)
        .await
        .expect("the relay must finish after both half-closes")
        .expect("relay task");
    assert!(
        result.first_failure.is_none(),
        "an orderly half-close in both directions must report no failure, got {:?}",
        result.first_failure
    );
    assert_eq!(result.bytes_client_to_backend, REQUEST.len() as u64);
    assert_eq!(result.bytes_backend_to_client, RESPONSE.len() as u64);
}

// ---------------------------------------------------------------------------
// Preserved: deadlines, cancellation, and error attribution
// ---------------------------------------------------------------------------

/// `backend_write_timeout` must still bound a writer that took the bytes and
/// cannot let go of them. The relay's own buffer is empty at that point, so the
/// write-stall watermark has to stay armed across the in-flight flush rather
/// than going inert the moment the writer said `Ok`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_writer_that_never_completes_its_flush_still_trips_the_write_timeout() {
    let (client, mut client_peer) = tokio::io::duplex(PEER_BUFFER);
    client_peer
        .write_all(REQUEST)
        .await
        .expect("client request");

    let relay = bidirectional_copy_for_test_with_timeouts(
        client,
        AcceptsButNeverFlushes,
        None,
        None,
        None,
        Some(Duration::from_millis(1500)),
        RELAY_BUFFER,
    );
    let started = std::time::Instant::now();
    let result = tokio::time::timeout(Duration::from_secs(10), relay)
        .await
        .expect("the write deadline must fire while the writer holds the bytes");
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_secs(6),
        "the write deadline must fire within timeout + a watchdog tick: {elapsed:?}"
    );
    let (dir, class, side, msg) = result
        .first_failure
        .as_ref()
        .expect("a stalled flush must surface the backend write inactivity timeout");
    assert_eq!(*dir, Direction::ClientToBackend);
    assert_eq!(*class, ErrorClass::ReadWriteTimeout);
    assert_eq!(*side, Some(StreamIoSide::Write));
    assert!(
        msg.contains("backend write inactivity"),
        "failure message must name the write inactivity deadline, got: {msg}"
    );
    assert_eq!(
        result.bytes_client_to_backend,
        REQUEST.len() as u64,
        "bytes the writer already accepted stay credited, matching the splice path"
    );
    drop(client_peer);
}

/// A failure raised by the flush belongs to the write side of the direction
/// that owed it, not to the reader it was about to park on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failing_flush_is_attributed_to_the_write_side() {
    let (client, mut client_peer) = tokio::io::duplex(PEER_BUFFER);
    client_peer
        .write_all(REQUEST)
        .await
        .expect("client request");

    let relay = bidirectional_copy_for_test_with_timeouts(
        client,
        AcceptsThenFailsFlush,
        RELAY_IDLE_TIMEOUT,
        RELAY_HALF_CLOSE_CAP,
        None,
        None,
        RELAY_BUFFER,
    );
    let result = tokio::time::timeout(DELIVERY_WINDOW, relay)
        .await
        .expect("a failing flush must end the relay rather than park it");

    let (dir, class, side, msg) = result
        .first_failure
        .as_ref()
        .expect("a failing flush must surface as a relay failure");
    assert_eq!(*dir, Direction::ClientToBackend);
    assert_eq!(*class, ErrorClass::ConnectionClosed);
    assert_eq!(
        *side,
        Some(StreamIoSide::Write),
        "the flush belongs to the writer, so the failure is write-side"
    );
    assert!(
        msg.contains(FLUSH_FAILURE_TEXT),
        "the transport's own message must survive classification, got: {msg}"
    );
    assert_eq!(
        result.bytes_client_to_backend,
        REQUEST.len() as u64,
        "bytes the writer accepted before failing its flush stay credited"
    );
    drop(client_peer);
}

/// The mesh admission fence revokes live tunnels through this relay. A writer
/// that is holding bytes it will never flush must not be able to keep a revoked
/// tunnel alive: the revocation bound is raced ahead of both copy halves.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admission_revocation_still_cuts_a_relay_whose_writer_holds_bytes() {
    let token = tokio_util::sync::CancellationToken::new();
    let (client, mut client_peer) = tokio::io::duplex(PEER_BUFFER);
    client_peer
        .write_all(REQUEST)
        .await
        .expect("client request");

    let relay = tokio::spawn(bidirectional_copy_for_fenced_relay_for_test(
        client,
        AcceptsButNeverFlushes,
        RELAY_IDLE_TIMEOUT,
        RELAY_HALF_CLOSE_CAP,
        None,
        None,
        RELAY_BUFFER,
        Some(token.clone()),
    ));

    // Let the relay accept the request into the stalled writer first, so the
    // revocation has to interrupt a direction that is parked mid-flush.
    tokio::time::sleep(Duration::from_millis(50)).await;
    token.cancel();

    let result = tokio::time::timeout(DELIVERY_WINDOW, relay)
        .await
        .expect("revocation must end the relay even with a flush outstanding")
        .expect("relay task");

    let (dir, class, side, msg) = result
        .first_failure
        .as_ref()
        .expect("a revoked tunnel must surface the fence's fixed failure");
    assert_eq!(*dir, Direction::ClientToBackend);
    assert_eq!(*class, ErrorClass::ConnectionClosed);
    assert_eq!(*side, Some(StreamIoSide::Read));
    assert!(
        msg.contains("mesh admission revoked"),
        "the fence's compiled-in message must survive, got: {msg}"
    );
    assert_eq!(
        result.bytes_client_to_backend,
        REQUEST.len() as u64,
        "bytes accepted before revocation stay credited"
    );
    drop(client_peer);
}

/// The authorization lifetime bound is the other top-level cut. Flushing while
/// the reader is pending must not delay it, and the bytes the writer already
/// took must still be delivered and counted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_authorization_deadline_still_fires_with_a_buffering_writer() {
    let expired = Arc::new(AtomicBool::new(false));
    let (client, mut client_peer) = tokio::io::duplex(PEER_BUFFER);
    let (backend, mut backend_peer) = buffered_leg(PEER_BUFFER);

    client_peer
        .write_all(REQUEST)
        .await
        .expect("client request");

    let relay = tokio::spawn(bidirectional_copy_with_authorization_for_test(
        client,
        backend,
        tokio::time::Instant::now() + Duration::from_millis(500),
        Arc::clone(&expired),
        RELAY_BUFFER,
    ));

    let mut seen = vec![0u8; REQUEST.len()];
    tokio::time::timeout(DELIVERY_WINDOW, backend_peer.read_exact(&mut seen))
        .await
        .expect("an authorization-bounded relay must still flush what it accepted")
        .expect("backend read");
    assert_eq!(seen, REQUEST);

    let result = tokio::time::timeout(DELIVERY_WINDOW, relay)
        .await
        .expect("the authorization deadline must end the relay")
        .expect("relay task");

    assert!(
        expired.load(Ordering::Acquire),
        "the authorization-expiry flag must latch"
    );
    let (dir, class, side, msg) = result
        .first_failure
        .as_ref()
        .expect("expiry must surface a typed failure");
    assert_eq!(*dir, Direction::ClientToBackend);
    assert_eq!(*class, ErrorClass::ReadWriteTimeout);
    assert_eq!(*side, Some(StreamIoSide::Read));
    assert!(
        msg.contains("authorization lifetime reached"),
        "failure message must be the fixed authorization lifetime text: {msg}"
    );
    assert_eq!(result.bytes_client_to_backend, REQUEST.len() as u64);
    drop(client_peer);
}
