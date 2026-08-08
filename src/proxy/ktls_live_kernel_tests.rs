//! Live-kernel proof for the frontend-TLS kTLS handoff (issue #3619).
//!
//! # Why this is inline, `#[ignore]`d, and not a `tests/` module
//!
//! The point of #3619 is that `FERRUM_KTLS_ENABLED` had been *inert*: the
//! handoff never happened. Classification unit tests
//! (`tests/unit/gateway_core/ktls_handoff_tests.rs`) can pin the decision
//! logic, but they cannot show that a real TLS 1.2 session actually reaches
//! `setsockopt(SOL_TLS, TLS_TX/TLS_RX)` and that the kernel record layer then
//! behaves the way the relay assumes. Only a real kernel can answer that, so
//! this module drives real sockets against the real
//! [`try_ktls_accept`](crate::proxy::ktls_accept::try_ktls_accept) and the real
//! splice relay.
//!
//! It is inline in `src/` (the repo otherwise prefers external tests) for the
//! same reason `ebpf::loader::live_kernel_tests` is: the entry points it must
//! exercise — `try_ktls_accept`, `KtlsAccepted`, and the `client_is_ktls` arm
//! of `bidirectional_splice` — are `pub(crate)`, and widening them to `pub`
//! purely for a test would export a dangerous secret-extraction path from the
//! library.
//!
//! # What is proved here, on a real kernel
//!
//! 1. A TLS 1.2 client handshakes and the session is handed to the kernel
//!    (`KtlsAcceptOutcome::Installed`).
//! 2. Application bytes relay in both directions through `splice(2)`, which is
//!    only possible if the kernel is really decrypting on read and encrypting
//!    on write.
//! 3. An authenticated warning `close_notify` from the client is a clean EOF
//!    and half-closes the backend leg.
//! 4. A clean backend EOF produces a **reciprocal** `close_notify` on the kTLS
//!    client leg — the client's own rustls session closes cleanly instead of
//!    reporting a truncation.
//! 5. A bare TCP FIN with no alert behind it is an attributed
//!    client→backend read failure, not a clean relay close.
//! 6. A record the kernel cannot authenticate ends the relay with an
//!    attributed failure and never with EOF.
//!
//! Peer-originated fatal and non-`close_notify` warning alerts are classified
//! by [`classify_ktls_control_record`](crate::proxy::ktls_record::classify_ktls_control_record),
//! which is covered exhaustively by the deterministic unit suite: rustls
//! exposes no API for emitting an arbitrary alert mid-session, so the live half
//! of that contract is case 6 — an unauthenticated record is refused rather
//! than mistaken for the end of the stream.
//!
//! # Capability gate
//!
//! Every test needs a kernel with the TLS ULP and AES-128-GCM kTLS support.
//! The throwaway client and server providers are deliberately restricted to
//! the single TLS 1.2 AES-128-GCM suite, so the production admission gate can
//! prove every offered suite is installable even on hosted kernels that do not
//! implement ChaCha20-Poly1305 kTLS. This narrows only the test offer set; it
//! does not weaken production eligibility. Without AES-128 support the tests
//! print `SKIP:` and pass — unless `FERRUM_KTLS_LIVE_REQUIRED=1`, which turns
//! an unavailable capability into a failure. The hosted gate sets that
//! variable, so the required CI signal is "the live path ran", never "the live
//! path was quietly unavailable".

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

use crate::plugins::Direction;
use crate::proxy::ktls_accept::{KtlsAcceptOutcome, KtlsAccepted, try_ktls_accept};
use crate::proxy::tcp_proxy::{
    StreamCopyResult, StreamIoSide, bidirectional_splice_ktls_client_for_test,
};
use crate::socket_opts::ktls;
use crate::tls::NoVerifier;

/// SNI / certificate subject used by every connection here.
const LIVE_SNI: &str = "ktls.live.test";

/// Whole-test wall-clock ceiling. Every test is a handful of loopback round
/// trips, so anything beyond this is a hang, not slowness.
const LIVE_TEST_BUDGET: Duration = Duration::from_secs(30);

/// Budget handed to the relay itself, comfortably inside `LIVE_TEST_BUDGET`.
const RELAY_BUDGET: Duration = Duration::from_secs(20);

/// Frontend TLS handshake budget for the accept under test.
const HANDSHAKE_SECS: u64 = 10;

/// Pipe size for the splice relay (the production default shape).
const PIPE_SIZE: usize = 64 * 1024;

/// Whether an unavailable capability must fail rather than skip.
fn live_required() -> bool {
    std::env::var("FERRUM_KTLS_LIVE_REQUIRED").as_deref() == Ok("1")
}

/// Decide whether the live path can run at all.
///
/// Returns `false` to skip. Panics instead when the hosted gate demanded the
/// live path, so a required check can never report success for a run that
/// silently exercised nothing.
fn kernel_supports_live_ktls() -> bool {
    let aes128 = ktls::is_ktls_aes128gcm_available();
    let aes256 = ktls::is_ktls_aes256gcm_available();
    let chacha = ktls::is_ktls_chacha20_poly1305_available();
    // The live provider below offers only AES-128-GCM, so that is the only
    // capability this proof needs. Keep the other probes in the diagnostic so
    // a red hosted gate still explains the runner's full kTLS posture.
    if aes128 {
        return true;
    }
    let probes = format!("aes128={aes128} aes256={aes256} chacha20={chacha}");
    if live_required() {
        panic!("FERRUM_KTLS_LIVE_REQUIRED=1 but the kernel TLS ULP is unusable: {probes}");
    }
    println!("SKIP: kernel TLS ULP is unusable ({probes}); needs Linux 5.11+ with `tls` loaded");
    false
}

/// Provider for the live proof, restricted to one TLS 1.2 cipher that the
/// hosted Linux kTLS gate supports.
///
/// Production remains conservative and declines a ClientHello unless every
/// selectable TLS 1.2 suite it offered has kernel support. Restricting this
/// throwaway test provider is how the live proof supplies such an offer set on
/// kernels that support AES-GCM but not ChaCha20-Poly1305 kTLS.
fn live_crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    let mut provider = crate::fips::base_crypto_provider();
    provider.cipher_suites.retain(|suite| {
        suite.suite() == rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    });
    assert_eq!(
        provider.cipher_suites.len(),
        1,
        "the base provider must expose the TLS 1.2 AES-128-GCM live-test suite"
    );
    Arc::new(provider)
}

/// Frontend `ServerConfig`: TLS 1.2 only, self-signed ECDSA leaf, kTLS secret
/// extraction enabled exactly as `enable_secret_extraction_for_ktls` does in
/// production.
fn live_server_config() -> Arc<ServerConfig> {
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .expect("generate an ECDSA P-256 key pair");
    let params = rcgen::CertificateParams::new(vec![LIVE_SNI.to_string()])
        .expect("certificate parameters for the live SNI");
    let cert = params
        .self_signed(&key_pair)
        .expect("self-sign the live test certificate");

    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
    let provider = live_crypto_provider();
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS12])
        .expect("TLS 1.2 is a supported protocol version")
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], key)
        .expect("the self-signed certificate matches its key");
    // Without this rustls refuses `dangerous_into_kernel_connection`, and the
    // accept declines before touching the socket.
    config.enable_secret_extraction = true;
    Arc::new(config)
}

/// TLS 1.2-only client that trusts the throwaway self-signed leaf.
fn live_connector() -> TlsConnector {
    let provider = live_crypto_provider();
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS12])
        .expect("TLS 1.2 is a supported protocol version")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

fn live_server_name() -> ServerName<'static> {
    ServerName::try_from(LIVE_SNI).expect("the live SNI is a valid DNS name")
}

/// Accept one connection through the real kTLS admission path and require that
/// the kernel actually took the keys.
async fn accept_ktls(listener: &TcpListener, config: &Arc<ServerConfig>) -> KtlsAccepted {
    let (stream, peer): (TcpStream, SocketAddr) = listener.accept().await.expect("frontend accept");
    let budget = Duration::from_secs(HANDSHAKE_SECS);
    let deadline = Some(tokio::time::Instant::now() + budget);
    match try_ktls_accept(stream, config, deadline, HANDSHAKE_SECS, &peer, false).await {
        KtlsAcceptOutcome::Installed(accepted) => *accepted,
        // A decline on a capability-gated kernel means the handoff is inert,
        // which is precisely the regression issue #3619 exists to close.
        KtlsAcceptOutcome::Declined(_) => {
            panic!("kTLS handoff declined; the #3619 kernel handoff would be inert here")
        }
        KtlsAcceptOutcome::Failed(e) => panic!("kTLS accept failed: {e}"),
    }
}

/// Run the relay with the client leg marked as kernel-TLS terminated, bounded
/// so a wedged direction fails the test instead of hanging CI.
async fn run_ktls_relay(client: TcpStream, backend: TcpStream) -> StreamCopyResult {
    let idle = Some(Duration::from_secs(10));
    let half_close = Some(Duration::from_secs(10));
    let relay =
        bidirectional_splice_ktls_client_for_test(client, backend, idle, half_close, PIPE_SIZE);
    tokio::time::timeout(RELAY_BUDGET, relay)
        .await
        .expect("the kTLS splice relay must terminate within its budget")
}

/// Bind a loopback listener and report its address.
async fn loopback_listener() -> (TcpListener, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a loopback listener");
    let addr = listener.local_addr().expect("loopback listener address");
    (listener, addr)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "live kernel: needs the Linux TLS ULP; run by the hosted kTLS live-kernel gate"]
async fn ktls_live_relays_plaintext_and_completes_the_tls_close_handshake() {
    if !kernel_supports_live_ktls() {
        return;
    }
    tokio::time::timeout(LIVE_TEST_BUDGET, async {
        let server_config = live_server_config();
        let (frontend, frontend_addr) = loopback_listener().await;
        let (backend_listener, backend_addr) = loopback_listener().await;

        // Backend application: a plain TCP peer, exactly as on the production
        // kTLS path (a plain backend is one of the eligibility conditions).
        let backend_app = tokio::spawn(async move {
            let (mut sock, _) = backend_listener.accept().await.expect("backend accept");
            let mut got = [0u8; 4];
            sock.read_exact(&mut got)
                .await
                .expect("backend receives the kernel-decrypted request");
            assert_eq!(&got, b"ping", "the kernel must decrypt on read");
            sock.write_all(b"pong").await.expect("backend responds");
            sock.flush().await.expect("backend flush");
            // The client's `close_notify` must be relayed as a half-close.
            let mut tail = Vec::new();
            sock.read_to_end(&mut tail)
                .await
                .expect("backend observes the relayed half-close");
            assert!(tail.is_empty(), "backend saw unexpected trailing bytes");
            // Closing here gives the relay a clean backend EOF, which is what
            // must become a reciprocal `close_notify` on the kTLS leg.
        });

        let client = tokio::spawn(async move {
            let connector = live_connector();
            let tcp = TcpStream::connect(frontend_addr)
                .await
                .expect("client connects to the frontend");
            let mut tls = connector
                .connect(live_server_name(), tcp)
                .await
                .expect("TLS 1.2 handshake completes");
            tls.write_all(b"ping").await.expect("client writes");
            tls.flush().await.expect("client flush");
            let mut got = [0u8; 4];
            tls.read_exact(&mut got)
                .await
                .expect("client reads the kernel-encrypted response");
            assert_eq!(&got, b"pong", "the kernel must encrypt on write");
            // Emits a real warning `close_notify`, then FINs the write side.
            tls.shutdown().await.expect("client sends close_notify");
            // A bare `shutdown(SHUT_WR)` from the relay would surface here as
            // `UnexpectedEof`; a reciprocal `close_notify` reads as clean EOF.
            let mut tail = Vec::new();
            tls.read_to_end(&mut tail)
                .await
                .expect("the relay must close the TLS session, not truncate it");
            assert!(tail.is_empty(), "client saw unexpected trailing bytes");
        });

        let accepted = accept_ktls(&frontend, &server_config).await;
        // SNI comes from the same peeked ClientHello that proved eligibility.
        let sni = accepted.sni_hostname.as_deref();
        assert_eq!(
            sni,
            Some(LIVE_SNI),
            "the accept must surface the peeked SNI"
        );
        let backend = TcpStream::connect(backend_addr)
            .await
            .expect("relay dials the backend");
        let result = run_ktls_relay(accepted.stream, backend).await;

        // An authenticated close_notify is never a relay failure.
        let failure = result.first_failure;
        assert!(failure.is_none(), "unexpected relay failure: {failure:?}");
        assert_eq!(result.bytes_client_to_backend, 4);
        assert_eq!(result.bytes_backend_to_client, 4);

        client.await.expect("client task");
        backend_app.await.expect("backend task");
    })
    .await
    .expect("live kTLS close-handshake test must finish within its budget");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "live kernel: needs the Linux TLS ULP; run by the hosted kTLS live-kernel gate"]
async fn ktls_live_bare_fin_is_attributed_as_a_tls_truncation() {
    if !kernel_supports_live_ktls() {
        return;
    }
    tokio::time::timeout(LIVE_TEST_BUDGET, async {
        let server_config = live_server_config();
        let (frontend, frontend_addr) = loopback_listener().await;
        let (backend_listener, backend_addr) = loopback_listener().await;

        // Backend stays silent and open: the failure under test belongs to the
        // client→backend direction and must not be confused with a backend
        // reset.
        let backend_app = tokio::spawn(async move {
            let (mut sock, _) = backend_listener.accept().await.expect("backend accept");
            let mut buf = [0u8; 1];
            let _ = sock.read(&mut buf).await;
        });

        let client = tokio::spawn(async move {
            let connector = live_connector();
            let tcp = TcpStream::connect(frontend_addr)
                .await
                .expect("client connects to the frontend");
            let tls = connector
                .connect(live_server_name(), tcp)
                .await
                .expect("TLS 1.2 handshake completes");
            // Drop to the raw socket and FIN it: a TCP half-close with no TLS
            // `close_notify` behind it. RFC 5246 §7.2.1 calls this a possible
            // truncation attack, and the relay must not report it as a clean
            // end of stream.
            let (mut raw, _session) = tls.into_inner();
            raw.shutdown().await.expect("raw FIN without close_notify");
            // Keep the socket alive so the relay's verdict comes from the FIN
            // rather than from an RST.
            tokio::time::sleep(Duration::from_secs(3)).await;
        });

        let accepted = accept_ktls(&frontend, &server_config).await;
        let backend = TcpStream::connect(backend_addr)
            .await
            .expect("relay dials the backend");
        let result = run_ktls_relay(accepted.stream, backend).await;

        let (direction, _class, side, message) = result
            .first_failure
            .expect("a bare FIN on a kTLS receive side must be an attributed relay failure");
        assert_eq!(direction, Direction::ClientToBackend);
        assert_eq!(side, Some(StreamIoSide::Read));
        let named = message.contains("close_notify") && message.contains("truncation");
        assert!(
            named,
            "the failure must name the missing close_notify: {message}"
        );
        assert_eq!(result.bytes_client_to_backend, 0, "no bytes were ever sent");

        client.await.expect("client task");
        backend_app.await.expect("backend task");
    })
    .await
    .expect("live kTLS truncation test must finish within its budget");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "live kernel: needs the Linux TLS ULP; run by the hosted kTLS live-kernel gate"]
async fn ktls_live_unauthenticated_record_never_becomes_a_clean_eof() {
    if !kernel_supports_live_ktls() {
        return;
    }
    tokio::time::timeout(LIVE_TEST_BUDGET, async {
        let server_config = live_server_config();
        let (frontend, frontend_addr) = loopback_listener().await;
        let (backend_listener, backend_addr) = loopback_listener().await;

        let backend_app = tokio::spawn(async move {
            let (mut sock, _) = backend_listener.accept().await.expect("backend accept");
            let mut buf = [0u8; 1];
            let _ = sock.read(&mut buf).await;
        });

        let client = tokio::spawn(async move {
            let connector = live_connector();
            let tcp = TcpStream::connect(frontend_addr)
                .await
                .expect("client connects to the frontend");
            let tls = connector
                .connect(live_server_name(), tcp)
                .await
                .expect("TLS 1.2 handshake completes");
            let (mut raw, _session) = tls.into_inner();
            // A structurally valid `application_data` record header whose body
            // cannot possibly authenticate. The kernel record layer owns
            // authentication once the keys are installed, so this is the live
            // form of "an attacker-supplied record must never be laundered
            // into a stream ending".
            let mut forged = vec![0x17, 0x03, 0x03, 0x00, 0x30];
            forged.extend_from_slice(&[0xA5u8; 0x30]);
            raw.write_all(&forged)
                .await
                .expect("write the unauthenticated record");
            raw.flush().await.expect("flush the forged record");
            tokio::time::sleep(Duration::from_secs(3)).await;
        });

        let accepted = accept_ktls(&frontend, &server_config).await;
        let backend = TcpStream::connect(backend_addr)
            .await
            .expect("relay dials the backend");
        let result = run_ktls_relay(accepted.stream, backend).await;

        let (direction, _class, side, message) = result
            .first_failure
            .expect("an unauthenticated record must end the relay with an attributed failure");
        assert_eq!(direction, Direction::ClientToBackend);
        assert_eq!(side, Some(StreamIoSide::Read));
        assert!(!message.is_empty(), "the failure must carry its cause");
        assert_eq!(
            result.bytes_client_to_backend, 0,
            "no forged byte reaches it"
        );

        client.await.expect("client task");
        backend_app.await.expect("backend task");
    })
    .await
    .expect("live kTLS unauthenticated-record test must finish within its budget");
}
