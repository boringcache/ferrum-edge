//! Functional coverage for the injector admission listener's connection-level
//! serving contract (`FERRUM_MODE=injector`).
//!
//! These spawn the real `ferrum-edge` binary so the assertions run against the
//! production TLS acceptor and HTTP/1 builder rather than a re-assembled test
//! harness:
//!
//!   - the TLS acceptor advertises `http/1.1` and never negotiates `h2`, even
//!     for a client that offers `h2` first (an HTTP/2-capable Kubernetes API
//!     server would);
//!   - it still advertises `acme-tls/1`, so an RFC 8737 TLS-ALPN-01 validator
//!     can negotiate the ACME challenge protocol against an injector whose
//!     cert source is ACME-issued;
//!   - a nonzero `FERRUM_HTTP_HEADER_READ_TIMEOUT_SECONDS` closes a connection
//!     that trickles request headers, and `0` is the documented opt-out.
//!
//! Two things keep the assertions non-vacuous. The plaintext cases explicitly
//! remove any inherited `FERRUM_INJECTOR_TLS_*` pair (a parent environment
//! exporting one makes the injector serve TLS regardless of
//! `FERRUM_INJECTOR_ALLOW_PLAINTEXT`, which would turn the raw-TCP slow-header
//! tests into TLS parse failures), and the readiness probe identifies the child
//! it reached rather than accepting whatever holds the port.

use std::io::Cursor;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use serde_json::json;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::scaffolding::certs::TestCa;
use crate::scaffolding::ports::reserve_port;

/// Spawn attempts before giving up. Matches the shared harness budget; each
/// attempt takes a fresh port and a fresh temp dir.
const MAX_SPAWN_ATTEMPTS: u32 = 5;

/// Readiness probes per spawn attempt, one per 100ms — a 10s startup budget.
const MAX_READINESS_PROBES: u32 = 100;

/// Per-probe I/O budget. Bounds the readiness loop deterministically instead of
/// letting a wedged listener stall the attempt.
const PROBE_IO_TIMEOUT: Duration = Duration::from_secs(5);

fn gateway_binary_path() -> String {
    std::env::var("CARGO_BIN_EXE_ferrum-edge")
        .unwrap_or_else(|_| super::namespace_helpers::gateway_binary_path().to_string())
}

/// A spawned injector-mode gateway. `Drop` reaps the child so a failing
/// assertion cannot leak a listener into the rest of the shard.
struct InjectorGateway {
    child: Child,
    port: u16,
    /// Retained so the on-disk TLS material outlives the child.
    tmp: tempfile::TempDir,
    /// Unique to this spawn attempt. The injector stamps it into the SPIFFE ID
    /// it patches into the pod, so an admission response carrying it could only
    /// have come from this child — that is what makes the readiness probe a
    /// real identity check rather than "something is listening".
    trust_domain: String,
}

impl Drop for InjectorGateway {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Start the injector, retrying on a port that another test grabbed between
/// our reservation and the child's bind.
async fn start_injector(tls: bool, header_read_timeout_seconds: &str) -> InjectorGateway {
    let mut last_error = String::new();
    for _ in 0..MAX_SPAWN_ATTEMPTS {
        match try_start_injector(tls, header_read_timeout_seconds).await {
            Ok(gateway) => return gateway,
            Err(error) => last_error = error,
        }
    }
    panic!("injector failed to start after {MAX_SPAWN_ATTEMPTS} attempts: {last_error}");
}

async fn try_start_injector(
    tls: bool,
    header_read_timeout_seconds: &str,
) -> Result<InjectorGateway, String> {
    let tmp = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
    let port = reserve_port()
        .await
        .map_err(|e| format!("reserve injector port: {e}"))?
        .drop_and_take_port();

    // Unique per spawning process and per port, so a listener that answers with
    // this trust domain is this child and not another test's injector.
    let trust_domain = format!("injector-probe-{}-{port}.test", std::process::id());

    let mut command = Command::new(gateway_binary_path());
    command
        .env("FERRUM_MODE", "injector")
        .env("FERRUM_INJECTOR_LISTEN_ADDR", format!("127.0.0.1:{port}"))
        .env(
            "FERRUM_HTTP_HEADER_READ_TIMEOUT_SECONDS",
            header_read_timeout_seconds,
        )
        .env("FERRUM_INJECTOR_TRUST_DOMAIN", &trust_domain)
        .env("FERRUM_LOG_LEVEL", "warn")
        // Keep the ACME store lookups the TLS-ALPN resolver performs inside
        // the temp dir instead of the ambient default store path.
        .env("FERRUM_TLS_MANAGED_STORE_PATH", tmp.path())
        // Pin the two other bounds the serving contract depends on. An ambient
        // `FERRUM_MAX_CONNECTIONS=0` or a tiny handshake timeout would change
        // which limit closes a connection and make these assertions vacuous.
        .env("FERRUM_MAX_CONNECTIONS", "64")
        .env("FERRUM_FRONTEND_TLS_HANDSHAKE_TIMEOUT_SECONDS", "10")
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    if tls {
        let ca = TestCa::new("ferrum-injector-test-root").map_err(|e| format!("test CA: {e}"))?;
        let (cert_pem, key_pem) = ca.valid().map_err(|e| format!("issue leaf: {e}"))?;
        let cert_path = tmp.path().join("tls.crt");
        let key_path = tmp.path().join("tls.key");
        let ca_path = tmp.path().join("ca.crt");
        std::fs::write(&cert_path, &cert_pem).map_err(|e| format!("write cert: {e}"))?;
        std::fs::write(&key_path, &key_pem).map_err(|e| format!("write key: {e}"))?;
        std::fs::write(&ca_path, &ca.cert_pem).map_err(|e| format!("write ca: {e}"))?;
        command
            .env("FERRUM_INJECTOR_TLS_CERT_PATH", &cert_path)
            .env("FERRUM_INJECTOR_TLS_KEY_PATH", &key_path)
            // Ambient plaintext opt-in must not weaken the TLS cases.
            .env("FERRUM_INJECTOR_ALLOW_PLAINTEXT", "false");
    } else {
        // `FERRUM_INJECTOR_ALLOW_PLAINTEXT=true` does NOT force plaintext: a
        // parent environment exporting the injector cert/key pair still
        // satisfies `validate_injector_tls_serving`, and `build_tls_acceptor`
        // would serve TLS. The raw-TCP slow-header assertions would then close
        // during TLS parsing rather than at the header read timeout — vacuously
        // passing. Drop the inherited pair explicitly.
        command
            .env_remove("FERRUM_INJECTOR_TLS_CERT_PATH")
            .env_remove("FERRUM_INJECTOR_TLS_KEY_PATH")
            .env("FERRUM_INJECTOR_ALLOW_PLAINTEXT", "true");
    }

    let child = command
        .spawn()
        .map_err(|e| format!("spawn injector: {e}"))?;
    let mut gateway = InjectorGateway {
        child,
        port,
        tmp,
        trust_domain,
    };

    let mut last_probe_error = "no probe attempted".to_string();
    for _ in 0..MAX_READINESS_PROBES {
        if let Some(status) = child_exit_status(&mut gateway)? {
            return Err(format!("injector exited during startup: {status}"));
        }
        match probe_injector_identity(&gateway, tls).await {
            Ok(()) => {
                // The probe proves the listener is an injector stamping this
                // attempt's unique trust domain. Re-check the child before
                // returning anyway: had it died between the poll above and the
                // probe, a bare TCP success could have come from whatever took
                // the port next, and this helper exists to retry that race
                // rather than hand the assertions a foreign listener.
                if let Some(status) = child_exit_status(&mut gateway)? {
                    return Err(format!("injector exited during readiness probe: {status}"));
                }
                return Ok(gateway);
            }
            Err(error) => last_probe_error = error,
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(format!(
        "injector never served an admission response on port {port}: {last_probe_error}"
    ))
}

fn child_exit_status(
    gateway: &mut InjectorGateway,
) -> Result<Option<std::process::ExitStatus>, String> {
    gateway
        .child
        .try_wait()
        .map_err(|e| format!("poll injector child: {e}"))
}

/// Readiness probe: drive one real `POST /mutate` and require the response to
/// carry this attempt's unique trust domain.
///
/// A bare TCP connect only proves *something* is listening. Under parallel test
/// load another process can take the reserved port between
/// `drop_and_take_port()` and the child's bind, so the probe has to identify the
/// peer. On TLS the handshake alone already does (the leaf chains to a CA
/// generated in this attempt's temp dir); the admission response is checked on
/// both paths so plaintext gets the same guarantee.
async fn probe_injector_identity(gateway: &InjectorGateway, tls: bool) -> Result<(), String> {
    let stream = timeout(
        PROBE_IO_TIMEOUT,
        TcpStream::connect(("127.0.0.1", gateway.port)),
    )
    .await
    .map_err(|_| "probe connect timed out".to_string())?
    .map_err(|e| format!("probe connect: {e}"))?;

    let response = if tls {
        install_crypto_provider();
        let mut client_config = rustls::ClientConfig::builder()
            .with_root_certificates(probe_root_store(gateway)?)
            .with_no_client_auth();
        client_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
        let server_name = rustls::pki_types::ServerName::try_from("localhost".to_string())
            .map_err(|e| format!("probe server name: {e}"))?;
        let tls_stream = timeout(PROBE_IO_TIMEOUT, connector.connect(server_name, stream))
            .await
            .map_err(|_| "probe TLS handshake timed out".to_string())?
            .map_err(|e| format!("probe TLS handshake: {e}"))?;
        probe_admission_exchange(tls_stream).await?
    } else {
        probe_admission_exchange(stream).await?
    };

    if !response.starts_with("HTTP/1.1 200 OK") {
        return Err(format!("probe response was {response:?}"));
    }
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .ok_or_else(|| "probe response had no body".to_string())?;
    let value: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("probe body was not JSON: {e}"))?;
    let patch = value
        .pointer("/response/patch")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "probe response carried no patch".to_string())?;
    let patch = base64::engine::general_purpose::STANDARD
        .decode(patch)
        .map_err(|e| format!("probe patch was not base64: {e}"))?;
    let patch = String::from_utf8_lossy(&patch);
    if !patch.contains(&gateway.trust_domain) {
        return Err(format!(
            "port {} answered without this attempt's `{}` trust domain, so the \
             listener is not this injector",
            gateway.port, gateway.trust_domain
        ));
    }
    Ok(())
}

async fn probe_admission_exchange<S>(stream: S) -> Result<String, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut reader, mut writer) = tokio::io::split(stream);
    timeout(
        PROBE_IO_TIMEOUT,
        writer.write_all(mutate_request(&admission_review("readiness-probe")).as_bytes()),
    )
    .await
    .map_err(|_| "probe write timed out".to_string())?
    .map_err(|e| format!("probe write: {e}"))?;
    let mut response = Vec::new();
    timeout(PROBE_IO_TIMEOUT, reader.read_to_end(&mut response))
        .await
        .map_err(|_| "probe read timed out".to_string())?
        .map_err(|e| format!("probe read: {e}"))?;
    Ok(String::from_utf8_lossy(&response).to_string())
}

fn probe_root_store(gateway: &InjectorGateway) -> Result<rustls::RootCertStore, String> {
    let ca_pem = std::fs::read(gateway.tmp.path().join("ca.crt"))
        .map_err(|e| format!("read test CA pem: {e}"))?;
    let mut root_store = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut Cursor::new(ca_pem)) {
        root_store
            .add(cert.map_err(|e| format!("parse CA cert: {e}"))?)
            .map_err(|e| format!("add CA: {e}"))?;
    }
    Ok(root_store)
}

/// The CA PEM the running TLS injector serves under, as a rustls trust anchor.
fn root_store_for(gateway: &InjectorGateway) -> rustls::RootCertStore {
    probe_root_store(gateway).expect("build test CA root store")
}

fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Open a TLS connection offering exactly `alpn` and return the negotiated
/// protocol alongside the stream.
async fn connect_tls(
    gateway: &InjectorGateway,
    alpn: &[&[u8]],
) -> (Option<Vec<u8>>, tokio_rustls::client::TlsStream<TcpStream>) {
    install_crypto_provider();
    let mut client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store_for(gateway))
        .with_no_client_auth();
    client_config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));

    let tcp = TcpStream::connect(("127.0.0.1", gateway.port)).await;
    let tcp = tcp.expect("tcp connect to injector");
    let name = "localhost".to_string();
    let server_name = rustls::pki_types::ServerName::try_from(name).expect("server name");
    let tls_stream = connector.connect(server_name, tcp).await;
    let tls_stream = tls_stream.expect("tls handshake with injector");
    let negotiated = tls_stream.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
    (negotiated, tls_stream)
}

fn admission_review(uid: &str) -> String {
    json!({
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "request": {
            "uid": uid,
            "namespace": "payments",
            "kind": {"group": "", "version": "v1", "kind": "Pod"},
            "object": {
                "metadata": {"labels": {"ferrum.io/mesh": "enabled"}},
                "spec": {"containers": [{"name": "app", "image": "app:test"}]}
            }
        }
    })
    .to_string()
}

fn mutate_request(body: &str) -> String {
    format!(
        "POST /mutate HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )
}

#[ignore]
#[tokio::test]
async fn functional_injector_tls_never_negotiates_h2_and_serves_admission() {
    let gateway = start_injector(true, "10").await;

    // Offer h2 first, exactly as an HTTP/2-capable Kubernetes API server does.
    let offered = [b"h2".as_slice(), b"http/1.1".as_slice()];
    let (negotiated, tls_stream) = connect_tls(&gateway, &offered).await;
    assert_eq!(
        negotiated.as_deref(),
        Some(b"http/1.1".as_slice()),
        "injector must never negotiate h2 with its HTTP/1-only server"
    );

    let (mut reader, mut writer) = tokio::io::split(tls_stream);
    writer
        .write_all(mutate_request(&admission_review("alpn-check")).as_bytes())
        .await
        .expect("write AdmissionReview");
    let mut response = Vec::new();
    timeout(Duration::from_secs(10), reader.read_to_end(&mut response))
        .await
        .expect("injector responded within 10s")
        .expect("read injector response");
    let response = String::from_utf8_lossy(&response).to_string();

    assert!(
        response.starts_with("HTTP/1.1 200 OK"),
        "response was {response:?}"
    );
    assert!(
        response.contains(r#""allowed":true"#),
        "AdmissionReview was not admitted: {response}"
    );
}

#[ignore]
#[tokio::test]
async fn functional_injector_tls_still_advertises_acme_tls_alpn() {
    let gateway = start_injector(true, "10").await;

    // An RFC 8737 TLS-ALPN-01 validator offers `acme-tls/1` alone. Dropping the
    // protocol from the acceptor would fail this handshake outright and break
    // ACME renewal for an injector using an `acme://` cert source, even though
    // the shared loader's resolver can serve the challenge certificate.
    let (negotiated, _tls_stream) = connect_tls(&gateway, &[b"acme-tls/1".as_slice()]).await;
    assert_eq!(
        negotiated.as_deref(),
        Some(b"acme-tls/1".as_slice()),
        "injector must keep advertising acme-tls/1 for TLS-ALPN-01 validation"
    );
}

#[ignore]
#[tokio::test]
async fn functional_injector_header_read_timeout_closes_trickling_connection() {
    let gateway = start_injector(false, "1").await;

    // Taken before the connect so it can never postdate the server-side timer
    // this assertion compares against.
    let started = Instant::now();
    let mut stream = TcpStream::connect(("127.0.0.1", gateway.port))
        .await
        .expect("connect to injector");
    stream
        .write_all(b"POST /mutate HTTP/1.1\r\nHost: localhost\r\n")
        .await
        .expect("write partial headers");

    let mut buf = Vec::new();
    let read = timeout(Duration::from_secs(10), stream.read_to_end(&mut buf)).await;
    assert!(
        read.is_ok(),
        "connection should be closed by the header read timeout, not hang"
    );
    // A close well before the configured budget would mean the connection was
    // torn down for some other reason, making the assertion above vacuous. The
    // bound is slightly under 1s only to absorb clock coarseness, not to
    // tolerate an early close.
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(900),
        "connection closed after {elapsed:?}, before the 1s header read timeout could fire"
    );
    assert!(
        buf.is_empty(),
        "a trickling connection must not receive a response, got: {}",
        String::from_utf8_lossy(&buf)
    );
}

#[ignore]
#[tokio::test]
async fn functional_injector_header_read_timeout_zero_allows_slow_headers() {
    let gateway = start_injector(false, "0").await;

    let body = admission_review("slow-headers");
    let mut stream = TcpStream::connect(("127.0.0.1", gateway.port))
        .await
        .expect("connect to injector");
    stream
        .write_all(b"POST /mutate HTTP/1.1\r\nHost: localhost\r\n")
        .await
        .expect("write partial headers");
    // Waiting out the default 10s budget would make the test needlessly slow;
    // the point is that no timeout fires while the remaining headers are
    // withheld well past the 1s budget the companion test proves is enforced
    // when configured.
    tokio::time::sleep(Duration::from_secs(2)).await;
    stream
        .write_all(
            format!(
                "Content-Type: application/json\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .as_bytes(),
        )
        .await
        .expect("write remaining headers and body");

    let mut response = Vec::new();
    timeout(Duration::from_secs(10), stream.read_to_end(&mut response))
        .await
        .expect("server should respond after slow headers when the timeout is disabled")
        .expect("read injector response");
    let response = String::from_utf8_lossy(&response).to_string();

    assert!(
        response.starts_with("HTTP/1.1 200 OK"),
        "response was {response:?}"
    );
    assert!(
        response.contains(r#""allowed":true"#),
        "AdmissionReview was not admitted: {response}"
    );
}
