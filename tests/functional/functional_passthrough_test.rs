//! Functional tests for TLS/DTLS passthrough mode on stream proxies.
//!
//! Passthrough proxies forward encrypted client bytes directly to the
//! backend without TLS termination. The gateway peeks at the ClientHello
//! for SNI but never decrypts application data.
//!
//! Run with:
//!   cargo build --bin ferrum-edge && cargo test --test functional_tests -- functional_passthrough --ignored --nocapture

use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::sleep;

// ── Helpers ───────────────────────────────────────────────────────────────

fn gateway_binary_path() -> &'static str {
    if std::path::Path::new("./target/debug/ferrum-edge").exists() {
        "./target/debug/ferrum-edge"
    } else {
        "./target/release/ferrum-edge"
    }
}

/// Plain TCP echo server — reads data, echoes it back, and closes.
async fn start_tcp_echo_server(port: u16) {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .expect("Failed to bind TCP echo");

    loop {
        if let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
        }
    }
}

/// TLS-wrapped TCP echo server — clients perform TLS handshake, then echo.
async fn start_tls_echo_server(port: u16, cert_pem: &str, key_pem: &str) {
    use rustls::ServerConfig;
    use rustls_pemfile::{certs, private_key};
    use std::io::BufReader;
    use std::sync::Arc;
    use tokio_rustls::TlsAcceptor;

    let cert_chain: Vec<_> = certs(&mut BufReader::new(cert_pem.as_bytes()))
        .filter_map(|r| r.ok())
        .collect();
    let key = private_key(&mut BufReader::new(key_pem.as_bytes()))
        .unwrap()
        .unwrap();

    let _ = rustls::crypto::ring::default_provider().install_default();

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .expect("bad tls config");

    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .expect("Failed to bind TLS echo");

    loop {
        if let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut tls_stream) = acceptor.accept(stream).await {
                    let mut buf = vec![0u8; 8192];
                    loop {
                        match tls_stream.read(&mut buf).await {
                            Ok(0) => break,
                            Ok(n) => {
                                if tls_stream.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                }
            });
        }
    }
}

fn generate_self_signed_cert() -> (String, String) {
    use rcgen::{CertificateParams, KeyPair};
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    (cert.pem(), key_pair.serialize_pem())
}

/// Names of the captured gateway output files inside a harness `TempDir`.
const GATEWAY_STDOUT_LOG: &str = "gateway.stdout.log";
const GATEWAY_STDERR_LOG: &str = "gateway.stderr.log";

/// Everything the gateway has written so far, both streams concatenated.
fn gateway_logs(dir: &std::path::Path) -> String {
    let mut combined = String::new();
    for name in [GATEWAY_STDOUT_LOG, GATEWAY_STDERR_LOG] {
        if let Ok(text) = std::fs::read_to_string(dir.join(name)) {
            combined.push_str(&text);
        }
    }
    combined
}

/// Poll the captured gateway logs until `needle` appears, up to `within`.
///
/// This is the state observation that replaces "sleep and hope": a test can
/// wait for a specific gateway-side transition (a circuit breaker opening, a
/// connection being rejected) instead of guessing how long it takes.
async fn wait_for_gateway_log(dir: &std::path::Path, needle: &str, within: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        if gateway_logs(dir).contains(needle) {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        sleep(Duration::from_millis(25)).await;
    }
}

/// Kills the gateway child on every exit path, including panics.
struct GatewayProcess(std::process::Child);

impl Drop for GatewayProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Wait for the gateway health endpoint to respond.
/// Returns true if healthy, false if timed out.
async fn wait_for_health(admin_port: u16) -> bool {
    let health_url = format!("http://127.0.0.1:{}/health", admin_port);
    let deadline = std::time::SystemTime::now() + Duration::from_secs(30);
    loop {
        if std::time::SystemTime::now() >= deadline {
            return false;
        }
        match reqwest::get(&health_url).await {
            Ok(r) if r.status().is_success() => return true,
            _ => sleep(Duration::from_millis(500)).await,
        }
    }
}

/// Start the gateway with retry on port-binding failures.
///
/// Allocates fresh ephemeral proxy listen, HTTP, and admin ports on each attempt
/// to handle the bind-drop-rebind port race.  The `write_config` closure receives
/// `(proxy_listen_port, dir)` and must write the config file, returning
/// `(config_path_string, TempDir)`.
///
/// Returns (child, proxy_listen_port, http_port, admin_port, TempDir).
async fn start_gateway_with_retry<F>(
    write_config: F,
) -> (std::process::Child, u16, u16, u16, TempDir)
where
    F: Fn(u16, &std::path::Path) -> String,
{
    start_gateway_with_retry_env(write_config, &[]).await
}

/// Variant of `start_gateway_with_retry` that lets the caller add extra env
/// variables (e.g. `FERRUM_FRONTEND_TLS_HANDSHAKE_TIMEOUT_SECONDS`) without
/// duplicating the port-allocation + retry scaffolding.
async fn start_gateway_with_retry_env<F>(
    write_config: F,
    extra_env: &[(&str, &str)],
) -> (std::process::Child, u16, u16, u16, TempDir)
where
    F: Fn(u16, &std::path::Path) -> String,
{
    const MAX_ATTEMPTS: u32 = 3;
    for attempt in 1..=MAX_ATTEMPTS {
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_listen_port = proxy_listener.local_addr().unwrap().port();
        drop(proxy_listener);

        let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_port = http_listener.local_addr().unwrap().port();
        drop(http_listener);

        let admin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let admin_port = admin_listener.local_addr().unwrap().port();
        drop(admin_listener);

        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join("config.yaml");
        let config_content = write_config(proxy_listen_port, dir.path());
        std::fs::write(&config_path, &config_content).unwrap();

        // Redirect the gateway's output into files inside the temp dir rather
        // than /dev/null. Files (not pipes — an unread pipe deadlocks, see the
        // functional-test rules) let a test observe gateway-side state
        // transitions instead of sleeping and hoping. Tests that don't read
        // them are unaffected.
        let stdout_log = std::fs::File::create(dir.path().join(GATEWAY_STDOUT_LOG)).unwrap();
        let stderr_log = std::fs::File::create(dir.path().join(GATEWAY_STDERR_LOG)).unwrap();

        let mut cmd = std::process::Command::new(gateway_binary_path());
        cmd.env("FERRUM_MODE", "file")
            .env("FERRUM_FILE_CONFIG_PATH", config_path.to_str().unwrap())
            .env("FERRUM_PROXY_HTTP_PORT", http_port.to_string())
            .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string())
            .env("FERRUM_LOG_LEVEL", "debug")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::from(stdout_log))
            .stderr(std::process::Stdio::from(stderr_log));
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        let mut child = cmd.spawn().expect("Failed to start gateway");

        if wait_for_health(admin_port).await {
            return (child, proxy_listen_port, http_port, admin_port, dir);
        }

        eprintln!(
            "Gateway startup attempt {}/{} failed (ports: stream={}, http={}, admin={})",
            attempt, MAX_ATTEMPTS, proxy_listen_port, http_port, admin_port
        );
        let _ = child.kill();
        let _ = child.wait();

        if attempt < MAX_ATTEMPTS {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
    panic!("Gateway did not start after {} attempts", MAX_ATTEMPTS);
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn test_tcp_passthrough_plain_echo() {
    // Backend: plain TCP echo (same-process, no port race)
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);
    tokio::spawn(start_tcp_echo_server(backend_port));

    // Start gateway with retry to handle ephemeral port races
    let (mut gateway, proxy_listen_port, _http_port, _admin_port, _dir) =
        start_gateway_with_retry(|stream_port, _dir_path| {
            format!(
                r#"
version: "1"
proxies:
  - id: "tcp-passthrough"
    backend_scheme: tcp
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    listen_port: {stream_port}
    passthrough: true

consumers: []
plugin_configs: []
upstreams: []
"#,
            )
        })
        .await;

    // Connect through the gateway's stream proxy port
    let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", proxy_listen_port))
        .await
        .expect("Failed to connect to passthrough proxy");

    let msg = b"hello passthrough";
    stream.write_all(msg).await.unwrap();

    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .expect("read timeout")
        .expect("read error");

    assert_eq!(&buf[..n], msg, "echo response should match");

    gateway.kill().ok();
    gateway.wait().ok();
}

/// An attempt at the passthrough circuit-breaker scenario could not establish
/// its preconditions because something outside the gateway interfered with the
/// backend port. Distinct from a product failure, which panics on the spot.
struct PortRaced(String);

/// Circuit-breaker ordering on the passthrough path.
///
/// Production order (`src/proxy/tcp_proxy.rs`): the passthrough branch calls
/// `circuit_breaker_cache.can_execute()` *before* DNS resolution and the
/// backend dial, and records the connect failure via `inspect_err` on
/// `connect_candidates` *before* the error propagates and the client socket is
/// dropped. So a second connection that starts after the first one's client
/// socket has closed is deterministically admitted-or-rejected against a
/// settled breaker — there is no product-side window.
///
/// The old test could not see that ordering. It discarded the first client
/// read's result (so a first attempt that had not finished — or had never even
/// been dialed — still counted as "breaker tripped"), then rebound the backend
/// port and slept a second before reading an accept counter. Any accept in that
/// window failed the test, including one from an unrelated process that grabbed
/// the port during the deliberate refusal window (issue #3431).
///
/// This version instead:
///   * requires the first client connection to actually end (EOF/error) rather
///     than ignoring a timeout,
///   * waits for the gateway to *report* the breaker opening before the backend
///     listener is installed, so the failed dial provably precedes the rebind,
///   * proves the rejection positively (the gateway logs the breaker-open
///     rejection) instead of only inferring it from an absent accept, and
///   * attributes any backend accept by payload: only a connection carrying
///     this attempt's unique marker proves the gateway dialed. An
///     unattributable accept, or a port that was taken during the refusal
///     window, retries the scenario with fresh ports instead of reporting a
///     product failure that did not happen.
async fn try_passthrough_circuit_breaker_scenario(attempt: u32) -> Result<(), PortRaced> {
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU32, Ordering};

    // Reserve a backend port and release it: the first gateway dial must get a
    // real ECONNREFUSED so the breaker trips on a connection error. This
    // release/rebind window is inherent to the scenario; everything below
    // detects interference in it rather than misreporting it.
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);

    let first_marker = format!("ferrum-cb-first-{attempt}-{backend_port}");
    let second_marker = format!("ferrum-cb-second-{attempt}-{backend_port}");

    let (gateway, proxy_listen_port, _http_port, _admin_port, dir) =
        start_gateway_with_retry(|stream_port, _dir_path| {
            format!(
                r#"
version: "1"
proxies:
  - id: "tcp-passthrough-cb"
    backend_scheme: tcp
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    listen_port: {stream_port}
    passthrough: true
    backend_connect_timeout_ms: 200
    circuit_breaker:
      failure_threshold: 1
      success_threshold: 1
      timeout_seconds: 60
      failure_status_codes: [500, 502, 503]
      half_open_max_requests: 1
      trip_on_connection_errors: true

consumers: []
plugin_configs: []
upstreams: []
"#,
            )
        })
        .await;
    let _gateway = GatewayProcess(gateway);

    // ── Step 1: the first attempt must fail and must be observed failing ──
    let mut first = tokio::net::TcpStream::connect(format!("127.0.0.1:{proxy_listen_port}"))
        .await
        .expect("connect to passthrough proxy");
    first.write_all(first_marker.as_bytes()).await.ok();
    let mut buf = [0u8; 64];
    match tokio::time::timeout(Duration::from_secs(10), first.read(&mut buf)).await {
        // EOF or a transport error: the gateway finished handling the
        // connection, which on this path means the dial failed and the
        // failure was recorded before the socket was dropped.
        Ok(Ok(0)) | Ok(Err(_)) => {}
        Ok(Ok(n)) => {
            return Err(PortRaced(format!(
                "backend port {backend_port} was serving during the refusal window: \
                 the first passthrough attempt read back {n} byte(s) ({:?})",
                String::from_utf8_lossy(&buf[..n])
            )));
        }
        Err(_) => {
            return Err(PortRaced(format!(
                "the first passthrough attempt never completed within 10s \
                 (backend port {backend_port} was most likely taken by another \
                 process and accepted the dial without replying)"
            )));
        }
    }

    // ── Step 2: the breaker transition must be observable BEFORE the port is
    // rebound, so the failed dial provably precedes the backend listener ──
    assert!(
        wait_for_gateway_log(dir.path(), "Circuit breaker opening", Duration::from_secs(10)).await,
        "the gateway never reported the circuit breaker opening after the first \
         passthrough dial failed; the connection-error path did not record a \
         failure against the breaker. (If the log instead shows the dial \
         succeeding, another process was listening on backend port \
         {backend_port} during the refusal window.) Gateway log:\n{}",
        gateway_logs(dir.path())
    );

    // ── Step 3: install the backend listener now that the breaker is open ──
    let backend_listener = match TcpListener::bind(format!("127.0.0.1:{backend_port}")).await {
        Ok(listener) => listener,
        Err(e) => {
            return Err(PortRaced(format!(
                "backend port {backend_port} was taken by another process during \
                 the refusal window: {e}"
            )));
        }
    };
    let accepted = Arc::new(AtomicU32::new(0));
    let payloads: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let accepted_for_task = accepted.clone();
    let payloads_for_task = payloads.clone();
    let backend_task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = backend_listener.accept().await {
            accepted_for_task.fetch_add(1, Ordering::SeqCst);
            let payloads = payloads_for_task.clone();
            tokio::spawn(async move {
                // Capture whatever the peer sends so the accept can be
                // attributed. A gateway dial relays the client's already-buffered
                // bytes immediately; an unrelated probe sends nothing.
                let mut probe = vec![0u8; 512];
                let observed =
                    match tokio::time::timeout(Duration::from_secs(2), stream.read(&mut probe))
                        .await
                    {
                        Ok(Ok(n)) => probe[..n].to_vec(),
                        _ => Vec::new(),
                    };
                if let Ok(mut guard) = payloads.lock() {
                    guard.push(observed);
                }
            });
        }
    });

    // ── Step 4: the second connection must be rejected before any dial ──
    let mut second = tokio::net::TcpStream::connect(format!("127.0.0.1:{proxy_listen_port}"))
        .await
        .expect("connect to passthrough proxy while breaker is open");
    second.write_all(second_marker.as_bytes()).await.ok();
    let second_outcome = tokio::time::timeout(Duration::from_secs(10), second.read(&mut buf)).await;
    assert!(
        matches!(&second_outcome, Ok(Ok(0)) | Ok(Err(_))),
        "with the breaker open the gateway must close the client connection \
         immediately; instead the connection stayed open (outcome={second_outcome:?}), \
         which means it was relayed to the backend. Gateway log:\n{}",
        gateway_logs(dir.path())
    );

    // Positive proof of the rejection. Without this, a gateway that dropped the
    // connection for some unrelated reason (or never handled it at all) would
    // leave the accept assertion below passing vacuously.
    assert!(
        wait_for_gateway_log(
            dir.path(),
            "TCP passthrough connection rejected: circuit breaker open",
            Duration::from_secs(10),
        )
        .await,
        "the gateway closed the second connection but never reported a \
         circuit-breaker rejection, so the accept count below would prove \
         nothing. Gateway log:\n{}",
        gateway_logs(dir.path())
    );

    // ── Step 5: no backend dial happened ──
    // The gateway's decision is final by now (the client saw EOF and the
    // rejection is logged), so any accept the listener will ever see has
    // already happened. Only the classification of those accepts can still be
    // in flight, so wait on that state rather than on a fixed sleep.
    let accepted_count = accepted.load(Ordering::SeqCst) as usize;
    if accepted_count > 0 {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        loop {
            let classified = payloads.lock().map(|g| g.len()).unwrap_or(0);
            if classified >= accepted_count || tokio::time::Instant::now() >= deadline {
                break;
            }
            sleep(Duration::from_millis(25)).await;
        }
    }
    let observed = payloads.lock().map(|g| g.clone()).unwrap_or_default();
    backend_task.abort();

    let relayed = observed.iter().any(|payload| {
        payload
            .windows(second_marker.len())
            .any(|window| window == second_marker.as_bytes())
    });
    assert!(
        !relayed,
        "open passthrough circuit breaker must reject before backend dial, but \
         the backend received this client's payload. Gateway log:\n{}",
        gateway_logs(dir.path())
    );
    if accepted_count > 0 {
        return Err(PortRaced(format!(
            "backend port {backend_port} received {accepted_count} connection(s) that did \
             not carry this attempt's marker: {:?}",
            observed
                .iter()
                .map(|p| String::from_utf8_lossy(p).into_owned())
                .collect::<Vec<_>>()
        )));
    }
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_tcp_passthrough_circuit_breaker_rejects_without_backend_dial() {
    const MAX_ATTEMPTS: u32 = 3;
    let mut races = Vec::new();
    for attempt in 1..=MAX_ATTEMPTS {
        match try_passthrough_circuit_breaker_scenario(attempt).await {
            Ok(()) => return,
            Err(PortRaced(reason)) => {
                eprintln!("attempt {attempt}/{MAX_ATTEMPTS}: {reason}");
                races.push(reason);
            }
        }
    }
    panic!(
        "could not establish the passthrough circuit-breaker preconditions in \
         {MAX_ATTEMPTS} attempts (the backend port was interfered with every \
         time): {races:?}"
    );
}

#[tokio::test]
#[ignore]
async fn test_tcp_tls_passthrough_forwards_encrypted_data() {
    let (cert_pem, key_pem) = generate_self_signed_cert();

    // Backend: TLS echo server (same-process, no port race)
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);

    let cert_clone = cert_pem.clone();
    let key_clone = key_pem.clone();
    tokio::spawn(async move {
        start_tls_echo_server(backend_port, &cert_clone, &key_clone).await;
    });

    // Start gateway with retry to handle ephemeral port races
    let (mut gateway, proxy_listen_port, _http_port, _admin_port, _dir) =
        start_gateway_with_retry(|stream_port, _dir_path| {
            format!(
                r#"
version: "1"
proxies:
  - id: "tls-passthrough"
    backend_scheme: tcp
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    listen_port: {stream_port}
    passthrough: true

consumers: []
plugin_configs: []
upstreams: []
"#,
            )
        })
        .await;

    // Connect via raw TCP to the proxy port, then do TLS handshake.
    // The gateway passes bytes through without TLS termination;
    // the TLS handshake reaches the backend directly.
    let tcp_stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", proxy_listen_port))
        .await
        .expect("Failed to connect to passthrough proxy");

    // Build a TLS client that trusts our self-signed cert
    let cert_chain: Vec<_> =
        rustls_pemfile::certs(&mut std::io::BufReader::new(cert_pem.as_bytes()))
            .filter_map(|r| r.ok())
            .collect();
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add_parsable_certificates(cert_chain);

    let _ = rustls::crypto::ring::default_provider().install_default();
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(client_config));
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();

    let mut tls_stream = connector
        .connect(server_name, tcp_stream)
        .await
        .expect("TLS handshake through passthrough should succeed");

    // Send data through the TLS tunnel (through the gateway passthrough)
    let msg = b"encrypted passthrough data";
    tls_stream.write_all(msg).await.unwrap();

    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(5), tls_stream.read(&mut buf))
        .await
        .expect("read timeout")
        .expect("read error");

    assert_eq!(
        &buf[..n],
        msg,
        "TLS echo through passthrough should return same data"
    );

    gateway.kill().ok();
    gateway.wait().ok();
}

/// Slow-loris defense: a peer that opens a TCP connection to a passthrough
/// listener and never writes a ClientHello must NOT park a connection-handler
/// task indefinitely. The peek is bounded by
/// `FERRUM_FRONTEND_TLS_HANDSHAKE_TIMEOUT_SECONDS`.
///
/// Before the fix, the gateway sits forever at `TcpStream::peek()` waiting for
/// the silent peer's first byte and never even attempts the backend connect.
/// After the fix, the peek returns `None` once the deadline expires and the
/// gateway proceeds with whatever bytes were available (zero) — at which
/// point the backend connection is initiated and the backend's accept queue
/// records a new connection.
///
/// We assert on the backend-side accept count: it must reach 1 within
/// roughly `timeout + slack`. If the bug were still present, the accept
/// count would stay at 0 indefinitely.
#[tokio::test]
#[ignore]
async fn test_tcp_passthrough_sni_peek_timeout_drops_silent_peer() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    // Backend that just counts accepted connections and holds them open
    // (so the OS doesn't reset them, and the gateway doesn't see EOF early).
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    let accepts = Arc::new(AtomicU32::new(0));
    let accepts_for_task = accepts.clone();
    tokio::spawn(async move {
        loop {
            if let Ok((stream, _)) = backend_listener.accept().await {
                accepts_for_task.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(async move {
                    let _hold = stream;
                    tokio::time::sleep(Duration::from_secs(60)).await;
                });
            }
        }
    });

    // Gateway: 2-second handshake timeout for the passthrough SNI peek.
    let (mut gateway, proxy_listen_port, _http_port, _admin_port, _dir) =
        start_gateway_with_retry_env(
            |stream_port, _dir_path| {
                format!(
                    r#"
version: "1"
proxies:
  - id: "tcp-passthrough-slow-loris"
    backend_scheme: tcp
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    listen_port: {stream_port}
    passthrough: true

consumers: []
plugin_configs: []
upstreams: []
"#,
                )
            },
            &[("FERRUM_FRONTEND_TLS_HANDSHAKE_TIMEOUT_SECONDS", "2")],
        )
        .await;

    // Connect and never send anything — classic slow-loris.
    let _silent = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", proxy_listen_port))
        .await
        .expect("connect to gateway");

    let started = std::time::Instant::now();
    let deadline = started + Duration::from_secs(5); // 2s timeout + 3s slack
    let mut accept_observed = false;
    while std::time::Instant::now() < deadline {
        if accepts.load(Ordering::Relaxed) >= 1 {
            accept_observed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let elapsed = started.elapsed();

    assert!(
        accept_observed,
        "Backend never saw a connection within {:?}; SNI peek timeout did not fire (slow-loris bug regressed)",
        elapsed
    );
    // Sanity: the timeout shouldn't fire much earlier than the configured 2s.
    assert!(
        elapsed >= Duration::from_millis(1500),
        "Backend connection observed too early ({elapsed:?}) — peek timeout may be wired to the wrong knob"
    );

    gateway.kill().ok();
    gateway.wait().ok();
}
