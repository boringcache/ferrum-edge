//! End-to-end canonical policy path parity across HTTP/1.1, HTTP/2, and
//! HTTP/3 (private advisory GHSA-69xf-42xm-4w4f).
//!
//! Each case is a single request target checked against three things at once:
//! the client-visible status, whether a policy plugin
//! (`request_termination`) fired, and — through a raw-TCP backend that
//! records the request line it actually received — the path the backend would
//! execute. That triple is what the advisory says must never diverge.
//!
//! Every case runs identically over all three frontend protocols, because a
//! per-protocol difference is itself a bypass.

use crate::common::TestGateway;
use crate::scaffolding::clients::Http3Client;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;

// ============================================================================
// Request-target recording backend
// ============================================================================

/// Raw-TCP HTTP/1.1 backend that records the request target of every request
/// line it receives. Raw on purpose: a typed client would re-encode the target
/// and hide exactly the difference under test.
struct RecordingBackend {
    port: u16,
    targets: Arc<Mutex<Vec<String>>>,
    handle: tokio::task::JoinHandle<()>,
}

impl RecordingBackend {
    async fn start() -> Self {
        // Hold the bound listener rather than drop-and-rebind, so parallel
        // tests cannot steal the port between reservation and use.
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind backend");
        let port = listener.local_addr().expect("backend addr").port();
        let targets: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&targets);

        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let recorded = Arc::clone(&recorded);
                tokio::spawn(async move {
                    let mut buffer = Vec::new();
                    let mut chunk = [0u8; 1024];
                    // Read until the end of the header block; these requests
                    // carry no body.
                    while !buffer.windows(4).any(|window| window == b"\r\n\r\n") {
                        match stream.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(read) => buffer.extend_from_slice(&chunk[..read]),
                        }
                    }
                    let text = String::from_utf8_lossy(&buffer).into_owned();
                    let target = text
                        .lines()
                        .next()
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap_or_default()
                        .to_string();
                    recorded.lock().expect("targets lock").push(target.clone());

                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                        target.len(),
                        target
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.flush().await;
                });
            }
        });

        Self {
            port,
            targets,
            handle,
        }
    }

    fn targets(&self) -> Vec<String> {
        self.targets.lock().expect("targets lock").clone()
    }

    fn take_targets(&self) -> Vec<String> {
        std::mem::take(&mut *self.targets.lock().expect("targets lock"))
    }
}

impl Drop for RecordingBackend {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

// ============================================================================
// Gateway
// ============================================================================

fn build_config(backend_port: u16) -> String {
    format!(
        r#"version: "1"
proxies:
  - id: "canon"
    listen_path: "/canon"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: false
    pool_enable_http2: false
    plugins:
      - plugin_config_id: "canon-termination"
  - id: "strip"
    listen_path: "/strip"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true
    pool_enable_http2: false

consumers: []
plugin_configs:
  - id: "canon-termination"
    plugin_name: request_termination
    scope: proxy
    proxy_id: "canon"
    enabled: true
    config:
      status_code: 403
      content_type: application/json
      message: "blocked by policy"
      trigger:
        path_prefix: "/canon/blocked"
"#
    )
}

async fn spawn_gateway(backend_port: u16) -> (TestGateway, u16) {
    const MAX_ATTEMPTS: usize = 5;
    let mut last_error = String::new();

    for _ in 0..MAX_ATTEMPTS {
        // Reserve a fresh HTTPS/QUIC port per attempt (functional-test rule:
        // every retry gets fresh ports).
        let reservation = match TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(error) => {
                last_error = error.to_string();
                sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        let https_port = match reservation.local_addr() {
            Ok(address) => address.port(),
            Err(error) => {
                last_error = error.to_string();
                sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        drop(reservation);

        let result = TestGateway::builder()
            .mode_file(build_config(backend_port))
            .log_level("warn")
            .max_attempts(1)
            .env("FERRUM_ENABLE_HTTP3", "true")
            .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
            .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
            .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
            .env("FERRUM_POOL_WARMUP_ENABLED", "false")
            .spawn()
            .await;
        match result {
            Ok(gateway) => return (gateway, https_port),
            Err(error) => {
                last_error = error.to_string();
                sleep(Duration::from_millis(200)).await;
            }
        }
    }

    panic!("failed to spawn policy-path gateway after {MAX_ATTEMPTS} attempts: {last_error}");
}

// ============================================================================
// Per-protocol senders — each puts `target` on the wire verbatim
// ============================================================================

/// HTTP/1.1 over a raw socket: the only way to control the request-line bytes
/// exactly, including targets no URL type would round-trip (`/canon/%zz`).
async fn send_h1(proxy_port: u16, target: &str) -> u16 {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .expect("connect h1");
    let _ = stream.set_nodelay(true);
    let request =
        format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write h1 request");

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("read h1 response");
    let text = String::from_utf8_lossy(&response).into_owned();
    text.lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("no status line in H1 response for {target:?}: {text:?}"))
}

/// HTTP/2 cleartext with prior knowledge. `http::Uri` preserves percent
/// escapes verbatim, so `:path` carries the spelling under test.
async fn send_h2(proxy_port: u16, target: &str) -> u16 {
    let stream = TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .expect("connect h2");
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
        .await
        .expect("h2 handshake");
    let conn_task = tokio::spawn(async move {
        let _ = conn.await;
    });

    let request = Request::builder()
        .method("GET")
        .uri(format!("http://127.0.0.1:{proxy_port}{target}"))
        .body(Full::new(Bytes::new()))
        .expect("build h2 request");
    let response = sender.send_request(request).await.expect("send h2 request");
    let status = response.status().as_u16();
    let _ = response.into_body().collect().await;

    drop(sender);
    conn_task.abort();
    status
}

async fn send_h3(client: &Http3Client, https_port: u16, target: &str) -> u16 {
    let url = format!("https://127.0.0.1:{https_port}{target}");
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match client.get(&url).await {
            Ok(response) => return response.status.as_u16(),
            Err(error) if Instant::now() < deadline => {
                let _ = error;
                sleep(Duration::from_millis(100)).await;
            }
            Err(error) => panic!("H3 GET {url} did not complete: {error}"),
        }
    }
}

// ============================================================================
// Cases
// ============================================================================

/// What the recording backend must have seen once the response arrives.
enum Backend {
    /// The request must never reach a backend — the gateway answered it.
    Never,
    /// The backend must have executed exactly this request target.
    Exact(&'static str),
    /// The backend was reached; the exact rendering is outside this contract.
    Reached,
}

struct Case {
    /// Request target exactly as it goes on the wire.
    target: &'static str,
    status: u16,
    backend_target: Backend,
    why: &'static str,
}

const CASES: &[Case] = &[
    // Ordinary single encoding of a character that is legal literally in a
    // path: the advisory's headline bypass. Policy and backend must both see
    // `/canon/admin`.
    Case {
        target: "/canon/%61dmin",
        status: 200,
        backend_target: Backend::Exact("/canon/admin"),
        why: "single-encoded legal character decodes for policy and backend alike",
    },
    Case {
        target: "/canon/%61%64%6D%69%6E",
        status: 200,
        backend_target: Backend::Exact("/canon/admin"),
        why: "fully encoded spelling is the same policy path",
    },
    // An escape of a character that cannot appear literally in a path is
    // refused: it could not be decoded into the forwarded target, and keeping
    // it escaped would leave policy reading `/canon/a%20b` while a decoding
    // backend resolves `/canon/a b`.
    Case {
        target: "/canon/a%20b",
        status: 400,
        backend_target: Backend::Never,
        why: "encoded space cannot be forwarded literally",
    },
    Case {
        target: "/canon/a%7Bb",
        status: 400,
        backend_target: Backend::Never,
        why: "encoded brace cannot be forwarded literally",
    },
    Case {
        target: "/canon/caf%C3%A9",
        status: 400,
        backend_target: Backend::Never,
        why: "encoded non-ASCII bytes cannot be forwarded literally",
    },
    Case {
        target: "/canon/a%2fb",
        status: 400,
        backend_target: Backend::Never,
        why: "encoded separator is refused, not folded",
    },
    Case {
        target: "/canon/a%5Cb",
        status: 400,
        backend_target: Backend::Never,
        why: "encoded backslash is a separator to several backends",
    },
    Case {
        target: "/canon/a%252Fb",
        status: 400,
        backend_target: Backend::Never,
        why: "double encoding cannot survive a second decode",
    },
    Case {
        target: "/canon/%2e%2e/secret",
        status: 400,
        backend_target: Backend::Never,
        why: "escape-synthesized dot segment is ambiguous",
    },
    Case {
        target: "/canon/%zz",
        status: 400,
        backend_target: Backend::Never,
        why: "non-hex escape has no single reading",
    },
    Case {
        target: "/canon/%2",
        status: 400,
        backend_target: Backend::Never,
        why: "truncated escape has no single reading",
    },
    Case {
        target: "/canon/caf%C3%28",
        status: 400,
        backend_target: Backend::Never,
        why: "escaped non-ASCII bytes are refused, valid UTF-8 or not",
    },
    Case {
        target: "/canon/%00",
        status: 400,
        backend_target: Backend::Never,
        why: "encoded NUL truncates the path in several runtimes",
    },
    // `request_termination` is configured with `path_prefix: /canon/blocked`.
    // The encoded spelling must hit the same rule as the plain one.
    Case {
        target: "/canon/blocked/thing",
        status: 403,
        backend_target: Backend::Never,
        why: "plain spelling trips the termination prefix",
    },
    Case {
        target: "/canon/%62locked/thing",
        status: 403,
        backend_target: Backend::Never,
        why: "encoded spelling trips the same termination prefix",
    },
    // Listen-path stripping is measured in the canonical coordinate, so the
    // forwarded remainder matches the routing decision.
    Case {
        target: "/strip/%74ail",
        status: 200,
        backend_target: Backend::Exact("/tail"),
        why: "strip_listen_path shares the canonical coordinate with routing",
    },
    Case {
        target: "/%73trip/tail",
        status: 200,
        backend_target: Backend::Exact("/tail"),
        why: "an encoded listen-path prefix still routes and strips identically",
    },
    // Literal dot segments are accepted rather than rejected: canonicalization
    // refuses ambiguity, it does not rewrite meaning, and a literal `..` is
    // equally visible to operator, gateway, and backend. Only the status is
    // asserted here — how the backend URL builder renders dot segments is
    // pre-existing behavior outside this contract.
    Case {
        target: "/canon/a/../b",
        status: 200,
        backend_target: Backend::Reached,
        why: "literal dot segments are not an encoding ambiguity",
    },
];

fn assert_case(protocol: &str, case: &Case, status: u16, observed: Vec<String>) {
    assert_eq!(
        status, case.status,
        "{protocol} {}: expected {} ({}), got {status}",
        case.target, case.status, case.why
    );
    match case.backend_target {
        Backend::Exact(expected) => assert_eq!(
            observed,
            vec![expected.to_string()],
            "{protocol} {}: backend must execute {expected:?} ({})",
            case.target,
            case.why
        ),
        Backend::Never => assert!(
            observed.is_empty(),
            "{protocol} {}: request must never reach a backend ({}), backend saw {observed:?}",
            case.target,
            case.why
        ),
        Backend::Reached => assert_eq!(
            observed.len(),
            1,
            "{protocol} {}: expected exactly one backend request ({}), backend saw {observed:?}",
            case.target,
            case.why
        ),
    }
}

#[ignore]
#[tokio::test]
async fn functional_policy_path_canonicalization_is_identical_across_h1_h2_h3() {
    let backend = RecordingBackend::start().await;
    let (mut gateway, https_port) = spawn_gateway(backend.port).await;
    gateway
        .wait_for_proxy_port(Duration::from_secs(15))
        .await
        .expect("proxy port ready");
    let proxy_port = gateway.proxy_port;

    // Drain anything a readiness probe may have produced before the matrix.
    let _ = backend.take_targets();

    for case in CASES {
        let status = send_h1(proxy_port, case.target).await;
        assert_case("H1", case, status, backend.take_targets());
    }

    for case in CASES {
        let status = send_h2(proxy_port, case.target).await;
        assert_case("H2", case, status, backend.take_targets());
    }

    let h3 = Http3Client::insecure().expect("H3 client");
    for case in CASES {
        let status = send_h3(&h3, https_port, case.target).await;
        assert_case("H3", case, status, backend.take_targets());
    }

    assert!(
        backend.targets().is_empty(),
        "no stray backend traffic should remain"
    );

    gateway.shutdown();
}
