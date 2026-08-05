//! Functional tests for `a2a_gateway` unary gRPC Agent Card rewriting
//! (issue #3297).
//!
//! Issue #3297 asks for evidence on the LIVE data path, not just at the plugin
//! hook boundary: the rewrite changes what a discovery client is told to connect
//! to, and it re-frames a native gRPC response, so the framing, headers, and
//! terminal trailers have to be right on the wire.
//!
//! These tests:
//! 1. Start a local gRPC echo backend (h2c HTTP/2) that returns the request body
//!    as the response body, so the test controls the exact protobuf Agent Card
//!    payload the gateway sees. It emits `grpc-status: 0` as a real TRAILERS
//!    frame after the DATA frame, which is what the gateway's merged
//!    header+trailer plugin view is built from.
//! 2. Start the gateway binary in file mode with an `a2a_gateway` config whose
//!    `discovery.public_base_url` and `endpoint.protocol_versions` drive the
//!    rewrite and the version gate.
//! 3. Assert the rewritten frame, the preserved non-JSONRPC interfaces, the
//!    removed signatures, protocol-correct headers/trailers, and fail-closed
//!    behaviour for malformed / mis-versioned / compressed cards — all end to
//!    end over the real native gRPC data path.
//! 4. Assert reload behaviour: a changed public base and a withdrawn
//!    `rewrite_agent_card_urls` both take effect on a SIGHUP'd running gateway,
//!    so the feature is not merely correct at first construction.
//!
//! The harness is deliberately the bounded one `functional_ai_response_guard_grpc_test`
//! uses: one echo backend holding its own pre-bound listener, one gateway child
//! with retry on fresh ports, and no unbounded servers.
//!
//! Run with:
//! `cargo test --test functional_tests functional_a2a_gateway_grpc_card -- --ignored --nocapture`

use crate::scaffolding::ports::reserve_port;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::server::conn::http2::Builder as Http2ServerBuilder;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::collections::HashMap;
use std::io::Write;
use std::net::SocketAddr;
use std::time::Duration;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time::{Instant, sleep};
use tokio_stream::wrappers::ReceiverStream;

const PUBLIC_BASE: &str = "https://agents.example.com";
// Reload coverage is Unix-only: file-mode SIGHUP reload is not supported by the
// gateway on Windows.
#[cfg_attr(not(unix), allow(dead_code))]
const ALTERNATE_PUBLIC_BASE: &str = "https://agents-2.example.com";
const A2A_SERVICE: &str = "/lf.a2a.v1.A2AService";

// ============================================================================
// A2A 0.3 protobuf fixtures
//
// Hand-encoded rather than descriptor-driven: the gateway performs wire surgery
// against these exact field numbers, so the fixture must be the wire and not a
// generated view of it.
//   AgentCard: name=1 description=2 url=3 preferred_transport=14
//              additional_interfaces=15 protocol_version=16 signatures=17
//   AgentInterface: url=1 transport=2
// ============================================================================

fn encode_varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn encode_len_field(field: u32, value: &[u8], out: &mut Vec<u8>) {
    encode_varint(u64::from(field) << 3 | 2, out);
    encode_varint(value.len() as u64, out);
    out.extend_from_slice(value);
}

fn encode_string_field(field: u32, value: &str, out: &mut Vec<u8>) {
    encode_len_field(field, value.as_bytes(), out);
}

fn encode_agent_interface(url: &str, transport: &str) -> Vec<u8> {
    let mut out = Vec::new();
    encode_string_field(1, url, &mut out);
    encode_string_field(2, transport, &mut out);
    out
}

/// A complete A2A 0.3 Agent Card: JSON-RPC preferred, one JSON-RPC interface,
/// one gRPC interface, and a signature block.
fn encode_agent_card(protocol_version: &str) -> Vec<u8> {
    let mut out = Vec::new();
    encode_string_field(1, "planner", &mut out);
    encode_string_field(2, "planning agent", &mut out);
    encode_string_field(3, "https://planner.internal/a2a", &mut out);
    encode_string_field(14, "JSONRPC", &mut out);
    encode_len_field(
        15,
        &encode_agent_interface("https://planner.internal/a2a", "JSONRPC"),
        &mut out,
    );
    encode_len_field(
        15,
        &encode_agent_interface("https://planner.internal/grpc", "GRPC"),
        &mut out,
    );
    encode_string_field(16, protocol_version, &mut out);
    let mut signature = Vec::new();
    encode_string_field(1, "eyJhbGciOiJFUzI1NiJ9", &mut signature);
    encode_string_field(2, "stale-signature", &mut signature);
    encode_len_field(17, &signature, &mut out);
    out
}

fn grpc_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(0);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// Split one identity-framed gRPC message out of a response body, verifying the
/// declared length matches what actually arrived.
fn single_frame_payload(body: &[u8]) -> Vec<u8> {
    assert!(
        body.len() >= 5,
        "expected a framed gRPC message, got {} bytes",
        body.len()
    );
    assert_eq!(body[0], 0, "rewritten frames must be uncompressed identity");
    let declared = u32::from_be_bytes([body[1], body[2], body[3], body[4]]) as usize;
    assert_eq!(
        declared,
        body.len() - 5,
        "the frame length prefix must describe exactly the bytes on the wire"
    );
    body[5..].to_vec()
}

/// Minimal reader for the fields these assertions inspect.
fn walk_fields(message: &[u8], mut visit: impl FnMut(u32, u8, &[u8])) {
    let mut buf = message;
    while !buf.is_empty() {
        let mut key = 0u64;
        let mut shift = 0;
        loop {
            let Some(&byte) = buf.first() else { return };
            buf = &buf[1..];
            key |= u64::from(byte & 0x7f) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                break;
            }
        }
        let field = (key >> 3) as u32;
        let wire = (key & 0x07) as u8;
        match wire {
            0 => {
                loop {
                    let Some(&byte) = buf.first() else { return };
                    buf = &buf[1..];
                    if byte & 0x80 == 0 {
                        break;
                    }
                }
                visit(field, wire, &[]);
            }
            1 => {
                if buf.len() < 8 {
                    return;
                }
                let (value, rest) = buf.split_at(8);
                buf = rest;
                visit(field, wire, value);
            }
            2 => {
                let mut len = 0usize;
                let mut shift = 0;
                loop {
                    let Some(&byte) = buf.first() else { return };
                    buf = &buf[1..];
                    len |= usize::from(byte & 0x7f) << shift;
                    shift += 7;
                    if byte & 0x80 == 0 {
                        break;
                    }
                }
                if buf.len() < len {
                    return;
                }
                let (value, rest) = buf.split_at(len);
                buf = rest;
                visit(field, wire, value);
            }
            5 => {
                if buf.len() < 4 {
                    return;
                }
                let (value, rest) = buf.split_at(4);
                buf = rest;
                visit(field, wire, value);
            }
            _ => return,
        }
    }
}

fn string_field(message: &[u8], target: u32) -> Option<String> {
    let mut found = None;
    walk_fields(message, |field, wire, value| {
        if field == target && wire == 2 {
            found = String::from_utf8(value.to_vec()).ok();
        }
    });
    found
}

fn repeated_messages(message: &[u8], target: u32) -> Vec<Vec<u8>> {
    let mut found = Vec::new();
    walk_fields(message, |field, wire, value| {
        if field == target && wire == 2 {
            found.push(value.to_vec());
        }
    });
    found
}

fn has_field(message: &[u8], target: u32) -> bool {
    let mut found = false;
    walk_fields(message, |field, _wire, _value| {
        if field == target {
            found = true;
        }
    });
    found
}

// ============================================================================
// Harness
// ============================================================================

async fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    listener.local_addr().unwrap().port()
}

/// Echo backend: returns the request body as the gRPC response body, mirrors
/// `x-set-grpc-encoding` into the response `grpc-encoding`, and mirrors
/// `x-set-grpc-status` into the terminal trailer so a test can drive a non-OK
/// upstream reply that still carries a DATA frame.
///
/// The terminal status always rides an HTTP/2 TRAILERS frame after the DATA
/// frame(s). Putting it in the initial HEADERS block is protocol-invalid for a
/// message-carrying response, and the gateway treats that field as
/// transport-managed rather than as a success signal.
async fn start_grpc_echo_backend() -> (u16, tokio::task::JoinHandle<()>) {
    let reservation = reserve_port().await.expect("reserve backend port");
    let port = reservation.port;
    let listener = reservation.into_listener();

    let handle = tokio::spawn(async move {
        loop {
            let (stream, _addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => break,
            };
            let _ = stream.set_nodelay(true);

            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let builder = Http2ServerBuilder::new(TokioExecutor::new());
                let service = service_fn(|req: Request<Incoming>| async move {
                    let header = |name: &str| {
                        req.headers()
                            .get(name)
                            .and_then(|value| value.to_str().ok())
                            .map(str::to_string)
                    };
                    let encoding = header("x-set-grpc-encoding");
                    let status = header("x-set-grpc-status").unwrap_or_else(|| "0".to_string());
                    let body_bytes = req
                        .into_body()
                        .collect()
                        .await
                        .map(|collected| collected.to_bytes())
                        .unwrap_or_default();

                    let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, std::io::Error>>(2);
                    let _ = tx.send(Ok(Frame::data(body_bytes))).await;
                    let mut trailers = hyper::HeaderMap::new();
                    if let Ok(value) = hyper::header::HeaderValue::from_str(&status) {
                        trailers.insert("grpc-status", value);
                    }
                    let _ = tx.send(Ok(Frame::trailers(trailers))).await;
                    drop(tx);

                    let mut builder = Response::builder()
                        .status(200)
                        .header("content-type", "application/grpc");
                    if let Some(encoding) = encoding {
                        builder = builder.header("grpc-encoding", encoding);
                    }
                    let response = builder
                        .body(StreamBody::new(ReceiverStream::new(rx)))
                        .unwrap();
                    Ok::<_, hyper::Error>(response)
                });
                if let Err(e) = builder.serve_connection(io, service).await
                    && !format!("{}", e).contains("connection closed")
                {
                    eprintln!("gRPC echo backend error: {}", e);
                }
            });
        }
    });

    (port, handle)
}

fn build_gateway() -> Result<(), Box<dyn std::error::Error>> {
    crate::common::ensure_gateway_built().map_err(|e| -> Box<dyn std::error::Error> { e })
}

fn gateway_binary_path() -> &'static str {
    if std::path::Path::new("./target/debug/ferrum-edge").exists() {
        "./target/debug/ferrum-edge"
    } else {
        "./target/release/ferrum-edge"
    }
}

fn start_gateway(
    config_path: &str,
    http_port: u16,
    admin_port: u16,
) -> Result<std::process::Child, Box<dyn std::error::Error>> {
    let child = std::process::Command::new(gateway_binary_path())
        .env("FERRUM_MODE", "file")
        .env("FERRUM_FILE_CONFIG_PATH", config_path)
        .env("FERRUM_PROXY_HTTP_PORT", http_port.to_string())
        .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string())
        .env("FERRUM_ACCEPT_THREADS", "1")
        .env("FERRUM_POOL_WARMUP_ENABLED", "false")
        .env("RUST_LOG", "ferrum_edge=debug")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    Ok(child)
}

async fn wait_for_gateway(
    admin_port: u16,
    gateway_port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let health_url = format!("http://127.0.0.1:{}/health", admin_port);
    for _ in 0..60 {
        if let Ok(resp) = client.get(&health_url).send().await
            && resp.status().is_success()
            && tokio::net::TcpStream::connect(("127.0.0.1", gateway_port))
                .await
                .is_ok()
        {
            return Ok(());
        }
        sleep(Duration::from_millis(250)).await;
    }
    Err("Gateway did not become healthy within 15 seconds".into())
}

async fn start_gateway_with_retry(config_path: &str) -> (std::process::Child, u16, u16) {
    const MAX_ATTEMPTS: u32 = 3;
    for attempt in 1..=MAX_ATTEMPTS {
        let gateway_port = free_port().await;
        let admin_port = free_port().await;
        let mut child = match start_gateway(config_path, gateway_port, admin_port) {
            Ok(child) => child,
            Err(e) => {
                eprintln!(
                    "Gateway spawn attempt {}/{} failed: {}",
                    attempt, MAX_ATTEMPTS, e
                );
                if attempt < MAX_ATTEMPTS {
                    sleep(Duration::from_secs(1)).await;
                }
                continue;
            }
        };
        match wait_for_gateway(admin_port, gateway_port).await {
            Ok(()) => return (child, gateway_port, admin_port),
            Err(e) => {
                eprintln!(
                    "Gateway health attempt {}/{} failed: {}",
                    attempt, MAX_ATTEMPTS, e
                );
                let _ = child.kill();
                let _ = child.wait();
                if attempt < MAX_ATTEMPTS {
                    sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }
    panic!("Gateway did not start after {} attempts", MAX_ATTEMPTS);
}

struct GrpcCall {
    status: u16,
    headers: HashMap<String, String>,
    trailers: HashMap<String, String>,
    body: Vec<u8>,
}

impl GrpcCall {
    fn terminal_grpc_status(&self) -> &str {
        self.trailers
            .get("grpc-status")
            .or_else(|| self.headers.get("grpc-status"))
            .map(String::as_str)
            .unwrap_or("")
    }
}

/// A successful message-carrying gRPC response: HTTP 200, `grpc-status: 0` in
/// terminal TRAILERS, and no terminal metadata in the initial HEADERS block.
fn assert_ok_message_carrying(call: &GrpcCall, context: &str) {
    assert_eq!(call.status, 200, "{context}: gRPC rides HTTP 200");
    assert_eq!(
        call.trailers.get("grpc-status").map(String::as_str),
        Some("0"),
        "{context}: expected grpc-status: 0 in terminal trailers (headers={:?})",
        call.headers.get("grpc-status"),
    );
    assert!(
        !call.headers.contains_key("grpc-status"),
        "{context}: a message-carrying response must not expose grpc-status in initial HEADERS",
    );
    assert_eq!(
        call.headers.get("content-type").map(String::as_str),
        Some("application/grpc"),
        "{context}: content-type must stay application/grpc",
    );
}

/// A fail-closed rewrite refusal: HTTP 200 Trailers-Only with a nonzero
/// `grpc-status` and an EMPTY body. An HTTP JSON error body here would be an
/// HTTP-body leak onto a native gRPC stream.
fn assert_trailers_only_failure(call: &GrpcCall, context: &str) {
    assert_eq!(
        call.status, 200,
        "{context}: a gRPC failure rides HTTP 200, not a synthetic 5xx",
    );
    let raw = call.terminal_grpc_status();
    assert!(
        !raw.is_empty(),
        "{context}: expected a present terminal grpc-status, got empty/missing",
    );
    let code: u32 = raw
        .parse()
        .unwrap_or_else(|_| panic!("{context}: grpc-status {raw:?} is not a parseable u32"));
    assert_ne!(
        code, 0,
        "{context}: expected a nonzero terminal grpc-status"
    );
    assert!(
        call.body.is_empty(),
        "{context}: a gRPC rewrite refusal must be trailers-only, not an HTTP body ({} bytes)",
        call.body.len(),
    );
}

async fn send_grpc_request(
    gateway_addr: &str,
    path: &str,
    body: &[u8],
    extra_headers: &[(&str, &str)],
) -> Result<GrpcCall, Box<dyn std::error::Error + Send + Sync>> {
    use hyper::client::conn::http2;

    let addr: SocketAddr = gateway_addr.parse()?;
    let stream = tokio::net::TcpStream::connect(addr).await?;
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);

    let (mut sender, conn) = http2::handshake(TokioExecutor::new(), io).await?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            eprintln!("Client h2 connection error: {}", e);
        }
    });

    let mut req_builder = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/grpc")
        .header("te", "trailers");
    for (key, value) in extra_headers {
        req_builder = req_builder.header(*key, *value);
    }
    let req = req_builder.body(Full::new(Bytes::from(body.to_vec())))?;
    let response = sender.send_request(req).await?;

    let status = response.status().as_u16();
    let mut headers = HashMap::new();
    for (key, value) in response.headers() {
        if let Ok(text) = value.to_str() {
            headers.insert(key.as_str().to_string(), text.to_string());
        }
    }
    let collected = response.into_body().collect().await?;
    let mut trailers = HashMap::new();
    if let Some(trailer_map) = collected.trailers() {
        for (key, value) in trailer_map {
            if let Ok(text) = value.to_str() {
                trailers.insert(key.as_str().to_string(), text.to_string());
            }
        }
    }

    Ok(GrpcCall {
        status,
        headers,
        trailers,
        body: collected.to_bytes().to_vec(),
    })
}

/// A file-mode config with one `a2a_gateway` instance. The backend port stays a
/// placeholder so the same template can be re-rendered for a reload against the
/// harness's already-running backend.
fn config_template(
    public_base: &str,
    rewrite_agent_card_urls: bool,
    protocol_versions: &str,
) -> String {
    format!(
        r#"
version: "1"
proxies:
  - id: "a2a-grpc-proxy"
    listen_path: "/"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: BACKEND_PORT_PLACEHOLDER
    strip_listen_path: false
    auth_mode: single
    plugins:
      - plugin_config_id: "a2a-grpc"

consumers: []

plugin_configs:
  - id: "a2a-grpc"
    plugin_name: "a2a_gateway"
    scope: proxy
    proxy_id: "a2a-grpc-proxy"
    enabled: true
    config:
      enabled: true
      endpoint:
        path: "/a2a"
        protocol_versions: {protocol_versions}
      detection:
        bindings: [grpc]
      discovery:
        rewrite_agent_card_urls: {rewrite_agent_card_urls}
        public_base_url: "{public_base}"
      observability:
        emit_metadata: true
"#
    )
}

struct Harness {
    gateway: std::process::Child,
    backend: tokio::task::JoinHandle<()>,
    /// Only read by the Unix-only SIGHUP reload path.
    #[cfg_attr(not(unix), allow(dead_code))]
    backend_port: u16,
    addr: String,
    /// Only read by the Unix-only SIGHUP reload path.
    #[cfg_attr(not(unix), allow(dead_code))]
    config_path: std::path::PathBuf,
    _temp: TempDir,
}

impl Harness {
    async fn start_with(template: String) -> Self {
        build_gateway().expect("build gateway binary");
        let (backend_port, backend) = start_grpc_echo_backend().await;
        let temp = TempDir::new().expect("temp dir");
        let config_path = temp.path().join("config.yaml");
        write_config(&config_path, &render(&template, backend_port));
        let (gateway, port, _admin) =
            start_gateway_with_retry(config_path.to_str().expect("utf-8 path")).await;
        Self {
            gateway,
            backend,
            backend_port,
            addr: format!("127.0.0.1:{}", port),
            config_path,
            _temp: temp,
        }
    }

    /// Default harness: rewriting on, public base `PUBLIC_BASE`, `0.3.0` only.
    async fn start() -> Self {
        Self::start_with(config_template(PUBLIC_BASE, true, r#"["0.3.0"]"#)).await
    }

    /// Rewrite the config file and SIGHUP the RUNNING child. Callers then poll
    /// the behavior that proves the new generation is active; an unconditional
    /// sleep is not a reload-completion signal and becomes flaky under runner
    /// contention.
    #[cfg(unix)]
    async fn reload_with(&self, template: String) {
        write_config(&self.config_path, &render(&template, self.backend_port));
        let pid = self.gateway.id();
        let output = std::process::Command::new("kill")
            .args(["-HUP", &pid.to_string()])
            .output()
            .expect("send SIGHUP to gateway");
        assert!(
            output.status.success(),
            "sending SIGHUP to gateway failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// Poll the live data path until one response proves a reload has taken
    /// effect, or fail with the last observed response/error. This waits on the
    /// actual behavior under test instead of guessing how long a runner needs.
    #[cfg(unix)]
    async fn wait_for_reloaded_call(
        &self,
        path: &str,
        body: &[u8],
        context: &str,
        mut ready: impl FnMut(&GrpcCall) -> bool,
    ) -> GrpcCall {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let last_observation = match send_grpc_request(&self.addr, path, body, &[]).await {
                Ok(call) if ready(&call) => return call,
                Ok(call) => format!(
                    "HTTP {}, grpc-status {:?}, body {} bytes",
                    call.status,
                    call.terminal_grpc_status(),
                    call.body.len()
                ),
                Err(error) => format!("request failed: {error}"),
            };
            assert!(
                Instant::now() < deadline,
                "{context}: reloaded behavior did not appear within 10 seconds; last observation: {last_observation}"
            );
            sleep(Duration::from_millis(50)).await;
        }
    }

    fn shutdown(self) {
        drop(self);
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = self.gateway.kill();
        let _ = self.gateway.wait();
        self.backend.abort();
    }
}

fn render(template: &str, backend_port: u16) -> String {
    template.replace("BACKEND_PORT_PLACEHOLDER", &backend_port.to_string())
}

fn write_config(path: &std::path::Path, config: &str) {
    let mut file = std::fs::File::create(path).expect("create config file");
    file.write_all(config.as_bytes()).expect("write config");
}

// ============================================================================
// Tests
// ============================================================================

/// The core acceptance: a unary `GetAgentCard` response is re-framed with the
/// JSON-RPC endpoints pointed at the public base, the advertised gRPC interface
/// left alone, and the now-invalid signature block removed — with
/// protocol-correct HTTP status, headers, and terminal trailers.
#[tokio::test]
#[ignore]
async fn a2a_grpc_agent_card_is_rewritten_on_the_live_data_path() {
    let harness = Harness::start().await;
    let card = encode_agent_card("0.3.0");
    let call = send_grpc_request(
        &harness.addr,
        &format!("{A2A_SERVICE}/GetAgentCard"),
        &grpc_frame(&card),
        &[],
    )
    .await
    .expect("gRPC call");

    assert_ok_message_carrying(&call, "rewritten agent card");
    assert!(
        !call.headers.contains_key("grpc-encoding"),
        "a rewritten frame is uncompressed identity, so grpc-encoding must be gone",
    );
    // Validators and integrity digests describe the backend's ORIGINAL
    // representation and are invalidated by the rewrite. `content-length` is
    // deliberately not asserted here: it is transport-owned on this path and
    // the gateway recomputes it from the bytes it actually sends.
    assert!(
        !call.headers.contains_key("etag")
            && !call.headers.contains_key("content-digest")
            && !call.headers.contains_key("content-encoding"),
        "body-coupled headers must not describe the backend's replaced representation",
    );

    let message = single_frame_payload(&call.body);
    assert_eq!(
        string_field(&message, 3).as_deref(),
        Some(format!("{PUBLIC_BASE}/a2a").as_str()),
        "AgentCard.url must point at the public JSON-RPC endpoint",
    );
    let interfaces = repeated_messages(&message, 15);
    assert_eq!(interfaces.len(), 2, "both interfaces must survive");
    assert_eq!(
        string_field(&interfaces[0], 1).as_deref(),
        Some(format!("{PUBLIC_BASE}/a2a").as_str()),
        "the JSONRPC interface must be rewritten",
    );
    assert_eq!(
        string_field(&interfaces[1], 1).as_deref(),
        Some("https://planner.internal/grpc"),
        "a non-JSONRPC interface must be preserved verbatim",
    );
    assert!(
        !has_field(&message, 17),
        "signatures must be removed: the rewrite invalidated them",
    );
    assert_eq!(
        string_field(&message, 1).as_deref(),
        Some("planner"),
        "unrelated fields must round-trip unchanged",
    );
    assert_eq!(string_field(&message, 16).as_deref(), Some("0.3.0"));
    harness.shutdown();
}

/// `GetExtendedAgentCard` is the other card RPC and takes the same path.
#[tokio::test]
#[ignore]
async fn a2a_grpc_extended_agent_card_is_rewritten_too() {
    let harness = Harness::start().await;
    let call = send_grpc_request(
        &harness.addr,
        &format!("{A2A_SERVICE}/GetExtendedAgentCard"),
        &grpc_frame(&encode_agent_card("0.3.0")),
        &[],
    )
    .await
    .expect("gRPC call");

    assert_ok_message_carrying(&call, "extended agent card");
    let message = single_frame_payload(&call.body);
    assert_eq!(
        string_field(&message, 3).as_deref(),
        Some(format!("{PUBLIC_BASE}/a2a").as_str()),
    );
    harness.shutdown();
}

/// A non-card A2A RPC on the same service must be forwarded byte-for-byte: the
/// rewriter is scoped to Agent Card responses, not to A2A traffic generally.
#[tokio::test]
#[ignore]
async fn a2a_grpc_non_card_rpc_is_forwarded_untouched() {
    let harness = Harness::start().await;
    let body = grpc_frame(&encode_agent_card("0.3.0"));
    let call = send_grpc_request(&harness.addr, &format!("{A2A_SERVICE}/GetTask"), &body, &[])
        .await
        .expect("gRPC call");

    assert_ok_message_carrying(&call, "non-card RPC");
    assert_eq!(
        call.body, body,
        "a non-card RPC response must be forwarded verbatim",
    );
    harness.shutdown();
}

/// A card whose wire `protocol_version` is not an exactly-configured 0.3 version
/// fails closed. Serving it un-rewritten would hand discovery clients internal
/// URLs; rewriting it with 0.3 field numbers could corrupt a renumbered layout.
#[tokio::test]
#[ignore]
async fn a2a_grpc_unconfigured_card_version_fails_closed() {
    let harness = Harness::start().await;

    // Same 0.3 family, but not the configured `0.3.0`.
    let call = send_grpc_request(
        &harness.addr,
        &format!("{A2A_SERVICE}/GetAgentCard"),
        &grpc_frame(&encode_agent_card("0.3.99")),
        &[],
    )
    .await
    .expect("gRPC call");
    assert_trailers_only_failure(&call, "unconfigured 0.3.x version");

    // A renumbered 1.0 layout.
    let call = send_grpc_request(
        &harness.addr,
        &format!("{A2A_SERVICE}/GetAgentCard"),
        &grpc_frame(&encode_agent_card("1.0.0")),
        &[],
    )
    .await
    .expect("gRPC call");
    assert_trailers_only_failure(&call, "non-0.3 layout");
    harness.shutdown();
}

/// Malformed framing and message-level compression both fail closed with
/// protocol-correct gRPC semantics rather than a partially-rewritten card.
#[tokio::test]
#[ignore]
async fn a2a_grpc_malformed_and_compressed_cards_fail_closed() {
    let harness = Harness::start().await;

    let mut truncated = grpc_frame(&encode_agent_card("0.3.0"));
    truncated.pop();
    let call = send_grpc_request(
        &harness.addr,
        &format!("{A2A_SERVICE}/GetAgentCard"),
        &truncated,
        &[],
    )
    .await
    .expect("gRPC call");
    assert_trailers_only_failure(&call, "truncated gRPC frame");

    let call = send_grpc_request(
        &harness.addr,
        &format!("{A2A_SERVICE}/GetAgentCard"),
        &grpc_frame(&encode_agent_card("0.3.0")),
        &[("x-set-grpc-encoding", "gzip")],
    )
    .await
    .expect("gRPC call");
    assert_trailers_only_failure(&call, "message-compressed card");
    harness.shutdown();
}

/// A non-OK upstream reply that still carries a DATA frame must reach the client
/// as the backend's own failure. The terminal status arrives in TRAILERS, so a
/// rewriter that only inspects initial HEADERS would mistake it for a successful
/// Agent Card and then blame itself for failing to rewrite it.
#[tokio::test]
#[ignore]
async fn a2a_grpc_non_ok_upstream_reply_is_not_mistaken_for_a_card() {
    let harness = Harness::start().await;
    let call = send_grpc_request(
        &harness.addr,
        &format!("{A2A_SERVICE}/GetAgentCard"),
        &grpc_frame(&encode_agent_card("0.3.0")),
        &[("x-set-grpc-status", "7")],
    )
    .await
    .expect("gRPC call");

    assert_eq!(call.status, 200);
    assert_eq!(
        call.terminal_grpc_status(),
        "7",
        "the backend's own PERMISSION_DENIED must survive, not become a rewrite INTERNAL",
    );
    harness.shutdown();
}

/// Reload/update: a changed `discovery.public_base_url` takes effect on the
/// running gateway. First construction being correct is not enough — issue #3297
/// asks for reload coverage explicitly.
#[cfg(unix)]
#[tokio::test]
#[ignore]
async fn a2a_grpc_card_rewrite_follows_a_reloaded_public_base() {
    let harness = Harness::start().await;
    let path = format!("{A2A_SERVICE}/GetAgentCard");
    let body = grpc_frame(&encode_agent_card("0.3.0"));

    let call = send_grpc_request(&harness.addr, &path, &body, &[])
        .await
        .expect("pre-reload gRPC call");
    assert_ok_message_carrying(&call, "pre-reload");
    assert_eq!(
        string_field(&single_frame_payload(&call.body), 3).as_deref(),
        Some(format!("{PUBLIC_BASE}/a2a").as_str()),
    );

    harness
        .reload_with(config_template(ALTERNATE_PUBLIC_BASE, true, r#"["0.3.0"]"#))
        .await;

    let expected_url = format!("{ALTERNATE_PUBLIC_BASE}/a2a");
    let call = harness
        .wait_for_reloaded_call(&path, &body, "public-base reload", |call| {
            call.terminal_grpc_status() == "0"
                && call
                    .body
                    .windows(expected_url.len())
                    .any(|window| window == expected_url.as_bytes())
        })
        .await;
    assert_ok_message_carrying(&call, "post-reload");
    let message = single_frame_payload(&call.body);
    assert_eq!(
        string_field(&message, 3).as_deref(),
        Some(format!("{ALTERNATE_PUBLIC_BASE}/a2a").as_str()),
        "the reloaded public base must be the one advertised",
    );
    assert_eq!(
        string_field(&repeated_messages(&message, 15)[0], 1).as_deref(),
        Some(format!("{ALTERNATE_PUBLIC_BASE}/a2a").as_str()),
    );
    harness.shutdown();
}

/// Reload/withdrawal: turning `rewrite_agent_card_urls` off must actually stop
/// the rewrite on the running gateway — including stopping the fail-closed
/// refusal for versions it can no longer rewrite, which is the documented way an
/// operator fronts a non-0.3 backend.
#[cfg(unix)]
#[tokio::test]
#[ignore]
async fn a2a_grpc_card_rewrite_withdrawal_takes_effect_on_reload() {
    let harness = Harness::start().await;
    let path = format!("{A2A_SERVICE}/GetAgentCard");
    let card = encode_agent_card("0.3.0");
    let body = grpc_frame(&card);

    let call = send_grpc_request(&harness.addr, &path, &body, &[])
        .await
        .expect("pre-reload gRPC call");
    assert_ne!(
        call.body, body,
        "the rewrite must be active before withdrawal"
    );

    harness
        .reload_with(config_template(PUBLIC_BASE, false, r#"["0.3.0"]"#))
        .await;

    let call = harness
        .wait_for_reloaded_call(&path, &body, "rewrite withdrawal", |call| {
            call.terminal_grpc_status() == "0" && call.body.as_slice() == body
        })
        .await;
    assert_ok_message_carrying(&call, "withdrawn rewrite");
    assert_eq!(
        call.body, body,
        "with rewriting withdrawn, the backend's signed card must pass through verbatim",
    );

    // And a version this gateway cannot rewrite is no longer refused either.
    let unsupported = grpc_frame(&encode_agent_card("1.0.0"));
    let call = send_grpc_request(&harness.addr, &path, &unsupported, &[])
        .await
        .expect("gRPC call");
    assert_ok_message_carrying(&call, "withdrawn rewrite, 1.0 card");
    assert_eq!(call.body, unsupported);
    harness.shutdown();
}

/// Reload/update of the version allow-list: adding the wire version an upstream
/// actually serves turns a fail-closed refusal into a rewrite, without a
/// restart.
#[cfg(unix)]
#[tokio::test]
#[ignore]
async fn a2a_grpc_card_version_allow_list_reload_admits_a_new_version() {
    let harness = Harness::start().await;
    let path = format!("{A2A_SERVICE}/GetAgentCard");
    let body = grpc_frame(&encode_agent_card("0.3.7"));

    let call = send_grpc_request(&harness.addr, &path, &body, &[])
        .await
        .expect("pre-reload gRPC call");
    assert_trailers_only_failure(&call, "0.3.7 before it is configured");

    harness
        .reload_with(config_template(PUBLIC_BASE, true, r#"["0.3.0", "0.3.7"]"#))
        .await;

    let expected_url = format!("{PUBLIC_BASE}/a2a");
    let call = harness
        .wait_for_reloaded_call(&path, &body, "version allow-list reload", |call| {
            call.terminal_grpc_status() == "0"
                && call
                    .body
                    .windows(expected_url.len())
                    .any(|window| window == expected_url.as_bytes())
        })
        .await;
    assert_ok_message_carrying(&call, "0.3.7 after it is configured");
    assert_eq!(
        string_field(&single_frame_payload(&call.body), 3).as_deref(),
        Some(format!("{PUBLIC_BASE}/a2a").as_str()),
    );
    harness.shutdown();
}
