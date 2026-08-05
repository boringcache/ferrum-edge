//! Functional tests for `ai_transcript_audit` native-gRPC payload capture
//! (issue #3304), exercised over the REAL proxy data path rather than by
//! calling plugin hooks directly.
//!
//! Issue #3304 requires coverage through live unary and streaming gRPC data
//! paths, so each test here:
//! 1. Starts a local gRPC echo backend (h2c HTTP/2) that returns the request
//!    body as the response body, so the test controls both protobuf payloads.
//! 2. Starts a local HTTP audit collector and points the plugin's batching sink
//!    at it, so the assertion target is the record the gateway actually shipped.
//! 3. Starts the gateway binary in file mode with an `ai_transcript_audit`
//!    config whose `grpc` block enrolls `/test.Greeter/SayHello` against the
//!    checked-in `tests/fixtures/test_validator.bin` descriptor.
//! 4. Drives real native gRPC calls through the gateway and asserts on the
//!    exported record.
//!
//! Assertions are deliberately positive: a real, nonempty, decoded excerpt (or
//! the exact compiled-in omission reason), never merely "the secret is absent"
//! — an empty record would satisfy that trivially.
//!
//! Run with:
//! `cargo test --test functional_tests functional_ai_transcript_audit_grpc -- --ignored --nocapture`

use crate::scaffolding::ports::reserve_port;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::server::conn::http1::Builder as Http1ServerBuilder;
use hyper::server::conn::http2::Builder as Http2ServerBuilder;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde_json::Value;
use std::collections::HashMap;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time::sleep;
use tokio_stream::wrappers::ReceiverStream;

// ============================================================================
// Protobuf fixtures
// ============================================================================

fn descriptor_path() -> String {
    format!(
        "{}/tests/fixtures/test_validator.bin",
        env!("CARGO_MANIFEST_DIR")
    )
}

/// `test.HelloRequest { string name = 1; int32 age = 2; }`.
///
/// `age` is the knob that controls whether the encoded message is valid UTF-8:
/// a negative `int32` encodes as a ten-byte varint of `0xFF` bytes, which is
/// not valid UTF-8 anywhere in the buffer.
///
/// Leaving `age` at the proto3 default (`0`) omits it from the wire, so the
/// encoding is exactly `field 1 = <name>` — byte-identical to a
/// `test.HelloResponse { string message = 1; }`. The echo backend can therefore
/// return the request verbatim and still be a well-formed response of the
/// enrolled response type.
fn encode_hello_request(name: &str, age: i32) -> Vec<u8> {
    use prost::Message;
    use prost_reflect::{DescriptorPool, DynamicMessage, Value as ProtoValue};

    let bytes = std::fs::read(descriptor_path()).expect("descriptor fixture");
    let pool = DescriptorPool::decode(bytes.as_slice()).expect("descriptor parses");
    let descriptor = pool
        .get_message_by_name("test.HelloRequest")
        .expect("test.HelloRequest");
    let mut msg = DynamicMessage::new(descriptor);
    msg.set_field_by_name("name", ProtoValue::String(name.to_string()));
    msg.set_field_by_name("age", ProtoValue::I32(age));
    msg.encode_to_vec()
}

fn grpc_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(0);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn gzip_grpc_frame(payload: &[u8]) -> Vec<u8> {
    use flate2::write::GzEncoder;

    let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(payload).expect("gzip write");
    let compressed = encoder.finish().expect("gzip finish");
    let mut frame = Vec::with_capacity(5 + compressed.len());
    frame.push(1);
    frame.extend_from_slice(&(compressed.len() as u32).to_be_bytes());
    frame.extend_from_slice(&compressed);
    frame
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

/// Echo backend: returns the request body as the gRPC response body. Terminal
/// `grpc-status: 0` is emitted as an HTTP/2 TRAILERS frame after the DATA
/// frame(s), which is what an ordinary message-carrying gRPC reply looks like.
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
                    let encoding = req
                        .headers()
                        .get("grpc-encoding")
                        .and_then(|value| value.to_str().ok())
                        .map(str::to_string);
                    let body_bytes = req
                        .into_body()
                        .collect()
                        .await
                        .map(|collected| collected.to_bytes())
                        .unwrap_or_default();

                    let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, std::io::Error>>(2);
                    let _ = tx.send(Ok(Frame::data(body_bytes))).await;
                    let mut trailers = hyper::HeaderMap::new();
                    trailers.insert("grpc-status", hyper::header::HeaderValue::from_static("0"));
                    let _ = tx.send(Ok(Frame::trailers(trailers))).await;
                    drop(tx);

                    let mut builder = Response::builder()
                        .status(200)
                        .header("content-type", "application/grpc");
                    // Echo the request encoding back so the response frames are
                    // self-consistent with what the client sent.
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

/// Collected audit records, newest last. Each POSTed batch is a JSON array.
#[derive(Clone, Default)]
struct CollectedRecords(Arc<Mutex<Vec<Value>>>);

impl CollectedRecords {
    fn push_batch(&self, body: &[u8]) {
        if let Ok(Value::Array(batch)) = serde_json::from_slice::<Value>(body)
            && let Ok(mut guard) = self.0.lock()
        {
            guard.extend(batch);
        }
    }

    fn snapshot(&self) -> Vec<Value> {
        self.0.lock().map(|guard| guard.clone()).unwrap_or_default()
    }

    /// Poll until at least `expected` records have arrived, then return them.
    /// Returns whatever arrived if the wait elapses, so callers assert.
    async fn wait_for(&self, expected: usize) -> Vec<Value> {
        for _ in 0..120 {
            let records = self.snapshot();
            if records.len() >= expected {
                return records;
            }
            sleep(Duration::from_millis(100)).await;
        }
        self.snapshot()
    }
}

/// Local HTTP/1.1 collector standing in for the operator's transcript sink.
async fn start_audit_collector() -> (u16, CollectedRecords, tokio::task::JoinHandle<()>) {
    let reservation = reserve_port().await.expect("reserve collector port");
    let port = reservation.port;
    let listener = reservation.into_listener();
    let records = CollectedRecords::default();

    let served = records.clone();
    let handle = tokio::spawn(async move {
        loop {
            let (stream, _addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => break,
            };
            let _ = stream.set_nodelay(true);
            let connection_records = served.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let service = service_fn(move |req: Request<Incoming>| {
                    let request_records = connection_records.clone();
                    async move {
                        let body = req
                            .into_body()
                            .collect()
                            .await
                            .map(|collected| collected.to_bytes())
                            .unwrap_or_default();
                        request_records.push_batch(&body);
                        Ok::<_, hyper::Error>(
                            Response::builder()
                                .status(200)
                                .header("content-type", "application/json")
                                .body(Full::new(Bytes::from_static(b"{\"status\":\"ok\"}")))
                                .unwrap(),
                        )
                    }
                });
                let _ = Http1ServerBuilder::new()
                    .serve_connection(io, service)
                    .await;
            });
        }
    });

    (port, records, handle)
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
}

impl GrpcCall {
    fn grpc_status(&self) -> &str {
        self.trailers
            .get("grpc-status")
            .or_else(|| self.headers.get("grpc-status"))
            .map(String::as_str)
            .unwrap_or("")
    }
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
    })
}

/// Write a file-mode config with one `ai_transcript_audit` instance whose
/// `grpc` block enrolls `/test.Greeter/SayHello`, plus optional extra plugin
/// entries/configs (used to install a `before_proxy` short-circuit).
fn write_audit_config(
    config_path: &std::path::Path,
    backend_port: u16,
    collector_port: u16,
    extra_proxy_plugins: &str,
    extra_plugin_configs: &str,
) {
    let descriptor = descriptor_path();
    let config = format!(
        r#"
version: "1"
proxies:
  - id: "grpc-audit-proxy"
    listen_path: "/"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: false
    auth_mode: single
    plugins:
      - plugin_config_id: "grpc-audit"
{extra_proxy_plugins}

consumers: []

plugin_configs:
  - id: "grpc-audit"
    plugin_name: "ai_transcript_audit"
    scope: proxy
    proxy_id: "grpc-audit-proxy"
    enabled: true
    config:
      mode: "redacted_body"
      sampling:
        rate: 1.0
      redaction:
        builtins: ["email"]
        hash_redacted_values: false
      sink:
        type: "http"
        endpoint_url: "http://127.0.0.1:{collector_port}/ingest"
        allow_insecure_loopback: true
        batch_size: 1
        flush_interval_ms: 100
      grpc:
        descriptor_path: "{descriptor}"
        methods:
          "/test.Greeter/SayHello":
            request_type: "test.HelloRequest"
            response_type: "test.HelloResponse"
{extra_plugin_configs}
"#
    );
    let mut file = std::fs::File::create(config_path).expect("create config file");
    file.write_all(config.as_bytes()).expect("write config");
}

/// A 100%-abort `fault_injection` instance. Its priority (2940) is after
/// `ai_transcript_audit` (2740), so it is a genuine `before_proxy`
/// short-circuit for an already-staged audit candidate: no backend dispatch,
/// and therefore no final request-body hook.
const ABORT_PROXY_PLUGIN: &str = r#"      - plugin_config_id: "grpc-abort""#;
const ABORT_PLUGIN_CONFIG: &str = r#"  - id: "grpc-abort"
    plugin_name: "fault_injection"
    scope: proxy
    proxy_id: "grpc-audit-proxy"
    enabled: true
    config:
      abort:
        status_code: 503
        percentage: 100.0
"#;

struct Harness {
    gateway: std::process::Child,
    backend: tokio::task::JoinHandle<()>,
    collector: tokio::task::JoinHandle<()>,
    records: CollectedRecords,
    addr: String,
    _temp: TempDir,
}

impl Harness {
    async fn start(extra_proxy_plugins: &str, extra_plugin_configs: &str) -> Self {
        build_gateway().expect("build gateway binary");
        let (backend_port, backend) = start_grpc_echo_backend().await;
        let (collector_port, records, collector) = start_audit_collector().await;
        let temp = TempDir::new().expect("temp dir");
        let config_path = temp.path().join("config.yaml");
        write_audit_config(
            &config_path,
            backend_port,
            collector_port,
            extra_proxy_plugins,
            extra_plugin_configs,
        );
        let (gateway, port, _admin) =
            start_gateway_with_retry(config_path.to_str().expect("utf-8 path")).await;
        Self {
            gateway,
            backend,
            collector,
            records,
            addr: format!("127.0.0.1:{}", port),
            _temp: temp,
        }
    }

    async fn plain() -> Self {
        Self::start("", "").await
    }

    fn shutdown(mut self) {
        let _ = self.gateway.kill();
        let _ = self.gateway.wait();
        self.backend.abort();
        self.collector.abort();
    }
}

/// The single record's decoded request excerpt. Fails loudly rather than
/// degrading to an empty string, so no assertion below can pass vacuously.
fn request_excerpt(record: &Value) -> String {
    assert_eq!(
        record
            .get("request_body_omitted_reason")
            .and_then(Value::as_str),
        None,
        "the request excerpt must not be omitted: {record}"
    );
    let excerpt = record
        .get("request_body")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("record carries no request_body excerpt: {record}"));
    assert!(
        !excerpt.is_empty(),
        "record carries an empty request_body excerpt: {record}"
    );
    excerpt.to_string()
}

// ============================================================================
// Tests
// ============================================================================

/// Live unary path: one framed request through the real native-gRPC dispatch
/// must produce exactly one audit record whose excerpt is a real decoded
/// protobuf projection naming the enrolled method.
#[tokio::test]
#[ignore]
async fn grpc_audit_captures_live_unary_request_and_response() {
    let harness = Harness::plain().await;
    let body = grpc_frame(&encode_hello_request("live-unary-subject", 0));
    let call = send_grpc_request(&harness.addr, "/test.Greeter/SayHello", &body, &[])
        .await
        .expect("gRPC call");
    assert_eq!(call.status, 200);
    assert_eq!(
        call.grpc_status(),
        "0",
        "unary call must succeed end to end"
    );

    let records = harness.records.wait_for(1).await;
    assert_eq!(
        records.len(),
        1,
        "one enrolled unary call must export exactly one audit record: {records:?}"
    );
    let excerpt = request_excerpt(&records[0]);
    assert!(
        excerpt.contains("/test.Greeter/SayHello"),
        "the excerpt must name the normalized enrolled method: {excerpt}"
    );
    assert!(
        excerpt.contains("live-unary-subject"),
        "the excerpt must carry the decoded protobuf string field: {excerpt}"
    );
    assert!(
        records[0]
            .get("request_hash")
            .and_then(Value::as_str)
            .is_some_and(|hash| !hash.is_empty()),
        "a captured request must carry its keyed body hash: {}",
        records[0]
    );
    // The echo backend returns the request frame, so the response side must
    // decode as the enrolled response type against the same descriptor.
    assert_eq!(
        records[0]
            .get("response_body_omitted_reason")
            .and_then(Value::as_str),
        None,
        "the response excerpt must not be omitted: {}",
        records[0]
    );
    assert!(
        records[0]
            .get("response_body")
            .and_then(Value::as_str)
            .is_some_and(|body| body.contains("live-unary-subject")),
        "the response excerpt must carry the decoded echoed field: {}",
        records[0]
    );
    harness.shutdown();
}

/// Live multi-message (streaming-framed) path: every frame of one enrolled
/// request body must appear in the excerpt under its own message index, not
/// just the first.
#[tokio::test]
#[ignore]
async fn grpc_audit_captures_every_frame_of_a_live_multi_message_request() {
    let harness = Harness::plain().await;
    let mut body = grpc_frame(&encode_hello_request("stream-frame-alpha", 0));
    body.extend_from_slice(&grpc_frame(&encode_hello_request("stream-frame-beta", 0)));
    body.extend_from_slice(&grpc_frame(&encode_hello_request("stream-frame-gamma", 0)));

    let call = send_grpc_request(&harness.addr, "/test.Greeter/SayHello", &body, &[])
        .await
        .expect("gRPC call");
    assert_eq!(call.status, 200);
    assert_eq!(call.grpc_status(), "0", "streamed frames must succeed");

    let records = harness.records.wait_for(1).await;
    assert_eq!(records.len(), 1, "expected one audit record: {records:?}");
    let excerpt = request_excerpt(&records[0]);
    for subject in [
        "stream-frame-alpha",
        "stream-frame-beta",
        "stream-frame-gamma",
    ] {
        assert!(
            excerpt.contains(subject),
            "every framed message must be captured, missing {subject}: {excerpt}"
        );
    }
    assert!(
        excerpt.contains("\"index\":2"),
        "each frame must export under its own message index: {excerpt}"
    );
    harness.shutdown();
}

/// Live redaction: a PII value inside a decoded protobuf string must be
/// replaced in the exported excerpt while the surrounding capture stays real.
#[tokio::test]
#[ignore]
async fn grpc_audit_redacts_pii_inside_a_live_decoded_protobuf_string() {
    let harness = Harness::plain().await;
    let body = grpc_frame(&encode_hello_request("escalate for ops@example.com now", 0));
    let call = send_grpc_request(&harness.addr, "/test.Greeter/SayHello", &body, &[])
        .await
        .expect("gRPC call");
    assert_eq!(call.grpc_status(), "0");

    let records = harness.records.wait_for(1).await;
    assert_eq!(records.len(), 1, "expected one audit record: {records:?}");
    let excerpt = request_excerpt(&records[0]);
    assert!(
        !excerpt.contains("ops@example.com"),
        "the live excerpt leaked an email: {excerpt}"
    );
    // Not merely "the secret is absent": the surrounding decoded text must
    // still be there, so the redaction is proven to be surgical rather than a
    // dropped capture.
    assert!(
        excerpt.contains("escalate for") && excerpt.contains("now"),
        "redaction must keep the rest of the decoded string: {excerpt}"
    );
    harness.shutdown();
}

/// Enrollment is the gate: an unenrolled method travelling the same live
/// native-gRPC path must be forwarded untouched and export no record at all.
#[tokio::test]
#[ignore]
async fn grpc_audit_never_captures_an_unenrolled_live_method() {
    let harness = Harness::plain().await;
    let body = grpc_frame(&encode_hello_request("unenrolled-subject", 0));
    let call = send_grpc_request(&harness.addr, "/test.Greeter/Unenrolled", &body, &[])
        .await
        .expect("gRPC call");
    assert_eq!(call.status, 200);
    assert_eq!(call.grpc_status(), "0", "unenrolled call must pass through");

    // Give the batching sink well past its 100 ms flush interval to prove the
    // absence is real rather than a race.
    sleep(Duration::from_secs(2)).await;
    let records = harness.records.snapshot();
    assert!(
        records.is_empty(),
        "an unenrolled method must not be captured: {records:?}"
    );
    harness.shutdown();
}

/// Live gzip framing: a compressed enrolled request must be inflated within
/// the configured bounds and exported as a real decoded excerpt.
#[tokio::test]
#[ignore]
async fn grpc_audit_decodes_a_live_gzip_framed_request() {
    let harness = Harness::plain().await;
    let body = gzip_grpc_frame(&encode_hello_request("gzip-framed-subject", 0));
    let call = send_grpc_request(
        &harness.addr,
        "/test.Greeter/SayHello",
        &body,
        &[("grpc-encoding", "gzip")],
    )
    .await
    .expect("gRPC call");
    assert_eq!(call.grpc_status(), "0");

    let records = harness.records.wait_for(1).await;
    assert_eq!(records.len(), 1, "expected one audit record: {records:?}");
    let excerpt = request_excerpt(&records[0]);
    assert!(
        excerpt.contains("gzip-framed-subject"),
        "a gzip-framed request must export its inflated decoded excerpt: {excerpt}"
    );
    harness.shutdown();
}

/// Binary-safe short-circuit, end to end.
///
/// The request body is deliberately NOT valid UTF-8 (a negative `int32` field),
/// so the UTF-8-only body view the plugin used to depend on does not exist, and
/// a 100%-abort `fault_injection` instance at priority 2940 terminates the
/// request in `before_proxy` — after `ai_transcript_audit` (2740) staged it and
/// before any backend dispatch or final request-body hook. The audit record
/// must still ship, with a real decoded excerpt.
#[tokio::test]
#[ignore]
async fn grpc_audit_captures_a_non_utf8_request_short_circuited_in_before_proxy() {
    let harness = Harness::start(ABORT_PROXY_PLUGIN, ABORT_PLUGIN_CONFIG).await;
    let payload = encode_hello_request("binary-safe-subject", -1);
    assert!(
        std::str::from_utf8(&payload).is_err(),
        "the fixture must be non-UTF-8 for this test to mean anything"
    );
    let body = grpc_frame(&payload);

    let call = send_grpc_request(&harness.addr, "/test.Greeter/SayHello", &body, &[])
        .await
        .expect("gRPC call");
    assert_ne!(
        call.grpc_status(),
        "0",
        "the injected abort must terminate the call before the backend: \
         headers={:?} trailers={:?}",
        call.headers,
        call.trailers
    );

    let records = harness.records.wait_for(1).await;
    assert_eq!(
        records.len(),
        1,
        "a short-circuited enrolled request must still be audited: {records:?}"
    );
    let excerpt = request_excerpt(&records[0]);
    assert!(
        excerpt.contains("/test.Greeter/SayHello"),
        "the excerpt must name the enrolled method: {excerpt}"
    );
    assert!(
        excerpt.contains("binary-safe-subject"),
        "a non-UTF-8 protobuf request must still export its decoded excerpt: {excerpt}"
    );
    harness.shutdown();
}
