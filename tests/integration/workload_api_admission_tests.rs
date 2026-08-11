//! Live transport-admission coverage for the SPIFFE Workload API listener
//! (issue #3758).
//!
//! The unit suite (`tests/unit/identity/workload_api_admission_tests.rs`) pins
//! the *decision* half — ceilings, refusal of `0`, per-UID fair share across two
//! different UIDs, and the closed reason-label set — because a single-uid test
//! process cannot reach the second-UID case through real sockets. These tests
//! pin the half that only real sockets can prove:
//!
//! - the total ceiling admits exactly `N` and sheds `N + 1` **without allocating
//!   a gRPC connection** — the shed peer sees an immediate EOF, not a session;
//! - the per-UID quota binds for this process's own UID while the global pool
//!   still has room, so the quota is genuinely per principal;
//! - `SETTINGS_MAX_CONCURRENT_STREAMS` is actually advertised on the wire at the
//!   configured value, read straight off a raw HTTP/2 handshake;
//! - the service-wide RPC ceiling **sheds** with `RESOURCE_EXHAUSTED` rather
//!   than queueing, and releases exactly when the streaming RPC that held the
//!   permit ends;
//! - permits come back on every close path a test can drive: the watchdog's
//!   initial-connection deadline, a client disconnect, and shutdown;
//! - shutdown completes inside its bounded deadline while clients hold an idle
//!   socket, a half-finished HTTP/2 session, and a long-lived Workload API
//!   stream — the shape that hangs a purely graceful drain forever;
//! - normal X.509-SVID rotation, JWT-SVID mint/validate, bundle streaming, peer
//!   attestation, and socket-inode cleanup all still work under tight limits;
//! - the exported metric families stay fixed-cardinality.
//!
//! Everything runs on the ordinary hosted Linux CI runner: Unix sockets in a
//! per-test temp directory, no root, no network. Nothing here sleeps for a fixed
//! duration where a bounded poll would do, so the flood assertions are
//! deterministic rather than timing-lucky.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use ferrum_edge::identity::attestation::{AttestError, Attestor, PeerInfo, WorkloadIdentity};
use ferrum_edge::identity::ca::{CertificateAuthority, bootstrap, internal};
use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain};
use ferrum_edge::identity::workload_api::proto::spiffe_workload_api_client::SpiffeWorkloadApiClient;
use ferrum_edge::identity::workload_api::proto::{
    JwtsvidRequest, ValidateJwtsvidRequest, X509BundlesRequest, X509svidRequest,
};
use ferrum_edge::identity::workload_api::{
    WorkloadApiAdmissionConfig, WorkloadApiListener, WorkloadApiService, WorkloadApiSocketConfig,
    close_reason, reject_reason, serve_workload_api_with_admission,
};
use ferrum_edge::plugins::mesh::prometheus_helpers::render_mesh_observability_metrics;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio_stream::StreamExt;
use tonic::Request;
use tonic::metadata::AsciiMetadataValue;
use tonic::transport::{Channel, Endpoint};
use tower::service_fn;

const TRUST_DOMAIN: &str = "workload-admission.test";

/// Long enough that no test's held connection is closed by a lifetime deadline
/// unless that is what the test is about.
const GENEROUS_INITIAL_SECS: u64 = 60;
const GENEROUS_IDLE_SECS: u64 = 120;

fn trust_domain() -> TrustDomain {
    TrustDomain::new(TRUST_DOMAIN.to_string()).expect("test trust domain is valid")
}

fn workload_id() -> SpiffeId {
    SpiffeId::from_parts(&trust_domain(), "ns/test/sa/app").expect("test SPIFFE ID is valid")
}

/// Stands in for a peer-credential rule: it authorizes exactly one identity, so
/// the subject is never caller-selected. Retained under the limits so the
/// attestation half of the surface is exercised, not bypassed.
struct FixedAttestor;

#[async_trait]
impl Attestor for FixedAttestor {
    fn kind(&self) -> &'static str {
        "test-fixed"
    }

    async fn attest(&self, _peer: &PeerInfo) -> Result<WorkloadIdentity, AttestError> {
        Ok(WorkloadIdentity {
            spiffe_id: workload_id(),
            selectors: Default::default(),
            attestor_kind: "test-fixed".to_string(),
        })
    }
}

/// A dev-root-backed internal CA with an ephemeral JWT authority.
///
/// Ephemeral is correct here: none of these tests depends on JWT continuity
/// across a restart, and the dev posture keeps the fixture free of configured
/// key material.
fn internal_ca() -> Arc<internal::InternalCa> {
    // SAFETY: set before any Workload API server is constructed in this test
    // binary, and only ever to these values, so no concurrently running test
    // observes a different value for them.
    unsafe {
        std::env::set_var("FERRUM_MESH_PRODUCTION_MODE", "false");
        std::env::set_var("FERRUM_MESH_CA_BOOTSTRAP_DEV", "true");
    }
    let root = bootstrap::bootstrap_dev_root(bootstrap::BootstrapConfig::new(trust_domain()))
        .expect("dev root bootstraps");
    Arc::new(
        internal::InternalCa::new(internal::InternalCaConfig {
            root_cert_pem: root.root_cert_pem,
            root_key_pem: root.root_key_pem,
            trust_domain: root.trust_domain,
            bundle_refresh_hint_secs: None,
            default_svid_ttl_secs: 600,
            max_svid_ttl_secs: 3600,
            jwt_signing_key_pem: None,
            jwt_retired_key_pems: Vec::new(),
            jwt_key_lifetime_secs: 0,
            allow_ephemeral_jwt_key: true,
        })
        .expect("internal CA builds"),
    )
}

/// A unique socket path under the system temp dir.
///
/// Deliberately short: `sockaddr_un.sun_path` is ~104 bytes, and a long per-test
/// path is the classic reason a UDS test fails with a bare `EINVAL`.
fn socket_path(label: &str) -> PathBuf {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock is after the epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("fe-wa-{label}-{}.sock", unique % 1_000_000_000))
}

/// Limits built from the shipped defaults, so a test only states the bound it is
/// actually about and every other bound stays at its production value.
fn limits() -> WorkloadApiAdmissionConfig {
    WorkloadApiAdmissionConfig {
        initial_connection_timeout: Duration::from_secs(GENEROUS_INITIAL_SECS),
        idle_timeout: Duration::from_secs(GENEROUS_IDLE_SECS),
        ..WorkloadApiAdmissionConfig::default()
    }
}

struct Harness {
    listener: WorkloadApiListener,
    path: PathBuf,
    rotation_signal: Arc<tokio::sync::watch::Sender<u64>>,
}

impl Harness {
    async fn start(label: &str, admission: WorkloadApiAdmissionConfig) -> Self {
        admission
            .validate()
            .expect("every fixture configuration must itself be acceptable configuration");
        let path = socket_path(label);
        let ca = internal_ca();
        let rotation_signal = Arc::new(tokio::sync::watch::channel(0u64).0);
        let service = WorkloadApiService::with_rotation_signal(
            vec![Arc::new(FixedAttestor) as Arc<dyn Attestor>],
            ca as Arc<dyn CertificateAuthority>,
            trust_domain(),
            600,
            Arc::clone(&rotation_signal),
        )
        .with_jwt_svid_ttl_secs(300);
        let socket = WorkloadApiSocketConfig::from_parts(path.clone(), "0660")
            .expect("socket config is well formed");
        let listener = serve_workload_api_with_admission(service, socket, admission)
            .await
            .expect("Workload API listener binds");
        Self {
            listener,
            path,
            rotation_signal,
        }
    }

    /// Shut down and return how long that took, so a caller can assert the
    /// bounded-drain contract rather than merely that it eventually finished.
    async fn shutdown_within(self, budget: Duration) -> Duration {
        let path = self.path.clone();
        let started = Instant::now();
        tokio::time::timeout(budget, self.listener.shutdown())
            .await
            .expect("Workload API shutdown must complete inside its bounded deadline");
        let elapsed = started.elapsed();
        assert!(
            !path.exists(),
            "the socket artifact Ferrum created must still be unlinked on the bounded path"
        );
        elapsed
    }
}

/// Dial a Unix socket with the same connector shape the production client uses.
async fn connect(path: &Path) -> SpiffeWorkloadApiClient<Channel> {
    let path = path.to_path_buf();
    let channel = Endpoint::try_from("http://[::1]:0")
        .expect("dummy endpoint parses")
        .connect_with_connector(service_fn(move |_: tonic::transport::Uri| {
            let path = path.clone();
            async move {
                let stream = UnixStream::connect(path).await?;
                Ok::<_, std::io::Error>(TokioIo::new(stream))
            }
        }))
        .await
        .expect("Workload API socket accepts a connection");
    SpiffeWorkloadApiClient::new(channel)
}

/// Every Workload API RPC must carry the mandatory metadata header.
fn workload_request<T>(payload: T) -> Request<T> {
    let mut req = Request::new(payload);
    req.metadata_mut().insert(
        "workload.spiffe.io",
        AsciiMetadataValue::from_static("true"),
    );
    req
}

/// The two `reason`-labelled admission metric families.
const REJECTED_FAMILY: &str = "ferrum_mesh_workload_api_connections_rejected_total";
const CLOSED_FAMILY: &str = "ferrum_mesh_workload_api_connections_closed_total";

/// The HTTP/2 client connection preface followed by an empty SETTINGS frame.
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00";

/// Connect a raw socket and confirm the listener handed it to the gRPC stack.
///
/// The discriminator is exact rather than timing-based: an HTTP/2 server flushes
/// its own SETTINGS frame before it reads the client preface, so an *admitted*
/// connection always yields bytes and a *shed* one always yields EOF. Neither
/// outcome depends on how fast the runner is.
async fn connect_admitted(path: &Path) -> UnixStream {
    let mut stream = UnixStream::connect(path)
        .await
        .expect("the socket accepts a connection");
    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut byte))
        .await
        .expect("an admitted connection reaches the HTTP/2 server")
        .expect("an admitted connection is not torn down");
    assert!(
        read > 0,
        "an admitted connection must receive server SETTINGS; EOF means it was shed"
    );
    stream
}

/// Connect a raw socket and require the listener to have shed it before any
/// gRPC session existed.
async fn connect_expecting_shed(path: &Path) {
    let mut stream = UnixStream::connect(path)
        .await
        .expect("the listener still accepts, then sheds; it does not stop listening");
    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut byte))
        .await
        .expect("an over-limit connection must be shed promptly, never queued")
        .expect("a shed connection is closed cleanly, not with an error");
    assert_eq!(read, 0, "a shed peer observes EOF with no HTTP/2 exchanged");
}

/// Poll until a full RPC succeeds, or fail after `budget`.
///
/// Used where the property under test is that capacity *came back*: the release
/// happens on the server's own schedule (a dropped connection task, a watchdog
/// close), so the assertion is "within a bound", never "on the next attempt".
async fn wait_for_service(path: &Path, budget: Duration) {
    let deadline = Instant::now() + budget;
    let mut last: Option<String> = None;
    while Instant::now() < deadline {
        let mut client = connect(path).await;
        match client
            .fetch_jwtsvid(workload_request(JwtsvidRequest {
                audience: vec!["spiffe://audience.test/api".to_string()],
                spiffe_id: String::new(),
            }))
            .await
        {
            Ok(_) => return,
            Err(status) => last = Some(status.code().to_string()),
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!(
        "capacity was never released within {budget:?}; last RPC outcome: {}",
        last.unwrap_or_else(|| "no attempt completed".to_string())
    );
}

#[tokio::test]
async fn the_total_connection_ceiling_sheds_the_next_connection_before_any_grpc_allocation() {
    const TOTAL: usize = 3;
    let harness = Harness::start(
        "total",
        WorkloadApiAdmissionConfig {
            max_connections: TOTAL,
            max_connections_per_uid: TOTAL,
            ..limits()
        },
    )
    .await;

    // Every connection up to the ceiling is admitted and stays open.
    let mut held = Vec::new();
    for _ in 0..TOTAL {
        held.push(connect_admitted(&harness.path).await);
    }

    // The next one is shed. Accepts are FIFO, so the three above are already
    // charged by the time this one reaches admission.
    connect_expecting_shed(&harness.path).await;
    // Repeatedly, and without the listener degrading: a flood is refused for as
    // long as it lasts rather than knocking the accept loop over.
    for _ in 0..20 {
        connect_expecting_shed(&harness.path).await;
    }

    // Releasing one returns exactly one slot's worth of capacity.
    drop(held.pop());
    wait_for_service(&harness.path, Duration::from_secs(15)).await;

    drop(held);
    harness.shutdown_within(Duration::from_secs(30)).await;
}

#[tokio::test]
async fn a_saturated_peer_uid_is_shed_while_the_global_pool_still_has_room() {
    // The test process has one UID, so this proves the *quota* half live: the
    // global ceiling is four times the per-UID quota and cannot be what refuses
    // the third connection. The fair-share half — a second UID still being
    // served — is a different-UID case a single-uid process cannot produce and
    // is pinned in the unit suite against the same accounting.
    const PER_UID: usize = 2;
    let harness = Harness::start(
        "peruid",
        WorkloadApiAdmissionConfig {
            max_connections: PER_UID * 4,
            max_connections_per_uid: PER_UID,
            ..limits()
        },
    )
    .await;

    let mut held = Vec::new();
    for _ in 0..PER_UID {
        held.push(connect_admitted(&harness.path).await);
    }
    connect_expecting_shed(&harness.path).await;

    drop(held.pop());
    wait_for_service(&harness.path, Duration::from_secs(15)).await;

    drop(held);
    harness.shutdown_within(Duration::from_secs(30)).await;
}

#[tokio::test]
async fn the_configured_stream_ceiling_is_advertised_on_the_wire() {
    // Read off a real HTTP/2 handshake rather than inferred from behaviour: a
    // conforming client obeys SETTINGS, so an unadvertised ceiling would be
    // invisible to every gRPC-level assertion while leaving the server
    // unbounded against a client that does not.
    const STREAMS: u32 = 7;
    let harness = Harness::start(
        "settings",
        WorkloadApiAdmissionConfig {
            max_concurrent_streams: STREAMS,
            ..limits()
        },
    )
    .await;

    let mut stream = UnixStream::connect(&harness.path)
        .await
        .expect("the socket accepts a connection");
    stream
        .write_all(H2_PREFACE)
        .await
        .expect("the client preface is written");

    let settings = read_max_concurrent_streams(&mut stream);
    let advertised = tokio::time::timeout(Duration::from_secs(10), settings)
        .await
        .expect("the server sends its SETTINGS frame promptly");
    assert_eq!(
        advertised,
        Some(STREAMS),
        "SETTINGS_MAX_CONCURRENT_STREAMS must carry the configured ceiling"
    );

    drop(stream);
    harness.shutdown_within(Duration::from_secs(30)).await;
}

/// Read HTTP/2 frames until the peer's SETTINGS frame, and return its
/// `SETTINGS_MAX_CONCURRENT_STREAMS` (identifier `0x3`) if it carries one.
async fn read_max_concurrent_streams(stream: &mut UnixStream) -> Option<u32> {
    loop {
        let mut header = [0u8; 9];
        stream
            .read_exact(&mut header)
            .await
            .expect("the server sends well-formed HTTP/2 frames");
        let length = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
        let frame_type = header[3];
        let flags = header[4];
        let mut payload = vec![0u8; length];
        if length > 0 {
            stream
                .read_exact(&mut payload)
                .await
                .expect("a frame's payload follows its header");
        }
        // Type 0x4 is SETTINGS; the ACK flag marks the peer's answer to ours
        // rather than its own parameters.
        if frame_type == 0x4 && (flags & 0x1) == 0 {
            for entry in payload.chunks_exact(6) {
                if u16::from_be_bytes([entry[0], entry[1]]) == 0x3 {
                    return Some(u32::from_be_bytes([entry[2], entry[3], entry[4], entry[5]]));
                }
            }
            return None;
        }
    }
}

#[tokio::test]
async fn the_service_wide_rpc_ceiling_sheds_rather_than_queueing_and_releases_exactly() {
    let harness = Harness::start(
        "rpccap",
        WorkloadApiAdmissionConfig {
            max_concurrent_rpcs: 1,
            ..limits()
        },
    )
    .await;

    // A streaming RPC holds its permit for the whole stream — the producer task,
    // the rotation subscription, and the pending material all live that long.
    let mut holder = connect(&harness.path).await;
    let mut bundles = holder
        .fetch_x509_bundles(workload_request(X509BundlesRequest {}))
        .await
        .expect("the first RPC is admitted")
        .into_inner();
    let first = tokio::time::timeout(Duration::from_secs(10), bundles.next())
        .await
        .expect("the bundle stream produces a frame")
        .expect("the bundle stream did not end")
        .expect("the bundle frame is not an error");
    assert!(
        !first.bundles.is_empty(),
        "the held RPC must be doing real work, or it is not holding a real permit"
    );

    // The next call is shed immediately. The bound matters as much as the code:
    // a queued identity request served far too late is worse than a refusal the
    // client can retry, and an unbounded backlog is the exhaustion itself.
    let mut second = connect(&harness.path).await;
    let started = Instant::now();
    let shed = tokio::time::timeout(
        Duration::from_secs(5),
        second.fetch_jwtsvid(workload_request(JwtsvidRequest {
            audience: vec!["spiffe://audience.test/api".to_string()],
            spiffe_id: String::new(),
        })),
    )
    .await
    .expect("an over-ceiling RPC must be answered, not parked behind the limit")
    .expect_err("an over-ceiling RPC must be refused");
    assert_eq!(shed.code(), tonic::Code::ResourceExhausted);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the shed must be immediate; anything else is a queue"
    );

    // Ending the streaming RPC releases the permit exactly.
    drop(bundles);
    drop(holder);
    wait_for_service(&harness.path, Duration::from_secs(15)).await;

    harness.shutdown_within(Duration::from_secs(30)).await;
}

#[tokio::test]
async fn a_connection_that_never_speaks_is_closed_on_its_deadline_and_returns_its_permit() {
    // The cheapest flood shape there is, and the one no per-request timeout can
    // see. The global ceiling is 1, so the follow-up RPC can only succeed if the
    // silent connection's permit was actually released.
    let harness = Harness::start(
        "initial",
        WorkloadApiAdmissionConfig {
            max_connections: 1,
            max_connections_per_uid: 1,
            initial_connection_timeout: Duration::from_secs(1),
            idle_timeout: Duration::from_secs(2),
            ..limits()
        },
    )
    .await;

    let mut silent = UnixStream::connect(&harness.path)
        .await
        .expect("the socket accepts a connection");
    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(15), silent.read(&mut byte))
        .await
        .expect("a connection that never sends a byte must be closed on its initial deadline")
        .expect("the close is a clean transport teardown");
    assert_eq!(read, 0, "the peer observes EOF, not a half-open socket");

    wait_for_service(&harness.path, Duration::from_secs(15)).await;
    harness.shutdown_within(Duration::from_secs(30)).await;
}

#[tokio::test]
async fn a_client_disconnect_returns_its_connection_permit() {
    let harness = Harness::start(
        "release",
        WorkloadApiAdmissionConfig {
            max_connections: 1,
            max_connections_per_uid: 1,
            ..limits()
        },
    )
    .await;

    {
        let mut client = connect(&harness.path).await;
        client
            .fetch_x509svid(workload_request(X509svidRequest {}))
            .await
            .expect("the only permitted connection is served normally");
    }

    // The pool was full while that client existed; it can only be served now if
    // the permit followed the connection object rather than any one code path.
    wait_for_service(&harness.path, Duration::from_secs(15)).await;
    harness.shutdown_within(Duration::from_secs(30)).await;
}

#[tokio::test]
async fn shutdown_is_bounded_while_clients_hold_idle_partial_and_long_lived_connections() {
    // All three shapes at once, because each defeats a different half-measure: a
    // purely graceful drain waits forever on the idle socket and the half-open
    // HTTP/2 session, and the long-lived stream is what a Workload API client is
    // *designed* to hold across rotations.
    let grace = Duration::from_secs(1);
    let harness = Harness::start(
        "drain",
        WorkloadApiAdmissionConfig {
            shutdown_grace: grace,
            ..limits()
        },
    )
    .await;

    let _idle = UnixStream::connect(&harness.path)
        .await
        .expect("an idle socket connects");

    let mut partial = UnixStream::connect(&harness.path)
        .await
        .expect("a partial HTTP/2 session connects");
    partial
        .write_all(&H2_PREFACE[..12])
        .await
        .expect("a truncated preface is written");

    let mut streaming = connect(&harness.path).await;
    let _svids = streaming
        .fetch_x509svid(workload_request(X509svidRequest {}))
        .await
        .expect("a long-lived SVID stream is established")
        .into_inner();

    // Generous enough that a real regression is unambiguous, tight enough that
    // an unbounded drain cannot pass: grace + the force-close settle window is
    // 6s, so 25s of budget is failure only if shutdown does not terminate.
    let elapsed = harness.shutdown_within(Duration::from_secs(25)).await;
    assert!(
        elapsed < Duration::from_secs(20),
        "shutdown must be bounded by the drain deadline plus the settle window, took {elapsed:?}"
    );
}

#[tokio::test]
async fn normal_identity_service_is_unchanged_under_tight_limits() {
    // Every limit in force, none of them binding: attestation, X.509-SVID
    // issuance, rotation republication on an open stream, JWT-SVID mint and
    // validate, bundle streaming, and socket cleanup must all behave exactly as
    // they do without the admission boundary.
    let harness = Harness::start(
        "normal",
        WorkloadApiAdmissionConfig {
            max_connections: 4,
            max_connections_per_uid: 4,
            max_concurrent_streams: 8,
            max_concurrent_rpcs: 8,
            shutdown_grace: Duration::from_secs(5),
            ..limits()
        },
    )
    .await;
    let mut client = connect(&harness.path).await;

    // X.509-SVID for the attested identity — never a caller-selected subject.
    let mut svids = client
        .fetch_x509svid(workload_request(X509svidRequest {}))
        .await
        .expect("FetchX509SVID succeeds")
        .into_inner();
    let first = tokio::time::timeout(Duration::from_secs(10), svids.next())
        .await
        .expect("the SVID stream produces a frame")
        .expect("the SVID stream did not end")
        .expect("the SVID frame is not an error");
    assert_eq!(first.svids.len(), 1);
    assert_eq!(first.svids[0].spiffe_id, workload_id().as_str());
    assert!(
        !first.svids[0].x509_svid.is_empty() && !first.svids[0].x509_svid_key.is_empty(),
        "a real leaf and its private key are delivered under the limits"
    );

    // Rotation still republishes on the already-open stream.
    harness
        .rotation_signal
        .send_modify(|revision| *revision += 1);
    let rotated = tokio::time::timeout(Duration::from_secs(10), svids.next())
        .await
        .expect("rotation republishes on the open stream")
        .expect("the SVID stream did not end")
        .expect("the rotated frame is not an error");
    assert_eq!(rotated.svids.len(), 1);

    // JWT mint and round-trip validation.
    let minted = client
        .fetch_jwtsvid(workload_request(JwtsvidRequest {
            audience: vec!["spiffe://audience.test/api".to_string()],
            spiffe_id: String::new(),
        }))
        .await
        .expect("FetchJWTSVID succeeds")
        .into_inner();
    assert_eq!(minted.svids.len(), 1);
    let token = minted.svids[0].svid.clone();
    let validated = client
        .validate_jwtsvid(workload_request(ValidateJwtsvidRequest {
            audience: "spiffe://audience.test/api".to_string(),
            svid: token,
        }))
        .await
        .expect("ValidateJWTSVID succeeds")
        .into_inner();
    assert_eq!(validated.spiffe_id, workload_id().as_str());

    // Bundle streaming.
    let mut bundles = client
        .fetch_x509_bundles(workload_request(X509BundlesRequest {}))
        .await
        .expect("FetchX509Bundles succeeds")
        .into_inner();
    let bundle = tokio::time::timeout(Duration::from_secs(10), bundles.next())
        .await
        .expect("the bundle stream produces a frame")
        .expect("the bundle stream did not end")
        .expect("the bundle frame is not an error");
    assert!(
        bundle.bundles.contains_key(TRUST_DOMAIN),
        "the local trust domain's X.509 bundle is published under the limits"
    );

    // An unentitled subject is still refused: the ceilings did not become a
    // substitute for the entitlement check.
    let denied = client
        .fetch_jwtsvid(workload_request(JwtsvidRequest {
            audience: vec!["spiffe://audience.test/api".to_string()],
            spiffe_id: format!("spiffe://{TRUST_DOMAIN}/ns/other/sa/victim"),
        }))
        .await
        .expect_err("an unentitled subject must still be refused");
    assert_eq!(denied.code(), tonic::Code::PermissionDenied);

    drop(svids);
    drop(bundles);
    drop(client);
    // Socket inode cleanup is asserted inside `shutdown_within`.
    harness.shutdown_within(Duration::from_secs(30)).await;
}

#[tokio::test]
async fn the_exported_admission_metrics_stay_fixed_cardinality() {
    // Drive at least one rejection so the families are actually rendered, then
    // assert every `reason` value present belongs to the closed compile-time
    // set. Nothing peer-controlled — UID, PID, SPIFFE ID, token material — may
    // reach a label: each is both an unbounded cardinality dimension and a
    // disclosure surface.
    let harness = Harness::start(
        "metrics",
        WorkloadApiAdmissionConfig {
            max_connections: 1,
            max_connections_per_uid: 1,
            ..limits()
        },
    )
    .await;
    let _held = connect_admitted(&harness.path).await;
    connect_expecting_shed(&harness.path).await;

    let mut rendered = String::new();
    render_mesh_observability_metrics(&mut rendered);

    let allowed_reject = [
        reject_reason::PEER_CREDENTIALS,
        reject_reason::MAX_CONNECTIONS,
        reject_reason::MAX_CONNECTIONS_PER_UID,
        reject_reason::SHUTTING_DOWN,
    ];
    let allowed_close = [
        close_reason::INITIAL_TIMEOUT,
        close_reason::IDLE_TIMEOUT,
        close_reason::SHUTDOWN_DEADLINE,
    ];

    let mut saw_rejection_series = false;
    for line in rendered.lines() {
        if line.starts_with('#') {
            continue;
        }
        if let Some(reason) = metric_reason(line, REJECTED_FAMILY) {
            saw_rejection_series = true;
            assert!(
                allowed_reject.contains(&reason.as_str()),
                "an unexpected rejection reason label appeared: {reason}"
            );
        }
        if let Some(reason) = metric_reason(line, CLOSED_FAMILY) {
            assert!(
                allowed_close.contains(&reason.as_str()),
                "an unexpected close reason label appeared: {reason}"
            );
        }
        // The gauges and the RPC-shed counter carry no per-caller dimension at
        // all, so any `reason`/`uid`/`pid` on them would be a regression.
        for family in [
            "ferrum_mesh_workload_api_active_connections",
            "ferrum_mesh_workload_api_active_rpcs",
            "ferrum_mesh_workload_api_rpcs_rejected_total",
        ] {
            if line.starts_with(family) {
                assert!(
                    !line.contains("reason=")
                        && !line.contains("uid=")
                        && !line.contains("pid=")
                        && !line.contains("spiffe"),
                    "{family} must carry no per-caller label: {line}"
                );
            }
        }
    }
    assert!(
        saw_rejection_series,
        "the rejection counter must be exported once a connection has been shed"
    );

    harness.shutdown_within(Duration::from_secs(30)).await;
}

/// The hosted-Linux flood gate.
///
/// This is the "run a flood from an authorized socket-group process" check the
/// issue asks for, in the form a hosted runner can actually make: the test
/// process *is* an authorized socket-group member (it owns the socket), so a
/// sustained connection flood from it is exactly the hostile shape. What it
/// pins is that the flood costs the server nothing that accumulates —
/// descriptors return to their baseline, identity service continues for the
/// peers inside the pool, and shutdown stays bounded afterwards.
///
/// What it deliberately does **not** claim: the "an independent peer UID keeps
/// being served" half needs a second UID, which an unprivileged CI process
/// cannot create. That property is pinned against the same accounting in
/// `tests/unit/identity/workload_api_admission_tests.rs`.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_sustained_connection_flood_leaves_descriptors_and_shutdown_bounded() {
    const TOTAL: usize = 4;
    let harness = Harness::start(
        "flood",
        WorkloadApiAdmissionConfig {
            max_connections: TOTAL,
            max_connections_per_uid: TOTAL,
            shutdown_grace: Duration::from_secs(1),
            ..limits()
        },
    )
    .await;

    let mut held = Vec::new();
    for _ in 0..TOTAL {
        held.push(connect_admitted(&harness.path).await);
    }
    let baseline = open_descriptors();

    for _ in 0..200 {
        connect_expecting_shed(&harness.path).await;
    }

    let after = open_descriptors();
    assert!(
        after <= baseline + 16,
        "a 200-connection flood must not accumulate descriptors: {baseline} -> {after}"
    );

    // Identity service is still available to a peer inside the pool.
    drop(held.pop());
    wait_for_service(&harness.path, Duration::from_secs(15)).await;

    let elapsed = harness.shutdown_within(Duration::from_secs(25)).await;
    assert!(
        elapsed < Duration::from_secs(20),
        "shutdown must stay bounded after a flood, took {elapsed:?}"
    );
    drop(held);
}

/// Descriptors this process currently holds.
#[cfg(target_os = "linux")]
fn open_descriptors() -> usize {
    std::fs::read_dir("/proc/self/fd")
        .map(|entries| entries.count())
        .unwrap_or(0)
}

/// The `reason` label of `line` when it belongs to `family`.
fn metric_reason(line: &str, family: &str) -> Option<String> {
    let rest = line.strip_prefix(family)?.strip_prefix("{reason=\"")?;
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}
