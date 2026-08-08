//! Live coverage for Ferrum's in-process SPIFFE Workload API server over a real
//! Unix domain socket (issue #3617).
//!
//! These tests exercise the *runtime* half that unit tests cannot: an actual
//! bind, an actual gRPC dial, and the socket lifecycle. Concretely they pin
//!
//! - **server startup** — the socket exists, carries the configured mode, and
//!   answers RPCs;
//! - **mint / bundle / validate over the wire** — `FetchJWTSVID` mints for the
//!   attested identity, `FetchJWTBundles` streams a JWKS for the local trust
//!   domain, and `ValidateJWTSVID` accepts that token round-trip;
//! - **rotation publication** — driving the authority's rotation and bumping the
//!   rotation signal republishes a *changed* JWKS on an already-open stream;
//! - **cancellation** — dropping a bundle stream lets the server-side rotation
//!   task exit instead of parking forever;
//! - **restart continuity** — a token minted by one server instance still
//!   validates against a *new* instance built from the same configured signing
//!   material;
//! - **shutdown cleanup** — the socket artifact Ferrum created is unlinked, and
//!   a foreign artifact at the same path is refused rather than clobbered.
//!
//! Everything runs on the ordinary hosted CI runner: a Unix socket in a
//! per-test temp directory, no root, no network.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use ferrum_edge::identity::attestation::{AttestError, Attestor, PeerInfo, WorkloadIdentity};
use ferrum_edge::identity::ca::{CertificateAuthority, bootstrap, internal};
use ferrum_edge::identity::jwt_svid::{JwtSvidSigner, MAX_JWT_SVID_TTL_SECS};
use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain};
use ferrum_edge::identity::workload_api::WorkloadApiService;
use ferrum_edge::identity::workload_api::proto::spiffe_workload_api_client::SpiffeWorkloadApiClient;
use ferrum_edge::identity::workload_api::proto::{
    JwtBundlesRequest, JwtsvidRequest, ValidateJwtsvidRequest,
};
use ferrum_edge::identity::workload_api::{WorkloadApiSocketConfig, serve_workload_api};
use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;
use tokio_stream::StreamExt;
use tonic::Request;
use tonic::metadata::AsciiMetadataValue;
use tonic::transport::{Channel, Endpoint};
use tower::service_fn;

const TRUST_DOMAIN: &str = "workload-api.test";
const SOCKET_MODE: u32 = 0o660;

fn trust_domain() -> TrustDomain {
    TrustDomain::new(TRUST_DOMAIN.to_string()).expect("test trust domain is valid")
}

fn workload_id() -> SpiffeId {
    SpiffeId::from_parts(&trust_domain(), "ns/test/sa/app").expect("test SPIFFE ID is valid")
}

/// Attestor standing in for a peer-credential rule: it authorizes exactly one
/// identity, which is the property the mint path depends on (the subject is
/// never caller-selected).
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

/// A fresh ES256 (P-256) PKCS#8 PEM — the shape
/// `FERRUM_MESH_JWT_SIGNING_KEY_PEM` accepts.
fn signing_key_pem() -> String {
    rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .expect("P-256 key generated")
        .serialize_pem()
}

/// Build an `internal` CA with a *configured* (stable) JWT signing key.
///
/// The X.509 root is bootstrapped per call — it plays no part in the JWT
/// assertions, which is itself the point: JWT signing material is separate from
/// the certificate root, so a fresh root does not disturb JWT continuity.
fn internal_ca_with_jwt_key(jwt_key_pem: &str) -> Arc<internal::InternalCa> {
    // `bootstrap_dev_root` is double-gated on these two reads. This process is a
    // test binary, never a serving gateway.
    //
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
            jwt_signing_key_pem: Some(zeroize::Zeroizing::new(jwt_key_pem.to_string())),
            jwt_retired_key_pems: Vec::new(),
            // Rotation is driven explicitly in these tests; the scheduled cadence
            // is covered by unit tests.
            jwt_key_lifetime_secs: 0,
            allow_ephemeral_jwt_key: false,
        })
        .expect("internal CA builds"),
    )
}

/// A unique socket path under the system temp dir.
///
/// Deliberately short: `sockaddr_un.sun_path` is ~104 bytes, and a long
/// per-test path is the classic reason a UDS test fails with a bare `EINVAL`.
fn socket_path(label: &str) -> PathBuf {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock is after the epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("fe-wl-{label}-{}.sock", unique % 1_000_000_000))
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
    req.metadata_mut()
        .insert("workload.spiffe.io", AsciiMetadataValue::from_static("true"));
    req
}

struct Harness {
    listener: ferrum_edge::identity::workload_api::WorkloadApiListener,
    path: PathBuf,
    /// Held as the CONCRETE internal CA so a test can drive its JWT authority
    /// directly — that is the runtime authority the server reads bundles from, so
    /// rotating it here is the same event the mesh rotation loop produces.
    ca: Arc<internal::InternalCa>,
    rotation_signal: Arc<tokio::sync::watch::Sender<u64>>,
}

impl Harness {
    async fn start(label: &str, jwt_key_pem: &str) -> Self {
        let path = socket_path(label);
        let ca = internal_ca_with_jwt_key(jwt_key_pem);
        let rotation_signal = Arc::new(tokio::sync::watch::channel(0u64).0);
        let service = WorkloadApiService::with_rotation_signal(
            vec![Arc::new(FixedAttestor) as Arc<dyn Attestor>],
            Arc::clone(&ca) as Arc<dyn CertificateAuthority>,
            trust_domain(),
            600,
            Arc::clone(&rotation_signal),
        )
        .with_jwt_svid_ttl_secs(300);
        let socket = WorkloadApiSocketConfig::from_parts(path.clone(), "0660")
            .expect("socket config is well formed");
        let listener = serve_workload_api(service, socket)
            .await
            .expect("Workload API listener binds");
        Self {
            listener,
            path,
            ca,
            rotation_signal,
        }
    }

    async fn shutdown(self) -> PathBuf {
        let path = self.path.clone();
        self.listener.shutdown().await;
        path
    }
}

#[tokio::test]
async fn workload_api_server_starts_and_serves_mint_bundle_validate() {
    let harness = Harness::start("mbv", &signing_key_pem()).await;

    // Startup: the socket exists as a socket with the configured mode.
    let metadata = std::fs::symlink_metadata(&harness.path).expect("socket exists after bind");
    {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        assert!(metadata.file_type().is_socket(), "bound path is a socket");
        assert_eq!(
            metadata.mode() & 0o777,
            SOCKET_MODE,
            "the socket must carry the configured mode, not the process umask"
        );
    }

    let mut client = connect(&harness.path).await;

    // Mint: the subject is the attested identity.
    let minted = client
        .fetch_jwtsvid(workload_request(JwtsvidRequest {
            audience: vec!["spiffe://audience.test/api".to_string()],
            spiffe_id: String::new(),
        }))
        .await
        .expect("FetchJWTSVID succeeds")
        .into_inner();
    assert_eq!(minted.svids.len(), 1);
    assert_eq!(minted.svids[0].spiffe_id, workload_id().as_str());
    let token = minted.svids[0].svid.clone();
    assert!(!token.is_empty(), "a JWT-SVID was returned");

    // Bundles: a JWKS for the local trust domain, never an empty map.
    let mut bundles = client
        .fetch_jwt_bundles(workload_request(JwtBundlesRequest {}))
        .await
        .expect("FetchJWTBundles succeeds")
        .into_inner();
    let first = tokio::time::timeout(std::time::Duration::from_secs(5), bundles.next())
        .await
        .expect("bundle stream produced a frame")
        .expect("bundle stream did not end")
        .expect("bundle frame is not an error");
    let jwks = first
        .bundles
        .get(TRUST_DOMAIN)
        .expect("the local trust domain is always present");
    assert!(
        !jwks.is_empty(),
        "an empty JWKS is not a conformant 'no authorities' signal"
    );

    // Validate: the same token round-trips.
    let validated = client
        .validate_jwtsvid(workload_request(ValidateJwtsvidRequest {
            audience: "spiffe://audience.test/api".to_string(),
            svid: token.clone(),
        }))
        .await
        .expect("ValidateJWTSVID succeeds")
        .into_inner();
    assert_eq!(validated.spiffe_id, workload_id().as_str());

    // A different audience must not validate — the audience binding is real.
    let wrong_audience = client
        .validate_jwtsvid(workload_request(ValidateJwtsvidRequest {
            audience: "spiffe://other.test/api".to_string(),
            svid: token,
        }))
        .await
        .expect_err("a token for another audience must be refused");
    assert_eq!(wrong_audience.code(), tonic::Code::InvalidArgument);

    harness.shutdown().await;
}

#[tokio::test]
async fn a_requested_spiffe_id_the_workload_is_not_entitled_to_is_denied() {
    let harness = Harness::start("deny", &signing_key_pem()).await;
    let mut client = connect(&harness.path).await;

    let denied = client
        .fetch_jwtsvid(workload_request(JwtsvidRequest {
            audience: vec!["spiffe://audience.test/api".to_string()],
            spiffe_id: format!("spiffe://{TRUST_DOMAIN}/ns/other/sa/victim"),
        }))
        .await
        .expect_err("an unentitled subject must be refused");
    assert_eq!(denied.code(), tonic::Code::PermissionDenied);

    harness.shutdown().await;
}

#[tokio::test]
async fn a_jwt_key_rotation_republishes_the_bundle_on_an_open_stream() {
    let harness = Harness::start("rot", &signing_key_pem()).await;
    let mut client = connect(&harness.path).await;

    let mut bundles = client
        .fetch_jwt_bundles(workload_request(JwtBundlesRequest {}))
        .await
        .expect("FetchJWTBundles succeeds")
        .into_inner();
    let initial = tokio::time::timeout(std::time::Duration::from_secs(5), bundles.next())
        .await
        .expect("initial bundle arrives")
        .expect("stream did not end")
        .expect("initial bundle is not an error")
        .bundles
        .get(TRUST_DOMAIN)
        .cloned()
        .expect("local trust domain present");

    // Drive the runtime authority path: rotate the JWT signing key on the CA the
    // server actually reads bundles from, then publish the rotation revision
    // exactly as the mesh rotation loop does. `rotate_if_due` is a deliberate
    // no-op here (the cadence is disabled in this harness), so the rotation is
    // driven outright — the same call the scheduled path makes once due.
    let authority = harness
        .ca
        .jwt_authority()
        .expect("configured signing material yields a JWT authority");
    let generation_before = authority.generation();
    authority.rotate().await.expect("rotation succeeds");
    assert!(
        authority.generation() > generation_before,
        "the authority generation must advance on rotation"
    );
    assert!(
        harness
            .ca
            .jwt_signer()
            .expect("the internal CA owns a JWT signing authority")
            .authorities()
            .len()
            >= 2,
        "the retired key stays published through its verification overlap"
    );

    harness
        .rotation_signal
        .send_modify(|revision| *revision = revision.saturating_add(1));

    let republished = tokio::time::timeout(std::time::Duration::from_secs(5), bundles.next())
        .await
        .expect("a rotation republishes on the open stream")
        .expect("stream did not end")
        .expect("republished bundle is not an error")
        .bundles
        .get(TRUST_DOMAIN)
        .cloned()
        .expect("local trust domain present");
    assert_ne!(
        initial, republished,
        "a JWT key rotation must change the published JWKS"
    );

    harness.shutdown().await;
}

#[tokio::test]
async fn dropping_a_bundle_stream_cancels_the_server_side_producer() {
    let harness = Harness::start("cancel", &signing_key_pem()).await;
    let mut client = connect(&harness.path).await;

    let mut bundles = client
        .fetch_jwt_bundles(workload_request(JwtBundlesRequest {}))
        .await
        .expect("FetchJWTBundles succeeds")
        .into_inner();
    tokio::time::timeout(std::time::Duration::from_secs(5), bundles.next())
        .await
        .expect("initial bundle arrives")
        .expect("stream did not end")
        .expect("initial bundle is not an error");

    // Cancel. The server-side rotation task must observe the closed sink rather
    // than parking on the rotation signal forever.
    drop(bundles);
    // Publish a rotation the cancelled stream must not consume; the server must
    // stay healthy and continue serving new callers.
    harness
        .rotation_signal
        .send_modify(|revision| *revision = revision.saturating_add(1));

    let mut fresh = connect(&harness.path).await;
    let mut fresh_bundles = fresh
        .fetch_jwt_bundles(workload_request(JwtBundlesRequest {}))
        .await
        .expect("the server still serves after a cancelled stream")
        .into_inner();
    tokio::time::timeout(std::time::Duration::from_secs(5), fresh_bundles.next())
        .await
        .expect("a new stream still receives its initial bundle")
        .expect("stream did not end")
        .expect("bundle is not an error");

    harness.shutdown().await;
}

#[tokio::test]
async fn a_token_minted_before_a_server_restart_validates_after_it() {
    // The whole point of configured signing material: the SECOND server is a
    // different process-lifetime authority with the same material, and it must
    // accept the first one's token.
    let jwt_key = signing_key_pem();

    let first = Harness::start("restart-a", &jwt_key).await;
    let mut client = connect(&first.path).await;
    let minted = client
        .fetch_jwtsvid(workload_request(JwtsvidRequest {
            audience: vec!["spiffe://audience.test/api".to_string()],
            spiffe_id: String::new(),
        }))
        .await
        .expect("FetchJWTSVID succeeds")
        .into_inner();
    let token = minted.svids[0].svid.clone();
    drop(client);
    let old_path = first.shutdown().await;
    assert!(
        !old_path.exists(),
        "shutdown must unlink the socket it created"
    );

    let second = Harness::start("restart-b", &jwt_key).await;
    let mut client = connect(&second.path).await;
    let validated = client
        .validate_jwtsvid(workload_request(ValidateJwtsvidRequest {
            audience: "spiffe://audience.test/api".to_string(),
            svid: token,
        }))
        .await
        .expect("a pre-restart token validates against the restarted server")
        .into_inner();
    assert_eq!(validated.spiffe_id, workload_id().as_str());

    // The advertised JWT-SVID ceiling is what makes that guarantee bounded rather
    // than open-ended; assert the constant the docs quote.
    assert_eq!(MAX_JWT_SVID_TTL_SECS, 3600);

    second.shutdown().await;
}

#[tokio::test]
async fn shutdown_removes_only_the_socket_ferrum_created() {
    let harness = Harness::start("cleanup", &signing_key_pem()).await;
    let path = harness.path.clone();
    assert!(path.exists(), "the socket exists while serving");
    harness.shutdown().await;
    assert!(
        !path.exists(),
        "the socket artifact must be unlinked on shutdown"
    );

    // A NON-socket artifact at the same path is refused, not clobbered: the
    // cleanup path only ever removes an owned socket.
    std::fs::write(&path, b"operator data").expect("write a decoy regular file");
    let ca = internal_ca_with_jwt_key(&signing_key_pem());
    let service = WorkloadApiService::new(
        vec![Arc::new(FixedAttestor) as Arc<dyn Attestor>],
        ca as Arc<dyn CertificateAuthority>,
        trust_domain(),
        600,
    );
    let socket = WorkloadApiSocketConfig::from_parts(path.clone(), "0660")
        .expect("socket config is well formed");
    let refused = serve_workload_api(service, socket)
        .await
        .expect_err("a regular file at the socket path must be refused");
    assert!(
        refused.to_string().contains("not a socket"),
        "unexpected refusal reason: {refused}"
    );
    assert_eq!(
        std::fs::read(&path).expect("the decoy file survives"),
        b"operator data",
        "a foreign artifact must never be deleted"
    );
    std::fs::remove_file(&path).expect("test cleanup");
}
