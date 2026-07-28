//! Black-box regression coverage for advisory GHSA-3f2j-wwqw-grmg —
//! "Fleet-wide CP/DP HS256 secret lets a compromised tenant forge namespace
//! authorization".
//!
//! The attacker model is a fully compromised tenant-A node: it holds every
//! credential actually installed in tenant A and may write anything it likes
//! into the token it presents. The invariant under test is that such a node
//! cannot reach tenant B on **any** configuration surface — `ConfigSync`
//! (`Subscribe` and `GetFullConfig`), native `MeshConfigSync.MeshSubscribe`,
//! or xDS ADS — and that the refusal happens before a single byte of tenant-B
//! gateway config, mesh inventory, trust material, or xDS resource is
//! serialized.
//!
//! These tests drive the real gRPC services over a real loopback socket with
//! hand-minted tokens, so they exercise the wire path rather than the
//! resolver in isolation.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use chrono::Utc;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::json;
use tokio::time::timeout;
use tonic::transport::Server;

use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::grpc::auth::MESH_LOCAL_SUBSCRIBE_AUDIENCE;
use ferrum_edge::grpc::cp_server::{CpGrpcServer, CpScope, DpNodeRegistry};
use ferrum_edge::grpc::cp_trust::{
    CpDpTrustBundle, CpDpVerifier, CpGrpcConnectInfo, PeerNamespaceScope,
};
use ferrum_edge::grpc::mesh_registry::MeshNodeRegistry;
use ferrum_edge::grpc::mesh_server::MeshGrpcServer;
use ferrum_edge::identity::TrustDomain;
use ferrum_edge::modes::mesh::config::{MeshConfig, MeshService, TrustBundle, TrustBundleSet};
use ferrum_edge::xds::{LDS_TYPE_URL, XdsAdsServer};

const TEST_ISSUER: &str = "ferrum-edge-cp-dp";

/// The secret actually installed on tenant A's data planes. Under the
/// pre-advisory design this was the *fleet* secret; the whole point of the fix
/// is that holding it now buys tenant A nothing outside tenant A.
const TENANT_A_SECRET: &str = "tenant-a-cp-dp-secret-2026-ferrum-edge";
const TENANT_B_SECRET: &str = "tenant-b-cp-dp-secret-2026-ferrum-edge";

const TENANT_A: &str = "tenant-a";
const TENANT_B: &str = "tenant-b";

// ── Trust bundle fixtures ────────────────────────────────────────────────

/// A two-tenant symmetric trust bundle: each `kid` is bound, by control-plane
/// configuration, to exactly one namespace.
fn two_tenant_bundle() -> Arc<CpDpVerifier> {
    let document = json!({
        "version": 1,
        "keys": [
            { "kid": TENANT_A, "algorithm": "HS256", "secret": TENANT_A_SECRET,
              "namespaces": [TENANT_A] },
            { "kid": TENANT_B, "algorithm": "HS256", "secret": TENANT_B_SECRET,
              "namespaces": [TENANT_B] },
        ]
    })
    .to_string();
    let bundle = CpDpTrustBundle::from_document_str(&document, "test-bundle")
        .expect("two-tenant bundle must load");
    Arc::new(CpDpVerifier::TrustBundle(bundle))
}

/// Mint a token exactly as a compromised node would: arbitrary claims, signed
/// with whatever key that node actually holds, and stamped with whatever `kid`
/// the attacker chooses.
fn mint(
    secret: &str,
    kid: Option<&str>,
    node_id: &str,
    ns: Option<serde_json::Value>,
    audience: Option<&str>,
) -> String {
    let now = Utc::now().timestamp();
    let mut claims = json!({
        "sub": node_id,
        "iat": now,
        "exp": now + 600,
        "iss": TEST_ISSUER,
        "role": "data_plane",
    });
    if let Some(ns) = ns {
        claims["ns"] = ns;
    }
    if let Some(audience) = audience {
        claims["aud"] = json!(audience);
    }
    let mut header = Header::new(Algorithm::HS256);
    header.kid = kid.map(str::to_string);
    encode(&header, &claims, &EncodingKey::from_secret(secret.as_bytes()))
        .expect("test JWT must encode")
}

// ── Config fixtures ──────────────────────────────────────────────────────

fn tenant_marked_config() -> GatewayConfig {
    GatewayConfig {
        version: "1".to_string(),
        loaded_at: Utc::now(),
        known_namespaces: vec![TENANT_A.to_string(), TENANT_B.to_string()],
        mesh: Some(Box::new(MeshConfig {
            services: vec![
                mesh_service("svc-tenant-a-marker", TENANT_A),
                mesh_service("svc-tenant-b-marker", TENANT_B),
            ],
            trust_bundles: Some(test_trust_bundles()),
            ..MeshConfig::default()
        })),
        ..Default::default()
    }
}

fn mesh_service(name: &str, namespace: &str) -> MeshService {
    MeshService {
        name: name.to_string(),
        namespace: namespace.to_string(),
        ports: Vec::new(),
        workloads: Vec::new(),
        protocol_overrides: HashMap::new(),
        cluster_ips: Vec::new(),
    }
}

fn test_trust_bundles() -> TrustBundleSet {
    TrustBundleSet {
        local: TrustBundle {
            trust_domain: TrustDomain::new("cluster.local").expect("valid trust domain"),
            x509_authorities: vec!["AQIDBA==".to_string()],
            jwt_authorities: Vec::new(),
            refresh_hint_seconds: None,
        },
        federated: Vec::new(),
    }
}

fn multi_tenant_scope() -> CpScope {
    CpScope::Set(
        [TENANT_A.to_string(), TENANT_B.to_string()]
            .into_iter()
            .collect(),
    )
}

// ── Server harnesses ─────────────────────────────────────────────────────

async fn start_configsync(
    verifier: Arc<CpDpVerifier>,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let cfg_arc = Arc::new(ArcSwap::new(Arc::new(tenant_marked_config())));
    let (server, _tx) = CpGrpcServer::builder(cfg_arc, TENANT_A_SECRET.to_string())
        .channel_capacity(64)
        .registry(Arc::new(DpNodeRegistry::new()))
        .expected_issuer(TEST_ISSUER.to_string())
        .verifier(verifier)
        .scope(multi_tenant_scope())
        .real_ip_header(None)
        .build();
    let (listener, addr) = bind_loopback().await;
    let handle = tokio::spawn(async move {
        Server::builder()
            .add_service(server.into_service())
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .expect("ConfigSync server failed");
    });
    settle().await;
    (addr, handle)
}

async fn start_mesh(verifier: Arc<CpDpVerifier>) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let cfg_arc = Arc::new(ArcSwap::new(Arc::new(tenant_marked_config())));
    let (server, _tx) = MeshGrpcServer::builder(cfg_arc, TENANT_A_SECRET.to_string())
        .channel_capacity(64)
        .registry(Arc::new(MeshNodeRegistry::new()))
        .expected_issuer(TEST_ISSUER.to_string())
        .verifier(verifier)
        .scope(multi_tenant_scope())
        .build();
    let (listener, addr) = bind_loopback().await;
    let handle = tokio::spawn(async move {
        Server::builder()
            .add_service(server.into_service())
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .expect("mesh gRPC server failed");
    });
    settle().await;
    (addr, handle)
}

async fn start_xds(verifier: Arc<CpDpVerifier>) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let cfg_arc = Arc::new(ArcSwap::new(Arc::new(tenant_marked_config())));
    let (_cp, update_tx) = CpGrpcServer::builder(cfg_arc.clone(), TENANT_A_SECRET.to_string())
        .channel_capacity(64)
        .scope(multi_tenant_scope())
        .build();
    let server = XdsAdsServer::new(
        cfg_arc,
        update_tx,
        TENANT_A_SECRET.to_string(),
        TEST_ISSUER.to_string(),
        TENANT_A.to_string(),
        32,
    )
    .with_verifier(verifier)
    .with_scope(multi_tenant_scope());
    let (listener, addr) = bind_loopback().await;
    let handle = tokio::spawn(async move {
        Server::builder()
            .add_service(server.into_service())
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .expect("xDS server failed");
    });
    settle().await;
    (addr, handle)
}

async fn bind_loopback() -> (tokio::net::TcpListener, SocketAddr) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    (listener, addr)
}

/// Give the spawned server a moment to start accepting before the client
/// dials, matching the surrounding integration suites.
async fn settle() {
    tokio::time::sleep(Duration::from_millis(50)).await;
}

macro_rules! configsync_client {
    ($addr:expr, $token:expr) => {{
        let token_meta: tonic::metadata::MetadataValue<_> =
            format!("Bearer {}", $token).parse().unwrap();
        let channel = tonic::transport::Channel::from_shared(format!("http://{}", $addr))
            .unwrap()
            .connect()
            .await
            .unwrap();
        ferrum_edge::grpc::proto::config_sync_client::ConfigSyncClient::with_interceptor(
            channel,
            move |mut req: tonic::Request<()>| {
                req.metadata_mut()
                    .insert("authorization", token_meta.clone());
                Ok(req)
            },
        )
    }};
}

macro_rules! mesh_client {
    ($addr:expr, $token:expr) => {{
        let token_meta: tonic::metadata::MetadataValue<_> =
            format!("Bearer {}", $token).parse().unwrap();
        let channel = tonic::transport::Channel::from_shared(format!("http://{}", $addr))
            .unwrap()
            .connect()
            .await
            .unwrap();
        ferrum_edge::grpc::proto::mesh_config_sync_client::MeshConfigSyncClient::with_interceptor(
            channel,
            move |mut req: tonic::Request<()>| {
                req.metadata_mut()
                    .insert("authorization", token_meta.clone());
                Ok(req)
            },
        )
    }};
}

fn subscribe_request(node_id: &str, namespace: &str) -> ferrum_edge::grpc::proto::SubscribeRequest {
    ferrum_edge::grpc::proto::SubscribeRequest {
        node_id: node_id.to_string(),
        ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
        namespace: namespace.to_string(),
        real_ip_header: Some(String::new()),
        supports_heartbeat: true,
    }
}

// ── The core cross-tenant forgery, per surface ───────────────────────────

/// ConfigSync `Subscribe`: tenant A signs an otherwise-valid tenant-B token
/// with the credential it actually holds. The CP must refuse before any
/// snapshot is serialized.
#[tokio::test(flavor = "multi_thread")]
async fn configsync_refuses_tenant_a_credential_signing_a_tenant_b_claim() {
    let (addr, handle) = start_configsync(two_tenant_bundle()).await;

    // Sanity: the same credential works for its OWN tenant, so the refusal
    // below is about the namespace binding and not a broken fixture.
    let own = mint(
        TENANT_A_SECRET,
        Some(TENANT_A),
        "dp-a",
        Some(json!(TENANT_A)),
        None,
    );
    let mut client = configsync_client!(addr, own);
    let mut stream = client
        .subscribe(tonic::Request::new(subscribe_request("dp-a", TENANT_A)))
        .await
        .expect("tenant A must reach its own namespace")
        .into_inner();
    let first = timeout(Duration::from_secs(5), stream.message())
        .await
        .expect("snapshot within 5s")
        .expect("stream ok")
        .expect("snapshot present");
    assert!(
        !first.config_json.contains("tenant-b"),
        "tenant A's own snapshot must not carry tenant B state"
    );

    // The attack: same installed secret, `ns` rewritten to tenant B. The
    // signature is valid — that was never the boundary.
    let forged = mint(
        TENANT_A_SECRET,
        Some(TENANT_A),
        "dp-a",
        Some(json!(TENANT_B)),
        None,
    );
    let mut client = configsync_client!(addr, forged);
    let err = client
        .subscribe(tonic::Request::new(subscribe_request("dp-a", TENANT_B)))
        .await
        .expect_err("forged tenant-B subscription must be refused");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    // Naming tenant B's `kid` does not help either: selection is not a grant,
    // and tenant A does not hold tenant B's key.
    let wrong_kid = mint(
        TENANT_A_SECRET,
        Some(TENANT_B),
        "dp-a",
        Some(json!(TENANT_B)),
        None,
    );
    let mut client = configsync_client!(addr, wrong_kid);
    let err = client
        .subscribe(tonic::Request::new(subscribe_request("dp-a", TENANT_B)))
        .await
        .expect_err("selecting tenant B's kid without its key must fail");
    assert_eq!(err.code(), tonic::Code::Unauthenticated);

    handle.abort();
}

/// `GetFullConfig` shares the authorization seam with `Subscribe`; pin it
/// separately so a future refactor cannot leave the unary surface behind.
#[tokio::test(flavor = "multi_thread")]
async fn get_full_config_refuses_cross_tenant_forgery() {
    let (addr, handle) = start_configsync(two_tenant_bundle()).await;

    let forged = mint(
        TENANT_A_SECRET,
        Some(TENANT_A),
        "dp-a",
        Some(json!(TENANT_B)),
        None,
    );
    let mut client = configsync_client!(addr, forged);
    let err = client
        .get_full_config(tonic::Request::new(
            ferrum_edge::grpc::proto::FullConfigRequest {
                node_id: "dp-a".to_string(),
                ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
                namespace: TENANT_B.to_string(),
                real_ip_header: Some(String::new()),
            },
        ))
        .await
        .expect_err("forged tenant-B GetFullConfig must be refused");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    handle.abort();
}

/// Native `MeshSubscribe`: same forgery, same refusal — and specifically
/// before any mesh slice (which carries the tenant's service inventory and
/// trust bundle) is serialized.
#[tokio::test(flavor = "multi_thread")]
async fn mesh_subscribe_refuses_tenant_a_credential_signing_a_tenant_b_claim() {
    let (addr, handle) = start_mesh(two_tenant_bundle()).await;

    let forged = mint(
        TENANT_A_SECRET,
        Some(TENANT_A),
        "mesh-a",
        Some(json!(TENANT_B)),
        Some(MESH_LOCAL_SUBSCRIBE_AUDIENCE),
    );
    let mut client = mesh_client!(addr, forged);
    let err = client
        .mesh_subscribe(tonic::Request::new(
            ferrum_edge::grpc::proto::MeshSubscribeRequest {
                node_id: "mesh-a".to_string(),
                ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
                namespace: TENANT_B.to_string(),
                workload_spiffe_id: String::new(),
                labels: HashMap::new(),
                waypoint_name: String::new(),
                ambient_udp_source_scoping: false,
                remote_discovery: false,
            },
        ))
        .await
        .expect_err("forged tenant-B MeshSubscribe must be refused");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    handle.abort();
}

/// xDS ADS has no namespace request field, so the tenant identity comes purely
/// from the resolved namespace set. A tenant-A credential asserting tenant B
/// must never produce a tenant-B snapshot.
#[tokio::test(flavor = "multi_thread")]
async fn xds_refuses_tenant_a_credential_signing_a_tenant_b_claim() {
    let (addr, handle) = start_xds(two_tenant_bundle()).await;

    let forged = mint(
        TENANT_A_SECRET,
        Some(TENANT_A),
        "xds-a",
        Some(json!(TENANT_B)),
        None,
    );
    let channel = tonic::transport::Channel::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client =
        ferrum_edge::xds::proto::aggregated_discovery_service_client::AggregatedDiscoveryServiceClient::new(
            channel,
        );
    let requests = tokio_stream::iter(vec![ferrum_edge::xds::proto::DiscoveryRequest {
        version_info: String::new(),
        node: Some(ferrum_edge::xds::proto::Node {
            id: "xds-a".to_string(),
            cluster: String::new(),
            metadata: Vec::new(),
        }),
        resource_names: vec!["*".to_string()],
        type_url: LDS_TYPE_URL.to_string(),
        response_nonce: String::new(),
        error_detail: None,
    }]);
    let mut request = tonic::Request::new(requests);
    request.metadata_mut().insert(
        "authorization",
        tonic::metadata::MetadataValue::try_from(format!("Bearer {forged}")).unwrap(),
    );
    let err = client
        .stream_aggregated_resources(request)
        .await
        .expect_err("forged tenant-B ADS stream must be refused before serialization");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    handle.abort();
}

// ── Shared-CA mTLS: a valid certificate is not namespace authorization ───

/// A certificate issued by the CA both tenants share proves the peer is
/// *some* member of the mesh. It must not, on its own, authorize a namespace,
/// and it must never widen what a credential permits.
///
/// Driven at the authorization seam rather than over a real TLS handshake:
/// the peer scope is exactly what the CP gRPC listener derives from a verified
/// leaf, so injecting it directly is the same input with less ceremony.
#[test]
fn shared_ca_peer_identity_cannot_widen_or_authorize_alone() {
    use ferrum_edge::grpc::cp_trust::resolve_authorized_namespaces;
    use std::collections::HashSet;

    let bound: HashSet<String> = [TENANT_A.to_string()].into_iter().collect();
    let peer_b = PeerNamespaceScope::single(TENANT_B);
    let claim_b: HashSet<String> = [TENANT_B.to_string()].into_iter().collect();

    // Tenant A's credential + a (mis-issued or stolen) tenant-B SPIFFE peer:
    // the intersection is empty, so this is refused rather than granted.
    assert!(
        resolve_authorized_namespaces(Some(&bound), Some(&peer_b), Some(&claim_b)).is_err(),
        "a peer certificate must not widen a credential's namespace binding"
    );

    // Tenant A's credential + tenant A's peer identity + no claim: authorized
    // for exactly tenant A.
    let peer_a = PeerNamespaceScope::single(TENANT_A);
    let resolved = resolve_authorized_namespaces(Some(&bound), Some(&peer_a), None)
        .expect("matching peer identity resolves")
        .expect("bundle mode always resolves a set");
    assert_eq!(resolved, bound);

    // A peer identity NARROWS a broader credential.
    let broad: HashSet<String> = [TENANT_A.to_string(), TENANT_B.to_string()]
        .into_iter()
        .collect();
    let narrowed = resolve_authorized_namespaces(Some(&broad), Some(&peer_a), None)
        .expect("peer narrows")
        .expect("set present");
    assert_eq!(narrowed, bound);

    // A peer whose certificate encodes no SPIFFE namespace contributes
    // nothing — it cannot widen, and it cannot substitute for a credential.
    let unchanged = resolve_authorized_namespaces(Some(&broad), None, None)
        .expect("no peer evidence")
        .expect("set present");
    assert_eq!(unchanged, broad);
}

/// The connect-info the listener attaches defaults to "no evidence", so a
/// plaintext or non-SPIFFE connection can never be mistaken for authorization.
#[test]
fn default_connect_info_carries_no_namespace_evidence() {
    let info = CpGrpcConnectInfo::default();
    assert!(info.peer_namespace_scope.is_none());
}

// ── Key selection, malformed, and ambiguous bundles ──────────────────────

/// A token with no `kid` cannot select a credential deterministically, so a
/// trust-bundle CP refuses it rather than guessing.
#[tokio::test(flavor = "multi_thread")]
async fn trust_bundle_cp_refuses_a_token_with_no_key_id() {
    let (addr, handle) = start_configsync(two_tenant_bundle()).await;

    let no_kid = mint(TENANT_A_SECRET, None, "dp-a", Some(json!(TENANT_A)), None);
    let mut client = configsync_client!(addr, no_kid);
    let err = client
        .subscribe(tonic::Request::new(subscribe_request("dp-a", TENANT_A)))
        .await
        .expect_err("a kid-less token must be refused by a trust-bundle CP");
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
    assert!(
        !err.message().contains(TENANT_A_SECRET),
        "rejection must never echo credential material"
    );

    handle.abort();
}

/// An unknown `kid` is refused, and the refusal discloses nothing about which
/// credentials the control plane actually trusts.
#[tokio::test(flavor = "multi_thread")]
async fn trust_bundle_cp_refuses_an_unknown_key_id_without_disclosure() {
    let (addr, handle) = start_configsync(two_tenant_bundle()).await;

    let unknown = mint(
        TENANT_A_SECRET,
        Some("tenant-z"),
        "dp-a",
        Some(json!(TENANT_A)),
        None,
    );
    let mut client = configsync_client!(addr, unknown);
    let err = client
        .subscribe(tonic::Request::new(subscribe_request("dp-a", TENANT_A)))
        .await
        .expect_err("an unknown kid must be refused");
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
    let message = err.message();
    assert!(
        !message.contains(TENANT_A) && !message.contains(TENANT_B),
        "rejection must not enumerate the trusted key inventory, got: {message}"
    );

    handle.abort();
}

/// The bearer may only narrow: an array claim listing both tenants resolves to
/// the credential's single bound namespace, not to both.
#[tokio::test(flavor = "multi_thread")]
async fn multi_namespace_claim_cannot_widen_a_single_namespace_credential() {
    let (addr, handle) = start_configsync(two_tenant_bundle()).await;

    let greedy = mint(
        TENANT_A_SECRET,
        Some(TENANT_A),
        "dp-a",
        Some(json!([TENANT_A, TENANT_B])),
        None,
    );
    let mut client = configsync_client!(addr, greedy.clone());
    let err = client
        .subscribe(tonic::Request::new(subscribe_request("dp-a", TENANT_B)))
        .await
        .expect_err("a widened claim must not reach tenant B");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    // The same token still works for the namespace it is genuinely bound to.
    let mut client = configsync_client!(addr, greedy);
    client
        .subscribe(tonic::Request::new(subscribe_request("dp-a", TENANT_A)))
        .await
        .expect("the bound namespace remains reachable");

    handle.abort();
}

/// A claim disjoint from the credential's binding resolves to nothing, and is
/// refused at authentication rather than producing a silently empty allow-set.
#[test]
fn disjoint_claim_resolves_to_no_authorized_namespace() {
    use ferrum_edge::grpc::cp_trust::resolve_authorized_namespaces;
    use std::collections::HashSet;

    let bound: HashSet<String> = [TENANT_A.to_string()].into_iter().collect();
    let claim: HashSet<String> = ["tenant-c".to_string()].into_iter().collect();
    let reason = resolve_authorized_namespaces(Some(&bound), None, Some(&claim))
        .expect_err("a disjoint claim must fail closed");
    assert_eq!(reason.as_metric_label(), "no_authorized_namespace");
}

// ── Trust-bundle document validation (fail-closed configuration) ─────────

#[test]
fn duplicate_key_ids_are_refused_as_ambiguous_selection() {
    let document = json!({
        "keys": [
            { "kid": "dup", "algorithm": "HS256", "secret": TENANT_A_SECRET,
              "namespaces": [TENANT_A] },
            { "kid": "dup", "algorithm": "HS256", "secret": TENANT_B_SECRET,
              "namespaces": [TENANT_B] },
        ]
    })
    .to_string();
    let error = CpDpTrustBundle::from_document_str(&document, "dup-bundle")
        .expect_err("duplicate kids must be refused");
    assert!(error.contains("duplicate kid"), "got: {error}");
}

#[test]
fn malformed_bundles_are_refused_without_echoing_material() {
    let cases: Vec<(serde_json::Value, &str)> = vec![
        (json!({ "keys": [] }), "declares no keys"),
        (
            json!({ "keys": [{ "kid": "", "algorithm": "HS256", "secret": TENANT_A_SECRET,
                               "namespaces": [TENANT_A] }] }),
            "non-empty `kid`",
        ),
        (
            json!({ "keys": [{ "kid": "k", "algorithm": "NOPE", "secret": TENANT_A_SECRET,
                               "namespaces": [TENANT_A] }] }),
            "unsupported algorithm",
        ),
        (
            json!({ "keys": [{ "kid": "k", "algorithm": "HS256", "secret": TENANT_A_SECRET,
                               "namespaces": [] }] }),
            "at least one namespace",
        ),
        (
            json!({ "keys": [{ "kid": "k", "algorithm": "HS256", "secret": "too-short",
                               "namespaces": [TENANT_A] }] }),
            "at least 32 bytes",
        ),
        (
            json!({ "keys": [{ "kid": "k", "algorithm": "HS256",
                               "namespaces": [TENANT_A] }] }),
            "exactly one of",
        ),
        (
            json!({ "keys": [{ "kid": "k", "algorithm": "HS256", "secret": TENANT_A_SECRET,
                               "public_key_pem": "x", "namespaces": [TENANT_A] }] }),
            "exactly one of",
        ),
        (
            json!({ "keys": [{ "kid": "k", "algorithm": "ES256", "secret": TENANT_A_SECRET,
                               "namespaces": [TENANT_A] }] }),
            "symmetric secret material",
        ),
        (
            json!({ "version": 99, "keys": [{ "kid": "k", "algorithm": "HS256",
                    "secret": TENANT_A_SECRET, "namespaces": [TENANT_A] }] }),
            "unsupported version",
        ),
    ];

    for (document, expected) in cases {
        let raw = document.to_string();
        let error = CpDpTrustBundle::from_document_str(&raw, "bad-bundle")
            .expect_err("malformed bundle must be refused");
        assert!(
            error.contains(expected),
            "expected {expected:?} in error, got: {error}"
        );
        assert!(
            !error.contains(TENANT_A_SECRET) && !error.contains("too-short"),
            "startup errors must not echo secret material, got: {error}"
        );
    }
}

// ── Fail-closed startup ──────────────────────────────────────────────────

/// A multi-namespace control plane must refuse the fleet-wide self-minting
/// secret outright. There is no unsafe override.
#[test]
fn multi_namespace_startup_refuses_the_fleet_wide_secret() {
    let legacy = CpDpVerifier::SharedSecret(TENANT_A_SECRET.to_string());
    let error = legacy
        .validate_for_scope(true)
        .expect_err("multi-namespace CP must refuse the fleet-wide secret");
    assert!(error.contains("GHSA-3f2j-wwqw-grmg"), "got: {error}");
    assert!(
        !error.contains(TENANT_A_SECRET),
        "startup refusal must not echo the secret"
    );

    // Single-namespace stays usable: there is no second tenant to cross into.
    legacy
        .validate_for_scope(false)
        .expect("single-namespace CP keeps the legacy secret");

    // A trust bundle satisfies both.
    let bundle = two_tenant_bundle();
    bundle
        .validate_for_scope(true)
        .expect("a trust bundle is accepted for multi-namespace scope");
    assert!(bundle.has_namespace_binding());
    assert!(
        !bundle.describe().contains(TENANT_A_SECRET),
        "the startup description must not render material"
    );
}

/// `Debug` on the verifier is a disclosure surface (panics, `{:#?}` in
/// diagnostics). It must never render key material.
#[test]
fn verifier_debug_never_renders_material() {
    let legacy = CpDpVerifier::SharedSecret(TENANT_A_SECRET.to_string());
    let rendered = format!("{legacy:#?}");
    assert!(!rendered.contains(TENANT_A_SECRET), "got: {rendered}");

    let bundle = two_tenant_bundle();
    let rendered = format!("{bundle:#?}");
    assert!(
        !rendered.contains(TENANT_A_SECRET) && !rendered.contains(TENANT_B_SECRET),
        "got: {rendered}"
    );
}
