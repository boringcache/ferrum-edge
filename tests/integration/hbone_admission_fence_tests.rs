//! Receiver-side HBONE admission fence (issue #5042 step 1).
//!
//! An HBONE CONNECT is judged once, at admission; the relay then byte-copies
//! for as long as the tunnel lives. These tests pin the fence that re-applies
//! the admission gates to LIVE tunnels on every request-epoch publication and
//! every inbound PeerAuthentication swap:
//!
//! * a tightened authorize chain revokes the tunnel and denies the same
//!   principal's next CONNECT (parity between the sweep and the request path);
//! * an unrelated publication re-evaluates but keeps the tunnel flowing;
//! * withdrawing the admitting proxy revokes the tunnel;
//! * a PeerAuthentication swap the tunnel's transport no longer satisfies
//!   revokes it, on both the byte-stream and the datagram relay, while a
//!   swap it does satisfy leaves it alone;
//! * an admission that RACED a publication is re-swept when it registers, so a
//!   CONNECT in flight across a tightening apply cannot escape the fence;
//! * the relay-destination gate revokes a synthesized inbound relay whose
//!   destination left this terminator's inventory, and one whose dialled
//!   address is loopback after the own-namespace privilege is withdrawn;
//! * a CONNECT declaring a gRPC content type is refused before it can become a
//!   tunnel, so a peer cannot steer the fence onto a view it was never admitted
//!   with;
//! * a side-effecting operator authorize plugin is NOT re-run by a sweep — no
//!   consumed budget, no spurious revocation;
//! * a tunnel failing BOTH the authorize gate and the transport gate is
//!   attributed `authorization_denied`, because that is the gate order the
//!   CONNECT path applies and the `reason` label is the operator's only
//!   attribution;
//! * retirement and revocation are one atomic transition: a relay that ends
//!   first is never counted or classified as revoked, and a sweep that wins
//!   first leaves its reason readable after the relay retires;
//! * publications coalesce and revoke every live tunnel exactly once;
//! * a revocation never lands on `ferrum_mesh_hbone_relay_failures_total`.
//!
//! and the CREDENTIAL dimension (issue #5568), which a sweep re-decides because
//! an established inbound mTLS session is never re-handshaked:
//!
//! * a gateway trust rotation that still anchors the peer revokes nothing;
//! * withdrawing the peer's trust domain, and rotating away the authority that
//!   issued its leaf, each revoke with `peer_trust`;
//! * an admitted SVID past its `notAfter` is revoked by the fence's own expiry
//!   watcher with NO publication of any kind;
//! * a published trust bundle that cannot be compiled into a verifier fails
//!   closed with `reevaluation_failed`;
//! * a peer the admitting gateway trust generation never anchored — the
//!   chain-only inbound posture — is never revoked for trust.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use chrono::Utc;
use hyper::{Method, Request, StatusCode};
use rustls::pki_types::CertificateRevocationListDer;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;

use crate::scaffolding::port_registry::TestSocket;

use ferrum_edge::config::types::{GatewayConfig, PluginConfig, PluginScope, Proxy};
use ferrum_edge::config::{EnvConfig, OperatingMode};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::identity::{
    SpiffeId, SvidBundle, TrustBundle as RuntimeTrustBundle,
    TrustBundleSet as RuntimeTrustBundleSet, TrustDomain,
};
use ferrum_edge::modes::mesh::config::{
    MeshConfig, MeshInboundRelayDestination, MeshInboundRelayHost, MeshPolicy,
    MeshRelayEnrollmentEvidence, MtlsMode, PolicyScope,
};
use ferrum_edge::modes::mesh::{MeshTrafficDirection, prepare_gateway_config_for_mesh};
use ferrum_edge::plugins::{ProxyProtocol, RequestContext};
use ferrum_edge::proxy::hbone_admission_fence::{
    AdmittedHboneTunnel, HboneAdmissionSnapshot, HbonePeerCredential, HboneRelayDestinationGate,
    HboneRevocationReason,
};
use ferrum_edge::proxy::{
    ConfigApplyOutcome, MeshInboundTlsPolicy, ProxyState,
    start_proxy_listener_with_bound_listener_and_mesh_direction,
};
use ferrum_edge::tls;

use super::mesh_hbone_tests::{
    connect_hbone_h2_mtls, create_egress_udp_gateway_state, create_mesh_proxy,
    egress_udp_mesh_config, frame_datagram, generate_hbone_mtls_certs, hbone_client_config,
    hbone_server_config, read_framed_datagram, start_external_udp_echo, udp_connect_request,
};
use super::mesh_test_support::{
    DEFAULT_NAMESPACE, default_mesh_runtime, gateway_config_with_mesh, mesh_config_with,
    policy_allow_principal, policy_deny_principal,
};

const CLIENT_SPIFFE: &str = "spiffe://cluster.local/ns/default/sa/client";
const OTHER_SPIFFE: &str = "spiffe://cluster.local/ns/default/sa/other";
const CONNECT_AUTHORITY: &str = "orders.default.svc.cluster.local:8080";
const DEADLINE: Duration = Duration::from_secs(5);
/// Mesh synthesis builds the ordinary transparent inbound relay under this
/// reserved id. The constant itself is crate-private, so the literal is pinned
/// here exactly as the other mesh suites pin it.
const MESH_INBOUND_HBONE_RELAY_PROXY_ID: &str = "__mesh-inbound-hbone-relay";
const RELAY_APP_HOST: &str = "orders.default.svc.cluster.local";
const RELAY_APP_PORT: u16 = 8080;

fn namespace_scope() -> PolicyScope {
    PolicyScope::Namespace {
        namespace: DEFAULT_NAMESPACE.to_string(),
    }
}

fn allow_client() -> MeshPolicy {
    policy_allow_principal(
        "allow-client",
        DEFAULT_NAMESPACE,
        namespace_scope(),
        CLIENT_SPIFFE,
    )
}

fn allow_other() -> MeshPolicy {
    policy_allow_principal(
        "allow-other",
        DEFAULT_NAMESPACE,
        namespace_scope(),
        OTHER_SPIFFE,
    )
}

fn deny_client() -> MeshPolicy {
    policy_deny_principal(
        "deny-client",
        DEFAULT_NAMESPACE,
        namespace_scope(),
        CLIENT_SPIFFE,
    )
}

/// Production materializes the mesh-managed `spiffe_identity` / `mesh_authz`
/// rows under reserved `__mesh_*` ids and republishes them through the
/// crate-private `ProxyState::update_mesh_config`. These tests publish through
/// the public `update_config`, whose resource-id grammar refuses the reserved
/// prefix, so the injected rows are retagged as ordinary operator globals. On
/// the Sidecar topology `mesh_authz` reads only its config JSON, never its row
/// id, so the retag changes nothing about enforcement.
fn retag_mesh_managed_plugins(config: &mut GatewayConfig) {
    let retag = |id: &str| {
        id.strip_prefix("__mesh_")
            .map(|rest| format!("mesh-managed-{}", rest.replace('_', "-")))
    };
    for plugin in &mut config.plugin_configs {
        if let Some(public) = retag(&plugin.id) {
            plugin.id = public;
        }
    }
    for proxy in &mut config.proxies {
        for association in &mut proxy.plugins {
            if let Some(public) = retag(&association.plugin_config_id) {
                association.plugin_config_id = public;
            }
        }
    }
    assert!(
        config.proxies.iter().all(|p| !p.id.starts_with("__mesh"))
            && config.upstreams.iter().all(|u| !u.id.starts_with("__mesh")),
        "fixture must not depend on reserved mesh-generated proxies or upstreams"
    );
}

/// Sidecar mesh config with one configured HBONE proxy (or none) and the
/// supplied AuthorizationPolicies, run through the production mesh preparation
/// so `spiffe_identity` and `mesh_authz` are injected exactly as at runtime.
fn prepared_config(proxy_backend_port: Option<u16>, policies: Vec<MeshPolicy>) -> GatewayConfig {
    prepared_config_with(proxy_backend_port, None, policies, Vec::new())
}

/// [`prepared_config`] with an optional proxy-id override (so one test can own a
/// metric series no other test can touch) and operator-global plugin rows.
fn prepared_config_with(
    proxy_backend_port: Option<u16>,
    proxy_id: Option<&str>,
    policies: Vec<MeshPolicy>,
    plugin_configs: Vec<PluginConfig>,
) -> GatewayConfig {
    let runtime = default_mesh_runtime();
    let proxies = proxy_backend_port
        .map(|port| {
            let mut proxy = create_mesh_proxy(port);
            if let Some(id) = proxy_id {
                proxy.id = id.to_string();
            }
            proxy
        })
        .into_iter()
        .collect();
    let mut config = gateway_config_with_mesh(
        proxies,
        Vec::new(),
        mesh_config_with(Vec::new(), Vec::new(), policies),
    );
    config.plugin_configs = plugin_configs;
    let mut prepared =
        prepare_gateway_config_for_mesh(config, &runtime).expect("mesh-prepared config");
    retag_mesh_managed_plugins(&mut prepared);
    prepared
}

/// A globally scoped `rate_limiting` instance keyed by the peer's SPIFFE
/// identity — an operator authorize plugin whose `authorize` CONSUMES a token.
/// The fence must never re-run it for a live tunnel.
///
/// The windows live inside a `limits` rule: `rate_limiting` rejects the legacy
/// top-level `window_seconds` / `max_requests` spelling outright, so a fixture
/// using it would abort gateway startup instead of exercising the budget.
fn spiffe_rate_limit_plugin(max_requests: u32) -> PluginConfig {
    PluginConfig {
        labels: Default::default(),
        id: "operator-spiffe-rate-limit".to_string(),
        plugin_name: "rate_limiting".to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        config: json!({
            "limit_by": "spiffe_identity",
            "limits": [
                {
                    "scope": "default",
                    "window_seconds": 60,
                    "max_requests": max_requests
                }
            ]
        }),
        scope: PluginScope::Global,
        proxy_id: None,
        enabled: true,
        priority_override: None,
        trigger: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

/// One entry in this terminator's inbound-relay destination inventory, declared
/// by NAME so the guard matches the CONNECT authority verbatim (an IP authority
/// would take the address arm instead).
fn relay_destination(host: &str, port: u16) -> MeshInboundRelayDestination {
    MeshInboundRelayDestination {
        host: MeshInboundRelayHost::Name(host.to_string()),
        ports: vec![port],
        enrollment: MeshRelayEnrollmentEvidence::default(),
        registry_uncontested: true,
    }
}

/// A generation carrying exactly the inbound-relay inventory a test needs. The
/// configured proxy differs per `generation_tag` so the config delta always
/// publishes; the gate under test reads only `config.mesh`.
fn relay_destination_config(
    destinations: Vec<MeshInboundRelayDestination>,
    admits_loopback_namespace: bool,
    generation_tag: u16,
) -> GatewayConfig {
    let mut config = gateway_config_with_mesh(
        vec![create_mesh_proxy(generation_tag)],
        Vec::new(),
        MeshConfig {
            inbound_relay_destinations: destinations,
            inbound_relay_admits_loopback_namespace: admits_loopback_namespace,
            ..MeshConfig::default()
        },
    );
    config.version = format!("relay-destination-{generation_tag}");
    config
}

/// The synthesized ordinary inbound relay, as mesh synthesis builds it for one
/// application destination.
fn inbound_relay_proxy(app_host: &str, app_port: u16) -> Proxy {
    let mut proxy = create_mesh_proxy(app_port);
    proxy.id = MESH_INBOUND_HBONE_RELAY_PROXY_ID.to_string();
    proxy.backend_host = app_host.to_string();
    proxy.backend_port = app_port;
    proxy
}

/// An admission snapshot for a gate the live-gateway fixtures cannot reach.
///
/// Every field is what the CONNECT path would have captured. `mesh_direction`
/// stays `None`, which leaves the post-route PeerAuthentication gate
/// inapplicable, and the synthesized relay carries no lifecycle generation, so
/// each test isolates exactly the gate it names.
fn synthetic_snapshot(
    proxy: Proxy,
    destination_gate: HboneRelayDestinationGate,
    resolved_ip: Option<IpAddr>,
    admission_sweep_epoch: u64,
) -> HboneAdmissionSnapshot {
    HboneAdmissionSnapshot {
        ctx: RequestContext::new(
            "127.0.0.1".to_string(),
            "CONNECT".to_string(),
            "/".to_string(),
        ),
        proxy: Arc::new(proxy),
        upstream_target: None,
        is_tls: true,
        has_verified_peer_certificate: true,
        mesh_inbound_pre_handshake_app_port: None,
        destination_gate,
        resolved_ip,
        proxy_lifecycle_generation: None,
        request_protocol: ProxyProtocol::Http,
        grpc_web_request: false,
        admission_sweep_epoch,
        // No peer credential: these fixtures isolate a POLICY gate, and a
        // credential-less snapshot leaves the credential gate (and the expiry
        // watcher) inapplicable. `credential_snapshot` is the fixture for that
        // dimension.
        gateway_trust_generation: 0,
        // The generation a `ProxyState` with no CRL source publishes at
        // startup, which is what every fixture here runs with. A snapshot
        // matching no real generation would force the chain re-verification on
        // every sweep and quietly defeat the fast path these tests rely on;
        // the revocation tests set it explicitly from the live slot instead.
        mesh_inbound_crl_generation: 1,
        peer_credential: None,
    }
}

/// An admission snapshot that arms BOTH the authorize gate and the post-route
/// PeerAuthentication transport gate, so one sweep sees two failing gates and
/// has to choose which one it attributes the revocation to.
///
/// `mesh_direction: Inbound` is what arms the transport gate at all; the peer
/// SPIFFE id is what the authorize chain judges; and plaintext transport
/// (`is_tls: false`) satisfies the default PERMISSIVE posture while failing
/// STRICT, so the transport gate can be armed by a later publication without
/// touching the authorize side. The proxy is a CONFIGURED one, so the
/// destination gate does not apply and no lifecycle generation is recorded —
/// exactly two gates are live.
fn dual_gate_snapshot(proxy: Arc<Proxy>, admission_sweep_epoch: u64) -> HboneAdmissionSnapshot {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "CONNECT".to_string(),
        "/".to_string(),
    );
    ctx.mesh_direction = Some(MeshTrafficDirection::Inbound);
    ctx.peer_spiffe_id = Some(SpiffeId::new(CLIENT_SPIFFE).expect("client spiffe id"));
    ctx.matched_proxy = Some(Arc::clone(&proxy));
    HboneAdmissionSnapshot {
        ctx,
        proxy,
        upstream_target: None,
        is_tls: false,
        has_verified_peer_certificate: false,
        mesh_inbound_pre_handshake_app_port: None,
        destination_gate: HboneRelayDestinationGate::Configured,
        resolved_ip: None,
        proxy_lifecycle_generation: None,
        request_protocol: ProxyProtocol::Http,
        grpc_web_request: false,
        admission_sweep_epoch,
        gateway_trust_generation: 0,
        // The generation a `ProxyState` with no CRL source publishes at
        // startup, which is what every fixture here runs with. A snapshot
        // matching no real generation would force the chain re-verification on
        // every sweep and quietly defeat the fast path these tests rely on;
        // the revocation tests set it explicitly from the live slot instead.
        mesh_inbound_crl_generation: 1,
        peer_credential: None,
    }
}

fn build_state(prepared: GatewayConfig) -> ProxyState {
    let env_config = EnvConfig {
        mode: OperatingMode::Mesh,
        log_level: "error".to_string(),
        proxy_http_port: 0,
        proxy_https_port: 0,
        admin_http_port: 0,
        admin_https_port: 0,
        shutdown_drain_seconds: 0,
        max_connections: 0,
        namespace: DEFAULT_NAMESPACE.to_string(),
        ..EnvConfig::default()
    };
    ProxyState::new(
        prepared,
        DnsCache::new(DnsConfig::default()),
        env_config,
        None,
        None,
    )
    .expect("mesh proxy state")
    .0
}

/// Inbound-direction mTLS gateway. The direction is what arms the post-route
/// PeerAuthentication transport gate and marks the authorize chain's inbound
/// leg, so both fence gates under test are live.
async fn start_inbound_gateway(
    state: ProxyState,
    server_config: std::sync::Arc<rustls::ServerConfig>,
) -> (SocketAddr, watch::Sender<bool>) {
    let listener = TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind gateway");
    let addr = listener.local_addr().expect("gateway local addr");
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        let _ = start_proxy_listener_with_bound_listener_and_mesh_direction(
            listener,
            state,
            shutdown_rx,
            Some(server_config),
            Some(MeshTrafficDirection::Inbound),
        )
        .await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, shutdown_tx)
}

/// Echoes every chunk back as it arrives, so a tunnel's liveness can be probed
/// mid-flight (the classic `read_to_end` echo only answers at EOF). Accepts in a
/// loop: several concurrent tunnels each dial their own backend connection.
async fn start_interactive_echo_backend() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind echo backend");
    let addr = listener.local_addr().expect("echo backend local addr");
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0_u8; 4096];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    (addr, handle)
}

struct Tunnel {
    request_body: h2::SendStream<Bytes>,
    response_body: h2::RecvStream,
}

/// Send a plain HBONE CONNECT and, on a `200`, hand back both halves of the
/// live tunnel. A non-`200` head is the admission refusal.
///
/// Deliberately plain: a CONNECT carrying a gRPC `content-type` classifies as
/// gRPC before the HBONE branch is reached and is refused as a trailers-only
/// `200`, which this helper could not tell from an admitted tunnel. Tests that
/// want that shape use [`send_connect`] and read the `grpc-status` themselves.
async fn open_tunnel(sender: &mut h2::client::SendRequest<Bytes>) -> Result<Tunnel, StatusCode> {
    let (resp, request_body) = send_connect(sender, None).await;
    if resp.status() != StatusCode::OK {
        return Err(resp.status());
    }
    Ok(Tunnel {
        request_body,
        response_body: resp.into_body(),
    })
}

/// Send a CONNECT and hand back the response head plus the request-body handle.
/// The caller decides what the head means — a gRPC-classified refusal is shaped
/// as trailers-only (`200` + `grpc-status`), not as an HTTP error status.
async fn send_connect(
    sender: &mut h2::client::SendRequest<Bytes>,
    content_type: Option<&str>,
) -> (hyper::Response<h2::RecvStream>, h2::SendStream<Bytes>) {
    let mut builder = Request::builder()
        .method(Method::CONNECT)
        .uri(CONNECT_AUTHORITY);
    if let Some(content_type) = content_type {
        builder = builder.header("content-type", content_type);
    }
    let req = builder.body(()).expect("connect request");
    let (response_fut, request_body) = sender.send_request(req, false).expect("send CONNECT");
    let resp = tokio::time::timeout(DEADLINE, response_fut)
        .await
        .expect("CONNECT response within deadline")
        .expect("CONNECT response");
    (resp, request_body)
}

/// The `grpc-status` a trailers-only refusal carries, if any. An admitted HBONE
/// CONNECT's `200` carries none.
fn grpc_status_of(response: &hyper::Response<h2::RecvStream>) -> Option<String> {
    response
        .headers()
        .get("grpc-status")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

async fn read_exact_from_body(body: &mut h2::RecvStream, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        let chunk = body
            .data()
            .await
            .expect("tunnel closed before the echo arrived")
            .expect("tunnel chunk");
        let _ = body.flow_control().release_capacity(chunk.len());
        out.extend_from_slice(&chunk);
    }
    out
}

async fn echo_round_trip(tunnel: &mut Tunnel, payload: &'static [u8]) {
    tunnel
        .request_body
        .send_data(Bytes::from_static(payload), false)
        .expect("send tunnel bytes");
    let echoed = tokio::time::timeout(
        DEADLINE,
        read_exact_from_body(&mut tunnel.response_body, payload.len()),
    )
    .await
    .expect("echo within deadline");
    assert_eq!(echoed, payload);
}

/// A revoked tunnel ends from the peer's point of view: the CONNECT response
/// body reaches END_STREAM or the stream is reset. Anything still buffered
/// before the cut is drained and ignored.
async fn assert_tunnel_closed(body: &mut h2::RecvStream) {
    tokio::time::timeout(DEADLINE, async {
        loop {
            match body.data().await {
                None | Some(Err(_)) => return,
                Some(Ok(chunk)) => {
                    let _ = body.flow_control().release_capacity(chunk.len());
                }
            }
        }
    })
    .await
    .expect("revoked tunnel must close toward the peer");
}

async fn wait_for_sweep_after(state: &ProxyState, completed_before: u64) {
    tokio::time::timeout(DEADLINE, async {
        while state.hbone_admission_fence.sweeps_completed() <= completed_before {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("fence sweep completes after publication");
}

async fn wait_for_no_live_tunnels(state: &ProxyState) {
    tokio::time::timeout(DEADLINE, async {
        while state.hbone_admission_fence.live_tunnels() != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("revoked tunnel deregisters once its relay task ends");
}

/// Every requested sweep has settled. Coalescing folds concurrent requests into
/// one pass, so `completed` catches up to `requested` rather than matching it
/// one request per pass.
async fn wait_for_settled_sweeps(state: &ProxyState) {
    let fence = &state.hbone_admission_fence;
    tokio::time::timeout(DEADLINE, async {
        while fence.sweeps_completed() < fence.sweep_epoch() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("every requested fence sweep settles");
}

async fn wait_for_revocation(tunnel: &AdmittedHboneTunnel) {
    tokio::time::timeout(DEADLINE, tunnel.revocation_token().cancelled_owned())
        .await
        .expect("the fence must revoke the tunnel within the deadline");
}

/// Every revocation reason, in the fence's own GATE ORDER, so an assertion
/// reads the same way the sweep decides:
/// `[proxy_withdrawn, peer_expired, peer_trust, peer_revoked,
///   authorization_denied, peer_auth_transport, relay_destination,
///   reevaluation_failed]`.
///
/// The three credential arms are ordered by webpki's own error precedence —
/// `notAfter` before any anchor, `UnknownIssuer` before revocation — so this
/// array is also the pin on that derivation (issue #5574).
fn revocation_counts(state: &ProxyState) -> [u64; 8] {
    let fence = &state.hbone_admission_fence;
    [
        fence.revocations(HboneRevocationReason::ProxyWithdrawn),
        fence.revocations(HboneRevocationReason::PeerExpired),
        fence.revocations(HboneRevocationReason::PeerTrust),
        fence.revocations(HboneRevocationReason::PeerRevoked),
        fence.revocations(HboneRevocationReason::AuthorizationDenied),
        fence.revocations(HboneRevocationReason::PeerAuthTransport),
        fence.revocations(HboneRevocationReason::RelayDestination),
        fence.revocations(HboneRevocationReason::ReevaluationFailed),
    ]
}

/// One admitted byte-stream tunnel plus the handles a test needs to publish
/// against it and to tear it down.
struct AdmittedFixture {
    state: ProxyState,
    tunnel: Tunnel,
    sender: h2::client::SendRequest<Bytes>,
    conn_task: tokio::task::JoinHandle<Result<(), h2::Error>>,
    backend_handle: tokio::task::JoinHandle<()>,
    backend_port: u16,
    shutdown_tx: watch::Sender<bool>,
}

async fn admit_client_tunnel(policies: Vec<MeshPolicy>) -> AdmittedFixture {
    let certs = generate_hbone_mtls_certs(CLIENT_SPIFFE);
    let (backend_addr, backend_handle) = start_interactive_echo_backend().await;
    let state = build_state(prepared_config(Some(backend_addr.port()), policies));
    let (gateway_addr, shutdown_tx) =
        start_inbound_gateway(state.clone(), hbone_server_config(&certs)).await;
    let (mut sender, conn_task) =
        connect_hbone_h2_mtls(gateway_addr, hbone_client_config(&certs)).await;

    let mut tunnel = open_tunnel(&mut sender)
        .await
        .expect("admitted CONNECT under the initial policy generation");
    echo_round_trip(&mut tunnel, b"before-publish").await;
    assert_eq!(state.hbone_admission_fence.live_tunnels(), 1);
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0, 0, 0, 0, 0]);

    AdmittedFixture {
        state,
        tunnel,
        sender,
        conn_task,
        backend_handle,
        backend_port: backend_addr.port(),
        shutdown_tx,
    }
}

impl AdmittedFixture {
    async fn teardown(self) {
        let _ = self.shutdown_tx.send(true);
        self.backend_handle.abort();
        self.conn_task.abort();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn tightened_authorization_policy_revokes_live_tunnel_and_denies_the_next_connect() {
    let mut fx = admit_client_tunnel(vec![allow_client()]).await;

    // Operator replaces the ALLOW with a DENY for the admitted principal.
    let outcome = fx
        .state
        .update_config(prepared_config(Some(fx.backend_port), vec![deny_client()]));
    assert_eq!(outcome, ConfigApplyOutcome::Applied);

    assert_tunnel_closed(&mut fx.tunnel.response_body).await;
    wait_for_no_live_tunnels(&fx.state).await;
    assert_eq!(
        revocation_counts(&fx.state),
        [0, 0, 0, 0, 1, 0, 0, 0],
        "exactly one authorization_denied revocation"
    );
    assert!(
        fx.state.hbone_admission_fence.reevaluations() >= 1,
        "the sweep must have re-run the authorize chain for the live tunnel"
    );

    // Request-path parity: the same principal's fresh CONNECT is now refused
    // at admission, so the fence and the gate agree on the new generation.
    let denied = open_tunnel(&mut fx.sender).await.err();
    assert_eq!(
        denied,
        Some(StatusCode::FORBIDDEN),
        "a new CONNECT from the denied principal must be refused at admission"
    );
    assert_eq!(
        revocation_counts(&fx.state),
        [0, 0, 0, 0, 1, 0, 0, 0],
        "a refused CONNECT is never a revocation"
    );

    fx.teardown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn unrelated_policy_publication_reevaluates_but_keeps_the_tunnel() {
    let mut fx = admit_client_tunnel(vec![allow_client()]).await;
    let completed_before = fx.state.hbone_admission_fence.sweeps_completed();
    let reevaluations_before = fx.state.hbone_admission_fence.reevaluations();

    // A second ALLOW for a different principal: a real generation change that
    // still admits the live tunnel's CONNECT.
    let outcome = fx.state.update_config(prepared_config(
        Some(fx.backend_port),
        vec![allow_client(), allow_other()],
    ));
    assert_eq!(outcome, ConfigApplyOutcome::Applied);
    wait_for_sweep_after(&fx.state, completed_before).await;

    assert!(
        fx.state.hbone_admission_fence.reevaluations() > reevaluations_before,
        "the publication must re-judge the live tunnel, not skip it"
    );
    assert_eq!(revocation_counts(&fx.state), [0, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(fx.state.hbone_admission_fence.live_tunnels(), 1);
    echo_round_trip(&mut fx.tunnel, b"after-unrelated-publish").await;

    fx.teardown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn withdrawing_the_admitting_proxy_revokes_live_tunnel() {
    let mut fx = admit_client_tunnel(vec![allow_client()]).await;

    // The configured proxy disappears from the published generation.
    let outcome = fx
        .state
        .update_config(prepared_config(None, vec![allow_client()]));
    assert_eq!(outcome, ConfigApplyOutcome::Applied);

    assert_tunnel_closed(&mut fx.tunnel.response_body).await;
    wait_for_no_live_tunnels(&fx.state).await;
    assert_eq!(
        revocation_counts(&fx.state),
        [1, 0, 0, 0, 0, 0, 0, 0],
        "exactly one proxy_withdrawn revocation"
    );

    fx.teardown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn peer_authentication_swap_revokes_only_a_non_compliant_tunnel() {
    let mut fx = admit_client_tunnel(vec![allow_client()]).await;

    // STRICT is satisfied by this mTLS tunnel: re-judged, kept.
    let completed_before = fx.state.hbone_admission_fence.sweeps_completed();
    fx.state
        .publish_mesh_inbound_tls_policy(MeshInboundTlsPolicy {
            default_mode: MtlsMode::Strict,
            ..MeshInboundTlsPolicy::default()
        });
    wait_for_sweep_after(&fx.state, completed_before).await;
    assert_eq!(revocation_counts(&fx.state), [0, 0, 0, 0, 0, 0, 0, 0]);
    echo_round_trip(&mut fx.tunnel, b"still-admitted-under-strict").await;

    // DISABLE refuses TLS transport for the app port: the same tunnel is now
    // non-compliant and must not outlive the swap.
    fx.state
        .publish_mesh_inbound_tls_policy(MeshInboundTlsPolicy {
            default_mode: MtlsMode::Disable,
            ..MeshInboundTlsPolicy::default()
        });
    assert_tunnel_closed(&mut fx.tunnel.response_body).await;
    wait_for_no_live_tunnels(&fx.state).await;
    assert_eq!(
        revocation_counts(&fx.state),
        [0, 0, 0, 0, 0, 1, 0, 0],
        "exactly one peer_auth_transport revocation"
    );

    fx.teardown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn peer_authentication_swap_revokes_a_live_datagram_tunnel() {
    let certs = generate_hbone_mtls_certs(CLIENT_SPIFFE);
    let (external_addr, external_handle) = start_external_udp_echo().await;
    let state = create_egress_udp_gateway_state(egress_udp_mesh_config(
        "127.0.0.1",
        external_addr.port(),
        external_addr.port(),
    ));
    let (gateway_addr, shutdown_tx) =
        start_inbound_gateway(state.clone(), hbone_server_config(&certs)).await;
    let (mut sender, conn_task) =
        connect_hbone_h2_mtls(gateway_addr, hbone_client_config(&certs)).await;

    let (response_fut, mut request_body) = sender
        .send_request(
            udp_connect_request(&format!("127.0.0.1:{}", external_addr.port())),
            false,
        )
        .expect("send udp CONNECT");
    let resp = tokio::time::timeout(DEADLINE, response_fut)
        .await
        .expect("udp CONNECT response within deadline")
        .expect("udp CONNECT response");
    assert_eq!(resp.status(), StatusCode::OK);
    let mut response_body = resp.into_body();

    request_body
        .send_data(frame_datagram(b"ping"), false)
        .expect("send framed datagram");
    let echoed = tokio::time::timeout(DEADLINE, read_framed_datagram(&mut response_body))
        .await
        .expect("external udp reply");
    assert_eq!(echoed, b"pong:ping".to_vec());
    assert_eq!(state.hbone_admission_fence.live_tunnels(), 1);

    state.publish_mesh_inbound_tls_policy(MeshInboundTlsPolicy {
        default_mode: MtlsMode::Disable,
        ..MeshInboundTlsPolicy::default()
    });
    assert_tunnel_closed(&mut response_body).await;
    wait_for_no_live_tunnels(&state).await;
    assert_eq!(
        revocation_counts(&state),
        [0, 0, 0, 0, 0, 1, 0, 0],
        "the datagram relay honors the same revocation as the byte-stream relay"
    );

    let _ = shutdown_tx.send(true);
    external_handle.abort();
    conn_task.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn an_admission_that_raced_a_publication_is_reswept_when_it_registers() {
    let destination = relay_destination(RELAY_APP_HOST, RELAY_APP_PORT);
    let state = build_state(relay_destination_config(vec![destination], false, 9301));
    let fence = &state.hbone_admission_fence;

    // Captured exactly where the request path captures it: BEFORE the epoch the
    // admission gates judge.
    let captured = fence.sweep_epoch();

    // The operator applies while this CONNECT is still in the authorize chain /
    // backend dial. The publication's own sweep reads the registry — which the
    // tunnel has not reached yet — and settles.
    let outcome = state.update_config(relay_destination_config(Vec::new(), false, 9302));
    assert_eq!(outcome, ConfigApplyOutcome::Applied);
    wait_for_settled_sweeps(&state).await;
    assert!(
        fence.sweep_epoch() > captured,
        "the publication must have advanced the fence's sweep-request counter"
    );

    // Only publish-then-recheck can revoke this: the superseded generation
    // admitted it, and on a quiet mesh no further publication is coming.
    let tunnel = fence.admit(synthetic_snapshot(
        inbound_relay_proxy(RELAY_APP_HOST, RELAY_APP_PORT),
        HboneRelayDestinationGate::InboundRelay,
        None,
        captured,
    ));
    wait_for_revocation(&tunnel).await;
    assert_eq!(
        tunnel.revoked_reason(),
        Some(HboneRevocationReason::RelayDestination),
        "the re-sweep must judge the tunnel against the CURRENT generation"
    );
    // Read at the cancellation edge, deliberately: the accounting is published
    // before the token is cancelled, so anything woken by the cancellation
    // already sees the revocation counted.
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0, 0, 0, 1, 0]);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_admission_under_the_current_generation_schedules_no_sweep() {
    let destination = relay_destination(RELAY_APP_HOST, RELAY_APP_PORT);
    let state = build_state(relay_destination_config(vec![destination], false, 9401));
    let fence = &state.hbone_admission_fence;
    let completed_before = fence.sweeps_completed();

    let tunnel = fence.admit(synthetic_snapshot(
        inbound_relay_proxy(RELAY_APP_HOST, RELAY_APP_PORT),
        HboneRelayDestinationGate::InboundRelay,
        None,
        fence.sweep_epoch(),
    ));

    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(
        fence.sweeps_completed(),
        completed_before,
        "an uncontested admission must not schedule a sweep of its own"
    );
    assert_eq!(tunnel.revoked_reason(), None);
    assert_eq!(fence.live_tunnels(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_withdrawn_relay_destination_revokes_a_live_inbound_relay_tunnel() {
    let destination = relay_destination(RELAY_APP_HOST, RELAY_APP_PORT);
    let state = build_state(relay_destination_config(vec![destination], false, 9101));
    let fence = &state.hbone_admission_fence;

    let tunnel = fence.admit(synthetic_snapshot(
        inbound_relay_proxy(RELAY_APP_HOST, RELAY_APP_PORT),
        HboneRelayDestinationGate::InboundRelay,
        None,
        fence.sweep_epoch(),
    ));
    assert_eq!(fence.live_tunnels(), 1);
    assert_eq!(tunnel.revoked_reason(), None);

    // The workload leaves this terminator's inventory.
    let outcome = state.update_config(relay_destination_config(Vec::new(), false, 9102));
    assert_eq!(outcome, ConfigApplyOutcome::Applied);

    wait_for_revocation(&tunnel).await;
    assert_eq!(
        tunnel.revoked_reason(),
        Some(HboneRevocationReason::RelayDestination),
        "the synthesized inbound relay's ownership guard is what revoked it"
    );
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0, 0, 0, 1, 0]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_loopback_pinned_inbound_relay_is_revoked_when_the_namespace_privilege_is_withdrawn() {
    let destination = relay_destination(RELAY_APP_HOST, RELAY_APP_PORT);
    // Sidecar posture: the terminator shares the application pod's network
    // namespace, so a declared name that resolves to loopback is admitted.
    let state = build_state(relay_destination_config(
        vec![destination.clone()],
        true,
        9201,
    ));
    let fence = &state.hbone_admission_fence;

    let tunnel = fence.admit(synthetic_snapshot(
        inbound_relay_proxy(RELAY_APP_HOST, RELAY_APP_PORT),
        HboneRelayDestinationGate::InboundRelay,
        Some("127.0.0.1".parse::<IpAddr>().expect("loopback literal")),
        fence.sweep_epoch(),
    ));
    assert_eq!(tunnel.revoked_reason(), None);

    // The authority is STILL in the inventory — only the own-namespace loopback
    // privilege is gone, which a fresh CONNECT's post-DNS screen would refuse.
    let outcome = state.update_config(relay_destination_config(vec![destination], false, 9202));
    assert_eq!(outcome, ConfigApplyOutcome::Applied);

    wait_for_revocation(&tunnel).await;
    assert_eq!(
        tunnel.revoked_reason(),
        Some(HboneRevocationReason::RelayDestination),
        "the sweep must re-apply the post-DNS loopback screen to the dialled address"
    );
}

/// A peer cannot steer the fence onto a plugin view the tunnel was never
/// admitted with, because a CONNECT that declares a gRPC content type is not
/// admitted at all.
///
/// `content-type: application/grpc` classifies the request as
/// `HttpFlavor::Grpc` well before the HBONE branch, and the gRPC spec's POST
/// requirement then refuses any other method as trailers-only (`200` + a
/// non-zero `grpc-status`, END_STREAM) — a refusal, not a tunnel. Every
/// admitted HBONE tunnel is therefore admitted on the plain-HTTP view, which is
/// the view a sweep re-resolves. The snapshot still records whichever view the
/// request path actually used
/// (`HboneAdmissionSnapshot::request_protocol` / `grpc_web_request`, pinned by
/// `the_fence_sweep_resolves_the_admitting_plugin_view`) instead of hardcoding
/// plain HTTP, so the sweep cannot drift from the request path if that gate
/// ever moves.
#[tokio::test(flavor = "multi_thread")]
async fn a_grpc_classified_connect_is_refused_before_it_can_become_a_fenced_tunnel() {
    let certs = generate_hbone_mtls_certs(CLIENT_SPIFFE);
    let (backend_addr, backend_handle) = start_interactive_echo_backend().await;
    let state = build_state(prepared_config(
        Some(backend_addr.port()),
        vec![allow_client()],
    ));
    let (gateway_addr, shutdown_tx) =
        start_inbound_gateway(state.clone(), hbone_server_config(&certs)).await;
    let (mut sender, conn_task) =
        connect_hbone_h2_mtls(gateway_addr, hbone_client_config(&certs)).await;

    // This generation ALLOWS the principal, so the refusal below is the
    // protocol gate rather than authorization.
    let (refused, _refused_request) = send_connect(&mut sender, Some("application/grpc")).await;
    assert_eq!(
        refused.status(),
        StatusCode::OK,
        "a gRPC-classified refusal is trailers-only, not an HTTP error status"
    );
    let refused_grpc_status = grpc_status_of(&refused);
    assert!(
        refused_grpc_status
            .as_deref()
            .is_some_and(|status| status != "0"),
        "a gRPC-classified CONNECT must be refused, never admitted as a tunnel; got \
         grpc-status {refused_grpc_status:?}"
    );
    let mut refused_body = refused.into_body();
    assert_tunnel_closed(&mut refused_body).await;
    assert_eq!(
        state.hbone_admission_fence.live_tunnels(),
        0,
        "a refused CONNECT must not register a sweepable tunnel"
    );
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0, 0, 0, 0, 0]);

    // The same peer's plain CONNECT IS admitted, on the plain-HTTP view, and
    // the fence judges it against exactly that view.
    let mut tunnel = open_tunnel(&mut sender)
        .await
        .expect("a plain CONNECT is admitted under the same generation");
    echo_round_trip(&mut tunnel, b"admitting-view").await;
    assert_eq!(state.hbone_admission_fence.live_tunnels(), 1);
    let reevaluations_before = state.hbone_admission_fence.reevaluations();

    let outcome = state.update_config(prepared_config(
        Some(backend_addr.port()),
        vec![deny_client()],
    ));
    assert_eq!(outcome, ConfigApplyOutcome::Applied);

    assert_tunnel_closed(&mut tunnel.response_body).await;
    wait_for_no_live_tunnels(&state).await;
    assert!(
        state.hbone_admission_fence.reevaluations() > reevaluations_before,
        "the sweep must have resolved a non-empty authorize chain for the admitting view"
    );
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0, 1, 0, 0, 0]);

    let _ = shutdown_tx.send(true);
    backend_handle.abort();
    conn_task.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_side_effecting_operator_authorize_plugin_is_never_re_run_by_a_sweep() {
    let certs = generate_hbone_mtls_certs(CLIENT_SPIFFE);
    let (backend_addr, backend_handle) = start_interactive_echo_backend().await;
    // Budget of two CONNECTs for this peer identity, for the whole window.
    let state = build_state(prepared_config_with(
        Some(backend_addr.port()),
        None,
        vec![allow_client()],
        vec![spiffe_rate_limit_plugin(2)],
    ));
    let (gateway_addr, shutdown_tx) =
        start_inbound_gateway(state.clone(), hbone_server_config(&certs)).await;
    let (mut sender, conn_task) =
        connect_hbone_h2_mtls(gateway_addr, hbone_client_config(&certs)).await;

    // Token 1 of 2.
    let mut tunnel = open_tunnel(&mut sender)
        .await
        .expect("first CONNECT admitted under the operator rate limit");
    echo_round_trip(&mut tunnel, b"before-sweeps").await;

    // PeerAuthentication publications the tunnel still satisfies. They do NOT
    // rebuild the plugin cache, so the limiter instance — and its remaining
    // budget — is exactly the one the CONNECT charged.
    for _ in 0..3 {
        let completed_before = state.hbone_admission_fence.sweeps_completed();
        state.publish_mesh_inbound_tls_policy(MeshInboundTlsPolicy {
            default_mode: MtlsMode::Strict,
            ..MeshInboundTlsPolicy::default()
        });
        wait_for_sweep_after(&state, completed_before).await;
    }

    assert_eq!(
        revocation_counts(&state),
        [0, 0, 0, 0, 0, 0, 0, 0],
        "a sweep must not revoke a compliant tunnel over a plugin it may not re-run"
    );
    assert_eq!(state.hbone_admission_fence.live_tunnels(), 1);
    echo_round_trip(&mut tunnel, b"after-sweeps").await;

    // Token 2 of 2 is still there: the sweeps spent none of the peer's budget.
    let second = open_tunnel(&mut sender).await;
    assert!(
        second.is_ok(),
        "the sweeps must not have consumed the peer's rate-limit budget: {:?}",
        second.err()
    );

    let _ = shutdown_tx.send(true);
    backend_handle.abort();
    conn_task.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn close_publications_coalesce_and_revoke_every_live_tunnel_exactly_once() {
    let certs = generate_hbone_mtls_certs(CLIENT_SPIFFE);
    let (backend_addr, backend_handle) = start_interactive_echo_backend().await;
    let state = build_state(prepared_config(
        Some(backend_addr.port()),
        vec![allow_client()],
    ));
    let (gateway_addr, shutdown_tx) =
        start_inbound_gateway(state.clone(), hbone_server_config(&certs)).await;
    let (mut sender, conn_task) =
        connect_hbone_h2_mtls(gateway_addr, hbone_client_config(&certs)).await;

    let mut tunnels = Vec::new();
    for _ in 0..3 {
        let mut tunnel = open_tunnel(&mut sender).await.expect("CONNECT admitted");
        echo_round_trip(&mut tunnel, b"live").await;
        tunnels.push(tunnel);
    }
    assert_eq!(state.hbone_admission_fence.live_tunnels(), 3);

    let requested_before = state.hbone_admission_fence.sweep_epoch();
    let reevaluations_before = state.hbone_admission_fence.reevaluations();

    // Two publications back to back: the first still admits every tunnel, the
    // second denies the principal.
    let first = state.update_config(prepared_config(
        Some(backend_addr.port()),
        vec![allow_client(), allow_other()],
    ));
    assert_eq!(first, ConfigApplyOutcome::Applied);
    let second = state.update_config(prepared_config(
        Some(backend_addr.port()),
        vec![deny_client()],
    ));
    assert_eq!(second, ConfigApplyOutcome::Applied);

    for tunnel in tunnels.iter_mut() {
        assert_tunnel_closed(&mut tunnel.response_body).await;
    }
    wait_for_no_live_tunnels(&state).await;
    wait_for_settled_sweeps(&state).await;

    assert_eq!(
        revocation_counts(&state),
        [0, 0, 0, 0, 3, 0, 0, 0],
        "each live tunnel is revoked exactly once"
    );
    let fence = &state.hbone_admission_fence;
    assert!(
        fence.sweep_epoch() >= requested_before + 2,
        "both publications must be counted as sweep requests"
    );
    let reevaluations = fence.reevaluations() - reevaluations_before;
    assert!(
        (3..=6).contains(&reevaluations),
        "coalescing bounds the work at one pass per publication over three \
         tunnels, and at least one full pass must have run; got {reevaluations}"
    );

    let _ = shutdown_tx.send(true);
    backend_handle.abort();
    conn_task.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_revoked_tunnel_never_counts_as_an_hbone_relay_failure() {
    // A proxy id no other test publishes, so the assertions below read exactly
    // this test's series out of the process-wide registry.
    const METRICS_PROXY_ID: &str = "mesh-hbone-revocation-metrics";

    let certs = generate_hbone_mtls_certs(CLIENT_SPIFFE);
    let (backend_addr, backend_handle) = start_interactive_echo_backend().await;
    let state = build_state(prepared_config_with(
        Some(backend_addr.port()),
        Some(METRICS_PROXY_ID),
        vec![allow_client()],
        Vec::new(),
    ));
    let (gateway_addr, shutdown_tx) =
        start_inbound_gateway(state.clone(), hbone_server_config(&certs)).await;
    let (mut sender, conn_task) =
        connect_hbone_h2_mtls(gateway_addr, hbone_client_config(&certs)).await;

    let mut tunnel = open_tunnel(&mut sender).await.expect("CONNECT admitted");
    echo_round_trip(&mut tunnel, b"before-revocation").await;

    let outcome = state.update_config(prepared_config_with(
        Some(backend_addr.port()),
        Some(METRICS_PROXY_ID),
        vec![deny_client()],
        Vec::new(),
    ));
    assert_eq!(outcome, ConfigApplyOutcome::Applied);

    assert_tunnel_closed(&mut tunnel.response_body).await;
    wait_for_no_live_tunnels(&state).await;
    // The relay records its outcome just after deregistering; give that tail a
    // moment so an incorrectly classified failure would be visible below.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let rendered = ferrum_edge::plugins::prometheus_metrics::global_registry().render_uncached();
    assert!(
        rendered.contains(&format!(
            "ferrum_mesh_hbone_tunnel_revocations_total{{proxy_id=\"{METRICS_PROXY_ID}\",\
             reason=\"authorization_denied\""
        )),
        "the revocation must be counted on the fence's own family: {rendered}"
    );
    assert!(
        !rendered.contains(&format!(
            "ferrum_mesh_hbone_relay_failures_total{{proxy_id=\"{METRICS_PROXY_ID}\""
        )),
        "a policy revocation must never increment the relay-failure family: {rendered}"
    );

    let _ = shutdown_tx.send(true);
    backend_handle.abort();
    conn_task.abort();
}

/// Gate ORDER, not just gate coverage: the sweep's `reason` label and the
/// operator log line are the only attribution a revocation carries, so a tunnel
/// that fails two gates must be attributed the one its peer's next CONNECT
/// would actually be refused with. The request path authorizes in
/// `handle_proxy_request_inner` BEFORE it branches into `handle_hbone_request`,
/// which only then checks the PeerAuthentication transport mode — so
/// `authorization_denied` outranks `peer_auth_transport`, and a rollout
/// dashboard watching `ferrum_mesh_hbone_tunnel_revocations_total` by `reason`
/// agrees with what the client sees on its next CONNECT.
#[tokio::test(flavor = "multi_thread")]
async fn an_authorization_denial_outranks_a_transport_mismatch_in_one_sweep() {
    const APP_PORT: u16 = 8080;
    // The published generation already DENIES this principal, so the authorize
    // gate is armed before the tunnel is ever registered.
    let state = build_state(prepared_config(Some(APP_PORT), vec![deny_client()]));
    let fence = &state.hbone_admission_fence;
    let proxy = Arc::new(create_mesh_proxy(APP_PORT));

    let tunnel = fence.admit(dual_gate_snapshot(proxy, fence.sweep_epoch()));
    assert_eq!(tunnel.revoked_reason(), None);
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0, 0, 0, 0, 0]);

    // STRICT arms the transport gate for this plaintext tunnel AND is what
    // schedules the single sweep that now sees both gates failing.
    state.publish_mesh_inbound_tls_policy(MeshInboundTlsPolicy {
        default_mode: MtlsMode::Strict,
        ..MeshInboundTlsPolicy::default()
    });

    wait_for_revocation(&tunnel).await;
    assert_eq!(
        tunnel.revoked_reason(),
        Some(HboneRevocationReason::AuthorizationDenied),
        "a tunnel failing both gates must carry the reason the CONNECT path would refuse it \
         with, not the reason the sweep happened to evaluate first"
    );
    assert_eq!(
        revocation_counts(&state),
        [0, 0, 0, 0, 1, 0, 0, 0],
        "exactly one authorization_denied revocation, and no peer_auth_transport one"
    );
    assert!(
        fence.reevaluations() >= 1,
        "the authorize chain must actually have run for the live tunnel"
    );
}

/// Retirement and revocation are ONE compare-exchange against the same terminal
/// state, so exactly one wins. When the relay wins, the tunnel is neither
/// counted, metered, nor classified as revoked: two separate atomics let a
/// sweep that read "not retired" microseconds before the relay ended still
/// increment `revocations[..]` and log a revocation for a tunnel carrying no
/// bytes — and the datagram relay, which reads `revoked_reason()` AFTER
/// `retire()` and has no `first_failure` to cross-check against, then reported
/// an ordinary idle/EOF close as an admission revocation.
#[tokio::test(flavor = "multi_thread")]
async fn a_tunnel_the_relay_retired_first_is_never_counted_or_classified_as_revoked() {
    let destination = relay_destination(RELAY_APP_HOST, RELAY_APP_PORT);
    let state = build_state(relay_destination_config(vec![destination], false, 9501));
    let fence = &state.hbone_admission_fence;

    let tunnel = fence.admit(synthetic_snapshot(
        inbound_relay_proxy(RELAY_APP_HOST, RELAY_APP_PORT),
        HboneRelayDestinationGate::InboundRelay,
        None,
        fence.sweep_epoch(),
    ));
    assert!(
        tunnel.retire(),
        "the relay ended first, so it owns the terminal transition"
    );
    assert!(!tunnel.retire(), "the terminal transition is one-shot");
    assert_eq!(fence.live_tunnels(), 0);

    // Exactly the publication that WOULD have revoked this tunnel.
    let outcome = state.update_config(relay_destination_config(Vec::new(), false, 9502));
    assert_eq!(outcome, ConfigApplyOutcome::Applied);
    wait_for_settled_sweeps(&state).await;

    assert_eq!(
        tunnel.revoked_reason(),
        None,
        "a retired tunnel must never be classified as revoked"
    );
    assert_eq!(
        revocation_counts(&state),
        [0, 0, 0, 0, 0, 0, 0, 0],
        "a retired tunnel must never be counted as a revocation"
    );
    assert!(
        !tunnel.revocation_token().is_cancelled(),
        "a retired tunnel's relay must not be told the fence cut it"
    );
}

/// The other side of the same transition. Once a sweep has claimed a tunnel,
/// the relay's `retire()` loses and the recorded reason stays readable — which
/// is exactly what the datagram relay depends on, because it calls `retire()`
/// and THEN reads `revoked_reason()` to classify its own close.
#[tokio::test(flavor = "multi_thread")]
async fn a_revoked_tunnels_reason_survives_the_relays_retire() {
    let destination = relay_destination(RELAY_APP_HOST, RELAY_APP_PORT);
    let state = build_state(relay_destination_config(vec![destination], false, 9601));
    let fence = &state.hbone_admission_fence;

    let tunnel = fence.admit(synthetic_snapshot(
        inbound_relay_proxy(RELAY_APP_HOST, RELAY_APP_PORT),
        HboneRelayDestinationGate::InboundRelay,
        None,
        fence.sweep_epoch(),
    ));
    let outcome = state.update_config(relay_destination_config(Vec::new(), false, 9602));
    assert_eq!(outcome, ConfigApplyOutcome::Applied);
    wait_for_revocation(&tunnel).await;

    assert!(
        !tunnel.retire(),
        "a sweep already owns the terminal transition for this tunnel"
    );
    assert_eq!(
        tunnel.revoked_reason(),
        Some(HboneRevocationReason::RelayDestination),
        "the reason must outlive the relay's retire(), or the datagram relay misreports it"
    );
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0, 0, 0, 1, 0]);
}

// ── Credential dimension (issue #5568) ────────────────────────────────────

/// The peer's trust domain, as it appears in [`CLIENT_SPIFFE`].
const PEER_TRUST_DOMAIN: &str = "cluster.local";
/// The gateway's own workload identity. Never consulted by the fence, which
/// reads only the trust bundles, but a real SVID keeps the published slot the
/// shape every other consumer expects.
const GATEWAY_SPIFFE: &str = "spiffe://cluster.local/ns/default/sa/gateway";
/// `backend_port` on the configured proxy the credential fixtures name.
///
/// No socket is ever bound to it and nothing dials it: these fixtures register
/// a snapshot with the fence directly and assert on the sweep's verdict, so the
/// value is only a field on a `Proxy` struct — the same way the relay-
/// destination fixtures above use their generation tag.
const CREDENTIAL_BACKEND_PORT: u16 = 9600;

/// The serial every minted leaf carries, so a CRL fixture can name it without
/// re-parsing the certificate (issue #5574). Fixed rather than random because
/// the revocation tests turn on "this serial versus another one", and the other
/// one is [`UNRELATED_LEAF_SERIAL`].
const PEER_LEAF_SERIAL: u64 = 0x5574;
/// A serial no minted leaf carries. A CRL listing only this must revoke nothing.
const UNRELATED_LEAF_SERIAL: u64 = 0x5575;

/// A self-signed CA plus one SPIFFE leaf it issued, both DER.
///
/// Minted here rather than borrowed from `mesh_hbone_tests` so these tests own
/// the issuing root they assert about: several of them turn on one chain
/// anchoring in one bundle and not in another.
///
/// The issuer is retained (issue #5574) because the revocation tests have to
/// sign a CRL with the very key that issued the leaf — a CRL signed by anything
/// else is not the authority for that chain and webpki would ignore it, which
/// would make a revocation test pass for the wrong reason.
struct PeerChain {
    ca_der: Vec<u8>,
    leaf_der: Vec<u8>,
    issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
}

fn mint_peer_chain(spiffe: &str) -> PeerChain {
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
        KeyPair, KeyUsagePurpose, SanType, SerialNumber, string::Ia5String,
    };

    let ca_key = KeyPair::generate().expect("ca key");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, format!("{spiffe} issuing CA"));
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_cert = ca_params.self_signed(&ca_key).expect("self-signed ca");
    let ca_der = ca_cert.der().to_vec();
    // `Issuer::new` consumes the params + key, so capture the CA DER first.
    let issuer = Issuer::new(ca_params, ca_key);

    let leaf_key = KeyPair::generate().expect("leaf key");
    let mut leaf_params = CertificateParams::new(Vec::<String>::new()).expect("leaf params");
    leaf_params.serial_number = Some(SerialNumber::from(PEER_LEAF_SERIAL));
    leaf_params.subject_alt_names.push(SanType::URI(
        Ia5String::try_from(spiffe.to_string()).expect("spiffe uri san"),
    ));
    leaf_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let leaf = leaf_params.signed_by(&leaf_key, &issuer).expect("leaf");

    PeerChain {
        ca_der,
        leaf_der: leaf.der().to_vec(),
        issuer,
    }
}

/// A properly signed, in-window CRL from `chain`'s CA revoking `serials`.
///
/// Signed by the chain's own issuer so it is authoritative for that chain; the
/// window brackets now, so `enforce_revocation_expiration()` — which the shared
/// CRL policy always sets — accepts it.
fn signed_crl(chain: &PeerChain, serials: &[u64]) -> CertificateRevocationListDer<'static> {
    signed_crl_in_window(
        chain,
        serials,
        time::OffsetDateTime::now_utc() - time::Duration::hours(1),
        time::OffsetDateTime::now_utc() + time::Duration::days(30),
    )
}

fn signed_crl_in_window(
    chain: &PeerChain,
    serials: &[u64],
    this_update: time::OffsetDateTime,
    next_update: time::OffsetDateTime,
) -> CertificateRevocationListDer<'static> {
    let revoked_certs = serials
        .iter()
        .map(|serial| rcgen::RevokedCertParams {
            serial_number: rcgen::SerialNumber::from(*serial),
            revocation_time: this_update,
            reason_code: Some(rcgen::RevocationReason::KeyCompromise),
            invalidity_date: None,
        })
        .collect();
    let params = rcgen::CertificateRevocationListParams {
        this_update,
        next_update,
        crl_number: rcgen::SerialNumber::from(1u64),
        issuing_distribution_point: None,
        revoked_certs,
        key_identifier_method: rcgen::KeyIdMethod::Sha256,
    };
    CertificateRevocationListDer::from(
        params
            .signed_by(&chain.issuer)
            .expect("sign CRL")
            .der()
            .to_vec(),
    )
}

/// The enforced mesh inbound CRL generation the fence and the inbound SPIFFE
/// verifier both read.
fn mesh_inbound_crl_generation(state: &ProxyState) -> u64 {
    state.mesh_inbound_crls.load().generation()
}

/// Publish `records` as the enforced mesh inbound CRL set, through the one
/// writer production uses. Returns whether the enforced set actually changed.
fn publish_crls(state: &ProxyState, records: Vec<CertificateRevocationListDer<'static>>) -> bool {
    state.publish_mesh_inbound_crls(Arc::new(records))
}

/// An SVID slot carrying `authorities` for [`PEER_TRUST_DOMAIN`], shaped exactly
/// as `publish_gateway_trust` shapes the published bundle.
///
/// The handshake half of these tests needs a slot of its own because
/// `build_spiffe_client_cert_verifier_with_enforced_crls` takes the slot
/// directly — this is the component the mesh inbound listener installs, so
/// asserting on it is asserting on what the peer's next CONNECT would meet.
fn peer_bundle_slot(gateway: &PeerChain, authorities: Vec<Vec<u8>>) -> tls::SharedBundleSlot {
    let bundle = SvidBundle {
        spiffe_id: SpiffeId::new(GATEWAY_SPIFFE).expect("gateway spiffe id"),
        cert_chain_der: vec![gateway.leaf_der.clone()],
        private_key_pkcs8_der: vec![8, 8, 8].into(),
        trust_bundles: RuntimeTrustBundleSet {
            local: RuntimeTrustBundle {
                trust_domain: TrustDomain::new(PEER_TRUST_DOMAIN).expect("trust domain"),
                x509_authorities: authorities,
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            },
            federated: Default::default(),
        },
    };
    Arc::new(arc_swap::ArcSwap::new(Arc::new(Some(bundle))))
}

/// Whether the inbound SPIFFE peer verifier the mesh listener builds from
/// `state`'s LIVE enforced CRL slot still accepts `peer`'s leaf.
///
/// This is the "next CONNECT" half of issue #5574: the fence cuts the live
/// tunnel, and the same published CRL must also refuse the peer's next
/// handshake — otherwise a revoked workload simply reconnects.
fn inbound_handshake_admits(
    state: &ProxyState,
    slot: &tls::SharedBundleSlot,
    peer: &PeerChain,
) -> bool {
    let verifier = tls::build_spiffe_client_cert_verifier_with_enforced_crls(
        slot.clone(),
        true,
        Arc::clone(&state.mesh_inbound_crls),
    );
    rustls::server::danger::ClientCertVerifier::verify_client_cert(
        verifier.as_ref(),
        &rustls::pki_types::CertificateDer::from(peer.leaf_der.clone()),
        &[],
        rustls::pki_types::UnixTime::now(),
    )
    .is_ok()
}

/// Publish one gateway trust generation carrying exactly `authorities` for
/// `trust_domain`.
///
/// Goes through `install_gateway_runtime_svid_bundle`, the production SVID
/// source-rotation entry point, so the publication really is the complete
/// fence → install → retire → commit transaction that ends at
/// `publish_live_gateway_trust` — the one writer that schedules the sweep.
fn publish_gateway_trust(
    state: &ProxyState,
    gateway: &PeerChain,
    trust_domain: &str,
    authorities: Vec<Vec<u8>>,
) {
    let _withdrew = state.install_gateway_runtime_svid_bundle(SvidBundle {
        spiffe_id: SpiffeId::new(GATEWAY_SPIFFE).expect("gateway spiffe id"),
        cert_chain_der: vec![gateway.leaf_der.clone()],
        private_key_pkcs8_der: vec![8, 8, 8].into(),
        trust_bundles: RuntimeTrustBundleSet {
            local: RuntimeTrustBundle {
                trust_domain: TrustDomain::new(trust_domain).expect("trust domain"),
                x509_authorities: authorities,
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            },
            federated: Default::default(),
        },
    });
}

fn gateway_trust_generation(state: &ProxyState) -> u64 {
    state.request_epoch.load().gateway_trust().generation()
}

/// A credential deadline far enough out that the expiry half of the gate never
/// fires, so a test isolates the trust half.
fn live_deadline() -> Option<tokio::time::Instant> {
    Some(tokio::time::Instant::now() + Duration::from_secs(3600))
}

fn peer_credential(
    chain: &PeerChain,
    leaf_not_after: Option<tokio::time::Instant>,
    anchored_at_admission: bool,
) -> HbonePeerCredential {
    HbonePeerCredential {
        spiffe_id: SpiffeId::new(CLIENT_SPIFFE).expect("client spiffe id"),
        leaf_der: Arc::new(chain.leaf_der.clone()),
        intermediates_der: None,
        leaf_not_after,
        anchored_at_admission,
    }
}

/// An admission snapshot whose ONLY live gate is the credential one.
///
/// A configured proxy (so the relay-destination guard does not apply and no
/// lifecycle generation is recorded), no mesh direction (so the transport gate
/// is inapplicable), and a published generation carrying no authorize plugins
/// at all — see [`relay_destination_config`], which does not run mesh
/// preparation.
fn credential_snapshot(
    admission_sweep_epoch: u64,
    gateway_trust_generation: u64,
    peer_credential: HbonePeerCredential,
) -> HboneAdmissionSnapshot {
    let mut snapshot = synthetic_snapshot(
        create_mesh_proxy(CREDENTIAL_BACKEND_PORT),
        HboneRelayDestinationGate::Configured,
        None,
        admission_sweep_epoch,
    );
    snapshot.gateway_trust_generation = gateway_trust_generation;
    snapshot.peer_credential = Some(peer_credential);
    snapshot
}

/// A state whose published generation exercises nothing but the credential
/// gate: no relay inventory, no policies, no injected plugins.
fn credential_state(generation_tag: u16) -> ProxyState {
    build_state(relay_destination_config(Vec::new(), false, generation_tag))
}

#[tokio::test(flavor = "multi_thread")]
async fn a_trust_rotation_that_keeps_the_peer_anchored_revokes_nothing() {
    let gateway = mint_peer_chain(GATEWAY_SPIFFE);
    let peer = mint_peer_chain(CLIENT_SPIFFE);
    let joining = mint_peer_chain(OTHER_SPIFFE);
    let state = credential_state(9601);

    publish_gateway_trust(
        &state,
        &gateway,
        PEER_TRUST_DOMAIN,
        vec![peer.ca_der.clone()],
    );
    let admitted_generation = gateway_trust_generation(&state);
    let fence = &state.hbone_admission_fence;
    let tunnel = fence.admit(credential_snapshot(
        fence.sweep_epoch(),
        admitted_generation,
        peer_credential(&peer, live_deadline(), true),
    ));
    assert_eq!(tunnel.revoked_reason(), None);

    // A CA rotation that ADDS a root: a real new generation, and the authority
    // that issued this peer's leaf is still in it.
    publish_gateway_trust(
        &state,
        &gateway,
        PEER_TRUST_DOMAIN,
        vec![peer.ca_der.clone(), joining.ca_der.clone()],
    );
    assert!(
        gateway_trust_generation(&state) > admitted_generation,
        "the rotation must advance the gateway trust generation, or the sweep would \
         legitimately skip the chain re-verification and prove nothing"
    );
    wait_for_settled_sweeps(&state).await;

    assert_eq!(tunnel.revoked_reason(), None);
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(fence.live_tunnels(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn withdrawing_the_peers_trust_domain_revokes_its_live_tunnel() {
    let gateway = mint_peer_chain(GATEWAY_SPIFFE);
    let peer = mint_peer_chain(CLIENT_SPIFFE);
    let state = credential_state(9602);

    publish_gateway_trust(
        &state,
        &gateway,
        PEER_TRUST_DOMAIN,
        vec![peer.ca_der.clone()],
    );
    let fence = &state.hbone_admission_fence;
    let tunnel = fence.admit(credential_snapshot(
        fence.sweep_epoch(),
        gateway_trust_generation(&state),
        peer_credential(&peer, live_deadline(), true),
    ));
    assert_eq!(tunnel.revoked_reason(), None);

    // The federated trust domain is retired. The peer's own issuing root is
    // still in the published material — it simply no longer names a trust
    // domain this gateway accepts, which is exactly what a fresh handshake
    // would refuse.
    publish_gateway_trust(&state, &gateway, "partner.local", vec![peer.ca_der.clone()]);

    wait_for_revocation(&tunnel).await;
    assert_eq!(
        tunnel.revoked_reason(),
        Some(HboneRevocationReason::PeerTrust),
        "a retired trust domain is a credential withdrawal, not a policy denial"
    );
    assert_eq!(revocation_counts(&state), [0, 0, 1, 0, 0, 0, 0, 0]);
}

#[tokio::test(flavor = "multi_thread")]
async fn rotating_away_the_issuing_authority_revokes_its_live_tunnel() {
    let gateway = mint_peer_chain(GATEWAY_SPIFFE);
    let peer = mint_peer_chain(CLIENT_SPIFFE);
    let replacement = mint_peer_chain(OTHER_SPIFFE);
    let state = credential_state(9603);

    publish_gateway_trust(
        &state,
        &gateway,
        PEER_TRUST_DOMAIN,
        vec![peer.ca_der.clone()],
    );
    let fence = &state.hbone_admission_fence;
    let tunnel = fence.admit(credential_snapshot(
        fence.sweep_epoch(),
        gateway_trust_generation(&state),
        peer_credential(&peer, live_deadline(), true),
    ));
    assert_eq!(tunnel.revoked_reason(), None);

    // Same trust domain, different root: the retained chain no longer builds a
    // path. Only re-verifying the chain can see this — the trust domain is
    // still present, so a membership check alone would keep the tunnel.
    publish_gateway_trust(
        &state,
        &gateway,
        PEER_TRUST_DOMAIN,
        vec![replacement.ca_der.clone()],
    );

    wait_for_revocation(&tunnel).await;
    assert_eq!(
        tunnel.revoked_reason(),
        Some(HboneRevocationReason::PeerTrust)
    );
    assert_eq!(revocation_counts(&state), [0, 0, 1, 0, 0, 0, 0, 0]);
}

/// The one revocation nothing publishes. An established inbound mTLS session is
/// never re-handshaked, so a peer SVID that simply ages out on an otherwise
/// quiet mesh is ended by the fence's own expiry watcher or by nothing at all.
#[tokio::test(flavor = "multi_thread")]
async fn an_expired_peer_svid_is_revoked_with_no_publication_at_all() {
    let peer = mint_peer_chain(CLIENT_SPIFFE);
    let state = credential_state(9604);
    let fence = &state.hbone_admission_fence;
    let sweep_epoch_before = fence.sweep_epoch();

    // `Instant::now()` is monotonic and non-decreasing and the gate compares
    // `>=`, so this deadline is already elapsed for every later clock read —
    // without the panic risk of subtracting from a fresh monotonic instant.
    let tunnel = fence.admit(credential_snapshot(
        sweep_epoch_before,
        gateway_trust_generation(&state),
        peer_credential(&peer, Some(tokio::time::Instant::now()), false),
    ));

    wait_for_revocation(&tunnel).await;
    assert_eq!(
        tunnel.revoked_reason(),
        Some(HboneRevocationReason::PeerExpired),
        "an aged-out leaf is `peer_expired`, never folded into the trust verdict"
    );
    assert_eq!(revocation_counts(&state), [0, 1, 0, 0, 0, 0, 0, 0]);
    assert_eq!(
        fence.sweep_epoch(),
        sweep_epoch_before,
        "the expiry watcher must sweep directly, not through the coalescing \
         publication counter"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_trust_bundle_that_cannot_be_compiled_fails_closed() {
    let gateway = mint_peer_chain(GATEWAY_SPIFFE);
    let peer = mint_peer_chain(CLIENT_SPIFFE);
    let state = credential_state(9605);

    publish_gateway_trust(
        &state,
        &gateway,
        PEER_TRUST_DOMAIN,
        vec![peer.ca_der.clone()],
    );
    let fence = &state.hbone_admission_fence;
    let tunnel = fence.admit(credential_snapshot(
        fence.sweep_epoch(),
        gateway_trust_generation(&state),
        peer_credential(&peer, live_deadline(), true),
    ));
    assert_eq!(tunnel.revoked_reason(), None);

    // The published generation still declares the peer's trust domain, but its
    // authorities are not usable trust roots, so the sweep can produce no
    // verdict for anything anchored there.
    publish_gateway_trust(
        &state,
        &gateway,
        PEER_TRUST_DOMAIN,
        vec![b"not-a-certificate".to_vec()],
    );

    wait_for_revocation(&tunnel).await;
    assert_eq!(
        tunnel.revoked_reason(),
        Some(HboneRevocationReason::ReevaluationFailed),
        "an unjudgeable trust state cuts the tunnel rather than leaving it serving"
    );
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0, 0, 0, 0, 1]);
}

/// The guard against a false mass revocation: a mesh inbound listener with no
/// gateway SVID material verifies peers chain-only against the operator client
/// CA bundle, which the request epoch's gateway trust does not describe at all.
/// Such a tunnel was never anchored by a gateway trust generation, so the trust
/// half of the gate must never judge it.
#[tokio::test(flavor = "multi_thread")]
async fn a_peer_the_admitting_generation_never_anchored_is_not_revoked_for_trust() {
    let gateway = mint_peer_chain(GATEWAY_SPIFFE);
    let peer = mint_peer_chain(CLIENT_SPIFFE);
    let unrelated = mint_peer_chain(OTHER_SPIFFE);
    let state = credential_state(9606);

    // The admitting generation carries a bundle for an unrelated trust domain,
    // so it never anchored this peer.
    publish_gateway_trust(
        &state,
        &gateway,
        "partner.local",
        vec![unrelated.ca_der.clone()],
    );
    let fence = &state.hbone_admission_fence;
    let tunnel = fence.admit(credential_snapshot(
        fence.sweep_epoch(),
        gateway_trust_generation(&state),
        peer_credential(&peer, live_deadline(), false),
    ));

    publish_gateway_trust(&state, &gateway, "other.local", vec![unrelated.ca_der]);
    wait_for_settled_sweeps(&state).await;

    assert_eq!(tunnel.revoked_reason(), None);
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(fence.live_tunnels(), 1);
}

/// The credential gate is only as good as the publication that schedules it.
/// `publish_live_gateway_trust` is the ONE writer of the request-facing trust
/// generation, and every trust publisher — an accepted `Replace`/`Clear`, a
/// SPIRE/file/CA-backend SVID source rotation, and the request-epoch
/// publication — ends there. Pinning the sweep request inside it is what keeps
/// a future publisher from growing its own path and silently leaving live
/// tunnels judged against retired trust.
#[test]
fn the_single_gateway_trust_publisher_requests_a_sweep() {
    let source = include_str!("../../src/proxy/mod.rs");
    let start = source
        .find("fn publish_live_gateway_trust(&self) {")
        .expect("publish_live_gateway_trust must exist");
    let body = &source[start..];
    let end = body
        .find("\n    /// Whether request paths may authenticate gateway-to-mesh peers")
        .expect("admits_gateway_mesh_identity follows the live-trust publisher");
    let func = &body[..end];

    let store = func
        .find("self.request_epoch.update_gateway_trust(")
        .expect("the epoch store is what publishes the trust generation");
    let sweep = func
        .find("self.hbone_admission_fence.request_sweep()")
        .expect("every gateway trust publication must schedule an admission-fence sweep");
    assert!(
        store < sweep,
        "publish-then-recheck: the sweep must be requested AFTER the store, or a CONNECT that \
         read the superseded trust could register between them and never be re-judged"
    );
}

// ── Revocation dimension: the mesh inbound CRL (issue #5574) ──────────────

/// The gap #5574 closes. A CRL that revokes an already-admitted peer's leaf
/// must cut the live tunnel, not wait for a handshake that an established mTLS
/// session will never perform again — and the same published CRL must also
/// refuse that peer's next CONNECT, or a revoked workload simply reconnects.
///
/// The gateway trust generation is deliberately NOT republished here: the
/// assertion below that it is unchanged across the CRL publication is what
/// proves the revocation was driven by the CRL generation alone.
#[tokio::test(flavor = "multi_thread")]
async fn a_crl_revoking_the_admitted_leaf_revokes_the_tunnel_and_refuses_the_next_handshake() {
    let gateway = mint_peer_chain(GATEWAY_SPIFFE);
    let peer = mint_peer_chain(CLIENT_SPIFFE);
    let state = credential_state(9640);

    publish_gateway_trust(
        &state,
        &gateway,
        PEER_TRUST_DOMAIN,
        vec![peer.ca_der.clone()],
    );
    let admitted_trust_generation = gateway_trust_generation(&state);
    let handshake_slot = peer_bundle_slot(&gateway, vec![peer.ca_der.clone()]);
    assert!(
        inbound_handshake_admits(&state, &handshake_slot, &peer),
        "the peer's credential must be admissible before anything revokes it"
    );

    let fence = &state.hbone_admission_fence;
    let mut snapshot = credential_snapshot(
        fence.sweep_epoch(),
        admitted_trust_generation,
        peer_credential(&peer, live_deadline(), true),
    );
    snapshot.mesh_inbound_crl_generation = mesh_inbound_crl_generation(&state);
    let tunnel = fence.admit(snapshot);
    assert_eq!(tunnel.revoked_reason(), None);

    let revoking = signed_crl(&peer, &[PEER_LEAF_SERIAL]);
    assert!(
        publish_crls(&state, vec![revoking]),
        "a CRL carrying records the enforced set did not have is a real publication"
    );
    wait_for_revocation(&tunnel).await;

    assert_eq!(
        tunnel.revoked_reason(),
        Some(HboneRevocationReason::PeerRevoked),
        "a chain that still anchors but whose leaf the enforced CRL lists is `peer_revoked`, \
         not `peer_trust`"
    );
    assert_eq!(revocation_counts(&state), [0, 0, 0, 1, 0, 0, 0, 0]);
    assert_eq!(
        gateway_trust_generation(&state),
        admitted_trust_generation,
        "no trust publication occurred; the CRL generation alone drove this revocation"
    );
    assert!(
        !inbound_handshake_admits(&state, &handshake_slot, &peer),
        "the same published CRL must refuse the peer's next CONNECT handshake, or a revoked \
         workload just reconnects"
    );
}

/// The other side of the gate: a CRL is not a blanket re-admission event. One
/// that lists a serial no live peer carries leaves every tunnel alone, so an
/// operator publishing an unrelated revocation does not churn the mesh.
#[tokio::test(flavor = "multi_thread")]
async fn a_crl_revoking_a_different_serial_revokes_nothing() {
    let gateway = mint_peer_chain(GATEWAY_SPIFFE);
    let peer = mint_peer_chain(CLIENT_SPIFFE);
    let state = credential_state(9641);

    publish_gateway_trust(
        &state,
        &gateway,
        PEER_TRUST_DOMAIN,
        vec![peer.ca_der.clone()],
    );
    let fence = &state.hbone_admission_fence;
    let mut snapshot = credential_snapshot(
        fence.sweep_epoch(),
        gateway_trust_generation(&state),
        peer_credential(&peer, live_deadline(), true),
    );
    snapshot.mesh_inbound_crl_generation = mesh_inbound_crl_generation(&state);
    let tunnel = fence.admit(snapshot);

    let unrelated = signed_crl(&peer, &[UNRELATED_LEAF_SERIAL]);
    assert!(publish_crls(&state, vec![unrelated]));
    wait_for_settled_sweeps(&state).await;

    assert_eq!(
        tunnel.revoked_reason(),
        None,
        "a CRL that does not list this leaf's serial must not revoke it"
    );
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(fence.live_tunnels(), 1);
}

/// The fast path must key on BOTH generations. Nothing about the gateway trust
/// moves here, so a sweep that skipped on an unchanged trust generation — which
/// is exactly what the fence did before #5574 — would never look at the chain
/// and the revoked peer would keep its tunnel.
///
/// Pins the publication mechanics too: the CRL store schedules a sweep, and a
/// republication of the SAME records schedules none, so an operator's reload
/// cadence never becomes per-tunnel certificate path building.
#[tokio::test(flavor = "multi_thread")]
async fn a_crl_reload_sweeps_and_reverifies_with_no_trust_generation_change() {
    let gateway = mint_peer_chain(GATEWAY_SPIFFE);
    let peer = mint_peer_chain(CLIENT_SPIFFE);
    let state = credential_state(9642);

    publish_gateway_trust(
        &state,
        &gateway,
        PEER_TRUST_DOMAIN,
        vec![peer.ca_der.clone()],
    );
    let admitted_trust_generation = gateway_trust_generation(&state);
    let admitted_crl_generation = mesh_inbound_crl_generation(&state);
    let fence = &state.hbone_admission_fence;
    let mut snapshot = credential_snapshot(
        fence.sweep_epoch(),
        admitted_trust_generation,
        peer_credential(&peer, live_deadline(), true),
    );
    snapshot.mesh_inbound_crl_generation = admitted_crl_generation;
    let tunnel = fence.admit(snapshot);
    wait_for_settled_sweeps(&state).await;
    let sweeps_before = fence.sweeps_completed();

    let revoking = signed_crl(&peer, &[PEER_LEAF_SERIAL]);
    assert!(publish_crls(&state, vec![revoking.clone()]));
    assert_eq!(
        mesh_inbound_crl_generation(&state),
        admitted_crl_generation + 1,
        "publishing new records advances the enforced generation by exactly one"
    );
    wait_for_revocation(&tunnel).await;

    assert!(
        fence.sweeps_completed() > sweeps_before,
        "the CRL publication must schedule a sweep of its own"
    );
    assert_eq!(
        gateway_trust_generation(&state),
        admitted_trust_generation,
        "the trust generation never moved; only the CRL generation did"
    );
    assert_eq!(
        tunnel.revoked_reason(),
        Some(HboneRevocationReason::PeerRevoked)
    );

    // Republishing the identical records is not a rotation: no generation bump
    // and no sweep, so a periodic reload of an unchanged CRL file is free.
    let settled = fence.sweeps_completed();
    let generation = mesh_inbound_crl_generation(&state);
    assert!(
        !publish_crls(&state, vec![revoking]),
        "byte-identical records are not a new enforced set"
    );
    assert_eq!(mesh_inbound_crl_generation(&state), generation);
    wait_for_settled_sweeps(&state).await;
    assert_eq!(
        fence.sweeps_completed(),
        settled,
        "an unchanged republication must schedule no sweep at all"
    );
}

/// Fail closed. An enforced CRL that cannot be attached to a verifier leaves
/// the fence unable to answer the revocation question for an anchored tunnel,
/// and an un-judgeable tunnel is cut rather than left serving — never a silent
/// skip back to "no revocation data".
#[tokio::test(flavor = "multi_thread")]
async fn an_unusable_crl_fails_closed() {
    let gateway = mint_peer_chain(GATEWAY_SPIFFE);
    let peer = mint_peer_chain(CLIENT_SPIFFE);
    let state = credential_state(9643);

    publish_gateway_trust(
        &state,
        &gateway,
        PEER_TRUST_DOMAIN,
        vec![peer.ca_der.clone()],
    );
    let fence = &state.hbone_admission_fence;
    let mut snapshot = credential_snapshot(
        fence.sweep_epoch(),
        gateway_trust_generation(&state),
        peer_credential(&peer, live_deadline(), true),
    );
    snapshot.mesh_inbound_crl_generation = mesh_inbound_crl_generation(&state);
    let tunnel = fence.admit(snapshot);

    // Not a CRL at all. The enforced set is non-empty, so the shared CRL policy
    // attaches it and the verifier build fails — the trust domain compiles to
    // "unusable", which is an inability to judge, not a withdrawal.
    let not_a_crl = CertificateRevocationListDer::from(vec![0x30, 0x03, 0x02, 0x01, 0x00]);
    assert!(publish_crls(&state, vec![not_a_crl]));
    wait_for_revocation(&tunnel).await;

    assert_eq!(
        tunnel.revoked_reason(),
        Some(HboneRevocationReason::ReevaluationFailed),
        "an enforced CRL set that cannot be applied must fail closed, not skip"
    );
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0, 0, 0, 0, 1]);
}

/// A CRL that has itself aged past `nextUpdate` can no longer answer the
/// revocation question either. The shared policy always sets
/// `enforce_revocation_expiration()`, so this is the same fail-closed
/// direction `crl_policy::validate_crl_windows` takes at admission, applied to
/// a list that aged out after it was admitted.
#[tokio::test(flavor = "multi_thread")]
async fn an_expired_crl_fails_closed() {
    let gateway = mint_peer_chain(GATEWAY_SPIFFE);
    let peer = mint_peer_chain(CLIENT_SPIFFE);
    let state = credential_state(9644);

    publish_gateway_trust(
        &state,
        &gateway,
        PEER_TRUST_DOMAIN,
        vec![peer.ca_der.clone()],
    );
    let fence = &state.hbone_admission_fence;
    let mut snapshot = credential_snapshot(
        fence.sweep_epoch(),
        gateway_trust_generation(&state),
        peer_credential(&peer, live_deadline(), true),
    );
    snapshot.mesh_inbound_crl_generation = mesh_inbound_crl_generation(&state);
    let tunnel = fence.admit(snapshot);

    let now = time::OffsetDateTime::now_utc();
    let expired = signed_crl_in_window(
        &peer,
        &[UNRELATED_LEAF_SERIAL],
        now - time::Duration::days(30),
        now - time::Duration::days(1),
    );
    assert!(publish_crls(&state, vec![expired]));
    wait_for_revocation(&tunnel).await;

    assert_eq!(
        tunnel.revoked_reason(),
        Some(HboneRevocationReason::ReevaluationFailed),
        "an enforced CRL past its own nextUpdate must fail closed"
    );
}

/// The `reason` label is an operator's only attribution, so its order is a
/// contract, not a detail: a tunnel failing several gates carries the one its
/// peer's next CONNECT would actually be refused with.
///
/// The three credential arms follow webpki's own path-building sequence:
/// `notAfter` is validated before any trust anchor is considered, the
/// trust-anchor loop defaults to `UnknownIssuer`, and revocation is consulted
/// only inside the signed-chain check — i.e. only once a candidate anchor has
/// matched. So expiry wins over anchoring, and anchoring wins over revocation.
#[test]
fn the_revocation_reason_order_is_pinned() {
    let labels: Vec<&'static str> = [
        HboneRevocationReason::ProxyWithdrawn,
        HboneRevocationReason::PeerExpired,
        HboneRevocationReason::PeerTrust,
        HboneRevocationReason::PeerRevoked,
        HboneRevocationReason::AuthorizationDenied,
        HboneRevocationReason::PeerAuthTransport,
        HboneRevocationReason::RelayDestination,
        HboneRevocationReason::ReevaluationFailed,
    ]
    .iter()
    .map(|reason| reason.as_str())
    .collect();

    assert_eq!(
        labels,
        vec![
            "proxy_withdrawn",
            "peer_expired",
            "peer_trust",
            "peer_revoked",
            "authorization_denied",
            "peer_auth_transport",
            "relay_destination",
            "reevaluation_failed",
        ],
        "the closed `reason` set and its gate order are pinned by docs/mesh.md, \
         docs/prometheus_metrics.md, and docs/prometheus_metric_contract.json"
    );
}
