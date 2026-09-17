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
//! an established inbound mTLS session is never re-handshaked. Its trust input
//! is the INBOUND ADMISSION SLOT — the `tls::SharedBundleSlot` the mesh SPIFFE
//! client-certificate verifier reads — not the request epoch's gateway trust,
//! because the fence's verdict means "this peer's next CONNECT would be
//! refused" and that is the verifier which would refuse it:
//!
//! * a trust rotation that still anchors the peer revokes nothing, and costs
//!   exactly one certificate path build per tunnel;
//! * a root rotation the inbound verifier ACCEPTED keeps live tunnels, even
//!   while the request epoch's separately-built bundles never carried that root
//!   — the false-mass-revocation regression the independent review found;
//! * withdrawing the peer's trust domain (local or federated), and rotating
//!   away the authority that issued its leaf, each revoke with `peer_trust`;
//! * an unchanged republish — including one beneath a rotated gateway leaf —
//!   revokes nothing and does NO certificate path building, and a tunnel
//!   already verified against the current revision never rebuilds its path;
//! * an admitted SVID past its `notAfter` is revoked by the fence's own expiry
//!   watcher with NO publication of any kind, an unparseable retained leaf
//!   fails closed as `reevaluation_failed` rather than as `peer_expired`, and
//!   an unbounded one is not revoked at all;
//! * a published trust bundle that cannot be compiled into a verifier fails
//!   closed with `reevaluation_failed`;
//! * a peer the admitting inbound trust never anchored — the chain-only inbound
//!   posture — is never revoked for trust;
//! * and the production capture itself runs end to end over a REAL mTLS
//!   handshake: what `HbonePeerCredential::from_admitted_connect` retained is
//!   read back out of the fence's registry, including the case where the slot's
//!   local trust domain is the SVID's own and the slice's differs.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use chrono::Utc;
use hyper::{Method, Request, StatusCode};
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
    AdmittedHboneTunnel, AdmittedLeafExpiry, HboneAdmissionSnapshot, HbonePeerCredential,
    HboneRelayDestinationGate, HboneRevocationReason,
};
use ferrum_edge::proxy::{
    ConfigApplyOutcome, MeshInboundTlsPolicy, ProxyState,
    start_proxy_listener_with_bound_listener_and_mesh_direction,
};
use ferrum_edge::tls::SharedBundleSlot;

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
/// `[proxy_withdrawn, peer_expired, peer_trust, authorization_denied,
///   peer_auth_transport, relay_destination, reevaluation_failed]`.
fn revocation_counts(state: &ProxyState) -> [u64; 7] {
    let fence = &state.hbone_admission_fence;
    [
        fence.revocations(HboneRevocationReason::ProxyWithdrawn),
        fence.revocations(HboneRevocationReason::PeerExpired),
        fence.revocations(HboneRevocationReason::PeerTrust),
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
    /// The inbound SPIFFE verifier's trust slot, when this fixture installed
    /// one. `None` is the chain-only inbound posture: peers are verified
    /// against the operator client-CA bundle and the fence's trust half is
    /// inapplicable.
    inbound_trust_slot: Option<SharedBundleSlot>,
}

async fn admit_client_tunnel(policies: Vec<MeshPolicy>) -> AdmittedFixture {
    admit_client_tunnel_with_inbound_trust(policies, false).await
}

/// One admitted byte-stream tunnel over a REAL inbound mTLS handshake.
///
/// With `install_inbound_trust`, the fence is additionally given an inbound
/// SPIFFE trust slot whose LOCAL bundle is the fixture CA's trust domain — the
/// peer's — and whose federated map carries the slice's differing local domain.
/// That is the exact shape `merge_trust_overlay_into_svid_bundle` produces, and
/// it is the shape under which the request epoch's separately-built bundles
/// would have reported the peer as unanchored.
async fn admit_client_tunnel_with_inbound_trust(
    policies: Vec<MeshPolicy>,
    install_inbound: bool,
) -> AdmittedFixture {
    let certs = generate_hbone_mtls_certs(CLIENT_SPIFFE);
    let (backend_addr, backend_handle) = start_interactive_echo_backend().await;
    let state = build_state(prepared_config(Some(backend_addr.port()), policies));
    let inbound_trust_slot = install_inbound.then(|| {
        let gateway = mint_peer_chain(GATEWAY_SPIFFE);
        let mut federated = std::collections::HashMap::new();
        federated.insert(
            TrustDomain::new(SLICE_TRUST_DOMAIN).expect("slice trust domain"),
            trust_bundle(SLICE_TRUST_DOMAIN, vec![gateway.ca_der.clone()]),
        );
        install_inbound_trust(
            &state,
            &gateway,
            RuntimeTrustBundleSet {
                local: trust_bundle(PEER_TRUST_DOMAIN, vec![certs.ca_der()]),
                federated,
            },
        )
    });
    let (gateway_addr, shutdown_tx) =
        start_inbound_gateway(state.clone(), hbone_server_config(&certs)).await;
    let (mut sender, conn_task) =
        connect_hbone_h2_mtls(gateway_addr, hbone_client_config(&certs)).await;

    let mut tunnel = open_tunnel(&mut sender)
        .await
        .expect("admitted CONNECT under the initial policy generation");
    echo_round_trip(&mut tunnel, b"before-publish").await;
    assert_eq!(state.hbone_admission_fence.live_tunnels(), 1);
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0, 0, 0, 0]);

    AdmittedFixture {
        state,
        tunnel,
        sender,
        conn_task,
        backend_handle,
        backend_port: backend_addr.port(),
        shutdown_tx,
        inbound_trust_slot,
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
        [0, 0, 0, 1, 0, 0, 0],
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
        [0, 0, 0, 1, 0, 0, 0],
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
    assert_eq!(revocation_counts(&fx.state), [0, 0, 0, 0, 0, 0, 0]);
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
        [1, 0, 0, 0, 0, 0, 0],
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
    assert_eq!(revocation_counts(&fx.state), [0, 0, 0, 0, 0, 0, 0]);
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
        [0, 0, 0, 0, 1, 0, 0],
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
        [0, 0, 0, 0, 1, 0, 0],
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
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0, 0, 1, 0]);
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
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0, 0, 1, 0]);
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
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0, 0, 0, 0]);

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
    assert_eq!(revocation_counts(&state), [0, 0, 0, 1, 0, 0, 0]);

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
        [0, 0, 0, 0, 0, 0, 0],
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
        [0, 0, 0, 3, 0, 0, 0],
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
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0, 0, 0, 0]);

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
        [0, 0, 0, 1, 0, 0, 0],
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
        [0, 0, 0, 0, 0, 0, 0],
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
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0, 0, 1, 0]);
}

// ── Credential dimension (issue #5568) ────────────────────────────────────

/// The peer's trust domain, as it appears in [`CLIENT_SPIFFE`].
const PEER_TRUST_DOMAIN: &str = "cluster.local";
/// A second trust domain, used as the domain a slice declares locally when it
/// differs from the gateway SVID's own.
const SLICE_TRUST_DOMAIN: &str = "partner.local";
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

/// A self-signed CA plus one SPIFFE leaf it issued, both DER.
///
/// Minted here rather than borrowed from `mesh_hbone_tests` so these tests own
/// the issuing root they assert about: several of them turn on one chain
/// anchoring in one bundle and not in another.
struct PeerChain {
    ca_der: Vec<u8>,
    leaf_der: Vec<u8>,
}

fn mint_peer_chain(spiffe: &str) -> PeerChain {
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
        KeyPair, KeyUsagePurpose, SanType, string::Ia5String,
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
    }
}

/// One trust domain's bundle.
fn trust_bundle(trust_domain: &str, authorities: Vec<Vec<u8>>) -> RuntimeTrustBundle {
    RuntimeTrustBundle {
        trust_domain: TrustDomain::new(trust_domain).expect("trust domain"),
        x509_authorities: authorities,
        jwt_authorities: Vec::new(),
        refresh_hint_seconds: None,
    }
}

/// A trust set whose local bundle is `trust_domain` and which federates
/// nothing.
fn local_trust(trust_domain: &str, authorities: Vec<Vec<u8>>) -> RuntimeTrustBundleSet {
    RuntimeTrustBundleSet {
        local: trust_bundle(trust_domain, authorities),
        federated: Default::default(),
    }
}

/// An SVID bundle in the shape the mesh inbound SPIFFE verifier's slot carries.
fn inbound_bundle(gateway: &PeerChain, trust_bundles: RuntimeTrustBundleSet) -> SvidBundle {
    SvidBundle {
        spiffe_id: SpiffeId::new(GATEWAY_SPIFFE).expect("gateway spiffe id"),
        cert_chain_der: vec![gateway.leaf_der.clone()],
        private_key_pkcs8_der: vec![8, 8, 8].into(),
        trust_bundles,
    }
}

/// Install the inbound mTLS verifier's trust slot — the slot the fence judges
/// live tunnels against — carrying `trust_bundles`.
///
/// Production wires the ONE slot `mesh_inbound_spiffe_verifier` reads; these
/// fixtures wire an equivalent one, because the fence's contract is defined by
/// what that verifier would accept on the peer's next handshake.
fn install_inbound_trust(
    state: &ProxyState,
    gateway: &PeerChain,
    trust_bundles: RuntimeTrustBundleSet,
) -> SharedBundleSlot {
    let slot = ferrum_edge::tls::shared_bundle_slot(Some(inbound_bundle(gateway, trust_bundles)));
    state.install_mesh_inbound_admission_trust(&slot);
    slot
}

/// Republish the inbound verifier's trust slot through the one production
/// writer, which advances the slot's trust revision when the X.509 material
/// changed and then requests a fence sweep.
fn publish_inbound_trust(
    state: &ProxyState,
    slot: &SharedBundleSlot,
    gateway: &PeerChain,
    trust_bundles: RuntimeTrustBundleSet,
) {
    state.publish_mesh_inbound_trust_bundle(
        slot,
        Arc::new(Some(inbound_bundle(gateway, trust_bundles))),
    );
}

/// Publish one REQUEST-EPOCH gateway trust generation carrying exactly
/// `authorities` for `trust_domain`.
///
/// Goes through `install_gateway_runtime_svid_bundle`, the production SVID
/// source-rotation entry point, so the publication really is the complete
/// fence → install → retire → commit transaction that ends at
/// `publish_live_gateway_trust`.
///
/// Deliberately separate from [`publish_inbound_trust`]: the two really are
/// different material written by different code, which is the whole point of
/// the divergence tests below. The epoch's bundles are the CP/database
/// override; the inbound slot's are what a peer handshake is checked against.
fn publish_gateway_trust(
    state: &ProxyState,
    gateway: &PeerChain,
    trust_domain: &str,
    authorities: Vec<Vec<u8>>,
) {
    let _withdrew = state.install_gateway_runtime_svid_bundle(inbound_bundle(
        gateway,
        local_trust(trust_domain, authorities),
    ));
}

fn gateway_trust_generation(state: &ProxyState) -> u64 {
    state.request_epoch.load().gateway_trust().generation()
}

/// The trust revision the fence's installed inbound slot currently publishes.
fn inbound_trust_revision(state: &ProxyState) -> u64 {
    state
        .hbone_admission_fence
        .inbound_trust_revision()
        .expect("the credential fixtures install an inbound admission trust slot")
}

/// A credential deadline far enough out that the expiry half of the gate never
/// fires, so a test isolates the trust half.
fn live_expiry() -> AdmittedLeafExpiry {
    AdmittedLeafExpiry::At(tokio::time::Instant::now() + Duration::from_secs(3600))
}

fn peer_credential(
    chain: &PeerChain,
    leaf_expiry: AdmittedLeafExpiry,
    anchored_at_admission: bool,
    admitted_trust_revision: u64,
) -> HbonePeerCredential {
    HbonePeerCredential {
        spiffe_id: SpiffeId::new(CLIENT_SPIFFE).expect("client spiffe id"),
        leaf_der: Arc::new(chain.leaf_der.clone()),
        intermediates_der: None,
        leaf_expiry,
        anchored_at_admission,
        admitted_trust_revision,
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
    peer_credential: HbonePeerCredential,
) -> HboneAdmissionSnapshot {
    let mut snapshot = synthetic_snapshot(
        create_mesh_proxy(CREDENTIAL_BACKEND_PORT),
        HboneRelayDestinationGate::Configured,
        None,
        admission_sweep_epoch,
    );
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

    let slot = install_inbound_trust(
        &state,
        &gateway,
        local_trust(PEER_TRUST_DOMAIN, vec![peer.ca_der.clone()]),
    );
    let admitted_revision = inbound_trust_revision(&state);
    let fence = &state.hbone_admission_fence;
    let tunnel = fence.admit(credential_snapshot(
        fence.sweep_epoch(),
        peer_credential(&peer, live_expiry(), true, admitted_revision),
    ));
    assert_eq!(tunnel.revoked_reason(), None);

    // A CA rotation that ADDS a root: a real new revision, and the authority
    // that issued this peer's leaf is still in it.
    publish_inbound_trust(
        &state,
        &slot,
        &gateway,
        local_trust(
            PEER_TRUST_DOMAIN,
            vec![peer.ca_der.clone(), joining.ca_der.clone()],
        ),
    );
    assert!(
        inbound_trust_revision(&state) > admitted_revision,
        "the rotation must advance the inbound trust revision, or the sweep would \
         legitimately skip the chain re-verification and prove nothing"
    );
    wait_for_settled_sweeps(&state).await;

    assert_eq!(tunnel.revoked_reason(), None);
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(fence.live_tunnels(), 1);
    assert_eq!(
        fence.trust_rechecks(),
        1,
        "a trust change costs exactly ONE certificate path build per tunnel"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn withdrawing_the_peers_trust_domain_revokes_its_live_tunnel() {
    let gateway = mint_peer_chain(GATEWAY_SPIFFE);
    let peer = mint_peer_chain(CLIENT_SPIFFE);
    let state = credential_state(9602);

    let slot = install_inbound_trust(
        &state,
        &gateway,
        local_trust(PEER_TRUST_DOMAIN, vec![peer.ca_der.clone()]),
    );
    let fence = &state.hbone_admission_fence;
    let tunnel = fence.admit(credential_snapshot(
        fence.sweep_epoch(),
        peer_credential(&peer, live_expiry(), true, inbound_trust_revision(&state)),
    ));
    assert_eq!(tunnel.revoked_reason(), None);

    // The trust domain is retired. The peer's own issuing root is still in the
    // published material — it simply no longer names a trust domain this
    // gateway accepts, which is exactly what a fresh handshake would refuse.
    publish_inbound_trust(
        &state,
        &slot,
        &gateway,
        local_trust(SLICE_TRUST_DOMAIN, vec![peer.ca_der.clone()]),
    );

    wait_for_revocation(&tunnel).await;
    assert_eq!(
        tunnel.revoked_reason(),
        Some(HboneRevocationReason::PeerTrust),
        "a retired trust domain is a credential withdrawal, not a policy denial"
    );
    assert_eq!(revocation_counts(&state), [0, 0, 1, 0, 0, 0, 0]);
}

/// Withdrawing a FEDERATED trust domain is the same withdrawal as withdrawing
/// the local one, and reaches the peer whose chain anchored there.
#[tokio::test(flavor = "multi_thread")]
async fn withdrawing_a_federated_trust_domain_revokes_its_live_tunnel() {
    let gateway = mint_peer_chain(GATEWAY_SPIFFE);
    let peer = mint_peer_chain(CLIENT_SPIFFE);
    let state = credential_state(9608);

    // The gateway SVID's own domain is the slice's; the peer's domain rides the
    // set as a federated entry, exactly as `merge_trust_overlay_into_svid_bundle`
    // files a cross-domain bundle.
    let mut federated = std::collections::HashMap::new();
    federated.insert(
        TrustDomain::new(PEER_TRUST_DOMAIN).expect("peer trust domain"),
        trust_bundle(PEER_TRUST_DOMAIN, vec![peer.ca_der.clone()]),
    );
    let slot = install_inbound_trust(
        &state,
        &gateway,
        RuntimeTrustBundleSet {
            local: trust_bundle(SLICE_TRUST_DOMAIN, vec![gateway.ca_der.clone()]),
            federated,
        },
    );
    let fence = &state.hbone_admission_fence;
    let tunnel = fence.admit(credential_snapshot(
        fence.sweep_epoch(),
        peer_credential(&peer, live_expiry(), true, inbound_trust_revision(&state)),
    ));
    assert_eq!(tunnel.revoked_reason(), None);

    // The federation is dropped; the local domain is untouched.
    publish_inbound_trust(
        &state,
        &slot,
        &gateway,
        local_trust(SLICE_TRUST_DOMAIN, vec![gateway.ca_der.clone()]),
    );

    wait_for_revocation(&tunnel).await;
    assert_eq!(
        tunnel.revoked_reason(),
        Some(HboneRevocationReason::PeerTrust)
    );
    assert_eq!(revocation_counts(&state), [0, 0, 1, 0, 0, 0, 0]);
}

#[tokio::test(flavor = "multi_thread")]
async fn rotating_away_the_issuing_authority_revokes_its_live_tunnel() {
    let gateway = mint_peer_chain(GATEWAY_SPIFFE);
    let peer = mint_peer_chain(CLIENT_SPIFFE);
    let replacement = mint_peer_chain(OTHER_SPIFFE);
    let state = credential_state(9603);

    let slot = install_inbound_trust(
        &state,
        &gateway,
        local_trust(PEER_TRUST_DOMAIN, vec![peer.ca_der.clone()]),
    );
    let fence = &state.hbone_admission_fence;
    let tunnel = fence.admit(credential_snapshot(
        fence.sweep_epoch(),
        peer_credential(&peer, live_expiry(), true, inbound_trust_revision(&state)),
    ));
    assert_eq!(tunnel.revoked_reason(), None);

    // Same trust domain, different root: the retained chain no longer builds a
    // path. Only re-verifying the chain can see this — the trust domain is
    // still present, so a membership check alone would keep the tunnel.
    publish_inbound_trust(
        &state,
        &slot,
        &gateway,
        local_trust(PEER_TRUST_DOMAIN, vec![replacement.ca_der.clone()]),
    );

    wait_for_revocation(&tunnel).await;
    assert_eq!(
        tunnel.revoked_reason(),
        Some(HboneRevocationReason::PeerTrust)
    );
    assert_eq!(revocation_counts(&state), [0, 0, 1, 0, 0, 0, 0]);
}

/// The regression the independent review of #5573 found, in its own words: a
/// SPIRE CA rotation arrives through the SVID installer, the INBOUND verifier
/// gains the new root and keeps admitting, and the request epoch's gateway
/// trust — which a CP/database override replaces wholesale — does not describe
/// that root at all.
///
/// Judging the tunnel by the epoch revoked every such peer as `peer_trust` and
/// then immediately re-admitted its reconnect, a self-inflicted reconnect storm
/// that contradicted the fence's own "no false mass revocation" claim. Judging
/// it by the slot the handshake reads is the fix, and this pins it: the epoch
/// generation moves twice and never anchors the peer, while the tunnel stays
/// live because the verifier it would be re-handshaked against still does.
#[tokio::test(flavor = "multi_thread")]
async fn a_root_rotation_the_inbound_verifier_accepted_keeps_live_tunnels() {
    let gateway = mint_peer_chain(GATEWAY_SPIFFE);
    let peer = mint_peer_chain(CLIENT_SPIFFE);
    let joining = mint_peer_chain(OTHER_SPIFFE);
    let cp_override = mint_peer_chain(OTHER_SPIFFE);
    let state = credential_state(9607);

    let slot = install_inbound_trust(
        &state,
        &gateway,
        local_trust(PEER_TRUST_DOMAIN, vec![peer.ca_der.clone()]),
    );
    // The request epoch carries the CP/database override for the SAME trust
    // domain, and that override never carried the peer's issuing root.
    publish_gateway_trust(
        &state,
        &gateway,
        PEER_TRUST_DOMAIN,
        vec![cp_override.ca_der.clone()],
    );
    let admitted_epoch_generation = gateway_trust_generation(&state);

    let fence = &state.hbone_admission_fence;
    let tunnel = fence.admit(credential_snapshot(
        fence.sweep_epoch(),
        peer_credential(&peer, live_expiry(), true, inbound_trust_revision(&state)),
    ));
    assert_eq!(tunnel.revoked_reason(), None);

    // SPIRE rotates: the installer merges the joining root into the inbound
    // slot additively, and publishes its own (masked) epoch generation.
    publish_inbound_trust(
        &state,
        &slot,
        &gateway,
        local_trust(
            PEER_TRUST_DOMAIN,
            vec![peer.ca_der.clone(), joining.ca_der.clone()],
        ),
    );
    publish_gateway_trust(
        &state,
        &gateway,
        PEER_TRUST_DOMAIN,
        vec![cp_override.ca_der.clone(), joining.ca_der.clone()],
    );
    assert!(
        gateway_trust_generation(&state) > admitted_epoch_generation,
        "the epoch generation must move, or this proves nothing about which trust the \
         fence reads"
    );
    wait_for_settled_sweeps(&state).await;

    assert_eq!(
        tunnel.revoked_reason(),
        None,
        "a peer the inbound verifier still admits must not be revoked because the request \
         epoch's separately-built bundles never carried its root"
    );
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(fence.live_tunnels(), 1);
}

/// An ordinary publication is free. A slice apply republishes the inbound slot
/// from unchanged inputs and a pure leaf/key SVID rotation replaces the slot's
/// bundle without touching a single anchor; neither may cost a certificate path
/// build, and a tunnel that has already been verified against the current
/// revision must not be re-verified by every later sweep.
#[tokio::test(flavor = "multi_thread")]
async fn an_unchanged_republish_revokes_nothing_and_builds_no_certificate_path() {
    let gateway = mint_peer_chain(GATEWAY_SPIFFE);
    let peer = mint_peer_chain(CLIENT_SPIFFE);
    let rotated_leaf = mint_peer_chain(GATEWAY_SPIFFE);
    let state = credential_state(9609);

    let slot = install_inbound_trust(
        &state,
        &gateway,
        local_trust(PEER_TRUST_DOMAIN, vec![peer.ca_der.clone()]),
    );
    let admitted_revision = inbound_trust_revision(&state);
    let fence = &state.hbone_admission_fence;
    let tunnel = fence.admit(credential_snapshot(
        fence.sweep_epoch(),
        peer_credential(&peer, live_expiry(), true, admitted_revision),
    ));

    // Byte-identical trust material, republished twice, plus a gateway SVID
    // whose LEAF rotated while its anchors did not.
    for _ in 0..2 {
        publish_inbound_trust(
            &state,
            &slot,
            &gateway,
            local_trust(PEER_TRUST_DOMAIN, vec![peer.ca_der.clone()]),
        );
    }
    publish_inbound_trust(
        &state,
        &slot,
        &rotated_leaf,
        local_trust(PEER_TRUST_DOMAIN, vec![peer.ca_der.clone()]),
    );
    wait_for_settled_sweeps(&state).await;

    assert_eq!(tunnel.revoked_reason(), None);
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(
        inbound_trust_revision(&state),
        admitted_revision,
        "republishing the same anchors — even beneath a rotated leaf — must not advance \
         the trust revision"
    );
    assert_eq!(
        fence.trust_rechecks(),
        0,
        "an ordinary publication must do no certificate path building at all"
    );

    // And a real trust change costs exactly one path build per tunnel, not one
    // per sweep for the rest of the tunnel's life.
    let joining = mint_peer_chain(OTHER_SPIFFE);
    publish_inbound_trust(
        &state,
        &slot,
        &gateway,
        local_trust(
            PEER_TRUST_DOMAIN,
            vec![peer.ca_der.clone(), joining.ca_der.clone()],
        ),
    );
    wait_for_settled_sweeps(&state).await;
    assert_eq!(fence.trust_rechecks(), 1);

    state.publish_mesh_inbound_tls_policy(MeshInboundTlsPolicy::default());
    state.publish_mesh_inbound_tls_policy(MeshInboundTlsPolicy::default());
    wait_for_settled_sweeps(&state).await;
    assert_eq!(
        fence.trust_rechecks(),
        1,
        "a tunnel re-verified against the current revision must not rebuild its path on \
         every later sweep"
    );
    assert_eq!(tunnel.revoked_reason(), None);
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
        peer_credential(
            &peer,
            AdmittedLeafExpiry::At(tokio::time::Instant::now()),
            false,
            0,
        ),
    ));

    wait_for_revocation(&tunnel).await;
    assert_eq!(
        tunnel.revoked_reason(),
        Some(HboneRevocationReason::PeerExpired),
        "an aged-out leaf is `peer_expired`, never folded into the trust verdict"
    );
    assert_eq!(revocation_counts(&state), [0, 1, 0, 0, 0, 0, 0]);
    assert_eq!(
        fence.sweep_epoch(),
        sweep_epoch_before,
        "the expiry watcher must sweep directly, not through the coalescing \
         publication counter"
    );
}

/// A leaf the fence cannot parse is a FENCE failure, not a statement about the
/// peer's SVID lifetime. The `reason` label is the operator's only attribution,
/// so it must not point at rotation when the problem is a parser.
#[tokio::test(flavor = "multi_thread")]
async fn an_unparseable_retained_leaf_fails_closed_as_a_reevaluation_failure() {
    let peer = mint_peer_chain(CLIENT_SPIFFE);
    let state = credential_state(9610);
    let fence = &state.hbone_admission_fence;

    let tunnel = fence.admit(credential_snapshot(
        fence.sweep_epoch(),
        peer_credential(&peer, AdmittedLeafExpiry::Unparseable, false, 0),
    ));
    state.publish_mesh_inbound_tls_policy(MeshInboundTlsPolicy::default());

    wait_for_revocation(&tunnel).await;
    assert_eq!(
        tunnel.revoked_reason(),
        Some(HboneRevocationReason::ReevaluationFailed),
        "an unparseable leaf must not be attributed to the peer's SVID lifetime"
    );
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0, 0, 0, 1]);
}

/// A leaf whose `notAfter` outruns the representable monotonic range carries no
/// upper bound of its own (issue #5396). It is an admission, not a refusal, and
/// the expiry half simply has nothing to decide.
#[tokio::test(flavor = "multi_thread")]
async fn an_unbounded_leaf_is_not_revoked_by_the_expiry_half() {
    let peer = mint_peer_chain(CLIENT_SPIFFE);
    let state = credential_state(9611);
    let fence = &state.hbone_admission_fence;

    let tunnel = fence.admit(credential_snapshot(
        fence.sweep_epoch(),
        peer_credential(&peer, AdmittedLeafExpiry::Unbounded, false, 0),
    ));
    state.publish_mesh_inbound_tls_policy(MeshInboundTlsPolicy::default());
    wait_for_settled_sweeps(&state).await;

    assert_eq!(tunnel.revoked_reason(), None);
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0, 0, 0, 0]);
}

/// Parity with the inbound verifier, which is what "would still be admitted"
/// has to mean (issue #5568 review).
///
/// `SpiffePeerVerifierCache::build` compiles a candidate trust set ATOMICALLY
/// and, when it fails, keeps its last-known-good set and carries on admitting
/// peers. A candidate the fence cannot compile must therefore not replace what
/// the fence judges against either — classifying per trust domain cut tunnels in
/// the domains that DID compile while the verifier was still admitting their
/// peers, and judged every other domain against material the verifier never
/// adopted. It is reachable without malformed input: a federated trust domain
/// carrying only `jwtAuthorities` passes mesh config validation and is merged
/// verbatim into the inbound slot.
#[tokio::test(flavor = "multi_thread")]
async fn a_trust_publication_that_does_not_compile_never_takes_force() {
    let gateway = mint_peer_chain(GATEWAY_SPIFFE);
    let peer = mint_peer_chain(CLIENT_SPIFFE);
    let state = credential_state(9605);

    let slot = install_inbound_trust(
        &state,
        &gateway,
        local_trust(PEER_TRUST_DOMAIN, vec![peer.ca_der.clone()]),
    );
    let in_force = inbound_trust_revision(&state);
    let fence = &state.hbone_admission_fence;
    let compilations = fence.trust_anchor_builds();
    let tunnel = fence.admit(credential_snapshot(
        fence.sweep_epoch(),
        peer_credential(&peer, live_expiry(), true, in_force),
    ));
    assert_eq!(tunnel.revoked_reason(), None);

    // A federated trust domain declaring no X.509 authority at all: the inbound
    // verifier refuses the WHOLE candidate on an empty root store.
    let mut jwt_only = std::collections::HashMap::new();
    jwt_only.insert(
        TrustDomain::new(SLICE_TRUST_DOMAIN).expect("slice trust domain"),
        trust_bundle(SLICE_TRUST_DOMAIN, Vec::new()),
    );
    publish_inbound_trust(
        &state,
        &slot,
        &gateway,
        RuntimeTrustBundleSet {
            local: trust_bundle(PEER_TRUST_DOMAIN, vec![peer.ca_der.clone()]),
            federated: jwt_only,
        },
    );
    // ...and authorities that are not usable trust roots at all.
    publish_inbound_trust(
        &state,
        &slot,
        &gateway,
        local_trust(PEER_TRUST_DOMAIN, vec![b"not-a-certificate".to_vec()]),
    );
    wait_for_settled_sweeps(&state).await;

    assert_eq!(
        inbound_trust_revision(&state),
        in_force,
        "a publication the inbound verifier would reject must not advance the trust in force"
    );
    assert_eq!(
        fence.trust_anchor_builds(),
        compilations,
        "a refused candidate must not replace the cached anchors either"
    );
    assert_eq!(
        tunnel.revoked_reason(),
        None,
        "the verifier is still admitting this peer under its last-known-good set, so the \
         fence must not cut its tunnel"
    );
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(fence.trust_rechecks(), 0);

    // A withdrawal that DOES compile is still a withdrawal: the fence has not
    // been turned off, only aligned with what is in force.
    publish_inbound_trust(
        &state,
        &slot,
        &gateway,
        local_trust(SLICE_TRUST_DOMAIN, vec![gateway.ca_der.clone()]),
    );

    wait_for_revocation(&tunnel).await;
    assert_eq!(
        tunnel.revoked_reason(),
        Some(HboneRevocationReason::PeerTrust),
        "a trust set that IS in force and no longer anchors the peer still revokes"
    );
    assert_eq!(revocation_counts(&state), [0, 0, 1, 0, 0, 0, 0]);
    assert!(inbound_trust_revision(&state) > in_force);
}

/// The guard against a false mass revocation: a mesh inbound listener with no
/// gateway SVID material verifies peers chain-only against the operator client
/// CA bundle, which the inbound SPIFFE slot does not describe at all. Such a
/// tunnel was never anchored by the inbound admission trust, so the trust half
/// of the gate must never judge it.
#[tokio::test(flavor = "multi_thread")]
async fn a_peer_the_admitting_trust_never_anchored_is_not_revoked_for_trust() {
    let gateway = mint_peer_chain(GATEWAY_SPIFFE);
    let peer = mint_peer_chain(CLIENT_SPIFFE);
    let unrelated = mint_peer_chain(OTHER_SPIFFE);
    let state = credential_state(9606);

    // The admitting slot carries a bundle for an unrelated trust domain, so it
    // never anchored this peer.
    let slot = install_inbound_trust(
        &state,
        &gateway,
        local_trust(SLICE_TRUST_DOMAIN, vec![unrelated.ca_der.clone()]),
    );
    let fence = &state.hbone_admission_fence;
    let tunnel = fence.admit(credential_snapshot(
        fence.sweep_epoch(),
        peer_credential(&peer, live_expiry(), false, inbound_trust_revision(&state)),
    ));

    publish_inbound_trust(
        &state,
        &slot,
        &gateway,
        local_trust("other.local", vec![unrelated.ca_der.clone()]),
    );
    wait_for_settled_sweeps(&state).await;

    assert_eq!(tunnel.revoked_reason(), None);
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(fence.live_tunnels(), 1);
    assert_eq!(fence.trust_rechecks(), 0);
}

// ── End-to-end admission capture (issue #5568) ────────────────────────────

/// `HbonePeerCredential::from_admitted_connect` runs on the real CONNECT path,
/// against a real mTLS handshake, so what it captured is asserted from the
/// fence's own registry rather than reconstructed by a fixture.
///
/// This is the coverage whose absence let the trust-source divergence ship:
/// every other credential fixture passes `anchored_at_admission` as a literal,
/// and the production constructor — the one that decides which trust the tunnel
/// is judged by — was never executed at all.
#[tokio::test(flavor = "multi_thread")]
async fn a_real_connect_captures_its_peer_credential_from_the_inbound_trust() {
    let mut fx = admit_client_tunnel_with_inbound_trust(vec![allow_client()], true).await;

    let captured = fx
        .state
        .hbone_admission_fence
        .inspect_live_tunnels(|snapshot| {
            snapshot.peer_credential.as_ref().map(|credential| {
                (
                    credential.spiffe_id.to_string(),
                    credential.anchored_at_admission,
                    matches!(credential.leaf_expiry, AdmittedLeafExpiry::At(_)),
                )
            })
        });
    assert_eq!(
        captured,
        vec![Some((CLIENT_SPIFFE.to_string(), true, true))],
        "a certificate-authenticated CONNECT must retain its peer SPIFFE id, a finite leaf \
         deadline, and the anchoring the INBOUND verifier's trust implies"
    );

    echo_round_trip(&mut fx.tunnel, b"still-flowing").await;
    fx.teardown().await;
}

/// The chain-only inbound posture, end to end: no inbound admission trust is
/// installed, so the credential is still captured — the expiry half applies —
/// but the trust half stays inapplicable for the tunnel's whole life.
#[tokio::test(flavor = "multi_thread")]
async fn a_real_connect_with_no_inbound_trust_installed_is_never_anchored() {
    let mut fx = admit_client_tunnel(vec![allow_client()]).await;

    let captured = fx
        .state
        .hbone_admission_fence
        .inspect_live_tunnels(|snapshot| {
            snapshot
                .peer_credential
                .as_ref()
                .map(|credential| credential.anchored_at_admission)
        });
    assert_eq!(
        captured,
        vec![Some(false)],
        "with no inbound SPIFFE slot installed, peers are verified chain-only against the \
         operator client-CA bundle and must never be judged by the trust gate"
    );

    echo_round_trip(&mut fx.tunnel, b"still-flowing").await;
    fx.teardown().await;
}

/// Scenario B of the independent review, end to end.
///
/// The inbound slot's LOCAL domain is the gateway SVID's own — the peer's — and
/// the slice's differing local domain is filed beside it as federated, which is
/// exactly what `merge_trust_overlay_into_svid_bundle` produces. Reading the
/// request epoch instead would find no bundle for the peer's domain at all,
/// mark the tunnel unanchored, and then never judge it again: withdrawing that
/// domain would revoke nothing, silently, for the tunnel's whole life.
#[tokio::test(flavor = "multi_thread")]
async fn withdrawing_the_svids_own_trust_domain_revokes_a_real_tunnel() {
    let fx = admit_client_tunnel_with_inbound_trust(vec![allow_client()], true).await;
    let slot = fx
        .inbound_trust_slot
        .clone()
        .expect("the fixture installed an inbound admission trust slot");
    let gateway = mint_peer_chain(GATEWAY_SPIFFE);

    // The peer's trust domain — the SVID's own local domain — loses its
    // authorities; the slice's domain is untouched.
    publish_inbound_trust(
        &fx.state,
        &slot,
        &gateway,
        local_trust(SLICE_TRUST_DOMAIN, vec![gateway.ca_der.clone()]),
    );

    tokio::time::timeout(DEADLINE, async {
        while fx
            .state
            .hbone_admission_fence
            .revocations(HboneRevocationReason::PeerTrust)
            == 0
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("withdrawing the peer's trust domain must revoke its live tunnel");

    assert_eq!(revocation_counts(&fx.state), [0, 0, 1, 0, 0, 0, 0]);
    fx.teardown().await;
}

/// The pooled-session hole the verification re-review of PR #5573 found.
///
/// An established inbound HBONE mTLS session is NEVER re-handshaked and many
/// CONNECTs multiplex over it, so a peer the fence just revoked simply re-opens
/// a tunnel on the same connection. Seeding the replacement tunnel's
/// last-verified revision from the revision its CONNECT merely READ admitted it
/// under trust that had already refused its chain, and then short-circuited
/// every later sweep for that tunnel's whole life — the fence defeated in its
/// own primary scenario. The CONNECT now re-verifies the retained chain.
#[tokio::test(flavor = "multi_thread")]
async fn a_pooled_connect_after_a_trust_withdrawal_is_refused_not_reseeded() {
    let mut fx = admit_client_tunnel_with_inbound_trust(vec![allow_client()], true).await;
    let slot = fx
        .inbound_trust_slot
        .clone()
        .expect("the fixture installed an inbound admission trust slot");
    let gateway = mint_peer_chain(GATEWAY_SPIFFE);
    let compilations_before = fx.state.hbone_admission_fence.trust_anchor_builds();

    // R2 still declares the peer's trust domain and still compiles; only the
    // root that issued the live peer's leaf is retired. A membership check
    // alone would see nothing.
    let replacement = mint_peer_chain(OTHER_SPIFFE);
    publish_inbound_trust(
        &fx.state,
        &slot,
        &gateway,
        local_trust(PEER_TRUST_DOMAIN, vec![replacement.ca_der.clone()]),
    );

    // (i) the live tunnel is revoked for trust...
    assert_tunnel_closed(&mut fx.tunnel.response_body).await;
    wait_for_no_live_tunnels(&fx.state).await;
    assert_eq!(
        revocation_counts(&fx.state),
        [0, 0, 1, 0, 0, 0, 0],
        "exactly one peer_trust revocation"
    );

    // (ii) ...and the peer's immediate retry, on the SAME never-re-handshaked
    // inbound mTLS connection, is refused at admission rather than admitted and
    // never checked again.
    let refused = open_tunnel(&mut fx.sender).await.err();
    assert_eq!(
        refused,
        Some(StatusCode::FORBIDDEN),
        "a CONNECT whose chain no longer anchors must be refused, not re-admitted"
    );
    assert_eq!(fx.state.hbone_admission_fence.live_tunnels(), 0);
    assert_eq!(fx.state.hbone_admission_fence.connect_trust_refusals(), 1);
    assert_eq!(
        revocation_counts(&fx.state),
        [0, 0, 1, 0, 0, 0, 0],
        "a refused CONNECT is never a revocation"
    );
    assert_eq!(
        fx.state.hbone_admission_fence.trust_anchor_builds(),
        compilations_before + 1,
        "the publication compiles the anchors once; the CONNECT validates a path against \
         them and compiles nothing"
    );

    fx.teardown().await;
}

/// The chain-only inbound posture must be untouched by the CONNECT-time trust
/// gate. With no inbound admission trust installed there is nothing in force to
/// verify against — peers are verified against the operator client-CA bundle,
/// which `tls::client_trust` bounds separately (issue #3857) — so refusing
/// would be an outage rather than a fence.
#[tokio::test(flavor = "multi_thread")]
async fn a_chain_only_posture_still_admits_a_pooled_second_connect() {
    let mut fx = admit_client_tunnel(vec![allow_client()]).await;
    let fence = &fx.state.hbone_admission_fence;
    assert!(
        fence.inbound_trust_revision().is_none(),
        "this posture installs no inbound admission trust at all"
    );

    let mut second = open_tunnel(&mut fx.sender)
        .await
        .expect("a chain-only posture admits a second CONNECT on the same connection");
    echo_round_trip(&mut second, b"chain-only").await;

    assert_eq!(fence.live_tunnels(), 2);
    assert_eq!(fence.connect_trust_refusals(), 0);
    assert_eq!(fence.trust_anchor_builds(), 0);
    assert_eq!(revocation_counts(&fx.state), [0, 0, 0, 0, 0, 0, 0]);

    fx.teardown().await;
}

/// The credential gate is only as good as the publications that schedule it.
/// Two writers must each store first and sweep second: the inbound admission
/// trust (which decides the trust verdict) and the request-facing gateway trust
/// generation (retained as the defence-in-depth half of the two-publication
/// step). Pinning both in source is what keeps a future publisher from growing
/// its own path and silently leaving live tunnels judged against retired trust.
#[test]
fn every_trust_publisher_stores_before_it_requests_a_sweep() {
    fn body<'a>(source: &'a str, signature: &str, end: &str) -> &'a str {
        let start = source.find(signature).expect("publisher must exist");
        let rest = &source[start..];
        let end = rest.find(end).expect("publisher body must terminate");
        &rest[..end]
    }

    fn assert_store_then_sweep(func: &str, store: &str, sweep: &str, what: &str) {
        let store = func.find(store).unwrap_or_else(|| {
            panic!("{what}: the store is what publishes the material a sweep judges")
        });
        let sweep = func
            .find(sweep)
            .unwrap_or_else(|| panic!("{what}: every publication must schedule a fence sweep"));
        assert!(
            store < sweep,
            "{what}: publish-then-recheck — the sweep must be requested AFTER the store, or a \
             CONNECT that read the superseded state could register between them and never be \
             re-judged"
        );
    }

    let proxy = include_str!("../../src/proxy/mod.rs");
    assert_store_then_sweep(
        body(
            proxy,
            "fn publish_live_gateway_trust(&self) {",
            "\n    /// Whether request paths may authenticate gateway-to-mesh peers",
        ),
        "self.request_epoch.update_gateway_trust(",
        "self.hbone_admission_fence.request_sweep()",
        "publish_live_gateway_trust",
    );

    let fence = include_str!("../../src/proxy/hbone_admission_fence.rs");
    let publish_inbound = body(
        fence,
        "pub fn publish_inbound_admission_trust(",
        "\n    /// The inbound admission trust IN FORCE",
    );
    assert_store_then_sweep(
        publish_inbound,
        "trust.slot.store(bundle)",
        "self.request_sweep()",
        "publish_inbound_admission_trust",
    );

    // A publication that does not take force is the one failure mode an
    // operator cannot see from the outside — the verifier keeps admitting and
    // the fence keeps judging, both against the previous set — so it must reach
    // the sampled operator warning rather than being silently dropped.
    assert!(
        publish_inbound.contains("self.warn_trust_not_in_force("),
        "a publication the fence refuses to put in force must not do so silently"
    );

    // And the mesh writers must reach that publisher rather than storing into
    // the verifier's slot themselves. Every `.store(` inside each publisher's
    // own body is enumerated, because the two writers bind the inbound slot
    // under DIFFERENT names (`inbound_slot` and, in `publish_staged_spiffe_
    // bundle`'s `DirectSlot` arm, plain `slot`): pinning one variable name
    // leaves the other free to regress, and only the sibling call-count
    // assertion would notice — and only because the call disappeared.
    let mesh = include_str!("../../src/modes/mesh/mod.rs");
    for (what, publisher, permitted_stores) in [
        (
            "publish_runtime_svid_to_inbound_slot",
            body(
                mesh,
                "fn publish_runtime_svid_to_inbound_slot(",
                "\nfn start_mesh_inbound_svid_rotation_republisher(",
            ),
            &[][..],
        ),
        (
            "publish_staged_spiffe_bundle",
            body(
                mesh,
                "fn publish_staged_spiffe_bundle(",
                "\n/// Stage the exact effective mesh/federation gateway trust decision",
            ),
            // The accepted trust OVERLAY is a different slot with no fence
            // binding; publishing it is this writer's own job.
            &["trust_overlay_slot.store(Arc::new(trust_overlay));"][..],
        ),
    ] {
        assert_eq!(
            publisher.matches(".store(").count(),
            permitted_stores.len(),
            "{what}: the mesh inbound SPIFFE slot must be published through \
             ProxyState::publish_mesh_inbound_trust_bundle, never stored into directly"
        );
        for permitted in permitted_stores {
            assert!(
                publisher.contains(permitted),
                "{what}: expected store `{permitted}` is gone; re-derive what this publisher \
                 is allowed to write before relaxing the count above"
            );
        }
        assert!(
            publisher.contains("publish_mesh_inbound_trust_bundle(")
                || publisher.contains("publish_runtime_svid_to_inbound_slot("),
            "{what}: every inbound-slot publisher must reach the one writer"
        );
    }
    assert_eq!(
        mesh.matches("publish_mesh_inbound_trust_bundle(").count(),
        2,
        "exactly the two inbound-slot writers — the runtime SVID republisher and the staged \
         slice publisher — may publish inbound trust"
    );
}

// ---------------------------------------------------------------------------
// Issue #5042 step 2: the fence's CAPABILITY ADVERTISEMENT.
//
// Source-side reuse of the application connection inside a tunnel is
// admissible only because a later policy or credential generation can still
// reach that tunnel and cut it. The destination therefore SAYS so, on the
// CONNECT `200`, and only while the fence really holds the tunnel. These tests
// pin both directions of that contract; the source-side half — what a peer
// does with the header — lives in `hbone_inner_pool_tests.rs`.
// ---------------------------------------------------------------------------

/// The advertised value, read off the CONNECT response head.
fn tunnel_reuse_advertisement(response: &hyper::Response<h2::RecvStream>) -> Option<String> {
    response
        .headers()
        .get(ferrum_edge::modes::mesh::hbone::TUNNEL_REUSE_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

#[tokio::test(flavor = "multi_thread")]
async fn an_admitted_connect_advertises_the_fence_capability_on_its_200() {
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

    let (response, _request_body) = send_connect(&mut sender, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        tunnel_reuse_advertisement(&response).as_deref(),
        Some(ferrum_edge::modes::mesh::hbone::TUNNEL_REUSE_FENCED),
        "an admitted tunnel the fence holds must advertise that the receiver \
         re-evaluates it, so the source may reuse the application connection"
    );
    assert_eq!(
        state.hbone_admission_fence.live_tunnels(),
        1,
        "the advertisement must describe a tunnel that is actually registered"
    );
    // The advertisement is a capability flag, never an authorization: the
    // admission counters are untouched by it.
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0, 0, 0, 0]);

    let _ = shutdown_tx.send(true);
    backend_handle.abort();
    conn_task.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_connect_never_advertises_the_fence_capability() {
    let certs = generate_hbone_mtls_certs(CLIENT_SPIFFE);
    let (backend_addr, backend_handle) = start_interactive_echo_backend().await;
    // DENY for the connecting principal: the CONNECT is refused at admission,
    // so no tunnel is ever registered and nothing may be advertised.
    let state = build_state(prepared_config(
        Some(backend_addr.port()),
        vec![deny_client()],
    ));
    let (gateway_addr, shutdown_tx) =
        start_inbound_gateway(state.clone(), hbone_server_config(&certs)).await;
    let (mut sender, conn_task) =
        connect_hbone_h2_mtls(gateway_addr, hbone_client_config(&certs)).await;

    let (response, _request_body) = send_connect(&mut sender, None).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        tunnel_reuse_advertisement(&response),
        None,
        "a refusal must carry no capability: there is no tunnel for a later \
         generation to reach, so there is nothing a source may reuse"
    );
    assert_eq!(state.hbone_admission_fence.live_tunnels(), 0);

    let _ = shutdown_tx.send(true);
    backend_handle.abort();
    conn_task.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn the_capability_is_not_advertised_once_the_fence_has_revoked_the_tunnel() {
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

    let (admitted, _first_body) = send_connect(&mut sender, None).await;
    assert_eq!(admitted.status(), StatusCode::OK);
    assert!(tunnel_reuse_advertisement(&admitted).is_some());

    // Tighten: the live tunnel is revoked and the same principal's next CONNECT
    // is refused. The refusal carries no advertisement, which is exactly what
    // stops a source from re-establishing a reusable lease under a policy that
    // no longer admits it.
    let outcome = state.update_config(prepared_config(
        Some(backend_addr.port()),
        vec![deny_client()],
    ));
    assert_eq!(outcome, ConfigApplyOutcome::Applied);
    wait_for_no_live_tunnels(&state).await;

    let (refused, _second_body) = send_connect(&mut sender, None).await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert_eq!(tunnel_reuse_advertisement(&refused), None);

    let _ = shutdown_tx.send(true);
    backend_handle.abort();
    conn_task.abort();
}

/// The residual risk the re-review named: nothing proved that production wires
/// the SAME slot into the rustls inbound verifier and into the fence. Those
/// constructors are private to `modes::mesh`, so the chain of custody is pinned
/// in source instead — every link of it, so a new slot binding cannot quietly
/// appear between them.
#[test]
fn the_inbound_spiffe_verifier_and_the_fence_share_one_trust_slot() {
    // Collapse runs of whitespace so an assertion survives rustfmt reflow.
    fn flat(source: &str) -> String {
        source.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    // The serving path's ONE inbound SPIFFE slot binding.
    const SLOT_BINDING: &str =
        "let mesh_inbound_spiffe_slot = build_mesh_inbound_spiffe_slot_with_federation(";
    // The install that binds exactly that value to the admission fence.
    const SLOT_INSTALL: &str = "if let Some(slot) = mesh_inbound_spiffe_slot.as_ref() { \
                                proxy_state.install_mesh_inbound_admission_trust(slot); }";
    // That same binding is what the inbound TLS state hands every verifier build.
    const VERIFIER_SLOT: &str = "spiffe_bundle_slot: mesh_inbound_spiffe_slot";
    const VERIFIER_CALL: &str = "mesh_inbound_spiffe_verifier(spiffe_bundle_slot";
    const VERIFIER_BUILD: &str = "tls::build_spiffe_client_cert_verifier(";
    // The CA-backend slot origin, and the carry-through that keeps it the SAME
    // `Arc` rather than a second slot the fence never saw.
    const CA_INSTALL: &str = "proxy_state.install_mesh_inbound_admission_trust(&inbound_slot);";
    const CARRY_THROUGH: &str =
        "if let Some(slot) = runtime_svid_slot { return Some(slot.clone()); }";
    const ANY_INSTALL: &str = "install_mesh_inbound_admission_trust(";

    let mesh = flat(include_str!("../../src/modes/mesh/mod.rs"));

    // One slot binding in the serving path, and it is installed on the fence.
    assert_eq!(
        mesh.matches(SLOT_BINDING).count(),
        1,
        "the serving path must derive its inbound SPIFFE slot exactly once"
    );
    assert!(
        mesh.contains(&flat(SLOT_INSTALL)),
        "that binding must be the slot installed on the admission fence"
    );

    // ...and the SAME binding is what every inbound-TLS verifier build reads.
    assert_eq!(
        mesh.matches(VERIFIER_SLOT).count(),
        1,
        "the inbound TLS state's verifier slot must be that same binding"
    );
    assert_eq!(
        mesh.matches(VERIFIER_CALL).count(),
        1,
        "exactly one production site may build the inbound peer verifier"
    );
    assert_eq!(
        mesh.matches(VERIFIER_BUILD).count(),
        2,
        "only `mesh_inbound_spiffe_verifier`'s two mTLS-mode arms may build it"
    );

    // The CA-backend slot reaches that binding as the SAME `Arc`: the builder
    // returns the runtime slot it was handed rather than constructing a second
    // one, and it is installed before the first SVID can be published into it.
    assert!(
        mesh.contains(CA_INSTALL),
        "the CA-backend slot must be installed before its first SVID fetch"
    );
    assert!(
        mesh.contains(CARRY_THROUGH),
        "a runtime SVID slot must be carried through, never rebuilt — a second slot would \
         give the verifier and the fence different trust"
    );
    assert_eq!(
        mesh.matches(ANY_INSTALL).count(),
        2,
        "exactly the two slot origins may bind the fence's inbound admission trust"
    );
}
