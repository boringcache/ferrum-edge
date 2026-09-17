//! Source-side reuse of the APPLICATION connection inside a fenced HBONE
//! tunnel (issue #5042 step 2).
//!
//! The receiver half of the contract — that the admission fence re-evaluates
//! live tunnels, and that `handle_hbone_request` advertises it on the CONNECT
//! `200` only while the fence really holds the tunnel — lives in
//! `hbone_admission_fence_tests.rs`. These tests are the SOURCE half: what a
//! gateway does with that advertisement, and what it must never do without it.
//!
//! The fixture is a real SPIFFE-mTLS HTTP/2 CONNECT terminator that relays each
//! admitted tunnel to a real loopback application over a FRESH TCP connection,
//! exactly as a destination relay does. That is what makes the two counters the
//! issue's own measurement table is written in observable here: `connects` (one
//! per CONNECT the peer admitted) and `app_accepts` (one per `accept(2)` the
//! application saw). Pre-#5042 both equal the request count; with reuse both
//! equal the pool size.
//!
//! The peer can also be told to REFUSE new CONNECTs and to REVOKE live ones —
//! the two things a receiver-side policy tightening does — so the source's
//! reaction is pinned without re-testing the sweep itself.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use bytes::Bytes;
use chrono::Utc;
use ferrum_edge::_test_support::hbone_inner_h1_request_body_for_test;
use ferrum_edge::config::PoolConfig;
use ferrum_edge::config::types::{
    AuthMode, BackendScheme, DispatchKind, Proxy, ResponseBodyMode, default_namespace,
};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain, spiffe_id_to_san};
use ferrum_edge::identity::{SharedSvidBundle, SvidBundle, TrustBundle, TrustBundleSet};
use ferrum_edge::modes::mesh::hbone::{TUNNEL_REUSE_FENCED, TUNNEL_REUSE_HEADER};
use ferrum_edge::proxy::grpc_proxy::GrpcBody;
use ferrum_edge::proxy::hbone_inner_pool::{
    HboneInnerConnectionPool, HboneInnerH1Checkout, HboneInnerH1RequestBody, HboneInnerKeyParts,
    HboneInnerProtocol, HboneSourceCredential, MAX_IDLE_H1_PER_KEY,
};
use ferrum_edge::proxy::hbone_pool::HboneConnectionPool;
use ferrum_edge::tls::spiffe::build_spiffe_inbound_config;
use http::{Response, StatusCode};
use http_body_util::BodyExt;
use hyper::client::conn::http2::SendRequest as H2SendRequest;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

use crate::scaffolding::port_registry::TestSocket;

const TRUST_DOMAIN: &str = "cluster.local";
const GATEWAY_SPIFFE: &str = "ns/edge/sa/gateway";
const PEER_SPIFFE: &str = "ns/default/sa/orders";
const CALLER_A: &str = "spiffe://cluster.local/ns/default/sa/caller-a";
const CALLER_B: &str = "spiffe://cluster.local/ns/default/sa/caller-b";
/// The namespace `source_proxy` declares, so the hand-built key identity and
/// the proxy the dial runs under agree.
const NAMESPACE: &str = ferrum_edge::config::types::DEFAULT_NAMESPACE;
const PROXY_ID: &str = "hbone-inner-pool";
const UPSTREAM_ID: &str = "orders";
const DEADLINE: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// Synthetic SPIFFE identity material
// ---------------------------------------------------------------------------

fn synthetic_root(td: &TrustDomain) -> (Vec<u8>, String, String) {
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(
        DnType::CommonName,
        format!("{}-inner-pool-root", td.as_str()),
    );
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("root key");
    let cert = params.self_signed(&key).expect("root cert");
    (cert.der().to_vec(), cert.pem(), key.serialize_pem())
}

fn issue_svid(spiffe_id: &SpiffeId, root_pem: &str, root_key_pem: &str) -> (Vec<u8>, Vec<u8>) {
    let issuer_key = KeyPair::from_pem(root_key_pem).expect("issuer key");
    let issuer = Issuer::from_ca_cert_pem(root_pem, issuer_key).expect("issuer");
    let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("leaf key");

    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params
        .subject_alt_names
        .push(spiffe_id_to_san(spiffe_id).expect("spiffe san"));
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    // An explicit, parseable validity window: the source credential deadline is
    // read out of this leaf's `notAfter`, so a lease's bound and the
    // certificate the tunnel actually presents describe the same instant.
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + time::Duration::hours(1);

    let leaf = params.signed_by(&leaf_key, &issuer).expect("leaf cert");
    (leaf.der().to_vec(), leaf_key.serialize_der())
}

fn bundle_for(id: SpiffeId, leaf_der: Vec<u8>, key_der: Vec<u8>, root_der: Vec<u8>) -> SvidBundle {
    SvidBundle {
        spiffe_id: id.clone(),
        cert_chain_der: vec![leaf_der],
        private_key_pkcs8_der: key_der.into(),
        trust_bundles: TrustBundleSet::local_only(TrustBundle {
            trust_domain: id.trust_domain().clone(),
            x509_authorities: vec![root_der],
            jwt_authorities: Vec::new(),
            refresh_hint_seconds: None,
        }),
    }
}

fn svid_slot(bundle: SvidBundle) -> SharedSvidBundle {
    Arc::new(ArcSwap::new(Arc::new(Some(bundle))))
}

/// Gateway + peer identities issued from one synthetic root, so the peer
/// verifies the gateway's client SVID and the gateway pins the peer's.
struct Identities {
    gateway: SvidBundle,
    peer: SvidBundle,
    peer_id: SpiffeId,
}

fn identities() -> Identities {
    let td = TrustDomain::new(TRUST_DOMAIN).expect("trust domain");
    let (root_der, root_pem, root_key_pem) = synthetic_root(&td);
    let gateway_id = SpiffeId::from_parts(&td, GATEWAY_SPIFFE).expect("gateway id");
    let peer_id = SpiffeId::from_parts(&td, PEER_SPIFFE).expect("peer id");
    let (gateway_leaf, gateway_key) = issue_svid(&gateway_id, &root_pem, &root_key_pem);
    let (peer_leaf, peer_key) = issue_svid(&peer_id, &root_pem, &root_key_pem);
    Identities {
        gateway: bundle_for(gateway_id, gateway_leaf, gateway_key, root_der.clone()),
        peer: bundle_for(peer_id.clone(), peer_leaf, peer_key, root_der),
        peer_id,
    }
}

// ---------------------------------------------------------------------------
// The application behind the peer's relay
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum AppBehaviour {
    /// One `200` with a 2-byte `Content-Length` body per request, keep-alive.
    /// The shape the issue's own measurement used.
    Ok,
    /// Declares 16 bytes, writes 5, and closes. The response is TRUNCATED, so
    /// the exchange never completes cleanly and the lease must not come back.
    Truncate,
    /// An h2c server: one `200` per request, and after `goaway_after` requests
    /// it gracefully shuts the connection down (GOAWAY).
    H2c { goaway_after: usize },
}

struct App {
    addr: SocketAddr,
    accepts: Arc<AtomicUsize>,
    handle: JoinHandle<()>,
}

impl App {
    fn accepts(&self) -> usize {
        self.accepts.load(Ordering::SeqCst)
    }
}

impl Drop for App {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// Read one complete HTTP/1.1 request — head plus any declared body — off
/// `stream`, returning `false` at EOF.
///
/// Draining the declared body matters: these tests keep the application
/// connection alive across requests, so leaving upload bytes in the socket
/// would make the NEXT request's head unparseable and turn a reuse assertion
/// into a framing accident.
async fn read_h1_request(stream: &mut TcpStream) -> bool {
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte).await {
            Ok(0) | Err(_) => return false,
            Ok(_) => head.push(byte[0]),
        }
    }
    let declared = String::from_utf8_lossy(&head)
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    if declared > 0 {
        let mut body = vec![0_u8; declared];
        if stream.read_exact(&mut body).await.is_err() {
            return false;
        }
    }
    true
}

async fn start_app(behaviour: AppBehaviour) -> App {
    let listener = TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind application");
    let addr = listener.local_addr().expect("application addr");
    let accepts = Arc::new(AtomicUsize::new(0));
    let accepts_for_task = Arc::clone(&accepts);
    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            accepts_for_task.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(serve_app_connection(stream, behaviour));
        }
    });
    App {
        addr,
        accepts,
        handle,
    }
}

async fn serve_app_connection(mut stream: TcpStream, behaviour: AppBehaviour) {
    match behaviour {
        AppBehaviour::Ok => {
            while read_h1_request(&mut stream).await {
                if stream
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
                    .await
                    .is_err()
                {
                    return;
                }
            }
        }
        AppBehaviour::Truncate => {
            if read_h1_request(&mut stream).await {
                // Declares sixteen body bytes and writes five, then hangs up.
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 16\r\n\r\nshort")
                    .await;
                let _ = stream.shutdown().await;
            }
        }
        AppBehaviour::H2c { goaway_after } => {
            let Ok(mut server) = h2::server::handshake(stream).await else {
                return;
            };
            let mut served = 0_usize;
            while let Some(next) = server.accept().await {
                let Ok((_request, mut respond)) = next else {
                    return;
                };
                let response = Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "application/grpc")
                    .body(())
                    .expect("h2c response");
                let Ok(mut send) = respond.send_response(response, false) else {
                    return;
                };
                let _ = send.send_data(Bytes::from_static(b"ok"), true);
                served += 1;
                if goaway_after > 0 && served >= goaway_after {
                    server.graceful_shutdown();
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The peer: a SPIFFE-mTLS HTTP/2 CONNECT terminator that relays to the app
// ---------------------------------------------------------------------------

struct Peer {
    addr: SocketAddr,
    /// CONNECTs the peer ADMITTED (a refused CONNECT is not counted).
    connects: Arc<AtomicUsize>,
    /// Whether new CONNECTs are refused — a receiver-side policy tightening.
    refuse: Arc<AtomicBool>,
    /// Live relay tasks, so a test can cut every tunnel the way a fence sweep
    /// does: the relay ends, its `SendStream` drops, and the peer resets the
    /// CONNECT stream.
    live: Arc<Mutex<Vec<JoinHandle<()>>>>,
    handle: JoinHandle<()>,
}

impl Peer {
    fn connects(&self) -> usize {
        self.connects.load(Ordering::SeqCst)
    }

    fn set_refuse(&self, on: bool) {
        self.refuse.store(on, Ordering::SeqCst);
    }

    /// Cut every live tunnel, as a fence sweep's revocation does.
    async fn revoke_all(&self) {
        let mut live = self.live.lock().await;
        for task in live.drain(..) {
            task.abort();
        }
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

async fn start_peer(peer_slot: SharedSvidBundle, app_addr: SocketAddr, advertise: bool) -> Peer {
    let listener = TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind hbone peer");
    let addr = listener.local_addr().expect("peer addr");
    let connects = Arc::new(AtomicUsize::new(0));
    let advertise = Arc::new(AtomicBool::new(advertise));
    let refuse = Arc::new(AtomicBool::new(false));
    let live: Arc<Mutex<Vec<JoinHandle<()>>>> = Arc::new(Mutex::new(Vec::new()));

    let connects_for_task = Arc::clone(&connects);
    let advertise_for_task = Arc::clone(&advertise);
    let refuse_for_task = Arc::clone(&refuse);
    let live_for_task = Arc::clone(&live);

    let handle = tokio::spawn(async move {
        let inbound = build_spiffe_inbound_config(peer_slot, true, Arc::new(Vec::new()))
            .expect("peer server config");
        let acceptor = TlsAcceptor::from(inbound);
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let connects = Arc::clone(&connects_for_task);
            let advertise = Arc::clone(&advertise_for_task);
            let refuse = Arc::clone(&refuse_for_task);
            let live = Arc::clone(&live_for_task);
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let Ok(mut server) = h2::server::handshake(tls).await else {
                    return;
                };
                while let Some(next) = server.accept().await {
                    let Ok((request, mut respond)) = next else {
                        return;
                    };
                    if request.method() != http::Method::CONNECT {
                        continue;
                    }
                    if refuse.load(Ordering::SeqCst) {
                        let refusal = Response::builder()
                            .status(StatusCode::FORBIDDEN)
                            .body(())
                            .expect("refusal");
                        let _ = respond.send_response(refusal, true);
                        continue;
                    }
                    connects.fetch_add(1, Ordering::SeqCst);
                    let mut builder = Response::builder().status(StatusCode::OK);
                    if advertise.load(Ordering::SeqCst) {
                        builder = builder.header(TUNNEL_REUSE_HEADER, TUNNEL_REUSE_FENCED);
                    }
                    let Ok(accepted) =
                        respond.send_response(builder.body(()).expect("connect response"), false)
                    else {
                        return;
                    };
                    let recv = request.into_body();
                    let task = tokio::spawn(relay_tunnel(recv, accepted, app_addr));
                    live.lock().await.push(task);
                }
            });
        }
    });

    Peer {
        addr,
        connects,
        refuse,
        live,
        handle,
    }
}

/// Byte-relay one admitted tunnel to a FRESH application connection, which is
/// what makes `app_accepts` count exactly what a destination relay costs.
async fn relay_tunnel(
    mut recv: h2::RecvStream,
    mut send: h2::SendStream<Bytes>,
    app_addr: SocketAddr,
) {
    let Ok(app) = TcpStream::connect(app_addr).await else {
        send.send_reset(h2::Reason::CONNECT_ERROR);
        return;
    };
    let (mut app_read, mut app_write) = tokio::io::split(app);
    let upstream = tokio::spawn(async move {
        while let Some(chunk) = recv.data().await {
            let Ok(chunk) = chunk else { return };
            let _ = recv.flow_control().release_capacity(chunk.len());
            if app_write.write_all(&chunk).await.is_err() {
                return;
            }
        }
        let _ = app_write.shutdown().await;
    });
    let mut buf = vec![0_u8; 16 * 1024];
    loop {
        match app_read.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if send
                    .send_data(Bytes::copy_from_slice(&buf[..n]), false)
                    .is_err()
                {
                    break;
                }
            }
        }
    }
    let _ = send.send_data(Bytes::new(), true);
    upstream.abort();
}

// ---------------------------------------------------------------------------
// Source-side gateway
// ---------------------------------------------------------------------------

fn source_proxy() -> Proxy {
    let now = Utc::now();
    Proxy {
        labels: Default::default(),
        id: PROXY_ID.to_string(),
        namespace: default_namespace(),
        name: Some("HBONE inner pool".to_string()),
        hosts: vec!["orders.local".to_string()],
        listen_path: Some("/".to_string()),
        backend_scheme: Some(BackendScheme::Http),
        dispatch_kind: DispatchKind::from(BackendScheme::Http),
        backend_host: "127.0.0.1".to_string(),
        backend_port: 8080,
        backend_path: None,
        strip_listen_path: true,
        preserve_host_header: false,
        backend_connect_timeout_ms: 5_000,
        backend_read_timeout_ms: 5_000,
        backend_write_timeout_ms: 5_000,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        resolved_tls: Default::default(),
        dispatch_port_overrides: None,
        dispatch_port_override_fallback: None,
        dns_override: None,
        dns_cache_ttl_seconds: None,
        auth_mode: AuthMode::Single,
        plugins: vec![],
        pool_idle_timeout_seconds: None,
        pool_enable_http_keep_alive: None,
        pool_enable_http2: None,
        pool_tcp_keepalive_seconds: None,
        pool_http2_keep_alive_interval_seconds: None,
        pool_http2_keep_alive_timeout_seconds: None,
        pool_http2_initial_stream_window_size: None,
        pool_http2_initial_connection_window_size: None,
        pool_http2_adaptive_window: None,
        pool_http2_max_frame_size: None,
        pool_http2_max_concurrent_streams: None,
        pool_http3_connections_per_backend: None,
        h2_upgrade_policy: None,
        pool_max_requests_per_connection: None,
        pool_http1_max_pending_requests: None,
        upstream_id: Some(UPSTREAM_ID.to_string()),
        upstream_subset: None,
        api_spec_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: ResponseBodyMode::default(),
        listen_port: None,
        frontend_tls: false,
        passthrough: false,
        udp_idle_timeout_seconds: 60,
        tcp_idle_timeout_seconds: Some(300),
        websocket_idle_timeout_seconds: None,
        allowed_methods: None,
        allowed_ws_origins: vec![],
        udp_max_response_amplification_factor: None,
        stream_proxy_protocol: None,
        backend_proxy_protocol: None,
        stream_match: None,
        compiled_stream_match: None,
        created_at: now,
        updated_at: now,
        pending_limit_scope: None,
    }
}

fn source_pool(gateway: SvidBundle) -> Arc<HboneConnectionPool> {
    Arc::new(HboneConnectionPool::new(
        PoolConfig::default(),
        DnsCache::new(DnsConfig::default()),
        svid_slot(gateway),
        8,
    ))
}

/// The dispatch-side key identity, built exactly the way
/// `proxy_to_backend_hbone` builds it: everything that decides who is talking
/// to whom, under what credential, over what wire settings.
struct KeyIdentity {
    credential: HboneSourceCredential,
    pool_config: PoolConfig,
    peer_id: SpiffeId,
    app_host: String,
    app_port: u16,
    hbone_port: u16,
    asserted_principal: Option<SpiffeId>,
}

impl KeyIdentity {
    fn parts(&self, protocol: HboneInnerProtocol) -> HboneInnerKeyParts<'_> {
        HboneInnerKeyParts {
            protocol,
            namespace: NAMESPACE,
            proxy_id: PROXY_ID,
            upstream_id: Some(UPSTREAM_ID),
            proxy_lifecycle_generation: None,
            app_host: self.app_host.as_str(),
            app_port: self.app_port,
            dial_host: self.app_host.as_str(),
            hbone_port: self.hbone_port,
            expected_peer: Some(&self.peer_id),
            expected_trust_domain: None,
            sni_override: None,
            source_principal: self
                .asserted_principal
                .as_ref()
                .unwrap_or(&self.credential.identity),
            source_principal_asserted: self.asserted_principal.is_some(),
            credential: &self.credential,
            pool_config: &self.pool_config,
        }
    }
}

/// Everything one test drives: a real source pool, a real peer, a real app.
struct Fixture {
    pool: Arc<HboneConnectionPool>,
    peer: Peer,
    app: App,
    identity: KeyIdentity,
}

async fn fixture(behaviour: AppBehaviour, advertise: bool) -> Fixture {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let ids = identities();
    let app = start_app(behaviour).await;
    let peer = start_peer(svid_slot(ids.peer), app.addr, advertise).await;
    let pool = source_pool(ids.gateway);
    let credential = pool
        .source_credential_identity()
        .expect("the gateway SVID resolves a source credential identity");
    let identity = KeyIdentity {
        credential,
        pool_config: PoolConfig::default(),
        peer_id: ids.peer_id,
        app_host: "127.0.0.1".to_string(),
        app_port: 8080,
        hbone_port: peer.addr.port(),
        asserted_principal: None,
    };
    Fixture {
        pool,
        peer,
        app,
        identity,
    }
}

impl Fixture {
    /// Open ONE new CONNECT and run a fresh inner HTTP/1.1 client over it —
    /// the dispatch's cold-miss path, including reading the peer's capability
    /// advertisement off the `200` before the tunnel is consumed.
    async fn try_open_fresh_h1(&self) -> Result<HboneInnerH1Checkout, String> {
        let proxy = source_proxy();
        let tunnel = tokio::time::timeout(
            DEADLINE,
            self.pool.get_tunnel_via(
                &proxy,
                "127.0.0.1",
                &self.identity.app_host,
                self.identity.app_port,
                self.identity.app_port,
                self.identity.hbone_port,
                Some(&self.identity.peer_id),
                None,
                None,
                self.identity.asserted_principal.as_ref(),
            ),
        )
        .await
        .map_err(|_| "CONNECT timed out".to_string())?
        .map_err(|err| format!("the peer refused the CONNECT: {err}"))?;
        let advertised = tunnel.peer_advertises_inner_reuse();
        let (sender, connection) = hyper::client::conn::http1::Builder::new()
            .handshake::<_, HboneInnerH1RequestBody>(TokioIo::new(tunnel))
            .await
            .map_err(|err| format!("inner HTTP/1.1 handshake failed: {err}"))?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(self.pool.inner_pool().fresh_h1(
            &self.identity.parts(HboneInnerProtocol::Http1),
            sender,
            advertised,
            true,
            self.identity.credential.leaf_deadline,
        ))
    }

    async fn open_fresh_h1(&self) -> HboneInnerH1Checkout {
        self.try_open_fresh_h1()
            .await
            .expect("the peer admits the CONNECT")
    }

    /// One inner request, exactly as the dispatch does it: check out a lease if
    /// one is pooled, otherwise open a fresh CONNECT; send; and return the
    /// lease ONLY after the whole response body has been read.
    async fn request(&self) -> Result<(StatusCode, Bytes), String> {
        let mut checkout = match self.pool.inner_pool().checkout_h1(
            &self.identity.parts(HboneInnerProtocol::Http1),
            true,
            self.identity.credential.leaf_deadline,
        ) {
            Some(pooled) => pooled,
            None => self.try_open_fresh_h1().await?,
        };
        let request = http::Request::builder()
            .method(http::Method::GET)
            .uri("/")
            .header("host", "orders.local")
            .body(hbone_inner_h1_request_body_for_test(Bytes::new()))
            .expect("inner request");
        let response = tokio::time::timeout(DEADLINE, checkout.sender.send_request(request))
            .await
            .map_err(|_| "inner request timed out".to_string())?
            .map_err(|err| format!("inner send failed: {err}"))?;
        let status = response.status();
        // Every error arm below returns WITHOUT checking in, which is the whole
        // contract: a lease comes back only after a clean, fully consumed
        // response.
        let collected = tokio::time::timeout(DEADLINE, response.into_body().collect())
            .await
            .map_err(|_| "inner response body timed out".to_string())?
            .map_err(|err| format!("inner response body failed: {err}"))?;
        HboneInnerConnectionPool::checkin_h1_when_idle(self.pool.inner_pool(), checkout);
        Ok((status, collected.to_bytes()))
    }
}

/// `checkin_h1_when_idle` may defer onto a spawned task when hyper's
/// dispatcher has not re-armed yet, so residency is asserted by polling rather
/// than by reading the counter once.
async fn wait_for_pooled(pool: &HboneInnerConnectionPool, expected: usize) {
    tokio::time::timeout(DEADLINE, async {
        while pool.pooled_connections() != expected {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "expected {expected} pooled inner connections, found {}",
            pool.pooled_connections()
        )
    });
}

// ---------------------------------------------------------------------------
// The reuse claim, in the issue's own two counters
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_fenced_peer_reuses_the_inner_connection_and_the_app_accepts_once() {
    let fx = fixture(AppBehaviour::Ok, true).await;

    for _ in 0..3 {
        let (status, body) = fx.request().await.expect("request succeeds");
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.as_ref(), b"ok");
        wait_for_pooled(fx.pool.inner_pool(), 1).await;
    }

    assert_eq!(
        fx.peer.connects(),
        1,
        "three requests over a fenced tunnel must cost ONE CONNECT"
    );
    assert_eq!(
        fx.app.accepts(),
        1,
        "the destination application must see ONE accept(2), not one per request"
    );
    let stats = fx.pool.inner_pool().stats();
    assert_eq!(stats.h1_misses, 1, "only the first request is a cold miss");
    assert_eq!(stats.h1_hits, 2, "the other two are pool hits");
    assert_eq!(stats.evictions, 0);
    assert_eq!(stats.discards, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_peer_that_does_not_advertise_the_fence_keeps_per_request_behaviour() {
    let fx = fixture(AppBehaviour::Ok, false).await;

    for _ in 0..3 {
        let (status, body) = fx.request().await.expect("request succeeds");
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.as_ref(), b"ok");
    }

    assert_eq!(
        fx.peer.connects(),
        3,
        "without the capability the source must open one CONNECT per request"
    );
    assert_eq!(
        fx.app.accepts(),
        3,
        "and the application must see one accept(2) per request, exactly as before"
    );
    assert_eq!(
        fx.pool.inner_pool().pooled_connections(),
        0,
        "nothing may be pooled for a peer that does not fence its live tunnels"
    );
    let stats = fx.pool.inner_pool().stats();
    assert_eq!(stats.h1_hits, 0);
    assert_eq!(stats.h1_misses, 3);
    assert_eq!(
        stats.discards, 3,
        "each healthy-but-unpoolable connection is accounted as a discard"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn alternating_source_principals_never_share_an_inner_connection() {
    let mut fx = fixture(AppBehaviour::Ok, true).await;
    let caller_a = SpiffeId::new(CALLER_A).expect("caller a");
    let caller_b = SpiffeId::new(CALLER_B).expect("caller b");

    for round in 0..4 {
        fx.identity.asserted_principal = Some(if round % 2 == 0 {
            caller_a.clone()
        } else {
            caller_b.clone()
        });
        let (status, _) = fx.request().await.expect("request succeeds");
        assert_eq!(status, StatusCode::OK);
        wait_for_pooled(fx.pool.inner_pool(), if round == 0 { 1 } else { 2 }).await;
    }

    assert_eq!(
        fx.peer.connects(),
        2,
        "two principals must open two tunnels — and only two, because each \
         principal reuses its own"
    );
    assert_eq!(fx.app.accepts(), 2);
    let stats = fx.pool.inner_pool().stats();
    assert_eq!(stats.h1_misses, 2, "one cold miss per principal");
    assert_eq!(stats.h1_hits, 2, "and one hit per principal after that");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_gateways_own_svid_is_a_different_key_from_asserting_that_identity() {
    // "The gateway acting as itself" and "the gateway asserting an identity on
    // behalf of a peer" are different admission facts at the destination even
    // when the SPIFFE string is identical, so they must not share a connection.
    let mut fx = fixture(AppBehaviour::Ok, true).await;
    let own = fx.identity.credential.identity.clone();

    fx.request().await.expect("gateway-as-itself request");
    wait_for_pooled(fx.pool.inner_pool(), 1).await;

    fx.identity.asserted_principal = Some(own);
    fx.request().await.expect("asserted-identity request");
    wait_for_pooled(fx.pool.inner_pool(), 2).await;

    assert_eq!(
        fx.peer.connects(),
        2,
        "the asserted form must not inherit the unasserted form's connection"
    );
    assert_eq!(fx.app.accepts(), 2);
}

// ---------------------------------------------------------------------------
// Revocation, refusal, and credential bounds
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_revoked_tunnel_is_discarded_and_the_next_request_faces_the_new_policy() {
    let fx = fixture(AppBehaviour::Ok, true).await;

    fx.request().await.expect("first request");
    wait_for_pooled(fx.pool.inner_pool(), 1).await;
    assert_eq!(fx.peer.connects(), 1);

    // The receiver tightens: every live tunnel is cut (what a fence sweep's
    // revocation does to the wire) and the same principal's next CONNECT is
    // refused. Both halves matter — cutting alone would only cost a redial.
    fx.peer.revoke_all().await;
    fx.peer.set_refuse(true);

    // The next request must face the CURRENT policy rather than ride the
    // revoked tunnel. Either the pooled lease is already observably closed and
    // the fresh CONNECT is refused, or the close has not propagated yet and the
    // send fails pre-wire — which is exactly the case the dispatch replays onto
    // a fresh CONNECT that this peer now refuses. Both are failures here, and
    // neither is a served request.
    let refused = fx.request().await;
    assert!(
        refused.is_err(),
        "a reused tunnel must never survive its revocation, got {refused:?}"
    );

    // And the revoked connection is gone from the pool either way: a checkout
    // that found it took it out, and a checkout that found it closed evicted it.
    assert_eq!(fx.pool.inner_pool().pooled_connections(), 0);
    assert!(
        fx.pool
            .inner_pool()
            .checkout_h1(
                &fx.identity.parts(HboneInnerProtocol::Http1),
                true,
                fx.identity.credential.leaf_deadline,
            )
            .is_none(),
        "nothing reusable may remain for a principal the receiver now refuses"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_elapsed_source_credential_is_never_handed_out() {
    let fx = fixture(AppBehaviour::Ok, true).await;

    // A lease whose admitting credential has ALREADY elapsed. `checkin_h1` is
    // the direct entry point (`checkin_h1_when_idle` would refuse to pool it,
    // which is the production guard), so the pool is deliberately put into the
    // state time would otherwise produce: a resident connection past its bound.
    let elapsed = tokio::time::Instant::now();
    let expired = fx.pool.inner_pool().fresh_h1(
        &fx.identity.parts(HboneInnerProtocol::Http1),
        fx.open_fresh_h1().await.sender,
        true,
        true,
        Some(elapsed),
    );
    fx.pool.inner_pool().checkin_h1(expired);
    assert_eq!(fx.pool.inner_pool().pooled_connections(), 1);

    let checkout = fx.pool.inner_pool().checkout_h1(
        &fx.identity.parts(HboneInnerProtocol::Http1),
        true,
        fx.identity.credential.leaf_deadline,
    );
    assert!(
        checkout.is_none(),
        "reuse must never outlive the source credential that admitted it"
    );
    assert_eq!(
        fx.pool.inner_pool().pooled_connections(),
        0,
        "an expired entry is EVICTED, not merely skipped: it must not stay \
         reachable for the next caller either"
    );
    assert!(fx.pool.inner_pool().stats().evictions >= 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_lease_bound_only_ever_tightens_across_the_requests_that_use_it() {
    // The current request's credential bound is folded INTO the lease that
    // comes back, so a connection pooled under a long-lived credential cannot
    // be handed on with a longer bound than the request that last used it.
    // It deliberately does NOT decide whether the pooled entry may exist: a
    // caller arriving with a short-lived credential must not evict a healthy
    // connection out from under everyone else.
    let fx = fixture(AppBehaviour::Ok, true).await;

    fx.request().await.expect("first request");
    wait_for_pooled(fx.pool.inner_pool(), 1).await;

    let short_lived = tokio::time::Instant::now() + Duration::from_millis(50);
    let leased = fx
        .pool
        .inner_pool()
        .checkout_h1(
            &fx.identity.parts(HboneInnerProtocol::Http1),
            true,
            Some(short_lived),
        )
        .expect("a healthy connection is still reusable");
    assert!(leased.reused());

    // Once that short bound has passed, the lease may not re-enter the idle
    // set — even though the connection itself is perfectly healthy.
    tokio::time::sleep(Duration::from_millis(80)).await;
    HboneInnerConnectionPool::checkin_h1_when_idle(fx.pool.inner_pool(), leased);
    assert_eq!(
        fx.pool.inner_pool().pooled_connections(),
        0,
        "a lease past the earliest credential that ever used it is discarded"
    );
    assert!(fx.pool.inner_pool().stats().discards >= 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn keep_alive_off_never_consults_or_fills_the_idle_set() {
    let fx = fixture(AppBehaviour::Ok, true).await;

    let checkout = fx.pool.inner_pool().checkout_h1(
        &fx.identity.parts(HboneInnerProtocol::Http1),
        false,
        fx.identity.credential.leaf_deadline,
    );
    assert!(checkout.is_none(), "keep-alive off never reuses");

    let lease = fx.pool.inner_pool().fresh_h1(
        &fx.identity.parts(HboneInnerProtocol::Http1),
        fx.open_fresh_h1().await.sender,
        true,
        false,
        fx.identity.credential.leaf_deadline,
    );
    assert!(
        !lease.poolable(),
        "a lease taken under keep-alive off may never re-enter the idle set"
    );
    HboneInnerConnectionPool::checkin_h1_when_idle(fx.pool.inner_pool(), lease);
    assert_eq!(fx.pool.inner_pool().pooled_connections(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_truncated_response_never_returns_the_lease() {
    let fx = fixture(AppBehaviour::Truncate, true).await;

    let first = fx.request().await;
    assert!(
        first.is_err(),
        "a response that declares sixteen bytes and delivers five is truncated"
    );
    assert_eq!(
        fx.pool.inner_pool().pooled_connections(),
        0,
        "a truncated exchange leaves the framing state unknown, so the lease is \
         dropped and the tunnel retired — never pooled"
    );

    // The next request therefore pays a fresh CONNECT and a fresh app accept,
    // which is the point: a poisoned connection must not be handed to anyone.
    let _ = fx.request().await;
    assert_eq!(fx.peer.connects(), 2);
    assert_eq!(fx.app.accepts(), 2);
}

// ---------------------------------------------------------------------------
// Trust drains reach the inner connections
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn an_svid_rotation_retires_inner_connections_built_under_the_retired_leaf() {
    let fx = fixture(AppBehaviour::Ok, true).await;

    fx.request().await.expect("first request");
    wait_for_pooled(fx.pool.inner_pool(), 1).await;

    // The rotation drain resolves the retired leaf fingerprint out of the key,
    // exactly as it does for the outer transports.
    fx.pool
        .inner_pool()
        .retire_svid_fingerprints(&[Arc::clone(&fx.identity.credential.fingerprint)]);
    assert_eq!(
        fx.pool.inner_pool().pooled_connections(),
        0,
        "an inner connection must stop being reachable when the leaf that \
         authenticated its tunnel rotates out"
    );
    assert!(fx.pool.inner_pool().stats().evictions >= 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unrelated_fingerprint_retirement_leaves_the_pool_alone() {
    let fx = fixture(AppBehaviour::Ok, true).await;

    fx.request().await.expect("first request");
    wait_for_pooled(fx.pool.inner_pool(), 1).await;

    fx.pool
        .inner_pool()
        .retire_svid_fingerprints(&[Arc::from("some-other-leaf-fingerprint")]);
    assert_eq!(
        fx.pool.inner_pool().pooled_connections(),
        1,
        "a drain for a leaf this connection was never built under must not touch it"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_whole_pool_retirement_reaches_the_inner_connections_through_the_outer_pool() {
    let fx = fixture(AppBehaviour::Ok, true).await;

    fx.request().await.expect("first request");
    wait_for_pooled(fx.pool.inner_pool(), 1).await;

    // A committed gateway trust withdrawal clears the mesh pools WHOLE. Because
    // the inner pool is OWNED by the outer one, that reaches the inner
    // connections without a second call site anybody has to remember.
    fx.pool.force_drain_all();
    assert_eq!(
        fx.pool.inner_pool().pooled_connections(),
        0,
        "an inner connection is only ever as trustworthy as the tunnel it rides"
    );
}

// ---------------------------------------------------------------------------
// Bounds
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn the_per_key_idle_bound_is_enforced() {
    let fx = fixture(AppBehaviour::Ok, true).await;

    // One more exclusive lease than the per-key bound admits.
    let mut leases = Vec::new();
    for _ in 0..(MAX_IDLE_H1_PER_KEY + 1) {
        leases.push(fx.open_fresh_h1().await);
    }
    assert_eq!(fx.peer.connects(), MAX_IDLE_H1_PER_KEY + 1);
    for lease in leases {
        fx.pool.inner_pool().checkin_h1(lease);
    }

    assert_eq!(
        fx.pool.inner_pool().pooled_connections(),
        MAX_IDLE_H1_PER_KEY,
        "one key may never retain more than its bound"
    );
    assert_eq!(
        fx.pool.inner_pool().stats().discards,
        1,
        "the over-cap connection is discarded, which is the pre-reuse cost — \
         never an error"
    );
}

// ---------------------------------------------------------------------------
// Nested HTTP/2 (native gRPC inside the tunnel)
// ---------------------------------------------------------------------------

/// Open a CONNECT and run a nested HTTP/2 client over it, the way
/// `open_hbone_grpc_sender` does.
async fn open_fresh_h2(fx: &Fixture) -> (H2SendRequest<GrpcBody>, bool) {
    let proxy = source_proxy();
    let tunnel = tokio::time::timeout(
        DEADLINE,
        fx.pool.get_tunnel_via(
            &proxy,
            "127.0.0.1",
            &fx.identity.app_host,
            fx.identity.app_port,
            fx.identity.app_port,
            fx.identity.hbone_port,
            Some(&fx.identity.peer_id),
            None,
            None,
            None,
        ),
    )
    .await
    .expect("timely CONNECT")
    .expect("the peer admits the CONNECT");
    let advertised = tunnel.peer_advertises_inner_reuse();
    let (sender, connection) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .handshake::<_, GrpcBody>(TokioIo::new(tunnel))
        .await
        .expect("nested HTTP/2 handshake");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    (sender, advertised)
}

fn empty_grpc_body() -> GrpcBody {
    GrpcBody::Buffered(http_body_util::Full::new(Bytes::new()))
}

async fn send_rpc(sender: &mut H2SendRequest<GrpcBody>) -> Result<StatusCode, String> {
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri("http://orders.local/svc/Method")
        .header("content-type", "application/grpc")
        .body(empty_grpc_body())
        .expect("rpc request");
    tokio::time::timeout(DEADLINE, sender.ready())
        .await
        .map_err(|_| "rpc carrier never became ready".to_string())?
        .map_err(|err| format!("rpc carrier unusable: {err}"))?;
    let response = tokio::time::timeout(DEADLINE, sender.send_request(request))
        .await
        .map_err(|_| "rpc timed out".to_string())?
        .map_err(|err| format!("rpc failed: {err}"))?;
    let status = response.status();
    let _ = tokio::time::timeout(DEADLINE, response.into_body().collect()).await;
    Ok(status)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_nested_h2_sender_is_shared_across_rpcs_on_one_connect() {
    let fx = fixture(AppBehaviour::H2c { goaway_after: 0 }, true).await;
    let parts = fx.identity.parts(HboneInnerProtocol::H2);

    assert!(
        fx.pool.inner_pool().checkout_h2(&parts).is_none(),
        "the first RPC cannot be a pool hit"
    );
    let (mut sender, advertised) = open_fresh_h2(&fx).await;
    assert!(advertised, "the fixture peer advertises the fence");
    fx.pool.inner_pool().publish_h2(
        &parts,
        &sender,
        advertised,
        fx.identity.credential.leaf_deadline,
    );
    assert_eq!(
        send_rpc(&mut sender).await.expect("first rpc"),
        StatusCode::OK
    );

    // Every later RPC clones the published carrier: no CONNECT, no nested
    // preface/SETTINGS exchange, no second app accept.
    for _ in 0..2 {
        let mut shared = fx
            .pool
            .inner_pool()
            .checkout_h2(&parts)
            .expect("the shared nested HTTP/2 sender is reused");
        assert_eq!(
            send_rpc(&mut shared).await.expect("shared rpc"),
            StatusCode::OK
        );
    }

    assert_eq!(fx.peer.connects(), 1, "three RPCs must cost ONE CONNECT");
    assert_eq!(fx.app.accepts(), 1);
    let stats = fx.pool.inner_pool().stats();
    assert_eq!(stats.h2_hits, 2);
    assert_eq!(stats.h2_misses, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_nested_h2_sender_that_received_goaway_is_retired_and_never_reissued() {
    let fx = fixture(AppBehaviour::H2c { goaway_after: 1 }, true).await;
    let parts = fx.identity.parts(HboneInnerProtocol::H2);

    let (mut sender, advertised) = open_fresh_h2(&fx).await;
    fx.pool.inner_pool().publish_h2(
        &parts,
        &sender,
        advertised,
        fx.identity.credential.leaf_deadline,
    );
    assert_eq!(
        send_rpc(&mut sender).await.expect("first rpc"),
        StatusCode::OK
    );
    drop(sender);

    // The application answered one RPC and then went away. Once the connection
    // has drained, the carrier reports closed and the pool must retire it
    // rather than hand it out again.
    tokio::time::timeout(DEADLINE, async {
        loop {
            match fx.pool.inner_pool().checkout_h2(&parts) {
                Some(reused) if !reused.is_closed() => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                _ => return,
            }
        }
    })
    .await
    .expect("a drained carrier must stop being reissued");

    assert_eq!(
        fx.pool.inner_pool().pooled_connections(),
        0,
        "a retired carrier leaves the pool rather than staying reachable"
    );
    assert!(fx.pool.inner_pool().stats().evictions >= 1);

    // The next RPC opens a fresh CONNECT and a fresh nested connection.
    let (mut fresh, _) = open_fresh_h2(&fx).await;
    assert_eq!(
        send_rpc(&mut fresh).await.expect("rpc after goaway"),
        StatusCode::OK
    );
    assert_eq!(fx.peer.connects(), 2);
    assert_eq!(fx.app.accepts(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_nested_h2_sender_is_never_published_for_a_peer_without_the_capability() {
    let fx = fixture(AppBehaviour::H2c { goaway_after: 0 }, false).await;
    let parts = fx.identity.parts(HboneInnerProtocol::H2);

    let (mut sender, advertised) = open_fresh_h2(&fx).await;
    assert!(
        !advertised,
        "this peer does not advertise the admission fence"
    );
    fx.pool.inner_pool().publish_h2(
        &parts,
        &sender,
        advertised,
        fx.identity.credential.leaf_deadline,
    );
    assert_eq!(send_rpc(&mut sender).await.expect("rpc"), StatusCode::OK);

    assert_eq!(
        fx.pool.inner_pool().pooled_connections(),
        0,
        "an unfenced peer's nested connection must never be retained"
    );
    assert!(fx.pool.inner_pool().checkout_h2(&parts).is_none());
    assert_eq!(fx.pool.inner_pool().stats().discards, 1);
}

// ---------------------------------------------------------------------------
// Key partitioning, proven on the key text itself
// ---------------------------------------------------------------------------

/// Render the key for `parts` so a test can compare two identities directly.
fn key_of(parts: &HboneInnerKeyParts<'_>) -> String {
    let mut buf = String::new();
    ferrum_edge::proxy::hbone_inner_pool::write_hbone_inner_pool_key(&mut buf, parts);
    buf
}

#[tokio::test(flavor = "multi_thread")]
async fn every_admission_component_partitions_the_key() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let ids = identities();
    let pool = source_pool(ids.gateway);
    let credential = pool
        .source_credential_identity()
        .expect("source credential identity");
    let base = KeyIdentity {
        credential,
        pool_config: PoolConfig::default(),
        peer_id: ids.peer_id.clone(),
        app_host: "10.0.0.7".to_string(),
        app_port: 8080,
        hbone_port: 15008,
        asserted_principal: None,
    };
    let baseline = key_of(&base.parts(HboneInnerProtocol::Http1));

    // The inner wire protocol.
    assert_ne!(baseline, key_of(&base.parts(HboneInnerProtocol::H2)));

    let mut variant = KeyIdentity {
        credential: base.credential.clone(),
        pool_config: PoolConfig::default(),
        peer_id: ids.peer_id.clone(),
        app_host: base.app_host.clone(),
        app_port: base.app_port,
        hbone_port: base.hbone_port,
        asserted_principal: None,
    };

    variant.app_host = "10.0.0.8".to_string();
    assert_ne!(
        baseline,
        key_of(&variant.parts(HboneInnerProtocol::Http1)),
        "a different application endpoint is a different connection"
    );
    variant.app_host = base.app_host.clone();

    variant.app_port = 9090;
    assert_ne!(baseline, key_of(&variant.parts(HboneInnerProtocol::Http1)));
    variant.app_port = base.app_port;

    variant.hbone_port = 15009;
    assert_ne!(
        baseline,
        key_of(&variant.parts(HboneInnerProtocol::Http1)),
        "a different peer HBONE listener is a different dial"
    );
    variant.hbone_port = base.hbone_port;

    variant.asserted_principal = Some(SpiffeId::new(CALLER_A).expect("caller a"));
    let asserted_a = key_of(&variant.parts(HboneInnerProtocol::Http1));
    assert_ne!(baseline, asserted_a, "an asserted principal partitions");
    variant.asserted_principal = Some(SpiffeId::new(CALLER_B).expect("caller b"));
    assert_ne!(
        asserted_a,
        key_of(&variant.parts(HboneInnerProtocol::Http1)),
        "two asserted principals never share an inner connection"
    );
    variant.asserted_principal = None;

    // The source credential generation.
    variant.credential = HboneSourceCredential {
        generation: base.credential.generation + 1,
        ..base.credential.clone()
    };
    assert_ne!(
        baseline,
        key_of(&variant.parts(HboneInnerProtocol::Http1)),
        "a rotation partitions the pool rather than laundering a connection"
    );

    // The leaf fingerprint, at the fixed index the rotation drain resolves.
    variant.credential = HboneSourceCredential {
        fingerprint: Arc::from("a-different-leaf"),
        ..base.credential.clone()
    };
    let rotated = key_of(&variant.parts(HboneInnerProtocol::Http1));
    assert_ne!(baseline, rotated);
    assert_eq!(
        rotated.split('|').nth(2),
        Some("a-different-leaf"),
        "the rotation drain resolves the fingerprint positionally, so its index \
         is part of the contract"
    );

    // The effective connection policy.
    variant.credential = base.credential.clone();
    variant.pool_config = PoolConfig {
        http2_max_frame_size: PoolConfig::default().http2_max_frame_size + 1024,
        ..PoolConfig::default()
    };
    assert_ne!(
        baseline,
        key_of(&variant.parts(HboneInnerProtocol::Http1)),
        "wire settings that configure the constructed client are part of the key"
    );
}

/// The per-request policy fields the sibling pools also exclude. They are
/// applied per dispatch on every request, reused connection or not, so keying
/// on them would fragment the pool without bounding anything.
#[tokio::test(flavor = "multi_thread")]
async fn per_request_policy_is_not_part_of_the_key() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let ids = identities();
    let pool = source_pool(ids.gateway);
    let credential = pool
        .source_credential_identity()
        .expect("source credential identity");

    let mut proxy = source_proxy();
    let baseline = PoolConfig::default().for_proxy(&proxy);
    proxy.backend_connect_timeout_ms = 1;
    proxy.backend_read_timeout_ms = 2;
    proxy.backend_write_timeout_ms = 3;
    let retimed = PoolConfig::default().for_proxy(&proxy);

    let identity_for = |pool_config: PoolConfig| KeyIdentity {
        credential: credential.clone(),
        pool_config,
        peer_id: ids.peer_id.clone(),
        app_host: "10.0.0.7".to_string(),
        app_port: 8080,
        hbone_port: 15008,
        asserted_principal: None,
    };

    assert_eq!(
        key_of(&identity_for(baseline).parts(HboneInnerProtocol::Http1)),
        key_of(&identity_for(retimed).parts(HboneInnerProtocol::Http1)),
        "connect/read/write timeouts are applied per dispatch and must not \
         partition a pooled connection"
    );
}
