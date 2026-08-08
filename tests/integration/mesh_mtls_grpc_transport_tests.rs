//! Live data-path regression for gRPC dispatched over the Sidecar SVID-mTLS
//! mesh transport (issue #3284).
//!
//! Before #3284 every gRPC dispatch surface that could not reach
//! `proxy_to_backend_mesh_mtls` — notably the HTTP/3 cross-protocol bridge —
//! refused a `mesh.mtls`-tagged target pre-dial with UNAVAILABLE. The fix routes
//! those dispatches through `GrpcDispatchTransport`, which hands the SHARED
//! `GrpcBody` to the SVID-mTLS HTTP/2 pool instead of the direct-dial gRPC pool.
//!
//! These tests drive that exact transport against a REAL peer: a rustls SVID
//! mTLS listener speaking real HTTP/2, answering with response headers, a DATA
//! frame, and a terminal TRAILERS frame. They assert the authenticated hop is
//! taken (the server observes this gateway's client SVID), that the request is
//! addressed with the mesh `:authority` rather than the transport dial port,
//! that `te: trailers` survives, and that `grpc-status` relays back — and that a
//! target whose pinned peer identity does not match FAILS CLOSED rather than
//! falling back to an unauthenticated direct dial.

use arc_swap::ArcSwap;
use bytes::Bytes;
use chrono::Utc;
use ferrum_edge::config::PoolConfig;
use ferrum_edge::config::types::{
    AuthMode, BackendScheme, DispatchKind, Proxy, ResponseBodyMode, UpstreamTarget,
};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain, spiffe_id_to_san};
use ferrum_edge::identity::{SharedSvidBundle, SvidBundle, TrustBundle, TrustBundleSet};
use ferrum_edge::proxy::grpc_proxy::{
    GrpcConnectionPool, GrpcDispatchTransport, GrpcResponseKind, proxy_grpc_request_from_bytes,
};
use ferrum_edge::proxy::hbone_pool::MESH_SPIFFE_ID_TAG;
use ferrum_edge::proxy::mesh_mtls_pool::{
    MESH_MTLS_PORT_TAG, MESH_MTLS_TARGET_TAG, MeshMtlsConnectionPool,
};
use ferrum_edge::tls::spiffe::build_spiffe_inbound_config;
use http::{HeaderMap, Response, StatusCode};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_rustls::TlsAcceptor;

/// The destination's declared APPLICATION port. Deliberately different from the
/// port the transport actually dials (the peer sidecar's inbound mTLS listener),
/// so the test proves the authority/dial-port split rather than a coincidence.
const APP_PORT: u16 = 9080;

fn init_crypto_provider() {
    // Installing twice across tests in one binary is expected; ignore the error.
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());
}

fn synthetic_root(td: &TrustDomain) -> (Vec<u8>, String, String) {
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, format!("{}-test-root", td.as_str()));
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
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + time::Duration::hours(1);

    let cert = params.signed_by(&leaf_key, &issuer).expect("leaf cert");
    (cert.der().to_vec(), leaf_key.serialize_der())
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

fn grpc_proxy_for_test() -> Proxy {
    let now = Utc::now();
    Proxy {
        id: "mesh-mtls-grpc".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: Some("Mesh mTLS gRPC".to_string()),
        hosts: vec!["reviews.default.svc.cluster.local".to_string()],
        listen_path: Some("/".to_string()),
        backend_scheme: Some(BackendScheme::Http),
        dispatch_kind: DispatchKind::from(BackendScheme::Http),
        backend_host: "127.0.0.1".to_string(),
        backend_port: APP_PORT,
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
        upstream_id: None,
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
        stream_match: None,
        compiled_stream_match: None,
        created_at: now,
        updated_at: now,
    }
}

/// The mesh-tagged target: `host:APP_PORT` is the destination workload, while
/// `mesh.mtls_port` is the peer sidecar's inbound mTLS listener that is actually
/// dialed.
fn mesh_mtls_target(mtls_port: u16, pinned_peer: &str) -> UpstreamTarget {
    let mut tags = HashMap::new();
    tags.insert(MESH_MTLS_TARGET_TAG.to_string(), "true".to_string());
    tags.insert(MESH_MTLS_PORT_TAG.to_string(), mtls_port.to_string());
    tags.insert(MESH_SPIFFE_ID_TAG.to_string(), pinned_peer.to_string());
    UpstreamTarget {
        host: "127.0.0.1".to_string(),
        port: APP_PORT,
        service_port_policy_key: None,
        weight: 1,
        tags,
        locality: None,
        path: None,
    }
}

/// What the peer sidecar observed on the accepted gRPC stream.
struct ObservedRequest {
    authority: String,
    path: String,
    te: Option<String>,
    content_type: Option<String>,
    peer_presented_client_cert: bool,
}

/// A real SVID-mTLS HTTP/2 listener that answers ONE gRPC request with
/// headers + DATA + a terminal TRAILERS frame carrying `grpc-status`.
async fn start_mesh_mtls_grpc_server(
    server_slot: SharedSvidBundle,
    response_body: Bytes,
) -> (std::net::SocketAddr, oneshot::Receiver<ObservedRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mesh mtls server");
    let addr = listener.local_addr().expect("listener addr");
    let (observed_tx, observed_rx) = oneshot::channel();

    tokio::spawn(async move {
        let inbound = build_spiffe_inbound_config(server_slot, true, Arc::new(Vec::new()))
            .expect("server config");
        let acceptor = TlsAcceptor::from(inbound);
        let (tcp, _) = listener.accept().await.expect("accept mesh mtls tcp");
        let tls = acceptor.accept(tcp).await.expect("accept spiffe tls");
        let peer_presented_client_cert = tls.get_ref().1.peer_certificates().is_some();
        let mut h2 = h2::server::handshake(tls).await.expect("h2 server");
        let (request, mut respond) = h2
            .accept()
            .await
            .expect("gRPC stream")
            .expect("stream ok");

        let header = |name: &str| {
            request
                .headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        let _ = observed_tx.send(ObservedRequest {
            authority: request
                .uri()
                .authority()
                .map(|a| a.to_string())
                .unwrap_or_default(),
            path: request.uri().path().to_string(),
            te: header("te"),
            content_type: header("content-type"),
            peer_presented_client_cert,
        });

        // Drain the request body so the client's upload completes before the
        // terminal trailers are written.
        let mut recv = request.into_body();
        while let Some(chunk) = recv.data().await {
            let chunk = chunk.expect("request data");
            let _ = recv.flow_control().release_capacity(chunk.len());
        }

        let response = Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/grpc")
            .body(())
            .expect("grpc response");
        let mut send = respond.send_response(response, false).expect("send headers");
        send.send_data(response_body, false).expect("send data");
        let mut trailers = HeaderMap::new();
        trailers.insert("grpc-status", "0".parse().expect("status value"));
        trailers.insert("grpc-message", "ok".parse().expect("message value"));
        send.send_trailers(trailers).expect("send trailers");

        // Keep the connection alive until the client is done reading.
        while let Some(next) = h2.accept().await {
            if next.is_err() {
                break;
            }
        }
    });

    (addr, observed_rx)
}

fn mesh_mtls_pool(gateway_slot: SharedSvidBundle) -> MeshMtlsConnectionPool {
    MeshMtlsConnectionPool::new_with_svid_generation(
        PoolConfig::default(),
        DnsCache::new(DnsConfig::default()),
        gateway_slot,
        8,
        Arc::new(AtomicU64::new(0)),
    )
}

/// A length-prefixed gRPC message (5-byte prefix + payload), the wire shape both
/// directions carry.
fn grpc_message(payload: &[u8]) -> Bytes {
    let mut framed = Vec::with_capacity(5 + payload.len());
    framed.push(0);
    framed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    framed.extend_from_slice(payload);
    Bytes::from(framed)
}

#[tokio::test]
async fn grpc_dispatches_over_sidecar_mesh_mtls_and_relays_status_trailers() {
    init_crypto_provider();
    let td = TrustDomain::new("cluster.local").expect("trust domain");
    let (root_der, root_pem, root_key_pem) = synthetic_root(&td);

    let gateway_id =
        SpiffeId::new("spiffe://cluster.local/ns/default/sa/gateway").expect("gateway id");
    let peer_id = SpiffeId::new("spiffe://cluster.local/ns/default/sa/reviews").expect("peer id");
    let (gateway_leaf, gateway_key) = issue_svid(&gateway_id, &root_pem, &root_key_pem);
    let (peer_leaf, peer_key) = issue_svid(&peer_id, &root_pem, &root_key_pem);

    let gateway_slot = svid_slot(bundle_for(
        gateway_id.clone(),
        gateway_leaf,
        gateway_key,
        root_der.clone(),
    ));
    let server_slot = svid_slot(bundle_for(
        peer_id.clone(),
        peer_leaf,
        peer_key,
        root_der.clone(),
    ));

    let expected_body = grpc_message(b"pong");
    let (addr, observed_rx) =
        start_mesh_mtls_grpc_server(server_slot, expected_body.clone()).await;

    let grpc_pool = GrpcConnectionPool::default();
    let mesh_pool = mesh_mtls_pool(gateway_slot);
    let proxy = grpc_proxy_for_test();
    let target = mesh_mtls_target(addr.port(), peer_id.as_str());

    let transport = GrpcDispatchTransport::for_target(&grpc_pool, &mesh_pool, Some(&target))
        .expect("mesh.mtls target must resolve the sidecar mTLS transport");
    assert_eq!(
        transport.label(),
        "mesh_mtls",
        "a mesh.mtls target must NOT resolve to the direct-dial gRPC pool"
    );

    let mut headers = hyper::HeaderMap::new();
    headers.insert("content-type", "application/grpc".parse().unwrap());
    let dns = DnsCache::new(DnsConfig::default());
    // `proxy_headers` is the AUTHORITATIVE materialized header view: a name
    // absent from it is treated as a plugin removal, so the content type has to
    // be present here exactly as the real request path supplies it.
    let mut proxy_headers = HashMap::new();
    proxy_headers.insert("content-type".to_string(), "application/grpc".to_string());

    let result = proxy_grpc_request_from_bytes(
        hyper::Method::POST,
        headers,
        grpc_message(b"ping"),
        None,
        &proxy,
        &format!("http://127.0.0.1:{APP_PORT}/reviews.Reviews/Get"),
        &transport,
        &dns,
        &proxy_headers,
        false,
        0,
        None,
    )
    .await
    .expect("gRPC over the sidecar mesh mTLS transport must succeed");

    let response = match result {
        GrpcResponseKind::Buffered(response) => response,
        GrpcResponseKind::Streaming(_) => panic!("buffered dispatch returned a streaming response"),
    };
    assert_eq!(response.status, 200);
    assert_eq!(
        response.body, expected_body,
        "the backend's gRPC message must relay byte-for-byte"
    );
    assert_eq!(
        response.trailers.get("grpc-status").map(String::as_str),
        Some("0"),
        "HTTP/2 trailers must survive the mesh hop; trailers were {:?}",
        response.trailers
    );
    assert_eq!(
        response.trailers.get("grpc-message").map(String::as_str),
        Some("ok")
    );

    let observed = observed_rx.await.expect("server observed the request");
    assert!(
        observed.peer_presented_client_cert,
        "the mesh hop must present this gateway's client SVID, never an unauthenticated dial"
    );
    assert_eq!(
        observed.authority,
        format!("127.0.0.1:{APP_PORT}"),
        "the request must be addressed to the destination APP port, not the :15006-style dial port"
    );
    assert_eq!(observed.path, "/reviews.Reviews/Get");
    assert_eq!(
        observed.te.as_deref(),
        Some("trailers"),
        "the gRPC HTTP/2 mapping mandates `te: trailers` on the mesh transport too"
    );
    assert_eq!(observed.content_type.as_deref(), Some("application/grpc"));
}

#[tokio::test]
async fn grpc_over_mesh_mtls_fails_closed_when_the_pinned_peer_does_not_match() {
    init_crypto_provider();
    let td = TrustDomain::new("cluster.local").expect("trust domain");
    let (root_der, root_pem, root_key_pem) = synthetic_root(&td);

    let gateway_id =
        SpiffeId::new("spiffe://cluster.local/ns/default/sa/gateway").expect("gateway id");
    let peer_id = SpiffeId::new("spiffe://cluster.local/ns/default/sa/reviews").expect("peer id");
    let (gateway_leaf, gateway_key) = issue_svid(&gateway_id, &root_pem, &root_key_pem);
    let (peer_leaf, peer_key) = issue_svid(&peer_id, &root_pem, &root_key_pem);

    let gateway_slot = svid_slot(bundle_for(
        gateway_id.clone(),
        gateway_leaf,
        gateway_key,
        root_der.clone(),
    ));
    let server_slot = svid_slot(bundle_for(
        peer_id.clone(),
        peer_leaf,
        peer_key,
        root_der.clone(),
    ));

    let (addr, _observed_rx) =
        start_mesh_mtls_grpc_server(server_slot, grpc_message(b"pong")).await;

    let grpc_pool = GrpcConnectionPool::default();
    let mesh_pool = mesh_mtls_pool(gateway_slot);
    let proxy = grpc_proxy_for_test();
    // Same reachable peer, but the target pins a DIFFERENT workload identity.
    let target = mesh_mtls_target(addr.port(), "spiffe://cluster.local/ns/default/sa/ratings");

    let transport = GrpcDispatchTransport::for_target(&grpc_pool, &mesh_pool, Some(&target))
        .expect("a well-formed mesh.mtls target still resolves the transport");

    let mut headers = hyper::HeaderMap::new();
    headers.insert("content-type", "application/grpc".parse().unwrap());
    let dns = DnsCache::new(DnsConfig::default());
    // `proxy_headers` is the AUTHORITATIVE materialized header view: a name
    // absent from it is treated as a plugin removal, so the content type has to
    // be present here exactly as the real request path supplies it.
    let mut proxy_headers = HashMap::new();
    proxy_headers.insert("content-type".to_string(), "application/grpc".to_string());

    let result = proxy_grpc_request_from_bytes(
        hyper::Method::POST,
        headers,
        grpc_message(b"ping"),
        None,
        &proxy,
        &format!("http://127.0.0.1:{APP_PORT}/reviews.Reviews/Get"),
        &transport,
        &dns,
        &proxy_headers,
        false,
        0,
        None,
    )
    .await;

    assert!(
        result.is_err(),
        "a peer whose SVID does not match the pinned mesh.spiffe_id must fail closed, \
         never fall back to an unauthenticated direct dial"
    );
}
