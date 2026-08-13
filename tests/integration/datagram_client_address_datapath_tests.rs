//! Live UDP and DTLS datapaths for the datagram client-address envelope
//! (issue #3289).
//!
//! A real `start_udp_listener` runs with the gate engaged, a real UDP client
//! plays the trusted datagram load balancer, and a real echo backend answers.
//! What is asserted is what the feature exists for: the authenticated forwarded
//! address becomes the plugin-visible `client_ip` while `direct_client_ip`
//! stays the balancer's socket peer, the backend receives the payload with the
//! envelope stripped, and every unauthenticated or malformed variant is dropped
//! with nothing reaching the backend.
//!
//! The DTLS listener has its own pre-demux path, so it is covered separately
//! against a real `DtlsServer`: a wrapping relay drives a real `dimpl`
//! handshake through the gate, proving the envelope is validated and stripped
//! before the record layer and that the authenticated forwarded client reaches
//! the accepted `DtlsServerConn`, while handshake-shaped datagrams that fail
//! the gate allocate no association at all.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, watch};

use ferrum_edge::_test_support::prepend_proxy_plugin_for_test;
use ferrum_edge::adaptive_buffer::AdaptiveBufferTracker;
use ferrum_edge::circuit_breaker::CircuitBreakerCache;
use ferrum_edge::config::types::{AuthMode, BackendScheme, DispatchKind, GatewayConfig, Proxy};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::dtls::{
    BackendDtlsParams, DtlsConnection, DtlsServer, DtlsServerLimits, FrontendDtlsConfig,
};
use ferrum_edge::fips::approved::HmacSha256Key;
use ferrum_edge::modes::mesh::outbound_enforcement::empty_slot;
use ferrum_edge::overload::OverloadState;
use ferrum_edge::plugin_cache::PluginCache;
use ferrum_edge::plugins::{
    Plugin, PluginResult, ProxyProtocol, StreamConnectionContext, UDP_ONLY_PROTOCOLS,
    UdpDatagramContext, UdpDatagramDirection, UdpDatagramVerdict,
};
use ferrum_edge::proxy::client_ip::TrustedProxies;
use ferrum_edge::proxy::datagram_client_address::{
    DatagramClientAddressGate, encode_datagram_with_metadata,
};
use ferrum_edge::proxy::udp_proxy::{UdpListenerConfig, UdpProxyMetrics, start_udp_listener};
use ferrum_edge::request_epoch::RequestEpochStore;

use crate::scaffolding::ports::reserve_udp_port;

const PROXY_ID: &str = "udp-datagram-client-address";
const SECRET: &str = "0123456789abcdef0123456789abcdef";
const RECV_TIMEOUT: Duration = Duration::from_secs(5);
const DROP_OBSERVATION_WINDOW: Duration = Duration::from_millis(250);
const PER_ATTEMPT_STARTED_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_GATEWAY_ATTEMPTS: u32 = 3;

/// Records the identities the gateway published for admitted traffic.
#[derive(Default)]
struct IdentityRecorder {
    /// `(client_ip, direct_client_ip)` from `on_stream_connect`.
    stream: Mutex<Vec<(String, String)>>,
    /// `client_ip` from each client→backend `on_udp_datagram`.
    datagram: Mutex<Vec<String>>,
    datagram_count: AtomicU64,
}

#[async_trait]
impl Plugin for IdentityRecorder {
    fn name(&self) -> &str {
        "test_datagram_identity_recorder"
    }

    fn priority(&self) -> u16 {
        0
    }

    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        UDP_ONLY_PROTOCOLS
    }

    fn requires_udp_datagram_hooks(&self) -> bool {
        true
    }

    async fn on_stream_connect(&self, ctx: &mut StreamConnectionContext) -> PluginResult {
        self.stream
            .lock()
            .await
            .push((ctx.client_ip.clone(), ctx.direct_client_ip.clone()));
        PluginResult::Continue
    }

    async fn on_udp_datagram(&self, ctx: &UdpDatagramContext<'_>) -> UdpDatagramVerdict {
        if ctx.direction == UdpDatagramDirection::ClientToBackend {
            self.datagram_count.fetch_add(1, Ordering::Relaxed);
            self.datagram.lock().await.push(ctx.client_ip.to_string());
        }
        UdpDatagramVerdict::Forward
    }
}

fn udp_proxy(listen_port: u16, backend_port: u16) -> Proxy {
    Proxy {
        id: PROXY_ID.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: Some("Datagram client address".to_string()),
        hosts: vec![],
        listen_path: None,
        backend_scheme: Some(BackendScheme::Udp),
        dispatch_kind: DispatchKind::UdpRaw,
        backend_host: "127.0.0.1".to_string(),
        backend_port,
        backend_path: None,
        strip_listen_path: true,
        preserve_host_header: false,
        backend_connect_timeout_ms: 5000,
        backend_read_timeout_ms: 30000,
        backend_write_timeout_ms: 30000,
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
        circuit_breaker: None,
        retry: None,
        response_body_mode: Default::default(),
        listen_port: Some(listen_port),
        frontend_tls: false,
        passthrough: false,
        udp_idle_timeout_seconds: 60,
        udp_max_response_amplification_factor: None,
        // The datagram client-address envelope is required on this listener.
        stream_proxy_protocol: Some(true),
        backend_proxy_protocol: None,
        stream_match: None,
        compiled_stream_match: None,
        tcp_idle_timeout_seconds: Some(0),
        websocket_idle_timeout_seconds: None,
        allowed_methods: None,
        allowed_ws_origins: vec![],
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        pending_limit_scope: None,
    }
}

async fn spawn_udp_echo_backend(socket: Arc<UdpSocket>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((n, peer)) => {
                    let _ = socket.send_to(&buf[..n], peer).await;
                }
                Err(_) => return,
            }
        }
    })
}

struct SpawnedGateway {
    listen_port: u16,
    shutdown_tx: watch::Sender<bool>,
    join: tokio::task::JoinHandle<()>,
    metrics: Arc<UdpProxyMetrics>,
    recorder: Arc<IdentityRecorder>,
}

impl SpawnedGateway {
    async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        let _ = tokio::time::timeout(RECV_TIMEOUT, self.join).await;
    }
}

async fn try_spawn_gateway(
    backend_port: u16,
    listen_port: u16,
    authenticated: bool,
) -> Option<SpawnedGateway> {
    let recorder = Arc::new(IdentityRecorder::default());
    let proxy = udp_proxy(listen_port, backend_port);
    let proxy_namespace = proxy.namespace.clone();
    let gateway_config = GatewayConfig {
        version: "1".to_string(),
        proxies: vec![proxy],
        consumers: vec![],
        plugin_configs: vec![],
        upstreams: vec![],
        loaded_at: Utc::now(),
        known_namespaces: Vec::new(),
        ..Default::default()
    };
    let plugin_cache =
        Arc::new(PluginCache::new(&gateway_config).expect("PluginCache builds with no plugins"));
    prepend_proxy_plugin_for_test(
        &plugin_cache,
        &proxy_namespace,
        PROXY_ID,
        Arc::clone(&recorder) as Arc<dyn Plugin>,
    )
    .expect("inject identity recorder");

    let consumer_index = Arc::new(ferrum_edge::consumer_index::ConsumerIndex::new(
        &gateway_config.consumers,
    ));
    let load_balancer_cache = Arc::new(ferrum_edge::load_balancer::LoadBalancerCache::new(
        &gateway_config,
    ));
    let request_epoch = Arc::new(RequestEpochStore::from_runtime_parts(
        gateway_config,
        &plugin_cache,
        &consumer_index,
        &load_balancer_cache,
    ));
    let metrics = Arc::new(UdpProxyMetrics::default());
    let started = Arc::new(AtomicBool::new(false));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // The test client plays the trusted load balancer on loopback.
    let trusted_proxies =
        Arc::new(TrustedProxies::parse_strict("127.0.0.1", "test").expect("trust list"));
    let gate = Arc::new(DatagramClientAddressGate::new(
        trusted_proxies,
        authenticated.then_some(SECRET),
        listen_port,
    ));

    let listener_started = Arc::clone(&started);
    let listener_metrics = Arc::clone(&metrics);
    let cfg = UdpListenerConfig {
        port: listen_port,
        bind_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        proxy_id: PROXY_ID.to_string(),
        proxy_namespace,
        dns_cache: DnsCache::new(DnsConfig::default()),
        request_epoch,
        health_checker: Arc::new(ferrum_edge::health_check::HealthChecker::new()),
        shutdown: shutdown_rx,
        global_shutdown: None,
        metrics: listener_metrics,
        frontend_dtls_config: None,
        dtls_server_tx: None,
        tls_no_verify: false,
        tls_ca_bundle_path: None,
        max_sessions: 1024,
        frontend_tls_handshake_timeout_seconds: 10,
        cleanup_interval_seconds: 10,
        session_shard_amount: 0,
        circuit_breaker_cache: Arc::new(CircuitBreakerCache::new()),
        crls: Arc::new(Vec::new()),
        backend_tls_reload_epoch: Arc::new(AtomicU64::new(0)),
        started: listener_started,
        sni_proxy_ids: None,
        adaptive_buffer: Arc::new(AdaptiveBufferTracker::new(
            true, true, 300, 8192, 262_144, 65_536, 6000,
        )),
        recvmmsg_batch_size: 64,
        overload: Arc::new(OverloadState::new()),
        so_busy_poll_us: 0,
        udp_gro_enabled: false,
        udp_gso_enabled: false,
        udp_pktinfo_enabled: false,
        mesh_outbound_enforcement: empty_slot(),
        datagram_client_address: Some(gate),
    };
    let join = tokio::spawn(async move {
        let _ = start_udp_listener(cfg).await;
    });

    let deadline = std::time::Instant::now() + PER_ATTEMPT_STARTED_TIMEOUT;
    loop {
        if started.load(Ordering::Acquire) {
            return Some(SpawnedGateway {
                listen_port,
                shutdown_tx,
                join,
                metrics,
                recorder,
            });
        }
        if join.is_finished() {
            let _ = join.await;
            return None;
        }
        if std::time::Instant::now() > deadline {
            let _ = shutdown_tx.send(true);
            join.abort();
            let _ = join.await;
            return None;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

async fn spawn_gateway(backend_port: u16, authenticated: bool) -> SpawnedGateway {
    for attempt in 1..=MAX_GATEWAY_ATTEMPTS {
        let frontend = reserve_udp_port().await.expect("reserve frontend UDP port");
        let listen_port = frontend.drop_and_take_port();
        if let Some(gateway) = try_spawn_gateway(backend_port, listen_port, authenticated).await {
            return gateway;
        }
        eprintln!(
            "datagram client-address spawn attempt {attempt}/{MAX_GATEWAY_ATTEMPTS} on \
             {listen_port} failed — retrying"
        );
        if attempt < MAX_GATEWAY_ATTEMPTS {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    panic!("udp listener never reported started=true after {MAX_GATEWAY_ATTEMPTS} attempts");
}

fn key() -> HmacSha256Key {
    HmacSha256Key::new_from_slice(SECRET.as_bytes()).expect("hmac key")
}

/// Run a datagram load-balancer shim between one DTLS client and Ferrum's DTLS
/// demuxer. The first ClientHello is deliberately replayed without an envelope
/// and must be dropped; every retransmission and application packet is wrapped
/// with authenticated client-address metadata. Server packets travel back
/// unchanged because the envelope is an inbound load-balancer contract.
async fn spawn_dtls_metadata_relay(
    server_addr: SocketAddr,
    forwarded_client: SocketAddr,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let socket = Arc::new(
        UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind DTLS metadata relay"),
    );
    let relay_addr = socket.local_addr().expect("DTLS metadata relay addr");
    let task = tokio::spawn(async move {
        let mut client_addr = None;
        let mut replayed_bare_client_hello = false;
        let mut buf = vec![0u8; 65_535];
        while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
            if peer == server_addr {
                if let Some(client_addr) = client_addr {
                    let _ = socket.send_to(&buf[..len], client_addr).await;
                }
                continue;
            }

            if client_addr.is_some_and(|established| established != peer) {
                continue;
            }
            client_addr = Some(peer);

            if !replayed_bare_client_hello {
                replayed_bare_client_hello = true;
                let _ = socket.send_to(&buf[..len], server_addr).await;
                continue;
            }

            let wrapped = encode_datagram_with_metadata(
                forwarded_client,
                server_addr,
                &buf[..len],
                Some(&key()),
            );
            let _ = socket.send_to(&wrapped, server_addr).await;
        }
    });
    (relay_addr, task)
}

/// Receive one datagram, or `None` if the observation window elapses. Used both
/// for success (a reply must arrive) and for refusal (nothing may arrive).
async fn recv_within(socket: &UdpSocket, window: Duration) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; 65535];
    match tokio::time::timeout(window, socket.recv_from(&mut buf)).await {
        Ok(Ok((n, _))) => Some(buf[..n].to_vec()),
        _ => None,
    }
}

#[tokio::test]
async fn authenticated_envelope_drives_the_live_dtls_demux_and_binds_identity() {
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    let mut server = None;
    let mut drops = Arc::new(AtomicU64::new(0));
    for attempt in 1..=MAX_GATEWAY_ATTEMPTS {
        let frontend = reserve_udp_port().await.expect("reserve DTLS port");
        let listen_port = frontend.drop_and_take_port();
        let frontend_config = FrontendDtlsConfig {
            dimpl_config: Arc::new(
                dimpl::Config::builder()
                    .build()
                    .expect("DTLS server config"),
            ),
            certificate: dimpl::certificate::generate_self_signed_certificate()
                .expect("DTLS server certificate")
                .into(),
            client_cert_verifier: None,
        };
        let attempt_drops = Arc::new(AtomicU64::new(0));
        let gate = Arc::new(DatagramClientAddressGate::new(
            Arc::new(TrustedProxies::parse_strict("127.0.0.1", "test").expect("trust list")),
            Some(SECRET),
            listen_port,
        ));
        match DtlsServer::bind_with_limits(
            SocketAddr::from(([127, 0, 0, 1], listen_port)),
            frontend_config,
            DtlsServerLimits {
                max_sessions: Some(16),
                handshake_timeout: Some(Duration::from_secs(15)),
                datagram_client_address: Some(gate),
                datagram_client_address_drops: Some(Arc::clone(&attempt_drops)),
                datagram_client_address_listener: Some((Arc::from(PROXY_ID), listen_port)),
                ..Default::default()
            },
        )
        .await
        {
            Ok(bound) => {
                drops = attempt_drops;
                server = Some(bound);
                break;
            }
            Err(error) => {
                eprintln!(
                    "gated DTLS bind attempt {attempt}/{MAX_GATEWAY_ATTEMPTS} on \
                     {listen_port} failed: {error}"
                );
            }
        }
    }
    let server = Arc::new(server.expect("bind gated DTLS server"));
    let server_addr = server.local_addr();
    let server_runner = Arc::clone(&server);
    let server_task = tokio::spawn(async move {
        let _ = server_runner.run().await;
    });

    let forwarded_client: SocketAddr = "203.0.113.9:41234".parse().expect("client addr");

    // Pre-association refusal: a handshake-shaped datagram is exactly what the
    // demuxer would otherwise spawn a session for, so each of these proves the
    // envelope decision happens before any per-peer state exists. They come
    // from a trusted loopback peer, so only the envelope can refuse them.
    let hostile = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind hostile sender");
    let foreign_key =
        HmacSha256Key::new_from_slice(b"ffffffffffffffffffffffffffffffff").expect("foreign key");
    let client_hello_shaped = {
        let mut packet = vec![0x16u8, 0xfe, 0xfd];
        packet.extend_from_slice(&[0u8; 42]);
        packet
    };
    let pre_association_refusals: Vec<Vec<u8>> = vec![
        client_hello_shaped.clone(),
        encode_datagram_with_metadata(forwarded_client, server_addr, &client_hello_shaped, None),
        encode_datagram_with_metadata(
            forwarded_client,
            server_addr,
            &client_hello_shaped,
            Some(&foreign_key),
        ),
        encode_datagram_with_metadata(
            forwarded_client,
            SocketAddr::new(server_addr.ip(), server_addr.port().wrapping_add(1).max(1)),
            &client_hello_shaped,
            Some(&key()),
        ),
    ];
    for datagram in &pre_association_refusals {
        hostile
            .send_to(datagram, server_addr)
            .await
            .expect("send refused datagram");
    }
    // Bounded wait for the demuxer to have consumed all three, so the
    // accounting assertions below observe a settled state rather than racing
    // the recv loop under CI load.
    let expected_drops = pre_association_refusals.len() as u64;
    let deadline = std::time::Instant::now() + RECV_TIMEOUT;
    while drops.load(Ordering::Relaxed) < expected_drops && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // Nothing may come back, and nothing may be allocated for the sender.
    assert!(
        recv_within(&hostile, DROP_OBSERVATION_WINDOW)
            .await
            .is_none(),
        "a refused datagram must not be answered"
    );
    assert_eq!(
        server.active_session_count(),
        0,
        "a refused datagram must not allocate a DTLS association"
    );
    assert_eq!(
        drops.load(Ordering::Relaxed),
        expected_drops,
        "every pre-association refusal must be counted"
    );

    let (relay_addr, relay_task) = spawn_dtls_metadata_relay(server_addr, forwarded_client).await;
    let client_socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind DTLS client");
    client_socket
        .connect(relay_addr)
        .await
        .expect("connect DTLS client to relay");
    let client_params = BackendDtlsParams {
        config: Arc::new(
            dimpl::Config::builder()
                .build()
                .expect("DTLS client config"),
        ),
        certificate: dimpl::certificate::generate_self_signed_certificate()
            .expect("DTLS client certificate")
            .into(),
        server_name: None,
        server_cert_verifier: None,
        connect_timeout_ms: 15_000,
    };
    let client = tokio::time::timeout(
        Duration::from_secs(20),
        DtlsConnection::connect(client_socket, client_params),
    )
    .await
    .expect("authenticated DTLS handshake timed out")
    .expect("authenticated DTLS handshake failed");

    let (server_conn, direct_peer) = tokio::time::timeout(RECV_TIMEOUT, server.accept())
        .await
        .expect("DTLS accept timed out")
        .expect("DTLS accept failed");
    assert_eq!(
        direct_peer, relay_addr,
        "the socket peer must remain the relay"
    );
    assert_eq!(
        server_conn.forwarded_client_addr,
        Some(forwarded_client),
        "the authenticated envelope must bind the forwarded client to the DTLS association"
    );
    assert_eq!(
        drops.load(Ordering::Relaxed),
        expected_drops + 1,
        "the deliberately bare first ClientHello must be refused before association allocation"
    );

    client
        .send(b"dtls-through-envelope")
        .await
        .expect("DTLS send");
    assert_eq!(
        tokio::time::timeout(RECV_TIMEOUT, server_conn.recv())
            .await
            .expect("server receive timed out")
            .expect("server receive failed"),
        b"dtls-through-envelope",
        "the demuxer must strip every envelope before DTLS decryption"
    );
    server_conn.send(b"dtls-reply").await.expect("DTLS reply");
    assert_eq!(
        tokio::time::timeout(RECV_TIMEOUT, client.recv())
            .await
            .expect("client receive timed out")
            .expect("client receive failed"),
        b"dtls-reply",
        "server ciphertext must traverse the relay unchanged"
    );

    client.close().await;
    server.close().await;
    relay_task.abort();
    let _ = tokio::time::timeout(RECV_TIMEOUT, server_task).await;
}

#[tokio::test]
async fn authenticated_envelope_publishes_the_forwarded_client_and_strips_the_payload() {
    let backend = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("backend bind"));
    let backend_port = backend.local_addr().expect("backend addr").port();
    let _backend = spawn_udp_echo_backend(Arc::clone(&backend)).await;

    let gateway = spawn_gateway(backend_port, true).await;
    let gateway_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), gateway.listen_port);

    // The balancer's own socket peer; the client it speaks for is elsewhere.
    let balancer = UdpSocket::bind("127.0.0.1:0").await.expect("balancer bind");
    let balancer_ip = balancer
        .local_addr()
        .expect("balancer addr")
        .ip()
        .to_canonical()
        .to_string();
    let original_client: SocketAddr = "203.0.113.9:41234".parse().expect("client addr");

    let datagram = encode_datagram_with_metadata(original_client, gateway_addr, b"q", Some(&key()));
    balancer
        .send_to(&datagram, gateway_addr)
        .await
        .expect("send wrapped datagram");

    // The backend echoes the payload, so a reply proves the envelope was
    // stripped before the backend send (the backend echoes whatever it got).
    let reply = recv_within(&balancer, RECV_TIMEOUT)
        .await
        .expect("an authenticated datagram must round-trip");
    assert_eq!(
        reply, b"q",
        "the backend must see the payload with the envelope stripped"
    );

    let stream = gateway.recorder.stream.lock().await.clone();
    assert_eq!(stream.len(), 1, "exactly one session must be admitted");
    assert_eq!(
        stream[0].0, "203.0.113.9",
        "client_ip must be the authenticated forwarded client"
    );
    assert_eq!(
        stream[0].1, balancer_ip,
        "direct_client_ip must remain the balancer's socket peer"
    );

    let datagrams = gateway.recorder.datagram.lock().await.clone();
    assert_eq!(
        datagrams,
        vec!["203.0.113.9".to_string()],
        "per-datagram hooks must see the forwarded client too"
    );

    gateway.shutdown().await;
}

#[tokio::test]
async fn unauthenticated_and_malformed_datagrams_are_dropped_before_the_backend() {
    let backend = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("backend bind"));
    let backend_port = backend.local_addr().expect("backend addr").port();
    let _backend = spawn_udp_echo_backend(Arc::clone(&backend)).await;

    let gateway = spawn_gateway(backend_port, true).await;
    let gateway_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), gateway.listen_port);
    let sender = UdpSocket::bind("127.0.0.1:0").await.expect("sender bind");
    let original_client: SocketAddr = "203.0.113.9:41234".parse().expect("client addr");
    let foreign = HmacSha256Key::new_from_slice(b"ffffffffffffffffffffffffffffffff").expect("key");

    let refused: Vec<(&str, Vec<u8>)> = vec![
        // A bare payload on an enabled listener: no silent pass-through.
        ("bare payload", b"query".to_vec()),
        // Correct envelope, no authentication tag.
        (
            "untagged envelope",
            encode_datagram_with_metadata(original_client, gateway_addr, b"query", None),
        ),
        // Tag minted under a different secret.
        (
            "foreign tag",
            encode_datagram_with_metadata(original_client, gateway_addr, b"query", Some(&foreign)),
        ),
        (
            "wrong listener dest port",
            encode_datagram_with_metadata(
                original_client,
                SocketAddr::new(
                    gateway_addr.ip(),
                    gateway_addr.port().wrapping_add(1).max(1),
                ),
                b"query",
                Some(&key()),
            ),
        ),
        // Truncated header.
        ("truncated header", b"\r\n\r\n\x00\r\nQUI".to_vec()),
    ];

    for (label, datagram) in &refused {
        sender
            .send_to(datagram, gateway_addr)
            .await
            .expect("send refused datagram");
        assert!(
            recv_within(&sender, DROP_OBSERVATION_WINDOW)
                .await
                .is_none(),
            "{label} must be dropped, not forwarded"
        );
    }

    assert_eq!(
        gateway.recorder.datagram_count.load(Ordering::Relaxed),
        0,
        "no refused datagram may reach the per-datagram hooks"
    );
    assert!(
        gateway.recorder.stream.lock().await.is_empty(),
        "no refused datagram may admit a session"
    );
    assert_eq!(
        gateway.metrics.active_sessions.load(Ordering::Relaxed),
        0,
        "no refused datagram may create a session"
    );
    assert_eq!(
        gateway
            .metrics
            .client_address_metadata_drops
            .load(Ordering::Relaxed),
        refused.len() as u64,
        "every refusal must be counted"
    );

    // The listener is still healthy: a correctly authenticated datagram after
    // the refusals still round-trips.
    let good = encode_datagram_with_metadata(original_client, gateway_addr, b"ok", Some(&key()));
    sender
        .send_to(&good, gateway_addr)
        .await
        .expect("send authenticated datagram");
    assert_eq!(
        recv_within(&sender, RECV_TIMEOUT).await.as_deref(),
        Some(&b"ok"[..]),
        "refusals must not wedge the listener"
    );

    gateway.shutdown().await;
}

#[tokio::test]
async fn authenticated_envelope_for_a_different_listener_port_is_dropped_before_session() {
    let backend = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("backend bind"));
    let backend_port = backend.local_addr().expect("backend addr").port();
    let _backend = spawn_udp_echo_backend(Arc::clone(&backend)).await;

    let gateway = spawn_gateway(backend_port, true).await;
    let gateway_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), gateway.listen_port);
    let sender = UdpSocket::bind("127.0.0.1:0").await.expect("sender bind");
    let original_client: SocketAddr = "203.0.113.9:41234".parse().expect("client addr");
    let wrong_dest = SocketAddr::new(
        gateway_addr.ip(),
        gateway_addr.port().wrapping_add(1).max(1),
    );

    sender
        .send_to(
            &encode_datagram_with_metadata(
                original_client,
                wrong_dest,
                b"other-listener",
                Some(&key()),
            ),
            gateway_addr,
        )
        .await
        .expect("send portable envelope");

    assert!(
        recv_within(&sender, DROP_OBSERVATION_WINDOW)
            .await
            .is_none(),
        "a valid envelope for another listener port must be dropped"
    );
    assert!(
        gateway.recorder.stream.lock().await.is_empty(),
        "wrong dest port must not admit a session"
    );
    assert_eq!(
        gateway.metrics.active_sessions.load(Ordering::Relaxed),
        0,
        "wrong dest port must not allocate a session"
    );
    assert_eq!(
        gateway.recorder.datagram_count.load(Ordering::Relaxed),
        0,
        "wrong dest port must not reach plugin hooks"
    );
    assert_eq!(
        gateway
            .metrics
            .client_address_metadata_drops
            .load(Ordering::Relaxed),
        1,
        "wrong dest port must be counted before any allocation"
    );

    let good = encode_datagram_with_metadata(original_client, gateway_addr, b"ok", Some(&key()));
    sender
        .send_to(&good, gateway_addr)
        .await
        .expect("send matching dest-port envelope");
    assert_eq!(
        recv_within(&sender, RECV_TIMEOUT).await.as_deref(),
        Some(&b"ok"[..]),
        "matching dest port must still be admitted"
    );

    gateway.shutdown().await;
}

#[tokio::test]
async fn a_second_forwarded_client_on_one_socket_peer_is_refused() {
    let backend = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("backend bind"));
    let backend_port = backend.local_addr().expect("backend addr").port();
    let _backend = spawn_udp_echo_backend(Arc::clone(&backend)).await;

    // Address-trust posture (no secret): the session-binding rule is
    // independent of authentication.
    let gateway = spawn_gateway(backend_port, false).await;
    let gateway_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), gateway.listen_port);
    let balancer = UdpSocket::bind("127.0.0.1:0").await.expect("balancer bind");

    let first: SocketAddr = "203.0.113.9:41234".parse().expect("client addr");
    let second: SocketAddr = "198.51.100.7:41234".parse().expect("client addr");

    balancer
        .send_to(
            &encode_datagram_with_metadata(first, gateway_addr, b"first", None),
            gateway_addr,
        )
        .await
        .expect("send first client");
    assert_eq!(
        recv_within(&balancer, RECV_TIMEOUT).await.as_deref(),
        Some(&b"first"[..]),
        "the first client establishes the session"
    );

    balancer
        .send_to(
            &encode_datagram_with_metadata(second, gateway_addr, b"second", None),
            gateway_addr,
        )
        .await
        .expect("send second client");
    assert!(
        recv_within(&balancer, DROP_OBSERVATION_WINDOW)
            .await
            .is_none(),
        "a different forwarded client on the same socket peer must be dropped, not \
         attributed to the established session"
    );

    let datagrams = gateway.recorder.datagram.lock().await.clone();
    assert_eq!(
        datagrams,
        vec!["203.0.113.9".to_string()],
        "only the admitted client's datagram may reach the hooks"
    );
    assert_eq!(
        gateway
            .metrics
            .client_address_metadata_drops
            .load(Ordering::Relaxed),
        1,
        "the mismatch must be counted as a client-address metadata drop"
    );

    gateway.shutdown().await;
}

#[tokio::test]
async fn an_untrusted_peer_cannot_assert_a_client_address() {
    let backend = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("backend bind"));
    let backend_port = backend.local_addr().expect("backend addr").port();
    let _backend = spawn_udp_echo_backend(Arc::clone(&backend)).await;

    let gateway = spawn_gateway(backend_port, false).await;
    let gateway_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), gateway.listen_port);

    // 127.0.0.2 is outside the configured trust list (`127.0.0.1`), so this
    // sender is an ordinary client forging balancer metadata.
    let Ok(untrusted) = UdpSocket::bind("127.0.0.2:0").await else {
        // Some CI images do not route the whole 127/8 range; the unit-level
        // trust test covers this case unconditionally.
        eprintln!("skipping: 127.0.0.2 is not bindable on this host");
        gateway.shutdown().await;
        return;
    };

    let spoofed = encode_datagram_with_metadata(
        "203.0.113.9:41234".parse().expect("client addr"),
        gateway_addr,
        b"spoofed",
        None,
    );
    untrusted
        .send_to(&spoofed, gateway_addr)
        .await
        .expect("send spoofed datagram");

    assert!(
        recv_within(&untrusted, DROP_OBSERVATION_WINDOW)
            .await
            .is_none(),
        "an untrusted peer's datagram must be dropped"
    );
    assert!(
        gateway.recorder.stream.lock().await.is_empty(),
        "an untrusted peer must not admit a session"
    );
    assert_eq!(
        gateway
            .metrics
            .client_address_metadata_drops
            .load(Ordering::Relaxed),
        1,
        "the untrusted peer must be counted"
    );

    gateway.shutdown().await;
}
