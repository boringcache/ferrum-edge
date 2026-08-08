//! Live traffic coverage for port-aware HTTP route identity (issue #3612).
//!
//! Spawns two in-process proxy listeners that share one RouterCache, with two
//! proxies that claim the same host+path on distinct `listen_port` values.
//! Each frontend must reach only its intended backend.

use std::time::Duration;

use bytes::Bytes;
use chrono::Utc;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use ferrum_edge::config::types::{AuthMode, BackendScheme, DispatchKind, GatewayConfig, Proxy};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::proxy::{ProxyState, start_proxy_listener_with_bound_listener};

fn create_test_proxy(id: &str, listen_path: &str, backend_port: u16, listen_port: u16) -> Proxy {
    Proxy {
        id: id.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: Some(format!("Port Aware {id}")),
        hosts: vec!["app.example.com".to_string()],
        listen_path: Some(listen_path.to_string()),
        backend_scheme: Some(BackendScheme::Http),
        dispatch_kind: DispatchKind::from(BackendScheme::Http),
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
        api_spec_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: Default::default(),
        listen_port: Some(listen_port),
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
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn create_test_env_config() -> ferrum_edge::config::EnvConfig {
    ferrum_edge::config::EnvConfig {
        mode: ferrum_edge::config::env_config::OperatingMode::File,
        log_level: "error".into(),
        proxy_http_port: 0,
        proxy_https_port: 0,
        admin_http_port: 0,
        admin_https_port: 0,
        shutdown_drain_seconds: 1,
        max_connections: 0,
        ..ferrum_edge::config::EnvConfig::default()
    }
}

fn create_test_proxy_state(proxies: Vec<Proxy>) -> ProxyState {
    let dns_cache = DnsCache::new(DnsConfig::default());
    let config = GatewayConfig {
        version: "1".to_string(),
        proxies,
        consumers: vec![],
        plugin_configs: vec![],
        upstreams: vec![],
        loaded_at: Utc::now(),
        known_namespaces: Vec::new(),
        frontend_tls_cert_path: None,
        frontend_tls_key_path: None,
        frontend_tls_source_namespace: None,
        frontend_tls_namespace_sources: Vec::new(),
        trust_bundles: None,
        mesh: None,
        http_tls_listen_ports: Default::default(),
        mesh_revision: None,
        k8s_mesh_overlay: Default::default(),
    };
    ProxyState::new(config, dns_cache, create_test_env_config(), None, None)
        .unwrap()
        .0
}

async fn start_body_backend(body: &'static [u8]) -> (u16, tokio::task::JoinHandle<()>) {
    use hyper::server::conn::http1;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(c) => c,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let _ = stream.set_nodelay(true);
                let io = TokioIo::new(stream);
                let svc = service_fn(move |_req: Request<Incoming>| async move {
                    Ok::<_, hyper::Error>(
                        Response::builder()
                            .status(200)
                            .header("content-type", "text/plain")
                            .body(Full::new(Bytes::from_static(body)))
                            .unwrap(),
                    )
                });
                let _ = http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    (port, handle)
}

async fn http_get(addr: std::net::SocketAddr, host: &str, path: &str) -> (u16, String) {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf);
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = text
        .split("\r\n\r\n")
        .nth(1)
        .unwrap_or("")
        .trim()
        .to_string();
    (status, body)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn same_host_path_on_distinct_listen_ports_routes_independently() {
    let (backend_a, _a) = start_body_backend(b"from-a").await;
    let (backend_b, _b) = start_body_backend(b"from-b").await;

    let listener_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listener_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr_a = listener_a.local_addr().unwrap();
    let addr_b = listener_b.local_addr().unwrap();

    let proxy_a = create_test_proxy("a", "/api", backend_a, addr_a.port());
    let proxy_b = create_test_proxy("b", "/api", backend_b, addr_b.port());
    let state = create_test_proxy_state(vec![proxy_a, proxy_b]);

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let state_a = state.clone();
    let state_b = state;
    let shutdown_a = shutdown_rx.clone();
    let shutdown_b = shutdown_rx;
    let handle_a = tokio::spawn(async move {
        let _ = start_proxy_listener_with_bound_listener(listener_a, state_a, shutdown_a, None)
            .await;
    });
    let handle_b = tokio::spawn(async move {
        let _ = start_proxy_listener_with_bound_listener(listener_b, state_b, shutdown_b, None)
            .await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let (status_a, body_a) = http_get(addr_a, "app.example.com", "/api/x").await;
    let (status_b, body_b) = http_get(addr_b, "app.example.com", "/api/x").await;
    assert_eq!(status_a, 200, "listener A must route: {body_a}");
    assert_eq!(status_b, 200, "listener B must route: {body_b}");
    assert_eq!(body_a, "from-a");
    assert_eq!(body_b, "from-b");

    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(2), handle_a).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), handle_b).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn overlapping_same_port_siblings_still_fail_closed_at_validation() {
    let mut a = create_test_proxy("a", "/api", 8080, 9001);
    let mut b = create_test_proxy("b", "/api", 8081, 9001);
    a.hosts = vec!["app.example.com".into()];
    b.hosts = vec!["app.example.com".into()];
    let config = GatewayConfig {
        proxies: vec![a, b],
        ..GatewayConfig::default()
    };
    let err = config.validate_unique_listen_paths().unwrap_err();
    assert!(
        err.iter().any(|e| e.contains("Overlapping")),
        "same effective listener must still fail closed: {err:?}"
    );
}
