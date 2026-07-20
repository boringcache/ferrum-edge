//! Request-path coverage for outbound-capture HTTP route misses under
//! effective REGISTRY_ONLY (`MeshOutboundEnforcement::http_route_miss_reject_status`
//! consulted from the H1/H2 proxy route-miss arm).
//!
//! These tests drive [`ferrum_edge::proxy::handle_proxy_request`] so the
//! production pre-plugin reject path runs — not just the helper in isolation.
//! Coverage:
//!   - unknown host on outbound capture → configured non-default reject status
//!   - fixed-cardinality deny metric (`host="<denied>",decision="deny"`)
//!   - empty registry fails closed on the same path
//!   - native gRPC wire normalization (HTTP 200 + grpc-status mapping)
//!   - inbound / non-capture listen ports keep the generic 404

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use chrono::Utc;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request};
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde_json::json;
use tokio::net::TcpListener;

use ferrum_edge::config::types::{GatewayConfig, Proxy};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::modes::mesh::outbound_enforcement::MeshOutboundEnforcement;
use ferrum_edge::plugins::mesh::outbound_registry::OutboundRegistry;
use ferrum_edge::proxy::ProxyState;

const OUTBOUND_CAPTURE_PORT: u16 = 15001;
const INBOUND_MTLS_PORT: u16 = 15006;
const REJECT_STATUS: u16 = 403;
const UNKNOWN_HOST: &str = "not-in-slice.example";
const ADMITTED_HOST: &str = "reviews.svc";

// Distinct namespaces avoid racing parallel tests on the process-wide
// Prometheus registry when asserting deny-counter deltas.
const NS_HTTP_DENY: &str = "route-miss-http-deny";
const NS_EMPTY_REGISTRY: &str = "route-miss-empty-registry";
const NS_GRPC_DENY: &str = "route-miss-grpc-deny";
const NS_INBOUND_SKIP: &str = "route-miss-inbound-skip";

fn make_env(frontend_http_port: u16) -> ferrum_edge::config::EnvConfig {
    ferrum_edge::config::EnvConfig {
        mode: ferrum_edge::config::env_config::OperatingMode::File,
        log_level: "error".into(),
        proxy_http_port: frontend_http_port,
        proxy_https_port: 0,
        admin_http_port: 0,
        admin_https_port: 0,
        file_config_path: Some("/tmp/test-route-miss-config.json".into()),
        max_connections: 0,
        pool_warmup_enabled: false,
        shutdown_drain_seconds: 0,
        ..Default::default()
    }
}

fn make_proxy_state(
    frontend_http_port: u16,
    namespace: &str,
    registry_entries: &[&str],
    capture_ports: Vec<u16>,
    reject_status: u16,
) -> ProxyState {
    let dns_cache = DnsCache::new(DnsConfig::default());
    // Empty proxy table: every Host is a route miss so the REGISTRY_ONLY
    // pre-plugin gate is the only decision on the path.
    let config = GatewayConfig {
        version: "1".to_string(),
        proxies: Vec::<Proxy>::new(),
        consumers: vec![],
        plugin_configs: vec![],
        upstreams: vec![],
        loaded_at: Utc::now(),
        known_namespaces: Vec::new(),
        ..Default::default()
    };
    let (state, _handles) =
        ProxyState::new(config, dns_cache, make_env(frontend_http_port), None, None)
            .expect("ProxyState for route-miss coverage");

    let registry =
        OutboundRegistry::new(&json!({ "registry": registry_entries })).expect("valid registry");
    let enforcement = MeshOutboundEnforcement::from_registry_with_reject_status(
        namespace.to_string(),
        capture_ports,
        registry,
        reject_status,
    );
    // Replace the empty slot installed by ProxyState::new with the fixture.
    state
        .mesh_outbound_enforcement
        .store(Arc::new(Some(Arc::new(enforcement))));
    state
}

async fn start_test_gateway(state: ProxyState) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind route-miss test gateway");
    let gateway_addr = listener.local_addr().expect("gateway addr");

    let handle = tokio::spawn(async move {
        loop {
            let (stream, remote_addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => break,
            };
            let state = state.clone();
            tokio::spawn(async move {
                let _ = stream.set_nodelay(true);
                let io = TokioIo::new(stream);
                let mut builder =
                    hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
                builder.http1().max_buf_size(state.max_header_size_bytes);
                builder
                    .http2()
                    .max_header_list_size(state.max_header_size_bytes as u32);

                let svc = service_fn(move |req: Request<Incoming>| {
                    let state = state.clone();
                    let addr = remote_addr;
                    async move {
                        ferrum_edge::proxy::handle_proxy_request(
                            req, state, addr, false, None, None,
                        )
                        .await
                    }
                });
                let _ = builder.serve_connection_with_upgrades(io, svc).await;
            });
        }
    });

    tokio::time::sleep(Duration::from_millis(20)).await;
    (gateway_addr, handle)
}

#[derive(Clone, Copy, Debug)]
enum TestHttpVersion {
    H1,
    H2,
}

async fn send_request(
    gateway_addr: SocketAddr,
    version: TestHttpVersion,
    method: Method,
    path: &str,
    host: &str,
    content_type: Option<&str>,
) -> Result<(u16, HashMap<String, String>, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
    let stream = tokio::net::TcpStream::connect(gateway_addr).await?;
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);

    // H1 needs an explicit Host header; H2 prefers :authority via absolute-form
    // URI so the route-miss gate sees the same destination host on both paths.
    let uri = match version {
        TestHttpVersion::H1 => path.to_string(),
        TestHttpVersion::H2 => format!("http://{host}{path}"),
    };
    let mut builder = Request::builder().method(method).uri(uri);
    if matches!(version, TestHttpVersion::H1) {
        builder = builder.header("host", host);
    }
    if let Some(ct) = content_type {
        builder = builder.header("content-type", ct);
        if ct.starts_with("application/grpc") {
            builder = builder.header("te", "trailers");
        }
    }
    let request = builder.body(Full::new(Bytes::new()))?;

    let response = match version {
        TestHttpVersion::H1 => {
            let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            sender.send_request(request).await?
        }
        TestHttpVersion::H2 => {
            let (mut sender, conn) =
                hyper::client::conn::http2::handshake(TokioExecutor::new(), io).await?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            sender.send_request(request).await?
        }
    };

    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_string(), value.to_string()))
        })
        .collect();
    let body = response
        .into_body()
        .collect()
        .await
        .map(|collected| collected.to_bytes().to_vec())
        .unwrap_or_default();
    Ok((status, headers, body))
}

fn http_deny_count(mesh_namespace: &str) -> u64 {
    let rendered = ferrum_edge::plugins::prometheus_metrics::global_registry().render_uncached();
    let needle = format!(
        "ferrum_mesh_outbound_registry_decisions_total{{mesh_namespace=\"{mesh_namespace}\",host=\"<denied>\",decision=\"deny\""
    );
    for line in rendered.lines() {
        if let Some(rest) = line.strip_prefix(needle.as_str())
            && let Some(value_str) = rest.split_whitespace().last()
            && let Ok(value) = value_str.parse::<u64>()
        {
            return value;
        }
    }
    0
}

#[tokio::test(flavor = "multi_thread")]
async fn outbound_capture_route_miss_returns_configured_reject_and_deny_metric() {
    let state = make_proxy_state(
        OUTBOUND_CAPTURE_PORT,
        NS_HTTP_DENY,
        &[ADMITTED_HOST],
        vec![OUTBOUND_CAPTURE_PORT],
        REJECT_STATUS,
    );
    let before = http_deny_count(NS_HTTP_DENY);
    let (gateway_addr, _handle) = start_test_gateway(state).await;

    for version in [TestHttpVersion::H1, TestHttpVersion::H2] {
        let (status, headers, body) = send_request(
            gateway_addr,
            version,
            Method::GET,
            "/",
            UNKNOWN_HOST,
            None,
        )
        .await
        .unwrap_or_else(|error| panic!("{version:?} unknown-host route miss failed: {error}"));

        assert_eq!(
            status, REJECT_STATUS,
            "{version:?} must return configured REGISTRY_ONLY reject status"
        );
        assert_eq!(
            headers.get("content-type").map(String::as_str),
            Some("application/json"),
            "{version:?} content-type"
        );
        let body_text = String::from_utf8_lossy(&body);
        assert!(
            body_text.contains("destination not in mesh registry"),
            "{version:?} body must identify REGISTRY_ONLY denial, got {body_text}"
        );
    }

    // Admitted destinations keep the generic route-miss path (no configured
    // reject status) even on the outbound capture listener.
    let (status, _, body) = send_request(
        gateway_addr,
        TestHttpVersion::H1,
        Method::GET,
        "/",
        ADMITTED_HOST,
        None,
    )
    .await
    .expect("admitted-host route miss");
    assert_eq!(status, 404, "admitted host without a route stays generic 404");
    assert_eq!(
        String::from_utf8_lossy(&body),
        r#"{"error":"Not Found"}"#,
        "admitted route miss must not use the registry denial body"
    );

    let after = http_deny_count(NS_HTTP_DENY);
    assert!(
        after >= before + 2,
        "unknown-host H1+H2 denials must increment host=<denied> deny counter \
         (before={before}, after={after})"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn empty_registry_route_miss_fails_closed_with_configured_status() {
    let state = make_proxy_state(
        OUTBOUND_CAPTURE_PORT,
        NS_EMPTY_REGISTRY,
        &[],
        vec![OUTBOUND_CAPTURE_PORT],
        REJECT_STATUS,
    );
    let before = http_deny_count(NS_EMPTY_REGISTRY);
    let (gateway_addr, _handle) = start_test_gateway(state).await;

    let (status, _, body) = send_request(
        gateway_addr,
        TestHttpVersion::H1,
        Method::GET,
        "/",
        ADMITTED_HOST,
        None,
    )
    .await
    .expect("empty-registry route miss");

    assert_eq!(status, REJECT_STATUS, "empty registry must fail closed");
    assert!(
        String::from_utf8_lossy(&body).contains("destination not in mesh registry"),
        "empty registry must use the REGISTRY_ONLY denial body"
    );
    let after = http_deny_count(NS_EMPTY_REGISTRY);
    assert!(
        after >= before + 1,
        "empty-registry deny must increment host=<denied> (before={before}, after={after})"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn outbound_capture_grpc_route_miss_normalizes_wire_contract() {
    // 403 → gRPC PERMISSION_DENIED (7) via build_pre_plugin_reject_response.
    let state = make_proxy_state(
        OUTBOUND_CAPTURE_PORT,
        NS_GRPC_DENY,
        &[ADMITTED_HOST],
        vec![OUTBOUND_CAPTURE_PORT],
        REJECT_STATUS,
    );
    let before = http_deny_count(NS_GRPC_DENY);
    let (gateway_addr, _handle) = start_test_gateway(state).await;

    let (status, headers, body) = send_request(
        gateway_addr,
        TestHttpVersion::H2,
        Method::POST,
        "/pkg.Service/Call",
        UNKNOWN_HOST,
        Some("application/grpc"),
    )
    .await
    .expect("native gRPC outbound route-miss request");

    assert_eq!(status, 200, "native gRPC reject must use HTTP 200");
    assert_eq!(
        headers.get("content-type").map(String::as_str),
        Some("application/grpc")
    );
    assert_eq!(
        headers.get("grpc-status").map(String::as_str),
        Some("7"),
        "configured HTTP 403 must map to gRPC PERMISSION_DENIED"
    );
    assert!(
        headers
            .get("grpc-message")
            .is_some_and(|msg| msg.contains("destination not in mesh registry")),
        "grpc-message must carry the REGISTRY_ONLY denial text, got {:?}",
        headers.get("grpc-message")
    );
    assert!(
        body.is_empty(),
        "native gRPC reject must remain trailers-only"
    );

    let after = http_deny_count(NS_GRPC_DENY);
    assert!(
        after >= before + 1,
        "gRPC route-miss deny must increment host=<denied> (before={before}, after={after})"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn inbound_non_capture_route_miss_keeps_generic_not_found() {
    // Frontend listen port is inbound mTLS (15006); enforcement only scopes
    // outbound capture (15001). The REGISTRY_ONLY gate must Skip.
    let state = make_proxy_state(
        INBOUND_MTLS_PORT,
        NS_INBOUND_SKIP,
        &[ADMITTED_HOST],
        vec![OUTBOUND_CAPTURE_PORT],
        REJECT_STATUS,
    );
    let before = http_deny_count(NS_INBOUND_SKIP);
    let (gateway_addr, _handle) = start_test_gateway(state).await;

    let (status, _, body) = send_request(
        gateway_addr,
        TestHttpVersion::H1,
        Method::GET,
        "/",
        UNKNOWN_HOST,
        None,
    )
    .await
    .expect("inbound route miss");

    assert_eq!(status, 404, "inbound route miss must stay generic Not Found");
    assert_eq!(
        String::from_utf8_lossy(&body),
        r#"{"error":"Not Found"}"#,
        "inbound miss must not use the REGISTRY_ONLY denial body"
    );
    assert_eq!(
        http_deny_count(NS_INBOUND_SKIP),
        before,
        "inbound / non-capture route miss must not increment the deny metric"
    );
}
