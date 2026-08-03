//! Live traffic-path acceptance for selected-subset DestinationRule HTTP policy.
//!
//! Covers the three child mechanisms on a real in-process Ferrum gateway:
//! selected-subset `h2UpgradePolicy` (ALPN/protocol observable at the backend),
//! `maxRetries` attempt capping, and subset-isolated `http1MaxPendingRequests`
//! admission/permit release — including sibling/unmatched non-leakage.
//!
//! Run: `cargo build --bin ferrum-edge && cargo test --test functional_tests \
//!   functional_subset_http_policy -- --ignored --nocapture`

use crate::scaffolding::{
    H2Step, MatchHeaders, ScriptedH2Backend, ScriptedTlsBackend, TcpStep, TestCa, TlsConfig,
    reserve_port,
};

use ferrum_edge::admin::jwt_auth::{JwtConfig, JwtManager};
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::config::{EnvConfig, OperatingMode};
use ferrum_edge::modes::file::ServeOptions;
use ferrum_edge::modes::mesh::{
    MeshConfigProtocol, MeshRuntimeConfig, MeshTopology, prepare_gateway_config_for_mesh,
};
use http::StatusCode;
use serde_json::json;
use std::collections::HashMap;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, watch};
use tokio::task::JoinHandle;
use tokio::time::sleep;

const NS: &str = "ferrum";
const UPSTREAM_ID: &str = "subset-http-upstream";
const JWT_SECRET: &str = "ferrum-edge-subset-http-policy-secret-0000";
const JWT_ISSUER: &str = "ferrum-edge-subset-http-policy";

#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn functional_subset_http_h2_upgrade_policy_is_observable_at_backend() {
    let ca = TestCa::new("subset-http-h2").expect("ca");
    let (cert, key) = ca.valid().expect("leaf");

    let h1_res = reserve_port().await.expect("h1 backend port");
    let h2_res = reserve_port().await.expect("h2 backend port");
    let h1_port = h1_res.port;
    let h2_port = h2_res.port;

    // v1 DoNotUpgrade must land on this H1-speaking TLS fixture with http/1.1 ALPN.
    let h1_backend = ScriptedTlsBackend::builder(
        h1_res.into_listener(),
        TlsConfig::new(cert.clone(), key.clone())
            .with_alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
    )
    .step(TcpStep::ReadUntil(b"\r\n\r\n".to_vec()))
    .step(TcpStep::Write(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec(),
    ))
    .step(TcpStep::Drop)
    .spawn()
    .expect("spawn h1 tls backend");

    // v2 Upgrade must take direct-H2 against this H2-only TLS fixture.
    let h2_backend = ScriptedH2Backend::builder_tls(h2_res.into_listener(), &cert, &key)
        .expect("h2 tls builder")
        .repeat_script()
        .step(H2Step::ExpectHeaders(MatchHeaders::any()))
        .step(H2Step::RespondHeaders(vec![
            (":status", "200".into()),
            ("content-type", "text/plain".into()),
        ]))
        .step(H2Step::RespondData {
            data: bytes::Bytes::from_static(b"ok"),
            end_stream: true,
        })
        .spawn()
        .expect("spawn h2 tls backend");

    let gateway = start_subset_gateway(subset_https_dual_backend_config(h1_port, h2_port))
        .await
        .expect("start subset h2 gateway");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("http client");

    let v1 = client
        .get(format!("http://127.0.0.1:{}/v1/probe", gateway.http_port))
        .send()
        .await
        .expect("v1 request");
    assert_eq!(v1.status(), StatusCode::OK, "v1 DoNotUpgrade must succeed");
    wait_for(
        || async { h1_backend.handshakes_completed() >= 1 },
        Duration::from_secs(5),
    )
    .await;
    let v1_alpn = h1_backend.last_alpn().await;
    assert_eq!(
        v1_alpn.as_deref(),
        Some(b"http/1.1".as_slice()),
        "selected subset v1 DoNotUpgrade must force HTTP/1.1 ALPN; got {v1_alpn:?}"
    );
    assert_eq!(
        h2_backend.accepted_connections(),
        0,
        "v1 traffic must not leak onto the H2-only sibling backend"
    );

    let v2 = client
        .get(format!("http://127.0.0.1:{}/v2/probe", gateway.http_port))
        .send()
        .await
        .expect("v2 request");
    assert_eq!(v2.status(), StatusCode::OK, "v2 Upgrade must succeed over H2");
    wait_for(
        || async { h2_backend.handshakes_completed() >= 1 },
        Duration::from_secs(5),
    )
    .await;
    assert!(
        !h2_backend.received_streams().await.is_empty(),
        "selected subset v2 Upgrade must deliver an HTTP/2 stream to the backend"
    );

    gateway.shutdown().await;
    drop(h1_backend);
    drop(h2_backend);
}

#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn functional_subset_http_max_retries_caps_live_attempts() {
    // v1 (cap 1): two 503s. unmatched (top-level cap 5): three 503s then 200.
    let (backend_port, hits, scripts_done, backend_task) = spawn_status_script_backend(&[
        StatusCode::SERVICE_UNAVAILABLE,
        StatusCode::SERVICE_UNAVAILABLE,
        StatusCode::SERVICE_UNAVAILABLE,
        StatusCode::SERVICE_UNAVAILABLE,
        StatusCode::SERVICE_UNAVAILABLE,
        StatusCode::OK,
    ])
    .await;

    let gateway = start_subset_gateway(subset_http_retry_config(backend_port))
        .await
        .expect("start subset retry gateway");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .expect("http client");

    let v1 = client
        .get(format!("http://127.0.0.1:{}/v1/retry", gateway.http_port))
        .send()
        .await
        .expect("v1 retry request");
    // Subset v1 caps maxRetries to 1 → exactly two attempts; both 503 under the
    // script so the client sees the final failure rather than recovering.
    assert_eq!(
        v1.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "v1 capped retries must exhaust after the subset cap"
    );
    wait_for(|| async { hits.load(Ordering::SeqCst) >= 2 }, Duration::from_secs(5)).await;
    assert_eq!(
        hits.load(Ordering::SeqCst),
        2,
        "selected subset maxRetries=1 must allow exactly 1 initial + 1 retry"
    );

    hits.store(0, Ordering::SeqCst);
    let unmatched = client
        .get(format!(
            "http://127.0.0.1:{}/unmatched/retry",
            gateway.http_port
        ))
        .send()
        .await
        .expect("unmatched retry request");
    assert_eq!(
        unmatched.status(),
        StatusCode::OK,
        "unmatched top-level maxRetries=5 must recover within the larger budget"
    );
    wait_for(|| async { hits.load(Ordering::SeqCst) >= 4 }, Duration::from_secs(5)).await;
    assert_eq!(
        hits.load(Ordering::SeqCst),
        4,
        "unmatched must not inherit the v1 subset cap of 1 (expects 3 failures + recovery)"
    );

    scripts_done.store(true, Ordering::SeqCst);
    gateway.shutdown().await;
    match tokio::time::timeout(Duration::from_secs(5), backend_task).await {
        Ok(Ok(())) => {}
        Ok(Err(join_err)) => panic!("status-script backend panicked: {join_err}"),
        Err(_) => panic!("status-script backend did not exit after shutdown"),
    }
}

#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn functional_subset_http1_pending_admission_is_subset_isolated() {
    let (backend_port, hits, release, backend_task) = spawn_holding_backend().await;
    let gateway = start_subset_gateway(subset_http_pending_config(backend_port))
        .await
        .expect("start subset pending gateway");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .pool_max_idle_per_host(0)
        .build()
        .expect("http client");

    let hold_url = format!("http://127.0.0.1:{}/v1/hold", gateway.http_port);
    let hold_client = client.clone();
    let hold = tokio::spawn(async move {
        hold_client
            .get(hold_url)
            .send()
            .await
            .expect("held v1 request")
    });
    wait_for(|| async { hits.load(Ordering::SeqCst) >= 1 }, Duration::from_secs(10)).await;

    let shed = client
        .get(format!("http://127.0.0.1:{}/v1/shed", gateway.http_port))
        .send()
        .await
        .expect("shed request");
    assert_eq!(
        shed.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "second v1 request must hit the subset http1MaxPendingRequests=1 cap"
    );
    let shed_body = shed.text().await.unwrap_or_default();
    assert!(
        shed_body.contains("pending request queue full") || shed_body.contains("upstream overflow"),
        "pending-cap response body should identify the shed: {shed_body}"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "shed request must not reach the backend"
    );

    let sibling = client
        .get(format!("http://127.0.0.1:{}/v2/ok", gateway.http_port))
        .send()
        .await
        .expect("sibling subset request");
    assert_eq!(
        sibling.status(),
        StatusCode::OK,
        "sibling subset v2 must not share the v1 pending lane"
    );
    wait_for(|| async { hits.load(Ordering::SeqCst) >= 2 }, Duration::from_secs(5)).await;

    release.release();
    let held = hold.await.expect("held task join");
    assert_eq!(held.status(), StatusCode::OK, "held v1 request must complete");

    let after = client
        .get(format!("http://127.0.0.1:{}/v1/after", gateway.http_port))
        .send()
        .await
        .expect("post-release v1 request");
    assert_eq!(
        after.status(),
        StatusCode::OK,
        "pending permit must release after the held request completes"
    );

    gateway.shutdown().await;
    backend_task.abort();
}

struct RunningGateway {
    http_port: u16,
    shutdown_tx: watch::Sender<bool>,
    join: JoinHandle<()>,
}

impl RunningGateway {
    async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        match tokio::time::timeout(Duration::from_secs(5), self.join).await {
            Ok(Ok(())) => {}
            Ok(Err(join_err)) => panic!("subset gateway task panicked: {join_err}"),
            Err(_) => panic!("subset gateway shutdown timed out"),
        }
    }
}

async fn start_subset_gateway(
    config: GatewayConfig,
) -> Result<RunningGateway, Box<dyn std::error::Error + Send + Sync>> {
    let http = reserve_port().await?;
    let admin = reserve_port().await?;
    let http_port = http.port;
    let admin_port = admin.port;

    let env_config = EnvConfig {
        mode: OperatingMode::File,
        log_level: "warn".to_string(),
        proxy_http_port: http_port,
        proxy_https_port: 0,
        admin_http_port: admin_port,
        admin_https_port: 0,
        admin_jwt_secret: Some(JWT_SECRET.to_string()),
        admin_jwt_issuer: JWT_ISSUER.to_string(),
        pool_warmup_enabled: false,
        shutdown_drain_seconds: 0,
        max_connections: 0,
        namespace: NS.to_string(),
        ..EnvConfig::default()
    };
    let prepared = prepare_gateway_config_for_mesh(config, &mesh_runtime_config()).map_err(
        |e| -> Box<dyn std::error::Error + Send + Sync> {
            format!("mesh preparation failed: {e}").into()
        },
    )?;
    assert!(
        prepared.proxies.iter().any(|proxy| {
            proxy.upstream_subset.as_deref() == Some("v1")
                && proxy
                    .dispatch_port_override_fallback
                    .as_ref()
                    .is_some_and(|fallback| {
                        fallback.http1_max_pending_requests == Some(1)
                            || fallback.max_retries == Some(1)
                            || fallback.h2_upgrade_policy.is_some()
                    })
        }),
        "selected subset HTTP policy was not projected onto the v1 proxy fallback"
    );

    let jwt_manager = JwtManager::new(JwtConfig {
        secret: JWT_SECRET.to_string(),
        issuer: JWT_ISSUER.to_string(),
        audience: None,
        max_ttl_seconds: 3600,
        algorithm: jsonwebtoken::Algorithm::HS256,
    });
    let opts = ServeOptions {
        proxy_http: Some(http.into_listener()),
        admin_http: Some(admin.into_listener()),
        admin_jwt_manager: Some(jwt_manager),
        skip_initial_capability_refresh: true,
        ..ServeOptions::default()
    };
    let (shutdown_tx, _) = watch::channel(false);
    let handles = ferrum_edge::modes::file::serve(env_config, prepared, opts, shutdown_tx.clone())
        .await
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
            format!("file::serve failed: {e}").into()
        })?;
    let join = tokio::spawn(async move {
        if let Err(err) = handles.join().await {
            panic!("in-process subset HTTP policy gateway listener failed: {err}");
        }
    });

    Ok(RunningGateway {
        http_port,
        shutdown_tx,
        join,
    })
}

fn mesh_runtime_config() -> MeshRuntimeConfig {
    MeshRuntimeConfig {
        node_id: "subset-http-node".to_string(),
        namespace: NS.to_string(),
        cp_urls: vec!["http://127.0.0.1:1".to_string()],
        config_protocol: MeshConfigProtocol::Native,
        file_config_path: None,
        topology: MeshTopology::Sidecar,
        inbound_listen_addr: "127.0.0.1:0".parse().expect("addr"),
        outbound_listen_addr: "127.0.0.1:0".parse().expect("addr"),
        hbone_listen_addr: "127.0.0.1:0".parse().expect("addr"),
        east_west_listen_port: 15443,
        egress_hbone_port: 15008,
        egress_mtls_port: 15006,
        egress_listen_addr: "0.0.0.0:15090".parse().expect("addr"),
        workload_spiffe_id: None,
        waypoint_name: None,
        xds_node_cluster: "default".to_string(),
        xds_stream_channel_capacity: 32,
        xds_primary_retry_secs: 300,
        xds_connect_timeout_seconds: 10,
        trust_domain_aliases: Vec::new(),
        trusted_hbone_assertors: Vec::new(),
        workload_labels: HashMap::new(),
        dns_enabled: false,
        dns_listen_addr: "127.0.0.1:15053".parse().expect("addr"),
        dns_upstream_addr: "127.0.0.53:53".parse().expect("addr"),
        dns_ttl_seconds: 60,
        dns_max_concurrent_queries: 1024,
        dns_response_cache_max_entries: 4096,
        cluster_domain: "cluster.local".to_string(),
        capture_mode: ferrum_edge::capture::CaptureMode::Explicit,
        outbound_traffic_policy: ferrum_edge::modes::mesh::config::OutboundTrafficPolicy::AllowAny,
        outbound_registry_reject_status: 502,
        sidecar_enforced: false,
        sidecar_enforced_dry_run: false,
        sidecar_identity_narrowing: false,
        workload_svid_cert_path: None,
        workload_svid_key_path: None,
        workload_svid_trust_bundle_path: None,
        ca_backend: ferrum_edge::identity::ca::CaBackend::None,
        egress_stream_enabled: false,
        egress_stream_allow_plaintext: false,
        request_auth_require_exp: true,
        locality_lb_strict: false,
    }
}

fn subset_https_dual_backend_config(h1_port: u16, h2_port: u16) -> GatewayConfig {
    let mut config = subset_policy_config(
        h1_port,
        "https",
        json!({
            "connection_pool_http": {
                "h2_upgrade_policy": "UPGRADE",
                "max_retries": 5,
                "http1_max_pending_requests": 100
            }
        }),
        json!({
            "h2_upgrade_policy": "DO_NOT_UPGRADE",
            "max_retries": 1,
            "http1_max_pending_requests": 1
        }),
        json!({
            "h2_upgrade_policy": "UPGRADE",
            "max_retries": 3,
            "http1_max_pending_requests": 50
        }),
        None,
        false,
    );
    // Point v2 targets at the H2-only fixture; v1 keeps the H1 fixture port.
    for upstream in &mut config.upstreams {
        for target in &mut upstream.targets {
            if target.tags.get("version").map(String::as_str) == Some("v2") {
                target.port = h2_port;
            }
        }
    }
    // Dual-backend H2 coverage only needs the subset-bound proxies.
    config
        .proxies
        .retain(|proxy| proxy.upstream_subset.is_some());
    config
}

fn subset_http_retry_config(backend_port: u16) -> GatewayConfig {
    subset_policy_config(
        backend_port,
        "http",
        json!({
            "connection_pool_http": {
                "h2_upgrade_policy": "DO_NOT_UPGRADE",
                "max_retries": 5,
                "http1_max_pending_requests": 100
            }
        }),
        json!({
            "h2_upgrade_policy": "DO_NOT_UPGRADE",
            "max_retries": 1,
            "http1_max_pending_requests": 1
        }),
        json!({
            "h2_upgrade_policy": "DO_NOT_UPGRADE",
            "max_retries": 3,
            "http1_max_pending_requests": 50
        }),
        Some(json!({
            "max_retries": 5,
            "retryable_status_codes": [503],
            "retryable_methods": ["GET"],
            "retry_on_connect_failure": false
        })),
        true,
    )
}

fn subset_http_pending_config(backend_port: u16) -> GatewayConfig {
    subset_policy_config(
        backend_port,
        "http",
        json!({
            "connection_pool_http": {
                "h2_upgrade_policy": "DO_NOT_UPGRADE",
                "max_retries": 5,
                "http1_max_pending_requests": 100
            }
        }),
        json!({
            "h2_upgrade_policy": "DO_NOT_UPGRADE",
            "max_retries": 1,
            "http1_max_pending_requests": 1
        }),
        json!({
            "h2_upgrade_policy": "DO_NOT_UPGRADE",
            "max_retries": 3,
            "http1_max_pending_requests": 50
        }),
        None,
        true,
    )
}

fn subset_policy_config(
    backend_port: u16,
    backend_scheme: &str,
    top_level: serde_json::Value,
    v1_http: serde_json::Value,
    v2_http: serde_json::Value,
    retry: Option<serde_json::Value>,
    force_h1_pool: bool,
) -> GatewayConfig {
    let mut proxies = Vec::new();
    for (id, path, subset) in [
        ("subset-v1", "/v1", Some("v1")),
        ("subset-v2", "/v2", Some("v2")),
        ("subset-unmatched", "/unmatched", None),
    ] {
        let mut proxy = json!({
            "id": id,
            "namespace": NS,
            "listen_path": path,
            "backend_scheme": backend_scheme,
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "backend_tls_verify_server_cert": false,
            "strip_listen_path": true,
            "upstream_id": UPSTREAM_ID,
            "pool_enable_http2": !force_h1_pool
        });
        if let Some(subset) = subset {
            proxy["upstream_subset"] = json!(subset);
        }
        if force_h1_pool {
            proxy["pool_enable_http2"] = json!(false);
        }
        if let Some(retry) = retry.clone() {
            proxy["retry"] = retry;
        }
        proxies.push(proxy);
    }

    serde_json::from_value(json!({
        "version": "1",
        "proxies": proxies,
        "upstreams": [{
            "id": UPSTREAM_ID,
            "namespace": NS,
            "name": "subset HTTP policy upstream",
            "algorithm": "round_robin",
            "targets": [
                {
                    "host": "127.0.0.1",
                    "port": backend_port,
                    "weight": 1,
                    "tags": { "version": "v1" }
                },
                {
                    "host": "127.0.0.1",
                    "port": backend_port,
                    "weight": 1,
                    "tags": { "version": "v2" }
                }
            ],
            "subsets": [
                {
                    "name": "v1",
                    "labels": { "version": "v1" }
                },
                {
                    "name": "v2",
                    "labels": { "version": "v2" }
                }
            ]
        }],
        "consumers": [],
        "plugin_configs": [],
        "mesh": {
            "destination_rules": [{
                "name": "subset-http-dr",
                "namespace": NS,
                "host": UPSTREAM_ID,
                "traffic_policy": top_level,
                "subsets": [
                    {
                        "name": "v1",
                        "labels": { "version": "v1" },
                        "traffic_policy": {
                            "connection_pool_http": v1_http
                        }
                    },
                    {
                        "name": "v2",
                        "labels": { "version": "v2" },
                        "traffic_policy": {
                            "connection_pool_http": v2_http
                        }
                    }
                ]
            }]
        }
    }))
    .expect("subset policy config is valid")
}

struct ReleaseGate {
    released: AtomicBool,
    notify: Notify,
}

impl ReleaseGate {
    fn new() -> Self {
        Self {
            released: AtomicBool::new(false),
            notify: Notify::new(),
        }
    }

    fn release(&self) {
        self.released.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    async fn wait(&self) {
        loop {
            let notified = self.notify.notified();
            if self.released.load(Ordering::SeqCst) {
                return;
            }
            notified.await;
        }
    }
}

async fn spawn_holding_backend() -> (u16, Arc<AtomicUsize>, Arc<ReleaseGate>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind holding backend");
    let port = listener.local_addr().expect("backend addr").port();
    let hits = Arc::new(AtomicUsize::new(0));
    let release = Arc::new(ReleaseGate::new());
    let task_hits = Arc::clone(&hits);
    let task_release = Arc::clone(&release);
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let hits = Arc::clone(&task_hits);
            let release = Arc::clone(&task_release);
            tokio::spawn(async move {
                if let Err(err) = serve_held_http(stream, &hits, Some(release)).await {
                    panic!("holding backend connection failed: {err}");
                }
            });
        }
    });
    (port, hits, release, task)
}

async fn spawn_status_script_backend(
    statuses: &[StatusCode],
) -> (u16, Arc<AtomicUsize>, Arc<AtomicBool>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind status backend");
    let port = listener.local_addr().expect("backend addr").port();
    let hits = Arc::new(AtomicUsize::new(0));
    let done = Arc::new(AtomicBool::new(false));
    let script: Vec<u16> = statuses.iter().map(|s| s.as_u16()).collect();
    let task_hits = Arc::clone(&hits);
    let task_done = Arc::clone(&done);
    let task = tokio::spawn(async move {
        let mut idx = 0usize;
        while !task_done.load(Ordering::SeqCst) {
            let accept = tokio::time::timeout(Duration::from_millis(200), listener.accept()).await;
            let Ok(Ok((stream, _))) = accept else {
                continue;
            };
            let status = script.get(idx).copied().unwrap_or(200);
            idx = idx.saturating_add(1);
            let hits = Arc::clone(&task_hits);
            tokio::spawn(async move {
                if let Err(err) = serve_status_http(stream, &hits, status).await {
                    panic!("status-script backend connection failed: {err}");
                }
            });
        }
    });
    (port, hits, done, task)
}

async fn serve_held_http(
    mut stream: TcpStream,
    hits: &AtomicUsize,
    release: Option<Arc<ReleaseGate>>,
) -> std::io::Result<()> {
    read_headers(&mut stream).await?;
    hits.fetch_add(1, Ordering::SeqCst);
    if let Some(release) = release {
        release.wait().await;
    }
    stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        .await?;
    let _ = stream.shutdown().await;
    Ok(())
}

async fn serve_status_http(
    mut stream: TcpStream,
    hits: &AtomicUsize,
    status: u16,
) -> std::io::Result<()> {
    read_headers(&mut stream).await?;
    hits.fetch_add(1, Ordering::SeqCst);
    let body = if status == 200 { "ok" } else { "retry" };
    let response = format!(
        "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    let _ = stream.shutdown().await;
    Ok(())
}

async fn read_headers(stream: &mut TcpStream) -> std::io::Result<()> {
    let mut buf = vec![0; 8192];
    let mut read = 0;
    loop {
        let n = stream.read(&mut buf[read..]).await?;
        if n == 0 {
            return Ok(());
        }
        read += n;
        if buf[..read].windows(4).any(|w| w == b"\r\n\r\n") {
            return Ok(());
        }
        if read == buf.len() {
            buf.resize(buf.len() * 2, 0);
        }
    }
}

async fn wait_for<F, Fut>(mut probe: F, timeout: Duration)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if probe().await {
            return;
        }
        sleep(Duration::from_millis(25)).await;
    }
    panic!("condition not met within {timeout:?}");
}
