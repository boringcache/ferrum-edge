//! Integration coverage for `GET /mesh/remote-clusters` (F7.2).
//!
//! Exercises the end-to-end admin surface: AdminState is built with a
//! `MeshRuntimeState`, a discovered-remote-cluster snapshot is staged in the
//! `RemoteEndpointStore`, an accepted slice carrying a `MultiClusterConfig` is
//! installed, and the handler must reflect the `discovered` counts, the
//! `configured` list, the `discovered`-cross-reference flag, and the
//! `discovery_enabled` flag. The pure response-builder logic is covered by
//! inline unit tests in `src/admin/mesh_remote_clusters.rs`; this leg
//! validates JWT gating, the not-in-mesh-mode 404 case, and the
//! snapshot/slice → admin response contract.

use arc_swap::ArcSwap;
use chrono::Utc;
use ferrum_edge::admin::{
    AdminState,
    jwt_auth::{JwtConfig, JwtManager},
    serve_admin_on_listener,
};
use ferrum_edge::config::env_config::EnvConfig;
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::identity::{SpiffeId, TrustDomain};
use ferrum_edge::modes::mesh::config::{
    MeshConfig, MeshService, MultiClusterConfig, RemoteCluster, ServicePort, Workload, WorkloadRef,
    WorkloadSelector,
};
use ferrum_edge::modes::mesh::multicluster::{RemoteClusterEndpoints, RemoteClusterEntry};
use ferrum_edge::modes::mesh::runtime::MeshRuntimeState;
use ferrum_edge::modes::mesh::slice::MeshSlice;
use ferrum_edge::proxy::ProxyState;
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Clone)]
struct TestConfig {
    jwt_secret: String,
    jwt_issuer: String,
    max_ttl: u64,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            jwt_secret: "test-secret-key-for-mesh-remote-clusters-32".to_string(),
            jwt_issuer: "test-ferrum-edge".to_string(),
            max_ttl: 3600,
        }
    }
}

fn create_test_jwt_manager(config: &TestConfig) -> JwtManager {
    JwtManager::new(JwtConfig {
        secret: config.jwt_secret.clone(),
        issuer: config.jwt_issuer.clone(),
        max_ttl_seconds: config.max_ttl,
        algorithm: jsonwebtoken::Algorithm::HS256,
    })
}

fn generate_test_token(config: &TestConfig) -> String {
    let now = Utc::now();
    let claims = json!({
        "iss": config.jwt_issuer,
        "sub": "test-user",
        "role": "admin",
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + chrono::Duration::seconds(config.max_ttl as i64)).timestamp(),
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    let header = Header::new(jsonwebtoken::Algorithm::HS256);
    let key = EncodingKey::from_secret(config.jwt_secret.as_bytes());
    encode(&header, &claims, &key).unwrap()
}

/// Build an `AdminState` in mesh mode. `discovery_poll_interval` > 0 flips the
/// `discovery_enabled` flag the handler reads from env config.
fn build_admin_state(
    jwt: JwtManager,
    mesh_runtime_state: Option<MeshRuntimeState>,
    discovery_poll_interval: u64,
) -> AdminState {
    let cfg = GatewayConfig {
        version: "1".to_string(),
        loaded_at: Utc::now(),
        mesh: Some(Box::new(MeshConfig::default())),
        ..GatewayConfig::default()
    };
    let env_config = EnvConfig {
        namespace: "alpha".to_string(),
        mesh_config_protocol: "native".to_string(),
        mesh_remote_discovery_poll_interval_seconds: discovery_poll_interval,
        ..EnvConfig::default()
    };
    let (proxy_state, _handles) = ProxyState::new(
        cfg,
        DnsCache::new(DnsConfig::default()),
        env_config,
        None,
        None,
    )
    .expect("proxy state");

    AdminState {
        db: None,
        jwt_manager: jwt,
        cached_config: None,
        proxy_state: Some(proxy_state),
        mode: "mesh".to_string(),
        read_only: false,
        admin_audit_enabled: false,
        startup_ready: None,
        db_available: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: Arc::new(ferrum_edge::proxy::client_ip::TrustedProxies::none()),
        cached_db_health: Arc::new(ArcSwap::new(Arc::new(None))),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        mesh_runtime_state,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendAllowIps::Both,
    }
}

async fn start_test_admin(state: AdminState) -> (String, tokio::sync::watch::Sender<bool>) {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let actual_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = serve_admin_on_listener(listener, state, shutdown_rx, None).await;
    });
    for _ in 0..200 {
        if tokio::net::TcpStream::connect(actual_addr).await.is_ok() {
            return (format!("http://{}", actual_addr), shutdown_tx);
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("admin listener at {} never became ready", actual_addr);
}

fn td(raw: &str) -> TrustDomain {
    TrustDomain::new(raw).expect("trust domain")
}

fn spiffe(raw: &str) -> SpiffeId {
    SpiffeId::new(raw.to_string()).expect("spiffe id")
}

fn workload(spiffe_id: &str, service: &str, address: &str) -> Workload {
    let id = spiffe(spiffe_id);
    let trust_domain = id.trust_domain().clone();
    Workload {
        spiffe_id: id,
        selector: WorkloadSelector::default(),
        service_name: service.to_string(),
        addresses: vec![address.to_string()],
        ports: vec![],
        trust_domain,
        namespace: "default".to_string(),
        network: None,
        cluster: None,
        weight: None,
        locality: None,
        service_account: None,
        pod_uid: None,
    }
}

fn service(name: &str) -> MeshService {
    MeshService {
        cluster_ips: Vec::new(),
        name: name.to_string(),
        namespace: "default".to_string(),
        ports: vec![ServicePort {
            port: 8080,
            protocol: Default::default(),
            name: Some("http".to_string()),
            target_port: None,
        }],
        workloads: vec![WorkloadRef {
            spiffe_id: spiffe("spiffe://east.example.com/ns/default/sa/reviews"),
        }],
        protocol_overrides: HashMap::new(),
    }
}

/// Stage a discovered remote cluster into the runtime's `RemoteEndpointStore`
/// via the `#[doc(hidden)]` test-support seeder.
fn seed_discovered(runtime: &MeshRuntimeState, cluster: &str, trust_domain: &str, fetched_at: u64) {
    runtime
        .remote_endpoint_store()
        .install_for_test(RemoteClusterEntry {
            cluster_name: cluster.to_string(),
            trust_domain: td(trust_domain),
            network: Some("net2".to_string()),
            endpoints: RemoteClusterEndpoints {
                workloads: vec![
                    workload(
                        "spiffe://east.example.com/ns/default/sa/reviews",
                        "reviews",
                        "10.9.0.1",
                    ),
                    workload(
                        "spiffe://east.example.com/ns/default/sa/reviews",
                        "reviews",
                        "10.9.0.2",
                    ),
                ],
                services: vec![service("reviews")],
            },
            fetched_at_unix_seconds: fetched_at,
        });
}

/// Install an accepted slice carrying a `MultiClusterConfig` declaring two
/// remote clusters (one discoverable, one federation-only).
fn install_accepted_slice_with_config(runtime: &MeshRuntimeState) {
    let slice = MeshSlice {
        namespace: "alpha".to_string(),
        version: "v-rc-1".to_string(),
        multi_cluster: Some(MultiClusterConfig {
            local_cluster: Some("local".to_string()),
            federation_endpoint: None,
            remote_clusters: vec![
                RemoteCluster {
                    name: "remote-east".to_string(),
                    trust_domain: td("east.example.com"),
                    network: Some("net2".to_string()),
                    control_plane_url: Some("grpcs://cp.east.example.com:50051".to_string()),
                    federation_endpoint: Some("https://spire.east.example.com/bundle".to_string()),
                },
                RemoteCluster {
                    name: "remote-west".to_string(),
                    trust_domain: td("west.example.com"),
                    network: None,
                    // Federation-only: no control plane, never discoverable.
                    control_plane_url: None,
                    federation_endpoint: Some("https://spire.west.example.com/bundle".to_string()),
                },
            ],
            east_west_gateways: Vec::new(),
        }),
        ..MeshSlice::default()
    };
    runtime.install_slice(slice.clone());
    runtime.record_applied_slice(&slice);
}

#[tokio::test]
async fn remote_clusters_endpoint_requires_jwt() {
    let tc = TestConfig::default();
    let state = build_admin_state(
        create_test_jwt_manager(&tc),
        Some(MeshRuntimeState::new()),
        60,
    );
    let (base_url, _shutdown) = start_test_admin(state).await;

    let response = reqwest::Client::new()
        .get(format!("{base_url}/mesh/remote-clusters"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 401);
}

#[tokio::test]
async fn remote_clusters_endpoint_returns_404_outside_mesh_mode() {
    let tc = TestConfig::default();
    let token = generate_test_token(&tc);
    // No mesh_runtime_state wired in — mirrors the other `/mesh/*` endpoints'
    // wrong-mode branch.
    let state = build_admin_state(create_test_jwt_manager(&tc), None, 60);
    let (base_url, _shutdown) = start_test_admin(state).await;

    let response = reqwest::Client::new()
        .get(format!("{base_url}/mesh/remote-clusters"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 404);
}

#[tokio::test]
async fn remote_clusters_endpoint_returns_200_empty_before_discovery() {
    // Mesh runtime wired but nothing discovered and no slice accepted — the DP
    // is in mesh mode but hasn't converged. Both lists must be present (and
    // empty) so dashboards can poll continuously across boot. Discovery is
    // disabled here (poll interval 0).
    let tc = TestConfig::default();
    let token = generate_test_token(&tc);
    let state = build_admin_state(
        create_test_jwt_manager(&tc),
        Some(MeshRuntimeState::new()),
        0,
    );
    let (base_url, _shutdown) = start_test_admin(state).await;

    let response = reqwest::Client::new()
        .get(format!("{base_url}/mesh/remote-clusters"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let body: Value = response.json().await.unwrap();

    assert_eq!(body["discovery_enabled"], false);
    assert_eq!(
        body["discovered"].as_array().map(Vec::len),
        Some(0),
        "discovered must be an empty array, not null"
    );
    assert_eq!(
        body["configured"].as_array().map(Vec::len),
        Some(0),
        "configured must be an empty array, not null"
    );
}

#[tokio::test]
async fn remote_clusters_endpoint_reflects_discovered_and_configured() {
    let tc = TestConfig::default();
    let token = generate_test_token(&tc);
    let runtime = MeshRuntimeState::new();
    // Discovered: remote-east, fetched 5s ago. Configured: remote-east +
    // remote-west (federation-only).
    let fetched_at = (Utc::now().timestamp().max(0) as u64).saturating_sub(5);
    seed_discovered(&runtime, "remote-east", "east.example.com", fetched_at);
    install_accepted_slice_with_config(&runtime);

    let state = build_admin_state(create_test_jwt_manager(&tc), Some(runtime), 60);
    let (base_url, _shutdown) = start_test_admin(state).await;

    let body: Value = reqwest::Client::new()
        .get(format!("{base_url}/mesh/remote-clusters"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(body["discovery_enabled"], true);

    // ── discovered view ──────────────────────────────────────────────────
    let discovered = body["discovered"].as_array().expect("discovered array");
    assert_eq!(discovered.len(), 1);
    let east = &discovered[0];
    assert_eq!(east["cluster_name"], "remote-east");
    assert_eq!(east["trust_domain"], "east.example.com");
    assert_eq!(east["network"], "net2");
    assert_eq!(east["workload_count"], 2);
    assert_eq!(east["service_count"], 1);
    assert_eq!(east["fetched_at_unix_seconds"], fetched_at);
    let age = east["age_seconds"].as_u64().expect("age_seconds u64");
    assert!(age >= 5, "age_seconds should be at least 5, got {age}");
    // The payload must NOT leak raw workload addresses / SPIFFE IDs.
    let east_str = serde_json::to_string(east).unwrap();
    assert!(
        !east_str.contains("10.9.0.1") && !east_str.contains("spiffe://"),
        "discovered entry must not expose raw addresses or SPIFFE IDs: {east_str}"
    );

    // ── configured view ──────────────────────────────────────────────────
    let configured = body["configured"].as_array().expect("configured array");
    assert_eq!(configured.len(), 2);
    // Sorted by cluster_name: remote-east before remote-west.
    let cfg_east = &configured[0];
    assert_eq!(cfg_east["cluster_name"], "remote-east");
    assert_eq!(cfg_east["trust_domain"], "east.example.com");
    assert_eq!(cfg_east["control_plane_configured"], true);
    assert_eq!(cfg_east["federation_endpoint_configured"], true);
    assert_eq!(
        cfg_east["discovered"], true,
        "remote-east is both configured and discovered"
    );

    let cfg_west = &configured[1];
    assert_eq!(cfg_west["cluster_name"], "remote-west");
    assert_eq!(
        cfg_west["control_plane_configured"], false,
        "remote-west is federation-only"
    );
    assert_eq!(cfg_west["federation_endpoint_configured"], true);
    assert_eq!(
        cfg_west["discovered"], false,
        "remote-west is configured but not discovered — the operator's signal"
    );

    // Control-plane / federation URLs must never appear in the payload.
    let body_str = serde_json::to_string(&body).unwrap();
    assert!(
        !body_str.contains("grpcs://") && !body_str.contains("https://spire"),
        "configured entries must not expose control-plane / federation URLs: {body_str}"
    );
}
