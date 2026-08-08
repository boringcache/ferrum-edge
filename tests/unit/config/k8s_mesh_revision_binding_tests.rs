//! Kubernetes producer mesh↔revision binding (issue #3611).
//!
//! `K8sConfigRevisionTracker::publish` can retain an equal scalar while
//! reconcile evolves mesh content. The publication boundary must retain the
//! last accepted mesh until the sequence advances — without weakening the
//! data-plane `MeshRevisionGate`, and without letting a DB overlay recompose
//! resurrect a withheld divergent candidate.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use arc_swap::ArcSwap;
use ferrum_edge::_test_support::{
    CpPublicationGate, K8sOverlaySlot, compose_db_with_k8s_overlay, empty_k8s_overlay_slot,
    publish_k8s_reconcile,
};
use ferrum_edge::config::types::{
    AuthMode, BackendScheme, DispatchKind, GatewayConfig, K8sMeshOverlay, Proxy, ResponseBodyMode,
};
use ferrum_edge::grpc::cp_server::{CpScope, DpNodeRegistry, NamespaceBroadcasts};
use ferrum_edge::grpc::mesh_registry::MeshNodeRegistry;
use ferrum_edge::grpc::mesh_server::MeshConfigBroadcast;
use ferrum_edge::modes::mesh::config::{MeshConfig, MeshService};
use ferrum_edge::modes::mesh::revision::MeshConfigRevision;
use tokio::sync::broadcast;

fn make_proxy(id: &str, namespace: &str) -> Proxy {
    Proxy {
        id: id.to_string(),
        namespace: namespace.to_string(),
        name: Some(id.to_string()),
        hosts: vec![],
        listen_path: Some(format!("/{id}")),
        backend_scheme: Some(BackendScheme::Http),
        dispatch_kind: DispatchKind::from(BackendScheme::Http),
        backend_host: "localhost".to_string(),
        backend_port: 8080,
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
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

fn mesh_with_service(name: &str) -> Box<MeshConfig> {
    Box::new(MeshConfig {
        services: vec![MeshService {
            cluster_ips: Vec::new(),
            name: name.to_string(),
            namespace: "ferrum".to_string(),
            ports: Vec::new(),
            workloads: Vec::new(),
            protocol_overrides: HashMap::new(),
        }],
        ..Default::default()
    })
}

fn authoritative_translation(proxy_id: &str, mesh_service: &str) -> GatewayConfig {
    let mut translation = GatewayConfig::default();
    translation
        .proxies
        .push(make_proxy(proxy_id, "ferrum"));
    translation.mesh = Some(mesh_with_service(mesh_service));
    translation.k8s_mesh_overlay = K8sMeshOverlay::authoritative_translation();
    translation
}

fn revision(sequence: u64) -> MeshConfigRevision {
    MeshConfigRevision::new("k8s", sequence)
}

struct Harness {
    gate: CpPublicationGate,
    config_arc: Arc<ArcSwap<GatewayConfig>>,
    overlay_slot: K8sOverlaySlot,
    broadcasts: Arc<NamespaceBroadcasts>,
    dp_registry: Arc<DpNodeRegistry>,
    cp_scope: CpScope,
    mesh_tx: broadcast::Sender<MeshConfigBroadcast>,
    mesh_registry: Arc<MeshNodeRegistry>,
    managed: BTreeSet<String>,
}

impl Harness {
    fn new() -> Self {
        let (mesh_tx, _) = broadcast::channel(64);
        Self {
            gate: CpPublicationGate::new(),
            config_arc: Arc::new(ArcSwap::from_pointee(GatewayConfig::default())),
            overlay_slot: empty_k8s_overlay_slot(),
            broadcasts: Arc::new(NamespaceBroadcasts::new(64)),
            dp_registry: Arc::new(DpNodeRegistry::new()),
            cp_scope: CpScope::Single("ferrum".to_string()),
            mesh_tx,
            mesh_registry: Arc::new(MeshNodeRegistry::new()),
            managed: BTreeSet::from(["ferrum".to_string()]),
        }
    }

    fn publish(
        &self,
        translation: &GatewayConfig,
        mesh_revision: Option<&MeshConfigRevision>,
    ) -> Option<Arc<GatewayConfig>> {
        publish_k8s_reconcile(
            &self.gate,
            self.config_arc.as_ref(),
            &self.overlay_slot,
            translation,
            &self.managed,
            "ferrum",
            self.broadcasts.as_ref(),
            self.dp_registry.as_ref(),
            &self.cp_scope,
            &self.mesh_tx,
            self.mesh_registry.as_ref(),
            mesh_revision,
        )
    }

    fn overlay_mesh_service_names(&self) -> Vec<String> {
        let slot = self.overlay_slot.load_full();
        let overlay = slot.as_ref().as_ref().expect("overlay must be accepted");
        overlay
            .translation
            .mesh
            .as_ref()
            .map(|mesh| {
                mesh.services
                    .iter()
                    .map(|service| service.name.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn live_mesh_service_names(&self) -> Vec<String> {
        self.config_arc
            .load()
            .mesh
            .as_ref()
            .map(|mesh| {
                mesh.services
                    .iter()
                    .map(|service| service.name.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn overlay_revision(&self) -> Option<MeshConfigRevision> {
        self.overlay_slot
            .load_full()
            .as_ref()
            .as_ref()
            .and_then(|overlay| overlay.mesh_revision.clone())
    }
}

#[test]
fn equal_revision_with_changed_mesh_retains_prior_mesh() {
    let harness = Harness::new();
    let first = authoritative_translation("gwapi-route-a", "svc-a");
    assert!(harness.publish(&first, Some(&revision(664))).is_some());
    assert_eq!(harness.live_mesh_service_names(), vec!["svc-a".to_string()]);

    let divergent = authoritative_translation("gwapi-route-a", "svc-b");
    // Equal scalar + changed mesh: retain prior mesh. Non-mesh identical → no
    // content change to broadcast, but the overlay must still hold svc-a.
    assert!(harness.publish(&divergent, Some(&revision(664))).is_none());
    assert_eq!(harness.overlay_mesh_service_names(), vec!["svc-a".to_string()]);
    assert_eq!(harness.live_mesh_service_names(), vec!["svc-a".to_string()]);
    assert_eq!(harness.overlay_revision(), Some(revision(664)));
    assert_eq!(
        harness.config_arc.load().mesh_revision,
        Some(revision(664))
    );
}

#[test]
fn equal_revision_with_identical_mesh_is_idempotent() {
    let harness = Harness::new();
    let first = authoritative_translation("gwapi-route-a", "svc-a");
    assert!(harness.publish(&first, Some(&revision(100))).is_some());

    let replay = authoritative_translation("gwapi-route-a", "svc-a");
    assert!(harness.publish(&replay, Some(&revision(100))).is_none());
    assert_eq!(harness.overlay_mesh_service_names(), vec!["svc-a".to_string()]);
    assert_eq!(harness.overlay_revision(), Some(revision(100)));
}

#[test]
fn advanced_revision_releases_changed_mesh_and_withdrawal() {
    let harness = Harness::new();
    let first = authoritative_translation("gwapi-route-a", "svc-a");
    assert!(harness.publish(&first, Some(&revision(100))).is_some());

    let advanced = authoritative_translation("gwapi-route-a", "svc-b");
    assert!(harness.publish(&advanced, Some(&revision(200))).is_some());
    assert_eq!(harness.live_mesh_service_names(), vec!["svc-b".to_string()]);
    assert_eq!(harness.overlay_revision(), Some(revision(200)));

    let mut withdrawal = GatewayConfig::default();
    withdrawal
        .proxies
        .push(make_proxy("gwapi-route-a", "ferrum"));
    withdrawal.mesh = None;
    withdrawal.k8s_mesh_overlay = K8sMeshOverlay::authoritative_translation();
    assert!(harness.publish(&withdrawal, Some(&revision(300))).is_some());
    assert!(harness.live_mesh_service_names().is_empty());
    assert!(harness.config_arc.load().mesh.is_none());
    assert_eq!(harness.overlay_revision(), Some(revision(300)));
}

#[test]
fn non_mesh_changes_publish_while_equal_revision_mesh_is_retained() {
    let harness = Harness::new();
    let first = authoritative_translation("gwapi-route-a", "svc-a");
    assert!(harness.publish(&first, Some(&revision(50))).is_some());

    let mut divergent_mesh_new_proxy = authoritative_translation("gwapi-route-b", "svc-divergent");
    // Keep the same managed proxy family prefix so merge replaces cleanly.
    divergent_mesh_new_proxy.proxies[0].id = "gwapi-route-b".to_string();
    assert!(
        harness
            .publish(&divergent_mesh_new_proxy, Some(&revision(50)))
            .is_some()
    );

    let live = harness.config_arc.load_full();
    assert!(
        live.proxies.iter().any(|proxy| proxy.id == "gwapi-route-b"),
        "non-mesh Gateway/API changes must still publish"
    );
    assert_eq!(
        harness.live_mesh_service_names(),
        vec!["svc-a".to_string()],
        "divergent mesh under an equal revision must be retained"
    );
    assert_eq!(harness.overlay_mesh_service_names(), vec!["svc-a".to_string()]);
    assert_eq!(harness.overlay_revision(), Some(revision(50)));
    assert_eq!(live.mesh_revision, Some(revision(50)));
}

#[test]
fn db_overlay_recomposition_cannot_publish_withheld_divergent_mesh() {
    let harness = Harness::new();
    let first = authoritative_translation("gwapi-route-a", "svc-a");
    assert!(harness.publish(&first, Some(&revision(664))).is_some());

    let divergent = authoritative_translation("gwapi-route-a", "svc-withheld");
    assert!(harness.publish(&divergent, Some(&revision(664))).is_none());

    let mut db_reload = GatewayConfig::default();
    db_reload.proxies.push(make_proxy("db-proxy", "ferrum"));
    let composed = compose_db_with_k8s_overlay(&db_reload, &harness.overlay_slot);
    assert!(
        composed.proxies.iter().any(|proxy| proxy.id == "db-proxy"),
        "DB resources must compose"
    );
    assert_eq!(
        composed
            .mesh
            .as_ref()
            .map(|mesh| {
                mesh.services
                    .iter()
                    .map(|service| service.name.clone())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default(),
        vec!["svc-a".to_string()],
        "DB recomposition must use the retained overlay mesh, not the withheld candidate"
    );
    assert_eq!(composed.mesh_revision, Some(revision(664)));
}

#[test]
fn unversioned_bootstrap_still_publishes_evolving_mesh() {
    let harness = Harness::new();
    let first = authoritative_translation("gwapi-route-a", "svc-a");
    assert!(harness.publish(&first, None).is_some());
    assert_eq!(harness.live_mesh_service_names(), vec!["svc-a".to_string()]);
    assert!(harness.overlay_revision().is_none());

    let second = authoritative_translation("gwapi-route-a", "svc-b");
    assert!(harness.publish(&second, None).is_some());
    assert_eq!(
        harness.live_mesh_service_names(),
        vec!["svc-b".to_string()],
        "before any versioned snapshot, unversioned bootstrap must still evolve mesh"
    );
    assert!(harness.overlay_revision().is_none());
}
