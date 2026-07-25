//! CP DB-poll / Kubernetes-overlay isolation (issues #2982–#2984).
//!
//! Covers overlay survival across full DB reload, per-namespace failure
//! isolation, and concurrent poll/reconcile CAS publication.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use arc_swap::ArcSwap;
use chrono::Utc;
use ferrum_edge::_test_support::{
    cas_publish_db_snapshot_with_k8s_overlay_for_test, cas_publish_incremental_partitions_for_test,
    compose_db_with_k8s_overlay, compose_incremental_partitions_for_test, empty_k8s_overlay_slot,
    store_accepted_k8s_overlay, swap_merged_k8s_translation,
};
use ferrum_edge::config::db_backend::IncrementalResult;
use ferrum_edge::config::types::{
    AuthMode, BackendScheme, DispatchKind, GatewayConfig, Proxy, ResponseBodyMode,
};
use ferrum_edge::modes::mesh::config::{MeshConfig, MeshService};

fn empty_incremental() -> IncrementalResult {
    IncrementalResult {
        added_or_modified_proxies: vec![],
        removed_proxy_ids: vec![],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec![],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![],
        removed_upstream_ids: vec![],
        sequence_cursor: 0,
        poll_timestamp: Utc::now(),
    }
}

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
        created_at: Utc::now(),
        updated_at: Utc::now(),
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

#[test]
fn full_db_reload_reapplies_k8s_overlay_and_mesh() {
    // #2982: DB-only snapshot must not wipe the independently owned overlay.
    let overlay_slot = empty_k8s_overlay_slot();
    let mut k8s = GatewayConfig::default();
    k8s.proxies
        .push(make_proxy("gwapi-route-httpbin", "ferrum"));
    k8s.mesh = Some(mesh_with_service("overlay-svc"));
    let managed = BTreeSet::from(["ferrum".to_string()]);
    store_accepted_k8s_overlay(&overlay_slot, k8s.clone(), managed);

    let mut db_reload = GatewayConfig::default();
    db_reload.proxies.push(make_proxy("db-proxy", "ferrum"));

    let config_arc = ArcSwap::from_pointee(GatewayConfig::default());
    let published =
        cas_publish_db_snapshot_with_k8s_overlay_for_test(&config_arc, &overlay_slot, db_reload);

    assert!(
        published.proxies.iter().any(|p| p.id == "db-proxy"),
        "DB resources must survive publication"
    );
    assert!(
        published
            .proxies
            .iter()
            .any(|p| p.id == "gwapi-route-httpbin"),
        "K8s overlay proxy must be re-merged across full reload"
    );
    assert!(
        published.mesh.is_some(),
        "mesh block from the overlay slot must survive full reload"
    );
    assert_eq!(
        compose_db_with_k8s_overlay(&GatewayConfig::default(), &overlay_slot)
            .proxies
            .len(),
        1,
        "compose helper must read the same slot"
    );
}

#[test]
fn per_namespace_incremental_rejection_keeps_sibling_lkg() {
    // #2983: invalid ns-b must not block ns-a refresh.
    let mut base = GatewayConfig::default();
    base.proxies.push(make_proxy("a-old", "ns-a"));
    base.proxies.push(make_proxy("b-old", "ns-b"));

    let mut ok_delta = empty_incremental();
    ok_delta.added_or_modified_proxies = vec![make_proxy("a-new", "ns-a")];
    ok_delta.removed_proxy_ids = vec!["a-old".to_string()];

    let mut bad_delta = empty_incremental();
    let mut dangling = make_proxy("b-bad", "ns-b");
    dangling.upstream_id = Some("missing-upstream".to_string());
    bad_delta.added_or_modified_proxies = vec![dangling];
    bad_delta.removed_proxy_ids = vec!["b-old".to_string()];

    let partitions = HashMap::from([
        ("ns-a".to_string(), ok_delta),
        ("ns-b".to_string(), bad_delta),
    ]);

    let (composed, accepted, rejected) =
        compose_incremental_partitions_for_test(&base, &partitions);

    assert_eq!(accepted, vec!["ns-a".to_string()]);
    assert_eq!(rejected, vec!["ns-b".to_string()]);
    assert!(
        composed.proxies.iter().any(|p| p.id == "a-new"),
        "valid namespace must refresh"
    );
    assert!(
        composed.proxies.iter().any(|p| p.id == "b-old"),
        "rejected namespace must retain last-known-good"
    );
    assert!(
        !composed.proxies.iter().any(|p| p.id == "b-bad"),
        "rejected namespace must not apply the invalid delta"
    );
}

#[test]
fn concurrent_poll_and_reconcile_cas_preserves_both_sources() {
    // #2984: poll CAS must not revert a concurrent reconciler overlay write.
    let mut db_base = GatewayConfig::default();
    db_base.proxies.push(make_proxy("db-base", "ferrum"));
    let config_arc = Arc::new(ArcSwap::from_pointee(db_base.clone()));

    let overlay_slot = empty_k8s_overlay_slot();
    let mut k8s = GatewayConfig::default();
    k8s.proxies
        .push(make_proxy("gwapi-route-overlay", "ferrum"));
    let managed = BTreeSet::from(["ferrum".to_string()]);
    store_accepted_k8s_overlay(&overlay_slot, k8s.clone(), managed.clone());

    let writer = {
        let config_arc = Arc::clone(&config_arc);
        let k8s = k8s.clone();
        let managed = managed.clone();
        thread::spawn(move || {
            for _ in 0..200 {
                let _ = swap_merged_k8s_translation(config_arc.as_ref(), &k8s, &managed);
                thread::sleep(Duration::from_micros(50));
            }
        })
    };

    let mut db_reload = db_base;
    db_reload.proxies.push(make_proxy("db-updated", "ferrum"));
    for _ in 0..50 {
        let _ = cas_publish_db_snapshot_with_k8s_overlay_for_test(
            config_arc.as_ref(),
            &overlay_slot,
            db_reload.clone(),
        );
        thread::sleep(Duration::from_micros(50));
    }

    writer.join().expect("reconciler thread");

    let final_config = config_arc.load_full();
    assert!(
        final_config
            .proxies
            .iter()
            .any(|p| p.id == "db-updated" || p.id == "db-base"),
        "DB-authored proxies must remain after concurrent publication"
    );
    assert!(
        final_config
            .proxies
            .iter()
            .any(|p| p.id == "gwapi-route-overlay"),
        "K8s overlay must not be lost to a concurrent poll store"
    );
}

#[test]
fn concurrent_incremental_cas_retains_reconciler_overlay() {
    let mut base = GatewayConfig::default();
    base.proxies.push(make_proxy("db-base", "ferrum"));
    let config_arc = Arc::new(ArcSwap::from_pointee(base));

    let mut k8s = GatewayConfig::default();
    k8s.proxies
        .push(make_proxy("gwapi-route-overlay", "ferrum"));
    let managed = BTreeSet::from(["ferrum".to_string()]);
    let _ = swap_merged_k8s_translation(config_arc.as_ref(), &k8s, &managed);

    let writer = {
        let config_arc = Arc::clone(&config_arc);
        let k8s = k8s.clone();
        let managed = managed.clone();
        thread::spawn(move || {
            for _ in 0..100 {
                let _ = swap_merged_k8s_translation(config_arc.as_ref(), &k8s, &managed);
                thread::sleep(Duration::from_micros(50));
            }
        })
    };

    let mut delta = empty_incremental();
    delta.added_or_modified_proxies = vec![make_proxy("db-delta", "ferrum")];
    let partitions = HashMap::from([("ferrum".to_string(), delta)]);

    for _ in 0..30 {
        let _ = cas_publish_incremental_partitions_for_test(config_arc.as_ref(), &partitions);
        thread::sleep(Duration::from_micros(50));
    }

    writer.join().expect("reconciler thread");

    let final_config = config_arc.load_full();
    assert!(
        final_config.proxies.iter().any(|p| p.id == "db-delta"),
        "incremental DB delta must commit"
    );
    assert!(
        final_config
            .proxies
            .iter()
            .any(|p| p.id == "gwapi-route-overlay"),
        "concurrent reconciler overlay must survive incremental CAS"
    );
}
