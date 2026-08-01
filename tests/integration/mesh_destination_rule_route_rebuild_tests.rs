//! #3243: DestinationRule-only edits must atomically republish route-held
//! `Arc<Proxy>` projections before any programmed-status / revision ACK.
//!
//! `ConfigDelta` keys on resource `updated_at`, but DR-derived proxy fields
//! (`dispatch_port_overrides`, `dispatch_port_override_fallback`,
//! `resolved_tls`) are `#[serde(skip)]`. These tests drive the live
//! `ProxyState::update_config` path — including the empty-delta publish
//! branch — so a DR-only create/update/removal cannot leave stale route
//! snapshots until an unrelated proxy edit.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{Duration, Utc};
use ferrum_edge::config::types::{
    DnsSdConfig, GatewayConfig, LoadBalancerAlgorithm, MAX_TARGET_WEIGHT, Proxy, SdProvider,
    ServiceDiscoveryConfig, Upstream, UpstreamPortOverride, UpstreamTarget,
};
use ferrum_edge::config::{EnvConfig, OperatingMode};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::modes::mesh::config::{
    MeshConfig, MeshConnectionPoolHttp, MeshDestinationRule, MeshTrafficPolicy,
    MeshTrafficPolicyTls, MtlsMode,
};
use ferrum_edge::modes::mesh::{
    MeshConfigProtocol, MeshRuntimeConfig, MeshTopology, prepare_gateway_config_for_mesh,
};
use ferrum_edge::proxy::{ConfigApplyOutcome, ProxyState};

fn runtime() -> MeshRuntimeConfig {
    MeshRuntimeConfig {
        node_id: "node-a".to_string(),
        namespace: "default".to_string(),
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

fn mesh_env() -> EnvConfig {
    EnvConfig {
        mode: OperatingMode::Mesh,
        ..EnvConfig::default()
    }
}

fn http_proxy() -> Proxy {
    serde_json::from_value(serde_json::json!({
        "id": "reviews-p",
        "namespace": "default",
        "hosts": ["reviews.example.com"],
        "listen_path": "/http",
        "backend_host": "reviews.default.svc.cluster.local",
        "backend_port": 0,
        "backend_scheme": "http",
        "upstream_id": "reviews-u"
    }))
    .expect("proxy fixture")
}

fn sd_upstream() -> Upstream {
    let now = Utc::now();
    Upstream {
        id: "reviews-u".to_string(),
        namespace: "default".to_string(),
        name: Some("reviews.default.svc.cluster.local".to_string()),
        targets: vec![UpstreamTarget {
            host: "reviews.default.svc.cluster.local".to_string(),
            port: 8080,
            service_port_policy_key: None,
            weight: MAX_TARGET_WEIGHT.min(1),
            tags: HashMap::new(),
            locality: None,
            path: None,
        }],
        algorithm: LoadBalancerAlgorithm::RoundRobin,
        hash_on: None,
        hash_on_cookie_config: None,
        health_checks: None,
        service_discovery: Some(ServiceDiscoveryConfig {
            provider: SdProvider::DnsSd,
            dns_sd: Some(DnsSdConfig {
                service_name: "_http._tcp.reviews.default.svc.cluster.local".to_string(),
                poll_interval_seconds: 30,
            }),
            kubernetes: None,
            consul: None,
            mesh: None,
            default_weight: 1,
        }),
        subsets: None,
        port_overrides: HashMap::new(),
        source_locality: None,
        locality_lb_strict: false,
        locality_lb_setting: None,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        backend_tls_sni: None,
        backend_tls_san_allow_list: Vec::new(),
        resolved_subset_tls: HashMap::new(),
        dispatch_port_override_fallback: None,
        api_spec_id: None,
        created_at: now,
        updated_at: now,
    }
}

fn destination_rule(idle_ms: Option<u64>, tls_sni: Option<&str>) -> MeshDestinationRule {
    MeshDestinationRule {
        name: "reviews-dr".to_string(),
        namespace: "default".to_string(),
        host: "reviews.default.svc.cluster.local".to_string(),
        traffic_policy: Some(MeshTrafficPolicy {
            connection_pool_http: idle_ms.map(|ms| MeshConnectionPoolHttp {
                idle_timeout_ms: Some(ms),
                ..MeshConnectionPoolHttp::default()
            }),
            tls: tls_sni.map(|sni| MeshTrafficPolicyTls {
                mode: MtlsMode::Simple,
                sni: Some(sni.to_string()),
                ..MeshTrafficPolicyTls::default()
            }),
            ..MeshTrafficPolicy::default()
        }),
        port_level_settings: HashMap::new(),
        subsets: Vec::new(),
    }
}

fn prepared_with_dr(dr: Option<MeshDestinationRule>) -> GatewayConfig {
    let stamp = Utc::now() - Duration::seconds(30);
    let mut proxy = http_proxy();
    proxy.created_at = stamp;
    proxy.updated_at = stamp;
    let mut upstream = sd_upstream();
    upstream.created_at = stamp;
    upstream.updated_at = stamp;
    let mut config = GatewayConfig {
        proxies: vec![proxy],
        upstreams: vec![upstream],
        mesh: Some(Box::new(MeshConfig {
            destination_rules: dr.into_iter().collect(),
            ..MeshConfig::default()
        })),
        ..GatewayConfig::default()
    };
    config.normalize_fields();
    let mut prepared = prepare_gateway_config_for_mesh(config, &runtime()).expect("mesh prepare");
    // Stabilize operator-authored proxy timestamps so DR-only prepares do not
    // accidentally look like Proxy resource edits.
    for proxy in &mut prepared.proxies {
        if proxy.id == "reviews-p" {
            proxy.created_at = stamp;
            proxy.updated_at = stamp;
        }
    }
    prepared
}

fn route_fallback_idle_ms(state: &ProxyState) -> Option<u64> {
    state
        .router_cache
        .find_proxy(Some("reviews.example.com"), "/http")
        .expect("route present")
        .proxy
        .dispatch_port_override_fallback
        .as_ref()
        .and_then(|override_config| override_config.http_idle_timeout_ms)
}

fn route_tls_sni(state: &ProxyState) -> Option<String> {
    state
        .router_cache
        .find_proxy(Some("reviews.example.com"), "/http")
        .expect("route present")
        .proxy
        .resolved_tls
        .sni
        .clone()
}

fn new_proxy_state(config: GatewayConfig) -> (ProxyState, Vec<tokio::task::JoinHandle<()>>) {
    let dns_cache = DnsCache::new(DnsConfig::default());
    ProxyState::new(config, dns_cache, mesh_env(), None, None).expect("ProxyState")
}

/// Same serialized proxy/upstream timestamps, different `#[serde(skip)]`
/// projections — the empty-ConfigDelta DR-only shape that previously reused a
/// stale route table until an unrelated event.
fn projected_only_configs(
    mutate_old: impl FnOnce(&mut Upstream),
    mutate_new: impl FnOnce(&mut Upstream),
) -> (GatewayConfig, GatewayConfig) {
    let stamp = Utc::now();
    let mut old_upstream = sd_upstream();
    old_upstream.created_at = stamp;
    old_upstream.updated_at = stamp;
    mutate_old(&mut old_upstream);

    let mut new_upstream = sd_upstream();
    new_upstream.created_at = stamp;
    new_upstream.updated_at = stamp;
    mutate_new(&mut new_upstream);

    let mut proxy = http_proxy();
    proxy.created_at = stamp;
    proxy.updated_at = stamp;

    let mut old_config = GatewayConfig {
        proxies: vec![proxy.clone()],
        upstreams: vec![old_upstream],
        ..GatewayConfig::default()
    };
    let mut new_config = GatewayConfig {
        proxies: vec![proxy],
        upstreams: vec![new_upstream],
        ..GatewayConfig::default()
    };
    old_config.normalize_fields();
    old_config.resolve_upstream_tls();
    new_config.normalize_fields();
    new_config.resolve_upstream_tls();
    (old_config, new_config)
}

#[tokio::test]
async fn update_config_republishes_routes_for_empty_delta_dr_fallback_change() {
    let (old_config, new_config) = projected_only_configs(
        |upstream| {
            upstream.dispatch_port_override_fallback = Some(UpstreamPortOverride {
                http_idle_timeout_ms: Some(1_000),
                ..Default::default()
            });
        },
        |upstream| {
            upstream.dispatch_port_override_fallback = Some(UpstreamPortOverride {
                http_idle_timeout_ms: Some(2_000),
                ..Default::default()
            });
        },
    );

    let delta = ferrum_edge::config_delta::ConfigDelta::compute(&old_config, &new_config);
    assert!(
        delta.is_empty(),
        "fixture must keep ConfigDelta empty so the empty-delta publish path is exercised"
    );
    assert!(
        delta.modified_proxies.is_empty(),
        "DR-only edits must not manufacture a Proxy resource modification"
    );

    let (state, _handles) = new_proxy_state(old_config);
    assert_eq!(route_fallback_idle_ms(&state), Some(1_000));

    let outcome = state.update_config(new_config);
    assert_eq!(outcome, ConfigApplyOutcome::Applied);
    assert_eq!(
        route_fallback_idle_ms(&state),
        Some(2_000),
        "empty-delta DR projection change must swap the route-held Arc<Proxy> immediately"
    );
}

#[tokio::test]
async fn update_config_republishes_routes_for_empty_delta_dr_tls_change() {
    let (old_config, new_config) = projected_only_configs(
        |upstream| {
            upstream.backend_tls_sni = Some("old.backend.mesh.internal".to_string());
        },
        |upstream| {
            upstream.backend_tls_sni = Some("new.backend.mesh.internal".to_string());
        },
    );

    // TLS fields are serialized, so bumping content without advancing
    // `updated_at` is the same ConfigDelta-blind shape operators hit when a
    // DR projection lands without a proxy edit.
    let mut old = old_config;
    let mut new = new_config;
    // Force identical timestamps after projection so ConfigDelta stays empty
    // even though serialized TLS content differs — the production mesh
    // reconcile normally advances `updated_at`, but the route signal must not
    // depend on that alone.
    let stamp = old.upstreams[0].updated_at;
    new.upstreams[0].updated_at = stamp;
    new.upstreams[0].created_at = old.upstreams[0].created_at;
    old.resolve_upstream_tls();
    new.resolve_upstream_tls();
    // Re-run normalize so dispatch projections stay consistent with the TLS
    // resolve pass above.
    old.normalize_fields();
    new.normalize_fields();
    old.resolve_upstream_tls();
    new.resolve_upstream_tls();
    new.upstreams[0].updated_at = stamp;
    new.upstreams[0].created_at = old.upstreams[0].created_at;
    new.proxies[0].updated_at = old.proxies[0].updated_at;
    new.proxies[0].created_at = old.proxies[0].created_at;

    let delta = ferrum_edge::config_delta::ConfigDelta::compute(&old, &new);
    assert!(
        delta.is_empty(),
        "TLS fixture must keep ConfigDelta empty (same resource timestamps)"
    );

    let (state, _handles) = new_proxy_state(old);
    assert_eq!(
        route_tls_sni(&state).as_deref(),
        Some("old.backend.mesh.internal")
    );

    assert_eq!(state.update_config(new), ConfigApplyOutcome::Applied);
    assert_eq!(
        route_tls_sni(&state).as_deref(),
        Some("new.backend.mesh.internal"),
        "DR TLS projection change must refresh route-held resolved_tls without a Proxy delta"
    );
}

#[tokio::test]
async fn update_config_removes_dr_fallback_and_restores_route_defaults() {
    let (with_fallback, without_fallback) = projected_only_configs(
        |upstream| {
            upstream.dispatch_port_override_fallback = Some(UpstreamPortOverride {
                http_idle_timeout_ms: Some(4_000),
                ..Default::default()
            });
        },
        |_upstream| {},
    );

    let (state, _handles) = new_proxy_state(with_fallback);
    assert_eq!(route_fallback_idle_ms(&state), Some(4_000));

    assert_eq!(
        state.update_config(without_fallback),
        ConfigApplyOutcome::Applied
    );
    assert_eq!(
        route_fallback_idle_ms(&state),
        None,
        "DR removal must clear the route-held fallback projection back to defaults"
    );
}

#[tokio::test]
async fn update_config_dr_noop_and_repeated_reload_are_stable() {
    let prepared = prepared_with_dr(Some(destination_rule(Some(7_000), None)));
    let (state, _handles) = new_proxy_state(prepared.clone());
    assert_eq!(route_fallback_idle_ms(&state), Some(7_000));

    // Unchanged-config no-op: re-applying the same generation must not invent
    // a route rebuild requirement beyond what ArcSwap publish already did.
    let first = state.update_config(prepared.clone());
    assert!(
        matches!(
            first,
            ConfigApplyOutcome::Unchanged | ConfigApplyOutcome::Applied
        ),
        "identical candidate must be accepted; got {first:?}"
    );
    assert_eq!(route_fallback_idle_ms(&state), Some(7_000));

    // Repeated reload with a real DR pool change then a second identical apply.
    let changed = prepared_with_dr(Some(destination_rule(Some(9_000), None)));
    assert_eq!(state.update_config(changed.clone()), ConfigApplyOutcome::Applied);
    assert_eq!(route_fallback_idle_ms(&state), Some(9_000));

    let repeat = state.update_config(changed);
    assert!(
        matches!(
            repeat,
            ConfigApplyOutcome::Unchanged | ConfigApplyOutcome::Applied
        ),
        "repeated identical DR reload must stay accepted; got {repeat:?}"
    );
    assert_eq!(route_fallback_idle_ms(&state), Some(9_000));
}

#[tokio::test]
async fn update_config_applies_mesh_dr_prepare_without_proxy_resource_edit() {
    // Live mesh prepare path: Services/VirtualServices (proxies) unchanged;
    // only DestinationRule pool + TLS projections change. No manufactured
    // Proxy `updated_at` bump — the invalidation signal must fire from the
    // projected fields alone (or the mesh-block / upstream timestamp delta
    // the mesh apply already produces).
    let initial = prepared_with_dr(Some(destination_rule(
        Some(1_500),
        Some("initial.reviews.mesh.internal"),
    )));
    let updated = prepared_with_dr(Some(destination_rule(
        Some(3_500),
        Some("updated.reviews.mesh.internal"),
    )));

    assert_eq!(
        initial
            .proxies
            .iter()
            .find(|proxy| proxy.id == "reviews-p")
            .expect("reviews proxy")
            .updated_at,
        updated
            .proxies
            .iter()
            .find(|proxy| proxy.id == "reviews-p")
            .expect("reviews proxy")
            .updated_at
    );

    let (state, _handles) = new_proxy_state(initial);
    assert_eq!(route_fallback_idle_ms(&state), Some(1_500));
    assert_eq!(
        route_tls_sni(&state).as_deref(),
        Some("initial.reviews.mesh.internal")
    );

    assert_eq!(state.update_config(updated), ConfigApplyOutcome::Applied);
    assert_eq!(route_fallback_idle_ms(&state), Some(3_500));
    assert_eq!(
        route_tls_sni(&state).as_deref(),
        Some("updated.reviews.mesh.internal"),
        "mesh DR-only prepare must refresh pool + TLS on the live route table without a Proxy edit"
    );
}

#[tokio::test]
async fn update_config_unrelated_mesh_policy_does_not_require_proxy_edit_for_dr() {
    // Pin the "no unrelated event" acceptance criterion: a DestinationRule
    // projection change is sufficient by itself. The prior generation already
    // carries a non-DR mesh block; swapping only the DR still republishes.
    let mut base = prepared_with_dr(Some(destination_rule(Some(2_200), None)));
    if let Some(mesh) = base.mesh.as_mut() {
        // Keep a stable non-DR mesh field so the candidate is not "mesh absent".
        mesh.istio_root_namespace = "istio-system".to_string();
    }
    let mut next = prepared_with_dr(Some(destination_rule(Some(8_800), None)));
    if let Some(mesh) = next.mesh.as_mut() {
        mesh.istio_root_namespace = "istio-system".to_string();
    }

    let (state, _handles) = new_proxy_state(base);
    let before = Arc::as_ptr(
        &state
            .router_cache
            .find_proxy(Some("reviews.example.com"), "/http")
            .expect("route")
            .proxy,
    );
    assert_eq!(route_fallback_idle_ms(&state), Some(2_200));

    assert_eq!(state.update_config(next), ConfigApplyOutcome::Applied);
    let after = Arc::as_ptr(
        &state
            .router_cache
            .find_proxy(Some("reviews.example.com"), "/http")
            .expect("route")
            .proxy,
    );
    assert_ne!(
        before, after,
        "DR-only change must publish a fresh route-held Arc<Proxy>, not wait for an unrelated proxy event"
    );
    assert_eq!(route_fallback_idle_ms(&state), Some(8_800));
}
