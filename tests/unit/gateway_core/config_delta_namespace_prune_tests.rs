//! Regression coverage for issue #3094: full-snapshot ConfigDelta identity and
//! cache pruning must key resources by `(namespace, id)` so the same id in two
//! namespaces cannot hide a tenant removal or prune the wrong tenant's state.

use chrono::Utc;
use ferrum_edge::circuit_breaker::{CircuitBreakerCache, target_key};
use ferrum_edge::config::db_backend::NamespacedResourceId;
use ferrum_edge::config::types::*;
use ferrum_edge::config_delta::ConfigDelta;
use ferrum_edge::health_check::HealthChecker;
use ferrum_edge::load_balancer::LoadBalancerCache;
use ferrum_edge::plugin_cache::PluginCache;
use std::collections::HashMap;

fn make_proxy(namespace: &str, id: &str, listen_path: &str) -> Proxy {
    let now = Utc::now();
    Proxy {
        id: id.to_string(),
        namespace: namespace.to_string(),
        name: None,
        hosts: vec![],
        listen_path: Some(listen_path.to_string()),
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
        circuit_breaker: Some(CircuitBreakerConfig::default()),
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
        created_at: now,
        updated_at: now,
    }
}

fn make_upstream(namespace: &str, id: &str, host: &str) -> Upstream {
    let now = Utc::now();
    Upstream {
        id: id.to_string(),
        namespace: namespace.to_string(),
        name: None,
        targets: vec![UpstreamTarget {
            host: host.to_string(),
            port: 8080,
            service_port_policy_key: None,
            weight: 100,
            tags: HashMap::new(),
            locality: None,
            path: None,
        }],
        algorithm: LoadBalancerAlgorithm::default(),
        hash_on: None,
        hash_on_cookie_config: None,
        health_checks: None,
        service_discovery: None,
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

fn make_plugin_config(namespace: &str, id: &str) -> PluginConfig {
    let now = Utc::now();
    PluginConfig {
        id: id.to_string(),
        namespace: namespace.to_string(),
        plugin_name: "request_transformer".to_string(),
        config: serde_json::json!({}),
        scope: PluginScope::Global,
        proxy_id: None,
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: now,
        updated_at: now,
    }
}

fn make_consumer(namespace: &str, id: &str) -> Consumer {
    let now = Utc::now();
    Consumer {
        id: id.to_string(),
        namespace: namespace.to_string(),
        username: format!("{namespace}-{id}"),
        custom_id: None,
        credentials: HashMap::new(),
        acl_groups: Vec::new(),
        created_at: now,
        updated_at: now,
    }
}

#[test]
fn config_delta_removal_is_namespace_qualified_for_all_resource_kinds() {
    let old = GatewayConfig {
        proxies: vec![
            make_proxy("prod", "shared", "/prod"),
            make_proxy("staging", "shared", "/staging"),
        ],
        consumers: vec![
            make_consumer("prod", "shared"),
            make_consumer("staging", "shared"),
        ],
        plugin_configs: vec![
            make_plugin_config("prod", "shared"),
            make_plugin_config("staging", "shared"),
        ],
        upstreams: vec![
            make_upstream("prod", "shared", "prod.example"),
            make_upstream("staging", "shared", "staging.example"),
        ],
        ..GatewayConfig::default()
    };
    let new = GatewayConfig {
        proxies: vec![make_proxy("prod", "shared", "/prod")],
        consumers: vec![make_consumer("prod", "shared")],
        plugin_configs: vec![make_plugin_config("prod", "shared")],
        upstreams: vec![make_upstream("prod", "shared", "prod.example")],
        ..GatewayConfig::default()
    };

    let delta = ConfigDelta::compute(&old, &new);

    assert_eq!(
        delta.removed_proxy_ids,
        vec![NamespacedResourceId::new("staging", "shared")]
    );
    assert_eq!(
        delta.removed_consumer_ids,
        vec![NamespacedResourceId::new("staging", "shared")]
    );
    assert_eq!(
        delta.removed_plugin_config_ids,
        vec![NamespacedResourceId::new("staging", "shared")]
    );
    assert_eq!(
        delta.removed_upstream_ids,
        vec![NamespacedResourceId::new("staging", "shared")]
    );
    assert!(delta.added_proxies.is_empty());
    assert!(delta.modified_proxies.is_empty());
}

#[test]
fn circuit_breaker_prune_removes_only_matching_namespace() {
    let cache = CircuitBreakerCache::new();
    let cfg = CircuitBreakerConfig::default();
    let tk = target_key("10.0.0.1", 8080);

    let _ = cache.get_or_create("prod", "shared", Some(&tk), &cfg);
    let _ = cache.get_or_create("staging", "shared", Some(&tk), &cfg);
    assert_eq!(cache.len(), 2);

    cache.prune(&[NamespacedResourceId::new("staging", "shared")]);

    assert!(cache.peek("staging", "shared", Some(&tk)).is_none());
    assert!(cache.peek("prod", "shared", Some(&tk)).is_some());
    assert_eq!(cache.len(), 1);
}

#[test]
fn health_check_prune_removes_only_matching_namespace() {
    let checker = HealthChecker::new();
    let target = UpstreamTarget {
        host: "10.0.0.1".to_string(),
        port: 8080,
        service_port_policy_key: None,
        weight: 100,
        tags: HashMap::new(),
        locality: None,
        path: None,
    };
    let passive = PassiveHealthCheck {
        unhealthy_status_codes: vec![500],
        unhealthy_threshold: 1,
        unhealthy_window_seconds: 60,
        healthy_after_seconds: 0,
        max_ejection_percent: None,
        gateway_error_codes: None,
        split_external_local_origin_errors: None,
    };

    checker.report_response("prod", "shared", &target, 500, false, Some(&passive));
    checker.report_response("staging", "shared", &target, 500, false, Some(&passive));
    assert_eq!(checker.passive_health.len(), 2);

    checker.prune_removed_proxies(&[NamespacedResourceId::new("staging", "shared")]);

    assert!(!checker
        .passive_health
        .contains_key(&NamespacedResourceId::new("staging", "shared").runtime_key()));
    assert!(checker
        .passive_health
        .contains_key(&NamespacedResourceId::new("prod", "shared").runtime_key()));
}

#[test]
fn plugin_cache_delta_prunes_only_matching_namespace() {
    let old = GatewayConfig {
        proxies: vec![
            make_proxy("prod", "shared", "/prod"),
            make_proxy("staging", "shared", "/staging"),
        ],
        ..GatewayConfig::default()
    };
    let new = GatewayConfig {
        proxies: vec![make_proxy("prod", "shared", "/prod")],
        ..GatewayConfig::default()
    };

    let cache = PluginCache::new(&old).expect("initial plugin cache");
    let delta = ConfigDelta::compute(&old, &new);
    assert_eq!(
        delta.removed_proxy_ids,
        vec![NamespacedResourceId::new("staging", "shared")]
    );
    let rebuild = delta.proxy_ids_needing_plugin_rebuild(&old, &new);
    cache
        .apply_delta(&new, &rebuild, &delta.removed_proxy_ids, false)
        .expect("namespace-qualified prune must succeed");

    assert!(ferrum_edge::_test_support::plugin_cache_contains_proxy_for_test(
        &cache, "prod", "shared"
    ));
    assert!(!ferrum_edge::_test_support::plugin_cache_contains_proxy_for_test(
        &cache, "staging", "shared"
    ));
}

#[test]
fn load_balancer_delta_prunes_only_matching_namespace() {
    let old = GatewayConfig {
        upstreams: vec![
            make_upstream("prod", "shared", "prod.example"),
            make_upstream("staging", "shared", "staging.example"),
        ],
        ..GatewayConfig::default()
    };
    let new = GatewayConfig {
        upstreams: vec![make_upstream("prod", "shared", "prod.example")],
        ..GatewayConfig::default()
    };

    let cache = LoadBalancerCache::new(&old);
    assert!(cache.get_upstream("prod", "shared").is_some());
    assert!(cache.get_upstream("staging", "shared").is_some());

    let delta = ConfigDelta::compute(&old, &new);
    cache.apply_delta(
        &new,
        &delta.added_upstreams,
        &delta.removed_upstream_ids,
        &delta.modified_upstreams,
    );

    assert!(cache.get_upstream("prod", "shared").is_some());
    assert!(cache.get_upstream("staging", "shared").is_none());
    assert_eq!(
        delta.removed_upstream_ids,
        vec![NamespacedResourceId::new("staging", "shared")]
    );
}

#[test]
fn consumer_index_delta_prunes_only_matching_namespace() {
    use ferrum_edge::consumer_index::ConsumerIndex;

    let old_consumers = vec![
        make_consumer("prod", "shared"),
        make_consumer("staging", "shared"),
    ];
    let new_consumers = vec![make_consumer("prod", "shared")];
    let index = ConsumerIndex::new(&old_consumers);
    assert_eq!(index.consumers().len(), 2);

    let delta = ConfigDelta::compute(
        &GatewayConfig {
            consumers: old_consumers.clone(),
            ..GatewayConfig::default()
        },
        &GatewayConfig {
            consumers: new_consumers.clone(),
            ..GatewayConfig::default()
        },
    );
    index.apply_delta(
        &delta.added_consumers,
        &delta.removed_consumer_ids,
        &delta.modified_consumers,
    );

    let remaining = index.consumers();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].namespace, "prod");
    assert_eq!(remaining[0].id, "shared");
    assert_eq!(
        delta.removed_consumer_ids,
        vec![NamespacedResourceId::new("staging", "shared")]
    );
}

#[test]
fn same_id_modification_is_isolated_per_namespace() {
    let t1 = Utc::now();
    let t2 = t1 + chrono::Duration::seconds(5);
    let mut old_proxy = make_proxy("staging", "shared", "/staging");
    old_proxy.updated_at = t1;
    let mut new_proxy = make_proxy("staging", "shared", "/staging-v2");
    new_proxy.updated_at = t2;

    let old = GatewayConfig {
        proxies: vec![make_proxy("prod", "shared", "/prod"), old_proxy],
        ..GatewayConfig::default()
    };
    let new = GatewayConfig {
        proxies: vec![make_proxy("prod", "shared", "/prod"), new_proxy],
        ..GatewayConfig::default()
    };

    let delta = ConfigDelta::compute(&old, &new);
    assert!(delta.removed_proxy_ids.is_empty());
    assert_eq!(delta.modified_proxies.len(), 1);
    assert_eq!(delta.modified_proxies[0].namespace, "staging");
    assert_eq!(
        delta.modified_proxies[0].listen_path.as_deref(),
        Some("/staging-v2")
    );
}
