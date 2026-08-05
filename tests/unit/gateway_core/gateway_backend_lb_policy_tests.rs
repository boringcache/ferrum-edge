//! Live LB-path coverage for Gateway API BackendLBPolicy /
//! XBackendTrafficPolicy session persistence (#3278).
//!
//! Translation alone is covered in `gateway_api.rs`. These tests feed the
//! translated Upstream through `LoadBalancerCache` so sticky cookie hashing
//! actually selects the same target — the data path that changes traffic.

use std::collections::HashMap;

use ferrum_edge::config::types::{
    HashOnCookieConfig, LoadBalancerAlgorithm, Upstream, UpstreamTarget,
};
use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::load_balancer::{HashOnStrategy, LoadBalancerCache};
use serde_json::json;

fn options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("test trust domain"),
    )
}

fn object(kind: &str, api_version: &str, name: &str, spec: serde_json::Value) -> K8sObject {
    K8sObject {
        api_version: api_version.to_string(),
        kind: kind.to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            uid: String::new(),
            namespace: "default".to_string(),
            generation: None,
            labels: HashMap::new(),
            annotations: HashMap::new(),
            creation_timestamp: None,
            deletion_timestamp: None,
        },
        spec,
        status: serde_json::Value::Object(serde_json::Map::new()),
    }
}

#[test]
fn backend_lb_policy_cookie_affinity_selects_stable_target_on_lb_path() {
    let policy = object(
        "BackendLBPolicy",
        "gateway.networking.k8s.io/v1alpha2",
        "sticky",
        json!({
            "targetRefs": [{"group": "", "kind": "Service", "name": "api"}],
            "sessionPersistence": {
                "sessionName": "lb-affinity",
                "type": "Cookie",
                "cookieConfig": {"lifetimeType": "Session"}
            }
        }),
    );
    // Headless multi-endpoint Service so sticky hashing has >1 target.
    let service = object(
        "Service",
        "v1",
        "api",
        json!({
            "clusterIP": "None",
            "selector": {"app": "api"},
            "ports": [{
                "name": "http",
                "port": 8080,
                "targetPort": 8080
            }]
        }),
    );
    let mut endpoints = object(
        "EndpointSlice",
        "discovery.k8s.io/v1",
        "api-slices",
        json!({
            "addressType": "IPv4",
            "ports": [{"name": "http", "port": 8080, "protocol": "TCP"}],
            "endpoints": [
                {"addresses": ["10.1.0.10"], "conditions": {"ready": true}},
                {"addresses": ["10.1.0.11"], "conditions": {"ready": true}},
                {"addresses": ["10.1.0.12"], "conditions": {"ready": true}}
            ]
        }),
    );
    endpoints
        .metadata
        .labels
        .insert("kubernetes.io/service-name".to_string(), "api".to_string());
    let route = object(
        "HTTPRoute",
        "gateway.networking.k8s.io/v1",
        "sample",
        json!({
            "hostnames": ["api.example.com"],
            "rules": [{
                "matches": [{"path": {"type": "PathPrefix", "value": "/api"}}],
                "backendRefs": [{"name": "api", "port": 8080}]
            }]
        }),
    );

    let result = translate_k8s_objects(
        &[policy, service, endpoints, route],
        options().with_pod_discovery_enabled(true),
    )
    .expect("BackendLBPolicy + multi-endpoint Service should translate");

    assert_eq!(result.config.upstreams.len(), 1);
    let upstream = &result.config.upstreams[0];
    assert_eq!(upstream.algorithm, LoadBalancerAlgorithm::ConsistentHashing);
    let cookie_name = upstream
        .hash_on
        .as_deref()
        .and_then(|value| value.strip_prefix("cookie:"))
        .expect("cookie hash strategy");
    assert!(
        cookie_name.starts_with("lb-affinity-fe-"),
        "cookie must be scoped to the route rule: {cookie_name}"
    );
    assert!(
        upstream
            .hash_on_cookie_config
            .as_ref()
            .is_some_and(|c| c.session_cookie),
        "Session lifetime must set session_cookie"
    );
    assert!(
        upstream.targets.len() >= 2,
        "need multiple endpoints for sticky affinity proof, got {}",
        upstream.targets.len()
    );

    let cache = LoadBalancerCache::new(&result.config);
    assert_eq!(
        cache.get_hash_on_strategy(&upstream.namespace, &upstream.id),
        HashOnStrategy::Cookie(cookie_name.to_string())
    );

    // `get_balancer` lives on the inner snapshot, so reach it through the
    // `ArcSwap` load the same way the other load-balancer tests do.
    let lb = cache
        .load()
        .get_balancer(&upstream.namespace, &upstream.id)
        .expect("translated upstream must be in LB cache");
    let first = lb
        .select("cookie-value-abc", None)
        .expect("selection succeeds");
    for _ in 0..50 {
        let next = lb
            .select("cookie-value-abc", None)
            .expect("selection succeeds");
        assert_eq!(next.target.host, first.target.host);
        assert_eq!(next.target.port, first.target.port);
    }

    // A different cookie value must be able to land on a different pod
    // (otherwise the "sticky" assertion above is vacuously true).
    let mut other_hosts = std::collections::HashSet::new();
    for i in 0..40 {
        let key = format!("other-cookie-{i}");
        let sel = lb.select(&key, None).expect("selection succeeds");
        other_hosts.insert(sel.target.host.clone());
    }
    assert!(
        other_hosts.len() > 1,
        "diverse cookie keys should spread across endpoints, got {other_hosts:?}"
    );
}

#[test]
fn sticky_session_cookie_omits_max_age_on_set_cookie() {
    let target = UpstreamTarget {
        host: "10.1.0.10".into(),
        port: 8080,
        weight: 1,
        tags: HashMap::new(),
        locality: None,
        path: None,
        service_port_policy_key: None,
    };
    let session = HashOnCookieConfig {
        session_cookie: true,
        ttl_seconds: 3600,
        ..HashOnCookieConfig::default()
    };
    let header = ferrum_edge::_test_support::build_sticky_cookie_header_for_test(
        "lb-affinity",
        &target,
        &session,
    );
    assert!(
        header.starts_with("lb-affinity="),
        "cookie name must be present: {header}"
    );
    assert!(
        !header.contains("Max-Age="),
        "Session lifetimeType must omit Max-Age: {header}"
    );
    assert!(header.contains("Path=/"));
    assert!(header.contains("HttpOnly"));

    let permanent = HashOnCookieConfig {
        session_cookie: false,
        ttl_seconds: 7200,
        ..HashOnCookieConfig::default()
    };
    let permanent_header = ferrum_edge::_test_support::build_sticky_cookie_header_for_test(
        "lb-affinity",
        &target,
        &permanent,
    );
    assert!(
        permanent_header.contains("Max-Age=7200"),
        "Permanent cookies must set Max-Age: {permanent_header}"
    );

    // Translated Upstream shape must still pass field validation.
    let upstream = Upstream {
        id: "u1".into(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: Some("u1".into()),
        targets: vec![target],
        algorithm: LoadBalancerAlgorithm::ConsistentHashing,
        hash_on: Some("cookie:lb-affinity".into()),
        hash_on_cookie_config: Some(session),
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
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    assert!(upstream.validate_fields().is_ok());
}
