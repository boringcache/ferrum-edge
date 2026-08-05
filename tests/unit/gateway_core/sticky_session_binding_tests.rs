//! Backend-bound sticky-session token coverage (issue #3278 / PR #3585).
//!
//! Gateway API session persistence requires a client to return to the backend
//! that served its initial response — not merely to *a* deterministic backend.
//! These tests pin the read side of that contract (`LoadBalancer::select_sticky`)
//! and the boundary handling of untrusted cookie input:
//!
//! - a token minted for a target resolves to that exact target;
//! - malformed, oversized, empty, uppercase, and non-hex values are rejected by
//!   bounded validation and never resolve;
//! - a token minted under another upstream identity (another route / service /
//!   namespace / BackendLBPolicy) does not steer traffic across that boundary;
//! - a token whose backend was removed, ejected by health, or lives outside the
//!   selected subset / port lane resolves to nothing, so the caller falls back
//!   to ordinary selection instead of dialing an ineligible target.
//!
//! Translation and the emitted `Set-Cookie` shape live in
//! `gateway_backend_lb_policy_tests.rs`.

use std::collections::HashMap;

use chrono::Utc;
use dashmap::DashMap;
use ferrum_edge::config::types::{
    GatewayConfig, LoadBalancerAlgorithm, SubsetDefinition, Upstream, UpstreamPortOverride,
    UpstreamTarget,
};
use ferrum_edge::load_balancer::{
    HealthContext, LoadBalancerCache, STICKY_SESSION_TOKEN_LEN, is_sticky_session_token,
    sticky_session_token,
};

const NAMESPACE: &str = "ferrum";
const UPSTREAM_ID: &str = "gwapi-route-upstream-default-sample-r0";

fn target(host: &str, port: u16) -> UpstreamTarget {
    tagged_target(host, port, &[])
}

fn tagged_target(host: &str, port: u16, tags: &[(&str, &str)]) -> UpstreamTarget {
    UpstreamTarget {
        host: host.to_string(),
        port,
        service_port_policy_key: None,
        weight: 1,
        tags: tags
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect(),
        locality: None,
        path: None,
    }
}

fn sticky_upstream(targets: Vec<UpstreamTarget>) -> Upstream {
    let now = Utc::now();
    Upstream {
        id: UPSTREAM_ID.to_string(),
        namespace: NAMESPACE.to_string(),
        name: Some(UPSTREAM_ID.to_string()),
        targets,
        algorithm: LoadBalancerAlgorithm::ConsistentHashing,
        hash_on: Some("cookie:lb-affinity-fe-0123456789abcdef".to_string()),
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

fn cache_for(upstream: Upstream) -> LoadBalancerCache {
    LoadBalancerCache::new(&GatewayConfig {
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    })
}

/// The scope string a token is bound to: the namespace-qualified upstream
/// identity `LoadBalancerCache` keys balancers by.
fn scope(namespace: &str, upstream_id: &str) -> String {
    format!("{namespace}|{upstream_id}")
}

fn token_for(namespace: &str, upstream_id: &str, target: &UpstreamTarget) -> String {
    sticky_session_token(&scope(namespace, upstream_id), target)
}

#[test]
fn emitted_token_resolves_to_the_exact_minting_backend() {
    let targets = vec![
        target("10.1.0.10", 8080),
        target("10.1.0.11", 8080),
        target("10.1.0.12", 8080),
    ];
    let cache = cache_for(sticky_upstream(targets.clone()));
    let snapshot = cache.load();

    for expected in &targets {
        let token = token_for(NAMESPACE, UPSTREAM_ID, expected);
        assert!(is_sticky_session_token(&token));
        assert_eq!(token.len(), STICKY_SESSION_TOKEN_LEN);

        // Repeat: the binding must not drift request to request.
        for _ in 0..10 {
            let bound = LoadBalancerCache::select_sticky_from(
                &snapshot,
                NAMESPACE,
                UPSTREAM_ID,
                &token,
                None,
                None,
                None,
            )
            .expect("minted token must resolve to its backend");
            assert_eq!(bound.host, expected.host);
            assert_eq!(bound.port, expected.port);
        }
    }
}

#[test]
fn distinct_backends_mint_distinct_tokens() {
    let a = target("10.1.0.10", 8080);
    let b = target("10.1.0.11", 8080);
    let other_port = target("10.1.0.10", 9090);
    let token_a = token_for(NAMESPACE, UPSTREAM_ID, &a);
    let token_b = token_for(NAMESPACE, UPSTREAM_ID, &b);
    let token_other_port = token_for(NAMESPACE, UPSTREAM_ID, &other_port);
    assert_ne!(token_a, token_b);
    assert_ne!(token_a, token_other_port);
}

#[test]
fn malformed_and_oversized_tokens_are_rejected_at_the_boundary() {
    let pinned = target("10.1.0.10", 8080);
    let targets = vec![pinned.clone(), target("10.1.0.11", 8080)];
    let cache = cache_for(sticky_upstream(targets));
    let snapshot = cache.load();
    let valid = token_for(NAMESPACE, UPSTREAM_ID, &pinned);

    let hostile = [
        String::new(),
        "not-a-token".to_string(),
        valid[..STICKY_SESSION_TOKEN_LEN - 1].to_string(),
        format!("{valid}0"),
        valid.to_ascii_uppercase(),
        // Right length, wrong alphabet.
        "g".repeat(STICKY_SESSION_TOKEN_LEN),
        format!("{}\n{}", &valid[..32], &valid[32..]),
        // Oversized: length is checked first, so this costs one comparison.
        "a".repeat(1024 * 1024),
        format!("{valid}; Path=/"),
    ];

    for value in &hostile {
        assert!(
            !is_sticky_session_token(value),
            "hostile value must fail bounded validation"
        );
        assert!(
            LoadBalancerCache::select_sticky_from(
                &snapshot,
                NAMESPACE,
                UPSTREAM_ID,
                value,
                None,
                None,
                None,
            )
            .is_none(),
            "hostile value must not resolve to a backend"
        );
    }

    // A well-formed but unknown token (right shape, never minted here) is
    // likewise unbound rather than a wildcard.
    let unknown = "0".repeat(STICKY_SESSION_TOKEN_LEN);
    assert!(is_sticky_session_token(&unknown));
    assert!(
        LoadBalancerCache::select_sticky_from(
            &snapshot,
            NAMESPACE,
            UPSTREAM_ID,
            &unknown,
            None,
            None,
            None,
        )
        .is_none()
    );

    // The genuine token still works — the rejections above are not blanket.
    assert!(
        LoadBalancerCache::select_sticky_from(
            &snapshot,
            NAMESPACE,
            UPSTREAM_ID,
            &valid,
            None,
            None,
            None,
        )
        .is_some()
    );
}

#[test]
fn tokens_do_not_cross_route_service_or_namespace_scopes() {
    let pinned = target("10.1.0.10", 8080);
    let targets = vec![pinned.clone(), target("10.1.0.11", 8080)];
    let cache = cache_for(sticky_upstream(targets));
    let snapshot = cache.load();
    let local = token_for(NAMESPACE, UPSTREAM_ID, &pinned);

    // Same backend address, minted under a different route rule's upstream, a
    // different Service-derived upstream, and a different namespace. All three
    // are foreign scopes and must not steer traffic here.
    let foreign_scopes = [
        (NAMESPACE, "gwapi-route-upstream-default-sample-r1"),
        (NAMESPACE, "gwapi-route-upstream-default-other-r0"),
        ("tenant-b", UPSTREAM_ID),
    ];
    for (ns, id) in foreign_scopes {
        let foreign = token_for(ns, id, &pinned);
        assert_ne!(foreign, local, "foreign scopes must differ");
        assert!(
            LoadBalancerCache::select_sticky_from(
                &snapshot,
                NAMESPACE,
                UPSTREAM_ID,
                &foreign,
                None,
                None,
                None,
            )
            .is_none(),
            "foreign-scope token must not resolve inside {NAMESPACE}|{UPSTREAM_ID}"
        );
    }
}

#[test]
fn stale_token_for_a_removed_backend_does_not_resolve() {
    let removed = target("10.1.0.12", 8080);
    let token = token_for(NAMESPACE, UPSTREAM_ID, &removed);

    let full = vec![
        target("10.1.0.10", 8080),
        target("10.1.0.11", 8080),
        removed.clone(),
    ];
    let before = cache_for(sticky_upstream(full));
    assert!(
        LoadBalancerCache::select_sticky_from(
            &before.load(),
            NAMESPACE,
            UPSTREAM_ID,
            &token,
            None,
            None,
            None,
        )
        .is_some(),
        "precondition: the token resolves while the backend exists"
    );

    // Scale-down / EndpointSlice update drops that endpoint; the index is
    // rebuilt with the balancer, so the old token becomes unbound.
    let shrunk = vec![target("10.1.0.10", 8080), target("10.1.0.11", 8080)];
    let after = cache_for(sticky_upstream(shrunk));
    assert!(
        LoadBalancerCache::select_sticky_from(
            &after.load(),
            NAMESPACE,
            UPSTREAM_ID,
            &token,
            None,
            None,
            None,
        )
        .is_none(),
        "a token for a removed backend must not resolve"
    );
}

#[test]
fn unhealthy_pinned_backend_is_not_selected() {
    let pinned = target("10.1.0.10", 8080);
    let targets = vec![pinned.clone(), target("10.1.0.11", 8080)];
    let cache = cache_for(sticky_upstream(targets));
    let snapshot = cache.load();
    let token = token_for(NAMESPACE, UPSTREAM_ID, &pinned);

    let active_unhealthy = DashMap::new();
    active_unhealthy.insert(format!("{NAMESPACE}|{UPSTREAM_ID}::10.1.0.10:8080"), 0u64);
    let health = HealthContext {
        active_unhealthy: &active_unhealthy,
        proxy_passive: None,
        max_ejection_percent: None,
    };

    assert!(
        LoadBalancerCache::select_sticky_from(
            &snapshot,
            NAMESPACE,
            UPSTREAM_ID,
            &token,
            None,
            None,
            Some(&health),
        )
        .is_none(),
        "an ejected pinned backend must not be dialed"
    );
    // Recovery re-pins without a new cookie: the binding itself is unchanged.
    active_unhealthy.clear();
    assert!(
        LoadBalancerCache::select_sticky_from(
            &snapshot,
            NAMESPACE,
            UPSTREAM_ID,
            &token,
            None,
            None,
            Some(&health),
        )
        .is_some()
    );
}

#[test]
fn sticky_binding_respects_subset_scoping() {
    let v1 = tagged_target("10.1.0.10", 8080, &[("version", "v1")]);
    let v2 = tagged_target("10.1.0.11", 8080, &[("version", "v2")]);
    let mut upstream = sticky_upstream(vec![v1.clone(), v2.clone()]);
    upstream.subsets = Some(vec![
        SubsetDefinition {
            name: "v1".to_string(),
            labels: HashMap::from([("version".to_string(), "v1".to_string())]),
            traffic_policy: None,
        },
        SubsetDefinition {
            name: "v2".to_string(),
            labels: HashMap::from([("version".to_string(), "v2".to_string())]),
            traffic_policy: None,
        },
    ]);
    let cache = cache_for(upstream);
    let snapshot = cache.load();
    let v1_token = token_for(NAMESPACE, UPSTREAM_ID, &v1);

    let in_subset = LoadBalancerCache::select_sticky_from(
        &snapshot,
        NAMESPACE,
        UPSTREAM_ID,
        &v1_token,
        None,
        Some("v1"),
        None,
    )
    .expect("v1 token resolves inside the v1 subset");
    assert_eq!(in_subset.host, "10.1.0.10");

    assert!(
        LoadBalancerCache::select_sticky_from(
            &snapshot,
            NAMESPACE,
            UPSTREAM_ID,
            &v1_token,
            None,
            Some("v2"),
            None,
        )
        .is_none(),
        "a v1 binding must not escape into the v2 subset"
    );
    assert!(
        LoadBalancerCache::select_sticky_from(
            &snapshot,
            NAMESPACE,
            UPSTREAM_ID,
            &v1_token,
            None,
            Some("does-not-exist"),
            None,
        )
        .is_none(),
        "an unknown subset has no candidate pool at all"
    );
}

#[test]
fn sticky_binding_respects_port_lane_scoping() {
    let http = target("10.1.0.10", 8080);
    let grpc = target("10.1.0.11", 9090);
    let mut upstream = sticky_upstream(vec![http.clone(), grpc.clone()]);
    upstream
        .port_overrides
        .insert(8080, UpstreamPortOverride::default());
    upstream
        .port_overrides
        .insert(9090, UpstreamPortOverride::default());
    let cache = cache_for(upstream);
    let snapshot = cache.load();
    let http_token = token_for(NAMESPACE, UPSTREAM_ID, &http);

    let same_lane = LoadBalancerCache::select_sticky_from(
        &snapshot,
        NAMESPACE,
        UPSTREAM_ID,
        &http_token,
        Some(8080),
        None,
        None,
    )
    .expect("token resolves inside its own port lane");
    assert_eq!(same_lane.port, 8080);

    assert!(
        LoadBalancerCache::select_sticky_from(
            &snapshot,
            NAMESPACE,
            UPSTREAM_ID,
            &http_token,
            Some(9090),
            None,
            None,
        )
        .is_none(),
        "an 8080-lane binding must not be dialed on the 9090 lane"
    );
}

#[test]
fn non_cookie_upstreams_build_no_binding_index() {
    // An upstream that cannot mint tokens must not resolve one either, so the
    // index stays empty (and free) outside session-persistence configurations.
    let pinned = target("10.1.0.10", 8080);
    let targets = vec![pinned.clone(), target("10.1.0.11", 8080)];
    let mut upstream = sticky_upstream(targets);
    upstream.hash_on = Some("ip".to_string());
    let cache = cache_for(upstream);

    assert!(
        LoadBalancerCache::select_sticky_from(
            &cache.load(),
            NAMESPACE,
            UPSTREAM_ID,
            &token_for(NAMESPACE, UPSTREAM_ID, &pinned),
            None,
            None,
            None,
        )
        .is_none()
    );
}

#[test]
fn unknown_upstream_identity_never_panics() {
    let pinned = target("10.1.0.10", 8080);
    let cache = cache_for(sticky_upstream(vec![pinned.clone()]));
    assert!(
        LoadBalancerCache::select_sticky_from(
            &cache.load(),
            "no-such-namespace",
            "no-such-upstream",
            &token_for(NAMESPACE, UPSTREAM_ID, &pinned),
            None,
            None,
            None,
        )
        .is_none()
    );
}
