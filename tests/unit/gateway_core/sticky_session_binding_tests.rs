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
    GatewayConfig, LoadBalancerAlgorithm, Proxy, SubsetDefinition, Upstream, UpstreamPortOverride,
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

// ---------------------------------------------------------------------------
// Retry-rotation reissue (root review finding 1)
// ---------------------------------------------------------------------------
//
// Selection decides "does this response need a cookie?" BEFORE any backend is
// dialed, so an honored binding carries `false`. Every retry-capable dispatch
// path (H1/H2, direct gRPC, WebSocket incl. H2 extended CONNECT, native H3, the
// H3→HTTP and H3→gRPC cross-protocol bridges, H3 WebSocket) can then rotate off
// that target. Carrying the stale `false` through to response-cookie injection
// leaves the client pinned to the backend that just failed — retry rotation
// does not necessarily eject it. These pin the shared derivation every one of
// those paths now routes through.

/// Two distinct `UpstreamTarget` values for the same endpoint, so the assertion
/// cannot pass merely because both sides are the same allocation.
fn distinct_clone(t: &UpstreamTarget) -> UpstreamTarget {
    target(&t.host, t.port)
}

#[test]
fn honored_binding_that_served_its_own_backend_is_not_reissued() {
    let bound = target("10.1.0.10", 8080);
    let served = distinct_clone(&bound);

    assert!(
        ferrum_edge::_test_support::sticky_cookie_reissue_target_for_test(
            false,
            Some(&bound),
            Some(&served),
        )
        .is_none(),
        "a binding honored end-to-end must not re-mint the identical token"
    );
}

#[test]
fn honored_binding_reissues_for_the_backend_a_retry_rotated_onto() {
    let bound = target("10.1.0.10", 8080);
    let rotated = target("10.1.0.11", 8080);

    let reissue = ferrum_edge::_test_support::sticky_cookie_reissue_target_for_test(
        // Selection honored the presented cookie: `false` at selection time.
        false,
        Some(&bound),
        // Retry then rotated; this is the backend that produced the response.
        Some(&rotated),
    )
    .expect("a rotation off the bound backend must reissue");
    assert_eq!((reissue.host.as_str(), reissue.port), ("10.1.0.11", 8080));

    // ... and the token that reissue mints resolves back to that same backend,
    // so the client's NEXT request lands there instead of on the failed one.
    let cache = cache_for(sticky_upstream(vec![bound.clone(), rotated.clone()]));
    let next = LoadBalancerCache::select_sticky_from(
        &cache.load(),
        NAMESPACE,
        UPSTREAM_ID,
        &token_for(NAMESPACE, UPSTREAM_ID, reissue),
        None,
        None,
        None,
    )
    .expect("the reissued token must resolve");
    assert_eq!(next.host, rotated.host);
    assert_eq!(next.port, rotated.port);
    assert!(
        next.host != bound.host || next.port != bound.port,
        "the reissued binding must not point back at the rotated-away backend"
    );
}

#[test]
fn a_rotation_that_only_changed_ports_still_reissues() {
    // Affinity identity is `host:port`: the same host on a different port is a
    // different endpoint and a different token.
    let bound = target("10.1.0.10", 8080);
    let rotated = target("10.1.0.10", 9090);

    let reissue = ferrum_edge::_test_support::sticky_cookie_reissue_target_for_test(
        false,
        Some(&bound),
        Some(&rotated),
    )
    .expect("a port rotation is still a different backend");
    assert_eq!(reissue.port, 9090);
    assert_ne!(
        token_for(NAMESPACE, UPSTREAM_ID, &bound),
        token_for(NAMESPACE, UPSTREAM_ID, &rotated),
    );
}

#[test]
fn a_first_ever_request_always_mints_for_the_backend_that_served_it() {
    let selected = target("10.1.0.10", 8080);
    let rotated = target("10.1.0.11", 8080);

    for served in [&selected, &rotated] {
        let reissue = ferrum_edge::_test_support::sticky_cookie_reissue_target_for_test(
            true,
            Some(&selected),
            Some(served),
        )
        .expect("a request with no usable binding always mints one");
        assert_eq!(reissue.host, served.host);
        assert_eq!(reissue.port, served.port);
    }
}

#[test]
fn a_response_no_backend_served_never_claims_a_binding() {
    // Gateway-synthesized refusals (mesh-transport / egress screens on a
    // ROTATED candidate that was never dialed, or no target at all) pass
    // `None`: a rejected response must not pin the client to a backend that
    // did not serve it — least of all one the gateway refuses to dial.
    let selected = target("10.1.0.10", 8080);
    for needs_set in [false, true] {
        assert!(
            ferrum_edge::_test_support::sticky_cookie_reissue_target_for_test(
                needs_set,
                Some(&selected),
                None,
            )
            .is_none()
        );
    }
}

// ---------------------------------------------------------------------------
// Selected-port policy precedence for a resolved binding (root review finding 2)
// ---------------------------------------------------------------------------
//
// The binding lookup runs before the target is known, so it is validated
// against the INITIAL dispatch port's lane. When that port carries no per-port
// override the candidate pool is the whole upstream, so a resolved target can
// sit in a DIFFERENT `dispatch_policy_port()` lane whose effective algorithm is
// not consistent hashing, or whose `hashOn` names a different cookie. Honoring
// a binding there would reach past the per-port policy that actually governs
// the target. `resolve_sticky_binding` fails closed to ordinary selection and a
// fresh binding instead.

const COOKIE_NAME: &str = "lb-affinity-fe-0123456789abcdef";

/// Production-shaped `(cache, proxy)` pair: `resolve_dispatch_port_overrides`
/// projects the upstream's `port_overrides` onto the proxy exactly as config
/// resolution does, so `has_effective_port_override` sees what it sees at
/// runtime.
fn resolved_fixture(
    upstream: Upstream,
    proxy_backend_port: u16,
    subset: Option<&str>,
) -> (LoadBalancerCache, Proxy) {
    let proxy_json = serde_json::json!({
        "id": "sticky-proxy",
        "listen_path": "/sticky",
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": proxy_backend_port,
        "upstream_id": UPSTREAM_ID,
    });
    let mut proxy: Proxy = serde_json::from_value(proxy_json).expect("proxy fixture");
    proxy.namespace = NAMESPACE.to_string();
    proxy.upstream_subset = subset.map(str::to_string);

    let mut config = GatewayConfig {
        upstreams: vec![upstream],
        proxies: vec![proxy],
        ..GatewayConfig::default()
    };
    config.resolve_dispatch_port_overrides();
    let proxy = config.proxies[0].clone();
    (LoadBalancerCache::new(&config), proxy)
}

fn port_override(
    algorithm: Option<LoadBalancerAlgorithm>,
    hash_on: Option<&str>,
) -> UpstreamPortOverride {
    UpstreamPortOverride {
        algorithm,
        hash_on: hash_on.map(str::to_string),
        ..UpstreamPortOverride::default()
    }
}

#[test]
fn binding_fails_closed_when_the_targets_port_lane_is_not_cookie_hashing() {
    // Initial dispatch port 8080 has no override, so the raw binding index
    // spans the whole upstream — but 9090 is a round-robin lane.
    let http = target("10.1.0.10", 8080);
    let other_lane = target("10.1.0.11", 9090);
    let mut upstream = sticky_upstream(vec![http.clone(), other_lane.clone()]);
    upstream.port_overrides.insert(
        9090,
        port_override(Some(LoadBalancerAlgorithm::RoundRobin), None),
    );
    let (cache, proxy) = resolved_fixture(upstream, 8080, None);
    let snapshot = cache.load();
    let token = token_for(NAMESPACE, UPSTREAM_ID, &other_lane);

    // The raw index alone WOULD hand back the cross-lane target: the guard is
    // load-bearing, not a restatement of `select_sticky`'s own scoping.
    assert!(
        LoadBalancerCache::select_sticky_from(
            &snapshot,
            NAMESPACE,
            UPSTREAM_ID,
            &token,
            None,
            None,
            None,
        )
        .is_some(),
        "fixture must actually exercise the cross-lane case"
    );
    assert!(
        ferrum_edge::_test_support::resolve_sticky_binding_for_test(
            &proxy,
            &snapshot,
            UPSTREAM_ID,
            &token,
            COOKIE_NAME,
            None,
            None,
        )
        .is_none(),
        "a round-robin port lane must not honor a session-persistence binding"
    );

    // A binding inside the un-overridden lane the lookup was validated against
    // is still honored, so the guard is not simply refusing everything.
    let same_lane = ferrum_edge::_test_support::resolve_sticky_binding_for_test(
        &proxy,
        &snapshot,
        UPSTREAM_ID,
        &token_for(NAMESPACE, UPSTREAM_ID, &http),
        COOKIE_NAME,
        None,
        None,
    )
    .expect("same-lane binding stays honored");
    assert_eq!(same_lane.port, 8080);
}

#[test]
fn binding_fails_closed_when_the_targets_port_lane_names_another_cookie() {
    let http = target("10.1.0.10", 8080);
    let other_lane = target("10.1.0.11", 9090);
    let mut upstream = sticky_upstream(vec![http, other_lane.clone()]);
    upstream.port_overrides.insert(
        9090,
        port_override(
            Some(LoadBalancerAlgorithm::ConsistentHashing),
            Some("cookie:some-other-session"),
        ),
    );
    let (cache, proxy) = resolved_fixture(upstream, 8080, None);

    assert!(
        ferrum_edge::_test_support::resolve_sticky_binding_for_test(
            &proxy,
            &cache.load(),
            UPSTREAM_ID,
            &token_for(NAMESPACE, UPSTREAM_ID, &other_lane),
            COOKIE_NAME,
            None,
            None,
        )
        .is_none(),
        "a lane keyed on a different cookie must not honor this cookie's binding"
    );
}

#[test]
fn binding_is_honored_when_the_targets_port_lane_keeps_the_same_cookie() {
    let http = target("10.1.0.10", 8080);
    let other_lane = target("10.1.0.11", 9090);
    let mut upstream = sticky_upstream(vec![http, other_lane.clone()]);
    upstream.port_overrides.insert(
        9090,
        port_override(
            Some(LoadBalancerAlgorithm::ConsistentHashing),
            Some(&format!("cookie:{COOKIE_NAME}")),
        ),
    );
    let (cache, proxy) = resolved_fixture(upstream, 8080, None);

    let bound = ferrum_edge::_test_support::resolve_sticky_binding_for_test(
        &proxy,
        &cache.load(),
        UPSTREAM_ID,
        &token_for(NAMESPACE, UPSTREAM_ID, &other_lane),
        COOKIE_NAME,
        None,
        None,
    )
    .expect("an equivalent cookie lane keeps the session");
    assert_eq!(bound.port, 9090);
}

#[test]
fn port_lane_precedence_composes_with_subset_scoping() {
    // The subset dimension keeps its own scoping under the port guard: an
    // in-lane, in-subset binding is honored; the same target outside the
    // selected subset is not, and neither is a cross-lane one.
    let v1 = tagged_target("10.1.0.10", 8080, &[("version", "v1")]);
    let v2 = tagged_target("10.1.0.11", 9090, &[("version", "v2")]);
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
    upstream.port_overrides.insert(
        9090,
        port_override(Some(LoadBalancerAlgorithm::RoundRobin), None),
    );
    let (cache, proxy) = resolved_fixture(upstream, 8080, Some("v1"));
    let snapshot = cache.load();

    assert!(
        ferrum_edge::_test_support::resolve_sticky_binding_for_test(
            &proxy,
            &snapshot,
            UPSTREAM_ID,
            &token_for(NAMESPACE, UPSTREAM_ID, &v1),
            COOKIE_NAME,
            None,
            Some("v1"),
        )
        .is_some(),
        "an in-subset, in-lane binding stays honored"
    );
    assert!(
        ferrum_edge::_test_support::resolve_sticky_binding_for_test(
            &proxy,
            &snapshot,
            UPSTREAM_ID,
            &token_for(NAMESPACE, UPSTREAM_ID, &v2),
            COOKIE_NAME,
            None,
            Some("v1"),
        )
        .is_none(),
        "subset scoping still rejects a foreign-subset binding"
    );
}

// ---------------------------------------------------------------------------
// The shared mint site — and with it the fully-streaming native-gRPC fast path
// ---------------------------------------------------------------------------
//
// The direct H1/H2 native-gRPC dispatch has two response arms. The BUFFERED arm
// minted the affinity cookie; the FULLY-STREAMING arm committed its HEADERS
// frame and returned first, so a GRPCRoute with no response-body-buffering
// plugin and no retry selected a backend and never issued the initial cookie —
// session persistence silently did nothing for exactly the RPC shape gRPC is
// used for. Both arms now write through the one shared mint site exercised here,
// composed the same way the call sites compose it.

/// Mint exactly as the streaming native-gRPC fast path does: derive the reissue
/// target from the post-dispatch derivation, then hand it (and nothing else) to
/// the shared mint site.
fn mint_like_a_grpc_dispatch_arm(
    proxy: &Proxy,
    balancers: &ferrum_edge::load_balancer::LoadBalancerCacheInner,
    selection_needs_set: bool,
    selected: Option<&UpstreamTarget>,
    served: Option<&UpstreamTarget>,
    response_headers: &mut HashMap<String, String>,
) -> bool {
    let reissue_target = ferrum_edge::_test_support::sticky_cookie_reissue_target_for_test(
        selection_needs_set,
        selected,
        served,
    );
    ferrum_edge::_test_support::inject_sticky_affinity_cookie_for_test(
        proxy,
        balancers,
        reissue_target,
        reissue_target.is_some(),
        response_headers,
    )
}

/// The `Set-Cookie` line the production builder emits for `target`.
fn expected_affinity_cookie(target: &UpstreamTarget) -> String {
    ferrum_edge::_test_support::build_sticky_cookie_header_for_test(
        COOKIE_NAME,
        NAMESPACE,
        UPSTREAM_ID,
        target,
        &ferrum_edge::config::types::HashOnCookieConfig::default(),
    )
}

#[test]
fn a_streaming_dispatch_mints_the_initial_affinity_cookie() {
    // No usable cookie was presented, so selection asked for a fresh binding and
    // the streaming response owes the client one. On 0e9f3c31 this arm wrote
    // nothing at all.
    let served = target("10.1.0.10", 8080);
    let upstream = sticky_upstream(vec![served.clone(), target("10.1.0.11", 8080)]);
    let (cache, proxy) = resolved_fixture(upstream, 8080, None);
    let snapshot = cache.load();

    let mut response_headers: HashMap<String, String> = HashMap::new();
    assert!(
        mint_like_a_grpc_dispatch_arm(
            &proxy,
            &snapshot,
            true,
            Some(&served),
            Some(&served),
            &mut response_headers,
        ),
        "a first-ever streaming gRPC response must issue the affinity cookie"
    );
    assert_eq!(
        response_headers.get("set-cookie"),
        Some(&expected_affinity_cookie(&served)),
        "the minted cookie must name the backend that produced the response"
    );

    // End-to-end: the emitted cookie is the token that steers the NEXT request
    // back to this exact backend, so the mint is usable and not merely present.
    let minted_value = response_headers["set-cookie"]
        .split(';')
        .next()
        .and_then(|pair| pair.split_once('='))
        .map(|(_, value)| value.to_string())
        .expect("minted Set-Cookie carries a name=value pair");
    let rebound = ferrum_edge::_test_support::resolve_sticky_binding_for_test(
        &proxy,
        &snapshot,
        UPSTREAM_ID,
        &minted_value,
        COOKIE_NAME,
        None,
        None,
    )
    .expect("the minted token must resolve back to a backend");
    assert_eq!((rebound.host.as_str(), rebound.port), ("10.1.0.10", 8080));
}

#[test]
fn a_streaming_dispatch_does_not_reissue_an_honored_binding() {
    // The client presented a valid cookie, selection honored it, and no retry
    // rotated: re-minting the identical token would be pure wire noise, and a
    // reissue here is how a "mint on every response" regression would show up.
    let served = target("10.1.0.10", 8080);
    let bound = distinct_clone(&served);
    let upstream = sticky_upstream(vec![served.clone(), target("10.1.0.11", 8080)]);
    let (cache, proxy) = resolved_fixture(upstream, 8080, None);
    let snapshot = cache.load();

    let mut response_headers: HashMap<String, String> = HashMap::new();
    assert!(
        !mint_like_a_grpc_dispatch_arm(
            &proxy,
            &snapshot,
            false,
            Some(&bound),
            Some(&served),
            &mut response_headers,
        ),
        "an honored binding that served its own backend must not be re-issued"
    );
    assert!(
        !response_headers.contains_key("set-cookie"),
        "no gateway cookie may be written when the binding was honored"
    );
}

#[test]
fn a_streaming_dispatch_appends_beside_a_backend_set_cookie() {
    // RFC 6265 forbids folding Set-Cookie into one value; the proxy keeps the
    // lines newline-separated and every response builder splits them back out.
    // A backend cookie must survive the affinity append untouched.
    let served = target("10.1.0.10", 8080);
    let upstream = sticky_upstream(vec![served.clone()]);
    let (cache, proxy) = resolved_fixture(upstream, 8080, None);
    let snapshot = cache.load();

    let mut response_headers: HashMap<String, String> = HashMap::new();
    response_headers.insert(
        "set-cookie".to_string(),
        "backend_session=abc; Path=/".to_string(),
    );
    assert!(mint_like_a_grpc_dispatch_arm(
        &proxy,
        &snapshot,
        true,
        Some(&served),
        Some(&served),
        &mut response_headers,
    ));

    let expected = expected_affinity_cookie(&served);
    let lines: Vec<&str> = response_headers["set-cookie"].split('\n').collect();
    assert_eq!(
        lines,
        vec!["backend_session=abc; Path=/", expected.as_str()],
        "the affinity cookie is appended as its own line, leaving the backend's intact"
    );
}

#[test]
fn a_streaming_dispatch_writes_nothing_for_a_non_cookie_lane() {
    // The served target's OWN per-port policy lane decides the mint. A rotation
    // (or an upstream whose landing lane is round-robin) must not hand the
    // client a token that lane would never honor.
    let cookie_lane = target("10.1.0.10", 8080);
    let round_robin_lane = target("10.1.0.11", 9090);
    let mut upstream = sticky_upstream(vec![cookie_lane.clone(), round_robin_lane.clone()]);
    upstream.port_overrides.insert(
        9090,
        port_override(Some(LoadBalancerAlgorithm::RoundRobin), None),
    );
    let (cache, proxy) = resolved_fixture(upstream, 8080, None);
    let snapshot = cache.load();

    let mut response_headers: HashMap<String, String> = HashMap::new();
    assert!(
        !mint_like_a_grpc_dispatch_arm(
            &proxy,
            &snapshot,
            true,
            Some(&round_robin_lane),
            Some(&round_robin_lane),
            &mut response_headers,
        ),
        "a non-cookie landing lane must not mint an affinity cookie"
    );
    assert!(response_headers.is_empty());
}

#[test]
fn a_streaming_dispatch_that_served_nothing_never_pins_a_client() {
    // A gateway-synthesized refusal that dialed no backend passes `None`, and a
    // route with no upstream has no binding scope at all. Neither may write.
    let served = target("10.1.0.10", 8080);
    let upstream = sticky_upstream(vec![served.clone()]);
    let (cache, mut proxy) = resolved_fixture(upstream, 8080, None);
    let snapshot = cache.load();

    let mut response_headers: HashMap<String, String> = HashMap::new();
    assert!(!mint_like_a_grpc_dispatch_arm(
        &proxy,
        &snapshot,
        true,
        Some(&served),
        None,
        &mut response_headers,
    ));
    assert!(response_headers.is_empty());

    proxy.upstream_id = None;
    assert!(!mint_like_a_grpc_dispatch_arm(
        &proxy,
        &snapshot,
        true,
        Some(&served),
        Some(&served),
        &mut response_headers,
    ));
    assert!(response_headers.is_empty());
}

// ---------------------------------------------------------------------------
// Anti-drift: every mint site routes through the shared derivation
// ---------------------------------------------------------------------------

#[test]
fn every_retry_capable_mint_site_uses_the_shared_reissue_derivation() {
    // The defect this guards is copy-paste drift: a response path that mints
    // from the immutable selection-time flag instead of the post-dispatch
    // derivation silently pins clients to rotated-away backends again. Each
    // dispatch file that can rotate targets must reference the shared
    // derivation, and the mint-site count is locked so a NEW site cannot be
    // added without revisiting this contract.
    let proxy_src = include_str!("../../../src/proxy/mod.rs");
    let h3_server_src = include_str!("../../../src/http3/server.rs");
    let h3_cross_src = include_str!("../../../src/http3/cross_protocol.rs");
    let h3_ws_src = include_str!("../../../src/http3/websocket.rs");

    for (label, source) in [
        ("proxy/mod.rs", proxy_src),
        ("http3/server.rs", h3_server_src),
        ("http3/cross_protocol.rs", h3_cross_src),
        ("http3/websocket.rs", h3_ws_src),
    ] {
        assert!(
            source.contains("sticky_cookie_reissue_target("),
            "{label} owns a retry-capable sticky dispatch path and must derive \
             the reissue decision from \
             backend_dispatch::sticky_cookie_reissue_target"
        );
    }

    // `build_sticky_cookie_header` is reached from exactly ONE place: the shared
    // `inject_sticky_affinity_cookie` mint site in proxy/mod.rs. So proxy/mod.rs
    // holds 1 definition + that 1 call, and every other dispatch file holds
    // none — the H1/H2, gRPC (buffered AND fully-streaming), WebSocket, and H3
    // paths all append through the shared site. A new count here means a path
    // grew its own copy, which is how the streaming gRPC arm came to omit the
    // cookie entirely.
    let mint_sites = |src: &str| src.matches("build_sticky_cookie_header(").count();
    assert_eq!(mint_sites(proxy_src), 2);
    assert_eq!(mint_sites(h3_server_src), 0);
    assert_eq!(mint_sites(h3_ws_src), 0);
    assert_eq!(mint_sites(h3_cross_src), 0);
}

#[test]
fn both_direct_grpc_response_arms_inject_the_affinity_cookie() {
    // The regression this locks: the direct H1/H2 native-gRPC dispatch returns
    // its FULLY-STREAMING response from its own match arm, ahead of the buffered
    // arm's injection. An arm that stops calling the shared mint site ships a
    // GRPCRoute that selects a backend and never binds the client to it.
    let proxy_src = include_str!("../../../src/proxy/mod.rs");

    let streaming_arm = proxy_src
        .split_once("Ok(GrpcResponseKind::Streaming(grpc_streaming)) => {")
        .expect("direct gRPC dispatch keeps a fully-streaming response arm")
        .1;
    let (streaming_arm, buffered_arm) = streaming_arm
        .split_once("Ok(GrpcResponseKind::Buffered(grpc_resp)) => {")
        .expect("direct gRPC dispatch keeps a buffered response arm");
    // Bound the buffered arm at the sibling `Err` arm of the same match;
    // otherwise the slice runs to end-of-file and the plain H1/H2 mint site
    // would satisfy the assertion for it.
    let buffered_arm = buffered_arm
        .split_once("\n            Err(e) => {")
        .expect("direct gRPC dispatch keeps an error arm after the buffered arm")
        .0;

    for (label, arm) in [
        ("fully-streaming", streaming_arm),
        ("buffered", buffered_arm),
    ] {
        assert!(
            arm.contains("inject_sticky_affinity_cookie_with_deadline_provenance("),
            "the direct gRPC {label} response arm must inject the sticky-affinity \
             cookie through the shared mint site before its headers are committed"
        );
    }
}
