//! Shared H3-eligible retry selection (issue #3620 / PR #3798).
//!
//! The plain H3 bridge and H3 WebSocket retry paths share
//! `select_next_h3_eligible_retry_target`, which must:
//! - exclude the original failed identity;
//! - accumulate every ineligible (Unix) candidate already seen;
//! - terminate deterministically for an all-Unix pool up to
//!   `MAX_TARGETS_PER_UPSTREAM` without cycling;
//! - still reach an eligible target after a long ineligible prefix (>32).

use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use ferrum_edge::config::types::{
    GatewayConfig, LoadBalancerAlgorithm, Proxy, Upstream, UpstreamTarget, MAX_TARGETS_PER_UPSTREAM,
};
use ferrum_edge::proxy::unix_backend::MESH_UNIX_SOCKET_TAG;

const NAMESPACE: &str = "ferrum";
const UPSTREAM_ID: &str = "h3-retry-eligibility-upstream";

fn plain_target(host: &str, port: u16) -> UpstreamTarget {
    UpstreamTarget {
        host: host.to_string(),
        port,
        service_port_policy_key: None,
        weight: 1,
        tags: HashMap::new(),
        locality: None,
        path: None,
    }
}

fn unix_target(idx: usize) -> UpstreamTarget {
    let mut tags = HashMap::new();
    // Distinct socket paths keep sticky identities distinct while remaining
    // H3-ineligible (Unix-tagged hosts are schema placeholders).
    tags.insert(
        MESH_UNIX_SOCKET_TAG.to_string(),
        format!("/run/ferrum/h3-retry-{idx}.sock"),
    );
    UpstreamTarget {
        host: format!("127.0.0.{idx}"),
        port: 1,
        service_port_policy_key: None,
        weight: 1,
        tags,
        locality: None,
        path: None,
    }
}

fn rr_upstream(targets: Vec<UpstreamTarget>) -> Upstream {
    let now = Utc::now();
    Upstream {
        id: UPSTREAM_ID.to_string(),
        namespace: NAMESPACE.to_string(),
        name: Some(UPSTREAM_ID.to_string()),
        targets,
        algorithm: LoadBalancerAlgorithm::RoundRobin,
        hash_on: None,
        hash_on_cookie_config: None,
        health_checks: None,
        service_discovery: None,
        subsets: None,
        port_overrides: HashMap::new(),
        source_locality: None,
        source_labels: HashMap::new(),
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

async fn retry_state_for(upstream: Upstream) -> (ferrum_edge::proxy::ProxyState, Proxy) {
    let proxy_json = serde_json::json!({
        "id": "h3-retry-eligibility-proxy",
        "listen_path": "/retry",
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": 8080,
        "upstream_id": UPSTREAM_ID,
        "namespace": NAMESPACE,
    });
    let mut proxy: Proxy = serde_json::from_value(proxy_json).expect("proxy fixture");
    proxy.namespace = NAMESPACE.to_string();
    let mut config = GatewayConfig {
        upstreams: vec![upstream],
        proxies: vec![proxy],
        ..GatewayConfig::default()
    };
    config.normalize_fields();
    config.resolve_dispatch_port_overrides();
    let proxy = config.proxies[0].clone();
    let dns_cache = ferrum_edge::dns::DnsCache::new(ferrum_edge::dns::DnsConfig::default());
    let env_config = ferrum_edge::config::env_config::EnvConfig::default();
    let (state, _) = ferrum_edge::proxy::ProxyState::new(config, dns_cache, env_config, None, None)
        .expect("test proxy state should build");
    (state, proxy)
}

fn select_h3(
    state: &ferrum_edge::proxy::ProxyState,
    proxy: &Proxy,
    prev: &UpstreamTarget,
) -> Option<Arc<UpstreamTarget>> {
    let epoch = state.request_epoch.load();
    ferrum_edge::_test_support::select_next_h3_eligible_retry_target_for_test(
        state,
        &epoch,
        proxy,
        prev,
        ferrum_edge::_test_support::RetryTargetRequestForTest {
            base_hash_key: "h3-retry-key",
            client_ip: "192.0.2.10",
            proxy_headers: &HashMap::new(),
            request_authority: None,
        },
    )
}

#[tokio::test]
async fn h3_eligible_retry_skips_more_than_32_unix_targets_to_reach_plain() {
    // Previously a hard-coded 32-iteration loop could fail closed before
    // reaching an eligible target beyond that prefix.
    let mut targets = Vec::with_capacity(42);
    let original = plain_target("10.0.0.1", 8080);
    targets.push(original.clone());
    for i in 0..40 {
        targets.push(unix_target(i + 2));
    }
    let eligible = plain_target("10.0.0.99", 8080);
    targets.push(eligible.clone());

    let (state, proxy) = retry_state_for(rr_upstream(targets)).await;
    let next = select_h3(&state, &proxy, &original)
        .expect("eligible plain target after a 40-Unix prefix must be reachable");
    assert!(
        ferrum_edge::_test_support::h3_dispatch_target_eligible_for_test(&next),
        "selected retry target must be H3-eligible"
    );
    assert_eq!(next.host, eligible.host);
    assert_eq!(next.port, eligible.port);
}

#[tokio::test]
async fn h3_eligible_retry_excludes_original_failed_target() {
    let original = plain_target("10.0.0.1", 8080);
    let other = plain_target("10.0.0.2", 8080);
    let (state, proxy) = retry_state_for(rr_upstream(vec![
        original.clone(),
        unix_target(3),
        other.clone(),
    ]))
    .await;

    let next = select_h3(&state, &proxy, &original).expect("another eligible target must remain");
    assert_eq!(next.host, other.host);
    assert_ne!(next.host, original.host);
}

#[tokio::test]
async fn h3_eligible_retry_all_unix_pool_terminates_without_cycle() {
    // Original plain failed identity plus an all-Unix remainder: selection
    // must return None (fail closed) and must not revisit the original.
    let original = plain_target("10.0.0.1", 8080);
    let mut targets = vec![original.clone()];
    for i in 0..48 {
        targets.push(unix_target(i + 2));
    }
    let (state, proxy) = retry_state_for(rr_upstream(targets)).await;

    assert!(
        select_h3(&state, &proxy, &original).is_none(),
        "all-Unix remainder must terminate as None rather than cycling or reselecting the original"
    );
}

#[tokio::test]
async fn h3_eligible_retry_bound_covers_configured_upstream_ceiling() {
    // Guard the bound itself: the helper must be willing to walk past the
    // old 32-iteration cap up to the configured MAX_TARGETS_PER_UPSTREAM.
    assert!(
        MAX_TARGETS_PER_UPSTREAM > 32,
        "regression depends on the configured upstream ceiling exceeding the old hard-coded 32"
    );

    // Keep the fixture smaller than the absolute ceiling for unit-test speed,
    // but still well above 32, with the eligible target last.
    let mut targets = Vec::with_capacity(65);
    let original = plain_target("10.0.0.1", 8080);
    targets.push(original.clone());
    for i in 0..63 {
        targets.push(unix_target(i + 2));
    }
    let eligible = plain_target("10.0.0.200", 8080);
    targets.push(eligible.clone());
    assert!(targets.len() > 32);

    let (state, proxy) = retry_state_for(rr_upstream(targets)).await;
    let next = select_h3(&state, &proxy, &original)
        .expect("eligible target beyond a >32 Unix prefix must still be selected");
    assert_eq!(next.host, eligible.host);
}

#[test]
fn h3_plain_and_ws_retry_share_eligible_helper_not_ad_hoc_loops() {
    let cross = include_str!("../../../src/http3/cross_protocol.rs");
    let ws = include_str!("../../../src/http3/websocket.rs");
    let dispatch = include_str!("../../../src/proxy/backend_dispatch.rs");

    assert!(
        dispatch.contains("pub(crate) fn select_next_h3_eligible_retry_target(")
            && dispatch.contains("pub(crate) fn select_next_eligible_retry_target(")
            && dispatch.contains("MAX_TARGETS_PER_UPSTREAM"),
        "shared eligibility helper must live in backend_dispatch and honour MAX_TARGETS_PER_UPSTREAM"
    );
    assert_eq!(
        cross.matches("select_next_h3_eligible_retry_target(").count(),
        1,
        "cross-protocol must call the shared H3-eligible helper once"
    );
    assert_eq!(
        ws.matches("select_next_h3_eligible_retry_target(").count(),
        1,
        "H3 WebSocket must call the shared H3-eligible helper once"
    );
    assert!(
        !cross.contains("for _ in 0..32") && !ws.contains("for _ in 0..32"),
        "ad-hoc 32-iteration Unix skip loops must not remain in H3 retry paths"
    );
}
