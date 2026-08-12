//! Shared H3-eligible retry selection (issue #3620 / PR #3798).
//!
//! The plain H3 bridge and H3 WebSocket retry paths share
//! `select_next_h3_eligible_retry_target`, which must:
//! - exclude the original failed identity;
//! - drop every ineligible (Unix) pool entry inside the SAME load-balancer
//!   selection pass that builds the candidate lane — one bounded scan, no
//!   repeated probing and no per-probe allocation;
//! - fail closed (`None`) for an all-Unix remainder;
//! - still reach an eligible target behind a long ineligible prefix, on both
//!   the bitset lane (<= 128 targets) and the Vec fallback lane (> 128).

use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use ferrum_edge::config::types::{
    GatewayConfig, LoadBalancerAlgorithm, Proxy, Upstream, UpstreamTarget,
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
async fn h3_eligible_retry_applies_eligibility_on_the_vec_fallback_lane() {
    // Above MAX_BITSET_TARGETS (128) the load balancer takes its Vec fallback
    // lane. Eligibility must be applied there too, in the same single pass.
    let mut targets = Vec::with_capacity(160);
    let original = plain_target("10.0.0.1", 8080);
    targets.push(original.clone());
    for i in 0..150 {
        targets.push(unix_target(i + 2));
    }
    let eligible = plain_target("10.0.0.200", 8080);
    targets.push(eligible.clone());
    assert!(targets.len() > 128, "fixture must exceed the bitset lane");

    let (state, proxy) = retry_state_for(rr_upstream(targets)).await;
    let next = select_h3(&state, &proxy, &original)
        .expect("eligible target behind a 150-Unix prefix must still be selected");
    assert_eq!(next.host, eligible.host);
}

#[tokio::test]
async fn h3_eligible_retry_all_unix_pool_terminates_on_the_vec_fallback_lane() {
    let original = plain_target("10.0.0.1", 8080);
    let mut targets = vec![original.clone()];
    for i in 0..150 {
        targets.push(unix_target(i + 2));
    }
    assert!(targets.len() > 128, "fixture must exceed the bitset lane");

    let (state, proxy) = retry_state_for(rr_upstream(targets)).await;
    assert!(
        select_h3(&state, &proxy, &original).is_none(),
        "an all-Unix remainder must fail closed on the Vec fallback lane too"
    );
}

#[test]
fn every_h3_retry_surface_shares_eligible_helper_not_ad_hoc_loops() {
    let cross = include_str!("../../../src/http3/cross_protocol.rs");
    let ws = include_str!("../../../src/http3/websocket.rs");
    let server = include_str!("../../../src/http3/server.rs");
    let dispatch = include_str!("../../../src/proxy/backend_dispatch.rs");

    assert!(
        dispatch.contains("pub(crate) fn select_next_h3_eligible_retry_target(")
            && dispatch.contains("pub(crate) fn select_next_eligible_retry_target("),
        "shared eligibility helper must live in backend_dispatch"
    );
    assert_eq!(
        cross
            .matches("select_next_h3_eligible_retry_target(")
            .count(),
        1,
        "cross-protocol must call the shared H3-eligible helper once"
    );
    assert_eq!(
        ws.matches("select_next_h3_eligible_retry_target(").count(),
        1,
        "H3 WebSocket must call the shared H3-eligible helper once"
    );
    assert_eq!(
        server
            .matches("select_next_h3_eligible_retry_target(")
            .count(),
        1,
        "native buffered H3 retry must call the shared H3-eligible helper once"
    );
    assert!(
        !cross.contains("for _ in 0..32")
            && !ws.contains("for _ in 0..32")
            && !server.contains("for _ in 0..32"),
        "ad-hoc 32-iteration Unix skip loops must not remain in H3 retry paths"
    );

    // WebSocket caller must map helper None to the abort flag (fail closed),
    // not silently skip an `if let Some(...)` and retry the original target.
    let ws_retry = ws
        .split("let mut retry_backend_url = current_backend_url.clone();")
        .nth(1)
        .expect("H3 WebSocket retry staging")
        .split("\"Retrying H3 WebSocket backend connection\"")
        .next()
        .expect("bounded H3 WebSocket retry block");
    assert!(
        ws_retry.contains("None =>")
            && ws_retry.contains("retry_path_mismatch = true")
            && ws_retry
                .contains("\"Aborting H3 WebSocket retry: no H3-eligible candidate remains\""),
        "H3 WebSocket must abort when select_next_h3_eligible_retry_target returns None"
    );

    // Cross-protocol keeps established Unchanged-on-None caller semantics:
    // selection returns Unchanged; abort variants remain path/budget only.
    assert!(
        cross.contains(") else {\n        return CrossProtocolRetryTarget::Unchanged;\n    };"),
        "cross-protocol must keep mapping helper None to Unchanged"
    );
}

/// Hot-path shape guard: eligibility is a load-balancer input, not an outer
/// retry loop.
///
/// The rejected design re-ran the full retry selection once per ineligible
/// target with a growing exclusion slice. With `MAX_TARGETS_PER_UPSTREAM`
/// (1,000) configured targets that is hundreds of millions of comparisons plus
/// one temporary `Vec` per probe on a request/retry path, and it also forced
/// the ordinary single-exclusion retry to build a heap `Vec` of capacity one.
#[test]
fn eligibility_is_pushed_into_selection_not_an_outer_probe_loop() {
    let dispatch = include_str!("../../../src/proxy/backend_dispatch.rs");
    let lb = include_str!("../../../src/load_balancer.rs");

    // The eligibility predicate must reach the load balancer as part of the
    // retry candidate filter.
    assert!(
        dispatch.contains("RetryCandidateFilter::excluding_eligible(primary_exclude, eligible)"),
        "the eligibility predicate must be handed to the LB candidate filter"
    );
    assert!(
        lb.contains("pub struct RetryCandidateFilter<'a>")
            && lb.contains("fn rejects(&self, target: &UpstreamTarget"),
        "load_balancer must own the combined exclusion + eligibility candidate test"
    );

    // Every retry selection lane (upstream, per-port, subset, per-port × subset,
    // plus their >128-target Vec fallbacks) must consult that one filter while
    // building its candidate lane. Eight sites: four bitset `clear_retry_exclusions`
    // calls and four `filter.rejects(...)` fallback filters.
    assert_eq!(
        lb.matches("clear_retry_exclusions(&self.targets, filter,").count(),
        4,
        "all four bitset retry lanes must clear via the shared candidate filter"
    );
    assert_eq!(
        lb.matches("!filter.rejects(&self.targets[idx]").count(),
        4,
        "all four Vec-fallback retry lanes must filter via the shared candidate filter"
    );

    // No outer probe loop and no accumulated exclusion set may return.
    let helper = dispatch
        .split("pub(crate) fn select_next_eligible_retry_target(")
        .nth(1)
        .expect("shared eligibility helper")
        .split("\n/// H3-eligible variant of")
        .next()
        .expect("helper body ends before the H3 variant");
    assert!(
        !helper.contains("for ") && !helper.contains("while ") && !helper.contains("loop "),
        "the eligibility helper must not re-run selection in a loop: {helper}"
    );
    assert!(
        !helper.contains("Vec::") && !helper.contains("Arc::clone"),
        "the eligibility helper must not allocate or retain per-candidate state: {helper}"
    );
    assert!(
        !dispatch.contains("seen_ineligible") && !dispatch.contains("additional_excludes"),
        "the accumulating growing-exclusion retry design must not return"
    );

    // The ordinary single-exclusion retry path must stay heap-free.
    let ordinary = dispatch
        .split("fn select_next_retry_target_filtered(")
        .nth(1)
        .expect("shared retry selection body")
        .split("\n/// Select the next retry dial target")
        .next()
        .expect("body ends before the eligibility helper");
    assert!(
        !ordinary.contains("Vec::with_capacity") && !ordinary.contains("Vec<&UpstreamTarget>"),
        "shared retry selection must not build an exclusion Vec: {ordinary}"
    );
}
