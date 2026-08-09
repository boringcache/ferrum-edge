//! Runtime behavior of the declarative per-instance execution trigger, through
//! the real `PluginCache` publication path.
//!
//! Covers: absent-trigger parity, request/stream gating, decide-once
//! memoization, phase safety at the authentication boundary, no-work and
//! no-buffering on skip, global/proxy scopes, multiple instances, priority and
//! ordering preservation, reload/publication, and the fail-closed composition
//! refusals.
//!
//! The pure schema/compilation layer lives in
//! `tests/unit/config/plugin_trigger_tests.rs`.

use chrono::Utc;
use ferrum_edge::PluginCache;
use ferrum_edge::_test_support::set_request_wire_protocol_for_test;
use ferrum_edge::config::types::{
    BackendScheme, DispatchKind, GatewayConfig, HttpWireTransport, PluginConfig, PluginScope, Proxy,
};
use ferrum_edge::consumer_index::ConsumerIndex;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext, StreamConnectionContext};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

use super::{make_plugin_config_with_json, make_proxy, minimal_plugin_config};

const NS: &str = "ferrum";

/// A `request_transformer` instance whose only observable effect is adding one
/// request header in `before_proxy` — a precise probe for "did this instance
/// run at all".
fn header_stamper(
    id: &str,
    scope: PluginScope,
    proxy_id: Option<&str>,
    header: &str,
) -> PluginConfig {
    make_plugin_config_with_json(
        id,
        "request_transformer",
        json!({"rules": [{
            "operation": "add", "target": "header", "key": header, "value": "1"
        }]}),
        scope,
        proxy_id,
    )
}

fn builtin(id: &str, plugin_name: &str, proxy_id: &str) -> PluginConfig {
    make_plugin_config_with_json(
        id,
        plugin_name,
        minimal_plugin_config(plugin_name),
        PluginScope::Proxy,
        Some(proxy_id),
    )
}

fn with_trigger(mut pc: PluginConfig, trigger: serde_json::Value) -> PluginConfig {
    pc.trigger = Some(serde_json::from_value(trigger).expect("trigger parses"));
    pc
}

fn stream_proxy(id: &str, scheme: BackendScheme, port: u16, plugin_ids: Vec<&str>) -> Proxy {
    let mut proxy = make_proxy(id, "/unused", plugin_ids);
    proxy.listen_path = None;
    proxy.listen_port = Some(port);
    proxy.backend_scheme = Some(scheme);
    proxy.dispatch_kind = DispatchKind::from(scheme);
    proxy
}

fn config(proxies: Vec<Proxy>, plugin_configs: Vec<PluginConfig>) -> GatewayConfig {
    GatewayConfig {
        version: "1".to_string(),
        proxies,
        plugin_configs,
        loaded_at: Utc::now(),
        ..Default::default()
    }
}

fn request(method: &str, path: &str) -> RequestContext {
    request_from(method, path, "10.1.2.3", HttpWireTransport::Http2)
}

/// A request carrying the representation a JSON body policy actually governs,
/// so "would this instance buffer" is a real question rather than a vacuous no.
fn json_request(method: &str, path: &str) -> RequestContext {
    let mut ctx = request(method, path);
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx
}

fn request_from(
    method: &str,
    path: &str,
    client_ip: &str,
    transport: HttpWireTransport,
) -> RequestContext {
    let mut ctx =
        RequestContext::new(client_ip.to_string(), method.to_string(), path.to_string());
    set_request_wire_protocol_for_test(&mut ctx, transport, false);
    ctx
}

/// Run the whole published chain's `on_request_received` then `before_proxy`,
/// exactly as the dispatchers do, and return the resulting header map.
async fn run_request(
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
) -> HashMap<String, String> {
    for plugin in plugins {
        plugin.on_request_received(ctx).await;
    }
    let mut headers = HashMap::new();
    for plugin in plugins {
        plugin.before_proxy(ctx, &mut headers).await;
    }
    headers
}

fn published(config: &GatewayConfig, proxy_id: &str) -> Vec<Arc<dyn Plugin>> {
    let cache = PluginCache::new(config).expect("plugin cache builds");
    cache.get_plugins(NS, proxy_id).as_ref().clone()
}

// ---------------------------------------------------------------------------
// Absent trigger preserves existing behavior
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_absent_trigger_leaves_the_instance_running_for_every_request() {
    let plugins = published(
        &config(
            vec![make_proxy("api", "/api", vec!["stamp"])],
            vec![header_stamper(
                "stamp",
                PluginScope::Proxy,
                Some("api"),
                "x-stamp",
            )],
        ),
        "api",
    );

    for (method, path) in [("GET", "/api/health"), ("POST", "/api/orders")] {
        let mut ctx = request(method, path);
        let headers = run_request(&plugins, &mut ctx).await;
        assert_eq!(headers.get("x-stamp").map(String::as_str), Some("1"));
        assert!(
            !ctx.metadata
                .keys()
                .any(|key| key.starts_with("plugin_trigger.")),
            "an untriggered instance must not record trigger metadata"
        );
    }
}

// ---------------------------------------------------------------------------
// Request gating
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_matching_trigger_runs_the_instance_and_a_non_matching_one_skips_it() {
    let gated = with_trigger(
        header_stamper("stamp", PluginScope::Proxy, Some("api"), "x-stamp"),
        json!({"when": {"all": [
            {"match": {"method": ["POST", "PUT"]}},
            {"match": {"path": {"prefix": ["/api/orders"]}}}
        ]}}),
    );
    let plugins = published(
        &config(vec![make_proxy("api", "/api", vec!["stamp"])], vec![gated]),
        "api",
    );

    let mut hit = request("POST", "/api/orders/42");
    assert_eq!(
        run_request(&plugins, &mut hit)
            .await
            .get("x-stamp")
            .map(String::as_str),
        Some("1")
    );
    assert!(!hit.metadata.contains_key("plugin_trigger.stamp.skipped"));

    let mut method_miss = request("GET", "/api/orders/42");
    assert!(run_request(&plugins, &mut method_miss).await.is_empty());
    assert_eq!(
        method_miss
            .metadata
            .get("plugin_trigger.stamp.skipped")
            .map(String::as_str),
        Some("true"),
        "a skip records exactly one bounded, redacted metadata pair"
    );

    let mut path_miss = request("POST", "/api/health");
    assert!(run_request(&plugins, &mut path_miss).await.is_empty());
}

#[tokio::test]
async fn header_query_and_cookie_predicates_read_the_live_request() {
    let plugins = published(
        &config(
            vec![make_proxy("api", "/api", vec!["stamp"])],
            vec![with_trigger(
                header_stamper("stamp", PluginScope::Proxy, Some("api"), "x-stamp"),
                json!({"when": {"any": [
                    {"match": {"header": {"name": "X-Debug", "value": {"exact": ["on"]}}}},
                    {"match": {"query": {"name": "debug"}}},
                    {"match": {"cookie": {"name": "debug", "value": {"exact": ["1"]}}}}
                ]}}),
            )],
        ),
        "api",
    );

    let mut header_hit = request("GET", "/api");
    header_hit
        .headers
        .insert("x-debug".to_string(), "on".to_string());
    assert!(!run_request(&plugins, &mut header_hit).await.is_empty());

    let mut query_hit = request("GET", "/api");
    query_hit.set_raw_query_string("debug=&other=1".to_string());
    assert!(!run_request(&plugins, &mut query_hit).await.is_empty());

    let mut cookie_hit = request("GET", "/api");
    cookie_hit
        .headers
        .insert("cookie".to_string(), "a=b; debug=1".to_string());
    assert!(!run_request(&plugins, &mut cookie_hit).await.is_empty());

    let mut miss = request("GET", "/api");
    miss.headers
        .insert("x-debug".to_string(), "off".to_string());
    assert!(run_request(&plugins, &mut miss).await.is_empty());
}

#[tokio::test]
async fn protocol_predicates_read_the_frontend_stamped_wire_transport() {
    let plugins = published(
        &config(
            vec![make_proxy("api", "/api", vec!["stamp"])],
            vec![with_trigger(
                header_stamper("stamp", PluginScope::Proxy, Some("api"), "x-stamp"),
                json!({"when": {"match": {"protocol": ["http3"]}}}),
            )],
        ),
        "api",
    );

    let mut h2 = request_from("GET", "/api", "10.1.2.3", HttpWireTransport::Http2);
    assert!(run_request(&plugins, &mut h2).await.is_empty());

    let mut h3 = request_from("GET", "/api", "10.1.2.3", HttpWireTransport::Http3);
    assert!(!run_request(&plugins, &mut h3).await.is_empty());
}

#[tokio::test]
async fn source_cidr_predicates_read_the_gateway_resolved_client_ip() {
    let plugins = published(
        &config(
            vec![make_proxy("api", "/api", vec!["stamp"])],
            vec![with_trigger(
                header_stamper("stamp", PluginScope::Proxy, Some("api"), "x-stamp"),
                json!({"when": {"not": {"match": {"source_cidr": ["10.0.0.0/8"]}}}}),
            )],
        ),
        "api",
    );

    let mut internal = request_from("GET", "/api", "10.7.7.7", HttpWireTransport::Http2);
    assert!(run_request(&plugins, &mut internal).await.is_empty());

    let mut external = request_from("GET", "/api", "203.0.113.9", HttpWireTransport::Http2);
    assert!(!run_request(&plugins, &mut external).await.is_empty());
}

// ---------------------------------------------------------------------------
// Decide-once
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_trigger_decision_is_memoized_so_a_later_rewrite_cannot_flip_it() {
    let plugins = published(
        &config(
            vec![make_proxy("api", "/api", vec!["stamp"])],
            vec![with_trigger(
                header_stamper("stamp", PluginScope::Proxy, Some("api"), "x-stamp"),
                json!({"when": {"match": {"path": {"prefix": ["/api/orders"]}}}}),
            )],
        ),
        "api",
    );

    // Decided TRUE at `on_request_received`; a route override then rewrites the
    // path to something the predicate would reject. The instance must still run.
    let mut ctx = request("GET", "/api/orders/42");
    for plugin in &plugins {
        plugin.on_request_received(&mut ctx).await;
    }
    ctx.path = "/internal/rewritten".to_string();
    let mut headers = HashMap::new();
    for plugin in &plugins {
        plugin.before_proxy(&mut ctx, &mut headers).await;
    }
    assert_eq!(headers.get("x-stamp").map(String::as_str), Some("1"));

    // Decided FALSE first; a rewrite into the matching prefix must not resurrect
    // the instance for a later phase.
    let mut ctx = request("GET", "/api/health");
    for plugin in &plugins {
        plugin.on_request_received(&mut ctx).await;
    }
    ctx.path = "/api/orders/42".to_string();
    let mut headers = HashMap::new();
    for plugin in &plugins {
        plugin.before_proxy(&mut ctx, &mut headers).await;
    }
    assert!(headers.is_empty(), "a memoized skip must stay a skip");
}

// ---------------------------------------------------------------------------
// Phase safety at the authentication boundary
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_identity_predicate_does_not_gate_hooks_before_authentication() {
    let plugins = published(
        &config(
            vec![make_proxy("api", "/api", vec!["stamp"])],
            vec![with_trigger(
                header_stamper("stamp", PluginScope::Proxy, Some("api"), "x-stamp"),
                json!({"when": {"match": {"consumer": {"value": {"exact": ["alice"]}}}}}),
            )],
        ),
        "api",
    );

    // No identity has been established when `on_request_received` runs, so the
    // pre-auth phase must NOT memoize a skip — that would be a fail-open gate.
    let mut ctx = request("GET", "/api");
    for plugin in &plugins {
        plugin.on_request_received(&mut ctx).await;
    }
    assert!(
        !ctx.metadata.contains_key("plugin_trigger.stamp.skipped"),
        "pre-auth evaluation of an identity predicate must not record a decision"
    );

    // The `before_proxy` (post-auth) phase is where the real decision is taken.
    ctx.authenticated_identity = Some("alice".to_string());
    let mut headers = HashMap::new();
    for plugin in &plugins {
        plugin.before_proxy(&mut ctx, &mut headers).await;
    }
    assert_eq!(headers.get("x-stamp").map(String::as_str), Some("1"));

    let mut other = request("GET", "/api");
    other.authenticated_identity = Some("mallory".to_string());
    let mut headers = HashMap::new();
    for plugin in &plugins {
        plugin.before_proxy(&mut other, &mut headers).await;
    }
    assert!(headers.is_empty());
}

// ---------------------------------------------------------------------------
// No work / no buffering on skip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_skipped_instance_does_not_request_request_body_buffering() {
    let gated = with_trigger(
        builtin("validate", "body_validator", "api"),
        json!({"when": {"match": {"path": {"prefix": ["/api/orders"]}}}}),
    );
    let plugins = published(
        &config(vec![make_proxy("api", "/api", vec!["validate"])], vec![gated]),
        "api",
    );
    let plugin = plugins.first().expect("one published instance");

    let mut hit = json_request("POST", "/api/orders");
    plugin.on_request_received(&mut hit).await;
    assert!(
        plugin.should_buffer_request_body(&hit),
        "a running body policy still buffers its configured representation"
    );

    let mut miss = json_request("POST", "/api/health");
    plugin.on_request_received(&mut miss).await;
    assert!(
        !plugin.should_buffer_request_body(&miss),
        "a skipped instance must not force trigger-only body buffering"
    );
}

#[tokio::test]
async fn a_capability_predicate_fails_closed_to_running_before_any_decision_exists() {
    let gated = with_trigger(
        builtin("validate", "body_validator", "api"),
        json!({"when": {"match": {"path": {"prefix": ["/never"]}}}}),
    );
    let plugins = published(
        &config(vec![make_proxy("api", "/api", vec!["validate"])], vec![gated]),
        "api",
    );
    let plugin = plugins.first().expect("one published instance");

    // No hook has run, so no decision is memoized. The read-only predicate must
    // report "runs" rather than silently suppressing a guard.
    let unresolved = json_request("POST", "/api/orders");
    assert!(plugin.should_buffer_request_body(&unresolved));
}

// ---------------------------------------------------------------------------
// Scope, multiplicity, ordering
// ---------------------------------------------------------------------------

#[tokio::test]
async fn triggers_are_independent_per_instance_and_preserve_priority_order() {
    let mut first = with_trigger(
        header_stamper("first", PluginScope::Proxy, Some("api"), "x-first"),
        json!({"when": {"match": {"method": ["POST"]}}}),
    );
    first.priority_override = Some(3001);
    let mut second = with_trigger(
        header_stamper("second", PluginScope::Proxy, Some("api"), "x-second"),
        json!({"when": {"match": {"method": ["GET"]}}}),
    );
    second.priority_override = Some(3002);
    let mut third = header_stamper("third", PluginScope::Proxy, Some("api"), "x-third");
    third.priority_override = Some(3000);

    let cfg = config(
        vec![make_proxy("api", "/api", vec!["first", "second", "third"])],
        vec![first, second, third],
    );
    let plugins = published(&cfg, "api");
    assert_eq!(
        plugins.len(),
        3,
        "every instance stays on the published chain"
    );
    let priorities: Vec<_> = plugins.iter().map(|plugin| plugin.priority()).collect();
    assert_eq!(
        priorities,
        vec![3000, 3001, 3002],
        "trigger wrapping must not disturb effective priority ordering"
    );

    let mut post = request("POST", "/api");
    let headers = run_request(&plugins, &mut post).await;
    assert!(headers.contains_key("x-first"));
    assert!(!headers.contains_key("x-second"));
    assert!(
        headers.contains_key("x-third"),
        "an untriggered instance always runs"
    );

    let mut get = request("GET", "/api");
    let headers = run_request(&plugins, &mut get).await;
    assert!(!headers.contains_key("x-first"));
    assert!(headers.contains_key("x-second"));
    assert!(headers.contains_key("x-third"));
}

#[tokio::test]
async fn a_global_scoped_trigger_applies_per_proxy_without_changing_scope_merge() {
    let global = with_trigger(
        header_stamper("global", PluginScope::Global, None, "x-global"),
        json!({"when": {"match": {"proxy_id": ["alpha"]}}}),
    );
    let cfg = config(
        vec![
            make_proxy("alpha", "/alpha", vec![]),
            make_proxy("beta", "/beta", vec![]),
        ],
        vec![global],
    );

    for (proxy_id, expected) in [("alpha", true), ("beta", false)] {
        let plugins = published(&cfg, proxy_id);
        assert_eq!(plugins.len(), 1, "the global instance is on every chain");
        let mut ctx = request("GET", &format!("/{proxy_id}"));
        ctx.matched_proxy = Some(Arc::new(make_proxy(proxy_id, "/x", vec![])));
        let headers = run_request(&plugins, &mut ctx).await;
        assert_eq!(
            headers.contains_key("x-global"),
            expected,
            "proxy {proxy_id}"
        );
    }
}

#[tokio::test]
async fn a_reload_republishes_the_updated_trigger() {
    let cfg = config(
        vec![make_proxy("api", "/api", vec!["stamp"])],
        vec![with_trigger(
            header_stamper("stamp", PluginScope::Proxy, Some("api"), "x-stamp"),
            json!({"when": {"match": {"method": ["POST"]}}}),
        )],
    );
    let cache = PluginCache::new(&cfg).expect("initial cache builds");

    let mut get = request("GET", "/api");
    let plugins = cache.get_plugins(NS, "api").as_ref().clone();
    assert!(run_request(&plugins, &mut get).await.is_empty());

    let reloaded = config(
        vec![make_proxy("api", "/api", vec!["stamp"])],
        vec![with_trigger(
            header_stamper("stamp", PluginScope::Proxy, Some("api"), "x-stamp"),
            json!({"when": {"match": {"method": ["GET"]}}}),
        )],
    );
    cache.rebuild(&reloaded).expect("reload republishes");

    let mut get = request("GET", "/api");
    let plugins = cache.get_plugins(NS, "api").as_ref().clone();
    assert!(!run_request(&plugins, &mut get).await.is_empty());
}

// ---------------------------------------------------------------------------
// Stream connections
// ---------------------------------------------------------------------------

fn stream_ctx(ip: &str) -> StreamConnectionContext {
    let mut ctx = StreamConnectionContext::new(
        ip.to_string(),
        ip.to_string(),
        "tcp".to_string(),
        Some("tcp".to_string()),
        19_311,
        BackendScheme::Tcp,
        Arc::new(ConsumerIndex::new(&[])),
    );
    ctx.proxy_namespace = NS.to_string();
    ctx
}

#[tokio::test]
async fn stream_triggers_gate_on_network_facts() {
    let gated = with_trigger(
        make_plugin_config_with_json(
            "throttle",
            "tcp_connection_throttle",
            json!({"max_connections_per_key": 1}),
            PluginScope::Proxy,
            Some("tcp"),
        ),
        json!({"when": {"match": {"source_cidr": ["10.0.0.0/8"]}}}),
    );
    let plugins = published(
        &config(
            vec![stream_proxy("tcp", BackendScheme::Tcp, 19_311, vec!["throttle"])],
            vec![gated],
        ),
        "tcp",
    );
    let plugin = plugins.first().expect("one published instance");

    // Outside the CIDR the instance never runs, so its one-connection budget is
    // never consumed no matter how many connections arrive.
    for _ in 0..3 {
        let mut skipped = stream_ctx("203.0.113.5");
        assert!(matches!(
            plugin.on_stream_connect(&mut skipped).await,
            PluginResult::Continue
        ));
        assert_eq!(
            skipped
                .metadata
                .as_ref()
                .and_then(|meta| meta.get("plugin_trigger.throttle.skipped"))
                .map(String::as_str),
            Some("true")
        );
    }

    // Inside the CIDR the instance runs and the budget applies.
    let mut first = stream_ctx("10.9.9.9");
    assert!(matches!(
        plugin.on_stream_connect(&mut first).await,
        PluginResult::Continue
    ));
    let mut second = stream_ctx("10.9.9.9");
    assert!(
        !matches!(
            plugin.on_stream_connect(&mut second).await,
            PluginResult::Continue
        ),
        "a running throttle must refuse the over-budget connection"
    );
}

// ---------------------------------------------------------------------------
// Fail-closed publication refusals
// ---------------------------------------------------------------------------

fn publication_error(cfg: &GatewayConfig) -> String {
    match PluginCache::new(cfg) {
        Ok(_) => panic!("plugin cache should have refused this trigger"),
        Err(error) => error,
    }
}

#[test]
fn an_invalid_trigger_is_refused_at_plugin_cache_publication() {
    let cfg = config(
        vec![make_proxy("api", "/api", vec!["stamp"])],
        vec![with_trigger(
            header_stamper("stamp", PluginScope::Proxy, Some("api"), "x-stamp"),
            json!({"when": {"match": {"source_cidr": ["10.0.0.0/33"]}}}),
        )],
    );
    let error = publication_error(&cfg);
    assert!(error.contains("execution trigger is invalid"), "{error}");
    assert!(error.contains("source_cidr"), "{error}");
}

#[test]
fn a_trigger_on_a_websocket_frame_plugin_is_refused_rather_than_half_applied() {
    let cfg = config(
        vec![make_proxy("api", "/api", vec!["ws"])],
        vec![with_trigger(
            builtin("ws", "ws_message_size_limiting", "api"),
            json!({"when": {"match": {"method": ["GET"]}}}),
        )],
    );
    let error = publication_error(&cfg);
    assert!(error.contains("cannot carry an execution trigger"), "{error}");
    assert!(error.contains("WebSocket"), "{error}");
}

#[test]
fn a_trigger_on_a_udp_datagram_plugin_is_refused() {
    let cfg = config(
        vec![stream_proxy(
            "udp",
            BackendScheme::Udp,
            19_411,
            vec!["udp-rl"],
        )],
        vec![with_trigger(
            builtin("udp-rl", "udp_rate_limiting", "udp"),
            json!({"when": {"match": {"source_cidr": ["10.0.0.0/8"]}}}),
        )],
    );
    let error = publication_error(&cfg);
    assert!(error.contains("cannot carry an execution trigger"), "{error}");
    assert!(error.contains("UDP datagram"), "{error}");
}

#[test]
fn an_identity_predicate_on_an_authentication_plugin_is_refused() {
    let cfg = config(
        vec![make_proxy("api", "/api", vec!["auth"])],
        vec![with_trigger(
            builtin("auth", "key_auth", "api"),
            json!({"when": {"match": {"consumer": {"presence": "absent"}}}}),
        )],
    );
    let error = publication_error(&cfg);
    assert!(error.contains("cannot carry an execution trigger"), "{error}");
    assert!(error.contains("authentication plugin"), "{error}");
}

#[test]
fn a_non_identity_trigger_on_an_authentication_plugin_is_accepted() {
    let cfg = config(
        vec![make_proxy("api", "/api", vec!["auth"])],
        vec![with_trigger(
            builtin("auth", "key_auth", "api"),
            json!({"when": {"not": {"match": {"path": {"prefix": ["/api/public"]}}}}}),
        )],
    );
    PluginCache::new(&cfg).expect("a path-scoped auth trigger is a supported composition");
}
