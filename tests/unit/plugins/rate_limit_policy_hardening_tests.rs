//! Rate-limit policy hardening coverage for three advisories:
//!
//! * GHSA-q3p3-94cj-8wh6 — rate-limiter plugins silently ignored top-level
//!   policy typos, so a misspelled synchronization/identity/Redis key let a
//!   security-relevant default replace the intended policy.
//! * GHSA-jjjw-rqjm-fvf3 — unbounded window/request specifications underflowed
//!   monotonic subtraction, wrapped signed Redis TTLs into a counter-deleting
//!   expiry, or allowed request-controlled per-key memory growth.
//! * GHSA-gr3x-g777-hm78 — every instance of one plugin type in a namespace
//!   received the same default Redis prefix, so independent policies
//!   incremented and rejected against each other's counters.

use std::time::{Duration, Instant};

use ferrum_edge::_test_support::{
    create_rate_limit_plugin_with_config_id, rate_limit_redis_key_prefix,
};
use ferrum_edge::plugins::utils::rate_limit::{
    DynamicHttpRateLimitAlgorithm, DynamicRateLimitOp, LOCAL_TOKEN_BUCKET_MAX_WINDOW_SECONDS,
    LocalLimiter, LocalWindowAlgorithm, MAX_RATE_LIMIT_MAX_REQUESTS, MAX_RATE_LIMIT_WINDOW_SECONDS,
    RateLimitWindowSpec, SLIDING_WINDOW_BUCKET_COUNT, SlidingWindow, local_window_algorithm,
    single_window_ttl_seconds, two_window_ttl_seconds,
};
use ferrum_edge::plugins::{PluginHttpClient, create_plugin};
use serde_json::{Value, json};

const OVER_WINDOW: u64 = MAX_RATE_LIMIT_WINDOW_SECONDS + 1;
const OVER_REQUESTS: u64 = MAX_RATE_LIMIT_MAX_REQUESTS + 1;

fn rate_limiting(config: Value) -> Result<(), String> {
    ferrum_edge::plugins::rate_limiting::RateLimiting::new(&config, PluginHttpClient::default())
        .map(|_| ())
}

fn grpc_method_router(config: Value) -> Result<(), String> {
    create_plugin("grpc_method_router", &config).map(|_| ())
}

fn graphql(config: Value) -> Result<(), String> {
    create_plugin("graphql", &config).map(|_| ())
}

fn udp_rate_limiting(config: Value) -> Result<(), String> {
    create_plugin("udp_rate_limiting", &config).map(|_| ())
}

fn valid_rate_limiting_rule() -> Value {
    json!([{"scope": "default", "requests_per_second": 10}])
}

// ── GHSA-q3p3-94cj-8wh6: strict unknown-key rejection ───────────────────────

#[test]
fn rate_limiting_rejects_misspelled_sync_mode_even_with_a_valid_rule() {
    // The advisory's core scenario: a valid rule made construction succeed, so
    // `sync_mdoe` was dropped and every process enforced its own local budget.
    let error = rate_limiting(json!({
        "limits": valid_rate_limiting_rule(),
        "sync_mdoe": "redis",
        "redis_url": "redis://127.0.0.1:6379/0",
    }))
    .expect_err("misspelled sync_mode must fail admission");
    assert!(error.contains("unknown configuration key(s)"), "{error}");
    assert!(error.contains("config.sync_mdoe"), "{error}");
    assert!(error.contains("sync_mode"), "suggestion missing: {error}");
}

#[test]
fn rate_limiting_rejects_misspelled_identity_and_redis_keys() {
    for key in [
        "limit_byy",
        "redis_tsl",
        "redis_key_prefx",
        "expose_header",
        "redis_pool_sze",
    ] {
        let mut config = serde_json::Map::new();
        config.insert("limits".to_string(), valid_rate_limiting_rule());
        config.insert(key.to_string(), json!("consumer"));
        let error = rate_limiting(Value::Object(config))
            .expect_err("a misspelled root key must fail admission");
        assert!(error.contains(key), "{error}");
    }
}

#[test]
fn rate_limiting_accepts_every_documented_root_key() {
    rate_limiting(json!({
        "limit_by": "consumer",
        "expose_headers": true,
        "limits": [{"scope": "default", "window_seconds": 60, "max_requests": 100}],
        "sync_mode": "redis",
        "redis_url": "redis://127.0.0.1:6379/0",
        "redis_tls": false,
        "redis_key_prefix": "explicit:prefix",
        "redis_pool_size": 4,
        "redis_connect_timeout_seconds": 5,
        "redis_health_check_interval_seconds": 5,
        "redis_username": "user",
        "redis_password": "pass",
    }))
    .expect("the documented root key set must remain accepted");
}

#[test]
fn grpc_method_router_rejects_misspelled_root_keys_behind_a_valid_method_rule() {
    for key in ["sync_mdoe", "limit_byy", "redis_key_prefx"] {
        let mut config = serde_json::Map::new();
        config.insert(
            "method_rate_limits".to_string(),
            json!({"/pkg.Svc/Method": {"max_requests": 10, "window_seconds": 1}}),
        );
        config.insert(key.to_string(), json!("redis"));
        let error = grpc_method_router(Value::Object(config))
            .expect_err("a valid method rule must not mask an unknown root key");
        assert!(error.contains("unknown configuration key(s)"), "{error}");
        assert!(error.contains(key), "{error}");
    }
}

#[test]
fn grpc_method_router_rejects_unknown_keys_inside_one_method_rate_limit() {
    let error = grpc_method_router(json!({
        "method_rate_limits": {
            "/pkg.Svc/Method": {"max_requests": 10, "window_seconds": 1, "max_requets": 5}
        }
    }))
    .expect_err("unknown per-method spec keys must fail admission");
    assert!(error.contains("max_requets"), "{error}");
}

#[test]
fn grpc_method_router_accepts_every_documented_root_key() {
    grpc_method_router(json!({
        "allow_methods": ["/pkg.Svc/Method"],
        "deny_methods": ["/pkg.Svc/Blocked"],
        "method_rate_limits": {"/pkg.Svc/Method": {"max_requests": 10, "window_seconds": 1}},
        "limit_by": "consumer",
        "sync_mode": "redis",
        "redis_url": "redis://127.0.0.1:6379/0",
        "redis_tls": false,
        "redis_key_prefix": "explicit:prefix",
        "redis_pool_size": 4,
        "redis_connect_timeout_seconds": 5,
        "redis_health_check_interval_seconds": 5,
        "redis_username": "user",
        "redis_password": "pass",
    }))
    .expect("the documented root key set must remain accepted");
}

#[test]
fn udp_rate_limiting_rejects_misspelled_root_keys() {
    let error = udp_rate_limiting(json!({
        "datagrams_per_second": 100,
        "bytes_per_secnod": 1024,
    }))
    .expect_err("a misspelled byte limit must not load as datagram-only policy");
    assert!(error.contains("bytes_per_secnod"), "{error}");
}

#[test]
fn udp_rate_limiting_accepts_every_documented_root_key() {
    udp_rate_limiting(json!({
        "datagrams_per_second": 100,
        "bytes_per_second": 65536,
        "window_seconds": 5,
        "sync_mode": "redis",
        "redis_url": "redis://127.0.0.1:6379/0",
        "redis_tls": false,
        "redis_key_prefix": "explicit:prefix",
        "redis_pool_size": 4,
        "redis_connect_timeout_seconds": 5,
        "redis_health_check_interval_seconds": 5,
        "redis_username": "user",
        "redis_password": "pass",
    }))
    .expect("the documented root key set must remain accepted");
}

// ── GHSA-jjjw-rqjm-fvf3: bounded numeric configuration ──────────────────────

#[test]
fn rate_limiting_rejects_unbounded_custom_window_and_cap() {
    let error = rate_limiting(json!({
        "limits": [{"scope": "default", "window_seconds": u64::MAX, "max_requests": 1}]
    }))
    .expect_err("u64::MAX window must fail admission");
    assert!(error.contains("window_seconds"), "{error}");

    let error = rate_limiting(json!({
        "limits": [{"scope": "default", "window_seconds": OVER_WINDOW, "max_requests": 1}]
    }))
    .expect_err("one second past the cap must fail admission");
    assert!(error.contains("window_seconds"), "{error}");

    let error = rate_limiting(json!({
        "limits": [{"scope": "default", "window_seconds": 60, "max_requests": OVER_REQUESTS}]
    }))
    .expect_err("an unbounded request cap must fail admission");
    assert!(error.contains("max_requests"), "{error}");
}

#[test]
fn rate_limiting_accepts_the_exact_boundary_values() {
    rate_limiting(json!({
        "limits": [{
            "scope": "default",
            "window_seconds": MAX_RATE_LIMIT_WINDOW_SECONDS,
            "max_requests": MAX_RATE_LIMIT_MAX_REQUESTS,
        }]
    }))
    .expect("the documented maxima must remain configurable");
}

#[test]
fn rate_limiting_rejects_unbounded_preset_windows() {
    for field in [
        "requests_per_second",
        "requests_per_minute",
        "requests_per_hour",
    ] {
        let mut rule = serde_json::Map::new();
        rule.insert("scope".to_string(), json!("default"));
        rule.insert(field.to_string(), json!(OVER_REQUESTS));
        let error = rate_limiting(json!({"limits": [Value::Object(rule)]}))
            .expect_err("an unbounded preset window must fail admission");
        assert!(error.contains(field), "{error}");
    }
}

#[test]
fn rate_limiting_still_rejects_zero_windows_and_caps() {
    assert!(
        rate_limiting(json!({
            "limits": [{"scope": "default", "window_seconds": 0, "max_requests": 1}]
        }))
        .is_err()
    );
    assert!(
        rate_limiting(json!({
            "limits": [{"scope": "default", "window_seconds": 60, "max_requests": 0}]
        }))
        .is_err()
    );
}

#[test]
fn graphql_rejects_unbounded_type_and_operation_rate_specs() {
    let error = graphql(json!({
        "type_rate_limits": {"query": {"max_requests": 1, "window_seconds": u64::MAX}}
    }))
    .expect_err("u64::MAX GraphQL window must fail admission");
    assert!(error.contains("window_seconds"), "{error}");

    let error = graphql(json!({
        "operation_rate_limits": {"GetUser": {"max_requests": OVER_REQUESTS, "window_seconds": 60}}
    }))
    .expect_err("an unbounded GraphQL request cap must fail admission");
    assert!(error.contains("max_requests"), "{error}");

    graphql(json!({
        "type_rate_limits": {
            "query": {
                "max_requests": MAX_RATE_LIMIT_MAX_REQUESTS,
                "window_seconds": MAX_RATE_LIMIT_WINDOW_SECONDS,
            }
        }
    }))
    .expect("the documented maxima must remain configurable");
}

#[test]
fn grpc_method_router_rejects_unbounded_method_rate_specs() {
    let error = grpc_method_router(json!({
        "method_rate_limits": {"/pkg.Svc/M": {"max_requests": 1, "window_seconds": u64::MAX}}
    }))
    .expect_err("u64::MAX gRPC method window must fail admission");
    assert!(error.contains("window_seconds"), "{error}");

    let error = grpc_method_router(json!({
        "method_rate_limits": {"/pkg.Svc/M": {"max_requests": OVER_REQUESTS, "window_seconds": 60}}
    }))
    .expect_err("an unbounded gRPC method request cap must fail admission");
    assert!(error.contains("max_requests"), "{error}");
}

#[test]
fn udp_rate_limiting_rejects_the_extreme_window_that_survived_checked_multiplication() {
    // `rate = 1, window = u64::MAX` passed `rate * window` but wrapped
    // `window + 1` (Redis TTL) and `window * 2` (retention) to zero.
    let error = udp_rate_limiting(json!({
        "datagrams_per_second": 1,
        "window_seconds": u64::MAX,
    }))
    .expect_err("u64::MAX UDP window must fail admission");
    assert!(error.contains("window_seconds"), "{error}");

    udp_rate_limiting(json!({
        "datagrams_per_second": 1,
        "window_seconds": MAX_RATE_LIMIT_WINDOW_SECONDS,
    }))
    .expect("the documented maximum must remain configurable");
}

#[test]
fn ai_rate_limiter_rejects_unbounded_window() {
    let config = json!({"token_limit": 10, "window_seconds": u64::MAX});
    let error = create_plugin("ai_rate_limiter", &config)
        .expect_err("u64::MAX AI token window must fail admission");
    assert!(error.contains("window_seconds"), "{error}");
}

#[test]
fn redis_ttl_helpers_saturate_instead_of_wrapping_into_a_deleting_expiry() {
    // A wrapped TTL became zero or negative, and Redis treats that as DEL — the
    // counter deleted itself on every increment.
    assert_eq!(two_window_ttl_seconds(10), 21);
    assert_eq!(single_window_ttl_seconds(10), 11);
    for window in [u64::MAX, u64::MAX - 1, i64::MAX as u64 + 1] {
        assert!(two_window_ttl_seconds(window) > 0);
        assert!(two_window_ttl_seconds(window) <= i64::MAX as u64);
        assert!(single_window_ttl_seconds(window) > 0);
        assert!(single_window_ttl_seconds(window) <= i64::MAX as u64);
    }
}

// ── GHSA-gr3x-g777-hm78: policy-isolated default Redis keys ─────────────────

fn redis_config_for(plugin_name: &str) -> Value {
    let mut config = match plugin_name {
        "rate_limiting" => json!({"limits": valid_rate_limiting_rule()}),
        "graphql" => json!({
            "type_rate_limits": {"query": {"max_requests": 10, "window_seconds": 1}}
        }),
        "grpc_method_router" => json!({
            "method_rate_limits": {"/pkg.Svc/M": {"max_requests": 10, "window_seconds": 1}}
        }),
        "udp_rate_limiting" => json!({"datagrams_per_second": 10}),
        other => panic!("unsupported plugin in this fixture: {other}"),
    };
    let object = config.as_object_mut().expect("fixture is an object");
    object.insert("sync_mode".to_string(), json!("redis"));
    object.insert("redis_url".to_string(), json!("redis://127.0.0.1:6379/0"));
    config
}

#[test]
fn independent_policies_of_one_plugin_type_no_longer_share_a_default_prefix() {
    for plugin_name in [
        "rate_limiting",
        "graphql",
        "grpc_method_router",
        "udp_rate_limiting",
    ] {
        let config = redis_config_for(plugin_name);
        let a = rate_limit_redis_key_prefix(plugin_name, &config, "policy-a")
            .expect("policy-a admits")
            .expect("redis mode yields a prefix");
        let b = rate_limit_redis_key_prefix(plugin_name, &config, "policy-b")
            .expect("policy-b admits")
            .expect("redis mode yields a prefix");
        assert_ne!(
            a, b,
            "{plugin_name}: two independent policies must not share counters"
        );
        assert!(a.ends_with(":policy-a"), "{plugin_name}: {a}");
        assert!(
            a.contains(plugin_name),
            "{plugin_name}: prefix must stay plugin-scoped: {a}"
        );
    }
}

#[test]
fn replicas_of_the_same_policy_still_share_one_distributed_budget() {
    // Cross-data-plane sharing is the property the fix must preserve: the same
    // configured resource id must resolve to the same key space.
    let config = redis_config_for("rate_limiting");
    let first = rate_limit_redis_key_prefix("rate_limiting", &config, "rl-public-api")
        .expect("admits")
        .expect("redis mode yields a prefix");
    let second = rate_limit_redis_key_prefix("rate_limiting", &config, "rl-public-api")
        .expect("admits")
        .expect("redis mode yields a prefix");
    assert_eq!(first, second);
}

#[test]
fn an_explicit_prefix_remains_the_shared_budget_opt_in() {
    let mut config = redis_config_for("rate_limiting");
    config
        .as_object_mut()
        .expect("fixture is an object")
        .insert("redis_key_prefix".to_string(), json!("team:shared-budget"));
    let a = rate_limit_redis_key_prefix("rate_limiting", &config, "policy-a")
        .expect("admits")
        .expect("redis mode yields a prefix");
    let b = rate_limit_redis_key_prefix("rate_limiting", &config, "policy-b")
        .expect("admits")
        .expect("redis mode yields a prefix");
    assert_eq!(a, "team:shared-budget");
    assert_eq!(a, b);
}

#[test]
fn local_mode_reports_no_redis_prefix() {
    let config = json!({"limits": valid_rate_limiting_rule()});
    assert_eq!(
        rate_limit_redis_key_prefix("rate_limiting", &config, "policy-a").expect("admits"),
        None
    );
}

#[test]
fn the_production_factory_threads_the_config_id_into_every_rate_limit_plugin() {
    // A blank id must fail closed: it would otherwise collapse sibling policies
    // back onto one shared default key space. Reaching this error at all proves
    // the factory passed the id through to the constructor.
    let method_rate_limits = json!({
        "method_rate_limits": {"/pkg.Svc/M": {"max_requests": 10, "window_seconds": 1}}
    });
    for (plugin_name, config) in [
        (
            "rate_limiting",
            json!({"limits": valid_rate_limiting_rule()}),
        ),
        (
            "graphql",
            json!({"type_rate_limits": {"query": {"max_requests": 10, "window_seconds": 1}}}),
        ),
        ("grpc_method_router", method_rate_limits),
        ("udp_rate_limiting", json!({"datagrams_per_second": 10})),
        ("ws_rate_limiting", json!({"frames_per_second": 10})),
        (
            "ai_rate_limiter",
            json!({"token_limit": 100, "window_seconds": 60}),
        ),
    ] {
        create_rate_limit_plugin_with_config_id(plugin_name, &config, Some("  "))
            .expect_err(&format!("{plugin_name}: blank config id must fail closed"));
        create_rate_limit_plugin_with_config_id(plugin_name, &config, Some("policy-a"))
            .unwrap_or_else(|error| panic!("{plugin_name}: valid config id must admit: {error}"));
        create_rate_limit_plugin_with_config_id(plugin_name, &config, None)
            .unwrap_or_else(|error| panic!("{plugin_name}: standalone id must admit: {error}"));
    }
}

// ── GHSA-jjjw-rqjm-fvf3: bounded aggregate local sliding window ─────────────

#[test]
fn sliding_window_retained_state_is_fixed_under_sustained_hot_key() {
    // The advisory's residual: one Instant per admission let a hot key grow
    // with max_requests. Aggregate buckets stay at SLIDING_WINDOW_BUCKET_COUNT.
    let mut window = SlidingWindow::new(250_000, Duration::from_secs(60));
    let now = Instant::now();
    for i in 0..200_000u64 {
        assert!(window.would_allow(now), "hot-key admission {i} must pass");
        window.increment(now);
        assert_eq!(
            window.retained_buckets(),
            SLIDING_WINDOW_BUCKET_COUNT,
            "retained bucket slots must not grow with admissions"
        );
    }
    assert_eq!(window.counted_requests(), 200_000);
    assert_eq!(window.retained_buckets(), SlidingWindow::bucket_capacity());
}

#[test]
fn sliding_window_enforces_configured_boundary() {
    let mut window = SlidingWindow::new(4, Duration::from_secs(30));
    let now = Instant::now();
    for _ in 0..4 {
        assert!(window.would_allow(now));
        window.increment(now);
    }
    assert!(!window.would_allow(now), "limit+1 must deny");
    assert_eq!(window.remaining(), 0);
    assert_eq!(window.retained_buckets(), SLIDING_WINDOW_BUCKET_COUNT);
}

#[test]
fn http_graphql_grpc_shared_windows_select_bounded_sliding_aggregate() {
    // Ordinary HTTP / GraphQL / gRPC-method windows > 5s all route through
    // `new_http_window_states` → SlidingWindow. Prove the shared selector and
    // that construction still admits those plugins onto the shared path.
    let sliding = Duration::from_secs(LOCAL_TOKEN_BUCKET_MAX_WINDOW_SECONDS + 1);
    assert_eq!(
        local_window_algorithm(sliding),
        LocalWindowAlgorithm::SlidingAggregate
    );
    assert_eq!(
        local_window_algorithm(Duration::from_secs(LOCAL_TOKEN_BUCKET_MAX_WINDOW_SECONDS)),
        LocalWindowAlgorithm::TokenBucket
    );

    rate_limiting(json!({
        "limits": [{"scope": "default", "window_seconds": 60, "max_requests": 1000}]
    }))
    .expect("HTTP rate_limiting must construct sliding-window specs");
    graphql(json!({
        "type_rate_limits": {"query": {"max_requests": 1000, "window_seconds": 60}}
    }))
    .expect("graphql must construct shared dynamic HTTP sliding windows");
    grpc_method_router(json!({
        "method_rate_limits": {"/pkg.Svc/M": {"max_requests": 1000, "window_seconds": 60}}
    }))
    .expect("grpc_method_router must construct shared dynamic HTTP sliding windows");
    udp_rate_limiting(json!({"datagrams_per_second": 10, "window_seconds": 60}))
        .expect("udp_rate_limiting still constructs through shared bounds/helpers");

    // Shared limiter path: DynamicHttpRateLimitAlgorithm + SlidingAggregate
    // admits up to the configured boundary and then denies, without depending
    // on per-request timestamp growth.
    let op = DynamicRateLimitOp::new(vec![RateLimitWindowSpec {
        limit: 5,
        duration: Duration::from_secs(60),
    }]);
    let limiter = LocalLimiter::new(DynamicHttpRateLimitAlgorithm::new(), 1);
    let now = Instant::now();
    for i in 0..5 {
        let outcome = limiter.check_at("hot-key".to_string(), &op, now);
        assert!(outcome.allowed, "shared admission {i} must pass");
    }
    let denied = limiter.check_at("hot-key".to_string(), &op, now);
    assert!(!denied.allowed, "shared path must enforce the boundary");
}
