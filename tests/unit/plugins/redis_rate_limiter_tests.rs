use ferrum_edge::_test_support::{
    MAX_REDIS_POOL_SIZE, RedisConfig, RedisRateLimitClient, redis_client_credentials,
    redis_config_url_with_ip, redis_rate_limit_client_for_test,
};
use serde_json::json;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

fn make_config(url: &str, tls: bool) -> RedisConfig {
    RedisConfig {
        url: url.to_string(),
        tls,
        key_prefix: "ferrum:test".to_string(),
        pool_size: 4,
        connect_timeout_seconds: 5,
        health_check_interval_seconds: 5,
        username: None,
        password: None,
    }
}

#[test]
fn test_hostname_uses_url_parser_and_preserves_credentials() {
    let config = make_config("redis://user:pass@redis:6379/15", false);
    assert_eq!(config.hostname().as_deref(), Some("redis"));
}

/// Connect/health-check failures log `redis_url`. `redis_url` is a documented
/// place to encode Redis ACL credentials, so the logged rendering must strip
/// userinfo while keeping scheme/host/port/db as actionable diagnostics.
#[test]
fn test_redacted_url_strips_userinfo_and_keeps_diagnostics() {
    let with_both = make_config("redis://user:pass@redis.internal:6379/15", false);
    assert_eq!(
        with_both.redacted_url(),
        "redis://redacted@redis.internal:6379/15"
    );

    let password_only = make_config("rediss://:hunter2@redis.internal:6380/0", false);
    assert_eq!(
        password_only.redacted_url(),
        "rediss://redacted@redis.internal:6380/0"
    );

    let username_only = make_config("redis://aclUser@redis.internal:6379/1", false);
    assert_eq!(
        username_only.redacted_url(),
        "redis://redacted@redis.internal:6379/1"
    );

    let suffix_secrets = make_config(
        "redis://redis.internal:6379/4?password=query-secret#fragment-secret",
        false,
    );
    assert_eq!(
        suffix_secrets.redacted_url(),
        "redis://redis.internal:6379/4"
    );

    // No userinfo: the original bytes are returned, not the parser's
    // normalization, so a credential-free URL is never silently rewritten.
    let bare = make_config("redis://Redis.Internal:6379/0", false);
    assert_eq!(bare.redacted_url(), "redis://Redis.Internal:6379/0");

    // Unparseable values cannot be proven credential-free, so they fail closed.
    let unparseable = make_config("not a url", false);
    assert_eq!(unparseable.redacted_url(), "[REDACTED]");

    // Non-Redis schemes are never safe diagnostics for a `redis_url` field —
    // even after stripping userinfo — so they fail closed wholesale.
    let http_scheme = make_config(
        "http://user:pass@collector.internal/path?token=query-secret#frag-secret",
        false,
    );
    assert_eq!(http_scheme.redacted_url(), "[REDACTED]");

    // IPv6 authorities keep diagnostics while stripping userinfo.
    let ipv6 = make_config("redis://user:pass@[2001:db8::10]:6379/2", false);
    assert_eq!(
        ipv6.redacted_url(),
        "redis://redacted@[2001:db8::10]:6379/2"
    );

    // Opaque schemes can embed secrets outside userinfo/query/fragment; they
    // must not be echoed just because the URL crate can parse them.
    let opaque = make_config("mailto:user:pass@example.com", false);
    assert_eq!(opaque.redacted_url(), "[REDACTED]");
    let data_url = make_config("data:text/plain,super-secret-token", false);
    assert_eq!(data_url.redacted_url(), "[REDACTED]");
}

/// `RedisConfig` used to derive `Debug`, which printed the ACL password and the
/// URL userinfo verbatim into any `{:?}` rendering.
#[test]
fn test_debug_rendering_hides_credentials() {
    let mut config = make_config("redis://user:urlpass@redis.internal:6379/2", false);
    config.username = Some("acl-user".to_string());
    config.password = Some("acl-password".to_string());

    let rendered = format!("{config:?}");
    assert!(
        !rendered.contains("urlpass")
            && !rendered.contains("acl-password")
            && !rendered.contains("acl-user"),
        "RedisConfig Debug leaked credentials: {rendered}"
    );
    assert!(
        rendered.contains("redis.internal:6379"),
        "RedisConfig Debug dropped useful diagnostics: {rendered}"
    );
}

#[test]
fn test_hostname_skips_ipv6_literals() {
    let config = make_config("redis://[2001:db8::10]:6379/0", false);
    assert_eq!(config.hostname(), None);
}

#[test]
fn test_url_with_resolved_ip_replaces_host_not_scheme() {
    let config = make_config("redis://redis:6379/0", false);
    let url = redis_config_url_with_ip(&config, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    assert_eq!(url, "redis://127.0.0.1:6379/0");
}

#[test]
fn test_url_with_resolved_ip_preserves_credentials_and_path() {
    let config = make_config("redis://user:pass@redis:6379/15", false);
    let url = redis_config_url_with_ip(&config, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)));
    assert_eq!(url, "redis://user:pass@10.0.0.5:6379/15");
}

#[test]
fn test_url_with_resolved_ip_formats_ipv6_authority() {
    let config = make_config("redis://cache.internal:6379/0", false);
    let url = redis_config_url_with_ip(&config, IpAddr::V6(Ipv6Addr::LOCALHOST));
    assert_eq!(url, "redis://[::1]:6379/0");
}

#[test]
fn test_url_with_resolved_ip_preserves_tls_hostname_for_sni() {
    let config = make_config("redis://cache.internal:6379/0", true);
    let url = redis_config_url_with_ip(&config, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    assert_eq!(url, "rediss://cache.internal:6379/0");
}

// ── ACL credential injection ─────────────────────────────────────────────
//
// Regression coverage for "Redis ACL credentials silently ignored": before
// the fix, `redis_username` / `redis_password` were parsed off the plugin
// JSON config but never forwarded to `redis::Client::open()` /
// `build_with_tls()`, so the gateway would connect unauthenticated even
// though the operator had configured ACL credentials. These tests assert
// that the credentials now flow through to `redis::ConnectionInfo`.

#[test]
fn test_explicit_credentials_are_applied_to_plain_client() {
    let mut config = make_config("redis://localhost:6379/0", false);
    config.username = Some("alice".to_string());
    config.password = Some("secret".to_string());

    let (user, pass) =
        redis_client_credentials(config, "redis://localhost:6379/0").expect("build_client");
    assert_eq!(user.as_deref(), Some("alice"));
    assert_eq!(pass.as_deref(), Some("secret"));
}

#[test]
fn test_explicit_credentials_are_applied_to_tls_client() {
    let mut config = make_config("rediss://cache.internal:6379/0", true);
    config.username = Some("svc-rate-limit".to_string());
    config.password = Some("hunter2".to_string());

    // Use rediss:// + TLS so we exercise the build_with_tls branch.
    let (user, pass) =
        redis_client_credentials(config, "rediss://cache.internal:6379/0").expect("build_client");
    assert_eq!(user.as_deref(), Some("svc-rate-limit"));
    assert_eq!(pass.as_deref(), Some("hunter2"));
}

#[test]
fn test_explicit_credentials_override_url_userinfo() {
    // URL-embedded creds (`bob:fromurl`) are parsed by the redis crate, but the
    // explicit fields must take precedence so operators have a single source of
    // truth for credential rotation.
    let mut config = make_config("redis://bob:fromurl@localhost:6379/0", false);
    config.username = Some("alice".to_string());
    config.password = Some("frompayload".to_string());

    let (user, pass) = redis_client_credentials(config, "redis://bob:fromurl@localhost:6379/0")
        .expect("build_client");
    assert_eq!(user.as_deref(), Some("alice"));
    assert_eq!(pass.as_deref(), Some("frompayload"));
}

#[test]
fn test_url_userinfo_is_preserved_when_no_explicit_credentials() {
    // When neither `redis_username` nor `redis_password` is set, the URL
    // userinfo flows through (matches redis-rs' default URL parsing).
    let config = make_config("redis://carol:urlpw@localhost:6379/0", false);

    let (user, pass) = redis_client_credentials(config, "redis://carol:urlpw@localhost:6379/0")
        .expect("build_client");
    assert_eq!(user.as_deref(), Some("carol"));
    assert_eq!(pass.as_deref(), Some("urlpw"));
}

#[test]
fn test_password_only_credential() {
    // Common Redis 5 pattern: AUTH with no username, just a password.
    let mut config = make_config("redis://localhost:6379/0", false);
    config.username = None;
    config.password = Some("redis-pw".to_string());

    let (user, pass) =
        redis_client_credentials(config, "redis://localhost:6379/0").expect("build_client");
    assert_eq!(user, None);
    assert_eq!(pass.as_deref(), Some("redis-pw"));
}

#[test]
fn test_no_credentials_means_unauthenticated() {
    let config = make_config("redis://localhost:6379/0", false);
    let (user, pass) =
        redis_client_credentials(config, "redis://localhost:6379/0").expect("build_client");
    assert_eq!(user, None);
    assert_eq!(pass, None);
}

#[test]
fn test_from_plugin_config_local_modes() {
    assert!(
        RedisConfig::from_plugin_config(&json!({}), "ferrum:test")
            .unwrap()
            .is_none()
    );
    assert!(
        RedisConfig::from_plugin_config(&json!({"sync_mode": "local"}), "ferrum:test")
            .unwrap()
            .is_none()
    );
}

#[test]
fn test_from_plugin_config_rejects_invalid_redis_mode() {
    let cases = [
        json!(null),
        json!([]),
        json!({"sync_mode": false}),
        json!({"sync_mode": "redsi"}),
        json!({"sync_mode": "redis"}),
        json!({"sync_mode": "redis", "redis_url": ""}),
        json!({"sync_mode": "redis", "redis_url": "redis://localhost:6379/0", "redis_tls": "true"}),
        json!({"sync_mode": "redis", "redis_url": "redis://localhost:6379/0", "redis_key_prefix": ""}),
        json!({"sync_mode": "redis", "redis_url": "redis://localhost:6379/0", "redis_pool_size": 0}),
        json!({"sync_mode": "redis", "redis_url": "redis://localhost:6379/0", "redis_pool_size": (MAX_REDIS_POOL_SIZE as u64) + 1}),
        json!({"sync_mode": "redis", "redis_url": "redis://localhost:6379/0", "redis_pool_size": u64::MAX}),
        json!({"sync_mode": "redis", "redis_url": "redis://localhost:6379/0", "redis_connect_timeout_seconds": 0}),
        json!({"sync_mode": "redis", "redis_url": "redis://localhost:6379/0", "redis_health_check_interval_seconds": 0}),
        json!({"sync_mode": "redis", "redis_url": "redis://localhost:6379/0", "redis_username": false}),
        json!({"sync_mode": "redis", "redis_url": "redis://localhost:6379/0", "redis_password": []}),
    ];

    for config in cases {
        assert!(
            RedisConfig::from_plugin_config(&config, "ferrum:test").is_err(),
            "config should fail validation: {config}"
        );
    }
}

#[test]
fn test_from_plugin_config_rejects_malformed_redis_urls() {
    for redis_url in [
        "not a url",
        "http://cache.internal:6379/0",
        "redis:///0",
        "rediss:///0",
    ] {
        let config = json!({
            "sync_mode": "redis",
            "redis_url": redis_url
        });
        assert!(
            RedisConfig::from_plugin_config(&config, "ferrum:test").is_err(),
            "redis_url should fail validation: {redis_url}"
        );
    }
}

#[test]
fn test_from_plugin_config_parses_valid_redis_mode() {
    let config = RedisConfig::from_plugin_config(
        &json!({
            "sync_mode": "redis",
            "redis_url": "redis://cache.internal:6379/0",
            "redis_tls": true,
            "redis_key_prefix": "tenant:rate",
            "redis_pool_size": 8,
            "redis_connect_timeout_seconds": 2,
            "redis_health_check_interval_seconds": 3,
            "redis_username": "svc",
            "redis_password": "secret"
        }),
        "ferrum:test",
    )
    .unwrap()
    .unwrap();

    assert_eq!(config.url, "redis://cache.internal:6379/0");
    assert!(config.tls);
    assert_eq!(config.key_prefix, "tenant:rate");
    assert_eq!(config.pool_size, 8);
    assert_eq!(config.connect_timeout_seconds, 2);
    assert_eq!(config.health_check_interval_seconds, 3);
    assert_eq!(config.username.as_deref(), Some("svc"));
    assert_eq!(config.password.as_deref(), Some("secret"));
}

#[test]
fn test_from_plugin_config_accepts_exact_max_redis_pool_size() {
    // Inclusive upper bound: redis_pool_size == MAX_REDIS_POOL_SIZE must parse
    // and be preserved exactly (MAX+1 / u64::MAX remain covered by rejection cases).
    let config = RedisConfig::from_plugin_config(
        &json!({
            "sync_mode": "redis",
            "redis_url": "redis://localhost:6379/0",
            "redis_pool_size": MAX_REDIS_POOL_SIZE,
        }),
        "ferrum:test",
    )
    .expect("exact MAX_REDIS_POOL_SIZE must be accepted")
    .expect("sync_mode=redis must yield Some(RedisConfig)");

    assert_eq!(config.pool_size, MAX_REDIS_POOL_SIZE);
}

// ── Connection-attempt timeout wiring (issue #2310) ───────────────────────
//
// redis-rs 1.2.1 defaults `AsyncConnectionConfig` timeouts to one second.
// Ferrum must install `redis_connect_timeout_seconds` into that inner config so
// values above one second are effective. `AsyncConnectionConfig` exposes no
// getter, so the wiring is pinned by source text plus the outer-bound value.
// Assertions below are outcome-based (success/failure / config equality), not
// wall-clock ranges.

#[test]
fn connect_timeout_is_installed_into_redis_connection_config_above_and_below_one_second() {
    for seconds in [1_u64, 2, 5, 30] {
        let mut config = make_config("redis://127.0.0.1:6379/0", false);
        config.connect_timeout_seconds = seconds;
        let client = redis_rate_limit_client_for_test(config);
        assert_eq!(
            client.connection_timeout_for_test(),
            Duration::from_secs(seconds)
        );
    }

    let source = include_str!("../../../src/plugins/utils/redis_rate_limiter.rs");
    assert!(
        source.contains(
            "redis::AsyncConnectionConfig::new().set_connection_timeout(Some(self.connect_timeout()))"
        ),
        "inner AsyncConnectionConfig must carry Ferrum's timeout, not the crate 1s default"
    );
}

/// Accept TCP, optionally delay, then answer every RESP array command with +OK.
///
/// Used to simulate a Redis endpoint whose protocol handshake is delayed after
/// TCP accept (the failure mode in issue #2310).
async fn spawn_delayed_redis_handshake_server(
    handshake_delay: Option<Duration>,
) -> (u16, oneshot::Sender<()>, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("local_addr").port();
    let accepts = Arc::new(AtomicUsize::new(0));
    let accepts_task = Arc::clone(&accepts);
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                accepted = listener.accept() => {
                    let Ok((mut stream, _)) = accepted else { break; };
                    accepts_task.fetch_add(1, Ordering::Relaxed);
                    let delay = handshake_delay;
                    tokio::spawn(async move {
                        if let Some(delay) = delay {
                            tokio::time::sleep(delay).await;
                        }
                        let mut buf = vec![0_u8; 4096];
                        loop {
                            match stream.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    // Rough RESP command count: each top-level array
                                    // begins with '*'. Enough for CLIENT SETINFO pipelines.
                                    let commands = buf[..n].iter().filter(|&&b| b == b'*').count().max(1);
                                    let mut reply = Vec::new();
                                    for _ in 0..commands {
                                        reply.extend_from_slice(b"+OK\r\n");
                                    }
                                    if stream.write_all(&reply).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                    });
                }
            }
        }
    });

    (port, shutdown_tx, accepts)
}

#[tokio::test]
async fn connect_timeout_above_one_second_allows_delayed_redis_handshake() {
    // Handshake completes after >1s. With the buggy crate default (1s) this
    // fails; with Ferrum's configured 5s inner timeout it must succeed.
    let (port, shutdown, _accepts) =
        spawn_delayed_redis_handshake_server(Some(Duration::from_millis(1500))).await;
    let mut config = make_config(&format!("redis://127.0.0.1:{port}/0"), false);
    config.connect_timeout_seconds = 5;
    config.health_check_interval_seconds = 60;
    let client = redis_rate_limit_client_for_test(config);

    assert!(
        client.connect_cached_for_test().await,
        "cached path must honor redis_connect_timeout_seconds > 1s"
    );

    // Fresh client for the dedicated path (the pooled connection is already warm).
    let mut config = make_config(&format!("redis://127.0.0.1:{port}/0"), false);
    config.connect_timeout_seconds = 5;
    config.health_check_interval_seconds = 60;
    let dedicated = redis_rate_limit_client_for_test(config);
    assert!(
        dedicated.connect_dedicated_for_test().await,
        "dedicated path must honor redis_connect_timeout_seconds > 1s"
    );

    let mut config = make_config(&format!("redis://127.0.0.1:{port}/0"), false);
    config.connect_timeout_seconds = 5;
    config.health_check_interval_seconds = 60;
    let health = redis_rate_limit_client_for_test(config);
    assert!(
        health.health_check_connect_for_test().await,
        "health-check path must honor redis_connect_timeout_seconds > 1s"
    );

    let _ = shutdown.send(());
}

#[tokio::test]
async fn connect_timeout_of_one_second_fails_closed_on_hung_handshake() {
    // Accept, then delay the Redis protocol reply far beyond the configured
    // timeout. A 1s Ferrum timeout must fail closed on every path. Outcomes
    // only — no elapsed-time assertions.
    let (port, shutdown, accepts) =
        spawn_delayed_redis_handshake_server(Some(Duration::from_secs(30))).await;

    let mut config = make_config(&format!("redis://127.0.0.1:{port}/0"), false);
    config.connect_timeout_seconds = 1;
    config.health_check_interval_seconds = 60;
    let client = redis_rate_limit_client_for_test(config);
    assert!(
        !client.connect_cached_for_test().await,
        "cached path must fail closed when handshake exceeds 1s timeout"
    );
    assert!(
        !client.is_available(),
        "failed connect must mark Redis unavailable for local fallback"
    );
    assert!(
        accepts.load(Ordering::Relaxed) >= 1,
        "server must have accepted at least one dial attempt"
    );

    let mut config = make_config(&format!("redis://127.0.0.1:{port}/0"), false);
    config.connect_timeout_seconds = 1;
    config.health_check_interval_seconds = 60;
    let dedicated = redis_rate_limit_client_for_test(config);
    assert!(
        !dedicated.connect_dedicated_for_test().await,
        "dedicated path must fail closed when handshake exceeds 1s timeout"
    );

    let mut config = make_config(&format!("redis://127.0.0.1:{port}/0"), false);
    config.connect_timeout_seconds = 1;
    config.health_check_interval_seconds = 60;
    let health = redis_rate_limit_client_for_test(config);
    assert!(
        !health.health_check_connect_for_test().await,
        "health-check path must fail closed when handshake exceeds 1s timeout"
    );

    let _ = shutdown.send(());
}

#[test]
fn plugin_consumers_parse_connect_timeout_above_one_second() {
    // rate_limiting / graphql / grpc_method_router all share RedisConfig parsing.
    // Prove each consumer's documented default prefix + a >1s timeout parses.
    for (prefix, seconds) in [
        ("ferrum:rate_limiting", 5_u64),
        ("ferrum:graphql", 2_u64),
        ("ferrum:grpc_method_router", 10_u64),
    ] {
        let config = RedisConfig::from_plugin_config(
            &json!({
                "sync_mode": "redis",
                "redis_url": "redis://127.0.0.1:6379/0",
                "redis_connect_timeout_seconds": seconds,
            }),
            prefix,
        )
        .expect("parse")
        .expect("redis mode");
        assert_eq!(config.connect_timeout_seconds, seconds);
        assert_eq!(config.key_prefix, prefix);
        let client = redis_rate_limit_client_for_test(config);
        assert_eq!(
            client.connection_timeout_for_test(),
            Duration::from_secs(seconds)
        );
    }
}

// ── redis_pool_size cardinality / selection (issue #2304) ─────────────────
//
// Before the fix, `redis_pool_size` was parsed and validated but every instance
// cached exactly one connection. These tests prove configured pool size controls
// runtime cardinality and round-robin selection — not merely parsing.

#[test]
fn pool_size_controls_client_cardinality_for_named_consumers() {
    // rate_limiting / graphql / grpc_method_router all construct RedisRateLimitClient
    // through RedisConfig / RateLimitBackend::from_plugin_config.
    for (prefix, pool_size) in [
        ("ferrum:rate_limiting", 1_usize),
        ("ferrum:graphql", 3_usize),
        ("ferrum:grpc_method_router", 8_usize),
    ] {
        let config = RedisConfig::from_plugin_config(
            &json!({
                "sync_mode": "redis",
                "redis_url": "redis://127.0.0.1:6379/0",
                "redis_pool_size": pool_size,
            }),
            prefix,
        )
        .expect("parse")
        .expect("redis mode");
        assert_eq!(config.pool_size, pool_size);
        assert_eq!(config.key_prefix, prefix);
        let client = redis_rate_limit_client_for_test(config);
        assert_eq!(
            client.pool_size_for_test(),
            pool_size,
            "client pool must match redis_pool_size for {prefix}"
        );
        assert_eq!(
            client.cached_pool_cardinality_for_test(),
            0,
            "pool slots must be empty before lazy establishment"
        );
    }
}

#[test]
fn pool_slot_selection_is_deterministic_round_robin() {
    let mut config = make_config("redis://127.0.0.1:6379/0", false);
    config.pool_size = 4;
    let client = redis_rate_limit_client_for_test(config);
    assert_eq!(
        client.select_slot_indexes_for_test(10),
        vec![0, 1, 2, 3, 0, 1, 2, 3, 0, 1]
    );

    let mut config = make_config("redis://127.0.0.1:6379/0", false);
    config.pool_size = 1;
    let single = redis_rate_limit_client_for_test(config);
    assert_eq!(single.select_slot_indexes_for_test(5), vec![0, 0, 0, 0, 0]);
}

#[tokio::test]
async fn pool_size_one_establishes_single_tcp_connection() {
    let (port, shutdown, accepts) = spawn_delayed_redis_handshake_server(None).await;
    let mut config = make_config(&format!("redis://127.0.0.1:{port}/0"), false);
    config.pool_size = 1;
    config.health_check_interval_seconds = 60;
    let client = redis_rate_limit_client_for_test(config);

    assert_eq!(client.warm_pool_for_test().await, 1);
    assert_eq!(client.cached_pool_cardinality_for_test(), 1);
    assert_eq!(
        accepts.load(Ordering::Relaxed),
        1,
        "pool_size=1 must open exactly one multiplexed TCP connection"
    );

    // Re-warming must reuse the cached connection, not dial again.
    assert_eq!(client.warm_pool_for_test().await, 1);
    assert_eq!(accepts.load(Ordering::Relaxed), 1);

    let _ = shutdown.send(());
}

#[tokio::test]
async fn pool_size_four_establishes_four_tcp_connections() {
    let (port, shutdown, accepts) = spawn_delayed_redis_handshake_server(None).await;
    let mut config = make_config(&format!("redis://127.0.0.1:{port}/0"), false);
    config.pool_size = 4;
    config.health_check_interval_seconds = 60;
    let client = redis_rate_limit_client_for_test(config);

    assert_eq!(client.warm_pool_for_test().await, 4);
    assert_eq!(client.cached_pool_cardinality_for_test(), 4);
    assert_eq!(
        accepts.load(Ordering::Relaxed),
        4,
        "pool_size=4 must open four multiplexed TCP connections"
    );

    // Second warm must reuse all slots.
    assert_eq!(client.warm_pool_for_test().await, 4);
    assert_eq!(accepts.load(Ordering::Relaxed), 4);
    assert_eq!(client.cached_pool_cardinality_for_test(), 4);

    let _ = shutdown.send(());
}

#[tokio::test]
async fn pool_clear_on_reconnect_drops_all_slots_then_reestablishes() {
    let (port, shutdown, accepts) = spawn_delayed_redis_handshake_server(None).await;
    let mut config = make_config(&format!("redis://127.0.0.1:{port}/0"), false);
    config.pool_size = 3;
    config.health_check_interval_seconds = 60;
    let client = redis_rate_limit_client_for_test(config);

    assert_eq!(client.warm_pool_for_test().await, 3);
    assert_eq!(accepts.load(Ordering::Relaxed), 3);

    // Reconnect clearing must wipe every slot (partial-failure / mark_unavailable path).
    client.clear_pool_for_test();
    assert_eq!(client.cached_pool_cardinality_for_test(), 0);

    assert_eq!(client.warm_pool_for_test().await, 3);
    assert_eq!(
        accepts.load(Ordering::Relaxed),
        6,
        "after clear, all three slots must dial again"
    );
    assert_eq!(client.cached_pool_cardinality_for_test(), 3);

    let _ = shutdown.send(());
}

#[tokio::test]
async fn named_consumer_pool_sizes_produce_matching_tcp_cardinality() {
    // End-to-end for the three issue-named consumers: parse their config shape,
    // construct the shared client, and prove TCP accepts == redis_pool_size.
    for (prefix, pool_size) in [
        ("ferrum:rate_limiting", 2_usize),
        ("ferrum:graphql", 5_usize),
        ("ferrum:grpc_method_router", 3_usize),
    ] {
        let (port, shutdown, accepts) = spawn_delayed_redis_handshake_server(None).await;
        let config = RedisConfig::from_plugin_config(
            &json!({
                "sync_mode": "redis",
                "redis_url": format!("redis://127.0.0.1:{port}/0"),
                "redis_pool_size": pool_size,
                "redis_health_check_interval_seconds": 60,
            }),
            prefix,
        )
        .expect("parse")
        .expect("redis mode");
        let client = redis_rate_limit_client_for_test(config);
        assert_eq!(client.pool_size_for_test(), pool_size);
        assert_eq!(client.warm_pool_for_test().await, pool_size);
        assert_eq!(
            accepts.load(Ordering::Relaxed),
            pool_size,
            "{prefix}: TCP accepts must equal redis_pool_size={pool_size}"
        );
        assert_eq!(client.cached_pool_cardinality_for_test(), pool_size);
        let _ = shutdown.send(());
    }
}

#[test]
fn rate_limit_backend_from_plugin_config_honors_pool_size_for_named_consumers() {
    use ferrum_edge::plugins::utils::http_client::PluginHttpClient;
    use ferrum_edge::plugins::utils::rate_limit::{
        DynamicHttpRateLimitAlgorithm, RateLimitBackend,
    };

    let http = PluginHttpClient::default();
    let algorithm = DynamicHttpRateLimitAlgorithm::new();

    for (plugin_name, pool_size) in [
        ("rate_limiting", 1_usize),
        ("graphql", 4_usize),
        ("grpc_method_router", 7_usize),
    ] {
        let backend: RateLimitBackend<String, DynamicHttpRateLimitAlgorithm> =
            RateLimitBackend::from_plugin_config(
                plugin_name,
                &json!({
                    "sync_mode": "redis",
                    "redis_url": "redis://127.0.0.1:6379/0",
                    "redis_pool_size": pool_size,
                    "redis_health_check_interval_seconds": 60,
                }),
                &http,
                algorithm,
            )
            .expect("failover backend");
        assert!(matches!(backend, RateLimitBackend::Failover(_)));
        assert_eq!(
            backend.redis_pool_size_for_test(),
            Some(pool_size),
            "{plugin_name}: RateLimitBackend must retain redis_pool_size"
        );
    }

    let local: RateLimitBackend<String, DynamicHttpRateLimitAlgorithm> =
        RateLimitBackend::from_plugin_config(
            "rate_limiting",
            &json!({"sync_mode": "local"}),
            &http,
            algorithm,
        )
        .expect("local backend");
    assert_eq!(local.redis_pool_size_for_test(), None);
}

// ── Sliding-window subsecond precision (issue #2303) ──────────────────────
//
// Before the fix, `elapsed_fraction` used whole epoch seconds, so a one-second
// window always reported fraction 0.0 and never decayed the previous bucket.
// Index and fraction also used separate clock reads that could straddle a
// boundary. Coverage below is pure/deterministic via `window_progress_at`.

#[test]
fn window_progress_one_second_start_midpoint_and_end() {
    use ferrum_edge::_test_support::redis_window_progress_at;

    let start = redis_window_progress_at(Duration::from_secs(100), 1);
    assert_eq!(start.index, 100);
    assert_eq!(start.elapsed_fraction, 0.0);

    let mid = redis_window_progress_at(Duration::from_millis(100_500), 1);
    assert_eq!(mid.index, 100);
    assert!((mid.elapsed_fraction - 0.5).abs() < 1e-12);

    let near_end = redis_window_progress_at(Duration::from_nanos(100_999_999_999), 1);
    assert_eq!(near_end.index, 100);
    assert!(near_end.elapsed_fraction > 0.999);
    assert!(near_end.elapsed_fraction < 1.0);

    let boundary = redis_window_progress_at(Duration::from_secs(101), 1);
    assert_eq!(boundary.index, 101);
    assert_eq!(boundary.elapsed_fraction, 0.0);
}

#[test]
fn window_progress_multi_second_start_midpoint_and_end() {
    use ferrum_edge::_test_support::redis_window_progress_at;

    let start = redis_window_progress_at(Duration::from_secs(10), 5);
    assert_eq!(start.index, 2);
    assert_eq!(start.elapsed_fraction, 0.0);

    let mid = redis_window_progress_at(Duration::from_millis(12_500), 5);
    assert_eq!(mid.index, 2);
    assert!((mid.elapsed_fraction - 0.5).abs() < 1e-12);

    let near_end = redis_window_progress_at(Duration::from_nanos(14_999_999_999), 5);
    assert_eq!(near_end.index, 2);
    assert!(near_end.elapsed_fraction > 0.999);
    assert!(near_end.elapsed_fraction < 1.0);

    let boundary = redis_window_progress_at(Duration::from_secs(15), 5);
    assert_eq!(boundary.index, 3);
    assert_eq!(boundary.elapsed_fraction, 0.0);
}

#[test]
fn window_progress_rejects_former_boundary_straddle_mismatch() {
    use ferrum_edge::_test_support::redis_window_progress_at;

    // Instant just before a 5s boundary vs the next instant: each sample must
    // stay internally consistent. The old bug could pair index from t0 with
    // fraction from t1 (index=2 with fraction=0.0) and under-decay the prior
    // bucket.
    let before = redis_window_progress_at(Duration::from_millis(14_999), 5);
    let after = redis_window_progress_at(Duration::from_secs(15), 5);
    assert_eq!(before.index, 2);
    assert!(before.elapsed_fraction > 0.99);
    assert_eq!(after.index, 3);
    assert_eq!(after.elapsed_fraction, 0.0);

    // A single captured sample never yields the mismatched (index=2, frac=0.0)
    // pairing that separate clock reads produced across this boundary.
    assert!(
        !(before.index == 2 && before.elapsed_fraction == 0.0),
        "pre-boundary sample must not report a zero fraction with the prior index"
    );
}

#[test]
fn redis_one_second_prior_bucket_decays_instead_of_full_suppression() {
    use ferrum_edge::_test_support::redis_window_progress_at;
    use ferrum_edge::plugins::utils::rate_limit::FixedWindow;

    // Redis path: prev bucket full (10), current has the candidate request (1).
    // At fraction 0.0 the old code always denied; with subsecond decay the mid-
    // window candidate is admitted.
    let window = FixedWindow::new(10, 1);
    let start = redis_window_progress_at(Duration::from_secs(50), 1);
    let mid = redis_window_progress_at(Duration::from_millis(50_500), 1);
    let near_end = redis_window_progress_at(Duration::from_nanos(50_900_000_000), 1);

    assert!(
        !window.outcome(10, 1, start.elapsed_fraction).allowed,
        "at window start a full prior bucket still suppresses (weighted=11)"
    );
    assert!(
        window.outcome(10, 1, mid.elapsed_fraction).allowed,
        "mid one-second window must decay prior bucket (weighted=6)"
    );
    assert!(
        window.outcome(10, 1, near_end.elapsed_fraction).allowed,
        "near end of one-second window prior bucket is nearly gone"
    );
    assert!(
        (window.weighted_count(10, 0, mid.elapsed_fraction) - 5.0).abs() < 1e-12,
        "half-elapsed prior bucket of 10 contributes exactly 5"
    );
}

#[test]
fn shared_consumers_use_same_window_progress_helper() {
    // rate_limiting, GraphQL type/named-operation limits, and grpc_method_router
    // per-method limits all reach check_http_windows_redis → window_progress.
    // Prove the shared helper (not a per-plugin copy) is what the test support
    // and live clock path expose.
    use ferrum_edge::_test_support::{redis_window_progress, redis_window_progress_at};
    use ferrum_edge::plugins::utils::redis_rate_limiter::RedisRateLimitClient;

    let at = redis_window_progress_at(Duration::from_millis(1_250), 1);
    let direct = RedisRateLimitClient::window_progress_at(Duration::from_millis(1_250), 1);
    assert_eq!(at, direct);
    assert!((at.elapsed_fraction - 0.25).abs() < 1e-12);

    let live = redis_window_progress(1);
    assert!(live.elapsed_fraction >= 0.0 && live.elapsed_fraction < 1.0);
}

// ── Redis health-task lifecycle (issue #2305) ─────────────────────────────

#[tokio::test(start_paused = true)]
async fn redis_health_checker_stops_after_client_drop() {
    let (port, shutdown, accepts) = spawn_delayed_redis_handshake_server(None).await;
    let mut config = make_config(&format!("redis://127.0.0.1:{port}/0"), false);
    config.health_check_interval_seconds = 1;
    config.connect_timeout_seconds = 1;

    let client = redis_rate_limit_client_for_test(config);
    client.mark_unavailable_for_test();
    assert!(client.health_checker_started_for_test());
    let abort = client
        .health_checker_abort_for_test()
        .expect("health checker abort handle");

    // The checker is spawned asynchronously, so its first sleep may arm after
    // an initial clock advance. Advance whole virtual intervals (not arbitrary
    // wall-clock sleeps) until the mock server observes the real dial.
    for _ in 0..3 {
        tokio::time::advance(Duration::from_secs(1)).await;
        for _ in 0..100 {
            if accepts.load(Ordering::Relaxed) >= 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
        if accepts.load(Ordering::Relaxed) >= 1 {
            break;
        }
    }
    let after_first = accepts.load(Ordering::Relaxed);
    assert!(
        after_first >= 1,
        "health checker must dial at least once after the first interval"
    );

    drop(client);
    for _ in 0..10 {
        if abort.is_finished() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(abort.is_finished(), "drop must abort the health checker");

    let baseline_accepts = accepts.load(Ordering::Relaxed);
    tokio::time::advance(Duration::from_secs(5)).await;
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        accepts.load(Ordering::Relaxed),
        baseline_accepts,
        "retired client must not keep dialing Redis after drop"
    );

    let _ = shutdown.send(());
}

#[tokio::test(start_paused = true)]
async fn failover_observer_drop_releases_client_and_stops_task() {
    use ferrum_edge::plugins::utils::http_client::PluginHttpClient;
    use ferrum_edge::plugins::utils::rate_limit::{
        DynamicHttpRateLimitAlgorithm, RateLimitBackend,
    };
    use std::sync::Arc;

    let http = PluginHttpClient::default();
    let backend: RateLimitBackend<String, DynamicHttpRateLimitAlgorithm> =
        RateLimitBackend::from_plugin_config(
            "rate_limiting",
            &json!({
                "sync_mode": "redis",
                "redis_url": "redis://127.0.0.1:9/0",
                "redis_health_check_interval_seconds": 1,
            }),
            &http,
            DynamicHttpRateLimitAlgorithm::new(),
        )
        .expect("failover backend");

    let client = backend
        .redis_client_arc_for_test()
        .expect("redis client arc");
    let weak = Arc::downgrade(&client);
    let observer = backend
        .health_observer_abort_for_test()
        .expect("observer abort");
    // Backend + local clone: observer must NOT hold an extra strong Arc.
    assert_eq!(Arc::strong_count(&client), 2);
    drop(client);

    drop(backend);
    for _ in 0..20 {
        if observer.is_finished() && weak.strong_count() == 0 {
            break;
        }
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(1)).await;
    }
    assert!(
        observer.is_finished(),
        "drop must abort the failover observer"
    );
    assert_eq!(
        weak.strong_count(),
        0,
        "dropping the limiter must release Redis client ownership"
    );
    assert!(
        weak.upgrade().is_none(),
        "retired Redis client must be fully released"
    );
}

#[tokio::test(start_paused = true)]
async fn repeated_failover_replacement_leaves_only_active_observer() {
    use ferrum_edge::plugins::utils::http_client::PluginHttpClient;
    use ferrum_edge::plugins::utils::rate_limit::{
        DynamicHttpRateLimitAlgorithm, RateLimitBackend,
    };

    let http = PluginHttpClient::default();
    let algorithm = DynamicHttpRateLimitAlgorithm::new();
    let mut retired_observers = Vec::new();
    let mut active: Option<RateLimitBackend<String, DynamicHttpRateLimitAlgorithm>> = None;

    for generation in 0..5 {
        let next: RateLimitBackend<String, DynamicHttpRateLimitAlgorithm> =
            RateLimitBackend::from_plugin_config(
                // Shared path used by rate_limiting / graphql / grpc_method_router.
                match generation % 3 {
                    0 => "rate_limiting",
                    1 => "graphql",
                    _ => "grpc_method_router",
                },
                &json!({
                    "sync_mode": "redis",
                    "redis_url": format!("redis://127.0.0.1:{}/0", 9000 + generation),
                    "redis_key_prefix": format!("gen:{generation}"),
                    "redis_health_check_interval_seconds": 1,
                }),
                &http,
                algorithm,
            )
            .expect("failover backend");
        let next_abort = next
            .health_observer_abort_for_test()
            .expect("active observer");
        if let Some(prev) = active.replace(next) {
            let prev_abort = prev
                .health_observer_abort_for_test()
                .expect("retired observer");
            drop(prev);
            retired_observers.push(prev_abort);
        }
        assert!(!next_abort.is_finished());
    }

    for _ in 0..30 {
        if retired_observers.iter().all(|a| a.is_finished()) {
            break;
        }
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(1)).await;
    }
    assert!(
        retired_observers.iter().all(|a| a.is_finished()),
        "every retired generation observer must stop"
    );
    let active_abort = active
        .as_ref()
        .and_then(|b| b.health_observer_abort_for_test())
        .expect("active generation");
    assert!(
        !active_abort.is_finished(),
        "only the active generation observer may remain"
    );
}

// ── WATCH fencing connection type + fail-closed disconnect (GHSA-f72h) ────

/// Static pin: ownership CAS helpers must dial a non-reconnecting
/// `MultiplexedConnection`, never a transparently-reconnecting
/// `ConnectionManager` that can drop WATCH state across a reconnect.
#[test]
fn watch_transaction_path_pins_multiplexed_connection_not_connection_manager() {
    let source = include_str!("../../../src/plugins/utils/redis_rate_limiter.rs");
    assert!(
        source.contains(
            "async fn get_dedicated_connection(&self) -> Option<redis::aio::MultiplexedConnection>"
        ),
        "get_dedicated_connection must return MultiplexedConnection"
    );
    assert!(
        !source.contains(
            "async fn get_dedicated_connection(&self) -> Option<redis::aio::ConnectionManager>"
        ),
        "get_dedicated_connection must not return ConnectionManager"
    );
    assert!(
        source.contains("client.get_multiplexed_async_connection_with_config"),
        "dedicated path must dial MultiplexedConnection directly"
    );

    let type_name = RedisRateLimitClient::dedicated_watch_connection_type_name_for_test();
    assert_eq!(
        type_name,
        std::any::type_name::<redis::aio::MultiplexedConnection>()
    );
    assert!(
        !type_name.contains("ConnectionManager"),
        "WATCH helper type must not be ConnectionManager: {type_name}"
    );

    for marker in [
        "pub async fn delete_if_value_matches",
        "pub async fn set_bytes_with_expire_if_value_matches",
    ] {
        let start = source
            .find(marker)
            .unwrap_or_else(|| panic!("missing helper {marker}"));
        let rest = &source[start..];
        let end = rest[1..]
            .find("\n    pub async fn ")
            .map(|i| i + 1)
            .unwrap_or(rest.len().min(12_000));
        let body = &rest[..end];
        assert!(
            body.contains("get_dedicated_connection()"),
            "{marker} must use get_dedicated_connection"
        );
        let brace = body
            .find('{')
            .unwrap_or_else(|| panic!("{marker} missing body"));
        let impl_body = &body[brace..];
        assert!(
            !impl_body.contains("get_connection()"),
            "{marker} must not use the shared pooled connection path"
        );
        assert!(
            !impl_body.contains("ConnectionManager"),
            "{marker} implementation must not reference ConnectionManager"
        );
        // Mismatch path + GET-error path must both attempt UNWATCH (fail closed).
        assert!(
            impl_body.matches("UNWATCH").count() >= 2,
            "{marker} must UNWATCH on pre-MULTI mismatch and GET failure"
        );
    }
}

/// Accept TCP, complete the redis-rs handshake with +OK replies, answer the
/// first WATCH with +OK, then drop the socket before GET/EXEC. Counts SET/DEL
/// payloads so a fail-open unconditional write would be observable.
async fn spawn_watch_then_drop_redis_server() -> (u16, oneshot::Sender<()>, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("local_addr").port();
    let writes = Arc::new(AtomicUsize::new(0));
    let writes_task = Arc::clone(&writes);
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                accepted = listener.accept() => {
                    let Ok((mut stream, _)) = accepted else { break; };
                    let writes = Arc::clone(&writes_task);
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 16 * 1024];
                        let mut pending = Vec::new();
                        loop {
                            let n = match stream.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => n,
                            };
                            pending.extend_from_slice(&buf[..n]);
                            if pending
                                .windows(b"$3\r\nSET\r\n".len())
                                .any(|w| w == b"$3\r\nSET\r\n")
                                || pending
                                    .windows(b"$3\r\nDEL\r\n".len())
                                    .any(|w| w == b"$3\r\nDEL\r\n")
                            {
                                writes.fetch_add(1, Ordering::Relaxed);
                            }
                            if pending
                                .windows(b"$5\r\nWATCH\r\n".len())
                                .any(|w| w == b"$5\r\nWATCH\r\n")
                            {
                                let _ = stream.write_all(b"+OK\r\n").await;
                                // Drop after acknowledging WATCH so GET/EXEC
                                // observe a dead socket with no watch state.
                                break;
                            }
                            let commands =
                                pending.iter().filter(|&&b| b == b'*').count().max(1);
                            let mut reply = Vec::new();
                            for _ in 0..commands {
                                reply.extend_from_slice(b"+OK\r\n");
                            }
                            if stream.write_all(&reply).await.is_err() {
                                break;
                            }
                            pending.clear();
                        }
                    });
                }
            }
        }
    });

    (port, shutdown_tx, writes)
}

#[tokio::test]
async fn watch_cas_helpers_fail_closed_when_connection_drops_after_watch() {
    let (port, shutdown, writes) = spawn_watch_then_drop_redis_server().await;
    let mut config = make_config(&format!("redis://127.0.0.1:{port}/0"), false);
    config.connect_timeout_seconds = 5;
    config.health_check_interval_seconds = 60;
    let client = redis_rate_limit_client_for_test(config);

    let set_result = client
        .set_bytes_with_expire_if_value_matches("fence-key", b"expected", b"stale", 60)
        .await;
    assert!(
        set_result.is_err(),
        "disconnect after WATCH must fail closed, got {set_result:?}"
    );

    let delete_result = client
        .delete_if_value_matches("fence-key", b"expected")
        .await;
    assert!(
        delete_result.is_err(),
        "disconnect after WATCH must fail closed on delete, got {delete_result:?}"
    );

    assert_eq!(
        writes.load(Ordering::Relaxed),
        0,
        "a dropped WATCH sequence must not publish SET/DEL"
    );
    assert!(
        !client.is_available(),
        "I/O failure must mark Redis unavailable"
    );
    assert!(
        client.health_checker_started_for_test(),
        "a dedicated command failure must arm recovery instead of pinning fail-closed consumers \
         unavailable until reload"
    );

    let _ = shutdown.send(());
}

/// Validation diagnostics on the shared Redis admission path must name the
/// field/shape without echoing rejected values, URLs, or credential-bearing
/// config objects (request_deduplication reaches this helper).
#[test]
fn redis_config_validation_diagnostics_are_value_redacted() {
    const PASSWORD: &str = "sentinel-redis-password-9f21c8a4";
    const USER: &str = "sentinel-redis-user-6c38";
    const TOKEN: &str = "sentinel-query-token-4a57";

    let leaked_shape = json!(format!(
        "redis://{USER}:{PASSWORD}@cache.internal:6379/0?auth={TOKEN}"
    ));
    let err = RedisConfig::from_plugin_config(&leaked_shape, "ferrum:test")
        .expect_err("non-object config must be rejected");
    assert!(
        err.contains("must be a JSON object"),
        "unexpected non-object diagnostic: {err}"
    );
    for secret in [PASSWORD, USER, TOKEN, "redis://", "cache.internal"] {
        assert!(
            !err.contains(secret),
            "non-object diagnostic must not echo {secret:?}: {err}"
        );
    }

    let sync_err = RedisConfig::from_plugin_config(
        &json!({
            "sync_mode": format!("redis-with-{PASSWORD}"),
            "redis_url": format!("redis://{USER}:{PASSWORD}@cache.internal:6379/0"),
        }),
        "ferrum:test",
    )
    .expect_err("invalid sync_mode must be rejected");
    assert!(
        sync_err.contains("'sync_mode'") && sync_err.contains("'local' or 'redis'"),
        "unexpected sync_mode diagnostic: {sync_err}"
    );
    for secret in [PASSWORD, USER] {
        assert!(
            !sync_err.contains(secret),
            "sync_mode diagnostic must not echo {secret:?}: {sync_err}"
        );
    }

    let url_err = RedisConfig::from_plugin_config(
        &json!({
            "sync_mode": "redis",
            "redis_url": format!(
                "http://{USER}:{PASSWORD}@cache.internal:6379/0?auth={TOKEN}#{PASSWORD}"
            ),
        }),
        "ferrum:test",
    )
    .expect_err("non-redis scheme must be rejected");
    assert!(
        url_err.contains("'redis_url'") && url_err.contains("scheme"),
        "unexpected url diagnostic: {url_err}"
    );
    for secret in [PASSWORD, USER, TOKEN, "http://", "cache.internal"] {
        assert!(
            !url_err.contains(secret),
            "redis_url diagnostic must not echo {secret:?}: {url_err}"
        );
    }

    let parse_err = RedisConfig::from_plugin_config(
        &json!({
            "sync_mode": "redis",
            "redis_url": format!("not a url {USER}:{PASSWORD}?auth={TOKEN}"),
        }),
        "ferrum:test",
    )
    .expect_err("unparseable redis_url must be rejected");
    assert!(
        parse_err.contains("'redis_url'") && parse_err.contains("valid URL"),
        "unexpected parse diagnostic: {parse_err}"
    );
    for secret in [PASSWORD, USER, TOKEN] {
        assert!(
            !parse_err.contains(secret),
            "parse diagnostic must not echo {secret:?}: {parse_err}"
        );
    }
}

// ── Redis topology screening (GHSA-87rq-v4hx-8rcq) ────────────────────────
//
// The shared client is not Cluster-aware. Pointing an enforcement plugin at a
// Redis Cluster endpoint used to surface only as "Redis is down", which silently
// turned one distributed budget into one budget per gateway process. These
// prove the endpoint is screened proactively (INFO CLUSTER) and reactively
// (Cluster-only error codes), and that the rejection is terminal.

#[test]
fn parse_cluster_enabled_recognizes_only_a_reported_value() {
    use ferrum_edge::_test_support::parse_cluster_enabled;

    assert_eq!(
        parse_cluster_enabled("# Cluster\r\ncluster_enabled:1\r\n"),
        Some(true)
    );
    assert_eq!(
        parse_cluster_enabled("# Cluster\r\ncluster_enabled:0\r\n"),
        Some(false)
    );
    // Any non-zero value counts as enabled.
    assert_eq!(parse_cluster_enabled("cluster_enabled:2"), Some(true));
    // Absent / unparseable stays unknown so RESP-compatible servers that do not
    // report the field are never rejected by the proactive screen.
    assert_eq!(
        parse_cluster_enabled("# Server\r\nredis_version:7.2.4"),
        None
    );
    assert_eq!(parse_cluster_enabled(""), None);
    assert_eq!(parse_cluster_enabled("cluster_enabled:"), None);
    assert_eq!(parse_cluster_enabled("cluster_enabled_extra:1"), None);
}

#[test]
fn cluster_topology_codes_are_terminal_but_outage_codes_are_not() {
    use ferrum_edge::_test_support::is_cluster_topology_code;

    for code in ["MOVED", "ASK", "CROSSSLOT", "CLUSTERDOWN", "TRYAGAIN"] {
        assert!(
            is_cluster_topology_code(Some(code)),
            "{code} proves an unsupported Cluster topology"
        );
    }
    // MASTERDOWN/LOADING are ordinary replication/availability failures and must
    // stay recoverable; None is a transport error, not a topology verdict.
    for code in ["MASTERDOWN", "LOADING", "ERR", "NOAUTH", "WRONGTYPE"] {
        assert!(
            !is_cluster_topology_code(Some(code)),
            "{code} must not permanently disable the endpoint"
        );
    }
    assert!(!is_cluster_topology_code(None));
}

#[test]
fn slot_keys_of_one_rate_key_share_a_hash_tag() {
    use ferrum_edge::_test_support::redis_slot_key;

    let config = || make_config("redis://127.0.0.1:6379/0", false);
    let prev = redis_slot_key(config(), "ip:1.2.3.4", &["41"]);
    let curr = redis_slot_key(config(), "ip:1.2.3.4", &["42"]);
    assert_eq!(prev, "{ferrum%3Atest:ip%3A1.2.3.4}:41");
    assert_eq!(curr, "{ferrum%3Atest:ip%3A1.2.3.4}:42");

    fn hash_tag(key: &str) -> &str {
        let open = key.find('{').expect("hash tag opens");
        let close = key[open + 1..].find('}').expect("hash tag closes") + open + 1;
        &key[open + 1..close]
    }
    assert_eq!(
        hash_tag(&prev),
        hash_tag(&curr),
        "previous and current window buckets must land in one slot"
    );

    // The UDP datagram/byte pair of one client shares a slot too.
    let datagrams = redis_slot_key(config(), "udp:1.2.3.4", &["datagrams", "7"]);
    let bytes = redis_slot_key(config(), "udp:1.2.3.4", &["bytes", "7"]);
    assert_eq!(hash_tag(&datagrams), hash_tag(&bytes));

    // Distinct rate keys still spread across slots — the tag must not collapse
    // an entire policy onto one hot slot.
    let other = redis_slot_key(config(), "ip:5.6.7.8", &["42"]);
    assert_ne!(hash_tag(&curr), hash_tag(&other));

    // Caller-controlled braces cannot terminate the tag early, and delimiters
    // are escaped so distinct prefix/rate-key pairs cannot collapse onto the
    // same logical tag.
    let hostile = redis_slot_key(config(), "identity}:x%y{z", &["42"]);
    assert_eq!(hash_tag(&hostile), "ferrum%3Atest:identity%7D%3Ax%25y%7Bz");
    assert_ne!(hash_tag(&hostile), hash_tag(&curr));
}

/// Parse one complete RESP command array out of `buf`.
///
/// Returns the uppercased command name and the number of bytes it consumed, or
/// `None` when the buffer holds only a partial command. Framing has to be exact:
/// a fake server that guesses reply counts from a read chunk (say, by counting
/// `*` bytes) answers a split or coalesced write with the wrong number of
/// replies, and an extra reply drives the client's multiplexed connection into
/// an internal accounting underflow instead of the behavior under test.
fn parse_resp_command(buf: &[u8]) -> Option<(String, usize)> {
    fn read_line(buf: &[u8], from: usize) -> Option<(&[u8], usize)> {
        let rest = buf.get(from..)?;
        let idx = rest.windows(2).position(|w| w == b"\r\n")?;
        Some((&rest[..idx], from + idx + 2))
    }

    if *buf.first()? != b'*' {
        return None;
    }
    let (count_line, mut cursor) = read_line(buf, 1)?;
    let argc: usize = std::str::from_utf8(count_line).ok()?.parse().ok()?;
    let mut name = None;
    for arg in 0..argc {
        if *buf.get(cursor)? != b'$' {
            return None;
        }
        let (len_line, after_len) = read_line(buf, cursor + 1)?;
        let len: usize = std::str::from_utf8(len_line).ok()?.parse().ok()?;
        let end = after_len.checked_add(len)?;
        let payload = buf.get(after_len..end)?;
        if buf.get(end..end + 2)? != b"\r\n" {
            return None;
        }
        if arg == 0 {
            name = Some(String::from_utf8_lossy(payload).to_uppercase());
        }
        cursor = end + 2;
    }
    Some((name?, cursor))
}

/// Minimal RESP server: replies `+OK` to every command except `INFO`, which gets
/// `info_payload` as a bulk string. Once `after_info_reply` is set, every later
/// command receives that raw reply instead of `+OK` — except `MULTI`, which is
/// still answered `+OK` because that is what a real Cluster node does: it opens
/// the transaction and redirects the keyed commands queued inside it. Counts
/// accepted TCP connections and observed `INCR` commands.
async fn spawn_topology_redis_server(
    info_payload: &'static str,
    after_info_reply: Option<&'static str>,
) -> (u16, oneshot::Sender<()>, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("local_addr").port();
    let accepts = Arc::new(AtomicUsize::new(0));
    let incrs = Arc::new(AtomicUsize::new(0));
    let accepts_task = Arc::clone(&accepts);
    let incrs_task = Arc::clone(&incrs);
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                accepted = listener.accept() => {
                    let Ok((mut stream, _)) = accepted else { break; };
                    accepts_task.fetch_add(1, Ordering::Relaxed);
                    let incrs = Arc::clone(&incrs_task);
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 16 * 1024];
                        let mut pending: Vec<u8> = Vec::new();
                        let mut info_seen = false;
                        loop {
                            let n = match stream.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => n,
                            };
                            pending.extend_from_slice(&buf[..n]);
                            let mut reply = Vec::new();
                            // Exactly one reply per fully received command, so
                            // the client's in-flight accounting always matches.
                            while let Some((name, consumed)) = parse_resp_command(&pending) {
                                pending.drain(..consumed);
                                if name == "INCR" {
                                    incrs.fetch_add(1, Ordering::Relaxed);
                                }
                                if name == "INFO" {
                                    info_seen = true;
                                    reply.extend_from_slice(
                                        format!("${}\r\n{info_payload}\r\n", info_payload.len())
                                            .as_bytes(),
                                    );
                                } else if info_seen
                                    && let Some(raw) = after_info_reply
                                    && name != "MULTI"
                                {
                                    reply.extend_from_slice(raw.as_bytes());
                                } else {
                                    reply.extend_from_slice(b"+OK\r\n");
                                }
                            }
                            if reply.is_empty() {
                                continue;
                            }
                            if stream.write_all(&reply).await.is_err() {
                                break;
                            }
                        }
                    });
                }
            }
        }
    });

    (port, shutdown_tx, accepts, incrs)
}

/// A Cluster endpoint must be refused at connect, before it can serve a single
/// policy operation, and must never be redialed by the recovery checker.
#[tokio::test]
async fn cluster_enabled_endpoint_is_refused_before_serving_policy_operations() {
    let (port, shutdown, accepts, incrs) =
        spawn_topology_redis_server("# Cluster\r\ncluster_enabled:1\r\n", None).await;
    let mut config = make_config(&format!("redis://127.0.0.1:{port}/0"), false);
    config.connect_timeout_seconds = 5;
    config.health_check_interval_seconds = 3600;
    config.pool_size = 1;
    let client = redis_rate_limit_client_for_test(config);

    let first = client.incr_with_expire("{ferrum:test:key}:1", 60).await;
    assert!(first.is_err(), "a Cluster endpoint must not serve counters");
    assert!(
        client.is_topology_unsupported(),
        "cluster_enabled:1 must be recorded as an unsupported topology"
    );
    assert!(!client.is_available(), "topology rejection is terminal");
    assert_eq!(
        incrs.load(Ordering::Relaxed),
        0,
        "no counter command may reach a Cluster endpoint"
    );

    let dials_after_first = accepts.load(Ordering::Relaxed);
    let second = client.incr_with_expire("{ferrum:test:key}:1", 60).await;
    assert!(second.is_err());
    assert_eq!(
        accepts.load(Ordering::Relaxed),
        dials_after_first,
        "a rejected topology must never be redialed"
    );

    let _ = shutdown.send(());
}

/// A server that hides its topology from `INFO` is still caught the first time
/// it answers with a Cluster-only redirection.
///
/// The redirection has to be caught through the shape a real Cluster node
/// produces: `incr_with_expire` sends a `MULTI`/`EXEC` transaction, the node
/// accepts `MULTI` and redirects the keyed commands at queue time, and the
/// client surfaces one aborted-transaction error whose *own* code is
/// `EXECABORT` with the `MOVED` replies nested inside it.
#[tokio::test]
async fn cluster_redirection_error_permanently_disables_the_endpoint() {
    let (port, shutdown, accepts, _incrs) = spawn_topology_redis_server(
        "# Cluster\r\ncluster_enabled:0\r\n",
        Some("-MOVED 1234 127.0.0.1:7001\r\n"),
    )
    .await;
    let mut config = make_config(&format!("redis://127.0.0.1:{port}/0"), false);
    config.connect_timeout_seconds = 5;
    config.health_check_interval_seconds = 3600;
    config.pool_size = 1;
    let client = redis_rate_limit_client_for_test(config);

    let first = client.incr_with_expire("{ferrum:test:key}:1", 60).await;
    assert!(
        first.is_err(),
        "a MOVED redirection must fail the operation"
    );
    assert!(
        client.is_topology_unsupported(),
        "MOVED proves the endpoint is a Cluster this client cannot enforce against"
    );
    assert!(!client.is_available());

    let dials = accepts.load(Ordering::Relaxed);
    let second = client.incr_with_expire("{ferrum:test:key}:1", 60).await;
    assert!(second.is_err());
    assert_eq!(
        accepts.load(Ordering::Relaxed),
        dials,
        "topology rejection must stop reconnection attempts"
    );

    let _ = shutdown.send(());
}

// ── Bounded topology screening + terminal rejection under concurrency ──────
//   (GHSA-87rq-v4hx-8rcq)
//
// Two properties the screen has to hold beyond "a Cluster is refused":
//
// 1. The proactive `INFO CLUSTER` probe is bounded by the configured
//    `redis_connect_timeout_seconds`. A server can accept and authenticate a
//    connection and then never answer `INFO`; an unbounded screen would hang
//    the first enforcement operation instead of refusing it. A probe that does
//    not complete is an ordinary outage — never proof of Cluster topology — and
//    its unscreened connection must not carry a policy command.
// 2. Rejection is terminal *under concurrency*. A connection, command, or
//    recovery probe that completes successfully after another task proved
//    Cluster topology must not be published, must not be returned as a success,
//    and must not make a failover health observer advertise a recovery.

/// RESP wire form of the command-name bulk string the fake server matches on.
const INFO_CMD: &[u8] = b"$4\r\nINFO\r\n";
const GET_CMD: &[u8] = b"$3\r\nGET\r\n";

/// How the fake server answers `INFO CLUSTER`.
#[derive(Clone, Copy)]
enum InfoBehavior {
    /// Answer with this text as a bulk string.
    Payload(&'static str),
    /// Answer with these raw RESP bytes (an error line, for example).
    Raw(&'static str),
    /// Accept and authenticate the connection, then never answer `INFO`.
    Never,
    /// Answer the FIRST screen with this text, then report Cluster topology on
    /// every later screen. Models an endpoint that is re-pointed at a Cluster
    /// node after Ferrum already screened and cached a connection to it, so the
    /// re-screen on the post-disconnect reconnect is what must catch it.
    PayloadThenCluster(&'static str),
}

const CLUSTER_INFO: &str = "# Cluster\r\ncluster_enabled:1\r\n";

struct ScreenedServer {
    port: u16,
    shutdown: oneshot::Sender<()>,
    accepts: Arc<AtomicUsize>,
    infos: Arc<AtomicUsize>,
    gets: Arc<AtomicUsize>,
}

fn chunk_contains(chunk: &[u8], needle: &[u8]) -> bool {
    chunk.windows(needle.len()).any(|window| window == needle)
}

/// Number of RESP command arrays in one read chunk — the redis crate pipelines
/// its connection setup, so a single read can carry several commands.
fn command_count(chunk: &[u8]) -> usize {
    chunk.iter().filter(|&&byte| byte == b'*').count().max(1)
}

/// Minimal RESP server: `+OK` to every command except `INFO` (per
/// [`InfoBehavior`]) and `GET` (always a nil bulk string). `info_delay` /
/// `get_delay` hold the corresponding reply *after* counting it, so a test can
/// land a concurrent topology rejection while that exact operation is in flight.
async fn spawn_screened_redis_server(
    info: InfoBehavior,
    info_delay: Duration,
    get_delay: Duration,
) -> ScreenedServer {
    spawn_screened_redis_server_with_drop(info, info_delay, get_delay, None).await
}

/// As [`spawn_screened_redis_server`], plus `drop_after_gets`: once a connection
/// has answered that many `GET`s, the server closes the socket instead of
/// replying. That is the physical disconnect a transparently reconnecting
/// redis-rs `ConnectionManager` would paper over without re-screening.
async fn spawn_screened_redis_server_with_drop(
    info: InfoBehavior,
    info_delay: Duration,
    get_delay: Duration,
    drop_after_gets: Option<usize>,
) -> ScreenedServer {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("local_addr").port();
    let accepts = Arc::new(AtomicUsize::new(0));
    let infos = Arc::new(AtomicUsize::new(0));
    let gets = Arc::new(AtomicUsize::new(0));
    let accepts_task = Arc::clone(&accepts);
    let infos_task = Arc::clone(&infos);
    let gets_task = Arc::clone(&gets);
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                accepted = listener.accept() => {
                    let Ok((mut stream, _)) = accepted else { break; };
                    accepts_task.fetch_add(1, Ordering::Relaxed);
                    let infos = Arc::clone(&infos_task);
                    let gets = Arc::clone(&gets_task);
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 16 * 1024];
                        // Per-connection GET count, so the drop applies to each
                        // physical socket independently.
                        let mut conn_gets = 0usize;
                        loop {
                            let n = match stream.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => n,
                            };
                            let chunk = &buf[..n];
                            let mut reply: Vec<u8> = Vec::new();
                            if chunk_contains(chunk, INFO_CMD) {
                                let screen_index = infos.fetch_add(1, Ordering::Relaxed);
                                tokio::time::sleep(info_delay).await;
                                match info {
                                    InfoBehavior::Payload(text) => {
                                        let len = text.len();
                                        let bulk = format!("${len}\r\n{text}\r\n");
                                        reply.extend_from_slice(bulk.as_bytes());
                                    }
                                    InfoBehavior::PayloadThenCluster(first) => {
                                        let text = if screen_index == 0 {
                                            first
                                        } else {
                                            CLUSTER_INFO
                                        };
                                        let len = text.len();
                                        let bulk = format!("${len}\r\n{text}\r\n");
                                        reply.extend_from_slice(bulk.as_bytes());
                                    }
                                    InfoBehavior::Raw(raw) => {
                                        reply.extend_from_slice(raw.as_bytes());
                                    }
                                    // Accepted, authenticated, silent.
                                    InfoBehavior::Never => continue,
                                }
                            } else if chunk_contains(chunk, GET_CMD) {
                                gets.fetch_add(1, Ordering::Relaxed);
                                conn_gets += 1;
                                if drop_after_gets.is_some_and(|limit| conn_gets > limit) {
                                    // Physical disconnect: no reply, socket closed.
                                    break;
                                }
                                tokio::time::sleep(get_delay).await;
                                reply.extend_from_slice(b"$-1\r\n");
                            } else {
                                for _ in 0..command_count(chunk) {
                                    reply.extend_from_slice(b"+OK\r\n");
                                }
                            }
                            if stream.write_all(&reply).await.is_err() {
                                break;
                            }
                        }
                    });
                }
            }
        }
    });

    ScreenedServer {
        port,
        shutdown: shutdown_tx,
        accepts,
        infos,
        gets,
    }
}

fn screened_client(port: u16, connect_timeout_seconds: u64) -> RedisRateLimitClient {
    let url = format!("redis://127.0.0.1:{port}/0");
    let mut config = make_config(&url, false);
    config.connect_timeout_seconds = connect_timeout_seconds;
    // Long enough that no background recovery dial happens during a test.
    config.health_check_interval_seconds = 3600;
    config.pool_size = 1;
    redis_rate_limit_client_for_test(config)
}

/// Await a server-side counter reaching `target`, so a race is landed at a known
/// point rather than on a hopeful sleep.
async fn wait_for_count(counter: &Arc<AtomicUsize>, target: usize, what: &str) {
    for _ in 0..6_000 {
        if counter.load(Ordering::Relaxed) >= target {
            return;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    panic!("{what} never reached {target}");
}

/// A RESP-compatible server that simply does not report `cluster_enabled` is not
/// proven to be anything, so it must keep serving policy operations.
#[tokio::test]
async fn a_server_without_a_cluster_enabled_field_still_serves_policy_operations() {
    let info = InfoBehavior::Payload("# Server\r\nredis_version:7.2.4\r\n");
    let server = spawn_screened_redis_server(info, Duration::ZERO, Duration::ZERO).await;
    let client = screened_client(server.port, 5);

    let served = client.get_bytes("{ferrum%3Atest:probe}").await;
    assert_eq!(
        served,
        Ok(None),
        "an unknown topology must fall through to the reactive screen"
    );
    assert!(!client.is_topology_unsupported());
    assert!(client.is_available());
    assert_eq!(server.gets.load(Ordering::Relaxed), 1);

    let _ = server.shutdown.send(());
}

/// A server that answers `INFO` with an ordinary command error (unknown command,
/// restricted ACL) keeps the documented compatibility behavior.
#[tokio::test]
async fn an_unsupported_info_command_error_keeps_the_endpoint_usable() {
    let info = InfoBehavior::Raw("-ERR unknown command 'INFO'\r\n");
    let server = spawn_screened_redis_server(info, Duration::ZERO, Duration::ZERO).await;
    let client = screened_client(server.port, 5);

    let served = client.get_bytes("{ferrum%3Atest:probe}").await;
    assert_eq!(
        served,
        Ok(None),
        "a server error reply to INFO is not proof of Cluster topology"
    );
    assert!(!client.is_topology_unsupported());
    assert!(client.is_available());

    let _ = server.shutdown.send(());
}

/// An `INFO` answered with a Cluster-only wire code is itself proof, even when
/// the server never reports `cluster_enabled`.
#[tokio::test]
async fn a_cluster_wire_error_on_the_info_probe_is_terminal() {
    let info = InfoBehavior::Raw("-MOVED 1234 127.0.0.1:7001\r\n");
    let server = spawn_screened_redis_server(info, Duration::ZERO, Duration::ZERO).await;
    let client = screened_client(server.port, 5);

    let refused = client.get_bytes("{ferrum%3Atest:probe}").await;
    assert!(
        refused.is_err(),
        "a Cluster endpoint must not serve a policy operation"
    );
    assert!(
        client.is_topology_unsupported(),
        "a Cluster wire code on the screen proves the topology"
    );
    assert!(!client.is_available());
    assert_eq!(
        server.gets.load(Ordering::Relaxed),
        0,
        "no policy command may reach a refused endpoint"
    );

    let _ = server.shutdown.send(());
}

/// The finding that motivated the deadline: a server that accepts and
/// authenticates but never answers `INFO` must not hang the first enforcement
/// operation. The probe is bounded by `redis_connect_timeout_seconds`, and an
/// unanswered screen is an outage — not proof of Cluster topology.
#[tokio::test]
async fn an_endpoint_that_never_answers_info_fails_closed_within_the_connect_timeout() {
    let info = InfoBehavior::Never;
    let server = spawn_screened_redis_server(info, Duration::ZERO, Duration::ZERO).await;
    // One-second connect timeout, which now also bounds the topology probe.
    let client = screened_client(server.port, 1);

    let started = std::time::Instant::now();
    let refused = client.get_bytes("{ferrum%3Atest:probe}").await;
    let elapsed = started.elapsed();
    assert!(
        refused.is_err(),
        "an unscreened endpoint must fail closed instead of serving the command"
    );
    assert!(
        elapsed < Duration::from_secs(10),
        "the topology probe must be bounded by redis_connect_timeout_seconds, took {elapsed:?}"
    );
    assert!(!client.is_available());
    assert!(
        !client.is_topology_unsupported(),
        "an unanswered probe is a retryable outage, not proof of Cluster topology"
    );
    assert_eq!(server.infos.load(Ordering::Relaxed), 1);
    assert_eq!(
        server.gets.load(Ordering::Relaxed),
        0,
        "a policy command must never run on a connection that was not screened"
    );

    let _ = server.shutdown.send(());
}

/// A command whose reply lands *after* another task proved Cluster topology must
/// be reported as a failure, so the consumer's `redis_failure_policy` governs.
/// Over-counting one operation is safer than admitting traffic against a
/// topology this client cannot enforce on.
#[tokio::test]
async fn a_command_completing_after_a_topology_rejection_fails_closed() {
    let info = InfoBehavior::Payload("# Cluster\r\ncluster_enabled:0\r\n");
    let held = Duration::from_millis(300);
    let server = spawn_screened_redis_server(info, Duration::ZERO, held).await;
    let client = Arc::new(screened_client(server.port, 5));

    // Control: this fake really does answer the command successfully, so the
    // failure asserted below is attributable to the rejection alone.
    let control = client.get_bytes("{ferrum%3Atest:control}").await;
    assert_eq!(control, Ok(None));
    assert!(client.is_available());

    let racer = Arc::clone(&client);
    let raced_key = "{ferrum%3Atest:raced}";
    let inflight = tokio::spawn(async move { racer.get_bytes(raced_key).await });
    // The server now holds the racing GET's reply.
    wait_for_count(&server.gets, 2, "racing GET").await;
    client.mark_topology_unsupported_for_test();

    let raced = inflight.await.expect("racing task");
    assert!(
        raced.is_err(),
        "a command that completed after the rejection must not be a success"
    );
    assert!(
        !client.is_available(),
        "topology rejection must stay terminal for this client generation"
    );
    assert!(
        !client.observer_sees_available_for_test(),
        "a failover health observer must never see a refused endpoint as available"
    );

    // Later operations, and the redials they would trigger, stay disabled.
    let dials = server.accepts.load(Ordering::Relaxed);
    let after = client.get_bytes("{ferrum%3Atest:after}").await;
    assert!(after.is_err());
    assert_eq!(
        server.accepts.load(Ordering::Relaxed),
        dials,
        "a rejected topology must never be redialed"
    );

    let _ = server.shutdown.send(());
}

/// A connection still being screened when another task proves Cluster topology
/// must never be published to the hot path, even though its own screen passed.
#[tokio::test]
async fn a_connection_screened_across_a_topology_rejection_is_never_published() {
    let info = InfoBehavior::Payload("# Cluster\r\ncluster_enabled:0\r\n");
    let held = Duration::from_millis(300);
    let server = spawn_screened_redis_server(info, held, Duration::ZERO).await;
    let client = Arc::new(screened_client(server.port, 5));

    let connecting = Arc::clone(&client);
    let inflight = tokio::spawn(async move { connecting.connect_cached_for_test().await });
    // The server now holds the screen's INFO reply.
    wait_for_count(&server.infos, 1, "screening INFO").await;
    client.mark_topology_unsupported_for_test();

    let published = inflight.await.expect("connecting task");
    assert!(
        !published,
        "a connection screened across a rejection must not be published"
    );
    assert_eq!(
        client.cached_pool_cardinality_for_test(),
        0,
        "no pool slot may hold a connection to a refused endpoint"
    );
    assert!(!client.is_available());
    assert!(!client.observer_sees_available_for_test());

    let _ = server.shutdown.send(());
}

/// The recovery checker's own race: its `PING` and topology screen both succeed,
/// but a rejection landed while the probe was in flight. It must not restore
/// availability, so no observer can advertise a false recovery.
#[tokio::test]
async fn a_recovery_probe_completing_after_a_rejection_advertises_no_recovery() {
    let info = InfoBehavior::Payload("# Cluster\r\ncluster_enabled:0\r\n");
    let held = Duration::from_millis(300);
    let server = spawn_screened_redis_server(info, held, Duration::ZERO).await;
    let url = format!("redis://127.0.0.1:{}/0", server.port);
    let mut config = make_config(&url, false);
    config.connect_timeout_seconds = 5;
    // Probe once per second so the race window is reached promptly.
    config.health_check_interval_seconds = 1;
    config.pool_size = 1;
    let client = redis_rate_limit_client_for_test(config);

    // Enter the state an outage produces: unavailable, recovery checker running.
    client.mark_unavailable_for_test();
    assert!(client.health_checker_started_for_test());

    // Let the recovery probe reach its topology screen, then prove Cluster
    // topology from another task while that probe is still in flight.
    wait_for_count(&server.infos, 1, "recovery screen INFO").await;
    client.mark_topology_unsupported_for_test();

    // The probe's PING and INFO both succeed after the rejection landed.
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert!(
        !client.is_available(),
        "a successful recovery probe must not resurrect a refused endpoint"
    );
    assert!(
        !client.observer_sees_available_for_test(),
        "no false recovery may be advertised to a failover health observer"
    );
    assert!(client.is_topology_unsupported());

    let _ = server.shutdown.send(());
}

// ── Cached pool must not transparently reconnect (GHSA-87rq root review) ──
//
// redis-rs `ConnectionManager` re-establishes its physical socket internally.
// Ferrum screens DNS, egress, and `INFO CLUSTER` only when it creates a
// connection itself, so a manager in the hot-path pool could replace a screened
// socket with an unscreened one after any blip. The pool therefore caches plain
// `MultiplexedConnection`s: a broken connection surfaces its I/O error, the pool
// is cleared, and the next operation re-establishes through the screened path.

/// Static + type pin: the hot-path pool caches a non-reconnecting
/// `MultiplexedConnection`, never a `ConnectionManager`, and no connection
/// helper constructs one.
#[test]
fn cached_pool_pins_multiplexed_connection_not_connection_manager() {
    let source = include_str!("../../../src/plugins/utils/redis_rate_limiter.rs");

    assert!(
        source.contains("connection: ArcSwap<Option<redis::aio::MultiplexedConnection>>"),
        "pool slots must cache MultiplexedConnection"
    );
    assert!(
        !source.contains("ArcSwap<Option<redis::aio::ConnectionManager>>"),
        "pool slots must not cache a transparently reconnecting ConnectionManager"
    );
    assert!(
        source.contains(
            "async fn get_or_connect_slot(&self, idx: usize) -> Option<redis::aio::MultiplexedConnection>"
        ),
        "pooled establishment must return MultiplexedConnection"
    );
    assert!(
        source.contains(
            "async fn get_connection(&self) -> Option<redis::aio::MultiplexedConnection>"
        ),
        "pooled accessor must return MultiplexedConnection"
    );

    // No code path may construct a manager or its config any more.
    for banned in [
        "redis::aio::ConnectionManager::new",
        "redis::aio::ConnectionManagerConfig",
        "fn connect_manager",
    ] {
        assert!(
            !source.contains(banned),
            "obsolete ConnectionManager construction still present: {banned}"
        );
    }

    let type_name = RedisRateLimitClient::cached_pool_connection_type_name_for_test();
    assert_eq!(
        type_name,
        std::any::type_name::<redis::aio::MultiplexedConnection>()
    );
    assert!(
        !type_name.contains("ConnectionManager"),
        "pooled connection type must not be ConnectionManager: {type_name}"
    );

    // Both connect helpers dial multiplexed connections directly, and the
    // pooled path screens topology before publishing into the ArcSwap slot.
    let publish = source
        .find("slot.connection.store(Arc::new(Some(conn.clone())))")
        .expect("pooled publication site");
    let establish = source
        .find("match self.connect_multiplexed(client).await {")
        .expect("pooled establishment site");
    let screen = source[establish..publish]
        .find("self.screen_topology(&mut conn)")
        .expect("pooled path must screen topology before publishing");
    assert!(
        screen > 0,
        "topology screen must sit between connect and publication"
    );
}

/// A pooled connection that is physically disconnected must not be silently
/// replaced by redis-rs. The failing command fails, the pool is cleared, and the
/// re-established connection is screened again (`INFO CLUSTER` per socket).
#[tokio::test]
async fn pooled_reconnect_after_disconnect_reruns_the_topology_screen() {
    let info = InfoBehavior::Payload("# Cluster\r\ncluster_enabled:0\r\n");
    let server =
        spawn_screened_redis_server_with_drop(info, Duration::ZERO, Duration::ZERO, Some(1)).await;
    let client = screened_client(server.port, 5);

    // First operation establishes and screens exactly one physical connection.
    assert_eq!(client.get_bytes("{ferrum%3Atest:probe}").await, Ok(None));
    assert_eq!(server.accepts.load(Ordering::Relaxed), 1);
    assert_eq!(server.infos.load(Ordering::Relaxed), 1);
    assert_eq!(client.cached_pool_cardinality_for_test(), 1);

    // Second operation hits the server's disconnect. It must FAIL (not silently
    // ride a redis-rs reconnect) and must drop the cached slot.
    assert_eq!(
        client.get_bytes("{ferrum%3Atest:probe}").await,
        Err(()),
        "a disconnected pooled connection must fail the operation, not auto-reconnect"
    );
    assert_eq!(
        client.cached_pool_cardinality_for_test(),
        0,
        "an I/O failure must clear the cached pool"
    );
    assert_eq!(
        server.accepts.load(Ordering::Relaxed),
        1,
        "redis-rs must not have dialled a replacement connection on its own"
    );

    // Third operation re-establishes — through the full screened path.
    assert_eq!(client.get_bytes("{ferrum%3Atest:probe}").await, Ok(None));
    assert_eq!(
        server.accepts.load(Ordering::Relaxed),
        2,
        "recovery must open a new physical connection"
    );
    assert_eq!(
        server.infos.load(Ordering::Relaxed),
        2,
        "every newly established pooled connection must be topology-screened"
    );
    assert_eq!(
        client.cached_pool_cardinality_for_test(),
        1,
        "the pool stays bounded at redis_pool_size across reconnects"
    );

    let _ = server.shutdown.send(());
}

/// The topology-after-disconnect seam: an endpoint that screened clean, then
/// disconnected, then came back reporting Cluster topology must be caught by the
/// re-screen and refused terminally. A transparent reconnect would have skipped
/// that screen entirely and kept serving policy operations.
#[tokio::test]
async fn cluster_topology_appearing_after_a_disconnect_is_caught_by_the_rescreen() {
    let info = InfoBehavior::PayloadThenCluster("# Cluster\r\ncluster_enabled:0\r\n");
    let server =
        spawn_screened_redis_server_with_drop(info, Duration::ZERO, Duration::ZERO, Some(1)).await;
    let client = screened_client(server.port, 5);

    // Screened clean, serving normally.
    assert_eq!(client.get_bytes("{ferrum%3Atest:probe}").await, Ok(None));
    assert!(!client.is_topology_unsupported());

    // Disconnect fails the in-flight operation and clears the pool.
    assert_eq!(client.get_bytes("{ferrum%3Atest:probe}").await, Err(()));
    assert!(
        !client.is_topology_unsupported(),
        "an ordinary disconnect is an outage, never proof of Cluster topology"
    );

    // The reconnect re-screens and now sees cluster_enabled:1 — terminal refusal.
    assert_eq!(client.get_bytes("{ferrum%3Atest:probe}").await, Err(()));
    assert!(
        client.is_topology_unsupported(),
        "the post-disconnect re-screen must catch a Cluster endpoint"
    );
    assert!(!client.is_available());
    assert_eq!(client.cached_pool_cardinality_for_test(), 0);

    // Terminal: no further dialling of the refused endpoint.
    let accepts_at_rejection = server.accepts.load(Ordering::Relaxed);
    assert_eq!(client.get_bytes("{ferrum%3Atest:probe}").await, Err(()));
    assert_eq!(
        server.accepts.load(Ordering::Relaxed),
        accepts_at_rejection,
        "a refused topology must never be redialled"
    );

    let _ = server.shutdown.send(());
}

/// Every slot of a multi-slot pool is screened on establishment, and the pool
/// never exceeds `redis_pool_size` physical connections.
#[tokio::test]
async fn every_pool_slot_is_screened_and_the_pool_stays_bounded() {
    let info = InfoBehavior::Payload("# Cluster\r\ncluster_enabled:0\r\n");
    let server = spawn_screened_redis_server(info, Duration::ZERO, Duration::ZERO).await;
    let url = format!("redis://127.0.0.1:{}/0", server.port);
    let mut config = make_config(&url, false);
    config.pool_size = 3;
    config.health_check_interval_seconds = 3600;
    let client = redis_rate_limit_client_for_test(config);

    assert_eq!(client.warm_pool_for_test().await, 3);
    assert_eq!(client.cached_pool_cardinality_for_test(), 3);
    assert_eq!(server.accepts.load(Ordering::Relaxed), 3);
    assert_eq!(
        server.infos.load(Ordering::Relaxed),
        3,
        "each pool slot must be screened on establishment"
    );

    // Many more operations than slots must reuse the bounded pool, not dial.
    for _ in 0..12 {
        assert_eq!(client.get_bytes("{ferrum%3Atest:probe}").await, Ok(None));
    }
    assert_eq!(
        server.accepts.load(Ordering::Relaxed),
        3,
        "the round-robin pool must stay bounded at redis_pool_size"
    );
    assert_eq!(server.infos.load(Ordering::Relaxed), 3);
    assert_eq!(client.cached_pool_cardinality_for_test(), 3);

    let _ = server.shutdown.send(());
}

// ── Identity-bearing keys must never reach operational logs (GHSA-87rq) ───
//
// Redis/rate-limit keys embed the enforcement identity dimension: internal
// consumer usernames, `ctx.authenticated_identity`, and SPIFFE IDs. Emitting
// them in a warning writes those identities into every configured log sink at
// attacker-influenced rates. Diagnostics keep only bounded, non-identifying
// context (operation name, redacted endpoint, pool slot, plugin name, static
// topology reason, Redis error). Hashes/encodings are NOT an acceptable
// substitute — they are still per-identity correlators.

/// Static canary over the limiter surfaces that talk to the shared Redis client.
#[test]
fn limiter_log_statements_never_carry_identity_bearing_keys() {
    let sources: [(&str, &str); 8] = [
        (
            "src/plugins/utils/redis_rate_limiter.rs",
            include_str!("../../../src/plugins/utils/redis_rate_limiter.rs"),
        ),
        (
            "src/plugins/utils/rate_limit.rs",
            include_str!("../../../src/plugins/utils/rate_limit.rs"),
        ),
        (
            "src/plugins/rate_limiting.rs",
            include_str!("../../../src/plugins/rate_limiting.rs"),
        ),
        (
            "src/plugins/ai_rate_limiter.rs",
            include_str!("../../../src/plugins/ai_rate_limiter.rs"),
        ),
        (
            "src/plugins/ws_rate_limiting.rs",
            include_str!("../../../src/plugins/ws_rate_limiting.rs"),
        ),
        (
            "src/plugins/udp_rate_limiting.rs",
            include_str!("../../../src/plugins/udp_rate_limiting.rs"),
        ),
        // The remaining two Redis-backed enforcement consumers. They do not log
        // a rate key today, and this canary is what keeps that true: both build
        // an identity-bearing key (`limit_by` consumer/identity/SPIFFE/IP) and
        // both gained a fail-closed refusal arm here, which is exactly the kind
        // of edit that tends to add a "which key?" diagnostic.
        (
            "src/plugins/graphql.rs",
            include_str!("../../../src/plugins/graphql.rs"),
        ),
        (
            "src/plugins/grpc_method_router.rs",
            include_str!("../../../src/plugins/grpc_method_router.rs"),
        ),
    ];

    // `tracing` field syntax for an identity-bearing key, in every spelling the
    // limiter surfaces have used. The `%`/`?` sigils are required so an ordinary
    // `let previous_key = ...` binding is not a false positive — only a value
    // actually recorded into a log event matches.
    let banned_fields = [
        "rate_limit_key = %",
        "rate_limit_key = ?",
        "previous_key = %",
        "previous_key = ?",
        "current_key = %",
        "current_key = ?",
        "count_key = %",
        "count_key = ?",
        "total_key = %",
        "total_key = ?",
        "curr_key = %",
        "prev_key = %",
        "redis_key = %",
        "key = %key",
        "key = ?key",
        "key = %curr",
        "key = %prev",
        "key = %redis_key",
        "key = %self.make",
        // Reversible encodings / digests are not an acceptable substitute.
        "key_hash = %",
        "key_digest = %",
        "key_b64 = %",
    ];

    for (path, source) in sources {
        for banned in banned_fields {
            assert!(
                !source.contains(banned),
                "{path} logs an identity-bearing rate-limit key field: {banned}"
            );
        }
    }
}
