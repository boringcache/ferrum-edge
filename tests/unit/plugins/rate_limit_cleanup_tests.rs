//! Controllable-time coverage for shared rate-limit stale pruning (#2316).
//!
//! Periodic sweeps must reclaim idle keys below the hard cap while preserving
//! active keys, for every shared local algorithm and the Redis-fallback map.

use ferrum_edge::plugins::utils::http_client::PluginHttpClient;
use ferrum_edge::plugins::utils::rate_limit::{
    AiRateLimitOp, AiTokenRateAlgorithm, DynamicHttpRateLimitAlgorithm, DynamicRateLimitOp,
    LocalLimiter, RateLimitBackend, RateLimitWindowSpec, UdpRateLimitAlgorithm, UdpRateLimitOp,
    WsFrameRateAlgorithm, WsRateLimitOp,
};
use serde_json::json;
use std::time::{Duration, Instant};

fn shard_amount() -> usize {
    PluginHttpClient::default().pool_shard_amount()
}

#[test]
fn udp_below_cap_periodic_prune_removes_stale_preserves_active() {
    let epoch = Instant::now();
    let limiter: LocalLimiter<String, _> = LocalLimiter::new(
        UdpRateLimitAlgorithm::new(Some(1_000), None, 1, epoch),
        shard_amount(),
    );
    let op = UdpRateLimitOp { datagram_size: 1 };

    assert!(limiter.check_at("10.0.0.1".to_string(), &op, epoch).allowed);
    assert!(limiter.check_at("10.0.0.2".to_string(), &op, epoch).allowed);
    // Idle threshold is max(window_seconds * 2, 10) == 10s for window=1.
    let active_at = epoch + Duration::from_secs(11);
    assert!(
        limiter
            .check_at("10.0.0.3".to_string(), &op, active_at)
            .allowed
    );
    assert_eq!(limiter.tracked_keys_count(), 3);

    limiter.prune_stale_at(active_at);
    assert_eq!(limiter.tracked_keys_count(), 1);
    assert!(limiter.contains_key(&"10.0.0.3".to_string()));
    assert!(!limiter.contains_key(&"10.0.0.1".to_string()));
    assert!(!limiter.contains_key(&"10.0.0.2".to_string()));
}

#[test]
fn dynamic_http_below_cap_prune_covers_rate_limiting_graphql_grpc() {
    // Shared by rate_limiting, graphql, and grpc_method_router.
    let limiter: LocalLimiter<String, _> =
        LocalLimiter::new(DynamicHttpRateLimitAlgorithm::new(), shard_amount());
    let op = DynamicRateLimitOp::new(vec![RateLimitWindowSpec {
        limit: 100,
        duration: Duration::from_secs(1),
    }]);
    let t0 = Instant::now();

    assert!(limiter.check_at("ip:1".to_string(), &op, t0).allowed);
    assert!(limiter.check_at("ip:2".to_string(), &op, t0).allowed);
    // Token-bucket activity window is 2× duration for windows ≤ 5s.
    let active_at = t0 + Duration::from_secs(3);
    assert!(limiter.check_at("ip:3".to_string(), &op, active_at).allowed);
    assert_eq!(limiter.tracked_keys_count(), 3);

    limiter.prune_stale_at(active_at);
    assert_eq!(limiter.tracked_keys_count(), 1);
    assert!(limiter.contains_key(&"ip:3".to_string()));
    assert!(!limiter.contains_key(&"ip:1".to_string()));
    assert!(!limiter.contains_key(&"ip:2".to_string()));
}

#[test]
fn ai_token_below_cap_prune_removes_stale_preserves_active() {
    let limiter: LocalLimiter<String, _> =
        LocalLimiter::new(AiTokenRateAlgorithm::new(1_000, 1), shard_amount());
    let reserve = AiRateLimitOp::Reserve { tokens: 1 };
    let t0 = Instant::now();

    assert!(
        limiter
            .check_at("consumer:a".to_string(), &reserve, t0)
            .allowed
    );
    assert!(
        limiter
            .check_at("consumer:b".to_string(), &reserve, t0)
            .allowed
    );
    let active_at = t0 + Duration::from_secs(2);
    assert!(
        limiter
            .check_at("consumer:c".to_string(), &reserve, active_at)
            .allowed
    );
    assert_eq!(limiter.tracked_keys_count(), 3);

    limiter.prune_stale_at(active_at);
    assert_eq!(limiter.tracked_keys_count(), 1);
    assert!(limiter.contains_key(&"consumer:c".to_string()));
    assert!(!limiter.contains_key(&"consumer:a".to_string()));
    assert!(!limiter.contains_key(&"consumer:b".to_string()));
}

#[test]
fn ws_frame_below_cap_prune_removes_stale_preserves_active() {
    let limiter: LocalLimiter<u64, _> =
        LocalLimiter::new(WsFrameRateAlgorithm::new(100.0, 100.0), shard_amount());
    let op = WsRateLimitOp;
    let t0 = Instant::now();

    assert!(limiter.check_at(1u64, &op, t0).allowed);
    assert!(limiter.check_at(2u64, &op, t0).allowed);
    // Token-bucket activity window is 2× (burst / fps) == 2s.
    let active_at = t0 + Duration::from_secs(3);
    assert!(limiter.check_at(3u64, &op, active_at).allowed);
    assert_eq!(limiter.tracked_keys_count(), 3);

    limiter.prune_stale_at(active_at);
    assert_eq!(limiter.tracked_keys_count(), 1);
    assert!(limiter.contains_key(&3u64));
    assert!(!limiter.contains_key(&1u64));
    assert!(!limiter.contains_key(&2u64));
}

#[test]
fn enforce_capacity_still_force_evicts_active_over_cap() {
    let limiter: LocalLimiter<String, _> =
        LocalLimiter::new(DynamicHttpRateLimitAlgorithm::new(), shard_amount());
    let op = DynamicRateLimitOp::new(vec![RateLimitWindowSpec {
        limit: 100,
        duration: Duration::from_secs(60),
    }]);
    let now = Instant::now();

    for idx in 0..5 {
        assert!(limiter.check_at(format!("k:{idx}"), &op, now).allowed);
    }
    assert_eq!(limiter.tracked_keys_count(), 5);

    limiter.enforce_capacity(2, now);
    assert!(limiter.tracked_keys_count() <= 2);
}

#[test]
fn rate_limit_backend_local_and_failover_expose_below_cap_prune() {
    let local = RateLimitBackend::from_plugin_config(
        "rate_limiting",
        &json!({}),
        &PluginHttpClient::default(),
        DynamicHttpRateLimitAlgorithm::new(),
    )
    .expect("local backend");
    assert!(matches!(local, RateLimitBackend::Local(_)));

    let failover = RateLimitBackend::from_plugin_config(
        "rate_limiting",
        &json!({
            "sync_mode": "redis",
            "redis_url": "redis://127.0.0.1:9/0",
            "redis_health_check_interval_seconds": 1
        }),
        &PluginHttpClient::default(),
        DynamicHttpRateLimitAlgorithm::new(),
    )
    .expect("failover backend");
    assert!(matches!(failover, RateLimitBackend::Failover(_)));

    // Both backend variants accept prune_stale_at without requiring an
    // over-cap map (the historical below-cap no-op).
    let now = Instant::now();
    local.prune_stale_at(now);
    failover.prune_stale_at(now);
    assert_eq!(local.tracked_keys_count(), 0);
    assert_eq!(failover.tracked_keys_count(), 0);
}
