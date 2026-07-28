//! WebSocket frame rate limiting with shared local/Redis/failover storage.

use async_trait::async_trait;
use serde_json::Value;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::tungstenite::protocol::frame::CloseFrame;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tracing::warn;
use uuid::Uuid;

use super::utils::rate_limit::{
    RateLimitBackend, STANDALONE_RATE_LIMIT_CONFIG_ID, WsFrameRateAlgorithm, WsRateLimitOp,
    apply_rate_limit_cleanup, debug_assert_closed_root_keys, validate_ws_frame_rate_params,
};
use super::utils::redis_rate_limiter::REDIS_PLUGIN_CONFIG_KEYS;
use super::{Plugin, PluginHttpClient, ProxyProtocol, WS_ONLY_PROTOCOLS, WebSocketFrameDirection};
use crate::util::unknown_keys::reject_unknown_keys;

/// `ws_rate_limiting`-specific top-level config keys (excludes Redis fields).
const WS_RATE_LIMITING_POLICY_CONFIG_KEYS: &[&str] =
    &["frames_per_second", "burst_size", "close_reason"];

/// Closed top-level key set for `ws_rate_limiting` plugin config.
///
/// Must stay aligned with OpenAPI `WsRateLimitingConfig`,
/// [`REDIS_PLUGIN_CONFIG_KEYS`], and `docs/plugins.md`. A misspelled
/// `frames_per_secod`/`redis_tsl` otherwise loaded silently as the default
/// frame budget or plaintext Redis transport.
pub const WS_RATE_LIMITING_CONFIG_KEYS: &[&str] = &[
    "frames_per_second",
    "burst_size",
    "close_reason",
    // Shared Redis sync (see REDIS_PLUGIN_CONFIG_KEYS)
    "sync_mode",
    "redis_tls",
    "redis_url",
    "redis_key_prefix",
    "redis_pool_size",
    "redis_connect_timeout_seconds",
    "redis_health_check_interval_seconds",
    "redis_username",
    "redis_password",
];

const MAX_STATE_ENTRIES: usize = 50_000;
const EVICTION_CHECK_INTERVAL: u64 = 100_000;
/// Bounds below-cap full-map scans under high frame rates. Over-cap pressure
/// still triggers an immediate idle-key reclaim (no cooldown), but live
/// budgets are never force-evicted — hard cardinality is enforced by atomic
/// admission reservation.
const EVICTION_COOLDOWN_SECS: u64 = 1;

pub struct WsRateLimiting {
    close_reason: String,
    frame_counter: AtomicU64,
    redis_instance_id: String,
    limiter: RateLimitBackend<u64, WsFrameRateAlgorithm>,
    epoch_base: Instant,
    last_periodic_sweep_secs: AtomicU64,
}

impl WsRateLimiting {
    const MAX_CLOSE_REASON_BYTES: usize = 123;

    #[allow(dead_code)] // direct/test construction; production factory supplies the config id
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        Self::new_with_config_id(config, http_client, STANDALONE_RATE_LIMIT_CONFIG_ID)
    }

    /// Construct with the stable plugin-config resource id that isolates this
    /// policy's default Redis frame counters from sibling `ws_rate_limiting`
    /// instances in the same namespace. See
    /// [`super::utils::rate_limit::RedisLimiter::new_with_config_id`].
    pub fn new_with_config_id(
        config: &Value,
        http_client: PluginHttpClient,
        config_id: &str,
    ) -> Result<Self, String> {
        let object = config
            .as_object()
            .ok_or_else(|| "ws_rate_limiting: config must be an object".to_string())?;
        debug_assert_closed_root_keys(
            WS_RATE_LIMITING_CONFIG_KEYS,
            WS_RATE_LIMITING_POLICY_CONFIG_KEYS,
            REDIS_PLUGIN_CONFIG_KEYS,
        );
        reject_unknown_keys(
            object,
            "config",
            WS_RATE_LIMITING_CONFIG_KEYS,
            "ws_rate_limiting: ",
        )?;

        let frames_per_second = optional_positive_u64(config, "frames_per_second")?.unwrap_or(100);
        let burst_size = optional_positive_u64(config, "burst_size")?.unwrap_or(frames_per_second);

        // Local token-bucket and Redis two-window enforcement must share the
        // same sustained rate for every accepted config (including Redis
        // failure/recovery). Reject values Redis cannot represent without
        // over-admitting or under-admitting relative to the local policy
        // (GHSA-cjcm-546w-696v).
        validate_ws_frame_rate_params(frames_per_second, burst_size)?;

        let mut close_reason = optional_string(config, "close_reason")?
            .unwrap_or("Frame rate exceeded")
            .to_string();
        if close_reason.len() > Self::MAX_CLOSE_REASON_BYTES {
            tracing::debug!(
                max_bytes = Self::MAX_CLOSE_REASON_BYTES,
                "ws_rate_limiting: 'close_reason' exceeds WebSocket control-frame limit — truncating"
            );
            close_reason.truncate(Self::truncate_utf8_boundary(
                &close_reason,
                Self::MAX_CLOSE_REASON_BYTES,
            ));
        }

        Ok(Self {
            close_reason,
            frame_counter: AtomicU64::new(0),
            redis_instance_id: Uuid::new_v4().simple().to_string(),
            limiter: RateLimitBackend::from_plugin_config_with_config_id(
                "ws_rate_limiting",
                config_id,
                config,
                &http_client,
                WsFrameRateAlgorithm::new(frames_per_second as f64, burst_size as f64),
            )?,
            epoch_base: Instant::now(),
            last_periodic_sweep_secs: AtomicU64::new(0),
        })
    }

    /// Local/fallback DashMap shard count. Test-only; not a production API.
    #[cfg(test)]
    pub(crate) fn local_map_shard_amount(&self) -> usize {
        self.limiter.local_map_shard_amount()
    }

    /// Controllable-time seed for external cleanup tests. Not a production API.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn seed_connection_at_for_test(&self, connection_id: u64, now: Instant) {
        let _ = self
            .limiter
            .check_local_at(connection_id, &WsRateLimitOp::ONE, now);
    }

    /// Attempt to seed one local/fallback key through the production atomic
    /// capacity gate. Returns false only for a previously unseen key at cap.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn seed_connection_at_with_cap_for_test(
        &self,
        connection_id: u64,
        now: Instant,
        max_entries: usize,
    ) -> bool {
        self.limiter
            .check_local_at_with_capacity(connection_id, &WsRateLimitOp::ONE, now, max_entries)
            .is_some()
    }

    /// Arm the sampled periodic gate without spinning 100k frames. Test-only.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn arm_periodic_eviction_for_test(&self) {
        self.frame_counter
            .store(EVICTION_CHECK_INTERVAL, Ordering::Relaxed);
        self.last_periodic_sweep_secs.store(0, Ordering::Relaxed);
    }

    /// Block the below-cap cooldown so an armed sample does not scan. Test-only.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn block_periodic_cooldown_at_for_test(&self, now: Instant) {
        let now_secs = now.saturating_duration_since(self.epoch_base).as_secs();
        self.last_periodic_sweep_secs
            .store(now_secs, Ordering::Relaxed);
    }

    /// Invoke the production sampled/cooldown eviction path at `now`. Test-only.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn maybe_evict_at_for_test(&self, now: Instant) -> bool {
        self.maybe_evict_at(now)
    }

    /// Exercise the shared prune/enforce branch with a testable cap. Test-only.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn apply_cleanup_branch_for_test(
        &self,
        now: Instant,
        over_capacity: bool,
        max_entries: usize,
    ) {
        apply_rate_limit_cleanup(&self.limiter, max_entries, now, over_capacity);
    }

    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn contains_connection_for_test(&self, connection_id: u64) -> bool {
        self.limiter.contains_local_key(&connection_id)
    }

    pub(crate) fn redis_connection_scope_key(&self, proxy_id: &str, connection_id: u64) -> String {
        let mut key = String::with_capacity(self.redis_instance_id.len() + proxy_id.len() + 22);
        key.push_str(&self.redis_instance_id);
        key.push(':');
        key.push_str(proxy_id);
        key.push(':');
        let _ = write!(&mut key, "{connection_id}");
        key
    }

    fn truncate_utf8_boundary(value: &str, max_bytes: usize) -> usize {
        let mut end = value.len().min(max_bytes);
        while end > 0 && !value.is_char_boundary(end) {
            end -= 1;
        }
        end
    }

    /// Shared admission for reassembled messages and for the physical fragments
    /// they were built from. Returns the terminal policy Close when the budget
    /// is exhausted or the connection cannot be admitted to local state.
    async fn charge_frames(
        &self,
        proxy_id: &str,
        connection_id: u64,
        direction: WebSocketFrameDirection,
        op: WsRateLimitOp,
    ) -> Option<Message> {
        let _ = self.maybe_evict();
        let Some(outcome) = self
            .limiter
            .check_with_redis_key_and_local_capacity(
                connection_id,
                || self.redis_connection_scope_key(proxy_id, connection_id),
                &op,
                MAX_STATE_ENTRIES,
            )
            .await
        else {
            super::prometheus_metrics::global_registry().record_rate_limit_exceeded();
            return Some(self.policy_close());
        };

        if outcome.allowed {
            return None;
        }
        super::prometheus_metrics::global_registry().record_rate_limit_exceeded();

        let dir_label = match direction {
            WebSocketFrameDirection::ClientToBackend => "client->backend",
            WebSocketFrameDirection::BackendToClient => "backend->client",
        };
        // One bounded, low-cardinality warning per closed connection: this is
        // the terminal decision, not a per-frame event.
        warn!(
            plugin = "ws_rate_limiting",
            proxy_id = %proxy_id,
            connection_id,
            direction = dir_label,
            charged_frames = op.frame_count(),
            "WebSocket frame rate exceeded, closing connection"
        );
        Some(self.policy_close())
    }

    fn policy_close(&self) -> Message {
        Message::Close(Some(CloseFrame {
            code: CloseCode::Policy,
            reason: self.close_reason.clone().into(),
        }))
    }

    fn maybe_evict(&self) -> bool {
        self.maybe_evict_at(Instant::now())
    }

    fn maybe_evict_at(&self, now: Instant) -> bool {
        let count = self.frame_counter.fetch_add(1, Ordering::Relaxed);
        let tracked_keys = self.limiter.tracked_keys_count();
        let over_capacity = tracked_keys > MAX_STATE_ENTRIES;

        // Over-cap pressure immediately reclaims idle keys (no sample/cooldown
        // gate). Live budgets are never force-evicted; previously unseen keys
        // fail closed via atomic admission reservation.
        if over_capacity {
            apply_rate_limit_cleanup(&self.limiter, MAX_STATE_ENTRIES, now, true);
            return self.limiter.tracked_keys_count() > MAX_STATE_ENTRIES;
        }

        let periodic =
            count > 0 && count.is_multiple_of(EVICTION_CHECK_INTERVAL) && tracked_keys > 0;
        if periodic {
            let now_secs = now.saturating_duration_since(self.epoch_base).as_secs();
            let last_sweep = self.last_periodic_sweep_secs.load(Ordering::Relaxed);
            if now_secs.saturating_sub(last_sweep) >= EVICTION_COOLDOWN_SECS
                && self
                    .last_periodic_sweep_secs
                    .compare_exchange(last_sweep, now_secs, Ordering::AcqRel, Ordering::Relaxed)
                    .is_ok()
            {
                apply_rate_limit_cleanup(&self.limiter, MAX_STATE_ENTRIES, now, false);
            }
        }

        self.limiter.tracked_keys_count() > MAX_STATE_ENTRIES
    }
}

fn optional_positive_u64(config: &Value, field: &'static str) -> Result<Option<u64>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    let Some(value) = value.as_u64() else {
        return Err(format!(
            "ws_rate_limiting: '{field}' must be an integer greater than zero"
        ));
    };
    if value == 0 {
        return Err(format!(
            "ws_rate_limiting: '{field}' must be greater than zero"
        ));
    }
    Ok(Some(value))
}

fn optional_string<'a>(config: &'a Value, field: &'static str) -> Result<Option<&'a str>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    value
        .as_str()
        .map(Some)
        .ok_or_else(|| format!("ws_rate_limiting: '{field}' must be a string"))
}

#[async_trait]
impl Plugin for WsRateLimiting {
    fn name(&self) -> &str {
        "ws_rate_limiting"
    }

    fn priority(&self) -> u16 {
        super::priority::WS_RATE_LIMITING
    }

    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        WS_ONLY_PROTOCOLS
    }

    fn requires_ws_frame_hooks(&self) -> bool {
        true
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        self.limiter.warmup_hostname().into_iter().collect()
    }

    fn tracked_keys_count(&self) -> Option<usize> {
        Some(self.limiter.tracked_keys_count())
    }

    async fn on_ws_frame(
        &self,
        proxy_id: &str,
        connection_id: u64,
        direction: WebSocketFrameDirection,
        message: &Message,
    ) -> Option<Message> {
        // An earlier admission/mutating frame plugin may already have synthesized
        // a terminal Close. Do not charge local/Redis budget, run eviction
        // sampling, or replace that Close with a 1008 Policy Violation.
        if matches!(message, Message::Close(_)) {
            return None;
        }

        // One reassembled message or control frame == one wire frame. The
        // fragments it was assembled from were already charged through
        // `on_ws_reassembly_frames`, so this never double-charges them.
        self.charge_frames(proxy_id, connection_id, direction, WsRateLimitOp::ONE)
            .await
    }

    async fn on_ws_reassembly_frames(
        &self,
        proxy_id: &str,
        connection_id: u64,
        direction: WebSocketFrameDirection,
        fragment_frames: u64,
    ) -> Option<Message> {
        if fragment_frames == 0 {
            return None;
        }
        // Physical fragments that produced no message: an initial non-final
        // Text/Binary frame plus every intermediate continuation, including
        // zero-length ones. Charged as one batched op so the Redis path stays
        // at a single round trip (GHSA-qq94-2gv2-phh6).
        self.charge_frames(
            proxy_id,
            connection_id,
            direction,
            WsRateLimitOp::frames(fragment_frames),
        )
        .await
    }
}
