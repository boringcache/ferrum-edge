//! UDP datagram rate limiting with shared local/Redis/failover storage.

use async_trait::async_trait;
use serde_json::Value;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tracing::warn;

use super::utils::rate_limit::{
    RateLimitBackend, UdpRateLimitAlgorithm, UdpRateLimitOp, apply_rate_limit_cleanup,
};
use super::{
    Plugin, PluginHttpClient, ProxyProtocol, UDP_ONLY_PROTOCOLS, UdpDatagramContext,
    UdpDatagramVerdict,
};

const MAX_STATE_ENTRIES: usize = 100_000;
const EVICTION_COOLDOWN_SECS: u64 = 1;
const EVICTION_CHECK_INTERVAL: u64 = 100_000;

pub struct UdpRateLimiting {
    check_counter: AtomicU64,
    epoch_base: Instant,
    last_eviction_secs: AtomicU64,
    limiter: RateLimitBackend<Arc<str>, UdpRateLimitAlgorithm>,
}

impl UdpRateLimiting {
    pub fn new_with_http_client(
        config: &Value,
        http_client: PluginHttpClient,
    ) -> Result<Self, String> {
        if !config.is_object() {
            return Err("udp_rate_limiting: config must be an object".to_string());
        }

        let datagrams_per_second = optional_positive_u64(config, "datagrams_per_second")?;
        let bytes_per_second = optional_positive_u64(config, "bytes_per_second")?;

        if datagrams_per_second.is_none() && bytes_per_second.is_none() {
            return Err(
                "udp_rate_limiting: at least one of 'datagrams_per_second' or 'bytes_per_second' must be set"
                    .to_string(),
            );
        }

        let window_seconds = optional_positive_u64(config, "window_seconds")?.unwrap_or(1);
        let datagrams_per_window = per_window_limit(datagrams_per_second, window_seconds)?;
        let bytes_per_window = per_window_limit(bytes_per_second, window_seconds)?;
        let epoch_base = Instant::now();

        Ok(Self {
            check_counter: AtomicU64::new(0),
            epoch_base,
            last_eviction_secs: AtomicU64::new(0),
            limiter: RateLimitBackend::from_plugin_config(
                "udp_rate_limiting",
                config,
                &http_client,
                UdpRateLimitAlgorithm::new(
                    datagrams_per_window,
                    bytes_per_window,
                    window_seconds,
                    epoch_base,
                ),
            )?,
        })
    }

    /// Local/fallback DashMap shard count. Test-only; not a production API.
    #[cfg(test)]
    pub(crate) fn local_map_shard_amount(&self) -> usize {
        self.limiter.local_map_shard_amount()
    }

    /// All-shard `DashMap::len()` observations on the local/fallback map.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn all_shard_len_calls_for_test(&self) -> usize {
        self.limiter.all_shard_len_calls_for_test()
    }

    /// Exact DashMap length for reconciling the atomic entry count in tests.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn map_len_for_test(&self) -> usize {
        self.limiter.map_len_for_test()
    }

    /// Controllable-time seed for external cleanup tests. Not a production API.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn seed_client_at_for_test(
        &self,
        client_ip: Arc<str>,
        datagram_size: u64,
        now: Instant,
    ) {
        let _ = self
            .limiter
            .check_local_at(client_ip, &UdpRateLimitOp { datagram_size }, now);
    }

    /// Arm the sampled periodic gate without spinning 100k hooks. Test-only.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn arm_periodic_eviction_for_test(&self) {
        self.check_counter
            .store(EVICTION_CHECK_INTERVAL, Ordering::Relaxed);
        self.last_eviction_secs.store(0, Ordering::Relaxed);
    }

    /// Force the cooldown clock so the next armed periodic sweep is blocked.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn block_eviction_cooldown_at_for_test(&self, now: Instant) {
        let now_secs = now.saturating_duration_since(self.epoch_base).as_secs();
        self.last_eviction_secs.store(now_secs, Ordering::Relaxed);
    }

    /// Invoke the production sampled/cooldown eviction path at `now`. Test-only.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn maybe_evict_at_for_test(&self, now: Instant) -> bool {
        self.maybe_evict_at(now)
    }

    /// Exercise the production sampled/cooldown path with a testable cap.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn maybe_evict_at_with_cap_for_test(
        &self,
        now: Instant,
        max_entries: usize,
    ) -> bool {
        self.maybe_evict_at_with_cap(now, max_entries)
    }

    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn contains_client_for_test(&self, client_ip: &Arc<str>) -> bool {
        self.limiter.contains_local_key(client_ip)
    }

    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn epoch_base_for_test(&self) -> Instant {
        self.epoch_base
    }

    fn redis_ip_key(client_ip: &str) -> String {
        let mut key = String::with_capacity(3 + client_ip.len());
        key.push_str("ip:");
        key.push_str(client_ip);
        key
    }

    fn maybe_evict(&self) -> bool {
        self.maybe_evict_at(Instant::now())
    }

    fn maybe_evict_at(&self, now: Instant) -> bool {
        self.maybe_evict_at_with_cap(now, MAX_STATE_ENTRIES)
    }

    fn maybe_evict_at_with_cap(&self, now: Instant, max_entries: usize) -> bool {
        let count = self.check_counter.fetch_add(1, Ordering::Relaxed);
        let len = self.limiter.tracked_keys_count();
        let over_capacity = len > max_entries;
        let periodic = count > 0 && count.is_multiple_of(EVICTION_CHECK_INTERVAL) && len > 0;
        let now_secs = now.saturating_duration_since(self.epoch_base).as_secs();

        // Keep strict admission active for every over-cap observation, even
        // when this call wins cleanup and brings the map back to the cap. That
        // prevents a spoofed new-IP stream from defeating the caller's O(1)
        // rejection guard by alternating insertion with full-map eviction.
        // Reuse the periodic timestamp as a once-per-second single-flight gate
        // so attacker-controlled datagrams cannot trigger retain/eviction on
        // every packet.
        if over_capacity {
            let last_sweep = self.last_eviction_secs.load(Ordering::Relaxed);
            if now_secs.saturating_sub(last_sweep) >= EVICTION_COOLDOWN_SECS
                && self
                    .last_eviction_secs
                    .compare_exchange(last_sweep, now_secs, Ordering::AcqRel, Ordering::Relaxed)
                    .is_ok()
            {
                apply_rate_limit_cleanup(&self.limiter, max_entries, now, true);
            }
            return true;
        }

        if periodic {
            let last_sweep = self.last_eviction_secs.load(Ordering::Relaxed);
            if now_secs.saturating_sub(last_sweep) >= EVICTION_COOLDOWN_SECS
                && self
                    .last_eviction_secs
                    .compare_exchange(last_sweep, now_secs, Ordering::AcqRel, Ordering::Relaxed)
                    .is_ok()
            {
                // Periodic sweeps prune idle keys even while the map is
                // below the hard cap. A later over-cap observation keeps the
                // strict new-IP guard active and force-evicts at most once per
                // second after pruning.
                apply_rate_limit_cleanup(&self.limiter, max_entries, now, false);
            }
        }

        self.limiter.tracked_keys_count() > max_entries
    }
}

#[async_trait]
impl Plugin for UdpRateLimiting {
    fn name(&self) -> &str {
        "udp_rate_limiting"
    }

    fn priority(&self) -> u16 {
        super::priority::UDP_RATE_LIMITING
    }

    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        UDP_ONLY_PROTOCOLS
    }

    fn requires_udp_datagram_hooks(&self) -> bool {
        true
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        self.limiter.warmup_hostname().into_iter().collect()
    }

    fn tracked_keys_count(&self) -> Option<usize> {
        Some(self.limiter.tracked_keys_count())
    }

    async fn on_udp_datagram(&self, ctx: &UdpDatagramContext<'_>) -> UdpDatagramVerdict {
        let over_capacity = self.maybe_evict();
        let key = Arc::clone(&ctx.client_ip);

        if over_capacity && !self.limiter.contains_local_key(&key) {
            super::prometheus_metrics::global_registry().record_rate_limit_exceeded();
            return UdpDatagramVerdict::Drop;
        }

        let outcome = self
            .limiter
            .check_with_redis_key(
                Arc::clone(&key),
                || Self::redis_ip_key(key.as_ref()),
                &UdpRateLimitOp {
                    datagram_size: ctx.datagram_size as u64,
                },
            )
            .await;

        if outcome.allowed {
            return UdpDatagramVerdict::Forward;
        }
        super::prometheus_metrics::global_registry().record_rate_limit_exceeded();

        match outcome.metric {
            Some("bytes") => warn!(
                plugin = "udp_rate_limiting",
                proxy_id = %ctx.proxy_id,
                client_ip = %ctx.client_ip,
                bytes = outcome.usage.unwrap_or(0),
                limit = outcome.limit.unwrap_or(0),
                "UDP byte rate exceeded, dropping"
            ),
            _ => warn!(
                plugin = "udp_rate_limiting",
                proxy_id = %ctx.proxy_id,
                client_ip = %ctx.client_ip,
                count = outcome.usage.unwrap_or(0),
                limit = outcome.limit.unwrap_or(0),
                "UDP datagram rate exceeded, dropping"
            ),
        }

        UdpDatagramVerdict::Drop
    }
}

fn optional_positive_u64(config: &Value, field: &'static str) -> Result<Option<u64>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    let Some(value) = value.as_u64() else {
        return Err(format!(
            "udp_rate_limiting: '{field}' must be an integer greater than zero"
        ));
    };
    if value == 0 {
        return Err(format!(
            "udp_rate_limiting: '{field}' must be greater than zero"
        ));
    }
    Ok(Some(value))
}

fn per_window_limit(limit: Option<u64>, window_seconds: u64) -> Result<Option<u64>, String> {
    limit
        .map(|value| {
            value.checked_mul(window_seconds).ok_or_else(|| {
                "udp_rate_limiting: per-window limit overflows u64; reduce the rate or window"
                    .to_string()
            })
        })
        .transpose()
}
