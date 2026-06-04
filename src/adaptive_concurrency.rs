//! Adaptive backend concurrency limiter.
//!
//! The limiter answers one question on the backend dispatch path: is the
//! selected destination currently healthy enough to accept one more in-flight
//! request? It is intentionally plugin-owned so proxy, proxy-group, and global
//! plugin scopes control how state is shared.

use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use crossbeam_utils::CachePadded;
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;

use crate::config::types::{Proxy, UpstreamTarget};
use crate::plugins::{BackendAdmissionOutcome, BackendAdmissionPermit};
use crate::retry::ErrorClass;

const EWMA_PREVIOUS_WEIGHT: u64 = 8;
const EWMA_SAMPLE_WEIGHT: u64 = 2;
const EWMA_WEIGHT_SUM: u64 = EWMA_PREVIOUS_WEIGHT + EWMA_SAMPLE_WEIGHT;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdaptiveConcurrencyKeyBy {
    /// Separate limit per proxy and selected backend endpoint.
    Proxy,
    /// Separate limit per upstream and selected backend endpoint; direct
    /// backends fall back to proxy-target scoping.
    Upstream,
    /// Shared limit per backend endpoint across every proxy using this plugin
    /// instance.
    Backend,
}

#[derive(Clone, Debug)]
pub struct AdaptiveConcurrencyConfig {
    pub key_by: AdaptiveConcurrencyKeyBy,
    pub max_tracked_keys: usize,
    pub min_limit: u64,
    pub initial_limit: u64,
    pub max_limit: u64,
    pub min_samples: u64,
    pub target_latency_multiplier: f64,
    pub decrease_ratio: f64,
    pub increase_step: u64,
    pub shadow_mode: bool,
    pub expose_headers: bool,
}

#[derive(Clone, Debug, Eq)]
pub struct AdaptiveConcurrencyKey {
    scope: String,
    host: String,
    port: u16,
}

impl PartialEq for AdaptiveConcurrencyKey {
    fn eq(&self, other: &Self) -> bool {
        self.scope == other.scope && self.host == other.host && self.port == other.port
    }
}

impl Hash for AdaptiveConcurrencyKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.scope.hash(state);
        self.host.hash(state);
        self.port.hash(state);
    }
}

struct AdaptiveConcurrencyState {
    in_flight: CachePadded<AtomicU64>,
    limit: CachePadded<AtomicU64>,
    baseline_latency_us: AtomicU64,
    latency_ewma_us: AtomicU64,
    samples: AtomicU64,
    rejections: AtomicU64,
}

impl AdaptiveConcurrencyState {
    fn new(initial_limit: u64) -> Self {
        Self {
            in_flight: CachePadded::new(AtomicU64::new(0)),
            limit: CachePadded::new(AtomicU64::new(initial_limit)),
            baseline_latency_us: AtomicU64::new(0),
            latency_ewma_us: AtomicU64::new(0),
            samples: AtomicU64::new(0),
            rejections: AtomicU64::new(0),
        }
    }
}

pub struct AdaptiveConcurrencyLimiter {
    inner: DashMap<AdaptiveConcurrencyKey, Arc<AdaptiveConcurrencyState>>,
    tracked_keys: AtomicUsize,
}

impl AdaptiveConcurrencyLimiter {
    pub fn new(shards: usize) -> Self {
        Self {
            inner: DashMap::with_shard_amount(shards),
            tracked_keys: AtomicUsize::new(0),
        }
    }

    pub fn tracked_keys_count(&self) -> usize {
        self.inner.len()
    }

    pub fn try_acquire(
        &self,
        proxy: &Proxy,
        target: Option<&UpstreamTarget>,
        config: Arc<AdaptiveConcurrencyConfig>,
    ) -> Result<Arc<AdaptiveConcurrencyPermit>, AdaptiveConcurrencyLimitExceeded> {
        let key = build_key(proxy, target, config.key_by);
        let state = match self.inner.entry(key) {
            Entry::Occupied(entry) => Arc::clone(entry.get()),
            Entry::Vacant(entry) => {
                self.reserve_key_slot(config.max_tracked_keys)?;
                let state = Arc::new(AdaptiveConcurrencyState::new(config.initial_limit));
                entry.insert(Arc::clone(&state));
                state
            }
        };

        loop {
            let current = state.in_flight.load(Ordering::Relaxed);
            let limit = state.limit.load(Ordering::Acquire);
            if current >= limit && !config.shadow_mode {
                state.rejections.fetch_add(1, Ordering::Relaxed);
                return Err(AdaptiveConcurrencyLimitExceeded {
                    current_in_flight: current,
                    limit,
                });
            }

            match state.in_flight.compare_exchange_weak(
                current,
                current.saturating_add(1),
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    return Ok(Arc::new(AdaptiveConcurrencyPermit {
                        state,
                        config,
                        recorded: AtomicBool::new(false),
                    }));
                }
                Err(_) => continue,
            }
        }
    }

    fn reserve_key_slot(
        &self,
        max_tracked_keys: usize,
    ) -> Result<(), AdaptiveConcurrencyLimitExceeded> {
        let mut current = self.tracked_keys.load(Ordering::Acquire);
        loop {
            if current >= max_tracked_keys {
                return Err(AdaptiveConcurrencyLimitExceeded {
                    current_in_flight: current as u64,
                    limit: max_tracked_keys as u64,
                });
            }
            match self.tracked_keys.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(()),
                Err(observed) => current = observed,
            }
        }
    }

    #[allow(dead_code)]
    pub fn snapshot(
        &self,
        proxy: &Proxy,
        target: Option<&UpstreamTarget>,
        key_by: AdaptiveConcurrencyKeyBy,
    ) -> Option<AdaptiveConcurrencySnapshot> {
        let key = build_key(proxy, target, key_by);
        self.inner
            .get(&key)
            .map(|entry| AdaptiveConcurrencySnapshot::from_state(key, entry.value()))
    }
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct AdaptiveConcurrencySnapshot {
    pub key: AdaptiveConcurrencyKey,
    pub in_flight: u64,
    pub limit: u64,
    pub baseline_latency_us: u64,
    pub latency_ewma_us: u64,
    pub samples: u64,
    pub rejections: u64,
}

impl AdaptiveConcurrencySnapshot {
    fn from_state(key: AdaptiveConcurrencyKey, state: &AdaptiveConcurrencyState) -> Self {
        Self {
            key,
            in_flight: state.in_flight.load(Ordering::Relaxed),
            limit: state.limit.load(Ordering::Acquire),
            baseline_latency_us: state.baseline_latency_us.load(Ordering::Acquire),
            latency_ewma_us: state.latency_ewma_us.load(Ordering::Acquire),
            samples: state.samples.load(Ordering::Acquire),
            rejections: state.rejections.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone, Debug)]
pub struct AdaptiveConcurrencyLimitExceeded {
    pub current_in_flight: u64,
    pub limit: u64,
}

pub struct AdaptiveConcurrencyPermit {
    state: Arc<AdaptiveConcurrencyState>,
    config: Arc<AdaptiveConcurrencyConfig>,
    recorded: AtomicBool,
}

impl AdaptiveConcurrencyPermit {
    fn record_success_latency(&self, backend_elapsed: Duration) {
        let latency_us = (backend_elapsed.as_micros() as u64).max(1);
        update_min(&self.state.baseline_latency_us, latency_us);
        let ewma = update_ewma(&self.state.latency_ewma_us, latency_us);
        let samples = self.state.samples.fetch_add(1, Ordering::AcqRel) + 1;
        if samples < self.config.min_samples {
            return;
        }

        let baseline = self.state.baseline_latency_us.load(Ordering::Acquire);
        if baseline == 0 {
            return;
        }
        let target_latency = (baseline as f64 * self.config.target_latency_multiplier)
            .round()
            .max(1.0) as u64;
        let current_limit = self.state.limit.load(Ordering::Acquire);
        let current_in_flight = self.state.in_flight.load(Ordering::Acquire);
        if ewma > target_latency {
            decrease_limit(&self.state.limit, &self.config);
        } else if current_in_flight >= current_limit {
            increase_limit(&self.state.limit, &self.config);
        }
    }
}

impl BackendAdmissionPermit for AdaptiveConcurrencyPermit {
    fn record_backend_outcome(&self, outcome: BackendAdmissionOutcome) {
        if self.recorded.swap(true, Ordering::AcqRel) {
            return;
        }
        if outcome.error_class == Some(ErrorClass::ClientDisconnect) {
            return;
        }
        if outcome.connection_error || outcome.response_status >= 500 {
            decrease_limit(&self.state.limit, &self.config);
            return;
        }
        self.record_success_latency(outcome.backend_elapsed);
    }
}

impl Drop for AdaptiveConcurrencyPermit {
    fn drop(&mut self) {
        self.state.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

fn build_key(
    proxy: &Proxy,
    target: Option<&UpstreamTarget>,
    key_by: AdaptiveConcurrencyKeyBy,
) -> AdaptiveConcurrencyKey {
    let (host, port) = target
        .map(|target| (target.host.as_str(), target.port))
        .unwrap_or((proxy.backend_host.as_str(), proxy.backend_port));

    let scope = match key_by {
        AdaptiveConcurrencyKeyBy::Proxy => scoped_proxy(proxy),
        AdaptiveConcurrencyKeyBy::Upstream => proxy
            .upstream_id
            .as_deref()
            .map(|upstream_id| {
                let mut scope = String::with_capacity(
                    "upstream::".len() + proxy.namespace.len() + upstream_id.len(),
                );
                scope.push_str("upstream:");
                scope.push_str(&proxy.namespace);
                scope.push(':');
                scope.push_str(upstream_id);
                scope
            })
            .unwrap_or_else(|| scoped_proxy(proxy)),
        AdaptiveConcurrencyKeyBy::Backend => "backend".to_string(),
    };

    AdaptiveConcurrencyKey {
        scope,
        host: host.to_string(),
        port,
    }
}

fn scoped_proxy(proxy: &Proxy) -> String {
    let mut scope = String::with_capacity("proxy::".len() + proxy.namespace.len() + proxy.id.len());
    scope.push_str("proxy:");
    scope.push_str(&proxy.namespace);
    scope.push(':');
    scope.push_str(&proxy.id);
    scope
}

fn update_min(atomic: &AtomicU64, candidate: u64) {
    let mut current = atomic.load(Ordering::Acquire);
    loop {
        if current != 0 && current <= candidate {
            return;
        }
        match atomic.compare_exchange(current, candidate, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

fn update_ewma(atomic: &AtomicU64, sample: u64) -> u64 {
    let mut current = atomic.load(Ordering::Acquire);
    loop {
        let next = if current == 0 {
            sample
        } else {
            current
                .saturating_mul(EWMA_PREVIOUS_WEIGHT)
                .saturating_add(sample.saturating_mul(EWMA_SAMPLE_WEIGHT))
                / EWMA_WEIGHT_SUM
        };
        match atomic.compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return next,
            Err(observed) => current = observed,
        }
    }
}

fn decrease_limit(limit: &AtomicU64, config: &AdaptiveConcurrencyConfig) {
    let mut current = limit.load(Ordering::Acquire);
    loop {
        let decreased = ((current as f64) * config.decrease_ratio).floor() as u64;
        let next = decreased.max(config.min_limit).min(config.max_limit);
        if next >= current {
            return;
        }
        match limit.compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

fn increase_limit(limit: &AtomicU64, config: &AdaptiveConcurrencyConfig) {
    let mut current = limit.load(Ordering::Acquire);
    loop {
        if current >= config.max_limit {
            return;
        }
        let next = current
            .saturating_add(config.increase_step)
            .max(config.min_limit)
            .min(config.max_limit);
        if next == current {
            return;
        }
        match limit.compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}
