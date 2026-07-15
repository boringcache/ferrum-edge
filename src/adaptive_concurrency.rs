//! Adaptive backend concurrency limiter.
//!
//! The limiter answers one question on the backend dispatch path: is the
//! selected destination currently healthy enough to accept one more in-flight
//! request? Proxy, proxy-group, and global plugin scopes control how state is
//! shared, and compatible cache generations reuse that state across reloads.

use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use arc_swap::ArcSwapOption;
use crossbeam_utils::CachePadded;
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;

use crate::config::types::{Proxy, UpstreamTarget};
use crate::plugins::{BackendAdmissionOutcome, BackendAdmissionPermit};

const EWMA_PREVIOUS_WEIGHT: u64 = 8;
const EWMA_SAMPLE_WEIGHT: u64 = 2;
const EWMA_WEIGHT_SUM: u64 = EWMA_PREVIOUS_WEIGHT + EWMA_SAMPLE_WEIGHT;
const POLICY_ACTIVE: u8 = 0;
const POLICY_DRAINING: u8 = 1;
const POLICY_RESETTING: u8 = 2;

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
    // `Arc<str>` (not `String`): the scope is request-independent and resolved
    // through a per-proxy cache, so building a key on the hot path is a refcount
    // bump rather than a fresh allocation. `Hash`/`PartialEq` below stay
    // content-based (`Arc<str>` hashes/compares the `str`), so distinct `Arc`
    // instances carrying the same scope still collide/compare equal.
    scope: Arc<str>,
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
    /// Recovery cohort. A decrease advances this epoch so requests admitted
    /// before the decrease cannot use their later successes to immediately
    /// restore the old limit.
    feedback_epoch: AtomicU64,
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
            feedback_epoch: AtomicU64::new(1),
            baseline_latency_us: AtomicU64::new(0),
            latency_ewma_us: AtomicU64::new(0),
            samples: AtomicU64::new(0),
            rejections: AtomicU64::new(0),
        }
    }
}

struct AdaptiveConcurrencyPolicyLifecycle {
    /// Plugin-cache generation currently authorized to admit and train.
    active_generation: AtomicU64,
    /// Oldest compatible plugin-cache generation still authorized to admit.
    /// Requests can pin a cache view before a reload and reach backend
    /// admission afterward, so compatible commits retain this floor. A
    /// structural key-space change advances it to the replacement generation.
    minimum_admission_generation: AtomicU64,
    /// Load-balancer snapshot generation currently authorized for admission.
    active_lb_generation: AtomicU64,
    /// Oldest compatible load-balancer generation still authorized. An
    /// affected service-discovery target-set change advances this floor.
    minimum_lb_admission_generation: AtomicU64,
    /// Replacement load-balancer generation staged around request-epoch
    /// publication.
    pending_lb_generation: AtomicU64,
    pending_lb_requires_drain: AtomicBool,
    /// Validated replacement generation staged around the cache's atomic
    /// publication. Compatible old/new plugins can both admit during this
    /// handoff because they share the same target counters.
    pending_generation: AtomicU64,
    pending_requires_drain: AtomicBool,
    /// Latest committed admission configuration. A request pinned to an older
    /// compatible plugin view must use these bounds instead of reviving its
    /// retired minimum, initial limit, key cap, or shadow-mode setting.
    active_config: ArcSwapOption<AdaptiveConcurrencyPolicyConfig>,
    /// Permits across every target key. This is used only as a cold-generation
    /// transition barrier; ordinary admission remains target-local.
    total_in_flight: AtomicU64,
    /// Feedback callbacks that linearized under the active generation. Reload
    /// waits for this short synchronous critical section before clamping and
    /// publishing replacement policy bounds.
    feedback_in_progress: AtomicU64,
    /// Brief commit barrier preventing feedback from crossing the generation
    /// cutover while admission continues against generation-local bounds.
    feedback_blocked: AtomicBool,
    /// Structural policy changes (scope or `key_by`) drain older permits and
    /// exclusively reset the retired target-key space before admitting under
    /// the replacement definition.
    transition_state: AtomicU8,
}

struct AdaptiveConcurrencyPolicyConfig {
    generation: u64,
    config: Arc<AdaptiveConcurrencyConfig>,
}

impl AdaptiveConcurrencyPolicyLifecycle {
    fn new() -> Self {
        Self {
            active_generation: AtomicU64::new(1),
            minimum_admission_generation: AtomicU64::new(1),
            active_lb_generation: AtomicU64::new(1),
            minimum_lb_admission_generation: AtomicU64::new(1),
            pending_lb_generation: AtomicU64::new(0),
            pending_lb_requires_drain: AtomicBool::new(false),
            pending_generation: AtomicU64::new(0),
            pending_requires_drain: AtomicBool::new(false),
            active_config: ArcSwapOption::empty(),
            total_in_flight: AtomicU64::new(0),
            feedback_in_progress: AtomicU64::new(0),
            feedback_blocked: AtomicBool::new(false),
            transition_state: AtomicU8::new(POLICY_ACTIVE),
        }
    }
}

struct AdaptiveConcurrencyFeedbackGuard<'a> {
    policy: &'a AdaptiveConcurrencyPolicyLifecycle,
}

impl Drop for AdaptiveConcurrencyFeedbackGuard<'_> {
    fn drop(&mut self) {
        self.policy
            .feedback_in_progress
            .fetch_sub(1, Ordering::AcqRel);
    }
}

pub struct AdaptiveConcurrencyLimiter {
    inner: DashMap<AdaptiveConcurrencyKey, Arc<AdaptiveConcurrencyState>>,
    /// Per-proxy scope cache for `proxy` scoping, keyed by `proxy.id` (unique and
    /// stable per proxy). Bounded by the number of proxies using this plugin
    /// instance and rebuilt with the plugin on reload, so it needs no eviction.
    /// `upstream` scoping is intentionally not cached here — see `resolve_scope`.
    scope_cache: DashMap<Box<str>, Arc<str>>,
    /// Shared scope for `key_by = backend_target` (a single constant string).
    backend_scope: Arc<str>,
    tracked_keys: AtomicUsize,
    policy: Arc<AdaptiveConcurrencyPolicyLifecycle>,
}

impl AdaptiveConcurrencyLimiter {
    pub fn new(shards: usize) -> Self {
        Self {
            inner: DashMap::with_shard_amount(shards),
            // `scope_cache.get()` runs on the backend-dispatch hot path for
            // proxy scoping, so honor the operator's configured shard count
            // (pool_shard_amount) like `inner` rather than DashMap's default,
            // keeping per-shard lock contention bounded under load.
            scope_cache: DashMap::with_shard_amount(shards),
            backend_scope: Arc::from("backend"),
            tracked_keys: AtomicUsize::new(0),
            policy: Arc::new(AdaptiveConcurrencyPolicyLifecycle::new()),
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
        let generation = self.policy.active_generation.load(Ordering::Acquire);
        let lb_generation = self.policy.active_lb_generation.load(Ordering::Acquire);
        self.try_acquire_for_generation(proxy, target, config, generation, lb_generation)
    }

    pub(crate) fn try_acquire_for_generation(
        &self,
        proxy: &Proxy,
        target: Option<&UpstreamTarget>,
        request_config: Arc<AdaptiveConcurrencyConfig>,
        generation: u64,
        lb_generation: u64,
    ) -> Result<Arc<AdaptiveConcurrencyPermit>, AdaptiveConcurrencyLimitExceeded> {
        'admission: loop {
            let (config, config_generation) =
                self.admission_config(generation, Arc::clone(&request_config));
            self.reserve_policy_slot(generation, lb_generation, &config)?;
            let key = build_key(self.resolve_scope(proxy, config.key_by), proxy, target);
            let state = match self.inner.entry(key) {
                Entry::Occupied(entry) => Arc::clone(entry.get()),
                Entry::Vacant(entry) => match self.reserve_key_slot(config.max_tracked_keys) {
                    Ok(()) => {
                        let state = Arc::new(AdaptiveConcurrencyState::new(config.initial_limit));
                        entry.insert(Arc::clone(&state));
                        state
                    }
                    Err(_) => {
                        // Key-cardinality cap reached. Fail OPEN with a per-request,
                        // untracked state rather than rejecting: `max_tracked_keys`
                        // only bounds the limiter's own memory, so a target beyond
                        // the cap must still be admitted (never black-holed by a
                        // blanket 503), and `shadow_mode` must never reject at all.
                        // This state is NOT inserted into the map (memory stays
                        // bounded) and dies with the permit, so overflow targets run
                        // without adaptive limiting until the policy is removed and
                        // recreated (or a structural key-space change resets it).
                        // Starting at `in_flight = 0` it always admits below.
                        drop(entry);
                        Arc::new(AdaptiveConcurrencyState::new(config.initial_limit))
                    }
                },
            };

            loop {
                let current = state.in_flight.load(Ordering::Relaxed);
                // During the two-phase cache handoff, compatible old/new plugin
                // objects can briefly admit together. After commit, an old view
                // uses the replacement admission configuration.
                let limit = state
                    .limit
                    .load(Ordering::Acquire)
                    .max(config.min_limit)
                    .min(config.max_limit);
                if current >= limit && !config.shadow_mode {
                    if !self.admission_config_current(config_generation) {
                        self.policy.total_in_flight.fetch_sub(1, Ordering::AcqRel);
                        self.clamp_to_active_config(&state);
                        continue 'admission;
                    }
                    state.rejections.fetch_add(1, Ordering::Relaxed);
                    self.policy.total_in_flight.fetch_sub(1, Ordering::AcqRel);
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
                        // A cache activation may race this cold target lookup/CAS.
                        // Roll back instead of returning a permit owned by a
                        // retired policy generation, crossing a structural drain,
                        // or applying an admission config superseded by commit.
                        let generation_admitted =
                            self.policy_generation_admitted(generation, lb_generation);
                        let config_current = self.admission_config_current(config_generation);
                        if !generation_admitted || !config_current {
                            state.in_flight.fetch_sub(1, Ordering::AcqRel);
                            self.policy.total_in_flight.fetch_sub(1, Ordering::AcqRel);
                            if generation_admitted && !config_current {
                                self.clamp_to_active_config(&state);
                                continue 'admission;
                            }
                            return Err(self.policy_transition_rejection(&config));
                        }
                        let feedback_epoch = state.feedback_epoch.load(Ordering::Acquire);
                        return Ok(Arc::new(AdaptiveConcurrencyPermit {
                            state,
                            config,
                            policy: Arc::clone(&self.policy),
                            policy_generation: generation,
                            lb_generation,
                            feedback_epoch,
                            recorded: AtomicBool::new(false),
                        }));
                    }
                    Err(_) => continue,
                }
            }
        }
    }

    fn admission_config(
        &self,
        generation: u64,
        config: Arc<AdaptiveConcurrencyConfig>,
    ) -> (Arc<AdaptiveConcurrencyConfig>, u64) {
        let active = self.policy.active_config.load();
        match active
            .as_ref()
            .filter(|active| active.generation > generation)
        {
            Some(active) => (Arc::clone(&active.config), active.generation),
            None => (config, generation),
        }
    }

    fn admission_config_current(&self, config_generation: u64) -> bool {
        self.policy
            .active_config
            .load()
            .as_ref()
            .is_none_or(|active| active.generation <= config_generation)
    }

    fn clamp_to_active_config(&self, state: &AdaptiveConcurrencyState) {
        if let Some(active) = self.policy.active_config.load().as_ref() {
            clamp_limit(
                &state.limit,
                active.config.min_limit,
                active.config.max_limit,
            );
        }
    }

    fn reserve_policy_slot(
        &self,
        generation: u64,
        lb_generation: u64,
        config: &AdaptiveConcurrencyConfig,
    ) -> Result<(), AdaptiveConcurrencyLimitExceeded> {
        loop {
            if !self.policy_generation_current(generation, lb_generation) {
                return Err(self.policy_transition_rejection(config));
            }

            match self.policy.transition_state.load(Ordering::Acquire) {
                POLICY_ACTIVE => {}
                POLICY_DRAINING => {
                    if self.policy.total_in_flight.load(Ordering::Acquire) != 0 {
                        return Err(self.policy_transition_rejection(config));
                    }
                    if self
                        .policy
                        .transition_state
                        .compare_exchange(
                            POLICY_DRAINING,
                            POLICY_RESETTING,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_err()
                    {
                        continue;
                    }
                    // No permit from either generation exists once the total
                    // reaches zero. Clear the retired key space before making
                    // the replacement policy visible to competing acquirers.
                    self.inner.clear();
                    self.scope_cache.clear();
                    self.tracked_keys.store(0, Ordering::Release);
                    if self
                        .policy
                        .transition_state
                        .compare_exchange(
                            POLICY_RESETTING,
                            POLICY_ACTIVE,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_err()
                    {
                        // A newer structural generation requested another
                        // drain while this reset was running.
                        continue;
                    }
                }
                _ => return Err(self.policy_transition_rejection(config)),
            }

            self.policy.total_in_flight.fetch_add(1, Ordering::AcqRel);
            if self.policy_generation_admitted(generation, lb_generation) {
                return Ok(());
            }
            self.policy.total_in_flight.fetch_sub(1, Ordering::AcqRel);
        }
    }

    fn policy_generation_admitted(&self, generation: u64, lb_generation: u64) -> bool {
        if self.policy.transition_state.load(Ordering::Acquire) != POLICY_ACTIVE {
            return false;
        }
        self.policy_generation_current(generation, lb_generation)
    }

    fn policy_generation_current(&self, generation: u64, lb_generation: u64) -> bool {
        let active = self.policy.active_generation.load(Ordering::Acquire);
        let minimum = self
            .policy
            .minimum_admission_generation
            .load(Ordering::Acquire);
        let config_current = (generation >= minimum && generation <= active)
            || (self.policy.pending_generation.load(Ordering::Acquire) == generation
                && generation != 0
                && !self.policy.pending_requires_drain.load(Ordering::Acquire));
        if !config_current {
            return false;
        }

        let active_lb = self.policy.active_lb_generation.load(Ordering::Acquire);
        let minimum_lb = self
            .policy
            .minimum_lb_admission_generation
            .load(Ordering::Acquire);
        (lb_generation >= minimum_lb && lb_generation <= active_lb)
            || (self.policy.pending_lb_generation.load(Ordering::Acquire) == lb_generation
                && lb_generation != 0
                && !self
                    .policy
                    .pending_lb_requires_drain
                    .load(Ordering::Acquire))
    }

    fn policy_transition_rejection(
        &self,
        config: &AdaptiveConcurrencyConfig,
    ) -> AdaptiveConcurrencyLimitExceeded {
        AdaptiveConcurrencyLimitExceeded {
            current_in_flight: self.policy.total_in_flight.load(Ordering::Acquire),
            limit: config.min_limit,
        }
    }

    /// Stage a fully validated generation immediately before its plugin-cache
    /// snapshot is published. The active generation remains authorized until
    /// the snapshot store, avoiding a fail-closed gap for compatible reloads.
    pub(crate) fn prepare_policy_generation(&self, generation: u64, drain_older_generation: bool) {
        if generation <= self.policy.active_generation.load(Ordering::Acquire) {
            return;
        }
        self.policy
            .pending_requires_drain
            .store(drain_older_generation, Ordering::Release);
        self.policy
            .pending_generation
            .store(generation, Ordering::Release);
    }

    /// Commit the staged generation immediately after its cache snapshot is
    /// published. Already-linearized feedback completes before replacement
    /// bounds are clamped; later retired feedback is ignored.
    pub(crate) fn commit_policy_generation(
        &self,
        generation: u64,
        config: Arc<AdaptiveConcurrencyConfig>,
        drain_older_generation: bool,
    ) {
        let mut current = self.policy.active_generation.load(Ordering::Acquire);
        if generation <= current {
            return;
        }

        self.policy.feedback_blocked.store(true, Ordering::Release);

        // A callback that acquired its guard before the commit barrier is
        // ordered before this activation. Later callbacks fail the barrier or
        // generation checks and cannot mutate stale sampling or limit state.
        let mut spins = 0_u8;
        while self.policy.feedback_in_progress.load(Ordering::Acquire) != 0 {
            if spins < 64 {
                std::hint::spin_loop();
                spins = spins.saturating_add(1);
            } else {
                std::thread::yield_now();
            }
        }

        if drain_older_generation {
            // Exclusively block admission before retiring the older key-space
            // generations. In particular, an older request view must not be
            // allowed to observe DRAINING, perform the zero-permit reset, and
            // reactivate itself before `active_generation` advances.
            self.policy
                .transition_state
                .store(POLICY_RESETTING, Ordering::Release);
            self.policy
                .minimum_admission_generation
                .fetch_max(generation, Ordering::AcqRel);
        }

        let replacement_config = Arc::new(AdaptiveConcurrencyPolicyConfig {
            generation,
            config: Arc::clone(&config),
        });
        self.policy.active_config.rcu(|current| {
            if current
                .as_ref()
                .is_some_and(|active| active.generation >= generation)
            {
                current.clone()
            } else {
                Some(Arc::clone(&replacement_config))
            }
        });

        loop {
            if generation <= current {
                self.policy.feedback_blocked.store(false, Ordering::Release);
                return;
            }
            match self.policy.active_generation.compare_exchange(
                current,
                generation,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
        let _ = self.policy.pending_generation.compare_exchange(
            generation,
            0,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        self.policy
            .pending_requires_drain
            .store(false, Ordering::Release);

        // Learned state and in-flight accounting survive compatible config
        // changes, but the replacement bounds become authoritative at commit.
        for entry in &self.inner {
            clamp_limit(&entry.value().limit, config.min_limit, config.max_limit);
        }
        if drain_older_generation {
            if self.policy.total_in_flight.load(Ordering::Acquire) == 0 {
                self.inner.clear();
                self.scope_cache.clear();
                self.tracked_keys.store(0, Ordering::Release);
                self.policy
                    .transition_state
                    .store(POLICY_ACTIVE, Ordering::Release);
            } else {
                self.policy
                    .transition_state
                    .store(POLICY_DRAINING, Ordering::Release);
            }
        }
        self.policy.feedback_blocked.store(false, Ordering::Release);
    }

    /// Stage the load-balancer generation that will be published in the next
    /// request epoch. Policies whose referenced upstream endpoint sets changed
    /// drain their old target-key space; unrelated policies keep old pinned
    /// request views compatible with the replacement snapshot.
    pub(crate) fn prepare_lb_generation(&self, generation: u64, drain_older_generation: bool) {
        if generation <= self.policy.active_lb_generation.load(Ordering::Acquire) {
            return;
        }
        self.policy
            .pending_lb_requires_drain
            .store(drain_older_generation, Ordering::Release);
        self.policy
            .pending_lb_generation
            .store(generation, Ordering::Release);
    }

    /// Commit a staged load-balancer generation after request-epoch
    /// publication. An affected target-set change advances the admission floor
    /// before clearing the retired key space, so an old pinned request cannot
    /// recreate an endpoint after the drain completes.
    pub(crate) fn commit_lb_generation(&self, generation: u64, drain_older_generation: bool) {
        let mut current = self.policy.active_lb_generation.load(Ordering::Acquire);
        if generation <= current {
            return;
        }

        self.policy.feedback_blocked.store(true, Ordering::Release);
        let mut spins = 0_u8;
        while self.policy.feedback_in_progress.load(Ordering::Acquire) != 0 {
            if spins < 64 {
                std::hint::spin_loop();
                spins = spins.saturating_add(1);
            } else {
                std::thread::yield_now();
            }
        }

        if drain_older_generation {
            self.policy
                .transition_state
                .store(POLICY_RESETTING, Ordering::Release);
            self.policy
                .minimum_lb_admission_generation
                .fetch_max(generation, Ordering::AcqRel);
        }

        loop {
            if generation <= current {
                self.policy.feedback_blocked.store(false, Ordering::Release);
                return;
            }
            match self.policy.active_lb_generation.compare_exchange(
                current,
                generation,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
        let _ = self.policy.pending_lb_generation.compare_exchange(
            generation,
            0,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        self.policy
            .pending_lb_requires_drain
            .store(false, Ordering::Release);

        if drain_older_generation {
            if self.policy.total_in_flight.load(Ordering::Acquire) == 0 {
                self.inner.clear();
                self.scope_cache.clear();
                self.tracked_keys.store(0, Ordering::Release);
                self.policy
                    .transition_state
                    .store(POLICY_ACTIVE, Ordering::Release);
            } else {
                self.policy
                    .transition_state
                    .store(POLICY_DRAINING, Ordering::Release);
            }
        }
        self.policy.feedback_blocked.store(false, Ordering::Release);
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
        let key = build_key(self.resolve_scope(proxy, key_by), proxy, target);
        self.inner
            .get(&key)
            .map(|entry| AdaptiveConcurrencySnapshot::from_state(key, entry.value()))
    }

    /// Resolve the scope component of the key for `proxy` under `key_by`.
    /// `backend` scoping returns one shared constant. `proxy` scoping caches a
    /// reused `Arc<str>` per `proxy.id` — which uniquely and stably identifies
    /// the proxy, so the cached `proxy:{ns}:{id}` scope never goes stale.
    /// `upstream` scoping is computed per call: its `upstream:{ns}:{upstream_id}`
    /// depends on the proxy's upstream, which can change across a reload while a
    /// shared (global/proxy_group) limiter instance — and this cache — is
    /// preserved, so caching it by `proxy.id` would serve a stale upstream scope
    /// (and keying by `upstream_id` alone could collide across namespaces). The
    /// string is short, and the admission path already allocates the full key in
    /// `build_key`.
    fn resolve_scope(&self, proxy: &Proxy, key_by: AdaptiveConcurrencyKeyBy) -> Arc<str> {
        match key_by {
            AdaptiveConcurrencyKeyBy::Backend => Arc::clone(&self.backend_scope),
            AdaptiveConcurrencyKeyBy::Upstream => Arc::from(compute_scope_string(proxy, key_by)),
            AdaptiveConcurrencyKeyBy::Proxy => {
                if let Some(cached) = self.scope_cache.get(proxy.id.as_str()) {
                    return Arc::clone(cached.value());
                }
                let scope: Arc<str> = Arc::from(compute_scope_string(proxy, key_by));
                self.scope_cache
                    .insert(proxy.id.as_str().into(), Arc::clone(&scope));
                scope
            }
        }
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
    policy: Arc<AdaptiveConcurrencyPolicyLifecycle>,
    policy_generation: u64,
    lb_generation: u64,
    feedback_epoch: u64,
    recorded: AtomicBool,
}

impl AdaptiveConcurrencyPermit {
    fn begin_feedback(&self) -> Option<AdaptiveConcurrencyFeedbackGuard<'_>> {
        if self.policy.feedback_blocked.load(Ordering::Acquire)
            || !self.feedback_generation_current()
        {
            return None;
        }
        self.policy
            .feedback_in_progress
            .fetch_add(1, Ordering::AcqRel);
        if self.policy.feedback_blocked.load(Ordering::Acquire)
            || !self.feedback_generation_current()
        {
            self.policy
                .feedback_in_progress
                .fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        Some(AdaptiveConcurrencyFeedbackGuard {
            policy: self.policy.as_ref(),
        })
    }

    fn feedback_generation_current(&self) -> bool {
        let config_current = self.policy.active_generation.load(Ordering::Acquire)
            == self.policy_generation
            || self.policy.pending_generation.load(Ordering::Acquire) == self.policy_generation;
        let lb_current = self.policy.active_lb_generation.load(Ordering::Acquire)
            == self.lb_generation
            || self.policy.pending_lb_generation.load(Ordering::Acquire) == self.lb_generation;
        config_current && lb_current
    }

    /// Feed one healthy backend sample into the limiter.
    ///
    /// `backend_elapsed` is the dispatch-relative backend latency. For buffered
    /// responses it is the full backend round trip; for streamed responses it is
    /// TTFB (headers), recorded at body completion — so for streaming backends
    /// the latency signal is TTFB while the slot is held for the whole body.
    /// That asymmetry is acceptable because a streamed slot is still transient
    /// (it frees when the body completes), unlike a WebSocket session, which is
    /// why streaming keeps `allow_increase = true` rather than using the holding
    /// variant.
    ///
    /// Heuristic caveat: `baseline_latency_us` is a monotonically-decreasing
    /// minimum that never decays back up, so a single unusually-fast response
    /// (a tiny 200, a 304, a cache hit) permanently lowers `target_latency` and
    /// can keep the limit pinned low. A windowed/decaying minimum would avoid
    /// this; it is left as a documented sensitivity for now.
    fn record_success_latency(&self, backend_elapsed: Duration, allow_increase: bool) {
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
            invalidate_recovery_cohort_and_decrease(&self.state, &self.config);
        } else if allow_increase && current_in_flight >= current_limit {
            increase_limit_for_epoch(
                &self.state.limit,
                &self.state.feedback_epoch,
                self.feedback_epoch,
                &self.config,
            );
        }
    }

    /// Shared outcome accounting. `allow_increase` is `false` for long-lived
    /// admissions (WebSocket sessions) whose in-flight slot is still held when
    /// the outcome is recorded: every concurrent handshake then observes
    /// `in_flight >= limit`, so growing the limit there would ratchet it up to
    /// `max_limit` and defeat the in-flight session cap.
    fn record(&self, outcome: BackendAdmissionOutcome, allow_increase: bool) {
        if self.recorded.swap(true, Ordering::AcqRel) {
            return;
        }
        // Config changes publish a new feedback generation. Retired permits
        // still release their shared in-flight slots on Drop, but must not
        // train the replacement policy with stale bounds or sampling controls.
        // The guard makes this check coherent with concurrent activation.
        let Some(_feedback_guard) = self.begin_feedback() else {
            return;
        };
        // Client-/gateway-side outcomes do not reflect backend health: release
        // the slot without feeding a latency, growth, or shrink signal. An
        // oversized *client* upload surfaces as a gateway 413
        // (`RequestBodyTooLarge`), a client abort as `ClientDisconnect`, and a
        // pre-dial dispatch-policy shed (backend-TLS-SNI reject, or an
        // `http1MaxPendingRequests` in-flight-overflow 503) as
        // `DispatchPolicyRejected`; none is the backend's fault, so they must
        // not train the limiter. Shares `client_side_no_backend_signal` with the
        // circuit-breaker / passive-health accounting so an overflow shed's
        // synthetic 503 cannot reach the `>= 500` shrink branch below and shrink
        // a backend that was never dialed — the predicates cannot drift.
        if crate::proxy::backend_dispatch::client_side_no_backend_signal(outcome.error_class) {
            return;
        }
        // Backend faults shrink the limit. Besides connection errors and 5xx,
        // this covers post-wire backend failures — a stream that returned healthy
        // 2xx headers and then timed out / reset mid-body (`ReadWriteTimeout` /
        // `ConnectionReset` / `ConnectionClosed` / `ProtocolError`) or over-sent
        // past the response-size cap (`ResponseBodyTooLarge`). Without them the
        // limiter would treat a post-header backend stall as a fast success and
        // grow the limit. Shares the predicate with the circuit-breaker /
        // passive-health accounting so the two cannot drift.
        if outcome.connection_error
            || outcome.response_status >= 500
            || crate::proxy::backend_dispatch::error_class_is_post_wire_backend_failure(
                outcome.error_class,
            )
        {
            invalidate_recovery_cohort_and_decrease(&self.state, &self.config);
            return;
        }
        self.record_success_latency(outcome.backend_elapsed, allow_increase);
    }
}

impl BackendAdmissionPermit for AdaptiveConcurrencyPermit {
    fn record_backend_outcome(&self, outcome: BackendAdmissionOutcome) {
        self.record(outcome, true);
    }

    fn record_backend_outcome_holding(&self, outcome: BackendAdmissionOutcome) {
        self.record(outcome, false);
    }
}

impl Drop for AdaptiveConcurrencyPermit {
    fn drop(&mut self) {
        self.state.in_flight.fetch_sub(1, Ordering::AcqRel);
        self.policy.total_in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

fn build_key(
    scope: Arc<str>,
    proxy: &Proxy,
    target: Option<&UpstreamTarget>,
) -> AdaptiveConcurrencyKey {
    // Only host/port vary per request; `scope` is resolved (and cached) by the
    // caller via `resolve_scope`.
    let (host, port) = target
        .map(|target| (target.host.as_str(), target.port))
        .unwrap_or((proxy.backend_host.as_str(), proxy.backend_port));

    AdaptiveConcurrencyKey {
        scope,
        host: host.to_string(),
        port,
    }
}

fn compute_scope_string(proxy: &Proxy, key_by: AdaptiveConcurrencyKeyBy) -> String {
    match key_by {
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
        // `backend` scope is served as a shared constant by `resolve_scope` and
        // never reaches this function in practice.
        AdaptiveConcurrencyKeyBy::Backend => "backend".to_string(),
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

fn invalidate_recovery_cohort_and_decrease(
    state: &AdaptiveConcurrencyState,
    config: &AdaptiveConcurrencyConfig,
) {
    let limit_before_invalidation = state.limit.load(Ordering::Acquire);
    // This increment is the recovery-ordering linearization point. A success
    // racing after it cannot pass `increase_limit_for_epoch` with its stale
    // epoch. A success that passed its epoch check just before this increment
    // may still win its limit CAS afterward, so the decrease uses the
    // pre-invalidation limit as a fixed ceiling rather than multiplying that
    // stale increase into a weaker backoff.
    state.feedback_epoch.fetch_add(1, Ordering::AcqRel);
    decrease_limit(&state.limit, config, limit_before_invalidation);
}

fn decrease_limit(
    limit: &AtomicU64,
    config: &AdaptiveConcurrencyConfig,
    limit_before_invalidation: u64,
) {
    let decreased = ((limit_before_invalidation as f64) * config.decrease_ratio).floor() as u64;
    let target = decreased.max(config.min_limit).min(config.max_limit);
    let mut current = limit.load(Ordering::Acquire);
    loop {
        if target >= current {
            return;
        }
        match limit.compare_exchange(current, target, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

fn increase_limit_for_epoch(
    limit: &AtomicU64,
    feedback_epoch: &AtomicU64,
    expected_epoch: u64,
    config: &AdaptiveConcurrencyConfig,
) {
    let mut current = limit.load(Ordering::Acquire);
    loop {
        if feedback_epoch.load(Ordering::Acquire) != expected_epoch {
            return;
        }
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

fn clamp_limit(limit: &AtomicU64, min_limit: u64, max_limit: u64) {
    let mut current = limit.load(Ordering::Acquire);
    loop {
        let next = current.max(min_limit).min(max_limit);
        if next == current {
            return;
        }
        match limit.compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}
