//! Cooldown gate + recovery state machine for proxy_alerts.
//!
//! - [`CooldownGate`] suppresses repeated dispatches per `(rule_id,
//!   proxy_id, ownership_generation, channel_id)`. Atomic CAS on a single
//!   `AtomicU64` per ownership key.
//! - [`RecoveryGate`] tracks per-`(rule_id, proxy_id, ownership_generation)`
//!   lifecycle so a rule that breaches and then recovers can dispatch a
//!   single resolve event.
//!
//! Both surfaces are infallible by design — they only return whether to
//! proceed; the caller's `tokio::spawn` does the actual dispatch.
//!
//! Rows are keyed by admission ownership generation so a stale write that
//! races past retain cannot populate or poison the replacement incarnation.
//! Per-proxy entries are retired when a proxy leaves a preserved global or
//! proxy-group instance, or when its published generation advances
//! ([`CooldownGate::retain_proxies`] / [`RecoveryGate::retain_proxies`]).
//! Expired cooldown / resolved recovery rows are swept by the plugin's
//! background eviction task.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashMap;

use crate::util::sharding::pool_shard_amount;

type CooldownKey = (u32, u32);
type CooldownGenerationMap = DashMap<u64, Arc<AtomicU64>>;
type SharedCooldownGenerationMap = Arc<CooldownGenerationMap>;
type CooldownProxyMap = DashMap<String, SharedCooldownGenerationMap>;
type SharedCooldownProxyMap = Arc<CooldownProxyMap>;
type RecoveryGenerationMap = DashMap<u64, RuleState>;
type SharedRecoveryGenerationMap = Arc<RecoveryGenerationMap>;
type RecoveryRuleMap = DashMap<String, SharedRecoveryGenerationMap>;
type SharedRecoveryRuleMap = Arc<RecoveryRuleMap>;

#[derive(Debug)]
pub struct CooldownGate {
    last_sent: DashMap<CooldownKey, SharedCooldownProxyMap>,
    inner_shard_amount: usize,
}

impl Default for CooldownGate {
    fn default() -> Self {
        Self::new()
    }
}

impl CooldownGate {
    pub fn new() -> Self {
        let shard_amount = pool_shard_amount(0);
        Self {
            last_sent: DashMap::with_shard_amount(shard_amount),
            inner_shard_amount: shard_amount,
        }
    }

    /// Returns `true` if the cooldown window has elapsed and the dispatch
    /// should proceed. On success the gate is rearmed atomically with the
    /// `now_ms` value.
    ///
    /// `ownership_generation` is the admission-time lifecycle generation
    /// (or [`super::UNARMED_PROXY_LIFECYCLE_GENERATION`] for offline tests).
    pub fn try_acquire(
        &self,
        rule_id: u32,
        proxy_id: &str,
        channel_id: u32,
        cooldown_ms: u64,
        now_ms: u64,
        ownership_generation: u64,
    ) -> bool {
        let per_proxy = if let Some(existing) = self.last_sent.get(&(rule_id, channel_id)) {
            Arc::clone(existing.value())
        } else {
            Arc::clone(
                self.last_sent
                    .entry((rule_id, channel_id))
                    .or_insert_with(|| {
                        Arc::new(DashMap::with_shard_amount(self.inner_shard_amount))
                    })
                    .value(),
            )
        };
        let per_generation = if let Some(existing) = per_proxy.get(proxy_id) {
            Arc::clone(existing.value())
        } else {
            Arc::clone(
                per_proxy
                    .entry(proxy_id.to_string())
                    .or_insert_with(|| {
                        Arc::new(DashMap::with_shard_amount(self.inner_shard_amount))
                    })
                    .value(),
            )
        };
        let atomic = if let Some(existing) = per_generation.get(&ownership_generation) {
            Arc::clone(existing.value())
        } else {
            Arc::clone(
                per_generation
                    .entry(ownership_generation)
                    .or_insert_with(|| Arc::new(AtomicU64::new(0)))
                    .value(),
            )
        };
        let mut prev = atomic.load(Ordering::Acquire);
        loop {
            if prev != 0 && now_ms.saturating_sub(prev) < cooldown_ms {
                return false;
            }
            match atomic.compare_exchange_weak(prev, now_ms, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return true,
                Err(p) => prev = p,
            }
        }
    }

    /// Drop cooldown rows for proxies absent from `active_proxy_generations`
    /// or whose stored generation does not match the published incarnation.
    ///
    /// Cold-path only: called after incremental plugin-cache commit when a
    /// preserved global/proxy-group instance outlives individual proxies.
    pub fn retain_proxies(&self, active_proxy_generations: &HashMap<&str, u64>) {
        self.last_sent.retain(|_, per_proxy| {
            per_proxy.retain(|proxy_id, generations| {
                match active_proxy_generations.get(proxy_id.as_str()).copied() {
                    Some(active_gen) => {
                        generations.retain(|&gen, _| gen == active_gen);
                        !generations.is_empty()
                    }
                    None => false,
                }
            });
            !per_proxy.is_empty()
        });
    }

    /// Drop cooldown timestamps older than `keep_ms`.
    ///
    /// Entries whose last dispatch is still inside the keep window are
    /// retained so an in-flight cooldown continues to suppress duplicates.
    pub fn evict_stale(&self, now_ms: u64, keep_ms: u64) {
        let cutoff = now_ms.saturating_sub(keep_ms);
        self.last_sent.retain(|_, per_proxy| {
            per_proxy.retain(|_, generations| {
                generations.retain(|_, atomic| {
                    let ts = atomic.load(Ordering::Acquire);
                    ts == 0 || ts >= cutoff
                });
                !generations.is_empty()
            });
            !per_proxy.is_empty()
        });
    }

    /// Whether any `(rule, channel)` map currently holds a row for `proxy_id`
    /// under any ownership generation.
    #[allow(dead_code)] // Used by external test crate and admin/debug helpers.
    pub fn contains_proxy(&self, proxy_id: &str) -> bool {
        self.last_sent.iter().any(|entry| {
            entry
                .value()
                .get(proxy_id)
                .is_some_and(|generations| !generations.is_empty())
        })
    }

    /// Whether any `(rule, channel)` map holds a row for `(proxy_id, generation)`.
    #[allow(dead_code)] // Used by external test crate.
    pub fn contains_proxy_generation(&self, proxy_id: &str, ownership_generation: u64) -> bool {
        self.last_sent.iter().any(|entry| {
            entry
                .value()
                .get(proxy_id)
                .is_some_and(|generations| generations.contains_key(&ownership_generation))
        })
    }
}

/// Per-`(rule, proxy, generation)` lifecycle for recovery notifications.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleState {
    Healthy,
    Active { fired_at_ms: u64 },
    Recovering { left_threshold_at_ms: u64 },
}

/// Outcome of evaluating a single observation against the recovery state
/// machine. The dispatch loop translates this into zero or one notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleOutcome {
    /// Healthy → Active. Caller should dispatch a `Trigger` notification
    /// (subject to cooldown).
    Trigger,
    /// Active → Active. Caller MAY dispatch a re-trigger if its cooldown
    /// allows; this is informational so the cooldown gate stays the source
    /// of truth.
    StillActive,
    /// Active → Recovering. No notification.
    EnteringRecovery,
    /// Recovering → Healthy. Caller should dispatch a `Resolve` notification
    /// (no cooldown applies — recovery events are always one-shot).
    Resolve,
    /// Recovering → Active (re-breach inside the resolved window). No
    /// notification — the rule is still considered alerting.
    Reactivate,
    /// No transition; the rule remains in its prior state.
    Quiet,
}

#[derive(Debug)]
pub struct RecoveryGate {
    state: DashMap<u32, SharedRecoveryRuleMap>,
    inner_shard_amount: usize,
}

impl Default for RecoveryGate {
    fn default() -> Self {
        Self::new()
    }
}

impl RecoveryGate {
    pub fn new() -> Self {
        let shard_amount = pool_shard_amount(0);
        Self {
            state: DashMap::with_shard_amount(shard_amount),
            inner_shard_amount: shard_amount,
        }
    }

    /// Advance the state machine for `(rule_id, proxy_id, ownership_generation)`
    /// based on whether the current observation is above threshold (`breach`).
    /// `recovery_ms` is the configured `resolved_window_seconds * 1000`; pass
    /// `0` for rules that opt out of recovery (in which case `Resolve` will
    /// never be returned).
    pub fn observe(
        &self,
        rule_id: u32,
        proxy_id: &str,
        breach: bool,
        recovery_ms: u64,
        now_ms: u64,
        ownership_generation: u64,
    ) -> LifecycleOutcome {
        let per_generation = self.per_proxy_generations(rule_id, proxy_id);
        let mut entry = if let Some(existing) = per_generation.get_mut(&ownership_generation) {
            existing
        } else {
            per_generation
                .entry(ownership_generation)
                .or_insert(RuleState::Healthy)
        };
        Self::transition(entry.value_mut(), breach, recovery_ms, now_ms)
    }

    /// Evaluate the next lifecycle outcome without mutating state.
    ///
    /// Used by the dispatch path so Trigger/Resolve transitions can be
    /// committed only after at least one notification channel accepts the
    /// event. Non-notifying outcomes still use [`Self::observe`] directly.
    ///
    /// # Concurrency: deliberate TOCTOU + commit-or-drop
    ///
    /// `evaluate()` reads state without a lock and `observe()` commits the
    /// transition later, after dispatch permits + cooldowns are reserved. The
    /// dispatch loop in `mod.rs` gates the commit on the freshly-observed
    /// outcome still matching the originally-evaluated `event_action`; if the
    /// state shifted between evaluate and observe (high-frequency
    /// breach/recover oscillation, or a sibling worker racing the same
    /// rule/proxy), the dispatch is dropped rather than fired against stale
    /// reasoning.
    ///
    /// This is by design: under concurrent oscillation a missed alert is
    /// preferable to a phantom alert. Adding a lock to make evaluate+commit
    /// atomic would serialise every observation through a single critical
    /// section per `(rule, proxy)` and defeat the lock-free hot path.
    pub fn evaluate(
        &self,
        rule_id: u32,
        proxy_id: &str,
        breach: bool,
        recovery_ms: u64,
        now_ms: u64,
        ownership_generation: u64,
    ) -> LifecycleOutcome {
        let state = self
            .state
            .get(&rule_id)
            .and_then(|per_rule| {
                per_rule.get(proxy_id).and_then(|generations| {
                    generations
                        .get(&ownership_generation)
                        .map(|entry| *entry.value())
                })
            })
            .unwrap_or(RuleState::Healthy);
        let mut state = state;
        Self::transition(&mut state, breach, recovery_ms, now_ms)
    }

    fn per_proxy_generations(&self, rule_id: u32, proxy_id: &str) -> SharedRecoveryGenerationMap {
        let per_rule = self.per_rule(rule_id);
        if let Some(existing) = per_rule.get(proxy_id) {
            Arc::clone(existing.value())
        } else {
            Arc::clone(
                per_rule
                    .entry(proxy_id.to_string())
                    .or_insert_with(|| {
                        Arc::new(DashMap::with_shard_amount(self.inner_shard_amount))
                    })
                    .value(),
            )
        }
    }

    fn per_rule(&self, rule_id: u32) -> SharedRecoveryRuleMap {
        if let Some(existing) = self.state.get(&rule_id) {
            Arc::clone(existing.value())
        } else {
            Arc::clone(
                self.state
                    .entry(rule_id)
                    .or_insert_with(|| {
                        Arc::new(DashMap::with_shard_amount(self.inner_shard_amount))
                    })
                    .value(),
            )
        }
    }

    fn transition(
        state: &mut RuleState,
        breach: bool,
        recovery_ms: u64,
        now_ms: u64,
    ) -> LifecycleOutcome {
        match (*state, breach) {
            (RuleState::Healthy, true) => {
                *state = RuleState::Active {
                    fired_at_ms: now_ms,
                };
                LifecycleOutcome::Trigger
            }
            (RuleState::Healthy, false) => LifecycleOutcome::Quiet,
            (RuleState::Active { .. }, true) => LifecycleOutcome::StillActive,
            (RuleState::Active { .. }, false) if recovery_ms == 0 => {
                *state = RuleState::Healthy;
                LifecycleOutcome::Quiet
            }
            (RuleState::Active { .. }, false) => {
                *state = RuleState::Recovering {
                    left_threshold_at_ms: now_ms,
                };
                LifecycleOutcome::EnteringRecovery
            }
            (
                RuleState::Recovering {
                    left_threshold_at_ms,
                },
                false,
            ) => {
                if recovery_ms > 0 && now_ms.saturating_sub(left_threshold_at_ms) >= recovery_ms {
                    *state = RuleState::Healthy;
                    LifecycleOutcome::Resolve
                } else if recovery_ms == 0 {
                    *state = RuleState::Healthy;
                    LifecycleOutcome::Quiet
                } else {
                    LifecycleOutcome::Quiet
                }
            }
            (RuleState::Recovering { .. }, true) if recovery_ms == 0 => {
                *state = RuleState::Active {
                    fired_at_ms: now_ms,
                };
                LifecycleOutcome::Trigger
            }
            (RuleState::Recovering { .. }, true) => {
                *state = RuleState::Active {
                    fired_at_ms: now_ms,
                };
                LifecycleOutcome::Reactivate
            }
        }
    }

    /// Returns the current state for the given (rule, proxy, generation)
    /// triple, or `None` if no observation has been recorded yet. Useful for
    /// tests and admin debugging.
    #[allow(dead_code)] // Used by external test crate and future admin debug surface.
    pub fn current_state(
        &self,
        rule_id: u32,
        proxy_id: &str,
        ownership_generation: u64,
    ) -> Option<RuleState> {
        self.state.get(&rule_id).and_then(|per_rule| {
            per_rule.get(proxy_id).and_then(|generations| {
                generations
                    .get(&ownership_generation)
                    .map(|e| *e.value())
            })
        })
    }

    /// Drop recovery rows for proxies absent from `active_proxy_generations`
    /// or whose stored generation does not match the published incarnation.
    ///
    /// Cold-path only: called after incremental plugin-cache commit when a
    /// preserved global/proxy-group instance outlives individual proxies.
    pub fn retain_proxies(&self, active_proxy_generations: &HashMap<&str, u64>) {
        self.state.retain(|_, per_rule| {
            per_rule.retain(|proxy_id, generations| {
                match active_proxy_generations.get(proxy_id.as_str()).copied() {
                    Some(active_gen) => {
                        generations.retain(|&gen, _| gen == active_gen);
                        !generations.is_empty()
                    }
                    None => false,
                }
            });
            !per_rule.is_empty()
        });
    }

    /// Drop terminal `Healthy` rows left after a Resolve (or recovery-less
    /// reset). Active/Recovering incidents are owned by
    /// [`Self::retain_proxies`] so a long-lived breach is never TTL-reset
    /// while its proxy remains in the active set.
    pub fn evict_stale(&self, _now_ms: u64, _keep_ms: u64) {
        self.state.retain(|_, per_rule| {
            per_rule.retain(|_, generations| {
                generations.retain(|_, state| !matches!(*state, RuleState::Healthy));
                !generations.is_empty()
            });
            !per_rule.is_empty()
        });
    }

    /// Whether any rule map currently holds a row for `proxy_id` under any
    /// ownership generation.
    #[allow(dead_code)] // Used by external test crate and admin/debug helpers.
    pub fn contains_proxy(&self, proxy_id: &str) -> bool {
        self.state.iter().any(|entry| {
            entry
                .value()
                .get(proxy_id)
                .is_some_and(|generations| !generations.is_empty())
        })
    }

    /// Whether any rule map holds a row for `(proxy_id, generation)`.
    #[allow(dead_code)] // Used by external test crate.
    pub fn contains_proxy_generation(&self, proxy_id: &str, ownership_generation: u64) -> bool {
        self.state.iter().any(|entry| {
            entry
                .value()
                .get(proxy_id)
                .is_some_and(|generations| generations.contains_key(&ownership_generation))
        })
    }
}
