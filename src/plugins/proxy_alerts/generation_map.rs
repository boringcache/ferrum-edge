//! Compact ownership-generation → value maps for `proxy_alerts` lifecycle rows.
//!
//! Per-proxy lifecycle state is almost always a single live generation. A
//! pool-sharded `DashMap` for that dimension would cost many KB per essentially
//! one-entry row. This module stores generations in a small
//! poison-recovering `Mutex<HashMap<…>>` instead.
//!
//! Outer `rule` / `proxy` (and cooldown `channel`) dimensions remain pool-sharded
//! `DashMap`s. Callers that store `Arc` values look up under the brief map lock,
//! then perform lock-free atomic work after the guard is dropped.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

/// Concurrent map from admission ownership generation → value.
#[derive(Default)]
pub(crate) struct GenerationMap<V> {
    inner: Mutex<HashMap<u64, V>>,
}

impl<V> GenerationMap<V> {
    pub(crate) fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<u64, V>> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    pub(crate) fn contains_key(&self, generation: &u64) -> bool {
        self.lock().contains_key(generation)
    }

    pub(crate) fn get_cloned(&self, generation: &u64) -> Option<V>
    where
        V: Clone,
    {
        self.lock().get(generation).cloned()
    }

    pub(crate) fn get_copied(&self, generation: &u64) -> Option<V>
    where
        V: Copy,
    {
        self.lock().get(generation).copied()
    }

    /// Return a clone of the value for `generation`, inserting with `init` on miss.
    ///
    /// Steady-state hits allocate nothing beyond the `V: Clone` cost (typically
    /// an `Arc` bump).
    pub(crate) fn get_or_insert_with(&self, generation: u64, init: impl FnOnce() -> V) -> V
    where
        V: Clone,
    {
        let mut guard = self.lock();
        if let Some(existing) = guard.get(&generation) {
            return existing.clone();
        }
        let value = init();
        guard.insert(generation, value.clone());
        value
    }

    /// Mutate the value for `generation`, inserting with `init` on miss.
    pub(crate) fn with_mut<R>(
        &self,
        generation: u64,
        init: impl FnOnce() -> V,
        f: impl FnOnce(&mut V) -> R,
    ) -> R {
        let mut guard = self.lock();
        let value = guard.entry(generation).or_insert_with(init);
        f(value)
    }

    pub(crate) fn retain(&self, f: impl FnMut(&u64, &mut V) -> bool) {
        self.lock().retain(f);
    }
}

impl<V: std::fmt::Debug> std::fmt::Debug for GenerationMap<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let guard = self.lock();
        f.debug_map().entries(guard.iter()).finish()
    }
}
