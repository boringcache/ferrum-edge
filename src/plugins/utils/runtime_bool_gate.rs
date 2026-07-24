//! Shared process-global boolean gate storage for RTDS overlay consumers.
//!
//! Plugins own their static store and key namespace, but the cold-path
//! mechanics are identical: rebuild a `HashMap<String, bool>` from a
//! [`MeshRuntimeOverlay`], publish it through `ArcSwap`, and let hot paths
//! read a cheap snapshot.
//!
//! ## Gate provenance
//!
//! A consumer whose gate decision shapes a representation that outlives the
//! request (today `response_caching` storing a `response_transformer` output)
//! needs to know *which* published gate map produced those bytes. Publishing
//! a [`GateProvenance`] alongside the map gives it two cheap request-path
//! reads:
//!
//! - [`GateProvenance::fingerprint`] — content digest of the published map.
//!   Content-keyed rather than monotonic on purpose: a gate that flips away
//!   and back to an identical map really does describe the stored
//!   representation, and an unrelated plugin's overlay store never disturbs
//!   this one.
//! - [`GateProvenance::epoch`] — monotonic publication count, used only to
//!   detect "a publication happened while this request was in flight", which
//!   a content digest alone cannot see across an A→B→A sequence.

use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use arc_swap::ArcSwap;

use crate::modes::mesh::config::MeshRuntimeOverlay;

use super::transformer_gate;

pub type BoolGateMap = HashMap<String, bool>;

/// Publication provenance for one gate store.
///
/// Both values are plain atomics so request-path readers do no allocation and
/// take no lock.
pub struct GateProvenance {
    fingerprint: AtomicU64,
    epoch: AtomicU64,
}

impl GateProvenance {
    /// Provenance of a store that has never published, i.e. the empty gate map.
    pub const fn new() -> Self {
        Self {
            fingerprint: AtomicU64::new(EMPTY_GATE_FINGERPRINT),
            epoch: AtomicU64::new(0),
        }
    }

    /// Content digest of the currently published gate map.
    ///
    /// Two publications with equal gates share a fingerprint, so a stored
    /// representation stamped with it is replayable exactly while the policy
    /// that produced it is still live.
    pub fn fingerprint(&self) -> u64 {
        self.fingerprint.load(Ordering::Acquire)
    }

    /// Monotonic count of publications to this store.
    pub fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::Acquire)
    }

    /// Record a publication **after** the new map is visible in the `ArcSwap`.
    ///
    /// Ordering is load-bearing. Publishing the map first means a reader can
    /// only ever observe (new gates, old provenance), which makes a persisted
    /// representation look older than the policy that produced it — the safe
    /// direction, costing at most one extra invalidation. The inverse
    /// (old gates, new provenance) would stamp a stale representation as
    /// current and let it bypass a newer policy, so it must stay impossible.
    pub fn publish(&self, fingerprint: u64) {
        self.fingerprint.store(fingerprint, Ordering::Release);
        self.epoch.fetch_add(1, Ordering::AcqRel);
    }
}

impl Default for GateProvenance {
    fn default() -> Self {
        Self::new()
    }
}

/// Fingerprint reserved for "no gates published". Held as a constant so
/// [`GateProvenance::new`] stays `const` and a never-published store already
/// reads the same value a later empty publication would produce.
const EMPTY_GATE_FINGERPRINT: u64 = 0;

/// Order-independent content digest of a gate map.
///
/// Cold path (publication only). Per-entry digests are XOR-folded so the
/// result does not depend on `HashMap` iteration order, and the entry count is
/// mixed in so no set of entries can cancel out to the empty fingerprint.
fn fingerprint_of(gates: &BoolGateMap) -> u64 {
    if gates.is_empty() {
        return EMPTY_GATE_FINGERPRINT;
    }
    let mut folded = 0u64;
    for (scope, enabled) in gates {
        let mut hasher = DefaultHasher::new();
        scope.hash(&mut hasher);
        enabled.hash(&mut hasher);
        folded ^= hasher.finish();
    }
    let mut hasher = DefaultHasher::new();
    folded.hash(&mut hasher);
    gates.len().hash(&mut hasher);
    let fingerprint = hasher.finish();
    // Never collide with "nothing published"; an all-ones nudge keeps the
    // mapping injective for every other input.
    if fingerprint == EMPTY_GATE_FINGERPRINT {
        u64::MAX
    } else {
        fingerprint
    }
}

#[derive(Clone)]
pub struct BoolGateSnapshot {
    inner: Arc<BoolGateMap>,
}

impl BoolGateSnapshot {
    pub fn gate(&self, scope: &str) -> Option<bool> {
        self.inner.get(scope).copied()
    }
}

pub fn new_store() -> ArcSwap<BoolGateMap> {
    ArcSwap::new(Arc::new(HashMap::new()))
}

pub fn current_snapshot(store: &ArcSwap<BoolGateMap>) -> BoolGateSnapshot {
    BoolGateSnapshot {
        inner: store.load_full(),
    }
}

/// Publish a rebuilt gate map and return its content fingerprint.
///
/// Consumers that expose provenance pass the returned value to
/// [`GateProvenance::publish`]; consumers that do not simply ignore it.
pub fn apply_overlay(
    store: &ArcSwap<BoolGateMap>,
    overlay: &MeshRuntimeOverlay,
    key_prefix: &str,
    enabled_suffix: &str,
) -> u64 {
    let mut next = HashMap::new();
    transformer_gate::collect_gates(overlay, key_prefix, enabled_suffix, &mut next);
    let fingerprint = fingerprint_of(&next);
    store.store(Arc::new(next));
    fingerprint
}

/// Clear a gate store and return the empty map's fingerprint.
pub fn reset(store: &ArcSwap<BoolGateMap>) -> u64 {
    store.store(Arc::new(HashMap::new()));
    EMPTY_GATE_FINGERPRINT
}
