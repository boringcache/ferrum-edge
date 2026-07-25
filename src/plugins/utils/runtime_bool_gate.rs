//! Shared process-global boolean gate storage for RTDS overlay consumers.
//!
//! Plugins own their static store and key namespace, but the cold-path
//! mechanics are identical: rebuild a `HashMap<String, bool>` from a
//! [`MeshRuntimeOverlay`], publish it through `ArcSwap`, and let hot paths read
//! a cheap snapshot.
//!
//! ## Gate provenance
//!
//! A consumer whose gate decision shapes a representation that outlives the
//! request (today `response_caching` storing a `response_transformer` output)
//! must know which exact publication produced those bytes. The gate map and an
//! opaque [`GatePolicyStamp`] are therefore published together in one ArcSwap
//! state. A reader can never observe a new map paired with an old stamp (or the
//! inverse), and pointer identity cannot collide or wrap like an integer digest
//! or generation counter.

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use sha2::{Digest, Sha256};

use crate::modes::mesh::config::MeshRuntimeOverlay;

use super::transformer_gate;

pub type BoolGateMap = HashMap<String, bool>;

/// Opaque identity of one atomically published gate-map state.
///
/// The token carries no gate, rule, header, or body content. Equality uses
/// allocation identity, so two different publications can never compare equal.
#[derive(Clone)]
pub struct GatePolicyStamp(Arc<GatePublication>);

#[derive(Debug)]
struct GatePublication {
    fingerprint: [u8; 32],
}

impl GatePolicyStamp {
    fn new(gates: &BoolGateMap) -> Self {
        let mut entries: Vec<_> = gates.iter().collect();
        entries.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
        let mut digest = Sha256::new();
        for (scope, enabled) in entries {
            digest.update((scope.len() as u64).to_be_bytes());
            digest.update(scope.as_bytes());
            digest.update([u8::from(*enabled)]);
        }
        Self(Arc::new(GatePublication {
            fingerprint: digest.finalize().into(),
        }))
    }

    /// Stable, content-only identity suitable for provenance stored outside
    /// this process. It reveals no scope names or gate values.
    pub(crate) fn fingerprint(&self) -> [u8; 32] {
        self.0.fingerprint
    }
}

impl std::fmt::Debug for GatePolicyStamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GatePolicyStamp(<opaque>)")
    }
}

impl PartialEq for GatePolicyStamp {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for GatePolicyStamp {}

/// One atomically published gate map and its unforgeable publication identity.
pub struct BoolGateState {
    gates: BoolGateMap,
    stamp: GatePolicyStamp,
}

impl BoolGateState {
    fn new(gates: BoolGateMap) -> Self {
        Self {
            gates,
            stamp: GatePolicyStamp::new(&gates),
        }
    }
}

pub type BoolGateStore = ArcSwap<BoolGateState>;

#[derive(Clone)]
pub struct BoolGateSnapshot {
    inner: Arc<BoolGateState>,
}

impl BoolGateSnapshot {
    pub fn gate(&self, scope: &str) -> Option<bool> {
        self.inner.gates.get(scope).copied()
    }
}

pub fn new_store() -> BoolGateStore {
    ArcSwap::new(Arc::new(BoolGateState::new(HashMap::new())))
}

pub fn current_snapshot(store: &BoolGateStore) -> BoolGateSnapshot {
    BoolGateSnapshot {
        inner: store.load_full(),
    }
}

/// Return the identity paired atomically with the currently published map.
pub fn current_policy_stamp(store: &BoolGateStore) -> GatePolicyStamp {
    store.load().stamp.clone()
}

/// Publish a rebuilt gate map and a fresh identity in one atomic store.
///
/// Reapplying the identical current map is a no-op, avoiding needless cache
/// invalidation for repeated equivalent RTDS updates. A real A→B→A cycle still
/// receives a fresh identity on the final A and conservatively retires entries
/// that survived from the first A.
pub fn apply_overlay(
    store: &BoolGateStore,
    overlay: &MeshRuntimeOverlay,
    key_prefix: &str,
    enabled_suffix: &str,
) {
    let mut next = HashMap::new();
    transformer_gate::collect_gates(overlay, key_prefix, enabled_suffix, &mut next);
    if store.load().gates.eq(&next) {
        return;
    }
    store.store(Arc::new(BoolGateState::new(next)));
}

/// Clear a gate store. Already-empty state is left untouched.
pub fn reset(store: &BoolGateStore) {
    if store.load().gates.is_empty() {
        return;
    }
    store.store(Arc::new(BoolGateState::new(HashMap::new())));
}
