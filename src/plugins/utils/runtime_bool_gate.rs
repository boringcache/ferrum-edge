//! Shared process-global boolean gate storage for RTDS overlay consumers.
//!
//! Plugins own their static store and key namespace, but the cold-path
//! mechanics are identical: rebuild a `HashMap<String, bool>` from a
//! [`MeshRuntimeOverlay`], publish it through `ArcSwap`, and let hot paths
//! read a cheap snapshot.

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::modes::mesh::config::MeshRuntimeOverlay;

use super::transformer_gate;

pub type BoolGateMap = HashMap<String, bool>;

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

pub fn apply_overlay(
    store: &ArcSwap<BoolGateMap>,
    overlay: &MeshRuntimeOverlay,
    key_prefix: &str,
    enabled_suffix: &str,
) {
    let mut next = HashMap::new();
    transformer_gate::collect_gates(overlay, key_prefix, enabled_suffix, &mut next);
    store.store(Arc::new(next));
}

pub fn reset(store: &ArcSwap<BoolGateMap>) {
    store.store(Arc::new(HashMap::new()));
}
