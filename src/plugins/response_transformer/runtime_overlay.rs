//! RTDS overlay consumer for the `response_transformer` plugin.
//!
//! Reserved keys (per opt-in scope `<scope>`):
//!
//! - `ferrum.response_transformer.<scope>.enabled` → `Bool`
//!
//! Mirrors the `request_transformer` overlay consumer
//! ([`crate::plugins::request_transformer::runtime_overlay`]) — the two
//! plugins maintain independent gate maps so an operator can disable one
//! direction without affecting the other.

use std::sync::LazyLock;

use arc_swap::ArcSwap;

use crate::modes::mesh::config::MeshRuntimeOverlay;
use crate::plugins::utils::runtime_bool_gate::{self, BoolGateMap};

pub(crate) const KEY_PREFIX: &str = "ferrum.response_transformer.";
pub(crate) const ENABLED_SUFFIX: &str = ".enabled";

static GATES: LazyLock<ArcSwap<BoolGateMap>> = LazyLock::new(runtime_bool_gate::new_store);

pub type GateSnapshot = runtime_bool_gate::BoolGateSnapshot;

pub fn current_gates() -> GateSnapshot {
    runtime_bool_gate::current_snapshot(&GATES)
}

pub fn apply_overlay(overlay: &MeshRuntimeOverlay) {
    runtime_bool_gate::apply_overlay(&GATES, overlay, KEY_PREFIX, ENABLED_SUFFIX);
}

/// Same contract as
/// [`crate::plugins::request_transformer::runtime_overlay::reset_for_test`].
#[doc(hidden)]
#[allow(dead_code)]
pub fn reset_for_test() {
    runtime_bool_gate::reset(&GATES);
}
