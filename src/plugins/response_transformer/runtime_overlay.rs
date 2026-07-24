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
use crate::plugins::utils::runtime_bool_gate::{self, BoolGateMap, GateProvenance};

pub(crate) const KEY_PREFIX: &str = "ferrum.response_transformer.";
pub(crate) const ENABLED_SUFFIX: &str = ".enabled";

static GATES: LazyLock<ArcSwap<BoolGateMap>> = LazyLock::new(runtime_bool_gate::new_store);

/// Publication provenance for [`GATES`].
///
/// These gates decide whether client-visible header/body rules run, so a
/// representation cached by `response_caching` is only replayable while the
/// same gate map is live. The cache stamps [`policy_fingerprint`] onto every
/// stored entry and uses [`publication_epoch`] to notice a publication that
/// landed mid-request. Both are process-global, matching [`GATES`].
static PROVENANCE: GateProvenance = GateProvenance::new();

pub type GateSnapshot = runtime_bool_gate::BoolGateSnapshot;

pub fn current_gates() -> GateSnapshot {
    runtime_bool_gate::current_snapshot(&GATES)
}

/// Content digest of the live response-side gate map (one atomic load).
///
/// Equal digests mean equal gate decisions, so a cached representation stamped
/// with this value was produced under exactly the policy in force now.
pub fn policy_fingerprint() -> u64 {
    PROVENANCE.fingerprint()
}

/// Monotonic count of response-side gate publications (one atomic load).
pub fn publication_epoch() -> u64 {
    PROVENANCE.epoch()
}

pub fn apply_overlay(overlay: &MeshRuntimeOverlay) {
    let fingerprint = runtime_bool_gate::apply_overlay(&GATES, overlay, KEY_PREFIX, ENABLED_SUFFIX);
    PROVENANCE.publish(fingerprint);
}

/// Same contract as
/// [`crate::plugins::request_transformer::runtime_overlay::reset_for_test`].
#[doc(hidden)]
#[allow(dead_code)]
pub fn reset_for_test() {
    let fingerprint = runtime_bool_gate::reset(&GATES);
    PROVENANCE.publish(fingerprint);
}
