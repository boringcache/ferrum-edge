//! Consumers for the xDS RTDS-driven [`MeshRuntimeOverlay`].
//!
//! Operators ship runtime knobs through the mesh xDS client; every accepted
//! slice runs through [`apply_overlay`] before the snapshot is published so
//! process-wide consumers can publish their current value without walking the
//! overlay on every request. Fault injection is deliberately absent: its
//! values are captured during plugin-cache construction and atomically
//! published with the request epoch whose config they modify.
//!
//! Consumer dispatch is by reserved key namespace:
//!
//! - `ferrum.log.level` — rebuild the tracing `EnvFilter` via the global
//!   reload handle installed at startup (`crate::logging::reload_layer`).
//! - `ferrum.request_transformer.<scope>.enabled` /
//!   `ferrum.response_transformer.<scope>.enabled` — gate the header /
//!   query / body rules of opted-in `request_transformer` /
//!   `response_transformer` plugins.
//!
//! GAP-3E note: the registry is intentionally tiny — each consumer owns its
//! own state and reads what it cares about. Adding a new consumer is a
//! single `apply_*` call from [`apply_overlay`] plus its own module-global
//! `ArcSwap` (or equivalent reload handle).

#![allow(dead_code)]

use std::sync::{LazyLock, Mutex, MutexGuard};

use crate::modes::mesh::config::MeshRuntimeOverlay;

static RUNTIME_OVERLAY_TEST_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

#[doc(hidden)]
pub fn test_lock() -> MutexGuard<'static, ()> {
    RUNTIME_OVERLAY_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Apply every RTDS-driven runtime knob exposed on `overlay`. Called from
/// `MeshRuntimeState::record_applied_slice` after the proxy runtime accepts a
/// slice so consumers never observe values from rejected updates.
///
/// Cold path; allocations are bounded by the number of `ferrum.*` keys in
/// the overlay. No-op when none are present.
pub fn apply_overlay(overlay: &MeshRuntimeOverlay) {
    crate::plugins::request_transformer::runtime_overlay::apply_overlay(overlay);
    crate::plugins::response_transformer::runtime_overlay::apply_overlay(overlay);
    crate::logging::runtime_overlay::apply_overlay(overlay);
}
