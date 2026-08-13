//! Process-wide lock shared by every gateway-trust observability unit test.
//!
//! `config::gateway_trust`'s counters and its published-namespace `ArcSwap` map
//! are PROCESS-GLOBAL by design (a per-namespace label would be unbounded on a
//! cluster-wide control plane, so the namespace-scoped view lives on the
//! authenticated admin surface instead). `cargo test --test unit_tests` runs
//! tests in parallel, and `record_trust_generation_published` REPLACES the whole
//! published map, so any two tests that call it — or that call
//! `reset_observability_for_tests` — must serialize against one mutex or each
//! will wipe the other's state mid-assertion.
//!
//! A per-file mutex is not a substitute: the observability assertions live in
//! `config::gateway_trust_bundle_tests` AND
//! `gateway_core::gateway_trust_runtime_publication_tests`, which are separate
//! modules in the SAME binary, so a per-file lock would order each file against
//! itself while leaving the two racing each other.
//!
//! Acquire it poison-tolerantly (`unwrap_or_else(|p| p.into_inner())`): it
//! guards no invariant of its own, only mutual exclusion, so one panicking test
//! must not cascade into unrelated failures across the binary.
#![allow(dead_code)] // used by sibling test modules

use std::sync::{Mutex, MutexGuard};

pub static GATEWAY_TRUST_OBSERVABILITY_LOCK: Mutex<()> = Mutex::new(());

/// Acquire the shared lock and reset every process-global gateway-trust counter
/// and the published-namespace map, so the caller starts from a known baseline.
///
/// Hold the returned guard for the whole test.
pub fn lock_gateway_trust_observability() -> MutexGuard<'static, ()> {
    let guard = GATEWAY_TRUST_OBSERVABILITY_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    ferrum_edge::config::gateway_trust::reset_observability_for_tests();
    guard
}
