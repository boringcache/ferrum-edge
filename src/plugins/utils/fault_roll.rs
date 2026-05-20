//! Shared percent-roll helper for fault-injection style plugins.
//!
//! Both the proxy-scoped [`fault_injection`](crate::plugins::fault_injection)
//! plugin and the per-rule `Fault` action carried by
//! [`mesh_route_dispatch`](crate::plugins::mesh_route_dispatch) make the same
//! per-request "did this percentile roll hit?" decision. Keeping the math in
//! one place ensures both surfaces stay semantically identical: same RNG,
//! same threshold mapping, same handling of the `>= 100.0` short-circuit.
//!
//! ## Sampling model
//!
//! Each call to [`FaultRoller::roll_pair`] consumes one `AtomicU64::fetch_add`
//! and one `splitmix64` mix, then splits the 64-bit mix into two independent
//! 32-bit samples (delay = high 32, abort = low 32). Each sample is compared
//! against `(percentage / 100) * 2^32` to decide whether the roll hit.
//!
//! ## Hot-path properties
//!
//! - Zero allocations.
//! - One relaxed atomic increment per call.
//! - Pure arithmetic — no syscalls, no `thread_rng()` lazy init, no locks.

use std::sync::atomic::{AtomicU64, Ordering};

const PROBABILITY_DENOMINATOR: u64 = 1 << 32;

/// Per-instance roll counter. Wrap one of these per plugin instance (or per
/// per-rule action carrier) so concurrent requests get distinct samples and
/// percentile distributions converge to the configured percentage.
#[derive(Debug, Default)]
pub struct FaultRoller {
    counter: AtomicU64,
}

/// Outcome of one paired roll for delay + abort.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FaultRollOutcome {
    pub delay_triggered: bool,
    pub abort_triggered: bool,
}

impl FaultRoller {
    pub fn new() -> Self {
        Self::default()
    }

    /// Roll for both delay and abort percentages in one atomic-counter
    /// increment.
    ///
    /// `None` for either percentage skips that side (returns `false`).
    /// `Some(pct)` rolls a single 32-bit sample against `pct / 100`.
    /// `pct >= 100.0` is a definite hit, `pct <= 0.0` is a definite miss.
    pub fn roll_pair(
        &self,
        delay_percentage: Option<f64>,
        abort_percentage: Option<f64>,
    ) -> FaultRollOutcome {
        let sample = splitmix64(self.counter.fetch_add(1, Ordering::Relaxed));
        let delay_sample = (sample >> 32) as u32;
        let abort_sample = sample as u32;
        FaultRollOutcome {
            delay_triggered: delay_percentage.is_some_and(|pct| probability_hit(delay_sample, pct)),
            abort_triggered: abort_percentage.is_some_and(|pct| probability_hit(abort_sample, pct)),
        }
    }
}

/// Compare a 32-bit sample against a percentage threshold.
///
/// `percentage >= 100.0` always hits; `percentage <= 0.0` never hits.
/// Non-finite (`NaN`, `+Inf`, `-Inf`) inputs are treated as misses so a
/// future bug that lets garbage reach the hot path can never accidentally
/// fire 100% faults. Config validators reject non-finite / out-of-range
/// inputs at construction; this is defense-in-depth.
pub fn probability_hit(sample: u32, percentage: f64) -> bool {
    if !percentage.is_finite() {
        return false;
    }
    if percentage >= 100.0 {
        return true;
    }
    if percentage <= 0.0 {
        return false;
    }
    let threshold = ((percentage / 100.0) * PROBABILITY_DENOMINATOR as f64) as u64;
    u64::from(sample) < threshold
}

/// 64-bit SplitMix used as a stateless mixer over a monotonic counter.
/// Identical constants to the canonical `splitmix64` finalizer — keeps
/// sample distribution identical to the original fault-injection plugin.
pub fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9E3779B97F4A7C15);
    value = (value ^ (value >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94D049BB133111EB);
    value ^ (value >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probability_hit_zero_and_below_never_hits() {
        assert!(!probability_hit(0, 0.0));
        assert!(!probability_hit(u32::MAX, 0.0));
        assert!(!probability_hit(u32::MAX, -10.0));
    }

    #[test]
    fn probability_hit_one_hundred_and_above_always_hits() {
        assert!(probability_hit(0, 100.0));
        assert!(probability_hit(u32::MAX, 100.0));
        assert!(probability_hit(u32::MAX, 150.0));
    }

    #[test]
    fn probability_hit_non_finite_never_hits() {
        assert!(!probability_hit(0, f64::NAN));
        assert!(!probability_hit(0, f64::INFINITY));
        assert!(!probability_hit(0, f64::NEG_INFINITY));
    }

    #[test]
    fn roll_pair_with_zero_percentages_never_triggers() {
        let roller = FaultRoller::new();
        for _ in 0..1000 {
            let outcome = roller.roll_pair(Some(0.0), Some(0.0));
            assert!(!outcome.delay_triggered);
            assert!(!outcome.abort_triggered);
        }
    }

    #[test]
    fn roll_pair_with_full_percentages_always_triggers() {
        let roller = FaultRoller::new();
        for _ in 0..1000 {
            let outcome = roller.roll_pair(Some(100.0), Some(100.0));
            assert!(outcome.delay_triggered);
            assert!(outcome.abort_triggered);
        }
    }

    #[test]
    fn roll_pair_with_none_returns_false_for_that_side() {
        let roller = FaultRoller::new();
        // Even at 100% on the configured side, the unset side should never trigger.
        for _ in 0..100 {
            let outcome = roller.roll_pair(None, Some(100.0));
            assert!(!outcome.delay_triggered);
            assert!(outcome.abort_triggered);
        }
        // And vice versa.
        for _ in 0..100 {
            let outcome = roller.roll_pair(Some(100.0), None);
            assert!(outcome.delay_triggered);
            assert!(!outcome.abort_triggered);
        }
    }

    #[test]
    fn roll_pair_converges_to_configured_percentage() {
        // The sampler is deterministic given the counter sequence, so we can
        // assert a fairly tight bound. 50% over 10k draws should land near
        // 5000 hits; allow a 2.5% absolute slack to keep the test stable.
        let roller = FaultRoller::new();
        let n = 10_000;
        let mut hits = 0usize;
        for _ in 0..n {
            if roller.roll_pair(Some(50.0), None).delay_triggered {
                hits += 1;
            }
        }
        let ratio = hits as f64 / n as f64;
        assert!(
            (ratio - 0.5).abs() < 0.025,
            "50% over {n} draws produced {hits} hits ({ratio}); expected ~5000"
        );
    }
}
