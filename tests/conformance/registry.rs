//! Process-global conformance feature registry.
//!
//! Each conformance test calls [`register`] (typically via the
//! [`register_feature!`] macro) before its assertions. The registry stores
//! `(category, feature, status, notes, test_name)` tuples behind a mutex; the
//! end-of-suite reporter ([`super::report`]) drains the registry to produce
//! the coverage matrix.
//!
//! Concurrency: `cargo test` runs test functions in parallel. The mutex
//! protects against races and duplicate registrations — duplicates are silently
//! deduplicated on `(category, feature)` so a test that runs twice (e.g. via
//! `cargo test -- --test-threads=2`) doesn't inflate the matrix.

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Status {
    /// The feature works as documented. Most entries should land here.
    Supported,
    /// Known not-yet-implemented; the test records the assertion needed to
    /// flip the status to `Supported` once the gap closes. Operators see a
    /// clear note explaining why.
    Deferred,
    /// Explicit non-goals (e.g. Wasm, EnvoyFilter). Documented for completeness
    /// so operators don't keep asking.
    OutOfScope,
}

/// Maturity tier for a conformance feature. This is what makes the matrix
/// *prescriptive* instead of merely observational.
///
/// - [`Maturity::Ga`] features are a product promise: they MUST be
///   [`Status::Supported`]. The per-call assertion in [`register`] fails the
///   declaring test the moment a GA feature is registered as anything else, so
///   a silent `Supported → Deferred` downgrade can no longer keep CI green.
///   (Full GA additionally requires the live-datapath e2e gate; see the GA
///   contract in `ga_scope.rs`.)
/// - [`Maturity::Beta`] / [`Maturity::Experimental`] features are
///   observational — they may be `Deferred` without failing CI, and are where
///   the in-progress mesh surface lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Maturity {
    /// Contractually promised. Must be `Supported`; a regression fails CI.
    Ga,
    /// Feature-complete and tested, but with a documented sharp edge or an owed
    /// verification step. Observational in the matrix.
    Beta,
    /// Usable with a safety caveat, or partial. Observational.
    Experimental,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Feature {
    pub category: &'static str,
    pub feature: String,
    pub status: Status,
    pub maturity: Maturity,
    pub notes: Option<String>,
    pub test_name: &'static str,
}

fn registry() -> &'static Mutex<BTreeMap<(String, String), Feature>> {
    static REGISTRY: OnceLock<Mutex<BTreeMap<(String, String), Feature>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(BTreeMap::new()))
}

pub(crate) fn register(
    category: &'static str,
    feature: impl Into<String>,
    status: Status,
    maturity: Maturity,
    notes: Option<String>,
    test_name: &'static str,
) {
    let feature = feature.into();
    // GA-scope gate (ordering-independent): a feature we contractually promise
    // as GA must be Supported. If a regression forces its test down to Deferred
    // (or OutOfScope), fail *this* test immediately rather than silently
    // shrinking the green matrix — this is what makes the suite prescriptive for
    // GA scope instead of merely observational. Beta/Experimental are exempt.
    assert!(
        maturity != Maturity::Ga || status == Status::Supported,
        "GA-scope conformance feature `{category}/{feature}` is {status:?}, expected Supported. \
         A GA feature regressed or was downgraded; fix the regression, or — if the change is \
         intentional — drop it from GA scope (and the supported-feature matrix) deliberately.",
    );
    let key = (category.to_string(), feature.clone());
    let entry = Feature {
        category,
        feature,
        status,
        maturity,
        notes,
        test_name,
    };
    if let Ok(mut guard) = registry().lock() {
        // Insert-or-replace: a test that runs more than once should record the
        // *latest* status. Tests that legitimately register the same feature
        // (e.g., the matcher matrix module covering one VS predicate in two
        // tests) should pick distinct feature names.
        guard.insert(key, entry);
    }
}

pub(crate) fn snapshot() -> Vec<Feature> {
    let guard = match registry().lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    guard.values().cloned().collect()
}

/// Convenience macro that auto-populates `test_name` from the surrounding
/// `fn` via `function_name!()`-style stringification — or, simpler, from a
/// caller-supplied `module_path` plus literal.
///
/// Usage:
/// ```ignore
/// register_feature!(
///     category = "istio_virtual_service",
///     feature = "uri.exact",
///     status = Status::Supported,
/// );
/// ```
///
/// The macro stamps `module_path!()` as the test name so the matrix points
/// operators at the test that proved the behavior.
///
/// `maturity` is optional and defaults to [`Maturity::Beta`] (observational).
/// Pass `maturity = $crate::conformance::registry::Maturity::Ga` to put a
/// feature under the prescriptive GA contract — it must then be
/// [`Status::Supported`] or the test fails.
#[macro_export]
macro_rules! register_feature {
    (
        category = $category:expr,
        feature = $feature:expr,
        status = $status:expr,
        maturity = $maturity:expr,
        notes = $notes:expr $(,)?
    ) => {
        $crate::conformance::registry::register(
            $category,
            $feature,
            $status,
            $maturity,
            Some(($notes).to_string()),
            module_path!(),
        );
    };
    (
        category = $category:expr,
        feature = $feature:expr,
        status = $status:expr,
        maturity = $maturity:expr $(,)?
    ) => {
        $crate::conformance::registry::register(
            $category,
            $feature,
            $status,
            $maturity,
            None,
            module_path!(),
        );
    };
    (
        category = $category:expr,
        feature = $feature:expr,
        status = $status:expr,
        notes = $notes:expr $(,)?
    ) => {
        $crate::conformance::registry::register(
            $category,
            $feature,
            $status,
            $crate::conformance::registry::Maturity::Beta,
            Some(($notes).to_string()),
            module_path!(),
        );
    };
    (
        category = $category:expr,
        feature = $feature:expr,
        status = $status:expr $(,)?
    ) => {
        $crate::conformance::registry::register(
            $category,
            $feature,
            $status,
            $crate::conformance::registry::Maturity::Beta,
            None,
            module_path!(),
        );
    };
}
