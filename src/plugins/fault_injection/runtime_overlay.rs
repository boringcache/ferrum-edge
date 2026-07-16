//! RTDS overlay consumer for the [`FaultInjectionPlugin`](super::FaultInjectionPlugin).
//!
//! Reserved keys (per opt-in scope `<scope>`):
//!
//! - `ferrum.fault_injection.<scope>.abort_percent`
//! - `ferrum.fault_injection.<scope>.delay_percent`
//!
//! Accepted value kinds:
//!
//! - `RuntimeValue::Number(0.0..=100.0)`
//! - `RuntimeValue::FractionalPercent(_)` (mapped to a 0–100 percentage via
//!   [`runtime_value_as_percent`](crate::modes::mesh::config::runtime_value_as_percent))
//!
//! Out-of-range numbers, non-finite values, and other variants (`Bool`,
//! `String`) are silently dropped on the cold path so a malformed overlay
//! never disables the plugin. The plugin's static `percentage` config is the
//! fallback when the scoped key is absent or invalid; a valid RTDS `0.0`
//! explicitly disables that fault side for the generation.
//!
//! Mesh preparation materializes valid scoped values directly into the
//! candidate plugin config. That effective config and its plugin cache publish
//! in one request epoch, so an in-flight old request retains the old effective
//! percentages. The request hot path performs no RTDS lookup or synchronization.

use std::collections::HashMap;

use serde_json::Value;

use crate::modes::mesh::config::{MeshRuntimeOverlay, runtime_value_as_percent};

const KEY_PREFIX: &str = "ferrum.fault_injection.";
const ABORT_SUFFIX: &str = ".abort_percent";
const DELAY_SUFFIX: &str = ".delay_percent";

/// Per-scope override values. Absent fields mean "fall back to static
/// config".
#[derive(Debug, Clone, Default, PartialEq)]
struct ScopeOverride {
    abort_percent: Option<f64>,
    delay_percent: Option<f64>,
}

type OverrideMap = HashMap<String, ScopeOverride>;

/// Parsed fault namespace of one candidate RTDS overlay.
#[derive(Default)]
struct FaultOverrides {
    inner: OverrideMap,
}

impl FaultOverrides {
    /// Build the fault namespace of an RTDS overlay on the cold path. Missing,
    /// malformed, and unrelated entries are omitted so the plugin falls back
    /// to its validated static percentages.
    fn from_overlay(overlay: &MeshRuntimeOverlay) -> Self {
        let mut next: OverrideMap = HashMap::new();
        for (raw_key, value) in &overlay.fields {
            let Some(rest) = raw_key.strip_prefix(KEY_PREFIX) else {
                continue;
            };
            // Strip whichever suffix is present; `<scope>` is everything
            // between the prefix and the suffix.
            let (scope, slot) = if let Some(scope) = rest.strip_suffix(ABORT_SUFFIX) {
                (scope, OverrideSlot::Abort)
            } else if let Some(scope) = rest.strip_suffix(DELAY_SUFFIX) {
                (scope, OverrideSlot::Delay)
            } else {
                continue;
            };
            if scope.is_empty() {
                continue;
            }
            let Some(pct) = runtime_value_as_percent(value) else {
                continue;
            };
            let entry = next.entry(scope.to_string()).or_default();
            match slot {
                OverrideSlot::Abort => entry.abort_percent = Some(pct),
                OverrideSlot::Delay => entry.delay_percent = Some(pct),
            }
        }
        Self { inner: next }
    }

    fn abort_percent(&self, scope: &str) -> Option<f64> {
        self.inner.get(scope).and_then(|s| s.abort_percent)
    }

    fn delay_percent(&self, scope: &str) -> Option<f64> {
        self.inner.get(scope).and_then(|s| s.delay_percent)
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

enum OverrideSlot {
    Abort,
    Delay,
}

/// Result of materializing one plugin config against an RTDS generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultOverlayMaterialization {
    /// No matching valid key changed either configured fault side.
    Unchanged,
    /// At least one configured percentage was replaced, or one fault side was
    /// disabled while another remains.
    Changed,
    /// Every object-valued fault side was disabled by an explicit RTDS zero;
    /// omitted and null sides are absent.
    Disabled,
}

/// Apply scoped RTDS percentages directly to a candidate plugin config.
///
/// This runs only on the mesh configuration cold path. The resulting config is
/// then validated, built into the candidate plugin cache, and published in the
/// same `RequestEpoch`. Missing or malformed keys leave the static percentage
/// untouched. A valid zero removes that fault side for this generation; the
/// caller disables the plugin when no object-valued side remains. Omitted and
/// null sides both represent an absent fault kind, matching plugin validation.
pub fn materialize_config(
    config: &mut Value,
    overlay: &MeshRuntimeOverlay,
) -> FaultOverlayMaterialization {
    let Some(config_object) = config.as_object_mut() else {
        return FaultOverlayMaterialization::Unchanged;
    };
    let Some(scope) = config_object
        .get("runtime_overlay_scope")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|scope| !scope.is_empty())
        .map(str::to_string)
    else {
        return FaultOverlayMaterialization::Unchanged;
    };
    let overrides = FaultOverrides::from_overlay(overlay);
    let mut changed = false;

    for (side, percentage) in [
        ("abort", overrides.abort_percent(&scope)),
        ("delay", overrides.delay_percent(&scope)),
    ] {
        let Some(percentage) = percentage else {
            continue;
        };
        if !config_object.get(side).is_some_and(Value::is_object) {
            continue;
        }
        if percentage == 0.0 {
            config_object.remove(side);
            changed = true;
            continue;
        }
        let Some(fault) = config_object.get_mut(side).and_then(Value::as_object_mut) else {
            continue;
        };
        let Some(number) = serde_json::Number::from_f64(percentage) else {
            continue;
        };
        let next = Value::Number(number);
        let numerically_unchanged = fault
            .get("percentage")
            .and_then(Value::as_f64)
            .is_some_and(|current| current.total_cmp(&percentage).is_eq());
        if !numerically_unchanged {
            fault.insert("percentage".to_string(), next);
            changed = true;
        }
    }

    let has_fault_side = ["abort", "delay"]
        .into_iter()
        .any(|side| config_object.get(side).is_some_and(Value::is_object));
    if changed && !has_fault_side {
        FaultOverlayMaterialization::Disabled
    } else if changed {
        FaultOverlayMaterialization::Changed
    } else {
        FaultOverlayMaterialization::Unchanged
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modes::mesh::config::{
        FractionalPercentDenominator, RuntimeFractionalPercent, RuntimeValue,
    };

    fn overlay(entries: &[(&str, RuntimeValue)]) -> MeshRuntimeOverlay {
        let mut fields = HashMap::new();
        for (key, value) in entries {
            fields.insert((*key).to_string(), value.clone());
        }
        MeshRuntimeOverlay { fields }
    }

    #[test]
    fn snapshots_are_generation_local() {
        let populated = FaultOverrides::from_overlay(&overlay(&[(
            "ferrum.fault_injection.cart.abort_percent",
            RuntimeValue::Number(50.0),
        )]));
        let empty = FaultOverrides::from_overlay(&MeshRuntimeOverlay::default());
        assert_eq!(populated.abort_percent("cart"), Some(50.0));
        assert_eq!(empty.abort_percent("cart"), None);
        assert_eq!(populated.abort_percent("cart"), Some(50.0));
    }

    #[test]
    fn parses_numeric_abort_and_delay() {
        let snap = FaultOverrides::from_overlay(&overlay(&[
            (
                "ferrum.fault_injection.checkout.abort_percent",
                RuntimeValue::Number(12.5),
            ),
            (
                "ferrum.fault_injection.checkout.delay_percent",
                RuntimeValue::Number(75.0),
            ),
        ]));
        assert_eq!(snap.abort_percent("checkout"), Some(12.5));
        assert_eq!(snap.delay_percent("checkout"), Some(75.0));
    }

    #[test]
    fn parses_fractional_percent() {
        let snap = FaultOverrides::from_overlay(&overlay(&[(
            "ferrum.fault_injection.reviews.abort_percent",
            RuntimeValue::FractionalPercent(RuntimeFractionalPercent {
                numerator: 2_500,
                denominator: FractionalPercentDenominator::TenThousand,
            }),
        )]));
        assert!((snap.abort_percent("reviews").unwrap() - 25.0).abs() < 1e-9);
    }

    #[test]
    fn rejects_non_numeric_values() {
        let snap = FaultOverrides::from_overlay(&overlay(&[
            (
                "ferrum.fault_injection.bad.abort_percent",
                RuntimeValue::Bool(true),
            ),
            (
                "ferrum.fault_injection.bad.delay_percent",
                RuntimeValue::String("nope".into()),
            ),
        ]));
        assert_eq!(snap.abort_percent("bad"), None);
        assert_eq!(snap.delay_percent("bad"), None);
    }

    #[test]
    fn rejects_out_of_range_numbers() {
        let snap = FaultOverrides::from_overlay(&overlay(&[
            (
                "ferrum.fault_injection.high.abort_percent",
                RuntimeValue::Number(150.0),
            ),
            (
                "ferrum.fault_injection.low.delay_percent",
                RuntimeValue::Number(-1.0),
            ),
        ]));
        assert_eq!(snap.abort_percent("high"), None);
        assert_eq!(snap.delay_percent("low"), None);
    }

    #[test]
    fn ignores_keys_with_empty_scope() {
        let snap = FaultOverrides::from_overlay(&overlay(&[(
            "ferrum.fault_injection..abort_percent",
            RuntimeValue::Number(50.0),
        )]));
        assert!(snap.is_empty());
    }

    #[test]
    fn ignores_unrelated_keys() {
        let snap = FaultOverrides::from_overlay(&overlay(&[
            ("envoy.reloadable_features.foo", RuntimeValue::Number(50.0)),
            (
                "ferrum.fault_injection.cart.unknown_suffix",
                RuntimeValue::Number(50.0),
            ),
        ]));
        assert!(snap.is_empty());
    }

    #[test]
    fn materializes_matching_values_and_trims_scope() {
        let mut config = serde_json::json!({
            "abort": {"status_code": 503, "percentage": 10.0},
            "delay": {"duration_ms": 5, "percentage": 20.0},
            "runtime_overlay_scope": "  checkout  "
        });
        let result = materialize_config(
            &mut config,
            &overlay(&[
                (
                    "ferrum.fault_injection.checkout.abort_percent",
                    RuntimeValue::Number(75.0),
                ),
                (
                    "ferrum.fault_injection.checkout.delay_percent",
                    RuntimeValue::Number(25.0),
                ),
            ]),
        );

        assert_eq!(result, FaultOverlayMaterialization::Changed);
        assert_eq!(config["abort"]["percentage"], serde_json::json!(75.0));
        assert_eq!(config["delay"]["percentage"], serde_json::json!(25.0));
    }

    #[test]
    fn explicit_zero_removes_only_the_matching_fault_side() {
        let mut config = serde_json::json!({
            "abort": {"status_code": 503, "percentage": 10.0},
            "delay": {"duration_ms": 5, "percentage": 20.0},
            "runtime_overlay_scope": "checkout"
        });
        let result = materialize_config(
            &mut config,
            &overlay(&[(
                "ferrum.fault_injection.checkout.abort_percent",
                RuntimeValue::Number(0.0),
            )]),
        );

        assert_eq!(result, FaultOverlayMaterialization::Changed);
        assert!(config.get("abort").is_none());
        assert_eq!(config["delay"]["percentage"], serde_json::json!(20.0));
    }

    #[test]
    fn materializes_positive_sub_bucket_rtds_value() {
        let percentage = f64::from_bits(1);
        let mut config = serde_json::json!({
            "abort": {"status_code": 503, "percentage": 10.0},
            "runtime_overlay_scope": "checkout"
        });
        let result = materialize_config(
            &mut config,
            &overlay(&[(
                "ferrum.fault_injection.checkout.abort_percent",
                RuntimeValue::Number(percentage),
            )]),
        );

        assert_eq!(result, FaultOverlayMaterialization::Changed);
        assert_eq!(config["abort"]["percentage"], serde_json::json!(percentage));
    }

    #[test]
    fn integer_static_percentage_equal_to_float_overlay_is_unchanged() {
        let mut config = serde_json::json!({
            "abort": {"status_code": 503, "percentage": 50},
            "runtime_overlay_scope": "checkout"
        });
        let original = config.clone();
        let result = materialize_config(
            &mut config,
            &overlay(&[(
                "ferrum.fault_injection.checkout.abort_percent",
                RuntimeValue::Number(50.0),
            )]),
        );

        assert_eq!(result, FaultOverlayMaterialization::Unchanged);
        assert_eq!(config, original);
        assert_eq!(config["abort"]["percentage"], serde_json::json!(50));
    }

    #[test]
    fn explicit_zero_for_the_only_side_disables_the_generation() {
        let mut config = serde_json::json!({
            "delay": {"duration_ms": 5, "percentage": 20.0},
            "runtime_overlay_scope": "checkout"
        });
        let result = materialize_config(
            &mut config,
            &overlay(&[(
                "ferrum.fault_injection.checkout.delay_percent",
                RuntimeValue::Number(0.0),
            )]),
        );

        assert_eq!(result, FaultOverlayMaterialization::Disabled);
        assert!(config.get("delay").is_none());
    }

    #[test]
    fn missing_or_malformed_values_preserve_static_config() {
        let static_config = serde_json::json!({
            "abort": {"status_code": 503, "percentage": 10.0},
            "runtime_overlay_scope": "checkout"
        });
        for candidate_overlay in [
            MeshRuntimeOverlay::default(),
            overlay(&[(
                "ferrum.fault_injection.checkout.abort_percent",
                RuntimeValue::String("invalid".to_string()),
            )]),
        ] {
            let mut config = static_config.clone();
            assert_eq!(
                materialize_config(&mut config, &candidate_overlay),
                FaultOverlayMaterialization::Unchanged
            );
            assert_eq!(config, static_config);
        }
    }

    #[test]
    fn invalid_config_without_fault_sides_is_not_silently_disabled() {
        let mut config = serde_json::json!({"runtime_overlay_scope": "checkout"});
        assert_eq!(
            materialize_config(&mut config, &MeshRuntimeOverlay::default()),
            FaultOverlayMaterialization::Unchanged
        );
    }
}
