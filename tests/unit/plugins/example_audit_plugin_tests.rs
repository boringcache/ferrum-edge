//! Tests for the `example_audit_plugin` custom-plugin template.
//!
//! Finding #83: the template's `new()` must honor the `custom_plugins/mod.rs`
//! contract — return `Err` for a config key that is present but has the wrong
//! type or an invalid value, while still defaulting absent/null keys.

use ferrum_edge::custom_plugins::example_audit_plugin::ExampleAuditPlugin;
use serde_json::json;

#[test]
fn test_new_uses_defaults_for_absent_or_null_keys() {
    // Empty config → both fields default, no error.
    assert!(ExampleAuditPlugin::new(&json!({})).is_ok());
    // Explicit nulls also fall back to defaults.
    assert!(
        ExampleAuditPlugin::new(&json!({
            "log_request_headers": null,
            "retention_days": null,
        }))
        .is_ok()
    );
}

#[test]
fn test_new_accepts_valid_values() {
    assert!(
        ExampleAuditPlugin::new(&json!({
            "log_request_headers": true,
            "retention_days": 30,
        }))
        .is_ok()
    );
}

// `ExampleAuditPlugin` does not derive `Debug`, so `Result::expect_err`/
// `unwrap_err` are unavailable; extract the error via `.err()` instead.
fn new_err(config: serde_json::Value) -> String {
    ExampleAuditPlugin::new(&config)
        .err()
        .expect("config should be rejected")
}

#[test]
fn test_new_rejects_wrong_typed_log_request_headers() {
    // A non-bool value must be rejected, not silently coerced to false.
    let err = new_err(json!({ "log_request_headers": "true" }));
    assert!(err.contains("log_request_headers"), "got: {err}");
}

#[test]
fn test_new_rejects_wrong_typed_retention_days() {
    // A non-integer value must be rejected, not silently mapped to the default.
    let err = new_err(json!({ "retention_days": "ninety" }));
    assert!(err.contains("retention_days"), "got: {err}");

    // A negative number is not a u64 → rejected.
    assert!(ExampleAuditPlugin::new(&json!({ "retention_days": -5 })).is_err());
}

#[test]
fn test_new_rejects_zero_retention_days() {
    let err = new_err(json!({ "retention_days": 0 }));
    assert!(err.contains("retention_days"), "got: {err}");
}
