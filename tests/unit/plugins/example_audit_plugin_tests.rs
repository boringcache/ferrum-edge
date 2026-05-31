//! Tests for the `example_audit_plugin` custom-plugin template.
//!
//! Finding #83: the template's `new()` must honor the `custom_plugins/mod.rs`
//! contract — return `Err` for a config key that is present but has the wrong
//! type or an invalid value, while still defaulting absent/null keys.

use ferrum_edge::custom_plugins::{create_custom_plugin, custom_plugin_names};
use ferrum_edge::plugins::PluginHttpClient;
use serde_json::json;

fn example_audit_plugin_registered() -> bool {
    custom_plugin_names().contains(&"example_audit_plugin")
}

fn create_example_audit_plugin(config: &serde_json::Value) -> Result<bool, String> {
    create_custom_plugin("example_audit_plugin", config, PluginHttpClient::default())
        .map(|plugin| plugin.is_some())
}

#[test]
fn test_new_uses_defaults_for_absent_or_null_keys() {
    if !example_audit_plugin_registered() {
        return;
    }

    // Empty config → both fields default, no error.
    assert_eq!(create_example_audit_plugin(&json!({})), Ok(true));
    // Explicit nulls also fall back to defaults.
    assert_eq!(
        create_example_audit_plugin(&json!({
            "log_request_headers": null,
            "retention_days": null,
        })),
        Ok(true)
    );
}

#[test]
fn test_new_accepts_valid_values() {
    if !example_audit_plugin_registered() {
        return;
    }

    assert_eq!(
        create_example_audit_plugin(&json!({
            "log_request_headers": true,
            "retention_days": 30,
        })),
        Ok(true)
    );
}

fn new_err(config: serde_json::Value) -> String {
    create_example_audit_plugin(&config)
        .err()
        .expect("config should be rejected")
}

#[test]
fn test_new_rejects_wrong_typed_log_request_headers() {
    if !example_audit_plugin_registered() {
        return;
    }

    // A non-bool value must be rejected, not silently coerced to false.
    let err = new_err(json!({ "log_request_headers": "true" }));
    assert!(err.contains("log_request_headers"), "got: {err}");
}

#[test]
fn test_new_rejects_wrong_typed_retention_days() {
    if !example_audit_plugin_registered() {
        return;
    }

    // A non-integer value must be rejected, not silently mapped to the default.
    let err = new_err(json!({ "retention_days": "ninety" }));
    assert!(err.contains("retention_days"), "got: {err}");

    // A negative number is not a u64 → rejected.
    assert!(create_example_audit_plugin(&json!({ "retention_days": -5 })).is_err());
}

#[test]
fn test_new_rejects_zero_retention_days() {
    if !example_audit_plugin_registered() {
        return;
    }

    let err = new_err(json!({ "retention_days": 0 }));
    assert!(err.contains("retention_days"), "got: {err}");
}
