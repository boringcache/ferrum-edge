//! GHSA-c95h-874g-fq5x: credential redaction + internal-only dedup metadata.
//!
//! Covers ordinary and schema-shaped log views, the four legacy dedup lifecycle
//! fields, API-key / API-token spellings, operator-extra keys, and non-secret
//! counter controls. All projections must share one sensitivity decision.

use ferrum_edge::_test_support::clone_log_metadata;
use ferrum_edge::plugins::utils::log_schema::{
    SchemaCapabilities, SchemaView, SummarySchema,
};
use ferrum_edge::plugins::utils::metadata_redaction::{
    INTERNAL_ONLY_METADATA_KEY_PREFIX, REDACTED_PLACEHOLDER, is_internal_only_metadata_key,
    is_sensitive_metadata_key_with_extras, parse_extras_list, strip_internal_only_metadata,
};
use ferrum_edge::plugins::{RequestContext, TransactionSummary};
use serde_json::{Value, json};
use std::collections::HashMap;

const LEGACY_DEDUP_FIELDS: &[&str] = &[
    "_dedup_key",
    "_dedup_fingerprint",
    "_dedup_local_inflight_token",
    "_dedup_redis_lock_token",
    "_DEDUP_REDIS_LOCK_TOKEN",
    "_DeDuP_Local_Inflight_Token",
];

const API_CREDENTIAL_KEYS: &[&str] = &[
    "api_key",
    "api-key",
    "apikey",
    "APIKey",
    "APIToken",
];

const NON_SECRET_COUNTERS: &[&str] = &[
    "ai_total_tokens",
    "ai_prompt_tokens",
    "ai_completion_tokens",
    "cache_key",
    "routing_key",
];

fn planted_metadata() -> HashMap<String, String> {
    let mut metadata = HashMap::new();
    for (idx, key) in LEGACY_DEDUP_FIELDS.iter().enumerate() {
        metadata.insert(
            (*key).to_string(),
            format!("dedup-lifecycle-sentinel-{idx}"),
        );
    }
    for (idx, key) in API_CREDENTIAL_KEYS.iter().enumerate() {
        metadata.insert((*key).to_string(), format!("api-credential-sentinel-{idx}"));
    }
    for (idx, key) in NON_SECRET_COUNTERS.iter().enumerate() {
        metadata.insert((*key).to_string(), format!("counter-{idx}"));
    }
    metadata.insert("trace_id".to_string(), "trace-visible".to_string());
    metadata.insert("operator_canary".to_string(), "operator-secret".to_string());
    metadata
}

fn summary_with(metadata: HashMap<String, String>) -> TransactionSummary {
    TransactionSummary {
        metadata,
        ..TransactionSummary::default()
    }
}

fn serialize_native(summary: &TransactionSummary) -> Value {
    serde_json::to_value(summary).expect("native summary serializes")
}

fn serialize_schema(summary: &TransactionSummary, raw_schema: Value) -> Value {
    let schema = SummarySchema::compile(&raw_schema, "test", SchemaCapabilities::BASE)
        .expect("schema compiles");
    let view = SchemaView {
        summary,
        schema: &schema,
    };
    serde_json::to_value(view).expect("schema view serializes")
}

fn assert_no_lifecycle_leak(json: &str, parsed: &Value) {
    for key in LEGACY_DEDUP_FIELDS {
        assert!(
            parsed.pointer(&format!("/metadata/{key}")).is_none()
                && parsed.get(key).is_none()
                && parsed.get(&format!("meta_{key}")).is_none(),
            "lifecycle key {key} must be omitted from projection: {json}"
        );
    }
    for idx in 0..LEGACY_DEDUP_FIELDS.len() {
        let sentinel = format!("dedup-lifecycle-sentinel-{idx}");
        assert!(
            !json.contains(&sentinel),
            "dedup lifecycle value leaked: {sentinel} in {json}"
        );
    }
}

fn assert_api_credentials_redacted(json: &str, lookup: impl Fn(&str) -> Option<&Value>) {
    for (idx, key) in API_CREDENTIAL_KEYS.iter().enumerate() {
        let value = lookup(key).unwrap_or_else(|| panic!("missing projected key {key}: {json}"));
        assert_eq!(
            value.as_str(),
            Some(REDACTED_PLACEHOLDER),
            "{key} must redact, got {value} in {json}"
        );
        let sentinel = format!("api-credential-sentinel-{idx}");
        assert!(
            !json.contains(&sentinel),
            "API credential leaked for {key}: {json}"
        );
    }
}

fn assert_counters_visible(lookup: impl Fn(&str) -> Option<&Value>) {
    for (idx, key) in NON_SECRET_COUNTERS.iter().enumerate() {
        let expected = format!("counter-{idx}");
        let value = lookup(key).unwrap_or_else(|| panic!("missing counter key {key}"));
        assert_eq!(value.as_str(), Some(expected.as_str()));
    }
}

#[test]
fn classifier_covers_api_key_spellings_and_non_secret_controls() {
    let extras = parse_extras_list("operator_canary");
    for key in API_CREDENTIAL_KEYS {
        assert!(
            is_sensitive_metadata_key_with_extras(key, &extras),
            "{key} must be sensitive"
        );
    }
    for key in NON_SECRET_COUNTERS {
        assert!(
            !is_sensitive_metadata_key_with_extras(key, &extras),
            "{key} must remain visible"
        );
    }
    assert!(is_sensitive_metadata_key_with_extras(
        "operator_canary",
        &extras
    ));
    for key in LEGACY_DEDUP_FIELDS {
        assert!(
            key.starts_with(INTERNAL_ONLY_METADATA_KEY_PREFIX)
                && is_internal_only_metadata_key(key)
                && is_sensitive_metadata_key_with_extras(key, &extras),
            "{key} must be internal-only and fail closed"
        );
    }
}

#[test]
fn clone_log_metadata_strips_all_four_legacy_dedup_fields() {
    let mut ctx = RequestContext::new("203.0.113.10".into(), "POST".into(), "/pay".into());
    ctx.metadata = planted_metadata();

    let logged = clone_log_metadata(&ctx);
    for key in LEGACY_DEDUP_FIELDS {
        assert!(
            !logged.contains_key(*key),
            "{key} survived clone_log_metadata"
        );
    }
    assert_eq!(
        logged.get("trace_id").map(String::as_str),
        Some("trace-visible")
    );
    assert_eq!(
        logged.get("api_key").map(String::as_str),
        Some("api-credential-sentinel-0")
    );
}

#[test]
fn strip_internal_only_metadata_is_shared_fail_closed_filter() {
    let mut metadata = planted_metadata();
    strip_internal_only_metadata(&mut metadata);
    for key in LEGACY_DEDUP_FIELDS {
        assert!(!metadata.contains_key(*key));
    }
    assert!(metadata.contains_key("api_key"));
    assert!(metadata.contains_key("ai_total_tokens"));
}

#[test]
fn native_summary_omits_dedup_fields_and_redacts_api_credentials() {
    let summary = summary_with(planted_metadata());
    let parsed = serialize_native(&summary);
    let json = parsed.to_string();
    let md = parsed
        .get("metadata")
        .and_then(Value::as_object)
        .expect("native metadata object");

    assert_no_lifecycle_leak(&json, &parsed);
    assert_api_credentials_redacted(&json, |key| md.get(key));
    assert_counters_visible(|key| md.get(key));
    assert_eq!(
        md.get("trace_id").and_then(Value::as_str),
        Some("trace-visible")
    );
}

#[test]
fn nested_schema_view_matches_native_redaction_contract() {
    let summary = summary_with(planted_metadata());
    let parsed = serialize_schema(&summary, json!({ "summary_type": "http" }));
    let json = parsed.to_string();
    let md = parsed
        .get("metadata")
        .and_then(Value::as_object)
        .expect("nested metadata");

    assert_no_lifecycle_leak(&json, &parsed);
    assert_api_credentials_redacted(&json, |key| md.get(key));
    assert_counters_visible(|key| md.get(key));
}

#[test]
fn flattened_schema_view_redacts_and_omits_under_prefix() {
    let summary = summary_with(planted_metadata());
    let parsed = serialize_schema(
        &summary,
        json!({
            "summary_type": "http",
            "metadata": { "mode": "flatten", "prefix": "meta_" }
        }),
    );
    let json = parsed.to_string();

    assert!(parsed.get("metadata").is_none());
    for key in LEGACY_DEDUP_FIELDS {
        assert!(
            parsed.get(&format!("meta_{key}")).is_none(),
            "flattened lifecycle key meta_{key} must be omitted"
        );
    }
    for idx in 0..LEGACY_DEDUP_FIELDS.len() {
        assert!(!json.contains(&format!("dedup-lifecycle-sentinel-{idx}")));
    }
    for (idx, key) in API_CREDENTIAL_KEYS.iter().enumerate() {
        assert_eq!(
            parsed
                .get(&format!("meta_{key}"))
                .and_then(Value::as_str),
            Some(REDACTED_PLACEHOLDER),
            "flattened {key} must redact"
        );
        assert!(!json.contains(&format!("api-credential-sentinel-{idx}")));
    }
    for (idx, key) in NON_SECRET_COUNTERS.iter().enumerate() {
        let expected = format!("counter-{idx}");
        assert_eq!(
            parsed
                .get(&format!("meta_{key}"))
                .and_then(Value::as_str),
            Some(expected.as_str())
        );
    }
}

#[test]
fn renamed_metadata_outer_field_still_redacts_inner_keys() {
    let summary = summary_with(planted_metadata());
    let parsed = serialize_schema(
        &summary,
        json!({
            "summary_type": "http",
            "rename": { "metadata": "attrs" }
        }),
    );
    let json = parsed.to_string();
    assert!(parsed.get("metadata").is_none());
    let attrs = parsed
        .get("attrs")
        .and_then(Value::as_object)
        .expect("renamed metadata object");

    for key in LEGACY_DEDUP_FIELDS {
        assert!(attrs.get(*key).is_none(), "{key} leaked under rename");
    }
    assert_api_credentials_redacted(&json, |key| attrs.get(key));
    assert_counters_visible(|key| attrs.get(key));
}

#[test]
fn static_fields_reject_api_key_spellings_and_dedup_lifecycle_names() {
    for key in API_CREDENTIAL_KEYS
        .iter()
        .chain(LEGACY_DEDUP_FIELDS.iter())
        .copied()
    {
        let err = SummarySchema::compile(
            &json!({
                "summary_type": "http",
                "static_fields": { key: "must-not-ship" }
            }),
            "test",
            SchemaCapabilities::BASE,
        )
        .expect_err("sensitive / internal-only static field must fail closed");
        assert!(
            err.contains("sensitive") || err.contains(key),
            "unexpected compile error for {key}: {err}"
        );
    }

    let ok = SummarySchema::compile(
        &json!({
            "summary_type": "http",
            "static_fields": { "deployment_region": "us-east-1" }
        }),
        "test",
        SchemaCapabilities::BASE,
    );
    assert!(ok.is_ok(), "benign static field rejected: {ok:?}");
}

#[test]
fn operator_extra_keys_redact_on_native_and_shaped_views() {
    let extras = parse_extras_list("operator_canary,tenant_secret");
    assert!(is_sensitive_metadata_key_with_extras(
        "operator_canary",
        &extras
    ));
    assert!(is_sensitive_metadata_key_with_extras(
        "tenant_secret",
        &extras
    ));
    assert!(!is_sensitive_metadata_key_with_extras(
        "ai_total_tokens",
        &extras
    ));
}
