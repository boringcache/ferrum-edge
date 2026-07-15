//! Tests for admin API validation improvements.
//!
//! Tests credential type whitelist, credential redaction coverage,
//! and validation constants.

use serde_json::json;

// --- Credential type whitelist tests ---

#[test]
fn test_allowed_credential_types_contains_expected() {
    let expected = &["basicauth", "keyauth", "jwt", "hmac_auth", "mtls_auth"];
    for cred_type in expected {
        assert!(
            ferrum_edge::admin::ALLOWED_CREDENTIAL_TYPES.contains(cred_type),
            "Expected '{}' to be in ALLOWED_CREDENTIAL_TYPES",
            cred_type
        );
    }
}

#[test]
fn test_disallowed_credential_types_rejected() {
    let disallowed = &[
        "admin_flag",
        "custom",
        "unknown",
        "",
        "BASICAUTH",
        "basic_auth",
    ];
    for cred_type in disallowed {
        assert!(
            !ferrum_edge::admin::ALLOWED_CREDENTIAL_TYPES.contains(cred_type),
            "Expected '{}' to NOT be in ALLOWED_CREDENTIAL_TYPES",
            cred_type
        );
    }
}

#[test]
fn test_credential_types_count() {
    // Ensure we have exactly the 5 known credential types
    assert_eq!(
        ferrum_edge::admin::ALLOWED_CREDENTIAL_TYPES.len(),
        5,
        "Expected exactly 5 allowed credential types"
    );
}

// --- Credential redaction tests ---

fn make_consumer(
    credentials: std::collections::HashMap<String, serde_json::Value>,
) -> ferrum_edge::config::types::Consumer {
    ferrum_edge::config::types::Consumer {
        id: "test-consumer".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: "test-user".to_string(),
        custom_id: None,
        credentials,
        acl_groups: Vec::new(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

#[test]
fn test_redact_basicauth_password_hash_by_omission() {
    let mut credentials = std::collections::HashMap::new();
    credentials.insert(
        "basicauth".to_string(),
        json!({"username": "alice", "password_hash": "$2b$12$realhashabcdef"}),
    );
    let consumer = make_consumer(credentials);

    let redacted = ferrum_edge::admin::redact_consumer_credentials(&consumer);
    assert!(!redacted.credentials.contains_key("basicauth"));
}

#[test]
fn test_redact_basicauth_plaintext_password_by_omission() {
    let mut credentials = std::collections::HashMap::new();
    credentials.insert(
        "basicauth".to_string(),
        json!({"password": "must-not-escape"}),
    );
    let consumer = make_consumer(credentials);

    let redacted = ferrum_edge::admin::redact_consumer_credentials(&consumer);
    assert!(!redacted.credentials.contains_key("basicauth"));
}

#[test]
fn test_basic_credential_user_shape_failure_is_bad_request() {
    let mut credential = json!({
        "password": "x".repeat(ferrum_edge::config::types::MAX_CREDENTIAL_VALUE_LENGTH + 1)
    });

    let status =
        ferrum_edge::_test_support::prepare_basic_auth_credential_for_test(&mut credential)
            .expect_err("oversized Basic password must be rejected");

    assert_eq!(status, hyper::StatusCode::BAD_REQUEST);
    assert!(credential.get("password").is_some());
    assert!(credential.get("password_hash").is_none());
}

#[test]
fn test_basic_credential_server_configuration_failures_are_internal_errors() {
    assert_eq!(
        ferrum_edge::_test_support::basic_auth_server_configuration_status_for_test(None),
        Some(hyper::StatusCode::INTERNAL_SERVER_ERROR)
    );
    assert_eq!(
        ferrum_edge::_test_support::basic_auth_server_configuration_status_for_test(Some("weak")),
        Some(hyper::StatusCode::INTERNAL_SERVER_ERROR)
    );
}

#[test]
fn test_disabled_basic_auth_config_skips_plugin_construction() {
    let now = chrono::Utc::now();
    let mut plugin_config = ferrum_edge::config::types::PluginConfig {
        id: "disabled-basic-auth".to_string(),
        plugin_name: "basic_auth".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        // An unsupported field makes constructor invocation fail regardless of
        // process environment, so this deterministically proves the disabled
        // admin path does not construct the plugin.
        config: json!({"realm": "staged-but-unused"}),
        scope: ferrum_edge::config::types::PluginScope::Global,
        proxy_id: None,
        enabled: false,
        priority_override: None,
        api_spec_id: None,
        created_at: now,
        updated_at: now,
    };

    assert!(
        ferrum_edge::_test_support::validate_admin_plugin_config_for_test(&plugin_config).is_ok()
    );

    plugin_config.enabled = true;
    assert!(
        ferrum_edge::_test_support::validate_admin_plugin_config_for_test(&plugin_config).is_err()
    );
}

#[test]
fn test_basic_auth_audit_redaction_uses_one_shape_independent_marker() {
    let password_hash = format!("hmac_sha256:{}", "a".repeat(64));
    let mut credentials = std::collections::HashMap::new();
    credentials.insert(
        "basicauth".to_string(),
        json!([{
            "password_hash": password_hash.clone(),
            "credential_label": "must-not-escape"
        }]),
    );
    let consumer = make_consumer(credentials);

    let redacted = ferrum_edge::config::types::redact_consumer_credentials_for_audit(&consumer);
    assert_eq!(redacted.credentials["basicauth"], "[REDACTED]");

    let serialized = serde_json::to_string(&redacted).expect("redacted consumer serializes");
    assert!(!serialized.contains("password_hash"));
    assert!(!serialized.contains("credential_label"));
    assert!(!serialized.contains("must-not-escape"));
    assert!(!serialized.contains(&password_hash));
}

#[test]
fn test_redact_hmac_auth_secret() {
    let mut credentials = std::collections::HashMap::new();
    credentials.insert(
        "hmac_auth".to_string(),
        json!({"username": "bob", "secret": "supersecret123"}),
    );
    let consumer = make_consumer(credentials);

    let redacted = ferrum_edge::admin::redact_consumer_credentials(&consumer);
    let hmac = redacted.credentials.get("hmac_auth").unwrap();
    assert_eq!(hmac["secret"], "[REDACTED]");
    assert_eq!(hmac["username"], "bob");
}

#[test]
fn test_redact_jwt_secret() {
    let mut credentials = std::collections::HashMap::new();
    credentials.insert(
        "jwt".to_string(),
        json!({"secret": "my-jwt-secret", "algorithm": "HS256"}),
    );
    let consumer = make_consumer(credentials);

    let redacted = ferrum_edge::admin::redact_consumer_credentials(&consumer);
    let jwt = redacted.credentials.get("jwt").unwrap();
    assert_eq!(jwt["secret"], "[REDACTED]");
    assert_eq!(jwt["algorithm"], "HS256");
}

#[test]
fn test_redact_keyauth_key() {
    let mut credentials = std::collections::HashMap::new();
    credentials.insert("keyauth".to_string(), json!({"key": "api-key-value"}));
    let consumer = make_consumer(credentials);

    let redacted = ferrum_edge::admin::redact_consumer_credentials(&consumer);
    let keyauth = redacted.credentials.get("keyauth").unwrap();
    assert_eq!(keyauth["key"], "[REDACTED]");
}

#[test]
fn test_redact_multiple_credential_types() {
    let mut credentials = std::collections::HashMap::new();
    credentials.insert(
        "basicauth".to_string(),
        json!({"username": "alice", "password_hash": "hash123"}),
    );
    credentials.insert(
        "hmac_auth".to_string(),
        json!({"username": "alice", "secret": "secret123"}),
    );
    credentials.insert("keyauth".to_string(), json!({"key": "api-key-value"}));
    let consumer = make_consumer(credentials);

    let redacted = ferrum_edge::admin::redact_consumer_credentials(&consumer);

    assert!(!redacted.credentials.contains_key("basicauth"));
    assert_eq!(redacted.credentials["hmac_auth"]["secret"], "[REDACTED]");
    assert_eq!(redacted.credentials["keyauth"]["key"], "[REDACTED]");
}

#[test]
fn test_redact_mtls_identity_unchanged() {
    let mut credentials = std::collections::HashMap::new();
    credentials.insert(
        "mtls_auth".to_string(),
        json!({"identity": "CN=client.example.com"}),
    );
    let consumer = make_consumer(credentials);

    let redacted = ferrum_edge::admin::redact_consumer_credentials(&consumer);
    assert_eq!(
        redacted.credentials["mtls_auth"]["identity"],
        "CN=client.example.com"
    );
}

#[test]
fn test_redact_empty_credentials() {
    let consumer = make_consumer(std::collections::HashMap::new());
    let redacted = ferrum_edge::admin::redact_consumer_credentials(&consumer);
    assert!(redacted.credentials.is_empty());
}

// ---- Multi-credential array redaction tests ----

#[test]
fn test_redact_array_jwt_secrets() {
    let mut credentials = std::collections::HashMap::new();
    credentials.insert(
        "jwt".to_string(),
        json!([
            {"secret": "old-secret", "algorithm": "HS256"},
            {"secret": "new-secret", "algorithm": "HS256"}
        ]),
    );
    let consumer = make_consumer(credentials);

    let redacted = ferrum_edge::admin::redact_consumer_credentials(&consumer);
    let jwt = redacted.credentials.get("jwt").unwrap();
    let arr = jwt.as_array().unwrap();
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["secret"], "[REDACTED]");
    assert_eq!(arr[0]["algorithm"], "HS256");
    assert_eq!(arr[1]["secret"], "[REDACTED]");
    assert_eq!(arr[1]["algorithm"], "HS256");
}

#[test]
fn test_redact_array_basicauth_passwords_by_omission() {
    let mut credentials = std::collections::HashMap::new();
    credentials.insert(
        "basicauth".to_string(),
        json!([
            {"password_hash": "hash-old"},
            {"password_hash": "hash-new"}
        ]),
    );
    let consumer = make_consumer(credentials);

    let redacted = ferrum_edge::admin::redact_consumer_credentials(&consumer);
    assert!(!redacted.credentials.contains_key("basicauth"));
}

#[test]
fn test_redact_array_hmac_secrets() {
    let mut credentials = std::collections::HashMap::new();
    credentials.insert(
        "hmac_auth".to_string(),
        json!([
            {"secret": "secret-1"},
            {"secret": "secret-2"}
        ]),
    );
    let consumer = make_consumer(credentials);

    let redacted = ferrum_edge::admin::redact_consumer_credentials(&consumer);
    let hmac = redacted.credentials.get("hmac_auth").unwrap();
    let arr = hmac.as_array().unwrap();
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["secret"], "[REDACTED]");
    assert_eq!(arr[1]["secret"], "[REDACTED]");
}
