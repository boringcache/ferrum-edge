//! Tests for basic_auth plugin

use ferrum_edge::ConsumerIndex;
use ferrum_edge::plugins::{
    HTTP_FAMILY_PROTOCOLS, Plugin, PluginResult, RequestContext, basic_auth::BasicAuth, priority,
    utils::auth_flow::VerifyOutcome,
};
use hmac::{KeyInit, Mac};
use serde_json::json;

use super::plugin_utils::assert_continue;

/// A fixed test secret used for all basic_auth tests.
/// Tests set `FERRUM_BASIC_AUTH_HMAC_SECRET` to this value before constructing
/// the plugin.
const TEST_HMAC_SECRET: &str = "test-hmac-secret-for-basic-auth-unit-tests";
const BASIC_CHALLENGE: &str = r#"Basic realm="ferrum-edge", charset="UTF-8""#;

fn assert_basic_reject(result: PluginResult) {
    match result {
        PluginResult::Reject {
            status_code,
            headers,
            ..
        } => {
            assert_eq!(status_code, 401);
            assert_eq!(
                headers.get("WWW-Authenticate").map(String::as_str),
                Some(BASIC_CHALLENGE)
            );
        }
        other => panic!("expected Basic-auth rejection, got {other:?}"),
    }
}

/// Set the test HMAC secret in the environment. Required before constructing
/// `BasicAuth` because the plugin rejects missing secrets.
///
/// SAFETY: `std::env::set_var` is unsafe in Rust 2024 because it races with
/// concurrent reads. Our `#[tokio::test]` tests are single-threaded by default,
/// so there is no concurrent reader.
fn set_test_hmac_secret() {
    unsafe {
        std::env::set_var("FERRUM_BASIC_AUTH_HMAC_SECRET", TEST_HMAC_SECRET);
    }
}

fn make_ctx() -> RequestContext {
    RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/test".to_string(),
    )
}

fn basic_header(user: &str, pass: &str) -> String {
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", user, pass));
    format!("Basic {}", encoded)
}

/// Create a consumer with a known HMAC-SHA256 password hash.
fn create_basic_auth_consumer() -> ferrum_edge::config::types::Consumer {
    use chrono::Utc;
    use serde_json::Value;
    use std::collections::HashMap;

    let hash = hmac_sha256_password_hash("password");

    let mut credentials = HashMap::new();
    credentials.insert(
        "basicauth".to_string(),
        Value::Array(vec![json!({"password_hash": hash})]),
    );

    ferrum_edge::config::types::Consumer {
        id: "basic-consumer".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: "testuser".to_string(),
        custom_id: None,
        credentials,
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn create_basic_auth_consumer_with_hash(
    username: &str,
    password_hash: String,
) -> ferrum_edge::config::types::Consumer {
    use chrono::Utc;
    use serde_json::Value;
    use std::collections::HashMap;

    let mut credentials = HashMap::new();
    credentials.insert(
        "basicauth".to_string(),
        Value::Array(vec![json!({"password_hash": password_hash})]),
    );

    ferrum_edge::config::types::Consumer {
        id: format!("{username}-consumer"),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: username.to_string(),
        custom_id: None,
        credentials,
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn hmac_sha256_password_hash(password: &str) -> String {
    type HmacSha256 = hmac::Hmac<sha2::Sha256>;

    let mut mac = HmacSha256::new_from_slice(TEST_HMAC_SECRET.as_bytes()).unwrap();
    mac.update(password.as_bytes());
    format!("hmac_sha256:{}", hex::encode(mac.finalize().into_bytes()))
}

#[tokio::test]
async fn test_basic_auth_plugin_creation() {
    set_test_hmac_secret();
    let plugin = BasicAuth::new(&json!({})).unwrap();
    assert_eq!(plugin.name(), "basic_auth");
}

#[test]
fn test_basic_auth_enabled_construction_requires_a_strong_hmac_secret() {
    let construct = ferrum_edge::_test_support::basic_auth_construction_with_secret_for_test;
    assert!(construct(&json!({}), None).is_err());
    assert!(construct(&json!({}), Some("weak")).is_err());
    assert!(construct(&json!({}), Some(TEST_HMAC_SECRET)).is_ok());
}

#[test]
fn test_basic_auth_plugin_contract() {
    set_test_hmac_secret();
    let plugin = BasicAuth::new(&json!({})).unwrap();

    assert_eq!(plugin.priority(), priority::BASIC_AUTH);
    assert_eq!(plugin.priority(), 1300);
    assert_eq!(plugin.supported_protocols(), HTTP_FAMILY_PROTOCOLS);
    assert!(plugin.is_auth_plugin());
    assert_eq!(plugin.authentication_challenge(), Some(BASIC_CHALLENGE));
    assert!(!plugin.modifies_request_headers());
    assert!(!plugin.modifies_request_body());
    assert!(!plugin.requires_request_body_before_before_proxy());
    assert!(!plugin.requires_request_body_before_authenticate());
    assert!(!plugin.needs_request_body_bytes());
    assert!(!plugin.requires_request_body_buffering());
    assert!(!plugin.requires_response_body_buffering());
    assert!(!plugin.applies_after_proxy_on_reject());
}

#[test]
fn test_basic_auth_rejects_invalid_config() {
    set_test_hmac_secret();
    let invalid_configs = [
        json!(""),
        json!(true),
        json!({"unexpected": true}),
        json!({"realm": "private"}),
    ];

    for config in invalid_configs {
        assert!(
            BasicAuth::new(&config).is_err(),
            "config should be rejected: {config}"
        );
    }

    assert!(BasicAuth::new(&json!(null)).is_ok());
}

#[tokio::test]
async fn test_basic_auth_successful() {
    set_test_hmac_secret();
    let plugin = BasicAuth::new(&json!({})).unwrap();
    let consumer = create_basic_auth_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        basic_header("testuser", "password"),
    );
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
    assert_eq!(ctx.identified_consumer.unwrap().username, "testuser");
}

#[tokio::test]
async fn test_basic_auth_wrong_password() {
    set_test_hmac_secret();
    let plugin = BasicAuth::new(&json!({})).unwrap();
    let consumer = create_basic_auth_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        basic_header("testuser", "wrongpassword"),
    );
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_basic_reject(result);
}

#[tokio::test]
async fn test_basic_auth_wrong_username() {
    set_test_hmac_secret();
    let plugin = BasicAuth::new(&json!({})).unwrap();
    let consumer = create_basic_auth_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        basic_header("unknownuser", "password"),
    );
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_basic_reject(result);
}

#[tokio::test]
async fn test_basic_auth_missing_header() {
    set_test_hmac_secret();
    let plugin = BasicAuth::new(&json!({})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_basic_auth_consumer()]);

    let mut ctx = make_ctx();
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_none());
}

#[tokio::test]
async fn test_basic_auth_invalid_scheme() {
    set_test_hmac_secret();
    let plugin = BasicAuth::new(&json!({})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_basic_auth_consumer()]);

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), "Bearer some-token".to_string());

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_none());
}

#[tokio::test]
async fn test_basic_auth_invalid_base64() {
    set_test_hmac_secret();
    let plugin = BasicAuth::new(&json!({})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_basic_auth_consumer()]);

    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        "Basic !!!not-valid-base64!!!".to_string(),
    );

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_basic_reject(result);
}

#[tokio::test]
async fn test_basic_auth_invalid_utf8_uses_basic_challenge() {
    use base64::Engine;

    set_test_hmac_secret();
    let plugin = BasicAuth::new(&json!({})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_basic_auth_consumer()]);
    let encoded = base64::engine::general_purpose::STANDARD.encode([0xff, 0xfe]);
    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Basic {encoded}"));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_basic_reject(result);
}

#[tokio::test]
async fn test_basic_auth_missing_colon_separator() {
    set_test_hmac_secret();
    let plugin = BasicAuth::new(&json!({})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_basic_auth_consumer()]);

    let mut ctx = make_ctx();
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode("nocolonhere");
    ctx.headers
        .insert("authorization".to_string(), format!("Basic {}", encoded));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_basic_reject(result);
}

#[tokio::test]
async fn test_basic_auth_case_insensitive_scheme() {
    set_test_hmac_secret();
    let plugin = BasicAuth::new(&json!({})).unwrap();
    let consumer = create_basic_auth_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let mut ctx = make_ctx();
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode("testuser:password");
    ctx.headers
        .insert("authorization".to_string(), format!("basic {}", encoded));
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
}

#[tokio::test]
async fn test_basic_auth_uppercase_scheme() {
    set_test_hmac_secret();
    let plugin = BasicAuth::new(&json!({})).unwrap();
    let consumer = create_basic_auth_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let mut ctx = make_ctx();
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode("testuser:password");
    ctx.headers
        .insert("authorization".to_string(), format!("BASIC {}", encoded));
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
}

#[tokio::test]
async fn test_basic_auth_empty_consumers() {
    set_test_hmac_secret();
    let plugin = BasicAuth::new(&json!({})).unwrap();
    let consumer_index = ConsumerIndex::new(&[]);

    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        basic_header("testuser", "password"),
    );

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_basic_reject(result);
}

#[tokio::test]
async fn test_basic_auth_password_with_colon() {
    set_test_hmac_secret();
    let plugin = BasicAuth::new(&json!({})).unwrap();
    let consumer = create_basic_auth_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let mut ctx = make_ctx();
    use base64::Engine;
    let encoded =
        base64::engine::general_purpose::STANDARD.encode("testuser:pass:word:with:colons");
    ctx.headers
        .insert("authorization".to_string(), format!("Basic {}", encoded));
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_basic_reject(result);
}

#[tokio::test]
async fn test_basic_auth_rejects_non_hmac_hash() {
    set_test_hmac_secret();
    let plugin = BasicAuth::new(&json!({})).unwrap();

    use chrono::Utc;
    use serde_json::Value;

    let mut credentials = std::collections::HashMap::new();
    credentials.insert(
        "basicauth".to_string(),
        Value::Array(vec![json!({"password_hash": "$2b$04$abcdefghijklmnopqrstuu6NIIqkG2DLUQF6wqv0nO5Rvqf3PI0Q2"})]),
    );

    let consumer = ferrum_edge::config::types::Consumer {
        id: "non-hmac-consumer".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: "nonhmacuser".to_string(),
        custom_id: None,
        credentials,
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        basic_header("nonhmacuser", "mypassword"),
    );
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_basic_reject(result);
}

#[tokio::test]
async fn test_basic_auth_hmac_sha256_password_hash() {
    set_test_hmac_secret();
    let plugin = BasicAuth::new(&json!({})).unwrap();
    let consumer = create_basic_auth_consumer_with_hash(
        "hmacuser",
        hmac_sha256_password_hash("correct-password"),
    );
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        basic_header("hmacuser", "correct-password"),
    );
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert_eq!(ctx.identified_consumer.unwrap().username, "hmacuser");

    let mut wrong_ctx = make_ctx();
    wrong_ctx.headers.insert(
        "authorization".to_string(),
        basic_header("hmacuser", "wrong-password"),
    );

    let result = plugin.authenticate(&mut wrong_ctx, &consumer_index).await;
    assert_basic_reject(result);
}

#[tokio::test]
async fn test_basic_auth_malformed_hmac_hash_is_rejected() {
    set_test_hmac_secret();
    let plugin = BasicAuth::new(&json!({})).unwrap();
    let consumer =
        create_basic_auth_consumer_with_hash("hmacuser", "hmac_sha256:not-hex".to_string());
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        basic_header("hmacuser", "correct-password"),
    );

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_basic_reject(result);
}

// ---- Multi-credential rotation tests ----

fn create_basic_auth_consumer_with_two_passwords() -> ferrum_edge::config::types::Consumer {
    use chrono::Utc;
    use serde_json::Value;
    use std::collections::HashMap;

    let hash_old = hmac_sha256_password_hash("old-password");
    let hash_new = hmac_sha256_password_hash("new-password");

    let mut credentials = HashMap::new();
    credentials.insert(
        "basicauth".to_string(),
        Value::Array(vec![
            json!({"password_hash": hash_old}),
            json!({"password_hash": hash_new}),
        ]),
    );

    ferrum_edge::config::types::Consumer {
        id: "basic-consumer".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: "testuser".to_string(),
        custom_id: None,
        credentials,
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

#[tokio::test]
async fn test_basic_auth_multi_password_old_password_works() {
    set_test_hmac_secret();
    let plugin = BasicAuth::new(&json!({})).unwrap();
    let consumer = create_basic_auth_consumer_with_two_passwords();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        basic_header("testuser", "old-password"),
    );
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert_eq!(ctx.identified_consumer.unwrap().username, "testuser");
}

#[tokio::test]
async fn test_basic_auth_multi_password_new_password_works() {
    set_test_hmac_secret();
    let plugin = BasicAuth::new(&json!({})).unwrap();
    let consumer = create_basic_auth_consumer_with_two_passwords();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        basic_header("testuser", "new-password"),
    );
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert_eq!(ctx.identified_consumer.unwrap().username, "testuser");
}

#[tokio::test]
async fn test_basic_auth_multi_password_wrong_password_rejected() {
    set_test_hmac_secret();
    let plugin = BasicAuth::new(&json!({})).unwrap();
    let consumer = create_basic_auth_consumer_with_two_passwords();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        basic_header("testuser", "wrong-password"),
    );
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_basic_reject(result);
}

fn timing_consumer_with_hashes(hashes: Vec<String>) -> ferrum_edge::config::types::Consumer {
    use chrono::Utc;
    use serde_json::Value;
    use std::collections::HashMap;

    ferrum_edge::config::types::Consumer {
        id: "basic-timing".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: "alice".to_string(),
        custom_id: None,
        credentials: HashMap::from([(
            "basicauth".to_string(),
            Value::Array(
                hashes
                    .into_iter()
                    .map(|password_hash| json!({"password_hash": password_hash}))
                    .collect(),
            ),
        )]),
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn timing_password_hash(password: &str) -> String {
    type HmacSha256 = hmac::Hmac<sha2::Sha256>;

    let mut mac = HmacSha256::new_from_slice(&[b'x'; 32]).unwrap();
    mac.update(password.as_bytes());
    format!("hmac_sha256:{}", hex::encode(mac.finalize().into_bytes()))
}

#[test]
fn test_verification_rounds_do_not_reveal_username_or_rotation_state() {
    let dummy_password_hash = format!("hmac_sha256:{}", "0".repeat(64));

    for (index, consumers) in [
        Vec::new(),
        vec![timing_consumer_with_hashes(vec![timing_password_hash(
            "one",
        )])],
        vec![timing_consumer_with_hashes(vec![
            timing_password_hash("one"),
            timing_password_hash("two"),
        ])],
    ]
    .into_iter()
    .enumerate()
    {
        let username = if index == 0 { "unknown" } else { "alice" };
        let (outcome, verification_count) =
            ferrum_edge::_test_support::basic_auth_verify_with_test_material_for_test(
                dummy_password_hash.clone(),
                2,
                username,
                "wrong",
                &ConsumerIndex::new(&consumers),
            );
        assert!(matches!(outcome, VerifyOutcome::VerificationFailed(_)));
        assert_eq!(verification_count, 2);
    }
}

#[test]
fn test_dummy_verification_round_cannot_authenticate_a_consumer() {
    let consumers = [timing_consumer_with_hashes(vec![timing_password_hash(
        "real-password",
    )])];

    let (outcome, verification_count) =
        ferrum_edge::_test_support::basic_auth_verify_with_test_material_for_test(
            timing_password_hash("dummy-password"),
            2,
            "alice",
            "dummy-password",
            &ConsumerIndex::new(&consumers),
        );

    assert!(matches!(outcome, VerifyOutcome::VerificationFailed(_)));
    assert_eq!(verification_count, 2);
}

#[test]
fn test_verification_rounds_are_bounded_by_serializable_credential_capacity() {
    let bounded = ferrum_edge::_test_support::basic_auth_bounded_verification_rounds_for_test;
    assert_eq!(bounded(0), 1);
    assert_eq!(bounded(2), 2);
    assert_eq!(
        bounded(usize::MAX),
        ferrum_edge::config::types::MAX_CREDENTIALS_SIZE / ("hmac_sha256:".len() + 64)
    );
}
