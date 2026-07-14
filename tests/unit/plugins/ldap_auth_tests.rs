//! Tests for ldap_auth plugin — config validation and credential extraction.
//!
//! Note: These tests validate plugin construction (config validation) and
//! credential parsing from the Authorization header. Actual LDAP server
//! interaction is not tested here since it requires a real LDAP server;
//! those scenarios are covered by integration/functional tests.

use ferrum_edge::consumer_index::ConsumerIndex;
use ferrum_edge::plugins::{
    HTTP_FAMILY_PROTOCOLS, Plugin, PluginHttpClient, RequestContext,
    ldap_auth::{LDAP_AUTH_MAX_CACHE_TTL_SECONDS, LdapAuth},
    priority,
};
use serde_json::json;

use super::plugin_utils::{assert_continue, assert_reject};

fn http_client() -> PluginHttpClient {
    PluginHttpClient::default()
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

// ─── Config validation tests ─────────────────────────────────────────────

#[test]
fn test_missing_ldap_url_rejected() {
    let result = LdapAuth::new(&json!({}), http_client());
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("ldap_url"));
}

#[test]
fn test_empty_ldap_url_rejected() {
    let result = LdapAuth::new(&json!({ "ldap_url": "" }), http_client());
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("ldap_url"));
}

#[test]
fn test_invalid_config_types_rejected() {
    let invalid_configs = [
        json!(null),
        json!(""),
        json!({
            "ldap_url": 123,
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com"
        }),
        json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": 123
        }),
        json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "starttls": "yes"
        }),
        json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "required_groups": "admins"
        }),
        json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "connect_timeout_seconds": 0
        }),
        json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "max_cache_entries": 0
        }),
    ];

    for config in invalid_configs {
        assert!(
            LdapAuth::new(&config, http_client()).is_err(),
            "config should be rejected: {config}"
        );
    }
}

#[test]
fn test_invalid_ldap_url_scheme_rejected() {
    let result = LdapAuth::new(
        &json!({
            "ldap_url": "http://ldap.example.com",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com"
        }),
        http_client(),
    );
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("ldap://"));
}

#[test]
fn test_malformed_ldap_url_rejected() {
    let result = LdapAuth::new(
        &json!({
            "ldap_url": "ldap://[not-ipv6",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com"
        }),
        http_client(),
    );
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("valid URL"));
}

#[test]
fn test_ldap_url_empty_authority_rejected() {
    let result = LdapAuth::new(
        &json!({
            "ldap_url": "ldap:///dc=example,dc=com",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com"
        }),
        http_client(),
    );
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("hostname"));
}

#[test]
fn test_no_bind_mode_rejected() {
    let result = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://ldap.example.com:636"
        }),
        http_client(),
    );
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("bind_dn_template"));
}

#[test]
fn test_direct_bind_valid() {
    let result = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com"
        }),
        http_client(),
    );
    assert!(result.is_ok());
}

#[test]
fn test_ldaps_url_valid() {
    let result = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com"
        }),
        http_client(),
    );
    assert!(result.is_ok());
}

#[test]
fn test_bind_dn_template_missing_placeholder_rejected() {
    let result = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid=admin,ou=users,dc=example,dc=com"
        }),
        http_client(),
    );
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("{username}"));
}

#[test]
fn test_search_then_bind_valid() {
    let result = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "search_base_dn": "ou=users,dc=example,dc=com",
            "search_filter": "(&(objectClass=person)(uid={username}))",
            "canonical_identity_attribute": "uid",
            "service_account_dn": "cn=admin,dc=example,dc=com",
            "service_account_password": "admin_password"
        }),
        http_client(),
    );
    assert!(result.is_ok());
}

#[test]
fn test_search_bind_without_service_account_rejected() {
    let result = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "search_base_dn": "ou=users,dc=example,dc=com",
            "search_filter": "(&(objectClass=person)(uid={username}))"
        }),
        http_client(),
    );
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("service_account_dn"));
}

#[test]
fn test_search_filter_missing_placeholder_rejected() {
    let result = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "search_base_dn": "ou=users,dc=example,dc=com",
            "search_filter": "(&(objectClass=person)(uid=admin))",
            "service_account_dn": "cn=admin,dc=example,dc=com",
            "service_account_password": "admin_password"
        }),
        http_client(),
    );
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("{username}"));
}

#[test]
fn test_starttls_with_ldaps_rejected() {
    let result = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "starttls": true
        }),
        http_client(),
    );
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("starttls"));
}

#[test]
fn test_starttls_with_ldap_valid() {
    let result = LdapAuth::new(
        &json!({
            "ldap_url": "ldap://ldap.example.com:389",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "starttls": true
        }),
        http_client(),
    );
    assert!(result.is_ok());
}

#[test]
fn test_required_groups_without_group_base_dn_rejected() {
    let result = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "required_groups": ["admins"]
        }),
        http_client(),
    );
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("group_base_dn"));
}

#[test]
fn test_required_groups_with_group_base_dn_valid() {
    let result = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "required_groups": ["admins", "developers"],
            "group_base_dn": "ou=groups,dc=example,dc=com"
        }),
        http_client(),
    );
    assert!(result.is_ok());
}

#[test]
fn test_required_groups_direct_bind_without_service_account_accepted() {
    // Finding #33: direct-bind + required_groups with no service account is a
    // footgun (the group search falls back to an ANONYMOUS bind, which many
    // directories restrict). The plugin emits a startup warning but does NOT
    // reject the config — anonymous group search is legitimate on directories
    // that permit it, so failing construction would break valid deployments.
    let result = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "required_groups": ["admins"],
            "group_base_dn": "ou=groups,dc=example,dc=com"
        }),
        http_client(),
    );
    assert!(
        result.is_ok(),
        "direct-bind + required_groups without a service account must remain a \
         valid (warned) config, not a hard error"
    );
}

#[test]
fn test_required_groups_with_service_account_accepted() {
    // The recommended configuration: a service account is supplied for the
    // group-membership search, so no anonymous bind is used.
    let result = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "required_groups": ["admins"],
            "group_base_dn": "ou=groups,dc=example,dc=com",
            "service_account_dn": "cn=admin,dc=example,dc=com",
            "service_account_password": "admin_password"
        }),
        http_client(),
    );
    assert!(result.is_ok());
}

#[test]
fn test_custom_group_attribute() {
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "required_groups": ["admins"],
            "group_base_dn": "ou=groups,dc=example,dc=com",
            "group_attribute": "sAMAccountName"
        }),
        http_client(),
    );
    assert!(plugin.is_ok());
}

#[test]
fn test_cache_ttl_config() {
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "cache_ttl_seconds": 300
        }),
        http_client(),
    );
    assert!(plugin.is_ok());
}

#[test]
fn test_consumer_mapping_disabled() {
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "consumer_mapping": false
        }),
        http_client(),
    );
    assert!(plugin.is_ok());
}

#[test]
fn test_unknown_config_key_rejected() {
    let error = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "required_group": ["admins"]
        }),
        http_client(),
    )
    .err()
    .expect("misspelled authorization key must fail closed");

    assert!(
        error.contains("unknown config key 'required_group'"),
        "{error}"
    );
}

#[test]
fn test_static_custom_group_filter_rejected() {
    let error = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "group_base_dn": "ou=groups,dc=example,dc=com",
            "group_filter": "(cn=admins)",
            "required_groups": ["admins"]
        }),
        http_client(),
    )
    .err()
    .expect("static group filter must not authorize every bound user");

    assert!(
        error.contains("{user_dn}") && error.contains("{username}"),
        "{error}"
    );
}

#[test]
fn test_user_specific_custom_group_filters_accepted() {
    for group_filter in [
        "(&(objectClass=group)(member={user_dn}))",
        "(&(objectClass=posixGroup)(memberUid={username}))",
    ] {
        let result = LdapAuth::new(
            &json!({
                "ldap_url": "ldaps://ldap.example.com:636",
                "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
                "group_base_dn": "ou=groups,dc=example,dc=com",
                "group_filter": group_filter,
                "required_groups": ["admins"]
            }),
            http_client(),
        );
        assert!(
            result.is_ok(),
            "user-specific filter should be valid: {:?}",
            result.err()
        );
    }
}

#[test]
fn test_search_bind_requires_canonical_identity_attribute() {
    let error = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "search_base_dn": "ou=users,dc=example,dc=com",
            "search_filter": "(uid={username})",
            "service_account_dn": "cn=admin,dc=example,dc=com",
            "service_account_password": "admin-password"
        }),
        http_client(),
    )
    .err()
    .expect("search bind without a canonical identity must fail closed");

    assert!(error.contains("canonical_identity_attribute"), "{error}");
}

#[test]
fn test_cache_ttl_maximum_boundary() {
    let at_max = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "cache_ttl_seconds": LDAP_AUTH_MAX_CACHE_TTL_SECONDS
        }),
        http_client(),
    );
    assert!(
        at_max.is_ok(),
        "documented maximum should be accepted: {:?}",
        at_max.err()
    );

    let above_max = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "cache_ttl_seconds": LDAP_AUTH_MAX_CACHE_TTL_SECONDS + 1
        }),
        http_client(),
    )
    .err()
    .expect("TTL above maximum must be rejected");
    assert!(above_max.contains("cache_ttl_seconds"), "{above_max}");

    let hostile = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "cache_ttl_seconds": u64::MAX
        }),
        http_client(),
    )
    .err()
    .expect("unrepresentable cache expiry must be rejected at construction");
    assert!(hostile.contains("cache_ttl_seconds"), "{hostile}");
}

#[test]
fn test_ldap_resource_boundaries_rejected() {
    for (field, value) in [
        ("connect_timeout_seconds", json!(301)),
        ("request_timeout_seconds", json!(0)),
        ("request_timeout_seconds", json!(301)),
        ("max_concurrent_requests", json!(0)),
        ("max_concurrent_requests", json!(1025)),
    ] {
        let mut config = json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com"
        });
        config[field] = value;
        let error = LdapAuth::new(&config, http_client())
            .err()
            .expect("out-of-range resource bound must be rejected");
        assert!(error.contains(field), "{field}: {error}");
    }
}

#[test]
fn test_remote_plaintext_ldap_requires_explicit_opt_in() {
    let config = json!({
        "ldap_url": "ldap://directory.example.test:389",
        "bind_dn_template": "uid={username},ou=users,dc=example,dc=test"
    });
    let error = LdapAuth::new(&config, http_client())
        .err()
        .expect("remote plaintext LDAP must be rejected by default");
    assert!(
        error.contains("STARTTLS") && error.contains("allow_plaintext"),
        "{error}"
    );

    let mut opted_in = config;
    opted_in["allow_plaintext"] = json!(true);
    assert!(LdapAuth::new(&opted_in, http_client()).is_ok());
}

#[test]
fn test_loopback_plaintext_ldap_remains_available_for_local_testing() {
    for ldap_url in [
        "ldap://127.0.0.1:389",
        "ldap://[::1]:389",
        "ldap://localhost:389",
    ] {
        let result = LdapAuth::new(
            &json!({
                "ldap_url": ldap_url,
                "bind_dn_template": "uid={username},ou=users,dc=example,dc=com"
            }),
            http_client(),
        );
        assert!(
            result.is_ok(),
            "loopback URL should be accepted: {ldap_url}"
        );
    }
}

#[test]
fn test_embedded_ldap_url_credentials_rejected() {
    let error = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://admin:secret@ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com"
        }),
        http_client(),
    )
    .err()
    .expect("embedded URL credentials must be rejected");
    assert!(error.contains("embedded credentials"), "{error}");
    assert!(
        !error.contains("secret@"),
        "secret leaked in error: {error}"
    );
}

#[test]
fn test_malformed_service_account_password_errors_are_redacted() {
    for malformed in [
        json!({"value": "never-log-object-secret"}),
        json!(["never-log-array-secret"]),
        json!(123456789),
        json!(null),
    ] {
        let error = LdapAuth::new(
            &json!({
                "ldap_url": "ldaps://ldap.example.com:636",
                "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
                "service_account_password": malformed
            }),
            http_client(),
        )
        .err()
        .expect("non-string service account password must be rejected");

        assert!(error.contains("service_account_password"), "{error}");
        assert!(
            !error.contains("never-log"),
            "secret leaked in error: {error}"
        );
        assert!(
            !error.contains("123456789"),
            "secret-like value leaked in error: {error}"
        );
    }
}

// ─── Plugin trait tests ──────────────────────────────────────────────────

#[test]
fn test_plugin_name() {
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com"
        }),
        http_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "ldap_auth");
}

#[test]
fn test_is_auth_plugin() {
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com"
        }),
        http_client(),
    )
    .unwrap();
    assert!(plugin.is_auth_plugin());
}

#[test]
fn test_priority() {
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com"
        }),
        http_client(),
    )
    .unwrap();
    assert_eq!(plugin.priority(), priority::LDAP_AUTH);
    assert_eq!(plugin.priority(), 1250);
}

#[test]
fn test_ldap_auth_plugin_contract() {
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com"
        }),
        http_client(),
    )
    .unwrap();

    assert_eq!(plugin.supported_protocols(), HTTP_FAMILY_PROTOCOLS);
    assert!(plugin.is_auth_plugin());
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
fn test_warmup_hostnames_ldap() {
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": "ldap://ldap.example.com:389",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "allow_plaintext": true
        }),
        http_client(),
    )
    .unwrap();
    assert_eq!(plugin.warmup_hostnames(), vec!["ldap.example.com"]);
}

#[test]
fn test_warmup_hostnames_ldaps() {
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://secure-ldap.corp.internal:636",
            "bind_dn_template": "uid={username},ou=users,dc=corp,dc=internal"
        }),
        http_client(),
    )
    .unwrap();
    assert_eq!(plugin.warmup_hostnames(), vec!["secure-ldap.corp.internal"]);
}

#[test]
fn test_warmup_hostnames_unbrackets_ipv6_ldap_url() {
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://[2001:db8::50]:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com"
        }),
        http_client(),
    )
    .unwrap();

    assert_eq!(plugin.warmup_hostnames(), vec!["2001:db8::50"]);
}

// ─── Authenticate credential extraction tests ────────────────────────────
// These test the credential parsing path without requiring an LDAP server.
// The LDAP connection will fail, but we can verify header parsing rejects.

#[tokio::test]
async fn test_missing_authorization_header() {
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com"
        }),
        http_client(),
    )
    .unwrap();

    let mut ctx = make_ctx();
    let consumer_index = ConsumerIndex::new(&[]);

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_none());
    assert!(ctx.authenticated_identity.is_none());
    assert!(ctx.authenticated_identity_header.is_none());
}

#[tokio::test]
async fn test_non_basic_auth_scheme_rejected() {
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com"
        }),
        http_client(),
    )
    .unwrap();

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), "Bearer some-token".to_string());
    let consumer_index = ConsumerIndex::new(&[]);

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_invalid_base64_rejected() {
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com"
        }),
        http_client(),
    )
    .unwrap();

    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        "Basic !!!invalid!!!".to_string(),
    );
    let consumer_index = ConsumerIndex::new(&[]);

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_missing_colon_in_credentials_rejected() {
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com"
        }),
        http_client(),
    )
    .unwrap();

    let mut ctx = make_ctx();
    // Encode "nocolon" without a colon separator
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode("nocolon");
    ctx.headers
        .insert("authorization".to_string(), format!("Basic {}", encoded));
    let consumer_index = ConsumerIndex::new(&[]);

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_empty_username_rejected() {
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com"
        }),
        http_client(),
    )
    .unwrap();

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), basic_header("", "password"));
    let consumer_index = ConsumerIndex::new(&[]);

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_empty_password_rejected_without_contacting_ldap() {
    // RFC 4513 §5.1.2: simple bind with empty password is treated as an
    // unauthenticated bind by many directories (notably Active Directory),
    // and would silently succeed for any username. The plugin must reject
    // empty passwords up front, before they reach the server.
    //
    // Point at a guaranteed-closed loopback port rather than a public DNS
    // name — sandboxed CI runners may have no DNS, and a slow resolver
    // could make this test flaky even when the short-circuit works. A
    // closed loopback port gives immediate connection refusal if the
    // plugin ever regressed and actually attempted a bind.
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": "ldap://127.0.0.1:1",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com"
        }),
        http_client(),
    )
    .unwrap();

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), basic_header("alice", ""));
    let consumer_index = ConsumerIndex::new(&[]);

    // The test should complete quickly (no LDAP roundtrip).
    let start = std::time::Instant::now();
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
    assert!(
        start.elapsed() < std::time::Duration::from_millis(500),
        "Empty-password rejection must short-circuit before contacting LDAP"
    );
}

/// Minimal mock LDAP server: accepts one TCP connection, reads the client's
/// first request (the simple bind), and replies with a `bindResponse` carrying
/// the provided `resultCode`. ldap3 assigns message ID 1 to the first operation
/// on a fresh connection, so the response is encoded at message ID 1.
///
/// LDAPMessage ::= SEQUENCE { messageID INTEGER (1), BindResponse }
/// BindResponse ::= [APPLICATION 1] SEQUENCE { resultCode ENUMERATED,
///                                             matchedDN "", diagnosticMessage "" }
async fn spawn_bind_response_ldap_server(result_code: u8) -> (u16, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock LDAP server");
    let port = listener.local_addr().expect("mock LDAP local addr").port();

    let task = tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            // Drain the bind request so ldap3 doesn't see a half-open peer.
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await;

            // bindResponse, messageID 1, caller-provided resultCode.
            let response: [u8; 14] = [
                0x30,
                0x0c, // LDAPMessage SEQUENCE, len 12
                0x02,
                0x01,
                0x01, // messageID INTEGER 1
                0x61,
                0x07, // [APPLICATION 1] BindResponse, len 7
                0x0a,
                0x01,
                result_code, // resultCode ENUMERATED
                0x04,
                0x00, // matchedDN ""
                0x04,
                0x00, // diagnosticMessage ""
            ];
            let _ = stream.write_all(&response).await;
            let _ = stream.flush().await;
            // Hold the connection briefly so the client reads the response
            // before the socket is torn down.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
    });

    (port, task)
}

fn ber_tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(contents.len() + 4);
    encoded.push(tag);
    if contents.len() < 128 {
        encoded.push(contents.len() as u8);
    } else if contents.len() <= u8::MAX as usize {
        encoded.extend_from_slice(&[0x81, contents.len() as u8]);
    } else {
        encoded.push(0x82);
        encoded.extend_from_slice(&(contents.len() as u16).to_be_bytes());
    }
    encoded.extend_from_slice(contents);
    encoded
}

fn ldap_message(message_id: u8, protocol_op: &[u8]) -> Vec<u8> {
    let mut contents = ber_tlv(0x02, &[message_id]);
    contents.extend_from_slice(protocol_op);
    ber_tlv(0x30, &contents)
}

fn bind_response(message_id: u8, result_code: u8) -> Vec<u8> {
    ldap_message(
        message_id,
        &ber_tlv(0x61, &[0x0a, 0x01, result_code, 0x04, 0x00, 0x04, 0x00]),
    )
}

fn search_result_entry(message_id: u8, dn: &str, attributes: &[(&str, &[&str])]) -> Vec<u8> {
    let mut attribute_list = Vec::new();
    for (name, values) in attributes {
        let mut partial_attribute = ber_tlv(0x04, name.as_bytes());
        let mut encoded_values = Vec::new();
        for value in *values {
            encoded_values.extend_from_slice(&ber_tlv(0x04, value.as_bytes()));
        }
        partial_attribute.extend_from_slice(&ber_tlv(0x31, &encoded_values));
        attribute_list.extend_from_slice(&ber_tlv(0x30, &partial_attribute));
    }

    let mut entry = ber_tlv(0x04, dn.as_bytes());
    entry.extend_from_slice(&ber_tlv(0x30, &attribute_list));
    ldap_message(message_id, &ber_tlv(0x64, &entry))
}

fn search_result_done(message_id: u8, result_code: u8) -> Vec<u8> {
    ldap_message(
        message_id,
        &ber_tlv(0x65, &[0x0a, 0x01, result_code, 0x04, 0x00, 0x04, 0x00]),
    )
}

async fn read_ldap_message(stream: &mut tokio::net::TcpStream) {
    use tokio::io::AsyncReadExt;

    let mut header = [0u8; 2];
    stream
        .read_exact(&mut header)
        .await
        .expect("read LDAP message header");
    assert_eq!(header[0], 0x30, "LDAP message must be a BER sequence");
    let body_len = if header[1] & 0x80 == 0 {
        usize::from(header[1])
    } else {
        let length_octets = usize::from(header[1] & 0x7f);
        let mut encoded_len = vec![0u8; length_octets];
        stream
            .read_exact(&mut encoded_len)
            .await
            .expect("read LDAP long-form length");
        encoded_len
            .into_iter()
            .fold(0usize, |length, octet| (length << 8) | usize::from(octet))
    };
    let mut body = vec![0u8; body_len];
    stream
        .read_exact(&mut body)
        .await
        .expect("read LDAP message body");
}

async fn spawn_search_bind_server(
    entries: Vec<(String, String, String)>,
    accept_user_bind: bool,
) -> (u16, tokio::task::JoinHandle<()>) {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind search-bind LDAP server");
    let port = listener
        .local_addr()
        .expect("search-bind LDAP local addr")
        .port();
    let task = tokio::spawn(async move {
        let (mut service_stream, _) = listener.accept().await.expect("accept service bind");
        read_ldap_message(&mut service_stream).await;
        service_stream
            .write_all(&bind_response(1, 0))
            .await
            .expect("write service bind success");

        read_ldap_message(&mut service_stream).await;
        for (dn, attribute_name, attribute_value) in entries {
            service_stream
                .write_all(&search_result_entry(
                    2,
                    &dn,
                    &[(attribute_name.as_str(), &[attribute_value.as_str()])],
                ))
                .await
                .expect("write user search entry");
        }
        service_stream
            .write_all(&search_result_done(2, 0))
            .await
            .expect("write user search done");
        drop(service_stream);

        if accept_user_bind {
            let (mut user_stream, _) = listener.accept().await.expect("accept user bind");
            read_ldap_message(&mut user_stream).await;
            user_stream
                .write_all(&bind_response(1, 0))
                .await
                .expect("write user bind success");
        }
    });
    (port, task)
}

#[tokio::test]
async fn test_search_bind_uses_canonical_entry_identity() {
    let (port, task) = spawn_search_bind_server(
        vec![(
            "uid=canonical-alice,ou=users,dc=example,dc=com".to_string(),
            "UID".to_string(),
            "canonical-alice".to_string(),
        )],
        true,
    )
    .await;
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": format!("ldap://127.0.0.1:{port}"),
            "search_base_dn": "ou=users,dc=example,dc=com",
            "search_filter": "(uid={username})",
            "canonical_identity_attribute": "uid",
            "service_account_dn": "cn=admin,dc=example,dc=com",
            "service_account_password": "service-secret",
            "consumer_mapping": false
        }),
        http_client(),
    )
    .expect("valid search-bind config");
    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        basic_header("presented-alias", "user-secret"),
    );

    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_continue(result);
    assert_eq!(
        ctx.authenticated_identity.as_deref(),
        Some("canonical-alice")
    );
    assert_eq!(
        ctx.authenticated_identity_header.as_deref(),
        Some("canonical-alice")
    );
    task.abort();
}

#[tokio::test]
async fn test_search_bind_rejects_ambiguous_results() {
    let (port, task) = spawn_search_bind_server(
        vec![
            (
                "uid=victim,ou=users,dc=example,dc=com".to_string(),
                "uid".to_string(),
                "victim".to_string(),
            ),
            (
                "uid=attacker,ou=users,dc=example,dc=com".to_string(),
                "uid".to_string(),
                "attacker".to_string(),
            ),
        ],
        false,
    )
    .await;
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": format!("ldap://127.0.0.1:{port}"),
            "search_base_dn": "ou=users,dc=example,dc=com",
            "search_filter": "(uid={username})",
            "canonical_identity_attribute": "uid",
            "service_account_dn": "cn=admin,dc=example,dc=com",
            "service_account_password": "service-secret"
        }),
        http_client(),
    )
    .expect("valid search-bind config");
    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        basic_header("victim", "attacker-secret"),
    );

    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_reject(result, Some(401));
    assert!(ctx.authenticated_identity.is_none());
    task.abort();
}

#[tokio::test]
async fn test_group_attribute_lookup_is_case_insensitive() {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind group LDAP server");
    let port = listener.local_addr().expect("group LDAP local addr").port();
    let task = tokio::spawn(async move {
        let (mut user_stream, _) = listener.accept().await.expect("accept direct bind");
        read_ldap_message(&mut user_stream).await;
        user_stream
            .write_all(&bind_response(1, 0))
            .await
            .expect("write direct bind success");
        drop(user_stream);

        let (mut group_stream, _) = listener.accept().await.expect("accept group search");
        read_ldap_message(&mut group_stream).await;
        group_stream
            .write_all(&search_result_entry(
                1,
                "CN=unrelated-cn,OU=Groups,DC=example,DC=com",
                &[("samaccountname", &["gateway-admins"])],
            ))
            .await
            .expect("write group search entry");
        group_stream
            .write_all(&search_result_done(1, 0))
            .await
            .expect("write group search done");
    });

    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": format!("ldap://127.0.0.1:{port}"),
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "group_base_dn": "ou=groups,dc=example,dc=com",
            "group_filter": "(member={user_dn})",
            "group_attribute": "sAMAccountName",
            "required_groups": ["gateway-admins"]
        }),
        http_client(),
    )
    .expect("valid direct-bind group config");
    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        basic_header("alice", "user-secret"),
    );

    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_continue(result);
    task.abort();
}

#[tokio::test]
async fn test_complete_flow_wall_clock_timeout() {
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind stalling LDAP server");
    let port = listener.local_addr().expect("stall LDAP local addr").port();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept stalled bind");
        read_ldap_message(&mut stream).await;
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    });
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": format!("ldap://127.0.0.1:{port}"),
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "connect_timeout_seconds": 5,
            "request_timeout_seconds": 1
        }),
        http_client(),
    )
    .expect("valid bounded LDAP config");
    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        basic_header("alice", "user-secret"),
    );
    let started = std::time::Instant::now();
    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_reject(result, Some(500));
    assert!(
        started.elapsed() < std::time::Duration::from_secs(3),
        "overall authentication deadline was not enforced"
    );
    task.abort();
}

#[tokio::test]
async fn test_operation_timeout_is_reapplied_after_service_bind() {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind post-bind stall server");
    let port = listener.local_addr().expect("stall LDAP local addr").port();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept service bind");
        read_ldap_message(&mut stream).await;
        stream
            .write_all(&bind_response(1, 0))
            .await
            .expect("write service bind success");
        read_ldap_message(&mut stream).await;
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    });
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": format!("ldap://127.0.0.1:{port}"),
            "search_base_dn": "ou=users,dc=example,dc=com",
            "search_filter": "(uid={username})",
            "canonical_identity_attribute": "uid",
            "service_account_dn": "cn=admin,dc=example,dc=com",
            "service_account_password": "service-secret",
            "connect_timeout_seconds": 1,
            "request_timeout_seconds": 5
        }),
        http_client(),
    )
    .expect("valid bounded search-bind config");
    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        basic_header("alice", "user-secret"),
    );
    let started = std::time::Instant::now();
    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_reject(result, Some(500));
    assert!(
        started.elapsed() < std::time::Duration::from_secs(3),
        "search should use a fresh per-operation timeout after service bind"
    );
    task.abort();
}

#[tokio::test]
async fn test_concurrency_limit_rejects_excess_without_new_connection() {
    use std::sync::Arc;
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind concurrency LDAP server");
    let port = listener.local_addr().expect("concurrency LDAP addr").port();
    let (accepted_tx, accepted_rx) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept first bind");
        read_ldap_message(&mut stream).await;
        let _ = accepted_tx.send(());
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    });
    let plugin = Arc::new(
        LdapAuth::new(
            &json!({
                "ldap_url": format!("ldap://127.0.0.1:{port}"),
                "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
                "connect_timeout_seconds": 5,
                "request_timeout_seconds": 5,
                "max_concurrent_requests": 1
            }),
            http_client(),
        )
        .expect("valid concurrency-bounded LDAP config"),
    );
    let consumer_index = Arc::new(ConsumerIndex::new(&[]));
    let first_plugin = Arc::clone(&plugin);
    let first_consumers = Arc::clone(&consumer_index);
    let first = tokio::spawn(async move {
        let mut ctx = make_ctx();
        ctx.headers.insert(
            "authorization".to_string(),
            basic_header("first", "user-secret"),
        );
        first_plugin.authenticate(&mut ctx, &first_consumers).await
    });
    accepted_rx
        .await
        .expect("first request reached LDAP server");

    let mut second_ctx = make_ctx();
    second_ctx.headers.insert(
        "authorization".to_string(),
        basic_header("second", "user-secret"),
    );
    let started = std::time::Instant::now();
    let second = plugin.authenticate(&mut second_ctx, &consumer_index).await;
    assert_reject(second, Some(500));
    assert!(
        started.elapsed() < std::time::Duration::from_millis(500),
        "excess LDAP work should be rejected immediately"
    );

    first.abort();
    server.abort();
}

async fn spawn_invalid_credentials_ldap_server() -> (u16, tokio::task::JoinHandle<()>) {
    spawn_bind_response_ldap_server(49).await
}

#[tokio::test]
async fn test_ldap_invalid_credentials_returns_401() {
    // Finding #32: a directory that accepts the connection but REJECTS the bind
    // (resultCode 49, invalidCredentials) is the genuine wrong-password case and
    // must map to 401 — not the 500 reserved for backend/config failures.
    let (port, task) = spawn_invalid_credentials_ldap_server().await;

    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": format!("ldap://127.0.0.1:{port}"),
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "connect_timeout_seconds": 5
        }),
        http_client(),
    )
    .unwrap();

    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        basic_header("alice", "wrong-password"),
    );
    let consumer_index = ConsumerIndex::new(&[]);

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));

    task.abort();
}

#[tokio::test]
async fn test_ldap_busy_bind_result_returns_500() {
    // A directory can report operational failures as LDAP result codes after
    // accepting the TCP connection. Only rc=49 is a credential failure; rc=51
    // (`busy`) must surface as backend trouble.
    let (port, task) = spawn_bind_response_ldap_server(51).await;

    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": format!("ldap://127.0.0.1:{port}"),
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "connect_timeout_seconds": 5
        }),
        http_client(),
    )
    .unwrap();

    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        basic_header("alice", "password"),
    );
    let consumer_index = ConsumerIndex::new(&[]);

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(500));

    task.abort();
}

#[tokio::test]
async fn test_ldap_connection_failure_returns_500() {
    // Finding #32: an unreachable LDAP server is a backend/infrastructure
    // failure, not a credential failure. It must surface as a 500 so the client
    // is not falsely told its credentials are wrong (which would prompt useless
    // credential re-submission and mask the outage). Point at a closed loopback
    // port so the connection is refused immediately.
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": "ldap://127.0.0.1:19",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "connect_timeout_seconds": 1
        }),
        http_client(),
    )
    .unwrap();

    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        basic_header("testuser", "password"),
    );
    let consumer_index = ConsumerIndex::new(&[]);

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(500));
}

#[tokio::test]
async fn test_ldap_connection_failure_search_bind_returns_500() {
    // Finding #32: the same backend-vs-credential distinction must hold in
    // search-then-bind mode. An unreachable directory (refused connection on a
    // closed loopback port) is a 500, not a 401 — the service-account bind never
    // even runs, so this is unambiguously infrastructure, not bad credentials.
    let plugin = LdapAuth::new(
        &json!({
            "ldap_url": "ldap://127.0.0.1:19",
            "search_base_dn": "ou=users,dc=example,dc=com",
            "search_filter": "(&(objectClass=person)(uid={username}))",
            "canonical_identity_attribute": "uid",
            "service_account_dn": "cn=admin,dc=example,dc=com",
            "service_account_password": "admin_password",
            "connect_timeout_seconds": 1
        }),
        http_client(),
    )
    .unwrap();

    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        basic_header("testuser", "password"),
    );
    let consumer_index = ConsumerIndex::new(&[]);

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(500));
}

// ─── AD config combination tests ─────────────────────────────────────────

#[test]
fn test_full_ad_config() {
    let result = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://dc.contoso.com:636",
            "search_base_dn": "OU=Users,DC=contoso,DC=com",
            "search_filter": "(&(objectClass=user)(sAMAccountName={username}))",
            "canonical_identity_attribute": "sAMAccountName",
            "service_account_dn": "CN=svc-proxy,OU=ServiceAccounts,DC=contoso,DC=com",
            "service_account_password": "S3cret!",
            "group_base_dn": "OU=Groups,DC=contoso,DC=com",
            "group_filter": "(&(objectClass=group)(member={user_dn}))",
            "required_groups": ["Domain Admins", "Proxy Users"],
            "group_attribute": "cn",
            "cache_ttl_seconds": 300,
            "connect_timeout_seconds": 3,
            "consumer_mapping": true
        }),
        http_client(),
    );
    assert!(result.is_ok());
}

#[test]
fn test_both_bind_modes_accepted() {
    // Config is valid when both bind_dn_template and search config are provided.
    // At runtime, direct bind takes precedence (see authenticate_user logic).
    let result = LdapAuth::new(
        &json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "search_base_dn": "ou=users,dc=example,dc=com",
            "search_filter": "(&(objectClass=person)(uid={username}))",
            "service_account_dn": "cn=admin,dc=example,dc=com",
            "service_account_password": "admin_password"
        }),
        http_client(),
    );
    assert!(result.is_ok());
}

// ─── Cache bounding config tests ─────────────────────────────────────────

#[test]
fn test_ldap_auth_max_cache_entries_default() {
    // Create a valid config without max_cache_entries — default is 10000
    let config = json!({
        "ldap_url": "ldaps://ldap.example.com:636",
        "bind_dn_template": "uid={username},ou=users,dc=example,dc=com"
    });
    let plugin = LdapAuth::new(&config, http_client()).unwrap();
    assert_eq!(plugin.name(), "ldap_auth");
}

#[test]
fn test_ldap_auth_max_cache_entries_custom() {
    let config = json!({
        "ldap_url": "ldaps://ldap.example.com:636",
        "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
        "max_cache_entries": 500
    });
    let plugin = LdapAuth::new(&config, http_client()).unwrap();
    assert_eq!(plugin.name(), "ldap_auth");
}

// ─── Security plugin registration test ───────────────────────────────────

#[test]
fn test_ldap_auth_is_security_plugin() {
    assert_eq!(
        ferrum_edge::plugins::plugin_failure_policy("ldap_auth"),
        Some(ferrum_edge::plugins::PluginFailurePolicy::FailClosed)
    );
}

#[test]
fn test_ldap_auth_in_available_plugins() {
    let plugins = ferrum_edge::plugins::available_plugins();
    assert!(plugins.contains(&"ldap_auth"));
}

// ─── LDAP escaping tests ─────────────────────────────────────────────────

use ferrum_edge::plugins::ldap_auth::{escape_dn_value, escape_filter_value};

// ── DN escaping (RFC 4514) ──────────────────────────────────────────

#[test]
fn test_dn_escape_plain_username() {
    assert_eq!(escape_dn_value("alice"), "alice");
}

#[test]
fn test_dn_escape_special_chars() {
    assert_eq!(escape_dn_value("a,b+c\"d"), "a\\,b\\+c\\\"d");
}

#[test]
fn test_dn_escape_backslash_angle_semi() {
    assert_eq!(escape_dn_value("a\\b<c>d;e"), "a\\\\b\\<c\\>d\\;e");
}

#[test]
fn test_dn_escape_leading_space() {
    assert_eq!(escape_dn_value(" alice"), "\\ alice");
}

#[test]
fn test_dn_escape_trailing_space() {
    assert_eq!(escape_dn_value("alice "), "alice\\ ");
}

#[test]
fn test_dn_escape_trailing_space_after_multibyte() {
    // `é` is 2 UTF-8 bytes — the old enumerate()-vs-input.len() comparison
    // would never flag the trailing space as the last character for any
    // input containing multi-byte UTF-8.
    assert_eq!(escape_dn_value("héllo "), "héllo\\ ");
}

#[test]
fn test_dn_escape_leading_space_with_multibyte() {
    assert_eq!(escape_dn_value(" héllo"), "\\ héllo");
}

#[test]
fn test_dn_escape_no_change_for_unicode_without_trailing_space() {
    assert_eq!(escape_dn_value("héllo"), "héllo");
}

#[test]
fn test_dn_escape_leading_hash() {
    assert_eq!(escape_dn_value("#alice"), "\\#alice");
}

// ── Filter escaping (RFC 4515) ──────────────────────────────────────

#[test]
fn test_filter_escape_plain_username() {
    assert_eq!(escape_filter_value("alice"), "alice");
}

#[test]
fn test_filter_escape_special_chars() {
    assert_eq!(escape_filter_value("a*b(c)d\\e"), "a\\2ab\\28c\\29d\\5ce");
}

#[test]
fn test_filter_escape_nul() {
    assert_eq!(escape_filter_value("a\0b"), "a\\00b");
}

#[test]
fn test_filter_escape_injection_attempt() {
    // Attacker tries: username = "admin)(objectClass=*"
    let escaped = escape_filter_value("admin)(objectClass=*");
    assert_eq!(escaped, "admin\\29\\28objectClass=\\2a");
}

#[test]
fn test_filter_escape_preserves_utf8() {
    // A non-ASCII filter value (e.g. an accented username/group) must keep its
    // real UTF-8 bytes — only the five RFC 4515 metacharacters are escaped.
    // Iterating bytes and doing `byte as char` re-encodes each UTF-8 byte as a
    // separate code point, corrupting the value so the directory search never
    // matches the entry (a non-ASCII user in search-then-bind / group lookup is
    // wrongly denied). `escape_dn_value` already handles this correctly; the
    // filter path must match.
    assert_eq!(escape_filter_value("café"), "café");
    assert_eq!(escape_filter_value("café").into_bytes(), "café".as_bytes());
    // Multi-byte characters and the metacharacter escaping must coexist.
    assert_eq!(escape_filter_value("café*"), "café\\2a");
    assert_eq!(escape_filter_value("naïve(user)"), "naïve\\28user\\29");
}
