//! Tests for hmac_auth plugin

use base64::Engine;
use chrono::Utc;
use ferrum_edge::ConsumerIndex;
use ferrum_edge::config::types::Consumer;
use ferrum_edge::plugins::{
    HTTP_FAMILY_PROTOCOLS, Plugin, PluginResult, RequestContext, hmac_auth::HmacAuth, priority,
};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256, Sha512};
use std::collections::HashMap;
use std::sync::Arc;

use super::plugin_utils::{assert_continue, assert_reject, create_test_proxy};

type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

const TEST_SECRET: &str = "my-hmac-secret-key-at-least-32-bytes";
const TEST_USERNAME: &str = "hmacuser";
const TEST_AUTHORITY: &str = "api.example.com";

fn default_config() -> Value {
    json!({})
}

/// Create a consumer with hmac_auth credentials.
fn create_hmac_consumer() -> Consumer {
    create_hmac_consumer_named("hmac-consumer", TEST_USERNAME, TEST_SECRET)
}

fn create_hmac_consumer_named(id: &str, username: &str, secret: &str) -> Consumer {
    let mut credentials = HashMap::new();
    let mut hmac_creds = Map::new();
    hmac_creds.insert("secret".to_string(), Value::String(secret.to_string()));
    credentials.insert(
        "hmac_auth".to_string(),
        Value::Array(vec![Value::Object(hmac_creds)]),
    );

    Consumer {
        id: id.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: username.to_string(),
        custom_id: None,
        credentials,
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

/// Create a consumer without hmac_auth credentials (only has keyauth).
fn create_consumer_without_hmac_creds() -> Consumer {
    let mut credentials = HashMap::new();
    let mut keyauth_creds = Map::new();
    keyauth_creds.insert("key".to_string(), Value::String("some-key".to_string()));
    credentials.insert(
        "keyauth".to_string(),
        Value::Array(vec![Value::Object(keyauth_creds)]),
    );

    Consumer {
        id: "no-hmac-consumer".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: "nokeyuser".to_string(),
        custom_id: None,
        credentials,
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn make_ctx(method: &str, path: &str) -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        method.to_string(),
        path.to_string(),
    );
    let empty_body = bytes::Bytes::new();
    ctx.headers
        .insert("digest".to_string(), sha256_digest_header(&empty_body));
    ctx.request_body_sha256 = Some(Sha256::digest(&empty_body).into());
    ctx.request_body_sha512 = Some(Sha512::digest(&empty_body).into());
    ctx.request_authority = Some(TEST_AUTHORITY.to_string());
    ctx.matched_proxy = Some(Arc::new(create_test_proxy()));
    ctx
}

/// Like `make_ctx` but also sets the raw query string (as the proxy would on
/// request init), so the query string is bound into the HMAC signing string.
fn make_ctx_with_query(method: &str, path: &str, query: &str) -> RequestContext {
    let mut ctx = make_ctx(method, path);
    ctx.set_raw_query_string(query.to_string());
    ctx
}

fn set_ctx_namespace(ctx: &mut RequestContext, namespace: &str) {
    let mut proxy = create_test_proxy();
    proxy.namespace = namespace.to_string();
    ctx.matched_proxy = Some(Arc::new(proxy));
}

/// Generate a current RFC 2822 date string.
fn current_date() -> String {
    Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

/// Version 1 binds credential identity and authority before the request fields.
/// `make_ctx` produces requests with no
/// query, so the helpers below sign an empty query by default; tests that set
/// a query string use `sign_sha256_with_query`.
fn build_signing_string(input: HmacSigningInput<'_>) -> String {
    format!(
        "ferrum-hmac-v1\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        input.namespace,
        input.username,
        input.authority,
        input.method,
        input.path,
        input.query,
        input.date,
        input.digest_header
    )
}

/// Compute an HMAC-SHA256 signature over an empty-body, no-query request.
fn sign_sha256(secret: &str, method: &str, path: &str, date: &str) -> String {
    sign_sha256_with_digest(secret, method, path, date, &sha256_digest_header(&[]))
}

/// Compute an HMAC-SHA512 signature over an empty-body, no-query request.
fn sign_sha512(secret: &str, method: &str, path: &str, date: &str) -> String {
    let digest_header = sha256_digest_header(&[]);
    let signing_string = build_signing_string(HmacSigningInput {
        namespace: ferrum_edge::config::types::DEFAULT_NAMESPACE,
        username: TEST_USERNAME,
        authority: TEST_AUTHORITY,
        method,
        path,
        query: "",
        date,
        digest_header: &digest_header,
    });
    let mut mac = HmacSha512::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(signing_string.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
}

/// Compute an HMAC-SHA256 signature over version 1 with the default test
/// identity, authority, and an empty query.
fn sign_sha256_with_digest(
    secret: &str,
    method: &str,
    path: &str,
    date: &str,
    digest_header: &str,
) -> String {
    sign_sha256_for_identity(
        secret,
        HmacSigningInput {
            namespace: ferrum_edge::config::types::DEFAULT_NAMESPACE,
            username: TEST_USERNAME,
            authority: TEST_AUTHORITY,
            method,
            path,
            query: "",
            date,
            digest_header,
        },
    )
}

struct HmacSigningInput<'a> {
    namespace: &'a str,
    username: &'a str,
    authority: &'a str,
    method: &'a str,
    path: &'a str,
    query: &'a str,
    date: &'a str,
    digest_header: &'a str,
}

fn sign_sha256_for_identity(secret: &str, input: HmacSigningInput<'_>) -> String {
    let signing_string = build_signing_string(input);
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(signing_string.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
}

/// Compute an HMAC-SHA256 signature binding a specific raw query string.
fn sign_sha256_with_query(
    secret: &str,
    method: &str,
    path: &str,
    query: &str,
    date: &str,
) -> String {
    let digest_header = sha256_digest_header(&[]);
    sign_sha256_for_identity(
        secret,
        HmacSigningInput {
            namespace: ferrum_edge::config::types::DEFAULT_NAMESPACE,
            username: TEST_USERNAME,
            authority: TEST_AUTHORITY,
            method,
            path,
            query,
            date,
            digest_header: &digest_header,
        },
    )
}

/// Build a `Digest:` (RFC 3230) header value of the form `sha-256=<base64>`
/// for the given body bytes.
fn sha256_digest_header(body: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body);
    let b64 = base64::engine::general_purpose::STANDARD.encode(hasher.finalize());
    format!("sha-256={}", b64)
}

/// Build an RFC 9530 `Content-Digest` SHA-256 structured field.
fn sha256_content_digest_header(body: &[u8]) -> String {
    let digest = Sha256::digest(body);
    format!(
        "sha-256=:{}:",
        base64::engine::general_purpose::STANDARD.encode(digest)
    )
}

/// Build a `Digest:` header value of the form `sha-512=<base64>`.
fn sha512_digest_header(body: &[u8]) -> String {
    let mut hasher = Sha512::new();
    hasher.update(body);
    let b64 = base64::engine::general_purpose::STANDARD.encode(hasher.finalize());
    format!("sha-512={}", b64)
}

/// Build the Authorization header value.
fn hmac_auth_header(username: &str, algorithm: Option<&str>, signature: &str) -> String {
    match algorithm {
        Some(alg) => format!(
            r#"hmac username="{}", algorithm="{}", signature="{}""#,
            username, alg, signature
        ),
        None => format!(r#"hmac username="{}", signature="{}""#, username, signature),
    }
}

// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_hmac_auth_plugin_creation() {
    let plugin = HmacAuth::new(&json!({})).unwrap();
    assert_eq!(plugin.name(), "hmac_auth");
    assert!(plugin.is_auth_plugin());
    assert_eq!(plugin.priority(), priority::HMAC_AUTH);
    assert_eq!(plugin.priority(), 1400);
    assert_eq!(plugin.supported_protocols(), HTTP_FAMILY_PROTOCOLS);
    assert!(!plugin.modifies_request_headers());
    assert!(!plugin.modifies_request_body());
    assert!(!plugin.requires_request_body_before_before_proxy());
    assert!(!plugin.requires_response_body_buffering());
    assert!(!plugin.applies_after_proxy_on_reject());
}

#[tokio::test]
async fn test_hmac_auth_custom_clock_skew() {
    let plugin = HmacAuth::new(&json!({"clock_skew_seconds": 600})).unwrap();
    assert_eq!(plugin.name(), "hmac_auth");
}

#[test]
fn test_hmac_auth_rejects_invalid_config() {
    let invalid_configs = [
        json!(null),
        json!(""),
        json!({"clock_skew_seconds": "300"}),
        json!({"clock_skew_seconds": -1}),
        json!({"require_digest": "true"}),
        json!({"require_digest": false}),
    ];

    for config in invalid_configs {
        assert!(
            HmacAuth::new(&config).is_err(),
            "config should be rejected: {config}"
        );
    }
}

#[tokio::test]
async fn test_hmac_auth_default_requires_digest() {
    let plugin = HmacAuth::new(&json!({})).unwrap();
    assert!(plugin.requires_request_body_before_authenticate());
    assert!(plugin.requires_request_body_buffering());
    assert!(!plugin.needs_request_body_bytes());
    assert!(plugin.needs_request_body_digests());
}

#[tokio::test]
async fn test_hmac_auth_always_requires_body() {
    let plugin = HmacAuth::new(&default_config()).unwrap();
    assert!(plugin.requires_request_body_before_authenticate());
    assert!(plugin.requires_request_body_buffering());
    assert!(!plugin.needs_request_body_bytes());
    assert!(plugin.needs_request_body_digests());
    assert!(!plugin.needs_request_body_text());
    assert_eq!(plugin.request_body_buffer_limit(), Some(10 * 1024 * 1024));
}

#[tokio::test]
async fn test_hmac_auth_prebuffer_only_for_hmac_authorization() {
    let plugin = HmacAuth::new(&default_config()).unwrap();

    let mut missing = make_ctx("POST", "/test");
    assert!(!plugin.should_buffer_request_body(&missing));

    missing
        .headers
        .insert("authorization".to_string(), "Bearer token".to_string());
    assert!(!plugin.should_buffer_request_body(&missing));

    missing.headers.insert(
        "authorization".to_string(),
        r#"hmac username="u", signature="s""#.to_string(),
    );
    assert!(plugin.should_buffer_request_body(&missing));
}

// ── 1. Valid HMAC-SHA256 authentication (digest signing) ─────

#[tokio::test]
async fn test_valid_hmac_sha256() {
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer = create_hmac_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let method = "GET";
    let path = "/test";
    let date = current_date();
    let signature = sign_sha256(TEST_SECRET, method, path, &date);

    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("hmacuser", Some("hmac-sha256"), &signature),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
    assert_eq!(
        ctx.identified_consumer.as_ref().unwrap().username,
        "hmacuser"
    );
}

#[tokio::test]
async fn test_auth_params_accept_quoted_commas_escapes_and_mixed_case_names() {
    let username = "ops,\"blue\\team";
    let consumer = create_hmac_consumer_named("quoted-user", username, TEST_SECRET);
    let consumer_index = ConsumerIndex::new(&[consumer]);
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let method = "GET";
    let path = "/quoted";
    let date = current_date();
    let digest = sha256_digest_header(&[]);
    let signature = sign_sha256_for_identity(
        TEST_SECRET,
        HmacSigningInput {
            namespace: ferrum_edge::config::types::DEFAULT_NAMESPACE,
            username,
            authority: TEST_AUTHORITY,
            method,
            path,
            query: "",
            date: &date,
            digest_header: &digest,
        },
    );
    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(
        "authorization".to_string(),
        format!(
            r#"hmac UserName="ops,\"blue\\team", ALGORITHM="hmac-sha256", Signature="{}""#,
            signature
        ),
    );
    ctx.headers.insert("date".to_string(), date);

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert_eq!(ctx.identified_consumer.unwrap().username, username);
}

#[tokio::test]
async fn test_auth_params_reject_unclosed_quotes_and_duplicates() {
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_hmac_consumer()]);
    for authorization in [
        r#"hmac username="hmacuser, algorithm="hmac-sha256", signature="abc""#,
        r#"hmac username="hmacuser", Username="other", signature="abc""#,
        r#"hmac username="hmacuser", signature="abc", Signature="def""#,
    ] {
        let mut ctx = make_ctx("GET", "/test");
        ctx.headers
            .insert("authorization".to_string(), authorization.to_string());
        ctx.headers.insert("date".to_string(), current_date());
        assert_reject(
            plugin.authenticate(&mut ctx, &consumer_index).await,
            Some(401),
        );
    }
}

#[tokio::test]
async fn test_signature_binds_authority_and_username() {
    let shared = "shared-hmac-secret-at-least-32-characters";
    let consumers = [
        create_hmac_consumer_named("alice-id", "alice", shared),
        create_hmac_consumer_named("bob-id", "bob", shared),
    ];
    let consumer_index = ConsumerIndex::new(&consumers);
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let date = current_date();
    let digest = sha256_digest_header(&[]);
    let signature = sign_sha256_for_identity(
        shared,
        HmacSigningInput {
            namespace: ferrum_edge::config::types::DEFAULT_NAMESPACE,
            username: "alice",
            authority: TEST_AUTHORITY,
            method: "GET",
            path: "/bound",
            query: "",
            date: &date,
            digest_header: &digest,
        },
    );

    let mut relabeled = make_ctx("GET", "/bound");
    relabeled.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("bob", Some("hmac-sha256"), &signature),
    );
    relabeled.headers.insert("date".to_string(), date.clone());
    assert_reject(
        plugin.authenticate(&mut relabeled, &consumer_index).await,
        Some(401),
    );

    let mut cross_host = make_ctx("GET", "/bound");
    cross_host.request_authority = Some("other.example.com".to_string());
    cross_host.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("alice", Some("hmac-sha256"), &signature),
    );
    cross_host.headers.insert("date".to_string(), date);
    assert_reject(
        plugin.authenticate(&mut cross_host, &consumer_index).await,
        Some(401),
    );
}

#[tokio::test]
async fn test_signature_and_identity_lookup_are_namespace_scoped() {
    let shared = "cross-namespace-reused-hmac-secret-at-least-32-characters";
    let mut tenant_a = create_hmac_consumer_named("tenant-a-id", "alice", shared);
    tenant_a.namespace = "tenant-a".to_string();
    let mut tenant_b = create_hmac_consumer_named("tenant-b-id", "bob", shared);
    tenant_b.namespace = "tenant-b".to_string();
    let consumer_index = ConsumerIndex::new(&[tenant_a, tenant_b]);
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let date = current_date();
    let digest = sha256_digest_header(&[]);

    let tenant_a_signature = sign_sha256_for_identity(
        shared,
        HmacSigningInput {
            namespace: "tenant-a",
            username: "alice",
            authority: TEST_AUTHORITY,
            method: "GET",
            path: "/bound",
            query: "",
            date: &date,
            digest_header: &digest,
        },
    );
    let mut replayed_in_tenant_b = make_ctx("GET", "/bound");
    set_ctx_namespace(&mut replayed_in_tenant_b, "tenant-b");
    replayed_in_tenant_b.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("alice", Some("hmac-sha256"), &tenant_a_signature),
    );
    replayed_in_tenant_b
        .headers
        .insert("date".to_string(), date.clone());
    assert_reject(
        plugin
            .authenticate(&mut replayed_in_tenant_b, &consumer_index)
            .await,
        Some(401),
    );

    let tenant_b_wrong_identity = sign_sha256_for_identity(
        shared,
        HmacSigningInput {
            namespace: "tenant-b",
            username: "alice",
            authority: TEST_AUTHORITY,
            method: "GET",
            path: "/bound",
            query: "",
            date: &date,
            digest_header: &digest,
        },
    );
    let mut wrong_identity = make_ctx("GET", "/bound");
    set_ctx_namespace(&mut wrong_identity, "tenant-b");
    wrong_identity.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("alice", Some("hmac-sha256"), &tenant_b_wrong_identity),
    );
    wrong_identity
        .headers
        .insert("date".to_string(), date.clone());
    assert_reject(
        plugin
            .authenticate(&mut wrong_identity, &consumer_index)
            .await,
        Some(401),
    );

    let tenant_b_signature = sign_sha256_for_identity(
        shared,
        HmacSigningInput {
            namespace: "tenant-b",
            username: "bob",
            authority: TEST_AUTHORITY,
            method: "GET",
            path: "/bound",
            query: "",
            date: &date,
            digest_header: &digest,
        },
    );
    let mut valid_tenant_b = make_ctx("GET", "/bound");
    set_ctx_namespace(&mut valid_tenant_b, "tenant-b");
    valid_tenant_b.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("bob", Some("hmac-sha256"), &tenant_b_signature),
    );
    valid_tenant_b.headers.insert("date".to_string(), date);
    assert_continue(
        plugin
            .authenticate(&mut valid_tenant_b, &consumer_index)
            .await,
    );
    assert_eq!(
        valid_tenant_b.identified_consumer.unwrap().id,
        "tenant-b-id"
    );
}

#[tokio::test]
async fn test_pre_auth_body_screening_requires_a_verified_signature() {
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_hmac_consumer()]);
    let date = current_date();
    let signature = sign_sha256(TEST_SECRET, "POST", "/upload", &date);
    let mut valid = make_ctx("POST", "/upload");
    valid.request_body_bytes = None;
    valid.headers.insert(
        "authorization".to_string(),
        hmac_auth_header(TEST_USERNAME, Some("hmac-sha256"), &signature),
    );
    valid.headers.insert("date".to_string(), date.clone());
    assert!(plugin.should_buffer_request_body_before_authenticate(&valid, &consumer_index));

    // A wrong-secret signature is still well-formed base64 with exactly the
    // expected 32-byte decoded length. Knowing a real username must not be
    // enough to opt into the 10 MiB pre-auth collection budget.
    let wrong_signature = sign_sha256(
        "wrong-secret-that-is-still-long-enough-for-the-test",
        "POST",
        "/upload",
        &date,
    );
    let mut known_wrong = make_ctx("POST", "/upload");
    known_wrong.request_body_bytes = None;
    known_wrong.headers.insert(
        "authorization".to_string(),
        hmac_auth_header(TEST_USERNAME, Some("hmac-sha256"), &wrong_signature),
    );
    known_wrong.headers.insert("date".to_string(), date.clone());
    let known_wrong_buffers =
        plugin.should_buffer_request_body_before_authenticate(&known_wrong, &consumer_index);

    let mut unknown = make_ctx("POST", "/upload");
    unknown.request_body_bytes = None;
    unknown.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("unknown", Some("hmac-sha256"), &wrong_signature),
    );
    unknown.headers.insert("date".to_string(), date.clone());
    let unknown_buffers =
        plugin.should_buffer_request_body_before_authenticate(&unknown, &consumer_index);

    assert!(!known_wrong_buffers);
    assert_eq!(known_wrong_buffers, unknown_buffers);

    // Both non-buffered paths must also expose the same authentication result,
    // independent of whether the username exists.
    let known_wrong_reject = match plugin.authenticate(&mut known_wrong, &consumer_index).await {
        PluginResult::Reject {
            status_code, body, ..
        } => (status_code, body),
        other => panic!("expected known wrong signature to reject, got {other:?}"),
    };
    let unknown_reject = match plugin.authenticate(&mut unknown, &consumer_index).await {
        PluginResult::Reject {
            status_code, body, ..
        } => (status_code, body),
        other => panic!("expected unknown consumer to reject, got {other:?}"),
    };
    assert_eq!(known_wrong_reject, unknown_reject);

    let mut malformed = make_ctx("POST", "/upload");
    malformed.headers.insert(
        "authorization".to_string(),
        r#"hmac username="hmacuser", signature="not-base64""#.to_string(),
    );
    malformed.headers.insert("date".to_string(), date);
    assert!(!plugin.should_buffer_request_body_before_authenticate(&malformed, &consumer_index));
}

#[tokio::test]
async fn test_preverified_reuse_still_rejects_final_digest_mismatch() {
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_hmac_consumer()]);
    let method = "POST";
    let path = "/upload";
    let date = current_date();
    let signed_body = br#"{"amount":1}"#;
    let digest = sha256_digest_header(signed_body);
    let signature = sign_sha256_with_digest(TEST_SECRET, method, path, &date, &digest);

    let mut tampered = make_ctx(method, path);
    tampered.request_body_sha256 = None;
    tampered.request_body_sha512 = None;
    tampered.headers.insert(
        "authorization".to_string(),
        hmac_auth_header(TEST_USERNAME, Some("hmac-sha256"), &signature),
    );
    tampered.headers.insert("date".to_string(), date.clone());
    tampered
        .headers
        .insert("digest".to_string(), digest.clone());

    assert!(
        plugin.should_buffer_request_body_before_authenticate(&tampered, &consumer_index),
        "a valid pre-body signature must enable body collection"
    );
    assert!(
        format!("{tampered:?}").contains("HmacPrebufferState { staged: true }"),
        "the request-scoped reuse path should be staged"
    );
    assert!(
        format!("{:?}", tampered.clone()).contains("HmacPrebufferState { staged: false }"),
        "request-context clones must not inherit staged HMAC credentials"
    );

    set_request_body(&mut tampered, br#"{"amount":999}"#);
    assert_reject(
        plugin.authenticate(&mut tampered, &consumer_index).await,
        Some(401),
    );
    assert!(tampered.identified_consumer.is_none());

    // Exercise the same staged path with matching bytes to prove the
    // preverified signature remains sufficient to reach post-body auth.
    let mut valid = make_ctx(method, path);
    valid.request_body_sha256 = None;
    valid.request_body_sha512 = None;
    valid.headers.insert(
        "authorization".to_string(),
        hmac_auth_header(TEST_USERNAME, Some("hmac-sha256"), &signature),
    );
    valid.headers.insert("date".to_string(), date);
    valid.headers.insert("digest".to_string(), digest);
    assert!(plugin.should_buffer_request_body_before_authenticate(&valid, &consumer_index));
    set_request_body(&mut valid, signed_body);
    assert_continue(plugin.authenticate(&mut valid, &consumer_index).await);
    assert_eq!(valid.identified_consumer.unwrap().username, TEST_USERNAME);
}

#[tokio::test]
async fn test_preverified_reuse_verifies_seeded_empty_body_digests() {
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_hmac_consumer()]);

    for method in ["GET", "HEAD", "OPTIONS"] {
        let path = "/empty";
        let date = current_date();
        let digest = sha256_content_digest_header(&[]);
        let signature = sign_sha256_with_digest(TEST_SECRET, method, path, &date, &digest);
        let mut ctx = make_ctx(method, path);
        ctx.request_body_sha256 = None;
        ctx.request_body_sha512 = None;
        ctx.headers.remove("digest");
        ctx.headers.insert(
            "authorization".to_string(),
            hmac_auth_header(TEST_USERNAME, Some("hmac-sha256"), &signature),
        );
        ctx.headers.insert("date".to_string(), date);
        ctx.headers.insert("content-digest".to_string(), digest);

        assert!(
            plugin.should_buffer_request_body_before_authenticate(&ctx, &consumer_index),
            "{method} should stage a correctly signed empty-body request"
        );
        // Mirrors the shared proxy boundary after Incoming has definitively
        // reported END_STREAM without requiring body collection.
        set_request_body(&mut ctx, &[]);
        assert_continue(plugin.authenticate(&mut ctx, &consumer_index).await);
        assert_eq!(ctx.identified_consumer.unwrap().username, TEST_USERNAME);
    }

    for method in ["GET", "HEAD", "OPTIONS"] {
        let path = "/empty";
        let date = current_date();
        let incorrect_digest = sha256_content_digest_header(b"not empty");
        let signature =
            sign_sha256_with_digest(TEST_SECRET, method, path, &date, &incorrect_digest);
        let mut ctx = make_ctx(method, path);
        ctx.request_body_sha256 = None;
        ctx.request_body_sha512 = None;
        ctx.headers.remove("digest");
        ctx.headers.insert(
            "authorization".to_string(),
            hmac_auth_header(TEST_USERNAME, Some("hmac-sha256"), &signature),
        );
        ctx.headers.insert("date".to_string(), date);
        ctx.headers
            .insert("content-digest".to_string(), incorrect_digest);

        assert!(
            plugin.should_buffer_request_body_before_authenticate(&ctx, &consumer_index),
            "{method} has a valid signature even though its body digest is wrong"
        );
        set_request_body(&mut ctx, &[]);
        assert_reject(
            plugin.authenticate(&mut ctx, &consumer_index).await,
            Some(401),
        );
        assert!(ctx.identified_consumer.is_none());
    }
}

#[tokio::test]
async fn test_preverified_reuse_discards_changed_authorization() {
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_hmac_consumer()]);
    let method = "POST";
    let path = "/upload";
    let date = current_date();
    let body = br#"{"amount":1}"#;
    let digest = sha256_digest_header(body);
    let signature = sign_sha256_with_digest(TEST_SECRET, method, path, &date, &digest);

    let mut ctx = make_ctx(method, path);
    ctx.request_body_sha256 = None;
    ctx.request_body_sha512 = None;
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header(TEST_USERNAME, Some("hmac-sha256"), &signature),
    );
    ctx.headers.insert("date".to_string(), date.clone());
    ctx.headers.insert("digest".to_string(), digest);
    assert!(plugin.should_buffer_request_body_before_authenticate(&ctx, &consumer_index));

    // No plug-in hook runs between screening and authentication in H1/H2/H3,
    // but bind the cache defensively so a future lifecycle change cannot reuse
    // a preverified result after the credential header changes.
    let wrong_signature = sign_sha256_with_digest(
        "wrong-secret-that-cannot-authenticate",
        method,
        path,
        &date,
        ctx.headers.get("digest").unwrap(),
    );
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header(TEST_USERNAME, Some("hmac-sha256"), &wrong_signature),
    );
    set_request_body(&mut ctx, body);
    assert_reject(
        plugin.authenticate(&mut ctx, &consumer_index).await,
        Some(401),
    );
    assert!(ctx.identified_consumer.is_none());
}

// ── 2. Valid HMAC-SHA512 authentication (digest signing) ─────

#[tokio::test]
async fn test_valid_hmac_sha512() {
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer = create_hmac_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let method = "POST";
    let path = "/api/data";
    let date = current_date();
    let signature = sign_sha512(TEST_SECRET, method, path, &date);

    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("hmacuser", Some("hmac-sha512"), &signature),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
    assert_eq!(
        ctx.identified_consumer.as_ref().unwrap().username,
        "hmacuser"
    );
}

// ── 3. Missing Authorization header ──────────────────────────────────

#[tokio::test]
async fn test_missing_authorization_header() {
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_hmac_consumer()]);

    let mut ctx = make_ctx("GET", "/test");
    // No authorization header set
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_none());
}

// ── 4. Invalid auth format (not starting with "hmac ") ──────────────

#[tokio::test]
async fn test_invalid_auth_format_bearer() {
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_hmac_consumer()]);

    let mut ctx = make_ctx("GET", "/test");
    ctx.headers
        .insert("authorization".to_string(), "Bearer some-token".to_string());
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_invalid_auth_format_basic() {
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_hmac_consumer()]);

    let mut ctx = make_ctx("GET", "/test");
    ctx.headers.insert(
        "authorization".to_string(),
        "Basic dXNlcjpwYXNz".to_string(),
    );
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

// ── 5. Missing username in auth header ──────────────────────────────

#[tokio::test]
async fn test_missing_username() {
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_hmac_consumer()]);

    let mut ctx = make_ctx("GET", "/test");
    ctx.headers.insert(
        "authorization".to_string(),
        r#"hmac algorithm="hmac-sha256", signature="abc123""#.to_string(),
    );
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

// ── 6. Missing signature in auth header ──────────────────────────────

#[tokio::test]
async fn test_missing_signature() {
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_hmac_consumer()]);

    let mut ctx = make_ctx("GET", "/test");
    ctx.headers.insert(
        "authorization".to_string(),
        r#"hmac username="hmacuser", algorithm="hmac-sha256""#.to_string(),
    );
    ctx.headers.insert("date".to_string(), current_date());
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

// ── 7. Missing Date header ──────────────────────────────────────────

#[tokio::test]
async fn test_missing_date_header() {
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer = create_hmac_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let method = "GET";
    let path = "/test";
    // Sign with empty date since that's what the plugin will see
    let signature = sign_sha256(TEST_SECRET, method, path, "");

    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("hmacuser", Some("hmac-sha256"), &signature),
    );
    // No date header
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

// ── 8. Expired Date header (clock skew exceeded) ─────────────────────

#[tokio::test]
async fn test_expired_date_header() {
    // Use a very tight clock skew of 1 second
    let plugin = HmacAuth::new(&json!({"clock_skew_seconds": 1})).unwrap();
    let consumer = create_hmac_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let method = "GET";
    let path = "/test";
    // Use a date far in the past
    let old_date = "Mon, 01 Jan 2024 00:00:00 GMT";
    let signature = sign_sha256(TEST_SECRET, method, path, old_date);

    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("hmacuser", Some("hmac-sha256"), &signature),
    );
    ctx.headers.insert("date".to_string(), old_date.to_string());
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_unparseable_date_header() {
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer = create_hmac_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let method = "GET";
    let path = "/test";
    let bad_date = "not-a-date";
    let signature = sign_sha256(TEST_SECRET, method, path, bad_date);

    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("hmacuser", Some("hmac-sha256"), &signature),
    );
    ctx.headers.insert("date".to_string(), bad_date.to_string());
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

// ── 9. Unknown consumer ──────────────────────────────────────────────

#[tokio::test]
async fn test_unknown_consumer() {
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_hmac_consumer()]);

    let method = "GET";
    let path = "/test";
    let date = current_date();
    let signature = sign_sha256(TEST_SECRET, method, path, &date);

    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("nonexistent-user", Some("hmac-sha256"), &signature),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_empty_consumer_index() {
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer_index = ConsumerIndex::new(&[]);

    let method = "GET";
    let path = "/test";
    let date = current_date();
    let signature = sign_sha256(TEST_SECRET, method, path, &date);

    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("hmacuser", Some("hmac-sha256"), &signature),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

// ── 10. Consumer without hmac_auth credentials ──────────────────────

#[tokio::test]
async fn test_consumer_without_hmac_credentials() {
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer = create_consumer_without_hmac_creds();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let method = "GET";
    let path = "/test";
    let date = current_date();
    let signature = sign_sha256("irrelevant-secret", method, path, &date);

    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("nokeyuser", Some("hmac-sha256"), &signature),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

// ── 11. Invalid signature ────────────────────────────────────────────

#[tokio::test]
async fn test_invalid_signature() {
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer = create_hmac_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let method = "GET";
    let path = "/test";
    let date = current_date();

    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header(
            "hmacuser",
            Some("hmac-sha256"),
            "dGhpcy1pcy1ub3QtYS12YWxpZC1zaWduYXR1cmU=",
        ),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_malformed_base64_signature_rejected() {
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer = create_hmac_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let mut ctx = make_ctx("GET", "/test");
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("hmacuser", Some("hmac-sha256"), "not base64!"),
    );
    ctx.headers.insert("date".to_string(), current_date());
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_signature_wrong_secret() {
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer = create_hmac_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let method = "GET";
    let path = "/test";
    let date = current_date();
    // Sign with wrong secret
    let signature = sign_sha256("wrong-secret", method, path, &date);

    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("hmacuser", Some("hmac-sha256"), &signature),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_signature_wrong_method() {
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer = create_hmac_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let method = "GET";
    let path = "/test";
    let date = current_date();
    // Sign with different method
    let signature = sign_sha256(TEST_SECRET, "POST", path, &date);

    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("hmacuser", Some("hmac-sha256"), &signature),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_signature_wrong_path() {
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer = create_hmac_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let method = "GET";
    let path = "/test";
    let date = current_date();
    // Sign with different path
    let signature = sign_sha256(TEST_SECRET, method, "/other", &date);

    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("hmacuser", Some("hmac-sha256"), &signature),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

// ── Query-string binding (#30) ───────────────────────────────────────

#[tokio::test]
async fn test_valid_signature_with_query_string() {
    // A signature that binds the request's query string verifies when the
    // request carries exactly that query.
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer = create_hmac_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let method = "GET";
    let path = "/transfer";
    let query = "account=alice&amount=100";
    let date = current_date();
    let signature = sign_sha256_with_query(TEST_SECRET, method, path, query, &date);

    let mut ctx = make_ctx_with_query(method, path, query);
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("hmacuser", Some("hmac-sha256"), &signature),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
}

#[tokio::test]
async fn test_signature_query_param_tampering_rejected() {
    // #30: the signing string binds the query string, so replaying a captured
    // signature against the same path with an altered query parameter
    // (account=alice -> account=victim) must fail verification.
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer = create_hmac_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let method = "GET";
    let path = "/transfer";
    let date = current_date();
    // Client legitimately signed `account=alice`...
    let signature = sign_sha256_with_query(TEST_SECRET, method, path, "account=alice", &date);

    // ...but the request arrives with the query tampered to `account=victim`.
    let mut ctx = make_ctx_with_query(method, path, "account=victim");
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("hmacuser", Some("hmac-sha256"), &signature),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_signature_added_query_param_rejected() {
    // #30: a signature computed over a request with no query must not verify
    // when an attacker adds query parameters to the replayed request.
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer = create_hmac_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let method = "GET";
    let path = "/transfer";
    let date = current_date();
    // Signed with no query string.
    let signature = sign_sha256(TEST_SECRET, method, path, &date);

    // Replayed with an added query parameter.
    let mut ctx = make_ctx_with_query(method, path, "admin=true");
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("hmacuser", Some("hmac-sha256"), &signature),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

// ── 12. Default algorithm (when algorithm not specified) ─────────────

#[tokio::test]
async fn test_default_algorithm_is_sha256() {
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer = create_hmac_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let method = "GET";
    let path = "/test";
    let date = current_date();
    // Sign with SHA256 (the expected default)
    let signature = sign_sha256(TEST_SECRET, method, path, &date);

    let mut ctx = make_ctx(method, path);
    // No algorithm specified in header
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("hmacuser", None, &signature),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
    assert_eq!(
        ctx.identified_consumer.as_ref().unwrap().username,
        "hmacuser"
    );
}

// ── Additional edge-case tests ───────────────────────────────────────

#[tokio::test]
async fn test_case_insensitive_hmac_prefix() {
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer = create_hmac_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let method = "GET";
    let path = "/test";
    let date = current_date();
    let signature = sign_sha256(TEST_SECRET, method, path, &date);

    let mut ctx = make_ctx(method, path);
    // Use uppercase "HMAC" prefix
    ctx.headers.insert(
        "authorization".to_string(),
        format!(
            r#"HMAC username="hmacuser", algorithm="hmac-sha256", signature="{}""#,
            signature
        ),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    // The plugin does .to_lowercase().starts_with("hmac "), so HMAC should work
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
}

#[tokio::test]
async fn test_rfc3339_date_format() {
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer = create_hmac_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let method = "GET";
    let path = "/test";
    // Use RFC 3339 date format
    let date = Utc::now().to_rfc3339();
    let signature = sign_sha256(TEST_SECRET, method, path, &date);

    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("hmacuser", Some("hmac-sha256"), &signature),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
}

#[tokio::test]
async fn test_algorithm_name_is_case_insensitive() {
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer = create_hmac_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let method = "GET";
    let path = "/test";
    let date = current_date();
    let signature = sign_sha512(TEST_SECRET, method, path, &date);

    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("hmacuser", Some("HMAC-SHA512"), &signature),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_unknown_algorithm_rejected() {
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer = create_hmac_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let method = "GET";
    let path = "/test";
    let date = current_date();
    let signature = sign_sha256(TEST_SECRET, method, path, &date);

    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("hmacuser", Some("sha1"), &signature),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_sha512_with_default_algorithm_fails() {
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer = create_hmac_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let method = "GET";
    let path = "/test";
    let date = current_date();
    // Sign with SHA512 but don't specify algorithm (defaults to SHA256)
    let signature = sign_sha512(TEST_SECRET, method, path, &date);

    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("hmacuser", None, &signature),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    // SHA512 signature won't match SHA256 expected
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_consumer_set_on_successful_auth() {
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer = create_hmac_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let method = "PUT";
    let path = "/api/resource/42";
    let date = current_date();
    let signature = sign_sha256(TEST_SECRET, method, path, &date);

    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("hmacuser", Some("hmac-sha256"), &signature),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);

    let identified = ctx.identified_consumer.as_ref().unwrap();
    assert_eq!(identified.id, "hmac-consumer");
    assert_eq!(identified.username, "hmacuser");
}

// ---- Multi-credential rotation tests ----

fn create_hmac_consumer_with_secrets(secrets: &[&str]) -> Consumer {
    let mut credentials = HashMap::new();
    let arr: Vec<Value> = secrets.iter().map(|s| json!({"secret": s})).collect();
    credentials.insert("hmac_auth".to_string(), Value::Array(arr));

    Consumer {
        id: "hmac-consumer".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: "hmacuser".to_string(),
        custom_id: None,
        credentials,
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

#[tokio::test]
async fn test_hmac_multi_secret_old_secret_still_works() {
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer = create_hmac_consumer_with_secrets(&["old-secret", "new-secret"]);
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let date = current_date();
    let sig = sign_sha256("old-secret", "GET", "/api", &date);
    let mut ctx = make_ctx("GET", "/api");
    ctx.headers.insert(
        "authorization".to_string(),
        format!(
            "hmac username=\"hmacuser\", algorithm=\"hmac-sha256\", signature=\"{}\"",
            sig
        ),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert_eq!(ctx.identified_consumer.unwrap().username, "hmacuser");
}

#[tokio::test]
async fn test_hmac_multi_secret_new_secret_works() {
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer = create_hmac_consumer_with_secrets(&["old-secret", "new-secret"]);
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let date = current_date();
    let sig = sign_sha256("new-secret", "GET", "/api", &date);
    let mut ctx = make_ctx("GET", "/api");
    ctx.headers.insert(
        "authorization".to_string(),
        format!(
            "hmac username=\"hmacuser\", algorithm=\"hmac-sha256\", signature=\"{}\"",
            sig
        ),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert_eq!(ctx.identified_consumer.unwrap().username, "hmacuser");
}

#[tokio::test]
async fn test_hmac_multi_secret_wrong_secret_rejected() {
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer = create_hmac_consumer_with_secrets(&["secret-a", "secret-b"]);
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let date = current_date();
    let sig = sign_sha256("wrong-secret", "GET", "/api", &date);
    let mut ctx = make_ctx("GET", "/api");
    ctx.headers.insert(
        "authorization".to_string(),
        format!(
            "hmac username=\"hmacuser\", algorithm=\"hmac-sha256\", signature=\"{}\"",
            sig
        ),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

// ────────────────────────────────────────────────────────────────────
// Digest verification tests.
// ────────────────────────────────────────────────────────────────────

/// Helper to populate the buffered request body in a way that mirrors what
/// the proxy hot path does in `store_request_body_metadata`.
fn set_request_body(ctx: &mut RequestContext, body: &[u8]) {
    ctx.request_body_sha256 = Some(Sha256::digest(body).into());
    ctx.request_body_sha512 = Some(Sha512::digest(body).into());
    if let Ok(s) = std::str::from_utf8(body) {
        ctx.metadata
            .insert("request_body".to_string(), s.to_string());
    }
}

#[tokio::test]
async fn test_digest_required_valid_signature_with_correct_body() {
    // Default config signs and verifies the request body digest.
    let plugin = HmacAuth::new(&json!({})).unwrap();
    let consumer = create_hmac_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let method = "POST";
    let path = "/api/data";
    let date = current_date();
    let body = br#"{"hello":"world"}"#;
    let digest = sha256_digest_header(body);
    let signature = sign_sha256_with_digest(TEST_SECRET, method, path, &date, &digest);

    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("hmacuser", Some("hmac-sha256"), &signature),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.headers.insert("digest".to_string(), digest);
    set_request_body(&mut ctx, body);
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert_eq!(
        ctx.identified_consumer.as_ref().unwrap().username,
        "hmacuser"
    );
}

#[tokio::test]
async fn test_digest_required_modified_body_rejected() {
    // Same Digest header + same HMAC signature, but the body was modified
    // after signing — must be rejected.
    let plugin = HmacAuth::new(&json!({})).unwrap();
    let consumer = create_hmac_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let method = "POST";
    let path = "/api/data";
    let date = current_date();
    let original_body = br#"{"amount":1}"#;
    let digest = sha256_digest_header(original_body);
    let signature = sign_sha256_with_digest(TEST_SECRET, method, path, &date, &digest);

    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("hmacuser", Some("hmac-sha256"), &signature),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.headers.insert("digest".to_string(), digest);
    // Attacker swaps body but reuses the captured Digest+signature.
    let tampered_body = br#"{"amount":1000000}"#;
    set_request_body(&mut ctx, tampered_body);
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
    assert!(ctx.identified_consumer.is_none());
}

#[tokio::test]
async fn test_digest_required_missing_digest_header_rejected() {
    let plugin = HmacAuth::new(&json!({})).unwrap();
    let consumer = create_hmac_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let method = "POST";
    let path = "/api/data";
    let date = current_date();
    let body = br#"{"hello":"world"}"#;
    let digest = sha256_digest_header(body);
    let signature = sign_sha256_with_digest(TEST_SECRET, method, path, &date, &digest);

    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("hmacuser", Some("hmac-sha256"), &signature),
    );
    ctx.headers.insert("date".to_string(), date);
    // Intentionally do not set the digest header.
    ctx.headers.remove("digest");
    set_request_body(&mut ctx, body);
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_missing_digest_rejected() {
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer = create_hmac_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let method = "POST";
    let path = "/api/data";
    let date = current_date();
    let signature = sign_sha256(TEST_SECRET, method, path, &date);

    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("hmacuser", Some("hmac-sha256"), &signature),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.headers.remove("digest");
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_digest_required_tampered_digest_header_rejected() {
    // Attacker recomputes a digest matching their tampered body, but lacks
    // the secret to re-sign — the HMAC mismatches because the digest header
    // is part of the signing string.
    let plugin = HmacAuth::new(&json!({})).unwrap();
    let consumer = create_hmac_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let method = "POST";
    let path = "/api/data";
    let date = current_date();
    let original_body = br#"{"amount":1}"#;
    let original_digest = sha256_digest_header(original_body);
    let signature = sign_sha256_with_digest(TEST_SECRET, method, path, &date, &original_digest);

    // Attacker substitutes a tampered body AND recomputes the digest header
    // to match the tampered body. Without the HMAC secret they cannot
    // re-sign, so they reuse the old signature.
    let tampered_body = br#"{"amount":9999999}"#;
    let tampered_digest = sha256_digest_header(tampered_body);

    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("hmacuser", Some("hmac-sha256"), &signature),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.headers.insert("digest".to_string(), tampered_digest);
    set_request_body(&mut ctx, tampered_body);
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_digest_required_sha512_digest_accepted() {
    let plugin = HmacAuth::new(&json!({})).unwrap();
    let consumer = create_hmac_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let method = "POST";
    let path = "/api/data";
    let date = current_date();
    let body = b"some payload bytes";
    let digest = sha512_digest_header(body);
    let signature = sign_sha256_with_digest(TEST_SECRET, method, path, &date, &digest);

    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("hmacuser", Some("hmac-sha256"), &signature),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.headers.insert("digest".to_string(), digest);
    set_request_body(&mut ctx, body);
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_digest_required_content_digest_header_accepted() {
    // RFC 9530 Content-Digest structured-field form is accepted.
    let plugin = HmacAuth::new(&json!({})).unwrap();
    let consumer = create_hmac_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let method = "POST";
    let path = "/api/data";
    let date = current_date();
    let body = br#"{"hello":"world"}"#;
    let legacy_digest = sha256_digest_header(body);
    let digest = format!("sha-256=:{}:", legacy_digest.trim_start_matches("sha-256="));
    let signature = sign_sha256_with_digest(TEST_SECRET, method, path, &date, &digest);

    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("hmacuser", Some("hmac-sha256"), &signature),
    );
    ctx.headers.insert("date".to_string(), date);
    // RFC 9530 header name and byte-sequence syntax (instead of legacy Digest).
    ctx.headers.insert("content-digest".to_string(), digest);
    set_request_body(&mut ctx, body);
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_digest_required_empty_body_with_digest() {
    // GET requests with empty body still must include a valid digest header
    // with digest signing enabled.
    let plugin = HmacAuth::new(&json!({})).unwrap();
    let consumer = create_hmac_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let method = "GET";
    let path = "/api/data";
    let date = current_date();
    let body = b"";
    let digest = sha256_digest_header(body);
    let signature = sign_sha256_with_digest(TEST_SECRET, method, path, &date, &digest);

    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("hmacuser", Some("hmac-sha256"), &signature),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.headers.insert("digest".to_string(), digest);
    // Empty-body hash snapshots were populated by `make_ctx`.
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
}

// `verify_body_digest` is a `pub(crate)` helper — its dedicated tests live
// inline in `src/plugins/hmac_auth.rs::tests` since `tests/` is a separate
// crate that can't see crate-private items. The end-to-end auth flow is
// covered above (correct-body vs. tampered-body vs. tampered-digest).
