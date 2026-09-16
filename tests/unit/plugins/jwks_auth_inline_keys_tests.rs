use ferrum_edge::ConsumerIndex;
use ferrum_edge::plugins::{Plugin, jwks_auth::JwksAuth};
use serde_json::json;

use super::jwks_auth_support::{
    build_rsa_jwks_from_pem, create_rs256_token, default_client, make_ctx,
};
use super::plugin_utils::{assert_continue, assert_reject};

#[tokio::test]
async fn inline_jwks_verifies_token_without_network() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");
    let inline_jwks = build_rsa_jwks_from_pem(public_key_pem).to_string();
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "issuer": "https://issuer.example.com",
                "jwks": inline_jwks
            }]
        }),
        default_client(),
    )
    .unwrap();

    assert!(plugin.active_jwks_uris().is_empty());
    plugin.warmup_jwks().await;

    let token = create_rs256_token(
        &json!({
            "iss": "https://issuer.example.com",
            "sub": "inline-user"
        }),
        private_key_pem,
    );
    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {token}"));

    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_continue(result);
    assert_eq!(ctx.authenticated_identity.as_deref(), Some("inline-user"));
}

#[test]
fn inline_jwks_rejects_malformed_json() {
    let result = JwksAuth::new(
        &json!({
            "providers": [{
                "issuer": "https://issuer.example.com",
                "jwks": "not-json"
            }]
        }),
        default_client(),
    );

    assert!(result.is_err());
    assert!(
        result
            .as_ref()
            .err()
            .unwrap()
            .contains("inline JWKS parse failed")
    );
}

#[test]
fn inline_jwks_rejects_remote_source_conflict() {
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");
    let inline_jwks = build_rsa_jwks_from_pem(public_key_pem).to_string();
    let result = JwksAuth::new(
        &json!({
            "providers": [{
                "issuer": "https://issuer.example.com",
                "jwks": inline_jwks,
                "jwks_uri": "https://issuer.example.com/.well-known/jwks.json"
            }]
        }),
        default_client(),
    );

    assert!(result.is_err());
    assert!(
        result
            .as_ref()
            .err()
            .unwrap()
            .contains("must configure exactly one")
    );
}

#[tokio::test]
async fn inline_jwks_with_no_keys_rejects_tokens() {
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "issuer": "https://issuer.example.com",
                "jwks": {"keys": []}
            }]
        }),
        default_client(),
    )
    .unwrap();
    let token = create_rs256_token(
        &json!({
            "iss": "https://issuer.example.com",
            "sub": "no-key-user"
        }),
        include_bytes!("../../../tests/fixtures/test_rsa_private.pem"),
    );
    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {token}"));

    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_reject(result, Some(401));
}

/// Issue #5522 sibling of the `jwt_auth` regression: the shared JWKS verifier
/// delegates issuer matching to `jsonwebtoken`, which matches a multi-valued
/// `iss` by set intersection. RFC 7519 §4.1.1 allows exactly one `StringOrURI`,
/// so a signed token claiming several issuers must never satisfy a provider's
/// exactly configured issuer.
#[tokio::test]
async fn inline_jwks_rejects_an_array_valued_issuer_claim() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");
    let inline_jwks = build_rsa_jwks_from_pem(public_key_pem).to_string();
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "issuer": "https://issuer.example.com",
                "jwks": inline_jwks
            }]
        }),
        default_client(),
    )
    .unwrap();
    plugin.warmup_jwks().await;

    for issuer in [
        json!(["https://issuer.example.com", "https://other.example.com"]),
        json!(["https://issuer.example.com"]),
        json!({"value": "https://issuer.example.com"}),
        json!(1234),
        json!(null),
    ] {
        let token = create_rs256_token(
            &json!({"iss": issuer, "sub": "array-issuer-user"}),
            private_key_pem,
        );
        let mut ctx = make_ctx();
        ctx.headers
            .insert("authorization".to_string(), format!("Bearer {token}"));

        let result = plugin
            .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
            .await;
        assert_reject(result, Some(401));
        assert!(
            ctx.authenticated_identity.is_none(),
            "non-string iss must not authenticate: {issuer}"
        );
    }
}

/// No-regression guard for the same fix: the single configured issuer, as a
/// plain string, still authenticates.
#[tokio::test]
async fn inline_jwks_still_accepts_the_configured_string_issuer() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");
    let inline_jwks = build_rsa_jwks_from_pem(public_key_pem).to_string();
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "issuer": "https://issuer.example.com",
                "jwks": inline_jwks
            }]
        }),
        default_client(),
    )
    .unwrap();
    plugin.warmup_jwks().await;

    let token = create_rs256_token(
        &json!({"iss": "https://issuer.example.com", "sub": "string-issuer-user"}),
        private_key_pem,
    );
    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {token}"));

    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_continue(result);
    assert_eq!(
        ctx.authenticated_identity.as_deref(),
        Some("string-issuer-user")
    );
}
