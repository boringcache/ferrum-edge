use ferrum_edge::plugins::RequestContext;
use ferrum_edge::plugins::utils::auth_flow::ExtractedCredential;
use ferrum_edge::plugins::utils::cert_hash::{sha256_base64url_no_pad, sha256_hex_lower};
use ferrum_edge::plugins::utils::claim_resolver::{
    extract_claim_string, extract_claim_string_exact, extract_claim_values, parse_claim_path_value,
};
use ferrum_edge::plugins::utils::json_escape::escape_json_string;
use ferrum_edge::plugins::utils::jwt_verifier::peek_unverified_issuer;
use ferrum_edge::plugins::utils::query::has_conflicting_duplicate_query_key;
use ferrum_edge::plugins::utils::scope_role_check::{ScopeRoleRequirements, check};
use ferrum_edge::plugins::utils::token_extract::{
    TokenHeaderLocation, TokenLocation, TokenLocationExtract, extract_authorization_bearer,
    extract_from_location,
};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::json;

#[test]
fn json_escape_escapes_backslash_and_quote() {
    assert_eq!(escape_json_string(r#"a"b\c"#), r#"a\"b\\c"#);
}

#[test]
fn json_escape_escapes_angle_brackets() {
    assert_eq!(escape_json_string("<script>"), "\\u003cscript\\u003e");
}

#[test]
fn json_escape_passes_plain_text_through() {
    assert_eq!(escape_json_string("hello world"), "hello world");
}

#[test]
fn json_escape_escapes_named_json_control_characters() {
    assert_eq!(
        escape_json_string("line\ncarriage\rthing\tback\u{08}form\u{0c}"),
        "line\\ncarriage\\rthing\\tback\\bform\\f"
    );
}

#[test]
fn json_escape_escapes_all_other_control_characters_as_unicode() {
    let raw: String = (0u8..=0x1f)
        .filter(|b| !matches!(*b, b'\n' | b'\r' | b'\t' | 0x08 | 0x0c))
        .map(char::from)
        .collect();
    let escaped = escape_json_string(&raw);

    assert!(!escaped.chars().any(|ch| ch < '\u{20}'));
    assert!(escaped.contains("\\u0000"));
    assert!(escaped.contains("\\u001f"));
}

#[test]
fn json_escape_output_can_be_interpolated_into_json_string() {
    let raw = "bad\"\n<script>\u{00}\u{1f}\\";
    let body = format!(r#"{{"message":"{}"}}"#, escape_json_string(raw));
    let parsed: serde_json::Value =
        serde_json::from_str(&body).expect("escaped string should be valid JSON");

    assert_eq!(parsed["message"], raw);
}

#[test]
fn query_duplicate_check_detects_conflicting_duplicate_values() {
    assert!(has_conflicting_duplicate_query_key("a=1&a=2"));
}

#[test]
fn query_duplicate_check_allows_identical_duplicate_values() {
    assert!(!has_conflicting_duplicate_query_key("a=1&a=1"));
}

#[test]
fn query_duplicate_check_detects_percent_encoded_key_collision() {
    assert!(has_conflicting_duplicate_query_key("a%20b=1&a%20b=2"));
}

#[test]
fn query_duplicate_check_allows_percent_encoded_keys_with_same_value() {
    assert!(!has_conflicting_duplicate_query_key("a%20b=1&a%20b=1"));
}

#[test]
fn query_duplicate_check_detects_keys_without_equals() {
    assert!(has_conflicting_duplicate_query_key("flag&flag=1"));
}

#[test]
fn query_duplicate_check_allows_distinct_keys_without_equals() {
    assert!(!has_conflicting_duplicate_query_key("flag&other"));
}

#[test]
fn query_duplicate_check_ignores_empty_pairs() {
    assert!(has_conflicting_duplicate_query_key("a=1&&a=2"));
    assert!(!has_conflicting_duplicate_query_key("a=1&&a=1"));
}

#[test]
fn cert_hash_sha256_hex_lower_matches_known_value() {
    assert_eq!(
        sha256_hex_lower(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn cert_hash_sha256_base64url_no_pad_matches_known_value() {
    assert_eq!(
        sha256_base64url_no_pad(b"abc"),
        "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0"
    );
}

#[test]
fn claim_resolver_resolves_hash_inside_path_segment() {
    let claims = json!({"cnf": {"x5t#S256": "thumbprint"}});
    assert_eq!(
        extract_claim_string(&claims, "cnf.x5t#S256").as_deref(),
        Some("thumbprint")
    );
}

#[test]
fn claim_resolver_rejects_blank_or_non_string_identity_values() {
    for claims in [
        json!({}),
        json!({"sub": null}),
        json!({"sub": 42}),
        json!({"sub": ""}),
        json!({"sub": "   \t"}),
    ] {
        assert_eq!(extract_claim_string(&claims, "sub"), None);
    }
}

#[test]
fn claim_resolver_exact_string_distinguishes_blank_from_missing() {
    let claims = json!({"display_name": "   \t"});

    assert_eq!(
        extract_claim_string_exact(&claims, "display_name").as_deref(),
        Some("   \t")
    );
    assert_eq!(extract_claim_string_exact(&claims, "missing"), None);
}

#[test]
fn claim_resolver_extracts_space_delimited_and_array_values() {
    let claims = json!({
        "scope": "read write",
        "realm_access": {"roles": ["admin", "editor"]}
    });
    assert_eq!(
        extract_claim_values(&claims, "scope"),
        vec!["read", "write"]
    );
    assert_eq!(
        extract_claim_values(&claims, "realm_access.roles"),
        vec!["admin", "editor"]
    );
}

#[test]
fn claim_resolver_rejects_empty_path_segments() {
    let err = parse_claim_path_value("scope_claim", &json!("realm..roles"), "test")
        .expect_err("path should be rejected");
    assert!(err.contains("scope_claim"));
}

#[test]
fn scope_role_check_accepts_required_scope_and_role() {
    let claims = json!({"scope": "read write", "roles": ["admin"]});
    let scopes = vec!["read".to_string()];
    let roles = vec!["admin".to_string()];
    let req = ScopeRoleRequirements {
        required_scopes: &scopes,
        required_roles: &roles,
        scope_claim: "scope",
        role_claim: "roles",
        plugin_name: "test",
    };

    assert!(check(&claims, &req).is_ok());
}

#[test]
fn scope_role_check_rejects_missing_scope() {
    let claims = json!({"scope": "read"});
    let scopes = vec!["write".to_string()];
    let req = ScopeRoleRequirements {
        required_scopes: &scopes,
        required_roles: &[],
        scope_claim: "scope",
        role_claim: "roles",
        plugin_name: "test",
    };

    let (status, body) = check(&claims, &req).expect_err("missing scope should reject");
    assert_eq!(status, 403);
    assert!(body.contains("Insufficient scope"));
}

#[test]
fn jwt_verifier_peeks_issuer_without_verifying_signature() {
    let token = encode(
        &Header::default(),
        &json!({"iss": "https://issuer", "exp": 9_999_999_999u64}),
        &EncodingKey::from_secret(b"secret"),
    )
    .expect("test token should encode");

    assert_eq!(
        peek_unverified_issuer(&token).as_deref(),
        Some("https://issuer")
    );
}

#[test]
fn jwt_verifier_malformed_token_has_no_issuer() {
    assert!(peek_unverified_issuer("not.a.jwt.extra").is_none());
}

fn ctx_with_header(name: &str, value: &str) -> RequestContext {
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/".into());
    ctx.headers.insert(name.to_string(), value.to_string());
    ctx
}

#[test]
fn token_extract_extracts_bearer_token_from_authorization() {
    let ctx = ctx_with_header("authorization", "Bearer abc");
    assert!(matches!(
        extract_authorization_bearer(&ctx),
        ExtractedCredential::BearerToken(token) if token == "abc"
    ));
}

#[test]
fn token_extract_treats_foreign_authorization_scheme_as_missing() {
    let ctx = ctx_with_header("authorization", "Basic dXNlcjpwYXNz");
    assert!(matches!(
        extract_authorization_bearer(&ctx),
        ExtractedCredential::Missing
    ));
}

#[test]
fn token_extract_configured_header_prefix_mismatch_is_missing() {
    let ctx = ctx_with_header("x-token", "Token abc");
    let location = TokenLocation::Header(TokenHeaderLocation {
        name: "x-token".to_string(),
        prefix: Some("Bearer ".to_string()),
    });
    assert!(matches!(
        extract_from_location(&location, &ctx),
        TokenLocationExtract::Missing
    ));
}

#[test]
fn token_extract_prefixless_authorization_location_classifies_bearer_scheme() {
    let location = TokenLocation::Header(TokenHeaderLocation {
        name: "authorization".to_string(),
        prefix: None,
    });

    let bearer_ctx = ctx_with_header("authorization", "Bearer abc");
    assert!(matches!(
        extract_from_location(&location, &bearer_ctx),
        TokenLocationExtract::Credential(ExtractedCredential::BearerToken(token))
            if token == "abc"
    ));

    let basic_ctx = ctx_with_header("authorization", "Basic dXNlcjpwYXNz");
    assert!(matches!(
        extract_from_location(&location, &basic_ctx),
        TokenLocationExtract::Missing
    ));
}
