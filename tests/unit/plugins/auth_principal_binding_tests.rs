//! Coverage for the shared authentication-composition boundary:
//!
//! * `claim_headers` destinations are gateway-owned and always sanitized, so a
//!   client-supplied value can never survive an authenticated request.
//! * Composed authentication factors must prove the same canonical principal
//!   before authorization runs.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use serde_json::{Value, json};

use ferrum_edge::ConsumerIndex;
use ferrum_edge::config::types::{Consumer, default_namespace};
use ferrum_edge::plugins::utils::auth_attempt::AuthenticationAttempt;
use ferrum_edge::plugins::utils::auth_flow::{
    VerifyOutcome, commit_authentication_attempt, stream_principal_binding_conflicts,
};
use ferrum_edge::plugins::utils::claim_header_fanout::{
    ClaimHeaderDestinations, ClaimHeaderMapping, apply_claim_headers_from_context,
    emit_claim_headers_to_attempt, parse_claim_headers,
};
use ferrum_edge::plugins::{Plugin, RequestContext, jwks_auth::JwksAuth};

use super::jwks_auth_support::{build_rsa_jwks_from_pem, create_rs256_token, default_client};
use super::plugin_utils::assert_continue;

const PREFIX: &str = "test_auth.claim_header.";

fn ctx() -> RequestContext {
    RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/protected".to_string(),
    )
}

fn consumer(id: &str, username: &str) -> Consumer {
    Consumer {
        id: id.to_string(),
        username: username.to_string(),
        namespace: default_namespace(),
        custom_id: None,
        credentials: HashMap::new(),
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn mappings(config: &Value) -> Vec<ClaimHeaderMapping> {
    parse_claim_headers(
        config.as_object().expect("object"),
        "claim_headers",
        "test_auth",
        PREFIX,
    )
    .expect("valid claim_headers")
}

/// Authenticate an external principal and install claim headers over `headers`.
fn authenticate_and_apply(claims: &Value, config: &Value, headers: &mut HashMap<String, String>) {
    let mapped = mappings(config);
    let destinations = ClaimHeaderDestinations::from_mapping_groups(std::iter::once(
        mapped.as_slice(),
    ));

    let mut ctx = ctx();
    let mut attempt = AuthenticationAttempt::new();
    emit_claim_headers_to_attempt(&mut attempt, claims, &mapped, ",");
    commit_authentication_attempt(
        &mut ctx,
        attempt,
        VerifyOutcome::success(None, Some("alice@example.test".to_string()), None),
        "test_auth",
        true,
    )
    .expect("attempt commits");

    apply_claim_headers_from_context(&mut ctx, headers, PREFIX, &destinations);
}

// ---------------------------------------------------------------------------
// GHSA-99wm-qwwv-33v9 — gateway-owned claim-header destinations
// ---------------------------------------------------------------------------

#[test]
fn present_claim_replaces_client_supplied_destination() {
    let config = json!({"claim_headers": {"email": "X-Authenticated-Email"}});
    let mut headers = HashMap::from([(
        "X-Authenticated-Email".to_string(),
        "attacker@example.test".to_string(),
    )]);

    authenticate_and_apply(
        &json!({"email": "verified@example.test"}),
        &config,
        &mut headers,
    );

    assert_eq!(
        headers.get("x-authenticated-email").map(String::as_str),
        Some("verified@example.test")
    );
    assert!(
        !headers.contains_key("X-Authenticated-Email"),
        "the client's case-variant copy must not survive alongside the gateway value"
    );
    assert_eq!(headers.len(), 1);
}

#[test]
fn absent_claim_leaves_destination_absent_instead_of_client_input() {
    let config = json!({"claim_headers": {"email": "X-Authenticated-Email"}});
    let mut headers = HashMap::from([(
        "X-Authenticated-Email".to_string(),
        "attacker@example.test".to_string(),
    )]);

    // Authenticated, but the token carries no `email` claim.
    authenticate_and_apply(&json!({"sub": "alice"}), &config, &mut headers);

    assert!(
        headers.is_empty(),
        "an absent claim must strip the gateway-owned destination, got {headers:?}"
    );
}

#[test]
fn unusable_claim_shapes_all_produce_an_absent_destination() {
    let config = json!({"claim_headers": {"email": "X-Authenticated-Email"}});
    for claims in [
        json!({"email": null}),
        json!({"email": ""}),
        json!({"email": "   "}),
        json!({"email": 42}),
        json!({"email": true}),
        json!({"email": []}),
        json!({"email": ["", "  "]}),
        json!({"email": [1, 2]}),
        json!({"email": {"nested": "value"}}),
    ] {
        let mut headers = HashMap::from([(
            "x-authenticated-email".to_string(),
            "attacker@example.test".to_string(),
        )]);
        authenticate_and_apply(&claims, &config, &mut headers);
        assert!(
            headers.is_empty(),
            "claims {claims} must leave the destination absent, got {headers:?}"
        );
    }
}

#[test]
fn every_case_variant_of_a_destination_is_removed() {
    let config = json!({"claim_headers": {"email": "X-Authenticated-Email"}});
    let mut headers = HashMap::from([
        (
            "X-Authenticated-Email".to_string(),
            "one@example.test".to_string(),
        ),
        (
            "x-AUTHENTICATED-email".to_string(),
            "two@example.test".to_string(),
        ),
        (
            "X-AUTHENTICATED-EMAIL".to_string(),
            "three@example.test".to_string(),
        ),
        ("X-Unrelated".to_string(), "keep-me".to_string()),
    ]);

    authenticate_and_apply(&json!({"sub": "alice"}), &config, &mut headers);

    assert_eq!(
        headers,
        HashMap::from([("X-Unrelated".to_string(), "keep-me".to_string())]),
        "only the gateway-owned destination may be stripped"
    );
}

#[test]
fn an_instance_never_strips_a_destination_it_does_not_own() {
    let config = json!({"claim_headers": {"email": "X-Owned"}});
    let mut headers = HashMap::from([
        ("X-Owned".to_string(), "attacker".to_string()),
        ("X-Other-Plugin-Destination".to_string(), "other".to_string()),
    ]);

    authenticate_and_apply(&json!({"sub": "alice"}), &config, &mut headers);

    assert!(!headers.contains_key("X-Owned"));
    assert_eq!(
        headers.get("X-Other-Plugin-Destination").map(String::as_str),
        Some("other"),
        "another instance's destination must be untouched"
    );
}

#[test]
fn provider_override_destinations_are_owned_and_sanitized() {
    // Plugin-level mapping plus a provider override that targets a different
    // destination: both belong to the owned set.
    let plugin_level = mappings(&json!({"claim_headers": {"email": "X-Plugin-Email"}}));
    let provider_level = mappings(&json!({"claim_headers": {"email": "X-Provider-Email"}}));
    let destinations = ClaimHeaderDestinations::from_mapping_groups(
        [plugin_level.as_slice(), provider_level.as_slice()],
    );
    let owned: Vec<&str> = destinations.names().iter().map(String::as_str).collect();
    assert_eq!(
        owned,
        vec!["x-plugin-email", "x-provider-email"],
        "the owned set is the deduplicated union across provider overrides"
    );

    let mut ctx = ctx();
    let mut attempt = AuthenticationAttempt::new();
    // The matched provider staged only its own destination.
    emit_claim_headers_to_attempt(
        &mut attempt,
        &json!({"email": "verified@example.test"}),
        &provider_level,
        ",",
    );
    commit_authentication_attempt(
        &mut ctx,
        attempt,
        VerifyOutcome::success(None, Some("alice@example.test".to_string()), None),
        "test_auth",
        true,
    )
    .expect("attempt commits");

    let mut headers = HashMap::from([
        ("X-Plugin-Email".to_string(), "attacker@example.test".to_string()),
        (
            "X-Provider-Email".to_string(),
            "attacker@example.test".to_string(),
        ),
    ]);
    apply_claim_headers_from_context(&mut ctx, &mut headers, PREFIX, &destinations);

    assert_eq!(
        headers.get("x-provider-email").map(String::as_str),
        Some("verified@example.test")
    );
    assert!(
        !headers.contains_key("X-Plugin-Email") && !headers.contains_key("x-plugin-email"),
        "the unmatched plugin-level destination must be stripped, not left as client input"
    );
}

#[test]
fn a_later_instance_does_not_erase_a_shared_destination_already_installed() {
    let shared = mappings(&json!({"claim_headers": {"email": "X-Shared"}}));
    let destinations =
        ClaimHeaderDestinations::from_mapping_groups(std::iter::once(shared.as_slice()));

    let mut ctx = ctx();
    let mut attempt = AuthenticationAttempt::new();
    emit_claim_headers_to_attempt(
        &mut attempt,
        &json!({"email": "verified@example.test"}),
        &shared,
        ",",
    );
    commit_authentication_attempt(
        &mut ctx,
        attempt,
        VerifyOutcome::success(None, Some("alice@example.test".to_string()), None),
        "test_auth",
        true,
    )
    .expect("attempt commits");

    let mut headers =
        HashMap::from([("X-Shared".to_string(), "attacker@example.test".to_string())]);

    // First instance sanitizes and installs the verified value.
    apply_claim_headers_from_context(&mut ctx, &mut headers, PREFIX, &destinations);
    assert_eq!(
        headers.get("x-shared").map(String::as_str),
        Some("verified@example.test")
    );

    // A second instance sharing the destination has nothing staged; it must not
    // erase the value the first instance already installed.
    apply_claim_headers_from_context(&mut ctx, &mut headers, PREFIX, &destinations);
    assert_eq!(
        headers.get("x-shared").map(String::as_str),
        Some("verified@example.test"),
        "a shared destination is claimed once per request"
    );
}

#[tokio::test]
async fn jwks_auth_strips_client_claim_header_when_the_token_omits_the_claim() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");
    let jwks = build_rsa_jwks_from_pem(public_key_pem);

    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "jwks": jwks,
                "claim_headers": {"email": "X-Authenticated-Email"}
            }]
        }),
        default_client(),
    )
    .expect("valid jwks_auth config");
    assert!(plugin.modifies_request_headers());

    let consumer_index = ConsumerIndex::new(&[consumer("alice-id", "alice")]);
    // Valid token for an accepted principal, but with no `email` claim.
    let token = create_rs256_token(&json!({"sub": "alice"}), private_key_pem);

    let mut ctx = ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {token}"));
    ctx.headers.insert(
        "X-Authenticated-Email".to_string(),
        "attacker@example.test".to_string(),
    );
    assert_continue(plugin.authenticate(&mut ctx, &consumer_index).await);

    let mut headers = ctx.headers.clone();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);

    assert!(
        !headers
            .keys()
            .any(|name| name.eq_ignore_ascii_case("x-authenticated-email")),
        "an authenticated request without the mapped claim must not forward client input, \
         got {headers:?}"
    );
}

// ---------------------------------------------------------------------------
// GHSA-2xjg-2v8q-cr33 — same-principal binding for composed factors
// ---------------------------------------------------------------------------

/// Commit a second factor onto a context that already committed a principal.
fn commit_second_factor(ctx: &mut RequestContext, outcome: VerifyOutcome) -> Result<bool, u16> {
    commit_authentication_attempt(
        ctx,
        AuthenticationAttempt::new(),
        outcome,
        "second_factor",
        true,
    )
    .map_err(|rejection| match rejection {
        VerifyOutcome::Forbidden(_) => 403,
        VerifyOutcome::Internal(_) => 500,
        _ => 401,
    })
}

fn commit_first_factor(ctx: &mut RequestContext, outcome: VerifyOutcome) {
    commit_authentication_attempt(
        ctx,
        AuthenticationAttempt::new(),
        outcome,
        "first_factor",
        true,
    )
    .expect("first factor commits");
}

#[test]
fn mixed_consumer_and_external_factors_are_rejected() {
    // Bob proves an external identity; Alice's Consumer credential is then
    // composed on top. No single principal proved both factors.
    let mut ctx = ctx();
    commit_first_factor(
        &mut ctx,
        VerifyOutcome::success(None, Some("bob@example.test".to_string()), None),
    );

    let result = commit_second_factor(
        &mut ctx,
        VerifyOutcome::consumer(Arc::new(consumer("alice-id", "alice"))),
    );

    assert_eq!(result, Err(403));
    assert!(
        ctx.identified_consumer.is_none(),
        "a rejected composition must not install the second principal"
    );
    assert_eq!(ctx.authenticated_identity.as_deref(), Some("bob@example.test"));
    assert_eq!(ctx.auth_method, Some("first_factor"));
}

#[test]
fn two_different_consumers_are_rejected() {
    let mut ctx = ctx();
    commit_first_factor(
        &mut ctx,
        VerifyOutcome::consumer(Arc::new(consumer("alice-id", "alice"))),
    );

    let result = commit_second_factor(
        &mut ctx,
        VerifyOutcome::consumer(Arc::new(consumer("bob-id", "bob"))),
    );

    assert_eq!(result, Err(403));
    assert_eq!(
        ctx.identified_consumer
            .as_ref()
            .map(|c| c.username.as_str()),
        Some("alice")
    );
}

#[test]
fn two_different_external_identities_are_rejected() {
    let mut ctx = ctx();
    commit_first_factor(
        &mut ctx,
        VerifyOutcome::success(None, Some("alice@example.test".to_string()), None),
    );

    let result = commit_second_factor(
        &mut ctx,
        VerifyOutcome::success(None, Some("bob@example.test".to_string()), None),
    );

    assert_eq!(result, Err(403));
}

#[test]
fn distinct_consumers_sharing_a_display_name_are_rejected() {
    // Two separate Consumer records that merely happen to share a username must
    // not be treated as one principal.
    let mut ctx = ctx();
    commit_first_factor(
        &mut ctx,
        VerifyOutcome::consumer(Arc::new(consumer("tenant-a-alice", "alice"))),
    );

    let result = commit_second_factor(
        &mut ctx,
        VerifyOutcome::consumer(Arc::new(consumer("tenant-b-alice", "alice"))),
    );

    assert_eq!(
        result,
        Err(403),
        "principals must be compared by stable Consumer ID, not display name"
    );
}

#[test]
fn the_same_consumer_presented_twice_is_accepted() {
    let mut ctx = ctx();
    commit_first_factor(
        &mut ctx,
        VerifyOutcome::consumer(Arc::new(consumer("alice-id", "alice"))),
    );

    let result = commit_second_factor(
        &mut ctx,
        VerifyOutcome::consumer(Arc::new(consumer("alice-id", "alice"))),
    );

    assert_eq!(result, Ok(true));
    assert_eq!(
        ctx.identified_consumer
            .as_ref()
            .map(|c| c.username.as_str()),
        Some("alice")
    );
    assert_eq!(ctx.auth_method, Some("first_factor"));
}

#[test]
fn the_same_external_identity_presented_twice_is_accepted() {
    let mut ctx = ctx();
    commit_first_factor(
        &mut ctx,
        VerifyOutcome::success(None, Some("alice@example.test".to_string()), None),
    );

    let result = commit_second_factor(
        &mut ctx,
        VerifyOutcome::success(None, Some("alice@example.test".to_string()), None),
    );

    assert_eq!(result, Ok(true));
    assert_eq!(
        ctx.authenticated_identity.as_deref(),
        Some("alice@example.test")
    );
}

#[test]
fn a_single_credential_may_bind_a_consumer_and_an_external_identity() {
    // One mechanism proved both sides, which is the only supported mapping
    // between a Consumer and an external identity. Replaying it is accepted.
    let mut ctx = ctx();
    commit_first_factor(
        &mut ctx,
        VerifyOutcome::success(
            Some(Arc::new(consumer("alice-id", "alice"))),
            Some("alice@example.test".to_string()),
            None,
        ),
    );

    let result = commit_second_factor(
        &mut ctx,
        VerifyOutcome::success(
            Some(Arc::new(consumer("alice-id", "alice"))),
            Some("alice@example.test".to_string()),
            None,
        ),
    );

    assert_eq!(result, Ok(true));
}

#[test]
fn a_factor_adding_an_unproven_external_identity_is_rejected() {
    // The committed factor proved only a Consumer. A later factor asserting the
    // same Consumer plus an extra external identity introduces an identity no
    // credential in the chain vouched for.
    let mut ctx = ctx();
    commit_first_factor(
        &mut ctx,
        VerifyOutcome::consumer(Arc::new(consumer("alice-id", "alice"))),
    );

    let result = commit_second_factor(
        &mut ctx,
        VerifyOutcome::success(
            Some(Arc::new(consumer("alice-id", "alice"))),
            Some("bob@example.test".to_string()),
            None,
        ),
    );

    assert_eq!(result, Err(403));
}

#[test]
fn a_principal_less_second_factor_is_not_a_conflict() {
    let mut ctx = ctx();
    commit_first_factor(
        &mut ctx,
        VerifyOutcome::consumer(Arc::new(consumer("alice-id", "alice"))),
    );

    // Blank principals are filtered before the binding check, so this is simply
    // "established nothing" rather than a conflicting principal.
    let result = commit_second_factor(
        &mut ctx,
        VerifyOutcome::success(None, Some("   ".to_string()), None),
    );

    assert_eq!(result, Ok(false));
    assert_eq!(
        ctx.identified_consumer
            .as_ref()
            .map(|c| c.username.as_str()),
        Some("alice")
    );
}

#[test]
fn stream_binding_rule_matches_the_request_rule() {
    let alice = consumer("alice-id", "alice");
    let bob = consumer("bob-id", "bob");
    let alice_other_tenant = consumer("tenant-b-alice", "alice");

    // Nothing committed yet.
    assert!(!stream_principal_binding_conflicts(None, None, &alice));
    // Same stable Consumer.
    assert!(!stream_principal_binding_conflicts(Some(&alice), None, &alice));
    // Different Consumer.
    assert!(stream_principal_binding_conflicts(Some(&alice), None, &bob));
    // Same display name, different stable ID.
    assert!(stream_principal_binding_conflicts(
        Some(&alice),
        None,
        &alice_other_tenant
    ));
    // A separately asserted external principal cannot vouch for a Consumer.
    assert!(stream_principal_binding_conflicts(
        None,
        Some("spiffe://example.test/ns/default/sa/bob"),
        &alice
    ));
    // A blank external identity is not a committed principal.
    assert!(!stream_principal_binding_conflicts(None, Some("  "), &alice));
}
