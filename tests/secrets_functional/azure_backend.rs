//! Azure Key Vault functional tests against an in-process fake.
//!
//! The real `azure_security_keyvault_secrets::SecretClient` makes real HTTP
//! calls to the fake; the only thing faked out is Entra ID — a dummy bearer
//! token is injected via `AzureCredentials::from_static_token(..)`, so no real
//! Azure AD round trip ever happens.

// `.err().expect(..)` is used deliberately on the secret-returning fetch path:
// the `Ok` value is the resolved secret, and `.expect_err()` (clippy's
// suggestion) would format and print it on an unexpected success. `.err()`
// drops the `Ok` value so a secret can never reach panic output.
#![allow(clippy::err_expect)]

use crate::common::env::EnvGuard;
use crate::common::fakes::AzureKeyVaultFake;
use ferrum_edge::secrets::{
    AzureCredentials, azure_parse_keyvault_reference, resolve_all_env_secrets,
};
use serial_test::serial;
use std::time::Duration;

const KEY: &str = "FERRUM_ADMIN_JWT_SECRET";

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn azure_secret_url_success() {
    let _guard = EnvGuard::new();
    let fake = AzureKeyVaultFake::start().await;
    fake.mock_secret("admin-jwt", "azure-admin-jwt").await;

    let creds = AzureCredentials::from_static_token("dummy-token");
    let value = creds
        .fetch_secret(&fake.secret_url("admin-jwt"), KEY)
        .await
        .expect("fetch should succeed against the fake");
    assert_eq!(value, "azure-admin-jwt");
}

/// Regression for the port-dropping bug: an explicit port in the secret URL
/// must be preserved when constructing the vault URL.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn azure_port_is_preserved_regression() {
    // (a) Direct parser assertion — the explicit port survives.
    let (vault_url, name) =
        azure_parse_keyvault_reference("http://127.0.0.1:12345/secrets/admin-jwt", KEY)
            .expect("valid URL should parse");
    assert_eq!(vault_url, "http://127.0.0.1:12345");
    assert_eq!(name, "admin-jwt");

    // (b) End-to-end: a successful fetch via the fake (which listens on an
    // ephemeral non-standard port) can only happen if the port was preserved —
    // dropping it would target :80 and fail to connect.
    let _guard = EnvGuard::new();
    let fake = AzureKeyVaultFake::start().await;
    fake.mock_secret("admin-jwt", "azure-admin-jwt").await;

    let creds = AzureCredentials::from_static_token("dummy-token");
    let value = creds
        .fetch_secret(&fake.secret_url("admin-jwt"), KEY)
        .await
        .expect("fetch on an explicit ephemeral port should succeed");
    assert_eq!(value, "azure-admin-jwt");

    let hits = fake.server.received_requests().await.unwrap_or_default();
    assert!(
        !hits.is_empty(),
        "the fake on the explicit port must have received the request"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn azure_invalid_url_errors() {
    let _guard = EnvGuard::new();
    let creds = AzureCredentials::from_static_token("dummy-token");
    let err = creds
        .fetch_secret("not-a-url", KEY)
        .await
        .err()
        .expect("a non-URL reference must fail");
    assert!(
        err.contains("Invalid Azure Key Vault URL"),
        "expected an invalid-URL error, got: {err}"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn azure_invalid_path_errors() {
    let _guard = EnvGuard::new();
    let creds = AzureCredentials::from_static_token("dummy-token");
    // `/keys/...` is the wrong resource path; only `/secrets/<name>` is valid.
    let err = creds
        .fetch_secret("http://127.0.0.1:12345/keys/admin-jwt", KEY)
        .await
        .err()
        .expect("a non-/secrets path must fail");
    assert!(
        err.contains("expected format"),
        "expected a path-format error, got: {err}"
    );
}

/// The production credential constructor must fail (before any network call)
/// when the Entra ID env vars are missing.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn azure_missing_env_credentials_errors() {
    // EnvGuard clears all AZURE_* vars, so the constructor sees none.
    let _guard = EnvGuard::new();
    let err = AzureCredentials::new()
        .err()
        .expect("missing AZURE_* must fail");
    assert!(
        err.contains("AZURE_TENANT_ID")
            || err.contains("AZURE_CLIENT_ID")
            || err.contains("AZURE_CLIENT_SECRET"),
        "expected a missing-credential error, got: {err}"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn azure_secret_not_found_errors() {
    let _guard = EnvGuard::new();
    let fake = AzureKeyVaultFake::start().await;
    fake.mock_secret_status("admin-jwt", 404).await;

    let creds = AzureCredentials::from_static_token("dummy-token");
    let err = creds
        .fetch_secret(&fake.secret_url("admin-jwt"), KEY)
        .await
        .err()
        .expect("404 must fail");
    assert!(
        err.contains("Failed to get Azure secret"),
        "expected an Azure fetch failure, got: {err}"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn azure_secret_has_no_value_errors() {
    let _guard = EnvGuard::new();
    let fake = AzureKeyVaultFake::start().await;
    fake.mock_secret_no_value("admin-jwt").await;

    let creds = AzureCredentials::from_static_token("dummy-token");
    let err = creds
        .fetch_secret(&fake.secret_url("admin-jwt"), KEY)
        .await
        .err()
        .expect("a secret with no value must fail");
    assert!(
        err.contains("has no value"),
        "expected a no-value error, got: {err}"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn azure_malformed_response_errors() {
    let _guard = EnvGuard::new();
    let fake = AzureKeyVaultFake::start().await;
    fake.mock_secret_malformed("admin-jwt").await;

    let creds = AzureCredentials::from_static_token("dummy-token");
    let err = creds
        .fetch_secret(&fake.secret_url("admin-jwt"), KEY)
        .await
        .err()
        .expect("a malformed body must fail");
    assert!(
        err.contains("Failed to get Azure secret") || err.contains("Failed to parse Azure secret"),
        "expected a fetch/parse error, got: {err}"
    );
}

/// Drives the registry timeout (`FERRUM_SECRET_FETCH_TIMEOUT_SECONDS`) through
/// the full resolver. The fake delays its first (unauthenticated) response, so
/// the resolver times out before any token is ever requested — no Entra ID call
/// occurs even though `AzureCredentials::new()` builds a real client-secret
/// credential from placeholder env values.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn azure_timeout_errors() {
    let guard = EnvGuard::new();
    let fake = AzureKeyVaultFake::start().await;
    fake.mock_secret_delayed("slow", "value", Duration::from_secs(5))
        .await;

    // Placeholder credentials so `AzureCredentials::new()` succeeds; they are
    // never exchanged because the delayed first response times out first.
    guard.set("AZURE_TENANT_ID", "00000000-0000-0000-0000-000000000000");
    guard.set("AZURE_CLIENT_ID", "00000000-0000-0000-0000-000000000001");
    guard.set("AZURE_CLIENT_SECRET", "placeholder-not-used");
    guard.set("FERRUM_SECRET_FETCH_TIMEOUT_SECONDS", "1");
    guard.set("FERRUM_ADMIN_JWT_SECRET_AZURE", fake.secret_url("slow"));

    let started = std::time::Instant::now();
    let err = resolve_all_env_secrets()
        .await
        .err()
        .expect("slow backend must time out");
    assert!(
        err.contains("Timeout"),
        "expected a timeout error, got: {err}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "resolution should give up at ~1s, not hang"
    );
}

/// Documents current behavior: a `/secrets/<name>/<version>` URL is accepted
/// but the version segment is ignored (the latest version is fetched). This is
/// explicit, not a silent drop — if versioned reads become supported, invert
/// this assertion.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn azure_versioned_url_behavior_is_documented() {
    let (vault_url, name) = azure_parse_keyvault_reference(
        "https://vault.example.net/secrets/admin-jwt/abc123version",
        KEY,
    )
    .expect("versioned URL should parse");
    assert_eq!(vault_url, "https://vault.example.net");
    // The version segment (`abc123version`) is intentionally dropped today.
    assert_eq!(name, "admin-jwt");
}
