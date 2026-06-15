//! GCP Secret Manager functional tests against an in-process REST fake.
//!
//! The real `google-cloud-secretmanager-v1` client is pointed at the fake via
//! `FERRUM_GCP_SECRET_MANAGER_ENDPOINT` with anonymous credentials, so no ADC
//! or real GCP call ever happens. Tests drive the full
//! `resolve_all_env_secrets()` path.

use crate::common::env::{EnvGuard, assert_resolved_var};
use crate::common::fakes::GcpSecretManagerFake;
use ferrum_edge::secrets::resolve_all_env_secrets;
use serial_test::serial;
use std::time::Duration;

const RESOURCE_LATEST: &str = "projects/test-project/secrets/ferrum-admin/versions/latest";

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn gcp_latest_version_success() {
    let guard = EnvGuard::new();
    let fake = GcpSecretManagerFake::start().await;
    fake.mock_access_success(RESOURCE_LATEST, b"gcp-admin-jwt")
        .await;

    guard.set("FERRUM_GCP_SECRET_MANAGER_ENDPOINT", fake.endpoint());
    guard.set("FERRUM_ADMIN_JWT_SECRET_GCP", RESOURCE_LATEST);

    let result = resolve_all_env_secrets().await.expect("resolution failed");
    assert_resolved_var(&result, "FERRUM_ADMIN_JWT_SECRET", "gcp-admin-jwt");
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn gcp_numeric_version_success() {
    let resource = "projects/test-project/secrets/ferrum-admin/versions/3";
    let guard = EnvGuard::new();
    let fake = GcpSecretManagerFake::start().await;
    fake.mock_access_success(resource, b"gcp-v3-secret").await;

    guard.set("FERRUM_GCP_SECRET_MANAGER_ENDPOINT", fake.endpoint());
    guard.set("FERRUM_ADMIN_JWT_SECRET_GCP", resource);

    let result = resolve_all_env_secrets().await.expect("resolution failed");
    assert_resolved_var(&result, "FERRUM_ADMIN_JWT_SECRET", "gcp-v3-secret");
}

/// The configured resource name must be forwarded to the access endpoint
/// verbatim: `GET /v1/{name}:access`.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn gcp_reference_is_passed_exactly() {
    let guard = EnvGuard::new();
    let fake = GcpSecretManagerFake::start().await;
    fake.mock_access_success(RESOURCE_LATEST, b"value").await;

    guard.set("FERRUM_GCP_SECRET_MANAGER_ENDPOINT", fake.endpoint());
    guard.set("FERRUM_ADMIN_JWT_SECRET_GCP", RESOURCE_LATEST);

    resolve_all_env_secrets().await.expect("resolution failed");

    let paths = fake.recorded_paths().await;
    let expected = format!("/v1/{RESOURCE_LATEST}:access");
    assert!(
        paths.iter().any(|p| p.starts_with(&expected)),
        "client did not request the exact resource path; expected prefix {expected}, saw {paths:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn gcp_missing_payload_errors() {
    let guard = EnvGuard::new();
    let fake = GcpSecretManagerFake::start().await;
    fake.mock_access_no_payload(RESOURCE_LATEST).await;

    guard.set("FERRUM_GCP_SECRET_MANAGER_ENDPOINT", fake.endpoint());
    guard.set("FERRUM_ADMIN_JWT_SECRET_GCP", RESOURCE_LATEST);

    let err = resolve_all_env_secrets()
        .await
        .err()
        .expect("missing payload must fail");
    assert!(
        err.contains("no payload"),
        "expected a no-payload error, got: {err}"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn gcp_invalid_utf8_errors() {
    let guard = EnvGuard::new();
    let fake = GcpSecretManagerFake::start().await;
    fake.mock_access_invalid_utf8(RESOURCE_LATEST).await;

    guard.set("FERRUM_GCP_SECRET_MANAGER_ENDPOINT", fake.endpoint());
    guard.set("FERRUM_ADMIN_JWT_SECRET_GCP", RESOURCE_LATEST);

    let err = resolve_all_env_secrets()
        .await
        .err()
        .expect("invalid UTF-8 payload must fail");
    assert!(
        err.contains("not valid UTF-8"),
        "expected a UTF-8 error, got: {err}"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn gcp_not_found_errors() {
    let guard = EnvGuard::new();
    let fake = GcpSecretManagerFake::start().await;
    fake.mock_access_status(RESOURCE_LATEST, 404, "NOT_FOUND")
        .await;

    guard.set("FERRUM_GCP_SECRET_MANAGER_ENDPOINT", fake.endpoint());
    guard.set("FERRUM_ADMIN_JWT_SECRET_GCP", RESOURCE_LATEST);

    let err = resolve_all_env_secrets()
        .await
        .err()
        .expect("404 must fail");
    assert!(
        err.contains("Failed to access GCP secret"),
        "expected a GCP access failure, got: {err}"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn gcp_permission_denied_errors() {
    let guard = EnvGuard::new();
    let fake = GcpSecretManagerFake::start().await;
    fake.mock_access_status(RESOURCE_LATEST, 403, "PERMISSION_DENIED")
        .await;

    guard.set("FERRUM_GCP_SECRET_MANAGER_ENDPOINT", fake.endpoint());
    guard.set("FERRUM_ADMIN_JWT_SECRET_GCP", RESOURCE_LATEST);

    let err = resolve_all_env_secrets()
        .await
        .err()
        .expect("403 must fail");
    assert!(
        err.contains("Failed to access GCP secret"),
        "expected the provider failure to propagate, got: {err}"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn gcp_timeout_errors() {
    let guard = EnvGuard::new();
    let fake = GcpSecretManagerFake::start().await;
    fake.mock_access_delayed(RESOURCE_LATEST, b"too-slow", Duration::from_secs(5))
        .await;

    guard.set("FERRUM_GCP_SECRET_MANAGER_ENDPOINT", fake.endpoint());
    guard.set("FERRUM_SECRET_FETCH_TIMEOUT_SECONDS", "1");
    guard.set("FERRUM_ADMIN_JWT_SECRET_GCP", RESOURCE_LATEST);

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
