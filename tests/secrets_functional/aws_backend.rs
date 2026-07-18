//! AWS Secrets Manager functional tests against LocalStack.
//!
//! Connectivity tests run against LocalStack (Secrets Manager) started in
//! Docker via testcontainers, pointed at by `AWS_ENDPOINT_URL_SECRETS_MANAGER`.
//! When LocalStack is unavailable they FAIL in CI (where Docker is required)
//! and skip with a printed notice locally. The timeout test needs no Docker (it
//! uses an in-process delaying endpoint).

use crate::common::containers::{
    LocalStackContainer, fail_in_ci_else_skip, start_localstack_for_aws_secretsmanager,
};
use crate::common::env::{EnvGuard, assert_resolved_var};
use ferrum_edge::secrets::resolve_all_env_secrets;
use serial_test::serial;
use std::time::Duration;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

const JSON_SECRET: &str = r#"{"admin_jwt":"aws-json-jwt","port":5432,"enabled":true}"#;

/// Standard LocalStack-friendly AWS env (dummy static credentials + endpoint).
///
/// Both the service-specific (`AWS_ENDPOINT_URL_SECRETS_MANAGER`, the primary
/// override the production code relies on) and the global (`AWS_ENDPOINT_URL`)
/// endpoint vars are set to the local fake/emulator. The global var is a safety
/// net so a request can never escape to real AWS even if the SDK were to ignore
/// the service-specific one.
fn set_aws_env(guard: &EnvGuard, endpoint: &str) {
    guard.set("AWS_REGION", "us-east-1");
    guard.set("AWS_DEFAULT_REGION", "us-east-1");
    guard.set("AWS_ACCESS_KEY_ID", "test");
    guard.set("AWS_SECRET_ACCESS_KEY", "test");
    guard.set("AWS_ENDPOINT_URL_SECRETS_MANAGER", endpoint);
    guard.set("AWS_ENDPOINT_URL", endpoint);
}

/// Start LocalStack. Fails the test in CI and skips it locally when the
/// container is unavailable.
async fn try_localstack(test: &str) -> Option<LocalStackContainer> {
    match start_localstack_for_aws_secretsmanager().await {
        Ok(ls) => Some(ls),
        Err(e) => {
            fail_in_ci_else_skip(test, "LocalStack", &e);
            None
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn aws_plain_secret_by_name_success() {
    let guard = EnvGuard::new();
    let Some(ls) = try_localstack("aws_plain_secret_by_name_success").await else {
        return;
    };
    ls.create_secret_string("ferrum/plain", "aws-plain-secret")
        .await
        .expect("seed plain secret");

    set_aws_env(&guard, &ls.endpoint);
    guard.set("FERRUM_ADMIN_JWT_SECRET_AWS", "ferrum/plain");

    let result = resolve_all_env_secrets().await.expect("resolution failed");
    assert_resolved_var(&result, "FERRUM_ADMIN_JWT_SECRET", "aws-plain-secret");
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn aws_json_field_by_name_success() {
    let guard = EnvGuard::new();
    let Some(ls) = try_localstack("aws_json_field_by_name_success").await else {
        return;
    };
    ls.create_secret_string("ferrum/json", JSON_SECRET)
        .await
        .expect("seed json secret");

    set_aws_env(&guard, &ls.endpoint);
    guard.set("FERRUM_ADMIN_JWT_SECRET_AWS", "ferrum/json#admin_jwt");

    let result = resolve_all_env_secrets().await.expect("resolution failed");
    assert_resolved_var(&result, "FERRUM_ADMIN_JWT_SECRET", "aws-json-jwt");
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn aws_json_number_field_success() {
    let guard = EnvGuard::new();
    let Some(ls) = try_localstack("aws_json_number_field_success").await else {
        return;
    };
    ls.create_secret_string("ferrum/json", JSON_SECRET)
        .await
        .expect("seed json secret");

    set_aws_env(&guard, &ls.endpoint);
    // Numeric JSON values are stringified.
    guard.set("FERRUM_DB_PORT_AWS", "ferrum/json#port");

    let result = resolve_all_env_secrets().await.expect("resolution failed");
    assert_resolved_var(&result, "FERRUM_DB_PORT", "5432");
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn aws_json_bool_field_success() {
    let guard = EnvGuard::new();
    let Some(ls) = try_localstack("aws_json_bool_field_success").await else {
        return;
    };
    ls.create_secret_string("ferrum/json", JSON_SECRET)
        .await
        .expect("seed json secret");

    set_aws_env(&guard, &ls.endpoint);
    guard.set("FERRUM_FEATURE_ENABLED_AWS", "ferrum/json#enabled");

    let result = resolve_all_env_secrets().await.expect("resolution failed");
    assert_resolved_var(&result, "FERRUM_FEATURE_ENABLED", "true");
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn aws_secret_by_arn_success() {
    let guard = EnvGuard::new();
    let Some(ls) = try_localstack("aws_secret_by_arn_success").await else {
        return;
    };
    let arn = ls
        .create_secret_string("ferrum/json", JSON_SECRET)
        .await
        .expect("seed json secret");

    set_aws_env(&guard, &ls.endpoint);
    guard.set("FERRUM_ADMIN_JWT_SECRET_AWS", format!("{arn}#admin_jwt"));

    let result = resolve_all_env_secrets().await.expect("resolution failed");
    assert_resolved_var(&result, "FERRUM_ADMIN_JWT_SECRET", "aws-json-jwt");
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn aws_missing_json_field_errors() {
    let guard = EnvGuard::new();
    let Some(ls) = try_localstack("aws_missing_json_field_errors").await else {
        return;
    };
    ls.create_secret_string("ferrum/json", JSON_SECRET)
        .await
        .expect("seed json secret");

    set_aws_env(&guard, &ls.endpoint);
    // A distinctive absent field name, so the absence assertion below cannot
    // pass by accident on a common English word.
    const ABSENT_FIELD: &str = "ferrum-absent-json-field-sentinel";
    guard.set(
        "FERRUM_ADMIN_JWT_SECRET_AWS",
        &format!("ferrum/json#{ABSENT_FIELD}"),
    );

    let err = resolve_all_env_secrets()
        .await
        .err()
        .expect("missing JSON field must fail");
    // The failure class and the base key are the actionable parts and are kept.
    assert!(
        err.contains("does not contain the requested key")
            && err.contains("FERRUM_ADMIN_JWT_SECRET"),
        "error must stay actionable at base-key + failure-class level, got: {err}"
    );
    // The requested JSON field and the secret id are both parts of the source
    // reference, which is as sensitive as the value it points at. Naming the
    // field would also confirm which keys a secret does *not* have to anyone
    // who can read startup output.
    assert!(
        !err.contains(ABSENT_FIELD) && !err.contains("ferrum/json"),
        "error must not disclose the source reference or requested field, got: {err}"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn aws_invalid_json_with_field_errors() {
    let guard = EnvGuard::new();
    let Some(ls) = try_localstack("aws_invalid_json_with_field_errors").await else {
        return;
    };
    ls.create_secret_string("ferrum/plain", "aws-plain-secret")
        .await
        .expect("seed plain secret");

    set_aws_env(&guard, &ls.endpoint);
    // Requesting a #field on a non-JSON secret must fail clearly.
    guard.set("FERRUM_ADMIN_JWT_SECRET_AWS", "ferrum/plain#admin_jwt");

    let err = resolve_all_env_secrets()
        .await
        .err()
        .expect("non-JSON secret with #field must fail");
    assert!(
        err.contains("not valid JSON"),
        "expected a JSON parse error, got: {err}"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn aws_binary_secret_errors() {
    let guard = EnvGuard::new();
    let Some(ls) = try_localstack("aws_binary_secret_errors").await else {
        return;
    };
    ls.create_secret_binary("ferrum/binary", &[0x00, 0x01, 0x02, 0xff])
        .await
        .expect("seed binary secret");

    set_aws_env(&guard, &ls.endpoint);
    guard.set("FERRUM_ADMIN_JWT_SECRET_AWS", "ferrum/binary");

    let err = resolve_all_env_secrets()
        .await
        .err()
        .expect("binary-only secret must fail");
    assert!(
        err.contains("binary"),
        "expected a binary-secret error, got: {err}"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn aws_not_found_errors() {
    let guard = EnvGuard::new();
    let Some(ls) = try_localstack("aws_not_found_errors").await else {
        return;
    };

    set_aws_env(&guard, &ls.endpoint);
    guard.set("FERRUM_ADMIN_JWT_SECRET_AWS", "ferrum/missing");

    let err = resolve_all_env_secrets()
        .await
        .err()
        .expect("unknown secret must fail");
    assert!(
        err.contains("Failed to fetch") && err.contains("AWS Secrets Manager"),
        "expected an AWS fetch failure, got: {err}"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn aws_batch_multiple_secrets_success() {
    let guard = EnvGuard::new();
    let Some(ls) = try_localstack("aws_batch_multiple_secrets_success").await else {
        return;
    };
    ls.create_secret_string("ferrum/plain", "aws-plain-secret")
        .await
        .expect("seed plain secret");
    ls.create_secret_string("ferrum/json", JSON_SECRET)
        .await
        .expect("seed json secret");

    set_aws_env(&guard, &ls.endpoint);
    guard.set("FERRUM_ADMIN_JWT_SECRET_AWS", "ferrum/json#admin_jwt");
    guard.set("FERRUM_DB_URL_AWS", "ferrum/plain");

    let result = resolve_all_env_secrets().await.expect("resolution failed");
    assert_resolved_var(&result, "FERRUM_ADMIN_JWT_SECRET", "aws-json-jwt");
    assert_resolved_var(&result, "FERRUM_DB_URL", "aws-plain-secret");
}

/// No Docker required — a slow endpoint trips the fetch timeout without
/// hanging. The registry wraps every fetch in `FERRUM_SECRET_FETCH_TIMEOUT_SECONDS`,
/// so even the AWS SDK's own retries cannot outlast it.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn aws_timeout_errors() {
    let guard = EnvGuard::new();
    let slow = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
        .mount(&slow)
        .await;

    set_aws_env(&guard, &slow.uri());
    guard.set("FERRUM_SECRET_FETCH_TIMEOUT_SECONDS", "1");
    guard.set("FERRUM_ADMIN_JWT_SECRET_AWS", "ferrum/slow");

    let started = std::time::Instant::now();
    let err = resolve_all_env_secrets()
        .await
        .err()
        .expect("slow AWS endpoint must time out");
    assert!(
        err.contains("Timeout"),
        "expected a timeout error, got: {err}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "resolution should give up at ~1s, not hang"
    );
}
