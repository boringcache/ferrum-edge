//! Static contracts for the scheduled scaling harness and gate signal (#3892).
//!
//! These pin the workflow-sized admin JWT policy, documented-only namespace-fence
//! batch retries, and the fail-closed scaling-gate notification without executing
//! the 10k/30k suites.

use std::time::Duration;

use serde_json::json;

#[path = "../../common/scheduled_scaling.rs"]
mod scheduled_scaling;

use scheduled_scaling::{
    BatchProvisionDecision, NAMESPACE_FENCE_DEFAULT_RETRY_AFTER_SECS, NAMESPACE_FENCE_MAX_ATTEMPTS,
    NAMESPACE_FENCE_MAX_RETRY_AFTER_SECS, NAMESPACE_FENCE_RETRY_MESSAGE,
    SCHEDULED_SCALING_ADMIN_JWT_TTL_SECS, classify_admin_batch_response,
    documented_namespace_fence_body, namespace_fence_retry_after_delay,
    scheduled_scaling_admin_jwt_max_ttl_value,
};

const WORKFLOW: &str = include_str!("../../../.github/workflows/scaling-regression.yml");
const FRESHNESS: &str = include_str!("../../../.github/workflows/scaling-gate-freshness.yml");
const SIGNAL: &str = include_str!("../../../.github/scripts/publish_scaling_gate_signal.py");
const VERIFIER: &str =
    include_str!("../../../.github/scripts/verify_scaling_regression_workflow.py");
const SCALE: &str = include_str!("../../../tests/functional/functional_scale_perf_test.rs");
const LOAD: &str = include_str!("../../../tests/functional/functional_load_stress_test.rs");
const CI_CD: &str = include_str!("../../../docs/ci_cd.md");

#[test]
fn admin_jwt_ttl_covers_the_180_minute_job_and_is_accepted_by_configured_max_ttl() {
    assert_eq!(SCHEDULED_SCALING_ADMIN_JWT_TTL_SECS, 4 * 60 * 60);
    const { assert!(SCHEDULED_SCALING_ADMIN_JWT_TTL_SECS >= 180 * 60) };
    assert_eq!(
        scheduled_scaling_admin_jwt_max_ttl_value(),
        SCHEDULED_SCALING_ADMIN_JWT_TTL_SECS.to_string()
    );
    assert!(
        SCALE.contains("FERRUM_ADMIN_JWT_MAX_TTL")
            && SCALE.contains("SCHEDULED_SCALING_ADMIN_JWT_TTL_SECS"),
        "scale harness must mint and accept the workflow-sized admin JWT"
    );
    assert!(
        LOAD.contains("FERRUM_ADMIN_JWT_MAX_TTL")
            && LOAD.contains("SCHEDULED_SCALING_ADMIN_JWT_TTL_SECS"),
        "load harness must mint and accept the workflow-sized admin JWT"
    );
}

#[test]
fn consumer_jwt_minting_stays_separate_from_the_admin_workflow_ttl() {
    assert!(
        LOAD.contains("fn generate_consumer_jwt"),
        "load harness must keep a dedicated consumer JWT helper"
    );
    let consumer_fn = LOAD
        .split("fn generate_consumer_jwt")
        .nth(1)
        .expect("consumer JWT helper")
        .split("fn ")
        .next()
        .expect("consumer JWT helper body");
    assert!(
        consumer_fn.contains("chrono::Duration::seconds(3600)"),
        "consumer JWTs must remain on the 1-hour mint path"
    );
    assert!(
        !consumer_fn.contains("SCHEDULED_SCALING_ADMIN_JWT_TTL_SECS"),
        "consumer JWT minting must not reuse the admin workflow TTL"
    );
}

#[test]
fn documented_namespace_fence_503_is_the_only_retried_batch_response() {
    let body = serde_json::to_string(&documented_namespace_fence_body()).expect("json");
    assert_eq!(
        classify_admin_batch_response(503, Some("1"), &body),
        BatchProvisionDecision::Retry {
            delay: Duration::from_secs(1)
        }
    );
    assert_eq!(
        classify_admin_batch_response(503, Some("99"), &body),
        BatchProvisionDecision::Retry {
            delay: Duration::from_secs(NAMESPACE_FENCE_MAX_RETRY_AFTER_SECS)
        }
    );
    assert_eq!(
        classify_admin_batch_response(201, None, "{}"),
        BatchProvisionDecision::Success
    );

    match classify_admin_batch_response(200, None, "") {
        BatchProvisionDecision::Fatal { status, .. } => assert_eq!(status, 200),
        other => panic!("undocumented 2xx statuses must be fatal, got {other:?}"),
    }

    let other_503 = json!({"error": "Service Unavailable"}).to_string();
    match classify_admin_batch_response(503, Some("1"), &other_503) {
        BatchProvisionDecision::Fatal { status, body } => {
            assert_eq!(status, 503);
            assert!(body.contains("Service Unavailable"));
        }
        other => panic!("other 503s must be fatal, got {other:?}"),
    }

    match classify_admin_batch_response(503, Some("1"), "retry later") {
        BatchProvisionDecision::Fatal { status, .. } => assert_eq!(status, 503),
        other => panic!("malformed 503 bodies must be fatal, got {other:?}"),
    }

    let fence_on_500 = serde_json::to_string(&documented_namespace_fence_body()).expect("json");
    match classify_admin_batch_response(500, Some("1"), &fence_on_500) {
        BatchProvisionDecision::Fatal { status, .. } => assert_eq!(status, 500),
        other => panic!("non-503 statuses must be fatal, got {other:?}"),
    }

    match classify_admin_batch_response(207, None, "{\"accepted\":1}") {
        BatchProvisionDecision::Fatal { status, .. } => assert_eq!(status, 207),
        other => panic!("partial-success statuses must be fatal, got {other:?}"),
    }

    assert_eq!(
        NAMESPACE_FENCE_RETRY_MESSAGE,
        "Namespace mutation is temporarily unavailable; retry later"
    );
    assert_eq!(NAMESPACE_FENCE_MAX_ATTEMPTS, 6);
}

#[test]
fn documented_namespace_fence_error_plus_extra_field_is_fatal() {
    let extra = json!({
        "error": NAMESPACE_FENCE_RETRY_MESSAGE,
        "retry": true
    })
    .to_string();
    match classify_admin_batch_response(503, Some("1"), &extra) {
        BatchProvisionDecision::Fatal { status, body } => {
            assert_eq!(status, 503);
            assert!(body.contains("retry"));
        }
        other => panic!("documented error plus an extra field must be fatal, got {other:?}"),
    }
}

#[test]
fn retry_after_honors_delay_seconds_with_a_bounded_default() {
    assert_eq!(
        namespace_fence_retry_after_delay(None),
        Duration::from_secs(NAMESPACE_FENCE_DEFAULT_RETRY_AFTER_SECS)
    );
    assert_eq!(
        namespace_fence_retry_after_delay(Some("2")),
        Duration::from_secs(2)
    );
    assert_eq!(
        namespace_fence_retry_after_delay(Some("0")),
        Duration::from_secs(NAMESPACE_FENCE_DEFAULT_RETRY_AFTER_SECS)
    );
    assert_eq!(
        namespace_fence_retry_after_delay(Some("99")),
        Duration::from_secs(NAMESPACE_FENCE_MAX_RETRY_AFTER_SECS)
    );
    assert_eq!(
        namespace_fence_retry_after_delay(Some("Wed, 21 Oct 2015 07:28:00 GMT")),
        Duration::from_secs(NAMESPACE_FENCE_DEFAULT_RETRY_AFTER_SECS)
    );
}

#[test]
fn both_harnesses_route_every_batch_phase_through_the_shared_helper() {
    assert_eq!(SCALE.matches("post_admin_batch(").count(), 3);
    assert_eq!(LOAD.matches("post_admin_batch(").count(), 4);
    assert!(
        !SCALE.contains(".post(format!(\"{}/batch\"")
            && !LOAD.contains(".post(format!(\"{}/batch\""),
        "neither harness may POST /batch outside the shared helper"
    );
}

#[test]
fn scheduled_scaling_workflow_keeps_the_180_minute_matrix_and_signal_job() {
    assert!(WORKFLOW.contains("timeout-minutes: 180"));
    assert!(WORKFLOW.contains("cron: \"0 4 * * 6\""));
    assert!(WORKFLOW.contains("  scaling-gate-signal:"));
    assert!(WORKFLOW.contains("issues: write"));
    assert!(WORKFLOW.contains("actions: read"));
    assert!(WORKFLOW.contains("if: always()"));
    assert!(WORKFLOW.contains("publish_scaling_gate_signal.py"));
    assert!(WORKFLOW.contains("verify_scaling_regression_workflow.py --self-test"));
    assert!(!WORKFLOW.contains("pull_request:"));
    assert!(!WORKFLOW.contains("LAUNCH_ADVISORY_READ_TOKEN"));
    assert!(!WORKFLOW.contains("Launch Readiness Gate"));
    assert!(!WORKFLOW.contains("contents: write"));
}

#[test]
fn freshness_workflow_is_fail_closed_and_does_not_run_the_suites() {
    assert!(FRESHNESS.contains("cron: \"0 12 * * *\""));
    assert!(FRESHNESS.contains("publish_scaling_gate_signal.py"));
    assert!(FRESHNESS.contains("issues: write"));
    assert!(FRESHNESS.contains("actions: read"));
    assert!(!FRESHNESS.contains("cargo test"));
    assert!(!FRESHNESS.contains("cargo build"));
    assert!(!FRESHNESS.contains("pull_request:"));
    assert!(!FRESHNESS.contains("LAUNCH_ADVISORY_READ_TOKEN"));
    assert!(!FRESHNESS.contains("Launch Readiness Gate"));
    assert!(SIGNAL.contains("MAX_AGE_SECONDS = 8 * 24 * 60 * 60"));
    assert!(SIGNAL.contains("launch-blocker"));
    assert!(SIGNAL.contains("refs/heads/main"));
    assert!(VERIFIER.contains("verify_scaling_regression_workflow.py"));
    assert!(CI_CD.contains("scaling-gate-freshness.yml"));
}
