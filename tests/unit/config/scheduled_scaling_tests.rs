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
    ADMIN_BATCH_REQUEST_TIMEOUT_SECS, BatchProvisionDecision,
    NAMESPACE_FENCE_DEFAULT_RETRY_AFTER_SECS, NAMESPACE_FENCE_MAX_ATTEMPTS,
    NAMESPACE_FENCE_MAX_BACKOFF_SECS, NAMESPACE_FENCE_MAX_RETRY_AFTER_SECS,
    NAMESPACE_FENCE_RETRY_MESSAGE, SCHEDULED_SCALING_ADMIN_JWT_TTL_SECS,
    classify_admin_batch_response, documented_namespace_fence_body, namespace_fence_backoff,
    namespace_fence_retry_after_delay, scheduled_scaling_admin_jwt_max_ttl_value,
};

const WORKFLOW: &str = include_str!("../../../.github/workflows/scaling-regression.yml");
const FRESHNESS: &str = include_str!("../../../.github/workflows/scaling-gate-freshness.yml");
const SIGNAL: &str = include_str!("../../../.github/scripts/publish_scaling_gate_signal.py");
const VERIFIER: &str =
    include_str!("../../../.github/scripts/verify_scaling_regression_workflow.py");
const SCALE: &str = include_str!("../../../tests/functional/functional_scale_perf_test.rs");
const LOAD: &str = include_str!("../../../tests/functional/functional_load_stress_test.rs");
const CI_CD: &str = include_str!("../../../docs/ci_cd.md");
const PUBLISHER_CONCURRENCY_GROUP: &str = "scaling-gate-publisher";

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
    assert_eq!(NAMESPACE_FENCE_MAX_ATTEMPTS, 10);
}

#[test]
fn namespace_fence_retries_back_off_past_the_servers_one_second_minimum() {
    // The gateway always answers the fence with `Retry-After: 1`, so a
    // header-only schedule would exhaust the whole attempt budget in about
    // five seconds — far shorter than the fenced windows observed in the red
    // scheduled-scaling runs this harness exists to survive (issue #3892).
    assert_eq!(
        namespace_fence_retry_after_delay(Some("1")),
        Duration::from_secs(1)
    );
    let mut schedule = Vec::new();
    for attempt in 1..NAMESPACE_FENCE_MAX_ATTEMPTS {
        let header = namespace_fence_retry_after_delay(Some("1"));
        let wait = header.max(namespace_fence_backoff(attempt));
        schedule.push(wait.as_secs());
    }
    assert_eq!(schedule, [1, 2, 4, 8, 16, 30, 30, 30, 30]);
    assert_eq!(
        namespace_fence_backoff(NAMESPACE_FENCE_MAX_ATTEMPTS).as_secs(),
        NAMESPACE_FENCE_MAX_BACKOFF_SECS,
        "backoff must saturate rather than grow without bound"
    );

    // The first exhausted body aborts provisioning, so this is the entire
    // added cost of a fence that never clears.
    let total: u64 = schedule.iter().sum();
    assert_eq!(total, 151);
    assert!(
        total < 180 * 60,
        "one atomic body's fence-retry budget must stay inside the job timeout"
    );
    assert!(
        total > 10 * NAMESPACE_FENCE_DEFAULT_RETRY_AFTER_SECS,
        "the retry budget must not collapse back onto the server's minimum"
    );
}

#[test]
fn atomic_admin_batches_have_a_bounded_timeout_without_transport_retries() {
    assert_eq!(ADMIN_BATCH_REQUEST_TIMEOUT_SECS, 5 * 60);
    let helper = include_str!("../../common/scheduled_scaling.rs");
    assert!(
        helper.contains(".timeout(Duration::from_secs(ADMIN_BATCH_REQUEST_TIMEOUT_SECS))"),
        "each admin batch request must override the shorter data-plane client timeout"
    );
    assert!(
        helper.contains("{operation} transport error: {err}"),
        "ambiguous transport failures must remain fatal instead of being retried"
    );
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
fn scaling_gate_publisher_jobs_preserve_queued_work() {
    assert!(
        VERIFIER.contains("PUBLISHER_CONCURRENCY_GROUP = \"scaling-gate-publisher\""),
        "verifier must pin the shared scaling-gate publisher concurrency group"
    );
    assert!(
        VERIFIER.contains("queue: max"),
        "verifier must pin queue: max so pending publishers are preserved"
    );
    for (workflow, job_name) in [
        (WORKFLOW, "scaling-gate-signal"),
        (FRESHNESS, "scaling-gate-freshness"),
    ] {
        let job_header = format!("  {job_name}:");
        let job = workflow
            .lines()
            .skip_while(|line| *line != job_header)
            .skip(1)
            .take_while(|line| line.trim().is_empty() || line.starts_with("    "))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!job.is_empty(), "missing {job_name} job body");
        assert!(
            job.contains("concurrency:")
                && job.contains(&format!("group: {PUBLISHER_CONCURRENCY_GROUP}"))
                && job.contains("cancel-in-progress: false")
                && job.contains("queue: max"),
            "{job_name} publisher job must queue pending scaling-gate publishers without canceling in-progress work"
        );
        assert!(
            !job.contains("cancel-in-progress: true"),
            "{job_name} must not combine queue: max with cancel-in-progress: true"
        );
    }
}

#[test]
fn scaling_gate_signal_is_generation_aware() {
    assert!(
        SIGNAL.contains("current_run_id == latest.run_id"),
        "weekly SCALING_JOB_RESULT may be authoritative only for the exact latest scaling-regression run"
    );
    assert!(
        SIGNAL.contains("latest_run_on_main(repo, token, now)"),
        "every live invocation must query the latest scaling-regression run on main"
    );
    assert!(
        SIGNAL.contains("parse_github_run_id"),
        "signal must bind GITHUB_RUN_ID before mutating issues"
    );
    assert!(
        !SIGNAL
            .split("def self_test")
            .next()
            .expect("production signal")
            .contains("GREEN_RESULTS | RED_RESULTS"),
        "weekly success/failure must not skip the latest-run query"
    );
    for label in [
        "stale older success over newer failure",
        "stale older failure over newer fresh success",
        "latest nonterminal",
        "missing current run identity",
        "malformed current run identity",
        "history API failure",
        "exact current run success",
        "exact current run failure",
        "numeric run-id is not generation order",
    ] {
        assert!(
            SIGNAL.contains(label),
            "signal self-test must cover {label}"
        );
    }
    assert!(
        VERIFIER.contains("stale older success over newer failure")
            && VERIFIER.contains("exact current run success")
            && VERIFIER.contains("queue: max"),
        "verifier must pin generation-aware and queue-preservation contracts"
    );
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
    // PR #4010 deleted the launch-readiness lane, so nothing consumes a
    // `launch-blocker` label any more; the signal issue carries severity only.
    assert!(SIGNAL.contains("severity:high"));
    assert!(!SIGNAL.contains("launch-blocker"));
    assert!(SIGNAL.contains("refs/heads/main"));
    assert!(VERIFIER.contains("verify_scaling_regression_workflow.py"));
    assert!(CI_CD.contains("scaling-gate-freshness.yml"));
}
