//! Kubernetes status-write budgets on the serialized reconcile loop (#4239).
//!
//! The Gateway API conformance suite waits 60s for an HTTPRoute's parent status.
//! Before these budgets the controller's status patch batch was bounded only by
//! a single 60s whole-batch timeout with unbounded requests inside it, so one
//! stalled Kubernetes status write held the reconcile loop for exactly as long
//! as the suite was willing to wait — and whichever route happened to be created
//! in that window failed, on an arbitrary test.
//!
//! These tests inject the stall directly (a request future that never resolves)
//! and run on tokio's paused clock, so they assert the release without sleeping.

use std::future::pending;
use std::sync::atomic::Ordering;
use std::time::Duration;

use ferrum_edge::k8s_controller::metrics::ControllerMetrics;
use ferrum_edge::k8s_controller::status_budget::{
    STATUS_BATCH_BACKSTOP, STATUS_BATCH_BUDGET, STATUS_BATCH_SLOW_WARN, STATUS_REQUEST_BUDGET,
    STATUS_UPDATE_BUDGET, StatusOperation, await_status_operation, is_status_timeout_error,
    status_operation_budget, status_timeout_error,
};
use tokio::time::Instant;

/// The suite's own parent-status wait. A budget at or above this reproduces the
/// original defect exactly, because the reconcile loop is then allowed to stay
/// blocked for the entire time the observer is willing to wait.
const CONFORMANCE_PARENT_STATUS_WAIT: Duration = Duration::from_secs(60);

fn operation() -> StatusOperation<'static> {
    StatusOperation {
        phase: "patch",
        kind: "HTTPRoute",
        namespace: "gateway-conformance-infra",
        name: "invalid-backend-ref-unknown-kind",
    }
}

#[test]
fn status_budgets_stay_below_the_conformance_parent_status_wait() {
    assert!(
        STATUS_REQUEST_BUDGET <= STATUS_UPDATE_BUDGET,
        "one request may never outlast the object it belongs to"
    );
    assert!(
        STATUS_UPDATE_BUDGET <= STATUS_BATCH_BUDGET,
        "one object may never outlast the batch holding the reconcile loop"
    );
    assert!(
        STATUS_BATCH_BUDGET < STATUS_BATCH_BACKSTOP,
        "the defensive backstop must be reachable only after the batch's own budget"
    );
    assert!(
        STATUS_BATCH_BACKSTOP < CONFORMANCE_PARENT_STATUS_WAIT,
        "a stalled status write must never hold the reconcile loop for the observer's whole wait"
    );
    assert!(
        STATUS_BATCH_SLOW_WARN < STATUS_BATCH_BUDGET,
        "a slow batch must be reported before it is abandoned"
    );
}

#[test]
fn operation_budget_is_clamped_by_the_batch_deadline() {
    let now = Instant::now();

    // Plenty of batch budget left: the per-operation budget governs.
    assert_eq!(
        status_operation_budget(now, now + Duration::from_secs(30), Duration::from_secs(5)),
        Some(Duration::from_secs(5))
    );

    // Batch nearly spent: the operation may not overrun it.
    assert_eq!(
        status_operation_budget(now, now + Duration::from_millis(400), Duration::from_secs(5)),
        Some(Duration::from_millis(400))
    );

    // Batch spent: refuse rather than issue a request that cannot finish.
    assert_eq!(
        status_operation_budget(now, now, Duration::from_secs(5)),
        None
    );
    assert_eq!(
        status_operation_budget(now, now - Duration::from_secs(1), Duration::from_secs(5)),
        None
    );
}

#[test]
fn a_budget_expiry_is_a_gateway_timeout_and_never_a_conflict() {
    let error = status_timeout_error(operation(), Some(Duration::from_secs(5)));

    assert!(is_status_timeout_error(&error));
    match &error {
        kube::Error::Api(status) => {
            assert_eq!(status.code, 504);
            assert_eq!(status.reason, "Timeout");
            assert!(
                status.message.contains("invalid-backend-ref-unknown-kind"),
                "the error must name the object so the batch does not lose the evidence: {}",
                status.message
            );
        }
        other => panic!("expected an API status error, got {other:?}"),
    }
}

#[tokio::test(start_paused = true)]
async fn a_stalled_status_request_releases_the_reconcile_loop_within_its_budget() {
    let metrics = ControllerMetrics::new();
    let started = Instant::now();
    let deadline = started + STATUS_BATCH_BUDGET;

    let result: Result<(), kube::Error> = await_status_operation(
        operation(),
        deadline,
        STATUS_REQUEST_BUDGET,
        Some(&metrics),
        pending::<Result<(), kube::Error>>(),
    )
    .await;

    let error = result.expect_err("a request that never resolves must not be awaited forever");
    assert!(is_status_timeout_error(&error));
    let elapsed = started.elapsed();
    assert!(
        elapsed >= STATUS_REQUEST_BUDGET && elapsed < STATUS_BATCH_BUDGET,
        "the loop must be released after one request budget, not the batch budget: {elapsed:?}"
    );
    assert_eq!(metrics.status_request_timeouts.load(Ordering::Relaxed), 1);
}

#[tokio::test(start_paused = true)]
async fn a_stalled_request_never_overruns_the_batch_deadline() {
    let metrics = ControllerMetrics::new();
    let started = Instant::now();
    // Less batch budget left than one request budget.
    let deadline = started + Duration::from_millis(250);

    let result: Result<(), kube::Error> = await_status_operation(
        operation(),
        deadline,
        STATUS_REQUEST_BUDGET,
        Some(&metrics),
        pending::<Result<(), kube::Error>>(),
    )
    .await;

    assert!(is_status_timeout_error(
        &result.expect_err("the stalled request must be abandoned")
    ));
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(250) && elapsed < STATUS_REQUEST_BUDGET,
        "an operation must not extend the batch that holds the reconcile loop: {elapsed:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn a_spent_batch_refuses_further_requests_without_waiting() {
    let metrics = ControllerMetrics::new();
    let started = Instant::now();

    let result: Result<(), kube::Error> = await_status_operation(
        operation(),
        started,
        STATUS_REQUEST_BUDGET,
        Some(&metrics),
        pending::<Result<(), kube::Error>>(),
    )
    .await;

    assert!(is_status_timeout_error(
        &result.expect_err("a spent batch must refuse, not issue an unbounded request")
    ));
    assert_eq!(
        started.elapsed(),
        Duration::ZERO,
        "a spent batch must refuse immediately"
    );
    assert_eq!(metrics.status_request_timeouts.load(Ordering::Relaxed), 1);
}

#[tokio::test(start_paused = true)]
async fn a_request_that_finishes_inside_its_budget_is_passed_through_untouched() {
    let metrics = ControllerMetrics::new();
    let started = Instant::now();
    let deadline = started + STATUS_BATCH_BUDGET;

    let result = await_status_operation(
        operation(),
        deadline,
        STATUS_REQUEST_BUDGET,
        Some(&metrics),
        async {
            tokio::time::sleep(Duration::from_millis(20)).await;
            Ok::<&str, kube::Error>("published")
        },
    )
    .await;

    assert_eq!(
        result.expect("the request completed inside its budget"),
        "published"
    );
    assert_eq!(
        metrics.status_request_timeouts.load(Ordering::Relaxed),
        0,
        "a healthy status write must not be counted as a budget expiry"
    );
}

#[tokio::test(start_paused = true)]
async fn a_stalled_object_does_not_stop_the_rest_of_the_batch() {
    // The failure this reproduces: one object's status write stalls, and every
    // other object in the same reconcile silently loses its publication window.
    let metrics = ControllerMetrics::new();
    let started = Instant::now();
    let deadline = started + STATUS_BATCH_BUDGET;

    let stalled = await_status_operation(
        operation(),
        deadline,
        STATUS_REQUEST_BUDGET,
        Some(&metrics),
        pending::<Result<&str, kube::Error>>(),
    );
    let healthy = await_status_operation(
        StatusOperation {
            phase: "patch",
            kind: "HTTPRoute",
            namespace: "gateway-conformance-infra",
            name: "invalid-cross-namespace-backend-ref",
        },
        deadline,
        STATUS_REQUEST_BUDGET,
        Some(&metrics),
        async { Ok::<&str, kube::Error>("published") },
    );

    let (stalled, healthy) = tokio::join!(stalled, healthy);

    assert!(is_status_timeout_error(
        &stalled.expect_err("the stalled object is abandoned")
    ));
    assert_eq!(
        healthy.expect("the healthy object still publishes"),
        "published"
    );
    assert_eq!(metrics.status_request_timeouts.load(Ordering::Relaxed), 1);
    assert!(
        started.elapsed() <= STATUS_REQUEST_BUDGET,
        "the batch must not outlast its slowest bounded request"
    );
}
