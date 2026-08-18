//! Issue #3926 — database-mode admin read-your-write coordinator.
//!
//! These cover waiter coalescing, rejection, timeout, and the post-tick nudge
//! that prevents a consumed immediate permit from parking waiters on the
//! periodic poll interval. The coordinator never applies config itself.

use std::sync::Arc;
use std::time::Duration;

use ferrum_edge::config::runtime_config_apply::{LiveApplyFailure, RuntimeConfigApply};

#[tokio::test]
async fn already_accepted_sequence_returns_immediately() {
    let apply = RuntimeConfigApply::new("ferrum", 7);
    apply
        .await_committed(7)
        .await
        .expect("accepted generation must not wait");
    apply
        .await_committed(3)
        .await
        .expect("older sequences are already live");
}

#[tokio::test]
async fn record_accepted_unblocks_a_waiter() {
    let apply = Arc::new(RuntimeConfigApply::new("ferrum", 0));
    let waiter = apply.clone();
    let handle = tokio::spawn(async move { waiter.await_committed(4).await });
    tokio::task::yield_now().await;
    apply.record_accepted(4);
    handle
        .await
        .expect("waiter task")
        .expect("accepted sequence must unblock");
}

#[tokio::test]
async fn record_rejected_fails_waiters_through_that_sequence() {
    let apply = Arc::new(RuntimeConfigApply::new("ferrum", 0));
    let waiter = apply.clone();
    let handle = tokio::spawn(async move { waiter.await_committed(4).await });
    tokio::task::yield_now().await;
    apply.record_rejected(4);
    let err = handle.await.expect("waiter task").expect_err("rejected");
    assert_eq!(err, LiveApplyFailure::ConfigRejected);
    assert_eq!(err.as_str(), "config_rejected");
}

#[tokio::test]
async fn one_accepted_generation_unblocks_coalesced_waiters() {
    let apply = Arc::new(RuntimeConfigApply::new("ferrum", 0));
    let first = apply.clone();
    let second = apply.clone();
    let handle_a = tokio::spawn(async move { first.await_committed(1).await });
    let handle_b = tokio::spawn(async move { second.await_committed(2).await });
    tokio::task::yield_now().await;
    assert!(apply.waiter_count() >= 1);
    apply.record_accepted(2);
    handle_a
        .await
        .expect("first waiter")
        .expect("sequence 1 is covered by accepted 2");
    handle_b
        .await
        .expect("second waiter")
        .expect("sequence 2 is live");
}

#[tokio::test(start_paused = true)]
async fn await_committed_times_out_when_poll_never_publishes() {
    let apply = Arc::new(RuntimeConfigApply::with_timeout(
        "ferrum",
        0,
        Duration::from_secs(5),
    ));
    let waiter = apply.clone();
    let handle = tokio::spawn(async move { waiter.await_committed(1).await });
    tokio::time::sleep(Duration::from_secs(5)).await;
    let err = handle.await.expect("waiter task").expect_err("timeout");
    assert_eq!(err, LiveApplyFailure::Timeout);
    assert_eq!(err.as_str(), "reload_timeout");
}

#[tokio::test]
async fn nudge_signals_immediate_only_while_waiters_are_behind() {
    let apply = Arc::new(RuntimeConfigApply::new("ferrum", 0));
    apply.nudge_if_waiters_pending();
    assert!(
        !apply.wake_signal().take_immediate(),
        "no waiters means no immediate nudge"
    );

    let waiter = apply.clone();
    let handle = tokio::spawn(async move { waiter.await_committed(9).await });
    tokio::task::yield_now().await;
    assert!(apply.waiter_count() >= 1);
    // await_committed already raised immediate; consume it so the nudge is visible.
    let _ = apply.wake_signal().take_immediate();
    apply.nudge_if_waiters_pending();
    assert!(
        apply.wake_signal().take_immediate(),
        "pending waiters behind accepted must re-arm an immediate poll"
    );
    apply.record_accepted(9);
    handle
        .await
        .expect("waiter task")
        .expect("accepted after nudge");
}

#[test]
fn live_apply_failure_labels_are_closed() {
    assert_eq!(LiveApplyFailure::ConfigRejected.as_str(), "config_rejected");
    assert_eq!(LiveApplyFailure::Timeout.as_str(), "reload_timeout");
    assert_eq!(
        LiveApplyFailure::SequenceUnavailable.as_str(),
        "sequence_unavailable"
    );
}

#[test]
fn coordinator_is_namespace_scoped() {
    let apply = RuntimeConfigApply::new("ferrum", 0);
    assert!(apply.serves_namespace("ferrum"));
    assert!(!apply.serves_namespace("other"));
}
