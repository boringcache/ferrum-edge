//! Kubernetes controller shutdown supervision (issue #3220).
//!
//! CP mode used to keep the controller handle in an underscore-prefixed local
//! and drop it at the end of `run()`, which *detaches* the watcher, reconciler,
//! and CRD reprobe tasks instead of awaiting them; the old `join()` also threw
//! away every `JoinError`. These tests drive the real
//! `K8sControllerHandle::shutdown` path with synthetic tasks (no Kubernetes API
//! server required) and assert the four terminal dispositions: clean exit after
//! a delay, panic propagation, grace-deadline abort with a confirmed
//! termination, and exit-before-shutdown under the *real* control-plane
//! ordering (global shutdown watch already `true` when teardown begins).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use ferrum_edge::_test_support::k8s_controller_handle_for_test;
use tokio::sync::watch;

/// Spin the scheduler enough times for the just-spawned per-task supervisors to
/// reach their first `await` on the underlying `JoinHandle` and record the
/// shutdown state at the completion boundary.
async fn settle_supervisors() {
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
}

/// A task that takes time to unwind after observing shutdown must be awaited,
/// not detached: `shutdown()` may not return before the task has exited.
#[tokio::test]
async fn shutdown_awaits_task_that_exits_after_a_delay() {
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let exited = Arc::new(AtomicBool::new(false));

    let task_exited = exited.clone();
    let handle = tokio::spawn(async move {
        while !*shutdown_rx.borrow() {
            if shutdown_rx.changed().await.is_err() {
                break;
            }
        }
        // Simulate a watcher finishing an in-flight status write before it
        // returns. A detached task would still be here when the caller moved on.
        tokio::time::sleep(Duration::from_millis(150)).await;
        task_exited.store(true, Ordering::SeqCst);
    });

    let controller = k8s_controller_handle_for_test(
        vec![("crd-watcher-0".to_string(), handle)],
        shutdown_tx.subscribe(),
    );
    let outcome = controller
        .shutdown(&shutdown_tx, Duration::from_secs(5))
        .await;

    assert!(
        exited.load(Ordering::SeqCst),
        "shutdown() returned before the controller task finished"
    );
    assert!(outcome.is_clean(), "unexpected outcome: {outcome:?}");
    assert_eq!(outcome.completed, vec!["crd-watcher-0".to_string()]);
    assert!(outcome.failure_error().is_none());
    // shutdown() owns the signalling, so the channel is closed out even when
    // the caller had not already fired it.
    assert!(*shutdown_tx.borrow());
}

/// A panicking controller task must be reported, not silently discarded the way
/// the old `let _ = handle.await` did.
#[tokio::test]
async fn shutdown_surfaces_a_panicked_controller_task() {
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

    let clean = tokio::spawn({
        let mut rx = shutdown_tx.subscribe();
        async move {
            while !*rx.borrow() {
                if rx.changed().await.is_err() {
                    break;
                }
            }
        }
    });
    let panicking = tokio::spawn(async move {
        while !*shutdown_rx.borrow() {
            if shutdown_rx.changed().await.is_err() {
                break;
            }
        }
        panic!("reconciler blew up during shutdown");
    });

    let controller = k8s_controller_handle_for_test(
        vec![
            ("crd-watcher-0".to_string(), clean),
            ("reconciler".to_string(), panicking),
        ],
        shutdown_tx.subscribe(),
    );
    let outcome = controller
        .shutdown(&shutdown_tx, Duration::from_secs(5))
        .await;

    assert!(!outcome.is_clean(), "panic was reported as a clean exit");
    assert_eq!(outcome.failed.len(), 1, "unexpected outcome: {outcome:?}");
    assert_eq!(outcome.failed[0].task, "reconciler");
    assert!(outcome.failed[0].panicked);
    // The sibling is still awaited rather than short-circuited by the panic.
    assert_eq!(outcome.completed, vec!["crd-watcher-0".to_string()]);
    assert!(outcome.timed_out.is_empty());
    assert!(outcome.abort_unconfirmed.is_empty());
    assert!(outcome.exited_before_shutdown.is_empty());

    let err = outcome
        .failure_error()
        .expect("panicked task must produce an error for run() to propagate");
    assert!(err.to_string().contains("reconciler"), "error: {err}");
}

/// A task that ignores shutdown is bounded by the grace period and then
/// *aborted*, and the abort is settled before `shutdown()` returns. Dropping
/// its `JoinHandle` instead would detach it, so the test asserts the task's
/// future was already dropped by the time the call returned — no polling.
#[tokio::test]
async fn shutdown_aborts_a_task_still_running_at_the_grace_deadline() {
    struct DropFlag(Arc<AtomicBool>);
    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    let (shutdown_tx, _shutdown_rx) = watch::channel(false);
    let dropped = Arc::new(AtomicBool::new(false));

    let flag = dropped.clone();
    let handle = tokio::spawn(async move {
        let _guard = DropFlag(flag);
        // Deliberately never observes the shutdown channel.
        loop {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    });

    let controller = k8s_controller_handle_for_test(
        vec![("crd-reprobe".to_string(), handle)],
        shutdown_tx.subscribe(),
    );
    let outcome = controller
        .shutdown(&shutdown_tx, Duration::from_millis(150))
        .await;

    assert_eq!(outcome.timed_out, vec!["crd-reprobe".to_string()]);
    assert!(!outcome.is_clean());
    // A stuck task is an operational warning, not a process-failing defect.
    assert!(outcome.failure_error().is_none());
    assert!(outcome.failed.is_empty(), "unexpected: {outcome:?}");
    assert!(outcome.exited_before_shutdown.is_empty());
    // The abort-settle phase joined the aborted task, so its termination is an
    // established happens-before boundary rather than a hope.
    assert!(
        outcome.abort_unconfirmed.is_empty(),
        "abort should have settled well inside the budget: {outcome:?}"
    );
    assert!(
        dropped.load(Ordering::SeqCst),
        "timed-out controller task was detached instead of aborted and joined"
    );
}

/// A controller task that stopped during normal operation means part of the
/// controller quietly stopped reconciling. It must stay classified as an early
/// exit — and fail the process — even though CP mode reaches controller
/// teardown only *after* the global shutdown watch has already been set to
/// `true`, which is the ordering reproduced here.
#[tokio::test]
async fn shutdown_reports_a_task_that_exited_before_shutdown_even_when_the_watch_is_already_set() {
    let (shutdown_tx, _shutdown_rx) = watch::channel(false);

    let early = tokio::spawn(async {});
    for _ in 0..200 {
        if early.is_finished() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(early.is_finished(), "synthetic early task never finished");

    let still_running = tokio::spawn({
        let mut rx = shutdown_tx.subscribe();
        async move {
            while !*rx.borrow() {
                if rx.changed().await.is_err() {
                    break;
                }
            }
        }
    });

    // The handle is built while the controller is still running normally,
    // exactly as `start_k8s_controller` builds it — that is when the
    // supervisors latch each task's completion boundary.
    let controller = k8s_controller_handle_for_test(
        vec![
            ("crd-watcher-0".to_string(), early),
            ("reconciler".to_string(), still_running),
        ],
        shutdown_tx.subscribe(),
    );
    settle_supervisors().await;

    // Real CP order: the listener wait observes/fires the global shutdown watch
    // long before the controller handle is torn down. A pre-send
    // `is_finished()` scan is blind here; only the completion-boundary record
    // still knows the watcher had already stopped reconciling.
    shutdown_tx
        .send(true)
        .expect("watch receivers are still alive");

    let outcome = controller
        .shutdown(&shutdown_tx, Duration::from_secs(5))
        .await;

    assert_eq!(
        outcome.exited_before_shutdown,
        vec!["crd-watcher-0".to_string()],
        "unexpected outcome: {outcome:?}"
    );
    assert!(!outcome.is_clean());
    assert!(outcome.failed.is_empty());
    assert!(outcome.timed_out.is_empty());
    assert!(outcome.abort_unconfirmed.is_empty());
    // The task that was still running when shutdown fired is the only clean
    // completion; the early exit is not double-counted as one.
    assert_eq!(outcome.completed, vec!["reconciler".to_string()]);

    // A silently dead controller is degraded service, so it fails the process
    // rather than only logging a warning.
    let err = outcome
        .failure_error()
        .expect("an early controller exit must fail the process");
    assert!(
        err.to_string().contains("crd-watcher-0"),
        "error should name the dead task: {err}"
    );
}
