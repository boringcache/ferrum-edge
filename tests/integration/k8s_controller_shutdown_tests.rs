//! Kubernetes controller shutdown supervision (issue #3220).
//!
//! CP mode used to keep the controller handle in an underscore-prefixed local
//! and drop it at the end of `run()`, which *detaches* the watcher, reconciler,
//! and CRD reprobe tasks instead of awaiting them; the old `join()` also threw
//! away every `JoinError`. These tests drive the real
//! `K8sControllerHandle::shutdown` path with synthetic tasks (no Kubernetes API
//! server required) and assert the four terminal dispositions: clean exit after
//! a delay, panic propagation, grace-deadline abort, and exit-before-shutdown.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use ferrum_edge::_test_support::k8s_controller_handle_for_test;
use tokio::sync::watch;

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

    let controller = k8s_controller_handle_for_test(vec![("crd-watcher-0".to_string(), handle)]);
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

    let controller = k8s_controller_handle_for_test(vec![
        ("crd-watcher-0".to_string(), clean),
        ("reconciler".to_string(), panicking),
    ]);
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

    let err = outcome
        .failure_error()
        .expect("panicked task must produce an error for run() to propagate");
    assert!(err.to_string().contains("reconciler"), "error: {err}");
}

/// A task that ignores shutdown is bounded by the grace period and then
/// *aborted*. Dropping its `JoinHandle` instead would detach it, so the test
/// asserts the task's future was actually dropped.
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

    let controller = k8s_controller_handle_for_test(vec![("crd-reprobe".to_string(), handle)]);
    let outcome = controller
        .shutdown(&shutdown_tx, Duration::from_millis(150))
        .await;

    assert_eq!(outcome.timed_out, vec!["crd-reprobe".to_string()]);
    assert!(!outcome.is_clean());
    // A stuck task is an operational warning, not a process-failing defect.
    assert!(outcome.failure_error().is_none());

    for _ in 0..200 {
        if dropped.load(Ordering::SeqCst) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        dropped.load(Ordering::SeqCst),
        "timed-out controller task was detached instead of aborted"
    );
}

/// A controller task that stopped during normal operation (before anyone asked
/// for shutdown) means part of the controller quietly stopped reconciling. It
/// must not be mistaken for a clean shutdown exit.
#[tokio::test]
async fn shutdown_reports_a_task_that_exited_before_shutdown_was_requested() {
    let (shutdown_tx, _shutdown_rx) = watch::channel(false);

    let early = tokio::spawn(async {});
    while !early.is_finished() {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

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

    let controller = k8s_controller_handle_for_test(vec![
        ("crd-watcher-0".to_string(), early),
        ("reconciler".to_string(), still_running),
    ]);
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
    // Early exit is reported, but it is not a panic, so it does not fail the
    // process exit code on its own.
    assert!(outcome.failure_error().is_none());
    assert_eq!(outcome.completed.len(), 2);
}
