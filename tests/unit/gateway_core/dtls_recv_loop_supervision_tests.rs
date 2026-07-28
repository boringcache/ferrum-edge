//! External regression coverage for DTLS frontend recv-loop supervision
//! (issue #3215).
//!
//! The DTLS socket receive loop previously ran as an unchecked `JoinHandle`
//! while the accept loop awaited forever. Recv-loop errors and panics left
//! `started`/readiness healthy with no task reading UDP. These tests exercise
//! the production classifier and shutdown/failure supervisor through a narrow
//! `_test_support` wrapper with synthetic tasks (including deliberate panics
//! and ordinary errors) so JoinError/error classification stays deterministic
//! without a production fault seam.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use ferrum_edge::_test_support::{
    classify_dtls_recv_loop_exit_for_test, supervise_dtls_recv_loop_task_for_test,
};
use tokio::sync::watch;

#[tokio::test]
async fn supervise_observes_recv_loop_panic_while_accept_would_block() {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let started = Arc::new(AtomicBool::new(true));
    let shutdown_hooks = Arc::new(AtomicUsize::new(0));

    let server_task = tokio::spawn(async {
        panic!("DTLS recv loop crash");
    });

    // Keep the shutdown sender alive so the watch does not spuriously fire.
    let _keep_shutdown = shutdown_tx;
    let hooks = shutdown_hooks.clone();
    let began = Instant::now();
    let err = supervise_dtls_recv_loop_task_for_test(
        server_task,
        shutdown_rx,
        None,
        started.clone(),
        move || {
            hooks.fetch_add(1, Ordering::SeqCst);
        },
    )
    .await
    .expect_err("recv-loop panic must fail the supervised listener");

    assert!(
        err.to_string().contains("panicked"),
        "failure must report panic; got {err}"
    );
    assert!(
        began.elapsed() < Duration::from_secs(2),
        "panic must be observed promptly while accept would still block; took {:?}",
        began.elapsed()
    );
    assert!(
        !started.load(Ordering::Acquire),
        "unexpected recv-loop exit must clear started/readiness"
    );
    assert_eq!(
        shutdown_hooks.load(Ordering::SeqCst),
        0,
        "graceful-shutdown hook must not fire on operational failure"
    );
}

#[tokio::test]
async fn supervise_observes_ordinary_recv_loop_error() {
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let started = Arc::new(AtomicBool::new(true));

    let server_task = tokio::spawn(async {
        Err(anyhow::anyhow!("DTLS server recv error: permanent I/O failure"))
    });

    let began = Instant::now();
    let err = supervise_dtls_recv_loop_task_for_test(
        server_task,
        shutdown_rx,
        None,
        started.clone(),
        || {},
    )
    .await
    .expect_err("ordinary recv-loop error must fail the listener");

    assert!(
        err.to_string().contains("exited with error"),
        "failure must surface the ordinary error path; got {err}"
    );
    assert!(
        err.to_string().contains("permanent I/O failure"),
        "failure must preserve the recv-loop context; got {err}"
    );
    assert!(
        began.elapsed() < Duration::from_secs(2),
        "early error must fail the listener promptly"
    );
    assert!(
        !started.load(Ordering::Acquire),
        "ordinary recv-loop error must clear started/readiness"
    );
}

#[tokio::test]
async fn supervise_clean_shutdown_is_not_operational_failure() {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (close_tx, mut close_rx) = watch::channel(false);
    let started = Arc::new(AtomicBool::new(true));
    let shutdown_hooks = Arc::new(AtomicUsize::new(0));

    // Mirror production: recv loop exits only after on_shutdown closes the
    // server (separate from the operator shutdown watch the supervisor sees).
    let server_task = tokio::spawn(async move {
        let _ = close_rx.changed().await;
        Ok(())
    });

    let trigger = shutdown_tx.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        let _ = trigger.send(true);
    });

    let hooks = shutdown_hooks.clone();
    let began = Instant::now();
    supervise_dtls_recv_loop_task_for_test(
        server_task,
        shutdown_rx,
        None,
        started.clone(),
        move || {
            hooks.fetch_add(1, Ordering::SeqCst);
            let _ = close_tx.send(true);
        },
    )
    .await
    .expect("shutdown-triggered completion must remain Ok");

    assert!(
        began.elapsed() < Duration::from_secs(2),
        "clean shutdown must drain promptly"
    );
    assert_eq!(
        shutdown_hooks.load(Ordering::SeqCst),
        1,
        "graceful-shutdown hook must fire once"
    );
    assert!(
        started.load(Ordering::Acquire),
        "clean shutdown must not clear started via the failure path"
    );
}

#[tokio::test]
async fn supervise_global_shutdown_is_not_operational_failure() {
    let (_local_tx, local_rx) = watch::channel(false);
    let (global_tx, global_rx) = watch::channel(false);
    let (close_tx, mut close_rx) = watch::channel(false);
    let started = Arc::new(AtomicBool::new(true));
    let shutdown_hooks = Arc::new(AtomicUsize::new(0));

    let server_task = tokio::spawn(async move {
        let _ = close_rx.changed().await;
        Ok(())
    });

    let trigger = global_tx.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        let _ = trigger.send(true);
    });

    let hooks = shutdown_hooks.clone();
    supervise_dtls_recv_loop_task_for_test(
        server_task,
        local_rx,
        Some(global_rx),
        started.clone(),
        move || {
            hooks.fetch_add(1, Ordering::SeqCst);
            let _ = close_tx.send(true);
        },
    )
    .await
    .expect("global shutdown must remain Ok");

    assert_eq!(shutdown_hooks.load(Ordering::SeqCst), 1);
    assert!(
        started.load(Ordering::Acquire),
        "global shutdown must not clear started via the failure path"
    );
}

#[tokio::test]
async fn classify_unexpected_ok_exit_is_operational_failure() {
    let err = classify_dtls_recv_loop_exit_for_test(Ok(Ok(())));
    assert!(
        err.to_string()
            .contains("exited unexpectedly without error"),
        "clean Ok without shutdown arm must still fail; got {err}"
    );
}

#[tokio::test]
async fn classify_cancelled_join_is_operational_failure() {
    let task: tokio::task::JoinHandle<Result<(), anyhow::Error>> = tokio::spawn(async {
        std::future::pending::<()>().await;
        Ok(())
    });
    task.abort();
    let join_result = task.await;
    assert!(
        join_result.as_ref().err().is_some_and(|e| e.is_cancelled()),
        "fixture must produce a cancelled JoinError"
    );

    let err = classify_dtls_recv_loop_exit_for_test(join_result);
    assert!(
        err.to_string().contains("cancelled unexpectedly"),
        "unexpected cancel must be an operational failure; got {err}"
    );
}
