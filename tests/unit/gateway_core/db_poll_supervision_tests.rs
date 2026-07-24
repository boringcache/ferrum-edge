//! Issue #2986: DB/CP config poll-task exit classification and supervision.

use ferrum_edge::modes::database::{DatabaseDeltaPollMetrics, PollCompletedGuard};
use ferrum_edge::modes::db_poll_supervision::{
    DbPollTaskExitKind, classify_db_poll_task_exit, record_unexpected_cp_poll_task_exit,
    supervise_control_plane_poll_task, supervise_database_mode_poll_task,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::watch;

#[test]
fn classify_treats_any_join_as_ordinary_when_shutdown_requested() {
    assert_eq!(
        classify_db_poll_task_exit(Ok(()), true),
        DbPollTaskExitKind::OrdinaryShutdown
    );
}

#[test]
fn classify_unexpected_completion_without_shutdown() {
    assert_eq!(
        classify_db_poll_task_exit(Ok(()), false),
        DbPollTaskExitKind::UnexpectedCompletion
    );
}

#[tokio::test]
async fn classify_abort_without_shutdown_is_unexpected() {
    let handle = tokio::spawn(async {
        std::future::pending::<()>().await;
    });
    handle.abort();
    let result = handle.await;
    assert!(result.is_err());
    assert_eq!(
        classify_db_poll_task_exit(result, false),
        DbPollTaskExitKind::Abort
    );
}

#[tokio::test]
async fn classify_panic_without_shutdown_is_unexpected() {
    let handle = tokio::spawn(async {
        panic!("intentional poll-task panic for classification test");
    });
    let result = handle.await;
    assert!(result.is_err());
    let err = result.as_ref().unwrap_err();
    assert!(err.is_panic());
    assert_eq!(
        classify_db_poll_task_exit(result, false),
        DbPollTaskExitKind::Panic
    );
}

#[test]
fn record_unexpected_cp_poll_exit_sets_sticky_serving_degraded() {
    let startup_ready = AtomicBool::new(true);
    let serving_degraded = AtomicBool::new(false);
    record_unexpected_cp_poll_task_exit(
        &startup_ready,
        &serving_degraded,
        DbPollTaskExitKind::Abort,
    );
    assert!(serving_degraded.load(Ordering::Acquire));
    assert!(!startup_ready.load(Ordering::Acquire));
}

#[tokio::test]
async fn abort_of_cp_poll_task_flips_serving_degraded() {
    let startup_ready = Arc::new(AtomicBool::new(true));
    let serving_degraded = Arc::new(AtomicBool::new(false));
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);

    let handle = tokio::spawn(async {
        std::future::pending::<()>().await;
    });
    handle.abort();

    supervise_control_plane_poll_task(
        handle,
        startup_ready.clone(),
        serving_degraded.clone(),
        shutdown_rx,
    )
    .await;

    assert!(
        serving_degraded.load(Ordering::Acquire),
        "aborted CP poll task must flip sticky serving_degraded"
    );
    assert!(!startup_ready.load(Ordering::Acquire));
}

#[tokio::test]
async fn ordinary_cp_shutdown_does_not_degrade() {
    let startup_ready = Arc::new(AtomicBool::new(true));
    let serving_degraded = Arc::new(AtomicBool::new(false));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let mut poll_shutdown = shutdown_tx.subscribe();
    let handle = tokio::spawn(async move {
        let _ = poll_shutdown.changed().await;
    });

    let supervise = tokio::spawn({
        let startup_ready = startup_ready.clone();
        let serving_degraded = serving_degraded.clone();
        async move {
            supervise_control_plane_poll_task(
                handle,
                startup_ready,
                serving_degraded,
                shutdown_rx,
            )
            .await;
        }
    });

    shutdown_tx.send(true).expect("shutdown send");
    supervise.await.expect("supervisor join");

    assert!(
        !serving_degraded.load(Ordering::Acquire),
        "ordinary shutdown must not mark serving degraded"
    );
    assert!(startup_ready.load(Ordering::Acquire));
}

#[tokio::test]
async fn database_mode_supervisor_respawns_after_abort() {
    let spawn_count = Arc::new(AtomicUsize::new(0));
    let first_abort = Arc::new(std::sync::Mutex::new(None));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let spawn_count_for_factory = spawn_count.clone();
    let first_abort_for_factory = first_abort.clone();
    let shutdown_tx_for_poll = shutdown_tx.clone();

    let supervisor = tokio::spawn(async move {
        supervise_database_mode_poll_task(
            move || {
                let n = spawn_count_for_factory.fetch_add(1, Ordering::AcqRel);
                let mut shutdown_rx = shutdown_tx_for_poll.subscribe();
                let handle = tokio::spawn(async move {
                    if n == 0 {
                        std::future::pending::<()>().await;
                    } else {
                        let _ = shutdown_rx.changed().await;
                    }
                });
                if n == 0 {
                    let abort = handle.abort_handle();
                    *first_abort_for_factory
                        .lock()
                        .unwrap_or_else(|e| e.into_inner()) = Some(abort);
                }
                handle
            },
            shutdown_rx,
        )
        .await;
    });

    // Wait for first generation abort handle.
    let abort_handle = {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            if let Some(handle) = first_abort
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
            {
                break handle;
            }
            if tokio::time::Instant::now() >= deadline {
                panic!("timed out waiting for first poll generation");
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    };
    abort_handle.abort();

    // Wait for respawn.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while spawn_count.load(Ordering::Acquire) < 2 {
        if tokio::time::Instant::now() >= deadline {
            panic!(
                "timed out waiting for respawn; spawn_count={}",
                spawn_count.load(Ordering::Acquire)
            );
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    shutdown_tx.send(true).expect("shutdown");
    supervisor.await.expect("supervisor join");
    assert!(
        spawn_count.load(Ordering::Acquire) >= 2,
        "database-mode supervisor must respawn after unexpected abort"
    );
}

#[test]
fn last_poll_completed_at_advances_on_empty_success_guard() {
    let metrics = Arc::new(DatabaseDeltaPollMetrics::default());
    assert_eq!(metrics.last_poll_completed_at_unix_ms(), 0);
    assert!(metrics.snapshot().last_poll_completed_at.is_none());

    {
        let _guard = PollCompletedGuard::new(metrics.clone());
        // Drop records completion — simulates an empty-but-successful poll tick.
    }

    let first = metrics.last_poll_completed_at_unix_ms();
    assert!(
        first > 0,
        "empty-success poll must stamp last_poll_completed_at"
    );
    assert!(metrics.snapshot().last_poll_completed_at.is_some());

    std::thread::sleep(Duration::from_millis(2));
    {
        let _guard = PollCompletedGuard::new(metrics.clone());
    }
    let second = metrics.last_poll_completed_at_unix_ms();
    assert!(
        second >= first,
        "subsequent empty-success poll must advance or retain freshness"
    );
}
