//! Issue #2986: DB/CP config poll-task exit classification and supervision.

use ferrum_edge::modes::database::{
    DatabaseDeltaPollMetrics, run_poll_attempt_recording_completion,
};
use ferrum_edge::modes::db_poll_supervision::{
    DbPollTaskExitKind, classify_db_poll_task_exit, record_unexpected_cp_poll_task_exit,
    supervise_control_plane_poll_task, supervise_database_mode_poll_task_with_delay,
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

async fn yield_until(predicate: impl Fn() -> bool, label: &str) {
    for _ in 0..10_000 {
        if predicate() {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("timed out waiting for {label}");
}

#[tokio::test(start_paused = true)]
async fn database_mode_supervisor_respawns_after_abort_with_delay() {
    let spawn_count = Arc::new(AtomicUsize::new(0));
    let first_abort = Arc::new(std::sync::Mutex::new(None));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let spawn_count_for_factory = spawn_count.clone();
    let first_abort_for_factory = first_abort.clone();
    let shutdown_tx_for_poll = shutdown_tx.clone();
    let respawn_delay = Duration::from_secs(1);

    let supervisor = tokio::spawn(async move {
        supervise_database_mode_poll_task_with_delay(
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
            respawn_delay,
        )
        .await;
    });

    yield_until(
        || {
            first_abort
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_some()
        },
        "first poll generation",
    )
    .await;
    let abort_handle = first_abort
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .expect("abort handle");
    abort_handle.abort();

    // Supervisor observes abort and enters the respawn delay.
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        spawn_count.load(Ordering::Acquire),
        1,
        "respawn must wait for the bounded delay"
    );

    tokio::time::advance(respawn_delay).await;
    yield_until(
        || spawn_count.load(Ordering::Acquire) >= 2,
        "respawn after delay",
    )
    .await;

    shutdown_tx.send(true).expect("shutdown");
    supervisor.await.expect("supervisor join");
    assert!(
        spawn_count.load(Ordering::Acquire) >= 2,
        "database-mode supervisor must respawn after unexpected abort"
    );
}

#[tokio::test(start_paused = true)]
async fn database_mode_supervisor_rate_limits_repeated_unexpected_exits() {
    let spawn_count = Arc::new(AtomicUsize::new(0));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let spawn_count_for_factory = spawn_count.clone();
    let respawn_delay = Duration::from_millis(500);

    let supervisor = tokio::spawn(async move {
        supervise_database_mode_poll_task_with_delay(
            move || {
                spawn_count_for_factory.fetch_add(1, Ordering::AcqRel);
                // Every generation exits immediately (unexpected completion).
                tokio::spawn(async {})
            },
            shutdown_rx,
            respawn_delay,
        )
        .await;
    });

    yield_until(
        || spawn_count.load(Ordering::Acquire) >= 1,
        "first spawn",
    )
    .await;
    assert_eq!(spawn_count.load(Ordering::Acquire), 1);
    for _ in 0..32 {
        tokio::task::yield_now().await;
    }

    // Before the respawn delay elapses, no second generation.
    tokio::time::advance(respawn_delay - Duration::from_millis(1)).await;
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        spawn_count.load(Ordering::Acquire),
        1,
        "must not tight-loop respawn before delay elapses"
    );

    tokio::time::advance(Duration::from_millis(1)).await;
    yield_until(
        || spawn_count.load(Ordering::Acquire) >= 2,
        "second spawn",
    )
    .await;
    assert_eq!(spawn_count.load(Ordering::Acquire), 2);
    for _ in 0..32 {
        tokio::task::yield_now().await;
    }

    // Third generation also waits a full delay after the second unexpected exit.
    tokio::time::advance(respawn_delay - Duration::from_millis(1)).await;
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        spawn_count.load(Ordering::Acquire),
        2,
        "repeated failures must remain rate-limited"
    );

    tokio::time::advance(Duration::from_millis(1)).await;
    yield_until(
        || spawn_count.load(Ordering::Acquire) >= 3,
        "third spawn",
    )
    .await;

    shutdown_tx.send(true).expect("shutdown");
    // Allow the supervisor to observe shutdown if it re-entered the delay sleep.
    tokio::time::advance(respawn_delay).await;
    supervisor.await.expect("supervisor join");
    assert_eq!(
        spawn_count.load(Ordering::Acquire),
        3,
        "shutdown after third spawn must not start another generation"
    );
}

#[tokio::test(start_paused = true)]
async fn database_mode_shutdown_interrupts_respawn_wait_without_another_generation() {
    let spawn_count = Arc::new(AtomicUsize::new(0));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let spawn_count_for_factory = spawn_count.clone();
    let respawn_delay = Duration::from_secs(5);

    let supervisor = tokio::spawn(async move {
        supervise_database_mode_poll_task_with_delay(
            move || {
                spawn_count_for_factory.fetch_add(1, Ordering::AcqRel);
                tokio::spawn(async {})
            },
            shutdown_rx,
            respawn_delay,
        )
        .await;
    });

    yield_until(
        || spawn_count.load(Ordering::Acquire) >= 1,
        "first spawn",
    )
    .await;
    // Let the supervisor enter the respawn delay after unexpected completion.
    for _ in 0..32 {
        tokio::task::yield_now().await;
    }
    assert_eq!(spawn_count.load(Ordering::Acquire), 1);

    shutdown_tx.send(true).expect("shutdown during respawn wait");
    supervisor.await.expect("supervisor join");
    assert_eq!(
        spawn_count.load(Ordering::Acquire),
        1,
        "shutdown during respawn delay must not spawn another generation"
    );
}

#[tokio::test]
async fn last_poll_completed_at_advances_on_normal_empty_success() {
    let metrics = Arc::new(DatabaseDeltaPollMetrics::default());
    assert_eq!(metrics.last_poll_completed_at_unix_ms(), 0);

    run_poll_attempt_recording_completion(metrics.as_ref(), async {
        // Empty-success poll tick body returns normally.
    })
    .await;

    let first = metrics.last_poll_completed_at_unix_ms();
    assert!(
        first > 0,
        "empty-success poll must stamp last_poll_completed_at"
    );
    assert!(metrics.snapshot().last_poll_completed_at.is_some());

    std::thread::sleep(Duration::from_millis(2));
    run_poll_attempt_recording_completion(metrics.as_ref(), async {
        // Handled rejection/error path also returns normally.
    })
    .await;
    let second = metrics.last_poll_completed_at_unix_ms();
    assert!(
        second >= first,
        "subsequent handled outcome must advance or retain freshness"
    );
}

#[tokio::test]
async fn mid_poll_abort_does_not_advance_freshness() {
    let metrics = Arc::new(DatabaseDeltaPollMetrics::default());
    // Seed a prior completed stamp so we can detect unwanted advancement.
    run_poll_attempt_recording_completion(metrics.as_ref(), async {}).await;
    let before = metrics.last_poll_completed_at_unix_ms();
    assert!(before > 0);

    let metrics_for_task = metrics.clone();
    let handle = tokio::spawn(async move {
        run_poll_attempt_recording_completion(metrics_for_task.as_ref(), async {
            std::future::pending::<()>().await;
        })
        .await;
    });
    // Let the attempt future start, then abort mid-poll.
    tokio::task::yield_now().await;
    handle.abort();
    let _ = handle.await;

    assert_eq!(
        metrics.last_poll_completed_at_unix_ms(),
        before,
        "JoinHandle abort mid-poll must leave last_poll_completed_at unchanged"
    );
}

#[tokio::test]
async fn mid_poll_panic_does_not_advance_freshness() {
    let metrics = Arc::new(DatabaseDeltaPollMetrics::default());
    run_poll_attempt_recording_completion(metrics.as_ref(), async {}).await;
    let before = metrics.last_poll_completed_at_unix_ms();
    assert!(before > 0);

    let metrics_for_task = metrics.clone();
    let handle = tokio::spawn(async move {
        run_poll_attempt_recording_completion(metrics_for_task.as_ref(), async {
            panic!("intentional mid-poll panic for freshness test");
        })
        .await;
    });
    let result = handle.await;
    assert!(result.unwrap_err().is_panic());

    assert_eq!(
        metrics.last_poll_completed_at_unix_ms(),
        before,
        "panic mid-poll must leave last_poll_completed_at unchanged"
    );
}

#[tokio::test]
async fn dropping_in_flight_poll_attempt_future_does_not_advance_freshness() {
    let metrics = Arc::new(DatabaseDeltaPollMetrics::default());
    run_poll_attempt_recording_completion(metrics.as_ref(), async {}).await;
    let before = metrics.last_poll_completed_at_unix_ms();

    {
        let attempt = run_poll_attempt_recording_completion(metrics.as_ref(), async {
            std::future::pending::<()>().await;
        });
        // Simulate select-cancellation / future drop during an in-flight poll.
        drop(attempt);
    }

    assert_eq!(
        metrics.last_poll_completed_at_unix_ms(),
        before,
        "dropping an in-flight poll attempt must not publish a fresh timestamp"
    );
}
