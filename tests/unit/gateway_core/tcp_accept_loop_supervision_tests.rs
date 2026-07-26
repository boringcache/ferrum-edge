//! External regression coverage for TCP SO_REUSEPORT accept-loop supervision
//! (issue #3216).
//!
//! Extra accept loops previously ran as unchecked `JoinHandle`s while the
//! primary loop was awaited forever. Panics and ordinary early errors on a
//! non-primary peer stayed invisible until listener shutdown (and were then
//! discarded). These tests exercise the production supervisor through a narrow
//! `_test_support` wrapper with synthetic peer tasks (including deliberate
//! non-primary panics and ordinary errors) so JoinError/error classification
//! and sibling cancellation stay deterministic without a production fault seam.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use ferrum_edge::_test_support::{
    TcpAcceptLoopClass, supervise_tcp_accept_loop_peers_for_test,
};
use tokio::sync::watch;

#[tokio::test]
async fn supervise_observes_non_primary_panic_while_primary_still_pending() {
    let (cancel_tx, _) = watch::channel(false);
    let started = Arc::new(AtomicBool::new(true));
    let cancel_count = Arc::new(AtomicUsize::new(0));

    let mut primary_rx = cancel_tx.subscribe();
    let primary = tokio::spawn(async move {
        let _ = primary_rx.changed().await;
        Ok(())
    });

    let extra = tokio::spawn(async {
        panic!("non-primary TCP accept loop crash");
    });

    let started_flag = started.clone();
    let cancel_counter = cancel_count.clone();
    let trigger = cancel_tx.clone();
    let began = Instant::now();
    let err = supervise_tcp_accept_loop_peers_for_test(
        vec![
            (TcpAcceptLoopClass::Primary, primary),
            (TcpAcceptLoopClass::Extra { index: 1 }, extra),
        ],
        move || {
            cancel_counter.fetch_add(1, Ordering::SeqCst);
            let _ = trigger.send(true);
            started_flag.store(false, Ordering::Release);
        },
    )
    .await
    .expect_err("non-primary panic must fail the supervised listener");
    let elapsed = began.elapsed();

    assert!(
        err.to_string().contains("extra(1)"),
        "failure must identify the extra loop class; got {err}"
    );
    assert!(
        err.to_string().contains("panicked"),
        "failure must report panic; got {err}"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "panic must be observed promptly while primary was pending; took {elapsed:?}"
    );
    assert_eq!(
        cancel_count.load(Ordering::SeqCst),
        1,
        "sibling teardown must fire exactly once"
    );
    assert!(
        !started.load(Ordering::Acquire),
        "unexpected peer exit must clear started/readiness"
    );
}

#[tokio::test]
async fn supervise_observes_ordinary_early_error_on_extra_loop() {
    let (cancel_tx, _) = watch::channel(false);

    let mut primary_rx = cancel_tx.subscribe();
    let primary_finished = Arc::new(AtomicBool::new(false));
    let primary_finished_flag = primary_finished.clone();
    let primary = tokio::spawn(async move {
        let _ = primary_rx.changed().await;
        primary_finished_flag.store(true, Ordering::SeqCst);
        Ok(())
    });

    let extra = tokio::spawn(async {
        Err(anyhow::anyhow!("accept loop socket failed"))
    });

    let trigger = cancel_tx.clone();
    let began = Instant::now();
    let err = supervise_tcp_accept_loop_peers_for_test(
        vec![
            (TcpAcceptLoopClass::Primary, primary),
            (TcpAcceptLoopClass::Extra { index: 1 }, extra),
        ],
        move || {
            let _ = trigger.send(true);
        },
    )
    .await
    .expect_err("ordinary early error must fail the listener");

    assert!(
        err.to_string().contains("exited with error"),
        "failure must surface the ordinary error path; got {err}"
    );
    assert!(
        began.elapsed() < Duration::from_secs(2),
        "early error must tear down siblings promptly"
    );
    assert!(
        primary_finished.load(Ordering::SeqCst),
        "primary sibling must drain via peer-cancel after extra early error"
    );
}

#[tokio::test]
async fn supervise_observes_primary_failure_and_drains_extras() {
    let (cancel_tx, _) = watch::channel(false);
    let extras_finished = Arc::new(AtomicUsize::new(0));

    let primary = tokio::spawn(async {
        Err(anyhow::anyhow!("primary accept loop failed"))
    });

    let mut extra_a_rx = cancel_tx.subscribe();
    let extras_a = extras_finished.clone();
    let extra_a = tokio::spawn(async move {
        let _ = extra_a_rx.changed().await;
        extras_a.fetch_add(1, Ordering::SeqCst);
        Ok(())
    });

    let mut extra_b_rx = cancel_tx.subscribe();
    let extras_b = extras_finished.clone();
    let extra_b = tokio::spawn(async move {
        let _ = extra_b_rx.changed().await;
        extras_b.fetch_add(1, Ordering::SeqCst);
        Ok(())
    });

    let trigger = cancel_tx.clone();
    let err = supervise_tcp_accept_loop_peers_for_test(
        vec![
            (TcpAcceptLoopClass::Primary, primary),
            (TcpAcceptLoopClass::Extra { index: 1 }, extra_a),
            (TcpAcceptLoopClass::Extra { index: 2 }, extra_b),
        ],
        move || {
            let _ = trigger.send(true);
        },
    )
    .await
    .expect_err("primary failure must fail the listener");

    assert!(
        err.to_string().contains("primary"),
        "failure must identify the primary loop; got {err}"
    );
    assert_eq!(
        extras_finished.load(Ordering::SeqCst),
        2,
        "both extra siblings must drain; no orphaned accept loops"
    );
}

#[tokio::test]
async fn supervise_clean_shutdown_is_not_operational_failure() {
    let (cancel_tx, _) = watch::channel(false);
    let cancel_fired = Arc::new(AtomicBool::new(false));

    let mut primary_rx = cancel_tx.subscribe();
    let primary = tokio::spawn(async move {
        let _ = primary_rx.changed().await;
        Ok(())
    });
    let mut extra_rx = cancel_tx.subscribe();
    let extra = tokio::spawn(async move {
        let _ = extra_rx.changed().await;
        Ok(())
    });

    let shutdown = cancel_tx.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        let _ = shutdown.send(true);
    });

    let cancel_flag = cancel_fired.clone();
    let began = Instant::now();
    supervise_tcp_accept_loop_peers_for_test(
        vec![
            (TcpAcceptLoopClass::Primary, primary),
            (TcpAcceptLoopClass::Extra { index: 1 }, extra),
        ],
        move || {
            cancel_flag.store(true, Ordering::SeqCst);
        },
    )
    .await
    .expect("shutdown-triggered completion must remain Ok");

    assert!(
        began.elapsed() < Duration::from_secs(2),
        "clean shutdown must drain promptly"
    );
    assert!(
        !cancel_fired.load(Ordering::SeqCst),
        "peer-failure cancel must not fire on clean shutdown"
    );
}

#[tokio::test]
async fn supervise_aborts_siblings_when_cancel_signal_is_ignored() {
    // Models a lost peer-cancel: siblings never observe the watch channel.
    // Supervisor must abort rather than hang.
    let primary = tokio::spawn(async {
        Err(anyhow::anyhow!("primary failed"))
    });
    let stuck_extra = tokio::spawn(async {
        std::future::pending::<()>().await;
        Ok(())
    });

    let began = Instant::now();
    let err = supervise_tcp_accept_loop_peers_for_test(
        vec![
            (TcpAcceptLoopClass::Primary, primary),
            (TcpAcceptLoopClass::Extra { index: 1 }, stuck_extra),
        ],
        || {
            // Deliberately do not unblock the stuck sibling.
        },
    )
    .await
    .expect_err("primary failure must still surface");

    assert!(
        err.to_string().contains("primary"),
        "original failure must be preserved; got {err}"
    );
    assert!(
        began.elapsed() < Duration::from_secs(5),
        "lost cancel must not hang forever; took {:?}",
        began.elapsed()
    );
}

#[tokio::test]
async fn supervise_does_not_double_count_cancel_on_multiple_failures() {
    let cancel_count = Arc::new(AtomicUsize::new(0));
    let primary = tokio::spawn(async {
        Err(anyhow::anyhow!("primary failed"))
    });
    let extra = tokio::spawn(async {
        Err(anyhow::anyhow!("extra also failed"))
    });

    let counter = cancel_count.clone();
    let err = supervise_tcp_accept_loop_peers_for_test(
        vec![
            (TcpAcceptLoopClass::Primary, primary),
            (TcpAcceptLoopClass::Extra { index: 1 }, extra),
        ],
        move || {
            counter.fetch_add(1, Ordering::SeqCst);
        },
    )
    .await
    .expect_err("first failure must surface");

    assert_eq!(
        cancel_count.load(Ordering::SeqCst),
        1,
        "cancel/teardown must run once even when multiple peers fail"
    );
    // Either peer may win the race; both are operational failures.
    let msg = err.to_string();
    assert!(
        msg.contains("primary") || msg.contains("extra(1)"),
        "failure must identify a loop class; got {msg}"
    );
}
