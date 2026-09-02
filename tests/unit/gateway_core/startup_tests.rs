//! Tests for startup signal waiting.

use ferrum_edge::startup::{
    ServingListenerFailures, flip_ready_off_on_listener_failure,
    record_post_start_listener_failure, wait_for_start_signals,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::oneshot;

#[tokio::test]
async fn test_all_signals_received_returns_ok() {
    let (tx1, rx1) = oneshot::channel();
    let (tx2, rx2) = oneshot::channel();
    tx1.send(()).unwrap();
    tx2.send(()).unwrap();

    let result = wait_for_start_signals(
        vec![("listener-1".into(), rx1), ("listener-2".into(), rx2)],
        Duration::from_secs(1),
    )
    .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_empty_signals_returns_ok() {
    let result = wait_for_start_signals(vec![], Duration::from_secs(1)).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_channel_closed_before_signal_returns_error() {
    let (tx, rx) = oneshot::channel::<()>();
    drop(tx); // Close without sending

    let result = wait_for_start_signals(vec![("proxy".into(), rx)], Duration::from_secs(1)).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("exited before completing startup"),
        "Expected channel-closed error, got: {}",
        err
    );
}

#[tokio::test]
async fn test_timeout_returns_error() {
    let (_tx, rx) = oneshot::channel::<()>();
    // tx is held but never sent — will timeout

    let result =
        wait_for_start_signals(vec![("admin".into(), rx)], Duration::from_millis(10)).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("Timed out"),
        "Expected timeout error, got: {}",
        err
    );
}

#[tokio::test]
async fn test_second_signal_fails_first_succeeds() {
    let (tx1, rx1) = oneshot::channel();
    let (_tx2, rx2) = oneshot::channel::<()>();
    tx1.send(()).unwrap();
    drop(_tx2); // Second channel closed

    let result = wait_for_start_signals(
        vec![("ok-listener".into(), rx1), ("bad-listener".into(), rx2)],
        Duration::from_secs(1),
    )
    .await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("bad-listener"));
}

#[tokio::test]
async fn test_timeout_is_overall_deadline_not_per_signal() {
    let (tx1, rx1) = oneshot::channel();
    let (_tx2, rx2) = oneshot::channel::<()>();

    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let _ = tx1.send(());
    });

    let result = tokio::time::timeout(
        Duration::from_millis(220),
        wait_for_start_signals(
            vec![
                ("slow-listener".into(), rx1),
                ("missing-listener".into(), rx2),
            ],
            Duration::from_millis(150),
        ),
    )
    .await
    .expect("startup wait should enforce one overall deadline");

    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("missing-listener"),
        "expected timeout to report the pending listener, got: {err}"
    );
}

#[test]
fn test_flip_ready_off_on_listener_failure_sets_not_ready() {
    // A serving listener task that exits with an error after startup must flip
    // the shared readiness flag back to not-ready so `/health` stops reporting
    // `ready` while the surface is silently dead (issue #2117).
    let ready = AtomicBool::new(true);
    let degraded = AtomicBool::new(false);
    flip_ready_off_on_listener_failure(
        &ready,
        &degraded,
        "HTTP proxy listener",
        &"accept loop failed",
    );
    assert!(
        !ready.load(Ordering::Acquire),
        "readiness flag should be flipped to false after a listener serve failure"
    );
    assert!(
        degraded.load(Ordering::Acquire),
        "serving_degraded flag should be set after a listener serve failure"
    );
}

#[test]
fn test_flip_ready_off_on_listener_failure_is_idempotent_when_already_not_ready() {
    // Flipping an already-not-ready flag is a no-op (the flag is only ever
    // driven toward not-ready on this path), so multiple failing listeners
    // cannot resurrect readiness.
    let ready = AtomicBool::new(false);
    let degraded = AtomicBool::new(false);
    flip_ready_off_on_listener_failure(&ready, &degraded, "Admin HTTPS listener", &"bind failed");
    assert!(!ready.load(Ordering::Acquire));
    assert!(degraded.load(Ordering::Acquire));
}

#[test]
fn test_serving_degraded_is_sticky_across_readiness_restore() {
    // The core of the PR #2128 durability fix: after a serve failure sets the
    // sticky `serving_degraded` flag, a later `startup_ready.store(true)` — as
    // performed by the CP main task after the gRPC start signal, or by the DP
    // client on every CP-reconnect snapshot — must NOT clear it. `/health`
    // computes readiness as `startup_ready && !serving_degraded`, so the flip
    // stays durable even though `startup_ready` was clobbered back to `true`.
    let ready = AtomicBool::new(true);
    let degraded = AtomicBool::new(false);

    flip_ready_off_on_listener_failure(&ready, &degraded, "CP gRPC server", &"serve future exited");
    assert!(!ready.load(Ordering::Acquire));
    assert!(degraded.load(Ordering::Acquire));

    // Simulate the later main-task / reconnect readiness restore.
    ready.store(true, Ordering::Release);

    // startup_ready was restored, but the sticky flag keeps readiness false.
    let effective_ready = ready.load(Ordering::Acquire) && !degraded.load(Ordering::Acquire);
    assert!(
        !effective_ready,
        "serving_degraded must keep /health not-ready across a startup_ready restore"
    );
}

#[test]
fn test_cp_admin_serve_failure_flips_effective_readiness() {
    // CP admin HTTP and HTTPS task closures use this same sticky failure path
    // after their bind-start signal. Even if CP's main task subsequently marks
    // startup complete, a failed admin serve future must remain not-ready.
    let ready = AtomicBool::new(true);
    let degraded = AtomicBool::new(false);

    flip_ready_off_on_listener_failure(
        &ready,
        &degraded,
        "CP admin HTTPS listener",
        &"serve future exited",
    );
    ready.store(true, Ordering::Release);

    assert!(degraded.load(Ordering::Acquire));
    assert!(
        !ready.load(Ordering::Acquire) || degraded.load(Ordering::Acquire),
        "CP admin serve failure must remain visible after startup-ready is restored"
    );
}

#[test]
fn mesh_post_start_listener_failure_is_sticky_and_recorded_safely() {
    let ready = AtomicBool::new(true);
    let degraded = AtomicBool::new(false);
    let failures = ServingListenerFailures::default();

    record_post_start_listener_failure(
        &ready,
        &degraded,
        &failures,
        "Mesh traffic listener",
        15001,
        &"secret=/operator/private/path",
    );
    ready.store(true, Ordering::Release);

    assert!(degraded.load(Ordering::Acquire));
    assert!(!ready.load(Ordering::Acquire) || degraded.load(Ordering::Acquire));
    let snapshot = failures.snapshot();
    assert_eq!(snapshot.failures_total, 1);
    assert_eq!(snapshot.failures[0].listener, "Mesh traffic listener");
    assert_eq!(snapshot.failures[0].listen_port, 15001);
    assert_eq!(
        snapshot.failures[0].error,
        "listener serve task exited after successful bind"
    );
    assert!(!snapshot.failures[0].error.contains("secret"));
}

#[test]
fn healthy_mesh_listener_set_keeps_ready_and_has_no_failure_snapshot() {
    let ready = AtomicBool::new(true);
    let degraded = AtomicBool::new(false);
    let failures = ServingListenerFailures::default();

    assert!(ready.load(Ordering::Acquire) && !degraded.load(Ordering::Acquire));
    let snapshot = failures.snapshot();
    assert_eq!(snapshot.failures_total, 0);
    assert!(snapshot.failures.is_empty());
}

// ── SIGHUP disposition (issue #4548) ────────────────────────────────────────

use ferrum_edge::config::env_config::OperatingMode;
use ferrum_edge::startup::{SighupDisposition, sighup_disposition};

/// Every operating mode, matched exhaustively so a newly added variant forces
/// this file to be updated rather than silently inheriting a default.
fn all_modes() -> Vec<OperatingMode> {
    let all = vec![
        OperatingMode::Database,
        OperatingMode::File,
        OperatingMode::ControlPlane,
        OperatingMode::DataPlane,
        OperatingMode::Mesh,
        OperatingMode::Injector,
        OperatingMode::NodeAgent,
        OperatingMode::Migrate,
    ];
    for mode in &all {
        // Exhaustive match: adding a variant breaks the build here.
        match mode {
            OperatingMode::Database
            | OperatingMode::File
            | OperatingMode::ControlPlane
            | OperatingMode::DataPlane
            | OperatingMode::Mesh
            | OperatingMode::Injector
            | OperatingMode::NodeAgent
            | OperatingMode::Migrate => {}
        }
    }
    all
}

#[test]
fn sighup_reloads_config_only_in_file_mode() {
    for mode in all_modes() {
        let disposition = sighup_disposition(&mode);
        if mode == OperatingMode::File {
            assert_eq!(
                disposition,
                SighupDisposition::ReloadsConfig,
                "file mode owns the real SIGHUP reload handler"
            );
        } else {
            assert!(
                matches!(disposition, SighupDisposition::IgnoredWithNotice(_)),
                "{mode:?} has no SIGHUP reload path and must be a logged no-op"
            );
        }
    }
}

#[test]
fn sighup_notices_name_the_real_reload_mechanism_and_promise_survival() {
    let expectations: &[(OperatingMode, &str)] = &[
        (OperatingMode::Database, "FERRUM_DB_POLL_INTERVAL"),
        (OperatingMode::ControlPlane, "gRPC"),
        (OperatingMode::DataPlane, "control plane"),
        (OperatingMode::Mesh, "config source"),
        (OperatingMode::Injector, "restart the"),
        (OperatingMode::NodeAgent, "restart the"),
        (OperatingMode::Migrate, "one-shot"),
    ];

    for (mode, needle) in expectations {
        let SighupDisposition::IgnoredWithNotice(text) = sighup_disposition(mode) else {
            panic!("{mode:?} must carry an ignored-with-notice disposition");
        };
        assert!(
            text.contains(needle),
            "{mode:?} notice must name its reload mechanism ({needle}): {text}"
        );
        // The operationally load-bearing half: the operator must be told the
        // process survived the signal.
        assert!(
            text.contains("will not terminate"),
            "{mode:?} notice must say the process is not terminating: {text}"
        );
        assert!(
            text.starts_with("SIGHUP received"),
            "{mode:?} notice must identify the signal: {text}"
        );
    }
}

/// The CLI's second `reload` line must match the disposition table: file mode
/// (and mesh with a local config source) reload, everything else ignores.
#[test]
fn reload_scope_notice_scopes_sighup_to_file_and_local_mesh_sources() {
    let notice = ferrum_edge::cli::RELOAD_SCOPE_NOTICE;
    assert!(notice.contains("file mode"), "{notice}");
    assert!(notice.contains("mesh mode"), "{notice}");
    assert!(notice.contains("xDS"), "{notice}");
    assert!(
        notice.contains("log the signal and ignore it"),
        "the notice must state the no-op outcome: {notice}"
    );
}
