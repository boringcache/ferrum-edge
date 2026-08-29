//! External coverage for issue #2372: mesh late-startup rollback.
//!
//! Once mesh startup has created tasks / capture side effects, every later
//! initialization error must signal shared shutdown and finish bounded
//! teardown (including netns-style async manager shutdown) before returning
//! the original cause.

use ferrum_edge::_test_support::{
    MeshStartupRollbackProbe, mesh_startup_failure_before_owner_probe_for_test,
    mesh_startup_failure_before_startup_result_gate_probe_for_test,
    mesh_startup_failure_inside_startup_result_gate_probe_for_test,
    mesh_startup_failure_listener_join_bounded_probe_for_test,
};

use crate::unit::env_lock::ENV_LOCK;

/// The production startup path reads the UDP placement variables directly.
/// Run each async probe to completion while owning the same process-wide lock
/// as every environment-mutating unit test. A synchronous wrapper is
/// deliberate: it avoids carrying a `MutexGuard` across an `.await` in test
/// source while still excluding transient sibling-test environment state.
fn run_env_locked_startup_probe(
    probe: impl std::future::Future<Output = MeshStartupRollbackProbe>,
) -> MeshStartupRollbackProbe {
    let _env_lock = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("startup rollback probe runtime")
        .block_on(probe)
}

#[test]
fn failure_before_owner_drains_spawned_tasks() {
    let probe = run_env_locked_startup_probe(mesh_startup_failure_before_owner_probe_for_test());

    assert!(
        !probe.ok,
        "injected pre-owner failure must abort mesh startup"
    );
    let error = probe
        .error
        .expect("pre-owner failure must surface an error");
    assert!(
        error.contains("injected mesh startup failure before MeshStartupOwner"),
        "original startup error preserved: {error}"
    );
    assert!(
        probe.shutdown_observed,
        "shared shutdown must reach netns-style background tasks"
    );
    assert!(
        probe.teardown_completed,
        "netns-style async teardown must complete before return"
    );
}

#[test]
fn failure_before_startup_result_gate_drains_spawned_tasks() {
    let probe = run_env_locked_startup_probe(
        mesh_startup_failure_before_startup_result_gate_probe_for_test(),
    );

    assert!(
        !probe.ok,
        "injected before-gate failure must abort mesh startup"
    );
    let error = probe
        .error
        .expect("before-gate failure must surface an error");
    assert!(
        error.contains("injected mesh startup failure before startup_result gate"),
        "original startup error preserved: {error}"
    );
    assert!(
        probe.shutdown_observed,
        "shared shutdown must reach netns-style background tasks"
    );
    assert!(
        probe.teardown_completed,
        "netns-style async teardown must complete before return"
    );
}

#[test]
fn failure_inside_startup_result_gate_drains_spawned_tasks() {
    let probe = run_env_locked_startup_probe(
        mesh_startup_failure_inside_startup_result_gate_probe_for_test(),
    );

    assert!(
        !probe.ok,
        "injected inside-gate failure must abort mesh startup"
    );
    let error = probe
        .error
        .expect("inside-gate failure must surface an error");
    assert!(
        error.contains("injected mesh startup failure inside startup_result gate"),
        "original startup error preserved: {error}"
    );
    assert!(
        probe.shutdown_observed,
        "shared shutdown must reach netns-style background tasks"
    );
    assert!(
        probe.teardown_completed,
        "netns-style async teardown must complete before return"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn startup_failure_listener_join_is_bounded_and_aborts_stragglers() {
    let probe = mesh_startup_failure_listener_join_bounded_probe_for_test().await;

    assert!(
        probe.returned_promptly,
        "startup-failure listener join must honor the drain timeout"
    );
    assert!(
        probe.stuck_aborted,
        "stuck listeners must be aborted after the drain timeout"
    );
}
