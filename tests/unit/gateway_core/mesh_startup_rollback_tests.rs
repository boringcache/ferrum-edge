//! External coverage for issue #2372: mesh late-startup rollback.
//!
//! Once mesh startup has created tasks / capture side effects, every later
//! initialization error must signal shared shutdown and finish bounded
//! teardown (including netns-style async manager shutdown) before returning
//! the original cause.

use ferrum_edge::_test_support::{
    mesh_startup_failure_before_owner_probe_for_test,
    mesh_startup_failure_before_startup_result_gate_probe_for_test,
    mesh_startup_failure_inside_startup_result_gate_probe_for_test,
    mesh_startup_failure_listener_join_bounded_probe_for_test,
};

use crate::unit::env_lock::EnvGuard;

/// Process env vars the mesh startup path resolves while a probe runs.
///
/// `serve_mesh_runtime` resolves the UDP capture settings from the PROCESS
/// environment and then validates them against the probe's resolved topology
/// (`Sidecar`). `mesh_host_udp_capture_plan_tests` legitimately sets
/// `FERRUM_MESH_CAPTURE_UDP_HOST_NETNS_ENABLED=true` for the duration of its
/// own assertions, and `cargo test --test unit_tests` runs the two files in
/// parallel — so without this serialization a probe can observe that mutation
/// and abort on the host-placement topology error instead of on its injected
/// fault.
const MESH_STARTUP_PROBE_ENV_KEYS: &[&str] = &[
    "FERRUM_MESH_CAPTURE_UDP_ENABLED",
    "FERRUM_MESH_CAPTURE_UDP_PORT",
    "FERRUM_MESH_TPROXY_MARK",
    "FERRUM_MESH_CAPTURE_UDP_HOST_NETNS_ENABLED",
];

/// Take the process-wide env lock and pin the capture keys to their defaults
/// for the duration of one probe. Held across the probe's `.await` on purpose:
/// the probe reads the environment throughout mesh startup, not only at entry.
fn mesh_startup_probe_env_guard() -> EnvGuard {
    let guard = EnvGuard::new(MESH_STARTUP_PROBE_ENV_KEYS);
    for key in MESH_STARTUP_PROBE_ENV_KEYS {
        guard.unset(key);
    }
    guard
}

// The env guard owns a std mutex and is deliberately held across the probe's
// `.await`: mesh startup reads the process environment throughout, not only at
// entry, and this test runs on a single-threaded runtime where no other task
// can contend for it.
#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "current_thread")]
async fn failure_before_owner_drains_spawned_tasks() {
    let _env = mesh_startup_probe_env_guard();
    let probe = mesh_startup_failure_before_owner_probe_for_test().await;

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

// The env guard owns a std mutex and is deliberately held across the probe's
// `.await`: mesh startup reads the process environment throughout, not only at
// entry, and this test runs on a single-threaded runtime where no other task
// can contend for it.
#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "current_thread")]
async fn failure_before_startup_result_gate_drains_spawned_tasks() {
    let _env = mesh_startup_probe_env_guard();
    let probe = mesh_startup_failure_before_startup_result_gate_probe_for_test().await;

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

// The env guard owns a std mutex and is deliberately held across the probe's
// `.await`: mesh startup reads the process environment throughout, not only at
// entry, and this test runs on a single-threaded runtime where no other task
// can contend for it.
#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "current_thread")]
async fn failure_inside_startup_result_gate_drains_spawned_tasks() {
    let _env = mesh_startup_probe_env_guard();
    let probe = mesh_startup_failure_inside_startup_result_gate_probe_for_test().await;

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
