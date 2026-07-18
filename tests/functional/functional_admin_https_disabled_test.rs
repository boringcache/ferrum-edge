//! Functional tests for `FERRUM_ADMIN_HTTPS_PORT=0` (issue #2362).
//!
//! The helper truth table (`EnvConfig::admin_https_listener_enabled`) is
//! covered by unit tests. These tests prove the *mode-level side effect*: with
//! the disable sentinel set, a serving mode must not load admin TLS material at
//! all, so cert/key paths that do not exist cannot fail startup and no
//! ephemeral admin HTTPS socket is bound.
//!
//! CP mode is the probe: it is the cheapest mode to spawn as a real process
//! (SQLite + loopback gRPC, no peer gateway) and, before the fix, it took the
//! unconditional "TLS material configured ⇒ build the listener" branch that DP
//! and mesh mode share verbatim. The `else if let` gate is now identical in all
//! three, so CP is a faithful proxy for the shared shape.
//!
//! The pair is deliberate: the negative control proves the bogus TLS paths are
//! genuinely fatal when the listener IS enabled, so the positive test cannot
//! pass vacuously (e.g. if the paths silently resolved to something loadable).
//!
//! Both directions run on the shared [`TestGateway`] harness, which supplies
//! the properties these assertions depend on:
//!
//! - **Hermetic child environment** (`clear_env`): the child inherits only
//!   command lookup, home/temp, locale, and loader paths. That is load-bearing
//!   rather than hygiene — it is what removes an inherited `RUST_LOG` (which
//!   wins over `FERRUM_LOG_LEVEL`, because the binary builds its `EnvFilter`
//!   with `try_from_default_env()`), and the
//!   `FERRUM_ADMIN_TLS_CERT_SOURCE`/`FERRUM_ADMIN_TLS_KEY_SOURCE` overrides
//!   plus their `_VAULT`/`_AWS`/`_AZURE`/`_GCP`/`_FILE` external-secret
//!   suffixes, any of which would silently replace the deliberately missing
//!   paths these tests configure.
//! - **File-backed log capture** (`capture_output`): no pipe buffer to
//!   deadlock and no detached drainer thread on the test side. The child's own
//!   async log sink is still asynchronous, so the positive test waits for its
//!   marker through `wait_for_captured_output` rather than reading once.
//! - **Bounded retry** with fresh ports and a fresh temp dir/DB per attempt,
//!   and `Drop` cleanup of the child.
//!
//! Marked with `#[ignore]` — run with:
//!   cargo test --test functional_tests -- --ignored functional_admin_https_disabled

use crate::common::{DbType, TestGateway, TestGatewayBuilder, ephemeral_port};
use std::time::Duration;
use tempfile::TempDir;

/// Budget for "CP reaches full readiness" and for "CP aborts startup". Both
/// are seconds-scale locally; the headroom is for loaded CI runners.
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);

/// Budget for the gateway's async log worker to drain an already-emitted line
/// into the capture file. Sub-millisecond in practice; the headroom is for
/// loaded CI runners.
const LOG_FLUSH_TIMEOUT: Duration = Duration::from_secs(10);

/// Substring proving the gateway touched the admin TLS material in *either*
/// direction: the failure log ("Failed to load admin TLS configuration" /
/// "Invalid admin TLS configuration") and the success log ("Admin TLS
/// configuration loaded ...") both contain it. Matched case-insensitively.
const ADMIN_TLS_LOAD_MARKER: &str = "admin tls configuration";

/// Substring of the CP disable log. Asserted in the positive test so a pass
/// cannot be vacuous: it proves the port-0 branch actually executed rather
/// than the test merely failing to find a TLS log.
const ADMIN_HTTPS_DISABLED_MARKER: &str = "admin HTTPS listener disabled";

/// Paths for admin TLS material that does not exist, plus an empty
/// `ferrum.conf`.
///
/// The empty conf file is deliberate: with a cleared environment there is no
/// `FERRUM_CONF_PATH`, and the binary would fall back to discovering
/// `./ferrum.conf` relative to the test's working directory — the repository
/// root, which ships one. Pinning an empty file keeps the child's
/// configuration exactly what the builder sets.
struct MissingAdminTls {
    cert_path: String,
    key_path: String,
    conf_path: String,
    /// Kept alive so the paths above stay valid for the whole test.
    _temp_dir: TempDir,
}

fn missing_admin_tls() -> MissingAdminTls {
    let temp_dir = TempDir::new().expect("create temp dir");
    let conf_path = temp_dir.path().join("empty-ferrum.conf");
    std::fs::write(&conf_path, "").expect("write empty ferrum.conf");
    MissingAdminTls {
        cert_path: temp_dir
            .path()
            .join("does-not-exist.crt")
            .display()
            .to_string(),
        key_path: temp_dir
            .path()
            .join("does-not-exist.key")
            .display()
            .to_string(),
        conf_path: conf_path.display().to_string(),
        _temp_dir: temp_dir,
    }
}

/// CP-mode builder against SQLite with unloadable admin TLS material.
/// `admin_https_port` is the only variable between the two tests.
fn cp_builder(tls: &MissingAdminTls, admin_https_port: u16) -> TestGatewayBuilder {
    TestGateway::builder()
        .mode_cp(DbType::Sqlite, None)
        .clear_env()
        .capture_output()
        .log_level("info")
        .env("FERRUM_CONF_PATH", tls.conf_path.as_str())
        .env("FERRUM_ADMIN_BIND_ADDRESS", "127.0.0.1")
        .env("FERRUM_ADMIN_HTTPS_PORT", admin_https_port.to_string())
        // Configured but unloadable: the whole point of the test.
        .env("FERRUM_ADMIN_TLS_CERT_PATH", tls.cert_path.as_str())
        .env("FERRUM_ADMIN_TLS_KEY_PATH", tls.key_path.as_str())
        // Loopback plaintext gRPC is always permitted; set explicitly so the
        // secure-by-default transport gate is never the reason a run fails.
        .env("FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT", "true")
}

fn mentions_admin_tls_load(output: &str) -> bool {
    output.to_ascii_lowercase().contains(ADMIN_TLS_LOAD_MARKER)
}

// ── Test 1: port 0 suppresses admin TLS loading entirely ────────────────────

/// With `FERRUM_ADMIN_HTTPS_PORT=0`, CP must skip admin TLS loading, the reload
/// watcher, the startup signal, and the listener task — so cert/key paths that
/// do not exist are never opened and startup completes. Before the fix this
/// process exited with "Invalid admin TLS configuration".
///
/// The success condition is `/health` reporting `ready`, not a bare TCP accept
/// on the admin port. CP binds admin HTTP *before* the admin HTTPS branch and
/// the gRPC bind, and stores `startup_ready` only after `wait_for_start_signals`
/// — so a regression that still loads the bad TLS material (or a gRPC bind
/// failure) can satisfy a raw accept for a moment on its way to exiting, but
/// can never satisfy `ready`. `wait_for_ready` is asserted explicitly on top of
/// the harness's `/health` wait (which is a barrier only because `/health`
/// answers `503` until ready) so the barrier does not depend on that policy.
#[ignore]
#[tokio::test]
async fn functional_admin_https_disabled_port_zero_ignores_unloadable_tls() {
    let tls = missing_admin_tls();
    let mut gateway = cp_builder(&tls, 0)
        .spawn()
        .await
        .expect("CP must start with FERRUM_ADMIN_HTTPS_PORT=0 and unloadable admin TLS paths");

    gateway
        .wait_for_ready(STARTUP_TIMEOUT)
        .await
        .expect("CP must reach full startup readiness, not just an admin HTTP accept");
    assert!(
        gateway.is_running(),
        "CP exited after reporting ready with FERRUM_ADMIN_HTTPS_PORT=0"
    );

    // The admin HTTPS branch runs strictly before the readiness store, but the
    // gateway logs through an async `NonBlockingSink`: `ready` can be observed
    // before the log worker drains that line into the capture file. Poll for
    // the marker instead of reading once. Polling cannot weaken the assertion —
    // if the port-0 branch never ran, the marker never appears and this fails
    // at the deadline exactly as a single read would have.
    let output = gateway
        .wait_for_captured_output(
            |output| output.contains(ADMIN_HTTPS_DISABLED_MARKER),
            LOG_FLUSH_TIMEOUT,
        )
        .await
        .expect("read captured gateway output");
    assert!(
        output.contains(ADMIN_HTTPS_DISABLED_MARKER),
        "expected the port-0 disable log, so the assertion below is not vacuous; output: {output}"
    );
    // Asserted on the same snapshot: the disable log and the admin TLS logs come
    // from mutually exclusive arms of one startup step, so a run that reached
    // this line took the port-0 arm and never entered the loading arm.
    assert!(
        !mentions_admin_tls_load(&output),
        "CP loaded admin TLS material for a disabled HTTPS listener; output: {output}"
    );
}

// ── Test 2: negative control — nonzero port still fails on bad TLS ──────────

/// The same unloadable cert/key paths with a nonzero `FERRUM_ADMIN_HTTPS_PORT`
/// must still abort startup. Without this control, test 1 would pass even if
/// the paths were somehow loadable.
///
/// `spawn_expect_failure` reads the captured log files only after the child has
/// exited, so the expected error line cannot be missed by reaping the process
/// early.
#[ignore]
#[tokio::test]
async fn functional_admin_https_enabled_port_still_fails_on_unloadable_tls() {
    let tls = missing_admin_tls();
    // Nonzero and unlikely to collide, though collisions are harmless here:
    // admin TLS loading fails before any socket is bound.
    let admin_https_port = ephemeral_port().await.expect("reserve an admin HTTPS port");

    let failure = cp_builder(&tls, admin_https_port)
        .spawn_expect_failure(STARTUP_TIMEOUT)
        .await
        .expect("CP must refuse to start when an ENABLED admin HTTPS listener has bad TLS");

    let output = failure.combined_output();
    assert!(
        failure.status.is_some_and(|status| !status.success()),
        "CP must exit non-zero; status: {:?}, output: {output}",
        failure.status
    );
    assert!(
        mentions_admin_tls_load(&output),
        "expected an admin TLS configuration error in CP output, got: {output}"
    );
}
