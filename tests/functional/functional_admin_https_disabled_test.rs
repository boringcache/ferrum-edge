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
//! Marked with `#[ignore]` — run with:
//!   cargo test --test functional_tests -- --ignored functional_admin_https_disabled

use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tempfile::TempDir;

/// Attempts for the port-race retry wrapper. Bind-drop-rebind can lose the
/// reserved port to a parallel test between `free_port()` and the child's bind.
const SPAWN_ATTEMPTS: usize = 3;

/// Locate the compiled `ferrum-edge` binary, preferring debug, then release.
fn binary_path() -> &'static str {
    if std::path::Path::new("./target/debug/ferrum-edge").exists() {
        "./target/debug/ferrum-edge"
    } else {
        "./target/release/ferrum-edge"
    }
}

/// Reserve an OS-assigned loopback port and release it for the child to bind.
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral loopback port");
    let port = listener.local_addr().expect("read local addr").port();
    drop(listener);
    port
}

/// A spawned gateway whose stdout/stderr are drained by background threads.
///
/// Draining from the moment of spawn matters: the gateway logs continuously,
/// and a `Stdio::piped()` pipe that is only read after the fact can fill its
/// buffer and deadlock the child mid-test.
struct Gateway {
    child: Child,
    output: Arc<Mutex<String>>,
}

impl Gateway {
    fn output(&self) -> String {
        self.output.lock().expect("output mutex").clone()
    }

    /// Poll a loopback TCP connect until it succeeds or the deadline passes.
    fn wait_for_admin_http(&self, port: u16, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        false
    }

    fn is_running(&mut self) -> bool {
        self.child.try_wait().expect("poll child").is_none()
    }

    /// Wait up to `timeout` for the child to exit. `None` on timeout, so a
    /// still-running gateway fails an assertion instead of hanging the suite.
    fn wait_for_exit(&mut self, timeout: Duration) -> Option<std::process::ExitStatus> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Some(status) = self.child.try_wait().expect("poll child") {
                return Some(status);
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        None
    }
}

impl Drop for Gateway {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Spawn CP mode against a fresh SQLite database with admin TLS paths that do
/// not exist. `admin_https_port` is the only variable between the two tests.
fn spawn_cp(temp_dir: &TempDir, admin_https_port: u16, admin_http_port: u16) -> Gateway {
    let db_path = temp_dir.path().join("cp.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.display());
    let missing_cert = temp_dir.path().join("does-not-exist.crt");
    let missing_key = temp_dir.path().join("does-not-exist.key");

    let mut child = Command::new(binary_path())
        .env("FERRUM_MODE", "cp")
        .env("FERRUM_DB_TYPE", "sqlite")
        .env("FERRUM_DB_URL", &db_url)
        .env("FERRUM_LOG_LEVEL", "info")
        .env(
            "FERRUM_ADMIN_JWT_SECRET",
            "functional-admin-https-disabled-secret-key-1234567890",
        )
        .env(
            "FERRUM_CP_DP_GRPC_JWT_SECRET",
            "functional-admin-https-disabled-grpc-secret-1234567890",
        )
        .env("FERRUM_ADMIN_BIND_ADDRESS", "127.0.0.1")
        .env("FERRUM_ADMIN_HTTP_PORT", admin_http_port.to_string())
        .env("FERRUM_ADMIN_HTTPS_PORT", admin_https_port.to_string())
        // Configured but unloadable: the whole point of the test.
        .env(
            "FERRUM_ADMIN_TLS_CERT_PATH",
            missing_cert.display().to_string(),
        )
        .env(
            "FERRUM_ADMIN_TLS_KEY_PATH",
            missing_key.display().to_string(),
        )
        .env(
            "FERRUM_CP_GRPC_LISTEN_ADDR",
            format!("127.0.0.1:{}", free_port()),
        )
        // Loopback plaintext gRPC is always permitted; set explicitly so the
        // secure-by-default transport gate is never the reason a run fails.
        .env("FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT", "true")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ferrum-edge cp process");

    let output = Arc::new(Mutex::new(String::new()));
    for pipe in [
        child.stdout.take().map(PipeSource::Out),
        child.stderr.take().map(PipeSource::Err),
    ]
    .into_iter()
    .flatten()
    {
        let sink = Arc::clone(&output);
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            let mut reader = pipe;
            while let Ok(n) = reader.read(&mut buf) {
                if n == 0 {
                    break;
                }
                let chunk = String::from_utf8_lossy(&buf[..n]).into_owned();
                sink.lock().expect("output mutex").push_str(&chunk);
            }
        });
    }

    Gateway { child, output }
}

/// Tiny enum so both pipe handles can share one draining loop.
enum PipeSource {
    Out(std::process::ChildStdout),
    Err(std::process::ChildStderr),
}

impl Read for PipeSource {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            PipeSource::Out(p) => p.read(buf),
            PipeSource::Err(p) => p.read(buf),
        }
    }
}

/// Whether the gateway's output shows it touched the admin TLS material at
/// all, in either the success or the failure direction.
fn mentions_admin_tls_load(output: &str) -> bool {
    let lowered = output.to_ascii_lowercase();
    lowered.contains("admin tls configuration")
}

// ── Test 1: port 0 suppresses admin TLS loading entirely ────────────────────

/// With `FERRUM_ADMIN_HTTPS_PORT=0`, CP must skip admin TLS loading, the reload
/// watcher, the startup signal, and the listener task — so cert/key paths that
/// do not exist are never opened and startup succeeds. Before the fix this
/// process exited with "Invalid admin TLS configuration".
#[ignore]
#[test]
fn functional_admin_https_disabled_port_zero_ignores_unloadable_tls() {
    let mut last_output = String::new();

    for attempt in 1..=SPAWN_ATTEMPTS {
        // Fresh ports AND a fresh temp dir/DB per attempt: a killed SQLite can
        // leave WAL state behind.
        let temp_dir = TempDir::new().expect("create temp dir");
        let admin_http_port = free_port();
        let mut gateway = spawn_cp(&temp_dir, 0, admin_http_port);

        let came_up = gateway.wait_for_admin_http(admin_http_port, Duration::from_secs(30));
        let still_running = gateway.is_running();
        last_output = gateway.output();

        if came_up && still_running {
            // Case-insensitive: catches both the failure log ("Failed to load
            // admin TLS configuration") and the success log ("Admin TLS
            // configuration loaded ..."). Neither may appear — a disabled
            // listener must not touch the material at all.
            assert!(
                !mentions_admin_tls_load(&last_output),
                "CP loaded admin TLS material for a disabled HTTPS listener; \
                 output: {last_output}"
            );
            return;
        }

        eprintln!(
            "attempt {attempt}/{SPAWN_ATTEMPTS} did not reach a serving CP \
             (came_up={came_up}, still_running={still_running}); retrying"
        );
    }

    panic!(
        "CP never served admin HTTP with FERRUM_ADMIN_HTTPS_PORT=0 and unloadable \
         admin TLS paths after {SPAWN_ATTEMPTS} attempts; last output: {last_output}"
    );
}

// ── Test 2: negative control — nonzero port still fails on bad TLS ──────────

/// The same unloadable cert/key paths with a nonzero `FERRUM_ADMIN_HTTPS_PORT`
/// must still abort startup. Without this control, test 1 would pass even if
/// the paths were somehow loadable.
///
/// No port-race retry here: this test only asserts that startup fails, and a
/// lost port would make it fail for a *different* reason, which the output
/// assertion catches rather than papers over.
#[ignore]
#[test]
fn functional_admin_https_enabled_port_still_fails_on_unloadable_tls() {
    let temp_dir = TempDir::new().expect("create temp dir");
    let mut gateway = spawn_cp(&temp_dir, free_port(), free_port());

    let status = gateway.wait_for_exit(Duration::from_secs(30));
    let output = gateway.output();

    let status = status.unwrap_or_else(|| {
        panic!(
            "CP must refuse to start when the ENABLED admin HTTPS listener has \
             unloadable TLS material, but it was still running; output: {output}"
        )
    });
    assert!(
        !status.success(),
        "CP exited successfully despite unloadable TLS on an enabled admin HTTPS \
         listener; status: {status:?}, output: {output}"
    );
    assert!(
        mentions_admin_tls_load(&output),
        "expected an admin TLS configuration error in CP output, got: {output}"
    );
}
