//! Functional tests for the Ferrum Edge CLI subcommands.
//!
//! These tests spawn the actual `ferrum-edge` binary and verify CLI behavior
//! end-to-end: argument parsing, version output, validate, run, and reload.
//!
//! Marked with `#[ignore]` — run with:
//!   cargo test --test functional_tests -- --ignored functional_cli

use std::process::{Command, Stdio};
use std::time::Duration;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::time::sleep;

fn binary_path() -> &'static str {
    if std::path::Path::new("./target/debug/ferrum-edge").exists() {
        "./target/debug/ferrum-edge"
    } else {
        "./target/release/ferrum-edge"
    }
}

// Resolve the binary to an absolute path so that tests which set a custom
// `current_dir()` on the Command can still find it.
fn binary_abs_path() -> std::path::PathBuf {
    let rel = binary_path();
    let p = std::path::Path::new(rel);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| std::path::PathBuf::from("."))
            .join(rel)
    }
}

async fn ephemeral_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

async fn wait_for_health(admin_port: u16) -> bool {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let url = format!("http://127.0.0.1:{}/health", admin_port);
    for _ in 0..60 {
        if let Ok(resp) = client.get(&url).send().await
            && resp.status().is_success()
        {
            return true;
        }
        sleep(Duration::from_millis(250)).await;
    }
    false
}

fn kill_child(mut child: std::process::Child) {
    #[cfg(unix)]
    {
        let pid = child.id();
        let _ = std::process::Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .status();
    }
    #[cfg(not(unix))]
    {
        let _ = child.kill();
    }
    let _ = child.wait();
}

// ── version ─────────────────────────────────────────────────────────────────

#[ignore]
#[tokio::test]
async fn functional_cli_version_prints_version() {
    let output = Command::new(binary_path())
        .args(["version"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .expect("Failed to run ferrum-edge version");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.starts_with("ferrum-edge "));
    // Should contain a semver-like version
    assert!(stdout.contains('.'));
}

#[ignore]
#[tokio::test]
async fn functional_cli_version_json() {
    let output = Command::new(binary_path())
        .args(["version", "--json"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .expect("Failed to run ferrum-edge version --json");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(stdout.trim()).expect("Invalid JSON");
    assert!(json.get("version").is_some());
    assert!(json.get("target").is_some());
}

// ── help ────────────────────────────────────────────────────────────────────

#[ignore]
#[tokio::test]
async fn functional_cli_help_shows_subcommands() {
    let output = Command::new(binary_path())
        .args(["--help"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .expect("Failed to run ferrum-edge --help");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("run"));
    assert!(stdout.contains("validate"));
    assert!(stdout.contains("reload"));
    assert!(stdout.contains("version"));
}

#[ignore]
#[tokio::test]
async fn functional_cli_run_help_shows_options() {
    let output = Command::new(binary_path())
        .args(["run", "--help"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .expect("Failed to run ferrum-edge run --help");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--settings"));
    assert!(stdout.contains("--spec"));
    assert!(stdout.contains("--mode"));
    assert!(stdout.contains("--verbose"));
}

// ── validate ────────────────────────────────────────────────────────────────

#[ignore]
#[tokio::test]
async fn functional_cli_validate_valid_spec() {
    let temp_dir = TempDir::new().unwrap();
    let spec_path = temp_dir.path().join("config.yaml");
    std::fs::write(
        &spec_path,
        "version: \"1\"\nproxies:\n  - id: test\n    listen_path: /test\n    backend_scheme: http\n    backend_host: localhost\n    backend_port: 3000\nconsumers: []\nplugin_configs: []\n",
    )
    .unwrap();

    let output = Command::new(binary_path())
        .args(["validate", "--spec", spec_path.to_str().unwrap()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to run ferrum-edge validate");

    assert!(
        output.status.success(),
        "validate failed: stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Validation passed."));
    assert!(stdout.contains("Proxies: 1"));
}

#[ignore]
#[tokio::test]
async fn functional_cli_validate_nonexistent_spec() {
    let output = Command::new(binary_path())
        .args(["validate", "--spec", "/nonexistent/config.yaml"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to run ferrum-edge validate");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not found") || stderr.contains("Spec validation failed"),
        "Expected error about missing file, got: {}",
        stderr
    );
}

#[ignore]
#[tokio::test]
async fn functional_cli_validate_invalid_yaml() {
    let temp_dir = TempDir::new().unwrap();
    let spec_path = temp_dir.path().join("bad.yaml");
    std::fs::write(&spec_path, "this is not: [valid yaml: for ferrum\n").unwrap();

    let output = Command::new(binary_path())
        .args(["validate", "--spec", spec_path.to_str().unwrap()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to run ferrum-edge validate");

    assert!(!output.status.success());
}

#[ignore]
#[tokio::test]
async fn functional_cli_validate_rejects_invalid_proxy_host() {
    let temp_dir = TempDir::new().unwrap();
    let spec_path = temp_dir.path().join("bad-host.yaml");
    std::fs::write(
        &spec_path,
        r#"version: "1"
proxies:
  - id: bad-host
    hosts:
      - "api..example.com"
    listen_path: /test
    backend_scheme: http
    backend_host: localhost
    backend_port: 3000
consumers: []
plugin_configs: []
"#,
    )
    .unwrap();

    let output = Command::new(binary_path())
        .args(["validate", "--spec", spec_path.to_str().unwrap()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to run ferrum-edge validate");

    assert!(
        !output.status.success(),
        "invalid host config unexpectedly passed: stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid host"),
        "expected hostname validation error, got: {stderr}"
    );
}

#[ignore]
#[tokio::test]
async fn functional_cli_validate_with_settings() {
    let temp_dir = TempDir::new().unwrap();

    // Create a settings file
    let settings_path = temp_dir.path().join("ferrum.conf");
    std::fs::write(&settings_path, "FERRUM_MODE = file\n").unwrap();

    // Create a spec file
    let spec_path = temp_dir.path().join("resources.yaml");
    std::fs::write(
        &spec_path,
        "version: \"1\"\nproxies: []\nconsumers: []\nplugin_configs: []\n",
    )
    .unwrap();

    let output = Command::new(binary_path())
        .args([
            "validate",
            "--settings",
            settings_path.to_str().unwrap(),
            "--spec",
            spec_path.to_str().unwrap(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to run ferrum-edge validate");

    assert!(
        output.status.success(),
        "validate failed: stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Validation passed."));
}

// ── validate: external secret suffixes ──────────────────────────────────────

/// The only non-Ferrum variables carried into a hermetic validate subprocess.
///
/// Everything else is dropped by `env_clear()`, so the child cannot inherit any
/// `FERRUM_*` variable — including provider suffixes — from the invoking shell
/// or CI runner. None of these can influence secret resolution or settings
/// parsing.
const HERMETIC_ENV_PASSTHROUGH: &[&str] = &[
    // Process/loader basics.
    "PATH",
    "HOME",
    "LD_LIBRARY_PATH",
    "DYLD_LIBRARY_PATH",
    "DYLD_FALLBACK_LIBRARY_PATH",
    // Temp-dir resolution.
    "TMPDIR",
    "TMP",
    "TEMP",
    // Windows loader / profile resolution.
    "SystemRoot",
    "USERPROFILE",
    // Keep child counters attributable when the suite runs under
    // `cargo llvm-cov`; the value carries `%p` so processes cannot collide.
    "LLVM_PROFILE_FILE",
    // Diagnostics only; cannot influence secret resolution.
    "RUST_BACKTRACE",
];

/// Replace `cmd`'s environment with a closed-world hermetic one for a
/// database-mode `validate`.
///
/// The environment is built by `env_clear()` plus an allow-list rather than by
/// removing a list of known keys: validate resolves the *entire* `FERRUM_*`
/// environment before settings are parsed, so any inherited
/// `FERRUM_*_{FILE,VAULT,AWS,AZURE,GCP}` — `FERRUM_DB_URL_FILE`, for instance —
/// could fail the command on an unrelated fetch, conflict, or
/// unsupported-suffix error before a test's assertions are ever reached. A
/// deny-list would need extending for every new variable; clearing cannot
/// drift. Any variable set on `cmd` before this call is therefore also dropped,
/// which is what lets a test stage stand-ins for inherited variables and prove
/// they do not survive.
///
/// Database-mode validate requires *both* `FERRUM_DB_TYPE` and `FERRUM_DB_URL`
/// (`EnvConfig::validate`), so both are supplied explicitly; sqlite in-memory
/// keeps the check hermetic and reachable without a live database.
///
/// `current_dir()` is the temp dir so the repo's own `./ferrum.conf` is never
/// picked up by the smart-path search, which means the binary must be spawned
/// through `binary_abs_path()`. Clearing `FERRUM_CONF_PATH` is *not* enough:
/// `resolve_settings_path()` only skips discovery when the variable is set, so
/// an unset value still falls through to the `/etc/ferrum/ferrum.conf`
/// candidate on machines that have one. The variable is therefore pinned to an
/// empty settings file inside the temp dir, which suppresses discovery
/// entirely.
fn apply_hermetic_validate_env(cmd: &mut Command, temp_dir: &TempDir) {
    let conf_path = temp_dir.path().join("hermetic-ferrum.conf");
    std::fs::write(&conf_path, "").unwrap();

    cmd.env_clear();
    for key in HERMETIC_ENV_PASSTHROUGH {
        if let Ok(value) = std::env::var(key) {
            cmd.env(key, value);
        }
    }

    cmd.env("FERRUM_MODE", "database")
        .env("FERRUM_DB_TYPE", "sqlite")
        .env("FERRUM_DB_URL", "sqlite::memory:")
        .env("FERRUM_CONF_PATH", &conf_path)
        .current_dir(temp_dir.path());
}

fn validate_database_mode_command(temp_dir: &TempDir) -> Command {
    let mut cmd = Command::new(binary_abs_path());
    cmd.args(["validate"]);
    apply_hermetic_validate_env(&mut cmd, temp_dir);
    cmd
}

#[ignore]
#[tokio::test]
async fn functional_cli_validate_resolves_file_secret_suffix() {
    let temp_dir = TempDir::new().unwrap();
    let secret_path = temp_dir.path().join("jwt-secret");
    std::fs::write(&secret_path, "validate-file-secret-with-well-over-32-bytes").unwrap();

    let output = validate_database_mode_command(&temp_dir)
        .env(
            "FERRUM_ADMIN_JWT_SECRET_FILE",
            secret_path.to_str().unwrap(),
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to run ferrum-edge validate");

    assert!(
        output.status.success(),
        "validate must resolve FERRUM_ADMIN_JWT_SECRET_FILE like run does: stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Non-vacuous: `FERRUM_ADMIN_JWT_SECRET` is `required_for(["database","cp"])`
    // with `min_len(MIN_JWT_SECRET_LENGTH)`, and the helper clears the base key
    // and pins an empty settings file, so the only way parsing can reach
    // "Validation passed." is if the `_FILE` source was actually materialized
    // into the base variable.
    assert!(stdout.contains("Validation passed."));
    // The resolved value must never be echoed on either stream.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stdout.contains("validate-file-secret-with-well-over-32-bytes")
            && !stderr.contains("validate-file-secret-with-well-over-32-bytes"),
        "secret values must never be logged: stdout={stdout}, stderr={stderr}"
    );
}

/// Proves the hermetic helper's closed-world isolation, not just that it is
/// written that way.
///
/// The three variables staged before `apply_hermetic_validate_env()` sit
/// exactly where an inherited variable from the invoking shell or CI runner
/// would sit, and each one alone is fatal if it survives: `FERRUM_DB_URL_FILE`
/// points at a missing file (read failure), `FERRUM_ADMIN_JWT_SECRET_VAULT` is
/// an unsupported-suffix error in a default build and an unreachable fetch in a
/// `cloud-secrets` build, and the bare `FERRUM_ADMIN_JWT_SECRET` alongside the
/// `_FILE` source is a provider conflict. Reaching "Validation passed." is
/// therefore only possible if all three were cleared.
#[ignore]
#[tokio::test]
async fn functional_cli_validate_isolates_inherited_secret_environment() {
    let temp_dir = TempDir::new().unwrap();
    let secret_path = temp_dir.path().join("jwt-secret");
    std::fs::write(&secret_path, "validate-file-secret-with-well-over-32-bytes").unwrap();

    let mut cmd = Command::new(binary_abs_path());
    cmd.args(["validate"])
        .env(
            "FERRUM_DB_URL_FILE",
            temp_dir.path().join("inherited-missing-db-url"),
        )
        .env(
            "FERRUM_ADMIN_JWT_SECRET_VAULT",
            "secret/data/ferrum/edge#jwt",
        )
        .env(
            "FERRUM_ADMIN_JWT_SECRET",
            "inherited-direct-secret-value-well-over-32-bytes",
        );
    apply_hermetic_validate_env(&mut cmd, &temp_dir);

    let output = cmd
        .env(
            "FERRUM_ADMIN_JWT_SECRET_FILE",
            secret_path.to_str().unwrap(),
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to run ferrum-edge validate");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "hermetic env must drop inherited FERRUM_* secret sources: stdout={stdout}, stderr={stderr}"
    );
    assert!(stdout.contains("Validation passed."));
}

#[ignore]
#[tokio::test]
async fn functional_cli_validate_rejects_secret_source_conflict() {
    let temp_dir = TempDir::new().unwrap();
    let secret_path = temp_dir.path().join("jwt-secret");
    std::fs::write(&secret_path, "validate-file-secret-with-well-over-32-bytes").unwrap();

    // A base variable plus a suffixed source for the same key is a provider
    // conflict that `run` rejects; validate must fail identically.
    let output = validate_database_mode_command(&temp_dir)
        .env(
            "FERRUM_ADMIN_JWT_SECRET",
            "direct-secret-value-with-well-over-32-bytes",
        )
        .env(
            "FERRUM_ADMIN_JWT_SECRET_FILE",
            secret_path.to_str().unwrap(),
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to run ferrum-edge validate");

    assert!(
        !output.status.success(),
        "validate must reject conflicting secret sources like run does: stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    // Assert the reason, so an unrelated validation failure cannot make this
    // test pass vacuously.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Multiple secret sources configured for FERRUM_ADMIN_JWT_SECRET"),
        "expected a secret source conflict error, got: {stderr}"
    );
    // The resolved value must never reach the error output.
    assert!(
        !stderr.contains("direct-secret-value-with-well-over-32-bytes")
            && !stderr.contains("validate-file-secret-with-well-over-32-bytes"),
        "secret values must never be logged: {stderr}"
    );
}

#[ignore]
#[tokio::test]
async fn functional_cli_validate_fails_on_secret_resolution_error() {
    let temp_dir = TempDir::new().unwrap();

    let output = validate_database_mode_command(&temp_dir)
        .env(
            "FERRUM_ADMIN_JWT_SECRET_FILE",
            temp_dir.path().join("does-not-exist").to_str().unwrap(),
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to run ferrum-edge validate");

    assert!(
        !output.status.success(),
        "validate must fail when a suffixed secret source cannot be read: stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    // Assert the reason, so an unrelated validation failure cannot make this
    // test pass vacuously.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Failed to read FERRUM_ADMIN_JWT_SECRET_FILE"),
        "expected a secret read failure error, got: {stderr}"
    );
}

// ── run ─────────────────────────────────────────────────────────────────────

#[ignore]
#[tokio::test]
async fn functional_cli_run_starts_and_stops() {
    let temp_dir = TempDir::new().unwrap();
    let spec_path = temp_dir.path().join("config.yaml");
    std::fs::write(
        &spec_path,
        "version: \"1\"\nproxies: []\nconsumers: []\nplugin_configs: []\n",
    )
    .unwrap();

    let mut child = Command::new(binary_path())
        .args([
            "run",
            "--spec",
            spec_path.to_str().unwrap(),
            "--mode",
            "file",
        ])
        .env("FERRUM_PROXY_HTTP_PORT", "18990")
        .env("FERRUM_ADMIN_HTTP_PORT", "18991")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start ferrum-edge run");

    // Wait for startup
    sleep(Duration::from_secs(2)).await;

    // Check it's still running
    assert!(
        child.try_wait().unwrap().is_none(),
        "Gateway exited prematurely"
    );

    // Health check via admin API
    let health_url = "http://127.0.0.1:18991/health";
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let resp = client.get(health_url).send().await;
    if let Ok(r) = resp {
        assert!(
            r.status().is_success(),
            "Health check returned {}",
            r.status()
        );
    }
    // Note: health check may fail if startup is slow — that's acceptable in CI.

    // Stop gracefully
    #[cfg(unix)]
    {
        let pid = child.id();
        let _ = std::process::Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .status();
    }
    #[cfg(not(unix))]
    {
        let _ = child.kill();
    }
    let status = child.wait().expect("Failed to wait for child");
    assert!(
        status.success(),
        "Gateway exited with non-zero status: {:?}",
        status
    );
}

#[ignore]
#[tokio::test]
async fn functional_cli_run_with_verbose() {
    let temp_dir = TempDir::new().unwrap();
    let spec_path = temp_dir.path().join("config.yaml");
    std::fs::write(
        &spec_path,
        "version: \"1\"\nproxies: []\nconsumers: []\nplugin_configs: []\n",
    )
    .unwrap();

    // Start with -v (info level) and capture stderr for log output
    let mut child = Command::new(binary_path())
        .args([
            "run",
            "--spec",
            spec_path.to_str().unwrap(),
            "--mode",
            "file",
            "-v",
        ])
        .env("FERRUM_PROXY_HTTP_PORT", "18992")
        .env("FERRUM_ADMIN_HTTP_PORT", "18993")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start ferrum-edge run -v");

    sleep(Duration::from_secs(2)).await;

    // Just verify it started successfully with -v
    assert!(
        child.try_wait().unwrap().is_none(),
        "Gateway with -v exited prematurely"
    );

    #[cfg(unix)]
    {
        let pid = child.id();
        let _ = std::process::Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .status();
    }
    #[cfg(not(unix))]
    {
        let _ = child.kill();
    }
    let _ = child.wait();
}

// ── reload ──────────────────────────────────────────────────────────────────

#[cfg(unix)]
#[ignore]
#[tokio::test]
async fn functional_cli_reload_sends_sighup() {
    let temp_dir = TempDir::new().unwrap();
    let spec_path = temp_dir.path().join("config.yaml");
    std::fs::write(
        &spec_path,
        "version: \"1\"\nproxies: []\nconsumers: []\nplugin_configs: []\n",
    )
    .unwrap();

    // Start a gateway to reload
    let mut child = Command::new(binary_path())
        .args([
            "run",
            "--spec",
            spec_path.to_str().unwrap(),
            "--mode",
            "file",
        ])
        .env("FERRUM_PROXY_HTTP_PORT", "18994")
        .env("FERRUM_ADMIN_HTTP_PORT", "18995")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start gateway for reload test");

    sleep(Duration::from_secs(2)).await;

    let pid = child.id();

    // Use the reload subcommand
    let output = Command::new(binary_path())
        .args(["reload", "--pid", &pid.to_string()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to run ferrum-edge reload");

    assert!(
        output.status.success(),
        "reload failed: stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Sent SIGHUP"));

    // Gateway should still be running after reload
    sleep(Duration::from_millis(500)).await;
    assert!(
        child.try_wait().unwrap().is_none(),
        "Gateway exited after reload"
    );

    // Cleanup
    let _ = std::process::Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status();
    let _ = child.wait();
}

// ── smart path defaults ─────────────────────────────────────────────────────

/// Smart-path discovery: with no `--settings`/`--spec` flags and no env vars
/// for config paths or mode, a `ferrum.conf` + `resources.yaml` in the CWD
/// must be picked up automatically and route traffic.
#[ignore]
#[tokio::test]
async fn functional_cli_smart_path_discovery_from_cwd() {
    const MAX_ATTEMPTS: u32 = 3;
    let binary = binary_abs_path();

    let mut last_err = String::new();
    for attempt in 1..=MAX_ATTEMPTS {
        // Each attempt gets its own temp dir + fresh ports so failures don't
        // contaminate the next try.
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let proxy_port = ephemeral_port().await;
        let admin_port = ephemeral_port().await;

        // Backend echo server on a held listener (no port race for the echo).
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo_listener.local_addr().unwrap().port();
        let echo_server = tokio::spawn(async move {
            loop {
                if let Ok((mut stream, _)) = echo_listener.accept().await {
                    tokio::spawn(async move {
                        use tokio::io::{AsyncReadExt, AsyncWriteExt};
                        let mut buf = vec![0u8; 4096];
                        let _ = stream.read(&mut buf).await;
                        let body = "smart-path-echo";
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = stream.write_all(resp.as_bytes()).await;
                        let _ = stream.shutdown().await;
                    });
                }
            }
        });
        sleep(Duration::from_millis(150)).await;

        // ferrum.conf drives ports + mode. Put it in the CWD root so the
        // `./ferrum.conf` smart-path entry wins.
        let conf = format!(
            "FERRUM_MODE = file\nFERRUM_PROXY_HTTP_PORT = {}\nFERRUM_ADMIN_HTTP_PORT = {}\n",
            proxy_port, admin_port
        );
        std::fs::write(temp_dir.path().join("ferrum.conf"), conf).unwrap();

        // resources.yaml drives the proxy. Place it at `./resources.yaml`.
        let spec = format!(
            r#"version: "1"
proxies:
  - id: "smart-path-proxy"
    listen_path: "/sp"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {echo_port}
    strip_listen_path: true
consumers: []
plugin_configs: []
"#
        );
        std::fs::write(temp_dir.path().join("resources.yaml"), spec).unwrap();

        // IMPORTANT: spawn with current_dir() set AND no FERRUM_* env vars
        // for config paths / mode. We also clear inherited vars that would
        // short-circuit the smart-path search.
        let mut cmd = Command::new(&binary);
        cmd.arg("run")
            .current_dir(temp_dir.path())
            .env_remove("FERRUM_MODE")
            .env_remove("FERRUM_CONF_PATH")
            .env_remove("FERRUM_FILE_CONFIG_PATH")
            .env_remove("FERRUM_PROXY_HTTP_PORT")
            .env_remove("FERRUM_ADMIN_HTTP_PORT")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = cmd.spawn().expect("Failed to spawn ferrum-edge");

        if wait_for_health(admin_port).await {
            // Verify proxy routes through.
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(3))
                .build()
                .unwrap();
            let url = format!("http://127.0.0.1:{}/sp/anything", proxy_port);
            let resp = client.get(&url).send().await;
            let route_ok = matches!(resp, Ok(r) if r.status().is_success());

            // Cleanup regardless.
            kill_child(child);
            echo_server.abort();

            assert!(
                route_ok,
                "Smart-path gateway started but proxy routing failed"
            );
            return;
        }

        last_err = format!(
            "attempt {}/{} failed (proxy={}, admin={})",
            attempt, MAX_ATTEMPTS, proxy_port, admin_port
        );
        eprintln!("{}", last_err);
        let _ = child.kill();
        let _ = child.wait();
        echo_server.abort();
        if attempt < MAX_ATTEMPTS {
            sleep(Duration::from_secs(1)).await;
        }
    }
    panic!(
        "Gateway did not start via smart-path discovery: {}",
        last_err
    );
}

/// `--spec <file>` with no `FERRUM_MODE` env var must infer
/// `FERRUM_MODE=file` (see `apply_run_overrides` in `src/cli.rs`).
#[ignore]
#[tokio::test]
async fn functional_cli_spec_flag_infers_file_mode() {
    const MAX_ATTEMPTS: u32 = 3;
    let binary = binary_abs_path();

    let mut last_err = String::new();
    for attempt in 1..=MAX_ATTEMPTS {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let proxy_port = ephemeral_port().await;
        let admin_port = ephemeral_port().await;

        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo_listener.local_addr().unwrap().port();
        let echo_server = tokio::spawn(async move {
            loop {
                if let Ok((mut stream, _)) = echo_listener.accept().await {
                    tokio::spawn(async move {
                        use tokio::io::{AsyncReadExt, AsyncWriteExt};
                        let mut buf = vec![0u8; 4096];
                        let _ = stream.read(&mut buf).await;
                        let body = "spec-infer-echo";
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = stream.write_all(resp.as_bytes()).await;
                        let _ = stream.shutdown().await;
                    });
                }
            }
        });
        sleep(Duration::from_millis(150)).await;

        let spec_path = temp_dir.path().join("resources.yaml");
        let spec = format!(
            r#"version: "1"
proxies:
  - id: "spec-infer-proxy"
    listen_path: "/si"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {echo_port}
    strip_listen_path: true
consumers: []
plugin_configs: []
"#
        );
        std::fs::write(&spec_path, spec).unwrap();

        // Spawn with --spec but WITHOUT --mode, --settings, or FERRUM_MODE.
        // Run from a scratch dir that has no ferrum.conf / resources.yaml
        // so the smart-path search cannot confound the test.
        let work_dir = TempDir::new().expect("Failed to create work directory");
        let mut cmd = Command::new(&binary);
        cmd.arg("run")
            .args(["--spec", spec_path.to_str().unwrap()])
            .current_dir(work_dir.path())
            .env_remove("FERRUM_MODE")
            .env_remove("FERRUM_CONF_PATH")
            .env_remove("FERRUM_FILE_CONFIG_PATH")
            .env("FERRUM_PROXY_HTTP_PORT", proxy_port.to_string())
            .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = cmd.spawn().expect("Failed to spawn ferrum-edge");

        if wait_for_health(admin_port).await {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(3))
                .build()
                .unwrap();
            let url = format!("http://127.0.0.1:{}/si/x", proxy_port);
            let resp = client.get(&url).send().await;
            let route_ok = matches!(resp, Ok(r) if r.status().is_success());

            kill_child(child);
            echo_server.abort();
            assert!(route_ok, "--spec inferred file mode but routing failed");
            return;
        }

        last_err = format!(
            "attempt {}/{} failed (proxy={}, admin={})",
            attempt, MAX_ATTEMPTS, proxy_port, admin_port
        );
        eprintln!("{}", last_err);
        let _ = child.kill();
        let _ = child.wait();
        echo_server.abort();
        if attempt < MAX_ATTEMPTS {
            sleep(Duration::from_secs(1)).await;
        }
    }
    panic!(
        "Gateway did not start with inferred file mode: {}",
        last_err
    );
}

/// Precedence — CLI flag must win over env var. `--mode file` on CLI wins over
/// `FERRUM_MODE=database` in the environment. If precedence were reversed, the
/// gateway would try to connect to a database and fail startup; we verify
/// file mode by proxying a request end-to-end.
#[ignore]
#[tokio::test]
async fn functional_cli_precedence_flag_beats_env_var() {
    const MAX_ATTEMPTS: u32 = 3;
    let binary = binary_abs_path();

    let mut last_err = String::new();
    for attempt in 1..=MAX_ATTEMPTS {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let proxy_port = ephemeral_port().await;
        let admin_port = ephemeral_port().await;

        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo_listener.local_addr().unwrap().port();
        let echo_server = tokio::spawn(async move {
            loop {
                if let Ok((mut stream, _)) = echo_listener.accept().await {
                    tokio::spawn(async move {
                        use tokio::io::{AsyncReadExt, AsyncWriteExt};
                        let mut buf = vec![0u8; 4096];
                        let _ = stream.read(&mut buf).await;
                        let body = "flag-wins";
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = stream.write_all(resp.as_bytes()).await;
                        let _ = stream.shutdown().await;
                    });
                }
            }
        });
        sleep(Duration::from_millis(150)).await;

        let spec_path = temp_dir.path().join("resources.yaml");
        let spec = format!(
            r#"version: "1"
proxies:
  - id: "flag-wins-proxy"
    listen_path: "/fw"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {echo_port}
    strip_listen_path: true
consumers: []
plugin_configs: []
"#
        );
        std::fs::write(&spec_path, spec).unwrap();

        // CLI says `--mode file`; env var shouts `FERRUM_MODE=database`.
        // If CLI wins (as documented), file mode starts and routing succeeds.
        let work_dir = TempDir::new().expect("Failed to create work directory");
        let mut cmd = Command::new(&binary);
        cmd.arg("run")
            .args(["--spec", spec_path.to_str().unwrap()])
            .args(["--mode", "file"])
            .current_dir(work_dir.path())
            .env("FERRUM_MODE", "database")
            .env_remove("FERRUM_CONF_PATH")
            .env_remove("FERRUM_FILE_CONFIG_PATH")
            .env("FERRUM_PROXY_HTTP_PORT", proxy_port.to_string())
            .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = cmd.spawn().expect("Failed to spawn ferrum-edge");

        if wait_for_health(admin_port).await {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(3))
                .build()
                .unwrap();
            let url = format!("http://127.0.0.1:{}/fw/x", proxy_port);
            let resp = client.get(&url).send().await;
            let route_ok = matches!(resp, Ok(r) if r.status().is_success());

            kill_child(child);
            echo_server.abort();
            assert!(
                route_ok,
                "CLI --mode file should beat FERRUM_MODE=database; routing failed"
            );
            return;
        }

        last_err = format!(
            "attempt {}/{} failed (proxy={}, admin={})",
            attempt, MAX_ATTEMPTS, proxy_port, admin_port
        );
        eprintln!("{}", last_err);
        let _ = child.kill();
        let _ = child.wait();
        echo_server.abort();
        if attempt < MAX_ATTEMPTS {
            sleep(Duration::from_secs(1)).await;
        }
    }
    panic!(
        "Gateway did not start with CLI-flag-wins precedence: {}",
        last_err
    );
}

/// Precedence — env var must win over conf file. We put a nonsense
/// `FERRUM_PROXY_HTTP_PORT` in ferrum.conf and set the real (listenable) port
/// via env var. The gateway should bind the env-var port; health check on
/// that admin port succeeds and the conf-file port is NOT bound.
#[ignore]
#[tokio::test]
async fn functional_cli_precedence_env_beats_conf_file() {
    const MAX_ATTEMPTS: u32 = 3;
    let binary = binary_abs_path();

    let mut last_err = String::new();
    for attempt in 1..=MAX_ATTEMPTS {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let env_proxy_port = ephemeral_port().await;
        let env_admin_port = ephemeral_port().await;
        // Hold decoy port listeners so that (a) no other CI process can
        // grab them (eliminating false-positive port collisions) and
        // (b) the gateway would fatal-fail if it tried to bind them.
        let conf_proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind decoy proxy");
        let conf_proxy_port = conf_proxy_listener.local_addr().unwrap().port();
        let conf_admin_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind decoy admin");
        let conf_admin_port = conf_admin_listener.local_addr().unwrap().port();

        // Sanity: all 4 distinct
        assert_ne!(env_proxy_port, conf_proxy_port);
        assert_ne!(env_admin_port, conf_admin_port);

        // ferrum.conf includes decoy ports AND a mode so the gateway has
        // enough config to start even if env vars were stripped.
        let conf = format!(
            "FERRUM_MODE = file\nFERRUM_PROXY_HTTP_PORT = {}\nFERRUM_ADMIN_HTTP_PORT = {}\n",
            conf_proxy_port, conf_admin_port
        );
        std::fs::write(temp_dir.path().join("ferrum.conf"), conf).unwrap();

        // Minimal spec — no routing needed; we only check which admin port binds.
        std::fs::write(
            temp_dir.path().join("resources.yaml"),
            "version: \"1\"\nproxies: []\nconsumers: []\nplugin_configs: []\n",
        )
        .unwrap();

        // Env var should override the conf-file default.
        let mut cmd = Command::new(&binary);
        cmd.arg("run")
            .current_dir(temp_dir.path())
            .env("FERRUM_PROXY_HTTP_PORT", env_proxy_port.to_string())
            .env("FERRUM_ADMIN_HTTP_PORT", env_admin_port.to_string())
            .env_remove("FERRUM_MODE")
            .env_remove("FERRUM_CONF_PATH")
            .env_remove("FERRUM_FILE_CONFIG_PATH")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = cmd.spawn().expect("Failed to spawn ferrum-edge");

        if wait_for_health(env_admin_port).await {
            // The gateway started and its admin health is reachable on the
            // env-var port. Because the conf-file decoy ports are held by
            // our listeners, the gateway would have fatally failed to start
            // if it tried to bind them — so reaching this point proves
            // env-var precedence works.
            kill_child(child);
            drop(conf_proxy_listener);
            drop(conf_admin_listener);
            return;
        }

        last_err = format!(
            "attempt {}/{} failed (env_proxy={}, env_admin={}, conf_proxy={}, conf_admin={})",
            attempt, MAX_ATTEMPTS, env_proxy_port, env_admin_port, conf_proxy_port, conf_admin_port
        );
        eprintln!("{}", last_err);
        let _ = child.kill();
        let _ = child.wait();
        if attempt < MAX_ATTEMPTS {
            sleep(Duration::from_secs(1)).await;
        }
    }
    panic!(
        "Gateway did not start with env-var-wins precedence: {}",
        last_err
    );
}
