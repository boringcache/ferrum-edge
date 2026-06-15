//! Startup smoke tests: boot the real `ferrum-edge` binary in database mode
//! with `FERRUM_ADMIN_JWT_SECRET` supplied by an external secret provider, and
//! assert the gateway comes up, `/health` responds, the provider source is
//! logged, and the secret value never appears in the logs.
//!
//! These spawn the binary, so they are `#[ignore]` (run with `--ignored`, after
//! `cargo build --bin ferrum-edge`) and self-skip when their fake/emulator is
//! unavailable. They are intentionally minimal — the resolver-level tests in
//! the sibling modules carry the detailed coverage.
//!
//! Azure has no binary smoke test on purpose: the gateway's resolver path
//! constructs a real `ClientSecretCredential` (Entra ID), which a local fake
//! cannot satisfy without a real tenant. Azure is covered at the fetch level in
//! `azure_backend` via an injected dummy token instead.

#![allow(dead_code)] // some helpers are only used by feature-gated smoke tests

use serial_test::serial;
use std::io::Read;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::TempDir;

/// A 40-char admin JWT secret (>= the 32-char minimum DB/CP mode requires).
const SMOKE_SECRET: &str = "smoke-test-admin-secret-0123456789abcde0";

/// Locate the freshly-built `ferrum-edge` binary next to the test runner.
fn locate_binary() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    // exe is .../target/<profile>/deps/secrets_functional-<hash>
    for ancestor in exe.ancestors().skip(1).take(3) {
        let candidate = ancestor.join("ferrum-edge");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

/// A spawned gateway process whose stdout/stderr are captured to files.
struct GatewaySmoke {
    child: Child,
    admin_port: u16,
    stdout_path: PathBuf,
    _tmp: TempDir,
}

impl GatewaySmoke {
    /// Spawn the gateway in database/SQLite mode with the given extra env. The
    /// caller supplies the provider indirection vars
    /// (e.g. `FERRUM_ADMIN_JWT_SECRET_FILE`).
    fn spawn(bin: &PathBuf, extra_env: &[(String, String)]) -> std::io::Result<Self> {
        let tmp = TempDir::new()?;
        let admin_port = free_port();
        let proxy_port = free_port();
        let stdout_path = tmp.path().join("stdout.log");
        let stderr_path = tmp.path().join("stderr.log");
        let db_url = format!("sqlite:{}?mode=rwc", tmp.path().join("smoke.db").display());

        let stdout = std::fs::File::create(&stdout_path)?;
        let stderr = std::fs::File::create(&stderr_path)?;

        let mut cmd = Command::new(bin);
        cmd.arg("run")
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", std::env::var("HOME").unwrap_or_default())
            .env("RUST_LOG", "info")
            .env("FERRUM_LOG_LEVEL", "info")
            .env("FERRUM_MODE", "database")
            .env("FERRUM_DB_TYPE", "sqlite")
            .env("FERRUM_DB_URL", db_url)
            .env("FERRUM_NAMESPACE", "ferrum")
            .env("FERRUM_POOL_WARMUP_ENABLED", "false")
            .env("FERRUM_PROXY_HTTP_PORT", proxy_port.to_string())
            .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string());
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        let child = cmd
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()?;

        Ok(Self {
            child,
            admin_port,
            stdout_path,
            _tmp: tmp,
        })
    }

    /// Poll `/health` until it answers or the deadline passes.
    async fn wait_for_health(&self, timeout: Duration) -> bool {
        let client = reqwest::Client::new();
        let url = format!("http://127.0.0.1:{}/health", self.admin_port);
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Ok(resp) = client.get(&url).send().await
                && resp.status().is_success()
            {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        false
    }

    fn captured_logs(&self) -> String {
        let mut out = String::new();
        if let Ok(mut f) = std::fs::File::open(&self.stdout_path) {
            let _ = f.read_to_string(&mut out);
        }
        out
    }
}

impl Drop for GatewaySmoke {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Shared assertions for a successful provider-backed startup.
async fn assert_healthy_and_clean(mut gw: GatewaySmoke, source_label: &str) {
    let healthy = gw.wait_for_health(Duration::from_secs(20)).await;
    let logs = gw.captured_logs();
    assert!(healthy, "gateway did not become healthy; logs:\n{logs}");
    assert!(
        logs.contains(&format!(
            "Loaded FERRUM_ADMIN_JWT_SECRET from {source_label}"
        )),
        "logs should record the provider source '{source_label}'; logs:\n{logs}"
    );
    assert!(
        !logs.contains(SMOKE_SECRET),
        "the resolved secret value must never appear in logs"
    );
    let _ = gw.child.kill();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
#[ignore = "spawns the ferrum-edge binary; run with --ignored after building it"]
async fn smoke_file_provider_starts_gateway() {
    let Some(bin) = locate_binary() else {
        eprintln!("SKIP smoke_file_provider: ferrum-edge binary not found (build it first)");
        return;
    };
    let tmp = TempDir::new().unwrap();
    let secret_path = tmp.path().join("admin_jwt");
    std::fs::write(&secret_path, format!("{SMOKE_SECRET}\n")).unwrap();

    let env = vec![(
        "FERRUM_ADMIN_JWT_SECRET_FILE".to_string(),
        secret_path.to_string_lossy().into_owned(),
    )];
    let gw = match GatewaySmoke::spawn(&bin, &env) {
        Ok(gw) => gw,
        Err(e) => {
            eprintln!("SKIP smoke_file_provider: could not spawn gateway: {e}");
            return;
        }
    };
    assert_healthy_and_clean(gw, "file").await;
}

#[cfg(feature = "secrets-gcp")]
#[tokio::test(flavor = "multi_thread")]
#[serial]
#[ignore = "spawns the ferrum-edge binary; run with --ignored after building it"]
async fn smoke_gcp_provider_starts_gateway() {
    use crate::common::fakes::GcpSecretManagerFake;

    let Some(bin) = locate_binary() else {
        eprintln!("SKIP smoke_gcp_provider: ferrum-edge binary not found");
        return;
    };
    // The fake runs in this (parent) process; the child gateway reaches it on
    // 127.0.0.1.
    let fake = GcpSecretManagerFake::start().await;
    let resource = "projects/test-project/secrets/ferrum-admin/versions/latest";
    fake.mock_access_success(resource, SMOKE_SECRET.as_bytes())
        .await;

    let env = vec![
        (
            "FERRUM_GCP_SECRET_MANAGER_ENDPOINT".to_string(),
            fake.endpoint(),
        ),
        (
            "FERRUM_ADMIN_JWT_SECRET_GCP".to_string(),
            resource.to_string(),
        ),
    ];
    let gw = match GatewaySmoke::spawn(&bin, &env) {
        Ok(gw) => gw,
        Err(e) => {
            eprintln!("SKIP smoke_gcp_provider: could not spawn gateway: {e}");
            return;
        }
    };
    assert_healthy_and_clean(gw, "GCP Secret Manager").await;
}

#[cfg(feature = "secrets-vault")]
#[tokio::test(flavor = "multi_thread")]
#[serial]
#[ignore = "spawns the ferrum-edge binary + Vault container; run with --ignored"]
async fn smoke_vault_provider_starts_gateway() {
    use crate::common::containers::start_vault_dev_container;

    let Some(bin) = locate_binary() else {
        eprintln!("SKIP smoke_vault_provider: ferrum-edge binary not found");
        return;
    };
    let vault = match start_vault_dev_container().await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("SKIP smoke_vault_provider: Vault container unavailable: {e}");
            return;
        }
    };
    // The seeded `secret/data/ferrum#admin_jwt` is "vault-admin-jwt" (12 chars),
    // which is too short for the 32-char admin-secret minimum, so seed a
    // dedicated long secret for the smoke test.
    let client = reqwest::Client::new();
    client
        .post(format!("{}/v1/secret/data/smoke", vault.addr))
        .header("X-Vault-Token", &vault.token)
        .json(&serde_json::json!({ "data": { "admin_jwt": SMOKE_SECRET } }))
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .expect("seed smoke secret");

    let env = vec![
        ("VAULT_ADDR".to_string(), vault.addr.clone()),
        ("VAULT_TOKEN".to_string(), vault.token.clone()),
        (
            "FERRUM_ADMIN_JWT_SECRET_VAULT".to_string(),
            "secret/data/smoke#admin_jwt".to_string(),
        ),
    ];
    let gw = match GatewaySmoke::spawn(&bin, &env) {
        Ok(gw) => gw,
        Err(e) => {
            eprintln!("SKIP smoke_vault_provider: could not spawn gateway: {e}");
            return;
        }
    };
    assert_healthy_and_clean(gw, "Vault").await;
}

#[cfg(feature = "secrets-aws")]
#[tokio::test(flavor = "multi_thread")]
#[serial]
#[ignore = "spawns the ferrum-edge binary + LocalStack; run with --ignored"]
async fn smoke_aws_provider_starts_gateway() {
    use crate::common::containers::start_localstack_for_aws_secretsmanager;

    let Some(bin) = locate_binary() else {
        eprintln!("SKIP smoke_aws_provider: ferrum-edge binary not found");
        return;
    };
    let ls = match start_localstack_for_aws_secretsmanager().await {
        Ok(ls) => ls,
        Err(e) => {
            eprintln!("SKIP smoke_aws_provider: LocalStack unavailable: {e}");
            return;
        }
    };
    ls.create_secret_string("ferrum/smoke-admin", SMOKE_SECRET)
        .await
        .expect("seed smoke secret");

    let env = vec![
        ("AWS_REGION".to_string(), "us-east-1".to_string()),
        ("AWS_DEFAULT_REGION".to_string(), "us-east-1".to_string()),
        ("AWS_ACCESS_KEY_ID".to_string(), "test".to_string()),
        ("AWS_SECRET_ACCESS_KEY".to_string(), "test".to_string()),
        (
            "AWS_ENDPOINT_URL_SECRETS_MANAGER".to_string(),
            ls.endpoint.clone(),
        ),
        (
            "FERRUM_ADMIN_JWT_SECRET_AWS".to_string(),
            "ferrum/smoke-admin".to_string(),
        ),
    ];
    let gw = match GatewaySmoke::spawn(&bin, &env) {
        Ok(gw) => gw,
        Err(e) => {
            eprintln!("SKIP smoke_aws_provider: could not spawn gateway: {e}");
            return;
        }
    };
    assert_healthy_and_clean(gw, "AWS Secrets Manager").await;
}
