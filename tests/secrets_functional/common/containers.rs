//! Local container fixtures for the Vault and AWS secret backends, started via
//! `testcontainers` (Docker). These exercise the real provider SDKs against
//! locally-run servers — a HashiCorp Vault dev server and LocalStack's Secrets
//! Manager — so no real cloud account or credentials are ever involved.
//!
//! When Docker is not available the `start_*` helpers return `Err`; callers are
//! expected to print a skip notice and return rather than fail.

#![allow(dead_code)] // helpers are used selectively per feature-gated module

use testcontainers::core::{ExecCommand, IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Decide how to handle an unavailable container.
///
/// In CI (`CI` env var set, e.g. GitHub Actions) a container that fails to
/// start is a HARD failure: the `test-secrets` job runs on a Docker-enabled
/// runner, so an image-pull error, a changed wait condition, or broken setup
/// must fail the job rather than let it pass without ever executing the
/// assertions. Outside CI (no Docker locally) it is a graceful skip so the
/// suite stays runnable on a developer machine.
pub fn fail_in_ci_else_skip(test: &str, provider: &str, err: &BoxError) {
    if std::env::var("CI").is_ok() {
        panic!("{test}: {provider} is required in CI but failed to start: {err}");
    }
    eprintln!("SKIP {test}: {provider} unavailable (Docker?): {err}");
}

// ---------------------------------------------------------------------------
// HashiCorp Vault dev server (KV v2)
// ---------------------------------------------------------------------------

/// A running Vault dev server with the fixed test fixtures seeded.
pub struct VaultContainer {
    // Held to keep the container alive for the test's lifetime.
    _container: ContainerAsync<GenericImage>,
    /// `http://127.0.0.1:<mapped-port>` — set as `VAULT_ADDR`.
    pub addr: String,
    /// Dev-server root token — set as `VAULT_TOKEN`.
    pub token: String,
}

/// Start a Vault dev server (root token `root`) and seed KV v2 fixtures:
///   - `secret/data/ferrum` → `admin_jwt=vault-admin-jwt`, `db_url=sqlite:///tmp/ferrum.db`
///   - `secret/data/single` → `value=only-one`
pub async fn start_vault_dev_container() -> Result<VaultContainer, BoxError> {
    let container = GenericImage::new("hashicorp/vault", "1.15")
        .with_exposed_port(8200.tcp())
        .with_wait_for(WaitFor::message_on_stdout("Vault server started!"))
        .with_env_var("VAULT_DEV_ROOT_TOKEN_ID", "root")
        .with_env_var("VAULT_DEV_LISTEN_ADDRESS", "0.0.0.0:8200")
        .with_cmd(["server", "-dev"])
        .start()
        .await?;

    let port = container.get_host_port_ipv4(8200.tcp()).await?;
    let addr = format!("http://127.0.0.1:{port}");
    let token = "root".to_string();

    seed_vault_kv2(&addr, &token).await?;

    Ok(VaultContainer {
        _container: container,
        addr,
        token,
    })
}

async fn seed_vault_kv2(addr: &str, token: &str) -> Result<(), BoxError> {
    let client = reqwest::Client::new();

    // KV v2 writes nest the secret data under a `data` key.
    let ferrum = serde_json::json!({
        "data": { "admin_jwt": "vault-admin-jwt", "db_url": "sqlite:///tmp/ferrum.db" }
    });
    client
        .post(format!("{addr}/v1/secret/data/ferrum"))
        .header("X-Vault-Token", token)
        .json(&ferrum)
        .send()
        .await?
        .error_for_status()?;

    let single = serde_json::json!({ "data": { "value": "only-one" } });
    client
        .post(format!("{addr}/v1/secret/data/single"))
        .header("X-Vault-Token", token)
        .json(&single)
        .send()
        .await?
        .error_for_status()?;

    Ok(())
}

// ---------------------------------------------------------------------------
// LocalStack — AWS Secrets Manager
// ---------------------------------------------------------------------------

/// A running LocalStack instance with Secrets Manager enabled.
pub struct LocalStackContainer {
    _container: ContainerAsync<GenericImage>,
    /// `http://127.0.0.1:<mapped-port>` — set as `AWS_ENDPOINT_URL_SECRETS_MANAGER`.
    pub endpoint: String,
}

/// Start LocalStack with only the Secrets Manager service enabled.
pub async fn start_localstack_for_aws_secretsmanager() -> Result<LocalStackContainer, BoxError> {
    let container = GenericImage::new("localstack/localstack", "3")
        .with_exposed_port(4566.tcp())
        .with_wait_for(WaitFor::message_on_stdout("Ready."))
        .with_env_var("SERVICES", "secretsmanager")
        .with_env_var("EAGER_SERVICE_LOADING", "1")
        .start()
        .await?;

    let port = container.get_host_port_ipv4(4566.tcp()).await?;
    Ok(LocalStackContainer {
        _container: container,
        endpoint: format!("http://127.0.0.1:{port}"),
    })
}

impl LocalStackContainer {
    /// Create a `SecretString` secret via the bundled `awslocal` CLI and return
    /// its ARN.
    pub async fn create_secret_string(&self, name: &str, value: &str) -> Result<String, BoxError> {
        let out = self
            .exec_awslocal(&[
                "secretsmanager",
                "create-secret",
                "--name",
                name,
                "--secret-string",
                value,
                "--output",
                "json",
            ])
            .await?;
        let parsed: serde_json::Value = serde_json::from_str(&out).map_err(|e| {
            format!("could not parse create-secret output as JSON: {e}; raw: {out}")
        })?;
        parsed
            .get("ARN")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| format!("create-secret output missing ARN: {out}").into())
    }

    /// Create a binary-only secret (no `SecretString`). The bytes are written
    /// to a file in the container and supplied via `fileb://`, which avoids any
    /// AWS-CLI base64/binary-format ambiguity.
    pub async fn create_secret_binary(&self, name: &str, raw_bytes: &[u8]) -> Result<(), BoxError> {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(raw_bytes);
        let script = format!(
            "echo {b64} | base64 -d > /tmp/binsecret && \
             awslocal secretsmanager create-secret --name {name} --secret-binary fileb:///tmp/binsecret"
        );
        self.exec_sh(&script).await?;
        Ok(())
    }

    async fn exec_awslocal(&self, args: &[&str]) -> Result<String, BoxError> {
        let mut cmd: Vec<String> = vec!["awslocal".to_string()];
        cmd.extend(args.iter().map(|s| s.to_string()));
        self.exec_capture(cmd).await
    }

    async fn exec_sh(&self, script: &str) -> Result<String, BoxError> {
        self.exec_capture(vec!["sh".to_string(), "-c".to_string(), script.to_string()])
            .await
    }

    async fn exec_capture(&self, cmd: Vec<String>) -> Result<String, BoxError> {
        let mut result = self._container.exec(ExecCommand::new(cmd)).await?;
        let stdout = result.stdout_to_vec().await?;
        Ok(String::from_utf8_lossy(&stdout).into_owned())
    }
}
