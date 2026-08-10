//! In-process gateway driven by a **trusted projected** [`GatewayConfig`].
//!
//! Production mesh materialization builds `GatewayConfig` in-process (with
//! reserved `mesh.*` target tags) and feeds it to `ProxyState` /
//! `modes::file::serve` — it never goes through the operator file-loader or
//! admin write paths that call [`GatewayConfig::validate_operator_provided_fields`].
//!
//! Functional coverage that must exercise those internal transport tags has to
//! use the same boundary. This helper:
//! - deserializes / accepts a `GatewayConfig` that may carry `mesh.*` tags,
//! - normalizes it the way mesh projection does,
//! - deliberately does **not** call operator-field validation,
//! - starts the real file-mode serve path in-process.
//!
//! It is **not** a file-loader escape hatch, env bypass, or allowlist. Operator
//! YAML/admin inputs remain fail-closed via `validate_operator_provided_fields`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use chrono::Utc;
use ferrum_edge::admin::jwt_auth::{JwtConfig, JwtManager};
use ferrum_edge::config::EnvConfig;
use ferrum_edge::config::env_config::OperatingMode;
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::modes::file::{ServeOptions, serve};
use ferrum_edge::proxy::{ConfigApplyOutcome, ProxyState};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::json;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use uuid::Uuid;

/// Parse fixture YAML into a trusted projected config.
///
/// This mirrors mesh materialization: deserialize + normalize, and **never**
/// run operator-provided-field rejection. Callers that need operator-boundary
/// coverage must use the file loader / admin paths instead.
pub fn trusted_projected_config_from_yaml(yaml: &str) -> GatewayConfig {
    let mut config: GatewayConfig =
        serde_yaml::from_str(yaml).expect("trusted projected fixture YAML must deserialize");
    config.normalize_fields();
    config
}

/// Options for spawning a trusted projected in-process gateway.
#[derive(Default)]
pub struct TrustedProjectedGatewayOptions {
    /// Extra env-config overrides applied before `serve`.
    pub env: EnvConfig,
    /// When true, bind an ephemeral HTTPS listener (and HTTP/3 when
    /// `env.enable_http3` is set) using the frontend TLS paths on `env`.
    pub enable_https: bool,
    /// Ports already promised to fixtures / siblings; ephemeral binds retry
    /// until they land outside this set (and are held for the gateway lifetime).
    pub excluded_ports: Vec<u16>,
    /// Optional containment / unix-socket roots (copied onto env).
    pub mesh_unix_socket_allowed_roots: Vec<String>,
}

/// Running in-process gateway whose config entered through the trusted
/// projection boundary (`file::serve` / `ProxyState::update_config`).
pub struct TrustedProjectedGateway {
    pub proxy_state: ProxyState,
    pub proxy_http_port: u16,
    pub proxy_https_port: Option<u16>,
    pub admin_port: u16,
    admin_base_url: String,
    jwt_secret: String,
    jwt_issuer: String,
    shutdown_tx: Option<watch::Sender<bool>>,
    join: Option<JoinHandle<()>>,
    /// Retained so callers can keep cert/key temp dirs alive by embedding
    /// them in the options path strings; this field documents ownership of
    /// any helper-owned scratch (currently unused, reserved for future).
    _scratch: Option<PathBuf>,
}

impl TrustedProjectedGateway {
    /// Start an in-process gateway from a trusted projected `GatewayConfig`.
    pub async fn spawn(
        config: GatewayConfig,
        mut options: TrustedProjectedGatewayOptions,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let excluded: std::collections::HashSet<u16> =
            options.excluded_ports.iter().copied().collect();
        // Hold rejected listeners so the kernel cannot immediately re-offer an
        // excluded port to the next `:0` bind in this process.
        let mut held_rejected: Vec<TcpListener> = Vec::new();
        let proxy_http = bind_ephemeral_excluding(&excluded, &mut held_rejected).await?;
        let admin_http = bind_ephemeral_excluding(&excluded, &mut held_rejected).await?;
        let proxy_http_port = proxy_http.local_addr()?.port();
        let admin_port = admin_http.local_addr()?.port();

        let jwt_secret = format!("trusted-projected-jwt-{}", Uuid::new_v4());
        let jwt_issuer = "ferrum-edge-trusted-projected-test".to_string();

        let mut env_config = options.env;
        env_config.mode = OperatingMode::File;
        if env_config.log_level.is_empty() {
            env_config.log_level = "warn".into();
        }
        env_config.proxy_http_port = proxy_http_port;
        env_config.admin_http_port = admin_port;
        env_config.admin_https_port = 0;
        env_config.admin_jwt_secret = Some(jwt_secret.clone());
        env_config.admin_jwt_issuer = jwt_issuer.clone();
        env_config.shutdown_drain_seconds = 0;
        if !options.mesh_unix_socket_allowed_roots.is_empty() {
            env_config.mesh_unix_socket_allowed_roots =
                std::mem::take(&mut options.mesh_unix_socket_allowed_roots);
        }

        let mut proxy_https = None;
        let mut proxy_https_port = None;
        if options.enable_https {
            let listener = bind_ephemeral_excluding(&excluded, &mut held_rejected).await?;
            let https_port = listener.local_addr()?.port();
            proxy_https_port = Some(https_port);
            env_config.proxy_https_port = https_port;
            proxy_https = Some(listener);
        } else {
            env_config.proxy_https_port = 0;
        }
        drop(held_rejected);

        let jwt_manager = JwtManager::new(JwtConfig {
            secret: jwt_secret.clone(),
            issuer: jwt_issuer.clone(),
            audience: None,
            max_ttl_seconds: 3600,
            algorithm: jsonwebtoken::Algorithm::HS256,
        });

        let opts = ServeOptions {
            proxy_http: Some(proxy_http),
            proxy_https,
            admin_http: Some(admin_http),
            admin_https: None,
            admin_jwt_manager: Some(jwt_manager),
            skip_initial_capability_refresh: !env_config.pool_warmup_enabled,
            background_drain_timeout: Some(Duration::from_millis(500)),
        };

        let (shutdown_tx, _) = watch::channel(false);
        let handles = serve(env_config, config, opts, shutdown_tx.clone())
            .await
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                format!("trusted projected file::serve failed: {e}").into()
            })?;

        let proxy_state = handles.proxy_state.clone();
        let admin_base_url = format!("http://127.0.0.1:{admin_port}");
        let join = tokio::spawn(async move {
            if let Err(err) = handles.join().await {
                eprintln!("TrustedProjectedGateway listener panicked: {err}");
            }
        });

        let gateway = Self {
            proxy_state,
            proxy_http_port,
            proxy_https_port,
            admin_port,
            admin_base_url,
            jwt_secret,
            jwt_issuer,
            shutdown_tx: Some(shutdown_tx),
            join: Some(join),
            _scratch: None,
        };
        gateway
            .wait_for_admin_ready(Duration::from_secs(15))
            .await?;
        Ok(gateway)
    }

    /// Convenience: deserialize fixture YAML then spawn.
    pub async fn spawn_from_yaml(
        yaml: &str,
        options: TrustedProjectedGatewayOptions,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Self::spawn(trusted_projected_config_from_yaml(yaml), options).await
    }

    pub fn proxy_url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.proxy_http_port)
    }

    pub fn admin_url(&self, path: &str) -> String {
        format!("{}{path}", self.admin_base_url)
    }

    pub fn auth_header(&self) -> String {
        format!("Bearer {}", self.admin_token())
    }

    pub fn admin_token(&self) -> String {
        let now = Utc::now();
        let claims = json!({
            "iss": self.jwt_issuer,
            "sub": "test-admin",
            "role": "admin",
            "iat": now.timestamp(),
            "nbf": now.timestamp(),
            "exp": (now + chrono::Duration::seconds(3600)).timestamp(),
            "jti": Uuid::new_v4().to_string(),
        });
        let header = Header::new(jsonwebtoken::Algorithm::HS256);
        let key = EncodingKey::from_secret(self.jwt_secret.as_bytes());
        encode(&header, &claims, &key).expect("encode admin JWT")
    }

    /// Apply a new trusted projected config the way mesh slice apply does
    /// (`ProxyState::update_config`), not via SIGHUP / file-loader reload.
    pub fn apply_projected_config(&self, config: GatewayConfig) -> ConfigApplyOutcome {
        self.proxy_state.update_config(config)
    }

    pub fn apply_projected_yaml(&self, yaml: &str) -> ConfigApplyOutcome {
        self.apply_projected_config(trusted_projected_config_from_yaml(yaml))
    }

    /// Live upstream target tags from the applied admin/config projection.
    pub fn live_upstream_tags(&self, upstream_id: &str) -> HashMap<String, String> {
        self.proxy_state
            .config
            .load_full()
            .upstreams
            .iter()
            .find(|upstream| upstream.id == upstream_id)
            .and_then(|upstream| upstream.targets.first())
            .map(|target| target.tags.clone())
            .unwrap_or_default()
    }

    pub async fn wait_for_proxy_port(
        &self,
        timeout: Duration,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if tokio::net::TcpStream::connect(("127.0.0.1", self.proxy_http_port))
                .await
                .is_ok()
            {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                return Err(format!(
                    "trusted projected proxy port {} never accepted within {timeout:?}",
                    self.proxy_http_port
                )
                .into());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    async fn wait_for_admin_ready(
        &self,
        timeout: Duration,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let deadline = std::time::Instant::now() + timeout;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()?;
        let url = format!("{}/health", self.admin_base_url);
        loop {
            if let Ok(resp) = client
                .get(&url)
                .header("Authorization", self.auth_header())
                .send()
                .await
                && resp.status().is_success()
            {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                return Err(format!(
                    "trusted projected admin /health not ready within {timeout:?}"
                )
                .into());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    pub fn shutdown(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(true);
        }
        let _ = self.join.take();
    }
}

impl Drop for TrustedProjectedGateway {
    fn drop(&mut self) {
        self.shutdown();
    }
}

async fn bind_ephemeral_excluding(
    excluded: &std::collections::HashSet<u16>,
    held_rejected: &mut Vec<TcpListener>,
) -> Result<TcpListener, Box<dyn std::error::Error + Send + Sync>> {
    for _ in 0..64 {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        if excluded.contains(&port) {
            held_rejected.push(listener);
            continue;
        }
        return Ok(listener);
    }
    Err("exhausted ephemeral binds while avoiding excluded fixture ports".into())
}
