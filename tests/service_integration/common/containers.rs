//! Local container fixtures for the external middleware that Ferrum integrates
//! with but which can only be validated against the REAL third-party software:
//! a service registry (HashiCorp Consul), an LDAP directory server (OpenLDAP),
//! and a Kafka-compatible broker (Redpanda). All run locally via
//! `testcontainers` (Docker) — no managed or cloud service is ever involved,
//! and the fixtures seed their own fully controlled data so the assertions are
//! deterministic.
//!
//! This mirrors `tests/secrets_functional/common/containers.rs` (Vault /
//! LocalStack): when Docker is not available the `start_*` helpers return
//! `Err`, and callers print a skip notice and return rather than fail — except
//! in CI, where a container that fails to start is a hard failure (see
//! [`fail_in_ci_else_skip`]).

#![allow(dead_code)] // helpers are used selectively per backend module

use std::time::Duration;

use testcontainers::core::{ExecCommand, IntoContainerPort};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Decide how to handle an unavailable container.
///
/// In CI (`CI` env var set, e.g. GitHub Actions) a container that fails to
/// start is a HARD failure: the `test-service-integration` job runs on a
/// Docker-enabled runner, so an image-pull error, a changed wait condition, or
/// broken setup must fail the job rather than let it pass without ever
/// executing the assertions. Outside CI (no Docker locally) it is a graceful
/// skip so the suite stays runnable on a developer machine.
pub fn fail_in_ci_else_skip(test: &str, service: &str, err: &BoxError) {
    if std::env::var("CI").is_ok() {
        panic!("{test}: {service} is required in CI but failed to start: {err}");
    }
    eprintln!("SKIP {test}: {service} unavailable (Docker?): {err}");
}

// ---------------------------------------------------------------------------
// HashiCorp Consul (dev agent)
// ---------------------------------------------------------------------------

/// A running Consul dev agent.
pub struct ConsulContainer {
    // Held to keep the container alive for the test's lifetime.
    _container: ContainerAsync<GenericImage>,
    /// `http://127.0.0.1:<mapped-port>` — the Consul HTTP API base URL.
    pub addr: String,
    client: reqwest::Client,
}

/// Start a single-node Consul dev agent with the HTTP API exposed.
///
/// Dev mode keeps everything in memory and comes up in well under a second.
/// Readiness is confirmed by polling the leader endpoint rather than matching a
/// startup log line, so the helper does not depend on which stream Consul logs
/// to.
pub async fn start_consul_dev_container() -> Result<ConsulContainer, BoxError> {
    let container = GenericImage::new("hashicorp/consul", "1.19")
        .with_exposed_port(8500.tcp())
        .with_cmd(["agent", "-dev", "-client", "0.0.0.0"])
        .start()
        .await?;

    let port = container.get_host_port_ipv4(8500.tcp()).await?;
    let addr = format!("http://127.0.0.1:{port}");
    let client = reqwest::Client::new();

    wait_consul_ready(&client, &addr).await?;

    Ok(ConsulContainer {
        _container: container,
        addr,
        client,
    })
}

/// Poll Consul's leader endpoint until the dev agent has elected itself and is
/// ready to accept catalog writes.
async fn wait_consul_ready(client: &reqwest::Client, addr: &str) -> Result<(), BoxError> {
    for _ in 0..60 {
        if let Ok(resp) = client.get(format!("{addr}/v1/status/leader")).send().await
            && resp.status().is_success()
        {
            // `""` before leadership; `"127.0.0.1:8300"` once ready.
            let body = resp.text().await.unwrap_or_default();
            if !body.trim().trim_matches('"').is_empty() {
                return Ok(());
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Err("Consul did not elect a leader within 30s".into())
}

impl ConsulContainer {
    /// Register a service instance via the local agent API
    /// (`PUT /v1/agent/service/register`). `body` is the raw registration
    /// document, e.g.
    /// `{"ID":"web-1","Name":"web","Address":"10.0.0.5","Port":8080}`.
    pub async fn register_service(&self, body: serde_json::Value) -> Result<(), BoxError> {
        self.client
            .put(format!("{}/v1/agent/service/register", self.addr))
            .json(&body)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// OpenLDAP directory server
// ---------------------------------------------------------------------------

/// Base DN the OpenLDAP fixture is bootstrapped with (derived from
/// `LDAP_DOMAIN=example.org`).
pub const LDAP_BASE_DN: &str = "dc=example,dc=org";
/// Directory admin (root) DN, usable as a search-then-bind service account.
pub const LDAP_ADMIN_DN: &str = "cn=admin,dc=example,dc=org";
/// Directory admin password (set via `LDAP_ADMIN_PASSWORD`).
pub const LDAP_ADMIN_PASSWORD: &str = "adminpassword";
/// Plaintext LDAP port inside the container.
const LDAP_CONTAINER_PORT: u16 = 389;

/// A running OpenLDAP server.
pub struct OpenLdapContainer {
    _container: ContainerAsync<GenericImage>,
    /// `ldap://127.0.0.1:<mapped-port>` — pass as the plugin's `ldap_url`.
    pub url: String,
}

/// Start an OpenLDAP server bootstrapped with base DN `dc=example,dc=org`.
///
/// The image only creates the base suffix and the admin account; the test data
/// (people, groups) is added afterwards via [`OpenLdapContainer::seed_ldif`] so
/// every DN, password, and group membership is controlled by the test.
pub async fn start_openldap_container() -> Result<OpenLdapContainer, BoxError> {
    let container = GenericImage::new("osixia/openldap", "1.5.0")
        .with_exposed_port(LDAP_CONTAINER_PORT.tcp())
        // Readiness is confirmed by `seed_ldif`, which retries `ldapadd` until
        // the final slapd is answering on TCP — so we do not have to match a
        // startup log line/stream or race the first-boot bootstrap (which only
        // serves the bootstrap directory over a private socket).
        .with_env_var("LDAP_ORGANISATION", "Ferrum Test")
        .with_env_var("LDAP_DOMAIN", "example.org")
        .with_env_var("LDAP_ADMIN_PASSWORD", LDAP_ADMIN_PASSWORD)
        .start()
        .await?;

    let port = container
        .get_host_port_ipv4(LDAP_CONTAINER_PORT.tcp())
        .await?;
    let url = format!("ldap://127.0.0.1:{port}");

    Ok(OpenLdapContainer {
        _container: container,
        url,
    })
}

impl OpenLdapContainer {
    /// Add the given LDIF document to the directory by piping it to `ldapadd`
    /// inside the container (binding as the admin account). Retries while the
    /// server is still coming up so callers do not have to race the bootstrap.
    pub async fn seed_ldif(&self, ldif: &str) -> Result<(), BoxError> {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(ldif);
        // base64-decode the LDIF on the container side to sidestep all shell
        // quoting/heredoc concerns, then feed it to ldapadd.
        let script = format!(
            "echo {b64} | base64 -d | \
             ldapadd -x -H ldap://localhost:{LDAP_CONTAINER_PORT} \
             -D '{LDAP_ADMIN_DN}' -w '{LDAP_ADMIN_PASSWORD}'"
        );

        // Give the first-boot bootstrap a moment to hand off to the final slapd
        // before the first attempt; the retry loop covers the rest.
        tokio::time::sleep(Duration::from_secs(2)).await;

        let mut last = String::new();
        for _ in 0..40 {
            let out = self.exec_sh(&script).await?;
            let combined = out.combined();
            if out.exit_code == Some(0) {
                return Ok(());
            }
            // slapd not up yet (or mid-restart during first-boot bootstrap).
            if combined.contains("Can't contact LDAP server")
                || combined.contains("Can't connect")
                || combined.trim().is_empty()
            {
                last = combined;
                tokio::time::sleep(Duration::from_millis(750)).await;
                continue;
            }
            if combined.contains("adding new entry") {
                return Err(format!(
                    "ldapadd partially applied LDIF before failing with exit {:?}: {}",
                    out.exit_code,
                    combined.trim()
                )
                .into());
            }
            // A real LDIF/schema error — surface it immediately.
            return Err(format!(
                "ldapadd failed with exit {:?}: {}",
                out.exit_code,
                combined.trim()
            )
            .into());
        }
        Err(format!("ldapadd never succeeded; last output: {last}").into())
    }

    async fn exec_sh(&self, script: &str) -> Result<ExecOutput, BoxError> {
        let cmd = vec!["sh".to_string(), "-c".to_string(), script.to_string()];
        let mut result = self._container.exec(ExecCommand::new(cmd)).await?;
        let stdout = result.stdout_to_vec().await?;
        let stderr = result.stderr_to_vec().await?;
        Ok(ExecOutput {
            exit_code: result.exit_code().await?,
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
        })
    }
}

struct ExecOutput {
    exit_code: Option<i64>,
    stdout: String,
    stderr: String,
}

impl ExecOutput {
    fn combined(&self) -> String {
        match (self.stdout.trim().is_empty(), self.stderr.trim().is_empty()) {
            (true, true) => String::new(),
            (false, true) => self.stdout.clone(),
            (true, false) => self.stderr.clone(),
            (false, false) => format!("{}\n{}", self.stdout, self.stderr),
        }
    }
}

// ---------------------------------------------------------------------------
// Redpanda (Kafka API) — real broker for kafka_logging
// ---------------------------------------------------------------------------

/// A single-node Redpanda broker with a host-routable Kafka listener.
///
/// Advertised listeners need the host-mapped port up front, so the helper binds
/// an ephemeral local port, pins that mapping, and advertises
/// `127.0.0.1:<host-port>` on the external Kafka listener. Readiness is polled
/// via librdkafka metadata (not a log line).
pub struct RedpandaContainer {
    _container: ContainerAsync<GenericImage>,
    /// `127.0.0.1:<mapped-port>` — pass as `kafka_logging.broker_list`.
    pub bootstrap: String,
}

/// Bind an ephemeral localhost TCP port for a deterministic host→container map.
fn free_localhost_port() -> Result<u16, BoxError> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

/// Start a single-node Redpanda with auto-topic-create disabled.
///
/// Disabling auto-create keeps unknown-topic rejection deterministic for the
/// real-broker acceptance suite.
pub async fn start_redpanda_container() -> Result<RedpandaContainer, BoxError> {
    let host_port = free_localhost_port()?;
    let advertise = format!("internal://127.0.0.1:9092,external://127.0.0.1:{host_port}");

    let container = GenericImage::new("redpandadata/redpanda", "v24.2.4")
        .with_exposed_port(9093.tcp())
        .with_mapped_port(host_port, 9093.tcp())
        .with_cmd([
            "redpanda".to_string(),
            "start".to_string(),
            "--overprovisioned".to_string(),
            "--smp".to_string(),
            "1".to_string(),
            "--memory".to_string(),
            "512M".to_string(),
            "--reserve-memory".to_string(),
            "0M".to_string(),
            "--node-id".to_string(),
            "0".to_string(),
            "--check=false".to_string(),
            "--kafka-addr".to_string(),
            "internal://0.0.0.0:9092,external://0.0.0.0:9093".to_string(),
            "--advertise-kafka-addr".to_string(),
            advertise,
            "--set".to_string(),
            "redpanda.auto_create_topics_enabled=false".to_string(),
        ])
        .start()
        .await?;

    let bootstrap = format!("127.0.0.1:{host_port}");
    wait_redpanda_ready(&bootstrap).await?;

    Ok(RedpandaContainer {
        _container: container,
        bootstrap,
    })
}

/// Poll librdkafka metadata until the broker answers (or 30s elapses).
async fn wait_redpanda_ready(bootstrap: &str) -> Result<(), BoxError> {
    for _ in 0..60 {
        let bootstrap = bootstrap.to_string();
        let ready = tokio::task::spawn_blocking(move || redpanda_metadata_ok(&bootstrap))
            .await
            .unwrap_or(false);
        if ready {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Err("Redpanda did not become metadata-ready within 30s".into())
}

fn redpanda_metadata_ok(bootstrap: &str) -> bool {
    use rdkafka::consumer::{BaseConsumer, Consumer};
    use rdkafka::ClientConfig;

    let consumer: Result<BaseConsumer, _> = ClientConfig::new()
        .set("bootstrap.servers", bootstrap)
        .set("group.id", "ferrum-redpanda-ready")
        .set("socket.timeout.ms", "1500")
        .set("api.version.request.timeout.ms", "1500")
        .set("log_level", "0")
        .create();
    let Ok(consumer) = consumer else {
        return false;
    };
    consumer
        .fetch_metadata(None, Duration::from_secs(2))
        .map(|meta| !meta.brokers().is_empty())
        .unwrap_or(false)
}

impl RedpandaContainer {
    /// Create a single-partition topic, optionally with broker topic configs
    /// (`max.message.bytes`, `min.insync.replicas`, …). Retries while the
    /// admin path is still warming up.
    pub async fn create_topic(
        &self,
        name: &str,
        configs: &[(&str, &str)],
    ) -> Result<(), BoxError> {
        let mut script = format!("rpk topic create {name} -p 1 -r 1");
        for (key, value) in configs {
            script.push_str(&format!(" --config {key}={value}"));
        }

        let mut last = String::new();
        for _ in 0..40 {
            let out = self.exec_sh(&script).await?;
            let combined = out.combined();
            if out.exit_code == Some(0)
                || combined.contains("already exists")
                || combined.contains("TOPIC_ALREADY_EXISTS")
            {
                return Ok(());
            }
            last = combined;
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        Err(format!("rpk topic create never succeeded for {name}; last output: {last}").into())
    }

    /// Consume one record from `topic` (earliest), returning `(key, payload)`.
    /// Payload is returned only for assertion against known test markers —
    /// callers must not log it.
    pub async fn consume_one(
        &self,
        topic: &str,
        timeout: Duration,
    ) -> Result<Option<(Option<String>, String)>, BoxError> {
        let bootstrap = self.bootstrap.clone();
        let topic = topic.to_string();
        tokio::task::spawn_blocking(move || consume_one_blocking(&bootstrap, &topic, timeout))
            .await
            .map_err(|error| -> BoxError { format!("consume task join failed: {error}").into() })?
    }

    async fn exec_sh(&self, script: &str) -> Result<ExecOutput, BoxError> {
        let cmd = vec!["sh".to_string(), "-c".to_string(), script.to_string()];
        let mut result = self._container.exec(ExecCommand::new(cmd)).await?;
        let stdout = result.stdout_to_vec().await?;
        let stderr = result.stderr_to_vec().await?;
        Ok(ExecOutput {
            exit_code: result.exit_code().await?,
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
        })
    }
}

fn consume_one_blocking(
    bootstrap: &str,
    topic: &str,
    timeout: Duration,
) -> Result<Option<(Option<String>, String)>, BoxError> {
    use rdkafka::config::ClientConfig;
    use rdkafka::consumer::{BaseConsumer, Consumer};
    use rdkafka::{Message, Offset, TopicPartitionList};

    let consumer: BaseConsumer = ClientConfig::new()
        .set("bootstrap.servers", bootstrap)
        .set(
            "group.id",
            format!("ferrum-si-{}-{}", std::process::id(), topic),
        )
        .set("enable.auto.commit", "false")
        .set("auto.offset.reset", "earliest")
        .set("socket.timeout.ms", "2000")
        .set("log_level", "0")
        .create()?;

    let mut tpl = TopicPartitionList::new();
    tpl.add_partition_offset(topic, 0, Offset::Beginning)?;
    consumer.assign(&tpl)?;

    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        let poll_timeout = deadline
            .saturating_duration_since(std::time::Instant::now())
            .min(Duration::from_millis(200));
        match consumer.poll(poll_timeout) {
            Some(Ok(message)) => {
                let key = message
                    .key()
                    .map(|bytes| String::from_utf8_lossy(bytes).into_owned());
                let payload = String::from_utf8_lossy(message.payload().unwrap_or(b"")).into_owned();
                return Ok(Some((key, payload)));
            }
            Some(Err(_)) | None => continue,
        }
    }
    Ok(None)
}
