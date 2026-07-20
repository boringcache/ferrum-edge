//! Example Audit Plugin — Custom Plugin with Database Migrations
//!
//! Opt-in pedagogical plugin (see `custom_plugins/examples/README.md`). When
//! compiled in via `FERRUM_CUSTOM_PLUGINS=example_audit_plugin`, it records a
//! bounded audit row for every gateway transaction it is selected for —
//! HTTP-family `log()` hooks and stream `on_stream_disconnect()` hooks —
//! into a plugin-prefixed table created by its bundled migrations.
//!
//! ## Storage target
//!
//! Migrations and runtime writes both use the **gateway configuration
//! database** (`FERRUM_DB_URL` / `FERRUM_DB_TYPE`). There is no separate
//! plugin database URL: a second URL would silently diverge from the schema
//! that migrate mode / auto-apply maintain.
//!
//! Supported modes for the storage path: `database`, `cp`, and standalone
//! `migrate` (for schema). File / DP / mesh / injector / node-agent modes do
//! not run SQL custom-plugin migrations; constructing the plugin there will
//! still attempt writes against `FERRUM_DB_URL` if set.
//!
//! ## Failure contract
//!
//! This is a best-effort audit example (`OptionalFailOpen` at construction).
//! Queue-full and flush failures are logged and dropped — not a compliance
//! or durable-audit guarantee. Do not treat an empty table as proof that no
//! traffic occurred when the sink was unavailable. Batch writes are
//! transactional so a retry never encounters rows partially committed by its
//! own previous attempt. The hourly retention task is aborted with the plugin
//! generation, so repeated configuration reloads do not accumulate workers.
//! Native and translated gRPC transactions retain their terminal gRPC status
//! separately from the HTTP transport status. WebSocket uses its HTTP upgrade
//! transaction; this example deliberately does not capture frame payloads.
//! Request methods are capped at 256 Unicode characters before persistence so
//! hostile extension methods cannot exceed the portable MySQL column contract.
//!
//! ## Features Demonstrated
//!
//! - Database migrations via `plugin_migrations()` with multi-DB support
//! - Bounded queue + lifecycle-owned worker (`start_background_tasks`)
//! - `ALL_PROTOCOLS` coverage with HTTP `log` and stream disconnect hooks
//! - PostgreSQL-specific and MySQL-specific SQL overrides
//! - Multi-statement migrations with exact MySQL index reconciliation
//!
//! ## Configuration
//!
//! ```json
//! {
//!   "plugin_name": "example_audit_plugin",
//!   "config": {
//!     "log_request_headers": false,
//!     "retention_days": 90,
//!     "queue_capacity": 10000
//!   }
//! }
//! ```
//!
//! `log_request_headers` includes a redacted metadata / user-agent snapshot
//! when true. Full request headers are not available on the terminal log
//! hook; this field does not capture `Authorization` / cookie values.
//! `retention_days` accepts 1 through 36,500. Configure only one of
//! `queue_capacity` or its shared batching alias `buffer_capacity`.
//!
//! ## Running Migrations
//!
//! ```bash
//! FERRUM_CUSTOM_PLUGINS=example_audit_plugin \
//!   FERRUM_MODE=migrate FERRUM_MIGRATE_ACTION=up cargo run
//! ```

use async_trait::async_trait;
use serde_json::Value;
use sqlx::AnyPool;
use sqlx::any::AnyPoolOptions;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::warn;
use uuid::Uuid;

use crate::config::migrations::CustomPluginMigration;
use crate::plugins::utils::{
    BatchConfig, BatchConfigDefaults, BatchingLogger, build_batch_config, validate_batch_config,
};
use crate::plugins::{
    ALL_PROTOCOLS, Plugin, PluginHttpClient, ProxyProtocol, StreamTransactionSummary,
    TransactionSummary,
};

const TABLE_NAME: &str = "example_audit_log";
const PLUGIN_NAME: &str = "example_audit_plugin";
const MAX_RETENTION_DAYS: u64 = 36_500;
const MAX_HTTP_METHOD_CHARS: usize = 256;
const MAX_METADATA_ENTRIES: usize = 64;
const MAX_METADATA_KEY_CHARS: usize = 128;
const MAX_METADATA_VALUE_CHARS: usize = 512;
const MAX_CONTEXT_BYTES: usize = 4096;

#[derive(Clone)]
struct AuditRecord {
    id: String,
    timestamp: String,
    client_ip: String,
    protocol: String,
    http_method: Option<String>,
    request_path: Option<String>,
    response_status: Option<i32>,
    grpc_status: Option<i64>,
    latency_ms: f64,
    consumer_username: Option<String>,
    proxy_id: Option<String>,
    request_context: Option<String>,
    connection_error: Option<String>,
}

pub struct ExampleAuditPlugin {
    log_request_headers: bool,
    retention_days: u64,
    batch_config: BatchConfig,
    logger: Mutex<Option<BatchingLogger<AuditRecord>>>,
    retention_task: Mutex<Option<tokio::task::AbortHandle>>,
}

impl ExampleAuditPlugin {
    pub fn new(config: &Value) -> Result<Self, String> {
        let obj = config
            .as_object()
            .ok_or_else(|| "example_audit_plugin config must be a JSON object".to_string())?;

        for key in obj.keys() {
            if !matches!(
                key.as_str(),
                "log_request_headers"
                    | "retention_days"
                    | "queue_capacity"
                    | "batch_size"
                    | "flush_interval_ms"
                    | "max_retries"
                    | "retry_delay_ms"
                    | "buffer_capacity"
            ) {
                return Err(format!(
                    "example_audit_plugin config contains unknown key '{key}'; \
                     expected only log_request_headers, retention_days, and optional batch keys \
                     (queue_capacity/buffer_capacity, batch_size, flush_interval_ms, max_retries, retry_delay_ms). \
                     Storage uses the gateway database (FERRUM_DB_URL / FERRUM_DB_TYPE); \
                     per-plugin db_url/db_type are not supported."
                ));
            }
        }

        let log_request_headers = match config.get("log_request_headers") {
            None | Some(Value::Null) => false,
            Some(value) => value
                .as_bool()
                .ok_or_else(|| "log_request_headers must be a boolean".to_string())?,
        };

        let retention_days = match config.get("retention_days") {
            None | Some(Value::Null) => 90,
            Some(value) => {
                let days = value
                    .as_u64()
                    .ok_or_else(|| "retention_days must be a positive integer".to_string())?;
                if days == 0 {
                    return Err("retention_days must be greater than zero".to_string());
                }
                if days > MAX_RETENTION_DAYS {
                    return Err(format!(
                        "retention_days must not exceed {MAX_RETENTION_DAYS}"
                    ));
                }
                days
            }
        };

        let queue_capacity_configured = config
            .get("queue_capacity")
            .is_some_and(|value| !value.is_null());
        let buffer_capacity_configured = config
            .get("buffer_capacity")
            .is_some_and(|value| !value.is_null());
        if queue_capacity_configured && buffer_capacity_configured {
            return Err(
                "example_audit_plugin: configure only one of queue_capacity or buffer_capacity"
                    .to_string(),
            );
        }

        let queue_capacity = match config
            .get("queue_capacity")
            .filter(|value| !value.is_null())
            .or_else(|| {
                config
                    .get("buffer_capacity")
                    .filter(|value| !value.is_null())
            }) {
            None | Some(Value::Null) => 10_000u64,
            Some(value) => {
                let capacity = value
                    .as_u64()
                    .ok_or_else(|| "queue_capacity must be a positive integer".to_string())?;
                if capacity == 0 {
                    return Err("queue_capacity must be greater than zero".to_string());
                }
                capacity
            }
        };

        let batch_defaults = BatchConfigDefaults {
            batch_size_key: "batch_size",
            batch_size: 50,
            flush_interval_ms: 1000,
            min_flush_interval_ms: 100,
            buffer_capacity: queue_capacity,
            max_retries: 3,
            retry_delay_ms: 1000,
        };
        // validate_batch_config expects buffer_capacity on the config object;
        // synthesize a view that includes the resolved queue capacity.
        let mut batch_cfg_value = config.clone();
        if let Some(obj) = batch_cfg_value.as_object_mut() {
            obj.insert("buffer_capacity".to_string(), Value::from(queue_capacity));
        }
        validate_batch_config(&batch_cfg_value, PLUGIN_NAME, batch_defaults)?;
        let batch_config = build_batch_config(&batch_cfg_value, PLUGIN_NAME, batch_defaults);

        Ok(Self {
            log_request_headers,
            retention_days,
            batch_config,
            logger: Mutex::new(None),
            retention_task: Mutex::new(None),
        })
    }

    fn enqueue(&self, record: AuditRecord) {
        let Ok(guard) = self.logger.lock() else {
            warn!(
                plugin = PLUGIN_NAME,
                "example_audit_plugin: logger lock poisoned; dropping audit record"
            );
            return;
        };
        match guard.as_ref() {
            Some(logger) => {
                let _ = logger.try_send(record);
            }
            None => {
                warn!(
                    plugin = PLUGIN_NAME,
                    "example_audit_plugin: dropping audit record because the \
                     background worker has not started (start_background_tasks)"
                );
            }
        }
    }

    fn record_from_http(&self, summary: &TransactionSummary) -> AuditRecord {
        let request_context = if self.log_request_headers {
            Some(bounded_http_context(summary))
        } else {
            None
        };
        let grpc_status = summary.grpc_status().map(i64::from);
        AuditRecord {
            id: Uuid::new_v4().to_string(),
            timestamp: canonical_timestamp(&summary.timestamp_received),
            client_ip: summary.client_ip.clone(),
            protocol: if grpc_status.is_some() {
                "grpc".to_string()
            } else {
                "http".to_string()
            },
            http_method: Some(truncate_chars(
                &summary.http_method,
                MAX_HTTP_METHOD_CHARS,
            )),
            request_path: Some(truncate_chars(&summary.request_path, 2048)),
            response_status: Some(i32::from(summary.response_status_code)),
            grpc_status,
            latency_ms: summary.latency_total_ms,
            consumer_username: summary.consumer_username.clone(),
            proxy_id: summary.proxy_id.clone(),
            request_context,
            connection_error: summary
                .error_class
                .as_ref()
                .map(|c| format!("{c:?}"))
                .or_else(|| {
                    summary
                        .body_error_class
                        .as_ref()
                        .map(|c| format!("{c:?}"))
                }),
        }
    }

    fn record_from_stream(&self, summary: &StreamTransactionSummary) -> AuditRecord {
        let request_context = if self.log_request_headers {
            Some(bounded_stream_context(summary))
        } else {
            None
        };
        AuditRecord {
            id: Uuid::new_v4().to_string(),
            timestamp: canonical_timestamp(&summary.timestamp_disconnected),
            client_ip: summary.client_ip.clone(),
            protocol: summary.protocol.clone(),
            http_method: None,
            request_path: None,
            response_status: None,
            grpc_status: None,
            latency_ms: summary.duration_ms,
            consumer_username: summary.consumer_username.clone(),
            proxy_id: Some(summary.proxy_id.clone()),
            request_context,
            connection_error: summary.connection_error.clone(),
        }
    }
}

fn bounded_http_context(summary: &TransactionSummary) -> String {
    let mut map = serde_json::Map::new();
    if let Some(ua) = &summary.request_user_agent {
        map.insert(
            "user_agent".to_string(),
            Value::String(truncate_chars(ua, 512)),
        );
    }
    if let Some(auth) = summary.auth_method {
        map.insert("auth_method".to_string(), Value::String(auth.to_string()));
    }
    map.insert(
        "metadata".to_string(),
        bounded_redacted_metadata(&summary.metadata),
    );
    encode_bounded_context(map)
}

fn bounded_stream_context(summary: &StreamTransactionSummary) -> String {
    let mut map = serde_json::Map::new();
    if let Some(auth) = summary.auth_method {
        map.insert("auth_method".to_string(), Value::String(auth.to_string()));
    }
    if let Some(sni) = &summary.sni_hostname {
        map.insert(
            "sni_hostname".to_string(),
            Value::String(truncate_chars(sni, 256)),
        );
    }
    map.insert(
        "metadata".to_string(),
        bounded_redacted_metadata(&summary.metadata),
    );
    encode_bounded_context(map)
}

fn encode_bounded_context(map: serde_json::Map<String, Value>) -> String {
    let encoded = Value::Object(map).to_string();
    if encoded.len() <= MAX_CONTEXT_BYTES {
        encoded
    } else {
        // Never byte/character-slice serialized JSON: doing so can leave an
        // invalid document or split an escape sequence. Oversized context is
        // represented by a small valid marker instead.
        serde_json::json!({
            "metadata": {
                "__ferrum_context_truncated": true
            }
        })
        .to_string()
    }
}

fn bounded_redacted_metadata(metadata: &std::collections::HashMap<String, String>) -> Value {
    use crate::plugins::utils::metadata_redaction::{
        REDACTED_PLACEHOLDER, is_sensitive_metadata_key,
    };

    let mut bounded = serde_json::Map::new();
    for (key, value) in metadata.iter().take(MAX_METADATA_ENTRIES) {
        let value = if is_sensitive_metadata_key(key) {
            REDACTED_PLACEHOLDER.to_string()
        } else {
            truncate_chars(value, MAX_METADATA_VALUE_CHARS)
        };
        bounded.insert(truncate_chars(key, MAX_METADATA_KEY_CHARS), Value::String(value));
    }
    let omitted = metadata.len().saturating_sub(MAX_METADATA_ENTRIES);
    if omitted > 0 {
        bounded.insert(
            "__ferrum_omitted_metadata_entries".to_string(),
            Value::from(omitted as u64),
        );
    }
    Value::Object(bounded)
}

fn truncate_chars(input: &str, max_chars: usize) -> String {
    if input.chars().count() <= max_chars {
        return input.to_string();
    }
    input.chars().take(max_chars).collect()
}

fn canonical_timestamp(input: &str) -> String {
    match chrono::DateTime::parse_from_rfc3339(input) {
        Ok(timestamp) => timestamp
            .with_timezone(&chrono::Utc)
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        Err(error) => {
            warn!(
                plugin = PLUGIN_NAME,
                error = %error,
                "example_audit_plugin: transaction summary carried an invalid timestamp; using current time"
            );
            chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
        }
    }
}

fn connect_gateway_pool_lazy() -> Result<AnyPool, String> {
    let db_url = std::env::var("FERRUM_DB_URL").map_err(|_| {
        "example_audit_plugin requires FERRUM_DB_URL (gateway configuration database)".to_string()
    })?;
    let db_type = std::env::var("FERRUM_DB_TYPE").unwrap_or_else(|_| "sqlite".to_string());
    if !matches!(db_type.as_str(), "sqlite" | "postgres" | "mysql") {
        return Err(format!(
            "example_audit_plugin: unsupported FERRUM_DB_TYPE '{db_type}' \
             (expected sqlite, postgres, or mysql)"
        ));
    }
    // Never log the raw URL — it may embed credentials. Use a lazy pool so
    // `start_background_tasks` stays sync-safe on the Tokio runtime; the first
    // flush surfaces connectivity errors through the batching retry/warn path.
    sqlx::any::install_default_drivers();
    let is_sqlite = db_type == "sqlite";
    AnyPoolOptions::new()
        .max_connections(2)
        .min_connections(0)
        .acquire_timeout(Duration::from_secs(5))
        .after_connect(move |conn, _meta| {
            Box::pin(async move {
                if is_sqlite {
                    use sqlx::Executor;
                    conn.execute("PRAGMA foreign_keys = ON").await?;
                    conn.execute("PRAGMA busy_timeout = 5000").await?;
                }
                Ok(())
            })
        })
        .connect_lazy(&db_url)
        .map_err(|_| {
            "example_audit_plugin: failed to create gateway database pool from FERRUM_DB_URL"
                .to_string()
        })
}

async fn insert_batch(pool: &AnyPool, batch: Vec<AuditRecord>) -> Result<(), String> {
    let mut transaction = pool
        .begin()
        .await
        .map_err(|e| format!("example_audit_plugin batch transaction failed: {e}"))?;
    for record in batch {
        sqlx::query(
            r#"
            INSERT INTO example_audit_log (
                id, timestamp, client_ip, protocol, http_method, request_path,
                response_status, grpc_status, latency_ms, consumer_username, proxy_id,
                request_context, connection_error
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&record.id)
        .bind(&record.timestamp)
        .bind(&record.client_ip)
        .bind(&record.protocol)
        .bind(&record.http_method)
        .bind(&record.request_path)
        .bind(record.response_status)
        .bind(record.grpc_status)
        .bind(record.latency_ms)
        .bind(&record.consumer_username)
        .bind(&record.proxy_id)
        .bind(&record.request_context)
        .bind(&record.connection_error)
        .execute(&mut *transaction)
        .await
        .map_err(|e| format!("example_audit_plugin insert failed: {e}"))?;
    }
    transaction
        .commit()
        .await
        .map_err(|e| format!("example_audit_plugin batch commit failed: {e}"))
}

async fn run_retention(pool: AnyPool, retention_days: u64) {
    let mut interval = tokio::time::interval(Duration::from_secs(3600));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        let cutoff = (chrono::Utc::now() - chrono::Duration::days(retention_days as i64))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        match sqlx::query(&format!(
            "DELETE FROM {TABLE_NAME} WHERE timestamp < ?"
        ))
        .bind(&cutoff)
        .execute(&pool)
        .await
        {
            Ok(result) => {
                let deleted = result.rows_affected();
                if deleted > 0 {
                    tracing::info!(
                        plugin = PLUGIN_NAME,
                        deleted,
                        retention_days,
                        "example_audit_plugin: purged expired audit rows"
                    );
                }
            }
            Err(e) => {
                warn!(
                    plugin = PLUGIN_NAME,
                    error = %e,
                    "example_audit_plugin: retention delete failed"
                );
            }
        }
    }
}

impl Drop for ExampleAuditPlugin {
    fn drop(&mut self) {
        let retention_task = match self.retention_task.get_mut() {
            Ok(task) => task,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(task) = retention_task.take() {
            task.abort();
        }
    }
}

#[async_trait]
impl Plugin for ExampleAuditPlugin {
    fn name(&self) -> &str {
        PLUGIN_NAME
    }

    fn priority(&self) -> u16 {
        // Run in the logging band, after all other processing
        9150
    }

    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        ALL_PROTOCOLS
    }

    fn start_background_tasks(&self) -> Result<(), String> {
        let mut logger_guard = self
            .logger
            .lock()
            .map_err(|_| "example_audit_plugin: logger lock poisoned".to_string())?;
        if logger_guard.is_some() {
            return Ok(());
        }
        let mut retention_guard = self
            .retention_task
            .lock()
            .map_err(|_| "example_audit_plugin: retention lock poisoned".to_string())?;

        let runtime = tokio::runtime::Handle::try_current().map_err(|_| {
            "example_audit_plugin: start_background_tasks requires a Tokio runtime".to_string()
        })?;

        let pool = connect_gateway_pool_lazy()?;
        let flush_pool = pool.clone();
        let logger = BatchingLogger::spawn(self.batch_config, move |batch| {
            let pool = flush_pool.clone();
            async move { insert_batch(&pool, batch).await }
        });

        let retention_pool = pool.clone();
        let retention_days = self.retention_days;
        let retention_task = runtime
            .spawn(async move {
                run_retention(retention_pool, retention_days).await;
            })
            .abort_handle();
        *logger_guard = Some(logger);
        *retention_guard = Some(retention_task);

        Ok(())
    }

    /// Record each HTTP-family transaction. Buffered handlers await this hook;
    /// hyper-owned streaming bodies invoke it from a spawned terminal task;
    /// native H3 awaits it after body completion. The hot path only enqueues.
    async fn log(&self, summary: &TransactionSummary) {
        self.enqueue(self.record_from_http(summary));
    }

    /// Record TCP/TLS, UDP/DTLS, and other stream sessions at disconnect.
    /// WebSocket upgraded sessions are covered by the HTTP `log()` hook for
    /// the handshake transaction; this hook covers native stream proxies.
    async fn on_stream_disconnect(&self, summary: &StreamTransactionSummary) {
        self.enqueue(self.record_from_stream(summary));
    }
}

/// Factory function — called automatically by the build-script-generated registry.
/// Must return `Result` so invalid configs are rejected at admission time.
pub fn create_plugin(
    config: &Value,
    _http_client: PluginHttpClient,
) -> Result<Option<Arc<dyn Plugin>>, String> {
    Ok(Some(Arc::new(ExampleAuditPlugin::new(config)?)))
}

pub fn failure_policy() -> crate::plugins::PluginFailurePolicy {
    // Best-effort telemetry: a bad new config can fall back to the previous
    // generation rather than taking down the proxy. Storage failures at flush
    // time are still only warnings — see the module failure contract.
    crate::plugins::PluginFailurePolicy::OptionalFailOpen
}

/// Database migrations for this plugin.
///
/// Discovered by the build script when this example is opted in via
/// `FERRUM_CUSTOM_PLUGINS`. Applied against the gateway configuration
/// database by migrate mode / `FERRUM_AUTO_APPLY_PLUGIN_MIGRATIONS`.
///
/// ## Guidelines
///
/// - Version numbers are scoped to this plugin (start at 1, increment by 1)
/// - Table names are plugin-prefixed (`example_audit_log`) to avoid collisions
/// - The `sql` field is the default SQL used for all databases
/// - Use `sql_postgres` / `sql_mysql` for database-specific overrides
/// - Multi-statement SQL is supported (separate statements with `;`)
/// - MySQL index reconciliation is retry-safe: pair `DROP INDEX` with
///   `CREATE INDEX`; the runner tolerates only a structured missing-key (1091)
///   error on the drop so every retry reconstructs the intended definition
pub fn plugin_migrations() -> Vec<CustomPluginMigration> {
    vec![
        CustomPluginMigration {
            version: 1,
            name: "create_example_audit_log",
            checksum: "v1_create_example_audit_log_7c2b31",
            sql: r#"
                CREATE TABLE IF NOT EXISTS example_audit_log (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    client_ip TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    http_method TEXT,
                    request_path TEXT,
                    response_status INTEGER,
                    grpc_status INTEGER,
                    latency_ms REAL NOT NULL,
                    consumer_username TEXT,
                    proxy_id TEXT,
                    request_context TEXT,
                    connection_error TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_example_audit_log_timestamp ON example_audit_log (timestamp);
                CREATE INDEX IF NOT EXISTS idx_example_audit_log_client_ip ON example_audit_log (client_ip)
            "#,
            sql_postgres: Some(
                r#"
                CREATE TABLE IF NOT EXISTS example_audit_log (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    client_ip TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    http_method TEXT,
                    request_path TEXT,
                    response_status INTEGER,
                    grpc_status BIGINT,
                    latency_ms DOUBLE PRECISION NOT NULL,
                    consumer_username TEXT,
                    proxy_id TEXT,
                    request_context TEXT,
                    connection_error TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_example_audit_log_timestamp ON example_audit_log (timestamp);
                CREATE INDEX IF NOT EXISTS idx_example_audit_log_client_ip ON example_audit_log (client_ip)
            "#,
            ),
            // MySQL index DDL implicitly commits. Rebuild these plugin-owned
            // indexes from their intended definitions on every retry; the
            // runner tolerates only missing-key 1091 on each DROP INDEX.
            sql_mysql: Some(
                r#"
                CREATE TABLE IF NOT EXISTS example_audit_log (
                    id VARCHAR(255) PRIMARY KEY,
                    timestamp VARCHAR(32) NOT NULL,
                    client_ip VARCHAR(255) NOT NULL,
                    protocol VARCHAR(32) NOT NULL,
                    http_method VARCHAR(256),
                    request_path TEXT,
                    response_status INTEGER,
                    grpc_status BIGINT,
                    latency_ms DOUBLE NOT NULL,
                    consumer_username VARCHAR(255),
                    proxy_id VARCHAR(255),
                    request_context TEXT,
                    connection_error TEXT
                );
                DROP INDEX idx_example_audit_log_timestamp ON example_audit_log;
                CREATE INDEX idx_example_audit_log_timestamp ON example_audit_log (timestamp);
                DROP INDEX idx_example_audit_log_client_ip ON example_audit_log;
                CREATE INDEX idx_example_audit_log_client_ip ON example_audit_log (client_ip)
            "#,
            ),
        },
        CustomPluginMigration {
            version: 2,
            name: "add_status_timestamp_index",
            checksum: "v2_example_audit_status_ts_91e4c6",
            sql: "CREATE INDEX IF NOT EXISTS idx_example_audit_log_status_ts ON example_audit_log (response_status, timestamp)",
            sql_postgres: None,
            sql_mysql: Some(
                "DROP INDEX idx_example_audit_log_status_ts ON example_audit_log; \
                 CREATE INDEX idx_example_audit_log_status_ts ON example_audit_log (response_status, timestamp)",
            ),
        },
    ]
}
