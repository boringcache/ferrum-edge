//! Tests for the `example_audit_plugin` custom-plugin template.
//!
//! The template's `new()` must honor the `custom_plugins/mod.rs` contract —
//! return `Err` for a config key that is present but has the wrong type or an
//! invalid value, while still defaulting absent/null keys. Persistence,
//! protocol coverage, and migration contracts are covered when the example is
//! compiled in via `FERRUM_CUSTOM_PLUGINS`.

use ferrum_edge::custom_plugins::{
    collect_all_custom_plugin_migrations, create_custom_plugin, custom_plugin_names,
};
use ferrum_edge::plugins::{
    ALL_PROTOCOLS, Plugin, PluginHttpClient, StreamTransactionSummary, TransactionSummary,
};
use serde_json::json;
use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::sync::Arc;
use std::time::Duration;

fn example_audit_plugin_registered() -> bool {
    custom_plugin_names().contains(&"example_audit_plugin")
}

fn create_example_audit_plugin(
    config: &serde_json::Value,
) -> Result<Option<Arc<dyn Plugin>>, String> {
    create_custom_plugin("example_audit_plugin", config, PluginHttpClient::default())
}

struct ScopedEnv {
    key: &'static str,
    previous: Option<OsString>,
}

impl ScopedEnv {
    fn set(key: &'static str, value: impl AsRef<OsStr>) -> Self {
        let previous = std::env::var_os(key);
        // SAFETY: callers hold the repository-wide ENV_LOCK while mutating
        // process-global variables; this guard restores the prior value.
        unsafe { std::env::set_var(key, value) };
        Self { key, previous }
    }

    fn remove(key: &'static str) -> Self {
        let previous = std::env::var_os(key);
        // SAFETY: see `set`; the shared ENV_LOCK excludes sibling mutation.
        unsafe { std::env::remove_var(key) };
        Self { key, previous }
    }
}

impl Drop for ScopedEnv {
    fn drop(&mut self) {
        match self.previous.take() {
            Some(value) => {
                // SAFETY: restoration occurs before the caller releases ENV_LOCK.
                unsafe { std::env::set_var(self.key, value) };
            }
            None => {
                // SAFETY: restoration occurs before the caller releases ENV_LOCK.
                unsafe { std::env::remove_var(self.key) };
            }
        }
    }
}

#[test]
fn test_new_uses_defaults_for_absent_or_null_keys() {
    if !example_audit_plugin_registered() {
        return;
    }

    assert!(create_example_audit_plugin(&json!({})).unwrap().is_some());
    assert!(
        create_example_audit_plugin(&json!({
            "log_request_headers": null,
            "retention_days": null,
        }))
        .unwrap()
        .is_some()
    );
}

#[test]
fn test_new_accepts_valid_values() {
    if !example_audit_plugin_registered() {
        return;
    }

    assert!(
        create_example_audit_plugin(&json!({
            "log_request_headers": true,
            "retention_days": 30,
            "queue_capacity": 100,
        }))
        .unwrap()
        .is_some()
    );
}

fn new_err(config: serde_json::Value) -> String {
    match create_example_audit_plugin(&config) {
        Ok(_) => panic!("config should be rejected"),
        Err(error) => error,
    }
}

#[test]
fn test_new_rejects_wrong_typed_log_request_headers() {
    if !example_audit_plugin_registered() {
        return;
    }

    let err = new_err(json!({ "log_request_headers": "true" }));
    assert!(err.contains("log_request_headers"), "got: {err}");
}

#[test]
fn test_new_rejects_wrong_typed_retention_days() {
    if !example_audit_plugin_registered() {
        return;
    }

    let err = new_err(json!({ "retention_days": "ninety" }));
    assert!(err.contains("retention_days"), "got: {err}");

    assert!(create_example_audit_plugin(&json!({ "retention_days": -5 })).is_err());
}

#[test]
fn test_new_rejects_zero_retention_days() {
    if !example_audit_plugin_registered() {
        return;
    }

    let err = new_err(json!({ "retention_days": 0 }));
    assert!(err.contains("retention_days"), "got: {err}");
}

#[test]
fn test_new_rejects_excessive_retention_and_conflicting_queue_aliases() {
    if !example_audit_plugin_registered() {
        return;
    }

    let retention_err = new_err(json!({ "retention_days": 36_501 }));
    assert!(
        retention_err.contains("retention_days"),
        "got: {retention_err}"
    );

    let queue_err = new_err(json!({
        "queue_capacity": 100,
        "buffer_capacity": 100,
    }));
    assert!(queue_err.contains("only one"), "got: {queue_err}");
}

#[test]
fn test_new_rejects_unknown_keys_and_legacy_db_url() {
    if !example_audit_plugin_registered() {
        return;
    }

    let err = new_err(json!({ "db_url": "sqlite://x.db" }));
    assert!(
        err.contains("unknown key") || err.contains("db_url"),
        "got: {err}"
    );
}

#[test]
fn test_supported_protocols_is_all_protocols() {
    if !example_audit_plugin_registered() {
        return;
    }

    let plugin = create_example_audit_plugin(&json!({}))
        .unwrap()
        .expect("plugin instance");
    assert_eq!(plugin.supported_protocols(), ALL_PROTOCOLS);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_log_and_stream_hooks_enqueue_without_panic() {
    if !example_audit_plugin_registered() {
        return;
    }

    let plugin = create_example_audit_plugin(&json!({
        "log_request_headers": true,
        "retention_days": 7,
        "queue_capacity": 16,
        "flush_interval_ms": 100,
    }))
    .unwrap()
    .expect("plugin instance");

    // Without FERRUM_DB_URL, start_background_tasks must fail closed rather
    // than silently claiming a durable sink.
    let start_err = {
        let _env_lock = crate::unit::env_lock::ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _db_url = ScopedEnv::remove("FERRUM_DB_URL");
        plugin
            .start_background_tasks()
            .expect_err("missing FERRUM_DB_URL must fail")
    };
    assert!(start_err.contains("FERRUM_DB_URL"), "got: {start_err}");

    // Hooks remain panic-free even when the worker was not started.
    let http = TransactionSummary {
        timestamp_received: "2026-01-01T00:00:00Z".to_string(),
        client_ip: "127.0.0.1".to_string(),
        http_method: "GET".to_string(),
        request_path: "/audit".to_string(),
        response_status_code: 200,
        latency_total_ms: 12.5,
        metadata: HashMap::from([("authorization".to_string(), "secret".to_string())]),
        ..Default::default()
    };
    plugin.log(&http).await;

    let stream = StreamTransactionSummary {
        namespace: "ferrum".to_string(),
        proxy_id: "p1".to_string(),
        proxy_name: None,
        client_ip: "10.0.0.1".to_string(),
        consumer_username: None,
        auth_method: None,
        backend_target: "10.0.0.2:443".to_string(),
        backend_resolved_ip: None,
        protocol: "tcp".to_string(),
        listen_port: 443,
        duration_ms: 40.0,
        bytes_sent: 1,
        bytes_received: 2,
        connection_error: None,
        error_class: None,
        disconnect_direction: None,
        disconnect_cause: None,
        timestamp_connected: "2026-01-01T00:00:00Z".to_string(),
        timestamp_disconnected: "2026-01-01T00:00:01Z".to_string(),
        sni_hostname: None,
        metadata: HashMap::new(),
    };
    plugin.on_stream_disconnect(&stream).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_persists_http_and_stream_rows_against_sqlite() {
    if !example_audit_plugin_registered() {
        return;
    }

    use ferrum_edge::config::db_backend::DatabaseBackend;
    use ferrum_edge::config::db_loader::{DatabaseStore, DbPoolConfig};

    let dir = tempfile::TempDir::new().unwrap();
    let db_path = dir.path().join("audit.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.display());

    // Apply the example's migrations against the same gateway DB URL the
    // plugin will use at runtime.
    let store = DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
        .await
        .expect("core migrations");
    let pool = store.pool();
    let migrations = collect_all_custom_plugin_migrations();
    assert!(
        migrations
            .iter()
            .any(|(name, _)| *name == "example_audit_plugin"),
        "opted-in build must collect example_audit_plugin migrations"
    );
    store
        .apply_plugin_migrations(&migrations)
        .await
        .expect("example migrations");

    sqlx::query(
        "INSERT INTO example_audit_log \
         (id, timestamp, client_ip, protocol, latency_ms) \
         VALUES ('expired-row', '2000-01-01T00:00:00.000Z', '192.0.2.99', 'http', 1.0)",
    )
    .execute(&pool)
    .await
    .expect("seed expired retention row");

    let plugin = create_example_audit_plugin(&json!({
        "log_request_headers": true,
        "retention_days": 30,
        "queue_capacity": 32,
        "batch_size": 1,
        "flush_interval_ms": 100,
        "max_retries": 1,
        "retry_delay_ms": 50,
    }))
    .unwrap()
    .expect("plugin");
    {
        let _env_lock = crate::unit::env_lock::ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _db_url = ScopedEnv::set("FERRUM_DB_URL", &db_url);
        let _db_type = ScopedEnv::set("FERRUM_DB_TYPE", "sqlite");
        plugin
            .start_background_tasks()
            .expect("worker should start with FERRUM_DB_URL");
    }

    plugin
        .log(&TransactionSummary {
            timestamp_received: "2026-07-20T12:00:00.000Z".to_string(),
            client_ip: "192.0.2.10".to_string(),
            http_method: "POST".to_string(),
            request_path: "/v1/widgets".to_string(),
            response_status_code: 201,
            latency_total_ms: 3.25,
            consumer_username: Some("alice".to_string()),
            proxy_id: Some("proxy-1".to_string()),
            metadata: HashMap::from([
                ("cookie".to_string(), "session=1".to_string()),
                ("note".to_string(), "x".repeat(10_000)),
            ]),
            ..Default::default()
        })
        .await;

    plugin
        .log(&TransactionSummary {
            timestamp_received: "2026-07-20T12:00:00.500Z".to_string(),
            client_ip: "192.0.2.14".to_string(),
            http_method: "POST".to_string(),
            request_path: "/example.Audit/Write".to_string(),
            response_status_code: 200,
            latency_total_ms: 4.0,
            metadata: HashMap::from([
                ("request_protocol".to_string(), "grpc".to_string()),
                ("grpc_status".to_string(), "13".to_string()),
            ]),
            ..Default::default()
        })
        .await;

    plugin
        .log(&TransactionSummary {
            timestamp_received: "2026-07-20T12:00:00.750Z".to_string(),
            client_ip: "192.0.2.15".to_string(),
            http_method: "M".repeat(300),
            request_path: "/bounded-method".to_string(),
            response_status_code: 200,
            latency_total_ms: 1.0,
            ..Default::default()
        })
        .await;

    plugin
        .on_stream_disconnect(&StreamTransactionSummary {
            namespace: "ferrum".to_string(),
            proxy_id: "stream-1".to_string(),
            proxy_name: Some("tcp-in".to_string()),
            client_ip: "192.0.2.11".to_string(),
            consumer_username: None,
            auth_method: None,
            backend_target: "192.0.2.20:5432".to_string(),
            backend_resolved_ip: None,
            protocol: "tcp".to_string(),
            listen_port: 5432,
            duration_ms: 88.0,
            bytes_sent: 10,
            bytes_received: 20,
            connection_error: Some("reset".to_string()),
            error_class: None,
            disconnect_direction: None,
            disconnect_cause: None,
            timestamp_connected: "2026-07-20T12:00:00.000Z".to_string(),
            timestamp_disconnected: "2026-07-20T12:00:01.000Z".to_string(),
            sni_hostname: None,
            metadata: HashMap::new(),
        })
        .await;

    // Allow the batching worker to flush.
    use sqlx::Row;
    let mut saw_http = false;
    let mut saw_grpc = false;
    let mut saw_bounded_method = false;
    let mut saw_stream = false;
    let mut expired_gone = false;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let rows = sqlx::query(
            "SELECT id, protocol, client_ip, http_method, response_status, grpc_status \
             FROM example_audit_log",
        )
        .fetch_all(&pool)
        .await
        .unwrap_or_default();
        expired_gone = rows
            .iter()
            .all(|row| row.get::<String, _>("id") != "expired-row");
        for row in &rows {
            let protocol: String = row.get("protocol");
            let client_ip: String = row.get("client_ip");
            let method: Option<String> = row.get("http_method");
            let status: Option<i32> = row.try_get("response_status").ok().flatten();
            let grpc_status: Option<i64> = row.try_get("grpc_status").ok().flatten();
            if protocol == "http" && client_ip == "192.0.2.10" {
                assert_eq!(method.as_deref(), Some("POST"));
                assert_eq!(status, Some(201));
                saw_http = true;
            }
            if protocol == "grpc" && client_ip == "192.0.2.14" {
                assert_eq!(method.as_deref(), Some("POST"));
                assert_eq!(status, Some(200));
                assert_eq!(grpc_status, Some(13));
                saw_grpc = true;
            }
            if protocol == "http" && client_ip == "192.0.2.15" {
                let method = method.as_deref().expect("bounded HTTP method");
                assert_eq!(method.chars().count(), 256);
                assert!(method.chars().all(|c| c == 'M'));
                saw_bounded_method = true;
            }
            if protocol == "tcp" && client_ip == "192.0.2.11" {
                assert!(method.is_none());
                assert!(status.is_none());
                saw_stream = true;
            }
        }
        if saw_http && saw_grpc && saw_bounded_method && saw_stream && expired_gone {
            break;
        }
    }

    assert!(saw_http, "expected HTTP audit row");
    assert!(saw_grpc, "expected gRPC audit row with terminal status");
    assert!(
        saw_bounded_method,
        "expected overlong HTTP method to persist within the portable column bound"
    );
    assert!(saw_stream, "expected stream audit row");
    assert!(expired_gone, "retention worker must purge the expired row");

    // Redacted context must not contain the raw cookie value.
    let ctx_row = sqlx::query(
        "SELECT request_context FROM example_audit_log WHERE protocol = 'http' LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .expect("http row context");
    let ctx: Option<String> = ctx_row.get("request_context");
    let ctx = ctx.as_deref().unwrap_or("");
    assert!(ctx.len() <= 4096, "context must stay byte-bounded");
    serde_json::from_str::<serde_json::Value>(ctx).expect("context must remain valid JSON");
    assert!(
        !ctx.contains("session=1"),
        "secret cookie must be redacted: {ctx}"
    );
    assert!(
        ctx.contains("[REDACTED]") || ctx.contains("metadata"),
        "expected redacted metadata snapshot: {ctx}"
    );

    // The documented OptionalFailOpen contract drops a failed batch and keeps
    // the worker alive for later records. Make the table briefly unavailable,
    // then restore it and prove a subsequent record persists.
    sqlx::query("ALTER TABLE example_audit_log RENAME TO example_audit_log_unavailable")
        .execute(&pool)
        .await
        .expect("make audit table unavailable");
    plugin
        .log(&TransactionSummary {
            timestamp_received: "2026-07-20T12:00:02.000Z".to_string(),
            client_ip: "192.0.2.12".to_string(),
            http_method: "GET".to_string(),
            request_path: "/dropped-during-outage".to_string(),
            response_status_code: 200,
            latency_total_ms: 1.0,
            ..Default::default()
        })
        .await;
    // Leave enough wall time for both immediate attempts even on a loaded
    // hosted runner before restoring the table.
    tokio::time::sleep(Duration::from_secs(1)).await;
    sqlx::query("ALTER TABLE example_audit_log_unavailable RENAME TO example_audit_log")
        .execute(&pool)
        .await
        .expect("restore audit table");
    plugin
        .log(&TransactionSummary {
            timestamp_received: "2026-07-20T12:00:03.000Z".to_string(),
            client_ip: "192.0.2.13".to_string(),
            http_method: "GET".to_string(),
            request_path: "/after-recovery".to_string(),
            response_status_code: 200,
            latency_total_ms: 1.0,
            ..Default::default()
        })
        .await;

    let mut recovered = false;
    for _ in 0..30 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let paths: Vec<String> = sqlx::query("SELECT request_path FROM example_audit_log")
            .fetch_all(&pool)
            .await
            .unwrap_or_default()
            .into_iter()
            .filter_map(|row| row.try_get("request_path").ok())
            .collect();
        assert!(
            !paths.iter().any(|path| path == "/dropped-during-outage"),
            "failed batch must not appear after its retry budget is exhausted"
        );
        if paths.iter().any(|path| path == "/after-recovery") {
            recovered = true;
            break;
        }
    }
    assert!(
        recovered,
        "batching worker must persist after storage recovery"
    );
}
