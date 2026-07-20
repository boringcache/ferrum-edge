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
    create_example_audit_plugin(&config).expect_err("config should be rejected")
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
    let start_err = plugin
        .start_background_tasks()
        .expect_err("missing FERRUM_DB_URL must fail");
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

    // SAFETY: temporary env for this multi-thread test; restored below.
    let prev_url = std::env::var("FERRUM_DB_URL").ok();
    let prev_type = std::env::var("FERRUM_DB_TYPE").ok();
    unsafe {
        std::env::set_var("FERRUM_DB_URL", &db_url);
        std::env::set_var("FERRUM_DB_TYPE", "sqlite");
    }

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
    plugin
        .start_background_tasks()
        .expect("worker should start with FERRUM_DB_URL");

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
            metadata: HashMap::from([("cookie".to_string(), "session=1".to_string())]),
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
    let mut saw_stream = false;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let rows = sqlx::query(
            "SELECT protocol, client_ip, http_method, response_status FROM example_audit_log",
        )
        .fetch_all(&pool)
        .await
        .unwrap_or_default();
        for row in &rows {
            let protocol: String = row.get("protocol");
            let client_ip: String = row.get("client_ip");
            let method: Option<String> = row.get("http_method");
            let status: Option<i32> = row.try_get("response_status").ok().flatten();
            if protocol == "http" && client_ip == "192.0.2.10" {
                assert_eq!(method.as_deref(), Some("POST"));
                assert_eq!(status, Some(201));
                saw_http = true;
            }
            if protocol == "tcp" && client_ip == "192.0.2.11" {
                assert!(method.is_none());
                assert!(status.is_none());
                saw_stream = true;
            }
        }
        if saw_http && saw_stream {
            break;
        }
    }

    match prev_url {
        Some(v) => unsafe { std::env::set_var("FERRUM_DB_URL", v) },
        None => unsafe { std::env::remove_var("FERRUM_DB_URL") },
    }
    match prev_type {
        Some(v) => unsafe { std::env::set_var("FERRUM_DB_TYPE", v) },
        None => unsafe { std::env::remove_var("FERRUM_DB_TYPE") },
    }

    assert!(saw_http, "expected HTTP audit row");
    assert!(saw_stream, "expected stream audit row");

    // Redacted context must not contain the raw cookie value.
    let ctx_row = sqlx::query(
        "SELECT request_context FROM example_audit_log WHERE protocol = 'http' LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .expect("http row context");
    let ctx: Option<String> = ctx_row.get("request_context");
    let ctx = ctx.as_deref().unwrap_or("");
    assert!(
        !ctx.contains("session=1"),
        "secret cookie must be redacted: {ctx}"
    );
    assert!(
        ctx.contains("[REDACTED]") || ctx.contains("metadata"),
        "expected redacted metadata snapshot: {ctx}"
    );
}
