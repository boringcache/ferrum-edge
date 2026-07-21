//! Live MySQL contracts for custom-plugin migration recovery.

use std::time::Duration;

use ferrum_edge::config::migrations::MigrationRunner;
use sqlx::Row;
use testcontainers::core::IntoContainerPort;
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};

use super::common::containers::{BoxError, fail_in_ci_else_skip};

struct MySqlFixture {
    _container: ContainerAsync<GenericImage>,
    pool: sqlx::AnyPool,
}

async fn start_mysql() -> Result<MySqlFixture, BoxError> {
    const PASSWORD: &str = "ferrum-mysql-test-password";
    let container = GenericImage::new("mysql", "8.4")
        .with_exposed_port(3306.tcp())
        .with_env_var("MYSQL_ROOT_PASSWORD", PASSWORD)
        .with_env_var("MYSQL_ROOT_HOST", "%")
        .with_env_var("MYSQL_DATABASE", "ferrum")
        .start()
        .await?;
    let port = container.get_host_port_ipv4(3306.tcp()).await?;
    let url = format!("mysql://root:{PASSWORD}@127.0.0.1:{port}/ferrum");

    sqlx::any::install_default_drivers();
    let mut last_error = String::new();
    for _ in 0..90 {
        match sqlx::any::AnyPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(Duration::from_secs(2))
            .connect(&url)
            .await
        {
            Ok(pool) => {
                return Ok(MySqlFixture {
                    _container: container,
                    pool,
                });
            }
            Err(error) => {
                last_error = error.to_string();
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }
    Err(format!("MySQL did not become ready within 45s: {last_error}").into())
}

async fn index_definition(pool: &sqlx::AnyPool, index_name: &str) -> Vec<(String, i64)> {
    sqlx::query(
        "SELECT COLUMN_NAME, CAST(NON_UNIQUE AS SIGNED) \
         FROM information_schema.statistics \
         WHERE table_schema = DATABASE() AND table_name = 'example_audit_log' \
           AND index_name = ? \
         ORDER BY SEQ_IN_INDEX",
    )
    .bind(index_name)
    .fetch_all(pool)
    .await
    .expect("inspect example_audit_log index definition")
    .into_iter()
    .map(|row| {
        (
            row.try_get(0).expect("index column name"),
            row.try_get(1).expect("index uniqueness"),
        )
    })
    .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn mysql_example_audit_partial_ddl_recovers_and_accepts_text_bindings() {
    // Check plugin presence before starting Docker so default local builds
    // self-skip without waiting ~30-45s for a MySQL container.
    let migrations = ferrum_edge::custom_plugins::collect_all_custom_plugin_migrations();
    let Some((_, example)) = migrations
        .into_iter()
        .find(|(name, _)| *name == "example_audit_plugin")
    else {
        eprintln!(
            "SKIP mysql_example_audit_partial_ddl_recovers_and_accepts_text_bindings: \
             example_audit_plugin not compiled in (set FERRUM_CUSTOM_PLUGINS=example_audit_plugin)"
        );
        return;
    };

    let fixture = match start_mysql().await {
        Ok(fixture) => fixture,
        Err(error) => {
            fail_in_ci_else_skip(
                "mysql_example_audit_partial_ddl_recovers_and_accepts_text_bindings",
                "MySQL 8.4",
                &error,
            );
            return;
        }
    };
    let pool = &fixture.pool;

    // A partial V1 table is missing client_ip. The first attempt successfully
    // rebuilds the timestamp index, then fails on the later client_ip index.
    // MySQL commits that earlier DDL even though no tracking row is written.
    sqlx::query(
        r#"
        CREATE TABLE example_audit_log (
            id VARCHAR(255) PRIMARY KEY,
            timestamp VARCHAR(32) NOT NULL,
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
        )
        "#,
    )
    .execute(pool)
    .await
    .expect("partial example audit table");
    sqlx::query("CREATE INDEX idx_example_audit_log_timestamp ON example_audit_log (proxy_id)")
        .execute(pool)
        .await
        .expect("wrong timestamp index");
    sqlx::query("CREATE INDEX idx_example_audit_log_client_ip ON example_audit_log (timestamp)")
        .execute(pool)
        .await
        .expect("wrong client index");

    let runner = MigrationRunner::new(pool.clone(), "mysql".to_string());
    let list = vec![("example_audit_plugin", example)];
    let first_error = runner
        .run_plugin_pending(&list)
        .await
        .expect_err("missing client_ip must fail after earlier DDL committed");
    assert!(
        format!("{first_error:#}").contains("client_ip"),
        "unexpected first migration error: {first_error:#}"
    );
    assert_eq!(
        index_definition(pool, "idx_example_audit_log_timestamp").await,
        [("timestamp".to_string(), 1)],
        "the successful earlier index DDL must survive the failed migration"
    );
    assert!(
        index_definition(pool, "idx_example_audit_log_client_ip")
            .await
            .is_empty(),
        "the failing client index must remain absent"
    );
    let tracked_v3: i64 = sqlx::query_scalar(
        "SELECT CAST(COUNT(*) AS SIGNED) FROM _ferrum_plugin_migrations \
         WHERE plugin_name = ? AND version = 3",
    )
    .bind("example_audit_plugin")
    .fetch_one(pool)
    .await
    .expect("inspect missing V3 tracking row");
    assert_eq!(tracked_v3, 0);

    sqlx::query("ALTER TABLE example_audit_log ADD COLUMN client_ip VARCHAR(255) NOT NULL")
        .execute(pool)
        .await
        .expect("repair client_ip column");
    sqlx::query("CREATE INDEX idx_example_audit_log_client_ip ON example_audit_log (timestamp)")
        .execute(pool)
        .await
        .expect("seed wrong client index before retry");

    let applied = runner
        .run_plugin_pending(&list)
        .await
        .expect("retry after partial MySQL DDL must succeed");
    assert!(applied.iter().any(|record| record.version == 3));
    assert!(applied.iter().any(|record| record.version == 4));
    assert_eq!(
        index_definition(pool, "idx_example_audit_log_timestamp").await,
        [("timestamp".to_string(), 1)]
    );
    assert_eq!(
        index_definition(pool, "idx_example_audit_log_client_ip").await,
        [("client_ip".to_string(), 1)]
    );
    assert_eq!(
        index_definition(pool, "idx_example_audit_log_status_ts").await,
        [
            ("response_status".to_string(), 1),
            ("timestamp".to_string(), 1),
        ]
    );

    // Exercise the exact SQLx Any bindings used by the runtime sink.
    sqlx::query(
        "INSERT INTO example_audit_log \
         (id, timestamp, client_ip, protocol, latency_ms, request_context) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind("runtime-row")
    .bind("2026-07-20T12:00:00.000Z")
    .bind("192.0.2.10")
    .bind("http")
    .bind(1.25_f64)
    .bind("{\"redacted\":true}")
    .execute(pool)
    .await
    .expect("runtime text bindings must be accepted by MySQL through sqlx::Any");
    let context: Vec<u8> = sqlx::query_scalar(
        "SELECT request_context FROM example_audit_log WHERE id = 'runtime-row'",
    )
    .fetch_one(pool)
    .await
    .expect("read runtime text binding");
    assert_eq!(context.as_slice(), b"{\"redacted\":true}");

    // Simulate V4 CREATE INDEX committing before its tracker insert.
    sqlx::query(
        "DELETE FROM _ferrum_plugin_migrations \
         WHERE plugin_name = ? AND version = 4",
    )
    .bind("example_audit_plugin")
    .execute(pool)
    .await
    .expect("remove V4 tracker row");
    let recovered_v4 = runner
        .run_plugin_pending(&list)
        .await
        .expect("V4 tracking-gap retry must succeed");
    assert_eq!(recovered_v4.len(), 1);
    assert_eq!(recovered_v4[0].version, 4);
    assert_eq!(
        index_definition(pool, "idx_example_audit_log_status_ts").await,
        [
            ("response_status".to_string(), 1),
            ("timestamp".to_string(), 1),
        ]
    );
    assert!(runner.run_plugin_pending(&list).await.unwrap().is_empty());
}
