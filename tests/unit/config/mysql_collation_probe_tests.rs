//! External unit tests for the MySQL identity-collation startup probe (#3626).

use ferrum_edge::config::migrations::{
    LiveColumnCollation, LiveTableCollation, MigrationRunner, REQUIRED_MYSQL_IDENTITY_COLLATION,
    StaleCollationFinding, find_stale_column_collations, find_stale_table_collations,
    format_affected_columns_summary, identity_bearing_columns, inspect_mysql_identity_collations,
    merge_stale_collation_findings, remediation_alter_statements,
};

#[test]
fn required_collation_constant_matches_baseline() {
    assert_eq!(REQUIRED_MYSQL_IDENTITY_COLLATION, "utf8mb4_0900_bin");
}

#[test]
fn identity_inventory_covers_consumer_and_proxy_keys() {
    let names: Vec<(&str, &str)> = identity_bearing_columns()
        .iter()
        .map(|c| (c.table, c.column))
        .collect();
    assert!(names.contains(&("consumers", "username")));
    assert!(names.contains(&("consumer_identity_index", "identity_value")));
    assert!(names.contains(&("proxies", "name")));
    assert!(names.contains(&("upstreams", "name")));
    assert!(names.contains(&("api_specs", "content_hash")));
    assert!(names.contains(&("audit_events", "source_address")));
}

#[test]
fn stale_general_ci_collation_is_detected() {
    let live = vec![
        LiveColumnCollation {
            table_name: "consumers".into(),
            column_name: "username".into(),
            collation_name: Some("utf8mb4_general_ci".into()),
        },
        LiveColumnCollation {
            table_name: "consumer_identity_index".into(),
            column_name: "identity_value".into(),
            collation_name: Some("utf8mb4_0900_as_cs".into()),
        },
        LiveColumnCollation {
            table_name: "proxies".into(),
            column_name: "name".into(),
            collation_name: Some("utf8mb4_bin".into()),
        },
    ];
    let findings = find_stale_column_collations(&live);
    assert_eq!(findings.len(), 3);
    assert!(
        findings
            .iter()
            .any(|f| f.table_name == "consumers" && f.found_collation == "utf8mb4_general_ci")
    );
    assert!(
        findings.iter().any(|f| {
            f.table_name == "consumer_identity_index" && f.found_collation == "utf8mb4_0900_as_cs"
        })
    );
    assert!(
        findings
            .iter()
            .any(|f| f.table_name == "proxies" && f.found_collation == "utf8mb4_bin")
    );
}

#[test]
fn correct_0900_bin_collation_is_clean() {
    let live: Vec<LiveColumnCollation> = identity_bearing_columns()
        .iter()
        .take(8)
        .map(|c| LiveColumnCollation {
            table_name: c.table.into(),
            column_name: c.column.into(),
            collation_name: Some(REQUIRED_MYSQL_IDENTITY_COLLATION.into()),
        })
        .collect();
    assert!(find_stale_column_collations(&live).is_empty());
}

#[test]
fn non_inventory_columns_are_ignored() {
    let live = vec![LiveColumnCollation {
        table_name: "consumers".into(),
        column_name: "credentials".into(),
        collation_name: Some("utf8mb4_general_ci".into()),
    }];
    assert!(find_stale_column_collations(&live).is_empty());
}

#[test]
fn null_collation_rows_are_ignored() {
    let live = vec![LiveColumnCollation {
        table_name: "consumers".into(),
        column_name: "username".into(),
        collation_name: None,
    }];
    assert!(find_stale_column_collations(&live).is_empty());
}

#[test]
fn stale_table_default_and_columns_merge_with_dedupe() {
    let columns = find_stale_column_collations(&[LiveColumnCollation {
        table_name: "consumers".into(),
        column_name: "username".into(),
        collation_name: Some("utf8mb4_general_ci".into()),
    }]);
    let tables = find_stale_table_collations(&[LiveTableCollation {
        table_name: "consumers".into(),
        table_collation: Some("utf8mb4_general_ci".into()),
    }]);
    let merged = merge_stale_collation_findings(columns, tables);
    assert_eq!(merged.len(), 2);
    let alters = remediation_alter_statements(&merged);
    assert_eq!(
        alters,
        vec![
            "ALTER TABLE consumers CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin"
                .to_string()
        ]
    );
}

#[test]
fn remediation_statements_are_stable_and_exact() {
    let findings = vec![
        StaleCollationFinding {
            table_name: "proxies".into(),
            column_name: "name".into(),
            found_collation: "utf8mb4_unicode_ci".into(),
        },
        StaleCollationFinding {
            table_name: "consumers".into(),
            column_name: "username".into(),
            found_collation: "utf8mb4_unicode_ci".into(),
        },
    ];
    assert_eq!(
        remediation_alter_statements(&findings),
        vec![
            "ALTER TABLE consumers CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin"
                .to_string(),
            "ALTER TABLE proxies CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin"
                .to_string(),
        ]
    );
}

#[test]
fn affected_summary_lists_table_column_and_found_collation() {
    let findings = vec![StaleCollationFinding {
        table_name: "consumers".into(),
        column_name: "username".into(),
        found_collation: "utf8mb4_general_ci".into(),
    }];
    assert_eq!(
        format_affected_columns_summary(&findings),
        "consumers.username (utf8mb4_general_ci)"
    );
}

#[tokio::test]
async fn inspect_is_noop_for_sqlite() {
    sqlx::any::install_default_drivers();
    let pool = sqlx::any::AnyPoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let runner = MigrationRunner::new(pool.clone(), "sqlite".to_string());
    runner.run_pending().await.unwrap();

    let mut conn = pool.acquire().await.unwrap();
    let findings = inspect_mysql_identity_collations(&mut conn, "sqlite")
        .await
        .expect("sqlite probe must be a successful no-op");
    assert!(findings.is_empty());
}

#[tokio::test]
async fn inspect_is_noop_for_postgres_db_type_label() {
    // Even if a connection exists, a non-mysql db_type label must short-circuit
    // before any information_schema query (SQLite has no such catalog).
    sqlx::any::install_default_drivers();
    let pool = sqlx::any::AnyPoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let mut conn = pool.acquire().await.unwrap();
    let findings = inspect_mysql_identity_collations(&mut conn, "postgres")
        .await
        .expect("postgres label must no-op without querying");
    assert!(findings.is_empty());
}
