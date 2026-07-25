//! Unit coverage for admin audit-event retention (#2996).
//!
//! Behavioral SQLite coverage lives in
//! `tests/integration/audit_retention_tests.rs`. This module locks config
//! validation and SQL/Mongo source parity for the shared retention contract.

use ferrum_edge::admin::audit::{
    AUDIT_RETENTION_DAYS_MAX, AUDIT_RETENTION_MAX_ROWS_CAP, AUDIT_RETENTION_MAX_ROWS_DEFAULT,
    AUDIT_RETENTION_PRUNE_BATCH_SIZE, AUDIT_RETENTION_PRUNE_MAX_BATCHES, AuditRetentionPolicy,
};
use ferrum_edge::config::EnvConfig;

use crate::unit::env_lock::ENV_LOCK;

fn with_env_vars<F: FnOnce()>(vars: &[(&str, &str)], f: F) {
    let _guard = ENV_LOCK.lock().unwrap();
    for (k, v) in vars {
        // SAFETY: We hold a mutex preventing concurrent access.
        unsafe {
            std::env::set_var(k, v);
        }
    }
    f();
    for (k, _) in vars {
        // SAFETY: We hold a mutex preventing concurrent access.
        unsafe {
            std::env::remove_var(k);
        }
    }
}

const DB_LOADER_SOURCE: &str = include_str!("../../../src/config/db_loader.rs");
const MONGO_STORE_SOURCE: &str = include_str!("../../../src/config/mongo_store.rs");

#[test]
fn audit_retention_policy_defaults_to_a_namespace_cap() {
    let policy = AuditRetentionPolicy::default();
    assert!(policy.is_enabled());
    assert_eq!(policy.retention_days, None);
    assert_eq!(
        policy.max_rows_per_namespace,
        Some(AUDIT_RETENTION_MAX_ROWS_DEFAULT)
    );
}

#[test]
fn audit_retention_policy_accepts_safe_bounds() {
    let policy = AuditRetentionPolicy::from_parts(Some(90), Some(100_000)).unwrap();
    assert!(policy.is_enabled());
    assert_eq!(policy.retention_days, Some(90));
    assert_eq!(policy.max_rows_per_namespace, Some(100_000));

    let days_only = AuditRetentionPolicy::from_parts(Some(AUDIT_RETENTION_DAYS_MAX), None).unwrap();
    assert_eq!(days_only.retention_days, Some(AUDIT_RETENTION_DAYS_MAX));

    let rows_only =
        AuditRetentionPolicy::from_parts(None, Some(AUDIT_RETENTION_MAX_ROWS_CAP)).unwrap();
    assert_eq!(
        rows_only.max_rows_per_namespace,
        Some(AUDIT_RETENTION_MAX_ROWS_CAP)
    );
}

#[test]
fn audit_retention_policy_rejects_zero_and_oversize() {
    let zero_days = AuditRetentionPolicy::from_parts(Some(0), None).unwrap_err();
    assert!(
        zero_days.contains("FERRUM_AUDIT_RETENTION_DAYS"),
        "got: {zero_days}"
    );

    let zero_rows = AuditRetentionPolicy::from_parts(None, Some(0)).unwrap_err();
    assert!(
        zero_rows.contains("FERRUM_AUDIT_RETENTION_MAX_ROWS"),
        "got: {zero_rows}"
    );

    let over_days =
        AuditRetentionPolicy::from_parts(Some(AUDIT_RETENTION_DAYS_MAX + 1), None).unwrap_err();
    assert!(
        over_days.contains("FERRUM_AUDIT_RETENTION_DAYS"),
        "got: {over_days}"
    );

    let over_rows =
        AuditRetentionPolicy::from_parts(None, Some(AUDIT_RETENTION_MAX_ROWS_CAP + 1)).unwrap_err();
    assert!(
        over_rows.contains("FERRUM_AUDIT_RETENTION_MAX_ROWS"),
        "got: {over_rows}"
    );
}

#[test]
fn env_config_parses_audit_retention_knobs() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_AUDIT_RETENTION_DAYS", "30"),
            ("FERRUM_AUDIT_RETENTION_MAX_ROWS", "5000"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.audit_retention_days, Some(30));
            assert_eq!(config.audit_retention_max_rows, Some(5000));
        },
    );
}

#[test]
fn env_config_defaults_to_bounded_audit_retention() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.audit_retention_days, None);
            assert_eq!(
                config.audit_retention_max_rows,
                Some(AUDIT_RETENTION_MAX_ROWS_DEFAULT)
            );
        },
    );
}

#[test]
fn env_config_rejects_invalid_audit_retention() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_AUDIT_RETENTION_DAYS", "0"),
        ],
        || {
            let err = EnvConfig::from_env().unwrap_err();
            assert!(err.contains("FERRUM_AUDIT_RETENTION_DAYS"), "got: {err}");
        },
    );

    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_AUDIT_RETENTION_MAX_ROWS", "not-a-number"),
        ],
        || {
            let err = EnvConfig::from_env().unwrap_err();
            assert!(
                err.contains("FERRUM_AUDIT_RETENTION_MAX_ROWS"),
                "got: {err}"
            );
        },
    );
}

#[test]
fn sql_and_mongo_audit_retention_share_bounded_namespace_contract() {
    for source in [DB_LOADER_SOURCE, MONGO_STORE_SOURCE] {
        assert!(
            source.contains("prune_audit_events"),
            "both backends must expose prune_audit_events"
        );
        assert!(
            source.contains("AUDIT_RETENTION_PRUNE_BATCH_SIZE"),
            "both backends must bound delete batch size"
        );
        assert!(
            source.contains("AUDIT_RETENTION_PRUNE_MAX_BATCHES"),
            "both backends must bound batches per prune call"
        );
        assert!(
            source.contains("namespace"),
            "retention must stay namespace-scoped"
        );
        assert!(
            source.contains("Failed to prune audit_events after insert"),
            "insert must keep best-effort prune semantics distinct from #2421 delivery loss"
        );
    }

    assert!(
        DB_LOADER_SOURCE.contains("ORDER BY ts ASC, id ASC"),
        "SQL age/cap deletes must use deterministic (ts, id) order"
    );
    assert!(
        DB_LOADER_SOURCE.contains("ORDER BY ts DESC, id DESC LIMIT 1 OFFSET"),
        "SQL max-row boundary must use newest-first (ts, id) keyset"
    );
    assert!(
        MONGO_STORE_SOURCE.contains("\"ts\": -1, \"id\": -1")
            || MONGO_STORE_SOURCE.contains("ts\": -1, \"id\": -1"),
        "Mongo list/cap boundary must use deterministic (ts, id) order"
    );
    assert!(
        MONGO_STORE_SOURCE.contains("\"namespace\": 1, \"ts\": -1, \"id\": -1"),
        "Mongo baseline index must include id for (ts, id) parity"
    );
    assert_eq!(AUDIT_RETENTION_PRUNE_BATCH_SIZE, 1_000);
    assert_eq!(AUDIT_RETENTION_PRUNE_MAX_BATCHES, 8);
}
