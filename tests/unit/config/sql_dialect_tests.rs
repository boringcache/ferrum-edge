//! External regression tests for V001 dialect-specific SQL text.
//!
//! `V001SqlBuilder` is crate-private. Static inspection of `sql_dialect.rs`
//! pins cross-dialect unique-index definitions that migration and integration
//! tests assume.

const SQL_DIALECT_SOURCE: &str = include_str!("../../../src/config/migrations/sql_dialect.rs");

#[test]
fn upstream_namespace_name_unique_index_across_dialects() {
    // Issue #2999: upstream (namespace, name) uniqueness must be a durable
    // DB invariant, not only an advisory admin precheck.
    assert!(
        SQL_DIALECT_SOURCE.contains(
            "CREATE UNIQUE INDEX idx_upstreams_namespace_name ON upstreams (namespace, name)"
        ),
        "MySQL must declare a non-partial unique index on upstreams (namespace, name)"
    );
    assert!(
        SQL_DIALECT_SOURCE.contains(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_upstreams_namespace_name ON upstreams (namespace, name) WHERE name IS NOT NULL"
        ),
        "Postgres/SQLite must use a partial unique index so unnamed upstreams may coexist"
    );
}
