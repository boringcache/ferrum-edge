//! File backend (`_FILE` suffix) functional tests.
//!
//! Exercises `resolve_all_env_secrets()` against on-disk secret files created
//! with `tempfile`. No Docker, no cloud — runs anywhere.

use crate::common::env::{
    EnvGuard, assert_resolved_var, assert_secret_not_logged_or_exposed, assert_source_removed,
};
use ferrum_edge::secrets::resolve_all_env_secrets;
use serial_test::serial;
use std::fs;
use tempfile::TempDir;

#[tokio::test]
#[serial]
async fn file_backend_resolves_value_and_marks_source_for_removal() {
    let guard = EnvGuard::new();
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("admin_jwt");
    fs::write(&path, "file-secret-value\n").unwrap();

    guard.set("FERRUM_ADMIN_JWT_SECRET_FILE", path.to_string_lossy());

    let result = resolve_all_env_secrets().await.expect("resolution failed");

    assert_resolved_var(&result, "FERRUM_ADMIN_JWT_SECRET", "file-secret-value");
    assert_source_removed(&result, "FERRUM_ADMIN_JWT_SECRET_FILE");
    assert_secret_not_logged_or_exposed(&result, "file-secret-value");

    // The loaded-source metadata must name the `file` backend, not the value.
    let sources: std::collections::HashMap<_, _> = result
        .loaded_sources
        .iter()
        .map(|(k, s)| (k.as_str(), *s))
        .collect();
    assert_eq!(sources.get("FERRUM_ADMIN_JWT_SECRET"), Some(&"file"));
}

#[tokio::test]
#[serial]
async fn file_backend_trims_trailing_whitespace() {
    let guard = EnvGuard::new();
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("secret");
    // Trailing newlines/spaces are common in Docker secrets and heredocs.
    fs::write(&path, "trimmed-secret  \n\n").unwrap();

    guard.set("FERRUM_DB_URL_FILE", path.to_string_lossy());

    let result = resolve_all_env_secrets().await.expect("resolution failed");
    assert_resolved_var(&result, "FERRUM_DB_URL", "trimmed-secret");
}

#[tokio::test]
#[serial]
async fn file_backend_preserves_internal_whitespace() {
    let guard = EnvGuard::new();
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("secret");
    fs::write(&path, "value with internal spaces\n").unwrap();

    guard.set("FERRUM_DB_URL_FILE", path.to_string_lossy());

    let result = resolve_all_env_secrets().await.expect("resolution failed");
    assert_resolved_var(&result, "FERRUM_DB_URL", "value with internal spaces");
}

#[tokio::test]
#[serial]
async fn file_backend_missing_file_errors() {
    let guard = EnvGuard::new();
    guard.set(
        "FERRUM_ADMIN_JWT_SECRET_FILE",
        "/nonexistent/path/to/secret-file",
    );

    let err = resolve_all_env_secrets()
        .await
        .err()
        .expect("missing file must fail resolution");
    assert!(
        err.contains("Failed to read"),
        "expected a read failure error, got: {err}"
    );
}

#[tokio::test]
#[serial]
async fn file_backend_empty_file_errors() {
    let guard = EnvGuard::new();
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("empty");
    fs::write(&path, "").unwrap();

    guard.set("FERRUM_ADMIN_JWT_SECRET_FILE", path.to_string_lossy());

    let err = resolve_all_env_secrets()
        .await
        .err()
        .expect("empty file must fail resolution");
    assert!(
        err.contains("empty"),
        "expected an empty-file error, got: {err}"
    );
}

#[tokio::test]
#[serial]
async fn file_backend_resolves_multiple_files_in_one_pass() {
    let guard = EnvGuard::new();
    let dir = TempDir::new().unwrap();
    let path_a = dir.path().join("a");
    let path_b = dir.path().join("b");
    fs::write(&path_a, "alpha\n").unwrap();
    fs::write(&path_b, "beta\n").unwrap();

    guard.set("FERRUM_SECRET_A_FILE", path_a.to_string_lossy());
    guard.set("FERRUM_SECRET_B_FILE", path_b.to_string_lossy());

    let result = resolve_all_env_secrets().await.expect("resolution failed");
    assert_resolved_var(&result, "FERRUM_SECRET_A", "alpha");
    assert_resolved_var(&result, "FERRUM_SECRET_B", "beta");
    assert_source_removed(&result, "FERRUM_SECRET_A_FILE");
    assert_source_removed(&result, "FERRUM_SECRET_B_FILE");
}

/// `FERRUM_DNS_RESOLVER_HOSTS_FILE` ends in `_FILE` but is a real config path,
/// not a secret indirection — resolution must leave it untouched.
#[tokio::test]
#[serial]
async fn file_backend_ignores_non_secret_file_suffix() {
    let guard = EnvGuard::new();
    guard.set("FERRUM_DNS_RESOLVER_HOSTS_FILE", "/etc/hosts.ferrum");

    let result = resolve_all_env_secrets().await.expect("resolution failed");
    assert!(result.vars.is_empty());
    assert!(result.source_keys_to_remove.is_empty());
    assert!(result.loaded_sources.is_empty());
}
