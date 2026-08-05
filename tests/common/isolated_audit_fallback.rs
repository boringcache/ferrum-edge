//! Per-test admin audit local-fallback directories (issue #3573).
//!
//! Production defaults to `./ferrum-admin-audit`. Under nextest
//! (process-per-test), every `AdminState` that leaves
//! `admin_audit_fallback_dir` unset would share that CWD path and contend on
//! the cross-process lock — the top flake for concurrent `GET /backup` paths.
//! Call [`isolated_audit_fallback_dir`] whenever a test builds an `AdminState`
//! that might admit a security-sensitive event to the local fallback.

use std::path::PathBuf;

/// Allocate a unique local audit fallback directory for one test `AdminState`.
///
/// Uses `TempDir::into_path` so callers need not retain a guard across the
/// many inline `AdminState { ... }` sites; leftover empty directories under the
/// system temp root are acceptable for the suite.
pub fn isolated_audit_fallback_dir() -> PathBuf {
    tempfile::TempDir::new()
        .expect("create isolated admin audit fallback tempdir")
        .into_path()
}
