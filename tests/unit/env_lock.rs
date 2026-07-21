//! Process-wide environment lock shared by every env-var-mutating unit test.
//!
//! `cargo test --test unit_tests` runs tests in parallel, so any two tests
//! that read or write the same `FERRUM_*` process env var must serialize
//! against a single mutex — otherwise one test's mutation races another's
//! read. The config env-var helper (`config::env_config_tests`), the identity
//! guardrail tests (`identity::env_guard`), the CLI tests (`cli::cli_tests`),
//! every secret-backend suite under `secrets::*`, and
//! `plugins::serverless_function_tests` all acquire THIS lock, so e.g. an
//! identity test toggling `FERRUM_MESH_PRODUCTION_MODE` can never interleave
//! with a config test that reads it through `EnvConfig::from_env()`.
//!
//! A per-file mutex is NOT an acceptable substitute and must not be
//! reintroduced. It orders a file against itself only, which leaves `set_var`
//! in one module racing `getenv` in another — the exact undefined behavior
//! Rust 2024 made `set_var` unsafe to flag. It also produced a subtler bug:
//! `secrets::redaction_tests` builds a lazily cached, process-wide redaction
//! plan by reading fixture variables back out of the environment, so a
//! concurrently mutating test elsewhere could get that cache built from
//! transient state and poison every later assertion in the binary.
//!
//! Acquire it poison-tolerantly (`unwrap_or_else(|p| p.into_inner())`). It
//! guards no invariant of its own, only mutual exclusion, so one panicking
//! test must not cascade into unrelated failures across the whole binary.
#![allow(dead_code)] // used by sibling test modules

use std::sync::Mutex;

pub static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Poison-tolerant RAII guard for tests that read or mutate process environment.
///
/// The guard owns [`ENV_LOCK`], snapshots the named variables, and restores
/// their exact `OsString` values on drop so failures cannot leak test state.
pub struct EnvGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
    saved: Vec<(&'static str, Option<std::ffi::OsString>)>,
}

impl EnvGuard {
    pub fn new(keys: &[&'static str]) -> Self {
        let lock = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let saved = keys
            .iter()
            .map(|&key| (key, std::env::var_os(key)))
            .collect();
        Self { _lock: lock, saved }
    }

    pub fn set(&self, key: &str, value: &str) {
        // SAFETY: this guard owns the process-wide environment lock.
        unsafe { std::env::set_var(key, value) }
    }

    pub fn unset(&self, key: &str) {
        // SAFETY: this guard owns the process-wide environment lock.
        unsafe { std::env::remove_var(key) }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (key, value) in &self.saved {
            // SAFETY: `Drop::drop` runs while all fields, including `_lock`,
            // remain alive, so restoration is still serialized by ENV_LOCK.
            unsafe {
                match value {
                    Some(value) => std::env::set_var(*key, value),
                    None => std::env::remove_var(*key),
                }
            }
        }
    }
}
