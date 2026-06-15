//! Process-environment isolation + resolver assertions shared by every
//! secret-backend functional test.
//!
//! Secret resolution reads the whole `FERRUM_*` (and provider) environment, and
//! `cargo` runs tests in parallel threads inside one process, so any test that
//! mutates these vars must run in isolation. Every env-mutating test in this
//! suite is annotated `#[serial]` (serial_test) AND constructs an [`EnvGuard`]
//! at the top of its body. The guard snapshots, clears, and restores the
//! secret-related environment so a test starts from a known-clean slate and
//! cannot leak into the host shell, CI, or sibling tests.

#![allow(dead_code)] // helpers are used selectively per feature-gated module

use std::collections::BTreeMap;

use ferrum_edge::secrets::ResolvedEnvSecrets;

/// Env-var name prefixes that secret resolution and the cloud SDKs read.
/// `EnvGuard` manages (snapshots/clears/restores) every var matching one of
/// these. This deliberately covers the suffixed source keys
/// (`FERRUM_X_FILE`/`_VAULT`/`_AWS`/`_GCP`/`_AZURE`), the cloud auth vars
/// (`AWS_*`, `AZURE_*`, `GOOGLE_*`, `VAULT_*`), and the endpoint overrides
/// (`AWS_ENDPOINT_URL_SECRETS_MANAGER`, `FERRUM_GCP_SECRET_MANAGER_ENDPOINT`).
const MANAGED_PREFIXES: &[&str] = &["FERRUM_", "AWS_", "AZURE_", "GOOGLE_", "GCP_", "VAULT_"];

fn is_managed(key: &str) -> bool {
    MANAGED_PREFIXES.iter().any(|p| key.starts_with(p))
}

/// RAII guard that isolates and restores the secret-related process
/// environment. Construct it first in every env-mutating test, bind it to a
/// named local (never `_`), and keep it alive for the whole test body.
///
/// MUST be paired with `#[serial]` on the test: the guard provides isolation
/// and cleanup, `#[serial]` provides mutual exclusion between env-mutating
/// tests.
pub struct EnvGuard {
    saved: BTreeMap<String, String>,
    /// Non-managed keys explicitly set during the test, with their prior value,
    /// so they too are restored on drop.
    extra: std::cell::RefCell<Vec<(String, Option<String>)>>,
}

impl EnvGuard {
    /// Snapshot and clear every managed-prefix env var, returning a guard that
    /// restores the snapshot exactly on drop.
    pub fn new() -> Self {
        // `std::env::vars()` materializes a snapshot, so mutating during the
        // following loop is safe.
        let saved: BTreeMap<String, String> =
            std::env::vars().filter(|(k, _)| is_managed(k)).collect();
        for key in saved.keys() {
            // SAFETY: env-mutating tests are serialized via `#[serial]`, so no
            // other thread reads or writes the process environment concurrently.
            unsafe { std::env::remove_var(key) };
        }
        Self {
            saved,
            extra: std::cell::RefCell::new(Vec::new()),
        }
    }

    /// Set a managed env var for the duration of the test.
    pub fn set(&self, key: &str, value: impl AsRef<str>) {
        debug_assert!(
            is_managed(key),
            "EnvGuard::set only manages secret-related env vars; use set_other for '{key}'"
        );
        // SAFETY: serialized by `#[serial]`.
        unsafe { std::env::set_var(key, value.as_ref()) };
    }

    /// Set an arbitrary (possibly non-managed) env var, recording its prior
    /// value so the guard restores it on drop. Used for negative cases such as
    /// a non-`FERRUM_`-prefixed key.
    pub fn set_other(&self, key: &str, value: impl AsRef<str>) {
        self.extra
            .borrow_mut()
            .push((key.to_string(), std::env::var(key).ok()));
        // SAFETY: serialized by `#[serial]`.
        unsafe { std::env::set_var(key, value.as_ref()) };
    }

    /// Remove a managed env var for the duration of the test.
    pub fn remove(&self, key: &str) {
        // SAFETY: serialized by `#[serial]`.
        unsafe { std::env::remove_var(key) };
    }
}

impl Default for EnvGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        // Remove anything the test added (any managed var currently set), then
        // restore the original snapshot exactly. This leaves the environment
        // byte-for-byte as it was before the guard was constructed.
        let current: Vec<String> = std::env::vars()
            .map(|(k, _)| k)
            .filter(|k| is_managed(k))
            .collect();
        for key in current {
            // SAFETY: serialized by `#[serial]`.
            unsafe { std::env::remove_var(&key) };
        }
        for (key, value) in &self.saved {
            // SAFETY: serialized by `#[serial]`.
            unsafe { std::env::set_var(key, value) };
        }
        // Restore any explicitly-tracked non-managed keys (most recent first so
        // repeated sets of the same key resolve to the earliest prior value).
        for (key, prior) in self.extra.borrow().iter().rev() {
            // SAFETY: serialized by `#[serial]`.
            unsafe {
                match prior {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }
}

/// Assert that resolution produced `(key, expected_value)` in `result.vars`.
pub fn assert_resolved_var(result: &ResolvedEnvSecrets, key: &str, expected_value: &str) {
    let found = result
        .vars
        .iter()
        .find(|(k, _)| k == key)
        .unwrap_or_else(|| panic!("resolved vars do not contain key '{key}'"));
    // The resolved value is the secret; comparing it here is the intentional
    // exception to the "never surface secrets" rule, but we keep the failure
    // message free of the actual resolved bytes.
    assert!(
        found.1 == expected_value,
        "resolved value for '{key}' did not match the expected value"
    );
}

/// Assert that `suffixed_key` was scheduled for removal from the environment
/// (so the indirection var does not linger after resolution).
pub fn assert_source_removed(result: &ResolvedEnvSecrets, suffixed_key: &str) {
    assert!(
        result
            .source_keys_to_remove
            .iter()
            .any(|k| k == suffixed_key),
        "expected source key '{suffixed_key}' to be marked for removal; \
         marked keys: {:?}",
        result.source_keys_to_remove
    );
}

/// Assert that the resolved value never appears in any logging/metadata
/// channel. `result.vars` legitimately carries the value (it is injected into
/// the env), so it is excluded; everything an operator could see in logs —
/// `loaded_sources` (base key + backend display name) and the
/// `source_keys_to_remove` list — must be free of it.
pub fn assert_secret_not_logged_or_exposed(result: &ResolvedEnvSecrets, secret_value: &str) {
    let leaked_in_loaded = result
        .loaded_sources
        .iter()
        .any(|(base_key, source)| base_key.contains(secret_value) || source.contains(secret_value));
    assert!(
        !leaked_in_loaded,
        "secret value leaked into loaded_sources metadata (base key or source name)"
    );

    let leaked_in_removed = result
        .source_keys_to_remove
        .iter()
        .any(|k| k.contains(secret_value));
    assert!(
        !leaked_in_removed,
        "secret value leaked into source_keys_to_remove metadata"
    );
}
