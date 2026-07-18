//! File-based secret resolution (`_FILE` suffix convention).
//!
//! When `FERRUM_X_FILE=/path/to/secret` is set, the secret value is read from
//! that file. Supports Docker secrets (`/run/secrets/`), Kubernetes volume mounts,
//! and Vault Agent file injection.

use std::env;

/// Check if the `{key}_FILE` env var is set and non-empty.
/// Returns the file path if so.
/// Used by the registry's single-key `resolve_secret()` path and its tests.
#[allow(dead_code)]
pub fn resolve_ref(key: &str) -> Option<String> {
    let file_key = format!("{}_FILE", key);
    env::var(&file_key).ok().filter(|s| !s.is_empty())
}

/// Read a secret value from a file path. Trims trailing whitespace
/// (trailing newlines are common in Docker secrets and heredocs).
/// Returns an error if the file cannot be read or is empty after trimming.
///
/// The errors name the suffixed variable and the `io::Error` reason ("No such
/// file or directory", "Permission denied") but never the path itself: a
/// secret's source reference is treated as sensitive alongside its value, and
/// `run` logs / `validate` prints this text. `std::fs::read_to_string` does not
/// attach the path to its `io::Error`, so the reason is safe to forward
/// verbatim.
pub fn read_secret(path: &str, key: &str) -> Result<String, String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("Failed to read {}_FILE: {}", key, e))?;

    let trimmed = content.trim_end().to_string();
    if trimmed.is_empty() {
        return Err(format!("{}_FILE source is empty after trimming", key));
    }

    Ok(trimmed)
}
