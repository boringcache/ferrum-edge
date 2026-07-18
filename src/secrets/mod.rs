//! Secret resolution with pluggable backends.
//!
//! Any `FERRUM_*` environment variable can be loaded from an external source
//! by setting a suffixed variant instead of the variable itself.
//!
//! Startup secret resolution finishes before non-blocking logging and the
//! multi-threaded gateway runtime, and its temporary runtime is dropped before
//! env mutation happens.

#[cfg(feature = "secrets-aws")]
mod aws;
#[cfg(feature = "secrets-azure")]
mod azure;
pub mod env;
pub mod file;
#[cfg(feature = "secrets-gcp")]
mod gcp;
mod registry;
#[cfg(feature = "secrets-vault")]
mod vault;

#[cfg(any(feature = "secrets-aws", feature = "secrets-vault"))]
pub(crate) fn split_reference_field(reference: &str) -> (&str, Option<&str>) {
    match reference.split_once('#') {
        Some((base, field)) => (base, Some(field)),
        None => (reference, None),
    }
}

#[allow(unused_imports)]
pub use registry::{
    ResolvedEnvSecrets, ResolvedSecret, resolve_all_env_secrets, resolve_external_reference,
    resolve_secret,
};

/// Base `FERRUM_*` variables whose current value was materialized from an
/// external secret source in this process.
///
/// Only the key names are stored. The values live in the process environment
/// already (startup writes them there with `set_var` before config is parsed),
/// so [`redact_external_secret_values`] reads them back from there instead of
/// keeping a second copy of secret material alive for the process lifetime.
static EXTERNAL_SECRET_KEYS: std::sync::OnceLock<std::collections::BTreeSet<String>> =
    std::sync::OnceLock::new();

/// Substituted for an externally resolved value in an operator-facing message.
pub const EXTERNAL_SECRET_PLACEHOLDER: &str = "<redacted: value from external secret source>";

/// Record which base variables were materialized from an external secret
/// source.
///
/// Called exactly once at startup, immediately after the resolved values are
/// written to the environment and before any configuration is parsed. Later
/// calls are ignored, so this cannot be re-pointed after config load.
///
/// This is what makes downstream redaction *key-tied* rather than a guess about
/// what looks secret: an externally resolved variable is known by name, so a
/// diagnostic about it can name the variable and withhold only its value.
pub fn record_external_secret_keys<I>(keys: I)
where
    I: IntoIterator<Item = String>,
{
    let _ = EXTERNAL_SECRET_KEYS.set(keys.into_iter().collect());
}

/// True when `key`'s current value came from an external secret source.
///
/// Returns `false` before [`record_external_secret_keys`] runs and in any
/// process that never resolved external secrets (including unit tests), so
/// ordinary configuration diagnostics are unaffected.
pub fn is_external_secret_key(key: &str) -> bool {
    EXTERNAL_SECRET_KEYS
        .get()
        .is_some_and(|keys| keys.contains(key))
}

/// Remove externally resolved secret values from an operator-facing message.
///
/// This is the backstop behind the structured boundary in
/// `config::env_config_macro::invalid_env_value`, which is where typed
/// `EnvConfig` parse failures already withhold the raw value by key. Config
/// validation is far wider than that one site — hand-written messages, URL and
/// namespace validators, and the file-mode spec loader all interpolate resolved
/// values — and a resolved secret is indistinguishable from ordinary
/// configuration once it is in the environment. Rather than auditing every
/// present and future message, the final rendering of a startup/validation
/// failure is filtered here against the authoritative set of externally
/// resolved keys.
///
/// Replacement is exact and by key: the value is read back from the environment
/// under a name known to have come from an external source, never guessed at by
/// shape. There is deliberately no minimum length — a short resolved secret is
/// still a secret, and mangling an unrelated substring of a diagnostic is
/// strictly preferable to printing the secret. Longest values are replaced
/// first so one secret that contains another cannot leave a fragment behind.
///
/// Matching runs against the *original* diagnostic only. Substituted
/// placeholders are never re-examined, so a resolved value that happens to be a
/// substring of [`EXTERNAL_SECRET_PLACEHOLDER`] (`value`, `external`, `a`)
/// cannot make one replacement's output the next replacement's input. A
/// repeated-substitution loop over the running message compounds instead:
/// n such values multiply the diagnostic by roughly the placeholder's density
/// of each, which turns a handful of externally resolved short secrets into a
/// validation-time memory/CPU exhaustion. See [`redact_values`] for the bound.
pub fn redact_external_secret_values(message: &str) -> String {
    let Some(keys) = EXTERNAL_SECRET_KEYS.get() else {
        return message.to_string();
    };

    let mut values: Vec<String> = keys
        .iter()
        .filter_map(|key| std::env::var(key).ok())
        .filter(|value| !value.is_empty())
        .collect();
    // Distinct values only: two keys holding the same secret describe one span,
    // and a duplicate would otherwise be scanned (and charged for) twice.
    values.sort_unstable();
    values.dedup();
    // Longest first, so the find below yields the longest match at a position.
    values.sort_by_key(|value| std::cmp::Reverse(value.len()));

    redact_values(message, &values)
}

/// Single left-to-right pass over `message`, substituting the longest matching
/// value at each position.
///
/// `values` must be non-empty strings ordered longest-first. The cursor only
/// ever advances — past a matched value, or by one character — so every byte of
/// the original is examined once and no generated placeholder text re-enters
/// matching. Output is therefore bounded by
/// `message.chars().count() * EXTERNAL_SECRET_PLACEHOLDER.len()` regardless of
/// how many values are configured or how short they are, and the work is
/// `O(message.len() * values.len() * longest_value.len())`.
fn redact_values(message: &str, values: &[String]) -> String {
    if values.is_empty() {
        return message.to_string();
    }

    let mut out = String::with_capacity(message.len());
    // Start of the not-yet-copied literal run, and the scan position.
    let mut copied = 0usize;
    let mut cursor = 0usize;

    while cursor < message.len() {
        let rest = &message[cursor..];
        if let Some(matched) = values.iter().find(|value| rest.starts_with(value.as_str())) {
            out.push_str(&message[copied..cursor]);
            out.push_str(EXTERNAL_SECRET_PLACEHOLDER);
            cursor += matched.len();
            copied = cursor;
            continue;
        }
        // Advance a whole character, so `cursor` only ever sits on a character
        // boundary and the slicing above cannot panic on multi-byte input.
        match rest.chars().next() {
            Some(next) => cursor += next.len_utf8(),
            None => break,
        }
    }

    out.push_str(&message[copied..]);
    out
}

// Azure Key Vault credential injection + reference parsing are exposed so the
// data-plane fetch path can be exercised against a local fake Key Vault with a
// pre-acquired bearer token (no Entra ID round trip). `AzureCredentials`
// carries `from_static_token()` for that injection.
#[cfg(feature = "secrets-azure")]
pub use azure::{AzureCredentials, parse_keyvault_reference as azure_parse_keyvault_reference};

#[cfg(all(test, any(feature = "secrets-aws", feature = "secrets-vault")))]
mod tests {
    use super::split_reference_field;

    #[test]
    fn split_reference_field_handles_optional_suffix() {
        assert_eq!(
            split_reference_field("secret/data/app#password"),
            ("secret/data/app", Some("password"))
        );
        assert_eq!(
            split_reference_field("secret/data/app"),
            ("secret/data/app", None)
        );
    }
}
