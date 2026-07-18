//! Registry-backed secret resolution for env and external secret backends.
//!
//! The registry keeps backend-specific client/init logic inside each provider
//! module while centralizing suffix matching, conflict detection, and startup
//! ordering in one place.

use async_trait::async_trait;
use std::collections::HashMap;
use std::time::Duration;
use tracing::info;

#[cfg(feature = "secrets-aws")]
use super::aws;
#[cfg(feature = "secrets-azure")]
use super::azure;
#[cfg(feature = "secrets-gcp")]
use super::gcp;
#[cfg(feature = "secrets-vault")]
use super::vault;
use super::{env, file};

/// Only scan environment variables with this prefix.
const FERRUM_PREFIX: &str = "FERRUM_";

const NON_SECRET_FILE_SUFFIX_KEYS: &[&str] = &["FERRUM_DNS_RESOLVER_HOSTS_FILE"];

/// Substituted for a secret's source reference in an operator-facing error.
const REDACTED_REFERENCE: &str = "<redacted source reference>";

/// Strip a secret's source reference out of a backend error before it reaches
/// an operator.
///
/// A source reference — a file path, a Vault path, an ARN, a Key Vault URL — is
/// treated as sensitive alongside the value it points at: `run` logs this text
/// and `validate` prints it, while the success report deliberately reports the
/// base key and provider name only. Ferrum's own leaf errors no longer
/// interpolate the reference, but provider SDK errors are outside our control
/// and routinely echo the resource they were asked for, so the reference is
/// removed here as well. This is the single boundary every startup fetch passes
/// through, so a new backend cannot bypass it.
///
/// Both the full reference and its pre-`#` path half are replaced, longest
/// first, so a `path#field` reference cannot leak its path. Very short
/// references are left alone: they carry no meaningful location and replacing a
/// one- or two-character substring would corrupt unrelated text.
fn redact_source_reference(mut error: String, reference: &str) -> String {
    const MIN_REDACTABLE_REFERENCE_LEN: usize = 3;

    let mut candidates = vec![reference];
    if let Some((path, _field)) = reference.split_once('#') {
        candidates.push(path);
    }
    candidates.sort_by_key(|candidate| std::cmp::Reverse(candidate.len()));

    for candidate in candidates {
        if candidate.len() >= MIN_REDACTABLE_REFERENCE_LEN && error.contains(candidate) {
            error = error.replace(candidate, REDACTED_REFERENCE);
        }
    }
    error
}

/// Default timeout (seconds) for individual secret fetch operations from cloud backends.
const DEFAULT_SECRET_FETCH_TIMEOUT_SECS: u64 = 30;

/// Read the secret fetch timeout from `FERRUM_SECRET_FETCH_TIMEOUT_SECONDS` env var,
/// falling back to the default. Called before EnvConfig is parsed (secrets are
/// resolved first), so this reads the env var directly.
fn secret_fetch_timeout() -> Duration {
    let secs = crate::config::conf_file::resolve_ferrum_var("FERRUM_SECRET_FETCH_TIMEOUT_SECONDS")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_SECRET_FETCH_TIMEOUT_SECS);
    Duration::from_secs(secs)
}

/// A successfully resolved secret value with its source for logging.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ResolvedSecret {
    pub value: String,
    /// Human-readable source description (e.g. "env", "file:/run/secrets/jwt").
    /// Never contains the secret value itself.
    pub source: String,
}

/// The result of resolving all env-based secrets at startup.
///
/// Every vector is sorted by base key. Candidate sources are discovered by
/// iterating `std::env::vars()` into a `HashMap`, whose order varies between
/// processes, so an unsorted result would let two runs of `ferrum-edge
/// validate` on identical input print the `Loaded <KEY> from <provider>` lines
/// in different orders. Base keys are unique across the result (two sources for
/// one base key is a conflict error), so ordering by base key is total and
/// stable. See [`resolve_all_env_secrets`].
pub struct ResolvedEnvSecrets {
    /// Resolved `(base_key, value)` pairs to inject into the environment.
    /// Sorted by base key.
    pub vars: Vec<(String, String)>,
    /// Suffixed source keys (e.g., `FERRUM_X_FILE`) to remove from the
    /// environment. Sorted lexicographically, which is base-key order because a
    /// suffixed key is its base key plus a fixed provider suffix.
    pub source_keys_to_remove: Vec<String>,
    /// `(base_key, backend display name)` pairs to report once tracing is
    /// initialized. Sorted by base key.
    pub loaded_sources: Vec<(String, &'static str)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum BackendKind {
    // Used by the intentionally retained single-key `resolve_secret` path,
    // which is not referenced by the production binary in every target.
    #[allow(dead_code)]
    DirectEnv,
    File,
    #[cfg(feature = "secrets-vault")]
    Vault,
    #[cfg(feature = "secrets-aws")]
    Aws,
    #[cfg(feature = "secrets-gcp")]
    Gcp,
    #[cfg(feature = "secrets-azure")]
    Azure,
}

#[derive(Clone)]
pub(crate) struct PendingSecret {
    base_key: String,
    reference: String,
    suffixed_key: String,
    backend_kind: BackendKind,
}

#[derive(Debug, Clone)]
pub(crate) struct ResolvedPendingSecret {
    base_key: String,
    value: String,
    suffixed_key: String,
}

#[async_trait]
pub(crate) trait SecretBackend: Sync + Send {
    fn kind(&self) -> BackendKind;
    fn name(&self) -> &'static str;
    fn display_name(&self) -> &'static str;
    fn suffix(&self) -> Option<&'static str> {
        None
    }
    #[allow(dead_code)]
    fn resolve_ref(&self, key: &str) -> Option<String>;
    #[allow(dead_code)]
    fn source(&self, reference: &str) -> String;
    fn log_loaded(&self) -> bool {
        self.name() != "environment"
    }

    fn matches_suffix<'a>(&self, raw_key: &'a str) -> Option<&'a str> {
        self.suffix()
            .and_then(|suffix| raw_key.strip_suffix(suffix))
    }

    async fn resolve_one(&self, reference: &str, key: &str) -> Result<String, String>;

    async fn resolve_many(
        &self,
        secrets: &[PendingSecret],
        timeout: Duration,
    ) -> Result<Vec<ResolvedPendingSecret>, String> {
        // Apply the same timeout envelope to every backend, including file
        // reads, so startup cannot hang indefinitely on a blocked mount/FIFO.
        let mut resolved = Vec::with_capacity(secrets.len());
        for secret in secrets {
            let value = tokio::time::timeout(
                timeout,
                self.resolve_one(&secret.reference, &secret.base_key),
            )
            .await
            .map_err(|_| {
                format!(
                    "Timeout resolving {} from {} after {}s",
                    secret.base_key,
                    self.display_name(),
                    timeout.as_secs()
                )
            })?
            .map_err(|error| redact_source_reference(error, &secret.reference))?;
            resolved.push(ResolvedPendingSecret {
                base_key: secret.base_key.clone(),
                value,
                suffixed_key: secret.suffixed_key.clone(),
            });
        }
        Ok(resolved)
    }
}

#[allow(dead_code)]
struct DirectEnvBackend;
struct FileBackend;

#[cfg(feature = "secrets-vault")]
struct VaultBackend;
#[cfg(feature = "secrets-aws")]
struct AwsBackend;
#[cfg(feature = "secrets-gcp")]
struct GcpBackend;
#[cfg(feature = "secrets-azure")]
struct AzureBackend;

#[allow(dead_code)]
static DIRECT_ENV_BACKEND: DirectEnvBackend = DirectEnvBackend;
static FILE_BACKEND: FileBackend = FileBackend;
#[cfg(feature = "secrets-vault")]
static VAULT_BACKEND: VaultBackend = VaultBackend;
#[cfg(feature = "secrets-aws")]
static AWS_BACKEND: AwsBackend = AwsBackend;
#[cfg(feature = "secrets-gcp")]
static GCP_BACKEND: GcpBackend = GcpBackend;
#[cfg(feature = "secrets-azure")]
static AZURE_BACKEND: AzureBackend = AzureBackend;

#[allow(dead_code)]
fn all_backends() -> Vec<&'static dyn SecretBackend> {
    #[allow(unused_mut)]
    let mut backends: Vec<&'static dyn SecretBackend> = vec![&DIRECT_ENV_BACKEND, &FILE_BACKEND];
    #[cfg(feature = "secrets-vault")]
    backends.push(&VAULT_BACKEND);
    #[cfg(feature = "secrets-aws")]
    backends.push(&AWS_BACKEND);
    #[cfg(feature = "secrets-gcp")]
    backends.push(&GCP_BACKEND);
    #[cfg(feature = "secrets-azure")]
    backends.push(&AZURE_BACKEND);
    backends
}

fn startup_backends() -> Vec<&'static dyn SecretBackend> {
    #[allow(unused_mut)]
    let mut backends: Vec<&'static dyn SecretBackend> = vec![&FILE_BACKEND];
    #[cfg(feature = "secrets-vault")]
    backends.push(&VAULT_BACKEND);
    #[cfg(feature = "secrets-aws")]
    backends.push(&AWS_BACKEND);
    #[cfg(feature = "secrets-gcp")]
    backends.push(&GCP_BACKEND);
    #[cfg(feature = "secrets-azure")]
    backends.push(&AZURE_BACKEND);
    backends
}

fn suffix_backends() -> Vec<&'static dyn SecretBackend> {
    #[allow(unused_mut)]
    let mut backends: Vec<&'static dyn SecretBackend> = vec![&FILE_BACKEND];
    #[cfg(feature = "secrets-azure")]
    backends.insert(0, &AZURE_BACKEND);
    #[cfg(feature = "secrets-vault")]
    backends.insert(
        #[cfg(feature = "secrets-azure")]
        1,
        #[cfg(not(feature = "secrets-azure"))]
        0,
        &VAULT_BACKEND,
    );
    #[cfg(feature = "secrets-aws")]
    backends.push(&AWS_BACKEND);
    #[cfg(feature = "secrets-gcp")]
    backends.push(&GCP_BACKEND);
    backends
}

#[allow(dead_code)]
fn timeout_error(key: &str, backend_name: &str, timeout: Duration) -> String {
    format!(
        "Timeout resolving {} from {} after {}s",
        key,
        backend_name,
        timeout.as_secs()
    )
}

#[cfg(any(
    feature = "secrets-vault",
    feature = "secrets-aws",
    feature = "secrets-gcp",
    feature = "secrets-azure"
))]
async fn resolve_many_concurrent<C, F>(
    secrets: &[PendingSecret],
    timeout: Duration,
    backend_name: &'static str,
    client: &C,
    fetch: F,
) -> Result<Vec<ResolvedPendingSecret>, String>
where
    C: Sync,
    F: for<'a> Fn(
        &'a C,
        &'a str,
        &'a str,
    ) -> futures_util::future::BoxFuture<'a, Result<String, String>>,
{
    let futs: Vec<_> = secrets
        .iter()
        .map(|secret| async {
            let value =
                tokio::time::timeout(timeout, fetch(client, &secret.reference, &secret.base_key))
                    .await
                    .map_err(|_| timeout_error(&secret.base_key, backend_name, timeout))?
                    .map_err(|error| redact_source_reference(error, &secret.reference))?;
            Ok::<_, String>(ResolvedPendingSecret {
                base_key: secret.base_key.clone(),
                value,
                suffixed_key: secret.suffixed_key.clone(),
            })
        })
        .collect();

    let mut resolved = Vec::with_capacity(secrets.len());
    for item in futures_util::future::join_all(futs).await {
        resolved.push(item?);
    }
    Ok(resolved)
}

fn match_suffix(raw_key: &str) -> Option<(&'static dyn SecretBackend, &str)> {
    if NON_SECRET_FILE_SUFFIX_KEYS.contains(&raw_key) {
        return None;
    }
    for backend in suffix_backends() {
        if let Some(base) = backend.matches_suffix(raw_key) {
            return Some((backend, base));
        }
    }
    None
}

fn unsupported_cloud_suffix(raw_key: &str) -> Option<(&'static str, &'static str)> {
    const KNOWN: [(&str, &str, bool); 4] = [
        ("_AZURE", "Azure Key Vault", cfg!(feature = "secrets-azure")),
        ("_VAULT", "Vault", cfg!(feature = "secrets-vault")),
        ("_AWS", "AWS Secrets Manager", cfg!(feature = "secrets-aws")),
        ("_GCP", "GCP Secret Manager", cfg!(feature = "secrets-gcp")),
    ];

    for (suffix, backend_name, enabled) in KNOWN {
        if raw_key.ends_with(suffix) && !enabled {
            return Some((suffix, backend_name));
        }
    }

    None
}

fn unsupported_cloud_suffix_for_base_key(key: &str) -> Option<(&'static str, &'static str)> {
    for suffix in ["_AZURE", "_VAULT", "_AWS", "_GCP"] {
        let suffixed_key = format!("{key}{suffix}");
        let is_set = std::env::var(&suffixed_key)
            .ok()
            .filter(|s| !s.is_empty())
            .is_some();
        if is_set && let Some(unsupported) = unsupported_cloud_suffix(&suffixed_key) {
            return Some(unsupported);
        }
    }
    None
}

pub async fn resolve_all_env_secrets() -> Result<ResolvedEnvSecrets, String> {
    let mut to_resolve: HashMap<String, Vec<(String, String, BackendKind)>> = HashMap::new();

    for (raw_key, value) in std::env::vars() {
        if !raw_key.starts_with(FERRUM_PREFIX) {
            continue;
        }
        // Empty suffixed variables are unset-equivalent for every backend.
        // Check this before feature gating so behavior does not change based
        // on whether a cloud provider was compiled into the binary.
        if value.is_empty() {
            continue;
        }
        if let Some((suffix, backend_name)) = unsupported_cloud_suffix(&raw_key) {
            return Err(format!(
                "Unsupported secret suffix {} on {}: {} support is not enabled in this build.",
                suffix, raw_key, backend_name
            ));
        }
        if let Some((backend, base_key)) = match_suffix(&raw_key) {
            if base_key.is_empty() {
                continue;
            }
            to_resolve.entry(base_key.to_string()).or_default().push((
                raw_key.clone(),
                value,
                backend.kind(),
            ));
        }
    }

    let mut pending: Vec<PendingSecret> = Vec::new();

    // Iterate base keys in sorted order rather than `HashMap` order. This fixes
    // both which conflict is reported first when several keys are misconfigured
    // and the order of the resolved results, so two runs on identical input
    // produce byte-identical output. See [`ResolvedEnvSecrets`].
    let mut base_keys: Vec<&String> = to_resolve.keys().collect();
    base_keys.sort();

    for base_key in base_keys {
        let sources = &to_resolve[base_key];
        let direct_set = std::env::var(base_key)
            .ok()
            .filter(|s| !s.is_empty())
            .is_some();

        let total_sources = sources.len() + if direct_set { 1 } else { 0 };
        if total_sources > 1 {
            let mut names: Vec<String> = Vec::new();
            for (suffixed_key, _, _) in sources {
                names.push(suffixed_key.clone());
            }
            // Suffixed sources arrive in `std::env::vars()` order; sort them so
            // the conflict message is byte-identical across processes. The
            // direct variable is prepended afterwards because it is the source
            // an operator is most likely to have forgotten about.
            names.sort();
            if direct_set {
                names.insert(0, "direct env var".to_string());
            }
            return Err(format!(
                "Multiple secret sources configured for {}: {}. Only one source is allowed.",
                base_key,
                names.join(", ")
            ));
        }

        let (suffixed_key, reference, backend) = &sources[0];
        pending.push(PendingSecret {
            base_key: base_key.to_string(),
            reference: reference.clone(),
            suffixed_key: suffixed_key.clone(),
            backend_kind: *backend,
        });
    }

    let fetch_timeout = secret_fetch_timeout();

    let mut results = ResolvedEnvSecrets {
        vars: Vec::new(),
        source_keys_to_remove: Vec::new(),
        loaded_sources: Vec::new(),
    };

    for backend in startup_backends() {
        let backend_pending: Vec<PendingSecret> = pending
            .iter()
            .filter(|s| s.backend_kind == backend.kind())
            .cloned()
            .collect();
        if backend_pending.is_empty() {
            continue;
        }

        let resolved = backend
            .resolve_many(&backend_pending, fetch_timeout)
            .await?;
        for item in resolved {
            if backend.log_loaded() {
                results
                    .loaded_sources
                    .push((item.base_key.clone(), backend.display_name()));
            }
            results.vars.push((item.base_key, item.value));
            results.source_keys_to_remove.push(item.suffixed_key);
        }
    }

    // Results are accumulated provider by provider, so they are grouped by
    // backend rather than ordered by base key. Sort them into the documented
    // base-key order: this is what `validate` prints, and an operator diffing
    // two reports must not see spurious reordering.
    results.vars.sort_by(|left, right| left.0.cmp(&right.0));
    results
        .loaded_sources
        .sort_by(|left, right| left.0.cmp(&right.0));
    results.source_keys_to_remove.sort();

    Ok(results)
}

#[allow(dead_code)]
/// Resolve a single secret key across all configured backends.
///
/// Startup uses `resolve_all_env_secrets()` for bulk env injection; this helper
/// remains for the existing single-key tests and ad-hoc secret lookups.
pub async fn resolve_secret(key: &str) -> Result<Option<ResolvedSecret>, String> {
    if let Some((suffix, backend_name)) = unsupported_cloud_suffix_for_base_key(key) {
        return Err(format!(
            "Unsupported secret suffix {suffix} on {key}{suffix}: {backend_name} support is not enabled in this build."
        ));
    }

    let mut sources: Vec<(&'static dyn SecretBackend, String)> = Vec::new();

    for backend in all_backends() {
        if let Some(reference) = backend.resolve_ref(key) {
            sources.push((backend, reference));
        }
    }

    if sources.len() > 1 {
        let names: Vec<&str> = sources.iter().map(|(backend, _)| backend.name()).collect();
        return Err(format!(
            "Multiple secret sources configured for {}: {}. Only one source is allowed.",
            key,
            names.join(", ")
        ));
    }

    let Some((backend, reference)) = sources.into_iter().next() else {
        return Ok(None);
    };

    let value = tokio::time::timeout(secret_fetch_timeout(), backend.resolve_one(&reference, key))
        .await
        .map_err(|_| timeout_error(key, backend.display_name(), secret_fetch_timeout()))?
        .map_err(|error| redact_source_reference(error, &reference))?;

    if backend.log_loaded() {
        info!("Loaded {} from {}", key, backend.display_name());
    }

    Ok(Some(ResolvedSecret {
        value,
        source: backend.source(&reference),
    }))
}

/// Resolve a direct provider reference such as a `vault://...` or `aws://...`
/// TLS material URI.
///
/// Unlike [`resolve_secret`], this does not inspect environment variables for
/// suffixed variants; the caller has already selected the provider and passed
/// its backend-specific reference. The same backend clients, timeouts, and
/// feature gates are used so typed TLS source URIs do not duplicate provider
/// setup logic.
pub async fn resolve_external_reference(
    provider: &str,
    reference: &str,
    key: &str,
) -> Result<ResolvedSecret, String> {
    if let Some(display_name) = unsupported_provider_name(provider) {
        return Err(format!(
            "{} support is not enabled in this build",
            display_name
        ));
    }

    let Some(backend) = suffix_backends()
        .into_iter()
        .find(|backend| backend.name() == provider)
    else {
        return Err(format!("Unsupported secret provider scheme '{}'", provider));
    };

    let value = tokio::time::timeout(secret_fetch_timeout(), backend.resolve_one(reference, key))
        .await
        .map_err(|_| timeout_error(key, backend.display_name(), secret_fetch_timeout()))?
        .map_err(|error| redact_source_reference(error, reference))?;

    if backend.log_loaded() {
        info!("Loaded {} from {}", key, backend.display_name());
    }

    Ok(ResolvedSecret {
        value,
        source: backend.source(reference),
    })
}

fn unsupported_provider_name(provider: &str) -> Option<&'static str> {
    match provider {
        "vault" if !cfg!(feature = "secrets-vault") => Some("Vault"),
        "aws" if !cfg!(feature = "secrets-aws") => Some("AWS Secrets Manager"),
        "gcp" if !cfg!(feature = "secrets-gcp") => Some("GCP Secret Manager"),
        "azure" if !cfg!(feature = "secrets-azure") => Some("Azure Key Vault"),
        _ => None,
    }
}

#[async_trait]
impl SecretBackend for DirectEnvBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::DirectEnv
    }

    fn name(&self) -> &'static str {
        "direct"
    }

    fn display_name(&self) -> &'static str {
        "environment"
    }

    fn log_loaded(&self) -> bool {
        false
    }

    fn resolve_ref(&self, key: &str) -> Option<String> {
        env::resolve(key)
    }

    fn source(&self, _reference: &str) -> String {
        "env".to_string()
    }

    async fn resolve_one(&self, _reference: &str, key: &str) -> Result<String, String> {
        env::resolve(key).ok_or_else(|| {
            format!(
                "Environment variable {} was not set when resolving direct env secret",
                key
            )
        })
    }
}

#[async_trait]
impl SecretBackend for FileBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::File
    }

    fn name(&self) -> &'static str {
        "file"
    }

    fn display_name(&self) -> &'static str {
        "file"
    }

    fn suffix(&self) -> Option<&'static str> {
        Some("_FILE")
    }

    fn resolve_ref(&self, key: &str) -> Option<String> {
        file::resolve_ref(key)
    }

    fn source(&self, reference: &str) -> String {
        format!("file:{}", reference)
    }

    async fn resolve_one(&self, reference: &str, key: &str) -> Result<String, String> {
        let reference = reference.to_string();
        let key = key.to_string();
        let key_for_error = key.clone();

        tokio::task::spawn_blocking(move || file::read_secret(&reference, &key))
            .await
            .map_err(|err| {
                format!(
                    "Blocking file secret read task failed for {}: {}",
                    key_for_error, err
                )
            })?
    }
}

#[cfg(feature = "secrets-vault")]
#[async_trait]
impl SecretBackend for VaultBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Vault
    }

    fn name(&self) -> &'static str {
        "vault"
    }

    fn display_name(&self) -> &'static str {
        "Vault"
    }

    fn suffix(&self) -> Option<&'static str> {
        Some("_VAULT")
    }

    fn resolve_ref(&self, key: &str) -> Option<String> {
        vault::resolve_ref(key)
    }

    fn source(&self, reference: &str) -> String {
        format!("vault:{}", reference)
    }

    async fn resolve_one(&self, reference: &str, key: &str) -> Result<String, String> {
        vault::fetch_secret(reference, key).await
    }

    async fn resolve_many(
        &self,
        secrets: &[PendingSecret],
        timeout: Duration,
    ) -> Result<Vec<ResolvedPendingSecret>, String> {
        let client = vault::VaultClientWrapper::new()?;
        resolve_many_concurrent(
            secrets,
            timeout,
            self.display_name(),
            &client,
            |client, reference, key| Box::pin(client.fetch_secret(reference, key)),
        )
        .await
    }
}

#[cfg(feature = "secrets-aws")]
#[async_trait]
impl SecretBackend for AwsBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Aws
    }

    fn name(&self) -> &'static str {
        "aws"
    }

    fn display_name(&self) -> &'static str {
        "AWS Secrets Manager"
    }

    fn suffix(&self) -> Option<&'static str> {
        Some("_AWS")
    }

    fn resolve_ref(&self, key: &str) -> Option<String> {
        aws::resolve_ref(key)
    }

    fn source(&self, reference: &str) -> String {
        format!("aws:{}", reference)
    }

    async fn resolve_one(&self, reference: &str, key: &str) -> Result<String, String> {
        aws::fetch_secret(reference, key).await
    }

    async fn resolve_many(
        &self,
        secrets: &[PendingSecret],
        timeout: Duration,
    ) -> Result<Vec<ResolvedPendingSecret>, String> {
        let client = aws::AwsClientWrapper::new().await;
        resolve_many_concurrent(
            secrets,
            timeout,
            self.display_name(),
            &client,
            |client, reference, key| Box::pin(client.fetch_secret(reference, key)),
        )
        .await
    }
}

#[cfg(feature = "secrets-gcp")]
#[async_trait]
impl SecretBackend for GcpBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Gcp
    }

    fn name(&self) -> &'static str {
        "gcp"
    }

    fn display_name(&self) -> &'static str {
        "GCP Secret Manager"
    }

    fn suffix(&self) -> Option<&'static str> {
        Some("_GCP")
    }

    fn resolve_ref(&self, key: &str) -> Option<String> {
        gcp::resolve_ref(key)
    }

    fn source(&self, reference: &str) -> String {
        format!("gcp:{}", reference)
    }

    async fn resolve_one(&self, reference: &str, key: &str) -> Result<String, String> {
        gcp::fetch_secret(reference, key).await
    }

    async fn resolve_many(
        &self,
        secrets: &[PendingSecret],
        timeout: Duration,
    ) -> Result<Vec<ResolvedPendingSecret>, String> {
        let client = gcp::GcpClientWrapper::new().await?;
        resolve_many_concurrent(
            secrets,
            timeout,
            self.display_name(),
            &client,
            |client, reference, key| Box::pin(client.fetch_secret(reference, key)),
        )
        .await
    }
}

#[cfg(feature = "secrets-azure")]
#[async_trait]
impl SecretBackend for AzureBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Azure
    }

    fn name(&self) -> &'static str {
        "azure"
    }

    fn display_name(&self) -> &'static str {
        "Azure Key Vault"
    }

    fn suffix(&self) -> Option<&'static str> {
        Some("_AZURE")
    }

    fn resolve_ref(&self, key: &str) -> Option<String> {
        azure::resolve_ref(key)
    }

    fn source(&self, reference: &str) -> String {
        format!("azure:{}", reference)
    }

    async fn resolve_one(&self, reference: &str, key: &str) -> Result<String, String> {
        azure::fetch_secret(reference, key).await
    }

    async fn resolve_many(
        &self,
        secrets: &[PendingSecret],
        timeout: Duration,
    ) -> Result<Vec<ResolvedPendingSecret>, String> {
        let creds = azure::AzureCredentials::new()?;
        resolve_many_concurrent(
            secrets,
            timeout,
            self.display_name(),
            &creds,
            |creds, reference, key| Box::pin(creds.fetch_secret(reference, key)),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn match_suffix_file() {
        let (backend, base) = match_suffix("FERRUM_DB_URL_FILE").unwrap();
        assert_eq!(base, "FERRUM_DB_URL");
        assert_eq!(backend.name(), "file");
    }

    #[cfg(feature = "secrets-vault")]
    #[test]
    fn match_suffix_vault() {
        let (backend, base) = match_suffix("FERRUM_JWT_SECRET_VAULT").unwrap();
        assert_eq!(base, "FERRUM_JWT_SECRET");
        assert_eq!(backend.name(), "vault");
    }

    #[cfg(feature = "secrets-aws")]
    #[test]
    fn match_suffix_aws() {
        let (backend, base) = match_suffix("FERRUM_DB_URL_AWS").unwrap();
        assert_eq!(base, "FERRUM_DB_URL");
        assert_eq!(backend.name(), "aws");
    }

    #[cfg(feature = "secrets-gcp")]
    #[test]
    fn match_suffix_gcp() {
        let (backend, base) = match_suffix("FERRUM_DB_URL_GCP").unwrap();
        assert_eq!(base, "FERRUM_DB_URL");
        assert_eq!(backend.name(), "gcp");
    }

    #[cfg(feature = "secrets-azure")]
    #[test]
    fn match_suffix_azure() {
        let (backend, base) = match_suffix("FERRUM_DB_URL_AZURE").unwrap();
        assert_eq!(base, "FERRUM_DB_URL");
        assert_eq!(backend.name(), "azure");
    }

    #[test]
    fn match_suffix_no_match() {
        assert!(match_suffix("FERRUM_DB_URL").is_none());
        assert!(match_suffix("FERRUM_DB_URL_ETCD").is_none());
        assert!(match_suffix("FERRUM_DNS_RESOLVER_HOSTS_FILE").is_none());
        assert!(match_suffix("").is_none());
        assert!(match_suffix("RANDOM_KEY").is_none());
    }

    #[test]
    fn match_suffix_bare_suffix_returns_empty_base() {
        let (backend, base) = match_suffix("_FILE").unwrap();
        assert_eq!(base, "");
        assert_eq!(backend.name(), "file");
    }

    #[cfg(feature = "secrets-azure")]
    #[test]
    fn match_suffix_azure_checked_before_file() {
        let (backend, base) = match_suffix("FERRUM_X_AZURE").unwrap();
        assert_eq!(base, "FERRUM_X");
        assert_eq!(backend.name(), "azure");
    }

    #[test]
    fn match_suffix_case_sensitive() {
        assert!(match_suffix("FERRUM_DB_URL_file").is_none());
        assert!(match_suffix("FERRUM_DB_URL_vault").is_none());
        assert!(match_suffix("FERRUM_DB_URL_aws").is_none());
    }

    #[test]
    fn startup_backends_have_distinct_kinds() {
        let kinds: Vec<BackendKind> = startup_backends()
            .iter()
            .map(|backend| backend.kind())
            .collect();
        let unique: HashSet<BackendKind> = kinds.iter().copied().collect();
        assert_eq!(kinds.len(), unique.len());
    }
}
