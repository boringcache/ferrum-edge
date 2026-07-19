//! Azure Key Vault secret resolution (requires `secrets-azure` feature).
//!
//! Authentication uses `ClientSecretCredential` via env vars:
//! - `AZURE_TENANT_ID` — Azure AD tenant ID
//! - `AZURE_CLIENT_ID` — Application (service principal) client ID
//! - `AZURE_CLIENT_SECRET` — Application client secret

use std::env;
use std::sync::Arc;

use azure_core::credentials::{AccessToken, TokenCredential, TokenRequestOptions};

/// Check if the `{key}_AZURE` env var is set and non-empty.
/// Returns the Azure Key Vault secret URL
/// (e.g. `https://<vault>.vault.azure.net/secrets/<name>`) if so.
pub fn resolve_ref(key: &str) -> Option<String> {
    let azure_key = format!("{}_AZURE", key);
    env::var(&azure_key).ok().filter(|s| !s.is_empty())
}

/// Reusable Azure credentials for batch secret resolution.
/// The credential is created once and shared across fetches from multiple
/// vault URLs, avoiding repeated OAuth token acquisition.
pub struct AzureCredentials {
    credential: Arc<dyn TokenCredential>,
}

impl AzureCredentials {
    /// Create Azure credentials from standard env vars.
    pub fn new() -> Result<Self, String> {
        let tenant_id = env::var("AZURE_TENANT_ID").map_err(|_| {
            "AZURE_TENANT_ID must be set to resolve secrets from Azure Key Vault".to_string()
        })?;
        let client_id = env::var("AZURE_CLIENT_ID").map_err(|_| {
            "AZURE_CLIENT_ID must be set to resolve secrets from Azure Key Vault".to_string()
        })?;
        let client_secret = env::var("AZURE_CLIENT_SECRET").map_err(|_| {
            "AZURE_CLIENT_SECRET must be set to resolve secrets from Azure Key Vault".to_string()
        })?;

        let credential: Arc<dyn TokenCredential> = azure_identity::ClientSecretCredential::new(
            &tenant_id,
            client_id,
            client_secret.into(),
            None,
        )
        .map_err(|e| format!("Failed to create Azure credentials: {}", e))?;

        Ok(Self { credential })
    }

    /// Build credentials from a pre-acquired bearer token instead of acquiring
    /// one from Entra ID.
    ///
    /// This supports environments where a valid Key Vault access token is
    /// obtained out of band — e.g. a workload-identity sidecar, a federated
    /// token file, or an IMDS proxy — and only the Key Vault data-plane call
    /// needs to be made in-process. The credential performs no Entra ID round
    /// trip of its own; it simply replays the supplied token when the Key Vault
    /// pipeline requests one (including after an authentication challenge).
    pub fn from_static_token(token: impl Into<String>) -> Self {
        Self {
            credential: Arc::new(StaticTokenCredential::new(token)),
        }
    }

    /// Fetch a secret value from Azure Key Vault using these credentials.
    pub async fn fetch_secret(&self, reference: &str, key: &str) -> Result<String, String> {
        fetch_with_credential(&self.credential, reference, key).await
    }
}

/// Fetch a single secret from Azure Key Vault (creates new credentials).
/// For batch resolution, use `AzureCredentials`.
pub async fn fetch_secret(reference: &str, key: &str) -> Result<String, String> {
    let creds = AzureCredentials::new()?;
    creds.fetch_secret(reference, key).await
}

/// Parse a Key Vault secret reference URL into `(vault_url, secret_name)`.
///
/// The returned `vault_url` preserves the scheme, host **and port** of the
/// reference. Dropping the port (the previous behavior) silently rewrote a URL
/// like `http://127.0.0.1:12345/secrets/admin-jwt` to `http://127.0.0.1`, which
/// breaks any vault served on a non-default port — including local fakes,
/// emulators, and sidecar/proxy front ends.
pub fn parse_keyvault_reference(reference: &str, key: &str) -> Result<(String, String), String> {
    let url = url::Url::parse(reference)
        .map_err(|e| format!("Invalid Azure Key Vault URL for {}: {}", key, e))?;

    let host = url
        .host_str()
        .ok_or_else(|| format!("Azure Key Vault URL for {} has no host", key))?;

    // Preserve an explicit port when present so non-standard ports survive.
    let authority = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };
    let vault_url = format!("{}://{}", url.scheme(), authority);

    let path_segments: Vec<&str> = url.path().trim_matches('/').split('/').collect();
    if path_segments.len() < 2 || path_segments[0] != "secrets" {
        return Err(format!(
            "Invalid Azure Key Vault URL for {}: expected format \
             https://<vault>.vault.azure.net/secrets/<name>",
            key
        ));
    }
    // NOTE: a trailing `/<version>` segment is currently ignored — the latest
    // version is always fetched. See the `azure_versioned_url_behavior` test.
    let secret_name = path_segments[1].to_string();

    Ok((vault_url, secret_name))
}

/// Shared fetch logic used by both single and batch paths.
async fn fetch_with_credential(
    credential: &Arc<dyn TokenCredential>,
    reference: &str,
    key: &str,
) -> Result<String, String> {
    let (vault_url, secret_name) = parse_keyvault_reference(reference, key)?;

    let client =
        azure_security_keyvault_secrets::SecretClient::new(&vault_url, credential.clone(), None)
            .map_err(|e| format!("Failed to create Azure Key Vault client for {}: {}", key, e))?;

    // Errors name the base key and the failure class only — the vault URL and
    // secret name are the source reference and are treated as sensitive. The
    // registry additionally redacts any residual occurrence echoed back by the
    // SDK error itself.
    let response = client
        .get_secret(&secret_name, None)
        .await
        .map_err(|e| format!("Failed to get Azure secret for {}: {}", key, e))?;

    let secret = response
        .into_model()
        .map_err(|e| format!("Failed to parse Azure secret for {}: {}", key, e))?;

    secret
        .value
        .ok_or_else(|| format!("Azure secret for {} has no value", key))
}

/// A [`TokenCredential`] backed by a fixed, pre-acquired bearer token.
///
/// Used by [`AzureCredentials::from_static_token`]; performs no token
/// acquisition of its own and simply replays the supplied token.
#[derive(Debug)]
struct StaticTokenCredential {
    token: String,
}

impl StaticTokenCredential {
    fn new(token: impl Into<String>) -> Self {
        Self {
            token: token.into(),
        }
    }
}

#[async_trait::async_trait]
impl TokenCredential for StaticTokenCredential {
    async fn get_token(
        &self,
        _scopes: &[&str],
        _options: Option<TokenRequestOptions<'_>>,
    ) -> azure_core::Result<AccessToken> {
        // The token is supplied externally and is not refreshed in-process;
        // hand back a generous expiry so the pipeline treats it as valid.
        let expires_on = time::OffsetDateTime::now_utc() + time::Duration::hours(1);
        Ok(AccessToken::new(self.token.clone(), expires_on))
    }
}
