//! HTTP Basic Authentication plugin with HMAC-SHA256 password verification.
//!
//! Supports `hmac_sha256:<hex>` password hashes using a server secret.
//! This keeps verification fast and avoids variable-time password-hash
//! work on the request path.
//!
//! The server secret (`FERRUM_BASIC_AUTH_HMAC_SECRET`) MUST be set to a
//! unique, random value of at least 32 bytes. The plugin rejects construction
//! if that requirement is not met — there is no insecure default.

use async_trait::async_trait;
use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use serde_json::Value;
use sha2::Sha256;
use tracing::{debug, warn};

use crate::consumer_index::ConsumerIndex;

use super::utils::auth_flow::{
    self, AuthMechanism, ExtractedCredential, VerifyOutcome, constant_time_eq,
};
use super::{RequestContext, strip_auth_scheme};

type HmacSha256 = Hmac<Sha256>;

// A canonical stored Basic hash alone consumes this many serialized bytes,
// before its JSON field/object/array overhead. Capping dummy work by the total
// credential JSON limit therefore cannot omit any valid stored Basic hash, but
// prevents a mistaken enormous FERRUM_MAX_CREDENTIALS_PER_TYPE value from
// turning an unknown-user request into unbounded HMAC work.
const MIN_STORED_BASIC_AUTH_HASH_BYTES: usize = "hmac_sha256:".len() + 64;
const MAX_BASIC_AUTH_VERIFICATION_ROUNDS: usize =
    crate::config::types::MAX_CREDENTIALS_SIZE / MIN_STORED_BASIC_AUTH_HASH_BYTES;

pub(crate) fn bounded_verification_rounds(configured_limit: usize) -> usize {
    configured_limit.clamp(1, MAX_BASIC_AUTH_VERIFICATION_ROUNDS)
}

pub struct BasicAuth {
    /// Pre-computed HMAC key from FERRUM_BASIC_AUTH_HMAC_SECRET.
    hmac_secret: Vec<u8>,
    /// A valid process-local hash used to equalize missing credential rounds.
    dummy_password_hash: String,
    /// Fixed verification work, independent of consumer rotation state.
    verification_rounds: usize,
}

impl BasicAuth {
    pub fn new(config: &Value) -> Result<Self, String> {
        use crate::config::conf_file::resolve_ferrum_var;

        let hmac_secret = resolve_ferrum_var("FERRUM_BASIC_AUTH_HMAC_SECRET");
        Self::new_with_hmac_secret(config, hmac_secret.as_deref())
    }

    pub(crate) fn new_with_hmac_secret(
        config: &Value,
        hmac_secret: Option<&str>,
    ) -> Result<Self, String> {
        match config {
            Value::Null => {}
            Value::Object(obj) if obj.is_empty() => {}
            Value::Object(_) => {
                return Err("basic_auth: no configuration fields are supported".to_string());
            }
            other => {
                return Err(format!(
                    "basic_auth: config must be an object, got: {other}"
                ));
            }
        }

        let hmac_secret = hmac_secret.ok_or_else(|| {
            "basic_auth: FERRUM_BASIC_AUTH_HMAC_SECRET must be set to a unique, random value of \
             at least 32 bytes. The plugin cannot operate without a strong secret."
                .to_string()
        })?;
        crate::config::types::validate_basic_auth_hmac_secret(hmac_secret)
            .map_err(|error| format!("basic_auth: {error}"))?;

        let mut dummy_mac = HmacSha256::new_from_slice(hmac_secret.as_bytes())
            .map_err(|_| "basic_auth: failed to initialize HMAC verification".to_string())?;
        dummy_mac.update(uuid::Uuid::new_v4().as_bytes());
        let dummy_password_hash = format!(
            "hmac_sha256:{}",
            hex::encode(dummy_mac.finalize().into_bytes())
        );

        debug!("basic_auth: HMAC-SHA256 configured with operator-provided secret");

        Ok(Self {
            hmac_secret: hmac_secret.as_bytes().to_vec(),
            dummy_password_hash,
            verification_rounds: bounded_verification_rounds(
                crate::config::types::max_credentials_per_type(),
            ),
        })
    }

    /// Verify a password against a stored hash.
    ///
    /// Supports `hmac_sha256:<hex>` — HMAC-SHA256 with the server secret.
    fn verify_password(&self, password: &str, stored_hash: &str) -> bool {
        let Ok(mut mac) = HmacSha256::new_from_slice(&self.hmac_secret) else {
            warn!("basic_auth: failed to create HMAC instance");
            return false;
        };
        mac.update(password.as_bytes());
        let computed = mac.finalize().into_bytes();
        let Some(hex_hash) = stored_hash.strip_prefix("hmac_sha256:") else {
            return false;
        };
        let mut expected = [0u8; 32];
        if hex::decode_to_slice(hex_hash, &mut expected).is_err() {
            return false;
        }

        constant_time_eq(&computed, &expected)
    }

    fn verify_credential_with_round_observer<F>(
        &self,
        credential: ExtractedCredential,
        consumer_index: &ConsumerIndex,
        mut observe_round: F,
    ) -> VerifyOutcome
    where
        F: FnMut(),
    {
        let ExtractedCredential::BasicAuth { username, password } = credential else {
            return VerifyOutcome::NotApplicable;
        };

        let consumer = consumer_index.find_by_username(&username);
        let mut password_matched = false;

        for round in 0..self.verification_rounds {
            observe_round();
            // Fixed indexed access avoids collecting a username-dependent
            // number of entries before the padded verification work begins.
            let configured_hash = consumer
                .as_ref()
                .and_then(|consumer| consumer.credentials.get("basicauth"))
                .and_then(Value::as_array)
                .and_then(|entries| entries.get(round))
                .and_then(|entry| entry.get("password_hash"))
                .and_then(Value::as_str);
            let round_matched = self.verify_password(
                &password,
                configured_hash.unwrap_or(&self.dummy_password_hash),
            );
            // Always execute the padded HMAC round, but only a configured
            // credential is allowed to establish identity. The random dummy
            // material is timing padding, never a process-local master password.
            password_matched |= configured_hash.is_some() & round_matched;
        }

        if password_matched && let Some(consumer) = consumer {
            return VerifyOutcome::consumer(consumer);
        }

        VerifyOutcome::VerificationFailed(r#"{"error":"Invalid credentials"}"#.into())
    }

    // The library target exposes this through `_test_support` to external unit
    // tests. The binary test target compiles this module separately without
    // that bridge, so the helper is intentionally unused there.
    #[allow(dead_code)]
    pub(crate) fn verify_with_test_material(
        dummy_password_hash: String,
        verification_rounds: usize,
        username: &str,
        password: &str,
        consumer_index: &ConsumerIndex,
    ) -> (VerifyOutcome, usize) {
        let plugin = Self {
            hmac_secret: vec![b'x'; 32],
            dummy_password_hash,
            verification_rounds,
        };
        let mut verification_count = 0;
        let outcome = plugin.verify_credential_with_round_observer(
            ExtractedCredential::BasicAuth {
                username: username.to_string(),
                password: password.to_string(),
            },
            consumer_index,
            || verification_count += 1,
        );
        (outcome, verification_count)
    }
}

#[async_trait]
impl AuthMechanism for BasicAuth {
    fn mechanism_name(&self) -> &'static str {
        "basic_auth"
    }

    fn authentication_challenge(&self) -> Option<&'static str> {
        Some(r#"Basic realm="ferrum-edge", charset="UTF-8""#)
    }

    fn extract(&self, ctx: &RequestContext) -> ExtractedCredential {
        let Some(auth_header) = ctx.headers.get("authorization") else {
            return ExtractedCredential::Missing;
        };

        let scheme = auth_header
            .split(|c: char| c.is_ascii_whitespace())
            .next()
            .unwrap_or_default();
        if !scheme.eq_ignore_ascii_case("Basic") {
            return ExtractedCredential::Missing;
        }

        let Some(encoded) = strip_auth_scheme(auth_header, "Basic") else {
            return ExtractedCredential::InvalidFormat(
                r#"{"error":"Invalid Basic auth format"}"#.into(),
            );
        };

        let decoded = match base64::engine::general_purpose::STANDARD.decode(encoded) {
            Ok(decoded) => decoded,
            Err(_) => {
                return ExtractedCredential::InvalidFormat(
                    r#"{"error":"Invalid base64 in Basic auth"}"#.into(),
                );
            }
        };

        let credential_str = match String::from_utf8(decoded) {
            Ok(credential_str) => credential_str,
            Err(_) => {
                return ExtractedCredential::InvalidFormat(
                    r#"{"error":"Invalid UTF-8 in Basic auth"}"#.into(),
                );
            }
        };

        let Some((username, password)) = credential_str.split_once(':') else {
            return ExtractedCredential::InvalidFormat(
                r#"{"error":"Invalid Basic auth format"}"#.into(),
            );
        };

        ExtractedCredential::BasicAuth {
            username: username.to_string(),
            password: password.to_string(),
        }
    }

    async fn verify(
        &self,
        credential: ExtractedCredential,
        consumer_index: &ConsumerIndex,
    ) -> VerifyOutcome {
        self.verify_credential_with_round_observer(credential, consumer_index, || {})
    }
}

auth_flow::impl_auth_plugin!(
    BasicAuth,
    "basic_auth",
    super::priority::BASIC_AUTH,
    crate::plugins::HTTP_FAMILY_PROTOCOLS,
    auth_flow::run_auth
);
