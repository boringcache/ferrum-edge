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

fn bounded_verification_rounds(configured_limit: usize) -> usize {
    configured_limit.clamp(1, MAX_BASIC_AUTH_VERIFICATION_ROUNDS)
}

pub struct BasicAuth {
    /// Pre-computed HMAC key from FERRUM_BASIC_AUTH_HMAC_SECRET.
    hmac_secret: Vec<u8>,
    /// A valid process-local hash used to equalize missing credential rounds.
    dummy_password_hash: String,
    /// Fixed verification work, independent of consumer rotation state.
    verification_rounds: usize,
    #[cfg(test)]
    verification_count: std::sync::atomic::AtomicUsize,
}

impl BasicAuth {
    pub fn new(config: &Value) -> Result<Self, String> {
        use crate::config::conf_file::resolve_ferrum_var;

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

        let hmac_secret = resolve_ferrum_var("FERRUM_BASIC_AUTH_HMAC_SECRET").ok_or_else(|| {
            "basic_auth: FERRUM_BASIC_AUTH_HMAC_SECRET must be set to a unique, random value of \
             at least 32 bytes. The plugin cannot operate without a strong secret."
                .to_string()
        })?;
        crate::config::types::validate_basic_auth_hmac_secret(&hmac_secret)
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
            hmac_secret: hmac_secret.into_bytes(),
            dummy_password_hash,
            verification_rounds: bounded_verification_rounds(
                crate::config::types::max_credentials_per_type(),
            ),
            #[cfg(test)]
            verification_count: std::sync::atomic::AtomicUsize::new(0),
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
        let ExtractedCredential::BasicAuth { username, password } = credential else {
            return VerifyOutcome::NotApplicable;
        };

        let consumer = consumer_index.find_by_username(&username);
        let credential_entries = consumer
            .as_ref()
            .map(|consumer| consumer.credential_entries("basicauth"))
            .unwrap_or_default();
        let mut password_matched = false;

        for round in 0..self.verification_rounds {
            #[cfg(test)]
            self.verification_count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let configured_hash = credential_entries
                .get(round)
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
}

auth_flow::impl_auth_plugin!(
    BasicAuth,
    "basic_auth",
    super::priority::BASIC_AUTH,
    crate::plugins::HTTP_FAMILY_PROTOCOLS,
    auth_flow::run_auth
);

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::atomic::Ordering;

    use chrono::Utc;
    use serde_json::json;

    use super::*;
    use crate::config::types::Consumer;

    fn consumer_with_hashes(hashes: Vec<String>) -> Consumer {
        Consumer {
            id: "basic-timing".to_string(),
            namespace: crate::config::types::default_namespace(),
            username: "alice".to_string(),
            custom_id: None,
            credentials: HashMap::from([(
                "basicauth".to_string(),
                Value::Array(
                    hashes
                        .into_iter()
                        .map(|password_hash| json!({"password_hash": password_hash}))
                        .collect(),
                ),
            )]),
            acl_groups: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn test_plugin() -> BasicAuth {
        BasicAuth {
            hmac_secret: vec![b'x'; 32],
            dummy_password_hash: format!("hmac_sha256:{}", "0".repeat(64)),
            verification_rounds: 2,
            verification_count: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn hash(password: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(&[b'x'; 32]).unwrap();
        mac.update(password.as_bytes());
        format!("hmac_sha256:{}", hex::encode(mac.finalize().into_bytes()))
    }

    #[tokio::test]
    async fn verification_rounds_do_not_reveal_username_or_rotation_state() {
        let plugin = test_plugin();
        for (index, consumers) in [
            Vec::new(),
            vec![consumer_with_hashes(vec![hash("one")])],
            vec![consumer_with_hashes(vec![hash("one"), hash("two")])],
        ]
        .into_iter()
        .enumerate()
        {
            let username = if index == 0 { "unknown" } else { "alice" };
            let outcome = plugin
                .verify(
                    ExtractedCredential::BasicAuth {
                        username: username.to_string(),
                        password: "wrong".to_string(),
                    },
                    &ConsumerIndex::new(&consumers),
                )
                .await;
            assert!(matches!(outcome, VerifyOutcome::VerificationFailed(_)));
            assert_eq!(plugin.verification_count.swap(0, Ordering::Relaxed), 2);
        }
    }

    #[tokio::test]
    async fn dummy_verification_round_cannot_authenticate_a_consumer() {
        let mut plugin = test_plugin();
        plugin.dummy_password_hash = hash("dummy-password");
        let consumers = [consumer_with_hashes(vec![hash("real-password")])];

        let outcome = plugin
            .verify(
                ExtractedCredential::BasicAuth {
                    username: "alice".to_string(),
                    password: "dummy-password".to_string(),
                },
                &ConsumerIndex::new(&consumers),
            )
            .await;

        assert!(matches!(outcome, VerifyOutcome::VerificationFailed(_)));
        assert_eq!(plugin.verification_count.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn verification_rounds_are_bounded_by_serializable_credential_capacity() {
        assert_eq!(bounded_verification_rounds(0), 1);
        assert_eq!(bounded_verification_rounds(2), 2);
        assert_eq!(
            bounded_verification_rounds(usize::MAX),
            MAX_BASIC_AUTH_VERIFICATION_ROUNDS
        );
    }
}
