use std::collections::{HashMap, HashSet};

use base64::Engine;
use jsonwebtoken::{Algorithm, Header, Validation, decode, decode_header};
use serde_json::Value;

use super::jwks_store::{CachedJwk, JwksKeyStore};

pub struct JwtVerifyParams<'a> {
    pub issuer: Option<&'a str>,
    pub audiences: &'a [String],
    pub require_exp: bool,
    pub leeway_secs: u64,
    pub validate_nbf: bool,
}

/// Verify a JWT against a trusted JWKS snapshot.
///
/// Key selection is exclusively the JWT header `kid`:
/// - missing or empty `kid` fails closed
/// - a `kid` absent from the current trusted map fails closed
/// - a matching `kid` binds verification to that one key
///
/// There is no all-keys fallback. A token signed by a different published key
/// is rejected even when that other key would verify the signature. Failures
/// return `None` with no token, claim, key, or `kid` logging.
pub async fn verify_jwt_with_jwks(
    token: &str,
    store: &JwksKeyStore,
    params: &JwtVerifyParams<'_>,
) -> Option<Value> {
    let all_keys = store.trusted_keys()?;
    let header = decode_header(token).ok()?;
    let cached_key = key_for_header_kid(&header, &all_keys)?;
    let validation = build_validation(cached_key.algorithm, params);
    decode::<Value>(token, &cached_key.decoding_key, &validation)
        .ok()
        .map(|td| td.claims)
}

/// Bind verification to the single trusted key named by the JWT header `kid`.
///
/// Missing, empty, and unknown identifiers return `None`. The identifier itself
/// is never logged.
fn key_for_header_kid<'a>(
    header: &Header,
    keys: &'a HashMap<String, CachedJwk>,
) -> Option<&'a CachedJwk> {
    let kid = header.kid.as_deref().filter(|kid| !kid.is_empty())?;
    keys.get(kid)
}

pub fn peek_unverified_issuer(token: &str) -> Option<String> {
    let mut parts = token.split('.');
    let _header = parts.next()?;
    let payload_segment = parts.next()?;
    let _signature = parts.next()?;
    if parts.next().is_some() {
        return None;
    }

    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_segment)
        .ok()?;
    let payload: Value = serde_json::from_slice(&payload_bytes).ok()?;
    payload
        .get("iss")
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned)
}

fn build_validation(algorithm: Algorithm, params: &JwtVerifyParams<'_>) -> Validation {
    let mut validation = Validation::new(algorithm);
    validation.validate_exp = true;
    validation.leeway = params.leeway_secs;
    validation.validate_nbf = params.validate_nbf;
    if params.require_exp {
        validation.required_spec_claims = HashSet::from(["exp".to_string()]);
    } else {
        validation.required_spec_claims.clear();
    }
    if let Some(issuer) = params.issuer {
        validation.set_issuer(&[issuer]);
    }
    if !params.audiences.is_empty() {
        validation.set_audience(params.audiences);
    }
    validation
}
