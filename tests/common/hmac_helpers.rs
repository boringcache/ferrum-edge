//! Shared HMAC test helpers for functional tests that exercise HMAC
//! authentication (auth/ACL, credential rotation, etc.).

use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Generate an HMAC-SHA256 signature for a request, matching the signing
/// string format expected by the `hmac_auth` plugin. No-query requests still
/// include the empty query field in the signed string.
pub fn generate_hmac_signature(
    method: &str,
    path: &str,
    date: &str,
    username: &str,
    authority: &str,
    secret: &str,
) -> String {
    generate_hmac_signature_with_query(method, path, "", date, username, authority, secret)
}

/// Generate an HMAC-SHA256 signature for a request with a raw query string.
pub fn generate_hmac_signature_with_query(
    method: &str,
    path: &str,
    query: &str,
    date: &str,
    username: &str,
    authority: &str,
    secret: &str,
) -> String {
    let signing_string = format!(
        "ferrum-hmac-v1\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        username,
        authority,
        method,
        path,
        query,
        date,
        empty_digest_header()
    );
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("Failed to create HMAC instance");
    mac.update(signing_string.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
}

/// Return the canonical authority used to sign a request sent to `url`.
pub fn hmac_authority_from_url(url: &str) -> String {
    let parsed = reqwest::Url::parse(url).expect("test HMAC URL must be valid");
    let raw_host = parsed.host_str().expect("test HMAC URL must have a host");
    let host = if raw_host.contains(':') {
        format!("[{raw_host}]")
    } else {
        raw_host.to_ascii_lowercase()
    };
    parsed
        .port()
        .map_or(host.clone(), |port| format!("{host}:{port}"))
}

/// Return the SHA-256 digest header value for an empty body.
pub fn empty_digest_header() -> String {
    let digest = Sha256::digest([]);
    format!(
        "sha-256={}",
        base64::engine::general_purpose::STANDARD.encode(digest)
    )
}
