//! Shared HMAC test helpers for functional tests that exercise HMAC
//! authentication (auth/ACL, credential rotation, etc.).

use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

struct HmacSignatureInput<'a> {
    namespace: &'a str,
    method: &'a str,
    path: &'a str,
    query: &'a str,
    date: &'a str,
    username: &'a str,
    authority: &'a str,
    secret: &'a str,
    digest_header: &'a str,
}

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
    generate_hmac_signature_from(HmacSignatureInput {
        namespace: ferrum_edge::config::types::DEFAULT_NAMESPACE,
        method,
        path,
        query: "",
        date,
        username,
        authority,
        secret,
        digest_header: &empty_digest_header(),
    })
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
    generate_hmac_signature_from(HmacSignatureInput {
        namespace: ferrum_edge::config::types::DEFAULT_NAMESPACE,
        method,
        path,
        query,
        date,
        username,
        authority,
        secret,
        digest_header: &empty_digest_header(),
    })
}

/// Generate an HMAC-SHA256 signature for a no-query request with an explicit
/// Digest or Content-Digest header value.
pub fn generate_hmac_signature_with_digest(
    method: &str,
    path: &str,
    date: &str,
    username: &str,
    authority: &str,
    secret: &str,
    digest_header: &str,
) -> String {
    generate_hmac_signature_from(HmacSignatureInput {
        namespace: ferrum_edge::config::types::DEFAULT_NAMESPACE,
        method,
        path,
        query: "",
        date,
        username,
        authority,
        secret,
        digest_header,
    })
}

fn generate_hmac_signature_from(input: HmacSignatureInput<'_>) -> String {
    let signing_string = format!(
        "ferrum-hmac-v1\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        input.namespace,
        input.username,
        input.authority,
        input.method,
        input.path,
        input.query,
        input.date,
        input.digest_header
    );
    let mut mac = HmacSha256::new_from_slice(input.secret.as_bytes())
        .expect("Failed to create HMAC instance");
    mac.update(signing_string.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
}

/// Fields signed by the `ferrum-hmac-v2` base.
pub struct HmacV2Request<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub date: &'a str,
    pub username: &'a str,
    pub authority: &'a str,
    pub secret: &'a str,
    pub digest_header: &'a str,
    /// The nonce bound into the signature.
    pub nonce: &'a str,
}

/// Compute a `ferrum-hmac-v2` signature.
///
/// The v2 base is v1 plus a trailing bound `{NONCE}` field, and the profile
/// version is the base's first field — so this signature cannot verify under
/// v1 and a v1 signature cannot verify here.
pub fn hmac_v2_signature(request: &HmacV2Request<'_>) -> String {
    let signing_string = format!(
        "ferrum-hmac-v2\n{}\n{}\n{}\n{}\n{}\n\n{}\n{}\n{}",
        ferrum_edge::config::types::DEFAULT_NAMESPACE,
        request.username,
        request.authority,
        request.method,
        request.path,
        request.date,
        request.digest_header,
        request.nonce
    );
    let mut mac = HmacSha256::new_from_slice(request.secret.as_bytes())
        .expect("Failed to create HMAC instance");
    mac.update(signing_string.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
}

/// Build a `ferrum-hmac-v2` `Authorization` header value.
///
/// `declared_nonce` is what goes on the wire; it defaults to the signed nonce.
/// Passing a different value is how a test proves the nonce is actually bound:
/// swapping it without recomputing the signature must fail authentication.
pub fn hmac_v2_authorization_header(
    request: &HmacV2Request<'_>,
    declared_nonce: Option<&str>,
) -> String {
    let signature = hmac_v2_signature(request);
    let nonce = declared_nonce.unwrap_or(request.nonce);
    let username = request.username;
    format!(
        r#"hmac username="{username}", algorithm="hmac-sha256", nonce="{nonce}", signature="{signature}""#
    )
}

/// A 32-character lowercase-hex nonce — exactly the 128-bit minimum the v2
/// wire form admits for the hex spelling.
pub fn hmac_v2_nonce(seed: u64) -> String {
    format!("{seed:032x}")
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
