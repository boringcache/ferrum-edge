//! JWKS conversion for SPIFFE JWT bundles.
//!
//! CA backends publish JWT authorities as
//! [`PublishedJwtAuthority`] — a key id plus an SPKI (`-----BEGIN PUBLIC
//! KEY-----`) PEM document. The SPIFFE Workload API instead speaks JWKS
//! (`FetchJWTBundles.bundles[trust_domain]` is a JWKS document), and
//! validation needs a `jsonwebtoken` [`DecodingKey`]. This module is the one
//! place both conversions live.
//!
//! ## Algorithm binding
//!
//! The allowed signature algorithms are derived from the **authority's own
//! public key**, never from the token header:
//!
//! | Key | Allowed `alg` |
//! |---|---|
//! | EC P-256 (`prime256v1`) | `ES256` |
//! | EC P-384 (`secp384r1`) | `ES384` |
//! | RSA ≥ 2048 bit | `RS256` `RS384` `RS512` `PS256` `PS384` `PS512` |
//!
//! Everything else — EC P-521 (no `jsonwebtoken` verifier), other curves,
//! Ed25519, DSA, GOST, unknown SPKI — is refused rather than guessed at, and
//! the HMAC family is never reachable, so `alg: HS256` signed with a public
//! key (the classic algorithm-confusion attack) cannot validate.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey};
use serde_json::{Map, Value};
use x509_parser::asn1_rs::Tag;
use x509_parser::prelude::{FromDer, SubjectPublicKeyInfo};
use x509_parser::public_key::PublicKey;

use super::{
    JwtSvidError, MAX_JWKS_DOCUMENT_BYTES, MAX_JWT_AUTHORITIES_PER_TRUST_DOMAIN,
    MAX_JWT_KEY_ID_BYTES, MAX_JWT_PUBLIC_KEY_PEM_BYTES,
};
use crate::identity::ca::PublishedJwtAuthority;

const PEM_PUBLIC_KEY_BEGIN: &str = "-----BEGIN PUBLIC KEY-----";
const PEM_PUBLIC_KEY_END: &str = "-----END PUBLIC KEY-----";

/// Maximum accepted SPKI DER size. An SPKI for the key types we support is a
/// few hundred bytes; RSA-8192 is the practical ceiling.
const MAX_SPKI_DER_BYTES: usize = 4 * 1024;
/// Minimum accepted RSA modulus size in bytes (2048 bit).
const MIN_RSA_MODULUS_BYTES: usize = 256;
/// Maximum accepted RSA public exponent size. Real exponents are 3 bytes
/// (`65537`); a large one is a malformed or hostile JWK.
const MAX_RSA_EXPONENT_BYTES: usize = 8;

/// DER content bytes of the named-curve OIDs we accept.
/// `1.2.840.10045.3.1.7` — NIST P-256 / prime256v1.
const OID_BYTES_P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
/// `1.3.132.0.34` — NIST P-384 / secp384r1.
const OID_BYTES_P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
/// `1.2.840.10045.2.1` — id-ecPublicKey.
const OID_BYTES_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
/// `1.2.840.113549.1.1.1` — rsaEncryption.
const OID_BYTES_RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

/// A public key decomposed into its JWK members.
struct JwkPublicKey {
    kty: &'static str,
    /// JWK members in RFC 7638 lexicographic order, excluding `kty` itself,
    /// which is inserted at its own lexicographic position by
    /// [`Self::thumbprint_input`].
    members: Vec<(&'static str, String)>,
    /// The `alg` advertised in the published JWK.
    preferred_alg: Algorithm,
    /// Every algorithm this key type may legitimately have signed with.
    allowed_algs: Vec<Algorithm>,
}

impl JwkPublicKey {
    /// RFC 7638 §3.2 canonical JWK: the required members only, lexicographic
    /// by member name, no whitespace.
    fn thumbprint_input(&self) -> String {
        // Sorted explicitly rather than via `serde_json::Map`: that type is a
        // `BTreeMap` only while the `preserve_order` feature is off, and any
        // crate in the graph can turn it on. A thumbprint that silently
        // changes with a transitive cargo feature would rotate every key id.
        let mut members: Vec<(&str, &str)> = self
            .members
            .iter()
            .map(|(name, value)| (*name, value.as_str()))
            .collect();
        members.push(("kty", self.kty));
        members.sort_unstable_by(|left, right| left.0.cmp(right.0));

        let mut out = String::from("{");
        for (index, (name, value)) in members.iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            out.push_str(&Value::String((*name).to_string()).to_string());
            out.push(':');
            out.push_str(&Value::String((*value).to_string()).to_string());
        }
        out.push('}');
        out
    }

    /// The published JWK for this key, including `kid`, `alg`, and `use`.
    fn to_jwk(&self, key_id: &str) -> Value {
        let mut jwk = Map::new();
        jwk.insert("kty".to_string(), Value::String(self.kty.to_string()));
        for (name, value) in &self.members {
            jwk.insert((*name).to_string(), Value::String(value.clone()));
        }
        jwk.insert("kid".to_string(), Value::String(key_id.to_string()));
        jwk.insert(
            "alg".to_string(),
            Value::String(format!("{:?}", self.preferred_alg)),
        );
        jwk.insert("use".to_string(), Value::String("sig".to_string()));
        Value::Object(jwk)
    }
}

/// Compute the RFC 7638 JWK thumbprint (base64url, unpadded SHA-256) of an
/// SPKI PEM public key. Used as the `kid` for Ferrum-minted JWT-SVIDs so the
/// key id is derived from the key itself rather than a counter that could
/// collide across restarts.
pub fn published_authority_key_id(public_key_pem: &str) -> Result<String, JwtSvidError> {
    let spki_der = spki_der_from_pem(public_key_pem)?;
    let key = jwk_public_key(&spki_der)?;
    let digest = crate::fips::backend::digest::digest(
        &crate::fips::backend::digest::SHA256,
        key.thumbprint_input().as_bytes(),
    );
    Ok(URL_SAFE_NO_PAD.encode(digest.as_ref()))
}

/// Validate one trust domain's **complete** authority set against every
/// documented bound, and return the serialized JWKS document.
///
/// This is the single gate both publication and validation go through, so
/// `ValidateJWTSVID` can never accept material `FetchJWTBundles` would have
/// refused. Checks, all before any authority is used for anything:
///
/// - the set is non-empty (an empty JWKS is not a conformant "no authorities"
///   signal — SPIFFE Workload API §6.2.2 requires at least the local
///   trust-domain bundle);
/// - the set is no larger than [`MAX_JWT_AUTHORITIES_PER_TRUST_DOMAIN`], so a
///   hostile or misconfigured bundle cannot drive an unbounded scan;
/// - every authority is stamped with `expected_trust_domain`, so a bundle keyed
///   under one domain can never carry another domain's key;
/// - every `key_id` is present, bounded, and control-character free;
/// - no two authorities share a `key_id` (an ambiguous `kid` must not silently
///   resolve to whichever entry came first);
/// - every authority's PEM/DER/key-type/key-size parses into a supported public
///   key;
/// - the serialized JWKS document itself is within
///   [`MAX_JWKS_DOCUMENT_BYTES`].
///
/// A malformed authority is never published or trusted alongside good ones —
/// the whole set is refused.
pub fn validate_published_authorities(
    expected_trust_domain: &crate::identity::spiffe::TrustDomain,
    authorities: &[PublishedJwtAuthority],
) -> Result<Vec<u8>, JwtSvidError> {
    if authorities.is_empty() {
        return Err(JwtSvidError::NoJwtAuthority(
            "this trust domain publishes no JWT authorities",
        ));
    }
    // Bound FIRST: every later check is per-authority work, so the cap has to
    // be enforced before the loop, not inside it.
    if authorities.len() > MAX_JWT_AUTHORITIES_PER_TRUST_DOMAIN {
        return Err(JwtSvidError::InvalidAuthority(
            "too many JWT authorities published for one trust domain",
        ));
    }

    let mut keys: Vec<Value> = Vec::with_capacity(authorities.len());
    let mut seen_key_ids: Vec<&str> = Vec::with_capacity(authorities.len());
    for authority in authorities {
        if authority.trust_domain != *expected_trust_domain {
            return Err(JwtSvidError::InvalidAuthority(
                "a published JWT authority does not belong to its bundle's trust domain",
            ));
        }
        validate_key_id(&authority.key_id)?;
        if seen_key_ids.contains(&authority.key_id.as_str()) {
            return Err(JwtSvidError::InvalidAuthority(
                "two JWT authorities share a key id",
            ));
        }
        seen_key_ids.push(authority.key_id.as_str());

        let spki_der = spki_der_from_pem(&authority.public_key_pem)?;
        let key = jwk_public_key(&spki_der)?;
        keys.push(key.to_jwk(&authority.key_id));
    }

    let mut document = Map::new();
    document.insert("keys".to_string(), Value::Array(keys));
    let bytes = serde_json::to_vec(&Value::Object(document))
        .map_err(|e| JwtSvidError::Internal(format!("JWKS serialization failed: {e}")))?;
    if bytes.len() > MAX_JWKS_DOCUMENT_BYTES {
        return Err(JwtSvidError::InvalidAuthority("JWKS document is too large"));
    }
    Ok(bytes)
}

/// Build the JWKS document for one trust domain's published authorities.
///
/// Thin wrapper over [`validate_published_authorities`], which performs every
/// bound and binding check. The trust domain is taken from the first authority
/// and then required of all of them, so a mixed-domain set is refused here too.
pub fn jwks_document(authorities: &[PublishedJwtAuthority]) -> Result<Vec<u8>, JwtSvidError> {
    let Some(first) = authorities.first() else {
        return Err(JwtSvidError::NoJwtAuthority(
            "this trust domain publishes no JWT authorities",
        ));
    };
    validate_published_authorities(&first.trust_domain, authorities)
}

/// Parse an **externally supplied** JWKS document (a SPIRE agent's JWT bundle,
/// or a federated peer's) into published authorities.
///
/// This is the inverse of [`validate_published_authorities`] and is deliberately
/// as strict: the document is size-bounded before parsing, key entries are
/// bounded before conversion, every entry must be an asymmetric signing key of a
/// supported type/size, and the result is put back through
/// [`validate_published_authorities`] so an externally sourced bundle is held to
/// exactly the bounds a locally produced one is. `kid` is **required** — an
/// unnamed key in a multi-key bundle would be unselectable — and the recovered
/// `kid` is the peer's own, not recomputed, because that is what its tokens
/// carry.
///
/// Unknown JWK members are ignored (JWKS is an extensible document), but an
/// entry whose `use` or `key_ops` says it is not for signature verification is
/// refused rather than repurposed.
pub fn authorities_from_jwks(
    trust_domain: &crate::identity::spiffe::TrustDomain,
    document: &[u8],
) -> Result<Vec<PublishedJwtAuthority>, JwtSvidError> {
    if document.is_empty() {
        return Err(JwtSvidError::InvalidAuthority("JWT bundle JWKS is empty"));
    }
    if document.len() > MAX_JWKS_DOCUMENT_BYTES {
        return Err(JwtSvidError::InvalidAuthority(
            "JWT bundle JWKS document is too large",
        ));
    }
    let parsed = super::parse_strict_json_object(document)
        .map_err(|_| JwtSvidError::InvalidAuthority("JWT bundle JWKS is not a JSON object"))?;
    let keys = match parsed.get("keys") {
        Some(Value::Array(keys)) => keys,
        _ => {
            return Err(JwtSvidError::InvalidAuthority(
                "JWT bundle JWKS has no 'keys' array",
            ));
        }
    };
    if keys.is_empty() {
        return Err(JwtSvidError::InvalidAuthority(
            "JWT bundle JWKS publishes no keys",
        ));
    }
    // Bound before the per-key work, so an oversized key list is refused rather
    // than scanned.
    if keys.len() > MAX_JWT_AUTHORITIES_PER_TRUST_DOMAIN {
        return Err(JwtSvidError::InvalidAuthority(
            "JWT bundle JWKS publishes more keys than one trust domain may hold",
        ));
    }

    let mut authorities = Vec::with_capacity(keys.len());
    for key in keys {
        let Value::Object(jwk) = key else {
            return Err(JwtSvidError::InvalidAuthority(
                "JWT bundle JWKS key entry is not an object",
            ));
        };
        let key_id = match jwk.get("kid") {
            Some(Value::String(kid)) => kid.clone(),
            _ => {
                return Err(JwtSvidError::InvalidAuthority(
                    "JWT bundle JWKS key entry has no string 'kid'",
                ));
            }
        };
        validate_key_id(&key_id)?;
        if let Some(Value::String(use_)) = jwk.get("use")
            && use_ != "sig"
        {
            return Err(JwtSvidError::InvalidAuthority(
                "JWT bundle JWKS key is not declared for signature use",
            ));
        }
        if let Some(Value::Array(ops)) = jwk.get("key_ops")
            && !ops
                .iter()
                .any(|op| op.as_str().is_some_and(|op| op == "verify"))
        {
            return Err(JwtSvidError::InvalidAuthority(
                "JWT bundle JWKS key does not permit signature verification",
            ));
        }
        let public_key_pem = spki_pem_from_jwk(jwk)?;
        authorities.push(PublishedJwtAuthority {
            trust_domain: trust_domain.clone(),
            key_id,
            public_key_pem,
        });
    }

    // Hold the external bundle to exactly the local bounds (duplicate `kid`,
    // trust-domain binding, total JWKS size).
    validate_published_authorities(trust_domain, &authorities)?;
    Ok(authorities)
}

/// Re-encode a JWK public key as an SPKI `PUBLIC KEY` PEM.
///
/// Only the key types Ferrum can verify with are accepted (EC P-256 / P-384 and
/// RSA ≥ 2048 bit); everything else is refused rather than guessed at, matching
/// [`jwk_public_key`]'s allowed set exactly. The re-encoded SPKI is parsed back
/// through that same function, so a JWK that round-trips into something
/// unsupported cannot slip past.
fn spki_pem_from_jwk(jwk: &Map<String, Value>) -> Result<String, JwtSvidError> {
    let kty = jwk
        .get("kty")
        .and_then(Value::as_str)
        .ok_or(JwtSvidError::InvalidAuthority(
            "JWT bundle JWKS key entry has no 'kty'",
        ))?;
    let spki_der = match kty {
        "EC" => {
            let crv = jwk
                .get("crv")
                .and_then(Value::as_str)
                .ok_or(JwtSvidError::InvalidAuthority(
                    "JWT bundle JWKS EC key names no curve",
                ))?;
            let (curve_oid, coordinate_bytes) = match crv {
                "P-256" => (OID_BYTES_P256, 32usize),
                "P-384" => (OID_BYTES_P384, 48usize),
                _ => {
                    return Err(JwtSvidError::InvalidAuthority(
                        "unsupported JWT authority EC curve",
                    ));
                }
            };
            let x = jwk_base64url_member(jwk, "x", coordinate_bytes)?;
            let y = jwk_base64url_member(jwk, "y", coordinate_bytes)?;
            let mut point = Vec::with_capacity(1 + 2 * coordinate_bytes);
            point.push(0x04);
            point.extend_from_slice(&x);
            point.extend_from_slice(&y);
            let algorithm = der_sequence(&[der_oid(OID_BYTES_EC_PUBLIC_KEY), der_oid(curve_oid)]);
            der_sequence(&[algorithm, der_bit_string(&point)])
        }
        "RSA" => {
            // `n` / `e` are unsigned big-endian with no leading zeros
            // (RFC 7518 §6.3.1). The modulus bound is re-checked by
            // `jwk_public_key` after the round trip; checking the raw length
            // here keeps an oversized member from being DER-encoded at all.
            let modulus = jwk_base64url_bounded(jwk, "n", MAX_SPKI_DER_BYTES)?;
            let exponent = jwk_base64url_bounded(jwk, "e", MAX_RSA_EXPONENT_BYTES)?;
            if modulus.len() < MIN_RSA_MODULUS_BYTES {
                return Err(JwtSvidError::InvalidAuthority(
                    "JWT authority RSA public key is smaller than 2048 bits",
                ));
            }
            if exponent.is_empty() {
                return Err(JwtSvidError::InvalidAuthority(
                    "JWT authority RSA public key has an empty exponent",
                ));
            }
            let rsa_public_key = der_sequence(&[
                der_positive_integer(&modulus),
                der_positive_integer(&exponent),
            ]);
            let algorithm = der_sequence(&[der_oid(OID_BYTES_RSA_ENCRYPTION), der_null()]);
            der_sequence(&[algorithm, der_bit_string(&rsa_public_key)])
        }
        _ => {
            return Err(JwtSvidError::InvalidAuthority(
                "unsupported JWT authority key type",
            ));
        }
    };
    if spki_der.len() > MAX_SPKI_DER_BYTES {
        return Err(JwtSvidError::InvalidAuthority(
            "JWT authority public key DER is empty or oversized",
        ));
    }
    // Re-parse what we just built: the PEM we hand on must be exactly as
    // acceptable as one that arrived as a PEM in the first place.
    jwk_public_key(&spki_der)?;
    Ok(spki_pem_from_der(&spki_der))
}

/// Decode a required base64url JWK member and require an exact byte length.
fn jwk_base64url_member(
    jwk: &Map<String, Value>,
    name: &str,
    expected_len: usize,
) -> Result<Vec<u8>, JwtSvidError> {
    let bytes = jwk_base64url_bounded(jwk, name, expected_len)?;
    if bytes.len() != expected_len {
        return Err(JwtSvidError::InvalidAuthority(
            "JWT authority EC public key coordinate is not the named curve's size",
        ));
    }
    Ok(bytes)
}

/// Decode a required base64url JWK member, bounded before decoding.
fn jwk_base64url_bounded(
    jwk: &Map<String, Value>,
    name: &str,
    max_len: usize,
) -> Result<Vec<u8>, JwtSvidError> {
    let encoded = jwk
        .get(name)
        .and_then(Value::as_str)
        .ok_or(JwtSvidError::InvalidAuthority(
            "JWT bundle JWKS key entry is missing a required member",
        ))?;
    // 4 base64 characters carry 3 bytes; refuse before allocating.
    if encoded.len() / 4 * 3 > max_len {
        return Err(JwtSvidError::InvalidAuthority(
            "JWT bundle JWKS key member is too large",
        ));
    }
    let decoded = URL_SAFE_NO_PAD.decode(encoded.as_bytes()).map_err(|_| {
        JwtSvidError::InvalidAuthority("JWT bundle JWKS key member is not unpadded base64url")
    })?;
    if decoded.is_empty() || decoded.len() > max_len {
        return Err(JwtSvidError::InvalidAuthority(
            "JWT bundle JWKS key member is empty or too large",
        ));
    }
    Ok(decoded)
}

/// Wrap SPKI DER into a 64-column `PUBLIC KEY` PEM block.
fn spki_pem_from_der(der: &[u8]) -> String {
    let encoded = STANDARD.encode(der);
    let mut out = String::with_capacity(encoded.len() + encoded.len() / 64 + 64);
    out.push_str(PEM_PUBLIC_KEY_BEGIN);
    for (index, byte) in encoded.bytes().enumerate() {
        if index % 64 == 0 {
            out.push('\n');
        }
        out.push(byte as char);
    }
    out.push('\n');
    out.push_str(PEM_PUBLIC_KEY_END);
    out.push('\n');
    out
}

/// Minimal DER writers. Only the shapes an SPKI needs, and only for lengths a
/// bounded key can produce — every input here is already size-checked.
fn der_tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(contents.len() + 5);
    out.push(tag);
    let len = contents.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let first = bytes
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(bytes.len() - 1);
        let significant = &bytes[first..];
        out.push(0x80 | significant.len() as u8);
        out.extend_from_slice(significant);
    }
    out.extend_from_slice(contents);
    out
}

fn der_sequence(parts: &[Vec<u8>]) -> Vec<u8> {
    let mut contents = Vec::new();
    for part in parts {
        contents.extend_from_slice(part);
    }
    der_tlv(0x30, &contents)
}

fn der_oid(content: &[u8]) -> Vec<u8> {
    der_tlv(0x06, content)
}

fn der_null() -> Vec<u8> {
    der_tlv(0x05, &[])
}

/// BIT STRING with a zero "unused bits" prefix octet.
fn der_bit_string(content: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(content.len() + 1);
    body.push(0x00);
    body.extend_from_slice(content);
    der_tlv(0x03, &body)
}

/// INTEGER from unsigned big-endian bytes. A leading `0x00` is prepended when
/// the high bit is set, so the value never round-trips as negative.
fn der_positive_integer(unsigned_be: &[u8]) -> Vec<u8> {
    let first_significant = unsigned_be
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(unsigned_be.len());
    let trimmed = &unsigned_be[first_significant..];
    if trimmed.is_empty() {
        return der_tlv(0x02, &[0x00]);
    }
    if trimmed[0] & 0x80 != 0 {
        let mut body = Vec::with_capacity(trimmed.len() + 1);
        body.push(0x00);
        body.extend_from_slice(trimmed);
        der_tlv(0x02, &body)
    } else {
        der_tlv(0x02, trimmed)
    }
}

/// Build a `jsonwebtoken` decoding key for a published authority, together
/// with the algorithms that authority's key type is allowed to have used.
pub fn decoding_key_for_authority(
    authority: &PublishedJwtAuthority,
) -> Result<(DecodingKey, Vec<Algorithm>), JwtSvidError> {
    validate_key_id(&authority.key_id)?;
    let spki_der = spki_der_from_pem(&authority.public_key_pem)?;
    let key = jwk_public_key(&spki_der)?;
    let pem_bytes = authority.public_key_pem.as_bytes();
    let decoding = match key.kty {
        "EC" => DecodingKey::from_ec_pem(pem_bytes),
        "RSA" => DecodingKey::from_rsa_pem(pem_bytes),
        _ => {
            return Err(JwtSvidError::InvalidAuthority(
                "unsupported JWT authority key type",
            ));
        }
    }
    .map_err(|_| JwtSvidError::InvalidAuthority("JWT authority public key is unusable"))?;
    Ok((decoding, key.allowed_algs))
}

fn validate_key_id(key_id: &str) -> Result<(), JwtSvidError> {
    if key_id.is_empty() {
        return Err(JwtSvidError::InvalidAuthority(
            "JWT authority key id must not be empty",
        ));
    }
    if key_id.len() > MAX_JWT_KEY_ID_BYTES {
        return Err(JwtSvidError::InvalidAuthority(
            "JWT authority key id is too long",
        ));
    }
    if key_id.chars().any(|c| c.is_control()) {
        return Err(JwtSvidError::InvalidAuthority(
            "JWT authority key id contains control characters",
        ));
    }
    Ok(())
}

/// Decode exactly one `PUBLIC KEY` PEM block into SPKI DER.
///
/// Rejects multi-block documents outright: an operator (or a federated peer)
/// concatenating several keys under one `kid` would otherwise silently have
/// only the first honoured.
fn spki_der_from_pem(pem: &str) -> Result<Vec<u8>, JwtSvidError> {
    if pem.is_empty() {
        return Err(JwtSvidError::InvalidAuthority(
            "JWT authority public key PEM is empty",
        ));
    }
    if pem.len() > MAX_JWT_PUBLIC_KEY_PEM_BYTES {
        return Err(JwtSvidError::InvalidAuthority(
            "JWT authority public key PEM is too large",
        ));
    }
    let begin = pem.find(PEM_PUBLIC_KEY_BEGIN).ok_or(
        JwtSvidError::InvalidAuthority("JWT authority public key is not a PUBLIC KEY PEM block"),
    )?;
    let body_start = begin + PEM_PUBLIC_KEY_BEGIN.len();
    let rest = &pem[body_start..];
    let end = rest.find(PEM_PUBLIC_KEY_END).ok_or(
        JwtSvidError::InvalidAuthority("JWT authority public key PEM block is unterminated"),
    )?;
    let after_end = &rest[end + PEM_PUBLIC_KEY_END.len()..];
    if after_end.contains(PEM_PUBLIC_KEY_BEGIN) {
        return Err(JwtSvidError::InvalidAuthority(
            "JWT authority public key PEM contains more than one block",
        ));
    }

    let base64_body: String = rest[..end].chars().filter(|c| !c.is_whitespace()).collect();
    let der = STANDARD
        .decode(base64_body.as_bytes())
        .map_err(|_| JwtSvidError::InvalidAuthority("JWT authority public key PEM is not base64"))?;
    if der.is_empty() || der.len() > MAX_SPKI_DER_BYTES {
        return Err(JwtSvidError::InvalidAuthority(
            "JWT authority public key DER is empty or oversized",
        ));
    }
    Ok(der)
}

/// Decompose an SPKI DER document into JWK members and the algorithms its key
/// type is allowed to have signed with.
fn jwk_public_key(spki_der: &[u8]) -> Result<JwkPublicKey, JwtSvidError> {
    let (rest, spki) = SubjectPublicKeyInfo::from_der(spki_der).map_err(|_| {
        JwtSvidError::InvalidAuthority("JWT authority public key is not a valid SPKI document")
    })?;
    if !rest.is_empty() {
        return Err(JwtSvidError::InvalidAuthority(
            "JWT authority public key has trailing SPKI bytes",
        ));
    }
    let parsed = spki.parsed().map_err(|_| {
        JwtSvidError::InvalidAuthority("JWT authority public key could not be parsed")
    })?;

    match parsed {
        PublicKey::EC(_) => {
            let curve = ec_curve(&spki)?;
            // Read the point from the SPKI BIT STRING directly: `ECPoint` is
            // just a view over these bytes, and its accessor is tied to the
            // SPKI's own lifetime rather than the local binding's.
            let data: &[u8] = spki.subject_public_key.data.as_ref();
            let expected = 1 + 2 * curve.coordinate_bytes;
            if data.len() != expected || data[0] != 0x04 {
                return Err(JwtSvidError::InvalidAuthority(
                    "JWT authority EC public key is not an uncompressed point of the named curve",
                ));
            }
            let (x, y) = data[1..].split_at(curve.coordinate_bytes);
            Ok(JwkPublicKey {
                kty: "EC",
                members: vec![
                    ("crv", curve.jwk_name.to_string()),
                    ("x", URL_SAFE_NO_PAD.encode(x)),
                    ("y", URL_SAFE_NO_PAD.encode(y)),
                ],
                preferred_alg: curve.alg,
                allowed_algs: vec![curve.alg],
            })
        }
        PublicKey::RSA(rsa) => {
            let modulus = strip_leading_zeros(rsa.modulus);
            let exponent = strip_leading_zeros(rsa.exponent);
            if modulus.len() < MIN_RSA_MODULUS_BYTES {
                return Err(JwtSvidError::InvalidAuthority(
                    "JWT authority RSA public key is smaller than 2048 bits",
                ));
            }
            if exponent.is_empty() {
                return Err(JwtSvidError::InvalidAuthority(
                    "JWT authority RSA public key has an empty exponent",
                ));
            }
            Ok(JwkPublicKey {
                kty: "RSA",
                members: vec![
                    ("e", URL_SAFE_NO_PAD.encode(exponent)),
                    ("n", URL_SAFE_NO_PAD.encode(modulus)),
                ],
                preferred_alg: Algorithm::RS256,
                allowed_algs: vec![
                    Algorithm::RS256,
                    Algorithm::RS384,
                    Algorithm::RS512,
                    Algorithm::PS256,
                    Algorithm::PS384,
                    Algorithm::PS512,
                ],
            })
        }
        _ => Err(JwtSvidError::InvalidAuthority(
            "unsupported JWT authority key type",
        )),
    }
}

struct EcCurve {
    jwk_name: &'static str,
    coordinate_bytes: usize,
    alg: Algorithm,
}

/// Resolve the named curve from the SPKI algorithm parameters.
///
/// The curve is taken from the OID, not inferred from the coordinate length:
/// brainpoolP256r1 has the same 32-byte coordinates as P-256 and must not be
/// silently verified as `ES256`.
fn ec_curve(spki: &SubjectPublicKeyInfo<'_>) -> Result<EcCurve, JwtSvidError> {
    let parameters = spki.algorithm.parameters.as_ref().ok_or(
        JwtSvidError::InvalidAuthority("JWT authority EC public key names no curve"),
    )?;
    if parameters.tag() != Tag::Oid {
        return Err(JwtSvidError::InvalidAuthority(
            "JWT authority EC curve parameter is not an OID",
        ));
    }
    let oid = parameters.as_bytes();
    if oid == OID_BYTES_P256 {
        Ok(EcCurve {
            jwk_name: "P-256",
            coordinate_bytes: 32,
            alg: Algorithm::ES256,
        })
    } else if oid == OID_BYTES_P384 {
        Ok(EcCurve {
            jwk_name: "P-384",
            coordinate_bytes: 48,
            alg: Algorithm::ES384,
        })
    } else {
        Err(JwtSvidError::InvalidAuthority(
            "unsupported JWT authority EC curve",
        ))
    }
}

/// DER INTEGERs carry a leading `0x00` when the high bit is set; JWK `n` / `e`
/// are unsigned big-endian with no such padding (RFC 7518 §6.3.1).
fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let first_significant = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len());
    &bytes[first_significant..]
}
