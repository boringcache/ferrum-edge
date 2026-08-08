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

/// DER content bytes of the named-curve OIDs we accept.
/// `1.2.840.10045.3.1.7` — NIST P-256 / prime256v1.
const OID_BYTES_P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
/// `1.3.132.0.34` — NIST P-384 / secp384r1.
const OID_BYTES_P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];

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

/// Build the JWKS document for one trust domain's published authorities.
///
/// Fails closed when the authority set is empty (an empty JWKS is not a
/// conformant "no authorities" signal — SPIFFE Workload API §6.2.2 requires
/// at least the local trust-domain bundle), when any bound is exceeded, when
/// two authorities share a key id, or when any authority's material does not
/// parse into a supported public key. Malformed authorities are never
/// published alongside good ones — the whole document is refused.
pub fn jwks_document(authorities: &[PublishedJwtAuthority]) -> Result<Vec<u8>, JwtSvidError> {
    if authorities.is_empty() {
        return Err(JwtSvidError::NoJwtAuthority(
            "this trust domain publishes no JWT authorities",
        ));
    }
    if authorities.len() > MAX_JWT_AUTHORITIES_PER_TRUST_DOMAIN {
        return Err(JwtSvidError::InvalidAuthority(
            "too many JWT authorities published for one trust domain",
        ));
    }

    let mut keys: Vec<Value> = Vec::with_capacity(authorities.len());
    let mut seen_key_ids: Vec<&str> = Vec::with_capacity(authorities.len());
    for authority in authorities {
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
