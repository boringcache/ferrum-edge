//! SPIFFE JWT-SVID mint / validate / bundle support.
//!
//! This module owns everything the SPIFFE Workload API needs for the three
//! JWT RPCs (`FetchJWTSVID`, `FetchJWTBundles`, `ValidateJWTSVID`) while
//! staying independent of the gRPC layer so it can be unit-tested directly:
//!
//! - [`authority`] — [`LocalJwtAuthority`], the process-local JWT signing
//!   authority used by CA backends that actually own signing material
//!   (today: [`crate::identity::ca::internal::InternalCa`]). It generates an
//!   ES256 key at construction, signs bounded short-lived JWT-SVIDs, and
//!   rotates with a documented verification overlap.
//! - [`jwks`] — conversion between the CA-published
//!   [`PublishedJwtAuthority`](crate::identity::ca::PublishedJwtAuthority)
//!   (SPKI PEM + key id) and both a JWKS document and a `jsonwebtoken`
//!   [`DecodingKey`](jsonwebtoken::DecodingKey).
//! - [`validate`] — fail-closed JWT-SVID validation.
//!
//! ## Security posture
//!
//! - **The subject is never caller-selected.** The Workload API server mints
//!   only for the attested workload identity; a caller-supplied
//!   `JWTSVIDRequest.spiffe_id` is accepted only when it is byte-equal to the
//!   attested SPIFFE ID.
//! - **Only asymmetric algorithms.** Ferrum mints ES256 and validates against
//!   the algorithm family implied by the *authority's own public key*, never
//!   the one advertised in the token header. `alg: none` cannot even be
//!   deserialized by `jsonwebtoken` (there is no `Algorithm::None`), and the
//!   HMAC family is never in an allowed set, so both HMAC substitution and
//!   algorithm confusion fail closed.
//! - **Errors never reflect hostile input.** Every rejection reason is a fixed
//!   `&'static str`; token bytes, claim values, and key material never appear
//!   in an error, a log line, or a `Debug` rendering.
//! - **Everything is bounded.** Audience count/size, token size, per-segment
//!   size, claim-document size, authority count, key-id size, PEM size, and
//!   the JWKS document itself all have hard caps checked before any parse or
//!   publication.

pub mod authority;
pub mod jwks;
mod strict_json;
pub mod validate;

pub use authority::{
    JwtSvidSigner, LocalJwtAuthority, LocalJwtAuthorityConfig, MintedJwtSvid, SharedJwtSvidSigner,
};
pub use jwks::{decoding_key_for_authority, jwks_document, published_authority_key_id};
pub use validate::{ValidatedJwtSvid, validate_jwt_svid};

pub(crate) use strict_json::parse_strict_json_object;

/// Maximum number of audiences a single `FetchJWTSVID` request may name.
pub const MAX_JWT_SVID_AUDIENCES: usize = 32;
/// Maximum byte length of one audience value.
pub const MAX_JWT_SVID_AUDIENCE_BYTES: usize = 512;
/// Maximum accepted serialized JWT-SVID size. SPIFFE JWT-SVIDs are small;
/// anything larger is a resource-exhaustion attempt, not a real token.
pub const MAX_JWT_SVID_TOKEN_BYTES: usize = 8 * 1024;
/// Maximum decoded size of a single JOSE segment (header or claims).
pub const MAX_JWT_SVID_SEGMENT_BYTES: usize = 4 * 1024;
/// Maximum number of JWT authorities published for one trust domain.
pub const MAX_JWT_AUTHORITIES_PER_TRUST_DOMAIN: usize = 16;
/// Maximum byte length of a JWT authority key id (`kid`).
pub const MAX_JWT_KEY_ID_BYTES: usize = 256;
/// Maximum byte length of an authority's SPKI PEM document.
pub const MAX_JWT_PUBLIC_KEY_PEM_BYTES: usize = 8 * 1024;
/// Maximum serialized size of one trust domain's JWKS document.
pub const MAX_JWKS_DOCUMENT_BYTES: usize = 64 * 1024;
/// Maximum number of trust domains in one `FetchJWTBundles` response.
pub const MAX_JWT_BUNDLE_TRUST_DOMAINS: usize = 64;
/// Maximum serialized size of the claims document returned by
/// `ValidateJWTSVID`.
pub const MAX_JWT_CLAIMS_JSON_BYTES: usize = 8 * 1024;
/// Default JWT-SVID lifetime. Deliberately short — a JWT-SVID is a bearer
/// credential with no revocation channel.
pub const DEFAULT_JWT_SVID_TTL_SECS: u64 = 300;
/// Hard ceiling on JWT-SVID lifetime. Also the basis for the rotation
/// verification overlap: a token minted one instant before a rotation stays
/// verifiable for at most this long.
pub const MAX_JWT_SVID_TTL_SECS: u64 = 3600;
/// Clock-skew leeway applied to `exp` / `nbf` / `iat` validation and added on
/// top of [`MAX_JWT_SVID_TTL_SECS`] when computing the rotation overlap.
pub const JWT_SVID_CLOCK_SKEW_LEEWAY_SECS: u64 = 60;
/// Default lifetime of a local JWT signing key before it is rotated out.
pub const DEFAULT_JWT_KEY_LIFETIME_SECS: u64 = 24 * 3600;

/// Errors raised by the JWT-SVID mint / validate / bundle paths.
///
/// Every variant except [`JwtSvidError::Internal`] carries a fixed
/// `&'static str`: rejection reasons must never echo caller-supplied token
/// bytes, claim values, audiences, or key material back to the caller.
/// `Internal` is only ever constructed from Ferrum-authored text.
#[derive(Debug, thiserror::Error)]
pub enum JwtSvidError {
    /// The request itself is malformed (audience list, requested subject,
    /// oversized input). Maps to gRPC `INVALID_ARGUMENT`.
    #[error("JWT-SVID request rejected: {0}")]
    InvalidRequest(&'static str),
    /// The presented token failed a structural, cryptographic, or claim
    /// check. Maps to gRPC `INVALID_ARGUMENT`.
    #[error("JWT-SVID rejected: {0}")]
    InvalidToken(&'static str),
    /// The caller asked for an identity it is not entitled to. Maps to gRPC
    /// `PERMISSION_DENIED`.
    #[error("JWT-SVID request denied: {0}")]
    Denied(&'static str),
    /// The active backend has no JWT signing authority at all. Maps to gRPC
    /// `UNIMPLEMENTED` — this is the honest "this backend cannot do JWT-SVID"
    /// signal, distinct from "there are zero trusted authorities".
    #[error("JWT-SVID unsupported: {0}")]
    NoJwtAuthority(&'static str),
    /// Published authority material is malformed or out of bounds and must
    /// not be republished. Maps to gRPC `INTERNAL`.
    #[error("JWT authority material rejected: {0}")]
    InvalidAuthority(&'static str),
    /// Ferrum-side failure. Maps to gRPC `INTERNAL`.
    #[error("JWT-SVID internal error: {0}")]
    Internal(String),
}

/// Validate and canonicalize a requested audience list.
///
/// SPIFFE Workload API §5.3: `FetchJWTSVID` requires at least one audience.
/// We additionally require every entry to be non-empty and free of control
/// characters, bound the count and each entry's length, and collapse exact
/// duplicates while preserving first-occurrence order so the minted `aud`
/// array is canonical.
pub fn canonical_audiences(requested: &[String]) -> Result<Vec<String>, JwtSvidError> {
    if requested.is_empty() {
        return Err(JwtSvidError::InvalidRequest(
            "at least one audience is required",
        ));
    }
    if requested.len() > MAX_JWT_SVID_AUDIENCES {
        return Err(JwtSvidError::InvalidRequest("too many audiences requested"));
    }
    let mut canonical: Vec<String> = Vec::with_capacity(requested.len());
    for audience in requested {
        validate_audience_value(audience)?;
        if !canonical.iter().any(|existing| existing == audience) {
            canonical.push(audience.clone());
        }
    }
    // Unreachable while `requested` is non-empty and every entry is accepted,
    // but keep the post-condition explicit: an empty `aud` array must never
    // be minted.
    if canonical.is_empty() {
        return Err(JwtSvidError::InvalidRequest(
            "at least one audience is required",
        ));
    }
    Ok(canonical)
}

/// Bounds and character checks shared by mint and validate.
pub fn validate_audience_value(audience: &str) -> Result<(), JwtSvidError> {
    if audience.is_empty() {
        return Err(JwtSvidError::InvalidRequest("audience must not be empty"));
    }
    if audience.len() > MAX_JWT_SVID_AUDIENCE_BYTES {
        return Err(JwtSvidError::InvalidRequest("audience is too long"));
    }
    if audience.trim().is_empty() {
        return Err(JwtSvidError::InvalidRequest(
            "audience must not be whitespace only",
        ));
    }
    if audience.chars().any(|c| c.is_control()) {
        return Err(JwtSvidError::InvalidRequest(
            "audience must not contain control characters",
        ));
    }
    Ok(())
}
