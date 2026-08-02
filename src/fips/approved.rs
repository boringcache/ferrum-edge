//! Approved SHA-2 and HMAC-SHA-2 primitives, backed by the selected module.
//!
//! # Why this module exists
//!
//! SHA-2 (FIPS 180-4) and HMAC (FIPS 198-1) are approved *algorithms*, but an
//! approved algorithm computed by an unvalidated implementation is still
//! outside the module boundary. Ferrum's security-relevant digests and MACs
//! previously ran on the RustCrypto `sha2`/`hmac` crates, which the selected
//! validated module does not cover and which no amount of TLS-provider
//! switching reaches. Routing them here puts them inside the boundary on a
//! `fips` build and changes nothing on an ordinary one.
//!
//! # Scope
//!
//! This covers the operations that are load-bearing for an authentication,
//! integrity, or confidentiality control: request MAC verification, password
//! MACs, certificate and JWK thumbprints, PKCE, DPoP, SigV4 signing, keyed
//! redaction, replay/partition keying, and workload attestation. Digests that
//! are *not* a security service — cache keys, deduplication keys, ETags,
//! configuration-drift digests, xDS nonces — deliberately stay on RustCrypto
//! and are recorded as [`crate::fips::inventory::Disposition::OutsideBoundary`]
//! with that rationale, rather than being relabelled approved.
//!
//! # API shape
//!
//! Deliberately a drop-in for the `sha2::Digest` / `hmac::Mac` subset the
//! migrated call sites used (`new`, `digest`, `update`, `finalize`,
//! `new_from_slice`, `into_bytes`). Keeping the shape identical is what made
//! the migration a mechanical, reviewable substitution rather than a rewrite of
//! every authentication path.

use super::backend::{digest, hmac};

/// SHA-256, computed by the selected cryptographic module.
#[derive(Clone)]
pub struct Sha256(digest::Context);

impl Sha256 {
    /// Start an incremental SHA-256 computation.
    pub fn new() -> Self {
        Self(digest::Context::new(&digest::SHA256))
    }

    /// Absorb more input.
    pub fn update(&mut self, data: impl AsRef<[u8]>) {
        self.0.update(data.as_ref());
    }

    /// Finish and return the 32-byte digest.
    pub fn finalize(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(self.0.finish().as_ref());
        out
    }

    /// One-shot SHA-256.
    pub fn digest(data: impl AsRef<[u8]>) -> [u8; 32] {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

/// SHA-512, computed by the selected cryptographic module.
#[derive(Clone)]
pub struct Sha512(digest::Context);

impl Sha512 {
    /// Start an incremental SHA-512 computation.
    pub fn new() -> Self {
        Self(digest::Context::new(&digest::SHA512))
    }

    /// Absorb more input.
    pub fn update(&mut self, data: impl AsRef<[u8]>) {
        self.0.update(data.as_ref());
    }

    /// Finish and return the 64-byte digest.
    pub fn finalize(self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out.copy_from_slice(self.0.finish().as_ref());
        out
    }

    /// One-shot SHA-512.
    pub fn digest(data: impl AsRef<[u8]>) -> [u8; 64] {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }
}

impl Default for Sha512 {
    fn default() -> Self {
        Self::new()
    }
}

/// Returned by `new_from_slice` for API compatibility with `hmac::Mac`.
///
/// HMAC admits a key of any length, so no construction below actually produces
/// this. It exists so the migrated call sites keep their `let Ok(mut mac) = …
/// else { … }` fallback rather than growing an `unwrap` on the request path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidKeyLength;

impl std::fmt::Display for InvalidKeyLength {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid HMAC key length")
    }
}

impl std::error::Error for InvalidKeyLength {}

/// A finished MAC tag.
///
/// Wrapped rather than returned bare so the migrated `finalize().into_bytes()`
/// spelling still reads the same at every call site.
#[derive(Clone, Copy)]
pub struct MacOutput<const N: usize>([u8; N]);

impl<const N: usize> MacOutput<N> {
    /// The raw tag.
    pub fn into_bytes(self) -> [u8; N] {
        self.0
    }
}

impl<const N: usize> AsRef<[u8]> for MacOutput<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// A pre-derived HMAC-SHA-256 key, reusable across many MACs.
///
/// Keying is the expensive step, so a caller that MACs many small values under
/// one key (`ai_pii`'s per-match redaction digests) holds this and calls
/// [`HmacSha256Key::begin`] per value.
///
/// This is a separate type on purpose. `aws-lc-rs`'s `hmac::Context` is not
/// `Clone` where `ring`'s is, so a `Clone` on the *in-progress* MAC could not
/// be implemented on both backends without either silently dropping absorbed
/// bytes on the FIPS build or buffering the whole message. Splitting the key
/// from the context makes the reusable thing explicitly the key — which is the
/// only thing the caller wanted to reuse.
#[derive(Clone)]
pub struct HmacSha256Key(hmac::Key);

impl HmacSha256Key {
    /// Derive a reusable HMAC-SHA-256 key.
    pub fn new_from_slice(key: &[u8]) -> Result<Self, InvalidKeyLength> {
        Ok(Self(hmac::Key::new(hmac::HMAC_SHA256, key)))
    }

    /// Start a fresh MAC under this key.
    pub fn begin(&self) -> HmacSha256 {
        HmacSha256(hmac::Context::with_key(&self.0))
    }
}

/// HMAC-SHA-256, computed by the selected cryptographic module.
pub struct HmacSha256(hmac::Context);

impl HmacSha256 {
    /// Key an HMAC-SHA-256 instance.
    pub fn new_from_slice(key: &[u8]) -> Result<Self, InvalidKeyLength> {
        Ok(Self(hmac::Context::with_key(&hmac::Key::new(
            hmac::HMAC_SHA256,
            key,
        ))))
    }

    /// Absorb more input.
    pub fn update(&mut self, data: impl AsRef<[u8]>) {
        self.0.update(data.as_ref());
    }

    /// Finish and return the 32-byte tag.
    pub fn finalize(self) -> MacOutput<32> {
        let mut out = [0u8; 32];
        out.copy_from_slice(self.0.sign().as_ref());
        MacOutput(out)
    }
}

/// HMAC-SHA-512, computed by the selected cryptographic module.
pub struct HmacSha512(hmac::Context);

impl HmacSha512 {
    /// Key an HMAC-SHA-512 instance.
    pub fn new_from_slice(key: &[u8]) -> Result<Self, InvalidKeyLength> {
        Ok(Self(hmac::Context::with_key(&hmac::Key::new(
            hmac::HMAC_SHA512,
            key,
        ))))
    }

    /// Absorb more input.
    pub fn update(&mut self, data: impl AsRef<[u8]>) {
        self.0.update(data.as_ref());
    }

    /// Finish and return the 64-byte tag.
    pub fn finalize(self) -> MacOutput<64> {
        let mut out = [0u8; 64];
        out.copy_from_slice(self.0.sign().as_ref());
        MacOutput(out)
    }
}
