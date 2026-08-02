//! Approved key strengths and forms for operator-controlled key material.
//!
//! # Why this exists separately from the provider
//!
//! Selecting the AWS-LC FIPS module decides *which implementation* computes a
//! signature. It does not, on its own, decide which **keys** Ferrum will agree
//! to serve with. Those are two different gates, and only one of them is the
//! provider's:
//!
//! - The rustls FIPS provider does reject a non-approved *algorithm* — it will
//!   not negotiate a suite, group, or signature scheme outside the approved
//!   set, and `fips::policy::check_tls_policy` re-asserts that over the
//!   constructed policy.
//! - It does **not** uniformly reject an approved algorithm used with an
//!   under-strength key. An RSA-1024 leaf certificate is `rsaEncryption` with
//!   `rsa_pkcs1_sha256`, both nominally approved; SP 800-131A Rev. 2 disallows
//!   the 1024-bit *key*, not the scheme. Depending on the construction path
//!   that key can reach a handshake, or it can fail later with an opaque
//!   provider error that names nothing the operator can act on.
//!
//! So this module is the Ferrum-enforced half, applied at admission: at the
//! single PEM certificate-loading boundary
//! ([`crate::tls::parse_pem_certificate_bundle`]) and at the JWKS key-admission
//! boundary. Both are construction/reload paths, never the request hot path.
//!
//! # What is checked, and on what material
//!
//! Only **public** key material is inspected: the `SubjectPublicKeyInfo` of a
//! certificate, or the public components of a JWK. Private keys keep flowing
//! through the existing secure loading boundary
//! ([`crate::tls::parse_pem_private_key`]) untouched — this module never parses,
//! copies, or logs private-key bytes. That is deliberate: a private key's
//! strength is pinned by the certificate it is paired with, so the public side
//! is both sufficient and the safe place to look.
//!
//! # Diagnostics
//!
//! Every diagnostic names the fixed Ferrum surface label, the key algorithm
//! family, and the observed strength in bits. It never interpolates a file
//! path, a URL, a subject name, or any key bytes. The surface label is bounded
//! to [`MAX_SURFACE_LABEL_CHARS`] because a few callers derive it from a
//! configuration-supplied source kind.

use x509_parser::prelude::{FromDer, X509Certificate};
use x509_parser::public_key::PublicKey;

/// Minimum approved RSA modulus size, in bits.
///
/// SP 800-131A Rev. 2 disallows RSA below 2048 bits for signature generation
/// and key transport. 1024-bit RSA has been disallowed since 2013.
pub const MIN_RSA_MODULUS_BITS: usize = 2048;

/// Largest RSA modulus Ferrum will admit, in bits.
///
/// Not a security floor — a bound. A certificate carrying a 64 Kib modulus is
/// a denial-of-service vector against every handshake that uses it, and no
/// approved profile needs one.
pub const MAX_RSA_MODULUS_BITS: usize = 8192;

/// Approved elliptic-curve field sizes, in bits: P-256, P-384, P-521.
///
/// These are the NIST prime curves of FIPS 186-5 / SP 800-186. Curve25519 and
/// Curve448 are absent: they are not approved for the ECDSA/ECDH schemes in
/// SP 800-56A, which is also why `fips::policy::FIPS_DEFAULT_KX_GROUPS` omits
/// X25519.
///
/// P-521 is admitted for *certificates* even though `ES512` is refused for
/// JWS. That is not an inconsistency: the JWS exclusion is about the
/// `jsonwebtoken` backend's implementation contract, while a P-521 certificate
/// is handled by the rustls provider, which classifies `secp521r1` itself.
pub const APPROVED_EC_FIELD_BITS: &[usize] = &[256, 384, 521];

/// Upper bound on how much of a surface label a diagnostic reproduces.
pub const MAX_SURFACE_LABEL_CHARS: usize = 64;

/// Truncate a caller-supplied surface label to a bounded, single-line form.
fn bounded_label(label: &str) -> String {
    let sanitized: String = label
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_SURFACE_LABEL_CHARS)
        .collect();
    if sanitized.is_empty() {
        "configured key material".to_string()
    } else {
        sanitized
    }
}

/// Admit one certificate's public key, when FIPS mode is enforced.
///
/// `surface_label` is the fixed Ferrum vocabulary label the caller already uses
/// for this material ("frontend TLS certificate", "backend CA bundle", …).
pub fn check_certificate_public_key(der: &[u8], surface_label: &str) -> Result<(), String> {
    if !super::is_enforcing() {
        return Ok(());
    }
    check_certificate_public_key_enforced(der, surface_label)
}

/// The enforced half of [`check_certificate_public_key`].
///
/// Split out so the policy is directly testable on an ordinary build, where
/// enforcement can never be established at runtime — the same split
/// `fips::policy` uses.
pub fn check_certificate_public_key_enforced(
    der: &[u8],
    surface_label: &str,
) -> Result<(), String> {
    let label = bounded_label(surface_label);

    // A certificate that does not parse is not this check's business: the
    // caller's own PEM/DER admission already reports it with the record index
    // and source it knows about. Re-reporting it here would produce two
    // diagnostics for one fault and would let a parse quirk masquerade as a
    // key-strength rejection.
    let Ok((_, certificate)) = X509Certificate::from_der(der) else {
        return Ok(());
    };

    let spki = certificate.public_key();
    let Ok(parsed) = spki.parsed() else {
        return Err(format!(
            "{label}: the certificate's public key could not be classified against the approved \
             key set, so it is refused while FIPS mode is enforced. Approved: RSA \
             {MIN_RSA_MODULUS_BITS}-{MAX_RSA_MODULUS_BITS} bits, or ECDSA over P-256/P-384/P-521."
        ));
    };

    match parsed {
        PublicKey::RSA(rsa) => check_rsa_modulus_bits(rsa.key_size(), &label),
        PublicKey::EC(point) => {
            let bits = point.key_size();
            if APPROVED_EC_FIELD_BITS.contains(&bits) {
                Ok(())
            } else if bits == 0 {
                // `ECPoint::key_size()` returns 0 for a point whose leading
                // octet is neither the uncompressed (0x04) nor a compressed
                // (0x02/0x03) form — including the RFC 5480 "hybrid" forms and
                // anything malformed. Refuse the form explicitly rather than
                // guessing a curve from a length.
                Err(format!(
                    "{label}: the certificate carries an elliptic-curve public key in a point \
                     encoding Ferrum does not admit while FIPS mode is enforced. Use an \
                     uncompressed or compressed SEC1 point on P-256, P-384, or P-521."
                ))
            } else {
                Err(format!(
                    "{label}: the certificate's elliptic-curve public key is over a {bits}-bit \
                     field, which is not an approved curve while FIPS mode is enforced. Approved \
                     curves: P-256, P-384, P-521."
                ))
            }
        }
        // Everything else is a definite "no", not an unclassified maybe. DSA is
        // withdrawn for signature generation by FIPS 186-5; the GOST curves are
        // not in any approved set; `Unknown` covers Ed25519/Ed448/X25519 and
        // any future algorithm this build has not classified.
        PublicKey::DSA(_) => Err(format!(
            "{label}: the certificate carries a DSA public key. FIPS 186-5 withdrew DSA for \
             signature generation, so it is refused while FIPS mode is enforced. Use RSA \
             (>= {MIN_RSA_MODULUS_BITS} bits) or ECDSA over P-256/P-384/P-521."
        )),
        PublicKey::GostR3410(_) | PublicKey::GostR3410_2012(_) => Err(format!(
            "{label}: the certificate carries a GOST R 34.10 public key, which is not in an \
             approved algorithm set and is refused while FIPS mode is enforced."
        )),
        PublicKey::Unknown(_) => Err(format!(
            "{label}: the certificate's public-key algorithm is not one Ferrum routes through the \
             selected cryptographic module (this includes Ed25519, Ed448, and X25519 keys), so it \
             is refused while FIPS mode is enforced. Use RSA (>= {MIN_RSA_MODULUS_BITS} bits) or \
             ECDSA over P-256/P-384/P-521."
        )),
    }
}

/// Shared RSA strength rule for certificates and JWKs.
///
/// Public and ungated: it is a pure predicate over an already-measured bit
/// count, so it is the unit both admission paths agree on and the one a test
/// can exercise without minting an under-strength key. The mode gate lives on
/// the callers above.
pub fn check_rsa_modulus_bits(bits: usize, label: &str) -> Result<(), String> {
    if bits == 0 {
        return Err(format!(
            "{label}: the RSA public key's modulus could not be measured, so its strength cannot \
             be established and it is refused while FIPS mode is enforced."
        ));
    }
    if bits < MIN_RSA_MODULUS_BITS {
        return Err(format!(
            "{label}: the RSA public key is {bits} bits. FIPS mode requires at least \
             {MIN_RSA_MODULUS_BITS} bits (SP 800-131A Rev. 2 disallows shorter RSA keys for \
             signature generation and key transport)."
        ));
    }
    if bits > MAX_RSA_MODULUS_BITS {
        return Err(format!(
            "{label}: the RSA public key is {bits} bits, above the {MAX_RSA_MODULUS_BITS}-bit \
             admission ceiling. An oversized modulus is a handshake denial-of-service vector and \
             no approved profile requires one."
        ));
    }
    Ok(())
}

/// Admit a JWK RSA modulus, when FIPS mode is enforced.
///
/// `modulus` is the decoded, unsigned big-endian `n` member of an RFC 7518 RSA
/// JWK — public material only. JWKs are fetched from an operator-configured
/// issuer, so a weak signing key admitted here would let that issuer's
/// compromise become Ferrum's authentication failure.
pub fn check_jwk_rsa_modulus(modulus: &[u8]) -> Result<(), String> {
    if !super::is_enforcing() {
        return Ok(());
    }
    check_jwk_rsa_modulus_enforced(modulus)
}

/// The enforced half of [`check_jwk_rsa_modulus`].
pub fn check_jwk_rsa_modulus_enforced(modulus: &[u8]) -> Result<(), String> {
    // RFC 7518 §6.3.1.1 requires `n` to be the unsigned big-endian octets with
    // no leading zero padding, but an issuer that pads anyway must not be
    // credited with the extra byte, and one that pads *short* must not be
    // rejected for a byte it legitimately omitted.
    let significant = modulus
        .iter()
        .position(|byte| *byte != 0)
        .map(|start| &modulus[start..])
        .unwrap_or(&[]);
    check_rsa_modulus_bits(significant.len() * 8, "JWKS RSA signing key")
}

/// Approved JWK elliptic curves, as spelled in the RFC 7518 `crv` member.
///
/// P-521 is absent because its only JWS use is `ES512`, which
/// [`super::policy::APPROVED_JWT_ALGORITHMS`] refuses — see that constant for
/// why. Admitting the curve while refusing every algorithm that can use it
/// would just move the failure later.
pub const APPROVED_JWK_EC_CURVES: &[&str] = &["P-256", "P-384"];

/// Admit a JWK elliptic curve, when FIPS mode is enforced.
pub fn check_jwk_ec_curve(curve: &str) -> Result<(), String> {
    if !super::is_enforcing() {
        return Ok(());
    }
    check_jwk_ec_curve_enforced(curve)
}

/// The enforced half of [`check_jwk_ec_curve`].
pub fn check_jwk_ec_curve_enforced(curve: &str) -> Result<(), String> {
    if APPROVED_JWK_EC_CURVES
        .iter()
        .any(|approved| approved.eq_ignore_ascii_case(curve.trim()))
    {
        return Ok(());
    }
    // `crv` is a fixed RFC 7518 registry vocabulary, so naming the observed
    // value is actionable and discloses nothing.
    let observed = bounded_label(curve);
    Err(format!(
        "JWKS EC signing key names curve `{observed}`, which is not admitted while FIPS mode is \
         enforced. Approved: {}.",
        APPROVED_JWK_EC_CURVES.join(", ")
    ))
}
