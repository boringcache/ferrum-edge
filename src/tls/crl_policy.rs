//! Shared Certificate Revocation List (CRL) admission and verifier policy.
//!
//! Issues #4297 and #4298. Every CRL-enabled verifier Ferrum builds — frontend
//! and admin mTLS, the mesh operator-CA path, backend server verification, the
//! HTTP/3 client-certificate verifier, SPIFFE peer verification, DTLS client
//! authentication, and the rustls LDAP / logging sinks — routes through the two
//! `apply_*` helpers below, so one decision covers every surface and a new
//! verifier cannot quietly adopt a weaker posture.
//!
//! The policy has three parts:
//!
//! - **Full-chain revocation.** rustls checks the revocation status of every
//!   non-trust-anchor certificate in the built chain by default. Ferrum no
//!   longer narrows that to the presented leaf, so a revoked issuing
//!   intermediate stops the certificates it signed instead of continuing to
//!   authenticate them (issue #4298).
//! - **Unknown status stays tolerated.** `allow_unknown_revocation_status()` is
//!   retained deliberately. A configured CRL list is an operator's list of
//!   issuers to police, not a completeness claim about every trusted anchor, so
//!   a chain that no configured CRL is authoritative for is still accepted.
//!   Removing this would fail closed on every public-CA chain the moment a
//!   single private CRL is configured.
//! - **Validity windows are enforced.** `enforce_revocation_expiration()` makes
//!   rustls refuse a chain whose authoritative CRL has reached `nextUpdate`, so
//!   a CRL that expires while the process is running stops authorizing new
//!   handshakes rather than being trusted indefinitely (issue #4297).
//!
//! [`validate_crl_windows`] applies the temporal half of that policy at
//! admission — startup, config load, live reload, and admin-managed
//! create/update — using exactly the boundary semantics rustls applies at
//! handshake time, so a candidate that admission accepts is one the handshake
//! path can also use.

use rustls::client::ServerCertVerifierBuilder;
use rustls::pki_types::CertificateRevocationListDer;
use rustls::server::ClientCertVerifierBuilder;
use x509_parser::prelude::FromDer;
use x509_parser::revocation_list::CertificateRevocationList;
use x509_parser::time::ASN1Time;

/// Apply the shared CRL policy to a client-certificate verifier builder.
///
/// An empty `crls` list leaves the builder untouched: revocation checking stays
/// off entirely, which is the unchanged behavior of a deployment with no CRL
/// source configured.
pub fn apply_client_crl_policy(
    builder: ClientCertVerifierBuilder,
    crls: &[CertificateRevocationListDer<'static>],
) -> ClientCertVerifierBuilder {
    if crls.is_empty() {
        return builder;
    }
    builder
        .with_crls(crls.iter().cloned())
        .allow_unknown_revocation_status()
        .enforce_revocation_expiration()
}

/// Apply the shared CRL policy to a server-certificate verifier builder.
///
/// An empty `crls` list leaves the builder untouched, matching
/// [`apply_client_crl_policy`].
pub fn apply_server_crl_policy(
    builder: ServerCertVerifierBuilder,
    crls: &[CertificateRevocationListDer<'static>],
) -> ServerCertVerifierBuilder {
    if crls.is_empty() {
        return builder;
    }
    builder
        .with_crls(crls.iter().cloned())
        .allow_unknown_revocation_status()
        .enforce_revocation_expiration()
}

/// Why a candidate CRL record was refused admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrlWindowRejection {
    /// The record is not a parseable X.509 CRL, or carries trailing bytes.
    Unparseable,
    /// `thisUpdate` is later than the admission instant.
    NotYetValid,
    /// `nextUpdate` is absent, so the record declares no validity window.
    MissingNextUpdate,
    /// The admission instant has reached `nextUpdate`.
    Expired,
}

impl CrlWindowRejection {
    /// Operator-facing reason for the refusal.
    ///
    /// Deliberately free of CRL contents, issuer names, serial numbers, and
    /// validity timestamps: a refusal diagnostic must not widen the TLS
    /// redaction contract beyond the record index and the already-redacted
    /// source display id its caller supplies.
    pub fn reason(self) -> &'static str {
        match self {
            Self::Unparseable => "is not a parseable X.509 CRL",
            Self::NotYetValid => "is not yet valid (thisUpdate is in the future)",
            Self::MissingNextUpdate => {
                "omits the required nextUpdate field, so its validity window cannot be enforced"
            }
            Self::Expired => "has expired (nextUpdate has passed)",
        }
    }
}

/// Classify one CRL record's validity window against `now_unix`.
///
/// Boundary semantics, chosen to match rustls/webpki exactly so admission and
/// handshake enforcement can never disagree about the same bytes:
///
/// - `thisUpdate > now` is refused; `thisUpdate == now` is accepted.
/// - A missing `nextUpdate` is refused. RFC 5280 §5.1.2.5 requires conforming
///   issuers to emit it, webpki refuses to parse a CRL without it, and a record
///   that declares no expiry cannot have an expiry enforced — so Ferrum fails
///   closed at admission rather than letting the verifier build fail later with
///   an opaque DER error.
/// - `now >= nextUpdate` is refused; `now == nextUpdate - 1` is accepted. This
///   is webpki's own `time >= next_update` test, so a CRL admitted one second
///   before expiry is still one the verifier accepts.
pub fn classify_crl_window(
    crl: &CertificateRevocationListDer<'_>,
    now_unix: i64,
) -> Result<(), CrlWindowRejection> {
    let Ok((remaining, parsed)) = CertificateRevocationList::from_der(crl.as_ref()) else {
        return Err(CrlWindowRejection::Unparseable);
    };
    if !remaining.is_empty() {
        return Err(CrlWindowRejection::Unparseable);
    }
    if parsed.last_update().timestamp() > now_unix {
        return Err(CrlWindowRejection::NotYetValid);
    }
    let Some(next_update) = parsed.next_update() else {
        return Err(CrlWindowRejection::MissingNextUpdate);
    };
    if now_unix >= next_update.timestamp() {
        return Err(CrlWindowRejection::Expired);
    }
    Ok(())
}

/// Validate every CRL in a candidate list against `now_unix`.
///
/// Atomic by construction: the first unusable record refuses the whole
/// candidate, so a caller can never publish the usable subset of a partially
/// invalid multi-CRL source. `display_source` must already be the redacted
/// source display id.
///
/// `now_unix` is a parameter so deterministic tests can place a candidate on
/// either side of a boundary without sleeping.
pub fn validate_crl_windows_at(
    crls: &[CertificateRevocationListDer<'static>],
    display_source: &str,
    now_unix: i64,
) -> Result<(), String> {
    for (index, crl) in crls.iter().enumerate() {
        if let Err(rejection) = classify_crl_window(crl, now_unix) {
            return Err(format!(
                "CRL record #{} in '{}' {}",
                index + 1,
                display_source,
                rejection.reason()
            ));
        }
    }
    Ok(())
}

/// [`validate_crl_windows_at`] against the current system time.
pub fn validate_crl_windows(
    crls: &[CertificateRevocationListDer<'static>],
    display_source: &str,
) -> Result<(), String> {
    validate_crl_windows_at(crls, display_source, ASN1Time::now().timestamp())
}
