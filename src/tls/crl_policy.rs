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
//!
//! [`EnforcedCrlSet`] carries an admitted list plus the generation it was
//! published under (issue #5574). The mesh inbound SPIFFE peer verifier reads
//! that shared slot on every handshake rather than a snapshot captured when its
//! `ServerConfig` was built, so an operator's rotation reaches the next peer
//! without rebinding the listener, and the generation is the other half of its
//! verifier-cache identity beside the SVID source. The same records are
//! compiled into the HBONE admission fence's in-force anchors, which is what
//! re-judges peers whose established inbound session is never re-handshaked;
//! publication for both surfaces goes through
//! `ProxyState::publish_mesh_inbound_crls`.

use std::sync::Arc;

use arc_swap::ArcSwap;
use rustls::client::ServerCertVerifierBuilder;
use rustls::pki_types::CertificateRevocationListDer;
use rustls::server::ClientCertVerifierBuilder;
use x509_parser::prelude::FromDer;
use x509_parser::revocation_list::CertificateRevocationList;
use x509_parser::time::ASN1Time;

use crate::tls::CrlList;

/// The CRL set a verifier surface ENFORCES right now, tagged with the
/// generation it was published under (issue #5574).
///
/// A plain [`CrlList`] answers "which records" but not "which publication",
/// and the verifier cache needs both: it keeps per-trust-domain chain verifiers
/// compiled from an SVID source AND a CRL set, and reuses them only while both
/// halves still match. Without the tag a rotation that changed no SVID material
/// would keep serving handshakes under the records the listener started with.
///
/// The bytes are shared, never copied: publishing a new generation is one
/// `Arc` store.
#[derive(Debug)]
pub struct EnforcedCrlSet {
    crls: CrlList,
    generation: u64,
}

impl EnforcedCrlSet {
    /// The records this generation enforces. Empty means revocation checking
    /// is off, which is the unchanged behavior of a deployment with no CRL
    /// source configured.
    pub fn crls(&self) -> &CrlList {
        &self.crls
    }

    /// The publication this set came from. Monotonic within a process; the
    /// first published set is generation 1, so `0` can never collide with a
    /// real generation.
    pub fn generation(&self) -> u64 {
        self.generation
    }
}

/// A hot-swappable [`EnforcedCrlSet`], read lock-free by verifiers and by the
/// admission fence's sweep.
pub type SharedEnforcedCrlSet = Arc<ArcSwap<EnforcedCrlSet>>;

/// The first generation of an enforced CRL set.
pub fn enforced_crl_set(crls: CrlList) -> SharedEnforcedCrlSet {
    Arc::new(ArcSwap::new(Arc::new(EnforcedCrlSet {
        crls,
        generation: 1,
    })))
}

/// Publish `crls` as the next generation of `slot`, or leave it untouched when
/// the records are byte-identical to the ones already enforced.
///
/// Returns `true` only when the enforced set actually changed. The comparison
/// is what keeps a periodic reload of an UNCHANGED CRL file from rebuilding
/// every cached chain verifier — and, through the admission fence, every live
/// tunnel's certificate path — for no decision at all.
///
/// This is deliberately a free function rather than a method on the slot: the
/// caller that owns the surface is the one place allowed to publish, and it
/// must recompile and re-check whatever the change implies. For the mesh
/// inbound set that caller is `HboneAdmissionFence::publish_inbound_admission_crls`,
/// reached through `ProxyState::publish_mesh_inbound_crls`; nothing else may
/// store into that slot.
pub fn publish_enforced_crl_set(slot: &SharedEnforcedCrlSet, crls: CrlList) -> bool {
    let current = slot.load();
    if crl_records_equal(current.crls(), &crls) {
        return false;
    }
    let generation = current.generation().saturating_add(1);
    slot.store(Arc::new(EnforcedCrlSet { crls, generation }));
    true
}

/// Whether two CRL candidate lists carry the same records in the same order.
///
/// Byte equality on the DER, not pointer equality: each reload parses the
/// source afresh, so an unchanged file always produces a different allocation.
///
/// Shared with the HBONE admission fence (issue #5574), which compares a
/// candidate against both the records the verifier enforces and the records the
/// anchors in force were compiled with. One implementation, so "unchanged" can
/// never mean two different things on the two surfaces.
pub(crate) fn crl_records_equal(
    left: &[CertificateRevocationListDer<'static>],
    right: &[CertificateRevocationListDer<'static>],
) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right.iter())
            .all(|(a, b)| a.as_ref() == b.as_ref())
}

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

    /// Fixed-cardinality class label for a refusal, for a diagnostic that must
    /// carry no record contents at all (issue #5574).
    ///
    /// Distinct from [`Self::reason`], which is prose for a message that already
    /// names a record index and a redacted source: this is the closed
    /// four-value set the admission fence puts on a structured field.
    pub fn class(self) -> &'static str {
        match self {
            Self::Unparseable => "unparseable",
            Self::NotYetValid => "not_yet_valid",
            Self::MissingNextUpdate => "missing_next_update",
            Self::Expired => "expired",
        }
    }
}

/// Whether every record in a candidate list is usable as an ENFORCED set right
/// now, reporting the first refusal's class (issue #5574).
///
/// The all-or-nothing form of [`validate_crl_windows`], for a caller that must
/// decide whether a candidate takes force rather than render an operator
/// message about a named source: the HBONE admission fence compiles the
/// enforced records into the anchors it judges live tunnels with, so a record
/// the verifier cannot use must not become the record the fence judges by. The
/// first unusable record refuses the whole candidate, exactly as at admission —
/// publishing the usable subset of a partially invalid source would silently
/// stop policing an issuer the operator listed.
pub(crate) fn usable_crl_records(
    crls: &[CertificateRevocationListDer<'static>],
) -> Result<(), &'static str> {
    let now_unix = ASN1Time::now().timestamp();
    for crl in crls {
        classify_crl_window(crl, now_unix).map_err(CrlWindowRejection::class)?;
    }
    Ok(())
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

/// The `nextUpdate` instant of one CRL record, as a Unix timestamp.
///
/// Sibling of [`classify_crl_window`] rather than a second parser: admission
/// and the lead-time warning must read the same field out of the same bytes,
/// so a record this returns `None` for is exactly one `classify_crl_window`
/// refuses (unparseable, or no declared `nextUpdate`).
pub fn crl_next_update_unix(crl: &CertificateRevocationListDer<'_>) -> Option<i64> {
    let (remaining, parsed) = CertificateRevocationList::from_der(crl.as_ref()).ok()?;
    if !remaining.is_empty() {
        return None;
    }
    parsed.next_update().map(|next| next.timestamp())
}

/// The soonest `nextUpdate` across a candidate list, as a Unix timestamp.
///
/// The whole list is one admission unit, so the operator's deadline is the
/// earliest record's: once that one expires the entire source is refused, and
/// the later records buy nothing.
pub fn earliest_next_update_unix(crls: &[CertificateRevocationListDer<'static>]) -> Option<i64> {
    crls.iter().filter_map(crl_next_update_unix).min()
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
