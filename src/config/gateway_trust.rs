//! Namespace-keyed gateway trust bundles as a first-class configuration
//! resource (issue #3727).
//!
//! Before this module the only authority for `GatewayConfig.trust_bundles` was
//! a file-sourced document: every SQL/MongoDB backend could persist proxies,
//! consumers, upstreams and plugin configs but had no storage shape for the
//! gateway-to-mesh trust roots the control plane distributes to its data
//! planes. Database-mode CP replicas could therefore not commit a root
//! rotation or an emergency revocation, and a namespace-scoped ConfigSync
//! stream had to clear the unpartitioned trust field outright rather than
//! publish the subscriber's own trust state.
//!
//! [`GatewayTrustBundleRecord`] is that missing resource. It is deliberately a
//! thin, namespace-keyed envelope around the existing serializable
//! [`TrustBundleSet`] domain type rather than a parallel representation: the
//! bytes that reach a data plane through the `trust_bundles_json` side channel
//! are exactly the bytes an operator wrote, so there is no second schema that
//! can drift from the one mesh validation already understands.
//!
//! Invariants enforced here (all of them *before* persistence and again before
//! publication):
//!
//! - One record per namespace. The resource is a singleton so a namespace's
//!   projected trust state is never ambiguous; SQL enforces it with the
//!   `namespace` primary key and MongoDB with `_id = namespace`.
//! - `trust_domain` is the bundle identity and must equal
//!   `bundle.local.trust_domain`, so the stored identity column can never
//!   disagree with the material it names.
//! - Bounded material: authority counts, per-authority size, and total encoded
//!   size are capped so a hostile or accidental write cannot push an unbounded
//!   blob through the change log and into every subscriber's snapshot.
//! - Usable material, not just well-formed wrappers: every `x509_authorities`
//!   entry must be valid base64 **and** parse as an X.509 certificate that
//!   consumes the complete DER entry (no accepted trailing bytes); every
//!   `jwt_authorities` entry must carry a non-empty unique `key_id` and a PEM
//!   block the JWT-SVID authority parser can actually turn into a usable
//!   public key.
//! - No duplicate trust domains across `local` + `federated`.
//!
//! Nothing in this module logs, formats, or returns trust material. Errors name
//! the offending field and index only.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::identity::TrustDomain;
use crate::modes::mesh::config::TrustBundleSet;

/// Maximum number of X.509 authorities in any single bundle (local or one
/// federated entry). Root rotation needs an overlap of two or three; the cap is
/// generous enough for staged rollouts and small enough that a snapshot stays
/// bounded.
pub const MAX_X509_AUTHORITIES_PER_BUNDLE: usize = 16;

/// Maximum number of JWT authorities in any single bundle.
pub const MAX_JWT_AUTHORITIES_PER_BUNDLE: usize = 16;

/// Maximum number of federated bundles in one record.
pub const MAX_FEDERATED_BUNDLES: usize = 32;

/// Maximum DER size of one X.509 authority, in bytes.
pub const MAX_X509_AUTHORITY_DER_BYTES: usize = 16 * 1024;

/// Maximum size of one JWT authority PEM public key, in bytes.
pub const MAX_JWT_AUTHORITY_PEM_BYTES: usize = 16 * 1024;

/// Maximum length of a JWT authority `key_id`.
pub const MAX_JWT_AUTHORITY_KEY_ID_BYTES: usize = 256;

/// Maximum serialized size of the whole `bundle` value. This is the value that
/// is stored in one column/field, replicated through the change log, and
/// serialized into every `trust_bundles_json` side channel, so it is the bound
/// that actually matters for propagation cost.
pub const MAX_TRUST_BUNDLE_JSON_BYTES: usize = 256 * 1024;

/// Maximum length of the resource id.
pub const MAX_TRUST_BUNDLE_ID_BYTES: usize = 255;

/// Authoritative, namespace-keyed gateway trust-bundle resource.
///
/// `revision` is assigned by the BACKEND from a durable monotonic source (the
/// SQL `config_changes.sequence` / MongoDB config-change sequence counter), not
/// by the caller and not by a per-record counter that restarts at 1. A client
/// echoes the revision it read back on update; a mismatch is a 409, which is how
/// a concurrent rotation from a second admin replica is detected rather than
/// silently overwritten.
///
/// Sourcing the revision from the change sequence is what closes the ABA hole a
/// per-record counter leaves open. With a counter that restarts at 1 for every
/// incarnation, a client could read revision 1, a second actor could DELETE the
/// namespace singleton and recreate it (revision 1 again), and the first
/// client's later `PUT` with expected revision 1 would compare-and-set
/// successfully against a *different* trust incarnation and overwrite it. The
/// namespace admission lease serializes individual writes, but nothing
/// serializes the gap between a client's `GET` and its later `PUT`, so only a
/// revision that can never be reused fixes it. Every trust mutation — including
/// the delete — advances the shared change sequence, so a recreated record is
/// always strictly newer than the incarnation it replaced and the stale
/// expectation can only conflict or report not-found.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GatewayTrustBundleRecord {
    /// Stable resource identity. Defaults to the namespace when a client omits
    /// it, which keeps the singleton addressable without forcing operators to
    /// invent a name.
    #[serde(default)]
    pub id: String,
    #[serde(default = "crate::config::types::default_namespace")]
    pub namespace: String,
    /// Bundle identity. Must equal `bundle.local.trust_domain`.
    #[serde(default)]
    pub trust_domain: String,
    /// The admitted trust material, in the same shape mesh config uses.
    pub bundle: TrustBundleSet,
    /// Monotonic revision. Backend-assigned on every physical write from the
    /// durable change sequence — never carried over from a request body, a
    /// backup payload, or a previous incarnation — and supplied by the client on
    /// update as the expected current value (`0` = no expectation).
    #[serde(default)]
    pub revision: u64,
    /// Audit actor that last wrote the record. Never a credential — the admin
    /// JWT subject only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<String>,
    #[serde(default = "Utc::now")]
    pub created_at: DateTime<Utc>,
    #[serde(default = "Utc::now")]
    pub updated_at: DateTime<Utc>,
}

impl GatewayTrustBundleRecord {
    /// Build a record from an already-validated bundle. Used by loaders and
    /// tests; admin writes go through the CRUD admission path.
    ///
    /// `revision` is left UNASSIGNED (`0`). A caller-authored revision is never
    /// persisted: the store stamps the backend-assigned value inside the write
    /// transaction, so no construction site can seed a value that a later
    /// incarnation could repeat.
    pub fn new(namespace: &str, id: &str, bundle: TrustBundleSet) -> Self {
        let now = Utc::now();
        Self {
            id: id.to_string(),
            trust_domain: bundle.local.trust_domain.to_string(),
            namespace: namespace.to_string(),
            bundle,
            revision: 0,
            updated_by: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Trim-only normalization. Deliberately derives NOTHING from
    /// `self.namespace`: on the admin path the body's namespace is still
    /// whatever the client sent at this point, and the server-selected
    /// `X-Ferrum-Namespace` value is applied afterwards.
    pub fn trim_fields(&mut self) {
        self.id = self.id.trim().to_string();
        self.trust_domain = self.trust_domain.trim().to_string();
    }

    /// The id a namespace's singleton record defaults to when the writer omits
    /// one. Derived from the SERVER-selected namespace by every caller — never
    /// from a request body — so a hostile body cannot steer either the stored
    /// namespace or the stored id.
    pub fn default_singleton_id(namespace: &str) -> String {
        namespace.to_string()
    }

    /// Idempotent admission normalization for entrypoints that have already
    /// forced the authenticated target namespace onto the record (restore,
    /// import, loaders).
    ///
    /// Trims, then defaults `id` to the (already server-owned) namespace. A
    /// client that sends a *conflicting* `trust_domain` is rejected by
    /// [`Self::validate_fields`] rather than silently corrected — see the
    /// mismatch check there.
    pub fn normalize_fields(&mut self) {
        self.trim_fields();
        if self.id.is_empty() {
            self.id = Self::default_singleton_id(&self.namespace);
        }
    }

    /// Full syntactic + semantic admission validation.
    ///
    /// Returns every problem found so an operator repairing a bad rotation sees
    /// the whole list. No message ever contains trust material — only field
    /// names, indices, and sizes.
    pub fn validate_fields(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if self.id.is_empty() {
            errors.push("gateway trust bundle id is required".to_string());
        } else if self.id.len() > MAX_TRUST_BUNDLE_ID_BYTES {
            errors.push(format!(
                "gateway trust bundle id exceeds {MAX_TRUST_BUNDLE_ID_BYTES} bytes"
            ));
        }
        if self.namespace.trim().is_empty() {
            errors.push("gateway trust bundle namespace is required".to_string());
        }

        // Identity: the stored trust domain names the material it carries.
        let local_domain = self.bundle.local.trust_domain.as_str();
        if self.trust_domain.is_empty() {
            errors.push("gateway trust bundle trust_domain is required".to_string());
        } else if self.trust_domain != local_domain {
            errors.push(
                "gateway trust bundle trust_domain does not match bundle.local.trust_domain"
                    .to_string(),
            );
        }
        if TrustDomain::new(local_domain.to_string()).is_err() {
            errors.push(
                "gateway trust bundle bundle.local.trust_domain is not a valid SPIFFE trust domain"
                    .to_string(),
            );
        }

        // Reuse the mesh validator so a bundle admitted here is exactly a
        // bundle the mesh/DP side already accepts (empty authorities, base64,
        // duplicate federated trust domains).
        errors.extend(crate::modes::mesh::config::validate_mesh_config(
            &[],
            &[],
            &[],
            &[],
            &[],
            &[],
            Some(&self.bundle),
        ));

        if self.bundle.federated.len() > MAX_FEDERATED_BUNDLES {
            errors.push(format!(
                "gateway trust bundle declares {} federated bundles; the maximum is {MAX_FEDERATED_BUNDLES}",
                self.bundle.federated.len()
            ));
        }

        validate_single_bundle(&self.bundle.local, "bundle.local", &mut errors);
        for (index, federated) in self.bundle.federated.iter().enumerate() {
            validate_single_bundle(
                federated,
                &format!("bundle.federated[{index}]"),
                &mut errors,
            );
        }

        // A federated entry that repeats the local trust domain would make
        // "which authorities are authoritative for this domain" ambiguous at
        // verification time. `validate_mesh_config` already seeds its seen-set
        // with the local domain, so this is covered there; the explicit check
        // stays for the record-level message.
        if self
            .bundle
            .federated
            .iter()
            .any(|federated| federated.trust_domain.as_str() == local_domain)
        {
            errors.push(
                "gateway trust bundle federated entry repeats the local trust domain".to_string(),
            );
        }

        match serde_json::to_string(&self.bundle) {
            Ok(encoded) => {
                if encoded.len() > MAX_TRUST_BUNDLE_JSON_BYTES {
                    errors.push(format!(
                        "gateway trust bundle encodes to {} bytes; the maximum is {MAX_TRUST_BUNDLE_JSON_BYTES}",
                        encoded.len()
                    ));
                }
            }
            Err(_) => errors.push("gateway trust bundle could not be serialized".to_string()),
        }

        // Final gate: the bundle must convert to the runtime representation the
        // proxy actually installs. Anything that fails here would be a bundle
        // that persists but can never be applied.
        if self.bundle.to_runtime().is_err() {
            errors.push("gateway trust bundle contains undecodable trust material".to_string());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            errors.sort();
            errors.dedup();
            Err(errors)
        }
    }

    /// Redacted, fixed-shape summary for logs, metrics, and admin status.
    ///
    /// Deliberately carries no PEM/DER bytes, no key material, and no
    /// unbounded identifiers — only the trust domain (which is already public
    /// configuration), counts, and the revision.
    pub fn summary(&self) -> GatewayTrustBundleSummary {
        GatewayTrustBundleSummary {
            namespace: self.namespace.clone(),
            trust_domain: self.trust_domain.clone(),
            revision: self.revision,
            x509_authority_count: self.bundle.local.x509_authorities.len(),
            jwt_authority_count: self.bundle.local.jwt_authorities.len(),
            federated_count: self.bundle.federated.len(),
            updated_at: self.updated_at,
        }
    }
}

fn validate_single_bundle(
    bundle: &crate::modes::mesh::config::TrustBundle,
    label: &str,
    errors: &mut Vec<String>,
) {
    if bundle.x509_authorities.len() > MAX_X509_AUTHORITIES_PER_BUNDLE {
        errors.push(format!(
            "{label} declares {} x509 authorities; the maximum is {MAX_X509_AUTHORITIES_PER_BUNDLE}",
            bundle.x509_authorities.len()
        ));
    }
    if bundle.jwt_authorities.len() > MAX_JWT_AUTHORITIES_PER_BUNDLE {
        errors.push(format!(
            "{label} declares {} jwt authorities; the maximum is {MAX_JWT_AUTHORITIES_PER_BUNDLE}",
            bundle.jwt_authorities.len()
        ));
    }

    match bundle.decode_x509_authorities() {
        Ok(ders) => {
            for (index, der) in ders.iter().enumerate() {
                if der.len() > MAX_X509_AUTHORITY_DER_BYTES {
                    errors.push(format!(
                        "{label}.x509_authorities[{index}] is {} bytes; the maximum is {MAX_X509_AUTHORITY_DER_BYTES}",
                        der.len()
                    ));
                    continue;
                }
                // The certificate must consume the COMPLETE entry. A parser
                // that stops early would admit an authority whose stored bytes
                // carry appended material an operator (or a differently-strict
                // verifier) would read as part of the document.
                match X509Certificate::from_der(der) {
                    Ok(([], _)) => {}
                    Ok(_) => errors.push(format!(
                        "{label}.x509_authorities[{index}] carries trailing bytes after its X.509 certificate"
                    )),
                    Err(_) => errors.push(format!(
                        "{label}.x509_authorities[{index}] is not a parseable X.509 certificate"
                    )),
                }
            }
        }
        Err(_) => {
            // `validate_mesh_config` already reported the base64 failure with
            // its index; do not duplicate the message here.
        }
    }

    let mut seen_key_ids = HashSet::new();
    for (index, authority) in bundle.jwt_authorities.iter().enumerate() {
        if authority.key_id.trim().is_empty() {
            errors.push(format!(
                "{label}.jwt_authorities[{index}] has an empty key_id"
            ));
        } else if authority.key_id.len() > MAX_JWT_AUTHORITY_KEY_ID_BYTES {
            errors.push(format!(
                "{label}.jwt_authorities[{index}] key_id exceeds {MAX_JWT_AUTHORITY_KEY_ID_BYTES} bytes"
            ));
        } else if !seen_key_ids.insert(authority.key_id.as_str()) {
            errors.push(format!(
                "{label}.jwt_authorities[{index}] repeats a key_id already declared in this bundle"
            ));
        }
        if authority.public_key_pem.len() > MAX_JWT_AUTHORITY_PEM_BYTES {
            errors.push(format!(
                "{label}.jwt_authorities[{index}] public_key_pem exceeds {MAX_JWT_AUTHORITY_PEM_BYTES} bytes"
            ));
        } else if !is_usable_public_key_pem(&authority.public_key_pem) {
            errors.push(format!(
                "{label}.jwt_authorities[{index}] public_key_pem is not a usable PEM public key"
            ));
        }
    }
}

/// Prove the purported public key is one the JWT-SVID stack can actually use.
///
/// This reuses the existing JWT/JWKS authority parser
/// ([`is_usable_public_key_material`](crate::identity::jwt_svid::jwks::is_usable_public_key_material)),
/// which decodes the SPKI DER (or the SPIFFE-federation JWK form) completely
/// and refuses a key type or curve point the validator could not verify with. A
/// structural starts_with/ends_with check would admit a PRIVATE KEY paste
/// wrapped in the right header, a truncated body, or a key type the mesh cannot
/// use — material that persists and publishes to every subscriber but can never
/// validate.
///
/// The parser's error is discarded on purpose: its text is already
/// material-free, but this module's contract is that admission messages name
/// only the field and index.
fn is_usable_public_key_pem(pem: &str) -> bool {
    crate::identity::jwt_svid::jwks::is_usable_public_key_material(pem)
}

/// Fixed-cardinality, material-free description of one namespace's trust state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayTrustBundleSummary {
    pub namespace: String,
    pub trust_domain: String,
    pub revision: u64,
    pub x509_authority_count: usize,
    pub jwt_authority_count: usize,
    pub federated_count: usize,
    pub updated_at: DateTime<Utc>,
}

/// Publication semantics for one namespace's gateway trust state.
///
/// This is the CP-side mirror of the DP's `GatewayTrustBundleUpdate` and the
/// reason the side channel can express a rotation, a revocation, and "nothing
/// to say" without any of the three being inferable from the other two.
#[derive(Debug, Clone, PartialEq)]
pub enum GatewayTrustPublication<'a> {
    /// Emit nothing: the subscriber keeps whatever it already applied. Encoded
    /// as an empty `trust_bundles_json`.
    Unchanged,
    /// Withdraw previously delivered trust material. Encoded as JSON `null`.
    Clear,
    /// Install this material, replacing whatever was applied before. Encoded as
    /// the serialized `TrustBundleSet`.
    Replace(&'a TrustBundleSet),
}

impl<'a> GatewayTrustPublication<'a> {
    /// Resolve the publication for a full snapshot, where the CP always states
    /// the complete current state so a reconnecting DP can reconstruct it.
    pub fn for_snapshot(record: Option<&'a GatewayTrustBundleRecord>) -> Self {
        match record {
            Some(record) => Self::Replace(&record.bundle),
            None => Self::Clear,
        }
    }

    /// Resolve the publication for a delta, where "no trust change in this
    /// poll" must be distinguishable from "trust was revoked".
    ///
    /// `previous` is the state the CP last published for the namespace and
    /// `current` is the state it just committed. Equality is on the complete
    /// record identity + material, so a revision bump with identical material
    /// still republishes (cheap, and keeps a lagging replica convergent) while
    /// an untouched namespace emits nothing at all.
    pub fn for_delta(
        previous: Option<&GatewayTrustBundleRecord>,
        current: Option<&'a GatewayTrustBundleRecord>,
    ) -> Self {
        match (previous, current) {
            (None, None) => Self::Unchanged,
            (Some(_), None) => Self::Clear,
            (None, Some(current)) => Self::Replace(&current.bundle),
            (Some(previous), Some(current)) => {
                if previous.revision == current.revision && previous.bundle == current.bundle {
                    Self::Unchanged
                } else {
                    Self::Replace(&current.bundle)
                }
            }
        }
    }

    /// Encode to the `trust_bundles_json` wire value.
    ///
    /// A serialization failure fails closed to `Clear`: publishing stale trust
    /// the CP can no longer describe would be worse than withdrawing it, and a
    /// bundle that cannot serialize never passed admission in the first place.
    pub fn to_side_channel_json(&self) -> Result<String, serde_json::Error> {
        match self {
            Self::Unchanged => Ok(String::new()),
            Self::Clear => Ok("null".to_string()),
            Self::Replace(bundle) => serde_json::to_string(bundle),
        }
    }
}

/// Resolve the single authoritative trust source for a namespace.
///
/// Precedence is deliberately not "database wins, quietly": a deployment that
/// carries BOTH a database record and a file/overlay-sourced
/// `GatewayConfig.trust_bundles` has two authorities that can disagree per
/// replica, which is exactly the divergence issue #3727 exists to remove. In
/// that case production modes fail closed and keep the last known good state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustAuthorityResolution {
    /// The database record is authoritative (or there is nothing to publish).
    Database,
    /// No database record; the file-sourced value stands.
    File,
    /// Both authorities present — ambiguous, refuse.
    Ambiguous,
}

/// Classify the trust authorities visible for one namespace.
pub fn resolve_trust_authority(
    database_record: Option<&GatewayTrustBundleRecord>,
    file_sourced: Option<&TrustBundleSet>,
) -> TrustAuthorityResolution {
    match (database_record, file_sourced) {
        (Some(_), Some(_)) => TrustAuthorityResolution::Ambiguous,
        (Some(_), None) => TrustAuthorityResolution::Database,
        (None, Some(_)) => TrustAuthorityResolution::File,
        (None, None) => TrustAuthorityResolution::Database,
    }
}

/// What one namespace-scoped publication should say about trust.
///
/// This is the candidate/publication boundary for trust: it is resolved from
/// the authorities visible BEFORE any namespace partitioning clears the
/// unpartitioned slot, so a database record plus a file/overlay value is still
/// recognizable as two authorities rather than looking database-only.
#[derive(Debug, Clone, PartialEq)]
pub enum NamespaceTrustProjection {
    /// Install this material.
    Replace(TrustBundleSet),
    /// Withdraw previously delivered material.
    Clear,
    /// Say nothing: the subscriber keeps the last trust generation it accepted.
    ///
    /// This is the ambiguous-authority outcome. Converting ambiguity into a
    /// `Clear` would revoke a working generation on every replica the moment a
    /// leftover file value appeared next to a database record — an outage
    /// caused by a configuration smell. Issue #3727 asks for the ambiguity to
    /// be *rejected* while last-known-good is retained, which is exactly this.
    KeepPrevious,
}

/// Resolve the publication for one namespace from the authorities visible
/// before partitioning.
///
/// `file_sourced_admissible` is false on scopes that require a namespace claim
/// (multi-namespace control planes): an unpartitioned value must never reach a
/// namespace-scoped stream there, so a file-only deployment withdraws rather
/// than publishing material it cannot attribute to the subscriber.
pub fn project_namespace_trust(
    database_record: Option<&GatewayTrustBundleRecord>,
    file_sourced: Option<&TrustBundleSet>,
    file_sourced_admissible: bool,
) -> NamespaceTrustProjection {
    match resolve_trust_authority(database_record, file_sourced) {
        TrustAuthorityResolution::Ambiguous => {
            record_ambiguous_authority();
            NamespaceTrustProjection::KeepPrevious
        }
        TrustAuthorityResolution::Database => match database_record {
            Some(record) => NamespaceTrustProjection::Replace(record.bundle.clone()),
            None => NamespaceTrustProjection::Clear,
        },
        TrustAuthorityResolution::File => match (file_sourced, file_sourced_admissible) {
            (Some(bundle), true) => NamespaceTrustProjection::Replace(bundle.clone()),
            _ => NamespaceTrustProjection::Clear,
        },
    }
}

/// Operator-facing message for the ambiguous-authority refusal. Names no paths,
/// no material, and no namespace-derived secrets.
pub const AMBIGUOUS_TRUST_AUTHORITY_MESSAGE: &str = "namespace declares both a database gateway trust-bundle resource and a file-sourced \
     trust_bundles value; resolve to a single authority before the control plane can publish";

// ─── Observability ──────────────────────────────────────────────────────────
//
// Fixed cardinality by construction: these are process-wide counters with NO
// labels. A per-namespace label would be unbounded on a cluster-wide CP, and
// namespace names are tenant-identifying, so the namespace-scoped view lives on
// the authenticated admin status surface instead. Nothing here can carry PEM /
// JWKS bytes, secret or provider URIs, or an unbounded identifier — only
// counters, a revision number, and a bounded reason enum.

static PUBLISHED_GENERATIONS_TOTAL: AtomicU64 = AtomicU64::new(0);
static LOAD_REJECTIONS_TOTAL: AtomicU64 = AtomicU64::new(0);
static AMBIGUOUS_AUTHORITY_TOTAL: AtomicU64 = AtomicU64::new(0);
static LAST_PUBLISHED_UNIX_SECONDS: AtomicU64 = AtomicU64::new(0);
static LAST_FAILURE_REASON: AtomicU8 = AtomicU8::new(0);

/// Bounded reason for the most recent trust-load failure. Deliberately an enum,
/// not a message: a free-form reason could echo stored material into `/metrics`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayTrustFailureReason {
    None,
    /// Stored material failed admission validation (size, syntax, identity).
    InvalidMaterial,
    /// The stored row/document could not be decoded at all.
    Undecodable,
    /// Two authorities were visible at once, so the publication was REFUSED.
    /// Trust is not withdrawn: the side channel says nothing and every
    /// subscriber keeps the last generation it accepted
    /// ([`NamespaceTrustProjection::KeepPrevious`]).
    AmbiguousAuthority,
}

impl GatewayTrustFailureReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::InvalidMaterial => "invalid_material",
            Self::Undecodable => "undecodable",
            Self::AmbiguousAuthority => "ambiguous_authority",
        }
    }

    const fn code(self) -> u8 {
        match self {
            Self::None => 0,
            Self::InvalidMaterial => 1,
            Self::Undecodable => 2,
            Self::AmbiguousAuthority => 3,
        }
    }

    const fn from_code(code: u8) -> Self {
        match code {
            1 => Self::InvalidMaterial,
            2 => Self::Undecodable,
            3 => Self::AmbiguousAuthority,
            _ => Self::None,
        }
    }
}

/// Record a trust generation that reached the ACTUAL publication boundary —
/// the `ArcSwap` store that makes a configuration generation live.
///
/// Deliberately not called from inside a per-namespace database load: a load
/// still has validation, overlay composition, the atomic swap, and broadcast
/// ahead of it, so counting there would report generations that were never
/// published. Publications that carry no database trust record at all are not
/// counted either — this counter answers "did a stored trust generation go
/// live", not "did any config swap happen".
///
/// It is also not counted per subscriber: the call site is the swap, not a
/// stream, so a data plane reconnecting and receiving the same generation again
/// never inflates the counter.
///
/// `file_sourced` is the publication's unpartitioned `GatewayConfig.trust_bundles`
/// slot, and it is what keeps the counter honest about the ambiguity refusal.
/// The per-namespace projection that refuses an ambiguous authority runs later,
/// during broadcast, so counting here without consulting it would report a
/// successful trust publication for a generation whose every database record
/// was about to be refused. That slot is a SINGLE unpartitioned value compared
/// against every namespace's record by [`resolve_trust_authority`], so the
/// outcome is all-or-nothing: when it is `Some`, every database record in this
/// generation is ambiguous and nothing distributable is published (the
/// refusal's own counter and bounded reason are recorded by
/// [`record_ambiguous_authority`] at the projection); when it is `None`, no
/// record is ambiguous and a mixed generation — some namespaces accepted, some
/// refused — cannot arise. Multi-namespace generations therefore still count
/// exactly once, as one generation reaching the swap.
///
/// There is deliberately no process-wide "published revision": revisions are
/// per namespace and a last-writer-wins process atomic would be actively
/// misleading on a multi-namespace control plane. The per-namespace revision is
/// on the authenticated `GET /gateway-trust/status` view instead.
pub fn record_trust_generation_published(
    records: &[GatewayTrustBundleRecord],
    file_sourced: Option<&TrustBundleSet>,
    now_unix_seconds: u64,
) {
    if records.is_empty() || file_sourced.is_some() {
        return;
    }
    PUBLISHED_GENERATIONS_TOTAL.fetch_add(1, Ordering::Relaxed);
    LAST_PUBLISHED_UNIX_SECONDS.store(now_unix_seconds, Ordering::Relaxed);
    LAST_FAILURE_REASON.store(GatewayTrustFailureReason::None.code(), Ordering::Relaxed);
}

/// Stable fingerprint of a trust generation.
///
/// Covers exactly the fields that decide what a subscriber will validate with —
/// namespace, id, trust domain, revision, and the canonical encoding of the
/// material — so two control-plane replicas that reconstructed the same
/// committed state produce the same string, and any rotation or revocation
/// produces a different one. Used for configuration identity/equivalence and
/// surfaced on the authenticated status view; it is a digest, so it carries no
/// material.
pub fn trust_generation_fingerprint(records: &[GatewayTrustBundleRecord]) -> String {
    // SHA-2 goes through the FIPS-approved wrapper, never the RustCrypto crate
    // directly (which is dev-only in this workspace).
    use crate::fips::approved::Sha256;

    let mut ordered: Vec<&GatewayTrustBundleRecord> = records.iter().collect();
    ordered.sort_by(|a, b| a.namespace.cmp(&b.namespace).then_with(|| a.id.cmp(&b.id)));

    let mut hasher = Sha256::new();
    for record in ordered {
        hasher.update(record.namespace.as_bytes());
        hasher.update([0]);
        hasher.update(record.id.as_bytes());
        hasher.update([0]);
        hasher.update(record.trust_domain.as_bytes());
        hasher.update([0]);
        hasher.update(record.revision.to_be_bytes());
        hasher.update([0]);
        match serde_json::to_vec(&record.bundle) {
            Ok(encoded) => hasher.update(encoded),
            // A bundle that cannot serialize never passed admission; fold in a
            // distinct marker rather than silently hashing nothing.
            Err(_) => hasher.update(b"unserializable"),
        }
        hasher.update([0]);
    }
    hex::encode(hasher.finalize())
}

/// Record a candidate that was refused before the live swap. The previous valid
/// generation stays active, so the published-generation counter and timestamp
/// are deliberately untouched.
pub fn record_trust_load_rejection(reason: GatewayTrustFailureReason) {
    LOAD_REJECTIONS_TOTAL.fetch_add(1, Ordering::Relaxed);
    LAST_FAILURE_REASON.store(reason.code(), Ordering::Relaxed);
}

/// Record a publication that found two authorities and was therefore refused.
///
/// Nothing is withdrawn by this outcome: the projection is
/// [`NamespaceTrustProjection::KeepPrevious`], the side channel is empty, and
/// subscribers retain the last trust generation they accepted. The counter and
/// the bounded failure reason exist precisely so a refusal that changes nothing
/// on the wire is still visible to an operator.
pub fn record_ambiguous_authority() {
    AMBIGUOUS_AUTHORITY_TOTAL.fetch_add(1, Ordering::Relaxed);
    LAST_FAILURE_REASON.store(
        GatewayTrustFailureReason::AmbiguousAuthority.code(),
        Ordering::Relaxed,
    );
}

/// Process-wide, label-free snapshot for `/metrics` and admin status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GatewayTrustObservabilitySnapshot {
    /// Trust generations that reached the live-configuration swap.
    pub published_generations_total: u64,
    pub load_rejections_total: u64,
    pub ambiguous_authority_total: u64,
    /// Unix seconds of the most recently published generation; `0` when none.
    pub last_published_unix_seconds: u64,
    /// Bounded reason for the most recent failure.
    pub last_failure_reason: &'static str,
}

pub fn observability_snapshot() -> GatewayTrustObservabilitySnapshot {
    GatewayTrustObservabilitySnapshot {
        published_generations_total: PUBLISHED_GENERATIONS_TOTAL.load(Ordering::Relaxed),
        load_rejections_total: LOAD_REJECTIONS_TOTAL.load(Ordering::Relaxed),
        ambiguous_authority_total: AMBIGUOUS_AUTHORITY_TOTAL.load(Ordering::Relaxed),
        last_published_unix_seconds: LAST_PUBLISHED_UNIX_SECONDS.load(Ordering::Relaxed),
        last_failure_reason: GatewayTrustFailureReason::from_code(
            LAST_FAILURE_REASON.load(Ordering::Relaxed),
        )
        .as_str(),
    }
}

/// Reset every counter. Test-support only — the production paths are monotonic
/// within a process.
pub fn reset_observability_for_tests() {
    PUBLISHED_GENERATIONS_TOTAL.store(0, Ordering::Relaxed);
    LOAD_REJECTIONS_TOTAL.store(0, Ordering::Relaxed);
    AMBIGUOUS_AUTHORITY_TOTAL.store(0, Ordering::Relaxed);
    LAST_PUBLISHED_UNIX_SECONDS.store(0, Ordering::Relaxed);
    LAST_FAILURE_REASON.store(0, Ordering::Relaxed);
}
