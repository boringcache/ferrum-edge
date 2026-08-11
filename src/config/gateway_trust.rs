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
//! - Syntactic admission: every `x509_authorities` entry must be valid base64
//!   **and** parse as an X.509 certificate; every `jwt_authorities` entry must
//!   carry a non-empty unique `key_id` and a bounded PEM public-key block.
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
/// `revision` is server-assigned and monotonic per record. A client echoes the
/// revision it read back on update; a mismatch is a 409, which is how a
/// concurrent rotation from a second admin replica is detected rather than
/// silently overwritten.
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
    /// Monotonic revision. Server-assigned on write; supplied by the client on
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
    pub fn new(namespace: &str, id: &str, bundle: TrustBundleSet) -> Self {
        let now = Utc::now();
        Self {
            id: id.to_string(),
            trust_domain: bundle.local.trust_domain.to_string(),
            namespace: namespace.to_string(),
            bundle,
            revision: 1,
            updated_by: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Idempotent admission normalization, applied on every write entrypoint
    /// (admin, restore, import) exactly like the other config resources.
    ///
    /// The only normalization is derivation: `id` defaults to the namespace and
    /// `trust_domain` is re-derived from the bundle so the identity column can
    /// never be authored to disagree with the material. A client that sends a
    /// *conflicting* `trust_domain` is rejected by [`Self::validate_fields`]
    /// rather than silently corrected — see the mismatch check there.
    pub fn normalize_fields(&mut self) {
        self.id = self.id.trim().to_string();
        if self.id.is_empty() {
            self.id = self.namespace.clone();
        }
        self.trust_domain = self.trust_domain.trim().to_string();
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
            validate_single_bundle(federated, &format!("bundle.federated[{index}]"), &mut errors);
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
                if X509Certificate::from_der(der).is_err() {
                    errors.push(format!(
                        "{label}.x509_authorities[{index}] is not a parseable X.509 certificate"
                    ));
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
            errors.push(format!("{label}.jwt_authorities[{index}] has an empty key_id"));
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
        } else if !is_public_key_pem(&authority.public_key_pem) {
            errors.push(format!(
                "{label}.jwt_authorities[{index}] public_key_pem is not a PEM public key block"
            ));
        }
    }
}

/// Cheap structural PEM check. The point is to reject an operator pasting a
/// PRIVATE KEY (or arbitrary text) into a field that is published to every
/// subscriber, not to re-implement key parsing.
fn is_public_key_pem(pem: &str) -> bool {
    let trimmed = pem.trim();
    (trimmed.starts_with("-----BEGIN PUBLIC KEY-----")
        && trimmed.ends_with("-----END PUBLIC KEY-----"))
        || (trimmed.starts_with("-----BEGIN RSA PUBLIC KEY-----")
            && trimmed.ends_with("-----END RSA PUBLIC KEY-----"))
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

/// Operator-facing message for the ambiguous-authority refusal. Names no paths,
/// no material, and no namespace-derived secrets.
pub const AMBIGUOUS_TRUST_AUTHORITY_MESSAGE: &str =
    "namespace declares both a database gateway trust-bundle resource and a file-sourced \
     trust_bundles value; resolve to a single authority before the control plane can publish";

// ─── Observability ──────────────────────────────────────────────────────────
//
// Fixed cardinality by construction: these are process-wide counters with NO
// labels. A per-namespace label would be unbounded on a cluster-wide CP, and
// namespace names are tenant-identifying, so the namespace-scoped view lives on
// the authenticated admin status surface instead. Nothing here can carry PEM /
// JWKS bytes, secret or provider URIs, or an unbounded identifier — only
// counters, a revision number, and a bounded reason enum.

static LOADS_TOTAL: AtomicU64 = AtomicU64::new(0);
static LOAD_REJECTIONS_TOTAL: AtomicU64 = AtomicU64::new(0);
static AMBIGUOUS_AUTHORITY_TOTAL: AtomicU64 = AtomicU64::new(0);
static PUBLISHED_REVISION: AtomicU64 = AtomicU64::new(0);
static LAST_SUCCESSFUL_LOAD_UNIX_SECONDS: AtomicU64 = AtomicU64::new(0);
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
    /// Two authorities disagreed; publication withdrew trust.
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

/// Record a trust generation that loaded, validated, and published.
///
/// `revision` is the record's monotonic counter (`0` when the namespace has no
/// record, i.e. trust is legitimately absent).
pub fn record_trust_load_success(revision: u64, now_unix_seconds: u64) {
    LOADS_TOTAL.fetch_add(1, Ordering::Relaxed);
    PUBLISHED_REVISION.store(revision, Ordering::Relaxed);
    LAST_SUCCESSFUL_LOAD_UNIX_SECONDS.store(now_unix_seconds, Ordering::Relaxed);
    LAST_FAILURE_REASON.store(
        GatewayTrustFailureReason::None.code(),
        Ordering::Relaxed,
    );
}

/// Record a candidate that was refused before the live swap. The previous valid
/// generation stays active, so `PUBLISHED_REVISION` is deliberately untouched.
pub fn record_trust_load_rejection(reason: GatewayTrustFailureReason) {
    LOAD_REJECTIONS_TOTAL.fetch_add(1, Ordering::Relaxed);
    LAST_FAILURE_REASON.store(reason.code(), Ordering::Relaxed);
}

/// Record a publication that found two authorities and withdrew trust.
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
    pub loads_total: u64,
    pub load_rejections_total: u64,
    pub ambiguous_authority_total: u64,
    /// Revision of the most recently published generation; `0` when none.
    pub published_revision: u64,
    /// Unix seconds of the most recent successful load; `0` when none.
    pub last_successful_load_unix_seconds: u64,
    /// Bounded reason for the most recent failure.
    pub last_failure_reason: &'static str,
}

pub fn observability_snapshot() -> GatewayTrustObservabilitySnapshot {
    GatewayTrustObservabilitySnapshot {
        loads_total: LOADS_TOTAL.load(Ordering::Relaxed),
        load_rejections_total: LOAD_REJECTIONS_TOTAL.load(Ordering::Relaxed),
        ambiguous_authority_total: AMBIGUOUS_AUTHORITY_TOTAL.load(Ordering::Relaxed),
        published_revision: PUBLISHED_REVISION.load(Ordering::Relaxed),
        last_successful_load_unix_seconds: LAST_SUCCESSFUL_LOAD_UNIX_SECONDS
            .load(Ordering::Relaxed),
        last_failure_reason: GatewayTrustFailureReason::from_code(
            LAST_FAILURE_REASON.load(Ordering::Relaxed),
        )
        .as_str(),
    }
}

/// Reset every counter. Test-support only — the production paths are monotonic
/// within a process.
pub fn reset_observability_for_tests() {
    LOADS_TOTAL.store(0, Ordering::Relaxed);
    LOAD_REJECTIONS_TOTAL.store(0, Ordering::Relaxed);
    AMBIGUOUS_AUTHORITY_TOTAL.store(0, Ordering::Relaxed);
    PUBLISHED_REVISION.store(0, Ordering::Relaxed);
    LAST_SUCCESSFUL_LOAD_UNIX_SECONDS.store(0, Ordering::Relaxed);
    LAST_FAILURE_REASON.store(0, Ordering::Relaxed);
}
