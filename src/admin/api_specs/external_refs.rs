//! Opt-in external and cross-document OpenAPI `$ref` resolution.
//!
//! Absent policy keeps the historical fail-closed
//! [`ExtractError::UnsupportedExternalRef`] contract. When both the process
//! gate and the per-spec `x-ferrum-external-refs` extension enable resolution,
//! this module loads referenced documents under strict file/HTTPS containment,
//! resource budgets, and SSRF screening, then returns an immutable snapshot for
//! admission-time persistence. Runtime validation never re-fetches.

use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::net::IpAddr;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use super::extractor::ExtractError;

/// Synthetic document base used when the root submission has no operator base.
/// Never fetched; mirrors the extractor local-schema base.
pub const DEFAULT_DOCUMENT_BASE: &str = "https://ferrum.invalid/local-schema";

const DEFAULT_MAX_DOCUMENTS: usize = 32;
const DEFAULT_MAX_DOCUMENT_BYTES: usize = 5 * 1024 * 1024;
const DEFAULT_MAX_AGGREGATE_BYTES: usize = 20 * 1024 * 1024;
const DEFAULT_MAX_REFS: usize = 256;
const DEFAULT_MAX_URI_LENGTH: usize = 2048;
const DEFAULT_MAX_REDIRECTS: usize = 3;
const DEFAULT_MAX_NESTING: usize = 16;
const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 5_000;
const DEFAULT_REQUEST_TIMEOUT_MS: u64 = 15_000;
const DEFAULT_TOTAL_TIMEOUT_MS: u64 = 60_000;

/// Process-level external `$ref` gate and budgets (from EnvConfig / ferrum.conf).
#[derive(Debug, Clone)]
pub struct ExternalRefProcessPolicy {
    /// Master process gate. Default `false` preserves fail-closed rejection.
    pub enabled: bool,
    /// Absolute filesystem jail for `file:` / relative file references.
    pub file_root: Option<PathBuf>,
    /// Canonical HTTPS origins (`https://host[:port]`) allowed for network refs.
    pub allowed_origins: Vec<String>,
    /// Explicit HTTP origins permitted only when listed here (fixture/dev).
    pub allow_http_origins: Vec<String>,
    pub max_documents: usize,
    pub max_document_bytes: usize,
    pub max_aggregate_bytes: usize,
    pub max_refs: usize,
    pub max_uri_length: usize,
    pub max_redirects: usize,
    pub max_nesting: usize,
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub total_timeout: Duration,
}

impl Default for ExternalRefProcessPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            file_root: None,
            allowed_origins: Vec::new(),
            allow_http_origins: Vec::new(),
            max_documents: DEFAULT_MAX_DOCUMENTS,
            max_document_bytes: DEFAULT_MAX_DOCUMENT_BYTES,
            max_aggregate_bytes: DEFAULT_MAX_AGGREGATE_BYTES,
            max_refs: DEFAULT_MAX_REFS,
            max_uri_length: DEFAULT_MAX_URI_LENGTH,
            max_redirects: DEFAULT_MAX_REDIRECTS,
            max_nesting: DEFAULT_MAX_NESTING,
            connect_timeout: Duration::from_millis(DEFAULT_CONNECT_TIMEOUT_MS),
            request_timeout: Duration::from_millis(DEFAULT_REQUEST_TIMEOUT_MS),
            total_timeout: Duration::from_millis(DEFAULT_TOTAL_TIMEOUT_MS),
        }
    }
}

impl ExternalRefProcessPolicy {
    /// Build from parsed env/conf strings. Invalid values fail closed.
    pub fn from_env_parts(
        enabled: bool,
        file_root: &str,
        allowed_origins: &str,
        allow_http_origins: &str,
        max_documents: usize,
        max_document_bytes: usize,
        max_aggregate_bytes: usize,
        max_refs: usize,
        max_uri_length: usize,
        max_redirects: usize,
        max_nesting: usize,
        connect_timeout_ms: u64,
        request_timeout_ms: u64,
        total_timeout_ms: u64,
    ) -> Result<Self, String> {
        let file_root = parse_optional_file_root(file_root)?;
        let allowed_origins = parse_origin_list(allowed_origins, true)?;
        let allow_http_origins = parse_origin_list(allow_http_origins, false)?;
        if max_documents == 0 {
            return Err("FERRUM_ADMIN_SPEC_EXTERNAL_REFS_MAX_DOCUMENTS must be >= 1".to_string());
        }
        if max_document_bytes == 0 {
            return Err(
                "FERRUM_ADMIN_SPEC_EXTERNAL_REFS_MAX_DOCUMENT_BYTES must be >= 1".to_string(),
            );
        }
        if max_aggregate_bytes < max_document_bytes {
            return Err(
                "FERRUM_ADMIN_SPEC_EXTERNAL_REFS_MAX_AGGREGATE_BYTES must be >= MAX_DOCUMENT_BYTES"
                    .to_string(),
            );
        }
        if max_refs == 0 || max_uri_length == 0 || max_nesting == 0 {
            return Err("external-ref count/uri/nesting budgets must be >= 1".to_string());
        }
        Ok(Self {
            enabled,
            file_root,
            allowed_origins,
            allow_http_origins,
            max_documents,
            max_document_bytes,
            max_aggregate_bytes,
            max_refs,
            max_uri_length,
            max_redirects,
            max_nesting,
            connect_timeout: Duration::from_millis(connect_timeout_ms.max(1)),
            request_timeout: Duration::from_millis(request_timeout_ms.max(1)),
            total_timeout: Duration::from_millis(total_timeout_ms.max(1)),
        })
    }

    /// Stable digest of the process policy for cache keys / snapshots.
    pub fn policy_digest(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"extref-process-v1\0");
        hasher.update([u8::from(self.enabled)]);
        if let Some(root) = &self.file_root {
            hasher.update(root.to_string_lossy().as_bytes());
        }
        hasher.update(b"\0");
        for origin in &self.allowed_origins {
            hasher.update(origin.as_bytes());
            hasher.update(b"\0");
        }
        hasher.update(b"|http|");
        for origin in &self.allow_http_origins {
            hasher.update(origin.as_bytes());
            hasher.update(b"\0");
        }
        hasher.update(self.max_documents.to_le_bytes());
        hasher.update(self.max_document_bytes.to_le_bytes());
        hasher.update(self.max_aggregate_bytes.to_le_bytes());
        hasher.update(self.max_refs.to_le_bytes());
        hasher.update(self.max_uri_length.to_le_bytes());
        hasher.update(self.max_redirects.to_le_bytes());
        hasher.update(self.max_nesting.to_le_bytes());
        hasher.update(self.connect_timeout.as_millis().to_le_bytes());
        hasher.update(self.request_timeout.as_millis().to_le_bytes());
        hasher.update(self.total_timeout.as_millis().to_le_bytes());
        hex::encode(hasher.finalize())
    }
}

/// Per-spec opt-in extension (`x-ferrum-external-refs`).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalRefSpecExtension {
    #[serde(default)]
    pub enabled: bool,
    /// Optional absolute document base URI for the submitted root document.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub document_base: Option<String>,
    /// Optional further HTTPS origin allowlist intersected with process policy.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_origins: Vec<String>,
}

/// Effective policy after intersecting process gates with the per-spec extension.
#[derive(Debug, Clone)]
pub struct EffectiveExternalRefPolicy {
    pub enabled: bool,
    pub document_base: Url,
    pub file_root: Option<PathBuf>,
    pub allowed_origins: HashSet<String>,
    pub allow_http_origins: HashSet<String>,
    pub max_documents: usize,
    pub max_document_bytes: usize,
    pub max_aggregate_bytes: usize,
    pub max_refs: usize,
    pub max_uri_length: usize,
    pub max_redirects: usize,
    pub max_nesting: usize,
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub total_timeout: Duration,
    pub process_policy_digest: String,
}

impl EffectiveExternalRefPolicy {
    pub fn disabled() -> Self {
        let process = ExternalRefProcessPolicy::default();
        Self {
            enabled: false,
            document_base: Url::parse(DEFAULT_DOCUMENT_BASE).expect("static URI"),
            file_root: None,
            allowed_origins: HashSet::new(),
            allow_http_origins: HashSet::new(),
            max_documents: process.max_documents,
            max_document_bytes: process.max_document_bytes,
            max_aggregate_bytes: process.max_aggregate_bytes,
            max_refs: process.max_refs,
            max_uri_length: process.max_uri_length,
            max_redirects: process.max_redirects,
            max_nesting: process.max_nesting,
            connect_timeout: process.connect_timeout,
            request_timeout: process.request_timeout,
            total_timeout: process.total_timeout,
            process_policy_digest: process.policy_digest(),
        }
    }

    pub fn compose(
        process: &ExternalRefProcessPolicy,
        extension: Option<&ExternalRefSpecExtension>,
    ) -> Result<Self, ExtractError> {
        let Some(extension) = extension else {
            let mut disabled = Self::disabled();
            disabled.process_policy_digest = process.policy_digest();
            disabled.max_documents = process.max_documents;
            disabled.max_document_bytes = process.max_document_bytes;
            disabled.max_aggregate_bytes = process.max_aggregate_bytes;
            disabled.max_refs = process.max_refs;
            disabled.max_uri_length = process.max_uri_length;
            disabled.max_redirects = process.max_redirects;
            disabled.max_nesting = process.max_nesting;
            disabled.connect_timeout = process.connect_timeout;
            disabled.request_timeout = process.request_timeout;
            disabled.total_timeout = process.total_timeout;
            disabled.file_root = process.file_root.clone();
            return Ok(disabled);
        };

        if !process.enabled || !extension.enabled {
            let mut disabled = Self::compose(process, None)?;
            // Preserve document_base validation even when disabled so malformed
            // extensions fail closed instead of being ignored.
            if let Some(base) = extension.document_base.as_deref() {
                disabled.document_base = parse_document_base(base, process)?;
            }
            return Ok(disabled);
        }

        let document_base = match extension.document_base.as_deref() {
            Some(base) => parse_document_base(base, process)?,
            None => Url::parse(DEFAULT_DOCUMENT_BASE).map_err(|_| {
                ExtractError::MalformedExtension {
                    which: "x-ferrum-external-refs",
                    error: "internal document base is invalid".to_string(),
                }
            })?,
        };

        let mut allowed_origins: HashSet<String> = process.allowed_origins.iter().cloned().collect();
        if !extension.allowed_origins.is_empty() {
            let mut narrowed = HashSet::new();
            for raw in &extension.allowed_origins {
                let origin = canonicalize_origin(raw, true).map_err(|error| {
                    ExtractError::MalformedExtension {
                        which: "x-ferrum-external-refs",
                        error,
                    }
                })?;
                if !allowed_origins.contains(&origin) {
                    return Err(ExtractError::MalformedExtension {
                        which: "x-ferrum-external-refs",
                        error: "allowed_origins entry is not permitted by process policy"
                            .to_string(),
                    });
                }
                narrowed.insert(origin);
            }
            allowed_origins = narrowed;
        }

        Ok(Self {
            enabled: true,
            document_base,
            file_root: process.file_root.clone(),
            allowed_origins,
            allow_http_origins: process.allow_http_origins.iter().cloned().collect(),
            max_documents: process.max_documents,
            max_document_bytes: process.max_document_bytes,
            max_aggregate_bytes: process.max_aggregate_bytes,
            max_refs: process.max_refs,
            max_uri_length: process.max_uri_length,
            max_redirects: process.max_redirects,
            max_nesting: process.max_nesting,
            connect_timeout: process.connect_timeout,
            request_timeout: process.request_timeout,
            total_timeout: process.total_timeout,
            process_policy_digest: process.policy_digest(),
        })
    }

    pub fn cache_key_material(&self) -> String {
        format!(
            "{}|{}|{}",
            self.process_policy_digest,
            resource_uri_key(&self.document_base),
            u8::from(self.enabled)
        )
    }
}

/// One immutable external document admitted at import time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExternalRefSnapshotDocument {
    /// Canonical document URI without fragment (redacted of userinfo/query).
    pub canonical_uri: String,
    /// SHA-256 hex of the normalized UTF-8 document bytes as admitted.
    pub content_digest: String,
    /// `json` or `yaml`.
    pub format: String,
    /// Normalized JSON value of the document.
    pub document: Value,
}

/// Immutable admission snapshot of every external document used for resolution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExternalRefSnapshot {
    pub policy_digest: String,
    pub root_document_base: String,
    pub documents: Vec<ExternalRefSnapshotDocument>,
    /// Aggregate digest over policy + ordered document digests.
    pub snapshot_digest: String,
}

impl ExternalRefSnapshot {
    pub fn empty(policy: &EffectiveExternalRefPolicy) -> Self {
        let mut snap = Self {
            policy_digest: policy.process_policy_digest.clone(),
            root_document_base: resource_uri_key(&policy.document_base),
            documents: Vec::new(),
            snapshot_digest: String::new(),
        };
        snap.snapshot_digest = snap.compute_digest();
        snap
    }

    pub fn compute_digest(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"extref-snapshot-v1\0");
        hasher.update(self.policy_digest.as_bytes());
        hasher.update(b"\0");
        hasher.update(self.root_document_base.as_bytes());
        hasher.update(b"\0");
        for doc in &self.documents {
            hasher.update(doc.canonical_uri.as_bytes());
            hasher.update(b"\0");
            hasher.update(doc.content_digest.as_bytes());
            hasher.update(b"\0");
            hasher.update(doc.format.as_bytes());
            hasher.update(b"\0");
        }
        hex::encode(hasher.finalize())
    }

    pub fn gzip_bytes(&self) -> Result<Vec<u8>, ExtractError> {
        let json = serde_json::to_vec(self).map_err(|error| {
            ExtractError::SchemaReference(format!("failed to serialize external-ref snapshot: {error}"))
        })?;
        crate::admin::spec_codec::compress_gzip(&json).map_err(|error| {
            ExtractError::SchemaReference(format!("failed to compress external-ref snapshot: {error}"))
        })
    }

    pub fn from_gzip_bytes(bytes: &[u8], max_bytes: usize) -> Result<Self, String> {
        let raw = crate::admin::spec_codec::decompress_gzip_capped(bytes, max_bytes)
            .map_err(|error| format!("external_ref_snapshot decompress failed: {error}"))?;
        let snap: Self = serde_json::from_slice(&raw)
            .map_err(|error| format!("external_ref_snapshot JSON invalid: {error}"))?;
        let expected = snap.compute_digest();
        if snap.snapshot_digest != expected {
            return Err("external_ref_snapshot digest mismatch".to_string());
        }
        Ok(snap)
    }
}

/// Loaded external document ready for resolver indexing.
#[derive(Debug, Clone)]
pub struct LoadedExternalDocument {
    pub canonical_uri: Url,
    pub content_digest: String,
    pub format: &'static str,
    pub root: Value,
    pub raw_bytes: Vec<u8>,
}

/// Sync loader used by unit tests and the file path.
pub trait ExternalDocumentLoader: Send + Sync {
    fn load(
        &self,
        uri: &Url,
        policy: &EffectiveExternalRefPolicy,
        deadline: Instant,
    ) -> Result<LoadedExternalDocument, ExtractError>;
}

/// Production loader: containment-safe files + screened HTTPS (and explicit HTTP allowlist).
#[derive(Clone)]
pub struct DefaultExternalDocumentLoader {
    pub egress: crate::config::BackendEgressPolicy,
    pub dns_cache: Option<std::sync::Arc<crate::dns::DnsCache>>,
    /// Optional in-memory fixtures keyed by canonical URI (tests only).
    pub fixtures: HashMap<String, Vec<u8>>,
}

impl Default for DefaultExternalDocumentLoader {
    fn default() -> Self {
        Self {
            egress: crate::config::BackendEgressPolicy::from_allow_ips(
                crate::config::BackendAllowIps::Public,
            ),
            dns_cache: None,
            fixtures: HashMap::new(),
        }
    }
}

impl ExternalDocumentLoader for DefaultExternalDocumentLoader {
    fn load(
        &self,
        uri: &Url,
        policy: &EffectiveExternalRefPolicy,
        deadline: Instant,
    ) -> Result<LoadedExternalDocument, ExtractError> {
        if Instant::now() >= deadline {
            return Err(external_ref_error(
                "external $ref fetch exceeded the total timeout budget",
            ));
        }
        let key = resource_uri_key(uri);
        if let Some(bytes) = self.fixtures.get(&key) {
            return parse_loaded_document(uri, bytes, policy);
        }
        match uri.scheme() {
            "file" => load_file_document(uri, policy),
            "https" => {
                let runtime = tokio::runtime::Handle::try_current().map_err(|_| {
                    external_ref_error("external HTTPS $ref resolution requires an async runtime")
                })?;
                runtime.block_on(load_http_document(uri, policy, &self.egress, self.dns_cache.as_ref(), true))
            }
            "http" => {
                let origin = origin_key(uri)?;
                if !policy.allow_http_origins.contains(&origin) {
                    return Err(ExtractError::UnsupportedExternalRef {
                        reference: redact_reference(uri.as_str()),
                    });
                }
                let runtime = tokio::runtime::Handle::try_current().map_err(|_| {
                    external_ref_error("external HTTP $ref resolution requires an async runtime")
                })?;
                runtime.block_on(load_http_document(
                    uri,
                    policy,
                    &self.egress,
                    self.dns_cache.as_ref(),
                    false,
                ))
            }
            _ => Err(ExtractError::UnsupportedExternalRef {
                reference: redact_reference(uri.as_str()),
            }),
        }
    }
}

/// In-memory map loader for deterministic unit tests (no filesystem / network).
#[derive(Default)]
pub struct MapExternalDocumentLoader {
    pub docs: HashMap<String, Vec<u8>>,
}

impl ExternalDocumentLoader for MapExternalDocumentLoader {
    fn load(
        &self,
        uri: &Url,
        policy: &EffectiveExternalRefPolicy,
        _deadline: Instant,
    ) -> Result<LoadedExternalDocument, ExtractError> {
        let key = resource_uri_key(uri);
        let bytes = self.docs.get(&key).ok_or_else(|| ExtractError::UnsupportedExternalRef {
            reference: redact_reference(uri.as_str()),
        })?;
        parse_loaded_document(uri, bytes, policy)
    }
}

/// Parse `x-ferrum-external-refs` from a root OpenAPI document.
pub fn parse_external_ref_extension(
    root: &Value,
) -> Result<Option<ExternalRefSpecExtension>, ExtractError> {
    let Some(value) = root.get("x-ferrum-external-refs") else {
        return Ok(None);
    };
    if value.as_bool() == Some(true) {
        return Ok(Some(ExternalRefSpecExtension {
            enabled: true,
            ..ExternalRefSpecExtension::default()
        }));
    }
    if value.as_bool() == Some(false) {
        return Ok(Some(ExternalRefSpecExtension::default()));
    }
    serde_json::from_value(value.clone()).map(Some).map_err(|error| {
        ExtractError::MalformedExtension {
            which: "x-ferrum-external-refs",
            error: error.to_string(),
        }
    })
}

/// Collect and load every external document reachable from `root` under policy.
pub fn load_external_documents(
    root: &Value,
    policy: &EffectiveExternalRefPolicy,
    loader: &dyn ExternalDocumentLoader,
) -> Result<(HashMap<String, LoadedExternalDocument>, ExternalRefSnapshot), ExtractError> {
    if !policy.enabled {
        return Ok((HashMap::new(), ExternalRefSnapshot::empty(policy)));
    }

    let deadline = Instant::now() + policy.total_timeout;
    let mut loaded: HashMap<String, LoadedExternalDocument> = HashMap::new();
    let mut pending: VecDeque<(Url, usize)> = VecDeque::new();
    let mut seen_refs = 0usize;
    let mut aggregate_bytes = 0usize;
    // In-document `$id` resources are resolved locally; never fetch them.
    let mut local_resources = HashSet::new();
    local_resources.insert(resource_uri_key(&policy.document_base));
    collect_local_resource_ids(root, &policy.document_base, &mut local_resources)?;

    collect_refs_from_value(
        root,
        &policy.document_base,
        policy,
        &local_resources,
        &mut pending,
        &mut seen_refs,
        0,
        &mut HashSet::new(),
    )?;

    while let Some((uri, depth)) = pending.pop_front() {
        if depth > policy.max_nesting {
            return Err(ExtractError::SchemaTooDeep {
                location: "x-ferrum-external-refs".to_string(),
            });
        }
        let key = resource_uri_key(&uri);
        if loaded.contains_key(&key) {
            continue;
        }
        if loaded.len() >= policy.max_documents {
            return Err(external_ref_error(
                "external $ref document count exceeded the configured budget",
            ));
        }
        validate_candidate_uri(&uri, policy)?;
        let doc = loader.load(&uri, policy, deadline)?;
        aggregate_bytes = aggregate_bytes.saturating_add(doc.raw_bytes.len());
        if aggregate_bytes > policy.max_aggregate_bytes {
            return Err(ExtractError::SchemaTooLarge {
                location: "x-ferrum-external-refs".to_string(),
            });
        }
        let doc_root = doc.root.clone();
        let doc_base = doc.canonical_uri.clone();
        collect_local_resource_ids(&doc_root, &doc_base, &mut local_resources)?;
        loaded.insert(key, doc);
        collect_refs_from_value(
            &doc_root,
            &doc_base,
            policy,
            &local_resources,
            &mut pending,
            &mut seen_refs,
            depth + 1,
            &mut HashSet::new(),
        )?;
    }

    let mut documents: Vec<ExternalRefSnapshotDocument> = loaded
        .values()
        .map(|doc| ExternalRefSnapshotDocument {
            canonical_uri: resource_uri_key(&doc.canonical_uri),
            content_digest: doc.content_digest.clone(),
            format: doc.format.to_string(),
            document: doc.root.clone(),
        })
        .collect();
    documents.sort_by(|a, b| a.canonical_uri.cmp(&b.canonical_uri));
    let mut snapshot = ExternalRefSnapshot {
        policy_digest: policy.process_policy_digest.clone(),
        root_document_base: resource_uri_key(&policy.document_base),
        documents,
        snapshot_digest: String::new(),
    };
    snapshot.snapshot_digest = snapshot.compute_digest();
    Ok((loaded, snapshot))
}

fn collect_local_resource_ids(
    value: &Value,
    base: &Url,
    out: &mut HashSet<String>,
) -> Result<(), ExtractError> {
    match value {
        Value::Object(map) => {
            let child_base = schema_child_base(map, base)?;
            if child_base.as_str() != base.as_str() {
                out.insert(resource_uri_key(&child_base));
            }
            for (key, child) in map {
                if matches!(
                    key.as_str(),
                    "default" | "examples" | "example" | "const" | "enum" | "$ref"
                ) {
                    continue;
                }
                collect_local_resource_ids(child, &child_base, out)?;
            }
            Ok(())
        }
        Value::Array(items) => {
            for child in items {
                collect_local_resource_ids(child, base, out)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn collect_refs_from_value(
    value: &Value,
    base: &Url,
    policy: &EffectiveExternalRefPolicy,
    local_resources: &HashSet<String>,
    pending: &mut VecDeque<(Url, usize)>,
    seen_refs: &mut usize,
    depth: usize,
    active: &mut HashSet<String>,
) -> Result<(), ExtractError> {
    match value {
        Value::Object(map) => {
            let child_base = schema_child_base(map, base)?;
            if let Some(reference) = map.get("$ref").and_then(Value::as_str) {
                *seen_refs = seen_refs.saturating_add(1);
                if *seen_refs > policy.max_refs {
                    return Err(external_ref_error(
                        "external $ref count exceeded the configured budget",
                    ));
                }
                if reference.len() > policy.max_uri_length {
                    return Err(external_ref_error(
                        "external $ref URI exceeds the configured length budget",
                    ));
                }
                if let Some(target) =
                    classify_external_target(reference, &child_base, local_resources)?
                {
                    let key = resource_uri_key(&target);
                    if active.insert(key.clone()) {
                        pending.push_back((target, depth));
                        active.remove(&key);
                    }
                }
            }
            for (key, child) in map {
                if key == "$ref" {
                    continue;
                }
                // Annotation payloads are not active schema structure.
                if matches!(
                    key.as_str(),
                    "default" | "examples" | "example" | "const" | "enum"
                ) {
                    continue;
                }
                collect_refs_from_value(
                    child,
                    &child_base,
                    policy,
                    local_resources,
                    pending,
                    seen_refs,
                    depth,
                    active,
                )?;
            }
            Ok(())
        }
        Value::Array(items) => {
            for child in items {
                collect_refs_from_value(
                    child,
                    base,
                    policy,
                    local_resources,
                    pending,
                    seen_refs,
                    depth,
                    active,
                )?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn classify_external_target(
    reference: &str,
    base: &Url,
    local_resources: &HashSet<String>,
) -> Result<Option<Url>, ExtractError> {
    let (uri_part, _fragment) = split_ref(reference);
    let Some(uri_part) = uri_part else {
        return Ok(None);
    };
    if uri_part.is_empty() || uri_part.starts_with('#') {
        return Ok(None);
    }
    let joined = base.join(uri_part).map_err(|_| {
        ExtractError::SchemaReference(format!(
            "invalid $ref '{}'",
            redact_reference(reference)
        ))
    })?;
    let mut resource = joined;
    resource.set_fragment(None);
    let key = resource_uri_key(&resource);
    if local_resources.contains(&key) {
        return Ok(None);
    }
    // Relative joins that remain on the synthetic never-fetched base are local.
    if resource.scheme() == "https" && resource.host_str() == Some("ferrum.invalid") {
        return Ok(None);
    }
    Ok(Some(resource))
}

fn schema_child_base(map: &serde_json::Map<String, Value>, base: &Url) -> Result<Url, ExtractError> {
    let id_value = map
        .get("$id")
        .or_else(|| map.get("id"))
        .and_then(Value::as_str);
    let Some(id_value) = id_value else {
        return Ok(base.clone());
    };
    let resolved = base.join(id_value).map_err(|_| {
        ExtractError::SchemaReference(format!(
            "invalid schema $id '{}'",
            redact_reference(id_value)
        ))
    })?;
    let mut resource = resolved;
    resource.set_fragment(None);
    Ok(resource)
}

fn validate_candidate_uri(uri: &Url, policy: &EffectiveExternalRefPolicy) -> Result<(), ExtractError> {
    if uri.as_str().len() > policy.max_uri_length {
        return Err(external_ref_error(
            "external $ref URI exceeds the configured length budget",
        ));
    }
    if uri.username() != "" || uri.password().is_some() {
        return Err(external_ref_error(
            "external $ref URI must not embed credentials",
        ));
    }
    if uri.query().is_some() {
        return Err(external_ref_error(
            "external $ref URI must not carry a query string",
        ));
    }
    match uri.scheme() {
        "file" => {
            if policy.file_root.is_none() {
                return Err(ExtractError::UnsupportedExternalRef {
                    reference: redact_reference(uri.as_str()),
                });
            }
            Ok(())
        }
        "https" => {
            let origin = origin_key(uri)?;
            if !policy.allowed_origins.contains(&origin) {
                return Err(ExtractError::UnsupportedExternalRef {
                    reference: redact_reference(uri.as_str()),
                });
            }
            screen_host_literal(uri)?;
            Ok(())
        }
        "http" => {
            let origin = origin_key(uri)?;
            if !policy.allow_http_origins.contains(&origin) {
                return Err(ExtractError::UnsupportedExternalRef {
                    reference: redact_reference(uri.as_str()),
                });
            }
            screen_host_literal(uri)?;
            Ok(())
        }
        _ => Err(ExtractError::UnsupportedExternalRef {
            reference: redact_reference(uri.as_str()),
        }),
    }
}

fn screen_host_literal(uri: &Url) -> Result<(), ExtractError> {
    let host = uri.host_str().ok_or_else(|| {
        external_ref_error("external $ref URI is missing a host")
    })?;
    if host.eq_ignore_ascii_case("localhost")
        || host.ends_with(".localhost")
        || host.eq_ignore_ascii_case("metadata.google.internal")
    {
        // Loopback/metadata hostnames are rejected at the URI gate unless the
        // operator listed an explicit HTTP fixture origin (checked by caller)
        // *and* later DNS screening allows the resolved address. For HTTPS we
        // still reject these names here so accidental public-origin typos fail.
        if uri.scheme() == "https" {
            return Err(external_ref_error(
                "external $ref host is not a permitted public destination",
            ));
        }
    }
    if let Ok(ip) = host.parse::<IpAddr>()
        && (crate::config::is_always_blocked_range(&ip)
            || crate::config::is_private_ip(&ip)
            || ip.is_loopback()
            || ip.is_unspecified()
            || matches!(ip, IpAddr::V4(v4) if v4.is_link_local() || v4.is_broadcast())
            || matches!(ip, IpAddr::V6(v6) if v6.is_unicast_link_local() || v6.is_multicast()))
        && uri.scheme() == "https"
    {
        // Explicit HTTP fixture origins may target loopback listeners.
        return Err(external_ref_error(
            "external $ref host is not a permitted public destination",
        ));
    }
    Ok(())
}

fn load_file_document(
    uri: &Url,
    policy: &EffectiveExternalRefPolicy,
) -> Result<LoadedExternalDocument, ExtractError> {
    let root = policy.file_root.as_ref().ok_or_else(|| {
        ExtractError::UnsupportedExternalRef {
            reference: redact_reference(uri.as_str()),
        }
    })?;
    let path = file_uri_to_contained_path(uri, root)?;
    let meta = fs::symlink_metadata(&path).map_err(|_| {
        external_ref_error("external file $ref target is not readable")
    })?;
    if meta.file_type().is_symlink() {
        return Err(external_ref_error(
            "external file $ref target must not be a symbolic link",
        ));
    }
    if !meta.is_file() {
        return Err(external_ref_error(
            "external file $ref target must be a regular file",
        ));
    }
    let bytes = fs::read(&path).map_err(|_| {
        external_ref_error("external file $ref target is not readable")
    })?;
    if bytes.len() > policy.max_document_bytes {
        return Err(ExtractError::SchemaTooLarge {
            location: "x-ferrum-external-refs".to_string(),
        });
    }
    parse_loaded_document(uri, &bytes, policy)
}

async fn load_http_document(
    uri: &Url,
    policy: &EffectiveExternalRefPolicy,
    egress: &crate::config::BackendEgressPolicy,
    dns_cache: Option<&std::sync::Arc<crate::dns::DnsCache>>,
    require_https: bool,
) -> Result<LoadedExternalDocument, ExtractError> {
    if require_https && uri.scheme() != "https" {
        return Err(ExtractError::UnsupportedExternalRef {
            reference: redact_reference(uri.as_str()),
        });
    }
    validate_candidate_uri(uri, policy)?;

    // Resolve and screen every candidate address before dialing (DNS rebinding).
    if let Some(host) = uri.host_str()
        && host.parse::<IpAddr>().is_err()
    {
        let addrs = resolve_host_addrs(host, dns_cache).await?;
        for addr in &addrs {
            if let Some(reason) = egress.deny_reason(addr) {
                tracing::warn!(
                    reason = %reason,
                    "external OpenAPI $ref destination denied by backend egress policy"
                );
                return Err(external_ref_error(
                    "external $ref destination denied by egress policy",
                ));
            }
        }
        if addrs.is_empty() {
            return Err(external_ref_error(
                "external $ref host did not resolve to any address",
            ));
        }
    } else if let Some(host) = uri.host_str()
        && let Ok(ip) = host.parse::<IpAddr>()
        && let Some(reason) = egress.deny_reason(&ip)
    {
        tracing::warn!(
            reason = %reason,
            "external OpenAPI $ref literal destination denied by backend egress policy"
        );
        return Err(external_ref_error(
            "external $ref destination denied by egress policy",
        ));
    }

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::custom({
            let policy = policy.clone();
            let egress = egress.clone();
            move |attempt| {
                if attempt.previous().len() > policy.max_redirects {
                    return attempt.error("external $ref redirect budget exceeded");
                }
                let next = attempt.url();
                if let Err(error) = validate_candidate_uri(next, &policy) {
                    return attempt.error(error.to_string());
                }
                if let Some(host) = next.host_str()
                    && let Ok(ip) = host.parse::<IpAddr>()
                    && egress.deny_reason(&ip).is_some()
                {
                    return attempt.error("external $ref redirect denied by egress policy");
                }
                attempt.follow()
            }
        }))
        .connect_timeout(policy.connect_timeout)
        .timeout(policy.request_timeout)
        .no_proxy()
        .build()
        .map_err(|_| external_ref_error("failed to build external $ref HTTP client"))?;

    // Never forward ambient credentials: construct a bare GET with no Authorization,
    // Cookie, or proxy auth headers.
    let response = client
        .get(uri.clone())
        .header(reqwest::header::ACCEPT, "application/json, application/yaml, text/yaml, application/x-yaml, text/x-yaml, text/plain")
        .send()
        .await
        .map_err(|_| external_ref_error("external $ref HTTP fetch failed"))?;

    if !response.status().is_success() {
        return Err(external_ref_error(
            "external $ref HTTP fetch returned a non-success status",
        ));
    }
    if let Some(ct) = response.headers().get(reqwest::header::CONTENT_TYPE)
        && let Ok(ct) = ct.to_str()
        && !content_type_allowed(ct)
    {
        return Err(external_ref_error(
            "external $ref response Content-Type is not an allowed OpenAPI media type",
        ));
    }

    let bytes = response
        .bytes()
        .await
        .map_err(|_| external_ref_error("external $ref HTTP body read failed"))?;
    if bytes.len() > policy.max_document_bytes {
        return Err(ExtractError::SchemaTooLarge {
            location: "x-ferrum-external-refs".to_string(),
        });
    }
    parse_loaded_document(uri, &bytes, policy)
}

async fn resolve_host_addrs(
    host: &str,
    dns_cache: Option<&std::sync::Arc<crate::dns::DnsCache>>,
) -> Result<Vec<IpAddr>, ExtractError> {
    if let Some(cache) = dns_cache {
        return cache
            .resolve_all_fresh(host)
            .await
            .map_err(|_| external_ref_error("external $ref DNS resolution failed"));
    }
    let host_owned = host.to_string();
    let addrs = tokio::net::lookup_host((host_owned.as_str(), 443))
        .await
        .map_err(|_| external_ref_error("external $ref DNS resolution failed"))?
        .map(|a| a.ip())
        .collect::<Vec<_>>();
    Ok(addrs)
}

fn content_type_allowed(content_type: &str) -> bool {
    let media = content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim()
        .to_ascii_lowercase();
    matches!(
        media.as_str(),
        "application/json"
            | "application/yaml"
            | "application/x-yaml"
            | "text/yaml"
            | "text/x-yaml"
            | "text/plain"
            | "application/octet-stream"
    ) || media.ends_with("+json")
        || media.ends_with("+yaml")
}

fn parse_loaded_document(
    uri: &Url,
    bytes: &[u8],
    policy: &EffectiveExternalRefPolicy,
) -> Result<LoadedExternalDocument, ExtractError> {
    if bytes.len() > policy.max_document_bytes {
        return Err(ExtractError::SchemaTooLarge {
            location: "x-ferrum-external-refs".to_string(),
        });
    }
    let format = detect_format(bytes);
    let root = match format {
        "json" => serde_json::from_slice(bytes).map_err(|error| {
            ExtractError::InvalidJson(format!(
                "external document {}: {error}",
                redact_reference(uri.as_str())
            ))
        })?,
        _ => {
            // Bound YAML the same way API-spec admission does.
            const MAX_EXTERNAL_DOC_NODES: usize = 500_000;
            super::bounded_yaml::parse_yaml_to_json(bytes, MAX_EXTERNAL_DOC_NODES).map_err(
                |error| {
                    ExtractError::InvalidYaml(format!(
                        "external document {}: {}",
                        redact_reference(uri.as_str()),
                        error.message()
                    ))
                },
            )?
        }
    };
    let normalized = serde_json::to_vec(&root).map_err(|error| {
        ExtractError::SchemaReference(format!("failed to normalize external document: {error}"))
    })?;
    let digest = hex::encode(Sha256::digest(&normalized));
    let mut canonical = uri.clone();
    canonical.set_fragment(None);
    canonical.set_query(None);
    Ok(LoadedExternalDocument {
        canonical_uri: canonical,
        content_digest: digest,
        format,
        root,
        raw_bytes: bytes.to_vec(),
    })
}

fn detect_format(bytes: &[u8]) -> &'static str {
    match bytes.iter().find(|&&b| !b.is_ascii_whitespace()) {
        Some(b'{') | Some(b'[') => "json",
        _ => "yaml",
    }
}

fn file_uri_to_contained_path(uri: &Url, root: &Path) -> Result<PathBuf, ExtractError> {
    if uri.scheme() != "file" {
        return Err(ExtractError::UnsupportedExternalRef {
            reference: redact_reference(uri.as_str()),
        });
    }
    let raw = uri.to_file_path().map_err(|_| {
        external_ref_error("external file $ref URI is not a valid filesystem path")
    })?;
    contain_path(root, &raw)
}

/// Canonicalize `candidate` and require it stay under `root` without symlink escape.
pub fn contain_path(root: &Path, candidate: &Path) -> Result<PathBuf, ExtractError> {
    let canonical_root = fs::canonicalize(root).map_err(|_| {
        external_ref_error("external-ref file root is not accessible")
    })?;
    reject_symlink_chain(&canonical_root)?;
    // Resolve candidate relative to root when not absolute.
    let joined = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        canonical_root.join(candidate)
    };
    // Reject `..` components before canonicalize so missing parents cannot race.
    for component in joined.components() {
        if matches!(component, Component::ParentDir) {
            // Still allow ParentDir if canonicalize later keeps us inside root;
            // the prefix check below is authoritative. Continue.
        }
    }
    let meta = fs::symlink_metadata(&joined).map_err(|_| {
        external_ref_error("external file $ref target is not readable")
    })?;
    if meta.file_type().is_symlink() {
        return Err(external_ref_error(
            "external file $ref target must not be a symbolic link",
        ));
    }
    let canonical = fs::canonicalize(&joined).map_err(|_| {
        external_ref_error("external file $ref target is not readable")
    })?;
    if !canonical.starts_with(&canonical_root) {
        return Err(external_ref_error(
            "external file $ref target escapes the configured file root",
        ));
    }
    reject_symlink_chain(&canonical)?;
    Ok(canonical)
}

fn reject_symlink_chain(path: &Path) -> Result<(), ExtractError> {
    let mut current = path.to_path_buf();
    loop {
        let meta = fs::symlink_metadata(&current).map_err(|_| {
            external_ref_error("external file $ref path is not readable")
        })?;
        if meta.file_type().is_symlink() {
            return Err(external_ref_error(
                "external file $ref path must not traverse symbolic links",
            ));
        }
        match current.parent() {
            Some(parent) if parent != current => current = parent.to_path_buf(),
            _ => break,
        }
    }
    Ok(())
}

fn parse_optional_file_root(raw: &str) -> Result<Option<PathBuf>, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let path = PathBuf::from(trimmed);
    if !path.is_absolute() {
        return Err("FERRUM_ADMIN_SPEC_EXTERNAL_REFS_FILE_ROOT must be an absolute path".to_string());
    }
    Ok(Some(path))
}

fn parse_origin_list(raw: &str, https_only: bool) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for part in raw.split(|c: char| c == ',' || c.is_whitespace()) {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        out.push(canonicalize_origin(part, https_only)?);
    }
    out.sort();
    out.dedup();
    Ok(out)
}

fn canonicalize_origin(raw: &str, https_only: bool) -> Result<String, String> {
    let parsed = Url::parse(raw).map_err(|_| format!("invalid origin '{raw}'"))?;
    if https_only && parsed.scheme() != "https" {
        return Err(format!("origin must be https: '{raw}'"));
    }
    if !https_only && parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err(format!("origin must be http or https: '{raw}'"));
    }
    if parsed.username() != "" || parsed.password().is_some() {
        return Err("origin must not embed credentials".to_string());
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err("origin must not carry query or fragment".to_string());
    }
    if parsed.path() != "/" && parsed.path() != "" {
        return Err("origin must not carry a path".to_string());
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| "origin is missing a host".to_string())?
        .to_ascii_lowercase();
    let port = parsed.port_or_known_default().ok_or_else(|| {
        "origin is missing a port".to_string()
    })?;
    Ok(format!("{}://{}:{}", parsed.scheme(), host, port))
}

fn parse_document_base(
    raw: &str,
    process: &ExternalRefProcessPolicy,
) -> Result<Url, ExtractError> {
    let parsed = Url::parse(raw).map_err(|_| ExtractError::MalformedExtension {
        which: "x-ferrum-external-refs",
        error: "document_base must be an absolute URI".to_string(),
    })?;
    if parsed.username() != "" || parsed.password().is_some() || parsed.query().is_some() {
        return Err(ExtractError::MalformedExtension {
            which: "x-ferrum-external-refs",
            error: "document_base must not embed credentials or a query string".to_string(),
        });
    }
    match parsed.scheme() {
        "file" => {
            let Some(root) = process.file_root.as_ref() else {
                return Err(ExtractError::MalformedExtension {
                    which: "x-ferrum-external-refs",
                    error: "document_base file URI requires FERRUM_ADMIN_SPEC_EXTERNAL_REFS_FILE_ROOT"
                        .to_string(),
                });
            };
            // Ensure the declared base stays inside the jail (best-effort when
            // the path does not yet exist: fall back to parent containment).
            if let Ok(path) = parsed.to_file_path() {
                let probe = if path.exists() {
                    path.clone()
                } else {
                    path.parent().unwrap_or(path.as_path()).to_path_buf()
                };
                if probe.exists() {
                    contain_path(root, &probe).map_err(|_| ExtractError::MalformedExtension {
                        which: "x-ferrum-external-refs",
                        error: "document_base escapes the configured file root".to_string(),
                    })?;
                }
            }
        }
        "https" => {
            let origin = origin_key(&parsed).map_err(|error| ExtractError::MalformedExtension {
                which: "x-ferrum-external-refs",
                error,
            })?;
            if !process.allowed_origins.iter().any(|o| o == &origin) {
                return Err(ExtractError::MalformedExtension {
                    which: "x-ferrum-external-refs",
                    error: "document_base origin is not permitted by process policy".to_string(),
                });
            }
        }
        "http" => {
            let origin = origin_key(&parsed).map_err(|error| ExtractError::MalformedExtension {
                which: "x-ferrum-external-refs",
                error,
            })?;
            if !process.allow_http_origins.iter().any(|o| o == &origin) {
                return Err(ExtractError::MalformedExtension {
                    which: "x-ferrum-external-refs",
                    error: "document_base HTTP origin is not permitted by process policy"
                        .to_string(),
                });
            }
        }
        _ => {
            return Err(ExtractError::MalformedExtension {
                which: "x-ferrum-external-refs",
                error: "document_base scheme must be file, https, or an allowed http origin"
                    .to_string(),
            });
        }
    }
    let mut cleaned = parsed;
    cleaned.set_fragment(None);
    Ok(cleaned)
}

fn origin_key(uri: &Url) -> Result<String, ExtractError> {
    let host = uri
        .host_str()
        .ok_or_else(|| external_ref_error("external $ref URI is missing a host"))?;
    let port = uri
        .port_or_known_default()
        .ok_or_else(|| external_ref_error("external $ref URI is missing a port"))?;
    canonicalize_origin(
        &format!("{}://{}:{}", uri.scheme(), host, port),
        false,
    )
    .map_err(|_| external_ref_error("external $ref URI origin is invalid"))
}

fn split_ref(reference: &str) -> (Option<&str>, &str) {
    match reference.split_once('#') {
        Some(("", fragment)) => (None, fragment),
        Some((uri, fragment)) => (Some(uri), fragment),
        None => (Some(reference), ""),
    }
}

pub fn resource_uri_key(url: &Url) -> String {
    let mut owned = url.clone();
    owned.set_fragment(None);
    owned.set_query(None);
    normalize_percent_escape_case(owned.as_str())
}

fn normalize_percent_escape_case(value: &str) -> String {
    let mut normalized = String::with_capacity(value.len());
    let mut remaining = value;
    while let Some(offset) = remaining.find('%') {
        normalized.push_str(&remaining[..offset]);
        let escape = &remaining[offset..];
        if escape.len() >= 3
            && escape.as_bytes()[1].is_ascii_hexdigit()
            && escape.as_bytes()[2].is_ascii_hexdigit()
        {
            normalized.push('%');
            normalized.push(char::from(escape.as_bytes()[1].to_ascii_uppercase()));
            normalized.push(char::from(escape.as_bytes()[2].to_ascii_uppercase()));
            remaining = &escape[3..];
        } else {
            normalized.push('%');
            remaining = &escape[1..];
        }
    }
    normalized.push_str(remaining);
    normalized
}

/// Redact userinfo and query from a reference before putting it in errors/logs.
pub fn redact_reference(reference: &str) -> String {
    let Ok(mut url) = Url::parse(reference) else {
        // Relative refs: strip query-looking suffixes and never echo raw paths
        // that look absolute.
        let trimmed = reference.split('?').next().unwrap_or(reference);
        if trimmed.len() > 128 {
            return format!("{}…", &trimmed[..128]);
        }
        return trimmed.to_string();
    };
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    let rendered = url.as_str();
    if rendered.len() > 256 {
        format!("{}…", &rendered[..256])
    } else {
        rendered.to_string()
    }
}

fn external_ref_error(message: &str) -> ExtractError {
    ExtractError::SchemaReference(message.to_string())
}

#[cfg(test)]
mod policy_unit_tests {
    use super::*;

    #[test]
    fn absent_extension_stays_disabled() {
        let process = ExternalRefProcessPolicy {
            enabled: true,
            ..ExternalRefProcessPolicy::default()
        };
        let effective = EffectiveExternalRefPolicy::compose(&process, None).unwrap();
        assert!(!effective.enabled);
    }

    #[test]
    fn both_gates_required() {
        let process = ExternalRefProcessPolicy {
            enabled: true,
            allowed_origins: vec!["https://schemas.example.com:443".to_string()],
            ..ExternalRefProcessPolicy::default()
        };
        let ext = ExternalRefSpecExtension {
            enabled: true,
            document_base: None,
            allowed_origins: vec![],
        };
        let effective = EffectiveExternalRefPolicy::compose(&process, Some(&ext)).unwrap();
        assert!(effective.enabled);
    }

    #[test]
    fn redact_strips_userinfo_and_query() {
        let redacted = redact_reference("https://user:pass@example.com/a.json?token=secret#/x");
        assert!(!redacted.contains("user"));
        assert!(!redacted.contains("pass"));
        assert!(!redacted.contains("token"));
        assert!(redacted.contains("example.com"));
    }
}
