//! Durable Ferrum CNI attachment ownership for CNI 1.1 GC.
//!
//! Successful CNI ADD records that claim GC ownership are persisted next to the
//! configured node-agent CNI socket so a process crash/restart can rehydrate
//! `(containerID, ifname) -> pod UID` identity before GC acts. The on-disk
//! document is bounded, crash-safe (temp + fsync + rename), and fail-closed on
//! malformed, oversized, truncated, symlinked, or path-like input. Hostile
//! bytes are never echoed into errors or logs.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use super::spec::{
    MAX_CNI_ATTACHMENT_FIELD_BYTES, MAX_CNI_GC_ATTACHMENTS, is_safe_cni_container_id,
    is_safe_cni_ifname,
};
use crate::tls::private_file::replace_private_file;

/// On-disk schema version. Unknown versions fail closed.
pub const CNI_OWNERSHIP_STORE_VERSION: u32 = 1;

/// Sibling filename under the configured CNI socket parent directory.
pub const CNI_OWNERSHIP_STORE_FILENAME: &str = "cni-owned-attachments.v1";

/// Hard cap on durable store file size. Dense-node attachment counts stay under
/// [`MAX_CNI_GC_ATTACHMENTS`]; this bound rejects hostile oversized files before
/// JSON parse.
pub const MAX_CNI_OWNERSHIP_STORE_BYTES: usize = 8 * 1024 * 1024;

/// One Ferrum-owned CNI attachment identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurableCniOwnershipRecord {
    pub container_id: String,
    pub ifname: String,
    pub pod_uid: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DurableCniOwnershipDocument {
    version: u32,
    attachments: Vec<DurableCniOwnershipRecord>,
}

/// Why durable ownership state was rejected. Messages are sanitized — they must
/// never include raw file contents or attacker-controlled identifiers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CniOwnershipStoreError {
    Path,
    Symlink,
    Io,
    Oversized,
    TruncatedOrInvalid,
    UnsupportedVersion,
    TooManyAttachments,
    InvalidRecord,
}

impl CniOwnershipStoreError {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Path => "cni ownership store path is invalid",
            Self::Symlink => "cni ownership store refuses symlinked durable state",
            Self::Io => "cni ownership store I/O failure",
            Self::Oversized => "cni ownership store exceeds size cap",
            Self::TruncatedOrInvalid => "cni ownership store is truncated or malformed",
            Self::UnsupportedVersion => "cni ownership store version is unsupported",
            Self::TooManyAttachments => "cni ownership store exceeds attachment cap",
            Self::InvalidRecord => "cni ownership store contains an invalid record",
        }
    }
}

impl std::fmt::Display for CniOwnershipStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for CniOwnershipStoreError {}

/// Derive the durable ownership path from the configured CNI socket path.
///
/// Returns `None` when the socket path has no usable parent directory.
pub fn ownership_store_path_for_socket(socket_path: &str) -> Option<PathBuf> {
    let trimmed = socket_path.trim();
    if trimmed.is_empty() {
        return None;
    }
    let path = Path::new(trimmed);
    let parent = path.parent()?;
    if parent.as_os_str().is_empty() {
        return None;
    }
    Some(parent.join(CNI_OWNERSHIP_STORE_FILENAME))
}

/// Validate a Kubernetes pod UID for durable ownership identity.
///
/// Rejects empty, oversized, path-like, and non-ASCII-safe values without
/// echoing the input.
pub fn is_safe_cni_pod_uid(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_CNI_ATTACHMENT_FIELD_BYTES {
        return false;
    }
    if value.contains('/') || value.contains('\\') || value.contains("..") || value.contains('\0')
    {
        return false;
    }
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_alphanumeric() {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn validate_record(record: &DurableCniOwnershipRecord) -> Result<(), CniOwnershipStoreError> {
    if !is_safe_cni_container_id(&record.container_id)
        || record.container_id.len() > MAX_CNI_ATTACHMENT_FIELD_BYTES
    {
        return Err(CniOwnershipStoreError::InvalidRecord);
    }
    if !is_safe_cni_ifname(&record.ifname) {
        return Err(CniOwnershipStoreError::InvalidRecord);
    }
    if !is_safe_cni_pod_uid(&record.pod_uid) {
        return Err(CniOwnershipStoreError::InvalidRecord);
    }
    Ok(())
}

fn refuse_symlink(path: &Path) -> Result<(), CniOwnershipStoreError> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Err(CniOwnershipStoreError::Symlink),
        Ok(_) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(CniOwnershipStoreError::Io),
    }
}

/// Load and validate durable ownership records from `path`.
///
/// A missing file yields an empty list. Any validation or I/O failure returns a
/// sanitized error and must not be treated as authoritative ownership.
pub fn load_durable_cni_ownership(
    path: &Path,
) -> Result<Vec<DurableCniOwnershipRecord>, CniOwnershipStoreError> {
    refuse_symlink(path)?;
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err(CniOwnershipStoreError::Io),
    };
    if bytes.len() > MAX_CNI_OWNERSHIP_STORE_BYTES {
        return Err(CniOwnershipStoreError::Oversized);
    }
    parse_durable_cni_ownership_bytes(&bytes)
}

/// Parse validated ownership records from already-read bytes.
pub fn parse_durable_cni_ownership_bytes(
    bytes: &[u8],
) -> Result<Vec<DurableCniOwnershipRecord>, CniOwnershipStoreError> {
    if bytes.len() > MAX_CNI_OWNERSHIP_STORE_BYTES {
        return Err(CniOwnershipStoreError::Oversized);
    }
    let doc: DurableCniOwnershipDocument = match serde_json::from_slice(bytes) {
        Ok(doc) => doc,
        Err(_) => return Err(CniOwnershipStoreError::TruncatedOrInvalid),
    };
    if doc.version != CNI_OWNERSHIP_STORE_VERSION {
        return Err(CniOwnershipStoreError::UnsupportedVersion);
    }
    if doc.attachments.len() > MAX_CNI_GC_ATTACHMENTS {
        return Err(CniOwnershipStoreError::TooManyAttachments);
    }
    let mut seen = std::collections::HashSet::with_capacity(doc.attachments.len());
    let mut out = Vec::with_capacity(doc.attachments.len());
    for record in doc.attachments {
        validate_record(&record)?;
        let key = (record.container_id.clone(), record.ifname.clone());
        if !seen.insert(key) {
            return Err(CniOwnershipStoreError::InvalidRecord);
        }
        out.push(record);
    }
    Ok(out)
}

fn encode_durable_cni_ownership(
    records: &[DurableCniOwnershipRecord],
) -> Result<Vec<u8>, CniOwnershipStoreError> {
    if records.len() > MAX_CNI_GC_ATTACHMENTS {
        return Err(CniOwnershipStoreError::TooManyAttachments);
    }
    for record in records {
        validate_record(record)?;
    }
    let doc = DurableCniOwnershipDocument {
        version: CNI_OWNERSHIP_STORE_VERSION,
        attachments: records.to_vec(),
    };
    let bytes = serde_json::to_vec(&doc).map_err(|_| CniOwnershipStoreError::Io)?;
    if bytes.len() > MAX_CNI_OWNERSHIP_STORE_BYTES {
        return Err(CniOwnershipStoreError::Oversized);
    }
    Ok(bytes)
}

/// Atomically replace durable ownership state at `path`.
pub fn store_durable_cni_ownership(
    path: &Path,
    records: &[DurableCniOwnershipRecord],
) -> Result<(), CniOwnershipStoreError> {
    let parent = path.parent().ok_or(CniOwnershipStoreError::Path)?;
    if parent.as_os_str().is_empty() {
        return Err(CniOwnershipStoreError::Path);
    }
    refuse_symlink(path)?;
    // Refuse a symlinked parent so writes cannot be redirected off the
    // configured Ferrum CNI runtime directory.
    refuse_symlink(parent)?;
    if let Err(err) = fs::create_dir_all(parent)
        && err.kind() != io::ErrorKind::AlreadyExists
    {
        return Err(CniOwnershipStoreError::Io);
    }
    // Re-check after create: a raced symlink must not become authoritative.
    refuse_symlink(parent)?;
    refuse_symlink(path)?;
    let bytes = encode_durable_cni_ownership(records)?;
    replace_private_file(path, &bytes).map_err(|_| CniOwnershipStoreError::Io)
}

/// Process-global durable store configuration and load fence for the live
/// node-agent CNI generation.
#[derive(Debug, Default)]
struct CniOwnershipRuntime {
    path: Option<PathBuf>,
    /// `true` once a load attempt completed for the configured path.
    loaded: bool,
    /// `true` when the configured durable state was rejected; GC must fail
    /// closed without sweeping.
    rejected: bool,
}

static CNI_OWNERSHIP_RUNTIME: Mutex<CniOwnershipRuntime> = Mutex::new(CniOwnershipRuntime {
    path: None,
    loaded: false,
    rejected: false,
});

fn lock_runtime() -> std::sync::MutexGuard<'static, CniOwnershipRuntime> {
    CNI_OWNERSHIP_RUNTIME
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Configure the durable ownership path for this node-agent CNI generation.
///
/// Passing `None` disables durable persistence (in-memory ownership only). Used
/// by production startup and tests; resets the load fence.
pub fn configure_cni_ownership_store(path: Option<PathBuf>) {
    let mut runtime = lock_runtime();
    runtime.path = path;
    runtime.loaded = false;
    runtime.rejected = false;
}

/// Test/helper: current configured durable path.
#[cfg(test)]
#[allow(dead_code)]
pub fn configured_cni_ownership_store_path() -> Option<PathBuf> {
    lock_runtime().path.clone()
}

/// Whether durable state was rejected for the current configuration.
pub fn cni_ownership_store_is_rejected() -> bool {
    lock_runtime().rejected
}

/// Load durable records for the configured path, updating the load fence.
///
/// Returns `Ok(None)` when durability is disabled. Returns `Ok(Some(records))`
/// on a successful load (including missing-file empty). Returns `Err` after
/// marking the store rejected so GC fails closed.
pub fn load_configured_cni_ownership(
) -> Result<Option<Vec<DurableCniOwnershipRecord>>, CniOwnershipStoreError> {
    let mut runtime = lock_runtime();
    let Some(path) = runtime.path.clone() else {
        runtime.loaded = true;
        runtime.rejected = false;
        return Ok(None);
    };
    match load_durable_cni_ownership(&path) {
        Ok(records) => {
            runtime.loaded = true;
            runtime.rejected = false;
            Ok(Some(records))
        }
        Err(err) => {
            runtime.loaded = true;
            runtime.rejected = true;
            Err(err)
        }
    }
}

/// Persist `records` to the configured path. No-op success when durability is
/// disabled. Fails closed without mutating the rejection fence on I/O errors
/// (callers retain in-memory ownership and retry).
pub fn persist_configured_cni_ownership(
    records: &[DurableCniOwnershipRecord],
) -> Result<(), CniOwnershipStoreError> {
    let runtime = lock_runtime();
    let Some(path) = runtime.path.as_ref() else {
        return Ok(());
    };
    if runtime.rejected {
        return Err(CniOwnershipStoreError::TruncatedOrInvalid);
    }
    store_durable_cni_ownership(path, records)
}

/// Reset runtime state for tests.
pub fn reset_cni_ownership_store_for_tests() {
    configure_cni_ownership_store(None);
}
