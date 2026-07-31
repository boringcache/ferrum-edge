//! Shared, expiring renewal leases for file-backed TLS material stores.
//!
//! Every serving replica starts its own ACME renewal scheduler, so without a
//! shared claim two replicas can decide the same certificate is due, create two
//! orders against the same account, collide on challenge state, and burn CA
//! rate limits (issue #2409). A lease is a named, holder-stamped, expiring
//! claim persisted next to the ACME stores in the same shared directory and
//! mutated through the same exclusive-lock read-modify-write, so "who owns this
//! renewal" is decided by authoritative shared state rather than by a
//! process-local map.
//!
//! Ownership is fail-closed in both directions: a lease that cannot be read or
//! written is *not* acquired (the certificate is skipped this cycle rather than
//! renewed twice), and a holder that crashes loses its claim automatically once
//! `expires_at` passes, so another replica takes over without operator action.
//! A fencing counter (`fence`) makes renew/release idempotent against a claim
//! that was already taken over.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::tls::shared_store::{SharedStoreError, SharedStoreFile, VersionedStoreFile};

const LEASE_STORE_FILE_NAME: &str = "tls-leases.json";
const DEFAULT_STORE_DIR: &str = "./ferrum-managed-tls";

/// Expired leases are kept this long so operators can see recent ownership
/// history, then pruned so the document cannot grow without bound.
const EXPIRED_LEASE_RETENTION_SECONDS: i64 = 24 * 60 * 60;

/// Fallback TTL when a caller-supplied duration is not representable.
const FALLBACK_LEASE_TTL_MILLIS: i64 = 900 * 1_000;

/// Longest accepted `FERRUM_TLS_STORE_INSTANCE_ID`.
const MAX_INSTANCE_ID_LEN: usize = 128;

/// Lease name for the per-certificate ACME renewal claim.
pub fn acme_renewal_lease_name(certificate_id: &str) -> String {
    format!("acme-renewal:{certificate_id}")
}

#[derive(Debug, Error)]
pub enum TlsLeaseError {
    #[error(transparent)]
    Store(#[from] SharedStoreError),
    #[error("TLS lease store path is invalid: {0}")]
    InvalidPath(String),
}

/// One persisted claim. Contains no material and no credentials.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TlsLeaseRecord {
    /// Opaque instance identity of the current holder.
    pub holder: String,
    pub acquired_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// Monotonic per-name counter bumped on every acquisition. A guard whose
    /// fence no longer matches has been superseded and must not renew, release,
    /// or act on the claim.
    pub fence: u64,
}

impl TlsLeaseRecord {
    pub fn is_live_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at > now
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TlsLeaseStoreFile {
    #[serde(default)]
    version: u64,
    #[serde(default)]
    leases: BTreeMap<String, TlsLeaseRecord>,
}

impl VersionedStoreFile for TlsLeaseStoreFile {
    fn store_version(&self) -> u64 {
        self.version
    }

    fn set_store_version(&mut self, version: u64) {
        self.version = version;
    }
}

/// Shared lease table for one managed-TLS store directory.
#[derive(Debug)]
pub struct TlsLeaseStore {
    holder: String,
    file: SharedStoreFile<TlsLeaseStoreFile>,
}

impl TlsLeaseStore {
    /// Open the lease table in `dir` under this process's instance identity.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, TlsLeaseError> {
        Self::open_with_holder(dir, process_instance_id().to_string())
    }

    /// Open the lease table under an explicit holder identity.
    ///
    /// Exposed so a deployment (or a two-instance test) can give two stores
    /// over the same directory the distinct identities two replicas would have.
    pub fn open_with_holder(
        dir: impl Into<PathBuf>,
        holder: String,
    ) -> Result<Self, TlsLeaseError> {
        let dir = dir.into();
        if dir.as_os_str().is_empty() {
            return Err(TlsLeaseError::InvalidPath(
                "store directory must not be empty".to_string(),
            ));
        }
        std::fs::create_dir_all(&dir).map_err(|error| {
            TlsLeaseError::InvalidPath(format!(
                "failed to create TLS lease store directory '{}': {error}",
                dir.display()
            ))
        })?;
        let file = SharedStoreFile::open(dir.join(LEASE_STORE_FILE_NAME))?;
        let holder = sanitize_instance_id(&holder);
        let holder = holder.unwrap_or_else(|| process_instance_id().to_string());
        Ok(Self { holder, file })
    }

    pub fn holder(&self) -> &str {
        &self.holder
    }

    /// Current record for `name`, live or expired. Diagnostics and tests only.
    pub fn peek(&self, name: &str) -> Result<Option<TlsLeaseRecord>, TlsLeaseError> {
        let document = self.file.snapshot()?;
        Ok(document.leases.get(name).cloned())
    }

    /// Claim `name` for `ttl`, or return `None` when another live holder owns it.
    ///
    /// The decision is made under the exclusive store lock against authoritative
    /// shared state, so exactly one instance can hold a given name at a time.
    pub fn try_acquire(
        self: &Arc<Self>,
        name: &str,
        ttl: Duration,
    ) -> Result<Option<TlsLeaseGuard>, TlsLeaseError> {
        let holder = self.holder.clone();
        let name_owned = name.to_string();
        let fence = self.file.mutate_if::<_, TlsLeaseError>(move |document| {
            let now = Utc::now();
            if let Some(existing) = document.leases.get(&name_owned)
                && existing.is_live_at(now)
                && existing.holder != holder
            {
                // Denied: another instance owns this claim. Publish nothing, so
                // a non-owner scanning every cycle does not rewrite the shared
                // document (and cannot lose a race it already lost).
                return Ok((false, None));
            }
            prune_expired(document, now);
            let fence = document
                .leases
                .get(&name_owned)
                .map(|existing| existing.fence)
                .unwrap_or(0)
                .saturating_add(1);
            let acquired_at = document
                .leases
                .get(&name_owned)
                .filter(|existing| existing.holder == holder && existing.is_live_at(now))
                .map(|existing| existing.acquired_at)
                .unwrap_or(now);
            document.leases.insert(
                name_owned.clone(),
                TlsLeaseRecord {
                    holder: holder.clone(),
                    acquired_at,
                    expires_at: now + lease_delta(ttl),
                    fence,
                },
            );
            Ok((true, Some(fence)))
        })?;
        let Some(fence) = fence else {
            return Ok(None);
        };
        Ok(Some(TlsLeaseGuard {
            store: Arc::clone(self),
            name: name.to_string(),
            fence,
            released: false,
        }))
    }

    /// Extend a claim this instance still owns. `false` means it was lost.
    pub fn renew(&self, guard: &TlsLeaseGuard, ttl: Duration) -> Result<bool, TlsLeaseError> {
        let holder = self.holder.clone();
        let name = guard.name.clone();
        let fence = guard.fence;
        self.file.mutate_if::<_, TlsLeaseError>(move |document| {
            let now = Utc::now();
            let Some(existing) = document.leases.get_mut(&name) else {
                return Ok((false, false));
            };
            if existing.holder != holder || existing.fence != fence || !existing.is_live_at(now) {
                return Ok((false, false));
            }
            existing.expires_at = now + lease_delta(ttl);
            Ok((true, true))
        })
    }

    fn release_claim(&self, name: &str, fence: u64) -> Result<bool, TlsLeaseError> {
        let holder = self.holder.clone();
        let name = name.to_string();
        self.file.mutate_if::<_, TlsLeaseError>(move |document| {
            let Some(existing) = document.leases.get_mut(&name) else {
                return Ok((false, false));
            };
            if existing.holder != holder || existing.fence != fence {
                // Superseded by another holder (or by a later acquisition):
                // releasing here would hand away a claim we no longer own.
                return Ok((false, false));
            }
            // Retain the record with an elapsed expiry rather than deleting it,
            // so the fence keeps advancing monotonically for this name.
            existing.expires_at = Utc::now();
            Ok((true, true))
        })
    }
}

/// A held lease. Releases on drop so a completed or aborted renewal does not
/// block another instance for the remainder of the TTL.
#[derive(Debug)]
pub struct TlsLeaseGuard {
    store: Arc<TlsLeaseStore>,
    name: String,
    fence: u64,
    released: bool,
}

impl TlsLeaseGuard {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn fence(&self) -> u64 {
        self.fence
    }

    pub fn holder(&self) -> &str {
        self.store.holder()
    }

    /// Extend this claim. `false` means another instance has taken it over and
    /// the caller must stop acting on it.
    pub fn renew(&self, ttl: Duration) -> Result<bool, TlsLeaseError> {
        self.store.renew(self, ttl)
    }

    /// Release explicitly, surfacing a persistence failure the `Drop` path can
    /// only log.
    pub fn release(mut self) -> Result<(), TlsLeaseError> {
        self.released = true;
        self.store.release_claim(&self.name, self.fence).map(|_| ())
    }
}

impl Drop for TlsLeaseGuard {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        // A failed release is not fatal: the lease expires on its own.
        if let Err(error) = self.store.release_claim(&self.name, self.fence) {
            tracing::warn!(
                lease = %self.name,
                error = %error,
                "failed to release TLS renewal lease; it will expire on its own"
            );
        }
    }
}

fn prune_expired(document: &mut TlsLeaseStoreFile, now: DateTime<Utc>) {
    let retention = chrono::TimeDelta::try_seconds(EXPIRED_LEASE_RETENTION_SECONDS)
        .unwrap_or_else(chrono::TimeDelta::zero);
    let cutoff = now - retention;
    document.leases.retain(|_, lease| lease.expires_at > cutoff);
}

/// Clamp a lease TTL into `chrono` space. Callers pass operator-clamped values;
/// this only guards against an unrepresentable duration.
fn lease_delta(ttl: Duration) -> chrono::TimeDelta {
    let millis = i64::try_from(ttl.as_millis());
    let millis = millis.unwrap_or(FALLBACK_LEASE_TTL_MILLIS);
    let delta = chrono::TimeDelta::try_milliseconds(millis);
    delta.unwrap_or_else(chrono::TimeDelta::zero)
}

/// Reduce a configured instance id to a bounded, printable identity.
fn sanitize_instance_id(raw: &str) -> Option<String> {
    let sanitized: String = raw
        .trim()
        .chars()
        .filter(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | ':')
        })
        .take(MAX_INSTANCE_ID_LEN)
        .collect();
    if sanitized.is_empty() {
        None
    } else {
        Some(sanitized)
    }
}

static PROCESS_INSTANCE_ID: OnceLock<String> = OnceLock::new();

/// Stable identity for this process's lease claims.
///
/// `FERRUM_TLS_STORE_INSTANCE_ID` lets an operator pin a stable per-replica
/// identity (for example a StatefulSet pod name) so a restarted replica can
/// reclaim its own live lease instead of waiting for it to expire. Otherwise a
/// per-process random identity is used, which is always distinct across
/// replicas.
pub fn process_instance_id() -> &'static str {
    PROCESS_INSTANCE_ID.get_or_init(|| {
        crate::config::env_config::tls_store_instance_id_from_env()
            .as_deref()
            .and_then(sanitize_instance_id)
            .unwrap_or_else(|| format!("pid{}-{}", std::process::id(), Uuid::new_v4().simple()))
    })
}

fn lease_store_dir_from_env() -> PathBuf {
    let path = crate::config::env_config::tls_managed_store_path_from_env();
    if path.is_empty() {
        PathBuf::from(DEFAULT_STORE_DIR)
    } else {
        PathBuf::from(path)
    }
}

static GLOBAL_TLS_LEASE_STORE: OnceLock<Result<Arc<TlsLeaseStore>, String>> = OnceLock::new();

pub fn global_lease_store() -> Result<Arc<TlsLeaseStore>, String> {
    GLOBAL_TLS_LEASE_STORE
        .get_or_init(|| {
            TlsLeaseStore::open(lease_store_dir_from_env())
                .map(Arc::new)
                .map_err(|error| error.to_string())
        })
        .clone()
}
