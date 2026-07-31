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
//!
//! # Exclusion is unconditional
//!
//! A **live** claim excludes every acquirer, including one presenting the same
//! holder identity. Two processes can legitimately share an identity —
//! `FERRUM_TLS_STORE_INSTANCE_ID` set to the same value by mistake, or the old
//! and new pod of an overlapping replacement — and letting the second one
//! reacquire would bump the fence and start a second renewal while the first is
//! still mid-ACME. There is therefore no "restart reclaims its own claim" fast
//! path: **crash recovery happens through expiry**, and a configured instance
//! id is validated strictly (never silently sanitized into a collision) so two
//! distinct configured values cannot converge onto one identity.
//!
//! # The TTL alone does not bound overlap
//!
//! ACME is not a fenced remote system: the CA honours an order regardless of
//! which replica believes it owns the renewal. So the claim has to stay alive
//! for the *whole* external operation, not just past the parts we predicted
//! would be slow. [`RenewalLeaseKeeper`] runs a heartbeat for the lifetime of a
//! renewal, extends the claim at a fraction of the TTL through
//! `spawn_blocking` (store I/O and locking are synchronous), fails closed on
//! any store error, and publishes a loss signal that the long-running async
//! ACME/hook/sleep/poll work selects against — so a lost claim cancels the
//! renewal before the next side effect instead of at the next explicit check.

use std::collections::BTreeMap;
use std::future::Future;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::watch;
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

/// Shortest heartbeat cadence, so a deliberately tiny test TTL still produces
/// useful beats without becoming a busy loop.
const MIN_HEARTBEAT_INTERVAL: Duration = Duration::from_millis(200);

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
    /// Fail-closed rejection of a configured instance identity. Carries only the
    /// rule that was broken — never the configured value, which is echoed back
    /// into logs and shared state.
    #[error("FERRUM_TLS_STORE_INSTANCE_ID is invalid: {0}")]
    InvalidInstanceId(String),
    /// A lease operation could not be driven to a conclusion (blocking task
    /// join failure). Treated as loss of ownership by every caller.
    #[error("TLS lease maintenance failed: {0}")]
    Maintenance(String),
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
        let holder = process_instance_id()?.to_string();
        Self::open_with_holder(dir, holder)
    }

    /// Open the lease table under an explicit holder identity.
    ///
    /// Exposed so a deployment (or a two-instance test) can give two stores
    /// over the same directory the distinct identities two replicas would have.
    /// The identity is validated, never sanitized: silently folding an invalid
    /// value onto some other identity is exactly how two replicas end up
    /// colliding on one claim.
    pub fn open_with_holder(
        dir: impl Into<PathBuf>,
        holder: String,
    ) -> Result<Self, TlsLeaseError> {
        let holder = validate_instance_id(&holder).map_err(TlsLeaseError::InvalidInstanceId)?;
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

    /// Claim `name` for `ttl`, or return `None` when a live claim already exists.
    ///
    /// The decision is made under the exclusive store lock against authoritative
    /// shared state, so exactly one instance can hold a given name at a time.
    ///
    /// **Any** live claim denies acquisition, including one stamped with this
    /// instance's own holder identity. Two processes sharing an identity (an
    /// operator pinning `FERRUM_TLS_STORE_INSTANCE_ID` to the same value twice,
    /// or an overlapping rolling replacement) would otherwise both believe they
    /// own the renewal while the first is still driving external ACME work; the
    /// fence would advance under it and it would only notice at its next
    /// explicit check. A crashed holder is recovered through expiry instead.
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
            {
                // Denied: a live claim exists. Publish nothing, so a non-owner
                // scanning every cycle does not rewrite the shared document
                // (and cannot lose a race it already lost).
                return Ok((false, None));
            }
            prune_expired(document, now);
            let fence = document
                .leases
                .get(&name_owned)
                .map(|existing| existing.fence)
                .unwrap_or(0)
                .saturating_add(1);
            document.leases.insert(
                name_owned.clone(),
                TlsLeaseRecord {
                    holder: holder.clone(),
                    acquired_at: now,
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

    /// Whether this instance still holds a live claim on `name` at `fence`.
    ///
    /// A read-only ownership check for the points either side of a synchronous
    /// commit, where "did we still own this when we wrote it" is the question
    /// and extending the claim would be wrong.
    pub fn is_owner(&self, name: &str, fence: u64) -> Result<bool, TlsLeaseError> {
        let document = self.file.snapshot()?;
        let now = Utc::now();
        Ok(document.leases.get(name).is_some_and(|existing| {
            existing.holder == self.holder && existing.fence == fence && existing.is_live_at(now)
        }))
    }

    /// Extend a claim this instance still owns. `false` means it was lost.
    pub fn renew(&self, guard: &TlsLeaseGuard, ttl: Duration) -> Result<bool, TlsLeaseError> {
        self.renew_claim(&guard.name, guard.fence, ttl)
    }

    /// [`Self::renew`] addressed by name and fence, for the heartbeat, which
    /// cannot borrow the guard the caller is still using.
    pub fn renew_claim(
        &self,
        name: &str,
        fence: u64,
        ttl: Duration,
    ) -> Result<bool, TlsLeaseError> {
        let holder = self.holder.clone();
        let name = name.to_string();
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

    fn store(&self) -> &Arc<TlsLeaseStore> {
        &self.store
    }
}

/// The shared claim was lost mid-operation: it expired and was taken over, or
/// the lease table could not be reached. Either way this instance must stop
/// producing side effects for the operation immediately.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("the shared TLS renewal claim was lost")]
pub struct RenewalLeaseLost;

/// Keeps a renewal claim alive for the whole external operation and cancels the
/// operation the moment it cannot.
///
/// The claim's TTL is not a bound on overlap by itself: the ACME directory does
/// not honour Ferrum's fence, so a certificate order, a DNS-01 hook, a
/// propagation wait, or an authorization poll that outlives the TTL lets a
/// second replica acquire and start ordering while the first is still running.
/// The keeper closes that window:
///
/// * a heartbeat extends the claim every `ttl / 3` (never faster than
///   [`MIN_HEARTBEAT_INTERVAL`]), so the TTL only has to cover one beat plus
///   scheduling slack rather than an entire ACME cycle;
/// * every extension runs inside `spawn_blocking`, because the store's I/O and
///   its advisory lock are synchronous and must not occupy a runtime worker;
/// * **any** heartbeat outcome other than "still ours" — takeover, store error,
///   or a task that could not be joined — is fail-closed loss;
/// * loss is published on a `watch` channel that [`Self::guarded`] selects
///   against, so long-running async work is abandoned at its next await point
///   instead of at the next explicit check;
/// * [`Self::ensure_owned`] is the synchronous-commit companion: it re-reads
///   authoritative state without extending anything, for the checks either side
///   of a store write and before publishing final certificate/order state.
///
/// A crashed process runs no heartbeat, so its claim expires and the
/// certificate becomes reclaimable exactly as before.
#[derive(Debug)]
pub struct RenewalLeaseKeeper {
    guard: Option<TlsLeaseGuard>,
    store: Arc<TlsLeaseStore>,
    name: String,
    fence: u64,
    lost_tx: Arc<watch::Sender<bool>>,
    lost_rx: watch::Receiver<bool>,
    heartbeat: Option<tokio::task::JoinHandle<()>>,
}

impl RenewalLeaseKeeper {
    /// Take over `guard` and start heartbeating it.
    pub fn start(guard: TlsLeaseGuard, ttl: Duration) -> Self {
        let store = Arc::clone(guard.store());
        let name = guard.name().to_string();
        let fence = guard.fence();
        let (lost_tx, lost_rx) = watch::channel(false);
        let lost_tx = Arc::new(lost_tx);
        let heartbeat = tokio::spawn(heartbeat_loop(
            Arc::clone(&store),
            name.clone(),
            fence,
            ttl,
            Arc::clone(&lost_tx),
        ));
        Self {
            guard: Some(guard),
            store,
            name,
            fence,
            lost_tx,
            lost_rx,
            heartbeat: Some(heartbeat),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn fence(&self) -> u64 {
        self.fence
    }

    /// Whether the claim has already been observed as lost.
    pub fn is_lost(&self) -> bool {
        *self.lost_rx.borrow()
    }

    /// Run `future`, abandoning it if the claim is lost while it is in flight.
    ///
    /// This is how ACME network calls, provider hooks, propagation sleeps, and
    /// readiness polls stop producing side effects promptly rather than at some
    /// later checkpoint.
    pub async fn guarded<F>(&self, future: F) -> Result<F::Output, RenewalLeaseLost>
    where
        F: Future,
    {
        if self.is_lost() {
            return Err(RenewalLeaseLost);
        }
        let mut lost = self.lost_rx.clone();
        tokio::select! {
            biased;
            _ = lost.wait_for(|lost| *lost) => Err(RenewalLeaseLost),
            output = future => Ok(output),
        }
    }

    /// Confirm this instance still owns the claim, without extending it.
    ///
    /// Fail-closed: a store error is loss, and marks the keeper lost so any
    /// concurrently [`guarded`](Self::guarded) work is cancelled too.
    pub async fn ensure_owned(&self) -> Result<(), RenewalLeaseLost> {
        if self.is_lost() {
            return Err(RenewalLeaseLost);
        }
        let store = Arc::clone(&self.store);
        let name = self.name.clone();
        let fence = self.fence;
        let owned = tokio::task::spawn_blocking(move || store.is_owner(&name, fence)).await;
        match owned {
            Ok(Ok(true)) => Ok(()),
            Ok(Ok(false)) => {
                tracing::warn!(
                    lease = %self.name,
                    "the shared TLS renewal claim is no longer held by this instance"
                );
                self.mark_lost();
                Err(RenewalLeaseLost)
            }
            Ok(Err(error)) => {
                tracing::warn!(
                    lease = %self.name,
                    error = %error,
                    "could not confirm ownership of the shared TLS renewal claim"
                );
                self.mark_lost();
                Err(RenewalLeaseLost)
            }
            Err(error) => {
                tracing::warn!(
                    lease = %self.name,
                    error = %error,
                    "TLS renewal claim ownership check could not be joined"
                );
                self.mark_lost();
                Err(RenewalLeaseLost)
            }
        }
    }

    fn mark_lost(&self) {
        let _ = self.lost_tx.send(true);
    }

    /// Stop the heartbeat, wait for it to settle, then release the claim.
    ///
    /// The release also runs on a blocking thread, because it is another
    /// synchronous read-modify-write under the store's advisory lock.
    pub async fn finish(mut self) -> Result<(), TlsLeaseError> {
        self.stop_heartbeat().await;
        let Some(guard) = self.guard.take() else {
            return Ok(());
        };
        match tokio::task::spawn_blocking(move || guard.release()).await {
            Ok(result) => result,
            Err(error) => Err(TlsLeaseError::Maintenance(format!(
                "renewal claim release task failed: {error}"
            ))),
        }
    }

    async fn stop_heartbeat(&mut self) {
        let Some(handle) = self.heartbeat.take() else {
            return;
        };
        handle.abort();
        // Join so the heartbeat cannot still be mid-`spawn_blocking` extension
        // while the release below removes the claim.
        let _ = handle.await;
    }
}

impl Drop for RenewalLeaseKeeper {
    fn drop(&mut self) {
        // Without this an abandoned keeper would keep extending a claim nobody
        // is acting on until the process exits.
        if let Some(handle) = self.heartbeat.take() {
            handle.abort();
        }
    }
}

/// Extend the claim until it is lost or the task is aborted.
async fn heartbeat_loop(
    store: Arc<TlsLeaseStore>,
    name: String,
    fence: u64,
    ttl: Duration,
    lost_tx: Arc<watch::Sender<bool>>,
) {
    let interval = heartbeat_interval(ttl);
    loop {
        tokio::time::sleep(interval).await;
        let store = Arc::clone(&store);
        let beat_name = name.clone();
        let outcome =
            tokio::task::spawn_blocking(move || store.renew_claim(&beat_name, fence, ttl)).await;
        match outcome {
            Ok(Ok(true)) => continue,
            Ok(Ok(false)) => {
                tracing::warn!(
                    lease = %name,
                    "the shared TLS renewal claim was taken over by another instance"
                );
            }
            Ok(Err(error)) => {
                // Fail closed. An unwritable lease table means ownership can no
                // longer be asserted, so the renewal must stop rather than keep
                // producing ACME side effects on an assumption.
                tracing::warn!(
                    lease = %name,
                    error = %error,
                    "could not extend the shared TLS renewal claim; abandoning the renewal"
                );
            }
            Err(error) => {
                tracing::warn!(
                    lease = %name,
                    error = %error,
                    "TLS renewal claim heartbeat could not be joined; abandoning the renewal"
                );
            }
        }
        let _ = lost_tx.send(true);
        return;
    }
}

/// Beat at a third of the TTL so a single missed or slow extension does not
/// expire the claim.
fn heartbeat_interval(ttl: Duration) -> Duration {
    let floor = MIN_HEARTBEAT_INTERVAL;
    let ceiling = ttl.max(floor);
    (ttl / 3).max(floor).min(ceiling)
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

/// Accept a configured instance id verbatim, or reject it.
///
/// Deliberately **not** a sanitizer. Dropping disallowed characters or
/// truncating an overlong value maps two distinct configured identities onto
/// one — `pod-a/1` and `pod-a1`, or two pod names sharing a 128-character
/// prefix — and a collision here is what lets a second process reacquire a live
/// claim. An unusable value fails closed instead, so the misconfiguration is
/// visible at startup rather than as a duplicate ACME order weeks later.
///
/// The error names the rule, never the value: the id is operator-supplied text
/// that flows into logs and shared state.
fn validate_instance_id(raw: &str) -> Result<String, String> {
    if raw.is_empty() {
        return Err("must not be empty".to_string());
    }
    if raw.chars().count() > MAX_INSTANCE_ID_LEN {
        return Err(format!(
            "must be at most {MAX_INSTANCE_ID_LEN} characters (got {})",
            raw.chars().count()
        ));
    }
    let permitted = |character: char| {
        character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | ':')
    };
    if !raw.chars().all(permitted) {
        return Err(
            "must contain only ASCII letters, digits, '-', '_', '.', or ':'".to_string(),
        );
    }
    Ok(raw.to_string())
}

static PROCESS_INSTANCE_ID: OnceLock<Result<String, String>> = OnceLock::new();

/// Stable identity for this process's lease claims.
///
/// `FERRUM_TLS_STORE_INSTANCE_ID` lets an operator pin a stable per-replica
/// identity (for example a StatefulSet pod name) so ownership is attributable
/// in the shared lease table and in logs. It does **not** let a restarted
/// replica reclaim its own still-live claim: a live claim excludes every
/// acquirer, and a crashed holder is recovered through expiry.
///
/// A configured value that is empty, overlong, or contains disallowed
/// characters is an error. The generated fallback is always valid and always
/// distinct across processes.
pub fn process_instance_id() -> Result<&'static str, TlsLeaseError> {
    let resolved = PROCESS_INSTANCE_ID.get_or_init(|| {
        match crate::config::env_config::tls_store_instance_id_from_env() {
            Some(configured) => validate_instance_id(&configured),
            None => Ok(format!(
                "pid{}-{}",
                std::process::id(),
                Uuid::new_v4().simple()
            )),
        }
    });
    match resolved {
        Ok(identity) => Ok(identity.as_str()),
        Err(reason) => Err(TlsLeaseError::InvalidInstanceId(reason.clone())),
    }
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
