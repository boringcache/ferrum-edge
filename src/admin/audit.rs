//! Admin API audit logging.
//!
//! When enabled, audit events are written through a bounded worker queue per
//! database backend. The HTTP mutation path never waits for queue capacity; if
//! the bounded queue is full, enqueue fails fast and the committed mutation
//! response can proceed after logging the audit failure. Audit persistence is
//! best-effort and happens after the mutation response path has enqueued the
//! event.
//!
//! Security-sensitive surfaces that must not release unredacted material without
//! a durable record (notably `GET /backup`) use [`admit_security_sensitive_event`]
//! instead. That path is unconditional — independent of
//! `FERRUM_ADMIN_AUDIT_ENABLED` — and awaits a synchronous database insert when
//! a backend is available, otherwise appending to a bounded local fallback file
//! so capture does not depend solely on the same unavailable primary used for
//! config load. General mutation delivery-loss hardening remains issue #2421 and
//! is out of scope for the backup-specific admit path.

use crate::admin::jwt_auth::{AdminClaims, AdminRole};
use crate::config::db_backend::DatabaseBackend;
use anyhow::anyhow;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, TryLockError, Weak};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::time::{Duration, MissedTickBehavior, interval};
use tracing::{error, info, warn};
use uuid::Uuid;

const AUDIT_CHANNEL_CAPACITY: usize = 1024;
const AUDIT_SINK_STALE_CHECK_INTERVAL_SECONDS: u64 = 60;
/// Max accepted client-supplied admin request/correlation ID length.
pub const AUDIT_REQUEST_ID_MAX_LEN: usize = 128;
/// Bound on local fallback events retained on disk (newest kept).
pub const AUDIT_LOCAL_FALLBACK_CAPACITY: usize = 4_096;
const AUDIT_LOCAL_FALLBACK_FILE_NAME: &str = "admin-audit-fallback.json";
const AUDIT_LOCAL_FALLBACK_LOCK_FILE_NAME: &str = "admin-audit-fallback.lock";
const AUDIT_LOCAL_FALLBACK_DEFAULT_DIR: &str = "./ferrum-admin-audit";

/// Closed allow-list of backup resource filter names persisted in audit events.
pub const BACKUP_AUDIT_RESOURCE_NAMES: &[&str] = &[
    "proxies",
    "consumers",
    "plugin_configs",
    "upstreams",
    "api_specs",
];
/// Fixed non-sensitive sentinel when a filter contained unknown tokens.
pub const BACKUP_RESOURCES_INVALID_SENTINEL: &str = "invalid";

/// Fixed-cardinality outcomes stored on [`AuditEvent::outcome`].
///
/// Typed so callers cannot persist arbitrary outcome strings through the
/// security-sensitive builder API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOutcome {
    Success,
    Denied,
    ValidationFailed,
    Unavailable,
}

impl AuditOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Denied => "denied",
            Self::ValidationFailed => "validation_failed",
            Self::Unavailable => "unavailable",
        }
    }
}

/// Fixed-cardinality failure categories for backup audit `diff` payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupFailureCategory {
    Forbidden,
    NamespaceDenied,
    ValidationFailed,
    Unavailable,
}

impl BackupFailureCategory {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Forbidden => "forbidden",
            Self::NamespaceDenied => "namespace_denied",
            Self::ValidationFailed => "validation_failed",
            Self::Unavailable => "unavailable",
        }
    }
}

/// Convenience aliases for closed backup audit outcomes.
pub mod outcome {
    use super::AuditOutcome;
    pub const SUCCESS: AuditOutcome = AuditOutcome::Success;
    pub const DENIED: AuditOutcome = AuditOutcome::Denied;
    pub const VALIDATION_FAILED: AuditOutcome = AuditOutcome::ValidationFailed;
    pub const UNAVAILABLE: AuditOutcome = AuditOutcome::Unavailable;
}

/// Convenience aliases for closed backup failure categories.
pub mod failure_category {
    use super::BackupFailureCategory;
    pub const FORBIDDEN: BackupFailureCategory = BackupFailureCategory::Forbidden;
    pub const NAMESPACE_DENIED: BackupFailureCategory = BackupFailureCategory::NamespaceDenied;
    pub const VALIDATION_FAILED: BackupFailureCategory = BackupFailureCategory::ValidationFailed;
    pub const UNAVAILABLE: BackupFailureCategory = BackupFailureCategory::Unavailable;
}

/// Upper bound for `FERRUM_AUDIT_RETENTION_DAYS` (100 years).
pub const AUDIT_RETENTION_DAYS_MAX: u64 = 36_500;
/// Upper bound for `FERRUM_AUDIT_RETENTION_MAX_ROWS` per namespace.
pub const AUDIT_RETENTION_MAX_ROWS_CAP: u64 = 10_000_000;
/// Default durable audit-event cap per namespace. Audit logging must not remain
/// unbounded merely because the operator did not discover a retention knob.
pub const AUDIT_RETENTION_MAX_ROWS_DEFAULT: u64 = 100_000;
/// Rows deleted per prune statement so a multi-million-row backlog cannot hold
/// a write lock for one unbounded DELETE / deleteMany.
pub const AUDIT_RETENTION_PRUNE_BATCH_SIZE: u64 = 1_000;
/// Max DELETE batches per prune call so insert-path piggyback stays bounded.
pub const AUDIT_RETENTION_PRUNE_MAX_BATCHES: u32 = 8;
/// Soft-cap cadence for max-row boundary scans on the insert path.
///
/// Finding the excess boundary requires newest-first `OFFSET max_rows`, which
/// is O(max_rows) index work. Steady-state inserts therefore skip that scan
/// until this many additional inserts (per gateway instance, per namespace)
/// have landed since the last verified at-or-under-cap check — unless the
/// namespace has not been checked yet or a prior prune hit the per-call batch
/// budget. Equals the prune batch size so soft overshoot stays small and
/// deterministic.
pub const AUDIT_RETENTION_MAX_ROWS_CHECK_INTERVAL: u64 = AUDIT_RETENTION_PRUNE_BATCH_SIZE;
/// Max per-gateway-instance namespaces tracked for insert-path max-row prune
/// cadence. When the map is full and a namespace has no entry, inserts behave
/// as if the gate required a boundary scan (no new entry is inserted).
pub const AUDIT_MAX_ROWS_PRUNE_GATES_CAP: usize = 256;

static AUDIT_SINKS: LazyLock<DashMap<usize, AuditSinkEntry>> = LazyLock::new(DashMap::new);

/// Per-namespace insert-path gate for max-row retention scans.
///
/// `FERRUM_AUDIT_RETENTION_MAX_ROWS` is a soft cap: after a verified
/// at-or-under-cap observation, one gateway instance may admit up to
/// [`audit_retention_max_rows_check_interval`] further inserts for that
/// namespace before the next O(max_rows) boundary scan. When a scan finds
/// excess and the bounded delete budget is exhausted, `scan_pending` keeps
/// subsequent inserts pruning immediately so backlog drains promptly. A new
/// gate also starts pending so the first successful insert checks any backlog
/// that predates this process. Explicit `prune_audit_events` calls always force
/// a scan. Multiple gateway instances each keep their own gate, so worst-case
/// soft overshoot scales with instance count × interval; deletes remain
/// namespace-scoped and idempotent.
#[derive(Debug, Clone)]
pub struct AuditMaxRowsPruneGate {
    inserts_since_check: u64,
    scan_pending: bool,
}

impl Default for AuditMaxRowsPruneGate {
    fn default() -> Self {
        Self {
            inserts_since_check: 0,
            scan_pending: true,
        }
    }
}

impl AuditMaxRowsPruneGate {
    /// Whether this insert (or forced prune) should run the max-rows boundary scan.
    pub fn should_run_max_rows_prune(&mut self, max_rows: u64, force: bool) -> bool {
        if force || self.scan_pending {
            return true;
        }
        self.inserts_since_check = self.inserts_since_check.saturating_add(1);
        self.inserts_since_check >= audit_retention_max_rows_check_interval(max_rows)
    }

    /// Record the outcome of a max-rows prune so the next insert can either
    /// resume soft-cap cadence or keep draining.
    pub fn note_max_rows_prune_result(&mut self, hit_batch_budget: bool) {
        self.inserts_since_check = 0;
        self.scan_pending = hit_batch_budget;
    }
}

/// Resolve whether insert-path max-row pruning should run for `namespace`.
///
/// When the gate map is at [`AUDIT_MAX_ROWS_PRUNE_GATES_CAP`] and `namespace`
/// has no entry, returns `true` without inserting so every insert pays the
/// bounded boundary query (cheap for low-row namespaces).
pub fn audit_max_rows_prune_gate_should_run(
    gates: &DashMap<String, AuditMaxRowsPruneGate>,
    namespace: &str,
    max_rows: u64,
    force: bool,
) -> bool {
    if force {
        return true;
    }
    if let Some(mut gate) = gates.get_mut(namespace) {
        return gate.should_run_max_rows_prune(max_rows, false);
    }
    if gates.len() >= AUDIT_MAX_ROWS_PRUNE_GATES_CAP {
        return true;
    }
    let mut gate = gates.entry(namespace.to_string()).or_default();
    gate.should_run_max_rows_prune(max_rows, false)
}

/// Soft-overshoot interval for a configured per-namespace max-row cap.
pub fn audit_retention_max_rows_check_interval(max_rows: u64) -> u64 {
    AUDIT_RETENTION_MAX_ROWS_CHECK_INTERVAL.min(max_rows).max(1)
}

/// True when a prune deleted a full per-call budget and may still have excess.
pub fn audit_retention_hit_prune_batch_budget(deleted: u64) -> bool {
    deleted
        >= AUDIT_RETENTION_PRUNE_BATCH_SIZE
            .saturating_mul(u64::from(AUDIT_RETENTION_PRUNE_MAX_BATCHES))
}

/// Per-namespace audit-event retention policy from env/config.
///
/// Distinct from delivery-loss hardening (#2421): this only bounds durable
/// `audit_events` growth after successful inserts. Unset fields disable that
/// half of the policy. When both are unset, stores skip prune work entirely.
///
/// Max-row retention is a soft cap enforced with a bounded per-instance insert
/// cadence (see [`AuditMaxRowsPruneGate`]); age retention uses strict
/// `ts < cutoff` on every piggybacked prune.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditRetentionPolicy {
    /// Delete events older than this many days (strict `ts < cutoff`).
    pub retention_days: Option<u64>,
    /// Soft per-namespace row cap: keep the newest N events by `(ts, id)`,
    /// allowing a documented bounded overshoot between insert-path checks.
    pub max_rows_per_namespace: Option<u64>,
}

impl Default for AuditRetentionPolicy {
    fn default() -> Self {
        Self {
            retention_days: None,
            max_rows_per_namespace: Some(AUDIT_RETENTION_MAX_ROWS_DEFAULT),
        }
    }
}

impl AuditRetentionPolicy {
    pub fn is_enabled(&self) -> bool {
        self.retention_days.is_some() || self.max_rows_per_namespace.is_some()
    }

    /// Emit one startup log line when a retention policy is active.
    pub fn log_if_enabled(&self) {
        if self.is_enabled() {
            info!(
                retention_days = ?self.retention_days,
                max_rows_per_namespace = ?self.max_rows_per_namespace,
                "Audit event retention policy active"
            );
        }
    }

    /// Validate operator-supplied optional retention knobs.
    pub fn from_parts(
        retention_days: Option<u64>,
        max_rows_per_namespace: Option<u64>,
    ) -> Result<Self, String> {
        if let Some(days) = retention_days {
            if days == 0 {
                return Err(
                    "FERRUM_AUDIT_RETENTION_DAYS must be greater than zero when set".to_string(),
                );
            }
            if days > AUDIT_RETENTION_DAYS_MAX {
                return Err(format!(
                    "FERRUM_AUDIT_RETENTION_DAYS must not exceed {AUDIT_RETENTION_DAYS_MAX}"
                ));
            }
        }
        let max_rows_per_namespace = match max_rows_per_namespace {
            Some(0) => None,
            Some(max_rows) => {
                if max_rows > AUDIT_RETENTION_MAX_ROWS_CAP {
                    return Err(format!(
                        "FERRUM_AUDIT_RETENTION_MAX_ROWS must not exceed \
                         {AUDIT_RETENTION_MAX_ROWS_CAP}"
                    ));
                }
                Some(max_rows)
            }
            None => None,
        };
        Ok(Self {
            retention_days,
            max_rows_per_namespace,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: String,
    pub ts: DateTime<Utc>,
    pub actor: String,
    pub action: String,
    pub resource_type: String,
    pub resource_id: String,
    pub namespace: String,
    /// Canonical peer/source address for the admin connection. Never derived
    /// from client-spoofable forwarding headers. Empty for legacy mutation
    /// events that predate request-context capture.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source_address: String,
    /// Bounded request/correlation ID (client-supplied when valid, otherwise
    /// generated). Empty for legacy mutation events.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub request_id: String,
    /// Fixed-cardinality outcome (`success`, `denied`, `validation_failed`,
    /// `unavailable`). Empty for legacy mutation events that only recorded
    /// successful commits. Set only through [`AuditEvent::with_outcome`].
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub outcome: String,
    pub diff: Value,
}

/// Trustworthy per-request context carried through the admin dispatcher into
/// security-sensitive audit events. Source address is always the socket peer;
/// request IDs are validated/bounded before storage.
#[derive(Debug, Clone)]
pub struct AuditRequestContext {
    pub source_address: String,
    pub request_id: String,
}

impl AuditRequestContext {
    pub fn from_peer_and_headers(peer: IpAddr, headers: &hyper::HeaderMap) -> Self {
        Self {
            source_address: crate::util::client_identity::canonical_ip_string(peer),
            request_id: extract_or_generate_request_id(headers),
        }
    }
}

impl AuditEvent {
    pub fn new(
        actor: &AuditActor,
        action: impl Into<String>,
        resource_type: impl Into<String>,
        resource_id: impl Into<String>,
        namespace: impl Into<String>,
        diff: Value,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            ts: Utc::now(),
            actor: actor.sub.clone(),
            action: action.into(),
            resource_type: resource_type.into(),
            resource_id: resource_id.into(),
            namespace: namespace.into(),
            source_address: String::new(),
            request_id: String::new(),
            outcome: String::new(),
            diff,
        }
    }

    pub fn with_request_context(mut self, ctx: &AuditRequestContext) -> Self {
        self.source_address = ctx.source_address.clone();
        self.request_id = ctx.request_id.clone();
        self
    }

    pub fn with_outcome(mut self, outcome: AuditOutcome) -> Self {
        self.outcome = outcome.as_str().to_string();
        self
    }
}

#[derive(Debug, Clone)]
pub struct AuditActor {
    pub sub: String,
    pub role: AdminRole,
    /// Namespaces authorized by the token's optional `ns` claim. Parsed
    /// fail-closed at authentication time (a malformed claim rejects the
    /// token); only *enforced* against `X-Ferrum-Namespace` when
    /// `FERRUM_ADMIN_REQUIRE_NAMESPACE_CLAIM=true`.
    pub allowed_namespaces: crate::grpc::auth::AllowedNamespaces,
}

impl AuditActor {
    pub fn from_claims(claims: &AdminClaims) -> Result<Self, String> {
        Ok(Self {
            sub: claims.sub.clone(),
            role: claims.admin_role()?,
            allowed_namespaces: claims.allowed_namespaces()?,
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct AuditListFilter {
    pub actor: Option<String>,
    pub action: Option<String>,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub start: Option<DateTime<Utc>>,
    pub end: Option<DateTime<Utc>>,
    pub limit: u32,
    pub offset: u32,
}

#[derive(Clone)]
struct AuditSink {
    tx: mpsc::Sender<AuditEnvelope>,
}

#[derive(Clone)]
struct AuditSinkEntry {
    backend: Weak<dyn DatabaseBackend>,
    sink: AuditSink,
}

struct AuditEnvelope {
    event: AuditEvent,
}

impl AuditSink {
    fn spawn(key: usize, db: Weak<dyn DatabaseBackend>) -> Self {
        let (tx, mut rx) = mpsc::channel::<AuditEnvelope>(AUDIT_CHANNEL_CAPACITY);
        tokio::spawn(async move {
            let mut stale_check =
                interval(Duration::from_secs(AUDIT_SINK_STALE_CHECK_INTERVAL_SECONDS));
            stale_check.set_missed_tick_behavior(MissedTickBehavior::Delay);

            loop {
                tokio::select! {
                    maybe_envelope = rx.recv() => {
                        let Some(envelope) = maybe_envelope else {
                            break;
                        };

                        let Some(db) = db.upgrade() else {
                            remove_stale_sink(key);
                            error!(
                                audit_event_id = %envelope.event.id,
                                "Dropped admin audit event because the backend is unavailable"
                            );
                            break;
                        };

                        if db.insert_audit_event(&envelope.event).await.is_err() {
                            error!(
                                audit_event_id = %envelope.event.id,
                                surface = "audit_event_persist",
                                detail_withheld = true,
                                "Failed to persist admin audit event; persistence detail withheld"
                            );
                        }
                    }
                    _ = stale_check.tick() => {
                        if db.upgrade().is_none() {
                            remove_stale_sink(key);
                            break;
                        }
                    }
                }
            }
        });
        Self { tx }
    }

    fn record(&self, event: AuditEvent) -> Result<(), anyhow::Error> {
        self.tx
            .try_send(AuditEnvelope { event })
            .map_err(|error| match error {
                TrySendError::Full(envelope) => anyhow!(
                    "admin audit queue is full; audit event {} was not enqueued",
                    envelope.event.id
                ),
                TrySendError::Closed(_) => anyhow!("admin audit worker is unavailable"),
            })
    }
}

fn db_key(db: &Arc<dyn DatabaseBackend>) -> usize {
    // Handler clones share this inner pointer, so the address is a stable
    // per-backend worker key while the backend Arc is alive. Stale entries are
    // tied to a Weak backend reference and removed once that backend drops.
    Arc::as_ptr(db) as *const () as usize
}

fn remove_stale_sink(key: usize) {
    AUDIT_SINKS.remove_if(&key, |_, entry| entry.backend.upgrade().is_none());
}

fn entry_matches_backend(entry: &AuditSinkEntry, db: &Arc<dyn DatabaseBackend>) -> bool {
    entry
        .backend
        .upgrade()
        .is_some_and(|existing| Arc::ptr_eq(&existing, db))
}

fn sink_for_db(db: Arc<dyn DatabaseBackend>) -> AuditSink {
    let key = db_key(&db);
    // Fast path: live entry for this exact backend pointer.
    if let Some(entry) = AUDIT_SINKS.get(&key)
        && entry_matches_backend(&entry, &db)
    {
        return entry.sink.clone();
    }

    // Slow path: take the entry write lock so the spawn-and-insert is atomic.
    // Without this, two threads can both miss the `get`, both spawn a worker,
    // and only one survives — leaving the other's mpsc Sender to be dropped at
    // the end of `record`, which closes that orphan worker before its event is
    // processed. Holding the entry lock across the live-check + spawn + insert
    // guarantees one worker per backend Arc.
    let entry = AUDIT_SINKS.entry(key).or_insert_with(|| {
        let backend = Arc::downgrade(&db);
        let sink = AuditSink::spawn(key, backend.clone());
        AuditSinkEntry { backend, sink }
    });
    if entry_matches_backend(&entry, &db) {
        return entry.sink.clone();
    }

    // The existing entry references a different (stale) backend at the same
    // address — drop it and retry. Calling `remove` while still holding the
    // RefMut would deadlock, so release it first.
    drop(entry);
    AUDIT_SINKS.remove(&key);
    let backend = Arc::downgrade(&db);
    let sink = AuditSink::spawn(key, backend.clone());
    AUDIT_SINKS.insert(
        key,
        AuditSinkEntry {
            backend,
            sink: sink.clone(),
        },
    );
    sink
}

pub fn record(
    enabled: bool,
    db: Arc<dyn DatabaseBackend>,
    event: AuditEvent,
) -> Result<(), anyhow::Error> {
    if !enabled {
        return Ok(());
    }

    let sink = sink_for_db(Arc::clone(&db));
    sink.record(event)
}

pub fn create_diff(after: Value) -> Value {
    json!({ "after": after })
}

pub fn update_diff(before: Value, after: Value) -> Value {
    json!({ "before": before, "after": after })
}

pub fn credential_update_diff(credential_type: &str, before: Value, after: Value) -> Value {
    json!({
        "credential_type": credential_type,
        "credential_change": "[REDACTED]",
        "before": before,
        "after": after,
    })
}

pub fn delete_diff(before: Value) -> Value {
    json!({ "before": before })
}

/// Which durable sink admitted a security-sensitive audit event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditAdmitSink {
    /// Synchronous insert into the primary audit store.
    Database,
    /// Bounded local fallback file (used when the primary store is absent or
    /// rejected the insert, including cached-backup paths).
    LocalFallback,
}

/// Resolve the local audit fallback directory from env/config, defaulting to
/// [`AUDIT_LOCAL_FALLBACK_DEFAULT_DIR`].
pub fn audit_local_fallback_dir() -> PathBuf {
    crate::config::conf_file::resolve_ferrum_var("FERRUM_ADMIN_AUDIT_FALLBACK_PATH")
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(AUDIT_LOCAL_FALLBACK_DEFAULT_DIR))
}

fn audit_local_fallback_file(dir: &Path) -> PathBuf {
    dir.join(AUDIT_LOCAL_FALLBACK_FILE_NAME)
}

/// Extract a bounded request/correlation ID from admin headers, or mint one.
///
/// Accepts `X-Request-Id` or `X-Correlation-Id` only when every character is in
/// a conservative printable allow-list and length ≤ [`AUDIT_REQUEST_ID_MAX_LEN`].
/// Invalid or missing values are replaced with a fresh UUID — the rejected
/// header bytes are never stored or logged.
pub fn extract_or_generate_request_id(headers: &hyper::HeaderMap) -> String {
    for name in ["x-request-id", "x-correlation-id"] {
        if let Some(value) = headers.get(name).and_then(|v| v.to_str().ok())
            && is_safe_request_id(value)
        {
            return value.to_string();
        }
    }
    Uuid::new_v4().to_string()
}

fn is_safe_request_id(value: &str) -> bool {
    if value.is_empty() || value.len() > AUDIT_REQUEST_ID_MAX_LEN {
        return false;
    }
    value
        .bytes()
        .all(|b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b':'))
}

/// Fixed-shape backup success diff. Never includes payload bytes or secrets.
pub fn backup_success_diff(
    data_source: &str,
    resources: Value,
    counts: Value,
    bytes: usize,
) -> Value {
    json!({
        "data_source": data_source,
        "resources": resources,
        "counts": counts,
        "bytes": bytes,
    })
}

/// Fixed-shape backup failure/denied diff. Categories are closed enums only.
pub fn backup_failure_diff(category: BackupFailureCategory, resources: Value) -> Value {
    json!({
        "failure_category": category.as_str(),
        "resources": resources,
    })
}

/// Whether `name` is a canonical backup resource filter token.
pub fn is_canonical_backup_resource(name: &str) -> bool {
    BACKUP_AUDIT_RESOURCE_NAMES.contains(&name)
}

/// Canonical resource-filter representation for audit events.
///
/// - Unfiltered → `"all"`
/// - Only allow-listed names → sorted JSON array of those names
/// - Any unknown token → fixed `"invalid"` sentinel (never the raw token)
pub fn backup_resources_audit_value(filter: Option<&std::collections::HashSet<&str>>) -> Value {
    match filter {
        None => json!("all"),
        Some(set) => {
            let mut names: Vec<&str> = Vec::with_capacity(set.len());
            for name in set.iter().copied() {
                if is_canonical_backup_resource(name) {
                    names.push(name);
                } else {
                    // Never persist or log the unknown raw token.
                    return json!(BACKUP_RESOURCES_INVALID_SENTINEL);
                }
            }
            names.sort_unstable();
            json!(names)
        }
    }
}

/// Admit a security-sensitive audit event before releasing unredacted material.
///
/// Backup security auditing is unconditional and independent of
/// `FERRUM_ADMIN_AUDIT_ENABLED` (which gates ordinary mutation audit events
/// only):
/// 1. Prefer a synchronous `insert_audit_event` on the provided backend.
/// 2. If no backend is present or the insert fails, append to the bounded local
///    fallback file under `fallback_dir` (or the configured default) on a
///    blocking worker so admin Tokio tasks are not stalled on disk I/O.
/// 3. If neither sink admits the event, return an error so the caller can fail
///    closed without emitting the sensitive response body.
///
/// This is intentionally narrower than #2421 (general mutation durability): it
/// only covers surfaces that must not silently export secrets without a record.
pub async fn admit_security_sensitive_event(
    db: Option<&Arc<dyn DatabaseBackend>>,
    event: &AuditEvent,
    fallback_dir: Option<&Path>,
) -> Result<AuditAdmitSink, anyhow::Error> {
    if let Some(db) = db {
        match db.insert_audit_event(event).await {
            Ok(()) => return Ok(AuditAdmitSink::Database),
            Err(_error) => {
                // Detail withheld: the primary may be the same unavailable store
                // that forced a cached backup. Fall through to local capture.
                warn!(
                    audit_event_id = %event.id,
                    surface = "audit_security_admit_database",
                    detail_withheld = true,
                    "Primary audit store rejected a security-sensitive event; trying local fallback"
                );
            }
        }
    }

    let dir = fallback_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(audit_local_fallback_dir);
    let event_id = event.id.clone();
    let event = event.clone();
    let join = tokio::task::spawn_blocking(move || append_local_fallback_event(&dir, &event)).await;
    match join {
        Ok(Ok(())) => Ok(AuditAdmitSink::LocalFallback),
        Ok(Err(_error)) | Err(_) => {
            error!(
                audit_event_id = %event_id,
                surface = "audit_security_admit_local_fallback",
                detail_withheld = true,
                "Failed to admit security-sensitive audit event to local fallback"
            );
            Err(anyhow!("security-sensitive audit event could not be admitted"))
        }
    }
}

/// Best-effort admit for authenticated backup denials/validation failures.
///
/// Uses the same unconditional database/local-fallback path as successful
/// exports. Never changes the caller's HTTP response path on failure — only
/// logs that the security record could not be stored.
pub async fn record_backup_attempt_best_effort(
    db: Option<&Arc<dyn DatabaseBackend>>,
    event: &AuditEvent,
    fallback_dir: Option<&Path>,
) {
    if let Err(_error) = admit_security_sensitive_event(db, event, fallback_dir).await {
        warn!(
            audit_event_id = %event.id,
            surface = "backup_audit_attempt",
            detail_withheld = true,
            "Authenticated backup attempt could not be audited"
        );
    }
}

static LOCAL_FALLBACK_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

/// Cross-process exclusive lock held for the fallback read/modify/write window.
struct FallbackFileLock {
    _file: File,
}

/// Append one event to the bounded local fallback store.
///
/// Enforces a non-symlink directory/data/lock target, owner-only Unix
/// permissions, collision-resistant temp publication with same-directory
/// atomic replace (Unix `rename(2)`; Windows
/// `MoveFileExW(REPLACE_EXISTING|WRITE_THROUGH)`), directory sync, and
/// cross-process exclusion where the platform supports it. In-process and
/// cross-process locks are acquired without waiting (`try_lock` /
/// `LOCK_EX|LOCK_NB` on Unix; immediate share denial on Windows): contention
/// or poisoning fails closed so a credential-bearing admit path cannot hang a
/// Tokio blocking-pool thread. Never logs event contents.
pub fn append_local_fallback_event(dir: &Path, event: &AuditEvent) -> Result<(), anyhow::Error> {
    let _process_guard = acquire_local_fallback_process_lock()?;
    prepare_fallback_directory(dir)?;
    let lock_path = dir.join(AUDIT_LOCAL_FALLBACK_LOCK_FILE_NAME);
    let _cross_process = acquire_fallback_file_lock(&lock_path)?;
    let path = audit_local_fallback_file(dir);
    reject_symlink_or_non_regular_file(&path, "audit local fallback data file")?;
    let mut events = read_local_fallback_events_unlocked(&path)?;
    events.push(event.clone());
    if events.len() > AUDIT_LOCAL_FALLBACK_CAPACITY {
        let overflow = events.len() - AUDIT_LOCAL_FALLBACK_CAPACITY;
        events.drain(0..overflow);
    }
    write_local_fallback_events_unlocked(dir, &path, &events)
}

/// Read all events currently retained in the local fallback store.
///
/// Uses the same non-blocking process and cross-process lock acquisition as
/// [`append_local_fallback_event`]; contention fails closed immediately.
pub fn list_local_fallback_events(dir: &Path) -> Result<Vec<AuditEvent>, anyhow::Error> {
    let _process_guard = acquire_local_fallback_process_lock()?;
    prepare_existing_fallback_directory(dir)?;
    let lock_path = dir.join(AUDIT_LOCAL_FALLBACK_LOCK_FILE_NAME);
    let _cross_process = acquire_fallback_file_lock(&lock_path)?;
    let path = audit_local_fallback_file(dir);
    reject_symlink_or_non_regular_file(&path, "audit local fallback data file")?;
    read_local_fallback_events_unlocked(&path)
}

/// Non-blocking in-process mutex for the local fallback critical section.
///
/// Contention and poisoning both return a static, non-sensitive error so
/// security-sensitive admit never waits indefinitely on another holder.
fn acquire_local_fallback_process_lock() -> Result<MutexGuard<'static, ()>, anyhow::Error> {
    match LOCAL_FALLBACK_LOCK.try_lock() {
        Ok(guard) => Ok(guard),
        Err(TryLockError::WouldBlock) => {
            Err(anyhow!("audit local fallback process lock contended"))
        }
        Err(TryLockError::Poisoned(_)) => Err(anyhow!("audit local fallback lock poisoned")),
    }
}

/// Test seam: hold the in-process fallback mutex without waiting.
pub(crate) fn hold_local_fallback_process_lock_for_test()
-> Result<MutexGuard<'static, ()>, anyhow::Error> {
    acquire_local_fallback_process_lock()
}

fn prepare_fallback_directory(dir: &Path) -> Result<(), anyhow::Error> {
    match fs::symlink_metadata(dir) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(anyhow!("audit local fallback path must not be a symlink"));
            }
            if !meta.is_dir() {
                return Err(anyhow!("audit local fallback path must be a directory"));
            }
            enforce_owner_only_dir_permissions(dir)?;
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(dir)?;
            // Re-validate after create so a raced symlink/non-dir fails closed.
            prepare_existing_fallback_directory(dir)
        }
        Err(error) => Err(error.into()),
    }
}

fn prepare_existing_fallback_directory(dir: &Path) -> Result<(), anyhow::Error> {
    let meta = fs::symlink_metadata(dir)?;
    if meta.file_type().is_symlink() {
        return Err(anyhow!("audit local fallback path must not be a symlink"));
    }
    if !meta.is_dir() {
        return Err(anyhow!("audit local fallback path must be a directory"));
    }
    enforce_owner_only_dir_permissions(dir)
}

fn enforce_owner_only_dir_permissions(dir: &Path) -> Result<(), anyhow::Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    let _ = dir;
    Ok(())
}

fn reject_symlink_or_non_regular_file(
    path: &Path,
    label: &'static str,
) -> Result<(), anyhow::Error> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(anyhow!("{label} must not be a symlink"));
            }
            if !meta.file_type().is_file() {
                return Err(anyhow!("{label} must be a regular file"));
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(unix)]
fn acquire_fallback_file_lock(lock_path: &Path) -> Result<FallbackFileLock, anyhow::Error> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::os::unix::io::AsRawFd;

    reject_symlink_or_non_regular_file(lock_path, "audit local fallback lock file")?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(lock_path)
        .map_err(|error| anyhow!("failed to open audit local fallback lock: {error}"))?;
    let lock_metadata = file.metadata()?;
    if !lock_metadata.file_type().is_file() {
        return Err(anyhow!("audit local fallback lock file must be a regular file"));
    }
    file.set_permissions(fs::Permissions::from_mode(0o600))?;

    // SAFETY: `file` owns a valid descriptor for the lifetime of this guard.
    // `flock` does not access Rust-managed memory. `LOCK_NB` fails immediately
    // on contention so admit cannot hang a blocking-pool thread.
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result != 0 {
        let error = std::io::Error::last_os_error();
        let errno = error.raw_os_error();
        if errno == Some(libc::EWOULDBLOCK) || errno == Some(libc::EAGAIN) {
            return Err(anyhow!("audit local fallback cross-process lock contended"));
        }
        return Err(anyhow!(
            "failed to acquire audit local fallback cross-process lock: {error}"
        ));
    }

    let path_metadata = fs::symlink_metadata(lock_path)?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.file_type().is_file()
        || path_metadata.dev() != lock_metadata.dev()
        || path_metadata.ino() != lock_metadata.ino()
    {
        return Err(anyhow!(
            "audit local fallback lock file changed identity during acquisition"
        ));
    }

    Ok(FallbackFileLock { _file: file })
}

#[cfg(windows)]
fn acquire_fallback_file_lock(lock_path: &Path) -> Result<FallbackFileLock, anyhow::Error> {
    use std::os::windows::fs::OpenOptionsExt;

    reject_symlink_or_non_regular_file(lock_path, "audit local fallback lock file")?;
    // `share_mode(0)` denies all share access for as long as this handle is
    // held — a std-only cross-process exclusive critical section. Open fails
    // immediately when another holder already has the file (no wait).
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .share_mode(0)
        .open(lock_path)
        .map_err(|error| anyhow!("failed to open audit local fallback lock: {error}"))?;
    let lock_metadata = file.metadata()?;
    if !lock_metadata.file_type().is_file() {
        return Err(anyhow!("audit local fallback lock file must be a regular file"));
    }
    Ok(FallbackFileLock { _file: file })
}

#[cfg(not(any(unix, windows)))]
fn acquire_fallback_file_lock(_lock_path: &Path) -> Result<FallbackFileLock, anyhow::Error> {
    Err(anyhow!(
        "audit local fallback cross-process exclusion is unavailable on this platform"
    ))
}

fn read_local_fallback_events_unlocked(path: &Path) -> Result<Vec<AuditEvent>, anyhow::Error> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(anyhow!("audit local fallback data file must not be a symlink"));
            }
            if !meta.file_type().is_file() {
                return Err(anyhow!("audit local fallback data file must be a regular file"));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    }
    let raw = fs::read(path)?;
    if raw.iter().all(u8::is_ascii_whitespace) {
        return Ok(Vec::new());
    }
    serde_json::from_slice(&raw).map_err(|_| anyhow!("corrupt audit local fallback store"))
}

fn write_local_fallback_events_unlocked(
    dir: &Path,
    path: &Path,
    events: &[AuditEvent],
) -> Result<(), anyhow::Error> {
    let body = serde_json::to_vec_pretty(events)?;
    let tmp_name = format!("{}.{}.tmp", AUDIT_LOCAL_FALLBACK_FILE_NAME, Uuid::new_v4());
    let tmp = dir.join(tmp_name);
    let write_result = write_temp_fallback_file(&tmp, &body);
    if let Err(error) = write_result {
        let _ = fs::remove_file(&tmp);
        return Err(error);
    }
    // Same-directory replace: never unlink the destination before publish, and
    // never leave a visibility gap. Unix `rename(2)` replaces atomically;
    // Windows uses `MoveFileExW(REPLACE_EXISTING|WRITE_THROUGH)` because
    // `std::fs::rename` does not replace an existing destination there.
    if let Err(error) = replace_local_fallback_file(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(error);
    }
    sync_directory(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Atomically publish `temp` over `destination` in the same directory.
///
/// Safety boundary: both paths must already be siblings under the prepared
/// fallback directory (caller holds the process/cross-process locks and wrote
/// `temp` via [`write_temp_fallback_file`]). This never removes `destination`
/// before replacement and never logs path contents.
fn replace_local_fallback_file(temp: &Path, destination: &Path) -> Result<(), anyhow::Error> {
    #[cfg(windows)]
    {
        return replace_local_fallback_file_windows(temp, destination);
    }
    #[cfg(not(windows))]
    {
        fs::rename(temp, destination).map_err(|error| error.into())
    }
}

/// Windows same-directory replacement with replace-existing + write-through.
///
/// `std::fs::rename` maps to `MoveFileExW` without `MOVEFILE_REPLACE_EXISTING`,
/// so the first append can succeed while every later append fails closed when
/// the destination already exists. This path uses
/// `MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH` and propagates Win32
/// failures without deleting the live destination first (no visibility gap).
#[cfg(windows)]
fn replace_local_fallback_file_windows(
    temp: &Path,
    destination: &Path,
) -> Result<(), anyhow::Error> {
    use std::os::windows::ffi::OsStrExt;

    // MOVEFILE_REPLACE_EXISTING = 0x1, MOVEFILE_WRITE_THROUGH = 0x8
    const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x8;

    let source: Vec<u16> = temp
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let target: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // SAFETY: `source`/`target` are NUL-terminated wide paths owned for the
    // duration of the call. Flags request replace-existing + write-through
    // durability only; no path bytes are logged on failure.
    let ok = unsafe {
        windows_ffi::MoveFileExW(
            source.as_ptr(),
            target.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if ok == 0 {
        let error = std::io::Error::last_os_error();
        return Err(anyhow!(
            "failed to replace audit local fallback file: {error}"
        ));
    }
    Ok(())
}

/// Minimal kernel32 bindings for atomic same-directory file replacement.
///
/// Kept local (no `windows-sys` dependency) because this is the only Win32
/// primitive the backup-audit fallback needs today.
#[cfg(windows)]
mod windows_ffi {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        pub(super) fn MoveFileExW(
            lp_existing_file_name: *const u16,
            lp_new_file_name: *const u16,
            dw_flags: u32,
        ) -> i32;
    }
}

fn write_temp_fallback_file(tmp: &Path, body: &[u8]) -> Result<(), anyhow::Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(tmp)?;
        file.write_all(body)?;
        file.sync_all()?;
        return Ok(());
    }
    #[cfg(not(unix))]
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(tmp)?;
        file.write_all(body)?;
        file.sync_all()?;
        Ok(())
    }
}

fn sync_directory(dir: &Path) -> Result<(), anyhow::Error> {
    #[cfg(unix)]
    {
        let dir_file = OpenOptions::new().read(true).open(dir)?;
        dir_file.sync_all()?;
    }
    let _ = dir;
    Ok(())
}
