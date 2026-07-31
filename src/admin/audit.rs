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
//! instead: that path awaits a synchronous database insert when a backend is
//! available, and otherwise appends to a bounded local fallback file so capture
//! does not depend solely on the same unavailable primary used for config load.
//! General mutation delivery-loss hardening remains issue #2421 and is out of
//! scope for the backup-specific admit path.

use crate::admin::jwt_auth::{AdminClaims, AdminRole};
use crate::config::db_backend::DatabaseBackend;
use anyhow::anyhow;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex, Weak};
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
const AUDIT_LOCAL_FALLBACK_DEFAULT_DIR: &str = "./ferrum-admin-audit";

/// Fixed-cardinality outcomes stored on [`AuditEvent::outcome`].
pub mod outcome {
    pub const SUCCESS: &str = "success";
    pub const DENIED: &str = "denied";
    pub const VALIDATION_FAILED: &str = "validation_failed";
    pub const UNAVAILABLE: &str = "unavailable";
    pub const AUDIT_ADMIT_FAILED: &str = "audit_admit_failed";
}

/// Fixed-cardinality failure categories for backup audit `diff` payloads.
pub mod failure_category {
    pub const FORBIDDEN: &str = "forbidden";
    pub const NAMESPACE_DENIED: &str = "namespace_denied";
    pub const VALIDATION_FAILED: &str = "validation_failed";
    pub const UNAVAILABLE: &str = "unavailable";
    pub const AUDIT_ADMIT_FAILED: &str = "audit_admit_failed";
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
    /// `unavailable`, `audit_admit_failed`). Empty for legacy mutation events
    /// that only recorded successful commits.
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

    pub fn with_outcome(mut self, outcome: impl Into<String>) -> Self {
        self.outcome = outcome.into();
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
    /// Audit disabled — no record required.
    Disabled,
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
pub fn backup_failure_diff(category: &str, resources: Value) -> Value {
    json!({
        "failure_category": category,
        "resources": resources,
    })
}

/// Canonical resource-filter representation for audit events (sorted names, or
/// the sentinel `"all"` when unfiltered).
pub fn backup_resources_audit_value(filter: Option<&std::collections::HashSet<&str>>) -> Value {
    match filter {
        None => json!("all"),
        Some(set) => {
            let mut names: Vec<&str> = set.iter().copied().collect();
            names.sort_unstable();
            json!(names)
        }
    }
}

/// Admit a security-sensitive audit event before releasing unredacted material.
///
/// When auditing is disabled this is a no-op success. Otherwise:
/// 1. Prefer a synchronous `insert_audit_event` on the provided backend.
/// 2. If no backend is present or the insert fails, append to the bounded local
///    fallback file under `fallback_dir` (or the configured default).
/// 3. If neither sink admits the event, return an error so the caller can fail
///    closed without emitting the sensitive response body.
///
/// This is intentionally narrower than #2421 (general mutation durability): it
/// only covers surfaces that must not silently export secrets without a record.
pub async fn admit_security_sensitive_event(
    enabled: bool,
    db: Option<&Arc<dyn DatabaseBackend>>,
    event: &AuditEvent,
    fallback_dir: Option<&Path>,
) -> Result<AuditAdmitSink, anyhow::Error> {
    if !enabled {
        return Ok(AuditAdmitSink::Disabled);
    }

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
    append_local_fallback_event(&dir, event).map_err(|_error| {
        error!(
            audit_event_id = %event.id,
            surface = "audit_security_admit_local_fallback",
            detail_withheld = true,
            "Failed to admit security-sensitive audit event to local fallback"
        );
        anyhow!("security-sensitive audit event could not be admitted")
    })?;
    Ok(AuditAdmitSink::LocalFallback)
}

/// Best-effort admit for authenticated backup denials/validation failures.
/// Never changes the caller's HTTP response path on failure — only logs that
/// the security record could not be stored.
pub async fn record_backup_attempt_best_effort(
    enabled: bool,
    db: Option<&Arc<dyn DatabaseBackend>>,
    event: &AuditEvent,
    fallback_dir: Option<&Path>,
) {
    if let Err(_error) = admit_security_sensitive_event(enabled, db, event, fallback_dir).await {
        warn!(
            audit_event_id = %event.id,
            surface = "backup_audit_attempt",
            detail_withheld = true,
            "Authenticated backup attempt could not be audited"
        );
    }
}

static LOCAL_FALLBACK_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

/// Append one event to the bounded local fallback store. Creates the directory
/// with owner-only permissions when possible. Never logs event contents.
pub fn append_local_fallback_event(dir: &Path, event: &AuditEvent) -> Result<(), anyhow::Error> {
    let _guard = LOCAL_FALLBACK_LOCK
        .lock()
        .map_err(|_| anyhow!("audit local fallback lock poisoned"))?;
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    }
    let path = audit_local_fallback_file(dir);
    let mut events = read_local_fallback_events_unlocked(&path)?;
    events.push(event.clone());
    if events.len() > AUDIT_LOCAL_FALLBACK_CAPACITY {
        let overflow = events.len() - AUDIT_LOCAL_FALLBACK_CAPACITY;
        events.drain(0..overflow);
    }
    write_local_fallback_events_unlocked(&path, &events)
}

/// Read all events currently retained in the local fallback store.
pub fn list_local_fallback_events(dir: &Path) -> Result<Vec<AuditEvent>, anyhow::Error> {
    let _guard = LOCAL_FALLBACK_LOCK
        .lock()
        .map_err(|_| anyhow!("audit local fallback lock poisoned"))?;
    read_local_fallback_events_unlocked(&audit_local_fallback_file(dir))
}

fn read_local_fallback_events_unlocked(path: &Path) -> Result<Vec<AuditEvent>, anyhow::Error> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw = fs::read_to_string(path)?;
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str(&raw).map_err(|e| anyhow!("corrupt audit local fallback store: {e}"))
}

fn write_local_fallback_events_unlocked(
    path: &Path,
    events: &[AuditEvent],
) -> Result<(), anyhow::Error> {
    let tmp = path.with_extension("json.tmp");
    let body = serde_json::to_vec_pretty(events)?;
    {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)?;
        file.write_all(&body)?;
        file.sync_all()?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600));
    }
    fs::rename(&tmp, path)?;
    Ok(())
}
