//! Admin API audit logging.
//!
//! When enabled, audit events are written through a bounded worker queue per
//! database backend. The HTTP mutation path never waits for queue capacity; if
//! the bounded queue is full, enqueue fails fast and the committed mutation
//! response can proceed after logging the audit failure. Audit persistence is
//! best-effort and happens after the mutation response path has enqueued the
//! event.

use crate::admin::jwt_auth::{AdminClaims, AdminRole};
use crate::config::db_backend::DatabaseBackend;
use anyhow::anyhow;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::{Arc, LazyLock, Weak};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::time::{Duration, MissedTickBehavior, interval};
use tracing::error;
use uuid::Uuid;

const AUDIT_CHANNEL_CAPACITY: usize = 1024;
const AUDIT_SINK_STALE_CHECK_INTERVAL_SECONDS: u64 = 60;

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
/// have landed since the last verified at-or-under-cap check — unless a prior
/// prune hit the per-call batch budget and left `drain_pending` set. Equals
/// the prune batch size so soft overshoot stays small and deterministic.
pub const AUDIT_RETENTION_MAX_ROWS_CHECK_INTERVAL: u64 = AUDIT_RETENTION_PRUNE_BATCH_SIZE;

static AUDIT_SINKS: LazyLock<DashMap<usize, AuditSinkEntry>> = LazyLock::new(DashMap::new);

/// Per-namespace insert-path gate for max-row retention scans.
///
/// `FERRUM_AUDIT_RETENTION_MAX_ROWS` is a soft cap: after a verified
/// at-or-under-cap observation, one gateway instance may admit up to
/// [`audit_retention_max_rows_check_interval`] further inserts for that
/// namespace before the next O(max_rows) boundary scan. When a scan finds
/// excess and the bounded delete budget is exhausted, `drain_pending` keeps
/// subsequent inserts pruning immediately so backlog drains promptly. Explicit
/// `prune_audit_events` calls always force a scan. Multiple gateway instances
/// each keep their own gate, so worst-case soft overshoot scales with instance
/// count × interval; deletes remain namespace-scoped and idempotent.
#[derive(Debug, Default, Clone)]
pub struct AuditMaxRowsPruneGate {
    inserts_since_check: u64,
    drain_pending: bool,
}

impl AuditMaxRowsPruneGate {
    /// Whether this insert (or forced prune) should run the max-rows boundary scan.
    pub fn should_run_max_rows_prune(&mut self, max_rows: u64, force: bool) -> bool {
        if force || self.drain_pending {
            return true;
        }
        self.inserts_since_check = self.inserts_since_check.saturating_add(1);
        self.inserts_since_check >= audit_retention_max_rows_check_interval(max_rows)
    }

    /// Record the outcome of a max-rows prune so the next insert can either
    /// resume soft-cap cadence or keep draining.
    pub fn note_max_rows_prune_result(&mut self, hit_batch_budget: bool) {
        self.inserts_since_check = 0;
        self.drain_pending = hit_batch_budget;
    }

    pub fn drain_pending(&self) -> bool {
        self.drain_pending
    }
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
        if let Some(max_rows) = max_rows_per_namespace {
            if max_rows == 0 {
                return Err(
                    "FERRUM_AUDIT_RETENTION_MAX_ROWS must be greater than zero when set"
                        .to_string(),
                );
            }
            if max_rows > AUDIT_RETENTION_MAX_ROWS_CAP {
                return Err(format!(
                    "FERRUM_AUDIT_RETENTION_MAX_ROWS must not exceed {AUDIT_RETENTION_MAX_ROWS_CAP}"
                ));
            }
        }
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
    pub diff: Value,
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
            diff,
        }
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
