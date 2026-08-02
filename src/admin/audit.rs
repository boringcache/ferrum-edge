//! Admin API audit logging.
//!
//! # Durable handoff (issue #2421)
//!
//! An audited admin mutation commits, then hands its audit event to a **durable
//! spool** before the success response is acknowledged. The handoff is an
//! fsynced write plus an fsynced rename into `<spool>/pending/`, so a crash
//! after the response still leaves a replayable record. Delivery into
//! `audit_events` is asynchronous, retried with bounded exponential backoff, and
//! removes the spool file only after the backend accepts the event.
//!
//! ## Delivery semantics
//!
//! **At-least-once with a stable identity.** The event `id` is a UUID minted
//! once, before the durable write, and is reused verbatim by every retry and
//! every post-restart replay. Every backend insert is idempotent on that id
//! (`ON CONFLICT DO NOTHING` / `INSERT IGNORE` / a `_id` upsert), so a replayed
//! event converges to exactly one durable row. Audit history is therefore
//! unambiguous even though the transport is at-least-once.
//!
//! ## Residual crash window
//!
//! The event body is only knowable after the mutation commits, so the durable
//! write necessarily follows the commit. A crash in the window strictly between
//! the config-database commit and the spool write loses that one event; the
//! response is not acknowledged in that window, so no client has been told the
//! change was audited. Closing that window entirely needs a per-backend
//! transactional outbox writing the event inside the mutation's own
//! transaction, which is a cross-backend refactor tracked separately.
//!
//! ## Unavailability policy
//!
//! `FERRUM_ADMIN_AUDIT_UNAVAILABLE_POLICY` selects what happens when the durable
//! handoff is not working:
//!
//! - `fail_open` (default) — the mutation response proceeds and the failure is
//!   counted, logged, and exposed through health/status and `/metrics`.
//! - `fail_closed` — the admin write gate refuses **subsequent** audited
//!   mutations with `503` until the pipeline recovers. Refusing a change that
//!   cannot be audited is strictly better than making it and reporting failure
//!   afterwards, so the gate is evaluated up front in
//!   `AdminState::evaluate_non_topology_write_gate`.
//!
//! Nothing on this path logs an actor token, a secret, a request body, or
//! credential metadata. Failure surfaces carry a static reason label and the
//! audit event id only.

use crate::admin::audit_spool::{AuditSpool, SpoolError, SpoolErrorKind, SpooledAuditRecord};
use crate::admin::jwt_auth::{AdminClaims, AdminRole};
use crate::config::db_backend::DatabaseBackend;
use anyhow::anyhow;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, OnceLock, Weak};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::task::JoinHandle;
use tokio::time::{Duration, Instant, MissedTickBehavior, interval};
use tracing::{error, info, warn};
use uuid::Uuid;

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

// ---------------------------------------------------------------------------
// Delivery target
// ---------------------------------------------------------------------------

/// Terminal sink for a durable audit event.
///
/// Production delivery is [`DatabaseBackend::insert_audit_event`]; the trait
/// exists so queue-saturation, backend-failure, replay, and shutdown behavior
/// can be exercised by external tests without a full database backend. Every
/// implementation must be **idempotent on `event.id`**, because replay after a
/// crash or a partial failure re-delivers the same identity.
#[async_trait]
pub trait AuditEventDelivery: Send + Sync {
    async fn deliver(&self, event: &AuditEvent) -> Result<(), anyhow::Error>;
}

struct DatabaseAuditDelivery {
    db: Weak<dyn DatabaseBackend>,
}

#[async_trait]
impl AuditEventDelivery for DatabaseAuditDelivery {
    async fn deliver(&self, event: &AuditEvent) -> Result<(), anyhow::Error> {
        let Some(db) = self.db.upgrade() else {
            return Err(anyhow!("audit delivery backend is no longer available"));
        };
        db.insert_audit_event(event).await
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Default durable spool root. Mirrors the chargeback sink's managed-state
/// convention so operators mount one writable state volume.
pub const AUDIT_SPOOL_DIR_DEFAULT: &str = "/var/lib/ferrum/audit-spool";
/// Default bounded in-memory hand-off queue depth.
pub const AUDIT_QUEUE_CAPACITY_DEFAULT: usize = 1024;
/// Accepted range for `FERRUM_ADMIN_AUDIT_QUEUE_CAPACITY`.
pub const AUDIT_QUEUE_CAPACITY_MIN: usize = 1;
pub const AUDIT_QUEUE_CAPACITY_MAX: usize = 65_536;
/// Default durable pending-record ceiling.
pub const AUDIT_SPOOL_MAX_RECORDS_DEFAULT: u64 = 100_000;
pub const AUDIT_SPOOL_MAX_RECORDS_MAX: u64 = 10_000_000;
/// Default ceiling for retained unrecoverable records.
pub const AUDIT_RETAINED_MAX_RECORDS_DEFAULT: u64 = 10_000;
pub const AUDIT_RETAINED_MAX_RECORDS_MAX: u64 = 1_000_000;
/// Default bounded delivery-attempt budget per event, across restarts.
pub const AUDIT_MAX_DELIVERY_ATTEMPTS_DEFAULT: u32 = 10;
pub const AUDIT_MAX_DELIVERY_ATTEMPTS_MAX: u32 = 1_000;

/// First retry delay after a transient delivery failure.
const AUDIT_RETRY_BASE_DELAY_MS: u64 = 250;
/// Ceiling for the exponential retry delay.
const AUDIT_RETRY_MAX_DELAY_MS: u64 = 30_000;
/// Cadence of the durable-spool replay scan.
const AUDIT_REPLAY_INTERVAL_SECONDS: u64 = 30;
/// Records admitted per replay scan so a huge backlog stays incremental and a
/// shutdown signal is still observed promptly.
const AUDIT_REPLAY_BATCH: usize = 256;

/// What the admin write gate does when the audit pipeline cannot durably
/// record events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditUnavailablePolicy {
    /// Committed mutations proceed; the failure is counted and surfaced.
    #[default]
    FailOpen,
    /// Subsequent audited mutations are refused with `503` until recovery.
    FailClosed,
}

impl AuditUnavailablePolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            AuditUnavailablePolicy::FailOpen => "fail_open",
            AuditUnavailablePolicy::FailClosed => "fail_closed",
        }
    }

    /// Parse an operator-supplied value. Unknown values fail closed at startup
    /// rather than silently selecting a permissive default.
    pub fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "fail_open" | "fail-open" | "open" => Ok(AuditUnavailablePolicy::FailOpen),
            "fail_closed" | "fail-closed" | "closed" => Ok(AuditUnavailablePolicy::FailClosed),
            _ => Err(
                "FERRUM_ADMIN_AUDIT_UNAVAILABLE_POLICY must be 'fail_open' or 'fail_closed'"
                    .to_string(),
            ),
        }
    }
}

/// Operator-configured audit delivery pipeline settings.
#[derive(Debug, Clone)]
pub struct AuditPipelineConfig {
    pub enabled: bool,
    /// Durable spool root. `None` disables the durable handoff entirely and is
    /// rejected when the policy is `fail_closed`.
    pub spool_dir: Option<PathBuf>,
    pub policy: AuditUnavailablePolicy,
    pub queue_capacity: usize,
    pub spool_max_records: u64,
    pub retained_max_records: u64,
    pub max_delivery_attempts: u32,
}

impl Default for AuditPipelineConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            spool_dir: Some(PathBuf::from(AUDIT_SPOOL_DIR_DEFAULT)),
            policy: AuditUnavailablePolicy::FailOpen,
            queue_capacity: AUDIT_QUEUE_CAPACITY_DEFAULT,
            spool_max_records: AUDIT_SPOOL_MAX_RECORDS_DEFAULT,
            retained_max_records: AUDIT_RETAINED_MAX_RECORDS_DEFAULT,
            max_delivery_attempts: AUDIT_MAX_DELIVERY_ATTEMPTS_DEFAULT,
        }
    }
}

impl AuditPipelineConfig {
    /// Validate operator input. Bounds are clamped ranges, not silent
    /// truncations: an out-of-range value is an error at startup.
    pub fn validate(&self) -> Result<(), String> {
        if !(AUDIT_QUEUE_CAPACITY_MIN..=AUDIT_QUEUE_CAPACITY_MAX).contains(&self.queue_capacity) {
            return Err(format!(
                "FERRUM_ADMIN_AUDIT_QUEUE_CAPACITY must be between {AUDIT_QUEUE_CAPACITY_MIN} \
                 and {AUDIT_QUEUE_CAPACITY_MAX}"
            ));
        }
        if self.spool_max_records == 0 || self.spool_max_records > AUDIT_SPOOL_MAX_RECORDS_MAX {
            return Err(format!(
                "FERRUM_ADMIN_AUDIT_SPOOL_MAX_RECORDS must be between 1 and \
                 {AUDIT_SPOOL_MAX_RECORDS_MAX}"
            ));
        }
        if self.retained_max_records == 0
            || self.retained_max_records > AUDIT_RETAINED_MAX_RECORDS_MAX
        {
            return Err(format!(
                "FERRUM_ADMIN_AUDIT_RETAINED_MAX_RECORDS must be between 1 and \
                 {AUDIT_RETAINED_MAX_RECORDS_MAX}"
            ));
        }
        if self.max_delivery_attempts == 0
            || self.max_delivery_attempts > AUDIT_MAX_DELIVERY_ATTEMPTS_MAX
        {
            return Err(format!(
                "FERRUM_ADMIN_AUDIT_MAX_DELIVERY_ATTEMPTS must be between 1 and \
                 {AUDIT_MAX_DELIVERY_ATTEMPTS_MAX}"
            ));
        }
        if self.enabled
            && self.policy == AuditUnavailablePolicy::FailClosed
            && self.spool_dir.is_none()
        {
            return Err(
                "FERRUM_ADMIN_AUDIT_UNAVAILABLE_POLICY=fail_closed requires a durable \
                 FERRUM_ADMIN_AUDIT_SPOOL_DIR"
                    .to_string(),
            );
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Unavailability reasons and metrics
// ---------------------------------------------------------------------------

/// Closed set of operator-facing pipeline failure reasons.
///
/// Kept as a fixed enum so it is safe both as a Prometheus label value (bounded
/// cardinality) and as a health-surface string (no OS error text, no path, no
/// actor identity).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AuditUnavailableReason {
    None = 0,
    SpoolUnavailable = 1,
    SpoolSaturated = 2,
    SpoolIo = 3,
    InvalidRecord = 4,
    CorruptRecord = 5,
    QueueSaturated = 6,
    WorkerUnavailable = 7,
    DeliveryExhausted = 8,
    RetainedCapacity = 9,
    NoDurableSpool = 10,
}

impl AuditUnavailableReason {
    pub fn as_str(self) -> &'static str {
        match self {
            AuditUnavailableReason::None => "none",
            AuditUnavailableReason::SpoolUnavailable => "spool_unavailable",
            AuditUnavailableReason::SpoolSaturated => "spool_saturated",
            AuditUnavailableReason::SpoolIo => "spool_io_error",
            AuditUnavailableReason::InvalidRecord => "invalid_record",
            AuditUnavailableReason::CorruptRecord => "corrupt_record",
            AuditUnavailableReason::QueueSaturated => "queue_saturated",
            AuditUnavailableReason::WorkerUnavailable => "worker_unavailable",
            AuditUnavailableReason::DeliveryExhausted => "delivery_exhausted",
            AuditUnavailableReason::RetainedCapacity => "retained_capacity",
            AuditUnavailableReason::NoDurableSpool => "no_durable_spool",
        }
    }

    fn from_u8(value: u8) -> Self {
        match value {
            1 => AuditUnavailableReason::SpoolUnavailable,
            2 => AuditUnavailableReason::SpoolSaturated,
            3 => AuditUnavailableReason::SpoolIo,
            4 => AuditUnavailableReason::InvalidRecord,
            5 => AuditUnavailableReason::CorruptRecord,
            6 => AuditUnavailableReason::QueueSaturated,
            7 => AuditUnavailableReason::WorkerUnavailable,
            8 => AuditUnavailableReason::DeliveryExhausted,
            9 => AuditUnavailableReason::RetainedCapacity,
            10 => AuditUnavailableReason::NoDurableSpool,
            _ => AuditUnavailableReason::None,
        }
    }

    fn from_spool_error(error: &SpoolError) -> Self {
        match error.kind {
            SpoolErrorKind::Unavailable => AuditUnavailableReason::SpoolUnavailable,
            SpoolErrorKind::Saturated => AuditUnavailableReason::SpoolSaturated,
            SpoolErrorKind::Io => AuditUnavailableReason::SpoolIo,
            SpoolErrorKind::InvalidRecord => AuditUnavailableReason::InvalidRecord,
            SpoolErrorKind::Corrupt => AuditUnavailableReason::CorruptRecord,
        }
    }
}

/// Lock-free process-wide audit pipeline counters.
#[derive(Debug, Default)]
pub struct AuditPipelineMetrics {
    accepted: AtomicU64,
    spooled: AtomicU64,
    enqueued: AtomicU64,
    delivered: AtomicU64,
    retries: AtomicU64,
    delivery_failures: AtomicU64,
    retained: AtomicU64,
    replayed: AtomicU64,
    corrupt: AtomicU64,
    truncated_diffs: AtomicU64,
    dropped_handoff: AtomicU64,
    dropped_no_spool: AtomicU64,
    dropped_retained_capacity: AtomicU64,
    fail_closed_rejections: AtomicU64,
    queue_depth: AtomicU64,
    spool_pending: AtomicU64,
    spool_retained: AtomicU64,
}

/// Point-in-time counters for `/health`, `/status`, and `/metrics`.
///
/// Counts and static reason labels only — never an actor subject, a token, a
/// request body, a diff, or a filesystem path.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct AuditPipelineMetricsSnapshot {
    pub accepted_total: u64,
    pub spooled_total: u64,
    pub enqueued_total: u64,
    pub delivered_total: u64,
    pub retries_total: u64,
    pub delivery_failures_total: u64,
    pub retained_total: u64,
    pub replayed_total: u64,
    pub corrupt_records_total: u64,
    pub truncated_diffs_total: u64,
    pub dropped_durable_handoff_failed_total: u64,
    pub dropped_no_durable_spool_total: u64,
    pub dropped_retained_capacity_total: u64,
    pub fail_closed_rejections_total: u64,
    pub queue_depth: u64,
    pub spool_pending_records: u64,
    pub spool_retained_records: u64,
}

/// Saturating decrement for a gauge that several tasks adjust concurrently.
fn saturating_decrement(gauge: &AtomicU64) {
    let _ = gauge.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_sub(1))
    });
}

impl AuditPipelineMetrics {
    pub fn snapshot(&self) -> AuditPipelineMetricsSnapshot {
        AuditPipelineMetricsSnapshot {
            accepted_total: self.accepted.load(Ordering::Relaxed),
            spooled_total: self.spooled.load(Ordering::Relaxed),
            enqueued_total: self.enqueued.load(Ordering::Relaxed),
            delivered_total: self.delivered.load(Ordering::Relaxed),
            retries_total: self.retries.load(Ordering::Relaxed),
            delivery_failures_total: self.delivery_failures.load(Ordering::Relaxed),
            retained_total: self.retained.load(Ordering::Relaxed),
            replayed_total: self.replayed.load(Ordering::Relaxed),
            corrupt_records_total: self.corrupt.load(Ordering::Relaxed),
            truncated_diffs_total: self.truncated_diffs.load(Ordering::Relaxed),
            dropped_durable_handoff_failed_total: self.dropped_handoff.load(Ordering::Relaxed),
            dropped_no_durable_spool_total: self.dropped_no_spool.load(Ordering::Relaxed),
            dropped_retained_capacity_total: self
                .dropped_retained_capacity
                .load(Ordering::Relaxed),
            fail_closed_rejections_total: self.fail_closed_rejections.load(Ordering::Relaxed),
            queue_depth: self.queue_depth.load(Ordering::Relaxed),
            spool_pending_records: self.spool_pending.load(Ordering::Relaxed),
            spool_retained_records: self.spool_retained.load(Ordering::Relaxed),
        }
    }
}

/// Durability mode actually in force, independent of what was configured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditDurabilityMode {
    /// Events are fsynced to the spool before the mutation response.
    Spool,
    /// No usable spool: bounded in-memory queue only (pre-#2421 semantics).
    Memory,
    /// Auditing is disabled.
    Disabled,
}

impl AuditDurabilityMode {
    pub fn as_str(self) -> &'static str {
        match self {
            AuditDurabilityMode::Spool => "spool",
            AuditDurabilityMode::Memory => "memory",
            AuditDurabilityMode::Disabled => "disabled",
        }
    }
}

/// Health/status projection of pipeline state.
#[derive(Debug, Clone, Serialize)]
pub struct AuditPipelineStatus {
    pub enabled: bool,
    pub durability: &'static str,
    pub policy: &'static str,
    pub available: bool,
    pub last_unavailable_reason: &'static str,
    pub queue_capacity: u64,
    pub spool_max_records: u64,
    pub retained_max_records: u64,
    pub max_delivery_attempts: u32,
    #[serde(flatten)]
    pub metrics: AuditPipelineMetricsSnapshot,
}

// ---------------------------------------------------------------------------
// Pipeline
// ---------------------------------------------------------------------------

/// Process-wide durable audit pipeline state: configuration, spool handle,
/// counters, and the availability flag the admin write gate reads.
#[derive(Debug)]
pub struct AuditPipeline {
    config: AuditPipelineConfig,
    spool: Option<Arc<AuditSpool>>,
    metrics: Arc<AuditPipelineMetrics>,
    available: AtomicBool,
    last_unavailable_reason: AtomicU8,
    draining: AtomicBool,
    /// Unix millis of the last durable-backlog rescan. The worker keeps the
    /// gauges accurate incrementally; this bounded reconciliation exists so a
    /// `/health` or `/metrics` caller cannot drive an unbounded `read_dir` per
    /// request.
    spool_gauges_refreshed_at_ms: AtomicI64,
}

/// Minimum spacing between durable-backlog rescans behind the observability
/// surfaces.
const SPOOL_GAUGE_REFRESH_INTERVAL_MS: i64 = 5_000;

impl AuditPipeline {
    /// Build a pipeline, preparing the durable spool when one is configured.
    ///
    /// A spool that cannot be prepared is fatal under `fail_closed` and
    /// degrades to memory-only under `fail_open` (loudly, and visible on
    /// `/health` and `/metrics`).
    pub fn new(config: AuditPipelineConfig) -> Result<Self, String> {
        config.validate()?;
        let metrics = Arc::new(AuditPipelineMetrics::default());
        let mut spool = None;
        let mut reason = AuditUnavailableReason::None;

        if config.enabled && let Some(dir) = config.spool_dir.as_ref() {
            match AuditSpool::open(
                dir.clone(),
                config.spool_max_records,
                config.retained_max_records,
            ) {
                Ok(prepared) => spool = Some(Arc::new(prepared)),
                Err(error) => {
                    if config.policy == AuditUnavailablePolicy::FailClosed {
                        return Err(format!(
                            "admin audit spool could not be prepared ({}) and \
                             FERRUM_ADMIN_AUDIT_UNAVAILABLE_POLICY=fail_closed",
                            error.reason()
                        ));
                    }
                    reason = AuditUnavailableReason::from_spool_error(&error);
                    error!(
                        surface = "audit_spool_open",
                        reason = error.reason(),
                        "Admin audit durable spool is unusable; audit delivery is memory-only \
                         until the spool directory is writable"
                    );
                }
            }
        } else if config.enabled {
            reason = AuditUnavailableReason::NoDurableSpool;
            warn!(
                surface = "audit_spool_disabled",
                "Admin audit durable spool is disabled; committed mutations can lose audit \
                 events across a crash"
            );
        }

        let available = !config.enabled || spool.is_some();
        let pipeline = Self {
            config,
            spool,
            metrics,
            available: AtomicBool::new(available),
            last_unavailable_reason: AtomicU8::new(reason as u8),
            draining: AtomicBool::new(false),
            spool_gauges_refreshed_at_ms: AtomicI64::new(0),
        };
        pipeline.refresh_spool_gauges();
        Ok(pipeline)
    }

    /// Raw counters. Used by external tests; the binary target otherwise flags
    /// it as dead code.
    #[allow(dead_code)]
    pub fn metrics(&self) -> &Arc<AuditPipelineMetrics> {
        &self.metrics
    }

    pub fn durability_mode(&self) -> AuditDurabilityMode {
        if !self.config.enabled {
            AuditDurabilityMode::Disabled
        } else if self.spool.is_some() {
            AuditDurabilityMode::Spool
        } else {
            AuditDurabilityMode::Memory
        }
    }

    /// True when a committed mutation can still be durably audited.
    pub fn is_available(&self) -> bool {
        !self.config.enabled || self.available.load(Ordering::Acquire)
    }

    pub fn last_unavailable_reason(&self) -> AuditUnavailableReason {
        AuditUnavailableReason::from_u8(self.last_unavailable_reason.load(Ordering::Relaxed))
    }

    fn mark_unavailable(&self, reason: AuditUnavailableReason) {
        self.last_unavailable_reason
            .store(reason as u8, Ordering::Relaxed);
        self.available.store(false, Ordering::Release);
    }

    /// Restore availability after a successful durable handoff or delivery.
    ///
    /// Memory-only mode never becomes "available": there is no durable handoff
    /// to recover, so a delivered event must not paper over the fact that a
    /// crash can still lose committed mutations' audit events.
    fn mark_available(&self) {
        if self.spool.is_none() && self.config.enabled {
            return;
        }
        self.last_unavailable_reason
            .store(AuditUnavailableReason::None as u8, Ordering::Relaxed);
        self.available.store(true, Ordering::Release);
    }

    /// Whether the admin write gate must refuse audited mutations right now.
    ///
    /// Observationally pure: `/health` calls the same gate, so counting a
    /// rejection here would inflate the counter on every probe. Real admission
    /// attempts call [`Self::note_fail_closed_rejection`] instead.
    pub fn fail_closed_block_reason(&self) -> Option<&'static str> {
        if self.config.policy != AuditUnavailablePolicy::FailClosed || self.is_available() {
            return None;
        }
        Some(self.last_unavailable_reason().as_str())
    }

    /// Count one refused admin mutation. Called only from the admission paths.
    pub fn note_fail_closed_rejection(&self) {
        if self.fail_closed_block_reason().is_some() {
            self.metrics
                .fail_closed_rejections
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    fn refresh_spool_gauges(&self) {
        let Some(spool) = self.spool.as_ref() else {
            return;
        };
        let now = Utc::now().timestamp_millis();
        let last = self.spool_gauges_refreshed_at_ms.load(Ordering::Relaxed);
        if last != 0 && now.saturating_sub(last) < SPOOL_GAUGE_REFRESH_INTERVAL_MS {
            return;
        }
        if self
            .spool_gauges_refreshed_at_ms
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            // Another caller is already rescanning; incremental counters stay
            // authoritative in the meantime.
            return;
        }
        let stats = spool.stats();
        self.metrics
            .spool_pending
            .store(stats.pending_records, Ordering::Relaxed);
        self.metrics
            .spool_retained
            .store(stats.retained_records, Ordering::Relaxed);
    }

    pub fn status(&self) -> AuditPipelineStatus {
        self.refresh_spool_gauges();
        AuditPipelineStatus {
            enabled: self.config.enabled,
            durability: self.durability_mode().as_str(),
            policy: self.config.policy.as_str(),
            available: self.is_available(),
            last_unavailable_reason: self.last_unavailable_reason().as_str(),
            queue_capacity: self.config.queue_capacity as u64,
            spool_max_records: self.config.spool_max_records,
            retained_max_records: self.config.retained_max_records,
            max_delivery_attempts: self.config.max_delivery_attempts,
            metrics: self.metrics.snapshot(),
        }
    }

    /// Durably persist `event` before the caller acknowledges its mutation.
    ///
    /// Returns the record on success so the caller can hand it to a worker. An
    /// error means the durable handoff did not happen; the caller applies the
    /// configured policy.
    fn spool_record(&self, event: AuditEvent) -> Result<SpooledAuditRecord, AuditUnavailableReason> {
        self.metrics.accepted.fetch_add(1, Ordering::Relaxed);
        let Some(spool) = self.spool.as_ref() else {
            // Memory-only mode: nothing is durable, so the drop accounting
            // happens at enqueue/retry-exhaustion instead of here.
            return Ok(SpooledAuditRecord::with_bounded_diff(
                event,
                crate::admin::audit_spool::AUDIT_SPOOL_MAX_RECORD_BYTES,
            ));
        };
        let record = SpooledAuditRecord::with_bounded_diff(event, spool.max_record_bytes());
        if record.diff_omitted {
            self.metrics
                .truncated_diffs
                .fetch_add(1, Ordering::Relaxed);
        }
        match spool.write(&record) {
            Ok(()) => {
                self.metrics.spooled.fetch_add(1, Ordering::Relaxed);
                self.metrics.spool_pending.fetch_add(1, Ordering::Relaxed);
                self.mark_available();
                Ok(record)
            }
            Err(error) => {
                let reason = AuditUnavailableReason::from_spool_error(&error);
                self.metrics.dropped_handoff.fetch_add(1, Ordering::Relaxed);
                self.mark_unavailable(reason);
                Err(reason)
            }
        }
    }

    /// Finish one event: remove it from the spool after acceptance.
    fn note_delivered(&self, record: &SpooledAuditRecord) {
        self.metrics.delivered.fetch_add(1, Ordering::Relaxed);
        if let Some(spool) = self.spool.as_ref() {
            if spool.remove_pending(record.id()).is_err() {
                // The record stays durable and will be replayed; a duplicate
                // insert is a no-op because delivery is idempotent on the id.
                warn!(
                    audit_event_id = %record.id(),
                    surface = "audit_spool_remove",
                    "Delivered admin audit event could not be removed from the spool; it will \
                     be replayed idempotently"
                );
            } else {
                saturating_decrement(&self.metrics.spool_pending);
            }
        }
        self.mark_available();
    }

    /// Move an event that exhausted its retry budget into operator-visible
    /// retention. Never silently deletes while retention capacity remains.
    fn note_unrecoverable(&self, record: &SpooledAuditRecord) {
        self.metrics.retained.fetch_add(1, Ordering::Relaxed);
        self.mark_unavailable(AuditUnavailableReason::DeliveryExhausted);
        let Some(spool) = self.spool.as_ref() else {
            self.metrics.dropped_no_spool.fetch_add(1, Ordering::Relaxed);
            error!(
                audit_event_id = %record.id(),
                surface = "audit_event_unrecoverable",
                reason = AuditUnavailableReason::DeliveryExhausted.as_str(),
                "Admin audit event exhausted delivery retries with no durable spool configured"
            );
            return;
        };
        match spool.retain_unrecoverable(record.id()) {
            Ok(true) => {
                saturating_decrement(&self.metrics.spool_pending);
                self.metrics.spool_retained.fetch_add(1, Ordering::Relaxed);
                error!(
                    audit_event_id = %record.id(),
                    surface = "audit_event_unrecoverable",
                    reason = AuditUnavailableReason::DeliveryExhausted.as_str(),
                    "Admin audit event exhausted delivery retries and was retained for operator \
                     remediation"
                );
            }
            Ok(false) => {
                self.metrics
                    .dropped_retained_capacity
                    .fetch_add(1, Ordering::Relaxed);
                self.mark_unavailable(AuditUnavailableReason::RetainedCapacity);
                error!(
                    audit_event_id = %record.id(),
                    surface = "audit_event_unrecoverable",
                    reason = AuditUnavailableReason::RetainedCapacity.as_str(),
                    "Admin audit retained-record capacity is exhausted; the newest unrecoverable \
                     event was discarded to preserve older evidence"
                );
            }
            Err(error) => {
                self.mark_unavailable(AuditUnavailableReason::from_spool_error(&error));
                error!(
                    audit_event_id = %record.id(),
                    surface = "audit_event_unrecoverable",
                    reason = error.reason(),
                    "Admin audit event could not be moved into retained state"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Global pipeline installation
// ---------------------------------------------------------------------------

static AUDIT_PIPELINE: OnceLock<Arc<AuditPipeline>> = OnceLock::new();

static DISABLED_PIPELINE: LazyLock<Arc<AuditPipeline>> = LazyLock::new(|| {
    // Non-serving callers (tests, tooling) that never called `initialize` see a
    // disabled pipeline rather than an implicit spool on the local filesystem.
    Arc::new(AuditPipeline {
        config: AuditPipelineConfig {
            enabled: false,
            spool_dir: None,
            ..AuditPipelineConfig::default()
        },
        spool: None,
        metrics: Arc::new(AuditPipelineMetrics::default()),
        available: AtomicBool::new(true),
        last_unavailable_reason: AtomicU8::new(AuditUnavailableReason::None as u8),
        draining: AtomicBool::new(false),
        spool_gauges_refreshed_at_ms: AtomicI64::new(0),
    })
});

/// Install the process audit pipeline. Called once from `main` before mode
/// dispatch, so a fail-closed deployment refuses to start with an unusable
/// spool rather than discovering it on the first mutation.
pub fn initialize(config: AuditPipelineConfig) -> Result<(), String> {
    let pipeline = Arc::new(AuditPipeline::new(config)?);
    if pipeline.config.enabled {
        info!(
            durability = pipeline.durability_mode().as_str(),
            policy = pipeline.config.policy.as_str(),
            queue_capacity = pipeline.config.queue_capacity,
            spool_max_records = pipeline.config.spool_max_records,
            retained_max_records = pipeline.config.retained_max_records,
            max_delivery_attempts = pipeline.config.max_delivery_attempts,
            "Admin audit delivery pipeline active"
        );
    }
    // A second install in one process (in-process harnesses) keeps the first
    // pipeline rather than orphaning workers that already hold its spool.
    let _ = AUDIT_PIPELINE.set(pipeline);
    Ok(())
}

/// The installed pipeline, or a disabled one when `initialize` never ran.
pub fn pipeline() -> Arc<AuditPipeline> {
    AUDIT_PIPELINE
        .get()
        .cloned()
        .unwrap_or_else(|| Arc::clone(&DISABLED_PIPELINE))
}

/// Reason the admin write gate must refuse an audited mutation, if any.
/// Pure: safe to call from `/health` as well as from the admission path.
pub fn fail_closed_block_reason() -> Option<&'static str> {
    pipeline().fail_closed_block_reason()
}

/// Count one admin mutation refused by the fail-closed policy.
pub fn note_fail_closed_rejection() {
    pipeline().note_fail_closed_rejection();
}

/// Cheap availability check for callers that must not pay a backlog rescan
/// (notably the unauthenticated `/health` tier).
pub fn pipeline_available() -> bool {
    pipeline().is_available()
}

/// Health/status projection of the installed pipeline.
pub fn pipeline_status() -> AuditPipelineStatus {
    pipeline().status()
}

/// Counter snapshot for the Prometheus exposition.
pub fn pipeline_metrics_snapshot() -> AuditPipelineMetricsSnapshot {
    let pipeline = pipeline();
    pipeline.refresh_spool_gauges();
    pipeline.metrics.snapshot()
}

// ---------------------------------------------------------------------------
// Worker
// ---------------------------------------------------------------------------

struct AuditEnvelope {
    record: SpooledAuditRecord,
}

/// One delivery worker: a bounded queue, its task, and the shutdown handle.
pub struct AuditWorker {
    pipeline: Arc<AuditPipeline>,
    tx: Mutex<Option<mpsc::Sender<AuditEnvelope>>>,
    join: Mutex<Option<JoinHandle<()>>>,
}

impl AuditWorker {
    /// Spawn a worker delivering into `delivery`.
    ///
    /// `on_target_lost` runs when the delivery target's `Weak` can no longer be
    /// upgraded, so the process-global registry can drop the stale entry.
    pub fn spawn(
        pipeline: Arc<AuditPipeline>,
        delivery: Arc<dyn AuditEventDelivery>,
        alive: Option<Weak<dyn DatabaseBackend>>,
        on_target_lost: Option<Box<dyn Fn() + Send + Sync>>,
    ) -> Arc<Self> {
        let capacity = pipeline.config.queue_capacity.max(AUDIT_QUEUE_CAPACITY_MIN);
        let (tx, rx) = mpsc::channel::<AuditEnvelope>(capacity);
        let worker_pipeline = Arc::clone(&pipeline);
        let join = tokio::spawn(async move {
            run_worker(worker_pipeline, delivery, alive, on_target_lost, rx).await;
        });
        Arc::new(Self {
            pipeline,
            tx: Mutex::new(Some(tx)),
            join: Mutex::new(Some(join)),
        })
    }

    /// Spawn a worker over an arbitrary delivery target.
    ///
    /// External tests drive queue saturation, backend failure/recovery, replay,
    /// idempotency, and shutdown through this entry point; the binary target
    /// otherwise flags it as dead code.
    #[allow(dead_code)]
    pub fn spawn_for_delivery(
        pipeline: Arc<AuditPipeline>,
        delivery: Arc<dyn AuditEventDelivery>,
    ) -> Arc<Self> {
        Self::spawn(pipeline, delivery, None, None)
    }

    fn sender(&self) -> Option<mpsc::Sender<AuditEnvelope>> {
        self.tx.lock().ok().and_then(|guard| guard.clone())
    }

    /// Durable handoff + enqueue. Errors only when the *durable* step failed.
    ///
    /// A full or closed queue is not an error once the record is on disk: the
    /// replay scan picks it up, so back-pressure degrades latency rather than
    /// integrity.
    pub fn record(&self, event: AuditEvent) -> Result<(), anyhow::Error> {
        let event_id = event.id.clone();
        let record = match self.pipeline.spool_record(event) {
            Ok(record) => record,
            Err(reason) => {
                return Err(anyhow!(
                    "admin audit durable handoff failed ({}) for audit event {}",
                    reason.as_str(),
                    event_id
                ));
            }
        };
        let durable = self.pipeline.spool.is_some();
        let Some(tx) = self.sender() else {
            return self.note_enqueue_failure(
                durable,
                AuditUnavailableReason::WorkerUnavailable,
                &event_id,
            );
        };
        match tx.try_send(AuditEnvelope { record }) {
            Ok(()) => {
                self.pipeline.metrics.enqueued.fetch_add(1, Ordering::Relaxed);
                self.pipeline.metrics.queue_depth.store(
                    (self.pipeline.config.queue_capacity.saturating_sub(tx.capacity())) as u64,
                    Ordering::Relaxed,
                );
                Ok(())
            }
            Err(TrySendError::Full(_)) => self.note_enqueue_failure(
                durable,
                AuditUnavailableReason::QueueSaturated,
                &event_id,
            ),
            Err(TrySendError::Closed(_)) => self.note_enqueue_failure(
                durable,
                AuditUnavailableReason::WorkerUnavailable,
                &event_id,
            ),
        }
    }

    fn note_enqueue_failure(
        &self,
        durable: bool,
        reason: AuditUnavailableReason,
        event_id: &str,
    ) -> Result<(), anyhow::Error> {
        if durable {
            // Already fsynced; the replay scan owns delivery from here.
            warn!(
                audit_event_id = %event_id,
                surface = "audit_enqueue",
                reason = reason.as_str(),
                "Admin audit event deferred to durable spool replay"
            );
            return Ok(());
        }
        self.pipeline
            .metrics
            .dropped_no_spool
            .fetch_add(1, Ordering::Relaxed);
        self.pipeline.mark_unavailable(reason);
        Err(anyhow!(
            "admin audit event {} was not enqueued ({})",
            event_id,
            reason.as_str()
        ))
    }

    /// Close admission and drain within `timeout`.
    ///
    /// Undelivered records stay in `pending/`, so an expired deadline costs
    /// latency, never durability.
    pub async fn shutdown(&self, timeout: Duration) -> bool {
        self.pipeline.draining.store(true, Ordering::Release);
        if let Ok(mut guard) = self.tx.lock() {
            let _ = guard.take();
        }
        let handle = self.join.lock().ok().and_then(|mut guard| guard.take());
        let Some(handle) = handle else {
            return true;
        };
        match tokio::time::timeout(timeout, handle).await {
            Ok(_) => true,
            Err(_) => {
                warn!(
                    surface = "audit_shutdown",
                    "Admin audit drain deadline expired; undelivered events remain durable and \
                     replayable"
                );
                false
            }
        }
    }
}

/// Exponential backoff for attempt `attempt` (1-based), capped.
fn retry_delay(attempt: u32) -> Duration {
    let shift = attempt.saturating_sub(1).min(20);
    let millis = AUDIT_RETRY_BASE_DELAY_MS
        .saturating_mul(1u64 << shift)
        .min(AUDIT_RETRY_MAX_DELAY_MS);
    Duration::from_millis(millis)
}

enum DeliveryOutcome {
    Delivered,
    Retained,
    /// Shutdown interrupted the retry loop; the record stays durable.
    Deferred,
}

async fn deliver_record(
    pipeline: &Arc<AuditPipeline>,
    delivery: &Arc<dyn AuditEventDelivery>,
    mut record: SpooledAuditRecord,
) -> DeliveryOutcome {
    loop {
        match delivery.deliver(&record.event).await {
            Ok(()) => {
                pipeline.note_delivered(&record);
                return DeliveryOutcome::Delivered;
            }
            Err(_) => {
                record.attempts = record.attempts.saturating_add(1);
                pipeline
                    .metrics
                    .delivery_failures
                    .fetch_add(1, Ordering::Relaxed);
                error!(
                    audit_event_id = %record.event.id,
                    surface = "audit_event_persist",
                    attempts = record.attempts,
                    detail_withheld = true,
                    "Failed to persist admin audit event; persistence detail withheld"
                );
                if record.attempts >= pipeline.config.max_delivery_attempts {
                    pipeline.note_unrecoverable(&record);
                    return DeliveryOutcome::Retained;
                }
                if let Some(spool) = pipeline.spool.as_ref()
                    && let Err(error) = spool.update_attempts(&record)
                {
                    // Losing attempt bookkeeping only costs budget accuracy;
                    // the record itself is still durable.
                    warn!(
                        audit_event_id = %record.event.id,
                        surface = "audit_spool_attempts",
                        reason = error.reason(),
                        "Could not persist admin audit delivery attempt count"
                    );
                }
                pipeline.metrics.retries.fetch_add(1, Ordering::Relaxed);
                if pipeline.draining.load(Ordering::Acquire) {
                    return DeliveryOutcome::Deferred;
                }
                tokio::time::sleep(retry_delay(record.attempts)).await;
                if pipeline.draining.load(Ordering::Acquire) {
                    return DeliveryOutcome::Deferred;
                }
            }
        }
    }
}

/// Replay durable records that were never enqueued (restart, queue overflow, or
/// a deferred shutdown). Bounded per call so shutdown stays responsive.
async fn replay_spool(pipeline: &Arc<AuditPipeline>, delivery: &Arc<dyn AuditEventDelivery>) {
    let Some(spool) = pipeline.spool.clone() else {
        return;
    };
    let ids = {
        let spool = Arc::clone(&spool);
        match tokio::task::spawn_blocking(move || spool.list_pending_ids(AUDIT_REPLAY_BATCH)).await {
            Ok(ids) => ids,
            Err(_) => return,
        }
    };
    for id in ids {
        if pipeline.draining.load(Ordering::Acquire) {
            return;
        }
        let read = {
            let spool = Arc::clone(&spool);
            let id = id.clone();
            tokio::task::spawn_blocking(move || spool.read_pending(&id)).await
        };
        let record = match read {
            Ok(Ok(record)) => record,
            Ok(Err(error)) => {
                if error.kind == SpoolErrorKind::Corrupt {
                    pipeline.metrics.corrupt.fetch_add(1, Ordering::Relaxed);
                    pipeline.mark_unavailable(AuditUnavailableReason::CorruptRecord);
                    error!(
                        audit_event_id = %id,
                        surface = "audit_spool_replay",
                        reason = error.reason(),
                        "Corrupt admin audit spool record quarantined for operator remediation"
                    );
                }
                continue;
            }
            Err(_) => continue,
        };
        if record.attempts >= pipeline.config.max_delivery_attempts {
            pipeline.note_unrecoverable(&record);
            continue;
        }
        pipeline.metrics.replayed.fetch_add(1, Ordering::Relaxed);
        if matches!(
            deliver_record(pipeline, delivery, record).await,
            DeliveryOutcome::Deferred
        ) {
            return;
        }
    }
}

async fn run_worker(
    pipeline: Arc<AuditPipeline>,
    delivery: Arc<dyn AuditEventDelivery>,
    alive: Option<Weak<dyn DatabaseBackend>>,
    on_target_lost: Option<Box<dyn Fn() + Send + Sync>>,
    mut rx: mpsc::Receiver<AuditEnvelope>,
) {
    let mut stale_check = interval(Duration::from_secs(AUDIT_SINK_STALE_CHECK_INTERVAL_SECONDS));
    stale_check.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut replay = interval(Duration::from_secs(AUDIT_REPLAY_INTERVAL_SECONDS));
    replay.set_missed_tick_behavior(MissedTickBehavior::Delay);

    // Replay anything a previous process left durable before serving new work.
    //
    // The replay scan and the queue can briefly select the same record (it is
    // enqueued but still pending on disk). Delivery is idempotent on the event
    // id, so the only cost is a duplicate insert attempt and a transient gauge
    // drift that the throttled backlog rescan reconciles.
    replay_spool(&pipeline, &delivery).await;

    loop {
        tokio::select! {
            biased;
            maybe_envelope = rx.recv() => {
                let Some(envelope) = maybe_envelope else {
                    // Admission closed: drain the durable backlog once, then exit.
                    replay_spool(&pipeline, &delivery).await;
                    break;
                };
                saturating_decrement(&pipeline.metrics.queue_depth);
                if matches!(
                    deliver_record(&pipeline, &delivery, envelope.record).await,
                    DeliveryOutcome::Deferred
                ) {
                    break;
                }
            }
            _ = replay.tick() => {
                replay_spool(&pipeline, &delivery).await;
            }
            _ = stale_check.tick() => {
                if let Some(alive) = alive.as_ref()
                    && alive.upgrade().is_none()
                {
                    if let Some(callback) = on_target_lost.as_ref() {
                        callback();
                    }
                    break;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Per-backend worker registry
// ---------------------------------------------------------------------------

struct AuditSinkEntry {
    backend: Weak<dyn DatabaseBackend>,
    worker: Arc<AuditWorker>,
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

fn spawn_backend_worker(key: usize, db: &Arc<dyn DatabaseBackend>) -> AuditSinkEntry {
    let backend = Arc::downgrade(db);
    let delivery: Arc<dyn AuditEventDelivery> = Arc::new(DatabaseAuditDelivery {
        db: backend.clone(),
    });
    let worker = AuditWorker::spawn(
        pipeline(),
        delivery,
        Some(backend.clone()),
        Some(Box::new(move || remove_stale_sink(key))),
    );
    AuditSinkEntry { backend, worker }
}

fn worker_for_db(db: Arc<dyn DatabaseBackend>) -> Arc<AuditWorker> {
    let key = db_key(&db);
    // Fast path: live entry for this exact backend pointer.
    if let Some(entry) = AUDIT_SINKS.get(&key)
        && entry_matches_backend(&entry, &db)
    {
        return Arc::clone(&entry.worker);
    }

    // Slow path: take the entry write lock so the spawn-and-insert is atomic.
    // Without this, two threads can both miss the `get`, both spawn a worker,
    // and only one survives — leaving the other's mpsc Sender to be dropped at
    // the end of `record`, which closes that orphan worker before its event is
    // processed. Holding the entry lock across the live-check + spawn + insert
    // guarantees one worker per backend Arc.
    let entry = AUDIT_SINKS
        .entry(key)
        .or_insert_with(|| spawn_backend_worker(key, &db));
    if entry_matches_backend(&entry, &db) {
        return Arc::clone(&entry.worker);
    }

    // The existing entry references a different (stale) backend at the same
    // address — drop it and retry. Calling `remove` while still holding the
    // RefMut would deadlock, so release it first.
    drop(entry);
    AUDIT_SINKS.remove(&key);
    let entry = spawn_backend_worker(key, &db);
    let worker = Arc::clone(&entry.worker);
    AUDIT_SINKS.insert(key, entry);
    worker
}

/// Durably record an audited admin mutation.
///
/// Returns `Ok(())` once the event is on stable storage (or, in memory-only
/// mode, once it is queued). An error means the durable handoff did not happen;
/// callers log it and, under `fail_closed`, the write gate refuses subsequent
/// audited mutations.
pub async fn record(
    enabled: bool,
    db: Arc<dyn DatabaseBackend>,
    event: AuditEvent,
) -> Result<(), anyhow::Error> {
    if !enabled {
        return Ok(());
    }

    let worker = worker_for_db(db);
    // The durable write is blocking filesystem work. This is the admin mutation
    // path, never a proxy hot path, so moving it onto the blocking pool is the
    // correct trade: it keeps the reactor free while the response waits for
    // durability.
    tokio::task::spawn_blocking(move || worker.record(event))
        .await
        .unwrap_or_else(|error| Err(anyhow!("admin audit durable handoff task failed: {error}")))
}

/// Drain every registered audit worker within `timeout`.
///
/// Called from each serving mode's shutdown path **before** the database Arc is
/// dropped. Anything still undelivered stays in the durable spool.
pub async fn shutdown(timeout: Duration) {
    let workers: Vec<Arc<AuditWorker>> = AUDIT_SINKS
        .iter()
        .map(|entry| Arc::clone(&entry.worker))
        .collect();
    if workers.is_empty() {
        return;
    }
    let deadline = Instant::now() + timeout;
    for worker in workers {
        let remaining = deadline.saturating_duration_since(Instant::now());
        worker.shutdown(remaining).await;
    }
    AUDIT_SINKS.clear();
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
