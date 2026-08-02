//! Durable admin audit delivery pipeline (issue #2421).
//!
//! Covers queue saturation, backend failure/recovery, process-restart replay,
//! shutdown drain, idempotency, unavailability policy, bounds/corruption
//! handling, and redaction survival across the durable representation.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use ferrum_edge::admin::audit::{
    AuditDurabilityMode, AuditEvent, AuditEventDelivery, AuditPipeline, AuditPipelineConfig,
    AuditUnavailablePolicy, AuditWorker, credential_update_diff, update_diff,
};
use ferrum_edge::admin::audit_spool::{
    AUDIT_DIFF_OMITTED_MARKER, AUDIT_SPOOL_RECORD_VERSION, AuditSpool, SpooledAuditRecord,
    is_valid_record_id, record_id_from_file_name,
};
use serde_json::json;
use tempfile::TempDir;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn event_with(id: &str, diff: serde_json::Value) -> AuditEvent {
    AuditEvent {
        id: id.to_string(),
        ts: Utc::now(),
        actor: "audit-user".to_string(),
        action: "update".to_string(),
        resource_type: "proxy".to_string(),
        resource_id: "proxy-1".to_string(),
        namespace: "ferrum".to_string(),
        diff,
    }
}

fn event() -> AuditEvent {
    event_with(
        &Uuid::new_v4().to_string(),
        update_diff(json!({"name": "before"}), json!({"name": "after"})),
    )
}

fn config(spool_dir: Option<&TempDir>) -> AuditPipelineConfig {
    AuditPipelineConfig {
        enabled: true,
        spool_dir: spool_dir.map(|dir| dir.path().to_path_buf()),
        policy: AuditUnavailablePolicy::FailOpen,
        queue_capacity: 8,
        spool_max_records: 64,
        retained_max_records: 8,
        max_delivery_attempts: 3,
    }
}

/// Counts every delivery attempt per event id so at-least-once transport and
/// idempotent convergence can be asserted separately.
#[derive(Default)]
struct RecordingDelivery {
    fail_next: AtomicU64,
    always_fail: AtomicBool,
    attempts: Mutex<HashMap<String, u64>>,
    accepted: Mutex<Vec<AuditEvent>>,
}

impl RecordingDelivery {
    fn failing() -> Arc<Self> {
        let delivery = Arc::new(Self::default());
        delivery.always_fail.store(true, Ordering::SeqCst);
        delivery
    }

    fn recover(&self) {
        self.always_fail.store(false, Ordering::SeqCst);
        self.fail_next.store(0, Ordering::SeqCst);
    }

    fn accepted_ids(&self) -> Vec<String> {
        self.accepted
            .lock()
            .expect("accepted mutex is not poisoned in tests")
            .iter()
            .map(|event| event.id.clone())
            .collect()
    }

    fn attempts_for(&self, id: &str) -> u64 {
        *self
            .attempts
            .lock()
            .expect("attempts mutex is not poisoned in tests")
            .get(id)
            .unwrap_or(&0)
    }
}

#[async_trait]
impl AuditEventDelivery for RecordingDelivery {
    async fn deliver(&self, event: &AuditEvent) -> Result<(), anyhow::Error> {
        {
            let mut attempts = self
                .attempts
                .lock()
                .expect("attempts mutex is not poisoned in tests");
            *attempts.entry(event.id.clone()).or_insert(0) += 1;
        }
        if self.always_fail.load(Ordering::SeqCst) {
            return Err(anyhow::anyhow!("backend unavailable"));
        }
        if self
            .fail_next
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                Some(value.saturating_sub(1))
            })
            .unwrap_or(0)
            > 0
        {
            return Err(anyhow::anyhow!("transient backend failure"));
        }
        // Idempotent on the event id, exactly as every production backend is.
        let mut accepted = self
            .accepted
            .lock()
            .expect("accepted mutex is not poisoned in tests");
        if !accepted.iter().any(|existing| existing.id == event.id) {
            accepted.push(event.clone());
        }
        Ok(())
    }
}

/// Poll until `predicate` holds or the budget expires. Delivery is retried on a
/// bounded backoff, so the assertions are eventual rather than immediate.
async fn wait_until(budget: Duration, mut predicate: impl FnMut() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        if predicate() {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn pending_ids(dir: &TempDir) -> Vec<String> {
    read_ids(dir, "pending")
}

fn retained_ids(dir: &TempDir) -> Vec<String> {
    read_ids(dir, "failed")
}

fn read_ids(dir: &TempDir, sub: &str) -> Vec<String> {
    let mut ids: Vec<String> = std::fs::read_dir(dir.path().join(sub))
        .map(|entries| {
            entries
                .flatten()
                .filter_map(|entry| {
                    entry
                        .path()
                        .file_name()
                        .and_then(|name| name.to_str())
                        .and_then(record_id_from_file_name)
                })
                .collect()
        })
        .unwrap_or_default();
    ids.sort();
    ids
}

// ---------------------------------------------------------------------------
// Policy and configuration
// ---------------------------------------------------------------------------

#[test]
fn unavailability_policy_parses_documented_values() {
    assert_eq!(
        AuditUnavailablePolicy::parse("fail_open").unwrap(),
        AuditUnavailablePolicy::FailOpen
    );
    assert_eq!(
        AuditUnavailablePolicy::parse("  FAIL_CLOSED ").unwrap(),
        AuditUnavailablePolicy::FailClosed
    );
    assert_eq!(AuditUnavailablePolicy::FailOpen.as_str(), "fail_open");
    assert_eq!(AuditUnavailablePolicy::FailClosed.as_str(), "fail_closed");
}

#[test]
fn unavailability_policy_rejects_unknown_value_instead_of_defaulting_open() {
    let error = AuditUnavailablePolicy::parse("best_effort").unwrap_err();
    assert!(error.contains("FERRUM_ADMIN_AUDIT_UNAVAILABLE_POLICY"));
}

#[test]
fn fail_closed_requires_a_durable_spool_directory() {
    let mut cfg = AuditPipelineConfig {
        enabled: true,
        spool_dir: None,
        policy: AuditUnavailablePolicy::FailClosed,
        ..AuditPipelineConfig::default()
    };
    let error = cfg.validate().unwrap_err();
    assert!(error.contains("fail_closed"));

    // The same configuration with auditing disabled is not a startup failure.
    cfg.enabled = false;
    assert!(cfg.validate().is_ok());
}

#[test]
fn pipeline_config_bounds_are_rejected_not_silently_clamped() {
    for mutate in [
        (|c: &mut AuditPipelineConfig| c.queue_capacity = 0) as fn(&mut AuditPipelineConfig),
        |c: &mut AuditPipelineConfig| c.queue_capacity = 65_537,
        |c: &mut AuditPipelineConfig| c.spool_max_records = 0,
        |c: &mut AuditPipelineConfig| c.spool_max_records = 10_000_001,
        |c: &mut AuditPipelineConfig| c.retained_max_records = 0,
        |c: &mut AuditPipelineConfig| c.max_delivery_attempts = 0,
        |c: &mut AuditPipelineConfig| c.max_delivery_attempts = 1_001,
    ] {
        let mut cfg = AuditPipelineConfig::default();
        mutate(&mut cfg);
        assert!(cfg.validate().is_err(), "out-of-range value must be rejected");
    }
}

// ---------------------------------------------------------------------------
// Spool primitives: bounds, corruption, path safety, redaction
// ---------------------------------------------------------------------------

#[test]
fn record_ids_reject_path_traversal_and_separators() {
    assert!(is_valid_record_id(&Uuid::new_v4().to_string()));
    for hostile in [
        "..",
        "../../etc/passwd",
        "a/b",
        "a\\b",
        "a.b",
        "",
        &"a".repeat(65),
        "id\0",
    ] {
        assert!(!is_valid_record_id(hostile), "accepted hostile id {hostile:?}");
    }
    assert_eq!(record_id_from_file_name("abc.json").as_deref(), Some("abc"));
    assert_eq!(record_id_from_file_name("../x.json"), None);
    assert_eq!(record_id_from_file_name("abc.tmp"), None);
}

#[test]
fn spool_round_trip_preserves_redacted_credential_diffs() {
    let dir = TempDir::new().unwrap();
    let spool = AuditSpool::open(dir.path(), 16, 4).unwrap();
    let diff = credential_update_diff(
        "basicauth",
        json!({"username": "svc"}),
        json!({"username": "svc"}),
    );
    let id = Uuid::new_v4().to_string();
    let record = SpooledAuditRecord::with_bounded_diff(event_with(&id, diff), 1024 * 1024);
    spool.write(&record).unwrap();

    let loaded = spool.read_pending(&id).unwrap();
    assert_eq!(loaded.v, AUDIT_SPOOL_RECORD_VERSION);
    assert!(!loaded.diff_omitted);
    // The durable representation carries exactly the redacted marker the
    // database row would carry — no credential material is added by spooling.
    assert_eq!(loaded.event.diff["credential_change"], json!("[REDACTED]"));
    let serialized = serde_json::to_string(&loaded).unwrap();
    assert!(!serialized.contains("password"));

    spool.remove_pending(&id).unwrap();
    assert!(spool.read_pending(&id).is_err());
    // Removal is idempotent.
    spool.remove_pending(&id).unwrap();
}

#[test]
fn oversized_diff_is_replaced_by_a_marker_and_identity_survives() {
    let huge = json!({"blob": "x".repeat(4096)});
    let id = Uuid::new_v4().to_string();
    let record = SpooledAuditRecord::with_bounded_diff(event_with(&id, huge), 512);

    assert!(record.diff_omitted);
    assert_eq!(record.event.diff["omitted"], json!(AUDIT_DIFF_OMITTED_MARKER));
    // Losing "that a change happened" is the failure #2421 is about, so the
    // reconcilable identity must survive even when the body cannot.
    assert_eq!(record.event.id, id);
    assert_eq!(record.event.resource_type, "proxy");
    assert_eq!(record.event.resource_id, "proxy-1");
    assert_eq!(record.event.namespace, "ferrum");
}

#[test]
fn spool_saturation_fails_the_durable_handoff_rather_than_overfilling() {
    let dir = TempDir::new().unwrap();
    let spool = AuditSpool::open(dir.path(), 2, 4).unwrap();
    for _ in 0..2 {
        let record = SpooledAuditRecord::with_bounded_diff(event(), 1024 * 1024);
        spool.write(&record).unwrap();
    }
    let overflow = SpooledAuditRecord::with_bounded_diff(event(), 1024 * 1024);
    let error = spool.write(&overflow).unwrap_err();
    assert_eq!(error.reason(), "spool_saturated");
}

#[test]
fn spool_write_is_idempotent_for_an_already_durable_id() {
    let dir = TempDir::new().unwrap();
    let spool = AuditSpool::open(dir.path(), 2, 4).unwrap();
    let record = SpooledAuditRecord::with_bounded_diff(event(), 1024 * 1024);
    spool.write(&record).unwrap();
    // Re-spooling the same id must not consume a second backlog slot.
    spool.write(&record).unwrap();
    spool.write(&record).unwrap();
    assert_eq!(spool.stats().pending_records, 1);
}

#[test]
fn corrupt_records_are_quarantined_and_never_replayed() {
    let dir = TempDir::new().unwrap();
    let spool = AuditSpool::open(dir.path(), 16, 4).unwrap();

    // Unparseable body.
    let garbage_id = Uuid::new_v4().to_string();
    std::fs::write(
        dir.path().join("pending").join(format!("{garbage_id}.json")),
        b"{ not json",
    )
    .unwrap();

    // Well-formed JSON with an unsupported record version.
    let version_id = Uuid::new_v4().to_string();
    let mut record = SpooledAuditRecord::with_bounded_diff(event_with(&version_id, json!({})), 4096);
    record.v = AUDIT_SPOOL_RECORD_VERSION + 1;
    std::fs::write(
        dir.path().join("pending").join(format!("{version_id}.json")),
        serde_json::to_vec(&record).unwrap(),
    )
    .unwrap();

    // Embedded id disagreeing with the filename (a swapped/forged record).
    let outer_id = Uuid::new_v4().to_string();
    let inner = SpooledAuditRecord::with_bounded_diff(event(), 4096);
    std::fs::write(
        dir.path().join("pending").join(format!("{outer_id}.json")),
        serde_json::to_vec(&inner).unwrap(),
    )
    .unwrap();

    for id in [&garbage_id, &version_id, &outer_id] {
        let error = spool.read_pending(id).unwrap_err();
        assert_eq!(error.reason(), "corrupt_record", "id {id}");
    }
    assert_eq!(spool.stats().pending_records, 0);
    assert_eq!(spool.stats().retained_records, 3);
}

#[test]
fn foreign_files_in_the_spool_directory_are_not_listed_as_records() {
    let dir = TempDir::new().unwrap();
    let spool = AuditSpool::open(dir.path(), 16, 4).unwrap();
    std::fs::write(dir.path().join("pending").join("README.txt"), b"operator note").unwrap();
    std::fs::write(dir.path().join("pending").join("not-a-record"), b"junk").unwrap();
    let record = SpooledAuditRecord::with_bounded_diff(event(), 4096);
    spool.write(&record).unwrap();

    let ids = spool.list_pending_ids(64);
    assert_eq!(ids, vec![record.event.id.clone()]);
}

// ---------------------------------------------------------------------------
// Delivery: failure/recovery, saturation, replay, retention, shutdown
// ---------------------------------------------------------------------------

#[tokio::test]
async fn committed_mutation_is_durable_before_acknowledgement() {
    let dir = TempDir::new().unwrap();
    let pipeline = Arc::new(AuditPipeline::new(config(Some(&dir))).unwrap());
    assert_eq!(pipeline.durability_mode(), AuditDurabilityMode::Spool);

    let delivery = RecordingDelivery::failing();
    let worker = AuditWorker::spawn_for_delivery(Arc::clone(&pipeline), delivery.clone());
    let recorded = event();

    // The backend is down, yet the handoff succeeds: the response may proceed
    // because the event is already on stable storage.
    worker.record(recorded.clone()).unwrap();
    assert!(pending_ids(&dir).contains(&recorded.id));

    delivery.recover();
    assert!(
        wait_until(Duration::from_secs(10), || delivery
            .accepted_ids()
            .contains(&recorded.id))
        .await,
        "recovered backend must eventually receive the event"
    );
    assert!(
        wait_until(Duration::from_secs(5), || pending_ids(&dir).is_empty()).await,
        "the spool record is removed only after the backend accepts it"
    );
    worker.shutdown(Duration::from_secs(5)).await;
}

#[tokio::test]
async fn queue_saturation_defers_to_durable_replay_instead_of_dropping() {
    let dir = TempDir::new().unwrap();
    let mut cfg = config(Some(&dir));
    cfg.queue_capacity = 1;
    // A generous attempt budget keeps every record in `pending/` for the whole
    // assertion window, so this test measures saturation rather than retention.
    cfg.max_delivery_attempts = 50;
    let pipeline = Arc::new(AuditPipeline::new(cfg).unwrap());
    // A permanently failing backend keeps the worker busy so the bounded queue
    // saturates deterministically.
    let delivery = RecordingDelivery::failing();
    let worker = AuditWorker::spawn_for_delivery(Arc::clone(&pipeline), delivery.clone());

    let mut ids = Vec::new();
    for _ in 0..24 {
        let recorded = event();
        // Every handoff succeeds: saturation costs latency, never integrity.
        worker.record(recorded.clone()).unwrap();
        ids.push(recorded.id);
    }

    let durable = pending_ids(&dir);
    for id in &ids {
        assert!(durable.contains(id), "saturated queue dropped event {id}");
    }
    let snapshot = pipeline.metrics().snapshot();
    assert_eq!(snapshot.accepted_total, 24);
    assert_eq!(snapshot.spooled_total, 24);
    assert_eq!(snapshot.dropped_durable_handoff_failed_total, 0);
    assert_eq!(snapshot.dropped_no_durable_spool_total, 0);

    worker.shutdown(Duration::from_secs(2)).await;
    // An expired/aborted drain leaves the backlog replayable.
    assert!(!pending_ids(&dir).is_empty());
}

#[tokio::test]
async fn transient_backend_failure_recovers_and_converges_to_one_record() {
    let dir = TempDir::new().unwrap();
    let pipeline = Arc::new(AuditPipeline::new(config(Some(&dir))).unwrap());
    let delivery = Arc::new(RecordingDelivery::default());
    delivery.fail_next.store(2, Ordering::SeqCst);
    let worker = AuditWorker::spawn_for_delivery(Arc::clone(&pipeline), delivery.clone());

    let recorded = event();
    worker.record(recorded.clone()).unwrap();

    assert!(
        wait_until(Duration::from_secs(10), || delivery
            .accepted_ids()
            .contains(&recorded.id))
        .await,
        "bounded retry must recover from a transient failure"
    );
    // At-least-once transport: more attempts than acceptances.
    assert!(delivery.attempts_for(&recorded.id) >= 3);
    assert_eq!(
        delivery
            .accepted_ids()
            .iter()
            .filter(|id| **id == recorded.id)
            .count(),
        1,
        "idempotent delivery converges to exactly one durable record"
    );
    assert!(pipeline.metrics().snapshot().retries_total >= 2);
    worker.shutdown(Duration::from_secs(5)).await;
}

#[tokio::test]
async fn process_restart_replays_durable_records_with_a_stable_id() {
    let dir = TempDir::new().unwrap();

    // First "process": durable handoff succeeds, delivery never does.
    let first = Arc::new(AuditPipeline::new(config(Some(&dir))).unwrap());
    let down = RecordingDelivery::failing();
    let worker = AuditWorker::spawn_for_delivery(Arc::clone(&first), down);
    let recorded = event();
    worker.record(recorded.clone()).unwrap();
    worker.shutdown(Duration::from_secs(2)).await;
    assert!(pending_ids(&dir).contains(&recorded.id));

    // Second "process" over the same spool root.
    let second = Arc::new(AuditPipeline::new(config(Some(&dir))).unwrap());
    let delivery = Arc::new(RecordingDelivery::default());
    let replayer = AuditWorker::spawn_for_delivery(Arc::clone(&second), delivery.clone());

    assert!(
        wait_until(Duration::from_secs(10), || delivery
            .accepted_ids()
            .contains(&recorded.id))
        .await,
        "restart must replay the durable record"
    );
    // Replay reuses the original identity, which is what makes the idempotent
    // backend insert converge instead of forking audit history.
    let accepted = delivery
        .accepted
        .lock()
        .expect("accepted mutex is not poisoned in tests");
    let replayed = accepted
        .iter()
        .find(|candidate| candidate.id == recorded.id)
        .expect("replayed event present");
    assert_eq!(replayed.actor, recorded.actor);
    assert_eq!(replayed.resource_id, recorded.resource_id);
    assert_eq!(replayed.namespace, recorded.namespace);
    drop(accepted);
    assert!(second.metrics().snapshot().replayed_total >= 1);
    replayer.shutdown(Duration::from_secs(5)).await;
}

#[tokio::test]
async fn exhausted_retries_retain_the_record_for_operator_remediation() {
    let dir = TempDir::new().unwrap();
    let mut cfg = config(Some(&dir));
    cfg.max_delivery_attempts = 2;
    let pipeline = Arc::new(AuditPipeline::new(cfg).unwrap());
    let delivery = RecordingDelivery::failing();
    let worker = AuditWorker::spawn_for_delivery(Arc::clone(&pipeline), delivery);

    let recorded = event();
    worker.record(recorded.clone()).unwrap();

    assert!(
        wait_until(Duration::from_secs(10), || retained_ids(&dir)
            .contains(&recorded.id))
        .await,
        "an unrecoverable event must be retained, not silently dropped"
    );
    assert!(!pending_ids(&dir).contains(&recorded.id));

    let status = pipeline.status();
    assert!(!status.available);
    assert_eq!(status.last_unavailable_reason, "delivery_exhausted");
    assert_eq!(status.metrics.retained_total, 1);
    assert_eq!(status.metrics.dropped_durable_handoff_failed_total, 0);
    worker.shutdown(Duration::from_secs(5)).await;
}

#[tokio::test]
async fn shutdown_drains_accepted_events_before_returning() {
    let dir = TempDir::new().unwrap();
    let pipeline = Arc::new(AuditPipeline::new(config(Some(&dir))).unwrap());
    let delivery = Arc::new(RecordingDelivery::default());
    let worker = AuditWorker::spawn_for_delivery(Arc::clone(&pipeline), delivery.clone());

    let mut ids = Vec::new();
    for _ in 0..5 {
        let recorded = event();
        worker.record(recorded.clone()).unwrap();
        ids.push(recorded.id);
    }

    assert!(worker.shutdown(Duration::from_secs(10)).await);
    let accepted = delivery.accepted_ids();
    for id in &ids {
        assert!(accepted.contains(id), "shutdown abandoned event {id}");
    }
    assert!(pending_ids(&dir).is_empty());
}

// ---------------------------------------------------------------------------
// Unavailability policy behavior
// ---------------------------------------------------------------------------

#[tokio::test]
async fn fail_closed_blocks_after_a_failed_durable_handoff() {
    let dir = TempDir::new().unwrap();
    let mut cfg = config(Some(&dir));
    cfg.policy = AuditUnavailablePolicy::FailClosed;
    cfg.spool_max_records = 1;
    // Keep the single pending record in place for the whole assertion window.
    cfg.max_delivery_attempts = 50;
    let pipeline = Arc::new(AuditPipeline::new(cfg).unwrap());
    let delivery = RecordingDelivery::failing();
    let worker = AuditWorker::spawn_for_delivery(Arc::clone(&pipeline), delivery);

    assert!(pipeline.fail_closed_block_reason().is_none());
    worker.record(event()).unwrap();
    // The spool ceiling is reached, so the next durable handoff must fail.
    let error = worker.record(event()).unwrap_err();
    assert!(error.to_string().contains("spool_saturated"));

    assert_eq!(
        pipeline.fail_closed_block_reason(),
        Some("spool_saturated"),
        "fail_closed must refuse subsequent audited mutations"
    );
    // Observation is pure: reading the gate does not count a rejection.
    assert_eq!(pipeline.status().metrics.fail_closed_rejections_total, 0);
    pipeline.note_fail_closed_rejection();
    assert_eq!(pipeline.status().metrics.fail_closed_rejections_total, 1);
    assert_eq!(pipeline.status().metrics.dropped_durable_handoff_failed_total, 1);
    worker.shutdown(Duration::from_secs(2)).await;
}

#[tokio::test]
async fn fail_open_reports_a_memory_only_pipeline_without_blocking() {
    let mut cfg = AuditPipelineConfig {
        enabled: true,
        spool_dir: None,
        policy: AuditUnavailablePolicy::FailOpen,
        ..AuditPipelineConfig::default()
    };
    cfg.queue_capacity = 4;
    let pipeline = Arc::new(AuditPipeline::new(cfg).unwrap());

    assert_eq!(pipeline.durability_mode(), AuditDurabilityMode::Memory);
    // fail_open never blocks the write gate, whatever the durability mode.
    assert!(pipeline.fail_closed_block_reason().is_none());
    let status = pipeline.status();
    assert_eq!(status.durability, "memory");
    assert_eq!(status.policy, "fail_open");
    assert_eq!(status.last_unavailable_reason, "no_durable_spool");

    let delivery = Arc::new(RecordingDelivery::default());
    let worker = AuditWorker::spawn_for_delivery(Arc::clone(&pipeline), delivery.clone());
    let recorded = event();
    worker.record(recorded.clone()).unwrap();
    assert!(
        wait_until(Duration::from_secs(5), || delivery
            .accepted_ids()
            .contains(&recorded.id))
        .await
    );
    worker.shutdown(Duration::from_secs(5)).await;
}

#[test]
fn status_projection_exposes_counts_only() {
    let dir = TempDir::new().unwrap();
    let pipeline = AuditPipeline::new(config(Some(&dir))).unwrap();
    let rendered = serde_json::to_string(&pipeline.status()).unwrap();

    // The health/status surface must never carry actor identity, diff bodies,
    // credential markers, or the spool filesystem path.
    for forbidden in ["audit-user", "proxy-1", "REDACTED", "before", "after"] {
        assert!(
            !rendered.contains(forbidden),
            "status leaked {forbidden}: {rendered}"
        );
    }
    assert!(!rendered.contains(&dir.path().display().to_string()));
    assert!(rendered.contains("\"durability\":\"spool\""));
    assert!(rendered.contains("\"policy\":\"fail_open\""));
}
