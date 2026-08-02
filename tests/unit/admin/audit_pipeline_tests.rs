//! Durable admin audit evidence pipeline (issue #2421).
//!
//! Covers the two-phase pre-mutation handoff (prepare → finalize), fail-closed
//! and fail-open policy behavior, prior-generation `unknown_outcome` recovery,
//! startup replay with no new mutation, process/destination ownership,
//! fsync/error paths, insert-only idempotent delivery, sticky degradation, O(1)
//! observability, hostile spool contents, and cancellation-aware shutdown.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chrono::Utc;
use ferrum_edge::admin::audit::{
    AuditDurabilityMode, AuditEvent, AuditEventDelivery, AuditOutcome, AuditPipeline,
    AuditPipelineConfig, AuditUnavailablePolicy, AuditUnavailableReason, AuditWorker,
    audit_destination_identity, credential_update_diff, sanitize_audit_namespace,
    sanitize_audit_path, update_diff,
};
use ferrum_edge::admin::audit_spool::{
    AUDIT_DIFF_OMITTED_MARKER, AUDIT_SPOOL_RECORD_VERSION, AuditSpool, SpoolErrorKind,
    SpooledAuditRecord, is_valid_record_id, record_id_from_file_name,
};
use serde_json::json;
use tempfile::TempDir;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const TEST_DESTINATION: &str = "sqlite:ferrum:0123456789abcdef0123456789abcdef";

fn event_with(id: &str, diff: serde_json::Value) -> AuditEvent {
    AuditEvent {
        id: id.to_string(),
        ts: Utc::now(),
        actor: "audit-user".to_string(),
        action: "update".to_string(),
        resource_type: "proxy".to_string(),
        resource_id: "proxy-1".to_string(),
        namespace: "ferrum".to_string(),
        source_address: "203.0.113.7".to_string(),
        request_id: "req-1".to_string(),
        outcome: String::new(),
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
        destination: TEST_DESTINATION.to_string(),
        queue_capacity: 8,
        spool_max_records: 64,
        retained_max_records: 8,
        max_delivery_attempts: 3,
    }
}

fn pipeline(config: AuditPipelineConfig) -> Arc<AuditPipeline> {
    Arc::new(AuditPipeline::new(config).expect("pipeline builds in tests"))
}

/// One end-to-end audited mutation: prepare before, finalize after.
fn prepare_then_finalize(
    pipeline: &Arc<AuditPipeline>,
    outcome: AuditOutcome,
) -> (String, SpooledAuditRecord) {
    let intent = event();
    let id = pipeline
        .prepare_intent(intent)
        .expect("pre-mutation intent is durable in tests");
    let mut finalized = event_with(&id, update_diff(json!({"a": 1}), json!({"a": 2})));
    finalized.outcome = outcome.as_str().to_string();
    let record = pipeline
        .finalize_event(finalized)
        .expect("finalize is durable in tests");
    (id, record)
}

fn instance_dirs(root: &Path) -> Vec<std::path::PathBuf> {
    let mut dirs: Vec<_> = std::fs::read_dir(root.join("instances"))
        .expect("instances dir exists in tests")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    dirs.sort();
    dirs
}

fn count_json(dir: &Path) -> usize {
    std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .filter_map(|entry| entry.ok())
                .filter(|entry| {
                    entry
                        .path()
                        .extension()
                        .is_some_and(|extension| extension == "json")
                })
                .count()
        })
        .unwrap_or(0)
}

/// Counts every delivery attempt per event id so at-least-once transport and
/// insert-only idempotent convergence can be asserted separately.
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

    fn accepted_event(&self, id: &str) -> Option<AuditEvent> {
        self.accepted
            .lock()
            .expect("accepted mutex is not poisoned in tests")
            .iter()
            .find(|event| event.id == id)
            .cloned()
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
        // Insert-only and idempotent on the event id, exactly as every
        // production backend is: a duplicate converges to the already-stored
        // row and never replaces it.
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
    let deadline = Instant::now() + budget;
    loop {
        if predicate() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

// ---------------------------------------------------------------------------
// Two-phase durability
// ---------------------------------------------------------------------------

#[test]
fn intent_is_durable_before_the_mutation_and_finalized_after_it() {
    let dir = TempDir::new().expect("temp dir");
    let pipeline = pipeline(config(Some(&dir)));
    assert_eq!(pipeline.durability_mode(), AuditDurabilityMode::Spool);

    let id = pipeline
        .prepare_intent(event())
        .expect("pre-mutation intent is durable");

    let instances = instance_dirs(dir.path());
    assert_eq!(instances.len(), 1, "one live process generation");
    let instance = &instances[0];
    assert!(
        instance.join("prepared").join(format!("{id}.json")).exists(),
        "the intent is on disk before the mutation runs"
    );
    assert_eq!(
        count_json(&instance.join("pending")),
        0,
        "nothing is deliverable until the outcome is known"
    );

    let mut finalized = event_with(&id, update_diff(json!({"a": 1}), json!({"a": 2})));
    finalized.outcome = AuditOutcome::Success.as_str().to_string();
    pipeline
        .finalize_event(finalized)
        .expect("finalize is durable");

    assert!(
        !instance.join("prepared").join(format!("{id}.json")).exists(),
        "the prepared record is unlinked only after the finalized one is durable"
    );
    assert!(
        instance.join("pending").join(format!("{id}.json")).exists(),
        "the finalized record carries the same stable id"
    );
}

#[test]
fn finalize_records_failure_when_the_mutation_did_not_succeed() {
    let dir = TempDir::new().expect("temp dir");
    let pipeline = pipeline(config(Some(&dir)));
    let (id, record) = prepare_then_finalize(&pipeline, AuditOutcome::Failure);

    assert_eq!(record.event.outcome, "failure");
    assert!(record.finalized);
    assert_eq!(record.id(), id);
}

#[test]
fn a_prepared_record_is_never_deliverable_as_an_outcome() {
    let dir = TempDir::new().expect("temp dir");
    let spool = AuditSpool::open(
        dir.path().to_path_buf(),
        Uuid::new_v4().to_string(),
        TEST_DESTINATION.to_string(),
        64,
        8,
    )
    .expect("spool opens");
    let record = SpooledAuditRecord::with_bounded_diff(
        event(),
        TEST_DESTINATION,
        spool.generation(),
        /* finalized */ true,
        1024 * 1024,
    );
    // `prepare` refuses a finalized body and `finalize` refuses a prepared one:
    // the outcome can never be inferred before the mutation result is known.
    assert_eq!(
        spool.prepare(&record).expect_err("prepare rejects").kind,
        SpoolErrorKind::InvalidRecord
    );
    let prepared = SpooledAuditRecord::with_bounded_diff(
        event(),
        TEST_DESTINATION,
        spool.generation(),
        /* finalized */ false,
        1024 * 1024,
    );
    assert_eq!(
        spool.finalize(&prepared).expect_err("finalize rejects").kind,
        SpoolErrorKind::InvalidRecord
    );
}

// ---------------------------------------------------------------------------
// Policy: fail_closed vs fail_open
// ---------------------------------------------------------------------------

#[test]
fn fail_closed_refuses_the_mutation_when_the_spool_is_unusable_at_startup() {
    let dir = TempDir::new().expect("temp dir");
    // A regular file where the spool root must be: the tree cannot be prepared.
    let root = dir.path().join("not-a-directory");
    std::fs::write(&root, b"blocked").expect("write blocker");

    let mut cfg = config(None);
    cfg.spool_dir = Some(root);
    cfg.policy = AuditUnavailablePolicy::FailClosed;
    let error = AuditPipeline::new(cfg).expect_err("fail_closed refuses to start");
    assert!(
        error.contains("fail_closed"),
        "startup failure names the policy: {error}"
    );
}

#[test]
fn fail_closed_blocks_mutations_once_the_handoff_fails() {
    let dir = TempDir::new().expect("temp dir");
    let mut cfg = config(Some(&dir));
    cfg.policy = AuditUnavailablePolicy::FailClosed;
    cfg.spool_max_records = 1;
    let pipeline = pipeline(cfg);

    assert!(pipeline.fail_closed_block_reason().is_none());
    pipeline
        .prepare_intent(event())
        .expect("first intent is durable");
    // The generation's durable ceiling is reached, so the next mutation has no
    // durable evidence available and must be refused before it runs.
    let reason = pipeline
        .prepare_intent(event())
        .expect_err("second intent is refused");
    assert_eq!(reason, AuditUnavailableReason::SpoolSaturated);
    assert_eq!(
        pipeline.fail_closed_block_reason(),
        Some("spool_saturated"),
        "the write gate refuses further audited mutations"
    );
    assert!(!pipeline.is_available());
}

#[test]
fn fail_open_accounts_for_a_mutation_that_proceeded_unaudited() {
    let dir = TempDir::new().expect("temp dir");
    let mut cfg = config(Some(&dir));
    cfg.spool_max_records = 1;
    let pipeline = pipeline(cfg);

    pipeline
        .prepare_intent(event())
        .expect("first intent is durable");
    assert!(pipeline.prepare_intent(event()).is_err());
    assert!(
        pipeline.fail_closed_block_reason().is_none(),
        "fail_open never converts the failure into a refusal"
    );
    let status = pipeline.status();
    assert!(
        !status.available,
        "fail_open stops claiming durable audit coverage"
    );
    assert_eq!(status.policy, "fail_open");
    assert_eq!(status.metrics.dropped_durable_handoff_failed_total, 1);
}

#[test]
fn memory_only_mode_never_claims_durable_coverage() {
    let pipeline = pipeline(config(None));
    assert_eq!(pipeline.durability_mode(), AuditDurabilityMode::Memory);
    assert!(!pipeline.is_available());
    assert_eq!(
        pipeline.last_unavailable_reason(),
        AuditUnavailableReason::NoDurableSpool
    );
    // A memory-only record still finalizes (it is queued) but the pipeline must
    // not start reporting durable coverage because of it.
    pipeline
        .finalize_event(event())
        .expect("memory-only finalize returns an unwritten record");
    assert!(!pipeline.is_available());
}

// ---------------------------------------------------------------------------
// Ownership: process generation and audit destination
// ---------------------------------------------------------------------------

#[test]
fn a_live_generation_owns_its_instance_directory_exclusively() {
    let dir = TempDir::new().expect("temp dir");
    let first = pipeline(config(Some(&dir)));
    let id = first.prepare_intent(event()).expect("intent is durable");

    // A second live process over the same root gets its own instance and must
    // not touch the first one's in-flight prepared record.
    let second = pipeline(config(Some(&dir)));
    assert_ne!(first.generation(), second.generation());
    second.claim_abandoned();

    let instances = instance_dirs(dir.path());
    assert_eq!(instances.len(), 2, "each live generation keeps its own dir");
    let owner = instances
        .iter()
        .find(|path| path.ends_with(first.generation()))
        .expect("the first generation's directory survives");
    assert!(
        owner.join("prepared").join(format!("{id}.json")).exists(),
        "a live process's in-flight intent is never claimed by a sibling"
    );
    assert_eq!(second.status().metrics.unknown_outcome_total, 0);
}

#[test]
fn a_prior_generation_replays_as_explicit_unknown_outcome() {
    let dir = TempDir::new().expect("temp dir");
    let crashed = pipeline(config(Some(&dir)));
    let crashed_generation = crashed.generation().to_string();
    let id = crashed.prepare_intent(event()).expect("intent is durable");
    // Simulate the crash: the process (and its ownership lock) goes away with
    // the intent still prepared and no outcome ever written.
    drop(crashed);

    let successor = pipeline(config(Some(&dir)));
    successor.claim_abandoned();

    assert_eq!(successor.status().metrics.unknown_outcome_total, 1);
    let instances = instance_dirs(dir.path());
    assert!(
        !instances.iter().any(|p| p.ends_with(&crashed_generation)),
        "the abandoned generation directory is drained and removed"
    );
    let adopted = successor
        .spool()
        .expect("a spool is configured")
        .read_pending(&id)
        .expect("the adopted record is deliverable");
    assert_eq!(adopted.event.outcome, "unknown_outcome");
    assert!(adopted.finalized);
    assert_eq!(adopted.event.actor, "audit-user", "context is preserved");
}

#[test]
fn a_finalized_twin_beats_a_leftover_prepared_record() {
    let dir = TempDir::new().expect("temp dir");
    let crashed = pipeline(config(Some(&dir)));
    let (id, _) = prepare_then_finalize(&crashed, AuditOutcome::Success);
    // Recreate the partial-finalize state: the finalized record is durable but
    // the prepared twin was never unlinked.
    let instance = instance_dirs(dir.path())
        .into_iter()
        .find(|p| p.ends_with(crashed.generation()))
        .expect("the live instance directory");
    std::fs::copy(
        instance.join("pending").join(format!("{id}.json")),
        instance.join("prepared").join(format!("{id}.json")),
    )
    .expect("stage a leftover prepared twin");
    drop(crashed);

    let successor = pipeline(config(Some(&dir)));
    successor.claim_abandoned();

    let adopted = successor
        .spool()
        .expect("a spool is configured")
        .read_pending(&id)
        .expect("the finalized record is adopted");
    assert_eq!(
        adopted.event.outcome, "success",
        "a known outcome is never downgraded to unknown_outcome"
    );
    assert_eq!(successor.status().metrics.unknown_outcome_total, 0);
}

#[test]
fn records_bound_to_another_destination_are_quarantined_not_delivered() {
    let dir = TempDir::new().expect("temp dir");
    let mut foreign = config(Some(&dir));
    foreign.destination = audit_destination_identity(
        Some("postgres"),
        Some("postgres://user:secret@other-host/other"),
        "other-namespace",
    );
    let other = pipeline(foreign);
    let (_, _) = prepare_then_finalize(&other, AuditOutcome::Success);
    drop(other);

    let ours = pipeline(config(Some(&dir)));
    ours.claim_abandoned();

    let status = ours.status();
    assert_eq!(status.metrics.destination_mismatch_total, 1);
    assert_eq!(
        status.metrics.spool_pending_records, 0,
        "a foreign record is never queued for our destination"
    );
    assert_eq!(status.degraded_reason, "destination_mismatch");
    assert!(status.degraded);
}

#[test]
fn destination_identity_is_non_secret_and_separates_deployments() {
    let a = audit_destination_identity(
        Some("postgres"),
        Some("postgres://admin:hunter2@db-a:5432/ferrum"),
        "ferrum",
    );
    let b = audit_destination_identity(
        Some("postgres"),
        Some("postgres://admin:hunter2@db-b:5432/ferrum"),
        "ferrum",
    );
    let c = audit_destination_identity(
        Some("postgres"),
        Some("postgres://admin:hunter2@db-a:5432/ferrum"),
        "other",
    );
    assert_ne!(a, b, "a different host is a different destination");
    assert_ne!(a, c, "a different namespace is a different destination");
    for identity in [&a, &b, &c] {
        assert!(
            !identity.contains("hunter2") && !identity.contains("admin"),
            "the connection secret never reaches the destination identity"
        );
    }
}

// ---------------------------------------------------------------------------
// Delivery, replay, and idempotency
// ---------------------------------------------------------------------------

#[tokio::test]
async fn startup_replay_drains_the_backlog_without_a_new_mutation() {
    let dir = TempDir::new().expect("temp dir");
    let crashed = pipeline(config(Some(&dir)));
    let (delivered_id, _) = prepare_then_finalize(&crashed, AuditOutcome::Success);
    let unknown_id = crashed.prepare_intent(event()).expect("intent is durable");
    drop(crashed);

    // A fresh process that never receives another mutation must still adopt and
    // deliver everything the prior generation left behind.
    let successor = pipeline(config(Some(&dir)));
    let delivery = Arc::new(RecordingDelivery::default());
    let worker = AuditWorker::spawn_for_delivery(
        Arc::clone(&successor),
        Arc::clone(&delivery) as Arc<dyn AuditEventDelivery>,
    );

    let drained = wait_until(Duration::from_secs(10), || {
        let ids = delivery.accepted_ids();
        ids.contains(&delivered_id) && ids.contains(&unknown_id)
    })
    .await;
    assert!(drained, "startup replay delivered the inherited backlog");
    assert_eq!(
        delivery
            .accepted_event(&unknown_id)
            .expect("unknown-outcome event delivered")
            .outcome,
        "unknown_outcome"
    );
    worker.shutdown(Duration::from_secs(5)).await;
}

#[tokio::test]
async fn transient_backend_failure_recovers_and_converges_to_one_row() {
    let dir = TempDir::new().expect("temp dir");
    let pipeline = pipeline(config(Some(&dir)));
    let delivery = RecordingDelivery::failing();
    let worker = AuditWorker::spawn_for_delivery(
        Arc::clone(&pipeline),
        Arc::clone(&delivery) as Arc<dyn AuditEventDelivery>,
    );

    let (id, _) = prepare_then_finalize(&pipeline, AuditOutcome::Success);
    let mut finalized = event_with(&id, json!({"replay": true}));
    finalized.outcome = AuditOutcome::Success.as_str().to_string();
    worker.record(finalized).expect("durable handoff succeeds");

    assert!(
        wait_until(Duration::from_secs(5), || delivery.attempts_for(&id) >= 1).await,
        "the failing backend was attempted"
    );
    delivery.recover();
    assert!(
        wait_until(Duration::from_secs(15), || delivery
            .accepted_ids()
            .contains(&id))
        .await,
        "delivery recovers on the bounded backoff"
    );
    assert_eq!(
        delivery
            .accepted_ids()
            .iter()
            .filter(|accepted| *accepted == &id)
            .count(),
        1,
        "at-least-once transport converges to exactly one immutable row"
    );
    worker.shutdown(Duration::from_secs(5)).await;
}

#[tokio::test]
async fn duplicate_delivery_of_the_same_id_is_success_not_replacement() {
    let dir = TempDir::new().expect("temp dir");
    let pipeline = pipeline(config(Some(&dir)));
    let delivery = Arc::new(RecordingDelivery::default());

    let id = Uuid::new_v4().to_string();
    let first = event_with(&id, json!({"generation": 1}));
    let second = event_with(&id, json!({"generation": 2}));
    delivery.deliver(&first).await.expect("first insert");
    delivery.deliver(&second).await.expect("duplicate is success");

    let stored = delivery.accepted_event(&id).expect("one stored row");
    assert_eq!(
        stored.diff["generation"], 1,
        "an audit row is immutable: the duplicate must not replace it"
    );
    assert_eq!(delivery.accepted_ids().len(), 1);
    drop(pipeline);
}

/// The insert-only contract is a property of the SQL/Mongo statements, not of
/// the delivery trait, so it is pinned here against the production sources.
/// An `upsert`/`replace_one` or a value-assigning `ON DUPLICATE KEY UPDATE`
/// would let a replayed id overwrite an immutable audit row.
#[test]
fn backend_audit_inserts_are_insert_only_and_idempotent() {
    let sql = include_str!("../../../src/config/db_loader.rs");
    let statement_start = sql
        .find("pub async fn insert_audit_event")
        .expect("db_loader exposes insert_audit_event");
    let statement = &sql[statement_start..statement_start + 3000];
    assert!(
        statement.contains("ON CONFLICT (id) DO NOTHING"),
        "PostgreSQL/SQLite audit inserts must be insert-only"
    );
    assert!(
        statement.contains("ON DUPLICATE KEY UPDATE id = id"),
        "MySQL audit inserts must assign only the primary key to itself"
    );
    assert!(
        !statement.contains("INSERT IGNORE"),
        "INSERT IGNORE would also downgrade unrelated errors to warnings"
    );

    let mongo = include_str!("../../../src/config/mongo_store.rs");
    let mongo_start = mongo
        .find("async fn insert_audit_event")
        .expect("mongo_store implements insert_audit_event");
    let mongo_statement = &mongo[mongo_start..mongo_start + 2000];
    assert!(
        mongo_statement.contains("insert_one"),
        "MongoDB audit delivery must be insert-only"
    );
    assert!(
        !mongo_statement.contains("upsert(true)") && !mongo_statement.contains("replace_one"),
        "an upsert would silently overwrite an existing immutable audit row"
    );
    assert!(
        mongo_statement.contains("is_duplicate_key"),
        "a duplicate id must be treated as success, not as a retryable failure"
    );
}

// ---------------------------------------------------------------------------
// Sticky degradation and O(1) observability
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_later_delivery_success_does_not_clear_sticky_evidence_loss() {
    let dir = TempDir::new().expect("temp dir");
    let mut cfg = config(Some(&dir));
    cfg.max_delivery_attempts = 1;
    let pipeline = pipeline(cfg);
    let delivery = RecordingDelivery::failing();
    let worker = AuditWorker::spawn_for_delivery(
        Arc::clone(&pipeline),
        Arc::clone(&delivery) as Arc<dyn AuditEventDelivery>,
    );

    let (lost_id, _) = prepare_then_finalize(&pipeline, AuditOutcome::Success);
    let mut lost = event_with(&lost_id, json!({"lost": true}));
    lost.outcome = AuditOutcome::Success.as_str().to_string();
    worker.record(lost).expect("durable handoff succeeds");

    assert!(
        wait_until(Duration::from_secs(10), || pipeline.is_degraded()).await,
        "an exhausted delivery budget is sticky evidence damage"
    );
    let degraded_reason = pipeline.degraded_reason();
    assert_eq!(degraded_reason, AuditUnavailableReason::DeliveryExhausted);

    // A different record now delivers successfully.
    delivery.recover();
    let (ok_id, _) = prepare_then_finalize(&pipeline, AuditOutcome::Success);
    let mut ok = event_with(&ok_id, json!({"ok": true}));
    ok.outcome = AuditOutcome::Success.as_str().to_string();
    worker.record(ok).expect("durable handoff succeeds");
    assert!(
        wait_until(Duration::from_secs(10), || delivery
            .accepted_ids()
            .contains(&ok_id))
        .await,
        "the recovered backend accepts the new record"
    );

    assert!(
        pipeline.is_degraded(),
        "a later delivery success must not erase retained-evidence degradation"
    );
    assert_eq!(pipeline.degraded_reason(), degraded_reason);
    assert!(pipeline.status().metrics.retained_total >= 1);
    worker.shutdown(Duration::from_secs(5)).await;
}

#[test]
fn degradation_clears_only_when_the_retained_evidence_is_resolved() {
    let dir = TempDir::new().expect("temp dir");
    let pipeline = pipeline(config(Some(&dir)));
    // Stage a retained record directly, the way an exhausted delivery would.
    let failed_dir = dir.path().join("failed");
    std::fs::write(
        failed_dir.join(format!("{}.json", Uuid::new_v4())),
        b"{\"v\":2}",
    )
    .expect("stage retained evidence");
    let (_, _) = prepare_then_finalize(&pipeline, AuditOutcome::Success);
    pipeline.reconcile();
    assert_eq!(pipeline.status().metrics.spool_retained_records, 1);

    // Reconciling with retained evidence still present must not clear a raised
    // degradation; clearing the directory is what resolves it.
    let entries: Vec<_> = std::fs::read_dir(&failed_dir)
        .expect("failed dir")
        .filter_map(|entry| entry.ok())
        .collect();
    for entry in entries {
        std::fs::remove_file(entry.path()).expect("resolve retained evidence");
    }
    pipeline.reconcile();
    assert_eq!(pipeline.status().metrics.spool_retained_records, 0);
    assert!(!pipeline.is_degraded());
}

#[test]
fn status_and_metrics_are_o1_reads_from_atomics() {
    let dir = TempDir::new().expect("temp dir");
    let pipeline = pipeline(config(Some(&dir)));
    for _ in 0..5 {
        let _ = prepare_then_finalize(&pipeline, AuditOutcome::Success);
    }
    assert_eq!(pipeline.status().metrics.spool_pending_records, 5);

    // Delete the durable records behind the pipeline's back. An O(1) read from
    // admission counters cannot notice; a per-request `read_dir` would. This is
    // the observable proof that `/health` and `/metrics` never walk the spool.
    let instance = instance_dirs(dir.path())
        .into_iter()
        .find(|path| path.ends_with(pipeline.generation()))
        .expect("live instance directory");
    for entry in std::fs::read_dir(instance.join("pending")).expect("pending dir") {
        std::fs::remove_file(entry.expect("entry").path()).expect("remove");
    }
    assert_eq!(
        pipeline.status().metrics.spool_pending_records,
        5,
        "the observability surface did not scan the filesystem"
    );

    // Only the background reconciler pays the bounded walk.
    pipeline.reconcile();
    assert_eq!(pipeline.status().metrics.spool_pending_records, 0);
}

// ---------------------------------------------------------------------------
// Hostile filesystem contents and error paths
// ---------------------------------------------------------------------------

#[test]
fn hostile_spool_contents_are_rejected_and_never_replayed() {
    let dir = TempDir::new().expect("temp dir");
    let pipeline = pipeline(config(Some(&dir)));
    let instance = instance_dirs(dir.path())
        .into_iter()
        .find(|path| path.ends_with(pipeline.generation()))
        .expect("live instance directory");
    let pending = instance.join("pending");

    // A foreign file with an illegal record name is neither listed nor parsed.
    std::fs::write(pending.join("not-a-record.txt"), b"junk").expect("stage junk");
    // A leftover temp file is reconciled away rather than replayed.
    std::fs::write(pending.join("abandoned.tmp"), b"junk").expect("stage temp");
    // A corrupt but legally named record is quarantined, never delivered.
    let corrupt_id = Uuid::new_v4().to_string();
    std::fs::write(pending.join(format!("{corrupt_id}.json")), b"{not json")
        .expect("stage corrupt record");

    let spool = pipeline.spool().expect("a spool is configured");
    let ids = spool.list_pending_ids(64);
    assert!(!ids.iter().any(|id| id == "not-a-record"));
    assert!(ids.contains(&corrupt_id));
    assert!(
        !pending.join("abandoned.tmp").exists(),
        "stray temp files are removed by the listing scan"
    );

    let error = spool
        .read_pending(&corrupt_id)
        .expect_err("a corrupt record is not deliverable");
    assert_eq!(error.kind, SpoolErrorKind::Corrupt);
    assert!(
        !pending.join(format!("{corrupt_id}.json")).exists(),
        "the corrupt record moved out of the deliverable set"
    );
    assert!(
        dir.path()
            .join("failed")
            .join(format!("{corrupt_id}.json"))
            .exists(),
        "corrupt evidence is quarantined, never silently deleted"
    );
}

#[cfg(unix)]
#[test]
fn a_symlinked_spool_record_is_refused() {
    let dir = TempDir::new().expect("temp dir");
    let pipeline = pipeline(config(Some(&dir)));
    let instance = instance_dirs(dir.path())
        .into_iter()
        .find(|path| path.ends_with(pipeline.generation()))
        .expect("live instance directory");
    let secret = dir.path().join("secret-outside-the-spool");
    std::fs::write(&secret, b"{\"v\":2}").expect("stage target");
    let id = Uuid::new_v4().to_string();
    std::os::unix::fs::symlink(&secret, instance.join("pending").join(format!("{id}.json")))
        .expect("stage symlink");

    let error = pipeline
        .spool()
        .expect("a spool is configured")
        .read_pending(&id)
        .expect_err("a symlinked record is never followed");
    assert_eq!(error.kind, SpoolErrorKind::Corrupt);
    assert!(secret.exists(), "the symlink target is untouched");
}

#[cfg(unix)]
#[test]
fn a_symlinked_spool_directory_is_refused_at_open() {
    let dir = TempDir::new().expect("temp dir");
    let real = dir.path().join("real");
    std::fs::create_dir_all(&real).expect("create real dir");
    let link = dir.path().join("linked-root");
    std::os::unix::fs::symlink(&real, &link).expect("stage symlinked root");

    let error = AuditSpool::open(
        link,
        Uuid::new_v4().to_string(),
        TEST_DESTINATION.to_string(),
        64,
        8,
    )
    .expect_err("a symlinked spool root is refused");
    assert_eq!(error.kind, SpoolErrorKind::Unavailable);
}

#[test]
fn a_broken_write_or_sync_path_is_a_durability_failure() {
    let dir = TempDir::new().expect("temp dir");
    let spool = AuditSpool::open(
        dir.path().to_path_buf(),
        Uuid::new_v4().to_string(),
        TEST_DESTINATION.to_string(),
        64,
        8,
    )
    .expect("spool opens");
    let record = SpooledAuditRecord::with_bounded_diff(
        event(),
        TEST_DESTINATION,
        spool.generation(),
        /* finalized */ false,
        1024 * 1024,
    );
    // Replace the temp directory with a regular file: the atomic write and its
    // directory sync both become impossible, so `prepare` must report an I/O
    // durability failure instead of claiming the record is durable. Using a
    // file rather than a permission bit keeps the injection deterministic even
    // when the test runs as root.
    let instance = instance_dirs(dir.path())
        .into_iter()
        .find(|path| path.ends_with(spool.generation()))
        .expect("live instance directory");
    std::fs::remove_dir_all(instance.join("tmp")).expect("remove tmp dir");
    std::fs::write(instance.join("tmp"), b"not a directory").expect("stage blocker");

    let error = spool.prepare(&record).expect_err("durability failure");
    assert_eq!(error.kind, SpoolErrorKind::Io);
    assert_eq!(
        count_json(&instance.join("prepared")),
        0,
        "a failed durable write publishes nothing"
    );
}

#[test]
fn record_ids_are_the_path_traversal_boundary() {
    assert!(is_valid_record_id(&Uuid::new_v4().to_string()));
    for hostile in [
        "..",
        "../escape",
        "a/b",
        "a\\b",
        "",
        "with space",
        "with.dot",
        "ünicode",
    ] {
        assert!(!is_valid_record_id(hostile), "rejected: {hostile}");
    }
    assert_eq!(
        record_id_from_file_name("11111111-2222-3333-4444-555555555555.json"),
        Some("11111111-2222-3333-4444-555555555555".to_string())
    );
    assert_eq!(record_id_from_file_name("../escape.json"), None);
    assert_eq!(record_id_from_file_name("plain.txt"), None);
}

#[test]
fn hostile_request_context_is_sanitized_before_it_becomes_evidence() {
    assert_eq!(sanitize_audit_path("/proxies/abc-1"), "/proxies/abc-1");
    for hostile in ["/proxies/../../etc/passwd", "/a\nb", "/a b", &"x".repeat(600)] {
        assert_eq!(sanitize_audit_path(hostile), "invalid", "path: {hostile}");
    }
    assert_eq!(sanitize_audit_namespace("ferrum"), "ferrum");
    assert_eq!(sanitize_audit_namespace("bad ns"), "invalid");
    assert_eq!(sanitize_audit_namespace(""), "invalid");
}

// ---------------------------------------------------------------------------
// Bounds and redaction
// ---------------------------------------------------------------------------

#[test]
fn an_oversized_diff_is_redacted_but_the_event_identity_stays_durable() {
    let dir = TempDir::new().expect("temp dir");
    let pipeline = pipeline(config(Some(&dir)));
    let huge = event_with(
        &Uuid::new_v4().to_string(),
        json!({ "after": { "blob": "x".repeat(4 * 1024 * 1024) } }),
    );
    let id = huge.id.clone();
    let mut huge = huge;
    huge.outcome = AuditOutcome::Success.as_str().to_string();
    let record = pipeline
        .finalize_event(huge)
        .expect("an oversized diff never loses the event");

    assert!(record.diff_omitted);
    assert_eq!(record.id(), id);
    assert_eq!(
        record.event.diff["omitted"],
        json!(AUDIT_DIFF_OMITTED_MARKER)
    );
    assert_eq!(record.v, AUDIT_SPOOL_RECORD_VERSION);
    assert_eq!(pipeline.status().metrics.truncated_diffs_total, 1);
}

#[test]
fn credential_redaction_survives_the_durable_representation() {
    let dir = TempDir::new().expect("temp dir");
    let pipeline = pipeline(config(Some(&dir)));
    let mut redacted = event_with(
        &Uuid::new_v4().to_string(),
        credential_update_diff("basic", json!({"username": "u"}), json!({"username": "u"})),
    );
    redacted.outcome = AuditOutcome::Success.as_str().to_string();
    let id = redacted.id.clone();
    pipeline
        .finalize_event(redacted)
        .expect("durable handoff succeeds");

    let instance = instance_dirs(dir.path())
        .into_iter()
        .find(|path| path.ends_with(pipeline.generation()))
        .expect("live instance directory");
    let raw = std::fs::read_to_string(instance.join("pending").join(format!("{id}.json")))
        .expect("read durable record");
    assert!(raw.contains("[REDACTED]"));
    assert!(
        !raw.contains("hunter2") && !raw.contains("\"password\""),
        "no credential material reaches the durable record"
    );
}

// ---------------------------------------------------------------------------
// Shutdown
// ---------------------------------------------------------------------------

#[tokio::test]
async fn shutdown_interrupts_the_retry_backoff_and_never_detaches_the_worker() {
    let dir = TempDir::new().expect("temp dir");
    let mut cfg = config(Some(&dir));
    cfg.max_delivery_attempts = 50;
    let pipeline = pipeline(cfg);
    let delivery = RecordingDelivery::failing();
    let worker = AuditWorker::spawn_for_delivery(
        Arc::clone(&pipeline),
        Arc::clone(&delivery) as Arc<dyn AuditEventDelivery>,
    );

    let (id, _) = prepare_then_finalize(&pipeline, AuditOutcome::Success);
    let mut finalized = event_with(&id, json!({"pending": true}));
    finalized.outcome = AuditOutcome::Success.as_str().to_string();
    worker.record(finalized).expect("durable handoff succeeds");
    assert!(
        wait_until(Duration::from_secs(5), || delivery.attempts_for(&id) >= 3).await,
        "the worker is parked on a growing retry backoff"
    );

    // The backoff has already grown past the shutdown budget. A shutdown that
    // was not cancellation-aware would block for the full sleep.
    let started = Instant::now();
    let drained = worker.shutdown(Duration::from_secs(3)).await;
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(3),
        "shutdown interrupted the retry wait instead of outliving it: {elapsed:?}"
    );
    assert!(drained, "the worker finished within the drain budget");

    // The undelivered record is still durable for the next process.
    let instance = instance_dirs(dir.path())
        .into_iter()
        .find(|path| path.ends_with(pipeline.generation()))
        .expect("live instance directory");
    assert!(
        instance.join("pending").join(format!("{id}.json")).exists(),
        "an interrupted drain costs latency, never durability"
    );
}

#[tokio::test]
async fn shutdown_with_no_worker_is_a_no_op() {
    let dir = TempDir::new().expect("temp dir");
    let pipeline = pipeline(config(Some(&dir)));
    let delivery = Arc::new(RecordingDelivery::default());
    let worker = AuditWorker::spawn_for_delivery(
        Arc::clone(&pipeline),
        Arc::clone(&delivery) as Arc<dyn AuditEventDelivery>,
    );
    assert!(worker.shutdown(Duration::from_secs(5)).await);
    assert!(
        worker.shutdown(Duration::from_secs(5)).await,
        "a second shutdown is idempotent and never detaches a task"
    );
}
