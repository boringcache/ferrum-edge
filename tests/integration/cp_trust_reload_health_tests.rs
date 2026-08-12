//! Bounded, observable CP/DP trust-bundle reload health (issue #3813).
//!
//! The reload worker deliberately retains the last accepted verifier when a
//! candidate is unreadable, malformed, times out, or fails scope validation.
//! These tests pin the contract that makes that policy safe rather than silent:
//!
//! * the first refusal marks trust reload degraded immediately, under one
//!   closed reason label;
//! * repeated refusals advance stamps and counters without inventing labels;
//! * a valid candidate — including a semantically unchanged one — clears the
//!   degraded state and records exactly one recovery;
//! * the configured bound is the boundary, with no grace period, and crossing
//!   it blocks admission and readiness;
//! * an unexpectedly dead worker fails readiness immediately, while a clean
//!   shutdown is never reported as a failure;
//! * nothing published anywhere — health JSON, metrics text, or logs — carries
//!   a path, a `kid`, a namespace, key material, or any value *derived* from
//!   key material: no generation identifier, fingerprint, or digest, however
//!   re-hashed or truncated, because such a value is an offline oracle against
//!   a guessed symmetric secret.
//!
//! The five gRPC stream families' behaviour at the boundary is covered in
//! `cp_tenant_trust_binding_tests.rs`, which already owns the multi-surface
//! server harness.

use std::sync::Arc;
use std::time::Duration as StdDuration;

use serde_json::{Value, json};
use tokio::time::{Duration, Instant, advance};

use ferrum_edge::grpc::cp_trust::{CpDpTrustBundle, CpDpVerifier};
use ferrum_edge::grpc::cp_trust_health::{
    CpDpTrustReloadStatus, TRUST_RELOAD_FAILURES, TrustReloadFailure,
};
use ferrum_edge::plugins::prometheus_metrics::render_cp_dp_trust_reload_prometheus;

const KID: &str = "tenant-a-v1";
const NAMESPACE: &str = "tenant-a";
const SECRET: &str = "tenant-a-cp-dp-secret-2026-ferrum-edge";
const POLL_INTERVAL: Duration = Duration::from_secs(30);
const BOUND: Duration = Duration::from_secs(900);

fn bundle_document(kid: &str, namespace: &str, secret: &str) -> String {
    json!({
        "version": 1,
        "keys": [{
            "kid": kid,
            "algorithm": "HS256",
            "namespaces": [namespace],
            "secret": secret,
        }],
    })
    .to_string()
}

fn verifier(kid: &str, namespace: &str, secret: &str) -> CpDpVerifier {
    CpDpVerifier::TrustBundle(
        CpDpTrustBundle::from_document_str(
            &bundle_document(kid, namespace, secret),
            "trust-health-test",
            None,
        )
        .expect("test trust bundle must load"),
    )
}

fn status_at(now: Instant, max_stale: Duration) -> CpDpTrustReloadStatus {
    CpDpTrustReloadStatus::watching_at(max_stale, max_stale.is_zero(), POLL_INTERVAL, now)
}

// ── Degraded state and the closed reason set ─────────────────────────────

#[tokio::test(start_paused = true)]
async fn first_rejected_candidate_marks_degraded_immediately() {
    let status = status_at(Instant::now(), BOUND);
    let healthy = status.snapshot();
    assert!(!healthy.degraded, "a fresh acceptance is not degraded");
    assert_eq!(healthy.reason, "ok");
    assert!(!healthy.stale);
    assert!(!healthy.admission_blocked);

    status.record_attempt();
    status.record_rejected(TrustReloadFailure::DocumentUnreadable);

    let snapshot = status.snapshot();
    assert!(snapshot.degraded, "the first refusal degrades immediately");
    assert_eq!(snapshot.reason, "document_unreadable");
    assert_eq!(snapshot.consecutive_failures, 1);
    assert_eq!(snapshot.rejections_total, 1);
    assert_eq!(
        snapshot.rejections_by_reason.get("document_unreadable"),
        Some(&1)
    );
    // Retaining the previous verifier is still the policy inside the bound.
    assert!(
        !snapshot.stale && !snapshot.admission_blocked && !snapshot.readiness_blocked,
        "a transient failure inside the bound keeps serving: {snapshot:?}"
    );
    assert_eq!(
        snapshot.acceptances_total, healthy.acceptances_total,
        "a refusal is not an acceptance"
    );
}

#[tokio::test(start_paused = true)]
async fn repeated_rejections_advance_counters_without_unbounded_labels() {
    let status = status_at(Instant::now(), BOUND);
    for round in 0..60usize {
        status.record_attempt();
        // Cycle the reasons so a changing failure mode is exercised too.
        let failure = TRUST_RELOAD_FAILURES[round % TRUST_RELOAD_FAILURES.len()];
        status.record_rejected(failure);
        advance(Duration::from_secs(1)).await;
    }

    let snapshot = status.snapshot();
    assert_eq!(snapshot.consecutive_failures, 60);
    assert_eq!(snapshot.attempts_total, 60);
    assert_eq!(snapshot.rejections_total, 60);
    // Exactly the closed set — no reason label is ever derived from a path, a
    // parser message, a `kid`, or any other unbounded input.
    let observed: Vec<&str> = snapshot.rejections_by_reason.keys().copied().collect();
    let mut expected: Vec<&str> = TRUST_RELOAD_FAILURES
        .iter()
        .map(|failure| failure.as_str())
        .collect();
    expected.sort_unstable();
    assert_eq!(observed, expected);
    assert_eq!(snapshot.recoveries_total, 0);
}

#[tokio::test(start_paused = true)]
async fn every_closed_reason_has_a_distinct_fixed_label() {
    let mut labels: Vec<&str> = TRUST_RELOAD_FAILURES
        .iter()
        .map(|failure| failure.as_str())
        .collect();
    let total = labels.len();
    labels.sort_unstable();
    labels.dedup();
    assert_eq!(labels.len(), total, "reason labels must be distinct");
    assert_eq!(
        labels,
        [
            "document_invalid",
            "document_unreadable",
            "material_integrity_malformed",
            "material_integrity_mismatch",
            "material_integrity_unbound",
            "material_unreadable",
            "reader_unavailable",
            "reload_read_timed_out",
            "reload_reader_failed",
            "scope_validation_failed",
            "source_generation_escape",
            "source_generation_unstable",
            "source_generation_unsupported",
            "worker_exited",
        ]
    );
}

// ── Recovery ────────────────────────────────────────────────────────────

#[tokio::test(start_paused = true)]
async fn unchanged_candidate_after_an_outage_clears_degraded_and_counts_one_recovery() {
    let status = status_at(Instant::now(), BOUND);
    let accepted_before = status.snapshot().acceptances_total;
    for _ in 0..3 {
        status.record_attempt();
        status.record_rejected(TrustReloadFailure::ReadTimedOut);
        advance(Duration::from_secs(30)).await;
    }
    assert!(status.snapshot().degraded);

    // Semantically identical candidate: no verifier swap is needed, but the
    // trust source was read coherently and revalidated, which is exactly the
    // question the bound asks.
    status.record_attempt();
    status.record_accepted(false);

    let snapshot = status.snapshot();
    assert!(!snapshot.degraded, "recovery clears degraded: {snapshot:?}");
    assert_eq!(snapshot.reason, "ok");
    assert_eq!(snapshot.consecutive_failures, 0);
    assert_eq!(snapshot.recoveries_total, 1);
    assert_eq!(snapshot.acceptances_total, accepted_before + 1);
    assert_eq!(snapshot.last_acceptance_age_seconds, Some(0));

    // A second healthy poll is not a second recovery.
    status.record_attempt();
    status.record_accepted(false);
    assert_eq!(status.snapshot().recoveries_total, 1);
}

#[tokio::test(start_paused = true)]
async fn changed_candidate_recovers_and_counts_one_recovery() {
    let status = status_at(Instant::now(), BOUND);
    let accepted_before = status.snapshot().acceptances_total;
    status.record_attempt();
    status.record_rejected(TrustReloadFailure::DocumentInvalid);

    status.record_attempt();
    status.record_accepted(true);

    let snapshot = status.snapshot();
    assert!(!snapshot.degraded);
    assert_eq!(snapshot.recoveries_total, 1);
    assert_eq!(
        snapshot.acceptances_total,
        accepted_before + 1,
        "a rotation is one acceptance, and publishes no identifier of what was rotated"
    );
}

// ── The stale boundary ──────────────────────────────────────────────────

#[tokio::test(start_paused = true)]
async fn the_configured_bound_is_the_boundary_with_no_grace_period() {
    let bound = Duration::from_secs(120);
    let status = status_at(Instant::now(), bound);
    status.record_attempt();
    status.record_rejected(TrustReloadFailure::MaterialUnreadable);

    advance(bound - Duration::from_secs(1)).await;
    let inside = status.snapshot();
    assert!(
        !inside.stale && !inside.admission_blocked && !inside.readiness_blocked,
        "one second inside the bound still serves: {inside:?}"
    );
    assert!(inside.degraded);

    advance(Duration::from_secs(1)).await;
    let outside = status.snapshot();
    assert!(
        outside.stale,
        "the bound itself is the boundary: {outside:?}"
    );
    assert!(outside.admission_blocked);
    assert!(outside.readiness_blocked);
    assert_eq!(outside.reason, "material_unreadable");
    assert_eq!(outside.max_stale_seconds, 120);
    assert!(!outside.unbounded_stale_allowed);
}

#[tokio::test(start_paused = true)]
async fn a_later_valid_candidate_clears_stale_and_restores_admission() {
    let bound = Duration::from_secs(60);
    let status = status_at(Instant::now(), bound);
    status.record_attempt();
    status.record_rejected(TrustReloadFailure::SourceGenerationUnstable);
    advance(bound).await;
    assert!(status.admission_blocked());

    status.record_attempt();
    status.record_accepted(false);

    let snapshot = status.snapshot();
    assert!(!snapshot.stale, "acceptance clears the sticky bit");
    assert!(!snapshot.admission_blocked);
    assert!(!snapshot.readiness_blocked);
    assert!(!snapshot.degraded);
    assert_eq!(snapshot.recoveries_total, 1);
}

#[tokio::test(start_paused = true)]
async fn unbounded_retention_never_blocks_but_stays_visibly_degraded() {
    let status = status_at(Instant::now(), Duration::ZERO);
    status.record_attempt();
    status.record_rejected(TrustReloadFailure::DocumentUnreadable);
    advance(Duration::from_secs(86_400)).await;

    let snapshot = status.snapshot();
    assert!(
        !snapshot.stale && !snapshot.admission_blocked,
        "the explicit unsafe opt-in keeps admitting: {snapshot:?}"
    );
    assert!(
        snapshot.degraded,
        "unbounded retention is still an alertable state"
    );
    assert_eq!(snapshot.max_stale_seconds, 0);
    assert!(snapshot.unbounded_stale_allowed);
    assert!(
        snapshot
            .last_acceptance_age_seconds
            .is_some_and(|age| age >= 86_400)
    );
}

#[tokio::test(start_paused = true)]
async fn a_status_with_no_trust_bundle_never_blocks_anything() {
    let status = CpDpTrustReloadStatus::disabled();
    advance(Duration::from_secs(86_400)).await;
    assert!(!status.admission_blocked());
    assert!(!status.degraded());
    let snapshot = status.snapshot();
    assert!(!snapshot.readiness_blocked);
    assert!(!snapshot.configured);
    assert_eq!(snapshot.worker_state, "disabled");
    assert_eq!(snapshot.last_acceptance_age_seconds, None);
}

// ── Worker supervision ──────────────────────────────────────────────────

#[tokio::test(start_paused = true)]
async fn an_unexpected_worker_exit_fails_readiness_immediately() {
    let status = status_at(Instant::now(), BOUND);
    status.record_worker_stopped(false);

    let snapshot = status.snapshot();
    assert_eq!(snapshot.worker_state, "failed");
    assert!(!snapshot.worker_running);
    assert!(snapshot.degraded);
    assert_eq!(snapshot.reason, "worker_exited");
    assert!(
        snapshot.readiness_blocked,
        "a dead watcher can never publish another revocation, so the bound \
         must not be what decides: {snapshot:?}"
    );
    // Admission itself still follows the documented bound; only readiness is
    // immediate, so an operator's orchestrator replaces the replica rather
    // than the CP dropping every tenant at once.
    assert!(!snapshot.admission_blocked);
}

#[tokio::test(start_paused = true)]
async fn a_clean_shutdown_is_not_reported_as_a_reload_failure() {
    let status = status_at(Instant::now(), BOUND);
    status.record_worker_stopped(true);

    let snapshot = status.snapshot();
    assert_eq!(snapshot.worker_state, "stopped");
    assert!(
        !snapshot.degraded,
        "shutdown is not a failure: {snapshot:?}"
    );
    assert_eq!(snapshot.reason, "ok");
    assert!(!snapshot.readiness_blocked);
    assert_eq!(snapshot.rejections_total, 0);
    assert_eq!(snapshot.consecutive_failures, 0);
}

#[tokio::test(start_paused = true)]
async fn a_worker_whose_attempts_stop_landing_reads_as_stalled() {
    let status = status_at(Instant::now(), Duration::ZERO);
    assert_eq!(status.snapshot().worker_state, "running");
    // Well past three poll intervals with no completed attempt: the shape of a
    // read parked in the kernel on a stalled network filesystem.
    advance(POLL_INTERVAL * 10).await;
    let snapshot = status.snapshot();
    assert_eq!(snapshot.worker_state, "stalled");
    assert!(
        snapshot.worker_running,
        "a stalled worker is still alive, and is reported separately from a dead one"
    );
}

// ── Disclosure boundary ─────────────────────────────────────────────────

/// The longest run of ASCII hex digits in `text`.
///
/// A published generation identifier, fingerprint, or digest — whatever it is
/// called — shows up as an unbroken hex run. The closed reason labels and the
/// worker states are English words split by underscores, so their longest hex
/// run is short.
fn longest_hex_run(text: &str) -> usize {
    let mut longest = 0usize;
    let mut current = 0usize;
    for ch in text.chars() {
        if ch.is_ascii_hexdigit() {
            current += 1;
            longest = longest.max(current);
        } else {
            current = 0;
        }
    }
    longest
}

/// No candidate-verifiable material may reach a published surface.
///
/// The trust source's configuration fingerprint hashes each credential identity
/// (an HS\* secret-derived identity included), and every algorithm and domain
/// involved is public. Publishing that fingerprint — or **any** deterministic
/// unkeyed function of it, re-hashed, domain-separated, and truncated or not —
/// lets an attacker who guesses a candidate symmetric secret recompute the
/// value and confirm the guess offline. So the contract is not "redact it": it
/// is that no such identifier exists on the health or metric surface at all.
#[tokio::test(start_paused = true)]
async fn the_published_projection_carries_no_generation_identifier_or_digest() {
    let status = status_at(Instant::now(), BOUND);
    status.record_attempt();
    status.record_accepted(true);
    status.record_attempt();
    status.record_rejected(TrustReloadFailure::MaterialIntegrityMismatch);
    let snapshot = status.snapshot();

    // The projection's closed field set is pinned by
    // `the_health_projection_is_fixed_cardinality`, so an added field cannot
    // slip a derived identifier back in unnoticed. This asserts the content.
    let rendered = serde_json::to_string(&snapshot).expect("snapshot serializes");
    let mut metrics = String::new();
    render_cp_dp_trust_reload_prometheus(&mut metrics, ",namespace=\"edge\"", Some(&snapshot));

    for surface in [rendered.as_str(), metrics.as_str()] {
        for forbidden in [
            "active_generation",
            "fingerprint",
            "digest",
            "sha256",
            "candidate",
            SECRET,
            KID,
            NAMESPACE,
        ] {
            assert!(
                !surface.contains(forbidden),
                "published trust health must not carry `{forbidden}`: {surface}"
            );
        }
        assert!(
            longest_hex_run(surface) < 16,
            "a hex run this long is a generation identifier, fingerprint, or digest: {surface}"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn the_published_projection_carries_no_path_credential_or_namespace() {
    let status = status_at(Instant::now(), BOUND);
    status.record_attempt();
    status.record_rejected(TrustReloadFailure::MaterialIntegrityMismatch);
    let rendered = serde_json::to_string(&status.snapshot()).expect("snapshot serializes");

    for forbidden in [
        SECRET,
        KID,
        NAMESPACE,
        "/etc/ferrum/trust-bundle.json",
        "public_key",
        "secret",
        "kid",
        "Bearer",
    ] {
        assert!(
            !rendered.contains(forbidden),
            "published trust health must not carry `{forbidden}`: {rendered}"
        );
    }

    // And the same for the metric text.
    let mut metrics = String::new();
    let snapshot = status.snapshot();
    render_cp_dp_trust_reload_prometheus(&mut metrics, ",namespace=\"edge\"", Some(&snapshot));
    for forbidden in [SECRET, KID, NAMESPACE] {
        assert!(
            !metrics.contains(forbidden),
            "trust-reload metrics must not carry `{forbidden}`: {metrics}"
        );
    }
}

// ── Metric shape ────────────────────────────────────────────────────────

#[tokio::test(start_paused = true)]
async fn metric_labels_are_bounded_to_the_closed_reason_set() {
    let status = status_at(Instant::now(), BOUND);
    status.record_attempt();
    status.record_rejected(TrustReloadFailure::DocumentInvalid);
    advance(BOUND).await;
    let snapshot = status.snapshot();

    let mut output = String::new();
    render_cp_dp_trust_reload_prometheus(&mut output, "", Some(&snapshot));

    for family in [
        "ferrum_cp_dp_trust_reload_attempts_total",
        "ferrum_cp_dp_trust_reload_acceptances_total",
        "ferrum_cp_dp_trust_reload_rejections_total",
        "ferrum_cp_dp_trust_reload_recoveries_total",
        "ferrum_cp_dp_trust_reload_consecutive_failures",
        "ferrum_cp_dp_trust_last_acceptance_age_seconds",
        "ferrum_cp_dp_trust_max_stale_seconds",
        "ferrum_cp_dp_trust_degraded",
        "ferrum_cp_dp_trust_stale",
        "ferrum_cp_dp_trust_reload_worker_running",
    ] {
        assert!(
            output.contains(&format!("# TYPE {family} ")),
            "missing family {family}: {output}"
        );
    }
    assert!(output.contains("ferrum_cp_dp_trust_stale 1\n"));
    assert!(output.contains("ferrum_cp_dp_trust_degraded 1\n"));
    let invalid_series =
        "ferrum_cp_dp_trust_reload_rejections_total{reason=\"document_invalid\"} 1";
    assert!(output.contains(invalid_series), "{output}");
    // Every reason series is emitted, and only the closed set of them.
    let series = output
        .lines()
        .filter(|line| line.starts_with("ferrum_cp_dp_trust_reload_rejections_total{"))
        .count();
    assert_eq!(series, TRUST_RELOAD_FAILURES.len());

    // Nothing at all outside a CP that watches a bundle.
    let mut empty = String::new();
    render_cp_dp_trust_reload_prometheus(&mut empty, "", None);
    assert!(empty.is_empty());
}

// ── The live worker ─────────────────────────────────────────────────────

/// Wait for the published status to satisfy `predicate`, or fail.
async fn wait_for_status(
    status: &Arc<CpDpTrustReloadStatus>,
    what: &str,
    predicate: impl Fn(&ferrum_edge::grpc::cp_trust_health::CpDpTrustReloadSnapshot) -> bool,
) {
    let deadline = std::time::Instant::now() + StdDuration::from_secs(20);
    loop {
        let snapshot = status.snapshot();
        if predicate(&snapshot) {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for {what}: {snapshot:?}"
        );
        tokio::time::sleep(StdDuration::from_millis(50)).await;
    }
}

fn spawn_worker(
    path: &std::path::Path,
    status: Arc<CpDpTrustReloadStatus>,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    ferrum_edge::grpc::cp_trust::spawn_trust_bundle_reload(
        path.to_string_lossy().to_string(),
        None,
        Arc::new(ferrum_edge::grpc::cp_trust::CpDpVerifierStore::new(
            verifier(KID, NAMESPACE, SECRET),
        )),
        false,
        StdDuration::from_millis(1),
        status,
        shutdown,
    )
}

fn live_status() -> Arc<CpDpTrustReloadStatus> {
    Arc::new(CpDpTrustReloadStatus::watching(
        Duration::from_secs(900),
        false,
        Duration::from_secs(1),
    ))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_missing_bundle_document_publishes_the_closed_unreadable_reason() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("absent-bundle.json");
    let status = live_status();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let handle = spawn_worker(&path, status.clone(), shutdown_rx);

    wait_for_status(&status, "a rejected reload", |snapshot| {
        snapshot.degraded && snapshot.reason == "document_unreadable"
    })
    .await;
    let snapshot = status.snapshot();
    assert!(snapshot.consecutive_failures >= 1);
    assert!(!snapshot.stale, "still inside the bound: {snapshot:?}");

    // Writing a valid document recovers without any restart.
    std::fs::write(&path, bundle_document(KID, NAMESPACE, SECRET)).expect("write bundle");
    wait_for_status(&status, "recovery", |snapshot| {
        !snapshot.degraded && snapshot.recoveries_total == 1
    })
    .await;

    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(StdDuration::from_secs(5), handle).await;
    assert_eq!(status.snapshot().worker_state, "stopped");
    assert!(!status.snapshot().degraded);
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unreadable_bundle_document_publishes_the_closed_unreadable_reason() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("denied-bundle.json");
    std::fs::write(&path, bundle_document(KID, NAMESPACE, SECRET)).expect("write bundle");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000))
        .expect("drop read permission");
    if std::fs::read(&path).is_ok() {
        // Running as root: the permission bit is not enforced, so there is no
        // read failure to observe.
        return;
    }
    let status = live_status();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let handle = spawn_worker(&path, status.clone(), shutdown_rx);

    wait_for_status(&status, "a permission-denied reload", |snapshot| {
        snapshot.degraded && snapshot.reason == "document_unreadable"
    })
    .await;

    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(StdDuration::from_secs(5), handle).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_malformed_candidate_retains_the_previous_verifier_and_degrades() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("bundle.json");
    std::fs::write(&path, bundle_document(KID, NAMESPACE, SECRET)).expect("write bundle");
    let status = live_status();
    let accepted_before = status.snapshot().acceptances_total;
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let handle = spawn_worker(&path, status.clone(), shutdown_rx);

    std::fs::write(&path, "{ not json").expect("write malformed bundle");
    wait_for_status(&status, "a malformed candidate", |snapshot| {
        snapshot.degraded && snapshot.reason == "document_invalid"
    })
    .await;
    assert_eq!(
        status.snapshot().acceptances_total,
        accepted_before,
        "a malformed candidate must never be accepted, even partially"
    );

    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(StdDuration::from_secs(5), handle).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rotated_bundle_is_accepted_without_publishing_an_identifier() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("bundle.json");
    std::fs::write(&path, bundle_document(KID, NAMESPACE, SECRET)).expect("write bundle");
    let status = live_status();
    let accepted_before = status.snapshot().acceptances_total;
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let handle = spawn_worker(&path, status.clone(), shutdown_rx);

    std::fs::write(
        &path,
        bundle_document(
            "tenant-a-v2",
            NAMESPACE,
            "rotated-tenant-a-secret-2026-ferrum",
        ),
    )
    .expect("rotate bundle");
    wait_for_status(&status, "a rotated generation", |snapshot| {
        snapshot.acceptances_total > accepted_before
    })
    .await;
    let snapshot = status.snapshot();
    assert!(!snapshot.degraded);
    assert!(snapshot.acceptances_total >= 2);
    // The rotation is observable as an acceptance and a reset age — never as a
    // value an attacker could recompute from a guessed secret.
    assert_eq!(snapshot.reason, "ok");

    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(StdDuration::from_secs(5), handle).await;
}

// ── Authenticated / coarse health separation ────────────────────────────

/// The `/health` projection is authenticated-detail only, and readiness is the
/// only thing an unauthenticated probe learns. This asserts the projection
/// itself is fixed-cardinality and JSON-shaped as documented; the transport
/// tiering is exercised in `admin_observability_auth_tests.rs`.
#[tokio::test(start_paused = true)]
async fn the_health_projection_is_fixed_cardinality() {
    let status = status_at(Instant::now(), BOUND);
    status.record_attempt();
    status.record_rejected(TrustReloadFailure::ReaderUnavailable);
    let value: Value = serde_json::to_value(status.snapshot()).expect("snapshot serializes");
    let object = value.as_object().expect("object projection");

    let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "acceptances_total",
            "admission_blocked",
            "attempts_total",
            "configured",
            "consecutive_failures",
            "degraded",
            "last_acceptance_age_seconds",
            "last_attempt_age_seconds",
            "max_stale_seconds",
            "readiness_blocked",
            "reason",
            "recoveries_total",
            "rejections_by_reason",
            "rejections_total",
            "stale",
            "unbounded_stale_allowed",
            "worker_running",
            "worker_state",
        ]
    );
    assert_eq!(object["reason"], json!("reader_unavailable"));
    assert_eq!(object["configured"], json!(true));
}
