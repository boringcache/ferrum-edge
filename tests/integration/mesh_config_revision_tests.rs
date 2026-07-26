//! Authoritative mesh config-revision ordering (issue #2473).
//!
//! Native multi-CP failover must never move a data plane backwards. A fallback
//! control plane that missed a poll or is partitioned from the config store
//! still serves a structurally valid slice; installing it would reinstate
//! deleted routes, endpoints, policies, or trust material until failback. The
//! slice `version` cannot arbitrate that — it renders the serving CP's local
//! wall clock.
//!
//! Three layers of coverage:
//!
//! 1. The pure comparison contract (`MeshConfigRevision::compare`) and the
//!    stateful gate (`MeshRevisionGate`), including the time-dependent
//!    foreign-authority adoption and the operator reset.
//! 2. The consumer/runtime seam: a data plane whose stream rotates between two
//!    control planes at different revisions (N-1, N, N+1, clock skew, CP
//!    restart, intentional rollback published as N+1, failback after a stale
//!    fallback was quarantined).
//! 3. A live two-CP `MeshSubscribe` run: a stale primary is quarantined, the
//!    stream is torn down, and the data plane converges on the fresher
//!    fallback without ever serving the stale slice.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use chrono::{TimeZone, Utc};
use tokio::net::TcpListener;
use tokio::sync::{oneshot, watch};
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;
use tonic::{Request, Response, Status};

use ferrum_edge::grpc::dp_client::GrpcJwtSecret;
use ferrum_edge::grpc::proto::mesh_config_sync_server::{MeshConfigSync, MeshConfigSyncServer};
use ferrum_edge::grpc::proto::{MeshConfigUpdate, MeshSubscribeRequest};
use ferrum_edge::modes::mesh::config_consumer::native_client::{
    NativeMeshClientConfig, NativeMeshConfigConsumer, start_native_mesh_client_with_shutdown,
};
use ferrum_edge::modes::mesh::config_consumer::update_validation::{
    MeshUpdateConsumer, MeshUpdateExpectation, MeshUpdateRejectReason, validate_mesh_config_update,
};
use ferrum_edge::modes::mesh::revision::{
    MeshConfigRevision, MeshRevisionGate, MeshRevisionOrder, MeshRevisionPolicy,
    MeshRevisionRejectReason,
};
use ferrum_edge::modes::mesh::runtime::{MeshRuntimeState, MeshSliceInstall};
use ferrum_edge::modes::mesh::slice::MeshSlice;
use ferrum_edge::plugins::mesh::prometheus_helpers::render_mesh_observability_metrics;

const NODE_ID: &str = "dp-node-a";
const NAMESPACE: &str = "alpha";
const JWT_SECRET: &str = "mesh-config-revision-secret-00000000";

// ── Fixtures ───────────────────────────────────────────────────────────────

fn revision(authority: &str, sequence: u64) -> MeshConfigRevision {
    MeshConfigRevision::new(authority, sequence)
}

/// A slice bound to the test subscription at a given authoritative revision.
///
/// `version` is deliberately decoupled from `sequence` so the tests can prove
/// ordering follows the revision and NOT the CP-local wall clock rendering.
fn slice_at(version: &str, revision: Option<MeshConfigRevision>) -> MeshSlice {
    MeshSlice {
        node_id: NODE_ID.to_string(),
        namespace: NAMESPACE.to_string(),
        version: version.to_string(),
        revision,
        ..MeshSlice::default()
    }
}

fn update_for(slice: &MeshSlice) -> MeshConfigUpdate {
    MeshConfigUpdate {
        version: slice.version.clone(),
        timestamp: 1,
        mesh_slice_json: serde_json::to_string(slice).expect("slice serializes"),
        ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
        heartbeat: false,
        config_authority: slice
            .revision
            .as_ref()
            .map(|revision| revision.authority.clone())
            .unwrap_or_default(),
        config_sequence: slice
            .revision
            .as_ref()
            .map_or(0, |revision| revision.sequence),
    }
}

fn client_config() -> NativeMeshClientConfig {
    NativeMeshClientConfig {
        node_id: NODE_ID.to_string(),
        namespace: NAMESPACE.to_string(),
        workload_spiffe_id: None,
        waypoint_name: None,
        labels: HashMap::new(),
        ambient_udp_source_scoping: false,
        primary_retry_secs: 0,
    }
}

/// A consumer bound to exactly what `client_config` subscribes with. Each
/// control-plane stream builds its own consumer over the SAME runtime state,
/// which is precisely the multi-CP failover shape.
fn consumer_for(state: MeshRuntimeState) -> NativeMeshConfigConsumer {
    let request = client_config().subscribe_request(ferrum_edge::FERRUM_VERSION);
    NativeMeshConfigConsumer::new(state, MeshUpdateExpectation::from_subscribe_request(&request))
}

fn installed_version(state: &MeshRuntimeState) -> Option<String> {
    state
        .snapshot()
        .as_ref()
        .as_ref()
        .map(|slice| slice.version.clone())
}

fn rendered_counter(series: &str) -> u64 {
    let mut rendered = String::new();
    render_mesh_observability_metrics(&mut rendered);
    rendered
        .lines()
        .find_map(|line| line.strip_prefix(series))
        .and_then(|rest| rest.trim().parse::<u64>().ok())
        .unwrap_or(0)
}

// ── Comparison contract ────────────────────────────────────────────────────

#[test]
fn compare_orders_within_one_authority_and_refuses_across_authorities() {
    let accepted = revision("db", 100);

    assert_eq!(
        MeshConfigRevision::compare(None, Some(&accepted)),
        MeshRevisionOrder::Bootstrap,
        "the first slice installs regardless of revision"
    );
    assert_eq!(
        MeshConfigRevision::compare(Some(&accepted), Some(&revision("db", 101))),
        MeshRevisionOrder::Newer
    );
    assert_eq!(
        MeshConfigRevision::compare(Some(&accepted), Some(&revision("db", 100))),
        MeshRevisionOrder::Same,
        "a reconnect replays the same revision and must stay installable"
    );
    assert_eq!(
        MeshConfigRevision::compare(Some(&accepted), Some(&revision("db", 99))),
        MeshRevisionOrder::Older
    );
    assert_eq!(
        MeshConfigRevision::compare(Some(&accepted), Some(&revision("db-restored", 1_000_000))),
        MeshRevisionOrder::Incomparable,
        "a foreign authority is never ordered by sequence, however large"
    );
    assert_eq!(
        MeshConfigRevision::compare(Some(&accepted), None),
        MeshRevisionOrder::Unversioned
    );

    assert!(MeshRevisionOrder::Bootstrap.installs());
    assert!(MeshRevisionOrder::Newer.installs());
    assert!(MeshRevisionOrder::Same.installs());
    assert!(!MeshRevisionOrder::Older.installs());
    assert!(!MeshRevisionOrder::Incomparable.installs());
    assert!(!MeshRevisionOrder::Unversioned.installs());
}

/// A blank or over-long authority carries no ordering meaning, so it is treated
/// as absent (fail closed) rather than compared as a domain name.
#[test]
fn malformed_authorities_are_treated_as_absent() {
    let accepted = revision("db", 100);
    let blank = revision("   ", 500);
    let oversized = revision(&"a".repeat(129), 500);

    assert!(!blank.is_well_formed());
    assert!(!oversized.is_well_formed());
    assert_eq!(
        MeshConfigRevision::compare(Some(&accepted), Some(&blank)),
        MeshRevisionOrder::Unversioned
    );
    assert_eq!(
        MeshConfigRevision::compare(Some(&accepted), Some(&oversized)),
        MeshRevisionOrder::Unversioned
    );
    // A malformed ACCEPTED revision cannot lock the data plane out either.
    assert_eq!(
        MeshConfigRevision::compare(Some(&blank), Some(&accepted)),
        MeshRevisionOrder::Bootstrap
    );
}

// ── Gate state machine ─────────────────────────────────────────────────────

#[test]
fn gate_quarantines_stale_and_keeps_accepting_forward_progress() {
    let gate = MeshRevisionGate::new();
    let now = Utc.with_ymd_and_hms(2026, 7, 26, 12, 0, 0).expect("fixture time");

    gate.admit(Some(&revision("db", 100)), now)
        .expect("bootstrap installs");

    let rejection = gate
        .admit(Some(&revision("db", 99)), now)
        .expect_err("an older revision is quarantined");
    assert_eq!(
        rejection.reason(),
        MeshRevisionRejectReason::StaleRevision
    );
    assert!(
        rejection.terminates_stream(),
        "a lagging CP's whole view is behind; the stream must fail over"
    );
    assert_eq!(
        gate.accepted().map(|revision| revision.sequence),
        Some(100),
        "a quarantine must not move the accepted revision"
    );

    // Repeated quarantines of the same pair accumulate, and the diagnostics
    // never echo raw slice content.
    gate.admit(Some(&revision("db", 98)), now)
        .expect_err("still stale");
    let diagnostics = gate.diagnostics();
    assert!(diagnostics.quarantine_active);
    assert_eq!(diagnostics.rejected_total, 2);
    let quarantined = diagnostics.quarantined.expect("quarantine recorded");
    assert_eq!(quarantined.reason, "stale_revision");

    // Failback: the primary catches up and installs, clearing the quarantine.
    gate.admit(Some(&revision("db", 101)), now)
        .expect("a newer revision installs");
    assert_eq!(gate.accepted().map(|r| r.sequence), Some(101));
    let diagnostics = gate.diagnostics();
    assert!(!diagnostics.quarantine_active);
    assert!(diagnostics.quarantined.is_none());
    assert_eq!(
        diagnostics.rejected_total, 2,
        "the total is cumulative; only the active quarantine clears"
    );
}

/// A foreign authority is quarantined until it has been observed continuously
/// for the configured grace period, then adopted. This is the no-permanent-
/// lockout path for control-plane state loss and deliberate source resets.
#[test]
fn gate_adopts_a_persistent_foreign_authority_after_the_grace_period() {
    let gate = MeshRevisionGate::new();
    gate.set_policy(MeshRevisionPolicy {
        foreign_authority_adopt_secs: 300,
    });
    let t0 = Utc.with_ymd_and_hms(2026, 7, 26, 12, 0, 0).expect("fixture time");

    gate.admit(Some(&revision("db", 100)), t0)
        .expect("bootstrap installs");

    let rejection = gate
        .admit(Some(&revision("db-restored", 1)), t0)
        .expect_err("a foreign authority is quarantined on first sight");
    assert_eq!(
        rejection.reason(),
        MeshRevisionRejectReason::IncomparableAuthority
    );

    // Still inside the grace window.
    gate.admit(
        Some(&revision("db-restored", 2)),
        t0 + chrono::Duration::seconds(299),
    )
    .expect_err("still inside the adoption grace window");
    assert_eq!(gate.accepted().map(|r| r.authority), Some("db".to_string()));

    // A DIFFERENT foreign authority restarts the observation window, so a
    // flapping set of foreign CPs cannot accumulate grace.
    gate.admit(
        Some(&revision("db-other", 7)),
        t0 + chrono::Duration::seconds(300),
    )
    .expect_err("a different foreign authority restarts the window");
    gate.admit(
        Some(&revision("db-restored", 3)),
        t0 + chrono::Duration::seconds(301),
    )
    .expect_err("the original foreign authority also restarts its window");

    let order = gate
        .admit(
            Some(&revision("db-restored", 4)),
            t0 + chrono::Duration::seconds(601),
        )
        .expect("a continuously observed foreign authority is adopted");
    assert_eq!(order, MeshRevisionOrder::Incomparable);
    assert_eq!(
        gate.accepted(),
        Some(revision("db-restored", 4)),
        "adoption restarts ordering from the adopted revision"
    );
    assert_eq!(gate.diagnostics().adopted_total, 1);
}

#[test]
fn adoption_can_be_disabled_and_reset_is_the_operator_escape_hatch() {
    let gate = MeshRevisionGate::new();
    gate.set_policy(MeshRevisionPolicy {
        foreign_authority_adopt_secs: 0,
    });
    let t0 = Utc.with_ymd_and_hms(2026, 7, 26, 12, 0, 0).expect("fixture time");

    gate.admit(Some(&revision("db", 100)), t0)
        .expect("bootstrap installs");
    gate.admit(
        Some(&revision("db-restored", 1)),
        t0 + chrono::Duration::days(30),
    )
    .expect_err("adoption disabled: a foreign authority stays quarantined forever");

    // A sequence rewind INSIDE one authority is never auto-adopted, however
    // long it persists — it is indistinguishable from the rollback the gate
    // exists to prevent.
    gate.set_policy(MeshRevisionPolicy {
        foreign_authority_adopt_secs: 1,
    });
    gate.admit(Some(&revision("db", 5)), t0 + chrono::Duration::days(60))
        .expect_err("a same-authority rewind is never auto-adopted");

    // The operator reset clears the accepted revision, and the next slice from
    // any authority establishes a new baseline.
    let cleared = gate.reset().expect("the accepted revision is returned");
    assert_eq!(cleared, revision("db", 100));
    assert!(gate.diagnostics().quarantined.is_none());
    gate.admit(Some(&revision("db", 5)), t0 + chrono::Duration::days(61))
        .expect("after a reset the rewound revision installs");
    assert_eq!(gate.accepted(), Some(revision("db", 5)));
}

// ── Runtime install seam ───────────────────────────────────────────────────

#[test]
fn install_slice_quarantines_a_stale_slice_without_touching_live_state() {
    let state = MeshRuntimeState::new();

    assert_eq!(
        state.install_slice(slice_at("v-100", Some(revision("db", 100)))),
        MeshSliceInstall::Installed
    );
    let installed_at = state.last_install_at().expect("first install stamps");

    let outcome = state.install_slice(slice_at("v-99", Some(revision("db", 99))));
    let rejection = outcome
        .rejection()
        .expect("an older revision must be quarantined");
    assert_eq!(
        rejection.reason(),
        MeshRevisionRejectReason::StaleRevision
    );

    assert_eq!(installed_version(&state).as_deref(), Some("v-100"));
    assert_eq!(
        state.last_install_at(),
        Some(installed_at),
        "a quarantined slice must not advance the receive timestamp"
    );
    assert_eq!(state.accepted_revision(), Some(revision("db", 100)));
    assert!(state.revision_diagnostics().quarantine_active);
}

/// Unversioned sources (Kubernetes CRD controller, file source) keep working:
/// with no accepted revision the gate is inert. But once a REVISIONED slice is
/// accepted, an unrevisioned one can no longer displace it — otherwise a stale
/// or hostile control plane could downgrade simply by dropping the field.
#[test]
fn unversioned_slices_are_inert_until_a_revision_is_accepted() {
    let state = MeshRuntimeState::new();

    assert!(state.install_slice(slice_at("v1", None)).installed());
    assert!(state.install_slice(slice_at("v2", None)).installed());
    assert!(state.accepted_revision().is_none());

    assert!(
        state
            .install_slice(slice_at("v3", Some(revision("db", 10))))
            .installed()
    );
    let outcome = state.install_slice(slice_at("v4", None));
    assert_eq!(
        outcome
            .rejection()
            .expect("an unrevisioned slice cannot displace a revisioned one")
            .reason(),
        MeshRevisionRejectReason::MissingRevision
    );
    assert_eq!(installed_version(&state).as_deref(), Some("v3"));
}

#[test]
fn revision_rejections_increment_a_bounded_reason_labelled_metric() {
    let series = "ferrum_mesh_config_revision_rejections_total{reason=\"stale_revision\"}";
    let before = rendered_counter(series);

    let state = MeshRuntimeState::new();
    state.install_slice(slice_at("v-100", Some(revision("db", 100))));
    state.install_slice(slice_at("v-99", Some(revision("db", 99))));

    let after = rendered_counter(series);
    assert!(
        after > before,
        "the quarantine must increment {series} (before={before}, after={after})"
    );

    // The CP-supplied authority/sequence must never reach /metrics.
    let mut rendered = String::new();
    render_mesh_observability_metrics(&mut rendered);
    for line in rendered
        .lines()
        .filter(|line| line.starts_with("ferrum_mesh_config_revision_"))
    {
        assert!(
            !line.contains("authority=\"db\"") && !line.contains("sequence="),
            "revision metrics must carry no control-plane-supplied value: {line}"
        );
    }
}

// ── Multi-CP failover matrix (consumer seam) ───────────────────────────────

/// Simulate a data plane whose stream rotates between control planes: each
/// control plane's stream builds its own consumer over the SAME runtime state.
///
/// Covers the acceptance criteria matrix in one place so the relationship
/// between the cases stays visible: primary N → fallback N-1 / N / N+1, a CP
/// whose wall clock and restart make `version` useless, an intentional rollback
/// published as N+1, and failback after a stale fallback was quarantined.
#[test]
fn multi_cp_failover_never_moves_the_data_plane_backwards() {
    let state = MeshRuntimeState::new();
    let primary = consumer_for(state.clone());
    let fallback = consumer_for(state.clone());

    // Primary publishes N.
    primary
        .apply_update(&update_for(&slice_at(
            "cp-a-2026-07-26T12:00:00Z",
            Some(revision("db", 100)),
        )))
        .expect("the first slice installs");
    assert_eq!(
        installed_version(&state).as_deref(),
        Some("cp-a-2026-07-26T12:00:00Z")
    );

    // Fallback at N-1: quarantined. Note its `version` renders a LATER wall
    // clock than the primary's — a timestamp comparison would have accepted
    // this rollback.
    let stale = slice_at("cp-b-2026-07-26T13:00:00Z", Some(revision("db", 99)));
    let error = fallback
        .apply_update(&update_for(&stale))
        .expect_err("a lagging fallback must not roll the data plane back");
    assert_eq!(
        error.reason_label(),
        MeshRevisionRejectReason::StaleRevision.as_metric_label()
    );
    assert!(
        error.terminates_stream(),
        "the data plane drops the stale CP's stream and keeps failing over"
    );
    assert_eq!(
        installed_version(&state).as_deref(),
        Some("cp-a-2026-07-26T12:00:00Z"),
        "the last-good slice keeps serving"
    );

    // Fallback at N: the same generation, rendered by a different CP with a
    // different clock. Installs (it is not a rollback) and does not flap.
    fallback
        .apply_update(&update_for(&slice_at(
            "cp-b-2026-07-26T11:59:00Z",
            Some(revision("db", 100)),
        )))
        .expect("an equal revision from another replica installs");
    assert_eq!(state.accepted_revision(), Some(revision("db", 100)));

    // Fallback at N+1: forward progress from the fallback is accepted.
    fallback
        .apply_update(&update_for(&slice_at(
            "cp-b-2026-07-26T11:59:30Z",
            Some(revision("db", 101)),
        )))
        .expect("a newer revision from the fallback installs");
    assert_eq!(state.accepted_revision(), Some(revision("db", 101)));

    // CP restart / clock skew: the primary comes back with a wall clock BEHIND
    // the fallback's and a version string that sorts earlier, but a higher
    // durable sequence. Ordering follows the sequence, so it installs.
    primary
        .apply_update(&update_for(&slice_at(
            "cp-a-2026-07-26T09:00:00Z",
            Some(revision("db", 102)),
        )))
        .expect("a restarted CP with a skewed clock still orders by sequence");
    assert_eq!(
        installed_version(&state).as_deref(),
        Some("cp-a-2026-07-26T09:00:00Z")
    );

    // Intentional operator rollback: the old content is republished as a WRITE,
    // so it arrives at a HIGHER sequence and installs.
    primary
        .apply_update(&update_for(&slice_at(
            "cp-a-rollback-to-2026-07-20",
            Some(revision("db", 103)),
        )))
        .expect("an intentional rollback is a higher revision and installs");
    assert_eq!(
        installed_version(&state).as_deref(),
        Some("cp-a-rollback-to-2026-07-20")
    );

    // Failback after the stale fallback was quarantined: the primary is
    // authoritative again and forward progress resumes with no reset needed.
    primary
        .apply_update(&update_for(&slice_at(
            "cp-a-after-failback",
            Some(revision("db", 104)),
        )))
        .expect("failback resumes forward progress");
    assert_eq!(state.accepted_revision(), Some(revision("db", 104)));
    assert!(
        !state.revision_diagnostics().quarantine_active,
        "an accepted slice clears the active quarantine"
    );
}

/// The envelope carries a duplicate of the slice's own revision; a frame whose
/// two copies disagree is internally inconsistent and refused before install.
#[test]
fn envelope_revision_must_match_the_slice_revision() {
    let request = client_config().subscribe_request(ferrum_edge::FERRUM_VERSION);
    let expected = MeshUpdateExpectation::from_subscribe_request(&request);
    let slice = slice_at("v1", Some(revision("db", 100)));

    validate_mesh_config_update(&update_for(&slice), &expected, MeshUpdateConsumer::Native)
        .expect("a faithful envelope is accepted");

    let forged_sequence = MeshConfigUpdate {
        config_sequence: 1_000,
        ..update_for(&slice)
    };
    let rejection = validate_mesh_config_update(
        &forged_sequence,
        &expected,
        MeshUpdateConsumer::Native,
    )
    .expect_err("an envelope claiming a different sequence is refused");
    assert_eq!(
        rejection.reason(),
        MeshUpdateRejectReason::EnvelopeRevisionMismatch
    );

    let dropped_authority = MeshConfigUpdate {
        config_authority: String::new(),
        config_sequence: 0,
        ..update_for(&slice)
    };
    assert_eq!(
        validate_mesh_config_update(
            &dropped_authority,
            &expected,
            MeshUpdateConsumer::Native
        )
        .expect_err("dropping the envelope revision is a mismatch, not an exemption")
        .reason(),
        MeshUpdateRejectReason::EnvelopeRevisionMismatch
    );

    // An unrevisioned source is consistent when BOTH copies are absent.
    let unversioned = slice_at("v1", None);
    validate_mesh_config_update(
        &update_for(&unversioned),
        &expected,
        MeshUpdateConsumer::Native,
    )
    .expect("both copies absent is consistent");
}

// ── Live two-CP MeshSubscribe stream ───────────────────────────────────────

/// An in-process control plane that replays a fixed script of frames and then
/// holds the stream open.
#[derive(Clone)]
struct ScriptedMeshCp {
    updates: Arc<Vec<MeshConfigUpdate>>,
    subscribe_count: Arc<AtomicUsize>,
}

#[tonic::async_trait]
impl MeshConfigSync for ScriptedMeshCp {
    type MeshSubscribeStream =
        Pin<Box<dyn tokio_stream::Stream<Item = Result<MeshConfigUpdate, Status>> + Send>>;

    async fn mesh_subscribe(
        &self,
        _request: Request<MeshSubscribeRequest>,
    ) -> Result<Response<Self::MeshSubscribeStream>, Status> {
        self.subscribe_count.fetch_add(1, Ordering::Relaxed);
        let items: Vec<Result<MeshConfigUpdate, Status>> =
            self.updates.iter().cloned().map(Ok).collect();
        let scripted = tokio_stream::iter(items);
        let held_open = tokio_stream::pending::<Result<MeshConfigUpdate, Status>>();
        let stream: Self::MeshSubscribeStream = Box::pin(scripted.chain(held_open));
        Ok(Response::new(stream))
    }
}

struct CpHandle {
    url: String,
    subscribe_count: Arc<AtomicUsize>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
}

impl CpHandle {
    async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        let _ = tokio::time::timeout(Duration::from_secs(2), &mut self.task).await;
    }
}

async fn start_cp(updates: Vec<MeshConfigUpdate>) -> CpHandle {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind stub CP");
    let addr = listener.local_addr().expect("stub CP addr");
    let subscribe_count = Arc::new(AtomicUsize::new(0));
    let cp = ScriptedMeshCp {
        updates: Arc::new(updates),
        subscribe_count: subscribe_count.clone(),
    };
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let incoming = TcpListenerStream::new(listener);
    let task = tokio::spawn(async move {
        Server::builder()
            .add_service(MeshConfigSyncServer::new(cp))
            .serve_with_incoming_shutdown(incoming, async {
                let _ = shutdown_rx.await;
            })
            .await
    });
    CpHandle {
        url: format!("http://{addr}"),
        subscribe_count,
        shutdown_tx: Some(shutdown_tx),
        task,
    }
}

/// Live multi-CP failover: the primary control plane is serving an OLDER
/// authoritative revision than the one this data plane already accepted. It
/// must be quarantined (never installed), the stream torn down, and the client
/// must rotate to the fresher fallback and converge there.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_stale_primary_is_quarantined_and_the_client_converges_on_the_fresh_fallback() {
    let stale = slice_at("cp-stale", Some(revision("db", 99)));
    let fresh = slice_at("cp-fresh", Some(revision("db", 101)));
    let stale_cp = start_cp(vec![update_for(&stale)]).await;
    let fresh_cp = start_cp(vec![update_for(&fresh)]).await;

    // Seed the accepted revision the way a previously accepted update would.
    let state = MeshRuntimeState::new();
    assert!(
        state
            .install_slice(slice_at("last-good", Some(revision("db", 100))))
            .installed()
    );

    let (shutdown_tx, handle) = {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let handle = tokio::spawn(start_native_mesh_client_with_shutdown(
            vec![stale_cp.url.clone(), fresh_cp.url.clone()],
            GrpcJwtSecret::new(JWT_SECRET.to_string()),
            client_config(),
            state.clone(),
            shutdown_rx,
            None,
            None,
        ));
        (shutdown_tx, handle)
    };

    // The client backs off ~1s (±25%) between control planes, so allow a few
    // seconds for the rotation without pinning an exact schedule.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        if installed_version(&state).as_deref() == Some("cp-fresh") {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the client must converge on the fresher fallback; installed={:?}",
            installed_version(&state)
        );
        assert_ne!(
            installed_version(&state).as_deref(),
            Some("cp-stale"),
            "the stale slice must never become live"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    assert_eq!(state.accepted_revision(), Some(revision("db", 101)));
    assert!(
        stale_cp.subscribe_count.load(Ordering::Relaxed) >= 1,
        "the client must actually have subscribed to the stale CP"
    );

    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(3), handle).await;
    stale_cp.shutdown().await;
    fresh_cp.shutdown().await;
}
