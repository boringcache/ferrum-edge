//! Authoritative mesh config-revision ordering (issue #2473).
//!
//! Native multi-CP failover must never move a data plane backwards. A fallback
//! control plane that missed a poll or is partitioned from the config store
//! still serves a structurally valid slice; installing it would reinstate
//! deleted routes, endpoints, policies, or trust material until failback. The
//! slice `version` cannot arbitrate that — it renders the serving CP's local
//! wall clock.
//!
//! Five layers of coverage:
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
//! 4. The candidate LIFECYCLE across the freshness gate and the proxy runtime:
//!    admission is provisional, so a candidate the runtime later refuses must
//!    return the watermark to the last applied generation — without a late
//!    rejection disturbing a newer candidate received meanwhile.
//! 5. Bounding of the control-plane-supplied `authority` on every copy that
//!    leaves the gate (diagnostics, the operator reset, and the log lines built
//!    from them), while ordering keeps the raw value.

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

// ── Candidate lifecycle: received → applied, or rolled back ────────────────
//
// Passing the freshness gate only makes a slice the RECEIVED candidate. The
// mesh proxy runtime is a second, independent gate: slice→config preparation
// or `ProxyState::update_config` can still refuse it, leaving the previous
// generation serving. These tests drive the runtime seam
// (`install_slice` → `record_applied_slice` / `record_rejected_slice`) that the
// mesh apply loop uses, rather than `MeshRevisionGate::admit` in isolation,
// because the defect they cover lives in the relationship between the two
// gates and not in the comparison contract.

/// `record_applied_slice` fans the accepted slice's (here empty) runtime
/// overlay out to process-global RTDS consumers, so every lifecycle test below
/// serialises against `mesh_runtime_overlay_consumers_tests` through the
/// documented process-wide guard. Integration tests share one process per
/// shard, and an empty overlay still REPLACES those consumers' state.
fn overlay_consumer_guard() -> std::sync::MutexGuard<'static, ()> {
    ferrum_edge::modes::mesh::runtime_overlay_consumers::test_lock()
}

/// A candidate the proxy runtime refuses must not keep the authoritative
/// watermark. Otherwise a hostile or buggy control plane publishes ONE
/// runtime-invalid slice at a far-future sequence and permanently quarantines
/// every valid revision beneath it — with a slice that never served a request.
#[test]
fn a_runtime_rejected_candidate_rolls_the_watermark_back_and_reopens_recovery() {
    let _overlay_guard = overlay_consumer_guard();
    let state = MeshRuntimeState::new();

    // The proxy is serving revision N.
    let applied = slice_at("v-10", Some(revision("db", 10)));
    assert!(state.install_slice(applied.clone()).installed());
    state.record_applied_slice(&applied);
    assert_eq!(state.accepted_revision(), Some(revision("db", 10)));
    assert_eq!(state.applied_revision(), Some(revision("db", 10)));

    // N+10 passes wire binding and freshness admission and becomes the
    // received candidate...
    assert!(
        state
            .install_slice(slice_at("v-20", Some(revision("db", 20))))
            .installed()
    );
    assert_eq!(
        state.accepted_revision(),
        Some(revision("db", 20)),
        "admission is provisional but still advances the received watermark"
    );

    // ...and the proxy runtime then refuses it (preparation error, or
    // `update_config` rejecting the candidate config). The proxy keeps N.
    assert!(
        state.record_rejected_slice(&state.snapshot()),
        "the refused candidate owns the watermark, so it must roll back"
    );
    assert_eq!(
        state.accepted_revision(),
        Some(revision("db", 10)),
        "the watermark returns to the last PROXY-APPLIED revision"
    );
    assert_eq!(state.applied_revision(), Some(revision("db", 10)));

    // Every revision the poisoned watermark would have locked out is eligible
    // again, so a control plane can still recover the data plane.
    let recovery = slice_at("v-11", Some(revision("db", 11)));
    assert!(state.install_slice(recovery.clone()).installed());
    state.record_applied_slice(&recovery);
    assert_eq!(installed_version(&state).as_deref(), Some("v-11"));
    assert_eq!(state.applied_revision(), Some(revision("db", 11)));

    // The rollback is not a general relaxation: genuinely stale revisions are
    // still quarantined against the restored watermark.
    assert_eq!(
        state
            .install_slice(slice_at("v-9", Some(revision("db", 9))))
            .rejection()
            .expect("an older revision stays quarantined after a rollback")
            .reason(),
        MeshRevisionRejectReason::StaleRevision
    );
}

/// A rejection that lands after a NEWER candidate has already been received
/// must not roll that newer candidate's watermark back — the apply task and the
/// config consumer run concurrently, so this ordering is ordinary, not
/// exceptional.
#[test]
fn a_late_rejection_cannot_roll_back_a_newer_candidate() {
    let _overlay_guard = overlay_consumer_guard();
    let state = MeshRuntimeState::new();
    let applied = slice_at("v-10", Some(revision("db", 10)));
    assert!(state.install_slice(applied.clone()).installed());
    state.record_applied_slice(&applied);

    // The apply task picks up N+10 and starts preparing it.
    assert!(
        state
            .install_slice(slice_at("v-20", Some(revision("db", 20))))
            .installed()
    );
    let mid_apply = state.snapshot();

    // N+11 arrives while N+10 is still mid-apply and supersedes it.
    assert!(
        state
            .install_slice(slice_at("v-21", Some(revision("db", 21))))
            .installed()
    );
    assert_eq!(state.accepted_revision(), Some(revision("db", 21)));

    assert!(
        !state.record_rejected_slice(&mid_apply),
        "a superseded candidate must not finalize the watermark"
    );
    assert_eq!(
        state.accepted_revision(),
        Some(revision("db", 21)),
        "the newer candidate keeps the watermark it legitimately advanced"
    );
    assert_eq!(state.applied_revision(), Some(revision("db", 10)));

    // The newer candidate still finalizes normally when the runtime rules on it.
    assert!(state.record_rejected_slice(&state.snapshot()));
    assert_eq!(state.accepted_revision(), Some(revision("db", 10)));
}

/// A candidate refused before ANYTHING has been applied must return the gate to
/// no baseline, not pin it to a revision the proxy never served — otherwise a
/// single bad first slice poisons startup and every subsequent fallback.
#[test]
fn a_runtime_rejected_bootstrap_candidate_returns_to_no_baseline() {
    let _overlay_guard = overlay_consumer_guard();
    let state = MeshRuntimeState::new();

    assert!(
        state
            .install_slice(slice_at("v-9000", Some(revision("db", 9000))))
            .installed()
    );
    assert_eq!(state.accepted_revision(), Some(revision("db", 9000)));

    assert!(state.record_rejected_slice(&state.snapshot()));
    assert!(
        state.accepted_revision().is_none(),
        "nothing was ever applied, so there is no baseline to hold"
    );
    assert!(state.applied_revision().is_none());
    assert!(state.revision_diagnostics().accepted.is_none());

    // Bootstrap is open again — including from a lower sequence and from a
    // different ordering domain.
    let recovery = slice_at("v-1", Some(revision("db", 1)));
    assert!(state.install_slice(recovery.clone()).installed());
    state.record_applied_slice(&recovery);
    assert_eq!(state.applied_revision(), Some(revision("db", 1)));
}

/// The commit half has to remember equal-revision replays too: a reconnect
/// replays the CP's initial slice at the unchanged revision and the runtime
/// accepts it with no config delta. If that did not commit, a later rollback
/// would drop to a stale baseline (or to none at all).
#[test]
fn an_equal_revision_replay_commits_the_applied_watermark() {
    let _overlay_guard = overlay_consumer_guard();
    let state = MeshRuntimeState::new();
    let first = slice_at("v-10", Some(revision("db", 10)));
    assert!(state.install_slice(first.clone()).installed());
    state.record_applied_slice(&first);

    let replay = slice_at("v-10-replay", Some(revision("db", 10)));
    assert!(
        state.install_slice(replay.clone()).installed(),
        "an equal revision MUST install — every ordinary reconnect replays one"
    );
    state.record_applied_slice(&replay);
    assert_eq!(state.applied_revision(), Some(revision("db", 10)));
    assert_eq!(state.accepted_revision(), Some(revision("db", 10)));

    // A later runtime rejection rolls back to the replayed generation.
    assert!(
        state
            .install_slice(slice_at("v-50", Some(revision("db", 50))))
            .installed()
    );
    assert!(state.record_rejected_slice(&state.snapshot()));
    assert_eq!(state.accepted_revision(), Some(revision("db", 10)));
}

/// The operator reset clears the APPLIED watermark as well. Leaving it would
/// let the next runtime-refused candidate roll the gate straight back onto the
/// generation the operator just released, silently undoing the reset.
#[test]
fn reset_clears_the_applied_watermark_so_a_rejection_cannot_resurrect_it() {
    let _overlay_guard = overlay_consumer_guard();
    let state = MeshRuntimeState::new();
    let applied = slice_at("v-10", Some(revision("db", 10)));
    assert!(state.install_slice(applied.clone()).installed());
    state.record_applied_slice(&applied);

    let cleared = state
        .reset_accepted_revision()
        .expect("the accepted revision is returned for the audit log");
    assert_eq!(cleared, revision("db", 10));
    assert!(state.accepted_revision().is_none());
    assert!(state.applied_revision().is_none());

    // The store was restored from backup, so the next slice rewinds to a lower
    // sequence and installs on the cleared baseline.
    assert!(
        state
            .install_slice(slice_at("v-3", Some(revision("db", 3))))
            .installed()
    );
    assert!(
        state.record_rejected_slice(&state.snapshot()),
        "the rewound candidate owns the post-reset watermark"
    );
    assert!(
        state.accepted_revision().is_none(),
        "a rejection must not resurrect the pre-reset generation"
    );
}

// ── Diagnostic bounding of control-plane-supplied authorities ──────────────

/// A control-character-bearing authority is refused as malformed at the
/// boundary, so it can never reach the accepted watermark, the reset audit log,
/// or the admin surface. The quarantine record that DOES echo it is sanitized.
#[test]
fn control_character_authorities_are_refused_and_never_reach_a_watermark() {
    let _overlay_guard = overlay_consumer_guard();
    let forged = revision("db\n2026-07-26 WARN forged-by-the-control-plane", 100);
    assert!(!forged.is_well_formed());
    assert_eq!(
        MeshConfigRevision::compare(Some(&revision("db", 10)), Some(&forged)),
        MeshRevisionOrder::Unversioned
    );
    assert_eq!(
        MeshConfigRevision::compare(Some(&forged), Some(&revision("db", 10))),
        MeshRevisionOrder::Bootstrap,
        "a malformed ACCEPTED revision cannot lock the data plane out either"
    );

    let state = MeshRuntimeState::new();
    let applied = slice_at("v-10", Some(revision("db", 10)));
    assert!(state.install_slice(applied.clone()).installed());
    state.record_applied_slice(&applied);

    assert_eq!(
        state
            .install_slice(slice_at("v-forged", Some(forged)))
            .rejection()
            .expect("a malformed authority carries no ordering meaning")
            .reason(),
        MeshRevisionRejectReason::MissingRevision
    );

    let diagnostics = state.revision_diagnostics();
    let quarantined = diagnostics
        .quarantined
        .expect("the refusal is recorded for operators");
    assert!(
        !quarantined.authority.chars().any(char::is_control),
        "the echoed authority must not be able to forge a log line: {:?}",
        quarantined.authority
    );
    assert_eq!(diagnostics.accepted, Some(revision("db", 10)));
    assert_eq!(diagnostics.applied, Some(revision("db", 10)));

    let cleared = state
        .reset_accepted_revision()
        .expect("the accepted revision is returned");
    assert!(!cleared.authority.chars().any(char::is_control));
}

/// Every copy of an authority that LEAVES the gate — diagnostics, the reset
/// response, and the log lines built from them — is length-bounded, while the
/// raw value stays inside for exact ordering.
#[test]
fn output_copies_of_the_authority_are_bounded_but_ordering_stays_exact() {
    let _overlay_guard = overlay_consumer_guard();
    // Well formed (within `MAX_AUTHORITY_LEN`) but longer than the 64-character
    // diagnostic bound.
    let long = revision(&"d".repeat(100), 7);
    assert!(long.is_well_formed());
    let bounded = format!("{}(truncated)", "d".repeat(64));

    let state = MeshRuntimeState::new();
    let applied = slice_at("v-7", Some(long.clone()));
    assert!(state.install_slice(applied.clone()).installed());
    state.record_applied_slice(&applied);

    // Ordering keeps the RAW value: a different authority that shares the
    // first 64 characters must not be mistaken for the accepted one.
    assert_eq!(state.accepted_revision(), Some(long));
    let sibling = revision(&format!("{}x", "d".repeat(99)), 9);
    assert_eq!(
        state
            .install_slice(slice_at("v-9", Some(sibling)))
            .rejection()
            .expect("a distinct authority is a distinct ordering domain")
            .reason(),
        MeshRevisionRejectReason::IncomparableAuthority
    );

    let diagnostics = state.revision_diagnostics();
    assert_eq!(
        diagnostics
            .accepted
            .expect("accepted watermark is reported")
            .authority,
        bounded
    );
    assert_eq!(
        diagnostics
            .applied
            .expect("applied watermark is reported")
            .authority,
        bounded
    );

    let cleared = state
        .reset_accepted_revision()
        .expect("the accepted revision is returned");
    assert_eq!(cleared.authority, bounded);
    assert_eq!(cleared.sequence, 7);
}
