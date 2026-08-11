//! Localized file mesh config source (`FERRUM_MESH_CONFIG_PROTOCOL=file`).
//!
//! Exercises `config_consumer::file_source::load_mesh_slice_from_file`: the
//! document contract (mesh section only, optional `version` stamp), fail-closed
//! validation, and slice-building parity with the CP-side materialization
//! (namespace scoping, version stamping from `loaded_at`).

use std::io::Write;

use ferrum_edge::modes::mesh::config_consumer::file_source::load_mesh_slice_from_file;
use ferrum_edge::modes::mesh::slice::MeshSliceRequest;

fn request_for_namespace(namespace: &str) -> MeshSliceRequest {
    MeshSliceRequest {
        node_id: "file-source-node".to_string(),
        namespace: namespace.to_string(),
        ..MeshSliceRequest::default()
    }
}

fn write_temp(ext: &str, content: &str) -> tempfile::TempPath {
    let mut file = tempfile::Builder::new()
        .suffix(&format!(".{ext}"))
        .tempfile()
        .expect("create temp mesh config");
    file.write_all(content.as_bytes())
        .expect("write temp mesh config");
    file.into_temp_path()
}

const VALID_MESH_YAML: &str = r#"
version: "1"
mesh:
  workloads:
    - spiffe_id: spiffe://cluster.local/ns/ferrum/sa/api
      selector:
        labels:
          app: api
      service_name: api
      addresses: ["10.0.0.5"]
      ports:
        - port: 8080
          protocol: http
      trust_domain: cluster.local
      namespace: ferrum
  services:
    - name: api
      namespace: ferrum
      ports:
        - port: 80
          protocol: http
      workloads:
        - spiffe_id: spiffe://cluster.local/ns/ferrum/sa/api
"#;

#[test]
fn loads_yaml_mesh_document_and_builds_slice() {
    let path = write_temp("yaml", VALID_MESH_YAML);
    let slice = load_mesh_slice_from_file(&path, request_for_namespace("ferrum"))
        .expect("valid mesh document loads");

    assert_eq!(slice.node_id, "file-source-node");
    assert_eq!(slice.namespace, "ferrum");
    assert_eq!(slice.workloads.len(), 1);
    assert_eq!(slice.services.len(), 1);
    assert_eq!(slice.services[0].name, "api");
    assert!(
        !slice.version.is_empty(),
        "slice version must carry the load timestamp"
    );
    chrono::DateTime::parse_from_rfc3339(&slice.version)
        .expect("file-built slice version is the RFC3339 load timestamp");
}

#[test]
fn loads_json_mesh_document() {
    let json = serde_json::json!({
        "mesh": {
            "services": [{
                "name": "api",
                "namespace": "ferrum",
                "ports": [{"port": 80, "protocol": "http"}],
            }],
        }
    });
    let path = write_temp("json", &json.to_string());
    let slice = load_mesh_slice_from_file(&path, request_for_namespace("ferrum"))
        .expect("valid JSON mesh document loads");
    assert_eq!(slice.services.len(), 1);
}

#[test]
fn slice_building_scopes_by_request_namespace() {
    // Namespace scoping happens DP-side for the file source — the same
    // `MeshSlice::from_gateway_config` narrowing the CP applies.
    let path = write_temp("yaml", VALID_MESH_YAML);
    let slice = load_mesh_slice_from_file(&path, request_for_namespace("other"))
        .expect("document loads under a different namespace");
    assert!(
        slice.services.is_empty() && slice.workloads.is_empty(),
        "resources in 'ferrum' must not leak into the 'other' namespace slice"
    );
}

#[test]
fn rejects_gateway_resources_in_mesh_document() {
    let doc = r#"
version: "1"
proxies: []
mesh:
  services: []
"#;
    let path = write_temp("yaml", doc);
    let err = load_mesh_slice_from_file(&path, request_for_namespace("ferrum"))
        .expect_err("gateway resources must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("proxies") && msg.contains("FERRUM_MODE=file"),
        "error must name the offending field and steer to file mode: {msg}"
    );
}

#[test]
fn rejects_document_without_mesh_section() {
    let path = write_temp("yaml", "version: \"1\"\n");
    let err = load_mesh_slice_from_file(&path, request_for_namespace("ferrum"))
        .expect_err("a document without a mesh section must be rejected");
    assert!(err.to_string().contains("mesh"), "{err}");
}

#[test]
fn rejects_unknown_version_stamp() {
    let doc = r#"
version: "999"
mesh:
  services: []
"#;
    let path = write_temp("yaml", doc);
    let err = load_mesh_slice_from_file(&path, request_for_namespace("ferrum"))
        .expect_err("an unknown version stamp must be rejected");
    assert!(err.to_string().contains("version"), "{err}");
}

#[test]
fn rejects_invalid_mesh_fields() {
    // Port 0 fails `validate_mesh_fields` — the same validation the
    // slice-apply task would run; the file source fails it eagerly so startup
    // is fail-closed.
    let doc = r#"
mesh:
  services:
    - name: api
      namespace: ferrum
      ports:
        - port: 0
          protocol: http
"#;
    let path = write_temp("yaml", doc);
    let err = load_mesh_slice_from_file(&path, request_for_namespace("ferrum"))
        .expect_err("invalid mesh fields must be rejected");
    assert!(
        err.to_string().contains("validation failed"),
        "expected a mesh validation error, got: {err}"
    );
}

#[test]
fn missing_file_is_an_error() {
    let err = load_mesh_slice_from_file(
        std::path::Path::new("/nonexistent/ferrum-mesh-config.yaml"),
        request_for_namespace("ferrum"),
    )
    .expect_err("missing file must be an error");
    assert!(err.to_string().contains("not found"), "{err}");
}

#[test]
fn reload_then_load_produces_advancing_versions() {
    // The slice version is the load timestamp: two loads of the same document
    // produce slices that are `content_eq` (so the apply task no-ops) while
    // the version stamp itself advances.
    let path = write_temp("yaml", VALID_MESH_YAML);
    let first = load_mesh_slice_from_file(&path, request_for_namespace("ferrum"))
        .expect("first load succeeds");
    // Two `Utc::now()` stamps in the same instant would compare equal and
    // mask the assertion; force distinct timestamps.
    std::thread::sleep(std::time::Duration::from_millis(2));
    let second = load_mesh_slice_from_file(&path, request_for_namespace("ferrum"))
        .expect("second load succeeds");
    assert!(
        first.content_eq(&second),
        "identical documents must build content-equal slices"
    );
    assert_ne!(
        first.version, second.version,
        "each load stamps its own version"
    );
}

#[test]
fn mesh_file_oversized_sparse_document_is_refused() {
    use ferrum_edge::config::stable_file::MAX_MESH_CONFIG_FILE_BYTES;

    let dir = tempfile::tempdir().unwrap();
    let over = dir.path().join("mesh-over.yaml");
    let file = std::fs::File::create(&over).unwrap();
    file.set_len(MAX_MESH_CONFIG_FILE_BYTES + 1).unwrap();
    drop(file);
    let err =
        load_mesh_slice_from_file(&over, request_for_namespace("ferrum")).expect_err("limit+1");
    let msg = err.to_string();
    assert!(
        msg.contains("maximum supported size is 67108864 bytes"),
        "expected size diagnostic, got: {msg}"
    );
}

#[test]
fn mesh_file_at_documented_ceiling_constant_is_admitted_by_stable_reader() {
    // Full 64 MiB fixtures are covered by `stable_file_tests` at a reduced
    // ceiling; this pins the mesh source to that shared constant/primitive.
    use ferrum_edge::config::stable_file::{
        MAX_MESH_CONFIG_FILE_BYTES, StableFileReadOptions, read_stable_file,
    };

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mesh.yaml");
    std::fs::write(&path, VALID_MESH_YAML).unwrap();
    let options = StableFileReadOptions::new(MAX_MESH_CONFIG_FILE_BYTES, "mesh configuration file");
    read_stable_file(&path, options).expect("valid mesh document under ceiling");
    load_mesh_slice_from_file(&path, request_for_namespace("ferrum")).expect("loads");
}

#[test]
fn unknown_extension_json_object_parses_once_as_json() {
    // Extensionless/unknown paths that start with `{` must take the JSON path
    // without a prior full YAML probe parse.
    let json = serde_json::json!({
        "mesh": {
            "services": [{
                "name": "api",
                "namespace": "ferrum",
                "ports": [{"port": 80, "protocol": "http"}],
            }],
        }
    });
    let mut file = tempfile::Builder::new()
        .suffix(".unknown")
        .tempfile()
        .unwrap();
    write!(file, "{}", json).unwrap();
    let slice = load_mesh_slice_from_file(file.path(), request_for_namespace("ferrum"))
        .expect("JSON-shaped unknown extension");
    assert_eq!(slice.services.len(), 1);
}

#[test]
fn malformed_yaml_fails_without_echoing_document_body() {
    let path = write_temp("yaml", "mesh: [\n  this is not valid\n");
    let err =
        load_mesh_slice_from_file(&path, request_for_namespace("ferrum")).expect_err("malformed");
    let msg = err.to_string();
    assert!(
        msg.contains("invalid mesh configuration document"),
        "got: {msg}"
    );
}

#[cfg(unix)]
#[test]
fn fifo_mesh_path_is_rejected_promptly() {
    let dir = tempfile::tempdir().unwrap();
    let fifo = dir.path().join("mesh.yaml");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("mkfifo");
    assert!(status.success());
    let started = std::time::Instant::now();
    let err = load_mesh_slice_from_file(&fifo, request_for_namespace("ferrum")).expect_err("fifo");
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
    let msg = err.to_string();
    assert!(msg.contains("not a regular file"), "got: {msg}");
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn large_reload_does_not_stall_tokio_heartbeat() {
    use ferrum_edge::config::stable_file::MAX_MESH_CONFIG_FILE_BYTES;
    use ferrum_edge::modes::mesh::config_consumer::file_source::load_mesh_slice_from_file_off_thread;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    // A multi-MiB stable read (two full probes) must run on the blocking pool
    // so a Tokio heartbeat/timer on a core worker keeps advancing.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("large-mesh.yaml");
    let mut body = VALID_MESH_YAML.to_string();
    body.push('\n');
    let target = (8 * 1024 * 1024).min(MAX_MESH_CONFIG_FILE_BYTES as usize);
    let pad = target.saturating_sub(body.len());
    body.push('#');
    if pad > 1 {
        body.push_str(&"x".repeat(pad - 1));
    }
    std::fs::write(&path, &body).unwrap();

    let heartbeat = Arc::new(AtomicBool::new(false));
    let heartbeat_flag = Arc::clone(&heartbeat);
    let ticker = tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            heartbeat_flag.store(true, Ordering::SeqCst);
        }
    });

    let load = tokio::spawn(load_mesh_slice_from_file_off_thread(
        path.clone(),
        request_for_namespace("ferrum"),
    ));

    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while !heartbeat.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("Tokio heartbeat must advance while a large mesh file load runs off-thread");

    let loaded = load.await.expect("join").expect("large mesh loads");
    assert_eq!(loaded.services.len(), 1);
    ticker.abort();
    let _ = ticker.await;
}

#[test]
fn mesh_reload_generation_advances_on_signal_and_stales_inflight_candidate() {
    use ferrum_edge::modes::mesh::config_consumer::file_source::{
        mesh_reload_generation_is_current, record_mesh_reload_request,
    };
    use std::sync::atomic::{AtomicU64, Ordering};

    let latest = AtomicU64::new(0);
    let gen1 = record_mesh_reload_request(&latest);
    assert_eq!(gen1, 1);
    assert!(mesh_reload_generation_is_current(
        gen1,
        latest.load(Ordering::Acquire)
    ));

    // A signal observed during an in-flight load must advance the requested
    // generation immediately so the older candidate cannot install.
    let gen2 = record_mesh_reload_request(&latest);
    assert_eq!(gen2, 2);
    assert!(
        !mesh_reload_generation_is_current(gen1, latest.load(Ordering::Acquire)),
        "in-flight gen1 must be stale once a later signal is observed"
    );
    assert!(mesh_reload_generation_is_current(
        gen2,
        latest.load(Ordering::Acquire)
    ));

    // Coalesced follow-up signals collapse to one newer requested generation.
    let gen3 = record_mesh_reload_request(&latest);
    assert_eq!(gen3, 3);
    assert!(!mesh_reload_generation_is_current(gen2, 3));
    assert!(mesh_reload_generation_is_current(gen3, 3));
    // Exact equality only: a future/out-of-contract generation is not current.
    assert!(!mesh_reload_generation_is_current(4, 3));
}

#[test]
fn simultaneous_shutdown_and_completion_chooses_shutdown_and_does_not_publish() {
    use ferrum_edge::modes::mesh::config_consumer::file_source::{
        MeshReloadSelectReady, mesh_reload_completion_may_publish, mesh_reload_select_priority,
    };

    assert_eq!(
        mesh_reload_select_priority(false, true, true),
        Some(MeshReloadSelectReady::Shutdown),
        "tied shutdown+completion must choose shutdown"
    );
    assert!(!mesh_reload_completion_may_publish(
        true,
        MeshReloadSelectReady::Shutdown
    ));
    assert!(mesh_reload_completion_may_publish(
        true,
        MeshReloadSelectReady::Completion
    ));
    assert!(!mesh_reload_completion_may_publish(
        false,
        MeshReloadSelectReady::Completion
    ));
    assert_eq!(
        mesh_reload_select_priority(true, true, false),
        Some(MeshReloadSelectReady::Hangup)
    );
}

#[test]
fn mesh_local_source_recovery_requires_proxy_accept_and_fences_generations() {
    use ferrum_edge::modes::mesh::config_consumer::file_source::{
        MeshLocalReloadApply, MeshLocalSourceRecovery, apply_mesh_file_reload_candidate,
    };
    use ferrum_edge::modes::mesh::runtime::MeshRuntimeState;
    use ferrum_edge::modes::mesh::slice::MeshSlice;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let path = write_temp("yaml", VALID_MESH_YAML);
    let slice = load_mesh_slice_from_file(&path, request_for_namespace("ferrum")).unwrap();
    let state = MeshRuntimeState::new();
    state.install_slice(slice.clone());
    let flag = Arc::new(AtomicBool::new(false));
    let recovery = MeshLocalSourceRecovery::new(flag.clone());

    // Failure raises sticky health and retains last-good.
    let rejected = apply_mesh_file_reload_candidate(
        &state,
        &recovery,
        load_mesh_slice_from_file(
            std::path::Path::new("/nonexistent/ferrum-mesh-reload.yaml"),
            request_for_namespace("ferrum"),
        ),
    );
    assert_eq!(rejected, MeshLocalReloadApply::Rejected);
    assert!(recovery.is_rejected());
    assert!(
        state
            .snapshot()
            .as_ref()
            .as_ref()
            .unwrap()
            .content_eq(&slice)
    );

    // Valid candidate installs but must NOT clear until proxy accept.
    let recovered = apply_mesh_file_reload_candidate(&state, &recovery, Ok(slice.clone()));
    assert!(matches!(
        recovered,
        MeshLocalReloadApply::Applied | MeshLocalReloadApply::Unchanged
    ));
    assert!(
        recovery.is_rejected(),
        "provisional install_slice must leave config_rejected set"
    );
    assert_ne!(recovery.pending_epoch(), 0);

    // Exact current accepted recovery clears.
    recovery.note_proxy_apply_success(&slice);
    assert!(!recovery.is_rejected());
    assert_eq!(recovery.pending_epoch(), 0);

    // Unchanged recovery also clears only after proxy no-op accept.
    recovery.mark_rejected();
    let unchanged = apply_mesh_file_reload_candidate(&state, &recovery, Ok(slice.clone()));
    assert_eq!(unchanged, MeshLocalReloadApply::Unchanged);
    assert!(recovery.is_rejected());
    recovery.note_proxy_apply_success(&slice);
    assert!(!recovery.is_rejected());

    // Newer failure cancels an older pending success.
    recovery.mark_rejected();
    let older_pending = apply_mesh_file_reload_candidate(&state, &recovery, Ok(slice.clone()));
    assert!(matches!(
        older_pending,
        MeshLocalReloadApply::Applied | MeshLocalReloadApply::Unchanged
    ));
    let older_epoch = recovery.pending_epoch();
    assert_ne!(older_epoch, 0);
    recovery.mark_rejected();
    assert_eq!(recovery.pending_epoch(), 0);
    recovery.note_proxy_apply_success(&slice);
    assert!(
        recovery.is_rejected(),
        "older success must not clear after a newer failure"
    );

    // Unrelated overlay / ordinary activity (different slice content) does not
    // clear a local-source failure.
    recovery.mark_rejected();
    let _ = apply_mesh_file_reload_candidate(&state, &recovery, Ok(slice.clone()));
    let unrelated = MeshSlice {
        version: "unrelated-overlay".to_string(),
        labels: [("k".into(), "v".into())].into(),
        ..slice.clone()
    };
    recovery.note_proxy_apply_success(&unrelated);
    assert!(
        recovery.is_rejected(),
        "unrelated overlay/content must not clear local-source failure"
    );

    // Proxy rejection of the pending recovery stays degraded.
    recovery.mark_rejected();
    let _ = apply_mesh_file_reload_candidate(&state, &recovery, Ok(slice.clone()));
    recovery.note_proxy_apply_rejection(&slice);
    assert!(recovery.is_rejected());
    assert_eq!(recovery.pending_epoch(), 0);
}

/// Rounds per concurrency regression. Each round forces one barrier-aligned
/// interleaving of a stale callback against a newer transition; the asserted
/// invariant holds in EVERY linearization, so a correct handshake can never
/// fail a round while a torn (multi-atomic, check-then-act) handshake loses the
/// invariant as soon as one round lands in its window.
const RECOVERY_RACE_ROUNDS: usize = 512;

#[test]
fn concurrent_newer_rejection_and_stale_success_keep_local_source_health_degraded() {
    use ferrum_edge::modes::mesh::config_consumer::file_source::MeshLocalSourceRecovery;
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, Barrier};

    let path = write_temp("yaml", VALID_MESH_YAML);
    let slice = load_mesh_slice_from_file(&path, request_for_namespace("ferrum")).unwrap();

    // Race A: an older `note_proxy_apply_success` for the pending candidate runs
    // concurrently with a NEWER `mark_rejected`. Both linearizations end
    // degraded:
    //   * rejection first — the now-stale success must not clear;
    //   * success first  — it clears, then the newer rejection raises again.
    // So `config_rejected` is true after every round, and no pending recovery
    // survives. Without one transition authority the success's clear can land
    // after the rejection and health silently reports healthy.
    for round in 0..RECOVERY_RACE_ROUNDS {
        let recovery = MeshLocalSourceRecovery::new(Arc::new(AtomicBool::new(false)));
        recovery.mark_rejected();
        assert!(
            recovery.mark_slice_recovery_pending(&slice).is_some(),
            "round {round}: candidate must become pending"
        );

        let barrier = Arc::new(Barrier::new(2));
        let success = {
            let recovery = Arc::clone(&recovery);
            let barrier = Arc::clone(&barrier);
            let slice = slice.clone();
            std::thread::spawn(move || {
                barrier.wait();
                recovery.note_proxy_apply_success(&slice);
            })
        };
        let rejection = {
            let recovery = Arc::clone(&recovery);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                recovery.mark_rejected();
            })
        };
        success.join().expect("success callback thread");
        rejection.join().expect("rejection thread");

        assert!(
            recovery.is_rejected(),
            "round {round}: a stale success must never clear health after a newer failure"
        );
        assert_eq!(
            recovery.pending_epoch(),
            0,
            "round {round}: a newer failure must leave no pending recovery"
        );
    }
}

#[test]
fn concurrent_stale_rejection_and_newer_candidate_keep_the_newer_recovery() {
    use ferrum_edge::modes::mesh::config_consumer::file_source::MeshLocalSourceRecovery;
    use ferrum_edge::modes::mesh::slice::MeshSlice;
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, Barrier};

    let path = write_temp("yaml", VALID_MESH_YAML);
    let older = load_mesh_slice_from_file(&path, request_for_namespace("ferrum")).unwrap();
    // Distinct CONTENT (not just `version`, which the content digest clears).
    let newer = MeshSlice {
        labels: [("recovery-race".to_string(), "newer".to_string())].into(),
        ..older.clone()
    };

    // Race B: an older `note_proxy_apply_rejection` carrying the OLD pending
    // identity runs concurrently with a NEWER candidate becoming pending. Both
    // linearizations leave the newer recovery outstanding and clearable:
    //   * candidate first — the stale rejection's identity no longer matches
    //     the pending slot, so it cancels nothing;
    //   * rejection first — it cancels the old pending, then the newer
    //     candidate installs its own.
    // A torn handshake tests the old identity and then cancels unconditionally,
    // wiping the newer recovery so it can never clear health again.
    for round in 0..RECOVERY_RACE_ROUNDS {
        let recovery = MeshLocalSourceRecovery::new(Arc::new(AtomicBool::new(false)));
        recovery.mark_rejected();
        assert!(
            recovery.mark_slice_recovery_pending(&older).is_some(),
            "round {round}: older candidate must become pending"
        );

        let barrier = Arc::new(Barrier::new(2));
        let rejection = {
            let recovery = Arc::clone(&recovery);
            let barrier = Arc::clone(&barrier);
            let older = older.clone();
            std::thread::spawn(move || {
                barrier.wait();
                recovery.note_proxy_apply_rejection(&older);
            })
        };
        let candidate = {
            let recovery = Arc::clone(&recovery);
            let barrier = Arc::clone(&barrier);
            let newer = newer.clone();
            std::thread::spawn(move || {
                barrier.wait();
                recovery.mark_slice_recovery_pending(&newer)
            })
        };
        rejection.join().expect("rejection callback thread");
        assert!(
            candidate
                .join()
                .expect("candidate thread")
                .is_some_and(|epoch| epoch != 0),
            "round {round}: the newer candidate must always become pending"
        );

        assert_ne!(
            recovery.pending_epoch(),
            0,
            "round {round}: a stale rejection must not cancel a newer pending recovery"
        );
        // The surviving pending recovery is the NEWER one: accepting exactly it
        // clears sticky health in both linearizations.
        recovery.note_proxy_apply_success(&newer);
        assert!(
            !recovery.is_rejected(),
            "round {round}: proxy acceptance of the newer recovery must clear health"
        );
        assert_eq!(
            recovery.pending_epoch(),
            0,
            "round {round}: the clear consumes the pending recovery"
        );
    }
}

#[test]
fn stock_policy_recovery_pending_until_bound_slice_proxy_accept() {
    use ferrum_edge::modes::mesh::config_consumer::file_source::{
        MeshLocalReloadApply, MeshLocalSourceRecovery,
    };
    use ferrum_edge::modes::mesh::config_consumer::stock_xds_client::{
        StockPolicySnapshot, apply_stock_policy_reload_candidate, load_stock_policy_baseline,
    };
    use ferrum_edge::modes::mesh::slice::MeshSlice;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    const VALID_STOCK_POLICY_YAML: &str = r#"
version: "1"
mesh:
  peer_authentications:
    - name: strict-default
      namespace: ferrum
      mtls_mode: strict
"#;
    let path = write_temp("yaml", VALID_STOCK_POLICY_YAML);
    let baseline = load_stock_policy_baseline(&path).expect("policy baseline");
    let (tx, _rx) =
        tokio::sync::watch::channel(StockPolicySnapshot::initial(Arc::new(baseline.clone())));
    let recovery = MeshLocalSourceRecovery::new(Arc::new(AtomicBool::new(false)));

    let rejected = apply_stock_policy_reload_candidate(
        &tx,
        &recovery,
        load_stock_policy_baseline(std::path::Path::new("/nonexistent/stock-policy.yaml")),
    );
    assert_eq!(rejected, MeshLocalReloadApply::Rejected);
    assert!(recovery.is_rejected());

    let recovered = apply_stock_policy_reload_candidate(&tx, &recovery, Ok(baseline.clone()));
    assert_eq!(recovered, MeshLocalReloadApply::Unchanged);
    assert!(
        recovery.is_rejected(),
        "channel send must not clear config_rejected"
    );
    assert_ne!(recovery.pending_epoch(), 0);

    // Rebuild failure leaves/sets degraded and cancels pending clear.
    recovery.mark_rejected();
    assert_eq!(recovery.pending_epoch(), 0);

    let again = apply_stock_policy_reload_candidate(&tx, &recovery, Ok(baseline));
    assert_eq!(again, MeshLocalReloadApply::Unchanged);
    let bound = MeshSlice {
        version: "stock-recovery".to_string(),
        ..MeshSlice::default()
    };
    let epoch = recovery.pending_epoch();
    recovery.bind_installed_slice_if_policy_recovery(epoch, &bound);
    recovery.note_proxy_apply_success(&bound);
    assert!(!recovery.is_rejected());
}

#[test]
fn stock_policy_recovery_epoch_fences_stale_slice_binding() {
    use ferrum_edge::modes::mesh::config_consumer::file_source::MeshLocalSourceRecovery;
    use ferrum_edge::modes::mesh::slice::MeshSlice;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    let recovery = MeshLocalSourceRecovery::new(Arc::new(AtomicBool::new(false)));
    recovery.mark_rejected();
    let stale_epoch = recovery.begin_policy_recovery();
    let current_epoch = recovery.begin_policy_recovery();
    let stale = MeshSlice {
        labels: [("policy".to_string(), "stale".to_string())].into(),
        ..MeshSlice::default()
    };
    let current = MeshSlice {
        labels: [("policy".to_string(), "current".to_string())].into(),
        ..MeshSlice::default()
    };

    recovery.note_proxy_apply_rejection(&stale);
    assert_eq!(
        recovery.pending_epoch(),
        current_epoch,
        "an older apply rejection must not cancel an unbound newer policy recovery"
    );

    recovery.bind_installed_slice_if_policy_recovery(stale_epoch, &stale);
    recovery.note_proxy_apply_success(&stale);
    assert!(
        recovery.is_rejected(),
        "a stale policy slice must not clear the newer recovery"
    );
    assert_eq!(recovery.pending_epoch(), current_epoch);

    recovery.bind_installed_slice_if_policy_recovery(current_epoch, &current);
    recovery.note_proxy_apply_success(&current);
    assert!(!recovery.is_rejected());
}

#[test]
fn stock_policy_reload_without_consumer_fails_closed() {
    use ferrum_edge::modes::mesh::config::MeshConfig;
    use ferrum_edge::modes::mesh::config_consumer::file_source::{
        MeshLocalReloadApply, MeshLocalSourceRecovery,
    };
    use ferrum_edge::modes::mesh::config_consumer::stock_xds_client::{
        StockPolicySnapshot, apply_stock_policy_reload_candidate,
    };
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    let baseline = MeshConfig::default();
    let (tx, rx) =
        tokio::sync::watch::channel(StockPolicySnapshot::initial(Arc::new(baseline.clone())));
    drop(rx);
    let recovery = MeshLocalSourceRecovery::new(Arc::new(AtomicBool::new(false)));

    let outcome = apply_stock_policy_reload_candidate(&tx, &recovery, Ok(baseline));
    assert_eq!(outcome, MeshLocalReloadApply::Rejected);
    assert!(recovery.is_rejected());
    assert_eq!(
        recovery.pending_epoch(),
        0,
        "an undeliverable policy must not leave a recovery that can later clear"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn off_thread_mesh_and_stock_loaders_keep_tokio_heartbeat_alive() {
    // Behavioral replacement for source-string wiring checks: both off-thread
    // loaders must leave the Tokio runtime free to make progress.
    use ferrum_edge::modes::mesh::config_consumer::file_source::load_mesh_slice_from_file_off_thread;
    use ferrum_edge::modes::mesh::config_consumer::stock_xds_client::load_stock_policy_baseline_off_thread;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let mesh_path = write_temp("yaml", VALID_MESH_YAML);
    let stock_yaml = r#"
version: "1"
mesh:
  peer_authentications:
    - name: strict-default
      namespace: ferrum
      mtls_mode: strict
"#;
    let stock_path = write_temp("yaml", stock_yaml);

    let heartbeat = Arc::new(AtomicBool::new(false));
    let beat = heartbeat.clone();
    let ticker = tokio::spawn(async move {
        loop {
            beat.store(true, Ordering::SeqCst);
            tokio::task::yield_now().await;
        }
    });

    let mesh_load = tokio::spawn(load_mesh_slice_from_file_off_thread(
        mesh_path.to_path_buf(),
        request_for_namespace("ferrum"),
    ));
    let stock_load = tokio::spawn(load_stock_policy_baseline_off_thread(
        stock_path.to_path_buf(),
    ));

    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while !heartbeat.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("Tokio heartbeat must advance while off-thread loads run");

    mesh_load.await.expect("join").expect("mesh load");
    stock_load.await.expect("join").expect("stock load");
    ticker.abort();
    let _ = ticker.await;
}

#[cfg(unix)]
#[test]
fn failed_reload_retains_last_good_slice() {
    use ferrum_edge::modes::mesh::runtime::MeshRuntimeState;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mesh.yaml");
    std::fs::write(&path, VALID_MESH_YAML).unwrap();
    let slice = load_mesh_slice_from_file(&path, request_for_namespace("ferrum")).unwrap();
    let state = MeshRuntimeState::new();
    state.install_slice(slice);
    let before = state
        .snapshot()
        .as_ref()
        .as_ref()
        .cloned()
        .expect("installed");
    assert_eq!(before.services.len(), 1);

    // Replace with invalid content; a subsequent load fails while the installed
    // generation remains the last accepted slice.
    std::fs::write(&path, "mesh: {").unwrap();
    let err = load_mesh_slice_from_file(&path, request_for_namespace("ferrum"))
        .expect_err("invalid reload candidate");
    assert!(
        err.to_string()
            .contains("invalid mesh configuration document")
    );
    let after = state
        .snapshot()
        .as_ref()
        .as_ref()
        .cloned()
        .expect("retained");
    assert!(
        before.content_eq(&after),
        "failed reload must retain the complete prior mesh slice"
    );

    // Recovery without restart.
    std::fs::write(&path, VALID_MESH_YAML).unwrap();
    let recovered = load_mesh_slice_from_file(&path, request_for_namespace("ferrum")).unwrap();
    state.install_slice(recovered);
    assert_eq!(
        state.snapshot().as_ref().as_ref().unwrap().services.len(),
        1
    );
}
