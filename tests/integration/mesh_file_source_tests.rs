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
    let err = load_mesh_slice_from_file(&over, request_for_namespace("ferrum"))
        .expect_err("limit+1");
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
    let err = load_mesh_slice_from_file(&path, request_for_namespace("ferrum"))
        .expect_err("malformed");
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
    let err = load_mesh_slice_from_file(&fifo, request_for_namespace("ferrum"))
        .expect_err("fifo");
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
    let msg = err.to_string();
    assert!(
        msg.contains("not a regular file"),
        "got: {msg}"
    );
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn large_reload_does_not_stall_tokio_heartbeat() {
    use ferrum_edge::config::stable_file::MAX_MESH_CONFIG_FILE_BYTES;
    use ferrum_edge::modes::mesh::config_consumer::file_source::load_mesh_slice_from_file_off_thread;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

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
fn mesh_file_source_uses_spawn_blocking_and_stable_reader() {
    let src = include_str!("../../src/modes/mesh/config_consumer/file_source.rs");
    assert!(
        src.contains("spawn_blocking"),
        "SIGHUP reload must isolate filesystem/parse work on spawn_blocking"
    );
    assert!(
        src.contains("read_stable_file"),
        "mesh file source must use the shared stable-file primitive"
    );
    assert!(
        src.contains("pending_follow_up"),
        "rapid SIGHUP delivery must coalesce into at most one follow-up load"
    );
    assert!(
        !src.contains("std::fs::read_to_string"),
        "mesh file source must not use unbounded read_to_string"
    );
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
    assert!(err.to_string().contains("invalid mesh configuration document"));
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
