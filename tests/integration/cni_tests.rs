//! Integration tests for the CNI plugin → node-agent UDS path.
//!
//! These tests exercise the full wire round-trip end-to-end:
//!
//!     ferrum-cni client      ──▶  UDS  ──▶      node-agent CNI server
//!     (blocking sync client)        (length-prefixed JSON)
//!
//! Most tests drive the same `cni::client::send_rpc` API the binary uses.
//! That keeps the tests fast while still proving the UDS framing. One
//! targeted test invokes the standalone `ferrum-cni` binary to verify
//! kubelet-visible exit/status behavior.
//!
//! Each test:
//! 1. Builds a tokio runtime + a single oneshot worker that drains the
//!    server's `mpsc<CniWorkItem>` queue with a deterministic
//!    [`CniRpcResponse`].
//! 2. Spawns the [`spawn_cni_listener`] task on a temp UDS.
//! 3. Sends one or more synthetic CNI RPC requests via the blocking
//!    client from a spawn-blocking task (so we don't block the tokio
//!    runtime), and asserts the responses and the queued items.
//!
//! We exercise both `ferrum-cni` happy paths (ADD / DEL idempotent
//! round-trips) and one error path (server replies with `Error` →
//! `send_rpc` decodes it correctly).

use std::collections::HashSet;
use std::convert::Infallible;
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dashmap::DashMap;
use ferrum_edge::_test_support::{
    CNI_STATUS_KUBE_PROBE_TIMEOUT, apply_cni_request_with_kube_metadata_for_test,
};
use ferrum_edge::capture::{CaptureConfig, CaptureMode};
use ferrum_edge::cni::client::send_rpc;
use ferrum_edge::cni::rpc::{CniRpcRequest, CniRpcResponse, RpcVerb};
use ferrum_edge::ebpf::{
    CaptureContract, FallbackMode, MockEbpfBackend, NodeAgentMetrics, PodAttachmentState,
};
use ferrum_edge::modes::node_agent::NodeAgentConfig;
use ferrum_edge::modes::node_agent_cni_server::{cni_work_channel, spawn_cni_listener};
use http::{Method, Request, Response, StatusCode};
use kube::Client;
use kube::client::Body;
use serde_json::json;
use tempfile::tempdir;
use tokio::sync::{oneshot, watch};
use tower::service_fn;

/// Build a minimal RPC request with the given verb and a stable pod
/// identity so tests don't repeat 6 fields each.
fn build_request(verb: RpcVerb) -> CniRpcRequest {
    CniRpcRequest {
        verb,
        network_name: "ferrum-mesh-chain".to_string(),
        pod_namespace: "demo".to_string(),
        pod_name: "alpha".to_string(),
        pod_uid: Some("uid-1".to_string()),
        container_id: "ctr-1".to_string(),
        ifname: Some("eth0".to_string()),
        netns_path: Some("/var/run/netns/cni-1".to_string()),
        args: std::collections::HashMap::new(),
        valid_attachments: Vec::new(),
    }
}

fn run_ferrum_cni_gc(stdin_config: serde_json::Value) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ferrum-cni"))
        .env("CNI_COMMAND", "GC")
        .env("CNI_PATH", "/opt/cni/bin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ferrum-cni");
    child
        .stdin
        .as_mut()
        .expect("stdin pipe")
        .write_all(stdin_config.to_string().as_bytes())
        .expect("write stdin");
    child.wait_with_output().expect("wait ferrum-cni")
}

/// Wait until the async `spawn_cni_listener` task has published a connectable
/// UDS. `Path::exists` alone is insufficient: the listener binds in a private
/// staging directory and atomically renames into place, so the pathname can lag
/// under runner load while ferrum-cni would fail the invocation.
async fn wait_for_cni_listener_ready(socket_path: &std::path::Path) {
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if tokio::net::UnixStream::connect(socket_path).await.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;

    if result.is_err() {
        panic!(
            "CNI listener socket {:?} did not become connectable within 5s",
            socket_path
        );
    }
}

fn run_ferrum_cni_status(stdin_config: serde_json::Value) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ferrum-cni"))
        .env("CNI_COMMAND", "STATUS")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ferrum-cni");
    child
        .stdin
        .as_mut()
        .expect("stdin pipe")
        .write_all(stdin_config.to_string().as_bytes())
        .expect("write stdin");
    child.wait_with_output().expect("wait ferrum-cni")
}

/// Drive one synthetic CNI ADD round-trip: client sends the framed
/// request, listener task accepts the connection, work item arrives in
/// the queue, a stub "main loop" replies `Ok`, response wire-encodes
/// back through the same socket.
#[tokio::test]
async fn cni_add_round_trip_returns_ok() {
    let dir = tempdir().expect("tempdir");
    let socket_path = dir.path().join("agent.sock");
    let socket_path_str = socket_path.to_string_lossy().to_string();
    let metrics = Arc::new(NodeAgentMetrics::default());
    let (work_tx, mut work_rx) = cni_work_channel();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Stand-in "main loop": drain one work item, reply `Ok`, then exit.
    // This mirrors `process_cni_work_item` in `node_agent.rs` without
    // dragging in the full EbpfBackend.
    let drained = tokio::spawn(async move {
        let work = work_rx.recv().await.expect("work item arrives");
        assert_eq!(work.request.verb, RpcVerb::Add);
        assert_eq!(work.request.pod_namespace, "demo");
        assert_eq!(work.request.pod_name, "alpha");
        assert_eq!(work.request.pod_uid.as_deref(), Some("uid-1"));
        let _ = work.respond.send(CniRpcResponse::Ok);
    });

    let listener = spawn_cni_listener(
        socket_path_str.clone(),
        work_tx,
        metrics.clone(),
        shutdown_rx,
    );

    // Give the listener a moment to bind. The binary client is
    // blocking, so we drive it on a spawn-blocking thread to keep the
    // tokio runtime free for the listener / drainer tasks.
    let resp = tokio::task::spawn_blocking(move || {
        // Tight retry loop: listener task is async; the socket file
        // appears milliseconds after `spawn_cni_listener` returns.
        let mut last_err = None;
        for _ in 0..50 {
            match send_rpc(
                &socket_path_str,
                &build_request(RpcVerb::Add),
                Duration::from_secs(2),
            ) {
                Ok(resp) => return Ok::<_, String>(resp),
                Err(err) => {
                    last_err = Some(format!("{err}"));
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        }
        Err(last_err.unwrap_or_else(|| "no error captured".to_string()))
    })
    .await
    .expect("blocking task joined")
    .expect("client RPC eventually succeeds");
    assert_eq!(resp, CniRpcResponse::Ok);

    drained.await.expect("drainer joined");
    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(2), listener).await;
}

/// CNI DEL idempotency: send DEL twice; both round-trips return Ok and
/// the listener delivers two distinct work items to the queue.
#[tokio::test]
async fn cni_del_round_trip_is_idempotent() {
    let dir = tempdir().expect("tempdir");
    let socket_path = dir.path().join("agent.sock");
    let socket_path_str = socket_path.to_string_lossy().to_string();
    let metrics = Arc::new(NodeAgentMetrics::default());
    let (work_tx, mut work_rx) = cni_work_channel();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Drain two work items, reply Ok to both — that is the contract for
    // an idempotent DEL (kubelet may retry).
    let drained = tokio::spawn(async move {
        for expected_idx in 0..2 {
            let work = work_rx
                .recv()
                .await
                .unwrap_or_else(|| panic!("work item #{expected_idx} missing"));
            assert_eq!(work.request.verb, RpcVerb::Del);
            let _ = work.respond.send(CniRpcResponse::Ok);
        }
    });

    let listener = spawn_cni_listener(
        socket_path_str.clone(),
        work_tx,
        metrics.clone(),
        shutdown_rx,
    );

    let socket_for_client = socket_path_str.clone();
    let responses = tokio::task::spawn_blocking(move || {
        let mut out = Vec::with_capacity(2);
        for _ in 0..2 {
            // Same retry approach as the ADD test — listener bind is
            // asynchronous relative to the client.
            let mut last_err = None;
            let mut sent = None;
            for _ in 0..50 {
                match send_rpc(
                    &socket_for_client,
                    &build_request(RpcVerb::Del),
                    Duration::from_secs(2),
                ) {
                    Ok(resp) => {
                        sent = Some(resp);
                        break;
                    }
                    Err(err) => {
                        last_err = Some(format!("{err}"));
                        std::thread::sleep(Duration::from_millis(20));
                    }
                }
            }
            out.push(
                sent.ok_or_else(|| last_err.unwrap_or_else(|| "no error captured".to_string()))?,
            );
        }
        Ok::<_, String>(out)
    })
    .await
    .expect("blocking task joined")
    .expect("client RPCs succeed");
    assert_eq!(responses.len(), 2);
    assert_eq!(responses[0], CniRpcResponse::Ok);
    assert_eq!(responses[1], CniRpcResponse::Ok);

    drained.await.expect("drainer joined");
    // The CNI server records `success` outcomes for both ADD/DEL
    // verbs — this proves the metric wiring is reachable end-to-end,
    // not just unit-test stubbed.
    let snapshot = metrics.snapshot();
    assert_eq!(
        snapshot.cni_calls[ferrum_edge::ebpf::CniCallVerb::Del as usize]
            [ferrum_edge::ebpf::CniCallOutcome::Success as usize],
        2,
        "expected two DEL successes in metrics; got snapshot {snapshot:?}"
    );
    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(2), listener).await;
}

/// Error path: stub main loop replies with an `Error` variant — the
/// blocking client decodes it and surfaces it to the binary as a retryable
/// CNI error (code 11).
#[tokio::test]
async fn cni_round_trip_surfaces_main_loop_error() {
    let dir = tempdir().expect("tempdir");
    let socket_path = dir.path().join("agent.sock");
    let socket_path_str = socket_path.to_string_lossy().to_string();
    let metrics = Arc::new(NodeAgentMetrics::default());
    let (work_tx, mut work_rx) = cni_work_channel();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let drained = tokio::spawn(async move {
        let work = work_rx.recv().await.expect("work item arrives");
        let _ = work.respond.send(CniRpcResponse::Error {
            reason: "backend exploded".to_string(),
        });
    });

    let listener = spawn_cni_listener(
        socket_path_str.clone(),
        work_tx,
        metrics.clone(),
        shutdown_rx,
    );

    let resp = tokio::task::spawn_blocking(move || {
        let mut last_err = None;
        for _ in 0..50 {
            match send_rpc(
                &socket_path_str,
                &build_request(RpcVerb::Check),
                Duration::from_secs(2),
            ) {
                Ok(resp) => return Ok::<_, String>(resp),
                Err(err) => {
                    last_err = Some(format!("{err}"));
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        }
        Err(last_err.unwrap_or_else(|| "no error captured".to_string()))
    })
    .await
    .expect("blocking task joined")
    .expect("client RPC eventually succeeds");
    match resp {
        CniRpcResponse::Error { reason } => assert!(
            reason.contains("backend exploded"),
            "expected pass-through error reason, got: {reason}"
        ),
        other => panic!("expected Error variant, got {other:?}"),
    }

    drained.await.expect("drainer joined");
    let snapshot = metrics.snapshot();
    assert_eq!(
        snapshot.cni_calls[ferrum_edge::ebpf::CniCallVerb::Check as usize]
            [ferrum_edge::ebpf::CniCallOutcome::Error as usize],
        1,
        "expected one CHECK error in metrics"
    );
    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(2), listener).await;
}

/// Binary-level behavior: a rejected CHECK must fail the CNI invocation
/// so kubelet can detect that the pod is not currently enrolled.
#[tokio::test]
async fn ferrum_cni_binary_check_rejection_exits_nonzero() {
    let dir = tempdir().expect("tempdir");
    let socket_path = dir.path().join("agent.sock");
    let socket_path_str = socket_path.to_string_lossy().to_string();
    let metrics = Arc::new(NodeAgentMetrics::default());
    let (work_tx, mut work_rx) = cni_work_channel();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let drained = tokio::spawn(async move {
        let work = work_rx.recv().await.expect("work item arrives");
        assert_eq!(work.request.verb, RpcVerb::Check);
        let _ = work.respond.send(CniRpcResponse::Rejected {
            reason: "pod not currently enrolled".to_string(),
        });
    });

    let listener = spawn_cni_listener(
        socket_path_str.clone(),
        work_tx,
        metrics.clone(),
        shutdown_rx,
    );

    wait_for_cni_listener_ready(&socket_path).await;

    let output = tokio::task::spawn_blocking(move || {
        let stdin_config = serde_json::json!({
            "cniVersion": "0.4.0",
            "name": "ferrum-mesh-chain",
            "type": "ferrum-cni",
            "ferrum": {
                "socketPath": socket_path_str
            },
            "prevResult": {
                "interfaces": [],
                "ips": []
            }
        })
        .to_string();

        let mut child = Command::new(env!("CARGO_BIN_EXE_ferrum-cni"))
            .env("CNI_COMMAND", "CHECK")
            .env("CNI_CONTAINERID", "ctr-1")
            .env("CNI_NETNS", "/var/run/netns/cni-1")
            .env("CNI_IFNAME", "eth0")
            .env(
                "CNI_ARGS",
                "K8S_POD_NAMESPACE=demo;K8S_POD_NAME=alpha;K8S_POD_UID=uid-1",
            )
            .env("CNI_PATH", "/opt/cni/bin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn ferrum-cni");
        child
            .stdin
            .as_mut()
            .expect("stdin pipe")
            .write_all(stdin_config.as_bytes())
            .expect("write stdin");
        child.wait_with_output().expect("wait ferrum-cni")
    })
    .await
    .expect("blocking task joined");

    assert!(
        !output.status.success(),
        "CHECK rejection must fail CNI CHECK, stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let payload: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("CNI error JSON should parse");
    assert_eq!(payload["code"], 12);
    assert!(
        payload["msg"]
            .as_str()
            .is_some_and(|msg| msg.contains("pod not currently enrolled")),
        "unexpected payload: {payload}"
    );

    drained.await.expect("drainer joined");
    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(2), listener).await;
}

/// GC wire round-trip: valid attachments reach the main-loop work item and
/// an Ok reply maps to a success metric on the `gc` verb.
#[tokio::test]
async fn cni_gc_round_trip_forwards_valid_attachments() {
    use ferrum_edge::cni::spec::CniValidAttachment;

    let dir = tempdir().expect("tempdir");
    let socket_path = dir.path().join("agent.sock");
    let socket_path_str = socket_path.to_string_lossy().to_string();
    let metrics = Arc::new(NodeAgentMetrics::default());
    let (work_tx, mut work_rx) = cni_work_channel();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let drained = tokio::spawn(async move {
        let work = work_rx.recv().await.expect("work item arrives");
        assert_eq!(work.request.verb, RpcVerb::Gc);
        assert_eq!(work.request.valid_attachments.len(), 1);
        assert_eq!(work.request.valid_attachments[0].container_id, "ctr-live");
        assert_eq!(work.request.valid_attachments[0].ifname, "eth0");
        let _ = work.respond.send(CniRpcResponse::Ok);
    });

    let listener = spawn_cni_listener(
        socket_path_str.clone(),
        work_tx,
        metrics.clone(),
        shutdown_rx,
    );

    let resp = tokio::task::spawn_blocking(move || {
        let req = CniRpcRequest {
            verb: RpcVerb::Gc,
            network_name: "ferrum-mesh-chain".to_string(),
            pod_namespace: String::new(),
            pod_name: String::new(),
            pod_uid: None,
            container_id: String::new(),
            ifname: None,
            netns_path: None,
            args: std::collections::HashMap::new(),
            valid_attachments: vec![CniValidAttachment {
                container_id: "ctr-live".to_string(),
                ifname: "eth0".to_string(),
            }],
        };
        let mut last_err = None;
        for _ in 0..50 {
            match send_rpc(&socket_path_str, &req, Duration::from_secs(2)) {
                Ok(resp) => return Ok::<_, String>(resp),
                Err(err) => {
                    last_err = Some(format!("{err}"));
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        }
        Err(last_err.unwrap_or_else(|| "no error captured".to_string()))
    })
    .await
    .expect("blocking task joined")
    .expect("client RPC eventually succeeds");
    assert_eq!(resp, CniRpcResponse::Ok);

    drained.await.expect("drainer joined");
    let snapshot = metrics.snapshot();
    assert_eq!(
        snapshot.cni_calls[ferrum_edge::ebpf::CniCallVerb::Gc as usize]
            [ferrum_edge::ebpf::CniCallOutcome::Success as usize],
        1,
        "expected one GC success in metrics"
    );
    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(2), listener).await;
}

/// Binary-level VERSION negotiation advertises CNI 1.1.0 (GC support).
#[tokio::test]
async fn ferrum_cni_binary_version_advertises_1_1() {
    let output = tokio::task::spawn_blocking(|| {
        Command::new(env!("CARGO_BIN_EXE_ferrum-cni"))
            .env("CNI_COMMAND", "VERSION")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("run ferrum-cni VERSION")
    })
    .await
    .expect("blocking task joined");

    assert!(
        output.status.success(),
        "VERSION must succeed, stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let payload: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("VERSION JSON should parse");
    let supported = payload["supportedVersions"]
        .as_array()
        .expect("supportedVersions array");
    assert!(
        supported.iter().any(|v| v.as_str() == Some("1.1.0")),
        "expected 1.1.0 in supportedVersions: {payload}"
    );
}

/// GC on a pre-1.1 configuration must fail closed with unsupported version.
#[tokio::test]
async fn ferrum_cni_binary_gc_rejects_pre_1_1_version() {
    let output = tokio::task::spawn_blocking(|| {
        let stdin_config = serde_json::json!({
            "cniVersion": "1.0.0",
            "name": "ferrum-mesh-chain",
            "type": "ferrum-cni",
            "cni.dev/valid-attachments": []
        })
        .to_string();
        let mut child = Command::new(env!("CARGO_BIN_EXE_ferrum-cni"))
            .env("CNI_COMMAND", "GC")
            .env("CNI_PATH", "/opt/cni/bin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn ferrum-cni");
        child
            .stdin
            .as_mut()
            .expect("stdin pipe")
            .write_all(stdin_config.as_bytes())
            .expect("write stdin");
        child.wait_with_output().expect("wait ferrum-cni")
    })
    .await
    .expect("blocking task joined");

    assert!(
        !output.status.success(),
        "GC on 1.0.0 must fail closed, stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let payload: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("CNI error JSON should parse");
    assert_eq!(payload["code"], 1);
}

/// Omitting the required CNI 1.1 valid-attachment field must not collapse to an
/// authoritative empty set.
#[tokio::test]
async fn ferrum_cni_binary_gc_rejects_omitted_valid_attachment_set() {
    let output = tokio::task::spawn_blocking(|| {
        run_ferrum_cni_gc(serde_json::json!({
            "cniVersion": "1.1.0",
            "name": "ferrum-mesh-chain",
            "type": "ferrum-cni"
        }))
    })
    .await
    .expect("blocking task joined");

    assert!(!output.status.success());
    let payload: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("CNI error JSON should parse");
    assert_eq!(payload["code"], 7);
    assert!(
        payload["msg"]
            .as_str()
            .is_some_and(|message| message.contains("cni.dev/valid-attachments")),
        "unexpected payload: {payload}"
    );
}

/// The non-standard spelling previously accepted by Ferrum is a reserved-key
/// misspelling, not a compatibility alias for the CNI 1.1 wire field.
#[tokio::test]
async fn ferrum_cni_binary_gc_rejects_nonstandard_valid_attachments_key() {
    let output = tokio::task::spawn_blocking(|| {
        run_ferrum_cni_gc(serde_json::json!({
            "cniVersion": "1.1.0",
            "name": "ferrum-mesh-chain",
            "type": "ferrum-cni",
            "cni.dev/attachments": []
        }))
    })
    .await
    .expect("blocking task joined");

    assert!(!output.status.success());
    let payload: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("CNI error JSON should parse");
    assert_eq!(payload["code"], 7);
    assert!(
        payload["msg"]
            .as_str()
            .is_some_and(|message| message.contains("reserved cni.dev/")),
        "unexpected payload: {payload}"
    );
}

#[test]
fn cni_rpc_boundary_rejects_cross_verb_paths_and_identifiers() {
    use ferrum_edge::cni::spec::CniValidAttachment;

    let valid_gc = CniRpcRequest {
        verb: RpcVerb::Gc,
        network_name: "ferrum-mesh-chain".to_string(),
        pod_namespace: String::new(),
        pod_name: String::new(),
        pod_uid: None,
        container_id: String::new(),
        ifname: None,
        netns_path: None,
        args: std::collections::HashMap::new(),
        valid_attachments: vec![CniValidAttachment {
            container_id: "ctr-live".to_string(),
            ifname: "eth0".to_string(),
        }],
    };
    assert!(valid_gc.validate().is_ok());

    let mut cross_verb = valid_gc.clone();
    cross_verb.pod_name = "another-pod".to_string();
    assert!(cross_verb.validate().is_err());

    let mut unsafe_id = valid_gc.clone();
    unsafe_id.valid_attachments[0].container_id = "../escape".to_string();
    assert!(unsafe_id.validate().is_err());

    let mut unsafe_network = valid_gc;
    unsafe_network.network_name = "../../other-network".to_string();
    assert!(unsafe_network.validate().is_err());

    let mut unsafe_path = build_request(RpcVerb::Add);
    unsafe_path.netns_path = Some("/var/run/netns/../host".to_string());
    assert!(unsafe_path.validate().is_err());

    let mut oversized_args = build_request(RpcVerb::Add);
    oversized_args.args = (0..65)
        .map(|index| (format!("ARG_{index}"), "value".to_string()))
        .collect();
    assert!(oversized_args.validate().is_err());
}

#[test]
fn cni_args_boundary_accepts_valid_identity_and_one_trailing_delimiter() {
    let args = ferrum_edge::cni::spec::ingest_cni_args(
        "IgnoreUnknown=1;K8S_POD_NAMESPACE=demo;K8S_POD_NAME=alpha;",
    )
    .expect("valid CNI_ARGS with a trailing delimiter");
    assert_eq!(args.get("IGNOREUNKNOWN").map(String::as_str), Some("1"));
    assert_eq!(
        args.get("K8S_POD_NAMESPACE").map(String::as_str),
        Some("demo")
    );
    assert_eq!(args.get("K8S_POD_NAME").map(String::as_str), Some("alpha"));
}

#[test]
fn cni_args_boundary_rejects_malformed_tokens_without_echoing_them() {
    for (raw, hostile_fragment) in [
        ("K8S_POD_NAME=alpha;secret-token", "secret-token"),
        ("=secret-value", "secret-value"),
        ("BAD KEY=secret-value", "BAD KEY"),
        (" K8S_POD_NAME=secret-value", "secret-value"),
        ("K8S_POD_NAME=alpha;;K8S_POD_NAMESPACE=demo", ";;"),
    ] {
        let err = ferrum_edge::cni::spec::ingest_cni_args(raw)
            .expect_err("malformed CNI_ARGS must fail closed");
        let message = err.to_string();
        assert!(
            message.contains("CNI_ARGS"),
            "expected sanitized boundary error, got: {message}"
        );
        assert!(
            !message.contains(hostile_fragment),
            "boundary error must not echo malformed token contents: {message}"
        );
    }
}

/// Binary-level GC against a live node-agent socket succeeds with empty stdout.
#[tokio::test]
async fn ferrum_cni_binary_gc_exits_zero_on_ok() {
    let dir = tempdir().expect("tempdir");
    let socket_path = dir.path().join("agent.sock");
    let socket_path_str = socket_path.to_string_lossy().to_string();
    let metrics = Arc::new(NodeAgentMetrics::default());
    let (work_tx, mut work_rx) = cni_work_channel();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let drained = tokio::spawn(async move {
        let work = work_rx.recv().await.expect("work item arrives");
        assert_eq!(work.request.verb, RpcVerb::Gc);
        assert!(
            work.request.valid_attachments.is_empty(),
            "an explicitly empty authoritative set must reach reconciliation"
        );
        let _ = work.respond.send(CniRpcResponse::Ok);
    });

    let listener = spawn_cni_listener(
        socket_path_str.clone(),
        work_tx,
        metrics.clone(),
        shutdown_rx,
    );

    wait_for_cni_listener_ready(&socket_path).await;

    let output = tokio::task::spawn_blocking(move || {
        let stdin_config = serde_json::json!({
            "cniVersion": "1.1.0",
            "name": "ferrum-mesh-chain",
            "type": "ferrum-cni",
            "ferrum": { "socketPath": socket_path_str },
            "cni.dev/valid-attachments": []
        })
        .to_string();

        let mut child = Command::new(env!("CARGO_BIN_EXE_ferrum-cni"))
            .env("CNI_COMMAND", "GC")
            .env("CNI_PATH", "/opt/cni/bin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn ferrum-cni");
        child
            .stdin
            .as_mut()
            .expect("stdin pipe")
            .write_all(stdin_config.as_bytes())
            .expect("write stdin");
        child.wait_with_output().expect("wait ferrum-cni")
    })
    .await
    .expect("blocking task joined");

    assert!(
        output.status.success(),
        "GC success must exit 0, stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stdout.is_empty(),
        "GC success must emit no stdout payload"
    );

    drained.await.expect("drainer joined");
    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(2), listener).await;
}

/// STATUS wire round-trip: readiness probe reaches the main-loop work item
/// without attachment fields and records a `status` success metric.
#[tokio::test]
async fn cni_status_round_trip_forwards_without_attachment_fields() {
    let dir = tempdir().expect("tempdir");
    let socket_path = dir.path().join("agent.sock");
    let socket_path_str = socket_path.to_string_lossy().to_string();
    let metrics = Arc::new(NodeAgentMetrics::default());
    let (work_tx, mut work_rx) = cni_work_channel();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let drained = tokio::spawn(async move {
        let work = work_rx.recv().await.expect("work item arrives");
        assert_eq!(work.request.verb, RpcVerb::Status);
        assert!(work.request.pod_namespace.is_empty());
        assert!(work.request.pod_name.is_empty());
        assert!(work.request.pod_uid.is_none());
        assert!(work.request.container_id.is_empty());
        assert!(work.request.ifname.is_none());
        assert!(work.request.netns_path.is_none());
        assert!(work.request.args.is_empty());
        assert!(work.request.valid_attachments.is_empty());
        let _ = work.respond.send(CniRpcResponse::Ok);
    });

    let listener = spawn_cni_listener(
        socket_path_str.clone(),
        work_tx,
        metrics.clone(),
        shutdown_rx,
    );

    let resp = tokio::task::spawn_blocking(move || {
        let req = CniRpcRequest {
            verb: RpcVerb::Status,
            network_name: "ferrum-mesh-chain".to_string(),
            pod_namespace: String::new(),
            pod_name: String::new(),
            pod_uid: None,
            container_id: String::new(),
            ifname: None,
            netns_path: None,
            args: std::collections::HashMap::new(),
            valid_attachments: Vec::new(),
        };
        let mut last_err = None;
        for _ in 0..50 {
            match send_rpc(&socket_path_str, &req, Duration::from_secs(2)) {
                Ok(resp) => return Ok::<_, String>(resp),
                Err(err) => {
                    last_err = Some(format!("{err}"));
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        }
        Err(last_err.unwrap_or_else(|| "no error captured".to_string()))
    })
    .await
    .expect("blocking task joined")
    .expect("client RPC eventually succeeds");
    assert_eq!(resp, CniRpcResponse::Ok);

    drained.await.expect("drainer joined");
    let snapshot = metrics.snapshot();
    assert_eq!(
        snapshot.cni_calls[ferrum_edge::ebpf::CniCallVerb::Status as usize]
            [ferrum_edge::ebpf::CniCallOutcome::Success as usize],
        1,
        "expected one STATUS success in metrics"
    );
    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(2), listener).await;
}

/// STATUS on a pre-1.1 configuration must fail closed with unsupported version.
#[tokio::test]
async fn ferrum_cni_binary_status_rejects_pre_1_1_version() {
    let output = tokio::task::spawn_blocking(|| {
        run_ferrum_cni_status(serde_json::json!({
            "cniVersion": "1.0.0",
            "name": "ferrum-mesh-chain",
            "type": "ferrum-cni"
        }))
    })
    .await
    .expect("blocking task joined");

    assert!(
        !output.status.success(),
        "STATUS on 1.0.0 must fail closed, stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let payload: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("CNI error JSON should parse");
    assert_eq!(payload["code"], 1);
}

/// Attachment-specific reserved fields are malformed on STATUS.
#[tokio::test]
async fn ferrum_cni_binary_status_rejects_attachment_fields() {
    let output = tokio::task::spawn_blocking(|| {
        run_ferrum_cni_status(serde_json::json!({
            "cniVersion": "1.1.0",
            "name": "ferrum-mesh-chain",
            "type": "ferrum-cni",
            "cni.dev/valid-attachments": []
        }))
    })
    .await
    .expect("blocking task joined");

    assert!(!output.status.success());
    let payload: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("CNI error JSON should parse");
    assert_eq!(payload["code"], 7);
    assert!(
        payload["msg"]
            .as_str()
            .is_some_and(|message| message.contains("cni.dev/valid-attachments")),
        "unexpected payload: {payload}"
    );
}

/// Reserved cni.dev/ misspellings are rejected on STATUS without echoing them.
#[tokio::test]
async fn ferrum_cni_binary_status_rejects_reserved_cni_dev_keys() {
    let output = tokio::task::spawn_blocking(|| {
        run_ferrum_cni_status(serde_json::json!({
            "cniVersion": "1.1.0",
            "name": "ferrum-mesh-chain",
            "type": "ferrum-cni",
            "cni.dev/secret-token": "should-not-echo"
        }))
    })
    .await
    .expect("blocking task joined");

    assert!(!output.status.success());
    let payload: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("CNI error JSON should parse");
    assert_eq!(payload["code"], 7);
    let message = payload["msg"].as_str().unwrap_or_default();
    assert!(
        message.contains("reserved cni.dev/"),
        "unexpected payload: {payload}"
    );
    assert!(
        !message.contains("should-not-echo"),
        "STATUS error must not echo reserved-field contents: {message}"
    );
}

/// Missing node-agent socket maps to CNI STATUS code 50 without path echoing.
#[tokio::test]
async fn ferrum_cni_binary_status_unavailable_when_socket_missing() {
    let dir = tempdir().expect("tempdir");
    let missing_socket = dir.path().join("missing-agent.sock");
    let missing_socket_string = missing_socket.to_string_lossy().into_owned();
    let requested_socket = missing_socket_string.clone();
    let output = tokio::task::spawn_blocking(move || {
        run_ferrum_cni_status(serde_json::json!({
            "cniVersion": "1.1.0",
            "name": "ferrum-mesh-chain",
            "type": "ferrum-cni",
            "ferrum": { "socketPath": requested_socket }
        }))
    })
    .await
    .expect("blocking task joined");

    assert!(!output.status.success());
    let payload: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("CNI error JSON should parse");
    assert_eq!(payload["code"], 50);
    let message = payload["msg"].as_str().unwrap_or_default();
    assert!(
        message.contains("not available") || message.contains("unavailable"),
        "unexpected payload: {payload}"
    );
    assert!(
        !message.contains(missing_socket_string.as_str()),
        "STATUS unavailable error must not echo the socket path: {message}"
    );
}

/// Node-agent not-ready replies map to CNI STATUS code 50.
#[tokio::test]
async fn ferrum_cni_binary_status_not_ready_maps_to_code_50() {
    let dir = tempdir().expect("tempdir");
    let socket_path = dir.path().join("agent.sock");
    let socket_path_str = socket_path.to_string_lossy().to_string();
    let metrics = Arc::new(NodeAgentMetrics::default());
    let (work_tx, mut work_rx) = cni_work_channel();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let drained = tokio::spawn(async move {
        let work = work_rx.recv().await.expect("work item arrives");
        assert_eq!(work.request.verb, RpcVerb::Status);
        let _ = work.respond.send(CniRpcResponse::Error {
            reason: "node-agent initial pod sync is incomplete; not ready for ADD".to_string(),
        });
    });

    let listener = spawn_cni_listener(
        socket_path_str.clone(),
        work_tx,
        metrics.clone(),
        shutdown_rx,
    );

    wait_for_cni_listener_ready(&socket_path).await;

    let output = tokio::task::spawn_blocking(move || {
        run_ferrum_cni_status(serde_json::json!({
            "cniVersion": "1.1.0",
            "name": "ferrum-mesh-chain",
            "type": "ferrum-cni",
            "ferrum": { "socketPath": socket_path_str }
        }))
    })
    .await
    .expect("blocking task joined");

    assert!(!output.status.success());
    let payload: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("CNI error JSON should parse");
    assert_eq!(payload["code"], 50);
    let message = payload["msg"].as_str().unwrap_or_default();
    assert!(
        message.contains("not ready") || message.contains("not available"),
        "unexpected payload: {payload}"
    );
    assert!(
        !message.contains("initial pod sync"),
        "STATUS must use a sanitized availability message: {message}"
    );

    drained.await.expect("drainer joined");
    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(2), listener).await;
}

/// Binary-level STATUS against a ready node-agent succeeds with empty stdout.
#[tokio::test]
async fn ferrum_cni_binary_status_exits_zero_on_ok() {
    let dir = tempdir().expect("tempdir");
    let socket_path = dir.path().join("agent.sock");
    let socket_path_str = socket_path.to_string_lossy().to_string();
    let metrics = Arc::new(NodeAgentMetrics::default());
    let (work_tx, mut work_rx) = cni_work_channel();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let drained = tokio::spawn(async move {
        let work = work_rx.recv().await.expect("work item arrives");
        assert_eq!(work.request.verb, RpcVerb::Status);
        let _ = work.respond.send(CniRpcResponse::Ok);
    });

    let listener = spawn_cni_listener(
        socket_path_str.clone(),
        work_tx,
        metrics.clone(),
        shutdown_rx,
    );

    wait_for_cni_listener_ready(&socket_path).await;

    let output = tokio::task::spawn_blocking(move || {
        run_ferrum_cni_status(serde_json::json!({
            "cniVersion": "1.1.0",
            "name": "ferrum-mesh-chain",
            "type": "ferrum-cni",
            "ferrum": { "socketPath": socket_path_str }
        }))
    })
    .await
    .expect("blocking task joined");

    assert!(
        output.status.success(),
        "STATUS success must exit 0, stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stdout.is_empty(),
        "STATUS success must emit no stdout payload"
    );

    drained.await.expect("drainer joined");
    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(2), listener).await;
}

#[test]
fn cni_rpc_status_boundary_rejects_attachment_specific_fields() {
    let valid_status = CniRpcRequest {
        verb: RpcVerb::Status,
        network_name: "ferrum-mesh-chain".to_string(),
        pod_namespace: String::new(),
        pod_name: String::new(),
        pod_uid: None,
        container_id: String::new(),
        ifname: None,
        netns_path: None,
        args: std::collections::HashMap::new(),
        valid_attachments: Vec::new(),
    };
    assert!(valid_status.validate().is_ok());

    let mut with_pod = valid_status.clone();
    with_pod.pod_name = "alpha".to_string();
    assert!(with_pod.validate().is_err());

    let mut with_attachments = valid_status.clone();
    with_attachments.valid_attachments = vec![ferrum_edge::cni::spec::CniValidAttachment {
        container_id: "ctr-1".to_string(),
        ifname: "eth0".to_string(),
    }];
    assert!(with_attachments.validate().is_err());

    let mut with_netns = valid_status;
    with_netns.netns_path = Some("/var/run/netns/cni-1".to_string());
    assert!(with_netns.validate().is_err());
}

// ── STATUS live Kubernetes ADD-dependency readiness ─────────────────────────

const STATUS_PROBE_NODE: &str = "status-probe-node";

fn status_probe_config() -> NodeAgentConfig {
    let mut capture_config = CaptureConfig::explicit(15006, 15001);
    capture_config.mode = CaptureMode::Ebpf;
    NodeAgentConfig {
        node_name: STATUS_PROBE_NODE.to_string(),
        capture_config,
        cgroup_root: "/nonexistent".to_string(),
        bpf_fs_path: "/nonexistent".to_string(),
        fallback_mode: FallbackMode::Fail,
        excluded_namespaces: HashSet::new(),
        capture_contract: CaptureContract::local_pod_defaults(),
        trust_domain: "cluster.local".to_string(),
        node_waypoint_pod_registry_dir: None,
    }
}

fn status_rpc_request() -> CniRpcRequest {
    CniRpcRequest {
        verb: RpcVerb::Status,
        network_name: "ferrum-mesh-chain".to_string(),
        pod_namespace: String::new(),
        pod_name: String::new(),
        pod_uid: None,
        container_id: String::new(),
        ifname: None,
        netns_path: None,
        args: std::collections::HashMap::new(),
        valid_attachments: Vec::new(),
    }
}

fn empty_pod_list_response() -> Response<Body> {
    Response::builder()
        .status(StatusCode::OK)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({
                "apiVersion": "v1",
                "kind": "PodList",
                "metadata": { "resourceVersion": "1" },
                "items": []
            }))
            .expect("serialize empty PodList"),
        ))
        .expect("build empty PodList response")
}

fn kube_error_response(status: StatusCode, message: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({
                "apiVersion": "v1",
                "kind": "Status",
                "status": "Failure",
                "message": message,
                "reason": "ServiceUnavailable",
                "code": status.as_u16()
            }))
            .expect("serialize kube Status"),
        ))
        .expect("build kube error response")
}

fn assert_status_probe_list_request(request: &Request<Body>) {
    assert_eq!(request.method(), Method::GET);
    let path = request.uri().path();
    assert_eq!(path, "/api/v1/pods", "STATUS probe must list cluster pods");
    let query = request.uri().query().unwrap_or_default();
    assert!(
        query.contains("limit=1"),
        "STATUS probe must stay low-cost: {query}"
    );
    assert!(
        query.contains(&format!("fieldSelector=spec.nodeName={STATUS_PROBE_NODE}"))
            || query.contains(&format!(
                "fieldSelector=spec.nodeName%3D{STATUS_PROBE_NODE}"
            )),
        "STATUS probe must reuse the watcher node scope: {query}"
    );
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MockProbeOutcome {
    Ready,
    Unavailable,
}

#[derive(Default)]
struct MockStatusProbeState {
    outcomes: Vec<MockProbeOutcome>,
    hits: usize,
}

fn mock_status_probe_client(state: Arc<Mutex<MockStatusProbeState>>) -> Client {
    let service = service_fn(move |request: Request<Body>| {
        let state = state.clone();
        async move {
            assert_status_probe_list_request(&request);
            let mut guard = state.lock().expect("lock mock STATUS probe state");
            let idx = guard.hits;
            guard.hits += 1;
            let outcome = guard
                .outcomes
                .get(idx)
                .copied()
                .unwrap_or(MockProbeOutcome::Ready);
            let response = match outcome {
                MockProbeOutcome::Ready => empty_pod_list_response(),
                MockProbeOutcome::Unavailable => kube_error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "injected https://kube.example/token=secret namespace=hostile failure",
                ),
            };
            Ok::<_, Infallible>(response)
        }
    });
    Client::new(service, "default")
}

fn mock_hanging_status_probe_client(release: oneshot::Receiver<()>) -> Client {
    let release = Arc::new(Mutex::new(Some(release)));
    let service = service_fn(move |request: Request<Body>| {
        let release = release.clone();
        async move {
            assert_status_probe_list_request(&request);
            // Drop the synchronous MutexGuard before awaiting so the tower
            // service future remains Send and never holds a blocking lock
            // across a suspension point.
            let rx = { release.lock().expect("lock hang gate").take() };
            if let Some(rx) = rx {
                // Park until the sender is dropped or the outer timeout cancels
                // this future — no spawn, no wall-clock sleep, no task leak.
                let _ = rx.await;
            }
            Ok::<_, Infallible>(empty_pod_list_response())
        }
    });
    Client::new(service, "default")
}

fn assert_sanitized_status_error(response: &CniRpcResponse) {
    let CniRpcResponse::Error { reason } = response else {
        panic!("expected STATUS Error, got {response:?}");
    };
    assert!(
        reason.contains("not ready for ADD"),
        "unexpected STATUS reason: {reason}"
    );
    assert!(
        !reason.contains("https://")
            && !reason.contains("token=")
            && !reason.contains("namespace=")
            && !reason.contains("hostile")
            && !reason.contains("kube.example")
            && !reason.contains(STATUS_PROBE_NODE),
        "STATUS must not echo raw Kubernetes/dependency detail: {reason}"
    );
}

async fn run_status_with_client(
    kube_client: &Client,
) -> (CniRpcResponse, DashMap<String, PodAttachmentState>) {
    let mut backend = MockEbpfBackend::default();
    let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
    let metrics = NodeAgentMetrics::default();
    let config = status_probe_config();
    let (response, enrolled) = apply_cni_request_with_kube_metadata_for_test(
        &mut backend,
        &pod_states,
        &config,
        &metrics,
        kube_client,
        &status_rpc_request(),
    )
    .await;
    assert!(enrolled.is_none(), "STATUS must never enroll");
    assert!(pod_states.is_empty(), "STATUS must not mutate enrollment");
    assert!(
        backend.operations.is_empty()
            && backend.cgroup_attachments.is_empty()
            && backend.tc_attachments.is_empty()
            && backend.detached_pods.is_empty(),
        "STATUS must not touch BPF/enrollment state"
    );
    (response, pod_states)
}

/// Live Kubernetes dependency success → STATUS Ok without enrollment mutation.
#[tokio::test]
async fn cni_status_kube_dependency_ready_returns_ok() {
    let state = Arc::new(Mutex::new(MockStatusProbeState {
        outcomes: vec![MockProbeOutcome::Ready],
        hits: 0,
    }));
    let client = mock_status_probe_client(state.clone());
    let (response, _) = run_status_with_client(&client).await;
    assert_eq!(response, CniRpcResponse::Ok);
    assert_eq!(state.lock().expect("lock").hits, 1);
}

/// API refusal → sanitized STATUS Error (code-50 path at the binary boundary).
#[tokio::test]
async fn cni_status_kube_dependency_failure_returns_sanitized_error() {
    let state = Arc::new(Mutex::new(MockStatusProbeState {
        outcomes: vec![MockProbeOutcome::Unavailable],
        hits: 0,
    }));
    let client = mock_status_probe_client(state.clone());
    let (response, _) = run_status_with_client(&client).await;
    assert_sanitized_status_error(&response);
    let CniRpcResponse::Error { reason } = &response else {
        unreachable!();
    };
    assert!(
        reason.contains("unavailable"),
        "failure path should name unavailability: {reason}"
    );
    assert_eq!(state.lock().expect("lock").hits, 1);
}

/// Stuck dependency is cancelled by the documented probe budget (no HoL beyond it).
#[tokio::test(start_paused = true)]
async fn cni_status_kube_dependency_timeout_is_bounded() {
    let (_hold_tx, hold_rx) = oneshot::channel::<()>();
    let client = mock_hanging_status_probe_client(hold_rx);

    let mut backend = MockEbpfBackend::default();
    let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
    let metrics = NodeAgentMetrics::default();
    let config = status_probe_config();

    // The pinned future borrows the request across the virtual-time advances;
    // keep the request alive for that entire scope rather than borrowing a
    // statement-local temporary.
    let request = status_rpc_request();
    let probe = apply_cni_request_with_kube_metadata_for_test(
        &mut backend,
        &pod_states,
        &config,
        &metrics,
        &client,
        &request,
    );
    tokio::pin!(probe);

    // Poll the probe so the timeout is armed, then advance just under the budget.
    tokio::select! {
        biased;
        _ = &mut probe => panic!("STATUS must not finish before the probe timeout"),
        _ = async {
            tokio::time::advance(CNI_STATUS_KUBE_PROBE_TIMEOUT - Duration::from_millis(1)).await;
        } => {}
    }

    tokio::time::advance(Duration::from_millis(2)).await;
    let (response, enrolled) = probe.await;
    assert!(enrolled.is_none());
    assert!(pod_states.is_empty());
    assert_sanitized_status_error(&response);
    let CniRpcResponse::Error { reason } = &response else {
        unreachable!();
    };
    assert!(
        reason.contains("timed out"),
        "timeout path should name the timeout: {reason}"
    );

    // A subsequent STATUS against a healthy dependency must proceed (no sticky
    // hang after the bounded failure).
    let ready_state = Arc::new(Mutex::new(MockStatusProbeState {
        outcomes: vec![MockProbeOutcome::Ready],
        hits: 0,
    }));
    let ready_client = mock_status_probe_client(ready_state);
    let (recovered, _) = run_status_with_client(&ready_client).await;
    assert_eq!(recovered, CniRpcResponse::Ok);
}

/// Dependency outage then recovery: STATUS fails closed, then succeeds again.
#[tokio::test]
async fn cni_status_kube_dependency_recovers_after_outage() {
    let state = Arc::new(Mutex::new(MockStatusProbeState {
        outcomes: vec![MockProbeOutcome::Unavailable, MockProbeOutcome::Ready],
        hits: 0,
    }));
    let client = mock_status_probe_client(state.clone());

    let (first, _) = run_status_with_client(&client).await;
    assert_sanitized_status_error(&first);

    let (second, _) = run_status_with_client(&client).await;
    assert_eq!(second, CniRpcResponse::Ok);
    assert_eq!(state.lock().expect("lock").hits, 2);
}

/// Install / uninstall / rollback lifecycle for the chained CNI artifacts
/// (issue #3609).
///
/// These exercise the host-filesystem side of the plugin rather than the UDS
/// wire: what the installer writes, what cleanup is and is not willing to
/// remove, and how the readiness watcher decides between retaining and
/// rolling back. Every case runs against a temp directory laid out like a
/// real `/etc/cni/net.d` + `/opt/cni/bin` pair, including a neighbouring
/// primary CNI config that must survive untouched.
mod install_lifecycle {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use ferrum_edge::cni::install::{
        CniArtifactOutcome, CniInstallConfig, CniInstallError, CniOwnership, CniUninstallConfig,
        CniUninstallReport, FERRUM_MANAGED_BY, OWNERSHIP_MANIFEST_FILE_NAME, install, uninstall,
    };
    use ferrum_edge::cni::lifecycle::{
        RollbackWatchConfig, RollbackWatchOutcome, run_rollback_watch,
    };
    use serde_json::Value;

    const OWNER: &str = "ferrum/mesh";
    const PRIMARY_CONF: &str = "10-calico.conflist";
    const GENERATED_CONF: &str = "00-ferrum.conflist";

    struct Node {
        _root: tempfile::TempDir,
        bin_dir: PathBuf,
        conf_dir: PathBuf,
        socket_dir: PathBuf,
        source_binary: PathBuf,
    }

    impl Node {
        fn new() -> Self {
            let root = tempfile::tempdir().expect("tempdir");
            let bin_dir = root.path().join("opt-cni-bin");
            let conf_dir = root.path().join("etc-cni-net-d");
            let socket_dir = root.path().join("var-run-ferrum");
            fs::create_dir_all(&bin_dir).expect("bin dir");
            fs::create_dir_all(&conf_dir).expect("conf dir");
            fs::write(
                conf_dir.join(PRIMARY_CONF),
                serde_json::to_vec_pretty(&serde_json::json!({
                    "cniVersion": "1.0.0",
                    "name": "calico",
                    "plugins": [{"type": "calico", "ipam": {"type": "calico-ipam"}}]
                }))
                .expect("primary json"),
            )
            .expect("write primary");
            let source_binary = root.path().join("image-ferrum-cni");
            fs::write(&source_binary, b"ferrum-cni v1").expect("write source binary");
            Self {
                _root: root,
                bin_dir,
                conf_dir,
                socket_dir,
                source_binary,
            }
        }

        fn install_config(&self, owner: &str, generation: &str) -> CniInstallConfig {
            CniInstallConfig {
                host_bin_dir: self.bin_dir.display().to_string(),
                host_conf_dir: self.conf_dir.display().to_string(),
                host_socket_dir: self.socket_dir.display().to_string(),
                conf_file_name: GENERATED_CONF.to_string(),
                chained_with: "calico".to_string(),
                socket_path: "/var/run/ferrum/node-agent-cni.sock".to_string(),
                ownership: CniOwnership {
                    owner: owner.to_string(),
                    generation: generation.to_string(),
                },
            }
        }

        fn uninstall_config(
            &self,
            owner: Option<&str>,
            generation: Option<&str>,
        ) -> CniUninstallConfig {
            CniUninstallConfig {
                host_bin_dir: self.bin_dir.display().to_string(),
                host_conf_dir: self.conf_dir.display().to_string(),
                conf_file_name: GENERATED_CONF.to_string(),
                expected_owner: owner.map(str::to_string),
                expected_generation: generation.map(str::to_string),
            }
        }

        fn install(&self, owner: &str, generation: &str) -> PathBuf {
            let config = self.install_config(owner, generation);
            install(&config, &self.source_binary).expect("install")
        }

        /// Run cleanup scoped to the release under test, optionally pinned to
        /// one install generation (the rollback watcher's scope).
        fn cleanup(&self, generation: Option<&str>) -> CniUninstallReport {
            let config = self.uninstall_config(Some(OWNER), generation);
            uninstall(&config).expect("uninstall runs")
        }

        fn conf_path(&self) -> PathBuf {
            self.conf_dir.join(GENERATED_CONF)
        }

        fn binary_path(&self) -> PathBuf {
            self.bin_dir.join("ferrum-cni")
        }

        fn manifest_path(&self) -> PathBuf {
            self.conf_dir.join(OWNERSHIP_MANIFEST_FILE_NAME)
        }

        fn assert_primary_untouched(&self) {
            let primary = read_json(&self.conf_dir.join(PRIMARY_CONF));
            assert_eq!(primary["name"], "calico");
            assert_eq!(primary["plugins"][0]["type"], "calico");
            assert_eq!(
                primary["plugins"].as_array().expect("plugins").len(), 1,
                "the primary CNI config must never be rewritten by install or uninstall"
            );
        }
    }

    fn read_json(path: &Path) -> Value {
        let bytes = fs::read(path).expect("read json");
        serde_json::from_slice(&bytes).expect("parse json")
    }

    #[test]
    fn install_stamps_ownership_and_uninstall_removes_exactly_those_artifacts() {
        let node = Node::new();
        node.install("ferrum/mesh", "gen-1");

        let generated = read_json(&node.conf_path());
        assert_eq!(generated["plugins"][0]["type"], "calico");
        assert_eq!(generated["plugins"][1]["type"], "ferrum-cni");
        let ferrum = &generated["plugins"][1]["ferrum"];
        assert_eq!(ferrum["managedBy"], FERRUM_MANAGED_BY);
        assert_eq!(ferrum["owner"], "ferrum/mesh");
        assert_eq!(ferrum["generation"], "gen-1");
        let manifest = read_json(&node.manifest_path());
        assert_eq!(manifest["managedBy"], FERRUM_MANAGED_BY);
        assert_eq!(manifest["owner"], "ferrum/mesh");

        let report = uninstall(&node.uninstall_config(Some("ferrum/mesh"), None))
            .expect("uninstall should succeed");
        assert!(report.is_success(), "report: {report:?}");
        assert_eq!(report.conflist, CniArtifactOutcome::Removed);
        assert_eq!(report.binary, CniArtifactOutcome::Removed);
        assert_eq!(report.manifest, CniArtifactOutcome::Removed);
        assert!(!node.conf_path().exists());
        assert!(!node.binary_path().exists());
        assert!(!node.manifest_path().exists());
        node.assert_primary_untouched();
    }

    #[test]
    fn install_and_uninstall_are_both_idempotent() {
        let node = Node::new();
        node.install("ferrum/mesh", "gen-1");
        // A repeat install (upgrade, pod restart) must converge on one chained
        // entry rather than appending another.
        node.install("ferrum/mesh", "gen-2");
        let generated = read_json(&node.conf_path());
        assert_eq!(generated["plugins"].as_array().expect("plugins").len(), 2);
        assert_eq!(generated["plugins"][1]["ferrum"]["generation"], "gen-2");

        let first = node.cleanup(None);
        assert!(first.is_success());
        assert_eq!(first.conflist, CniArtifactOutcome::Removed);

        let second = node.cleanup(None);
        assert!(second.is_success(), "repeat cleanup must stay a success");
        assert_eq!(second.conflist, CniArtifactOutcome::AlreadyAbsent);
        assert_eq!(second.binary, CniArtifactOutcome::AlreadyAbsent);
        assert_eq!(second.manifest, CniArtifactOutcome::AlreadyAbsent);
    }

    #[test]
    fn uninstall_retains_a_foreign_conflist_and_reports_failure() {
        let node = Node::new();
        // Somebody else's chained config sitting at the configured name: it
        // references ferrum-cni but carries no ownership marker.
        fs::write(
            node.conf_path(),
            serde_json::to_vec_pretty(&serde_json::json!({
                "cniVersion": "1.0.0",
                "name": "operator-authored",
                "plugins": [
                    {"type": "calico"},
                    {"type": "ferrum-cni", "ferrum": {"socketPath": "/custom.sock"}}
                ]
            }))
            .expect("json"),
        )
        .expect("write foreign conflist");
        fs::write(node.binary_path(), b"operator-provided binary").expect("write binary");

        let report = node.cleanup(None);
        assert!(
            !report.is_success(),
            "an unremovable chain must not report success: {report:?}"
        );
        assert!(matches!(
            report.conflist,
            CniArtifactOutcome::RetainedForeign(_)
        ));
        assert!(
            node.conf_path().exists() && node.binary_path().exists(),
            "unowned artifacts must be left exactly as they were"
        );
        let still_referenced = CniArtifactOutcome::RetainedDeliberate(
            "a chained CNI configuration still references the plugin binary",
        );
        assert_eq!(
            report.binary, still_referenced,
            "the binary must never be removed while a config still chains to it"
        );
    }

    #[cfg(unix)]
    #[test]
    fn uninstall_refuses_a_symlinked_conflist() {
        let node = Node::new();
        node.install("ferrum/mesh", "gen-1");
        let real = node.conf_path();
        let moved = node.conf_dir.join("moved-ferrum.json");
        fs::rename(&real, &moved).expect("move generated file");
        std::os::unix::fs::symlink(&moved, &real).expect("symlink");

        let report = node.cleanup(None);
        assert!(!report.is_success());
        assert!(matches!(
            report.conflist,
            CniArtifactOutcome::RetainedForeign(reason) if reason.contains("symlink")
        ));
        assert!(
            moved.exists(),
            "a symlink must never be followed to delete its target"
        );
    }

    #[cfg(unix)]
    #[test]
    fn uninstall_refuses_a_hard_linked_conflist() {
        let node = Node::new();
        node.install("ferrum/mesh", "gen-1");
        let alias = node.conf_dir.join("alias-ferrum.json");
        fs::hard_link(node.conf_path(), &alias).expect("hard link");

        let report = node.cleanup(None);
        assert!(!report.is_success());
        assert!(matches!(
            report.conflist,
            CniArtifactOutcome::RetainedForeign(_)
        ));
        assert!(node.conf_path().exists() && alias.exists());
    }

    #[test]
    fn uninstall_retains_another_owners_artifacts_and_still_succeeds() {
        let node = Node::new();
        node.install("other/release", "gen-1");

        let report = node.cleanup(None);
        assert!(
            report.is_success(),
            "another release's chain is not this release's failure: {report:?}"
        );
        assert_eq!(report.conflist, CniArtifactOutcome::RetainedOtherOwner);
        assert!(node.conf_path().exists());
        assert!(node.binary_path().exists());
    }

    #[test]
    fn uninstall_scoped_to_a_generation_never_removes_a_newer_one() {
        let node = Node::new();
        node.install("ferrum/mesh", "gen-2");

        // The rollback watcher of the OLD generation runs late.
        let report = node.cleanup(Some("gen-1"));
        assert!(report.is_success());
        assert_eq!(report.conflist, CniArtifactOutcome::RetainedOtherGeneration);
        assert!(node.conf_path().exists());
        assert!(node.binary_path().exists());

        // The current generation's own cleanup still works.
        let report = node.cleanup(Some("gen-2"));
        assert_eq!(report.conflist, CniArtifactOutcome::Removed);
    }

    #[test]
    fn a_corrupt_ownership_manifest_still_lets_cleanup_lift_the_chain() {
        let node = Node::new();
        node.install("ferrum/mesh", "gen-1");
        fs::write(node.manifest_path(), b"{ truncated").expect("corrupt manifest");

        let report = node.cleanup(None);
        assert!(
            report.is_success(),
            "the conflist marker alone must be enough to remove the node-wide dependency"
        );
        assert_eq!(report.conflist, CniArtifactOutcome::Removed);
        assert!(
            matches!(report.binary, CniArtifactOutcome::RetainedForeign(_)),
            "without a manifest the binary's provenance is unproven, so it stays: {report:?}"
        );
        assert!(!node.conf_path().exists());
        assert!(node.binary_path().exists());
    }

    #[test]
    fn uninstall_retains_a_binary_that_no_longer_matches_the_recorded_digest() {
        let node = Node::new();
        node.install("ferrum/mesh", "gen-1");
        fs::write(node.binary_path(), b"replaced out of band").expect("replace binary");

        let report = node.cleanup(None);
        assert!(report.is_success());
        assert_eq!(report.conflist, CniArtifactOutcome::Removed);
        assert!(matches!(
            report.binary,
            CniArtifactOutcome::RetainedForeign(_)
        ));
        let retained_for_retry = CniArtifactOutcome::RetainedDeliberate(
            "retained so a later cleanup run can still prove ownership",
        );
        assert_eq!(report.manifest, retained_for_retry);
        assert!(node.binary_path().exists());
    }

    #[test]
    fn uninstall_rejects_a_conf_file_name_that_escapes_the_directory() {
        let node = Node::new();
        let mut config = node.uninstall_config(Some(OWNER), None);
        config.conf_file_name = "../10-calico.conflist".to_string();
        let err = uninstall(&config).expect_err("traversal must be refused");
        assert!(matches!(err, CniInstallError::InvalidFileName { .. }));
        node.assert_primary_untouched();
    }

    #[test]
    fn install_rejects_an_ownership_token_with_hostile_characters() {
        let node = Node::new();
        let mut config = node.install_config(OWNER, "gen-1");
        config.ownership.owner = "ferrum mesh\n".to_string();
        let err = install(&config, &node.source_binary).expect_err("must be refused");
        assert!(matches!(
            err,
            CniInstallError::InvalidOwnershipToken { .. }
        ));
    }

    fn watch_config(node: &Node, generation: &str) -> RollbackWatchConfig {
        let socket_path = node.socket_dir.join("node-agent-cni.sock");
        RollbackWatchConfig {
            socket_path: socket_path.display().to_string(),
            ready_timeout: Duration::from_millis(60),
            poll_interval: Duration::from_millis(10),
            uninstall: node.uninstall_config(Some(OWNER), Some(generation)),
        }
    }

    #[test]
    fn rollback_watch_retains_artifacts_once_readiness_is_observed() {
        let node = Node::new();
        node.install("ferrum/mesh", "gen-1");
        let mut probes = 0;
        let mut probe = || {
            probes += 1;
            probes >= 2
        };
        let config = watch_config(&node, "gen-1");
        let outcome = run_rollback_watch(&config, &mut probe).expect("watch runs");
        assert_eq!(outcome, RollbackWatchOutcome::Ready);
        assert!(
            node.conf_path().exists(),
            "a node-agent that became ready keeps its CNI chain"
        );
    }

    #[test]
    fn rollback_watch_removes_its_own_generation_when_readiness_never_arrives() {
        let node = Node::new();
        node.install("ferrum/mesh", "gen-1");
        let mut probe = || false;
        let config = watch_config(&node, "gen-1");
        let outcome = run_rollback_watch(&config, &mut probe).expect("watch runs");
        match outcome {
            RollbackWatchOutcome::RolledBack(report) => {
                assert_eq!(report.conflist, CniArtifactOutcome::Removed);
                assert_eq!(report.binary, CniArtifactOutcome::Removed);
            }
            other => panic!("expected a rollback, got {other:?}"),
        }
        assert!(!node.conf_path().exists());
        node.assert_primary_untouched();
    }

    #[test]
    fn rollback_watch_does_not_delete_a_newer_generations_artifacts() {
        let node = Node::new();
        // A newer install landed while this pod was still waiting.
        node.install("ferrum/mesh", "gen-2");
        let mut probe = || false;
        let config = watch_config(&node, "gen-1");
        let outcome = run_rollback_watch(&config, &mut probe).expect("watch runs");
        match outcome {
            RollbackWatchOutcome::RolledBack(report) => {
                assert_eq!(report.conflist, CniArtifactOutcome::RetainedOtherGeneration);
                assert!(report.is_success());
            }
            other => panic!("expected a generation-scoped no-op, got {other:?}"),
        }
        assert!(node.conf_path().exists());
        assert!(node.binary_path().exists());
    }
}
