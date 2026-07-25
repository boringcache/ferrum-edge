//! External coverage for node-agent watcher exit reasons (#2369).
//!
//! Uses an injected finite/pending watcher stream (no live Kubernetes API) to
//! verify that both explicit shutdown and unexpected watcher exhaustion run
//! BPF cleanup, then return `Ok` only for requested shutdown.

use std::collections::HashSet;
use std::sync::Arc;

use ferrum_edge::_test_support::run_with_pod_stream_for_test;
use ferrum_edge::capture::{CaptureConfig, CaptureMode};
use ferrum_edge::ebpf::{
    CaptureContract, FallbackMode, MockEbpfBackend, NodeAgentMetrics, PodAttachmentState,
};
use ferrum_edge::modes::node_agent::NodeAgentConfig;
use futures::stream;
use k8s_openapi::api::core::v1::Pod;
use kube::runtime::watcher::{Error as WatcherError, Event};

fn test_config() -> NodeAgentConfig {
    let mut capture_config = CaptureConfig::explicit(15006, 15001);
    capture_config.mode = CaptureMode::Ebpf;
    NodeAgentConfig {
        node_name: "test-node".to_string(),
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

fn seeded_attached_pod(uid: &str) -> PodAttachmentState {
    PodAttachmentState {
        pod_uid: uid.to_string(),
        pod_name: "seeded".to_string(),
        namespace: "default".to_string(),
        pod_ip: None,
        pod_ip6: None,
        cgroup_path: None,
        veth_iface: Some("veth-mock".to_string()),
        attached: true,
        include_ports_cgroup_ids: Vec::new(),
        include_ports_policy: None,
        workload_identity_cgroup_ids: Vec::new(),
        node_probe_ports: vec![8080],
    }
}

#[tokio::test]
async fn shutdown_requested_cleans_up_and_returns_ok() {
    let mut backend = MockEbpfBackend::default();
    let metrics = Arc::new(NodeAgentMetrics::default());
    // Already requested: the loop breaks before selecting on the pending stream.
    let (shutdown_tx, _shutdown_rx) = tokio::sync::watch::channel(true);
    let pending = stream::pending::<Result<Event<Pod>, WatcherError>>();

    let result = run_with_pod_stream_for_test(
        &mut backend,
        &test_config(),
        metrics,
        &shutdown_tx,
        pending,
        [seeded_attached_pod("pod-shutdown")],
    )
    .await;

    assert!(
        result.is_ok(),
        "explicit shutdown must return Ok, got {result:?}"
    );
    assert!(
        backend.cleaned_up,
        "shutdown path must run backend.cleanup_all"
    );
    assert_eq!(backend.detached_pods, vec!["pod-shutdown".to_string()]);
}

#[tokio::test]
async fn shutdown_requested_wins_over_an_already_exhausted_stream() {
    let mut backend = MockEbpfBackend::default();
    let metrics = Arc::new(NodeAgentMetrics::default());
    let (shutdown_tx, _shutdown_rx) = tokio::sync::watch::channel(true);
    let empty = stream::empty::<Result<Event<Pod>, WatcherError>>();

    let result = run_with_pod_stream_for_test(
        &mut backend,
        &test_config(),
        metrics,
        &shutdown_tx,
        empty,
        [seeded_attached_pod("pod-shutdown-race")],
    )
    .await;

    assert!(
        result.is_ok(),
        "requested shutdown must win over stream exhaustion, got {result:?}"
    );
    assert!(backend.cleaned_up);
    assert_eq!(backend.detached_pods, vec!["pod-shutdown-race".to_string()]);
}

#[tokio::test]
async fn watcher_exhaustion_cleans_up_and_returns_err() {
    let mut backend = MockEbpfBackend::default();
    let metrics = Arc::new(NodeAgentMetrics::default());
    let (shutdown_tx, _shutdown_rx) = tokio::sync::watch::channel(false);
    // Finite empty stream: first poll yields None → unexpected exhaustion.
    let empty = stream::empty::<Result<Event<Pod>, WatcherError>>();

    let result = run_with_pod_stream_for_test(
        &mut backend,
        &test_config(),
        metrics,
        &shutdown_tx,
        empty,
        [seeded_attached_pod("pod-exhausted")],
    )
    .await;

    let err = result.expect_err("watcher exhaustion must return Err");
    assert!(
        err.to_string().contains("Pod watcher ended unexpectedly"),
        "unexpected error text: {err}"
    );
    assert!(
        backend.cleaned_up,
        "watcher-exhaustion path must still run backend.cleanup_all"
    );
    assert_eq!(backend.detached_pods, vec!["pod-exhausted".to_string()]);
}
