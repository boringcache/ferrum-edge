//! Static contracts for the Ambient host-network UDP live-kernel gate (#3705).
//!
//! These pin workflow triggers, required-mode behavior, fixture invariants,
//! bounded diagnostics, and Ferrum-owned cleanup without executing the live
//! fixture.

use std::fs;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> String {
    fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|error| {
        panic!("failed to read {rel}: {error}");
    })
}

#[test]
fn ambient_host_udp_live_workflow_requires_live_mode_and_exact_counts() {
    let workflow = read(".github/workflows/ambient-host-udp-live.yml");
    assert!(
        workflow.contains("FERRUM_LIVE_TESTS_REQUIRED: \"1\""),
        "hosted gate must set required live mode"
    );
    assert!(
        workflow.contains("tests/k8s/ambient_host_udp_live/run.sh"),
        "workflow must invoke the shared fixture runner"
    );
    assert!(
        workflow.contains("src/proxy/host_udp_capture.rs"),
        "path filters must include production host UDP capture"
    );
    assert!(
        workflow.contains("src/proxy/mesh_udp_capture.rs"),
        "path filters must include mesh UDP serving"
    );
    assert!(
        workflow.contains("src/modes/mesh/"),
        "path filters must include mesh serving"
    );
    assert!(
        workflow.contains("charts/ferrum-mesh/"),
        "path filters must include Helm templates"
    );
    assert!(
        workflow.contains("src/capture/"),
        "path filters must include capture plan generators"
    );
    assert!(
        !workflow.contains("draft: true"),
        "workflow must not be draft-gated"
    );
}

#[test]
fn ambient_host_udp_live_runner_fail_closed_and_bounded_diagnostics() {
    let runner = read("tests/k8s/ambient_host_udp_live/run.sh");
    assert!(
        runner.contains("FERRUM_LIVE_TESTS_REQUIRED"),
        "runner must honor required live mode"
    );
    assert!(
        runner.contains("fail_required"),
        "runner must convert skips into hard failures when required"
    );
    assert!(
        runner.contains("redact"),
        "diagnostics must be redacted"
    );
    assert!(
        runner.contains("head -c 16384") || runner.contains("head -n 200"),
        "diagnostics must be bounded"
    );
    assert!(
        runner.contains("FERRUM_MESH_UDP_HOST"),
        "cleanup must target Ferrum-owned host UDP chains"
    );
    assert!(
        runner.contains("lookup 33135") || runner.contains("table 33135"),
        "cleanup must target the Ferrum-owned host UDP routing table"
    );
    assert!(
        runner.contains("priority 101"),
        "cleanup must target the Ferrum-owned host UDP rule priority"
    );
    assert!(
        !runner.contains("lookup 33133"),
        "cleanup must not touch the pod-netns table"
    );
    assert!(
        !runner.contains("flush table"),
        "cleanup must never flush a routing table"
    );
    assert!(
        runner.contains("proxy::host_udp_capture_live_tests"),
        "runner must execute the lib live-kernel module"
    );
    assert!(
        runner.contains("functional_mesh_live_host_udp_capture"),
        "runner must execute the production ProxyHostUdpBackend functional live test"
    );
    assert!(
        runner.contains("expected exactly 2 ambient host-UDP lib live tests"),
        "runner must pin the lib live pass count"
    );
    assert!(
        runner.contains("expected exactly 1 ambient host-UDP functional live test"),
        "runner must pin the functional live pass count"
    );
}

#[test]
fn ambient_host_udp_live_kernel_module_uses_production_scripts_and_skip_or_fail() {
    let live = read("src/proxy/host_udp_capture_live_tests.rs");
    assert!(
        live.contains("IptablesPlan::host_udp_setup_script"),
        "live gate must install via production host UDP setup script"
    );
    assert!(
        live.contains("IptablesPlan::host_udp_teardown_script"),
        "live gate must tear down via production host UDP teardown script"
    );
    assert!(
        live.contains("bind_mesh_udp_capture_socket_with_pktinfo"),
        "live gate must bind the production pktinfo capture socket"
    );
    assert!(
        live.contains("FERRUM_LIVE_TESTS_REQUIRED"),
        "live gate must use the shared skip-or-fail contract"
    );
    assert!(
        live.contains("skip_or_fail"),
        "live gate must convert missing prerequisites via skip_or_fail"
    );
    assert!(
        live.contains("SourceAddressMismatch"),
        "live gate must prove source spoofing refusal"
    );
    assert!(
        live.contains("AmbiguousInterface"),
        "live gate must prove ambiguous-interface refusal"
    );
    assert!(
        live.contains("redact_diag"),
        "live diagnostics must be redacted"
    );
    assert!(
        live.contains("DIAG_CAP"),
        "live diagnostics must be bounded"
    );
}

#[test]
fn pr_ci_plan_schedules_ebpf_live_for_host_udp_surfaces() {
    let plan = read(".github/scripts/pr_ci_plan.py");
    assert!(
        plan.contains("host_udp_capture"),
        "planner eBPF/netns live patterns must include host_udp_capture"
    );
    assert!(
        plan.contains("ambient_host_udp_live"),
        "planner must include the ambient host-UDP live fixture path"
    );
    assert!(
        plan.contains("ambient-host-udp-live"),
        "planner must treat the ambient host-UDP workflow as a live trigger"
    );
    assert!(
        plan.contains("[\"src/proxy/host_udp_capture.rs\"]"),
        "planner self-test must pin host_udp_capture as run_ebpf_live"
    );
}
