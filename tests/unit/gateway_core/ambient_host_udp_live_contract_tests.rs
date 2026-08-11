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
        !workflow.contains("draft: true"),
        "workflow must not be draft-gated"
    );
}

/// The workflow must run unconditionally and decide relevance from an
/// immutable trusted-base classifier, never from a top-level `paths:` filter
/// the pull request itself supplies. A `paths:` filter would let a pull request
/// make the required check disappear entirely instead of reporting a verdict.
#[test]
fn ambient_host_udp_live_workflow_is_unconditional_with_a_trusted_base_relevance_gate() {
    let workflow = read(".github/workflows/ambient-host-udp-live.yml");

    assert!(
        !workflow.contains("    paths:") && !workflow.contains("    paths-ignore:"),
        "the live workflow must carry no top-level event path filter; relevance \
         belongs to the trusted-base classifier job"
    );
    assert!(
        workflow.contains("  pull_request:\n") && workflow.contains("  merge_group:\n"),
        "the live workflow must trigger on every pull request and merge-group run"
    );

    // Relevance is computed from the base branch's copy of the classifier,
    // read by object id, never from the pull request's own checkout.
    assert!(
        workflow.contains("git cat-file blob \"$entry_object\" > \"$trusted_filter\""),
        "relevance must read the trusted filter by pinned object id"
    );
    assert!(
        workflow.contains("python3 -I \"$trusted_filter\" --self-test"),
        "the trusted filter must self-test under an isolated interpreter"
    );
    assert!(
        !workflow.contains("python3 .github/scripts/live_suite_path_filter.py"),
        "relevance must never execute the pull request's own classifier"
    );
    assert!(
        workflow.contains("github.event.merge_group.base_sha")
            && workflow.contains("merge_group base_sha missing or malformed"),
        "merge-group runs must bind relevance to the event's base SHA"
    );

    // Bootstrap: origin/main does not yet know the `ambient-host-udp` suite, so
    // the introducing pull request must still run the live suite. Only that
    // exact unknown-suite rejection may force relevance; everything else fails
    // closed.
    assert!(
        workflow.contains("invalid choice: 'ambient-host-udp'"),
        "the introducing pull request must force relevance on the exact \
         unknown-suite classifier rejection"
    );
    assert!(
        workflow.contains("::error::trusted relevance filter failed"),
        "every other classifier failure must fail closed"
    );

    assert!(
        workflow.contains("    name: Ambient Host UDP Live\n"),
        "the final gate must be named exactly `Ambient Host UDP Live`"
    );
    assert!(
        workflow.contains("    if: always()"),
        "the final gate must run on every event, including skipped live runs"
    );
    assert!(
        workflow.contains("if: needs.changes.outputs.relevant == 'true'"),
        "the live job must be bound to the trusted relevance verdict"
    );
    assert!(
        workflow.contains("${{ needs.ambient-host-udp-live.result }}\" != \"success\""),
        "the gate must fail when a relevant live job fails or is absent"
    );
}

/// `verify_cross_build_policy.py` must freeze both the bootstrap relevance job
/// and the final gate byte-for-byte, so a later untrusted workflow edit cannot
/// silently skip or rename the required check.
#[test]
fn ambient_host_udp_live_gate_shape_is_frozen_by_the_cross_build_policy_verifier() {
    let verifier = read(".github/scripts/verify_cross_build_policy.py");

    assert!(
        verifier.contains("\"ambient-host-udp-live.yml\""),
        "the verifier must register the ambient host-UDP live workflow"
    );
    assert!(
        verifier.contains("LIVE_SUITE_UNKNOWN_SUITE_BOOTSTRAP_WORKFLOWS"),
        "the verifier must pin the unknown-suite bootstrap relevance variant"
    );
    assert!(
        verifier.contains("AMBIENT_HOST_UDP_LIVE_GATE_JOB"),
        "the verifier must freeze the unconditional final-gate job"
    );
    assert!(
        verifier.contains("name: Ambient Host UDP Live"),
        "the frozen gate contract must pin the exact required check name"
    );

    let required_ci = read(".github/scripts/verify_required_ci.py");
    assert!(
        required_ci.contains(
            "\".github/workflows/ambient-host-udp-live.yml\": \"Ambient Host UDP Live\""
        ),
        "the required-CI verifier must require an unconditional merge-group \
         owner for `Ambient Host UDP Live`"
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
    assert!(runner.contains("redact"), "diagnostics must be redacted");
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
