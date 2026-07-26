//! External coverage for issue #2371: node-agent eBPF startup rollback.
//!
//! After `load_programs` succeeds, every failure/shutdown path must invoke
//! `cleanup_all` exactly once while preserving the original error.

use ferrum_edge::_test_support::{
    node_agent_cleanup_failure_preserves_original_error_probe_for_test,
    node_agent_k8s_client_style_late_failure_cleanup_probe_for_test,
    node_agent_normal_shutdown_cleanup_once_probe_for_test,
    node_agent_post_load_init_failure_cleanup_probe_for_test,
    node_agent_pre_load_failure_skips_cleanup_probe_for_test,
};

#[test]
fn post_load_programs_failure_calls_cleanup_all_once() {
    let probe = node_agent_post_load_init_failure_cleanup_probe_for_test();

    assert!(
        !probe.ok,
        "post-load capture-config failure must abort init"
    );
    let error = probe
        .error
        .expect("post-load failure must surface an error");
    assert!(
        error.contains("capture config update failed"),
        "original init error preserved: {error}"
    );
    assert!(probe.programs_loaded, "load_programs must have succeeded");
    assert!(
        !probe.capture_config_set,
        "failed capture-config write must leave no live config"
    );
    assert!(probe.cleaned_up);
    assert_eq!(
        probe.cleanup_all_calls, 1,
        "post-load rollback must call cleanup_all exactly once"
    );
}

#[test]
fn load_programs_failure_does_not_call_cleanup_all() {
    let probe = node_agent_pre_load_failure_skips_cleanup_probe_for_test();

    assert!(!probe.ok, "load_programs failure must abort init");
    let error = probe.error.expect("load failure must surface an error");
    assert!(
        error.contains("injected load_programs failure"),
        "original load error preserved: {error}"
    );
    assert!(
        !probe.programs_loaded,
        "load_programs must not report success"
    );
    assert!(!probe.cleaned_up);
    assert_eq!(
        probe.cleanup_all_calls, 0,
        "nothing was created before load_programs, so rollback must not run"
    );
}

#[test]
fn kubernetes_client_style_late_failure_calls_cleanup_all_once() {
    let probe = node_agent_k8s_client_style_late_failure_cleanup_probe_for_test();

    assert!(!probe.ok);
    let error = probe
        .error
        .expect("late failure must surface the injected error");
    assert!(
        error.contains("injected kube client construction failure"),
        "Kubernetes-client-style error must be preserved: {error}"
    );
    assert!(probe.cleaned_up);
    assert_eq!(
        probe.cleanup_all_calls, 1,
        "late failure after init must call cleanup_all exactly once"
    );
}

#[test]
fn normal_shutdown_calls_cleanup_all_exactly_once() {
    let probe = node_agent_normal_shutdown_cleanup_once_probe_for_test();

    assert!(
        probe.ok,
        "normal shutdown probe must succeed: {:?}",
        probe.error
    );
    assert!(probe.cleaned_up);
    assert_eq!(
        probe.cleanup_all_calls, 1,
        "shutdown + Drop must not double-clean: got {} calls",
        probe.cleanup_all_calls
    );
}

#[test]
fn cleanup_failure_preserves_original_error() {
    let probe = node_agent_cleanup_failure_preserves_original_error_probe_for_test();

    assert!(!probe.ok);
    let error = probe.error.expect("original error must still be returned");
    assert!(
        error.contains("original injected startup failure"),
        "cleanup failure must not hide the original cause: {error}"
    );
    assert!(
        !error.contains("injected cleanup_all failure"),
        "cleanup error must stay out of the returned cause: {error}"
    );
    assert!(probe.cleaned_up);
    assert_eq!(probe.cleanup_all_calls, 1);
}
