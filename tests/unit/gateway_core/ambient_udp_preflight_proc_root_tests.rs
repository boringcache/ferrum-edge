//! Explicit target-procfs resolution for the privileged Ambient UDP node
//! preflight (issue #3809).
//!
//! The preflight is an init container in the Ambient proxy's OWN pod, because
//! Kubernetes orders init-before-container only within one pod and orders
//! nothing between two DaemonSets — that ordering is what stops a replacement
//! proxy reading a leftover `.node-identity-v1.json` +
//! `.udp-node-cleanup-proof-v1.json` pair after a same-boot, same-name Node
//! recreation. Same-pod placement makes `hostPID` unacceptable, though: it is a
//! PodSpec field, so it would follow the long-running proxy container for its
//! whole lifetime.
//!
//! `--host-proc-root` is the replacement. These tests pin the resolution it
//! enables, the fail-closed validation of the flag, and the call graph, so no
//! hardcoded target `/proc/<pid>` path can quietly defeat the isolation.

use std::fs;
use std::path::{Path, PathBuf};

use ferrum_edge::proxy::netns_capture::{
    DEFAULT_PROC_ROOT, first_pid_in_cgroup_via_proc_root_until,
    is_proc_scan_deadline, proc_cgroup_is_in_subtree,
};

/// The pod cgroup as the node-agent registry publishes it: an ABSOLUTE
/// filesystem path under the mounted cgroup root.
const POD: &str = "/sys/fs/cgroup/kubepods.slice/kubepods-podabc.slice";

fn read_source(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!("failed to read {rel}: {error}");
    })
}

/// Build a synthetic procfs root holding `<root>/<pid>/cgroup` for each entry.
fn fake_proc_root(root: &Path, pids: &[(u32, &str)]) {
    for (pid, line) in pids {
        let dir = root.join(pid.to_string());
        fs::create_dir_all(&dir).expect("pid dir");
        fs::write(dir.join("cgroup"), format!("{line}\n")).expect("cgroup");
    }
}

// ── Subtree matching ────────────────────────────────────────────────────────

/// The registry publishes an ABSOLUTE cgroup filesystem path while procfs
/// reports a task's cgroup relative to the cgroup ROOT. Membership has to
/// survive both views without either side knowing where the other's root
/// begins.
#[test]
fn a_task_in_the_pod_cgroup_matches_through_the_cgroup_root_offset() {
    let inside = [
        // The pod's own cgroup, exactly.
        "0::/kubepods.slice/kubepods-podabc.slice",
        // A container scope BELOW it.
        "0::/kubepods.slice/kubepods-podabc.slice/cri-abc.scope",
        // The cgroup v1 multi-line form.
        "11:memory:/kubepods.slice/kubepods-podabc.slice/cri-abc.scope\n\
         10:cpu:/kubepods.slice/kubepods-podabc.slice",
        // A deeper cgroup root offset on the reader's side.
        "0::/kubepods.slice/kubepods-podabc.slice/x/y/z",
    ];
    for case in inside {
        assert!(proc_cgroup_is_in_subtree(case, POD), "inside: {case:?}");
    }
}

/// A guessed match would `setns` into the WRONG workload's network namespace
/// and retire its rules, so every near-miss must be refused.
#[test]
fn a_task_outside_the_pod_cgroup_never_matches() {
    let outside = [
        // A sibling pod.
        "0::/kubepods.slice/kubepods-poddef.slice",
        // An ancestor: being above the pod slice is not being in it.
        "0::/kubepods.slice",
        // The root cgroup.
        "0::/",
        // Component-misaligned: the last component merely ENDS with it.
        "0::/kubepods.slice/xkubepods-podabc.slice",
        // An unrelated tree.
        "0::/system.slice/sshd.service",
        // Not a cgroup file at all.
        "not a cgroup line",
        "",
    ];
    for case in outside {
        assert!(!proc_cgroup_is_in_subtree(case, POD), "outside: {case:?}");
    }
}

/// A published path that is empty, relative, or the bare root names no pod, so
/// it must match nothing rather than everything.
#[test]
fn a_degenerate_published_cgroup_path_matches_nothing() {
    let task = "0::/kubepods.slice/kubepods-podabc.slice";
    for bad in ["", "/", "kubepods.slice/podabc.slice", "relative"] {
        assert!(!proc_cgroup_is_in_subtree(task, bad), "degenerate: {bad:?}");
    }
}

// ── Resolution through an explicit procfs root ──────────────────────────────

#[test]
fn an_explicit_proc_root_resolves_a_task_in_the_pod_cgroup() {
    let root = tempfile::tempdir().expect("temp proc root");
    let entries = [
        (1u32, "0::/init.scope"),
        (4242, "0::/kubepods.slice/kubepods-podabc.slice/cri-a.scope"),
        (7, "0::/system.slice/kubelet.service"),
    ];
    fake_proc_root(root.path(), &entries);

    let pid = first_pid_in_cgroup_via_proc_root_until(root.path(), POD, None);
    assert_eq!(pid.expect("the enrolled pod's pid must resolve"), 4242);
}

/// Fail closed. A pod with no live task must be an error the caller reports,
/// never a silent fallback to some other pid.
#[test]
fn an_explicit_proc_root_with_no_matching_task_fails_closed() {
    let root = tempfile::tempdir().expect("temp proc root");
    let entries = [(1u32, "0::/init.scope"), (9, "0::/other.slice")];
    fake_proc_root(root.path(), &entries);

    let error = first_pid_in_cgroup_via_proc_root_until(root.path(), POD, None);
    let error = error.expect_err("no member task must be an error");
    assert_eq!(error.kind(), std::io::ErrorKind::NotFound);

    let missing = root.path().join("definitely-missing");
    assert!(
        first_pid_in_cgroup_via_proc_root_until(&missing, POD, None).is_err(),
        "an unreadable procfs root must fail rather than resolve"
    );
}

/// Non-numeric procfs entries (`self`, `net`, `sys`, …) and a task that exited
/// between readdir and read are ordinary, not a broken root.
#[test]
fn non_pid_entries_and_vanished_tasks_do_not_break_resolution() {
    let root = tempfile::tempdir().expect("temp proc root");
    fs::create_dir_all(root.path().join("sys/kernel")).expect("sys dir");
    fs::write(root.path().join("uptime"), "1 1\n").expect("uptime");
    // A pid directory with no `cgroup` file: the task already exited.
    fs::create_dir_all(root.path().join("31337")).expect("vanished pid");

    let entries = [(555u32, "0::/kubepods.slice/kubepods-podabc.slice")];
    fake_proc_root(root.path(), &entries);

    let pid = first_pid_in_cgroup_via_proc_root_until(root.path(), POD, None);
    assert_eq!(pid.expect("resolution must skip non-pid entries"), 555);
}

/// An already-elapsed preflight ceiling must fail closed as TimedOut even when
/// a matching pid exists, so `--timeout-seconds` cannot be bypassed by a hit.
#[test]
fn an_already_elapsed_deadline_fails_closed_before_returning_a_match() {
    use std::time::{Duration, Instant};

    let root = tempfile::tempdir().expect("temp proc root");
    fake_proc_root(
        root.path(),
        &[(4242u32, "0::/kubepods.slice/kubepods-podabc.slice")],
    );

    let deadline = Instant::now().checked_sub(Duration::from_secs(60));
    let error = first_pid_in_cgroup_via_proc_root_until(root.path(), POD, deadline)
        .expect_err("an elapsed deadline must not resolve a pid");
    assert!(
        is_proc_scan_deadline(&error),
        "already-elapsed must be the classified deadline outcome, got {error}"
    );
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
}

/// The scan must re-check the ceiling after each numeric pid, not only before
/// readdir. Otherwise a large host can run past `--timeout-seconds` on the way
/// to MAX_PROC_PID_SCAN. Non-matching entries plus a short remaining budget
/// must return TimedOut rather than NotFound after finishing the walk.
#[test]
fn a_deadline_that_elapses_during_the_scan_fails_closed_as_timeout() {
    use std::time::{Duration, Instant};

    let root = tempfile::tempdir().expect("temp proc root");
    let mut entries = Vec::new();
    for pid in 1u32..=2048 {
        entries.push((pid, "0::/system.slice/unrelated.service"));
    }
    fake_proc_root(root.path(), &entries);

    let deadline = Some(Instant::now() + Duration::from_millis(1));
    let error = first_pid_in_cgroup_via_proc_root_until(root.path(), POD, deadline)
        .expect_err("a mid-scan deadline must not complete as NotFound");
    assert!(
        is_proc_scan_deadline(&error),
        "during-scan expiry must be the classified deadline outcome, got {error}"
    );
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
}

// ── The call graph the isolation depends on ─────────────────────────────────

/// The one production consumer that runs under an explicit root is the
/// pod-netns cleanup backend. If it resolved target pids through the bare
/// helpers, the preflight would read ITS OWN procfs, where the enrolled pods'
/// pids do not exist — and the only way to make that work again would be
/// pod-scoped `hostPID` on the proxy.
#[test]
fn the_pod_netns_cleanup_backend_resolves_targets_through_the_explicit_root() {
    let netns_udp = read_source("src/proxy/netns_udp_capture.rs");
    let start = netns_udp
        .find("impl NetnsUdpCleanupBackend for ProxyNetnsUdpCleanupBackend")
        .expect("linux cleanup backend impl");
    let end = netns_udp[start..]
        .find("\n#[cfg(not(target_os = \"linux\"))]")
        .map(|offset| start + offset)
        .expect("end of the linux cleanup backend impl");
    let backend = &netns_udp[start..end];

    let inode_at = "netns_inode_for_cgroup_at_until(\n            self.proc_root(),\n            &target.cgroup_path,\n            deadline,";
    let handle_at = "open_pod_netns_handle_at_until(\n            self.proc_root(),\n            &target.cgroup_path,\n            deadline,";
    assert!(
        backend.contains(inode_at) && backend.contains(handle_at),
        "both target-pid resolutions must go through the explicit procfs root under the preflight deadline"
    );
    assert!(
        backend.contains("fn netns_key_until(")
            && backend.contains("NetnsUdpKeyOutcome::DeadlineElapsed")
            && backend.contains("is_proc_scan_deadline"),
        "reconcile netns-key lookup must classify a scan deadline instead of treating it as a retryable miss"
    );
    assert!(
        !backend.contains("netns_inode_for_cgroup(&target")
            && !backend.contains("open_pod_netns_handle(&target"),
        "the cleanup backend must not resolve targets through the caller's /proc"
    );
    // The caller's OWN namespace identity and the setns save/restore handle
    // deliberately stay on this container's procfs: the preflight already runs
    // in the host network namespace and must compare pod namespaces to its own.
    assert!(
        backend.contains("host_netns_inode()"),
        "the host-netns refusal must keep reading the caller's own netns"
    );
}

/// No target `/proc/<pid>` path may stay hardcoded on a path the preflight can
/// reach, and `/proc/self/ns/net` must never be redirected.
#[test]
fn the_linux_netns_primitives_confine_hardcoded_target_proc_paths() {
    let netns = read_source("src/proxy/netns_capture.rs");
    let imp_start = netns
        .find("#[cfg(target_os = \"linux\")]\nmod imp {")
        .expect("linux netns primitives");
    let imp_end = netns
        .find("#[cfg(not(target_os = \"linux\"))]\nmod imp {")
        .expect("non-linux netns primitives");
    let imp = &netns[imp_start..imp_end];

    assert!(
        imp.contains("std::fs::metadata(\"/proc/self/ns/net\")")
            && imp.contains("File::open(\"/proc/self/ns/net\")"),
        "/proc/self/ns/net is the caller's own identity and setns restore handle: \
         the target procfs root must never redirect it"
    );
    let target_path = "let path = target_proc_root.join(pid.to_string()).join(\"ns/net\");";
    assert_eq!(
        imp.matches(target_path).count(),
        2,
        "both target netns paths (inode stat and stable handle) must be built \
         from the explicit root"
    );
    // ONE hardcoded target path survives, and it must stay confined to the
    // node-waypoint TCP listener bind, which the preflight never calls (that
    // placement carries pod-scoped hostPID of its own).
    assert_eq!(
        imp.matches("format!(\"/proc/{pid}/ns/net\")").count(),
        1,
        "a NEW hardcoded target /proc/<pid> path would defeat the mount isolation"
    );
    assert_eq!(
        imp.matches("NetnsGuard::enter(").count(),
        1,
        "the pid-based netns guard must keep exactly one caller"
    );
    let guard_call = imp.find("NetnsGuard::enter(").expect("guard call");
    let bind_fn = "pub(super) fn bind_capture_listener_in_pod_netns";
    let bind_at = imp.find(bind_fn).expect("node-waypoint TCP bind");
    assert!(
        bind_at < guard_call,
        "the pid-based guard belongs to the node-waypoint TCP bind, not to any \
         path the preflight reaches"
    );
    assert!(
        imp.contains("if proc_root == Path::new(DEFAULT_PROC_ROOT) {")
            && imp.contains("let _ = deadline;")
            && imp.contains("return first_pid_in_cgroup(cgroup_path);"),
        "the default root must keep the original cgroup.procs read unchanged, so \
         the mesh data plane's own cleanup phase is untouched"
    );
    assert_eq!(DEFAULT_PROC_ROOT, "/proc");
}

/// `--timeout-seconds` is a hard wall-clock ceiling. The one-shot explicit-root
/// path must observe it in the pid walk, the netns-key lookup, and the stable
/// handle open. Unrelated backends keep the default trait method.
#[test]
fn the_oneshot_explicit_root_path_observes_the_preflight_deadline() {
    let netns = read_source("src/proxy/netns_capture.rs");
    let scan_start = netns
        .find("pub fn first_pid_in_cgroup_via_proc_root_until(")
        .expect("deadline-aware explicit-root scan");
    let scan_end = netns[scan_start..]
        .find("\n/// Production backend:")
        .map(|offset| scan_start + offset)
        .expect("end of explicit-root scan");
    let scan = &netns[scan_start..scan_end];
    assert!(
        scan.matches("deadline_elapsed(deadline)").count() >= 3,
        "the scan must check the ceiling before the walk, on each pid, and after each cgroup read"
    );
    assert!(
        scan.contains("proc_scan_deadline_error(proc_root)")
            && netns.contains("std::io::ErrorKind::TimedOut"),
        "deadline expiry must be a classified TimedOut outcome, not NotFound"
    );

    let imp_start = netns
        .find("#[cfg(target_os = \"linux\")]\nmod imp {")
        .expect("linux netns primitives");
    let imp_end = netns
        .find("#[cfg(not(target_os = \"linux\"))]\nmod imp {")
        .expect("non-linux netns primitives");
    let imp = &netns[imp_start..imp_end];
    assert!(
        imp.contains("fn netns_inode_for_cgroup_at_until(")
            && imp.contains("fn open_pod_netns_handle_at_until(")
            && imp.contains("first_pid_in_cgroup_at(target_proc_root, cgroup_path, deadline)"),
        "both explicit-root netns lookups must thread the deadline into pid resolution"
    );

    let udp = read_source("src/proxy/netns_udp_capture.rs");
    assert!(
        udp.contains("fn netns_key_until(")
            && udp.contains("let _ = deadline;\n        match self.netns_key(target)"),
        "unrelated cleanup backends must keep a default netns_key_until that ignores the deadline"
    );
    assert!(
        udp.contains("self.backend.netns_key_until(target, self.deadline)")
            && udp.contains(
                "NetnsUdpKeyOutcome::DeadlineElapsed => {\n                    return 0;"
            ),
        "cleanup reconcile must stop on a classified deadline instead of scanning remaining targets"
    );
}

/// Only the preflight sets the root. The mesh data plane's cleanup phase runs
/// inside the steady-state pod and must keep its own `/proc`.
#[test]
fn only_the_node_preflight_overrides_the_target_proc_root() {
    let cleanup = read_source("src/proxy/udp_placement_cleanup.rs");
    assert!(
        cleanup.contains("context.target_proc_root()")
            && cleanup.contains(".with_target_proc_root(target_proc_root)"),
        "the shared supervisor must thread the context's root into the backend"
    );

    let migration = read_source("src/proxy/udp_placement_migration.rs");
    assert_eq!(
        migration.matches("target_proc_root: None").count(),
        2,
        "both context constructors must default to the caller's own /proc"
    );

    let cli = read_source("src/cli.rs");
    assert!(
        cli.contains("long = \"host-proc-root\"")
            && cli.contains(".with_target_proc_root(target_proc_root)")
            && cli.contains("validate_host_proc_root"),
        "the preflight is the only producer of an explicit target procfs root"
    );
    assert!(
        !cli.contains("FERRUM_MESH_HOST_PROC_ROOT") && !cli.contains("FERRUM_HOST_PROC_ROOT"),
        "the root is a chart-internal argument, not a public FERRUM_* setting: \
         the ambient env map is copied verbatim into this container"
    );

    let mesh = read_source("src/modes/mesh/mod.rs");
    assert!(
        !mesh.contains("with_target_proc_root"),
        "the mesh data plane must never redirect target-pid reads"
    );
}

/// A typo'd or unmounted root must fail the init container rather than silently
/// degrade to `/proc`, where the enrolled pods' pids do not exist and every pod
/// would look unresolvable.
#[test]
fn an_unusable_host_proc_root_fails_closed() {
    use ferrum_edge::cli::validate_host_proc_root;

    let dir = tempfile::tempdir().expect("temp dir");

    assert!(
        validate_host_proc_root(Path::new("host/proc")).is_err(),
        "a relative root must be refused"
    );
    let missing = dir.path().join("definitely-missing");
    assert!(
        validate_host_proc_root(&missing).is_err(),
        "a missing root must be refused"
    );

    let file = dir.path().join("not-a-directory");
    fs::write(&file, b"x").expect("write file");
    assert!(
        validate_host_proc_root(&file).is_err(),
        "a non-directory root must be refused"
    );

    #[cfg(target_os = "linux")]
    {
        assert!(
            validate_host_proc_root(dir.path()).is_err(),
            "an empty mount point is not a procfs and must be refused"
        );
        let real = validate_host_proc_root(Path::new("/proc"));
        assert_eq!(
            real.expect("the real procfs validates"),
            PathBuf::from("/proc")
        );
    }
}
