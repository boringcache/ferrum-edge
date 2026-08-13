use std::time::{Duration, Instant};

use ferrum_edge::proxy::owned_shell::{self, OwnedShellError};

#[test]
fn empty_script_is_a_noop() {
    owned_shell::run_sh_c("  \n", None).expect("empty script");
    owned_shell::run_sh_c("", Some(Instant::now() + Duration::from_secs(1)))
        .expect("empty script with deadline");
}

#[test]
fn successful_command_completes_inside_the_deadline() {
    owned_shell::run_sh_c("true", Some(Instant::now() + Duration::from_secs(5)))
        .expect("true must succeed");
}

#[test]
fn failed_command_is_not_a_deadline() {
    let error = owned_shell::run_sh_c("false", None).expect_err("false must fail");
    assert!(!error.is_deadline_elapsed(), "{error}");
    assert!(matches!(error, OwnedShellError::Failed { .. }), "{error}");
}

#[test]
fn failed_command_preserves_bounded_stderr_inside_the_deadline() {
    let error = owned_shell::run_sh_c(
        "printf 'iptables: No chain/target/match by that name\\n' >&2; exit 7",
        Some(Instant::now() + Duration::from_secs(5)),
    )
    .expect_err("nonzero exit must fail");
    assert!(!error.is_deadline_elapsed(), "{error}");
    match error {
        OwnedShellError::Failed { stderr, .. } => {
            assert!(
                stderr.contains("No chain/target/match by that name"),
                "{stderr}"
            );
        }
        other => panic!("expected Failed with stderr, got {other}"),
    }
}

#[test]
fn unbounded_path_still_surfaces_stderr_when_no_deadline_is_supplied() {
    let error = owned_shell::run_sh_c("printf 'unbounded-diagnostic\\n' >&2; false", None)
        .expect_err("false must fail");
    assert!(!error.is_deadline_elapsed(), "{error}");
    match error {
        OwnedShellError::Failed { stderr, .. } => {
            assert!(stderr.contains("unbounded-diagnostic"), "{stderr}");
        }
        other => panic!("expected Failed with stderr, got {other}"),
    }
}

#[test]
fn an_already_elapsed_deadline_does_not_spawn() {
    let error = owned_shell::run_sh_c(
        "echo spawned",
        Some(Instant::now() - Duration::from_secs(1)),
    )
    .expect_err("past deadline");
    assert!(error.is_deadline_elapsed(), "{error}");
}

#[cfg(unix)]
#[test]
fn a_stalled_child_is_killed_with_its_process_group_at_deadline() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pid_file = dir.path().join("shell.pid");
    let child_pid_file = dir.path().join("sleep.pid");
    let script = format!(
        "echo $$ > {shell}; sleep 30 & echo $! > {sleep}; wait",
        shell = pid_file.display(),
        sleep = child_pid_file.display(),
    );
    let start = Instant::now();
    let error = owned_shell::run_sh_c(&script, Some(start + Duration::from_millis(250)))
        .expect_err("sleep must be cut off by the deadline");
    assert!(error.is_deadline_elapsed(), "{error}");
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "deadline must not wait out the 30s sleep, took {elapsed:?}"
    );

    for path in [&pid_file, &child_pid_file] {
        let Ok(contents) = std::fs::read_to_string(path) else {
            continue;
        };
        let Ok(pid) = contents.trim().parse::<i32>() else {
            continue;
        };
        assert!(
            !process_still_owned_after_deadline(pid),
            "{} pid {pid} must not outlive the deadline",
            path.file_name().unwrap_or_default().to_string_lossy()
        );
    }
}

/// True when `pid` is still running, or is a zombie this process still parents
/// (an unreaped leak). `kill(pid, 0)` returns success for both live processes
/// and zombies, so a reaped-by-init grandchild would otherwise look alive.
#[cfg(unix)]
fn process_still_owned_after_deadline(pid: i32) -> bool {
    if unsafe { libc::kill(pid, 0) } != 0 {
        return false;
    }
    #[cfg(target_os = "linux")]
    {
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
            return false;
        };
        let Some((_, after_comm)) = stat.rsplit_once(')') else {
            return true;
        };
        let mut fields = after_comm.split_whitespace();
        let state = fields.next().unwrap_or("");
        let Ok(ppid) = fields.next().unwrap_or("").parse::<u32>() else {
            return true;
        };
        if state == "Z" && ppid != std::process::id() {
            return false;
        }
    }
    true
}

#[cfg(unix)]
#[test]
fn a_shell_that_exits_while_a_descendant_holds_stderr_still_returns_by_the_deadline() {
    let dir = tempfile::tempdir().expect("tempdir");
    let child_pid_file = dir.path().join("sleep.pid");
    // The shell exits immediately; the background sleep inherits the piped
    // stderr fd. An unbounded `read_to_end` would block until that descendant
    // exits. The deadline path must return within a bounded margin and must
    // not leave the owned descendant running.
    let script = format!(
        "sleep 30 & echo $! > {sleep}; exit 0",
        sleep = child_pid_file.display(),
    );
    let start = Instant::now();
    let result = owned_shell::run_sh_c(&script, Some(start + Duration::from_millis(250)));
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "stderr held open by a descendant must not pin the caller, took {elapsed:?}"
    );
    match result {
        Ok(()) => {}
        Err(error) if error.is_deadline_elapsed() => {}
        Err(error) => panic!("expected success or a deadline error, got {error}"),
    }

    let Ok(contents) = std::fs::read_to_string(&child_pid_file) else {
        return;
    };
    let Ok(pid) = contents.trim().parse::<i32>() else {
        return;
    };
    let gone_by = Instant::now() + Duration::from_secs(2);
    while Instant::now() < gone_by {
        let alive = unsafe { libc::kill(pid, 0) == 0 };
        if !alive {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("owned descendant pid {pid} must not survive the invocation");
}

#[test]
fn an_unenforceable_deadline_is_not_reported_as_elapsed() {
    let error = OwnedShellError::DeadlineUnsupported {
        error: "test collector".to_string(),
    };
    assert!(!error.is_deadline_elapsed(), "{error}");
    assert!(error.deadline_cleanup_error().is_none(), "{error}");
    let displayed = error.to_string();
    assert!(displayed.contains("cannot be enforced"), "{displayed}");
}

#[cfg(not(unix))]
#[test]
fn deadline_path_fails_closed_when_process_groups_are_unavailable() {
    let start = Instant::now();
    let error = owned_shell::run_sh_c("sleep 30", Some(start + Duration::from_secs(30)))
        .expect_err("deadline path must not spawn an unbounded child");
    assert!(!error.is_deadline_elapsed(), "{error}");
    match error {
        OwnedShellError::DeadlineUnsupported { error } => {
            assert!(
                error.contains("Unix process group") && error.contains("nonblocking"),
                "{error}"
            );
        }
        other => panic!("expected DeadlineUnsupported, got {other}"),
    }
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "unsupported deadline path must not block, took {elapsed:?}"
    );
}

#[cfg(unix)]
#[test]
fn a_silent_stalled_child_still_returns_by_the_deadline_without_stderr() {
    // A child that never writes stderr used to hang forever when O_NONBLOCK
    // was not established, because drain issued a blocking read before wait.
    let start = Instant::now();
    let error = owned_shell::run_sh_c("sleep 30", Some(start + Duration::from_millis(250)))
        .expect_err("sleep must be cut off by the deadline");
    assert!(error.is_deadline_elapsed(), "{error}");
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "a silent child must not pin the deadline path on a blocking stderr read, took {elapsed:?}"
    );
}

#[test]
fn deadline_cleanup_failed_is_observable_without_leaking_inner_detail() {
    let leaked = "/tmp/secret-script.sh env=NODE_UID=abc stderr=1.2.3.4";
    let unproven = OwnedShellError::DeadlineCleanupFailed {
        error: leaked.to_string(),
    };
    let elapsed = OwnedShellError::DeadlineElapsed;

    assert!(elapsed.is_deadline_elapsed());
    assert!(!elapsed.is_deadline_cleanup_unproven());
    assert_eq!(
        elapsed.deadline_operator_reason(),
        Some("owned command exceeded its deadline and was terminated")
    );
    assert_eq!(
        elapsed.to_string(),
        "script exceeded its deadline and was terminated"
    );

    assert!(
        unproven.is_deadline_elapsed(),
        "callers must still fail closed"
    );
    assert!(unproven.is_deadline_cleanup_unproven());
    assert_eq!(
        unproven.deadline_operator_reason(),
        Some(
            "owned command exceeded its deadline and owned descendants could not be proven terminated"
        )
    );
    assert_ne!(
        elapsed.deadline_operator_reason(),
        unproven.deadline_operator_reason()
    );
    let displayed = unproven.to_string();
    assert_eq!(
        displayed,
        "script exceeded its deadline and owned descendants could not be proven terminated"
    );
    assert!(
        !displayed.contains(leaked)
            && !displayed.contains("/tmp")
            && !displayed.contains("secret-script")
            && !displayed.contains("NODE_UID")
            && !displayed.contains("1.2.3.4"),
        "Display must not interpolate the inner cleanup error: {displayed}"
    );
    assert_eq!(unproven.deadline_cleanup_error(), Some(leaked));
}
