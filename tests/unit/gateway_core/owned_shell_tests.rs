use std::time::{Duration, Instant};

use ferrum_edge::proxy::owned_shell::{self, OwnedShellError};

#[test]
fn empty_script_is_a_noop() {
    owned_shell::run_sh_c("  \n", None).expect("empty script");
    owned_shell::run_sh_c(
        "",
        Some(Instant::now() + Duration::from_secs(1)),
    )
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
        let alive = unsafe { libc::kill(pid, 0) == 0 };
        assert!(
            !alive,
            "{} pid {pid} must not outlive the deadline",
            path.file_name().unwrap_or_default().to_string_lossy()
        );
    }
}
