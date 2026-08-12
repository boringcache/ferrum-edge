//! Exclusive ownership of `sh -c` children used by Ambient UDP cleanup.
//!
//! Production capture/teardown scripts are synchronous external commands. The
//! one-shot `ambient-udp-preflight` init stage advertises a hard `--timeout-seconds`
//! ceiling, so a stalled `iptables`/`ip`/`sh` child must not pin the current-thread
//! runtime (or the init container) indefinitely. When a deadline is supplied this
//! module waits with `try_wait`, and on expiry SIGKILLs the child's process group
//! before returning so no grandchild can keep mutating network state after the
//! caller has reported timeout.
//!
//! The unbounded path (`deadline == None`) keeps a blocking `.output()` wait: the
//! ordinary migration cleanup phase intentionally retries forever.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const WAIT_POLL: Duration = Duration::from_millis(10);

/// Outcome of an owned `sh -c` invocation.
#[derive(Debug)]
pub enum OwnedShellError {
    /// The process could not be started, or wait/kill failed.
    Io(std::io::Error),
    /// The process exited non-zero.
    Failed {
        status: std::process::ExitStatus,
        stderr: String,
    },
    /// The caller's deadline elapsed. The child (and its process group, on Unix)
    /// has been killed and reaped before this error is returned.
    DeadlineElapsed,
}

impl OwnedShellError {
    pub fn is_deadline_elapsed(&self) -> bool {
        matches!(self, Self::DeadlineElapsed)
    }
}

impl std::fmt::Display for OwnedShellError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "{error}"),
            Self::Failed { status, stderr } => {
                write!(f, "script failed with status {status}: {stderr}")
            }
            Self::DeadlineElapsed => {
                write!(f, "script exceeded its deadline and was terminated")
            }
        }
    }
}

impl std::error::Error for OwnedShellError {}

impl From<std::io::Error> for OwnedShellError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

/// Whether `deadline` is present and already in the past.
pub fn deadline_elapsed(deadline: Option<Instant>) -> bool {
    deadline.is_some_and(|deadline| Instant::now() >= deadline)
}

/// Remaining time until `deadline`, if any.
pub fn remaining(deadline: Option<Instant>) -> Option<Duration> {
    deadline.map(|deadline| deadline.saturating_duration_since(Instant::now()))
}

/// Convert a tokio timer deadline into a wall-clock deadline that helper threads
/// (and blocking `wait`) can observe without polling the runtime clock.
pub fn std_deadline_from_tokio(deadline: tokio::time::Instant) -> Instant {
    Instant::now() + deadline.saturating_duration_since(tokio::time::Instant::now())
}

/// Run `sh -c script`. An empty script is a no-op.
///
/// When `deadline` is `None` this blocks until the child exits, matching the
/// historical `Command::output()` contract. When `deadline` is `Some`, a stalled
/// child cannot outlive the deadline: the process group is killed and reaped
/// before [`OwnedShellError::DeadlineElapsed`] is returned.
pub fn run_sh_c(script: &str, deadline: Option<Instant>) -> Result<(), OwnedShellError> {
    if script.trim().is_empty() {
        return Ok(());
    }
    if deadline_elapsed(deadline) {
        return Err(OwnedShellError::DeadlineElapsed);
    }
    match deadline {
        None => run_unbounded(script),
        Some(deadline) => run_until(script, deadline),
    }
}

fn run_unbounded(script: &str) -> Result<(), OwnedShellError> {
    let output = Command::new("sh").arg("-c").arg(script).output()?;
    finish_status(output.status, output.stderr)
}

fn run_until(script: &str, deadline: Instant) -> Result<(), OwnedShellError> {
    let mut command = Command::new("sh");
    command
        .arg("-c")
        .arg(script)
        .stdin(Stdio::null())
        // Stdout is unused by cleanup/tool probes; leaving it piped can stall a
        // child that fills the pipe while this thread is in `try_wait`.
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    // Own the whole tree so `iptables`/`ip` grandchildren die with the shell.
    // Safety: `setpgid(0, 0)` only rearranges this child's process-group
    // membership before `exec`, and the child has not yet started user code.
    #[cfg(unix)]
    unsafe {
        use std::os::unix::process::CommandExt;
        command.pre_exec(|| {
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn()?;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stderr = read_child_stderr(&mut child);
                if Instant::now() >= deadline {
                    return Err(OwnedShellError::DeadlineElapsed);
                }
                return finish_status(status, stderr);
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    terminate_owned_child(&mut child);
                    return Err(OwnedShellError::DeadlineElapsed);
                }
                let slice = deadline
                    .saturating_duration_since(Instant::now())
                    .min(WAIT_POLL);
                if !slice.is_zero() {
                    std::thread::sleep(slice);
                }
            }
            Err(error) => {
                terminate_owned_child(&mut child);
                return Err(OwnedShellError::Io(error));
            }
        }
    }
}

fn finish_status(
    status: std::process::ExitStatus,
    stderr: Vec<u8>,
) -> Result<(), OwnedShellError> {
    if status.success() {
        Ok(())
    } else {
        Err(OwnedShellError::Failed {
            status,
            stderr: String::from_utf8_lossy(&stderr).trim().to_string(),
        })
    }
}

fn read_child_stderr(child: &mut std::process::Child) -> Vec<u8> {
    let mut stderr = Vec::new();
    if let Some(mut pipe) = child.stderr.take() {
        use std::io::Read;
        let _ = pipe.read_to_end(&mut stderr);
    }
    stderr
}

fn terminate_owned_child(child: &mut std::process::Child) {
    let pid = child.id();
    #[cfg(unix)]
    {
        let pid = pid as i32;
        // Safety: `pid` is the child we spawned into its own process group.
        // SIGKILL to `-pid` terminates that group; SIGKILL to `pid` covers a
        // child that failed to join the group. Neither call dereferences
        // memory.
        let _ = unsafe { libc::kill(-pid, libc::SIGKILL) };
        let _ = unsafe { libc::kill(pid, libc::SIGKILL) };
    }
    #[cfg(not(unix))]
    {
        let _ = child.kill();
    }
    let _ = child.wait();
}
