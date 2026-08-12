//! Exclusive ownership of `sh -c` children used by Ambient UDP cleanup.
//!
//! Production capture/teardown scripts are synchronous external commands. The
//! one-shot `ambient-udp-preflight` init stage advertises a hard `--timeout-seconds`
//! ceiling, so a stalled `iptables`/`ip`/`sh` child must not pin the current-thread
//! runtime (or the init container) indefinitely. When a deadline is supplied this
//! module waits with `try_wait`, collects stderr under that same ceiling, and on
//! expiry SIGKILLs the child's process group before returning so no grandchild can
//! keep mutating network state — or hold the inherited stderr pipe open — after
//! the caller has reported timeout.
//!
//! The unbounded path (`deadline == None`) keeps a blocking `.output()` wait: the
//! ordinary migration cleanup phase intentionally retries forever.

use std::io::{self, Read};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const WAIT_POLL: Duration = Duration::from_millis(10);
/// Bounded diagnostic capture for the deadline path. Ordinary nonzero exits
/// still surface this prefix; a grandchild that never closes stderr cannot
/// grow it without bound.
const MAX_DEADLINE_STDERR: usize = 64 * 1024;

/// Outcome of an owned `sh -c` invocation.
#[derive(Debug)]
pub enum OwnedShellError {
    /// The process could not be started, or wait/kill failed before the deadline.
    Io(std::io::Error),
    /// The process exited non-zero.
    Failed {
        status: std::process::ExitStatus,
        stderr: String,
    },
    /// The caller's deadline elapsed. The owned process group was killed and
    /// reaped before this error is returned.
    DeadlineElapsed,
    /// The deadline elapsed, and SIGKILL/reap of the owned process group could
    /// not be proven. The caller must still fail closed and withhold proof; this
    /// variant exists so that failure is reported rather than claimed as a
    /// successful termination.
    DeadlineCleanupFailed { error: String },
}

impl OwnedShellError {
    pub fn is_deadline_elapsed(&self) -> bool {
        matches!(
            self,
            Self::DeadlineElapsed | Self::DeadlineCleanupFailed { .. }
        )
    }

    /// When process-group cleanup could not be proven after the deadline.
    pub fn deadline_cleanup_error(&self) -> Option<&str> {
        match self {
            Self::DeadlineCleanupFailed { error } => Some(error.as_str()),
            _ => None,
        }
    }

    fn from_deadline_cleanup(cleanup: Result<(), io::Error>) -> Self {
        match cleanup {
            Ok(()) => Self::DeadlineElapsed,
            Err(error) => Self::DeadlineCleanupFailed {
                error: error.to_string(),
            },
        }
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
            Self::DeadlineCleanupFailed { error } => {
                write!(
                    f,
                    "script exceeded its deadline; owned descendants could not be proven terminated: {error}"
                )
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
/// before a deadline error is returned, and stderr collection itself is bounded
/// so an orphaned grandchild holding the pipe cannot pin the caller forever.
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
    set_stderr_nonblocking(&mut child);
    let mut stderr = Vec::new();
    loop {
        drain_stderr_nonblocking(&mut child, &mut stderr);
        match child.try_wait() {
            Ok(Some(status)) => {
                // The direct child is gone. Remaining process-group members are
                // still owned by this invocation: they can hold the inherited
                // stderr fd open (defeating an unbounded `read_to_end`) and can
                // keep mutating network state. Reap them before collecting
                // diagnostics or returning success.
                let cleanup = terminate_owned_tree(&mut child);
                drain_stderr_until(&mut child, &mut stderr, deadline);
                if Instant::now() >= deadline {
                    return Err(OwnedShellError::from_deadline_cleanup(cleanup));
                }
                if let Err(error) = cleanup {
                    return Err(OwnedShellError::Io(error));
                }
                return finish_status(status, stderr);
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let cleanup = terminate_owned_tree(&mut child);
                    drain_stderr_until(&mut child, &mut stderr, deadline);
                    return Err(OwnedShellError::from_deadline_cleanup(cleanup));
                }
                let slice = deadline
                    .saturating_duration_since(Instant::now())
                    .min(WAIT_POLL);
                if !slice.is_zero() {
                    std::thread::sleep(slice);
                }
            }
            Err(error) => {
                let cleanup = terminate_owned_tree(&mut child);
                drain_stderr_until(&mut child, &mut stderr, deadline);
                if Instant::now() >= deadline {
                    return Err(OwnedShellError::from_deadline_cleanup(cleanup));
                }
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

fn set_stderr_nonblocking(child: &mut Child) {
    #[cfg(unix)]
    if let Some(pipe) = child.stderr.as_ref() {
        use std::os::unix::io::AsRawFd;
        let fd = pipe.as_raw_fd();
        // Safety: `fd` is the live stderr pipe of the child we spawned. GETFL
        // / SETFL only change the O_NONBLOCK flag on that descriptor.
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL, 0);
            if flags >= 0 {
                let _ = libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            }
        }
    }
}

fn drain_stderr_nonblocking(child: &mut Child, stderr: &mut Vec<u8>) {
    let Some(pipe) = child.stderr.as_mut() else {
        return;
    };
    let mut buf = [0u8; 4096];
    loop {
        if stderr.len() >= MAX_DEADLINE_STDERR {
            return;
        }
        match pipe.read(&mut buf) {
            Ok(0) => {
                child.stderr.take();
                return;
            }
            Ok(n) => {
                let room = MAX_DEADLINE_STDERR.saturating_sub(stderr.len());
                stderr.extend_from_slice(&buf[..n.min(room)]);
            }
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    || error.kind() == io::ErrorKind::Interrupted =>
            {
                return;
            }
            Err(_) => {
                child.stderr.take();
                return;
            }
        }
    }
}

fn drain_stderr_until(child: &mut Child, stderr: &mut Vec<u8>, deadline: Instant) {
    loop {
        drain_stderr_nonblocking(child, stderr);
        if child.stderr.is_none() || Instant::now() >= deadline {
            return;
        }
        let slice = deadline
            .saturating_duration_since(Instant::now())
            .min(WAIT_POLL);
        if slice.is_zero() {
            return;
        }
        std::thread::sleep(slice);
    }
}

/// SIGKILL the owned process group and reap the direct child. Remaining
/// grandchildren that were reparented to init cannot be `waitpid`'d here; the
/// group signal is the platform's ownership boundary.
fn terminate_owned_tree(child: &mut Child) -> Result<(), io::Error> {
    let pid = child.id();
    let mut kill_error = None;
    #[cfg(unix)]
    {
        let pid = pid as i32;
        // Safety: `pid` is the child we spawned into its own process group.
        // SIGKILL to `-pid` terminates that group even after the leader has
        // exited; SIGKILL to `pid` covers a child that failed to join the
        // group. Neither call dereferences memory.
        if unsafe { libc::kill(-pid, libc::SIGKILL) } != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                kill_error = Some(error);
            }
        }
        if unsafe { libc::kill(pid, libc::SIGKILL) } != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                kill_error = Some(error);
            }
        }
        loop {
            let mut status = 0;
            // Safety: `waitpid(-pgid, WNOHANG)` reaps any remaining children
            // in this process group that we still parent. It does not
            // dereference userspace memory.
            let reaped = unsafe { libc::waitpid(-pid, &mut status, libc::WNOHANG) };
            if reaped <= 0 {
                break;
            }
        }
    }
    #[cfg(not(unix))]
    {
        if let Err(error) = child.kill()
            && error.kind() != io::ErrorKind::InvalidInput
        {
            kill_error = Some(error);
        }
    }
    match child.wait() {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::InvalidInput => {}
        Err(error) => return Err(error),
    }
    match kill_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}
