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
//! The deadline path never issues a potentially blocking stderr read. Nonblocking
//! mode is established before any diagnostic `read`, and inability to do that is
//! an explicit error after the owned child is terminated as far as the platform
//! can prove. Platforms without a process-group/nonblocking collector fail closed
//! rather than pretending the deadline is enforced.
//!
//! The unbounded path (`deadline == None`) keeps a blocking `.output()` wait: the
//! ordinary migration cleanup phase intentionally retries forever.

use std::io;
#[cfg(unix)]
use std::io::Read;
use std::process::Command;
#[cfg(unix)]
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};

#[cfg(unix)]
const WAIT_POLL: Duration = Duration::from_millis(10);
/// Bounded diagnostic capture for the deadline path. Ordinary nonzero exits
/// still surface this prefix; a grandchild that never closes stderr cannot
/// grow it without bound.
#[cfg(unix)]
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
    /// A deadline was supplied, but a safe bounded/nonblocking diagnostic
    /// collector (and process-group kill) could not be established. The owned
    /// child was terminated as far as the platform can prove, or never spawned
    /// on platforms that cannot implement the contract.
    DeadlineUnsupported { error: String },
}

impl OwnedShellError {
    pub fn is_deadline_elapsed(&self) -> bool {
        matches!(
            self,
            Self::DeadlineElapsed | Self::DeadlineCleanupFailed { .. }
        )
    }

    /// When process-group cleanup could not be proven after the deadline.
    #[allow(dead_code)] // Public library API exercised by the external unit-test crate; unused by the binary target.
    pub fn deadline_cleanup_error(&self) -> Option<&str> {
        match self {
            Self::DeadlineCleanupFailed { error } => Some(error.as_str()),
            _ => None,
        }
    }

    #[cfg(unix)]
    fn from_deadline_cleanup(cleanup: Result<(), io::Error>) -> Self {
        match cleanup {
            Ok(()) => Self::DeadlineElapsed,
            Err(error) => Self::DeadlineCleanupFailed {
                error: error.to_string(),
            },
        }
    }

    #[cfg(unix)]
    fn from_collector_setup(setup: io::Error, cleanup: Result<(), io::Error>) -> Self {
        match cleanup {
            Ok(()) => Self::DeadlineUnsupported {
                error: setup.to_string(),
            },
            Err(cleanup_error) => Self::DeadlineCleanupFailed {
                error: format!(
                    "failed to establish a nonblocking stderr collector ({setup}); owned descendants could not be proven terminated: {cleanup_error}"
                ),
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
            Self::DeadlineUnsupported { error } => {
                write!(f, "script deadline cannot be enforced: {error}")
            }
        }
    }
}

impl std::error::Error for OwnedShellError {}

impl From<io::Error> for OwnedShellError {
    fn from(error: io::Error) -> Self {
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
    #[cfg(unix)]
    {
        run_until_unix(script, deadline)
    }
    #[cfg(not(unix))]
    {
        let _ = (script, deadline);
        Err(OwnedShellError::DeadlineUnsupported {
            error: "hard wall-clock deadlines require a Unix process group and a nonblocking stderr collector"
                .to_string(),
        })
    }
}

#[cfg(unix)]
fn run_until_unix(script: &str, deadline: Instant) -> Result<(), OwnedShellError> {
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
    if let Err(setup) = set_stderr_nonblocking(&child) {
        let cleanup = terminate_owned_tree(&mut child, deadline);
        // Never drain stderr here: the pipe may still be blocking.
        return Err(return_without_blocking_wait(
            child,
            OwnedShellError::from_collector_setup(setup, cleanup),
        ));
    }
    let mut stderr = Vec::new();
    loop {
        drain_stderr_nonblocking(&mut child, &mut stderr);
        match child.try_wait() {
            Ok(Some(status)) => {
                // The direct child is gone. Remaining process-group members are
                // still owned by this invocation: they can hold the inherited
                // stderr fd open and can keep mutating network state. Signal
                // the group (never the reaped PID) before collecting
                // diagnostics or returning success.
                let cleanup = terminate_owned_tree(&mut child, deadline);
                drain_stderr_until(&mut child, &mut stderr, deadline);
                if Instant::now() >= deadline {
                    return Err(return_without_blocking_wait(
                        child,
                        OwnedShellError::from_deadline_cleanup(cleanup),
                    ));
                }
                if let Err(error) = cleanup {
                    return Err(return_without_blocking_wait(
                        child,
                        OwnedShellError::Io(error),
                    ));
                }
                return finish_status(status, stderr);
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let cleanup = terminate_owned_tree(&mut child, deadline);
                    drain_stderr_until(&mut child, &mut stderr, deadline);
                    return Err(return_without_blocking_wait(
                        child,
                        OwnedShellError::from_deadline_cleanup(cleanup),
                    ));
                }
                let slice = deadline
                    .saturating_duration_since(Instant::now())
                    .min(WAIT_POLL);
                if !slice.is_zero() {
                    std::thread::sleep(slice);
                }
            }
            Err(error) => {
                let cleanup = terminate_owned_tree(&mut child, deadline);
                drain_stderr_until(&mut child, &mut stderr, deadline);
                if Instant::now() >= deadline {
                    return Err(return_without_blocking_wait(
                        child,
                        OwnedShellError::from_deadline_cleanup(cleanup),
                    ));
                }
                return Err(return_without_blocking_wait(
                    child,
                    OwnedShellError::Io(error),
                ));
            }
        }
    }
}

fn finish_status(status: std::process::ExitStatus, stderr: Vec<u8>) -> Result<(), OwnedShellError> {
    if status.success() {
        Ok(())
    } else {
        Err(OwnedShellError::Failed {
            status,
            stderr: String::from_utf8_lossy(&stderr).trim().to_string(),
        })
    }
}

/// Close the diagnostic pipe without reading it and leak `child` when it is
/// still unreaped, so `Child::drop` cannot issue a blocking `wait` after the
/// caller has already failed closed.
#[cfg(unix)]
fn return_without_blocking_wait(mut child: Child, error: OwnedShellError) -> OwnedShellError {
    match child.try_wait() {
        Ok(Some(_)) => error,
        Err(io_error) if io_error.kind() == io::ErrorKind::InvalidInput => error,
        _ => {
            let _ = child.stderr.take();
            std::mem::forget(child);
            error
        }
    }
}

#[cfg(unix)]
fn set_stderr_nonblocking(child: &Child) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let Some(pipe) = child.stderr.as_ref() else {
        return Err(io::Error::other("owned shell stderr pipe was not captured"));
    };
    let fd = pipe.as_raw_fd();
    // Safety: `fd` is the live stderr pipe of the child we spawned. GETFL /
    // SETFL only change the O_NONBLOCK flag on that descriptor.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL, 0);
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err(io::Error::last_os_error());
        }
        let confirmed = libc::fcntl(fd, libc::F_GETFL, 0);
        if confirmed < 0 {
            return Err(io::Error::last_os_error());
        }
        if (confirmed & libc::O_NONBLOCK) == 0 {
            return Err(io::Error::other(
                "O_NONBLOCK was not established on the owned shell stderr pipe",
            ));
        }
    }
    Ok(())
}

/// Caller must have proven the stderr pipe is `O_NONBLOCK`. A blocking `read`
/// here would violate the wall-clock deadline.
#[cfg(unix)]
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

#[cfg(unix)]
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

/// SIGKILL the owned process group and reap the direct child under `deadline`.
///
/// The group signal is the platform's ownership boundary: grandchildren that
/// were reparented to init cannot be `waitpid`'d here. The direct child is
/// reaped only through `Child` so this process never steals std's wait status.
/// After a successful `setpgid(0, 0)`, the child is the group leader; a
/// positive `kill(pid)` is therefore unnecessary, and after the leader has
/// been reaped it would be a PID-reuse hazard.
#[cfg(unix)]
fn terminate_owned_tree(child: &mut Child, deadline: Instant) -> Result<(), io::Error> {
    signal_owned_group(child)?;
    reap_direct_child_until(child, deadline)
}

#[cfg(unix)]
fn signal_owned_group(child: &Child) -> Result<(), io::Error> {
    let pid = child.id() as i32;
    // Safety: `pid` is the child we spawned into its own process group.
    // SIGKILL to `-pid` terminates that group even after the leader has
    // exited. This does not dereference memory.
    if unsafe { libc::kill(-pid, libc::SIGKILL) } != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(error);
        }
    }
    Ok(())
}

#[cfg(unix)]
fn reap_direct_child_until(child: &mut Child, deadline: Instant) -> Result<(), io::Error> {
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return Ok(()),
            Ok(None) => {
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "owned child was not reaped before the deadline",
                    ));
                }
                let slice = deadline
                    .saturating_duration_since(Instant::now())
                    .min(WAIT_POLL);
                if slice.is_zero() {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "owned child was not reaped before the deadline",
                    ));
                }
                std::thread::sleep(slice);
            }
            Err(error) if error.kind() == io::ErrorKind::InvalidInput => return Ok(()),
            Err(error) => return Err(error),
        }
    }
}
