//! Unix-socket listener lifecycle for the in-process SPIFFE Workload API
//! server.
//!
//! [`WorkloadApiService`](super::server::WorkloadApiService) implements the RPCs;
//! this module is the *runtime* half — the piece that actually binds a socket a
//! local workload can dial, serves the gRPC surface on it, and cleans up after
//! itself.
//!
//! ## Socket contract
//!
//! The socket is a credential-adjacent surface: anything that can connect to it
//! can attempt attestation and, if it attests, obtain an SVID. Anything that can
//! *replace* it can impersonate the endpoint workloads dial for their identity.
//! The contract is therefore validated *before* binding and is fail-closed at
//! every step ([`WorkloadApiSocketConfig::validate`]).
//!
//! **Path shape.** The path must be **absolute** and contain no `.` / `..`
//! component, so a relative or traversing path can never resolve somewhere the
//! operator did not name. The check inspects the **raw Unix path segments**
//! rather than [`Path::components`]: that iterator normalizes an embedded `.`
//! away on Unix, so a lexical rejection written in terms of it would silently
//! accept `/trusted/./api.sock` — a path that is not the one the operator wrote.
//!
//! **Every directory component, not just the parent.** Trust in the socket's
//! location is only as strong as the weakest directory on the way to it: a
//! writable `/run` makes a pristine `/run/ferrum/workload-api` worthless,
//! because the whole subtree can be moved aside. So each component from the
//! filesystem root down to the socket's parent is checked with
//! [`classify_directory_component`], and each must be
//!
//! - a **real directory**, never a symlink. Symlinked components are refused
//!   rather than followed: a followed link means the path Ferrum validated and
//!   the path an operator reads in configuration are different objects, and the
//!   link's owner — not the directory's — decides where it points;
//! - owned by this process's **effective uid or by root**, so no untrusted user
//!   owns a directory on the path (a directory's *owner* may always modify its
//!   entries regardless of mode, which is why ownership is checked separately
//!   from permissions);
//! - **not writable by an untrusted actor**: group- or world-writable is
//!   refused unless the directory carries the sticky bit. Sticky is the
//!   `/tmp` semantics that make shared-writable safe here — a non-owner can
//!   create entries but cannot unlink or rename ours. The directory owner
//!   remains able to, which is exactly why the ownership check above is not
//!   redundant with this one.
//!
//! The **parent directory must already exist** — Ferrum does not create it.
//! Creating it would mean choosing its owner and mode on the operator's behalf,
//! and a directory Ferrum creates under a symlink an attacker planted is exactly
//! the escape this refuses.
//!
//! **A live endpoint is never taken over, and a stale one is proven stale.**
//! An artifact at the socket path is only ever removed when it is a socket owned
//! by this process's effective uid — a regular file, a directory, a symlink, or
//! another user's socket is refused outright. Ownership alone is *not* enough,
//! though: a second Ferrum process running as the same uid would otherwise
//! unlink the first one's **live** Workload API socket and take over the path
//! workloads dial for their identity. So before any unlink, the existing socket
//! is probed with a real Unix-domain `connect(2)`
//! ([`probe_existing_socket`]) and
//!
//! - a **successful connection means live**: startup is refused and nothing is
//!   unlinked;
//! - only a **connection-refused / not-listening** result admits the socket as
//!   stale leftover from a crashed run;
//! - **anything ambiguous fails closed** — `EACCES`, `EAGAIN` (a listener whose
//!   backlog is full), a timeout, or any other error. "We could not tell" is
//!   never treated as "nobody is there".
//!
//! Immediately before the unlink the artifact's `(device, inode, type, owner)`
//! is re-checked against what was probed, so a replacement that raced in
//! between is never the thing deleted.
//!
//! **Permissions are established before publication, never through the process
//! umask.** The umask is process-global state; mesh mode has already started
//! admin and background tasks by the time this runs, so narrowing it here would
//! silently change the permissions of unrelated files those tasks create. The
//! socket is instead published in three steps:
//!
//! 1. a **private staging directory** is created under the already-validated
//!    parent with `mkdir(2)` mode `0700`. A requested `0700` can only be
//!    narrowed by a umask, never widened, so the directory is inaccessible to
//!    every other user regardless of ambient state (and its mode is verified
//!    anyway, because a pathological umask could have narrowed it to something
//!    this process cannot itself traverse);
//! 2. the socket is bound **inside** that directory and its mode is set and
//!    verified there. Whatever mode `bind(2)` happened to create it with is
//!    unreachable to anyone else for the whole of that window, so there is never
//!    a permissive temporary endpoint;
//! 3. the socket inode is **renamed** onto the final path — same parent, so the
//!    same filesystem, so the publication is atomic — and re-verified
//!    afterwards: still a socket, still owned by this process, still exactly the
//!    configured mode, and still the same `(device, inode)`. That pair is
//!    recorded as the **bound identity**.
//!
//! If the bound identity cannot be established at any point, startup **fails**
//! and every artifact (staged socket, staging directory, and a published socket
//! that failed its post-rename check) is cleaned up identity-checked. Ferrum
//! does not serve a credential endpoint whose on-disk identity it could not
//! confirm.
//!
//! The staging directory needs room inside `sockaddr_un.sun_path`, so
//! [`WorkloadApiSocketConfig::validate`] additionally requires the socket's
//! parent directory to leave [`MAX_STAGING_SUFFIX_BYTES`] of headroom.
//!
//! On shutdown the socket file is unlinked **only if Ferrum created it and the
//! object is still that same socket** — same device and inode, still of socket
//! type, and still owned by this effective uid. Device+inode alone is an
//! incomplete identity: inode numbers are reused, so a regular file that
//! happened to land on the freed inode would otherwise satisfy the predicate.
//!
//! **What is *not* claimed.** A POSIX Unix socket has no `fbind`/`fchmod` path
//! that reaches the bound filesystem inode (on Linux `fchmod(2)` on a socket fd
//! addresses the anonymous `sockfs` inode, not the bound name), so the checks
//! above are performed on pathnames and are therefore not atomic with respect to
//! a concurrent rename of an ancestor. What the ancestor walk removes is the
//! *ability* of an untrusted actor to perform such a rename in the first place;
//! the bound-identity verification and the inode-checked cleanup bound the
//! damage if a trusted actor (root, or the operator) does so anyway. Ferrum
//! never chmods or unlinks a path it has not just confirmed is the object it
//! bound.
//!
//! Bind, validation, and permission failures are all returned to the caller;
//! mesh startup treats them as fatal when the surface is enabled, so a
//! misconfigured Workload API never degrades silently into "not listening".
//!
//! ## Termination
//!
//! The serve task is spawned, so an unexpected exit — a tonic transport error,
//! or a panic — would otherwise leave the mesh runtime happily serving traffic
//! with no Workload API at all. [`WorkloadApiListener::termination_signal`]
//! publishes that event: the guard that fires it lives *inside* the spawned
//! task, so it is delivered on a panic unwind exactly as on a clean return, and
//! it carries the socket cleanup with it. Mesh mode observes the signal and
//! initiates the shared shutdown path; a requested shutdown races nothing,
//! because the observer checks the shared shutdown flag first and stays quiet.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use super::server::WorkloadApiService;

/// Default socket path for Ferrum's own Workload API surface.
///
/// Deliberately **not** the SPIRE agent convention
/// (`/run/spire/agent/agent.sock`): Ferrum's server and the SPIRE agent it may
/// itself consume are different endpoints, and colliding on one path would let a
/// misconfiguration silently point workloads at the wrong one.
pub const DEFAULT_FERRUM_WORKLOAD_API_SOCKET: &str = "/run/ferrum/workload-api/socket";

/// Default socket permissions: owner + group read/write, nothing for others.
pub const DEFAULT_WORKLOAD_API_SOCKET_MODE: u32 = 0o660;

/// Maximum accepted socket path length. `sockaddr_un.sun_path` is 108 bytes on
/// Linux and 104 on macOS; bind would fail with a bare `EINVAL`, so we refuse
/// with a diagnostic instead.
const MAX_SOCKET_PATH_BYTES: usize = 100;

/// Headroom the private staging directory needs inside `sun_path`, beyond the
/// socket's parent directory: `/` + `.fw-<pid>-<seq>` + `/s`.
///
/// The socket is bound at `<parent>/.fw-<pid>-<seq>/s` before it is renamed onto
/// its configured path, and *that* path is what `bind(2)` has to fit into
/// `sockaddr_un`. `pid` is at most 10 decimal digits and `seq` at most 8 hex
/// digits, so the worst case is `1 + 4 + 10 + 1 + 8 + 2`.
pub const MAX_STAGING_SUFFIX_BYTES: usize = 26;

/// Attempts to find an unused staging-directory name before giving up. A
/// collision needs another process with our pid, so one retry would do; a small
/// bound keeps it deterministic without ever looping.
#[cfg(unix)]
const MAX_STAGING_DIR_ATTEMPTS: u32 = 8;

/// Serial number distinguishing concurrent staging directories in one process.
#[cfg(unix)]
static STAGING_SEQUENCE: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Errors raised while establishing or tearing down the Workload API listener.
#[derive(Debug, thiserror::Error)]
pub enum WorkloadApiListenerError {
    /// The configured socket contract is not satisfiable. The message names the
    /// operator-supplied path, which is configuration they already hold — never
    /// any credential.
    #[error("SPIFFE Workload API socket rejected: {0}")]
    Socket(String),
    /// Bind, chmod, or accept-loop I/O failure.
    #[error("SPIFFE Workload API listener failed: {0}")]
    Io(String),
    /// The platform has no Unix-domain-socket transport.
    #[error("SPIFFE Workload API listener is only supported on Unix platforms")]
    Unsupported,
}

/// Socket-side configuration for the Workload API listener.
#[derive(Debug, Clone)]
pub struct WorkloadApiSocketConfig {
    /// Absolute filesystem path to bind.
    pub socket_path: PathBuf,
    /// Permission bits the published socket carries. Set and verified inside a
    /// private staging directory, then published by rename.
    pub socket_mode: u32,
}

impl Default for WorkloadApiSocketConfig {
    fn default() -> Self {
        Self {
            socket_path: PathBuf::from(DEFAULT_FERRUM_WORKLOAD_API_SOCKET),
            socket_mode: DEFAULT_WORKLOAD_API_SOCKET_MODE,
        }
    }
}

impl WorkloadApiSocketConfig {
    /// Build from an operator-supplied path and octal mode string.
    ///
    /// An unparseable or over-wide mode is an error, not a fallback: silently
    /// substituting a default here would hand the operator a socket with
    /// permissions they did not ask for.
    ///
    /// Two value ranges are refused outright:
    ///
    /// - **world-writable** (`0o002`), because any local process could then
    ///   impersonate the endpoint;
    /// - **no owner or group write bit** (`0o220`), because `connect(2)` to a
    ///   Unix socket requires *write* permission on the socket file. A mode such
    ///   as `0000` or `0440` parses and binds happily and then rejects every
    ///   workload with `EACCES`, which contradicts the whole point of the
    ///   fail-closed startup contract: a successful start must mean workloads
    ///   can actually connect.
    pub fn from_parts(
        socket_path: impl Into<PathBuf>,
        socket_mode: &str,
    ) -> Result<Self, WorkloadApiListenerError> {
        let raw = socket_mode.trim();
        let mode = if raw.is_empty() {
            DEFAULT_WORKLOAD_API_SOCKET_MODE
        } else {
            let digits = raw.strip_prefix("0o").unwrap_or(raw);
            u32::from_str_radix(digits, 8).map_err(|_| {
                WorkloadApiListenerError::Socket(format!(
                    "socket mode '{socket_mode}' is not an octal permission value such as 0660"
                ))
            })?
        };
        if mode & !0o777 != 0 {
            return Err(WorkloadApiListenerError::Socket(format!(
                "socket mode '{socket_mode}' sets bits outside the permission range"
            )));
        }
        if mode & 0o002 != 0 {
            return Err(WorkloadApiListenerError::Socket(format!(
                "socket mode '{socket_mode}' is world-writable; any local process could then \
                 impersonate the Workload API endpoint"
            )));
        }
        if mode & 0o220 == 0 {
            return Err(WorkloadApiListenerError::Socket(format!(
                "socket mode '{socket_mode}' grants no owner or group write bit, and connecting to \
                 a Unix socket requires write permission; no workload could reach the endpoint. \
                 Use a mode such as 0660 that grants the workload's group"
            )));
        }
        Ok(Self {
            socket_path: socket_path.into(),
            socket_mode: mode,
        })
    }

    /// Validate the socket contract described in the module docs.
    ///
    /// Runs before any bind so a misconfiguration is reported as configuration
    /// rather than as a bind failure. Covers the path shape and **every**
    /// directory component down to the socket's parent.
    pub fn validate(&self) -> Result<(), WorkloadApiListenerError> {
        let path = self.socket_path.as_path();
        if !path.is_absolute() {
            return Err(WorkloadApiListenerError::Socket(format!(
                "path '{}' must be absolute",
                path.display()
            )));
        }
        // Traversal is refused on the *lexical* path rather than resolved away:
        // an operator-facing setting should mean exactly what it says, and a
        // `..` component is either a mistake or an attempt to escape the
        // directory the deployment mounted. Inspected on raw segments, because
        // `Path::components()` drops an embedded `.` on Unix and a check written
        // over it would not actually enforce what this message promises.
        if has_dot_segment(path) {
            return Err(WorkloadApiListenerError::Socket(format!(
                "path '{}' must not contain '.' or '..' components",
                path.display()
            )));
        }
        if path.as_os_str().is_empty() || path.file_name().is_none() {
            return Err(WorkloadApiListenerError::Socket(
                "path names no socket file".to_string(),
            ));
        }
        if path.as_os_str().len() > MAX_SOCKET_PATH_BYTES {
            return Err(WorkloadApiListenerError::Socket(format!(
                "path '{}' is longer than the {MAX_SOCKET_PATH_BYTES}-byte Unix-socket limit",
                path.display()
            )));
        }

        let parent = path.parent().ok_or_else(|| {
            WorkloadApiListenerError::Socket(format!(
                "path '{}' has no parent directory",
                path.display()
            ))
        })?;
        // The socket is bound inside a private staging directory under this
        // parent and only then renamed into place, so it is the *staging* path
        // that has to fit `sockaddr_un.sun_path`.
        let max_parent = MAX_SOCKET_PATH_BYTES.saturating_sub(MAX_STAGING_SUFFIX_BYTES);
        if parent.as_os_str().len() > max_parent {
            return Err(WorkloadApiListenerError::Socket(format!(
                "the socket's parent directory '{}' leaves no room for the private staging \
                 directory the socket is published from; keep the parent within {max_parent} bytes",
                parent.display()
            )));
        }
        validate_parent_directory(parent)?;
        Ok(())
    }
}

/// Whether any raw path segment is exactly `.` or `..`.
///
/// Deliberately not written over [`Path::components`]: that iterator normalizes
/// `CurDir` away for anything but a leading `.`, so `/trusted/./api.sock` would
/// pass a check built on it while still not being the path the operator wrote.
#[cfg(unix)]
fn has_dot_segment(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    path.as_os_str()
        .as_bytes()
        .split(|byte| *byte == b'/')
        .any(|segment| segment == b"." || segment == b"..")
}

#[cfg(not(unix))]
fn has_dot_segment(path: &Path) -> bool {
    use std::path::Component;
    path.components()
        .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
}

/// A running Workload API listener.
///
/// Dropping the handle does **not** stop the server; call
/// [`WorkloadApiListener::shutdown`] so the serve future completes and the
/// socket artifact is cleaned up deterministically.
pub struct WorkloadApiListener {
    socket_path: PathBuf,
    shutdown_tx: watch::Sender<bool>,
    terminated_rx: watch::Receiver<bool>,
    join: JoinHandle<()>,
}

impl fmt::Debug for WorkloadApiListener {
    /// Only the bound path — operator-supplied configuration they already hold.
    /// Nothing about the served identities or their material.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WorkloadApiListener")
            .field("socket_path", &self.socket_path)
            .finish_non_exhaustive()
    }
}

impl WorkloadApiListener {
    /// The bound socket path, for diagnostics and for tests that dial it.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// A receiver that flips to `true` when the serve task has ended, **for any
    /// reason at all** — requested shutdown, transport error, or panic.
    ///
    /// The sender lives in a drop guard inside the spawned task, so a panic
    /// unwind publishes it exactly as a clean return does. The signal on its own
    /// says nothing about *why* the task ended; a caller that cares (mesh mode
    /// does) distinguishes a requested stop by checking its own shutdown state
    /// first, which is deterministic because that flag is always set before
    /// [`Self::shutdown`] is called.
    pub fn termination_signal(&self) -> watch::Receiver<bool> {
        self.terminated_rx.clone()
    }

    /// Signal the serve future to stop, wait for it, and unlink the socket we
    /// created.
    ///
    /// Idempotent with respect to a server that has already exited.
    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        if let Err(error) = self.join.await
            && !error.is_cancelled()
        {
            warn!(
                error = %error,
                "SPIFFE Workload API server task failed while stopping"
            );
        }
        info!(
            socket = %self.socket_path.display(),
            "SPIFFE Workload API listener stopped"
        );
    }
}

/// Runs the identity-checked socket cleanup and publishes the termination
/// signal when the serve task ends.
///
/// A drop guard rather than trailing statements: the task is spawned, so a panic
/// inside tonic would otherwise skip both, leaving a stale socket on disk *and*
/// a mesh runtime that never learns its Workload API is gone.
#[cfg(unix)]
struct ServeExitGuard {
    socket_path: PathBuf,
    bound_identity: Option<(u64, u64)>,
    terminated_tx: watch::Sender<bool>,
}

#[cfg(unix)]
impl Drop for ServeExitGuard {
    fn drop(&mut self) {
        cleanup_owned_socket(&self.socket_path, self.bound_identity);
        let _ = self.terminated_tx.send(true);
    }
}

/// Bind the socket, serve [`WorkloadApiService`] on it, and return a handle.
///
/// The socket exists and is correctly permissioned by the time this returns, so
/// a caller that treats an `Err` as fatal can be certain that a successful
/// startup means workloads can actually connect.
#[cfg(unix)]
pub async fn serve_workload_api(
    service: WorkloadApiService,
    config: WorkloadApiSocketConfig,
) -> Result<WorkloadApiListener, WorkloadApiListenerError> {
    use tokio_stream::wrappers::UnixListenerStream;

    config.validate()?;
    let path = config.socket_path.clone();
    refuse_live_or_clear_stale_socket(&path)?;

    let (listener, bound_identity) = bind_and_publish_socket(&path, config.socket_mode)?;

    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let (terminated_tx, terminated_rx) = watch::channel(false);
    // Built here rather than inside the spawned task so the receiver is moved
    // into exactly one future and its mutability is unambiguous.
    let shutdown_signal = async move {
        while !*shutdown_rx.borrow() {
            if shutdown_rx.changed().await.is_err() {
                return;
            }
        }
    };
    let incoming = UnixListenerStream::new(listener);
    let server = service.into_server();
    let guard = ServeExitGuard {
        socket_path: path.clone(),
        bound_identity: Some(bound_identity),
        terminated_tx,
    };
    let join = tokio::spawn(async move {
        // Bound first so it drops LAST — after the serve future, and on a panic
        // unwind as well as on a clean return.
        let exit_guard = guard;
        let result = tonic::transport::Server::builder()
            .add_service(server)
            .serve_with_incoming_shutdown(incoming, shutdown_signal)
            .await;
        if let Err(error) = result {
            warn!(
                error = %error,
                socket = %exit_guard.socket_path.display(),
                "SPIFFE Workload API server exited with an error"
            );
        }
    });

    info!(
        socket = %path.display(),
        mode = format!("{:#o}", config.socket_mode),
        "SPIFFE Workload API listener bound"
    );
    Ok(WorkloadApiListener {
        socket_path: path,
        shutdown_tx,
        terminated_rx,
        join,
    })
}

#[cfg(not(unix))]
pub async fn serve_workload_api(
    _service: WorkloadApiService,
    _config: WorkloadApiSocketConfig,
) -> Result<WorkloadApiListener, WorkloadApiListenerError> {
    Err(WorkloadApiListenerError::Unsupported)
}

/// A private, `0700`, per-attempt directory the socket is bound inside before it
/// is published.
///
/// This is what replaces the process-global umask narrowing the listener used to
/// perform. `mkdir(2)`'s mode argument is masked by the umask, so a requested
/// `0700` can only ever come out *narrower* — never wider — which is exactly the
/// property that makes it safe without touching process-global state. Nothing
/// but this process (and root) can traverse it, so the interval between `bind`
/// and the mode being set is not observable to any other user.
#[cfg(unix)]
struct StagingDir {
    path: PathBuf,
}

#[cfg(unix)]
impl StagingDir {
    /// Create the staging directory under `parent`, verifying that what landed
    /// on disk really is our own private `0700` directory.
    fn create(parent: &Path) -> Result<Self, WorkloadApiListenerError> {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
        use std::sync::atomic::Ordering;

        let pid = std::process::id();
        for _ in 0..MAX_STAGING_DIR_ATTEMPTS {
            let sequence = STAGING_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = parent.join(format!(".fw-{pid}-{sequence:x}"));
            // Re-checked here as well as in `validate`: the bound is what keeps
            // the staged bind inside `sockaddr_un.sun_path`, and a bare `EINVAL`
            // from `bind` would be an unreadable failure.
            if path.as_os_str().len() + 2 > MAX_SOCKET_PATH_BYTES {
                return Err(WorkloadApiListenerError::Socket(format!(
                    "the socket's parent directory '{}' leaves no room for the private staging \
                     directory the socket is published from",
                    parent.display()
                )));
            }
            match std::fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(WorkloadApiListenerError::Io(format!(
                        "cannot create the private staging directory '{}': {error}",
                        path.display()
                    )));
                }
            }
            let staging = Self { path };

            // Prove what we just created. A pathological umask can narrow `0700`
            // to something this process cannot itself traverse, and a broken
            // filesystem could ignore the mode entirely; neither may be served
            // through.
            let metadata = std::fs::symlink_metadata(&staging.path).map_err(|error| {
                WorkloadApiListenerError::Io(format!(
                    "cannot inspect the private staging directory '{}': {error}",
                    staging.path.display()
                ))
            })?;
            let effective_uid = unsafe { libc::geteuid() };
            if !metadata.is_dir()
                || metadata.file_type().is_symlink()
                || metadata.uid() != effective_uid
            {
                return Err(WorkloadApiListenerError::Io(format!(
                    "the private staging directory '{}' is not the directory this process just \
                     created",
                    staging.path.display()
                )));
            }
            if metadata.mode() & 0o777 != 0o700 {
                std::fs::set_permissions(&staging.path, std::fs::Permissions::from_mode(0o700))
                    .map_err(|error| {
                        WorkloadApiListenerError::Io(format!(
                            "cannot set mode 0700 on the private staging directory '{}': {error}",
                            staging.path.display()
                        ))
                    })?;
                let after = std::fs::symlink_metadata(&staging.path).map_err(|error| {
                    WorkloadApiListenerError::Io(format!(
                        "cannot re-inspect the private staging directory '{}': {error}",
                        staging.path.display()
                    ))
                })?;
                if after.mode() & 0o777 != 0o700
                    || (after.dev(), after.ino()) != (metadata.dev(), metadata.ino())
                {
                    return Err(WorkloadApiListenerError::Io(format!(
                        "the private staging directory '{}' could not be confirmed private",
                        staging.path.display()
                    )));
                }
            }
            return Ok(staging);
        }
        Err(WorkloadApiListenerError::Io(format!(
            "could not create a private staging directory under '{}' after \
             {MAX_STAGING_DIR_ATTEMPTS} attempts",
            parent.display()
        )))
    }

    /// The path the socket is bound at while it is being permissioned. One
    /// character, because the whole staging path has to fit `sun_path`.
    fn socket_path(&self) -> PathBuf {
        self.path.join("s")
    }
}

#[cfg(unix)]
impl Drop for StagingDir {
    /// Best-effort teardown on every path, success or failure. After a
    /// successful publication the staged socket has already been renamed away,
    /// so only the empty directory remains.
    fn drop(&mut self) {
        remove_self_owned_socket_best_effort(&self.socket_path());
        let _ = std::fs::remove_dir(&self.path);
    }
}

/// Bind the socket inside a private staging directory, permission it there, and
/// publish it onto `path` by rename.
///
/// Returns the listener together with the published `(device, inode)` identity.
/// Every failure leaves no artifact behind: the staging directory's `Drop`
/// removes the staged socket, and a post-publication verification failure
/// removes the published one identity-checked.
#[cfg(unix)]
fn bind_and_publish_socket(
    path: &Path,
    socket_mode: u32,
) -> Result<(tokio::net::UnixListener, (u64, u64)), WorkloadApiListenerError> {
    use std::os::unix::fs::PermissionsExt;

    let parent = path.parent().ok_or_else(|| {
        WorkloadApiListenerError::Socket(format!(
            "path '{}' has no parent directory",
            path.display()
        ))
    })?;
    let staging = StagingDir::create(parent)?;
    let staged_path = staging.socket_path();

    let listener = tokio::net::UnixListener::bind(&staged_path).map_err(|error| {
        WorkloadApiListenerError::Io(format!("bind '{}' failed: {error}", path.display()))
    })?;

    // Permission it while it is still unreachable to every other user. The mode
    // `bind(2)` happened to apply is never exposed.
    std::fs::set_permissions(&staged_path, std::fs::Permissions::from_mode(socket_mode)).map_err(
        |error| {
            WorkloadApiListenerError::Io(format!(
                "setting mode {socket_mode:#o} on the staged Workload API socket failed: {error}"
            ))
        },
    )?;
    let staged_identity = confirm_socket_identity(&staged_path, socket_mode, "in staging")?;

    // Publication. Same parent directory, therefore the same filesystem, so the
    // rename is atomic: a workload either sees no socket or sees the finished,
    // correctly permissioned one.
    std::fs::rename(&staged_path, path).map_err(|error| {
        WorkloadApiListenerError::Io(format!(
            "publishing the Workload API socket at '{}' failed: {error}",
            path.display()
        ))
    })?;

    match confirm_socket_identity(path, socket_mode, "after publication") {
        Ok(published_identity) if published_identity == staged_identity => {
            Ok((listener, published_identity))
        }
        Ok(_) => {
            drop(listener);
            cleanup_owned_socket(path, Some(staged_identity));
            Err(WorkloadApiListenerError::Io(format!(
                "the socket published at '{}' is not the inode this process bound; refusing to \
                 serve it",
                path.display()
            )))
        }
        Err(error) => {
            drop(listener);
            cleanup_owned_socket(path, Some(staged_identity));
            Err(error)
        }
    }
}

/// Confirm the artifact at `path` is a socket owned by this process carrying
/// exactly `expected_mode`, and return its `(device, inode)` identity.
///
/// A Unix socket gives no descriptor-based route to its bound filesystem inode,
/// so identity is established by stat'ing the name; `stage` names which of the
/// two checks (in staging, after publication) is reporting.
#[cfg(unix)]
fn confirm_socket_identity(
    path: &Path,
    expected_mode: u32,
    stage: &str,
) -> Result<(u64, u64), WorkloadApiListenerError> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    let effective_uid = unsafe { libc::geteuid() };
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        WorkloadApiListenerError::Io(format!(
            "cannot confirm the Workload API socket at '{}' ({stage}): {error}",
            path.display()
        ))
    })?;
    if !metadata.file_type().is_socket() {
        return Err(WorkloadApiListenerError::Io(format!(
            "'{}' is not a socket ({stage}); refusing to serve an endpoint whose on-disk identity \
             cannot be established",
            path.display()
        )));
    }
    if metadata.uid() != effective_uid {
        return Err(WorkloadApiListenerError::Io(format!(
            "the artifact at '{}' is owned by another user ({stage}); it is not the socket this \
             process created",
            path.display()
        )));
    }
    if metadata.mode() & 0o777 != expected_mode {
        return Err(WorkloadApiListenerError::Io(format!(
            "the socket at '{}' does not carry the configured mode {expected_mode:#o} ({stage}); \
             refusing to serve an endpoint whose permissions cannot be confirmed",
            path.display()
        )));
    }
    Ok((metadata.dev(), metadata.ino()))
}

/// Remove the artifact at `path` only if it is a socket owned by this process.
///
/// Used for staging teardown, where there is no confirmed identity to compare
/// against. Ownership plus file-type is the strongest check available there, and
/// it still refuses to delete another user's data or a non-socket.
#[cfg(unix)]
fn remove_self_owned_socket_best_effort(path: &Path) {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return;
    };
    let effective_uid = unsafe { libc::geteuid() };
    if !metadata.file_type().is_socket() || metadata.uid() != effective_uid {
        return;
    }
    let _ = std::fs::remove_file(path);
}

/// `(device, inode)` of the object at `path`, but **only** when it is still a
/// socket owned by this process's effective uid.
///
/// Type and ownership are part of the identity rather than a separate check:
/// inode numbers are reused, so a regular file that happens to land on the
/// freed inode would otherwise satisfy a device+inode-only predicate and be
/// unlinked as if it were our socket.
#[cfg(unix)]
fn owned_socket_identity(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let metadata = std::fs::symlink_metadata(path).ok()?;
    let identity = (metadata.dev(), metadata.ino());
    let effective_uid = unsafe { libc::geteuid() };
    // `identity` as its own "recorded" value reduces the predicate to exactly
    // the type + ownership half here; the caller compares the pair.
    matches_bound_socket_identity(
        metadata.file_type().is_socket(),
        metadata.uid(),
        identity,
        effective_uid,
        identity,
    )
    .then_some(identity)
}

#[cfg(not(unix))]
fn owned_socket_identity(_path: &Path) -> Option<(u64, u64)> {
    None
}

/// Whether an observed on-disk object is the **exact socket** recorded as bound.
///
/// Separated from the filesystem so the policy can be exercised over shapes a
/// test cannot force on disk — notably inode reuse, where a regular file lands
/// on the number a deleted socket freed. `(device, inode)` alone is an
/// incomplete identity precisely because inode numbers are recycled; type and
/// ownership are part of what "our socket" means, not extra checks alongside it.
pub fn matches_bound_socket_identity(
    is_socket: bool,
    uid: u32,
    identity: (u64, u64),
    effective_uid: u32,
    bound_identity: (u64, u64),
) -> bool {
    is_socket && uid == effective_uid && identity == bound_identity
}

/// Unlink the socket at `path` only when it is still the exact socket we bound.
#[cfg(unix)]
fn cleanup_owned_socket(path: &Path, bound_identity: Option<(u64, u64)>) {
    let Some(bound_identity) = bound_identity else {
        return;
    };
    if owned_socket_identity(path) != Some(bound_identity) {
        // Somebody else's socket (or nothing, or an object of another type) is
        // here now. Removing it would be destructive to a process that
        // legitimately took over the path.
        return;
    }
    if let Err(error) = std::fs::remove_file(path)
        && error.kind() != io::ErrorKind::NotFound
    {
        warn!(
            error = %error,
            socket = %path.display(),
            "failed to remove the SPIFFE Workload API socket on shutdown"
        );
    }
}

#[cfg(not(unix))]
fn cleanup_owned_socket(_path: &Path, _bound_identity: Option<(u64, u64)>) {}

/// What a `connect(2)` probe learned about an existing socket at the path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketLiveness {
    /// A connection succeeded: something is listening right now.
    Live,
    /// The kernel reported that nobody is listening (`ECONNREFUSED`) or that the
    /// name has since vanished. Only this verdict admits an unlink.
    NotListening,
    /// The probe could not decide — `EACCES`, a full backlog, a timeout, any
    /// other error. Fail closed.
    Undetermined,
}

/// Probe whether an existing socket path has a live listener behind it.
///
/// Exposed so the *policy* can be tested directly. The kernel error kind is the
/// only evidence available: `ECONNREFUSED` is the definitive "the inode exists
/// but no process has it bound and listening" signal a crashed predecessor
/// leaves behind, and everything else is either a live listener or an answer we
/// did not get.
pub fn classify_connect_result(result: &io::Result<()>) -> SocketLiveness {
    match result {
        Ok(()) => SocketLiveness::Live,
        Err(error) => match error.kind() {
            io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound => {
                SocketLiveness::NotListening
            }
            _ => SocketLiveness::Undetermined,
        },
    }
}

/// Attempt a Unix-domain connection to `path` and classify the outcome.
#[cfg(unix)]
fn probe_existing_socket(path: &Path) -> SocketLiveness {
    let result = std::os::unix::net::UnixStream::connect(path).map(|stream| {
        // Close immediately: the probe is the connection, not anything on it.
        drop(stream);
    });
    classify_connect_result(&result)
}

/// Refuse a live endpoint, and remove a leftover socket from a previous run.
///
/// A crashed process leaves its socket behind and `bind` would fail with
/// `EADDRINUSE`, so a stale artifact has to be cleared. Ownership alone is not
/// evidence of staleness — a second Ferrum process running as the same uid would
/// otherwise unlink a *live* peer's socket and take over the path workloads dial
/// for their identity — so liveness is established positively with a real
/// `connect(2)`, and anything the probe cannot decide fails closed.
///
/// A regular file, a directory, a symlink, or another user's socket is refused
/// outright rather than deleted.
#[cfg(unix)]
fn refuse_live_or_clear_stale_socket(path: &Path) -> Result<(), WorkloadApiListenerError> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(WorkloadApiListenerError::Socket(format!(
                "cannot inspect existing path '{}': {error}",
                path.display()
            )));
        }
    };
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(WorkloadApiListenerError::Socket(format!(
            "'{}' is a symlink; refusing to bind through it or replace it",
            path.display()
        )));
    }
    if !file_type.is_socket() {
        return Err(WorkloadApiListenerError::Socket(format!(
            "'{}' already exists and is not a socket; refusing to replace it",
            path.display()
        )));
    }
    // SAFETY-equivalent reasoning: `geteuid` is a pure read of process
    // credentials with no failure mode.
    let effective_uid = unsafe { libc::geteuid() };
    if metadata.uid() != effective_uid {
        return Err(WorkloadApiListenerError::Socket(format!(
            "'{}' is an existing socket owned by another user; refusing to remove it",
            path.display()
        )));
    }

    match probe_existing_socket(path) {
        SocketLiveness::Live => {
            return Err(WorkloadApiListenerError::Socket(format!(
                "'{}' is a SPIFFE Workload API socket that is currently LIVE — another process is \
                 listening on it. Refusing to unlink it and take over the endpoint workloads dial \
                 for their identity; stop that process or configure a different \
                 FERRUM_MESH_WORKLOAD_API_SOCKET_PATH",
                path.display()
            )));
        }
        SocketLiveness::Undetermined => {
            return Err(WorkloadApiListenerError::Socket(format!(
                "'{}' is an existing socket whose liveness could not be determined; refusing to \
                 unlink a socket that may still be serving workloads",
                path.display()
            )));
        }
        SocketLiveness::NotListening => {}
    }

    // Re-check the exact identity immediately before the unlink: between the
    // stat above and here a successor may have replaced the path, and deleting
    // *that* is the destructive act the probe exists to prevent.
    let probed_identity = (metadata.dev(), metadata.ino());
    match owned_socket_identity(path) {
        None => {
            // Gone (or no longer ours) — nothing of ours to remove, and nothing
            // we are entitled to remove either.
            return Ok(());
        }
        Some(identity) if identity != probed_identity => {
            return Err(WorkloadApiListenerError::Socket(format!(
                "the socket at '{}' was replaced while it was being checked; refusing to unlink \
                 the replacement",
                path.display()
            )));
        }
        Some(_) => {}
    }

    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(WorkloadApiListenerError::Socket(format!(
                "cannot remove the stale socket at '{}': {error}",
                path.display()
            )));
        }
    }
    warn!(
        socket = %path.display(),
        "removed a stale SPIFFE Workload API socket left by a previous run"
    );
    Ok(())
}

#[cfg(not(unix))]
fn refuse_live_or_clear_stale_socket(_path: &Path) -> Result<(), WorkloadApiListenerError> {
    Err(WorkloadApiListenerError::Unsupported)
}

/// Why one directory component of the socket path is or is not trustworthy.
///
/// Separated from the filesystem so the *policy* can be exercised exhaustively
/// in tests over every `(uid, mode)` shape, including ones a non-root test
/// process cannot create on disk (a directory owned by an unrelated user).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectoryTrustVerdict {
    /// The component is a real directory, trustworthily owned, and not mutable
    /// by an untrusted actor.
    Trusted,
    /// The component is a symlink. Refused rather than followed.
    Symlink,
    /// The component exists but is not a directory.
    NotADirectory,
    /// Owned by neither this process's effective uid nor root. The owner of a
    /// directory may always modify its entries, whatever the mode says.
    UntrustedOwner,
    /// Group- or world-writable without the sticky bit, so a non-owner can
    /// unlink or rename entries — including the socket.
    UntrustedlyWritable,
}

impl DirectoryTrustVerdict {
    /// Operator-facing explanation. Names no path — the caller interpolates the
    /// component it was checking.
    #[cfg(unix)]
    fn reason(self) -> &'static str {
        match self {
            Self::Trusted => "is trusted",
            Self::Symlink => {
                "is a symlink; name the real directory, because a link's owner rather than the \
                 directory's decides where the Workload API socket is created"
            }
            Self::NotADirectory => "is not a directory",
            Self::UntrustedOwner => {
                "is owned by neither this process nor root; its owner may replace entries \
                 regardless of its mode, so it could redirect or replace the Workload API socket"
            }
            Self::UntrustedlyWritable => {
                "is group- or world-writable without the sticky bit, so a local user who is not \
                 its owner could unlink or rename the Workload API socket"
            }
        }
    }
}

/// The pure directory-trust predicate the socket contract is defined by.
///
/// `mode` is the raw `st_mode` permission word (the sticky bit is `0o1000`).
/// A directory is trusted when it is a real directory, owned by `effective_uid`
/// or by root, and not writable by anyone who is not its owner:
///
/// - `0o022` (group- **or** world-writable) is the untrusted-mutation test.
///   Group-writable is deliberately included: a member of that group is an
///   untrusted actor exactly as a world user is.
/// - the sticky bit rescues a shared-writable directory (`/tmp`, `/run` on some
///   distributions), because it restricts unlink/rename to the entry's owner,
///   the directory's owner, and root. That **directory-owner exception** is why
///   ownership is checked independently and not folded into the mode test:
///   sticky does not constrain the directory's own owner at all.
pub fn classify_directory_component(
    is_symlink: bool,
    is_dir: bool,
    uid: u32,
    mode: u32,
    effective_uid: u32,
) -> DirectoryTrustVerdict {
    if is_symlink {
        return DirectoryTrustVerdict::Symlink;
    }
    if !is_dir {
        return DirectoryTrustVerdict::NotADirectory;
    }
    if uid != effective_uid && uid != 0 {
        return DirectoryTrustVerdict::UntrustedOwner;
    }
    if mode & 0o022 != 0 && mode & 0o1000 == 0 {
        return DirectoryTrustVerdict::UntrustedlyWritable;
    }
    DirectoryTrustVerdict::Trusted
}

/// Ownership and mode checks on **every** directory from the filesystem root
/// down to (and including) the directory the socket will live in.
///
/// Checking only the immediate parent is not sufficient: an untrusted actor who
/// controls any ancestor can rename the whole subtree aside and substitute one
/// of their own, so a pristine parent proves nothing about where the socket
/// actually ends up. Each prefix is inspected with `symlink_metadata`, so a
/// symlinked component is *observed* rather than silently traversed.
#[cfg(unix)]
fn validate_parent_directory(parent: &Path) -> Result<(), WorkloadApiListenerError> {
    use std::os::unix::fs::MetadataExt;

    let effective_uid = unsafe { libc::geteuid() };
    let mut prefix = PathBuf::new();
    for component in parent.components() {
        prefix.push(component.as_os_str());
        let metadata = std::fs::symlink_metadata(&prefix).map_err(|error| {
            WorkloadApiListenerError::Socket(format!(
                "directory '{}' on the socket path is not usable: {error}. Create the socket's \
                 parent directory (with the ownership and mode you want) before enabling the \
                 Workload API surface",
                prefix.display()
            ))
        })?;
        let verdict = classify_directory_component(
            metadata.file_type().is_symlink(),
            metadata.is_dir(),
            metadata.uid(),
            metadata.mode(),
            effective_uid,
        );
        if verdict != DirectoryTrustVerdict::Trusted {
            return Err(WorkloadApiListenerError::Socket(format!(
                "directory '{}' on the socket path {}",
                prefix.display(),
                verdict.reason()
            )));
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_parent_directory(_parent: &Path) -> Result<(), WorkloadApiListenerError> {
    Err(WorkloadApiListenerError::Unsupported)
}
