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
//! operator did not name.
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
//! **Existing artifacts are never clobbered.** An artifact at the socket path is
//! removed **only** when it is a socket *and* owned by this process's effective
//! uid. A regular file, a directory, a symlink, or another user's socket is
//! refused — that is somebody else's data, and deleting it is both destructive
//! and a way to be tricked into unlinking an arbitrary path.
//!
//! **Permissions are established at creation, then proven.** The socket is bound
//! under a temporarily narrowed `umask`, so the kernel applies the configured
//! mode *as part of* `bind(2)` and there is no window at the process umask at
//! all. Immediately afterwards the bound path is re-stat'ed and must be a socket
//! owned by this process with exactly the configured mode; that `(dev, ino)` is
//! recorded as the **bound identity**. If a platform ignores the umask, a
//! path-based `chmod` is attempted only while the path still resolves to that
//! same identity, and the result is re-verified. If the bound identity cannot be
//! established at all, startup **fails** and the artifact is cleaned up
//! identity-checked — Ferrum does not serve a credential endpoint whose on-disk
//! identity it could not confirm.
//!
//! On shutdown the socket file is unlinked **only if Ferrum created it and it is
//! still the same socket** (same device + inode as the one bound), so a
//! restarted peer's socket at the same path is never removed by a late shutdown
//! of the previous process.
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

use std::fmt;
use std::io;
use std::path::{Component, Path, PathBuf};

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
    /// Permission bits the bound socket is created with (applied through the
    /// umask at `bind`, then verified).
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
        // directory the deployment mounted.
        if path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
        {
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
        validate_parent_directory(parent)?;
        Ok(())
    }
}

/// A running Workload API listener.
///
/// Dropping the handle does **not** stop the server; call
/// [`WorkloadApiListener::shutdown`] so the serve future completes and the
/// socket artifact is cleaned up deterministically.
pub struct WorkloadApiListener {
    socket_path: PathBuf,
    shutdown_tx: watch::Sender<bool>,
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
    use tokio::net::UnixListener;
    use tokio_stream::wrappers::UnixListenerStream;

    config.validate()?;
    let path = config.socket_path.clone();
    remove_owned_stale_socket(&path)?;

    // Bind under a narrowed umask so the kernel applies the configured mode as
    // part of creating the socket inode. There is then no interval in which the
    // endpoint exists at whatever the process umask happened to be — a
    // post-bind `chmod` can only ever shrink that window, never remove it.
    let listener = {
        let _umask = ScopedUmask::narrowing_to(config.socket_mode);
        UnixListener::bind(&path).map_err(|e| {
            WorkloadApiListenerError::Io(format!("bind '{}' failed: {e}", path.display()))
        })?
    };

    // Establish the bound identity and prove the mode. A failure here is fatal
    // and the artifact is removed identity-checked: serving a credential
    // endpoint whose on-disk identity or permissions we could not confirm is
    // exactly the silent-downgrade this refuses.
    let bound_identity = match confirm_bound_socket(&path, config.socket_mode) {
        Ok(identity) => Some(identity),
        Err(error) => {
            drop(listener);
            remove_self_owned_socket_best_effort(&path);
            return Err(error);
        }
    };

    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
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
    let cleanup_path = path.clone();
    let server = service.into_server();
    let join = tokio::spawn(async move {
        let result = tonic::transport::Server::builder()
            .add_service(server)
            .serve_with_incoming_shutdown(incoming, shutdown_signal)
            .await;
        if let Err(error) = result {
            warn!(
                error = %error,
                socket = %cleanup_path.display(),
                "SPIFFE Workload API server exited with an error"
            );
        }
        // Clean up ONLY our own artifact: if the inode at this path is no
        // longer the socket we bound, another process owns it now.
        cleanup_owned_socket(&cleanup_path, bound_identity);
    });

    info!(
        socket = %path.display(),
        mode = format!("{:#o}", config.socket_mode),
        "SPIFFE Workload API listener bound"
    );
    Ok(WorkloadApiListener {
        socket_path: path,
        shutdown_tx,
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

/// Narrow the process umask for the duration of a bind, then restore it.
///
/// The umask is process-global, which is why the guard exists at all: it is held
/// across exactly one `bind(2)` and restored on drop, including on the error
/// path. Startup is the only place this runs — the Workload API listener is
/// bound once, before the serving runtime is doing anything else that creates
/// files — so the global window is a single syscall pair rather than a mode a
/// later file creation could inherit.
///
/// This is the only mechanism that gives a Unix socket its permissions
/// atomically. `fchmod(2)` is not an alternative: on Linux a socket file
/// descriptor's `f_path` is the anonymous `sockfs` inode, not the bound name, so
/// `fchmod` on it would "succeed" while leaving the bound path untouched.
#[cfg(unix)]
struct ScopedUmask {
    previous: libc::mode_t,
}

#[cfg(unix)]
impl ScopedUmask {
    /// Set the umask to the complement of `mode`, so a file created with
    /// permission bits `0o777` lands at exactly `mode`.
    // `mode_t` is `u32` on Linux but `u16` on the BSDs/macOS, so the cast is
    // load-bearing on some targets even where it is an identity on others.
    #[allow(clippy::unnecessary_cast)]
    fn narrowing_to(mode: u32) -> Self {
        // SAFETY: `umask` is an infallible process-credential call that returns
        // the previous mask; it has no failure mode and no memory effects.
        let previous = unsafe { libc::umask((!mode & 0o777) as libc::mode_t) };
        Self { previous }
    }
}

#[cfg(unix)]
impl Drop for ScopedUmask {
    fn drop(&mut self) {
        // SAFETY: as above.
        unsafe {
            libc::umask(self.previous);
        }
    }
}

/// Confirm the artifact at `path` is the socket this process just bound, with
/// exactly `expected_mode`, and return its `(device, inode)` identity.
///
/// This is the "fail startup if the bound identity cannot be established" step.
/// A Unix socket gives no descriptor-based route to its bound filesystem inode,
/// so identity is established by stat'ing the name and requiring it to be a
/// socket owned by this process's effective uid; anything else means the name we
/// bound is no longer the object at that name.
///
/// The chmod fallback exists only for a platform that ignored the umask. It is
/// performed *between two identity checks* so Ferrum can never chmod an artifact
/// it has not just confirmed is its own — the failure mode the pathname-based
/// approach otherwise has.
#[cfg(unix)]
fn confirm_bound_socket(
    path: &Path,
    expected_mode: u32,
) -> Result<(u64, u64), WorkloadApiListenerError> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};

    let effective_uid = unsafe { libc::geteuid() };
    let inspect = |stage: &str| -> Result<(u64, u64, u32), WorkloadApiListenerError> {
        let metadata = std::fs::symlink_metadata(path).map_err(|error| {
            WorkloadApiListenerError::Io(format!(
                "cannot confirm the bound Workload API socket at '{}' ({stage}): {error}",
                path.display()
            ))
        })?;
        if !metadata.file_type().is_socket() {
            return Err(WorkloadApiListenerError::Io(format!(
                "'{}' is not a socket after bind ({stage}); refusing to serve an endpoint whose \
                 on-disk identity cannot be established",
                path.display()
            )));
        }
        if metadata.uid() != effective_uid {
            return Err(WorkloadApiListenerError::Io(format!(
                "the artifact at '{}' is owned by another user after bind ({stage}); it is not \
                 the socket this process created",
                path.display()
            )));
        }
        Ok((metadata.dev(), metadata.ino(), metadata.mode() & 0o777))
    };

    let (dev, ino, mode) = inspect("after bind")?;
    if mode == expected_mode {
        return Ok((dev, ino));
    }

    // Fallback for a platform that did not honour the umask. Only reachable
    // while the path still resolves to the inode confirmed above.
    let permissions = std::fs::Permissions::from_mode(expected_mode);
    std::fs::set_permissions(path, permissions).map_err(|error| {
        WorkloadApiListenerError::Io(format!(
            "setting mode {expected_mode:#o} on '{}' failed: {error}",
            path.display()
        ))
    })?;
    let (dev_after, ino_after, mode_after) = inspect("after chmod")?;
    if (dev_after, ino_after) != (dev, ino) {
        return Err(WorkloadApiListenerError::Io(format!(
            "the socket at '{}' was replaced while its permissions were being set; refusing to \
             serve it",
            path.display()
        )));
    }
    if mode_after != expected_mode {
        return Err(WorkloadApiListenerError::Io(format!(
            "the socket at '{}' does not carry the configured mode {expected_mode:#o}; refusing \
             to serve an endpoint whose permissions cannot be confirmed",
            path.display()
        )));
    }
    Ok((dev, ino))
}

/// Remove the artifact at `path` only if it is a socket owned by this process.
///
/// Used on the bind-failure rollback, where there is no confirmed identity to
/// compare against. Ownership plus file-type is the strongest check available
/// there, and it still refuses to delete another user's data or a non-socket.
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

/// `(device, inode)` of the socket at `path`, when it exists.
#[cfg(unix)]
fn socket_identity(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::symlink_metadata(path).ok()?;
    Some((metadata.dev(), metadata.ino()))
}

#[cfg(not(unix))]
fn socket_identity(_path: &Path) -> Option<(u64, u64)> {
    None
}

/// Unlink the socket at `path` only when it is still the exact inode we bound.
#[cfg(unix)]
fn cleanup_owned_socket(path: &Path, bound_identity: Option<(u64, u64)>) {
    let Some(bound_identity) = bound_identity else {
        return;
    };
    if socket_identity(path) != Some(bound_identity) {
        // Somebody else's socket (or nothing) is here now. Removing it would be
        // destructive to a process that legitimately took over the path.
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

/// Remove a leftover socket from a previous run, and only that.
///
/// A crashed process leaves its socket behind and `bind` would fail with
/// `EADDRINUSE`, so a stale artifact has to be cleared. It is cleared only when
/// it is a socket owned by this process's effective uid: a regular file, a
/// directory, a symlink, or another user's socket is refused outright rather
/// than deleted.
#[cfg(unix)]
fn remove_owned_stale_socket(path: &Path) -> Result<(), WorkloadApiListenerError> {
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
    std::fs::remove_file(path).map_err(|error| {
        WorkloadApiListenerError::Socket(format!(
            "cannot remove the stale socket at '{}': {error}",
            path.display()
        ))
    })?;
    warn!(
        socket = %path.display(),
        "removed a stale SPIFFE Workload API socket left by a previous run"
    );
    Ok(())
}

#[cfg(not(unix))]
fn remove_owned_stale_socket(_path: &Path) -> Result<(), WorkloadApiListenerError> {
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
