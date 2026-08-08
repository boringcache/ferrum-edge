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
//! can attempt attestation and, if it attests, obtain an SVID. The contract is
//! therefore validated *before* binding and is fail-closed at every step
//! ([`WorkloadApiSocketConfig::validate`]):
//!
//! - the path must be **absolute** and contain no `.` / `..` component, so a
//!   relative or traversing path can never resolve somewhere the operator did
//!   not name;
//! - the **parent directory must already exist** — Ferrum does not create it.
//!   Creating it would mean choosing its owner and mode on the operator's
//!   behalf, and a directory Ferrum creates under a symlink an attacker planted
//!   is exactly the escape this refuses;
//! - the parent directory must be a real directory (not a symlink to one) and
//!   must be owned by this process's effective uid or by root;
//! - a world-writable parent directory is refused unless it carries the sticky
//!   bit, because any local user could otherwise replace the socket;
//! - an existing artifact at the path is removed **only** when it is a socket
//!   *and* owned by this process's effective uid. A regular file, a directory, a
//!   symlink, or another user's socket is never unlinked — that is somebody
//!   else's data, and clobbering it is both destructive and a way to be tricked
//!   into deleting an arbitrary path;
//! - the socket's mode is set to the configured value immediately after bind, so
//!   the window in which it sits at the process umask is as short as the OS
//!   allows.
//!
//! On shutdown the socket file is unlinked **only if Ferrum created it and it is
//! still the same socket** (same device + inode as the one bound), so a
//! restarted peer's socket at the same path is never removed by a late shutdown
//! of the previous process.
//!
//! Bind, validation, and permission failures are all returned to the caller;
//! mesh startup treats them as fatal when the surface is enabled, so a
//! misconfigured Workload API never degrades silently into "not listening".

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
    /// Permission bits applied to the bound socket.
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
    /// rather than as a bind failure.
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
    use std::os::unix::fs::PermissionsExt;
    use tokio::net::UnixListener;
    use tokio_stream::wrappers::UnixListenerStream;

    config.validate()?;
    let path = config.socket_path.clone();
    remove_owned_stale_socket(&path)?;

    let listener = UnixListener::bind(&path).map_err(|e| {
        WorkloadApiListenerError::Io(format!("bind '{}' failed: {e}", path.display()))
    })?;
    // Narrow the permissions immediately. A failure here is fatal and the
    // socket is removed: serving on a socket whose mode we could not confirm
    // would leave the surface open to whatever the umask allowed.
    let mode = std::fs::Permissions::from_mode(config.socket_mode);
    if let Err(error) = std::fs::set_permissions(&path, mode) {
        drop(listener);
        let _ = std::fs::remove_file(&path);
        return Err(WorkloadApiListenerError::Io(format!(
            "setting mode {:#o} on '{}' failed: {error}",
            config.socket_mode,
            path.display()
        )));
    }
    // Record the identity of the socket we created so shutdown can refuse to
    // unlink a *different* socket that later occupies the same path.
    let bound_identity = socket_identity(&path);

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

/// Ownership and mode checks on the directory the socket will live in.
#[cfg(unix)]
fn validate_parent_directory(parent: &Path) -> Result<(), WorkloadApiListenerError> {
    use std::os::unix::fs::MetadataExt;

    let metadata = std::fs::symlink_metadata(parent).map_err(|error| {
        WorkloadApiListenerError::Socket(format!(
            "parent directory '{}' is not usable: {error}. Create it (with the ownership and \
             mode you want) before enabling the Workload API surface",
            parent.display()
        ))
    })?;
    if metadata.file_type().is_symlink() {
        return Err(WorkloadApiListenerError::Socket(format!(
            "parent directory '{}' is a symlink; name the real directory so the socket cannot be \
             redirected",
            parent.display()
        )));
    }
    if !metadata.is_dir() {
        return Err(WorkloadApiListenerError::Socket(format!(
            "parent path '{}' is not a directory",
            parent.display()
        )));
    }
    let effective_uid = unsafe { libc::geteuid() };
    if metadata.uid() != effective_uid && metadata.uid() != 0 {
        return Err(WorkloadApiListenerError::Socket(format!(
            "parent directory '{}' is owned by neither this process nor root; another user could \
             replace the Workload API socket",
            parent.display()
        )));
    }
    let mode = metadata.mode();
    // World-writable is tolerable only with the sticky bit (`/tmp` semantics),
    // where a non-owner cannot unlink our socket.
    if mode & 0o002 != 0 && mode & 0o1000 == 0 {
        return Err(WorkloadApiListenerError::Socket(format!(
            "parent directory '{}' is world-writable without the sticky bit; any local user could \
             replace the Workload API socket",
            parent.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_parent_directory(_parent: &Path) -> Result<(), WorkloadApiListenerError> {
    Err(WorkloadApiListenerError::Unsupported)
}
