//! Unix-domain-socket backend transport for Sidecar `ingress[]` listeners.
//!
//! Istio lets a `Sidecar` ingress entry point at a co-located Unix socket
//! (`defaultEndpoint: unix:///var/run/app.sock`). Ferrum models that as a
//! single-target upstream carrying the RESERVED [`MESH_UNIX_SOCKET_TAG`], which
//! the HTTP dispatch path recognizes and dials with
//! [`tokio::net::UnixStream`] instead of TCP.
//!
//! Two properties are load-bearing and must not be relaxed:
//!
//! 1. **The tag is a fail-closed transport marker, never a hint.** A target
//!    carrying it is dialed over a Unix stream or the request is REFUSED — the
//!    dispatch path never falls back to the target's placeholder `host:port`
//!    (which nothing listens on). This mirrors the `mesh.hbone` / `mesh.mtls`
//!    contract.
//! 2. **The path is re-admitted at dial time.** The tag rides
//!    `UpstreamTarget.tags`, which is decoded from config that may have crossed
//!    the CP/DP or file boundary, so [`resolve_unix_socket_target`] re-runs
//!    [`crate::util::unix_socket::validate_unix_socket_path`] rather than
//!    trusting the value that reached it.
//!
//! The tag lives in the reserved `mesh.` namespace that
//! `strip_reserved_mesh_tags` removes from every operator/workload label copy,
//! so a hand-authored pod label can never forge it.

use crate::config::types::UpstreamTarget;
use crate::util::unix_socket::{UnixSocketPathRejection, validate_unix_socket_path};

/// Reserved `UpstreamTarget.tags` key carrying the absolute path of the
/// Unix-domain stream socket this target's backend listens on.
pub const MESH_UNIX_SOCKET_TAG: &str = "mesh.unix_socket";

/// Fallback connect timeout when the proxy configures none (`0` = unset).
///
/// A Unix connect is a local, non-routed operation, so it either succeeds
/// immediately or fails with `ENOENT`/`ECONNREFUSED`; the only way it BLOCKS is
/// a full listen backlog on a wedged app. A bound is still required so such an
/// app cannot pin request tasks indefinitely.
pub const DEFAULT_UNIX_CONNECT_TIMEOUT_MS: u64 = 5_000;

/// Why a `mesh.unix_socket`-tagged target could not be dialed.
#[derive(Debug)]
pub enum UnixBackendError {
    /// The tagged path failed the same admission rules translation applies.
    /// Fail-closed: a hostile or corrupted carrier never reaches `connect`.
    InadmissiblePath(UnixSocketPathRejection),
    /// `UnixStream::connect` failed — socket missing, not a socket, permission
    /// denied, listen backlog full, or the peer is gone.
    Connect(std::io::Error),
    /// The connect did not complete within the effective timeout.
    ConnectTimeout { timeout_ms: u64 },
    /// The build target has no Unix-domain sockets (Windows). Sidecar mesh
    /// deployments are Linux-only, so this is unreachable in practice; it
    /// exists so the non-Unix build refuses the dispatch rather than silently
    /// dropping the transport gate.
    PlatformUnsupported,
}

impl std::fmt::Display for UnixBackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InadmissiblePath(rejection) => {
                write!(f, "unix backend path rejected: {}", rejection.reason())
            }
            Self::Connect(err) => write!(f, "unix backend connect failed: {err}"),
            Self::ConnectTimeout { timeout_ms } => {
                write!(f, "unix backend connect timed out after {timeout_ms}ms")
            }
            Self::PlatformUnsupported => {
                write!(f, "unix backends are not supported on this platform")
            }
        }
    }
}

impl UnixBackendError {
    /// Retry/circuit-breaker classification.
    ///
    /// Every variant happens strictly BEFORE any request byte reaches the app,
    /// so `request_reached_wire` is false for all of them and a replay is safe.
    /// They differ in whether they are EVIDENCE about the backend:
    ///
    /// * an inadmissible path (or a platform with no Unix sockets) is a
    ///   terminal gateway-side policy decision — replaying it anywhere would
    ///   produce the same refusal, and the app is not implicated, so it is
    ///   `DispatchPolicyRejected` (health-neutral, not retried);
    /// * a failed or timed-out connect IS evidence the local app is down or
    ///   wedged, so it keeps the ordinary connect-phase classes.
    pub fn error_class(&self) -> crate::retry::ErrorClass {
        match self {
            Self::InadmissiblePath(_) | Self::PlatformUnsupported => {
                crate::retry::ErrorClass::DispatchPolicyRejected
            }
            Self::Connect(_) => crate::retry::ErrorClass::ConnectionRefused,
            Self::ConnectTimeout { .. } => crate::retry::ErrorClass::ConnectionTimeout,
        }
    }
}

/// The admitted Unix-socket path a target dials, or `None` when the target is
/// an ordinary TCP one.
///
/// Returns `Some(Err(..))` when the target IS tagged but its path is
/// inadmissible, so a caller can tell "not a Unix target" (fall through to the
/// ordinary path) apart from "a Unix target that must fail closed".
pub fn resolve_unix_socket_target(
    target: &UpstreamTarget,
) -> Option<Result<&str, UnixSocketPathRejection>> {
    let path = target.tags.get(MESH_UNIX_SOCKET_TAG)?.as_str();
    Some(validate_unix_socket_path(path).map(|()| path))
}

/// Whether this target must be dispatched over a Unix stream, admissible or
/// not. A `true` here means the ordinary TCP path is FORBIDDEN for the target.
#[inline]
pub fn target_is_unix_backend(target: &UpstreamTarget) -> bool {
    target.tags.contains_key(MESH_UNIX_SOCKET_TAG)
}

/// Effective connect timeout for a Unix dial, in milliseconds.
#[inline]
pub fn effective_connect_timeout_ms(proxy_connect_timeout_ms: u64) -> u64 {
    if proxy_connect_timeout_ms == 0 {
        DEFAULT_UNIX_CONNECT_TIMEOUT_MS
    } else {
        proxy_connect_timeout_ms
    }
}

/// Dial a co-located Unix-domain STREAM socket, re-admitting the path first and
/// bounding the connect with `connect_timeout_ms`.
///
/// Nothing here inspects or creates filesystem state: file type, ownership, and
/// mode are the kernel's to enforce at `connect(2)` (a directory or regular
/// file yields `ECONNREFUSED`/`ENOTSOCK`, an unreadable parent yields
/// `EACCES`), and pre-checking them would be a TOCTOU race that reports a
/// different fact than the dial. Every such outcome surfaces as
/// [`UnixBackendError::Connect`].
#[cfg(unix)]
pub async fn dial_unix_backend(
    path: &str,
    connect_timeout_ms: u64,
) -> Result<tokio::net::UnixStream, UnixBackendError> {
    if let Err(rejection) = validate_unix_socket_path(path) {
        return Err(UnixBackendError::InadmissiblePath(rejection));
    }
    let timeout_ms = effective_connect_timeout_ms(connect_timeout_ms);
    match tokio::time::timeout(
        std::time::Duration::from_millis(timeout_ms),
        tokio::net::UnixStream::connect(path),
    )
    .await
    {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(err)) => Err(UnixBackendError::Connect(err)),
        Err(_) => Err(UnixBackendError::ConnectTimeout { timeout_ms }),
    }
}
