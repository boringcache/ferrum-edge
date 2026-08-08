//! Unix-domain-socket backend transport for Sidecar `ingress[]` listeners.
//!
//! Istio lets a `Sidecar` ingress entry point at a co-located Unix socket
//! (`defaultEndpoint: unix:///var/run/app.sock`). Ferrum models that as a
//! single-target upstream carrying the RESERVED [`MESH_UNIX_SOCKET_TAG`], which
//! the HTTP dispatch path recognizes and dials with
//! [`tokio::net::UnixStream`] instead of TCP.
//!
//! Three properties are load-bearing and must not be relaxed:
//!
//! 1. **The tag is a fail-closed transport marker, never a hint.** A target
//!    carrying it is dialed over a Unix stream or the request is REFUSED — the
//!    dispatch path never falls back to the target's placeholder `host:port`
//!    (which nothing listens on). This mirrors the `mesh.hbone` / `mesh.mtls`
//!    contract.
//! 2. **The path is re-admitted at dial time, against the CONTAINMENT
//!    allowlist.** The tag rides `UpstreamTarget.tags`, decoded from config that
//!    may have crossed the CP/DP, file, or xDS boundary, so the dial re-runs the
//!    full [`crate::util::unix_socket::admit_socket_for_connect`] gate —
//!    containment, symlink-resolved containment, socket file type, owner uid,
//!    and mode — rather than trusting the value that reached it. With no
//!    configured roots (the default) every tagged target is refused.
//! 3. **The wire protocol is carried, never inferred.**
//!    [`MESH_UNIX_SOCKET_H2C_TAG`] is resolved at translation from the
//!    listener's declared `port.protocol`; an absent tag is HTTP/1.1. h2c
//!    carries native gRPC over the socket with full request/response streaming,
//!    deadlines, cancellation, and trailers, because it reuses the sidecar
//!    mesh-mTLS dispatch body (see [`dial_unix_h2c_sender`]).
//!
//! Both tags live in the reserved `mesh.` namespace that
//! `strip_reserved_mesh_tags` removes from every operator/workload label copy,
//! so a hand-authored pod label can never forge them.

use crate::config::types::UpstreamTarget;
use crate::util::unix_socket::{UnixSocketPathRejection, admit_configured_path};

/// Reserved `UpstreamTarget.tags` key carrying the absolute path of the
/// Unix-domain stream socket this target's backend listens on.
pub const MESH_UNIX_SOCKET_TAG: &str = "mesh.unix_socket";

/// Reserved `UpstreamTarget.tags` key marking the socket's wire protocol as
/// **h2c prior-knowledge HTTP/2** rather than HTTP/1.1.
///
/// Present (value `"true"`) only for a listener whose declared `port.protocol`
/// is `http2` / `https` / `grpc`. Resolved once at translation from that
/// declared protocol and never inferred at dispatch: an ABSENT tag means
/// HTTP/1.1, which is exactly what an `http` listener declared, so a stripped
/// tag degrades to the weaker-but-declared protocol instead of a guessed h2c
/// handshake the application would reject.
pub const MESH_UNIX_SOCKET_H2C_TAG: &str = "mesh.unix_socket_h2c";

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
    /// The h2c prior-knowledge HTTP/2 client handshake failed on an
    /// `http2`/`grpc`-declared listener. The socket accepted the connection but
    /// the application does not speak h2c on it — a configuration mismatch, not
    /// a reason to silently retry as HTTP/1.1 (that would deliver a request the
    /// declared protocol says the app cannot parse).
    H2Handshake(hyper::Error),
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
            Self::H2Handshake(err) => {
                write!(f, "unix backend h2c handshake failed: {err}")
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
    /// * a failed or timed-out connect — or a refused h2c handshake — IS
    ///   evidence the local app is down, wedged, or not speaking its declared
    ///   protocol, so those keep the ordinary connect-phase classes.
    pub fn error_class(&self) -> crate::retry::ErrorClass {
        match self {
            Self::InadmissiblePath(_) | Self::PlatformUnsupported => {
                crate::retry::ErrorClass::DispatchPolicyRejected
            }
            Self::Connect(_) => crate::retry::ErrorClass::ConnectionRefused,
            Self::ConnectTimeout { .. } => crate::retry::ErrorClass::ConnectionTimeout,
            // The handshake completes before any request frame is written, so
            // this is PRE-wire and replay-safe, but it IS evidence about the app
            // (it is not speaking the protocol its listener declared) — the same
            // posture the pooled transports give a failed connection setup.
            Self::H2Handshake(_) => crate::retry::ErrorClass::ConnectionPoolError,
        }
    }
}

/// The admitted, CONTAINED Unix-socket path a target dials, or `None` when the
/// target is an ordinary TCP one.
///
/// Returns `Some(Err(..))` when the target IS tagged but its path fails
/// admission, so a caller can tell "not a Unix target" (fall through to the
/// ordinary path) apart from "a Unix target that must fail closed".
///
/// `allowed_roots` is the process's configured containment allowlist
/// (`FERRUM_MESH_UNIX_SOCKET_ALLOWED_ROOTS`); an EMPTY allowlist refuses every
/// tagged target, which is the default posture.
pub fn resolve_unix_socket_target<'a>(
    target: &'a UpstreamTarget,
    allowed_roots: &[String],
) -> Option<Result<&'a str, UnixSocketPathRejection>> {
    let path = target.tags.get(MESH_UNIX_SOCKET_TAG)?.as_str();
    Some(admit_configured_path(path, allowed_roots).map(|()| path))
}

/// Whether this target must be dispatched over a Unix stream, admissible or
/// not. A `true` here means the ordinary TCP path is FORBIDDEN for the target.
#[inline]
pub fn target_is_unix_backend(target: &UpstreamTarget) -> bool {
    target.tags.contains_key(MESH_UNIX_SOCKET_TAG)
}

/// Whether this Unix target speaks h2c prior-knowledge HTTP/2 (and therefore
/// carries gRPC natively) rather than HTTP/1.1.
///
/// Strict equality against `"true"`: the tag is written by the materializer
/// only, and anything else is treated as ABSENT, so a corrupted carrier
/// degrades to the declared-HTTP/1.1 handshake rather than being guessed into
/// h2c.
#[inline]
pub fn target_unix_backend_is_h2c(target: &UpstreamTarget) -> bool {
    target
        .tags
        .get(MESH_UNIX_SOCKET_H2C_TAG)
        .is_some_and(|value| value == "true")
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

/// HTTP/2 client-connection bounds for an h2c Unix backend.
///
/// Fixed rather than operator-tunable: the peer is a co-located application on
/// the same host reached over a loopback-equivalent transport, so the windows
/// exist to BOUND memory, not to fill a bandwidth-delay product. Every buffer
/// on this transport is bounded by these values plus the request/response body
/// ceilings the caller already applies. Making them configurable is a
/// follow-up, not a correctness requirement.
#[cfg(unix)]
const UNIX_H2C_INITIAL_STREAM_WINDOW: u32 = 1024 * 1024;
#[cfg(unix)]
const UNIX_H2C_INITIAL_CONNECTION_WINDOW: u32 = 2 * 1024 * 1024;
#[cfg(unix)]
const UNIX_H2C_MAX_FRAME_SIZE: u32 = 16 * 1024;
/// Cap on concurrently reset streams the client tracks, so a misbehaving app
/// cannot grow that bookkeeping without bound.
#[cfg(unix)]
const UNIX_H2C_MAX_CONCURRENT_RESET_STREAMS: usize = 1024;

/// Admit `path` at the TOCTOU boundary and dial it, bounded by
/// `connect_timeout_ms`.
///
/// The admission re-run here is the SECOND half of the containment contract:
/// the value reached this process over a CP/DP, file, or xDS boundary, and the
/// filesystem may have changed since translation admitted it. It checks
/// containment, symlink-resolved containment, socket file type, owner uid, and
/// mode — see [`crate::util::unix_socket::admit_socket_for_connect`].
#[cfg(unix)]
async fn admit_and_connect(
    path: &str,
    connect_timeout_ms: u64,
    allowed_roots: &[String],
    allowed_uids: &[u32],
) -> Result<tokio::net::UnixStream, UnixBackendError> {
    if let Err(rejection) =
        crate::util::unix_socket::admit_socket_for_connect(path, allowed_roots, allowed_uids)
    {
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

/// Dial a co-located Unix-domain STREAM socket for an HTTP/1.1 backend,
/// re-admitting the path first and bounding the connect with
/// `connect_timeout_ms`.
#[cfg(unix)]
pub async fn dial_unix_backend(
    path: &str,
    connect_timeout_ms: u64,
    allowed_roots: &[String],
    allowed_uids: &[u32],
) -> Result<tokio::net::UnixStream, UnixBackendError> {
    admit_and_connect(path, connect_timeout_ms, allowed_roots, allowed_uids).await
}

/// Dial a co-located Unix-domain STREAM socket and complete an **h2c
/// prior-knowledge HTTP/2** client handshake on it, returning a sender of the
/// same type the sidecar mesh-mTLS pool produces.
///
/// Sharing that sender type is deliberate: it lets the Unix h2c transport reuse
/// `proxy_to_backend_mesh_mtls`'s dispatch body verbatim, so request/response
/// streaming, gRPC deadlines and cancellation, `te: trailers` regeneration, and
/// terminal-trailer forwarding are the SAME code on both transports and cannot
/// drift apart. The connection is 1:1 (not pooled) and its driver task ends
/// with the request, exactly like the mesh WebSocket / raw-TCP dials.
#[cfg(unix)]
pub async fn dial_unix_h2c_sender(
    path: &str,
    connect_timeout_ms: u64,
    allowed_roots: &[String],
    allowed_uids: &[u32],
) -> Result<crate::proxy::mesh_mtls_pool::MeshMtlsSender, UnixBackendError> {
    use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};

    let stream =
        admit_and_connect(path, connect_timeout_ms, allowed_roots, allowed_uids).await?;

    let mut builder = hyper::client::conn::http2::Builder::new(TokioExecutor::new());
    builder
        .timer(TokioTimer::new())
        .initial_stream_window_size(UNIX_H2C_INITIAL_STREAM_WINDOW)
        .initial_connection_window_size(UNIX_H2C_INITIAL_CONNECTION_WINDOW)
        .max_frame_size(UNIX_H2C_MAX_FRAME_SIZE)
        .max_concurrent_reset_streams(UNIX_H2C_MAX_CONCURRENT_RESET_STREAMS);

    let (sender, connection) = builder
        .handshake(TokioIo::new(stream))
        .await
        .map_err(UnixBackendError::H2Handshake)?;
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            tracing::debug!("unix_backend: h2c connection closed: {}", e);
        }
    });
    Ok(sender)
}

/// Non-Unix build: there is no Unix-domain socket to dial, so the shared
/// dispatch body refuses instead of losing the transport gate at compile time.
/// Sidecar mesh deployments are Linux-only, so this is unreachable in practice.
#[cfg(not(unix))]
pub async fn dial_unix_h2c_sender(
    _path: &str,
    _connect_timeout_ms: u64,
    _allowed_roots: &[String],
    _allowed_uids: &[u32],
) -> Result<crate::proxy::mesh_mtls_pool::MeshMtlsSender, UnixBackendError> {
    Err(UnixBackendError::PlatformUnsupported)
}
