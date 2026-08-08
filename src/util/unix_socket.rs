//! Admission rules for Unix-domain-socket backend paths.
//!
//! A `unix://` backend path arrives from operator-authored config (an Istio
//! `Sidecar` ingress `defaultEndpoint`) and, on the native/file/xDS carrier,
//! straight from untrusted wire JSON. It names a LOCAL filesystem object that
//! the Ferrum process — often the most privileged process in the pod — would
//! connect to. An unconstrained path is therefore a local privilege boundary:
//! `unix:///var/run/docker.sock` would hand every request-path client the
//! container runtime's API.
//!
//! Admission is a TWO-STAGE, fail-closed gate:
//!
//! 1. [`validate_unix_socket_path`] — pure syntax. Absolute, normalized,
//!    printable, and short enough for `sockaddr_un` on every supported
//!    platform.
//! 2. [`admit_configured_path`] — syntax PLUS **containment** inside an
//!    operator-configured allowlist of roots
//!    (`FERRUM_MESH_UNIX_SOCKET_ALLOWED_ROOTS`). The allowlist has **no
//!    default**: with none configured, every `unix://` endpoint is refused, so
//!    the feature is opt-in per deployment and there is no blanket `/run` or
//!    `/var/run` permission to inherit.
//!
//! At DIAL time [`admit_socket_for_connect`] re-runs both stages and adds the
//! filesystem facts that only exist at connect: the path is `canonicalize`d
//! (which fully resolves symlinks) and the RESOLVED path must land inside an
//! allowed root as well, so a symlink planted at an allowed location cannot
//! redirect the dial to `/var/run/docker.sock`. The resolved object must be a
//! Unix **socket**, owned by an admitted uid (default: the Ferrum process's own
//! effective uid), not world-writable, and sitting in a directory that is not
//! world-writable-without-sticky.
//!
//! **TOCTOU.** A filesystem check and the subsequent `connect(2)` cannot be
//! made atomic through the POSIX path API, so the resolve-then-connect window
//! is inherently racy. The containment allowlist is what actually bounds the
//! damage: an attacker who can win the race must already be able to create the
//! swapped object *inside an allowed root*, and the parent-directory
//! world-writability rule removes the ordinary way to obtain that. The
//! re-validation at connect narrows the window; it does not claim to close it.

/// Longest Unix-socket path Ferrum admits, in bytes (excluding the terminating
/// NUL the kernel adds).
///
/// `sockaddr_un.sun_path` is 108 bytes on Linux but only 104 on macOS/BSD, and
/// both reserve one byte for the NUL terminator. Ferrum uses the smaller
/// platform's usable budget everywhere so a config accepted on Linux cannot
/// become an un-dialable `EINVAL`/`ENAMETOOLONG` on another platform (and so a
/// path that passes admission on the control plane still dials on the data
/// plane).
pub const MAX_UNIX_SOCKET_PATH_BYTES: usize = 103;

/// Why a Unix-domain socket path is not usable as a backend endpoint.
///
/// Field-specific so callers can keep the operator's diagnostic precise (the
/// Istio status writer's `deferred_fields` report, the mesh listener resolution
/// warning) rather than collapsing every rejection into "unsupported".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnixSocketPathRejection {
    /// The path was empty (or `unix://` with nothing after it).
    Empty,
    /// The path has leading or trailing whitespace — almost always a config
    /// typo, and silently trimming it would dial a different path than written.
    SurroundingWhitespace,
    /// The path is not absolute. Relative paths are resolved against the
    /// process CWD, which is not a stable, reviewable location; abstract
    /// (Linux `\0`-prefixed) and `@`-prefixed sockets land here too — Istio
    /// does not define them for `defaultEndpoint`.
    NotAbsolute,
    /// The path contains a `.` or `..` component. Never normalized silently:
    /// a traversal segment can escape the directory an operator reviewed.
    TraversalComponent,
    /// The path contains an empty component (`//`), which is legal to the
    /// kernel but ambiguous to review and to string-equality dedup.
    EmptyComponent,
    /// The path ends with `/`, so it names a directory, never a socket.
    TrailingSlash,
    /// The path contains an interior NUL, which would truncate `sun_path`.
    InteriorNul,
    /// The path contains an ASCII control character.
    ControlCharacter,
    /// The path does not fit `sockaddr_un.sun_path` on every supported
    /// platform (see [`MAX_UNIX_SOCKET_PATH_BYTES`]).
    TooLong,
    /// No containment roots are configured
    /// (`FERRUM_MESH_UNIX_SOCKET_ALLOWED_ROOTS` is unset or empty), so no Unix
    /// socket path is admissible. This is the DEFAULT: the feature is opt-in
    /// per deployment rather than shipping a blanket `/run` allowance.
    ContainmentNotConfigured,
    /// A configured containment root is itself unusable — not absolute, bare
    /// `/` (which would contain everything and defeat the gate), or
    /// traversal-like. Refused rather than skipped, so a typo cannot silently
    /// widen or narrow the allowlist.
    InvalidContainmentRoot,
    /// The path is syntactically fine but does not sit under any configured
    /// containment root.
    OutsideAllowedRoots,
    /// The path could not be resolved on this host (missing, or a component of
    /// it is not searchable). Also covers a resolved path that is not valid
    /// UTF-8, which Ferrum's string-typed config cannot represent.
    UnresolvablePath,
    /// The path resolves — through one or more symlinks, a bind mount, or a
    /// mount-namespace difference — to a location OUTSIDE every configured
    /// containment root. This is the escape the lexical check alone cannot
    /// see, and is exactly how `/allowed/app.sock → /var/run/docker.sock`
    /// would otherwise be reached.
    SymlinkEscape,
    /// The resolved object exists but is not a Unix-domain socket (a regular
    /// file, directory, FIFO, or device).
    NotASocket,
    /// The socket's owning uid is not admitted. With
    /// `FERRUM_MESH_UNIX_SOCKET_ALLOWED_UIDS` unset the only admitted owner is
    /// the Ferrum process's own effective uid, so a root-owned system socket
    /// in an allowed root is still refused for a non-root Ferrum.
    UnexpectedOwner,
    /// The socket is world-writable (`o+w`), so any local user could connect
    /// to — or, with directory write access, replace — it.
    WorldWritableSocket,
    /// The socket's parent directory is world-writable without the sticky bit,
    /// so any local user can unlink the socket and bind their own in its
    /// place. This is the precondition for winning the connect-time race, so
    /// it is refused rather than merely narrowed.
    UnsafeParentDirectory,
    /// The build target has no Unix-domain sockets (Windows). Sidecar mesh
    /// deployments are Linux-only, so this is unreachable in practice; it
    /// exists so the non-Unix build refuses rather than silently admitting.
    PlatformUnsupported,
}

impl UnixSocketPathRejection {
    /// Stable, human-readable reason suitable for a status condition or log
    /// field. Never contains the path itself, so a caller decides whether the
    /// operator-supplied value is safe to echo back.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Empty => "unix socket path is empty",
            Self::SurroundingWhitespace => "unix socket path has leading or trailing whitespace",
            Self::NotAbsolute => "unix socket path is not absolute",
            Self::TraversalComponent => "unix socket path contains a '.' or '..' component",
            Self::EmptyComponent => "unix socket path contains an empty ('//') component",
            Self::TrailingSlash => "unix socket path ends with '/' (names a directory)",
            Self::InteriorNul => "unix socket path contains a NUL byte",
            Self::ControlCharacter => "unix socket path contains a control character",
            Self::TooLong => "unix socket path exceeds the portable sockaddr_un limit",
            Self::ContainmentNotConfigured => {
                "unix socket backends are disabled: FERRUM_MESH_UNIX_SOCKET_ALLOWED_ROOTS is unset"
            }
            Self::InvalidContainmentRoot => {
                "FERRUM_MESH_UNIX_SOCKET_ALLOWED_ROOTS contains an unusable root"
            }
            Self::OutsideAllowedRoots => {
                "unix socket path is outside every configured allowed root"
            }
            Self::UnresolvablePath => "unix socket path could not be resolved on this host",
            Self::SymlinkEscape => {
                "unix socket path resolves outside every configured allowed root"
            }
            Self::NotASocket => "unix socket path does not name a unix-domain socket",
            Self::UnexpectedOwner => "unix socket is not owned by an admitted uid",
            Self::WorldWritableSocket => "unix socket is world-writable",
            Self::UnsafeParentDirectory => {
                "unix socket parent directory is world-writable without the sticky bit"
            }
            Self::PlatformUnsupported => "unix socket backends are unsupported on this platform",
        }
    }
}

/// Admit a Unix-domain socket path for use as a backend endpoint, or explain
/// exactly why it is refused.
///
/// Fail-closed by construction: every accepted path is absolute, free of `.` /
/// `..` / empty components, printable, NUL-free, does not name a directory, and
/// fits `sockaddr_un` on every supported platform. Nothing is normalized or
/// trimmed — the value dialed is byte-for-byte the value the operator wrote.
pub fn validate_unix_socket_path(path: &str) -> Result<(), UnixSocketPathRejection> {
    if path.is_empty() {
        return Err(UnixSocketPathRejection::Empty);
    }
    if path.trim() != path {
        return Err(UnixSocketPathRejection::SurroundingWhitespace);
    }
    if path.contains('\0') {
        return Err(UnixSocketPathRejection::InteriorNul);
    }
    if path.chars().any(char::is_control) {
        return Err(UnixSocketPathRejection::ControlCharacter);
    }
    if !path.starts_with('/') {
        return Err(UnixSocketPathRejection::NotAbsolute);
    }
    // Covers bare `/` too: it names the root directory, never a socket.
    if path.ends_with('/') {
        return Err(UnixSocketPathRejection::TrailingSlash);
    }
    // Skip the leading empty segment produced by the absolute-path `/`.
    for component in path.split('/').skip(1) {
        if component.is_empty() {
            return Err(UnixSocketPathRejection::EmptyComponent);
        }
        if component == "." || component == ".." {
            return Err(UnixSocketPathRejection::TraversalComponent);
        }
    }
    if path.len() > MAX_UNIX_SOCKET_PATH_BYTES {
        return Err(UnixSocketPathRejection::TooLong);
    }
    Ok(())
}

/// Normalize one configured containment root, or explain why it is unusable.
///
/// A root must be an absolute, normalized directory path. A bare `/` is
/// REFUSED: it would contain every path on the host and turn the allowlist into
/// a no-op. A single trailing `/` is tolerated and trimmed (operators write
/// both forms), but nothing else is repaired.
pub fn normalize_allowed_root(root: &str) -> Result<&str, UnixSocketPathRejection> {
    let trimmed = root.strip_suffix('/').unwrap_or(root);
    if trimmed.is_empty() || trimmed == "/" || !trimmed.starts_with('/') {
        return Err(UnixSocketPathRejection::InvalidContainmentRoot);
    }
    if trimmed.contains('\0') || trimmed.chars().any(char::is_control) || trimmed.trim() != trimmed
    {
        return Err(UnixSocketPathRejection::InvalidContainmentRoot);
    }
    for component in trimmed.split('/').skip(1) {
        if component.is_empty() || component == "." || component == ".." {
            return Err(UnixSocketPathRejection::InvalidContainmentRoot);
        }
    }
    Ok(trimmed)
}

/// Validate the operator's configured containment roots at STARTUP, returning
/// the offending entry so the process can refuse to start rather than silently
/// running with a narrower (or wider) allowlist than was written.
pub fn validate_allowed_roots(roots: &[String]) -> Result<(), String> {
    for root in roots {
        if normalize_allowed_root(root).is_err() {
            return Err(format!(
                "FERRUM_MESH_UNIX_SOCKET_ALLOWED_ROOTS: '{root}' is not a usable containment root \
                 (must be an absolute, normalized directory path other than '/')"
            ));
        }
    }
    Ok(())
}

/// Whether `path` is a STRICT descendant of `root` (already normalized).
///
/// Compares whole path components — `/var/runner/app.sock` is NOT inside
/// `/var/run` — and requires at least one component below the root, so the root
/// directory itself can never be dialed.
fn path_is_within_root(path: &str, root: &str) -> bool {
    let Some(rest) = path.strip_prefix(root) else {
        return false;
    };
    matches!(rest.as_bytes().first(), Some(b'/')) && rest.len() > 1
}

/// Whether `path` sits under at least one configured containment root.
fn path_is_contained(path: &str, allowed_roots: &[String]) -> Result<(), UnixSocketPathRejection> {
    if allowed_roots.is_empty() {
        return Err(UnixSocketPathRejection::ContainmentNotConfigured);
    }
    for root in allowed_roots {
        // A malformed root is a hard error, never a skipped entry: skipping
        // would silently narrow the allowlist the operator reviewed.
        let root = normalize_allowed_root(root)?;
        if path_is_within_root(path, root) {
            return Ok(());
        }
    }
    Err(UnixSocketPathRejection::OutsideAllowedRoots)
}

/// Admit an operator-configured `unix://` backend path: full syntax rules PLUS
/// containment inside `allowed_roots`.
///
/// This is the TRANSLATION-time gate (Istio `Sidecar` resolution, the status
/// writer's `deferred_fields` classification, and carrier re-validation of an
/// already-resolved listener). It performs NO filesystem I/O, so it is safe to
/// run on a control plane that does not share the workload's filesystem; the
/// filesystem facts are checked at dial time by [`admit_socket_for_connect`].
pub fn admit_configured_path(
    path: &str,
    allowed_roots: &[String],
) -> Result<(), UnixSocketPathRejection> {
    validate_unix_socket_path(path)?;
    path_is_contained(path, allowed_roots)
}

/// Re-admit a `unix://` backend path at DIAL time, adding the filesystem facts
/// that only exist at connect.
///
/// Runs the full [`admit_configured_path`] gate again (the value may have
/// crossed a CP/DP or file boundary since translation admitted it), then:
///
/// * `canonicalize`s the path — which fully resolves symlinks, `..`, and mount
///   points — and requires the RESOLVED path to land inside an allowed root
///   too. This is the check that stops an attacker-controlled symlink inside an
///   allowed directory from redirecting the dial to a privileged socket such as
///   `/var/run/docker.sock`;
/// * requires the resolved object to be a Unix-domain SOCKET;
/// * requires its owner uid to be admitted — `allowed_uids` when non-empty,
///   otherwise the Ferrum process's own effective uid, so a root-owned system
///   socket that happens to sit in an allowed root is still refused for a
///   non-root Ferrum;
/// * refuses a world-writable socket, and a socket whose parent directory is
///   world-writable without the sticky bit (the precondition for swapping the
///   socket out from under the dial).
///
/// See the module docs for the TOCTOU contract: this narrows the
/// resolve-to-connect window, the containment allowlist bounds it.
#[cfg(unix)]
pub fn admit_socket_for_connect(
    path: &str,
    allowed_roots: &[String],
    allowed_uids: &[u32],
) -> Result<(), UnixSocketPathRejection> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    admit_configured_path(path, allowed_roots)?;

    let resolved = std::fs::canonicalize(path)
        .map_err(|_| UnixSocketPathRejection::UnresolvablePath)?;
    let resolved_str = resolved
        .to_str()
        .ok_or(UnixSocketPathRejection::UnresolvablePath)?;
    // `canonicalize` yields an absolute, symlink-free, `..`-free path, so
    // containment on it is the post-resolution half of the gate. A path that
    // was lexically contained but resolves elsewhere is an ESCAPE, reported
    // distinctly from a plainly out-of-root path.
    if path_is_contained(resolved_str, allowed_roots).is_err() {
        return Err(UnixSocketPathRejection::SymlinkEscape);
    }

    // `symlink_metadata` on an already-canonical path cannot traverse a further
    // symlink, so the facts below describe the object the dial will reach.
    let metadata = std::fs::symlink_metadata(&resolved)
        .map_err(|_| UnixSocketPathRejection::UnresolvablePath)?;
    if !metadata.file_type().is_socket() {
        return Err(UnixSocketPathRejection::NotASocket);
    }
    let owner_admitted = if allowed_uids.is_empty() {
        // SAFETY: `geteuid` reads the calling process's effective uid. It takes
        // no arguments, touches no memory, and is documented never to fail.
        metadata.uid() == unsafe { libc::geteuid() }
    } else {
        allowed_uids.contains(&metadata.uid())
    };
    if !owner_admitted {
        return Err(UnixSocketPathRejection::UnexpectedOwner);
    }
    if metadata.mode() & 0o002 != 0 {
        return Err(UnixSocketPathRejection::WorldWritableSocket);
    }

    let parent = resolved
        .parent()
        .ok_or(UnixSocketPathRejection::UnsafeParentDirectory)?;
    let parent_metadata = std::fs::symlink_metadata(parent)
        .map_err(|_| UnixSocketPathRejection::UnsafeParentDirectory)?;
    let parent_mode = parent_metadata.mode();
    // World-writable is safe only with the sticky bit (`/tmp` semantics), which
    // stops a non-owner from unlinking the socket and binding their own.
    if parent_mode & 0o002 != 0 && parent_mode & 0o1000 == 0 {
        return Err(UnixSocketPathRejection::UnsafeParentDirectory);
    }
    Ok(())
}

/// Non-Unix build: there is no Unix-domain socket to admit, so the dial-time
/// gate refuses rather than degrading to the lexical checks alone.
#[cfg(not(unix))]
pub fn admit_socket_for_connect(
    _path: &str,
    _allowed_roots: &[String],
    _allowed_uids: &[u32],
) -> Result<(), UnixSocketPathRejection> {
    Err(UnixSocketPathRejection::PlatformUnsupported)
}
