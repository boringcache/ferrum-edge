//! Admission rules for Unix-domain-socket backend paths.
//!
//! A `unix://` backend path arrives from operator-authored config (an Istio
//! `Sidecar` ingress `defaultEndpoint`) and, on the native/file/xDS carrier,
//! straight from untrusted wire JSON. Every consumer that would DIAL such a
//! path must first run it through [`validate_unix_socket_path`] so a malformed,
//! relative, traversal-like, or over-long value fails CLOSED with a
//! field-specific reason instead of reaching `UnixStream::connect`.
//!
//! The rules are intentionally strict — an absolute, normalized, printable path
//! that fits a `sockaddr_un` on every supported platform. They are a syntactic
//! admission gate only: file-type, ownership, and permission outcomes are
//! decided by the kernel at connect time and surfaced as dial errors.

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
