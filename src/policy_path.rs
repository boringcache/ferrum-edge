//! Canonical policy path — the single request-path representation that every
//! security decision and the backend request line share.
//!
//! # Why
//!
//! A percent-encoded request target has more than one plausible reading. The
//! gateway used to evaluate WAF URL-path rules, `openapi_validator` operation
//! selection, `request_termination` prefixes, authorization, and cache keys
//! against the *raw* target while common backend frameworks percent-decode
//! path segments before dispatch. A client could therefore pick a raw spelling
//! (`/%61dmin`) that misses an operator's literal policy while the backend
//! still executed the protected handler (private advisory
//! `GHSA-69xf-42xm-4w4f`).
//!
//! The fix is representational, not per-plugin: canonicalize once at the
//! frontend boundary, store the result in [`RequestContext::path`], and let
//! every existing consumer keep reading that one field.
//!
//! [`RequestContext::path`]: crate::plugins::RequestContext::path
//!
//! # Contract
//!
//! [`canonicalize_policy_path`] either returns a canonical path or rejects the
//! request. The canonical form guarantees:
//!
//! 1. **Every `%` starts a complete, valid `%XX` escape.** A truncated or
//!    non-hex escape is [`PolicyPathRejection::InvalidEscape`]; there is no
//!    "leave it alone" fallback, because a lenient backend parser and the
//!    gateway would then disagree about where the escape ends.
//! 2. **Decoding is structure-preserving.** An escape that decodes to `/`,
//!    `?`, `#` ([`PolicyPathRejection::EncodedSeparator`]) or `\` ([`PolicyPathRejection::EncodedBackslash`]) is
//!    rejected, so the canonical path has exactly the segment structure of the
//!    raw target. Routing, policy, and the backend cannot disagree about how
//!    many segments the request has.
//! 3. **Decoding cannot repeat.** An encoded `%` (`%25`, the first byte of any
//!    double encoding) is [`PolicyPathRejection::DoubleEncoding`]. Combined with rule 2 this means
//!    a second decode of the canonical path can never introduce a separator,
//!    so "decoded once" and "decoded twice" describe the same route.
//! 4. **The decoded byte stream is valid UTF-8.** Otherwise backends disagree
//!    (reject / replace with `U+FFFD` / pass bytes through), and the path the
//!    gateway authorized is not the path the backend resolves.
//!    ([`PolicyPathRejection::InvalidUtf8`].)
//! 5. **No escape may synthesize a dot segment.** `/a/%2e%2e/b` is
//!    [`PolicyPathRejection::AmbiguousDotSegment`]. A *literal* `/a/../b` is left exactly as it is —
//!    it is equally visible to the operator, the gateway, and the backend, and
//!    this function never changes a request's meaning, it only refuses the
//!    readings that have more than one.
//! 6. **Encoded C0 controls and `DEL` are rejected** ([`PolicyPathRejection::EncodedControl`]),
//!    including `%00`: a NUL truncates the path in several backend runtimes.
//! 7. **Escapes of characters that are legal literally in a path are decoded**
//!    (RFC 3986 `pchar` = `unreserved` / `sub-delims` / `:` / `@`), so
//!    `/%61dmin` canonicalizes to `/admin` and an operator's literal rule
//!    matches. Every surviving escape is uppercase-hex normalized
//!    (RFC 3986 §6.2.2.1).
//!
//! Because only `pchar`-legal bytes are ever decoded and every surviving
//! escape is still a valid escape, **the canonical path is always a valid HTTP
//! request target**. That is what lets one representation serve both policy
//! and forwarding: there is no second "wire" coordinate system to keep in
//! sync.
//!
//! The function is idempotent: `canonicalize(canonicalize(p)) == canonicalize(p)`.
//!
//! # Fast path
//!
//! A path with no `%` is returned borrowed, unmodified, and can never be
//! rejected. That is the overwhelming majority of production traffic, so the
//! hot path stays allocation-free and no request without a percent escape
//! changes behavior.
//!
//! # Relationship to `normalize_encoded_slashes`
//!
//! [`crate::router_cache::normalize_encoded_slashes`] predates this module and
//! folded `%2F`/`%252F` into `/` for route lookup. Folding *changes* structure,
//! so the router and a non-decoding backend could still disagree; this module
//! rejects those targets instead and runs strictly earlier. The router helper
//! is retained as an unreachable defense-in-depth residual for callers that do
//! not come through the frontend boundary (mesh authz normalization, backend
//! listen-path stripping). It is not a competing model: after canonicalization
//! it is always the identity function.

use std::borrow::Cow;

/// Why a request target was refused as a policy path.
///
/// Every variant maps to a fixed, non-echoing client error body: the raw
/// target is attacker-controlled and is never interpolated into a response or
/// a log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyPathRejection {
    /// A `%` was not followed by two hexadecimal digits.
    InvalidEscape,
    /// An encoded `%` (`%25`) — the lead byte of a double encoding.
    DoubleEncoding,
    /// An encoded `/`, `?`, or `#`.
    EncodedSeparator,
    /// An encoded `\`, which several backend stacks treat as a separator.
    EncodedBackslash,
    /// An encoded C0 control character or `DEL` (includes `%00`).
    EncodedControl,
    /// The fully decoded path is not valid UTF-8.
    InvalidUtf8,
    /// A percent escape produced a `.` or `..` path segment.
    AmbiguousDotSegment,
}

impl PolicyPathRejection {
    /// Stable machine-readable reason token, safe for logs and metrics.
    pub fn reason(self) -> &'static str {
        match self {
            Self::InvalidEscape => "invalid_escape",
            Self::DoubleEncoding => "double_encoding",
            Self::EncodedSeparator => "encoded_separator",
            Self::EncodedBackslash => "encoded_backslash",
            Self::EncodedControl => "encoded_control",
            Self::InvalidUtf8 => "invalid_utf8",
            Self::AmbiguousDotSegment => "ambiguous_dot_segment",
        }
    }

    /// Fixed JSON error body returned to the client. Contains no request bytes.
    pub fn client_error_body(self) -> &'static str {
        match self {
            Self::InvalidEscape => {
                r#"{"error":"Request path contains an incomplete percent-escape"}"#
            }
            Self::DoubleEncoding => {
                r#"{"error":"Request path contains a double-encoded percent-escape"}"#
            }
            Self::EncodedSeparator => {
                r#"{"error":"Request path contains an encoded path separator"}"#
            }
            Self::EncodedBackslash => r#"{"error":"Request path contains an encoded backslash"}"#,
            Self::EncodedControl => {
                r#"{"error":"Request path contains an encoded control character"}"#
            }
            Self::InvalidUtf8 => r#"{"error":"Request path does not decode to valid UTF-8"}"#,
            Self::AmbiguousDotSegment => {
                r#"{"error":"Request path contains an encoded dot segment"}"#
            }
        }
    }

    /// Fixed gRPC status message for gRPC/gRPC-Web shaped rejections.
    pub fn grpc_message(self) -> &'static str {
        match self {
            Self::InvalidEscape => "Incomplete percent-escape in request path",
            Self::DoubleEncoding => "Double-encoded percent-escape in request path",
            Self::EncodedSeparator => "Encoded path separator in request path",
            Self::EncodedBackslash => "Encoded backslash in request path",
            Self::EncodedControl => "Encoded control character in request path",
            Self::InvalidUtf8 => "Request path does not decode to valid UTF-8",
            Self::AmbiguousDotSegment => "Encoded dot segment in request path",
        }
    }
}

/// Bytes that are legal to appear literally in a path segment and are
/// therefore decoded rather than left escaped: RFC 3986 `pchar` minus
/// `pct-encoded`, i.e. `unreserved / sub-delims / ":" / "@"`.
///
/// `/` is deliberately absent — an encoded `/` is rejected, never decoded,
/// because decoding it would add a segment the raw target did not have.
const DECODE_TO_LITERAL: [bool; 256] = build_decode_table();

const fn build_decode_table() -> [bool; 256] {
    let mut table = [false; 256];
    let mut index = 0usize;
    while index < 256 {
        let byte = index as u8;
        let unreserved = byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~');
        let sub_delims = matches!(
            byte,
            b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'='
        );
        table[index] = unreserved || sub_delims || byte == b':' || byte == b'@';
        index += 1;
    }
    table
}

const HEX_UPPER: [u8; 16] = *b"0123456789ABCDEF";

#[inline]
const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Reject a segment that only became `.` or `..` because of a percent escape.
#[inline]
fn check_segment(
    canonical: &[u8],
    segment_start: usize,
    segment_has_escape: bool,
) -> Result<(), PolicyPathRejection> {
    if !segment_has_escape {
        return Ok(());
    }
    let segment: &[u8] = &canonical[segment_start..];
    if segment == b".".as_slice() || segment == b"..".as_slice() {
        return Err(PolicyPathRejection::AmbiguousDotSegment);
    }
    Ok(())
}

/// Build the canonical policy path for `raw`, or reject the request target.
///
/// See the module documentation for the full contract. `raw` is the path
/// component only — the query string is never part of the policy path.
pub fn canonicalize_policy_path(raw: &str) -> Result<Cow<'_, str>, PolicyPathRejection> {
    let bytes = raw.as_bytes();
    // Hot path: no escape means nothing to validate, decode, or allocate. A
    // path without `%` is always accepted verbatim.
    if !bytes.contains(&b'%') {
        return Ok(Cow::Borrowed(raw));
    }

    let mut canonical: Vec<u8> = Vec::with_capacity(bytes.len());
    // Byte stream a decoding backend would resolve. Validated as UTF-8 once at
    // the end; kept separate from `canonical` because canonical retains the
    // escapes for bytes that are not legal literally in a path.
    let mut decoded: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut changed = false;
    let mut segment_start = 0usize;
    let mut segment_has_escape = false;
    let mut index = 0usize;

    while index < bytes.len() {
        let byte = bytes[index];

        if byte == b'/' {
            check_segment(&canonical, segment_start, segment_has_escape)?;
            canonical.push(b'/');
            decoded.push(b'/');
            segment_start = canonical.len();
            segment_has_escape = false;
            index += 1;
            continue;
        }

        if byte != b'%' {
            canonical.push(byte);
            decoded.push(byte);
            index += 1;
            continue;
        }

        let (Some(high), Some(low)) = (
            bytes.get(index + 1).copied().and_then(hex_value),
            bytes.get(index + 2).copied().and_then(hex_value),
        ) else {
            return Err(PolicyPathRejection::InvalidEscape);
        };
        let value = (high << 4) | low;

        match value {
            b'%' => return Err(PolicyPathRejection::DoubleEncoding),
            b'/' | b'?' | b'#' => return Err(PolicyPathRejection::EncodedSeparator),
            b'\\' => return Err(PolicyPathRejection::EncodedBackslash),
            0x00..=0x1F | 0x7F => return Err(PolicyPathRejection::EncodedControl),
            _ => {}
        }

        decoded.push(value);
        if DECODE_TO_LITERAL[value as usize] {
            canonical.push(value);
            changed = true;
        } else {
            let high_hex = HEX_UPPER[(value >> 4) as usize];
            let low_hex = HEX_UPPER[(value & 0x0F) as usize];
            if bytes[index + 1] != high_hex || bytes[index + 2] != low_hex {
                changed = true;
            }
            canonical.push(b'%');
            canonical.push(high_hex);
            canonical.push(low_hex);
        }
        segment_has_escape = true;
        index += 3;
    }

    check_segment(&canonical, segment_start, segment_has_escape)?;

    if std::str::from_utf8(&decoded).is_err() {
        return Err(PolicyPathRejection::InvalidUtf8);
    }

    if !changed {
        return Ok(Cow::Borrowed(raw));
    }

    // `canonical` is `raw`'s literal bytes (valid UTF-8, copied in order and
    // never split mid-codepoint) interleaved with decoded ASCII `pchar`s and
    // ASCII escape text, so it is valid UTF-8 by construction. The fallible
    // form keeps this a documented invariant instead of a panic.
    match String::from_utf8(canonical) {
        Ok(canonical) => Ok(Cow::Owned(canonical)),
        Err(_) => Err(PolicyPathRejection::InvalidUtf8),
    }
}

/// Why an operator-configured path value is not already a canonical policy
/// path, or `None` when it is.
///
/// Configured `listen_path` prefixes and plugin path triggers are compared
/// against the canonical request path, so a configured value that is itself
/// non-canonical can never match anything. Admission uses this to reject at
/// config time rather than fail silently at request time; sharing
/// [`canonicalize_policy_path`] keeps admission and runtime on one model.
pub fn non_canonical_policy_path_reason(path: &str) -> Option<&'static str> {
    match canonicalize_policy_path(path) {
        Ok(Cow::Borrowed(_)) => None,
        Ok(Cow::Owned(_)) => Some("percent-escapes that canonicalize to a different path"),
        Err(rejection) => Some(rejection.reason()),
    }
}
