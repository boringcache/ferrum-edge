//! Shared synthetic-response wire semantics for H1/H2/H3.
//!
//! Plugin short-circuits and gateway reject writers must agree on when a final
//! response may carry content bytes. HEAD responses keep representation
//! metadata (including `Content-Length`) but never emit a message body.
//! Statuses 204/205/304 never carry content.

use std::borrow::Cow;
use std::collections::HashMap;

/// Statuses that must not carry a message body (RFC 9110).
#[inline]
pub fn status_forbids_response_body(status: u16) -> bool {
    matches!(status, 204 | 205 | 304)
}

/// Whether the wire response must omit content bytes for this method/status.
#[inline]
pub fn synthetic_response_omits_body(method: &str, status: u16) -> bool {
    method.eq_ignore_ascii_case("HEAD") || status_forbids_response_body(status)
}

/// Prepare headers and return the bytes that may be written on the wire.
///
/// For `HEAD`, preserves (or installs) `Content-Length` equal to the
/// representation size that a GET would have returned, then returns an empty
/// wire body. For 204/205/304, strips `Content-Length` and returns an empty
/// wire body. All other responses return `body` unchanged.
pub fn prepare_synthetic_response_wire<'a>(
    method: &str,
    status: u16,
    headers: &mut HashMap<String, String>,
    body: &'a [u8],
) -> Cow<'a, [u8]> {
    if method.eq_ignore_ascii_case("HEAD") {
        if status_forbids_response_body(status) {
            remove_content_length(headers);
        } else {
            headers
                .entry("content-length".to_string())
                .or_insert_with(|| body.len().to_string());
        }
        return Cow::Borrowed(&[]);
    }

    if status_forbids_response_body(status) {
        remove_content_length(headers);
        return Cow::Borrowed(&[]);
    }

    Cow::Borrowed(body)
}

fn remove_content_length(headers: &mut HashMap<String, String>) {
    headers.retain(|name, _| !name.eq_ignore_ascii_case("content-length"));
}
