//! Header lookup helpers for auth plugins reading credentials from request headers.
//!
//! `RequestContext::materialize_headers()` uses `HeaderValue::to_str()`, which
//! rejects bytes outside visible ASCII. Auth plugins must not treat a present
//! but non-materialized field line as absent.

use std::borrow::Cow;

use crate::plugins::{RequestContext, repeated_request_header_separator};

/// Result of looking up a configured header by name.
pub(crate) enum ConfiguredHeaderLookup<'a> {
    Absent,
    /// Borrowed for the common single-field-line case; repeated field lines
    /// allocate only when they actually need folding.
    Value(Cow<'a, str>),
    /// Raw field line(s) exist but cannot be represented as one visible-ASCII value.
    PresentNonMaterialized,
}

pub(crate) fn lookup_configured_header<'a>(
    ctx: &'a RequestContext,
    lower: &'a str,
    original: Option<&'a str>,
) -> ConfiguredHeaderLookup<'a> {
    // Retained raw field lines are authoritative. `materialize_headers()` can
    // preserve one visible-ASCII repeated line while omitting a malformed
    // sibling, so consulting the folded map first would let the valid line mask
    // hostile input.
    if ctx.has_raw_headers() {
        for name in [Some(lower), original] {
            let Some(name) = name else {
                continue;
            };
            if let Some(value) = raw_header_field_lines_to_utf8_string(ctx, name) {
                return value;
            }
        }
    }

    if let Some(value) = ctx
        .headers
        .get(lower)
        .or_else(|| original.and_then(|orig| ctx.headers.get(orig)))
    {
        return ConfiguredHeaderLookup::Value(Cow::Borrowed(value.as_str()));
    }

    ConfiguredHeaderLookup::Absent
}

fn raw_header_field_lines_to_utf8_string<'a>(
    ctx: &'a RequestContext,
    name: &'a str,
) -> Option<ConfiguredHeaderLookup<'a>> {
    let separator = repeated_request_header_separator(name);
    let mut values = ctx.raw_header_value_bytes(name);
    let first = values.next()?;
    let Some(first) = visible_ascii_header_value(first) else {
        return Some(ConfiguredHeaderLookup::PresentNonMaterialized);
    };
    let Some(second) = values.next() else {
        return Some(ConfiguredHeaderLookup::Value(Cow::Borrowed(first)));
    };

    let mut out = String::with_capacity(first.len() + separator.len() + second.len());
    out.push_str(first);
    for bytes in std::iter::once(second).chain(values) {
        let Some(value) = visible_ascii_header_value(bytes) else {
            return Some(ConfiguredHeaderLookup::PresentNonMaterialized);
        };
        out.push_str(separator);
        out.push_str(value);
    }
    Some(ConfiguredHeaderLookup::Value(Cow::Owned(out)))
}

fn visible_ascii_header_value(bytes: &[u8]) -> Option<&str> {
    // Keep this boundary identical to `HeaderValue::to_str()`, which is also
    // what `RequestContext::materialize_headers()` uses: SP through `~`, plus
    // HTAB. Merely checking UTF-8 would admit non-ASCII Unicode here even
    // though the materialized map deliberately omitted it, letting malformed
    // credential bytes reach a later parser as if the raw/materialized views
    // agreed.
    if !bytes
        .iter()
        .all(|byte| (*byte >= 0x20 && *byte < 0x7f) || *byte == b'\t')
    {
        return None;
    }
    std::str::from_utf8(bytes).ok()
}
