//! Header lookup helpers for auth plugins reading credentials from request headers.
//!
//! `RequestContext::materialize_headers()` uses `HeaderValue::to_str()`, which
//! rejects bytes outside visible ASCII. Auth plugins must not treat a present
//! but non-materialized field line as absent.

use crate::plugins::{RequestContext, repeated_request_header_separator};

/// Result of looking up a configured header by name.
pub(crate) enum ConfiguredHeaderLookup {
    Absent,
    Value(String),
    /// Raw field line(s) exist but cannot be represented as one valid UTF-8 value.
    PresentNonMaterialized,
}

pub(crate) fn lookup_configured_header(
    ctx: &RequestContext,
    lower: &str,
    original: Option<&str>,
) -> ConfiguredHeaderLookup {
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
        return ConfiguredHeaderLookup::Value(value.clone());
    }

    ConfiguredHeaderLookup::Absent
}

fn raw_header_field_lines_to_utf8_string(
    ctx: &RequestContext,
    name: &str,
) -> Option<ConfiguredHeaderLookup> {
    let separator = repeated_request_header_separator(name);
    let mut out = String::new();
    let mut found = false;
    for (idx, bytes) in ctx.raw_header_value_bytes(name).enumerate() {
        found = true;
        if idx > 0 {
            out.push_str(separator);
        }
        let Ok(value) = std::str::from_utf8(bytes) else {
            return Some(ConfiguredHeaderLookup::PresentNonMaterialized);
        };
        out.push_str(value);
    }
    found.then_some(ConfiguredHeaderLookup::Value(out))
}
