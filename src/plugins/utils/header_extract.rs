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
    /// Raw field line(s) exist but were omitted from the materialized map.
    PresentNonMaterialized,
}

pub(crate) fn lookup_configured_header(
    ctx: &RequestContext,
    lower: &str,
    original: Option<&str>,
) -> ConfiguredHeaderLookup {
    if let Some(value) = ctx
        .headers
        .get(lower)
        .or_else(|| original.and_then(|orig| ctx.headers.get(orig)))
    {
        return ConfiguredHeaderLookup::Value(value.clone());
    }

    if !ctx.has_raw_headers() {
        return ConfiguredHeaderLookup::Absent;
    }

    for name in [Some(lower), original] {
        let Some(name) = name else {
            continue;
        };
        if ctx.raw_header_value_bytes(name).next().is_some() {
            return ConfiguredHeaderLookup::PresentNonMaterialized;
        }
    }

    ConfiguredHeaderLookup::Absent
}

/// Read a configured header credential, falling back to raw field-line bytes
/// when `materialize_headers()` omitted a legal UTF-8 value.
pub(crate) fn extract_configured_header_value(
    ctx: &RequestContext,
    lower: &str,
    original: Option<&str>,
) -> Option<String> {
    match lookup_configured_header(ctx, lower, original) {
        ConfiguredHeaderLookup::Value(value) => Some(value),
        ConfiguredHeaderLookup::Absent => None,
        ConfiguredHeaderLookup::PresentNonMaterialized => {
            for name in [Some(lower), original] {
                let Some(name) = name else {
                    continue;
                };
                let values: Vec<&[u8]> = ctx.raw_header_value_bytes(name).collect();
                if values.is_empty() {
                    continue;
                }
                return raw_header_field_lines_to_utf8_string(name, &values);
            }
            None
        }
    }
}

fn raw_header_field_lines_to_utf8_string(name: &str, values: &[&[u8]]) -> Option<String> {
    let separator = repeated_request_header_separator(name);
    let mut out = String::new();
    for (idx, bytes) in values.iter().enumerate() {
        if idx > 0 {
            out.push_str(separator);
        }
        out.push_str(std::str::from_utf8(bytes).ok()?);
    }
    Some(out)
}
