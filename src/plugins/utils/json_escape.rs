//! Shared JSON string escape helper used by AI plugins to safely embed
//! user-controlled text inside JSON error response bodies.
//!
//! Escapes JSON string metacharacters, control characters, and the `<`/`>`
//! characters (the latter two as `\u003c` / `\u003e`) so the result is safe
//! to interpolate inside a JSON string literal that may also be served to a
//! browser context.

/// Escape `s` for use inside a JSON string literal.
///
/// Replaces `\` -> `\\`, `"` -> `\"`, JSON control characters, `<` ->
/// `\u003c`, and `>` -> `\u003e`.
pub fn escape_json_string(s: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut escaped = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            '\u{08}' => escaped.push_str("\\b"),
            '\u{0c}' => escaped.push_str("\\f"),
            '<' => escaped.push_str("\\u003c"),
            '>' => escaped.push_str("\\u003e"),
            ch if ch < '\u{20}' => {
                escaped.push_str("\\u00");
                let byte = ch as u8;
                escaped.push(HEX[(byte >> 4) as usize] as char);
                escaped.push(HEX[(byte & 0x0f) as usize] as char);
            }
            ch => escaped.push(ch),
        }
    }
    escaped
}
