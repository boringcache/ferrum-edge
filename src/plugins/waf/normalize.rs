//! Decode/normalization pass for WAF body scanning.
//!
//! The body regex set runs over raw bytes, so a payload hidden behind an
//! encoding the rules never see slips through: JSON `<script>`,
//! HTML `&lt;script&gt;`, or form `%3Cscript%3E`. `decoded_variants` returns
//! up to [`MAX_VARIANTS`] normalized forms of a value (deduped, and excluding
//! the raw input which the caller scans separately) so the same rule set
//! matches the decoded payload without per-rule changes.
//!
//! Decoders are deliberately content-type-agnostic: an attacker controls the
//! declared `Content-Type`, so we apply every transformation regardless. Each
//! decoder borrows its input when there is nothing to decode, so plain bodies
//! produce zero variants and zero allocations.

use std::borrow::Cow;

use percent_encoding::percent_decode_str;

/// Maximum number of normalized variants produced per value (excluding the
/// raw input). Bounds body-scan cost at `O(VARIANTS × bytes × rules)`; the
/// underlying `RegexSet` matching is linear so this is a hard multiplier.
const MAX_VARIANTS: usize = 4;
const MAX_NUMERIC_ENTITY_DIGITS: usize = 16;

/// Produce normalized decodings of `text` distinct from the raw input.
///
/// The caller already scans the raw bytes; these variants surface payloads
/// hidden behind percent-, HTML-entity-, and JSON/JS-unicode encoding,
/// including stacked combinations via the fully layered decode.
pub(super) fn decoded_variants(text: &str) -> Vec<String> {
    if !has_decodable_marker(text) {
        return Vec::new();
    }

    // Layered decode catches stacked encodings (e.g. percent-encoded HTML
    // entities). The single-layer decodes are kept as well because a layered
    // percent-decode can mangle a body that merely contains a literal `%`,
    // and we still want the JSON/HTML-only decode to fire in that case.
    let layered = layered_decode(text);
    let candidates = [
        Cow::Owned(layered),
        unicode_unescape(text),
        html_entity_decode(text),
        percent_decode_plus(text),
    ];

    let mut out: Vec<String> = Vec::new();
    for candidate in candidates {
        if out.len() >= MAX_VARIANTS {
            break;
        }
        if candidate.as_ref() != text && !out.iter().any(|existing| existing == candidate.as_ref())
        {
            out.push(candidate.into_owned());
        }
    }
    out
}

fn has_decodable_marker(text: &str) -> bool {
    text.as_bytes()
        .iter()
        .any(|byte| matches!(byte, b'%' | b'+' | b'\\' | b'&'))
}

fn layered_decode(text: &str) -> String {
    let mut current = text.to_string();
    for _ in 0..3 {
        let percent = percent_decode_plus(&current).into_owned();
        let unicode = unicode_unescape(&percent).into_owned();
        let html = html_entity_decode(&unicode).into_owned();
        if html == current {
            break;
        }
        current = html;
    }
    current
}

/// Percent-decode (`%XX`) and translate `+` to space (form-encoding). Lossy on
/// invalid UTF-8 sequences, which is fine for pattern detection.
fn percent_decode_plus(text: &str) -> Cow<'_, str> {
    if !text.as_bytes().contains(&b'%') {
        if text.as_bytes().contains(&b'+') {
            return Cow::Owned(text.replace('+', " "));
        }
        return Cow::Borrowed(text);
    }
    let decoded = percent_decode_str(text).decode_utf8_lossy();
    if decoded.as_bytes().contains(&b'+') {
        Cow::Owned(decoded.replace('+', " "))
    } else {
        decoded
    }
}

/// Decode JSON/JavaScript unicode escapes: `\uXXXX` (with surrogate pairs),
/// `\u{XXXX}`, and `\xXX`. Unrecognized escapes keep their literal backslash.
fn unicode_unescape(text: &str) -> Cow<'_, str> {
    let bytes = text.as_bytes();
    if !bytes.contains(&b'\\') {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            if let Some((cp, consumed)) = decode_escape(&bytes[i + 1..]) {
                push_cp(&mut out, cp);
                i += 1 + consumed;
                continue;
            }
            out.push('\\');
            i += 1;
            continue;
        }
        let len = utf8_char_len(bytes[i]);
        let end = (i + len).min(bytes.len());
        out.push_str(&text[i..end]);
        i = end;
    }
    Cow::Owned(out)
}

/// Parse a single backslash escape from `after` (the bytes following `\`).
/// Returns the decoded code point and the number of bytes consumed from
/// `after`.
fn decode_escape(after: &[u8]) -> Option<(u32, usize)> {
    match after.first()? {
        b'u' | b'U' => {
            if after.get(1) == Some(&b'{') {
                let rel = after[2..].iter().position(|&c| c == b'}')?;
                let hex = &after[2..2 + rel];
                if hex.is_empty() || hex.len() > 6 {
                    return None;
                }
                Some((hex_n(hex)?, 2 + rel + 1))
            } else {
                let unit = hex4(after.get(1..5)?)?;
                if (0xD800..=0xDBFF).contains(&unit)
                    && after.get(5) == Some(&b'\\')
                    && matches!(after.get(6), Some(b'u') | Some(b'U'))
                    && let Some(low) = after.get(7..11).and_then(hex4)
                    && (0xDC00..=0xDFFF).contains(&low)
                {
                    let cp = 0x10000 + (((unit as u32 - 0xD800) << 10) | (low as u32 - 0xDC00));
                    return Some((cp, 11));
                }
                Some((unit as u32, 5))
            }
        }
        b'x' | b'X' => Some((hex2(after.get(1..3)?)? as u32, 3)),
        _ => None,
    }
}

/// Decode HTML entities: numeric (`&#NN;`, `&#xHH;`) and a small named set
/// covering the characters that compose injection syntax.
fn html_entity_decode(text: &str) -> Cow<'_, str> {
    let bytes = text.as_bytes();
    if !bytes.contains(&b'&') {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'&' {
            if let Some((value, consumed)) = decode_entity(&bytes[i + 1..]) {
                match value {
                    EntityVal::Cp(cp) => push_cp(&mut out, cp),
                    EntityVal::Str(s) => out.push_str(s),
                }
                i += 1 + consumed;
                continue;
            }
            out.push('&');
            i += 1;
            continue;
        }
        let len = utf8_char_len(bytes[i]);
        let end = (i + len).min(bytes.len());
        out.push_str(&text[i..end]);
        i = end;
    }
    Cow::Owned(out)
}

enum EntityVal {
    Cp(u32),
    Str(&'static str),
}

/// Parse a single HTML entity from `after` (the bytes following `&`).
/// Returns the decoded value and bytes consumed from `after` (including `;`).
fn decode_entity(after: &[u8]) -> Option<(EntityVal, usize)> {
    if after.first() == Some(&b'#') {
        let (radix, start) = if matches!(after.get(1), Some(b'x') | Some(b'X')) {
            (16u32, 2usize)
        } else {
            (10u32, 1usize)
        };
        let mut j = start;
        // Keep this bounded while still accepting leading-zero padded entities.
        while j < after.len() && after[j] != b';' && j - start < MAX_NUMERIC_ENTITY_DIGITS {
            j += 1;
        }
        if j >= after.len() || after[j] != b';' || j == start {
            return None;
        }
        let digits = &after[start..j];
        let cp = if radix == 16 {
            hex_n(digits)?
        } else {
            dec_n(digits)?
        };
        Some((EntityVal::Cp(cp), j + 1))
    } else {
        let mut j = 0;
        while j < after.len() && after[j] != b';' && j < 10 {
            j += 1;
        }
        if j >= after.len() || after[j] != b';' {
            return None;
        }
        let name = &after[..j];
        let s = if name.eq_ignore_ascii_case(b"lt") {
            "<"
        } else if name.eq_ignore_ascii_case(b"gt") {
            ">"
        } else if name.eq_ignore_ascii_case(b"amp") {
            "&"
        } else if name.eq_ignore_ascii_case(b"quot") {
            "\""
        } else if name.eq_ignore_ascii_case(b"apos") {
            "'"
        } else if name.eq_ignore_ascii_case(b"sol") {
            "/"
        } else if name.eq_ignore_ascii_case(b"colon") {
            ":"
        } else if name.eq_ignore_ascii_case(b"lpar") {
            "("
        } else if name.eq_ignore_ascii_case(b"rpar") {
            ")"
        } else if name.eq_ignore_ascii_case(b"period") {
            "."
        } else if name.eq_ignore_ascii_case(b"excl") {
            "!"
        } else if name.eq_ignore_ascii_case(b"equals") {
            "="
        } else if name.eq_ignore_ascii_case(b"grave") {
            "`"
        } else if name.eq_ignore_ascii_case(b"dollar") {
            "$"
        } else if name.eq_ignore_ascii_case(b"lbrace") {
            "{"
        } else if name.eq_ignore_ascii_case(b"rbrace") {
            "}"
        } else if name.eq_ignore_ascii_case(b"nbsp") {
            " "
        } else if name.eq_ignore_ascii_case(b"tab") {
            "\t"
        } else if name.eq_ignore_ascii_case(b"newline") {
            "\n"
        } else {
            return None;
        };
        Some((EntityVal::Str(s), j + 1))
    }
}

#[inline]
fn push_cp(out: &mut String, cp: u32) {
    out.push(char::from_u32(cp).unwrap_or('\u{FFFD}'));
}

#[inline]
fn utf8_char_len(first: u8) -> usize {
    if first < 0x80 {
        1
    } else if first >> 5 == 0b110 {
        2
    } else if first >> 4 == 0b1110 {
        3
    } else if first >> 3 == 0b11110 {
        4
    } else {
        1
    }
}

#[inline]
fn hex_digit(c: u8) -> Option<u32> {
    match c {
        b'0'..=b'9' => Some((c - b'0') as u32),
        b'a'..=b'f' => Some((c - b'a' + 10) as u32),
        b'A'..=b'F' => Some((c - b'A' + 10) as u32),
        _ => None,
    }
}

fn hex_n(bytes: &[u8]) -> Option<u32> {
    let mut value = 0u32;
    for &c in bytes {
        value = value.checked_mul(16)?.checked_add(hex_digit(c)?)?;
    }
    Some(value)
}

fn hex4(bytes: &[u8]) -> Option<u16> {
    if bytes.len() != 4 {
        return None;
    }
    Some(hex_n(bytes)? as u16)
}

fn hex2(bytes: &[u8]) -> Option<u8> {
    if bytes.len() != 2 {
        return None;
    }
    Some(hex_n(bytes)? as u8)
}

fn dec_n(bytes: &[u8]) -> Option<u32> {
    let mut value = 0u32;
    for &c in bytes {
        if !c.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add((c - b'0') as u32)?;
    }
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unicode_unescape_decodes_json_payload() {
        assert_eq!(unicode_unescape(r"<script>"), "<script>");
        assert_eq!(unicode_unescape(r"${jndi"), "${jndi");
    }

    #[test]
    fn unicode_unescape_handles_surrogate_pairs_and_braces() {
        assert_eq!(unicode_unescape(r"😀"), "\u{1F600}");
        assert_eq!(unicode_unescape(r"\u{3c}script"), "<script");
        assert_eq!(unicode_unescape(r"\x3cscript"), "<script");
    }

    #[test]
    fn unicode_unescape_preserves_unknown_escapes_and_plain_text() {
        assert!(matches!(unicode_unescape("plain text"), Cow::Borrowed(_)));
        assert_eq!(unicode_unescape(r"a\nb\qc"), r"a\nb\qc");
    }

    #[test]
    fn html_entity_decode_named_and_numeric() {
        assert_eq!(html_entity_decode("&lt;script&gt;"), "<script>");
        assert_eq!(html_entity_decode("&LT;script&GT;"), "<script>");
        assert_eq!(html_entity_decode("&#60;script&#62;"), "<script>");
        assert_eq!(
            html_entity_decode("&#000000060;script&#000000062;"),
            "<script>"
        );
        assert_eq!(html_entity_decode("&#x3c;script&#x3e;"), "<script>");
        assert!(matches!(
            html_entity_decode("no entities"),
            Cow::Borrowed(_)
        ));
    }

    #[test]
    fn percent_decode_plus_decodes_form_encoding() {
        assert_eq!(percent_decode_plus("%3Cscript%3E"), "<script>");
        assert_eq!(percent_decode_plus("a+b"), "a b");
        assert!(matches!(percent_decode_plus("plain"), Cow::Borrowed(_)));
    }

    #[test]
    fn decoded_variants_skips_raw_and_dedups() {
        // Plain text yields no variants (raw is scanned by the caller).
        assert!(decoded_variants("nothing to decode").is_empty());
        // A stacked encoding is recovered by the layered decode.
        let variants = decoded_variants("%26lt%3Bscript%26gt%3B");
        assert!(variants.iter().any(|v| v == "<script>"));
        assert!(variants.len() <= MAX_VARIANTS);
    }

    #[test]
    fn plain_text_has_no_decodable_markers() {
        assert!(!has_decodable_marker("nothing to decode"));
        assert!(has_decodable_marker("%3Cscript%3E"));
        assert!(has_decodable_marker("&lt;script&gt;"));
        assert!(has_decodable_marker(r"\u003cscript\u003e"));
        assert!(has_decodable_marker("a+b"));
    }

    #[test]
    fn decoded_variants_recovers_escaped_script() {
        // `\x`-escaped `<script>` — the raw byte scan never sees the tag.
        let variants = decoded_variants(r"{q:\x3cscript\x3ealert(1)}");
        assert!(variants.iter().any(|v| v.contains("<script>")));
    }

    #[test]
    fn decoded_variants_redecodes_unicode_escaped_html_entities() {
        let variants = decoded_variants(r#"\u0026lt;script\u0026gt;"#);
        assert!(variants.iter().any(|v| v.contains("<script>")));
    }
}
