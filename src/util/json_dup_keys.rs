//! Bounded duplicate-object-member screening for governed JSON documents.
//!
//! `serde_json` collapses duplicate object members by retaining the LAST value.
//! Other JSON parsers — including many backends, SDKs, and browser/JS consumers
//! for some shapes — retain the FIRST. A gateway that evaluates policy on the
//! collapsed `serde_json::Value` while forwarding the original bytes therefore
//! makes a decision about a value the next parser may never see
//! (advisory `GHSA-c78j-5w9p-cpq6`, CWE-436 interpretation conflict).
//!
//! This module is the ONE duplicate-aware validation primitive every governed
//! JSON boundary uses, so those boundaries cannot drift into divergent ad hoc
//! scanners. It performs a single non-recursive pass over the raw bytes that:
//!
//! - walks arbitrary nesting inside explicit depth / token / member / key /
//!   body budgets ([`JsonScanLimits`]) using an explicit stack, so a hostile
//!   document can neither recurse nor allocate without bound;
//! - decodes JSON escape sequences (including surrogate pairs) before comparing
//!   member names, so a member spelled literally and a member spelled with a
//!   `u`-escape for the same code point are recognized as one duplicated
//!   member and rejected;
//! - rejects malformed input rather than panicking.
//!
//! The scanner deliberately does NOT build a `serde_json::Value`: callers still
//! parse with `serde_json` afterwards. Screening first keeps the decision the
//! gateway makes and the bytes it forwards attached to the same, unambiguous
//! document.
//!
//! # Ambiguity vs. malformedness
//!
//! Governed call sites care about a narrower question than "did the scan
//! succeed": *are these bytes something a downstream parser would accept, but
//! that this gateway cannot faithfully evaluate?* [`slice_ambiguity`] answers
//! exactly that — it reports a reason ONLY when `serde_json` itself accepts the
//! document. That makes the screen fail-safe against any grammar divergence
//! between this scanner and `serde_json`: bytes the scanner mis-parses but
//! `serde_json` accepts are reported as ambiguous (fail closed), and bytes both
//! reject keep their existing "malformed body" handling. The confirmation parse
//! runs only on the rejection path, so the success path stays a single pass.
//!
//! Reasons are fixed-cardinality `&'static str` values and never echo any byte
//! of the inspected document, so they are safe to surface in warn/audit
//! metadata and in client-facing validator errors.

use std::borrow::Cow;
use std::collections::HashSet;

use sha2::{Digest as _, Sha256};

/// Why the bounded scanner refused to vouch for a document.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JsonScanReject {
    /// Two members of the same object decode to the same name.
    DuplicateKey,
    /// Container nesting passed [`JsonScanLimits::max_depth`].
    DepthExceeded,
    /// Value/member count passed [`JsonScanLimits::max_tokens`].
    TokenBudgetExceeded,
    /// One object carried more members than [`JsonScanLimits::max_object_members`].
    MemberBudgetExceeded,
    /// A member name was longer than [`JsonScanLimits::max_key_bytes`].
    KeyTooLong,
    /// The document was larger than [`JsonScanLimits::max_bytes`].
    TooLarge,
    /// The bytes are not a well-formed JSON document.
    Malformed,
}

impl JsonScanReject {
    /// Fixed-cardinality, operator-safe reason. Never contains any byte of the
    /// inspected document, so it is safe in client errors and audit metadata.
    pub fn reason(self) -> &'static str {
        match self {
            Self::DuplicateKey => "JSON body contains duplicate object member names",
            Self::DepthExceeded => "JSON body exceeds the duplicate-key scan depth budget",
            Self::TokenBudgetExceeded => "JSON body exceeds the duplicate-key scan token budget",
            Self::MemberBudgetExceeded => {
                "JSON body exceeds the duplicate-key scan object-member budget"
            }
            Self::KeyTooLong => "JSON body exceeds the duplicate-key scan member-name budget",
            Self::TooLarge => "JSON body exceeds the duplicate-key scan size budget",
            Self::Malformed => "JSON body is not well-formed JSON",
        }
    }
}

/// Explicit budgets for one scan. Every one of these bounds an allocation or a
/// loop, so a hostile document costs at most `O(max_bytes)` time and
/// `O(max_depth * max_object_members)`-bounded key storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JsonScanLimits {
    /// Largest document the scanner will look at at all.
    pub max_bytes: usize,
    /// Largest container nesting depth.
    pub max_depth: usize,
    /// Largest number of values plus member names.
    pub max_tokens: usize,
    /// Largest member count in any single object.
    pub max_object_members: usize,
    /// Largest raw member-name length in bytes.
    pub max_key_bytes: usize,
}

/// Budgets used by every governed JSON surface.
///
/// Depth is deliberately far ABOVE `serde_json`'s own 128-level recursion limit
/// so a legitimate deeply-nested body is never refused by this screen before
/// `serde_json` has had its say: anything deeper than 128 is rejected by the
/// parser itself and keeps its existing malformed handling. The remaining
/// budgets are similarly sized above any realistic governed payload — every
/// caller already applies its own, much tighter, body-size cap before reaching
/// the screen (for example `ai_tool_governor`'s 4 MiB inspection window and
/// `openapi_validator`'s configured `max_body_bytes`).
pub const GOVERNED_JSON_LIMITS: JsonScanLimits = JsonScanLimits {
    max_bytes: 64 * 1024 * 1024,
    max_depth: 256,
    max_tokens: 8_000_000,
    max_object_members: 1_000_000,
    max_key_bytes: 1024 * 1024,
};

/// One live container on the explicit (non-recursive) parse stack.
#[derive(Clone, Copy)]
enum Frame {
    Array,
    /// Index of this object's member-name set in the reused set pool.
    Object(usize),
}

/// Walk `bytes` once and prove that every object member name in the document is
/// unique, within `limits`.
///
/// This is a validator, not a parser: it produces no `Value` and allocates only
/// the bounded per-object member-name sets (and only for member names that
/// actually carry escape sequences).
pub fn scan<'a>(bytes: &'a [u8], limits: &JsonScanLimits) -> Result<(), JsonScanReject> {
    if bytes.len() > limits.max_bytes {
        return Err(JsonScanReject::TooLarge);
    }
    let mut index = 0usize;
    let mut tokens = 0usize;
    let mut frames: Vec<Frame> = Vec::new();
    // Member-name sets are pooled and cleared on reuse so a document that opens
    // and closes many sibling objects does not allocate a set per object.
    let mut sets: Vec<HashSet<Cow<'a, str>>> = Vec::new();
    let mut live_sets = 0usize;

    skip_whitespace(bytes, &mut index);

    'value: loop {
        tokens += 1;
        if tokens > limits.max_tokens {
            return Err(JsonScanReject::TokenBudgetExceeded);
        }
        match bytes.get(index) {
            None => return Err(JsonScanReject::Malformed),
            Some(b'{') => {
                index += 1;
                if frames.len() >= limits.max_depth {
                    return Err(JsonScanReject::DepthExceeded);
                }
                if live_sets == sets.len() {
                    sets.push(HashSet::new());
                } else {
                    sets[live_sets].clear();
                }
                frames.push(Frame::Object(live_sets));
                live_sets += 1;
                skip_whitespace(bytes, &mut index);
                if bytes.get(index) == Some(&b'}') {
                    index += 1;
                    frames.pop();
                    live_sets -= 1;
                } else {
                    read_member_name(bytes, &mut index, &mut sets[live_sets - 1], limits)?;
                    continue 'value;
                }
            }
            Some(b'[') => {
                index += 1;
                if frames.len() >= limits.max_depth {
                    return Err(JsonScanReject::DepthExceeded);
                }
                frames.push(Frame::Array);
                skip_whitespace(bytes, &mut index);
                if bytes.get(index) == Some(&b']') {
                    index += 1;
                    frames.pop();
                } else {
                    continue 'value;
                }
            }
            Some(b'"') => {
                read_string(bytes, &mut index)?;
            }
            Some(b't') => expect_literal(bytes, &mut index, b"true")?,
            Some(b'f') => expect_literal(bytes, &mut index, b"false")?,
            Some(b'n') => expect_literal(bytes, &mut index, b"null")?,
            Some(_) => read_number(bytes, &mut index)?,
        }

        // A value just completed. Close every container it finished and, when a
        // sibling follows, jump back to the value parser.
        loop {
            skip_whitespace(bytes, &mut index);
            // Copied out so the frame stack can be mutated inside the arms.
            let Some(frame) = frames.last().copied() else {
                break;
            };
            match frame {
                Frame::Array => match bytes.get(index) {
                    Some(b',') => {
                        index += 1;
                        skip_whitespace(bytes, &mut index);
                        continue 'value;
                    }
                    Some(b']') => {
                        index += 1;
                        frames.pop();
                    }
                    _ => return Err(JsonScanReject::Malformed),
                },
                Frame::Object(set_index) => match bytes.get(index) {
                    Some(b',') => {
                        index += 1;
                        skip_whitespace(bytes, &mut index);
                        tokens += 1;
                        if tokens > limits.max_tokens {
                            return Err(JsonScanReject::TokenBudgetExceeded);
                        }
                        read_member_name(bytes, &mut index, &mut sets[set_index], limits)?;
                        continue 'value;
                    }
                    Some(b'}') => {
                        index += 1;
                        frames.pop();
                        live_sets -= 1;
                    }
                    _ => return Err(JsonScanReject::Malformed),
                },
            }
        }
        break;
    }

    skip_whitespace(bytes, &mut index);
    if index != bytes.len() {
        // Trailing data. `serde_json::from_slice` rejects this too.
        return Err(JsonScanReject::Malformed);
    }
    Ok(())
}

/// Screen `bytes` for policy-relevant JSON ambiguity under
/// [`GOVERNED_JSON_LIMITS`].
///
/// Returns `Some(reason)` only when the bytes are a document `serde_json`
/// accepts but this scanner cannot prove unambiguous. Bytes that `serde_json`
/// also rejects return `None` so callers keep their existing malformed-body
/// handling instead of reclassifying every parse error as an ambiguity.
///
/// The caller must pass exactly the bytes it will hand to `serde_json` (BOM
/// already stripped, body already decoded), or the two verdicts describe
/// different documents.
pub fn slice_ambiguity(bytes: &[u8]) -> Option<&'static str> {
    slice_ambiguity_with(bytes, &GOVERNED_JSON_LIMITS)
}

/// [`slice_ambiguity`] with explicit budgets.
pub fn slice_ambiguity_with(bytes: &[u8], limits: &JsonScanLimits) -> Option<&'static str> {
    match scan(bytes, limits) {
        Ok(()) => None,
        Err(reject) => {
            // Confirmation parse, rejection path only: `IgnoredAny` walks the
            // whole document (and rejects trailing data) without materializing
            // it, so this costs one extra bounded pass on inputs that were
            // going to be rejected or re-parsed anyway.
            if serde_json::from_slice::<serde::de::IgnoredAny>(bytes).is_ok() {
                Some(reject.reason())
            } else {
                None
            }
        }
    }
}

/// [`slice_ambiguity`] for a `&str` document (an already-UTF-8 body, or a JSON
/// string whose CONTENT is itself parsed as a governed argument object).
pub fn str_ambiguity(text: &str) -> Option<&'static str> {
    slice_ambiguity(text.as_bytes())
}

/// Per-request memo so a multi-plugin chain screens one body once.
///
/// Several governed plugins (`openapi_validator`, `body_validator`,
/// `ai_tool_governor`) can all inspect the SAME buffered body in the same hook
/// stage. Re-scanning it per plugin is avoidable work on the request path, so
/// the first scan's verdict is staged here and reused.
///
/// Identity is the body's SHA-256 digest plus its length, NOT any assertion a
/// client, a backend, or `ctx.metadata` can write: a transform that rewrites the
/// body produces a different digest and is therefore re-screened rather than
/// inheriting the previous verdict. The memo lives on a private
/// `RequestContext` field, so nothing outside the gateway can seed it.
///
/// Bounded by construction: at most [`JsonScanMemo::CAPACITY`] entries of fixed
/// size, oldest evicted first. Bodies below [`JsonScanMemo::MIN_MEMO_BYTES`]
/// bypass the memo entirely — hashing them would cost more than re-scanning.
#[derive(Clone, Debug, Default)]
pub struct JsonScanMemo {
    entries: Vec<MemoEntry>,
}

#[derive(Clone, Debug)]
struct MemoEntry {
    len: usize,
    digest: [u8; 32],
    verdict: Option<&'static str>,
}

impl JsonScanMemo {
    /// Retained verdicts. Covers the pre-transform request body, the final
    /// backend-visible request body, the raw response body, and the
    /// client-visible response body, with headroom for decoded variants.
    pub const CAPACITY: usize = 8;

    /// Bodies smaller than this are scanned directly; the digest that keys the
    /// memo would cost more than the scan it saves.
    pub const MIN_MEMO_BYTES: usize = 4096;

    /// Screen `bytes`, reusing a previous verdict for byte-identical content.
    pub fn ambiguity(&mut self, bytes: &[u8]) -> Option<&'static str> {
        if bytes.len() < Self::MIN_MEMO_BYTES {
            return slice_ambiguity(bytes);
        }
        let digest = sha256(bytes);
        if let Some(entry) = self
            .entries
            .iter()
            .find(|entry| entry.len == bytes.len() && entry.digest == digest)
        {
            return entry.verdict;
        }
        let verdict = slice_ambiguity(bytes);
        if self.entries.len() >= Self::CAPACITY {
            self.entries.remove(0);
        }
        self.entries.push(MemoEntry {
            len: bytes.len(),
            digest,
            verdict,
        });
        verdict
    }

    /// [`JsonScanMemo::ambiguity`] for a `&str` document.
    pub fn ambiguity_str(&mut self, text: &str) -> Option<&'static str> {
        self.ambiguity(text.as_bytes())
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let finalized = hasher.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&finalized);
    digest
}

fn skip_whitespace(bytes: &[u8], index: &mut usize) {
    while matches!(bytes.get(*index), Some(b' ' | b'\t' | b'\n' | b'\r')) {
        *index += 1;
    }
}

fn expect_literal(bytes: &[u8], index: &mut usize, literal: &[u8]) -> Result<(), JsonScanReject> {
    if bytes.get(*index..*index + literal.len()) == Some(literal) {
        *index += literal.len();
        Ok(())
    } else {
        Err(JsonScanReject::Malformed)
    }
}

/// Read one object member name plus its `:` separator, leaving `index` at the
/// first byte of the member value.
fn read_member_name<'a>(
    bytes: &'a [u8],
    index: &mut usize,
    names: &mut HashSet<Cow<'a, str>>,
    limits: &JsonScanLimits,
) -> Result<(), JsonScanReject> {
    let (raw, has_escape) = read_string(bytes, index)?;
    if raw.len() > limits.max_key_bytes {
        return Err(JsonScanReject::KeyTooLong);
    }
    skip_whitespace(bytes, index);
    if bytes.get(*index) != Some(&b':') {
        return Err(JsonScanReject::Malformed);
    }
    *index += 1;
    skip_whitespace(bytes, index);
    if names.len() >= limits.max_object_members {
        return Err(JsonScanReject::MemberBudgetExceeded);
    }
    // Compare DECODED names: `"a"` and `"a"` are the same member and must
    // collide here, exactly as they do in every JSON object model.
    if !names.insert(decode_member_name(raw, has_escape)) {
        return Err(JsonScanReject::DuplicateKey);
    }
    Ok(())
}

/// Validate one JSON string starting at `bytes[*index] == b'"'` and return its
/// raw (still-escaped) inner text plus whether it carries any escape sequence.
///
/// Grammar enforced here matches `serde_json`'s: no unescaped control bytes,
/// only the eight simple escapes plus `\uXXXX`, valid hex quads, and correctly
/// paired surrogates. On success `*index` points just past the closing quote.
fn read_string<'a>(bytes: &'a [u8], index: &mut usize) -> Result<(&'a str, bool), JsonScanReject> {
    if bytes.get(*index) != Some(&b'"') {
        return Err(JsonScanReject::Malformed);
    }
    let start = *index + 1;
    let mut position = start;
    let mut has_escape = false;
    loop {
        let byte = *bytes.get(position).ok_or(JsonScanReject::Malformed)?;
        match byte {
            b'"' => break,
            b'\\' => {
                has_escape = true;
                let escape = *bytes.get(position + 1).ok_or(JsonScanReject::Malformed)?;
                match escape {
                    b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => position += 2,
                    b'u' => {
                        let code = read_hex4(bytes, position + 2)?;
                        position += 6;
                        if (0xD800..0xDC00).contains(&code) {
                            // High surrogate: a low surrogate escape must follow.
                            if bytes.get(position) != Some(&b'\\')
                                || bytes.get(position + 1) != Some(&b'u')
                            {
                                return Err(JsonScanReject::Malformed);
                            }
                            let low = read_hex4(bytes, position + 2)?;
                            if !(0xDC00..0xE000).contains(&low) {
                                return Err(JsonScanReject::Malformed);
                            }
                            position += 6;
                        } else if (0xDC00..0xE000).contains(&code) {
                            // Lone low surrogate.
                            return Err(JsonScanReject::Malformed);
                        }
                    }
                    _ => return Err(JsonScanReject::Malformed),
                }
            }
            0x00..=0x1F => return Err(JsonScanReject::Malformed),
            _ => position += 1,
        }
    }
    let raw =
        std::str::from_utf8(&bytes[start..position]).map_err(|_| JsonScanReject::Malformed)?;
    *index = position + 1;
    Ok((raw, has_escape))
}

fn read_hex4(bytes: &[u8], at: usize) -> Result<u32, JsonScanReject> {
    let quad = bytes.get(at..at + 4).ok_or(JsonScanReject::Malformed)?;
    let mut value = 0u32;
    for &byte in quad {
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return Err(JsonScanReject::Malformed),
        };
        value = value * 16 + u32::from(digit);
    }
    Ok(value)
}

/// Decode a member name that [`read_string`] already validated. Borrowed when
/// the name carries no escape sequence, which is the overwhelmingly common
/// case, so ordinary bodies allocate nothing per member.
fn decode_member_name(raw: &str, has_escape: bool) -> Cow<'_, str> {
    if !has_escape {
        return Cow::Borrowed(raw);
    }
    let bytes = raw.as_bytes();
    let mut out = String::with_capacity(raw.len());
    let mut position = 0usize;
    while position < bytes.len() {
        if bytes[position] != b'\\' {
            let start = position;
            while position < bytes.len() && bytes[position] != b'\\' {
                position += 1;
            }
            // `\` is ASCII, so both ends are UTF-8 character boundaries.
            out.push_str(&raw[start..position]);
            continue;
        }
        // Every escape here was validated by `read_string`; the fallbacks below
        // keep this function total rather than relying on that invariant.
        match bytes.get(position + 1) {
            Some(b'"') => {
                out.push('"');
                position += 2;
            }
            Some(b'\\') => {
                out.push('\\');
                position += 2;
            }
            Some(b'/') => {
                out.push('/');
                position += 2;
            }
            Some(b'b') => {
                out.push('\u{0008}');
                position += 2;
            }
            Some(b'f') => {
                out.push('\u{000C}');
                position += 2;
            }
            Some(b'n') => {
                out.push('\n');
                position += 2;
            }
            Some(b'r') => {
                out.push('\r');
                position += 2;
            }
            Some(b't') => {
                out.push('\t');
                position += 2;
            }
            Some(b'u') => {
                let code = read_hex4(bytes, position + 2).unwrap_or(0);
                position += 6;
                let scalar = if (0xD800..0xDC00).contains(&code) {
                    let low = read_hex4(bytes, position + 2).unwrap_or(0xDC00);
                    position += 6;
                    0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00)
                } else {
                    code
                };
                out.push(char::from_u32(scalar).unwrap_or('\u{FFFD}'));
            }
            _ => position += 2,
        }
    }
    Cow::Owned(out)
}

/// Validate one JSON number. Mirrors `serde_json`: optional `-`, no leading `+`,
/// no leading zeros, at least one digit after `.` and after an exponent sign.
fn read_number(bytes: &[u8], index: &mut usize) -> Result<(), JsonScanReject> {
    let mut position = *index;
    if bytes.get(position) == Some(&b'-') {
        position += 1;
    }
    match bytes.get(position) {
        Some(b'0') => position += 1,
        Some(b'1'..=b'9') => {
            position += 1;
            while matches!(bytes.get(position), Some(b'0'..=b'9')) {
                position += 1;
            }
        }
        _ => return Err(JsonScanReject::Malformed),
    }
    if bytes.get(position) == Some(&b'.') {
        position += 1;
        if !matches!(bytes.get(position), Some(b'0'..=b'9')) {
            return Err(JsonScanReject::Malformed);
        }
        while matches!(bytes.get(position), Some(b'0'..=b'9')) {
            position += 1;
        }
    }
    if matches!(bytes.get(position), Some(b'e' | b'E')) {
        position += 1;
        if matches!(bytes.get(position), Some(b'+' | b'-')) {
            position += 1;
        }
        if !matches!(bytes.get(position), Some(b'0'..=b'9')) {
            return Err(JsonScanReject::Malformed);
        }
        while matches!(bytes.get(position), Some(b'0'..=b'9')) {
            position += 1;
        }
    }
    *index = position;
    Ok(())
}
