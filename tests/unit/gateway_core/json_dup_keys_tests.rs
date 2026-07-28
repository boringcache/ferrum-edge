//! Tests for the shared duplicate-object-member JSON screen
//! (`crate::util::json_dup_keys`), the single primitive every governed JSON
//! boundary uses for advisory `GHSA-c78j-5w9p-cpq6`.
//!
//! The property under test throughout is the parser differential itself: a
//! document where a FIRST-key-wins reader and `serde_json`'s LAST-key-wins
//! reader disagree must never be vouched for.

use ferrum_edge::util::json_dup_keys::{
    GOVERNED_JSON_LIMITS, JsonScanLimits, JsonScanMemo, JsonScanReject, scan, slice_ambiguity,
    slice_ambiguity_with, str_ambiguity,
};

/// A single escape sequence for U+0061 (`a`), built without embedding the
/// literal in a Rust string so no editor/tooling layer can silently decode it.
fn escaped_a() -> String {
    format!("{}u0061", '\\')
}

fn scan_governed(body: &str) -> Result<(), JsonScanReject> {
    scan(body.as_bytes(), &GOVERNED_JSON_LIMITS)
}

// ---------------------------------------------------------------------------
// First-key / last-key differentials
// ---------------------------------------------------------------------------

/// The core advisory shape: `serde_json` sees `role=safe`, a first-key-wins
/// backend sees `role=admin`. The screen must refuse to vouch for it.
#[test]
fn rejects_duplicate_member_first_and_last_differ() {
    let body = r#"{"role":"admin","role":"safe"}"#;
    assert_eq!(scan_governed(body), Err(JsonScanReject::DuplicateKey));
    assert!(str_ambiguity(body).is_some());

    // Confirm the differential actually exists: serde keeps the LAST value.
    let parsed: serde_json::Value = serde_json::from_str(body).expect("serde accepts it");
    assert_eq!(parsed["role"], "safe");
}

/// Order reversal is the same defect; neither direction may pass.
#[test]
fn rejects_duplicate_member_in_either_order() {
    let body = r#"{"role":"safe","role":"admin"}"#;
    assert_eq!(scan_governed(body), Err(JsonScanReject::DuplicateKey));
    assert!(str_ambiguity(body).is_some());
}

/// Identical repeated values are still ambiguous *documents*: the point is that
/// two parsers may structure them differently, and refusing uniformly keeps the
/// rule auditable.
#[test]
fn rejects_duplicate_member_with_equal_values() {
    assert_eq!(
        scan_governed(r#"{"a":1,"a":1}"#),
        Err(JsonScanReject::DuplicateKey)
    );
}

// ---------------------------------------------------------------------------
// Escaped / semantically equal names
// ---------------------------------------------------------------------------

/// `"a"` and the `u`-escaped spelling of the same code point are one member.
#[test]
fn rejects_escaped_and_literal_names_that_decode_equal() {
    let body = format!(r#"{{"a":"admin","{}":"safe"}}"#, escaped_a());
    assert_eq!(
        scan(body.as_bytes(), &GOVERNED_JSON_LIMITS),
        Err(JsonScanReject::DuplicateKey)
    );
    assert!(str_ambiguity(&body).is_some());

    // serde_json agrees these are one member (it keeps the later value), which
    // is exactly why the raw bytes are dangerous to forward.
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("serde accepts it");
    assert_eq!(parsed["a"], "safe");
    assert_eq!(parsed.as_object().expect("object").len(), 1);
}

/// Two differently-escaped spellings of the same name also collide.
#[test]
fn rejects_two_escaped_spellings_of_one_name() {
    let escaped = escaped_a();
    let body = format!(r#"{{"{escaped}":1,"{escaped}":2}}"#);
    assert_eq!(
        scan(body.as_bytes(), &GOVERNED_JSON_LIMITS),
        Err(JsonScanReject::DuplicateKey)
    );
}

/// Simple (non-`u`) escapes decode before comparison too: `a\/b` is `a/b`.
#[test]
fn rejects_simple_escape_equal_to_literal_name() {
    let escaped_slash = format!("{}/", '\\');
    let body = format!(r#"{{"a{escaped_slash}b":1,"a/b":2}}"#);
    assert_eq!(
        scan(body.as_bytes(), &GOVERNED_JSON_LIMITS),
        Err(JsonScanReject::DuplicateKey)
    );
}

/// An escaped name that DECODES to an existing name collides; one that decodes
/// to a different name does not. Escape handling must not over-reject.
#[test]
fn escaped_names_collide_only_when_they_decode_equal() {
    let colliding = format!(r#"{{"a":1,"{}b":2,"ab":3}}"#, escaped_a());
    assert_eq!(
        scan(colliding.as_bytes(), &GOVERNED_JSON_LIMITS),
        Err(JsonScanReject::DuplicateKey)
    );

    let distinct = format!(r#"{{"a":1,"{}c":2,"ab":3}}"#, escaped_a());
    assert_eq!(scan(distinct.as_bytes(), &GOVERNED_JSON_LIMITS), Ok(()));
    assert!(str_ambiguity(&distinct).is_none());
}

/// A surrogate pair decodes to one astral scalar and collides with its literal
/// spelling.
#[test]
fn rejects_surrogate_pair_equal_to_literal_astral_name() {
    let backslash = '\\';
    // U+1F600, spelled as a UTF-16 surrogate-pair escape.
    let escaped = format!("{backslash}ud83d{backslash}ude00");
    let literal = '\u{1F600}'.to_string();
    let body = format!(r#"{{"{literal}":1,"{escaped}":2}}"#);
    assert_eq!(
        scan(body.as_bytes(), &GOVERNED_JSON_LIMITS),
        Err(JsonScanReject::DuplicateKey)
    );
}

// ---------------------------------------------------------------------------
// Nesting, arrays, and clean documents
// ---------------------------------------------------------------------------

#[test]
fn accepts_clean_nested_document() {
    let body = r#"{
        "a": 1,
        "b": {"c": [1, 2, {"d": true, "e": null}], "f": "x"},
        "g": [[], {}, [{"h": -1.5e10}]],
        "i": ""
    }"#;
    assert_eq!(scan_governed(body), Ok(()));
    assert!(str_ambiguity(body).is_none());
}

#[test]
fn rejects_duplicate_in_deeply_nested_object() {
    let body = r#"{"a":{"b":{"c":{"d":{"tool":"danger","tool":"safe"}}}}}"#;
    assert_eq!(scan_governed(body), Err(JsonScanReject::DuplicateKey));
}

#[test]
fn rejects_duplicate_inside_array_element() {
    let body = r#"{"calls":[{"ok":1},{"name":"danger","name":"safe"}]}"#;
    assert_eq!(scan_governed(body), Err(JsonScanReject::DuplicateKey));
}

#[test]
fn rejects_duplicate_in_top_level_array_element() {
    let body = r#"[{"method":"tools/call"},{"name":"danger","name":"safe"}]"#;
    assert_eq!(scan_governed(body), Err(JsonScanReject::DuplicateKey));
}

/// Sibling objects reusing the same member names are perfectly legal; the
/// pooled per-object name sets must be cleared between them.
#[test]
fn accepts_sibling_objects_reusing_names() {
    let body = r#"[{"a":1,"b":2},{"a":3,"b":4},{"a":5,"b":6}]"#;
    assert_eq!(scan_governed(body), Ok(()));
}

/// An inner object's names must not leak into the enclosing object's set.
#[test]
fn accepts_same_name_at_different_nesting_levels() {
    let body = r#"{"a":{"a":{"a":1}}}"#;
    assert_eq!(scan_governed(body), Ok(()));
}

#[test]
fn accepts_all_scalar_forms() {
    for body in [
        "null", "true", "false", "0", "-0", "1", "-1", "1.5", "1e10", "1E+10", "1.5e-10", r#""""#,
        r#""x""#, "[]", "{}",
    ] {
        assert_eq!(scan_governed(body), Ok(()), "rejected {body:?}");
    }
}

// ---------------------------------------------------------------------------
// Malformed input: no panics, and no ambiguity claim
// ---------------------------------------------------------------------------

/// Malformed input must be reported as malformed, not as ambiguity: callers
/// keep their existing "invalid JSON" handling for it.
#[test]
fn malformed_documents_are_not_reported_as_ambiguous() {
    for body in [
        "",
        " ",
        "{",
        "}",
        "[",
        "]",
        "{\"a\"}",
        "{\"a\":}",
        "{a:1}",
        "{'a':1}",
        "{\"a\":1,}",
        "[1,]",
        "[1 2]",
        "{\"a\":1}{",
        "{\"a\":1} trailing",
        "nul",
        "tru",
        "01",
        "+1",
        ".5",
        "1.",
        "1e",
        "1e+",
        "-",
        "NaN",
        "Infinity",
        "\"unterminated",
        "{\"a\":\"b}",
    ] {
        assert!(
            scan_governed(body).is_err(),
            "scanner accepted malformed {body:?}"
        );
        assert!(
            str_ambiguity(body).is_none(),
            "malformed {body:?} was reported as ambiguity"
        );
    }
}

/// Control characters and bad escapes inside strings are rejected the same way
/// `serde_json` rejects them.
#[test]
fn rejects_invalid_string_content_without_panicking() {
    let backslash = '\\';
    for body in [
        "{\"a\u{0001}\":1}".to_string(),
        format!("{{\"{backslash}q\":1}}"),
        format!("{{\"{backslash}u00\":1}}"),
        format!("{{\"{backslash}uZZZZ\":1}}"),
        // Lone high surrogate.
        format!("{{\"{backslash}ud83d\":1}}"),
        // Lone low surrogate.
        format!("{{\"{backslash}ude00\":1}}"),
        // High surrogate not followed by a low one.
        format!("{{\"{backslash}ud83d{backslash}u0061\":1}}"),
    ] {
        assert!(
            scan(body.as_bytes(), &GOVERNED_JSON_LIMITS).is_err(),
            "scanner accepted {body:?}"
        );
        assert!(
            slice_ambiguity(body.as_bytes()).is_none(),
            "{body:?} was reported as ambiguity rather than malformed"
        );
    }
}

/// Non-UTF-8 bytes are malformed, never a panic.
#[test]
fn rejects_non_utf8_bytes() {
    let body = b"{\"\xff\xfe\":1}";
    assert!(scan(body, &GOVERNED_JSON_LIMITS).is_err());
    assert!(slice_ambiguity(body).is_none());
    assert!(serde_json::from_slice::<serde_json::Value>(body).is_err());
}

/// Confirmation must track governed `serde_json::Value` acceptance, not the
/// looser `IgnoredAny` ignore-path: valid documents and syntactically valid
/// duplicates are distinguished from UTF-8 / surrogate / nesting / trailing
/// failures that `Value` also rejects.
#[test]
fn confirmation_matches_serde_json_value_acceptance() {
    let backslash = '\\';

    // Ordinary valid document: scanner accepts, no ambiguity.
    let clean = r#"{"a":1,"b":[true,null,"x"]}"#;
    assert!(serde_json::from_str::<serde_json::Value>(clean).is_ok());
    assert_eq!(scan_governed(clean), Ok(()));
    assert!(str_ambiguity(clean).is_none());

    // Syntactically valid duplicate keys: serde accepts, screen reports
    // ambiguity (never weakens to a pass).
    let duplicate = r#"{"role":"admin","role":"safe"}"#;
    assert!(serde_json::from_str::<serde_json::Value>(duplicate).is_ok());
    assert_eq!(
        str_ambiguity(duplicate),
        Some(JsonScanReject::DuplicateKey.reason())
    );

    // Trailing data: both parsers reject; not an ambiguity.
    let trailing = r#"{"a":1}{"b":2}"#;
    assert!(serde_json::from_str::<serde_json::Value>(trailing).is_err());
    assert!(str_ambiguity(trailing).is_none());

    // Lone / mispaired surrogates: `Value` rejects; must not be ambiguity.
    for body in [
        format!("{{\"{backslash}ud83d\":1}}"),
        format!("{{\"{backslash}ude00\":1}}"),
        format!("{{\"{backslash}ud83d{backslash}u0061\":1}}"),
    ] {
        assert!(
            serde_json::from_str::<serde_json::Value>(&body).is_err(),
            "serde Value unexpectedly accepted {body:?}"
        );
        assert!(
            slice_ambiguity(body.as_bytes()).is_none(),
            "{body:?} was reported as ambiguity rather than malformed"
        );
    }

    // Malformed UTF-8 in a member name.
    let non_utf8 = b"{\"\xff\xfe\":1}";
    assert!(serde_json::from_slice::<serde_json::Value>(non_utf8).is_err());
    assert!(slice_ambiguity(non_utf8).is_none());

    // Deep nesting past serde's recursion limit: not an ambiguity, and must
    // not stack-overflow on confirmation.
    let depth = 100_000usize;
    let mut deep = String::with_capacity(depth * 2);
    for _ in 0..depth {
        deep.push('[');
    }
    for _ in 0..depth {
        deep.push(']');
    }
    assert!(serde_json::from_str::<serde_json::Value>(&deep).is_err());
    assert!(slice_ambiguity(deep.as_bytes()).is_none());
}

/// A leading BOM is not stripped by the screen: callers must pass exactly the
/// bytes `serde_json` will see, and `serde_json` rejects a BOM-prefixed body.
#[test]
fn bom_prefixed_body_is_malformed_for_both_parsers() {
    let mut body = b"\xEF\xBB\xBF".to_vec();
    body.extend_from_slice(br#"{"a":1,"a":2}"#);
    assert!(scan(&body, &GOVERNED_JSON_LIMITS).is_err());
    assert!(slice_ambiguity(&body).is_none());
    // Stripped, the duplicate is caught.
    assert!(slice_ambiguity(&body[3..]).is_some());
}

// ---------------------------------------------------------------------------
// Budgets
// ---------------------------------------------------------------------------

/// Deep nesting must be bounded, and bounded WITHOUT recursion — 100k levels
/// would blow a recursive-descent stack.
#[test]
fn deep_nesting_exhausts_the_depth_budget_without_stack_overflow() {
    let depth = 100_000usize;
    let mut body = String::with_capacity(depth * 2);
    for _ in 0..depth {
        body.push('[');
    }
    for _ in 0..depth {
        body.push(']');
    }
    assert_eq!(
        scan(body.as_bytes(), &GOVERNED_JSON_LIMITS),
        Err(JsonScanReject::DepthExceeded)
    );
    // `serde_json` also refuses it (128-level recursion limit), so this is not
    // reported to callers as an ambiguity.
    assert!(slice_ambiguity(body.as_bytes()).is_none());
}

/// A document within `serde_json`'s recursion limit stays inside the governed
/// depth budget, so the screen never rejects what the parser accepts.
#[test]
fn governed_depth_budget_is_more_permissive_than_serde() {
    let depth = 120usize;
    let mut body = String::new();
    for _ in 0..depth {
        body.push('[');
    }
    for _ in 0..depth {
        body.push(']');
    }
    assert_eq!(scan(body.as_bytes(), &GOVERNED_JSON_LIMITS), Ok(()));
    assert!(serde_json::from_str::<serde_json::Value>(&body).is_ok());
}

#[test]
fn explicit_budgets_are_enforced() {
    let tight = JsonScanLimits {
        max_bytes: 8,
        ..GOVERNED_JSON_LIMITS
    };
    assert_eq!(
        scan(br#"{"aaaa":1}"#, &tight),
        Err(JsonScanReject::TooLarge)
    );

    let shallow = JsonScanLimits {
        max_depth: 1,
        ..GOVERNED_JSON_LIMITS
    };
    assert_eq!(scan(br#"{"a":1}"#, &shallow), Ok(()));
    assert_eq!(
        scan(br#"{"a":{"b":1}}"#, &shallow),
        Err(JsonScanReject::DepthExceeded)
    );

    let few_tokens = JsonScanLimits {
        max_tokens: 2,
        ..GOVERNED_JSON_LIMITS
    };
    assert!(matches!(
        scan(br#"{"a":1,"b":2,"c":3}"#, &few_tokens),
        Err(JsonScanReject::TokenBudgetExceeded)
    ));

    let few_members = JsonScanLimits {
        max_object_members: 2,
        ..GOVERNED_JSON_LIMITS
    };
    assert_eq!(
        scan(br#"{"a":1,"b":2,"c":3}"#, &few_members),
        Err(JsonScanReject::MemberBudgetExceeded)
    );

    let short_keys = JsonScanLimits {
        max_key_bytes: 2,
        ..GOVERNED_JSON_LIMITS
    };
    assert_eq!(
        scan(br#"{"abc":1}"#, &short_keys),
        Err(JsonScanReject::KeyTooLong)
    );
}

/// Size-budget exhaustion fails closed with the fixed TooLarge reason and does
/// not run content confirmation: an over-budget body may be arbitrarily larger
/// than `max_bytes`, and walking it would violate the scanner resource contract.
/// Valid and malformed oversize bodies both get the same bounded rejection;
/// in-budget malformed input still returns `None`, and in-budget duplicates
/// still return DuplicateKey.
#[test]
fn oversize_body_reports_size_budget_without_content_confirmation() {
    let tight = JsonScanLimits {
        max_bytes: 8,
        ..GOVERNED_JSON_LIMITS
    };

    // Over-budget and parseable: still TooLarge, without needing confirmation.
    let valid = br#"{"aaaa":1}"#;
    assert!(valid.len() > tight.max_bytes);
    assert_eq!(scan(valid, &tight), Err(JsonScanReject::TooLarge));
    assert!(serde_json::from_slice::<serde_json::Value>(valid).is_ok());
    assert_eq!(
        slice_ambiguity_with(valid, &tight),
        Some(JsonScanReject::TooLarge.reason())
    );

    // Over-budget and malformed: same fixed TooLarge reason (not None). Content
    // confirmation must not run past max_bytes just to reclassify as malformed.
    let malformed = br#"{"aaaa":!"#;
    assert!(malformed.len() > tight.max_bytes);
    assert_eq!(scan(malformed, &tight), Err(JsonScanReject::TooLarge));
    assert!(serde_json::from_slice::<serde_json::Value>(malformed).is_err());
    assert_eq!(
        slice_ambiguity_with(malformed, &tight),
        Some(JsonScanReject::TooLarge.reason())
    );

    // Over-budget with an escaped payload that would allocate if confirmation
    // decoded past the size bound: still TooLarge only.
    let mut escaped_oversize = Vec::from(&b"{\"\\u0061\\u0061\\u0061\\u0061\":1"[..]);
    // Ensure well past the tiny budget; trailing garbage keeps it malformed too.
    escaped_oversize.extend_from_slice(b"!!!!");
    assert!(escaped_oversize.len() > tight.max_bytes);
    assert_eq!(
        scan(&escaped_oversize, &tight),
        Err(JsonScanReject::TooLarge)
    );
    assert_eq!(
        slice_ambiguity_with(&escaped_oversize, &tight),
        Some(JsonScanReject::TooLarge.reason())
    );

    // Contrast: in-budget malformed stays None (confirmation rejects with Value).
    let in_budget_malformed = br#"{"a":"#;
    assert!(in_budget_malformed.len() <= tight.max_bytes);
    assert!(serde_json::from_slice::<serde_json::Value>(in_budget_malformed).is_err());
    assert!(slice_ambiguity_with(in_budget_malformed, &tight).is_none());

    // Contrast: in-budget valid duplicate still reports DuplicateKey.
    let duplicate = br#"{"a":1,"a":2}"#;
    assert!(duplicate.len() <= GOVERNED_JSON_LIMITS.max_bytes);
    assert_eq!(
        slice_ambiguity(duplicate),
        Some(JsonScanReject::DuplicateKey.reason())
    );
}

/// Budget exhaustion on a document `serde_json` accepts is an AMBIGUITY, not a
/// pass: the screen could not prove uniqueness, so callers fail closed.
#[test]
fn budget_exhaustion_on_parseable_input_is_reported_as_ambiguity() {
    let few_members = JsonScanLimits {
        max_object_members: 2,
        ..GOVERNED_JSON_LIMITS
    };
    let body = br#"{"a":1,"b":2,"c":3}"#;
    assert!(serde_json::from_slice::<serde_json::Value>(body).is_ok());
    assert_eq!(
        slice_ambiguity_with(body, &few_members),
        Some(JsonScanReject::MemberBudgetExceeded.reason())
    );
}

/// Every reason is a fixed-cardinality static string that echoes no input.
#[test]
fn reasons_are_fixed_cardinality_and_echo_no_input() {
    let body = r#"{"SECRET_MEMBER_NAME":1,"SECRET_MEMBER_NAME":2}"#;
    let reason = str_ambiguity(body).expect("ambiguous");
    assert!(!reason.contains("SECRET_MEMBER_NAME"));
    assert_eq!(reason, JsonScanReject::DuplicateKey.reason());
    for reject in [
        JsonScanReject::DuplicateKey,
        JsonScanReject::DepthExceeded,
        JsonScanReject::TokenBudgetExceeded,
        JsonScanReject::MemberBudgetExceeded,
        JsonScanReject::KeyTooLong,
        JsonScanReject::TooLarge,
        JsonScanReject::Malformed,
    ] {
        assert!(!reject.reason().is_empty());
    }
}

// ---------------------------------------------------------------------------
// Memo: multi-plugin reuse with body-identity semantics
// ---------------------------------------------------------------------------

/// A large clean body screened twice returns the same verdict; a large
/// ambiguous one likewise. The memo is a cache, never a decision.
#[test]
fn memo_returns_stable_verdicts_for_repeated_bodies() {
    let mut memo = JsonScanMemo::default();

    let mut clean = String::from("{\"pad\":\"");
    clean.push_str(&"x".repeat(JsonScanMemo::MIN_MEMO_BYTES * 2));
    clean.push_str("\",\"role\":\"safe\"}");
    assert!(memo.ambiguity_str(&clean).is_none());
    assert!(memo.ambiguity_str(&clean).is_none());

    let mut dirty = String::from("{\"pad\":\"");
    dirty.push_str(&"x".repeat(JsonScanMemo::MIN_MEMO_BYTES * 2));
    dirty.push_str("\",\"role\":\"admin\",\"role\":\"safe\"}");
    assert_eq!(
        memo.ambiguity_str(&dirty),
        Some(JsonScanReject::DuplicateKey.reason())
    );
    assert_eq!(
        memo.ambiguity_str(&dirty),
        Some(JsonScanReject::DuplicateKey.reason())
    );

    // The earlier clean verdict was not corrupted by the ambiguous body.
    assert!(memo.ambiguity_str(&clean).is_none());
}

/// A DIFFERENT body never inherits a previous verdict: identity is the body's
/// digest, so a transform that rewrites the body is re-screened. This is the
/// property that keeps the memo from becoming a bypass.
#[test]
fn memo_does_not_transfer_a_clean_verdict_to_a_rewritten_body() {
    let mut memo = JsonScanMemo::default();
    let pad = "x".repeat(JsonScanMemo::MIN_MEMO_BYTES * 2);

    let clean = format!("{{\"pad\":\"{pad}\",\"role\":\"safe\"}}");
    assert!(memo.ambiguity_str(&clean).is_none());

    // Same length class, same prefix, one member duplicated: must be caught.
    let rewritten = format!("{{\"pad\":\"{pad}\",\"role\":\"admin\",\"role\":\"safe\"}}");
    assert_eq!(
        memo.ambiguity_str(&rewritten),
        Some(JsonScanReject::DuplicateKey.reason())
    );
}

/// Small bodies bypass the memo entirely and are always screened directly.
#[test]
fn memo_screens_small_bodies_directly() {
    let mut memo = JsonScanMemo::default();
    assert!(memo.ambiguity_str(r#"{"a":1}"#).is_none());
    assert!(memo.ambiguity_str(r#"{"a":1,"a":2}"#).is_some());
    assert!(memo.ambiguity_str(r#"{"a":1}"#).is_none());
}

/// The memo is bounded: many distinct large bodies evict rather than grow, and
/// eviction never turns an ambiguous body into a clean one.
#[test]
fn memo_is_bounded_and_eviction_is_safe() {
    let mut memo = JsonScanMemo::default();
    let pad = "x".repeat(JsonScanMemo::MIN_MEMO_BYTES * 2);
    for index in 0..(JsonScanMemo::CAPACITY * 4) {
        let body = format!("{{\"pad\":\"{pad}\",\"n\":{index}}}");
        assert!(memo.ambiguity_str(&body).is_none());
    }
    let dirty = format!("{{\"pad\":\"{pad}\",\"n\":1,\"n\":2}}");
    assert_eq!(
        memo.ambiguity_str(&dirty),
        Some(JsonScanReject::DuplicateKey.reason())
    );
}
