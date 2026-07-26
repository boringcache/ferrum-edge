//! Canonical policy path contract (`src/policy_path.rs`).
//!
//! Covers the representation that routing, WAF, `openapi_validator`,
//! `request_termination`, authorization, cache keys, rewrites, and backend
//! forwarding all share (private advisory GHSA-69xf-42xm-4w4f).

use std::borrow::Cow;

use ferrum_edge::policy_path::{
    PolicyPathRejection, canonicalize_policy_path, non_canonical_policy_path_reason,
};

fn canonical(path: &str) -> String {
    canonicalize_policy_path(path)
        .unwrap_or_else(|rejection| panic!("{path:?} unexpectedly rejected: {rejection:?}"))
        .into_owned()
}

fn rejection(path: &str) -> PolicyPathRejection {
    canonicalize_policy_path(path)
        .err()
        .unwrap_or_else(|| panic!("{path:?} was unexpectedly accepted"))
}

// ── Fast path: no percent escape is never touched and never rejected ────────

#[test]
fn paths_without_escapes_are_borrowed_unchanged() {
    for path in [
        "",
        "/",
        "*",
        "/admin",
        "/api/v1/users/42",
        "/a/../b",
        "/a/./b",
        "/api//double",
        "/weird!$&'()*+,;=:@chars",
    ] {
        let result = canonicalize_policy_path(path).expect("no-escape path must be accepted");
        assert!(
            matches!(result, Cow::Borrowed(_)),
            "{path:?} must not allocate"
        );
        assert_eq!(result, path);
    }
}

// ── Ordinary single encoding: the advisory's headline bypass ───────────────

#[test]
fn ordinary_single_encoding_of_a_legal_path_character_is_decoded() {
    // `/%61dmin` and `/admin` must be the same policy path, or an operator's
    // literal `/admin` rule misses while a decoding backend serves `/admin`.
    assert_eq!(canonical("/%61dmin"), "/admin");
    assert_eq!(canonical("/%41DMIN"), "/ADMIN");
    assert_eq!(canonical("/api/%76%31/users"), "/api/v1/users");
    assert_eq!(canonical("/%61%64%6d%69%6e"), "/admin");
}

#[test]
fn every_unreserved_and_sub_delim_escape_is_decoded() {
    // RFC 3986 pchar minus pct-encoded: unreserved / sub-delims / ":" / "@".
    let cases = [
        ("/%2Dx", "/-x"),
        ("/%2Ex", "/.x"),
        ("/%5Fx", "/_x"),
        ("/%7Ex", "/~x"),
        ("/%21x", "/!x"),
        ("/%24x", "/$x"),
        ("/%26x", "/&x"),
        ("/%27x", "/'x"),
        ("/%28x", "/(x"),
        ("/%29x", "/)x"),
        ("/%2Ax", "/*x"),
        ("/%2Bx", "/+x"),
        ("/%2Cx", "/,x"),
        ("/%3Bx", "/;x"),
        ("/%3Dx", "/=x"),
        ("/%3Ax", "/:x"),
        ("/%40x", "/@x"),
    ];
    for (raw, expected) in cases {
        assert_eq!(canonical(raw), expected, "decoding {raw:?}");
    }
}

#[test]
fn escapes_of_characters_illegal_in_a_path_stay_encoded_with_uppercase_hex() {
    // Space cannot appear literally in a request target, so it stays escaped —
    // and the canonical form is uppercase hex (RFC 3986 6.2.2.1).
    assert_eq!(canonical("/api%20name"), "/api%20name");
    assert_eq!(canonical("/api%7bname%7d"), "/api%7Bname%7D");
    assert_eq!(canonical("/caf%c3%a9"), "/caf%C3%A9");
    // Already uppercase and undecodable: borrowed, not rebuilt.
    assert!(matches!(
        canonicalize_policy_path("/api%20name").expect("accepted"),
        Cow::Borrowed(_)
    ));
}

#[test]
fn canonical_form_is_idempotent_and_is_a_valid_request_target() {
    for raw in [
        "/%61dmin",
        "/api%20name",
        "/caf%c3%a9/%76%31",
        "/a/%2Ehidden",
        "/%40user/%3Bmatrix",
    ] {
        let once = canonical(raw);
        let twice = canonical(&once);
        assert_eq!(once, twice, "canonicalization must be idempotent for {raw:?}");
        // Every surviving `%` still introduces a complete escape, and no byte
        // that would need escaping was emitted literally.
        assert!(
            !once.bytes().any(|byte| byte <= 0x20 || byte == 0x7F),
            "{once:?} must be transmissible as a request target"
        );
    }
}

// ── Structure-preservation: encoded separators are rejected, not folded ─────

#[test]
fn encoded_separators_are_rejected() {
    for path in [
        "/api%2Fadmin",
        "/api%2fadmin",
        "/%2F",
        "/api%3Fquery",
        "/api%23fragment",
    ] {
        assert_eq!(
            rejection(path),
            PolicyPathRejection::EncodedSeparator,
            "{path:?}"
        );
    }
}

#[test]
fn encoded_backslash_is_rejected() {
    // Several backend stacks treat `\` as a separator; folding it would change
    // structure and rejecting is the only reading-independent answer.
    assert_eq!(
        rejection("/api%5Cadmin"),
        PolicyPathRejection::EncodedBackslash
    );
    assert_eq!(
        rejection("/api%5cadmin"),
        PolicyPathRejection::EncodedBackslash
    );
}

#[test]
fn double_encoding_is_rejected_at_the_lead_byte() {
    // `%252F` is the historical encoded-slash bypass; `%2561` is the same
    // trick applied to an ordinary character. Both trip on the encoded `%`.
    for path in ["/api%252Fadmin", "/api%252fadmin", "/%2561dmin", "/a%25b"] {
        assert_eq!(
            rejection(path),
            PolicyPathRejection::DoubleEncoding,
            "{path:?}"
        );
    }
}

// ── Invalid escapes and invalid UTF-8 ──────────────────────────────────────

#[test]
fn incomplete_or_non_hex_escapes_are_rejected() {
    for path in ["/api%", "/api%2", "/api%zz", "/api%2z", "/api%g0/more"] {
        assert_eq!(
            rejection(path),
            PolicyPathRejection::InvalidEscape,
            "{path:?}"
        );
    }
}

#[test]
fn escapes_that_do_not_decode_to_utf8_are_rejected() {
    // Backends disagree about invalid UTF-8 (reject / replace with U+FFFD /
    // pass through), so the gateway cannot know which path it authorized.
    for path in ["/caf%C3%28", "/%FF", "/%C3", "/%E2%82"] {
        assert_eq!(rejection(path), PolicyPathRejection::InvalidUtf8, "{path:?}");
    }
    // Valid multi-byte UTF-8 is accepted and stays escaped.
    assert_eq!(canonical("/caf%C3%A9"), "/caf%C3%A9");
    assert_eq!(canonical("/%E2%9C%93"), "/%E2%9C%93");
}

#[test]
fn encoded_control_characters_including_nul_are_rejected() {
    for path in ["/api%00", "/api%00admin", "/api%0A", "/api%0d", "/api%7F"] {
        assert_eq!(
            rejection(path),
            PolicyPathRejection::EncodedControl,
            "{path:?}"
        );
    }
}

// ── Dot segments ───────────────────────────────────────────────────────────

#[test]
fn escape_synthesized_dot_segments_are_rejected() {
    for path in [
        "/api/%2e%2e/admin",
        "/api/%2E%2E/admin",
        "/api/.%2e/admin",
        "/api/%2e./admin",
        "/api/%2e/admin",
        "/api/%2E",
    ] {
        assert_eq!(
            rejection(path),
            PolicyPathRejection::AmbiguousDotSegment,
            "{path:?}"
        );
    }
}

#[test]
fn literal_dot_segments_are_left_exactly_as_written() {
    // Canonicalization refuses ambiguity; it never rewrites a request's
    // meaning. A literal `..` is equally visible to operator, gateway, and
    // backend, so it stays put even when the path has other escapes.
    assert_eq!(canonical("/api/../admin"), "/api/../admin");
    assert_eq!(canonical("/api/./admin"), "/api/./admin");
    assert_eq!(canonical("/api/../%61dmin"), "/api/../admin");
}

#[test]
fn escapes_in_a_segment_that_is_not_a_dot_segment_are_fine() {
    assert_eq!(canonical("/api/%2ehidden"), "/api/.hidden");
    assert_eq!(canonical("/api/%2e%2ehidden"), "/api/..hidden");
    assert_eq!(canonical("/api/a%2e/b"), "/api/a./b");
}

// ── Rejection metadata is fixed, non-echoing text ──────────────────────────

#[test]
fn rejection_reasons_and_bodies_are_stable_and_echo_no_request_bytes() {
    let variants = [
        (PolicyPathRejection::InvalidEscape, "invalid_escape"),
        (PolicyPathRejection::DoubleEncoding, "double_encoding"),
        (PolicyPathRejection::EncodedSeparator, "encoded_separator"),
        (PolicyPathRejection::EncodedBackslash, "encoded_backslash"),
        (PolicyPathRejection::EncodedControl, "encoded_control"),
        (PolicyPathRejection::InvalidUtf8, "invalid_utf8"),
        (
            PolicyPathRejection::AmbiguousDotSegment,
            "ambiguous_dot_segment",
        ),
    ];
    for (variant, reason) in variants {
        assert_eq!(variant.reason(), reason);
        let body = variant.client_error_body();
        assert!(body.starts_with(r#"{"error":""#), "{body}");
        assert!(body.ends_with(r#""}"#), "{body}");
        // Parseable JSON with no interpolation seams.
        serde_json::from_str::<serde_json::Value>(body).expect("error body must be JSON");
        assert!(!variant.grpc_message().is_empty());
    }
}

// ── Admission helper shared with config validation ─────────────────────────

#[test]
fn non_canonical_reason_flags_config_values_that_can_never_match() {
    assert_eq!(non_canonical_policy_path_reason("/admin"), None);
    assert_eq!(non_canonical_policy_path_reason("/api%20name"), None);
    assert_eq!(non_canonical_policy_path_reason("*"), None);
    assert_eq!(non_canonical_policy_path_reason("/api/../admin"), None);

    assert_eq!(
        non_canonical_policy_path_reason("/%61dmin"),
        Some("percent-escapes that canonicalize to a different path")
    );
    assert_eq!(
        non_canonical_policy_path_reason("/api%2Fadmin"),
        Some("encoded_separator")
    );
    assert_eq!(
        non_canonical_policy_path_reason("/api%252Fadmin"),
        Some("double_encoding")
    );
    assert_eq!(
        non_canonical_policy_path_reason("/api%2"),
        Some("invalid_escape")
    );
    // Lowercase hex on an escape that survives still changes the bytes, so it
    // is not canonical as configured.
    assert_eq!(
        non_canonical_policy_path_reason("/api%7bname"),
        Some("percent-escapes that canonicalize to a different path")
    );
}
