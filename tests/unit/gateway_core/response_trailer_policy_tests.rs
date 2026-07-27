//! Backend trailers must not re-open the response-header policy a protocol
//! path already applied — and must survive untouched when no policy governs
//! them.
//!
//! `after_proxy` and every later response-header phase see only the INITIAL
//! header map, so a backend trailer repeating a governed field name lands on
//! the wire after the policy boundary. The reconciliation here is the boundary
//! that closes that gap on the buffered native-HTTP/3 send path AND on the
//! plain native/refined HTTP/3 streaming relays, without punishing chains that
//! apply no response-header policy at all (issue #2941 — auth/logging-only
//! plugins keep their trailers).
//!
//! The streaming relays commit their initial HEADERS frame before the backend's
//! trailers exist, so they retain the pre-policy header map instead of
//! per-trailer values and derive the witness at the trailer frame; the
//! `reconcile_streaming` cases below pin that capture decision as well as the
//! shared governance rules.

use std::collections::HashMap;

use ferrum_edge::_test_support::reconcile_backend_trailers_with_response_policy_for_test as reconcile;
use ferrum_edge::_test_support::reconcile_streaming_backend_trailers_for_test as reconcile_streaming;

fn headers(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
        .collect()
}

fn names(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}

fn has(trailers: &[(String, String)], name: &str) -> bool {
    trailers.iter().any(|(key, _)| key == name)
}

#[test]
fn auth_logging_only_chain_preserves_every_backend_trailer() {
    // No declared policy names and no observed header mutation: nothing about
    // this chain can be re-opened by a trailer, so all of them are forwarded.
    let backend = headers(&[("content-type", "text/plain")]);
    let surviving = reconcile(
        &[
            ("x-backend-finished", "true"),
            ("x-request-id", "trail-auth-1"),
        ],
        &backend,
        &backend,
        &[],
        false,
    );
    assert_eq!(surviving.len(), 2, "surviving trailers: {surviving:?}");
    assert!(has(&surviving, "x-backend-finished"));
    assert!(has(&surviving, "x-request-id"));
}

#[test]
fn declared_policy_name_strips_only_that_trailer_field() {
    // The removal was a NO-OP on the initial map — the backend never sent
    // `x-powered-by` as a header — so only the config-time declaration can
    // catch it. Every ungoverned trailer must still survive.
    let backend = headers(&[("content-type", "text/plain")]);
    let surviving = reconcile(
        &[
            ("x-powered-by", "backend/1.2"),
            ("x-backend-finished", "true"),
        ],
        &backend,
        &backend,
        &names(&["x-powered-by", "x-frame-options"]),
        false,
    );
    assert_eq!(surviving.len(), 1, "surviving trailers: {surviving:?}");
    assert!(!has(&surviving, "x-powered-by"));
    assert!(has(&surviving, "x-backend-finished"));
}

#[test]
fn declared_policy_name_matches_case_insensitively() {
    let backend = headers(&[]);
    let surviving = reconcile(
        &[("x-powered-by", "backend/1.2")],
        &backend,
        &backend,
        &names(&["X-Powered-By"]),
        false,
    );
    assert!(surviving.is_empty(), "surviving trailers: {surviving:?}");
}

#[test]
fn every_duplicate_field_line_of_a_governed_trailer_is_removed() {
    // `HeaderMap` keeps repeated field lines; a single-shot removal would leave
    // the later copies on the wire and defeat the whole reconciliation.
    let backend = headers(&[]);
    let surviving = reconcile(
        &[
            ("x-powered-by", "first"),
            ("x-powered-by", "second"),
            ("x-powered-by", "third"),
            ("x-keep", "yes"),
        ],
        &backend,
        &backend,
        &names(&["x-powered-by"]),
        false,
    );
    assert_eq!(surviving, vec![("x-keep".to_string(), "yes".to_string())]);
}

#[test]
fn observed_header_removal_strips_the_matching_trailer_without_a_declaration() {
    // A plugin that declares nothing (custom plugin, request-time route
    // override) still cannot be bypassed: the diff against the pre-policy
    // witness sees the field disappear from the header map.
    let before = headers(&[
        ("x-internal-token", "leaked"),
        ("content-type", "text/plain"),
    ]);
    let after = headers(&[("content-type", "text/plain")]);
    let surviving = reconcile(
        &[("x-internal-token", "leaked"), ("x-keep", "yes")],
        &before,
        &after,
        &[],
        false,
    );
    assert_eq!(surviving, vec![("x-keep".to_string(), "yes".to_string())]);
}

#[test]
fn observed_header_override_and_injection_both_strip_the_trailer_copy() {
    let before = headers(&[("x-frame-options", "ALLOWALL")]);
    let after = headers(&[("x-frame-options", "DENY"), ("x-added", "gateway")]);
    let surviving = reconcile(
        &[
            ("x-frame-options", "ALLOWALL"),
            ("x-added", "backend-spoof"),
            ("x-keep", "yes"),
        ],
        &before,
        &after,
        &[],
        false,
    );
    assert_eq!(surviving, vec![("x-keep".to_string(), "yes".to_string())]);
}

#[test]
fn mixed_case_header_mutation_is_still_observed() {
    // Plugins may synthesize mixed-case keys; the trailer channel is always
    // lowercase, so the comparison has to be case-insensitive on both sides.
    let before = headers(&[("X-Internal-Token", "leaked")]);
    let after = headers(&[]);
    let surviving = reconcile(
        &[("x-internal-token", "leaked")],
        &before,
        &after,
        &[],
        false,
    );
    assert!(surviving.is_empty(), "surviving trailers: {surviving:?}");
}

#[test]
fn duplicate_case_variants_before_policy_are_ambiguous_and_governed() {
    // Two case variants of one field name in the pre-policy map: no single
    // value represents the field, so the reconciliation cannot prove the chain
    // left it alone and must not forward the trailer copy. A "first match wins"
    // lookup would have compared against whichever variant iteration happened
    // to reach first and called it unchanged.
    let before = headers(&[("x-name", "same"), ("X-Name", "same")]);
    let after = headers(&[("x-name", "same"), ("X-Name", "same")]);
    let surviving = reconcile(
        &[("x-name", "same"), ("x-keep", "yes")],
        &before,
        &after,
        &[],
        false,
    );
    assert_eq!(surviving, vec![("x-keep".to_string(), "yes".to_string())]);
}

#[test]
fn duplicate_case_variants_after_policy_are_ambiguous_and_governed() {
    // A plugin synthesized a second case variant carrying a different value.
    // One of the two matches the backend's pre-policy value exactly, so an
    // arbitrary first-match lookup could report "unchanged" and let the backend
    // trailer through beside the plugin's copy.
    let before = headers(&[("x-name", "backend")]);
    let after = headers(&[("x-name", "backend"), ("X-Name", "gateway")]);
    let surviving = reconcile(
        &[("x-name", "backend"), ("x-keep", "yes")],
        &before,
        &after,
        &[],
        false,
    );
    assert_eq!(surviving, vec![("x-keep".to_string(), "yes".to_string())]);
}

#[test]
fn an_absent_backend_field_is_unchanged_only_with_zero_final_matches() {
    // The backend sent the field only as a trailer. Any case variant appearing
    // in the final map is a gateway-owned value the trailer would contradict.
    let before = headers(&[]);
    let after = headers(&[("X-Name", "gateway")]);
    let surviving = reconcile(
        &[("x-name", "backend"), ("x-keep", "yes")],
        &before,
        &after,
        &[],
        false,
    );
    assert_eq!(surviving, vec![("x-keep".to_string(), "yes".to_string())]);
}

#[test]
fn unbounded_policy_drops_every_reconcilable_trailer() {
    let backend = headers(&[("content-type", "text/plain")]);
    let surviving = reconcile(
        &[("x-backend-finished", "true"), ("x-request-id", "abc")],
        &backend,
        &backend,
        &[],
        true,
    );
    assert!(surviving.is_empty(), "surviving trailers: {surviving:?}");
}

#[test]
fn grpc_control_trailers_survive_the_inferred_governance_signals() {
    // The fail-closed arm and observed-mutation diff say nothing about RPC
    // status; dropping these would strand the client without a `grpc-status`.
    let before = headers(&[("grpc-message", "backend said so")]);
    let after = headers(&[]);
    let surviving = reconcile(
        &[
            ("grpc-status", "0"),
            ("grpc-message", "backend said so"),
            ("grpc-status-details-bin", "AAAA"),
            ("x-powered-by", "backend/1.2"),
        ],
        &before,
        &after,
        &[],
        true,
    );
    assert_eq!(surviving.len(), 3, "surviving trailers: {surviving:?}");
    assert!(has(&surviving, "grpc-status"));
    assert!(has(&surviving, "grpc-message"));
    assert!(has(&surviving, "grpc-status-details-bin"));
    assert!(!has(&surviving, "x-powered-by"));
}

#[test]
fn an_explicitly_named_grpc_control_trailer_is_still_removed() {
    // Naming `grpc-status` in a response-header policy is a deliberate operator
    // declaration, and it wins over the exemption — the same precedence the
    // buffered gRPC-Web trailer boundary already applies.
    let backend = headers(&[]);
    let surviving = reconcile(
        &[("grpc-status", "0"), ("grpc-message", "ok")],
        &backend,
        &backend,
        &names(&["Grpc-Status"]),
        false,
    );
    assert_eq!(
        surviving,
        vec![("grpc-message".to_string(), "ok".to_string())]
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Streaming relays: the initial HEADERS frame is already on the wire when the
// backend's trailer section arrives, so the same policy boundary has to be
// re-applied at the trailer frame. The last argument is
// `header_phases_can_mutate` — whether any response-header phase can run for
// the response at all, which is what decides if a pre-policy snapshot is worth
// retaining.
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn streaming_relay_without_a_header_phase_preserves_backend_trailers() {
    // No plugins and no sticky-cookie injection: nothing can have rewritten the
    // headers, so no snapshot is retained and every trailer survives (#2941).
    let backend = headers(&[("content-type", "text/plain")]);
    let surviving = reconcile_streaming(
        &[
            ("x-backend-finished", "true"),
            ("x-request-id", "trail-stream-1"),
        ],
        &backend,
        &backend,
        &[],
        false,
        false,
    );
    assert_eq!(surviving.len(), 2, "surviving trailers: {surviving:?}");
    assert!(has(&surviving, "x-backend-finished"));
    assert!(has(&surviving, "x-request-id"));
}

#[test]
fn streaming_relay_reconciles_observed_header_mutations() {
    // The chain removed the field from the initial header map, which already
    // went on the wire; the trailer copy must not reintroduce it afterwards.
    let before = headers(&[
        ("x-internal-token", "leaked"),
        ("content-type", "text/plain"),
    ]);
    let after = headers(&[("content-type", "text/plain")]);
    let surviving = reconcile_streaming(
        &[("x-internal-token", "leaked"), ("x-keep", "yes")],
        &before,
        &after,
        &[],
        false,
        true,
    );
    assert_eq!(surviving, vec![("x-keep".to_string(), "yes".to_string())]);
}

#[test]
fn streaming_relay_binds_declared_policy_names_without_a_mutation() {
    // The removal was a no-op on the initial map — the backend sent the field
    // only as a trailer — so only the config-time declaration can bind it, with
    // or without a retained snapshot.
    let backend = headers(&[("content-type", "text/plain")]);
    let surviving = reconcile_streaming(
        &[("x-powered-by", "backend/1.2"), ("x-keep", "yes")],
        &backend,
        &backend,
        &names(&["x-powered-by"]),
        false,
        false,
    );
    assert_eq!(surviving, vec![("x-keep".to_string(), "yes".to_string())]);
}

#[test]
fn streaming_relay_unbounded_policy_fails_closed_without_evidence() {
    // The unbounded arm drops the reconcilable section regardless of what the
    // headers did, so the relay retains no snapshot at all — and the outcome is
    // identical to the buffered path's unbounded arm.
    let backend = headers(&[("content-type", "text/plain")]);
    let surviving = reconcile_streaming(
        &[("x-backend-finished", "true"), ("grpc-status", "0")],
        &backend,
        &backend,
        &[],
        true,
        true,
    );
    assert_eq!(
        surviving,
        vec![("grpc-status".to_string(), "0".to_string())],
        "gRPC control trailers stay exempt from the streaming fail-closed arm"
    );
}

#[test]
fn streaming_relay_duplicate_case_variants_are_governed() {
    // Same fail-closed ambiguity rule as the buffered path: a plugin-synthesized
    // duplicate case variant must never let the backend trailer through.
    let before = headers(&[("x-name", "backend")]);
    let after = headers(&[("x-name", "backend"), ("X-Name", "gateway")]);
    let surviving = reconcile_streaming(
        &[("x-name", "backend"), ("x-keep", "yes")],
        &before,
        &after,
        &[],
        false,
        true,
    );
    assert_eq!(surviving, vec![("x-keep".to_string(), "yes".to_string())]);
}
