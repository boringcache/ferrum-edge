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

use ferrum_edge::_test_support::govern_streaming_h2_backend_trailers_for_test as govern_h2;
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
fn unbounded_policy_drops_trailer_only_representation_metadata() {
    // `ai_stream_router`'s Anthropic SSE normalization removes / invalidates
    // these fields on the INITIAL header map. When the backend sent them ONLY
    // as trailers, the pre-policy and final maps both lack the name
    // (absent → absent), so the mutation witness forwards them unless the
    // plugin's Unbounded declaration fails closed.
    let backend = headers(&[("content-type", "text/event-stream")]);
    let surviving = reconcile(
        &[
            ("content-encoding", "gzip"),
            ("content-length", "42"),
            ("vary", "accept-encoding"),
            ("etag", "\"provider-repr\""),
            ("digest", "sha-256=:AAAA:"),
            ("signature", "sig1=:BBBB:"),
            ("x-amz-checksum-sha256", "deadbeef"),
            ("x-checksum-crc32", "AAAAAA=="),
            ("x-keep", "yes"),
        ],
        &backend,
        &backend,
        &[],
        true,
    );
    assert!(
        surviving.is_empty(),
        "trailer-only representation metadata must not survive Unbounded: {surviving:?}"
    );
}

#[test]
fn a_grpc_named_trailer_gets_no_exemption_from_the_unbounded_arm() {
    // Every path that reaches this reconciliation is a PLAIN-flavor HTTP/3 relay
    // — native gRPC finishes its own trailers in `dispatch_grpc_native_h3` and is
    // never reconciled. So a `grpc-*` trailer here is an ordinary backend field,
    // and exempting it by NAME would hand any non-gRPC backend a one-word bypass
    // of a fail-closed response-header policy.
    let backend = headers(&[("content-type", "text/plain")]);
    let surviving = reconcile(
        &[
            ("grpc-status", "0"),
            ("grpc-message", "backend said so"),
            ("grpc-status-details-bin", "AAAA"),
            ("x-powered-by", "backend/1.2"),
        ],
        &backend,
        &backend,
        &[],
        true,
    );
    assert!(
        surviving.is_empty(),
        "a grpc-* name must not bypass the unbounded arm: {surviving:?}"
    );
}

#[test]
fn a_grpc_named_trailer_gets_no_exemption_from_observed_mutation() {
    // The mirror bypass: a non-gRPC backend names its smuggled field
    // `grpc-status` and the gateway's observed removal of that same field from
    // the initial header map would be undone by the trailer copy.
    let before = headers(&[
        ("grpc-status", "13"),
        ("x-internal-token", "leaked"),
        ("content-type", "text/plain"),
    ]);
    let after = headers(&[("content-type", "text/plain")]);
    let surviving = reconcile(
        &[
            ("grpc-status", "13"),
            ("x-internal-token", "leaked"),
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
fn an_explicitly_named_grpc_control_trailer_is_still_removed() {
    // Naming `grpc-status` in a response-header policy remains a deliberate
    // operator declaration and removes it, exactly as any other declared name.
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

#[test]
fn sse_style_trailer_only_content_length_removal_is_bound_by_the_declaration() {
    // The load-bearing built-in-ownership case. `sse` with
    // `strip_content_length` removes `content-length` from the INITIAL map; when
    // the backend sent the field only as a TRAILER that removal is a no-op, so
    // the observed-mutation witness proves absent -> absent and forwards the
    // trailer. Only the config-time declaration closes it.
    let backend = headers(&[("content-type", "text/event-stream")]);

    let undeclared = reconcile(
        &[("content-length", "4096"), ("x-keep", "yes")],
        &backend,
        &backend,
        &[],
        false,
    );
    assert!(
        has(&undeclared, "content-length"),
        "without a declaration the no-op removal is invisible: {undeclared:?}"
    );

    let declared = reconcile(
        &[("content-length", "4096"), ("x-keep", "yes")],
        &backend,
        &backend,
        &names(&[
            "content-type",
            "cache-control",
            "x-accel-buffering",
            "content-length",
        ]),
        false,
    );
    assert_eq!(declared, vec![("x-keep".to_string(), "yes".to_string())]);
}

#[test]
fn an_idempotent_gateway_write_is_bound_by_the_declaration_only() {
    // The second shape the witness cannot see: the gateway writes a value the
    // backend already sent verbatim (`response_caching`'s guessable
    // `x-cache-status: MISS`, an echoed `traceparent`, an already-nominated
    // `vary` token). Before == after, so the diff is empty.
    let before = headers(&[("x-cache-status", "MISS")]);
    let after = headers(&[("x-cache-status", "MISS")]);

    let undeclared = reconcile(&[("x-cache-status", "HIT")], &before, &after, &[], false);
    assert!(
        has(&undeclared, "x-cache-status"),
        "an idempotent write leaves no observable diff: {undeclared:?}"
    );

    let declared = reconcile(
        &[("x-cache-status", "HIT")],
        &before,
        &after,
        &names(&["x-cache-status"]),
        false,
    );
    assert!(declared.is_empty(), "surviving trailers: {declared:?}");
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
    assert!(
        surviving.is_empty(),
        "the streaming fail-closed arm exempts no name, grpc-* included: {surviving:?}"
    );
}

#[test]
fn streaming_relay_unbounded_drops_trailer_only_representation_metadata() {
    // Streaming H3 commits initial HEADERS before TRAILERS exist. Without
    // `ai_stream_router`'s Unbounded ownership, a trailer-only
    // `content-encoding` / validator / `x-amz-checksum-*` reconciles as
    // absent→absent and reintroduces representation metadata the normalization
    // already invalidated on the header channel.
    let backend = headers(&[("content-type", "text/event-stream")]);
    let surviving = reconcile_streaming(
        &[
            ("content-encoding", "br"),
            ("content-length", "99"),
            ("vary", "accept-encoding"),
            ("etag", "\"sse-repr\""),
            ("content-digest", "sha-256=:CCCC:"),
            ("signature-input", "sig1=()"),
            ("x-amz-checksum-crc32", "AAAAAA=="),
            ("x-checksum-sha256", "cafebabe"),
            ("x-keep", "yes"),
        ],
        &backend,
        &backend,
        &[],
        true,
        true,
    );
    assert!(
        surviving.is_empty(),
        "streaming Unbounded must drop trailer-only representation metadata: {surviving:?}"
    );
}

#[test]
fn streaming_relay_binds_the_gateway_synthesized_default_content_type() {
    // Wire parity for the relays' `content-type: application/json` default. The
    // relay writes that field into the response-header MAP before building the
    // response, and counts the synthesis as a header phase, so the pre-policy
    // snapshot (backend: no content-type) versus the final map (gateway:
    // application/json) is a visible mutation and the backend's conflicting
    // `content-type` TRAILER is dropped.
    //
    // If the default only ever reached the builder, the final map would still
    // lack the field, reconciliation would prove absent -> absent, and the
    // trailer would land on the wire contradicting a header the gateway sent.
    let backend_without_content_type = headers(&[("x-backend", "1")]);
    let wire_headers = headers(&[("x-backend", "1"), ("content-type", "application/json")]);
    let surviving = reconcile_streaming(
        &[("content-type", "text/html"), ("x-keep", "yes")],
        &backend_without_content_type,
        &wire_headers,
        &[],
        false,
        // The relay passes `true` here precisely because it will synthesize the
        // default, even for an auth/logging-only chain.
        true,
    );
    assert_eq!(surviving, vec![("x-keep".to_string(), "yes".to_string())]);
}

#[test]
fn streaming_relay_keeps_trailers_when_the_backend_supplied_content_type() {
    // The mirror case: the backend already sent `content-type`, so the relay
    // synthesizes nothing, `header_phases_can_mutate` stays false for an
    // auth/logging-only chain, no snapshot is retained, and the #2941
    // pass-through is preserved with zero clones.
    let backend = headers(&[("content-type", "text/plain")]);
    let surviving = reconcile_streaming(
        &[("x-backend-finished", "true")],
        &backend,
        &backend,
        &[],
        false,
        false,
    );
    assert_eq!(
        surviving,
        vec![("x-backend-finished".to_string(), "true".to_string())]
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

// ── Streaming HTTP/2 (direct-H2) ────────────────────────────────────────────
//
// The plain direct-H2 `ResponseBody::StreamingH2` relay crosses the same
// boundary as the native-H3 streaming relays: its initial HEADERS frame is
// committed before the backend's TRAILERS frame exists. It cannot borrow the
// handler's locals the way an inline H3 relay can — the body is handed to hyper
// and the handler returns — so the boundary travels with the body as an owned
// `StreamingResponseTrailerGovernor`. These cases pin that owned form against
// the same governance contract, including the hop-by-hop strip the body wrapper
// applies immediately before reconciling.

#[test]
fn streaming_h2_security_headers_removal_binds_a_trailer_only_field() {
    // The reported case: `security_headers` with `{"remove": ["x-powered-by"]}`
    // is a NO-OP on the initial header map because the backend sent the field
    // ONLY as a trailer. `after_proxy` therefore had nothing to remove, and
    // without the config-time declaration the trailer would land on the wire
    // after the policy boundary and reintroduce exactly what was removed.
    let backend = headers(&[("content-type", "text/plain")]);
    let surviving = govern_h2(
        &[("x-powered-by", "backend/1.2"), ("x-keep", "yes")],
        &backend,
        &backend,
        &names(&["x-powered-by"]),
        false,
        true,
    );
    assert_eq!(surviving, vec![("x-keep".to_string(), "yes".to_string())]);
}

#[test]
fn streaming_h2_without_a_header_phase_preserves_backend_trailers() {
    // Exact no-policy behavior: an auth/logging-only chain with no gateway
    // header write retains no evidence and forwards every trailer (#2941).
    let backend = headers(&[("content-type", "text/plain")]);
    let surviving = govern_h2(
        &[
            ("x-backend-finished", "true"),
            ("x-request-id", "trail-h2-1"),
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
fn streaming_h2_observed_header_removal_binds_the_trailer_copy() {
    // No declaration at all — a custom plugin that simply deleted the field
    // from the initial map. The retained pre-policy snapshot is what proves the
    // mutation once the trailer frame finally arrives.
    let before = headers(&[
        ("x-internal-token", "leaked"),
        ("content-type", "text/plain"),
    ]);
    let after = headers(&[("content-type", "text/plain")]);
    let surviving = govern_h2(
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
fn streaming_h2_unbounded_policy_fails_closed_without_evidence() {
    // `response_transformer` / `ai_stream_router` (and anything else declaring
    // `Unbounded`) drops the whole reconcilable trailer section, so the relay
    // retains no snapshot at all. Same outcome as the buffered and streaming
    // H3 unbounded arms.
    let backend = headers(&[("content-type", "text/plain")]);
    let surviving = govern_h2(
        &[("x-backend-finished", "true"), ("x-keep", "yes")],
        &backend,
        &backend,
        &[],
        true,
        true,
    );
    assert!(
        surviving.is_empty(),
        "unbounded policy must drop every reconcilable trailer: {surviving:?}"
    );
}

#[test]
fn streaming_h2_unbounded_drops_trailer_only_representation_metadata() {
    // Direct-H2 StreamingH2 commits HEADERS before TRAILERS, identical to the
    // native-H3 streaming relays. Trailer-only representation metadata that
    // `ai_stream_router` invalidated on the header channel must not survive.
    let backend = headers(&[("content-type", "text/event-stream")]);
    let surviving = govern_h2(
        &[
            ("content-encoding", "gzip"),
            ("content-length", "12"),
            ("vary", "accept-encoding"),
            ("last-modified", "Mon, 01 Jan 2024 00:00:00 GMT"),
            ("repr-digest", "sha-256=:DDDD:"),
            ("content-signature", "sig1=:EEEE:"),
            ("x-amz-checksum-sha256", "feedface"),
            ("x-checksum-crc32c", "BBBBBB=="),
            ("x-keep", "yes"),
        ],
        &backend,
        &backend,
        &[],
        true,
        true,
    );
    assert!(
        surviving.is_empty(),
        "H2 Unbounded must drop trailer-only representation metadata: {surviving:?}"
    );
}

#[test]
fn streaming_h2_gateway_only_wire_header_binds_the_matching_trailer() {
    // `via` / `alt-svc` / `X-Gateway-*` are written straight onto the response
    // BUILDER, not into the plugin header map. The governor is handed the map
    // PLUS those fields, so a backend `via` trailer is seen as contradicting a
    // gateway header instead of reconciling absent->absent.
    let backend = headers(&[("content-type", "text/plain")]);
    let wire = headers(&[("content-type", "text/plain"), ("via", "2 ferrum-edge")]);
    let surviving = govern_h2(
        &[("via", "1.1 backend"), ("x-keep", "yes")],
        &backend,
        &wire,
        &[],
        false,
        true,
    );
    assert_eq!(surviving, vec![("x-keep".to_string(), "yes".to_string())]);
}

#[test]
fn streaming_h2_strips_hop_by_hop_trailers_before_reconciling() {
    // The body wrapper strips hop-by-hop names first, so they never count as
    // policy-governed removals — and an ungoverned chain still cannot leak
    // `connection` / `proxy-authenticate` through the trailer section.
    let backend = headers(&[("content-type", "text/plain")]);
    let surviving = govern_h2(
        &[
            ("connection", "close"),
            ("proxy-authenticate", "Basic"),
            ("x-keep", "yes"),
        ],
        &backend,
        &backend,
        &[],
        false,
        false,
    );
    assert_eq!(surviving, vec![("x-keep".to_string(), "yes".to_string())]);
}

// ── Source contracts ────────────────────────────────────────────────────────

#[test]
fn streaming_h2_body_reconciles_after_the_hop_by_hop_strip() {
    let src = include_str!("../../../src/proxy/body.rs");
    let filter = src
        .split("impl<B> http_body::Body for StripHopByHopTrailers<B>")
        .nth(1)
        .expect("StripHopByHopTrailers body impl")
        .split("fn is_end_stream")
        .next()
        .expect("bounded poll_frame region");
    let strip_at = filter
        .find("strip_response_hop_by_hop_trailers(&mut trailers);")
        .expect("hop-by-hop trailer strip");
    let govern_at = filter
        .find("governor.reconcile(&mut trailers)")
        .expect("response-trailer policy reconciliation");
    let send_at = filter
        .find("Frame::trailers(trailers)")
        .expect("trailer frame handoff");
    assert!(
        strip_at < govern_at && govern_at < send_at,
        "streaming H2 must strip hop-by-hop names, then reconcile, then emit"
    );
}

#[test]
fn every_streaming_h2_body_constructor_carries_the_trailer_governor() {
    let src = include_str!("../../../src/proxy/body.rs");
    for constructor in [
        "pub(crate) fn direct_streaming_h2_body_strip_hop_by_hop_trailers(",
        "pub(crate) fn size_limited_coalescing_h2_body_strip_hop_by_hop_trailers(",
        "pub(crate) fn coalescing_h2_body_strip_hop_by_hop_trailers(",
    ] {
        let body = src
            .split(constructor)
            .nth(1)
            .unwrap_or_else(|| panic!("missing constructor {constructor}"));
        let signature = body.split(") -> ProxyBody {").next().expect("signature");
        assert!(
            signature.contains(
                "trailer_governor: Option<crate::proxy::headers::StreamingResponseTrailerGovernor>"
            ),
            "{constructor} must accept the streaming trailer governor"
        );
        let block = body.split("\n}\n").next().expect("constructor body");
        assert!(
            block.contains("StripHopByHopTrailers::with_trailer_governor("),
            "{constructor} must install the governor on every wrapper it builds"
        );
        assert!(
            !block.contains("StripHopByHopTrailers::new("),
            "{constructor} must not build an ungoverned wrapper on any branch"
        );
    }
}

#[test]
fn native_grpc_and_grpc_web_h2_dispatches_are_never_reconciled() {
    let src = include_str!("../../../src/proxy/mod.rs");
    let gate = src
        .split("let h2_streaming_trailer_policy = ")
        .nth(1)
        .expect("streaming H2 trailer policy gate")
        .split("Some((pre_policy, unbounded))")
        .next()
        .expect("bounded gate region");
    assert!(
        gate.contains("!streaming_h2_native_grpc")
            && gate.contains("!grpc_request_is_web_translated"),
        "native gRPC reserved terminal metadata and gRPC-Web adaptation must stay \
         outside the response-header trailer boundary"
    );
    assert!(
        gate.contains("PrePolicyResponseHeaders::capture_for_streaming("),
        "the plain streaming H2 relay must capture the pristine backend header view"
    );
}
