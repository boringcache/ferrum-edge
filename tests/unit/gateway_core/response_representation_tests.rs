//! Behavior coverage for the shared buffered-response representation gate.
//!
//! Every test here drives the real production transform phase
//! (`transform_buffered_response_body_with_deadline`) with a real
//! `response_transformer` plugin and a real `RequestContext` carrying the same
//! pre-`after_proxy` snapshot the proxy stamps. That helper is the single body
//! phase the H1/H2, buffered gRPC, and native H3 paths all call, so asserting on
//! it asserts on all three; the H3 cross-protocol bridges and the synthetic
//! short-circuit call the same gate through
//! `admit_buffered_response_body_transforms`.
//!
//! The property under test is the one the advisory turned on: a configured body
//! policy must never *appear* to have applied. Either the protected field is
//! gone from the bytes the client receives, or the client receives no response
//! body at all.

use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;

use ferrum_edge::_test_support::{
    apply_synthetic_response_body_hooks_for_test,
    discard_grpc_application_trailers_after_body_rewrite_for_test,
    finalize_selected_buffered_grpc_terminal_response_for_test,
    representation_rejection_reason_for_test, retain_grpc_web_client_content_type_for_test,
    run_after_proxy_hooks_for_test, set_grpc_deadline_budget_for_test,
    set_original_response_content_encoding_for_test, set_request_http_flavor_for_test,
    stamp_original_request_metadata_for_test, stamp_original_response_metadata_for_test,
    transform_buffered_response_body_with_deadline_and_policy_for_test,
    transform_buffered_response_body_with_deadline_full_for_test,
};
use ferrum_edge::HttpFlavor;
use ferrum_edge::plugins::{
    Plugin, PluginResult, RequestContext, request_transformer::RequestTransformer,
    response_transformer::ResponseTransformer,
};
use serde_json::json;

/// A `response_transformer` whose only job is to strip a secret field, i.e. the
/// configuration whose bypass the advisory describes.
fn redacting_plugins() -> Vec<Arc<dyn Plugin>> {
    vec![Arc::new(
        ResponseTransformer::new(&json!({
            "rules": [
                {"operation": "remove", "target": "body", "key": "secret"}
            ]
        }))
        .expect("redacting response_transformer config must be valid"),
    )]
}

fn make_ctx() -> RequestContext {
    RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/test".to_string(),
    )
}

fn json_headers() -> HashMap<String, String> {
    HashMap::from([("content-type".to_string(), "application/json".to_string())])
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let level = flate2::Compression::default();
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), level);
    encoder.write_all(data).expect("gzip write must succeed");
    encoder.finish().expect("gzip finish must succeed")
}

fn brotli(data: &[u8]) -> Vec<u8> {
    let params = brotli::enc::BrotliEncoderParams::default();
    let mut out = Vec::new();
    let mut input = data;
    brotli::BrotliCompress(&mut input, &mut out, &params).expect("brotli must compress");
    out
}

/// Drive the real buffered transform phase over a backend response, stamping the
/// pristine snapshot first exactly as the proxy does.
async fn run_backend_transform(
    status: u16,
    headers: HashMap<String, String>,
    body: Vec<u8>,
) -> (
    bool,
    bool,
    u16,
    HashMap<String, String>,
    Vec<u8>,
    Option<String>,
) {
    let plugins = redacting_plugins();
    let mut ctx = make_ctx();
    let mut status = status;
    let mut headers = headers;
    let mut body = body;
    stamp_original_response_metadata_for_test(&mut ctx, status, &headers);
    let (replaced, transformed) = transform_buffered_response_body_with_deadline_full_for_test(
        &plugins,
        &mut ctx,
        &mut status,
        &mut headers,
        &mut body,
        None,
        false,
    )
    .await;
    let reason = representation_rejection_reason_for_test(&ctx).map(str::to_string);
    (replaced, transformed, status, headers, body, reason)
}

/// The secret must not survive in the bytes the client would receive.
fn assert_secret_not_forwarded(body: &[u8]) {
    let rendered = String::from_utf8_lossy(body);
    assert!(
        !rendered.contains("hunter2"),
        "protected value was forwarded to the client: {rendered}"
    );
}

// ---------------------------------------------------------------------------
// Baseline: the policy applies normally to a plain, complete JSON document.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn identity_json_body_is_redacted_and_representation_metadata_is_invalidated() {
    let mut headers = json_headers();
    headers.insert("etag".to_string(), "\"v1\"".to_string());
    headers.insert("content-digest".to_string(), "sha-256=:abc:".to_string());
    let modified = "Tue, 15 Nov 2022 12:45:26 GMT".to_string();
    headers.insert("last-modified".to_string(), modified);
    headers.insert("accept-ranges".to_string(), "bytes".to_string());

    let (replaced, transformed, status, headers, body, reason) =
        run_backend_transform(200, headers, br#"{"secret":"hunter2","keep":1}"#.to_vec()).await;

    assert!(!replaced, "a clean redaction must not replace the response");
    assert!(transformed, "the configured body rule must have applied");
    assert_eq!(status, 200);
    assert_eq!(reason, None);
    assert_secret_not_forwarded(&body);
    assert!(String::from_utf8_lossy(&body).contains("keep"));

    // Stale representation metadata for the pre-rewrite bytes must be gone.
    for stale in ["etag", "content-digest", "last-modified", "accept-ranges"] {
        assert!(
            !headers.contains_key(stale),
            "stale `{stale}` survived a body rewrite"
        );
    }
    let expected_len = body.len().to_string();
    assert_eq!(
        headers.get("content-length"),
        Some(&expected_len),
        "content-length must describe the rewritten bytes"
    );
}

// ---------------------------------------------------------------------------
// Encoded representations.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn gzip_encoded_body_is_decoded_redacted_and_served_as_identity() {
    let mut headers = json_headers();
    headers.insert("content-encoding".to_string(), "gzip".to_string());

    let (replaced, transformed, status, headers, body, reason) =
        run_backend_transform(200, headers, gzip(br#"{"secret":"hunter2","keep":1}"#)).await;

    assert!(!replaced);
    assert!(transformed, "gzip body must be decoded and redacted");
    assert_eq!(status, 200);
    assert_eq!(reason, None);
    assert_secret_not_forwarded(&body);
    assert!(
        !headers.contains_key("content-encoding"),
        "decoded bytes must not still claim a content coding"
    );
    let expected_len = body.len().to_string();
    assert_eq!(headers.get("content-length"), Some(&expected_len));
}

#[tokio::test]
async fn brotli_encoded_body_is_decoded_and_redacted() {
    let mut headers = json_headers();
    headers.insert("content-encoding".to_string(), "br".to_string());

    let (_, transformed, _, headers, body, reason) =
        run_backend_transform(200, headers, brotli(br#"{"secret":"hunter2","keep":1}"#)).await;

    assert!(transformed, "brotli body must be decoded and redacted");
    assert_eq!(reason, None);
    assert_secret_not_forwarded(&body);
    assert!(!headers.contains_key("content-encoding"));
}

#[tokio::test]
async fn stacked_codings_are_decoded_in_reverse_order() {
    let mut headers = json_headers();
    headers.insert("content-encoding".to_string(), "gzip, br".to_string());
    // Applied gzip first, then brotli — so brotli is the outermost layer.
    let body = brotli(&gzip(br#"{"secret":"hunter2","keep":1}"#));

    let (_, transformed, _, _, body, reason) = run_backend_transform(200, headers, body).await;

    assert!(transformed, "stacked codings must be fully decoded");
    assert_eq!(reason, None);
    assert_secret_not_forwarded(&body);
}

#[tokio::test]
async fn unsupported_coding_is_rejected_not_forwarded() {
    let mut headers = json_headers();
    headers.insert("content-encoding".to_string(), "zstd".to_string());

    let (replaced, transformed, status, _, body, reason) =
        run_backend_transform(200, headers, br#"{"secret":"hunter2"}"#.to_vec()).await;

    assert!(replaced, "an undecodable protected body must be replaced");
    assert!(!transformed);
    assert_eq!(status, 502);
    assert_eq!(reason.as_deref(), Some("unsupported_content_coding"));
    assert_secret_not_forwarded(&body);
}

#[tokio::test]
async fn malformed_coding_stream_is_rejected_not_forwarded() {
    let mut headers = json_headers();
    headers.insert("content-encoding".to_string(), "gzip".to_string());
    // Truncated gzip stream: a real decoder fails partway through.
    let mut truncated = gzip(br#"{"secret":"hunter2","keep":1}"#);
    truncated.truncate(truncated.len() / 2);

    let (replaced, _, status, _, body, reason) =
        run_backend_transform(200, headers, truncated).await;

    assert!(replaced);
    assert_eq!(status, 502);
    assert_eq!(reason.as_deref(), Some("malformed_content_coding"));
    assert_secret_not_forwarded(&body);
}

#[tokio::test]
async fn decompression_amplification_past_the_ceiling_is_rejected() {
    let mut headers = json_headers();
    headers.insert("content-encoding".to_string(), "gzip".to_string());
    // ~24 MiB of zeros compresses to a few KiB and exceeds the 10 MiB ceiling.
    let bomb = gzip(&vec![b'0'; 24 * 1024 * 1024]);
    assert!(bomb.len() < 1024 * 1024, "test bomb must actually be small");

    let (replaced, _, status, _, _, reason) = run_backend_transform(200, headers, bomb).await;

    assert!(replaced, "a decompression bomb must not be materialized");
    assert_eq!(status, 502);
    assert_eq!(reason.as_deref(), Some("decoded_body_too_large"));
}

#[tokio::test]
async fn excessively_stacked_codings_are_rejected() {
    let mut headers = json_headers();
    headers.insert(
        "content-encoding".to_string(),
        "gzip, gzip, gzip, gzip, gzip".to_string(),
    );

    let (replaced, _, status, _, body, reason) =
        run_backend_transform(200, headers, gzip(br#"{"secret":"hunter2"}"#)).await;

    assert!(replaced);
    assert_eq!(status, 502);
    assert_eq!(reason.as_deref(), Some("decoded_body_too_large"));
    assert_secret_not_forwarded(&body);
}

/// The bypass this closes: a header-only rule removed `Content-Encoding` during
/// `after_proxy`, so the live map says identity while the bytes are still gzip.
#[tokio::test]
async fn origin_encoding_is_read_from_the_snapshot_not_the_mutated_live_header() {
    let plugins = redacting_plugins();
    let mut ctx = make_ctx();
    let mut status = 200;
    let mut headers = json_headers();
    headers.insert("content-encoding".to_string(), "gzip".to_string());
    let mut body = gzip(br#"{"secret":"hunter2","keep":1}"#);

    stamp_original_response_metadata_for_test(&mut ctx, status, &headers);
    // A later `after_proxy` header hook drops the encoding header.
    headers.remove("content-encoding");

    let (_, transformed) = transform_buffered_response_body_with_deadline_full_for_test(
        &plugins,
        &mut ctx,
        &mut status,
        &mut headers,
        &mut body,
        None,
        false,
    )
    .await;

    assert!(
        transformed,
        "the snapshot must still prove the body was gzip-encoded"
    );
    assert_eq!(representation_rejection_reason_for_test(&ctx), None);
    assert_secret_not_forwarded(&body);
}

// ---------------------------------------------------------------------------
// Partial and delta representations.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn protected_206_range_fragment_is_rejected_and_never_relabeled_200() {
    let mut headers = json_headers();
    headers.insert("content-range".to_string(), "bytes 0-19/512".to_string());

    let (replaced, transformed, status, headers, body, reason) =
        run_backend_transform(206, headers, br#"{"secret":"hunter2","keep":1}"#.to_vec()).await;

    assert!(replaced, "a protected fragment must be rejected");
    assert!(!transformed);
    assert_ne!(
        status, 200,
        "a range fragment must never be presented as a complete 200 representation"
    );
    assert_eq!(status, 502);
    assert_eq!(reason.as_deref(), Some("partial_representation"));
    assert_secret_not_forwarded(&body);
    assert!(
        !headers.contains_key("content-range"),
        "the replacement response must not carry the fragment's range metadata"
    );
}

#[tokio::test]
async fn protected_226_delta_is_rejected_and_never_relabeled_200() {
    let mut headers = json_headers();
    headers.insert("im".to_string(), "feed".to_string());
    headers.insert("delta-base".to_string(), "\"v1\"".to_string());

    let (replaced, _, status, _, body, reason) =
        run_backend_transform(226, headers, br#"{"secret":"hunter2","keep":1}"#.to_vec()).await;

    assert!(replaced);
    assert_ne!(status, 200);
    assert_eq!(status, 502);
    assert_eq!(reason.as_deref(), Some("partial_representation"));
    assert_secret_not_forwarded(&body);
}

/// The status was rewritten to 200 by a hook, but the snapshot still proves the
/// backend sent a fragment.
#[tokio::test]
async fn fragment_hidden_by_a_rewritten_status_is_still_rejected() {
    let plugins = redacting_plugins();
    let mut ctx = make_ctx();
    let mut headers = json_headers();
    headers.insert("content-range".to_string(), "bytes 0-19/512".to_string());
    let mut body = br#"{"secret":"hunter2","keep":1}"#.to_vec();

    stamp_original_response_metadata_for_test(&mut ctx, 206, &headers);
    // A later hook presents it as a complete response.
    headers.remove("content-range");
    let mut status = 200;

    let (replaced, _) = transform_buffered_response_body_with_deadline_full_for_test(
        &plugins,
        &mut ctx,
        &mut status,
        &mut headers,
        &mut body,
        None,
        false,
    )
    .await;

    assert!(
        replaced,
        "the snapshot must still prove this was a fragment"
    );
    assert_eq!(
        representation_rejection_reason_for_test(&ctx),
        Some("partial_representation")
    );
    assert_secret_not_forwarded(&body);
}

// ---------------------------------------------------------------------------
// Gateway-generated bytes: the synthetic / serverless-terminate publication
// path.
//
// These never took a pre-`after_proxy` snapshot, so the gate applies the shared
// fragment rule to their live headers instead of to a stamped snapshot. The rule
// itself is the same one backend responses get: the response *status* decides
// whether range or delta headers are fragment evidence at all. That matters most
// here, because some of these bytes come from a provider that may echo
// representation metadata which never described this response.
// ---------------------------------------------------------------------------

/// Drive the real synthetic short-circuit body phase over gateway-generated
/// bytes, deliberately without stamping a snapshot (the proxy does not stamp one
/// on this path either).
async fn run_synthetic_transform(
    status: u16,
    headers: HashMap<String, String>,
    body: Vec<u8>,
) -> (u16, HashMap<String, String>, Vec<u8>, Option<String>) {
    let plugins = redacting_plugins();
    let mut ctx = make_ctx();
    let mut status = status;
    let mut headers = headers;
    let mut body = body;
    apply_synthetic_response_body_hooks_for_test(
        &plugins,
        &mut ctx,
        &mut status,
        &mut headers,
        &mut body,
    )
    .await;
    let reason = representation_rejection_reason_for_test(&ctx).map(str::to_string);
    (status, headers, body, reason)
}

/// A serverless provider answering `429` while echoing stale representation
/// metadata. `Content-Range` has no defined meaning on a `429` (RFC 9110 §14.4)
/// and a `4xx` body is an error document, not a slice of the target resource —
/// so these bytes are a complete, inspectable document. The policy is *applied*
/// to them and the stale metadata is invalidated by the rewrite. Rejecting here
/// would fail closed on ordinary provider replies while protecting nothing.
#[tokio::test]
async fn gateway_generated_error_status_with_stale_range_metadata_is_inspected_not_rejected() {
    let mut headers = json_headers();
    headers.insert("content-range".to_string(), "bytes 0-63/64".to_string());
    headers.insert("accept-ranges".to_string(), "bytes".to_string());
    headers.insert("etag".to_string(), "\"function-v1\"".to_string());

    let (status, headers, body, reason) =
        run_synthetic_transform(429, headers, br#"{"secret":"hunter2","keep":1}"#.to_vec()).await;

    assert_eq!(
        status, 429,
        "a complete error document must not be rejected as a fragment"
    );
    assert_eq!(reason, None);
    assert_secret_not_forwarded(&body);
    assert!(
        String::from_utf8_lossy(&body).contains("keep"),
        "the policy must have been applied to these bytes, not skipped"
    );
    for stale in ["content-range", "accept-ranges", "etag"] {
        assert!(
            !headers.contains_key(stale),
            "stale `{stale}` survived the permitted rewrite"
        );
    }
}

/// The counterpart that must stay fail-closed: on a **2xx** the status could
/// still be carrying a representation of the target resource, so live range
/// metadata is the shape a fragment whose status was rewritten would take.
#[tokio::test]
async fn gateway_generated_200_with_live_range_metadata_is_still_rejected() {
    let mut headers = json_headers();
    headers.insert("content-range".to_string(), "bytes 0-19/512".to_string());

    let (status, headers, body, reason) =
        run_synthetic_transform(200, headers, br#"{"secret":"hunter2","keep":1}"#.to_vec()).await;

    assert_eq!(
        status, 502,
        "a 2xx carrying range metadata is a possible relabeled fragment"
    );
    assert_eq!(reason.as_deref(), Some("partial_representation"));
    assert_secret_not_forwarded(&body);
    assert!(!headers.contains_key("content-range"));
}

/// The status rule itself is unconditional and provenance-independent: a
/// gateway-generated `206`/`226` is rejected regardless of the header narrowing
/// above.
#[tokio::test]
async fn gateway_generated_206_and_226_fragments_are_always_rejected() {
    let mut range_headers = json_headers();
    range_headers.insert("content-range".to_string(), "bytes 0-19/512".to_string());
    let (status, _, body, reason) =
        run_synthetic_transform(206, range_headers, br#"{"secret":"hunter2"}"#.to_vec()).await;
    assert_eq!(status, 502);
    assert_eq!(reason.as_deref(), Some("partial_representation"));
    assert_secret_not_forwarded(&body);

    let mut delta_headers = json_headers();
    delta_headers.insert("im".to_string(), "feed".to_string());
    let (status, _, body, reason) =
        run_synthetic_transform(226, delta_headers, br#"{"secret":"hunter2"}"#.to_vec()).await;
    assert_eq!(status, 502);
    assert_eq!(reason.as_deref(), Some("partial_representation"));
    assert_secret_not_forwarded(&body);
}

// ---------------------------------------------------------------------------
// Non-parseable documents, and the no-op that must stay a no-op.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unparseable_json_document_is_rejected_not_forwarded() {
    let (replaced, transformed, status, _, body, reason) = run_backend_transform(
        200,
        json_headers(),
        br#"{"secret":"hunter2", TRUNCATED"#.to_vec(),
    )
    .await;

    assert!(
        replaced,
        "a body the policy cannot parse must not be forwarded"
    );
    assert!(!transformed);
    assert_eq!(status, 502);
    assert_eq!(reason.as_deref(), Some("unparseable_document"));
    assert_secret_not_forwarded(&body);
}

/// Parses fine, but no configured rule matches. That is a legitimate no-op and
/// must stay one — conflating it with a parse failure would break normal traffic.
#[tokio::test]
async fn parseable_document_with_no_matching_rule_is_forwarded_unchanged() {
    let original = br#"{"keep":1}"#.to_vec();
    let (replaced, transformed, status, _, body, reason) =
        run_backend_transform(200, json_headers(), original.clone()).await;

    assert!(!replaced, "a clean non-matching document must be served");
    assert!(!transformed);
    assert_eq!(status, 200);
    assert_eq!(reason, None);
    assert_eq!(body, original);
}

#[tokio::test]
async fn empty_protected_body_is_forwarded_unchanged() {
    let (replaced, transformed, status, _, body, reason) =
        run_backend_transform(200, json_headers(), Vec::new()).await;

    assert!(!replaced, "an empty body carries nothing to redact");
    assert!(!transformed);
    assert_eq!(status, 200);
    assert_eq!(reason, None);
    assert!(body.is_empty());
}

#[tokio::test]
async fn unstamped_backend_response_cannot_prove_its_representation_and_is_rejected() {
    let plugins = redacting_plugins();
    let mut ctx = make_ctx();
    let mut status = 200;
    let mut headers = json_headers();
    let mut body = br#"{"secret":"hunter2"}"#.to_vec();
    // Deliberately no snapshot.

    let (replaced, _) = transform_buffered_response_body_with_deadline_full_for_test(
        &plugins,
        &mut ctx,
        &mut status,
        &mut headers,
        &mut body,
        None,
        false,
    )
    .await;

    assert!(replaced);
    assert_eq!(
        representation_rejection_reason_for_test(&ctx),
        Some("unproven_origin_state")
    );
    assert_secret_not_forwarded(&body);
}

// ---------------------------------------------------------------------------
// Unprotected traffic must be completely unaffected.
// ---------------------------------------------------------------------------

/// One unprotected-traffic case: the backend status, its response headers, and
/// the exact bytes that must be forwarded untouched.
type UnprotectedCase = (u16, Vec<(&'static str, &'static str)>, Vec<u8>);

/// The critical non-regression: without a configured body policy, none of the
/// above rejections may fire. A `206` video range, a gzip asset, and a
/// zstd-encoded payload all pass through untouched.
#[tokio::test]
async fn unprotected_responses_are_never_rejected_by_the_gate() {
    // A `response_transformer` with header rules only — no body policy.
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(
        ResponseTransformer::new(&json!({
            "rules": [
                {"operation": "add", "target": "header", "key": "X-Test", "value": "1"}
            ]
        }))
        .expect("header-only response_transformer config must be valid"),
    )];

    let cases: Vec<UnprotectedCase> = vec![
        (
            206,
            vec![
                ("content-type", "video/mp4"),
                ("content-range", "bytes 0-9/100"),
            ],
            b"0123456789".to_vec(),
        ),
        (
            200,
            vec![
                ("content-type", "application/json"),
                ("content-encoding", "gzip"),
            ],
            gzip(br#"{"secret":"hunter2"}"#),
        ),
        (
            200,
            vec![
                ("content-type", "application/json"),
                ("content-encoding", "zstd"),
            ],
            b"\x28\xb5\x2f\xfd not really zstd".to_vec(),
        ),
        (
            226,
            vec![("content-type", "application/json"), ("im", "feed")],
            br#"{"delta":true}"#.to_vec(),
        ),
        (
            200,
            vec![("content-type", "application/json")],
            b"{ not json at all".to_vec(),
        ),
    ];

    for (case_status, header_pairs, original) in cases {
        let mut ctx = make_ctx();
        let mut status = case_status;
        let mut headers: HashMap<String, String> = header_pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let mut body = original.clone();
        stamp_original_response_metadata_for_test(&mut ctx, status, &headers);

        let (replaced, transformed) = transform_buffered_response_body_with_deadline_full_for_test(
            &plugins,
            &mut ctx,
            &mut status,
            &mut headers,
            &mut body,
            None,
            false,
        )
        .await;

        assert!(
            !replaced,
            "unprotected {case_status} response must not be rejected"
        );
        assert!(!transformed);
        assert_eq!(status, case_status, "status must be preserved exactly");
        assert_eq!(body, original, "bytes must be forwarded untouched");
        assert_eq!(representation_rejection_reason_for_test(&ctx), None);
    }
}

/// Regression: the gate must parse exactly the way the enforcer does. A body the
/// gate accepts but `apply_body_rules` cannot parse would return `None` from the
/// transform, be read as "no rule matched", and forward the protected bytes —
/// the same conflation this whole gate exists to close. A UTF-8 BOM is the
/// concrete case: `serde_json` rejects it, so the gate must too.
#[tokio::test]
async fn bom_prefixed_json_is_rejected_rather_than_leniently_accepted() {
    let mut body = vec![0xef, 0xbb, 0xbf];
    body.extend_from_slice(br#"{"secret":"hunter2","keep":1}"#);

    let (replaced, transformed, status, _, body, reason) =
        run_backend_transform(200, json_headers(), body).await;

    assert!(
        replaced,
        "a body the enforcer cannot parse must not be blessed by the gate"
    );
    assert!(!transformed);
    assert_eq!(status, 502);
    assert_eq!(reason.as_deref(), Some("unparseable_document"));
    assert_secret_not_forwarded(&body);
}

// ---------------------------------------------------------------------------
// Absent `Content-Type`: the claim predicate must match the enforcer exactly.
//
// `transform_response_body` treats `None` as JSON — it only declines on a
// *present* non-JSON type — and calls `apply_body_rules`. A claim predicate that
// declined `None` would leave untyped bodies un-inspected by the gate while the
// enforcer still tried (and silently failed) to parse them, which is the exact
// `None`-conflation bypass the gate exists to close.
// ---------------------------------------------------------------------------

/// The bypass itself: an untyped **gzip** body carrying a protected field. The
/// gate must claim it, decode it, and let the redaction apply — never forward
/// the encoded protected bytes because the backend omitted `Content-Type`.
#[tokio::test]
async fn untyped_encoded_body_is_claimed_decoded_and_redacted() {
    let headers = HashMap::from([("content-encoding".to_string(), "gzip".to_string())]);

    let (replaced, transformed, status, headers, body, reason) =
        run_backend_transform(200, headers, gzip(br#"{"secret":"hunter2","keep":1}"#)).await;

    assert!(!replaced, "a decodable untyped JSON body must be served");
    assert!(
        transformed,
        "the configured body rule must apply to an untyped JSON document"
    );
    assert_eq!(status, 200);
    assert_eq!(reason, None);
    assert_secret_not_forwarded(&body);
    assert!(String::from_utf8_lossy(&body).contains("keep"));
    assert!(!headers.contains_key("content-encoding"));
}

/// An untyped body the enforcer cannot parse must be rejected, not forwarded.
/// Forwarding is what made this a bypass: `apply_body_rules` returns `None`, the
/// lifecycle reads "no rule matched", and the protected value ships.
#[tokio::test]
async fn untyped_unparseable_body_is_rejected_not_forwarded() {
    let original = br#"{"secret":"hunter2", TRUNCATED"#.to_vec();
    let (replaced, transformed, status, _, body, reason) =
        run_backend_transform(200, HashMap::new(), original).await;

    assert!(
        replaced,
        "an untyped body the enforcer cannot parse must not be forwarded"
    );
    assert!(!transformed);
    assert_eq!(status, 502);
    assert_eq!(reason.as_deref(), Some("unparseable_document"));
    assert_secret_not_forwarded(&body);
}

/// An untyped **fragment** is claimed too, so the partial-representation
/// rejection applies to it exactly as it does to a typed one.
#[tokio::test]
async fn untyped_partial_representation_is_rejected() {
    let headers = HashMap::from([("content-range".to_string(), "bytes 0-19/512".to_string())]);
    let (replaced, _, status, _, body, reason) =
        run_backend_transform(206, headers, br#"{"secret":"hunter2"}"#.to_vec()).await;

    assert!(replaced);
    assert_eq!(status, 502);
    assert_eq!(reason.as_deref(), Some("partial_representation"));
    assert_secret_not_forwarded(&body);
}

/// The ordinary case: an untyped body that *is* parseable JSON is transformed
/// like any other claimed document, matching what the enforcer already did.
#[tokio::test]
async fn untyped_transformable_json_body_is_redacted() {
    let (replaced, transformed, status, _, body, reason) = run_backend_transform(
        200,
        HashMap::new(),
        br#"{"secret":"hunter2","keep":1}"#.to_vec(),
    )
    .await;

    assert!(!replaced);
    assert!(transformed);
    assert_eq!(status, 200);
    assert_eq!(reason, None);
    assert_secret_not_forwarded(&body);
    assert!(String::from_utf8_lossy(&body).contains("keep"));
}

/// A non-JSON media type is a documented decline for this policy, not an
/// inspection failure, so it must not be rejected.
#[tokio::test]
async fn non_json_media_type_is_not_claimed_by_a_json_body_policy() {
    let mut headers = HashMap::from([("content-type".to_string(), "text/plain".to_string())]);
    headers.insert("content-encoding".to_string(), "zstd".to_string());
    let original = b"opaque bytes".to_vec();

    let (replaced, transformed, status, _, body, reason) =
        run_backend_transform(200, headers, original.clone()).await;

    assert!(!replaced);
    assert!(!transformed);
    assert_eq!(status, 200);
    assert_eq!(reason, None);
    assert_eq!(body, original);
}

// ---------------------------------------------------------------------------
// Multiple transformer instances.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn multiple_transformer_instances_all_apply_to_a_decoded_body() {
    let plugins: Vec<Arc<dyn Plugin>> = vec![
        Arc::new(
            ResponseTransformer::new(&json!({
                "rules": [{"operation": "remove", "target": "body", "key": "secret"}]
            }))
            .expect("first transformer config must be valid"),
        ),
        Arc::new(
            ResponseTransformer::new(&json!({
                "rules": [{"operation": "remove", "target": "body", "key": "other"}]
            }))
            .expect("second transformer config must be valid"),
        ),
    ];

    let mut ctx = make_ctx();
    let mut status = 200;
    let mut headers = json_headers();
    headers.insert("content-encoding".to_string(), "gzip".to_string());
    let mut body = gzip(br#"{"secret":"hunter2","other":"s3cr3t","keep":1}"#);
    stamp_original_response_metadata_for_test(&mut ctx, status, &headers);

    let (replaced, transformed) = transform_buffered_response_body_with_deadline_full_for_test(
        &plugins,
        &mut ctx,
        &mut status,
        &mut headers,
        &mut body,
        None,
        false,
    )
    .await;

    assert!(!replaced);
    assert!(transformed);
    let rendered = String::from_utf8_lossy(&body);
    assert!(!rendered.contains("hunter2"), "first rule must apply");
    assert!(!rendered.contains("s3cr3t"), "second rule must apply");
    assert!(rendered.contains("keep"));
    let expected_len = body.len().to_string();
    assert_eq!(
        headers.get("content-length"),
        Some(&expected_len),
        "content-length must describe the final bytes after both rewrites"
    );
}

// ---------------------------------------------------------------------------
// gRPC-Web flavor: a rejection must be a gRPC-Web trailer frame, not a bare 502.
// ---------------------------------------------------------------------------

/// A gRPC-Web response whose merged view is JSON *is* claimed by a JSON body
/// policy, so this composition genuinely reaches the gate. The rejection must
/// come back in the client's flavor: HTTP 200 carrying a gRPC-Web trailer frame,
/// not an HTTP 502 the gRPC-Web client cannot interpret.
#[tokio::test]
async fn grpc_web_representation_rejection_uses_the_grpc_web_error_shape() {
    let plugins = redacting_plugins();
    let mut ctx = make_ctx();
    let mut status = 206;
    let mut headers = json_headers();
    headers.insert("content-range".to_string(), "bytes 0-9/100".to_string());
    let mut body = br#"{"secret":"hunter2"}"#.to_vec();
    stamp_original_response_metadata_for_test(&mut ctx, status, &headers);

    let (replaced, transformed) = transform_buffered_response_body_with_deadline_full_for_test(
        &plugins,
        &mut ctx,
        &mut status,
        &mut headers,
        &mut body,
        Some("application/grpc-web+proto"),
        false,
    )
    .await;

    assert!(replaced, "a protected fragment must be rejected");
    assert!(!transformed);
    assert_eq!(
        status, 200,
        "a gRPC-Web error rides in a trailer frame under HTTP 200"
    );
    assert_eq!(
        representation_rejection_reason_for_test(&ctx),
        Some("partial_representation")
    );
    assert_eq!(
        headers.get("content-type").map(String::as_str),
        Some("application/grpc-web+proto")
    );
    assert_eq!(headers.get("x-grpc-web").map(String::as_str), Some("1"));
    assert!(
        !headers.contains_key("content-range"),
        "the replacement must not carry the fragment's range metadata"
    );
    assert_secret_not_forwarded(&body);
}

// ---------------------------------------------------------------------------
// A decode is itself a change to the client-visible bytes.
// ---------------------------------------------------------------------------

/// Regression: a claimed gzip body that decodes cleanly but that **no** body
/// rule happens to change never reaches `finalize_response_body_transformation`,
/// so the invalidation has to happen at the decode. Otherwise the client is
/// served identity bytes carrying the origin's validator for the *encoded* ones —
/// a strong `ETag`/`Digest` describing a representation it never receives, which
/// corrupts cache revalidation and integrity checks.
#[tokio::test]
async fn decoded_body_invalidates_validators_even_when_no_rule_matches() {
    let mut headers = json_headers();
    headers.insert("content-encoding".to_string(), "gzip".to_string());
    headers.insert("etag".to_string(), "\"gzipped-v1\"".to_string());
    headers.insert("content-digest".to_string(), "sha-256=:abc:".to_string());
    headers.insert("content-md5".to_string(), "deadbeef".to_string());
    let modified = "Tue, 15 Nov 2022 12:45:26 GMT".to_string();
    headers.insert("last-modified".to_string(), modified);
    headers.insert("x-amz-checksum-crc32".to_string(), "AAAAAA==".to_string());

    // No `secret` key, so the configured `remove` rule matches nothing.
    let plaintext = br#"{"keep":1}"#;
    let (replaced, transformed, status, headers, body, reason) =
        run_backend_transform(200, headers, gzip(plaintext)).await;

    assert!(!replaced, "a decodable, unmatched document must be served");
    assert!(
        transformed,
        "the decode itself must be reported as a client-visible representation rewrite"
    );
    assert_eq!(status, 200);
    assert_eq!(reason, None);
    assert_eq!(
        body, plaintext,
        "the client receives the decoded identity bytes"
    );
    assert!(
        !headers.contains_key("content-encoding"),
        "decoded bytes must not still claim a content coding"
    );
    for stale in [
        "etag",
        "content-digest",
        "content-md5",
        "last-modified",
        "x-amz-checksum-crc32",
    ] {
        assert!(
            !headers.contains_key(stale),
            "`{stale}` described the encoded bytes and must not survive the decode"
        );
    }
    assert_eq!(
        headers.get("content-length"),
        Some(&body.len().to_string()),
        "content-length must describe the decoded bytes"
    );
}

/// Defensive regression: if an identity-only coding marker reaches the decoder,
/// it is still not a byte rewrite. Reporting one would retire validators and
/// trailers even though the representation did not change.
#[tokio::test]
async fn identity_only_codings_are_not_reported_as_representation_rewrites() {
    let plugins = redacting_plugins();
    let mut ctx = make_ctx();
    let mut status = 200;
    let mut headers = json_headers();
    headers.insert(
        "content-encoding".to_string(),
        "identity, identity".to_string(),
    );
    headers.insert("etag".to_string(), "\"identity-v1\"".to_string());
    let original_body = br#"{"keep":1}"#.to_vec();
    let mut body = original_body.clone();
    stamp_original_response_metadata_for_test(&mut ctx, status, &headers);
    set_original_response_content_encoding_for_test(&mut ctx, "identity, identity");

    let (replaced, representation_rewritten) =
        transform_buffered_response_body_with_deadline_full_for_test(
            &plugins,
            &mut ctx,
            &mut status,
            &mut headers,
            &mut body,
            None,
            false,
        )
        .await;

    assert!(!replaced);
    assert!(
        !representation_rewritten,
        "identity-only tokens must not report a client-visible byte rewrite"
    );
    assert_eq!(body, original_body);
    assert_eq!(
        headers.get("etag").map(String::as_str),
        Some("\"identity-v1\""),
        "validators remain valid when no bytes changed"
    );
    assert_eq!(
        headers.get("content-encoding").map(String::as_str),
        Some("identity, identity"),
        "an identity-only field must not be stripped as though decoding occurred"
    );
}

// ---------------------------------------------------------------------------
// Backend fragment evidence is status-semantic, not header-presence.
// ---------------------------------------------------------------------------

/// A complete `416` status document. RFC 9110 §15.5.17 defines
/// `Content-Range: bytes */<len>` there as reporting the selected
/// representation's length — it does not make the body a range slice. Rejecting
/// it would fail closed on an ordinary backend error while protecting nothing,
/// since the body is a complete, fully inspectable document.
#[tokio::test]
async fn complete_416_with_unsatisfied_range_header_is_inspected_not_rejected() {
    let mut headers = json_headers();
    headers.insert("content-range".to_string(), "bytes */2048".to_string());

    let (replaced, transformed, status, headers, body, reason) =
        run_backend_transform(416, headers, br#"{"secret":"hunter2","keep":1}"#.to_vec()).await;

    assert!(
        !replaced,
        "a complete 416 error document must not become a 502"
    );
    assert!(
        transformed,
        "the configured policy must be applied to it, not bypassed"
    );
    assert_eq!(status, 416, "the backend's own status must survive");
    assert_eq!(reason, None);
    assert_secret_not_forwarded(&body);
    assert!(String::from_utf8_lossy(&body).contains("keep"));
    assert!(
        !headers.contains_key("content-range"),
        "the permitted rewrite must invalidate the stale range metadata"
    );
}

/// The same rule across the rest of the non-2xx category: a `503` echoing a
/// stale `IM` field is an error document, not a delta.
#[tokio::test]
async fn complete_non_2xx_with_stale_delta_header_is_inspected_not_rejected() {
    let mut headers = json_headers();
    headers.insert("im".to_string(), "feed".to_string());
    headers.insert("delta-base".to_string(), "\"base-v1\"".to_string());

    let (replaced, transformed, status, headers, body, reason) =
        run_backend_transform(503, headers, br#"{"secret":"hunter2","keep":1}"#.to_vec()).await;

    assert!(!replaced);
    assert!(transformed);
    assert_eq!(status, 503);
    assert_eq!(reason, None);
    assert_secret_not_forwarded(&body);
    for stale in ["im", "delta-base"] {
        assert!(!headers.contains_key(stale));
    }
}

/// The narrowing must not weaken real fragment rejection. A backend `2xx`
/// carrying range or delta metadata is still exactly the shape a relabeled
/// fragment takes, and is still rejected.
#[tokio::test]
async fn backend_2xx_carrying_fragment_metadata_is_still_rejected() {
    for header in ["content-range", "im"] {
        let mut headers = json_headers();
        let value = if header == "content-range" {
            "bytes 0-19/512"
        } else {
            "feed"
        };
        headers.insert(header.to_string(), value.to_string());

        let (replaced, _, status, _, body, reason) =
            run_backend_transform(200, headers, br#"{"secret":"hunter2"}"#.to_vec()).await;

        assert!(replaced, "a 200 bearing `{header}` must still be rejected");
        assert_eq!(status, 502);
        assert_eq!(reason.as_deref(), Some("partial_representation"));
        assert_secret_not_forwarded(&body);
    }
}

// ---------------------------------------------------------------------------
// Test-only plugins for the rejection-shape findings.
// ---------------------------------------------------------------------------

/// An opt-in reject decorator, standing in for the CORS / correlation-ID /
/// security-header plugins that set `applies_after_proxy_on_reject`.
struct RejectDecorator;

#[async_trait::async_trait]
impl Plugin for RejectDecorator {
    fn name(&self) -> &str {
        "test_reject_decorator"
    }

    fn applies_after_proxy_on_reject(&self) -> bool {
        true
    }

    async fn after_proxy(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        response_headers.insert(
            "access-control-allow-origin".to_string(),
            "https://app.example".to_string(),
        );
        PluginResult::Continue
    }
}

/// A body policy that claims every response regardless of media type. Real
/// `response_transformer` declines non-JSON, so this is the only way to drive a
/// claimed **native gRPC** response into the gate — the composition the native
/// branch of the rejection path exists for.
struct ClaimEverythingPolicy;

impl Plugin for ClaimEverythingPolicy {
    fn name(&self) -> &str {
        "test_claim_everything_policy"
    }

    fn enforces_response_body_policy(
        &self,
        _ctx: &RequestContext,
        _response_content_type: Option<&str>,
    ) -> bool {
        true
    }
}

/// Deterministic initial-response policy standing in for `security_headers`.
struct InitialHeaderPolicy;

impl Plugin for InitialHeaderPolicy {
    fn name(&self) -> &str {
        "test_initial_header_policy"
    }

    fn is_initial_response_header_policy(&self) -> bool {
        true
    }

    fn apply_initial_response_header_policy(&self, response_headers: &mut HashMap<String, String>) {
        response_headers.insert(
            "x-initial-policy".to_string(),
            "gateway-enforced".to_string(),
        );
    }
}

/// H3 cross-protocol buffered publication carries the prefiltered initial-policy
/// list into the shared gate. A gRPC-Web representation rejection must therefore
/// keep operator policy on the synthesized trailers-only error.
#[tokio::test]
async fn grpc_web_representation_rejection_applies_prefiltered_initial_policy() {
    let plugins = redacting_plugins();
    let initial_policy_plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(InitialHeaderPolicy)];
    let mut ctx = make_ctx();
    let mut status = 200;
    let mut headers = json_headers();
    headers.insert("content-encoding".to_string(), "zstd".to_string());
    let mut body = br#"{"secret":"hunter2"}"#.to_vec();
    stamp_original_response_metadata_for_test(&mut ctx, status, &headers);

    let replaced = transform_buffered_response_body_with_deadline_and_policy_for_test(
        &plugins,
        &mut ctx,
        &mut status,
        &mut headers,
        &mut body,
        Some("application/grpc-web+proto"),
        &initial_policy_plugins,
    )
    .await;

    assert!(replaced);
    assert_eq!(status, 200);
    assert_eq!(
        headers.get("x-initial-policy").map(String::as_str),
        Some("gateway-enforced")
    );
}

/// The synthetic/replay publication phase owns the live protocol plugin chain
/// rather than the cache's separate policy slice. It must still select and apply
/// opted-in initial policy when the gate synthesizes a gRPC-Web error.
#[tokio::test]
async fn synthetic_grpc_web_representation_rejection_applies_initial_policy() {
    let mut plugins = redacting_plugins();
    plugins.push(Arc::new(InitialHeaderPolicy));
    let mut ctx = make_ctx();
    retain_grpc_web_client_content_type_for_test(&mut ctx, "application/grpc-web+proto");
    let mut status = 200;
    let mut headers = json_headers();
    headers.insert("content-encoding".to_string(), "zstd".to_string());
    let mut body = br#"{"secret":"hunter2"}"#.to_vec();

    apply_synthetic_response_body_hooks_for_test(
        &plugins,
        &mut ctx,
        &mut status,
        &mut headers,
        &mut body,
    )
    .await;

    assert_eq!(status, 200);
    assert_eq!(
        headers.get("content-type").map(String::as_str),
        Some("application/grpc-web+proto")
    );
    assert_eq!(
        headers.get("x-initial-policy").map(String::as_str),
        Some("gateway-enforced")
    );
    assert_eq!(
        representation_rejection_reason_for_test(&ctx),
        Some("unsupported_content_coding")
    );
    assert_secret_not_forwarded(&body);
}

/// A representation rejection is a gateway-authored terminal response, so it must
/// keep the same opt-in reject decorators an ordinary body reject keeps. Dropping
/// `Access-Control-Allow-Origin` here while every other gateway rejection keeps it
/// makes the error unreadable to a browser client.
#[tokio::test]
async fn representation_rejection_preserves_opt_in_reject_decorators() {
    let mut plugins = redacting_plugins();
    plugins.push(Arc::new(RejectDecorator));

    let mut ctx = make_ctx();
    let mut status = 206;
    let mut headers = json_headers();
    headers.insert("content-range".to_string(), "bytes 0-19/512".to_string());
    headers.insert("etag".to_string(), "\"fragment-v1\"".to_string());
    let mut body = br#"{"secret":"hunter2"}"#.to_vec();
    stamp_original_response_metadata_for_test(&mut ctx, status, &headers);

    let (replaced, _) = transform_buffered_response_body_with_deadline_full_for_test(
        &plugins,
        &mut ctx,
        &mut status,
        &mut headers,
        &mut body,
        None,
        false,
    )
    .await;

    assert!(replaced);
    assert_eq!(status, 502);
    assert_eq!(
        representation_rejection_reason_for_test(&ctx),
        Some("partial_representation")
    );
    assert_eq!(
        headers
            .get("access-control-allow-origin")
            .map(String::as_str),
        Some("https://app.example"),
        "opt-in reject decorators must run for a representation error too"
    );
    // ...without letting the rejected representation's own headers survive.
    for leaked in ["content-range", "etag"] {
        assert!(
            !headers.contains_key(leaked),
            "backend `{leaked}` must not survive onto the gateway error"
        );
    }
    assert_secret_not_forwarded(&body);
}

/// The native gRPC branch must shed backend headers before synthesizing its
/// trailers-only `INTERNAL`, exactly as the gRPC-Web branch and the deadline
/// replacement do. Otherwise `set-cookie`, validators, and cache directives
/// describing the *rejected* representation ride out on a gateway-authored error.
#[tokio::test]
async fn native_grpc_representation_rejection_strips_backend_headers() {
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(ClaimEverythingPolicy)];

    let mut ctx = make_ctx();
    set_request_http_flavor_for_test(&mut ctx, HttpFlavor::Grpc);
    let mut status = 200;
    let mut headers = HashMap::from([(
        "content-type".to_string(),
        "application/grpc+proto".to_string(),
    )]);
    // An unsupported coding is the rejection trigger; the rest is backend
    // metadata that must not survive.
    headers.insert("content-encoding".to_string(), "zstd".to_string());
    headers.insert("set-cookie".to_string(), "session=abc123".to_string());
    headers.insert("etag".to_string(), "\"backend-v1\"".to_string());
    headers.insert(
        "cache-control".to_string(),
        "public, max-age=600".to_string(),
    );
    let mut body = b"\x00\x00\x00\x00\x05hello".to_vec();
    stamp_original_response_metadata_for_test(&mut ctx, status, &headers);

    let (replaced, _) = transform_buffered_response_body_with_deadline_full_for_test(
        &plugins,
        &mut ctx,
        &mut status,
        &mut headers,
        &mut body,
        None,
        false,
    )
    .await;

    assert!(
        replaced,
        "an undecodable claimed representation is rejected"
    );
    assert_eq!(
        status, 200,
        "a native gRPC error is trailers-only under HTTP 200"
    );
    assert_eq!(
        representation_rejection_reason_for_test(&ctx),
        Some("unsupported_content_coding")
    );
    assert!(
        body.is_empty(),
        "a trailers-only gRPC error carries no body"
    );
    assert!(
        headers.contains_key("grpc-status"),
        "the gRPC terminal status must be present"
    );
    for leaked in ["set-cookie", "etag", "cache-control", "content-encoding"] {
        assert!(
            !headers.contains_key(leaked),
            "backend `{leaked}` survived onto a gateway-authored gRPC error"
        );
    }
}

/// Native gRPC rejection shaping is request provenance, not response metadata.
/// A real `after_proxy` header policy may remove Content-Type before the body
/// gate rejects the backend representation; the rejection must still use the
/// trailers-only native gRPC wire shape rather than falling through to JSON 502.
#[tokio::test]
async fn native_grpc_rejection_survives_after_proxy_content_type_removal() {
    let remove_content_type = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "remove", "target": "header", "key": "Content-Type"}
        ]
    }))
    .expect("header policy must be valid");
    let plugins: Vec<Arc<dyn Plugin>> = vec![
        Arc::new(remove_content_type),
        Arc::new(ClaimEverythingPolicy),
    ];

    let mut ctx = make_ctx();
    set_request_http_flavor_for_test(&mut ctx, HttpFlavor::Grpc);
    let mut status = 200;
    let mut headers = HashMap::from([
        (
            "content-type".to_string(),
            "application/grpc+proto".to_string(),
        ),
        ("content-encoding".to_string(), "zstd".to_string()),
    ]);
    let mut body = b"backend-response".to_vec();
    stamp_original_response_metadata_for_test(&mut ctx, status, &headers);

    assert!(
        !run_after_proxy_hooks_for_test(&plugins, &mut ctx, status, &mut headers).await,
        "the header policy must not reject the response"
    );
    assert!(
        !headers.contains_key("content-type"),
        "the regression requires Content-Type to be absent before the gate"
    );

    let (replaced, transformed) = transform_buffered_response_body_with_deadline_full_for_test(
        &plugins,
        &mut ctx,
        &mut status,
        &mut headers,
        &mut body,
        None,
        false,
    )
    .await;

    assert!(replaced, "the claimed unsupported coding must be rejected");
    assert!(!transformed);
    assert_eq!(status, 200, "native gRPC errors stay under HTTP 200");
    assert!(body.is_empty(), "native gRPC errors are trailers-only");
    assert_eq!(headers.get("grpc-status").map(String::as_str), Some("13"));
    assert_eq!(
        headers.get("grpc-message").map(String::as_str),
        Some("response representation could not be inspected")
    );
    assert_eq!(
        representation_rejection_reason_for_test(&ctx),
        Some("unsupported_content_coding")
    );
}

/// The rejection retain step must use provenance captured before response
/// decorators, even when there is no RPC deadline. Otherwise the fail-closed
/// fallback clears both backend metadata and the gateway's CORS/correlation/
/// security output. Exercise native gRPC and gRPC-Web with and without an
/// active deadline so the representation-only provenance path cannot diverge
/// from the established deadline path.
#[tokio::test]
async fn grpc_representation_rejection_preserves_decorators_with_or_without_deadline() {
    for deadline_active in [false, true] {
        for grpc_web_content_type in [None, Some("application/grpc-web+proto")] {
            let plugins: Vec<Arc<dyn Plugin>> =
                vec![Arc::new(ClaimEverythingPolicy), Arc::new(RejectDecorator)];
            let mut ctx = make_ctx();
            set_request_http_flavor_for_test(
                &mut ctx,
                if grpc_web_content_type.is_some() {
                    HttpFlavor::Plain
                } else {
                    HttpFlavor::Grpc
                },
            );
            if deadline_active {
                set_grpc_deadline_budget_for_test(&mut ctx, Some(10_000));
            }
            let mut status = 200;
            let mut headers = HashMap::from([
                (
                    "content-type".to_string(),
                    "application/grpc+proto".to_string(),
                ),
                ("content-encoding".to_string(), "zstd".to_string()),
                ("etag".to_string(), "\"backend-v1\"".to_string()),
                ("set-cookie".to_string(), "backend=secret".to_string()),
            ]);
            let mut body = b"backend-response".to_vec();
            stamp_original_response_metadata_for_test(&mut ctx, status, &headers);

            assert!(
                !run_after_proxy_hooks_for_test(&plugins, &mut ctx, status, &mut headers).await,
                "decorators must not reject the response"
            );
            let (replaced, _) = transform_buffered_response_body_with_deadline_full_for_test(
                &plugins,
                &mut ctx,
                &mut status,
                &mut headers,
                &mut body,
                grpc_web_content_type,
                false,
            )
            .await;

            assert!(replaced);
            assert_eq!(status, 200);
            assert_eq!(
                headers
                    .get("access-control-allow-origin")
                    .map(String::as_str),
                Some("https://app.example"),
                "gateway decorator was lost (deadline={deadline_active}, grpc_web={})",
                grpc_web_content_type.is_some()
            );
            for leaked in ["etag", "set-cookie", "content-encoding"] {
                assert!(
                    !headers.contains_key(leaked),
                    "backend `{leaked}` survived (deadline={deadline_active}, grpc_web={})",
                    grpc_web_content_type.is_some()
                );
            }
        }
    }
}

/// A body rewrite retires application trailers that may describe the original
/// bytes, but it must retain reserved gRPC completion metadata on the trailer
/// channel. A trailer key shadowed by a genuine initial header keeps only that
/// initial-header value.
#[test]
fn grpc_body_rewrite_discards_application_trailers_but_preserves_terminal_status() {
    let mut headers = HashMap::from([
        ("content-type".to_string(), "application/grpc".to_string()),
        ("grpc-status".to_string(), "0".to_string()),
        ("content-digest".to_string(), "sha-256=:old:".to_string()),
        ("x-app-trailer".to_string(), "old".to_string()),
        ("x-shadowed".to_string(), "initial".to_string()),
    ]);
    let mut trailers = HashMap::from([
        ("grpc-status".to_string(), "0".to_string()),
        ("content-digest".to_string(), "sha-256=:old:".to_string()),
        ("x-app-trailer".to_string(), "old".to_string()),
        ("x-shadowed".to_string(), "trailing".to_string()),
    ]);

    discard_grpc_application_trailers_after_body_rewrite_for_test(
        &mut headers,
        &mut trailers,
        &["x-shadowed"],
    );

    assert_eq!(
        trailers,
        HashMap::from([("grpc-status".to_string(), "0".to_string())])
    );
    assert_eq!(headers.get("grpc-status").map(String::as_str), Some("0"));
    assert_eq!(
        headers.get("x-shadowed").map(String::as_str),
        Some("initial")
    );
    assert!(!headers.contains_key("content-digest"));
    assert!(!headers.contains_key("x-app-trailer"));
}

/// A representation rejection can replace a non-empty backend response. Its
/// new INTERNAL status must become the authoritative Trailers-Only metadata;
/// split finalization must neither strip it nor restore the stale backend OK.
#[test]
fn h3_bridge_replacement_preserves_synthesized_terminal_status() {
    let replacement_headers = HashMap::from([
        ("content-type".to_string(), "application/grpc".to_string()),
        ("grpc-status".to_string(), "13".to_string()),
        (
            "grpc-message".to_string(),
            "response representation could not be inspected".to_string(),
        ),
    ]);
    let stale_backend_trailers = HashMap::from([
        ("grpc-status".to_string(), "0".to_string()),
        ("x-backend-trailer".to_string(), "stale".to_string()),
    ]);

    let (headers, trailers) = finalize_selected_buffered_grpc_terminal_response_for_test(
        replacement_headers,
        stale_backend_trailers,
    );

    assert!(
        trailers.is_empty(),
        "Trailers-Only status must not be duplicated"
    );
    assert_eq!(headers.get("grpc-status").map(String::as_str), Some("13"));
    assert_eq!(
        headers.get("grpc-message").map(String::as_str),
        Some("response representation could not be inspected")
    );
    assert!(!headers.contains_key("x-backend-trailer"));
}

// ---------------------------------------------------------------------------
// An earlier body rejection must survive the gate.
// ---------------------------------------------------------------------------

/// Once `on_response_body` has replaced the backend response with a plugin
/// rejection, the buffered bytes are the gateway's own. Judging them against the
/// *replaced* backend's snapshot would decode a body that was never encoded — or,
/// as here, reject a legitimate gateway `403` as a `206` fragment and overwrite it
/// with a generic `502`, destroying the very rejection the policy asked for.
#[tokio::test]
async fn earlier_body_rejection_survives_the_representation_gate() {
    let plugins = redacting_plugins();
    let mut ctx = make_ctx();

    // The backend response really was an encoded fragment...
    let mut backend_headers = json_headers();
    backend_headers.insert("content-encoding".to_string(), "gzip".to_string());
    backend_headers.insert("content-range".to_string(), "bytes 0-19/512".to_string());
    stamp_original_response_metadata_for_test(&mut ctx, 206, &backend_headers);

    // ...but `on_response_body` already replaced it with a gateway rejection.
    let rejection_body = br#"{"error":"forbidden","keep":1}"#.to_vec();
    let mut status = 403;
    let mut headers = json_headers();
    let mut body = rejection_body.clone();

    let (replaced, _) = transform_buffered_response_body_with_deadline_full_for_test(
        &plugins,
        &mut ctx,
        &mut status,
        &mut headers,
        &mut body,
        None,
        true,
    )
    .await;

    assert!(
        !replaced,
        "a gateway-authored rejection must not be overwritten by a representation error"
    );
    assert_eq!(status, 403, "the plugin's rejection status must survive");
    assert_eq!(
        representation_rejection_reason_for_test(&ctx),
        None,
        "the replaced backend's representation is no longer under inspection"
    );
    assert_eq!(body, rejection_body, "the rejection body must survive");
}

/// The control for the case above: the identical backend snapshot, with the
/// backend response still in place, is still rejected. The provenance switch
/// must not become a way to skip the gate on real backend bytes.
#[tokio::test]
async fn backend_bytes_under_the_same_snapshot_are_still_rejected() {
    let plugins = redacting_plugins();
    let mut ctx = make_ctx();

    let mut headers = json_headers();
    headers.insert("content-encoding".to_string(), "gzip".to_string());
    headers.insert("content-range".to_string(), "bytes 0-19/512".to_string());
    stamp_original_response_metadata_for_test(&mut ctx, 206, &headers);

    let mut status = 206;
    let mut body = gzip(br#"{"secret":"hunter2"}"#);

    let (replaced, _) = transform_buffered_response_body_with_deadline_full_for_test(
        &plugins,
        &mut ctx,
        &mut status,
        &mut headers,
        &mut body,
        None,
        false,
    )
    .await;

    assert!(replaced);
    assert_eq!(status, 502);
    assert_eq!(
        representation_rejection_reason_for_test(&ctx),
        Some("partial_representation")
    );
    assert_secret_not_forwarded(&body);
}

// ---------------------------------------------------------------------------
// Framed gRPC media types are outside the policy's document model.
//
// `application/grpc+json` and the gRPC-Web `+json` variants end in `+json`, so
// a naive JSON media-type test claims them — but their bytes are length-
// prefixed frames, never a bare document. Claiming them would send every valid
// gRPC JSON response on a mixed HTTP/gRPC proxy into `unparseable_document`.
// ---------------------------------------------------------------------------

/// One length-prefixed gRPC frame: compressed flag, 4-byte big-endian length,
/// then the message. Byte 0 is the flag, which is why a frame can never parse
/// as a JSON document.
fn grpc_frame(message: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(5 + message.len());
    framed.push(0);
    framed.extend_from_slice(&(message.len() as u32).to_be_bytes());
    framed.extend_from_slice(message);
    framed
}

async fn run_with_content_type(
    content_type: &str,
    body: Vec<u8>,
) -> (bool, u16, Option<String>, Vec<u8>) {
    let headers = HashMap::from([("content-type".to_string(), content_type.to_string())]);
    let (replaced, _, status, _, body, reason) = run_backend_transform(200, headers, body).await;
    (replaced, status, reason, body)
}

#[tokio::test]
async fn framed_grpc_json_response_is_passed_through_not_rejected() {
    for content_type in [
        "application/grpc+json",
        "application/grpc-web+json",
        "application/grpc-web-text+json",
        "application/grpc+json; charset=utf-8",
        "APPLICATION/GRPC+JSON",
    ] {
        let framed = grpc_frame(br#"{"keep":1}"#);
        let (replaced, status, reason, body) =
            run_with_content_type(content_type, framed.clone()).await;

        assert!(!replaced, "`{content_type}` must not be claimed");
        assert_eq!(status, 200, "`{content_type}` must pass through");
        assert_eq!(reason, None, "`{content_type}` must not reject");
        assert_eq!(body, framed, "`{content_type}` bytes must survive");
    }
}

#[tokio::test]
async fn native_grpc_response_is_passed_through_not_rejected() {
    let framed = grpc_frame(b"\x08\x01");
    let (replaced, status, reason, body) =
        run_with_content_type("application/grpc", framed.clone()).await;

    assert!(!replaced);
    assert_eq!(status, 200);
    assert_eq!(reason, None);
    assert_eq!(body, framed);
}

/// Non-regression for the earlier P1 fix: an ABSENT `Content-Type` must still be
/// claimed and inspected, because the transform treats it as JSON. Excluding
/// framed gRPC must not have narrowed that.
#[tokio::test]
async fn untyped_json_response_is_still_claimed_and_redacted() {
    let body = br#"{"secret":"hunter2","keep":1}"#.to_vec();
    let (replaced, transformed, status, _, body, reason) =
        run_backend_transform(200, HashMap::new(), body).await;

    assert!(!replaced, "untyped parseable JSON is servable");
    assert!(transformed, "the body rule must still apply");
    assert_eq!(status, 200);
    assert_eq!(reason, None);
    assert_secret_not_forwarded(&body);
}

/// The other half of that P1 fix: an untyped body that is NOT parseable JSON
/// still fails closed. A framed-gRPC exclusion keyed off `Content-Type` cannot
/// reach this case, since there is no `Content-Type` to match.
#[tokio::test]
async fn untyped_unparseable_response_still_fails_closed() {
    let body = b"not json at all".to_vec();
    let (replaced, _, status, _, body, reason) =
        run_backend_transform(200, HashMap::new(), body).await;

    assert!(replaced);
    assert_eq!(status, 502);
    assert_eq!(reason.as_deref(), Some("unparseable_document"));
    assert_secret_not_forwarded(&body);
}

/// An ordinary vendor `+json` type is NOT gRPC and must stay claimed.
#[tokio::test]
async fn vendor_json_media_type_is_still_claimed_and_redacted() {
    let body = br#"{"secret":"hunter2","keep":1}"#.to_vec();
    let (replaced, status, reason, body) =
        run_with_content_type("application/vnd.acme.v2+json", body).await;

    assert!(!replaced);
    assert_eq!(status, 200);
    assert_eq!(reason, None);
    assert_secret_not_forwarded(&body);
}

// ---------------------------------------------------------------------------
// Identity coding acceptability.
//
// Decoding publishes identity bytes. A client that sent `identity;q=0` refused
// exactly that representation, and the gateway does not re-encode — so the
// encoded response must be rejected, never silently downgraded.
// ---------------------------------------------------------------------------

fn gzip_json_headers() -> HashMap<String, String> {
    let mut headers = json_headers();
    headers.insert("content-encoding".to_string(), "gzip".to_string());
    headers
}

/// Build a context whose pristine `Accept-Encoding` snapshot was captured by
/// the real production stamp from real raw wire headers — the same sequence the
/// H1/H2 and H3 handlers run at request init, before any `before_proxy` hook.
fn ctx_with_client_accept_encoding(accept_encoding: Option<&str>) -> RequestContext {
    let mut ctx = make_ctx();
    let mut raw = http::HeaderMap::new();
    if let Some(value) = accept_encoding {
        raw.insert(
            http::header::ACCEPT_ENCODING,
            http::HeaderValue::from_str(value).expect("accept-encoding must be a valid header"),
        );
    }
    ctx.set_raw_headers(raw);
    stamp_original_request_metadata_for_test(&mut ctx);
    ctx.materialize_headers();
    ctx
}

/// Drive the transform phase with a client `Accept-Encoding` on the context.
async fn run_with_accept_encoding(
    accept_encoding: Option<&str>,
    headers: HashMap<String, String>,
    body: Vec<u8>,
) -> (bool, u16, Option<String>, Vec<u8>, HashMap<String, String>) {
    let plugins = redacting_plugins();
    let mut ctx = ctx_with_client_accept_encoding(accept_encoding);
    let mut status = 200;
    let mut headers = headers;
    let mut body = body;
    stamp_original_response_metadata_for_test(&mut ctx, status, &headers);
    let (replaced, _) = transform_buffered_response_body_with_deadline_full_for_test(
        &plugins,
        &mut ctx,
        &mut status,
        &mut headers,
        &mut body,
        None,
        false,
    )
    .await;
    let reason = representation_rejection_reason_for_test(&ctx).map(str::to_string);
    (replaced, status, reason, body, headers)
}

#[tokio::test]
async fn encoded_body_is_rejected_when_client_forbids_identity() {
    for accept_encoding in [
        "gzip, identity;q=0",
        "gzip;q=1.0, identity;q=0.0",
        "gzip, identity;q=0, br",
        "gzip, *;q=0",
        "gzip, identity ; q=0",
        "gzip, IDENTITY;Q=0",
    ] {
        let encoded = gzip(br#"{"secret":"hunter2","keep":1}"#);
        let (replaced, status, reason, body, _) =
            run_with_accept_encoding(Some(accept_encoding), gzip_json_headers(), encoded).await;

        assert!(replaced, "`{accept_encoding}` forbids identity");
        assert_eq!(status, 502, "`{accept_encoding}` is unservable");
        assert_eq!(
            reason.as_deref(),
            Some("identity_coding_unacceptable"),
            "`{accept_encoding}` must report acceptability"
        );
        assert_secret_not_forwarded(&body);
    }
}

#[tokio::test]
async fn encoded_body_is_decoded_when_identity_is_acceptable() {
    for accept_encoding in [
        None,
        Some("gzip"),
        Some("gzip, identity"),
        Some("gzip, identity;q=0.1"),
        // An explicit non-zero `identity` outranks a `*;q=0` wildcard.
        Some("gzip, *;q=0, identity;q=1"),
        // A malformed qvalue must not be read as a refusal.
        Some("gzip, identity;q=bogus"),
        // An empty field value means identity, and only identity, is fine.
        Some(""),
    ] {
        let encoded = gzip(br#"{"secret":"hunter2","keep":1}"#);
        let (replaced, status, reason, body, headers) =
            run_with_accept_encoding(accept_encoding, gzip_json_headers(), encoded).await;

        assert!(!replaced, "`{accept_encoding:?}` accepts identity");
        assert_eq!(status, 200, "`{accept_encoding:?}` is servable");
        assert_eq!(reason, None, "`{accept_encoding:?}` is servable");
        assert!(!headers.contains_key("content-encoding"));
        assert_secret_not_forwarded(&body);
        assert!(String::from_utf8_lossy(&body).contains("keep"));
    }
}

/// `identity;q=0` only matters when a decode would actually change the octets.
/// An unencoded response is already identity and is unaffected.
#[tokio::test]
async fn identity_refusal_does_not_affect_unencoded_responses() {
    let body = br#"{"secret":"hunter2","keep":1}"#.to_vec();
    let (replaced, status, reason, body, _) =
        run_with_accept_encoding(Some("gzip, identity;q=0"), json_headers(), body).await;

    assert!(!replaced, "an identity body is unchanged by decoding");
    assert_eq!(status, 200);
    assert_eq!(reason, None);
    assert_secret_not_forwarded(&body);
}

/// An unclaimed response is never inspected, so a client that forbids identity
/// still gets its encoded bytes through untouched.
#[tokio::test]
async fn identity_refusal_does_not_reject_unclaimed_responses() {
    let headers = HashMap::from([
        ("content-type".to_string(), "text/plain".to_string()),
        ("content-encoding".to_string(), "gzip".to_string()),
    ]);
    let encoded = gzip(b"plain text body");
    let (replaced, status, reason, body, headers) =
        run_with_accept_encoding(Some("gzip, identity;q=0"), headers, encoded.clone()).await;

    assert!(!replaced, "a non-JSON response is not claimed");
    assert_eq!(status, 200);
    assert_eq!(reason, None);
    assert_eq!(body, encoded, "unclaimed bytes pass through");
    assert_eq!(
        headers.get("content-encoding").map(String::as_str),
        Some("gzip")
    );
}

// ---------------------------------------------------------------------------
// The operator's configured response-body limit bounds the decode.
//
// A small compressed body can pass every wire-size check and then inflate past
// `FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES` during inspection. Enabling a body
// policy must not buy a larger effective ceiling.
// ---------------------------------------------------------------------------

/// Drive the transform phase with the operator's configured response-body limit
/// on the context, exactly as the H1/H2 and H3 handlers set it from `ProxyState`.
async fn run_with_response_limit(
    max_response_body_size_bytes: usize,
    body: Vec<u8>,
) -> (bool, u16, Option<String>, Vec<u8>) {
    let plugins = redacting_plugins();
    let mut ctx = make_ctx();
    ctx.max_response_body_size_bytes = max_response_body_size_bytes;
    let mut headers = gzip_json_headers();
    let mut status = 200;
    let mut body = body;
    stamp_original_response_metadata_for_test(&mut ctx, status, &headers);
    let (replaced, _) = transform_buffered_response_body_with_deadline_full_for_test(
        &plugins,
        &mut ctx,
        &mut status,
        &mut headers,
        &mut body,
        None,
        false,
    )
    .await;
    let reason = representation_rejection_reason_for_test(&ctx).map(str::to_string);
    (replaced, status, reason, body)
}

/// A highly compressible JSON document whose decoded size far exceeds a small
/// configured limit while its compressed size stays trivially under it.
fn inflating_json(padding_len: usize) -> Vec<u8> {
    let padding = "A".repeat(padding_len);
    format!(r#"{{"secret":"hunter2","pad":"{padding}"}}"#).into_bytes()
}

#[tokio::test]
async fn decode_is_rejected_when_it_exceeds_the_configured_response_limit() {
    let plaintext = inflating_json(64 * 1024);
    let compressed = gzip(&plaintext);
    let limit = 8 * 1024;

    assert!(compressed.len() < limit, "wire size must pass");
    assert!(plaintext.len() > limit, "decoded size must exceed");

    let (replaced, status, reason, body) = run_with_response_limit(limit, compressed).await;

    assert!(replaced, "a decode past the limit is unservable");
    assert_eq!(status, 502);
    assert_eq!(reason.as_deref(), Some("decoded_body_too_large"));
    assert_secret_not_forwarded(&body);
}

#[tokio::test]
async fn decode_within_the_configured_response_limit_still_succeeds() {
    let plaintext = inflating_json(1024);
    let compressed = gzip(&plaintext);
    let limit = 64 * 1024;

    assert!(plaintext.len() < limit);

    let (replaced, status, reason, body) = run_with_response_limit(limit, compressed).await;

    assert!(!replaced, "a decode inside the limit is servable");
    assert_eq!(status, 200);
    assert_eq!(reason, None);
    assert_secret_not_forwarded(&body);
    assert!(String::from_utf8_lossy(&body).contains("pad"));
}

/// `0` is the project-wide "unlimited" spelling, and must fall back to the
/// module's hard ceiling rather than rejecting every decode.
#[tokio::test]
async fn unlimited_configured_response_limit_falls_back_to_hard_ceiling() {
    let plaintext = inflating_json(64 * 1024);
    let compressed = gzip(&plaintext);

    let (replaced, status, reason, body) = run_with_response_limit(0, compressed).await;

    assert!(!replaced, "`0` means unlimited, not zero-length");
    assert_eq!(status, 200);
    assert_eq!(reason, None);
    assert_secret_not_forwarded(&body);
}

// ---------------------------------------------------------------------------
// The identity refusal is read from a PRE-HOOK snapshot.
//
// `request_transformer` (priority 3000) runs before `compression` (priority
// 4050) and can remove or rewrite `Accept-Encoding`. If the gate consulted only
// the post-hook header map or compression's later metadata copy, an explicit
// `identity;q=0` would be erased and a protected encoded response would be
// decoded and served in the representation the client refused.
// ---------------------------------------------------------------------------

/// A `request_transformer` that removes the client's `Accept-Encoding` in
/// `before_proxy`, i.e. the ordering Codex described.
fn accept_encoding_removing_request_transformer() -> RequestTransformer {
    RequestTransformer::new(&json!({
        "rules": [
            {"operation": "remove", "target": "header", "key": "Accept-Encoding"}
        ]
    }))
    .expect("request_transformer config must be valid")
}

/// A `request_transformer` that REWRITES `Accept-Encoding` to a value with no
/// refusal in it — the rewrite half of the same bypass.
fn accept_encoding_rewriting_request_transformer() -> RequestTransformer {
    RequestTransformer::new(&json!({
        "rules": [
            {"operation": "update", "target": "header", "key": "Accept-Encoding", "value": "gzip"}
        ]
    }))
    .expect("request_transformer config must be valid")
}

/// Drive the real request hook over the context, then the real buffered
/// transform phase, exactly in the production order.
async fn run_with_request_hook_then_encoded_response(
    accept_encoding: &str,
    request_transformer: RequestTransformer,
) -> (bool, u16, Option<String>, Vec<u8>) {
    let mut ctx = ctx_with_client_accept_encoding(Some(accept_encoding));

    // `before_proxy` receives the live header map, as the proxy passes it.
    let mut request_headers = ctx.headers.clone();
    request_transformer
        .before_proxy(&mut ctx, &mut request_headers)
        .await;
    ctx.headers = request_headers;

    let plugins = redacting_plugins();
    let mut headers = gzip_json_headers();
    let mut status = 200;
    let mut body = gzip(br#"{"secret":"hunter2","keep":1}"#);
    stamp_original_response_metadata_for_test(&mut ctx, status, &headers);
    let (replaced, _) = transform_buffered_response_body_with_deadline_full_for_test(
        &plugins,
        &mut ctx,
        &mut status,
        &mut headers,
        &mut body,
        None,
        false,
    )
    .await;
    let reason = representation_rejection_reason_for_test(&ctx).map(str::to_string);
    (replaced, status, reason, body)
}

#[tokio::test]
async fn request_hook_removing_accept_encoding_cannot_erase_the_identity_refusal() {
    let (replaced, status, reason, body) = run_with_request_hook_then_encoded_response(
        "gzip, identity;q=0",
        accept_encoding_removing_request_transformer(),
    )
    .await;

    assert!(replaced, "the client still refused identity");
    assert_eq!(status, 502);
    assert_eq!(reason.as_deref(), Some("identity_coding_unacceptable"));
    assert_secret_not_forwarded(&body);
}

#[tokio::test]
async fn request_hook_rewriting_accept_encoding_cannot_erase_the_identity_refusal() {
    let (replaced, status, reason, body) = run_with_request_hook_then_encoded_response(
        "gzip, identity;q=0",
        accept_encoding_rewriting_request_transformer(),
    )
    .await;

    assert!(replaced, "the client still refused identity");
    assert_eq!(status, 502);
    assert_eq!(reason.as_deref(), Some("identity_coding_unacceptable"));
    assert_secret_not_forwarded(&body);
}

/// The snapshot must not invent a refusal either: a client that accepted
/// identity is still served its decoded, redacted body after the same hooks.
#[tokio::test]
async fn request_hook_rewrite_does_not_invent_an_identity_refusal() {
    let (replaced, status, reason, body) = run_with_request_hook_then_encoded_response(
        "gzip, identity",
        accept_encoding_removing_request_transformer(),
    )
    .await;

    assert!(!replaced, "the client accepted identity");
    assert_eq!(status, 200);
    assert_eq!(reason, None);
    assert_secret_not_forwarded(&body);
    assert!(String::from_utf8_lossy(&body).contains("keep"));
}

// ---------------------------------------------------------------------------
// Only a syntactically valid weight expresses a refusal.
//
// RFC 9110 §12.4.2 defines `qvalue` as `0[.0*3]` / `1[.0*3]`. A negative,
// out-of-range, or non-finite parameter is MALFORMED, not a zero weight, and
// this predicate can only ever turn a servable response into a 502 — so
// malformed must stay on the acceptable side.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn invalid_qvalues_are_malformed_rather_than_an_identity_refusal() {
    for accept_encoding in [
        // Negative weights: the case Codex raised.
        "gzip, identity;q=-1",
        "gzip, *;q=-1",
        "gzip, identity;q=-0.5",
        "gzip, identity;q=-0",
        // Signed zero and out-of-range / non-finite weights.
        "gzip, identity;q=+0",
        "gzip, identity;q=5",
        "gzip, identity;q=inf",
        "gzip, identity;q=NaN",
        "gzip, *;q=5",
    ] {
        let encoded = gzip(br#"{"secret":"hunter2","keep":1}"#);
        let (replaced, status, reason, body, headers) =
            run_with_accept_encoding(Some(accept_encoding), gzip_json_headers(), encoded).await;

        assert!(
            !replaced,
            "`{accept_encoding}` is malformed, not a refusal — it must not 502"
        );
        assert_eq!(status, 200, "`{accept_encoding}` stays servable");
        assert_eq!(reason, None, "`{accept_encoding}` must not be rejected");
        assert!(
            !headers.contains_key("content-encoding"),
            "`{accept_encoding}` is served decoded"
        );
        assert_secret_not_forwarded(&body);
        assert!(String::from_utf8_lossy(&body).contains("keep"));
    }
}

/// The valid-weight boundary still refuses, so widening the parse did not
/// weaken the refusal path itself.
#[tokio::test]
async fn valid_zero_weights_still_express_an_identity_refusal() {
    for accept_encoding in [
        "gzip, identity;q=0",
        "gzip, identity;q=0.0",
        "gzip, identity;q=0.000",
        "gzip, *;q=0",
        "gzip, *;q=0.000",
    ] {
        let encoded = gzip(br#"{"secret":"hunter2","keep":1}"#);
        let (replaced, status, reason, _, _) =
            run_with_accept_encoding(Some(accept_encoding), gzip_json_headers(), encoded).await;

        assert!(replaced, "`{accept_encoding}` refuses identity");
        assert_eq!(status, 502, "`{accept_encoding}` is unservable");
        assert_eq!(
            reason.as_deref(),
            Some("identity_coding_unacceptable"),
            "`{accept_encoding}` must report acceptability"
        );
    }
}

// ---------------------------------------------------------------------------
// A present-but-empty coding token is malformed, and must reach the
// fail-closed malformed-coding rejection on BOTH provenances rather than being
// filtered away as though the field were absent.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn empty_backend_coding_tokens_are_rejected_as_malformed() {
    for content_encoding in [",", "identity,", ",identity", " , ", "identity, ,"] {
        let mut headers = json_headers();
        headers.insert("content-encoding".to_string(), content_encoding.to_string());
        let body = br#"{"secret":"hunter2","keep":1}"#.to_vec();

        let (replaced, _, status, _, body, reason) =
            run_backend_transform(200, headers, body).await;

        assert!(
            replaced,
            "`{content_encoding}` is malformed and must not be forwarded"
        );
        assert_eq!(status, 502, "`{content_encoding}` is unservable");
        assert_eq!(
            reason.as_deref(),
            Some("malformed_content_coding"),
            "`{content_encoding}` must reach the malformed-coding branch"
        );
        assert_secret_not_forwarded(&body);
    }
}

/// `identity` alone is not malformed and must not be made to look encoded, so
/// it neither triggers a decode nor a rejection.
#[tokio::test]
async fn identity_only_codings_are_neither_decoded_nor_rejected() {
    for content_encoding in ["identity", "identity, identity", " identity "] {
        let mut headers = json_headers();
        headers.insert("content-encoding".to_string(), content_encoding.to_string());
        let body = br#"{"secret":"hunter2","keep":1}"#.to_vec();

        let (_, _, status, headers, body, reason) = run_backend_transform(200, headers, body).await;

        assert_eq!(status, 200, "`{content_encoding}` is servable");
        assert_eq!(reason, None, "`{content_encoding}` is not a rejection");
        assert_eq!(
            headers.get("content-encoding").map(String::as_str),
            Some(content_encoding),
            "an identity-only field must not be stripped as though decoding occurred"
        );
        assert_secret_not_forwarded(&body);
    }
}

// ---------------------------------------------------------------------------
// Framed gRPC is declined on PRE-HOOK evidence, not on the live response
// `Content-Type`.
//
// The gate reads `content-type` after `after_proxy`, so a header rule that
// removes or rewrites a gRPC response's type would otherwise land it on the
// untyped-JSON branch — and `response_transformer` would claim its
// length-prefixed frames, fail to parse them as a bare document, and replace a
// valid RPC reply with `unparseable_document`.
//
// The pristine stamped media type answers first; the request's immutable gRPC
// flavor and the retained gRPC-Web representation answer when the backend
// stamped no type at all.
// ---------------------------------------------------------------------------

/// Drive the buffered transform phase over a framed response, stamping the
/// backend's ORIGINAL `Content-Type` first and only then applying the relabel,
/// which is the real production ordering: the snapshot is taken before
/// `after_proxy`, and the header rule rewrites the live map afterwards.
///
/// `backend_content_type` is what the backend actually sent (`None` models a
/// backend that omitted it); `relabelled_content_type` is what the live map says
/// by the time the gate reads it (`None` models an outright removal).
async fn run_framed_response_with_relabelled_content_type(
    flavor: HttpFlavor,
    retained_grpc_web_content_type: Option<&str>,
    backend_content_type: Option<&str>,
    relabelled_content_type: Option<&str>,
) -> (bool, u16, Option<String>, Vec<u8>) {
    let plugins = redacting_plugins();
    let mut ctx = make_ctx();
    set_request_http_flavor_for_test(&mut ctx, flavor);
    if let Some(content_type) = retained_grpc_web_content_type {
        retain_grpc_web_client_content_type_for_test(&mut ctx, content_type);
    }

    let mut status = 200;
    let mut body = grpc_frame(br#"{"secret":"hunter2","keep":1}"#);

    // The pristine snapshot sees the backend's own headers.
    let mut headers = HashMap::new();
    if let Some(content_type) = backend_content_type {
        headers.insert("content-type".to_string(), content_type.to_string());
    }
    stamp_original_response_metadata_for_test(&mut ctx, status, &headers);

    // An `after_proxy` header rule then removes or rewrites the live type.
    headers.remove("content-type");
    if let Some(content_type) = relabelled_content_type {
        headers.insert("content-type".to_string(), content_type.to_string());
    }

    let (replaced, _) = transform_buffered_response_body_with_deadline_full_for_test(
        &plugins,
        &mut ctx,
        &mut status,
        &mut headers,
        &mut body,
        None,
        false,
    )
    .await;
    let reason = representation_rejection_reason_for_test(&ctx).map(str::to_string);
    (replaced, status, reason, body)
}

/// One relabelling case: the request flavor, the retained gRPC-Web type, the
/// backend's own `Content-Type`, and the type `after_proxy` relabelled it to.
type RelabelledCase = (
    HttpFlavor,
    Option<&'static str>,
    Option<&'static str>,
    Option<&'static str>,
);

#[tokio::test]
async fn relabelled_framed_grpc_responses_are_not_claimed_as_json() {
    // (request flavor, retained gRPC-Web type, backend type, relabelled type)
    let cases: [RelabelledCase; 10] = [
        // --- The pristine snapshot proves the framing. ---
        // Native gRPC whose response type was removed outright by `after_proxy`.
        (HttpFlavor::Grpc, None, Some("application/grpc+proto"), None),
        // Native gRPC relabelled to a plain JSON type.
        (
            HttpFlavor::Grpc,
            None,
            Some("application/grpc+proto"),
            Some("application/json"),
        ),
        // Native gRPC `+json` relabelled to a vendor `+json` type.
        (
            HttpFlavor::Grpc,
            None,
            Some("application/grpc+json"),
            Some("application/vnd.acme+json"),
        ),
        // gRPC-Web binary, type removed after the snapshot.
        (
            HttpFlavor::Plain,
            Some("application/grpc-web+proto"),
            Some("application/grpc-web+proto"),
            None,
        ),
        // gRPC-Web text, relabelled to plain JSON.
        (
            HttpFlavor::Plain,
            Some("application/grpc-web-text+proto"),
            Some("application/grpc-web-text+proto"),
            Some("application/json"),
        ),
        // gRPC-Web `+json`, relabelled to a vendor `+json` type.
        (
            HttpFlavor::Plain,
            Some("application/grpc-web+json"),
            Some("application/grpc-web+json"),
            Some("application/vnd.acme+json"),
        ),
        // --- No type was ever stamped, so the request flavor answers. ---
        // Native gRPC backend that omitted `Content-Type` entirely.
        (HttpFlavor::Grpc, None, None, None),
        // gRPC-Web binary, no backend type at all.
        (
            HttpFlavor::Plain,
            Some("application/grpc-web+proto"),
            None,
            None,
        ),
        // gRPC-Web text, no backend type at all.
        (
            HttpFlavor::Plain,
            Some("application/grpc-web-text+proto"),
            None,
            None,
        ),
        // Native gRPC over an H3/extended path that also omitted the type.
        (
            HttpFlavor::Grpc,
            Some("application/grpc-web+proto"),
            None,
            None,
        ),
    ];

    for (flavor, retained, backend_content_type, relabelled) in cases {
        let expected = grpc_frame(br#"{"secret":"hunter2","keep":1}"#);
        let (replaced, status, reason, body) = run_framed_response_with_relabelled_content_type(
            flavor,
            retained,
            backend_content_type,
            relabelled,
        )
        .await;

        let case = format!("{flavor:?}/{retained:?}/{backend_content_type:?}/{relabelled:?}");
        assert!(
            !replaced,
            "{case}: a framed gRPC response must not be claimed or rejected"
        );
        assert_eq!(status, 200, "{case}: a valid RPC reply stays a 200");
        assert_eq!(
            reason, None,
            "{case}: frames must never reach `unparseable_document`"
        );
        assert_eq!(body, expected, "{case}: the frames pass through intact");
    }
}

/// Non-regression for the earlier absent-`Content-Type` fix: an ordinary HTTP
/// request whose response omits `Content-Type` is still claimed and redacted.
/// Declining framed gRPC must key off the REQUEST, not exempt untyped
/// responses generally.
#[tokio::test]
async fn untyped_ordinary_http_json_is_still_claimed_and_redacted() {
    let body = br#"{"secret":"hunter2","keep":1}"#.to_vec();
    let (_, _, status, _, body, reason) = run_backend_transform(200, HashMap::new(), body).await;

    assert_eq!(status, 200, "an ordinary untyped JSON body is servable");
    assert_eq!(reason, None);
    assert_secret_not_forwarded(&body);
    assert!(
        String::from_utf8_lossy(&body).contains("keep"),
        "the untyped body is still transformed, not passed through"
    );
}

/// And an ordinary untyped response that is NOT parseable JSON still fails
/// closed, so the flavor-based decline did not widen into the untyped branch.
#[tokio::test]
async fn untyped_ordinary_http_non_json_is_still_rejected() {
    let body = b"\x00\x00\x00\x00\x05hello".to_vec();
    let (replaced, _, status, _, body, reason) =
        run_backend_transform(200, HashMap::new(), body).await;

    assert!(replaced, "an unparseable untyped body is not forwarded");
    assert_eq!(status, 502);
    assert_eq!(reason.as_deref(), Some("unparseable_document"));
    assert_secret_not_forwarded(&body);
}

/// The decline is keyed on proven FRAMING, not on the request being gRPC-Web.
/// A gRPC-Web request whose backend genuinely answered with a bare JSON
/// document is still claimed and still redacted — keying off the request flavor
/// alone would have silently dropped that redaction, which is the wrong
/// direction for a fail-closed gate.
#[tokio::test]
async fn grpc_web_request_with_a_genuine_json_response_is_still_redacted() {
    let plugins = redacting_plugins();
    let mut ctx = make_ctx();
    retain_grpc_web_client_content_type_for_test(&mut ctx, "application/grpc-web+proto");

    let mut status = 200;
    let mut headers = json_headers();
    let mut body = br#"{"secret":"hunter2","keep":1}"#.to_vec();
    stamp_original_response_metadata_for_test(&mut ctx, status, &headers);

    let (replaced, _) = transform_buffered_response_body_with_deadline_full_for_test(
        &plugins,
        &mut ctx,
        &mut status,
        &mut headers,
        &mut body,
        None,
        false,
    )
    .await;

    assert!(!replaced, "a real JSON document is servable");
    assert_eq!(status, 200);
    assert_eq!(
        representation_rejection_reason_for_test(&ctx),
        None,
        "a bare JSON document is not framed and must not be declined"
    );
    assert_secret_not_forwarded(&body);
    assert!(
        String::from_utf8_lossy(&body).contains("keep"),
        "the body is still transformed, not passed through"
    );
}
