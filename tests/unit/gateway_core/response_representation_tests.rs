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
    representation_rejection_reason_for_test, stamp_original_response_metadata_for_test,
    transform_buffered_response_body_with_deadline_full_for_test,
};
use ferrum_edge::plugins::{Plugin, RequestContext, response_transformer::ResponseTransformer};
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

/// A response with no `Content-Type` at all must not become a 502. Untyped
/// bodies (minimal error pages, redirect bodies, plain-text health output) are
/// outside what a JSON field policy can enforce, exactly like a mislabeled one.
#[tokio::test]
async fn untyped_response_is_not_claimed_and_is_forwarded_unchanged() {
    let original = b"<html><body>backend error</body></html>".to_vec();
    let (replaced, transformed, status, _, body, reason) =
        run_backend_transform(200, HashMap::new(), original.clone()).await;

    assert!(!replaced, "an untyped body must not be rejected");
    assert!(!transformed);
    assert_eq!(status, 200);
    assert_eq!(reason, None);
    assert_eq!(body, original);
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
