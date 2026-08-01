//! Shared backend-visible request representation gate (`GHSA-3973-47g5-4mcx`).
//!
//! These drive the PRODUCTION `evaluate_final_request_body_posture` through the
//! `_test_support` seam, so they assert the real fail-closed decision rather than
//! a reimplementation of it.

use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;

use ferrum_edge::_test_support::{
    FinalRequestRepresentationOutcome, evaluate_final_request_representation,
};
use ferrum_edge::plugins::body_validator::BodyValidator;
use ferrum_edge::plugins::waf::Waf;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext};
use serde_json::json;

const BLOCKED_JSON: &str = r#"{"note":"' OR 1=1 --","approved":false}"#;

fn ctx_with_json_post() -> RequestContext {
    let mut ctx = RequestContext::new("203.0.113.10".into(), "POST".into(), "/api".into());
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx
}

fn headers(content_encoding: Option<&str>) -> HashMap<String, String> {
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    if let Some(encoding) = content_encoding {
        headers.insert("content-encoding".to_string(), encoding.to_string());
    }
    headers
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).expect("gzip write");
    encoder.finish().expect("gzip finish")
}

fn brotli(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut writer = brotli::CompressorWriter::new(&mut out, 4096, 5, 22);
    writer.write_all(data).expect("brotli write");
    drop(writer);
    out
}

/// A WAF with an enforcing request-body rule: the reference claiming plugin.
fn enforcing_waf() -> Arc<dyn Plugin> {
    Arc::new(
        Waf::new(&json!({
            "mode": "enforce",
            "request_body_inspection": true,
            "default_rule_action": "enforce",
        }))
        .expect("waf config"),
    )
}

/// A `body_validator` requiring `approved: true` on JSON requests.
fn approving_body_validator() -> Arc<dyn Plugin> {
    Arc::new(
        BodyValidator::new(&json!({
            "required_fields": ["approved"],
            "content_types": ["application/json"],
        }))
        .expect("body_validator config"),
    )
}

#[test]
fn identity_request_needs_no_decode() {
    let plugins = vec![enforcing_waf()];
    let ctx = ctx_with_json_post();
    let outcome = evaluate_final_request_representation(
        &plugins,
        &ctx,
        &headers(None),
        BLOCKED_JSON.as_bytes(),
    );
    assert_eq!(outcome, FinalRequestRepresentationOutcome::Inspectable);
}

#[test]
fn explicit_identity_coding_needs_no_decode() {
    let plugins = vec![enforcing_waf()];
    let ctx = ctx_with_json_post();
    let outcome = evaluate_final_request_representation(
        &plugins,
        &ctx,
        &headers(Some("identity")),
        BLOCKED_JSON.as_bytes(),
    );
    assert_eq!(outcome, FinalRequestRepresentationOutcome::Inspectable);
}

#[test]
fn unclaimed_encoded_request_is_left_alone() {
    // No configured policy claims this request, so an ordinary compressed upload
    // keeps flowing to a backend that understands it.
    let plugins: Vec<Arc<dyn Plugin>> = Vec::new();
    let ctx = ctx_with_json_post();
    let outcome = evaluate_final_request_representation(
        &plugins,
        &ctx,
        &headers(Some("gzip")),
        &gzip(BLOCKED_JSON.as_bytes()),
    );
    assert_eq!(outcome, FinalRequestRepresentationOutcome::Inspectable);
}

#[test]
fn single_gzip_coding_is_decoded_for_a_claiming_policy() {
    let plugins = vec![enforcing_waf()];
    let ctx = ctx_with_json_post();
    let outcome = evaluate_final_request_representation(
        &plugins,
        &ctx,
        &headers(Some("gzip")),
        &gzip(BLOCKED_JSON.as_bytes()),
    );
    assert_eq!(
        outcome,
        FinalRequestRepresentationOutcome::Decoded(BLOCKED_JSON.as_bytes().to_vec())
    );
}

#[test]
fn single_brotli_coding_is_decoded_for_a_claiming_policy() {
    let plugins = vec![approving_body_validator()];
    let ctx = ctx_with_json_post();
    let outcome = evaluate_final_request_representation(
        &plugins,
        &ctx,
        &headers(Some("br")),
        &brotli(BLOCKED_JSON.as_bytes()),
    );
    assert_eq!(
        outcome,
        FinalRequestRepresentationOutcome::Decoded(BLOCKED_JSON.as_bytes().to_vec())
    );
}

#[test]
fn chained_gzip_then_brotli_is_decoded_in_reverse_application_order() {
    // `Content-Encoding: gzip, br` means gzip was applied first, then Brotli.
    // The chain the audited build refused to touch at all.
    let plugins = vec![enforcing_waf()];
    let ctx = ctx_with_json_post();
    let stacked = brotli(&gzip(BLOCKED_JSON.as_bytes()));
    let outcome =
        evaluate_final_request_representation(&plugins, &ctx, &headers(Some("gzip, br")), &stacked);
    assert_eq!(
        outcome,
        FinalRequestRepresentationOutcome::Decoded(BLOCKED_JSON.as_bytes().to_vec())
    );
}

#[test]
fn x_gzip_alias_is_decoded() {
    let plugins = vec![enforcing_waf()];
    let ctx = ctx_with_json_post();
    let outcome = evaluate_final_request_representation(
        &plugins,
        &ctx,
        &headers(Some("x-gzip")),
        &gzip(BLOCKED_JSON.as_bytes()),
    );
    assert_eq!(
        outcome,
        FinalRequestRepresentationOutcome::Decoded(BLOCKED_JSON.as_bytes().to_vec())
    );
}

#[test]
fn unsupported_coding_fails_closed() {
    let plugins = vec![enforcing_waf()];
    let ctx = ctx_with_json_post();
    let outcome = evaluate_final_request_representation(
        &plugins,
        &ctx,
        &headers(Some("zstd")),
        BLOCKED_JSON.as_bytes(),
    );
    assert_eq!(
        outcome,
        FinalRequestRepresentationOutcome::Rejected("unsupported_content_coding")
    );
}

#[test]
fn empty_coding_member_fails_closed() {
    let plugins = vec![enforcing_waf()];
    let ctx = ctx_with_json_post();
    for value in ["gzip,", ",gzip", "  ", "gzip,,br"] {
        let outcome = evaluate_final_request_representation(
            &plugins,
            &ctx,
            &headers(Some(value)),
            &gzip(BLOCKED_JSON.as_bytes()),
        );
        assert_eq!(
            outcome,
            FinalRequestRepresentationOutcome::Rejected("malformed_content_coding"),
            "value {value:?} must not be read as an absent coding"
        );
    }
}

#[test]
fn identity_mixed_with_a_transforming_coding_fails_closed() {
    let plugins = vec![enforcing_waf()];
    let ctx = ctx_with_json_post();
    let outcome = evaluate_final_request_representation(
        &plugins,
        &ctx,
        &headers(Some("identity, gzip")),
        &gzip(BLOCKED_JSON.as_bytes()),
    );
    assert_eq!(
        outcome,
        FinalRequestRepresentationOutcome::Rejected("malformed_content_coding")
    );
}

#[test]
fn parameterized_coding_member_fails_closed() {
    let plugins = vec![enforcing_waf()];
    let ctx = ctx_with_json_post();
    let outcome = evaluate_final_request_representation(
        &plugins,
        &ctx,
        &headers(Some("gzip;q=1")),
        &gzip(BLOCKED_JSON.as_bytes()),
    );
    assert_eq!(
        outcome,
        FinalRequestRepresentationOutcome::Rejected("malformed_content_coding")
    );
}

#[test]
fn too_many_stacked_codings_fails_closed() {
    let plugins = vec![enforcing_waf()];
    let ctx = ctx_with_json_post();
    let outcome = evaluate_final_request_representation(
        &plugins,
        &ctx,
        &headers(Some("gzip, gzip, gzip, gzip, gzip")),
        &gzip(BLOCKED_JSON.as_bytes()),
    );
    assert_eq!(
        outcome,
        FinalRequestRepresentationOutcome::Rejected("too_many_content_codings")
    );
}

#[test]
fn truncated_gzip_stream_fails_closed() {
    let plugins = vec![enforcing_waf()];
    let ctx = ctx_with_json_post();
    let mut encoded = gzip(BLOCKED_JSON.as_bytes());
    encoded.truncate(encoded.len() / 2);
    let outcome =
        evaluate_final_request_representation(&plugins, &ctx, &headers(Some("gzip")), &encoded);
    assert_eq!(
        outcome,
        FinalRequestRepresentationOutcome::Rejected("undecodable_content_coding")
    );
}

#[test]
fn plaintext_labelled_as_gzip_fails_closed() {
    let plugins = vec![enforcing_waf()];
    let ctx = ctx_with_json_post();
    let outcome = evaluate_final_request_representation(
        &plugins,
        &ctx,
        &headers(Some("gzip")),
        BLOCKED_JSON.as_bytes(),
    );
    assert_eq!(
        outcome,
        FinalRequestRepresentationOutcome::Rejected("undecodable_content_coding")
    );
}

#[test]
fn empty_body_under_a_declared_coding_fails_closed() {
    let plugins = vec![enforcing_waf()];
    let ctx = ctx_with_json_post();
    let outcome =
        evaluate_final_request_representation(&plugins, &ctx, &headers(Some("gzip")), &[]);
    assert_eq!(
        outcome,
        FinalRequestRepresentationOutcome::Rejected("undecodable_content_coding")
    );
}

#[test]
fn a_zip_bomb_is_refused_by_the_decoded_size_bound() {
    let plugins = vec![enforcing_waf()];
    let ctx = ctx_with_json_post();
    // 32 MiB of zeroes is a few kilobytes encoded and is refused past the
    // 10 MiB decoded ceiling; the decoder stops at the bound rather than
    // materializing the full expansion.
    let bomb = gzip(&vec![0u8; 32 * 1024 * 1024]);
    let outcome =
        evaluate_final_request_representation(&plugins, &ctx, &headers(Some("gzip")), &bomb);
    assert_eq!(
        outcome,
        FinalRequestRepresentationOutcome::Rejected("undecodable_content_coding")
    );
}

#[test]
fn multiple_claiming_instances_all_reach_the_same_decision() {
    let plugins = vec![enforcing_waf(), approving_body_validator(), enforcing_waf()];
    let ctx = ctx_with_json_post();
    let outcome = evaluate_final_request_representation(
        &plugins,
        &ctx,
        &headers(Some("gzip")),
        &gzip(BLOCKED_JSON.as_bytes()),
    );
    assert_eq!(
        outcome,
        FinalRequestRepresentationOutcome::Decoded(BLOCKED_JSON.as_bytes().to_vec())
    );
}

#[tokio::test]
async fn waf_scans_the_staged_plaintext_not_the_wire_octets() {
    let plugin = Waf::new(&json!({
        "mode": "enforce",
        "request_body_inspection": true,
        "default_rule_action": "enforce",
    }))
    .expect("waf config");
    let mut ctx = ctx_with_json_post();
    let encoded = gzip(BLOCKED_JSON.as_bytes());

    // Without the gate's plaintext view, the compressed octets match nothing.
    let opaque = plugin
        .on_final_request_body_with_context(&mut ctx, &headers(Some("gzip")), &encoded)
        .await;
    assert!(matches!(opaque, PluginResult::Continue));

    // With it, the SQLi signature inside the document is found and blocked.
    let mut ctx = ctx_with_json_post();
    ferrum_edge::_test_support::stage_final_request_body_plaintext(
        &mut ctx,
        BLOCKED_JSON.as_bytes().to_vec(),
    );
    let scanned = plugin
        .on_final_request_body_with_context(&mut ctx, &headers(Some("gzip")), &encoded)
        .await;
    assert!(
        matches!(scanned, PluginResult::Reject { .. }),
        "WAF must block the plaintext it was configured about"
    );
}

#[tokio::test]
async fn body_validator_validates_the_staged_plaintext() {
    let plugin = BodyValidator::new(&json!({
        "required_fields": ["approved_marker"],
        "content_types": ["application/json"],
    }))
    .expect("body_validator config");
    let document = br#"{"approved":false}"#;
    let encoded = gzip(document);
    let mut ctx = ctx_with_json_post();
    ferrum_edge::_test_support::stage_final_request_body_plaintext(&mut ctx, document.to_vec());

    let result = plugin
        .on_final_request_body_with_context(&mut ctx, &headers(Some("gzip")), &encoded)
        .await;

    assert!(
        matches!(result, PluginResult::Reject { .. }),
        "a missing required field in the decoded document must be rejected"
    );
}
