//! Ordering contract of the authoritative final client-visible response phases
//! (`GHSA-62jg-v563-4q23`, `GHSA-4vqr-427g-5cg7`).
//!
//! Every test here drives a PRODUCTION shared funnel — the buffered transform
//! phase (`transform_buffered_response_body_with_deadline`), the ordinary
//! `after_proxy` chain (`run_after_proxy_hooks`), or the synthetic /
//! short-circuit finalizer (`apply_reject_after_proxy_and_synthetic_body_hooks`)
//! — rather than calling a plugin hook directly. Calling the hook directly
//! proves only that the plugin can decide; these prove that the pipeline gives
//! it the last word.
//!
//! Plugin slices are supplied in configured priority order, exactly as the
//! plugin cache builds them, so "later" below means literally later in the
//! chain: `body_validator` 2950 and `waf` 2930 before `response_transformer`
//! 4000 and `compression` 4050.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::Arc;

use ferrum_edge::_test_support::{
    finalize_synthetic_response_for_test, gateway_capacity_response_selected_for_test,
    mark_buffered_response_capacity_refusal_pending_for_test,
    run_after_proxy_hooks_reject_for_test,
    set_original_response_content_encoding_for_test, stamp_original_response_metadata_for_test,
    take_buffered_response_capacity_refusal_pending_for_test,
    transform_buffered_response_body_with_deadline_full_for_test,
};
use ferrum_edge::plugins::{
    Plugin, RequestContext, body_validator::BodyValidator, compression::CompressionPlugin,
    response_transformer::ResponseTransformer, waf::Waf,
};
use serde_json::json;

/// The token an operator's WAF response-body rule blocks.
const BLOCKED_TOKEN: &str = "leak-secret";

/// The protected header name an operator's WAF response-header rule blocks.
const PROTECTED_HEADER: &str = "x-public-secret";

/// Final-body policy test double that reports the same one-shot bounded-scratch
/// refusal used by production response inspectors. It deliberately has no body
/// transform or transport encoder after it, covering the escape window where a
/// pending signal previously reached publication unconsumed.
struct FinalPolicyCapacityRefusal;

#[async_trait::async_trait]
impl Plugin for FinalPolicyCapacityRefusal {
    fn name(&self) -> &str {
        "final_policy_capacity_refusal"
    }

    fn requires_response_body_buffering(&self) -> bool {
        true
    }

    fn enforces_final_client_visible_response_body(&self, _ctx: &RequestContext) -> bool {
        true
    }

    async fn finalize_client_visible_response_body(
        &self,
        ctx: &mut RequestContext,
        _response_status: u16,
        _response_headers: &HashMap<String, String>,
        _body: &[u8],
    ) -> ferrum_edge::plugins::PluginResult {
        mark_buffered_response_capacity_refusal_pending_for_test(ctx);
        ferrum_edge::plugins::PluginResult::Continue
    }
}

fn ctx_for(method: &str, path: &str) -> RequestContext {
    let mut ctx = RequestContext::new(
        "203.0.113.7".to_string(),
        method.to_string(),
        path.to_string(),
    );
    ctx.max_response_body_size_bytes = 10 * 1024 * 1024;
    ctx
}

/// Run the real `before_proxy` and `after_proxy` hooks of a chain, exactly as
/// the proxy does before the buffered body phase. `compression` decides its
/// response encoding across those two hooks, so a transport-encoding test that
/// skipped them would never reach the encoder at all.
async fn run_request_and_response_header_hooks(
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
    response_headers: &mut HashMap<String, String>,
) {
    let mut request_headers = HashMap::new();
    for plugin in plugins {
        let _ = plugin.before_proxy(ctx, &mut request_headers).await;
    }
    // The pristine snapshot is taken from the BACKEND map, before any response
    // hook can add a gateway content coding to it.
    stamp_original_response_metadata_for_test(ctx, 200, response_headers);
    for plugin in plugins {
        let _ = plugin.after_proxy(ctx, 200, response_headers).await;
    }
}

fn json_headers() -> HashMap<String, String> {
    HashMap::from([("content-type".to_string(), "application/json".to_string())])
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).expect("gzip write");
    encoder.finish().expect("gzip finish")
}

fn gunzip(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(data)
        .read_to_end(&mut out)
        .expect("gzip round-trip");
    out
}

/// A WAF whose only enforcing rule blocks `BLOCKED_TOKEN` in the response body.
fn waf_blocking_response_body() -> Arc<dyn Plugin> {
    Arc::new(
        Waf::new(&json!({
            "mode": "enforce",
            "include_default_rules": false,
            "response_inspection": true,
            "response_body_inspection": true,
            "custom_rules": [{
                "id": "CUSTOM-RESP-BODY-LEAK",
                "name": "blocked response payload",
                "category": "custom",
                "severity": "high",
                "target": "response_body",
                "match_kind": "contains",
                "pattern": BLOCKED_TOKEN,
                "action": "enforce"
            }]
        }))
        .expect("waf response-body config"),
    )
}

/// A WAF whose only enforcing rule blocks the protected response header.
fn waf_blocking_protected_header(rule_id: &str) -> Arc<dyn Plugin> {
    Arc::new(
        Waf::new(&json!({
            "mode": "enforce",
            "include_default_rules": false,
            "response_inspection": true,
            "custom_rules": [{
                "id": rule_id,
                "name": "protected response header",
                "category": "custom",
                "severity": "high",
                "target": "response_headers",
                "match_kind": "contains",
                "pattern": PROTECTED_HEADER,
                "action": "enforce"
            }]
        }))
        .expect("waf response-header config"),
    )
}

/// A WAF configured against a header nothing in these tests ever produces.
fn waf_blocking_unrelated_header(rule_id: &str) -> Arc<dyn Plugin> {
    Arc::new(
        Waf::new(&json!({
            "mode": "enforce",
            "include_default_rules": false,
            "response_inspection": true,
            "custom_rules": [{
                "id": rule_id,
                "name": "unrelated response header",
                "category": "custom",
                "severity": "high",
                "target": "response_headers",
                "match_kind": "contains",
                "pattern": "x-never-emitted-header",
                "action": "enforce"
            }]
        }))
        .expect("waf unrelated response-header config"),
    )
}

/// A `body_validator` that requires `approved` on every JSON response.
fn body_validator_requiring_approved() -> Arc<dyn Plugin> {
    Arc::new(
        BodyValidator::new(&json!({
            "response_required_fields": ["approved"],
            "response_content_types": ["application/json"],
        }))
        .expect("body_validator response config"),
    )
}

/// A later `response_transformer` that renames the field the validator requires.
fn response_transformer_renaming_body_field() -> Arc<dyn Plugin> {
    Arc::new(
        ResponseTransformer::new(&json!({
            "rules": [
                {"operation": "rename", "target": "body",
                 "key": "approved", "new_key": "was_approved"}
            ]
        }))
        .expect("response_transformer body rename config"),
    )
}

/// A later `response_transformer` that adds the blocked token into the body.
fn response_transformer_adding_blocked_body_field() -> Arc<dyn Plugin> {
    Arc::new(
        ResponseTransformer::new(&json!({
            "rules": [
                {"operation": "add", "target": "body",
                 "key": "note", "value": format!("contains {BLOCKED_TOKEN} value")}
            ]
        }))
        .expect("response_transformer body add config"),
    )
}

/// A later `response_transformer` that renames a benign header into the
/// protected one — the exact advisory shape.
fn response_transformer_renaming_header() -> Arc<dyn Plugin> {
    Arc::new(
        ResponseTransformer::new(&json!({
            "rules": [
                {"operation": "rename", "target": "header",
                 "key": "x-pending-secret", "new_key": PROTECTED_HEADER}
            ]
        }))
        .expect("response_transformer header rename config"),
    )
}

fn compression_plugin() -> Arc<dyn Plugin> {
    let plugin = CompressionPlugin::new(&json!({"min_content_length": 10}))
        .expect("compression config");
    Arc::new(plugin)
}

/// Drive the production buffered transform funnel over a backend response.
///
/// The caller must already have stamped the pristine pre-`after_proxy` snapshot
/// (`stamp_original_response_metadata_for_test`): that snapshot IS the
/// production precondition the shared representation gate reads.
async fn run_buffered_transform(
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
    status: u16,
    headers: HashMap<String, String>,
    body: Vec<u8>,
) -> (bool, u16, HashMap<String, String>, Vec<u8>) {
    let mut status = status;
    let mut headers = headers;
    let mut body = bytes::Bytes::from(body);
    let (replaced, _rewritten) = transform_buffered_response_body_with_deadline_full_for_test(
        plugins,
        ctx,
        &mut status,
        &mut headers,
        &mut body,
        None,
        false,
    )
    .await;
    (replaced, status, headers, body.to_vec())
}

fn header_names_contain(headers: &HashMap<String, String>, name: &str) -> bool {
    headers.keys().any(|key| key.eq_ignore_ascii_case(name))
}

/// A one-shot capacity refusal raised by the authoritative final body policy
/// must install the shared terminal immediately even when no transport encoder
/// follows. Otherwise the original protected bytes could be published while the
/// refusal marker merely lingered on the request context.
#[tokio::test]
async fn final_body_policy_capacity_refusal_cannot_escape_without_transport_stage() {
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(FinalPolicyCapacityRefusal)];
    let mut ctx = ctx_for("GET", "/synthetic-capacity");
    let mut status = 200u16;
    let mut headers = json_headers();
    let mut body = bytes::Bytes::from_static(br#"{"secret":"must-not-publish"}"#);

    finalize_synthetic_response_for_test(
        &plugins,
        &mut ctx,
        &mut status,
        &mut headers,
        &mut body,
    )
    .await;

    assert_eq!(status, 503);
    assert!(gateway_capacity_response_selected_for_test(&ctx));
    assert!(!take_buffered_response_capacity_refusal_pending_for_test(
        &mut ctx
    ));
    assert!(!String::from_utf8_lossy(&body).contains("must-not-publish"));
}

// ─────────────── 1. late body rewrites cannot bypass body policy ───────────────

/// A later `response_transformer` body `rename` must not be able to remove the
/// field `body_validator` requires: the validator decides after every semantic
/// transform, over the exact plaintext the client would receive.
#[tokio::test]
async fn late_body_rename_cannot_bypass_body_validator() {
    let plugins = vec![
        body_validator_requiring_approved(),
        response_transformer_renaming_body_field(),
    ];
    let mut ctx = ctx_for("GET", "/orders");
    let headers = json_headers();
    stamp_original_response_metadata_for_test(&mut ctx, 200, &headers);
    let body_in = br#"{"approved":true}"#.to_vec();
    let (replaced, status, _headers, body) =
        run_buffered_transform(&plugins, &mut ctx, 200, headers, body_in).await;

    assert!(
        replaced,
        "the renamed representation must not be published as-is"
    );
    assert_eq!(status, 502, "response validation failure is a 502");
    let published = String::from_utf8_lossy(&body);
    assert!(
        !published.contains("was_approved"),
        "the renamed document must not reach the client: {published}"
    );
}

/// The same funnel, from the WAF's side: a later `add` rule that injects the
/// blocked token into the body cannot land behind the response-body scan.
#[tokio::test]
async fn late_body_add_cannot_bypass_waf_response_body_rule() {
    let plugins = vec![
        waf_blocking_response_body(),
        response_transformer_adding_blocked_body_field(),
    ];
    let mut ctx = ctx_for("GET", "/orders");
    let headers = json_headers();
    stamp_original_response_metadata_for_test(&mut ctx, 200, &headers);
    let body_in = br#"{"ok":true}"#.to_vec();
    let (replaced, status, _headers, body) =
        run_buffered_transform(&plugins, &mut ctx, 200, headers, body_in).await;

    assert!(replaced, "the injected token must not be published");
    assert_eq!(status, 403, "waf default reject status");
    assert!(
        !String::from_utf8_lossy(&body).contains(BLOCKED_TOKEN),
        "the blocked token must not survive into the client-visible body"
    );
}

/// The control: with no later rewrite, an untouched clean response still passes.
#[tokio::test]
async fn clean_response_is_published_unchanged() {
    let plugins = vec![
        waf_blocking_response_body(),
        body_validator_requiring_approved(),
    ];
    let mut ctx = ctx_for("GET", "/orders");
    let headers = json_headers();
    stamp_original_response_metadata_for_test(&mut ctx, 200, &headers);
    let body_in = br#"{"approved":true}"#.to_vec();
    let (replaced, status, _headers, body) =
        run_buffered_transform(&plugins, &mut ctx, 200, headers, body_in).await;

    assert!(!replaced);
    assert_eq!(status, 200);
    assert_eq!(body, br#"{"approved":true}"#.to_vec());
}

// ─────────── 2. late header rewrites cannot bypass WAF header policy ───────────

/// The advisory scenario. On a synthetic / short-circuit response the reject-path
/// `after_proxy` chain runs deliberately LAST, after the synthetic body hooks —
/// so a `response_transformer` header `rename` used to create the protected
/// header after the only enforcing pass. It must not survive.
#[tokio::test]
async fn late_header_rename_cannot_bypass_waf_on_synthetic_response() {
    let plugins = vec![
        waf_blocking_protected_header("CUSTOM-RESP-HEADER-SYNTHETIC"),
        response_transformer_renaming_header(),
    ];
    let mut ctx = ctx_for("GET", "/cache-hit");
    let mut status = 200u16;
    let mut headers = json_headers();
    headers.insert("x-pending-secret".to_string(), "value".to_string());
    // One-shot gateway session state staged onto the synthetic response.
    headers.insert("set-cookie".to_string(), "sid=rotated; HttpOnly".to_string());
    let mut body = bytes::Bytes::from_static(br#"{"ok":true}"#);

    finalize_synthetic_response_for_test(&plugins, &mut ctx, &mut status, &mut headers, &mut body)
        .await;

    assert_eq!(status, 403, "the protected header must be refused");
    assert!(
        !header_names_contain(&headers, PROTECTED_HEADER),
        "the refused header must not be resurrected by the rejection rebuild: {headers:?}"
    );
    assert!(
        !header_names_contain(&headers, "x-pending-secret"),
        "the synthetic representation header must not survive the rejection"
    );
    assert!(
        header_names_contain(&headers, "set-cookie"),
        "one-shot session state must survive the rejection rebuild: {headers:?}"
    );
}

/// The same late rename on the ORDINARY backend lifecycle, where the header
/// rules run inside the `after_proxy` chain. `run_after_proxy_hooks` is the one
/// funnel H1/H2, native gRPC, gRPC-Web, and both H3 paths share, and it covers
/// streaming responses too.
#[tokio::test]
async fn late_header_rename_cannot_bypass_waf_on_backend_response() {
    let plugins = vec![
        waf_blocking_protected_header("CUSTOM-RESP-HEADER-BACKEND"),
        response_transformer_renaming_header(),
    ];
    let mut ctx = ctx_for("GET", "/orders");
    let mut headers = json_headers();
    headers.insert("x-pending-secret".to_string(), "value".to_string());

    let reject = run_after_proxy_hooks_reject_for_test(&plugins, &mut ctx, 200, &mut headers)
        .await
        .expect("the late rename must be refused by the final header phase");

    assert_eq!(reject.0, 403);
    assert!(
        !header_names_contain(&reject.2, PROTECTED_HEADER),
        "the refused header must not survive onto the rejection: {:?}",
        reject.2
    );
}

/// Both shared funnels must reach the same conclusion for the same chain — the
/// ordering contract is a property of the pipeline, not of one lifecycle.
#[tokio::test]
async fn backend_and_synthetic_funnels_agree_on_late_header_rename() {
    let plugins = vec![
        waf_blocking_protected_header("CUSTOM-RESP-HEADER-PARITY"),
        response_transformer_renaming_header(),
    ];

    let mut backend_ctx = ctx_for("GET", "/orders");
    let mut backend_headers = json_headers();
    backend_headers.insert("x-pending-secret".to_string(), "value".to_string());
    let backend = run_after_proxy_hooks_reject_for_test(
        &plugins,
        &mut backend_ctx,
        200,
        &mut backend_headers,
    )
    .await
    .expect("backend lifecycle must refuse");

    let mut synthetic_ctx = ctx_for("GET", "/cache-hit");
    let mut synthetic_status = 200u16;
    let mut synthetic_headers = json_headers();
    synthetic_headers.insert("x-pending-secret".to_string(), "value".to_string());
    let mut synthetic_body = bytes::Bytes::from_static(br#"{"ok":true}"#);
    finalize_synthetic_response_for_test(
        &plugins,
        &mut synthetic_ctx,
        &mut synthetic_status,
        &mut synthetic_headers,
        &mut synthetic_body,
    )
    .await;

    assert_eq!(backend.0, synthetic_status);
    assert!(!header_names_contain(&backend.2, PROTECTED_HEADER));
    assert!(!header_names_contain(&synthetic_headers, PROTECTED_HEADER));
}

/// A chain whose late rules touch nothing protected must be untouched: the phase
/// is gated on the header map actually having changed into a refused shape.
#[tokio::test]
async fn unrelated_late_header_rules_do_not_reject() {
    let plugins = vec![
        waf_blocking_protected_header("CUSTOM-RESP-HEADER-BENIGN"),
        Arc::new(
            ResponseTransformer::new(&json!({
                "rules": [
                    {"operation": "add", "target": "header",
                     "key": "x-benign", "value": "1"}
                ]
            }))
            .expect("benign response_transformer config"),
        ) as Arc<dyn Plugin>,
    ];
    let mut ctx = ctx_for("GET", "/orders");
    let mut headers = json_headers();

    let reject = run_after_proxy_hooks_reject_for_test(&plugins, &mut ctx, 200, &mut headers).await;

    assert!(reject.is_none(), "a benign header add must not be refused");
    assert!(header_names_contain(&headers, "x-benign"));
}

// ───────────────────── 3. transport encoding runs last ─────────────────────

/// Gateway compression is deferred behind every semantic transform AND behind
/// the final body policy phase: the WAF must match the plaintext, not gzip
/// octets (`GHSA-4vqr-427g-5cg7`).
#[tokio::test]
async fn gateway_compression_runs_after_final_body_policy() {
    let plugins = vec![waf_blocking_response_body(), compression_plugin()];
    let mut ctx = ctx_for("GET", "/orders");
    ctx.headers
        .insert("accept-encoding".to_string(), "gzip".to_string());

    let payload = format!(r#"{{"note":"padding padding padding {BLOCKED_TOKEN} padding"}}"#);
    let mut headers = json_headers();
    headers.insert("content-length".to_string(), payload.len().to_string());
    run_request_and_response_header_hooks(&plugins, &mut ctx, &mut headers).await;
    let (replaced, status, headers_out, body) =
        run_buffered_transform(&plugins, &mut ctx, 200, headers, payload.into_bytes()).await;

    assert!(replaced, "the plaintext scan must have refused this body");
    assert_eq!(status, 403);
    assert!(
        !header_names_contain(&headers_out, "content-encoding"),
        "a refused response must not ship a gateway content coding: {headers_out:?}"
    );
    assert!(!String::from_utf8_lossy(&body).contains(BLOCKED_TOKEN));
}

/// The passing half of the same contract: validators see plaintext while the
/// published wire bytes are still correctly encoded.
#[tokio::test]
async fn gateway_compression_still_encodes_an_admitted_response() {
    let plugins = vec![waf_blocking_response_body(), compression_plugin()];
    let mut ctx = ctx_for("GET", "/orders");
    ctx.headers
        .insert("accept-encoding".to_string(), "gzip".to_string());

    let payload = r#"{"note":"padding padding padding padding padding padding"}"#;
    let mut headers = json_headers();
    headers.insert("content-length".to_string(), payload.len().to_string());
    run_request_and_response_header_hooks(&plugins, &mut ctx, &mut headers).await;
    let body_in = payload.as_bytes().to_vec();
    let (replaced, status, headers_out, body) =
        run_buffered_transform(&plugins, &mut ctx, 200, headers, body_in).await;

    assert!(!replaced);
    assert_eq!(status, 200);
    assert_eq!(
        headers_out.get("content-encoding").map(String::as_str),
        Some("gzip"),
        "the admitted response must still be transport encoded"
    );
    assert_eq!(
        gunzip(&body),
        payload.as_bytes(),
        "the wire body must decode back to the inspected plaintext"
    );
    assert_eq!(
        headers_out.get("content-length").map(String::as_str),
        Some(body.len().to_string().as_str()),
        "the published length must describe the encoded bytes"
    );
}

// ──────────── 4. origin content codings are decoded or fail closed ────────────

/// An origin gzip response claimed by an enforcing WAF response-body rule is
/// decoded boundedly before the scan, so the rule matches the document.
#[tokio::test]
async fn origin_gzip_response_is_decoded_for_the_waf_scan() {
    let plugins = vec![waf_blocking_response_body()];
    let mut ctx = ctx_for("GET", "/orders");
    let payload = format!(r#"{{"note":"{BLOCKED_TOKEN}"}}"#);
    let encoded = gzip(payload.as_bytes());
    let mut headers = json_headers();
    headers.insert("content-encoding".to_string(), "gzip".to_string());
    stamp_original_response_metadata_for_test(&mut ctx, 200, &headers);

    let (replaced, status, _headers, body) =
        run_buffered_transform(&plugins, &mut ctx, 200, headers, encoded).await;

    assert!(
        replaced,
        "a compressed body carrying the blocked token must be refused"
    );
    assert_eq!(status, 403);
    assert!(!String::from_utf8_lossy(&body).contains(BLOCKED_TOKEN));
}

/// An unsupported origin coding on a claimed response can never be reduced to
/// plaintext, so it fails closed rather than passing through unscanned.
#[tokio::test]
async fn unsupported_origin_coding_fails_closed_for_a_claiming_policy() {
    let plugins = vec![waf_blocking_response_body()];
    let mut ctx = ctx_for("GET", "/orders");
    let mut headers = json_headers();
    headers.insert("content-encoding".to_string(), "compress".to_string());
    // The pristine origin stamp is what the gate reads; force it so the
    // unsupported coding is judged as the ORIGIN's, not a gateway coding.
    stamp_original_response_metadata_for_test(&mut ctx, 200, &headers);
    set_original_response_content_encoding_for_test(&mut ctx, "compress");

    let opaque = b"\x00\x01opaque".to_vec();
    let (replaced, status, _headers, body) =
        run_buffered_transform(&plugins, &mut ctx, 200, headers, opaque.clone()).await;

    assert!(replaced, "an uninspectable representation must be replaced");
    assert_ne!(status, 200);
    assert_ne!(
        body, opaque,
        "the unscanned octets must not reach the client"
    );
}

// ──────────────────── 5. sibling instances stay independent ────────────────────

/// Two `waf` instances keep independent header-scan state. The one configured
/// against an unrelated header must not consume the digest marker — or the
/// decision — of the one that actually protects the header.
#[tokio::test]
async fn sibling_waf_instances_do_not_suppress_each_other() {
    for order in 0..2 {
        let protecting = waf_blocking_protected_header("CUSTOM-RESP-HEADER-SIBLING");
        let unrelated = waf_blocking_unrelated_header("CUSTOM-RESP-HEADER-SIBLING-OTHER");
        let mut plugins: Vec<Arc<dyn Plugin>> = if order == 0 {
            vec![protecting, unrelated]
        } else {
            vec![unrelated, protecting]
        };
        plugins.push(response_transformer_renaming_header());

        let mut ctx = ctx_for("GET", "/orders");
        let mut headers = json_headers();
        headers.insert("x-pending-secret".to_string(), "value".to_string());

        let reject = run_after_proxy_hooks_reject_for_test(&plugins, &mut ctx, 200, &mut headers)
            .await
            .unwrap_or_else(|| {
                panic!("sibling order {order}: the protected header must still be refused")
            });

        assert_eq!(reject.0, 403);
        assert!(!header_names_contain(&reject.2, PROTECTED_HEADER));
    }
}

/// A sibling that scanned an identical map must not stop the other from
/// rescanning a map that CHANGED. The digest is per instance, and the two
/// instances observe different points in the chain.
#[tokio::test]
async fn sibling_instances_recheck_independently_after_a_change() {
    let plugins = vec![
        waf_blocking_unrelated_header("CUSTOM-RESP-HEADER-A"),
        waf_blocking_protected_header("CUSTOM-RESP-HEADER-B"),
        response_transformer_renaming_header(),
    ];
    let mut ctx = ctx_for("GET", "/orders");
    let mut headers = json_headers();
    headers.insert("x-pending-secret".to_string(), "value".to_string());

    let reject = run_after_proxy_hooks_reject_for_test(&plugins, &mut ctx, 200, &mut headers)
        .await
        .expect("the second instance must recheck the changed map");

    assert_eq!(reject.0, 403);
}
