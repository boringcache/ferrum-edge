//! Shared backend-visible request representation gate.
//!
//! One decision, made identically on every path that can finalize a buffered
//! request body (H1/H2, buffered gRPC, native H3, the H3 cross-protocol bridge,
//! and the terminal-preparation ladders), for the question: *may a configured
//! final request-body policy claim to have been enforced over these bytes?*
//!
//! # Why this exists
//!
//! `waf` and `body_validator` decide in `on_final_request_body`, over the exact
//! bytes the backend will receive. That is the right phase, but it is not by
//! itself an inspection guarantee: when the client declared a
//! `Content-Encoding`, those bytes are a compressed representation of the
//! document the policy is configured about. Scanning them finds no signature and
//! parses no schema, and both plugins previously returned `Continue` — while a
//! backend or framework middleware that honors the coding decodes and executes
//! the hidden payload (`GHSA-3973-47g5-4mcx`).
//!
//! The gateway does have a decoder, but it belongs to the optional `compression`
//! plugin and only runs when an operator separately configured it with
//! `decompress_request: true`. An enforcing security policy must not silently
//! depend on that composition, so the plaintext view is established HERE, by the
//! proxy, for every governed request.
//!
//! # Posture
//!
//! There is exactly one posture, and it is fail-closed:
//!
//! * If **no** configured final request-body policy claims this request, nothing
//!   changes. Ordinary encoded uploads keep flowing to backends that understand
//!   them, exactly as before.
//! * If a policy **does** claim it, the representation must be inspectable. The
//!   ordered `#content-coding` list is parsed, each supported coding is
//!   boundedly decoded in reverse application order, and anything that cannot be
//!   reduced to one complete plaintext document — an unsupported coding, a
//!   malformed or truncated stream, too many stacked layers, an over-limit or
//!   over-amplified decode — is **rejected** with a fixed `400`, never forwarded.
//!
//! # What is and is not rewritten
//!
//! Unlike the response gate, this one never installs the decoded bytes as the
//! forwarded representation. The backend negotiated (or at least accepted) the
//! coding the client sent, and `Content-Encoding` / `Content-Length` /
//! `Content-Digest` describe those exact octets; silently swapping in plaintext
//! would change the backend-visible request in a way no plugin asked for and
//! would break request signing. The plaintext is instead staged on the request
//! context as an INSPECTION view that the claiming policy hooks read through
//! [`crate::plugins::RequestContext::inspectable_final_request_body`].
//!
//! When `compression` IS configured with request decompression, it already
//! rewrote the body and stripped `Content-Encoding` during the pre-`before_proxy`
//! normalization phase, so this gate sees an identity representation and does no
//! work at all. The two are complementary, not redundant.
//!
//! # Bounds
//!
//! Decoding attacker-supplied compressed input is an amplification vector, so
//! every decode is bounded three ways before a single inspection byte exists:
//!
//! * at most [`MAX_STACKED_REQUEST_CODINGS`] coding layers;
//! * at most [`decoded_inspection_limit`] bytes per layer and in aggregate —
//!   the operator's effective request-body ceiling narrowed by this module's
//!   hard cap, so enabling a security policy can never buy a larger buffer than
//!   the deployment already allows;
//! * at most [`MAX_REQUEST_DECODE_AMPLIFICATION_RATIO`]:1 expansion, per layer
//!   and end-to-end.
//!
//! All three are enforced inside the shared
//! [`crate::plugins::utils::content_encoding`] decoder, which is the same parser
//! and the same codec-strictness `compression`, `openapi_validator`, and
//! `ai_token_metrics` already use — so one request cannot be inspectable to one
//! plugin and opaque to another.

use std::collections::HashMap;
use std::sync::Arc;

use super::Plugin;
use super::RequestContext;
use super::utils::content_encoding::{DecodeLimits, decode_content_encoding};

/// Hard ceiling on the plaintext produced for one governed request body.
///
/// Matches [`crate::plugins::response_representation::MAX_DECODED_RESPONSE_INSPECTION_BYTES`]
/// so a deployment's two inspection directions are bounded alike.
pub(crate) const MAX_DECODED_REQUEST_INSPECTION_BYTES: usize = 10 * 1024 * 1024;

/// Maximum number of stacked request content codings decoded for one request.
///
/// `Content-Encoding` may list several codings applied in order. Each one is a
/// separate bounded decode pass, so an unbounded list is itself an amplification
/// vector; a legitimate client does not stack more than a couple.
pub(crate) const MAX_STACKED_REQUEST_CODINGS: usize = 4;

/// Maximum decoded-to-raw expansion admitted per layer and end-to-end.
///
/// The same ratio `compression`'s opt-in request decompression enforces, so a
/// zip bomb is refused identically whether or not that plugin is configured.
pub(crate) const MAX_REQUEST_DECODE_AMPLIFICATION_RATIO: u32 = 1024;

/// The effective decode ceiling for this request.
///
/// This module's hard cap, narrowed by any active route request-body ceiling so
/// a governed decode cannot materialize more plaintext than a route-scoped
/// `request_size_limiting` policy would have admitted as a body
/// (`GHSA-xrfj-852f-645j`). `0` is the project-wide "unlimited" spelling and
/// leaves the hard cap in force.
///
/// The global `FERRUM_MAX_REQUEST_BODY_SIZE_BYTES` is deliberately not consulted
/// here: it already bounded the ENCODED bytes at collection time, and it is the
/// wire-transfer bound rather than an inspection bound. The hard cap is what
/// bounds amplification, together with
/// [`MAX_REQUEST_DECODE_AMPLIFICATION_RATIO`].
fn decoded_inspection_limit(ctx: &RequestContext) -> usize {
    match ctx.route_request_body_limit() {
        Some(limit) if limit > 0 => limit.min(MAX_DECODED_REQUEST_INSPECTION_BYTES),
        _ => MAX_DECODED_REQUEST_INSPECTION_BYTES,
    }
}

/// Why a governed request representation could not be inspected.
///
/// Every variant means the same thing operationally: the configured final
/// request-body policy could not be applied, so the request must not be
/// forwarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RequestRepresentationRejection {
    /// A content coding the gateway cannot decode (`zstd`, `deflate`, a private
    /// coding). Declining to decode is not permission to forward.
    UnsupportedCoding,
    /// The field is not a well-formed `#content-coding` list: an empty member, a
    /// parameterized member, a non-token member, or `identity` combined with a
    /// transforming coding.
    MalformedCoding,
    /// More stacked codings than [`MAX_STACKED_REQUEST_CODINGS`].
    TooManyCodings,
    /// A supported, well-formed coding list whose stream could not be reduced to
    /// plaintext under the bounds: truncated, corrupt, trailing/concatenated
    /// data, over the byte ceiling, or over the amplification ratio.
    UndecodableCoding,
}

impl RequestRepresentationRejection {
    /// Stable, low-cardinality label for logs and transaction metadata.
    ///
    /// Deliberately describes the representation only — it never carries body
    /// bytes, header values, or decoded content.
    pub(crate) fn reason(self) -> &'static str {
        match self {
            Self::UnsupportedCoding => "unsupported_content_coding",
            Self::MalformedCoding => "malformed_content_coding",
            Self::TooManyCodings => "too_many_content_codings",
            Self::UndecodableCoding => "undecodable_content_coding",
        }
    }
}

/// The single shared decision for one finalized request body.
pub(crate) enum FinalRequestBodyPosture {
    /// No configured final request-body policy claims these bytes, or they are
    /// already the plaintext the policy will inspect. Nothing is staged.
    Inspectable,
    /// A policy claims these bytes and the complete ordered coding chain was
    /// decoded. The caller stages this plaintext as the inspection view.
    Decoded(Vec<u8>),
    /// A policy claims these bytes and they cannot be reduced to plaintext.
    /// The caller must reject; forwarding the encoded body is the bypass.
    Reject(RequestRepresentationRejection),
}

/// Fixed client-visible message for a rejected governed request representation.
///
/// Fixed-cardinality on purpose: it never echoes the offending coding token, a
/// header value, or any body byte (`GHSA-5p2h-fq6q-gwh9`).
pub(crate) const REQUEST_REPRESENTATION_UNINSPECTABLE_MESSAGE: &str =
    "Malformed or unsupported Content-Encoding";

/// `ctx.metadata` key recording why a governed request representation was
/// refused. The value is one of [`RequestRepresentationRejection::reason`].
pub(crate) const REQUEST_REPRESENTATION_REJECTED_METADATA_KEY: &str =
    "ferrum:request_representation_rejected";

/// Whether any active plugin's configured final request-body policy claims this
/// request's backend-visible bytes.
fn final_request_body_policy_claimed(
    plugins: &[Arc<dyn Plugin>],
    ctx: &RequestContext,
    headers: &HashMap<String, String>,
    body: &[u8],
) -> bool {
    plugins
        .iter()
        .any(|plugin| plugin.enforces_final_request_body_policy(ctx, headers, body))
}

/// Whether a `Content-Encoding` field value must be decoded before a governed
/// policy may claim to have inspected the body.
///
/// True for anything that is not a list of pure `identity` tokens — which
/// includes both a real coding (`gzip`) and a MALFORMED one (`,`, `identity,`, a
/// whitespace-only field). The empty-token case is why the test is "not provably
/// identity" rather than "names a transforming coding": an empty token changes
/// no octets, but it is also not provably `identity`, so a governed request
/// carrying one must reach the fail-closed malformed rejection instead of being
/// silently scanned as though the field were absent.
fn requires_decode_judgment(encoding: &str) -> bool {
    !encoding
        .split(',')
        .map(str::trim)
        .all(|token| token.eq_ignore_ascii_case("identity"))
}

/// True when a `Content-Encoding` member is an HTTP `token` (RFC 9110 §5.6.2).
fn is_http_token(value: &str) -> bool {
    !value.is_empty()
        && value.is_ascii()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

/// Classify the coding list before any decoding work happens.
///
/// The shared decoder reports every failure as one opaque string, and this gate
/// needs a low-cardinality, non-echoing REASON for operators. Classifying the
/// grammar here — rather than pattern-matching the decoder's message — keeps the
/// reason stable across decoder changes and keeps hostile tokens out of it.
///
/// The rules deliberately mirror [`super::utils::content_encoding::parse_content_codings`]
/// exactly, so a list this function admits is a list the decoder will parse.
fn classify_codings(encoding: &str) -> Result<(), RequestRepresentationRejection> {
    let mut count = 0usize;
    let mut has_identity = false;
    let mut has_transforming = false;
    for raw in encoding.split(',') {
        let coding = raw.trim();
        if coding.is_empty() || coding.contains(';') || !is_http_token(coding) {
            return Err(RequestRepresentationRejection::MalformedCoding);
        }
        count += 1;
        match coding.to_ascii_lowercase().as_str() {
            "gzip" | "x-gzip" | "br" => has_transforming = true,
            "identity" => has_identity = true,
            _ => return Err(RequestRepresentationRejection::UnsupportedCoding),
        }
    }
    if count == 0 {
        return Err(RequestRepresentationRejection::MalformedCoding);
    }
    if count > MAX_STACKED_REQUEST_CODINGS {
        return Err(RequestRepresentationRejection::TooManyCodings);
    }
    if has_identity && has_transforming {
        return Err(RequestRepresentationRejection::MalformedCoding);
    }
    Ok(())
}

/// Evaluate the shared request representation gate for one finalized body.
///
/// Called from [`crate::proxy::run_final_request_body_hooks_with_provenance`],
/// the single funnel every dispatch ladder uses, so a frontend protocol cannot
/// reach a different conclusion about the same bytes and the same configuration.
pub(crate) fn evaluate_final_request_body_posture(
    plugins: &[Arc<dyn Plugin>],
    ctx: &RequestContext,
    headers: &HashMap<String, String>,
    body: &[u8],
) -> FinalRequestBodyPosture {
    let Some(encoding) = headers
        .get("content-encoding")
        .map(String::as_str)
        .filter(|encoding| requires_decode_judgment(encoding))
    else {
        // The backend-visible representation is already identity-coded, so the
        // bytes the hooks receive ARE the plaintext. No claim question and no
        // decode: this is the ordinary path, including every request whose
        // encoding a configured `compression` instance already normalized away.
        return FinalRequestBodyPosture::Inspectable;
    };

    // Only ask the claim question once a coding is actually present. An
    // unclaimed encoded request keeps its pre-existing behavior — the gateway
    // does not start rejecting ordinary compressed uploads because a security
    // plugin happens to be configured for a different route or media type.
    if !final_request_body_policy_claimed(plugins, ctx, headers, body) {
        return FinalRequestBodyPosture::Inspectable;
    }

    // An empty encoded body carries nothing a policy could match, and a coding
    // header on it is still malformed input rather than a document. Fall through
    // to the decoder, which rejects a zero-length gzip/br stream — the same
    // answer `compression` gives an empty compressed upload.
    if let Err(rejection) = classify_codings(encoding) {
        return FinalRequestBodyPosture::Reject(rejection);
    }

    let limit = decoded_inspection_limit(ctx);
    let limits = DecodeLimits {
        max_decoded_bytes: limit,
        max_cumulative_bytes: limit,
        max_codings: MAX_STACKED_REQUEST_CODINGS,
        max_amplification_ratio: MAX_REQUEST_DECODE_AMPLIFICATION_RATIO,
    };
    match decode_content_encoding(Some(encoding), body, limits) {
        // `classify_codings` already proved this list names a transforming
        // coding, so a borrowed result would mean the decoder disagreed about
        // the grammar. Treat that as uninspectable rather than assuming the
        // wire bytes are plaintext.
        Ok(std::borrow::Cow::Borrowed(_)) => FinalRequestBodyPosture::Reject(
            RequestRepresentationRejection::UndecodableCoding,
        ),
        Ok(std::borrow::Cow::Owned(plaintext)) => FinalRequestBodyPosture::Decoded(plaintext),
        // The decoder's message can echo a hostile coding token, so it is
        // deliberately dropped here: the reason the caller records comes from
        // the fixed classification above.
        Err(_) => {
            FinalRequestBodyPosture::Reject(RequestRepresentationRejection::UndecodableCoding)
        }
    }
}
