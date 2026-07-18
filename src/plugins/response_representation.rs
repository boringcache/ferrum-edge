//! Shared buffered-response representation gate.
//!
//! One decision, made identically on every path that can publish a buffered
//! response body (H1/H2, native H3, both H3 cross-protocol bridges, the
//! synthetic/replay short-circuit, and provider/protocol normalization), for
//! the question: *may a configured response body policy claim to have been
//! enforced over these bytes?*
//!
//! # Why this exists
//!
//! A body-rewriting policy such as `response_transformer`'s `body_rules` is a
//! security control when it is configured to strip fields from a response. The
//! transform hook is allowed to return `None` for perfectly ordinary reasons
//! ("no configured rule matched this document"), and the lifecycle reads that
//! as "nothing to do, forward the original bytes". That conflation is the
//! bypass this module closes: a representation the transformer *cannot inspect*
//! — a `gzip`/`br`-encoded body, a `206` range slice, a `226` delta, or a byte
//! string that is not a parseable document — also produces `None`, and the
//! protected bytes were forwarded unchanged while the operator believed the
//! policy applied.
//!
//! # Posture
//!
//! There is exactly one posture, and it is fail-closed:
//!
//! * If **no** configured body policy claims this response, nothing changes.
//!   Ordinary unprotected traffic (range requests for media, encoded assets,
//!   non-JSON payloads) is forwarded exactly as before. A protective gate that
//!   turned every `206` into an error would be a worse defect than the bypass.
//! * If a body policy **does** claim this response, the representation must be
//!   inspectable. Supported content codings are decoded in a bounded
//!   pre-transform phase; anything that cannot be reduced to one complete,
//!   parseable document is **rejected**, never forwarded.
//!
//! Rejection — not relabeling — is the answer for partial and delta
//! representations. The gateway does not fetch the remaining ranges or apply
//! the delta, so it cannot produce the complete resource; presenting a rewritten
//! fragment as a `200 OK` complete representation would misrepresent (and let
//! downstream caches store) a truncated resource under the full resource's
//! identity. See [`RepresentationRejection::PartialRepresentation`].
//!
//! # Pristine origin state
//!
//! Encoding and range/delta state are read from the pre-`after_proxy` snapshot
//! stamped by [`crate::proxy::stamp_original_response_metadata`], never from the
//! live header map. By the time buffered body transforms run, `after_proxy`
//! hooks have already mutated the headers: a header-only `response_transformer`
//! rule can remove `Content-Encoding`, and `compression` legitimately *adds* a
//! `Content-Encoding` describing bytes it has not produced yet. Trusting the
//! live map would let the first case hide an encoded body from the gate and the
//! second case send still-plaintext bytes to a decoder. For a backend response
//! the snapshot is mandatory: an unstamped backend response cannot prove its own
//! representation and is rejected rather than assumed benign.
//!
//! # Known limits
//!
//! This gate governs the **buffered** response lifecycle. Three gaps are known
//! and deliberately out of its scope; none is introduced here, and each needs a
//! separate design rather than a widening of this module:
//!
//! * **Streaming responses.** A response that never buffers never reaches a body
//!   transform, so no body policy applies to it. `response_transformer` declines
//!   to buffer when the *client* sent `Accept: text/event-stream`, which means a
//!   client can currently keep a configured body policy from running by asking
//!   for SSE on a route that answers with ordinary JSON. Closing that requires
//!   deciding on the response media type instead of the request's, plus a
//!   streaming-side enforcement point — tracked separately.
//! * **Backend-chosen media type.** A backend that labels a JSON payload
//!   `text/plain`, `application/octet-stream`, or omits `Content-Type` is not
//!   claimed by a JSON body policy, here or in the transform itself. Content-type
//!   sniffing or an operator-configured media-type allowlist would be needed.
//! * **Trailing bytes after a gzip member.** Decoding uses `MultiGzDecoder`, for
//!   consistency with the bounded decoders in `ai_tool_governor` and
//!   `ai_semantic_firewall`. It is stricter than browsers about padding after the
//!   final member, so such a body is rejected rather than decoded.

use std::collections::HashMap;
use std::io::Read;
use std::sync::Arc;

use super::Plugin;
use super::RequestContext;
use super::utils::body_transform::is_json_content_type;

/// Hard ceiling on the decoded size of one buffered response body inspected on
/// behalf of a configured body policy.
///
/// Bounds decompression amplification: a few kilobytes of `gzip` or `br` can
/// expand to gigabytes, so the decoder is capped and a body that exceeds the
/// cap is rejected rather than materialized. Matches the ceiling
/// `ai_semantic_firewall` already applies to response inspection so a single
/// response cannot be inspectable to one guardrail and uninspectable to another.
pub(crate) const MAX_DECODED_RESPONSE_INSPECTION_BYTES: usize = 10 * 1024 * 1024;

/// Maximum number of stacked content codings decoded for one response.
///
/// `Content-Encoding` may list several codings applied in order. Each one is a
/// separate bounded decode pass, so an unbounded list is itself an amplification
/// vector; a legitimate origin does not stack more than a couple.
pub(crate) const MAX_STACKED_RESPONSE_CODINGS: usize = 4;

/// Where the buffered bytes under inspection came from.
///
/// This is passed explicitly by each call site rather than sniffed from context
/// metadata so that adding a new publication path is a compile-time decision
/// about which provenance rules apply, not a silent default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RepresentationOrigin {
    /// A real backend response. The pre-`after_proxy` snapshot is authoritative
    /// and its absence is itself a failure to prove the representation.
    Backend,
    /// Bytes the gateway itself produced (plugin short-circuit, mock, semantic
    /// cache hit, serverless terminate, dedup replay). There is no upstream
    /// representation to hide, so live headers are the only description of these
    /// bytes and are read directly.
    GatewayGenerated,
}

/// Why a protected representation could not be inspected.
///
/// Every variant means the same thing operationally: the configured body policy
/// could not be applied, so the response must not be served.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RepresentationRejection {
    /// A content coding the gateway cannot decode (`zstd`, `deflate`, a private
    /// coding). Declining to decode is not permission to forward.
    UnsupportedCoding,
    /// A supported coding whose stream is malformed or truncated.
    MalformedCoding,
    /// Decoded output exceeded [`MAX_DECODED_RESPONSE_INSPECTION_BYTES`], or the
    /// coding list exceeded [`MAX_STACKED_RESPONSE_CODINGS`].
    DecodedBodyTooLarge,
    /// A `206` range slice or `226` delta: only a fragment of the resource. The
    /// gateway cannot reconstruct the complete representation, and must not
    /// present the fragment as one.
    PartialRepresentation,
    /// The bytes are not a complete parseable document of the media type the
    /// policy operates on, so no field-level rule can be proven to have applied.
    UnparseableDocument,
    /// A backend response reached the body phase without a pre-`after_proxy`
    /// snapshot, so its original encoding and range state cannot be proven.
    UnprovenOriginState,
}

impl RepresentationRejection {
    /// Stable, low-cardinality label for logs and transaction metadata.
    ///
    /// Deliberately describes the representation only — it never carries body
    /// bytes, header values, or decoded content.
    pub(crate) fn reason(self) -> &'static str {
        match self {
            Self::UnsupportedCoding => "unsupported_content_coding",
            Self::MalformedCoding => "malformed_content_coding",
            Self::DecodedBodyTooLarge => "decoded_body_too_large",
            Self::PartialRepresentation => "partial_representation",
            Self::UnparseableDocument => "unparseable_document",
            Self::UnprovenOriginState => "unproven_origin_state",
        }
    }
}

/// The single shared decision for one buffered response.
pub(crate) enum ResponseBodyPolicyPosture {
    /// No configured body policy claims these bytes. The lifecycle keeps its
    /// pre-existing behavior, including leaving `206`/`226` bodies untouched.
    Unprotected,
    /// A body policy claims these bytes and they are inspectable. When
    /// `decoded` is `Some`, the caller must install those identity-coded bytes
    /// (and drop the stale `Content-Encoding`) before running transforms, so
    /// every transform sees the representation the policy was evaluated against.
    Enforce { decoded: Option<Vec<u8>> },
    /// A body policy claims these bytes and they are not inspectable. The caller
    /// must replace the response; forwarding the original bytes is the bypass.
    Reject(RepresentationRejection),
}

/// Whether any active plugin's configured body policy claims this response.
fn body_policy_claimed(
    plugins: &[Arc<dyn Plugin>],
    ctx: &RequestContext,
    content_type: Option<&str>,
) -> bool {
    plugins
        .iter()
        .any(|plugin| plugin.enforces_response_body_policy(ctx, content_type))
}

/// The origin's non-identity `Content-Encoding`, from the pristine snapshot for
/// a backend response and from the live map for gateway-generated bytes.
fn origin_content_encoding<'a>(
    ctx: &'a RequestContext,
    origin: RepresentationOrigin,
    response_headers: &'a HashMap<String, String>,
) -> Option<&'a str> {
    match origin {
        RepresentationOrigin::Backend => ctx
            .metadata
            .get(crate::proxy::ORIGIN_ENCODED_RESPONSE_METADATA_KEY)
            .map(String::as_str),
        RepresentationOrigin::GatewayGenerated => response_headers
            .get("content-encoding")
            .map(String::as_str)
            .filter(|encoding| {
                encoding
                    .split(',')
                    .map(str::trim)
                    .any(|token| !token.is_empty() && !token.eq_ignore_ascii_case("identity"))
            }),
    }
}

/// Whether these bytes are a range slice or a delta rather than a complete
/// representation.
///
/// The live status is consulted in addition to the snapshot: over-detecting a
/// fragment is safe (it rejects), while under-detecting is the bypass.
fn is_partial_representation(
    ctx: &RequestContext,
    origin: RepresentationOrigin,
    response_status: u16,
    response_headers: &HashMap<String, String>,
) -> bool {
    if matches!(response_status, 206 | 226) {
        return true;
    }
    match origin {
        RepresentationOrigin::Backend => {
            ctx.metadata
                .contains_key(crate::proxy::RANGE_RESPONSE_METADATA_KEY)
                || ctx
                    .metadata
                    .contains_key(crate::proxy::ORIGIN_DELTA_RESPONSE_METADATA_KEY)
        }
        RepresentationOrigin::GatewayGenerated => {
            response_headers.contains_key("content-range") || response_headers.contains_key("im")
        }
    }
}

/// Decode one supported content coding, bounded by `limit`.
///
/// Reads one byte past the limit so an output that lands exactly on the ceiling
/// is distinguishable from one that was truncated by it.
fn decode_one_coding(
    coding: &str,
    data: &[u8],
    limit: usize,
) -> Result<Vec<u8>, RepresentationRejection> {
    let mut out = Vec::new();
    let take = limit as u64 + 1;
    match coding {
        "gzip" | "x-gzip" => {
            let mut reader = flate2::read::MultiGzDecoder::new(data).take(take);
            reader
                .read_to_end(&mut out)
                .map_err(|_| RepresentationRejection::MalformedCoding)?;
        }
        "br" => {
            let mut reader = brotli::Decompressor::new(data, 4096).take(take);
            reader
                .read_to_end(&mut out)
                .map_err(|_| RepresentationRejection::MalformedCoding)?;
        }
        _ => return Err(RepresentationRejection::UnsupportedCoding),
    }
    if out.len() > limit {
        return Err(RepresentationRejection::DecodedBodyTooLarge);
    }
    Ok(out)
}

/// Decode a possibly stacked `Content-Encoding` down to identity bytes.
///
/// `Content-Encoding` lists codings in the order they were applied, so they are
/// undone in reverse. `identity` tokens are skipped; an empty or whitespace-only
/// token is malformed rather than absent, and is rejected — a present-but-empty
/// coding cannot be proven to describe identity-coded bytes.
fn decode_response_body(encoding: &str, body: &[u8]) -> Result<Vec<u8>, RepresentationRejection> {
    let codings: Vec<&str> = encoding
        .split(',')
        .map(str::trim)
        .filter(|token| !token.eq_ignore_ascii_case("identity"))
        .collect();
    if codings.is_empty() {
        return Ok(body.to_vec());
    }
    if codings.len() > MAX_STACKED_RESPONSE_CODINGS {
        return Err(RepresentationRejection::DecodedBodyTooLarge);
    }
    if codings.iter().any(|token| token.is_empty()) {
        return Err(RepresentationRejection::MalformedCoding);
    }

    let mut current = body.to_vec();
    for coding in codings.into_iter().rev() {
        let lowered = coding.to_ascii_lowercase();
        current = decode_one_coding(&lowered, &current, MAX_DECODED_RESPONSE_INSPECTION_BYTES)?;
    }
    Ok(current)
}

/// Whether the decoded bytes are a complete parseable document that a
/// field-level body rule can act on.
///
/// Only JSON is checked, because JSON is the document model every configured
/// body rule in the gateway operates on. A policy that declines on media type
/// never claims the response in the first place, so it never reaches here.
///
/// This parses **exactly** the way the enforcer does — `serde_json::from_slice`
/// over the same bytes, with no normalization. That symmetry is load-bearing: if
/// the gate were more lenient than [`crate::plugins::utils::body_transform::apply_body_rules`]
/// (say, by stripping a UTF-8 BOM the enforcer chokes on), a body could pass the
/// gate, fail to parse inside the transform, return `None`, and be forwarded
/// unredacted — which is precisely the `None`-conflation bypass this module
/// exists to close. A BOM-prefixed body is therefore rejected rather than
/// accommodated; RFC 8259 forbids emitting one, and fail-closed is the posture.
fn document_is_parseable(content_type: Option<&str>, body: &[u8]) -> bool {
    if content_type.is_some_and(|value| !is_json_content_type(value)) {
        return true;
    }
    serde_json::from_slice::<serde_json::Value>(body).is_ok()
}

/// Evaluate the shared representation gate for one buffered response.
///
/// Every buffered publication path calls exactly this function, so a frontend
/// protocol, a bridge, or a synthetic short-circuit cannot reach a different
/// conclusion about the same bytes and the same configuration.
pub(crate) fn evaluate_response_body_policy_posture(
    plugins: &[Arc<dyn Plugin>],
    ctx: &RequestContext,
    origin: RepresentationOrigin,
    response_status: u16,
    response_headers: &HashMap<String, String>,
    response_body: &[u8],
) -> ResponseBodyPolicyPosture {
    let content_type = response_headers.get("content-type").map(String::as_str);
    if !body_policy_claimed(plugins, ctx, content_type) {
        return ResponseBodyPolicyPosture::Unprotected;
    }
    // An absent body carries nothing the policy could redact, and rejecting
    // empty 200s would break ordinary traffic without protecting anything.
    if response_body.is_empty() {
        return ResponseBodyPolicyPosture::Unprotected;
    }

    if origin == RepresentationOrigin::Backend
        && !ctx
            .metadata
            .contains_key(crate::proxy::ORIGINAL_RESPONSE_METADATA_STAMPED_KEY)
    {
        return ResponseBodyPolicyPosture::Reject(RepresentationRejection::UnprovenOriginState);
    }

    if is_partial_representation(ctx, origin, response_status, response_headers) {
        return ResponseBodyPolicyPosture::Reject(RepresentationRejection::PartialRepresentation);
    }

    let decoded = match origin_content_encoding(ctx, origin, response_headers) {
        None => None,
        Some(encoding) => match decode_response_body(encoding, response_body) {
            Ok(decoded) => Some(decoded),
            Err(rejection) => return ResponseBodyPolicyPosture::Reject(rejection),
        },
    };

    let inspected = decoded.as_deref().unwrap_or(response_body);
    if !document_is_parseable(content_type, inspected) {
        return ResponseBodyPolicyPosture::Reject(RepresentationRejection::UnparseableDocument);
    }

    ResponseBodyPolicyPosture::Enforce { decoded }
}

/// Install decoded identity-coded bytes ahead of the transform phase.
///
/// The stale `Content-Encoding` is dropped and `Content-Length` recomputed so
/// the bytes every subsequent transform sees are exactly the bytes the gate
/// proved inspectable. The pristine origin-encoding marker is cleared for the
/// same reason: a later reader must not conclude these bytes are still encoded.
pub(crate) fn install_decoded_response_body(
    ctx: &mut RequestContext,
    response_headers: &mut HashMap<String, String>,
    response_body: &mut Vec<u8>,
    decoded: Vec<u8>,
) {
    *response_body = decoded;
    response_headers.retain(|name, _| !name.eq_ignore_ascii_case("content-encoding"));
    let length = response_body.len().to_string();
    response_headers.insert("content-length".to_string(), length);
    ctx.metadata
        .remove(crate::proxy::ORIGIN_ENCODED_RESPONSE_METADATA_KEY);
}
