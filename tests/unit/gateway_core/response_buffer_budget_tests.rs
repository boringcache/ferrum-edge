//! GHSA-pwcm-6rh8-f2gh — aggregate retained-response budget.
//!
//! The properties under test are the ones a collector-local reservation does
//! NOT give you: that the charge survives a successful return, that it is
//! released when the retained allocation is finally dropped, that a cheap clone
//! shares one charge instead of minting a second, that preallocated capacity is
//! charged before it is allocated, and that an exhaustion refusal is classified
//! as gateway-local transient capacity rather than a backend fault.
//!
//! Every test runs against `ResponseBufferBudgetProbe`, which is the production
//! budget type with its own semaphore — same clamping, same non-blocking
//! admission, same charge attachment — so these cannot pass against a parallel
//! implementation of the rules, and they do not race the process-global budget
//! under a parallel test binary.

use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;

use ferrum_edge::HttpFlavor;
use ferrum_edge::_test_support::{
    BufferedRepresentationOutcome, RESPONSE_BUFFER_OVERLOAD_BODY,
    RESPONSE_BUFFER_OVERLOAD_ERROR_CLASS, RESPONSE_BUFFER_OVERLOAD_GRPC_STATUS,
    RESPONSE_BUFFER_OVERLOAD_STATUS, RESPONSE_BUFFER_RESERVATION_UNIT_BYTES as UNIT,
    ResponseBufferBudgetProbe, error_class_is_backend_failure_for_test,
    error_class_is_health_neutral_for_test, install_response_buffer_capacity_refusal_for_test,
    set_request_http_flavor_for_test, stamp_original_response_metadata_for_test,
};
use ferrum_edge::plugins::{Plugin, RequestContext, response_transformer::ResponseTransformer};
use ferrum_edge::retry::ErrorClass;

/// 8 blocks of budget, with a 1-block fallback ceiling so the floor does not
/// dominate the total.
fn probe(total_blocks: usize) -> ResponseBufferBudgetProbe {
    ResponseBufferBudgetProbe::new(UNIT, total_blocks * UNIT)
}

// ---------------------------------------------------------------------------
// Lifetime: the charge outlives the collector and follows the allocation.
// ---------------------------------------------------------------------------

#[test]
fn a_charge_survives_the_collectors_successful_return() {
    let budget = probe(8);
    let total = budget.available_bytes();

    // Exactly what a collector does: reserve while growing, then publish.
    let body = {
        let mut charge = budget.try_reserve(UNIT).expect("first block admits");
        assert!(budget.grow(&mut charge, 3 * UNIT), "growth admits");
        budget.attach(vec![0u8; 3 * UNIT], charge)
    };

    // The collector frame is gone. If the charge had been a collector local,
    // the budget would be fully available here while 3 blocks stay resident —
    // exactly the bypass this advisory describes.
    assert_eq!(
        budget.available_bytes(),
        total - 3 * UNIT,
        "the retained body must still be charged after collection returned"
    );
    assert_eq!(body.len(), 3 * UNIT);
}

#[test]
fn dropping_the_retained_body_releases_the_charge() {
    let budget = probe(8);
    let total = budget.available_bytes();

    let body = budget
        .charge_retained_body(vec![0u8; 2 * UNIT])
        .expect("admits");
    assert_eq!(budget.available_bytes(), total - 2 * UNIT);

    drop(body);
    assert_eq!(
        budget.available_bytes(),
        total,
        "the budget is returned when the retained allocation is dropped"
    );
}

#[test]
fn cheap_clones_share_exactly_one_charge() {
    let budget = probe(8);
    let total = budget.available_bytes();

    let body = budget
        .charge_retained_body(vec![0u8; 2 * UNIT])
        .expect("admits");
    let charged_once = budget.available_bytes();
    assert_eq!(charged_once, total - 2 * UNIT);

    // A cached entry, a dedup replay, and a concurrent delivery are all clones
    // of one immutable allocation. They must not each mint a permit.
    let cache_entry = body.clone();
    let replay = body.clone();
    let slice = body.slice(0..UNIT);
    assert_eq!(
        budget.available_bytes(),
        charged_once,
        "a cheap clone shares the allocation, so it must share the one charge"
    );

    // ...and the charge is held until the LAST handle goes away.
    drop(body);
    drop(replay);
    drop(slice);
    assert_eq!(budget.available_bytes(), charged_once);
    drop(cache_entry);
    assert_eq!(
        budget.available_bytes(),
        total,
        "the last handle's drop is what returns the budget"
    );
}

#[test]
fn an_abandoned_collection_releases_immediately() {
    let budget = probe(8);
    let total = budget.available_bytes();

    // Retry abandonment / deadline / cancellation all look like this: the
    // reservation is dropped without ever being attached to bytes.
    {
        let mut charge = budget.try_reserve(UNIT).expect("admits");
        assert!(budget.grow(&mut charge, 4 * UNIT));
        assert_eq!(budget.available_bytes(), total - 4 * UNIT);
    }
    assert_eq!(budget.available_bytes(), total);
}

#[test]
fn an_empty_body_retains_nothing_and_holds_no_charge() {
    let budget = probe(4);
    let total = budget.available_bytes();
    let empty = budget.charge_retained_body(Vec::new()).expect("admits");
    assert!(empty.is_empty());
    assert_eq!(
        budget.available_bytes(),
        total,
        "nothing is resident, so nothing stays charged"
    );
}

// ---------------------------------------------------------------------------
// Preallocation: charged before it is allocated.
// ---------------------------------------------------------------------------

#[test]
fn preallocated_capacity_is_charged_before_it_is_allocated() {
    let budget = probe(4);
    let total = budget.available_bytes();

    // A backend that advertises a large `content-length` and then sends no DATA
    // still holds the capacity, so the reservation must precede the allocation.
    let charge = budget.try_reserve(3 * UNIT).expect("prealloc admits");
    assert_eq!(
        budget.available_bytes(),
        total - 3 * UNIT,
        "the preallocation is charged before the first DATA frame"
    );

    // A headers-only / stalled response never grows, and the charge is released
    // when the collector is abandoned.
    drop(charge);
    assert_eq!(budget.available_bytes(), total);
}

#[test]
fn growth_past_the_preallocation_is_charged_as_a_delta_not_twice() {
    let budget = probe(8);
    let total = budget.available_bytes();

    let mut charge = budget.try_reserve(2 * UNIT).expect("prealloc admits");
    assert!(budget.grow(&mut charge, 5 * UNIT), "growth admits");
    assert_eq!(
        budget.available_bytes(),
        total - 5 * UNIT,
        "5 blocks resident must cost 5 blocks, not 2 + 5"
    );

    // A shrinking report never releases mid-collection: the peak stays held.
    assert!(budget.grow(&mut charge, UNIT));
    assert_eq!(budget.available_bytes(), total - 5 * UNIT);
}

#[test]
fn an_unaffordable_preallocation_is_refused_rather_than_rounded_away() {
    let budget = probe(2);
    assert!(
        budget.try_reserve(3 * UNIT).is_none(),
        "reservation rounding must not hide a preallocation the budget cannot cover"
    );
    // ...and the refusal left nothing charged.
    assert_eq!(budget.available_bytes(), 2 * UNIT);
}

// ---------------------------------------------------------------------------
// Admission: non-blocking, exhaustion is refusal (never a queue).
// ---------------------------------------------------------------------------

#[test]
fn exhaustion_refuses_instead_of_queueing_and_recovers_on_release() {
    let budget = probe(4);

    let first = budget
        .charge_retained_body(vec![0u8; 4 * UNIT])
        .expect("the whole budget admits one response");
    assert_eq!(budget.available_bytes(), 0);

    // Non-blocking: the second caller is refused immediately rather than
    // waiting behind the first and burning its client's deadline.
    assert!(budget.charge_retained_body(vec![0u8; UNIT]).is_none());

    drop(first);
    assert!(
        budget.charge_retained_body(vec![0u8; UNIT]).is_some(),
        "capacity returns as soon as the resident bytes are gone"
    );
}

#[test]
fn concurrent_retained_responses_cannot_exceed_the_aggregate_budget() {
    let budget = probe(8);
    let mut resident = Vec::new();
    // Each response is individually well within any sane per-response ceiling;
    // the aggregate is what bounds them.
    for _ in 0..8 {
        resident.push(
            budget
                .charge_retained_body(vec![0u8; UNIT])
                .expect("within budget"),
        );
    }
    assert_eq!(budget.available_bytes(), 0);
    assert!(
        budget.charge_retained_body(vec![0u8; UNIT]).is_none(),
        "the 9th concurrent retained response must be refused, not admitted"
    );
    assert_eq!(resident.len(), 8);
}

// ---------------------------------------------------------------------------
// Ceilings: zero folds to a finite fallback; a configured ceiling is verbatim.
// ---------------------------------------------------------------------------

#[test]
fn zero_effective_limit_folds_to_the_configured_fallback_ceiling() {
    let budget = ResponseBufferBudgetProbe::new(4 * UNIT, 64 * UNIT);
    assert_eq!(
        budget.buffered_response_body_ceiling(0),
        4 * UNIT,
        "`0 = unlimited` is a streaming policy only"
    );
    assert_eq!(budget.buffered_response_body_ceiling(1234), 1234);
}

#[test]
fn a_fallback_ceiling_below_one_block_is_clamped_up_not_to_zero() {
    // A degenerate configuration must not make every retained response
    // impossible.
    let budget = ResponseBufferBudgetProbe::new(1, 0);
    assert!(budget.buffered_response_body_ceiling(0) >= UNIT);
    assert!(budget.available_bytes() >= UNIT);
}

#[test]
fn the_aggregate_budget_is_not_widened_to_fit_a_larger_per_response_ceiling() {
    // Floor is the FALLBACK ceiling only. A 1 GiB per-response ceiling
    // configured elsewhere does not enlarge a 4-block aggregate budget, so a
    // response above the budget is refused instead of uncapping it.
    let budget = ResponseBufferBudgetProbe::new(UNIT, 4 * UNIT);
    assert_eq!(budget.buffered_response_body_ceiling(1 << 30), 1 << 30);
    assert_eq!(budget.available_bytes(), 4 * UNIT);
    assert!(budget.charge_retained_body(vec![0u8; 5 * UNIT]).is_none());
}

// ---------------------------------------------------------------------------
// Classification: gateway-local capacity, not a backend fault.
// ---------------------------------------------------------------------------

#[test]
fn exhaustion_maps_to_a_neutral_overload_refusal_on_every_transport() {
    // HTTP: 503, not a backend 502.
    assert_eq!(RESPONSE_BUFFER_OVERLOAD_STATUS, 503);
    // gRPC: the resource/capacity status, not UNAVAILABLE (backend down) and
    // not INTERNAL (gateway defect).
    assert_eq!(RESPONSE_BUFFER_OVERLOAD_GRPC_STATUS, 8);
    // Fixed, redaction-safe body: no route, header, credential, or response
    // content can appear in it.
    assert_eq!(
        RESPONSE_BUFFER_OVERLOAD_BODY,
        r#"{"error":"Response buffering capacity exceeded"}"#
    );
}

#[test]
fn exhaustion_is_backend_health_neutral_and_distinct_from_oversize() {
    assert_eq!(
        RESPONSE_BUFFER_OVERLOAD_ERROR_CLASS,
        ErrorClass::GatewayBufferCapacity
    );
    assert_eq!(
        ErrorClass::GatewayBufferCapacity.as_str(),
        "gateway_buffer_capacity"
    );

    // Neutral: no circuit-breaker trip, no passive-health ding, no
    // adaptive-concurrency shrink for a backend that answered correctly.
    assert!(error_class_is_health_neutral_for_test(
        ErrorClass::GatewayBufferCapacity
    ));
    assert!(!error_class_is_backend_failure_for_test(
        ErrorClass::GatewayBufferCapacity
    ));

    // True per-response overflow stays a backend-attributed failure, so the two
    // conditions remain distinguishable in telemetry and in health accounting.
    assert!(!error_class_is_health_neutral_for_test(
        ErrorClass::ResponseBodyTooLarge
    ));
    assert!(error_class_is_backend_failure_for_test(
        ErrorClass::ResponseBodyTooLarge
    ));
}

// ---------------------------------------------------------------------------
// Allocation-owned accounting: a charge belongs to the allocation it paid for,
// never to the request that produced it.
// ---------------------------------------------------------------------------

/// A plugin-authored REPLACEMENT of the buffered body is a different allocation
/// than the one the collector charged. Its charge must follow the replacement
/// bytes — not the request context — so a copy that outlives the request stays
/// charged and a context that drops (or is cloned) neither releases nor
/// duplicates it.
#[test]
fn a_replacement_allocation_owns_its_own_charge() {
    let budget = probe(8);
    let total = budget.available_bytes();

    // Collected body: one charge.
    let collected = budget
        .charge_retained_body(vec![0u8; 2 * UNIT])
        .expect("collected body admits");
    assert_eq!(budget.available_bytes(), total - 2 * UNIT);

    // A normalizer/transform installs a DIFFERENT allocation. Both are resident
    // for the moment the swap happens, so both are charged.
    let replacement = budget
        .charge_retained_body(vec![1u8; 3 * UNIT])
        .expect("replacement admits");
    assert_eq!(budget.available_bytes(), total - 5 * UNIT);

    // Dropping the superseded body returns only ITS charge.
    drop(collected);
    assert_eq!(
        budget.available_bytes(),
        total - 3 * UNIT,
        "the replacement must stay charged after the body it replaced is gone"
    );

    // The replacement stays charged for as long as any handle exists — which is
    // what a request-scoped charge could not express, because the request can
    // end while a stored copy of the replacement is still resident.
    let outlives_the_request = replacement.clone();
    drop(replacement);
    assert_eq!(
        budget.available_bytes(),
        total - 3 * UNIT,
        "a surviving handle keeps the single charge"
    );
    drop(outlives_the_request);
    assert_eq!(budget.available_bytes(), total, "last handle returns it");
}

/// The `response_caching` entry body is a COPY that outlives the request. It
/// must acquire its own charge and hold it until the entry is evicted and the
/// last clone of it drops — the collector's charge cannot cover it, because the
/// collected body is released when the response finishes.
#[test]
fn a_cache_entry_copy_carries_its_own_charge_through_eviction() {
    let budget = probe(8);
    let total = budget.available_bytes();

    let entry = {
        // The response the client actually receives.
        let collected = budget
            .charge_retained_body(vec![7u8; 2 * UNIT])
            .expect("collected body admits");
        // The store copies it into an entry that will outlive this response.
        let entry = budget
            .charge_retained_copy(&collected)
            .expect("the entry copy is admitted");
        assert_eq!(
            budget.available_bytes(),
            total - 4 * UNIT,
            "the entry copy is charged separately from the collected body"
        );
        entry
    };

    // The request is over and its body is gone; the entry is still resident and
    // still charged.
    assert_eq!(
        budget.available_bytes(),
        total - 2 * UNIT,
        "the cache entry must stay charged after the request that stored it ended"
    );

    // A replay hands out a cheap clone: still exactly one charge.
    let replay = entry.clone();
    assert_eq!(budget.available_bytes(), total - 2 * UNIT);

    // Eviction drops the entry, but an in-flight replay still holds the bytes.
    drop(entry);
    assert_eq!(
        budget.available_bytes(),
        total - 2 * UNIT,
        "eviction with a live replay must not return the charge early"
    );
    drop(replay);
    assert_eq!(budget.available_bytes(), total, "last handle returns it");
}

/// When the budget cannot admit the entry copy, the store must be skipped —
/// never retained uncharged, and never materialised at all.
#[test]
fn an_unaffordable_cache_entry_copy_is_refused_rather_than_stored() {
    let budget = probe(2);
    let _pinned = budget
        .charge_retained_body(vec![0u8; 2 * UNIT])
        .expect("fills the budget");
    assert_eq!(budget.available_bytes(), 0);

    assert!(
        budget.charge_retained_copy(&[9u8; UNIT]).is_none(),
        "an unaffordable entry copy must be refused so the store is skipped"
    );
    assert_eq!(budget.available_bytes(), 0, "a refused copy leaks no partial reservation");
}

/// The eager small-response path never copies: reqwest already owns the bytes
/// as `Bytes`, so the charge is attached to that existing handle. The charge is
/// still acquired BEFORE the read, which is what stops concurrency from
/// multiplying the eager cutoff.
#[test]
fn eagerly_read_bytes_are_charged_in_place_before_the_read() {
    let budget = probe(4);
    let total = budget.available_bytes();

    // Declared Content-Length is reserved up front.
    let mut charge = budget.try_reserve(UNIT).expect("declared length admits");
    assert_eq!(budget.available_bytes(), total - UNIT);
    assert_eq!(charge.reserved_bytes(), UNIT);

    // The read completes; the charge is grown to the real length and attached
    // to the transport's own allocation.
    let read: bytes::Bytes = bytes::Bytes::from(vec![3u8; 2 * UNIT]);
    assert!(budget.grow(&mut charge, read.len()), "growth admits");
    let body = budget.attach_shared(read, charge);

    assert_eq!(
        budget.available_bytes(),
        total - 2 * UNIT,
        "the eagerly buffered body stays charged after the read frame returns"
    );
    drop(body);
    assert_eq!(budget.available_bytes(), total);
}

/// Concurrency must not be able to multiply the eager cutoff: once the budget
/// is spent, a further eager buffer is refused up front rather than read.
#[test]
fn eager_buffering_is_refused_once_the_aggregate_budget_is_spent() {
    let budget = probe(2);
    let first = budget.try_reserve(UNIT).expect("first eager read admits");
    let second = budget.try_reserve(UNIT).expect("second eager read admits");
    assert_eq!(budget.available_bytes(), 0);

    assert!(
        budget.try_reserve(UNIT).is_none(),
        "an eager read must be refused, not queued, once the budget is spent"
    );

    drop((first, second));
    assert_eq!(budget.available_bytes(), 2 * UNIT, "released eager charges restore capacity");
}

// ---------------------------------------------------------------------------
// Overflow-safe growth.
// ---------------------------------------------------------------------------

/// Collectors compute the prospective retained length ONCE and reuse it for the
/// ceiling check, the budget charge, and the allocation. It saturates, so a
/// hostile length cannot wrap past a finite ceiling (or panic a debug build).
#[test]
fn prospective_retained_length_saturates_instead_of_overflowing() {
    use ferrum_edge::_test_support::prospective_retained_len_for_test as prospective;

    assert_eq!(prospective(0, 0), 0);
    assert_eq!(prospective(10, 32), 42);
    assert_eq!(prospective(usize::MAX, 1), usize::MAX);
    assert_eq!(prospective(usize::MAX - 1, 8), usize::MAX);
    assert_eq!(prospective(usize::MAX, usize::MAX), usize::MAX);

    // Saturation fails closed: the saturated value exceeds every finite
    // ceiling, so the bound check rejects rather than admitting a wrapped sum.
    let ceiling = 10 * UNIT;
    assert!(prospective(usize::MAX - 1, 8) > ceiling);

    // And the budget refuses it rather than rounding it into a small block
    // count.
    let budget = probe(8);
    assert!(
        budget.try_reserve(usize::MAX).is_none(),
        "a saturated prospective length must be refused"
    );
    assert_eq!(budget.available_bytes(), 8 * UNIT);
}

// ---------------------------------------------------------------------------
// The refusal is a gateway-authored overload response, not the backend's status
// over a body the client is not getting.
// ---------------------------------------------------------------------------

fn refusal_headers(pairs: &[(&str, &str)]) -> std::collections::HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

fn refusal_ctx() -> ferrum_edge::plugins::RequestContext {
    ferrum_edge::plugins::RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/resource".to_string(),
    )
}

/// An HTTP response whose replacement the budget refuses becomes the gateway's
/// own `503` with the fixed redaction-safe body — never the backend's `200`
/// over bytes the client will not receive — and stale representation metadata
/// that described the discarded bytes is removed.
#[test]
fn a_refused_http_replacement_becomes_a_gateway_503_with_clean_metadata() {
    let mut ctx = refusal_ctx();
    let mut status = 200u16;
    let mut headers = refusal_headers(&[
        ("content-type", "application/xml"),
        ("content-encoding", "gzip"),
        ("content-length", "1048576"),
        ("content-range", "bytes 0-9/100"),
        ("transfer-encoding", "chunked"),
        ("etag", "\"v1\""),
        ("digest", "sha-256=abc"),
        ("x-request-id", "keep-me"),
    ]);
    let mut body = bytes::Bytes::from_static(b"backend representation");

    ferrum_edge::_test_support::install_response_buffer_capacity_refusal_for_test(
        &mut ctx,
        &mut status,
        &mut headers,
        &mut body,
    );

    assert_eq!(
        status,
        RESPONSE_BUFFER_OVERLOAD_STATUS,
        "the backend status must not survive a refusal that discarded its body"
    );
    assert_eq!(body, bytes::Bytes::from_static(RESPONSE_BUFFER_OVERLOAD_BODY.as_bytes()));
    assert_eq!(headers.get("content-type").map(String::as_str), Some("application/json"));
    let expected_length = RESPONSE_BUFFER_OVERLOAD_BODY.len().to_string();
    assert_eq!(
        headers.get("content-length"),
        Some(&expected_length),
        "Content-Length must describe the bytes actually emitted"
    );
    for stale in [
        "content-encoding",
        "content-range",
        "transfer-encoding",
        "etag",
        "digest",
    ] {
        assert!(
            !headers.contains_key(stale),
            "`{stale}` described bytes the gateway discarded and must be removed"
        );
    }
    assert_eq!(
        headers.get("x-request-id").map(String::as_str),
        Some("keep-me"),
        "unrelated headers are untouched"
    );

    // The fixed body names no route, header, credential, or response content.
    let rendered = String::from_utf8(body.to_vec()).expect("utf-8");
    assert!(!rendered.contains("/api/resource"));
    assert!(!rendered.contains("backend representation"));
}

/// A NATIVE gRPC response terminates through Trailers-Only gRPC status metadata
/// instead: gRPC errors ride HTTP 200, so rewriting the HTTP status would break
/// the protocol contract rather than express the refusal.
///
/// The flavor is taken from the request-scoped inbound classification, never
/// from a response `Content-Type` a hook may have relabelled.
#[test]
fn a_refused_native_grpc_replacement_terminates_through_grpc_metadata() {
    let mut ctx = refusal_ctx();
    ferrum_edge::_test_support::set_request_http_flavor_for_test(
        &mut ctx,
        ferrum_edge::HttpFlavor::Grpc,
    );
    let mut status = 200u16;
    let mut headers = refusal_headers(&[
        ("content-type", "application/grpc+proto"),
        ("content-encoding", "gzip"),
        // Terminal metadata the BACKEND authored for a different status. It
        // describes an outcome the client is not getting and must not ship
        // beside RESOURCE_EXHAUSTED.
        ("grpc-status", "0"),
        ("grpc-status-details-bin", "AAAA"),
        ("x-backend-trailer", "leaked"),
        ("set-cookie", "session=abc"),
        ("etag", "\"v1\""),
    ]);
    let mut body = bytes::Bytes::from_static(b"\x00\x00\x00\x00\x05hello");

    ferrum_edge::_test_support::install_response_buffer_capacity_refusal_for_test(
        &mut ctx,
        &mut status,
        &mut headers,
        &mut body,
    );

    assert_eq!(status, 200, "a gRPC terminal must stay on HTTP 200");
    assert!(body.is_empty(), "the refused frame must not reach the client");
    let expected_grpc_status = RESPONSE_BUFFER_OVERLOAD_GRPC_STATUS.to_string();
    assert_eq!(
        headers.get("grpc-status"),
        Some(&expected_grpc_status),
        "the resource/capacity status, not UNAVAILABLE, INTERNAL, or the backend's OK"
    );
    assert!(headers.contains_key("grpc-message"));
    assert_eq!(
        headers.get("content-type").map(String::as_str),
        Some("application/grpc")
    );
    for stale in [
        "grpc-status-details-bin",
        "x-backend-trailer",
        "set-cookie",
        "etag",
        "content-encoding",
    ] {
        assert!(
            !headers.contains_key(stale),
            "`{stale}` describes the discarded backend outcome and must not survive"
        );
    }
}

/// A TRANSLATED gRPC-Web response carries terminal metadata in a body trailer
/// FRAME, never as response header fields. A refusal that wrote `grpc-status`
/// into the header map and emptied the body would emit terminal metadata the
/// client cannot read as the RPC's status.
#[test]
fn a_refused_grpc_web_replacement_terminates_through_a_body_trailer_frame() {
    let mut ctx = refusal_ctx();
    ctx.metadata.insert(
        ferrum_edge::_test_support::GRPC_WEB_RETAINED_RESPONSE_CONTENT_TYPE_METADATA_KEY.to_string(),
        "application/grpc-web+proto".to_string(),
    );
    let mut status = 200u16;
    let mut headers = refusal_headers(&[
        ("content-type", "application/grpc-web+proto"),
        ("grpc-status", "0"),
        ("grpc-status-details-bin", "AAAA"),
        ("etag", "\"v1\""),
    ]);
    let mut body = bytes::Bytes::from_static(b"\x00\x00\x00\x00\x05hello");

    ferrum_edge::_test_support::install_response_buffer_capacity_refusal_for_test(
        &mut ctx,
        &mut status,
        &mut headers,
        &mut body,
    );

    assert_eq!(status, 200, "a gRPC-Web terminal must stay on HTTP 200");
    assert_eq!(
        headers.get("content-type").map(String::as_str),
        Some("application/grpc-web+proto")
    );

    // The terminal block is FRAMED: a trailer frame (flag byte 0x80) carrying
    // the capacity status, not header fields.
    assert!(
        !body.is_empty(),
        "gRPC-Web terminal metadata must be in the body, not header fields"
    );
    assert_eq!(body[0], 0x80, "leading byte marks a gRPC-Web trailer frame");
    let rendered = String::from_utf8_lossy(&body).to_string();
    let expected_grpc_status = RESPONSE_BUFFER_OVERLOAD_GRPC_STATUS.to_string();
    assert!(
        rendered.contains(&format!("grpc-status: {expected_grpc_status}")),
        "trailer frame must carry the capacity status: {rendered:?}"
    );

    for stale in ["grpc-status-details-bin", "etag"] {
        assert!(
            !headers.contains_key(stale),
            "`{stale}` describes the discarded backend outcome and must not survive"
        );
    }
    assert_ne!(
        headers.get("grpc-status").map(String::as_str),
        Some("0"),
        "the backend's OK status must never survive a refusal"
    );
}

// ---------------------------------------------------------------------------
// Static sweep: every retained-body construction reached by this advisory has
// to acquire a charge. These are source-shape assertions because the paths they
// cover need a live backend to exercise end to end, and a silent regression
// there is exactly the bypass being fixed.
// ---------------------------------------------------------------------------

#[test]
fn every_eager_reqwest_buffer_reserves_before_it_reads() {
    let proxy = include_str!("../../../src/proxy/mod.rs");

    // Three eager small-response paths: the retry loop, the limited
    // first-attempt arm, and the unlimited first-attempt arm.
    assert_eq!(
        proxy.matches("response.bytes(),").count(),
        3,
        "the eager small-response optimization is expected on exactly three \
         reqwest paths; a new one must be charged too"
    );
    assert_eq!(
        proxy
            .matches("response_buffer_budget::try_reserve_retained(declared_len)")
            .count(),
        3,
        "every eager path must reserve its declared Content-Length BEFORE the \
         read, so concurrency cannot multiply the eager cutoff"
    );
    assert_eq!(
        proxy.matches("buffered_backend_response_from_body_read(").count(),
        4,
        "three call sites plus the definition; each call site must hand over a \
         reservation"
    );

    // The unbounded `0 = unlimited` retained arm must not exist anywhere: every
    // buffered collection goes through the fail-closed ceiling.
    assert_eq!(
        proxy
            .matches("response_buffer_budget::buffered_response_body_ceiling(")
            .count(),
        4,
        "each buffered reqwest collection folds `0` to the fail-closed ceiling"
    );
}

#[test]
fn the_response_cache_entry_copy_is_charged_for_its_own_lifetime() {
    let caching = include_str!("../../../src/plugins/response_caching.rs");
    assert!(
        caching.contains("response_buffer_budget::charge_retained_copy(body)"),
        "the cache entry copy outlives the request, so it must carry its own \
         charge instead of claiming the collector's (GHSA-pwcm-6rh8-f2gh)"
    );
    assert!(
        !caching.contains("Bytes::copy_from_slice(body)"),
        "an uncharged entry copy must not be reintroduced"
    );
}

#[test]
fn the_replacement_charge_is_not_request_scoped() {
    let plugins = include_str!("../../../src/plugins/mod.rs");
    let proxy = include_str!("../../../src/proxy/mod.rs");
    for source in [plugins, proxy] {
        assert!(
            !source.contains("charge_replacement_response_body"),
            "a replacement charge held by the RequestContext drops with the \
             request and is emptied by its Clone, so it cannot bound a copy \
             that outlives the request (GHSA-pwcm-6rh8-f2gh)"
        );
    }
    assert!(
        plugins.contains("charge_replacement_body(body)"),
        "the normalizer replacement must be charged to the allocation"
    );
    assert!(
        proxy.contains("charge_replacement_body(transformed)"),
        "the body-transform replacement must be charged to the allocation"
    );
}

/// Both buffered phases that can be refused after the backend answered must
/// route through the SHARED gateway-terminal helper. A hand-rolled refusal is
/// how the gRPC-Web branch came to emit unframed terminal metadata.
#[test]
fn every_capacity_refusal_uses_the_shared_gateway_terminal() {
    let plugins = include_str!("../../../src/plugins/mod.rs");
    let proxy = include_str!("../../../src/proxy/mod.rs");
    for source in [plugins, proxy] {
        assert!(
            !source.contains("install_response_buffer_capacity_refusal"),
            "the hand-rolled refusal installer must not return; it wrote gRPC-Web \
             terminal metadata into header fields instead of a body trailer frame \
             (GHSA-pwcm-6rh8-f2gh)"
        );
    }
    assert_eq!(
        proxy
            .matches("replace_buffered_response_with_capacity_refusal(")
            .count(),
        2,
        "one definition plus the body-transform call site; the normalize call \
         site lives in src/plugins/mod.rs"
    );
    assert_eq!(
        proxy
            .matches("replace_buffered_response_with_capacity_refusal_with_policy_source(")
            .count(),
        3,
        "one definition, the prefiltered delegation, and the representation \
         gate's decode refusal — the gate is reached from callers holding the \
         unfiltered protocol plugin list, so it cannot use the prefiltered \
         wrapper"
    );
    assert!(
        plugins.contains("replace_buffered_response_with_capacity_refusal("),
        "the normalize phase must use the same shared terminal"
    );
    assert!(
        proxy.contains("crate::plugins::grpc_web::error_response_for_content_type("),
        "a gRPC-Web capacity terminal must be built as a body trailer frame"
    );
}

/// The final response-header phase is the whole basis for releasing a body, so
/// it must run from the one boundary every protocol path funnels through, and
/// the cache's own header effects must live in that hook rather than in a
/// speculative buffering predicate.
#[test]
fn the_final_response_header_phase_runs_at_the_after_proxy_boundary() {
    let proxy = include_str!("../../../src/proxy/mod.rs");
    let caching = include_str!("../../../src/plugins/response_caching.rs");
    assert_eq!(
        proxy
            .matches("crate::plugins::run_final_response_header_hooks(")
            .count(),
        1,
        "exactly one call site, inside `run_after_proxy_hooks`, so no protocol \
         path can skip it (GHSA-pwcm-6rh8-f2gh)"
    );
    assert!(
        caching.contains("fn on_final_response_headers("),
        "response_caching must own its header-only effects in the header phase"
    );
    assert!(
        caching.contains("fn classify_final_response_headers("),
        "the release predicate must be a pure classification"
    );
    // The speculative predicates must call the PURE classifier, never the
    // effect-taking one: an effect fired from a buffering vote would apply to
    // attempts the proxy never adopts.
    for speculative in [
        "fn should_buffer_response_body_for_content_type(",
        "fn should_release_response_body_under_retries(",
    ] {
        let start = caching.find(speculative).expect(speculative);
        let body: String = caching[start..].chars().take(1400).collect();
        assert!(
            !body.contains("apply_final_response_header_effects("),
            "`{speculative}` is speculative and must take no cache effect"
        );
    }
}

#[test]
fn no_collector_adds_lengths_without_saturating() {
    for source in [
        include_str!("../../../src/proxy/mod.rs"),
        include_str!("../../../src/proxy/grpc_proxy.rs"),
        include_str!("../../../src/http3/client.rs"),
        include_str!("../../../src/http3/cross_protocol.rs"),
    ] {
        for unchecked in [
            "body.len() + chunk.len()",
            "body_bytes.len() + data.len()",
            "body.len() + data.len()",
        ] {
            assert!(
                !source.contains(unchecked),
                "retained-body growth must go through \
                 `response_buffer_budget::prospective_retained_len`, computed \
                 once and reused by the ceiling check and the charge"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// The representation gate's decode: the allocation that becomes the retained,
// client-visible body, and the working set that produces it.
//
// This is the residual the first round of the advisory fix left open. The gate
// decodes a protected encoded response and installs the identity bytes as the
// body the client receives; a small compressed response can inflate to the
// decode ceiling, so an uncharged decode let concurrent requests amplify past
// the process aggregate even while their small encoded bodies were charged.
//
// Every test below drives the PRODUCTION gate
// (`evaluate_response_body_policy_posture` + `install_decoded_response_body`)
// with an isolated semaphore bound where the proxy binds the process-global
// one, so admission and release are observable without racing a parallel test
// binary.
// ---------------------------------------------------------------------------

/// A `response_transformer` whose only job is to strip a secret field — the
/// configuration whose bypass the advisory describes, and therefore a policy
/// that genuinely claims the response.
fn redacting_plugins() -> Vec<Arc<dyn Plugin>> {
    vec![Arc::new(
        ResponseTransformer::new(&serde_json::json!({
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

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).expect("gzip write must succeed");
    encoder.finish().expect("gzip finish must succeed")
}

/// A JSON document of exactly `payload_bytes` of high-entropy payload.
///
/// The point is not that gzip achieves nothing on it — a 64-symbol alphabet
/// still compresses to roughly three quarters — but that the DECODED size is
/// fixed by construction, so the decoder's working set is predictable instead of
/// being at the mercy of the compressor. Deterministic (a fixed LCG), because a
/// flaky budget assertion is worse than no budget assertion.
fn incompressible_json(payload_bytes: usize) -> Vec<u8> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut state: u64 = 0x2545_F491_4F6C_DD1D;
    let mut payload = Vec::with_capacity(payload_bytes);
    for _ in 0..payload_bytes {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        payload.push(ALPHABET[((state >> 33) % 64) as usize]);
    }
    let mut document = br#"{"secret":"hunter2","filler":""#.to_vec();
    document.extend_from_slice(&payload);
    document.extend_from_slice(br#""}"#);
    document
}

/// Drive the production gate over a backend response, stamping the pristine
/// pre-`after_proxy` snapshot exactly as every buffered path does.
fn admit_backend_representation(
    budget: &ResponseBufferBudgetProbe,
    headers: &mut HashMap<String, String>,
    body: &mut bytes::Bytes,
) -> BufferedRepresentationOutcome {
    let plugins = redacting_plugins();
    let mut ctx = make_ctx();
    stamp_original_response_metadata_for_test(&mut ctx, 200, headers);
    budget.admit_buffered_representation(&plugins, &mut ctx, true, 200, headers, body)
}

fn gzip_json_response(payload_bytes: usize) -> (Vec<u8>, HashMap<String, String>, bytes::Bytes) {
    let plain = incompressible_json(payload_bytes);
    let headers = HashMap::from([
        ("content-type".to_string(), "application/json".to_string()),
        ("content-encoding".to_string(), "gzip".to_string()),
        ("etag".to_string(), "\"v1\"".to_string()),
    ]);
    let body = bytes::Bytes::from(gzip(&plain));
    (plain, headers, body)
}

/// The core residual: the decoded allocation becomes the client-visible body
/// even when NO transform rewrites it afterwards, so it must own an aggregate
/// charge for its whole lifetime — and give it back only when the last clone of
/// those bytes drops.
#[test]
fn decoded_identity_bytes_are_charged_until_their_last_clone_drops() {
    let budget = probe(64);
    let total = budget.available_bytes();
    let (plain, mut headers, mut body) = gzip_json_response(192 * 1024);

    assert!(
        body.len() < plain.len(),
        "the residual is about amplification: the decoded bytes are larger than \
         the encoded ones the collector charged"
    );

    let outcome = admit_backend_representation(&budget, &mut headers, &mut body);
    assert_eq!(outcome, BufferedRepresentationOutcome::Decoded);
    assert_eq!(
        body.as_ref(),
        plain.as_slice(),
        "the identity bytes are what the client will receive"
    );

    let charged = total - budget.available_bytes();
    assert!(
        charged >= plain.len(),
        "the retained decoded allocation must be charged for at least its own \
         length; charged {charged}, decoded {}",
        plain.len()
    );

    // A cheap clone shares the one owner. If a clone minted its own charge —
    // or if the charge had been request-scoped — this would move.
    let replica = body.clone();
    assert_eq!(
        budget.available_bytes(),
        total - charged,
        "a clone shares the single charge"
    );

    drop(body);
    assert_eq!(
        budget.available_bytes(),
        total - charged,
        "the charge is owned by the allocation, and a clone is still holding it"
    );
    drop(replica);
    assert_eq!(
        budget.available_bytes(),
        total,
        "the last clone dropping returns the whole charge"
    );
}

/// The no-op-transform path is the one that made this exploitable: the gate
/// installs identity bytes, no configured rule matches them, and they stay
/// client-visible and resident for the rest of the response lifetime. They must
/// arrive charged, with the representation metadata the decode invalidated
/// already refreshed.
#[test]
fn a_decode_no_later_transform_rewrites_is_still_charged_and_reheadered() {
    let budget = probe(64);
    let total = budget.available_bytes();
    // No `secret` key, so every configured body rule is a no-op over these
    // bytes and nothing after the gate will replace the allocation.
    let plain = br#"{"public":"value"}"#.to_vec();
    let mut headers = HashMap::from([
        ("content-type".to_string(), "application/json".to_string()),
        ("content-encoding".to_string(), "gzip".to_string()),
        ("etag".to_string(), "\"v1\"".to_string()),
        ("content-length".to_string(), "999".to_string()),
    ]);
    let mut body = bytes::Bytes::from(gzip(&plain));

    let outcome = admit_backend_representation(&budget, &mut headers, &mut body);

    assert_eq!(outcome, BufferedRepresentationOutcome::Decoded);
    assert_eq!(body.as_ref(), plain.as_slice());
    assert!(
        budget.available_bytes() < total,
        "identity bytes nothing rewrites are still retained, so they are still \
         charged"
    );
    assert!(
        !headers.contains_key("content-encoding"),
        "the stale coding must not describe identity bytes"
    );
    assert!(
        !headers.contains_key("etag"),
        "a validator for the encoded representation must be invalidated"
    );
    assert_eq!(
        headers.get("content-length"),
        Some(&plain.len().to_string()),
        "the refreshed length must describe the installed bytes"
    );

    drop(body);
    assert_eq!(budget.available_bytes(), total);
}

/// A stacked `Content-Encoding` holds one pass's input and the next pass's
/// output at the same time. Charging only the final decoded body would let that
/// window escape the aggregate bound.
///
/// The pair is self-calibrating: the SAME plaintext under the SAME budget is
/// admitted when it arrives under one coding and refused when it arrives under
/// two, so the refusal can only come from the concurrent working set.
#[test]
fn a_stacked_decode_charges_its_input_and_output_concurrently() {
    // 300 KiB of payload: the decoded buffer lands in the (256 KiB, 512 KiB]
    // growth step (8 blocks) and the intermediate in (128 KiB, 256 KiB]
    // (4 blocks), with room on both sides for the compressor's exact ratio.
    let plain = incompressible_json(300 * 1024);
    let once = gzip(&plain);
    let twice = gzip(&once);
    let headers = || {
        HashMap::from([
            ("content-type".to_string(), "application/json".to_string()),
            ("content-encoding".to_string(), "gzip, gzip".to_string()),
        ])
    };

    // Sized between "one decoded copy fits" (8 blocks for this plaintext) and
    // "the intermediate and the final buffer fit at once" (12).
    let budget = probe(10);
    let total = budget.available_bytes();

    let mut single_headers = headers();
    single_headers.insert("content-encoding".to_string(), "gzip".to_string());
    let mut single_body = bytes::Bytes::from(once.clone());
    assert_eq!(
        admit_backend_representation(&budget, &mut single_headers, &mut single_body),
        BufferedRepresentationOutcome::Decoded,
        "one decoded copy of this plaintext fits in the budget"
    );
    drop(single_body);
    assert_eq!(budget.available_bytes(), total);

    let mut stacked_headers = headers();
    let mut stacked_body = bytes::Bytes::from(twice);
    assert_eq!(
        admit_backend_representation(&budget, &mut stacked_headers, &mut stacked_body),
        BufferedRepresentationOutcome::CapacityRefused,
        "the intermediate and the final buffer are resident at once, so the \
         same plaintext no longer fits"
    );
    assert_eq!(
        budget.available_bytes(),
        total,
        "a refused decode releases every block it had already taken"
    );
}

/// Refusal is a statement about the GATEWAY, not the representation, so it takes
/// the transient-capacity terminal: `503` with the fixed redaction-safe body,
/// `RESOURCE_EXHAUSTED` for gRPC, health-neutral and never retried. A `502`
/// representation error here would blame a backend that answered correctly and
/// poison breaker/passive-health accounting.
#[test]
fn a_refused_decode_fails_closed_as_gateway_capacity_not_a_backend_error() {
    let budget = probe(2);
    let total = budget.available_bytes();
    let (_, mut headers, mut body) = gzip_json_response(1024 * 1024);
    let encoded = body.clone();

    let outcome = admit_backend_representation(&budget, &mut headers, &mut body);

    assert_eq!(
        outcome,
        BufferedRepresentationOutcome::CapacityRefused,
        "an admissible decode the gateway has no memory for is a capacity \
         refusal, not a representation fault"
    );
    assert_eq!(
        budget.available_bytes(),
        total,
        "the refused decode leaks nothing"
    );
    assert_eq!(
        body, encoded,
        "nothing is installed on the refusal path; the caller replaces the \
         response with the capacity terminal"
    );

    // The terminal the proxy installs for exactly this outcome.
    let mut ctx = make_ctx();
    let mut status = 200u16;
    install_response_buffer_capacity_refusal_for_test(
        &mut ctx,
        &mut status,
        &mut headers,
        &mut body,
    );
    assert_eq!(status, RESPONSE_BUFFER_OVERLOAD_STATUS);
    assert_eq!(body.as_ref(), RESPONSE_BUFFER_OVERLOAD_BODY.as_bytes());
    assert!(error_class_is_health_neutral_for_test(
        RESPONSE_BUFFER_OVERLOAD_ERROR_CLASS
    ));
    assert!(!error_class_is_backend_failure_for_test(
        RESPONSE_BUFFER_OVERLOAD_ERROR_CLASS
    ));
}

/// The important claim-withdrawal behavior must survive the accounting: a decode
/// whose plaintext proves the policy cannot act on it forwards the ORIGINAL
/// encoded bytes untouched — and gives every block the decode took back, since
/// nothing it produced is retained.
#[test]
fn a_withdrawn_claim_forwards_the_encoded_bytes_and_releases_all_decode_capacity() {
    let budget = probe(64);
    let total = budget.available_bytes();

    // The untyped-gRPC shape: the wire bytes are not frames, so a decode is
    // owed; the plaintext IS a complete frame sequence, so the JSON policy
    // withdraws over it.
    let mut framed = vec![0u8];
    framed.extend_from_slice(&2u32.to_be_bytes());
    framed.extend_from_slice(b"\x08\x01");
    let encoded = gzip(&framed);

    let plugins = redacting_plugins();
    let mut ctx = make_ctx();
    set_request_http_flavor_for_test(&mut ctx, HttpFlavor::Grpc);
    let mut headers = HashMap::from([("content-encoding".to_string(), "gzip".to_string())]);
    let mut body = bytes::Bytes::from(encoded.clone());
    stamp_original_response_metadata_for_test(&mut ctx, 200, &headers);

    let outcome = budget.admit_buffered_representation(
        &plugins,
        &mut ctx,
        true,
        200,
        &mut headers,
        &mut body,
    );

    assert_eq!(
        outcome,
        BufferedRepresentationOutcome::Unprotected,
        "a valid RPC reply must not become an error"
    );
    assert_eq!(
        body.as_ref(),
        encoded.as_slice(),
        "the claim was withdrawn, so the original encoded bytes are forwarded"
    );
    assert_eq!(
        headers.get("content-encoding").map(String::as_str),
        Some("gzip"),
        "nothing was installed, so the representation is unchanged"
    );
    assert_eq!(
        budget.available_bytes(),
        total,
        "the temporary decode capacity is released with the dropped plaintext"
    );
}

/// A rejection after the decode (here: the client refuses identity coding) must
/// release the decode's capacity too. Every non-install exit from the gate is a
/// drop, which is what makes them uniformly leak-free.
#[test]
fn a_rejection_after_the_decode_releases_its_capacity() {
    let budget = probe(64);
    let total = budget.available_bytes();
    let (_, mut headers, mut body) = gzip_json_response(128 * 1024);

    let plugins = redacting_plugins();
    let mut ctx = make_ctx();
    ctx.headers.insert(
        "accept-encoding".to_string(),
        "gzip, identity;q=0".to_string(),
    );
    stamp_original_response_metadata_for_test(&mut ctx, 200, &headers);

    let outcome = budget.admit_buffered_representation(
        &plugins,
        &mut ctx,
        true,
        200,
        &mut headers,
        &mut body,
    );

    assert_eq!(
        outcome,
        BufferedRepresentationOutcome::Rejected("identity_coding_unacceptable")
    );
    assert_eq!(
        budget.available_bytes(),
        total,
        "a rejected representation retains nothing, so it must be charged \
         nothing"
    );
}

/// The decoded body must never reach the client uncharged. This pins the one
/// line that publishes it: a plain `Bytes::from(decoded)` is exactly the
/// residual this round repairs.
#[test]
fn the_decoded_body_is_published_through_the_charged_owner() {
    let representation = include_str!("../../../src/plugins/response_representation.rs");
    assert!(
        representation.contains("*response_body = decoded.into_charged_bytes();")
            && representation.contains("charged_bytes(self.data, self.reservation)"),
        "the decoded allocation must be published together with the permit that \
         paid for it (GHSA-pwcm-6rh8-f2gh)"
    );
    assert!(
        !representation.contains("*response_body = Bytes::from(decoded);"),
        "an uncharged decoded body must not be reintroduced: it stays \
         client-visible through the no-op-transform path with no permit at all"
    );
    assert!(
        !representation.contains("let mut current = body.to_vec();"),
        "the first decode pass must read the collector-charged wire bytes \
         directly rather than making an uncharged copy of them"
    );
}
