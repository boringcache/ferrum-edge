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

use ferrum_edge::_test_support::{
    RESPONSE_BUFFER_OVERLOAD_BODY, RESPONSE_BUFFER_OVERLOAD_ERROR_CLASS,
    RESPONSE_BUFFER_OVERLOAD_GRPC_STATUS, RESPONSE_BUFFER_OVERLOAD_STATUS,
    RESPONSE_BUFFER_RESERVATION_UNIT_BYTES as UNIT, ResponseBufferBudgetProbe,
    error_class_is_backend_failure_for_test, error_class_is_health_neutral_for_test,
};
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

/// A gRPC-flavored response terminates through gRPC status metadata instead:
/// gRPC errors ride HTTP 200, so rewriting the HTTP status would break the
/// protocol contract rather than express the refusal.
#[test]
fn a_refused_grpc_replacement_terminates_through_grpc_metadata() {
    let mut ctx = refusal_ctx();
    let mut status = 200u16;
    let mut headers = refusal_headers(&[
        ("content-type", "application/grpc+proto"),
        ("content-encoding", "gzip"),
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
        "the resource/capacity status, not UNAVAILABLE or INTERNAL"
    );
    assert!(headers.contains_key("grpc-message"));
    assert_eq!(headers.get("content-length").map(String::as_str), Some("0"));
    assert!(!headers.contains_key("content-encoding"));
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
