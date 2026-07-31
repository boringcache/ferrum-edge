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
