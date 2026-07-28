//! Shared observability byte-budget primitive tests.

use ferrum_edge::plugins::utils::byte_budget::{
    ByteBudget, DEFAULT_BUFFER_MAX_BYTES, DEFAULT_MAX_ENTRY_BYTES, HARD_MAX_BUFFER_MAX_BYTES,
    HARD_MAX_ENTRY_BYTES, MIN_MAX_ENTRY_BYTES, PROCESS_MAX_RETAINED_BYTES_DEFAULT,
    PROCESS_MAX_RETAINED_BYTES_MAX, PROCESS_MAX_RETAINED_BYTES_MIN, RetainedByteCeiling,
    admit_byte_limits,
};
use ferrum_edge::plugins::utils::summary_log_budget::serialize_under_byte_budget;
use serde_json::json;

#[test]
fn admit_byte_limits_defaults_and_bounds() {
    let defaults = admit_byte_limits(&json!({}), "probe").expect("defaults");
    assert_eq!(defaults.max_entry_bytes, DEFAULT_MAX_ENTRY_BYTES);
    assert_eq!(defaults.buffer_max_bytes, DEFAULT_BUFFER_MAX_BYTES);

    let err = admit_byte_limits(
        &json!({"max_entry_bytes": MIN_MAX_ENTRY_BYTES - 1}),
        "probe",
    )
    .expect_err("below minimum");
    assert!(err.contains("max_entry_bytes"), "{err}");

    let err = admit_byte_limits(
        &json!({"max_entry_bytes": HARD_MAX_ENTRY_BYTES + 1}),
        "probe",
    )
    .expect_err("above hard max");
    assert!(err.contains("max_entry_bytes"), "{err}");

    let err = admit_byte_limits(
        &json!({
            "max_entry_bytes": 2048,
            "buffer_max_bytes": 1024
        }),
        "probe",
    )
    .expect_err("buffer smaller than entry");
    assert!(err.contains("buffer_max_bytes"), "{err}");

    let err = admit_byte_limits(
        &json!({
            "max_entry_bytes": 2048,
            "buffer_max_bytes": HARD_MAX_BUFFER_MAX_BYTES + 1
        }),
        "probe",
    )
    .expect_err("buffer above hard max");
    assert!(err.contains("buffer_max_bytes"), "{err}");
}

#[test]
fn byte_budget_reserves_before_serialize_and_rejects_oversize() {
    let budget = ByteBudget::new("probe", 256);
    let held = budget.try_acquire(256).expect("fill budget");
    let rejected = serialize_under_byte_budget(&budget, 64, &json!({"k": "v"}));
    assert!(
        rejected.is_none(),
        "saturated budget must reject before retain"
    );
    assert!(budget.drops_total() > 0);
    drop(held);
    assert_eq!(budget.used(), 0);

    let admitted = serialize_under_byte_budget(&budget, 64, &json!({"k": "v"}))
        .expect("admission after release");
    assert!(admitted.as_bytes().len() <= 64);
    assert_eq!(budget.used(), (admitted.as_bytes().len() + 1) * 2);
    drop(admitted);
    assert_eq!(budget.used(), 0);
}

#[test]
fn byte_budget_rejects_hostile_serialized_length() {
    let budget = ByteBudget::new("probe", 1_024);
    let huge = "x".repeat(2_048);
    let rejected = serialize_under_byte_budget(&budget, 128, &json!({ "ua": huge }));
    assert!(rejected.is_none());
    assert_eq!(budget.used(), 0);
    assert!(budget.drops_total() > 0);
}

// ---------------------------------------------------------------------------
// Process-wide retained-byte ceiling (GHSA-83h5-52mw-f33p).
//
// Saturation coverage runs against a test-owned leaked `RetainedByteCeiling`
// so it can use a tiny ceiling without perturbing the process-global counter
// that other tests in this same binary reserve against. Coverage of the
// process-global path asserts *deltas*, which stay exact under concurrency.
// ---------------------------------------------------------------------------

fn test_ceiling(max_bytes: usize) -> &'static RetainedByteCeiling {
    let ceiling: &'static RetainedByteCeiling =
        Box::leak(Box::new(RetainedByteCeiling::new(max_bytes)));
    ceiling.set_max_unclamped_for_test(max_bytes);
    ceiling
}

#[test]
fn process_ceiling_rejects_past_the_total_and_releases_on_drop() {
    let ceiling = test_ceiling(1_024);

    let first = ceiling.try_acquire(768).expect("first reservation fits");
    assert_eq!(ceiling.used(), 768);

    // A second instance's admission is refused by the *aggregate* ceiling even
    // though it has taken nothing itself. This is the multi-instance clause:
    // N sinks cannot multiply past the process total.
    assert!(
        ceiling.try_acquire(512).is_none(),
        "aggregate ceiling must refuse the second instance"
    );
    assert_eq!(ceiling.rejections(), 1);
    assert_eq!(
        ceiling.used(),
        768,
        "a refused reservation must not charge the ceiling"
    );

    // Exactly-at-the-ceiling still fits; one byte more does not.
    let second = ceiling.try_acquire(256).expect("exact fit admitted");
    assert_eq!(ceiling.used(), 1_024);
    assert!(ceiling.try_acquire(1).is_none());
    assert_eq!(ceiling.rejections(), 2);

    assert_eq!(ceiling.high_water(), 1_024);

    drop(second);
    assert_eq!(ceiling.used(), 768, "drop releases exactly its own bytes");
    drop(first);
    assert_eq!(ceiling.used(), 0, "all permits released");

    // Capacity recovers without waiting for shutdown.
    let after = ceiling.try_acquire(1_024).expect("capacity recovered");
    assert_eq!(ceiling.used(), 1_024);
    drop(after);
    assert_eq!(ceiling.used(), 0);
    assert_eq!(
        ceiling.high_water(),
        1_024,
        "high water is a peak, not a live gauge"
    );
}

#[test]
fn process_ceiling_shrink_releases_only_the_unused_delta() {
    let ceiling = test_ceiling(4_096);

    // Sinks reserve a provisional `max_entry_bytes` lease *before* serializing,
    // then shrink to the measured size. Only the unused delta comes back.
    let lease = ceiling.try_acquire(4_096).expect("provisional reservation");
    assert_eq!(ceiling.used(), 4_096);
    lease.shrink_to(100);
    assert_eq!(ceiling.used(), 100);
    assert_eq!(lease.reserved(), 100);

    // Shrinking upward is a no-op: a lease can never silently grow its charge.
    lease.shrink_to(4_000);
    assert_eq!(ceiling.used(), 100);

    // Release is idempotent, so a double release cannot underflow the counter.
    lease.release();
    assert_eq!(ceiling.used(), 0);
    lease.release();
    assert_eq!(ceiling.used(), 0);
    drop(lease);
    assert_eq!(ceiling.used(), 0);

    // Freed capacity is reusable in full.
    let reused = ceiling.try_acquire(4_096).expect("full capacity reusable");
    assert_eq!(ceiling.used(), 4_096);
    drop(reused);
}

#[test]
fn zero_byte_reservations_are_free_and_never_rejected() {
    let ceiling = test_ceiling(16);
    let filled = ceiling.try_acquire(16).expect("fill");
    let free = ceiling
        .try_acquire(0)
        .expect("zero-byte reservations always succeed");
    assert_eq!(ceiling.used(), 16);
    assert_eq!(free.reserved(), 0);
    assert_eq!(ceiling.rejections(), 0);
    drop(free);
    assert_eq!(ceiling.used(), 16);
    drop(filled);
}

#[test]
fn per_instance_byte_budget_also_charges_the_shared_ceiling() {
    // A `ByteBudget` reservation must show up in aggregate accounting;
    // otherwise per-instance budgets would be the only bound and N instances
    // would multiply.
    let ceiling = test_ceiling(1 << 20);
    let budget = ByteBudget::with_ceiling("probe", 4_096, ceiling);

    let lease = budget.try_acquire(1_024).expect("admitted");
    assert_eq!(budget.used(), 1_024);
    assert_eq!(
        ceiling.used(),
        1_024,
        "per-instance reservation must also charge the shared ceiling"
    );

    // Shrink propagates to both counters in lockstep.
    lease.shrink_to(256);
    assert_eq!(budget.used(), 256);
    assert_eq!(ceiling.used(), 256);

    drop(lease);
    assert_eq!(budget.used(), 0);
    assert_eq!(
        ceiling.used(),
        0,
        "dropping the lease must release the ceiling reservation too"
    );
}

#[test]
fn two_instances_cannot_exceed_the_shared_ceiling_between_them() {
    // The multi-instance clause: each sink is individually within its own
    // budget, yet the process total still holds.
    let ceiling = test_ceiling(4_096);
    let first = ByteBudget::with_ceiling("probe_a", 4_096, ceiling);
    let second = ByteBudget::with_ceiling("probe_b", 4_096, ceiling);

    let held = first.try_acquire(4_096).expect("first instance fills");
    assert_eq!(ceiling.used(), 4_096);

    // The second instance's own budget is entirely free, but the aggregate is
    // not, so admission is refused and nothing is retained.
    assert!(
        second.try_acquire(1).is_none(),
        "the shared ceiling must refuse a second instance"
    );
    assert_eq!(second.used(), 0, "a refused admission charges nothing");
    assert!(second.drops_total() > 0, "the refusal is accounted");
    assert_eq!(ceiling.rejections(), 1);

    drop(held);
    assert_eq!(ceiling.used(), 0);
    let recovered = second.try_acquire(4_096).expect("capacity recovered");
    assert_eq!(ceiling.used(), 4_096);
    drop(recovered);
}

#[test]
fn serialize_under_byte_budget_releases_the_ceiling_reservation_on_rejection() {
    // A record refused for exceeding `max_entry_bytes` must leave *neither*
    // counter charged: rejection happens before the payload is retained, and
    // the provisional ceiling reservation is handed back.
    let ceiling = test_ceiling(1 << 20);
    let budget = ByteBudget::with_ceiling("probe", 1_048_576, ceiling);
    let hostile = "x".repeat(8_192);

    let rejected = serialize_under_byte_budget(&budget, 1_024, &json!({ "ua": hostile }));
    assert!(rejected.is_none(), "oversize record must be refused");
    assert_eq!(budget.used(), 0);
    assert_eq!(
        ceiling.used(),
        0,
        "a refused record must not leak a ceiling reservation"
    );

    // The admitted path charges both counters and releases both on drop.
    let admitted =
        serialize_under_byte_budget(&budget, 1_024, &json!({"k": "v"})).expect("small record fits");
    assert!(ceiling.used() > 0);
    assert_eq!(
        ceiling.used(),
        budget.used(),
        "both counters must agree after the lease shrinks to the measured size"
    );
    drop(admitted);
    assert_eq!(ceiling.used(), 0);
    assert_eq!(budget.used(), 0);
}

#[test]
fn a_saturated_ceiling_refuses_before_the_record_is_serialized() {
    // Admission-before-materialization: with the ceiling already full, the
    // hostile payload is never serialized, so nothing is retained anywhere.
    // 262_144 comfortably admits one 65_536-byte entry's accounted charge
    // ((65_536 + 1) * 2 = 131_074) once the ceiling drains again.
    let ceiling = test_ceiling(262_144);
    let budget = ByteBudget::with_ceiling("probe", 1_048_576, ceiling);
    let filled = ceiling.try_acquire(262_144).expect("saturate the ceiling");

    let hostile = "x".repeat(16_384);
    let rejected = serialize_under_byte_budget(&budget, 65_536, &json!({ "ua": hostile }));
    assert!(rejected.is_none(), "saturated ceiling must refuse");
    assert_eq!(budget.used(), 0);
    assert_eq!(
        ceiling.used(),
        262_144,
        "only the pre-existing hold remains"
    );
    assert!(budget.drops_total() > 0);

    drop(filled);
    assert_eq!(ceiling.used(), 0);
    assert!(
        serialize_under_byte_budget(&budget, 65_536, &json!({"k": "v"})).is_some(),
        "admission resumes once the ceiling drains"
    );
}

#[test]
fn process_ceiling_config_bounds_are_clamped_not_silently_accepted() {
    let ceiling = test_ceiling(PROCESS_MAX_RETAINED_BYTES_DEFAULT);

    ceiling.set_max(0);
    assert_eq!(
        ceiling.max(),
        PROCESS_MAX_RETAINED_BYTES_MIN,
        "an unsafely small ceiling is raised to the documented minimum"
    );

    ceiling.set_max(usize::MAX);
    assert_eq!(
        ceiling.max(),
        PROCESS_MAX_RETAINED_BYTES_MAX,
        "an unbounded ceiling is capped at the documented maximum"
    );

    ceiling.set_max(PROCESS_MAX_RETAINED_BYTES_DEFAULT);
    assert_eq!(ceiling.max(), PROCESS_MAX_RETAINED_BYTES_DEFAULT);

    assert!(PROCESS_MAX_RETAINED_BYTES_MIN < PROCESS_MAX_RETAINED_BYTES_DEFAULT);
    assert!(PROCESS_MAX_RETAINED_BYTES_DEFAULT <= PROCESS_MAX_RETAINED_BYTES_MAX);
    // The default process total must admit at least one maximally configured
    // sink instance, or a single legal instance could never fill its budget.
    assert!(HARD_MAX_BUFFER_MAX_BYTES <= PROCESS_MAX_RETAINED_BYTES_DEFAULT);
}
