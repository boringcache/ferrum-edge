//! Destination-wide `http2MaxRequests` active-request breaker (issue #3775).
//!
//! Istio defines `connectionPool.http.http2MaxRequests` as the maximum number of
//! ACTIVE REQUESTS to a destination, applicable to HTTP/1.1 and HTTP/2 alike —
//! not as an HTTP/2 per-connection stream setting. These tests pin the
//! properties that distinction requires:
//!
//! * one budget per LOGICAL destination, so connection count, pool shards, and
//!   endpoint rotation cannot multiply it;
//! * independent namespaces, destinations, ports, and subsets never consume one
//!   another's budget even when they share backend endpoints;
//! * reloads keep one stable lane, so active requests admitted by the previous
//!   config still count against the current cap;
//! * permits release exactly once, freeing the slot for a sequential retry, and
//!   idle lanes are evicted so churn cannot grow the map.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

use ferrum_edge::backend_active_request_limit::{BackendActiveRequestLimiter, DestinationScope};

fn scope<'a>(
    namespace: &'a str,
    destination: &'a str,
    policy_port: u16,
    subset: Option<&'a str>,
) -> DestinationScope<'a> {
    DestinationScope {
        namespace,
        destination,
        policy_port,
        subset,
    }
}

fn reviews(subset: Option<&str>) -> DestinationScope<'_> {
    scope("default", "reviews", 9080, subset)
}

#[test]
fn no_configured_cap_never_touches_the_lane_map() {
    let limiter = BackendActiveRequestLimiter::new();
    let guard = limiter
        .try_acquire(reviews(None), None)
        .expect("an unconfigured destination never errors");
    assert!(guard.is_none(), "no cap must not hand out a permit");
    assert_eq!(limiter.current(reviews(None)), 0);
    assert_eq!(
        limiter.resident_lanes(),
        0,
        "the uncapped hot path must not create a lane"
    );
}

#[test]
fn one_active_request_saturates_a_cap_of_one() {
    // The core acceptance case: with `http2MaxRequests: 1`, a second request to
    // the same effective destination is shed while the first is still active —
    // regardless of which transport either one would have used.
    let limiter = BackendActiveRequestLimiter::new();
    let held = limiter
        .try_acquire(reviews(None), Some(1))
        .expect("first request admitted")
        .expect("permit present");
    let shed = limiter
        .try_acquire(reviews(None), Some(1))
        .expect_err("second concurrent request must be shed");
    assert_eq!(shed.current, 1);
    assert_eq!(shed.cap, 1);
    drop(held);
    // A sequential retry reacquires the freed budget.
    let _retry = limiter
        .try_acquire(reviews(None), Some(1))
        .expect("budget freed by the terminated exchange")
        .expect("permit present");
    assert_eq!(limiter.current(reviews(None)), 1);
}

#[test]
fn a_zero_cap_denies_without_creating_a_lane() {
    // `http2MaxRequests: 0` is rejected at translate time (K8s and native/file),
    // so this is defensive — but it must never strand a permanent zero-count
    // lane, since no permit is handed out to evict it.
    let limiter = BackendActiveRequestLimiter::new();
    limiter
        .try_acquire(reviews(None), Some(0))
        .expect_err("a zero cap denies every request");
    assert_eq!(limiter.current(reviews(None)), 0);
    assert_eq!(limiter.resident_lanes(), 0);
}

#[test]
fn budgets_are_isolated_by_policy_identity_not_by_endpoint() {
    // Every component of the effective policy identity must partition the
    // budget. Two Services that resolve to the same pods, two ports of one
    // Service, and two subsets each keep their own ceiling — the exact
    // false-sharing failure a host:port key produces.
    let limiter = BackendActiveRequestLimiter::new();
    let held = vec![
        limiter
            .try_acquire(scope("default", "reviews", 9080, None), Some(1))
            .expect("baseline")
            .expect("permit"),
        limiter
            .try_acquire(scope("payments", "reviews", 9080, None), Some(1))
            .expect("another namespace has its own budget")
            .expect("permit"),
        limiter
            .try_acquire(scope("default", "ratings", 9080, None), Some(1))
            .expect("another logical destination has its own budget")
            .expect("permit"),
        limiter
            .try_acquire(scope("default", "reviews", 9081, None), Some(1))
            .expect("another policy port has its own budget")
            .expect("permit"),
        limiter
            .try_acquire(scope("default", "reviews", 9080, Some("v1")), Some(1))
            .expect("a named subset has its own budget")
            .expect("permit"),
        limiter
            .try_acquire(scope("default", "reviews", 9080, Some("v2")), Some(1))
            .expect("a sibling subset has its own budget")
            .expect("permit"),
    ];
    assert_eq!(held.len(), 6);
    assert_eq!(limiter.resident_lanes(), 6);
    for scope_at_cap in [
        scope("default", "reviews", 9080, None),
        scope("default", "reviews", 9080, Some("v1")),
    ] {
        limiter
            .try_acquire(scope_at_cap, Some(1))
            .expect_err("each isolated lane is still at its own cap");
    }
    drop(held);
    assert_eq!(
        limiter.resident_lanes(),
        0,
        "every lane must retire when its last permit releases"
    );
}

#[test]
fn a_hostile_subset_name_cannot_forge_another_lane() {
    // The subset component is length-prefixed, so a name carrying the key
    // delimiter cannot collide with the unmatched-destination lane or a sibling.
    let limiter = BackendActiveRequestLimiter::new();
    let _hostile = limiter
        .try_acquire(
            scope("default", "reviews", 9080, Some("v1|9080|n")),
            Some(1),
        )
        .expect("hostile subset name admitted into its own lane")
        .expect("permit");
    let _unmatched = limiter
        .try_acquire(scope("default", "reviews", 9080, None), Some(1))
        .expect("the unmatched-destination lane is untouched")
        .expect("permit");
    let _sibling = limiter
        .try_acquire(scope("default", "reviews", 9080, Some("v1")), Some(1))
        .expect("the real v1 lane is untouched")
        .expect("permit");
    assert_eq!(limiter.resident_lanes(), 3);
}

#[test]
fn a_reload_keeps_one_lane_and_applies_the_current_cap_to_old_permits() {
    // The request admitted before a reload must still consume the destination's
    // authoritative allowance. A generation-keyed lane would incorrectly let
    // the first post-reload request through and multiply the configured cap.
    let limiter = BackendActiveRequestLimiter::new();
    let pre_reload = limiter
        .try_acquire(scope("default", "reviews", 9080, None), Some(1))
        .expect("admitted before reload")
        .expect("permit");
    let unchanged = limiter
        .try_acquire(scope("default", "reviews", 9080, None), Some(1))
        .expect_err("an unrelated reload cannot mint another allowance");
    assert_eq!(unchanged.current, 1);
    assert_eq!(unchanged.cap, 1);
    assert_eq!(limiter.resident_lanes(), 1);

    let post_reload = limiter
        .try_acquire(scope("default", "reviews", 9080, None), Some(2))
        .expect("raising the reloaded cap takes effect on the shared lane")
        .expect("permit");
    assert_eq!(limiter.current(scope("default", "reviews", 9080, None)), 2);
    let lowered = limiter
        .try_acquire(scope("default", "reviews", 9080, None), Some(1))
        .expect_err("lowering the cap sheds while the shared count is above it");
    assert_eq!(lowered.current, 2);
    assert_eq!(lowered.cap, 1);

    drop(pre_reload);
    assert_eq!(
        limiter.current(scope("default", "reviews", 9080, None)),
        1,
        "the pre-reload guard releases from the shared lane"
    );
    drop(post_reload);
    assert_eq!(limiter.resident_lanes(), 0);
}

#[test]
fn removing_and_readding_a_cap_cannot_forget_active_old_permits() {
    let limiter = BackendActiveRequestLimiter::new();
    let pre_remove = limiter
        .try_acquire(reviews(None), Some(1))
        .expect("admitted before cap removal")
        .expect("permit");
    assert!(
        limiter
            .try_acquire(reviews(None), None)
            .expect("an uncapped reload does not acquire")
            .is_none()
    );
    assert_eq!(limiter.current(reviews(None)), 1);
    limiter
        .try_acquire(reviews(None), Some(1))
        .expect_err("a re-added cap still counts the pre-removal request");
    drop(pre_remove);
    let _after_drain = limiter
        .try_acquire(reviews(None), Some(1))
        .expect("the re-added cap admits after the old request drains")
        .expect("permit");
}

#[test]
fn a_shared_lane_stays_resident_until_the_last_permit_releases() {
    let limiter = BackendActiveRequestLimiter::new();
    let first = limiter
        .try_acquire(reviews(None), Some(2))
        .expect("first")
        .expect("permit");
    let second = limiter
        .try_acquire(reviews(None), Some(2))
        .expect("second")
        .expect("permit");
    assert_eq!(limiter.current(reviews(None)), 2);
    drop(first);
    assert_eq!(limiter.current(reviews(None)), 1);
    assert_eq!(
        limiter.resident_lanes(),
        1,
        "a still-active request keeps the lane resident"
    );
    drop(second);
    assert_eq!(limiter.resident_lanes(), 0);
}

#[test]
fn concurrent_attempts_never_exceed_the_destination_budget() {
    // Many connections / pool shards / frontends dispatching at once resolve to
    // ONE lane, so exactly `cap` of them can be active — the property a
    // per-connection SETTINGS value cannot provide.
    let limiter = Arc::new(BackendActiveRequestLimiter::new());
    let cap: u32 = 8;
    let granted = Arc::new(AtomicUsize::new(0));
    let held = Arc::new(std::sync::Mutex::new(Vec::new()));

    let mut handles = Vec::new();
    for _ in 0..64 {
        let limiter = Arc::clone(&limiter);
        let granted = Arc::clone(&granted);
        let held = Arc::clone(&held);
        handles.push(thread::spawn(move || {
            if let Ok(Some(permit)) = limiter.try_acquire(reviews(None), Some(cap)) {
                granted.fetch_add(1, Ordering::Relaxed);
                held.lock().expect("held lock").push(permit);
            }
        }));
    }
    for handle in handles {
        handle.join().expect("thread join");
    }

    assert_eq!(
        granted.load(Ordering::Relaxed),
        cap as usize,
        "exactly `cap` concurrent attempts may be active"
    );
    assert_eq!(limiter.current(reviews(None)), u64::from(cap));
    held.lock().expect("held lock").clear();
    assert_eq!(limiter.current(reviews(None)), 0);
    assert_eq!(limiter.resident_lanes(), 0);
}

#[test]
fn churn_leaves_no_stranded_lanes() {
    // Over-cap rejections racing the last release must not strand a zero-count
    // lane, and a drained destination must not stay resident: destination /
    // subset churn otherwise grows the map for the process lifetime.
    let limiter = Arc::new(BackendActiveRequestLimiter::new());
    let mut handles = Vec::new();
    for _ in 0..8 {
        let limiter = Arc::clone(&limiter);
        handles.push(thread::spawn(move || {
            for _ in 0..2_000 {
                if let Ok(Some(permit)) = limiter.try_acquire(reviews(None), Some(1)) {
                    for _ in 0..16 {
                        std::hint::spin_loop();
                    }
                    drop(permit);
                }
            }
        }));
    }
    for handle in handles {
        handle.join().expect("thread join");
    }
    assert_eq!(limiter.current(reviews(None)), 0);
    assert_eq!(limiter.resident_lanes(), 0);

    for destination_index in 0..1_000 {
        let destination = format!("reviews-{destination_index}");
        let permit = limiter
            .try_acquire(scope("default", &destination, 9080, None), Some(1))
            .expect("admitted")
            .expect("permit");
        drop(permit);
    }
    assert_eq!(
        limiter.resident_lanes(),
        0,
        "drained destination lanes must not accumulate"
    );
}

#[test]
fn exported_metrics_are_fixed_cardinality() {
    // Destination identity is operator-controlled and unbounded, so it must
    // never become a metric label; only the process totals are exported.
    let limiter = BackendActiveRequestLimiter::new();
    let probe = scope("tenant-a", "cardinality-probe", 8080, Some("v9"));
    let held = limiter
        .try_acquire(probe, Some(2))
        .expect("admitted")
        .expect("permit");
    let mut rendered = String::new();
    ferrum_edge::backend_active_request_limit::render_prometheus(&mut rendered, "");
    for family in [
        "ferrum_destination_active_requests",
        "ferrum_destination_active_requests_admitted_total",
        "ferrum_destination_active_requests_rejected_total",
    ] {
        assert!(
            rendered.contains(&format!("# TYPE {family} ")),
            "{family} must be exported: {rendered}"
        );
    }
    for identity in ["tenant-a", "cardinality-probe", "v9", "8080"] {
        assert!(
            !rendered.contains(identity),
            "destination identity `{identity}` must never appear as a label: {rendered}"
        );
    }
    drop(held);

    let mut labelled = String::new();
    ferrum_edge::backend_active_request_limit::render_prometheus(
        &mut labelled,
        ",gateway_namespace=\"edge\"",
    );
    assert!(
        labelled.contains("ferrum_destination_active_requests{gateway_namespace=\"edge\"}"),
        "the gateway namespace label must be applied verbatim: {labelled}"
    );
}
