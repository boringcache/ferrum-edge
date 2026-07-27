//! Frontend-DTLS idle-watermark contract (GHSA-m9rp-jm6c-f65p).
//!
//! Rate-rejected (and otherwise policy-dropped) decrypted application
//! datagrams must not refresh the shared session activity timestamp that
//! `dtls_shared_idle_watchdog` / plain-UDP idle cleanup consult. Admitted
//! forwards and successful backend→client deliveries must refresh. Coverage
//! uses virtual monotonic timestamps — no wall clock, no network.

use std::sync::atomic::{AtomicU64, Ordering};

use ferrum_edge::_test_support::{
    maybe_touch_udp_idle_activity_for_test, udp_idle_activity_should_refresh_for_test,
    udp_idle_expired_for_test,
};

#[test]
fn policy_rejected_datagrams_must_not_refresh_idle_activity() {
    assert!(
        !udp_idle_activity_should_refresh_for_test(false, false),
        "rejected + no forward"
    );
    assert!(
        !udp_idle_activity_should_refresh_for_test(false, true),
        "rejected must not refresh even if a send somehow succeeded"
    );
    assert!(
        !udp_idle_activity_should_refresh_for_test(true, false),
        "admitted but failed forward/deliver must not refresh"
    );
    assert!(
        udp_idle_activity_should_refresh_for_test(true, true),
        "admitted + successful forward/deliver must refresh"
    );
}

#[test]
fn virtual_time_rejected_datagrams_cannot_pin_session_past_idle_timeout() {
    // Mirrors frontend-DTLS client→backend: shared watermark starts at session
    // accept; subsequent rate-rejected receives leave it unchanged.
    let idle_timeout_ms = 2_000;
    let activity = AtomicU64::new(1_000);
    let baseline = activity.load(Ordering::Relaxed);

    for tick in [1_500_u64, 2_000, 2_500, 2_900] {
        // Decrypt/receive + udp_rate_limiting Drop — no admission, no forward.
        maybe_touch_udp_idle_activity_for_test(&activity, tick, false, false);
        assert_eq!(
            activity.load(Ordering::Relaxed),
            baseline,
            "rejected application datagram at {tick}ms must leave watermark at {baseline}"
        );
        assert!(
            !udp_idle_expired_for_test(tick, activity.load(Ordering::Relaxed), idle_timeout_ms),
            "still inside idle window at {tick}ms"
        );
    }

    // Exactly idle_timeout after baseline is not expired (> timeout required).
    assert!(!udp_idle_expired_for_test(
        baseline + idle_timeout_ms,
        activity.load(Ordering::Relaxed),
        idle_timeout_ms
    ));
    // One millisecond past the timeout expires even though rejected traffic
    // kept arriving just before the boundary.
    assert!(udp_idle_expired_for_test(
        baseline + idle_timeout_ms + 1,
        activity.load(Ordering::Relaxed),
        idle_timeout_ms
    ));
}

#[test]
fn virtual_time_admitted_forward_and_reverse_delivery_refresh_idle_watermark() {
    let idle_timeout_ms = 5_000;
    let activity = AtomicU64::new(10_000);

    // Client→backend admitted forward (plain UDP backend or backend-DTLS).
    maybe_touch_udp_idle_activity_for_test(&activity, 11_000, true, true);
    assert_eq!(activity.load(Ordering::Relaxed), 11_000);
    assert!(!udp_idle_expired_for_test(
        15_000,
        activity.load(Ordering::Relaxed),
        idle_timeout_ms
    ));

    // Backend→client successful delivery refreshes again (both backend modes
    // share this watermark in the frontend-DTLS relay).
    maybe_touch_udp_idle_activity_for_test(&activity, 14_500, true, true);
    assert_eq!(activity.load(Ordering::Relaxed), 14_500);
    assert!(!udp_idle_expired_for_test(
        19_400,
        activity.load(Ordering::Relaxed),
        idle_timeout_ms
    ));
    assert!(udp_idle_expired_for_test(
        19_501,
        activity.load(Ordering::Relaxed),
        idle_timeout_ms
    ));
}

#[test]
fn virtual_time_amplification_or_plugin_drop_on_reverse_does_not_refresh() {
    let activity = AtomicU64::new(20_000);

    // Oversized / plugin-dropped reverse datagram: received but not delivered.
    maybe_touch_udp_idle_activity_for_test(&activity, 22_000, false, false);
    assert_eq!(activity.load(Ordering::Relaxed), 20_000);

    // Failed client delivery after admission must also leave the watermark.
    maybe_touch_udp_idle_activity_for_test(&activity, 23_000, true, false);
    assert_eq!(activity.load(Ordering::Relaxed), 20_000);
}

#[test]
fn idle_timeout_boundary_is_strictly_greater_than() {
    // Production predicate: elapsed > idle_timeout_ms (not >=).
    assert!(!udp_idle_expired_for_test(1_000, 1_000, 60_000));
    assert!(!udp_idle_expired_for_test(61_000, 1_000, 60_000));
    assert!(udp_idle_expired_for_test(61_001, 1_000, 60_000));
    // Backward monotonic step must not expire.
    assert!(!udp_idle_expired_for_test(500, 1_000, 60_000));
}

#[test]
fn rejected_keepalive_pattern_releases_session_slot_at_timeout_boundary() {
    // Reproduction shape from GHSA-m9rp-jm6c-f65p: exhaust rate budget, then
    // keep sending rejected datagrams inside the idle interval. With the fixed
    // refresh policy the watermark never moves, so max-session slots reclaim
    // at the first idle deadline.
    let idle_timeout_ms = 60_000;
    let session_start = 1_000_000_u64;
    let activity = AtomicU64::new(session_start);

    for rejected_at in [
        session_start + 10_000,
        session_start + 20_000,
        session_start + 30_000,
        session_start + 40_000,
        session_start + idle_timeout_ms - 100,
    ] {
        maybe_touch_udp_idle_activity_for_test(&activity, rejected_at, false, false);
        assert_eq!(activity.load(Ordering::Relaxed), session_start);
        assert!(
            !udp_idle_expired_for_test(rejected_at, session_start, idle_timeout_ms),
            "rejected keepalive at {rejected_at}ms must still be inside the original idle window"
        );
    }

    assert!(udp_idle_expired_for_test(
        session_start + idle_timeout_ms + 1,
        activity.load(Ordering::Relaxed),
        idle_timeout_ms
    ));
}
