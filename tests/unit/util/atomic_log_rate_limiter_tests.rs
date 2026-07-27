use ferrum_edge::_test_support::{
    atomic_log_rate_limiter_dual_gate_emit_for_test, atomic_log_rate_limiter_on_event_for_test,
    atomic_log_rate_limiter_reset_for_test, atomic_log_rate_limiter_seed_for_test,
    atomic_log_rate_limiter_suppressed_count_for_test, atomic_log_rate_limiter_with_window_for_test,
};
use ferrum_edge::util::atomic_log_rate_limiter::DEFAULT_ATOMIC_LOG_RATE_LIMIT_WINDOW_MS;
use std::sync::Arc;
use std::thread;

#[test]
fn first_event_emits_with_zero_suppressed() {
    let limiter = atomic_log_rate_limiter_with_window_for_test(
        DEFAULT_ATOMIC_LOG_RATE_LIMIT_WINDOW_MS,
    );
    assert_eq!(atomic_log_rate_limiter_on_event_for_test(&limiter, 0), Some(0));
}

#[test]
fn suppresses_within_window_then_summarizes() {
    let limiter = atomic_log_rate_limiter_with_window_for_test(
        DEFAULT_ATOMIC_LOG_RATE_LIMIT_WINDOW_MS,
    );
    assert_eq!(atomic_log_rate_limiter_on_event_for_test(&limiter, 0), Some(0));
    for t in [1, 100, 500, 999] {
        assert_eq!(atomic_log_rate_limiter_on_event_for_test(&limiter, t), None);
    }
    assert_eq!(
        atomic_log_rate_limiter_on_event_for_test(&limiter, 1_000),
        Some(4)
    );
    assert_eq!(atomic_log_rate_limiter_on_event_for_test(&limiter, 1_001), None);
    assert_eq!(
        atomic_log_rate_limiter_on_event_for_test(&limiter, 2_000),
        Some(1)
    );
}

#[test]
fn non_advancing_clock_suppresses_after_first() {
    let limiter = atomic_log_rate_limiter_with_window_for_test(
        DEFAULT_ATOMIC_LOG_RATE_LIMIT_WINDOW_MS,
    );
    assert_eq!(atomic_log_rate_limiter_on_event_for_test(&limiter, 42), Some(0));
    for _ in 0..1_000 {
        assert_eq!(atomic_log_rate_limiter_on_event_for_test(&limiter, 42), None);
    }
}

#[test]
fn suppressed_count_saturates() {
    let limiter = atomic_log_rate_limiter_with_window_for_test(
        DEFAULT_ATOMIC_LOG_RATE_LIMIT_WINDOW_MS,
    );
    atomic_log_rate_limiter_seed_for_test(&limiter, 0, u64::MAX);
    assert_eq!(atomic_log_rate_limiter_on_event_for_test(&limiter, 10), None);
    assert_eq!(
        atomic_log_rate_limiter_suppressed_count_for_test(&limiter),
        u64::MAX,
        "saturating add must not wrap"
    );
    assert_eq!(
        atomic_log_rate_limiter_on_event_for_test(
            &limiter,
            DEFAULT_ATOMIC_LOG_RATE_LIMIT_WINDOW_MS,
        ),
        Some(u64::MAX)
    );
}

#[test]
fn dual_gate_rolls_back_instance_claim_when_global_denies() {
    let first_instance = atomic_log_rate_limiter_with_window_for_test(
        DEFAULT_ATOMIC_LOG_RATE_LIMIT_WINDOW_MS,
    );
    let late_instance = atomic_log_rate_limiter_with_window_for_test(
        DEFAULT_ATOMIC_LOG_RATE_LIMIT_WINDOW_MS,
    );
    let global = atomic_log_rate_limiter_with_window_for_test(
        DEFAULT_ATOMIC_LOG_RATE_LIMIT_WINDOW_MS,
    );
    atomic_log_rate_limiter_reset_for_test(&first_instance);
    atomic_log_rate_limiter_reset_for_test(&late_instance);
    atomic_log_rate_limiter_reset_for_test(&global);

    assert_eq!(
        atomic_log_rate_limiter_dual_gate_emit_for_test(&first_instance, &global, 0),
        Some((0, 0))
    );
    assert_eq!(
        atomic_log_rate_limiter_dual_gate_emit_for_test(&late_instance, &global, 0),
        None,
        "global within-window denial must not consume the late instance aggregate"
    );
    assert_eq!(
        atomic_log_rate_limiter_suppressed_count_for_test(&late_instance),
        1,
        "rolled-back instance claim must fold the rejection into suppressed"
    );
    assert_eq!(
        atomic_log_rate_limiter_suppressed_count_for_test(&global),
        1,
        "global must still record the rejection"
    );
}

#[test]
fn concurrent_events_keep_bounded_emits_and_preserved_accounting() {
    let limiter = Arc::new(atomic_log_rate_limiter_with_window_for_test(
        DEFAULT_ATOMIC_LOG_RATE_LIMIT_WINDOW_MS,
    ));
    let mut handles = Vec::new();
    for _ in 0..8 {
        let limiter = Arc::clone(&limiter);
        handles.push(thread::spawn(move || {
            let mut emissions = 0usize;
            for _ in 0..2_000 {
                if atomic_log_rate_limiter_on_event_for_test(&limiter, 1_000).is_some() {
                    emissions += 1;
                }
            }
            emissions
        }));
    }

    let emissions: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();
    assert_eq!(
        emissions, 1,
        "identical timestamps within one window must emit at most once"
    );
    assert_eq!(
        atomic_log_rate_limiter_suppressed_count_for_test(&limiter),
        8 * 2_000 - 1,
        "suppressed accounting must retain every non-winning rejection"
    );
}
