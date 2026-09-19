// Registered from store.rs for access to the private publication seam.
use super::*;
use std::sync::Arc;

#[test]
fn saturation_is_sticky_and_never_wraps() {
    let mut local = Local::new();
    local.add(0, u64::MAX);
    local.add(0, 1);
    local.add(COUNTERS, 1);
    assert_eq!(local.values[0], u64::MAX);
    assert_eq!(local.values[OVERFLOW], 2);
}

#[test]
fn unregistered_and_exited_thread_tails_are_not_claimed_complete() {
    let before = snapshot();
    std::thread::spawn(|| {
        with_local(|local| local.add(0, 3));
        // Deliberately no publication: non-destructible TLS has a visible tail.
    })
    .join()
    .unwrap();
    let after = snapshot();
    assert!(after.registered_slots > before.registered_slots);
    assert!(after.unpublished_events > 0);
}

#[test]
fn reentrant_observation_is_lost_without_borrow_panic() {
    let before = LOST.load(Ordering::Relaxed);
    with_local(|_| with_local(|_| panic!("must not run while borrowed")));
    assert!(LOST.load(Ordering::Relaxed) > before);
}

#[test]
fn concurrent_publication_keeps_fields_from_one_generation() {
    let slot = Arc::new(Slot::new());
    let writer = Arc::clone(&slot);
    let thread = std::thread::spawn(move || {
        for generation in 1..1000 {
            let mut values = [0; COUNTERS];
            values[0] = generation;
            values[1] = generation;
            writer.publish(&values, generation);
        }
    });
    while !thread.is_finished() {
        if let Some((values, _)) = slot.capture() {
            assert_eq!(values[0], values[1]);
        }
    }
    thread.join().unwrap();
}

#[test]
fn registration_exhaustion_and_busy_snapshot_are_bounded() {
    let slots = [Slot::new(), Slot::new()];
    assert_eq!(register(&slots), Some(0));
    assert_eq!(register(&slots), Some(1));
    assert_eq!(register(&slots), None);
    slots[0].sequence.store(1, Ordering::SeqCst);
    assert!(slots[0].capture().is_none());
    slots[0].sequence.store(2, Ordering::SeqCst);
    assert!(slots[0].capture().is_some());
}

#[test]
fn publication_version_exhaustion_is_reported_without_wrapping() {
    let slot = Slot::new();
    slot.sequence.store(u64::MAX - 1, Ordering::SeqCst);
    let before = LOST.load(Ordering::Relaxed);
    slot.publish(&[0; COUNTERS], 1);
    assert_eq!(slot.sequence.load(Ordering::SeqCst), u64::MAX - 1);
    assert!(LOST.load(Ordering::Relaxed) > before);
}
