use super::*;

#[test]
fn local_updates_publish_only_at_interval_and_flush_on_thread_exit() {
    let index = std::thread::spawn(|| {
        for _ in 0..PUBLICATION_INTERVAL - 1 {
            with_local(|local| local.add(Counter::PendingQueued as usize, 1));
        }
        let index = LOCAL.with(|local| local.borrow().slot.unwrap());
        assert_eq!(SLOTS[index].sequence.load(Ordering::SeqCst), 0);
        assert!(SLOTS[index].dirty.load(Ordering::SeqCst));
        with_local(|local| local.add(Counter::PendingQueued as usize, 1));
        assert_eq!(SLOTS[index].sequence.load(Ordering::SeqCst), 2);
        assert!(!SLOTS[index].dirty.load(Ordering::SeqCst));
        with_local(|local| local.add(Counter::PendingQueued as usize, 1));
        index
    })
    .join()
    .unwrap();
    let (values, dirty) = SLOTS[index].capture().unwrap();
    assert_eq!(
        values[Counter::PendingQueued as usize],
        PUBLICATION_INTERVAL + 1
    );
    assert!(!dirty, "TLS destructor publishes the terminal tail");
}

#[test]
fn atomic_publication_never_accepts_torn_fields() {
    let slot = std::sync::Arc::new(Slot::new());
    let writer = std::sync::Arc::clone(&slot);
    let task = std::thread::spawn(move || {
        for value in 1..100 {
            writer.publish(&[value; COUNTERS]);
        }
    });
    for _ in 0..1000 {
        if let Some((values, _)) = slot.capture() {
            assert!(values.iter().all(|value| *value == values[0]));
        }
    }
    task.join().unwrap();
}

#[test]
fn overflow_is_sticky_and_saturating() {
    let mut local = Local::new();
    local.add(Counter::PendingQueued as usize, u64::MAX);
    local.add(Counter::PendingQueued as usize, 1);
    assert_eq!(local.values[Counter::PendingQueued as usize], u64::MAX);
    assert_eq!(local.values[Counter::CounterOverflow as usize], 1);
    local.add(COUNTERS, 1);
    assert_eq!(local.values[Counter::CounterOverflow as usize], 2);
}
