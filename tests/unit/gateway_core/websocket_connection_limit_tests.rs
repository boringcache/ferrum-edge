use std::sync::Arc;
use std::sync::atomic::Ordering;

use ferrum_edge::proxy::{
    PerIpWebSocketLimitExceeded, try_acquire_per_ip_websocket_session,
    try_acquire_websocket_connection_permit,
};

#[test]
fn websocket_connection_permit_is_optional() {
    let permit = try_acquire_websocket_connection_permit(None).unwrap();
    assert!(permit.is_none());
}

#[test]
fn websocket_connection_permit_rejects_when_limit_is_exhausted() {
    let limit = Arc::new(tokio::sync::Semaphore::new(1));
    let _first = try_acquire_websocket_connection_permit(Some(&limit))
        .unwrap()
        .expect("first permit should be available");

    let second = try_acquire_websocket_connection_permit(Some(&limit));
    assert!(second.is_err(), "second permit should be rejected");
}

#[test]
fn per_ip_websocket_session_is_disabled_when_unconfigured() {
    let guard = try_acquire_per_ip_websocket_session(None, "198.51.100.1", 1).unwrap();
    assert!(guard.is_none());
}

#[test]
fn per_ip_websocket_session_is_disabled_when_max_is_zero() {
    let counts = Arc::new(dashmap::DashMap::new());
    let guard = try_acquire_per_ip_websocket_session(Some(&counts), "198.51.100.1", 0).unwrap();
    assert!(guard.is_none());
    assert!(counts.is_empty());
}

#[test]
fn per_ip_websocket_session_rejects_when_limit_is_exhausted() {
    let counts = Arc::new(dashmap::DashMap::new());
    let first = try_acquire_per_ip_websocket_session(Some(&counts), "198.51.100.1", 1)
        .unwrap()
        .expect("first session should be admitted");
    assert_eq!(
        counts
            .get("198.51.100.1")
            .expect("counter exists")
            .load(Ordering::Relaxed),
        1
    );

    let second = try_acquire_per_ip_websocket_session(Some(&counts), "198.51.100.1", 1);
    assert_eq!(second.unwrap_err(), PerIpWebSocketLimitExceeded);
    assert_eq!(
        counts
            .get("198.51.100.1")
            .expect("counter exists")
            .load(Ordering::Relaxed),
        1,
        "rejected acquire must not leak a slot"
    );

    drop(first);
    assert_eq!(
        counts
            .get("198.51.100.1")
            .expect("counter exists")
            .load(Ordering::Relaxed),
        0
    );
}

#[test]
fn per_ip_websocket_session_is_enforced_independently_per_source() {
    let counts = Arc::new(dashmap::DashMap::new());
    let _first = try_acquire_per_ip_websocket_session(Some(&counts), "198.51.100.1", 1)
        .unwrap()
        .expect("first source should be admitted");

    let other = try_acquire_per_ip_websocket_session(Some(&counts), "198.51.100.2", 1)
        .unwrap()
        .expect("second source should still be admitted");
    assert_eq!(
        counts
            .get("198.51.100.1")
            .expect("first counter")
            .load(Ordering::Relaxed),
        1
    );
    assert_eq!(
        counts
            .get("198.51.100.2")
            .expect("second counter")
            .load(Ordering::Relaxed),
        1
    );
    drop(other);
}

#[test]
fn per_ip_websocket_session_slot_is_reusable_after_release() {
    let counts = Arc::new(dashmap::DashMap::new());
    let first = try_acquire_per_ip_websocket_session(Some(&counts), "198.51.100.1", 1)
        .unwrap()
        .expect("first session should be admitted");
    drop(first);

    let reused = try_acquire_per_ip_websocket_session(Some(&counts), "198.51.100.1", 1)
        .unwrap()
        .expect("released slot should be reusable");
    drop(reused);
}
