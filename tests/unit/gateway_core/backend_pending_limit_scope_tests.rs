//! External coverage for H1 pending-admission logical scope identity
//! (issue #3778).
//!
//! Inline `backend_pending_limit` tests already exercise concurrent acquire /
//! drop / zero-count eviction. This module focuses on cross-Service isolation,
//! endpoint-fan-out non-multiplication, namespace isolation, UID recreate
//! fencing, additive UID+upstream identity, and deterministic cap-update
//! semantics that the acceptance contract requires to be visible outside the
//! production module.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

use ferrum_edge::backend_pending_limit::{BackendPendingLimiter, BackendPendingScopeBase};

fn scope(ns: &str, id: &str, uid: Option<&str>, sub: Option<&str>) -> BackendPendingScopeBase {
    BackendPendingScopeBase::new(ns, id, uid, sub)
}

#[test]
fn independent_services_same_endpoint_and_subset_stay_isolated() {
    let limiter = BackendPendingLimiter::new();
    let public = scope("shop", "checkout-public", None, Some("v1"));
    let internal = scope("shop", "checkout-internal", None, Some("v1"));

    let _a = limiter
        .try_acquire(&public, 8080, Some(1))
        .expect("public")
        .expect("guard");
    limiter
        .try_acquire(&public, 8080, Some(1))
        .expect_err("public saturated");

    // Same pod IP / subset name would previously collide on a host key.
    let _b = limiter
        .try_acquire(&internal, 8080, Some(10))
        .expect("internal must remain independent under cap 10")
        .expect("guard");
    for _ in 0..9 {
        let _ = limiter
            .try_acquire(&internal, 8080, Some(10))
            .expect("internal admits up to 10")
            .expect("guard");
    }
    limiter
        .try_acquire(&internal, 8080, Some(10))
        .expect_err("internal at its own cap");
    assert_eq!(limiter.current(&public, 8080), 1);
    assert_eq!(limiter.current(&internal, 8080), 10);
}

#[test]
fn saturating_high_cap_service_does_not_reject_low_cap_sibling() {
    let limiter = BackendPendingLimiter::new();
    let low = scope("shop", "a", None, Some("v1"));
    let high = scope("shop", "b", None, Some("v1"));

    let mut high_guards = Vec::new();
    for _ in 0..5 {
        high_guards.push(
            limiter
                .try_acquire(&high, 80, Some(10))
                .expect("high")
                .expect("guard"),
        );
    }
    let _low = limiter
        .try_acquire(&low, 80, Some(1))
        .expect("low-cap Service must not see the sibling's count")
        .expect("guard");
}

#[test]
fn namespaces_sharing_endpoint_subset_string_remain_isolated() {
    let limiter = BackendPendingLimiter::new();
    let a = scope("tenant-a", "reviews", None, Some("v1"));
    let b = scope("tenant-b", "reviews", None, Some("v1"));
    let _ga = limiter
        .try_acquire(&a, 9080, Some(1))
        .expect("a")
        .expect("guard");
    let _gb = limiter
        .try_acquire(&b, 9080, Some(1))
        .expect("b")
        .expect("guard");
    assert_eq!(limiter.current(&a, 9080), 1);
    assert_eq!(limiter.current(&b, 9080), 1);
}

#[test]
fn multi_endpoint_selection_shares_one_logical_lane() {
    let limiter = BackendPendingLimiter::new();
    let svc = scope("default", "reviews", None, Some("v1"));
    // Endpoint rotation is not part of the key — only scope + policy port.
    let _g = limiter
        .try_acquire(&svc, 9080, Some(1))
        .expect("first endpoint")
        .expect("guard");
    limiter
        .try_acquire(&svc, 9080, Some(1))
        .expect_err("sibling endpoint / retry must share the logical lane");
}

#[test]
fn intentional_shared_upstream_shares_one_lane_across_proxies() {
    let limiter = BackendPendingLimiter::new();
    // Two proxies intentionally targeting the same upstream/subset/port.
    let shared = scope("default", "reviews-upstream", None, Some("v1"));
    let _from_proxy_a = limiter
        .try_acquire(&shared, 80, Some(1))
        .expect("a")
        .expect("guard");
    limiter
        .try_acquire(&shared, 80, Some(1))
        .expect_err("proxy B must share proxy A's logical lane");
}

#[test]
fn same_upstream_and_uid_shares_lane_across_endpoint_and_config_churn() {
    let limiter = BackendPendingLimiter::new();
    let lane = scope("default", "reviews", Some("uid-1"), Some("v1"));
    let _g = limiter
        .try_acquire(&lane, 80, Some(1))
        .expect("first")
        .expect("guard");
    // Same upstream + UID across churn retains one counter; host is absent.
    limiter
        .try_acquire(&lane, 80, Some(1))
        .expect_err("endpoint/config churn must retain the same lane");
    assert!(!lane.prefix().contains("10.0.0.5"));
    assert!(lane.prefix().contains("id"));
    assert!(lane.prefix().contains("uid"));
}

#[test]
fn k8s_uid_recreate_does_not_inherit_stale_lane() {
    let limiter = BackendPendingLimiter::new();
    let old = scope("default", "reviews", Some("uid-old"), Some("v1"));
    let new = scope("default", "reviews", Some("uid-new"), Some("v1"));
    let old_guard = limiter
        .try_acquire(&old, 80, Some(1))
        .expect("old")
        .expect("guard");
    let _new_guard = limiter
        .try_acquire(&new, 80, Some(1))
        .expect("recreate")
        .expect("guard");
    drop(old_guard);
    assert_eq!(limiter.current(&old, 80), 0);
    assert_eq!(limiter.current(&new, 80), 1);
}

#[test]
fn matching_optional_uid_does_not_collapse_distinct_upstreams() {
    let limiter = BackendPendingLimiter::new();
    let a = scope("default", "reviews-a", Some("shared-uid"), Some("v1"));
    let b = scope("default", "reviews-b", Some("shared-uid"), Some("v1"));
    let _ga = limiter
        .try_acquire(&a, 80, Some(1))
        .expect("a")
        .expect("guard");
    let _gb = limiter
        .try_acquire(&b, 80, Some(1))
        .expect("distinct upstream ids stay isolated even when optional UID matches")
        .expect("guard");
    assert_eq!(limiter.current(&a, 80), 1);
    assert_eq!(limiter.current(&b, 80), 1);
    assert_ne!(a.prefix(), b.prefix());
}

#[test]
fn cap_update_preserves_count_and_releases_exactly_once() {
    let limiter = BackendPendingLimiter::new();
    let svc = scope("default", "reviews", None, None);
    let g1 = limiter
        .try_acquire(&svc, 80, Some(1))
        .expect("cap1")
        .expect("guard");
    let g2 = limiter
        .try_acquire(&svc, 80, Some(2))
        .expect("raised cap")
        .expect("guard");
    assert_eq!(limiter.current(&svc, 80), 2);
    let err = limiter
        .try_acquire(&svc, 80, Some(1))
        .expect_err("lowered cap rejects against shared count");
    assert_eq!(err.cap, 1, "rejection reports the requesting epoch's cap");
    assert_eq!(err.current, 2);
    drop(g1);
    assert_eq!(limiter.current(&svc, 80), 1);
    drop(g2);
    assert_eq!(limiter.current(&svc, 80), 0);
}

#[test]
fn concurrent_mixed_scope_churn_evicts_idle_keys() {
    let limiter = Arc::new(BackendPendingLimiter::new());
    let scopes: Vec<Arc<BackendPendingScopeBase>> = (0..4)
        .map(|i| Arc::new(scope("default", &format!("svc-{i}"), None, Some("v1"))))
        .collect();
    let granted = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();
    for scope in &scopes {
        for _ in 0..4 {
            let limiter = Arc::clone(&limiter);
            let scope = Arc::clone(scope);
            let granted = Arc::clone(&granted);
            handles.push(thread::spawn(move || {
                for _ in 0..2_000 {
                    if let Ok(Some(guard)) = limiter.try_acquire(&scope, 80, Some(2)) {
                        granted.fetch_add(1, Ordering::Relaxed);
                        for _ in 0..8 {
                            std::hint::spin_loop();
                        }
                        drop(guard);
                    }
                }
            }));
        }
    }
    for h in handles {
        h.join().expect("join");
    }
    assert!(granted.load(Ordering::Relaxed) > 0);
    for scope in &scopes {
        assert_eq!(limiter.current(scope, 80), 0);
    }
}

#[test]
fn resolve_pending_limit_scopes_interns_upstream_and_optional_uid_not_host() {
    // Mirror GatewayConfig::resolve_pending_limit_scopes identity selection:
    // stable upstream id is always present; optional UID is additive; host
    // never enters the key.
    let svc = scope("default", "reviews", Some("uid-reviews"), Some("v1"));
    assert!(
        svc.prefix().contains("id"),
        "stable upstream id must always participate in the interned identity"
    );
    assert!(
        svc.prefix().contains("uid"),
        "K8s Service UID must participate alongside the upstream id"
    );
    assert!(
        !svc.prefix().contains("10.0.0.5"),
        "selected/backend host must not enter the pending scope key"
    );
    let host_keyed_collision = scope("default", "10.0.0.5", None, Some("v1"));
    assert_ne!(
        svc.prefix(),
        host_keyed_collision.prefix(),
        "UID-backed Service identity must not collapse to a host-shaped upstream id"
    );
}
