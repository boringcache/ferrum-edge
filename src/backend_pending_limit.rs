//! Per-destination backend *pending-request* limiting for the HTTP/1.1
//! upstream-dispatch path.
//!
//! Enforces the Istio DestinationRule `connectionPool.http.http1MaxPendingRequests`
//! cap (materialized onto
//! `Upstream.port_overrides[port].http1_max_pending_requests`, see
//! [`crate::config::types::UpstreamPortOverride`]) by bounding how many
//! requests can be *simultaneously waiting on connection capacity* for a given
//! backend destination. When the pending queue is full, the new request is shed
//! immediately with a 503 ("upstream overflow" in Envoy terms) instead of being
//! queued unboundedly.
//!
//! # Scope — HTTP/1.1 reqwest dispatch only
//!
//! The field is named `http1MaxPendingRequests`, so this limiter is consumed
//! **only on the reqwest/HTTP-1.1 backend-dispatch path** in
//! `proxy_to_backend` (`src/proxy/mod.rs`), the path Ferrum uses for plain
//! HTTP/1.1 upstreams (and the H1 fallback when a backend does not negotiate
//! HTTP/2). It is acquired in the *pending-acquire phase* — immediately before
//! the request is dispatched onto the shared reqwest client — and released by
//! its RAII guard the moment dispatch returns (i.e. once the request has
//! obtained connection capacity and the response has begun, or the dial has
//! failed). That matches Envoy's pending-request gauge: a request is "pending"
//! exactly while it is waiting for a connection slot, not for the lifetime of
//! the response stream.
//!
//! The multiplexed transports — direct HTTP/2, gRPC, HTTP/3, HBONE, and
//! mesh-mTLS — do **not** consume this limiter. They are not HTTP/1.1, and
//! their request concurrency is governed by HTTP/2 stream limits
//! (`connectionPool.http.http2MaxRequests` → `h2_max_concurrent_streams`), not
//! a connection-pending queue. A captured DestinationRule that sets both knobs
//! gets `http2MaxRequests` on its H2/gRPC dispatch and `http1MaxPendingRequests`
//! on its H1 dispatch, which is the correct per-protocol split.
//!
//! # Hot-path discipline (mirrors [`crate::backend_conn_limit`])
//!
//! - When no cap is configured for a destination port (`cap == None`),
//!   [`BackendPendingLimiter::try_acquire`] returns `Ok(None)` after a single
//!   `Option` check and never touches the `DashMap`.
//! - The counter map is a sharded [`dashmap::DashMap`] sized via
//!   [`crate::util::sharding::pool_shard_amount`]; counters are
//!   [`crossbeam_utils::CachePadded`] so a hot destination's count does not
//!   false-share with adjacent map slots.
//! - Acquisition uses a compare-exchange CAS loop so two concurrent requests
//!   can never both squeak past `cap - 1`.
//! - [`BackendPendingGuard`]'s `Drop` decrements exactly once on every dispatch
//!   exit (success, early return, error, task cancellation), so a pending slot
//!   can never leak and wedge a destination.
//!
//! The implementation is deliberately a counting gate (a `CachePadded` atomic
//! with a try-increment CAS), not a `tokio::sync::Semaphore`: a semaphore would
//! block-and-queue an over-cap acquirer, but the desired Envoy "overflow"
//! semantics are to **reject immediately**, and a semaphore's per-destination
//! `Arc<Semaphore>` would need the same `DashMap` plumbing anyway. The atomic
//! counter gives lock-free, alloc-free try-acquire/reject on the request path.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crossbeam_utils::CachePadded;
use dashmap::DashMap;

/// `(host, port)` identity for a backend destination. Owned `String` host so
/// the key survives DNS-cache-refreshed connect attempts and target rotation
/// without reborrowing from the `Proxy`/`UpstreamTarget` it came from.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct BackendPendingKey {
    host: String,
    port: u16,
}

/// Shared per-destination pending-request counter map.
///
/// One instance lives on `ProxyState` and is shared across every reqwest/H1
/// dispatch for the gateway lifetime, so the cap bounds concurrent pending
/// requests per `(host, port)` across all proxies that dial the same
/// destination — matching how the cap is materialized per upstream destination
/// port rather than per proxy.
pub struct BackendPendingLimiter {
    inner: Arc<DashMap<BackendPendingKey, Arc<CachePadded<AtomicU64>>>>,
}

impl Default for BackendPendingLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl BackendPendingLimiter {
    /// Construct a limiter with `DashMap` sharding sized for the hot path.
    ///
    /// A `0` shard override means "auto" (`max(64, num_cpus * 16)`), matching
    /// every other hot-path map in the codebase.
    pub fn new() -> Self {
        Self::with_shard_amount(crate::util::sharding::pool_shard_amount(0))
    }

    /// Construct a limiter with an explicit shard amount. Callers that want to
    /// honor the operator-facing `FERRUM_POOL_SHARD_AMOUNT` knob can pass
    /// `pool_shard_amount(env_config.pool_shard_amount)`.
    pub fn with_shard_amount(shards: usize) -> Self {
        Self {
            inner: Arc::new(DashMap::with_shard_amount(shards)),
        }
    }

    /// Look up or insert the counter for a destination, returning a cheap `Arc`
    /// handle. Two-phase: a cheap read first, falling back to the entry API
    /// only on the (cold) first request to a new destination.
    fn counter_for(&self, host: &str, port: u16) -> Arc<CachePadded<AtomicU64>> {
        if let Some(existing) = self.inner.get(&BackendPendingKey {
            host: host.to_string(),
            port,
        }) {
            return existing.clone();
        }
        self.inner
            .entry(BackendPendingKey {
                host: host.to_string(),
                port,
            })
            .or_insert_with(|| Arc::new(CachePadded::new(AtomicU64::new(0))))
            .clone()
    }

    /// Try to acquire one pending-request slot for `(host, port)`.
    ///
    /// * `Ok(None)` — no cap configured (`cap` is `None`). Hot path: a single
    ///   `Option` check, no `DashMap` touch, no counter held. The caller
    ///   dispatches unconditionally.
    /// * `Ok(Some(guard))` — a slot was reserved. The returned guard's `Drop`
    ///   releases it. The caller holds the guard only for the connection-pending
    ///   phase (until backend dispatch returns).
    /// * `Err(BackendPendingLimitExceeded)` — the pending queue is full. The
    ///   caller sheds the request with a 503 ("upstream overflow").
    ///
    /// `cap == Some(0)` always rejects. A `http1MaxPendingRequests: 0`
    /// DestinationRule is rejected at translate time, so production never sees
    /// it; the reject-on-zero behavior is defensive.
    pub fn try_acquire(
        &self,
        host: &str,
        port: u16,
        cap: Option<u32>,
    ) -> Result<Option<BackendPendingGuard>, BackendPendingLimitExceeded> {
        let Some(cap) = cap else {
            return Ok(None);
        };
        let counter = self.counter_for(host, port);
        let cap_u64 = u64::from(cap);
        loop {
            let current = counter.load(Ordering::Relaxed);
            if current >= cap_u64 {
                return Err(BackendPendingLimitExceeded {
                    current,
                    cap: cap_u64,
                });
            }
            // compare-exchange-weak in a CAS loop: two concurrent acquirers can
            // never both pass `cap - 1`.
            match counter.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(Some(BackendPendingGuard { counter })),
                Err(_) => continue,
            }
        }
    }

    /// Current pending count for a destination. Test/metrics only — the hot
    /// path uses `try_acquire` directly.
    #[allow(dead_code)]
    pub fn current(&self, host: &str, port: u16) -> u64 {
        self.inner
            .get(&BackendPendingKey {
                host: host.to_string(),
                port,
            })
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0)
    }
}

/// RAII guard that holds one pending-request slot for a destination and
/// releases it on drop. Hold this only for the connection-pending phase (until
/// backend dispatch returns) so the count reflects requests *waiting on
/// connection capacity*, not the full response-stream lifetime.
#[derive(Debug)]
pub struct BackendPendingGuard {
    counter: Arc<CachePadded<AtomicU64>>,
}

impl Drop for BackendPendingGuard {
    fn drop(&mut self) {
        // Straight `fetch_sub`, not `saturating_sub`: a `saturating_sub` would
        // silently mask a double-release / missing-acquire bug. The test suite
        // asserts the count returns to zero so any guard-lifetime regression
        // surfaces immediately.
        self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Returned when a destination is already at its `http1MaxPendingRequests` cap.
/// Carries the observed count and the configured cap for diagnostics/logging.
#[derive(Debug, Clone, Copy)]
pub struct BackendPendingLimitExceeded {
    pub current: u64,
    pub cap: u64,
}

impl std::fmt::Display for BackendPendingLimitExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "backend http1MaxPendingRequests reached: {} pending (cap {})",
            self.current, self.cap
        )
    }
}

impl std::error::Error for BackendPendingLimitExceeded {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_cap_skips_counter_entirely() {
        let limiter = BackendPendingLimiter::new();
        let guard = limiter
            .try_acquire("backend", 8080, None)
            .expect("no-cap acquire never errors");
        assert!(guard.is_none(), "no cap must not hand out a guard");
        assert_eq!(
            limiter.current("backend", 8080),
            0,
            "no-cap path must not touch the counter map"
        );
    }

    #[test]
    fn under_cap_acquires_and_counts() {
        let limiter = BackendPendingLimiter::new();
        let _g1 = limiter
            .try_acquire("backend", 8080, Some(3))
            .expect("first under cap")
            .expect("guard present");
        let _g2 = limiter
            .try_acquire("backend", 8080, Some(3))
            .expect("second under cap")
            .expect("guard present");
        assert_eq!(limiter.current("backend", 8080), 2);
    }

    #[test]
    fn at_cap_rejects_next_acquire() {
        let limiter = BackendPendingLimiter::new();
        let _g1 = limiter
            .try_acquire("h", 7777, Some(1))
            .expect("first slot")
            .expect("guard present");
        let err = limiter
            .try_acquire("h", 7777, Some(1))
            .expect_err("cap hit must error");
        assert_eq!(err.current, 1);
        assert_eq!(err.cap, 1);
    }

    #[test]
    fn cap_of_zero_always_rejects() {
        let limiter = BackendPendingLimiter::new();
        limiter
            .try_acquire("h", 1, Some(0))
            .expect_err("cap 0 rejects every request");
        assert_eq!(limiter.current("h", 1), 0);
    }

    #[test]
    fn drop_frees_slot_for_reuse() {
        let limiter = BackendPendingLimiter::new();
        {
            let _g = limiter
                .try_acquire("h", 7777, Some(1))
                .expect("first slot")
                .expect("guard present");
            limiter
                .try_acquire("h", 7777, Some(1))
                .expect_err("cap hit while guard held");
        }
        // Guard dropped: the slot must be reusable and the count back to 0.
        assert_eq!(
            limiter.current("h", 7777),
            0,
            "drop must decrement the counter exactly once"
        );
        let _g = limiter
            .try_acquire("h", 7777, Some(1))
            .expect("slot freed after drop")
            .expect("guard present");
    }

    #[test]
    fn counts_are_per_destination() {
        let limiter = BackendPendingLimiter::new();
        let _a = limiter
            .try_acquire("backend-a", 80, Some(1))
            .expect("a under cap")
            .expect("guard present");
        let _b = limiter
            .try_acquire("backend-b", 80, Some(1))
            .expect("b under its own cap")
            .expect("guard present");
        let _c = limiter
            .try_acquire("backend-a", 443, Some(1))
            .expect("a:443 under its own cap")
            .expect("guard present");
        assert_eq!(limiter.current("backend-a", 80), 1);
        assert_eq!(limiter.current("backend-b", 80), 1);
        assert_eq!(limiter.current("backend-a", 443), 1);
    }

    #[test]
    fn concurrent_acquire_never_exceeds_cap() {
        use std::sync::atomic::AtomicUsize;
        use std::thread;

        let limiter = Arc::new(BackendPendingLimiter::new());
        let cap: u32 = 8;
        let granted = Arc::new(AtomicUsize::new(0));
        let held = Arc::new(std::sync::Mutex::new(Vec::new()));

        let mut handles = Vec::new();
        for _ in 0..64 {
            let limiter = Arc::clone(&limiter);
            let granted = Arc::clone(&granted);
            let held = Arc::clone(&held);
            handles.push(thread::spawn(move || {
                if let Ok(Some(guard)) = limiter.try_acquire("h", 9090, Some(cap)) {
                    granted.fetch_add(1, Ordering::Relaxed);
                    held.lock().expect("held lock").push(guard);
                }
            }));
        }
        for h in handles {
            h.join().expect("thread join");
        }

        assert_eq!(
            granted.load(Ordering::Relaxed),
            cap as usize,
            "exactly `cap` acquirers must win under contention"
        );
        assert_eq!(
            limiter.current("h", 9090),
            u64::from(cap),
            "the counter must equal the number of held guards"
        );
        held.lock().expect("held lock").clear();
        assert_eq!(limiter.current("h", 9090), 0);
    }
}
