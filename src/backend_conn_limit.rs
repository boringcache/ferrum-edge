//! Per-destination backend connection limiting for HTTP-family transports.
//!
//! Enforces the Istio DestinationRule `connectionPool.tcp.maxConnections`
//! cap (materialized onto `Upstream.port_overrides[port].max_connections`,
//! see [`crate::config::types::UpstreamPortOverride`]) for HTTP-family
//! backend transports whose connection lifecycle Ferrum actually owns.
//!
//! # Scope
//!
//! This limiter is consumed by the **WebSocket** dispatch path (H1/H2 in
//! `src/proxy/mod.rs` and H3 in `src/http3/websocket.rs`). A proxied
//! WebSocket session opens exactly one dedicated, non-pooled backend
//! TCP/TLS connection whose lifetime equals the session, so an RAII guard
//! held for the session duration bounds concurrent *open* connections per
//! destination target — the same semantics Envoy gives `maxConnections`,
//! and the same RAII pattern the raw-TCP path uses in
//! `src/proxy/tcp_proxy.rs` (`BackendInflightGuard`).
//!
//! The pooled, multiplexed HTTP-family transports (reqwest H1/H2, direct
//! H2, gRPC, HTTP/3, HBONE) do NOT consume this limiter. Their backend
//! connections are created and reused inside connection pools
//! (`src/connection_pool.rs`, `src/proxy/http2_pool.rs`,
//! `src/proxy/grpc_proxy.rs`, `src/proxy/hbone_pool.rs`,
//! `src/http3/client.rs`), so "open a new backend connection" is not an
//! event the request hot path observes — it is decoupled from the request
//! by pool reuse, sharding (`http2_connections_per_host`), and idle
//! eviction. Counting per request there would measure request concurrency
//! (Envoy's `http2MaxRequests` / `maxPendingRequests` territory, already
//! mapped via `h2_max_concurrent_streams`), not open connections, and
//! would risk decrement leaks across the streaming/retry/error exits.
//! See `docs/mesh.md` for the full rationale.
//!
//! # Hot-path discipline
//!
//! - When no cap is configured for a destination port (`cap == None`),
//!   [`BackendConnectionLimiter::try_acquire`] returns `Ok(None)` after a
//!   single `Option` check and never touches the `DashMap`. WebSocket
//!   upgrade is already a cold path relative to per-frame forwarding, and
//!   the per-frame relay never touches this limiter at all.
//! - The counter map is a sharded [`dashmap::DashMap`] sized via
//!   [`crate::util::sharding::pool_shard_amount`]; counters are
//!   [`crossbeam_utils::CachePadded`] so a hot destination's count does not
//!   false-share with adjacent map slots.
//! - Acquisition uses a compare-exchange CAS loop so two concurrent
//!   upgrades can never both squeak past `cap - 1`.
//! - [`BackendConnectionGuard`]'s `Drop` decrements exactly once on every
//!   session-end path (clean close, relay error, upgrade failure, task
//!   cancellation), so a connection slot can never leak and wedge a
//!   destination.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crossbeam_utils::CachePadded;
use dashmap::DashMap;

/// `(host, port)` identity for a backend destination. Owned `String` host so
/// the key survives DNS-cache-refreshed connect attempts and target rotation
/// without reborrowing from the `Proxy`/`UpstreamTarget` it came from.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct BackendConnKey {
    host: String,
    port: u16,
}

/// Shared per-destination open-connection counter map.
///
/// One instance lives on `ProxyState` and is shared across every HTTP-family
/// WebSocket dispatch for the gateway lifetime, so the cap bounds concurrent
/// open backend connections per `(host, port)` across all proxies that dial
/// the same destination — matching how the cap is materialized per upstream
/// destination port rather than per proxy.
pub struct BackendConnectionLimiter {
    inner: Arc<DashMap<BackendConnKey, Arc<CachePadded<AtomicU64>>>>,
}

impl Default for BackendConnectionLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl BackendConnectionLimiter {
    /// Construct a limiter with `DashMap` sharding sized for the hot path.
    ///
    /// A `0` shard override means "auto" (`max(64, num_cpus * 16)`), matching
    /// every other hot-path map in the codebase. WebSocket destinations are
    /// low-cardinality, but going through `pool_shard_amount` keeps the
    /// sizing contract uniform.
    pub fn new() -> Self {
        Self::with_shard_amount(crate::util::sharding::pool_shard_amount(0))
    }

    /// Construct a limiter with an explicit shard amount. Callers that want
    /// to honor the operator-facing `FERRUM_POOL_SHARD_AMOUNT` knob can pass
    /// `pool_shard_amount(env_config.pool_shard_amount)`.
    pub fn with_shard_amount(shards: usize) -> Self {
        Self {
            inner: Arc::new(DashMap::with_shard_amount(shards)),
        }
    }

    /// Look up or insert the counter for a destination, returning a cheap
    /// `Arc` handle. Two-phase: a cheap read first, falling back to the
    /// entry API only on the (cold) first request to a new destination.
    fn counter_for(&self, host: &str, port: u16) -> Arc<CachePadded<AtomicU64>> {
        if let Some(existing) = self.inner.get(&BackendConnKey {
            host: host.to_string(),
            port,
        }) {
            return existing.clone();
        }
        self.inner
            .entry(BackendConnKey {
                host: host.to_string(),
                port,
            })
            .or_insert_with(|| Arc::new(CachePadded::new(AtomicU64::new(0))))
            .clone()
    }

    /// Try to acquire one open-connection slot for `(host, port)`.
    ///
    /// * `Ok(None)` — no cap configured (`cap` is `None`). Hot path: a single
    ///   `Option` check, no `DashMap` touch, no counter held. The caller dials
    ///   the backend unconditionally.
    /// * `Ok(Some(guard))` — a slot was reserved. The returned guard's `Drop`
    ///   releases it. The caller must hold the guard for the full backend
    ///   connection lifetime (the WebSocket session).
    /// * `Err(BackendConnectionLimitExceeded)` — the cap is already reached.
    ///   The caller refuses the new connection (503-class).
    ///
    /// `cap == Some(0)` always rejects. A `maxConnections: 0` DestinationRule
    /// is rejected at translate time, so production never sees it; the
    /// reject-on-zero behavior is defensive and matches the raw-TCP path.
    pub fn try_acquire(
        &self,
        host: &str,
        port: u16,
        cap: Option<u32>,
    ) -> Result<Option<BackendConnectionGuard>, BackendConnectionLimitExceeded> {
        let Some(cap) = cap else {
            return Ok(None);
        };
        let counter = self.counter_for(host, port);
        let cap_u64 = u64::from(cap);
        loop {
            let current = counter.load(Ordering::Relaxed);
            if current >= cap_u64 {
                return Err(BackendConnectionLimitExceeded {
                    current,
                    cap: cap_u64,
                });
            }
            // compare-exchange-weak in a CAS loop: two concurrent acquirers
            // can never both pass `cap - 1`. A `fetch_add`/check/rollback
            // shape would have the same uncontended throughput but is harder
            // to reason about for correctness.
            match counter.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(Some(BackendConnectionGuard { counter })),
                Err(_) => continue,
            }
        }
    }

    /// Current open-connection count for a destination. Test/metrics only —
    /// the hot path uses `try_acquire` directly.
    #[allow(dead_code)]
    pub fn current(&self, host: &str, port: u16) -> u64 {
        self.inner
            .get(&BackendConnKey {
                host: host.to_string(),
                port,
            })
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0)
    }
}

/// RAII guard that holds one open-connection slot for a destination and
/// releases it on drop. Hold this for the full backend connection lifetime
/// (the WebSocket session) so the count reflects concurrent *open*
/// connections, not in-flight requests.
#[derive(Debug)]
pub struct BackendConnectionGuard {
    counter: Arc<CachePadded<AtomicU64>>,
}

impl Drop for BackendConnectionGuard {
    fn drop(&mut self) {
        // Straight `fetch_sub`, not `saturating_sub`: a `saturating_sub`
        // would silently mask a double-release / missing-acquire bug. The
        // test suite asserts the count returns to zero so any guard-lifetime
        // regression surfaces immediately.
        self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Returned when a destination is already at its `maxConnections` cap. Carries
/// the observed count and the configured cap for diagnostics/logging.
#[derive(Debug, Clone, Copy)]
pub struct BackendConnectionLimitExceeded {
    pub current: u64,
    pub cap: u64,
}

impl std::fmt::Display for BackendConnectionLimitExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "backend max_connections reached: {} open (cap {})",
            self.current, self.cap
        )
    }
}

impl std::error::Error for BackendConnectionLimitExceeded {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_cap_skips_counter_entirely() {
        let limiter = BackendConnectionLimiter::new();
        // `None` cap must return Ok(None) without inserting a counter.
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
        let limiter = BackendConnectionLimiter::new();
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
        let limiter = BackendConnectionLimiter::new();
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
        let limiter = BackendConnectionLimiter::new();
        limiter
            .try_acquire("h", 1, Some(0))
            .expect_err("cap 0 rejects every connection");
        assert_eq!(limiter.current("h", 1), 0);
    }

    #[test]
    fn drop_frees_slot_for_reuse() {
        let limiter = BackendConnectionLimiter::new();
        {
            let _g = limiter
                .try_acquire("h", 7777, Some(1))
                .expect("first slot")
                .expect("guard present");
            // At cap while the guard is alive.
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
        let limiter = BackendConnectionLimiter::new();
        let _a = limiter
            .try_acquire("backend-a", 80, Some(1))
            .expect("a under cap")
            .expect("guard present");
        // Different host with the same cap must not be blocked by `a`.
        let _b = limiter
            .try_acquire("backend-b", 80, Some(1))
            .expect("b under its own cap")
            .expect("guard present");
        // Different port on the same host is also its own bucket.
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

        let limiter = Arc::new(BackendConnectionLimiter::new());
        let cap: u32 = 8;
        let granted = Arc::new(AtomicUsize::new(0));
        // Keep granted guards alive for the duration so the cap is the only
        // thing bounding concurrency.
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
        // Releasing all guards must return the count to zero.
        held.lock().expect("held lock").clear();
        assert_eq!(limiter.current("h", 9090), 0);
    }
}
