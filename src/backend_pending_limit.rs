//! Per-destination backend HTTP/1.1 *in-flight-request* limiting for the
//! upstream-dispatch path.
//!
//! Enforces the Istio DestinationRule `connectionPool.http.http1MaxPendingRequests`
//! cap (materialized onto
//! `Upstream.port_overrides[port].http1_max_pending_requests`, see
//! [`crate::config::types::UpstreamPortOverride`]).
//!
//! # Honest reinterpretation — max concurrent in-flight H1 requests
//!
//! Envoy's `http1MaxPendingRequests` bounds the depth of the *pending queue*:
//! requests admitted but not yet assigned a connection slot. Ferrum dispatches
//! HTTP/1.1 over reqwest, whose `send().await` resolves when **response
//! headers** arrive — reqwest exposes **no connection-acquisition hook**, so a
//! slot held acquire-before-send / release-after-send unavoidably spans
//! connection-wait + request-upload + backend-TTFB, not the pending phase alone.
//! True pending-queue depth is therefore not implementable over reqwest.
//!
//! Mirroring how this repo honestly reinterprets DR `maxRetries` as a
//! per-request cap (see `docs/mesh.md`), this limiter reframes the knob as a
//! **max concurrent in-flight HTTP/1.1 requests per `(host, port)`** cap,
//! measured from dispatch to response-headers. When a destination is already at
//! its cap, the new request is shed immediately with a 503 ("upstream overflow"
//! in Envoy terms) instead of being queued unboundedly. This bounds H1
//! concurrency to a destination and approximates Envoy's overflow protection.
//!
//! # Scope — HTTP/1.1 reqwest dispatch only
//!
//! The field is named `http1MaxPendingRequests`, so this limiter is consumed
//! **only on the reqwest/HTTP-1.1 backend-dispatch path** in
//! `proxy_to_backend` (`src/proxy/mod.rs`), the path Ferrum uses for plain
//! HTTP/1.1 upstreams (and the H1 fallback when a backend does not negotiate
//! HTTP/2 — including a backend the capability registry has classified
//! H2/TLS-unsupported). It is acquired immediately before the request is
//! dispatched onto the shared reqwest client and released by its RAII guard the
//! moment dispatch returns (response headers arrived, or the dial failed). Under
//! the in-flight reinterpretation that release point is correct by definition:
//! the slot counts a request as in-flight from dispatch to response-headers, not
//! for the lifetime of the response stream. Because every H1-determined dispatch
//! is in-flight, there is **no body-shape exclusion** — bodyless GET/HEAD and
//! streamed-upload requests are capped alike.
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
//! - On the capped hit path the destination counter is looked up with a
//!   **borrowed `&str`** key built into a reused thread-local buffer (mirroring
//!   `backend_capabilities` / `pool` / `api_chargeback`): the `DashMap` is keyed
//!   by a flat `host|port` `String`, and `DashMap::get` accepts `&str` via
//!   `String: Borrow<str>`, so a repeat request to a known destination allocates
//!   nothing. Only the cold first request to a new destination allocates the
//!   owned key for the `entry` insert. This satisfies the hot-path no-alloc
//!   contract (the previous `host.to_string()` probe allocated per request).
//! - The counter map is a sharded [`dashmap::DashMap`] sized via
//!   [`crate::util::sharding::pool_shard_amount`]; counters are
//!   [`crossbeam_utils::CachePadded`] so a hot destination's count does not
//!   false-share with adjacent map slots.
//! - Acquisition uses a compare-exchange CAS loop so two concurrent requests
//!   can never both squeak past `cap - 1`.
//! - [`BackendPendingGuard`]'s `Drop` decrements exactly once on every dispatch
//!   exit (success, early return, error, task cancellation), so an in-flight
//!   slot can never leak and wedge a destination. When the count returns to
//!   zero, the guard also evicts the idle counter entry under the shard write
//!   lock, gated on `Arc::strong_count == 2` so an eviction can never race a
//!   concurrent re-acquirer (which would orphan a live counter and admit past
//!   the cap). That keeps wildcard upstreams, whose concrete host can come from
//!   request authority, from accumulating unbounded zero-count keys over the
//!   gateway lifetime.
//!
//! The implementation is deliberately a counting gate (a `CachePadded` atomic
//! with a try-increment CAS), not a `tokio::sync::Semaphore`: a semaphore would
//! block-and-queue an over-cap acquirer, but the desired Envoy "overflow"
//! semantics are to **reject immediately**, and a semaphore's per-destination
//! `Arc<Semaphore>` would need the same `DashMap` plumbing anyway. The atomic
//! counter gives lock-free, alloc-free try-acquire/reject on the request path.

use std::cell::RefCell;
use std::fmt::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crossbeam_utils::CachePadded;
use dashmap::DashMap;

thread_local! {
    /// Reused per-thread buffer for `(host, port)` counter-key lookups on the
    /// capped hot path. Mirrors the zero-allocation strategy of
    /// `backend_capabilities` / `pool` / `api_chargeback` so a repeat capped
    /// request to a known destination allocates nothing.
    static PENDING_KEY_BUF: RefCell<String> = RefCell::new(String::with_capacity(96));
}

/// Build the flat `host|port` counter-key for a destination into `buf`. `|` is
/// the codebase's pool-key delimiter; a bare host never contains it, so the
/// flat key is unambiguous and round-trips the `(host, port)` identity.
#[inline]
fn write_pending_key(buf: &mut String, host: &str, port: u16) {
    buf.push_str(host);
    buf.push('|');
    let _ = write!(buf, "{port}");
}

/// Shared per-destination pending-request counter map.
///
/// Keyed by a flat `host|port` `String` (an owned key survives DNS-cache
/// refreshes and target rotation without reborrowing from the
/// `Proxy`/`UpstreamTarget`) and looked up on the hit path by borrowed `&str`
/// via `String: Borrow<str>`, so the capped hot path allocates nothing on a
/// repeat request.
///
/// One instance lives on `ProxyState` and is shared across every reqwest/H1
/// dispatch for the gateway lifetime, so the cap bounds concurrent in-flight
/// requests per `(host, port)` across all proxies that dial the same
/// destination — matching how the cap is materialized per upstream destination
/// port rather than per proxy.
pub struct BackendPendingLimiter {
    inner: Arc<DashMap<String, Arc<BackendPendingCounter>>>,
}

#[derive(Debug)]
struct BackendPendingCounter {
    key: String,
    count: CachePadded<AtomicU64>,
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
    /// handle. Two-phase: a borrowed-`&str` read first (the flat key is built
    /// into a reused thread-local buffer, so the hit path allocates nothing),
    /// falling back to the owned-key entry API only on the (cold) first request
    /// to a new destination.
    fn counter_for(&self, host: &str, port: u16) -> Arc<BackendPendingCounter> {
        PENDING_KEY_BUF.with(|buf| {
            let mut buf = buf.borrow_mut();
            buf.clear();
            write_pending_key(&mut buf, host, port);
            // Hit path: borrowed `&str` lookup (`String: Borrow<str>`), no alloc.
            if let Some(existing) = self.inner.get(buf.as_str()) {
                return existing.clone();
            }
            // Cold path: a new destination — allocate the owned key once.
            self.inner
                .entry(buf.clone())
                .or_insert_with(|| {
                    Arc::new(BackendPendingCounter {
                        key: buf.clone(),
                        count: CachePadded::new(AtomicU64::new(0)),
                    })
                })
                .clone()
        })
    }

    /// Try to acquire one in-flight slot for `(host, port)`.
    ///
    /// * `Ok(None)` — no cap configured (`cap` is `None`). Hot path: a single
    ///   `Option` check, no `DashMap` touch, no counter held. The caller
    ///   dispatches unconditionally.
    /// * `Ok(Some(guard))` — a slot was reserved. The returned guard's `Drop`
    ///   releases it. The caller holds the guard only for the in-flight window
    ///   (dispatch until backend `send()` returns / response headers arrive).
    /// * `Err(BackendPendingLimitExceeded)` — the destination is at its
    ///   in-flight cap. The caller sheds the request with a 503 ("upstream
    ///   overflow").
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
        let cap_u64 = u64::from(cap);
        // A zero cap rejects unconditionally — reject BEFORE touching the map.
        // `try_acquire` never hands out a guard for a zero cap, so the drop-time
        // eviction can never fire for it; creating a counter here would leave a
        // permanent zero-count entry per unique host (the exact unbounded growth
        // this limiter guards against). `http1MaxPendingRequests: 0` is rejected
        // at translate time, so production never reaches this; it is defensive.
        if cap_u64 == 0 {
            return Err(BackendPendingLimitExceeded { current: 0, cap: 0 });
        }
        let counter = self.counter_for(host, port);
        loop {
            let current = counter.count.load(Ordering::Relaxed);
            if current >= cap_u64 {
                return Err(BackendPendingLimitExceeded {
                    current,
                    cap: cap_u64,
                });
            }
            // compare-exchange-weak in a CAS loop: two concurrent acquirers can
            // never both pass `cap - 1`.
            match counter.count.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    return Ok(Some(BackendPendingGuard {
                        counters: Arc::clone(&self.inner),
                        counter,
                    }));
                }
                Err(_) => continue,
            }
        }
    }

    /// Current in-flight count for a destination. Test/metrics only — the hot
    /// path uses `try_acquire` directly.
    #[allow(dead_code)]
    pub fn current(&self, host: &str, port: u16) -> u64 {
        PENDING_KEY_BUF.with(|buf| {
            let mut buf = buf.borrow_mut();
            buf.clear();
            write_pending_key(&mut buf, host, port);
            self.inner
                .get(buf.as_str())
                .map(|c| c.count.load(Ordering::Relaxed))
                .unwrap_or(0)
        })
    }

    #[cfg(test)]
    fn resident_counters(&self) -> usize {
        self.inner.len()
    }
}

/// RAII guard that holds one in-flight slot for a destination and releases it
/// on drop. Hold this only for the in-flight window (dispatch until backend
/// `send()` returns / response headers arrive) so the count reflects requests
/// *currently in flight to the destination*, not the full response-stream
/// lifetime.
#[derive(Debug)]
pub struct BackendPendingGuard {
    counters: Arc<DashMap<String, Arc<BackendPendingCounter>>>,
    counter: Arc<BackendPendingCounter>,
}

impl Drop for BackendPendingGuard {
    fn drop(&mut self) {
        // Straight `fetch_sub`, not `saturating_sub`: a `saturating_sub` would
        // silently mask a double-release / missing-acquire bug. The test suite
        // asserts the count returns to zero so any guard-lifetime regression
        // surfaces immediately.
        //
        // When this drop returns the count to zero, evict the idle entry so a
        // wildcard-host spray cannot retain unbounded zero-count keys. The
        // `remove_if` predicate runs under the DashMap shard write lock, which
        // makes the three checks a consistent snapshot:
        //   * `Arc::ptr_eq` — the mapped counter is still the exact one this
        //     guard held (not a fresh entry a re-acquirer cold-path inserted
        //     after a previous eviction).
        //   * `Arc::strong_count(current) == 2` — only the map and THIS dropping
        //     guard reference the counter. A concurrent acquirer that already
        //     cloned this counter via `counter_for`'s borrowed `get()` (but has
        //     not yet CAS-incremented) holds a third strong ref, so the count is
        //     left intact and that acquirer keeps using the still-mapped counter.
        //     Without this guard the eviction could race such an acquirer: the
        //     entry would be removed, the acquirer would increment an orphaned
        //     counter, a later request would cold-path a fresh entry, and the
        //     destination's in-flight count would split across two counters —
        //     silently admitting past the cap. An acquirer blocked on the shard
        //     lock behind this eviction has not cloned yet, so removing here is
        //     safe: its later `get()` misses and it cold-paths a fresh counter.
        //   * `count == 0` — defensive; guaranteed once `strong_count == 2` after
        //     a `1 -> 0` decrement (no other holder can have re-incremented).
        if self.counter.count.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.counters.remove_if(&self.counter.key, |_, current| {
                Arc::ptr_eq(current, &self.counter)
                    && Arc::strong_count(current) == 2
                    && current.count.load(Ordering::Acquire) == 0
            });
        }
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
        assert_eq!(
            limiter.resident_counters(),
            0,
            "no-cap path must not create resident counters"
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
        // A zero cap rejects without ever handing out a guard, so the drop-time
        // eviction can never fire. It must therefore not create a counter entry
        // at all — otherwise a unique-host spray at a zero-cap destination would
        // leave a permanent zero-count entry per host.
        assert_eq!(
            limiter.resident_counters(),
            0,
            "a zero cap must reject without creating a resident counter"
        );
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
    fn drop_removes_idle_counter_entry() {
        let limiter = BackendPendingLimiter::new();
        {
            let _g = limiter
                .try_acquire("ephemeral.example.com", 80, Some(1))
                .expect("slot acquired")
                .expect("guard present");
            assert_eq!(limiter.resident_counters(), 1);
        }

        assert_eq!(limiter.current("ephemeral.example.com", 80), 0);
        assert_eq!(
            limiter.resident_counters(),
            0,
            "idle counters must be evicted so wildcard hosts cannot grow the map forever"
        );
    }

    #[test]
    fn unique_hosts_do_not_leave_resident_zero_count_entries() {
        let limiter = BackendPendingLimiter::new();

        for i in 0..1_000 {
            let host = format!("a{i}.example.com");
            let guard = limiter
                .try_acquire(&host, 80, Some(1))
                .expect("slot acquired")
                .expect("guard present");
            drop(guard);
            assert_eq!(limiter.current(&host, 80), 0);
        }

        assert_eq!(
            limiter.resident_counters(),
            0,
            "completed unique wildcard hosts must not leave resident limiter keys"
        );
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

    #[test]
    fn shared_destination_entry_stays_until_last_guard_drops() {
        // The drop-time eviction must fire only when the LAST holder releases.
        // A second slot still held keeps the entry resident (count > 0); a
        // `remove_if` that evicted while a holder remained would drop a live
        // destination's counter and lose its in-flight accounting.
        let limiter = BackendPendingLimiter::new();
        let g1 = limiter
            .try_acquire("shared.example.com", 80, Some(2))
            .expect("first under cap")
            .expect("guard present");
        let g2 = limiter
            .try_acquire("shared.example.com", 80, Some(2))
            .expect("second under cap")
            .expect("guard present");
        assert_eq!(limiter.resident_counters(), 1);

        drop(g1);
        assert_eq!(
            limiter.resident_counters(),
            1,
            "a still-held slot must keep the destination counter resident"
        );
        assert_eq!(limiter.current("shared.example.com", 80), 1);

        drop(g2);
        assert_eq!(
            limiter.resident_counters(),
            0,
            "the last release must evict the now-idle counter"
        );
        assert_eq!(limiter.current("shared.example.com", 80), 0);
    }

    #[test]
    fn concurrent_evict_and_acquire_never_double_admits() {
        // Regression for the eviction-vs-acquire race the `Arc::strong_count`
        // guard in `BackendPendingGuard::drop` closes. With `cap == 1` every
        // successful acquire takes the counter 0 -> 1 and every drop takes it
        // 1 -> 0, so an idle-entry eviction constantly races a concurrent
        // acquirer that has already cloned the SAME counter via `counter_for`'s
        // borrowed `get()` but has not yet CAS-incremented. Without the
        // strong-count guard the eviction would drop that counter from the map,
        // the racing acquirer would bump an orphaned counter, a later request
        // would cold-path a fresh entry, and the destination would carry two
        // live holders past a cap of one. Assert simultaneously-held guards never
        // exceed the cap.
        use std::sync::atomic::AtomicUsize;
        use std::thread;

        let limiter = Arc::new(BackendPendingLimiter::new());
        let cap: u32 = 1;
        let live = Arc::new(AtomicUsize::new(0));
        let max_live = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for _ in 0..8 {
            let limiter = Arc::clone(&limiter);
            let live = Arc::clone(&live);
            let max_live = Arc::clone(&max_live);
            handles.push(thread::spawn(move || {
                for _ in 0..4_000 {
                    if let Ok(Some(guard)) = limiter.try_acquire("hot.example.com", 80, Some(cap)) {
                        let now = live.fetch_add(1, Ordering::AcqRel) + 1;
                        max_live.fetch_max(now, Ordering::AcqRel);
                        // Widen the hold window without a wall-clock sleep so a
                        // racing acquirer can overlap if the cap ever leaks.
                        for _ in 0..24 {
                            std::hint::spin_loop();
                        }
                        live.fetch_sub(1, Ordering::AcqRel);
                        drop(guard);
                    }
                }
            }));
        }
        for h in handles {
            h.join().expect("thread join");
        }

        assert!(
            max_live.load(Ordering::Acquire) <= cap as usize,
            "in-flight cap exceeded under concurrent eviction churn (observed {} \
             simultaneous holders for cap {}): an idle-entry eviction orphaned a \
             live counter",
            max_live.load(Ordering::Acquire),
            cap
        );
        assert_eq!(
            limiter.current("hot.example.com", 80),
            0,
            "all guards released — the count must be zero"
        );
        assert_eq!(
            limiter.resident_counters(),
            0,
            "the idle destination must be evicted once all churn completes"
        );
    }
}
