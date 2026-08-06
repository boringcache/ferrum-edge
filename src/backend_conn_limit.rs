//! Per-destination backend connection limiting for HTTP-family transports.
//!
//! Enforces the Istio DestinationRule `connectionPool.tcp.maxConnections`
//! cap (materialized onto `Upstream.port_overrides[port].max_connections`,
//! see [`crate::config::types::UpstreamPortOverride`]) for HTTP-family
//! backend transports whose connection lifecycle Ferrum actually owns.
//!
//! # Scope
//!
//! This limiter is consumed by **every** backend transport whose physical
//! connection lifecycle Ferrum owns:
//!
//! * **Raw TCP / TCP+TLS stream proxy** (`src/proxy/tcp_proxy.rs`) — one
//!   dedicated backend socket per relay session.
//! * **WebSocket** dispatch (H1/H2 in `src/proxy/mod.rs`, H3 in
//!   `src/http3/websocket.rs`) — one dedicated, non-pooled backend TCP/TLS
//!   connection whose lifetime equals the session.
//! * **The pooled, multiplexed transports** — direct H2
//!   (`src/proxy/http2_pool.rs`), gRPC (`src/proxy/grpc_proxy.rs`), native
//!   HTTP/3 (`src/http3/client.rs`), HBONE (`src/proxy/hbone_pool.rs`), and
//!   Sidecar mesh-mTLS (`src/proxy/mesh_mtls_pool.rs`). Each acquires a
//!   [`SharedBackendConnectionGuard`] at the exact moment a new physical
//!   connection is about to be constructed and hands it to that connection's
//!   own driver (the spawned hyper/h2 connection task, or the pooled QUIC
//!   handle), so the slot retires exactly when the socket dies — handshake
//!   failure, idle eviction, pool drain, reload/update/delete, SVID rotation
//!   drain, or shutdown. Reuse of a pooled connection takes NO new slot, so
//!   an arbitrary number of multiplexed streams still share one admitted
//!   connection.
//! * **reqwest HTTP/1.1 and HTTP/2** — admitted at reqwest's connector, the
//!   one place a NEW physical socket is dialed (pooled reuse and multiplexed
//!   H2 streams never reach it), via the vendored
//!   `ClientBuilder::connection_admission` hook
//!   (`docs/upstream-reqwest-patches/003-connection-admission-hook/`). The
//!   token returned by [`ReqwestConnectionAdmission`] is owned by the
//!   resulting connection object, so the slot retires exactly when that socket
//!   dies — including an idle socket reqwest keeps after the request that
//!   opened it finished. Because ONE admission hook is shared by every
//!   `reqwest::Client` in the pool, all effective reqwest pool keys for a
//!   destination share the one ceiling.
//!
//! Keying is per resolved `(host, DestinationRule policy port)` endpoint, not
//! per logical cluster — a destination with N endpoint hosts sharing one port
//! has an effective ceiling of N×cap, which diverges from Envoy's per-cluster
//! total. For the typical single-host mesh destination the two are equivalent.
//! Every transport admits on the **policy** port
//! (`UpstreamTarget::dispatch_policy_port()`), never the dial/transport port,
//! so a `targetPort` remap and the mesh tunnel listeners (`:15008` / `:15006`)
//! all share the one destination lane instead of splitting the ceiling.
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
        self.acquire_slot(host, port, cap).map(Some)
    }

    /// Shared CAS admission used by both the optional-cap and the mandatory-cap
    /// entry points, so the two can never drift.
    fn acquire_slot(
        &self,
        host: &str,
        port: u16,
        cap: u32,
    ) -> Result<BackendConnectionGuard, BackendConnectionLimitExceeded> {
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
                Ok(_) => return Ok(BackendConnectionGuard { counter }),
                Err(_) => continue,
            }
        }
    }

    /// Reserve one slot and return a **shareable** guard.
    ///
    /// Pooled transports need the guard to outlive the function that opened
    /// the connection: it is moved into the spawned connection-driver task (or
    /// stored on the pooled connection handle) so the slot is released exactly
    /// when the physical connection dies. `Arc` also lets a DNS-candidate loop
    /// clone the reservation into each attempt without double-counting — every
    /// failed attempt drops its clone, and the count only stays held while some
    /// clone (i.e. some live connection driver) still exists.
    ///
    /// Unlike [`Self::try_acquire`] the cap is mandatory here: callers resolve
    /// "no cap configured" once, up front, and skip this call entirely.
    pub fn try_acquire_shared(
        &self,
        host: &str,
        port: u16,
        cap: u32,
    ) -> Result<SharedBackendConnectionGuard, BackendConnectionLimitExceeded> {
        self.acquire_slot(host, port, cap).map(Arc::new)
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

/// A [`BackendConnectionGuard`] that several holders can keep alive at once.
///
/// The slot is released when the LAST clone drops. Pooled transports clone one
/// reservation into every DNS-candidate attempt and move the surviving clone
/// into the connection's driver task, so "slot held" is exactly "a physical
/// backend connection is (or is being) established".
pub type SharedBackendConnectionGuard = Arc<BackendConnectionGuard>;

/// Shared handle to the one gateway-wide [`BackendConnectionLimiter`].
///
/// Pools store this behind a `OnceLock` that `ProxyState` installs at
/// construction, so a pool built without it (focused tests, standalone
/// callers) simply never enforces a cap.
pub type SharedBackendConnectionLimiter = Arc<BackendConnectionLimiter>;

/// A resolved `connectionPool.tcp.maxConnections` reservation source for one
/// about-to-be-constructed pooled backend connection.
///
/// Built once on the pool's cold connection-establishment path (never on the
/// per-request hot path) and borrowed for the duration of that establishment.
/// Constructing it is the "is a cap configured for this destination?" check, so
/// a `None` return means the transport dials unconditionally with zero further
/// work — no map touch, no allocation.
#[derive(Clone, Copy)]
pub struct PooledConnectionAdmission<'a> {
    limiter: &'a BackendConnectionLimiter,
    host: &'a str,
    policy_port: u16,
    cap: u32,
}

impl<'a> PooledConnectionAdmission<'a> {
    /// Resolve the admission lane for a dial, or `None` when nothing is capped.
    ///
    /// `override_port` is the key the caller uses to read
    /// `Proxy.dispatch_port_overrides`. For the socket-owning HTTP pools that
    /// is `proxy.backend_port` (the per-dispatch clone built by
    /// `resolve_backend_connection_proxy_for_target` mirrors a `targetPort`-
    /// remapped service-port policy onto the dial port). For the mesh tunnels
    /// it is the destination's app/service policy port, because the transport
    /// dial is `:15008` / `:15006` and must never become the policy source.
    ///
    /// The resulting counter lane is keyed by the DestinationRule **policy**
    /// port — `ResolvedPortOverride::policy_port` when the entry was mirrored
    /// from a remapped service port, else `override_port` — so a pooled socket
    /// and a WebSocket/raw-TCP session to the same destination share one
    /// ceiling instead of getting one each.
    pub fn resolve(
        limiter: Option<&'a BackendConnectionLimiter>,
        proxy: &'a crate::config::types::Proxy,
        dial_host: &'a str,
        override_port: u16,
    ) -> Option<Self> {
        let limiter = limiter?;
        let entry = proxy
            .dispatch_port_overrides
            .as_ref()
            .and_then(|overrides| overrides.get(&override_port))?;
        let cap = entry.max_connections?;
        Some(Self {
            limiter,
            host: dial_host,
            policy_port: entry.policy_port.unwrap_or(override_port),
            cap,
        })
    }

    /// Reserve one physical-connection slot for this destination.
    pub fn acquire(&self) -> Result<SharedBackendConnectionGuard, BackendConnectionLimitExceeded> {
        self.limiter
            .try_acquire_shared(self.host, self.policy_port, self.cap)
    }

    /// Reserve one slot, mapping a refusal onto an [`anyhow::Error`] whose
    /// SOURCE CHAIN still carries the typed [`BackendConnectionLimitExceeded`].
    ///
    /// For pools whose create surface is `anyhow` (native HTTP/3). A plain
    /// `anyhow!("...")` would erase the type, leaving only the message —
    /// [`crate::retry::classify_boxed_setup_error`] would then fall through to
    /// `ErrorClass::RequestError`, which `retry::request_reached_wire` treats as
    /// POST-wire. That is exactly wrong for a refusal decided before any packet
    /// is sent: it would let the dispatch charge backend health and the
    /// capability probe downgrade a perfectly healthy backend. Keeping the type
    /// in the chain keeps the refusal a pre-wire `ConnectionPoolError` and lets
    /// callers recognize it structurally
    /// ([`is_backend_connection_limit_error`]).
    pub fn acquire_or_typed_error(
        &self,
        transport: &str,
    ) -> Result<SharedBackendConnectionGuard, anyhow::Error> {
        self.acquire().map_err(|limit| {
            let host = self.host;
            let port = self.policy_port;
            anyhow::Error::new(limit).context(format!(
                "{transport}: DestinationRule maxConnections reached for {host}:{port}"
            ))
        })
    }

    /// Destination host this lane counts sockets for (diagnostics/logging).
    pub fn host(&self) -> &str {
        self.host
    }

    /// DestinationRule policy port this lane counts sockets for.
    pub fn policy_port(&self) -> u16 {
        self.policy_port
    }

    /// Configured `connectionPool.tcp.maxConnections` for this lane.
    #[allow(dead_code)]
    pub fn cap(&self) -> u32 {
        self.cap
    }
}

/// One reqwest admission lane: the DestinationRule policy port and cap that
/// govern new sockets to a dial `(host, port)`.
///
/// `Ord` is `(cap, policy_port)` lexicographic, which is exactly "strictest
/// first": a lower ceiling wins, and a tie is broken deterministically by port
/// so two conflicting publications resolve the same way in either arrival
/// order. See [`ReqwestConnectionAdmission`] for why conflicts resolve to the
/// strictest lane rather than to the publishing request's own lane.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct ReqwestLane {
    cap: u32,
    policy_port: u16,
}

impl ReqwestLane {
    /// DestinationRule policy port this lane counts sockets on.
    pub fn policy_port(&self) -> u16 {
        self.policy_port
    }

    /// Configured `connectionPool.tcp.maxConnections` for this lane.
    pub fn cap(&self) -> u32 {
        self.cap
    }
}

/// Refcounted admission state for one dial `(host, port)`.
///
/// Mirrors [`crate::backend_pending_limit`]'s counter: the entry owns its map
/// key so the RAII lease can evict it under the same `DashMap` shard lock that
/// admission takes, and lives exactly as long as at least one capped dispatch to
/// this destination is in flight.
#[derive(Debug)]
struct ReqwestDialLaneEntry {
    key: String,
    /// Guarded together so a lease can never observe a lane from one
    /// publication paired with a generation from another. Every mutation runs
    /// while the caller already holds the `DashMap` shard write lock, so this
    /// mutex is uncontended by construction; it exists to give `remove_if`'s
    /// `&V` predicate a legal mutation path (the same role the pending
    /// limiter's `AtomicU64` plays for its single-field state).
    state: std::sync::Mutex<ReqwestDialLaneState>,
}

#[derive(Clone, Copy, Debug)]
struct ReqwestDialLaneState {
    /// Config generation that published `lane`.
    generation: u64,
    lane: ReqwestLane,
    /// Live [`ReqwestLaneLease`]s. The entry is evicted at zero.
    leases: u64,
}

impl ReqwestDialLaneEntry {
    fn lock(&self) -> std::sync::MutexGuard<'_, ReqwestDialLaneState> {
        // A panic can never happen inside the critical section (it is field
        // assignment on `Copy` scalars), but the production-code rule forbids
        // `unwrap()`, and recovering the inner value is the correct behavior
        // even if a future edit did panic: the state stays consistent and
        // admission keeps enforcing.
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Fold one publication into the lane and take a lease.
    fn acquire(&self, generation: u64, lane: ReqwestLane) {
        let mut state = self.lock();
        state.leases += 1;
        if state.leases == 1 || generation > state.generation {
            // Freshly created entry, or a NEWER config publication: the new
            // configuration replaces the old one wholesale, so an operator who
            // raised (or removed and re-added) a cap sees it take effect
            // immediately rather than being pinned to the retired ceiling.
            state.generation = generation;
            state.lane = lane;
        } else if generation == state.generation && lane < state.lane {
            // Same generation, conflicting lanes: strictest wins.
            state.lane = lane;
        }
        // `generation < state.generation` — a request pinned to a retired
        // configuration reaching dispatch after a reload. It keeps its lease
        // (so the destination stays governed) but may not weaken the live
        // policy back to the retired one.
    }

    /// Release one lease. Returns `true` when the entry is now idle and the
    /// caller (holding the shard write lock) should evict it.
    fn release_is_idle(&self) -> bool {
        let mut state = self.lock();
        // Straight subtraction, not `saturating_sub`: a double-release or
        // missing-acquire must panic in tests rather than be masked into a
        // silently unbounded destination.
        state.leases -= 1;
        state.leases == 0
    }

    fn lane(&self) -> ReqwestLane {
        self.lock().lane
    }
}

thread_local! {
    /// Reused per-thread buffer for lane keys, mirroring
    /// [`crate::backend_pending_limit`]: a repeat capped dispatch to a known
    /// destination allocates nothing (`DashMap::get` takes `&str` through
    /// `String: Borrow<str>`).
    static LANE_KEY_BUF: std::cell::RefCell<String> =
        std::cell::RefCell::new(String::with_capacity(96));
}

/// Normalize a host for lane keying: ASCII-lowercased and with IPv6 brackets
/// stripped, so the dispatch-side `UpstreamTarget.host` and the bracketed,
/// URL-normalized authority reqwest hands the connector land on one key.
fn push_normalized_host(buf: &mut String, host: &str) {
    let host = host.strip_prefix('[').unwrap_or(host);
    let host = host.strip_suffix(']').unwrap_or(host);
    for ch in host.chars() {
        buf.extend(ch.to_lowercase());
    }
}

fn write_lane_key(buf: &mut String, host: &str, dial_port: u16) {
    use std::fmt::Write;
    push_normalized_host(buf, host);
    let _ = write!(buf, "|{dial_port}");
}

/// The `connectionPool.tcp.maxConnections` admission hook Ferrum installs on
/// **every** pooled `reqwest::Client`.
///
/// # Why a connector hook and not a request counter
///
/// reqwest owns its socket pool internally: a request can reuse an idle socket
/// (no new connection), and after a request finishes reqwest keeps the socket
/// idle and reusable. A slot tied to a request's lifetime therefore reads zero
/// while sockets are still open, and would admit past the cap on the next
/// dispatch; it would also count HTTP/2 *streams* rather than connections. The
/// vendored `ClientBuilder::connection_admission` hook is consulted at the one
/// place a new physical connection is created, so:
///
/// * reuse and H2 multiplexing take **no** slot;
/// * the slot is released when the socket actually closes (handshake failure,
///   idle eviction, pool drain, reload, cancellation, shutdown), because the
///   token is owned by the connection object handed to hyper;
/// * one shared hook across all `reqwest::Client`s means divergent pool keys
///   (TLS material, `rcfg`, forced-H1 ALPN, subset) for the same destination
///   still share ONE ceiling.
///
/// # Binding a lane to the connect attempt
///
/// The connector only knows the dial `(host, port)` from the URI. The cap and
/// the DestinationRule **policy** port live on the dispatching `Proxy`, so the
/// dispatch path takes a [`ReqwestLaneLease`] for the destination immediately
/// before handing the request to reqwest and holds it until `send()` resolves —
/// the exact window in which that request can cause a dial. Only a destination
/// with a configured cap ever takes a lease, so an uncapped destination costs
/// nothing anywhere.
///
/// A lane therefore exists **exactly while some capped dispatch is in flight to
/// it**. That is what makes reload behavior correct without an epoch registry:
/// a `maxConnections` an operator removed stops applying as soon as the
/// requests that were dispatched under it complete (nothing re-leases it), and
/// nothing has to be swept, so no stale registry can accumulate.
///
/// # Why conflicts resolve to the strictest lane, not the publisher's own
///
/// Several logical upstreams (different proxies, subsets, or `targetPort`
/// remaps) can resolve DIFFERENT `(policy port, cap)` for the SAME dial
/// address. `maxConnections` is deliberately **not** part of the reqwest pool
/// key — it changes admission, not connection identity — so those upstreams
/// share one `reqwest::Client` and therefore one physical socket pool. A socket
/// admitted under the laxer lane is subsequently REUSED by the stricter
/// upstream, so binding each connect attempt to its own publisher's lane would
/// not enforce the stricter cap; it would only decide, nondeterministically,
/// which request paid for the socket. The only sound bound for a shared pool is
/// the strictest live lane, which is what [`ReqwestLane`]'s `Ord` selects. That
/// is deterministic (independent of publication order), fail-closed, and
/// converges on the exact configured cap in the overwhelmingly common
/// single-lane case.
///
/// Across a reload the newest configuration generation replaces the lane
/// wholesale, and a request pinned to a retired generation may never weaken it.
pub struct ReqwestConnectionAdmission {
    limiter: SharedBackendConnectionLimiter,
    lanes: Arc<DashMap<String, Arc<ReqwestDialLaneEntry>>>,
}

impl ReqwestConnectionAdmission {
    /// Build a hook that admits against `limiter`.
    pub fn new(limiter: SharedBackendConnectionLimiter, shards: usize) -> Self {
        Self {
            limiter,
            lanes: Arc::new(DashMap::with_shard_amount(shards)),
        }
    }

    /// Take a lease on the lane governing new sockets to
    /// `(dial_host, dial_port)`, binding it to this dispatch.
    ///
    /// Call ONLY when a cap is configured for the destination — the uncapped
    /// path must not touch this map. `policy_port` is the DestinationRule
    /// policy port ([`crate::proxy::dispatch_policy_port_for_target`]), which
    /// is what the counter lane is keyed by, so a `targetPort` remap and a raw
    /// TCP/WebSocket session to the same destination share one ceiling.
    ///
    /// `config_generation` is the request's pinned configuration generation; it
    /// decides reload precedence (see the type docs). The returned lease MUST be
    /// held across the reqwest `send()` this dispatch performs.
    #[must_use = "the lane exists only while its lease is held"]
    pub fn lease_lane(
        &self,
        config_generation: u64,
        dial_host: &str,
        dial_port: u16,
        policy_port: u16,
        cap: u32,
    ) -> ReqwestLaneLease {
        let lane = ReqwestLane { cap, policy_port };
        let entry = LANE_KEY_BUF.with(|buf| {
            let mut buf = buf.borrow_mut();
            buf.clear();
            write_lane_key(&mut buf, dial_host, dial_port);
            // Hit path: a borrowed-`&str` `get` (read-locks only this shard) —
            // no key allocation for a destination already in flight. The
            // allocating `entry` path runs only when this is the first capped
            // dispatch in flight to the destination.
            if let Some(existing) = self.lanes.get(buf.as_str()) {
                let entry = Arc::clone(existing.value());
                // Fold under the SHARD READ LOCK, which is still held by
                // `existing`: `release` evicts under the shard WRITE lock, so
                // the entry cannot be evicted between this clone and the
                // lease increment.
                entry.acquire(config_generation, lane);
                return entry;
            }
            let occupied = self.lanes.entry(buf.clone()).or_insert_with(|| {
                Arc::new(ReqwestDialLaneEntry {
                    key: buf.clone(),
                    state: std::sync::Mutex::new(ReqwestDialLaneState {
                        generation: config_generation,
                        lane,
                        leases: 0,
                    }),
                })
            });
            let entry = Arc::clone(occupied.value());
            // Increment while `occupied` still holds the shard WRITE lock, so a
            // concurrent lease/release can never evict this entry between its
            // insertion and its first lease (which would detach the lane from
            // the map and silently stop enforcing the cap).
            entry.acquire(config_generation, lane);
            drop(occupied);
            entry
        });
        ReqwestLaneLease {
            lanes: Arc::clone(&self.lanes),
            entry,
        }
    }

    /// Resolve the live lane for a dial destination, if any.
    ///
    /// Public so the external suite can assert lane resolution (conflict
    /// ordering, reload precedence, lease drain) without driving real sockets;
    /// production reads it only through [`reqwest::ConnectionAdmission::admit`].
    pub fn lane_for(&self, host: &str, port: u16) -> Option<ReqwestLane> {
        LANE_KEY_BUF.with(|buf| {
            let mut buf = buf.borrow_mut();
            buf.clear();
            write_lane_key(&mut buf, host, port);
            self.lanes.get(buf.as_str()).map(|entry| entry.lane())
        })
    }

    /// Number of dial destinations with a live lane. Tests/diagnostics — proves
    /// the registry drains rather than accumulating retired policy.
    #[allow(dead_code)]
    pub fn live_lane_count(&self) -> usize {
        self.lanes.len()
    }

    /// Current open-socket count for a destination lane. Tests/diagnostics.
    #[allow(dead_code)]
    pub fn current(&self, host: &str, policy_port: u16) -> u64 {
        self.limiter.current(host, policy_port)
    }
}

/// RAII lease binding one capped reqwest dispatch to its admission lane.
///
/// The lane governing a dial destination exists exactly while at least one lease
/// is held, so the cap is live for precisely the window in which the leasing
/// request can cause a physical dial. Dropping the last lease evicts the entry
/// under the same `DashMap` shard write lock that
/// [`ReqwestConnectionAdmission::lease_lane`] acquires under, so an acquirer can
/// never resurrect a half-evicted entry and a retired policy can never linger.
pub struct ReqwestLaneLease {
    lanes: Arc<DashMap<String, Arc<ReqwestDialLaneEntry>>>,
    entry: Arc<ReqwestDialLaneEntry>,
}

impl Drop for ReqwestLaneLease {
    fn drop(&mut self) {
        // Decrement and at-zero eviction in ONE shard-locked `remove_if`, the
        // same mutual exclusion `BackendPendingGuard` relies on: an acquirer
        // holding the shard lock can never observe the entry "between" the
        // decrement and the removal.
        self.lanes
            .remove_if(self.entry.key.as_str(), |_, entry| entry.release_is_idle());
    }
}

impl reqwest::ConnectionAdmission for ReqwestConnectionAdmission {
    fn admit(
        &self,
        dst: &http::Uri,
    ) -> Result<reqwest::ConnectionAdmissionToken, Box<dyn std::error::Error + Send + Sync>> {
        let Some(host) = dst.host() else {
            // No authority to key on: nothing to bound, and refusing here would
            // break dials this limiter has no opinion about.
            return Ok(reqwest::ConnectionAdmissionToken::unlimited());
        };
        let port = match dst.port_u16() {
            Some(port) => port,
            None => match dst.scheme_str() {
                Some("https") => 443,
                _ => 80,
            },
        };
        // Normalize once (brackets stripped, ASCII-lowercased) so the counter
        // key matches the one the WebSocket / raw-TCP / pooled transports use
        // for the same destination. This is the cold new-connection path, so
        // the small allocation never touches per-request work.
        let mut normalized_host = String::with_capacity(host.len());
        push_normalized_host(&mut normalized_host, host);
        let Some(lane) = self.lane_for(&normalized_host, port) else {
            return Ok(reqwest::ConnectionAdmissionToken::unlimited());
        };
        // Count on the POLICY port, never the dial port, so every transport to
        // this destination shares one ceiling.
        match self
            .limiter
            .try_acquire_shared(&normalized_host, lane.policy_port, lane.cap)
        {
            Ok(slot) => Ok(reqwest::ConnectionAdmissionToken::new(slot)),
            Err(limit) => Err(Box::new(limit)),
        }
    }
}

/// Recognize a reqwest error caused by this limiter refusing a new socket.
///
/// Walks the error's source chain: reqwest wraps a connector error in its own
/// `Error`, so the marker is never the top-level type. Used by the dispatch
/// path to answer with a neutral 503 instead of a 502 that would charge the
/// backend's health for a gateway-side ceiling.
pub fn is_backend_connection_limit_error(err: &(dyn std::error::Error + 'static)) -> bool {
    let mut source = Some(err);
    while let Some(current) = source {
        if current.is::<BackendConnectionLimitExceeded>() {
            return true;
        }
        source = current.source();
    }
    false
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
