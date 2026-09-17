//! Source-side reuse of the APPLICATION connection inside a fenced HBONE
//! tunnel (issue #5042 step 2).
//!
//! The outer HBONE HTTP/2 transport has always been pooled
//! ([`super::hbone_pool`]), but the connection the gateway runs INSIDE it was
//! built per request: one CONNECT stream, one inner HTTP/1.1 handshake for
//! plain HTTP, and for gRPC an entire nested HTTP/2 preface/SETTINGS exchange
//! through the destination relay — every time. The destination saw one
//! `accept(2)` per request, and a warm intra-cluster call paid one extra
//! round trip (HTTP) or two (gRPC) before its first request byte left.
//!
//! This module holds that inner connection open across requests.
//!
//! # Why this is admissible at all
//!
//! Pooling an application tunnel changes how often the DESTINATION authorizes.
//! Before step 1 of this issue, a tunnel admitted under one policy generation
//! kept flowing under every later one, so reuse would have carried later
//! requests under a stale decision with nothing able to notice. Step 1 closed
//! that: [`super::hbone_admission_fence`] re-applies the CONNECT admission
//! gates — policy AND credential — to every live tunnel on every publication,
//! and cuts the ones a later generation would refuse.
//!
//! Reuse is therefore gated on the destination SAYING it runs that fence:
//! `handle_hbone_request` stamps
//! [`crate::modes::mesh::hbone::TUNNEL_REUSE_HEADER`] on the CONNECT `200`
//! only while the fence really holds the tunnel, and a source that does not
//! see it keeps today's per-request behaviour exactly. The header is read for
//! that one decision and nothing else; it authorizes no request, and a peer
//! that forges it gains no more than it already gets by holding one long-lived
//! tunnel open.
//!
//! # What is NOT skipped
//!
//! Only the repeated CONNECT and the repeated inner handshake. Every NEW
//! CONNECT still runs the full source-side dial (SVID-mTLS to the peer, pinned
//! peer identity / SNI / trust-domain scope) and the destination still runs the
//! authenticated-peer gate, the PeerAuthentication transport mode, the
//! relay-destination ownership guard, and the authorize chain. There is no
//! plaintext fallback anywhere on this path: a peer that does not advertise the
//! fence gets more connections, never a weaker one.
//!
//! # The key IS the admission identity
//!
//! [`write_hbone_inner_pool_key`] encodes the COMPLETE transport and admission
//! identity of the connection, so nothing that would change who is talking to
//! whom, under what credential, or over what wire settings can share a pooled
//! connection:
//!
//! * the application endpoint as dialled (the CONNECT `:authority` host and
//!   port) and the dial peer (`dial_host` + the peer's HBONE listener port) —
//!   these are different hosts for NodeWaypoint and cross-cluster egress;
//! * the peer verification scope: pinned peer SPIFFE id, ClientHello SNI
//!   override, and the remote trust domain a cross-cluster session was verified
//!   against;
//! * the ASSERTED SOURCE PRINCIPAL and its scope — the identity stamped into
//!   the CONNECT baggage, plus whether it was asserted by an authenticated
//!   frontend peer or defaulted to this gateway's own SVID. Two principals
//!   never share an inner connection, and "gateway SVID acting as itself" is a
//!   different key from "gateway asserting that same identity on behalf of a
//!   peer";
//! * the route/policy generation: namespace, proxy id, effective upstream id,
//!   and the admitting proxy's lifecycle generation, so a republished or
//!   re-bound proxy is a new incarnation that inherits nothing;
//! * the source credential generation: the gateway SVID leaf fingerprint and
//!   the shared backend SVID/trust generation, so a rotation partitions the
//!   pool rather than laundering a connection across it;
//! * the effective connection policy that configures the constructed
//!   client — keep-alive, protocol selection, and the HTTP/2 SETTINGS — through
//!   the same `write_pool_config_key` segment every sibling pool uses.
//!
//! Per-request policy is deliberately EXCLUDED, exactly as
//! [`super::unix_backend_pool`] excludes it and for the same reason the repo
//! pool-key rule states: `backend_connect_timeout_ms`,
//! `backend_read_timeout_ms`, `backend_write_timeout_ms` and the route-scoped
//! body ceilings are applied per dispatch by the caller (they compose the
//! phase deadlines and the size-limiting body adapters on every request,
//! reused connection or not). They change nothing about the connection that was
//! constructed, so keying on them would fragment the pool without bounding
//! anything.
//!
//! # Credential lifetime
//!
//! A lease NEVER prolongs a credential. Every pooled connection records the
//! earliest monotonic deadline across the credentials that admitted it — the
//! admitting request's own `RequestContext::credential_deadline_at` (already
//! the minimum over every accepted credential on that request, SVID and JWT
//! alike) and the gateway SVID leaf's `notAfter` — and a checkout that finds an
//! elapsed deadline EVICTS the connection instead of handing it out. A leaf the
//! gateway cannot parse collapses to an already-elapsed deadline, so it is
//! never poolable; a `notAfter` beyond the representable monotonic range
//! publishes no deadline, exactly as
//! [`crate::plugins::utils::auth_flow::CredentialDeadline::Unbounded`] does,
//! and the idle timeout plus the pool bounds still apply.
//!
//! # Per-protocol lease semantics
//!
//! * **HTTP/1.1** — an EXCLUSIVE lease. It returns to the idle set ONLY after a
//!   clean, fully consumed response, for both the buffered and the streaming
//!   response shape, and only after hyper's own dispatcher has re-armed. A
//!   truncated body, a body error, a `Connection: close`, an early client
//!   cancel, a fired deadline, a read timeout, a size-limit refusal, or a
//!   dropped body all leave the lease in place and its `Drop` retires the
//!   tunnel. Receiving response HEADERS is never sufficient, and neither is
//!   hyper's `can_write_head()`: it is already true while a response body is
//!   still being read, so pooling on readiness alone would pipeline the next
//!   request onto a half-read connection.
//! * **HTTP/2 (native gRPC)** — ONE shared multiplexed sender per key, cloned
//!   per RPC. Liveness is `!is_closed()`, which is EXACTLY the predicate the
//!   direct HTTP/2 pool uses (`Http2PoolManager::is_healthy`), so the two
//!   cannot judge a carrier differently. A sender whose connection has ended —
//!   a received GOAWAY that drained, a connection-level error, or a tunnel a
//!   fence sweep cut — reports closed, is EVICTED on the next checkout, and is
//!   never handed out again. Between a peer's GOAWAY and its connection task
//!   finishing there is a window in which a clone can still be taken; its
//!   `send_request` then fails and is classified and retried exactly as the
//!   direct pool's is, because reuse must not introduce a second error regime.
//!   Trailers, RST_STREAM, cancellation and flow control are the transport's
//!   own and are unchanged by pooling.
//!
//! # Revocation reaches a pooled connection
//!
//! Three independent paths, all of them fail-closed:
//!
//! 1. **The receiver cut the tunnel.** A fence sweep resets the CONNECT stream,
//!    which the [`super::hbone_pool::H2ConnectTunnel`] under the inner sender
//!    surfaces as a terminal transport error; hyper's driver ends and
//!    `is_closed()` becomes true. Checkout evicts it. If the close has not
//!    propagated yet, the H1 path's PRE-WIRE `try_send_request` hands the
//!    untouched request back and the dispatch replays it on a fresh CONNECT
//!    that the destination judges under the CURRENT policy — see
//!    "Retry semantics" below.
//! 2. **Source trust changed.** This pool is owned by
//!    [`super::hbone_pool::HboneConnectionPool`], so the drains that already
//!    reach the outer transports reach these too, through the same two
//!    funnels: `drain_retired_fingerprints` (the SVID rotation drain, matched
//!    on the retired leaf fingerprint every key embeds) and `force_drain_all`
//!    (an SVID slot with no bundle, and `retire_withdrawn_trust`, which clears
//!    the mesh pools WHOLE for every committed gateway trust change because
//!    their keys carry no generation partition). That ownership is why this is
//!    structural rather than a list of call sites: an inner connection is only
//!    ever as trustworthy as the tunnel it rides.
//! 3. **Credential expiry.** The recorded deadline above.
//!
//! # What a pooled connection costs while idle
//!
//! One outer HTTP/2 stream, held for as long as the inner connection is
//! pooled — the CONNECT stream is what the inner connection IS. It therefore
//! counts against the destination's `http2MaxRequests` / `SETTINGS_MAX_CONCURRENT_STREAMS`
//! exactly as an in-flight tunnel does, through the same
//! `HboneStreamLease` the outer pool uses to measure connection load. That is
//! bounded, and strictly better than the alternative it replaces: per request
//! the unpooled path holds an equivalent stream for the whole exchange and
//! then opens another, whereas [`MAX_IDLE_H1_PER_KEY`] plus
//! [`MAX_POOLED_INNER_CONNECTIONS`] plus the idle timeout cap what reuse can
//! hold at rest. Do not raise those bounds without re-reading this paragraph.
//!
//! # Retry semantics are UNCHANGED
//!
//! Reuse must not turn a non-idempotent request into a replayed one. The only
//! replay this module enables is hyper's PRE-WIRE handback: `try_send_request`
//! returns the untouched request through `TrySendError::take_message()` ONLY
//! when nothing was written to the wire, it is taken at most once per dispatch,
//! and only for a lease that came from the idle set (a freshly dialled
//! connection that fails has a real failure to report). That is the identical
//! contract [`super::unix_backend_pool`]'s H1 dispatch already relies on. Every
//! post-wire failure is classified and surfaced exactly as it is today, and the
//! ordinary `retry::should_retry` path — with its `retryable_methods` guard —
//! is the only thing that may replay it.
//!
//! # Bounds
//!
//! Fixed defaults rather than new operator knobs: at most
//! [`MAX_IDLE_H1_PER_KEY`] idle HTTP/1.1 connections per key, at most
//! [`MAX_POOLED_INNER_CONNECTIONS`] pooled inner connections in total across
//! every key and both protocols, and an idle timeout taken from the effective
//! `PoolConfig::idle_timeout_seconds` the dispatch already resolved (floored by
//! [`MIN_INNER_IDLE_TIMEOUT_SECONDS`] so a `0` "never expire" transport setting
//! cannot make an inner application connection immortal). Over-cap is never an
//! error: the connection simply is not pooled, which is today's behaviour.
//!
//! The pool can never open more inner connections than the per-request path
//! would have. Every miss opens exactly one, exactly as today, and concurrent
//! cold misses for one key each serve their own request — the first to publish
//! wins the slot and the others are used once and closed, which is precisely
//! the pre-#5042 cost.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use dashmap::DashMap;
use hyper::client::conn::{http1, http2};
use tracing::debug;

use crate::config::PoolConfig;
use crate::identity::SpiffeId;
use crate::identity::spiffe::TrustDomain;
use crate::plugins::prometheus_metrics::HboneInnerPoolEvent;
use crate::proxy::body::{ReplayableRequestBody, SizeLimitedIncoming};
use crate::proxy::grpc_proxy::GrpcBody;
use crate::proxy::hbone_pool::{entry_idle_expired, unix_secs, write_pool_config_key};

/// Most idle HTTP/1.1 inner connections retained for ONE key.
///
/// One key is one `(principal, app endpoint, dial peer, verification scope,
/// route generation, credential generation, wire settings)` tuple, so this
/// bounds the concurrency a single logical caller→callee lane keeps warm. Eight
/// covers the concurrency the measurement in issue #5042 exercised without
/// letting one busy lane monopolise the global ceiling.
pub const MAX_IDLE_H1_PER_KEY: usize = 8;

/// Hard ceiling on POOLED inner connections across every key and both
/// protocols.
///
/// Reached only by breadth — many distinct principals or destinations — since
/// each key is already bounded above. An over-cap connection is used for its
/// own request and then closed, which is exactly the per-request behaviour this
/// module replaces, so the ceiling degrades to the old cost rather than to an
/// error.
pub const MAX_POOLED_INNER_CONNECTIONS: usize = 1024;

/// Floor applied to the effective `PoolConfig::idle_timeout_seconds` for inner
/// application connections.
///
/// `0` on the transport pool means "never expire", which is a defensible
/// setting for a gateway's own outbound mTLS sessions but not for a connection
/// held open inside a peer's application. A stale inner connection is also the
/// shape most likely to meet a destination that reaped its side, so it is
/// floored rather than honoured literally.
pub const MIN_INNER_IDLE_TIMEOUT_SECONDS: u64 = 15;

/// Amortisation interval for the idle sweep. The sweep runs at most this often,
/// on a checkout, never on a timer and never on the byte path.
const IDLE_PRUNE_INTERVAL_SECONDS: u64 = 5;

/// Request body carried by a pooled inner HTTP/1.1 sender.
///
/// Byte-identical to the shape the unpooled HBONE dispatch already built, so
/// naming the sender's concrete `SendRequest<B>` type changes nothing about
/// what the dispatch path constructs: `Left` is the streaming, size-limited
/// frontend body; `Right` is the retry-replayable buffered body.
pub type HboneInnerH1RequestBody =
    http_body_util::Either<SizeLimitedIncoming, ReplayableRequestBody>;

/// Concrete pooled inner HTTP/1.1 sender type.
pub type HboneInnerH1Sender = http1::SendRequest<HboneInnerH1RequestBody>;

/// Concrete shared inner HTTP/2 sender type (native gRPC inside the tunnel).
pub type HboneInnerH2Sender = http2::SendRequest<GrpcBody>;

/// Wire protocol spoken INSIDE the tunnel. Part of the key: an HTTP/1.1
/// application dispatch and a nested HTTP/2 gRPC dispatch must never share a
/// connection even when every other field agrees.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HboneInnerProtocol {
    Http1,
    H2,
}

impl HboneInnerProtocol {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Http1 => "http1",
            Self::H2 => "h2",
        }
    }

    const fn event_protocol(self) -> crate::plugins::prometheus_metrics::HboneInnerPoolProtocol {
        match self {
            Self::Http1 => crate::plugins::prometheus_metrics::HboneInnerPoolProtocol::Http1,
            Self::H2 => crate::plugins::prometheus_metrics::HboneInnerPoolProtocol::H2,
        }
    }
}

/// The source credential every inner lease is keyed and bounded by.
///
/// Resolved once per dispatch by
/// [`super::hbone_pool::HboneConnectionPool::source_credential_identity`], from
/// the same cached gateway SVID snapshot the outer dial uses, so the key's
/// credential fields and the connection's actual client certificate can never
/// come from two different generations.
#[derive(Clone)]
pub struct HboneSourceCredential {
    /// The gateway's own SPIFFE identity — the source principal a dispatch with
    /// no authenticated frontend peer asserts.
    pub identity: SpiffeId,
    /// Leaf fingerprint, the same value the outer HBONE pool key embeds.
    pub fingerprint: Arc<str>,
    /// Shared backend SVID/trust generation counter.
    pub generation: u64,
    /// The gateway leaf's `notAfter` on the monotonic clock. `None` means the
    /// expiry is beyond the representable range, not that it is unbounded in
    /// policy terms; an unparseable leaf collapses to an already-elapsed
    /// deadline so nothing is poolable under it.
    pub leaf_deadline: Option<tokio::time::Instant>,
}

/// Everything that identifies ONE reusable inner application connection,
/// borrowed from the dispatch so building a key allocates nothing.
pub struct HboneInnerKeyParts<'a> {
    pub protocol: HboneInnerProtocol,
    pub namespace: &'a str,
    pub proxy_id: &'a str,
    pub upstream_id: Option<&'a str>,
    /// The admitting proxy's lifecycle generation, when the request path
    /// resolved one. A proxy withdrawn and recreated is a new incarnation and
    /// must inherit nothing.
    pub proxy_lifecycle_generation: Option<u64>,
    /// CONNECT `:authority` host — the real destination the relay dials.
    pub app_host: &'a str,
    pub app_port: u16,
    /// The host the outer HTTP/2 session is dialled to. Differs from `app_host`
    /// on NodeWaypoint secured egress and cross-cluster east-west.
    pub dial_host: &'a str,
    pub hbone_port: u16,
    pub expected_peer: Option<&'a SpiffeId>,
    pub expected_trust_domain: Option<&'a TrustDomain>,
    pub sni_override: Option<&'a str>,
    /// The principal stamped into the CONNECT baggage.
    pub source_principal: &'a SpiffeId,
    /// `true` when `source_principal` was ASSERTED on behalf of an
    /// authenticated frontend peer, `false` when it is this gateway's own SVID
    /// identity acting as itself. The two are different admission facts at the
    /// destination and must not share a connection.
    pub source_principal_asserted: bool,
    pub credential: &'a HboneSourceCredential,
    pub pool_config: &'a PoolConfig,
}

thread_local! {
    static HBONE_INNER_POOL_KEY_BUF: std::cell::RefCell<String> =
        std::cell::RefCell::new(String::with_capacity(256));
}

/// Render the complete inner-connection identity into `buf`.
///
/// `|` is the repo's pool-key delimiter. The SVID fingerprint is written at a
/// FIXED early index (2) — after two compiled-in literals that contain no
/// delimiter — so the rotation drain can resolve it positionally without
/// depending on any later field being delimiter-free. A cross-cluster
/// `target.host` really does contain `|`, which is exactly why the fingerprint
/// is not parsed from the tail.
pub fn write_hbone_inner_pool_key(buf: &mut String, parts: &HboneInnerKeyParts<'_>) {
    use std::fmt::Write as _;

    buf.clear();
    let _ = write!(
        buf,
        "hbone-inner|{}|{}|{}",
        parts.protocol.as_str(),
        parts.credential.fingerprint.as_ref(),
        parts.credential.generation
    );
    let _ = write!(
        buf,
        "|{}|{}|{}|",
        parts.namespace,
        parts.proxy_id,
        parts.upstream_id.unwrap_or_default()
    );
    // Written by `write!` rather than through `to_string()` so a key build
    // allocates nothing on the dispatch path; an absent generation is the
    // empty segment, which no `u64` rendering can collide with.
    if let Some(generation) = parts.proxy_lifecycle_generation {
        let _ = write!(buf, "{generation}");
    }
    let _ = write!(
        buf,
        "|{}|{}|{}|{}",
        parts.app_host, parts.app_port, parts.dial_host, parts.hbone_port
    );
    let _ = write!(
        buf,
        "|{}|{}|{}",
        parts
            .expected_peer
            .map(SpiffeId::as_str)
            .unwrap_or_default(),
        parts.sni_override.unwrap_or_default(),
        parts
            .expected_trust_domain
            .map(TrustDomain::as_str)
            .unwrap_or_default()
    );
    let _ = write!(
        buf,
        "|{}|{}",
        parts.source_principal.as_str(),
        u8::from(parts.source_principal_asserted)
    );
    write_pool_config_key(buf, parts.pool_config);
}

/// The SVID leaf fingerprint embedded in an inner pool key, for the rotation
/// drain. See [`write_hbone_inner_pool_key`] for why the index is 2.
fn hbone_inner_key_svid_fingerprint(key: &str) -> Option<&str> {
    key.split('|').nth(2)
}

/// Build the key for `parts` in a thread-local buffer and hand it to `f`
/// without allocating. Mirrors `with_hbone_pool_key`.
pub fn with_hbone_inner_pool_key<R>(
    parts: &HboneInnerKeyParts<'_>,
    f: impl FnOnce(&str) -> R,
) -> R {
    HBONE_INNER_POOL_KEY_BUF.with(|cell| {
        let mut buf = cell.borrow_mut();
        write_hbone_inner_pool_key(&mut buf, parts);
        f(&buf)
    })
}

/// An EXCLUSIVE inner HTTP/1.1 lease.
///
/// Dropping the lease retires the connection AND the CONNECT tunnel under it.
/// Only [`HboneInnerConnectionPool::checkin_h1_when_idle`] returns it to the
/// idle set, and only after the response body has been completely read.
pub struct HboneInnerH1Checkout {
    key: String,
    /// `true` when this lease came from the idle set rather than a fresh
    /// CONNECT. The dispatch uses it to decide whether a PRE-WIRE send failure
    /// is a reuse race worth replaying once on a fresh tunnel.
    reused: bool,
    /// The earliest credential deadline that admitted this connection, or
    /// `None` when none of them published a representable bound.
    credential_deadline: Option<tokio::time::Instant>,
    /// Effective idle timeout for this connection, resolved at checkout so the
    /// check-in (which has no `PoolConfig`) applies the same value.
    idle_timeout_seconds: u64,
    /// `false` when the destination did not advertise the admission fence, or
    /// when keep-alive reuse is off for this dispatch. Such a lease is used
    /// once and never enters the idle set.
    poolable: bool,
    pub sender: HboneInnerH1Sender,
}

impl HboneInnerH1Checkout {
    /// Whether this lease came from the idle set.
    #[inline]
    pub fn reused(&self) -> bool {
        self.reused
    }

    /// Whether this lease may re-enter the idle set at all.
    ///
    /// `false` for a destination that did not advertise the admission fence,
    /// for a dispatch with keep-alive off, and for an unpooled lease. The
    /// plain-HTTP dispatch also reads it to decide whether it may apply the
    /// eager small-response buffering that keeps an exclusive H1 carrier
    /// alive, so a peer without the capability keeps byte-for-byte today's
    /// streaming behaviour.
    #[inline]
    pub fn poolable(&self) -> bool {
        self.poolable
    }
}

/// EOF-anchored owner of an exclusive inner HTTP/1.1 lease for a STREAMING
/// response.
///
/// Constructed by [`HboneInnerConnectionPool::streaming_lease`] and stored on
/// the `ProxyBody` that owns the backend `hyper::body::Incoming`. Two exits,
/// and only two:
///
/// * `release_on_clean_eof` — the body yielded `Ready(None)`, or a successful
///   terminal frame after `Body::is_end_stream()` proved the whole `Incoming`
///   was consumed.
/// * `Drop` with the lease still present — every abnormal terminal. The
///   `SendRequest` drops, hyper's driver ends, and the CONNECT tunnel closes.
struct HboneInnerH1StreamingLease {
    pool: Arc<HboneInnerConnectionPool>,
    checkout: Option<HboneInnerH1Checkout>,
}

impl crate::proxy::body::PooledBackendLease for HboneInnerH1StreamingLease {
    fn release_on_clean_eof(mut self: Box<Self>) {
        if let Some(checkout) = self.checkout.take() {
            HboneInnerConnectionPool::checkin_h1_when_idle(&self.pool, checkout);
        }
    }
}

struct IdleH1 {
    sender: HboneInnerH1Sender,
    last_used_at: AtomicU64,
    idle_timeout_seconds: u64,
    credential_deadline: Option<tokio::time::Instant>,
}

struct SharedH2 {
    sender: HboneInnerH2Sender,
    last_used_at: AtomicU64,
    idle_timeout_seconds: u64,
    credential_deadline: Option<tokio::time::Instant>,
}

/// Everything one key owns.
#[derive(Default)]
struct KeySlot {
    h1_idle: Vec<IdleH1>,
    h2: Option<SharedH2>,
}

impl KeySlot {
    fn is_empty(&self) -> bool {
        self.h1_idle.is_empty() && self.h2.is_none()
    }
}

/// A snapshot of this pool's own process-lifetime counters.
///
/// The operator-facing view is the Prometheus family
/// `ferrum_mesh_hbone_inner_pool_events_total`, which every recorder below
/// increments in step; this struct is the same accounting read back directly,
/// which is what lets a test assert "one CONNECT, two hits" rather than
/// scraping an exposition.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HboneInnerPoolStats {
    pub h1_hits: u64,
    pub h1_misses: u64,
    pub h2_hits: u64,
    pub h2_misses: u64,
    /// Connections removed from the pool because they were closed, idle-expired,
    /// or their credential deadline elapsed.
    pub evictions: u64,
    /// Connections that finished their exchange healthy but were NOT pooled: a
    /// peer that did not advertise the fence, keep-alive off, an elapsed
    /// credential deadline, a full key, or the global ceiling.
    pub discards: u64,
    /// Inner connections currently resident in the pool.
    pub pooled: u64,
}

/// Bounded pool of inner application connections inside fenced HBONE tunnels.
///
/// Owned by [`super::hbone_pool::HboneConnectionPool`], which is what makes
/// every existing source-side trust drain reach these connections too.
pub struct HboneInnerConnectionPool {
    entries: DashMap<String, KeySlot>,
    /// Resident inner connections, maintained at every insert and removal so
    /// the global ceiling never scans the map.
    pooled: AtomicUsize,
    last_idle_prune_unix_secs: AtomicU64,
    h1_hits: AtomicU64,
    h1_misses: AtomicU64,
    h2_hits: AtomicU64,
    h2_misses: AtomicU64,
    evictions: AtomicU64,
    discards: AtomicU64,
}

impl HboneInnerConnectionPool {
    pub fn new(shard_amount: usize) -> Self {
        Self {
            entries: DashMap::with_shard_amount(shard_amount.max(1)),
            pooled: AtomicUsize::new(0),
            last_idle_prune_unix_secs: AtomicU64::new(0),
            h1_hits: AtomicU64::new(0),
            h1_misses: AtomicU64::new(0),
            h2_hits: AtomicU64::new(0),
            h2_misses: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
            discards: AtomicU64::new(0),
        }
    }

    pub fn stats(&self) -> HboneInnerPoolStats {
        HboneInnerPoolStats {
            h1_hits: self.h1_hits.load(Ordering::Relaxed),
            h1_misses: self.h1_misses.load(Ordering::Relaxed),
            h2_hits: self.h2_hits.load(Ordering::Relaxed),
            h2_misses: self.h2_misses.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
            discards: self.discards.load(Ordering::Relaxed),
            pooled: self.pooled.load(Ordering::Relaxed) as u64,
        }
    }

    /// Resident inner connections right now.
    pub fn pooled_connections(&self) -> usize {
        self.pooled.load(Ordering::Relaxed)
    }

    /// The effective idle timeout for an inner connection under `pool_config`.
    fn idle_timeout_seconds(pool_config: &PoolConfig) -> u64 {
        pool_config
            .idle_timeout_seconds
            .max(MIN_INNER_IDLE_TIMEOUT_SECONDS)
    }

    fn record(&self, protocol: HboneInnerProtocol, event: HboneInnerPoolEvent) {
        crate::plugins::prometheus_metrics::global_registry()
            .record_hbone_inner_pool_event(protocol.event_protocol(), event);
    }

    fn record_hit(&self, protocol: HboneInnerProtocol) {
        match protocol {
            HboneInnerProtocol::Http1 => self.h1_hits.fetch_add(1, Ordering::Relaxed),
            HboneInnerProtocol::H2 => self.h2_hits.fetch_add(1, Ordering::Relaxed),
        };
        self.record(protocol, HboneInnerPoolEvent::Hit);
    }

    fn record_miss(&self, protocol: HboneInnerProtocol) {
        match protocol {
            HboneInnerProtocol::Http1 => self.h1_misses.fetch_add(1, Ordering::Relaxed),
            HboneInnerProtocol::H2 => self.h2_misses.fetch_add(1, Ordering::Relaxed),
        };
        self.record(protocol, HboneInnerPoolEvent::Miss);
    }

    fn record_evictions(&self, protocol: HboneInnerProtocol, count: usize) {
        if count == 0 {
            return;
        }
        self.evictions.fetch_add(count as u64, Ordering::Relaxed);
        self.release_pooled(count);
        // Resolve the registry ONCE: a whole-pool drain evicts many entries at
        // a time and `global_registry()` clones an `Arc` on every call.
        let registry = crate::plugins::prometheus_metrics::global_registry();
        for _ in 0..count {
            registry.record_hbone_inner_pool_event(
                protocol.event_protocol(),
                HboneInnerPoolEvent::Eviction,
            );
        }
    }

    fn record_discard(&self, protocol: HboneInnerProtocol) {
        self.discards.fetch_add(1, Ordering::Relaxed);
        self.record(protocol, HboneInnerPoolEvent::Discard);
    }

    /// Give `count` residency slots back to the global ceiling.
    ///
    /// Saturating: the counter is maintained at every insert and removal, and a
    /// gauge that can go negative would be worse than one that briefly
    /// over-reports, since the ceiling is what it guards.
    fn release_pooled(&self, count: usize) {
        let _ = self
            .pooled
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                Some(current.saturating_sub(count))
            });
    }

    /// Whether a pooled entry is still usable right now.
    fn entry_live(
        closed: bool,
        last_used_at: u64,
        idle_timeout_seconds: u64,
        credential_deadline: Option<tokio::time::Instant>,
        now_secs: u64,
        now_mono: tokio::time::Instant,
    ) -> bool {
        !closed
            && !entry_idle_expired(last_used_at, idle_timeout_seconds, now_secs)
            && credential_deadline.is_none_or(|deadline| now_mono < deadline)
    }

    /// The earlier of two optional monotonic deadlines. `None` on either side
    /// means "this credential published no representable bound", never
    /// "unbounded wins".
    pub fn earliest_deadline(
        left: Option<tokio::time::Instant>,
        right: Option<tokio::time::Instant>,
    ) -> Option<tokio::time::Instant> {
        match (left, right) {
            (Some(left), Some(right)) => Some(left.min(right)),
            (Some(only), None) | (None, Some(only)) => Some(only),
            (None, None) => None,
        }
    }

    /// Amortised idle/expiry sweep. Runs at most once every
    /// [`IDLE_PRUNE_INTERVAL_SECONDS`], on a checkout, never on a timer and
    /// never on the byte path.
    fn maybe_prune(&self) {
        let now = unix_secs();
        let last = self.last_idle_prune_unix_secs.load(Ordering::Relaxed);
        if now.saturating_sub(last) < IDLE_PRUNE_INTERVAL_SECONDS
            || self
                .last_idle_prune_unix_secs
                .compare_exchange(last, now, Ordering::AcqRel, Ordering::Relaxed)
                .is_err()
        {
            return;
        }
        let now_mono = tokio::time::Instant::now();
        let mut h1_dropped = 0usize;
        let mut h2_dropped = 0usize;
        self.entries.retain(|_, slot| {
            let before = slot.h1_idle.len();
            slot.h1_idle.retain(|entry| {
                Self::entry_live(
                    entry.sender.is_closed(),
                    entry.last_used_at.load(Ordering::Relaxed),
                    entry.idle_timeout_seconds,
                    entry.credential_deadline,
                    now,
                    now_mono,
                )
            });
            h1_dropped = h1_dropped.saturating_add(before.saturating_sub(slot.h1_idle.len()));
            if slot.h2.as_ref().is_some_and(|entry| {
                !Self::entry_live(
                    entry.sender.is_closed(),
                    entry.last_used_at.load(Ordering::Relaxed),
                    entry.idle_timeout_seconds,
                    entry.credential_deadline,
                    now,
                    now_mono,
                )
            }) {
                slot.h2 = None;
                h2_dropped = h2_dropped.saturating_add(1);
            }
            !slot.is_empty()
        });
        self.record_evictions(HboneInnerProtocol::Http1, h1_dropped);
        self.record_evictions(HboneInnerProtocol::H2, h2_dropped);
    }

    /// Take an idle inner HTTP/1.1 sender for `key`, with the credential
    /// deadline it was pooled under.
    ///
    /// Every entry the scan rejects is EVICTED rather than skipped: a closed,
    /// idle-expired, or credential-expired connection must not stay reachable.
    fn take_idle_h1(
        &self,
        key: &str,
    ) -> Option<(HboneInnerH1Sender, Option<tokio::time::Instant>)> {
        let now = unix_secs();
        let now_mono = tokio::time::Instant::now();
        let mut evicted = 0usize;
        let mut taken = None;
        let mut emptied = false;
        if let Some(mut slot) = self.entries.get_mut(key) {
            while let Some(entry) = slot.h1_idle.pop() {
                if Self::entry_live(
                    entry.sender.is_closed(),
                    entry.last_used_at.load(Ordering::Relaxed),
                    entry.idle_timeout_seconds,
                    entry.credential_deadline,
                    now,
                    now_mono,
                ) {
                    taken = Some((entry.sender, entry.credential_deadline));
                    break;
                }
                evicted = evicted.saturating_add(1);
            }
            emptied = slot.is_empty();
        }
        if emptied {
            self.entries.remove_if(key, |_, slot| slot.is_empty());
        }
        self.record_evictions(HboneInnerProtocol::Http1, evicted);
        if taken.is_some() {
            // The taken connection leaves the pool for the duration of the
            // exclusive lease; a check-in re-counts it.
            self.release_pooled(1);
        }
        taken
    }

    /// Check out an inner HTTP/1.1 lease for `parts`, or `None` when nothing
    /// reusable exists and the caller must dial a fresh CONNECT.
    ///
    /// `keep_alive` is the dispatch's effective `pool_enable_http_keep_alive`.
    /// With it off the idle set is not even consulted: nothing is ever checked
    /// in under that policy, so there is nothing to find.
    ///
    /// `credential_deadline` is the CURRENT request's source credential bound.
    /// It does NOT decide whether the pooled entry may exist — that is the
    /// entry's OWN recorded bound, and an elapsed one evicts. It is folded
    /// into the lease that comes back, so the bound a connection carries only
    /// ever TIGHTENS across the requests that use it and reuse can never
    /// prolong a credential's lifetime. Whether a request whose own credential
    /// has already elapsed may be dispatched at all is the request
    /// authorization lifetime's decision, taken before this pool is consulted.
    pub fn checkout_h1(
        &self,
        parts: &HboneInnerKeyParts<'_>,
        keep_alive: bool,
        credential_deadline: Option<tokio::time::Instant>,
    ) -> Option<HboneInnerH1Checkout> {
        if !keep_alive {
            return None;
        }
        self.maybe_prune();
        let idle_timeout_seconds = Self::idle_timeout_seconds(parts.pool_config);
        let taken = with_hbone_inner_pool_key(parts, |key| {
            self.take_idle_h1(key)
                .map(|(sender, pooled_deadline)| (key.to_string(), sender, pooled_deadline))
        });
        let (key, sender, pooled_deadline) = taken?;
        self.record_hit(HboneInnerProtocol::Http1);
        Some(HboneInnerH1Checkout {
            key,
            reused: true,
            credential_deadline: Self::earliest_deadline(pooled_deadline, credential_deadline),
            idle_timeout_seconds,
            poolable: true,
            sender,
        })
    }

    /// Wrap a freshly established inner HTTP/1.1 sender as a lease that is
    /// used ONCE and never pooled, with no key and no accounting.
    ///
    /// The escape hatch for a dispatch that has no pool identity to file the
    /// connection under — this gateway could not resolve its own SVID
    /// identity, which is already fatal for the dial the caller is about to
    /// report. Behaviourally identical to the pre-#5042 path, which is the
    /// point: the absence of a key must degrade to per-request behaviour, never
    /// to a connection pooled under a partial identity.
    pub fn unpooled_h1(sender: HboneInnerH1Sender) -> HboneInnerH1Checkout {
        HboneInnerH1Checkout {
            key: String::new(),
            reused: false,
            credential_deadline: None,
            idle_timeout_seconds: MIN_INNER_IDLE_TIMEOUT_SECONDS,
            poolable: false,
            sender,
        }
    }

    /// Wrap a freshly established inner HTTP/1.1 sender as a lease.
    ///
    /// `peer_advertises_fence` is
    /// [`super::hbone_pool::H2ConnectTunnel::peer_advertises_inner_reuse`] for
    /// the CONNECT this sender runs inside. `false` produces a lease that is
    /// used once and never pooled, which is exactly the pre-#5042 behaviour.
    pub fn fresh_h1(
        &self,
        parts: &HboneInnerKeyParts<'_>,
        sender: HboneInnerH1Sender,
        peer_advertises_fence: bool,
        keep_alive: bool,
        credential_deadline: Option<tokio::time::Instant>,
    ) -> HboneInnerH1Checkout {
        let key = with_hbone_inner_pool_key(parts, |key| key.to_string());
        self.record_miss(HboneInnerProtocol::Http1);
        HboneInnerH1Checkout {
            key,
            reused: false,
            credential_deadline,
            idle_timeout_seconds: Self::idle_timeout_seconds(parts.pool_config),
            poolable: peer_advertises_fence && keep_alive,
            sender,
        }
    }

    /// Return an inner HTTP/1.1 lease to the idle set once hyper's dispatcher
    /// has re-armed.
    ///
    /// The caller must already have proven that the ENTIRE response body was
    /// read: `SendRequest::is_ready()` is only the second half of the check.
    /// h1 `can_write_head()` is true while a response body is still being read,
    /// so readiness alone would pool a connection mid-body. It is consulted
    /// only to close the dispatcher re-arm gap — `try_send_request` does not
    /// wait for readiness, so a sender pooled before its dispatcher re-arms
    /// would bounce the next request.
    ///
    /// If the connection died instead, `ready()` resolves `Err` and the lease
    /// is dropped, so the waiter lives exactly as long as the connection it
    /// owns and cannot leak.
    pub fn checkin_h1_when_idle(pool: &Arc<Self>, mut checkout: HboneInnerH1Checkout) {
        if !checkout.poolable
            || checkout.sender.is_closed()
            || checkout
                .credential_deadline
                .is_some_and(|deadline| tokio::time::Instant::now() >= deadline)
        {
            pool.record_discard(HboneInnerProtocol::Http1);
            return;
        }
        if checkout.sender.is_ready() {
            pool.checkin_h1(checkout);
            return;
        }
        let pool = Arc::clone(pool);
        tokio::spawn(async move {
            if checkout.sender.ready().await.is_ok() {
                pool.checkin_h1(checkout);
            } else {
                pool.record_discard(HboneInnerProtocol::Http1);
            }
        });
    }

    /// Insert a proven-idle inner HTTP/1.1 sender, subject to the per-key and
    /// global bounds. Over-cap is a DISCARD, not an error: the connection is
    /// simply closed, which is the pre-#5042 cost.
    ///
    /// The dispatch path MUST NOT call this directly for a connection that
    /// carried a request — use [`Self::checkin_h1_when_idle`], which first
    /// waits for hyper to report the exchange complete. This entry point is for
    /// a lease whose request was abandoned before it was ever sent, and for
    /// tests. A closed sender is still dropped rather than pooled.
    pub fn checkin_h1(&self, checkout: HboneInnerH1Checkout) {
        let HboneInnerH1Checkout {
            key,
            credential_deadline,
            idle_timeout_seconds,
            sender,
            ..
        } = checkout;
        if sender.is_closed() || self.pooled.load(Ordering::Relaxed) >= MAX_POOLED_INNER_CONNECTIONS
        {
            self.record_discard(HboneInnerProtocol::Http1);
            return;
        }
        let over_key_cap = {
            let mut slot = self.entries.entry(key).or_default();
            if slot.h1_idle.len() >= MAX_IDLE_H1_PER_KEY {
                true
            } else {
                slot.h1_idle.push(IdleH1 {
                    sender,
                    last_used_at: AtomicU64::new(unix_secs()),
                    idle_timeout_seconds,
                    credential_deadline,
                });
                false
            }
        };
        if over_key_cap {
            self.record_discard(HboneInnerProtocol::Http1);
        } else {
            self.pooled.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Wrap an exclusive inner HTTP/1.1 lease as a
    /// [`crate::proxy::body::PooledBackendLease`] for a STREAMING response.
    ///
    /// The returned guard owns the lease for as long as the `ProxyBody` holding
    /// the backend stream lives; that body releases it only on a proven clean
    /// backend end and drops it on every other terminal. Because the guard owns
    /// the only checkout, the connection cannot be handed to another request
    /// while the body is still streaming.
    pub fn streaming_lease(
        pool: &Arc<Self>,
        checkout: HboneInnerH1Checkout,
    ) -> Box<dyn crate::proxy::body::PooledBackendLease> {
        Box::new(HboneInnerH1StreamingLease {
            pool: Arc::clone(pool),
            checkout: Some(checkout),
        })
    }

    /// Clone the shared inner HTTP/2 sender for `parts`, or `None` on a miss.
    ///
    /// A sender that reports `is_closed()` — GOAWAY received and drained, the
    /// tunnel cut by a fence sweep, a transport error — is EVICTED here rather
    /// than skipped, so it can never be handed out again. That is the same
    /// liveness predicate `Http2PoolManager::is_healthy` applies to a direct
    /// HTTP/2 carrier; a busy-but-live multiplexed sender is deliberately kept,
    /// since retiring one for transient stream backpressure would replace
    /// multiplexing with a connection per RPC.
    pub fn checkout_h2(&self, parts: &HboneInnerKeyParts<'_>) -> Option<HboneInnerH2Sender> {
        self.maybe_prune();
        let now = unix_secs();
        let now_mono = tokio::time::Instant::now();
        let mut evicted = 0usize;
        let mut taken = None;
        with_hbone_inner_pool_key(parts, |key| {
            let mut emptied = false;
            if let Some(mut slot) = self.entries.get_mut(key) {
                match slot.h2.as_ref() {
                    Some(entry)
                        if Self::entry_live(
                            entry.sender.is_closed(),
                            entry.last_used_at.load(Ordering::Relaxed),
                            entry.idle_timeout_seconds,
                            // The ENTRY's own bound, deliberately not folded
                            // with the current request's. The two answer
                            // different questions: whether this carrier may
                            // still exist (the pool's job), and whether this
                            // request may still be served (the request
                            // authorization lifetime's job, decided before
                            // dispatch). Folding them would evict a healthy
                            // multiplexed carrier — and every other RPC on
                            // it — because ONE caller arrived with a
                            // short-lived JWT.
                            entry.credential_deadline,
                            now,
                            now_mono,
                        ) =>
                    {
                        entry.last_used_at.store(now, Ordering::Relaxed);
                        taken = Some(entry.sender.clone());
                    }
                    Some(_) => {
                        slot.h2 = None;
                        evicted = 1;
                    }
                    None => {}
                }
                emptied = slot.is_empty();
            }
            if emptied {
                self.entries.remove_if(key, |_, slot| slot.is_empty());
            }
        });
        self.record_evictions(HboneInnerProtocol::H2, evicted);
        match &taken {
            Some(_) => self.record_hit(HboneInnerProtocol::H2),
            None => self.record_miss(HboneInnerProtocol::H2),
        }
        taken
    }

    /// Publish a freshly established shared inner HTTP/2 sender.
    ///
    /// Never an error and never a refusal: the caller already owns the sender
    /// and serves its RPC on it either way. A peer that did not advertise the
    /// fence, an elapsed credential deadline, the global ceiling, or losing the
    /// race to a concurrent cold miss all leave the sender unpooled — which is
    /// exactly the per-request behaviour this module replaces.
    pub fn publish_h2(
        &self,
        parts: &HboneInnerKeyParts<'_>,
        sender: &HboneInnerH2Sender,
        peer_advertises_fence: bool,
        credential_deadline: Option<tokio::time::Instant>,
    ) {
        if !peer_advertises_fence
            || sender.is_closed()
            || credential_deadline.is_some_and(|deadline| tokio::time::Instant::now() >= deadline)
            || self.pooled.load(Ordering::Relaxed) >= MAX_POOLED_INNER_CONNECTIONS
        {
            self.record_discard(HboneInnerProtocol::H2);
            return;
        }
        let idle_timeout_seconds = Self::idle_timeout_seconds(parts.pool_config);
        let published = with_hbone_inner_pool_key(parts, |key| {
            let mut slot = self.entries.entry(key.to_string()).or_default();
            // A live incumbent wins: a concurrent cold miss must not replace a
            // carrier other requests are already multiplexed on.
            if slot
                .h2
                .as_ref()
                .is_some_and(|entry| !entry.sender.is_closed())
            {
                return false;
            }
            let replaced = slot.h2.is_some();
            slot.h2 = Some(SharedH2 {
                sender: sender.clone(),
                last_used_at: AtomicU64::new(unix_secs()),
                idle_timeout_seconds,
                credential_deadline,
            });
            !replaced
        });
        if published {
            self.pooled.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Retire every inner connection whose key embeds one of the `retired`
    /// gateway SVID leaf fingerprints.
    ///
    /// Driven by the outer pool's SVID rotation drain, so an inner connection
    /// established under a rotated-out leaf stops being reachable at exactly
    /// the moment the outer sessions built from it do.
    pub fn retire_svid_fingerprints(&self, retired: &[Arc<str>]) {
        if retired.is_empty() {
            return;
        }
        let mut h1_dropped = 0usize;
        let mut h2_dropped = 0usize;
        self.entries.retain(|key, slot| {
            let drain = hbone_inner_key_svid_fingerprint(key)
                .is_some_and(|fingerprint| retired.iter().any(|fp| fp.as_ref() == fingerprint));
            if drain {
                h1_dropped = h1_dropped.saturating_add(slot.h1_idle.len());
                h2_dropped = h2_dropped.saturating_add(usize::from(slot.h2.is_some()));
            }
            !drain
        });
        if h1_dropped + h2_dropped > 0 {
            debug!(
                h1_dropped,
                h2_dropped,
                "hbone_inner_pool: retired inner application connections for rotated SVID leaves"
            );
        }
        self.record_evictions(HboneInnerProtocol::Http1, h1_dropped);
        self.record_evictions(HboneInnerProtocol::H2, h2_dropped);
    }

    /// Retire EVERY pooled inner connection.
    ///
    /// The transitive half of the outer pool's whole-pool retirements: a CRL
    /// reload, a committed gateway trust withdrawal, and a forced drain all
    /// clear the outer HBONE transports whole, and an inner connection is only
    /// ever as trustworthy as the tunnel it rides.
    pub fn drain_all(&self) {
        let mut h1_dropped = 0usize;
        let mut h2_dropped = 0usize;
        self.entries.retain(|_, slot| {
            h1_dropped = h1_dropped.saturating_add(slot.h1_idle.len());
            h2_dropped = h2_dropped.saturating_add(usize::from(slot.h2.is_some()));
            false
        });
        self.record_evictions(HboneInnerProtocol::Http1, h1_dropped);
        self.record_evictions(HboneInnerProtocol::H2, h2_dropped);
    }
}

impl Default for HboneInnerConnectionPool {
    fn default() -> Self {
        Self::new(8)
    }
}
