//! One shared, fail-closed **single-use replay authority** for every gateway
//! admission control whose security property is "this exact proof may be
//! accepted at most once".
//!
//! Two plugins own such a property today — `jwks_auth`'s RFC 9449 DPoP proofs
//! (`jti` + JWK thumbprint) and `hmac_auth`'s `ferrum-hmac-v2` signed nonces —
//! and they must not grow two incompatible replay infrastructures with
//! different ownership, capacity, reload, and HA semantics. Everything that
//! decides whether a marker is fresh lives here.
//!
//! # What is stored
//!
//! Nothing that came off the wire. A marker is a fixed-size SHA-256 digest of a
//! **protection domain** and a **proof identity**, produced by
//! [`ReplayDomain::marker`]. No raw token, proof JWT, `jti`, nonce, signature,
//! username, subject, issuer, request path, query string, body digest, or
//! secret is retained, keyed, logged, or sent to a shared backend. Redis keys
//! reach `MONITOR`, `SLOWLOG`, and the Redis client's own error logging, so the
//! only thing that may become a key is a digest.
//!
//! Every field of a domain and of a marker is written through
//! [`replay_partition::PartitionHasher`], which frames each field as
//! `len(label) || label || len(value) || value`. Raw delimiter concatenation
//! (`a|b`) is structurally unsafe: an attacker-chosen `jti` containing the
//! delimiter could otherwise reproduce another domain's preimage.
//!
//! # Ownership: the lane, not the plugin instance
//!
//! Replay state is owned by a **stable policy identity** — `namespace` +
//! plugin name + plugin-config id (+ an optional plugin-chosen sub-domain such
//! as a digest of one provider's trust anchor) — and never by the plugin object
//! a `PluginCache` rebuild happened to construct. A `jwks_auth` provider that
//! reloads with an equivalent configuration rejoins the same
//! [`ProcessReplayLane`] and inherits its live markers; an empty replacement
//! cache is exactly the reload replay opening this module exists to close.
//!
//! A sub-domain must be *semantic* for the same reason. `jwks_auth` derives one
//! from each provider's trust anchor rather than from its position in the
//! `providers` array: an ordinal is not an identity, and reordering an unchanged
//! list would otherwise strand a provider's live markers in a lane nothing
//! consults and readmit a proof it had already claimed.
//!
//! Lanes live in a process-global registry ([`PROCESS_REPLAY_LANES`]) held by
//! **strong** reference, so a deleted or renamed policy leaves its lane behind
//! as a tombstone until every marker it retains has expired. Reclamation is
//! cold-path only (lane creation), bounded, and never touches a live marker:
//! [`ProcessReplayLane::all_markers_expired`] reads one atomic high-water mark
//! rather than scanning the map.
//!
//! # Capacity never forgets a live marker
//!
//! At capacity the lane prunes **expired** entries and nothing else. If no
//! expired slot can be reclaimed the new protected request is refused with the
//! fixed [`ReplayAdmission::CapacityRefused`] classification. Evicting an
//! unexpired marker to admit a new request — the previous `DpopJtiCache`
//! behavior — treats capacity pressure as permission to forget a replay marker,
//! which lets a client with one valid credential burn other clients' protection
//! by generating unique proofs. Capacity degrades into refusal, never into
//! silent unprotection.
//!
//! The shared lane retains markers; each live authority enforces the
//! `max_entries` *it was admitted with* against that shared count. An equivalent
//! reload that raises or lowers the configured capacity therefore takes effect
//! without rebuilding the lane, evicting a live marker, or changing the replay
//! domain. Lowering the limit refuses new admissions once the shared count meets
//! the new cap; raising it restores headroom. The first constructor does **not**
//! freeze a cap onto the lane — that would make a later equivalent generation's
//! configured capacity silently inert, and would make duplicate equivalent
//! constructors order-dependent.
//!
//! # Retention is fixed, not configured
//!
//! Each caller declares one compile-time retention horizon that dominates the
//! widest span over which *any admissible configuration* can accept one
//! unchanged proof (for DPoP: `2 * max clock skew`). This is not a knob:
//!
//! * a later generation that **widens** its clock skew would otherwise make a
//!   captured proof acceptable again after its shorter marker had already been
//!   reclaimed, and nothing can resurrect a dropped marker;
//! * `SET … NX EX` cannot rewrite the TTL of a key it did not create, so a
//!   shared marker written under an old, shorter TTL expires early no matter
//!   what a new generation declares.
//!
//! Because every generation and every replica writes the same horizon, an
//! existing marker always keeps at least the protection interval it was
//! admitted with, across reloads and rolling deployments alike.
//!
//! # Scope is an explicit operator declaration
//!
//! [`ReplayScope`] has **no default**. A gateway cannot observe its own replica
//! count, so "is this deployment single-process?" is an auditable declaration
//! rather than an inference. `process` asserts a single-process/development
//! deployment; `shared` points every replica at one authority (an atomic Redis
//! `SET … NX EX`). There is deliberately no fallback between them: falling back
//! to process-local acceptance when the shared authority is unreachable
//! reinstates exactly the cross-replica bypass the shared authority exists to
//! close. A shared-backend timeout, partition, authentication failure,
//! corruption, or capacity failure rejects the protected request.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use dashmap::mapref::entry::Entry;

use super::redis_rate_limiter::RedisRateLimitClient;
use super::replay_partition::PartitionHasher;

/// Upper bound on distinct process replay lanes retained for the life of the
/// process.
///
/// Lanes are keyed by operator-controlled configuration identity, so the key
/// space must be bounded. Admission fails closed at the cap rather than
/// silently dropping replay history.
pub const MAX_PROCESS_REPLAY_LANES: usize = 1_024;

/// Fixed non-secret marker value written for a shared claim. The claim is
/// proven by the key existing, so nothing derived from a credential is stored.
const SHARED_MARKER_RECORD: &[u8] = b"ferrum-replay-marker-v1";

/// Redis key component that separates replay markers from any other keyspace
/// sharing a configured prefix.
const SHARED_KEY_COMPONENT: &str = "replay";

/// Process-relative monotonic base. Markers store an expiry in milliseconds
/// since this instant so an entry is 8 bytes and no `Instant` is retained.
static PROCESS_START: LazyLock<Instant> = LazyLock::new(Instant::now);

/// Monotonic milliseconds since [`PROCESS_START`].
///
/// Saturating: a process running longer than ~584 million years would clamp
/// rather than wrap, which is the fail-closed direction (markers stop expiring
/// rather than expiring early).
pub fn monotonic_millis() -> u64 {
    u64::try_from(PROCESS_START.elapsed().as_millis()).unwrap_or(u64::MAX)
}

// ── Observability ───────────────────────────────────────────────────────────

/// Process-global replay counters. Deliberately **unlabeled**: no namespace,
/// plugin id, provider, consumer, issuer, thumbprint, nonce, marker, route, or
/// backend error text can reach them.
static REPLAY_REJECTED: AtomicU64 = AtomicU64::new(0);
static CAPACITY_REFUSED: AtomicU64 = AtomicU64::new(0);
static AUTHORITY_UNAVAILABLE: AtomicU64 = AtomicU64::new(0);
static ADMITTED_PROCESS: AtomicU64 = AtomicU64::new(0);
static ADMITTED_SHARED: AtomicU64 = AtomicU64::new(0);
static LEGACY_UNSAFE_PROFILE_ACCEPTED: AtomicU64 = AtomicU64::new(0);

/// Snapshot of the replay-authority counters for the runtime metrics endpoint.
///
/// Monotonic for the process lifetime, except `shared_authorities_unavailable`
/// and `process_lanes`, which are current cardinalities.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct ReplayAuthorityCounters {
    /// Protected requests refused because the exact proof was already admitted.
    pub replay_rejected: u64,
    /// Protected requests refused because no expired marker slot could be
    /// reclaimed. Never an eviction of a live marker.
    pub capacity_refused: u64,
    /// Protected requests refused because the authority was unreachable,
    /// timed out, partitioned, rejected authentication, or returned an
    /// uncertain result. Never a fallback to local acceptance.
    pub authority_unavailable: u64,
    /// Markers admitted against a process-local (single-process) lane.
    pub admitted_process: u64,
    /// Markers admitted against the shared (cross-replica) authority.
    pub admitted_shared: u64,
    /// Requests accepted under an explicitly unsafe legacy freshness-only
    /// signing profile that provides no single-use guarantee.
    pub legacy_unsafe_profile_accepted: u64,
    /// Registered shared authorities whose backend is currently unavailable.
    /// Non-zero means protected requests on those policies are failing closed.
    pub shared_authorities_unavailable: u64,
    /// Registered shared authorities.
    pub shared_authorities: u64,
    /// Live process replay lanes (bounded by [`MAX_PROCESS_REPLAY_LANES`]).
    pub process_lanes: u64,
}

/// Read the replay-authority counters.
pub fn counters() -> ReplayAuthorityCounters {
    let (shared_authorities, shared_authorities_unavailable) = shared_authority_health();
    ReplayAuthorityCounters {
        replay_rejected: REPLAY_REJECTED.load(Ordering::Relaxed),
        capacity_refused: CAPACITY_REFUSED.load(Ordering::Relaxed),
        authority_unavailable: AUTHORITY_UNAVAILABLE.load(Ordering::Relaxed),
        admitted_process: ADMITTED_PROCESS.load(Ordering::Relaxed),
        admitted_shared: ADMITTED_SHARED.load(Ordering::Relaxed),
        legacy_unsafe_profile_accepted: LEGACY_UNSAFE_PROFILE_ACCEPTED.load(Ordering::Relaxed),
        shared_authorities_unavailable,
        shared_authorities,
        process_lanes: process_lane_count() as u64,
    }
}

/// Record one acceptance under an explicitly unsafe legacy freshness-only
/// profile, so operators can see that a deployment still depends on it.
pub fn record_legacy_unsafe_profile_accepted() {
    LEGACY_UNSAFE_PROFILE_ACCEPTED.fetch_add(1, Ordering::Relaxed);
}

// ── Scope ───────────────────────────────────────────────────────────────────

/// Operator-declared deployment scope for replay state.
///
/// There is no `Default` impl on purpose. Silently defaulting to process-local
/// state is the posture that lets a captured proof be accepted once per
/// replica; the caller must require an explicit declaration whenever its
/// single-use protection is active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayScope {
    /// Single-process / development contract. Replay state is stable across
    /// equivalent in-process reloads but is explicitly **not** cross-replica.
    Process,
    /// Production HA contract. Every replica serving one protection domain
    /// claims through one atomic shared authority.
    Shared,
}

impl ReplayScope {
    /// Parse the shared `replay_scope` configuration value.
    pub fn parse(plugin: &str, field: &str, value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "process" => Ok(Self::Process),
            "shared" => Ok(Self::Shared),
            _ => Err(format!(
                "{plugin}: '{field}' must be exactly 'process' or 'shared' — use 'shared' \
                 together with sync_mode: 'redis' for any deployment running more than one \
                 gateway replica, or 'process' to declare a single-process deployment whose \
                 replay protection is not cross-replica"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Process => "process",
            Self::Shared => "shared",
        }
    }
}

// ── Domain and marker identity ──────────────────────────────────────────────

/// Precomputed, fixed-size identity of one protection domain.
///
/// Built once at plugin construction (never per request) from a bounded set of
/// configuration-derived components. Two policies never share a domain, and two
/// replicas of the same policy always derive the same one — which is what makes
/// a shared claim meaningful and a rolling deployment safe.
#[derive(Clone)]
pub struct ReplayDomain {
    digest: [u8; 32],
}

impl std::fmt::Debug for ReplayDomain {
    /// The digest is not secret, but it is also not actionable, and printing it
    /// in a log line invites treating it as an identifier for correlation.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ReplayDomain(<digest>)")
    }
}

impl ReplayDomain {
    /// Derive a protection domain.
    ///
    /// * `profile` — the versioned proof profile (`ferrum-dpop-proof-v1`,
    ///   `ferrum-hmac-v2`). Two profiles never share markers, so a future
    ///   profile revision cannot be answered from an old profile's history.
    /// * `namespace` / `plugin` / `config_id` — the stable policy identity.
    /// * `sub_domain` — a bounded, configuration-derived discriminator such as
    ///   a digest of one provider's trust anchor. It must be *semantic*: an
    ///   ordinal position in a configuration array is not an identity, because
    ///   reordering an unchanged list would move a policy into a fresh lane and
    ///   reopen every proof it had already claimed. Never request-controlled
    ///   data.
    pub fn new(
        profile: &str,
        namespace: &str,
        plugin: &str,
        config_id: &str,
        sub_domain: &str,
    ) -> Self {
        let mut hasher = PartitionHasher::new("ferrum-edge/replay-authority/domain/v1");
        hasher.text("domain.profile", profile);
        hasher.text("domain.namespace", namespace);
        hasher.text("domain.plugin", plugin);
        hasher.text("domain.config_id", config_id);
        hasher.text("domain.sub_domain", sub_domain);
        Self {
            digest: hasher.digest(),
        }
    }

    /// Derive the marker for one proof identity inside this domain.
    ///
    /// `parts` are the credential-adjacent components that identify the proof
    /// (for DPoP the JWK thumbprint and the `jti`; for HMAC v2 the consumer
    /// identity and the client nonce). They are consumed here and never
    /// retained: only the resulting digest leaves this function.
    pub fn marker(&self, parts: &[&[u8]]) -> ReplayMarker {
        let mut hasher = PartitionHasher::new("ferrum-edge/replay-authority/marker/v1");
        hasher.nested("marker.domain", &self.digest);
        hasher.count("marker.parts", parts.len());
        for part in parts {
            hasher.field("marker.part", part);
        }
        ReplayMarker {
            digest: hasher.digest(),
        }
    }

    /// Raw domain digest.
    ///
    /// Opaque and non-secret: it is a hash of configuration identity only, and
    /// carries no credential, issuer, or request material. Callers use it to
    /// bind other request-scoped state to *this exact protection domain* (see
    /// `hmac_auth`'s prebuffer owner identity) and to assert domain isolation
    /// in external tests. It is deliberately not rendered by `Debug`.
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Stable process-lane registry key for this domain.
    ///
    /// The registry key is the domain digest in hex, so an operator-controlled
    /// namespace / config id can neither collide with another lane through a
    /// delimiter nor be read back out of the registry.
    fn lane_key(&self) -> String {
        hex::encode(self.digest)
    }
}

/// Fixed-size replay marker. Opaque; carries no recoverable proof material.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ReplayMarker {
    digest: [u8; 32],
}

impl std::fmt::Debug for ReplayMarker {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ReplayMarker(<digest>)")
    }
}

impl ReplayMarker {
    /// Lowercase hex rendering, used only as a shared-backend key component.
    fn hex(&self) -> String {
        hex::encode(self.digest)
    }

    /// Raw digest, for process-lane keying and external test assertions on
    /// domain isolation / cross-replica equality.
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

// ── Admission outcome ───────────────────────────────────────────────────────

/// Result of one atomic check-and-insert.
///
/// Every non-`Admitted` variant is terminal for the protected request. The
/// reasons are fixed-cardinality classifications, never backend error text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayAdmission {
    /// This exact proof was previously unseen and is now claimed.
    Admitted,
    /// This exact proof was already admitted inside its protection interval.
    Replay,
    /// Replay state is full and no expired marker could be reclaimed. A live
    /// marker is never evicted to admit a new request.
    CapacityRefused,
    /// The authority timed out, was partitioned, refused authentication,
    /// returned corrupt data, or was otherwise uncertain. Never a fallback to
    /// local acceptance.
    AuthorityUnavailable,
}

impl ReplayAdmission {
    #[allow(dead_code)] // exercised by external unit tests
    pub fn is_admitted(self) -> bool {
        matches!(self, Self::Admitted)
    }

    /// Fixed, content-free classification suitable for a log field.
    pub fn classification(self) -> &'static str {
        match self {
            Self::Admitted => "admitted",
            Self::Replay => "replay",
            Self::CapacityRefused => "capacity_refused",
            Self::AuthorityUnavailable => "authority_unavailable",
        }
    }
}

// ── Process lane ────────────────────────────────────────────────────────────

/// Process-local replay state for one protection domain.
///
/// Shared by every plugin generation that resolves the same domain, so an
/// equivalent reload inherits live markers instead of starting empty.
pub struct ProcessReplayLane {
    /// Marker digest → expiry in monotonic milliseconds since process start.
    entries: DashMap<[u8; 32], u64>,
    entry_count: AtomicUsize,
    /// Highest expiry ever written. Reading it is how lane reclamation proves
    /// "no live marker remains" without scanning the map.
    newest_expiry_millis: AtomicU64,
    /// Serializes the capacity-pressure prune so concurrent saturated requests
    /// do not each walk the map. Never taken on the ordinary admission path.
    prune_lock: Mutex<()>,
}

impl ProcessReplayLane {
    fn new(shard_amount: usize) -> Arc<Self> {
        Arc::new(Self {
            entries: DashMap::with_shard_amount(shard_amount),
            entry_count: AtomicUsize::new(0),
            newest_expiry_millis: AtomicU64::new(0),
            prune_lock: Mutex::new(()),
        })
    }

    /// Atomic check-and-insert. Exactly one of any number of concurrent
    /// admissions of a previously unseen marker observes
    /// [`ReplayAdmission::Admitted`].
    ///
    /// The decision and the insertion happen under one DashMap entry guard, so
    /// there is no read-then-write window. The capacity path releases that
    /// guard before pruning and then re-acquires it, because a concurrent
    /// request may have claimed the same marker while this one waited — a live
    /// duplicate must be rejected rather than displace the marker that beat it.
    pub fn admit_at(
        &self,
        marker: &ReplayMarker,
        retention: Duration,
        max_entries: usize,
        now_millis: u64,
    ) -> ReplayAdmission {
        let retention_millis = u64::try_from(retention.as_millis()).unwrap_or(u64::MAX);
        let expires_at = now_millis.saturating_add(retention_millis);
        let mut key = marker.digest;
        let mut pruned = false;

        loop {
            match self.entries.entry(key) {
                Entry::Occupied(mut existing) => {
                    if *existing.get() > now_millis {
                        return ReplayAdmission::Replay;
                    }
                    // The marker is expired. Replacing it in place is atomic
                    // under the shard guard and consumes no additional capacity
                    // slot, so an expired entry can never accumulate as a leak
                    // and can never be mistaken for a live claim. The stored
                    // expiry only ever moves forward.
                    let refreshed = (*existing.get()).max(expires_at);
                    existing.insert(refreshed);
                    self.note_expiry(refreshed);
                    return ReplayAdmission::Admitted;
                }
                Entry::Vacant(vacant) => {
                    if self.try_reserve_slot(max_entries) {
                        vacant.insert(expires_at);
                        self.note_expiry(expires_at);
                        return ReplayAdmission::Admitted;
                    }
                    // Do not walk other shards while holding a vacant-entry
                    // guard: the prune below touches every shard.
                    key = vacant.into_key();
                }
            }

            if pruned {
                // One bounded prune round has already run and the lane is still
                // full — either nothing was reclaimable or a concurrent request
                // took the reclaimed slot. Fail closed rather than retry
                // unboundedly, and never take a live marker to make room.
                return ReplayAdmission::CapacityRefused;
            }
            pruned = true;
            if self.prune_expired(now_millis) == 0 {
                return ReplayAdmission::CapacityRefused;
            }
        }
    }

    fn note_expiry(&self, expires_at: u64) {
        self.newest_expiry_millis
            .fetch_max(expires_at, Ordering::AcqRel);
    }

    fn try_reserve_slot(&self, max_entries: usize) -> bool {
        self.entry_count
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < max_entries).then_some(count + 1)
            })
            .is_ok()
    }

    /// Reclaim **expired** entries only. Returns how many were reclaimed.
    ///
    /// Serialized by [`Self::prune_lock`] so a burst of saturated requests pays
    /// for at most one concurrent walk. Bounded by the lane's retained entries,
    /// and reached only when the calling authority is already at its cap.
    fn prune_expired(&self, now_millis: u64) -> usize {
        let _guard = self
            .prune_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let expired: Vec<[u8; 32]> = self
            .entries
            .iter()
            .filter(|entry| *entry.value() <= now_millis)
            .map(|entry| *entry.key())
            .collect();
        let mut reclaimed = 0usize;
        for key in expired {
            // Re-check the expiry under the shard guard: a concurrent request
            // may have refreshed this marker between the scan and the removal,
            // and removing it then would drop a live claim.
            if self
                .entries
                .remove_if(&key, |_, expires_at| *expires_at <= now_millis)
                .is_some()
            {
                self.entry_count.fetch_sub(1, Ordering::AcqRel);
                reclaimed += 1;
            }
        }
        reclaimed
    }

    /// Whether every marker this lane retains has expired.
    ///
    /// One atomic load, not a map scan: the high-water mark is the newest
    /// expiry ever written, so if it is in the past no live marker remains.
    fn all_markers_expired(&self, now_millis: u64) -> bool {
        self.newest_expiry_millis.load(Ordering::Acquire) <= now_millis
    }

    /// Retained entry count, including entries whose expiry has passed but
    /// which lazy reclamation has not yet removed (test support).
    #[allow(dead_code)] // exercised by external unit tests
    pub fn retained_entries(&self) -> usize {
        self.entry_count.load(Ordering::Acquire)
    }
}

/// Process-global lane registry, keyed by protection-domain digest.
///
/// Held by strong reference: a deleted or reconfigured policy leaves its lane
/// as a tombstone so its live markers keep protecting, and the lane is
/// reclaimed only once every marker has expired.
static PROCESS_REPLAY_LANES: LazyLock<Mutex<HashMap<String, Arc<ProcessReplayLane>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn process_lane_count() -> usize {
    PROCESS_REPLAY_LANES
        .lock()
        .map(|registry| registry.len())
        .unwrap_or(0)
}

/// Resolve (or create) the process lane for `domain`.
///
/// Cold path only — plugin construction, never a request. Creating a new lane
/// first reclaims retired lanes whose markers have all expired, so deleted
/// configurations cannot permanently exhaust [`MAX_PROCESS_REPLAY_LANES`].
///
/// An existing lane is returned as-is: capacity is enforced by the calling
/// authority, not frozen onto the lane by the first constructor. Rejoining must
/// never rebuild, forget, or re-key the lane.
fn resolve_process_lane(
    plugin: &str,
    domain: &ReplayDomain,
    shard_amount: usize,
) -> Result<Arc<ProcessReplayLane>, String> {
    let key = domain.lane_key();
    let mut registry = PROCESS_REPLAY_LANES
        .lock()
        .map_err(|_| format!("{plugin}: replay lane registry is unavailable"))?;
    if let Some(existing) = registry.get(&key) {
        return Ok(Arc::clone(existing));
    }
    let now = monotonic_millis();
    registry.retain(|_, lane| Arc::strong_count(lane) > 1 || !lane.all_markers_expired(now));
    if registry.len() >= MAX_PROCESS_REPLAY_LANES {
        // Fixed diagnostic: the lane key is a digest and would not help an
        // operator act on this.
        return Err(format!(
            "{plugin}: refusing to create more than {MAX_PROCESS_REPLAY_LANES} distinct replay \
             lanes in one process"
        ));
    }
    let lane = ProcessReplayLane::new(shard_amount);
    registry.insert(key, Arc::clone(&lane));
    Ok(lane)
}

/// Number of live process replay lanes (test support).
#[allow(dead_code)] // exercised by external unit tests
pub fn process_lane_count_for_tests() -> usize {
    process_lane_count()
}

/// Whether a domain currently owns a registered process lane (test support).
#[allow(dead_code)] // exercised by external unit tests
pub fn process_lane_registered_for_tests(domain: &ReplayDomain) -> bool {
    PROCESS_REPLAY_LANES
        .lock()
        .map(|registry| registry.contains_key(&domain.lane_key()))
        .unwrap_or(false)
}

// ── Shared authority health registry ────────────────────────────────────────

/// Weak handles to every registered shared authority, so readiness/metrics can
/// report "a required shared replay backend is unavailable" without retaining
/// retired plugin generations, their connections, or their credentials.
static SHARED_AUTHORITIES: LazyLock<Mutex<Vec<std::sync::Weak<RedisRateLimitClient>>>> =
    LazyLock::new(|| Mutex::new(Vec::new()));

/// Bounded, fixed-cardinality aggregate of shared replay-authority health.
///
/// Two counters and nothing else. There is deliberately no endpoint, host,
/// namespace, plugin id, provider, key prefix, credential, or backend error
/// text here: this snapshot is published on the authenticated `/health` and
/// `/status` tier, so its cardinality must not grow with configuration.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct SharedReplayAuthorityHealth {
    /// Distinct shared authorities held by a live plugin generation. A retired
    /// generation drops its client, so it stops being counted.
    pub shared_authorities: u64,
    /// How many of those are currently unavailable. Non-zero means protected
    /// requests on those policies are failing closed.
    pub shared_authorities_unavailable: u64,
}

impl SharedReplayAuthorityHealth {
    /// Whether any live policy depends on a shared authority at all.
    pub fn required(self) -> bool {
        self.shared_authorities > 0
    }

    /// Whether a required shared authority is known unavailable.
    pub fn unavailable(self) -> bool {
        self.shared_authorities_unavailable > 0
    }
}

/// Recover a poisoned registry guard rather than dropping live authorities.
///
/// Poison means a previous holder panicked; the map itself is still the set of
/// weak handles that readiness aggregates. Returning the default empty/healthy
/// snapshot, or skipping registration, would hide an unavailable shared backend.
fn shared_authorities_lock()
-> std::sync::MutexGuard<'static, Vec<std::sync::Weak<RedisRateLimitClient>>> {
    SHARED_AUTHORITIES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn register_shared_authority(client: &Arc<RedisRateLimitClient>) {
    let mut registry = shared_authorities_lock();
    // Prune retired generations first: the registry is weak precisely so a
    // rebuilt plugin cache cannot keep an old generation's client, connections,
    // or credentials alive, and a stale entry must not keep being aggregated.
    registry.retain(|weak| weak.strong_count() > 0);
    // `jwks_auth` shares one client across every `shared` provider, so the same
    // authority reaches this function once per provider. Registering it twice
    // would report one backend as several and inflate a readiness aggregate.
    let target = Arc::as_ptr(client);
    if registry
        .iter()
        .any(|weak| std::ptr::eq(weak.as_ptr(), target))
    {
        return;
    }
    registry.push(Arc::downgrade(client));
}

/// Bounded aggregate over every live shared replay authority.
pub fn shared_health_snapshot() -> SharedReplayAuthorityHealth {
    let registry = shared_authorities_lock();
    let mut health = SharedReplayAuthorityHealth::default();
    for client in registry.iter().filter_map(std::sync::Weak::upgrade) {
        health.shared_authorities += 1;
        if !client.is_available() {
            health.shared_authorities_unavailable += 1;
        }
    }
    health
}

/// `(registered, unavailable)` shared authorities.
fn shared_authority_health() -> (u64, u64) {
    let health = shared_health_snapshot();
    (
        health.shared_authorities,
        health.shared_authorities_unavailable,
    )
}

/// Whether any registered shared replay authority is currently unavailable.
///
/// Protected requests on those policies are failing closed, which is a
/// readiness-relevant condition rather than a per-request error. Consumed by
/// the admin `/health` + `/status` readiness decision.
#[allow(dead_code)] // exercised by external unit tests
pub fn shared_authority_degraded() -> bool {
    shared_health_snapshot().unavailable()
}

// ── The authority ───────────────────────────────────────────────────────────

/// The replay authority one policy claims against.
pub enum ReplayAuthority {
    /// Single-process/development contract, stable across equivalent reloads.
    Process {
        lane: Arc<ProcessReplayLane>,
        retention: Duration,
        /// Cap this generation enforces against the shared lane. Live markers
        /// already in the lane are never evicted to meet it.
        max_entries: usize,
    },
    /// Production HA contract: one atomic `SET … NX EX` per marker.
    Shared {
        client: Arc<RedisRateLimitClient>,
        retention: Duration,
    },
}

impl std::fmt::Debug for ReplayAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReplayAuthority")
            .field("mode", &self.mode())
            .finish()
    }
}

impl ReplayAuthority {
    /// Build a process-scoped authority bound to `domain`'s stable lane.
    ///
    /// `retention` must be the caller's fixed compile-time horizon, not a
    /// configured value — see the module documentation.
    ///
    /// `max_entries` is enforced by *this* authority against the shared lane.
    /// An equivalent reload that changes the cap joins the same lane and
    /// applies the new cap without forgetting live markers.
    pub fn process(
        plugin: &str,
        domain: &ReplayDomain,
        max_entries: usize,
        retention: Duration,
        shard_amount: usize,
    ) -> Result<Self, String> {
        Ok(Self::Process {
            lane: resolve_process_lane(plugin, domain, shard_amount)?,
            retention,
            max_entries: max_entries.max(1),
        })
    }

    /// Build a shared authority over an existing Redis client.
    ///
    /// Callers must pass a client from
    /// [`RedisRateLimitClient::for_replay_authority`] so connection,
    /// authentication, command, topology, and recovery diagnostics stay
    /// classification-only. Generic rate-limiter clients retain
    /// [`RedisRateLimitClient::new`].
    pub fn shared(client: Arc<RedisRateLimitClient>, retention: Duration) -> Self {
        register_shared_authority(&client);
        Self::Shared { client, retention }
    }

    /// Fixed-cardinality mode label.
    pub fn mode(&self) -> &'static str {
        match self {
            Self::Process { .. } => ReplayScope::Process.as_str(),
            Self::Shared { .. } => ReplayScope::Shared.as_str(),
        }
    }

    /// Retention horizon written with every marker in this authority.
    #[allow(dead_code)] // exercised by external unit tests
    pub fn retention(&self) -> Duration {
        match self {
            Self::Process { retention, .. } | Self::Shared { retention, .. } => *retention,
        }
    }

    /// Hostnames this authority dials, for gateway DNS warmup.
    pub fn warmup_hostnames(&self) -> Vec<String> {
        match self {
            Self::Process { .. } => Vec::new(),
            Self::Shared { client, .. } => client.warmup_hostname().into_iter().collect(),
        }
    }

    /// Atomically claim `marker` for exactly one request inside the retention
    /// horizon.
    ///
    /// Callers must reach this **only after** every cryptographic and claim
    /// check has passed, so unauthenticated garbage can never consume replay
    /// capacity or a shared-backend round trip.
    pub async fn admit(&self, marker: &ReplayMarker) -> ReplayAdmission {
        let outcome = match self {
            Self::Process {
                lane,
                retention,
                max_entries,
            } => lane.admit_at(marker, *retention, *max_entries, monotonic_millis()),
            Self::Shared { client, retention } => admit_shared(client, *retention, marker).await,
        };
        record_admission(self.mode(), outcome);
        outcome
    }
}

/// Saturating ceil of `retention` to a Redis-valid positive whole-second TTL.
/// Integral durations stay exact; a fractional remainder rounds up; zero becomes
/// 1 so `EX` cannot delete the marker it just wrote.
fn redis_claim_ttl_seconds(retention: Duration) -> u64 {
    let ceil = if retention.subsec_nanos() == 0 {
        retention.as_secs()
    } else {
        retention.as_secs().saturating_add(1)
    };
    ceil.max(1)
}

/// Cross-replica claim: one atomic Redis `SET key value NX EX ttl`.
///
/// A single server-side operation, so among any number of concurrent requests
/// on any number of replicas exactly one observes `Ok(true)`. There is no
/// read-then-write window and no process-local pre-check that could answer
/// differently from the shared truth.
///
/// Every failure mode — unavailable client, command error, response timeout,
/// partition, authentication rejection, malformed protocol reply, or a
/// proven-unsupported topology — arrives as `Err(())` or a false availability
/// flag and rejects the protected request. There is no local fallback.
///
/// The claim runs through the **bounded** primitive
/// ([`RedisRateLimitClient::set_bytes_nx_with_expire_bounded`]) on a Redis
/// client constructed with [`RedisRateLimitClient::for_replay_authority`]: a
/// connected blackhole that accepts the command and never answers must return a
/// fixed fail-closed result rather than hold a protected request open for as
/// long as the peer keeps the socket. Connection, authentication, command,
/// topology, and recovery diagnostics on that client publish only a fixed
/// classification plus the redacted endpoint, so no key, marker, nonce, proof,
/// signature, identity, credential, operator key prefix, or backend error text
/// can reach a log line from here.
///
/// A command that Redis executed but whose reply was lost still fails closed:
/// the marker exists, so the retry observes `Ok(false)` (`Replay`). Losing the
/// reply can therefore cost the client one request, never a second acceptance.
async fn admit_shared(
    client: &RedisRateLimitClient,
    retention: Duration,
    marker: &ReplayMarker,
) -> ReplayAdmission {
    if !client.is_available() {
        return ReplayAdmission::AuthorityUnavailable;
    }
    let key = client.make_key(&[SHARED_KEY_COMPONENT, marker.hex().as_str()]);
    // Exact whole seconds stay exact; a fractional remainder rounds up so Redis
    // `EX` (integral seconds) can never shorten the declared horizon. Zero still
    // becomes 1: Redis treats `EX 0` as an immediate delete, which would admit
    // an unprotected marker.
    let ttl_seconds = redis_claim_ttl_seconds(retention);
    match client
        .set_bytes_nx_with_expire_bounded(&key, SHARED_MARKER_RECORD, ttl_seconds)
        .await
    {
        Ok(true) => ReplayAdmission::Admitted,
        Ok(false) => ReplayAdmission::Replay,
        Err(()) => ReplayAdmission::AuthorityUnavailable,
    }
}

fn record_admission(mode: &'static str, outcome: ReplayAdmission) {
    match outcome {
        ReplayAdmission::Admitted => {
            if mode == ReplayScope::Shared.as_str() {
                ADMITTED_SHARED.fetch_add(1, Ordering::Relaxed);
            } else {
                ADMITTED_PROCESS.fetch_add(1, Ordering::Relaxed);
            }
        }
        ReplayAdmission::Replay => {
            REPLAY_REJECTED.fetch_add(1, Ordering::Relaxed);
        }
        ReplayAdmission::CapacityRefused => {
            CAPACITY_REFUSED.fetch_add(1, Ordering::Relaxed);
        }
        ReplayAdmission::AuthorityUnavailable => {
            AUTHORITY_UNAVAILABLE.fetch_add(1, Ordering::Relaxed);
        }
    }
}

// ── Shared configuration admission ──────────────────────────────────────────

/// Reject a scope/backend combination that cannot deliver what it declares.
///
/// `shared` without a Redis backend would silently be process-local — the exact
/// "multi-replica production configuration falls back to local acceptance"
/// failure. A configured Redis backend without `shared` is equally a
/// misconfiguration: the operator provisioned a shared store the policy would
/// never consult.
pub fn validate_scope_backend(
    plugin: &str,
    field: &str,
    scope: ReplayScope,
    redis_configured: bool,
) -> Result<(), String> {
    match (scope, redis_configured) {
        (ReplayScope::Shared, false) => Err(format!(
            "{plugin}: '{field}' = 'shared' requires sync_mode: 'redis' and a 'redis_url'"
        )),
        (ReplayScope::Process, true) => Err(format!(
            "{plugin}: sync_mode: 'redis' is only meaningful with '{field}' = 'shared'"
        )),
        _ => Ok(()),
    }
}

/// Test-support admission against an explicit monotonic instant, so external
/// tests can pin exact TTL boundaries without sleeping.
#[allow(dead_code)] // exercised by external unit tests
pub fn admit_process_at(
    authority: &ReplayAuthority,
    marker: &ReplayMarker,
    now_millis: u64,
) -> Option<ReplayAdmission> {
    let ReplayAuthority::Process {
        lane,
        retention,
        max_entries,
    } = authority
    else {
        return None;
    };
    let outcome = lane.admit_at(marker, *retention, *max_entries, now_millis);
    record_admission(authority.mode(), outcome);
    Some(outcome)
}

/// Process-lane capacity this authority enforces (test support). `None` for a
/// shared authority, which does not admit against a process lane.
pub fn process_max_entries(authority: &ReplayAuthority) -> Option<usize> {
    match authority {
        ReplayAuthority::Process { max_entries, .. } => Some(*max_entries),
        ReplayAuthority::Shared { .. } => None,
    }
}

/// The process lane behind a process-scoped authority (test support).
#[allow(dead_code)] // exercised by external unit tests
pub fn process_lane(authority: &ReplayAuthority) -> Option<&Arc<ProcessReplayLane>> {
    match authority {
        ReplayAuthority::Process { lane, .. } => Some(lane),
        ReplayAuthority::Shared { .. } => None,
    }
}

/// Poison the shared-authority health registry (test support).
///
/// Production recovers the guard with `into_inner` so a panic in one
/// snapshot/register cannot hide retained live authorities. This helper
/// carries no production behavior.
#[allow(dead_code)] // exercised by external unit tests
pub fn poison_shared_authorities_for_tests() {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = SHARED_AUTHORITIES.lock().expect("lock before poison");
        panic!("replay_authority: intentional shared-authorities registry poison for tests");
    }));
}
