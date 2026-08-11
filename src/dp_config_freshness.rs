//! Bounded age for the DP's last-known-good configuration (issue #3726).
//!
//! A data plane that has accepted one configuration snapshot keeps serving it
//! while every control plane is unreachable. That preserves availability, but
//! without a bound it also means an operator can never be sure a revocation, a
//! deleted route, an emergency authorization change, or a rotated credential
//! has actually taken effect: the DP stays green forever behind a load
//! balancer while its authority is gone.
//!
//! This module is the safety boundary for that window:
//!
//! * The age is measured with [`Instant`] — a monotonic clock — from the last
//!   snapshot that was **validated and successfully applied**. A wall-clock
//!   step (NTP correction, operator `date`, VM restore) can neither extend nor
//!   shorten the window.
//! * Heartbeats, reconnect attempts, CP transport success, rejected/fenced
//!   snapshots, rejected deltas, and snapshots that fail to apply all leave the
//!   age untouched. Only [`DpConfigFreshness::record_snapshot_applied`] resets
//!   it.
//! * Staleness is evaluated only while no CP is connected. Failing over from
//!   one CP to another that remains authoritative therefore never marks the DP
//!   stale, because the DP is connected again long before the window matters.
//! * Once the DP has gone stale, recovery requires an applied snapshot.
//!   Reconnecting alone does not restore readiness or traffic admission — the
//!   sticky flag clears in `record_snapshot_applied` and nowhere else.
//!
//! Two operator-visible effects at the threshold:
//!
//! 1. Readiness degrades (`/health` reports `ready: false`, status
//!    `unavailable`), so orchestrators stop steering new traffic at the pod.
//! 2. Under the default [`StaleAction::FailClosed`], new HTTP/1.1, HTTP/2,
//!    HTTP/3, and TCP stream admissions are refused at the proxy boundary while
//!    already-accepted work drains normally. [`StaleAction::ReadinessOnly`] is
//!    the explicitly named compatibility mode that degrades readiness only.
//!
//! The hot path cost is one relaxed atomic load
//! ([`new_traffic_blocked`]) on a process-global flag that only a data plane
//! ever sets, so every other mode reads a constant `false`.

use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::time::{Duration, Instant};

use serde::Serialize;

/// Process-global admission gate read by the proxy request/connection paths.
///
/// Deliberately a plain static rather than a field on `ProxyState`: the value
/// is a single process-wide bit, and a `static` keeps the hot-path check to one
/// relaxed load with no pointer chase. Only the installed global
/// [`DpConfigFreshness`] (DP mode) ever writes it, so unit tests that build
/// their own instances cannot perturb an unrelated process.
static NEW_TRAFFIC_BLOCKED: AtomicBool = AtomicBool::new(false);

/// The installed DP freshness tracker, if this process is a data plane.
static GLOBAL: OnceLock<Arc<DpConfigFreshness>> = OnceLock::new();

/// How long every authoritative CP must have been unreachable before an
/// already-aged snapshot latches stale.
///
/// Without this, a DP whose configuration has simply been quiet for longer than
/// the bound — the normal steady state on a stable fleet — would fail closed
/// during the sub-second gap of a routine CP restart or failover, because it is
/// momentarily "disconnected with an old snapshot". The bound exists to fence a
/// real loss of authority, not a reconnect. Clamped to `max_stale` so a small
/// configured bound is never silently widened by this constant.
pub const CP_RECONNECT_GRACE: Duration = Duration::from_secs(30);

/// Whether new traffic must be refused because the applied configuration is
/// stale beyond the configured bound.
///
/// One `Relaxed` load (~1ns, no-op on x86). `Relaxed` is sufficient: the flag
/// is an advisory admission gate with no other state published alongside it,
/// and a request that observes the previous value simply lands on the other
/// side of a boundary it was already racing.
#[inline]
pub fn new_traffic_blocked() -> bool {
    NEW_TRAFFIC_BLOCKED.load(Ordering::Relaxed)
}

/// The installed DP freshness tracker (`None` outside DP mode).
pub fn global() -> Option<&'static Arc<DpConfigFreshness>> {
    GLOBAL.get()
}

/// Install the process-wide DP freshness tracker.
///
/// Idempotent: a second call (a test harness starting a second DP runtime in
/// one process) returns the already-installed tracker rather than replacing it,
/// so the admission gate can never be silently re-pointed at a fresh instance
/// with a zeroed age.
pub fn install(max_stale: Duration, action: StaleAction) -> Arc<DpConfigFreshness> {
    GLOBAL
        .get_or_init(|| Arc::new(DpConfigFreshness::new_publishing(max_stale, action)))
        .clone()
}

/// What the DP does for *new* traffic once its applied configuration is stale.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StaleAction {
    /// Degrade readiness **and** refuse new request/connection admissions.
    /// Already-accepted connections and in-flight requests are untouched and
    /// drain normally.
    FailClosed,
    /// Compatibility mode: degrade readiness only, keep admitting new traffic.
    /// Deliberately named so choosing it is a recorded operator decision.
    ReadinessOnly,
}

impl StaleAction {
    /// Parse `FERRUM_DP_CONFIG_STALE_ACTION`. Unknown values fail closed with an
    /// operator-actionable message rather than defaulting to the weaker mode.
    pub fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "fail_closed" | "fail-closed" => Ok(Self::FailClosed),
            "readiness_only" | "readiness-only" => Ok(Self::ReadinessOnly),
            other => Err(format!(
                "FERRUM_DP_CONFIG_STALE_ACTION must be 'fail_closed' or \
                 'readiness_only', got '{other}'"
            )),
        }
    }

    /// Stable label for metrics, logs, and admin diagnostics.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FailClosed => "fail_closed",
            Self::ReadinessOnly => "readiness_only",
        }
    }
}

/// Closed set of reason labels. Fixed cardinality: safe as a metric label and
/// as an admin diagnostic field, and it carries no CP endpoint, credential,
/// namespace, or other unbounded identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FreshnessReason {
    /// Connected to a CP with an applied snapshot inside the bound.
    Ok,
    /// No snapshot has ever been validated and applied on this process.
    AwaitingFirstSnapshot,
    /// No CP is connected, but the applied snapshot is still inside the bound.
    CpDisconnected,
    /// The applied snapshot has aged past the configured bound with no CP.
    SnapshotStale,
    /// The most recent CP payload was refused before apply (fenced snapshot or
    /// rejected delta). Last-known-good config keeps serving.
    SnapshotRejected,
    /// The most recent CP snapshot passed admission but failed to apply.
    SnapshotApplyFailed,
}

impl FreshnessReason {
    /// Stable label for metrics, logs, and admin diagnostics.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::AwaitingFirstSnapshot => "awaiting_first_snapshot",
            Self::CpDisconnected => "cp_disconnected",
            Self::SnapshotStale => "snapshot_stale",
            Self::SnapshotRejected => "snapshot_rejected",
            Self::SnapshotApplyFailed => "snapshot_apply_failed",
        }
    }
}

/// Last CP config outcome, encoded for the `last_outcome` atomic.
const OUTCOME_NONE: u8 = 0;
const OUTCOME_APPLIED: u8 = 1;
const OUTCOME_REJECTED: u8 = 2;
const OUTCOME_APPLY_FAILED: u8 = 3;

/// Fixed-cardinality projection of the freshness state for `/health`, the
/// Prometheus render pass, and tests.
#[derive(Clone, Debug, Serialize)]
pub struct DpConfigFreshnessSnapshot {
    /// Whether the applied configuration is currently past its bound.
    pub stale: bool,
    /// Closed-set reason label (see [`FreshnessReason`]).
    pub reason: &'static str,
    /// Configured stale action (`fail_closed` / `readiness_only`).
    pub stale_action: &'static str,
    /// Whether new traffic is currently refused at the proxy boundary.
    pub new_traffic_blocked: bool,
    /// Whether a ConfigSync stream to some CP is currently established.
    pub cp_connected: bool,
    /// How long every CP has been unreachable, in seconds. `0` while connected.
    pub cp_disconnected_seconds: u64,
    /// Configured bound in seconds. `0` means the bound is disabled.
    pub max_stale_seconds: u64,
    /// Whether any snapshot has ever been validated and applied.
    pub applied_snapshot: bool,
    /// Age of the last applied snapshot in seconds. With no applied snapshot
    /// this is the age of the tracker itself (process start), which is what the
    /// bound is measured against on a DP that never reached a CP.
    pub snapshot_age_seconds: u64,
    /// Snapshots/deltas validated and applied since process start.
    pub applied_total: u64,
    /// CP payloads refused before apply since process start.
    pub rejected_total: u64,
    /// CP snapshots that failed during apply since process start.
    pub apply_failed_total: u64,
    /// Transitions into the stale state since process start.
    pub stale_transitions_total: u64,
}

/// Monotonic freshness accounting for the DP's applied configuration.
pub struct DpConfigFreshness {
    /// Configured bound. `Duration::ZERO` disables the bound entirely.
    max_stale: Duration,
    action: StaleAction,
    /// Monotonic base. All stamps are millisecond offsets from here, so no
    /// wall-clock source participates in the age at any point.
    epoch: Instant,
    /// Offset of the last applied snapshot, stored as `offset_ms + 1` so `0`
    /// can mean "never applied" without a separate flag.
    last_applied_ms: AtomicU64,
    /// Offset at which the current CP outage began, stored as `offset_ms + 1`
    /// so `0` can mean "a CP is connected". Set once per outage: repeated
    /// failover attempts against successive CP URLs must not restart it.
    disconnected_since_ms: AtomicU64,
    cp_connected: AtomicBool,
    /// Sticky once raised; cleared only by an applied snapshot.
    stale: AtomicBool,
    last_outcome: AtomicU8,
    applied_total: AtomicU64,
    rejected_total: AtomicU64,
    apply_failed_total: AtomicU64,
    stale_transitions_total: AtomicU64,
    /// Only the installed global publishes to [`NEW_TRAFFIC_BLOCKED`].
    publishes: bool,
}

impl DpConfigFreshness {
    /// Construct a non-publishing tracker with an explicit monotonic base, so
    /// tests can drive the whole state machine from a fixed instant.
    pub fn new_at(epoch: Instant, max_stale: Duration, action: StaleAction) -> Self {
        Self::with_epoch(epoch, max_stale, action, false)
    }

    fn new_publishing(max_stale: Duration, action: StaleAction) -> Self {
        Self::with_epoch(Instant::now(), max_stale, action, true)
    }

    fn with_epoch(
        epoch: Instant,
        max_stale: Duration,
        action: StaleAction,
        publishes: bool,
    ) -> Self {
        Self {
            max_stale,
            action,
            epoch,
            last_applied_ms: AtomicU64::new(0),
            // A DP that has not yet reached a CP is already in an outage that
            // started at the epoch, so startup without any accepted snapshot is
            // bounded by exactly the same rule as a mid-life outage.
            disconnected_since_ms: AtomicU64::new(1),
            cp_connected: AtomicBool::new(false),
            stale: AtomicBool::new(false),
            last_outcome: AtomicU8::new(OUTCOME_NONE),
            applied_total: AtomicU64::new(0),
            rejected_total: AtomicU64::new(0),
            apply_failed_total: AtomicU64::new(0),
            stale_transitions_total: AtomicU64::new(0),
            publishes,
        }
    }

    /// Configured bound (`Duration::ZERO` = disabled).
    pub fn max_stale(&self) -> Duration {
        self.max_stale
    }

    /// Whether the bound is enforced at all.
    pub fn enabled(&self) -> bool {
        !self.max_stale.is_zero()
    }

    /// Minimum CP-outage duration before an aged snapshot latches stale, never
    /// wider than the configured bound itself.
    pub fn reconnect_grace(&self) -> Duration {
        CP_RECONNECT_GRACE.min(self.max_stale)
    }

    /// A ConfigSync stream to some CP is established. Transport success alone
    /// is **not** freshness: this records reachability for the staleness
    /// predicate and never touches the age or clears the sticky stale flag.
    pub fn record_cp_connected(&self) {
        self.disconnected_since_ms.store(0, Ordering::Relaxed);
        self.cp_connected.store(true, Ordering::Relaxed);
    }

    /// The DP has no CP stream. Re-evaluates immediately so an outage that
    /// starts with an already-old snapshot degrades without waiting a tick.
    pub fn record_cp_disconnected(&self) {
        self.record_cp_disconnected_at(Instant::now());
    }

    /// [`Self::record_cp_disconnected`] with an explicit instant (tests).
    ///
    /// Idempotent within one outage: the DP calls this once per failed CP
    /// attempt while cycling through `FERRUM_DP_CP_GRPC_URLS`, and restarting
    /// the outage stamp on each attempt would let an unreachable fleet of CPs
    /// hold the grace window open forever.
    pub fn record_cp_disconnected_at(&self, now: Instant) {
        self.cp_connected.store(false, Ordering::Relaxed);
        if self.disconnected_since_ms.load(Ordering::Relaxed) == 0 {
            self.disconnected_since_ms.store(self.stamp(now), Ordering::Relaxed);
        }
        self.evaluate_at(now);
    }

    /// Monotonic offset from the epoch, encoded as `offset_ms + 1`.
    fn stamp(&self, now: Instant) -> u64 {
        let offset = now.saturating_duration_since(self.epoch).as_millis();
        // Saturate rather than wrap: a u64 of milliseconds is ~584 million
        // years, so this is unreachable, and clamping keeps the stamp monotonic
        // in the impossible case instead of teleporting it back to the epoch.
        u64::try_from(offset)
            .unwrap_or(u64::MAX - 1)
            .saturating_add(1)
    }

    /// Elapsed time since a stamp of the `offset_ms + 1` encoding.
    fn since_stamp(&self, stamp: u64, now: Instant) -> Duration {
        now.saturating_duration_since(self.epoch)
            .saturating_sub(Duration::from_millis(stamp.saturating_sub(1)))
    }

    /// A snapshot or delta was validated and successfully applied. This is the
    /// only event that resets the age, and the only one that clears the sticky
    /// stale flag — a reconnect on its own must not restore admission.
    pub fn record_snapshot_applied(&self) {
        self.record_snapshot_applied_at(Instant::now());
    }

    /// [`Self::record_snapshot_applied`] with an explicit instant (tests).
    pub fn record_snapshot_applied_at(&self, now: Instant) {
        self.last_applied_ms.store(self.stamp(now), Ordering::Relaxed);
        self.applied_total.fetch_add(1, Ordering::Relaxed);
        self.last_outcome.store(OUTCOME_APPLIED, Ordering::Relaxed);
        self.stale.store(false, Ordering::Relaxed);
        self.evaluate_at(now);
    }

    /// A CP payload was refused before apply (fenced FULL_SNAPSHOT, rejected
    /// delta, or a snapshot that failed validation/staging). Age is untouched.
    pub fn record_snapshot_rejected(&self) {
        self.rejected_total.fetch_add(1, Ordering::Relaxed);
        self.last_outcome.store(OUTCOME_REJECTED, Ordering::Relaxed);
    }

    /// A CP snapshot passed admission but failed during apply. Age is
    /// untouched: nothing new is serving.
    pub fn record_snapshot_apply_failed(&self) {
        self.apply_failed_total.fetch_add(1, Ordering::Relaxed);
        self.last_outcome.store(OUTCOME_APPLY_FAILED, Ordering::Relaxed);
    }

    /// Age of the last applied snapshot, or of the tracker itself when no
    /// snapshot has ever been applied.
    pub fn age_at(&self, now: Instant) -> Duration {
        match self.last_applied_ms.load(Ordering::Relaxed) {
            0 => now.saturating_duration_since(self.epoch),
            stamp => self.since_stamp(stamp, now),
        }
    }

    /// How long every CP has been unreachable. `Duration::ZERO` while a CP
    /// stream is established.
    pub fn cp_outage_at(&self, now: Instant) -> Duration {
        match self.disconnected_since_ms.load(Ordering::Relaxed) {
            0 => Duration::ZERO,
            stamp => self.since_stamp(stamp, now),
        }
    }

    /// Whether any snapshot has ever been validated and applied.
    pub fn has_applied_snapshot(&self) -> bool {
        self.last_applied_ms.load(Ordering::Relaxed) != 0
    }

    /// Re-evaluate the bound and publish the admission gate. Pure atomics — no
    /// locks, no allocation — so `/health`, the background tick, and the CP
    /// event paths can all call it freely.
    pub fn evaluate(&self) -> DpConfigFreshnessSnapshot {
        self.evaluate_at(Instant::now())
    }

    /// [`Self::evaluate`] with an explicit instant (tests).
    pub fn evaluate_at(&self, now: Instant) -> DpConfigFreshnessSnapshot {
        let cp_connected = self.cp_connected.load(Ordering::Relaxed);
        let age = self.age_at(now);
        let outage = self.cp_outage_at(now);
        // Staleness requires an aged snapshot AND the loss of every
        // authoritative source for at least the reconnect grace. A DP connected
        // to any CP — primary or fallback — is still receiving revocations, so
        // a quiet configuration that simply has not changed in a long time is
        // not stale, and a failover that keeps some CP authoritative never
        // trips the bound.
        if self.enabled()
            && !cp_connected
            && age >= self.max_stale
            && outage >= self.reconnect_grace()
            && !self.stale.load(Ordering::Relaxed)
        {
            self.stale.store(true, Ordering::Relaxed);
            self.stale_transitions_total.fetch_add(1, Ordering::Relaxed);
        }
        let stale = self.stale.load(Ordering::Relaxed);
        let blocked = stale && self.action == StaleAction::FailClosed;
        if self.publishes {
            NEW_TRAFFIC_BLOCKED.store(blocked, Ordering::Relaxed);
        }
        DpConfigFreshnessSnapshot {
            stale,
            reason: self.reason(stale, cp_connected).as_str(),
            stale_action: self.action.as_str(),
            new_traffic_blocked: blocked,
            cp_connected,
            cp_disconnected_seconds: outage.as_secs(),
            max_stale_seconds: self.max_stale.as_secs(),
            applied_snapshot: self.has_applied_snapshot(),
            snapshot_age_seconds: age.as_secs(),
            applied_total: self.applied_total.load(Ordering::Relaxed),
            rejected_total: self.rejected_total.load(Ordering::Relaxed),
            apply_failed_total: self.apply_failed_total.load(Ordering::Relaxed),
            stale_transitions_total: self.stale_transitions_total.load(Ordering::Relaxed),
        }
    }

    /// Reason precedence: the strongest currently-true condition wins, so the
    /// four operator-distinguishable states (`cp_disconnected`,
    /// `snapshot_stale`, `snapshot_rejected`, `snapshot_apply_failed`) never
    /// mask a more severe one.
    fn reason(&self, stale: bool, cp_connected: bool) -> FreshnessReason {
        if stale {
            return FreshnessReason::SnapshotStale;
        }
        if !self.has_applied_snapshot() {
            return FreshnessReason::AwaitingFirstSnapshot;
        }
        if !cp_connected {
            return FreshnessReason::CpDisconnected;
        }
        match self.last_outcome.load(Ordering::Relaxed) {
            OUTCOME_REJECTED => FreshnessReason::SnapshotRejected,
            OUTCOME_APPLY_FAILED => FreshnessReason::SnapshotApplyFailed,
            _ => FreshnessReason::Ok,
        }
    }
}

/// Record an applied snapshot on the installed tracker, if any.
pub fn record_snapshot_applied() {
    if let Some(freshness) = global() {
        freshness.record_snapshot_applied();
    }
}

/// Record a refused-before-apply CP payload on the installed tracker, if any.
pub fn record_snapshot_rejected() {
    if let Some(freshness) = global() {
        freshness.record_snapshot_rejected();
    }
}

/// Record an apply failure on the installed tracker, if any.
pub fn record_snapshot_apply_failed() {
    if let Some(freshness) = global() {
        freshness.record_snapshot_apply_failed();
    }
}

/// Record CP connectivity on the installed tracker, if any.
pub fn record_cp_connected() {
    if let Some(freshness) = global() {
        freshness.record_cp_connected();
    }
}

/// Record CP disconnection on the installed tracker, if any.
pub fn record_cp_disconnected() {
    if let Some(freshness) = global() {
        freshness.record_cp_disconnected();
    }
}

/// Fixed-cardinality projection of the installed tracker for `/health` and
/// `/metrics` (`None` outside DP mode).
pub fn snapshot() -> Option<DpConfigFreshnessSnapshot> {
    global().map(|freshness| freshness.evaluate())
}
