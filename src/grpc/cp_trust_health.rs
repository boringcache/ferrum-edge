//! Observable, bounded CP/DP trust-bundle reload health (issue #3813).
//!
//! The file-backed CP/DP trust-bundle watcher deliberately keeps the last
//! accepted verifier when a candidate is unreadable, malformed, times out, or
//! fails multi-namespace scope validation. Retaining a known-good verifier
//! through a transient failure is the right availability policy — but on its
//! own it is also a silent, unbounded one: a credential an operator is trying
//! to revoke stays an active authorization source for as long as every reload
//! keeps failing, and nothing in health, readiness, or metrics says so.
//!
//! This module is that missing contract. It is the CP-side analogue of
//! [`crate::dp_config_freshness`] and follows the same three rules:
//!
//! * **Monotonic clock.** Every age is measured from
//!   [`tokio::time::Instant`] stamps, so a wall-clock step (NTP correction,
//!   operator `date`, VM restore) can neither extend nor shorten the stale
//!   window.
//! * **Only an accepted generation resets the age.** A reload *attempt*
//!   advances the attempt stamp and the counters; only
//!   [`CpDpTrustReloadStatus::record_accepted_at`] resets the age and clears
//!   degraded state. A candidate that is semantically unchanged still counts as
//!   an acceptance — the trust source was revalidated, which is exactly the
//!   question the bound asks.
//! * **The configured bound is the boundary.** No grace period is added on top
//!   of it anywhere.
//!
//! At the bound, [`CpDpTrustReloadStatus::admission_blocked`] turns true. The
//! shared gRPC authentication seam refuses to admit new ConfigSync,
//! MeshSubscribe (local and remote), SotW ADS, and Delta ADS streams, the
//! shared stream lease terminates already-admitted streams, and `/health`
//! reports `ready: false`. Recovery requires a valid candidate, never the mere
//! passage of time.
//!
//! # Disclosure discipline
//!
//! Nothing here renders a path, bundle bytes, a JWT, a namespace, a `kid`, a
//! credential identifier, or any key material — and nothing here renders any
//! value *derived* from key material either. In particular no generation
//! identifier, fingerprint, or digest is published. A deterministic identifier
//! computed from credential material is an offline verification oracle no
//! matter how it is re-hashed, domain-separated, or truncated: an attacker who
//! can guess a candidate symmetric secret can recompute the same value from
//! public algorithms and compare. The internal configuration fingerprint
//! therefore stays private to the reload worker, where it serves only as a
//! semantic change detector, and never reaches health, metrics, or logs.
//!
//! What is published is booleans, counters, monotonic ages in seconds, and one
//! closed, compile-time set of failure reasons.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::task::{Context, Poll};

use serde::Serialize;
use tokio::time::{Duration, Instant, Sleep};

use crate::grpc::cp_trust::TrustBundleRejectReason;

/// Low bit of the state word: sticky stale. The remaining bits are the accepted
/// generation counter.
const STALE_BIT: u64 = 1;

/// Log at most one warning per this many consecutive failures after the first.
/// Repeated attempts still advance every stamp, counter, and gauge; only the
/// log is rate limited.
const FAILURE_LOG_EVERY: u64 = 20;

/// Encoded [`WorkerState`].
const WORKER_DISABLED: u8 = 0;
const WORKER_RUNNING: u8 = 1;
const WORKER_STOPPED: u8 = 2;
const WORKER_FAILED: u8 = 3;

/// Why a CP/DP trust-bundle reload attempt did not produce a new accepted
/// generation.
///
/// A closed, fixed-cardinality set: safe as a Prometheus label and as an
/// authenticated `/health` field. No variant carries a path, a digest, a
/// namespace, a `kid`, or any document or key bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustReloadFailure {
    /// The bundle document is not a readable, bounded, regular UTF-8 file.
    DocumentUnreadable,
    /// The document was read but is not a valid trust-bundle configuration.
    DocumentInvalid,
    /// Path-backed material could not be read as a bounded regular file.
    MaterialUnreadable,
    /// Path-backed material lies outside a pinned source generation and the
    /// document binds it to no `material_sha256`.
    MaterialIntegrityUnbound,
    /// A declared `material_sha256` is not 64 lowercase hex digits.
    MaterialIntegrityMalformed,
    /// Resolved material does not match its manifest-bound digest.
    MaterialIntegrityMismatch,
    /// A reference claiming to live in the pinned generation escapes it.
    SourceGenerationEscape,
    /// The pinned generation could not be established or vanished mid-load.
    SourceGenerationUnstable,
    /// A projected generation was detected on a platform that cannot pin it.
    SourceGenerationUnsupported,
    /// The process-wide reload read slot could not be acquired.
    ReaderUnavailable,
    /// The detached reader thread could not be started or died without a
    /// verdict.
    ReaderFailed,
    /// The read did not complete inside the loader timeout — the shape of a
    /// FIFO, a carrier-less device, or a stalled network filesystem.
    ReadTimedOut,
    /// A structurally valid candidate failed multi-namespace scope validation.
    ScopeValidationFailed,
    /// The reload worker exited or panicked without being asked to stop.
    WorkerExited,
}

/// Every [`TrustReloadFailure`], in metric-render order.
pub const TRUST_RELOAD_FAILURES: [TrustReloadFailure; 14] = [
    TrustReloadFailure::DocumentUnreadable,
    TrustReloadFailure::DocumentInvalid,
    TrustReloadFailure::MaterialUnreadable,
    TrustReloadFailure::MaterialIntegrityUnbound,
    TrustReloadFailure::MaterialIntegrityMalformed,
    TrustReloadFailure::MaterialIntegrityMismatch,
    TrustReloadFailure::SourceGenerationEscape,
    TrustReloadFailure::SourceGenerationUnstable,
    TrustReloadFailure::SourceGenerationUnsupported,
    TrustReloadFailure::ReaderUnavailable,
    TrustReloadFailure::ReaderFailed,
    TrustReloadFailure::ReadTimedOut,
    TrustReloadFailure::ScopeValidationFailed,
    TrustReloadFailure::WorkerExited,
];

const FAILURE_COUNT: usize = TRUST_RELOAD_FAILURES.len();

impl TrustReloadFailure {
    /// Fixed-cardinality label for metrics, logs, and authenticated health.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DocumentUnreadable => "document_unreadable",
            Self::DocumentInvalid => "document_invalid",
            Self::MaterialUnreadable => "material_unreadable",
            Self::MaterialIntegrityUnbound => "material_integrity_unbound",
            Self::MaterialIntegrityMalformed => "material_integrity_malformed",
            Self::MaterialIntegrityMismatch => "material_integrity_mismatch",
            Self::SourceGenerationEscape => "source_generation_escape",
            Self::SourceGenerationUnstable => "source_generation_unstable",
            Self::SourceGenerationUnsupported => "source_generation_unsupported",
            Self::ReaderUnavailable => "reader_unavailable",
            Self::ReaderFailed => "reload_reader_failed",
            Self::ReadTimedOut => "reload_read_timed_out",
            Self::ScopeValidationFailed => "scope_validation_failed",
            Self::WorkerExited => "worker_exited",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::DocumentUnreadable => 0,
            Self::DocumentInvalid => 1,
            Self::MaterialUnreadable => 2,
            Self::MaterialIntegrityUnbound => 3,
            Self::MaterialIntegrityMalformed => 4,
            Self::MaterialIntegrityMismatch => 5,
            Self::SourceGenerationEscape => 6,
            Self::SourceGenerationUnstable => 7,
            Self::SourceGenerationUnsupported => 8,
            Self::ReaderUnavailable => 9,
            Self::ReaderFailed => 10,
            Self::ReadTimedOut => 11,
            Self::ScopeValidationFailed => 12,
            Self::WorkerExited => 13,
        }
    }

    /// Project the loader's closed rejection taxonomy onto this one.
    pub const fn from_reject_reason(reason: TrustBundleRejectReason) -> Self {
        match reason {
            TrustBundleRejectReason::DocumentUnreadable => Self::DocumentUnreadable,
            TrustBundleRejectReason::DocumentInvalid => Self::DocumentInvalid,
            TrustBundleRejectReason::MaterialUnreadable => Self::MaterialUnreadable,
            TrustBundleRejectReason::MaterialIntegrityUnbound => Self::MaterialIntegrityUnbound,
            TrustBundleRejectReason::MaterialIntegrityMalformed => Self::MaterialIntegrityMalformed,
            TrustBundleRejectReason::MaterialIntegrityMismatch => Self::MaterialIntegrityMismatch,
            TrustBundleRejectReason::SourceGenerationEscape => Self::SourceGenerationEscape,
            TrustBundleRejectReason::SourceGenerationUnstable => Self::SourceGenerationUnstable,
            TrustBundleRejectReason::SourceGenerationUnsupported => {
                Self::SourceGenerationUnsupported
            }
        }
    }
}

/// Supervision state of the reload worker task.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkerState {
    /// No trust bundle is configured, so no worker exists.
    Disabled,
    /// The worker is alive and its attempts are landing.
    Running,
    /// The worker is alive but no attempt has completed within the stall
    /// window — a read parked in the kernel, or a wedged runtime.
    Stalled,
    /// The worker exited because the process is shutting down.
    Stopped,
    /// The worker exited or panicked without being asked to. Fails readiness
    /// immediately: nothing will ever publish a credential removal again, so
    /// waiting for the stale bound to expire would leave the replica green
    /// while its revocation path is dead.
    Failed,
}

impl WorkerState {
    /// Fixed-cardinality label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Running => "running",
            Self::Stalled => "stalled",
            Self::Stopped => "stopped",
            Self::Failed => "failed",
        }
    }
}

/// Fixed-cardinality projection for authenticated `/health` and `/status`, the
/// Prometheus render pass, and tests.
///
/// Every field is a boolean, a count, a number of seconds, or a closed-set
/// label. Nothing here is derived from bundle bytes, key material, a path, a
/// namespace, a `kid`, or a token — including indirectly through a digest,
/// fingerprint, or generation identifier.
#[derive(Clone, Debug, Serialize)]
pub struct CpDpTrustReloadSnapshot {
    /// Whether a file-backed trust bundle is configured and watched at all.
    pub configured: bool,
    /// Closed-set worker supervision state.
    pub worker_state: &'static str,
    /// Whether the worker is currently expected to be alive.
    pub worker_running: bool,
    /// Whether the most recent attempt failed (or the worker died), so the CP
    /// is authorizing with a generation it could not revalidate.
    pub degraded: bool,
    /// Whether the active generation has aged past `max_stale_seconds` while
    /// degraded. Sticky until a valid candidate is accepted.
    pub stale: bool,
    /// Whether new authenticated configuration streams are currently refused.
    pub admission_blocked: bool,
    /// Whether this replica currently fails readiness because of trust state.
    pub readiness_blocked: bool,
    /// Closed-set reason: `ok` or a [`TrustReloadFailure`] label.
    pub reason: &'static str,
    /// Seconds since the last reload attempt completed. `None` if none has.
    pub last_attempt_age_seconds: Option<u64>,
    /// Seconds since the last accepted generation. `None` if none has been
    /// accepted (which cannot happen while `configured` is true).
    pub last_acceptance_age_seconds: Option<u64>,
    /// Configured bound in seconds. `0` means unbounded retention, which
    /// requires an explicit unsafe opt-in.
    pub max_stale_seconds: u64,
    /// Whether unbounded retention was explicitly opted into.
    pub unbounded_stale_allowed: bool,
    /// Consecutive failed attempts since the last acceptance.
    pub consecutive_failures: u64,
    /// Failure episodes ended by a later valid candidate.
    pub recoveries_total: u64,
    /// Reload attempts that produced a verdict since process start.
    pub attempts_total: u64,
    /// Attempts that produced a usable generation (replaced or confirmed).
    pub acceptances_total: u64,
    /// Attempts refused, across every closed reason.
    pub rejections_total: u64,
    /// Refusals per closed reason. Exactly [`TRUST_RELOAD_FAILURES`] keys.
    pub rejections_by_reason: BTreeMap<&'static str, u64>,
}

/// The installed CP trust-reload status, if this process runs a watched
/// CP/DP trust bundle.
static GLOBAL: OnceLock<Arc<CpDpTrustReloadStatus>> = OnceLock::new();

/// The shared "no trust bundle configured" status handed to every verifier
/// store that was not built by CP mode. It can never become degraded or stale,
/// so its gates are constant `false`.
static DISABLED: OnceLock<Arc<CpDpTrustReloadStatus>> = OnceLock::new();

/// Install the process-wide CP trust-reload status.
///
/// Idempotent: a second call (a test harness starting a second CP runtime in
/// one process) returns the already-installed status rather than replacing it,
/// so an observable degraded state can never be reset by a fresh instance.
pub fn install(status: Arc<CpDpTrustReloadStatus>) -> Arc<CpDpTrustReloadStatus> {
    GLOBAL.get_or_init(|| status).clone()
}

/// The installed status (`None` outside a CP with a watched trust bundle).
pub fn global() -> Option<&'static Arc<CpDpTrustReloadStatus>> {
    GLOBAL.get()
}

/// Fixed-cardinality projection of the installed status for `/health` and
/// `/metrics` (`None` when no trust bundle is watched in this process).
pub fn snapshot() -> Option<CpDpTrustReloadSnapshot> {
    global().map(|status| status.snapshot())
}

/// The shared disabled status: configured `false`, never degraded, never stale.
pub fn disabled_status() -> Arc<CpDpTrustReloadStatus> {
    DISABLED
        .get_or_init(|| Arc::new(CpDpTrustReloadStatus::disabled()))
        .clone()
}

/// Lock-free reload accounting for the CP/DP trust bundle.
///
/// Publication is atomics only: no lock, no allocation on the read path, and no
/// I/O. Every gRPC admission and every `/health` probe can call it freely.
pub struct CpDpTrustReloadStatus {
    configured: bool,
    /// `Duration::ZERO` = unbounded retention (explicit unsafe opt-in).
    max_stale: Duration,
    unbounded_allowed: bool,
    /// How long without a completed attempt counts as a stalled worker.
    stall_after: Duration,
    /// Monotonic base. Every stamp is a millisecond offset from here.
    epoch: Instant,
    /// `accepted_generation << 1 | stale`. The counter increments on every
    /// acceptance; the stale bit is sticky within a generation and is cleared
    /// only by the generation bump itself.
    state: AtomicU64,
    /// Offset of the last completed attempt, as `offset_ms + 1` so `0` can mean
    /// "never" without a second flag.
    last_attempt_ms: AtomicU64,
    /// Offset of the last accepted generation, same encoding.
    last_acceptance_ms: AtomicU64,
    consecutive_failures: AtomicU64,
    recoveries_total: AtomicU64,
    attempts_total: AtomicU64,
    acceptances_total: AtomicU64,
    rejections: [AtomicU64; FAILURE_COUNT],
    /// Last failure as `index + 1`; `0` = none.
    last_failure: AtomicU8,
    worker: AtomicU8,
}

impl std::fmt::Debug for CpDpTrustReloadStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CpDpTrustReloadStatus")
            .field("configured", &self.configured)
            .field("max_stale", &self.max_stale)
            .finish_non_exhaustive()
    }
}

impl CpDpTrustReloadStatus {
    /// A status for a process that watches no trust bundle.
    pub fn disabled() -> Self {
        Self::build(false, Duration::ZERO, false, Duration::ZERO, Instant::now())
    }

    /// A status for a watched trust bundle whose initial generation was already
    /// accepted at startup.
    ///
    /// `max_stale` is the operator's bound (`Duration::ZERO` = unbounded, which
    /// the configuration layer admits only behind an explicit unsafe opt-in),
    /// and `interval` is the watcher's poll period, which sets the
    /// stalled-worker window.
    pub fn watching(max_stale: Duration, unbounded_allowed: bool, interval: Duration) -> Self {
        Self::watching_at(max_stale, unbounded_allowed, interval, Instant::now())
    }

    /// [`Self::watching`] with an explicit monotonic base, so tests can drive
    /// the whole state machine from a fixed instant.
    pub fn watching_at(
        max_stale: Duration,
        unbounded_allowed: bool,
        interval: Duration,
        now: Instant,
    ) -> Self {
        // Three missed polls, floored at a minute, is long enough that ordinary
        // scheduling jitter never reads as a stall and short enough that a read
        // wedged in the kernel is visible well before the stale bound.
        let stall_after = interval.saturating_mul(3).max(Duration::from_secs(60));
        let status = Self::build(true, max_stale, unbounded_allowed, stall_after, now);
        status
            .last_acceptance_ms
            .store(status.stamp(now), Ordering::Release);
        status.acceptances_total.store(1, Ordering::Relaxed);
        status
    }

    fn build(
        configured: bool,
        max_stale: Duration,
        unbounded_allowed: bool,
        stall_after: Duration,
        epoch: Instant,
    ) -> Self {
        Self {
            configured,
            max_stale,
            unbounded_allowed,
            stall_after,
            epoch,
            state: AtomicU64::new(0),
            last_attempt_ms: AtomicU64::new(0),
            last_acceptance_ms: AtomicU64::new(0),
            consecutive_failures: AtomicU64::new(0),
            recoveries_total: AtomicU64::new(0),
            attempts_total: AtomicU64::new(0),
            acceptances_total: AtomicU64::new(0),
            rejections: std::array::from_fn(|_| AtomicU64::new(0)),
            last_failure: AtomicU8::new(0),
            worker: AtomicU8::new(if configured {
                WORKER_RUNNING
            } else {
                WORKER_DISABLED
            }),
        }
    }

    /// Monotonic offset from the epoch, encoded as `offset_ms + 1`.
    fn stamp(&self, now: Instant) -> u64 {
        let offset = now.saturating_duration_since(self.epoch).as_millis();
        // Saturate rather than wrap: a u64 of milliseconds is ~584 million
        // years, so this is unreachable, and clamping keeps the stamp monotonic
        // instead of teleporting it back to the epoch.
        u64::try_from(offset)
            .unwrap_or(u64::MAX - 1)
            .saturating_add(1)
    }

    fn since_stamp(&self, stamp: u64, now: Instant) -> Duration {
        now.saturating_duration_since(self.epoch)
            .saturating_sub(Duration::from_millis(stamp.saturating_sub(1)))
    }

    fn stamp_instant(&self, stamp: u64) -> Option<Instant> {
        self.epoch
            .checked_add(Duration::from_millis(stamp.saturating_sub(1)))
    }

    fn age_from(&self, stamp: u64, now: Instant) -> Duration {
        match stamp {
            0 => now.saturating_duration_since(self.epoch),
            stamp => self.since_stamp(stamp, now),
        }
    }

    /// A reload attempt is about to run. Recording the attempt separately from
    /// its verdict is what keeps a wedged reader visible: the attempt stamp
    /// stops advancing and the worker reads as `stalled`.
    pub fn record_attempt(&self) {
        self.attempts_total.fetch_add(1, Ordering::Relaxed);
    }

    /// A reload attempt produced a usable generation.
    ///
    /// `changed` distinguishes a replacement from a semantically identical
    /// confirmation; both are acceptances, because both prove the trust source
    /// is readable and coherent again. The candidate's configuration
    /// fingerprint stays inside the worker — it is a change detector, never an
    /// observable value.
    ///
    /// The write order is load-bearing: the acceptance stamp lands first, then
    /// the internal generation bump publishes it, so a staleness evaluation
    /// that observed the older generation fails its compare-and-swap instead of
    /// latching on top of the recovery.
    pub fn record_accepted_at(&self, now: Instant, changed: bool) {
        self.last_acceptance_ms
            .store(self.stamp(now), Ordering::Release);
        self.last_attempt_ms
            .store(self.stamp(now), Ordering::Release);
        self.acceptances_total.fetch_add(1, Ordering::Relaxed);
        self.last_failure.store(0, Ordering::Relaxed);
        let failures = self.consecutive_failures.swap(0, Ordering::AcqRel);
        // Bump the generation and clear the sticky stale bit in one step. The
        // word only ever grows, which is what makes publication monotonic.
        let _ = self
            .state
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                Some(((current >> 1) + 1) << 1)
            });
        if failures > 0 {
            self.recoveries_total.fetch_add(1, Ordering::Relaxed);
            tracing::info!(
                audit.event = "cp_dp_trust_bundle_reload_recovered",
                consecutive_failures = failures,
                generation_changed = changed,
                "CP/DP trust-bundle reload recovered; the active trust generation is \
                 revalidated and stale-trust admission blocking is cleared"
            );
        }
    }

    /// [`Self::record_accepted_at`] at the current instant.
    pub fn record_accepted(&self, changed: bool) {
        self.record_accepted_at(Instant::now(), changed);
    }

    /// A reload attempt was refused. The previous verifier is retained in full;
    /// only the failure accounting moves.
    ///
    /// The first refusal of an episode, a change of reason inside one episode,
    /// and every [`FAILURE_LOG_EVERY`]th refusal after that are logged. Every
    /// refusal advances the stamps and counters regardless, so an alert never
    /// depends on log sampling surviving a long incident.
    pub fn record_rejected_at(&self, now: Instant, failure: TrustReloadFailure) {
        self.last_attempt_ms
            .store(self.stamp(now), Ordering::Release);
        self.rejections[failure.index()].fetch_add(1, Ordering::Relaxed);
        let previous = self
            .last_failure
            .swap(failure.index() as u8 + 1, Ordering::AcqRel);
        let consecutive = self.consecutive_failures.fetch_add(1, Ordering::AcqRel) + 1;
        let reason_changed = previous != failure.index() as u8 + 1;
        if consecutive == 1 || reason_changed || consecutive.is_multiple_of(FAILURE_LOG_EVERY) {
            tracing::warn!(
                audit.event = "cp_dp_trust_bundle_reload_rejected",
                reason = failure.as_str(),
                consecutive_failures = consecutive,
                "CP/DP trust-bundle reload rejected; retaining the active verifier and marking \
                 trust reload degraded"
            );
        }
        // Evaluate immediately so a refusal that lands with an already-old
        // generation blocks admission without waiting for anything else.
        self.evaluate_at(now);
    }

    /// [`Self::record_rejected_at`] at the current instant.
    pub fn record_rejected(&self, failure: TrustReloadFailure) {
        self.record_rejected_at(Instant::now(), failure);
    }

    /// The worker task ended.
    ///
    /// `clean` is true only for a shutdown-signalled exit, which is not a
    /// failure and must never be reported as one.
    pub fn record_worker_stopped(&self, clean: bool) {
        if !self.configured {
            return;
        }
        if clean {
            self.worker.store(WORKER_STOPPED, Ordering::Release);
            return;
        }
        self.worker.store(WORKER_FAILED, Ordering::Release);
        self.rejections[TrustReloadFailure::WorkerExited.index()].fetch_add(1, Ordering::Relaxed);
        self.last_failure.store(
            TrustReloadFailure::WorkerExited.index() as u8 + 1,
            Ordering::Relaxed,
        );
        self.consecutive_failures.fetch_add(1, Ordering::AcqRel);
        tracing::error!(
            audit.event = "cp_dp_trust_bundle_reload_worker_exited",
            reason = TrustReloadFailure::WorkerExited.as_str(),
            "CP/DP trust-bundle reload worker exited unexpectedly; no credential removal can be \
             published again in this process. Failing readiness so the replica is replaced."
        );
    }

    fn worker_state_at(&self, now: Instant) -> WorkerState {
        match self.worker.load(Ordering::Acquire) {
            WORKER_DISABLED => WorkerState::Disabled,
            WORKER_STOPPED => WorkerState::Stopped,
            WORKER_FAILED => WorkerState::Failed,
            _ => {
                let last = self.last_attempt_ms.load(Ordering::Acquire);
                let reference = if last == 0 {
                    self.last_acceptance_ms.load(Ordering::Acquire)
                } else {
                    last
                };
                if self.age_from(reference, now) > self.stall_after {
                    WorkerState::Stalled
                } else {
                    WorkerState::Running
                }
            }
        }
    }

    /// Whether the CP is currently authorizing with a generation it could not
    /// revalidate.
    pub fn degraded(&self) -> bool {
        self.configured && self.consecutive_failures.load(Ordering::Acquire) > 0
    }

    /// Evaluate the bound, latching the sticky stale bit when it is crossed.
    ///
    /// Returns `(stale, next_deadline)`. `next_deadline` is `Some` only when the
    /// bound is enforced, has not been crossed, and is representable — in which
    /// case it is strictly the instant at which staleness begins, so a caller
    /// can arm exactly one timer instead of polling.
    pub fn evaluate_at(&self, now: Instant) -> (bool, Option<Instant>) {
        if !self.configured || self.max_stale.is_zero() {
            return (false, None);
        }
        loop {
            let observed = self.state.load(Ordering::Acquire);
            if observed & STALE_BIT != 0 {
                return (true, None);
            }
            let accepted = self.last_acceptance_ms.load(Ordering::Acquire);
            if self.age_from(accepted, now) < self.max_stale {
                let base = match accepted {
                    0 => Some(self.epoch),
                    stamp => self.stamp_instant(stamp),
                };
                // An unrepresentable deadline cannot occur inside the platform's
                // monotonic range, so `None` is correct rather than arming a
                // shorter substitute timer.
                let deadline = base.and_then(|base| base.checked_add(self.max_stale));
                return (false, deadline.map(|deadline| deadline.max(now)));
            }
            if self
                .state
                .compare_exchange(
                    observed,
                    observed | STALE_BIT,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                tracing::error!(
                    audit.event = "cp_dp_trust_bundle_stale",
                    max_stale_seconds = self.max_stale.as_secs(),
                    consecutive_failures = self.consecutive_failures.load(Ordering::Relaxed),
                    reason = self.last_failure_reason().map_or("ok", |f| f.as_str()),
                    "CP/DP trust generation has not been revalidated within the configured \
                     bound; refusing new authenticated configuration streams and terminating \
                     established ones"
                );
                return (true, None);
            }
            // Either another evaluator latched the same generation or a valid
            // candidate was accepted while this one was computing. Recompute
            // rather than commit a mixed-generation verdict.
        }
    }

    /// Whether new authenticated configuration streams must be refused.
    ///
    /// One `evaluate_at` call: a handful of relaxed/acquire atomic loads with
    /// no lock, no allocation, and no I/O.
    pub fn admission_blocked(&self) -> bool {
        self.evaluate_at(Instant::now()).0
    }

    fn last_failure_reason(&self) -> Option<TrustReloadFailure> {
        let encoded = self.last_failure.load(Ordering::Acquire);
        if encoded == 0 {
            return None;
        }
        TRUST_RELOAD_FAILURES.get(usize::from(encoded - 1)).copied()
    }

    /// Fixed-cardinality projection at the current instant.
    pub fn snapshot(&self) -> CpDpTrustReloadSnapshot {
        self.snapshot_at(Instant::now())
    }

    /// [`Self::snapshot`] with an explicit instant (tests).
    pub fn snapshot_at(&self, now: Instant) -> CpDpTrustReloadSnapshot {
        let (stale, _) = self.evaluate_at(now);
        let worker_state = self.worker_state_at(now);
        let last_attempt = self.last_attempt_ms.load(Ordering::Acquire);
        let last_acceptance = self.last_acceptance_ms.load(Ordering::Acquire);
        let mut rejections_by_reason = BTreeMap::new();
        let mut rejections_total = 0u64;
        for failure in TRUST_RELOAD_FAILURES {
            let value = self.rejections[failure.index()].load(Ordering::Relaxed);
            rejections_total = rejections_total.saturating_add(value);
            rejections_by_reason.insert(failure.as_str(), value);
        }
        CpDpTrustReloadSnapshot {
            configured: self.configured,
            worker_state: worker_state.as_str(),
            worker_running: matches!(worker_state, WorkerState::Running | WorkerState::Stalled),
            degraded: self.degraded() || worker_state == WorkerState::Failed,
            stale,
            admission_blocked: stale,
            readiness_blocked: stale || worker_state == WorkerState::Failed,
            reason: self.last_failure_reason().map_or("ok", |f| f.as_str()),
            last_attempt_age_seconds: (last_attempt != 0)
                .then(|| self.since_stamp(last_attempt, now).as_secs()),
            last_acceptance_age_seconds: (last_acceptance != 0)
                .then(|| self.since_stamp(last_acceptance, now).as_secs()),
            max_stale_seconds: self.max_stale.as_secs(),
            unbounded_stale_allowed: self.unbounded_allowed,
            consecutive_failures: self.consecutive_failures.load(Ordering::Acquire),
            recoveries_total: self.recoveries_total.load(Ordering::Relaxed),
            attempts_total: self.attempts_total.load(Ordering::Relaxed),
            acceptances_total: self.acceptances_total.load(Ordering::Relaxed),
            rejections_total,
            rejections_by_reason,
        }
    }
}

/// A single-timer view of "has the stale bound been crossed yet?".
///
/// Both stream lifecycles — the task-owned lease and the poll-driven response
/// stream — need the same thing: wake exactly once, at the boundary. No watch
/// channel is needed for correctness, because the deadline only ever moves
/// *later* (an acceptance is the only event that changes it). A stream that
/// wakes at a superseded deadline simply re-evaluates and re-arms.
pub struct TrustStaleWatch {
    status: Arc<CpDpTrustReloadStatus>,
    sleep: Pin<Box<Sleep>>,
    armed: Option<Instant>,
}

impl TrustStaleWatch {
    pub fn new(status: Arc<CpDpTrustReloadStatus>) -> Self {
        Self {
            status,
            // Parked until the first poll computes a real deadline.
            sleep: Box::pin(tokio::time::sleep(Duration::from_secs(0))),
            armed: None,
        }
    }

    /// Ready exactly when the configured stale bound has been crossed.
    ///
    /// When no bound can ever be crossed (no trust bundle, or unbounded
    /// retention explicitly opted into) this returns `Poll::Pending` without
    /// registering a waker: there is genuinely no event to wait for, and every
    /// caller polls it beside other wakeup sources.
    pub fn poll_stale(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        // Two iterations suffice: a fired timer means the deadline elapsed, so
        // the next evaluation either latches stale or reads an acceptance that
        // moved the deadline strictly later. The bound is a belt-and-braces
        // guard against a pathological clock, not an expected path.
        for _ in 0..2 {
            let now = Instant::now();
            let (stale, deadline) = self.status.evaluate_at(now);
            if stale {
                return Poll::Ready(());
            }
            let Some(deadline) = deadline else {
                return Poll::Pending;
            };
            if self.armed != Some(deadline) {
                self.sleep.as_mut().reset(deadline);
                self.armed = Some(deadline);
            }
            if self.sleep.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            self.armed = None;
        }
        Poll::Pending
    }

    /// Await the stale boundary. Never completes when no bound applies.
    pub async fn stale(&mut self) {
        std::future::poll_fn(|cx| self.poll_stale(cx)).await
    }
}
