//! Authoritative mesh config revision ordering (issue #2473).
//!
//! Native multi-CP failover used to install whatever slice the fallback CP
//! served first. The only "version" a slice carried was the serving CP's local
//! `GatewayConfig.loaded_at` wall clock, which is neither shared between CP
//! replicas nor safe to compare across clocks and restarts — so a lagging
//! fallback could roll the data plane back to an older, still structurally
//! valid snapshot (resurrecting deleted routes, endpoints, policies, or trust
//! material) until failback.
//!
//! This module defines the ordering primitive that replaces that timestamp:
//!
//! ```text
//! MeshConfigRevision = (authority, sequence)
//! ```
//!
//! * `authority` names the ORDERING DOMAIN — the shared source whose sequence
//!   numbers are comparable. Every CP replica reading the same durable config
//!   store advertises the SAME authority string, so slices from a primary and a
//!   fallback are directly comparable. It is operator-controllable
//!   (`FERRUM_MESH_CONFIG_AUTHORITY_ID`) precisely so a deliberate source reset
//!   (restore-from-backup, migration to a new store) can be signalled as a NEW
//!   domain instead of silently rewinding sequence numbers inside the old one.
//! * `sequence` is the durable, monotonically increasing config change sequence
//!   (`config_changes.sequence` — the same cursor CP incremental polling already
//!   treats as authoritative). It is NOT a process-local counter and NOT a
//!   clock, so it survives CP restarts and is identical on every replica.
//!
//! # Comparison contract
//!
//! [`MeshConfigRevision::compare`] is the single source of truth:
//!
//! | accepted        | candidate       | order                       |
//! |-----------------|-----------------|-----------------------------|
//! | `None`          | anything        | [`MeshRevisionOrder::Bootstrap`] |
//! | `Some(_)`       | `None`          | [`MeshRevisionOrder::Unversioned`] |
//! | same authority  | `seq >  accept` | [`MeshRevisionOrder::Newer`] |
//! | same authority  | `seq == accept` | [`MeshRevisionOrder::Same`]  |
//! | same authority  | `seq <  accept` | [`MeshRevisionOrder::Older`] |
//! | other authority | any             | [`MeshRevisionOrder::Incomparable`] |
//!
//! `Newer` and `Same` install. `Same` MUST install: reconnecting to the same CP
//! replays that CP's initial slice at the unchanged revision, and quarantining
//! it would break every ordinary reconnect. `Older`, `Unversioned`, and
//! `Incomparable` are quarantined — the previously accepted slice keeps serving.
//!
//! # Candidate lifecycle (received → applied, or rolled back)
//!
//! Passing the freshness gate only makes a slice the RECEIVED candidate. The
//! mesh proxy runtime is a second, independent gate: slice→config preparation
//! or `ProxyState::update_config` can still refuse it, in which case the proxy
//! keeps serving the previously applied generation. The watermark therefore has
//! two slots:
//!
//! * `accepted` — the highest revision admitted into the RECEIVED slot. This is
//!   what [`MeshRevisionGate::admit`] compares against, so a rapid burst of
//!   updates still orders correctly while an earlier one is mid-apply.
//! * `applied` — the revision of the slice the proxy runtime last ACCEPTED.
//!   This is the authoritative last-good generation and the rollback target.
//!
//! [`MeshRevisionGate::commit_applied`] advances `applied` when the runtime
//! accepts a candidate (including a content-no-op replay at the same revision).
//! [`MeshRevisionGate::rollback_rejected`] runs when the runtime REFUSES one and
//! returns `accepted` to `applied` — but only when the refused candidate is
//! still the accepted watermark, so a late rejection of N can never roll back an
//! already-received N+1. Without that rollback a hostile or buggy control plane
//! could publish one runtime-invalid slice at a far-future sequence and
//! permanently lock out every valid revision below it, even though its slice
//! never became the serving generation.
//!
//! # Intentional rollback
//!
//! An operator rolling configuration back writes to the config store, which
//! allocates NEW change-log sequences. A rollback therefore arrives as a HIGHER
//! revision carrying older content and installs normally. Rolling the data
//! plane back by replaying an old generation is never a supported operation.
//!
//! # No permanent lockout
//!
//! Two escape hatches, both explicit:
//!
//! * A foreign authority observed continuously for
//!   [`MeshRevisionPolicy::foreign_authority_adopt_secs`] is ADOPTED (warn +
//!   counter). This covers CP state loss and a deliberate source reset without
//!   an operator round trip. `0` disables adoption.
//! * `POST /mesh/config-revision/reset` (JWT-authenticated) clears the accepted
//!   revision so the next slice from any authority installs. This is the
//!   documented recovery for the one case that is NEVER auto-adopted: a
//!   sequence rewind INSIDE one authority (e.g. a store restored from backup
//!   without bumping `FERRUM_MESH_CONFIG_AUTHORITY_ID`). Auto-adopting that
//!   case would be indistinguishable from the rollback this module exists to
//!   prevent.

use std::sync::Mutex;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Maximum accepted length of a control-plane-supplied `authority` string.
///
/// The authority rides an untrusted wire field and is echoed into
/// length-bounded diagnostics, so an over-long value is refused at the boundary
/// rather than stored. Comfortably above any real authority id.
pub const MAX_AUTHORITY_LEN: usize = 128;

/// Default grace period before a continuously observed foreign authority is
/// adopted (`FERRUM_MESH_CONFIG_REVISION_ADOPT_SECS`).
pub const DEFAULT_FOREIGN_AUTHORITY_ADOPT_SECS: u64 = 300;

/// Default config authority id advertised by a DB-backed control plane
/// (`FERRUM_MESH_CONFIG_AUTHORITY_ID`). Shared by every replica reading the same
/// store, because the ordering domain is the STORE, not the process.
pub const DEFAULT_CONFIG_AUTHORITY_ID: &str = "db";

/// Authoritative, replica-shared mesh config revision.
///
/// Carried on [`crate::modes::mesh::slice::MeshSlice::revision`], duplicated on
/// the `MeshConfigUpdate` envelope, and on the xDS path recovered through the
/// `ConfigRevision` ECDS carrier so native and xDS materialize identically.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshConfigRevision {
    /// Ordering domain. Sequences are only comparable within one authority.
    pub authority: String,
    /// Durable config-change sequence within `authority`. Monotonic.
    pub sequence: u64,
}

impl MeshConfigRevision {
    pub fn new(authority: impl Into<String>, sequence: u64) -> Self {
        Self {
            authority: authority.into(),
            sequence,
        }
    }

    /// Whether the wire-supplied shape is usable for ordering.
    ///
    /// A blank, over-long, or control-character-bearing authority carries no
    /// ordering meaning and is treated as absent (fail closed) rather than
    /// compared. Control characters are refused at the boundary — not merely
    /// escaped downstream — because an authority that reaches the accepted
    /// watermark is echoed into the operator reset audit log and the
    /// `/mesh/config-drift` diagnostics; a CP that could park `\n`-bearing
    /// text there would be shaping operator-facing records rather than naming
    /// an ordering domain. Real authority ids are opaque printable labels
    /// (`FERRUM_MESH_CONFIG_AUTHORITY_ID`), so nothing legitimate is excluded.
    pub fn is_well_formed(&self) -> bool {
        !self.authority.trim().is_empty()
            && self.authority.len() <= MAX_AUTHORITY_LEN
            && !self.authority.chars().any(char::is_control)
    }

    /// Order `candidate` against `accepted`. See the module contract table.
    pub fn compare(accepted: Option<&Self>, candidate: Option<&Self>) -> MeshRevisionOrder {
        let Some(accepted) = accepted.filter(|revision| revision.is_well_formed()) else {
            return MeshRevisionOrder::Bootstrap;
        };
        let Some(candidate) = candidate.filter(|revision| revision.is_well_formed()) else {
            return MeshRevisionOrder::Unversioned;
        };
        if candidate.authority != accepted.authority {
            return MeshRevisionOrder::Incomparable;
        }
        match candidate.sequence.cmp(&accepted.sequence) {
            std::cmp::Ordering::Greater => MeshRevisionOrder::Newer,
            std::cmp::Ordering::Equal => MeshRevisionOrder::Same,
            std::cmp::Ordering::Less => MeshRevisionOrder::Older,
        }
    }
}

/// Result of the revision comparison contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshRevisionOrder {
    /// No usable accepted revision yet — anything installs.
    Bootstrap,
    /// Candidate carries no usable revision while one is already accepted.
    Unversioned,
    /// Candidate is from a different ordering domain.
    Incomparable,
    /// Candidate is strictly newer within the accepted authority.
    Newer,
    /// Candidate is the same revision (reconnect replay / republish).
    Same,
    /// Candidate is strictly older within the accepted authority.
    Older,
}

impl MeshRevisionOrder {
    /// Whether this ordering installs without further policy input.
    pub const fn installs(self) -> bool {
        matches!(self, Self::Bootstrap | Self::Newer | Self::Same)
    }
}

/// Why a slice was quarantined by the freshness gate. Fixed, compile-time set —
/// used directly as the bounded `reason` metric label, never a CP-supplied
/// string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshRevisionRejectReason {
    /// An older revision from the accepted authority: the stale-fallback case.
    StaleRevision,
    /// A revision from a different ordering domain.
    IncomparableAuthority,
    /// No usable revision at all while a revisioned slice is accepted.
    MissingRevision,
}

impl MeshRevisionRejectReason {
    pub const fn as_metric_label(self) -> &'static str {
        match self {
            Self::StaleRevision => "stale_revision",
            Self::IncomparableAuthority => "incomparable_authority",
            Self::MissingRevision => "missing_revision",
        }
    }

    /// Whether a streaming consumer must drop the stream instead of the frame.
    ///
    /// Every revision rejection means the serving control plane's whole view is
    /// behind (or belongs to another ordering domain), so nothing else it sends
    /// can be trusted either: the native client tears the stream down and lets
    /// multi-CP failover move on, exactly as it does for a binding failure. The
    /// last-good slice keeps serving throughout.
    pub const fn terminates_stream(self) -> bool {
        true
    }
}

/// A quarantined slice: a bounded reason plus a safe, non-secret diagnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshRevisionRejection {
    reason: MeshRevisionRejectReason,
    detail: String,
}

impl MeshRevisionRejection {
    pub const fn reason(&self) -> MeshRevisionRejectReason {
        self.reason
    }

    /// Human-readable diagnostic. Control-plane-supplied values inside are
    /// length-bounded and control-character-stripped; no slice payload,
    /// credential, or endpoint detail is included.
    pub fn detail(&self) -> &str {
        &self.detail
    }

    pub const fn terminates_stream(&self) -> bool {
        self.reason.terminates_stream()
    }
}

impl std::fmt::Display for MeshRevisionRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.reason.as_metric_label(), self.detail)
    }
}

impl std::error::Error for MeshRevisionRejection {}

/// Operator policy for the freshness gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeshRevisionPolicy {
    /// Seconds a foreign authority must be observed continuously before it is
    /// adopted. `0` disables adoption (operator reset only).
    pub foreign_authority_adopt_secs: u64,
}

impl Default for MeshRevisionPolicy {
    fn default() -> Self {
        Self {
            foreign_authority_adopt_secs: DEFAULT_FOREIGN_AUTHORITY_ADOPT_SECS,
        }
    }
}

/// Operator-facing quarantine view, surfaced (JWT-authenticated) under
/// `revision` on `GET /mesh/config-drift`.
///
/// Deliberately NOT on `/metrics`: it carries CP-supplied authority strings and
/// sequence numbers. `/metrics` gets only the fixed-cardinality
/// `ferrum_mesh_config_revision_rejections_total{reason}` counter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MeshRevisionQuarantine {
    /// Bounded, sanitized rendering of the refused authority.
    pub authority: String,
    pub sequence: u64,
    pub reason: String,
    /// Consecutive quarantines of this same (authority, reason) pair.
    pub consecutive: u64,
    pub first_seen_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
}

/// Full revision block on `GET /mesh/config-drift`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MeshRevisionDiagnostics {
    /// Revision of the slice currently accepted into the RECEIVED slot, or
    /// `None` when the DP has never accepted a revisioned slice (unversioned
    /// source, or pre-first slice).
    ///
    /// The `authority` here is a SANITIZED rendering (control characters
    /// stripped, truncated) of the CP-supplied value; the raw string is kept
    /// only inside the gate, where exact ordering comparisons need it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accepted: Option<MeshConfigRevision>,
    /// Revision of the slice the proxy runtime last ACCEPTED — the last-good
    /// generation actually serving traffic, and the rollback target when a
    /// received candidate is refused by the runtime.
    ///
    /// Normally equal to `accepted`. It lags while a freshly received
    /// candidate is mid-apply, and stays behind when that candidate turns out
    /// to be runtime-invalid. Sanitized like `accepted`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub applied: Option<MeshConfigRevision>,
    /// Most recent quarantine, retained until a slice is accepted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quarantined: Option<MeshRevisionQuarantine>,
    /// Total slices refused by the freshness gate since process start.
    pub rejected_total: u64,
    /// Total foreign authorities adopted after the grace period.
    pub adopted_total: u64,
    /// Effective `FERRUM_MESH_CONFIG_REVISION_ADOPT_SECS`.
    pub foreign_authority_adopt_secs: u64,
    /// True while the gate is holding the last-good slice against a refused
    /// candidate — the "stale fallback quarantined" operator signal.
    pub quarantine_active: bool,
}

#[derive(Debug, Default)]
struct GateState {
    /// Highest revision admitted into the RECEIVED slot. Ordering baseline for
    /// [`MeshRevisionGate::admit`]. Raw CP value — exact comparisons need it.
    accepted: Option<MeshConfigRevision>,
    /// Revision the proxy runtime last accepted. Rollback target when a
    /// received candidate is refused by the runtime. Raw CP value.
    applied: Option<MeshConfigRevision>,
    quarantined: Option<MeshRevisionQuarantine>,
    /// Foreign authority under observation for adoption, with the instant it
    /// was first seen. Reset whenever a slice is accepted or a DIFFERENT
    /// foreign authority appears.
    foreign_watch: Option<(String, DateTime<Utc>)>,
    rejected_total: u64,
    adopted_total: u64,
}

/// Lock-free-on-the-request-path freshness gate.
///
/// Every method here is cold path: slice install (config plane) and admin
/// diagnostics. Nothing on the proxy request path touches it, so a plain
/// `Mutex` around the small ordering state is correct and cheaper to reason
/// about than a multi-slot `ArcSwap` that must not tear between the accepted
/// revision and the quarantine record.
#[derive(Debug)]
pub struct MeshRevisionGate {
    state: Mutex<GateState>,
    policy: Mutex<MeshRevisionPolicy>,
}

impl Default for MeshRevisionGate {
    fn default() -> Self {
        Self::new()
    }
}

impl MeshRevisionGate {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(GateState::default()),
            policy: Mutex::new(MeshRevisionPolicy::default()),
        }
    }

    pub fn set_policy(&self, policy: MeshRevisionPolicy) {
        match self.policy.lock() {
            Ok(mut guard) => *guard = policy,
            Err(poisoned) => *poisoned.into_inner() = policy,
        }
    }

    pub fn policy(&self) -> MeshRevisionPolicy {
        match self.policy.lock() {
            Ok(guard) => *guard,
            Err(poisoned) => *poisoned.into_inner(),
        }
    }

    /// Clear the accepted revision and quarantine record.
    ///
    /// The documented operator escape hatch (`POST /mesh/config-revision/reset`)
    /// for a source reset inside one authority.
    ///
    /// Clears the `applied` watermark too: leaving it would let the next
    /// runtime-rejected candidate roll `accepted` straight back to the
    /// generation the operator just cleared, silently undoing the reset.
    ///
    /// Returns a SANITIZED copy of the revision that was cleared, for the audit
    /// log and the admin response: the authority is control-plane-supplied, so
    /// the value that leaves the gate is control-character-stripped and
    /// length-bounded. The raw string never escapes.
    pub fn reset(&self) -> Option<MeshConfigRevision> {
        let mut state = self.lock_state();
        state.quarantined = None;
        state.foreign_watch = None;
        state.applied = None;
        state.accepted.take().as_ref().map(sanitized_revision)
    }

    /// Commit the watermark for a slice the proxy runtime ACCEPTED.
    ///
    /// Advances `applied` to the accepted generation — including a
    /// content-no-op or equal-revision replay, where the runtime accepts
    /// without a config delta and the watermark must still record that this
    /// revision is the live one. Also raises `accepted` when it is somehow
    /// behind (an installer that bypassed [`Self::admit`], or the first slice
    /// applied after an operator reset), so the two slots can never disagree in
    /// the direction that would quarantine the generation actually serving.
    pub fn commit_applied(&self, revision: Option<&MeshConfigRevision>) {
        let revision = revision.filter(|revision| revision.is_well_formed());
        let mut state = self.lock_state();
        state.applied = revision.cloned();
        let raise_accepted = match revision {
            Some(candidate) => matches!(
                MeshConfigRevision::compare(state.accepted.as_ref(), Some(candidate)),
                MeshRevisionOrder::Bootstrap | MeshRevisionOrder::Newer
            ),
            None => false,
        };
        if raise_accepted {
            state.accepted = revision.cloned();
        }
    }

    /// Finalize a candidate the proxy runtime REFUSED.
    ///
    /// Returns `accepted` to the last proxy-applied revision so a runtime-
    /// invalid slice cannot permanently advance the authoritative watermark
    /// and lock out every valid revision beneath it.
    ///
    /// Rolls back ONLY when `candidate` is still the accepted watermark, using
    /// exact `(authority, sequence)` equality: if a newer candidate was
    /// received while this one was mid-apply, that newer candidate owns the
    /// watermark and a late rejection must not disturb it. Returns whether a
    /// rollback happened.
    pub fn rollback_rejected(&self, candidate: Option<&MeshConfigRevision>) -> bool {
        let candidate = candidate.filter(|revision| revision.is_well_formed());
        let mut state = self.lock_state();
        if state.accepted.as_ref() != candidate {
            return false;
        }
        if state.accepted == state.applied {
            return false;
        }
        let restored = state.applied.clone();
        let (rejected_authority, rejected_sequence) = match candidate {
            Some(revision) => (diagnostic_value(&revision.authority), revision.sequence),
            None => ("<absent>".to_string(), 0),
        };
        let (restored_authority, restored_sequence) = match restored.as_ref() {
            Some(revision) => (diagnostic_value(&revision.authority), revision.sequence),
            None => ("<none>".to_string(), 0),
        };
        state.accepted = restored;
        drop(state);

        tracing::warn!(
            rejected_authority = %rejected_authority,
            rejected_sequence,
            restored_authority = %restored_authority,
            restored_sequence,
            "Mesh proxy runtime refused a received slice; rolled the accepted config revision \
             back to the last applied generation so valid intermediate revisions stay eligible"
        );
        true
    }

    /// Decide whether `candidate` may replace the RECEIVED slice, updating the
    /// accepted revision on success and the quarantine record on refusal.
    ///
    /// Admission is not the end of the lifecycle: the proxy runtime still has
    /// to accept the candidate. See [`Self::commit_applied`] /
    /// [`Self::rollback_rejected`], which finalize the watermark once that
    /// second gate has ruled.
    ///
    /// `now` is injected so the adoption grace period is deterministic in
    /// tests. Runs to completion BEFORE any `ArcSwap` replacement.
    pub fn admit(
        &self,
        candidate: Option<&MeshConfigRevision>,
        now: DateTime<Utc>,
    ) -> Result<MeshRevisionOrder, MeshRevisionRejection> {
        let adopt_secs = self.policy().foreign_authority_adopt_secs;
        let mut state = self.lock_state();
        let order = MeshConfigRevision::compare(state.accepted.as_ref(), candidate);

        if order.installs() {
            state.accepted = candidate.filter(|r| r.is_well_formed()).cloned();
            state.quarantined = None;
            state.foreign_watch = None;
            return Ok(order);
        }

        // Incomparable authority: adopt once the SAME foreign authority has been
        // observed continuously for the configured grace period. This is the
        // no-permanent-lockout path for CP state loss / deliberate source reset.
        if order == MeshRevisionOrder::Incomparable
            && adopt_secs > 0
            && let Some(candidate) = candidate
        {
            let first_seen = match state.foreign_watch.as_ref() {
                Some((authority, first_seen)) if authority == &candidate.authority => *first_seen,
                _ => {
                    state.foreign_watch = Some((candidate.authority.clone(), now));
                    now
                }
            };
            let observed_secs = now.signed_duration_since(first_seen).num_seconds().max(0) as u64;
            if observed_secs >= adopt_secs {
                state.adopted_total = state.adopted_total.saturating_add(1);
                state.accepted = Some(candidate.clone());
                state.quarantined = None;
                state.foreign_watch = None;
                crate::plugins::mesh::prometheus_helpers::increment_mesh_config_revision_adoption();
                tracing::warn!(
                    authority = %diagnostic_value(&candidate.authority),
                    sequence = candidate.sequence,
                    observed_secs,
                    "Adopting foreign mesh config authority after the configured grace period; \
                     mesh config ordering restarts from this revision"
                );
                return Ok(MeshRevisionOrder::Incomparable);
            }
        } else if order != MeshRevisionOrder::Incomparable {
            state.foreign_watch = None;
        }

        let reason = match order {
            MeshRevisionOrder::Older => MeshRevisionRejectReason::StaleRevision,
            MeshRevisionOrder::Incomparable => MeshRevisionRejectReason::IncomparableAuthority,
            MeshRevisionOrder::Unversioned => MeshRevisionRejectReason::MissingRevision,
            // `installs()` returned false, so these are unreachable; mapping
            // them to the stale reason keeps the match total without a panic.
            MeshRevisionOrder::Bootstrap | MeshRevisionOrder::Newer | MeshRevisionOrder::Same => {
                MeshRevisionRejectReason::StaleRevision
            }
        };

        let (authority, sequence) = match candidate {
            Some(revision) => (diagnostic_value(&revision.authority), revision.sequence),
            None => ("<absent>".to_string(), 0),
        };
        let consecutive = match state.quarantined.as_ref() {
            Some(previous)
                if previous.authority == authority
                    && previous.reason == reason.as_metric_label() =>
            {
                previous.consecutive.saturating_add(1)
            }
            _ => 1,
        };
        let first_seen_at = match state.quarantined.as_ref() {
            Some(previous) if consecutive > 1 => previous.first_seen_at,
            _ => now,
        };
        state.rejected_total = state.rejected_total.saturating_add(1);
        state.quarantined = Some(MeshRevisionQuarantine {
            authority: authority.clone(),
            sequence,
            reason: reason.as_metric_label().to_string(),
            consecutive,
            first_seen_at,
            last_seen_at: now,
        });

        let accepted = state
            .accepted
            .as_ref()
            .map(|revision| (diagnostic_value(&revision.authority), revision.sequence));
        drop(state);

        let (accepted_authority, accepted_sequence) = match accepted {
            Some((authority, sequence)) => (authority, sequence),
            None => ("<none>".to_string(), 0),
        };
        crate::plugins::mesh::prometheus_helpers::increment_mesh_config_revision_rejection(
            reason.as_metric_label(),
        );
        let detail = format!(
            "candidate revision '{authority}'/{sequence} refused against accepted revision \
             '{accepted_authority}'/{accepted_sequence}"
        );
        tracing::warn!(
            reason = reason.as_metric_label(),
            candidate_authority = %authority,
            candidate_sequence = sequence,
            accepted_authority = %accepted_authority,
            accepted_sequence,
            consecutive,
            "Quarantined a mesh slice that is not newer than the accepted config revision; \
             keeping the last-good slice"
        );
        Err(MeshRevisionRejection { reason, detail })
    }

    /// RAW accepted revision, for ordering comparisons only. Anything that
    /// logs it or returns it to a caller must render it through
    /// [`Self::diagnostics`] (or [`Self::reset`]) instead, which sanitizes the
    /// CP-supplied authority.
    pub fn accepted(&self) -> Option<MeshConfigRevision> {
        self.lock_state().accepted.clone()
    }

    /// RAW last-applied revision. Same rule as [`Self::accepted`].
    pub fn applied(&self) -> Option<MeshConfigRevision> {
        self.lock_state().applied.clone()
    }

    /// Operator-facing view. Every control-plane-supplied authority in the
    /// returned value is sanitized (control characters stripped, truncated),
    /// so no CP can forge a log line or exceed the documented bounded
    /// diagnostic surface through it.
    pub fn diagnostics(&self) -> MeshRevisionDiagnostics {
        let policy = self.policy();
        let state = self.lock_state();
        MeshRevisionDiagnostics {
            accepted: state.accepted.as_ref().map(sanitized_revision),
            applied: state.applied.as_ref().map(sanitized_revision),
            quarantine_active: state.quarantined.is_some(),
            quarantined: state.quarantined.clone(),
            rejected_total: state.rejected_total,
            adopted_total: state.adopted_total,
            foreign_authority_adopt_secs: policy.foreign_authority_adopt_secs,
        }
    }

    /// Lock helper that keeps a poisoned mutex usable: the guarded state is
    /// plain data with no broken invariant to preserve, and a config-plane
    /// panic must not wedge slice installs for the rest of the process.
    fn lock_state(&self) -> std::sync::MutexGuard<'_, GateState> {
        match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

/// Copy of a revision whose CP-supplied authority is safe to log or return.
///
/// The sequence is a `u64` and needs no bounding; only the authority string
/// does. The gate keeps the raw value internally so ordering comparisons stay
/// exact — sanitizing in place would make two distinct authorities that share
/// a 64-character prefix compare equal.
fn sanitized_revision(revision: &MeshConfigRevision) -> MeshConfigRevision {
    MeshConfigRevision {
        authority: diagnostic_value(&revision.authority),
        sequence: revision.sequence,
    }
}

/// Render a control-plane-supplied value for a log line or admin surface:
/// control characters stripped (no log-line forgery) and truncated.
fn diagnostic_value(value: &str) -> String {
    const MAX_CHARS: usize = 64;
    let mut rendered = String::with_capacity(value.len().min(MAX_CHARS) + 12);
    let mut truncated = false;
    for (index, ch) in value.chars().enumerate() {
        if index >= MAX_CHARS {
            truncated = true;
            break;
        }
        rendered.push(if ch.is_control() { '.' } else { ch });
    }
    if truncated {
        rendered.push_str("(truncated)");
    }
    rendered
}
