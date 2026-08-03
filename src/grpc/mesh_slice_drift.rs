//! CP-side per-authenticated-DP mesh slice convergence / drift tracking
//! (issue #3265).
//!
//! Complements the DP-local `GET /mesh/config-drift` surface: this registry
//! records what the control plane **desired**, last **sent**, last
//! **acknowledged**, and last **rejected** for each authenticated mesh
//! subscriber so operators can spot stuck, partitioned, or repeatedly
//! rejecting data planes after a successful CP reconciliation.
//!
//! # Identity
//!
//! Entries are keyed by the authenticated JWT `sub` (bound to the
//! `MeshSubscribeRequest.node_id` at subscribe time). Caller-supplied display
//! fields are never trusted as identity.
//!
//! # Session semantics
//!
//! - **Subscribe / replacement**: a new session for the same identity replaces
//!   the prior entry. Generation is `connected_at`; stale stream drops and
//!   heartbeats must match that generation.
//! - **Duplicate concurrent streams**: last successful insert wins (same as
//!   [`super::mesh_registry::MeshNodeRegistry`]).
//! - **Send**: advances `sent` for the matching generation only.
//! - **Desired**: advanced when the CP publishes a new scoped slice version.
//! - **ACK / NACK**: recorded only for an existing identity; malformed reports
//!   fail closed with field-specific diagnostics.
//! - **Disconnect**: marks the entry disconnected but retains it until the
//!   retention TTL so partition/reconnect drift remains visible.
//! - **Retention expiry / cardinality**: expired disconnected entries are
//!   reaped; inserts that would exceed the hard cap first evict the oldest
//!   disconnected entry, otherwise refuse with a bounded error.
//!
//! Hot/admin reads consume an immutable [`MeshSliceDriftSnapshot`] via
//! `ArcSwap` — scrapes never walk the live map.

use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::Serialize;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Retention for disconnected DP drift rows (matches mesh node heartbeat TTL).
pub const MESH_SLICE_DRIFT_RETENTION_SECONDS: i64 = 300;

/// Hard cap on tracked identities. Operator-bounded fleets stay well under
/// this; hostile reconnect storms cannot grow the map unboundedly.
pub const MESH_SLICE_DRIFT_MAX_ENTRIES: usize = 4096;

/// Max accepted slice-version string length (fail closed above this).
pub const MESH_SLICE_DRIFT_MAX_VERSION_CHARS: usize = 256;

/// Max retained rejection-reason characters after sanitisation.
pub const MESH_SLICE_DRIFT_MAX_REASON_CHARS: usize = 64;

/// Closed-set convergence classification for summary metrics / admin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MeshSliceConvergenceState {
    /// Desired, sent, and acknowledged versions all agree and are present.
    Converged,
    /// Desired differs from sent and/or acknowledged (or ACK is missing while
    /// a desired version exists).
    Drifted,
    /// Last status report was a NACK (rejected version present). Takes
    /// precedence over plain drift so rejecting DPs are obvious.
    Rejecting,
    /// Connected but the CP has not yet stamped a desired version.
    Pending,
    /// Stream gone; row retained until retention expiry.
    Disconnected,
}

impl MeshSliceConvergenceState {
    pub const fn as_metric_label(self) -> &'static str {
        match self {
            Self::Converged => "converged",
            Self::Drifted => "drifted",
            Self::Rejecting => "rejecting",
            Self::Pending => "pending",
            Self::Disconnected => "disconnected",
        }
    }
}

/// One version watermark with useful age metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MeshSliceVersionStamp {
    pub version: String,
    pub at: DateTime<Utc>,
    /// `now - at` in seconds, clamped to zero on clock skew.
    pub age_seconds: u64,
}

impl MeshSliceVersionStamp {
    fn from_parts(version: String, at: DateTime<Utc>, now: DateTime<Utc>) -> Self {
        Self {
            version,
            at,
            age_seconds: age_seconds(now, at),
        }
    }
}

/// Immutable per-DP row exposed on the admin snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MeshSliceDriftEntry {
    /// Authenticated DP identity (JWT `sub`).
    pub node_id: String,
    pub namespace: String,
    pub connected: bool,
    pub session_connected_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disconnected_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub desired: Option<MeshSliceVersionStamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sent: Option<MeshSliceVersionStamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acknowledged: Option<MeshSliceVersionStamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejected: Option<MeshSliceRejectedStamp>,
    pub convergence: MeshSliceConvergenceState,
    pub drift: MeshSliceDriftFlags,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MeshSliceRejectedStamp {
    pub version: String,
    pub at: DateTime<Utc>,
    pub age_seconds: u64,
    /// Control-character-stripped, length-bounded reason. Never credentials.
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct MeshSliceDriftFlags {
    pub desired_vs_sent: bool,
    pub desired_vs_acknowledged: bool,
    pub sent_vs_acknowledged: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct MeshSliceDriftSummary {
    pub tracked: usize,
    pub connected: usize,
    pub converged: usize,
    pub drifted: usize,
    pub rejecting: usize,
    pub pending: usize,
    pub disconnected: usize,
}

/// Immutable admin/metrics view.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct MeshSliceDriftSnapshot {
    pub generated_at: DateTime<Utc>,
    pub data_planes: Vec<MeshSliceDriftEntry>,
    pub summary: MeshSliceDriftSummary,
}

#[derive(Debug, Clone)]
struct LiveEntry {
    node_id: String,
    namespace: String,
    connected_at: DateTime<Utc>,
    connected: bool,
    disconnected_at: Option<DateTime<Utc>>,
    desired_version: Option<String>,
    desired_at: Option<DateTime<Utc>>,
    sent_version: Option<String>,
    sent_at: Option<DateTime<Utc>>,
    acknowledged_version: Option<String>,
    acknowledged_at: Option<DateTime<Utc>>,
    rejected_version: Option<String>,
    rejected_at: Option<DateTime<Utc>>,
    rejected_reason: Option<String>,
}

/// Why a status report or subscribe was refused. Closed, compile-time set —
/// never echoes caller-supplied bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshSliceDriftAdmitError {
    EmptyNodeId,
    EmptyNamespace,
    EmptyVersion,
    VersionTooLong,
    UnknownNode,
    CardinalityExceeded,
}

impl MeshSliceDriftAdmitError {
    pub const fn as_status_message(self) -> &'static str {
        match self {
            Self::EmptyNodeId => "authenticated node identity must not be empty",
            Self::EmptyNamespace => "mesh slice drift namespace must not be empty",
            Self::EmptyVersion => "mesh slice status version must not be empty",
            Self::VersionTooLong => "mesh slice status version exceeds the maximum length",
            Self::UnknownNode => "no mesh slice drift session exists for this authenticated identity",
            Self::CardinalityExceeded => {
                "mesh slice drift registry is at capacity; disconnect idle data planes or raise retention reaping"
            }
        }
    }

    pub const fn field_name(self) -> &'static str {
        match self {
            Self::EmptyNodeId => "node_id",
            Self::EmptyNamespace => "namespace",
            Self::EmptyVersion => "version",
            Self::VersionTooLong => "version",
            Self::UnknownNode => "node_id",
            Self::CardinalityExceeded => "cardinality",
        }
    }
}

/// Process-global summary gauges (closed-set `state` label only).
static DRIFT_SUMMARY_CONVERGED: AtomicU64 = AtomicU64::new(0);
static DRIFT_SUMMARY_DRIFTED: AtomicU64 = AtomicU64::new(0);
static DRIFT_SUMMARY_REJECTING: AtomicU64 = AtomicU64::new(0);
static DRIFT_SUMMARY_PENDING: AtomicU64 = AtomicU64::new(0);
static DRIFT_SUMMARY_DISCONNECTED: AtomicU64 = AtomicU64::new(0);
static DRIFT_SUMMARY_TRACKED: AtomicU64 = AtomicU64::new(0);

/// Bounded per-authenticated-DP slice-version drift registry.
#[derive(Default)]
pub struct MeshSliceDriftRegistry {
    entries: DashMap<String, LiveEntry>,
    snapshot: ArcSwap<MeshSliceDriftSnapshot>,
}

impl MeshSliceDriftRegistry {
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
            snapshot: ArcSwap::from_pointee(MeshSliceDriftSnapshot {
                generated_at: Utc::now(),
                data_planes: Vec::new(),
                summary: MeshSliceDriftSummary::default(),
            }),
        }
    }

    /// Open or replace a local mesh subscription session.
    pub fn open_session(
        &self,
        node_id: &str,
        namespace: &str,
        connected_at: DateTime<Utc>,
        desired_version: Option<&str>,
    ) -> Result<(), MeshSliceDriftAdmitError> {
        let node_id = validate_identity(node_id)?;
        let namespace = validate_namespace(namespace)?;
        if let Some(version) = desired_version {
            validate_version(version)?;
        }

        if !self.entries.contains_key(node_id)
            && self.entries.len() >= MESH_SLICE_DRIFT_MAX_ENTRIES
            && !self.evict_oldest_disconnected()
        {
            return Err(MeshSliceDriftAdmitError::CardinalityExceeded);
        }

        let now = connected_at;
        self.entries.insert(
            node_id.to_string(),
            LiveEntry {
                node_id: node_id.to_string(),
                namespace: namespace.to_string(),
                connected_at,
                connected: true,
                disconnected_at: None,
                desired_version: desired_version.map(str::to_string),
                desired_at: desired_version.map(|_| now),
                sent_version: None,
                sent_at: None,
                acknowledged_version: None,
                acknowledged_at: None,
                rejected_version: None,
                rejected_at: None,
                rejected_reason: None,
            },
        );
        self.refresh_snapshot(Utc::now());
        Ok(())
    }

    /// Record that the CP pushed `version` on the matching session generation.
    pub fn record_sent(
        &self,
        node_id: &str,
        expected_connected_at: DateTime<Utc>,
        version: &str,
        at: DateTime<Utc>,
    ) -> Result<(), MeshSliceDriftAdmitError> {
        validate_version(version)?;
        let mut updated = false;
        if let Some(mut entry) = self.entries.get_mut(node_id)
            && entry.connected_at == expected_connected_at
            && entry.connected
        {
            entry.sent_version = Some(version.to_string());
            entry.sent_at = Some(at);
            // A fresh send clears a prior rejection for this generation so a
            // recovered DP is not permanently sticky-rejected after the CP
            // republishes a fixed slice.
            if entry.rejected_version.as_deref() == Some(version) {
                entry.rejected_version = None;
                entry.rejected_at = None;
                entry.rejected_reason = None;
            }
            updated = true;
        }
        if updated {
            self.refresh_snapshot(Utc::now());
        }
        Ok(())
    }

    /// Advance desired version for every tracked DP in `namespace` (connected
    /// and retained-disconnected alike) so reload/delete reconciliation is
    /// visible even while a DP is partitioned.
    pub fn set_desired_for_namespace(&self, namespace: &str, version: &str, at: DateTime<Utc>) {
        if validate_namespace(namespace).is_err() || validate_version(version).is_err() {
            return;
        }
        let mut touched = false;
        for mut entry in self.entries.iter_mut() {
            if entry.namespace == namespace {
                entry.desired_version = Some(version.to_string());
                entry.desired_at = Some(at);
                touched = true;
            }
        }
        if touched {
            self.refresh_snapshot(Utc::now());
        }
    }

    /// Advance desired for every tracked identity (full CP publish).
    pub fn set_desired_all(&self, version: &str, at: DateTime<Utc>) {
        if validate_version(version).is_err() {
            return;
        }
        if self.entries.is_empty() {
            return;
        }
        for mut entry in self.entries.iter_mut() {
            entry.desired_version = Some(version.to_string());
            entry.desired_at = Some(at);
        }
        self.refresh_snapshot(Utc::now());
    }

    /// Advance desired for a single authenticated identity (initial push).
    pub fn set_desired_for_node(
        &self,
        node_id: &str,
        expected_connected_at: DateTime<Utc>,
        version: &str,
        at: DateTime<Utc>,
    ) -> Result<(), MeshSliceDriftAdmitError> {
        validate_version(version)?;
        let mut updated = false;
        if let Some(mut entry) = self.entries.get_mut(node_id)
            && entry.connected_at == expected_connected_at
        {
            entry.desired_version = Some(version.to_string());
            entry.desired_at = Some(at);
            updated = true;
        }
        if updated {
            self.refresh_snapshot(Utc::now());
        }
        Ok(())
    }

    /// Record an ACK (`error_message` empty) or NACK (non-empty, sanitised).
    pub fn record_status(
        &self,
        node_id: &str,
        version: &str,
        error_message: Option<&str>,
        at: DateTime<Utc>,
    ) -> Result<(), MeshSliceDriftAdmitError> {
        let node_id = validate_identity(node_id)?;
        validate_version(version)?;
        if !self.entries.contains_key(node_id) {
            return Err(MeshSliceDriftAdmitError::UnknownNode);
        }
        if let Some(mut entry) = self.entries.get_mut(node_id) {
            match error_message {
                None | Some("") => {
                    entry.acknowledged_version = Some(version.to_string());
                    entry.acknowledged_at = Some(at);
                    // Successful ACK clears rejection sticky state when the
                    // ACK covers the previously rejected version or any newer
                    // apply — operators still see historical drift via versions.
                    entry.rejected_version = None;
                    entry.rejected_at = None;
                    entry.rejected_reason = None;
                }
                Some(raw) => {
                    entry.rejected_version = Some(version.to_string());
                    entry.rejected_at = Some(at);
                    entry.rejected_reason = Some(sanitize_reason(raw));
                }
            }
        }
        self.refresh_snapshot(Utc::now());
        Ok(())
    }

    /// Mark a matching generation disconnected; retain until reaper expiry.
    pub fn mark_disconnected(&self, node_id: &str, expected_connected_at: DateTime<Utc>) {
        let now = Utc::now();
        let mut updated = false;
        if let Some(mut entry) = self.entries.get_mut(node_id)
            && entry.connected_at == expected_connected_at
            && entry.connected
        {
            entry.connected = false;
            entry.disconnected_at = Some(now);
            updated = true;
        }
        if updated {
            self.refresh_snapshot(now);
        }
    }

    /// Remove expired disconnected rows. Returns how many were deleted.
    pub fn reap_expired(&self, now: DateTime<Utc>, retention: chrono::Duration) -> usize {
        let stale_before = now - retention;
        let before = self.entries.len();
        self.entries.retain(|_, entry| {
            if entry.connected {
                return true;
            }
            match entry.disconnected_at {
                Some(at) => at >= stale_before,
                None => false,
            }
        });
        let removed = before.saturating_sub(self.entries.len());
        if removed > 0 {
            self.refresh_snapshot(now);
        }
        removed
    }

    /// Lock-free immutable snapshot for admin / metrics.
    pub fn snapshot(&self) -> Arc<MeshSliceDriftSnapshot> {
        self.snapshot.load_full()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn evict_oldest_disconnected(&self) -> bool {
        let mut oldest: Option<(String, DateTime<Utc>)> = None;
        for entry in self.entries.iter() {
            if !entry.connected
                && let Some(at) = entry.disconnected_at
            {
                match &oldest {
                    None => oldest = Some((entry.node_id.clone(), at)),
                    Some((_, oldest_at)) if at < *oldest_at => {
                        oldest = Some((entry.node_id.clone(), at));
                    }
                    _ => {}
                }
            }
        }
        if let Some((node_id, _)) = oldest {
            self.entries.remove(&node_id);
            true
        } else {
            false
        }
    }

    fn refresh_snapshot(&self, now: DateTime<Utc>) {
        let mut data_planes: Vec<MeshSliceDriftEntry> = self
            .entries
            .iter()
            .map(|entry| publish_entry(entry.value(), now))
            .collect();
        data_planes.sort_by(|a, b| {
            a.namespace
                .cmp(&b.namespace)
                .then_with(|| a.node_id.cmp(&b.node_id))
        });

        let mut summary = MeshSliceDriftSummary {
            tracked: data_planes.len(),
            ..MeshSliceDriftSummary::default()
        };
        for entry in &data_planes {
            if entry.connected {
                summary.connected += 1;
            }
            match entry.convergence {
                MeshSliceConvergenceState::Converged => summary.converged += 1,
                MeshSliceConvergenceState::Drifted => summary.drifted += 1,
                MeshSliceConvergenceState::Rejecting => summary.rejecting += 1,
                MeshSliceConvergenceState::Pending => summary.pending += 1,
                MeshSliceConvergenceState::Disconnected => summary.disconnected += 1,
            }
        }

        DRIFT_SUMMARY_TRACKED.store(summary.tracked as u64, Ordering::Relaxed);
        DRIFT_SUMMARY_CONVERGED.store(summary.converged as u64, Ordering::Relaxed);
        DRIFT_SUMMARY_DRIFTED.store(summary.drifted as u64, Ordering::Relaxed);
        DRIFT_SUMMARY_REJECTING.store(summary.rejecting as u64, Ordering::Relaxed);
        DRIFT_SUMMARY_PENDING.store(summary.pending as u64, Ordering::Relaxed);
        DRIFT_SUMMARY_DISCONNECTED.store(summary.disconnected as u64, Ordering::Relaxed);

        self.snapshot.store(Arc::new(MeshSliceDriftSnapshot {
            generated_at: now,
            data_planes,
            summary,
        }));
    }
}

fn publish_entry(entry: &LiveEntry, now: DateTime<Utc>) -> MeshSliceDriftEntry {
    let desired = entry
        .desired_version
        .as_ref()
        .zip(entry.desired_at)
        .map(|(v, at)| MeshSliceVersionStamp::from_parts(v.clone(), at, now));
    let sent = entry
        .sent_version
        .as_ref()
        .zip(entry.sent_at)
        .map(|(v, at)| MeshSliceVersionStamp::from_parts(v.clone(), at, now));
    let acknowledged = entry
        .acknowledged_version
        .as_ref()
        .zip(entry.acknowledged_at)
        .map(|(v, at)| MeshSliceVersionStamp::from_parts(v.clone(), at, now));
    let rejected = entry.rejected_version.as_ref().map(|version| {
        let at = entry.rejected_at.unwrap_or(now);
        MeshSliceRejectedStamp {
            version: version.clone(),
            at,
            age_seconds: age_seconds(now, at),
            reason: entry
                .rejected_reason
                .clone()
                .unwrap_or_else(|| "unspecified".to_string()),
        }
    });

    let drift = MeshSliceDriftFlags {
        desired_vs_sent: versions_differ(
            desired.as_ref().map(|s| s.version.as_str()),
            sent.as_ref().map(|s| s.version.as_str()),
        ),
        desired_vs_acknowledged: versions_differ(
            desired.as_ref().map(|s| s.version.as_str()),
            acknowledged.as_ref().map(|s| s.version.as_str()),
        ),
        sent_vs_acknowledged: versions_differ(
            sent.as_ref().map(|s| s.version.as_str()),
            acknowledged.as_ref().map(|s| s.version.as_str()),
        ),
    };

    let convergence = classify(entry.connected, &desired, &sent, &acknowledged, &rejected, drift);

    MeshSliceDriftEntry {
        node_id: entry.node_id.clone(),
        namespace: entry.namespace.clone(),
        connected: entry.connected,
        session_connected_at: entry.connected_at,
        disconnected_at: entry.disconnected_at,
        desired,
        sent,
        acknowledged,
        rejected,
        convergence,
        drift,
    }
}

fn classify(
    connected: bool,
    desired: &Option<MeshSliceVersionStamp>,
    sent: &Option<MeshSliceVersionStamp>,
    acknowledged: &Option<MeshSliceVersionStamp>,
    rejected: &Option<MeshSliceRejectedStamp>,
    drift: MeshSliceDriftFlags,
) -> MeshSliceConvergenceState {
    if !connected {
        return MeshSliceConvergenceState::Disconnected;
    }
    if rejected.is_some() {
        return MeshSliceConvergenceState::Rejecting;
    }
    if desired.is_none() {
        return MeshSliceConvergenceState::Pending;
    }
    if drift.desired_vs_sent
        || drift.desired_vs_acknowledged
        || drift.sent_vs_acknowledged
        || sent.is_none()
        || acknowledged.is_none()
    {
        return MeshSliceConvergenceState::Drifted;
    }
    MeshSliceConvergenceState::Converged
}

fn versions_differ(left: Option<&str>, right: Option<&str>) -> bool {
    match (left, right) {
        (Some(a), Some(b)) => a != b,
        (None, None) => false,
        _ => true,
    }
}

fn age_seconds(now: DateTime<Utc>, at: DateTime<Utc>) -> u64 {
    now.signed_duration_since(at)
        .num_seconds()
        .max(0) as u64
}

fn validate_identity(node_id: &str) -> Result<&str, MeshSliceDriftAdmitError> {
    let trimmed = node_id.trim();
    if trimmed.is_empty() {
        return Err(MeshSliceDriftAdmitError::EmptyNodeId);
    }
    Ok(trimmed)
}

fn validate_namespace(namespace: &str) -> Result<&str, MeshSliceDriftAdmitError> {
    let trimmed = namespace.trim();
    if trimmed.is_empty() {
        return Err(MeshSliceDriftAdmitError::EmptyNamespace);
    }
    Ok(trimmed)
}

fn validate_version(version: &str) -> Result<(), MeshSliceDriftAdmitError> {
    let trimmed = version.trim();
    if trimmed.is_empty() {
        return Err(MeshSliceDriftAdmitError::EmptyVersion);
    }
    if trimmed.chars().count() > MESH_SLICE_DRIFT_MAX_VERSION_CHARS {
        return Err(MeshSliceDriftAdmitError::VersionTooLong);
    }
    Ok(())
}

/// Control-character-stripped, length-bounded rejection reason for admin
/// surfaces. Never retains credentials or unbounded caller text.
pub fn sanitize_reason(raw: &str) -> String {
    let mut rendered = String::new();
    let mut truncated = false;
    for (index, ch) in raw.chars().enumerate() {
        if index >= MESH_SLICE_DRIFT_MAX_REASON_CHARS {
            truncated = true;
            break;
        }
        rendered.push(if ch.is_control() { '.' } else { ch });
    }
    if rendered.trim().is_empty() {
        return "unspecified".to_string();
    }
    if truncated {
        rendered.push_str("(truncated)");
    }
    rendered
}

/// Render closed-set CP mesh slice convergence gauges into a Prometheus text
/// exposition buffer. Label cardinality is fixed (`state` ∈ five values).
pub fn render_mesh_slice_drift_metrics(output: &mut String, gateway_ns_label: &str) {
    let tracked = DRIFT_SUMMARY_TRACKED.load(Ordering::Relaxed);
    // Only emit when the CP has ever tracked a DP (avoids noise on non-CP
    // processes that share the binary).
    if tracked == 0
        && DRIFT_SUMMARY_CONVERGED.load(Ordering::Relaxed) == 0
        && DRIFT_SUMMARY_DRIFTED.load(Ordering::Relaxed) == 0
        && DRIFT_SUMMARY_REJECTING.load(Ordering::Relaxed) == 0
        && DRIFT_SUMMARY_PENDING.load(Ordering::Relaxed) == 0
        && DRIFT_SUMMARY_DISCONNECTED.load(Ordering::Relaxed) == 0
    {
        return;
    }

    output.push_str(
        "# HELP ferrum_mesh_slice_drift_data_planes Tracked mesh data planes by CP-side slice convergence state.\n",
    );
    output.push_str("# TYPE ferrum_mesh_slice_drift_data_planes gauge\n");
    for (state, value) in [
        (
            MeshSliceConvergenceState::Converged,
            DRIFT_SUMMARY_CONVERGED.load(Ordering::Relaxed),
        ),
        (
            MeshSliceConvergenceState::Drifted,
            DRIFT_SUMMARY_DRIFTED.load(Ordering::Relaxed),
        ),
        (
            MeshSliceConvergenceState::Rejecting,
            DRIFT_SUMMARY_REJECTING.load(Ordering::Relaxed),
        ),
        (
            MeshSliceConvergenceState::Pending,
            DRIFT_SUMMARY_PENDING.load(Ordering::Relaxed),
        ),
        (
            MeshSliceConvergenceState::Disconnected,
            DRIFT_SUMMARY_DISCONNECTED.load(Ordering::Relaxed),
        ),
    ] {
        output.push_str(&format!(
            "ferrum_mesh_slice_drift_data_planes{{state=\"{}\"{}}} {}\n",
            state.as_metric_label(),
            gateway_ns_label,
            value
        ));
    }

    output.push_str(
        "# HELP ferrum_mesh_slice_drift_tracked_data_planes Total mesh data planes retained in the CP slice-drift registry.\n",
    );
    output.push_str("# TYPE ferrum_mesh_slice_drift_tracked_data_planes gauge\n");
    if gateway_ns_label.is_empty() {
        output.push_str(&format!(
            "ferrum_mesh_slice_drift_tracked_data_planes {tracked}\n"
        ));
    } else {
        let label_body = gateway_ns_label
            .strip_prefix(',')
            .unwrap_or(gateway_ns_label);
        output.push_str(&format!(
            "ferrum_mesh_slice_drift_tracked_data_planes{{{label_body}}} {tracked}\n"
        ));
    }
}
