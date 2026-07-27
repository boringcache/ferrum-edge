//! NodeWaypoint secured-transport observability contract (issue #3334).
//!
//! Process-static, compile-time-bounded counters for the ADR signal set:
//! HBONE handshake success/failure, asserted source identity accept/reject,
//! destination-policy rejection, missing destination NodeWaypoint metadata,
//! and prohibited plaintext fallback attempts.
//!
//! ## Increment ownership
//!
//! One failed inbound session is counted in exactly one HBONE handshake phase:
//! - `inbound_tls` — TLS accept on a mesh mTLS/HBONE listener while NodeWaypoint
//!   observability is enabled. TLS failures also increment the mesh-wide
//!   umbrella `ferrum_mesh_mtls_handshake_failures_total` (distinct series;
//!   not a second ADR failure class).
//! - `inbound_connect` — HBONE CONNECT admission after TLS succeeded
//!   (authenticated peer / open-relay guard). Never incremented when TLS failed.
//! - `outbound_dial` — source-side secured HBONE dial (TLS+H2+CONNECT) to a
//!   destination NodeWaypoint. Independent of the destination's inbound phases.
//!
//! Asserted-identity and destination-policy counters are mutually exclusive for
//! a single authz decision: identity rejection is recorded first and skips the
//! destination-policy counter.
//!
//! ## Reset / monotonicity
//!
//! Counters are process-static atomics:
//! - config reload / SVID rotation: **do not reset** (monotonic within process);
//! - NodeWaypoint (ambient) process restart: **reset to zero**;
//! - node-agent restart: **does not reset** these proxy counters (different
//!   process). Capture-state / topology-degraded gauges live on the node-agent.
//!
//! Overlapping capture/identity accept drops stay on
//! [`crate::overload::NodeWaypointDropSnapshot`] (`/overload`); do not
//! duplicate them here.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use serde::Serialize;

use crate::plugins::prometheus_metrics::escape_label_value;

static ENABLED: AtomicBool = AtomicBool::new(false);

static HBONE_INBOUND_TLS_SUCCESS: AtomicU64 = AtomicU64::new(0);
static HBONE_INBOUND_TLS_FAILURE: AtomicU64 = AtomicU64::new(0);
static HBONE_INBOUND_CONNECT_SUCCESS: AtomicU64 = AtomicU64::new(0);
static HBONE_INBOUND_CONNECT_FAILURE: AtomicU64 = AtomicU64::new(0);
static HBONE_OUTBOUND_DIAL_SUCCESS: AtomicU64 = AtomicU64::new(0);
static HBONE_OUTBOUND_DIAL_FAILURE: AtomicU64 = AtomicU64::new(0);

static ASSERTED_IDENTITY_ACCEPTED: AtomicU64 = AtomicU64::new(0);
static ASSERTED_IDENTITY_REJECTED_UNTRUSTED_ASSERTOR: AtomicU64 = AtomicU64::new(0);
static ASSERTED_IDENTITY_REJECTED_TRUST_DOMAIN_MISMATCH: AtomicU64 = AtomicU64::new(0);
static ASSERTED_IDENTITY_REJECTED_UNAUTHENTICATED: AtomicU64 = AtomicU64::new(0);
static ASSERTED_IDENTITY_REJECTED_MALFORMED: AtomicU64 = AtomicU64::new(0);
static ASSERTED_IDENTITY_REJECTED_STALE_OR_UNKNOWN: AtomicU64 = AtomicU64::new(0);

static DESTINATION_POLICY_REJECTION_AUTHZ_DENY: AtomicU64 = AtomicU64::new(0);
static DESTINATION_POLICY_REJECTION_SCOPE_MISSING: AtomicU64 = AtomicU64::new(0);
static DESTINATION_POLICY_REJECTION_DESTINATION_SCOPE_MISSING: AtomicU64 = AtomicU64::new(0);
static DESTINATION_POLICY_REJECTION_RELAY_DESTINATION_DENIED: AtomicU64 = AtomicU64::new(0);

static MISSING_DESTINATION_METADATA: AtomicU64 = AtomicU64::new(0);
static PLAINTEXT_FALLBACK_ATTEMPTS: AtomicU64 = AtomicU64::new(0);

/// Bounded HBONE handshake phase for NodeWaypoint sessions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeWaypointHboneHandshakePhase {
    InboundTls,
    InboundConnect,
    OutboundDial,
}

impl NodeWaypointHboneHandshakePhase {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InboundTls => "inbound_tls",
            Self::InboundConnect => "inbound_connect",
            Self::OutboundDial => "outbound_dial",
        }
    }
}

/// Bounded asserted-identity rejection reasons (ADR contract).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeWaypointAssertedIdentityRejectReason {
    UntrustedAssertor,
    TrustDomainMismatch,
    UnauthenticatedHbone,
    Malformed,
    StaleOrUnknown,
}

impl NodeWaypointAssertedIdentityRejectReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UntrustedAssertor => "untrusted_assertor",
            Self::TrustDomainMismatch => "trust_domain_mismatch",
            Self::UnauthenticatedHbone => "unauthenticated_hbone",
            Self::Malformed => "malformed",
            Self::StaleOrUnknown => "stale_or_unknown",
        }
    }

    fn counter(self) -> &'static AtomicU64 {
        match self {
            Self::UntrustedAssertor => &ASSERTED_IDENTITY_REJECTED_UNTRUSTED_ASSERTOR,
            Self::TrustDomainMismatch => &ASSERTED_IDENTITY_REJECTED_TRUST_DOMAIN_MISMATCH,
            Self::UnauthenticatedHbone => &ASSERTED_IDENTITY_REJECTED_UNAUTHENTICATED,
            Self::Malformed => &ASSERTED_IDENTITY_REJECTED_MALFORMED,
            Self::StaleOrUnknown => &ASSERTED_IDENTITY_REJECTED_STALE_OR_UNKNOWN,
        }
    }
}

/// Bounded destination-policy rejection reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeWaypointDestinationPolicyRejectReason {
    AuthzDeny,
    ScopeMissing,
    DestinationScopeMissing,
    RelayDestinationDenied,
}

impl NodeWaypointDestinationPolicyRejectReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthzDeny => "authz_deny",
            Self::ScopeMissing => "scope_missing",
            Self::DestinationScopeMissing => "destination_scope_missing",
            Self::RelayDestinationDenied => "relay_destination_denied",
        }
    }

    fn counter(self) -> &'static AtomicU64 {
        match self {
            Self::AuthzDeny => &DESTINATION_POLICY_REJECTION_AUTHZ_DENY,
            Self::ScopeMissing => &DESTINATION_POLICY_REJECTION_SCOPE_MISSING,
            Self::DestinationScopeMissing => &DESTINATION_POLICY_REJECTION_DESTINATION_SCOPE_MISSING,
            Self::RelayDestinationDenied => &DESTINATION_POLICY_REJECTION_RELAY_DESTINATION_DENIED,
        }
    }
}

/// Authenticated admin /health snapshot of the NodeWaypoint ADR counters.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct NodeWaypointObservabilitySnapshot {
    pub enabled: bool,
    pub hbone_handshakes: NodeWaypointHboneHandshakeSnapshot,
    pub asserted_identity: NodeWaypointAssertedIdentitySnapshot,
    pub destination_policy_rejections: NodeWaypointDestinationPolicySnapshot,
    pub missing_destination_metadata: u64,
    pub plaintext_fallback_attempts: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct NodeWaypointHboneHandshakeSnapshot {
    pub inbound_tls_success: u64,
    pub inbound_tls_failure: u64,
    pub inbound_connect_success: u64,
    pub inbound_connect_failure: u64,
    pub outbound_dial_success: u64,
    pub outbound_dial_failure: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct NodeWaypointAssertedIdentitySnapshot {
    pub accepted: u64,
    pub rejected_untrusted_assertor: u64,
    pub rejected_trust_domain_mismatch: u64,
    pub rejected_unauthenticated_hbone: u64,
    pub rejected_malformed: u64,
    pub rejected_stale_or_unknown: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct NodeWaypointDestinationPolicySnapshot {
    pub authz_deny: u64,
    pub scope_missing: u64,
    pub destination_scope_missing: u64,
    pub relay_destination_denied: u64,
}

/// Enable or disable NodeWaypoint ADR counter producers for this process.
///
/// Called once at mesh startup from the topology. Counters themselves are never
/// cleared by this toggle so a mid-process topology flip (test-only) does not
/// rewrite history.
pub fn set_enabled(enabled: bool) {
    ENABLED.store(enabled, Ordering::Relaxed);
}

/// Whether NodeWaypoint ADR counter producers are active.
#[inline]
pub fn is_enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// Record a NodeWaypoint HBONE handshake outcome for one phase.
pub fn record_hbone_handshake(phase: NodeWaypointHboneHandshakePhase, success: bool) {
    if !is_enabled() {
        return;
    }
    let counter = match (phase, success) {
        (NodeWaypointHboneHandshakePhase::InboundTls, true) => &HBONE_INBOUND_TLS_SUCCESS,
        (NodeWaypointHboneHandshakePhase::InboundTls, false) => &HBONE_INBOUND_TLS_FAILURE,
        (NodeWaypointHboneHandshakePhase::InboundConnect, true) => &HBONE_INBOUND_CONNECT_SUCCESS,
        (NodeWaypointHboneHandshakePhase::InboundConnect, false) => &HBONE_INBOUND_CONNECT_FAILURE,
        (NodeWaypointHboneHandshakePhase::OutboundDial, true) => &HBONE_OUTBOUND_DIAL_SUCCESS,
        (NodeWaypointHboneHandshakePhase::OutboundDial, false) => &HBONE_OUTBOUND_DIAL_FAILURE,
    };
    counter.fetch_add(1, Ordering::Relaxed);
}

/// Record an accepted asserted source identity on inbound NodeWaypoint HBONE.
pub fn record_asserted_identity_accepted() {
    if !is_enabled() {
        return;
    }
    ASSERTED_IDENTITY_ACCEPTED.fetch_add(1, Ordering::Relaxed);
}

/// Record a rejected asserted source identity with a bounded reason.
pub fn record_asserted_identity_rejected(reason: NodeWaypointAssertedIdentityRejectReason) {
    if !is_enabled() {
        return;
    }
    reason.counter().fetch_add(1, Ordering::Relaxed);
}

/// Record a destination-policy rejection (AuthorizationPolicy / scope / relay).
pub fn record_destination_policy_rejection(reason: NodeWaypointDestinationPolicyRejectReason) {
    if !is_enabled() {
        return;
    }
    reason.counter().fetch_add(1, Ordering::Relaxed);
}

/// Record a skipped secured-route target because destination NodeWaypoint
/// metadata was absent under an identity-backed posture.
pub fn record_missing_destination_metadata() {
    if !is_enabled() {
        return;
    }
    MISSING_DESTINATION_METADATA.fetch_add(1, Ordering::Relaxed);
}

/// Record that a prohibited plaintext fallback was attempted and blocked.
///
/// Today this is incremented together with
/// [`record_missing_destination_metadata`] when identity-backed materialization
/// skips a metadata-absent target instead of retaining a plaintext backend.
pub fn record_plaintext_fallback_attempt() {
    if !is_enabled() {
        return;
    }
    PLAINTEXT_FALLBACK_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
}

/// Snapshot counters for authenticated admin diagnostics.
pub fn snapshot() -> NodeWaypointObservabilitySnapshot {
    NodeWaypointObservabilitySnapshot {
        enabled: is_enabled(),
        hbone_handshakes: NodeWaypointHboneHandshakeSnapshot {
            inbound_tls_success: HBONE_INBOUND_TLS_SUCCESS.load(Ordering::Relaxed),
            inbound_tls_failure: HBONE_INBOUND_TLS_FAILURE.load(Ordering::Relaxed),
            inbound_connect_success: HBONE_INBOUND_CONNECT_SUCCESS.load(Ordering::Relaxed),
            inbound_connect_failure: HBONE_INBOUND_CONNECT_FAILURE.load(Ordering::Relaxed),
            outbound_dial_success: HBONE_OUTBOUND_DIAL_SUCCESS.load(Ordering::Relaxed),
            outbound_dial_failure: HBONE_OUTBOUND_DIAL_FAILURE.load(Ordering::Relaxed),
        },
        asserted_identity: NodeWaypointAssertedIdentitySnapshot {
            accepted: ASSERTED_IDENTITY_ACCEPTED.load(Ordering::Relaxed),
            rejected_untrusted_assertor: ASSERTED_IDENTITY_REJECTED_UNTRUSTED_ASSERTOR
                .load(Ordering::Relaxed),
            rejected_trust_domain_mismatch: ASSERTED_IDENTITY_REJECTED_TRUST_DOMAIN_MISMATCH
                .load(Ordering::Relaxed),
            rejected_unauthenticated_hbone: ASSERTED_IDENTITY_REJECTED_UNAUTHENTICATED
                .load(Ordering::Relaxed),
            rejected_malformed: ASSERTED_IDENTITY_REJECTED_MALFORMED.load(Ordering::Relaxed),
            rejected_stale_or_unknown: ASSERTED_IDENTITY_REJECTED_STALE_OR_UNKNOWN
                .load(Ordering::Relaxed),
        },
        destination_policy_rejections: NodeWaypointDestinationPolicySnapshot {
            authz_deny: DESTINATION_POLICY_REJECTION_AUTHZ_DENY.load(Ordering::Relaxed),
            scope_missing: DESTINATION_POLICY_REJECTION_SCOPE_MISSING.load(Ordering::Relaxed),
            destination_scope_missing: DESTINATION_POLICY_REJECTION_DESTINATION_SCOPE_MISSING
                .load(Ordering::Relaxed),
            relay_destination_denied: DESTINATION_POLICY_REJECTION_RELAY_DESTINATION_DENIED
                .load(Ordering::Relaxed),
        },
        missing_destination_metadata: MISSING_DESTINATION_METADATA.load(Ordering::Relaxed),
        plaintext_fallback_attempts: PLAINTEXT_FALLBACK_ATTEMPTS.load(Ordering::Relaxed),
    }
}

/// Render NodeWaypoint ADR counters into Prometheus exposition format.
///
/// Always emits HELP/TYPE when the feature is enabled so scrapes expose a
/// stable zero baseline; when disabled, emits nothing (non-NodeWaypoint
/// processes must not advertise the series).
pub fn render_prometheus(output: &mut String, gateway_ns_label: &str) {
    if !is_enabled() {
        return;
    }
    let snap = snapshot();

    output.push_str(
        "# HELP ferrum_mesh_node_waypoint_hbone_handshakes_total \
NodeWaypoint HBONE handshake outcomes by phase. One failed session increments \
exactly one phase (inbound_tls XOR inbound_connect on the destination; \
outbound_dial is independent on the source).\n",
    );
    output.push_str("# TYPE ferrum_mesh_node_waypoint_hbone_handshakes_total counter\n");
    for (phase, result, value) in [
        ("inbound_tls", "success", snap.hbone_handshakes.inbound_tls_success),
        ("inbound_tls", "failure", snap.hbone_handshakes.inbound_tls_failure),
        (
            "inbound_connect",
            "success",
            snap.hbone_handshakes.inbound_connect_success,
        ),
        (
            "inbound_connect",
            "failure",
            snap.hbone_handshakes.inbound_connect_failure,
        ),
        (
            "outbound_dial",
            "success",
            snap.hbone_handshakes.outbound_dial_success,
        ),
        (
            "outbound_dial",
            "failure",
            snap.hbone_handshakes.outbound_dial_failure,
        ),
    ] {
        output.push_str(&format!(
            "ferrum_mesh_node_waypoint_hbone_handshakes_total{{phase=\"{}\",result=\"{}\"{}}} {}\n",
            escape_label_value(phase),
            escape_label_value(result),
            gateway_ns_label,
            value
        ));
    }

    output.push_str(
        "# HELP ferrum_mesh_node_waypoint_asserted_identity_total \
Asserted source-identity decisions on inbound NodeWaypoint HBONE. Rejection \
reasons are compile-time-bounded; SPIFFE IDs never appear as labels.\n",
    );
    output.push_str("# TYPE ferrum_mesh_node_waypoint_asserted_identity_total counter\n");
    for (result, reason, value) in [
        ("accepted", "honored", snap.asserted_identity.accepted),
        (
            "rejected",
            "untrusted_assertor",
            snap.asserted_identity.rejected_untrusted_assertor,
        ),
        (
            "rejected",
            "trust_domain_mismatch",
            snap.asserted_identity.rejected_trust_domain_mismatch,
        ),
        (
            "rejected",
            "unauthenticated_hbone",
            snap.asserted_identity.rejected_unauthenticated_hbone,
        ),
        (
            "rejected",
            "malformed",
            snap.asserted_identity.rejected_malformed,
        ),
        (
            "rejected",
            "stale_or_unknown",
            snap.asserted_identity.rejected_stale_or_unknown,
        ),
    ] {
        output.push_str(&format!(
            "ferrum_mesh_node_waypoint_asserted_identity_total{{result=\"{}\",reason=\"{}\"{}}} {}\n",
            escape_label_value(result),
            escape_label_value(reason),
            gateway_ns_label,
            value
        ));
    }

    output.push_str(
        "# HELP ferrum_mesh_node_waypoint_destination_policy_rejections_total \
Destination-side AuthorizationPolicy / scope / open-relay rejections on \
NodeWaypoint. Distinct from asserted-identity rejections.\n",
    );
    output
        .push_str("# TYPE ferrum_mesh_node_waypoint_destination_policy_rejections_total counter\n");
    for (reason, value) in [
        (
            "authz_deny",
            snap.destination_policy_rejections.authz_deny,
        ),
        (
            "scope_missing",
            snap.destination_policy_rejections.scope_missing,
        ),
        (
            "destination_scope_missing",
            snap.destination_policy_rejections.destination_scope_missing,
        ),
        (
            "relay_destination_denied",
            snap.destination_policy_rejections.relay_destination_denied,
        ),
    ] {
        output.push_str(&format!(
            "ferrum_mesh_node_waypoint_destination_policy_rejections_total{{reason=\"{}\"{}}} {}\n",
            escape_label_value(reason),
            gateway_ns_label,
            value
        ));
    }

    output.push_str(
        "# HELP ferrum_mesh_node_waypoint_missing_destination_metadata_total \
Secured NodeWaypoint service targets skipped because Workload.node_waypoint \
metadata was absent.\n",
    );
    output
        .push_str("# TYPE ferrum_mesh_node_waypoint_missing_destination_metadata_total counter\n");
    render_gauge_like_counter(
        output,
        "ferrum_mesh_node_waypoint_missing_destination_metadata_total",
        snap.missing_destination_metadata,
        gateway_ns_label,
    );

    output.push_str(
        "# HELP ferrum_mesh_node_waypoint_plaintext_fallback_attempts_total \
Prohibited plaintext fallback attempts blocked under identity-backed \
NodeWaypoint (fail-closed instead of retaining a plaintext backend).\n",
    );
    output
        .push_str("# TYPE ferrum_mesh_node_waypoint_plaintext_fallback_attempts_total counter\n");
    render_gauge_like_counter(
        output,
        "ferrum_mesh_node_waypoint_plaintext_fallback_attempts_total",
        snap.plaintext_fallback_attempts,
        gateway_ns_label,
    );
}

fn render_gauge_like_counter(
    output: &mut String,
    name: &str,
    value: u64,
    gateway_ns_label: &str,
) {
    if gateway_ns_label.is_empty() {
        output.push_str(&format!("{name} {value}\n"));
    } else {
        let label_body = gateway_ns_label
            .strip_prefix(',')
            .unwrap_or(gateway_ns_label);
        output.push_str(&format!("{name}{{{label_body}}} {value}\n"));
    }
}
