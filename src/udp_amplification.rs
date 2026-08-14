//! UDP response-amplification budget and fixed-cardinality observability.
//!
//! Accounting is **cumulative per admitted client request**: every backend
//! response datagram charges the same remaining payload-byte budget until the
//! next policy-admitted client datagram resets it. A per-datagram size check
//! is not sufficient — several in-budget replies to one small request would
//! otherwise amplify without bound. A zero-length response still consumes one
//! unit of remaining budget so a finite factor cannot admit an unbounded
//! packet count.
//!
//! Metrics are process-wide and unlabeled except for the Prometheus plugin's
//! own gateway-namespace series. They never carry route, backend, source,
//! factor, or error-text labels.

use std::sync::atomic::{AtomicU64, Ordering};

use crossbeam_utils::CachePadded;

/// Finite controller default projected onto every Gateway API `UDPRoute`
/// listener that has no more specific valid policy.
pub const GATEWAY_API_UDP_AMPLIFICATION_DEFAULT_FACTOR: f32 = 8.0;

/// Inclusive ceiling for a finite amplification factor. Values above this are
/// rejected at admission; protocols that need more must use the explicit
/// unlimited override.
pub const MAX_UDP_AMPLIFICATION_FACTOR: f32 = 1024.0;

/// Ferrum-owned Direct Policy Attachment group.
pub const UDP_AMPLIFICATION_POLICY_GROUP: &str = "gateway.ferrum.io";
/// CRD version watched by the Kubernetes controller.
pub const UDP_AMPLIFICATION_POLICY_VERSION: &str = "v1alpha1";
/// Kind of the Ferrum UDP amplification policy CRD.
pub const UDP_AMPLIFICATION_POLICY_KIND: &str = "UDPResponseAmplificationPolicy";
/// Plural resource name.
pub const UDP_AMPLIFICATION_POLICY_PLURAL: &str = "udpresponseamplificationpolicies";

/// Independently cache-line padded so allowed/drop/policy counters do not
/// false-share on the UDP response path.
static RESPONSES_ALLOWED: CachePadded<AtomicU64> = CachePadded::new(AtomicU64::new(0));
static RESPONSES_DROPPED: CachePadded<AtomicU64> = CachePadded::new(AtomicU64::new(0));
static POLICY_INVALID: CachePadded<AtomicU64> = CachePadded::new(AtomicU64::new(0));
static POLICY_UNLIMITED: CachePadded<AtomicU64> = CachePadded::new(AtomicU64::new(0));

/// Snapshot of the unlabeled amplification counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpAmplificationMetricsSnapshot {
    pub responses_allowed: u64,
    pub responses_dropped: u64,
    pub policy_invalid: u64,
    pub policy_unlimited: u64,
}

/// Process-wide unlabeled counters for Prometheus.
pub fn metrics_snapshot() -> UdpAmplificationMetricsSnapshot {
    UdpAmplificationMetricsSnapshot {
        responses_allowed: RESPONSES_ALLOWED.load(Ordering::Relaxed),
        responses_dropped: RESPONSES_DROPPED.load(Ordering::Relaxed),
        policy_invalid: POLICY_INVALID.load(Ordering::Relaxed),
        policy_unlimited: POLICY_UNLIMITED.load(Ordering::Relaxed),
    }
}

pub fn record_response_allowed() {
    RESPONSES_ALLOWED.fetch_add(1, Ordering::Relaxed);
}

/// Record a dropped response. Returns the new process-wide drop count for
/// rate-limited diagnostics.
pub fn record_response_dropped() -> u64 {
    RESPONSES_DROPPED.fetch_add(1, Ordering::Relaxed) + 1
}

pub fn record_policy_invalid() {
    POLICY_INVALID.fetch_add(1, Ordering::Relaxed);
}

pub fn record_policy_unlimited() {
    POLICY_UNLIMITED.fetch_add(1, Ordering::Relaxed);
}

/// Whether `factor` is an admissible finite amplification ratio.
pub fn factor_is_valid(factor: f32) -> bool {
    factor.is_finite() && factor > 0.0 && factor <= MAX_UDP_AMPLIFICATION_FACTOR
}

/// Maximum response payload allowed by the UDP amplification guard for one
/// admitted client request.
///
/// A zero-length request receives an explicit one-byte reply allowance so the
/// legal datagram does not create a black-holed session. Nonempty requests keep
/// the configured payload ratio exactly. Invalid factors fail closed to a zero
/// budget so no response is forwarded.
pub fn udp_amplification_response_budget(request_size: u64, factor: f32) -> u64 {
    if !factor_is_valid(factor) {
        return 0;
    }
    if request_size == 0 {
        return 1;
    }
    let product = request_size as f64 * f64::from(factor);
    if !product.is_finite() || product < 0.0 {
        0
    } else if product >= u64::MAX as f64 {
        u64::MAX
    } else {
        product as u64
    }
}

/// Reset the remaining response budget for a newly admitted client datagram.
pub fn publish_request_budget(remaining: &AtomicU64, request_size: u64, factor: f32) -> u64 {
    let budget = udp_amplification_response_budget(request_size, factor);
    remaining.store(budget, Ordering::Release);
    budget
}

/// Atomically charge `bytes` against a remaining per-request response budget.
///
/// Nonempty datagrams charge their payload size exactly. A zero-length
/// datagram still consumes one unit so a finite budget cannot admit an
/// unbounded number of empty replies. Returns `true` when the datagram is
/// admitted. The check is fail-closed: insufficient remaining refuses without
/// partial consumption. Several in-budget datagrams still fail closed once
/// their cumulative charge exceeds the request budget.
pub fn charge_response_budget(remaining: &AtomicU64, bytes: u64) -> bool {
    let charge = bytes.max(1);
    loop {
        let current = remaining.load(Ordering::Acquire);
        if current < charge {
            return false;
        }
        match remaining.compare_exchange_weak(
            current,
            current - charge,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return true,
            Err(_) => continue,
        }
    }
}
