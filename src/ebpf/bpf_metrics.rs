//! Shared counter store for the `__mesh_bpf_metrics` plugin.
//!
//! The eBPF `BPF_PROG_TYPE_SOCK_OPS` program and the `connect4`/`connect6`
//! capture hooks publish per-event records (Connect, AcceptEstablished, Rst,
//! FinSent/Received, RttSample, drop-reason hits) over a per-CPU ringbuf. The
//! userspace consumer (`event_consumer.rs`) drains the ringbuf and increments
//! the counters here; the [`crate::plugins::mesh::bpf_metrics`] plugin reads
//! from the same state and emits Prometheus metrics. This decoupling means the
//! plugin's hot/cold path doesn't touch the BPF maps directly and doesn't need
//! `aya` linked into every build.
//!
//! ## Concurrency
//!
//! All counters are `AtomicU64` with `Ordering::Relaxed` — these are
//! cumulative monotonically-increasing counters with no causal ordering
//! across counters, matching the same shape as `OverloadState` snapshot
//! fields. Atomics on the event-consumer hot path are wrapped in
//! `crossbeam_utils::CachePadded` so per-CPU consumer threads don't
//! coherence-traffic each other through a shared cache line.
//!
//! ## Latency histograms
//!
//! SRTT and SYN→ACK samples keep the historical `_sum`/`_count` series and
//! additionally maintain fixed exclusive bucket counters
//! ([`BPF_LATENCY_BUCKET_BOUNDS_US`] plus an implicit `+Inf` slot). Observe
//! cost is three atomics (checked sum CAS, count, one exclusive bucket) with
//! no locks, allocations, or per-flow labels. Zero samples are ignored;
//! samples that would overflow `u64` sum are dropped entirely.
//!
//! ## Ringbuf overrun handling
//!
//! [`BpfMetricsState::record_ringbuf_overrun`] increments `ringbuf_overruns`
//! AND tracks a one-shot state-transition so the consumer can emit a
//! `warn!` exactly once when the system enters an overrun regime and an
//! `info!` exactly once when it recovers — mirroring the overload manager
//! pattern (warn enter, info recover, no per-event spam). This is the
//! "silent drops would be a regression" guard from the GAP-SC3 plan.

#![allow(dead_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crossbeam_utils::CachePadded;

/// Inclusive upper bounds (`le`) for TCP-layer latency histograms, in
/// microseconds. Stable, low-cardinality contract shared by SRTT and
/// SYN→ACK. Samples strictly greater than the last bound land in `+Inf`.
pub const BPF_LATENCY_BUCKET_BOUNDS_US: [u64; 15] = [
    100, 250, 500, 1_000, 2_500, 5_000, 10_000, 25_000, 50_000, 100_000, 250_000, 500_000,
    1_000_000, 2_500_000, 5_000_000,
];

/// Number of finite latency buckets (excludes the `+Inf` slot).
pub const BPF_LATENCY_FINITE_BUCKET_COUNT: usize = BPF_LATENCY_BUCKET_BOUNDS_US.len();

/// Exclusive bucket slots: one per finite bound, plus one for `+Inf`.
pub const BPF_LATENCY_EXCLUSIVE_BUCKET_COUNT: usize = BPF_LATENCY_FINITE_BUCKET_COUNT + 1;

/// Prometheus `le` label strings for [`BPF_LATENCY_BUCKET_BOUNDS_US`].
pub const BPF_LATENCY_BUCKET_LE_LABELS: [&str; BPF_LATENCY_FINITE_BUCKET_COUNT] = [
    "100", "250", "500", "1000", "2500", "5000", "10000", "25000", "50000", "100000", "250000",
    "500000", "1000000", "2500000", "5000000",
];

/// Index into the exclusive-bucket array for a latency sample in microseconds.
///
/// Returns `0..BPF_LATENCY_FINITE_BUCKET_COUNT` for finite buckets and
/// [`BPF_LATENCY_FINITE_BUCKET_COUNT`] for the `+Inf` overflow slot.
#[inline]
pub fn bpf_latency_exclusive_bucket_index(us: u64) -> usize {
    for (i, &bound) in BPF_LATENCY_BUCKET_BOUNDS_US.iter().enumerate() {
        if us <= bound {
            return i;
        }
    }
    BPF_LATENCY_FINITE_BUCKET_COUNT
}

/// Fold exclusive bucket counts into Prometheus cumulative `le` counts.
#[inline]
pub fn bpf_latency_cumulative_from_exclusive(
    exclusive: &[u64; BPF_LATENCY_EXCLUSIVE_BUCKET_COUNT],
) -> [u64; BPF_LATENCY_FINITE_BUCKET_COUNT] {
    let mut out = [0u64; BPF_LATENCY_FINITE_BUCKET_COUNT];
    let mut cum = 0u64;
    for i in 0..BPF_LATENCY_FINITE_BUCKET_COUNT {
        cum = cum.saturating_add(exclusive[i]);
        out[i] = cum;
    }
    out
}

/// One BPF drop reason from the data path. Each variant maps to a
/// kernel-side decision the connect hooks logged before redirecting (or
/// not) the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BpfDropReason {
    /// Connection bypassed because the source UID was in the bypass set
    /// (typically the proxy's own UID — recursion prevention).
    BypassUidHit,
    /// Connection bypassed because the destination IP fell into an
    /// operator-configured exclude CIDR.
    ExcludeCidrHit,
    /// Connection bypassed because the destination was outside the include
    /// CIDR / includeOutboundPorts filter (capture is opt-in per policy).
    NotInIncludeCidr,
    /// Connection bypassed because the destination port was in the
    /// operator-configured port exclude set.
    ExcludePortHit,
}

impl BpfDropReason {
    pub fn label(self) -> &'static str {
        match self {
            Self::BypassUidHit => "bypass_uid_hit",
            Self::ExcludeCidrHit => "exclude_cidr_hit",
            Self::NotInIncludeCidr => "not_in_include_cidr",
            Self::ExcludePortHit => "exclude_port_hit",
        }
    }
}

/// Operator-visible counters published by the SOCK_OPS event consumer.
///
/// Held inside an `Arc` so the consumer task and the plugin can share
/// access without cloning. All fields are read concurrently with writes,
/// hence the `CachePadded` wrapping on the consumer-hot ones (`connect`,
/// `accept_established`, `rtt_sample` are the highest-volume events).
#[derive(Default)]
pub struct BpfMetricsState {
    // Connection lifecycle counters
    pub connect: CachePadded<AtomicU64>,
    pub accept_established: CachePadded<AtomicU64>,
    /// Abnormal ESTABLISHED→CLOSE transitions. Direction is not attributed
    /// by the kernel SOCK_OPS state callback (see mesh docs).
    pub rst: AtomicU64,
    pub fin_sent: AtomicU64,
    pub fin_received: AtomicU64,

    // Latency samples (TCP-layer only).
    //
    // Sum + count preserve the historical mean-derivation contract.
    // Exclusive bucket counters feed Prometheus histogram exposition
    // (cumulative at scrape time). Accept-to-first-byte remains absent:
    // SOCK_OPS has no first-inbound-data-byte callback.
    pub srtt_sample_us_sum: AtomicU64,
    pub srtt_count: CachePadded<AtomicU64>,
    pub srtt_bucket_exclusive: [CachePadded<AtomicU64>; BPF_LATENCY_EXCLUSIVE_BUCKET_COUNT],
    pub syn_to_ack_us_sum: AtomicU64,
    pub syn_to_ack_count: AtomicU64,
    pub syn_to_ack_bucket_exclusive: [CachePadded<AtomicU64>; BPF_LATENCY_EXCLUSIVE_BUCKET_COUNT],

    // BPF drop-reason counters — one bin per reason. Produced by the
    // connect4/connect6 bypass paths via the shared ringbuf.
    pub drop_bypass_uid_hit: AtomicU64,
    pub drop_exclude_cidr_hit: AtomicU64,
    pub drop_not_in_include_cidr: AtomicU64,
    pub drop_exclude_port_hit: AtomicU64,

    // Ringbuf health
    pub ringbuf_events_consumed: AtomicU64,
    pub ringbuf_overruns: AtomicU64,
    /// True while we believe we're in an overrun regime. The consumer
    /// flips this on the first overrun and back off only after the
    /// recovery threshold is met. Used to suppress per-event log spam.
    in_overrun_regime: AtomicBool,
}

impl BpfMetricsState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn record_connect(&self) {
        self.connect.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_accept_established(&self) {
        self.accept_established.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_rst(&self) {
        self.rst.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_fin(&self, direction: TcpDirection) {
        match direction {
            TcpDirection::Sent => self.fin_sent.fetch_add(1, Ordering::Relaxed),
            TcpDirection::Received => self.fin_received.fetch_add(1, Ordering::Relaxed),
        };
    }

    pub fn record_srtt_sample(&self, srtt_us: u64) {
        observe_latency(
            &self.srtt_sample_us_sum,
            &self.srtt_bucket_exclusive,
            srtt_us,
            || {
                self.srtt_count.fetch_add(1, Ordering::Relaxed);
            },
        );
    }

    pub fn record_syn_to_ack(&self, us: u64) {
        observe_latency(
            &self.syn_to_ack_us_sum,
            &self.syn_to_ack_bucket_exclusive,
            us,
            || {
                self.syn_to_ack_count.fetch_add(1, Ordering::Relaxed);
            },
        );
    }

    pub fn record_drop(&self, reason: BpfDropReason) {
        let target = match reason {
            BpfDropReason::BypassUidHit => &self.drop_bypass_uid_hit,
            BpfDropReason::ExcludeCidrHit => &self.drop_exclude_cidr_hit,
            BpfDropReason::NotInIncludeCidr => &self.drop_not_in_include_cidr,
            BpfDropReason::ExcludePortHit => &self.drop_exclude_port_hit,
        };
        target.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_ringbuf_event(&self) {
        self.ringbuf_events_consumed.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment ringbuf-overrun counter and report whether this is the
    /// first overrun in the current regime (call this once per detected
    /// overrun event from the consumer task). Returns `true` exactly once
    /// per entry into an overrun regime, allowing the caller to emit a
    /// single `warn!` line.
    pub fn record_ringbuf_overrun(&self) -> bool {
        self.ringbuf_overruns.fetch_add(1, Ordering::Relaxed);
        // compare_exchange returns Ok if we successfully flipped false→true,
        // i.e., we just entered the overrun regime.
        self.in_overrun_regime
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// Reset the overrun regime flag. Returns `true` exactly once per
    /// recovery (i.e., when the flag flips true→false), allowing the
    /// caller to emit a single `info!` recovery line.
    pub fn mark_ringbuf_recovered(&self) -> bool {
        self.in_overrun_regime
            .compare_exchange(true, false, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// `true` while at least one overrun has been recorded and the
    /// consumer hasn't observed recovery yet.
    pub fn is_in_overrun_regime(&self) -> bool {
        self.in_overrun_regime.load(Ordering::Acquire)
    }

    /// Cold-path snapshot used by the plugin to emit Prometheus metrics.
    pub fn snapshot(&self) -> BpfMetricsSnapshot {
        BpfMetricsSnapshot {
            connect: self.connect.load(Ordering::Relaxed),
            accept_established: self.accept_established.load(Ordering::Relaxed),
            rst: self.rst.load(Ordering::Relaxed),
            fin_sent: self.fin_sent.load(Ordering::Relaxed),
            fin_received: self.fin_received.load(Ordering::Relaxed),
            srtt_sample_us_sum: self.srtt_sample_us_sum.load(Ordering::Relaxed),
            srtt_count: self.srtt_count.load(Ordering::Relaxed),
            srtt_bucket_exclusive: load_exclusive_buckets(&self.srtt_bucket_exclusive),
            syn_to_ack_us_sum: self.syn_to_ack_us_sum.load(Ordering::Relaxed),
            syn_to_ack_count: self.syn_to_ack_count.load(Ordering::Relaxed),
            syn_to_ack_bucket_exclusive: load_exclusive_buckets(&self.syn_to_ack_bucket_exclusive),
            drop_bypass_uid_hit: self.drop_bypass_uid_hit.load(Ordering::Relaxed),
            drop_exclude_cidr_hit: self.drop_exclude_cidr_hit.load(Ordering::Relaxed),
            drop_not_in_include_cidr: self.drop_not_in_include_cidr.load(Ordering::Relaxed),
            drop_exclude_port_hit: self.drop_exclude_port_hit.load(Ordering::Relaxed),
            ringbuf_events_consumed: self.ringbuf_events_consumed.load(Ordering::Relaxed),
            ringbuf_overruns: self.ringbuf_overruns.load(Ordering::Relaxed),
            in_overrun_regime: self.in_overrun_regime.load(Ordering::Acquire),
        }
    }
}

/// Record one latency sample into sum/count/exclusive buckets.
///
/// - `us == 0` is treated as invalid and ignored (no sum/count/bucket update).
/// - Samples that would overflow the `u64` sum are dropped entirely.
/// - Otherwise: checked sum CAS, then `bump_count`, then one exclusive bucket++.
fn observe_latency(
    sum: &AtomicU64,
    exclusive: &[CachePadded<AtomicU64>; BPF_LATENCY_EXCLUSIVE_BUCKET_COUNT],
    us: u64,
    bump_count: impl FnOnce(),
) {
    if us == 0 {
        return;
    }
    loop {
        let old = sum.load(Ordering::Relaxed);
        let Some(new) = old.checked_add(us) else {
            // Deterministic overflow handling: drop the sample rather than
            // wrap the sum (which would corrupt mean derivation).
            return;
        };
        match sum.compare_exchange_weak(old, new, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(_) => continue,
        }
    }
    bump_count();
    exclusive[bpf_latency_exclusive_bucket_index(us)].fetch_add(1, Ordering::Relaxed);
}

fn load_exclusive_buckets(
    exclusive: &[CachePadded<AtomicU64>; BPF_LATENCY_EXCLUSIVE_BUCKET_COUNT],
) -> [u64; BPF_LATENCY_EXCLUSIVE_BUCKET_COUNT] {
    let mut out = [0u64; BPF_LATENCY_EXCLUSIVE_BUCKET_COUNT];
    for (i, slot) in exclusive.iter().enumerate() {
        out[i] = slot.load(Ordering::Relaxed);
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpDirection {
    Sent,
    Received,
}

/// Cold-path snapshot of [`BpfMetricsState`]. Cheaper to pass around than
/// the live state when emitting metrics so that the plugin doesn't hold
/// `Arc<BpfMetricsState>` across an await.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BpfMetricsSnapshot {
    pub connect: u64,
    pub accept_established: u64,
    pub rst: u64,
    pub fin_sent: u64,
    pub fin_received: u64,
    pub srtt_sample_us_sum: u64,
    pub srtt_count: u64,
    pub srtt_bucket_exclusive: [u64; BPF_LATENCY_EXCLUSIVE_BUCKET_COUNT],
    pub syn_to_ack_us_sum: u64,
    pub syn_to_ack_count: u64,
    pub syn_to_ack_bucket_exclusive: [u64; BPF_LATENCY_EXCLUSIVE_BUCKET_COUNT],
    pub drop_bypass_uid_hit: u64,
    pub drop_exclude_cidr_hit: u64,
    pub drop_not_in_include_cidr: u64,
    pub drop_exclude_port_hit: u64,
    pub ringbuf_events_consumed: u64,
    pub ringbuf_overruns: u64,
    pub in_overrun_regime: bool,
}

impl BpfMetricsSnapshot {
    pub fn drop_by_reason(&self, reason: BpfDropReason) -> u64 {
        match reason {
            BpfDropReason::BypassUidHit => self.drop_bypass_uid_hit,
            BpfDropReason::ExcludeCidrHit => self.drop_exclude_cidr_hit,
            BpfDropReason::NotInIncludeCidr => self.drop_not_in_include_cidr,
            BpfDropReason::ExcludePortHit => self.drop_exclude_port_hit,
        }
    }

    pub fn drop_reasons(&self) -> [(BpfDropReason, u64); 4] {
        [
            (BpfDropReason::BypassUidHit, self.drop_bypass_uid_hit),
            (BpfDropReason::ExcludeCidrHit, self.drop_exclude_cidr_hit),
            (
                BpfDropReason::NotInIncludeCidr,
                self.drop_not_in_include_cidr,
            ),
            (BpfDropReason::ExcludePortHit, self.drop_exclude_port_hit),
        ]
    }

    /// Cumulative `le` bucket counts for SRTT (finite bounds only).
    pub fn srtt_cumulative_buckets(&self) -> [u64; BPF_LATENCY_FINITE_BUCKET_COUNT] {
        bpf_latency_cumulative_from_exclusive(&self.srtt_bucket_exclusive)
    }

    /// Cumulative `le` bucket counts for SYN→ACK (finite bounds only).
    pub fn syn_to_ack_cumulative_buckets(&self) -> [u64; BPF_LATENCY_FINITE_BUCKET_COUNT] {
        bpf_latency_cumulative_from_exclusive(&self.syn_to_ack_bucket_exclusive)
    }
}
