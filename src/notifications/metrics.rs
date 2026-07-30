//! Bounded-cardinality notification delivery metrics.
//!
//! Every counter/gauge is labeled only by the fixed [`super::outcome::CHANNEL_TYPES`]
//! set (`slack` / `teams` / `discord` / `webhook` / `email`). Operator-chosen
//! channel *names* and attacker-controlled strings never appear as labels.
//!
//! Process-wide tallies dual-write into authenticated `/metrics` via
//! [`render_prometheus`]. Per-plugin-instance snapshots are available for
//! deterministic external tests through [`DeliveryMetrics::snapshot`].

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use super::outcome::CHANNEL_TYPES;

/// Index into the fixed channel-type arrays. Out-of-range maps to webhook as a
/// defensive fallback so a future discriminant cannot panic hot paths.
#[inline]
fn channel_index(channel_type: &str) -> usize {
    match channel_type {
        "slack" => 0,
        "teams" => 1,
        "discord" => 2,
        "webhook" => 3,
        "email" => 4,
        _ => 3,
    }
}

/// Process-wide delivery counters/gauges keyed by channel type.
#[derive(Debug)]
pub struct DeliveryMetrics {
    attempted: [AtomicU64; 5],
    succeeded: [AtomicU64; 5],
    failed_transient: [AtomicU64; 5],
    failed_permanent: [AtomicU64; 5],
    backpressure_dropped: [AtomicU64; 5],
    abandoned_at_deadline: [AtomicU64; 5],
    in_flight: [AtomicI64; 5],
}

impl Default for DeliveryMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl DeliveryMetrics {
    pub const fn new() -> Self {
        Self {
            attempted: [const { AtomicU64::new(0) }; 5],
            succeeded: [const { AtomicU64::new(0) }; 5],
            failed_transient: [const { AtomicU64::new(0) }; 5],
            failed_permanent: [const { AtomicU64::new(0) }; 5],
            backpressure_dropped: [const { AtomicU64::new(0) }; 5],
            abandoned_at_deadline: [const { AtomicU64::new(0) }; 5],
            in_flight: [const { AtomicI64::new(0) }; 5],
        }
    }

    pub fn record_attempted(&self, channel_type: &str) {
        let i = channel_index(channel_type);
        self.attempted[i].fetch_add(1, Ordering::Relaxed);
        self.in_flight[i].fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_succeeded(&self, channel_type: &str) {
        let i = channel_index(channel_type);
        self.succeeded[i].fetch_add(1, Ordering::Relaxed);
        self.in_flight[i].fetch_sub(1, Ordering::Relaxed);
    }

    pub fn record_failed_transient(&self, channel_type: &str) {
        let i = channel_index(channel_type);
        self.failed_transient[i].fetch_add(1, Ordering::Relaxed);
        self.in_flight[i].fetch_sub(1, Ordering::Relaxed);
    }

    pub fn record_failed_permanent(&self, channel_type: &str) {
        let i = channel_index(channel_type);
        self.failed_permanent[i].fetch_add(1, Ordering::Relaxed);
        self.in_flight[i].fetch_sub(1, Ordering::Relaxed);
    }

    pub fn record_backpressure_dropped(&self, channel_type: &str) {
        let i = channel_index(channel_type);
        self.backpressure_dropped[i].fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_abandoned_at_deadline(&self, channel_type: &str) {
        let i = channel_index(channel_type);
        self.abandoned_at_deadline[i].fetch_add(1, Ordering::Relaxed);
        // Abandonment settles an in-flight attempt that will not call
        // succeeded/failed (task cancelled before settle).
        self.in_flight[i].fetch_sub(1, Ordering::Relaxed);
    }

    /// Plain snapshot for external tests. Values are process-wide unless the
    /// caller constructed an isolated [`DeliveryMetrics`].
    pub fn snapshot(&self) -> DeliveryMetricsSnapshot {
        let mut out = DeliveryMetricsSnapshot::default();
        for (i, kind) in CHANNEL_TYPES.iter().enumerate() {
            out.by_channel[i] = ChannelMetricsSnapshot {
                channel_type: kind,
                attempted: self.attempted[i].load(Ordering::Relaxed),
                succeeded: self.succeeded[i].load(Ordering::Relaxed),
                failed_transient: self.failed_transient[i].load(Ordering::Relaxed),
                failed_permanent: self.failed_permanent[i].load(Ordering::Relaxed),
                backpressure_dropped: self.backpressure_dropped[i].load(Ordering::Relaxed),
                abandoned_at_deadline: self.abandoned_at_deadline[i].load(Ordering::Relaxed),
                in_flight: self.in_flight[i].load(Ordering::Relaxed),
            };
        }
        out
    }

    pub fn channel_snapshot(&self, channel_type: &str) -> ChannelMetricsSnapshot {
        let i = channel_index(channel_type);
        ChannelMetricsSnapshot {
            channel_type: CHANNEL_TYPES[i],
            attempted: self.attempted[i].load(Ordering::Relaxed),
            succeeded: self.succeeded[i].load(Ordering::Relaxed),
            failed_transient: self.failed_transient[i].load(Ordering::Relaxed),
            failed_permanent: self.failed_permanent[i].load(Ordering::Relaxed),
            backpressure_dropped: self.backpressure_dropped[i].load(Ordering::Relaxed),
            abandoned_at_deadline: self.abandoned_at_deadline[i].load(Ordering::Relaxed),
            in_flight: self.in_flight[i].load(Ordering::Relaxed),
        }
    }
}

/// Per-channel-type plain snapshot.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ChannelMetricsSnapshot {
    pub channel_type: &'static str,
    pub attempted: u64,
    pub succeeded: u64,
    pub failed_transient: u64,
    pub failed_permanent: u64,
    pub backpressure_dropped: u64,
    pub abandoned_at_deadline: u64,
    pub in_flight: i64,
}

/// Full process (or test-isolated) snapshot across every channel type.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DeliveryMetricsSnapshot {
    pub by_channel: [ChannelMetricsSnapshot; 5],
}

impl DeliveryMetricsSnapshot {
    pub fn for_channel(&self, channel_type: &str) -> ChannelMetricsSnapshot {
        self.by_channel[channel_index(channel_type)]
    }

    pub fn total_attempted(&self) -> u64 {
        self.by_channel.iter().map(|c| c.attempted).sum()
    }

    pub fn total_backpressure_dropped(&self) -> u64 {
        self.by_channel.iter().map(|c| c.backpressure_dropped).sum()
    }

    pub fn total_abandoned(&self) -> u64 {
        self.by_channel
            .iter()
            .map(|c| c.abandoned_at_deadline)
            .sum()
    }
}

static GLOBAL: OnceLock<Arc<DeliveryMetrics>> = OnceLock::new();

/// Process-wide metrics shared by every notification producer.
pub fn global() -> &'static Arc<DeliveryMetrics> {
    GLOBAL.get_or_init(|| Arc::new(DeliveryMetrics::new()))
}

/// Render Prometheus text for authenticated `/metrics`.
///
/// Always emits the full fixed channel-type series (including zeros) so
/// dashboards and recording rules have a stable contract from first scrape.
pub fn render_prometheus() -> String {
    let m = global();
    let mut out = String::with_capacity(4096);
    render_counter_family(
        &mut out,
        "ferrum_notification_delivery_attempted_total",
        "Notification delivery attempts admitted past the dispatch semaphore (includes retries' parent task once).",
        &m.attempted,
    );
    render_counter_family(
        &mut out,
        "ferrum_notification_delivery_succeeded_total",
        "Notification deliveries that completed successfully (after any bounded retries).",
        &m.succeeded,
    );
    render_counter_family(
        &mut out,
        "ferrum_notification_delivery_failed_transient_total",
        "Notification deliveries that exhausted retries on transient transport/HTTP failures.",
        &m.failed_transient,
    );
    render_counter_family(
        &mut out,
        "ferrum_notification_delivery_failed_permanent_total",
        "Notification deliveries that failed with a permanent (non-retryable) outcome.",
        &m.failed_permanent,
    );
    render_counter_family(
        &mut out,
        "ferrum_notification_delivery_backpressure_dropped_total",
        "Notification deliveries dropped because the bounded dispatch semaphore was exhausted.",
        &m.backpressure_dropped,
    );
    render_counter_family(
        &mut out,
        "ferrum_notification_delivery_abandoned_at_deadline_total",
        "Notification deliveries abandoned when reload retirement or the global shutdown drain deadline cancelled the task.",
        &m.abandoned_at_deadline,
    );
    out.push_str(
        "# HELP ferrum_notification_delivery_in_flight Notification deliveries currently executing (including bounded retry backoff).\n",
    );
    out.push_str("# TYPE ferrum_notification_delivery_in_flight gauge\n");
    for (i, kind) in CHANNEL_TYPES.iter().enumerate() {
        let value = m.in_flight[i].load(Ordering::Relaxed);
        out.push_str(&format!(
            "ferrum_notification_delivery_in_flight{{channel_type=\"{kind}\"}} {value}\n"
        ));
    }
    out
}

fn render_counter_family(out: &mut String, name: &str, help: &str, values: &[AtomicU64; 5]) {
    out.push_str(&format!("# HELP {name} {help}\n"));
    out.push_str(&format!("# TYPE {name} counter\n"));
    for (i, kind) in CHANNEL_TYPES.iter().enumerate() {
        let value = values[i].load(Ordering::Relaxed);
        out.push_str(&format!("{name}{{channel_type=\"{kind}\"}} {value}\n"));
    }
}
