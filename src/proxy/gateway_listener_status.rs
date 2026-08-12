//! Shared, bounded realization status for dynamic Gateway API listener ports
//! (issue #3810).
//!
//! [`crate::proxy::gateway_listener::GatewayListenerManager`] binds one socket
//! per Gateway API listener port and deliberately never dies over a port it
//! cannot bind: routing for that port fails closed, every healthy listener
//! keeps serving, and the bind is retried on a slow tick. That availability
//! policy is correct, but on its own it makes a partial outage invisible — the
//! process stays green while a configured listener has never bound or has died
//! after startup.
//!
//! This module is the observability consumer of that state. It owns one
//! atomically replaced snapshot that both the authenticated `/health` detail
//! and the Prometheus renderer read lock-free:
//!
//! * **Structured, not free-form.** Every entry carries the affected port, the
//!   protocol half ([`GatewayListenerProtocolHalf`] — TCP and QUIC fail
//!   independently), a bounded [`GatewayListenerFailureCategory`], whether the
//!   listener was refused at admission or failed at runtime
//!   ([`GatewayListenerFailureOrigin`]), the config generation that decided it,
//!   first/last observation timestamps, and how many consecutive reconcile
//!   passes have observed it.
//! * **Bounded.** At most [`MAX_TRACKED_FAILURES`] entries are retained (the
//!   configured listener set is itself bounded, but the cap is unconditional)
//!   and each `detail` string is sanitized to printable ASCII and truncated to
//!   [`MAX_DETAIL_CHARS`]. Counters still account for everything that was
//!   observed, so truncation loses per-port detail and never loses the signal.
//! * **Generation-fenced.** [`GatewayListenerStatus::publish`] refuses a
//!   publication whose config generation is older than the one already
//!   published, mirroring
//!   `ProxyState::publish_gateway_listener_admission`. A reconcile pass that
//!   awaited socket retirement while a newer config was published can therefore
//!   never overwrite the newer generation's status.
//! * **Recoverable.** A failure that is absent from the next publication is
//!   cleared from the snapshot and counted in
//!   `ferrum_gateway_listener_recoveries_total`. This is deliberately *not*
//!   [`crate::startup::ServingListenerFailures`], whose entries are sticky:
//!   that surface exists for fatal post-start serve-task exits, while a Gateway
//!   listener bind failure is retried every 30 s and must clear on its own.
//!
//! # What is never published here
//!
//! Prometheus labels come only from the two closed enums below. Port, listener
//! name, hostname, config generation, and error text are per-entry status
//! detail on the **authenticated** `/health` tier — never a metric label and
//! never part of an unauthenticated response body.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use arc_swap::ArcSwap;

/// Hard cap on retained per-listener failure entries.
///
/// The desired listener set already bounds this in practice; the cap is the
/// unconditional guarantee that a hostile or pathological configuration cannot
/// grow the snapshot without limit.
pub const MAX_TRACKED_FAILURES: usize = 64;

/// Hard cap on the sanitized `detail` retained for one entry.
pub const MAX_DETAIL_CHARS: usize = 200;

/// Which protocol half of a Gateway listener port a failure applies to.
///
/// A TLS-class listener owns a TCP socket and, when HTTP/3 is enabled, a QUIC
/// socket on the same numeric port. They fail independently: a QUIC bind
/// failure leaves HTTP/1.1 and HTTP/2 serving on the TCP half, and reporting it
/// as a listener-wide outage would be wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewayListenerProtocolHalf {
    Tcp,
    Quic,
}

impl GatewayListenerProtocolHalf {
    /// Every protocol half, in metric-label order.
    pub const ALL: [Self; 2] = [Self::Tcp, Self::Quic];

    /// Fixed-cardinality metric label value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Quic => "quic",
        }
    }
}

/// Bounded reason a Gateway listener port (or one protocol half of it) is not
/// serving.
///
/// Closed set: these are the only values that ever reach a Prometheus label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewayListenerFailureCategory {
    /// The port is reserved by another Ferrum listener (proxy / admin /
    /// control-plane gRPC / capture).
    PortReserved,
    /// A process-global proxy frontend already owns the port with the other
    /// TLS class, so the Gateway listener cannot be served from it.
    ProcessGlobalClassMismatch,
    /// A TCP/TLS stream proxy in the same config claims the port.
    StreamPortCollision,
    /// A UDP/DTLS stream proxy in the same config claims the port, so the
    /// TLS-class listener's QUIC socket is refused.
    UdpStreamCollision,
    /// Two HTTP-family proxies claim the port with different TLS classes.
    ClassConflict,
    /// A TLS-terminating listener was declared without frontend TLS material.
    FrontendTlsMissing,
    /// The OS refused the bind (address in use, missing `CAP_NET_BIND_SERVICE`,
    /// unavailable address).
    BindFailed,
    /// A listener task that had bound successfully later exited — cleanly, with
    /// an error, or by panic — and the port is being rebound.
    ListenerTaskEnded,
    /// A previous generation of this port has not finished closing its accept
    /// sockets, so the replacement bind is deferred fail-closed.
    RetirementPending,
}

impl GatewayListenerFailureCategory {
    /// Every category, in metric-label order.
    pub const ALL: [Self; 9] = [
        Self::PortReserved,
        Self::ProcessGlobalClassMismatch,
        Self::StreamPortCollision,
        Self::UdpStreamCollision,
        Self::ClassConflict,
        Self::FrontendTlsMissing,
        Self::BindFailed,
        Self::ListenerTaskEnded,
        Self::RetirementPending,
    ];

    /// Fixed-cardinality metric label value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PortReserved => "port_reserved",
            Self::ProcessGlobalClassMismatch => "process_global_class_mismatch",
            Self::StreamPortCollision => "stream_port_collision",
            Self::UdpStreamCollision => "udp_stream_collision",
            Self::ClassConflict => "class_conflict",
            Self::FrontendTlsMissing => "frontend_tls_missing",
            Self::BindFailed => "bind_failed",
            Self::ListenerTaskEnded => "listener_task_ended",
            Self::RetirementPending => "retirement_pending",
        }
    }

    /// Whether the listener was refused before any socket was attempted
    /// (configuration/admission) or failed while realizing it (runtime).
    ///
    /// Operators act on these differently: an admission refusal is repaired in
    /// the configuration, a runtime failure is repaired in the environment.
    pub fn origin(self) -> GatewayListenerFailureOrigin {
        match self {
            Self::PortReserved
            | Self::ProcessGlobalClassMismatch
            | Self::StreamPortCollision
            | Self::UdpStreamCollision
            | Self::ClassConflict
            | Self::FrontendTlsMissing => GatewayListenerFailureOrigin::Admission,
            Self::BindFailed | Self::ListenerTaskEnded | Self::RetirementPending => {
                GatewayListenerFailureOrigin::Runtime
            }
        }
    }

    fn index(self) -> usize {
        match self {
            Self::PortReserved => 0,
            Self::ProcessGlobalClassMismatch => 1,
            Self::StreamPortCollision => 2,
            Self::UdpStreamCollision => 3,
            Self::ClassConflict => 4,
            Self::FrontendTlsMissing => 5,
            Self::BindFailed => 6,
            Self::ListenerTaskEnded => 7,
            Self::RetirementPending => 8,
        }
    }
}

/// Whether a listener is administratively refused or failed at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewayListenerFailureOrigin {
    Admission,
    Runtime,
}

/// One failure observed during a reconcile pass, before it is merged with the
/// previous snapshot's first-seen / occurrence history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayListenerFailureObservation {
    pub port: u16,
    pub protocol: GatewayListenerProtocolHalf,
    pub category: GatewayListenerFailureCategory,
    pub detail: String,
}

impl GatewayListenerFailureObservation {
    pub fn new(
        port: u16,
        protocol: GatewayListenerProtocolHalf,
        category: GatewayListenerFailureCategory,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            port,
            protocol,
            category,
            detail: detail.into(),
        }
    }

    fn key(&self) -> FailureKey {
        (self.port, self.protocol, self.category)
    }
}

/// A currently-active Gateway listener failure, as published to authenticated
/// observability surfaces.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GatewayListenerFailureEntry {
    pub port: u16,
    pub protocol: GatewayListenerProtocolHalf,
    pub category: GatewayListenerFailureCategory,
    pub origin: GatewayListenerFailureOrigin,
    /// Config generation whose reconcile last observed this failure.
    pub config_generation: u64,
    /// Sanitized, bounded diagnostic. Never a secret; never a metric label.
    pub detail: String,
    pub first_observed_unix_ms: u64,
    pub last_observed_unix_ms: u64,
    /// Consecutive reconcile/retry passes that have observed this failure.
    pub observations: u64,
}

/// Active count for one (protocol, category) pair. Fixed cardinality.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GatewayListenerActiveCategory {
    pub protocol: GatewayListenerProtocolHalf,
    pub category: GatewayListenerFailureCategory,
    pub count: u64,
}

/// Bounded realization status for the dynamic Gateway listener set.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct GatewayListenerStatusSnapshot {
    /// Config generation this status was decided for.
    pub config_generation: u64,
    /// Gateway listener ports the published config asked this process to bind.
    pub desired_listeners: usize,
    /// Gateway listener ports with a live TCP accept loop right now.
    pub active_listeners: usize,
    /// Distinct ports carrying at least one active failure.
    pub failed_ports: usize,
    /// Active failure entries, counting entries dropped by the retention cap.
    pub active_failures: usize,
    /// Entries actually retained in `failures`.
    pub retained_failures: usize,
    /// Whether `failures` was truncated by [`MAX_TRACKED_FAILURES`].
    pub truncated: bool,
    /// Active counts by bounded (protocol, category), never truncated.
    pub active_by_category: Vec<GatewayListenerActiveCategory>,
    pub failures: Vec<GatewayListenerFailureEntry>,
}

impl GatewayListenerStatusSnapshot {
    /// Whether any dynamic Gateway listener is currently not serving.
    pub fn degraded(&self) -> bool {
        self.active_failures > 0
    }
}

/// One cumulative counter series, keyed by the two closed label sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GatewayListenerCounter {
    pub protocol: GatewayListenerProtocolHalf,
    pub category: GatewayListenerFailureCategory,
    pub value: u64,
}

/// Cumulative counter view for the Prometheus renderer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GatewayListenerCumulativeMetrics {
    /// Every non-zero cumulative failure series.
    pub failures_total: Vec<GatewayListenerCounter>,
    /// Every non-zero cumulative recovery series.
    pub recoveries_total: Vec<GatewayListenerCounter>,
}

/// Snapshot key: one failure is identified by port, protocol half, and reason.
type FailureKey = (u16, GatewayListenerProtocolHalf, GatewayListenerFailureCategory);

const PROTOCOL_COUNT: usize = GatewayListenerProtocolHalf::ALL.len();
const CATEGORY_COUNT: usize = GatewayListenerFailureCategory::ALL.len();

type CounterGrid = [[AtomicU64; CATEGORY_COUNT]; PROTOCOL_COUNT];

fn protocol_index(protocol: GatewayListenerProtocolHalf) -> usize {
    match protocol {
        GatewayListenerProtocolHalf::Tcp => 0,
        GatewayListenerProtocolHalf::Quic => 1,
    }
}

fn bump(
    grid: &CounterGrid,
    protocol: GatewayListenerProtocolHalf,
    category: GatewayListenerFailureCategory,
) {
    grid[protocol_index(protocol)][category.index()].fetch_add(1, Ordering::Relaxed);
}

fn read(
    grid: &CounterGrid,
    protocol: GatewayListenerProtocolHalf,
    category: GatewayListenerFailureCategory,
) -> u64 {
    grid[protocol_index(protocol)][category.index()].load(Ordering::Relaxed)
}

/// Shared, atomically replaced Gateway listener realization status.
///
/// One instance is owned by the mode, handed to the listener manager as its
/// publisher and to `AdminState` as a reader. Reads are lock-free `ArcSwap`
/// loads so an unauthenticated `/health` probe flood cannot drive work or
/// contend with a reconcile.
#[derive(Debug)]
pub struct GatewayListenerStatus {
    snapshot: ArcSwap<GatewayListenerStatusSnapshot>,
    /// `config_generation + 1`; `0` means "nothing published yet". Biased so
    /// generation `0` is still distinguishable from the initial state.
    published_generation: AtomicU64,
    /// Serializes the read-modify-write of `snapshot` during a publication.
    /// Never held by a reader.
    publish_lock: Mutex<()>,
    failures_total: CounterGrid,
    recoveries_total: CounterGrid,
}

impl Default for GatewayListenerStatus {
    fn default() -> Self {
        Self::new()
    }
}

impl GatewayListenerStatus {
    pub fn new() -> Self {
        Self {
            snapshot: ArcSwap::from_pointee(GatewayListenerStatusSnapshot::default()),
            published_generation: AtomicU64::new(0),
            publish_lock: Mutex::new(()),
            failures_total: Default::default(),
            recoveries_total: Default::default(),
        }
    }

    /// Lock-free current status.
    pub fn snapshot(&self) -> Arc<GatewayListenerStatusSnapshot> {
        self.snapshot.load_full()
    }

    /// Cumulative failure/recovery counters, non-zero entries only.
    pub fn cumulative(&self) -> GatewayListenerCumulativeMetrics {
        let mut failures_total = Vec::new();
        let mut recoveries_total = Vec::new();
        for protocol in GatewayListenerProtocolHalf::ALL {
            for category in GatewayListenerFailureCategory::ALL {
                let failures = read(&self.failures_total, protocol, category);
                if failures > 0 {
                    failures_total.push(GatewayListenerCounter {
                        protocol,
                        category,
                        value: failures,
                    });
                }
                let recoveries = read(&self.recoveries_total, protocol, category);
                if recoveries > 0 {
                    recoveries_total.push(GatewayListenerCounter {
                        protocol,
                        category,
                        value: recoveries,
                    });
                }
            }
        }
        GatewayListenerCumulativeMetrics {
            failures_total,
            recoveries_total,
        }
    }

    /// Publish the realization status decided for `config_generation`.
    ///
    /// Returns `false` — changing nothing at all — when `config_generation` is
    /// older than the generation already published. A reconcile pass that
    /// awaited socket retirement can finish after a newer config was published;
    /// its decision must never govern the newer generation's status, exactly as
    /// its route admission decision must not.
    ///
    /// An equal generation is accepted: the supervisor re-reconciles the same
    /// generation on every retry tick, and that is how a recovery clears.
    pub fn publish(
        &self,
        config_generation: u64,
        desired_listeners: usize,
        active_listeners: usize,
        observations: Vec<GatewayListenerFailureObservation>,
        now_unix_ms: u64,
    ) -> bool {
        let fence = config_generation.saturating_add(1);
        loop {
            let current = self.published_generation.load(Ordering::Acquire);
            if fence < current {
                return false;
            }
            if self
                .published_generation
                .compare_exchange(current, fence, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                break;
            }
        }

        // The manager already serializes reconcile passes, but the snapshot
        // merge is a read-modify-write over first-seen/occurrence history and
        // over the cumulative counters: keep it atomic against any other
        // publisher rather than relying on a caller-side invariant.
        let _guard = match self.publish_lock.lock() {
            Ok(guard) => guard,
            // A panicking publisher cannot corrupt the snapshot (it is replaced
            // wholesale), so recover rather than propagating the poison into an
            // observability path.
            Err(poisoned) => poisoned.into_inner(),
        };

        let previous = self.snapshot.load_full();
        let mut retained: BTreeMap<FailureKey, &GatewayListenerFailureEntry> = BTreeMap::new();
        for entry in &previous.failures {
            retained.insert((entry.port, entry.protocol, entry.category), entry);
        }

        let mut entries: BTreeMap<FailureKey, GatewayListenerFailureEntry> = BTreeMap::new();
        for observation in observations {
            let key = observation.key();
            if entries.contains_key(&key) {
                // One pass can legitimately record the same port twice (for
                // example a dead-task reap followed by a rebind failure). Keep
                // the first detail and do not double-count the occurrence.
                continue;
            }
            let (first_observed_unix_ms, observations_count) = match retained.get(&key) {
                Some(previous_entry) => (
                    previous_entry.first_observed_unix_ms,
                    previous_entry.observations.saturating_add(1),
                ),
                None => {
                    let protocol = observation.protocol;
                    bump(&self.failures_total, protocol, observation.category);
                    (now_unix_ms, 1)
                }
            };
            entries.insert(
                key,
                GatewayListenerFailureEntry {
                    port: observation.port,
                    protocol: observation.protocol,
                    category: observation.category,
                    origin: observation.category.origin(),
                    config_generation,
                    detail: sanitize_detail(&observation.detail),
                    first_observed_unix_ms,
                    last_observed_unix_ms: now_unix_ms,
                    observations: observations_count,
                },
            );
        }

        // Anything that was failing and is not observed now has recovered.
        for (key, entry) in &retained {
            if entries.contains_key(key) {
                continue;
            }
            bump(&self.recoveries_total, entry.protocol, entry.category);
        }

        let active_failures = entries.len();
        let mut failed_ports: Vec<u16> = entries.keys().map(|(port, _, _)| *port).collect();
        failed_ports.dedup();
        let mut active_counts = [[0u64; CATEGORY_COUNT]; PROTOCOL_COUNT];
        for entry in entries.values() {
            active_counts[protocol_index(entry.protocol)][entry.category.index()] += 1;
        }
        let mut active_by_category: Vec<GatewayListenerActiveCategory> = Vec::new();
        for protocol in GatewayListenerProtocolHalf::ALL {
            for category in GatewayListenerFailureCategory::ALL {
                let count = active_counts[protocol_index(protocol)][category.index()];
                if count > 0 {
                    active_by_category.push(GatewayListenerActiveCategory {
                        protocol,
                        category,
                        count,
                    });
                }
            }
        }

        let mut failures: Vec<GatewayListenerFailureEntry> = entries.into_values().collect();
        let truncated = failures.len() > MAX_TRACKED_FAILURES;
        failures.truncate(MAX_TRACKED_FAILURES);

        self.snapshot.store(Arc::new(GatewayListenerStatusSnapshot {
            config_generation,
            desired_listeners,
            active_listeners,
            failed_ports: failed_ports.len(),
            active_failures,
            retained_failures: failures.len(),
            truncated,
            active_by_category,
            failures,
        }));
        true
    }
}

/// The installed process-wide Gateway listener status, if this mode binds
/// dynamic Gateway listeners.
static GLOBAL: OnceLock<Arc<GatewayListenerStatus>> = OnceLock::new();

/// Publish this mode's status on the process-wide `/metrics` slot.
///
/// The authoritative handle is the `Arc` the mode owns: it is what the manager
/// publishes to and what `AdminState` reads for `/health`, so a process running
/// more than one serving runtime (a test binary) still gets per-instance health
/// detail. `/metrics` is inherently process-wide, so this slot is
/// first-writer-wins and is never re-pointed — exactly like
/// [`crate::dp_config_freshness::install`], which likewise must not be
/// swapped out from under an already-scraping process.
pub fn install_for_metrics(status: &Arc<GatewayListenerStatus>) {
    let _ = GLOBAL.set(status.clone());
}

/// The installed process-wide status, if any.
pub fn global() -> Option<&'static Arc<GatewayListenerStatus>> {
    GLOBAL.get()
}

/// Wall-clock milliseconds for a status observation.
///
/// Production timestamps only; the merge itself takes the clock as an argument
/// so tests are deterministic.
pub fn now_unix_ms() -> u64 {
    chrono::Utc::now().timestamp_millis().max(0) as u64
}

/// Bound and sanitize a diagnostic before it is retained.
///
/// Gateway listener errors are gateway-authored text plus OS error strings, but
/// this is a durable operator-visible surface: strip anything that is not
/// printable ASCII (control characters would corrupt a log or terminal render)
/// and cap the length so a pathological error cannot grow the snapshot.
fn sanitize_detail(detail: &str) -> String {
    let mut out = String::with_capacity(detail.len().min(MAX_DETAIL_CHARS + 3));
    let mut kept = 0usize;
    for ch in detail.chars() {
        if kept >= MAX_DETAIL_CHARS {
            out.push_str("...");
            break;
        }
        if ch == ' ' || ch.is_ascii_graphic() {
            out.push(ch);
            kept += 1;
        } else {
            // Newlines, tabs, and any non-ASCII byte sequence collapse to a
            // single space rather than being dropped, so token boundaries in
            // the original message survive.
            if !out.is_empty() && !out.ends_with(' ') {
                out.push(' ');
                kept += 1;
            }
        }
    }
    out.trim_end().to_string()
}

/// Render one unlabeled process gauge, honoring the shared `ns_label`
/// convention (`,namespace="…"`, or empty when no namespace is configured).
fn render_process_gauge(output: &mut String, metric_name: &str, value: u64, ns_label: &str) {
    if ns_label.is_empty() {
        output.push_str(&format!("{metric_name} {value}\n"));
    } else {
        let body = ns_label.strip_prefix(',').unwrap_or(ns_label);
        output.push_str(&format!("{metric_name}{{{body}}} {value}\n"));
    }
}

/// Render one `(protocol, reason)` series.
fn render_classified(
    output: &mut String,
    metric_name: &str,
    protocol: GatewayListenerProtocolHalf,
    category: GatewayListenerFailureCategory,
    value: u64,
    ns_label: &str,
) {
    output.push_str(&format!(
        "{metric_name}{{protocol=\"{}\",reason=\"{}\"{ns_label}}} {value}\n",
        protocol.as_str(),
        category.as_str()
    ));
}

/// Render the fixed-cardinality Gateway listener families.
///
/// Every label value comes from [`GatewayListenerProtocolHalf::as_str`] or
/// [`GatewayListenerFailureCategory::as_str`] — both closed sets — plus the
/// process namespace. Port, listener name, host, config generation, and error
/// text are deliberately absent: they are authenticated `/health` detail. The
/// complete series count is therefore `3 + 3 * 2 * 9` regardless of how many
/// Gateway listeners a configuration declares.
///
/// Emits nothing when the process has no dynamic Gateway listener status, so a
/// mode that never binds these listeners does not advertise empty families.
pub fn render_prometheus(
    output: &mut String,
    ns_label: &str,
    status: Option<&GatewayListenerStatus>,
) {
    let Some(status) = status else {
        return;
    };
    let snapshot = status.snapshot();
    let cumulative = status.cumulative();

    output.push_str(
        "# HELP ferrum_gateway_listeners_desired Dynamic Gateway API listener ports the published configuration asks this process to bind.\n",
    );
    output.push_str("# TYPE ferrum_gateway_listeners_desired gauge\n");
    render_process_gauge(
        output,
        "ferrum_gateway_listeners_desired",
        snapshot.desired_listeners as u64,
        ns_label,
    );

    output.push_str(
        "# HELP ferrum_gateway_listeners_active Dynamic Gateway API listener ports currently bound and accepting.\n",
    );
    output.push_str("# TYPE ferrum_gateway_listeners_active gauge\n");
    render_process_gauge(
        output,
        "ferrum_gateway_listeners_active",
        snapshot.active_listeners as u64,
        ns_label,
    );

    output.push_str(
        "# HELP ferrum_gateway_listener_failed_ports Distinct dynamic Gateway API listener ports with at least one active failure.\n",
    );
    output.push_str("# TYPE ferrum_gateway_listener_failed_ports gauge\n");
    render_process_gauge(
        output,
        "ferrum_gateway_listener_failed_ports",
        snapshot.failed_ports as u64,
        ns_label,
    );

    // The active gauge and both counters zero-fill the complete closed label
    // space, so an alert on a recovered listener reads `0` rather than losing
    // the series entirely.
    output.push_str(
        "# HELP ferrum_gateway_listener_failures_active Dynamic Gateway API listener halves currently failing, by protocol half and bounded reason.\n",
    );
    output.push_str("# TYPE ferrum_gateway_listener_failures_active gauge\n");
    for protocol in GatewayListenerProtocolHalf::ALL {
        for category in GatewayListenerFailureCategory::ALL {
            let count = snapshot
                .active_by_category
                .iter()
                .find(|active| active.protocol == protocol && active.category == category)
                .map_or(0, |active| active.count);
            render_classified(
                output,
                "ferrum_gateway_listener_failures_active",
                protocol,
                category,
                count,
                ns_label,
            );
        }
    }

    output.push_str(
        "# HELP ferrum_gateway_listener_failures_total Dynamic Gateway API listener failures observed since process start, by protocol half and bounded reason.\n",
    );
    output.push_str("# TYPE ferrum_gateway_listener_failures_total counter\n");
    render_cumulative(
        output,
        "ferrum_gateway_listener_failures_total",
        &cumulative.failures_total,
        ns_label,
    );

    output.push_str(
        "# HELP ferrum_gateway_listener_recoveries_total Dynamic Gateway API listener failures cleared by a later reconcile since process start, by protocol half and bounded reason.\n",
    );
    output.push_str("# TYPE ferrum_gateway_listener_recoveries_total counter\n");
    render_cumulative(
        output,
        "ferrum_gateway_listener_recoveries_total",
        &cumulative.recoveries_total,
        ns_label,
    );
}

fn render_cumulative(
    output: &mut String,
    metric_name: &str,
    values: &[GatewayListenerCounter],
    ns_label: &str,
) {
    for protocol in GatewayListenerProtocolHalf::ALL {
        for category in GatewayListenerFailureCategory::ALL {
            let value = values
                .iter()
                .find(|series| series.protocol == protocol && series.category == category)
                .map_or(0, |series| series.value);
            render_classified(output, metric_name, protocol, category, value, ns_label);
        }
    }
}
