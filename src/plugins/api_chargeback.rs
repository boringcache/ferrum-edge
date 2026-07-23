//! API Chargeback Plugin
//!
//! Tracks per-consumer API usage charges across three pricing dimensions:
//!
//! 1. **Per-call pricing** keyed by billable status code (`pricing_tiers`) —
//!    ordinary HTTP uses its wire status, while native gRPC and translated
//!    gRPC-Web use the final terminal status mapped to an effective HTTP status.
//! 2. **Bandwidth pricing** keyed by direction (`bandwidth_pricing`) — applied
//!    to both HTTP-family transactions and stream transactions (TCP, TCP+TLS,
//!    UDP, DTLS) using the gateway-perspective `bytes_sent` / `bytes_received`
//!    counters that the unified [`TransactionSummary`] /
//!    [`StreamTransactionSummary`] schema exposes.
//! 3. **Per-connection pricing** for stream sessions (`stream_connection_pricing`).
//!    Streams have no HTTP status code so they cannot use `pricing_tiers`; this
//!    knob charges a flat fee per stream session at disconnect time.
//!
//! Charges accumulate in-memory via a global singleton registry and are exposed
//! via the admin `/charges` endpoint in both Prometheus and JSON formats for
//! external billing system integration. Only requests with an identified
//! consumer (or authenticated identity) are charged — anonymous traffic is not
//! tracked.
//!
//! **Hot-path optimization**: The recording methods use a thread-local `String`
//! buffer for the DashMap lookup key, achieving **zero heap allocation on cache
//! hits** (99%+ of requests). Only the first record per unique
//! (consumer, proxy, status_code, currency, namespace, pricing) combination
//! allocates — subsequent records reuse the existing DashMap entry via a
//! read-lock `get()` on a borrowed `&str`. Stream entries use a `status_code`
//! sentinel of `0` to share the same key format and code path.

use arc_swap::ArcSwap;
use async_trait::async_trait;
use dashmap::DashMap;
use serde_json::Value;
use std::collections::HashMap;
use std::fmt::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use super::{Plugin, StreamTransactionSummary, TransactionSummary, WsDisconnectContext};
use crate::plugins::chargeback::pricing::{
    PricingConfig, checked_add_charge, checked_mul_quantity, require_finite_charge,
};
use crate::util::unknown_keys::reject_unknown_keys;

/// Closed top-level config key set for `api_chargeback` admission.
///
/// Source of truth: keys read by [`ApiChargeback::new`] and
/// [`PricingConfig::from_config`]. `schema` / `schema_ref` are intentionally
/// excluded — they are rejected with a dedicated non-shipping-plugin error
/// before unknown-key screening.
pub const API_CHARGEBACK_CONFIG_KEYS: &[&str] = &[
    "currency",
    "pricing_tiers",
    "bandwidth_pricing",
    "stream_connection_pricing",
    "render_cache_ttl_seconds",
    "stale_entry_ttl_seconds",
    "cache_invalidation_min_age_ms",
    "cleanup_interval_seconds",
];

/// Global chargeback registry (singleton per process).
static CHARGEBACK_REGISTRY: OnceLock<Arc<ChargebackRegistry>> = OnceLock::new();

pub fn global_registry() -> Arc<ChargebackRegistry> {
    CHARGEBACK_REGISTRY
        .get_or_init(|| Arc::new(ChargebackRegistry::new()))
        .clone()
}

fn escape_label_value(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

/// Protocol family of a recorded entry. Stored on `ChargebackEntry` so the
/// render path can label HTTP and stream activity distinctly without re-parsing
/// the entry key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolFamily {
    Http,
    Stream,
}

impl ProtocolFamily {
    /// Stable registry-key / export label for this family (`"http"` or `"stream"`).
    pub fn label(&self) -> &'static str {
        match self {
            ProtocolFamily::Http => "http",
            ProtocolFamily::Stream => "stream",
        }
    }
}

#[derive(Clone, Copy)]
struct EntryPrices {
    call: f64,
    bandwidth_sent: f64,
    bandwidth_received: f64,
}

type HttpChargeAggregateKey = (String, String, u16, Arc<str>, Arc<str>);
type StreamChargeAggregateKey = (String, String, Arc<str>, Arc<str>);
type BandwidthAggregateKey = (String, String, ProtocolFamily, Arc<str>, Arc<str>);

/// Currency and namespace of a single `api_chargeback` plugin instance
/// (finding #24).
///
/// The chargeback registry is a process-global singleton shared by every
/// `api_chargeback` instance, but currency and namespace are properties of the
/// individual instance (global / proxy / proxy_group scope), not of the
/// process. Each instance holds an `InstanceScope` and passes it (alongside the
/// per-request consumer) into the registry's `record_*` methods. The cold path
/// (first record per unique key) stamps these `Arc<str>` onto the new
/// [`ChargebackEntry`] with a cheap `Arc` clone; the hot path (cache hit)
/// touches none of them, preserving the zero-allocation recording path.
#[derive(Clone)]
pub struct InstanceScope {
    /// Instance currency label (e.g. "USD"). Emitted per-row at render time.
    pub currency: Arc<str>,
    /// Pre-rendered Prometheus namespace label fragment, e.g.
    /// `,namespace="ferrum"` (empty string when the namespace is empty). This is
    /// the only namespace representation the renderers need: Prometheus appends
    /// it verbatim and the JSON output does not carry a namespace field.
    pub namespace_label: Arc<str>,
}

impl InstanceScope {
    /// Build an instance scope from a currency and namespace, pre-rendering the
    /// Prometheus label fragment once at construction.
    pub fn new(currency: &str, namespace: &str) -> Self {
        Self {
            currency: Arc::from(currency),
            namespace_label: Arc::from(Self::namespace_label_for(namespace).as_str()),
        }
    }

    /// Build the Prometheus namespace label fragment for a namespace value.
    /// Empty namespace produces an empty fragment so no `namespace=""` label is
    /// emitted.
    pub fn namespace_label_for(namespace: &str) -> String {
        if namespace.is_empty() {
            String::new()
        } else {
            format!(",namespace=\"{}\"", escape_label_value(namespace))
        }
    }
}

fn write_chargeback_key(
    buf: &mut String,
    consumer: &str,
    proxy_id: &str,
    status_code: u16,
    protocol_family: ProtocolFamily,
    scope: &InstanceScope,
    prices: EntryPrices,
) {
    // Include protocol_family so status-0 WebSocket bandwidth (HTTP family) and
    // zero-connection-price stream sessions cannot collide when every other
    // key dimension matches (issue #2571).
    let _ = write!(
        buf,
        "{}|{}|{}|{}|{}|{}|{:016x}|{:016x}|{:016x}",
        consumer,
        proxy_id,
        status_code,
        protocol_family.label(),
        scope.currency,
        scope.namespace_label,
        prices.call.to_bits(),
        prices.bandwidth_sent.to_bits(),
        prices.bandwidth_received.to_bits()
    );
}

/// Atomic chargeback entry. Tracks call counts, exact byte counters, staleness,
/// and render metadata.
///
/// **Monetary accuracy (finding #76)**: monetary totals are NOT accumulated.
/// Only the exact integer inputs — `call_count`, `bytes_sent_total`,
/// `bytes_received_total` — are summed via plain `fetch_add`, and charges are
/// derived once at render time as `count * price` / `bytes * price`. This
/// eliminates the order-dependent per-add f64 rounding drift that an
/// accumulate-money-as-f64-bits design suffers over high transaction volume,
/// while keeping the lock-free atomics trivial. The per-entry prices
/// (`call_price`, `bw_price_sent`, `bw_price_received`) are config-derived
/// constants fixed at entry creation.
///
/// **Per-instance scoping (finding #24)**: `currency` and `namespace_label` are
/// stored per entry (set from the constructing plugin instance) rather than in
/// a single process-global, last-writer-wins registry field. A single process
/// legitimately hosts multiple `api_chargeback` instances with different
/// currencies/namespaces (global / proxy / proxy_group scopes), so each
/// exported row carries the currency and namespace of the instance that
/// recorded it.
///
/// The `consumer`, `proxy_id`, `proxy_name`, `status_code`,
/// `protocol_family`, prices, `currency`, and `namespace_label` fields are set
/// once on creation and read during render. They are included in the DashMap key
/// string so config reloads that change pricing create fresh entries instead of
/// adding new traffic to stale prices, and so HTTP-family status-0 WebSocket
/// bandwidth cannot share an entry with a stream session. The key is still a
/// plain `String`, which lets the hot-path `get()` use a borrowed `&str` from a
/// thread-local buffer with zero allocation.
///
/// For stream entries the `status_code` is `0` and there is exactly one entry
/// per `(consumer, proxy_id, protocol_family=stream)` (streams have no HTTP
/// status). WebSocket-disconnect bandwidth also uses status `0` but under
/// `protocol_family=http`, so the family discriminator keeps those rows apart.
pub struct ChargebackEntry {
    pub call_count: AtomicU64,
    /// Bytes the gateway sent onward toward the backend on the client's behalf
    /// (request body for HTTP, client→backend half of a stream relay).
    pub bytes_sent_total: AtomicU64,
    /// Bytes the gateway received from the backend and forwarded to the client
    /// (response body for HTTP, backend→client half of a stream relay).
    pub bytes_received_total: AtomicU64,
    pub last_updated: AtomicU64,
    // --- Pricing (immutable after creation, config-derived) ---
    /// Per-call (or per-stream-connection) price. Charge is `call_count * this`.
    pub call_price: f64,
    /// Per-byte price for client→backend bytes.
    pub bw_price_sent: f64,
    /// Per-byte price for backend→client bytes.
    pub bw_price_received: f64,
    // --- Render metadata (immutable after creation) ---
    pub consumer: Arc<str>,
    pub proxy_id: Arc<str>,
    pub proxy_name: Arc<str>,
    pub status_code: u16,
    pub protocol_family: ProtocolFamily,
    /// Currency label (e.g., "USD", "EUR") of the instance that created the
    /// entry. Per-entry so multiple instances with different currencies do not
    /// misattribute one another's charges.
    pub currency: Arc<str>,
    /// Pre-rendered Prometheus namespace label fragment, e.g.
    /// `,namespace="ferrum"` (empty string when no namespace), of the instance
    /// that created the entry.
    pub namespace_label: Arc<str>,
}

impl ChargebackEntry {
    #[allow(clippy::too_many_arguments)]
    fn new(
        epoch: Instant,
        consumer: Arc<str>,
        proxy_id: Arc<str>,
        proxy_name: Arc<str>,
        status_code: u16,
        protocol_family: ProtocolFamily,
        call_price: f64,
        bw_price_sent: f64,
        bw_price_received: f64,
        currency: Arc<str>,
        namespace_label: Arc<str>,
    ) -> Self {
        Self {
            call_count: AtomicU64::new(0),
            bytes_sent_total: AtomicU64::new(0),
            bytes_received_total: AtomicU64::new(0),
            last_updated: AtomicU64::new(epoch.elapsed().as_nanos() as u64),
            call_price,
            bw_price_sent,
            bw_price_received,
            consumer,
            proxy_id,
            proxy_name,
            status_code,
            protocol_family,
            currency,
            namespace_label,
        }
    }

    fn record(&self, bytes_sent: u64, bytes_received: u64, count_call: bool, epoch: Instant) {
        if count_call {
            self.call_count.fetch_add(1, Ordering::Relaxed);
        }
        if bytes_sent > 0 {
            self.bytes_sent_total
                .fetch_add(bytes_sent, Ordering::Relaxed);
        }
        if bytes_received > 0 {
            self.bytes_received_total
                .fetch_add(bytes_received, Ordering::Relaxed);
        }
        self.last_updated
            .store(epoch.elapsed().as_nanos() as u64, Ordering::Relaxed);
    }

    /// Total per-call (or per-connection) charge, computed once from exact
    /// inputs: `call_count * call_price`. Returns an error when the product is
    /// non-finite so exporters can fail closed instead of emitting JSON null /
    /// Prometheus `inf`.
    pub fn call_charge(&self) -> Result<f64, String> {
        checked_mul_quantity(self.call_count.load(Ordering::Relaxed), self.call_price)
    }

    /// Bandwidth charge for client→backend bytes: `bytes_sent_total * price`.
    pub fn bandwidth_charge_sent(&self) -> Result<f64, String> {
        checked_mul_quantity(
            self.bytes_sent_total.load(Ordering::Relaxed),
            self.bw_price_sent,
        )
    }

    /// Bandwidth charge for backend→client bytes: `bytes_received_total * price`.
    pub fn bandwidth_charge_received(&self) -> Result<f64, String> {
        checked_mul_quantity(
            self.bytes_received_total.load(Ordering::Relaxed),
            self.bw_price_received,
        )
    }

    fn nanos_since_update(&self, epoch: Instant) -> u64 {
        let now = epoch.elapsed().as_nanos() as u64;
        let last = self.last_updated.load(Ordering::Relaxed);
        now.saturating_sub(last)
    }
}

/// Default stale entry TTL: 1 hour in nanoseconds.
const DEFAULT_STALE_TTL_NANOS: u64 = 3_600_000_000_000;

/// Default render cache TTL: 5 seconds.
const DEFAULT_RENDER_CACHE_TTL_SECS: u64 = 5;

/// Default minimum cache age (in nanoseconds) before record() will invalidate.
const DEFAULT_CACHE_INVALIDATION_MIN_AGE_NANOS: u64 = 500_000_000; // 500ms

/// Sentinel `status_code` for stream sessions and WebSocket-disconnect
/// bandwidth rows. Ordinary HTTP wire statuses are in `100..=599`; the
/// registry key also carries [`ProtocolFamily`] so a bandwidth-only stream
/// session and a WebSocket bandwidth record with identical prices cannot
/// collide on this sentinel.
const STREAM_STATUS_SENTINEL: u16 = 0;

/// Chargeback registry holding per-consumer, per-proxy charge accumulators.
///
/// **Key design**: The DashMap uses plain `String` keys formatted as
/// `"consumer|proxy_id|status_code|protocol_family|currency|namespace_label|price_bits..."`.
/// Render metadata (consumer, proxy_id, proxy_name, status_code,
/// protocol_family) is stored in the `ChargebackEntry` value and
/// `protocol_family` is also part of the key so immutable family attribution
/// cannot be fixed by insertion order. This allows the hot-path recording
/// methods to use `DashMap::get(&str)` with a thread-local buffer — zero
/// allocation on cache hits. Only the cold path (first record per unique
/// billing/pricing combination) allocates a `String` key and `Arc<str>`
/// metadata. This matches the connection pool key pattern in
/// `connection_pool.rs`.
pub struct ChargebackRegistry {
    epoch: Instant,
    pub entries: DashMap<String, ChargebackEntry>,
    /// Cached render output with generation timestamp.
    prometheus_cache: ArcSwap<Option<(Instant, String)>>,
    json_cache: ArcSwap<Option<(Instant, String)>>,
    render_cache_ttl_secs: AtomicU64,
    stale_entry_ttl_nanos: AtomicU64,
    cache_invalidation_min_age_nanos: AtomicU64,
    configured_currency: ArcSwap<String>,
    /// Guards against spawning duplicate background cleanup tasks.
    cleanup_task_started: AtomicBool,
}

impl Default for ChargebackRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ChargebackRegistry {
    pub fn new() -> Self {
        Self {
            epoch: Instant::now(),
            entries: DashMap::new(),
            prometheus_cache: ArcSwap::from_pointee(None),
            json_cache: ArcSwap::from_pointee(None),
            render_cache_ttl_secs: AtomicU64::new(DEFAULT_RENDER_CACHE_TTL_SECS),
            stale_entry_ttl_nanos: AtomicU64::new(DEFAULT_STALE_TTL_NANOS),
            cache_invalidation_min_age_nanos: AtomicU64::new(
                DEFAULT_CACHE_INVALIDATION_MIN_AGE_NANOS,
            ),
            configured_currency: ArcSwap::from_pointee("USD".to_string()),
            cleanup_task_started: AtomicBool::new(false),
        }
    }

    pub fn set_configured_currency(&self, currency: &str) {
        self.configured_currency
            .store(Arc::new(currency.to_string()));
    }

    /// Configure the process-global render/cleanup knobs that govern the SHARED
    /// registry infrastructure (render cache TTL, stale-entry eviction TTL,
    /// cache-invalidation min age). These intentionally remain registry-global
    /// because a single cleanup task and a single render cache serve all plugin
    /// instances. Currency and namespace are NOT configured here — they are
    /// scoped per [`ChargebackEntry`] so multiple instances with different
    /// currencies/namespaces never misattribute one another's charges
    /// (finding #24).
    pub fn configure(
        &self,
        render_cache_ttl_secs: u64,
        stale_entry_ttl_secs: u64,
        cache_invalidation_min_age_ms: u64,
    ) {
        self.render_cache_ttl_secs
            .store(render_cache_ttl_secs, Ordering::Relaxed);
        self.stale_entry_ttl_nanos.store(
            stale_entry_ttl_secs.saturating_mul(1_000_000_000),
            Ordering::Relaxed,
        );
        self.cache_invalidation_min_age_nanos.store(
            cache_invalidation_min_age_ms.saturating_mul(1_000_000),
            Ordering::Relaxed,
        );
    }

    /// Start a background task that periodically evicts stale entries.
    /// Uses `compare_exchange` to ensure only one cleanup task runs per registry.
    /// Guard with `Handle::try_current()` so `new()` works in non-tokio test contexts.
    pub fn start_cleanup_task(self: &Arc<Self>, interval_seconds: u64) {
        if interval_seconds == 0 {
            return;
        }
        if tokio::runtime::Handle::try_current().is_err() {
            return; // No tokio runtime (e.g., unit tests)
        }
        if self
            .cleanup_task_started
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return; // Already started by another plugin instance
        }
        let registry = Arc::clone(self);
        tokio::spawn(async move {
            let mut timer = tokio::time::interval(std::time::Duration::from_secs(interval_seconds));
            loop {
                timer.tick().await;
                let ttl_nanos = registry.stale_entry_ttl_nanos.load(Ordering::Relaxed);
                registry.evict_stale(ttl_nanos);
            }
        });
    }

    /// Record a chargeable HTTP-family transaction (HTTP/1.1, H2, H3, gRPC,
    /// WebSocket upgrade). Status code is the response status.
    #[allow(clippy::too_many_arguments)]
    pub fn record_http(
        &self,
        scope: &InstanceScope,
        consumer: &str,
        proxy_id: &str,
        proxy_name: &str,
        status_code: u16,
        call_price: f64,
        bytes_sent: u64,
        bytes_received: u64,
        bw_price_sent: f64,
        bw_price_received: f64,
    ) {
        self.record_inner(
            scope,
            consumer,
            proxy_id,
            proxy_name,
            status_code,
            ProtocolFamily::Http,
            call_price,
            bytes_sent,
            bytes_received,
            bw_price_sent,
            bw_price_received,
            true,
        );
    }

    /// Record a chargeable stream session (TCP, TCP+TLS, UDP, DTLS). Streams
    /// have no HTTP status code; entries are keyed by
    /// `(consumer, proxy_id, ProtocolFamily::Stream)` with the
    /// [`STREAM_STATUS_SENTINEL`].
    #[allow(clippy::too_many_arguments)]
    pub fn record_stream(
        &self,
        scope: &InstanceScope,
        consumer: &str,
        proxy_id: &str,
        proxy_name: &str,
        connection_price: f64,
        bytes_sent: u64,
        bytes_received: u64,
        bw_price_sent: f64,
        bw_price_received: f64,
    ) {
        self.record_inner(
            scope,
            consumer,
            proxy_id,
            proxy_name,
            STREAM_STATUS_SENTINEL,
            ProtocolFamily::Stream,
            connection_price,
            bytes_sent,
            bytes_received,
            bw_price_sent,
            bw_price_received,
            true,
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_websocket_bandwidth(
        &self,
        scope: &InstanceScope,
        consumer: &str,
        proxy_id: &str,
        proxy_name: &str,
        bytes_sent: u64,
        bytes_received: u64,
        bw_price_sent: f64,
        bw_price_received: f64,
    ) {
        self.record_inner(
            scope,
            consumer,
            proxy_id,
            proxy_name,
            STREAM_STATUS_SENTINEL,
            ProtocolFamily::Http,
            0.0,
            bytes_sent,
            bytes_received,
            bw_price_sent,
            bw_price_received,
            false,
        );
    }

    /// Shared hot-path implementation behind `record_http` / `record_stream`.
    ///
    /// **Hot-path (cache hit)**: Uses `DashMap::get(&str)` with a thread-local
    /// buffer — one `write!` into a pre-allocated `String`, one DashMap read-lock,
    /// a handful of atomic operations. Zero heap allocation.
    ///
    /// **Cold-path (first record per unique combination)**: Clones the per-instance
    /// `Arc<str>` render metadata (consumer/proxy/currency/namespace) and allocates
    /// the owned `String` key and a new `ChargebackEntry`. This runs once per unique
    /// `(consumer, proxy, status_code, protocol_family, currency, namespace, prices)`
    /// combination. The currency/namespace come from the recording plugin
    /// instance's [`InstanceScope`], and are part of the key so multiple
    /// instances never reuse an entry stamped with another instance's render
    /// scope. `protocol_family` is part of the key so HTTP-family WebSocket
    /// bandwidth and stream sessions stay distinct even when both use status
    /// `0` and identical prices.
    #[allow(clippy::too_many_arguments)]
    fn record_inner(
        &self,
        scope: &InstanceScope,
        consumer: &str,
        proxy_id: &str,
        proxy_name: &str,
        status_code: u16,
        protocol_family: ProtocolFamily,
        call_price: f64,
        bytes_sent: u64,
        bytes_received: u64,
        bw_price_sent: f64,
        bw_price_received: f64,
        count_call: bool,
    ) {
        thread_local! {
            static KEY_BUF: std::cell::RefCell<String> =
                std::cell::RefCell::new(String::with_capacity(128));
        }

        // Fast path: build key in thread-local buffer, look up with borrowed &str.
        // DashMap::get takes &Q where String: Borrow<Q>, so &str works directly.
        let hit = KEY_BUF.with(|buf| {
            let mut buf = buf.borrow_mut();
            buf.clear();
            write_chargeback_key(
                &mut buf,
                consumer,
                proxy_id,
                status_code,
                protocol_family,
                scope,
                EntryPrices {
                    call: call_price,
                    bandwidth_sent: bw_price_sent,
                    bandwidth_received: bw_price_received,
                },
            );

            if let Some(entry) = self.entries.get(buf.as_str()) {
                entry.record(bytes_sent, bytes_received, count_call, self.epoch);
                return true;
            }
            false
        });

        if !hit {
            // Cold path: allocate owned key + metadata for DashMap insertion.
            // Currency/namespace come from the recording instance's scope so the
            // entry is attributed to the instance that created it (finding #24).
            // Capacity covers separators, status, protocol_family label
            // ("stream" is longest), and three 16-hex price bit fields.
            let mut owned_key = String::with_capacity(
                consumer.len()
                    + proxy_id.len()
                    + scope.currency.len()
                    + scope.namespace_label.len()
                    + 74,
            );
            write_chargeback_key(
                &mut owned_key,
                consumer,
                proxy_id,
                status_code,
                protocol_family,
                scope,
                EntryPrices {
                    call: call_price,
                    bandwidth_sent: bw_price_sent,
                    bandwidth_received: bw_price_received,
                },
            );
            self.entries
                .entry(owned_key)
                .or_insert_with(|| {
                    ChargebackEntry::new(
                        self.epoch,
                        Arc::from(consumer),
                        Arc::from(proxy_id),
                        Arc::from(proxy_name),
                        status_code,
                        protocol_family,
                        if count_call { call_price } else { 0.0 },
                        bw_price_sent,
                        bw_price_received,
                        Arc::clone(&scope.currency),
                        Arc::clone(&scope.namespace_label),
                    )
                })
                .record(bytes_sent, bytes_received, count_call, self.epoch);
        }

        self.maybe_invalidate_caches();
    }

    fn maybe_invalidate_caches(&self) {
        let min_age_nanos = self
            .cache_invalidation_min_age_nanos
            .load(Ordering::Relaxed);

        let cached = self.prometheus_cache.load();
        if let Some((generated_at, _)) = **cached {
            let age_nanos = generated_at.elapsed().as_nanos() as u64;
            if age_nanos < min_age_nanos {
                return;
            }
        }
        self.prometheus_cache.store(Arc::new(None));
        self.json_cache.store(Arc::new(None));
    }

    pub fn evict_stale(&self, ttl_nanos: u64) -> usize {
        let mut evicted = 0;
        self.entries.retain(|_, v| {
            let keep = v.nanos_since_update(self.epoch) < ttl_nanos;
            if !keep {
                evicted += 1;
            }
            keep
        });
        if evicted > 0 {
            self.prometheus_cache.store(Arc::new(None));
            self.json_cache.store(Arc::new(None));
        }
        evicted
    }

    /// Render in Prometheus exposition format with caching.
    ///
    /// Returns `Err` when any monetary sample would be non-finite; callers must
    /// surface that as an explicit export failure rather than emitting `inf`.
    pub fn render_prometheus(&self) -> Result<String, String> {
        let ttl_secs = self.render_cache_ttl_secs.load(Ordering::Relaxed);
        let cached = self.prometheus_cache.load();
        if let Some((generated_at, ref output)) = **cached
            && generated_at.elapsed().as_secs() < ttl_secs
        {
            return Ok(output.clone());
        }

        let stale_ttl = self.stale_entry_ttl_nanos.load(Ordering::Relaxed);
        self.evict_stale(stale_ttl);

        let output = self.render_prometheus_uncached()?;
        self.prometheus_cache
            .store(Arc::new(Some((Instant::now(), output.clone()))));
        Ok(output)
    }

    pub fn render_prometheus_uncached(&self) -> Result<String, String> {
        // Multiple counter families × ~200 bytes per entry
        let estimated_cap = 1024 + self.entries.len() * 600;
        let mut output = String::with_capacity(estimated_cap);

        // --- Per-call metrics (HTTP entries only — streams have no status code) ---
        struct ChargeAggregate {
            proxy_name: String,
            currency: Arc<str>,
            namespace_label: Arc<str>,
            count: u64,
            charges: f64,
        }

        // Entries are keyed by pricing bits so config reloads do not reuse
        // stale prices, but Prometheus label sets intentionally omit those
        // bits. Aggregate by the exposed labels before rendering so a scrape
        // never contains duplicate series after pricing changes.
        let mut http_aggregates: HashMap<HttpChargeAggregateKey, ChargeAggregate> = HashMap::new();
        let mut stream_aggregates: HashMap<StreamChargeAggregateKey, ChargeAggregate> =
            HashMap::new();

        for entry in self.entries.iter() {
            let v = entry.value();
            match v.protocol_family {
                ProtocolFamily::Http => {
                    let agg = http_aggregates
                        .entry((
                            v.consumer.to_string(),
                            v.proxy_id.to_string(),
                            v.status_code,
                            Arc::clone(&v.currency),
                            Arc::clone(&v.namespace_label),
                        ))
                        .or_insert_with(|| ChargeAggregate {
                            proxy_name: v.proxy_name.to_string(),
                            currency: Arc::clone(&v.currency),
                            namespace_label: Arc::clone(&v.namespace_label),
                            count: 0,
                            charges: 0.0,
                        });
                    agg.count += v.call_count.load(Ordering::Relaxed);
                    agg.charges = checked_add_charge(agg.charges, v.call_charge()?)?;
                }
                ProtocolFamily::Stream => {
                    let agg = stream_aggregates
                        .entry((
                            v.consumer.to_string(),
                            v.proxy_id.to_string(),
                            Arc::clone(&v.currency),
                            Arc::clone(&v.namespace_label),
                        ))
                        .or_insert_with(|| ChargeAggregate {
                            proxy_name: v.proxy_name.to_string(),
                            currency: Arc::clone(&v.currency),
                            namespace_label: Arc::clone(&v.namespace_label),
                            count: 0,
                            charges: 0.0,
                        });
                    agg.count += v.call_count.load(Ordering::Relaxed);
                    agg.charges = checked_add_charge(agg.charges, v.call_charge()?)?;
                }
            }
        }

        output.push_str(
            "# HELP ferrum_api_chargeable_calls_total Total chargeable HTTP-family API calls per consumer by billable status.\n",
        );
        output.push_str("# TYPE ferrum_api_chargeable_calls_total counter\n");
        for ((consumer, proxy_id, status_code, _, _), agg) in &http_aggregates {
            output.push_str(&format!(
                "ferrum_api_chargeable_calls_total{{consumer=\"{}\",proxy_id=\"{}\",proxy_name=\"{}\",status_code=\"{}\",currency=\"{}\"{}}} {}\n",
                escape_label_value(consumer),
                escape_label_value(proxy_id),
                escape_label_value(&agg.proxy_name),
                status_code,
                escape_label_value(&agg.currency),
                agg.namespace_label,
                agg.count
            ));
        }

        output.push_str(
            "# HELP ferrum_api_charges_total Total per-call charges accumulated per consumer.\n",
        );
        output.push_str("# TYPE ferrum_api_charges_total counter\n");
        for ((consumer, proxy_id, status_code, _, _), agg) in &http_aggregates {
            let charges = require_finite_charge(agg.charges, "ferrum_api_charges_total")?;
            output.push_str(&format!(
                "ferrum_api_charges_total{{consumer=\"{}\",proxy_id=\"{}\",proxy_name=\"{}\",status_code=\"{}\",currency=\"{}\"{}}} {:.10}\n",
                escape_label_value(consumer),
                escape_label_value(proxy_id),
                escape_label_value(&agg.proxy_name),
                status_code,
                escape_label_value(&agg.currency),
                agg.namespace_label,
                charges
            ));
        }

        // --- Stream connection metrics (stream entries only) ---

        output.push_str(
            "# HELP ferrum_api_stream_connections_total Total stream sessions (TCP/UDP/DTLS) per consumer.\n",
        );
        output.push_str("# TYPE ferrum_api_stream_connections_total counter\n");
        for ((consumer, proxy_id, _, _), agg) in &stream_aggregates {
            output.push_str(&format!(
                "ferrum_api_stream_connections_total{{consumer=\"{}\",proxy_id=\"{}\",proxy_name=\"{}\",currency=\"{}\"{}}} {}\n",
                escape_label_value(consumer),
                escape_label_value(proxy_id),
                escape_label_value(&agg.proxy_name),
                escape_label_value(&agg.currency),
                agg.namespace_label,
                agg.count
            ));
        }

        output.push_str(
            "# HELP ferrum_api_stream_connection_charges_total Total per-connection charges for stream sessions.\n",
        );
        output.push_str("# TYPE ferrum_api_stream_connection_charges_total counter\n");
        for ((consumer, proxy_id, _, _), agg) in &stream_aggregates {
            let charges =
                require_finite_charge(agg.charges, "ferrum_api_stream_connection_charges_total")?;
            output.push_str(&format!(
                "ferrum_api_stream_connection_charges_total{{consumer=\"{}\",proxy_id=\"{}\",proxy_name=\"{}\",currency=\"{}\"{}}} {:.10}\n",
                escape_label_value(consumer),
                escape_label_value(proxy_id),
                escape_label_value(&agg.proxy_name),
                escape_label_value(&agg.currency),
                agg.namespace_label,
                charges
            ));
        }

        // --- Bandwidth metrics. Aggregated per (consumer, proxy_id,
        //     protocol_family, currency, namespace) so HTTP entries spread
        //     across status codes collapse to one row per direction, while
        //     HTTP/stream and distinct billing scopes under the same proxy_id
        //     stay on separate, deterministically labeled rows.
        struct BandwidthAggregate {
            proxy_name: String,
            currency: Arc<str>,
            namespace_label: Arc<str>,
            bytes_sent: u64,
            bytes_received: u64,
            charge_sent: f64,
            charge_received: f64,
        }

        let mut bw_aggregates: HashMap<BandwidthAggregateKey, BandwidthAggregate> = HashMap::new();
        for entry in self.entries.iter() {
            let v = entry.value();
            let agg = bw_aggregates
                .entry((
                    v.consumer.to_string(),
                    v.proxy_id.to_string(),
                    v.protocol_family,
                    Arc::clone(&v.currency),
                    Arc::clone(&v.namespace_label),
                ))
                .or_insert_with(|| BandwidthAggregate {
                    proxy_name: v.proxy_name.to_string(),
                    currency: Arc::clone(&v.currency),
                    namespace_label: Arc::clone(&v.namespace_label),
                    bytes_sent: 0,
                    bytes_received: 0,
                    charge_sent: 0.0,
                    charge_received: 0.0,
                });
            agg.bytes_sent += v.bytes_sent_total.load(Ordering::Relaxed);
            agg.bytes_received += v.bytes_received_total.load(Ordering::Relaxed);
            agg.charge_sent = checked_add_charge(agg.charge_sent, v.bandwidth_charge_sent()?)?;
            agg.charge_received =
                checked_add_charge(agg.charge_received, v.bandwidth_charge_received()?)?;
        }

        output.push_str(
            "# HELP ferrum_api_bytes_sent_total Total bytes the gateway sent client->backend on this consumer's behalf.\n",
        );
        output.push_str("# TYPE ferrum_api_bytes_sent_total counter\n");
        for ((consumer, proxy_id, family, _, _), agg) in &bw_aggregates {
            output.push_str(&format!(
                "ferrum_api_bytes_sent_total{{consumer=\"{}\",proxy_id=\"{}\",proxy_name=\"{}\",currency=\"{}\",protocol_family=\"{}\"{}}} {}\n",
                escape_label_value(consumer),
                escape_label_value(proxy_id),
                escape_label_value(&agg.proxy_name),
                escape_label_value(&agg.currency),
                family.label(),
                agg.namespace_label,
                agg.bytes_sent
            ));
        }

        output.push_str(
            "# HELP ferrum_api_bytes_received_total Total bytes the gateway received backend->client and forwarded to this consumer.\n",
        );
        output.push_str("# TYPE ferrum_api_bytes_received_total counter\n");
        for ((consumer, proxy_id, family, _, _), agg) in &bw_aggregates {
            output.push_str(&format!(
                "ferrum_api_bytes_received_total{{consumer=\"{}\",proxy_id=\"{}\",proxy_name=\"{}\",currency=\"{}\",protocol_family=\"{}\"{}}} {}\n",
                escape_label_value(consumer),
                escape_label_value(proxy_id),
                escape_label_value(&agg.proxy_name),
                escape_label_value(&agg.currency),
                family.label(),
                agg.namespace_label,
                agg.bytes_received
            ));
        }

        output.push_str(
            "# HELP ferrum_api_bandwidth_charges_total Total bandwidth charges per consumer, split by direction.\n",
        );
        output.push_str("# TYPE ferrum_api_bandwidth_charges_total counter\n");
        for ((consumer, proxy_id, family, _, _), agg) in &bw_aggregates {
            let charge_sent =
                require_finite_charge(agg.charge_sent, "ferrum_api_bandwidth_charges_total")?;
            let charge_received =
                require_finite_charge(agg.charge_received, "ferrum_api_bandwidth_charges_total")?;
            output.push_str(&format!(
                "ferrum_api_bandwidth_charges_total{{consumer=\"{}\",proxy_id=\"{}\",proxy_name=\"{}\",direction=\"sent\",currency=\"{}\",protocol_family=\"{}\"{}}} {:.10}\n",
                escape_label_value(consumer),
                escape_label_value(proxy_id),
                escape_label_value(&agg.proxy_name),
                escape_label_value(&agg.currency),
                family.label(),
                agg.namespace_label,
                charge_sent
            ));
            output.push_str(&format!(
                "ferrum_api_bandwidth_charges_total{{consumer=\"{}\",proxy_id=\"{}\",proxy_name=\"{}\",direction=\"received\",currency=\"{}\",protocol_family=\"{}\"{}}} {:.10}\n",
                escape_label_value(consumer),
                escape_label_value(proxy_id),
                escape_label_value(&agg.proxy_name),
                escape_label_value(&agg.currency),
                family.label(),
                agg.namespace_label,
                charge_received
            ));
        }

        Ok(output)
    }

    /// Render as JSON with caching.
    ///
    /// Returns `Err` when any monetary field would be non-finite; callers must
    /// return an explicit error response rather than serializing JSON `null`.
    pub fn render_json(&self) -> Result<String, String> {
        let ttl_secs = self.render_cache_ttl_secs.load(Ordering::Relaxed);
        let cached = self.json_cache.load();
        if let Some((generated_at, ref output)) = **cached
            && generated_at.elapsed().as_secs() < ttl_secs
        {
            return Ok(output.clone());
        }

        let stale_ttl = self.stale_entry_ttl_nanos.load(Ordering::Relaxed);
        self.evict_stale(stale_ttl);

        let output = self.render_json_uncached()?;
        self.json_cache
            .store(Arc::new(Some((Instant::now(), output.clone()))));
        Ok(output)
    }

    pub fn render_json_uncached(&self) -> Result<String, String> {
        // Nested structure: consumer -> proxy -> {protocol, by_status, stream, bandwidth}.
        //
        // Currency is carried per proxy (it is a property of the recording
        // plugin instance — finding #24) and the proxy retains separate HTTP
        // (`by_status`) and stream (`stream_*`) breakdowns so a proxy serving
        // both families reports a deterministic `protocol_family` and always
        // emits its `stream` sub-object when stream activity exists (finding
        // #75).
        struct ProxyAggregate {
            proxy_name: String,
            currency: Arc<str>,
            has_http: bool,
            has_stream: bool,
            by_status: HashMap<u16, (u64, f64)>,
            stream_connections: u64,
            stream_charges: f64,
            bytes_sent: u64,
            bytes_received: u64,
            bandwidth_charge_sent: f64,
            bandwidth_charge_received: f64,
        }

        type ProxyAggregateKey = (String, Arc<str>, Arc<str>);
        type ConsumerProxyAggregates = HashMap<ProxyAggregateKey, ProxyAggregate>;

        let mut consumers: HashMap<String, ConsumerProxyAggregates> = HashMap::new();
        // Top-level currency: the single currency in use, or "mixed" when
        // instances disagree (consumers must then read per-proxy `currency`).
        let mut overall_currency: Option<Arc<str>> = None;
        let mut currency_mixed = false;

        for entry in self.entries.iter() {
            let v = entry.value();
            let calls = v.call_count.load(Ordering::Relaxed);
            let call_charge = v.call_charge()?;
            let bytes_sent = v.bytes_sent_total.load(Ordering::Relaxed);
            let bytes_received = v.bytes_received_total.load(Ordering::Relaxed);
            let bw_sent = v.bandwidth_charge_sent()?;
            let bw_received = v.bandwidth_charge_received()?;

            if !currency_mixed {
                match overall_currency.as_ref() {
                    None => overall_currency = Some(Arc::clone(&v.currency)),
                    Some(existing) if existing.as_ref() != v.currency.as_ref() => {
                        currency_mixed = true;
                    }
                    Some(_) => {}
                }
            }

            let proxy_map = consumers.entry(v.consumer.to_string()).or_default();
            let proxy_entry = proxy_map
                .entry((
                    v.proxy_id.to_string(),
                    Arc::clone(&v.currency),
                    Arc::clone(&v.namespace_label),
                ))
                .or_insert_with(|| ProxyAggregate {
                    proxy_name: v.proxy_name.to_string(),
                    currency: Arc::clone(&v.currency),
                    has_http: false,
                    has_stream: false,
                    by_status: HashMap::new(),
                    stream_connections: 0,
                    stream_charges: 0.0,
                    bytes_sent: 0,
                    bytes_received: 0,
                    bandwidth_charge_sent: 0.0,
                    bandwidth_charge_received: 0.0,
                });
            proxy_entry.bytes_sent += bytes_sent;
            proxy_entry.bytes_received += bytes_received;
            proxy_entry.bandwidth_charge_sent =
                checked_add_charge(proxy_entry.bandwidth_charge_sent, bw_sent)?;
            proxy_entry.bandwidth_charge_received =
                checked_add_charge(proxy_entry.bandwidth_charge_received, bw_received)?;

            match v.protocol_family {
                ProtocolFamily::Http => {
                    proxy_entry.has_http = true;
                    let status_entry = proxy_entry
                        .by_status
                        .entry(v.status_code)
                        .or_insert((0, 0.0));
                    status_entry.0 += calls;
                    status_entry.1 = checked_add_charge(status_entry.1, call_charge)?;
                }
                ProtocolFamily::Stream => {
                    proxy_entry.has_stream = true;
                    proxy_entry.stream_connections += calls;
                    proxy_entry.stream_charges =
                        checked_add_charge(proxy_entry.stream_charges, call_charge)?;
                }
            }
        }

        // Per-currency monetary rollup for a consumer. Never sum across
        // currencies into a unitless headline total (issue #2569).
        #[derive(Clone, Default)]
        struct CurrencyTotals {
            total_calls: u64,
            per_call_charges: f64,
            stream_connection_charges: f64,
            bandwidth_charges: f64,
        }

        impl CurrencyTotals {
            fn total_charges(&self) -> Result<f64, String> {
                checked_add_charge(self.per_call_charges, self.stream_connection_charges)
                    .and_then(|partial| checked_add_charge(partial, self.bandwidth_charges))
            }

            fn to_json(&self) -> Result<serde_json::Value, String> {
                Ok(serde_json::json!({
                    "total_calls": self.total_calls,
                    "total_charges": self.total_charges()?,
                    "per_call_charges": self.per_call_charges,
                    "stream_connection_charges": self.stream_connection_charges,
                    "bandwidth_charges": self.bandwidth_charges,
                }))
            }
        }

        let mut consumer_objects = serde_json::Map::new();
        for (consumer, proxies) in &consumers {
            let mut total_calls = 0u64;
            let mut by_currency: HashMap<String, CurrencyTotals> = HashMap::new();
            let mut proxy_objects = serde_json::Map::new();

            let mut proxy_id_counts: HashMap<&str, usize> = HashMap::new();
            for (proxy_id, _, _) in proxies.keys() {
                *proxy_id_counts.entry(proxy_id.as_str()).or_default() += 1;
            }

            for ((proxy_id, _, namespace_label), agg) in proxies {
                let mut proxy_per_call_charges = 0.0f64;
                let mut proxy_calls = 0u64;
                let mut status_objects = serde_json::Map::new();

                for (status_code, (calls, charge)) in &agg.by_status {
                    let charge = require_finite_charge(*charge, "by_status.charges")?;
                    proxy_per_call_charges = checked_add_charge(proxy_per_call_charges, charge)?;
                    proxy_calls += calls;
                    status_objects.insert(
                        status_code.to_string(),
                        serde_json::json!({
                            "calls": calls,
                            "charges": charge,
                        }),
                    );
                }

                let stream_charges =
                    require_finite_charge(agg.stream_charges, "stream.connection_charges")?;
                let bw_sent =
                    require_finite_charge(agg.bandwidth_charge_sent, "bandwidth.charge_sent")?;
                let bw_received = require_finite_charge(
                    agg.bandwidth_charge_received,
                    "bandwidth.charge_received",
                )?;

                // Stream connections also count toward total_calls for headline numbers.
                let proxy_total_calls = proxy_calls + agg.stream_connections;
                let proxy_total_charges =
                    checked_add_charge(proxy_per_call_charges, stream_charges)
                        .and_then(|partial| checked_add_charge(partial, bw_sent))
                        .and_then(|partial| checked_add_charge(partial, bw_received))?;
                require_finite_charge(proxy_total_charges, "proxy.total_charges")?;

                total_calls += proxy_total_calls;
                let proxy_bandwidth_charges = checked_add_charge(bw_sent, bw_received)?;
                let currency_totals = by_currency
                    .entry(agg.currency.as_ref().to_string())
                    .or_default();
                currency_totals.total_calls += proxy_total_calls;
                currency_totals.per_call_charges =
                    checked_add_charge(currency_totals.per_call_charges, proxy_per_call_charges)?;
                currency_totals.stream_connection_charges =
                    checked_add_charge(currency_totals.stream_connection_charges, stream_charges)?;
                currency_totals.bandwidth_charges =
                    checked_add_charge(currency_totals.bandwidth_charges, proxy_bandwidth_charges)?;

                // Deterministic protocol_family label: "mixed" when a proxy
                // carries both HTTP and stream activity, otherwise the single
                // family present (finding #75).
                let protocol_family = match (agg.has_http, agg.has_stream) {
                    (true, true) => "mixed",
                    (false, true) => ProtocolFamily::Stream.label(),
                    _ => ProtocolFamily::Http.label(),
                };

                let mut proxy_obj = serde_json::json!({
                    "proxy_id": proxy_id,
                    "proxy_name": agg.proxy_name,
                    "currency": agg.currency.as_ref(),
                    "protocol_family": protocol_family,
                    "total_calls": proxy_total_calls,
                    "total_charges": proxy_total_charges,
                    "by_status": serde_json::Value::Object(status_objects),
                    "bandwidth": {
                        "bytes_sent": agg.bytes_sent,
                        "bytes_received": agg.bytes_received,
                        "charge_sent": bw_sent,
                        "charge_received": bw_received,
                    },
                });
                // Always emit the stream sub-object when stream activity exists,
                // regardless of whether an HTTP entry shares the proxy_id, so the
                // visible breakdown reconciles with the totals (finding #75).
                if agg.has_stream {
                    proxy_obj["stream"] = serde_json::json!({
                        "connections": agg.stream_connections,
                        "connection_charges": stream_charges,
                    });
                }

                let output_key = if proxy_id_counts.get(proxy_id.as_str()).copied().unwrap_or(0) > 1
                {
                    format!(
                        "{}|currency={}{}",
                        proxy_id,
                        agg.currency.as_ref(),
                        namespace_label.as_ref()
                    )
                } else {
                    proxy_id.clone()
                };
                proxy_objects.insert(output_key, proxy_obj);
            }

            // Single-currency consumers keep the historical flat monetary fields.
            // Mixed-currency consumers null those fields and expose
            // `charges_by_currency` so billing integrations never treat a
            // USD+EUR sum as a settlement total (issue #2569). Call counts stay
            // flat because they are unitless. Per-proxy rows remain authoritative
            // within each currency and must reconcile with the matching
            // `charges_by_currency` partition.
            let mut consumer_obj = serde_json::Map::new();
            consumer_obj.insert("total_calls".to_string(), serde_json::json!(total_calls));
            consumer_obj.insert(
                "proxies".to_string(),
                serde_json::Value::Object(proxy_objects),
            );

            if by_currency.len() <= 1 {
                let totals = by_currency.values().next().cloned().unwrap_or_default();
                consumer_obj.insert(
                    "total_charges".to_string(),
                    serde_json::json!(totals.total_charges()?),
                );
                consumer_obj.insert(
                    "per_call_charges".to_string(),
                    serde_json::json!(totals.per_call_charges),
                );
                consumer_obj.insert(
                    "stream_connection_charges".to_string(),
                    serde_json::json!(totals.stream_connection_charges),
                );
                consumer_obj.insert(
                    "bandwidth_charges".to_string(),
                    serde_json::json!(totals.bandwidth_charges),
                );
            } else {
                consumer_obj.insert("total_charges".to_string(), serde_json::Value::Null);
                consumer_obj.insert("per_call_charges".to_string(), serde_json::Value::Null);
                consumer_obj.insert(
                    "stream_connection_charges".to_string(),
                    serde_json::Value::Null,
                );
                consumer_obj.insert("bandwidth_charges".to_string(), serde_json::Value::Null);

                let mut currency_entries: Vec<_> = by_currency.into_iter().collect();
                currency_entries.sort_by(|a, b| a.0.cmp(&b.0));
                let mut currency_objects = serde_json::Map::new();
                for (currency, totals) in currency_entries {
                    currency_objects.insert(currency, totals.to_json()?);
                }
                consumer_obj.insert(
                    "charges_by_currency".to_string(),
                    serde_json::Value::Object(currency_objects),
                );
            }

            consumer_objects.insert(consumer.clone(), serde_json::Value::Object(consumer_obj));
        }

        let currency = if currency_mixed {
            "mixed".to_string()
        } else {
            let configured_currency = self.configured_currency.load();
            overall_currency
                .as_deref()
                .map(str::to_string)
                .unwrap_or_else(|| configured_currency.as_str().to_string())
        };

        let result = serde_json::json!({
            "currency": currency,
            "generated_at": chrono::Utc::now().to_rfc3339(),
            "consumers": serde_json::Value::Object(consumer_objects),
        });

        serde_json::to_string_pretty(&result)
            .map_err(|err| format!("api_chargeback: failed to serialize charges JSON: {err}"))
    }
}

pub struct ApiChargeback {
    registry: Arc<ChargebackRegistry>,
    pricing: PricingConfig,
    /// This instance's currency + namespace, stamped onto every entry it
    /// records so multiple instances never misattribute one another's charges
    /// (finding #24).
    scope: InstanceScope,
}

fn optional_u64(config: &Value, key: &str, default: u64) -> Result<u64, String> {
    match config.get(key) {
        Some(value) => value
            .as_u64()
            .ok_or_else(|| format!("api_chargeback: '{key}' must be an unsigned integer")),
        None => Ok(default),
    }
}

impl ApiChargeback {
    pub fn new(config: &Value, namespace: &str) -> Result<Self, String> {
        let object = config
            .as_object()
            .ok_or_else(|| "api_chargeback: config must be an object".to_string())?;
        if config.get("schema").is_some() || config.get("schema_ref").is_some() {
            return Err("api_chargeback: 'schema' / 'schema_ref' is not supported \
                 (transaction-log schema customization applies only to log-shipping plugins; \
                 see docs/plugins.md)"
                .to_string());
        }
        reject_unknown_keys(
            object,
            "config",
            API_CHARGEBACK_CONFIG_KEYS,
            "api_chargeback: ",
        )?;

        let registry = global_registry();

        let currency = match config.get("currency") {
            Some(value) => {
                let currency = value
                    .as_str()
                    .ok_or_else(|| "api_chargeback: 'currency' must be a string".to_string())?
                    .trim();
                if currency.is_empty() {
                    return Err("api_chargeback: 'currency' must not be empty".to_string());
                }
                currency
            }
            None => "USD",
        };

        let render_cache_ttl_secs = optional_u64(
            config,
            "render_cache_ttl_seconds",
            DEFAULT_RENDER_CACHE_TTL_SECS,
        )?;

        let stale_entry_ttl_secs = optional_u64(
            config,
            "stale_entry_ttl_seconds",
            DEFAULT_STALE_TTL_NANOS / 1_000_000_000,
        )?;

        let cache_invalidation_min_age_ms = optional_u64(
            config,
            "cache_invalidation_min_age_ms",
            DEFAULT_CACHE_INVALIDATION_MIN_AGE_NANOS / 1_000_000,
        )?;

        // Validate ALL pricing dimensions before touching the global registry,
        // so a config error never leaves shared state half-mutated.
        let pricing = PricingConfig::from_config(config, "api_chargeback")?;

        if !pricing.has_any_pricing() {
            return Err(
                "api_chargeback: at least one of 'pricing_tiers', 'bandwidth_pricing', or \
                 'stream_connection_pricing' must be configured — the plugin would otherwise \
                 record nothing"
                    .to_string(),
            );
        }

        // Validation passed — now safe to configure the shared registry. Only
        // the process-global render/cleanup knobs are set here; currency and
        // namespace are scoped per entry via this instance's `InstanceScope`
        // (finding #24).
        registry.configure(
            render_cache_ttl_secs,
            stale_entry_ttl_secs,
            cache_invalidation_min_age_ms,
        );
        registry.set_configured_currency(currency);

        let cleanup_interval_seconds = optional_u64(config, "cleanup_interval_seconds", 300)?;
        registry.start_cleanup_task(cleanup_interval_seconds);

        let scope = InstanceScope::new(currency, namespace);

        Ok(Self {
            registry,
            pricing,
            scope,
        })
    }
}

#[async_trait]
impl Plugin for ApiChargeback {
    fn name(&self) -> &str {
        "api_chargeback"
    }

    fn priority(&self) -> u16 {
        super::priority::API_CHARGEBACK
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        // Stream protocols (TCP/UDP/DTLS) are now supported via on_stream_disconnect.
        super::ALL_PROTOCOLS
    }

    async fn log(&self, summary: &TransactionSummary) {
        let consumer = match summary.consumer_username.as_deref() {
            Some(c) if !c.is_empty() => c,
            _ => return,
        };

        let status_code = super::chargeback::http_billing_outcome(summary).status_code;

        let Some(charge) =
            self.pricing
                .compute_http(status_code, summary.bytes_sent, summary.bytes_received)
        else {
            return;
        };

        let proxy_id = summary.proxy_id.as_deref().unwrap_or("unknown");
        let proxy_name = summary.proxy_name.as_deref().unwrap_or("unknown");

        self.registry.record_http(
            &self.scope,
            consumer,
            proxy_id,
            proxy_name,
            status_code,
            charge.charge_call,
            summary.bytes_sent,
            summary.bytes_received,
            self.pricing.bandwidth_price_sent,
            self.pricing.bandwidth_price_received,
        );
    }

    async fn on_stream_disconnect(&self, summary: &StreamTransactionSummary) {
        let consumer = match summary.consumer_username.as_deref() {
            Some(c) if !c.is_empty() => c,
            _ => return,
        };

        let Some(charge) = self
            .pricing
            .compute_stream(summary.bytes_sent, summary.bytes_received)
        else {
            return;
        };

        let proxy_name = summary.proxy_name.as_deref().unwrap_or("unknown");

        self.registry.record_stream(
            &self.scope,
            consumer,
            &summary.proxy_id,
            proxy_name,
            charge.charge_call,
            summary.bytes_sent,
            summary.bytes_received,
            self.pricing.bandwidth_price_sent,
            self.pricing.bandwidth_price_received,
        );
    }

    fn requires_ws_disconnect_hooks(&self) -> bool {
        true
    }

    async fn on_ws_disconnect(&self, summary: &WsDisconnectContext) {
        let consumer = match summary.consumer_username.as_deref() {
            Some(c) if !c.is_empty() => c,
            _ => return,
        };
        if self
            .pricing
            .compute_websocket_bandwidth(
                summary.bytes_client_to_backend,
                summary.bytes_backend_to_client,
            )
            .is_none()
        {
            return;
        }
        let proxy_name = summary.proxy_name.as_deref().unwrap_or("unknown");
        self.registry.record_websocket_bandwidth(
            &self.scope,
            consumer,
            &summary.proxy_id,
            proxy_name,
            summary.bytes_client_to_backend,
            summary.bytes_backend_to_client,
            self.pricing.bandwidth_price_sent,
            self.pricing.bandwidth_price_received,
        );
    }
}
