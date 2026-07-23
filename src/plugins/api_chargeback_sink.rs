//! Durable ClickHouse chargeback sink.
//!
//! This plugin is intentionally independent from `api_chargeback`: it uses the
//! same pricing parser/math but owns its queue, spool, replay, metrics, and
//! optional snapshot accumulator.
//!
//! Delivery is persistence-aware by default: HTTP 200/204 alone is not success.
//! The sink requires a complete empty acknowledgement without ClickHouse
//! exception markers/headers before counting an export or deleting spool data.
//! `wait_for_async_insert=0` is rejected unless
//! `clickhouse.allow_lossy_async_insert` is explicitly enabled.
//!
//! Construction (`new`) is runtime-free shape validation: it does not create
//! spool directories, materialize secrets, build a dedicated TLS client, spawn
//! the batching worker / background tasks, or publish accepted-generation
//! observability. Live staging happens from [`Plugin::start_background_tasks`];
//! workers stay dormant until [`Plugin::commit_background_tasks`] after
//! PluginCache publication. Observability tracks the current accepted
//! generation for every stable plugin-config ID — never a process-wide
//! last-constructor-wins singleton.

use arc_swap::ArcSwap;
use async_trait::async_trait;
use chrono::{SecondsFormat, TimeZone, Utc};
use dashmap::DashMap;
use http::header::CONTENT_TYPE;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex as AsyncMutex, watch};
use tracing::warn;
use url::Url;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use super::chargeback::pricing::{ChargeComputation, PricingConfig, require_finite_charge};
use super::chargeback::{HttpBillingOutcome, http_billing_outcome};
use super::utils::response_body::{BoundedReadError, read_response_body_bounded};
use super::utils::{
    BatchConfig, BatchingLogger, HTTP_BATCH_RESPONSE_DRAIN_TIMEOUT, LoggerHooks,
    MAX_BATCH_FLUSH_INTERVAL_MS, MAX_BATCH_SIZE, MAX_BUFFER_CAPACITY, PluginHttpClient,
    RetryPolicy, wait_until_committed,
};
use super::{Plugin, StreamTransactionSummary, TransactionSummary, WsDisconnectContext};
use crate::dns::DnsCacheResolver;

const PLUGIN_NAME: &str = "api_chargeback_sink";
const STREAM_STATUS_SENTINEL: u16 = 0;
const DEFAULT_PRICING_VERSION: &str = "default";
const DEFAULT_CURRENCY: &str = "USD";
const DEFAULT_SPOOL_DIR: &str = "/var/lib/ferrum/chargeback-spool";
const STATUS_CACHE_TTL: Duration = Duration::from_secs(1);
const SNAPSHOT_FINALIZE_TIMEOUT: Duration = Duration::from_secs(5);
const SNAPSHOT_FINALIZE_RETRY_INTERVAL: Duration = Duration::from_secs(1);
const MAX_FIELD_LEN: usize = 512;
const MAX_METADATA_FIELD_LEN: usize = 256;
const SPOOL_WARN_INTERVAL_SECS: i64 = 60;
const GRPC_STATUS_OTHER_SENTINEL: u32 = u32::MAX;
/// Deployment-safe ceiling for ClickHouse export attempt count (total attempts,
/// including the initial try). Rejects the historical silent `.max(1)` rewrite
/// of `0` and unbounded `u32::MAX` budgets that can pin the sole flush worker.
const MAX_RETRY_MAX_ATTEMPTS: u32 = 32;
/// Deployment-safe ceiling for each configured inter-attempt delay field
/// (`retry.initial_delay_ms` and `retry.max_delay_ms`).
const MAX_RETRY_DELAY_MS: u64 = 60_000;
/// Worst-case cumulative inter-attempt delay budget across retries after the
/// initial try (exponential/capped schedule, ignoring jitter reduction).
const MAX_RETRY_TOTAL_DELAY_MS: u64 = 600_000;
/// Hard cap on ClickHouse acknowledgement bodies retained for exception sniffing.
///
/// Successful inserts are empty; exception text is small. Bytes are classified
/// and dropped — never logged or retained beyond the drain.
const CLICKHOUSE_ACK_BODY_LIMIT_BYTES: usize = 64 * 1024;
/// ClickHouse HTTP setting that disables persistence-aware async-insert waits.
const WAIT_FOR_ASYNC_INSERT_PARAM: &str = "wait_for_async_insert";
/// Standalone / validation constructors that omit a plugin-config resource id.
/// Production `PluginCache` always supplies the configured resource id.
const DEFAULT_PLUGIN_CONFIG_ID: &str = "__standalone__";

/// Accepted active sinks published after PluginCache commit. Keyed by stable
/// plugin-config ID so sibling configurations coexist while a newly accepted
/// generation atomically replaces the prior generation for the same ID. Drop
/// removes an entry only when it still points at that exact runtime.
static ACTIVE_SINKS: OnceLock<ArcSwap<BTreeMap<String, Arc<SinkRuntime>>>> = OnceLock::new();
static ACTIVE_SNAPSHOT_GENERATIONS: OnceLock<Mutex<BTreeMap<u64, Arc<SnapshotLifecycle>>>> =
    OnceLock::new();
static STATUS_CACHE: OnceLock<ArcSwap<Option<(Instant, String)>>> = OnceLock::new();
static NEXT_SINK_GENERATION: AtomicU64 = AtomicU64::new(1);
static ULID_COUNTER: AtomicU64 = AtomicU64::new(0);
static ULID_RANDOM_PREFIX: OnceLock<u128> = OnceLock::new();

fn active_sinks() -> &'static ArcSwap<BTreeMap<String, Arc<SinkRuntime>>> {
    ACTIVE_SINKS.get_or_init(|| ArcSwap::from_pointee(BTreeMap::new()))
}

fn status_cache() -> &'static ArcSwap<Option<(Instant, String)>> {
    STATUS_CACHE.get_or_init(|| ArcSwap::from_pointee(None))
}

fn invalidate_status_cache() {
    status_cache().store(Arc::new(None));
}

fn active_snapshot_generations() -> &'static Mutex<BTreeMap<u64, Arc<SnapshotLifecycle>>> {
    ACTIVE_SNAPSHOT_GENERATIONS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn register_snapshot_generation(lifecycle: Arc<SnapshotLifecycle>) {
    let mut generations = match active_snapshot_generations().lock() {
        Ok(generations) => generations,
        Err(poisoned) => poisoned.into_inner(),
    };
    generations.entry(lifecycle.generation).or_insert(lifecycle);
}

fn unregister_snapshot_generation(generation: u64) {
    let mut generations = match active_snapshot_generations().lock() {
        Ok(generations) => generations,
        Err(poisoned) => poisoned.into_inner(),
    };
    generations.remove(&generation);
}

fn pending_snapshot_finalizations() -> usize {
    let generations = match active_snapshot_generations().lock() {
        Ok(generations) => generations,
        Err(poisoned) => poisoned.into_inner(),
    };
    generations
        .values()
        .filter(|lifecycle| {
            lifecycle.committed.load(Ordering::Acquire)
                && !lifecycle.accepting.load(Ordering::Acquire)
                && !lifecycle.finalized.load(Ordering::Acquire)
        })
        .count()
}

/// Stop snapshot admission and durably spool every generation's final delta.
///
/// Serving modes call this after request/connection drain. Reload disposal
/// follows the same exact-once lifecycle from [`Drop for ApiChargebackSink`].
pub async fn finalize_all_snapshot_generations() {
    let generations: Vec<Arc<SnapshotLifecycle>> = {
        let generations = match active_snapshot_generations().lock() {
            Ok(generations) => generations,
            Err(poisoned) => poisoned.into_inner(),
        };
        generations.values().cloned().collect()
    };
    futures_util::future::join_all(
        generations
            .iter()
            .map(|generation| generation.finalize_within(SNAPSHOT_FINALIZE_TIMEOUT)),
    )
    .await;
}

fn register_active_sink(runtime: Arc<SinkRuntime>) {
    let key = runtime.plugin_config_id.to_string();
    active_sinks().rcu(|map| {
        if map
            .get(&key)
            .is_some_and(|existing| Arc::ptr_eq(existing, &runtime))
        {
            return Arc::clone(map);
        }
        let mut next = (**map).clone();
        next.insert(key.clone(), Arc::clone(&runtime));
        Arc::new(next)
    });
    invalidate_status_cache();
}

fn unregister_active_sink(runtime: &Arc<SinkRuntime>) {
    let key = runtime.plugin_config_id.as_ref();
    let previous = active_sinks().load_full();
    if !previous
        .get(key)
        .is_some_and(|existing| Arc::ptr_eq(existing, runtime))
    {
        return;
    }
    active_sinks().rcu(|map| {
        if !map
            .get(key)
            .is_some_and(|existing| Arc::ptr_eq(existing, runtime))
        {
            return Arc::clone(map);
        }
        let mut next = (**map).clone();
        next.remove(key);
        Arc::new(next)
    });
    invalidate_status_cache();
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SinkMode {
    #[default]
    PerEvent,
    Snapshot,
}

impl SinkMode {
    fn as_str(self) -> &'static str {
        match self {
            SinkMode::PerEvent => "per_event",
            SinkMode::Snapshot => "snapshot",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SpoolCompression {
    #[default]
    Zstd,
    None,
}

impl SpoolCompression {
    fn extension(self) -> &'static str {
        match self {
            SpoolCompression::Zstd => "ndjson.zst",
            SpoolCompression::None => "ndjson",
        }
    }
}

fn default_batch_size() -> usize {
    500
}

fn default_flush_interval_ms() -> u64 {
    2_000
}

fn default_buffer_capacity() -> usize {
    50_000
}

fn default_retry_max_attempts() -> u32 {
    5
}

fn default_retry_initial_delay_ms() -> u64 {
    250
}

fn default_retry_max_delay_ms() -> u64 {
    10_000
}

fn default_retry_jitter() -> bool {
    true
}

fn default_spool_enabled() -> bool {
    true
}

fn default_spool_dir() -> PathBuf {
    PathBuf::from(DEFAULT_SPOOL_DIR)
}

fn default_spool_max_bytes() -> u64 {
    10 * 1024 * 1024 * 1024
}

fn default_spool_replay_interval_secs() -> u64 {
    60
}

fn default_snapshot_interval_secs() -> u64 {
    30
}

fn default_snapshot_cleanup_interval_secs() -> u64 {
    300
}

fn default_snapshot_stale_entry_ttl_secs() -> u64 {
    3_600
}

fn default_clickhouse_database() -> String {
    "ferrum".to_string()
}

fn default_clickhouse_table() -> String {
    "charges_raw".to_string()
}

fn default_timeout_ms() -> u64 {
    5_000
}

fn default_verify_hostname() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClickHouseTlsConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_file: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_cert_file: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_key_file: Option<PathBuf>,
    #[serde(default = "default_verify_hostname")]
    pub verify_hostname: bool,
    pub insecure_skip_verify: bool,
}

impl Default for ClickHouseTlsConfig {
    fn default() -> Self {
        Self {
            ca_file: None,
            client_cert_file: None,
            client_key_file: None,
            verify_hostname: true,
            insecure_skip_verify: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClickHouseConfig {
    pub url: String,
    #[serde(default = "default_clickhouse_database")]
    pub database: String,
    #[serde(default = "default_clickhouse_table")]
    pub table: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_ref: Option<String>,
    pub tls: ClickHouseTlsConfig,
    pub insert_query_params: HashMap<String, String>,
    /// Explicit opt-in to fire-and-forget ClickHouse async inserts
    /// (`wait_for_async_insert=0`). Default durable mode rejects that setting
    /// because ClickHouse acknowledges buffered inserts before persistence.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_lossy_async_insert: bool,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

impl Default for ClickHouseConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            database: default_clickhouse_database(),
            table: default_clickhouse_table(),
            username: None,
            password_ref: None,
            tls: ClickHouseTlsConfig::default(),
            insert_query_params: HashMap::new(),
            allow_lossy_async_insert: false,
            timeout_ms: default_timeout_ms(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BatchSettings {
    #[serde(default = "default_batch_size")]
    pub size: usize,
    #[serde(default = "default_flush_interval_ms")]
    pub flush_interval_ms: u64,
    #[serde(default = "default_buffer_capacity")]
    pub buffer_capacity: usize,
}

impl Default for BatchSettings {
    fn default() -> Self {
        Self {
            size: default_batch_size(),
            flush_interval_ms: default_flush_interval_ms(),
            buffer_capacity: default_buffer_capacity(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RetrySettings {
    #[serde(default = "default_retry_max_attempts")]
    pub max_attempts: u32,
    #[serde(default = "default_retry_initial_delay_ms")]
    pub initial_delay_ms: u64,
    #[serde(default = "default_retry_max_delay_ms")]
    pub max_delay_ms: u64,
    #[serde(default = "default_retry_jitter")]
    pub jitter: bool,
}

impl Default for RetrySettings {
    fn default() -> Self {
        Self {
            max_attempts: default_retry_max_attempts(),
            initial_delay_ms: default_retry_initial_delay_ms(),
            max_delay_ms: default_retry_max_delay_ms(),
            jitter: default_retry_jitter(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SpoolSettings {
    #[serde(default = "default_spool_enabled")]
    pub enabled: bool,
    #[serde(default = "default_spool_dir")]
    pub dir: PathBuf,
    #[serde(default = "default_spool_max_bytes")]
    pub max_bytes: u64,
    #[serde(default = "default_spool_replay_interval_secs")]
    pub replay_interval_secs: u64,
    pub compression: SpoolCompression,
}

impl Default for SpoolSettings {
    fn default() -> Self {
        Self {
            enabled: default_spool_enabled(),
            dir: default_spool_dir(),
            max_bytes: default_spool_max_bytes(),
            replay_interval_secs: default_spool_replay_interval_secs(),
            compression: SpoolCompression::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SnapshotSettings {
    #[serde(default = "default_snapshot_interval_secs")]
    pub interval_secs: u64,
    pub emit_zero_deltas: bool,
    #[serde(default = "default_snapshot_cleanup_interval_secs")]
    pub cleanup_interval_secs: u64,
    #[serde(default = "default_snapshot_stale_entry_ttl_secs")]
    pub stale_entry_ttl_secs: u64,
}

impl Default for SnapshotSettings {
    fn default() -> Self {
        Self {
            interval_secs: default_snapshot_interval_secs(),
            emit_zero_deltas: false,
            cleanup_interval_secs: default_snapshot_cleanup_interval_secs(),
            stale_entry_ttl_secs: default_snapshot_stale_entry_ttl_secs(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ApiChargebackSinkConfig {
    pub mode: SinkMode,
    pub clickhouse: ClickHouseConfig,
    pub batch: BatchSettings,
    pub retry: RetrySettings,
    pub spool: SpoolSettings,
    pub snapshot: SnapshotSettings,
    pub pricing_version: String,
    pub currency: String,
    pub include_request_id: bool,
    pub include_trace_id: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pricing_tiers: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bandwidth_pricing: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_connection_pricing: Option<Value>,
}

impl Default for ApiChargebackSinkConfig {
    fn default() -> Self {
        Self {
            mode: SinkMode::PerEvent,
            clickhouse: ClickHouseConfig::default(),
            batch: BatchSettings::default(),
            retry: RetrySettings::default(),
            spool: SpoolSettings::default(),
            snapshot: SnapshotSettings::default(),
            pricing_version: DEFAULT_PRICING_VERSION.to_string(),
            currency: DEFAULT_CURRENCY.to_string(),
            include_request_id: true,
            include_trace_id: true,
            pricing_tiers: None,
            bandwidth_pricing: None,
            stream_connection_pricing: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChargeEvent {
    pub event_id: String,
    pub received_at: i64,
    pub node_id: String,
    pub namespace: String,
    pub consumer_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consumer_name: Option<String>,
    pub proxy_id: String,
    pub proxy_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_id: Option<String>,
    /// Billable status: wire HTTP for ordinary requests, canonical effective
    /// HTTP status for native gRPC and translated gRPC-Web.
    pub status_code: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_status_code: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grpc_status: Option<u32>,
    pub protocol: String,
    pub call_count: u32,
    pub charge_call: f64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub charge_bytes_sent: f64,
    pub charge_bytes_received: f64,
    pub charge_total: f64,
    pub currency: String,
    pub pricing_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_id: Option<String>,
}

#[derive(Clone)]
struct SinkSummary {
    mode: SinkMode,
    pricing_version: String,
    endpoint: String,
    database: String,
    table: String,
    batch_size: usize,
    flush_interval_ms: u64,
    retry_max_attempts: u32,
    retry_initial_delay_ms: u64,
    retry_max_delay_ms: u64,
    retry_jitter: bool,
}

/// Worst-case cumulative inter-attempt delay for `max_attempts` total tries
/// (including the initial). Matches [`RetryPolicy::backoff_delay`]'s
/// exponential/capped schedule, excludes the initial attempt, ignores jitter
/// reduction, and uses overflow-safe saturating arithmetic.
fn worst_case_inter_attempt_delay_ms(
    max_attempts: u32,
    initial_delay_ms: u64,
    max_delay_ms: u64,
) -> u64 {
    if max_attempts <= 1 {
        return 0;
    }
    let cap_ms = max_delay_ms.max(initial_delay_ms);
    let mut total: u64 = 0;
    for attempt in 1..max_attempts {
        let shift = (attempt - 1).min(63);
        let grown = initial_delay_ms.saturating_mul(1u64 << shift);
        let capped = grown.min(cap_ms);
        total = total.saturating_add(capped);
    }
    total
}

pub struct ApiChargebackSink {
    pricing: PricingConfig,
    config: Arc<ApiChargebackSinkConfig>,
    node_id: Arc<str>,
    /// Stable plugin-config resource id used for accepted-generation
    /// observability. Production cache supplies `PluginConfig.id`; standalone
    /// constructors fall back to [`DEFAULT_PLUGIN_CONFIG_ID`].
    plugin_config_id: Arc<str>,
    /// Shared gateway client retained for dedicated ClickHouse client build at start.
    http_client: PluginHttpClient,
    /// Live sink runtime after [`Plugin::start_background_tasks`].
    runtime: OnceLock<Arc<SinkRuntime>>,
    snapshot_accumulator: OnceLock<Arc<SnapshotAccumulator>>,
    /// Awaitable ownership of snapshot admission and the periodic emitter.
    /// Present only in snapshot mode.
    snapshot_lifecycle: OnceLock<Arc<SnapshotLifecycle>>,
    /// Handles for the per-instance background loops (spool replayer and, in
    /// per-event mode, all runtime work). Snapshot emitter ownership lives in
    /// [`SnapshotLifecycle`] so reload/shutdown can await its final handoff.
    background_tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    start_lock: Mutex<()>,
}

struct SinkRuntime {
    plugin_config_id: Arc<str>,
    generation: u64,
    summary: SinkSummary,
    logger: BatchingLogger<ChargeEvent>,
    metrics: Arc<SinkMetrics>,
    spool: Option<Arc<SpoolManager>>,
}

struct SnapshotLifecycle {
    generation: u64,
    runtime: Arc<SinkRuntime>,
    accumulator: Arc<SnapshotAccumulator>,
    config: Arc<ApiChargebackSinkConfig>,
    node_id: Arc<str>,
    accepting: AtomicBool,
    in_flight: AtomicUsize,
    committed: AtomicBool,
    finalized: AtomicBool,
    shutdown_tx: watch::Sender<bool>,
    task: Mutex<Option<tokio::task::JoinHandle<bool>>>,
    emission_lock: Arc<Mutex<()>>,
    finalize_lock: AsyncMutex<()>,
}

struct SnapshotAdmissionGuard<'a> {
    in_flight: &'a AtomicUsize,
}

impl Drop for SnapshotAdmissionGuard<'_> {
    fn drop(&mut self) {
        self.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

impl SnapshotLifecycle {
    fn admit(&self) -> Option<SnapshotAdmissionGuard<'_>> {
        if !self.accepting.load(Ordering::Acquire) {
            return None;
        }
        self.in_flight.fetch_add(1, Ordering::AcqRel);
        if !self.accepting.load(Ordering::Acquire) {
            self.in_flight.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        Some(SnapshotAdmissionGuard {
            in_flight: &self.in_flight,
        })
    }

    fn commit(&self) {
        self.committed.store(true, Ordering::Release);
    }

    async fn finalize_attempt(&self, deadline: Instant) -> bool {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return false;
        }
        let _guard = match tokio::time::timeout(remaining, self.finalize_lock.lock()).await {
            Ok(guard) => guard,
            Err(_) => return false,
        };
        if self.finalized.load(Ordering::Acquire) {
            unregister_snapshot_generation(self.generation);
            return true;
        }

        self.accepting.store(false, Ordering::Release);
        while self.in_flight.load(Ordering::Acquire) > 0 {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                invalidate_status_cache();
                return false;
            }
            tokio::time::sleep(remaining.min(Duration::from_millis(1))).await;
        }

        let _ = self.shutdown_tx.send(true);
        let mut task = {
            let mut task = match self.task.lock() {
                Ok(task) => task,
                Err(poisoned) => poisoned.into_inner(),
            };
            task.take()
        };
        if task.is_none() && self.committed.load(Ordering::Acquire) {
            let accumulator = Arc::clone(&self.accumulator);
            let runtime = Arc::clone(&self.runtime);
            let config = Arc::clone(&self.config);
            let node_id = Arc::clone(&self.node_id);
            let emission_lock = Arc::clone(&self.emission_lock);
            task = Some(tokio::task::spawn_blocking(move || {
                emit_final_snapshot_to_spool(
                    &accumulator,
                    &runtime,
                    &config,
                    &node_id,
                    &emission_lock,
                )
            }));
        }
        let durable = match task {
            Some(mut task) => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    let mut slot = match self.task.lock() {
                        Ok(slot) => slot,
                        Err(poisoned) => poisoned.into_inner(),
                    };
                    *slot = Some(task);
                    invalidate_status_cache();
                    return false;
                }
                match tokio::time::timeout(remaining, &mut task).await {
                    Ok(Ok(durable)) => durable,
                    Ok(Err(_)) if self.committed.load(Ordering::Acquire) => {
                        self.runtime.metrics.record_failure(
                            FailureReason::Serialize,
                            "snapshot finalizer task did not complete",
                        );
                        false
                    }
                    Ok(Err(_)) => true,
                    Err(_) => {
                        let mut slot = match self.task.lock() {
                            Ok(slot) => slot,
                            Err(poisoned) => poisoned.into_inner(),
                        };
                        *slot = Some(task);
                        invalidate_status_cache();
                        return false;
                    }
                }
            }
            None => true,
        };
        if durable {
            self.finalized.store(true, Ordering::Release);
            unregister_snapshot_generation(self.generation);
        }
        invalidate_status_cache();
        durable
    }

    async fn finalize_within(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            if self.finalize_attempt(deadline).await {
                return true;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                warn!(
                    plugin = PLUGIN_NAME,
                    generation = self.generation,
                    timeout_ms = timeout.as_millis(),
                    "Chargeback sink final snapshot handoff timed out; generation state retained"
                );
                return false;
            }
            tokio::time::sleep(remaining.min(SNAPSHOT_FINALIZE_RETRY_INTERVAL)).await;
        }
    }

    fn finalize_without_await(&self) {
        if self.finalized.load(Ordering::Acquire) {
            unregister_snapshot_generation(self.generation);
            return;
        }
        self.accepting.store(false, Ordering::Release);
        let _ = self.shutdown_tx.send(true);
        let task = {
            let mut task = match self.task.lock() {
                Ok(task) => task,
                Err(poisoned) => poisoned.into_inner(),
            };
            task.take()
        };
        if let Some(task) = task {
            task.abort();
        }
        let durable = if self.committed.load(Ordering::Acquire) {
            emit_final_snapshot_to_spool(
                &self.accumulator,
                &self.runtime,
                &self.config,
                &self.node_id,
                &self.emission_lock,
            )
        } else {
            true
        };
        if durable {
            self.finalized.store(true, Ordering::Release);
            unregister_snapshot_generation(self.generation);
        }
        invalidate_status_cache();
    }
}

impl Drop for SnapshotLifecycle {
    fn drop(&mut self) {
        let task = match self.task.get_mut() {
            Ok(task) => task,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(task) = task.take() {
            task.abort();
        }
    }
}

struct SinkMetrics {
    events_enqueued_total: AtomicU64,
    events_exported_total: AtomicU64,
    failures_total: AtomicU64,
    failure_reasons: FailureReasonCounters,
    queue_high_water_hits_total: AtomicU64,
    spool_drops_total: AtomicU64,
    spool_available: AtomicBool,
    spool_prepare_failures_total: AtomicU64,
    snapshot_emits_total: AtomicU64,
    last_success_at: AtomicI64,
    last_failure_at: AtomicI64,
    last_replay_at: AtomicI64,
    last_failure_reason: RwLock<Option<String>>,
    latency: LatencyHistogram,
}

impl Default for SinkMetrics {
    fn default() -> Self {
        Self {
            events_enqueued_total: AtomicU64::new(0),
            events_exported_total: AtomicU64::new(0),
            failures_total: AtomicU64::new(0),
            failure_reasons: FailureReasonCounters::default(),
            queue_high_water_hits_total: AtomicU64::new(0),
            spool_drops_total: AtomicU64::new(0),
            spool_available: AtomicBool::new(false),
            spool_prepare_failures_total: AtomicU64::new(0),
            snapshot_emits_total: AtomicU64::new(0),
            last_success_at: AtomicI64::new(0),
            last_failure_at: AtomicI64::new(0),
            last_replay_at: AtomicI64::new(0),
            last_failure_reason: RwLock::new(None),
            latency: LatencyHistogram::default(),
        }
    }
}

#[derive(Default)]
struct FailureReasonCounters {
    network: AtomicU64,
    http_4xx: AtomicU64,
    http_5xx: AtomicU64,
    serialize: AtomicU64,
    tls: AtomicU64,
    timeout: AtomicU64,
}

#[derive(Debug, Clone, Copy)]
enum FailureReason {
    Network,
    Http4xx,
    Http5xx,
    Serialize,
    Tls,
    Timeout,
}

impl FailureReason {
    fn as_str(self) -> &'static str {
        match self {
            FailureReason::Network => "network",
            FailureReason::Http4xx => "http_4xx",
            FailureReason::Http5xx => "http_5xx",
            FailureReason::Serialize => "serialize",
            FailureReason::Tls => "tls",
            FailureReason::Timeout => "timeout",
        }
    }
}

impl SinkMetrics {
    fn record_failure(&self, reason: FailureReason, detail: impl Into<String>) {
        self.failures_total.fetch_add(1, Ordering::Relaxed);
        match reason {
            FailureReason::Network => self.failure_reasons.network.fetch_add(1, Ordering::Relaxed),
            FailureReason::Http4xx => self
                .failure_reasons
                .http_4xx
                .fetch_add(1, Ordering::Relaxed),
            FailureReason::Http5xx => self
                .failure_reasons
                .http_5xx
                .fetch_add(1, Ordering::Relaxed),
            FailureReason::Serialize => self
                .failure_reasons
                .serialize
                .fetch_add(1, Ordering::Relaxed),
            FailureReason::Tls => self.failure_reasons.tls.fetch_add(1, Ordering::Relaxed),
            FailureReason::Timeout => self.failure_reasons.timeout.fetch_add(1, Ordering::Relaxed),
        };
        self.last_failure_at
            .store(unix_timestamp_seconds(), Ordering::Relaxed);
        if let Ok(mut slot) = self.last_failure_reason.write() {
            *slot = Some(bound_string(&detail.into(), MAX_METADATA_FIELD_LEN));
        }
        invalidate_status_cache();
    }

    fn record_success(&self, event_count: usize, elapsed: Duration) {
        self.events_exported_total
            .fetch_add(event_count as u64, Ordering::Relaxed);
        self.last_success_at
            .store(unix_timestamp_seconds(), Ordering::Relaxed);
        self.latency.observe(elapsed.as_secs_f64());
        invalidate_status_cache();
    }
}

struct LatencyHistogram {
    buckets: &'static [f64],
    counts: Vec<AtomicU64>,
    sum_bits: AtomicU64,
    count: AtomicU64,
}

impl Default for LatencyHistogram {
    fn default() -> Self {
        const BUCKETS: &[f64] = &[
            0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
        ];
        Self {
            buckets: BUCKETS,
            counts: BUCKETS.iter().map(|_| AtomicU64::new(0)).collect(),
            sum_bits: AtomicU64::new(0f64.to_bits()),
            count: AtomicU64::new(0),
        }
    }
}

impl LatencyHistogram {
    fn observe(&self, seconds: f64) {
        self.count.fetch_add(1, Ordering::Relaxed);
        add_f64_atomic(&self.sum_bits, seconds);
        for (idx, bucket) in self.buckets.iter().enumerate() {
            if seconds <= *bucket {
                self.counts[idx].fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

#[derive(Clone)]
struct ClickHouseFlushConfig {
    http: ClickHouseHttpClient,
    insert_url: String,
    username: Option<String>,
    password: Option<String>,
    timeout: Duration,
    metrics: Arc<SinkMetrics>,
}

#[derive(Clone)]
enum ClickHouseHttpClient {
    Shared(Box<PluginHttpClient>),
    Dedicated(reqwest::Client),
}

impl ClickHouseHttpClient {
    async fn execute(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<reqwest::Response, reqwest::Error> {
        match self {
            ClickHouseHttpClient::Shared(client) => client.execute(request, PLUGIN_NAME).await,
            ClickHouseHttpClient::Dedicated(_) => request.send().await,
        }
    }
}

impl ApiChargebackSink {
    #[allow(dead_code)] // direct/test construction; production factory supplies the config id
    pub fn new(
        raw_config: &Value,
        http_client: PluginHttpClient,
        namespace: &str,
    ) -> Result<Self, String> {
        Self::new_with_config_id(raw_config, http_client, namespace, None)
    }

    /// Construct with an optional stable plugin-config resource id.
    ///
    /// `plugin_config_id` partitions accepted-generation status/metrics across
    /// sibling sink instances. Blank supplied ids fail closed. `None` uses
    /// [`DEFAULT_PLUGIN_CONFIG_ID`] for standalone validation/tests.
    pub fn new_with_config_id(
        raw_config: &Value,
        http_client: PluginHttpClient,
        _namespace: &str,
        plugin_config_id: Option<&str>,
    ) -> Result<Self, String> {
        if !raw_config.is_object() {
            return Err(format!("{PLUGIN_NAME}: config must be an object"));
        }
        if raw_config.get("schema").is_some() || raw_config.get("schema_ref").is_some() {
            return Err(format!(
                "{PLUGIN_NAME}: 'schema' / 'schema_ref' is not supported \
                 (transaction-log schema customization applies only to log-shipping plugins; \
                 see docs/plugins.md)"
            ));
        }

        let plugin_config_id = match plugin_config_id {
            Some(id) if id.trim().is_empty() => {
                return Err(format!(
                    "{PLUGIN_NAME}: plugin config id must be a non-empty stable identity"
                ));
            }
            Some(id) => Arc::<str>::from(id),
            None => Arc::<str>::from(DEFAULT_PLUGIN_CONFIG_ID),
        };

        let config: ApiChargebackSinkConfig = serde_json::from_value(raw_config.clone())
            .map_err(|error| format!("{PLUGIN_NAME}: invalid config: {error}"))?;
        validate_config(&config)?;
        let pricing = PricingConfig::from_config(raw_config, PLUGIN_NAME)?;
        if !pricing.has_any_pricing() {
            return Err(format!(
                "{PLUGIN_NAME}: at least one of 'pricing_tiers', 'bandwidth_pricing', or \
                 'stream_connection_pricing' must be configured"
            ));
        }

        let parsed_url = parse_clickhouse_url(&config.clickhouse.url)?;
        // The ClickHouse sink builds a dedicated client, so screen a literal-IP
        // clickhouse.url against the egress policy at config-load (the shared
        // DNS-cache screen still applies at send time).
        crate::plugins::utils::log_helpers::screen_url_host_egress(
            PLUGIN_NAME,
            "clickhouse.url",
            &parsed_url,
            http_client.backend_allow_ips(),
        )?;

        Ok(Self {
            pricing,
            config: Arc::new(config),
            node_id: Arc::<str>::from(resolve_node_id()),
            plugin_config_id,
            http_client,
            runtime: OnceLock::new(),
            snapshot_accumulator: OnceLock::new(),
            snapshot_lifecycle: OnceLock::new(),
            background_tasks: Mutex::new(Vec::new()),
            start_lock: Mutex::new(()),
        })
    }

    fn activate(&self) -> Result<(), String> {
        // Fallible setup first. Staged workers share one commit gate and stay
        // dormant until commit_background_tasks; ACTIVE_SINKS stays unpublished.
        let parsed_url = parse_clickhouse_url(&self.config.clickhouse.url)?;
        let endpoint = sanitized_endpoint(&parsed_url);
        let insert_url = build_insert_url(&parsed_url, &self.config.clickhouse);
        let password = resolve_password_ref(self.config.clickhouse.password_ref.as_deref())?;
        let http = build_clickhouse_http_client(&self.config.clickhouse, &self.http_client)?;
        // Build the spool-replay client before staging so a TLS/file failure
        // cannot orphan an already-staged BatchingLogger or replayer task.
        let replay_http = if self.config.spool.enabled {
            Some(build_clickhouse_http_client(
                &self.config.clickhouse,
                &self.http_client,
            )?)
        } else {
            None
        };
        let metrics = Arc::new(SinkMetrics::default());
        let spool = if self.config.spool.enabled {
            Some(Arc::new(SpoolManager::new(
                self.config.spool.clone(),
                Arc::clone(&self.node_id),
                Arc::clone(&metrics),
            )?))
        } else {
            None
        };

        let flush_config = ClickHouseFlushConfig {
            http,
            insert_url: insert_url.clone(),
            username: self.config.clickhouse.username.clone(),
            password,
            timeout: Duration::from_millis(self.config.clickhouse.timeout_ms),
            metrics: Arc::clone(&metrics),
        };

        let failed_spool = spool.clone();
        let overflow_spool = spool.clone();
        let snapshot_events_are_pre_spooled = self.config.mode == SinkMode::Snapshot;
        let overflow_metrics = Arc::clone(&metrics);
        let hooks = LoggerHooks {
            on_failed_batch: Some(Arc::new(move |batch, error| {
                if snapshot_events_are_pre_spooled {
                    return;
                }
                if let Some(spool) = failed_spool.as_ref() {
                    if let Err(spool_error) = spool.write_events(&batch) {
                        warn!(
                            plugin = PLUGIN_NAME,
                            error = %spool_error,
                            original_error = %error,
                            "Failed to spool chargeback sink batch after export failure"
                        );
                    }
                } else {
                    warn!(
                        plugin = PLUGIN_NAME,
                        error = %error,
                        "Chargeback sink export failed and spool is disabled; batch was lost"
                    );
                }
            })),
            on_overflow: Some(Arc::new(move |event, reason| {
                overflow_metrics
                    .queue_high_water_hits_total
                    .fetch_add(1, Ordering::Relaxed);
                if snapshot_events_are_pre_spooled {
                    invalidate_status_cache();
                    return;
                }
                if let Some(spool) = overflow_spool.as_ref() {
                    if let Err(error) = spool.write_events(&[event]) {
                        warn!(
                            plugin = PLUGIN_NAME,
                            overflow_reason = reason,
                            error = %error,
                            "Failed to spool chargeback sink overflow event"
                        );
                    }
                } else {
                    warn!(
                        plugin = PLUGIN_NAME,
                        overflow_reason = reason,
                        "Chargeback sink queue overflowed and spool is disabled; event was lost"
                    );
                }
                invalidate_status_cache();
            })),
            on_high_water: Some(Arc::new(|_, _| {
                invalidate_status_cache();
            })),
            high_watermark_percent: 80,
        };

        let (commit_tx, commit_rx) = watch::channel(false);
        let logger = BatchingLogger::spawn_with_hooks_on_commit_gate(
            BatchConfig {
                batch_size: self.config.batch.size,
                flush_interval: Duration::from_millis(self.config.batch.flush_interval_ms),
                buffer_capacity: self.config.batch.buffer_capacity,
                // Honor the advertised retry schema: bounded exponential
                // backoff from initial_delay_ms up to max_delay_ms, with
                // optional full jitter (finding #77).
                retry: RetryPolicy {
                    max_attempts: self.config.retry.max_attempts,
                    delay: Duration::from_millis(self.config.retry.initial_delay_ms),
                    max_delay: Duration::from_millis(self.config.retry.max_delay_ms),
                    jitter: self.config.retry.jitter,
                },
                plugin_name: PLUGIN_NAME,
            },
            hooks,
            commit_tx,
            commit_rx,
            {
                let flush_config = flush_config.clone();
                move |batch| {
                    let flush_config = flush_config.clone();
                    async move { send_batch(&flush_config, batch).await }
                }
            },
        );

        let generation = NEXT_SINK_GENERATION.fetch_add(1, Ordering::Relaxed);
        let runtime = Arc::new(SinkRuntime {
            plugin_config_id: Arc::clone(&self.plugin_config_id),
            generation,
            summary: SinkSummary {
                mode: self.config.mode,
                pricing_version: self.config.pricing_version.clone(),
                endpoint,
                database: self.config.clickhouse.database.clone(),
                table: self.config.clickhouse.table.clone(),
                batch_size: self.config.batch.size,
                flush_interval_ms: self.config.batch.flush_interval_ms,
                retry_max_attempts: self.config.retry.max_attempts,
                retry_initial_delay_ms: self.config.retry.initial_delay_ms,
                retry_max_delay_ms: self.config.retry.max_delay_ms,
                retry_jitter: self.config.retry.jitter,
            },
            logger,
            metrics,
            spool,
        });

        let mut background_tasks = Vec::new();
        if let (Some(spool), Some(replay_http)) = (runtime.spool.clone(), replay_http) {
            background_tasks.push(start_spool_replayer(
                Arc::clone(&spool),
                runtime.summary.clone(),
                ClickHouseFlushConfig {
                    http: replay_http,
                    insert_url,
                    username: self.config.clickhouse.username.clone(),
                    password: flush_config.password.clone(),
                    timeout: Duration::from_millis(self.config.clickhouse.timeout_ms),
                    metrics: Arc::clone(&runtime.metrics),
                },
                self.config.batch.size,
                self.config.spool.replay_interval_secs,
                runtime.logger.commit_sender().subscribe(),
            ));
        }

        let snapshot_lifecycle = if self.config.mode == SinkMode::Snapshot {
            let accumulator = Arc::new(SnapshotAccumulator::new());
            let emission_lock = Arc::new(Mutex::new(()));
            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            let task = start_snapshot_task(
                Arc::clone(&accumulator),
                Arc::clone(&runtime),
                Arc::clone(&self.config),
                Arc::clone(&self.node_id),
                runtime.logger.commit_sender().subscribe(),
                shutdown_rx,
                Arc::clone(&emission_lock),
            );
            Some(Arc::new(SnapshotLifecycle {
                generation: runtime.generation,
                runtime: Arc::clone(&runtime),
                accumulator,
                config: Arc::clone(&self.config),
                node_id: Arc::clone(&self.node_id),
                // The cache atomically publishes this staged instance just
                // before commit_background_tasks runs. Admission must already
                // be ready for readers that observe that new cache snapshot;
                // external workers and spool activity remain commit-gated.
                accepting: AtomicBool::new(true),
                in_flight: AtomicUsize::new(0),
                committed: AtomicBool::new(false),
                finalized: AtomicBool::new(false),
                shutdown_tx,
                task: Mutex::new(Some(task)),
                emission_lock,
                finalize_lock: AsyncMutex::new(()),
            }))
        } else {
            None
        };

        // Stage ownership. Abort every staged task on any failure so infinite
        // replayer/snapshot loops cannot outlive a rejected activation. The
        // BatchingLogger is owned by `runtime` and is not published to
        // ACTIVE_SINKS until commit succeeds; dropping `runtime` cancels its
        // commit gate. ACTIVE_SINKS is published only after `self.runtime` is set.
        let abort_tasks = |tasks: &mut Vec<tokio::task::JoinHandle<()>>| {
            for task in tasks.drain(..) {
                task.abort();
            }
        };

        let mut owned_tasks = match self.background_tasks.lock() {
            Ok(guard) => guard,
            Err(_) => {
                abort_tasks(&mut background_tasks);
                if let Some(lifecycle) = snapshot_lifecycle.as_ref() {
                    lifecycle.finalize_without_await();
                }
                return Err(format!(
                    "{PLUGIN_NAME}: background task lock poisoned; refusing to start"
                ));
            }
        };

        *owned_tasks = std::mem::take(&mut background_tasks);

        if let Some(lifecycle) = snapshot_lifecycle.as_ref()
            && self
                .snapshot_accumulator
                .set(Arc::clone(&lifecycle.accumulator))
                .is_err()
        {
            abort_tasks(&mut owned_tasks);
            lifecycle.finalize_without_await();
            return Err(format!(
                "{PLUGIN_NAME}: snapshot accumulator already activated; refusing duplicate start"
            ));
        }

        if self.runtime.set(Arc::clone(&runtime)).is_err() {
            abort_tasks(&mut owned_tasks);
            if let Some(lifecycle) = snapshot_lifecycle.as_ref() {
                lifecycle.finalize_without_await();
            }
            return Err(format!(
                "{PLUGIN_NAME}: runtime already activated; refusing duplicate start"
            ));
        }

        if let Some(lifecycle) = snapshot_lifecycle
            && let Err(lifecycle) = self.snapshot_lifecycle.set(lifecycle)
        {
            abort_tasks(&mut owned_tasks);
            lifecycle.finalize_without_await();
            return Err(format!(
                "{PLUGIN_NAME}: snapshot lifecycle already activated; refusing duplicate start"
            ));
        }

        Ok(())
    }

    fn enqueue(&self, event: ChargeEvent) {
        let Some(runtime) = self.runtime.get() else {
            return;
        };
        runtime
            .metrics
            .events_enqueued_total
            .fetch_add(1, Ordering::Relaxed);
        runtime.logger.try_send(event);
        invalidate_status_cache();
    }

    /// Whether this instance currently owns a published slot in the
    /// process-global accepted-generation registry. Staging
    /// (`start_background_tasks`) must leave this false; only
    /// [`Plugin::commit_background_tasks`] publishes ownership.
    #[allow(dead_code)] // lifecycle tests observe pre/post-commit publication
    pub fn owns_active_sink(&self) -> bool {
        let Some(runtime) = self.runtime.get() else {
            return false;
        };
        active_sinks()
            .load_full()
            .get(runtime.plugin_config_id.as_ref())
            .is_some_and(|published| Arc::ptr_eq(published, runtime))
    }

    /// Accepted observability generation for this instance, if activated.
    #[allow(dead_code)] // multi-instance lifecycle tests assert exact-generation removal
    pub fn active_generation(&self) -> Option<u64> {
        self.runtime.get().map(|runtime| runtime.generation)
    }

    /// Stable plugin-config id used for observability identity.
    #[allow(dead_code)] // multi-instance lifecycle tests assert exact-id removal
    pub fn plugin_config_id(&self) -> &str {
        &self.plugin_config_id
    }

    // The library's hidden test-support module calls this accessor; the binary
    // compiles this module separately and cannot observe that use.
    #[allow(dead_code)]
    pub(crate) fn snapshot_accumulator_for_tests(&self) -> Option<Arc<SnapshotAccumulator>> {
        self.snapshot_accumulator.get().cloned()
    }

    #[allow(dead_code)]
    pub(crate) async fn finalize_snapshot_for_tests(&self) -> Option<bool> {
        let lifecycle = self.snapshot_lifecycle.get()?;
        Some(
            lifecycle
                .finalize_attempt(Instant::now() + SNAPSHOT_FINALIZE_TIMEOUT)
                .await,
        )
    }

    #[allow(dead_code)]
    pub(crate) async fn finalize_snapshot_with_held_admission_for_tests(
        &self,
        timeout: Duration,
    ) -> Option<bool> {
        let lifecycle = self.snapshot_lifecycle.get()?;
        let _admission = lifecycle.admit()?;
        Some(lifecycle.finalize_attempt(Instant::now() + timeout).await)
    }

    #[allow(dead_code)]
    pub(crate) fn snapshot_finalized_for_tests(&self) -> Option<bool> {
        self.snapshot_lifecycle
            .get()
            .map(|lifecycle| lifecycle.finalized.load(Ordering::Acquire))
    }

    #[allow(dead_code)]
    pub(crate) fn snapshot_generation_registered_for_tests(&self) -> Option<bool> {
        let lifecycle = self.snapshot_lifecycle.get()?;
        let generations = match active_snapshot_generations().lock() {
            Ok(generations) => generations,
            Err(poisoned) => poisoned.into_inner(),
        };
        Some(
            generations
                .get(&lifecycle.generation)
                .is_some_and(|registered| Arc::ptr_eq(registered, lifecycle)),
        )
    }

    #[allow(dead_code)]
    pub(crate) fn emit_snapshot_tick_for_tests(&self) -> Option<Result<usize, String>> {
        let lifecycle = self.snapshot_lifecycle.get()?;
        Some(emit_periodic_snapshot(
            &lifecycle.accumulator,
            &lifecycle.runtime,
            &lifecycle.config,
            &lifecycle.node_id,
            &lifecycle.emission_lock,
        ))
    }
}

impl Drop for ApiChargebackSink {
    fn drop(&mut self) {
        if let Some(lifecycle) = self.snapshot_lifecycle.get()
            && !lifecycle.finalized.load(Ordering::Acquire)
        {
            if let Ok(handle) = tokio::runtime::Handle::try_current()
                && handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread
            {
                let lifecycle = Arc::clone(lifecycle);
                tokio::task::block_in_place(|| {
                    handle.block_on(async move {
                        lifecycle.finalize_within(SNAPSHOT_FINALIZE_TIMEOUT).await;
                    });
                });
            } else {
                // Current-thread tests and teardown after runtime exit cannot
                // synchronously await a Tokio task. No task can run
                // concurrently on the current-thread path while Drop is
                // executing, so abort it and perform the same final spool
                // handoff inline.
                lifecycle.finalize_without_await();
            }
        }

        // Stop the per-instance spool replay loop so a config reload or an
        // admin-validation throwaway does not leak an immortal task. The
        // BatchingLogger flush loop remains covered by the shared queued-work
        // lifecycle tracked in issue #2533.
        if let Ok(mut tasks) = self.background_tasks.lock() {
            for task in tasks.drain(..) {
                task.abort();
            }
        }
        let Some(runtime) = self.runtime.get() else {
            // Never started: ACTIVE_SINKS was never published for this instance.
            return;
        };
        // Remove only when this exact runtime is still the accepted generation
        // for its plugin-config ID. Siblings and a newer replacement stay
        // published; a validation throwaway that never committed is a no-op.
        unregister_active_sink(runtime);
    }
}

#[async_trait]
impl Plugin for ApiChargebackSink {
    fn name(&self) -> &str {
        PLUGIN_NAME
    }

    fn priority(&self) -> u16 {
        super::priority::API_CHARGEBACK_SINK
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::ALL_PROTOCOLS
    }

    fn start_background_tasks(&self) -> Result<(), String> {
        if self.runtime.get().is_some() {
            return Ok(());
        }
        let _guard = self.start_lock.lock().map_err(|_| {
            format!("{PLUGIN_NAME}: start lock poisoned; refusing to start chargeback sink")
        })?;
        if self.runtime.get().is_some() {
            return Ok(());
        }
        let _runtime = tokio::runtime::Handle::try_current().map_err(|_| {
            format!("{PLUGIN_NAME}: start_background_tasks requires a Tokio runtime")
        })?;
        self.activate()
    }

    fn commit_background_tasks(&self) {
        let Some(runtime) = self.runtime.get() else {
            return;
        };
        // Release flush/replay/snapshot dormancy before publishing diagnostics
        // so the live instance cannot appear active while workers are gated.
        runtime.logger.commit();
        if let Some(lifecycle) = self.snapshot_lifecycle.get() {
            lifecycle.commit();
            register_snapshot_generation(Arc::clone(lifecycle));
        }
        register_active_sink(Arc::clone(runtime));
    }

    async fn log(&self, summary: &TransactionSummary) {
        // Shadow/mirror summaries retain the primary consumer identity for
        // logging correlation, but they are internal backend probes — never
        // consumer-billable per-call or bandwidth charges (issue #2437).
        if summary.mirror {
            return;
        }

        let consumer = match summary.consumer_username.as_deref() {
            Some(c) if !c.is_empty() => c,
            _ => return,
        };
        let outcome = http_billing_outcome(summary);
        let Some(charge) = self.pricing.compute_http(
            outcome.status_code,
            summary.bytes_sent,
            summary.bytes_received,
        ) else {
            return;
        };
        if self.config.mode == SinkMode::Snapshot {
            if let Some(lifecycle) = self.snapshot_lifecycle.get()
                && let Some(_admission) = lifecycle.admit()
            {
                lifecycle
                    .accumulator
                    .record_http(summary, consumer, outcome, charge);
            }
            return;
        }
        self.enqueue(event_from_http_summary(
            summary,
            consumer,
            outcome,
            charge,
            &self.config,
            &self.node_id,
            None,
        ));
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
        if self.config.mode == SinkMode::Snapshot {
            if let Some(lifecycle) = self.snapshot_lifecycle.get()
                && let Some(_admission) = lifecycle.admit()
            {
                lifecycle
                    .accumulator
                    .record_stream(summary, consumer, charge);
            }
            return;
        }
        self.enqueue(event_from_stream_summary(
            summary,
            consumer,
            charge,
            &self.config,
            &self.node_id,
            None,
        ));
    }

    fn requires_ws_disconnect_hooks(&self) -> bool {
        true
    }

    async fn on_ws_disconnect(&self, summary: &WsDisconnectContext) {
        let consumer = match summary.consumer_username.as_deref() {
            Some(c) if !c.is_empty() => c,
            _ => return,
        };
        let Some(charge) = self.pricing.compute_websocket_bandwidth(
            summary.bytes_client_to_backend,
            summary.bytes_backend_to_client,
        ) else {
            return;
        };
        if self.config.mode == SinkMode::Snapshot {
            if let Some(lifecycle) = self.snapshot_lifecycle.get()
                && let Some(_admission) = lifecycle.admit()
            {
                lifecycle
                    .accumulator
                    .record_websocket(summary, consumer, charge);
            }
            return;
        }
        self.enqueue(event_from_ws_summary(
            summary,
            consumer,
            charge,
            &self.config,
            &self.node_id,
            None,
        ));
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        parse_clickhouse_url(&self.config.clickhouse.url)
            .ok()
            .and_then(|url| url.host_str().map(str::to_string))
            .into_iter()
            .collect()
    }
}

pub fn render_status_json() -> String {
    let cache = status_cache();
    let cached = cache.load();
    if let Some((cached_at, ref output)) = **cached
        && cached_at.elapsed() < STATUS_CACHE_TTL
    {
        return output.clone();
    }

    let body = serde_json::to_string(&aggregate_status_snapshot(&active_sinks().load_full()))
        .unwrap_or_else(|_| {
            "{\"enabled\":false,\"instance_count\":0,\"snapshot_finalizations_pending\":0,\"totals\":{},\"instances\":[]}".to_string()
        });

    cache.store(Arc::new(Some((Instant::now(), body.clone()))));
    body
}

pub fn render_prometheus() -> String {
    let sinks = active_sinks().load_full();
    let pending_finalizations = pending_snapshot_finalizations();
    if sinks.is_empty() && pending_finalizations == 0 {
        return String::new();
    }
    render_prometheus_for_sinks(sinks.as_ref(), pending_finalizations)
}

fn disabled_status_snapshot() -> Value {
    serde_json::json!({
        "enabled": false,
        "instance_count": 0,
        "snapshot_finalizations_pending": pending_snapshot_finalizations(),
        "totals": {
            "queue": {"depth": 0, "capacity": 0, "high_water_hits_total": 0},
            "spool": {
                "files": 0,
                "bytes": 0,
                "drops_total": 0,
                "prepare_failures_total": 0,
                "available": false
            },
            "export": {
                "events_enqueued_total": 0,
                "events_exported_total": 0,
                "failures_total": 0
            }
        },
        "instances": []
    })
}

fn aggregate_status_snapshot(sinks: &BTreeMap<String, Arc<SinkRuntime>>) -> Value {
    if sinks.is_empty() {
        return disabled_status_snapshot();
    }

    let instances: Vec<Value> = sinks
        .values()
        .map(|runtime| runtime.status_snapshot())
        .collect();

    let mut queue_depth = 0u64;
    let mut queue_capacity = 0u64;
    let mut high_water = 0u64;
    let mut spool_files = 0u64;
    let mut spool_bytes = 0u64;
    let mut spool_drops = 0u64;
    let mut spool_prepare_failures = 0u64;
    let mut spool_enabled_any = false;
    let mut spool_all_available = true;
    let mut events_enqueued = 0u64;
    let mut events_exported = 0u64;
    let mut failures = 0u64;

    for runtime in sinks.values() {
        queue_depth = queue_depth.saturating_add(runtime.logger.queue_depth() as u64);
        queue_capacity = queue_capacity.saturating_add(runtime.logger.buffer_capacity() as u64);
        high_water = high_water.saturating_add(
            runtime
                .metrics
                .queue_high_water_hits_total
                .load(Ordering::Relaxed),
        );
        events_enqueued = events_enqueued.saturating_add(
            runtime
                .metrics
                .events_enqueued_total
                .load(Ordering::Relaxed),
        );
        events_exported = events_exported.saturating_add(
            runtime
                .metrics
                .events_exported_total
                .load(Ordering::Relaxed),
        );
        failures = failures.saturating_add(runtime.metrics.failures_total.load(Ordering::Relaxed));
        spool_prepare_failures = spool_prepare_failures.saturating_add(
            runtime
                .metrics
                .spool_prepare_failures_total
                .load(Ordering::Relaxed),
        );
        spool_drops =
            spool_drops.saturating_add(runtime.metrics.spool_drops_total.load(Ordering::Relaxed));
        if let Some(spool) = runtime.spool.as_ref() {
            spool_enabled_any = true;
            let stats = spool.scan_stats().unwrap_or_default();
            spool_files = spool_files.saturating_add(stats.files);
            spool_bytes = spool_bytes.saturating_add(stats.bytes);
            if !runtime.metrics.spool_available.load(Ordering::Acquire) {
                spool_all_available = false;
            }
        }
    }

    serde_json::json!({
        "enabled": true,
        "instance_count": sinks.len(),
        "snapshot_finalizations_pending": pending_snapshot_finalizations(),
        "totals": {
            "queue": {
                "depth": queue_depth,
                "capacity": queue_capacity,
                "high_water_hits_total": high_water
            },
            "spool": {
                "files": spool_files,
                "bytes": spool_bytes,
                "drops_total": spool_drops,
                "prepare_failures_total": spool_prepare_failures,
                "available": spool_enabled_any && spool_all_available
            },
            "export": {
                "events_enqueued_total": events_enqueued,
                "events_exported_total": events_exported,
                "failures_total": failures
            }
        },
        "instances": instances
    })
}

impl SinkRuntime {
    fn status_snapshot(&self) -> Value {
        let (spool_enabled, spool_files, spool_bytes) = match self.spool.as_ref() {
            Some(spool) => {
                let stats = spool.scan_stats().unwrap_or_default();
                (true, stats.files, stats.bytes)
            }
            None => (false, 0, 0),
        };
        let last_failure_reason = self
            .metrics
            .last_failure_reason
            .read()
            .ok()
            .and_then(|guard| guard.clone());
        serde_json::json!({
            "plugin_config_id": self.plugin_config_id.as_ref(),
            "generation": self.generation,
            "mode": self.summary.mode.as_str(),
            "pricing_version": self.summary.pricing_version,
            "clickhouse": {
                "endpoint": self.summary.endpoint,
                "database": self.summary.database,
                "table": self.summary.table,
            },
            "batch": {
                "size": self.summary.batch_size,
                "flush_interval_ms": self.summary.flush_interval_ms,
            },
            "retry": {
                "max_attempts": self.summary.retry_max_attempts,
                "initial_delay_ms": self.summary.retry_initial_delay_ms,
                "max_delay_ms": self.summary.retry_max_delay_ms,
                "jitter": self.summary.retry_jitter,
            },
            "queue": {
                "depth": self.logger.queue_depth(),
                "capacity": self.logger.buffer_capacity(),
                "high_water_hits_total": self.metrics.queue_high_water_hits_total.load(Ordering::Relaxed),
            },
            "spool": {
                "enabled": spool_enabled,
                "available": spool_enabled && self.metrics.spool_available.load(Ordering::Acquire),
                "prepare_failures_total": self.metrics.spool_prepare_failures_total.load(Ordering::Relaxed),
                "files": spool_files,
                "bytes": spool_bytes,
                "drops_total": self.metrics.spool_drops_total.load(Ordering::Relaxed),
                "last_replay_at": timestamp_json(self.metrics.last_replay_at.load(Ordering::Relaxed)),
            },
            "export": {
                "events_enqueued_total": self.metrics.events_enqueued_total.load(Ordering::Relaxed),
                "events_exported_total": self.metrics.events_exported_total.load(Ordering::Relaxed),
                "failures_total": self.metrics.failures_total.load(Ordering::Relaxed),
                "last_success_at": timestamp_json(self.metrics.last_success_at.load(Ordering::Relaxed)),
                "last_failure_at": timestamp_json(self.metrics.last_failure_at.load(Ordering::Relaxed)),
                "last_failure_reason": last_failure_reason,
            }
        })
    }
}

fn render_prometheus_for_sinks(
    sinks: &BTreeMap<String, Arc<SinkRuntime>>,
    pending_finalizations: usize,
) -> String {
    let mut output = String::with_capacity(4096 * sinks.len().max(1));

    // Preserve the existing metric names as process-wide aggregates across
    // every current accepted instance. Per-instance identity and counters live in
    // the authenticated status endpoint; avoiding generation labels keeps
    // scrape cardinality stable across reloads and prevents aggregate +
    // component double-counting in ordinary PromQL sums.
    let mut events_enqueued = 0u64;
    let mut events_exported = 0u64;
    let mut failure_network = 0u64;
    let mut failure_http_4xx = 0u64;
    let mut failure_http_5xx = 0u64;
    let mut failure_serialize = 0u64;
    let mut failure_tls = 0u64;
    let mut failure_timeout = 0u64;
    let mut queue_depth = 0u64;
    let mut spool_bytes = 0u64;
    let mut spool_files = 0u64;
    let mut spool_drops = 0u64;
    let mut spool_prepare_failures = 0u64;
    let mut spool_enabled_any = false;
    let mut spool_all_available = true;
    let mut snapshot_emits = 0u64;
    let mut any_snapshot = false;
    let mut latency_counts: Vec<u64> = Vec::new();
    let mut latency_sum = 0.0f64;
    let mut latency_total = 0u64;
    let mut latency_buckets: &'static [f64] = &[];

    for runtime in sinks.values() {
        let metrics = &runtime.metrics;
        events_enqueued =
            events_enqueued.saturating_add(metrics.events_enqueued_total.load(Ordering::Relaxed));
        events_exported =
            events_exported.saturating_add(metrics.events_exported_total.load(Ordering::Relaxed));
        failure_network =
            failure_network.saturating_add(metrics.failure_reasons.network.load(Ordering::Relaxed));
        failure_http_4xx = failure_http_4xx
            .saturating_add(metrics.failure_reasons.http_4xx.load(Ordering::Relaxed));
        failure_http_5xx = failure_http_5xx
            .saturating_add(metrics.failure_reasons.http_5xx.load(Ordering::Relaxed));
        failure_serialize = failure_serialize
            .saturating_add(metrics.failure_reasons.serialize.load(Ordering::Relaxed));
        failure_tls =
            failure_tls.saturating_add(metrics.failure_reasons.tls.load(Ordering::Relaxed));
        failure_timeout =
            failure_timeout.saturating_add(metrics.failure_reasons.timeout.load(Ordering::Relaxed));
        queue_depth = queue_depth.saturating_add(runtime.logger.queue_depth() as u64);
        spool_drops = spool_drops.saturating_add(metrics.spool_drops_total.load(Ordering::Relaxed));
        spool_prepare_failures = spool_prepare_failures
            .saturating_add(metrics.spool_prepare_failures_total.load(Ordering::Relaxed));
        let spool_stats = runtime
            .spool
            .as_ref()
            .and_then(|spool| spool.scan_stats().ok())
            .unwrap_or_default();
        spool_bytes = spool_bytes.saturating_add(spool_stats.bytes);
        spool_files = spool_files.saturating_add(spool_stats.files);
        if runtime.spool.is_some() {
            spool_enabled_any = true;
            if !metrics.spool_available.load(Ordering::Acquire) {
                spool_all_available = false;
            }
        }
        if runtime.summary.mode == SinkMode::Snapshot {
            any_snapshot = true;
            snapshot_emits =
                snapshot_emits.saturating_add(metrics.snapshot_emits_total.load(Ordering::Relaxed));
        }
        if latency_buckets.is_empty() {
            latency_buckets = metrics.latency.buckets;
            latency_counts = vec![0u64; latency_buckets.len()];
        }
        for (idx, count) in latency_counts.iter_mut().enumerate() {
            *count = count.saturating_add(metrics.latency.counts[idx].load(Ordering::Relaxed));
        }
        latency_sum += f64::from_bits(metrics.latency.sum_bits.load(Ordering::Relaxed));
        latency_total = latency_total.saturating_add(metrics.latency.count.load(Ordering::Relaxed));
    }

    output.push_str("# HELP chargeback_sink_events_enqueued_total Chargeback sink events accepted by the exporter.\n");
    output.push_str("# TYPE chargeback_sink_events_enqueued_total counter\n");
    output.push_str(&format!(
        "chargeback_sink_events_enqueued_total {}\n",
        events_enqueued
    ));
    output.push_str("# HELP chargeback_sink_events_exported_total Chargeback sink events successfully exported to ClickHouse.\n");
    output.push_str("# TYPE chargeback_sink_events_exported_total counter\n");
    output.push_str(&format!(
        "chargeback_sink_events_exported_total {}\n",
        events_exported
    ));
    output.push_str("# HELP chargeback_sink_export_failures_total Chargeback sink export failures by bounded reason.\n");
    output.push_str("# TYPE chargeback_sink_export_failures_total counter\n");
    for (reason, value) in [
        ("network", failure_network),
        ("http_4xx", failure_http_4xx),
        ("http_5xx", failure_http_5xx),
        ("serialize", failure_serialize),
        ("tls", failure_tls),
        ("timeout", failure_timeout),
    ] {
        output.push_str(&format!(
            "chargeback_sink_export_failures_total{{reason=\"{}\"}} {}\n",
            reason, value
        ));
    }
    output.push_str("# HELP chargeback_sink_queue_depth Chargeback sink in-memory queue depth.\n");
    output.push_str("# TYPE chargeback_sink_queue_depth gauge\n");
    output.push_str(&format!("chargeback_sink_queue_depth {}\n", queue_depth));
    output.push_str("# HELP chargeback_sink_snapshot_finalizations_pending Snapshot generations retaining unspooled terminal deltas after admission closed.\n");
    output.push_str("# TYPE chargeback_sink_snapshot_finalizations_pending gauge\n");
    output.push_str(&format!(
        "chargeback_sink_snapshot_finalizations_pending {}\n",
        pending_finalizations
    ));
    output.push_str(
        "# HELP chargeback_sink_spool_bytes Chargeback sink on-disk owned spool bytes (active, temp, corrupt, and dead-lettered files).\n",
    );
    output.push_str("# TYPE chargeback_sink_spool_bytes gauge\n");
    output.push_str(&format!("chargeback_sink_spool_bytes {}\n", spool_bytes));
    output.push_str(
        "# HELP chargeback_sink_spool_files Chargeback sink on-disk owned spool file count (active, temp, corrupt, and dead-lettered files).\n",
    );
    output.push_str("# TYPE chargeback_sink_spool_files gauge\n");
    output.push_str(&format!("chargeback_sink_spool_files {}\n", spool_files));
    output.push_str("# HELP chargeback_sink_spool_drops_total Chargeback sink spool files dropped to enforce max_bytes.\n");
    output.push_str("# TYPE chargeback_sink_spool_drops_total counter\n");
    output.push_str(&format!(
        "chargeback_sink_spool_drops_total {}\n",
        spool_drops
    ));
    output.push_str("# HELP chargeback_sink_spool_available Whether committed spool storage is currently writable (1) or unavailable (0). Aggregate is 1 only when every spool-enabled live instance is available.\n");
    output.push_str("# TYPE chargeback_sink_spool_available gauge\n");
    output.push_str(&format!(
        "chargeback_sink_spool_available {}\n",
        if spool_enabled_any && spool_all_available {
            1
        } else {
            0
        }
    ));
    output.push_str("# HELP chargeback_sink_spool_prepare_failures_total Chargeback sink committed spool storage preparation failures.\n");
    output.push_str("# TYPE chargeback_sink_spool_prepare_failures_total counter\n");
    output.push_str(&format!(
        "chargeback_sink_spool_prepare_failures_total {}\n",
        spool_prepare_failures
    ));
    output.push_str("# HELP chargeback_sink_export_latency_seconds Chargeback sink ClickHouse export latency in seconds.\n");
    output.push_str("# TYPE chargeback_sink_export_latency_seconds histogram\n");
    for (idx, bucket) in latency_buckets.iter().enumerate() {
        let cumulative = latency_counts.get(idx).copied().unwrap_or(0);
        output.push_str(&format!(
            "chargeback_sink_export_latency_seconds_bucket{{le=\"{}\"}} {}\n",
            bucket, cumulative
        ));
    }
    output.push_str(&format!(
        "chargeback_sink_export_latency_seconds_bucket{{le=\"+Inf\"}} {}\n",
        latency_total
    ));
    output.push_str(&format!(
        "chargeback_sink_export_latency_seconds_sum {:.6}\n",
        latency_sum
    ));
    output.push_str(&format!(
        "chargeback_sink_export_latency_seconds_count {}\n",
        latency_total
    ));
    if any_snapshot {
        output.push_str("# HELP chargeback_sink_snapshot_emits_total Chargeback sink snapshot delta events emitted.\n");
        output.push_str("# TYPE chargeback_sink_snapshot_emits_total counter\n");
        output.push_str(&format!(
            "chargeback_sink_snapshot_emits_total {}\n",
            snapshot_emits
        ));
    }

    output
}

/// Structured ClickHouse delivery result.
///
/// Distinguishes retryable transport/backpressure failures from permanent HTTP
/// rejection and payload-too-large (413) so spool replay can dead-letter or
/// split without head-of-line blocking newer files. Safe messages never include
/// response bodies, credentials, or charge-record fields.
#[derive(Debug, Clone, PartialEq, Eq)]
enum DeliveryOutcome {
    Delivered,
    Retryable { message: String },
    Permanent { status: u16, message: String },
    PayloadTooLarge { message: String },
}

impl DeliveryOutcome {
    fn safe_message(&self) -> &str {
        match self {
            DeliveryOutcome::Delivered => "delivered",
            DeliveryOutcome::Retryable { message }
            | DeliveryOutcome::Permanent { message, .. }
            | DeliveryOutcome::PayloadTooLarge { message } => message.as_str(),
        }
    }

    fn label(&self) -> &'static str {
        match self {
            DeliveryOutcome::Delivered => "delivered",
            DeliveryOutcome::Retryable { .. } => "retryable",
            DeliveryOutcome::Permanent { .. } => "permanent",
            DeliveryOutcome::PayloadTooLarge { .. } => "payload_too_large",
        }
    }
}

/// Bounded ClickHouse HTTP acknowledgement after headers arrive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClickHouseAckRead {
    /// Full body drained within the byte/time caps.
    Complete { byte_len: u64, has_exception: bool },
    /// Drain did not finish cleanly; treat as ambiguous for durability.
    Incomplete { kind: ClickHouseAckIncomplete },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClickHouseAckIncomplete {
    LimitExceeded,
    Timeout,
    TransportFailure,
}

impl ClickHouseAckIncomplete {
    fn as_str(self) -> &'static str {
        match self {
            Self::LimitExceeded => "acknowledgement body exceeded the drain limit",
            Self::Timeout => "acknowledgement body drain timed out",
            Self::TransportFailure => "acknowledgement body drain had a transport failure",
        }
    }
}

async fn send_batch(cfg: &ClickHouseFlushConfig, batch: Vec<ChargeEvent>) -> Result<(), String> {
    let body = serialize_json_each_row(&batch).inspect_err(|error| {
        cfg.metrics
            .record_failure(FailureReason::Serialize, error.clone());
    })?;
    match post_json_each_row(cfg, body, batch.len()).await {
        DeliveryOutcome::Delivered => Ok(()),
        other => Err(other.safe_message().to_string()),
    }
}

async fn post_json_each_row(
    cfg: &ClickHouseFlushConfig,
    body: String,
    event_count: usize,
) -> DeliveryOutcome {
    let start = Instant::now();
    let mut request = match &cfg.http {
        ClickHouseHttpClient::Shared(client) => client.get().post(&cfg.insert_url),
        ClickHouseHttpClient::Dedicated(client) => client.post(&cfg.insert_url),
    }
    .timeout(cfg.timeout)
    .header(CONTENT_TYPE, "application/json")
    .body(body);
    if let Some(username) = cfg.username.as_deref() {
        request = request.basic_auth(username, cfg.password.clone());
    }
    let result = cfg.http.execute(request).await;
    match result {
        Ok(response) => {
            let status = response.status();
            let has_exception_header = response
                .headers()
                .contains_key("x-clickhouse-exception-code");
            let ack = read_clickhouse_acknowledgement(response).await;
            classify_clickhouse_delivery(
                cfg,
                status,
                ack,
                has_exception_header,
                event_count,
                start.elapsed(),
            )
        }
        Err(error) => {
            let reason = classify_reqwest_failure(&error);
            let message = reason.as_str().to_string();
            cfg.metrics.record_failure(reason, message.clone());
            DeliveryOutcome::Retryable { message }
        }
    }
}

async fn read_clickhouse_acknowledgement(response: reqwest::Response) -> ClickHouseAckRead {
    if response
        .content_length()
        .is_some_and(|length| length > CLICKHOUSE_ACK_BODY_LIMIT_BYTES as u64)
    {
        return ClickHouseAckRead::Incomplete {
            kind: ClickHouseAckIncomplete::LimitExceeded,
        };
    }
    match tokio::time::timeout(
        HTTP_BATCH_RESPONSE_DRAIN_TIMEOUT,
        read_response_body_bounded(response, CLICKHOUSE_ACK_BODY_LIMIT_BYTES),
    )
    .await
    {
        Err(_) => ClickHouseAckRead::Incomplete {
            kind: ClickHouseAckIncomplete::Timeout,
        },
        Ok(Ok(bytes)) => {
            // Response (and its pooled connection) were dropped when the read
            // future completed; yield so idle-pool reclaim can run before the
            // next POST on this client.
            tokio::task::yield_now().await;
            ClickHouseAckRead::Complete {
                byte_len: bytes.len() as u64,
                has_exception: body_has_clickhouse_exception(&bytes),
            }
        }
        Ok(Err(BoundedReadError::LimitExceeded { .. })) => ClickHouseAckRead::Incomplete {
            kind: ClickHouseAckIncomplete::LimitExceeded,
        },
        Ok(Err(BoundedReadError::Stream(_))) => ClickHouseAckRead::Incomplete {
            kind: ClickHouseAckIncomplete::TransportFailure,
        },
    }
}

/// Detect ClickHouse exception markers in a bounded acknowledgement body.
///
/// Inspects bytes only for known markers; never logs or returns the payload.
fn body_has_clickhouse_exception(body: &[u8]) -> bool {
    const MARKERS: &[&[u8]] = &[b"DB::Exception", b"Code: "];
    MARKERS
        .iter()
        .any(|marker| find_bytes_subslice(body, marker).is_some())
}

fn find_bytes_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn classify_clickhouse_delivery(
    cfg: &ClickHouseFlushConfig,
    status: StatusCode,
    ack: ClickHouseAckRead,
    has_exception_header: bool,
    event_count: usize,
    elapsed: Duration,
) -> DeliveryOutcome {
    if matches!(status, StatusCode::OK | StatusCode::NO_CONTENT) {
        return classify_success_status_acknowledgement(
            cfg,
            status,
            ack,
            has_exception_header,
            event_count,
            elapsed,
        );
    }

    let code = status.as_u16();
    let message = format!("clickhouse returned HTTP {code}");
    if code == 413 {
        cfg.metrics
            .record_failure(FailureReason::Http4xx, message.clone());
        return DeliveryOutcome::PayloadTooLarge { message };
    }
    if code == 408 || code == 429 || status.is_server_error() {
        let reason = if status.is_server_error() {
            FailureReason::Http5xx
        } else {
            FailureReason::Http4xx
        };
        cfg.metrics.record_failure(reason, message.clone());
        return DeliveryOutcome::Retryable { message };
    }
    if status.is_client_error() {
        cfg.metrics
            .record_failure(FailureReason::Http4xx, message.clone());
        return DeliveryOutcome::Permanent {
            status: code,
            message,
        };
    }
    cfg.metrics
        .record_failure(FailureReason::Network, message.clone());
    DeliveryOutcome::Retryable { message }
}

fn classify_success_status_acknowledgement(
    cfg: &ClickHouseFlushConfig,
    status: StatusCode,
    ack: ClickHouseAckRead,
    has_exception_header: bool,
    event_count: usize,
    elapsed: Duration,
) -> DeliveryOutcome {
    let code = status.as_u16();
    if has_exception_header {
        let message = format!("clickhouse returned HTTP {code} with X-ClickHouse-Exception-Code");
        cfg.metrics
            .record_failure(FailureReason::Http4xx, message.clone());
        return DeliveryOutcome::Permanent {
            status: code,
            message,
        };
    }
    match ack {
        ClickHouseAckRead::Complete {
            byte_len: 0,
            has_exception: false,
        } => {
            cfg.metrics.record_success(event_count, elapsed);
            DeliveryOutcome::Delivered
        }
        ClickHouseAckRead::Complete {
            has_exception: true,
            ..
        } => {
            let message = format!(
                "clickhouse returned HTTP {code} with an exception in the acknowledgement body"
            );
            cfg.metrics
                .record_failure(FailureReason::Http4xx, message.clone());
            DeliveryOutcome::Permanent {
                status: code,
                message,
            }
        }
        ClickHouseAckRead::Complete {
            byte_len,
            has_exception: false,
        } => {
            // Non-empty success bodies are not a persistence-proof ACK for
            // INSERT JSONEachRow; keep the spool and retry idempotently.
            let message = format!(
                "clickhouse returned HTTP {code} with an ambiguous non-empty acknowledgement ({byte_len} bytes)"
            );
            cfg.metrics
                .record_failure(FailureReason::Network, message.clone());
            DeliveryOutcome::Retryable { message }
        }
        ClickHouseAckRead::Incomplete { kind } => {
            let message = format!(
                "clickhouse returned HTTP {code} but acknowledgement was incomplete: {}",
                kind.as_str()
            );
            let reason = match kind {
                ClickHouseAckIncomplete::Timeout => FailureReason::Timeout,
                ClickHouseAckIncomplete::LimitExceeded
                | ClickHouseAckIncomplete::TransportFailure => FailureReason::Network,
            };
            cfg.metrics.record_failure(reason, message.clone());
            DeliveryOutcome::Retryable { message }
        }
    }
}

/// Deterministic split point for a 413 replay chunk.
///
/// Prefers `batch_size` when that still shrinks the chunk; otherwise halves.
/// Always returns a value in `1..len` when `len >= 2` so splitting makes progress.
fn replay_split_len(len: usize, batch_size: usize) -> usize {
    debug_assert!(len >= 2);
    let half = len / 2;
    let preferred = batch_size.min(half).max(1);
    preferred.min(len - 1)
}

pub fn serialize_json_each_row(batch: &[ChargeEvent]) -> Result<String, String> {
    let mut output = String::new();
    for (idx, event) in batch.iter().enumerate() {
        for (field, value) in [
            ("charge_call", event.charge_call),
            ("charge_bytes_sent", event.charge_bytes_sent),
            ("charge_bytes_received", event.charge_bytes_received),
            ("charge_total", event.charge_total),
        ] {
            require_finite_charge(value, field).map_err(|error| {
                format!(
                    "{PLUGIN_NAME}: event '{}' cannot be serialized: {error}",
                    event.event_id
                )
            })?;
        }
        if idx > 0 {
            output.push('\n');
        }
        let row = serde_json::to_string(event)
            .map_err(|error| format!("{PLUGIN_NAME}: failed to serialize charge event: {error}"))?;
        output.push_str(&row);
    }
    Ok(output)
}

fn classify_reqwest_failure(error: &reqwest::Error) -> FailureReason {
    if error.is_timeout() {
        return FailureReason::Timeout;
    }
    let lower = error.to_string().to_ascii_lowercase();
    if lower.contains("tls")
        || lower.contains("certificate")
        || lower.contains("handshake")
        || lower.contains("rustls")
    {
        FailureReason::Tls
    } else {
        FailureReason::Network
    }
}

fn validate_config(config: &ApiChargebackSinkConfig) -> Result<(), String> {
    let url = parse_clickhouse_url(&config.clickhouse.url)?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(format!(
            "{PLUGIN_NAME}: clickhouse.url must not contain user-info; use username/password_ref"
        ));
    }
    validate_clickhouse_identifier(&config.clickhouse.database, "database")?;
    validate_clickhouse_identifier(&config.clickhouse.table, "table")?;
    if config.clickhouse.timeout_ms == 0 {
        return Err(format!(
            "{PLUGIN_NAME}: clickhouse.timeout_ms must be at least 1"
        ));
    }
    validate_query_params(&config.clickhouse.insert_query_params)?;
    validate_insert_durability_settings(&config.clickhouse)?;

    if config.batch.size == 0 || config.batch.size > MAX_BATCH_SIZE {
        return Err(format!(
            "{PLUGIN_NAME}: batch.size must be between 1 and {MAX_BATCH_SIZE}"
        ));
    }
    if config.batch.buffer_capacity == 0 || config.batch.buffer_capacity > MAX_BUFFER_CAPACITY {
        return Err(format!(
            "{PLUGIN_NAME}: batch.buffer_capacity must be between 1 and {MAX_BUFFER_CAPACITY}"
        ));
    }
    if config.batch.flush_interval_ms == 0
        || config.batch.flush_interval_ms > MAX_BATCH_FLUSH_INTERVAL_MS
    {
        return Err(format!(
            "{PLUGIN_NAME}: batch.flush_interval_ms must be between 1 and {MAX_BATCH_FLUSH_INTERVAL_MS}"
        ));
    }
    if config.retry.max_attempts == 0 || config.retry.max_attempts > MAX_RETRY_MAX_ATTEMPTS {
        return Err(format!(
            "{PLUGIN_NAME}: retry.max_attempts must be between 1 and {MAX_RETRY_MAX_ATTEMPTS}"
        ));
    }
    if config.retry.initial_delay_ms > MAX_RETRY_DELAY_MS {
        return Err(format!(
            "{PLUGIN_NAME}: retry.initial_delay_ms must be between 0 and {MAX_RETRY_DELAY_MS}"
        ));
    }
    if config.retry.max_delay_ms > MAX_RETRY_DELAY_MS {
        return Err(format!(
            "{PLUGIN_NAME}: retry.max_delay_ms must be between 0 and {MAX_RETRY_DELAY_MS}"
        ));
    }
    if config.retry.max_delay_ms < config.retry.initial_delay_ms {
        return Err(format!(
            "{PLUGIN_NAME}: retry.max_delay_ms must be >= retry.initial_delay_ms"
        ));
    }
    let worst_case_delay_ms = worst_case_inter_attempt_delay_ms(
        config.retry.max_attempts,
        config.retry.initial_delay_ms,
        config.retry.max_delay_ms,
    );
    if worst_case_delay_ms > MAX_RETRY_TOTAL_DELAY_MS {
        return Err(format!(
            "{PLUGIN_NAME}: retry worst-case cumulative inter-attempt delay ({worst_case_delay_ms} ms) exceeds the {MAX_RETRY_TOTAL_DELAY_MS} ms budget; reduce retry.max_attempts, retry.initial_delay_ms, and/or retry.max_delay_ms"
        ));
    }
    if config.spool.enabled {
        if config.spool.max_bytes == 0 {
            return Err(format!("{PLUGIN_NAME}: spool.max_bytes must be at least 1"));
        }
        if config.spool.replay_interval_secs == 0 {
            return Err(format!(
                "{PLUGIN_NAME}: spool.replay_interval_secs must be at least 1"
            ));
        }
        // Shape-only: do not mkdir/chmod/probe here. Live storage preparation
        // starts only after the candidate generation is committed.
        validate_spool_dir_shape(&config.spool.dir)?;
    } else if config.mode == SinkMode::Snapshot {
        return Err(format!(
            "{PLUGIN_NAME}: snapshot mode requires spool.enabled=true so emitted deltas remain durable during ClickHouse outages"
        ));
    }
    if config.snapshot.interval_secs == 0 {
        return Err(format!(
            "{PLUGIN_NAME}: snapshot.interval_secs must be at least 1"
        ));
    }
    if config.snapshot.cleanup_interval_secs == 0 {
        return Err(format!(
            "{PLUGIN_NAME}: snapshot.cleanup_interval_secs must be at least 1"
        ));
    }
    if config.snapshot.stale_entry_ttl_secs == 0 {
        return Err(format!(
            "{PLUGIN_NAME}: snapshot.stale_entry_ttl_secs must be at least 1"
        ));
    }
    if config
        .clickhouse
        .password_ref
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty() && url.scheme() != "https")
    {
        return Err(format!(
            "{PLUGIN_NAME}: clickhouse.password_ref requires clickhouse.url to use https://"
        ));
    }
    if config
        .clickhouse
        .password_ref
        .as_deref()
        .is_some_and(|value| {
            !value.trim().is_empty()
                && (config.clickhouse.tls.insecure_skip_verify
                    || !config.clickhouse.tls.verify_hostname)
        })
    {
        return Err(format!(
            "{PLUGIN_NAME}: clickhouse.password_ref cannot be used when ClickHouse TLS certificate or hostname verification is disabled"
        ));
    }
    // Shape-only secret-ref check (do not materialize the env value here).
    if let Some(reference) = config
        .clickhouse
        .password_ref
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        && !reference.starts_with("FERRUM_")
    {
        return Err(format!(
            "{PLUGIN_NAME}: clickhouse.password_ref must reference a FERRUM_* environment variable"
        ));
    }
    if config.pricing_version.trim().is_empty() {
        return Err(format!("{PLUGIN_NAME}: pricing_version must not be empty"));
    }
    if config.currency.trim().is_empty() {
        return Err(format!("{PLUGIN_NAME}: currency must not be empty"));
    }
    Ok(())
}

fn validate_spool_dir_shape(path: &Path) -> Result<(), String> {
    if path.as_os_str().is_empty() {
        return Err(format!("{PLUGIN_NAME}: spool.dir must not be empty"));
    }
    // Reject NUL-containing paths without touching the filesystem.
    let display = path.to_string_lossy();
    if display.contains('\0') {
        return Err(format!(
            "{PLUGIN_NAME}: spool.dir must not contain NUL bytes"
        ));
    }
    Ok(())
}

fn parse_clickhouse_url(raw: &str) -> Result<Url, String> {
    let url = Url::parse(raw)
        .map_err(|error| format!("{PLUGIN_NAME}: invalid clickhouse.url: {error}"))?;
    match url.scheme() {
        "http" | "https" => {}
        scheme => {
            return Err(format!(
                "{PLUGIN_NAME}: clickhouse.url must use http:// or https:// (got {scheme})"
            ));
        }
    }
    if url.host_str().is_none() {
        return Err(format!(
            "{PLUGIN_NAME}: clickhouse.url must include a hostname or IP address"
        ));
    }
    Ok(url)
}

/// ClickHouse database/table names are interpolated directly into the
/// `INSERT INTO <table> FORMAT JSONEachRow` query string in [`build_insert_url`],
/// so restrict them to a safe identifier charset (ASCII letters, digits,
/// underscore, and a `.` db-qualifier) to keep operator config from injecting
/// SQL into the export query.
fn validate_clickhouse_identifier(value: &str, field: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!(
            "{PLUGIN_NAME}: clickhouse.{field} must not be empty"
        ));
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
    {
        return Err(format!(
            "{PLUGIN_NAME}: clickhouse.{field} may only contain ASCII letters, digits, underscores, and dots"
        ));
    }
    Ok(())
}

fn validate_query_params(params: &HashMap<String, String>) -> Result<(), String> {
    for (key, value) in params {
        if key.is_empty() || key.len() > 128 || key.chars().any(char::is_control) {
            return Err(format!(
                "{PLUGIN_NAME}: clickhouse.insert_query_params contains invalid key"
            ));
        }
        if value.len() > 512 || value.chars().any(char::is_control) {
            return Err(format!(
                "{PLUGIN_NAME}: clickhouse.insert_query_params['{key}'] contains invalid value"
            ));
        }
    }
    Ok(())
}

/// Durable mode rejects fire-and-forget async inserts unless the operator sets
/// an explicitly named lossy opt-in that cannot be confused with durable mode.
fn validate_insert_durability_settings(cfg: &ClickHouseConfig) -> Result<(), String> {
    let Some(wait_value) = cfg.insert_query_params.get(WAIT_FOR_ASYNC_INSERT_PARAM) else {
        return Ok(());
    };
    if !is_falsy_clickhouse_setting(wait_value) {
        return Ok(());
    }
    if !cfg.allow_lossy_async_insert {
        return Err(format!(
            "{PLUGIN_NAME}: clickhouse.insert_query_params['{WAIT_FOR_ASYNC_INSERT_PARAM}']=\
             {wait_value:?} disables persistence-aware acknowledgement; set \
             wait_for_async_insert to \"1\" for durable export, or set \
             clickhouse.allow_lossy_async_insert=true to explicitly opt into \
             fire-and-forget loss"
        ));
    }
    Ok(())
}

fn is_falsy_clickhouse_setting(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "0" | "false" | "no" | "off"
    )
}

fn build_insert_url(base: &Url, cfg: &ClickHouseConfig) -> String {
    let mut url = base.clone();
    url.set_query(None);
    url.set_fragment(None);
    let pins_durable_async_ack = cfg
        .insert_query_params
        .get("async_insert")
        .is_some_and(|value| !is_falsy_clickhouse_setting(value))
        && !cfg
            .insert_query_params
            .contains_key(WAIT_FOR_ASYNC_INSERT_PARAM);
    {
        let mut pairs = url.query_pairs_mut();
        pairs.append_pair("database", &cfg.database);
        pairs.append_pair(
            "query",
            &format!("INSERT INTO {} FORMAT JSONEachRow", cfg.table),
        );
        for (key, value) in &cfg.insert_query_params {
            pairs.append_pair(key, value);
        }
        if pins_durable_async_ack {
            // Do not inherit a ClickHouse user/profile default that may be
            // fire-and-forget. An explicit falsy value remains available only
            // through the separately validated lossy opt-in.
            pairs.append_pair(WAIT_FOR_ASYNC_INSERT_PARAM, "1");
        }
    }
    url.to_string()
}

fn sanitized_endpoint(url: &Url) -> String {
    let mut safe = url.clone();
    let _ = safe.set_username("");
    let _ = safe.set_password(None);
    safe.set_query(None);
    safe.set_fragment(None);
    safe.to_string().trim_end_matches('/').to_string()
}

fn resolve_password_ref(password_ref: Option<&str>) -> Result<Option<String>, String> {
    let Some(reference) = password_ref
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    if !reference.starts_with("FERRUM_") {
        return Err(format!(
            "{PLUGIN_NAME}: clickhouse.password_ref must reference a FERRUM_* environment variable"
        ));
    }
    if let Ok(value) = std::env::var(reference) {
        return Ok(Some(value));
    }
    Err(format!(
        "{PLUGIN_NAME}: clickhouse.password_ref references unset environment variable"
    ))
}

fn build_clickhouse_http_client(
    cfg: &ClickHouseConfig,
    shared: &PluginHttpClient,
) -> Result<ClickHouseHttpClient, String> {
    let custom_tls = cfg.tls.ca_file.is_some()
        || cfg.tls.client_cert_file.is_some()
        || cfg.tls.client_key_file.is_some()
        || !cfg.tls.verify_hostname
        || cfg.tls.insecure_skip_verify;
    if !custom_tls {
        return Ok(ClickHouseHttpClient::Shared(Box::new(shared.clone())));
    }

    let mut builder = reqwest::Client::builder()
        .connect_timeout(Duration::from_millis(cfg.timeout_ms))
        .timeout(Duration::from_millis(cfg.timeout_ms))
        // Do not follow redirects: a 3xx from an allowed ClickHouse host could
        // otherwise bounce an export to an egress-policy-denied IP (matches the
        // shared PluginHttpClient redirect policy).
        .redirect(reqwest::redirect::Policy::none());
    if let Some(dns_cache) = shared.dns_cache().cloned() {
        builder = builder.dns_resolver(Arc::new(DnsCacheResolver::new(dns_cache)));
    }
    if cfg.tls.insecure_skip_verify {
        warn!(
            plugin = PLUGIN_NAME,
            "ClickHouse TLS certificate verification is disabled; use only for testing"
        );
        builder = builder.danger_accept_invalid_certs(true);
    }
    if !cfg.tls.verify_hostname {
        warn!(
            plugin = PLUGIN_NAME,
            "ClickHouse TLS hostname verification is disabled; use only for testing"
        );
        builder = builder.tls_danger_accept_invalid_hostnames(true);
    }
    if let Some(ca_file) = cfg.tls.ca_file.as_ref() {
        let pem = fs::read(ca_file).map_err(|error| {
            format!(
                "{PLUGIN_NAME}: failed to read clickhouse.tls.ca_file '{}': {error}",
                ca_file.display()
            )
        })?;
        let certs = reqwest::Certificate::from_pem_bundle(&pem).map_err(|error| {
            format!(
                "{PLUGIN_NAME}: failed to parse clickhouse.tls.ca_file '{}': {error}",
                ca_file.display()
            )
        })?;
        builder = builder.tls_certs_only(certs);
    }
    match (&cfg.tls.client_cert_file, &cfg.tls.client_key_file) {
        (Some(cert), Some(key)) => {
            let mut pem = fs::read(cert).map_err(|error| {
                format!(
                    "{PLUGIN_NAME}: failed to read clickhouse.tls.client_cert_file '{}': {error}",
                    cert.display()
                )
            })?;
            let mut key_pem = fs::read(key).map_err(|error| {
                format!(
                    "{PLUGIN_NAME}: failed to read clickhouse.tls.client_key_file '{}': {error}",
                    key.display()
                )
            })?;
            pem.push(b'\n');
            pem.append(&mut key_pem);
            let identity = reqwest::Identity::from_pem(&pem).map_err(|error| {
                format!("{PLUGIN_NAME}: failed to parse ClickHouse client identity: {error}")
            })?;
            builder = builder.identity(identity);
        }
        (None, None) => {}
        _ => {
            return Err(format!(
                "{PLUGIN_NAME}: clickhouse.tls.client_cert_file and client_key_file must be set together"
            ));
        }
    }
    builder
        .build()
        .map(ClickHouseHttpClient::Dedicated)
        .map_err(|error| format!("{PLUGIN_NAME}: failed to build ClickHouse HTTP client: {error}"))
}

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpoolStats {
    pub files: u64,
    pub bytes: u64,
}

pub struct SpoolManager {
    cfg: SpoolSettings,
    node_id: Arc<str>,
    metrics: Arc<SinkMetrics>,
    last_drop_warn_at: AtomicI64,
    live_storage_prepared: AtomicBool,
    write_lock: Mutex<()>,
}

impl SpoolManager {
    fn new(
        cfg: SpoolSettings,
        node_id: Arc<str>,
        metrics: Arc<SinkMetrics>,
    ) -> Result<Self, String> {
        Ok(Self {
            cfg,
            node_id,
            metrics,
            last_drop_warn_at: AtomicI64::new(0),
            live_storage_prepared: AtomicBool::new(false),
            write_lock: Mutex::new(()),
        })
    }

    #[allow(dead_code)]
    pub fn for_tests(cfg: SpoolSettings, node_id: &str) -> Result<Self, String> {
        let manager = Self::new(
            cfg,
            Arc::<str>::from(node_id.to_string()),
            Arc::new(SinkMetrics::default()),
        )?;
        // Test callers model a committed/live sink and retain the historical
        // eager startup validation contract.
        manager.prepare_live_storage()?;
        Ok(manager)
    }

    pub fn write_events(&self, events: &[ChargeEvent]) -> Result<PathBuf, String> {
        if events.is_empty() {
            return Err(format!("{PLUGIN_NAME}: refusing to spool empty batch"));
        }
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_| format!("{PLUGIN_NAME}: spool writer lock is poisoned"))?;
        self.prepare_live_storage_locked()?;
        // Size the pending encoded file before admission so max_bytes is a hard
        // ceiling over existing owned bytes plus this write.
        let body = serialize_json_each_row(events)?;
        let bytes = encode_spool_bytes(body.as_bytes(), self.cfg.compression)?;
        let incoming_len = bytes.len() as u64;
        if incoming_len > self.cfg.max_bytes {
            return Err(format!(
                "{PLUGIN_NAME}: encoded spool batch ({incoming_len} bytes) exceeds spool.max_bytes ({})",
                self.cfg.max_bytes
            ));
        }
        self.evict_until_can_admit(incoming_len)?;
        let day = Utc::now().format("%Y%m%d").to_string();
        let dir = self.cfg.dir.join(self.node_id.as_ref()).join(day);
        ensure_private_dir(&dir)?;
        let id = new_ulid();
        let final_path = dir.join(format!("{}.{}", id, self.cfg.compression.extension()));
        let tmp_path = final_path.with_file_name(format!(
            "{}.tmp",
            final_path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| format!("{PLUGIN_NAME}: invalid spool file path"))?
        ));
        write_private_file_atomically(&tmp_path, &final_path, &bytes)?;
        invalidate_status_cache();
        Ok(final_path)
    }

    /// Prepare mutable spool state only for a committed generation. Candidate
    /// staging must not create directories, write probes, or reconcile files.
    fn prepare_live_storage(&self) -> Result<(), String> {
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_| format!("{PLUGIN_NAME}: spool writer lock is poisoned"))?;
        self.prepare_live_storage_locked()
    }

    fn prepare_live_storage_locked(&self) -> Result<(), String> {
        let result = self.prepare_live_storage_locked_inner();
        let available = result.is_ok();
        let changed = self
            .metrics
            .spool_available
            .swap(available, Ordering::AcqRel)
            != available;
        if !available {
            self.metrics
                .spool_prepare_failures_total
                .fetch_add(1, Ordering::Relaxed);
        }
        if changed || !available {
            invalidate_status_cache();
        }
        result
    }

    fn prepare_live_storage_locked_inner(&self) -> Result<(), String> {
        let node_dir = self.cfg.dir.join(self.node_id.as_ref());
        // Avoid repeated chmod/write probes on every batch and replay tick.
        // If an operator removes either live directory, fall through and
        // securely recreate/re-probe it instead of creating permissive parents
        // implicitly from the later day-directory write.
        if self.live_storage_prepared.load(Ordering::Acquire)
            && self.cfg.dir.is_dir()
            && node_dir.is_dir()
        {
            return Ok(());
        }
        ensure_private_dir(&self.cfg.dir)?;
        ensure_private_dir(&node_dir)?;
        warn_on_sibling_spool_dirs(&self.cfg.dir, self.node_id.as_ref());
        // Crash-left *.tmp files consume disk but are incomplete; delete them
        // only after publication and before any live quota decision.
        self.reconcile_stale_temp_files()?;
        self.live_storage_prepared.store(true, Ordering::Release);
        Ok(())
    }

    pub fn scan_stats(&self) -> Result<SpoolStats, String> {
        let files = self.list_owned_spool_files()?;
        let mut stats = SpoolStats::default();
        for file in files {
            match fs::metadata(&file) {
                Ok(meta) => {
                    stats.files = stats.files.saturating_add(1);
                    stats.bytes = stats.bytes.saturating_add(meta.len());
                }
                Err(error) => {
                    return Err(format!(
                        "{PLUGIN_NAME}: failed to stat spool file '{}': {error}",
                        file.display()
                    ));
                }
            }
        }
        Ok(stats)
    }

    /// Drop oldest owned spool files until `owned_bytes + incoming_len <= max_bytes`.
    ///
    /// Owned bytes include active data files, crash-left temps, corrupt
    /// quarantine, and metadata-only dead-letter (`.rejected.meta`) files.
    /// When a single encoded batch cannot fit even after emptying the spool,
    /// the write is rejected (never silently over-admitted).
    fn evict_until_can_admit(&self, incoming_len: u64) -> Result<(), String> {
        if incoming_len > self.cfg.max_bytes {
            return Err(format!(
                "{PLUGIN_NAME}: encoded spool batch ({incoming_len} bytes) exceeds spool.max_bytes ({})",
                self.cfg.max_bytes
            ));
        }
        loop {
            let stats = self.scan_stats()?;
            if stats.bytes.saturating_add(incoming_len) <= self.cfg.max_bytes {
                return Ok(());
            }
            let Some(oldest) = self.list_owned_spool_files()?.into_iter().next() else {
                return Err(format!(
                    "{PLUGIN_NAME}: encoded spool batch ({incoming_len} bytes) cannot fit within spool.max_bytes ({}) after eviction",
                    self.cfg.max_bytes
                ));
            };
            match fs::remove_file(&oldest) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(format!(
                        "{PLUGIN_NAME}: failed to remove oldest spool file '{}': {error}",
                        oldest.display()
                    ));
                }
            }
            self.metrics
                .spool_drops_total
                .fetch_add(1, Ordering::Relaxed);
            let now = unix_timestamp_seconds();
            let last = self.last_drop_warn_at.load(Ordering::Relaxed);
            if now.saturating_sub(last) >= SPOOL_WARN_INTERVAL_SECS
                && self
                    .last_drop_warn_at
                    .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
            {
                warn!(
                    plugin = PLUGIN_NAME,
                    max_bytes = self.cfg.max_bytes,
                    incoming_bytes = incoming_len,
                    "Chargeback sink spool exceeded max_bytes; oldest owned spool file was dropped"
                );
            }
        }
    }

    fn reconcile_stale_temp_files(&self) -> Result<(), String> {
        let root = self.cfg.dir.join(self.node_id.as_ref());
        let mut temps = Vec::new();
        collect_spool_files(&root, &mut temps, SpoolFileClass::Temp)?;
        for path in temps {
            match fs::remove_file(&path) {
                Ok(()) => {
                    warn!(
                        plugin = PLUGIN_NAME,
                        path = %path.display(),
                        "Chargeback sink removed a stale spool temp file left by an interrupted write"
                    );
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(format!(
                        "{PLUGIN_NAME}: failed to remove stale spool temp file '{}': {error}",
                        path.display()
                    ));
                }
            }
        }
        Ok(())
    }

    fn list_owned_spool_files(&self) -> Result<Vec<PathBuf>, String> {
        let root = self.cfg.dir.join(self.node_id.as_ref());
        let mut files = Vec::new();
        collect_spool_files(&root, &mut files, SpoolFileClass::Owned)?;
        files.sort();
        Ok(files)
    }

    fn list_replayable_spool_files(&self) -> Result<Vec<PathBuf>, String> {
        let root = self.cfg.dir.join(self.node_id.as_ref());
        let mut files = Vec::new();
        collect_spool_files(&root, &mut files, SpoolFileClass::Replayable)?;
        files.sort();
        Ok(files)
    }
}

fn warn_on_sibling_spool_dirs(root: &Path, node_id: &str) {
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        if !meta.is_dir() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if name != node_id {
            warn!(
                plugin = PLUGIN_NAME,
                node_id,
                sibling_node_id = %name,
                spool_dir = %root.display(),
                "Chargeback sink found a sibling spool directory; use a stable FERRUM_NODE_ID when spool.dir is backed by persistent storage"
            );
        }
    }
}

#[derive(Clone, Copy)]
enum SpoolFileClass {
    /// Active data, crash-left temps, corrupt quarantine, and metadata-only
    /// dead-letter files — quota/status.
    Owned,
    /// Only durable replay candidates (`*.ndjson` / `*.ndjson.zst`).
    Replayable,
    /// Interrupted atomic-write temps (`*.ndjson.tmp` / `*.ndjson.zst.tmp`).
    Temp,
}

fn collect_spool_files(
    dir: &Path,
    files: &mut Vec<PathBuf>,
    class: SpoolFileClass,
) -> Result<(), String> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(format!(
                "{PLUGIN_NAME}: failed to read spool directory '{}': {error}",
                dir.display()
            ));
        }
    };
    for entry in entries {
        let entry = entry.map_err(|error| {
            format!(
                "{PLUGIN_NAME}: failed to read spool directory entry '{}': {error}",
                dir.display()
            )
        })?;
        let path = entry.path();
        let meta = entry.metadata().map_err(|error| {
            format!(
                "{PLUGIN_NAME}: failed to stat spool path '{}': {error}",
                path.display()
            )
        })?;
        if meta.is_dir() {
            collect_spool_files(&path, files, class)?;
        } else if spool_file_matches(&path, class) {
            files.push(path);
        }
    }
    Ok(())
}

fn quarantine_spool_file(path: &Path) -> Result<PathBuf, String> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("{PLUGIN_NAME}: invalid spool file path"))?;
    let quarantine_path = path.with_file_name(format!("{name}.corrupt"));
    fs::rename(path, &quarantine_path).map_err(|error| {
        format!(
            "{PLUGIN_NAME}: failed to quarantine corrupt spool file '{}' to '{}': {error}",
            path.display(),
            quarantine_path.display()
        )
    })?;
    Ok(quarantine_path)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeadLetterReason {
    PermanentHttp,
    PayloadTooLarge,
}

impl DeadLetterReason {
    fn as_str(self) -> &'static str {
        match self {
            DeadLetterReason::PermanentHttp => "permanent_http",
            DeadLetterReason::PayloadTooLarge => "payload_too_large",
        }
    }
}

/// One aggregated safe outcome within a metadata-only dead-letter record.
#[derive(Debug, Clone, Serialize)]
struct DeadLetterOutcomeMeta {
    reason: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    http_status: Option<u16>,
    row_count: usize,
}

/// Safe dead-letter metadata only: no response bodies, credentials, or charge PII.
#[derive(Debug, Clone, Serialize)]
struct DeadLetterMeta {
    rejected_rows: usize,
    outcomes: Vec<DeadLetterOutcomeMeta>,
    quarantined_at_unix: i64,
}

fn dead_letter_meta_paths(path: &Path) -> Result<(PathBuf, PathBuf), String> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("{PLUGIN_NAME}: invalid spool file path"))?;
    let meta_path = path.with_file_name(format!("{name}.rejected.meta"));
    let tmp_path = path.with_file_name(format!("{name}.rejected.meta.tmp"));
    Ok((tmp_path, meta_path))
}

fn write_dead_letter_meta(
    spool: &SpoolManager,
    source_path: &Path,
    meta: &DeadLetterMeta,
) -> Result<PathBuf, String> {
    let (tmp_path, meta_path) = dead_letter_meta_paths(source_path)?;
    let bytes = serde_json::to_vec(&meta).map_err(|error| {
        format!("{PLUGIN_NAME}: failed to serialize dead-letter metadata: {error}")
    })?;
    let _guard = spool
        .write_lock
        .lock()
        .map_err(|_| format!("{PLUGIN_NAME}: spool write lock poisoned"))?;
    match fs::remove_file(&meta_path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "{PLUGIN_NAME}: failed to replace dead-letter metadata '{}': {error}",
                meta_path.display()
            ));
        }
    }
    write_private_file_atomically(&tmp_path, &meta_path, &bytes)?;
    if let Err(error) = fs::remove_file(source_path) {
        let cleanup_error = fs::remove_file(&meta_path).err();
        return Err(format!(
            "{PLUGIN_NAME}: failed to remove permanently rejected spool file '{}': {error}; dead-letter metadata cleanup: {}",
            source_path.display(),
            cleanup_error
                .map(|cleanup| cleanup.to_string())
                .unwrap_or_else(|| "ok".to_string())
        ));
    }
    // Reuse the spool's owned-byte eviction policy after replacing the source
    // payload with its much smaller safe metadata record. This also handles an
    // operator-configured max_bytes too small to retain even the metadata.
    spool.evict_until_can_admit(0)?;
    Ok(meta_path)
}

fn spool_file_matches(path: &Path, class: SpoolFileClass) -> bool {
    match class {
        SpoolFileClass::Owned => is_spool_owned_file(path),
        SpoolFileClass::Replayable => is_spool_data_file(path),
        SpoolFileClass::Temp => is_spool_temp_file(path),
    }
}

fn is_spool_data_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    (name.ends_with(".ndjson.zst") || name.ends_with(".ndjson"))
        && !name.ends_with(".tmp")
        && !name.ends_with(".corrupt")
        && !name.ends_with(".rejected")
}

fn is_spool_temp_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    name.ends_with(".ndjson.tmp")
        || name.ends_with(".ndjson.zst.tmp")
        || name.ends_with(".ndjson.rejected.meta.tmp")
        || name.ends_with(".ndjson.zst.rejected.meta.tmp")
}

fn is_spool_corrupt_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    name.ends_with(".ndjson.corrupt") || name.ends_with(".ndjson.zst.corrupt")
}

fn is_spool_rejected_meta_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    name.ends_with(".ndjson.rejected.meta") || name.ends_with(".ndjson.zst.rejected.meta")
}

fn is_spool_owned_file(path: &Path) -> bool {
    is_spool_data_file(path)
        || is_spool_temp_file(path)
        || is_spool_corrupt_file(path)
        || is_spool_rejected_meta_file(path)
}

fn encode_spool_bytes(bytes: &[u8], compression: SpoolCompression) -> Result<Vec<u8>, String> {
    match compression {
        SpoolCompression::Zstd => zstd::stream::encode_all(bytes, 0)
            .map_err(|error| format!("{PLUGIN_NAME}: zstd compression failed: {error}")),
        SpoolCompression::None => Ok(bytes.to_vec()),
    }
}

#[doc(hidden)]
#[allow(dead_code)]
pub fn encode_spool_bytes_for_tests(
    bytes: &[u8],
    compression: SpoolCompression,
) -> Result<Vec<u8>, String> {
    encode_spool_bytes(bytes, compression)
}

fn decode_spool_file(path: &Path) -> Result<String, String> {
    let mut file = File::open(path).map_err(|error| {
        format!(
            "{PLUGIN_NAME}: failed to open spool file '{}': {error}",
            path.display()
        )
    })?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|error| {
        format!(
            "{PLUGIN_NAME}: failed to read spool file '{}': {error}",
            path.display()
        )
    })?;
    let decoded = if path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.contains(".ndjson.zst"))
    {
        zstd::stream::decode_all(bytes.as_slice()).map_err(|error| {
            format!(
                "{PLUGIN_NAME}: failed to decompress spool file '{}': {error}",
                path.display()
            )
        })?
    } else {
        bytes
    };
    String::from_utf8(decoded).map_err(|error| {
        format!(
            "{PLUGIN_NAME}: spool file '{}' is not valid UTF-8 JSONEachRow: {error}",
            path.display()
        )
    })
}

#[allow(dead_code)]
pub fn decode_spool_file_for_tests(path: &Path) -> Result<String, String> {
    decode_spool_file(path)
}

#[doc(hidden)]
#[allow(dead_code)]
pub async fn replay_spool_once_for_tests(
    spool: &SpoolManager,
    insert_url: &str,
) -> Result<(), String> {
    replay_spool_once_with_batch_size_for_tests(spool, insert_url, default_batch_size()).await
}

#[doc(hidden)]
#[allow(dead_code)]
pub async fn replay_spool_once_with_batch_size_for_tests(
    spool: &SpoolManager,
    insert_url: &str,
    batch_size: usize,
) -> Result<(), String> {
    let flush_config = ClickHouseFlushConfig {
        http: ClickHouseHttpClient::Dedicated(reqwest::Client::new()),
        insert_url: insert_url.to_string(),
        username: None,
        password: None,
        timeout: Duration::from_secs(5),
        metrics: Arc::clone(&spool.metrics),
    };
    replay_spool_once(spool, &flush_config, batch_size.max(1)).await
}

#[doc(hidden)]
#[allow(dead_code)]
pub fn classify_clickhouse_http_status_for_tests(status: u16) -> &'static str {
    // Status-only helper for non-success paths. HTTP 200/204 durable success
    // additionally requires a complete empty acknowledgement body with no
    // exception header; see classify_clickhouse_acknowledgement_for_tests.
    match status {
        200 | 204 => "delivered",
        413 => "payload_too_large",
        408 | 429 => "retryable",
        code if (500..600).contains(&code) => "retryable",
        code if (400..500).contains(&code) => "permanent",
        _ => "retryable",
    }
}

/// Classify a ClickHouse acknowledgement the same way production delivery does.
///
/// `body = None` models an incomplete/ambiguous drain. `body = Some(b"")` is the
/// durable success shape for HTTP 200/204. Exception markers and
/// `X-ClickHouse-Exception-Code` never appear in returned labels or messages
/// beyond bounded reason classes.
#[doc(hidden)]
#[allow(dead_code)]
pub fn classify_clickhouse_acknowledgement_for_tests(
    status: u16,
    body: Option<&[u8]>,
    has_exception_code_header: bool,
) -> &'static str {
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let ack = match body {
        Some(bytes) => ClickHouseAckRead::Complete {
            byte_len: bytes.len() as u64,
            has_exception: body_has_clickhouse_exception(bytes),
        },
        None => ClickHouseAckRead::Incomplete {
            kind: ClickHouseAckIncomplete::TransportFailure,
        },
    };
    let metrics = Arc::new(SinkMetrics::default());
    let cfg = ClickHouseFlushConfig {
        http: ClickHouseHttpClient::Dedicated(reqwest::Client::new()),
        insert_url: "http://127.0.0.1/".to_string(),
        username: None,
        password: None,
        timeout: Duration::from_secs(1),
        metrics,
    };
    classify_clickhouse_delivery(
        &cfg,
        status,
        ack,
        has_exception_code_header,
        1,
        Duration::from_millis(1),
    )
    .label()
}

#[doc(hidden)]
#[allow(dead_code)]
pub fn clickhouse_insert_url_for_tests(config: &ApiChargebackSinkConfig) -> Result<String, String> {
    let base = Url::parse(&config.clickhouse.url)
        .map_err(|err| format!("invalid ClickHouse URL: {err}"))?;
    Ok(build_insert_url(&base, &config.clickhouse))
}

#[doc(hidden)]
#[allow(dead_code)]
pub fn write_private_file_atomically_for_tests(
    tmp_path: &Path,
    final_path: &Path,
    bytes: &[u8],
) -> Result<(), String> {
    write_private_file_atomically(tmp_path, final_path, bytes)
}

fn write_private_file_atomically(
    tmp_path: &Path,
    final_path: &Path,
    bytes: &[u8],
) -> Result<(), String> {
    let result = write_private_file_atomically_inner(tmp_path, final_path, bytes);
    if result.is_err() {
        // Keep quota accounting honest after a failed write/rename: a leftover
        // *.tmp would otherwise consume disk while remaining invisible to replay.
        let _ = fs::remove_file(tmp_path);
    }
    result
}

fn write_private_file_atomically_inner(
    tmp_path: &Path,
    final_path: &Path,
    bytes: &[u8],
) -> Result<(), String> {
    if let Some(parent) = tmp_path.parent() {
        ensure_private_dir(parent)?;
    }
    #[cfg(unix)]
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(tmp_path)
        .map_err(|error| {
            format!(
                "{PLUGIN_NAME}: failed to create spool temp file '{}': {error}",
                tmp_path.display()
            )
        })?;
    #[cfg(not(unix))]
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(tmp_path)
        .map_err(|error| {
            format!(
                "{PLUGIN_NAME}: failed to create spool temp file '{}': {error}",
                tmp_path.display()
            )
        })?;
    file.write_all(bytes).map_err(|error| {
        format!(
            "{PLUGIN_NAME}: failed to write spool temp file '{}': {error}",
            tmp_path.display()
        )
    })?;
    file.sync_all().map_err(|error| {
        format!(
            "{PLUGIN_NAME}: failed to fsync spool temp file '{}': {error}",
            tmp_path.display()
        )
    })?;
    drop(file);
    fs::rename(tmp_path, final_path).map_err(|error| {
        format!(
            "{PLUGIN_NAME}: failed to rename spool temp file '{}' to '{}': {error}",
            tmp_path.display(),
            final_path.display()
        )
    })?;
    // Durably persist the rename itself: the file contents were fsynced above,
    // but the directory entry that points at them is only guaranteed after an
    // fsync of the containing directory. Without it a crash right after rename
    // can lose the spooled batch on some filesystems. Directory fsync is a Unix
    // concept and best-effort; failure here does not invalidate the written data.
    #[cfg(unix)]
    if let Some(parent) = final_path.parent()
        && let Ok(dir) = File::open(parent)
    {
        let _ = dir.sync_all();
    }
    Ok(())
}

fn ensure_private_dir(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|error| {
        format!(
            "{PLUGIN_NAME}: failed to create spool directory '{}': {error}",
            path.display()
        )
    })?;
    #[cfg(unix)]
    {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|error| {
            format!(
                "{PLUGIN_NAME}: failed to set permissions on spool directory '{}': {error}",
                path.display()
            )
        })?;
    }
    let probe = path.join(".ferrum-write-test");
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&probe)
            .map_err(|error| {
                format!(
                    "{PLUGIN_NAME}: spool directory '{}' is not writable: {error}",
                    path.display()
                )
            })?;
        file.write_all(b"ok").map_err(|error| {
            format!(
                "{PLUGIN_NAME}: spool directory '{}' write probe failed: {error}",
                path.display()
            )
        })?;
    }
    let _ = fs::remove_file(&probe);
    Ok(())
}

fn start_spool_replayer(
    spool: Arc<SpoolManager>,
    _summary: SinkSummary,
    flush_config: ClickHouseFlushConfig,
    batch_size: usize,
    replay_interval_secs: u64,
    commit_rx: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    let batch_size = batch_size.max(1);
    tokio::spawn(async move {
        if !wait_until_committed(commit_rx).await {
            return;
        }
        let mut timer = tokio::time::interval(Duration::from_secs(replay_interval_secs));
        loop {
            timer.tick().await;
            if let Err(error) = spool.prepare_live_storage() {
                warn!(
                    plugin = PLUGIN_NAME,
                    error = %error,
                    "Chargeback sink live spool preparation failed"
                );
                continue;
            }
            if let Err(error) = replay_spool_once(&spool, &flush_config, batch_size).await {
                warn!(plugin = PLUGIN_NAME, error = %error, "Chargeback sink spool replay failed");
            }
        }
    })
}

async fn replay_spool_once(
    spool: &SpoolManager,
    flush_config: &ClickHouseFlushConfig,
    batch_size: usize,
) -> Result<(), String> {
    let files = spool.list_replayable_spool_files()?;
    for file in files {
        let body = match decode_spool_file(&file) {
            Ok(body) => body,
            Err(error) => {
                spool
                    .metrics
                    .record_failure(FailureReason::Serialize, error.clone());
                match quarantine_spool_file(&file) {
                    Ok(quarantine_path) => {
                        warn!(
                            plugin = PLUGIN_NAME,
                            error = %error,
                            path = %file.display(),
                            quarantine_path = %quarantine_path.display(),
                            "Chargeback sink quarantined an unreadable spool file and will continue replay"
                        );
                    }
                    Err(quarantine_error) => {
                        warn!(
                            plugin = PLUGIN_NAME,
                            error = %error,
                            quarantine_error = %quarantine_error,
                            path = %file.display(),
                            "Chargeback sink could not quarantine an unreadable spool file; replay will continue"
                        );
                    }
                }
                continue;
            }
        };
        let lines: Vec<String> = body
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(str::to_owned)
            .collect();
        if lines.is_empty() {
            fs::remove_file(&file).map_err(|error| {
                format!(
                    "{PLUGIN_NAME}: failed to remove empty spool file '{}': {error}",
                    file.display()
                )
            })?;
            continue;
        }

        match replay_spool_lines(flush_config, &lines, batch_size).await {
            Ok(dead_letters) => {
                finalize_replayed_spool_file(spool, &file, lines.len(), dead_letters)?;
                spool
                    .metrics
                    .last_replay_at
                    .store(unix_timestamp_seconds(), Ordering::Relaxed);
                invalidate_status_cache();
            }
            Err(error) => {
                // Retryable delivery failure: keep this file and stop the tick so
                // ordering is preserved across transient outages. Permanent
                // rejection is handled inside replay_spool_lines via dead-letter.
                return Err(error);
            }
        }
    }
    Ok(())
}

struct DeadLetterChunk {
    row_count: usize,
    reason: DeadLetterReason,
    http_status: Option<u16>,
}

/// Deliver spool JSONEachRow lines with status-aware split / dead-letter policy.
///
/// On retryable failure returns `Err` and leaves caller-owned durable state
/// unchanged. Permanent rejection and single-row 413 become dead-letter chunks.
/// Multi-row 413 splits deterministically using `batch_size` without rewriting
/// row payloads (event_id and other fields stay byte-identical).
async fn replay_spool_lines(
    flush_config: &ClickHouseFlushConfig,
    lines: &[String],
    batch_size: usize,
) -> Result<Vec<DeadLetterChunk>, String> {
    let mut dead_letters = Vec::new();
    let mut stack: Vec<Vec<String>> = vec![lines.to_vec()];
    while let Some(chunk) = stack.pop() {
        if chunk.is_empty() {
            continue;
        }
        let body = chunk.join("\n");
        match post_json_each_row(flush_config, body, chunk.len()).await {
            DeliveryOutcome::Delivered => {}
            DeliveryOutcome::Retryable { message } => return Err(message),
            DeliveryOutcome::PayloadTooLarge { .. } => {
                if chunk.len() == 1 {
                    dead_letters.push(DeadLetterChunk {
                        row_count: 1,
                        reason: DeadLetterReason::PayloadTooLarge,
                        http_status: Some(413),
                    });
                } else {
                    let split_at = replay_split_len(chunk.len(), batch_size);
                    let right = chunk[split_at..].to_vec();
                    let left = chunk[..split_at].to_vec();
                    // Stack: push right first so left is delivered first.
                    stack.push(right);
                    stack.push(left);
                }
            }
            DeliveryOutcome::Permanent { status, .. } => {
                dead_letters.push(DeadLetterChunk {
                    row_count: chunk.len(),
                    reason: DeadLetterReason::PermanentHttp,
                    http_status: Some(status),
                });
            }
        }
    }
    Ok(dead_letters)
}

fn finalize_replayed_spool_file(
    spool: &SpoolManager,
    file: &Path,
    original_row_count: usize,
    dead_letters: Vec<DeadLetterChunk>,
) -> Result<(), String> {
    if dead_letters.is_empty() {
        fs::remove_file(file).map_err(|error| {
            format!(
                "{PLUGIN_NAME}: failed to remove replayed spool file '{}': {error}",
                file.display()
            )
        })?;
        return Ok(());
    }

    let rejected_rows: usize = dead_letters.iter().map(|chunk| chunk.row_count).sum();
    if rejected_rows > original_row_count {
        return Err(format!(
            "{PLUGIN_NAME}: dead-letter row count ({rejected_rows}) exceeds source row count ({original_row_count})"
        ));
    }
    let mut outcomes: Vec<DeadLetterOutcomeMeta> = Vec::new();
    for chunk in dead_letters {
        if let Some(existing) = outcomes.iter_mut().find(|outcome| {
            outcome.reason == chunk.reason.as_str() && outcome.http_status == chunk.http_status
        }) {
            existing.row_count = existing.row_count.saturating_add(chunk.row_count);
        } else {
            outcomes.push(DeadLetterOutcomeMeta {
                reason: chunk.reason.as_str(),
                http_status: chunk.http_status,
                row_count: chunk.row_count,
            });
        }
    }
    let meta = DeadLetterMeta {
        rejected_rows,
        outcomes,
        quarantined_at_unix: unix_timestamp_seconds(),
    };
    let meta_path = write_dead_letter_meta(spool, file, &meta)?;
    warn!(
        plugin = PLUGIN_NAME,
        rejected_rows,
        source_rows = original_row_count,
        outcome_count = meta.outcomes.len(),
        path = %file.display(),
        meta_path = %meta_path.display(),
        "Chargeback sink recorded safe dead-letter metadata for permanently rejected spool rows and will continue replay"
    );
    Ok(())
}

/// Immutable categorical dimensions for one snapshot accumulator identity.
///
/// The complete value is the typed accumulator key and is also copied into
/// emitted `ChargeEvent`s. It must not be treated as first-writer-wins
/// decoration on a coarser or delimiter-encoded identity.
#[derive(Clone, Eq, Hash, PartialEq)]
struct SnapshotMetadata {
    namespace: String,
    consumer_id: String,
    consumer_name: Option<String>,
    proxy_id: String,
    proxy_name: String,
    route_id: Option<String>,
    status_code: u16,
    http_status_code: Option<u16>,
    grpc_status: Option<u32>,
    protocol: String,
}

#[derive(Default, Debug, Clone, Copy, PartialEq)]
pub struct SnapshotTotals {
    pub call_count: u64,
    pub charge_call: f64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub charge_bytes_sent: f64,
    pub charge_bytes_received: f64,
    pub charge_total: f64,
}

impl SnapshotTotals {
    fn delta_since(self, last: SnapshotTotals) -> Result<SnapshotTotals, String> {
        Ok(SnapshotTotals {
            call_count: self.call_count.saturating_sub(last.call_count),
            charge_call: non_negative_delta(self.charge_call, last.charge_call, "charge_call")?,
            bytes_sent: self.bytes_sent.saturating_sub(last.bytes_sent),
            bytes_received: self.bytes_received.saturating_sub(last.bytes_received),
            charge_bytes_sent: non_negative_delta(
                self.charge_bytes_sent,
                last.charge_bytes_sent,
                "charge_bytes_sent",
            )?,
            charge_bytes_received: non_negative_delta(
                self.charge_bytes_received,
                last.charge_bytes_received,
                "charge_bytes_received",
            )?,
            charge_total: non_negative_delta(self.charge_total, last.charge_total, "charge_total")?,
        })
    }

    fn is_zero(self) -> bool {
        self.call_count == 0
            && self.bytes_sent == 0
            && self.bytes_received == 0
            && self.charge_call == 0.0
            && self.charge_bytes_sent == 0.0
            && self.charge_bytes_received == 0.0
            && self.charge_total == 0.0
    }
}

struct SnapshotAtomicTotals {
    call_count: AtomicU64,
    charge_call_bits: AtomicU64,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    charge_bytes_sent_bits: AtomicU64,
    charge_bytes_received_bits: AtomicU64,
    charge_total_bits: AtomicU64,
}

impl Default for SnapshotAtomicTotals {
    fn default() -> Self {
        Self {
            call_count: AtomicU64::new(0),
            charge_call_bits: AtomicU64::new(0f64.to_bits()),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            charge_bytes_sent_bits: AtomicU64::new(0f64.to_bits()),
            charge_bytes_received_bits: AtomicU64::new(0f64.to_bits()),
            charge_total_bits: AtomicU64::new(0f64.to_bits()),
        }
    }
}

impl SnapshotAtomicTotals {
    fn add(&self, charge: ChargeComputation) {
        self.call_count
            .fetch_add(charge.call_count as u64, Ordering::Relaxed);
        add_f64_atomic(&self.charge_call_bits, charge.charge_call);
        self.bytes_sent
            .fetch_add(charge.bytes_sent, Ordering::Relaxed);
        self.bytes_received
            .fetch_add(charge.bytes_received, Ordering::Relaxed);
        add_f64_atomic(&self.charge_bytes_sent_bits, charge.charge_bytes_sent);
        add_f64_atomic(
            &self.charge_bytes_received_bits,
            charge.charge_bytes_received,
        );
        add_f64_atomic(&self.charge_total_bits, charge.charge_total);
    }

    fn snapshot(&self) -> SnapshotTotals {
        SnapshotTotals {
            call_count: self.call_count.load(Ordering::Relaxed),
            charge_call: f64::from_bits(self.charge_call_bits.load(Ordering::Relaxed)),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            charge_bytes_sent: f64::from_bits(self.charge_bytes_sent_bits.load(Ordering::Relaxed)),
            charge_bytes_received: f64::from_bits(
                self.charge_bytes_received_bits.load(Ordering::Relaxed),
            ),
            charge_total: f64::from_bits(self.charge_total_bits.load(Ordering::Relaxed)),
        }
    }
}

struct SnapshotEntry {
    meta: SnapshotMetadata,
    totals: SnapshotAtomicTotals,
    last_seen_at: AtomicI64,
    /// Stable identity for this map slot. Assigned once at insert and never
    /// changed by in-place refreshes. Couples `last_emitted` cleanup to the
    /// exact entry generation that eviction removed.
    generation: u64,
    /// Bumped on every `record` (insert or refresh). Stale cleanup observes a
    /// revision and only evicts when that exact revision is still present, so a
    /// same-key refresh that races after the stale check cannot be deleted.
    revision: AtomicU64,
}

/// Baseline emitted for one accumulator generation of a snapshot identity.
struct LastEmitted {
    generation: u64,
    totals: SnapshotTotals,
}

struct PreparedSnapshot {
    events: Vec<ChargeEvent>,
    emitted_totals: Vec<(SnapshotMetadata, u64, SnapshotTotals)>,
}

#[cfg(test)]
type CleanupAfterStaleCheckHook = Arc<dyn Fn() + Send + Sync + 'static>;

pub struct SnapshotAccumulator {
    entries: DashMap<SnapshotMetadata, SnapshotEntry>,
    last_emitted: DashMap<SnapshotMetadata, LastEmitted>,
    next_generation: AtomicU64,
    /// Test-only callback invoked after a key is selected as a stale candidate
    /// and before conditional eviction. Production leaves this unset.
    #[cfg(test)]
    cleanup_after_stale_check_hook: Mutex<Option<CleanupAfterStaleCheckHook>>,
}

impl SnapshotAccumulator {
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
            last_emitted: DashMap::new(),
            next_generation: AtomicU64::new(1),
            #[cfg(test)]
            cleanup_after_stale_check_hook: Mutex::new(None),
        }
    }

    fn record_http(
        &self,
        summary: &TransactionSummary,
        consumer: &str,
        outcome: HttpBillingOutcome,
        charge: ChargeComputation,
    ) {
        let proxy_id = summary.proxy_id.as_deref().unwrap_or("unknown");
        let proxy_name = summary.proxy_name.as_deref().unwrap_or("unknown");
        let meta = SnapshotMetadata {
            namespace: bound_string(&summary.namespace, MAX_FIELD_LEN),
            consumer_id: bound_string(consumer, MAX_FIELD_LEN),
            consumer_name: metadata_value(&summary.metadata, &["consumer_name"]),
            proxy_id: bound_string(proxy_id, MAX_FIELD_LEN),
            proxy_name: bound_string(proxy_name, MAX_FIELD_LEN),
            route_id: metadata_value(&summary.metadata, &["route_id"]),
            status_code: outcome.status_code,
            http_status_code: Some(outcome.http_status_code),
            grpc_status: outcome.grpc_status.map(normalize_snapshot_grpc_status),
            protocol: infer_http_protocol(summary),
        };
        self.record(meta, charge);
    }

    fn record_stream(
        &self,
        summary: &StreamTransactionSummary,
        consumer: &str,
        charge: ChargeComputation,
    ) {
        let meta = SnapshotMetadata {
            namespace: bound_string(&summary.namespace, MAX_FIELD_LEN),
            consumer_id: bound_string(consumer, MAX_FIELD_LEN),
            consumer_name: metadata_value(&summary.metadata, &["consumer_name"]),
            proxy_id: bound_string(&summary.proxy_id, MAX_FIELD_LEN),
            proxy_name: bound_string(
                summary.proxy_name.as_deref().unwrap_or("unknown"),
                MAX_FIELD_LEN,
            ),
            route_id: metadata_value(&summary.metadata, &["route_id"]),
            status_code: STREAM_STATUS_SENTINEL,
            http_status_code: None,
            grpc_status: None,
            protocol: bound_string(&summary.protocol, MAX_FIELD_LEN),
        };
        self.record(meta, charge);
    }

    fn record_websocket(
        &self,
        summary: &WsDisconnectContext,
        consumer: &str,
        charge: ChargeComputation,
    ) {
        let meta = SnapshotMetadata {
            namespace: bound_string(&summary.namespace, MAX_FIELD_LEN),
            consumer_id: bound_string(consumer, MAX_FIELD_LEN),
            consumer_name: metadata_value(&summary.metadata, &["consumer_name"]),
            proxy_id: bound_string(&summary.proxy_id, MAX_FIELD_LEN),
            proxy_name: bound_string(
                summary.proxy_name.as_deref().unwrap_or("unknown"),
                MAX_FIELD_LEN,
            ),
            route_id: metadata_value(&summary.metadata, &["route_id"]),
            status_code: STREAM_STATUS_SENTINEL,
            http_status_code: None,
            grpc_status: None,
            protocol: "ws".to_string(),
        };
        self.record(meta, charge);
    }

    fn record(&self, meta: SnapshotMetadata, charge: ChargeComputation) {
        self.record_at(meta, charge, unix_timestamp_seconds());
    }

    fn record_at(&self, meta: SnapshotMetadata, charge: ChargeComputation, now: i64) {
        // Use the typed metadata value itself as the key. A delimiter-encoded
        // string would allow hostile or ordinary `|` characters in route/name
        // dimensions to collide and recreate mixed attribution.
        let key = meta.clone();
        let entry = self.entries.entry(key).or_insert_with(|| SnapshotEntry {
            meta,
            totals: SnapshotAtomicTotals::default(),
            last_seen_at: AtomicI64::new(now),
            generation: self.next_generation.fetch_add(1, Ordering::Relaxed),
            revision: AtomicU64::new(0),
        });
        // Refresh under the DashMap entry guard so a concurrent same-key
        // `remove_if` either observes the bumped revision or runs entirely
        // before this refresh (in which case this `entry` insert recreates).
        entry.last_seen_at.store(now, Ordering::Relaxed);
        entry.revision.fetch_add(1, Ordering::Relaxed);
        entry.totals.add(charge);
    }

    // External integration tests exercise the public accumulator contract;
    // the separately compiled binary cannot observe those call sites.
    #[allow(dead_code)]
    pub fn compute_deltas(
        &self,
        config: &ApiChargebackSinkConfig,
        node_id: &str,
        received_at: i64,
        snapshot_id: &str,
    ) -> Result<Vec<ChargeEvent>, String> {
        let prepared = self.prepare_deltas(config, node_id, received_at, snapshot_id)?;
        self.commit_prepared(&prepared);
        Ok(prepared.events)
    }

    fn prepare_deltas(
        &self,
        config: &ApiChargebackSinkConfig,
        node_id: &str,
        received_at: i64,
        snapshot_id: &str,
    ) -> Result<PreparedSnapshot, String> {
        let mut events = Vec::new();
        let mut emitted_totals = Vec::new();
        for entry in self.entries.iter() {
            let key = entry.key().clone();
            let generation = entry.value().generation;
            let current = entry.value().totals.snapshot();
            // Ignore a baseline tagged for a different generation (for example
            // an orphan left after eviction+reinsert). That treats the live
            // entry as starting from zero rather than subtracting a stale
            // prior total.
            let last = self
                .last_emitted
                .get(&key)
                .filter(|value| value.generation == generation)
                .map(|value| value.totals)
                .unwrap_or_default();
            let delta = current.delta_since(last)?;
            if !delta.is_zero() || config.snapshot.emit_zero_deltas {
                events.push(event_from_snapshot(
                    &entry.value().meta,
                    delta,
                    config,
                    node_id,
                    received_at,
                    snapshot_id,
                ));
                emitted_totals.push((key, generation, current));
            }
        }
        Ok(PreparedSnapshot {
            events,
            emitted_totals,
        })
    }

    fn commit_prepared(&self, prepared: &PreparedSnapshot) {
        for (key, generation, current) in &prepared.emitted_totals {
            // Publish the baseline only while this generation is still live so
            // a concurrent eviction cannot leave an orphaned baseline that a
            // later reinsert would mis-subtract, and so we cannot overwrite a
            // newer generation's baseline with an older snapshot read.
            if let Some(entry) = self.entries.get(key)
                && entry.generation == *generation
            {
                // Keep the entry guard through publication. Cleanup cannot
                // evict this generation and remove its baseline between
                // the generation check and the insert.
                self.last_emitted.insert(
                    key.clone(),
                    LastEmitted {
                        generation: *generation,
                        totals: *current,
                    },
                );
            }
        }
    }

    #[allow(dead_code)]
    pub fn cleanup_stale_for_tests(&self, stale_entry_ttl_secs: u64) -> usize {
        self.cleanup_stale(unix_timestamp_seconds(), stale_entry_ttl_secs)
    }

    #[cfg(test)]
    fn set_cleanup_after_stale_check_hook(&self, hook: Option<CleanupAfterStaleCheckHook>) {
        if let Ok(mut slot) = self.cleanup_after_stale_check_hook.lock() {
            *slot = hook;
        }
    }

    #[cfg(test)]
    fn run_cleanup_after_stale_check_hook(&self) {
        let hook = self
            .cleanup_after_stale_check_hook
            .lock()
            .ok()
            .and_then(|slot| slot.clone());
        if let Some(hook) = hook {
            hook();
        }
    }

    fn cleanup_stale(&self, now: i64, stale_entry_ttl_secs: u64) -> usize {
        let cutoff = now.saturating_sub(stale_entry_ttl_secs.min(i64::MAX as u64) as i64);
        // Candidate scan is best-effort. Eviction re-validates generation,
        // revision, and staleness atomically under the DashMap shard lock so a
        // same-key refresh cannot be deleted, and unrelated keys stay
        // non-blocking (no global request-path lock).
        let candidates: Vec<(SnapshotMetadata, u64, u64)> = self
            .entries
            .iter()
            .filter(|entry| entry.value().last_seen_at.load(Ordering::Relaxed) <= cutoff)
            .map(|entry| {
                (
                    entry.key().clone(),
                    entry.value().generation,
                    entry.value().revision.load(Ordering::Relaxed),
                )
            })
            .collect();
        let mut removed = 0;
        for (key, observed_generation, observed_revision) in candidates {
            #[cfg(test)]
            self.run_cleanup_after_stale_check_hook();
            if let Some((_, evicted)) = self.entries.remove_if(&key, |_, entry| {
                entry.generation == observed_generation
                    && entry.revision.load(Ordering::Relaxed) == observed_revision
                    && entry.last_seen_at.load(Ordering::Relaxed) <= cutoff
            }) {
                // Drop the baseline only for the generation that was actually
                // evicted. A concurrent reinsert+emit for a newer generation
                // must keep its last_emitted row.
                self.last_emitted.remove_if(&key, |_, baseline| {
                    baseline.generation == evicted.generation
                });
                removed += 1;
            }
        }
        removed
    }

    #[allow(dead_code)]
    #[allow(clippy::too_many_arguments)]
    pub fn record_for_test(
        &self,
        namespace: &str,
        consumer: &str,
        proxy_id: &str,
        proxy_name: &str,
        status_code: u16,
        protocol: &str,
        charge: ChargeComputation,
    ) {
        self.record_at(
            SnapshotMetadata {
                namespace: namespace.to_string(),
                consumer_id: consumer.to_string(),
                consumer_name: None,
                proxy_id: proxy_id.to_string(),
                proxy_name: proxy_name.to_string(),
                route_id: None,
                status_code,
                http_status_code: (protocol == "http").then_some(status_code),
                grpc_status: None,
                protocol: protocol.to_string(),
            },
            charge,
            unix_timestamp_seconds(),
        );
    }

    #[doc(hidden)]
    #[allow(dead_code)]
    pub fn record_http_for_test(
        &self,
        summary: &TransactionSummary,
        consumer: &str,
        charge: ChargeComputation,
    ) {
        self.record_http(summary, consumer, http_billing_outcome(summary), charge);
    }
}

impl Default for SnapshotAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

fn start_snapshot_task(
    accumulator: Arc<SnapshotAccumulator>,
    runtime: Arc<SinkRuntime>,
    config: Arc<ApiChargebackSinkConfig>,
    node_id: Arc<str>,
    commit_rx: watch::Receiver<bool>,
    mut shutdown_rx: watch::Receiver<bool>,
    emission_lock: Arc<Mutex<()>>,
) -> tokio::task::JoinHandle<bool> {
    tokio::spawn(async move {
        if *shutdown_rx.borrow() {
            return if *commit_rx.borrow() {
                emit_final_snapshot_to_spool(
                    &accumulator,
                    &runtime,
                    &config,
                    &node_id,
                    &emission_lock,
                )
            } else {
                true
            };
        }
        let commit_observer = commit_rx.clone();
        let committed = tokio::select! {
            committed = wait_until_committed(commit_rx) => committed,
            _ = wait_for_snapshot_shutdown(&mut shutdown_rx) => {
                if *commit_observer.borrow() {
                    return emit_final_snapshot_to_spool(
                        &accumulator,
                        &runtime,
                        &config,
                        &node_id,
                        &emission_lock,
                    );
                }
                false
            },
        };
        if !committed {
            return true;
        }
        let mut snapshot_timer =
            tokio::time::interval(Duration::from_secs(config.snapshot.interval_secs));
        let mut cleanup_timer =
            tokio::time::interval(Duration::from_secs(config.snapshot.cleanup_interval_secs));
        // Tokio intervals are immediately ready on their first tick. Consume
        // those scheduling ticks so the documented interval starts at
        // generation commit instead of racing the first request.
        snapshot_timer.tick().await;
        cleanup_timer.tick().await;
        loop {
            tokio::select! {
                biased;
                _ = wait_for_snapshot_shutdown(&mut shutdown_rx) => {
                    return emit_final_snapshot_to_spool(
                        &accumulator,
                        &runtime,
                        &config,
                        &node_id,
                        &emission_lock,
                    );
                }
                _ = snapshot_timer.tick() => {
                    let _ = emit_periodic_snapshot(
                        &accumulator,
                        &runtime,
                        &config,
                        &node_id,
                        &emission_lock,
                    );
                }
                _ = cleanup_timer.tick() => {
                    let removed = accumulator.cleanup_stale(
                        unix_timestamp_seconds(),
                        config.snapshot.stale_entry_ttl_secs,
                    );
                    if removed > 0 {
                        invalidate_status_cache();
                    }
                }
            }
        }
    })
}

fn emit_periodic_snapshot(
    accumulator: &SnapshotAccumulator,
    runtime: &SinkRuntime,
    config: &ApiChargebackSinkConfig,
    node_id: &str,
    emission_lock: &Mutex<()>,
) -> Result<usize, String> {
    let _emission_guard = match emission_lock.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let snapshot_id = new_ulid();
    let received_at = unix_timestamp_nanos();
    let prepared = match accumulator.prepare_deltas(config, node_id, received_at, &snapshot_id) {
        Ok(prepared) => prepared,
        Err(error) => {
            runtime
                .metrics
                .record_failure(FailureReason::Serialize, error.clone());
            warn!(
                plugin = PLUGIN_NAME,
                error = %error,
                "Chargeback sink snapshot arithmetic failed; no delta was advanced"
            );
            return Err(error);
        }
    };
    let event_count = prepared.events.len();
    if event_count == 0 {
        return Ok(0);
    }
    let Some(spool) = runtime.spool.as_ref() else {
        let error = "snapshot emission requires an available spool".to_string();
        runtime
            .metrics
            .record_failure(FailureReason::Serialize, error.clone());
        return Err(error);
    };
    if let Err(error) = spool.write_events(&prepared.events) {
        runtime
            .metrics
            .spool_available
            .store(false, Ordering::Release);
        let error = format!("periodic snapshot spool handoff failed: {error}");
        runtime
            .metrics
            .record_failure(FailureReason::Serialize, error.clone());
        warn!(
            plugin = PLUGIN_NAME,
            generation = runtime.generation,
            error = %error,
            "Chargeback sink could not durably spool its periodic snapshot; no baseline was advanced"
        );
        return Err(error);
    }
    // Snapshot mode requires the spool. Make it the durable commit point before
    // advancing the accumulator baseline, then enqueue the exact same event IDs
    // as a low-latency delivery attempt. A reload racing this point can abort the
    // queue worker without losing or double-charging the snapshot: replay is
    // idempotent on event_id.
    accumulator.commit_prepared(&prepared);
    runtime
        .metrics
        .snapshot_emits_total
        .fetch_add(event_count as u64, Ordering::Relaxed);
    for event in prepared.events {
        runtime
            .metrics
            .events_enqueued_total
            .fetch_add(1, Ordering::Relaxed);
        runtime.logger.try_send(event);
    }
    invalidate_status_cache();
    Ok(event_count)
}

async fn wait_for_snapshot_shutdown(shutdown_rx: &mut watch::Receiver<bool>) {
    while !*shutdown_rx.borrow() {
        if shutdown_rx.changed().await.is_err() {
            break;
        }
    }
}

fn emit_final_snapshot_to_spool(
    accumulator: &SnapshotAccumulator,
    runtime: &SinkRuntime,
    config: &ApiChargebackSinkConfig,
    node_id: &str,
    emission_lock: &Mutex<()>,
) -> bool {
    let _emission_guard = match emission_lock.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let snapshot_id = new_ulid();
    let received_at = unix_timestamp_nanos();
    let prepared = match accumulator.prepare_deltas(config, node_id, received_at, &snapshot_id) {
        Ok(prepared) => prepared,
        Err(error) => {
            runtime
                .metrics
                .record_failure(FailureReason::Serialize, error.clone());
            warn!(
                plugin = PLUGIN_NAME,
                generation = runtime.generation,
                error = %error,
                "Chargeback sink final snapshot arithmetic failed; generation state retained"
            );
            return false;
        }
    };
    if prepared.events.is_empty() {
        return true;
    }
    let Some(spool) = runtime.spool.as_ref() else {
        runtime.metrics.record_failure(
            FailureReason::Serialize,
            "snapshot finalization requires an available spool",
        );
        return false;
    };
    if let Err(error) = spool.write_events(&prepared.events) {
        runtime
            .metrics
            .spool_available
            .store(false, Ordering::Release);
        runtime.metrics.record_failure(
            FailureReason::Serialize,
            format!("final snapshot spool handoff failed: {error}"),
        );
        warn!(
            plugin = PLUGIN_NAME,
            generation = runtime.generation,
            error = %error,
            "Chargeback sink could not durably spool its final snapshot; generation state retained"
        );
        return false;
    }
    accumulator.commit_prepared(&prepared);
    runtime
        .metrics
        .snapshot_emits_total
        .fetch_add(prepared.events.len() as u64, Ordering::Relaxed);
    invalidate_status_cache();
    true
}

fn event_from_http_summary(
    summary: &TransactionSummary,
    consumer: &str,
    outcome: HttpBillingOutcome,
    charge: ChargeComputation,
    config: &ApiChargebackSinkConfig,
    node_id: &str,
    snapshot_id: Option<String>,
) -> ChargeEvent {
    let metadata = &summary.metadata;
    ChargeEvent {
        event_id: new_ulid(),
        received_at: unix_timestamp_nanos(),
        node_id: bound_string(node_id, MAX_FIELD_LEN),
        namespace: bound_string(&summary.namespace, MAX_FIELD_LEN),
        consumer_id: bound_string(consumer, MAX_FIELD_LEN),
        consumer_name: metadata_value(metadata, &["consumer_name"]),
        proxy_id: bound_string(
            summary.proxy_id.as_deref().unwrap_or("unknown"),
            MAX_FIELD_LEN,
        ),
        proxy_name: bound_string(
            summary.proxy_name.as_deref().unwrap_or("unknown"),
            MAX_FIELD_LEN,
        ),
        route_id: metadata_value(metadata, &["route_id"]),
        status_code: outcome.status_code,
        http_status_code: Some(outcome.http_status_code),
        grpc_status: outcome.grpc_status,
        protocol: infer_http_protocol(summary),
        call_count: charge.call_count,
        charge_call: charge.charge_call,
        bytes_sent: charge.bytes_sent,
        bytes_received: charge.bytes_received,
        charge_bytes_sent: charge.charge_bytes_sent,
        charge_bytes_received: charge.charge_bytes_received,
        charge_total: charge.charge_total,
        currency: config.currency.clone(),
        pricing_version: config.pricing_version.clone(),
        request_id: if config.include_request_id {
            metadata_value(
                metadata,
                &[
                    super::REQUEST_ID_METADATA_KEY,
                    "x-request-id",
                    "correlation_id",
                ],
            )
        } else {
            None
        },
        trace_id: if config.include_trace_id {
            metadata_value(metadata, &["trace_id", "traceparent"])
        } else {
            None
        },
        snapshot_id,
    }
}

fn event_from_stream_summary(
    summary: &StreamTransactionSummary,
    consumer: &str,
    charge: ChargeComputation,
    config: &ApiChargebackSinkConfig,
    node_id: &str,
    snapshot_id: Option<String>,
) -> ChargeEvent {
    let metadata = &summary.metadata;
    ChargeEvent {
        event_id: new_ulid(),
        received_at: unix_timestamp_nanos(),
        node_id: bound_string(node_id, MAX_FIELD_LEN),
        namespace: bound_string(&summary.namespace, MAX_FIELD_LEN),
        consumer_id: bound_string(consumer, MAX_FIELD_LEN),
        consumer_name: metadata_value(metadata, &["consumer_name"]),
        proxy_id: bound_string(&summary.proxy_id, MAX_FIELD_LEN),
        proxy_name: bound_string(
            summary.proxy_name.as_deref().unwrap_or("unknown"),
            MAX_FIELD_LEN,
        ),
        route_id: metadata_value(metadata, &["route_id"]),
        status_code: STREAM_STATUS_SENTINEL,
        http_status_code: None,
        grpc_status: None,
        protocol: bound_string(&summary.protocol, MAX_FIELD_LEN),
        call_count: charge.call_count,
        charge_call: charge.charge_call,
        bytes_sent: charge.bytes_sent,
        bytes_received: charge.bytes_received,
        charge_bytes_sent: charge.charge_bytes_sent,
        charge_bytes_received: charge.charge_bytes_received,
        charge_total: charge.charge_total,
        currency: config.currency.clone(),
        pricing_version: config.pricing_version.clone(),
        request_id: if config.include_request_id {
            metadata_value(
                metadata,
                &[
                    super::REQUEST_ID_METADATA_KEY,
                    "x-request-id",
                    "correlation_id",
                ],
            )
        } else {
            None
        },
        trace_id: if config.include_trace_id {
            metadata_value(metadata, &["trace_id", "traceparent"])
        } else {
            None
        },
        snapshot_id,
    }
}

fn event_from_ws_summary(
    summary: &WsDisconnectContext,
    consumer: &str,
    charge: ChargeComputation,
    config: &ApiChargebackSinkConfig,
    node_id: &str,
    snapshot_id: Option<String>,
) -> ChargeEvent {
    let metadata = &summary.metadata;
    ChargeEvent {
        event_id: new_ulid(),
        received_at: unix_timestamp_nanos(),
        node_id: bound_string(node_id, MAX_FIELD_LEN),
        namespace: bound_string(&summary.namespace, MAX_FIELD_LEN),
        consumer_id: bound_string(consumer, MAX_FIELD_LEN),
        consumer_name: metadata_value(metadata, &["consumer_name"]),
        proxy_id: bound_string(&summary.proxy_id, MAX_FIELD_LEN),
        proxy_name: bound_string(
            summary.proxy_name.as_deref().unwrap_or("unknown"),
            MAX_FIELD_LEN,
        ),
        route_id: metadata_value(metadata, &["route_id"]),
        status_code: STREAM_STATUS_SENTINEL,
        http_status_code: None,
        grpc_status: None,
        protocol: "ws".to_string(),
        call_count: charge.call_count,
        charge_call: charge.charge_call,
        bytes_sent: charge.bytes_sent,
        bytes_received: charge.bytes_received,
        charge_bytes_sent: charge.charge_bytes_sent,
        charge_bytes_received: charge.charge_bytes_received,
        charge_total: charge.charge_total,
        currency: config.currency.clone(),
        pricing_version: config.pricing_version.clone(),
        request_id: if config.include_request_id {
            metadata_value(
                metadata,
                &[
                    super::REQUEST_ID_METADATA_KEY,
                    "x-request-id",
                    "correlation_id",
                ],
            )
        } else {
            None
        },
        trace_id: if config.include_trace_id {
            metadata_value(metadata, &["trace_id", "traceparent"])
        } else {
            None
        },
        snapshot_id,
    }
}

fn event_from_snapshot(
    meta: &SnapshotMetadata,
    totals: SnapshotTotals,
    config: &ApiChargebackSinkConfig,
    node_id: &str,
    received_at: i64,
    snapshot_id: &str,
) -> ChargeEvent {
    ChargeEvent {
        event_id: new_ulid(),
        received_at,
        node_id: bound_string(node_id, MAX_FIELD_LEN),
        namespace: meta.namespace.clone(),
        consumer_id: meta.consumer_id.clone(),
        consumer_name: meta.consumer_name.clone(),
        proxy_id: meta.proxy_id.clone(),
        proxy_name: meta.proxy_name.clone(),
        route_id: meta.route_id.clone(),
        status_code: meta.status_code,
        http_status_code: meta.http_status_code,
        grpc_status: meta.grpc_status,
        protocol: meta.protocol.clone(),
        call_count: saturating_u64_to_u32(totals.call_count),
        charge_call: totals.charge_call,
        bytes_sent: totals.bytes_sent,
        bytes_received: totals.bytes_received,
        charge_bytes_sent: totals.charge_bytes_sent,
        charge_bytes_received: totals.charge_bytes_received,
        charge_total: totals.charge_total,
        currency: config.currency.clone(),
        pricing_version: config.pricing_version.clone(),
        request_id: None,
        trace_id: None,
        snapshot_id: Some(snapshot_id.to_string()),
    }
}

fn infer_http_protocol(summary: &TransactionSummary) -> String {
    if let Some(protocol) = summary
        .metadata
        .get("request_protocol")
        .or_else(|| summary.metadata.get("mesh.request_protocol"))
    {
        return bound_string(protocol, MAX_FIELD_LEN);
    }
    if summary.response_status_code == 101 {
        "ws".to_string()
    } else {
        "http".to_string()
    }
}

fn metadata_value(metadata: &HashMap<String, String>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| metadata.get(*key))
        .map(|value| bound_string(value, MAX_METADATA_FIELD_LEN))
        .filter(|value| !value.is_empty())
}

fn bound_string(value: &str, max_len: usize) -> String {
    if value.len() <= max_len {
        return value.to_string();
    }
    let mut end = max_len;
    while !value.is_char_boundary(end) && end > 0 {
        end -= 1;
    }
    value[..end].to_string()
}

fn normalize_snapshot_grpc_status(status: u32) -> u32 {
    if status <= 16 {
        status
    } else {
        GRPC_STATUS_OTHER_SENTINEL
    }
}

fn non_negative_delta(current: f64, last: f64, field: &str) -> Result<f64, String> {
    if !current.is_finite() || !last.is_finite() {
        return Err(format!(
            "{PLUGIN_NAME}: snapshot {field} is non-finite (current={current}, last={last})"
        ));
    }
    if current < last {
        return Err(format!(
            "{PLUGIN_NAME}: snapshot {field} regressed (current={current}, last={last})"
        ));
    }
    Ok(current - last)
}

fn saturating_u64_to_u32(value: u64) -> u32 {
    if value > u32::MAX as u64 {
        u32::MAX
    } else {
        value as u32
    }
}

fn add_f64_atomic(slot: &AtomicU64, delta: f64) {
    loop {
        let old = slot.load(Ordering::Relaxed);
        let new_val = f64::from_bits(old) + delta;
        match slot.compare_exchange_weak(
            old,
            new_val.to_bits(),
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(_) => continue,
        }
    }
}

pub fn new_ulid() -> String {
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    const RANDOM_MASK: u128 = (1u128 << 80) - 1;
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
        & 0x0000_FFFF_FFFF_FFFF;
    let seq = ULID_COUNTER.fetch_add(1, Ordering::Relaxed) as u128;
    let random_prefix =
        *ULID_RANDOM_PREFIX.get_or_init(|| uuid::Uuid::new_v4().as_u128() & RANDOM_MASK);
    let value = ((millis as u128) << 80) | (random_prefix.wrapping_add(seq) & RANDOM_MASK);
    let mut encoded = [b'0'; 26];
    let mut n = value;
    for idx in (0..26).rev() {
        encoded[idx] = ALPHABET[(n & 0x1f) as usize];
        n >>= 5;
    }
    String::from_utf8_lossy(&encoded).into_owned()
}

fn resolve_node_id() -> String {
    std::env::var("FERRUM_NODE_ID")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(|value| bound_string(value.trim(), MAX_FIELD_LEN))
        .or_else(|| {
            std::env::var("HOSTNAME")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .map(|value| bound_string(value.trim(), MAX_FIELD_LEN))
        })
        .or_else(|| {
            fs::read_to_string("/etc/hostname")
                .ok()
                .map(|value| bound_string(value.trim(), MAX_FIELD_LEN))
                .filter(|value| !value.is_empty())
        })
        .unwrap_or_else(|| "unknown".to_string())
}

fn unix_timestamp_nanos() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos().min(i64::MAX as u128) as i64)
        .unwrap_or(0)
}

fn unix_timestamp_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs().min(i64::MAX as u64) as i64)
        .unwrap_or(0)
}

fn timestamp_json(timestamp: i64) -> Value {
    if timestamp <= 0 {
        Value::Null
    } else {
        match Utc.timestamp_opt(timestamp, 0).single() {
            Some(dt) => Value::String(dt.to_rfc3339_opts(SecondsFormat::Secs, true)),
            None => Value::Null,
        }
    }
}

#[cfg(test)]
mod snapshot_cleanup_race_tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;

    fn test_metadata() -> SnapshotMetadata {
        SnapshotMetadata {
            namespace: "ferrum".to_string(),
            consumer_id: "alice".to_string(),
            consumer_name: None,
            proxy_id: "proxy-a".to_string(),
            proxy_name: "Payments".to_string(),
            route_id: None,
            status_code: 200,
            http_status_code: Some(200),
            grpc_status: None,
            protocol: "http".to_string(),
        }
    }

    fn call_charge(call_count: u32, price: f64) -> ChargeComputation {
        ChargeComputation {
            call_count,
            charge_call: price,
            charge_total: price,
            ..ChargeComputation::default()
        }
    }

    #[test]
    fn cleanup_loses_race_to_same_key_refresh_after_stale_check() {
        // Deterministic issue #2576 interleaving: park cleanup after candidate
        // selection, refresh the same key, then prove conditional eviction
        // preserves and emits the refresh exactly once.
        let config = ApiChargebackSinkConfig {
            mode: SinkMode::Snapshot,
            currency: "USD".to_string(),
            pricing_version: "test-v1".to_string(),
            ..Default::default()
        };

        let accumulator = Arc::new(SnapshotAccumulator::new());
        let metadata = test_metadata();
        accumulator.record_at(metadata.clone(), call_charge(1, 0.01), 100);
        assert_eq!(
            accumulator
                .compute_deltas(&config, "node-a", 100, "snap-1")
                .expect("initial delta")
                .len(),
            1
        );

        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        accumulator.set_cleanup_after_stale_check_hook(Some(Arc::new({
            let entered = Arc::clone(&entered);
            let release = Arc::clone(&release);
            move || {
                entered.wait();
                release.wait();
            }
        })));

        let cleanup_accumulator = Arc::clone(&accumulator);
        let cleanup =
            thread::spawn(move || cleanup_accumulator.cleanup_stale(200, /* ttl */ 0));

        entered.wait();
        accumulator.record_at(metadata, call_charge(2, 0.02), 201);
        release.wait();

        assert_eq!(
            cleanup.join().expect("cleanup thread"),
            0,
            "conditional eviction must preserve a same-key refresh"
        );
        accumulator.set_cleanup_after_stale_check_hook(None);
        assert_eq!(accumulator.entries.len(), 1);
        assert_eq!(accumulator.last_emitted.len(), 1);

        let delta = accumulator
            .compute_deltas(&config, "node-a", 200, "snap-2")
            .expect("refresh delta");
        assert_eq!(delta.len(), 1);
        assert_eq!(delta[0].call_count, 2);
        assert!((delta[0].charge_total - 0.02).abs() < f64::EPSILON);
        assert!(
            accumulator
                .compute_deltas(&config, "node-a", 300, "snap-3")
                .expect("post-refresh delta")
                .is_empty(),
            "refreshed charge must emit exactly once"
        );
    }
}
