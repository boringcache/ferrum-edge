//! Kafka access logging plugin — async log shipping to Apache Kafka via
//! `BatchingLogger<SummaryLogEntry>`, with librdkafka still owning internal
//! batching, compression, and delivery retries for both HTTP and stream
//! summaries.
//!
//! Local `ThreadedProducer::send` success only means the record was admitted
//! to librdkafka's in-memory queue. Terminal broker delivery (including
//! `acks: 0` local completion) is observed through a custom
//! [`ProducerContext`] delivery callback and exposed as authenticated
//! diagnostics/metrics. Graceful shutdown and reload close Ferrum admission,
//! await the batching worker, then await one bounded producer flush.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use rdkafka::ClientContext;
use rdkafka::config::ClientConfig;
use rdkafka::error::{KafkaError, RDKafkaErrorCode};
use rdkafka::message::DeliveryResult;
use rdkafka::producer::{BaseRecord, Producer, ProducerContext, ThreadedProducer};
use serde::Serialize;
use serde_json::{Map, Value};
use tokio::task::spawn_blocking;
use tracing::warn;

use super::utils::log_schema::{
    SchemaCapabilities, SummaryLogEntryView, SummarySchema, resolve_schema,
};
use super::utils::{
    BatchConfig, BatchingLogger, LoggerHooks, PluginHttpClient, RetryPolicy, SummaryLogEntry,
};
use super::{Plugin, StreamTransactionSummary, TransactionSummary};
use crate::util::unknown_keys::reject_unknown_keys;

/// Hard ceiling for Ferrum's userspace admission channel (record count).
pub const HARD_MAX_BUFFER_CAPACITY: usize = 100_000;
/// Default Ferrum userspace channel capacity.
pub const DEFAULT_BUFFER_CAPACITY: usize = 10_000;
/// Conservative librdkafka queue message budget (replaces 100_000 default).
pub const DEFAULT_QUEUE_MAX_MESSAGES: u32 = 10_000;
pub const HARD_MAX_QUEUE_MAX_MESSAGES: u32 = 100_000;
/// Conservative librdkafka queue byte budget in KiB (replaces ~1 GiB default).
pub const DEFAULT_QUEUE_MAX_KBYTES: u32 = 65_536;
pub const HARD_MAX_QUEUE_MAX_KBYTES: u32 = 262_144;
/// Conservative per-message byte budget.
pub const DEFAULT_MESSAGE_MAX_BYTES: u32 = 1_048_576;
pub const HARD_MAX_MESSAGE_MAX_BYTES: u32 = 4_194_304;

const DELIVERY_WARN_INTERVAL: Duration = Duration::from_secs(60);
const SATURATION_WARN_INTERVAL: Duration = Duration::from_secs(60);

const ALLOWED_CONFIG_KEYS: &[&str] = &[
    "broker_list",
    "topic",
    "key_field",
    "buffer_capacity",
    "compression",
    "flush_timeout_seconds",
    "acks",
    "message_timeout_ms",
    "security_protocol",
    "sasl_mechanism",
    "sasl_username",
    "sasl_password",
    "ssl_ca_location",
    "ssl_no_verify",
    "ssl_certificate_location",
    "ssl_key_location",
    "producer_config",
    "schema",
    "schema_ref",
];

#[derive(Clone, Copy)]
enum KeyField {
    ClientIp,
    ProxyId,
    None,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct KafkaSinkFailure {
    pub operation: &'static str,
    pub error_kind: String,
    pub occurred_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct KafkaSinkSnapshot {
    pub generation_id: u64,
    pub healthy: bool,
    pub accepting: bool,
    pub finalized: bool,
    pub flush_timeout_seconds: u64,
    pub admitted_total: u64,
    pub delivered_total: u64,
    pub delivery_failed_total: u64,
    pub queue_rejected_total: u64,
    pub ferrum_dropped_total: u64,
    pub flush_failures_total: u64,
    pub flush_timeouts_total: u64,
    pub shutdown_incomplete_total: u64,
    pub in_flight: i32,
    pub last_failure: Option<KafkaSinkFailure>,
}

struct KafkaDeliveryMetrics {
    generation_id: u64,
    admitted: AtomicU64,
    delivered: AtomicU64,
    delivery_failed: AtomicU64,
    queue_rejected: AtomicU64,
    ferrum_dropped: AtomicU64,
    flush_failures: AtomicU64,
    flush_timeouts: AtomicU64,
    shutdown_incomplete: AtomicU64,
    healthy: AtomicBool,
    accepting: AtomicBool,
    last_failure: Mutex<Option<KafkaSinkFailure>>,
    last_delivery_warn: Mutex<Option<Instant>>,
    last_saturation_warn: Mutex<Option<Instant>>,
}

impl KafkaDeliveryMetrics {
    fn new(generation_id: u64) -> Self {
        Self {
            generation_id,
            admitted: AtomicU64::new(0),
            delivered: AtomicU64::new(0),
            delivery_failed: AtomicU64::new(0),
            queue_rejected: AtomicU64::new(0),
            ferrum_dropped: AtomicU64::new(0),
            flush_failures: AtomicU64::new(0),
            flush_timeouts: AtomicU64::new(0),
            shutdown_incomplete: AtomicU64::new(0),
            healthy: AtomicBool::new(true),
            accepting: AtomicBool::new(true),
            last_failure: Mutex::new(None),
            last_delivery_warn: Mutex::new(None),
            last_saturation_warn: Mutex::new(None),
        }
    }

    fn record_admitted(&self) {
        self.admitted.fetch_add(1, Ordering::Relaxed);
    }

    fn record_delivered(&self) {
        self.delivered.fetch_add(1, Ordering::Relaxed);
        self.healthy.store(true, Ordering::Relaxed);
    }

    fn record_delivery_failed(&self, error: &KafkaError) {
        self.delivery_failed.fetch_add(1, Ordering::Relaxed);
        self.healthy.store(false, Ordering::Relaxed);
        let kind = safe_kafka_error_kind(error);
        self.store_failure("delivery", kind);
        self.warn_delivery(kind);
    }

    fn record_queue_rejected(&self, error: &KafkaError) {
        self.queue_rejected.fetch_add(1, Ordering::Relaxed);
        self.healthy.store(false, Ordering::Relaxed);
        let kind = safe_kafka_error_kind(error);
        self.store_failure("queue_reject", kind);
        self.warn_saturation("producer queue rejected", kind);
    }

    fn record_ferrum_drop(&self, reason: &'static str) {
        self.ferrum_dropped.fetch_add(1, Ordering::Relaxed);
        self.warn_saturation(reason, "ferrum_channel");
    }

    fn record_flush_failure(&self, kind: &'static str, timed_out: bool, incomplete: u64) {
        self.flush_failures.fetch_add(1, Ordering::Relaxed);
        if timed_out {
            self.flush_timeouts.fetch_add(1, Ordering::Relaxed);
        }
        if incomplete > 0 {
            self.shutdown_incomplete
                .fetch_add(incomplete, Ordering::Relaxed);
        }
        self.healthy.store(false, Ordering::Relaxed);
        self.store_failure("flush", kind);
        warn!(
            plugin = "kafka_logging",
            generation_id = self.generation_id,
            error_kind = kind,
            timed_out,
            incomplete,
            "kafka_logging: producer flush did not complete cleanly"
        );
    }

    fn store_failure(&self, operation: &'static str, error_kind: &str) {
        let occurred_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        if let Ok(mut slot) = self.last_failure.lock() {
            *slot = Some(KafkaSinkFailure {
                operation,
                error_kind: error_kind.to_string(),
                occurred_at,
            });
        }
    }

    fn warn_delivery(&self, error_kind: &str) {
        let mut last = match self.last_delivery_warn.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let now = Instant::now();
        let should_warn = last
            .map(|previous| now.saturating_duration_since(previous) >= DELIVERY_WARN_INTERVAL)
            .unwrap_or(true);
        if should_warn {
            *last = Some(now);
            warn!(
                plugin = "kafka_logging",
                generation_id = self.generation_id,
                error_kind,
                failed = self.delivery_failed.load(Ordering::Relaxed),
                "kafka_logging: terminal broker delivery failure"
            );
        }
    }

    fn warn_saturation(&self, reason: &str, error_kind: &str) {
        let mut last = match self.last_saturation_warn.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let now = Instant::now();
        let should_warn = last
            .map(|previous| now.saturating_duration_since(previous) >= SATURATION_WARN_INTERVAL)
            .unwrap_or(true);
        if should_warn {
            *last = Some(now);
            warn!(
                plugin = "kafka_logging",
                generation_id = self.generation_id,
                reason,
                error_kind,
                "kafka_logging: admission saturation"
            );
        }
    }

    fn snapshot(&self, in_flight: i32, finalized: bool, flush_timeout_seconds: u64) -> KafkaSinkSnapshot {
        let last_failure = self
            .last_failure
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or(None);
        KafkaSinkSnapshot {
            generation_id: self.generation_id,
            healthy: self.healthy.load(Ordering::Relaxed),
            accepting: self.accepting.load(Ordering::Relaxed),
            finalized,
            flush_timeout_seconds,
            admitted_total: self.admitted.load(Ordering::Relaxed),
            delivered_total: self.delivered.load(Ordering::Relaxed),
            delivery_failed_total: self.delivery_failed.load(Ordering::Relaxed),
            queue_rejected_total: self.queue_rejected.load(Ordering::Relaxed),
            ferrum_dropped_total: self.ferrum_dropped.load(Ordering::Relaxed),
            flush_failures_total: self.flush_failures.load(Ordering::Relaxed),
            flush_timeouts_total: self.flush_timeouts.load(Ordering::Relaxed),
            shutdown_incomplete_total: self.shutdown_incomplete.load(Ordering::Relaxed),
            in_flight,
            last_failure,
        }
    }
}

fn safe_kafka_error_kind(error: &KafkaError) -> &'static str {
    match error {
        KafkaError::MessageProduction(code) => match code {
            RDKafkaErrorCode::MessageSizeTooLarge | RDKafkaErrorCode::InvalidMessageSize => {
                "msg_size_too_large"
            }
            RDKafkaErrorCode::TopicAuthorizationFailed => "topic_authorization_failed",
            RDKafkaErrorCode::RequestTimedOut | RDKafkaErrorCode::OperationTimedOut => "timed_out",
            RDKafkaErrorCode::QueueFull => "queue_full",
            RDKafkaErrorCode::UnknownTopic | RDKafkaErrorCode::UnknownPartition => {
                "unknown_topic_or_partition"
            }
            RDKafkaErrorCode::NotEnoughReplicas
            | RDKafkaErrorCode::NotEnoughReplicasAfterAppend => "not_enough_replicas",
            RDKafkaErrorCode::BrokerTransportFailure => "broker_transport_failure",
            RDKafkaErrorCode::AllBrokersDown => "all_brokers_down",
            RDKafkaErrorCode::MessageTimedOut => "message_timed_out",
            _ => "message_production_error",
        },
        KafkaError::Flush(code) => match code {
            RDKafkaErrorCode::OperationTimedOut => "flush_timed_out",
            _ => "flush_error",
        },
        KafkaError::Subscription(_) => "subscription_error",
        KafkaError::ClientConfig(_, _, _, _) => "client_config_error",
        KafkaError::ClientCreation(_) => "client_creation_error",
        KafkaError::Global(_) => "global_error",
        _ => "kafka_error",
    }
}

struct KafkaDeliveryContext {
    metrics: Arc<KafkaDeliveryMetrics>,
}

impl ClientContext for KafkaDeliveryContext {}

impl ProducerContext for KafkaDeliveryContext {
    type DeliveryOpaque = ();

    fn delivery(&self, delivery_result: &DeliveryResult<'_>, _opaque: Self::DeliveryOpaque) {
        match delivery_result {
            Ok(_) => self.metrics.record_delivered(),
            Err((error, _message)) => self.metrics.record_delivery_failed(error),
        }
    }
}

struct KafkaProducerState {
    producer: ThreadedProducer<KafkaDeliveryContext>,
    metrics: Arc<KafkaDeliveryMetrics>,
    flush_timeout: Duration,
    finalized: AtomicBool,
}

impl KafkaProducerState {
    fn snapshot(&self) -> KafkaSinkSnapshot {
        self.metrics.snapshot(
            self.producer.in_flight_count(),
            self.finalized.load(Ordering::Acquire),
            self.flush_timeout.as_secs(),
        )
    }

    fn flush_once(&self) -> Result<(), KafkaError> {
        if self
            .finalized
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Ok(());
        }
        self.metrics.accepting.store(false, Ordering::Relaxed);
        let pending_before = self.producer.in_flight_count().max(0) as u64;
        let admitted = self.metrics.admitted.load(Ordering::Relaxed);
        if pending_before == 0 && admitted == 0 {
            return Ok(());
        }
        match self.producer.flush(self.flush_timeout) {
            Ok(()) => Ok(()),
            Err(error) => {
                let remaining = self.producer.in_flight_count().max(0) as u64;
                let timed_out =
                    matches!(error, KafkaError::Flush(RDKafkaErrorCode::OperationTimedOut));
                let incomplete = if remaining > 0 {
                    remaining
                } else {
                    pending_before
                };
                self.metrics.record_flush_failure(
                    safe_kafka_error_kind(&error),
                    timed_out,
                    incomplete,
                );
                Err(error)
            }
        }
    }
}

struct KafkaGeneration {
    state: Arc<KafkaProducerState>,
    logger: Mutex<Option<BatchingLogger<SummaryLogEntry>>>,
}

impl KafkaGeneration {
    async fn finalize(&self) {
        let logger = {
            let mut guard = self
                .logger
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            guard.take()
        };
        if let Some(mut owned) = logger {
            owned.close_and_await().await;
        }
        let state = Arc::clone(&self.state);
        let _ = spawn_blocking(move || state.flush_once()).await;
    }
}

static NEXT_GENERATION_ID: AtomicU64 = AtomicU64::new(1);
static ACTIVE_GENERATIONS: OnceLock<Mutex<BTreeMap<u64, Arc<KafkaGeneration>>>> = OnceLock::new();

fn active_generations() -> &'static Mutex<BTreeMap<u64, Arc<KafkaGeneration>>> {
    ACTIVE_GENERATIONS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn register_generation(generation: Arc<KafkaGeneration>) {
    let id = generation.state.metrics.generation_id;
    if let Ok(mut guard) = active_generations().lock() {
        guard.insert(id, generation);
    }
}

fn unregister_generation(id: u64) {
    if let Ok(mut guard) = active_generations().lock() {
        guard.remove(&id);
    }
}

/// Close admission, await Ferrum workers, and flush every live Kafka producer
/// generation within each instance's configured `flush_timeout_seconds`.
/// Exact-once: generations already finalized are skipped.
pub async fn finalize_all_generations() {
    let generations: Vec<Arc<KafkaGeneration>> = active_generations()
        .lock()
        .map(|guard| guard.values().cloned().collect())
        .unwrap_or_default();
    for generation in generations {
        generation.finalize().await;
        unregister_generation(generation.state.metrics.generation_id);
    }
}

/// Authenticated diagnostics snapshots for every registered generation.
pub fn snapshots() -> Vec<KafkaSinkSnapshot> {
    active_generations()
        .lock()
        .map(|guard| guard.values().map(|g| g.state.snapshot()).collect())
        .unwrap_or_default()
}

/// Prometheus exposition for Kafka logging sinks (fixed labels only).
pub fn render_prometheus() -> String {
    let snaps = snapshots();
    if snaps.is_empty() {
        return String::new();
    }
    let mut output = String::with_capacity(2_048);
    output.push_str(
        "# HELP ferrum_kafka_logging_healthy Whether the Kafka logging generation recovered from its latest failure.\n\
# TYPE ferrum_kafka_logging_healthy gauge\n",
    );
    output.push_str(
        "# HELP ferrum_kafka_logging_accepting Whether the Kafka logging generation still admits new records.\n\
# TYPE ferrum_kafka_logging_accepting gauge\n",
    );
    output.push_str(
        "# HELP ferrum_kafka_logging_in_flight Records waiting in librdkafka for terminal delivery.\n\
# TYPE ferrum_kafka_logging_in_flight gauge\n",
    );
    output.push_str(
        "# HELP ferrum_kafka_logging_records_total Kafka logging record outcomes.\n\
# TYPE ferrum_kafka_logging_records_total counter\n",
    );
    for snap in snaps {
        let id = snap.generation_id;
        output.push_str(&format!(
            "ferrum_kafka_logging_healthy{{generation=\"{id}\"}} {}\n",
            u8::from(snap.healthy)
        ));
        output.push_str(&format!(
            "ferrum_kafka_logging_accepting{{generation=\"{id}\"}} {}\n",
            u8::from(snap.accepting)
        ));
        output.push_str(&format!(
            "ferrum_kafka_logging_in_flight{{generation=\"{id}\"}} {}\n",
            snap.in_flight.max(0)
        ));
        for (outcome, value) in [
            ("admitted", snap.admitted_total),
            ("delivered", snap.delivered_total),
            ("delivery_failed", snap.delivery_failed_total),
            ("queue_rejected", snap.queue_rejected_total),
            ("ferrum_dropped", snap.ferrum_dropped_total),
            ("flush_failures", snap.flush_failures_total),
            ("flush_timeouts", snap.flush_timeouts_total),
            ("shutdown_incomplete", snap.shutdown_incomplete_total),
        ] {
            output.push_str(&format!(
                "ferrum_kafka_logging_records_total{{generation=\"{id}\",outcome=\"{outcome}\"}} {value}\n"
            ));
        }
    }
    output
}

pub struct KafkaLogging {
    generation: Arc<KafkaGeneration>,
    broker_hostnames: Vec<String>,
}

impl KafkaLogging {
    pub fn new(config: &Value, http_client: &PluginHttpClient) -> Result<Self, String> {
        let object = config
            .as_object()
            .ok_or_else(|| "kafka_logging: config must be an object".to_string())?;
        reject_unknown_keys(object, "config", ALLOWED_CONFIG_KEYS, "kafka_logging: ")?;

        let broker_list = required_non_empty_string(config, "broker_list").ok_or_else(|| {
            near_miss_hint(
                object,
                "broker_list",
                "kafka_logging: 'broker_list' is required (comma-separated broker addresses)",
            )
        })?;
        let brokers = broker_list
            .split(',')
            .map(str::trim)
            .filter(|broker| !broker.is_empty())
            .collect::<Vec<_>>();
        if brokers.is_empty() {
            return Err(
                "kafka_logging: 'broker_list' must contain at least one broker address".to_string(),
            );
        }
        let broker_list = brokers.join(",");

        let topic = required_non_empty_string(config, "topic").ok_or_else(|| {
            if config.get("topic").is_some() {
                "kafka_logging: 'topic' must not be empty".to_string()
            } else {
                near_miss_hint(object, "topic", "kafka_logging: 'topic' is required")
            }
        })?;

        let buffer_capacity = optional_u64(config, "buffer_capacity")?
            .unwrap_or(DEFAULT_BUFFER_CAPACITY as u64)
            .max(1);
        if buffer_capacity > HARD_MAX_BUFFER_CAPACITY as u64 {
            return Err(format!(
                "kafka_logging: 'buffer_capacity' must be <= {HARD_MAX_BUFFER_CAPACITY}"
            ));
        }
        let buffer_capacity = buffer_capacity as usize;

        let flush_timeout_seconds = optional_u64(config, "flush_timeout_seconds")?
            .unwrap_or(5)
            .max(1);

        let key_field = match optional_non_empty_string(config, "key_field")?.as_deref() {
            None => KeyField::ClientIp,
            Some("client_ip") => KeyField::ClientIp,
            Some("proxy_id") => KeyField::ProxyId,
            Some("none") => KeyField::None,
            Some(other) => {
                return Err(format!(
                    "kafka_logging: unsupported key_field '{other}' \
                     (use client_ip/proxy_id/none)"
                ));
            }
        };

        let mut kafka_config = ClientConfig::new();
        kafka_config.set("bootstrap.servers", &broker_list);
        // Keep client logs out of Ferrum's process sinks by default.
        kafka_config.set("log.connection.close", "false");

        if let Some(value) = optional_u64(config, "message_timeout_ms")? {
            kafka_config.set("message.timeout.ms", value.to_string());
        }

        let compression =
            optional_non_empty_string(config, "compression")?.unwrap_or_else(|| "lz4".to_string());
        match compression.as_str() {
            value @ ("none" | "gzip" | "snappy" | "lz4" | "zstd") => {
                kafka_config.set("compression.type", value);
            }
            other => {
                return Err(format!(
                    "kafka_logging: unsupported compression '{other}' \
                     (use none/gzip/snappy/lz4/zstd)"
                ));
            }
        }

        if let Some(acks) = optional_non_empty_string(config, "acks")? {
            match acks.as_str() {
                value @ ("0" | "1" | "all" | "-1") => {
                    kafka_config.set("acks", value);
                }
                other => {
                    return Err(format!(
                        "kafka_logging: unsupported acks '{other}' (use 0/1/all)"
                    ));
                }
            }
        }

        if let Some(protocol) = optional_non_empty_string(config, "security_protocol")? {
            match protocol.to_ascii_lowercase().as_str() {
                value @ ("plaintext" | "ssl" | "sasl_plaintext" | "sasl_ssl") => {
                    kafka_config.set("security.protocol", value);
                }
                other => {
                    return Err(format!(
                        "kafka_logging: unsupported security_protocol '{other}' \
                         (use plaintext/ssl/sasl_plaintext/sasl_ssl)"
                    ));
                }
            }
        }
        if let Some(mechanism) = optional_non_empty_string(config, "sasl_mechanism")? {
            kafka_config.set("sasl.mechanism", mechanism);
        }
        if let Some(username) = optional_non_empty_string(config, "sasl_username")? {
            kafka_config.set("sasl.username", username);
        }
        if let Some(password) = optional_non_empty_string(config, "sasl_password")? {
            kafka_config.set("sasl.password", password);
        }

        if let Some(ca) = optional_non_empty_string(config, "ssl_ca_location")? {
            kafka_config.set("ssl.ca.location", ca);
        } else if let Some(gateway_ca) = http_client.tls_ca_bundle_path() {
            kafka_config.set("ssl.ca.location", gateway_ca);
        }

        let ssl_no_verify =
            optional_bool(config, "ssl_no_verify")?.unwrap_or(http_client.tls_no_verify());
        if ssl_no_verify {
            kafka_config.set("enable.ssl.certificate.verification", "false");
        }

        let ssl_certificate_location =
            optional_non_empty_string(config, "ssl_certificate_location")?;
        let ssl_key_location = optional_non_empty_string(config, "ssl_key_location")?;
        if ssl_certificate_location.is_some() != ssl_key_location.is_some() {
            return Err(
                "kafka_logging: 'ssl_certificate_location' and 'ssl_key_location' must be provided together"
                    .to_string(),
            );
        }
        if let Some(cert) = ssl_certificate_location {
            kafka_config.set("ssl.certificate.location", cert);
        }
        if let Some(key) = ssl_key_location {
            kafka_config.set("ssl.key.location", key);
        }

        let gateway_crl_path = resolve_gateway_crl_path(http_client)?;
        let mut producer_queue_messages = DEFAULT_QUEUE_MAX_MESSAGES;
        let mut producer_queue_kbytes = DEFAULT_QUEUE_MAX_KBYTES;
        let mut producer_message_max_bytes = DEFAULT_MESSAGE_MAX_BYTES;
        let mut producer_set_crl: Option<String> = None;

        if let Some(producer_config) = config.get("producer_config") {
            let props = producer_config
                .as_object()
                .ok_or_else(|| "kafka_logging: 'producer_config' must be an object".to_string())?;
            for (key, value) in props {
                if key.trim().is_empty() {
                    return Err(
                        "kafka_logging: 'producer_config' keys must not be empty".to_string()
                    );
                }
                let prop = value.as_str().ok_or_else(|| {
                    format!("kafka_logging: 'producer_config.{key}' must be a string")
                })?;
                if prop.trim().is_empty() {
                    return Err(format!(
                        "kafka_logging: 'producer_config.{key}' must not be empty"
                    ));
                }
                if key.eq_ignore_ascii_case("bootstrap.servers")
                    || key.eq_ignore_ascii_case("metadata.broker.list")
                {
                    return Err(format!(
                        "kafka_logging: 'producer_config.{key}' is not allowed"
                    ));
                }
                if key.eq_ignore_ascii_case("ssl.crl.location") {
                    if !ssl_no_verify {
                        if let Some(ref gateway) = gateway_crl_path {
                            if prop != gateway.as_str() {
                                return Err(
                                    "kafka_logging: 'producer_config.ssl.crl.location' conflicts with gateway FERRUM_TLS_CRL_FILE_PATH"
                                        .to_string(),
                                );
                            }
                        }
                    }
                    producer_set_crl = Some(prop.to_string());
                    continue;
                }
                if key.eq_ignore_ascii_case("queue.buffering.max.messages") {
                    producer_queue_messages = parse_bounded_u32(
                        prop,
                        "producer_config.queue.buffering.max.messages",
                        HARD_MAX_QUEUE_MAX_MESSAGES,
                    )?;
                    continue;
                }
                if key.eq_ignore_ascii_case("queue.buffering.max.kbytes") {
                    producer_queue_kbytes = parse_bounded_u32(
                        prop,
                        "producer_config.queue.buffering.max.kbytes",
                        HARD_MAX_QUEUE_MAX_KBYTES,
                    )?;
                    continue;
                }
                if key.eq_ignore_ascii_case("message.max.bytes") {
                    producer_message_max_bytes = parse_bounded_u32(
                        prop,
                        "producer_config.message.max.bytes",
                        HARD_MAX_MESSAGE_MAX_BYTES,
                    )?;
                    continue;
                }
                kafka_config.set(key, prop);
            }
        }

        kafka_config.set(
            "queue.buffering.max.messages",
            producer_queue_messages.to_string(),
        );
        kafka_config.set(
            "queue.buffering.max.kbytes",
            producer_queue_kbytes.to_string(),
        );
        kafka_config.set("message.max.bytes", producer_message_max_bytes.to_string());

        if !ssl_no_verify {
            if let Some(gateway) = gateway_crl_path.as_ref() {
                kafka_config.set("ssl.crl.location", gateway);
            } else if let Some(override_path) = producer_set_crl {
                kafka_config.set("ssl.crl.location", override_path);
            }
        }

        let generation_id = NEXT_GENERATION_ID.fetch_add(1, Ordering::Relaxed);
        let metrics = Arc::new(KafkaDeliveryMetrics::new(generation_id));
        let context = KafkaDeliveryContext {
            metrics: Arc::clone(&metrics),
        };
        let producer: ThreadedProducer<KafkaDeliveryContext> = kafka_config
            .create_with_context(context)
            .map_err(|error| format!("kafka_logging: failed to create Kafka producer: {error}"))?;

        let broker_hostnames: Vec<String> = broker_list
            .split(',')
            .filter_map(|broker| {
                let trimmed = broker.trim();
                let host = if trimmed.starts_with('[') {
                    trimmed
                        .split(']')
                        .next()
                        .map(|value| value.trim_start_matches('['))
                } else {
                    trimmed.split(':').next()
                };
                host.filter(|value| !value.is_empty() && value.parse::<std::net::IpAddr>().is_err())
                    .map(|value| value.to_string())
            })
            .collect();

        let state = Arc::new(KafkaProducerState {
            producer,
            metrics: Arc::clone(&metrics),
            flush_timeout: Duration::from_secs(flush_timeout_seconds),
            finalized: AtomicBool::new(false),
        });
        let schema = resolve_schema(config, "kafka_logging", SchemaCapabilities::BASE)?;
        let metrics_for_hooks = Arc::clone(&metrics);
        let hooks = LoggerHooks {
            on_failed_batch: None,
            on_overflow: Some(Arc::new(move |_item, reason| {
                metrics_for_hooks.record_ferrum_drop(reason);
            })),
            on_high_water: None,
            high_watermark_percent: 80,
        };
        let logger = BatchingLogger::spawn_with_hooks(
            BatchConfig {
                // Kafka flushes one userspace message at a time here. Larger
                // batches would still serialize one spawn_blocking send per
                // entry while librdkafka owns the real batching underneath.
                batch_size: 1,
                flush_interval: Duration::from_millis(1000),
                buffer_capacity,
                // librdkafka handles its own delivery retries; keep the
                // shared logger at a single attempt for each message.
                retry: RetryPolicy::fixed(1, Duration::from_millis(0)),
                plugin_name: "kafka_logging",
            },
            hooks,
            {
                let state = Arc::clone(&state);
                move |batch| {
                    let state = Arc::clone(&state);
                    let topic = topic.clone();
                    let schema = schema.clone();
                    async move { send_batch(&state, &topic, key_field, batch, schema.as_deref()).await }
                }
            },
        );

        let generation = Arc::new(KafkaGeneration {
            state,
            logger: Mutex::new(Some(logger)),
        });
        register_generation(Arc::clone(&generation));

        Ok(Self {
            generation,
            broker_hostnames,
        })
    }

    pub fn snapshot(&self) -> KafkaSinkSnapshot {
        self.generation.state.snapshot()
    }

    pub async fn finalize(&self) {
        self.generation.finalize().await;
        unregister_generation(self.generation.state.metrics.generation_id);
    }
}

impl Drop for KafkaLogging {
    fn drop(&mut self) {
        if self.generation.state.finalized.load(Ordering::Acquire) {
            unregister_generation(self.generation.state.metrics.generation_id);
            return;
        }
        // Reload disposal / abandoned instance: close admission and run one
        // bounded flush so pending records are not silently detached from
        // process lifetime. Multi-thread runtimes can await the worker;
        // current-thread test runtimes close admission and flush without
        // `block_in_place` (which would panic there).
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread {
                let generation = Arc::clone(&self.generation);
                tokio::task::block_in_place(|| {
                    handle.block_on(async move {
                        generation.finalize().await;
                        unregister_generation(generation.state.metrics.generation_id);
                    });
                });
                return;
            }
        }
        let _ = self
            .generation
            .logger
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        let state = Arc::clone(&self.generation.state);
        let _ = state.flush_once();
        unregister_generation(state.metrics.generation_id);
    }
}

fn resolve_gateway_crl_path(http_client: &PluginHttpClient) -> Result<Option<String>, String> {
    if let Some(path) = http_client.tls_crl_file_path() {
        return Ok(Some(path.to_string()));
    }
    let from_env = std::env::var("FERRUM_TLS_CRL_FILE_PATH")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    if !http_client.tls_crls().is_empty() && from_env.is_none() {
        return Err(
            "kafka_logging: gateway CRL is loaded but no filesystem path is available for librdkafka ssl.crl.location"
                .to_string(),
        );
    }
    Ok(from_env)
}

fn near_miss_hint(object: &Map<String, Value>, required: &str, fallback: &str) -> String {
    match crate::util::unknown_keys::near_miss_for_missing_key(object, required) {
        Some(near) => format!("{fallback} (did you mean '{near}'?)"),
        None => fallback.to_string(),
    }
}

fn parse_bounded_u32(raw: &str, field: &str, hard_max: u32) -> Result<u32, String> {
    let value: u32 = raw.parse().map_err(|_| {
        format!("kafka_logging: '{field}' must be an unsigned integer string")
    })?;
    if value == 0 {
        return Err(format!("kafka_logging: '{field}' must be >= 1"));
    }
    if value > hard_max {
        return Err(format!("kafka_logging: '{field}' must be <= {hard_max}"));
    }
    Ok(value)
}

fn required_non_empty_string(config: &Value, key: &str) -> Option<String> {
    config.get(key)?.as_str().and_then(|value| {
        let value = value.trim();
        (!value.is_empty()).then(|| value.to_string())
    })
}

fn optional_non_empty_string(config: &Value, key: &str) -> Result<Option<String>, String> {
    match config.get(key) {
        Some(value) => {
            let value = value
                .as_str()
                .ok_or_else(|| format!("kafka_logging: '{key}' must be a string"))?
                .trim();
            if value.is_empty() {
                return Err(format!("kafka_logging: '{key}' must not be empty"));
            }
            Ok(Some(value.to_string()))
        }
        None => Ok(None),
    }
}

fn optional_bool(config: &Value, key: &str) -> Result<Option<bool>, String> {
    match config.get(key) {
        Some(value) => value
            .as_bool()
            .map(Some)
            .ok_or_else(|| format!("kafka_logging: '{key}' must be a boolean")),
        None => Ok(None),
    }
}

fn optional_u64(config: &Value, key: &str) -> Result<Option<u64>, String> {
    match config.get(key) {
        Some(value) => value
            .as_u64()
            .map(Some)
            .ok_or_else(|| format!("kafka_logging: '{key}' must be an unsigned integer")),
        None => Ok(None),
    }
}

#[async_trait]
impl Plugin for KafkaLogging {
    fn name(&self) -> &str {
        "kafka_logging"
    }

    fn priority(&self) -> u16 {
        super::priority::KAFKA_LOGGING
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::ALL_PROTOCOLS
    }

    async fn on_stream_disconnect(&self, summary: &StreamTransactionSummary) {
        let logger = self
            .generation
            .logger
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(logger) = logger.as_ref() {
            let _ = logger.try_send(summary.into());
        }
    }

    async fn log(&self, summary: &TransactionSummary) {
        let logger = self
            .generation
            .logger
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(logger) = logger.as_ref() {
            let _ = logger.try_send(summary.into());
        }
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        self.broker_hostnames.clone()
    }
}

async fn send_batch(
    state: &Arc<KafkaProducerState>,
    topic: &str,
    key_field: KeyField,
    batch: Vec<SummaryLogEntry>,
    schema: Option<&SummarySchema>,
) -> Result<(), String> {
    for entry in batch {
        // Serialize only after Ferrum-side admission succeeded; the worker
        // already owns the SummaryLogEntry.
        let serialized = match schema {
            Some(schema) => serde_json::to_string(&SummaryLogEntryView {
                entry: &entry,
                schema,
            }),
            None => serde_json::to_string(&entry),
        };
        let payload = match serialized {
            Ok(json) => json,
            Err(error) => {
                warn!("kafka_logging: failed to serialize log entry: {error}");
                continue;
            }
        };
        let key = match key_field {
            KeyField::None => None,
            KeyField::ClientIp => Some(entry.client_ip().to_string()),
            KeyField::ProxyId => entry.proxy_id().map(str::to_string),
        };
        let state = Arc::clone(state);
        let topic = topic.to_string();

        spawn_blocking(move || {
            let enqueue_error = match key {
                Some(key) => state
                    .producer
                    .send(
                        BaseRecord::<str, str>::to(&topic)
                            .payload(&payload)
                            .key(key.as_str()),
                    )
                    .err()
                    .map(|(error, _)| error),
                None => state
                    .producer
                    .send(BaseRecord::<(), str>::to(&topic).payload(&payload))
                    .err()
                    .map(|(error, _)| error),
            };

            match enqueue_error {
                Some(error) => {
                    state.metrics.record_queue_rejected(&error);
                    Err(format!("kafka_logging: failed to enqueue message: {error}"))
                }
                None => {
                    state.metrics.record_admitted();
                    Ok(())
                }
            }
        })
        .await
        .map_err(|error| format!("kafka_logging: producer task join failed: {error}"))??;
    }

    Ok(())
}
