//! UDP/DTLS access logging plugin — batched async log shipping over UDP.
//!
//! Serializes `TransactionSummary` and `StreamTransactionSummary` entries and
//! sends them to a remote UDP endpoint in batches. Uses
//! `BatchingLogger<LogEntry>` to decouple the proxy hot path from network I/O.
//!
//! Supports both plain UDP and DTLS-encrypted transport. When `dtls` is
//! enabled, certificate/key/CA sources are materialized at admission (and
//! through the mode-aware plugin file-dependency phase) and cached in the
//! committed plugin generation so first flush and reconnect do not rediscover
//! static source errors. The gateway's CRL list (`FERRUM_TLS_CRL_FILE_PATH`) is
//! applied to the DTLS server verifier with
//! `allow_unknown_revocation_status() + only_check_end_entity_revocation()`,
//! matching the proxy backend / DTLS / frontend mTLS surfaces.
//!
//! Each batch is serialized as a JSON array and sent as a single UDP datagram.
//! DTLS success means local engine + connected-socket acceptance, not remote
//! UDP delivery. Payloads larger than `FERRUM_DTLS_MAX_PLAINTEXT_BYTES`
//! (default 16,384) fail closed into the batching retry / final-loss path;
//! multi-entry batches that exceed the ceiling are split so one oversized
//! record cannot silently discard its co-batched neighbors.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use rustls::pki_types::CertificateRevocationListDer;
use serde_json::{Map, Value};
use tokio::net::UdpSocket;
use tokio::time::Instant;
use tracing::warn;

use super::utils::log_schema::{
    SchemaCapabilities, SummaryLogEntryBatchView, SummarySchema, resolve_schema,
};
use super::utils::{
    BatchConfigDefaults, BatchingLogger, PluginHttpClient, SummaryLogEntry,
    UDP_RE_RESOLVE_INTERVAL, bind_connected_udp_socket, build_batch_config, parse_socket_host,
    resolve_udp_endpoint, validate_batch_config,
};
use super::{Plugin, StreamTransactionSummary, TransactionSummary};
use crate::dns::DnsCache;
use crate::util::unknown_keys::reject_unknown_keys;

/// Accepted top-level `udp_logging` configuration keys.
///
/// Unknown keys (including near-miss transport typos such as `dtsl`) are
/// rejected at construction / Admin validation so encryption cannot silently
/// default to plaintext.
pub const UDP_LOGGING_CONFIG_KEYS: &[&str] = &[
    "batch_size",
    "buffer_capacity",
    "dtls",
    "dtls_ca_cert_path",
    "dtls_cert_path",
    "dtls_key_path",
    "dtls_no_verify",
    "flush_interval_ms",
    "host",
    "max_retries",
    "port",
    "retry_delay_ms",
    "schema",
    "schema_ref",
];

const LOCAL_RECORD_DROP_WARN_EVERY: u64 = 100;
static LOCAL_RECORD_DROPS: AtomicU64 = AtomicU64::new(0);

/// Pre-materialized DTLS client identity and verifier for one plugin generation.
#[derive(Clone)]
pub(crate) struct CachedDtlsMaterial {
    certificate: dimpl::DtlsCertificate,
    server_name: Option<rustls::pki_types::ServerName<'static>>,
    server_cert_verifier: Option<Arc<dyn rustls::client::danger::ServerCertVerifier>>,
}

#[derive(Clone)]
struct UdpFlushConfig {
    host: String,
    port: u16,
    dtls_enabled: bool,
    dtls_material: Option<Arc<CachedDtlsMaterial>>,
    dns_cache: Option<DnsCache>,
    schema: Option<Arc<SummarySchema>>,
    /// Test-only resolve override. Production construction leaves the slot
    /// empty; deterministic DNS-lifecycle tests may publish an address that
    /// the next resolve consumes exactly once.
    next_resolve_addr: Arc<Mutex<Option<SocketAddr>>>,
}

struct UdpFlushState {
    sender: Option<UdpSender>,
    current_addr: Option<SocketAddr>,
    last_resolve: Instant,
}

pub struct UdpLogging {
    logger: BatchingLogger<SummaryLogEntry>,
    endpoint_hostname: Option<String>,
    /// Shared with the flush worker; retained here so external unit tests can
    /// inspect/age DNS state. Binary target sees no readers.
    #[allow(dead_code)] // used only by tests/, dead code in the bin target
    flush_state: Arc<Mutex<UdpFlushState>>,
    /// One-shot resolve override shared with the flush worker; written by
    /// external unit tests. Binary target sees no readers on this field.
    #[allow(dead_code)] // used only by tests/, dead code in the bin target
    next_resolve_addr: Arc<Mutex<Option<SocketAddr>>>,
}

impl UdpLogging {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        let ParsedUdpLogging {
            host,
            port,
            socket_host_warmup,
            dtls_enabled,
            dtls_material,
            batch_defaults,
            schema,
        } = parse_udp_logging_config(config, &http_client)?;

        let next_resolve_addr = Arc::new(Mutex::new(None));
        let flush_config = UdpFlushConfig {
            host: host.clone(),
            port,
            dtls_enabled,
            dtls_material,
            dns_cache: http_client.dns_cache().cloned(),
            schema,
            next_resolve_addr: Arc::clone(&next_resolve_addr),
        };
        let state = Arc::new(Mutex::new(UdpFlushState {
            sender: None,
            current_addr: None,
            last_resolve: Instant::now(),
        }));
        let flush_state = Arc::clone(&state);
        let logger = BatchingLogger::spawn(
            // Config remains `max_retries`; the shared retry policy counts the
            // initial attempt plus those retries.
            build_batch_config(config, "udp_logging", batch_defaults),
            move |batch| {
                let flush_config = flush_config.clone();
                let state = Arc::clone(&state);
                async move { send_batch(&flush_config, &state, batch).await }
            },
        );

        Ok(Self {
            logger,
            endpoint_hostname: socket_host_warmup,
            flush_state,
            next_resolve_addr,
        })
    }

    /// Shape + DTLS material admission without spawning the batching worker.
    ///
    /// Used by shared plugin validation / Admin surfaces. Runtime construction
    /// still goes through [`Self::new`], which reuses the same parser and then
    /// starts the flush worker. Registration remains `OptionalFailOpen`: a
    /// failed enabled instance is omitted from the published cache rather than
    /// retaining last-known-good.
    pub(crate) fn validate_config(
        config: &Value,
        http_client: PluginHttpClient,
    ) -> Result<(), String> {
        parse_udp_logging_config(config, &http_client).map(|_| ())
    }
}

struct ParsedUdpLogging {
    host: String,
    port: u16,
    socket_host_warmup: Option<String>,
    dtls_enabled: bool,
    dtls_material: Option<Arc<CachedDtlsMaterial>>,
    batch_defaults: BatchConfigDefaults,
    schema: Option<Arc<SummarySchema>>,
}

fn parse_udp_logging_config(
    config: &Value,
    http_client: &PluginHttpClient,
) -> Result<ParsedUdpLogging, String> {
    let object = config
        .as_object()
        .ok_or_else(|| "udp_logging: config must be an object".to_string())?;
    reject_unknown_keys(object, "config", UDP_LOGGING_CONFIG_KEYS, "udp_logging: ")?;

    let raw_host = config
        .get("host")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "udp_logging: 'host' is required".to_string())?
        .to_string();
    let socket_host = parse_socket_host("udp_logging", "host", &raw_host)?;
    socket_host.screen_egress_ip("udp_logging", "host", http_client.backend_allow_ips())?;
    let host = socket_host.dial_host.clone();
    let port = config.get("port").and_then(Value::as_u64).ok_or_else(|| {
        "udp_logging: 'port' is required and must be a positive integer".to_string()
    })?;
    if port == 0 || port > 65535 {
        return Err(format!(
            "udp_logging: 'port' must be between 1 and 65535 (got {port})"
        ));
    }

    let dtls_enabled = optional_bool(config, "dtls")?.unwrap_or(false);
    let dtls_cert_path = optional_non_empty_string(config, "dtls_cert_path")?;
    let dtls_key_path = optional_non_empty_string(config, "dtls_key_path")?;
    let dtls_ca_cert_path = optional_non_empty_string(config, "dtls_ca_cert_path")?;
    let dtls_no_verify = optional_bool(config, "dtls_no_verify")?.unwrap_or(false);

    if dtls_cert_path.is_some() != dtls_key_path.is_some() {
        return Err(
            "udp_logging: 'dtls_cert_path' and 'dtls_key_path' must be provided together"
                .to_string(),
        );
    }

    let batch_defaults = BatchConfigDefaults {
        batch_size_key: "batch_size",
        batch_size: 10,
        flush_interval_ms: 1000,
        min_flush_interval_ms: 100,
        buffer_capacity: 10000,
        max_retries: 1,
        retry_delay_ms: 500,
    };
    validate_batch_config(config, "udp_logging", batch_defaults)?;
    let schema = resolve_schema(config, "udp_logging", SchemaCapabilities::BASE)?;

    let dtls_material = if dtls_enabled {
        Some(Arc::new(materialize_dtls_material(
            &host,
            dtls_cert_path.as_deref(),
            dtls_key_path.as_deref(),
            dtls_ca_cert_path.as_deref(),
            dtls_no_verify,
            http_client.tls_crls(),
        )?))
    } else {
        None
    };

    Ok(ParsedUdpLogging {
        host,
        port: port as u16,
        socket_host_warmup: socket_host.warmup_hostname,
        dtls_enabled,
        dtls_material,
        batch_defaults,
        schema,
    })
}

/// Materialize DTLS certificate/key/CA sources without network I/O.
///
/// Shared by constructor admission and the mode-aware plugin file-dependency
/// phase so both surfaces enforce the same usable-material contract.
pub(crate) fn materialize_dtls_material(
    host: &str,
    cert_path: Option<&str>,
    key_path: Option<&str>,
    ca_path: Option<&str>,
    no_verify: bool,
    crls: &[CertificateRevocationListDer<'static>],
) -> Result<CachedDtlsMaterial, String> {
    let certificate = if let (Some(cert_path), Some(key_path)) = (cert_path, key_path) {
        crate::dtls::load_dtls_certificate(cert_path, key_path).map_err(|error| {
            format!("udp_logging: DTLS cert/key materialization failed: {error}")
        })?
    } else {
        crate::dtls::generate_ephemeral_cert_public()
            .map_err(|error| format!("udp_logging: DTLS ephemeral cert failed: {error}"))?
    };

    // A configured CA source is still materialized under `no_verify`: although
    // verification is intentionally disabled, a missing or malformed declared
    // source must not pass admission and become a latent rollout defect.
    let configured_root_store = match ca_path {
        Some(ca_path) => Some(
            crate::dtls::load_root_store_from_pem(ca_path).map_err(|error| {
                format!("udp_logging: DTLS CA materialization failed: {error}")
            })?,
        ),
        None => None,
    };

    let (server_name, server_cert_verifier) = if no_verify {
        (None, None)
    } else {
        let root_store = if let Some(root_store) = configured_root_store {
            root_store
        } else {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            roots
        };
        let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
            .map_err(|_| format!("udp_logging: invalid DTLS server name: {host}"))?;
        let verifier = crate::tls::build_server_verifier_with_crls(root_store, crls)
            .map_err(|error| format!("udp_logging: DTLS verifier build failed: {error}"))?;
        (
            Some(server_name),
            Some(verifier as Arc<dyn rustls::client::danger::ServerCertVerifier>),
        )
    };

    Ok(CachedDtlsMaterial {
        certificate,
        server_name,
        server_cert_verifier,
    })
}

/// Validate enabled `udp_logging` DTLS file/provider sources for the shared
/// plugin file-dependency phase (file-mode fatal, DB warning, DP skip).
pub(crate) fn validate_dtls_file_dependencies(config: &Map<String, Value>) -> Result<(), String> {
    let dtls_enabled = match config.get("dtls") {
        Some(Value::Bool(enabled)) => *enabled,
        Some(_) => return Err("udp_logging: 'dtls' must be a boolean".to_string()),
        None => false,
    };
    if !dtls_enabled {
        return Ok(());
    }

    let cert_path = optional_non_empty_string_from_map(config, "dtls_cert_path")?;
    let key_path = optional_non_empty_string_from_map(config, "dtls_key_path")?;
    let ca_path = optional_non_empty_string_from_map(config, "dtls_ca_cert_path")?;
    let no_verify = match config.get("dtls_no_verify") {
        Some(Value::Bool(value)) => *value,
        Some(_) => return Err("udp_logging: 'dtls_no_verify' must be a boolean".to_string()),
        None => false,
    };

    if cert_path.is_some() != key_path.is_some() {
        return Err(
            "udp_logging: 'dtls_cert_path' and 'dtls_key_path' must be provided together"
                .to_string(),
        );
    }

    // Host is only needed for ServerName when verifying; fall back to a
    // syntactically valid placeholder when the shape phase has not yet run.
    let host = config
        .get("host")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("udp-logging.invalid");

    materialize_dtls_material(
        host,
        cert_path.as_deref(),
        key_path.as_deref(),
        ca_path.as_deref(),
        no_verify,
        &[],
    )
    .map(|_| ())
}

fn optional_non_empty_string_from_map(
    config: &Map<String, Value>,
    key: &str,
) -> Result<Option<String>, String> {
    match config.get(key) {
        Some(value) => {
            let value = value
                .as_str()
                .ok_or_else(|| format!("udp_logging: '{key}' must be a string"))?
                .trim();
            if value.is_empty() {
                return Err(format!("udp_logging: '{key}' must not be empty"));
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
            .ok_or_else(|| format!("udp_logging: '{key}' must be a boolean")),
        None => Ok(None),
    }
}

fn optional_non_empty_string(config: &Value, key: &str) -> Result<Option<String>, String> {
    match config.get(key) {
        Some(value) => {
            let value = value
                .as_str()
                .ok_or_else(|| format!("udp_logging: '{key}' must be a string"))?
                .trim();
            if value.is_empty() {
                return Err(format!("udp_logging: '{key}' must not be empty"));
            }
            Ok(Some(value.to_string()))
        }
        None => Ok(None),
    }
}

/// Pure DNS/lifecycle predicate shared with deterministic tests.
pub(crate) fn should_replace_sender_on_resolve(
    elapsed: Duration,
    current_addr: Option<SocketAddr>,
    new_addr: SocketAddr,
    interval: Duration,
) -> bool {
    elapsed >= interval && current_addr != Some(new_addr)
}

#[async_trait]
impl Plugin for UdpLogging {
    fn name(&self) -> &str {
        "udp_logging"
    }

    fn priority(&self) -> u16 {
        super::priority::UDP_LOGGING
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::ALL_PROTOCOLS
    }

    async fn on_stream_disconnect(&self, summary: &StreamTransactionSummary) {
        self.logger.try_send(summary.into());
    }

    async fn log(&self, summary: &TransactionSummary) {
        self.logger.try_send(summary.into());
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        self.endpoint_hostname.iter().cloned().collect()
    }
}

/// Sender abstraction to handle both plain UDP and DTLS connections.
enum UdpSender {
    Plain(Arc<UdpSocket>),
    Dtls(Arc<crate::dtls::DtlsConnection>),
}

/// One local delivery failure plus whether the connected sender can still be
/// trusted. Deterministic encoding/size rejection must participate in
/// retry/final-loss accounting without tearing down a healthy DTLS association.
struct UdpDeliveryError {
    message: String,
    reset_sender: bool,
}

impl UdpDeliveryError {
    fn local(message: String) -> Self {
        Self {
            message,
            reset_sender: false,
        }
    }

    fn transport(message: String) -> Self {
        Self {
            message,
            reset_sender: true,
        }
    }

    fn message(&self) -> &str {
        &self.message
    }

    fn into_message(self) -> String {
        self.message
    }

    fn requires_sender_reset(&self) -> bool {
        self.reset_sender
    }
}

fn record_local_record_drop(error: &UdpDeliveryError) {
    let total = LOCAL_RECORD_DROPS.fetch_add(1, Ordering::Relaxed).saturating_add(1);
    if total == 1 || total % LOCAL_RECORD_DROP_WARN_EVERY == 0 {
        warn!(
            dropped_records = total,
            reason = %error.message(),
            "udp_logging: discarded co-batched record after deterministic local rejection; \
             valid siblings were preserved"
        );
    }
}

impl UdpSender {
    async fn send(&self, data: &[u8]) -> Result<(), UdpDeliveryError> {
        match self {
            UdpSender::Plain(socket) => match socket.send(data).await {
                Ok(written) if written == data.len() => Ok(()),
                Ok(written) => Err(UdpDeliveryError::transport(format!(
                    "UDP send was incomplete: wrote {written} of {} bytes",
                    data.len()
                ))),
                Err(error) => Err(UdpDeliveryError::transport(format!(
                    "UDP send error: {error}"
                ))),
            },
            UdpSender::Dtls(conn) => conn
                .send(data)
                .await
                .map_err(|e| UdpDeliveryError::transport(format!("DTLS send error: {e}"))),
        }
    }
}

async fn resolve_endpoint(
    cfg: &UdpFlushConfig,
    dns_cache: Option<&DnsCache>,
) -> Result<SocketAddr, String> {
    if let Ok(mut slot) = cfg.next_resolve_addr.lock()
        && let Some(addr) = slot.take()
    {
        return Ok(addr);
    }
    resolve_udp_endpoint(&cfg.host, cfg.port, dns_cache, "udp_logging").await
}

async fn create_sender(
    cfg: &UdpFlushConfig,
    dns_cache: Option<&DnsCache>,
) -> Result<(UdpSender, SocketAddr), String> {
    let remote_addr = resolve_endpoint(cfg, dns_cache).await?;
    let sender = build_sender_for_addr(cfg, remote_addr).await?;
    Ok((sender, remote_addr))
}

/// Bind an ephemeral local UDP socket, connect to `remote_addr`, and (if
/// configured) complete a DTLS handshake using admission-cached material.
async fn build_sender_for_addr(
    cfg: &UdpFlushConfig,
    remote_addr: SocketAddr,
) -> Result<UdpSender, String> {
    let socket = bind_connected_udp_socket(remote_addr, "udp_logging").await?;

    if cfg.dtls_enabled {
        let material = cfg.dtls_material.as_ref().ok_or_else(|| {
            "udp_logging: DTLS enabled but admission-cached material is missing".to_string()
        })?;
        let params = crate::dtls::BackendDtlsParams {
            config: Arc::new(dimpl::Config::default()),
            certificate: material.certificate.clone(),
            server_name: material.server_name.clone(),
            server_cert_verifier: material.server_cert_verifier.clone(),
            // The udp_logging plugin doesn't expose a connect timeout config,
            // so preserve the historical 10s budget that this code path used
            // before `BackendDtlsParams.connect_timeout_ms` existed.
            connect_timeout_ms: 10_000,
        };

        let dtls_conn = crate::dtls::DtlsConnection::connect(socket, params)
            .await
            .map_err(|error| format!("udp_logging: DTLS handshake failed: {error}"))?;

        Ok(UdpSender::Dtls(Arc::new(dtls_conn)))
    } else {
        Ok(UdpSender::Plain(Arc::new(socket)))
    }
}

async fn send_batch(
    cfg: &UdpFlushConfig,
    state: &Mutex<UdpFlushState>,
    batch: Vec<SummaryLogEntry>,
) -> Result<(), String> {
    if batch.is_empty() {
        return Ok(());
    }

    let (mut sender, mut current_addr, mut last_resolve) = {
        let mut state = state
            .lock()
            .map_err(|_| "udp_logging: flush state lock poisoned".to_string())?;
        (state.sender.take(), state.current_addr, state.last_resolve)
    };

    if sender.is_none() {
        let (new_sender, new_addr) = create_sender(cfg, cfg.dns_cache.as_ref()).await?;
        last_resolve = Instant::now();
        sender = Some(new_sender);
        current_addr = Some(new_addr);
    }

    // Periodically re-resolve DNS and rebuild the sender when the endpoint
    // address actually changes (DNS rollover, pod reschedule, LB failover).
    // This applies to DTLS too: a connected DTLS association established once
    // at startup would otherwise keep sending to a stale peer forever. The
    // address-equality guard ensures a fresh DTLS handshake only runs when the
    // resolved address moved. Re-resolve or replacement-handshake failure
    // retains the current sender at the previously pinned address.
    if last_resolve.elapsed() >= UDP_RE_RESOLVE_INTERVAL {
        let elapsed = last_resolve.elapsed();
        last_resolve = Instant::now();
        match resolve_endpoint(cfg, cfg.dns_cache.as_ref()).await {
            Ok(new_addr)
                if should_replace_sender_on_resolve(
                    elapsed,
                    current_addr,
                    new_addr,
                    UDP_RE_RESOLVE_INTERVAL,
                ) =>
            {
                match build_sender_for_addr(cfg, new_addr).await {
                    Ok(new_sender) => {
                        sender = Some(new_sender);
                        current_addr = Some(new_addr);
                    }
                    Err(error) => {
                        warn!(
                            "udp_logging: DTLS/UDP sender rebuild after DNS change failed; \
                             retaining current association: {error}"
                        );
                    }
                }
            }
            Ok(_) => {}
            Err(error) => {
                warn!(
                    "udp_logging: periodic DNS re-resolve failed; retaining current association: {error}"
                );
            }
        }
    }

    let result = match sender.as_ref() {
        Some(active_sender) => deliver_batch(cfg, active_sender, &batch).await,
        None => Err(UdpDeliveryError::transport(
            "udp_logging: sender unavailable after initialization".to_string(),
        )),
    };

    // On transport/driver failure, tear down the sender so the next batch's
    // `sender.is_none()` branch forces a fresh resolve + handshake. UDP/DTLS
    // sends frequently succeed at the socket layer even when the peer is gone,
    // so error-triggered teardown is the most robust recovery trigger and also
    // covers plain-UDP socket errors that the periodic re-resolve would miss.
    // Deterministic local encoding/size rejection keeps the healthy sender.
    if result
        .as_ref()
        .is_err_and(UdpDeliveryError::requires_sender_reset)
    {
        sender = None;
        current_addr = None;
    }

    let mut state = state
        .lock()
        .map_err(|_| "udp_logging: flush state lock poisoned".to_string())?;
    state.sender = sender;
    state.current_addr = current_addr;
    state.last_resolve = last_resolve;

    result.map_err(UdpDeliveryError::into_message)
}

/// DTLS plaintext-size gate for one already-serialized batch payload.
///
/// Kept pure (no async / no I/O) so the multi-entry split path can call a
/// non-recursive single-entry helper without boxing an async recursion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DtlsBatchSizeDecision {
    /// Payload fits the ceiling (or DTLS is off); send as one datagram.
    SendAsIs,
    /// Single-entry batch exceeds the ceiling — fail closed into retry/final-loss.
    RejectOversizedSingle,
    /// Multi-entry batch exceeds the ceiling — deliver each entry independently.
    SplitPerEntry,
}

pub(crate) fn classify_dtls_batch_size(
    dtls_enabled: bool,
    payload_len: usize,
    batch_len: usize,
    max_plaintext: usize,
) -> DtlsBatchSizeDecision {
    if !dtls_enabled || payload_len <= max_plaintext {
        return DtlsBatchSizeDecision::SendAsIs;
    }
    if batch_len == 1 {
        DtlsBatchSizeDecision::RejectOversizedSingle
    } else {
        DtlsBatchSizeDecision::SplitPerEntry
    }
}

fn oversized_dtls_batch_error(max_plaintext: usize, got: usize) -> String {
    format!(
        "udp_logging: DTLS batch exceeds max_plaintext \
         ({max_plaintext} bytes, got {got}); local delivery rejected before driver enqueue"
    )
}

fn serialize_batch_payload(
    batch: &[SummaryLogEntry],
    schema: Option<&SummarySchema>,
) -> Result<Vec<u8>, UdpDeliveryError> {
    let view = SummaryLogEntryBatchView {
        entries: batch,
        schema,
    };
    match serde_json::to_vec(&view) {
        Ok(payload) => Ok(payload),
        Err(error) => Err(UdpDeliveryError::local(format!(
            "udp_logging: failed to serialize batch: {error}"
        ))),
    }
}

pub(crate) fn classify_serialized_dtls_batch_for_test(
    batch: &[SummaryLogEntry],
    max_plaintext: usize,
) -> Result<(DtlsBatchSizeDecision, usize), String> {
    let payload = serialize_batch_payload(batch, None).map_err(UdpDeliveryError::into_message)?;
    let decision = classify_dtls_batch_size(true, payload.len(), batch.len(), max_plaintext);
    Ok((decision, payload.len()))
}

async fn deliver_batch(
    cfg: &UdpFlushConfig,
    sender: &UdpSender,
    batch: &[SummaryLogEntry],
) -> Result<(), UdpDeliveryError> {
    let payload = serialize_batch_payload(batch, cfg.schema.as_deref())?;

    let max_plaintext = crate::dtls::max_plaintext_bytes();
    match classify_dtls_batch_size(cfg.dtls_enabled, payload.len(), batch.len(), max_plaintext) {
        DtlsBatchSizeDecision::SendAsIs => sender.send(&payload).await,
        DtlsBatchSizeDecision::RejectOversizedSingle => Err(UdpDeliveryError::local(
            oversized_dtls_batch_error(max_plaintext, payload.len()),
        )),
        DtlsBatchSizeDecision::SplitPerEntry => {
            // Fixed one-level fan-out into the non-recursive single-entry helper
            // so one oversized record cannot erase co-batched siblings. Oversized
            // singles are discarded with an explicit warning; other local delivery
            // failures still propagate into retry/final-loss.
            for entry in batch {
                match deliver_one_entry(cfg, sender, entry).await {
                    Ok(()) => {}
                    Err(error) if !error.requires_sender_reset() => {
                        record_local_record_drop(&error);
                    }
                    Err(error) => return Err(error),
                }
            }
            Ok(())
        }
    }
}

/// Deliver a single log entry as its own datagram. Never calls [`deliver_batch`],
/// so the multi-entry oversized split stays a fixed-depth fan-out (no async
/// recursion / no `Box::pin` of an unbounded path).
async fn deliver_one_entry(
    cfg: &UdpFlushConfig,
    sender: &UdpSender,
    entry: &SummaryLogEntry,
) -> Result<(), UdpDeliveryError> {
    let payload = serialize_batch_payload(std::slice::from_ref(entry), cfg.schema.as_deref())?;

    let max_plaintext = crate::dtls::max_plaintext_bytes();
    match classify_dtls_batch_size(cfg.dtls_enabled, payload.len(), 1, max_plaintext) {
        DtlsBatchSizeDecision::SendAsIs => sender.send(&payload).await,
        DtlsBatchSizeDecision::RejectOversizedSingle => Err(UdpDeliveryError::local(
            oversized_dtls_batch_error(max_plaintext, payload.len()),
        )),
        // `batch_len == 1` never selects split; keep fail-closed if the
        // classifier contract changes.
        DtlsBatchSizeDecision::SplitPerEntry => Err(UdpDeliveryError::local(
            oversized_dtls_batch_error(max_plaintext, payload.len()),
        )),
    }
}

// ---------------------------------------------------------------------------
// Test support
// ---------------------------------------------------------------------------

impl UdpLogging {
    /// Age the flush worker's last DNS resolve so the next batch exercises the
    /// periodic re-resolve path. Production code never calls this.
    #[allow(dead_code)] // used only by tests/, dead code in the bin target
    pub fn age_last_resolve_for_test(&self, elapsed: Duration) {
        if let Ok(mut state) = self.flush_state.lock() {
            state.last_resolve = Instant::now()
                .checked_sub(elapsed)
                .unwrap_or_else(Instant::now);
        }
    }

    /// Publish a one-shot resolve override consumed by the next DNS lookup in
    /// the flush worker. Production code never calls this.
    #[allow(dead_code)] // used only by tests/, dead code in the bin target
    pub fn set_next_resolve_addr_for_test(&self, addr: SocketAddr) {
        if let Ok(mut slot) = self.next_resolve_addr.lock() {
            *slot = Some(addr);
        }
    }

    /// Snapshot of the flush worker's currently pinned destination, if any.
    #[allow(dead_code)] // used only by tests/, dead code in the bin target
    pub fn current_addr_for_test(&self) -> Option<SocketAddr> {
        self.flush_state
            .lock()
            .ok()
            .and_then(|state| state.current_addr)
    }
}
