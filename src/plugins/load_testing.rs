//! Load Testing Plugin
//!
//! Enables on-demand load testing of a proxy's backend by sending concurrent
//! requests through the gateway's own proxy listener. Triggered when a request
//! includes an `X-Loadtesting-Key` header matching the configured secret key.
//!
//! ## How it works
//!
//! When a matching key is received in `before_proxy`, the plugin strips the
//! trigger key from the original request (so backends and earlier mirrors that
//! already copied headers cannot reuse a post-trigger observation from this
//! request path), then spawns a background load test that sends concurrent
//! requests back through the gateway's local listener
//! (`127.0.0.1:{gateway_port}`). Synthetic requests omit the trigger key, so
//! they flow through the full proxy pipeline without re-triggering the load
//! test. Native transaction logging captures every synthetic request.
//!
//! The triggering request itself proceeds normally through the proxy pipeline
//! and is not blocked by the load test.
//!
//! ## Multi-node fan-out
//!
//! When `gateway_addresses` is configured, the originating controller fans out
//! once with `X-Loadtesting-Fanout: 1`. Peer nodes that accept a fan-out
//! trigger start a local cohort only — they never re-fanout — and terminate
//! the control request before backend dispatch.
//!
//! ## HTTPS loopback
//!
//! For deployments that disable the HTTP listener and only expose HTTPS,
//! set `gateway_tls: true` to send synthetic requests to the HTTPS port.
//! Since the gateway's frontend TLS cert is typically issued for an external
//! domain (not `127.0.0.1`), `gateway_tls_no_verify` (default `true` when
//! `gateway_tls` is enabled) skips certificate verification for the loopback
//! connection only.
//!
//! ## Caveats
//!
//! - **Auth forwarding**: Synthetic requests forward the triggering request's
//!   headers (minus the trigger key, hop-by-hop headers, and client-supplied
//!   forwarding identity). For auth schemes with short-lived tokens, tokens may
//!   expire during long-duration tests.
//! - **Rate limiting**: Synthetic requests pass through rate limiting plugins
//!   on the proxy. High `concurrent_clients` values may trigger rate limits.
//!
//! Unknown top-level keys are rejected with path-qualified diagnostics.
//! Serving-mode publication uses `KeepLastKnownGood`.

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::StreamExt;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
use tracing::info;
use url::Url;

use super::utils::auth_flow::constant_time_eq;
use super::{Plugin, PluginHttpClient, PluginResult, RequestContext};
use crate::dns::DnsCacheResolver;
use crate::proxy::headers::{
    is_backend_request_strip_header, is_proxy_generated_forwarding_header,
};
use crate::retry::classify_reqwest_error;
use crate::util::unknown_keys::reject_unknown_keys;

/// Authoritative closed set of top-level `load_testing` configuration keys.
pub const LOAD_TESTING_CONFIG_KEYS: &[&str] = &[
    "concurrent_clients",
    "duration_seconds",
    "gateway_addresses",
    "gateway_port",
    "gateway_tls",
    "gateway_tls_no_verify",
    "key",
    "max_response_body_bytes",
    "ramp",
    "request_timeout_ms",
];

/// Minimum accepted trigger-key length. Short reusable keys are rejected at
/// admission so a weak shared secret is harder to guess or leak into logs.
pub const MIN_TRIGGER_KEY_LEN: usize = 16;

/// Hard ceiling for per-request timeout (independent of run duration).
pub const MAX_REQUEST_TIMEOUT_MS: u64 = 60_000;

/// Process-wide admission budget across every effective load_testing instance.
const MAX_PROCESS_ACTIVE_CLIENTS: u64 = 10_000;

const HEADER_TRIGGER_KEY: &str = "x-loadtesting-key";
const HEADER_FANOUT: &str = "x-loadtesting-fanout";
const FANOUT_MARKER: &str = "1";

static PROCESS_ACTIVE_CLIENTS: AtomicU64 = AtomicU64::new(0);
static SHARED_STATES: OnceLock<Mutex<HashMap<String, Weak<LoadTestingState>>>> = OnceLock::new();

/// Stable run-admission state shared across compatible plugin-cache generations
/// for one plugin-config identity.
pub(crate) struct LoadTestingState {
    is_running: AtomicBool,
    run_cancel: Mutex<CancellationToken>,
    last_result: Mutex<Option<RunResult>>,
}

impl LoadTestingState {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            is_running: AtomicBool::new(false),
            run_cancel: Mutex::new(CancellationToken::new()),
            last_result: Mutex::new(None),
        })
    }

    fn begin_run(&self) -> Option<CancellationToken> {
        if self
            .is_running
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return None;
        }
        let token = CancellationToken::new();
        let mut guard = self
            .run_cancel
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Cancel any residual token from a prior generation edge case.
        guard.cancel();
        *guard = token.clone();
        Some(token)
    }

    fn end_run(&self, result: RunResult) {
        if let Ok(mut guard) = self.last_result.lock() {
            *guard = Some(result);
        }
        self.is_running.store(false, Ordering::Release);
    }

    fn cancel_active_run(&self) {
        let guard = self
            .run_cancel
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.cancel();
    }
}

impl Drop for LoadTestingState {
    fn drop(&mut self) {
        self.cancel_active_run();
        self.is_running.store(false, Ordering::Release);
    }
}

/// Aggregated completion counters for one load-test cohort.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunResult {
    pub outcome: RunOutcome,
    pub attempted_requests: u64,
    pub responses_received: u64,
    pub responses_completed: u64,
    pub responses_truncated: u64,
    pub response_body_errors: u64,
    pub transport_errors: u64,
    pub status_2xx: u64,
    pub status_3xx: u64,
    pub status_4xx: u64,
    pub status_5xx: u64,
    pub status_other: u64,
    pub worker_failures: u64,
    pub cancelled_workers: u64,
    pub aggregation_saturated: bool,
    pub elapsed_ms: u64,
}

impl RunResult {
    pub fn completed_requests_per_second(&self) -> f64 {
        if self.elapsed_ms == 0 {
            return 0.0;
        }
        self.responses_completed as f64 / (self.elapsed_ms as f64 / 1000.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RunOutcome {
    #[default]
    Success,
    Degraded,
    Failed,
    Cancelled,
}

#[derive(Debug, Default)]
struct WorkerCounters {
    attempted_requests: u64,
    responses_received: u64,
    responses_completed: u64,
    responses_truncated: u64,
    response_body_errors: u64,
    transport_errors: u64,
    status_2xx: u64,
    status_3xx: u64,
    status_4xx: u64,
    status_5xx: u64,
    status_other: u64,
}

impl WorkerCounters {
    fn saturating_add_into(&self, total: &mut Self) -> bool {
        let mut saturated = false;
        saturated |= saturating_add_assign(&mut total.attempted_requests, self.attempted_requests);
        saturated |= saturating_add_assign(&mut total.responses_received, self.responses_received);
        saturated |=
            saturating_add_assign(&mut total.responses_completed, self.responses_completed);
        saturated |=
            saturating_add_assign(&mut total.responses_truncated, self.responses_truncated);
        saturated |=
            saturating_add_assign(&mut total.response_body_errors, self.response_body_errors);
        saturated |= saturating_add_assign(&mut total.transport_errors, self.transport_errors);
        saturated |= saturating_add_assign(&mut total.status_2xx, self.status_2xx);
        saturated |= saturating_add_assign(&mut total.status_3xx, self.status_3xx);
        saturated |= saturating_add_assign(&mut total.status_4xx, self.status_4xx);
        saturated |= saturating_add_assign(&mut total.status_5xx, self.status_5xx);
        saturated |= saturating_add_assign(&mut total.status_other, self.status_other);
        saturated
    }
}

fn saturating_add_assign(dst: &mut u64, src: u64) -> bool {
    let (sum, overflow) = dst.overflowing_add(src);
    *dst = if overflow { u64::MAX } else { sum };
    overflow
}

enum BodyConsumeOutcome {
    Completed,
    Truncated,
    StreamError,
}

pub struct LoadTesting {
    http_client: PluginHttpClient,
    load_test_client: reqwest::Client,
    key: String,
    concurrent_clients: u32,
    duration_seconds: u64,
    request_timeout_ms: u64,
    ramp: bool,
    max_response_body_bytes: u64,
    gateway_base_url: String,
    gateway_addresses: Vec<String>,
    state: Arc<LoadTestingState>,
}

impl LoadTesting {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        Self::from_parts(config, http_client, LoadTestingState::new())
    }

    /// Construct with state shared across reload generations for one plugin
    /// config identity (`namespace` + `id`).
    pub(crate) fn new_with_instance_id(
        config: &Value,
        http_client: PluginHttpClient,
        namespace: &str,
        plugin_config_id: &str,
    ) -> Result<Self, String> {
        let identity = format!("{namespace}\0{plugin_config_id}");
        let state = retain_shared_state(&identity);
        Self::from_parts(config, http_client, state)
    }

    pub(crate) fn with_shared_state(
        config: &Value,
        http_client: PluginHttpClient,
        state: Arc<LoadTestingState>,
    ) -> Result<Self, String> {
        Self::from_parts(config, http_client, state)
    }

    /// Construct another instance that shares this plugin's run-admission state.
    ///
    /// Used by unit tests (and mirrors plugin-cache reload sharing) so two
    /// `LoadTesting` values observe the same `is_running` guard.
    pub fn share_with(
        &self,
        config: &Value,
        http_client: PluginHttpClient,
    ) -> Result<Self, String> {
        Self::with_shared_state(config, http_client, Arc::clone(&self.state))
    }

    pub(crate) fn shared_state(&self) -> Arc<LoadTestingState> {
        Arc::clone(&self.state)
    }

    /// Whether a cohort is currently admitted on this plugin identity.
    pub fn is_running(&self) -> bool {
        self.state.is_running.load(Ordering::Acquire)
    }

    /// Most recent completed cohort result for this plugin identity, if any.
    pub fn last_run_result(&self) -> Option<RunResult> {
        self.state
            .last_result
            .lock()
            .ok()
            .and_then(|guard| guard.clone())
    }

    fn from_parts(
        config: &Value,
        http_client: PluginHttpClient,
        state: Arc<LoadTestingState>,
    ) -> Result<Self, String> {
        let config_obj = config
            .as_object()
            .ok_or_else(|| "load_testing: config must be an object".to_string())?;
        reject_unknown_keys(
            config_obj,
            "config",
            LOAD_TESTING_CONFIG_KEYS,
            "load_testing: ",
        )?;

        let key = optional_string(config, "key")?
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                "load_testing: 'key' is required and must be a non-empty string".to_string()
            })?;
        if key.len() < MIN_TRIGGER_KEY_LEN {
            return Err(format!(
                "load_testing: 'key' must be at least {MIN_TRIGGER_KEY_LEN} characters"
            ));
        }

        let concurrent_clients = optional_u64(config, "concurrent_clients")?
            .ok_or_else(|| "load_testing: 'concurrent_clients' is required".to_string())?;
        if concurrent_clients == 0 || concurrent_clients > 10_000 {
            return Err(format!(
                "load_testing: 'concurrent_clients' must be 1–10000 (got {})",
                concurrent_clients
            ));
        }

        let duration_seconds = optional_u64(config, "duration_seconds")?
            .ok_or_else(|| "load_testing: 'duration_seconds' is required".to_string())?;
        if duration_seconds == 0 || duration_seconds > 3600 {
            return Err(format!(
                "load_testing: 'duration_seconds' must be 1–3600 (got {})",
                duration_seconds
            ));
        }

        let ramp = optional_bool(config, "ramp")?.unwrap_or(false);

        let request_timeout_ms = optional_u64(config, "request_timeout_ms")?.unwrap_or(30_000);
        if request_timeout_ms == 0 {
            return Err("load_testing: 'request_timeout_ms' must be greater than 0".to_string());
        }
        if request_timeout_ms > MAX_REQUEST_TIMEOUT_MS {
            return Err(format!(
                "load_testing: 'request_timeout_ms' must be <= {MAX_REQUEST_TIMEOUT_MS} (got {request_timeout_ms})"
            ));
        }

        let max_response_body_bytes =
            optional_u64(config, "max_response_body_bytes")?.unwrap_or(1_048_576);
        if max_response_body_bytes == 0 {
            return Err(
                "load_testing: 'max_response_body_bytes' must be greater than 0".to_string(),
            );
        }

        let gateway_tls = optional_bool(config, "gateway_tls")?.unwrap_or(false);
        let gateway_tls_no_verify =
            optional_bool(config, "gateway_tls_no_verify")?.unwrap_or(gateway_tls);

        let default_env_var = if gateway_tls {
            "FERRUM_PROXY_HTTPS_PORT"
        } else {
            "FERRUM_PROXY_HTTP_PORT"
        };
        let default_port: u16 = if gateway_tls { 8443 } else { 8000 };
        let listener_name = if gateway_tls {
            "HTTPS (FERRUM_PROXY_HTTPS_PORT)"
        } else {
            "HTTP (FERRUM_PROXY_HTTP_PORT)"
        };

        let gateway_port = optional_u64(config, "gateway_port")?
            .map(|p| {
                if p == 0 || p > 65535 {
                    Err(format!(
                        "load_testing: 'gateway_port' must be 1–65535 (got {})",
                        p
                    ))
                } else {
                    Ok(p as u16)
                }
            })
            .transpose()?
            .unwrap_or_else(|| {
                std::env::var(default_env_var)
                    .ok()
                    .and_then(|v| v.parse::<u16>().ok())
                    .unwrap_or(default_port)
            });

        if gateway_port == 0 {
            return Err(format!(
                "load_testing: resolved gateway port is 0 because the selected {listener_name} \
listener is disabled; set gateway_tls to select an enabled listener and/or set an explicit \
gateway_port in 1–65535"
            ));
        }

        let scheme = if gateway_tls { "https" } else { "http" };
        let gateway_base_url = format!("{}://127.0.0.1:{}", scheme, gateway_port);

        let mut load_test_builder = reqwest::Client::builder()
            .danger_accept_invalid_certs(gateway_tls_no_verify)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_millis(request_timeout_ms));
        if let Some(dns_cache) = http_client.dns_cache() {
            load_test_builder =
                load_test_builder.dns_resolver(Arc::new(DnsCacheResolver::new(dns_cache.clone())));
        }
        let load_test_client = load_test_builder
            .build()
            .map_err(|e| format!("load_testing: failed to build HTTP client: {}", e))?;

        let gateway_addresses = parse_gateway_addresses(config, &http_client, &gateway_base_url)?;

        Ok(Self {
            http_client,
            load_test_client,
            key,
            concurrent_clients: concurrent_clients as u32,
            duration_seconds,
            request_timeout_ms,
            ramp,
            max_response_body_bytes,
            gateway_base_url,
            gateway_addresses,
            state,
        })
    }

    fn trigger_key_present_and_matches(&self, headers: &HashMap<String, String>) -> bool {
        headers
            .get(HEADER_TRIGGER_KEY)
            .map(|k| constant_time_eq(k.as_bytes(), self.key.as_bytes()))
            .unwrap_or(false)
    }

    fn is_fanout_control_request(headers: &HashMap<String, String>) -> bool {
        headers
            .get(HEADER_FANOUT)
            .is_some_and(|value| value == FANOUT_MARKER)
    }
}

fn retain_shared_state(identity: &str) -> Arc<LoadTestingState> {
    let registry = SHARED_STATES.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = registry
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(existing) = guard.get(identity).and_then(|weak| weak.upgrade()) {
        return existing;
    }
    let state = LoadTestingState::new();
    guard.insert(identity.to_string(), Arc::downgrade(&state));
    // Opportunistically prune dead weak entries.
    guard.retain(|_, weak| weak.strong_count() > 0);
    state
}

fn parse_gateway_addresses(
    config: &Value,
    http_client: &PluginHttpClient,
    local_base_url: &str,
) -> Result<Vec<String>, String> {
    match config.get("gateway_addresses") {
        Some(Value::Array(addresses)) => {
            if addresses.is_empty() {
                return Err(
                    "load_testing: 'gateway_addresses' must not be empty when provided".to_string(),
                );
            }
            let mut urls = Vec::with_capacity(addresses.len());
            let mut seen = HashSet::new();
            let local_label = sanitize_gateway_label(local_base_url);
            for addr in addresses {
                let url = addr.as_str().ok_or_else(|| {
                    "load_testing: each 'gateway_addresses' entry must be a string".to_string()
                })?;
                if url.is_empty() {
                    return Err(
                        "load_testing: 'gateway_addresses' entries must not be empty".to_string(),
                    );
                }
                validate_gateway_address(url)?;
                if let Ok(parsed) = Url::parse(url) {
                    crate::plugins::utils::log_helpers::screen_url_host_egress(
                        "load_testing",
                        "gateway_addresses",
                        &parsed,
                        http_client.backend_allow_ips(),
                    )?;
                }
                let normalized = url.trim_end_matches('/').to_string();
                let label = sanitize_gateway_label(&normalized);
                if label == local_label {
                    return Err(format!(
                        "load_testing: 'gateway_addresses' must not include this node's local loopback target ({label})"
                    ));
                }
                if !seen.insert(label.clone()) {
                    return Err(format!(
                        "load_testing: duplicate 'gateway_addresses' entry for {label}"
                    ));
                }
                urls.push(normalized);
            }
            Ok(urls)
        }
        Some(Value::Null) | None => Ok(Vec::new()),
        Some(_) => Err("load_testing: 'gateway_addresses' must be an array".to_string()),
    }
}

fn validate_gateway_address(url: &str) -> Result<(), String> {
    let parsed = Url::parse(url)
        .map_err(|e| format!("load_testing: invalid gateway address '{url}': {e}"))?;
    if !matches!(parsed.scheme(), "http" | "https")
        || !has_non_empty_authority(url)
        || parsed.host_str().is_none()
    {
        return Err(format!(
            "load_testing: gateway address '{url}' must be an http(s) URL with a host"
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(format!(
            "load_testing: gateway address must not include URL userinfo (credentials); got host '{}'",
            parsed.host_str().unwrap_or("unknown")
        ));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(format!(
            "load_testing: gateway address '{url}' must not include a query or fragment"
        ));
    }
    Ok(())
}

fn has_non_empty_authority(raw_url: &str) -> bool {
    raw_url
        .split_once("://")
        .and_then(|(_, rest)| rest.split(['/', '?', '#']).next())
        .is_some_and(|authority| !authority.is_empty())
}

/// Scheme/host/port label suitable for logs — never path, query, or userinfo.
fn sanitize_gateway_label(url: &str) -> String {
    match Url::parse(url) {
        Ok(parsed) => {
            let scheme = parsed.scheme();
            let host = parsed.host_str().unwrap_or("invalid-host");
            match parsed.port() {
                Some(port) => format!("{scheme}://{host}:{port}"),
                None => format!("{scheme}://{host}"),
            }
        }
        Err(_) => "invalid-gateway-address".to_string(),
    }
}

fn optional_bool(config: &Value, key: &str) -> Result<Option<bool>, String> {
    match config.get(key) {
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(format!("load_testing: '{key}' must be a boolean")),
    }
}

fn optional_string(config: &Value, key: &str) -> Result<Option<String>, String> {
    match config.get(key) {
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(format!("load_testing: '{key}' must be a string")),
    }
}

fn optional_u64(config: &Value, key: &str) -> Result<Option<u64>, String> {
    match config.get(key) {
        Some(Value::Number(value)) => value
            .as_u64()
            .map(Some)
            .ok_or_else(|| format!("load_testing: '{key}' must be an unsigned integer")),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(format!("load_testing: '{key}' must be an unsigned integer")),
    }
}

fn try_reserve_process_clients(count: u64) -> bool {
    loop {
        let current = PROCESS_ACTIVE_CLIENTS.load(Ordering::Relaxed);
        if current.saturating_add(count) > MAX_PROCESS_ACTIVE_CLIENTS {
            return false;
        }
        if PROCESS_ACTIVE_CLIENTS
            .compare_exchange_weak(
                current,
                current + count,
                Ordering::SeqCst,
                Ordering::Relaxed,
            )
            .is_ok()
        {
            return true;
        }
    }
}

fn release_process_clients(count: u64) {
    PROCESS_ACTIVE_CLIENTS.fetch_sub(count, Ordering::SeqCst);
}

#[async_trait]
impl Plugin for LoadTesting {
    fn name(&self) -> &str {
        "load_testing"
    }

    fn priority(&self) -> u16 {
        super::priority::LOAD_TESTING
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::HTTP_ONLY_PROTOCOLS
    }

    fn defer_before_proxy_until_backend_path_resolved(&self) -> bool {
        true
    }

    fn requires_request_body_before_before_proxy(&self) -> bool {
        true
    }

    fn needs_request_body_bytes(&self) -> bool {
        true
    }

    fn needs_request_body_text(&self) -> bool {
        false
    }

    fn should_buffer_request_body(&self, ctx: &RequestContext) -> bool {
        // Preserve the ordinary non-trigger hot path: buffer only when the
        // trigger header is present (matched later in before_proxy).
        ctx.headers.contains_key(HEADER_TRIGGER_KEY)
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        let key_matches = self.trigger_key_present_and_matches(headers);
        if !key_matches {
            return PluginResult::Continue;
        }

        let is_fanout = Self::is_fanout_control_request(headers);

        // Never forward the reusable administrative trigger key to backends.
        headers.remove(HEADER_TRIGGER_KEY);
        // Fanout marker is control-plane only.
        headers.remove(HEADER_FANOUT);

        let Some(run_cancel) = self.state.begin_run() else {
            tracing::warn!("load_testing: test already in progress, ignoring trigger");
            return if is_fanout {
                fanout_ack_result()
            } else {
                PluginResult::Continue
            };
        };

        if !try_reserve_process_clients(u64::from(self.concurrent_clients)) {
            tracing::warn!(
                requested = self.concurrent_clients,
                "load_testing: process-wide active client budget exhausted; ignoring trigger"
            );
            self.state.end_run(RunResult {
                outcome: RunOutcome::Failed,
                ..RunResult::default()
            });
            return if is_fanout {
                fanout_ack_result()
            } else {
                PluginResult::Continue
            };
        }

        let proxy_name = ctx
            .matched_proxy
            .as_ref()
            .and_then(|p| p.name.as_deref())
            .unwrap_or("unknown")
            .to_string();

        let path = ctx.path.clone();
        let raw_query = ctx.raw_query_string().map(str::to_owned);
        let method = ctx.method.clone();
        let body_bytes: Option<Bytes> = ctx.request_body_bytes.clone();

        let synthetic_headers = filter_outbound_headers(headers, /*keep_trigger_key=*/ false);
        let fanout_headers = filter_outbound_headers(headers, /*keep_trigger_key=*/ true);

        let concurrent_clients = self.concurrent_clients;
        let duration = Duration::from_secs(self.duration_seconds);
        let duration_secs = self.duration_seconds;
        let ramp = self.ramp;
        let max_response_body_bytes = self.max_response_body_bytes;
        let request_timeout_ms = self.request_timeout_ms;
        let gateway_base_url = self.gateway_base_url.clone();
        let load_test_client = self.load_test_client.clone();
        let state = Arc::clone(&self.state);
        let gateway_addresses = self.gateway_addresses.clone();
        let http_client = self.http_client.clone();
        let trigger_key = self.key.clone();

        // Originating controllers fan out once. Peer fan-out receivers never
        // re-forward, which collapses the previous quadratic mesh amplification.
        if !is_fanout && !gateway_addresses.is_empty() {
            for addr in &gateway_addresses {
                let fanout_url = build_url(addr, &path, raw_query.as_deref());
                let fanout_method = method.clone();
                let mut fanout_hdrs = fanout_headers.clone();
                fanout_hdrs.push((HEADER_TRIGGER_KEY.to_string(), trigger_key.clone()));
                fanout_hdrs.push((HEADER_FANOUT.to_string(), FANOUT_MARKER.to_string()));
                let client = http_client.clone();
                let remote_label = sanitize_gateway_label(addr);
                let body = body_bytes.clone();

                tokio::spawn(async move {
                    let mut req =
                        build_request(client.get(), &fanout_method, &fanout_url, &fanout_hdrs);
                    if method_allows_body(&fanout_method)
                        && let Some(bytes) = body
                    {
                        req = req.body(bytes);
                    }
                    if let Err(err) = client
                        .execute_redacted(req, "load_testing_fanout", &remote_label)
                        .await
                    {
                        tracing::warn!(
                            remote = %remote_label,
                            error = %err,
                            "load_testing: failed to fan out trigger to remote node"
                        );
                    }
                });
            }
        }

        info!(
            proxy = %proxy_name,
            concurrent_clients = concurrent_clients,
            duration_seconds = duration_secs,
            ramp = ramp,
            fanout_control = is_fanout,
            "load_testing: starting load test"
        );

        tokio::spawn(async move {
            let _client_budget = ProcessClientBudget::new(u64::from(concurrent_clients));
            let start = Instant::now();
            let deadline = start + duration;
            let mut handles = Vec::with_capacity(concurrent_clients as usize);

            for i in 0..concurrent_clients {
                let ramp_delay = if ramp {
                    duration * i / concurrent_clients
                } else {
                    Duration::ZERO
                };

                let client = load_test_client.clone();
                let base_url = gateway_base_url.clone();
                let path = path.clone();
                let raw_query = raw_query.clone();
                let method = method.clone();
                let req_headers = synthetic_headers.clone();
                let body = body_bytes.clone();
                let worker_cancel = run_cancel.clone();
                let per_request_timeout = Duration::from_millis(request_timeout_ms);

                let handle = tokio::spawn(async move {
                    if !ramp_delay.is_zero() {
                        tokio::select! {
                            _ = worker_cancel.cancelled() => {
                                return Ok(WorkerCounters::default());
                            }
                            _ = tokio::time::sleep(ramp_delay) => {}
                        }
                    }

                    let mut counters = WorkerCounters::default();

                    while Instant::now() < deadline {
                        if worker_cancel.is_cancelled() {
                            break;
                        }

                        let remaining = deadline.saturating_duration_since(Instant::now());
                        if remaining.is_zero() {
                            break;
                        }
                        let attempt_timeout = per_request_timeout.min(remaining);
                        counters.attempted_requests = counters.attempted_requests.saturating_add(1);

                        let url = build_url(&base_url, &path, raw_query.as_deref());
                        let mut req = build_request(&client, &method, &url, &req_headers);
                        if method_allows_body(&method)
                            && let Some(ref bytes) = body
                        {
                            req = req.body(bytes.clone());
                        }

                        let send_fut = async {
                            match req.send().await {
                                Ok(resp) => {
                                    counters.responses_received =
                                        counters.responses_received.saturating_add(1);
                                    record_status(&mut counters, resp.status().as_u16());
                                    match consume_response_with_cap(resp, max_response_body_bytes)
                                        .await
                                    {
                                        BodyConsumeOutcome::Completed => {
                                            counters.responses_completed =
                                                counters.responses_completed.saturating_add(1);
                                        }
                                        BodyConsumeOutcome::Truncated => {
                                            counters.responses_truncated =
                                                counters.responses_truncated.saturating_add(1);
                                        }
                                        BodyConsumeOutcome::StreamError => {
                                            counters.response_body_errors =
                                                counters.response_body_errors.saturating_add(1);
                                        }
                                    }
                                }
                                Err(err) => {
                                    // Classify without logging the raw reqwest error (URL/query
                                    // credentials must never reach structured logs).
                                    let _ = classify_reqwest_error(&err);
                                    counters.transport_errors =
                                        counters.transport_errors.saturating_add(1);
                                }
                            }
                        };

                        tokio::select! {
                            _ = worker_cancel.cancelled() => break,
                            result = tokio::time::timeout(attempt_timeout, send_fut) => {
                                if result.is_err() {
                                    counters.transport_errors =
                                        counters.transport_errors.saturating_add(1);
                                }
                            }
                        }
                    }

                    Ok::<WorkerCounters, ()>(counters)
                });

                handles.push(handle);
            }

            let mut totals = WorkerCounters::default();
            let mut worker_failures = 0u64;
            let mut cancelled_workers = 0u64;
            let mut aggregation_saturated = false;

            for handle in handles {
                match handle.await {
                    Ok(Ok(counters)) => {
                        aggregation_saturated |= counters.saturating_add_into(&mut totals);
                    }
                    Ok(Err(())) => {
                        worker_failures = worker_failures.saturating_add(1);
                    }
                    Err(join_err) => {
                        if join_err.is_cancelled() {
                            cancelled_workers = cancelled_workers.saturating_add(1);
                        } else {
                            worker_failures = worker_failures.saturating_add(1);
                        }
                    }
                }
            }

            let elapsed = start.elapsed();
            let cancelled = run_cancel.is_cancelled();
            let outcome = if cancelled {
                RunOutcome::Cancelled
            } else if totals.responses_completed == 0 || worker_failures > 0 {
                RunOutcome::Failed
            } else if totals.transport_errors > 0
                || totals.response_body_errors > 0
                || totals.responses_truncated > 0
                || cancelled_workers > 0
                || aggregation_saturated
                || totals.status_4xx > 0
                || totals.status_5xx > 0
            {
                RunOutcome::Degraded
            } else {
                RunOutcome::Success
            };

            let completed_rps = if elapsed.as_secs_f64() > 0.0 {
                totals.responses_completed as f64 / elapsed.as_secs_f64()
            } else {
                0.0
            };
            let attempted_rps = if elapsed.as_secs_f64() > 0.0 {
                totals.attempted_requests as f64 / elapsed.as_secs_f64()
            } else {
                0.0
            };

            let result = RunResult {
                outcome,
                attempted_requests: totals.attempted_requests,
                responses_received: totals.responses_received,
                responses_completed: totals.responses_completed,
                responses_truncated: totals.responses_truncated,
                response_body_errors: totals.response_body_errors,
                transport_errors: totals.transport_errors,
                status_2xx: totals.status_2xx,
                status_3xx: totals.status_3xx,
                status_4xx: totals.status_4xx,
                status_5xx: totals.status_5xx,
                status_other: totals.status_other,
                worker_failures,
                cancelled_workers,
                aggregation_saturated,
                elapsed_ms: elapsed.as_millis().min(u128::from(u64::MAX)) as u64,
            };

            info!(
                proxy = %proxy_name,
                outcome = ?result.outcome,
                attempted_requests = result.attempted_requests,
                responses_received = result.responses_received,
                responses_completed = result.responses_completed,
                responses_truncated = result.responses_truncated,
                response_body_errors = result.response_body_errors,
                transport_errors = result.transport_errors,
                status_2xx = result.status_2xx,
                status_3xx = result.status_3xx,
                status_4xx = result.status_4xx,
                status_5xx = result.status_5xx,
                status_other = result.status_other,
                worker_failures = result.worker_failures,
                cancelled_workers = result.cancelled_workers,
                aggregation_saturated = result.aggregation_saturated,
                elapsed_seconds = %format_args!("{:.2}", elapsed.as_secs_f64()),
                completed_requests_per_second = %format_args!("{:.1}", completed_rps),
                attempted_requests_per_second = %format_args!("{:.1}", attempted_rps),
                max_response_body_bytes = max_response_body_bytes,
                "load_testing: load test finished"
            );

            state.end_run(result);
        });

        if is_fanout {
            fanout_ack_result()
        } else {
            PluginResult::Continue
        }
    }
}

struct ProcessClientBudget {
    count: u64,
}

impl ProcessClientBudget {
    fn new(count: u64) -> Self {
        Self { count }
    }
}

impl Drop for ProcessClientBudget {
    fn drop(&mut self) {
        release_process_clients(self.count);
    }
}

fn fanout_ack_result() -> PluginResult {
    PluginResult::Reject {
        status_code: 204,
        body: String::new(),
        headers: HashMap::new(),
    }
}

fn filter_outbound_headers(
    headers: &HashMap<String, String>,
    keep_trigger_key: bool,
) -> Vec<(String, String)> {
    headers
        .iter()
        .filter(|(k, _)| {
            let name = k.as_str();
            if name == HEADER_FANOUT {
                return false;
            }
            if name == HEADER_TRIGGER_KEY {
                return keep_trigger_key;
            }
            if is_backend_request_strip_header(name) || is_proxy_generated_forwarding_header(name) {
                return false;
            }
            true
        })
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

fn method_allows_body(method: &str) -> bool {
    !matches!(
        method.to_ascii_uppercase().as_str(),
        "GET" | "HEAD" | "DELETE" | "OPTIONS" | "TRACE"
    )
}

fn record_status(counters: &mut WorkerCounters, status: u16) {
    match status {
        200..=299 => counters.status_2xx = counters.status_2xx.saturating_add(1),
        300..=399 => counters.status_3xx = counters.status_3xx.saturating_add(1),
        400..=499 => counters.status_4xx = counters.status_4xx.saturating_add(1),
        500..=599 => counters.status_5xx = counters.status_5xx.saturating_add(1),
        _ => counters.status_other = counters.status_other.saturating_add(1),
    }
}

/// Build a full URL from a base URL, path, and the original raw query string.
fn build_url(base: &str, path: &str, raw_query: Option<&str>) -> String {
    let query_len = raw_query.map(|q| q.len() + 1).unwrap_or(0);
    let mut url = String::with_capacity(base.len() + path.len() + query_len);
    url.push_str(base);
    url.push_str(path);
    if let Some(query) = raw_query.filter(|q| !q.is_empty()) {
        url.push('?');
        url.push_str(query);
    }
    url
}

fn build_request(
    client: &reqwest::Client,
    method: &str,
    url: &str,
    headers: &[(String, String)],
) -> reqwest::RequestBuilder {
    let mut req = match method {
        "GET" => client.get(url),
        "POST" => client.post(url),
        "PUT" => client.put(url),
        "DELETE" => client.delete(url),
        "PATCH" => client.patch(url),
        "HEAD" => client.head(url),
        _ => client.request(
            reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::GET),
            url,
        ),
    };

    for (k, v) in headers {
        req = req.header(k.as_str(), v.as_str());
    }

    req
}

async fn consume_response_with_cap(resp: reqwest::Response, max_bytes: u64) -> BodyConsumeOutcome {
    let mut stream = resp.bytes_stream();
    let mut consumed: u64 = 0;
    while let Some(chunk_result) = stream.next().await {
        match chunk_result {
            Ok(chunk) => {
                consumed = consumed.saturating_add(chunk.len() as u64);
                if consumed >= max_bytes {
                    return BodyConsumeOutcome::Truncated;
                }
            }
            Err(_) => return BodyConsumeOutcome::StreamError,
        }
    }
    BodyConsumeOutcome::Completed
}
