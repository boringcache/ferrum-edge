//! Request Mirror Plugin
//!
//! Duplicates live proxy traffic to a secondary destination for shadow testing,
//! validation, or migration checks without affecting client responses. Mirrored
//! requests are fire-and-forget — the gateway does not wait for the mirror
//! target's response and never propagates mirror failures to the client.
//!
//! Similar to APISIX's `proxy-mirror` plugin.
//!
//! ## How it works
//!
//! During the `before_proxy` phase (after all request transforms), the plugin
//! captures the request method, path, query string, headers, and optionally the
//! body, then spawns an async task to replay the request against the configured
//! mirror destination. The main request proceeds immediately — mirror latency
//! has zero impact on client response time.
//!
//! Multiple independent `request_mirror` instances on one proxy each dispatch
//! and each push their own result receiver onto a per-request collection. A
//! later instance never overwrites an earlier one. Transaction logging emits
//! one `mirror: true` summary per dispatched instance, attributable by plugin
//! config id and query-stripped destination URL. Sampled-out work leaves no
//! record; concurrency-limit rejection still publishes an explicit per-instance
//! failure (preserving prior observability).
//!
//! Outbound mirror headers cross the same canonical secondary-request boundary
//! as primary backend dispatch (Connection-listed hop-by-hop, Trailer, framing,
//! Ferrum request-only markers, and proxy-owned `X-Forwarded-*`). Forwarding
//! identity is stripped rather than regenerated. Off-mesh mirrors omit client
//! `Host` so authority comes from the mirror URL. When `mesh_route_dispatch`
//! has already matched the request, the mirror instead applies Istio/Envoy
//! shadow Host/:authority semantics: dial and validate the configured mirror
//! destination, but set Host to the selected (rewritten) authority with a
//! `-shadow` suffix. Native gRPC content-types re-synthesise `te: trailers` for
//! HTTP/2-capable mirror targets. Native gRPC mirrors dial through
//! `PluginHttpClient::get_http2` (h2c prior knowledge for cleartext `http`
//! targets, ALPN `h2` for `https`); ordinary HTTP mirrors keep the default
//! all-version client so HTTP/1.1 destinations continue to work. The
//! request-target prefers the original raw query (after the same auth
//! credential strips the primary backend uses) so duplicate keys, order, flags,
//! `+`, percent escapes, and encoded bytes match the primary contract.
//!
//! Path selection precedence when building the mirror URL:
//! 1. explicit plugin `mirror_path` (operator override; wins)
//! 2. else mesh `route_override_path` when set (final selected/rebased URI;
//!    read without consuming the override primary dispatch still needs)
//! 3. else the backend-effective authorized path when backend-path policy is
//!    active
//! 4. else the original request path
//!
//! The mirror request uses the gateway's shared `PluginHttpClient`, which means
//! it inherits the gateway's DNS cache, connection pool keepalive, TLS
//! settings (CA bundle, skip-verify), egress screening, and redacted logging.
//!
//! ## Mirror response logging
//!
//! The spawned task captures mirror response metadata (status code, response
//! size, latency) and writes it to a `tokio::sync::watch` channel. Transaction
//! logging consumes that channel from a separate detached task for the mirror
//! task's full configured lifetime, so late results remain visible without
//! delaying the client response. The channel is seeded with a sanitized task
//! failure fallback; concurrency drops are published as completed failures.
//!
//! Mirror timeout defaults to the proxy's `backend_read_timeout_ms`, ensuring
//! shadow requests respect the same timeout budget as the real backend call.
//!
//! ## Configuration
//!
//! ```json
//! {
//!   "mirror_host": "mirror.example.com",
//!   "mirror_port": 8080,
//!   "mirror_protocol": "https",
//!   "mirror_path": "/shadow",
//!   "percentage": 100.0,
//!   "mirror_request_body": true,
//!   "max_response_body_bytes": 1048576
//! }
//! ```
//!
//! | Field | Type | Default | Description |
//! |-------|------|---------|-------------|
//! | `mirror_host` | string | **(required)** | Hostname or IP of the mirror target |
//! | `mirror_port` | u16 | 80 (http) / 443 (https) | Port of the mirror target |
//! | `mirror_protocol` | string | `"http"` | `"http"` or `"https"` |
//! | `mirror_path` | string | (none) | Override the request path for the mirror. Must start with `/` and cannot contain a query or fragment. When unset, prefers the mesh route rewrite path when present; otherwise the backend-effective authorized path if backend-path policy is active; otherwise the original request path |
//! | `percentage` | f64 | `100.0` | Percentage of requests to mirror (0.0–100.0). Deterministic evenly spaced sampling at 0.1% granularity (see sampling notes below) |
//! | `mirror_request_body` | bool | `true` | Whether to include the request body in the mirror request |
//! | `max_response_body_bytes` | u64 | `1048576` (1 MiB) | Cap on bytes read from a mirror response when sizing it (only consulted when the response has no `content-length`). Streaming aborts as soon as the limit is crossed; mirror task discards the bytes after sizing. |
//! | `max_in_flight` | u64 | `256` | Maximum concurrent detached mirror tasks per plugin instance (minimum 1). Requests that arrive while every permit is in use are still served normally but are not mirrored — saturation drops the new mirror attempt without affecting the primary request. |
//!
//! ## Percentage sampling
//!
//! Sampling is **deterministic and evenly spaced** (Bresenham / dithered
//! accumulator), not randomized and not a contiguous prefix of each 1,000-request
//! window. Configuration is quantized to tenths of a percent: the effective
//! threshold is `round(percentage × 10)` clamped to `0..=1000`.
//!
//! - `0%` (threshold 0) never selects; the phase accumulator is not advanced.
//! - `100%` (threshold 1000) always selects; the phase accumulator is not advanced.
//! - Otherwise each eligible request adds `threshold` to a phase in `0..1000`.
//!   When the sum reaches or exceeds `1000`, that request is mirrored and the
//!   phase wraps by subtracting `1000`. Every complete 1,000-request cycle
//!   therefore mirrors exactly `threshold` requests, spaced with gaps of
//!   `floor(1000/threshold)` or `ceil(1000/threshold)`.
//!
//! **Construction / reload:** each plugin instance starts with phase `0`. The
//! first selection is deferred until the accumulator crosses `1000`, so reload
//! does not reopen with a mirrored burst/prefix. Recreating the plugin (config
//! reload) resets the phase to `0`.
//!
//! **Concurrency:** selection uses a single `AtomicU64` phase with a lock-free
//! compare-exchange update (relaxed ordering). No per-request allocation, RNG,
//! formatting, or mutex. The sampler guarantees system-wide progress under
//! contention; an individual caller may retry after a competing update.
//!
//! **Wrap / exhaustion:** the phase is bounded to `0..1000` at every successful
//! update, so integer wraparound of an unbounded counter cannot occur, cannot
//! panic, and cannot bias a complete sampling cycle.

use async_trait::async_trait;
use serde_json::Value;
use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tracing::warn;
use url::{Host, form_urlencoded};

use super::load_testing::{HEADER_FANOUT, HEADER_TRIGGER_KEY};
use super::utils::response_body::{
    BoundedReadError, measure_response_body_bounded, parse_max_response_body_bytes,
};
use super::{MirrorResponseMeta, Plugin, PluginHttpClient, PluginResult, RequestContext};
use crate::proxy::headers::{
    SecondaryRequestHostPolicy, filter_secondary_request_headers,
    synthesize_grpc_te_trailers_if_needed,
};

/// Default cap on the size of mirror response bodies the gateway is willing
/// to read. The body is discarded — only its length is reported in mirror
/// metadata — so 1 MiB is plenty for the size-derivation use case while still
/// protecting against a misbehaving mirror endpoint streaming an unbounded
/// response over a fire-and-forget task.
const DEFAULT_MIRROR_MAX_RESPONSE_BODY_BYTES: usize = 1024 * 1024;
const DEFAULT_MAX_IN_FLIGHT_MIRRORS: usize = 256;
const MIRROR_TASK_INCOMPLETE_ERROR: &str =
    "mirror task ended before publishing a result (cancelled or failed)";
const MIRROR_CONCURRENCY_DROP_ERROR: &str =
    "mirror request dropped because max_in_flight limit was reached";

/// Sampling period for percentage decisions: threshold is tenths of a percent
/// in `0..=SAMPLE_PERIOD`, so each complete cycle of `SAMPLE_PERIOD` requests
/// mirrors exactly `threshold` of them when `0 < threshold < SAMPLE_PERIOD`.
const SAMPLE_PERIOD: u64 = 1000;

fn strip_query_params(url: &str) -> &str {
    url.split_once('?').map_or(url, |(base, _)| base)
}

fn mirror_failure_meta(
    plugin_id: Option<String>,
    target_url: String,
    error: &'static str,
) -> MirrorResponseMeta {
    MirrorResponseMeta {
        mirror_plugin_id: plugin_id,
        mirror_target_url: target_url,
        mirror_response_status_code: None,
        mirror_response_size_bytes: None,
        mirror_latency_ms: 0.0,
        mirror_error: Some(error.to_string()),
    }
}

/// Append Envoy/Istio's `-shadow` suffix to a Host/:authority value.
///
/// Matches Envoy's documented shadowing behavior (`cluster1` →
/// `cluster1-shadow`). The suffix is appended to the hostname portion when a
/// `:port` is present so `internal.example:8080` becomes
/// `internal.example-shadow:8080`; bare authorities and bracketed IPv6 hosts
/// without a port receive a simple trailing `-shadow`.
fn append_shadow_host_suffix(authority: &str) -> String {
    let host_end = if authority.starts_with('[') {
        authority
            .find(']')
            .map(|index| index + 1)
            .unwrap_or(authority.len())
    } else if let Some((host, port)) = authority.rsplit_once(':')
        && !host.is_empty()
        && !host.contains(':')
        && !port.is_empty()
        && port.bytes().all(|byte| byte.is_ascii_digit())
    {
        host.len()
    } else {
        authority.len()
    };

    let mut shadow = String::with_capacity(authority.len() + "-shadow".len());
    shadow.push_str(&authority[..host_end]);
    shadow.push_str("-shadow");
    shadow.push_str(&authority[host_end..]);
    shadow
}

fn request_host_header(headers: &HashMap<String, String>) -> Option<&str> {
    headers
        .iter()
        .find(|(name, _)| {
            name.eq_ignore_ascii_case("host") || name.eq_ignore_ascii_case(":authority")
        })
        .map(|(_, value)| value.as_str())
}

fn completed_mirror_result(
    meta: MirrorResponseMeta,
) -> tokio::sync::watch::Receiver<Option<MirrorResponseMeta>> {
    let (_tx, rx) = tokio::sync::watch::channel(Some(meta));
    rx
}

/// Quantize a configured percentage to the integer tenth-percent threshold
/// used by the deterministic sampler (`0..=1000`).
fn sample_threshold_from_percentage(percentage: f64) -> u64 {
    // `percentage` is already validated to `[0.0, 100.0]` at construction.
    let rounded = (percentage * 10.0).round();
    if rounded <= 0.0 {
        0
    } else if rounded >= 1000.0 {
        SAMPLE_PERIOD
    } else {
        rounded as u64
    }
}

pub struct RequestMirror {
    http_client: PluginHttpClient,
    /// Stable plugin-config resource id when constructed through the plugin
    /// cache / factory. Surfaced on mirror summaries for multi-instance
    /// attribution; never a secret.
    plugin_config_id: Option<String>,
    mirror_host: String,
    mirror_port: u16,
    mirror_protocol: String,
    mirror_path: Option<String>,
    /// `round(percentage × 10)` clamped to `0..=1000` (0.1% granularity).
    sample_threshold: u64,
    mirror_request_body: bool,
    /// Maximum number of bytes to read from the mirror response when deriving
    /// `mirror_response_size_bytes`. The body is discarded after measurement,
    /// so this only bounds memory usage for fire-and-forget mirror tasks
    /// against misbehaving sinks. Used only when the mirror response has no
    /// `content-length` header (the CL fast path doesn't read the body).
    max_response_body_bytes: usize,
    mirror_hostname: Option<String>,
    /// Bresenham phase accumulator in `0..SAMPLE_PERIOD` for evenly spaced
    /// deterministic percentage sampling. Reset to `0` on construction/reload.
    sample_phase: AtomicU64,
    /// Bounds concurrent mirror tasks to prevent unbounded background work.
    mirror_in_flight: Arc<tokio::sync::Semaphore>,
}

impl RequestMirror {
    #[allow(dead_code)] // direct/test construction; production factory supplies the config id
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        Self::new_with_config_id(config, http_client, None)
    }

    pub fn new_with_config_id(
        config: &Value,
        http_client: PluginHttpClient,
        plugin_config_id: Option<&str>,
    ) -> Result<Self, String> {
        if !config.is_object() {
            return Err("request_mirror: config must be an object".to_string());
        }

        let raw_mirror_host = optional_string(config, "mirror_host")?
            .filter(|s| !s.is_empty())
            .ok_or_else(|| "request_mirror: 'mirror_host' is required".to_string())?
            .to_ascii_lowercase();
        let (mirror_host, mirror_hostname) = parse_mirror_host(&raw_mirror_host)?;

        let mirror_protocol = optional_string(config, "mirror_protocol")?
            .unwrap_or_else(|| "http".to_string())
            .to_ascii_lowercase();

        if mirror_protocol != "http" && mirror_protocol != "https" {
            return Err(format!(
                "request_mirror: 'mirror_protocol' must be 'http' or 'https' (got '{}')",
                mirror_protocol
            ));
        }

        let default_port: u16 = if mirror_protocol == "https" { 443 } else { 80 };
        let mirror_port = optional_u64(config, "mirror_port")?
            .map(|p| {
                if p == 0 || p > 65535 {
                    Err(format!(
                        "request_mirror: 'mirror_port' must be 1–65535 (got {})",
                        p
                    ))
                } else {
                    Ok(p as u16)
                }
            })
            .transpose()?
            .unwrap_or(default_port);

        let mirror_path = optional_string(config, "mirror_path")?.filter(|s| !s.is_empty());
        if let Some(path) = &mirror_path
            && !path.starts_with('/')
        {
            return Err("request_mirror: 'mirror_path' must start with '/'".to_string());
        }
        if let Some(path) = &mirror_path
            && (path.contains('?') || path.contains('#'))
        {
            return Err(
                "request_mirror: 'mirror_path' must not contain a query or fragment".to_string(),
            );
        }

        let percentage = optional_f64(config, "percentage")?.unwrap_or(100.0);
        if !(0.0..=100.0).contains(&percentage) {
            return Err(format!(
                "request_mirror: 'percentage' must be 0.0–100.0 (got {})",
                percentage
            ));
        }
        let sample_threshold = sample_threshold_from_percentage(percentage);

        let mirror_request_body = optional_bool(config, "mirror_request_body")?.unwrap_or(true);

        let max_in_flight = optional_u64(config, "max_in_flight")?
            .map(|v| {
                if v == 0 {
                    Err("request_mirror: 'max_in_flight' must be >= 1".to_string())
                } else {
                    usize::try_from(v).map_err(|_| {
                        "request_mirror: 'max_in_flight' is too large for this platform".to_string()
                    })
                }
            })
            .transpose()?
            .unwrap_or(DEFAULT_MAX_IN_FLIGHT_MIRRORS);

        let max_response_body_bytes = parse_max_response_body_bytes(
            config,
            "request_mirror",
            "max_response_body_bytes",
            DEFAULT_MIRROR_MAX_RESPONSE_BODY_BYTES,
        )?;

        let plugin_config_id = match plugin_config_id {
            Some(id) if id.trim().is_empty() => {
                return Err("request_mirror: plugin_config_id must not be blank".to_string());
            }
            Some(id) => Some(id.trim().to_owned()),
            None => None,
        };

        Ok(Self {
            http_client,
            plugin_config_id,
            mirror_host,
            mirror_port,
            mirror_protocol,
            mirror_path,
            sample_threshold,
            mirror_request_body,
            max_response_body_bytes,
            mirror_hostname,
            // Phase 0 defers the first selection until the accumulator crosses
            // SAMPLE_PERIOD — construction/reload never opens with a mirrored prefix.
            sample_phase: AtomicU64::new(0),
            mirror_in_flight: Arc::new(tokio::sync::Semaphore::new(max_in_flight)),
        })
    }

    /// Effective sampling threshold in tenths of a percent (`0..=1000`).
    // This accessor exists for the external sampling contract tests. The
    // production request path reads the field directly in `should_mirror`.
    #[allow(dead_code)]
    pub(crate) fn sample_threshold_for_test(&self) -> u64 {
        self.sample_threshold
    }

    /// Current Bresenham phase in `0..SAMPLE_PERIOD`.
    // This accessor exists for the external sampling contract tests. The
    // production request path updates the atomic directly in `should_mirror`.
    #[allow(dead_code)]
    pub(crate) fn sample_phase_for_test(&self) -> u64 {
        self.sample_phase.load(Ordering::Relaxed)
    }

    /// Select the path segment for the mirror URL without consuming primary
    /// route overrides.
    ///
    /// Precedence: explicit `mirror_path` → mesh `route_override_path` →
    /// authorized backend path → original `ctx.path`.
    fn select_mirror_path<'a>(&'a self, ctx: &'a RequestContext) -> &'a str {
        if let Some(path) = self.mirror_path.as_deref() {
            return path;
        }
        if ctx.mesh_route_dispatch_matched
            && let Some(path) = ctx.route_override_path.as_deref()
        {
            return path;
        }
        ctx.authorized_backend_path().unwrap_or(&ctx.path)
    }

    /// Build the full mirror URL from the configured or gateway-selected path.
    ///
    /// Prefer the effective raw query string (original wire query after the same
    /// auth credential strips primary dispatch applies) so duplicate keys,
    /// ordering, flags, empty values, `+`, percent escapes, and non-ASCII
    /// encoded bytes survive. Fall back to the materialised `query_params` map
    /// only when no raw query is available (tests / already-decoded contexts).
    fn build_mirror_url(
        &self,
        original_path: &str,
        raw_query: Option<&str>,
        query_params: &HashMap<String, String>,
    ) -> String {
        let path = self.mirror_path.as_deref().unwrap_or(original_path);

        let mut url = String::with_capacity(
            self.mirror_protocol.len() + 3 + self.mirror_host.len() + 1 + 5 + path.len(),
        );
        url.push_str(&self.mirror_protocol);
        url.push_str("://");
        url.push_str(&self.mirror_host);
        url.push(':');
        let _ = write!(&mut url, "{}", self.mirror_port);
        url.push_str(path);

        if let Some(query) = raw_query {
            // `Some("")` is authoritative: an auth strip may have removed the
            // entire raw query, so falling back to the materialised map here
            // would reintroduce the credential.
            if !query.is_empty() {
                url.push('?');
                url.push_str(query);
            }
        } else if !query_params.is_empty() {
            url.push('?');
            let encoded: String = form_urlencoded::Serializer::new(String::new())
                .extend_pairs(query_params.iter())
                .finish();
            url.push_str(&encoded);
        }

        url
    }

    /// Should this request be mirrored (deterministic evenly spaced sampling)?
    ///
    /// See the module-level "Percentage sampling" section for phase/reset,
    /// concurrency, and wrap semantics.
    fn should_mirror(&self) -> bool {
        let threshold = self.sample_threshold;
        if threshold == 0 {
            return false;
        }
        if threshold >= SAMPLE_PERIOD {
            return true;
        }

        // Lock-free Bresenham: keep phase in [0, SAMPLE_PERIOD). Successful
        // updates always store `next < SAMPLE_PERIOD`, and `threshold` is at
        // most 999, so `current + threshold` stays far below u64::MAX and
        // cannot overflow or panic.
        let mut current = self.sample_phase.load(Ordering::Relaxed);
        loop {
            let sum = current + threshold;
            let (selected, next) = if sum >= SAMPLE_PERIOD {
                (true, sum - SAMPLE_PERIOD)
            } else {
                (false, sum)
            };
            match self.sample_phase.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return selected,
                Err(observed) => current = observed,
            }
        }
    }

    /// External-test probe for the real state-advancing sampler without
    /// widening the production API surface.
    #[allow(dead_code)]
    pub(crate) fn should_mirror_for_test(&self) -> bool {
        self.should_mirror()
    }
}

fn parse_mirror_host(raw_host: &str) -> Result<(String, Option<String>), String> {
    let host = raw_host.trim();
    if host.is_empty() {
        return Err("request_mirror: 'mirror_host' is required".to_string());
    }
    if host
        .chars()
        .any(|c| c.is_ascii_whitespace() || c.is_control())
        || host.contains("://")
        || host.contains(['/', '?', '#', '@'])
    {
        return Err(
            "request_mirror: 'mirror_host' must be a hostname or IP address without scheme, path, query, fragment, or credentials"
                .to_string(),
        );
    }

    let bracketed = host.starts_with('[') || host.ends_with(']');
    let host_for_ip = if let Some(inner) = host.strip_prefix('[').and_then(|s| s.strip_suffix(']'))
    {
        inner
    } else {
        host
    };

    if let Ok(ip) = host_for_ip.parse::<std::net::IpAddr>() {
        return Ok(match ip {
            std::net::IpAddr::V4(ip) => (ip.to_string(), None),
            std::net::IpAddr::V6(ip) => (format!("[{ip}]"), None),
        });
    }

    if bracketed || host.contains(':') {
        return Err(
            "request_mirror: 'mirror_host' must not include brackets or a port unless it is an IPv6 literal"
                .to_string(),
        );
    }

    match Host::parse(host) {
        Ok(Host::Domain(domain)) if !domain.is_empty() => {
            let hostname = domain.to_ascii_lowercase();
            Ok((hostname.clone(), Some(hostname)))
        }
        _ => {
            Err("request_mirror: 'mirror_host' must be a valid hostname or IP address".to_string())
        }
    }
}

fn optional_bool(config: &Value, key: &str) -> Result<Option<bool>, String> {
    match config.get(key) {
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(format!("request_mirror: '{key}' must be a boolean")),
    }
}

fn optional_f64(config: &Value, key: &str) -> Result<Option<f64>, String> {
    match config.get(key) {
        Some(Value::Number(value)) => value
            .as_f64()
            .map(Some)
            .ok_or_else(|| format!("request_mirror: '{key}' must be a number")),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(format!("request_mirror: '{key}' must be a number")),
    }
}

fn optional_string(config: &Value, key: &str) -> Result<Option<String>, String> {
    match config.get(key) {
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(format!("request_mirror: '{key}' must be a string")),
    }
}

fn optional_u64(config: &Value, key: &str) -> Result<Option<u64>, String> {
    match config.get(key) {
        Some(Value::Number(value)) => value
            .as_u64()
            .map(Some)
            .ok_or_else(|| format!("request_mirror: '{key}' must be an unsigned integer")),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(format!(
            "request_mirror: '{key}' must be an unsigned integer"
        )),
    }
}

#[async_trait]
impl Plugin for RequestMirror {
    fn name(&self) -> &str {
        "request_mirror"
    }

    fn priority(&self) -> u16 {
        super::priority::REQUEST_MIRROR
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::HTTP_GRPC_PROTOCOLS
    }

    fn requires_request_body_before_before_proxy(&self) -> bool {
        self.mirror_request_body
    }

    fn should_buffer_request_body(&self, _ctx: &RequestContext) -> bool {
        self.mirror_request_body
    }

    fn needs_request_body_bytes(&self) -> bool {
        self.mirror_request_body
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        self.mirror_hostname.iter().cloned().collect()
    }

    fn defer_before_proxy_until_backend_path_resolved(&self) -> bool {
        true
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        if ctx
            .metadata
            .get("ai_stream_router_claimed")
            .map(String::as_str)
            == Some("true")
        {
            return PluginResult::Continue;
        }
        if !self.should_mirror() {
            return PluginResult::Continue;
        }

        // Mirror the final route-selected path without consuming the override
        // that primary dispatch still needs. An explicit operator mirror_path
        // remains authoritative.
        let mirror_path = self.select_mirror_path(ctx);
        // Match primary backend query construction: start from the retained raw
        // query, then apply auth credential strips marked on the context.
        // Decoded `request_transformer` query-map mutations are intentionally
        // not re-serialized here — primary dispatch likewise keeps the raw
        // (auth-stripped) wire query.
        let query_map_was_transformed = ctx
            .metadata
            .contains_key(crate::proxy::QUERY_PARAMS_TRANSFORMED_METADATA_KEY);
        let effective_query = match ctx.raw_query_string() {
            Some(raw) => Some(crate::proxy::query_string_after_plugin_strips(ctx, raw)),
            // Query-transformer map mutations are intentionally not serialized
            // by primary dispatch. Preserve that contract even when the client
            // supplied no original query, while retaining the legacy map
            // fallback for synthetic/test contexts with no transform marker.
            None if query_map_was_transformed => Some(Cow::Borrowed("")),
            None => None,
        };
        let mirror_url =
            self.build_mirror_url(mirror_path, effective_query.as_deref(), &ctx.query_params);
        let method = ctx.method.clone();

        // Mirror destinations are an egress boundary just like the primary
        // backend. Apply the canonical secondary-request sanitizer (hop-by-hop,
        // Connection-listed, framing, proxy-owned forwarding identity, Host
        // strip) before any mirror-specific exclusions.
        let mesh_shadow_host = if ctx.mesh_route_dispatch_matched {
            ctx.route_override_authority
                .as_deref()
                .or_else(|| request_host_header(headers))
                .filter(|authority| !authority.is_empty())
                .map(append_shadow_host_suffix)
        } else {
            None
        };
        let mut mirror_headers = filter_secondary_request_headers(
            headers,
            SecondaryRequestHostPolicy::Strip,
            &[HEADER_TRIGGER_KEY, HEADER_FANOUT],
        );
        if let Some(shadow_host) = mesh_shadow_host {
            // Keep the configured mirror URL as the dial/TLS identity. Only
            // the application Host/:authority follows Envoy's route-local
            // shadow contract.
            mirror_headers.push(("host".to_string(), shadow_host));
        }
        // gRPC mirrors need `te: trailers` after the generic strip removes `te`.
        synthesize_grpc_te_trailers_if_needed(&mut mirror_headers);
        let is_native_grpc = mirror_headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("content-type")
                && crate::proxy::backend_dispatch::is_native_grpc_content_type(value.as_bytes())
        });

        // Apply the operator-configured baggage strip
        // (`FERRUM_MESH_EGRESS_STRIP_BAGGAGE_KEYS`) so mesh-internal identity
        // claims like `source.principal` don't leak to mirror analytics /
        // auditing services that the operator considers off-mesh.
        self.http_client
            .strip_egress_baggage_in_vec(&mut mirror_headers);

        // Strip query params before ANY logging of the mirror URL — it is built
        // from the original request's query string and can carry secrets
        // (`?access_token=`, `?api_key=`, `?sig=`). Computed here, before the
        // permit-exhaustion drop path, so every log site uses the stripped form
        // (the full `mirror_url` is still used for the actual mirror request).
        let mirror_url_for_log = strip_query_params(&mirror_url).to_string();

        let permit = match self.mirror_in_flight.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                warn!(
                    "request_mirror: dropping mirror request for {} {} because max_in_flight limit was reached",
                    method, mirror_url_for_log
                );
                ctx.push_mirror_result_rx(completed_mirror_result(mirror_failure_meta(
                    self.plugin_config_id.clone(),
                    mirror_url_for_log,
                    MIRROR_CONCURRENCY_DROP_ERROR,
                )));
                return PluginResult::Continue;
            }
        };

        // Capture request body if configured and available.
        // Uses the binary-safe `request_body_bytes` field (preserves non-UTF-8
        // payloads like gRPC protobuf), falling back to the UTF-8 metadata key.
        let body_bytes: Option<Vec<u8>> = if self.mirror_request_body {
            ctx.request_body_bytes
                .as_ref()
                .map(|b| b.to_vec())
                .or_else(|| {
                    ctx.metadata
                        .get("request_body")
                        .map(|b| b.as_bytes().to_vec())
                })
        } else {
            None
        };

        let mirror_timeout = ctx.matched_proxy.as_ref().and_then(|p| {
            if p.backend_read_timeout_ms > 0 {
                Some(Duration::from_millis(p.backend_read_timeout_ms))
            } else {
                None
            }
        });

        // Seed the channel with a sanitized failure result. The detached
        // collector waits for the task's update, but if the task is cancelled
        // or panics its sender closes and the fallback becomes the explicit
        // mirror outcome instead of disappearing from observability.
        let task_fallback = mirror_failure_meta(
            self.plugin_config_id.clone(),
            mirror_url_for_log.clone(),
            MIRROR_TASK_INCOMPLETE_ERROR,
        );
        let (tx, rx) = tokio::sync::watch::channel(Some(task_fallback));
        ctx.push_mirror_result_rx(rx);

        let http_client = self.http_client.clone();
        let max_response_body_bytes = self.max_response_body_bytes;
        let mirror_plugin_id = self.plugin_config_id.clone();

        // Fire-and-forget: spawn an async task to send the mirror request.
        // The main request proceeds immediately — mirror latency has zero
        // impact on client response time.
        tokio::spawn(async move {
            let _permit = permit;
            let start = std::time::Instant::now();

            // Native gRPC must speak HTTP/2 (h2c prior knowledge on cleartext,
            // ALPN h2 on TLS). Ordinary HTTP mirrors keep the default client so
            // HTTP/1.1 destinations continue to work.
            let outbound = if is_native_grpc {
                http_client.get_http2()
            } else {
                http_client.get()
            };

            let mut req_builder = match method.as_str() {
                "GET" => outbound.get(&mirror_url),
                "POST" => outbound.post(&mirror_url),
                "PUT" => outbound.put(&mirror_url),
                "DELETE" => outbound.delete(&mirror_url),
                "PATCH" => outbound.patch(&mirror_url),
                "HEAD" => outbound.head(&mirror_url),
                _ => outbound.request(
                    reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::GET),
                    &mirror_url,
                ),
            };

            if let Some(t) = mirror_timeout {
                req_builder = req_builder.timeout(t);
            }

            // Forward sanitized headers from the original (transformed) request.
            // The canonical secondary-request filter already removed hop-by-hop,
            // Connection-listed, framing, proxy-owned forwarding, and Host
            // fields.
            for (key, value) in &mirror_headers {
                req_builder = req_builder.header(key.as_str(), value.as_str());
            }

            if let Some(body) = body_bytes {
                req_builder = req_builder.body(body);
            }

            // Route through `execute_redacted` so the mirror URL used in logs
            // and the returned error string is the query-stripped
            // `mirror_url_for_log`, never the full `mirror_url`. The full URL is
            // built from the original request's query params and can carry
            // credentials (`?access_token=...`, `?api_key=...`, `?sig=...`); a
            // raw `reqwest::Error` renders the full request URL in its Display
            // output, so stringifying it into `mirror_error` would leak those
            // secrets to every logging sink. `execute_redacted` reduces the
            // transport error to an `ErrorClass` plus the stripped URL.
            let response = if is_native_grpc {
                http_client
                    .execute_http2_redacted(req_builder, "request_mirror", &mirror_url_for_log)
                    .await
            } else {
                http_client
                    .execute_redacted(req_builder, "request_mirror", &mirror_url_for_log)
                    .await
            };
            let (status_code, response_size, error_msg) = match response {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    // Derive response size from content-length when available (avoids
                    // reading the body). When absent, the body would otherwise be
                    // unbounded — a misbehaving mirror sink could exhaust gateway
                    // memory in a fire-and-forget task. Stream and bound by
                    // `max_response_body_bytes`, discarding the bytes after sizing.
                    let (size, body_error) = match resp.content_length() {
                        Some(cl) => (Some(cl), None),
                        None => match measure_response_body_bounded(resp, max_response_body_bytes)
                            .await
                        {
                            Ok(n) => (Some(n), None),
                            Err(BoundedReadError::LimitExceeded { read_so_far, .. }) => {
                                warn!(
                                    "request_mirror: response from {} truncated at {} bytes \
                                         (max_response_body_bytes = {})",
                                    mirror_url_for_log, read_so_far, max_response_body_bytes
                                );
                                (Some(read_so_far as u64), None)
                            }
                            Err(BoundedReadError::Stream(_)) => {
                                (None, Some("mirror response body stream failed".to_string()))
                            }
                        },
                    };
                    (Some(status), size, body_error)
                }
                Err(err) => {
                    // `err` is already sanitized by `execute_redacted`
                    // (ErrorClass + stripped URL); it never contains the query
                    // string. Use the same string for the log line and the
                    // structured `mirror_error` field.
                    warn!(
                        "request_mirror: failed to mirror {} {} → {}",
                        method, mirror_url_for_log, err
                    );
                    (None, None, Some(err))
                }
            };

            let elapsed = start.elapsed();

            let meta = MirrorResponseMeta {
                mirror_plugin_id,
                mirror_target_url: mirror_url_for_log,
                mirror_response_status_code: status_code,
                mirror_response_size_bytes: response_size,
                mirror_latency_ms: elapsed.as_secs_f64() * 1000.0,
                mirror_error: error_msg,
            };

            // Send to the watch channel. Transaction logging owns a detached
            // receiver for the task's full configured request lifetime, so a
            // late-but-valid result is not discarded at an unrelated cutoff.
            let _ = tx.send(Some(meta));
        });

        PluginResult::Continue
    }
}

#[cfg(test)]
mod tests {
    use super::{RequestMirror, parse_mirror_host, strip_query_params};
    use crate::plugins::PluginHttpClient;
    use serde_json::json;
    use std::collections::HashMap;

    #[test]
    fn strip_query_params_removes_sensitive_query_data() {
        assert_eq!(
            strip_query_params("https://mirror.example.com:8443/path?token=secret&sig=abc"),
            "https://mirror.example.com:8443/path"
        );
        assert_eq!(
            strip_query_params("https://mirror.example.com:8443/path"),
            "https://mirror.example.com:8443/path"
        );
    }

    #[test]
    fn parse_mirror_host_brackets_ipv6_for_url_authority() {
        assert_eq!(
            parse_mirror_host("2001:db8::10").unwrap(),
            ("[2001:db8::10]".to_string(), None)
        );
        assert_eq!(
            parse_mirror_host("[2001:db8::10]").unwrap(),
            ("[2001:db8::10]".to_string(), None)
        );
    }

    #[test]
    fn build_mirror_url_uses_bracketed_ipv6_authority() {
        let plugin = RequestMirror::new(
            &json!({
                "mirror_host": "2001:db8::10",
                "mirror_port": 8443,
                "mirror_protocol": "https"
            }),
            PluginHttpClient::default(),
        )
        .unwrap();
        let mut query_params = HashMap::new();
        query_params.insert("page".to_string(), "1".to_string());

        assert_eq!(
            plugin.build_mirror_url("/shadow", None, &query_params),
            "https://[2001:db8::10]:8443/shadow?page=1"
        );
        assert_eq!(
            plugin.build_mirror_url("/shadow", Some("tag=red&tag=blue&q=a+b"), &query_params),
            "https://[2001:db8::10]:8443/shadow?tag=red&tag=blue&q=a+b"
        );
    }

    #[test]
    fn build_mirror_url_preserves_raw_query_edge_cases_byte_for_byte() {
        let plugin = RequestMirror::new(
            &json!({ "mirror_host": "mirror.example", "mirror_port": 8080 }),
            PluginHttpClient::default(),
        )
        .unwrap();
        let collapsed = HashMap::from([("tag".to_string(), "only-one".to_string())]);
        for raw in [
            "tag=red&tag=blue",
            "b=1&a=2",
            "flag",
            "empty=",
            "q=a+b",
            "path=%2Froot&k=a%26b",
            "key=a%2Fb",
            "name=%E2%9C%93&q=%C3%A9",
            "tag=red&tag=blue&q=a+b&flag&empty=&path=%2Froot&key=a%2Fb&name=%E2%9C%93",
        ] {
            let url = plugin.build_mirror_url("/api", Some(raw), &collapsed);
            assert!(
                url.ends_with(&format!("?{raw}")),
                "raw query must be preserved exactly: got {url}"
            );
            assert!(
                !url.contains("only-one"),
                "lossy query map must not replace raw query: {url}"
            );
        }
    }
}
