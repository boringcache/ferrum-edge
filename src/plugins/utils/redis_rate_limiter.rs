//! Shared Redis-backed rate limiting client for plugins.
//!
//! When a rate limiting plugin is configured with `"sync_mode": "redis"`, it uses
//! this shared client to store counters in Redis instead of in-memory DashMaps.
//! This enables centralized rate limiting across multiple data plane instances.
//!
//! # Redis protocol compatibility
//!
//! Uses the standard Redis protocol (RESP), so it works with Redis, Valkey,
//! DragonflyDB, KeyDB, Garnet, or any RESP-compatible server running in
//! **single-endpoint (non-Cluster) topology**.
//!
//! # Topology: Redis Cluster is NOT supported
//!
//! This client builds a plain single-node [`redis::Client`]; the crate's
//! Cluster features are deliberately not enabled, so it cannot follow `MOVED` /
//! `ASK` redirections. Pointing a Redis-backed policy at a Cluster endpoint
//! would make every misdirected command fail, and an enforcement plugin that
//! silently treats those failures as "Redis is down" degrades a distributed
//! security policy into one independent budget per gateway process.
//!
//! The client therefore screens topology instead of hoping for the best:
//!
//! 1. **Proactively**, right after each connection is established, it issues
//!    `INFO CLUSTER` and refuses the connection when the server reports
//!    `cluster_enabled:1` ([`parse_cluster_enabled`]). Servers that do not
//!    implement `INFO` (or omit the field) are not rejected — they fall through
//!    to the reactive screen so ordinary RESP-compatible servers keep working.
//! 2. **Reactively**, any command answered with a Cluster-only error code
//!    (`MOVED`, `ASK`, `CROSSSLOT`, `CLUSTERDOWN`, `TRYAGAIN` — see
//!    [`is_cluster_topology_code`]) marks the endpoint permanently unusable.
//!    Enforcement primitives send `MULTI`/`EXEC` pipelines, so the redirection
//!    usually arrives as a per-command server error inside an aborted
//!    transaction rather than as the outer error's own code
//!    ([`is_cluster_topology_error`]).
//!
//! The proactive probe is bounded by the configured
//! `redis_connect_timeout_seconds` (no separate knob): a server can accept and
//! authenticate a connection and then never answer `INFO`, and an unbounded
//! screen would hang the first enforcement operation instead of refusing it. A
//! probe that times out (or fails at the transport) is an ordinary retryable
//! outage — **not** proof of Cluster topology — and the connection is discarded
//! unscreened rather than carrying a policy command
//! ([`TopologyScreen::ProbeFailed`]).
//!
//! Topology rejection is **terminal for the life of the client**: unlike an
//! outage it is not something a `PING` can clear (a Cluster node answers `PING`
//! happily while still redirecting every key), so the recovery checker never
//! restores availability. A configuration change rebuilds the client. The
//! terminal state is sticky *under concurrency* too: availability lives in one
//! `EnforcementAvailability` atomic whose "reachable" transition cannot win
//! against a rejection, so a connection, command, or recovery probe that
//! completes successfully after another task proved Cluster topology can neither
//! be published nor reported as success.
//!
//! Every key that one atomic operation touches is additionally placed in a
//! shared hash slot via [`RedisRateLimitClient::make_slot_key`], so the
//! multi-key sliding-window and datagram/byte transactions are slot-stable if
//! they are ever run against a sharded deployment.
//!
//! # Algorithm
//!
//! Uses a **two-window weighted approximation** for sliding window rate limiting:
//!
//! 1. Two fixed windows are maintained: the current window and the previous window.
//! 2. The effective count = `prev_count * (1 - elapsed_fraction) + current_count`.
//! 3. Window index and `elapsed_fraction` are derived from **one** epoch timestamp
//!    with subsecond precision, so even a one-second window decays continuously
//!    through `[0, 1)` instead of staying stuck at `0.0`.
//! 4. This provides smooth rate limiting without boundary bursts.
//!
//! This is the same approach used by Cloudflare, Kong, and Nginx — no Lua scripts,
//! just native Redis `INCR`/`GET`/`EXPIRE` commands pipelined for efficiency.
//!
//! # DNS
//!
//! When the gateway's `DnsCache` is available, Redis hostnames are resolved through
//! it — sharing the pre-warmed cache, TTL management, stale-while-revalidate, and
//! background refresh with all other gateway DNS lookups. The resolved IP is used
//! for non-TLS connections; TLS connections keep the original hostname for SNI but
//! pre-warm the DNS cache entry.
//!
//! Gateway DNS screening/resolution runs **before** the Redis connection-attempt
//! timeout begins. The configured timeout covers TCP connect, TLS handshake (when
//! enabled), and the Redis protocol handshake against the screened URL. For TLS
//! hostnames the redis crate may re-resolve at dial time (see the accepted
//! limitation on [`RedisConfig::url_with_resolved_ip`]); that crate-internal
//! resolution is inside the connection timeout.
//!
//! # TLS
//!
//! Supports TLS via `rediss://` URL scheme (note the double-s). CA verification
//! and skip-verify are inherited from the gateway-level TLS settings.
//!
//! # Resilience
//!
//! If Redis becomes unreachable, the client marks itself unavailable. A
//! background task periodically pings Redis to detect recovery. That task is
//! owned by this client: dropping the client aborts it so retired plugin
//! generations do not retain connections or keep pinging obsolete endpoints.
//!
//! What a *consumer* does while the client is unavailable is the consumer's
//! policy, not this client's: rate-limit plugins choose between failing closed
//! and local fallback through `redis_failure_policy` (see
//! [`crate::plugins::utils::rate_limit::RedisFailurePolicy`]), and
//! `request_deduplication` through `on_redis_unavailable`. Local fallback means
//! one independent enforcement domain per gateway process, so it is an explicit
//! opt-in rather than the default.
//!
//! # Connection pool
//!
//! `redis_pool_size` sizes a bounded set of multiplexed
//! [`redis::aio::ConnectionManager`] instances. Slots are established lazily on
//! first use, selected round-robin on the hot path (lock-free atomic counter),
//! and cleared together on reconnect failure so TLS/DNS screening and
//! availability state stay coherent across the pool.

use crate::dns::DnsCache;
use crate::tls::source::{CertSource, MaterialKind, load_material_blocking};
use arc_swap::ArcSwap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::task::AbortHandle;
use tracing::{info, warn};
use url::{Host, Url};

/// Clamp a TTL into the signed range redis-rs sends for `EXPIRE`.
///
/// A raw `as i64` cast of a TTL above `i64::MAX` wraps negative, and Redis
/// treats a zero/negative `EXPIRE` as an immediate `DEL` — every increment
/// would then delete its own counter and silently remove rate enforcement.
/// Callers already bound the window (see
/// [`crate::plugins::utils::rate_limit::MAX_RATE_LIMIT_WINDOW_SECONDS`]); this
/// is the last-line conversion guard.
fn expire_seconds(ttl_seconds: u64) -> i64 {
    i64::try_from(ttl_seconds).unwrap_or(i64::MAX).max(1)
}

/// Operational upper bound for Redis ConnectionManager pool slots per plugin.
///
/// Each slot owns an ArcSwap, a Tokio mutex, and may lazily establish one
/// multiplexed Redis TCP connection, so configuration must keep this value a
/// small operational cardinality rather than an unbounded allocation size.
pub const MAX_REDIS_POOL_SIZE: usize = 128;

/// Redis sliding-window index and elapsed fraction from a single epoch timestamp.
///
/// `elapsed_fraction` is always in `[0, 1)`: at an exact window boundary the
/// index advances and the fraction resets to `0.0`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RedisWindowProgress {
    pub index: u64,
    pub elapsed_fraction: f64,
}

/// Redis sync fields read from a plugin's root JSON object.
///
/// Callers that close their own root allowlist must include these keys (or an
/// equivalent union) so misspelled Redis/storage fields fail admission. This
/// shared parser intentionally does **not** reject unknown root keys itself:
/// every Redis-backed plugin mixes these fields with plugin-specific properties,
/// and an independent Redis-only allowlist would reject legitimate plugin keys
/// (for example `ttl_seconds` on `ai_semantic_cache` or `window_seconds` on
/// `rate_limiting`).
pub const REDIS_PLUGIN_CONFIG_KEYS: &[&str] = &[
    "sync_mode",
    "redis_url",
    "redis_tls",
    "redis_key_prefix",
    "redis_pool_size",
    "redis_connect_timeout_seconds",
    "redis_health_check_interval_seconds",
    "redis_username",
    "redis_password",
];

/// Configuration parsed from a plugin's JSON config for Redis connectivity.
///
/// TLS verification uses the gateway-level settings (`FERRUM_TLS_CA_BUNDLE_PATH`,
/// `FERRUM_TLS_NO_VERIFY`) rather than per-plugin overrides, ensuring all outbound
/// connections share a single CA trust chain.
#[derive(Clone)]
pub struct RedisConfig {
    /// Redis connection URL (e.g., `redis://host:6379/0` or `rediss://host:6380/0` for TLS).
    pub url: String,
    /// Enable TLS for the Redis connection. When true and the URL uses `redis://`,
    /// it is automatically upgraded to `rediss://`.
    pub tls: bool,
    /// Key prefix for all Redis keys.
    ///
    /// Rate-limit consumers default to
    /// `{FERRUM_NAMESPACE}:{plugin_name}:{plugin-config-id}` (for example
    /// `ferrum:rate_limiting:rl-public-api`) so independent policies of one
    /// plugin type never share counters. An explicit `redis_key_prefix` is the
    /// documented opt-in for a deliberately shared budget.
    pub key_prefix: String,
    /// Bounded pool size: number of multiplexed [`redis::aio::ConnectionManager`]
    /// instances established lazily and selected round-robin on the hot path.
    pub pool_size: usize,
    /// Effective Redis connection-attempt timeout in seconds.
    ///
    /// Passed into redis-rs [`redis::aio::ConnectionManagerConfig`] /
    /// [`redis::AsyncConnectionConfig`] (not only an outer `tokio::time::timeout`)
    /// so values above the crate's one-second default take effect. Covers TCP
    /// connect, TLS handshake when enabled, and Redis protocol handshake on
    /// cached, dedicated, and health-check paths. Gateway `DnsCache` screening
    /// happens before this timeout starts (see module-level DNS notes).
    pub connect_timeout_seconds: u64,
    /// Interval in seconds for health check pings when Redis is marked unavailable.
    pub health_check_interval_seconds: u64,
    /// Redis username for ACL-based authentication (Redis 6+).
    ///
    /// When set, the value is injected into the parsed connection info before the
    /// client connects, overriding any user-info component already present in
    /// [`RedisConfig::url`]. To prefer URL-embedded credentials, leave this `None`
    /// and encode the userinfo directly in the URL (e.g., `redis://user:pass@host`).
    pub username: Option<String>,
    /// Redis password for authentication.
    ///
    /// When set, the value is injected into the parsed connection info before the
    /// client connects, overriding any user-info component already present in
    /// [`RedisConfig::url`]. To prefer URL-embedded credentials, leave this `None`
    /// and encode the userinfo directly in the URL (e.g., `redis://:pass@host`).
    pub password: Option<String>,
}

/// Manual `Debug` so a stray `{:?}` of a config (or of any struct that embeds
/// one) cannot dump the ACL password or the URL-embedded userinfo into logs or
/// error text. The derived impl printed both verbatim.
impl std::fmt::Debug for RedisConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let marker = super::metadata_redaction::REDACTED_PLACEHOLDER;
        f.debug_struct("RedisConfig")
            .field("url", &self.redacted_url())
            .field("tls", &self.tls)
            .field("key_prefix", &self.key_prefix)
            .field("pool_size", &self.pool_size)
            .field("connect_timeout_seconds", &self.connect_timeout_seconds)
            .field(
                "health_check_interval_seconds",
                &self.health_check_interval_seconds,
            )
            .field("username", &self.username.as_ref().map(|_| marker))
            .field("password", &self.password.as_ref().map(|_| marker))
            .finish()
    }
}

impl RedisConfig {
    /// Log-safe rendering of [`RedisConfig::url`].
    ///
    /// `redis_url` is a documented place to encode Redis ACL credentials
    /// (`redis://user:pass@host`), so the raw string must never reach a tracing
    /// field, an error message, or an admin projection. Scheme, host, port, and
    /// database path are preserved because they are the diagnostics that make a
    /// connect failure actionable; userinfo is replaced and query/fragment data
    /// is removed.
    ///
    /// Cold path only (connect/health-check failure logging), so the allocation
    /// here never touches a proxy hot path.
    pub fn redacted_url(&self) -> String {
        redact_url_userinfo(&self.url)
    }

    /// Parse Redis configuration from a plugin's JSON config.
    ///
    /// Returns `Ok(None)` if `sync_mode` is absent or `"local"`, after
    /// validating every explicitly supplied Redis field.
    ///
    /// Unknown root keys are left for the calling plugin to reject against its
    /// own allowlist unioned with [`REDIS_PLUGIN_CONFIG_KEYS`]. This function
    /// only reads the Redis fields listed there and must not impose a
    /// caller-specific allowlist on unrelated plugins.
    pub fn from_plugin_config(
        config: &serde_json::Value,
        default_prefix: &str,
    ) -> Result<Option<Self>, String> {
        // Value-redacted: config objects can carry redis_url / redis_password, so
        // diagnostics name the accepted shape without echoing the rejected value.
        let object = config
            .as_object()
            .ok_or_else(|| "redis rate limiter config must be a JSON object".to_string())?;

        let sync_mode = parse_optional_string(object, "sync_mode")?
            .unwrap_or("local")
            .to_ascii_lowercase();
        let redis_enabled = match sync_mode.as_str() {
            "local" => false,
            "redis" => true,
            _ => {
                return Err(
                    "redis rate limiter: 'sync_mode' must be exactly 'local' or 'redis'"
                        .to_string(),
                );
            }
        };

        // Validate every explicitly supplied Redis field even in local mode.
        // This keeps latent configuration fail-closed: toggling sync_mode later
        // cannot suddenly activate a malformed URL, wrong scalar type, or zero
        // connection bound that admission previously ignored.
        let url = parse_optional_string(object, "redis_url")?;
        if let Some(url) = url {
            if url.is_empty() {
                return Err("redis rate limiter: 'redis_url' must be non-empty".to_string());
            }
            validate_redis_url(url)?;
        } else if redis_enabled {
            return Err(
                "redis rate limiter: 'redis_url' is required when sync_mode='redis'".to_string(),
            );
        }

        let tls = parse_optional_bool(object, "redis_tls")?.unwrap_or(false);
        let key_prefix = parse_optional_string(object, "redis_key_prefix")?
            .unwrap_or(default_prefix)
            .to_string();
        if key_prefix.is_empty() {
            return Err("redis rate limiter: 'redis_key_prefix' must be non-empty".to_string());
        }

        let pool_size = parse_optional_u64(object, "redis_pool_size")?.unwrap_or(4);
        if pool_size == 0 {
            return Err(
                "redis rate limiter: 'redis_pool_size' must be greater than zero".to_string(),
            );
        }
        let pool_size = usize::try_from(pool_size)
            .map_err(|_| "redis rate limiter: 'redis_pool_size' is too large".to_string())?;
        if pool_size > MAX_REDIS_POOL_SIZE {
            return Err(format!(
                "redis rate limiter: 'redis_pool_size' must be <= {MAX_REDIS_POOL_SIZE}"
            ));
        }

        let connect_timeout_seconds =
            parse_optional_u64(object, "redis_connect_timeout_seconds")?.unwrap_or(5);
        if connect_timeout_seconds == 0 {
            return Err(
                "redis rate limiter: 'redis_connect_timeout_seconds' must be greater than zero"
                    .to_string(),
            );
        }

        let health_check_interval_seconds =
            parse_optional_u64(object, "redis_health_check_interval_seconds")?.unwrap_or(5);
        if health_check_interval_seconds == 0 {
            return Err(
                "redis rate limiter: 'redis_health_check_interval_seconds' must be greater than zero"
                    .to_string(),
            );
        }

        let username = parse_optional_string(object, "redis_username")?.map(ToString::to_string);
        let password = parse_optional_string(object, "redis_password")?.map(ToString::to_string);

        if !redis_enabled {
            return Ok(None);
        }
        let url = url.ok_or_else(|| {
            "redis rate limiter: 'redis_url' is required when sync_mode='redis'".to_string()
        })?;

        Ok(Some(RedisConfig {
            url: url.to_string(),
            tls,
            key_prefix,
            pool_size,
            connect_timeout_seconds,
            health_check_interval_seconds,
            username,
            password,
        }))
    }

    /// Build the effective Redis URL, upgrading to TLS scheme if needed.
    fn effective_url(&self) -> String {
        if self.tls && self.url.starts_with("redis://") {
            self.url.replacen("redis://", "rediss://", 1)
        } else {
            self.url.clone()
        }
    }

    /// Extract the hostname from the Redis URL for DNS pre-warming.
    ///
    /// Parses the URL to extract just the hostname (no port, no scheme).
    /// Returns `None` if the URL cannot be parsed or uses an IP address directly.
    pub fn hostname(&self) -> Option<String> {
        let url = Url::parse(&self.effective_url()).ok()?;
        let host = normalized_url_hostname(&url)?;

        // Skip if it's already an IP address
        if host.parse::<std::net::IpAddr>().is_ok() {
            return None;
        }

        Some(host)
    }

    /// Parse the Redis URL host as a literal IP — the dual of [`hostname`], which
    /// returns `None` for literals. Strips URI brackets; returns `None` for
    /// hostnames. Used to screen a literal `redis_url` at dial time, since the
    /// hostname-based DNS-cache screen never sees it.
    fn literal_host_ip(&self) -> Option<std::net::IpAddr> {
        let url = Url::parse(&self.effective_url()).ok()?;
        let host = normalized_url_hostname(&url)?;
        host.strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(&host)
            .parse::<std::net::IpAddr>()
            .ok()
    }

    /// Build a Redis URL with a resolved IP address substituted for the hostname.
    ///
    /// For non-TLS connections, replacing the hostname with a resolved IP avoids
    /// the redis crate doing its own DNS resolution, ensuring all DNS goes through
    /// the gateway's shared cache.
    ///
    /// For TLS connections, the hostname must be preserved for SNI verification,
    /// so this returns the original URL unchanged.
    ///
    /// ACCEPTED LIMITATION (egress policy, `rediss://` hostnames): the resolved IP
    /// is NOT pinned for TLS hostnames because the `redis` crate derives the TLS
    /// server name from the URL host — pinning the IP would break SNI/cert
    /// verification, and the crate exposes no way to dial a chosen address while
    /// presenting a separate server name. `screen_redis_endpoint` has already
    /// screened the CURRENT resolution against the egress policy, but the Redis
    /// client re-resolves the hostname itself at connect/reconnect time outside
    /// the gateway DNS cache, so a hostname whose DNS rebinds to a blocked address
    /// between screen and dial could still be reached. This is a narrow TOCTOU
    /// that requires control of the operator's own Redis DNS (which already
    /// implies control of the gateway's resolver). Literal-IP `rediss://` and all
    /// `redis://` (plaintext) endpoints ARE pinned/screened. Closing the TLS-
    /// hostname gap requires a custom pinned TLS connector (abandoning the crate's
    /// ConnectionManager) and is deliberately out of scope — see PR #1933.
    pub(crate) fn url_with_resolved_ip(&self, resolved_ip: std::net::IpAddr) -> String {
        let url = self.effective_url();

        // Don't replace hostname for TLS — SNI needs the original hostname (see
        // the ACCEPTED LIMITATION note above on the residual rebinding gap).
        if url.starts_with("rediss://") {
            return url;
        }

        let mut parsed = match Url::parse(&url) {
            Ok(parsed) => parsed,
            Err(_) => return url,
        };

        if parsed.host_str().is_none() {
            return url;
        }

        if parsed.set_ip_host(resolved_ip).is_err() {
            return url;
        }

        parsed.to_string()
    }
}

/// Strip userinfo, query, and fragment from a connection URL, keeping
/// scheme/host/port/path.
///
/// Only `redis` / `rediss` URLs receive the diagnostic-preserving projection.
/// Any other parseable scheme (including opaque `data:` / `mailto:` values and
/// ordinary `http(s):` URLs that may carry secrets in the path) fails closed to
/// a bare marker — admin projections match by the `redis_url` key name, so a
/// non-Redis value must never be echoed as if it were a safe endpoint label.
///
/// Unparseable strings also fail closed: they cannot be proven credential-free,
/// and `redis_url` is only validated for `sync_mode: "redis"` plus explicitly
/// supplied values, so a caller can still hold a string this function has never
/// validated.
pub(crate) fn redact_url_userinfo(raw_url: &str) -> String {
    let Ok(mut parsed) = Url::parse(raw_url) else {
        return super::metadata_redaction::REDACTED_PLACEHOLDER.to_string();
    };
    match parsed.scheme() {
        "redis" | "rediss" => {}
        _ => return super::metadata_redaction::REDACTED_PLACEHOLDER.to_string(),
    }
    let has_userinfo = !parsed.username().is_empty() || parsed.password().is_some();
    let has_suffix = parsed.query().is_some() || parsed.fragment().is_some();
    if !has_userinfo && !has_suffix {
        // Return the original bytes rather than the parser's normalization, so
        // a credential-free value is never silently rewritten in an admin
        // projection or a log line.
        return raw_url.to_string();
    }
    if has_userinfo
        && (parsed.set_password(None).is_err() || parsed.set_username("redacted").is_err())
    {
        return super::metadata_redaction::REDACTED_PLACEHOLDER.to_string();
    }
    // Redis URLs may carry non-secret transport options in the query, but
    // arbitrary disabled/unvalidated plugin configs can also put credentials
    // there or in a fragment. Neither is needed to identify the destination.
    parsed.set_query(None);
    parsed.set_fragment(None);
    parsed.to_string()
}

fn validate_redis_url(raw_url: &str) -> Result<(), String> {
    // Never echo the rejected URL (or parse detail that might restate it): the
    // field can carry userinfo credentials, query tokens, or fragments.
    let parsed = Url::parse(raw_url).map_err(|_| {
        "redis rate limiter: 'redis_url' must be a valid URL with scheme redis or rediss"
            .to_string()
    })?;
    match parsed.scheme() {
        "redis" | "rediss" => {}
        _ => {
            return Err(
                "redis rate limiter: 'redis_url' scheme must be exactly 'redis' or 'rediss'"
                    .to_string(),
            );
        }
    }
    if !has_non_empty_authority(raw_url) || normalized_url_hostname(&parsed).is_none() {
        return Err("redis rate limiter: 'redis_url' must include a hostname".to_string());
    }
    Ok(())
}

fn has_non_empty_authority(raw_url: &str) -> bool {
    raw_url
        .split_once("://")
        .and_then(|(_, rest)| rest.split(['/', '?', '#']).next())
        .is_some_and(|authority| !authority.is_empty())
}

fn normalized_url_hostname(url: &Url) -> Option<String> {
    match url.host()? {
        Host::Domain(host) if !host.is_empty() => Some(host.to_string()),
        Host::Ipv4(host) => Some(host.to_string()),
        Host::Ipv6(host) => Some(host.to_string()),
        _ => None,
    }
}

fn parse_optional_string<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<Option<&'a str>, String> {
    object
        .get(field)
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| format!("redis rate limiter: '{field}' must be a string"))
        })
        .transpose()
}

fn parse_optional_bool(
    object: &serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<Option<bool>, String> {
    object
        .get(field)
        .map(|value| {
            value
                .as_bool()
                .ok_or_else(|| format!("redis rate limiter: '{field}' must be a boolean"))
        })
        .transpose()
}

fn parse_optional_u64(
    object: &serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<Option<u64>, String> {
    object
        .get(field)
        .map(|value| {
            value
                .as_u64()
                .ok_or_else(|| format!("redis rate limiter: '{field}' must be an integer"))
        })
        .transpose()
}

/// A Redis-backed rate limiter client shared across plugin instances.
///
/// Provides atomic counter operations for rate limiting using native Redis
/// commands (no Lua scripts). Automatically falls back to local mode when
/// Redis is unreachable and recovers when connectivity is restored.
///
/// When a `DnsCache` is provided, Redis hostnames are resolved through the
/// Outcome of screening + resolving the Redis endpoint through the gateway DNS
/// cache. The client NEVER dials an address the egress policy hasn't cleared, so
/// any screen failure fails closed to the in-memory limiter rather than handing
/// an unscreened host to the Redis crate's own resolver.
enum RedisEndpoint {
    /// A policy-screened URL to dial.
    Url(String),
    /// Host blocked by the backend egress policy. Fail closed and do NOT start
    /// the recovery checker — this is configuration, not a transient outage, so a
    /// config change (which rebuilds the client) is the only recovery.
    EgressDenied,
    /// The DNS cache could not resolve the host (resolver outage / misconfigured
    /// gateway DNS). Fail closed rather than dialing an unscreened address, but
    /// the background recovery checker may re-screen successfully later.
    ResolveFailed,
}

/// Failure classifying a Redis connection attempt after DNS screening succeeded.
enum ConnectAttemptError {
    Redis(redis::RedisError),
    Timeout,
}

/// Redis error codes that only a Cluster-mode server ever returns.
///
/// This client is not Cluster-aware (see the module-level topology notes), so
/// any of these proves the configured endpoint is a topology it cannot enforce
/// against — not a transient outage. Matching on the wire code rather than a
/// `redis::ErrorKind` variant keeps the check stable across crate versions and
/// also catches RESP-compatible servers that return the code as an extension
/// error.
///
/// `MASTERDOWN` is deliberately excluded: plain replication returns it too, and
/// it is a genuine (recoverable) availability failure.
pub fn is_cluster_topology_code(code: Option<&str>) -> bool {
    matches!(
        code,
        Some("MOVED" | "ASK" | "CROSSSLOT" | "CLUSTERDOWN" | "TRYAGAIN")
    )
}

/// Whether a failed command proves the endpoint is a Cluster, including
/// redirections that only appear *inside* an aggregated pipeline error.
///
/// The top-level code is not sufficient. Every enforcement primitive here sends
/// a `MULTI`/`EXEC` pipeline, and a Cluster node answers `MULTI` with `+OK` and
/// only then redirects the keyed commands at queue time. The client surfaces
/// that as one aborted-transaction error whose own code is `EXECABORT`, with the
/// `MOVED`/`ASK`/… replies carried as the per-command server errors. Classifying
/// on the outer code alone would read a proven Cluster as an ordinary outage —
/// recoverable, and a Cluster node answers recovery `PING`s perfectly well — so
/// the endpoint would never reach the terminal state the advisory requires.
pub fn is_cluster_topology_error(error: &redis::RedisError) -> bool {
    if is_cluster_topology_code(error.code()) {
        return true;
    }
    // `into_server_errors` consumes the error; `RedisError` is `Clone` and the
    // aggregated variants are `Arc`-backed, so this is a refcount bump.
    let Some(errors) = error.clone().into_server_errors() else {
        return false;
    };
    errors.iter().any(|(_, err)| is_cluster_topology_code(Some(err.code())))
}

/// Read `cluster_enabled` out of an `INFO CLUSTER` reply.
///
/// Returns `None` when the field is absent — the server may be a
/// RESP-compatible implementation that does not report it, and an absent field
/// must never be treated as proof of either topology. `Some(true)` is the only
/// value that rejects an endpoint, so the "unknown" case stays compatible.
pub fn parse_cluster_enabled(info: &str) -> Option<bool> {
    for line in info.lines() {
        let line = line.trim();
        let Some(value) = line.strip_prefix("cluster_enabled:") else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() {
            return None;
        }
        return Some(value != "0");
    }
    None
}

/// Encoded length of one logical Redis hash-tag component.
///
/// `%`, `{`, `}`, and `:` are escaped so the outer tag cannot be truncated by
/// caller-controlled braces and the `prefix:rate_key` boundary is injective.
fn slot_tag_component_len(value: &str) -> usize {
    value.chars().fold(0usize, |len, ch| {
        len.saturating_add(if matches!(ch, '%' | '{' | '}' | ':') {
            3
        } else {
            ch.len_utf8()
        })
    })
}

fn push_slot_tag_component(key: &mut String, value: &str) {
    for ch in value.chars() {
        match ch {
            '%' => key.push_str("%25"),
            '{' => key.push_str("%7B"),
            '}' => key.push_str("%7D"),
            ':' => key.push_str("%3A"),
            _ => key.push(ch),
        }
    }
}

/// Screen + resolve the Redis endpoint through the gateway DNS cache, NEVER
/// returning an unscreened address. Shared by the hot-path connect (`resolve_url`)
/// AND the background recovery checker so neither can hand an unscreened host to
/// the Redis crate's own resolver.
async fn screen_redis_endpoint(
    config: &RedisConfig,
    dns_cache: Option<&DnsCache>,
) -> RedisEndpoint {
    if let Some(dns_cache) = dns_cache
        && let Some(hostname) = config.hostname()
    {
        match dns_cache.resolve(&hostname, None, None).await {
            Ok(ip) => return RedisEndpoint::Url(config.url_with_resolved_ip(ip)),
            Err(e) => {
                if crate::dns::is_egress_policy_denial(&e) {
                    warn!(
                        hostname = %hostname,
                        error = %e,
                        "Redis host blocked by backend egress policy — centralized Redis unavailable"
                    );
                    return RedisEndpoint::EgressDenied;
                }
                // Fail CLOSED on ANY screen failure (resolver outage / misconfigured
                // gateway DNS), not just policy denials: handing the unscreened
                // hostname to the Redis client would let it re-resolve outside the
                // egress policy and possibly dial a denied address.
                warn!(
                    hostname = %hostname,
                    error = %e,
                    "DNS cache resolution failed for Redis host — centralized Redis unavailable; will retry"
                );
                return RedisEndpoint::ResolveFailed;
            }
        }
    }
    // A literal-IP `redis_url` never reaches the hostname screen above
    // (`hostname()` is None for literals), and the config-load Redis screen is
    // warning-only in database mode — so screen the literal here too.
    if let Some(dns_cache) = dns_cache
        && let Some(ip) = config.literal_host_ip()
        && let Some(reason) = dns_cache.backend_allow_ips().deny_reason(&ip)
    {
        warn!(
            redis_ip = %ip,
            reason,
            "Redis literal host blocked by backend egress policy — centralized Redis unavailable"
        );
        return RedisEndpoint::EgressDenied;
    }
    RedisEndpoint::Url(config.effective_url())
}

/// Verdict of the proactive `INFO CLUSTER` topology screen.
///
/// Three states, not a `bool`: "not proven to be a Cluster" and "could not be
/// screened at all" have opposite safety properties. The first keeps ordinary
/// RESP-compatible servers working; the second must never let a policy command
/// run on the unscreened connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TopologyScreen {
    /// Not proven to be a Cluster: the connection may serve policy operations.
    /// The reactive per-command screen still catches redirections.
    Usable,
    /// Provably an unsupported Cluster topology. Terminal for the client.
    ClusterProven,
    /// The probe itself did not complete — it timed out against the configured
    /// connect timeout, or the transport failed. This is an ordinary retryable
    /// availability failure and is **not** evidence of either topology, so the
    /// connection is discarded rather than used unscreened.
    ProbeFailed,
}

/// Classify an `INFO CLUSTER` payload. Only a reported `cluster_enabled` of
/// non-zero rejects; absent/unparseable stays [`TopologyScreen::Usable`] so a
/// RESP-compatible server that does not report the field keeps working.
fn screen_from_info_text(text: &str) -> TopologyScreen {
    match parse_cluster_enabled(text) {
        Some(true) => TopologyScreen::ClusterProven,
        _ => TopologyScreen::Usable,
    }
}

/// Classify a successful `INFO CLUSTER` reply of any RESP shape.
///
/// Queried as [`redis::Value`] rather than `String` so a server whose reply is
/// not a plain bulk string produces the compatible "unknown topology" verdict
/// instead of a client-side type error that the caller would have to interpret.
fn screen_from_info_value(value: &redis::Value) -> TopologyScreen {
    match value {
        redis::Value::BulkString(bytes) => match std::str::from_utf8(bytes) {
            Ok(text) => screen_from_info_text(text),
            // Non-UTF-8 INFO payload: unknown, not proof of either topology.
            Err(_) => TopologyScreen::Usable,
        },
        redis::Value::SimpleString(text) => screen_from_info_text(text),
        redis::Value::VerbatimString { text, .. } => screen_from_info_text(text),
        // An error carried inline as a value still proves topology by its code.
        redis::Value::ServerError(error) => {
            if is_cluster_topology_code(Some(error.code())) {
                TopologyScreen::ClusterProven
            } else {
                TopologyScreen::Usable
            }
        }
        // Any other reply shape is not proof of either topology.
        _ => TopologyScreen::Usable,
    }
}

/// Ask a freshly established connection whether it belongs to a Cluster-mode
/// server, under a hard `probe_timeout` deadline.
///
/// A server that rejects or does not implement `INFO` (restricted ACL, minimal
/// RESP implementation) yields [`TopologyScreen::Usable`]: the endpoint is not
/// *proven* to be a Cluster, and the reactive per-command screen still catches
/// redirections. An `INFO` answered with a Cluster-only error code is itself
/// proof. A server that accepts and authenticates the connection but never
/// answers `INFO`, or whose transport fails mid-probe, yields
/// [`TopologyScreen::ProbeFailed`] — bounded by `probe_timeout` so the first
/// enforcement operation refuses instead of hanging.
async fn screen_connection_topology(
    conn: &mut impl redis::aio::ConnectionLike,
    probe_timeout: Duration,
) -> TopologyScreen {
    let mut probe = redis::cmd("INFO");
    probe.arg("CLUSTER");
    match tokio::time::timeout(probe_timeout, probe.query_async::<redis::Value>(conn)).await {
        Ok(Ok(value)) => screen_from_info_value(&value),
        Ok(Err(error)) => {
            if is_cluster_topology_error(&error) {
                TopologyScreen::ClusterProven
            } else if error.code().is_some() {
                // The server *answered* with an error reply (unknown command,
                // restricted ACL, …). Retain compatibility: not proven Cluster.
                TopologyScreen::Usable
            } else {
                // No server error code: an I/O, protocol, or parse failure. The
                // endpoint was never screened, so it must not carry a command.
                TopologyScreen::ProbeFailed
            }
        }
        // Accepted and authenticated but never answered INFO.
        Err(_elapsed) => TopologyScreen::ProbeFailed,
    }
}

/// Recovery-probe failure for an endpoint proven to be an unsupported topology.
///
/// The recovery loop reports its outcome as a `RedisResult`, so a topology
/// rejection needs an error value. It is never surfaced to a client.
fn cluster_topology_probe_error() -> redis::RedisError {
    redis::RedisError::from((
        redis::ErrorKind::InvalidClientConfig,
        "Redis endpoint reports an unsupported topology (Redis Cluster)",
    ))
}

/// Recovery-probe failure for a topology screen that never completed — an
/// ordinary retryable outage, classified as I/O rather than a config fault.
fn incomplete_topology_probe_error() -> redis::RedisError {
    redis::RedisError::from((
        redis::ErrorKind::Io,
        "Redis topology screen did not complete during recovery",
    ))
}

/// Availability of centralized enforcement for one Redis client generation,
/// shared with the client's recovery checker and with failover health observers.
///
/// Deliberately **one** atomic rather than an `available: AtomicBool` plus a
/// separate `topology_unsupported: AtomicBool`. With two flags, every
/// "reachable" publication is a check-then-store: a connection, command, or
/// recovery probe that completed successfully can observe a not-yet-terminal
/// topology, then store `available = true` after another task proved Cluster
/// topology — resurrecting enforcement that must stay dead, and making a
/// failover observer advertise a false recovery. Folding both into one state
/// makes publishing "reachable" a single read-modify-write that simply cannot
/// win against a rejection, so terminal really is terminal.
///
/// Every read is one atomic load, so hot-path callers keep their O(1) check with
/// no locks.
pub(crate) struct EnforcementAvailability {
    state: AtomicU8,
}

impl EnforcementAvailability {
    /// Reachable: enforcement may be consulted.
    const REACHABLE: u8 = 0;
    /// Unreachable, but recoverable — the recovery checker may clear this.
    const UNREACHABLE: u8 = 1;
    /// Proven to be an unsupported topology. Sticky for this generation.
    const TOPOLOGY_TERMINAL: u8 = 2;

    fn new() -> Self {
        Self {
            state: AtomicU8::new(Self::REACHABLE),
        }
    }

    /// Semantic availability: enforcement may be consulted. False whenever the
    /// topology is terminal, by construction — a caller cannot forget to pair
    /// this load with a separate terminal check.
    pub(crate) fn is_available(&self) -> bool {
        self.state.load(Ordering::Acquire) == Self::REACHABLE
    }

    /// Whether the endpoint was rejected as an unsupported topology.
    fn is_topology_terminal(&self) -> bool {
        self.state.load(Ordering::Acquire) == Self::TOPOLOGY_TERMINAL
    }

    /// Atomically move to `target` unless the topology is already terminal.
    ///
    /// Returns whether the transition happened. A single read-modify-write is
    /// what makes the terminal state actually terminal: there is no window
    /// between "check the flag" and "store availability" for a rejection to slip
    /// into.
    fn transition_unless_terminal(&self, target: u8) -> bool {
        self.state
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current != Self::TOPOLOGY_TERMINAL).then_some(target)
            })
            .is_ok()
    }

    /// Publish "reachable" — but only if the topology is not terminal.
    ///
    /// Returns `false` when the state is (or concurrently became) terminal, in
    /// which case nothing was written. Callers treat `false` as a failed
    /// operation: a command that already mutated Redis is reported as an error
    /// so the consumer's failure policy applies, because over-counting one
    /// operation is safer than admitting traffic against a topology this client
    /// cannot enforce on.
    fn publish_reachable(&self) -> bool {
        self.transition_unless_terminal(Self::REACHABLE)
    }

    /// Mark enforcement unreachable, preserving a terminal topology rejection.
    fn mark_unreachable(&self) {
        self.transition_unless_terminal(Self::UNREACHABLE);
    }

    /// Reject the endpoint permanently. Returns `true` the first time only, so
    /// the operator diagnostic is emitted once per client generation rather than
    /// once per request.
    fn reject_topology(&self) -> bool {
        let previous = self.state.swap(Self::TOPOLOGY_TERMINAL, Ordering::AcqRel);
        previous != Self::TOPOLOGY_TERMINAL
    }

    /// Log-safe rendering for `Debug` (never carries endpoint or credentials).
    fn describe(&self) -> &'static str {
        match self.state.load(Ordering::Acquire) {
            Self::REACHABLE => "reachable",
            Self::TOPOLOGY_TERMINAL => "topology_unsupported",
            _ => "unreachable",
        }
    }
}

/// One lazily-established multiplexed ConnectionManager slot in the pool.
///
/// Hot-path reads are lock-free via [`ArcSwap`]. Slow-path establishment is
/// serialized per slot so distinct slots can connect in parallel without a
/// global mutex, while same-slot racers still double-check under the lock.
struct ConnectionSlot {
    connection: ArcSwap<Option<redis::aio::ConnectionManager>>,
    connect_mutex: tokio::sync::Mutex<()>,
}

/// Outcome of a size-bounded Redis fetch ([`RedisRateLimitClient::get_bytes_bounded`]).
#[derive(Debug)]
pub enum BoundedRedisValue {
    /// Key is absent.
    Missing,
    /// Key exists but holds an empty value. Callers must quarantine rather than
    /// treating this as a permanent miss that leaves the empty key in place.
    Empty,
    /// Value present and within the requested byte cap.
    Found(Vec<u8>),
    /// Value present but its true length exceeds the cap; only a bounded prefix
    /// was transferred. Callers should treat it as invalid and quarantine it.
    Oversized { length: usize },
}

/// Why a Redis `GETRANGE` inclusive end index cannot be derived from a byte cap.
///
/// Callers must fail closed on either variant: Redis treats a negative end as
/// "read to the end of the string", so an unrepresentable or zero cap must never
/// be cast into a sentinel that would transfer an attacker-controlled value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedisGetrangeEndIndexError {
    /// Cap was zero (no positive inclusive end index).
    ZeroCap,
    /// Cap cannot be represented as a non-negative `isize` on this platform.
    Overflow,
}

/// Convert a Redis `GETRANGE` inclusive end index from a byte cap.
///
/// Redis treats a negative end index as an offset from the end of the string
/// (`-1` = last byte / whole value). Casting an unbounded `usize` cap with
/// `as isize` can therefore saturate to `-1` and ask Redis for the entire
/// attacker-controlled value. Fail closed before dispatch when the cap cannot
/// be represented as a non-negative `isize`.
pub fn redis_getrange_end_index(max_bytes: usize) -> Result<isize, RedisGetrangeEndIndexError> {
    if max_bytes == 0 {
        return Err(RedisGetrangeEndIndexError::ZeroCap);
    }
    isize::try_from(max_bytes).map_err(|_| RedisGetrangeEndIndexError::Overflow)
}

/// gateway's shared DNS cache. On connection failure, every pool slot is cleared
/// so the next attempt re-resolves DNS (handling IP changes gracefully).
pub struct RedisRateLimitClient {
    /// Bounded pool of multiplexed ConnectionManagers (`redis_pool_size`).
    /// Each slot is established lazily on first selection.
    pool: Box<[ConnectionSlot]>,
    /// Round-robin counter for deterministic, low-overhead slot selection.
    /// `fetch_add` + `% pool.len()` — no locks, no hashing on the hot path.
    next_slot: AtomicUsize,
    /// Configuration for connecting to Redis.
    config: RedisConfig,
    /// The gateway's shared DNS cache for resolving Redis hostnames.
    dns_cache: Option<DnsCache>,
    /// Whether centralized enforcement is reachable, and whether the configured
    /// endpoint was proven to be an unsupported topology (Redis Cluster).
    ///
    /// One atomic so a topology rejection is terminal even when a successful
    /// connection, command, or recovery probe completes concurrently: a Cluster
    /// node answers `PING` while still redirecting every key, so nothing may
    /// restore availability afterwards. See [`EnforcementAvailability`].
    availability: Arc<EnforcementAvailability>,
    /// Whether the background health checker has been started.
    health_checker_started: AtomicBool,
    /// Abort handle for the background recovery checker (set once on start).
    health_checker_abort: Mutex<Option<AbortHandle>>,
    /// Gateway-level TLS no-verify setting (`FERRUM_TLS_NO_VERIFY`).
    tls_no_verify: bool,
    /// Pre-read CA bundle PEM bytes from `FERRUM_TLS_CA_BUNDLE_PATH`.
    /// Loaded once at construction to avoid filesystem reads on every connection.
    tls_ca_bundle_pem: Option<Vec<u8>>,
}

/// Pure floor-at-zero decision for [`RedisRateLimitClient::incrby_with_expire_floor_zero`].
///
/// Given the value observed after the primary `INCRBY`, return the compensating
/// `INCRBY` delta needed to bring the counter back up to exactly zero, or `None`
/// when the value is already non-negative (no compensation needed). The
/// compensation is exactly `-new_total` so the corrective write fails only in
/// the conservative (over-count) direction if a concurrent increment raced
/// between our write and read — a rate limiter must never under-count usage.
///
/// Extracted as a free function so the floor logic is unit-testable without a
/// live Redis server (the surrounding method is pure I/O).
fn floor_zero_compensation(new_total: i64) -> Option<i64> {
    if new_total >= 0 {
        None
    } else {
        Some(new_total.saturating_neg())
    }
}

/// Clamp the post-compensation total so callers never observe a negative usage,
/// even if a concurrent decrement drove the counter back below zero between the
/// compensating write and its read-back.
fn clamp_floored_total(floored: i64) -> i64 {
    floored.max(0)
}

impl RedisRateLimitClient {
    /// Create a new Redis rate limit client.
    ///
    /// The connection is established lazily on first use to avoid blocking
    /// the plugin constructor (which is synchronous).
    ///
    /// TLS settings are inherited from the gateway's global configuration
    /// (`FERRUM_TLS_CA_BUNDLE_PATH`, `FERRUM_TLS_NO_VERIFY`) so all outbound
    /// connections share a single CA trust chain.
    ///
    /// When `dns_cache` is provided, Redis hostnames are resolved through the
    /// gateway's shared DNS cache instead of the system resolver.
    pub fn new(
        config: RedisConfig,
        dns_cache: Option<DnsCache>,
        tls_no_verify: bool,
        tls_ca_bundle_path: Option<&str>,
    ) -> Self {
        let tls_ca_bundle_pem = if !tls_no_verify {
            tls_ca_bundle_path.and_then(|path| {
                let source = CertSource::parse(path, MaterialKind::CaBundle);
                match load_material_blocking(&source, MaterialKind::CaBundle) {
                    Ok(material) => Some(material.bytes.expose_secret().to_vec()),
                    Err(e) => {
                        warn!(
                            error = %e,
                            "Failed to load CA bundle for Redis TLS — using system root CAs"
                        );
                        None
                    }
                }
            })
        } else {
            None
        };

        Self {
            pool: (0..config.pool_size.max(1))
                .map(|_| ConnectionSlot {
                    connection: ArcSwap::from_pointee(None),
                    connect_mutex: tokio::sync::Mutex::new(()),
                })
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            next_slot: AtomicUsize::new(0),
            config,
            dns_cache,
            availability: Arc::new(EnforcementAvailability::new()),
            health_checker_started: AtomicBool::new(false),
            health_checker_abort: Mutex::new(None),
            tls_no_verify,
            tls_ca_bundle_pem,
        }
    }

    /// Whether Redis is currently available.
    ///
    /// This is an O(1) atomic load — safe to call on every request. An endpoint
    /// proven to be an unsupported topology is never available again, so a
    /// consumer's failure policy applies for the life of the client.
    pub fn is_available(&self) -> bool {
        self.availability.is_available()
    }

    /// Whether the configured endpoint was rejected as an unsupported topology.
    pub fn is_topology_unsupported(&self) -> bool {
        self.availability.is_topology_terminal()
    }

    /// Shared availability signal for failover observers that must not retain
    /// the full client (and its cached connections / credentials) after Drop.
    ///
    /// Semantic, not raw: [`EnforcementAvailability::is_available`] cannot read
    /// `true` while the topology is terminal, so an observer can never advertise
    /// a recovery for an endpoint this client refused.
    pub(crate) fn availability_signal(&self) -> Arc<EnforcementAvailability> {
        Arc::clone(&self.availability)
    }

    /// Mark Redis unavailable and start the recovery checker (test support).
    #[allow(dead_code)] // public support used by the external unit-test target
    pub fn mark_unavailable_for_test(&self) {
        self.mark_unavailable();
        self.start_health_checker_if_needed();
    }

    /// Prove an unsupported Cluster topology the way a racing task would
    /// (test support), so concurrency coverage can land the rejection at an
    /// exact point in another operation's lifecycle.
    #[allow(dead_code)] // public support used by the external unit-test target
    pub fn mark_topology_unsupported_for_test(&self) {
        self.mark_topology_unsupported("test-injected cluster topology proof");
    }

    /// What a failover health observer reads from this client's shared
    /// availability signal — the same `Arc` the observer holds (test support).
    #[allow(dead_code)] // public support used by the external unit-test target
    pub fn observer_sees_available_for_test(&self) -> bool {
        self.availability_signal().is_available()
    }

    /// Whether the background recovery checker has been started (test support).
    #[allow(dead_code)] // public support used by the external unit-test target
    pub fn health_checker_started_for_test(&self) -> bool {
        self.health_checker_started.load(Ordering::Relaxed)
    }

    /// Abort handle for the background recovery checker, when started (tests).
    #[allow(dead_code)] // public support used by the external unit-test target
    pub fn health_checker_abort_for_test(&self) -> Option<AbortHandle> {
        self.health_checker_abort
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Configured pool cardinality (`redis_pool_size`).
    #[allow(dead_code)] // public support used by the external unit-test target
    pub fn pool_size_for_test(&self) -> usize {
        self.pool.len()
    }

    /// Number of pool slots that currently hold an established ConnectionManager.
    #[allow(dead_code)] // public support used by the external unit-test target
    pub fn cached_pool_cardinality_for_test(&self) -> usize {
        self.pool
            .iter()
            .filter(|slot| slot.connection.load().is_some())
            .count()
    }

    /// Round-robin slot indexes that the next `count` hot-path selections would use.
    #[allow(dead_code)] // public support used by the external unit-test target
    pub fn select_slot_indexes_for_test(&self, count: usize) -> Vec<usize> {
        (0..count).map(|_| self.select_slot_index()).collect()
    }

    /// Lazily establish every pool slot. Returns how many slots connected.
    #[allow(dead_code)] // public support used by the external unit-test target
    pub async fn warm_pool_for_test(&self) -> usize {
        let mut established = 0usize;
        for idx in 0..self.pool.len() {
            if self.get_or_connect_slot(idx).await.is_some() {
                established += 1;
            }
        }
        established
    }

    /// Clear every cached pool slot (same path as reconnect clearing).
    #[allow(dead_code)] // public support used by the external unit-test target
    pub fn clear_pool_for_test(&self) {
        self.clear_connection();
    }

    /// Establish (or reuse) one round-robin ConnectionManager for tests.
    #[allow(dead_code)] // public support used by the external integration-test target
    pub async fn connect_cached_for_test(&self) -> bool {
        self.get_connection().await.is_some()
    }

    /// Establish a dedicated non-reconnecting multiplexed connection for tests.
    #[allow(dead_code)] // public support used by the external integration-test target
    pub async fn connect_dedicated_for_test(&self) -> bool {
        self.get_dedicated_connection().await.is_some()
    }

    /// Type name of the concrete connection used by WATCH/MULTI/EXEC helpers.
    ///
    /// External tests assert this equals
    /// `type_name::<redis::aio::MultiplexedConnection>()` and does not name
    /// `ConnectionManager`. The production helper's return type is the
    /// compile-time pin; changing it back to ConnectionManager fails either
    /// this string check or the assignment in `get_dedicated_connection`.
    #[allow(dead_code)] // public support used by the external unit-test target
    pub fn dedicated_watch_connection_type_name_for_test() -> &'static str {
        std::any::type_name::<redis::aio::MultiplexedConnection>()
    }

    /// Run one health-check-style multiplexed connect+PING for tests.
    ///
    /// Uses the same Ferrum timeout wiring as the background recovery checker
    /// (inner `AsyncConnectionConfig` + defensive outer bound). DNS screening
    /// still happens first and remains outside the connection timeout.
    #[allow(dead_code)] // public support used by the external integration-test target
    pub async fn health_check_connect_for_test(&self) -> bool {
        let url = match self.resolve_url().await {
            RedisEndpoint::Url(url) => url,
            RedisEndpoint::EgressDenied | RedisEndpoint::ResolveFailed => return false,
        };
        let client = match self.build_client(&url) {
            Ok(client) => client,
            Err(_) => return false,
        };
        let connect_timeout = self.connect_timeout();
        let async_config = self.async_connection_config();
        let mut conn = match tokio::time::timeout(
            connect_timeout,
            client.get_multiplexed_async_connection_with_config(&async_config),
        )
        .await
        {
            Ok(Ok(conn)) => conn,
            Ok(Err(_)) | Err(_) => return false,
        };
        redis::cmd("PING")
            .query_async::<String>(&mut conn)
            .await
            .is_ok()
    }

    /// Connection-timeout duration installed into redis-rs configs (tests).
    #[allow(dead_code)] // public support used by the external integration-test target
    pub fn connection_timeout_for_test(&self) -> Duration {
        self.connect_timeout()
    }

    /// Manager-config connection timeout observed by redis-rs (tests).
    #[allow(dead_code)] // public support used by the external integration-test target
    pub fn connection_manager_timeout_for_test(&self) -> Option<Duration> {
        self.connection_manager_config().connection_timeout()
    }

    /// Deterministic round-robin index into the connection pool.
    fn select_slot_index(&self) -> usize {
        let len = self.pool.len();
        // pool.len() is always >= 1 (constructor uses pool_size.max(1); admission
        // rejects zero). Wrapping fetch_add keeps selection lock-free.
        self.next_slot.fetch_add(1, Ordering::Relaxed) % len
    }

    /// Resolve the Redis hostname via the gateway's DNS cache and build the
    /// connection URL with the resolved IP (for non-TLS) or the original
    /// hostname (for TLS, to preserve SNI).
    /// Resolve the Redis endpoint URL through the DNS cache, returning `None`
    /// when the host is blocked by the backend egress policy so the caller fails
    /// CLOSED (in-memory limiter) instead of dialing a denied address. A generic
    /// DNS failure still falls back to the hostname (the existing behavior).
    async fn resolve_url(&self) -> RedisEndpoint {
        screen_redis_endpoint(&self.config, self.dns_cache.as_ref()).await
    }

    /// Build a Redis client with proper TLS configuration.
    ///
    /// When TLS is enabled (`rediss://` URL), applies:
    /// - Custom CA bundle from `FERRUM_TLS_CA_BUNDLE_PATH` via `build_with_tls`
    /// - Skip-verify from `FERRUM_TLS_NO_VERIFY` via `#insecure` URL fragment
    ///
    /// ACL credentials from [`RedisConfig::username`] / [`RedisConfig::password`]
    /// are injected into the parsed [`redis::ConnectionInfo`] so that both the
    /// plain and TLS code paths perform `AUTH` / `HELLO` with the configured
    /// principal. When set, these fields override any user-info already encoded
    /// in [`RedisConfig::url`].
    pub(crate) fn build_client(&self, url: &str) -> Result<redis::Client, redis::RedisError> {
        let is_tls = url.starts_with("rediss://");

        // Parse the URL into ConnectionInfo so we can inject ACL credentials.
        // The URL parser already handles user:pass@host, db numbers, and the
        // #insecure fragment; we only override credentials when the operator
        // configured `redis_username` / `redis_password` explicitly.
        let conn_info_url = if is_tls && self.tls_no_verify && !url.contains('#') {
            // Append #insecure so the URL parser sets ConnectionAddr::TcpTls.insecure = true
            format!("{url}#insecure")
        } else {
            url.to_string()
        };

        let conn_info = self.build_connection_info(&conn_info_url)?;

        if is_tls && (self.tls_ca_bundle_pem.is_some() || self.tls_no_verify) {
            redis::Client::build_with_tls(
                conn_info,
                redis::TlsCertificates {
                    client_tls: None,
                    root_cert: self.tls_ca_bundle_pem.clone(),
                },
            )
        } else {
            redis::Client::open(conn_info)
        }
    }

    /// Parse a Redis URL into a [`redis::ConnectionInfo`] with ACL credentials
    /// from [`RedisConfig`] overriding any URL-embedded user-info.
    fn build_connection_info(&self, url: &str) -> Result<redis::ConnectionInfo, redis::RedisError> {
        use redis::IntoConnectionInfo;

        let mut conn_info = url.into_connection_info()?;

        if self.config.username.is_some() || self.config.password.is_some() {
            // Clone the parsed redis settings (preserves db number, protocol, etc.)
            // and override only the username/password before reinstalling them.
            let mut redis_settings = conn_info.redis_settings().clone();
            if let Some(username) = self.config.username.as_deref() {
                redis_settings = redis_settings.set_username(username);
            }
            if let Some(password) = self.config.password.as_deref() {
                redis_settings = redis_settings.set_password(password);
            }
            conn_info = conn_info.set_redis_settings(redis_settings);
        }

        Ok(conn_info)
    }

    /// Duration used as the effective Redis connection-attempt timeout.
    fn connect_timeout(&self) -> Duration {
        Duration::from_secs(self.config.connect_timeout_seconds)
    }

    /// redis-rs manager config carrying Ferrum's connection-attempt timeout.
    ///
    /// The crate default is one second; without this, outer `tokio::time::timeout`
    /// wrappers cannot extend attempts past that inner cap.
    fn connection_manager_config(&self) -> redis::aio::ConnectionManagerConfig {
        redis::aio::ConnectionManagerConfig::new()
            .set_connection_timeout(Some(self.connect_timeout()))
    }

    /// redis-rs async connection config carrying Ferrum's connection-attempt timeout.
    ///
    /// Used by the health-check path and by WATCH-transaction dedicated
    /// connections (plain [`redis::aio::MultiplexedConnection`], never a
    /// reconnecting [`redis::aio::ConnectionManager`]).
    fn async_connection_config(&self) -> redis::AsyncConnectionConfig {
        redis::AsyncConnectionConfig::new().set_connection_timeout(Some(self.connect_timeout()))
    }

    /// Establish a ConnectionManager with Ferrum's timeout on both the inner
    /// redis-rs config and a defensive outer `tokio::time::timeout` bound.
    async fn connect_manager(
        &self,
        client: redis::Client,
    ) -> Result<redis::aio::ConnectionManager, ConnectAttemptError> {
        let connect_timeout = self.connect_timeout();
        let manager_config = self.connection_manager_config();
        match tokio::time::timeout(
            connect_timeout,
            redis::aio::ConnectionManager::new_with_config(client, manager_config),
        )
        .await
        {
            Ok(Ok(manager)) => Ok(manager),
            Ok(Err(error)) => Err(ConnectAttemptError::Redis(error)),
            Err(_) => Err(ConnectAttemptError::Timeout),
        }
    }

    /// Establish a non-reconnecting multiplexed connection with Ferrum's timeout
    /// on both the inner redis-rs config and a defensive outer bound.
    ///
    /// Unlike [`Self::connect_manager`], this connection cannot transparently
    /// replace its physical TCP session mid-sequence, so connection-local
    /// `WATCH` state remains bound to the socket that observed it.
    async fn connect_multiplexed(
        &self,
        client: redis::Client,
    ) -> Result<redis::aio::MultiplexedConnection, ConnectAttemptError> {
        let connect_timeout = self.connect_timeout();
        let async_config = self.async_connection_config();
        match tokio::time::timeout(
            connect_timeout,
            client.get_multiplexed_async_connection_with_config(&async_config),
        )
        .await
        {
            Ok(Ok(conn)) => Ok(conn),
            Ok(Err(error)) => Err(ConnectAttemptError::Redis(error)),
            Err(_) => Err(ConnectAttemptError::Timeout),
        }
    }

    /// Get or create a Redis connection from the pool, establishing it lazily.
    ///
    /// Fast path (hot): round-robin slot pick + lock-free `ArcSwap::load()`.
    /// Slow path (cold): per-slot `Mutex`-guarded establishment with double-check.
    async fn get_connection(&self) -> Option<redis::aio::ConnectionManager> {
        let idx = self.select_slot_index();
        self.get_or_connect_slot(idx).await
    }

    /// Establish (or reuse) the ConnectionManager for a specific pool slot.
    async fn get_or_connect_slot(&self, idx: usize) -> Option<redis::aio::ConnectionManager> {
        // A rejected topology is terminal: never redial it, so no command can
        // succeed against an endpoint this client cannot enforce against.
        if self.is_topology_unsupported() {
            return None;
        }
        let slot = &self.pool[idx];

        // Fast path: lock-free read via ArcSwap
        let guard = slot.connection.load();
        if let Some(ref conn) = **guard {
            return Some(conn.clone());
        }
        drop(guard);

        // Slow path: serialize connection establishment for this slot only
        let _lock = slot.connect_mutex.lock().await;

        // Double-check after acquiring mutex
        let guard = slot.connection.load();
        if let Some(ref conn) = **guard {
            return Some(conn.clone());
        }
        drop(guard);

        let url = match self.resolve_url().await {
            RedisEndpoint::Url(url) => url,
            RedisEndpoint::EgressDenied => {
                // Policy denial leaves centralized Redis unavailable with NO
                // recovery checker — it would re-screen and stay denied every
                // interval. The consumer's explicit failure policy applies
                // until a config change rebuilds the client.
                self.mark_unavailable();
                return None;
            }
            RedisEndpoint::ResolveFailed => {
                // Transient DNS failure: never dial an unscreened host. Leave
                // centralized Redis unavailable and let the recovery checker
                // re-screen later; the consumer's failure policy applies.
                self.mark_unavailable();
                self.start_health_checker_if_needed();
                return None;
            }
        };
        let client = match self.build_client(&url) {
            Ok(c) => c,
            Err(e) => {
                warn!(
                    redis_url = %self.config.redacted_url(),
                    pool_slot = idx,
                    error = %e,
                    "Failed to create Redis client for rate limiting"
                );
                self.mark_unavailable();
                self.start_health_checker_if_needed();
                return None;
            }
        };

        match self.connect_manager(client).await {
            Ok(mut manager) => {
                // Screen topology before the connection is published to the hot
                // path: a Cluster endpoint must never serve a policy operation.
                if !self.screen_topology(&mut manager).await {
                    return None;
                }
                // Re-check at the publication boundary: another task may have
                // proven Cluster topology while this slot was being screened.
                // Publishing the connection (or availability) afterwards would
                // let a policy operation run against a refused endpoint.
                if !self.availability.publish_reachable() {
                    return None;
                }
                info!(
                    redis_url = %self.config.redacted_url(),
                    key_prefix = %self.config.key_prefix,
                    pool_slot = idx,
                    pool_size = self.pool.len(),
                    "Redis rate limiting connected"
                );
                self.start_health_checker_if_needed();
                slot.connection.store(Arc::new(Some(manager.clone())));
                Some(manager)
            }
            Err(ConnectAttemptError::Redis(e)) => {
                warn!(
                    redis_url = %self.config.redacted_url(),
                    pool_slot = idx,
                    error = %e,
                    "Failed to connect to Redis for rate limiting"
                );
                self.note_command_failure(&e);
                self.start_health_checker_if_needed();
                None
            }
            Err(ConnectAttemptError::Timeout) => {
                warn!(
                    redis_url = %self.config.redacted_url(),
                    pool_slot = idx,
                    timeout_seconds = self.config.connect_timeout_seconds,
                    "Timed out connecting to Redis for rate limiting"
                );
                self.mark_unavailable();
                self.start_health_checker_if_needed();
                None
            }
        }
    }

    /// Create a one-off non-reconnecting multiplexed connection that is not
    /// stored in the shared hot-path cache.
    ///
    /// Redis transactions that rely on connection-local state (`WATCH`/`MULTI`/
    /// `EXEC`) must:
    /// 1. Not share a cached [`redis::aio::ConnectionManager`] with unrelated
    ///    concurrent commands (another sequence on that manager can interleave
    ///    `UNWATCH`/`EXEC` and break the optimistic transaction boundary).
    /// 2. Not use [`redis::aio::ConnectionManager`] at all for the sequence —
    ///    that type owns an `ArcSwap`-backed connection and can transparently
    ///    reconnect (including after a RESP3 disconnect push). A reconnect
    ///    between `WATCH` and `EXEC` yields a fresh physical socket with no
    ///    watch state, so `EXEC` can become unconditional.
    ///
    /// This helper therefore returns a freshly dialed
    /// [`redis::aio::MultiplexedConnection`] against the already
    /// screened/redacted endpoint, using the same timeout/TLS/egress policy as
    /// other connection creation. Callers must not clone or share it during the
    /// transaction, and must fail closed on any I/O error rather than retrying
    /// a partial transaction on a new connection.
    async fn get_dedicated_connection(&self) -> Option<redis::aio::MultiplexedConnection> {
        // A rejected topology is terminal: never redial it (see
        // `get_or_connect_slot`).
        if self.is_topology_unsupported() {
            return None;
        }
        let url = match self.resolve_url().await {
            RedisEndpoint::Url(url) => url,
            RedisEndpoint::EgressDenied => {
                // Policy denial leaves centralized Redis unavailable with NO
                // recovery checker — it would re-screen and stay denied every
                // interval. The consumer's explicit failure policy applies
                // until a config change rebuilds the client.
                self.mark_unavailable();
                return None;
            }
            RedisEndpoint::ResolveFailed => {
                // Transient DNS failure: never dial an unscreened host. Leave
                // centralized Redis unavailable and let the recovery checker
                // re-screen later; the consumer's failure policy applies.
                self.mark_unavailable();
                self.start_health_checker_if_needed();
                return None;
            }
        };
        let client = match self.build_client(&url) {
            Ok(client) => client,
            Err(e) => {
                warn!(
                    redis_url = %self.config.redacted_url(),
                    error = %e,
                    "Failed to create dedicated Redis client"
                );
                self.mark_unavailable();
                self.start_health_checker_if_needed();
                return None;
            }
        };

        match self.connect_multiplexed(client).await {
            Ok(mut conn) => {
                // Screen topology before any WATCH/MULTI sequence runs on it.
                if !self.screen_topology(&mut conn).await {
                    return None;
                }
                // Same publication boundary as the pooled path: a concurrent
                // topology rejection wins over this dedicated connection.
                if !self.availability.publish_reachable() {
                    return None;
                }
                Some(conn)
            }
            Err(ConnectAttemptError::Redis(e)) => {
                warn!(
                    redis_url = %self.config.redacted_url(),
                    error = %e,
                    "Failed to connect dedicated Redis client"
                );
                self.note_command_failure(&e);
                self.start_health_checker_if_needed();
                None
            }
            Err(ConnectAttemptError::Timeout) => {
                warn!(
                    redis_url = %self.config.redacted_url(),
                    timeout_seconds = self.config.connect_timeout_seconds,
                    "Timed out connecting dedicated Redis client"
                );
                self.mark_unavailable();
                self.start_health_checker_if_needed();
                None
            }
        }
    }

    /// Clear every cached pool slot so the next `get_connection()` call
    /// re-resolves DNS and creates fresh connections.
    fn clear_connection(&self) {
        for slot in self.pool.iter() {
            slot.connection.store(Arc::new(None));
        }
    }

    /// Mark Redis as unavailable and clear the connection for re-resolution.
    fn mark_unavailable(&self) {
        self.availability.mark_unreachable();
        self.clear_connection();
    }

    /// Permanently reject the configured endpoint as an unsupported topology.
    ///
    /// Distinct from [`Self::mark_unavailable`] on purpose: this is a
    /// configuration fault, not an outage, so no amount of recovery pinging can
    /// make the next policy operation correct. Every later
    /// [`Self::is_available`] load stays false and the consumer's configured
    /// failure policy governs from here on.
    fn mark_topology_unsupported(&self, reason: &str) {
        let first = self.availability.reject_topology();
        // Drop cached connections so no slot can keep serving the refused
        // endpoint. `reject_topology` already made the state terminal, so this
        // cannot be downgraded back to a plain outage.
        self.clear_connection();
        if first {
            warn!(
                redis_url = %self.config.redacted_url(),
                key_prefix = %self.config.key_prefix,
                reason,
                "Redis endpoint reports an unsupported topology (Redis Cluster is not supported) \
                 — centralized Redis access is disabled for this configuration until it is changed"
            );
        }
    }

    /// Classify a failed Redis command: an unsupported topology is terminal,
    /// anything else is an ordinary (recoverable) availability failure.
    fn note_command_failure(&self, error: &redis::RedisError) {
        if is_cluster_topology_error(error) {
            self.mark_topology_unsupported("cluster redirection or cross-slot error");
        } else {
            self.mark_unavailable();
        }
    }

    /// Post-I/O success boundary for every Redis command.
    ///
    /// Publishes availability and reports whether the operation may be returned
    /// as a success. `Err(())` means another task proved an unsupported topology
    /// while this command was in flight: the command may already have mutated
    /// Redis, but reporting success would let admission proceed against an
    /// endpoint this client cannot enforce on. Failing the operation instead
    /// hands the decision to the consumer's `redis_failure_policy`, and a
    /// double-counted increment is the conservative direction for a limiter.
    fn note_command_success(&self) -> Result<(), ()> {
        if self.availability.publish_reachable() {
            Ok(())
        } else {
            Err(())
        }
    }

    /// Reject a freshly established connection whose server reports Cluster
    /// topology, or one that could not be screened at all. Returns `true` only
    /// when the connection may be used.
    async fn screen_topology(&self, conn: &mut impl redis::aio::ConnectionLike) -> bool {
        match screen_connection_topology(conn, self.connect_timeout()).await {
            TopologyScreen::Usable => true,
            TopologyScreen::ClusterProven => {
                self.mark_topology_unsupported("server reported cluster_enabled");
                false
            }
            TopologyScreen::ProbeFailed => {
                // Bounded by the configured connect timeout. Never proof of
                // Cluster topology, and never a licence to run a policy command
                // on the unscreened connection — an ordinary retryable outage.
                warn!(
                    redis_url = %self.config.redacted_url(),
                    timeout_seconds = self.config.connect_timeout_seconds,
                    "Redis topology screen did not complete — centralized Redis unavailable; \
                     will retry"
                );
                self.mark_unavailable();
                self.start_health_checker_if_needed();
                false
            }
        }
    }

    /// Start a background task that periodically pings Redis to detect recovery.
    ///
    /// The task is aborted when this client is dropped so retired plugin
    /// generations cannot keep dialing obsolete Redis endpoints.
    fn start_health_checker_if_needed(&self) {
        if self.health_checker_started.swap(true, Ordering::Relaxed) {
            return; // Already started
        }

        let availability = Arc::clone(&self.availability);
        let config = self.config.clone();
        let dns_cache = self.dns_cache.clone();
        let interval = Duration::from_secs(self.config.health_check_interval_seconds);
        let connect_timeout = self.connect_timeout();
        let tls_no_verify = self.tls_no_verify;
        let tls_ca_bundle_pem = self.tls_ca_bundle_pem.clone();

        let handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;

                // A rejected topology is a configuration fault, not an outage:
                // a Cluster node answers PING while still redirecting every
                // key, so recovery must never be reported for one. Checked
                // again at the publication boundary below, because a rejection
                // can also land while this probe is in flight.
                if availability.is_topology_terminal() {
                    continue;
                }

                // Screen + resolve through the shared DNS cache, fail-closed: the
                // recovery checker must NOT hand an unscreened host to the Redis
                // client either (a DNS-cache outage or a later rebind/policy denial
                // would otherwise let the background ping dial a denied address).
                let url = match screen_redis_endpoint(&config, dns_cache.as_ref()).await {
                    RedisEndpoint::Url(url) => url,
                    // Blocked by the egress policy or unresolvable — skip this ping
                    // and re-check next interval (stay on the in-memory limiter).
                    RedisEndpoint::EgressDenied | RedisEndpoint::ResolveFailed => continue,
                };

                // Build the client with TLS settings matching the main connection.
                // ACL credentials from `config.username` / `config.password` are
                // injected via ConnectionInfo so health-check pings authenticate
                // with the same principal as the main connection.
                //
                // Connection attempts use the same Ferrum timeout as cached/
                // dedicated paths (inner AsyncConnectionConfig + defensive outer
                // bound). Gateway DNS screening above is outside that timeout.
                let result: Result<(), redis::RedisError> = async {
                    use redis::IntoConnectionInfo;
                    let is_tls = url.starts_with("rediss://");
                    let conn_info_url = if is_tls && tls_no_verify && !url.contains('#') {
                        format!("{url}#insecure")
                    } else {
                        url.clone()
                    };
                    let mut conn_info = conn_info_url.as_str().into_connection_info()?;
                    if config.username.is_some() || config.password.is_some() {
                        let mut redis_settings = conn_info.redis_settings().clone();
                        if let Some(u) = config.username.as_deref() {
                            redis_settings = redis_settings.set_username(u);
                        }
                        if let Some(p) = config.password.as_deref() {
                            redis_settings = redis_settings.set_password(p);
                        }
                        conn_info = conn_info.set_redis_settings(redis_settings);
                    }
                    let client = if is_tls && (tls_ca_bundle_pem.is_some() || tls_no_verify) {
                        redis::Client::build_with_tls(
                            conn_info,
                            redis::TlsCertificates {
                                client_tls: None,
                                root_cert: tls_ca_bundle_pem.clone(),
                            },
                        )?
                    } else {
                        redis::Client::open(conn_info)?
                    };
                    let async_config = redis::AsyncConnectionConfig::new()
                        .set_connection_timeout(Some(connect_timeout));
                    let mut conn = match tokio::time::timeout(
                        connect_timeout,
                        client.get_multiplexed_async_connection_with_config(&async_config),
                    )
                    .await
                    {
                        Ok(Ok(conn)) => conn,
                        Ok(Err(error)) => return Err(error),
                        Err(_) => {
                            return Err(redis::RedisError::from((
                                redis::ErrorKind::Io,
                                "Redis health-check connection attempt timed out",
                            )));
                        }
                    };
                    redis::cmd("PING").query_async::<String>(&mut conn).await?;
                    // A PING alone proves nothing about topology, so screen the
                    // recovered endpoint before ever reporting it healthy. The
                    // probe is bounded by the same configured connect timeout as
                    // the connect paths, so an endpoint that accepts but never
                    // answers INFO cannot stall the recovery loop.
                    let screen = screen_connection_topology(&mut conn, connect_timeout).await;
                    match screen {
                        TopologyScreen::Usable => Ok::<(), redis::RedisError>(()),
                        TopologyScreen::ClusterProven => {
                            if availability.reject_topology() {
                                warn!(
                                    redis_url = %config.redacted_url(),
                                    key_prefix = %config.key_prefix,
                                    reason = "server reported cluster topology during recovery",
                                    "Redis endpoint reports an unsupported topology (Redis Cluster \
                                     is not supported) — centralized Redis access is disabled for \
                                     this configuration until it is changed"
                                );
                            }
                            Err(cluster_topology_probe_error())
                        }
                        TopologyScreen::ProbeFailed => Err(incomplete_topology_probe_error()),
                    }
                }
                .await;

                let was_available = availability.is_available();
                match result {
                    Ok(()) => {
                        // Publication boundary: a topology rejection proven by
                        // another task while this probe was in flight wins, so a
                        // successful PING/INFO can neither restore availability
                        // nor advertise a recovery an observer would relay.
                        if availability.publish_reachable() && !was_available {
                            info!("Redis connection recovered — centralized Redis access restored");
                        }
                    }
                    Err(_) => {
                        if was_available && !availability.is_topology_terminal() {
                            warn!("Redis health check failed — centralized Redis unavailable");
                        }
                        availability.mark_unreachable();
                    }
                }
            }
        });

        *self
            .health_checker_abort
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(handle.abort_handle());
    }

    /// Increment a counter and set expiry. Returns the new count.
    ///
    /// Uses a Redis pipeline to send `INCR` + `EXPIRE` in a single round-trip.
    /// This is the core primitive for fixed-window rate limiting.
    pub async fn incr_with_expire(&self, key: &str, ttl_seconds: u64) -> Result<i64, ()> {
        let mut conn = self.get_connection().await.ok_or(())?;

        let result: Result<(i64,), redis::RedisError> = redis::pipe()
            .atomic()
            .cmd("INCR")
            .arg(key)
            .cmd("EXPIRE")
            .arg(key)
            .arg(expire_seconds(ttl_seconds))
            .ignore()
            .query_async(&mut conn)
            .await;

        match result {
            Ok((count,)) => {
                self.note_command_success()?;
                Ok(count)
            }
            Err(e) => {
                warn!(
                    key = %key,
                    error = %e,
                    "Redis INCR+EXPIRE failed"
                );
                self.note_command_failure(&e);
                Err(())
            }
        }
    }

    /// Read the previous sliding-window bucket, increment the current bucket,
    /// and set the current bucket expiry in one Redis transaction.
    ///
    /// The caller makes its allow/deny decision from the returned post-INCR
    /// current count, tying admission to the mutation even when many gateway
    /// instances race on the same key.
    pub async fn sliding_window_increment(
        &self,
        previous_key: &str,
        current_key: &str,
        ttl_seconds: u64,
    ) -> Result<(i64, i64), ()> {
        let mut conn = self.get_connection().await.ok_or(())?;

        let result: Result<(Option<i64>, i64), redis::RedisError> = redis::pipe()
            .atomic()
            .cmd("GET")
            .arg(previous_key)
            .cmd("INCR")
            .arg(current_key)
            .cmd("EXPIRE")
            .arg(current_key)
            .arg(expire_seconds(ttl_seconds))
            .ignore()
            .query_async(&mut conn)
            .await;

        match result {
            Ok((previous_count, current_count)) => {
                self.note_command_success()?;
                Ok((previous_count.unwrap_or(0), current_count))
            }
            Err(e) => {
                warn!(
                    previous_key = %previous_key,
                    current_key = %current_key,
                    error = %e,
                    "Redis sliding-window GET+INCR+EXPIRE transaction failed"
                );
                self.note_command_failure(&e);
                Err(())
            }
        }
    }

    /// Increment a counter by a specific amount and set expiry. Returns the new total.
    ///
    /// Uses a Redis pipeline to send `INCRBY` + `EXPIRE` in a single round-trip.
    /// Used by the AI token rate limiter where each request may consume a variable
    /// number of tokens.
    pub async fn incrby_with_expire(
        &self,
        key: &str,
        amount: i64,
        ttl_seconds: u64,
    ) -> Result<i64, ()> {
        let mut conn = self.get_connection().await.ok_or(())?;

        let result: Result<(i64,), redis::RedisError> = redis::pipe()
            .atomic()
            .cmd("INCRBY")
            .arg(key)
            .arg(amount)
            .cmd("EXPIRE")
            .arg(key)
            .arg(expire_seconds(ttl_seconds))
            .ignore()
            .query_async(&mut conn)
            .await;

        match result {
            Ok((count,)) => {
                self.note_command_success()?;
                Ok(count)
            }
            Err(e) => {
                warn!(
                    key = %key,
                    error = %e,
                    "Redis INCRBY+EXPIRE failed"
                );
                self.note_command_failure(&e);
                Err(())
            }
        }
    }

    /// Increment a counter by `amount`, set expiry, and floor the result at
    /// zero. Returns the new (floored) total, or `Err(())` if Redis is
    /// unreachable for *either* the increment or the compensating floor write.
    ///
    /// A failed compensating write is reported as `Err(())` (not `Ok(0)`): the
    /// key may be left negative on the server, and silently reporting success
    /// would let a recovered Redis read that negative counter as zero usage and
    /// bypass enforcement. Returning the error makes the caller fall back to the
    /// local limiter for that operation, which is the conservative choice.
    ///
    /// This is the reconciliation-safe variant of [`incrby_with_expire`]. The
    /// AI token limiter applies reconciliation deltas (`actual - reserved`)
    /// that are usually *negative* (reserved estimates run high; non-2xx
    /// responses release the full reservation). A raw `INCRBY` can drive a
    /// missing or low window counter negative, and a negative counter later
    /// reads as zero usage — letting a consumer reserve the full limit again
    /// and bypassing centralized enforcement. The local in-memory path floors
    /// usage at zero (`TokenUsageWindow::adjust_usage`); this keeps the Redis
    /// path consistent.
    ///
    /// When the post-`INCRBY` value is negative we issue a *compensating*
    /// `INCRBY` of exactly `-new_total` to bring the key back to zero, rather
    /// than a blind `SET 0`. A blind `SET` would also discard any concurrent
    /// positive increment that landed between our write and read (a worse
    /// under-count); compensating by exactly the observed deficit only fails
    /// in the conservative direction (a concurrent add during the race can
    /// leave a transient over-count, which is safe for a rate limiter — it
    /// never under-counts usage).
    pub async fn incrby_with_expire_floor_zero(
        &self,
        key: &str,
        amount: i64,
        ttl_seconds: u64,
    ) -> Result<i64, ()> {
        let new_total = self.incrby_with_expire(key, amount, ttl_seconds).await?;
        let Some(compensation) = floor_zero_compensation(new_total) else {
            return Ok(new_total);
        };

        // Bring the counter back up to exactly zero, preserving the TTL.
        match self
            .incrby_with_expire(key, compensation, ttl_seconds)
            .await
        {
            Ok(floored) => Ok(clamp_floored_total(floored)),
            // The compensating write failed (Redis went away mid-operation), so
            // the key is left *negative* on the server. Do NOT report success:
            // a negative counter reads as zero usage once Redis recovers within
            // the key TTL, letting a consumer re-reserve the full budget —
            // exactly the bypass the floor exists to prevent. `incrby_with_expire`
            // already marked the client unavailable (triggering local failover);
            // surface the failure to the caller and log the leaked-floor state so
            // it is observable rather than silently undercounting.
            Err(()) => {
                warn!(
                    key = %key,
                    "Redis floor compensation failed after negative INCRBY accepted; \
                     window counter left negative until TTL — centralized enforcement unavailable"
                );
                Err(())
            }
        }
    }

    /// Increment one counter by 1 and another by a specific amount in a single
    /// pipelined round-trip. Returns `(new_count, new_total)`.
    pub async fn incr_and_incrby_with_expire(
        &self,
        count_key: &str,
        total_key: &str,
        amount: i64,
        ttl_seconds: u64,
    ) -> Result<(i64, i64), ()> {
        let mut conn = self.get_connection().await.ok_or(())?;

        let result: Result<(i64, i64), redis::RedisError> = redis::pipe()
            .atomic()
            .cmd("INCR")
            .arg(count_key)
            .cmd("INCRBY")
            .arg(total_key)
            .arg(amount)
            .cmd("EXPIRE")
            .arg(count_key)
            .arg(expire_seconds(ttl_seconds))
            .ignore()
            .cmd("EXPIRE")
            .arg(total_key)
            .arg(expire_seconds(ttl_seconds))
            .ignore()
            .query_async(&mut conn)
            .await;

        match result {
            Ok((count, total)) => {
                self.note_command_success()?;
                Ok((count, total))
            }
            Err(e) => {
                warn!(
                    count_key = %count_key,
                    total_key = %total_key,
                    error = %e,
                    "Redis INCR+INCRBY+EXPIRE pipeline failed"
                );
                self.note_command_failure(&e);
                Err(())
            }
        }
    }

    /// Get two counters in a single pipelined round-trip. Returns (0, 0) for missing keys.
    ///
    /// Used by the AI token rate limiter to fetch both the previous and current
    /// window counters without two separate round-trips.
    pub async fn get_two_counters(&self, key1: &str, key2: &str) -> Result<(i64, i64), ()> {
        let mut conn = self.get_connection().await.ok_or(())?;

        let result: Result<(Option<i64>, Option<i64>), redis::RedisError> = redis::pipe()
            .cmd("GET")
            .arg(key1)
            .cmd("GET")
            .arg(key2)
            .query_async(&mut conn)
            .await;

        match result {
            Ok((v1, v2)) => {
                self.note_command_success()?;
                Ok((v1.unwrap_or(0), v2.unwrap_or(0)))
            }
            Err(e) => {
                warn!(
                    error = %e,
                    "Redis GET+GET pipeline failed"
                );
                self.note_command_failure(&e);
                Err(())
            }
        }
    }

    /// Get a raw byte value from Redis.
    ///
    /// Used by plugins that need arbitrary key-value storage (e.g., request
    /// deduplication, AI semantic cache) rather than rate limiting counters.
    pub async fn get_bytes(&self, key: &str) -> Result<Option<Vec<u8>>, ()> {
        let mut conn = self.get_connection().await.ok_or(())?;

        let result: Result<Option<Vec<u8>>, redis::RedisError> =
            redis::cmd("GET").arg(key).query_async(&mut conn).await;

        match result {
            Ok(val) => {
                self.note_command_success()?;
                Ok(val)
            }
            Err(e) => {
                warn!(
                    key = %key,
                    error = %e,
                    "Redis GET failed"
                );
                self.note_command_failure(&e);
                Err(())
            }
        }
    }

    /// Get a raw byte value from Redis, bounded to `max_bytes` before
    /// allocation.
    ///
    /// A plain `GET` would allocate the full stored value regardless of size, so
    /// a compromised or oversized entry could force an unbounded allocation. This
    /// reads `EXISTS`, `STRLEN`, and `GETRANGE key 0 max_bytes` in one pipelined
    /// round-trip: the true length gates the outcome while the range read caps
    /// the transferred/allocated bytes at `max_bytes + 1`. The inclusive end
    /// index is converted with [`redis_getrange_end_index`] so an oversized cap
    /// cannot become Redis's "read to end" (`-1`) sentinel. Returned prefixes are
    /// independently verified against the bound before admission. Callers treat
    /// [`BoundedRedisValue::Oversized`] and [`BoundedRedisValue::Empty`] as
    /// invalid entries and quarantine them.
    pub async fn get_bytes_bounded(
        &self,
        key: &str,
        max_bytes: usize,
    ) -> Result<BoundedRedisValue, ()> {
        // Fail closed before any Redis dispatch when the cap cannot be expressed
        // as a non-negative GETRANGE end index (for example `usize::MAX` → `-1`).
        let end = redis_getrange_end_index(max_bytes).map_err(|_| ())?;
        let mut conn = self.get_connection().await.ok_or(())?;

        // GETRANGE end index is inclusive, so `0..=max_bytes` reads at most
        // `max_bytes + 1` bytes — enough to confirm an over-cap value without
        // materializing it. EXISTS distinguishes a missing key from an empty
        // value so callers can quarantine empty poisoned keys. Pipelined in one
        // round-trip (non-transactional like `get_two_counters`); a concurrent
        // rewrite between the commands can only cause a benign spurious
        // quarantine/miss, never an unbounded allocation.
        let result: Result<(i64, usize, Vec<u8>), redis::RedisError> = redis::pipe()
            .cmd("EXISTS")
            .arg(key)
            .cmd("STRLEN")
            .arg(key)
            .cmd("GETRANGE")
            .arg(key)
            .arg(0)
            .arg(end)
            .query_async(&mut conn)
            .await;

        match result {
            Ok((exists, length, prefix)) => {
                self.note_command_success()?;
                if exists == 0 {
                    return Ok(BoundedRedisValue::Missing);
                }
                if length == 0 {
                    return Ok(BoundedRedisValue::Empty);
                }
                // Independently verify Redis honored the bound. An over-cap probe
                // may return at most `max_bytes + 1` bytes; an in-cap value must
                // never exceed `max_bytes`.
                let max_prefix = if length > max_bytes {
                    max_bytes.saturating_add(1)
                } else {
                    max_bytes
                };
                if prefix.len() > max_prefix {
                    warn!(
                        key = %key,
                        prefix_len = prefix.len(),
                        max_bytes,
                        "Redis GETRANGE returned more bytes than the requested bound; failing closed"
                    );
                    return Err(());
                }
                if length > max_bytes {
                    Ok(BoundedRedisValue::Oversized { length })
                } else if prefix.len() != length {
                    // Length/prefix disagreement under the cap is treated as an
                    // invalid entry so callers quarantine rather than replay.
                    Ok(BoundedRedisValue::Oversized {
                        length: prefix.len().max(length),
                    })
                } else {
                    Ok(BoundedRedisValue::Found(prefix))
                }
            }
            Err(e) => {
                warn!(
                    key = %key,
                    error = %e,
                    "Redis EXISTS+STRLEN+GETRANGE failed"
                );
                self.note_command_failure(&e);
                Err(())
            }
        }
    }

    /// Best-effort unconditional key deletion, used to quarantine a poisoned or
    /// invalid cache entry so it is not re-served on the next request.
    pub async fn delete(&self, key: &str) -> Result<(), ()> {
        let mut conn = self.get_connection().await.ok_or(())?;

        let result: Result<i64, redis::RedisError> =
            redis::cmd("DEL").arg(key).query_async(&mut conn).await;

        match result {
            Ok(_) => {
                self.note_command_success()?;
                Ok(())
            }
            Err(e) => {
                warn!(
                    key = %key,
                    error = %e,
                    "Redis DEL failed"
                );
                self.note_command_failure(&e);
                Err(())
            }
        }
    }

    /// Set a raw byte value in Redis with a TTL.
    ///
    /// Uses a pipelined `SET` + `EXPIRE` in a single round-trip.
    /// Used by plugins that need arbitrary key-value storage.
    pub async fn set_bytes_with_expire(
        &self,
        key: &str,
        value: &[u8],
        ttl_seconds: u64,
    ) -> Result<(), ()> {
        let mut conn = self.get_connection().await.ok_or(())?;

        let result: Result<(), redis::RedisError> = redis::pipe()
            .atomic()
            .cmd("SET")
            .arg(key)
            .arg(value)
            .ignore()
            .cmd("EXPIRE")
            .arg(key)
            .arg(expire_seconds(ttl_seconds))
            .ignore()
            .query_async(&mut conn)
            .await;

        match result {
            Ok(()) => {
                self.note_command_success()?;
                Ok(())
            }
            Err(e) => {
                warn!(
                    key = %key,
                    error = %e,
                    "Redis SET+EXPIRE failed"
                );
                self.note_command_failure(&e);
                Err(())
            }
        }
    }

    /// Set a raw byte value only if the key does not already exist, with a TTL.
    ///
    /// Returns `Ok(true)` when the caller acquired the key, `Ok(false)` when an
    /// existing key prevented the write, and `Err(())` when Redis is unavailable.
    pub async fn set_bytes_nx_with_expire(
        &self,
        key: &str,
        value: &[u8],
        ttl_seconds: u64,
    ) -> Result<bool, ()> {
        let mut conn = self.get_connection().await.ok_or(())?;

        let result: Result<Option<String>, redis::RedisError> = redis::cmd("SET")
            .arg(key)
            .arg(value)
            .arg("NX")
            .arg("EX")
            .arg(expire_seconds(ttl_seconds))
            .query_async(&mut conn)
            .await;

        match result {
            Ok(value) => {
                self.note_command_success()?;
                Ok(value.is_some())
            }
            Err(e) => {
                warn!(
                    key = %key,
                    error = %e,
                    "Redis SET NX EX failed"
                );
                self.note_command_failure(&e);
                Err(())
            }
        }
    }

    /// Delete a key only when its current byte value exactly matches `expected`.
    ///
    /// Uses optimistic transactions (`WATCH` + `MULTI`/`EXEC`) instead of Lua so
    /// RESP-compatible Redis backends that do not support scripting can still
    /// use ownership-token lock release.
    ///
    /// The transaction runs on a freshly dialed, non-reconnecting
    /// [`redis::aio::MultiplexedConnection`] (never a
    /// [`redis::aio::ConnectionManager`]) so connection-local `WATCH` state
    /// cannot be silently dropped by a transparent reconnect. Any I/O failure
    /// at `WATCH`, `GET`, `UNWATCH`, or `EXEC` fails closed as `Err(())`.
    pub async fn delete_if_value_matches(&self, key: &str, expected: &[u8]) -> Result<bool, ()> {
        // Owned for the duration of the transaction; never cloned or shared.
        let mut conn = self.get_dedicated_connection().await.ok_or(())?;

        let watch_result: Result<(), redis::RedisError> =
            redis::cmd("WATCH").arg(key).query_async(&mut conn).await;
        if let Err(e) = watch_result {
            warn!(
                key = %key,
                error = %e,
                "Redis WATCH failed"
            );
            self.note_command_failure(&e);
            return Err(());
        }

        let current: Result<Option<Vec<u8>>, redis::RedisError> =
            redis::cmd("GET").arg(key).query_async(&mut conn).await;
        match current {
            Ok(Some(current)) if current == expected => {}
            Ok(_) => {
                let unwatch: Result<(), redis::RedisError> =
                    redis::cmd("UNWATCH").query_async(&mut conn).await;
                if let Err(e) = unwatch {
                    warn!(
                        key = %key,
                        error = %e,
                        "Redis UNWATCH failed"
                    );
                    self.note_command_failure(&e);
                    return Err(());
                }
                self.note_command_success()?;
                return Ok(false);
            }
            Err(e) => {
                warn!(
                    key = %key,
                    error = %e,
                    "Redis compare-delete GET failed"
                );
                // WATCH already succeeded: attempt UNWATCH before failing closed.
                // A failed UNWATCH is itself a failure; never retry on a new conn.
                let unwatch: Result<(), redis::RedisError> =
                    redis::cmd("UNWATCH").query_async(&mut conn).await;
                if let Err(unwatch_err) = unwatch {
                    warn!(
                        key = %key,
                        error = %unwatch_err,
                        "Redis UNWATCH failed"
                    );
                }
                self.note_command_failure(&e);
                return Err(());
            }
        }

        let result: Result<Option<(i64,)>, redis::RedisError> = redis::pipe()
            .atomic()
            .cmd("DEL")
            .arg(key)
            .query_async(&mut conn)
            .await;

        match result {
            Ok(Some((deleted,))) => {
                self.note_command_success()?;
                Ok(deleted > 0)
            }
            Ok(None) => {
                self.note_command_success()?;
                Ok(false)
            }
            Err(e) => {
                warn!(
                    key = %key,
                    error = %e,
                    "Redis compare-delete transaction failed"
                );
                self.note_command_failure(&e);
                Err(())
            }
        }
    }

    /// Replace a key's value with a TTL **only** when its current byte value
    /// exactly matches `expected` — a single-key compare-and-set.
    ///
    /// This is the fencing primitive for ownership-token protocols: the caller
    /// writes an ownership record, performs work, and then publishes its result
    /// into the same key. Because the compare and the write happen inside one
    /// `WATCH`/`MULTI`/`EXEC` transaction on a dedicated non-reconnecting
    /// [`redis::aio::MultiplexedConnection`], an owner whose record has since
    /// expired or been replaced by a successor can neither overwrite the
    /// successor's value nor resurrect a key that Redis already dropped:
    ///
    /// - `Ok(true)` — the caller still owned the key and the new value is live.
    /// - `Ok(false)` — the key is missing, holds a different value, or was
    ///   concurrently modified between `WATCH` and `EXEC`. Nothing was written.
    /// - `Err(())` — Redis is unavailable; the caller must not assume either
    ///   outcome.
    ///
    /// `WATCH`-based rather than Lua so RESP-compatible servers without
    /// scripting still fence correctly (same rationale as
    /// [`Self::delete_if_value_matches`]). Only one key is touched, so the
    /// transaction is also slot-safe on sharded deployments.
    ///
    /// Any I/O failure at `WATCH`, `GET`, `UNWATCH`, or `EXEC` fails closed;
    /// a partial transaction is never retried on a fresh connection.
    pub async fn set_bytes_with_expire_if_value_matches(
        &self,
        key: &str,
        expected: &[u8],
        value: &[u8],
        ttl_seconds: u64,
    ) -> Result<bool, ()> {
        // Owned for the duration of the transaction; never cloned or shared.
        let mut conn = self.get_dedicated_connection().await.ok_or(())?;

        let watch_result: Result<(), redis::RedisError> =
            redis::cmd("WATCH").arg(key).query_async(&mut conn).await;
        if let Err(e) = watch_result {
            warn!(
                key = %key,
                error = %e,
                "Redis WATCH failed"
            );
            self.note_command_failure(&e);
            return Err(());
        }

        let current: Result<Option<Vec<u8>>, redis::RedisError> =
            redis::cmd("GET").arg(key).query_async(&mut conn).await;
        match current {
            Ok(Some(current)) if current == expected => {}
            Ok(_) => {
                let unwatch: Result<(), redis::RedisError> =
                    redis::cmd("UNWATCH").query_async(&mut conn).await;
                if let Err(e) = unwatch {
                    warn!(
                        key = %key,
                        error = %e,
                        "Redis UNWATCH failed"
                    );
                    self.note_command_failure(&e);
                    return Err(());
                }
                self.note_command_success()?;
                return Ok(false);
            }
            Err(e) => {
                warn!(
                    key = %key,
                    error = %e,
                    "Redis compare-and-set GET failed"
                );
                // WATCH already succeeded: attempt UNWATCH before failing closed.
                // A failed UNWATCH is itself a failure; never retry on a new conn.
                let unwatch: Result<(), redis::RedisError> =
                    redis::cmd("UNWATCH").query_async(&mut conn).await;
                if let Err(unwatch_err) = unwatch {
                    warn!(
                        key = %key,
                        error = %unwatch_err,
                        "Redis UNWATCH failed"
                    );
                }
                self.note_command_failure(&e);
                return Err(());
            }
        }

        // A `nil` EXEC reply means the watched key changed after the compare,
        // so the caller lost ownership in the race window. That is reported as
        // `Ok(false)`, never as a successful publication.
        let result: Result<Option<(String,)>, redis::RedisError> = redis::pipe()
            .atomic()
            .cmd("SET")
            .arg(key)
            .arg(value)
            .arg("EX")
            .arg(expire_seconds(ttl_seconds))
            .query_async(&mut conn)
            .await;

        match result {
            Ok(Some(_)) => {
                self.note_command_success()?;
                Ok(true)
            }
            Ok(None) => {
                self.note_command_success()?;
                Ok(false)
            }
            Err(e) => {
                warn!(
                    key = %key,
                    error = %e,
                    "Redis compare-and-set transaction failed"
                );
                self.note_command_failure(&e);
                Err(())
            }
        }
    }

    /// Build a full Redis key whose prefix + logical rate key share one Redis
    /// Cluster hash slot: `{escaped-prefix:escaped-rate-key}:suffix…`.
    ///
    /// Redis hashes only the bytes between the first `{` and the following `}`,
    /// so every key produced for one `rate_key` — the previous and current
    /// sliding-window buckets, the datagram and byte counters — lands in the
    /// same slot and one multi-key transaction over them can never be a
    /// `CROSSSLOT` error. Different rate keys still spread across slots, so no
    /// single slot becomes the whole policy's hot spot. The tag components
    /// percent-escape `%`, braces, and `:` so caller-controlled identities
    /// cannot terminate the tag early or collide across the prefix/key
    /// boundary.
    ///
    /// This client refuses Cluster endpoints outright (see the module-level
    /// topology notes); the tag exists so the key layout is already correct if
    /// that ever changes, and it is inert on single-endpoint servers.
    pub fn make_slot_key(&self, rate_key: &str, suffix: &[&str]) -> String {
        let suffix_len: usize = suffix.iter().map(|component| component.len() + 1).sum();
        let prefix_len = slot_tag_component_len(&self.config.key_prefix);
        let rate_key_len = slot_tag_component_len(rate_key);
        let mut key = String::with_capacity(
            prefix_len
                .saturating_add(rate_key_len)
                .saturating_add(suffix_len)
                .saturating_add(3),
        );
        key.push('{');
        push_slot_tag_component(&mut key, &self.config.key_prefix);
        key.push(':');
        push_slot_tag_component(&mut key, rate_key);
        key.push('}');
        for component in suffix {
            key.push(':');
            key.push_str(component);
        }
        key
    }

    /// Build a full Redis key with the configured prefix.
    ///
    /// For keys that participate in a multi-key atomic operation use
    /// [`Self::make_slot_key`] instead so they share a hash slot.
    pub fn make_key(&self, components: &[&str]) -> String {
        let mut key = self.config.key_prefix.clone();
        for component in components {
            key.push(':');
            key.push_str(component);
        }
        key
    }

    /// Compute window index and elapsed fraction from the current wall clock.
    ///
    /// Both values come from **one** `SystemTime` sample so a boundary straddle
    /// cannot pair an index from one instant with a fraction from another.
    pub fn window_progress(window_seconds: u64) -> RedisWindowProgress {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        Self::window_progress_at(now, window_seconds)
    }

    /// Deterministic window index / elapsed fraction for a captured epoch offset.
    ///
    /// `elapsed_fraction` preserves subsecond precision and stays in `[0, 1)`.
    pub fn window_progress_at(now: Duration, window_seconds: u64) -> RedisWindowProgress {
        let window = window_seconds.max(1);
        let total_nanos = now.as_nanos();
        let window_nanos = (window as u128).saturating_mul(1_000_000_000);
        // `window` is at least 1, so `window_nanos` is at least 1e9.
        let index = (total_nanos / window_nanos) as u64;
        let elapsed_nanos = total_nanos % window_nanos;
        let elapsed_fraction = elapsed_nanos as f64 / window_nanos as f64;
        RedisWindowProgress {
            index,
            elapsed_fraction,
        }
    }

    /// Compute the window index for a given epoch time and window duration.
    ///
    /// Window index = `floor(epoch_nanos / window_nanos)`. All gateway instances
    /// sharing the same Redis will use the same window boundaries since they
    /// share the system epoch clock.
    pub fn window_index(window_seconds: u64) -> u64 {
        Self::window_progress(window_seconds).index
    }

    /// Return the Redis hostname for DNS pre-warming, if applicable.
    pub fn warmup_hostname(&self) -> Option<String> {
        self.config.hostname()
    }
}

impl Drop for RedisRateLimitClient {
    fn drop(&mut self) {
        let abort = match self.health_checker_abort.get_mut() {
            Ok(slot) => slot.take(),
            Err(poisoned) => poisoned.into_inner().take(),
        };
        if let Some(abort) = abort {
            abort.abort();
        }
    }
}

impl std::fmt::Debug for RedisRateLimitClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisRateLimitClient")
            .field("key_prefix", &self.config.key_prefix)
            .field("pool_size", &self.pool.len())
            .field("availability", &self.availability.describe())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        RedisGetrangeEndIndexError, clamp_floored_total, floor_zero_compensation,
        redis_getrange_end_index,
    };

    #[test]
    fn redis_getrange_end_index_rejects_zero_and_platform_overflow() {
        assert_eq!(
            redis_getrange_end_index(0),
            Err(RedisGetrangeEndIndexError::ZeroCap)
        );
        assert_eq!(
            redis_getrange_end_index(usize::MAX),
            Err(RedisGetrangeEndIndexError::Overflow)
        );
        assert_eq!(redis_getrange_end_index(1).expect("1 fits"), 1);
        assert_eq!(redis_getrange_end_index(1024).expect("1 KiB fits"), 1024);
    }

    #[test]
    fn floor_zero_compensation_skips_non_negative_totals() {
        // A non-negative post-INCRBY value needs no correction: the floor
        // helper must return `None` so the wrapper keeps the value as-is.
        assert_eq!(floor_zero_compensation(0), None);
        assert_eq!(floor_zero_compensation(1), None);
        assert_eq!(floor_zero_compensation(i64::MAX), None);
    }

    #[test]
    fn floor_zero_compensation_returns_exact_deficit_for_negative_totals() {
        // A negative value must be compensated by exactly its negation so the
        // counter returns to zero — never a blind SET that could clobber a
        // concurrent positive increment.
        assert_eq!(floor_zero_compensation(-1), Some(1));
        assert_eq!(floor_zero_compensation(-500), Some(500));
    }

    #[test]
    fn floor_zero_compensation_saturates_at_min() {
        // `-i64::MIN` overflows; the helper must saturate to `i64::MAX` rather
        // than panic on overflow.
        assert_eq!(floor_zero_compensation(i64::MIN), Some(i64::MAX));
    }

    #[test]
    fn from_plugin_config_ignores_unrelated_plugin_root_keys() {
        use super::RedisConfig;
        use serde_json::json;

        // Shared Redis admission must not reject plugin-specific root keys;
        // each caller closes its own allowlist (unioned with REDIS_PLUGIN_CONFIG_KEYS).
        assert!(
            RedisConfig::from_plugin_config(
                &json!({
                    "sync_mode": "local",
                    "ttl_seconds": 60,
                    "cache_multimodal": "reject",
                    "window_seconds": 10,
                    "max_requests": 100,
                }),
                "test",
            )
            .expect("local mode with plugin keys must parse")
            .is_none()
        );

        let redis = RedisConfig::from_plugin_config(
            &json!({
                "sync_mode": "redis",
                "redis_url": "redis://127.0.0.1:6379/0",
                "ttl_seconds": 60,
                "window_seconds": 10,
                "max_requests": 100,
            }),
            "test",
        )
        .expect("redis mode with plugin keys must parse")
        .expect("redis mode must produce a config");
        assert_eq!(redis.url, "redis://127.0.0.1:6379/0");
    }

    #[test]
    fn from_plugin_config_validates_explicit_redis_fields_in_local_mode() {
        use super::RedisConfig;
        use serde_json::json;

        for config in [
            json!({"sync_mode": "local", "redis_url": "garbage"}),
            json!({"sync_mode": "local", "redis_tls": "yes"}),
            json!({"sync_mode": "local", "redis_key_prefix": ""}),
            json!({"sync_mode": "local", "redis_pool_size": 0}),
            json!({"sync_mode": "local", "redis_connect_timeout_seconds": 0}),
            json!({"sync_mode": "local", "redis_health_check_interval_seconds": 0}),
        ] {
            assert!(
                RedisConfig::from_plugin_config(&config, "test").is_err(),
                "malformed latent Redis config must be rejected: {config}"
            );
        }

        assert!(
            RedisConfig::from_plugin_config(
                &json!({
                    "sync_mode": "local",
                    "redis_url": "redis://127.0.0.1:6379/0",
                    "redis_tls": false,
                    "redis_key_prefix": "test",
                    "redis_pool_size": 1,
                    "redis_connect_timeout_seconds": 1,
                    "redis_health_check_interval_seconds": 1,
                    "redis_username": "user",
                    "redis_password": "secret",
                }),
                "test",
            )
            .expect("well-formed latent Redis config must parse")
            .is_none()
        );
    }

    #[test]
    fn literal_host_ip_and_hostname_are_duals() {
        use super::RedisConfig;
        use serde_json::json;

        let cfg = |url: &str| {
            RedisConfig::from_plugin_config(
                &json!({"sync_mode": "redis", "redis_url": url}),
                "test",
            )
            .unwrap()
            .unwrap()
        };

        // Literal-IP redis_url: `hostname()` returns None (so the hostname DNS
        // screen never sees it), which is exactly why `literal_host_ip()` must
        // surface the IP for the dial-time literal screen / fail-closed path.
        let metadata = cfg("redis://169.254.169.254:6379");
        assert_eq!(metadata.hostname(), None);
        assert_eq!(
            metadata.literal_host_ip(),
            Some("169.254.169.254".parse().unwrap())
        );

        let loopback = cfg("redis://127.0.0.1:6379");
        assert_eq!(
            loopback.literal_host_ip(),
            Some("127.0.0.1".parse().unwrap())
        );

        // Hostname redis_url: the dual — `hostname()` Some, `literal_host_ip()` None.
        let host = cfg("redis://cache.internal:6379");
        assert_eq!(host.hostname(), Some("cache.internal".to_string()));
        assert_eq!(host.literal_host_ip(), None);
    }

    #[test]
    fn clamp_floored_total_floors_negatives_at_zero() {
        // After the compensating write, a value that still reads negative (a
        // concurrent decrement raced the read-back) must clamp to zero so
        // callers never observe a negative usage; non-negative values pass
        // through unchanged.
        assert_eq!(clamp_floored_total(-7), 0);
        assert_eq!(clamp_floored_total(0), 0);
        assert_eq!(clamp_floored_total(42), 42);
    }
}
