//! Kubelet application-probe rewrite server (issue #4533).
//!
//! ## Why this exists
//!
//! The inbound capture chain is a protocol-wide catch-all `REDIRECT` to
//! `:15006`. A kubelet probe dials `podIP:<appPort>` in plaintext, so a
//! captured probe lands on the mesh inbound listener; under `STRICT`
//! `PeerAuthentication` that listener does not demux plaintext
//! (`select_mesh_inbound_tls().accepts_plaintext == false`), the handshake
//! fails, and a `livenessProbe` restart-loops the container.
//!
//! The previous answer was to add each application probe port to
//! `--exclude-inbound-ports`. That is a *destination-port-wide* `RETURN`: it
//! also lets ORDINARY Service/Pod-IP traffic to that port bypass the sidecar
//! and, with it, mesh mTLS and `mesh_authz`. It was also incomplete — `grpc`
//! probes were skipped even though `GRPCAction` has a required `port` that
//! kubelet dials over plain TCP.
//!
//! Ferrum now does what Istio's `rewriteAppHTTPProbers` does instead: the
//! injector rewrites every application `httpGet` / `tcpSocket` / `grpc` probe
//! to an `httpGet` against **this** server on the sidecar's own probe port,
//! and records the ORIGINAL handler in `FERRUM_MESH_APP_PROBES`. Kubelet
//! probes the sidecar; the sidecar probes the application over loopback,
//! which capture never touches. **No application port is excluded from
//! capture** — only the sidecar's own probe port, which terminates here.
//!
//! ## Open-proxy posture
//!
//! The admissible target set is fixed at process start from
//! `FERRUM_MESH_APP_PROBES`. The server accepts NO target, port, path, scheme,
//! or header from the request: the request URI selects a pre-registered entry
//! by exact key or gets a `404`. Every probe it performs is against
//! `127.0.0.1`, so this listener can never be used to reach another pod, the
//! node, or the cluster.
//!
//! ## Scope
//!
//! Sidecar topology only. Ambient / node-agent workloads are not injected with
//! a sidecar and keep the node-agent's own kubelet-probe exemption path.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use crate::config::conf_file::resolve_ferrum_var;
use crate::plugins::prometheus_metrics::escape_label_value;

/// Default sidecar port kubelet probes after the rewrite. Matches Istio's
/// status port so cluster policies written for Istio keep working.
pub const DEFAULT_APP_PROBE_PORT: u16 = 15020;

/// Env var carrying the probe listen port. `0` disables the server.
pub const APP_PROBE_PORT_ENV: &str = "FERRUM_MESH_APP_PROBE_PORT";

/// Env var carrying the injector-emitted original probe handlers (JSON).
pub const APP_PROBES_ENV: &str = "FERRUM_MESH_APP_PROBES";

/// URL prefix owned by the rewrite server. Nothing else is served.
pub const APP_PROBE_PATH_PREFIX: &str = "/app-probe/";

/// Kubernetes probe fields eligible for rewriting.
pub const APP_PROBE_FIELDS: [&str; 3] = ["startupProbe", "readinessProbe", "livenessProbe"];

/// Kubernetes' own default when `timeoutSeconds` is unset.
pub const DEFAULT_PROBE_TIMEOUT_SECONDS: u64 = 1;

/// Upper bound applied to a recorded `timeoutSeconds` so a hostile or
/// mistyped pod spec cannot pin a probe task open indefinitely.
pub const MAX_PROBE_TIMEOUT_SECONDS: u64 = 600;

/// Header-read timeout for an inbound kubelet probe connection.
const PROBE_HEADER_READ_TIMEOUT_SECONDS: u64 = 5;

/// Listen backlog for the probe listener. Kubelet probes are low-rate.
const PROBE_LISTEN_BACKLOG: i32 = 128;

// ── Wire types (injector producer ⇄ sidecar consumer) ────────────────────

/// `scheme` of a rewritten `httpGet` probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum AppProbeScheme {
    #[default]
    #[serde(rename = "HTTP")]
    Http,
    #[serde(rename = "HTTPS")]
    Https,
}

/// One `httpGet` header, mirroring `HTTPHeader`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppProbeHeader {
    pub name: String,
    #[serde(default)]
    pub value: String,
}

/// The original `httpGet` handler, with any named port already resolved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AppProbeHttpGet {
    #[serde(default = "default_probe_path")]
    pub path: String,
    pub port: u16,
    #[serde(default)]
    pub scheme: AppProbeScheme,
    /// `httpGet.host`. Only ever used as the `Host` header — the connection is
    /// always to loopback.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub http_headers: Vec<AppProbeHeader>,
}

fn default_probe_path() -> String {
    "/".to_string()
}

/// The original `tcpSocket` handler.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppProbeTcpSocket {
    pub port: u16,
}

/// The original `grpc` handler (`GRPCAction`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppProbeGrpc {
    pub port: u16,
    /// `grpc.service`; absent/empty means the server's overall health.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
}

/// One recorded application probe. Exactly one handler is populated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AppProbeSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_get: Option<AppProbeHttpGet>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_socket: Option<AppProbeTcpSocket>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grpc: Option<AppProbeGrpc>,
    /// The original probe's `timeoutSeconds`, bounded at parse time.
    #[serde(default = "default_probe_timeout_seconds")]
    pub timeout_seconds: u64,
}

fn default_probe_timeout_seconds() -> u64 {
    DEFAULT_PROBE_TIMEOUT_SECONDS
}

impl AppProbeSpec {
    pub fn from_http_get(http_get: AppProbeHttpGet, timeout_seconds: u64) -> Self {
        Self {
            http_get: Some(http_get),
            tcp_socket: None,
            grpc: None,
            timeout_seconds: clamp_timeout_seconds(timeout_seconds),
        }
    }

    pub fn from_tcp_socket(tcp_socket: AppProbeTcpSocket, timeout_seconds: u64) -> Self {
        Self {
            http_get: None,
            tcp_socket: Some(tcp_socket),
            grpc: None,
            timeout_seconds: clamp_timeout_seconds(timeout_seconds),
        }
    }

    pub fn from_grpc(grpc: AppProbeGrpc, timeout_seconds: u64) -> Self {
        Self {
            http_get: None,
            tcp_socket: None,
            grpc: Some(grpc),
            timeout_seconds: clamp_timeout_seconds(timeout_seconds),
        }
    }

    /// Reject a spec that carries zero or more than one handler. The injector
    /// only ever writes exactly one; this is the consumer-side fail-closed.
    fn validate(&self, key: &str) -> Result<(), String> {
        let populated = usize::from(self.http_get.is_some())
            + usize::from(self.tcp_socket.is_some())
            + usize::from(self.grpc.is_some());
        if populated == 1 {
            Ok(())
        } else {
            Err(format!(
                "app probe '{key}' must carry exactly one of httpGet/tcpSocket/grpc, found \
{populated}"
            ))
        }
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(clamp_timeout_seconds(self.timeout_seconds))
    }
}

fn clamp_timeout_seconds(seconds: u64) -> u64 {
    seconds.clamp(1, MAX_PROBE_TIMEOUT_SECONDS)
}

/// Map key for one container/probe pair, and the tail of its rewritten path.
pub fn app_probe_key(container: &str, probe_field: &str) -> String {
    format!("{container}/{probe_field}")
}

/// Rewritten `httpGet.path` kubelet is pointed at.
pub fn app_probe_path(container: &str, probe_field: &str) -> String {
    format!("{APP_PROBE_PATH_PREFIX}{container}/{probe_field}")
}

/// Container names reach the mutating webhook BEFORE apiserver schema
/// validation, so a hand-rolled AdmissionReview can carry a name that is not a
/// DNS label. Refuse to build a URL path out of anything but the Kubernetes
/// character set rather than emitting a probe path that could be reinterpreted
/// by a URL parser.
pub fn validate_probe_container_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 63 {
        return Err(format!(
            "container name '{name}' is empty or too long to address as a rewritten kubelet \
probe target; refusing injection"
        ));
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(format!(
            "container name '{name}' is not a DNS-1123 label, so it cannot be addressed as a \
rewritten kubelet probe target; refusing injection"
        ));
    }
    Ok(())
}

/// Parse the injector-emitted `FERRUM_MESH_APP_PROBES` JSON object.
pub fn parse_app_probes(raw: &str) -> Result<BTreeMap<String, AppProbeSpec>, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(BTreeMap::new());
    }
    let parsed: BTreeMap<String, AppProbeSpec> =
        serde_json::from_str(trimmed).map_err(|e| format!("invalid {APP_PROBES_ENV} JSON: {e}"))?;
    for (key, spec) in &parsed {
        spec.validate(key)?;
        let Some((container, probe_field)) = key.split_once('/') else {
            return Err(format!(
                "app probe key '{key}' must be '<container>/<probeField>'"
            ));
        };
        validate_probe_container_name(container)?;
        if !APP_PROBE_FIELDS.contains(&probe_field) {
            return Err(format!(
                "app probe key '{key}' names an unknown probe field '{probe_field}'"
            ));
        }
    }
    Ok(parsed)
}

/// Resolve the configured probe port. `0` disables the server.
pub fn app_probe_port_from_env() -> Result<u16, String> {
    match resolve_ferrum_var(APP_PROBE_PORT_ENV) {
        Some(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Ok(DEFAULT_APP_PROBE_PORT);
            }
            trimmed
                .parse::<u16>()
                .map_err(|e| format!("invalid {APP_PROBE_PORT_ENV}='{trimmed}': {e}"))
        }
        None => Ok(DEFAULT_APP_PROBE_PORT),
    }
}

// ── Metrics ──────────────────────────────────────────────────────────────

/// Bounded probe outcome. Never carries a message or an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppProbeOutcome {
    Success,
    Failure,
    Timeout,
}

impl AppProbeOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Timeout => "timeout",
        }
    }
}

#[derive(Debug, Default)]
struct AppProbeOutcomeCounters {
    success: AtomicU64,
    failure: AtomicU64,
    timeout: AtomicU64,
}

/// Per-target counters. The label set is fixed at process start from the
/// injector-emitted target list, so cardinality is bounded by the pod's own
/// container/probe pairs and can never grow from request input.
#[derive(Debug, Default)]
pub struct AppProbeMetrics {
    counters: BTreeMap<(String, String), AppProbeOutcomeCounters>,
}

impl AppProbeMetrics {
    fn for_targets(targets: &BTreeMap<String, AppProbeSpec>) -> Self {
        let mut counters = BTreeMap::new();
        for key in targets.keys() {
            if let Some((container, probe_field)) = key.split_once('/') {
                counters.insert(
                    (container.to_string(), probe_field.to_string()),
                    AppProbeOutcomeCounters::default(),
                );
            }
        }
        Self { counters }
    }

    fn record(&self, container: &str, probe_field: &str, outcome: AppProbeOutcome) {
        // Borrowed scan rather than an allocated key tuple. The map holds one
        // entry per container/probe pair in this pod, and kubelet probe rates
        // are per-`periodSeconds`, so a linear walk is the cheaper side.
        let Some(counters) = self
            .counters
            .iter()
            .find(|(key, _)| key.0.as_str() == container && key.1.as_str() == probe_field)
            .map(|(_, counters)| counters)
        else {
            return;
        };
        let counter = match outcome {
            AppProbeOutcome::Success => &counters.success,
            AppProbeOutcome::Failure => &counters.failure,
            AppProbeOutcome::Timeout => &counters.timeout,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

static APP_PROBE_METRICS: OnceLock<Arc<AppProbeMetrics>> = OnceLock::new();

fn install_metrics(metrics: Arc<AppProbeMetrics>) {
    let _ = APP_PROBE_METRICS.set(metrics);
}

/// Render `ferrum_mesh_app_probe_total` from the live process-static counters.
///
/// Emits nothing when the probe server is not running, so a non-sidecar
/// process never advertises the family.
pub fn render_prometheus(output: &mut String, gateway_ns_label: &str) {
    let Some(metrics) = APP_PROBE_METRICS.get() else {
        return;
    };
    if metrics.counters.is_empty() {
        return;
    }
    output.push_str(
        "# HELP ferrum_mesh_app_probe_total Rewritten kubelet application probes performed by \
the sidecar against the application over loopback, by bounded outcome.\n",
    );
    output.push_str("# TYPE ferrum_mesh_app_probe_total counter\n");
    for ((container, probe_field), counters) in &metrics.counters {
        for (outcome, value) in [
            (
                AppProbeOutcome::Success,
                counters.success.load(Ordering::Relaxed),
            ),
            (
                AppProbeOutcome::Failure,
                counters.failure.load(Ordering::Relaxed),
            ),
            (
                AppProbeOutcome::Timeout,
                counters.timeout.load(Ordering::Relaxed),
            ),
        ] {
            output.push_str(&format!(
                "ferrum_mesh_app_probe_total{{container=\"{}\",probe=\"{}\",outcome=\"{}\"{}}} {}\n",
                escape_label_value(container),
                escape_label_value(probe_field),
                escape_label_value(outcome.as_str()),
                gateway_ns_label,
                value
            ));
        }
    }
}

// ── Server ───────────────────────────────────────────────────────────────

/// The rewritten-probe HTTP server. Immutable after construction.
#[derive(Debug)]
pub struct AppProbeServer {
    targets: BTreeMap<String, AppProbeSpec>,
    metrics: Arc<AppProbeMetrics>,
}

impl AppProbeServer {
    pub fn new(targets: BTreeMap<String, AppProbeSpec>) -> Self {
        let metrics = Arc::new(AppProbeMetrics::for_targets(&targets));
        Self { targets, metrics }
    }

    /// Build from `FERRUM_MESH_APP_PROBES`.
    pub fn from_env() -> Result<Self, String> {
        let raw = resolve_ferrum_var(APP_PROBES_ENV).unwrap_or_default();
        Ok(Self::new(parse_app_probes(&raw)?))
    }

    pub fn is_empty(&self) -> bool {
        self.targets.is_empty()
    }

    pub fn target_count(&self) -> usize {
        self.targets.len()
    }

    /// Map a request path to a pre-registered target.
    ///
    /// The whole admissible surface is `APP_PROBE_PATH_PREFIX` plus an EXACT
    /// map key. Nothing in the request contributes a host, port, scheme, or
    /// path to the probe that follows, so this cannot be driven as a proxy.
    pub fn resolve_target(&self, path: &str) -> Option<(&str, &str, &AppProbeSpec)> {
        let requested = path.strip_prefix(APP_PROBE_PATH_PREFIX)?;
        // Borrow the container / probe names from the REGISTERED key rather
        // than from the request, so nothing request-supplied outlives this
        // lookup or reaches a label.
        let (key, spec) = self.targets.get_key_value(requested)?;
        let (container, probe_field) = key.split_once('/')?;
        Some((container, probe_field, spec))
    }

    /// Serve one kubelet request.
    pub async fn handle_request(&self, method: &Method, path: &str) -> StatusCode {
        if method != Method::GET && method != Method::HEAD {
            return StatusCode::METHOD_NOT_ALLOWED;
        }
        let Some((container, probe_field, spec)) = self.resolve_target(path) else {
            return StatusCode::NOT_FOUND;
        };
        let outcome = run_probe(spec).await;
        self.metrics.record(container, probe_field, outcome);
        match outcome {
            AppProbeOutcome::Success => StatusCode::OK,
            AppProbeOutcome::Failure | AppProbeOutcome::Timeout => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

/// Bind the probe listener on the pod's wildcard address.
///
/// Kubelet dials `podIP:<port>`, so a loopback bind would never be reachable.
/// The dual-stack `[::]` bind (with `IPV6_V6ONLY` explicitly disabled) matches
/// the mesh capture listeners, and downgrades to the IPv4 wildcard only when
/// IPv6 is unavailable on the host.
pub fn bind_app_probe_listener(port: u16) -> Result<TcpListener, anyhow::Error> {
    let bind = crate::proxy::ProxyListenerBind {
        transparent: false,
        dual_stack: true,
    };
    let v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port);
    match crate::proxy::create_proxy_socket(v6, PROBE_LISTEN_BACKLOG, None, bind) {
        Ok(listener) => Ok(listener),
        Err(v6_error) => {
            debug!(
                error = %v6_error,
                "Mesh app-probe listener could not bind the dual-stack wildcard; \
                 retrying on the IPv4 wildcard"
            );
            let v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
            crate::proxy::create_proxy_socket(
                v4,
                PROBE_LISTEN_BACKLOG,
                None,
                crate::proxy::ProxyListenerBind {
                    transparent: false,
                    dual_stack: false,
                },
            )
        }
    }
}

/// Start the probe server from the environment.
///
/// Returns `None` when the port is `0` (disabled) or the pod has no rewritten
/// probes, so a workload that never had an HTTP/TCP/gRPC probe does not open a
/// listener at all.
pub fn start_from_env(
    shutdown: watch::Receiver<bool>,
) -> Result<Option<tokio::task::JoinHandle<()>>, anyhow::Error> {
    let port = app_probe_port_from_env().map_err(|e| anyhow::anyhow!(e))?;
    if port == 0 {
        info!(
            "{} — mesh application-probe rewrite server disabled",
            crate::secrets::report_env_assignment(APP_PROBE_PORT_ENV, "0")
        );
        return Ok(None);
    }
    let server = AppProbeServer::from_env().map_err(|e| anyhow::anyhow!(e))?;
    if server.is_empty() {
        debug!(
            "No rewritten kubelet application probes configured ({APP_PROBES_ENV} empty); \
             mesh application-probe server not started"
        );
        return Ok(None);
    }
    let target_count = server.target_count();
    let listener = bind_app_probe_listener(port)?;
    install_metrics(Arc::clone(&server.metrics));
    let server = Arc::new(server);
    info!(
        port,
        target_count, "Mesh application-probe rewrite server listening"
    );
    Ok(Some(tokio::spawn(async move {
        run_app_probe_server(listener, server, shutdown).await;
    })))
}

/// Accept loop. One task per connection; probes never run on the accept path.
pub async fn run_app_probe_server(
    listener: TcpListener,
    server: Arc<AppProbeServer>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut connections = JoinSet::new();
    let mut accept_backoff = crate::util::accept_backoff::AcceptBackoff::new();
    let mut accept_err_log = crate::util::accept_backoff::LogRateLimiter::new();
    loop {
        tokio::select! {
            result = listener.accept() => match result {
                Ok((stream, peer)) => {
                    accept_backoff.on_success();
                    let server = Arc::clone(&server);
                    connections.spawn(async move {
                        serve_app_probe_connection(stream, server, peer).await;
                    });
                }
                Err(e) => {
                    if let Some(suppressed) =
                        accept_err_log.on_event(crate::socket_opts::monotonic_now_ms())
                    {
                        warn!(
                            suppressed,
                            "Failed to accept mesh application-probe connection: {}", e
                        );
                    }
                    if let Some(delay) = accept_backoff.on_error(e.kind()) {
                        tokio::time::sleep(delay).await;
                    }
                }
            },
            _ = shutdown.changed() => {
                connections.abort_all();
                while connections.join_next().await.is_some() {}
                return;
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
}

async fn serve_app_probe_connection(
    stream: TcpStream,
    server: Arc<AppProbeServer>,
    peer: SocketAddr,
) {
    let io = TokioIo::new(stream);
    let service = service_fn(move |req: Request<hyper::body::Incoming>| {
        let server = Arc::clone(&server);
        async move {
            let status = server.handle_request(req.method(), req.uri().path()).await;
            let body = match status {
                StatusCode::OK => "ok\n",
                StatusCode::NOT_FOUND => "unknown app probe target\n",
                StatusCode::METHOD_NOT_ALLOWED => "method not allowed\n",
                _ => "app probe failed\n",
            };
            let mut response = Response::new(Full::new(Bytes::from_static(body.as_bytes())));
            *response.status_mut() = status;
            response.headers_mut().insert(
                hyper::header::CONTENT_TYPE,
                hyper::header::HeaderValue::from_static("text/plain; charset=utf-8"),
            );
            Ok::<_, std::convert::Infallible>(response)
        }
    });
    let mut builder = http1::Builder::new();
    builder.timer(hyper_util::rt::TokioTimer::new());
    builder.header_read_timeout(Duration::from_secs(PROBE_HEADER_READ_TIMEOUT_SECONDS));
    if let Err(e) = builder.serve_connection(io, service).await {
        debug!(peer = %peer, error = %e, "Mesh application-probe connection error");
    }
}

// ── Probe execution (always against 127.0.0.1) ───────────────────────────

async fn run_probe(spec: &AppProbeSpec) -> AppProbeOutcome {
    let timeout = spec.timeout();
    let result = if let Some(http_get) = &spec.http_get {
        tokio::time::timeout(timeout, probe_http_get(http_get)).await
    } else if let Some(tcp_socket) = &spec.tcp_socket {
        tokio::time::timeout(timeout, probe_tcp_socket(tcp_socket)).await
    } else if let Some(grpc) = &spec.grpc {
        tokio::time::timeout(timeout, probe_grpc(grpc, timeout)).await
    } else {
        // `parse_app_probes` refuses a handler-less spec, so this is
        // unreachable in a started server; fail closed rather than panic.
        return AppProbeOutcome::Failure;
    };
    match result {
        Ok(true) => AppProbeOutcome::Success,
        Ok(false) => AppProbeOutcome::Failure,
        Err(_) => AppProbeOutcome::Timeout,
    }
}

/// Loopback `httpGet`. Success mirrors kubelet: any 2xx or 3xx status.
async fn probe_http_get(action: &AppProbeHttpGet) -> bool {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), action.port);
    let stream = match TcpStream::connect(addr).await {
        Ok(stream) => stream,
        Err(e) => {
            debug!(port = action.port, error = %e, "App probe httpGet connect failed");
            return false;
        }
    };
    let _ = stream.set_nodelay(true);
    match action.scheme {
        AppProbeScheme::Http => send_probe_request(TokioIo::new(stream), action).await,
        AppProbeScheme::Https => {
            let Some(connector) = loopback_tls_connector() else {
                warn!(
                    port = action.port,
                    "App probe httpGet scheme is HTTPS but no TLS client configuration could be \
                     built in this process"
                );
                return false;
            };
            // Loopback only: the peer is this pod's own application container,
            // reached over 127.0.0.1, and kubelet itself does not verify an
            // HTTPS probe's certificate either. There is no name or trust
            // anchor to verify against.
            let server_name = rustls::pki_types::ServerName::IpAddress(
                rustls::pki_types::IpAddr::from(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            );
            match connector.connect(server_name, stream).await {
                Ok(tls) => send_probe_request(TokioIo::new(tls), action).await,
                Err(e) => {
                    debug!(port = action.port, error = %e, "App probe httpGet TLS handshake failed");
                    false
                }
            }
        }
    }
}

async fn send_probe_request<S>(io: TokioIo<S>, action: &AppProbeHttpGet) -> bool
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) = match hyper::client::conn::http1::handshake(io).await {
        Ok(pair) => pair,
        Err(e) => {
            debug!(port = action.port, error = %e, "App probe httpGet handshake failed");
            return false;
        }
    };
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });

    let mut path = action.path.clone();
    if !path.starts_with('/') {
        path.insert(0, '/');
    }
    let mut builder = Request::builder().method(Method::GET).uri(path);
    let default_host = action
        .host
        .as_deref()
        .filter(|host| !host.trim().is_empty())
        .unwrap_or("127.0.0.1");
    if let Ok(value) = hyper::header::HeaderValue::from_str(default_host) {
        builder = builder.header(hyper::header::HOST, value);
    }
    for header in &action.http_headers {
        let (Ok(name), Ok(value)) = (
            hyper::header::HeaderName::from_bytes(header.name.as_bytes()),
            hyper::header::HeaderValue::from_str(&header.value),
        ) else {
            debug!(
                port = action.port,
                "App probe httpGet drops a recorded header that is not valid on the wire"
            );
            continue;
        };
        // Kubelet lets `httpHeaders` override `Host`; keep that behaviour.
        builder = builder.header(name, value);
    }
    let request = match builder.body(Empty::<Bytes>::new()) {
        Ok(request) => request,
        Err(e) => {
            debug!(port = action.port, error = %e, "App probe httpGet request build failed");
            driver.abort();
            return false;
        }
    };

    let succeeded = match sender.send_request(request).await {
        Ok(response) => {
            let status = response.status();
            // Drain so the connection closes cleanly rather than being reset.
            let mut body = response.into_body();
            while let Some(Ok(_frame)) = body.frame().await {}
            status.as_u16() >= 200 && status.as_u16() < 400
        }
        Err(e) => {
            debug!(port = action.port, error = %e, "App probe httpGet request failed");
            false
        }
    };
    driver.abort();
    succeeded
}

/// Loopback `tcpSocket`. Success is a completed TCP connect, as for kubelet.
async fn probe_tcp_socket(action: &AppProbeTcpSocket) -> bool {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), action.port);
    match TcpStream::connect(addr).await {
        Ok(_) => true,
        Err(e) => {
            debug!(port = action.port, error = %e, "App probe tcpSocket connect failed");
            false
        }
    }
}

/// Loopback `grpc`, i.e. `grpc.health.v1.Health/Check`. Success is `SERVING`.
/// `GRPCAction` has no TLS knob, so kubelet's probe — and therefore this one —
/// is plaintext h2c.
async fn probe_grpc(action: &AppProbeGrpc, timeout: Duration) -> bool {
    use crate::health_check::grpc_health_v1;

    let endpoint = match tonic::transport::Endpoint::from_shared(format!(
        "http://127.0.0.1:{}",
        action.port
    )) {
        Ok(endpoint) => endpoint.timeout(timeout).connect_timeout(timeout),
        Err(e) => {
            debug!(port = action.port, error = %e, "App probe grpc endpoint invalid");
            return false;
        }
    };
    let channel = match endpoint.connect().await {
        Ok(channel) => channel,
        Err(e) => {
            debug!(port = action.port, error = %e, "App probe grpc connect failed");
            return false;
        }
    };
    let mut client = grpc_health_v1::health_client::HealthClient::new(channel);
    let request = tonic::Request::new(grpc_health_v1::HealthCheckRequest {
        service: action.service.clone().unwrap_or_default(),
    });
    match client.check(request).await {
        Ok(response) => {
            response.into_inner().status
                == grpc_health_v1::health_check_response::ServingStatus::Serving as i32
        }
        Err(e) => {
            debug!(port = action.port, error = %e, "App probe grpc check failed");
            false
        }
    }
}

/// Lazily built loopback TLS client config. Built once; `None` when the
/// process has no rustls crypto provider installed (never true in mesh mode,
/// which installs the ring/aws-lc provider during startup).
fn loopback_tls_connector() -> Option<&'static tokio_rustls::TlsConnector> {
    static CONNECTOR: OnceLock<Option<tokio_rustls::TlsConnector>> = OnceLock::new();
    CONNECTOR
        .get_or_init(|| {
            let builder = rustls::ClientConfig::builder_with_provider(
                rustls::crypto::CryptoProvider::get_default()?.clone(),
            )
            .with_safe_default_protocol_versions()
            .ok()?;
            let config = builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(LoopbackNoVerifier))
                .with_no_client_auth();
            Some(tokio_rustls::TlsConnector::from(Arc::new(config)))
        })
        .as_ref()
}

/// Certificate verifier for the loopback HTTPS probe only.
///
/// The peer is this pod's own application container over `127.0.0.1`; there is
/// no name and no trust anchor to check, and kubelet's own HTTPS probe does
/// not verify either. This verifier is reachable ONLY from
/// [`probe_http_get`] and is never installed on any mesh data path.
#[derive(Debug)]
struct LoopbackNoVerifier;

impl rustls::client::danger::ServerCertVerifier for LoopbackNoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}
