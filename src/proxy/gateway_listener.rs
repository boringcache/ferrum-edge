//! Dynamic HTTP-family listener lifecycle for Gateway API listener ports.
//!
//! Ferrum's process-wide `FERRUM_PROXY_HTTP_PORT` / `FERRUM_PROXY_HTTPS_PORT`
//! sockets serve every port-agnostic route. A Gateway API `Gateway` instead
//! declares its own listener ports (`:80`, `:443`, `:8080`, …), and port-aware
//! route identity is only real if those ports are actually bound: without a
//! socket on `:8080` a route scoped to that listener can never be reached.
//!
//! [`GatewayListenerManager`] owns that socket set. It derives the desired
//! listeners from the published [`GatewayConfig`] — every HTTP-family proxy
//! that carries a `listen_port`, classified plaintext or TLS by
//! `GatewayConfig::http_tls_listen_ports` — and reconciles the live set on
//! every config publication.
//!
//! # Lifecycle contract
//!
//! - **Startup.** The first reconcile runs before the mode reports readiness.
//!   In `file` / `database` mode a bind failure there is fatal, matching the
//!   stream-listener contract; in `dp` mode it is reported and retried on the
//!   next publication, because a data plane must not die on control-plane
//!   input.
//! - **Update.** A port whose TLS class changed is closed and rebound, because
//!   plaintext and TLS are different sockets.
//! - **Removal / withdrawal.** Routes are withdrawn by the atomic
//!   `ArcSwap` config publish that *precedes* this reconcile, so from the
//!   instant a listener leaves the config its port answers `404` — never stale
//!   routing. The socket itself closes asynchronously: the accept loop stops
//!   taking new connections as soon as it observes its per-listener shutdown
//!   signal and then drains in-flight requests under the normal graceful
//!   shutdown budget. The bounded window is therefore "already-accepted
//!   connections finish; nothing new is routed", not "traffic keeps being
//!   served".
//! - **Shutdown.** The global shutdown signal closes every managed listener and
//!   the manager awaits their drains before returning.
//!
//! # Ports this manager refuses
//!
//! A Gateway listener port that collides with a socket Ferrum already owns is
//! skipped fail-closed, never stolen:
//!
//! - anything in [`ProxyState::reserved_gateway_ports`] (the global proxy and
//!   admin HTTP/HTTPS ports and the CP gRPC port), and
//! - any port claimed by a TCP/UDP stream proxy in the same config.
//!
//! A skipped port is recorded in [`GatewayListenerManager::bind_failures`] and
//! logged, so the operator sees an unreachable listener instead of silently
//! losing one Gateway's traffic to another listener's socket.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::{Mutex, oneshot, watch};
use tracing::{error, info, warn};

use crate::config::types::GatewayConfig;
use crate::proxy::ProxyState;

/// Whether a Gateway listener port terminates TLS on the frontend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum GatewayListenerClass {
    Plaintext,
    Tls,
}

impl GatewayListenerClass {
    fn label(self) -> &'static str {
        match self {
            Self::Plaintext => "HTTP",
            Self::Tls => "HTTPS",
        }
    }
}

/// The set of Gateway API listener ports a config wants bound.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GatewayListenerPlan {
    pub ports: BTreeMap<u16, GatewayListenerClass>,
    /// Ports the config asked for that this process refuses to bind, with the
    /// reason. Surfaced rather than silently dropped.
    pub refused: BTreeMap<u16, String>,
}

impl GatewayListenerPlan {
    /// Derive the desired listener set from a published config.
    ///
    /// `reserved` is [`ProxyState::reserved_gateway_ports`] — the effective
    /// reservation for *this* process, not `EnvConfig` alone, so a pre-bound
    /// in-process harness socket is honored too.
    pub fn from_config(config: &GatewayConfig, reserved: &std::collections::HashSet<u16>) -> Self {
        let mut stream_ports: BTreeSet<u16> = BTreeSet::new();
        for proxy in &config.proxies {
            if proxy.dispatch_kind.is_stream()
                && let Some(port) = proxy.listen_port
            {
                stream_ports.insert(port);
            }
        }

        let mut ports: BTreeMap<u16, GatewayListenerClass> = BTreeMap::new();
        let mut refused: BTreeMap<u16, String> = BTreeMap::new();
        for proxy in &config.proxies {
            if proxy.dispatch_kind.is_stream() {
                continue;
            }
            let Some(port) = proxy.listen_port else {
                continue;
            };
            if port == 0 {
                continue;
            }
            if reserved.contains(&port) {
                refused.entry(port).or_insert_with(|| {
                    format!(
                        "port {port} is already owned by a global proxy/admin/control-plane \
                         listener; the Gateway listener is not bound"
                    )
                });
                continue;
            }
            if stream_ports.contains(&port) {
                refused.entry(port).or_insert_with(|| {
                    format!(
                        "port {port} is claimed by a TCP/UDP stream proxy in the same config; \
                         the HTTP-family Gateway listener is not bound"
                    )
                });
                continue;
            }
            // TLS class comes from this proxy's own namespace-qualified entry.
            let class = if config
                .http_tls_listen_ports
                .contains(&(proxy.namespace.clone(), port))
            {
                GatewayListenerClass::Tls
            } else {
                GatewayListenerClass::Plaintext
            };
            if let Some(existing) = ports.insert(port, class)
                && existing != class
            {
                // One socket cannot be both plaintext and TLS. The Gateway API
                // translator refuses this at admission, so reaching it means a
                // hand-authored config: refuse the port outright rather than
                // letting whichever proxy happened to sort first decide the
                // socket's protocol for the other.
                refused.entry(port).or_insert_with(|| {
                    format!(
                        "port {port} is claimed as both plaintext and TLS by HTTP-family proxies \
                         in this config; one socket cannot serve both, so the listener is not bound"
                    )
                });
            }
        }
        // Every refusal reason wins over any class this port also resolved to.
        ports.retain(|port, _| !refused.contains_key(port));
        Self { ports, refused }
    }
}

/// A refusal or bind failure for one Gateway listener port.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GatewayListenerBindFailure {
    pub port: u16,
    pub error: String,
}

struct LiveListener {
    class: GatewayListenerClass,
    shutdown_tx: watch::Sender<bool>,
    task: tokio::task::JoinHandle<Result<(), anyhow::Error>>,
}

/// TLS material for Gateway listeners that terminate TLS.
///
/// The dynamic slot is preferred so frontend cert rotation reaches these
/// sockets exactly as it reaches the global HTTPS listener.
#[derive(Clone, Default)]
pub struct GatewayListenerTls {
    pub static_config: Option<Arc<rustls::ServerConfig>>,
    pub reload_slot: Option<crate::tls::SharedFrontendTls>,
}

impl GatewayListenerTls {
    fn is_configured(&self) -> bool {
        self.static_config.is_some() || self.reload_slot.is_some()
    }
}

pub struct GatewayListenerManager {
    state: ProxyState,
    bind_addr: std::net::IpAddr,
    tls: GatewayListenerTls,
    listeners: Mutex<BTreeMap<u16, LiveListener>>,
    /// Draining listeners whose port left the config. Awaited at shutdown so a
    /// removal never leaks a task past process exit.
    draining: Mutex<Vec<tokio::task::JoinHandle<Result<(), anyhow::Error>>>>,
    bind_failures: arc_swap::ArcSwap<Vec<GatewayListenerBindFailure>>,
}

impl GatewayListenerManager {
    pub fn new(state: ProxyState, bind_addr: std::net::IpAddr, tls: GatewayListenerTls) -> Self {
        Self {
            state,
            bind_addr,
            tls,
            listeners: Mutex::new(BTreeMap::new()),
            draining: Mutex::new(Vec::new()),
            bind_failures: arc_swap::ArcSwap::from_pointee(Vec::new()),
        }
    }

    /// Ports currently bound by this manager, for tests and diagnostics.
    pub async fn active_ports(&self) -> Vec<u16> {
        self.listeners.lock().await.keys().copied().collect()
    }

    /// Most recent refusals / bind failures. Lock-free read.
    pub fn bind_failures(&self) -> Arc<Vec<GatewayListenerBindFailure>> {
        self.bind_failures.load_full()
    }

    /// Bind newly-declared Gateway listener ports and close withdrawn ones.
    ///
    /// Returns the failures observed in this pass. Callers decide severity:
    /// fatal at startup in file/database mode, advisory everywhere else.
    pub async fn reconcile(&self) -> Vec<GatewayListenerBindFailure> {
        let config = self.state.config.load_full();
        let plan =
            GatewayListenerPlan::from_config(&config, self.state.reserved_gateway_ports.as_ref());
        let mut failures: Vec<GatewayListenerBindFailure> = plan
            .refused
            .iter()
            .map(|(port, error)| GatewayListenerBindFailure {
                port: *port,
                error: error.clone(),
            })
            .collect();
        for failure in &failures {
            warn!(
                port = failure.port,
                "Gateway API listener refused: {}", failure.error
            );
        }

        let mut live = self.listeners.lock().await;

        // Close listeners whose port left the config, and rebind ports whose
        // TLS class changed — a socket is plaintext or TLS, never both.
        let stale: Vec<u16> = live
            .iter()
            .filter_map(|(port, listener)| {
                (plan.ports.get(port) != Some(&listener.class)).then_some(*port)
            })
            .collect();
        for port in stale {
            if let Some(listener) = live.remove(&port) {
                info!(
                    port,
                    "Closing Gateway API {} listener — no longer declared by the published config",
                    listener.class.label()
                );
                let _ = listener.shutdown_tx.send(true);
                self.draining.lock().await.push(listener.task);
            }
        }

        for (port, class) in &plan.ports {
            if live.contains_key(port) {
                continue;
            }
            if *class == GatewayListenerClass::Tls && !self.tls.is_configured() {
                let error = format!(
                    "port {port} is a TLS-terminating Gateway listener but frontend TLS is not \
                     configured on this gateway; the listener is not bound"
                );
                warn!(port = *port, "Gateway API listener refused: {error}");
                failures.push(GatewayListenerBindFailure { port: *port, error });
                continue;
            }
            match self.spawn_listener(*port, *class).await {
                Ok(listener) => {
                    live.insert(*port, listener);
                }
                Err(error) => {
                    error!(port = *port, "Gateway API listener bind failed: {error}");
                    failures.push(GatewayListenerBindFailure { port: *port, error });
                }
            }
        }
        drop(live);

        self.bind_failures.store(Arc::new(failures.clone()));
        failures
    }

    async fn spawn_listener(
        &self,
        port: u16,
        class: GatewayListenerClass,
    ) -> Result<LiveListener, String> {
        let addr = SocketAddr::new(self.bind_addr, port);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (started_tx, started_rx) = oneshot::channel();
        let state = self.state.clone();
        let tls = self.tls.clone();
        let task = tokio::spawn(async move {
            match class {
                GatewayListenerClass::Plaintext => {
                    crate::proxy::start_proxy_listener_with_tls_and_signal(
                        addr,
                        state,
                        shutdown_rx,
                        None,
                        Some(started_tx),
                    )
                    .await
                }
                GatewayListenerClass::Tls => {
                    if let Some(slot) = tls.reload_slot {
                        crate::proxy::start_proxy_listener_with_dynamic_tls_and_signal(
                            addr,
                            state,
                            shutdown_rx,
                            slot,
                            Some(started_tx),
                        )
                        .await
                    } else {
                        crate::proxy::start_proxy_listener_with_tls_and_signal(
                            addr,
                            state,
                            shutdown_rx,
                            tls.static_config,
                            Some(started_tx),
                        )
                        .await
                    }
                }
            }
        });

        // The signal is sent only after every accept socket is bound, and the
        // sender is dropped when the listener returns early — so a closed
        // channel is exactly "bind failed", with the real error in the task.
        match started_rx.await {
            Ok(()) => {
                info!(
                    port,
                    "Gateway API {} listener started on {addr}",
                    class.label()
                );
                Ok(LiveListener {
                    class,
                    shutdown_tx,
                    task,
                })
            }
            Err(_) => Err(match task.await {
                Ok(Err(err)) => format!("{err:#}"),
                Ok(Ok(())) => "listener exited before reporting readiness".to_string(),
                Err(err) => format!("listener task panicked: {err}"),
            }),
        }
    }

    /// Close every managed listener and await its drain.
    pub async fn shutdown_all(&self) {
        let listeners: Vec<LiveListener> = {
            let mut live = self.listeners.lock().await;
            std::mem::take(&mut *live).into_values().collect()
        };
        let mut tasks: Vec<tokio::task::JoinHandle<Result<(), anyhow::Error>>> = Vec::new();
        for listener in listeners {
            let _ = listener.shutdown_tx.send(true);
            tasks.push(listener.task);
        }
        tasks.append(&mut *self.draining.lock().await);
        for task in tasks {
            if let Err(err) = task.await {
                warn!("Gateway API listener task ended abnormally: {err}");
            }
        }
    }

    /// Drive the manager for the life of the process.
    ///
    /// The initial reconcile has already run; this loop reconciles on every
    /// subsequent config publication, retries outstanding bind failures on a
    /// slow tick, and shuts every listener down on the global shutdown signal.
    ///
    /// A bind failure is deliberately **not** fatal, in any mode. A Gateway
    /// listener port is control-plane input (or, for `:80`/`:443`, a port the
    /// container may lack `CAP_NET_BIND_SERVICE` for), so killing the gateway
    /// would take down every healthy listener over one unbindable port. The
    /// failure is loud, surfaced on [`Self::bind_failures`], and retried; the
    /// affected routes stay unreachable, which is fail-closed — no request is
    /// ever routed to a listener that did not bind.
    pub async fn run(
        self: Arc<Self>,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<(), anyhow::Error> {
        let mut revisions = self.state.subscribe_config_revision();
        let mut retry = tokio::time::interval(BIND_RETRY_INTERVAL);
        retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        retry.tick().await; // the first tick completes immediately
        loop {
            if *shutdown.borrow() {
                break;
            }
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                changed = revisions.changed() => {
                    if changed.is_err() {
                        // The publisher is gone; nothing more can change.
                        break;
                    }
                    self.reconcile().await;
                }
                _ = retry.tick() => {
                    if !self.bind_failures().is_empty() {
                        self.reconcile().await;
                    }
                }
            }
        }
        self.shutdown_all().await;
        Ok(())
    }
}

/// How often an unbound Gateway listener port is retried.
const BIND_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);
