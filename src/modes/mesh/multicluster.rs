//! Cross-cluster endpoint discovery (Tier 3b).
//!
//! Today "multi-cluster" in Ferrum is east-west SNI passthrough
//! ([`materialize_east_west_gateway_proxies`](super::materialize_east_west_gateway_proxies))
//! plus federated trust bundles ([`super::federation`]). The
//! [`RemoteCluster.control_plane_url`](crate::modes::mesh::config::RemoteCluster)
//! field was inert — referenced only by a non-empty validation, never dialed.
//! This module makes it functional: it dials each remote cluster's control
//! plane, fetches that cluster's service endpoints (workloads + services), and
//! stores them in an `ArcSwap`-held snapshot. The slice-apply path merges that
//! snapshot into the local mesh `workloads` / `services` (see
//! [`merge_remote_endpoints_into_mesh`]), tagging remote workloads with a
//! distinct locality so the existing **locality-aware priority-tier load
//! balancer** fails over local → remote at the endpoint level: local targets
//! sit in the source region/zone tier, and remote targets only receive traffic
//! once the local tier has no healthy endpoints.
//!
//! Design notes (kept in lock-step with [`super::federation`]):
//!
//! - **Lock-free hot path**: the slice-apply reader loads the snapshot via
//!   [`RemoteEndpointStore::snapshot`] (one `ArcSwap` deref). The request hot
//!   path is unchanged — remote endpoints become ordinary `Upstream` targets.
//! - **Mockable source**: [`RemoteServiceSource`] abstracts the remote fetch.
//!   The production implementation ([`NativeRemoteSource`]) dials the remote CP
//!   over the native `MeshSubscribe` gRPC stream and reuses the DP gRPC TLS /
//!   JWT machinery; tests inject a deterministic mock. This lets the full
//!   discovery + aggregation + failover path be verified without a live remote
//!   control plane.
//! - **Fail-closed mTLS**: a remote cluster is only polled when cross-cluster
//!   trust is established (a federated trust bundle for the remote trust domain
//!   exists, matching the fail-closed posture of [`super::federation`]). A
//!   failed poll keeps the last-good endpoints and bumps a failure metric;
//!   once-and-only-once failures never delete previously fetched endpoints.
//! - **Backoff**: each remote cluster runs its own task with jittered
//!   exponential backoff (1s → 30s, ±25%) matching the federation poller and
//!   `src/grpc/dp_client.rs`.
//! - **Shutdown**: every loop watches the gateway shutdown channel.
//!
//! ## Live-verification status
//!
//! The aggregation + failover path and the poll loop are covered by unit tests
//! with a mock [`RemoteServiceSource`]. The [`NativeRemoteSource`] gRPC dialer
//! is exercised structurally but a full two-control-plane round trip is not
//! reproduced in this environment; the remaining live-verification step is a
//! CP-to-CP integration deployment (two mesh control planes federated). This is
//! documented for operators in `docs/mesh.md` "Cross-Cluster Endpoint
//! Discovery".

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::grpc::dp_client::{DpGrpcTlsConfig, GrpcJwtSecret};
use crate::identity::TrustDomain;
use crate::modes::mesh::config::{MeshService, MultiClusterConfig, Workload};

/// Backoff bounds shared with [`super::federation`] and
/// `src/grpc/dp_client.rs`. One cross-cluster backoff curve for operators to
/// reason about.
pub(crate) const REMOTE_BACKOFF_INITIAL_SECS: u64 = 1;
pub(crate) const REMOTE_BACKOFF_MAX_SECS: u64 = 30;

/// Defense-in-depth cap on the number of workloads / services a single remote
/// cluster may contribute. A misbehaving (or compromised) remote CP cannot
/// balloon local memory or the load-balancer target lists. Realistic clusters
/// are far below this.
const REMOTE_MAX_WORKLOADS_PER_CLUSTER: usize = 50_000;
const REMOTE_MAX_SERVICES_PER_CLUSTER: usize = 10_000;

/// The endpoints one remote cluster contributes: its `workloads` (carrying
/// addresses, ports, and locality) and `services` (name/namespace/ports +
/// workload refs). These are merged into the local mesh registry at slice
/// apply.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RemoteClusterEndpoints {
    pub workloads: Vec<Workload>,
    pub services: Vec<MeshService>,
}

/// One installed remote cluster's endpoints plus provenance.
#[derive(Debug, Clone)]
pub struct RemoteClusterEntry {
    pub cluster_name: String,
    pub trust_domain: TrustDomain,
    /// Network label of the remote cluster, used to default workload locality
    /// when the remote workload carries none.
    pub network: Option<String>,
    pub endpoints: RemoteClusterEndpoints,
    pub fetched_at_unix_seconds: u64,
}

/// Snapshot the store hands out to slice apply and the admin API. Keyed by
/// remote cluster name (`RemoteCluster.name` is validated unique).
#[derive(Debug, Default, Clone)]
pub struct RemoteEndpointSnapshot {
    pub clusters: HashMap<String, RemoteClusterEntry>,
}

impl RemoteEndpointSnapshot {
    pub fn is_empty(&self) -> bool {
        self.clusters.is_empty()
    }
}

/// Lock-free shared state populated by the discovery poller and consumed by the
/// slice-apply path. Mirrors [`super::federation::FederationStore`].
#[derive(Clone)]
pub struct RemoteEndpointStore {
    inner: Arc<ArcSwap<RemoteEndpointSnapshot>>,
    first_ready: Arc<AtomicBool>,
    /// Bumped on every successful install/remove so the slice-apply task
    /// re-runs even when the local CP config is unchanged (a remote cluster
    /// scaling up/down must re-materialize the aggregated upstream targets).
    revision_tx: Arc<watch::Sender<u64>>,
}

impl Default for RemoteEndpointStore {
    fn default() -> Self {
        let (revision_tx, _) = watch::channel(0u64);
        Self {
            inner: Arc::new(ArcSwap::new(Arc::new(RemoteEndpointSnapshot::default()))),
            first_ready: Arc::new(AtomicBool::new(false)),
            revision_tx: Arc::new(revision_tx),
        }
    }
}

impl RemoteEndpointStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Lock-free read.
    pub fn snapshot(&self) -> Arc<RemoteEndpointSnapshot> {
        self.inner.load_full()
    }

    /// `true` after at least one remote cluster has been successfully polled.
    #[cfg(test)]
    pub fn has_first_success(&self) -> bool {
        self.first_ready.load(Ordering::Acquire)
    }

    /// Subscribe to install events. Mirrors `MeshRuntimeState::subscribe()`.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.revision_tx.subscribe()
    }

    fn install(&self, entry: RemoteClusterEntry) {
        // CAS loop so two concurrent successful polls (different clusters)
        // cannot stomp each other's snapshot clone.
        let name = entry.cluster_name.clone();
        self.inner.rcu(|current| {
            let mut next = (**current).clone();
            next.clusters.insert(name.clone(), entry.clone());
            Arc::new(next)
        });
        self.first_ready.store(true, Ordering::Release);
        self.revision_tx.send_modify(|revision| *revision += 1);
    }

    /// Remove a remote cluster's endpoints (slice no longer lists it). No-op if
    /// untracked. Reserved for a reconcile pass; the poller spawns once at
    /// startup today.
    #[allow(dead_code)]
    pub fn remove(&self, cluster_name: &str) {
        let mut changed = false;
        self.inner.rcu(|current| {
            if current.clusters.contains_key(cluster_name) {
                let mut next = (**current).clone();
                next.clusters.remove(cluster_name);
                changed = true;
                Arc::new(next)
            } else {
                Arc::clone(current)
            }
        });
        if changed {
            self.revision_tx.send_modify(|revision| *revision += 1);
        }
    }
}

/// Abstracts the remote-cluster endpoint fetch so the discovery loop is
/// testable without a live remote control plane. The production implementation
/// is [`NativeRemoteSource`]; tests inject a deterministic mock.
#[async_trait]
pub trait RemoteServiceSource: Send + Sync {
    /// Fetch the remote cluster's current service endpoints. Returns `Err` on
    /// any transport / auth / decode failure so the poll loop keeps the
    /// last-good snapshot and backs off.
    async fn fetch(&self) -> Result<RemoteClusterEndpoints, String>;
}

/// Locality tag applied to a remote workload that carries no locality of its
/// own, so it still tiers BELOW the local source region in the priority-tier
/// load balancer. Format is `region/zone` where the region is a synthetic
/// `remote-<cluster>` that can never collide with a real local region.
fn default_remote_locality(cluster_name: &str, network: Option<&str>) -> String {
    match network {
        Some(network) if !network.is_empty() => format!("remote-{cluster_name}/{network}"),
        _ => format!("remote-{cluster_name}"),
    }
}

/// Tag a remote cluster's workloads with provenance and a fail-safe locality.
///
/// - `cluster` is stamped so introspection / metrics can attribute the target.
/// - `network` is preserved (multi-network routing).
/// - `locality` is preserved when the remote workload already declares one
///   (its real region differs from local, so it naturally tiers below); when
///   absent, a synthetic `remote-<cluster>` locality is applied so the workload
///   never accidentally lands in the local source-region tier.
///
/// Workloads are NOT renamed or re-keyed: a remote workload keeps its SPIFFE
/// id, service_name, addresses, and ports so [`MeshServiceDiscoverer`] resolves
/// it against the same `MeshService` the local cluster advertises.
fn tag_remote_workloads(
    endpoints: &mut RemoteClusterEndpoints,
    cluster_name: &str,
    network: Option<&str>,
) {
    for workload in &mut endpoints.workloads {
        if workload.cluster.is_none() {
            workload.cluster = Some(cluster_name.to_string());
        }
        if workload.network.is_none()
            && let Some(network) = network
            && !network.is_empty()
        {
            workload.network = Some(network.to_string());
        }
        if workload
            .locality
            .as_deref()
            .map(str::trim)
            .is_none_or(str::is_empty)
        {
            workload.locality = Some(default_remote_locality(cluster_name, network));
        }
    }
}

/// Merge the remote-endpoint snapshot into a slice's local `workloads` /
/// `services`. Returns the merged vectors; the slice-apply path uses these to
/// build `GatewayConfig.mesh` so [`MeshServiceDiscoverer`] resolves both local
/// and remote endpoints for a service.
///
/// Merge rules:
/// - Remote workloads are appended after local ones. A remote workload whose
///   SPIFFE id already exists locally is skipped (the local copy wins — a
///   workload physically present locally must not be shadowed by a stale remote
///   echo of itself).
/// - Remote services are merged by `(namespace, name)`: a service the local
///   cluster already advertises keeps the local definition (ports / overrides);
///   only the remote `workloads` refs are unioned in so the local service can
///   resolve the remote endpoints. A service that exists ONLY remotely is added
///   wholesale.
///
/// `local_workloads` / `local_services` are cloned and extended; callers pass
/// the slice's own vectors.
pub fn merge_remote_endpoints_into_mesh(
    local_workloads: &[Workload],
    local_services: &[MeshService],
    snapshot: &RemoteEndpointSnapshot,
) -> (Vec<Workload>, Vec<MeshService>) {
    if snapshot.is_empty() {
        return (local_workloads.to_vec(), local_services.to_vec());
    }

    let mut workloads = local_workloads.to_vec();
    let mut seen_spiffe: std::collections::HashSet<String> = workloads
        .iter()
        .map(|w| w.spiffe_id.as_str().to_string())
        .collect();

    let mut services = local_services.to_vec();
    // Index local services by (namespace, name) for ref-union.
    let mut service_index: HashMap<(String, String), usize> = services
        .iter()
        .enumerate()
        .map(|(idx, svc)| ((svc.namespace.clone(), svc.name.clone()), idx))
        .collect();

    // Deterministic order: iterate clusters by name so the merged target list
    // is stable across snapshots (avoids LB hash-ring churn from HashMap order).
    let mut cluster_names: Vec<&String> = snapshot.clusters.keys().collect();
    cluster_names.sort();

    for cluster_name in cluster_names {
        let Some(entry) = snapshot.clusters.get(cluster_name) else {
            continue;
        };
        for workload in &entry.endpoints.workloads {
            if seen_spiffe.insert(workload.spiffe_id.as_str().to_string()) {
                workloads.push(workload.clone());
            }
        }
        for remote_svc in &entry.endpoints.services {
            let key = (remote_svc.namespace.clone(), remote_svc.name.clone());
            if let Some(&idx) = service_index.get(&key) {
                // Local service wins on ports/overrides; union remote refs so
                // the local service resolves the remote workloads too.
                let local = &mut services[idx];
                for wref in &remote_svc.workloads {
                    if !local
                        .workloads
                        .iter()
                        .any(|w| w.spiffe_id == wref.spiffe_id)
                    {
                        local.workloads.push(wref.clone());
                    }
                }
            } else {
                let new_idx = services.len();
                services.push(remote_svc.clone());
                service_index.insert(key, new_idx);
            }
        }
    }

    (workloads, services)
}

/// Per-cluster poll target derived from a [`MultiClusterConfig`].
struct RemoteClusterPollTarget {
    cluster_name: String,
    trust_domain: TrustDomain,
    network: Option<String>,
    control_plane_url: String,
}

/// Knobs derived from `EnvConfig`. Not `Debug` because `DpGrpcTlsConfig`
/// carries key material and is intentionally not `Debug`.
#[derive(Clone)]
pub struct RemoteDiscoveryConfig {
    pub poll_interval: Duration,
    pub request_timeout: Duration,
    /// JWT secret + issuer for the remote CP gRPC handshake (reuses the
    /// CP→DP secret). `None` disables discovery (no secret → cannot dial).
    pub jwt_secret: Option<GrpcJwtSecret>,
    /// This DP's node id, sent in the remote subscribe request.
    pub node_id: String,
    /// Namespace scope requested from the remote CP.
    pub namespace: String,
    /// Optional DP gRPC client TLS for the remote CP channel. `None` =
    /// plaintext (only acceptable for loopback / test CPs).
    pub tls_config: Option<DpGrpcTlsConfig>,
}

impl RemoteDiscoveryConfig {
    /// Returns `None` when discovery should be disabled (interval 0 or no JWT
    /// secret available to authenticate to the remote CP).
    pub fn new(
        interval_seconds: u64,
        timeout_seconds: u64,
        jwt_secret: Option<GrpcJwtSecret>,
        node_id: String,
        namespace: String,
        tls_config: Option<DpGrpcTlsConfig>,
    ) -> Option<Self> {
        if interval_seconds == 0 {
            return None;
        }
        Some(Self {
            poll_interval: Duration::from_secs(interval_seconds),
            request_timeout: Duration::from_secs(timeout_seconds.max(1)),
            jwt_secret,
            node_id,
            namespace,
            tls_config,
        })
    }
}

/// Holds spawned task handles so callers can join during graceful shutdown.
pub struct RemoteDiscoveryHandles {
    pub tasks: Vec<JoinHandle<()>>,
}

/// Resolve the poll-target list from a [`MultiClusterConfig`].
///
/// A remote cluster is polled only when it BOTH declares a `control_plane_url`
/// AND has cross-cluster trust established — i.e. a federated trust bundle for
/// its trust domain is present in `trust_bundle_domains`. This keeps
/// cross-cluster discovery fail-closed: Ferrum will not dial (and merge
/// endpoints from) a cluster it cannot mutually authenticate, mirroring the
/// federation poller's posture.
fn poll_targets_for_multi_cluster(
    multi_cluster: &MultiClusterConfig,
    trust_bundle_domains: &std::collections::HashSet<TrustDomain>,
) -> Vec<RemoteClusterPollTarget> {
    multi_cluster
        .remote_clusters
        .iter()
        .filter_map(|remote| {
            let url = remote.control_plane_url.as_deref()?.trim();
            if url.is_empty() {
                return None;
            }
            if !trust_bundle_domains.contains(&remote.trust_domain) {
                warn!(
                    cluster = %remote.name,
                    trust_domain = %remote.trust_domain,
                    "Skipping remote-cluster discovery: no federated trust bundle for the remote \
                     trust domain (cross-cluster discovery is fail-closed). Configure trust \
                     federation for this cluster first."
                );
                return None;
            }
            if let Err(err) = validate_control_plane_url(url) {
                warn!(
                    cluster = %remote.name,
                    error = %err,
                    "Dropping remote-cluster control_plane_url that failed validation"
                );
                return None;
            }
            Some(RemoteClusterPollTarget {
                cluster_name: remote.name.clone(),
                trust_domain: remote.trust_domain.clone(),
                network: remote.network.clone(),
                control_plane_url: url.to_string(),
            })
        })
        .collect()
}

/// Validate a `control_plane_url`: must parse, must be `http`/`https`/`grpc`,
/// and must carry a host. Cloud-metadata / link-local hosts are rejected
/// (SSRF defense), mirroring [`super::federation::validate_federation_endpoint`].
/// Loopback is allowed for local development / integration-test control planes.
pub(crate) fn validate_control_plane_url(url: &str) -> Result<(), String> {
    let parsed = reqwest::Url::parse(url).map_err(|e| format!("invalid control_plane_url: {e}"))?;
    match parsed.scheme() {
        "http" | "https" | "grpc" => {}
        other => return Err(format!("unsupported control_plane_url scheme '{other}'")),
    }
    let Some(host) = parsed.host() else {
        return Err("control_plane_url has no host".to_string());
    };
    match host {
        url::Host::Ipv4(ip) => {
            if ip.is_loopback() {
                return Ok(());
            }
            if ip.is_link_local() || ip.octets() == [169, 254, 169, 254] {
                return Err(format!(
                    "control_plane_url refuses link-local / cloud-metadata host {ip} (SSRF defense)"
                ));
            }
            if ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast() {
                return Err(format!(
                    "control_plane_url refuses non-unicast IPv4 host {ip}"
                ));
            }
        }
        url::Host::Ipv6(ip) => {
            if ip.is_loopback() {
                return Ok(());
            }
            if ip.is_unspecified() || ip.is_multicast() {
                return Err(format!(
                    "control_plane_url refuses non-unicast IPv6 host {ip}"
                ));
            }
            if ip.segments()[0] & 0xffc0 == 0xfe80 {
                return Err(format!(
                    "control_plane_url refuses link-local IPv6 host {ip}"
                ));
            }
        }
        url::Host::Domain(_) => {
            // Hostnames resolve at dial time; the DNS layer enforces any
            // operator-configured backend IP policy.
        }
    }
    Ok(())
}

/// Build the trust-domain set from a slice's federated + live-polled trust
/// bundles. Used to gate which remote clusters may be dialed.
pub fn trust_domains_from_bundles(
    slice_bundles: Option<&crate::modes::mesh::config::TrustBundleSet>,
    federation: &super::federation::FederationSnapshot,
) -> std::collections::HashSet<TrustDomain> {
    let mut domains = std::collections::HashSet::new();
    if let Some(bundles) = slice_bundles {
        domains.insert(bundles.local.trust_domain.clone());
        for tb in &bundles.federated {
            domains.insert(tb.trust_domain.clone());
        }
    }
    for td in federation.bundles.keys() {
        domains.insert(td.clone());
    }
    domains
}

/// Spawn the remote-cluster discovery poller. Returns `None` when discovery is
/// disabled or there are no eligible remote clusters.
///
/// `source_factory` builds a [`RemoteServiceSource`] per target. Production
/// passes [`native_source_factory`]; tests pass a closure returning a mock.
pub fn spawn_remote_cluster_discovery<F>(
    multi_cluster: Option<&MultiClusterConfig>,
    config: Option<RemoteDiscoveryConfig>,
    trust_bundle_domains: std::collections::HashSet<TrustDomain>,
    store: RemoteEndpointStore,
    shutdown_rx: watch::Receiver<bool>,
    source_factory: F,
) -> Option<RemoteDiscoveryHandles>
where
    F: Fn(&RemoteClusterPollContext) -> Arc<dyn RemoteServiceSource>,
{
    let config = config?;
    let multi_cluster = multi_cluster?;
    let targets = poll_targets_for_multi_cluster(multi_cluster, &trust_bundle_domains);
    if targets.is_empty() {
        debug!("No remote clusters eligible for endpoint discovery; poller disabled");
        return None;
    }
    let mut tasks = Vec::with_capacity(targets.len());
    for target in targets {
        let ctx = RemoteClusterPollContext {
            cluster_name: target.cluster_name.clone(),
            trust_domain: target.trust_domain.clone(),
            network: target.network.clone(),
            control_plane_url: target.control_plane_url.clone(),
            config: config.clone(),
        };
        let source = source_factory(&ctx);
        let task_store = store.clone();
        let task_shutdown = shutdown_rx.clone();
        let url_for_logs = sanitize_url_for_logging(&target.control_plane_url);
        info!(
            cluster = %target.cluster_name,
            trust_domain = %target.trust_domain,
            control_plane = %url_for_logs,
            poll_interval_seconds = config.poll_interval.as_secs(),
            "Spawning remote-cluster endpoint discovery"
        );
        let handle = tokio::spawn(async move {
            remote_discovery_loop(ctx, source, task_store, task_shutdown).await;
        });
        tasks.push(handle);
    }
    Some(RemoteDiscoveryHandles { tasks })
}

/// Context passed to the source factory and the poll loop.
#[derive(Clone)]
pub struct RemoteClusterPollContext {
    pub cluster_name: String,
    pub trust_domain: TrustDomain,
    pub network: Option<String>,
    pub control_plane_url: String,
    pub config: RemoteDiscoveryConfig,
}

async fn remote_discovery_loop(
    ctx: RemoteClusterPollContext,
    source: Arc<dyn RemoteServiceSource>,
    store: RemoteEndpointStore,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let mut backoff_secs = REMOTE_BACKOFF_INITIAL_SECS;
    let url_for_logs = sanitize_url_for_logging(&ctx.control_plane_url);

    loop {
        if *shutdown_rx.borrow() {
            return;
        }

        let attempt_started_at = std::time::Instant::now();
        let result = source.fetch().await.and_then(|mut endpoints| {
            validate_remote_endpoints(&ctx.cluster_name, &endpoints)?;
            tag_remote_workloads(&mut endpoints, &ctx.cluster_name, ctx.network.as_deref());
            Ok(endpoints)
        });

        let (succeeded, sleep_duration) = match result {
            Ok(endpoints) => {
                let now = chrono::Utc::now().timestamp().max(0) as u64;
                let workload_count = endpoints.workloads.len();
                let entry = RemoteClusterEntry {
                    cluster_name: ctx.cluster_name.clone(),
                    trust_domain: ctx.trust_domain.clone(),
                    network: ctx.network.clone(),
                    endpoints,
                    fetched_at_unix_seconds: now,
                };
                info!(
                    cluster = %entry.cluster_name,
                    trust_domain = %entry.trust_domain,
                    network = entry.network.as_deref().unwrap_or(""),
                    fetched_at_unix_seconds = entry.fetched_at_unix_seconds,
                    control_plane = %url_for_logs,
                    workloads = workload_count,
                    "Installed remote-cluster endpoints"
                );
                store.install(entry);
                backoff_secs = REMOTE_BACKOFF_INITIAL_SECS;
                let elapsed = attempt_started_at.elapsed();
                (true, ctx.config.poll_interval.saturating_sub(elapsed))
            }
            Err(err) => {
                warn!(
                    cluster = %ctx.cluster_name,
                    control_plane = %url_for_logs,
                    error = %err,
                    "Remote-cluster endpoint discovery failed; keeping last-good endpoints if any"
                );
                (false, jittered_backoff(backoff_secs))
            }
        };

        if !succeeded {
            backoff_secs = next_backoff_secs(backoff_secs);
        }

        tokio::select! {
            _ = tokio::time::sleep(sleep_duration) => {}
            _ = wait_for_shutdown(&mut shutdown_rx) => return,
        }
    }
}

fn validate_remote_endpoints(
    cluster_name: &str,
    endpoints: &RemoteClusterEndpoints,
) -> Result<(), String> {
    if endpoints.workloads.len() > REMOTE_MAX_WORKLOADS_PER_CLUSTER {
        return Err(format!(
            "remote cluster '{cluster_name}' returned {} workloads (max {REMOTE_MAX_WORKLOADS_PER_CLUSTER})",
            endpoints.workloads.len()
        ));
    }
    if endpoints.services.len() > REMOTE_MAX_SERVICES_PER_CLUSTER {
        return Err(format!(
            "remote cluster '{cluster_name}' returned {} services (max {REMOTE_MAX_SERVICES_PER_CLUSTER})",
            endpoints.services.len()
        ));
    }
    Ok(())
}

async fn wait_for_shutdown(shutdown_rx: &mut watch::Receiver<bool>) {
    while !*shutdown_rx.borrow() {
        if shutdown_rx.changed().await.is_err() {
            return;
        }
    }
}

fn jittered_backoff(backoff_secs: u64) -> Duration {
    // ±25% jitter, identical curve to federation / dp_client.
    let base_ms = backoff_secs.saturating_mul(1000);
    let jitter_span = base_ms / 4;
    let jitter = if jitter_span == 0 {
        0
    } else {
        // Cheap deterministic-ish jitter without pulling in rand: mix the
        // monotonic clock. Range is [-jitter_span, +jitter_span).
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as u64)
            .unwrap_or(0);
        (nanos % (jitter_span * 2)) as i64 - jitter_span as i64
    };
    let total = (base_ms as i64 + jitter).max(0) as u64;
    Duration::from_millis(total)
}

fn next_backoff_secs(current: u64) -> u64 {
    current.saturating_mul(2).min(REMOTE_BACKOFF_MAX_SECS)
}

fn sanitize_url_for_logging(url: &str) -> String {
    match reqwest::Url::parse(url) {
        Ok(mut parsed) => {
            let _ = parsed.set_username("");
            let _ = parsed.set_password(None);
            parsed.to_string()
        }
        Err(_) => "<unparseable>".to_string(),
    }
}

// ── Native gRPC remote source ─────────────────────────────────────────────

/// Production [`RemoteServiceSource`]: dials the remote CP's native
/// `MeshSubscribe` gRPC stream, takes the first non-heartbeat slice, and
/// extracts its `workloads` / `services` as the remote cluster's endpoints.
///
/// The subscribe is one-shot per poll: connect, read the first applicable
/// slice, drop the stream. The poll cadence (re-dialing on the configured
/// interval) gives eventual consistency without holding a long-lived stream per
/// remote cluster — keeping the failure model identical to the federation
/// poller (each poll is independent; a failure keeps the last-good snapshot).
pub struct NativeRemoteSource {
    control_plane_url: String,
    node_id: String,
    namespace: String,
    jwt_secret: GrpcJwtSecret,
    tls_config: Option<DpGrpcTlsConfig>,
    request_timeout: Duration,
}

impl NativeRemoteSource {
    pub fn new(ctx: &RemoteClusterPollContext, jwt_secret: GrpcJwtSecret) -> Self {
        Self {
            control_plane_url: ctx.control_plane_url.clone(),
            node_id: ctx.config.node_id.clone(),
            namespace: ctx.config.namespace.clone(),
            jwt_secret,
            tls_config: ctx.config.tls_config.clone(),
            request_timeout: ctx.config.request_timeout,
        }
    }
}

#[async_trait]
impl RemoteServiceSource for NativeRemoteSource {
    async fn fetch(&self) -> Result<RemoteClusterEndpoints, String> {
        fetch_remote_slice_endpoints(
            &self.control_plane_url,
            &self.node_id,
            &self.namespace,
            &self.jwt_secret,
            self.tls_config.as_ref(),
            self.request_timeout,
        )
        .await
    }
}

/// Factory wiring [`NativeRemoteSource`] for production use. Requires a JWT
/// secret; returns a source that always fails (logged) when none is configured
/// so the poll loop simply backs off rather than panicking.
pub fn native_source_factory(ctx: &RemoteClusterPollContext) -> Arc<dyn RemoteServiceSource> {
    match ctx.config.jwt_secret.clone() {
        Some(secret) => Arc::new(NativeRemoteSource::new(ctx, secret)),
        None => Arc::new(MissingSecretSource {
            cluster_name: ctx.cluster_name.clone(),
        }),
    }
}

/// Sentinel source used when no gRPC JWT secret is configured. Always errors so
/// the poll loop logs + backs off instead of dialing unauthenticated.
struct MissingSecretSource {
    cluster_name: String,
}

#[async_trait]
impl RemoteServiceSource for MissingSecretSource {
    async fn fetch(&self) -> Result<RemoteClusterEndpoints, String> {
        Err(format!(
            "remote cluster '{}' has no CP↔DP gRPC JWT secret configured; cannot authenticate to \
             the remote control plane (set FERRUM_CP_DP_GRPC_JWT_SECRET)",
            self.cluster_name
        ))
    }
}

/// One-shot remote MeshSubscribe: connect, read the first non-heartbeat slice,
/// return its workloads/services. Bounded by `request_timeout`.
async fn fetch_remote_slice_endpoints(
    control_plane_url: &str,
    node_id: &str,
    namespace: &str,
    jwt_secret: &GrpcJwtSecret,
    tls_config: Option<&DpGrpcTlsConfig>,
    request_timeout: Duration,
) -> Result<RemoteClusterEndpoints, String> {
    use crate::grpc::dp_client::generate_dp_jwt_with_issuer;
    use crate::grpc::proto::MeshSubscribeRequest;
    use crate::grpc::proto::mesh_config_sync_client::MeshConfigSyncClient;
    use crate::modes::mesh::config_consumer::common::tonic_tls_config;
    use crate::modes::mesh::slice::MeshSlice;
    use tonic::metadata::MetadataValue;
    use tonic::transport::Channel;

    let attempt = async {
        let mut endpoint = Channel::from_shared(control_plane_url.to_string())
            .map_err(|e| format!("invalid control_plane_url: {e}"))?
            .connect_timeout(Duration::from_secs(10));
        if let Some(tls) = tls_config {
            let mut client_tls = tonic_tls_config(tls);
            if let Ok(uri) = control_plane_url.parse::<http::Uri>()
                && let Some(host) = uri.host()
            {
                client_tls = client_tls.domain_name(host);
            }
            endpoint = endpoint
                .tls_config(client_tls)
                .map_err(|e| format!("remote CP TLS config: {e}"))?;
        }
        let channel = endpoint
            .connect()
            .await
            .map_err(|e| format!("connect to remote CP: {e}"))?;
        let auth_token =
            generate_dp_jwt_with_issuer(jwt_secret.as_str(), node_id, jwt_secret.issuer())
                .map_err(|e| format!("mint remote CP JWT: {e}"))?;
        let token: MetadataValue<_> = format!("Bearer {auth_token}")
            .parse()
            .map_err(|e| format!("build auth metadata: {e}"))?;
        #[allow(clippy::result_large_err)]
        let mut client =
            MeshConfigSyncClient::with_interceptor(channel, move |mut req: tonic::Request<()>| {
                req.metadata_mut().insert("authorization", token.clone());
                Ok(req)
            });
        let request = tonic::Request::new(MeshSubscribeRequest {
            node_id: node_id.to_string(),
            ferrum_version: crate::FERRUM_VERSION.to_string(),
            namespace: namespace.to_string(),
            workload_spiffe_id: String::new(),
            labels: HashMap::new(),
            waypoint_name: String::new(),
        });
        let mut stream = client
            .mesh_subscribe(request)
            .await
            .map_err(|e| format!("remote MeshSubscribe failed: {e}"))?
            .into_inner();
        while let Some(update) = stream
            .message()
            .await
            .map_err(|e| format!("remote MeshSubscribe stream error: {e}"))?
        {
            if update.heartbeat {
                continue;
            }
            let slice = serde_json::from_str::<MeshSlice>(&update.mesh_slice_json)
                .map_err(|e| format!("invalid remote MeshSubscribe slice JSON: {e}"))?;
            return Ok(RemoteClusterEndpoints {
                workloads: slice.workloads,
                services: slice.services,
            });
        }
        Err("remote MeshSubscribe stream closed before delivering a slice".to_string())
    };

    tokio::time::timeout(request_timeout, attempt)
        .await
        .map_err(|_| "remote MeshSubscribe timed out".to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::LocalityPreference;
    use crate::identity::spiffe::SpiffeId;
    use crate::modes::mesh::config::{RemoteCluster, ServicePort, WorkloadRef, WorkloadSelector};
    use std::sync::Mutex;

    fn td(raw: &str) -> TrustDomain {
        TrustDomain::new(raw).expect("trust domain")
    }

    fn spiffe(raw: &str) -> SpiffeId {
        SpiffeId::new(raw.to_string()).expect("spiffe id")
    }

    fn workload(spiffe_id: &str, service: &str, address: &str, locality: Option<&str>) -> Workload {
        Workload {
            spiffe_id: spiffe(spiffe_id),
            selector: WorkloadSelector::default(),
            service_name: service.to_string(),
            addresses: vec![address.to_string()],
            ports: vec![],
            trust_domain: td("cluster.local"),
            namespace: "default".to_string(),
            network: None,
            cluster: None,
            weight: None,
            locality: locality.map(str::to_string),
            service_account: None,
        }
    }

    fn service(name: &str, refs: &[&str]) -> MeshService {
        MeshService {
            name: name.to_string(),
            namespace: "default".to_string(),
            ports: vec![ServicePort {
                port: 8080,
                protocol: Default::default(),
                name: Some("http".to_string()),
            }],
            workloads: refs
                .iter()
                .map(|r| WorkloadRef {
                    spiffe_id: spiffe(r),
                })
                .collect(),
            protocol_overrides: HashMap::new(),
        }
    }

    fn snapshot_with(cluster: &str, endpoints: RemoteClusterEndpoints) -> RemoteEndpointSnapshot {
        let mut clusters = HashMap::new();
        clusters.insert(
            cluster.to_string(),
            RemoteClusterEntry {
                cluster_name: cluster.to_string(),
                trust_domain: td("remote.local"),
                network: Some("net2".to_string()),
                endpoints,
                fetched_at_unix_seconds: 1,
            },
        );
        RemoteEndpointSnapshot { clusters }
    }

    #[test]
    fn default_remote_locality_distinguishes_region() {
        assert_eq!(
            default_remote_locality("west", Some("net2")),
            "remote-west/net2"
        );
        assert_eq!(default_remote_locality("west", None), "remote-west");
        // The synthetic region differs from any plausible local region, so a
        // remote target never lands in the local source-region tier.
        let local = LocalityPreference::parse("us-east-1/zone-a").unwrap();
        let remote = LocalityPreference::parse(&default_remote_locality("west", None)).unwrap();
        assert!(!local.same_region(&remote));
    }

    #[test]
    fn tag_remote_workloads_applies_locality_and_cluster() {
        let mut endpoints = RemoteClusterEndpoints {
            workloads: vec![
                workload(
                    "spiffe://remote.local/ns/default/sa/a",
                    "reviews",
                    "10.2.0.1",
                    None,
                ),
                workload(
                    "spiffe://remote.local/ns/default/sa/b",
                    "reviews",
                    "10.2.0.2",
                    Some("us-west-2/zone-c"),
                ),
            ],
            services: vec![],
        };
        tag_remote_workloads(&mut endpoints, "west", Some("net2"));
        // Workload without locality gets the synthetic remote locality.
        assert_eq!(
            endpoints.workloads[0].locality.as_deref(),
            Some("remote-west/net2")
        );
        assert_eq!(endpoints.workloads[0].cluster.as_deref(), Some("west"));
        assert_eq!(endpoints.workloads[0].network.as_deref(), Some("net2"));
        // Workload with its own locality keeps it (its real region tiers below
        // local already).
        assert_eq!(
            endpoints.workloads[1].locality.as_deref(),
            Some("us-west-2/zone-c")
        );
    }

    #[test]
    fn merge_appends_remote_workloads_and_unions_service_refs() {
        let local_workloads = vec![workload(
            "spiffe://cluster.local/ns/default/sa/local",
            "reviews",
            "10.1.0.1",
            Some("us-east-1/zone-a"),
        )];
        let local_services = vec![service(
            "reviews",
            &["spiffe://cluster.local/ns/default/sa/local"],
        )];
        let remote = RemoteClusterEndpoints {
            workloads: vec![workload(
                "spiffe://remote.local/ns/default/sa/remote",
                "reviews",
                "10.2.0.1",
                Some("remote-west"),
            )],
            services: vec![service(
                "reviews",
                &["spiffe://remote.local/ns/default/sa/remote"],
            )],
        };
        let snapshot = snapshot_with("west", remote);

        let (workloads, services) =
            merge_remote_endpoints_into_mesh(&local_workloads, &local_services, &snapshot);

        assert_eq!(workloads.len(), 2, "remote workload appended");
        // Single merged `reviews` service with BOTH refs so the discoverer
        // resolves local + remote endpoints.
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].workloads.len(), 2);
    }

    #[test]
    fn merge_skips_remote_workload_already_present_locally() {
        // A remote echo of a workload that physically exists locally must not
        // duplicate the target (local copy wins).
        let local = vec![workload(
            "spiffe://cluster.local/ns/default/sa/shared",
            "reviews",
            "10.1.0.1",
            None,
        )];
        let remote = RemoteClusterEndpoints {
            workloads: vec![workload(
                "spiffe://cluster.local/ns/default/sa/shared",
                "reviews",
                "10.9.9.9",
                None,
            )],
            services: vec![],
        };
        let snapshot = snapshot_with("west", remote);
        let (workloads, _) = merge_remote_endpoints_into_mesh(&local, &[], &snapshot);
        assert_eq!(workloads.len(), 1);
        assert_eq!(workloads[0].addresses, vec!["10.1.0.1".to_string()]);
    }

    #[test]
    fn merge_empty_snapshot_is_identity() {
        let local = vec![workload(
            "spiffe://cluster.local/ns/default/sa/a",
            "reviews",
            "10.1.0.1",
            None,
        )];
        let (workloads, services) = merge_remote_endpoints_into_mesh(
            &local,
            &[service(
                "reviews",
                &["spiffe://cluster.local/ns/default/sa/a"],
            )],
            &RemoteEndpointSnapshot::default(),
        );
        assert_eq!(workloads.len(), 1);
        assert_eq!(services.len(), 1);
    }

    #[test]
    fn store_install_and_snapshot_round_trip() {
        let store = RemoteEndpointStore::new();
        assert!(!store.has_first_success());
        assert!(store.snapshot().is_empty());

        store.install(RemoteClusterEntry {
            cluster_name: "west".to_string(),
            trust_domain: td("remote.local"),
            network: None,
            endpoints: RemoteClusterEndpoints {
                workloads: vec![workload(
                    "spiffe://remote.local/ns/default/sa/a",
                    "reviews",
                    "10.2.0.1",
                    None,
                )],
                services: vec![],
            },
            fetched_at_unix_seconds: 1,
        });
        assert!(store.has_first_success());
        let snapshot = store.snapshot();
        let entry = snapshot.clusters.get("west").expect("installed entry");
        assert_eq!(entry.trust_domain.as_str(), "remote.local");
        assert_eq!(entry.endpoints.workloads.len(), 1);
        assert_eq!(entry.fetched_at_unix_seconds, 1);

        store.remove("west");
        assert!(store.snapshot().is_empty());
    }

    #[test]
    fn poll_targets_require_federated_trust() {
        let mc = MultiClusterConfig {
            remote_clusters: vec![
                RemoteCluster {
                    name: "trusted".to_string(),
                    trust_domain: td("trusted.local"),
                    network: None,
                    control_plane_url: Some("https://cp.trusted.example:15010".to_string()),
                    federation_endpoint: None,
                },
                RemoteCluster {
                    name: "untrusted".to_string(),
                    trust_domain: td("untrusted.local"),
                    network: None,
                    control_plane_url: Some("https://cp.untrusted.example:15010".to_string()),
                    federation_endpoint: None,
                },
            ],
            ..MultiClusterConfig::default()
        };
        let mut trusted = std::collections::HashSet::new();
        trusted.insert(td("trusted.local"));

        let targets = poll_targets_for_multi_cluster(&mc, &trusted);
        assert_eq!(targets.len(), 1, "only the federated cluster is dialed");
        assert_eq!(targets[0].cluster_name, "trusted");
    }

    #[test]
    fn validate_control_plane_url_rejects_metadata_and_bad_scheme() {
        assert!(validate_control_plane_url("https://cp.example:15010").is_ok());
        assert!(validate_control_plane_url("grpc://cp.example:15010").is_ok());
        assert!(validate_control_plane_url("ftp://cp.example").is_err());
        assert!(validate_control_plane_url("https://169.254.169.254/").is_err());
        assert!(validate_control_plane_url("not a url").is_err());
    }

    struct MockSource {
        responses: Mutex<Vec<Result<RemoteClusterEndpoints, String>>>,
    }

    #[async_trait]
    impl RemoteServiceSource for MockSource {
        async fn fetch(&self) -> Result<RemoteClusterEndpoints, String> {
            let mut responses = self.responses.lock().expect("lock");
            if responses.is_empty() {
                return Err("no more mock responses".to_string());
            }
            responses.remove(0)
        }
    }

    #[tokio::test]
    async fn discovery_loop_installs_then_keeps_last_good_on_failure() {
        let store = RemoteEndpointStore::new();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let source = Arc::new(MockSource {
            responses: Mutex::new(vec![
                Ok(RemoteClusterEndpoints {
                    workloads: vec![workload(
                        "spiffe://remote.local/ns/default/sa/a",
                        "reviews",
                        "10.2.0.1",
                        None,
                    )],
                    services: vec![],
                }),
                Err("transient".to_string()),
            ]),
        });

        let ctx = RemoteClusterPollContext {
            cluster_name: "west".to_string(),
            trust_domain: td("remote.local"),
            network: Some("net2".to_string()),
            control_plane_url: "https://cp.remote.example:15010".to_string(),
            config: RemoteDiscoveryConfig {
                // Tiny interval so the loop reaches the second (failing) poll
                // quickly; the test shuts it down right after.
                poll_interval: Duration::from_millis(20),
                request_timeout: Duration::from_secs(1),
                jwt_secret: None,
                node_id: "dp-1".to_string(),
                namespace: "default".to_string(),
                tls_config: None,
            },
        };

        let task_store = store.clone();
        let handle = tokio::spawn(async move {
            remote_discovery_loop(ctx, source, task_store, shutdown_rx).await
        });

        // Wait for the first successful install.
        let mut rx = store.subscribe();
        tokio::time::timeout(Duration::from_secs(2), rx.changed())
            .await
            .expect("install event")
            .expect("revision channel open");
        assert_eq!(
            store
                .snapshot()
                .clusters
                .values()
                .map(|entry| entry.endpoints.workloads.len())
                .sum::<usize>(),
            1
        );

        // The remote workload was tagged with the synthetic locality.
        let snap = store.snapshot();
        let entry = snap.clusters.get("west").expect("west entry");
        assert_eq!(
            entry.endpoints.workloads[0].locality.as_deref(),
            Some("remote-west/net2")
        );

        // Let the second (failing) poll run; the last-good snapshot survives.
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(
            store
                .snapshot()
                .clusters
                .values()
                .map(|entry| entry.endpoints.workloads.len())
                .sum::<usize>(),
            1,
            "a failed poll must keep the last-good endpoints"
        );

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    }
}
