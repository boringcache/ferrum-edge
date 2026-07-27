//! Kubernetes CRD controller (Layer 8).
//!
//! Watches Istio + Gateway API CRDs via kube-rs reflectors and feeds them
//! through `config_sources::k8s::translate_k8s_objects()` into the canonical
//! Layer 2 mesh model. Enabled in CP mode with `FERRUM_K8S_CONTROLLER_ENABLED=true`.

pub mod convert;
pub mod istio_status;
pub mod metrics;
pub mod reconciler;
pub mod resource_store;
pub mod status;
pub mod watcher;

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use tokio::sync::{broadcast, watch};
use tracing::{error, info, warn};

use crate::config::types::GatewayConfig;
use crate::grpc::cp_server::{CpScope, DpNodeRegistry, NamespaceBroadcasts};
use crate::grpc::mesh_registry::MeshNodeRegistry;
use crate::grpc::mesh_server::MeshConfigBroadcast;
use istio_status::IstioStatusWriter;
use metrics::ControllerMetrics;
pub use reconciler::ReconcileBroadcasters;
pub use reconciler::{
    CpPublicationGate, K8sOverlaySlot, compose_db_with_k8s_overlay, empty_k8s_overlay_slot,
};
use reconciler::{ReconcilerConfig, spawn_reconcile_loop};
use resource_store::ResourceStoreSet;
use status::GatewayApiStatusWriter;
use watcher::{WatcherSelection, spawn_crd_reprobe_task, start_crd_watchers};

pub struct K8sControllerConfig {
    pub namespace: String,
    pub controller_namespace: String,
    pub trust_domain: String,
    pub cluster_domain: String,
    pub istio_root_namespace: String,
    pub watch_namespaces: Vec<String>,
    pub watch_istio: bool,
    /// `FERRUM_K8S_WATCH_MESH_CONFIG` — opt-out for clusters where the
    /// gateway runs in a different trust boundary from `istio-system` and
    /// cannot easily grant cross-namespace `configmaps` RBAC. Only
    /// effective when `watch_istio` is true (without Istio CRDs there is
    /// no Telemetry resource that would consume meshConfig providers).
    pub watch_mesh_config: bool,
    pub watch_gateway_api: bool,
    pub pod_discovery_enabled: bool,
    pub watch_node_locality: bool,
    pub gateway_api_data_plane_service_namespace: Option<String>,
    pub gateway_api_data_plane_service_name: Option<String>,
    pub gateway_api_status_address: Option<String>,
    /// Effective Sidecar `ingress[]` materialization gate
    /// (`FERRUM_MESH_SIDECAR_ENFORCED && !FERRUM_MESH_SIDECAR_ENFORCED_DRY_RUN`).
    /// Threaded to the Istio status writer so it reports `ingress_modeled` only
    /// when the data plane actually materializes the listeners (F6 §6.2),
    /// matching the slice builder's ingress gate.
    pub mesh_sidecar_ingress_enforced: bool,
    pub debounce_ms: u64,
    pub full_sync_interval_secs: u64,
    pub kubeconfig_path: Option<String>,
}

/// A controller task that failed to terminate cleanly (panic or cancellation).
#[derive(Debug, Clone)]
pub struct K8sControllerTaskFailure {
    pub task: String,
    /// `true` when the task panicked, `false` when it was cancelled/aborted
    /// externally. Both are unexpected for a controller task that is supposed
    /// to observe the shutdown watch channel and return.
    pub panicked: bool,
    pub detail: String,
}

/// Terminal disposition of every task owned by [`K8sControllerHandle`].
///
/// Returned by [`K8sControllerHandle::shutdown`] so the control plane can log
/// and propagate controller-task failures instead of detaching them (#3220).
#[derive(Debug, Default)]
pub struct K8sControllerShutdownOutcome {
    /// Tasks that observed shutdown and returned within the grace period.
    pub completed: Vec<String>,
    /// Tasks that had already terminated *before* shutdown was requested.
    /// A watcher, reconciler, or reprobe loop returning during normal
    /// operation means that part of the controller silently stopped
    /// reconciling; it is reported rather than mistaken for a clean exit.
    pub exited_before_shutdown: Vec<String>,
    /// Tasks that panicked or were cancelled.
    pub failed: Vec<K8sControllerTaskFailure>,
    /// Tasks still running at the grace deadline. They are aborted, and the
    /// abort is reported instead of silently detaching them.
    pub timed_out: Vec<String>,
}

impl K8sControllerShutdownOutcome {
    /// `true` when every owned task stopped on its own, on time, without a
    /// panic and without having exited early.
    pub fn is_clean(&self) -> bool {
        self.exited_before_shutdown.is_empty()
            && self.failed.is_empty()
            && self.timed_out.is_empty()
    }

    /// An error describing panicked/cancelled controller tasks, if any.
    ///
    /// A grace-period timeout is deliberately *not* an error: a stuck task is
    /// aborted and warned about (mirroring background-task drain elsewhere in
    /// the modes), while a panic is a real defect and is surfaced to `run()`
    /// so the process exit code reflects it.
    pub fn failure_error(&self) -> Option<anyhow::Error> {
        if self.failed.is_empty() {
            return None;
        }
        let detail = self
            .failed
            .iter()
            .map(|failure| {
                let kind = if failure.panicked {
                    "panicked"
                } else {
                    "cancelled"
                };
                format!("{} {kind}: {}", failure.task, failure.detail)
            })
            .collect::<Vec<_>>()
            .join("; ");
        Some(anyhow::anyhow!(
            "Kubernetes controller task(s) terminated abnormally: {detail}"
        ))
    }
}

pub struct K8sControllerHandle {
    pub metrics: Arc<ControllerMetrics>,
    tasks: Vec<(String, tokio::task::JoinHandle<()>)>,
}

impl K8sControllerHandle {
    /// Assemble a handle from already-spawned, named controller tasks.
    ///
    /// Kept crate-visible plus a `_test_support` re-export so external tests
    /// can drive the real shutdown path with synthetic tasks without widening
    /// the production API.
    pub(crate) fn from_named_tasks(
        metrics: Arc<ControllerMetrics>,
        tasks: Vec<(String, tokio::task::JoinHandle<()>)>,
    ) -> Self {
        Self { metrics, tasks }
    }

    /// Signal shutdown, then await every owned task with a bounded grace
    /// period, aborting and reporting whatever is still running at the
    /// deadline.
    ///
    /// The signal is sent here (idempotently — `watch::Sender::send` on an
    /// already-`true` channel still notifies) so the ordering is structural:
    /// no caller can await controller tasks that were never told to stop.
    /// When shutdown was already requested by the caller, tasks that have
    /// finished are simply awaited; when it was not, any already-finished
    /// task exited for some other reason and is reported through
    /// [`K8sControllerShutdownOutcome::exited_before_shutdown`].
    pub async fn shutdown(
        self,
        shutdown_tx: &watch::Sender<bool>,
        grace: Duration,
    ) -> K8sControllerShutdownOutcome {
        let mut outcome = K8sControllerShutdownOutcome::default();
        let shutdown_already_requested = *shutdown_tx.borrow();
        if !shutdown_already_requested {
            for (name, handle) in &self.tasks {
                if handle.is_finished() {
                    error!(
                        task = %name,
                        "Kubernetes controller task exited before shutdown was requested"
                    );
                    outcome.exited_before_shutdown.push(name.clone());
                }
            }
        }
        // Ignore the send result: with no receivers left there is nothing to
        // notify, and every task is already gone or about to be joined.
        let _ = shutdown_tx.send(true);

        await_controller_tasks(self.tasks, grace, &mut outcome).await;
        outcome
    }
}

/// Await named controller tasks concurrently under a single deadline.
///
/// Concurrent (rather than sequential) so a slow watcher does not hide a
/// reconciler panic behind it, and so the whole set shares one grace budget.
async fn await_controller_tasks(
    tasks: Vec<(String, tokio::task::JoinHandle<()>)>,
    grace: Duration,
    outcome: &mut K8sControllerShutdownOutcome,
) {
    use futures_util::stream::{FuturesUnordered, StreamExt};
    use std::collections::BTreeMap;

    if tasks.is_empty() {
        return;
    }

    // Abort handles are captured up-front: dropping a `JoinHandle` (which is
    // what dropping the `FuturesUnordered` at the deadline would do) *detaches*
    // the task rather than stopping it — precisely the bug this shutdown path
    // exists to fix. Keyed by spawn index so the deadline path reports stuck
    // tasks in a deterministic order (watchers, reconciler, reprobe).
    let mut pending: BTreeMap<usize, (String, tokio::task::AbortHandle)> = BTreeMap::new();
    let mut futures = FuturesUnordered::new();
    for (index, (name, handle)) in tasks.into_iter().enumerate() {
        pending.insert(index, (name.clone(), handle.abort_handle()));
        futures.push(async move { (index, name, handle.await) });
    }

    let deadline = tokio::time::Instant::now() + grace;
    loop {
        match tokio::time::timeout_at(deadline, futures.next()).await {
            Ok(Some((index, name, result))) => {
                pending.remove(&index);
                match result {
                    Ok(()) => outcome.completed.push(name),
                    Err(err) => {
                        let panicked = err.is_panic();
                        error!(
                            task = %name,
                            panicked,
                            error = %err,
                            "Kubernetes controller task did not terminate cleanly"
                        );
                        outcome.failed.push(K8sControllerTaskFailure {
                            task: name,
                            panicked,
                            detail: err.to_string(),
                        });
                    }
                }
            }
            Ok(None) => break,
            Err(_) => {
                for (name, abort) in std::mem::take(&mut pending).into_values() {
                    warn!(
                        task = %name,
                        grace_secs = grace.as_secs_f64(),
                        "Kubernetes controller task still running at grace deadline; aborting"
                    );
                    abort.abort();
                    outcome.timed_out.push(name);
                }
                break;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn start_k8s_controller(
    controller_config: K8sControllerConfig,
    config_arc: Arc<ArcSwap<GatewayConfig>>,
    overlay_slot: K8sOverlaySlot,
    broadcasts: Arc<NamespaceBroadcasts>,
    cp_scope: CpScope,
    dp_registry: Arc<DpNodeRegistry>,
    mesh_update_tx: broadcast::Sender<MeshConfigBroadcast>,
    mesh_registry: Arc<MeshNodeRegistry>,
    publication_gate: CpPublicationGate,
    shutdown: watch::Receiver<bool>,
) -> Result<K8sControllerHandle, anyhow::Error> {
    info!(
        watch_istio = controller_config.watch_istio,
        watch_gateway_api = controller_config.watch_gateway_api,
        pod_discovery_enabled = controller_config.pod_discovery_enabled,
        watch_node_locality = controller_config.watch_node_locality,
        gateway_api_data_plane_service_namespace = ?controller_config
            .gateway_api_data_plane_service_namespace,
        gateway_api_data_plane_service_name = ?controller_config.gateway_api_data_plane_service_name,
        gateway_api_status_address = ?controller_config.gateway_api_status_address,
        istio_root_namespace = %controller_config.istio_root_namespace,
        watch_namespaces = ?controller_config.watch_namespaces,
        namespace = controller_config.namespace,
        controller_namespace = controller_config.controller_namespace,
        "Starting Kubernetes controller"
    );

    let client = build_kube_client(&controller_config.kubeconfig_path).await?;

    let store_set = Arc::new(tokio::sync::Mutex::new(ResourceStoreSet::new()));
    let metrics = Arc::new(ControllerMetrics::new());
    let watcher_selection = WatcherSelection {
        watch_istio: controller_config.watch_istio,
        watch_gateway_api: controller_config.watch_gateway_api,
        watch_core: controller_config.pod_discovery_enabled,
        watch_gateway_api_data_plane_service: controller_config.watch_gateway_api
            && controller_config
                .gateway_api_data_plane_service_namespace
                .is_some()
            && controller_config
                .gateway_api_data_plane_service_name
                .is_some(),
        watch_node_locality: controller_config.watch_node_locality,
        // Without Istio CRDs there is no Telemetry resource that would
        // consume meshConfig providers, so the configmaps watch and its
        // associated RBAC requirement are skipped automatically.
        watch_mesh_config: controller_config.watch_istio && controller_config.watch_mesh_config,
    };
    let controller_namespace = controller_config.controller_namespace.clone();
    let istio_root_namespace = controller_config.istio_root_namespace.clone();
    let gateway_api_data_plane_service_namespace = controller_config
        .gateway_api_data_plane_service_namespace
        .clone();

    let watcher_handles = start_crd_watchers(
        client.clone(),
        store_set.clone(),
        watcher_selection,
        controller_config.watch_namespaces.clone(),
        controller_namespace.clone(),
        istio_root_namespace.clone(),
        gateway_api_data_plane_service_namespace.clone(),
        shutdown.clone(),
    )
    .await;

    info!(watchers = watcher_handles.len(), "CRD watchers started");

    let reconciler_config = ReconcilerConfig {
        namespace: controller_config.namespace,
        controller_namespace: controller_config.controller_namespace,
        trust_domain: controller_config.trust_domain,
        cluster_domain: controller_config.cluster_domain,
        istio_root_namespace: controller_config.istio_root_namespace,
        watch_namespaces: controller_config.watch_namespaces.clone(),
        debounce_ms: controller_config.debounce_ms,
        full_sync_interval_secs: controller_config.full_sync_interval_secs,
        pod_discovery_enabled: controller_config.pod_discovery_enabled,
        gateway_api_data_plane_service_namespace: controller_config
            .gateway_api_data_plane_service_namespace,
        gateway_api_data_plane_service_name: controller_config.gateway_api_data_plane_service_name,
        gateway_api_status_address: controller_config.gateway_api_status_address,
        mesh_sidecar_ingress_enforced: controller_config.mesh_sidecar_ingress_enforced,
    };
    let gateway_status_writer = controller_config
        .watch_gateway_api
        .then(|| GatewayApiStatusWriter::new(client.clone()));
    // T2-B: the Istio status writer mirrors the Gateway API writer's
    // construction — only build it when the controller is actually
    // watching Istio CRDs, so non-Istio installs don't pay the (tiny)
    // overhead of an unused writer carrying a kube client clone.
    let istio_status_writer = controller_config
        .watch_istio
        .then(|| IstioStatusWriter::new(client.clone()));

    let reconciler_handle = spawn_reconcile_loop(
        store_set.clone(),
        config_arc,
        overlay_slot,
        ReconcileBroadcasters {
            broadcasts,
            cp_scope,
            dp_registry,
            mesh_update_tx,
            mesh_registry,
            publication_gate,
        },
        reconciler_config,
        gateway_status_writer,
        istio_status_writer,
        metrics.clone(),
        shutdown.clone(),
    );

    let reprobe_handle = spawn_crd_reprobe_task(
        client,
        store_set,
        watcher_selection,
        controller_config.watch_namespaces,
        controller_namespace,
        istio_root_namespace,
        gateway_api_data_plane_service_namespace,
        shutdown,
        Duration::from_secs(300),
    );

    let mut tasks: Vec<(String, tokio::task::JoinHandle<()>)> = watcher_handles
        .into_iter()
        .enumerate()
        .map(|(index, handle)| (format!("crd-watcher-{index}"), handle))
        .collect();
    tasks.push(("reconciler".to_string(), reconciler_handle));
    tasks.push(("crd-reprobe".to_string(), reprobe_handle));

    Ok(K8sControllerHandle::from_named_tasks(metrics, tasks))
}

async fn build_kube_client(
    kubeconfig_path: &Option<String>,
) -> Result<kube::Client, anyhow::Error> {
    let config = if let Some(path) = kubeconfig_path {
        info!(path, "Loading kubeconfig from explicit path");
        let kubeconfig = kube::config::Kubeconfig::read_from(path)?;
        kube::Config::from_custom_kubeconfig(kubeconfig, &Default::default()).await?
    } else {
        match kube::Config::incluster() {
            Ok(c) => {
                info!("Using in-cluster Kubernetes config");
                c
            }
            Err(in_cluster_err) => match kube::Config::infer().await {
                Ok(c) => {
                    info!("Using inferred kubeconfig (not in-cluster)");
                    c
                }
                Err(infer_err) => {
                    error!(
                        in_cluster_error = %in_cluster_err,
                        infer_error = %infer_err,
                        "Failed to build Kubernetes client config"
                    );
                    return Err(anyhow::anyhow!(
                        "Cannot create Kubernetes client: in-cluster failed ({in_cluster_err}), \
                         kubeconfig inference failed ({infer_err}). \
                         Set FERRUM_K8S_KUBECONFIG_PATH for out-of-cluster use."
                    ));
                }
            },
        }
    };

    Ok(kube::Client::try_from(config)?)
}
