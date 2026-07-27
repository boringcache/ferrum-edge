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
    /// Tasks that were still running when shutdown was requested and then
    /// observed it and returned within the grace period.
    pub completed: Vec<String>,
    /// Tasks that returned *before* their shutdown receiver had observed
    /// `true`. A watcher, reconciler, or reprobe loop returning during normal
    /// operation means that part of the controller silently stopped
    /// reconciling — degraded service, not a clean exit — so it is reported
    /// separately and fails the process through [`Self::failure_error`].
    pub exited_before_shutdown: Vec<String>,
    /// Tasks that panicked or were cancelled by something other than this
    /// shutdown path.
    pub failed: Vec<K8sControllerTaskFailure>,
    /// Tasks still running at the grace deadline. They are aborted, and the
    /// abort is reported instead of silently detaching them.
    pub timed_out: Vec<String>,
    /// Subset of [`Self::timed_out`] whose terminal join was *not* confirmed
    /// inside the abort-settle budget. For these the abort was issued but no
    /// happens-before boundary was established, so the task may still be
    /// unwinding when `shutdown()` returns. Reported explicitly rather than
    /// claimed as settled.
    pub abort_unconfirmed: Vec<String>,
}

impl K8sControllerShutdownOutcome {
    /// `true` when every owned task stopped on its own, on time, without a
    /// panic and without having exited early.
    pub fn is_clean(&self) -> bool {
        // `abort_unconfirmed` is a subset of `timed_out`, so it needs no
        // separate term here.
        self.exited_before_shutdown.is_empty()
            && self.failed.is_empty()
            && self.timed_out.is_empty()
    }

    /// An error describing abnormally terminated controller tasks, if any.
    ///
    /// Two conditions are process-failing:
    ///
    /// * a panicked/cancelled task — a real defect;
    /// * a task that returned successfully *before* shutdown was requested —
    ///   a silently dead watcher/reconciler/reprobe loop is degraded service,
    ///   and a control plane that keeps running with one is worse than one
    ///   that exits and gets restarted.
    ///
    /// A grace-period timeout is deliberately *not* an error: a stuck task is
    /// aborted and warned about, mirroring background-task drain elsewhere in
    /// the modes.
    pub fn failure_error(&self) -> Option<anyhow::Error> {
        if self.failed.is_empty() && self.exited_before_shutdown.is_empty() {
            return None;
        }
        let mut details: Vec<String> = self
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
            .collect();
        for task in &self.exited_before_shutdown {
            details.push(format!("{task} exited before shutdown was requested"));
        }
        Some(anyhow::anyhow!(
            "Kubernetes controller task(s) terminated abnormally: {}",
            details.join("; ")
        ))
    }
}

/// How long a deadline-aborted task gets to reach its terminal join before the
/// abort is reported as unconfirmed. Keeps total teardown bounded at
/// `grace + ABORT_SETTLE_BUDGET`; an abort normally lands in microseconds, so
/// this only matters for a task wedged in a blocking `Drop`.
const ABORT_SETTLE_BUDGET: Duration = Duration::from_secs(1);

/// What a supervisor observed at its task's completion boundary.
struct TaskCompletion {
    result: Result<(), tokio::task::JoinError>,
    /// The shutdown receiver's value read *at the instant the task's join
    /// resolved*. Reading it later (e.g. in `shutdown()`) would be useless in
    /// the real control-plane lifecycle, where the global watch is already
    /// `true` long before the handle is torn down.
    shutdown_observed: bool,
}

/// One owned controller task plus its supervisor.
struct SupervisedTask {
    name: String,
    /// Join handle of the **supervisor**, which owns the underlying task's
    /// `JoinHandle`. Never abort or drop this while the underlying task is
    /// live: dropping the inner `JoinHandle` would *detach* the real task,
    /// which is precisely the bug this path exists to fix.
    supervisor: tokio::task::JoinHandle<TaskCompletion>,
    /// Abort handle of the **underlying** task, kept separate so the deadline
    /// path can stop the real work without touching the supervisor.
    abort: tokio::task::AbortHandle,
}

/// Terminal classification of a single controller task, resolved once and then
/// materialized into [`K8sControllerShutdownOutcome`] in spawn order.
enum TaskDisposition {
    Completed,
    ExitedBeforeShutdown,
    Failed(K8sControllerTaskFailure),
    TimedOut { abort_confirmed: bool },
}

pub struct K8sControllerHandle {
    pub metrics: Arc<ControllerMetrics>,
    tasks: Vec<SupervisedTask>,
}

impl K8sControllerHandle {
    /// Assemble a handle from already-spawned, named controller tasks.
    ///
    /// Each task is immediately wrapped in a supervisor that awaits its real
    /// `JoinHandle` and records the shutdown-receiver state at the completion
    /// boundary. Doing it here — rather than inspecting `is_finished()` during
    /// teardown — is what makes an early successful exit detectable at all:
    /// by the time CP mode calls [`Self::shutdown`], the global shutdown watch
    /// has already fired, so a later inspection can no longer tell "returned
    /// while running normally" from "returned because we asked it to".
    ///
    /// Kept crate-visible plus a `_test_support` re-export so external tests
    /// can drive the real shutdown path with synthetic tasks without widening
    /// the production API.
    pub(crate) fn from_named_tasks(
        metrics: Arc<ControllerMetrics>,
        tasks: Vec<(String, tokio::task::JoinHandle<()>)>,
        shutdown: watch::Receiver<bool>,
    ) -> Self {
        let tasks = tasks
            .into_iter()
            .map(|(name, handle)| {
                let abort = handle.abort_handle();
                let shutdown_rx = shutdown.clone();
                let supervisor = tokio::spawn(async move {
                    let result = handle.await;
                    TaskCompletion {
                        result,
                        shutdown_observed: *shutdown_rx.borrow(),
                    }
                });
                SupervisedTask {
                    name,
                    supervisor,
                    abort,
                }
            })
            .collect();
        Self { metrics, tasks }
    }

    /// Signal shutdown, then await every owned task with a bounded grace
    /// period, aborting whatever is still running at the deadline and
    /// confirming those aborts within a bounded settle phase.
    ///
    /// The signal is sent here (idempotently — `watch::Sender::send` on an
    /// already-`true` channel still notifies) so the ordering is structural:
    /// no caller can await controller tasks that were never told to stop.
    /// Whether a task exited early is decided by its supervisor at the
    /// completion boundary, not by the state of the channel at this point.
    pub async fn shutdown(
        self,
        shutdown_tx: &watch::Sender<bool>,
        grace: Duration,
    ) -> K8sControllerShutdownOutcome {
        // Ignore the send result: with no receivers left there is nothing to
        // notify, and every task is already gone or about to be joined.
        let _ = shutdown_tx.send(true);

        let mut outcome = K8sControllerShutdownOutcome::default();
        for (name, disposition) in await_controller_tasks(self.tasks, grace).await {
            match disposition {
                TaskDisposition::Completed => outcome.completed.push(name),
                TaskDisposition::ExitedBeforeShutdown => {
                    error!(
                        task = %name,
                        "Kubernetes controller task exited before shutdown was requested"
                    );
                    outcome.exited_before_shutdown.push(name);
                }
                TaskDisposition::Failed(failure) => {
                    error!(
                        task = %failure.task,
                        panicked = failure.panicked,
                        error = %failure.detail,
                        "Kubernetes controller task did not terminate cleanly"
                    );
                    outcome.failed.push(failure);
                }
                TaskDisposition::TimedOut { abort_confirmed } => {
                    if !abort_confirmed {
                        warn!(
                            task = %name,
                            settle_secs = ABORT_SETTLE_BUDGET.as_secs_f64(),
                            "Kubernetes controller task abort was not confirmed within the \
                             settle budget; its termination is not established"
                        );
                        outcome.abort_unconfirmed.push(name.clone());
                    }
                    outcome.timed_out.push(name);
                }
            }
        }
        outcome
    }
}

/// Await supervised controller tasks concurrently under a single deadline,
/// then abort and settle whatever is left.
///
/// Concurrent (rather than sequential) so a slow watcher does not hide a
/// reconciler panic behind it, and so the whole set shares one grace budget.
/// Returns dispositions in spawn order (watchers, reconciler, reprobe)
/// regardless of completion order, so the outcome is deterministic.
async fn await_controller_tasks(
    tasks: Vec<SupervisedTask>,
    grace: Duration,
) -> Vec<(String, TaskDisposition)> {
    use futures_util::stream::{FuturesUnordered, StreamExt};
    use std::collections::{BTreeMap, BTreeSet};

    if tasks.is_empty() {
        return Vec::new();
    }

    let mut names: Vec<String> = Vec::with_capacity(tasks.len());
    let mut dispositions: BTreeMap<usize, TaskDisposition> = BTreeMap::new();
    // Underlying-task abort handles, keyed by spawn index. The supervisor
    // futures below are never aborted or dropped early, so the real tasks are
    // never detached.
    let mut pending: BTreeMap<usize, tokio::task::AbortHandle> = BTreeMap::new();
    let mut futures = FuturesUnordered::new();
    for (index, task) in tasks.into_iter().enumerate() {
        names.push(task.name.clone());
        pending.insert(index, task.abort);
        let supervisor = task.supervisor;
        futures.push(async move { (index, supervisor.await) });
    }

    let deadline = tokio::time::Instant::now() + grace;
    let mut timed_out: Vec<usize> = Vec::new();
    loop {
        match tokio::time::timeout_at(deadline, futures.next()).await {
            Ok(Some((index, joined))) => {
                pending.remove(&index);
                let name = names.get(index).cloned().unwrap_or_default();
                dispositions.insert(index, classify_completion(name, joined));
            }
            Ok(None) => break,
            Err(_) => {
                for (index, abort) in std::mem::take(&mut pending) {
                    if let Some(name) = names.get(index) {
                        warn!(
                            task = %name,
                            grace_secs = grace.as_secs_f64(),
                            "Kubernetes controller task still running at grace deadline; aborting"
                        );
                    }
                    abort.abort();
                    timed_out.push(index);
                }
                break;
            }
        }
    }

    // Bounded abort-settle phase: an aborted task's `JoinHandle` resolves only
    // after its future has actually been dropped, so awaiting the supervisors
    // here is what turns "abort was requested" into "termination happened".
    // Dropping `futures` without this would reintroduce detach-on-drop.
    if !timed_out.is_empty() {
        let mut confirmed: BTreeSet<usize> = BTreeSet::new();
        let settle_deadline = tokio::time::Instant::now() + ABORT_SETTLE_BUDGET;
        while confirmed.len() < timed_out.len() {
            match tokio::time::timeout_at(settle_deadline, futures.next()).await {
                Ok(Some((index, joined))) => {
                    // The task was aborted by *this* path, so a cancellation
                    // JoinError is the expected terminal state and must not be
                    // double-counted as a separate failure. A panic racing the
                    // abort is logged but keeps the `timed_out` classification
                    // for the same reason.
                    let name = names.get(index).cloned().unwrap_or_default();
                    if let Ok(completion) = &joined
                        && let Err(err) = &completion.result
                        && err.is_panic()
                    {
                        error!(
                            task = %name,
                            error = %err,
                            "Kubernetes controller task panicked while being aborted at the \
                             grace deadline"
                        );
                    }
                    confirmed.insert(index);
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }
        for index in timed_out {
            dispositions.insert(
                index,
                TaskDisposition::TimedOut {
                    abort_confirmed: confirmed.contains(&index),
                },
            );
        }
    }

    // Anything still unresolved here is a *supervisor* whose underlying task
    // was already aborted above, so dropping `futures` now detaches only the
    // supervisor — never live controller work — and the situation is reported
    // as `abort_unconfirmed` rather than claimed as a settled termination.
    drop(futures);

    let mut resolved: Vec<(String, TaskDisposition)> = Vec::with_capacity(names.len());
    for (index, name) in names.into_iter().enumerate() {
        let disposition = match dispositions.remove(&index) {
            Some(disposition) => disposition,
            // Unreachable: every index is either joined above, or aborted and
            // recorded by the settle phase. Classified conservatively rather
            // than panicking on the shutdown path.
            None => TaskDisposition::TimedOut {
                abort_confirmed: false,
            },
        };
        resolved.push((name, disposition));
    }
    resolved
}

/// Turn a supervisor's join result into a terminal disposition.
fn classify_completion(
    name: String,
    joined: Result<TaskCompletion, tokio::task::JoinError>,
) -> TaskDisposition {
    match joined {
        Ok(completion) => match completion.result {
            Ok(()) if completion.shutdown_observed => TaskDisposition::Completed,
            // Returned successfully while the shutdown watch was still
            // `false`: that part of the controller stopped reconciling on its
            // own.
            Ok(()) => TaskDisposition::ExitedBeforeShutdown,
            Err(err) => TaskDisposition::Failed(K8sControllerTaskFailure {
                task: name,
                panicked: err.is_panic(),
                detail: err.to_string(),
            }),
        },
        // The supervisor only awaits a `JoinHandle`, so it cannot panic and is
        // never aborted; treat a join failure as an abnormal termination of
        // the task it was supervising rather than swallowing it.
        Err(err) => TaskDisposition::Failed(K8sControllerTaskFailure {
            task: name,
            panicked: err.is_panic(),
            detail: format!("supervisor join failed: {err}"),
        }),
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
        shutdown.clone(),
        Duration::from_secs(300),
    );

    let mut tasks: Vec<(String, tokio::task::JoinHandle<()>)> = watcher_handles
        .into_iter()
        .enumerate()
        .map(|(index, handle)| (format!("crd-watcher-{index}"), handle))
        .collect();
    tasks.push(("reconciler".to_string(), reconciler_handle));
    tasks.push(("crd-reprobe".to_string(), reprobe_handle));

    // The same shutdown receiver the tasks themselves watch: each supervisor
    // reads it at its task's completion boundary, so a watcher/reconciler that
    // returns during normal operation is recorded as an early exit even though
    // CP mode only tears the handle down long after the global watch fired.
    let handle = K8sControllerHandle::from_named_tasks(metrics, tasks, shutdown);
    Ok(handle)
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
