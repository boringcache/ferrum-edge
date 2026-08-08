//! Install lifecycle for the chained `ferrum-cni` plugin: readiness-gated
//! automatic rollback, and the readiness marker the Helm cleanup hook uses to
//! report completion.
//!
//! # Why a rollback watcher exists
//!
//! Once `ferrum-cni install` writes the chained conflist, every pod ADD on
//! that node traverses `ferrum-cni`, and an unanswered ADD fails closed. That
//! is the intended capture-race posture, but it means an install that never
//! reaches a usable node-agent is a node-wide pod-creation outage rather than
//! a degraded optimization (issue #3609).
//!
//! The watcher runs beside the node-agent in the same pod. It polls the CNI
//! STATUS verb — the same readiness boundary kubelet would observe — and:
//!
//! - the moment STATUS answers `Ok`, it retains the artifacts permanently for
//!   that pod. A node-agent that later crashes is NOT rolled back: it was
//!   proven usable once, so removing the chain would silently drop capture
//!   for pods that are still expected to be enrolled.
//! - if STATUS never answers `Ok` before the deadline, it removes the
//!   artifacts **this pod's own installer wrote** and exits non-zero, so the
//!   node keeps creating pods and the failure stays visible.
//!
//! Time only decides *when* to act. What may be removed is decided by the
//! ownership evidence written at install: the watcher pins both the owner and
//! the install generation, so a slow start that is overtaken by a newer
//! install (a rollout, an upgrade) can never delete the newer generation's
//! artifacts — that run reports `retained-other-generation` instead.

use std::io;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::cni::install::{self, CniInstallError, CniUninstallConfig, CniUninstallReport};

/// Default budget for the node-agent to reach CNI readiness. Deliberately
/// generous: a healthy but slow start (image pull, BPF fs mount, initial pod
/// relist on a large node) must not be mistaken for a broken install.
pub const DEFAULT_READY_TIMEOUT: Duration = Duration::from_secs(300);

/// Default gap between STATUS probes.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Upper bounds so a mistyped value cannot park the watcher forever.
const MAX_READY_TIMEOUT_SECS: u64 = 3600;
const MAX_POLL_INTERVAL_SECS: u64 = 300;

/// Network name used for the STATUS probe when the generated conflist is not
/// (yet) present. STATUS readiness does not depend on the network name; the
/// node-agent only requires a well-formed one.
pub const FALLBACK_STATUS_NETWORK_NAME: &str = "ferrum-mesh";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackWatchConfig {
    pub socket_path: String,
    pub ready_timeout: Duration,
    pub poll_interval: Duration,
    /// Scope of what a rollback may remove. The Helm chart pins both
    /// `expected_owner` and `expected_generation` here.
    pub uninstall: CniUninstallConfig,
}

impl RollbackWatchConfig {
    pub fn from_env() -> Result<Self, CniInstallError> {
        let ready_timeout = duration_from_env(
            "READY_TIMEOUT_SECS",
            DEFAULT_READY_TIMEOUT,
            MAX_READY_TIMEOUT_SECS,
        )?;
        let poll_interval = duration_from_env(
            "POLL_INTERVAL_SECS",
            DEFAULT_POLL_INTERVAL,
            MAX_POLL_INTERVAL_SECS,
        )?;
        Ok(Self {
            socket_path: required_env("SOCKET_PATH")?,
            ready_timeout,
            poll_interval: poll_interval.min(ready_timeout),
            uninstall: CniUninstallConfig::from_env()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RollbackWatchOutcome {
    /// The node-agent answered STATUS before the deadline; artifacts are
    /// retained for the lifetime of this pod.
    Ready,
    /// The deadline passed with no successful STATUS; the generation-scoped
    /// cleanup ran and produced this report.
    RolledBack(CniUninstallReport),
}

/// Poll `probe` until it returns true or the readiness budget is exhausted,
/// then roll back this generation's artifacts.
///
/// `probe` is injected so the decision loop is testable without a live
/// node-agent; the binary passes [`probe_node_agent_status`].
pub fn run_rollback_watch(
    config: &RollbackWatchConfig,
    probe: &mut dyn FnMut() -> bool,
) -> Result<RollbackWatchOutcome, CniInstallError> {
    let deadline = Instant::now() + config.ready_timeout;
    loop {
        if probe() {
            return Ok(RollbackWatchOutcome::Ready);
        }
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        // Never sleep past the deadline: a long poll interval must not extend
        // the window in which the node cannot create pods.
        std::thread::sleep(config.poll_interval.min(deadline - now));
    }
    let report = install::uninstall(&config.uninstall)?;
    Ok(RollbackWatchOutcome::RolledBack(report))
}

/// One CNI STATUS round-trip against the node-agent socket.
///
/// Returns true only for an explicit `Ok`. A missing socket, an IPC failure,
/// a `Rejected` (initial pod sync incomplete / Kubernetes probe failed), or a
/// malformed request all read as "not ready" — the same fail-closed reading
/// the CNI binary applies to STATUS on the request path.
#[cfg(unix)]
pub fn probe_node_agent_status(config: &RollbackWatchConfig) -> bool {
    use crate::cni::client::{DEFAULT_RPC_TIMEOUT, send_rpc};
    use crate::cni::rpc::{CniRpcRequest, CniRpcResponse, RpcVerb};
    use crate::cni::spec::is_safe_cni_network_name;

    let conf_dir = &config.uninstall.host_conf_dir;
    let conf_file = &config.uninstall.conf_file_name;
    let network_name = install::generated_network_name(conf_dir, conf_file)
        .filter(|name| is_safe_cni_network_name(name))
        .unwrap_or_else(|| FALLBACK_STATUS_NETWORK_NAME.to_string());

    let request = CniRpcRequest {
        verb: RpcVerb::Status,
        network_name,
        pod_namespace: String::new(),
        pod_name: String::new(),
        pod_uid: None,
        container_id: String::new(),
        ifname: None,
        netns_path: None,
        args: Default::default(),
        valid_attachments: Vec::new(),
    };
    if request.validate().is_err() {
        return false;
    }
    matches!(
        send_rpc(&config.socket_path, &request, DEFAULT_RPC_TIMEOUT),
        Ok(CniRpcResponse::Ok)
    )
}

#[cfg(not(unix))]
pub fn probe_node_agent_status(_config: &RollbackWatchConfig) -> bool {
    false
}

/// Scope of the `await-cleanup` gate that fronts the Helm pre-delete phase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupWaitConfig {
    pub namespace: String,
    pub daemonset_name: String,
    pub timeout: Duration,
    pub poll_interval: Duration,
}

impl CleanupWaitConfig {
    pub fn from_env() -> Result<Self, CniInstallError> {
        let timeout = duration_from_env(
            "CLEANUP_TIMEOUT_SECS",
            DEFAULT_CLEANUP_TIMEOUT,
            MAX_READY_TIMEOUT_SECS,
        )?;
        let poll_interval = duration_from_env(
            "POLL_INTERVAL_SECS",
            DEFAULT_POLL_INTERVAL,
            MAX_POLL_INTERVAL_SECS,
        )?;
        Ok(Self {
            namespace: required_env("RELEASE_NAMESPACE")?,
            daemonset_name: required_env("CLEANUP_DAEMONSET_NAME")?,
            timeout,
            poll_interval: poll_interval.min(timeout),
        })
    }
}

/// Default budget for every node's cleanup pod to finish.
pub const DEFAULT_CLEANUP_TIMEOUT: Duration = Duration::from_secs(300);

/// What the cleanup DaemonSet's status said when the wait ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CleanupWaitReport {
    pub desired: i32,
    pub ready: i32,
}

/// Block until every node's cleanup pod is Ready — that is, until
/// `ferrum-cni uninstall` has succeeded on each node the DaemonSet scheduled
/// onto.
///
/// This exists because Helm's hook wait only watches `Job` and `Pod` kinds: a
/// hook DaemonSet is created and then immediately left behind, which would let
/// the release (and the node-agent socket) be deleted while cleanup pods were
/// still starting. Running this as a later-weighted hook **Job** gives the
/// phase a completion boundary Helm does understand, and makes a node that
/// cannot be cleaned fail the uninstall instead of passing silently.
///
/// `desired == 0` (no node currently matches the DaemonSet) is a success only
/// once the DaemonSet controller has observed the object, so an unobserved
/// all-zero status is never mistaken for "nothing to do".
pub async fn await_cleanup_daemonset(
    config: &CleanupWaitConfig,
) -> Result<CleanupWaitReport, String> {
    use k8s_openapi::api::apps::v1::DaemonSet;
    use kube::Api;

    let client = kube::Client::try_default()
        .await
        .map_err(|err| format!("could not build a Kubernetes client: {err}"))?;
    let api: Api<DaemonSet> = Api::namespaced(client, &config.namespace);

    let deadline = Instant::now() + config.timeout;
    let mut last = CleanupWaitReport {
        desired: 0,
        ready: 0,
    };
    loop {
        match api.get_status(&config.daemonset_name).await {
            Ok(daemonset) => {
                let generation = daemonset.metadata.generation;
                if let Some(status) = daemonset.status.as_ref() {
                    last = CleanupWaitReport {
                        desired: status.desired_number_scheduled,
                        ready: status.number_ready,
                    };
                    let observed = match (generation, status.observed_generation) {
                        (Some(generation), Some(observed)) => observed >= generation,
                        _ => true,
                    };
                    if observed && last.ready >= last.desired {
                        return Ok(last);
                    }
                }
            }
            Err(err) => {
                // A transient API error must not be read as "cleanup done".
                // This runs from the CLI, which installs no tracing
                // subscriber, so the operator only sees stderr.
                eprintln!(
                    "ferrum-cni: could not read the status of DaemonSet {}; retrying: {err}",
                    config.daemonset_name
                );
            }
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(format!(
                "cleanup did not finish on every node within {}s: {} of {} node cleanup pods \
                 reported success. The chained CNI configuration may still be present on the \
                 remaining nodes; inspect `kubectl -n {} logs daemonset/{}` before retrying.",
                config.timeout.as_secs(),
                last.ready,
                last.desired,
                config.namespace,
                config.daemonset_name
            ));
        }
        let nap = config.poll_interval.min(deadline - now);
        tokio::time::sleep(nap).await;
    }
}

/// Write the marker the Helm pre-delete hook's readiness probe reads.
///
/// The hook pod cannot report "cleanup finished" by exiting — Helm waits for
/// the hook resource to become ready, and a DaemonSet pod that exits is
/// restarted. So the container completes its cleanup, drops this marker, and
/// stays up; readiness then flips exactly once the work is done, and a failed
/// cleanup never publishes it.
pub fn write_ready_marker(path: &str) -> io::Result<()> {
    let path = Path::new(path);
    if let Some(parent) = path.parent() && !parent.as_os_str().is_empty() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, b"ferrum-cni cleanup complete\n")
}

/// True when a previous run in this container published the marker.
pub fn ready_marker_present(path: &str) -> bool {
    std::fs::metadata(path).is_ok_and(|meta| meta.is_file())
}

/// Marker path for the cleanup hold/readiness pair. Shared by the cleanup
/// container and its readiness probe, which inherit the same environment.
pub fn ready_marker_path_from_env() -> Result<String, CniInstallError> {
    required_env("READY_MARKER_PATH")
}

fn required_env(name: &'static str) -> Result<String, CniInstallError> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or(CniInstallError::MissingEnv(name))
}

fn duration_from_env(
    name: &'static str,
    default: Duration,
    max_secs: u64,
) -> Result<Duration, CniInstallError> {
    let Some(raw) = std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
    else {
        return Ok(default);
    };
    let Ok(parsed) = raw.trim().parse::<u64>() else {
        return Err(CniInstallError::InvalidEnvValue {
            name,
            expected: "a whole number of seconds",
        });
    };
    if parsed == 0 || parsed > max_secs {
        return Err(CniInstallError::InvalidEnvValue {
            name,
            expected: "a whole number of seconds within the supported range",
        });
    }
    Ok(Duration::from_secs(parsed))
}
