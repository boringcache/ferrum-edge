//! Localized file-based mesh config source (`FERRUM_MESH_CONFIG_PROTOCOL=file`).
//!
//! Instead of subscribing to a control plane, the data plane builds its
//! [`MeshSlice`] locally from a YAML/JSON document on disk — the same
//! DP-side materialization path the native/xDS consumers feed
//! (`MeshSlice::from_gateway_config` + the slice-apply task), so a file-built
//! slice is functionally equivalent to a CP-delivered one. Mirrors the
//! gateway's file mode: the initial load is fail-closed (an unreadable or
//! invalid document refuses startup) and SIGHUP (Unix) reloads the document,
//! keeping the last good slice when the reload fails.
//!
//! Reads go through the shared bounded stable-file primitive (regular-file
//! open target, Unix `O_NONBLOCK`, 64 MiB ceiling with `limit + 1`, stable
//! identity/content probes). Initial load and SIGHUP reload perform
//! filesystem and parse work on `spawn_blocking`, coalesce repeated signals
//! so only one generation is parsed at a time (with at most one follow-up
//! after an in-flight load), and refuse to let an older completed load
//! overwrite a newer requested generation. Watcher shutdown stops accepting
//! candidates promptly: it drops/aborts the in-flight join handle without
//! awaiting a non-cancellable started blocking job, and a late completion
//! cannot publish. A failed reload raises the shared `config_rejected`
//! admin-health signal (authenticated `/health` degraded) while retaining
//! the last-good slice; sticky recovery clears only when the exact current
//! recovery candidate is accepted (or content-identical no-op accepted) by
//! the proxy apply lifecycle — not on channel send or provisional
//! [`MeshRuntimeState::install_slice`].

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use serde::Deserialize;
use tracing::{info, warn};

use crate::config::stable_file::{
    MAX_MESH_CONFIG_FILE_BYTES, StableFileReadOptions, detect_json_or_yaml_extension,
    read_stable_file, stable_file_error_anyhow,
};
use crate::config::types::{CURRENT_CONFIG_VERSION, GatewayConfig};
use crate::modes::mesh::revision::MeshRevisionContentIdentity;
use crate::modes::mesh::runtime::{MeshRuntimeState, MeshSliceInstall, slice_content_identity};
use crate::modes::mesh::slice::{MeshSlice, MeshSliceRequest};

/// On-disk shape of the localized mesh config document.
///
/// `deny_unknown_fields` is load-bearing: a document carrying gateway
/// resources (`proxies:`, `upstreams:`, ...) fails deserialization with a
/// clear "unknown field" error instead of silently dropping them.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MeshFileDocument {
    /// Optional config schema version stamp. When present it must match
    /// [`CURRENT_CONFIG_VERSION`]; the mesh model has no file migrations.
    #[serde(default)]
    version: Option<String>,
    mesh: Box<crate::modes::mesh::config::MeshConfig>,
}

/// Load the mesh document at `path` and build the node's [`MeshSlice`].
///
/// Runs the same normalization + validation the CP-side slice builder applies
/// (`normalize_fields`/`normalize_mesh_fields` + `validate_mesh_fields`)
/// before narrowing via [`MeshSlice::from_gateway_config`], so a document the
/// initial load accepts cannot later be rejected by the slice-apply task for
/// mesh-field validity.
pub fn load_mesh_slice_from_file(
    path: &Path,
    request: MeshSliceRequest,
) -> Result<MeshSlice, anyhow::Error> {
    let mesh = read_mesh_config_document(path)?;
    let config = normalized_mesh_gateway_config(mesh)?;
    Ok(MeshSlice::from_gateway_config(&config, request))
}

/// Async-runtime wrapper: performs the bounded stable read + parse on a
/// blocking worker so Tokio core workers stay free for heartbeats/shutdown.
pub async fn load_mesh_slice_from_file_off_thread(
    path: PathBuf,
    request: MeshSliceRequest,
) -> Result<MeshSlice, anyhow::Error> {
    tokio::task::spawn_blocking(move || load_mesh_slice_from_file(&path, request))
        .await
        .map_err(|error| {
            anyhow::anyhow!("Mesh configuration file validation worker failed: {error}")
        })?
}

/// Parse the mesh document at `path` into its raw (un-normalized, un-validated)
/// [`crate::modes::mesh::config::MeshConfig`].
///
/// Split out of [`load_mesh_slice_from_file`] for the stock xDS
/// interoperability profile (issue #3317), which needs to substitute the
/// discovery-owned `services` / `workloads` before normalization and then run
/// the SAME normalize + validate + project pipeline, so a stock-built slice is
/// structurally indistinguishable from a file-built one.
pub fn read_mesh_config_document(
    path: &Path,
) -> Result<Box<crate::modes::mesh::config::MeshConfig>, anyhow::Error> {
    if !path.exists() {
        anyhow::bail!("mesh configuration file not found: {}", path.display());
    }

    // Mirror file mode's credential-hygiene warning: mesh documents can carry
    // JWT issuer material and trust bundles.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = std::fs::metadata(path) {
            let mode = metadata.permissions().mode();
            if mode & 0o004 != 0 {
                warn!(
                    "Mesh config file {} is world-readable (mode {:o}). Consider restricting \
                     permissions as it may contain trust material.",
                    path.display(),
                    mode & 0o777
                );
            }
        }
    }

    let options = StableFileReadOptions::new(MAX_MESH_CONFIG_FILE_BYTES, "mesh configuration file");
    let content = read_stable_file(path, options)
        .map_err(|error| stable_file_error_anyhow(path, options, error))?;

    // Extension first; unknown/extensionless paths sniff once so a large
    // document is not fully parsed twice merely to detect format.
    let is_yaml = detect_json_or_yaml_extension(path, &content);

    let document: MeshFileDocument = if is_yaml {
        serde_yaml::from_str(&content).map_err(|e| anyhow::anyhow!(mesh_doc_parse_error(e)))?
    } else {
        serde_json::from_str(&content).map_err(|e| anyhow::anyhow!(mesh_doc_parse_error(e)))?
    };

    if let Some(version) = document.version.as_deref()
        && version != CURRENT_CONFIG_VERSION
    {
        anyhow::bail!(
            "mesh configuration file declares version '{version}' but this gateway expects \
             '{CURRENT_CONFIG_VERSION}' (the mesh model has no file migrations)"
        );
    }

    Ok(document.mesh)
}

/// Wrap a mesh section in a [`GatewayConfig`] and run the same normalization +
/// mesh-field validation the CP-side slice builder applies, so a document this
/// accepts cannot later be rejected by the slice-apply task for mesh-field
/// validity.
pub fn normalized_mesh_gateway_config(
    mesh: Box<crate::modes::mesh::config::MeshConfig>,
) -> Result<GatewayConfig, anyhow::Error> {
    let mut config = GatewayConfig {
        version: CURRENT_CONFIG_VERSION.to_string(),
        mesh: Some(mesh),
        loaded_at: chrono::Utc::now(),
        ..GatewayConfig::default()
    };
    config.normalize_fields();
    config.normalize_mesh_fields();
    let mesh_errors = config.validate_mesh_fields();
    if !mesh_errors.is_empty() {
        anyhow::bail!(
            "mesh configuration validation failed: {}",
            mesh_errors.join("; ")
        );
    }
    Ok(config)
}

/// Wrap a serde error with a pointer at the document contract so an operator
/// who fed a full gateway config file gets steered instead of puzzled by a
/// bare "unknown field `proxies`".
fn mesh_doc_parse_error(err: impl std::fmt::Display) -> String {
    format!(
        "invalid mesh configuration document: {err} (the localized mesh source consumes only an \
         optional `version` plus the `mesh` section; gateway resources such as proxies/upstreams \
         belong to FERRUM_MODE=file)"
    )
}

/// Record that a localized mesh reload signal was observed.
///
/// Returns the generation that now owns the latest request. Call this when the
/// signal arrives — not when a follow-up worker is later spawned — so an
/// in-flight older candidate becomes stale immediately and cannot install.
pub fn record_mesh_reload_request(latest_requested: &AtomicU64) -> u64 {
    latest_requested.fetch_add(1, Ordering::AcqRel) + 1
}

/// A completed candidate may install only when it still owns the latest
/// requested generation (exact equality). A future/out-of-contract generation
/// must not be treated as current.
pub fn mesh_reload_generation_is_current(generation: u64, latest_requested: u64) -> bool {
    generation == latest_requested
}

/// Which reload-loop arm wins when one or more are simultaneously ready.
///
/// Shutdown is ordered first so a tied completion cannot publish after the
/// gate should already be closed. Production loops use a `biased;`
/// `tokio::select!` with the shutdown arm listed first; this helper is the
/// behavioral contract those loops implement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshReloadSelectReady {
    Hangup,
    Completion,
    Shutdown,
}

/// Deterministic winner for the localized file / stock-policy reload loop.
///
/// When shutdown and completion are both ready, shutdown wins. Hangup is only
/// selected when shutdown is not ready.
pub fn mesh_reload_select_priority(
    hangup_ready: bool,
    completion_ready: bool,
    shutdown_ready: bool,
) -> Option<MeshReloadSelectReady> {
    if shutdown_ready {
        return Some(MeshReloadSelectReady::Shutdown);
    }
    if hangup_ready {
        return Some(MeshReloadSelectReady::Hangup);
    }
    if completion_ready {
        return Some(MeshReloadSelectReady::Completion);
    }
    None
}

/// Whether a completed load may publish after the select winner is known.
///
/// Shutdown winners never publish, even if `publish_allowed` has not flipped
/// yet — callers must stop accepting before returning from the shutdown arm.
pub fn mesh_reload_completion_may_publish(
    publish_allowed: bool,
    select_winner: MeshReloadSelectReady,
) -> bool {
    publish_allowed && matches!(select_winner, MeshReloadSelectReady::Completion)
}

/// Sticky local-source health + race-safe recovery handshake (issue #3776).
///
/// `config_rejected` is the authenticated `/health` surface held by
/// [`crate::admin::AdminState`]. Clearing that flag is gated on the exact
/// current recovery candidate being accepted by the proxy apply lifecycle —
/// provisional `install_slice` / policy channel send must not clear it, and an
/// older success must not clear after a newer failure.
#[derive(Debug)]
pub struct MeshLocalSourceRecovery {
    config_rejected: Arc<AtomicBool>,
    /// Monotonic epoch advanced on reject and on every new pending recovery.
    epoch: AtomicU64,
    /// Epoch currently allowed to clear `config_rejected` after proxy apply.
    /// `0` means no pending recovery.
    pending_epoch: AtomicU64,
    /// Active stock-policy recovery epoch (`0` when none). While set, stock
    /// installs rebind the pending slice identity so a discovery update that
    /// incorporates the recovered policy can still clear.
    policy_recovery_epoch: AtomicU64,
    /// Content digest of the pending recovery slice. `None` until bound.
    pending_digest: Mutex<Option<[u8; 32]>>,
}

impl MeshLocalSourceRecovery {
    /// Share one recovery handshake across the source watcher, stock install
    /// path, and mesh apply task while exposing the same `Arc<AtomicBool>` to
    /// AdminState.
    pub fn new(config_rejected: Arc<AtomicBool>) -> Arc<Self> {
        Arc::new(Self {
            config_rejected,
            epoch: AtomicU64::new(0),
            pending_epoch: AtomicU64::new(0),
            policy_recovery_epoch: AtomicU64::new(0),
            pending_digest: Mutex::new(None),
        })
    }

    /// Authenticated `/health` sticky signal (unchanged AdminState surface).
    pub fn config_rejected_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.config_rejected)
    }

    /// Whether authenticated health currently reports local-source rejection.
    pub fn is_rejected(&self) -> bool {
        self.config_rejected.load(Ordering::Relaxed)
    }

    /// Epoch currently pending proxy acceptance (`0` = none).
    pub fn pending_epoch(&self) -> u64 {
        self.pending_epoch.load(Ordering::Acquire)
    }

    /// Raise `config_rejected` and cancel any older pending recovery so it can
    /// no longer clear health.
    pub fn mark_rejected(&self) {
        self.config_rejected.store(true, Ordering::Relaxed);
        let _ = self.epoch.fetch_add(1, Ordering::AcqRel);
        self.pending_epoch.store(0, Ordering::Release);
        self.policy_recovery_epoch.store(0, Ordering::Release);
        if let Ok(mut guard) = self.pending_digest.lock() {
            *guard = None;
        }
    }

    /// Mark a provisionally installed file-source recovery candidate.
    ///
    /// Does **not** clear `config_rejected`. An uncomputable content identity
    /// fails closed (stays/sets degraded) because recovery cannot be proven.
    pub fn mark_slice_recovery_pending(&self, slice: &MeshSlice) -> Option<u64> {
        match slice_content_identity(slice) {
            MeshRevisionContentIdentity::Digest(digest) => {
                let epoch = self.epoch.fetch_add(1, Ordering::AcqRel) + 1;
                if let Ok(mut guard) = self.pending_digest.lock() {
                    *guard = Some(digest);
                }
                self.pending_epoch.store(epoch, Ordering::Release);
                self.policy_recovery_epoch.store(0, Ordering::Release);
                Some(epoch)
            }
            MeshRevisionContentIdentity::Unavailable => {
                warn!(
                    "Mesh local reload candidate has uncomputable content identity; raising \
                     config_rejected because recovery cannot be proven"
                );
                self.mark_rejected();
                None
            }
        }
    }

    /// Begin a stock-policy recovery after a valid baseline is published to the
    /// watch channel. Does **not** clear `config_rejected`; the pending slice
    /// identity is bound later when the stock client installs a rebuilt slice.
    pub fn begin_policy_recovery(&self) -> u64 {
        let epoch = self.epoch.fetch_add(1, Ordering::AcqRel) + 1;
        if let Ok(mut guard) = self.pending_digest.lock() {
            *guard = None;
        }
        self.pending_epoch.store(epoch, Ordering::Release);
        self.policy_recovery_epoch.store(epoch, Ordering::Release);
        epoch
    }

    /// Rebind the pending recovery identity when the stock client installs a
    /// slice that incorporates the active policy recovery (including a later
    /// discovery update on that same recovered baseline).
    pub fn bind_installed_slice_if_policy_recovery(&self, slice: &MeshSlice) {
        let epoch = self.policy_recovery_epoch.load(Ordering::Acquire);
        if epoch == 0 || self.pending_epoch.load(Ordering::Acquire) != epoch {
            return;
        }
        match slice_content_identity(slice) {
            MeshRevisionContentIdentity::Digest(digest) => {
                if let Ok(mut guard) = self.pending_digest.lock() {
                    *guard = Some(digest);
                }
            }
            MeshRevisionContentIdentity::Unavailable => {
                warn!(
                    "Stock policy recovery slice has uncomputable content identity; raising \
                     config_rejected because recovery cannot be proven"
                );
                self.mark_rejected();
            }
        }
    }

    /// Clear sticky rejection only when the proxy accepted the exact current
    /// pending recovery identity (Applied or content-identical no-op).
    pub fn note_proxy_apply_success(&self, slice: &MeshSlice) {
        let pending = self.pending_epoch.load(Ordering::Acquire);
        if pending == 0 {
            return;
        }
        let expected = match self.pending_digest.lock() {
            Ok(guard) => *guard,
            Err(_) => return,
        };
        let Some(expected) = expected else {
            return;
        };
        match slice_content_identity(slice) {
            MeshRevisionContentIdentity::Digest(digest) if digest == expected => {
                if self.pending_epoch.load(Ordering::Acquire) != pending {
                    return;
                }
                crate::modes::clear_config_rejected_after_accepted_full_reload(
                    &self.config_rejected,
                    "mesh local-source recovery",
                );
                self.pending_epoch.store(0, Ordering::Release);
                self.policy_recovery_epoch.store(0, Ordering::Release);
                if let Ok(mut guard) = self.pending_digest.lock() {
                    *guard = None;
                }
            }
            _ => {}
        }
    }

    /// Proxy rejection / quarantine of a pending recovery leaves degraded and
    /// cancels that pending clear.
    pub fn note_proxy_apply_rejection(&self, slice: &MeshSlice) {
        let pending = self.pending_epoch.load(Ordering::Acquire);
        if pending == 0 {
            return;
        }
        let expected = match self.pending_digest.lock() {
            Ok(guard) => *guard,
            Err(_) => {
                self.mark_rejected();
                return;
            }
        };
        let matches_pending = match (expected, slice_content_identity(slice)) {
            (Some(expected), MeshRevisionContentIdentity::Digest(digest)) => digest == expected,
            // Unbound stock policy recovery (install not yet bound) still
            // cancels when any apply under that epoch fails closed.
            (None, _) => self.policy_recovery_epoch.load(Ordering::Acquire) == pending,
            _ => false,
        };
        if matches_pending {
            self.mark_rejected();
        }
    }
}

/// Apply outcome for a localized mesh file/policy reload candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshLocalReloadApply {
    /// Candidate replaced (or was admitted into) live received state.
    /// Sticky health clears only after proxy apply accepts this recovery.
    Applied,
    /// Candidate was valid and content-identical to the live generation.
    /// Sticky health clears only after proxy apply accepts this recovery.
    Unchanged,
    /// Candidate was refused; last-good retained and `config_rejected` raised.
    Rejected,
}

/// Apply a loaded mesh-file reload candidate through the recovery handshake.
///
/// Load failure or revision quarantine raises the sticky degraded signal and
/// cancels any older pending recovery. A provisionally installed candidate
/// marks recovery pending but does **not** clear `config_rejected` — only the
/// mesh apply task does, once the exact current recovery is proxy-accepted.
pub fn apply_mesh_file_reload_candidate(
    state: &MeshRuntimeState,
    recovery: &MeshLocalSourceRecovery,
    candidate: Result<MeshSlice, anyhow::Error>,
) -> MeshLocalReloadApply {
    match candidate {
        Ok(slice) => {
            let unchanged = state
                .snapshot()
                .as_ref()
                .as_ref()
                .is_some_and(|live| live.content_eq(&slice));
            let installed = slice.clone();
            match state.install_slice(slice) {
                MeshSliceInstall::Installed => {
                    if recovery.mark_slice_recovery_pending(&installed).is_none() {
                        return MeshLocalReloadApply::Rejected;
                    }
                    if unchanged {
                        MeshLocalReloadApply::Unchanged
                    } else {
                        MeshLocalReloadApply::Applied
                    }
                }
                MeshSliceInstall::Quarantined(rejection) => {
                    warn!(
                        ?rejection,
                        "Mesh file reload quarantined by the revision gate; keeping the last \
                         good mesh slice and raising config_rejected"
                    );
                    recovery.mark_rejected();
                    MeshLocalReloadApply::Rejected
                }
            }
        }
        Err(error) => {
            warn!(
                error = %error,
                "Failed to reload mesh config file; keeping the last good mesh slice and \
                 raising config_rejected"
            );
            recovery.mark_rejected();
            MeshLocalReloadApply::Rejected
        }
    }
}

/// Mark a localized mesh reload failure (join panic, worker failure) on the
/// shared recovery handshake without mutating the live slice.
pub fn mark_mesh_local_reload_rejected(recovery: &MeshLocalSourceRecovery) {
    recovery.mark_rejected();
}

/// Reload the mesh document on SIGHUP (Unix), keeping the last good slice
/// when a reload fails. The initial load happens before this task is spawned
/// (fail-closed at startup); identical reloads are deduped downstream by the
/// slice-apply task's `content_eq` check.
///
/// Filesystem + parse work runs on `spawn_blocking`. Rapid SIGHUP delivery is
/// coalesced: at most one load runs at a time, and a signal that arrives
/// during an in-flight load schedules exactly one follow-up generation. The
/// requested generation advances when the signal is observed so an older
/// completed load cannot install. Watcher shutdown stops accepting candidates
/// immediately and does not await a started (non-cancellable) blocking job.
/// The select is `biased` with shutdown first so a simultaneous completion
/// cannot publish.
pub async fn start_mesh_file_source_with_shutdown(
    path: String,
    request: MeshSliceRequest,
    state: MeshRuntimeState,
    recovery: Arc<MeshLocalSourceRecovery>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    #[cfg(unix)]
    {
        use futures_util::FutureExt as _;

        let mut hangup = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        {
            Ok(stream) => stream,
            Err(e) => {
                warn!(
                    error = %e,
                    "Failed to register SIGHUP handler for mesh file source; the mesh \
                     document will not reload until restart"
                );
                super::common::wait_for_shutdown(&mut shutdown_rx).await;
                return;
            }
        };

        let latest_requested = AtomicU64::new(0);
        let publish_allowed = AtomicBool::new(true);
        let mut accepted_generation = 0u64;
        let mut pending_follow_up = false;
        let mut in_flight: Option<(
            u64,
            tokio::task::JoinHandle<Result<MeshSlice, anyhow::Error>>,
        )> = None;

        loop {
            // `biased;` + shutdown first: when shutdown and completion are both
            // ready, shutdown wins and completion cannot publish.
            tokio::select! {
                biased;
                _ = super::common::wait_for_shutdown(&mut shutdown_rx) => {
                    info!("Mesh file source shutting down");
                    stop_accepting_reload_candidates(&publish_allowed, &mut in_flight);
                    return;
                }
                received = hangup.recv() => {
                    if received.is_none() {
                        warn!(
                            "SIGHUP stream closed; mesh file source will not reload until restart"
                        );
                        stop_accepting_reload_candidates(&publish_allowed, &mut in_flight);
                        super::common::wait_for_shutdown(&mut shutdown_rx).await;
                        return;
                    }
                    // Coalesce any already-queued hangups into one follow-up.
                    while hangup.recv().now_or_never().flatten().is_some() {}

                    // Advance the requested generation at signal observation so
                    // an in-flight older candidate becomes stale immediately.
                    let generation = record_mesh_reload_request(&latest_requested);
                    if in_flight.is_some() {
                        pending_follow_up = true;
                        continue;
                    }

                    in_flight = Some(spawn_mesh_reload(generation, &path, request.clone()));
                }
                join_result = async {
                    match in_flight.as_mut() {
                        Some((_, handle)) => Some(handle.await),
                        None => {
                            std::future::pending::<()>().await;
                            None
                        }
                    }
                } => {
                    let Some((generation, _)) = in_flight.take() else {
                        continue;
                    };
                    let Some(join_result) = join_result else {
                        continue;
                    };

                    if !mesh_reload_completion_may_publish(
                        publish_allowed.load(Ordering::Acquire),
                        MeshReloadSelectReady::Completion,
                    ) {
                        // Shutdown already stopped accepting candidates.
                        continue;
                    }

                    match join_result {
                        Ok(Ok(slice)) => {
                            let latest = latest_requested.load(Ordering::Acquire);
                            if !mesh_reload_generation_is_current(generation, latest) {
                                info!(
                                    file_path = %path,
                                    generation,
                                    latest,
                                    "Discarding stale mesh file reload generation"
                                );
                            } else if generation >= accepted_generation {
                                let version = slice.version.clone();
                                let outcome = apply_mesh_file_reload_candidate(
                                    &state,
                                    &recovery,
                                    Ok(slice),
                                );
                                if matches!(
                                    outcome,
                                    MeshLocalReloadApply::Applied
                                        | MeshLocalReloadApply::Unchanged
                                ) {
                                    info!(
                                        file_path = %path,
                                        mesh_slice_version = %version,
                                        generation,
                                        ?outcome,
                                        "Reloaded mesh config file on SIGHUP"
                                    );
                                    accepted_generation = generation;
                                }
                            }
                        }
                        Ok(Err(e)) => {
                            warn!(
                                file_path = %path,
                                generation,
                                error = %e,
                                "Failed to reload mesh config file on SIGHUP; keeping the last \
                                 good mesh slice"
                            );
                            mark_mesh_local_reload_rejected(&recovery);
                        }
                        Err(join_error) if join_error.is_cancelled() => {
                            info!(
                                file_path = %path,
                                generation,
                                "Mesh file reload join cancelled before publish"
                            );
                        }
                        Err(join_error) => {
                            warn!(
                                file_path = %path,
                                generation,
                                error = %join_error,
                                "Mesh file reload worker panicked; keeping the last good mesh slice"
                            );
                            mark_mesh_local_reload_rejected(&recovery);
                        }
                    }

                    if pending_follow_up && publish_allowed.load(Ordering::Acquire) {
                        pending_follow_up = false;
                        // Reuse the latest requested generation recorded when
                        // the coalesced signal(s) arrived.
                        let generation = latest_requested.load(Ordering::Acquire);
                        in_flight = Some(spawn_mesh_reload(generation, &path, request.clone()));
                    }
                }
            }
        }
    }

    #[cfg(not(unix))]
    {
        info!(
            file_path = %path,
            "Mesh file source loaded; live reload is Unix-only (SIGHUP), restart to pick up \
             changes"
        );
        let _ = &request;
        let _ = &state;
        let _ = &recovery;
        super::common::wait_for_shutdown(&mut shutdown_rx).await;
    }
}

#[cfg(unix)]
fn spawn_mesh_reload(
    generation: u64,
    path: &str,
    request: MeshSliceRequest,
) -> (
    u64,
    tokio::task::JoinHandle<Result<MeshSlice, anyhow::Error>>,
) {
    let load_path = PathBuf::from(path);
    let handle =
        tokio::task::spawn_blocking(move || load_mesh_slice_from_file(&load_path, request));
    (generation, handle)
}

/// Stop accepting reload candidates and detach any in-flight blocking work.
///
/// Tokio cannot cancel a `spawn_blocking` task once it has started. Aborting
/// the join handle only prevents scheduling if the job has not begun; awaiting
/// a started job would stall watcher shutdown. Dropping the handle detaches
/// the result, and [`publish_allowed`] prevents a late completion from
/// installing if the join arm still races.
#[cfg(unix)]
fn stop_accepting_reload_candidates(
    publish_allowed: &AtomicBool,
    in_flight: &mut Option<(u64, tokio::task::JoinHandle<Result<MeshSlice, anyhow::Error>>)>,
) {
    publish_allowed.store(false, Ordering::Release);
    if let Some((_, handle)) = in_flight.take() {
        handle.abort();
        drop(handle);
    }
}
