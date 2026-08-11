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
//! the last-good slice; the next accepted Applied/Unchanged reload clears it.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use serde::Deserialize;
use tracing::{info, warn};

use crate::config::stable_file::{
    MAX_MESH_CONFIG_FILE_BYTES, StableFileReadOptions, detect_json_or_yaml_extension,
    read_stable_file, stable_file_error_anyhow,
};
use crate::config::types::{CURRENT_CONFIG_VERSION, GatewayConfig};
use crate::modes::mesh::runtime::{MeshRuntimeState, MeshSliceInstall};
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

/// A completed candidate may install only when it is still current relative to
/// the latest requested generation.
pub fn mesh_reload_generation_is_current(generation: u64, latest_requested: u64) -> bool {
    generation >= latest_requested
}

/// Apply outcome for a localized mesh file/policy reload candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshLocalReloadApply {
    /// Candidate replaced (or was admitted into) live state.
    Applied,
    /// Candidate was valid and content-identical to the live generation.
    Unchanged,
    /// Candidate was refused; last-good retained and `config_rejected` raised.
    Rejected,
}

/// Apply a loaded mesh-file reload candidate and update `config_rejected`.
///
/// Mirrors file-mode [`crate::modes::file::apply_file_config_candidate`]: load
/// failure or apply quarantine raises the sticky degraded signal; Applied and
/// Unchanged clear it. Last-good slice retention is handled by skipping
/// install on Err / Quarantined.
pub fn apply_mesh_file_reload_candidate(
    state: &MeshRuntimeState,
    config_rejected: &AtomicBool,
    candidate: Result<MeshSlice, anyhow::Error>,
) -> MeshLocalReloadApply {
    match candidate {
        Ok(slice) => {
            let unchanged = state
                .snapshot()
                .as_ref()
                .as_ref()
                .is_some_and(|live| live.content_eq(&slice));
            match state.install_slice(slice) {
                MeshSliceInstall::Installed => {
                    let outcome = if unchanged {
                        MeshLocalReloadApply::Unchanged
                    } else {
                        MeshLocalReloadApply::Applied
                    };
                    crate::modes::clear_config_rejected_after_accepted_full_reload(
                        config_rejected,
                        "mesh file reload",
                    );
                    outcome
                }
                MeshSliceInstall::Quarantined(rejection) => {
                    warn!(
                        ?rejection,
                        "Mesh file reload quarantined by the revision gate; keeping the last \
                         good mesh slice and raising config_rejected"
                    );
                    config_rejected.store(true, Ordering::Relaxed);
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
            config_rejected.store(true, Ordering::Relaxed);
            MeshLocalReloadApply::Rejected
        }
    }
}

/// Mark a localized mesh reload failure (join panic, worker failure) on the
/// shared `config_rejected` signal without mutating the live slice.
pub fn mark_mesh_local_reload_rejected(config_rejected: &AtomicBool) {
    config_rejected.store(true, Ordering::Relaxed);
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
pub async fn start_mesh_file_source_with_shutdown(
    path: String,
    request: MeshSliceRequest,
    state: MeshRuntimeState,
    config_rejected: Arc<AtomicBool>,
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
            tokio::select! {
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

                    if !publish_allowed.load(Ordering::Acquire) {
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
                                    &config_rejected,
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
                            mark_mesh_local_reload_rejected(&config_rejected);
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
                            mark_mesh_local_reload_rejected(&config_rejected);
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
                _ = super::common::wait_for_shutdown(&mut shutdown_rx) => {
                    info!("Mesh file source shutting down");
                    stop_accepting_reload_candidates(&publish_allowed, &mut in_flight);
                    return;
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
        let _ = &config_rejected;
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
