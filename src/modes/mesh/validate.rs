//! `ferrum-edge validate` file-source selection for mesh mode (issue #3925).
//!
//! `run` is unchanged: `-c/--spec` still materializes only
//! `FERRUM_FILE_CONFIG_PATH`, and mesh file protocol still requires an
//! explicit `FERRUM_MESH_CONFIG_PROTOCOL=file` plus
//! `FERRUM_MESH_FILE_CONFIG_PATH`. Validate is the operator-facing check for a
//! localized slice, so this module may:
//!
//! * treat `-c/--spec` (`FERRUM_FILE_CONFIG_PATH`) as the file protocol's
//!   document when protocol is `file` / `stock_xds` or is safely inferred
//! * infer `file` only from the localized `{version?, mesh}` document shape
//! * fail closed on explicit contradictory protocol/path selections
//!
//! Call [`prepare_validate_file_source`] from `validate` only, before
//! `EnvConfig::from_env`, never from `run`.

use std::path::{Path, PathBuf};

use crate::config::conf_file::resolve_ferrum_var;
use crate::modes::mesh::MeshConfigProtocol;
use crate::modes::mesh::config_consumer::file_source::probe_localized_mesh_file_document;

/// `--spec/-c` (`FERRUM_FILE_CONFIG_PATH`) and `FERRUM_MESH_FILE_CONFIG_PATH`
/// name different documents while mesh file validation would consume one.
pub const CONFLICTING_MESH_FILE_SOURCES: &str = "conflicting mesh file sources: --spec/-c \
     (FERRUM_FILE_CONFIG_PATH) and FERRUM_MESH_FILE_CONFIG_PATH select different documents; \
     set only one or make both paths identical";

/// Prepare mesh file-source selection for `ferrum-edge validate`.
///
/// When the operating mode is mesh, this may materialize
/// `FERRUM_MESH_CONFIG_PROTOCOL=file` and/or `FERRUM_MESH_FILE_CONFIG_PATH`
/// into the process environment so `EnvConfig` and mesh runtime admission see
/// the same file-protocol picture `run` would after an explicit file-protocol
/// configuration. Must run before `EnvConfig::from_env` and only on the
/// validate path (single-threaded, before the multi-threaded runtime).
pub fn prepare_validate_file_source() -> Result<(), String> {
    if !mode_is_mesh() {
        return Ok(());
    }

    let protocol = explicit_mesh_config_protocol()?;
    let spec_path = optional_path("FERRUM_FILE_CONFIG_PATH");
    let mesh_path = optional_path("FERRUM_MESH_FILE_CONFIG_PATH");

    match protocol {
        Some(MeshConfigProtocol::File | MeshConfigProtocol::StockXds) => {
            bind_local_document_path(spec_path.as_deref(), mesh_path.as_deref())
        }
        Some(protocol @ (MeshConfigProtocol::Native | MeshConfigProtocol::Xds)) => {
            refuse_localized_spec_for_control_plane(protocol, spec_path.as_deref())
        }
        None => infer_file_from_localized_document(spec_path.as_deref(), mesh_path.as_deref()),
    }
}

fn native_or_xds_spec_conflict(protocol: MeshConfigProtocol) -> String {
    format!(
        "FERRUM_MESH_CONFIG_PROTOCOL={} cannot consume a localized {{version?, mesh}} document \
         from --spec/-c; set FERRUM_MESH_CONFIG_PROTOCOL=file or omit \
         FERRUM_MESH_CONFIG_PROTOCOL to infer file from that document",
        protocol.as_str()
    )
}

fn mode_is_mesh() -> bool {
    resolve_ferrum_var("FERRUM_MODE").is_some_and(|mode| mode.trim().eq_ignore_ascii_case("mesh"))
}

fn explicit_mesh_config_protocol() -> Result<Option<MeshConfigProtocol>, String> {
    match optional_path("FERRUM_MESH_CONFIG_PROTOCOL") {
        Some(raw) => MeshConfigProtocol::parse(&raw).map(Some),
        None => Ok(None),
    }
}

fn optional_path(key: &str) -> Option<String> {
    resolve_ferrum_var(key).filter(|value| !value.trim().is_empty())
}

fn bind_local_document_path(
    spec_path: Option<&str>,
    mesh_path: Option<&str>,
) -> Result<(), String> {
    match (spec_path, mesh_path) {
        (Some(spec), Some(mesh)) if !same_resolved_path(spec, mesh) => {
            Err(CONFLICTING_MESH_FILE_SOURCES.to_string())
        }
        (Some(spec), None) => {
            set_env("FERRUM_MESH_FILE_CONFIG_PATH", spec);
            Ok(())
        }
        _ => Ok(()),
    }
}

fn refuse_localized_spec_for_control_plane(
    protocol: MeshConfigProtocol,
    spec_path: Option<&str>,
) -> Result<(), String> {
    let Some(spec_path) = spec_path else {
        return Ok(());
    };
    match probe_localized_mesh_file_document(Path::new(spec_path)) {
        Ok(true) => Err(native_or_xds_spec_conflict(protocol)),
        Ok(false) | Err(_) => Ok(()),
    }
}

fn infer_file_from_localized_document(
    spec_path: Option<&str>,
    mesh_path: Option<&str>,
) -> Result<(), String> {
    if let Some(spec) = spec_path {
        match probe_localized_mesh_file_document(Path::new(spec)) {
            Ok(true) => {
                if let Some(mesh) = mesh_path
                    && !same_resolved_path(spec, mesh)
                {
                    return Err(CONFLICTING_MESH_FILE_SOURCES.to_string());
                }
                select_file_protocol(spec, mesh_path.is_none());
                return Ok(());
            }
            Ok(false) => return Ok(()),
            Err(error) => return Err(error.to_string()),
        }
    }

    if let Some(mesh) = mesh_path {
        match probe_localized_mesh_file_document(Path::new(mesh)) {
            Ok(true) => {
                select_file_protocol(mesh, false);
                Ok(())
            }
            Ok(false) => Ok(()),
            Err(error) => Err(error.to_string()),
        }
    } else {
        Ok(())
    }
}

fn select_file_protocol(document_path: &str, materialize_mesh_path: bool) {
    set_env("FERRUM_MESH_CONFIG_PROTOCOL", "file");
    if materialize_mesh_path {
        set_env("FERRUM_MESH_FILE_CONFIG_PATH", document_path);
    }
}

fn same_resolved_path(left: &str, right: &str) -> bool {
    resolve_against_cwd(Path::new(left.trim())) == resolve_against_cwd(Path::new(right.trim()))
}

fn resolve_against_cwd(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    }
}

fn set_env(key: &str, value: &str) {
    // SAFETY: `execute_validate` runs before the multi-threaded runtime, the
    // same single-threaded window `infer_file_mode` uses. Tests that call this
    // helper hold the process-wide env lock.
    unsafe { std::env::set_var(key, value) };
}
