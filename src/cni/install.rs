//! Host-side installer and uninstaller for the `ferrum-cni` binary.
//!
//! The node-agent image is distroless, so Helm cannot use `/bin/sh` to copy
//! files or render a CNI conflist. Instead the init container executes
//! `ferrum-cni install`, and this module performs those filesystem changes
//! directly.
//!
//! # Why uninstall needs ownership evidence
//!
//! Installing writes a chained `*-ferrum.conflist` into the host's shared
//! `/etc/cni/net.d/`. From that moment every pod ADD on the node traverses
//! `ferrum-cni`, so leaving the file behind after the node-agent goes away is
//! a node-wide pod-creation outage (issue #3609). Removal therefore has to be
//! available, idempotent, and — because the directory is shared with the
//! cluster's primary CNI and any other meta-plugin — provably scoped to
//! Ferrum's own artifacts.
//!
//! The proof is written at install time and is checked again at removal time:
//!
//! - the generated conflist carries a `managedBy` / `owner` / `generation`
//!   marker inside its own `ferrum-cni` plugin entry (a place the CNI spec
//!   reserves for the plugin, so no neighbour can be confused by it), and
//! - a sibling [`OWNERSHIP_MANIFEST_FILE_NAME`] manifest records the same
//!   ownership plus the SHA-256 of the binary that was installed.
//!
//! Uninstall removes an artifact only when that evidence is present and
//! matches; anything else is retained and reported. It never reads or
//! rewrites a neighbouring CNI configuration, never follows a symlink, and
//! never removes a binary while a conflist still references it.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

use serde_json::{Map, Value};
use thiserror::Error;

use crate::fips::approved::Sha256;

const FERRUM_PLUGIN_TYPE: &str = "ferrum-cni";

/// Value of the `managedBy` marker Ferrum writes into both the generated
/// conflist's own plugin entry and the sibling ownership manifest. Uninstall
/// refuses to remove any artifact that does not carry it.
pub const FERRUM_MANAGED_BY: &str = "ferrum-edge";

/// Sibling ownership manifest written next to the generated conflist.
///
/// The name deliberately does not end in `.conf` / `.conflist` / `.json`, so
/// the container runtime never mistakes it for a network configuration and
/// [`find_primary_config`]'s scan skips it outright.
pub const OWNERSHIP_MANIFEST_FILE_NAME: &str = ".ferrum-cni-owned.marker";

/// Schema version of the ownership manifest. A manifest with any other
/// version is treated as unreadable (ownership unproven) rather than
/// guessed at.
const OWNERSHIP_MANIFEST_SCHEMA_VERSION: u64 = 1;

/// Hard ceiling on the JSON artifacts uninstall is willing to read before
/// deciding ownership. Anything larger was not written by the installer, so
/// it is retained instead of parsed.
const MAX_OWNED_JSON_BYTES: u64 = 1024 * 1024;

/// Hard ceiling on the installed plugin binary uninstall is willing to hash.
const MAX_OWNED_BINARY_BYTES: u64 = 512 * 1024 * 1024;

/// Bound on the opaque operator-supplied owner / generation tokens.
const MAX_OWNERSHIP_TOKEN_BYTES: usize = 128;

/// Install-time identity stamped onto every generated artifact.
///
/// `owner` is expected to be stable across upgrades of one deployment (the
/// Helm chart uses `<release namespace>/<release name>`), while `generation`
/// identifies one concrete install instance (the chart uses the node-agent
/// pod UID). Uninstall matches on `owner`, so it cleans up whatever revision
/// is currently on the node; the readiness rollback watcher matches on both,
/// so it can never remove artifacts a newer install wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CniOwnership {
    pub owner: String,
    pub generation: String,
}

impl CniOwnership {
    fn validate(&self) -> Result<(), CniInstallError> {
        validate_ownership_token("OWNER_ID", &self.owner)?;
        validate_ownership_token("INSTALL_GENERATION", &self.generation)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CniInstallConfig {
    pub host_bin_dir: String,
    pub host_conf_dir: String,
    pub host_socket_dir: String,
    pub conf_file_name: String,
    pub chained_with: String,
    pub socket_path: String,
    pub ownership: CniOwnership,
}

impl CniInstallConfig {
    pub fn from_env() -> Result<Self, CniInstallError> {
        Ok(Self {
            host_bin_dir: required_env("HOST_BIN_DIR")?,
            host_conf_dir: required_env("HOST_CONF_DIR")?,
            host_socket_dir: required_env("HOST_SOCKET_DIR")?,
            conf_file_name: required_env("CONF_FILE_NAME")?,
            chained_with: required_env("CHAINED_WITH")?,
            socket_path: required_env("SOCKET_PATH")?,
            ownership: CniOwnership {
                owner: required_env("OWNER_ID")?,
                generation: required_env("INSTALL_GENERATION")?,
            },
        })
    }
}

/// Which Ferrum-generated artifacts a cleanup run may remove.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CniUninstallConfig {
    pub host_bin_dir: String,
    pub host_conf_dir: String,
    pub conf_file_name: String,
    /// When set, only artifacts recorded under this owner are removed.
    pub expected_owner: Option<String>,
    /// When set, only artifacts recorded under this install generation are
    /// removed. Left unset by `helm uninstall` (any generation of this
    /// owner's install should go) and set by the readiness rollback watcher
    /// (only its own generation may go).
    pub expected_generation: Option<String>,
}

impl CniUninstallConfig {
    pub fn from_env() -> Result<Self, CniInstallError> {
        Ok(Self {
            host_bin_dir: required_env("HOST_BIN_DIR")?,
            host_conf_dir: required_env("HOST_CONF_DIR")?,
            conf_file_name: required_env("CONF_FILE_NAME")?,
            expected_owner: optional_env("EXPECTED_OWNER"),
            expected_generation: optional_env("EXPECTED_GENERATION"),
        })
    }

    fn validate(&self) -> Result<(), CniInstallError> {
        validate_single_component("CONF_FILE_NAME", &self.conf_file_name)?;
        if let Some(owner) = self.expected_owner.as_deref() {
            validate_ownership_token("EXPECTED_OWNER", owner)?;
        }
        if let Some(generation) = self.expected_generation.as_deref() {
            validate_ownership_token("EXPECTED_GENERATION", generation)?;
        }
        Ok(())
    }
}

/// What happened to one artifact during cleanup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CniArtifactOutcome {
    /// The artifact was Ferrum-owned and has been removed.
    Removed,
    /// Nothing was there — a repeat cleanup, or an install that never landed.
    AlreadyAbsent,
    /// Something occupies the path but is not provably a Ferrum artifact.
    /// Retained untouched; the reason is a fixed, non-echoing string.
    RetainedForeign(&'static str),
    /// Ferrum-owned, deliberately kept (for example, so a later run can still
    /// prove ownership).
    RetainedDeliberate(&'static str),
    /// Owned by a different install (different `owner` marker).
    RetainedOtherOwner,
    /// Owned by a different generation of this install.
    RetainedOtherGeneration,
}

impl CniArtifactOutcome {
    /// True when the artifact is gone from the node as far as this run is
    /// concerned.
    pub fn is_cleared(&self) -> bool {
        matches!(self, Self::Removed | Self::AlreadyAbsent)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Removed => "removed",
            Self::AlreadyAbsent => "already-absent",
            Self::RetainedForeign(_) => "retained-foreign",
            Self::RetainedDeliberate(_) => "retained",
            Self::RetainedOtherOwner => "retained-other-owner",
            Self::RetainedOtherGeneration => "retained-other-generation",
        }
    }

    pub fn reason(&self) -> &'static str {
        match self {
            Self::Removed => "Ferrum ownership marker matched",
            Self::AlreadyAbsent => "no artifact present",
            Self::RetainedForeign(reason) | Self::RetainedDeliberate(reason) => *reason,
            Self::RetainedOtherOwner => "a different Ferrum install owns this artifact",
            Self::RetainedOtherGeneration => {
                "a different generation of this install owns this artifact"
            }
        }
    }
}

/// Per-artifact outcome of one cleanup run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CniUninstallReport {
    pub conf_path: String,
    pub conflist: CniArtifactOutcome,
    pub binary_path: String,
    pub binary: CniArtifactOutcome,
    pub manifest_path: String,
    pub manifest: CniArtifactOutcome,
}

impl CniUninstallReport {
    /// Cleanup succeeded when the chained conflist is no longer Ferrum's
    /// problem on this node: removed, already absent, or provably owned by a
    /// different install that this run must not touch.
    ///
    /// The plugin binary deliberately does not gate success. It is inert once
    /// nothing chains to it, and refusing to complete a `helm uninstall`
    /// because an unreferenced `/opt/cni/bin/ferrum-cni` could not be proven
    /// ours would trade a real outage for a cosmetic one. Its outcome is
    /// still reported so the retention is visible.
    pub fn is_success(&self) -> bool {
        !matches!(self.conflist, CniArtifactOutcome::RetainedForeign(_))
    }

    /// One line per artifact, safe to print to stderr: every field is either
    /// an operator-supplied path or a fixed reason string.
    pub fn summary_lines(&self) -> Vec<String> {
        vec![
            format!(
                "conflist {}: {} ({})",
                self.conf_path,
                self.conflist.as_str(),
                self.conflist.reason()
            ),
            format!(
                "binary {}: {} ({})",
                self.binary_path,
                self.binary.as_str(),
                self.binary.reason()
            ),
            format!(
                "ownership-manifest {}: {} ({})",
                self.manifest_path,
                self.manifest.as_str(),
                self.manifest.reason()
            ),
        ]
    }
}

#[derive(Debug, Error)]
pub enum CniInstallError {
    #[error("missing required installer env var {0}")]
    MissingEnv(&'static str),
    #[error("filesystem error at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid JSON in {path}: {source}")]
    Json {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("no primary CNI config matching type {plugin_type:?} found in {conf_dir}")]
    PrimaryConfigNotFound {
        conf_dir: String,
        plugin_type: String,
    },
    #[error("primary CNI config {path} is not a JSON object")]
    PrimaryConfigNotObject { path: String },
    #[error("primary CNI config {path} has an empty plugins array")]
    EmptyPluginList { path: String },
    #[error("could not resolve current executable: {0}")]
    CurrentExe(std::io::Error),
    #[error(
        "{name} must be 1..={max} bytes of [A-Za-z0-9._:/@#-]; \
         set it from a stable deployment identity"
    )]
    InvalidOwnershipToken { name: &'static str, max: usize },
    #[error("{name} must be a single file name with no path separators, `.` or `..`")]
    InvalidFileName { name: &'static str },
    #[error("{name} is not valid: expected {expected}")]
    InvalidEnvValue {
        name: &'static str,
        expected: &'static str,
    },
}

pub fn install_from_env() -> Result<PathBuf, CniInstallError> {
    let config = CniInstallConfig::from_env()?;
    let source_binary = std::env::current_exe().map_err(CniInstallError::CurrentExe)?;
    install(&config, &source_binary)
}

pub fn install(
    config: &CniInstallConfig,
    source_binary: &Path,
) -> Result<PathBuf, CniInstallError> {
    config.ownership.validate()?;
    validate_single_component("CONF_FILE_NAME", &config.conf_file_name)?;

    let host_bin_dir = Path::new(&config.host_bin_dir);
    let host_conf_dir = Path::new(&config.host_conf_dir);
    let host_socket_dir = Path::new(&config.host_socket_dir);

    create_dir_all(host_bin_dir)?;
    create_dir_all(host_conf_dir)?;
    create_dir_all(host_socket_dir)?;

    let target_binary = host_bin_dir.join(FERRUM_PLUGIN_TYPE);
    atomic_copy_executable(source_binary, &target_binary)?;
    let binary_sha256 = hash_file(&target_binary)?;

    // ORDER IS LOAD-BEARING, twice over.
    //
    // The ownership manifest goes down before anything that can fail later,
    // so every artifact this install can leave behind — including after a
    // mid-install error — is already provably ours and therefore removable.
    // And the conflist goes down LAST: the moment it lands, every pod ADD on
    // this node traverses ferrum-cni, so nothing that could fail may still be
    // pending at that point.
    write_ownership_manifest(
        host_conf_dir,
        &config.ownership,
        &config.conf_file_name,
        &binary_sha256,
    )?;

    let primary = find_primary_config(host_conf_dir, &config.conf_file_name, &config.chained_with)?;
    let chained = build_chained_conflist(
        &primary.json,
        &config.socket_path,
        &config.ownership,
        &primary.path,
    )?;
    let target_conf = host_conf_dir.join(&config.conf_file_name);
    let mut bytes =
        serde_json::to_vec_pretty(&chained).map_err(|source| CniInstallError::Json {
            path: target_conf.display().to_string(),
            source,
        })?;
    bytes.push(b'\n');
    atomic_write_file(&target_conf, &bytes, Some(0o644))?;
    Ok(target_conf)
}

pub fn uninstall_from_env() -> Result<CniUninstallReport, CniInstallError> {
    uninstall(&CniUninstallConfig::from_env()?)
}

/// Remove the Ferrum-generated CNI artifacts, and only those.
///
/// Idempotent: a repeat run over an already-cleaned node reports
/// `AlreadyAbsent` for every artifact and succeeds. Partial state (manifest
/// without conflist, conflist without manifest, truncated manifest) resolves
/// to the safest action each artifact can independently justify.
pub fn uninstall(config: &CniUninstallConfig) -> Result<CniUninstallReport, CniInstallError> {
    config.validate()?;

    let conf_dir = Path::new(&config.host_conf_dir);
    let bin_dir = Path::new(&config.host_bin_dir);
    let conf_path = conf_dir.join(&config.conf_file_name);
    let manifest_path = conf_dir.join(OWNERSHIP_MANIFEST_FILE_NAME);
    let binary_path = bin_dir.join(FERRUM_PLUGIN_TYPE);

    let manifest_state = read_ownership_manifest(&manifest_path)?;
    let manifest = match &manifest_state {
        ManifestState::Present(manifest) => Some(manifest),
        ManifestState::Absent | ManifestState::Unusable(_) => None,
    };

    // 1. The chained conflist. This is the artifact that makes the node-agent
    //    a node-wide pod-creation dependency, so it goes first: once it is
    //    gone kubelet stops invoking ferrum-cni and the binary is inert.
    //    Ownership comes from the marker inside the file itself, not from the
    //    manifest, so a lost manifest can never strand the chain.
    let conflist = match read_bounded_regular_file(&conf_path, MAX_OWNED_JSON_BYTES)? {
        ArtifactRead::Absent => CniArtifactOutcome::AlreadyAbsent,
        ArtifactRead::Rejected(reason) => CniArtifactOutcome::RetainedForeign(reason),
        ArtifactRead::Present(bytes) => match conflist_ownership(&bytes) {
            None => CniArtifactOutcome::RetainedForeign(
                "file carries no Ferrum ownership marker; it was not written by this installer",
            ),
            Some(found) => match match_ownership(config, &found) {
                OwnershipMatch::Match => {
                    remove_file(&conf_path)?;
                    CniArtifactOutcome::Removed
                }
                OwnershipMatch::OtherOwner => CniArtifactOutcome::RetainedOtherOwner,
                OwnershipMatch::OtherGeneration => CniArtifactOutcome::RetainedOtherGeneration,
            },
        },
    };

    // 2. The plugin binary. Never while a conflist still references it, and
    //    only when the manifest's recorded digest matches the bytes on disk —
    //    an operator or another product that replaced the file keeps it.
    let binary = if !conflist.is_cleared() {
        CniArtifactOutcome::RetainedDeliberate(
            "a chained CNI configuration still references the plugin binary",
        )
    } else {
        match manifest {
            None => match read_file_metadata(&binary_path)? {
                ArtifactMeta::Absent => CniArtifactOutcome::AlreadyAbsent,
                ArtifactMeta::Rejected(reason) => CniArtifactOutcome::RetainedForeign(reason),
                ArtifactMeta::Present => CniArtifactOutcome::RetainedForeign(
                    "no ownership manifest records this binary as Ferrum-installed",
                ),
            },
            Some(manifest) => match match_ownership(config, &manifest.ownership) {
                OwnershipMatch::OtherOwner => CniArtifactOutcome::RetainedOtherOwner,
                OwnershipMatch::OtherGeneration => CniArtifactOutcome::RetainedOtherGeneration,
                OwnershipMatch::Match => match read_file_metadata(&binary_path)? {
                    ArtifactMeta::Absent => CniArtifactOutcome::AlreadyAbsent,
                    ArtifactMeta::Rejected(reason) => CniArtifactOutcome::RetainedForeign(reason),
                    ArtifactMeta::Present => {
                        if hash_file(&binary_path)? == manifest.binary_sha256 {
                            remove_file(&binary_path)?;
                            CniArtifactOutcome::Removed
                        } else {
                            CniArtifactOutcome::RetainedForeign(
                                "binary content does not match the digest recorded at install",
                            )
                        }
                    }
                },
            },
        }
    };

    // 3. The ownership manifest itself, only once it has nothing left to
    //    prove. Retaining it after a partial cleanup is what makes a retry
    //    able to finish the job.
    let manifest_outcome = match &manifest_state {
        ManifestState::Absent => CniArtifactOutcome::AlreadyAbsent,
        ManifestState::Unusable(reason) => CniArtifactOutcome::RetainedForeign(*reason),
        ManifestState::Present(manifest) => {
            if !conflist.is_cleared() || !binary.is_cleared() {
                CniArtifactOutcome::RetainedDeliberate(
                    "retained so a later cleanup run can still prove ownership",
                )
            } else {
                match match_ownership(config, &manifest.ownership) {
                    OwnershipMatch::Match => {
                        remove_file(&manifest_path)?;
                        CniArtifactOutcome::Removed
                    }
                    OwnershipMatch::OtherOwner => CniArtifactOutcome::RetainedOtherOwner,
                    OwnershipMatch::OtherGeneration => CniArtifactOutcome::RetainedOtherGeneration,
                }
            }
        }
    };

    Ok(CniUninstallReport {
        conf_path: conf_path.display().to_string(),
        conflist,
        binary_path: binary_path.display().to_string(),
        binary,
        manifest_path: manifest_path.display().to_string(),
        manifest: manifest_outcome,
    })
}

/// Network name of the generated conflist, used by the readiness watcher's
/// STATUS probe. Returns `None` when the file is absent or unreadable — the
/// caller falls back to a constant rather than failing the probe.
pub fn generated_network_name(conf_dir: &str, conf_file_name: &str) -> Option<String> {
    if validate_single_component("CONF_FILE_NAME", conf_file_name).is_err() {
        return None;
    }
    let path = Path::new(conf_dir).join(conf_file_name);
    let bytes = match read_bounded_regular_file(&path, MAX_OWNED_JSON_BYTES) {
        Ok(ArtifactRead::Present(bytes)) => bytes,
        _ => return None,
    };
    let value: Value = serde_json::from_slice(&bytes).ok()?;
    let name = value.get("name")?.as_str()?;
    Some(name.to_string())
}

struct OwnershipManifest {
    ownership: CniOwnership,
    binary_sha256: String,
}

/// What the sibling ownership manifest could be made to say.
///
/// `Unusable` is deliberately distinct from `Absent`: a corrupt manifest
/// leaves a real file on disk, and reporting it as "already absent" would be
/// a quiet lie in the cleanup summary.
enum ManifestState {
    Absent,
    Unusable(&'static str),
    Present(OwnershipManifest),
}

enum OwnershipMatch {
    Match,
    OtherOwner,
    OtherGeneration,
}

fn match_ownership(config: &CniUninstallConfig, found: &CniOwnership) -> OwnershipMatch {
    if let Some(expected) = config.expected_owner.as_deref() && expected != found.owner {
        return OwnershipMatch::OtherOwner;
    }
    if let Some(expected) = config.expected_generation.as_deref() && expected != found.generation {
        return OwnershipMatch::OtherGeneration;
    }
    OwnershipMatch::Match
}

/// Ownership recorded inside the generated conflist's own plugin entry.
/// Returns `None` for anything that is not a Ferrum-generated chain.
fn conflist_ownership(bytes: &[u8]) -> Option<CniOwnership> {
    let value: Value = serde_json::from_slice(bytes).ok()?;
    let ferrum = value
        .get("plugins")?
        .as_array()?
        .iter()
        .find(|plugin| plugin_type(plugin) == Some(FERRUM_PLUGIN_TYPE))?
        .get("ferrum")?
        .as_object()?;
    if ferrum.get("managedBy").and_then(Value::as_str) != Some(FERRUM_MANAGED_BY) {
        return None;
    }
    Some(CniOwnership {
        owner: ferrum
            .get("owner")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        generation: ferrum
            .get("generation")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
    })
}

fn write_ownership_manifest(
    conf_dir: &Path,
    ownership: &CniOwnership,
    conf_file_name: &str,
    binary_sha256: &str,
) -> Result<(), CniInstallError> {
    let path = conf_dir.join(OWNERSHIP_MANIFEST_FILE_NAME);
    let manifest = serde_json::json!({
        "schemaVersion": OWNERSHIP_MANIFEST_SCHEMA_VERSION,
        "managedBy": FERRUM_MANAGED_BY,
        "owner": ownership.owner,
        "generation": ownership.generation,
        "confFileName": conf_file_name,
        "binaryFileName": FERRUM_PLUGIN_TYPE,
        "binarySha256": binary_sha256,
    });
    let mut bytes = serde_json::to_vec_pretty(&manifest).map_err(|source| CniInstallError::Json {
        path: path.display().to_string(),
        source,
    })?;
    bytes.push(b'\n');
    atomic_write_file(&path, &bytes, Some(0o600))
}

/// Read the ownership manifest.
///
/// A missing, non-regular, oversized, malformed, or wrong-schema manifest is
/// reported as "no manifest" with a warning rather than an error: the
/// conflist carries its own marker, so cleanup must still be able to lift the
/// node-wide dependency when the manifest is lost or corrupt.
fn read_ownership_manifest(path: &Path) -> Result<ManifestState, CniInstallError> {
    let bytes = match read_bounded_regular_file(path, MAX_OWNED_JSON_BYTES)? {
        ArtifactRead::Absent => return Ok(ManifestState::Absent),
        ArtifactRead::Rejected(reason) => {
            tracing::warn!(
                path = %path.display(),
                reason,
                "Ignoring CNI ownership manifest that is not a plain installer-written file"
            );
            return Ok(ManifestState::Unusable(reason));
        }
        ArtifactRead::Present(bytes) => bytes,
    };
    let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
        tracing::warn!(
            path = %path.display(),
            "Ignoring unparseable CNI ownership manifest; conflist ownership marker still applies"
        );
        return Ok(ManifestState::Unusable(
            "ownership manifest is not parseable JSON",
        ));
    };
    if value.get("schemaVersion").and_then(Value::as_u64) != Some(OWNERSHIP_MANIFEST_SCHEMA_VERSION)
        || value.get("managedBy").and_then(Value::as_str) != Some(FERRUM_MANAGED_BY)
    {
        tracing::warn!(
            path = %path.display(),
            "Ignoring CNI ownership manifest with an unrecognized schema or managedBy marker"
        );
        return Ok(ManifestState::Unusable(
            "ownership manifest has an unrecognized schema or managedBy marker",
        ));
    }
    let (Some(owner), Some(generation), Some(binary_sha256)) = (
        value.get("owner").and_then(Value::as_str),
        value.get("generation").and_then(Value::as_str),
        value.get("binarySha256").and_then(Value::as_str),
    ) else {
        tracing::warn!(
            path = %path.display(),
            "Ignoring CNI ownership manifest missing owner/generation/binarySha256"
        );
        return Ok(ManifestState::Unusable(
            "ownership manifest is missing owner/generation/binarySha256",
        ));
    };
    Ok(ManifestState::Present(OwnershipManifest {
        ownership: CniOwnership {
            owner: owner.to_string(),
            generation: generation.to_string(),
        },
        binary_sha256: binary_sha256.to_string(),
    }))
}

enum ArtifactRead {
    Absent,
    Rejected(&'static str),
    Present(Vec<u8>),
}

enum ArtifactMeta {
    Absent,
    Rejected(&'static str),
    Present,
}

enum OpenedArtifact {
    Absent,
    Rejected(&'static str),
    Opened(File),
}

/// Open a path without following symlinks and classify it.
///
/// `O_NOFOLLOW` closes the symlink-swap race that a `symlink_metadata` +
/// `open` pair would leave open: the kernel refuses the open outright, so
/// there is no window in which a traversal target can be substituted.
fn open_no_follow(path: &Path) -> Result<OpenedArtifact, CniInstallError> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    match options.open(path) {
        Ok(file) => Ok(OpenedArtifact::Opened(file)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(OpenedArtifact::Absent),
        Err(err) if is_symlink_open_refusal(&err) => Ok(OpenedArtifact::Rejected(
            "path is a symlink; Ferrum only installs and removes regular files",
        )),
        Err(source) => Err(CniInstallError::Io {
            path: path.display().to_string(),
            source,
        }),
    }
}

#[cfg(unix)]
fn is_symlink_open_refusal(err: &std::io::Error) -> bool {
    // Linux reports ELOOP for an O_NOFOLLOW symlink; some BSDs report EMLINK.
    matches!(err.raw_os_error(), Some(libc::ELOOP) | Some(libc::EMLINK))
}

#[cfg(not(unix))]
fn is_symlink_open_refusal(_err: &std::io::Error) -> bool {
    false
}

/// Classify a path as a removable Ferrum artifact candidate without reading
/// it. Used for the plugin binary, which is too large to buffer.
fn read_file_metadata(path: &Path) -> Result<ArtifactMeta, CniInstallError> {
    let file = match open_no_follow(path)? {
        OpenedArtifact::Absent => return Ok(ArtifactMeta::Absent),
        OpenedArtifact::Rejected(reason) => return Ok(ArtifactMeta::Rejected(reason)),
        OpenedArtifact::Opened(file) => file,
    };
    classify_open_file(&file, path, MAX_OWNED_BINARY_BYTES)
}

/// Reject anything that is not a plain, single-linked, plausibly-sized file.
/// The checks run against the already-open handle, so they describe the
/// object that will actually be read or removed.
fn classify_open_file(
    file: &File,
    path: &Path,
    max_bytes: u64,
) -> Result<ArtifactMeta, CniInstallError> {
    let meta = file.metadata().map_err(|source| CniInstallError::Io {
        path: path.display().to_string(),
        source,
    })?;
    if !meta.is_file() {
        return Ok(ArtifactMeta::Rejected("path is not a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.nlink() != 1 {
            return Ok(ArtifactMeta::Rejected(
                "path is hard-linked; removing it could affect another name for the same file",
            ));
        }
    }
    if meta.len() > max_bytes {
        return Ok(ArtifactMeta::Rejected(
            "file is larger than any artifact this installer writes",
        ));
    }
    Ok(ArtifactMeta::Present)
}

fn read_bounded_regular_file(path: &Path, max_bytes: u64) -> Result<ArtifactRead, CniInstallError> {
    let mut file = match open_no_follow(path)? {
        OpenedArtifact::Absent => return Ok(ArtifactRead::Absent),
        OpenedArtifact::Rejected(reason) => return Ok(ArtifactRead::Rejected(reason)),
        OpenedArtifact::Opened(file) => file,
    };
    match classify_open_file(&file, path, max_bytes)? {
        ArtifactMeta::Present => {}
        ArtifactMeta::Rejected(reason) => return Ok(ArtifactRead::Rejected(reason)),
        ArtifactMeta::Absent => return Ok(ArtifactRead::Absent),
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|source| CniInstallError::Io {
            path: path.display().to_string(),
            source,
        })?;
    Ok(ArtifactRead::Present(bytes))
}

fn hash_file(path: &Path) -> Result<String, CniInstallError> {
    let mut file = match open_no_follow(path)? {
        OpenedArtifact::Opened(file) => file,
        OpenedArtifact::Absent | OpenedArtifact::Rejected(_) => {
            return Err(CniInstallError::Io {
                path: path.display().to_string(),
                source: std::io::Error::other("path is not a readable regular file"),
            });
        }
    };
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buf).map_err(|source| CniInstallError::Io {
            path: path.display().to_string(),
            source,
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn remove_file(path: &Path) -> Result<(), CniInstallError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(CniInstallError::Io {
            path: path.display().to_string(),
            source,
        }),
    }
}

fn validate_ownership_token(name: &'static str, value: &str) -> Result<(), CniInstallError> {
    fn acceptable_byte(byte: u8) -> bool {
        byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@' | b'#')
    }
    let acceptable = !value.is_empty()
        && value.len() <= MAX_OWNERSHIP_TOKEN_BYTES
        && value.bytes().all(acceptable_byte);
    if acceptable {
        Ok(())
    } else {
        Err(CniInstallError::InvalidOwnershipToken {
            name,
            max: MAX_OWNERSHIP_TOKEN_BYTES,
        })
    }
}

/// Reject anything that is not a single, ordinary file name. The generated
/// conflist name is operator-configurable, and it is joined onto a host
/// directory before a `remove_file`, so `..`, `/`, and empty names must never
/// reach the filesystem.
fn validate_single_component(name: &'static str, value: &str) -> Result<(), CniInstallError> {
    let path = Path::new(value);
    let mut components = path.components();
    let single_normal =
        matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none();
    if single_normal
        && !value.is_empty()
        && value.len() <= 255
        && !value.contains('\0')
        && !value.chars().any(char::is_control)
    {
        Ok(())
    } else {
        Err(CniInstallError::InvalidFileName { name })
    }
}

struct PrimaryConfig {
    path: PathBuf,
    json: Value,
}

fn find_primary_config(
    conf_dir: &Path,
    target_file_name: &str,
    chained_with: &str,
) -> Result<PrimaryConfig, CniInstallError> {
    let mut entries = fs::read_dir(conf_dir)
        .map_err(|source| CniInstallError::Io {
            path: conf_dir.display().to_string(),
            source,
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| CniInstallError::Io {
            path: conf_dir.display().to_string(),
            source,
        })?;
    entries.sort_by_key(|entry| entry.file_name());
    let target_file_name = std::ffi::OsStr::new(target_file_name);

    for entry in entries {
        let path = entry.path();
        if !is_cni_config_file(&path) {
            continue;
        }
        let Some(file_name) = path.file_name() else {
            continue;
        };
        if file_name == target_file_name {
            continue;
        }
        let sorts_before_target = file_name < target_file_name;
        let json = match read_json_file(&path) {
            Ok(json) => json,
            Err(error @ CniInstallError::Json { .. }) => {
                if sorts_before_target {
                    return Err(error);
                }
                // A malformed neighbour in the shared CNI conf dir (a
                // half-written or vendor config another installer dropped) must
                // not abort the scan if the generated Ferrum file would sort
                // before it. Malformed files that sort before the generated
                // target remain fatal because the container runtime would pick
                // them before Ferrum's chain.
                tracing::warn!(
                    path = %path.display(),
                    error = %error,
                    "Skipping unparseable CNI config while searching for the primary to chain"
                );
                continue;
            }
            Err(error) => return Err(error),
        };
        if contains_plugin_type(&json, FERRUM_PLUGIN_TYPE) {
            continue;
        }
        if contains_plugin_type(&json, chained_with) {
            return Ok(PrimaryConfig { path, json });
        }
    }

    Err(CniInstallError::PrimaryConfigNotFound {
        conf_dir: conf_dir.display().to_string(),
        plugin_type: chained_with.to_string(),
    })
}

fn is_cni_config_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|ext| ext.to_str()),
        Some("conf" | "conflist" | "json")
    )
}

fn read_json_file(path: &Path) -> Result<Value, CniInstallError> {
    let bytes = fs::read(path).map_err(|source| CniInstallError::Io {
        path: path.display().to_string(),
        source,
    })?;
    serde_json::from_slice(&bytes).map_err(|source| CniInstallError::Json {
        path: path.display().to_string(),
        source,
    })
}

pub fn build_chained_conflist(
    primary_config: &Value,
    socket_path: &str,
    ownership: &CniOwnership,
    source_path: &Path,
) -> Result<Value, CniInstallError> {
    let Some(obj) = primary_config.as_object() else {
        return Err(CniInstallError::PrimaryConfigNotObject {
            path: source_path.display().to_string(),
        });
    };

    let ferrum_plugin = ferrum_plugin(socket_path, ownership);
    if let Some(plugins) = obj.get("plugins").and_then(Value::as_array) {
        if plugins.is_empty() {
            return Err(CniInstallError::EmptyPluginList {
                path: source_path.display().to_string(),
            });
        }
        let mut out = obj.clone();
        let mut chained_plugins: Vec<Value> = plugins
            .iter()
            .filter(|plugin| plugin_type(plugin) != Some(FERRUM_PLUGIN_TYPE))
            .cloned()
            .collect();
        chained_plugins.push(ferrum_plugin);
        out.insert("plugins".to_string(), Value::Array(chained_plugins));
        return Ok(Value::Object(out));
    }

    let mut primary_plugin = obj.clone();
    primary_plugin.remove("cniVersion");
    primary_plugin.remove("name");
    primary_plugin.remove("plugins");

    let mut out = Map::new();
    out.insert(
        "cniVersion".to_string(),
        obj.get("cniVersion")
            .cloned()
            .unwrap_or_else(|| Value::String("0.4.0".to_string())),
    );
    out.insert(
        "name".to_string(),
        obj.get("name")
            .cloned()
            .unwrap_or_else(|| Value::String("ferrum-mesh-chain".to_string())),
    );
    out.insert(
        "plugins".to_string(),
        Value::Array(vec![Value::Object(primary_plugin), ferrum_plugin]),
    );
    Ok(Value::Object(out))
}

/// The chained Ferrum entry.
///
/// The ownership markers live inside the plugin's own `ferrum` object. That
/// is the one place in a conflist the CNI spec reserves for this plugin, so
/// they cannot confuse a neighbouring plugin, they survive kubelet's
/// per-plugin config projection, and `FerrumCniOptions` ignores them on the
/// request path (it models only `socketPath`).
fn ferrum_plugin(socket_path: &str, ownership: &CniOwnership) -> Value {
    serde_json::json!({
        "type": FERRUM_PLUGIN_TYPE,
        "ferrum": {
            "socketPath": socket_path,
            "managedBy": FERRUM_MANAGED_BY,
            "owner": ownership.owner,
            "generation": ownership.generation,
        }
    })
}

fn contains_plugin_type(config: &Value, expected: &str) -> bool {
    if expected.trim().is_empty() {
        return false;
    }
    plugin_type(config) == Some(expected)
        || config
            .get("plugins")
            .and_then(Value::as_array)
            .is_some_and(|plugins| {
                plugins
                    .iter()
                    .any(|plugin| plugin_type(plugin) == Some(expected))
            })
}

fn plugin_type(plugin: &Value) -> Option<&str> {
    plugin.get("type").and_then(Value::as_str)
}

fn required_env(name: &'static str) -> Result<String, CniInstallError> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or(CniInstallError::MissingEnv(name))
}

fn optional_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn create_dir_all(path: &Path) -> Result<(), CniInstallError> {
    fs::create_dir_all(path).map_err(|source| CniInstallError::Io {
        path: path.display().to_string(),
        source,
    })
}

fn atomic_copy_executable(source: &Path, target: &Path) -> Result<(), CniInstallError> {
    let tmp_path = temp_sibling_path(target, "tmp");
    let result = (|| {
        fs::copy(source, &tmp_path).map_err(|source| CniInstallError::Io {
            path: tmp_path.display().to_string(),
            source,
        })?;
        set_executable(&tmp_path)?;
        atomic_rename(&tmp_path, target)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    result
}

fn atomic_write_file(
    target: &Path,
    contents: &[u8],
    mode: Option<u32>,
) -> Result<(), CniInstallError> {
    let tmp_path = temp_sibling_path(target, "tmp");
    let result = (|| {
        let mut file = File::create(&tmp_path).map_err(|source| CniInstallError::Io {
            path: tmp_path.display().to_string(),
            source,
        })?;
        file.write_all(contents)
            .and_then(|()| file.sync_all())
            .map_err(|source| CniInstallError::Io {
                path: tmp_path.display().to_string(),
                source,
            })?;
        drop(file);
        if let Some(mode) = mode {
            set_mode(&tmp_path, mode)?;
        }
        atomic_rename(&tmp_path, target)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    result
}

fn temp_sibling_path(target: &Path, suffix: &str) -> PathBuf {
    let pid = std::process::id();
    let name = target
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("ferrum-cni");
    target.with_file_name(format!(".{name}.{pid}.{suffix}"))
}

fn atomic_rename(source: &Path, target: &Path) -> Result<(), CniInstallError> {
    fs::rename(source, target).map_err(|source| CniInstallError::Io {
        path: target.display().to_string(),
        source,
    })
}

#[cfg(unix)]
fn set_executable(path: &Path) -> Result<(), CniInstallError> {
    set_mode(path, 0o755)
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) -> Result<(), CniInstallError> {
    Ok(())
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), CniInstallError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|source| {
        CniInstallError::Io {
            path: path.display().to_string(),
            source,
        }
    })
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<(), CniInstallError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ownership() -> CniOwnership {
        CniOwnership {
            owner: "ferrum/ferrum-mesh".to_string(),
            generation: "pod-uid-1".to_string(),
        }
    }

    #[test]
    fn wraps_single_primary_conf_and_preserves_ipam() {
        let primary = serde_json::json!({
            "cniVersion": "0.4.0",
            "name": "mynet",
            "type": "bridge",
            "bridge": "cni0",
            "ipam": {"type": "host-local"}
        });

        let chained = build_chained_conflist(
            &primary,
            "/var/run/ferrum/cni.sock",
            &test_ownership(),
            Path::new("10.conf"),
        )
        .expect("single plugin config should wrap");
        assert_eq!(chained["plugins"][0]["type"], "bridge");
        assert_eq!(chained["plugins"][0]["ipam"]["type"], "host-local");
        assert_eq!(chained["plugins"][1]["type"], "ferrum-cni");
        let entry = &chained["plugins"][1]["ferrum"];
        assert_eq!(entry["socketPath"], "/var/run/ferrum/cni.sock");
        assert_eq!(
            entry["managedBy"], FERRUM_MANAGED_BY,
            "the generated entry must carry the ownership marker uninstall checks"
        );
        assert_eq!(entry["owner"], "ferrum/ferrum-mesh");
        assert_eq!(entry["generation"], "pod-uid-1");
    }

    #[test]
    fn appends_to_existing_conflist_without_dropping_primary_fields() {
        let primary = serde_json::json!({
            "cniVersion": "1.0.0",
            "name": "cilium",
            "plugins": [
                {"type": "cilium-cni", "enable-debug": true},
                {"type": "portmap", "capabilities": {"portMappings": true}}
            ]
        });

        let chained = build_chained_conflist(
            &primary,
            "/var/run/ferrum/cni.sock",
            &test_ownership(),
            Path::new("10.conflist"),
        )
        .expect("conflist should append");
        assert_eq!(chained["plugins"].as_array().unwrap().len(), 3);
        assert_eq!(chained["plugins"][0]["type"], "cilium-cni");
        assert_eq!(chained["plugins"][0]["enable-debug"], true);
        assert_eq!(chained["plugins"][1]["type"], "portmap");
        assert_eq!(chained["plugins"][2]["type"], "ferrum-cni");
    }

    #[test]
    fn replaces_existing_ferrum_entry_when_rebuilding_chain() {
        let primary = serde_json::json!({
            "cniVersion": "1.0.0",
            "name": "calico",
            "plugins": [
                {"type": "calico", "ipam": {"type": "calico-ipam"}},
                {"type": "ferrum-cni", "ferrum": {"socketPath": "/old.sock"}}
            ]
        });

        let chained = build_chained_conflist(
            &primary,
            "/new.sock",
            &test_ownership(),
            Path::new("00-ferrum.conflist"),
        )
        .expect("existing ferrum entry should be replaced");
        assert_eq!(chained["plugins"].as_array().unwrap().len(), 2);
        assert_eq!(chained["plugins"][1]["ferrum"]["socketPath"], "/new.sock");
    }

    #[test]
    fn install_replaces_binary_and_config_atomically_visible() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source-ferrum-cni");
        fs::write(&source, b"new binary").unwrap();
        let bin_dir = root.path().join("bin");
        let conf_dir = root.path().join("conf");
        let socket_dir = root.path().join("run");
        fs::create_dir_all(&bin_dir).unwrap();
        fs::create_dir_all(&conf_dir).unwrap();
        fs::write(bin_dir.join("ferrum-cni"), b"old binary").unwrap();
        fs::write(
            conf_dir.join("10-calico.conflist"),
            serde_json::to_vec(&serde_json::json!({
                "cniVersion": "0.4.0",
                "name": "calico",
                "plugins": [{"type": "calico", "ipam": {"type": "calico-ipam"}}]
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(conf_dir.join("00-ferrum.conflist"), b"{truncated").unwrap();

        let config = CniInstallConfig {
            host_bin_dir: bin_dir.display().to_string(),
            host_conf_dir: conf_dir.display().to_string(),
            host_socket_dir: socket_dir.display().to_string(),
            conf_file_name: "00-ferrum.conflist".to_string(),
            chained_with: "calico".to_string(),
            socket_path: "/var/run/ferrum/node-agent-cni.sock".to_string(),
            ownership: test_ownership(),
        };

        let written = install(&config, &source).expect("install should succeed");
        assert_eq!(fs::read(bin_dir.join("ferrum-cni")).unwrap(), b"new binary");
        let generated: Value =
            serde_json::from_slice(&fs::read(written).unwrap()).expect("generated config parses");
        assert_eq!(generated["plugins"][0]["type"], "calico");
        assert_eq!(
            generated["plugins"][0]["ipam"]["type"], "calico-ipam",
            "primary config should be preserved"
        );
        assert_eq!(generated["plugins"][1]["type"], "ferrum-cni");
        assert!(
            fs::read_dir(bin_dir).unwrap().all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".tmp")),
            "successful install should not leave temp binary files"
        );
        assert!(
            fs::read_dir(conf_dir).unwrap().all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".tmp")),
            "successful install should not leave temp config files"
        );
    }

    #[test]
    fn install_skips_malformed_sibling_and_chains_valid_primary() {
        // A malformed NON-target sibling that sorts BEFORE the valid primary
        // must not abort the scan — install should still find and chain the
        // valid primary. (Regression: the parse error previously propagated via
        // `?` and aborted the whole install.)
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source-ferrum-cni");
        fs::write(&source, b"new binary").unwrap();
        let bin_dir = root.path().join("bin");
        let conf_dir = root.path().join("conf");
        let socket_dir = root.path().join("run");
        fs::create_dir_all(&bin_dir).unwrap();
        fs::create_dir_all(&conf_dir).unwrap();
        fs::write(bin_dir.join("ferrum-cni"), b"old binary").unwrap();
        // Malformed sibling sorting before the valid primary.
        fs::write(conf_dir.join("05-broken.conf"), b"{truncated").unwrap();
        fs::write(
            conf_dir.join("10-calico.conflist"),
            serde_json::to_vec(&serde_json::json!({
                "cniVersion": "0.4.0",
                "name": "calico",
                "plugins": [{"type": "calico", "ipam": {"type": "calico-ipam"}}]
            }))
            .unwrap(),
        )
        .unwrap();

        let config = CniInstallConfig {
            host_bin_dir: bin_dir.display().to_string(),
            host_conf_dir: conf_dir.display().to_string(),
            host_socket_dir: socket_dir.display().to_string(),
            conf_file_name: "00-ferrum.conflist".to_string(),
            chained_with: "calico".to_string(),
            socket_path: "/var/run/ferrum/node-agent-cni.sock".to_string(),
            ownership: test_ownership(),
        };

        let written = install(&config, &source)
            .expect("install should skip the malformed sibling and chain the valid primary");
        let generated: Value =
            serde_json::from_slice(&fs::read(written).unwrap()).expect("generated config parses");
        assert_eq!(generated["plugins"][0]["type"], "calico");
        assert_eq!(generated["plugins"][1]["type"], "ferrum-cni");
    }

    #[test]
    fn install_rejects_malformed_config_that_sorts_before_generated_target() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source-ferrum-cni");
        fs::write(&source, b"new binary").unwrap();
        let bin_dir = root.path().join("bin");
        let conf_dir = root.path().join("conf");
        let socket_dir = root.path().join("run");
        fs::create_dir_all(&bin_dir).unwrap();
        fs::create_dir_all(&conf_dir).unwrap();

        fs::write(conf_dir.join("00-alpha.conf"), b"{truncated").unwrap();
        fs::write(
            conf_dir.join("10-calico.conflist"),
            serde_json::to_vec(&serde_json::json!({
                "cniVersion": "0.4.0",
                "name": "calico",
                "plugins": [{"type": "calico"}]
            }))
            .unwrap(),
        )
        .unwrap();

        let config = CniInstallConfig {
            host_bin_dir: bin_dir.display().to_string(),
            host_conf_dir: conf_dir.display().to_string(),
            host_socket_dir: socket_dir.display().to_string(),
            conf_file_name: "00-ferrum.conflist".to_string(),
            chained_with: "calico".to_string(),
            socket_path: "/var/run/ferrum/node-agent-cni.sock".to_string(),
            ownership: test_ownership(),
        };

        let err = install(&config, &source)
            .expect_err("malformed configs before the generated target must fail install");
        assert!(
            matches!(err, CniInstallError::Json { .. }),
            "expected JSON error for earlier malformed config, got {err:?}"
        );
    }

    #[test]
    fn install_propagates_io_error_while_scanning_primary_candidates() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source-ferrum-cni");
        fs::write(&source, b"new binary").unwrap();
        let bin_dir = root.path().join("bin");
        let conf_dir = root.path().join("conf");
        let socket_dir = root.path().join("run");
        fs::create_dir_all(&bin_dir).unwrap();
        fs::create_dir_all(&conf_dir).unwrap();

        // A directory with a CNI config extension sorts before the valid
        // primary and makes fs::read return an I/O error. This must not be
        // treated like malformed JSON or the installer could chain a later
        // stale primary.
        let unreadable_candidate = conf_dir.join("05-unreadable.conf");
        fs::create_dir(&unreadable_candidate).unwrap();
        fs::write(
            conf_dir.join("10-calico.conflist"),
            serde_json::to_vec(&serde_json::json!({
                "cniVersion": "0.4.0",
                "name": "calico",
                "plugins": [{"type": "calico"}]
            }))
            .unwrap(),
        )
        .unwrap();

        let config = CniInstallConfig {
            host_bin_dir: bin_dir.display().to_string(),
            host_conf_dir: conf_dir.display().to_string(),
            host_socket_dir: socket_dir.display().to_string(),
            conf_file_name: "00-ferrum.conflist".to_string(),
            chained_with: "calico".to_string(),
            socket_path: "/var/run/ferrum/node-agent-cni.sock".to_string(),
            ownership: test_ownership(),
        };

        let err = install(&config, &source).expect_err("I/O errors must propagate");
        match err {
            CniInstallError::Io { path, .. } => {
                assert!(
                    path.ends_with("05-unreadable.conf"),
                    "reported path should be the unreadable candidate: {path}"
                );
            }
            other => panic!("expected CNI scan I/O error, got {other:?}"),
        }
    }
}
