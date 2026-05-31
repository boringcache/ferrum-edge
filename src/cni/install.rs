//! Host-side installer for the `ferrum-cni` binary.
//!
//! The node-agent image is distroless, so Helm cannot use `/bin/sh` to copy
//! files or render a CNI conflist. Instead the init container executes
//! `ferrum-cni install`, and this module performs those filesystem changes
//! directly.

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};
use thiserror::Error;

const FERRUM_PLUGIN_TYPE: &str = "ferrum-cni";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CniInstallConfig {
    pub host_bin_dir: String,
    pub host_conf_dir: String,
    pub host_socket_dir: String,
    pub conf_file_name: String,
    pub chained_with: String,
    pub socket_path: String,
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
        })
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
    let host_bin_dir = Path::new(&config.host_bin_dir);
    let host_conf_dir = Path::new(&config.host_conf_dir);
    let host_socket_dir = Path::new(&config.host_socket_dir);

    create_dir_all(host_bin_dir)?;
    create_dir_all(host_conf_dir)?;
    create_dir_all(host_socket_dir)?;

    let target_binary = host_bin_dir.join(FERRUM_PLUGIN_TYPE);
    atomic_copy_executable(source_binary, &target_binary)?;

    let primary = find_primary_config(host_conf_dir, &config.conf_file_name, &config.chained_with)?;
    let chained = build_chained_conflist(&primary.json, &config.socket_path, &primary.path)?;
    let target_conf = host_conf_dir.join(&config.conf_file_name);
    let mut bytes =
        serde_json::to_vec_pretty(&chained).map_err(|source| CniInstallError::Json {
            path: target_conf.display().to_string(),
            source,
        })?;
    bytes.push(b'\n');
    atomic_write_file(&target_conf, &bytes, None)?;
    Ok(target_conf)
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
    source_path: &Path,
) -> Result<Value, CniInstallError> {
    let Some(obj) = primary_config.as_object() else {
        return Err(CniInstallError::PrimaryConfigNotObject {
            path: source_path.display().to_string(),
        });
    };

    let ferrum_plugin = ferrum_plugin(socket_path);
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

fn ferrum_plugin(socket_path: &str) -> Value {
    serde_json::json!({
        "type": FERRUM_PLUGIN_TYPE,
        "ferrum": {
            "socketPath": socket_path
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

    #[test]
    fn wraps_single_primary_conf_and_preserves_ipam() {
        let primary = serde_json::json!({
            "cniVersion": "0.4.0",
            "name": "mynet",
            "type": "bridge",
            "bridge": "cni0",
            "ipam": {"type": "host-local"}
        });

        let chained =
            build_chained_conflist(&primary, "/var/run/ferrum/cni.sock", Path::new("10.conf"))
                .expect("single plugin config should wrap");
        assert_eq!(chained["plugins"][0]["type"], "bridge");
        assert_eq!(chained["plugins"][0]["ipam"]["type"], "host-local");
        assert_eq!(chained["plugins"][1]["type"], "ferrum-cni");
        assert_eq!(
            chained["plugins"][1]["ferrum"]["socketPath"],
            "/var/run/ferrum/cni.sock"
        );
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

        let chained =
            build_chained_conflist(&primary, "/new.sock", Path::new("00-ferrum.conflist"))
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
