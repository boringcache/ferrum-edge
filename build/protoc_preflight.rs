use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

const INSTALL_HINT: &str = "Install protobuf-compiler (e.g. `apt-get install protobuf-compiler` on \
Debian/Ubuntu, `brew install protobuf` on macOS) or set PROTOC to the protoc executable path";

/// Resolve a usable `protoc` binary before `tonic_prost_build` runs.
///
/// Honors `PROTOC` when set; otherwise scans `PATH` for `protoc` (or `protoc.exe` on Windows).
pub fn ensure_protoc() -> Result<PathBuf, String> {
    ensure_protoc_from(env::var_os("PROTOC"), env::var_os("PATH"))
}

pub fn ensure_protoc_from(
    protoc_env: Option<OsString>,
    path_env: Option<OsString>,
) -> Result<PathBuf, String> {
    if let Some(raw) = protoc_env {
        return validate_protoc_override(raw);
    }
    find_protoc_on_path(path_env.as_ref()).ok_or_else(protoc_missing_diagnostic)
}

fn validate_protoc_override(raw: OsString) -> Result<PathBuf, String> {
    let path_str = match raw.into_string() {
        Ok(s) => s,
        Err(_) => {
            return Err(protoc_override_diagnostic(
                "PROTOC contains non-UTF-8 bytes",
            ));
        }
    };
    if path_str.is_empty() {
        return Err(protoc_override_diagnostic("PROTOC is set but empty"));
    }
    let path = PathBuf::from(&path_str);
    validate_protoc_path(&path, &path_str)
}

fn validate_protoc_path(path: &Path, display: &str) -> Result<PathBuf, String> {
    if !path.exists() {
        return Err(protoc_override_diagnostic(&format!(
            "PROTOC points to a nonexistent path: {display}"
        )));
    }
    if !path.is_file() {
        return Err(protoc_override_diagnostic(&format!(
            "PROTOC is not a regular file: {display}"
        )));
    }
    if !is_executable(path) {
        return Err(protoc_override_diagnostic(&format!(
            "PROTOC is not executable: {display}"
        )));
    }
    Ok(path.to_path_buf())
}

fn find_protoc_on_path(path_env: Option<&OsString>) -> Option<PathBuf> {
    let path_env = path_env?;
    for dir in env::split_paths(path_env) {
        for name in protoc_executable_names() {
            let candidate = dir.join(name);
            if candidate.is_file() && is_executable(&candidate) {
                return Some(candidate);
            }
        }
    }
    None
}

fn protoc_executable_names() -> &'static [&'static str] {
    if cfg!(windows) {
        &["protoc.exe", "protoc"]
    } else {
        &["protoc"]
    }
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.metadata()
        .map(|m| m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

fn protoc_missing_diagnostic() -> String {
    format!(
        "protoc is required to compile Ferrum Edge gRPC/protobuf stubs but was not found on PATH. \
         {INSTALL_HINT}."
    )
}

fn protoc_override_diagnostic(reason: &str) -> String {
    format!(
        "protoc is required to compile Ferrum Edge gRPC/protobuf stubs but PROTOC is unusable: \
         {reason}. {INSTALL_HINT}."
    )
}
