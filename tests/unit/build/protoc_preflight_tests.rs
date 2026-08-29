//! Regression coverage for the `protoc` preflight in `build.rs` (issue #4361).

use std::ffi::OsString;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[allow(dead_code)]
mod protoc_preflight {
    include!("../../../build/protoc_preflight.rs");
}

fn assert_actionable_protoc_diagnostic(message: &str) {
    let lower = message.to_ascii_lowercase();
    assert!(
        lower.contains("protoc"),
        "diagnostic must mention protoc: {message}"
    );
    assert!(
        lower.contains("protobuf-compiler"),
        "diagnostic must mention protobuf-compiler: {message}"
    );
}

#[test]
fn missing_protoc_on_path_returns_actionable_diagnostic() {
    let dir = tempfile::tempdir().expect("tempdir");
    let err = protoc_preflight::ensure_protoc_from(None, Some(OsString::from(dir.path())))
        .expect_err("PATH without protoc must fail");
    assert_actionable_protoc_diagnostic(&err);
    assert!(err.contains("PATH"), "{err}");
}

#[test]
fn empty_protoc_override_is_rejected() {
    let err = protoc_preflight::ensure_protoc_from(Some(OsString::new()), None)
        .expect_err("empty PROTOC must fail");
    assert_actionable_protoc_diagnostic(&err);
    assert!(err.contains("PROTOC"), "{err}");
}

#[test]
fn nonexistent_protoc_override_is_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let missing = dir.path().join("missing-protoc");
    let err = protoc_preflight::ensure_protoc_from(Some(missing.into_os_string()), None)
        .expect_err("missing PROTOC path must fail");
    assert_actionable_protoc_diagnostic(&err);
    assert!(err.contains("PROTOC"), "{err}");
    assert!(err.contains("nonexistent"), "{err}");
}

#[test]
#[cfg(unix)]
fn non_executable_protoc_override_is_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("protoc");
    fs::write(&path, b"#!/bin/sh\n").expect("write fake protoc");
    #[cfg(unix)]
    {
        let mut perms = fs::metadata(&path).expect("metadata").permissions();
        perms.set_mode(0o644);
        fs::set_permissions(&path, perms).expect("chmod");
    }

    let err = protoc_preflight::ensure_protoc_from(Some(path.into_os_string()), None)
        .expect_err("non-executable PROTOC must fail");
    assert_actionable_protoc_diagnostic(&err);
    assert!(err.contains("not executable"), "{err}");
}

#[test]
#[cfg(unix)]
fn executable_protoc_on_path_is_discovered() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("protoc");
    fs::write(&path, b"#!/bin/sh\n").expect("write fake protoc");
    #[cfg(unix)]
    {
        let mut perms = fs::metadata(&path).expect("metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&path, perms).expect("chmod");
    }

    let resolved = protoc_preflight::ensure_protoc_from(None, Some(OsString::from(dir.path())))
        .expect("executable protoc on PATH must resolve");
    assert_eq!(resolved, path);
}

#[test]
#[cfg(unix)]
fn command_style_protoc_override_is_discovered_on_path() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("protoc-27.1");
    fs::write(&path, b"#!/bin/sh\n").expect("write fake protoc");
    let mut perms = fs::metadata(&path).expect("metadata").permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&path, perms).expect("chmod");

    let resolved = protoc_preflight::ensure_protoc_from(
        Some(OsString::from("protoc-27.1")),
        Some(OsString::from(dir.path())),
    )
    .expect("command-style PROTOC override on PATH must resolve");
    assert_eq!(resolved, path);
}

#[test]
fn build_script_preflights_protoc_before_tonic_compile() {
    let build = include_str!("../../../build.rs");
    let preflight = build
        .find("protoc_preflight::ensure_protoc")
        .expect("build.rs must preflight protoc");
    let compile = build
        .find("tonic_prost_build::configure()")
        .expect("build.rs must compile protos");
    assert!(
        preflight < compile,
        "protoc preflight must run before tonic_prost_build"
    );
    assert!(
        build.contains("cargo:rerun-if-env-changed=PROTOC"),
        "build.rs must rebuild when PROTOC changes"
    );
}
