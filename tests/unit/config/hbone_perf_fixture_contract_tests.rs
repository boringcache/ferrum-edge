//! Static contract: the HBONE performance harness must use trusted projection,
//! not operator file config with reserved `mesh.*` tags (issue #3332).
//!
//! `include_str!` only — no runtime, no production bypass.

const HBONE_FIXTURE: &str = include_str!("../../../examples/hbone_perf_fixture.rs");
const HBONE_RUN: &str = include_str!("../../../tests/performance/mesh-hbone-e2e/run.sh");
const ROOT_CARGO_TOML: &str = include_str!("../../../Cargo.toml");

#[test]
fn hbone_perf_fixture_uses_trusted_projection_not_operator_file_config() {
    assert!(
        HBONE_FIXTURE.contains("normalize_fields"),
        "fixture must normalize the internally constructed GatewayConfig"
    );
    assert!(
        HBONE_FIXTURE.contains("ServeOptions") && HBONE_FIXTURE.contains("serve("),
        "fixture must call file::serve with ServeOptions"
    );
    assert!(
        HBONE_FIXTURE.contains("install_crypto_provider"),
        "fixture must install the rustls crypto provider"
    );
    assert!(
        HBONE_FIXTURE.contains("JwtManager"),
        "fixture must supply an explicit admin JWT manager"
    );
    assert!(
        HBONE_FIXTURE.contains("\"mesh.hbone\"") && HBONE_FIXTURE.contains("\"mesh.hbone_port\""),
        "fixture must construct reserved mesh.* tags internally"
    );
    assert!(
        !HBONE_FIXTURE.contains(".validate_operator_provided_fields(")
            && !HBONE_FIXTURE.contains("validate_operator_provided_fields()"),
        "fixture must not call operator-field validation"
    );
    assert!(
        !HBONE_FIXTURE.contains("file_loader"),
        "fixture must not use the operator file loader"
    );
    assert!(
        !HBONE_FIXTURE.contains("FERRUM_FILE_CONFIG_PATH"),
        "fixture must not expose a file-config path"
    );
    assert!(
        HBONE_FIXTURE.contains("general-purpose trusted config loader"),
        "fixture must document that it is not a general-purpose trusted loader"
    );
}

#[test]
fn hbone_e2e_harness_launches_trusted_fixture_not_production_file_mode() {
    assert!(
        HBONE_RUN.contains("$PROJECT_ROOT/target/release/examples/hbone_perf_fixture"),
        "harness must launch the trusted fixture example"
    );
    assert!(
        HBONE_RUN.contains("cargo build --release --example hbone_perf_fixture"),
        "harness must build the trusted fixture example"
    );
    assert!(
        !HBONE_RUN.contains("./target/release/ferrum-edge"),
        "harness must not launch production ferrum-edge"
    );
    assert!(
        !HBONE_RUN.contains("FERRUM_FILE_CONFIG_PATH"),
        "harness must not load operator file config"
    );
    assert!(
        !HBONE_RUN.contains("FERRUM_MODE=file"),
        "harness must not start production file mode"
    );
    assert!(
        !HBONE_RUN.contains("write_gateway_config"),
        "harness must not write operator gateway YAML"
    );
    assert!(
        !HBONE_RUN.contains("\"mesh.hbone\"") && !HBONE_RUN.contains("'mesh.hbone'"),
        "harness must not stamp reserved mesh.* tags into operator file config"
    );
    assert!(
        HBONE_RUN.contains("FERRUM_BACKEND_ALLOW_IPS=private"),
        "harness must keep FERRUM_BACKEND_ALLOW_IPS=private on the fixture launch"
    );
}

#[test]
fn hbone_perf_fixture_example_is_test_false_in_root_manifest() {
    let marker = "name = \"hbone_perf_fixture\"";
    let name_at = ROOT_CARGO_TOML
        .find(marker)
        .expect("root Cargo.toml must declare hbone_perf_fixture");
    let block_start = ROOT_CARGO_TOML[..name_at]
        .rfind("[[example]]")
        .expect("hbone_perf_fixture must be declared as a Cargo example");
    let rest = &ROOT_CARGO_TOML[block_start..];
    let block_end = rest
        .find("\n[[")
        .map(|idx| block_start + idx)
        .unwrap_or(ROOT_CARGO_TOML.len());
    let block = &ROOT_CARGO_TOML[block_start..block_end];
    assert!(
        block.contains("path = \"examples/hbone_perf_fixture.rs\""),
        "example path must point at examples/hbone_perf_fixture.rs"
    );
    assert!(
        block.contains("test = false"),
        "hbone_perf_fixture must set test = false so cargo test does not run it"
    );
}
