//! Static Helm/chart contract coverage for required image.tag (issue #4440).
//!
//! These tests prove both charts fail render without an explicit tag and accept
//! one when set, without requiring a local `helm` binary. Hosted CI still runs
//! `helm template` end-to-end.

use std::path::PathBuf;

fn gateway_chart_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("charts/ferrum-gateway")
}

fn mesh_chart_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("charts/ferrum-mesh")
}

fn read_gateway(rel: &str) -> String {
    std::fs::read_to_string(gateway_chart_root().join(rel)).unwrap_or_else(|e| {
        panic!("failed to read charts/ferrum-gateway/{rel}: {e}");
    })
}

fn read_mesh(rel: &str) -> String {
    std::fs::read_to_string(mesh_chart_root().join(rel)).unwrap_or_else(|e| {
        panic!("failed to read charts/ferrum-mesh/{rel}: {e}");
    })
}

const FAIL_SNIPPET: &str = "image.tag is required";

#[test]
fn gateway_values_default_tag_empty_without_appversion_fallback() {
    let values = read_gateway("values.yaml");
    assert!(
        values.contains("tag: \"\""),
        "gateway values must leave image.tag empty so installs fail without an explicit tag"
    );
    assert!(
        !values.contains("Defaults to the chart appVersion"),
        "gateway values must not document an appVersion image fallback"
    );
}

#[test]
fn gateway_helpers_fail_render_without_tag_and_name_value() {
    let helpers = read_gateway("templates/_helpers.tpl");
    assert!(
        helpers.contains("define \"ferrum-gateway.validateImageTag\""),
        "gateway chart must validate image.tag at render time"
    );
    assert!(
        helpers.contains(FAIL_SNIPPET),
        "gateway validation must name image.tag in the failure message"
    );
    assert!(
        !helpers.contains("default .Chart.AppVersion"),
        "gateway image helper must not fall back to Chart.AppVersion"
    );
    assert!(
        helpers.contains("include \"ferrum-gateway.validateImageTag\" ."),
        "gateway validate must call image.tag validation"
    );
}

#[test]
fn gateway_schema_requires_nonempty_image_tag() {
    let schema = read_gateway("values.schema.json");
    assert!(
        schema.contains("\"required\": [\"repository\", \"tag\"]"),
        "gateway schema must require image.tag"
    );
    assert!(
        schema.contains("No immutable vX.Y.Z release is published yet"),
        "gateway schema must document why image.tag has no default"
    );
}

#[test]
fn mesh_values_default_tag_empty_without_hardcoded_release() {
    let values = read_mesh("values.yaml");
    assert!(
        values.contains("tag: \"\""),
        "mesh values must leave image.tag empty so installs fail without an explicit tag"
    );
    assert!(
        !values.contains("tag: \"0.9.0\""),
        "mesh values must not hard-code an unpublished 0.9.0 image tag"
    );
}

#[test]
fn mesh_helpers_fail_render_without_tag_and_render_image_helper() {
    let helpers = read_mesh("templates/_helpers.tpl");
    assert!(
        helpers.contains("define \"ferrum-mesh.validateImageTag\""),
        "mesh chart must validate image.tag at render time"
    );
    assert!(
        helpers.contains(FAIL_SNIPPET),
        "mesh validation must name image.tag in the failure message"
    );
    assert!(
        helpers.contains("define \"ferrum-mesh.image\""),
        "mesh chart must centralize image rendering"
    );
}

#[test]
fn mesh_validation_template_calls_image_tag_guard() {
    let validation = read_mesh("templates/validation.yaml");
    assert!(
        validation.contains("include \"ferrum-mesh.validateImageTag\" ."),
        "mesh validation.yaml must fail when image.tag is unset"
    );
}

#[test]
fn mesh_workloads_use_image_helper_not_raw_tag() {
    for rel in [
        "templates/injector-deployment.yaml",
        "templates/control-plane-deployment.yaml",
        "templates/ca-deployment.yaml",
        "templates/east-west-gateway-deployment.yaml",
    ] {
        let template = read_mesh(rel);
        assert!(
            template.contains("include \"ferrum-mesh.image\" ."),
            "{rel} must render image through ferrum-mesh.image helper"
        );
        assert!(
            !template.contains(".Values.image.tag }}"),
            "{rel} must not reference .Values.image.tag directly"
        );
    }
}

#[test]
fn mesh_schema_requires_nonempty_image_tag() {
    let schema = read_mesh("values.schema.json");
    assert!(
        schema.contains("\"required\": [\"repository\", \"tag\"]"),
        "mesh schema must require image.tag"
    );
    assert!(
        schema.contains("No immutable vX.Y.Z release is published yet"),
        "mesh schema must document why image.tag has no default"
    );
}
