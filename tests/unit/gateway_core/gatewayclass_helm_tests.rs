//! Static Helm/chart contract coverage for the observed GatewayClass object
//! (issue #3835). Ferrum no longer infers controller ownership from the class
//! name spelling, so the chart must create the cluster-scoped object.

use std::path::PathBuf;

fn chart_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("charts/ferrum-mesh")
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(chart_root().join(rel)).unwrap_or_else(|e| {
        panic!("failed to read charts/ferrum-mesh/{rel}: {e}");
    })
}

#[test]
fn values_create_owned_gatewayclass_by_default() {
    let values = read("values.yaml");
    assert!(
        values.contains("gatewayClass:")
            && values.contains("create: true")
            && values.contains("name: ferrum")
            && values.contains("controllerName: ferrum.io/gateway-controller"),
        "chart values must explicitly create Ferrum's GatewayClass"
    );
}

#[test]
fn schema_pins_controller_name_and_allows_non_default_class_name() {
    let schema = read("values.schema.json");
    assert!(schema.contains("\"gatewayClass\""));
    assert!(schema.contains("\"const\": \"ferrum.io/gateway-controller\""));
    assert!(
        schema.contains("\"name\"") && schema.contains("\"minLength\": 1"),
        "class name must remain overridable for Ferrum-owned non-default names"
    );
}

#[test]
fn template_creates_cluster_scoped_gatewayclass_without_name_fallback() {
    let template = read("templates/gatewayclass.yaml");
    assert!(template.contains("kind: GatewayClass"));
    assert!(template.contains("controllerName: ferrum.io/gateway-controller"));
    assert!(
        template.contains("hasKey $gc \"create\""),
        "create=false must disable the object; Sprig default would treat false as true"
    );
    assert!(
        template
            .contains("fail \"gatewayClass.controllerName must be ferrum.io/gateway-controller"),
        "chart must refuse a non-Ferrum controllerName instead of shipping a name-only shim"
    );
    assert!(
        !template.contains("namespace:"),
        "GatewayClass is cluster-scoped"
    );
}
