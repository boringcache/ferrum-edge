//! Static Helm/chart contract coverage for the observed GatewayClass object
//! (issue #3835). Ferrum no longer infers controller ownership from the class
//! name spelling, so the chart must create the cluster-scoped object. Independent
//! Helm releases in one cluster must own distinct GatewayClass names; the chart
//! must not skip, keep, or import another release's object.

use std::path::PathBuf;

fn chart_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("charts/ferrum-mesh")
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(chart_root().join(rel)).unwrap_or_else(|e| {
        panic!("failed to read charts/ferrum-mesh/{rel}: {e}");
    })
}

fn read_repo(rel: &str) -> String {
    std::fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| {
        panic!("failed to read {rel}: {e}");
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
    assert!(
        values.contains("Independent ferrum-mesh releases in one cluster must use unique `name`"),
        "values.yaml must document unique GatewayClass names for independent releases"
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
    assert!(
        schema.contains("Independent releases in one cluster must use unique names"),
        "schema must document unique GatewayClass names for independent releases"
    );
}

#[test]
fn conformance_harnesses_disable_helm_gatewayclass_creation() {
    let harnesses = [
        "scripts/gateway_api_data_plane_conformance.sh",
        "scripts/gateway_api_conformance_lab_setup.sh",
    ];
    for path in harnesses {
        let script = read_repo(path);
        assert!(
            script.contains("--set gatewayClass.create=false"),
            "{path} must disable chart GatewayClass creation; the harness applies and deletes/recreates GatewayClass/ferrum out of band"
        );
    }
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

#[test]
fn template_does_not_share_or_import_another_release_gatewayclass() {
    let template = read("templates/gatewayclass.yaml");
    assert!(
        !template.contains("lookup ")
            && !template.contains("lookup\t")
            && !template.contains("lookup\""),
        "chart must render its own GatewayClass; lookup would skip or share another release's object"
    );
    assert!(
        !template.contains("helm.sh/resource-policy")
            && !template.contains("meta.helm.sh/release-name")
            && !template.contains("meta.helm.sh/release-namespace"),
        "chart must not keep-or-fake Helm ownership of a cluster-scoped GatewayClass"
    );
}

#[test]
fn helm_ci_coresident_releases_set_unique_gatewayclass_names() {
    let ci = read_repo(".github/workflows/ci.yml").replace("\\\n", " ");
    let dev = helm_install_line(&ci, "ferrum-dev");
    let prod = helm_install_line(&ci, "ferrum-prod");
    let dev_name = gateway_class_name_override(&dev)
        .expect("ferrum-dev must --set gatewayClass.name to a unique cluster-scoped object");
    let prod_name = gateway_class_name_override(&prod)
        .expect("ferrum-prod must --set gatewayClass.name to a unique cluster-scoped object");
    assert_ne!(
        dev_name, prod_name,
        "co-resident Helm Chart fixtures must not share one GatewayClass name"
    );
    for (release, line) in [("ferrum-dev", dev.as_str()), ("ferrum-prod", prod.as_str())] {
        assert!(
            !line.contains("gatewayClass.create=false")
                && !line.contains("--force")
                && !line.contains("--take-ownership"),
            "{release} must own its GatewayClass; do not skip-create or force-import another release's object"
        );
    }
}

#[test]
fn example_values_keep_default_class_name_and_create() {
    for rel in [
        "examples/development-values.yaml",
        "examples/production-existing-secrets-values.yaml",
    ] {
        let values = read(rel);
        assert!(
            !values.contains("create: false") && !values.contains("gatewayClass:"),
            "{rel} is a standalone shape: inherit values.yaml name/create rather than sharing or disabling the class"
        );
        assert!(
            values.contains("unique gatewayClass.name"),
            "{rel} must warn that a second independent release needs a unique GatewayClass name"
        );
    }
}

#[test]
fn docs_require_unique_gatewayclass_name_for_independent_releases() {
    let docs = read_repo("docs/kubernetes_deployment.md");
    assert!(
        docs.contains("unique") && docs.contains("gatewayClass.name"),
        "deployment docs must tell operators that a second independent release needs a unique GatewayClass name"
    );
}

fn helm_install_line(ci: &str, release: &str) -> String {
    let prefix = format!("helm install {release} ./charts/ferrum-mesh");
    ci.lines()
        .map(str::trim)
        .find(|line| line.starts_with(&prefix))
        .unwrap_or_else(|| panic!("Helm Chart job must install {release}"))
        .to_string()
}

fn gateway_class_name_override(install: &str) -> Option<String> {
    const FLAG: &str = "gatewayClass.name=";
    let idx = install.find(FLAG)?;
    let rest = &install[idx + FLAG.len()..];
    let name = rest
        .split(|c: char| c.is_whitespace() || c == ',')
        .next()
        .unwrap_or("")
        .trim_matches('"');
    (!name.is_empty()).then(|| name.to_string())
}
