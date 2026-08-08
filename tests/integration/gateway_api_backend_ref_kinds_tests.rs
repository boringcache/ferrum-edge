//! Integration coverage for Gateway API ServiceImport backendRefs (#3270).
//!
//! Exercises translator + status planning together so ResolvedRefs cannot claim
//! support that traffic does not receive, including update and deletion.

use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::k8s_controller::status::{
    FERRUM_GATEWAY_CONTROLLER_NAME, plan_gateway_api_status_updates,
};
use serde_json::{Value, json};
use std::collections::HashMap;

fn options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("test trust domain"),
    )
}

fn object(kind: &str, name: &str, namespace: &str, api_version: &str, spec: Value) -> K8sObject {
    K8sObject {
        api_version: api_version.to_string(),
        kind: kind.to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            uid: format!("uid-{namespace}-{name}"),
            namespace: namespace.to_string(),
            generation: Some(1),
            labels: HashMap::new(),
            annotations: HashMap::new(),
            creation_timestamp: Some("2024-01-01T00:00:00Z".to_string()),
            deletion_timestamp: None,
        },
        spec,
        status: Value::Object(serde_json::Map::new()),
    }
}

fn gateway_fixture() -> Vec<K8sObject> {
    vec![
        object(
            "GatewayClass",
            "ferrum",
            "",
            "gateway.networking.k8s.io/v1",
            json!({ "controllerName": FERRUM_GATEWAY_CONTROLLER_NAME }),
        ),
        object(
            "Gateway",
            "edge",
            "default",
            "gateway.networking.k8s.io/v1",
            json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "http",
                    "port": 80,
                    "protocol": "HTTP",
                    "allowedRoutes": { "namespaces": { "from": "All" } }
                }]
            }),
        ),
    ]
}

fn resolved_refs_status(objects: &[K8sObject]) -> (String, Option<String>) {
    let updates = plan_gateway_api_status_updates(objects, options(), &[]);
    let route_update = updates
        .iter()
        .find(|update| update.kind == "HTTPRoute" && update.name == "store")
        .expect("HTTPRoute status");
    let condition = route_update.status["parents"][0]["conditions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|condition| condition["type"] == "ResolvedRefs")
        .expect("ResolvedRefs");
    (
        condition["status"].as_str().unwrap().to_string(),
        condition["reason"].as_str().map(ToOwned::to_owned),
    )
}

#[test]
fn service_import_live_materialization_tracks_create_update_delete() {
    let mut objects = gateway_fixture();
    let route = object(
        "HTTPRoute",
        "store",
        "default",
        "gateway.networking.k8s.io/v1",
        json!({
            "parentRefs": [{"name": "edge"}],
            "hostnames": ["store.example.com"],
            "rules": [{
                "matches": [{"path": {"type": "PathPrefix", "value": "/"}}],
                "backendRefs": [{
                    "group": "multicluster.x-k8s.io",
                    "kind": "ServiceImport",
                    "name": "store",
                    "port": 8080
                }]
            }]
        }),
    );
    let import = object(
        "ServiceImport",
        "store",
        "default",
        "multicluster.x-k8s.io/v1alpha1",
        json!({
            "type": "ClusterSetIP",
            "ports": [{ "port": 8080, "protocol": "TCP" }]
        }),
    );

    // Create
    objects.push(route.clone());
    objects.push(import.clone());
    let created = translate_k8s_objects(&objects, options()).expect("create");
    assert_eq!(
        created.config.proxies[0].backend_host,
        "store.default.svc.clusterset.local"
    );
    assert_eq!(resolved_refs_status(&objects).0, "True");

    // Update port on the import inventory while the route still asks for 8080
    let import_updated = object(
        "ServiceImport",
        "store",
        "default",
        "multicluster.x-k8s.io/v1alpha1",
        json!({
            "type": "ClusterSetIP",
            "ports": [
                { "port": 8080, "protocol": "TCP" },
                { "port": 8443, "protocol": "TCP" }
            ]
        }),
    );
    objects.pop();
    objects.push(import_updated);
    let updated = translate_k8s_objects(&objects, options()).expect("update");
    assert_eq!(updated.config.proxies[0].backend_port, 8080);
    assert_eq!(resolved_refs_status(&objects).0, "True");

    // Delete the ServiceImport → traffic and status withdraw together
    objects.pop();
    let deleted = translate_k8s_objects(&objects, options()).expect("delete");
    let plugin = deleted
        .config
        .plugin_configs
        .iter()
        .find(|plugin| plugin.plugin_name == "mesh_route_dispatch")
        .expect("fail-closed dispatch");
    assert_eq!(
        plugin.config["rules"][0]["fault"]["abort"]["status_code"],
        500
    );
    let (status, reason) = resolved_refs_status(&objects);
    assert_eq!(status, "False");
    assert_eq!(reason.as_deref(), Some("BackendNotFound"));
}
