//! Gateway API non-Service `backendRef` kinds (issue #3270).
//!
//! Covers the shared typed backend-kind adapter for MCS `ServiceImport`
//! (GEP-1748): same-namespace materialization, cross-namespace ReferenceGrant,
//! unknown-kind rejection, missing-target fail-closed, update/withdrawal, and
//! status/`ResolvedRefs` parity with translation.

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

fn http_route(name: &str, namespace: &str, backend_refs: Value) -> K8sObject {
    object(
        "HTTPRoute",
        name,
        namespace,
        "gateway.networking.k8s.io/v1",
        json!({
            "rules": [{ "backendRefs": backend_refs }]
        }),
    )
}

fn http_route_with_parent(name: &str, namespace: &str, backend_refs: Value) -> K8sObject {
    object(
        "HTTPRoute",
        name,
        namespace,
        "gateway.networking.k8s.io/v1",
        json!({
            "parentRefs": [{"name": "edge"}],
            "rules": [{ "backendRefs": backend_refs }]
        }),
    )
}

fn service_import(name: &str, namespace: &str, port: u16) -> K8sObject {
    object(
        "ServiceImport",
        name,
        namespace,
        "multicluster.x-k8s.io/v1alpha1",
        json!({
            "type": "ClusterSetIP",
            "ports": [{ "port": port, "protocol": "TCP" }]
        }),
    )
}

fn ferrum_gateway_class() -> K8sObject {
    object(
        "GatewayClass",
        "ferrum",
        "",
        "gateway.networking.k8s.io/v1",
        json!({ "controllerName": FERRUM_GATEWAY_CONTROLLER_NAME }),
    )
}

fn ferrum_gateway() -> K8sObject {
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
    )
}

fn find_condition<'a>(conditions: &'a [Value], type_name: &str) -> &'a Value {
    conditions
        .iter()
        .find(|condition| condition["type"] == type_name)
        .unwrap_or_else(|| panic!("missing condition {type_name}"))
}

fn assert_fault_route(translation: &ferrum_edge::config_sources::k8s::K8sTranslation) {
    assert_eq!(
        translation.config.proxies.len(),
        1,
        "expected a single fail-closed route proxy"
    );
    let plugin = translation
        .config
        .plugin_configs
        .iter()
        .find(|plugin| plugin.plugin_name == "mesh_route_dispatch")
        .expect("invalid backend route should carry mesh_route_dispatch");
    let abort = &plugin.config["rules"][0]["fault"]["abort"];
    assert_eq!(abort["status_code"], 500);
    assert_eq!(abort["percentage"], 100.0);
}

#[test]
fn service_import_same_namespace_materializes_clusterset_dns() {
    let route = http_route(
        "store",
        "default",
        json!([{
            "group": "multicluster.x-k8s.io",
            "kind": "ServiceImport",
            "name": "store",
            "port": 8080
        }]),
    );
    let import = service_import("store", "default", 8080);

    let translation = translate_k8s_objects(&[route, import], options())
        .expect("ServiceImport backendRef should translate");

    assert_eq!(
        translation.config.proxies[0].backend_host,
        "store.default.svc.clusterset.local"
    );
    assert_eq!(translation.config.proxies[0].backend_port, 8080);
}

#[test]
fn service_import_missing_target_fail_closed() {
    let route = http_route(
        "store",
        "default",
        json!([{
            "group": "multicluster.x-k8s.io",
            "kind": "ServiceImport",
            "name": "missing",
            "port": 8080
        }]),
    );

    let translation = translate_k8s_objects(&[route], options())
        .expect("missing ServiceImport should translate fail-closed");
    assert_fault_route(&translation);
}

#[test]
fn service_import_wrong_port_fail_closed() {
    let route = http_route(
        "store",
        "default",
        json!([{
            "group": "multicluster.x-k8s.io",
            "kind": "ServiceImport",
            "name": "store",
            "port": 9090
        }]),
    );
    let import = service_import("store", "default", 8080);

    let translation = translate_k8s_objects(&[route, import], options())
        .expect("wrong ServiceImport port should translate fail-closed");
    assert_fault_route(&translation);
}

#[test]
fn unknown_backend_kind_still_fail_closed() {
    let route = http_route(
        "api",
        "default",
        json!([{
            "group": "example.com",
            "kind": "Backend",
            "name": "api",
            "port": 8080
        }]),
    );

    let translation = translate_k8s_objects(&[route], options())
        .expect("unknown backend kind should translate fail-closed");
    assert_fault_route(&translation);
}

#[test]
fn service_import_cross_namespace_requires_reference_grant() {
    let route = http_route(
        "store",
        "default",
        json!([{
            "group": "multicluster.x-k8s.io",
            "kind": "ServiceImport",
            "name": "store",
            "namespace": "backend",
            "port": 8080
        }]),
    );
    let import = service_import("store", "backend", 8080);
    let opts = options().with_source_namespaces(vec!["default".to_string(), "backend".to_string()]);

    let denied = translate_k8s_objects(&[route.clone(), import.clone()], opts.clone())
        .expect("unauthorized ServiceImport should translate fail-closed");
    assert_fault_route(&denied);

    let grant = object(
        "ReferenceGrant",
        "allow-store",
        "backend",
        "gateway.networking.k8s.io/v1",
        json!({
            "from": [{
                "group": "gateway.networking.k8s.io",
                "kind": "HTTPRoute",
                "namespace": "default"
            }],
            "to": [{
                "group": "multicluster.x-k8s.io",
                "kind": "ServiceImport"
            }]
        }),
    );

    let allowed = translate_k8s_objects(&[route, import, grant], opts)
        .expect("ReferenceGrant should authorize ServiceImport backendRef");
    assert_eq!(
        allowed.config.proxies[0].backend_host,
        "store.backend.svc.clusterset.local"
    );
}

#[test]
fn service_import_withdrawal_removes_materialized_backend() {
    let route = http_route(
        "store",
        "default",
        json!([{
            "group": "multicluster.x-k8s.io",
            "kind": "ServiceImport",
            "name": "store",
            "port": 8080
        }]),
    );
    let import = service_import("store", "default", 8080);

    let with_import = translate_k8s_objects(&[route.clone(), import], options())
        .expect("initial ServiceImport load");
    assert_eq!(
        with_import.config.proxies[0].backend_host,
        "store.default.svc.clusterset.local"
    );

    let after_delete = translate_k8s_objects(&[route], options())
        .expect("ServiceImport deletion should withdraw to fail-closed");
    assert_fault_route(&after_delete);
}

#[test]
fn service_import_update_changes_port_materialization() {
    let route_v1 = http_route(
        "store",
        "default",
        json!([{
            "group": "multicluster.x-k8s.io",
            "kind": "ServiceImport",
            "name": "store",
            "port": 8080
        }]),
    );
    let import = service_import("store", "default", 8080);
    let first = translate_k8s_objects(&[route_v1, import.clone()], options()).unwrap();
    assert_eq!(first.config.proxies[0].backend_port, 8080);

    let route_v2 = http_route(
        "store",
        "default",
        json!([{
            "group": "multicluster.x-k8s.io",
            "kind": "ServiceImport",
            "name": "store",
            "port": 8080
        }]),
    );
    // Import gains a second published port; route still selects 8080.
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
    let second = translate_k8s_objects(&[route_v2, import_updated], options()).unwrap();
    assert_eq!(second.config.proxies[0].backend_host, first.config.proxies[0].backend_host);
    assert_eq!(second.config.proxies[0].backend_port, 8080);
}

#[test]
fn status_and_translation_agree_on_service_import_resolved_refs() {
    let route = http_route_with_parent(
        "store",
        "default",
        json!([{
            "group": "multicluster.x-k8s.io",
            "kind": "ServiceImport",
            "name": "store",
            "port": 8080
        }]),
    );
    let import = service_import("store", "default", 8080);
    let objects = vec![
        ferrum_gateway_class(),
        ferrum_gateway(),
        route.clone(),
        import.clone(),
    ];

    let translation = translate_k8s_objects(&objects, options()).unwrap();
    assert_eq!(
        translation.config.proxies[0].backend_host,
        "store.default.svc.clusterset.local"
    );

    let updates = plan_gateway_api_status_updates(&objects, options(), &[]);
    let route_update = updates
        .iter()
        .find(|update| update.kind == "HTTPRoute" && update.name == "store")
        .expect("HTTPRoute status update");
    let conditions = route_update.status["parents"][0]["conditions"]
        .as_array()
        .unwrap();
    assert_eq!(find_condition(conditions, "ResolvedRefs")["status"], "True");

    let missing = vec![ferrum_gateway_class(), ferrum_gateway(), route];
    let unresolved = plan_gateway_api_status_updates(&missing, options(), &[]);
    let route_update = unresolved
        .iter()
        .find(|update| update.kind == "HTTPRoute" && update.name == "store")
        .expect("HTTPRoute status update");
    let conditions = route_update.status["parents"][0]["conditions"]
        .as_array()
        .unwrap();
    assert_eq!(find_condition(conditions, "ResolvedRefs")["status"], "False");
    assert_eq!(
        find_condition(conditions, "ResolvedRefs")["reason"],
        "BackendNotFound"
    );
}

#[test]
fn service_import_endpoint_slice_expansion_when_pod_discovery_enabled() {
    let route = http_route(
        "store",
        "default",
        json!([{
            "group": "multicluster.x-k8s.io",
            "kind": "ServiceImport",
            "name": "store",
            "port": 8080
        }]),
    );
    let import = service_import("store", "default", 8080);
    let mut slice = object(
        "EndpointSlice",
        "store-mcs",
        "default",
        "discovery.k8s.io/v1",
        json!({
            "ports": [{ "port": 8080 }],
            "endpoints": [{
                "addresses": ["10.0.0.10"],
                "conditions": { "ready": true }
            }]
        }),
    );
    slice
        .metadata
        .labels
        .insert(
            "multicluster.kubernetes.io/service-name".to_string(),
            "store".to_string(),
        );

    let opts = options().with_pod_discovery_enabled(true);

    let translation = translate_k8s_objects(&[route, import, slice], opts)
        .expect("ServiceImport EndpointSlice expansion should translate");
    assert_eq!(translation.config.proxies[0].backend_host, "10.0.0.10");
    assert_eq!(translation.config.proxies[0].backend_port, 8080);
}
