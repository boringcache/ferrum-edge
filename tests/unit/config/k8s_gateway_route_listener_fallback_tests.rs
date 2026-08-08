//! External regressions for HTTPRoute / GRPCRoute parent attachment
//! materialization (issue #3612 / PR #3677).
//!
//! Port-aware routing keys each claim on the concrete Gateway listener behind
//! it. A declared Gateway `parentRef` that resolves no concrete,
//! materializable listener must fail closed: emit no proxy, upstream, plugin,
//! or materialized-parent record for that parent — including an absent Gateway
//! and sectionName/port/policy gates that clear no listener. Falling back to a
//! listener-less claim would expose the backend on unrelated frontends while
//! status reports `NoMatchingParent` / `NotAllowedByListeners`.
//!
//! The deliberately parentless legacy shape (`spec.parentRefs` absent) still
//! materializes a listener-less, port-agnostic claim. Resolved listeners still
//! stamp their own port.

use std::collections::HashMap;

use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::k8s_controller::status::plan_gateway_api_status_updates;
use serde_json::{Value, json};

fn options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("test trust domain"),
    )
}

fn object(kind: &str, name: &str, spec: Value) -> K8sObject {
    K8sObject {
        api_version: "gateway.networking.k8s.io/v1".to_string(),
        kind: kind.to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            uid: String::new(),
            namespace: "default".to_string(),
            generation: None,
            labels: HashMap::new(),
            creation_timestamp: None,
            deletion_timestamp: None,
            annotations: HashMap::new(),
        },
        spec,
        status: Value::Object(serde_json::Map::new()),
    }
}

fn gateway_class() -> K8sObject {
    object(
        "GatewayClass",
        "ferrum",
        json!({"controllerName": "ferrum.io/gateway-controller"}),
    )
}

fn http_gateway(name: &str, port: u16) -> K8sObject {
    object(
        "Gateway",
        name,
        json!({
            "gatewayClassName": "ferrum",
            "listeners": [{
                "name": "http",
                "port": port,
                "protocol": "HTTP",
                "allowedRoutes": {"namespaces": {"from": "All"}}
            }]
        }),
    )
}

fn http_route(name: &str, parent_refs: Option<Value>) -> K8sObject {
    let mut spec = json!({
        "hostnames": ["api.example.com"],
        "rules": [{
            "matches": [{"path": {"type": "PathPrefix", "value": "/api"}}],
            "backendRefs": [{"name": "api", "port": 8080}]
        }]
    });
    if let Some(parent_refs) = parent_refs {
        spec["parentRefs"] = parent_refs;
    }
    object("HTTPRoute", name, spec)
}

fn grpc_route(name: &str, parent_refs: Option<Value>) -> K8sObject {
    let mut spec = json!({
        "hostnames": ["grpc.example.com"],
        "rules": [{
            "matches": [{"method": {"service": "example.Echo", "method": "Get"}}],
            "backendRefs": [{"name": "grpc-api", "port": 50051}]
        }]
    });
    if let Some(parent_refs) = parent_refs {
        spec["parentRefs"] = parent_refs;
    }
    object("GRPCRoute", name, spec)
}

fn assert_no_http_family_traffic(objects: &[K8sObject], kind: &str, name: &str) {
    let result = translate_k8s_objects(objects, options()).expect("translation succeeds");

    assert!(
        result.config.proxies.is_empty(),
        "{kind} {name}: declared unresolved parent must emit no proxy, got {:?}",
        result
            .config
            .proxies
            .iter()
            .map(|proxy| (proxy.id.clone(), proxy.listen_port, proxy.backend_port))
            .collect::<Vec<_>>()
    );
    assert!(
        result.config.upstreams.is_empty(),
        "{kind} {name}: declared unresolved parent must emit no upstream, got {:?}",
        result.config.upstreams
    );
    assert!(
        result.config.plugin_configs.is_empty(),
        "{kind} {name}: declared unresolved parent must emit no plugin, got {:?}",
        result.config.plugin_configs
    );
    assert!(
        !result
            .materialized_route_parents
            .iter()
            .any(|entry| entry.route.kind == kind && entry.route.name == name),
        "{kind} {name}: declared unresolved parent must leave no materialized-parent record, got {:?}",
        result.materialized_route_parents
    );
}

fn assert_status_not_programmed(objects: &[K8sObject], kind: &str, name: &str, reason: &str) {
    let updates = plan_gateway_api_status_updates(objects, options(), &[]);
    let route_update = updates
        .iter()
        .find(|update| update.kind == kind && update.name == name)
        .unwrap_or_else(|| panic!("expected status update for {kind}/{name}"));
    let parents = route_update.status["parents"]
        .as_array()
        .expect("parents array");
    assert!(
        !parents.is_empty(),
        "{kind}/{name} must still surface a parent status entry"
    );
    let conditions = parents[0]["conditions"]
        .as_array()
        .expect("parent conditions");
    let accepted = conditions
        .iter()
        .find(|condition| condition["type"] == "Accepted")
        .expect("Accepted condition");
    let programmed = conditions
        .iter()
        .find(|condition| condition["type"] == "Programmed")
        .expect("Programmed condition");
    assert_eq!(accepted["status"], "False");
    assert_eq!(accepted["reason"], reason);
    assert_eq!(programmed["status"], "False");
    assert_ne!(
        programmed["reason"], "Programmed",
        "{kind}/{name} must not report Programmed while the declared parent resolves no listener"
    );
}

/// No `parentRefs` at all: the route still programs traffic, port-agnostically.
#[test]
fn a_route_without_parent_refs_materializes_a_listener_less_claim() {
    let result = translate_k8s_objects(&[http_route("sample", None)], options())
        .expect("translation succeeds");

    assert_eq!(
        result.config.proxies.len(),
        1,
        "a parentRef-less HTTPRoute must still materialize: {:?}",
        result.config.proxies
    );
    assert_eq!(result.config.proxies[0].listen_port, None);
    assert_eq!(result.config.proxies[0].backend_port, 8080);
}

/// A declared Gateway parent naming an absent Gateway must open nothing.
#[test]
fn httproute_with_unknown_gateway_parent_materializes_no_traffic() {
    let route = http_route("sample", Some(json!([{"name": "not-in-this-snapshot"}])));
    assert_no_http_family_traffic(&[route.clone()], "HTTPRoute", "sample");
    assert_status_not_programmed(&[route], "HTTPRoute", "sample", "NoMatchingParent");
}

/// Same fail-closed gate for GRPCRoute.
#[test]
fn grpcroute_with_unknown_gateway_parent_materializes_no_traffic() {
    let route = grpc_route("sample", Some(json!([{"name": "not-in-this-snapshot"}])));
    assert_no_http_family_traffic(&[route.clone()], "GRPCRoute", "sample");
    assert_status_not_programmed(&[route], "GRPCRoute", "sample", "NoMatchingParent");
}

/// A Gateway that exists but shares no hostname intersection with the route
/// resolves no concrete listener and must also fail closed rather than falling
/// back to a listener-less claim.
#[test]
fn httproute_with_mismatched_gateway_listener_materializes_no_traffic() {
    let gateway = object(
        "Gateway",
        "edge",
        json!({
            "gatewayClassName": "ferrum",
            "listeners": [{
                "name": "http",
                "port": 8081,
                "protocol": "HTTP",
                "hostname": "other.example.com",
                "allowedRoutes": {"namespaces": {"from": "All"}}
            }]
        }),
    );
    let route = http_route("sample", Some(json!([{"name": "edge"}])));
    let objects = [gateway_class(), gateway, route];
    assert_no_http_family_traffic(&objects, "HTTPRoute", "sample");
    assert_status_not_programmed(
        &objects,
        "HTTPRoute",
        "sample",
        "NoMatchingListenerHostname",
    );
}

#[test]
fn grpcroute_with_mismatched_gateway_listener_materializes_no_traffic() {
    let gateway = object(
        "Gateway",
        "edge",
        json!({
            "gatewayClassName": "ferrum",
            "listeners": [{
                "name": "http",
                "port": 8082,
                "protocol": "HTTP",
                "hostname": "other.example.com",
                "allowedRoutes": {"namespaces": {"from": "All"}}
            }]
        }),
    );
    let route = grpc_route("sample", Some(json!([{"name": "edge"}])));
    let objects = [gateway_class(), gateway, route];
    assert_no_http_family_traffic(&objects, "GRPCRoute", "sample");
    assert_status_not_programmed(
        &objects,
        "GRPCRoute",
        "sample",
        "NoMatchingListenerHostname",
    );
}

/// Once the Gateway listener IS in the snapshot, the claim is stamped with
/// that listener's port.
#[test]
fn a_resolved_httproute_listener_still_stamps_the_port_on_the_claim() {
    let objects = [
        gateway_class(),
        http_gateway("edge", 8081),
        http_route("sample", Some(json!([{"name": "edge"}]))),
    ];
    let result = translate_k8s_objects(&objects, options()).expect("translation succeeds");

    assert_eq!(
        result.config.proxies.len(),
        1,
        "the resolved claim must materialize once: {:?}",
        result.config.proxies
    );
    assert_eq!(
        result.config.proxies[0].listen_port,
        Some(8081),
        "a resolved listener must stamp its own port"
    );
    assert!(
        result
            .materialized_route_parents
            .iter()
            .any(|entry| entry.route.kind == "HTTPRoute" && entry.route.name == "sample"),
        "a resolved listener must record a materialized parent"
    );
}

#[test]
fn a_resolved_grpcroute_listener_still_stamps_the_port_on_the_claim() {
    let objects = [
        gateway_class(),
        http_gateway("edge", 8082),
        grpc_route("sample", Some(json!([{"name": "edge"}]))),
    ];
    let result = translate_k8s_objects(&objects, options()).expect("translation succeeds");

    assert_eq!(
        result.config.proxies.len(),
        1,
        "the resolved GRPCRoute claim must materialize once: {:?}",
        result.config.proxies
    );
    assert_eq!(
        result.config.proxies[0].listen_port,
        Some(8082),
        "a resolved GRPCRoute listener must stamp its own port"
    );
    assert_eq!(result.config.proxies[0].backend_port, 50051);
    assert!(
        result
            .materialized_route_parents
            .iter()
            .any(|entry| entry.route.kind == "GRPCRoute" && entry.route.name == "sample"),
        "a resolved GRPCRoute listener must record a materialized parent"
    );
}
