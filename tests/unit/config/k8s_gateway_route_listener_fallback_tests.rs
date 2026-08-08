//! External regressions for the unresolved-parentRef fallback in Gateway API
//! route materialization (issue #3612).
//!
//! Port-aware routing keys each claim on the concrete Gateway listener behind
//! it, but a snapshot does not always contain that Gateway: a route may be
//! reconciled before its parent, or authored with no `parentRefs` at all. The
//! resolver reports that case as a known-good parentRef with an EMPTY listener
//! set, and materialization must fall back to a listener-less, port-agnostic
//! claim. Treating the empty set as "no claim" silently drops every such route.

use std::collections::HashMap;

use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::TrustDomain;
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

/// A `parentRefs` entry naming a Gateway that is absent from the snapshot is an
/// unresolved selector, not a refusal: it keeps the pre-port-aware claim rather
/// than dropping the route.
#[test]
fn a_route_naming_an_absent_gateway_materializes_a_listener_less_claim() {
    let route = http_route("sample", Some(json!([{"name": "not-in-this-snapshot"}])));
    let result = translate_k8s_objects(&[route], options()).expect("translation succeeds");

    assert_eq!(
        result.config.proxies.len(),
        1,
        "an unresolvable parentRef must not drop the route: {:?}",
        result.config.proxies
    );
    assert_eq!(result.config.proxies[0].listen_port, None);
}

/// The fallback is a fallback only: once the Gateway listener IS in the
/// snapshot, the claim is stamped with that listener's port.
#[test]
fn a_resolved_listener_still_stamps_the_port_on_the_claim() {
    let gateway = object(
        "Gateway",
        "edge",
        json!({
            "gatewayClassName": "ferrum",
            "listeners": [{
                "name": "http",
                "port": 8081,
                "protocol": "HTTP",
                "allowedRoutes": {"namespaces": {"from": "All"}}
            }]
        }),
    );
    let route = http_route("sample", Some(json!([{"name": "edge"}])));
    let result = translate_k8s_objects(&[gateway, route], options()).expect("translation succeeds");

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
}
