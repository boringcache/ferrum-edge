//! Integration coverage for GatewayClass observed-authority (issue #3835).
//!
//! Translation and Gateway API status planning must share one verdict, and a
//! previously written Ferrum status must not keep claiming Accepted/Programmed
//! after the referenced class is absent or foreign.

use std::collections::HashMap;

use ferrum_edge::config_sources::k8s::{
    FERRUM_GATEWAY_CONTROLLER_NAME, K8sMetadata, K8sObject, K8sTranslationOptions,
    translate_k8s_objects,
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

fn object(kind: &str, name: &str, namespace: &str, spec: Value) -> K8sObject {
    K8sObject {
        api_version: "gateway.networking.k8s.io/v1".to_string(),
        kind: kind.to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            uid: format!("uid-{name}"),
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

fn ferrum_class() -> K8sObject {
    object(
        "GatewayClass",
        "ferrum",
        "",
        json!({ "controllerName": FERRUM_GATEWAY_CONTROLLER_NAME }),
    )
}

fn gateway() -> K8sObject {
    object(
        "Gateway",
        "edge",
        "default",
        json!({
            "gatewayClassName": "ferrum",
            "listeners": [{"name": "http", "port": 80, "protocol": "HTTP"}]
        }),
    )
}

fn route() -> K8sObject {
    object(
        "HTTPRoute",
        "app",
        "default",
        json!({
            "parentRefs": [{"name": "edge"}],
            "rules": [{
                "backendRefs": [{"name": "api", "port": 8080}]
            }]
        }),
    )
}

#[test]
fn translation_and_status_agree_across_create_delete_and_foreign_class() {
    let owned = vec![ferrum_class(), gateway(), route()];
    let owned_translation =
        translate_k8s_objects(&owned, options()).expect("owned snapshot translates");
    let owned_status = plan_gateway_api_status_updates(&owned, options(), &[]);
    assert!(
        !owned_translation.materialized_gateway_listeners.is_empty(),
        "owned class must program listeners"
    );
    assert!(
        owned_status
            .iter()
            .any(|update| update.kind == "Gateway" && update.name == "edge"),
        "owned class must plan Gateway status"
    );

    let absent: Vec<K8sObject> = owned
        .iter()
        .filter(|object| object.kind != "GatewayClass")
        .cloned()
        .collect();
    let absent_translation =
        translate_k8s_objects(&absent, options()).expect("absent class translates");
    let absent_status = plan_gateway_api_status_updates(&absent, options(), &[]);
    assert!(absent_translation.materialized_gateway_listeners.is_empty());
    assert!(
        !absent_status
            .iter()
            .any(|update| update.kind == "Gateway" && update.name == "edge"),
        "absent class must not plan new Gateway Accepted/Programmed writes"
    );

    let mut foreign_class = ferrum_class();
    foreign_class.spec = json!({ "controllerName": "example.com/other-controller" });
    let foreign = vec![foreign_class, gateway(), route()];
    let foreign_translation =
        translate_k8s_objects(&foreign, options()).expect("foreign class translates");
    let foreign_status = plan_gateway_api_status_updates(&foreign, options(), &[]);
    assert!(foreign_translation.materialized_gateway_listeners.is_empty());
    assert!(
        !foreign_status
            .iter()
            .any(|update| update.kind == "Gateway" && update.name == "edge")
    );
}

#[test]
fn leftover_ferrum_route_status_is_withdrawn_without_claiming_accepted() {
    let mut stale_route = route();
    stale_route.status = json!({
        "parents": [{
            "controllerName": FERRUM_GATEWAY_CONTROLLER_NAME,
            "parentRef": {"name": "edge"},
            "conditions": [{
                "type": "Accepted",
                "status": "True",
                "reason": "Accepted"
            }]
        }]
    });
    let objects = vec![gateway(), stale_route];
    let updates = plan_gateway_api_status_updates(&objects, options(), &[]);
    assert!(
        !updates
            .iter()
            .any(|update| update.kind == "Gateway" && update.name == "edge"),
        "Gateway status must not be planned without an owned GatewayClass"
    );

    let route_update = updates
        .iter()
        .find(|update| update.kind == "HTTPRoute" && update.name == "app")
        .expect("leftover Ferrum route parents must still be eligible so they can be stripped");
    let parents = route_update.status["parents"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        parents.iter().all(|parent| {
            parent.get("controllerName").and_then(Value::as_str)
                != Some(FERRUM_GATEWAY_CONTROLLER_NAME)
        }),
        "Ferrum must not keep claiming route Accepted after class authority is gone: {parents:?}"
    );
}
