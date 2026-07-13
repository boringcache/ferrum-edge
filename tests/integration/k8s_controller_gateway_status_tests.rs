//! Integration coverage for Gateway API status concurrency and typed route
//! materialization records.

use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::k8s_controller::status::{
    FERRUM_GATEWAY_CONTROLLER_NAME, GatewayApiStatusUpdate, GatewayApiStatusWriter,
    plan_gateway_api_status_updates,
};
use http::{Method, Request, Response, StatusCode};
use kube::Client;
use kube::client::Body;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use tower::service_fn;

#[derive(Default)]
struct MockKubeState {
    get_count: usize,
    patch_bodies: Vec<Value>,
}

fn options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("test trust domain"),
    )
}

fn object(api_version: &str, kind: &str, name: &str, namespace: &str, spec: Value) -> K8sObject {
    K8sObject {
        api_version: api_version.to_string(),
        kind: kind.to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            uid: String::new(),
            namespace: namespace.to_string(),
            generation: Some(3),
            labels: HashMap::new(),
            annotations: HashMap::new(),
            creation_timestamp: None,
            deletion_timestamp: None,
        },
        spec,
        status: Value::Object(serde_json::Map::new()),
    }
}

fn route_status_update() -> GatewayApiStatusUpdate {
    GatewayApiStatusUpdate {
        api_version: "gateway.networking.k8s.io/v1".to_string(),
        kind: "HTTPRoute".to_string(),
        namespace: "default".to_string(),
        name: "api".to_string(),
        status: json!({
            "parents": [{
                "parentRef": {"name": "edge"},
                "controllerName": FERRUM_GATEWAY_CONTROLLER_NAME,
                "conditions": [{
                    "type": "Accepted",
                    "status": "True",
                    "observedGeneration": 3,
                    "reason": "Accepted",
                    "message": "Ferrum accepted this route",
                    "lastTransitionTime": "2026-07-13T00:00:00Z"
                }]
            }]
        }),
        patch_gateway_addresses: false,
        patch_gateway_listeners: false,
    }
}

fn live_route(resource_version: &str, foreign_controller: &str) -> Value {
    json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": {
            "name": "api",
            "namespace": "default",
            "resourceVersion": resource_version
        },
        "status": {
            "parents": [{
                "parentRef": {"name": "foreign-edge"},
                "controllerName": foreign_controller,
                "conditions": [{"type": "Accepted", "status": "True"}]
            }]
        }
    })
}

fn json_response(status: StatusCode, value: Value) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&value).expect("serialize mock Kubernetes response"),
        ))
        .expect("build mock Kubernetes response")
}

fn conflict_response() -> Response<Body> {
    json_response(
        StatusCode::CONFLICT,
        json!({
            "apiVersion": "v1",
            "kind": "Status",
            "status": "Failure",
            "message": "the object has been modified",
            "reason": "Conflict",
            "details": {
                "group": "gateway.networking.k8s.io",
                "kind": "httproutes",
                "name": "api"
            },
            "code": 409
        }),
    )
}

fn mock_kube_client(state: Arc<Mutex<MockKubeState>>) -> Client {
    let service = service_fn(move |request: Request<Body>| {
        let state = state.clone();
        async move {
            let method = request.method().clone();
            assert_eq!(
                request.uri().path(),
                "/apis/gateway.networking.k8s.io/v1/namespaces/default/httproutes/api/status"
            );
            if method == Method::PATCH {
                assert_eq!(
                    request
                        .headers()
                        .get(http::header::CONTENT_TYPE)
                        .and_then(|value| value.to_str().ok()),
                    Some("application/merge-patch+json")
                );
            }
            let body = request
                .into_body()
                .collect_bytes()
                .await
                .expect("read mock Kubernetes request body");
            let response = match method {
                Method::GET => {
                    let mut state = state.lock().expect("lock mock Kubernetes state");
                    let response = if state.get_count == 0 {
                        live_route("1", "example.com/initial-controller")
                    } else {
                        live_route("2", "example.com/concurrent-controller")
                    };
                    state.get_count += 1;
                    json_response(StatusCode::OK, response)
                }
                Method::PATCH => {
                    let patch: Value =
                        serde_json::from_slice(&body).expect("parse status patch body");
                    let mut state = state.lock().expect("lock mock Kubernetes state");
                    state.patch_bodies.push(patch.clone());
                    if state.patch_bodies.len() == 1 {
                        conflict_response()
                    } else {
                        json_response(
                            StatusCode::OK,
                            json!({
                                "apiVersion": "gateway.networking.k8s.io/v1",
                                "kind": "HTTPRoute",
                                "metadata": {
                                    "name": "api",
                                    "namespace": "default",
                                    "resourceVersion": "3"
                                },
                                "status": patch["status"].clone()
                            }),
                        )
                    }
                }
                _ => json_response(
                    StatusCode::METHOD_NOT_ALLOWED,
                    json!({"apiVersion": "v1", "kind": "Status", "code": 405}),
                ),
            };
            Ok::<_, Infallible>(response)
        }
    });
    Client::new(service, "default")
}

#[tokio::test]
async fn route_status_conflict_refetches_and_preserves_concurrent_foreign_parent() {
    let state = Arc::new(Mutex::new(MockKubeState::default()));
    let writer = GatewayApiStatusWriter::new(mock_kube_client(state.clone()));

    writer
        .patch_updates(vec![route_status_update()])
        .await
        .expect("route status retry should succeed");

    let state = state.lock().expect("lock mock Kubernetes state");
    assert_eq!(state.get_count, 2, "a 409 must trigger a fresh status read");
    assert_eq!(state.patch_bodies.len(), 2);

    let first = &state.patch_bodies[0];
    assert_eq!(first["metadata"]["resourceVersion"].as_str(), Some("1"));
    assert!(has_parent(first, "example.com/initial-controller"));

    let retried = &state.patch_bodies[1];
    assert_eq!(retried["metadata"]["resourceVersion"].as_str(), Some("2"));
    assert!(has_parent(retried, "example.com/concurrent-controller"));
    assert!(!has_parent(retried, "example.com/initial-controller"));
    assert!(has_parent(retried, FERRUM_GATEWAY_CONTROLLER_NAME));
}

fn has_parent(patch: &Value, controller_name: &str) -> bool {
    patch["status"]["parents"]
        .as_array()
        .is_some_and(|parents| {
            parents
                .iter()
                .any(|parent| parent["controllerName"].as_str() == Some(controller_name))
        })
}

#[test]
fn typed_route_parent_mapping_is_emitted_and_drives_programmed_status() {
    let gateway_class = object(
        "gateway.networking.k8s.io/v1",
        "GatewayClass",
        "ferrum",
        "",
        json!({"controllerName": FERRUM_GATEWAY_CONTROLLER_NAME}),
    );
    let gateway = object(
        "gateway.networking.k8s.io/v1",
        "Gateway",
        "edge",
        "default",
        json!({
            "gatewayClassName": "ferrum",
            "listeners": [{"name": "web", "port": 80, "protocol": "HTTP"}]
        }),
    );
    let route = object(
        "gateway.networking.k8s.io/v1",
        "HTTPRoute",
        "api",
        "default",
        json!({
            "parentRefs": [{"name": "edge", "sectionName": "web"}],
            "rules": [{"backendRefs": [{"name": "api", "port": 8080}]}]
        }),
    );
    let objects = vec![gateway_class, gateway, route];
    let translation = translate_k8s_objects(&objects, options()).expect("route should materialize");

    assert!(translation.materialized_route_parents.iter().any(|entry| {
        entry.route.api_version == "gateway.networking.k8s.io/v1"
            && entry.route.kind == "HTTPRoute"
            && entry.route.namespace == "default"
            && entry.route.name == "api"
            && entry.parent_ref == "gateway.networking.k8s.io/Gateway/default/edge/web/*"
    }));

    let updates =
        plan_gateway_api_status_updates(&objects, options(), &translation.route_conflicts);
    let route_update = updates
        .iter()
        .find(|update| update.kind == "HTTPRoute" && update.name == "api")
        .expect("route status update");
    let conditions = route_update.status["parents"][0]["conditions"]
        .as_array()
        .expect("route parent conditions");
    assert!(conditions.iter().any(|condition| {
        condition["type"].as_str() == Some("Programmed")
            && condition["status"].as_str() == Some("True")
    }));
}
