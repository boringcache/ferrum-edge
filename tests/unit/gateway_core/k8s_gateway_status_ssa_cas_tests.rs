//! SSA Gateway API status writes must carry a live `resourceVersion` CAS token.
//!
//! Dropping a timed-out apply future does not prove the API server rejected the
//! request. The apply document is the only place kube serializes that
//! precondition (`Patch::Apply` → `serde_json::to_vec`).

use ferrum_edge::k8s_controller::status::{
    GatewayApiStatusUpdate, gateway_api_status_error_is_not_found,
    gateway_status_apply_patch_for_update,
};
use serde_json::{Value, json};

fn update(kind: &str, namespace: &str, name: &str) -> GatewayApiStatusUpdate {
    GatewayApiStatusUpdate {
        api_version: "gateway.networking.k8s.io/v1".to_string(),
        kind: kind.to_string(),
        namespace: namespace.to_string(),
        name: name.to_string(),
        status: json!({
            "conditions": [{
                "type": "Accepted",
                "status": "True",
                "observedGeneration": 1,
                "reason": "Accepted",
                "message": "Ferrum accepted this object",
                "lastTransitionTime": "2026-08-28T00:00:00Z"
            }]
        }),
        patch_gateway_addresses: false,
        patch_gateway_listeners: false,
    }
}

fn assert_ssa_identity(patch: &Value, kind: &str, name: &str, namespace: Option<&str>, rv: &str) {
    assert_eq!(patch["kind"].as_str(), Some(kind));
    assert_eq!(patch["metadata"]["name"].as_str(), Some(name));
    match namespace {
        Some(namespace) => {
            assert_eq!(patch["metadata"]["namespace"].as_str(), Some(namespace));
        }
        None => {
            assert!(
                patch["metadata"].get("namespace").is_none(),
                "cluster-scoped apply documents must omit metadata.namespace"
            );
        }
    }
    assert_eq!(
        patch["metadata"]["resourceVersion"].as_str(),
        Some(rv),
        "{kind} SSA status apply must copy the live resourceVersion exactly"
    );
}

#[test]
fn cluster_scoped_gatewayclass_apply_carries_live_resource_version() {
    let patch =
        gateway_status_apply_patch_for_update(&update("GatewayClass", "", "ferrum"), None, "101")
            .expect("non-empty resourceVersion must produce an apply document");

    assert_ssa_identity(&patch, "GatewayClass", "ferrum", None, "101");
}

#[test]
fn namespaced_gateway_apply_carries_live_resource_version() {
    let patch =
        gateway_status_apply_patch_for_update(&update("Gateway", "default", "edge"), None, "202")
            .expect("non-empty resourceVersion must produce an apply document");

    assert_ssa_identity(&patch, "Gateway", "edge", Some("default"), "202");
}

#[test]
fn namespaced_listenerset_apply_carries_live_resource_version() {
    let patch = gateway_status_apply_patch_for_update(
        &update("ListenerSet", "default", "extra"),
        None,
        "303",
    )
    .expect("non-empty resourceVersion must produce an apply document");

    assert_ssa_identity(&patch, "ListenerSet", "extra", Some("default"), "303");
}

#[test]
fn missing_resource_version_cannot_produce_an_unguarded_status_write() {
    assert!(
        gateway_status_apply_patch_for_update(&update("Gateway", "default", "edge"), None, "")
            .is_none(),
        "an empty resourceVersion must not emit an SSA status document"
    );
    assert!(
        gateway_status_apply_patch_for_update(&update("GatewayClass", "", "ferrum"), None, "")
            .is_none(),
        "cluster-scoped kinds must fail closed the same way"
    );
    assert!(
        gateway_status_apply_patch_for_update(&update("ListenerSet", "default", "extra"), None, "")
            .is_none(),
        "namespaced kinds must fail closed the same way"
    );
}

fn api_error(code: u16, reason: &str) -> kube::Error {
    let mut status = kube::core::Status::failure("synthetic status error", reason);
    status.code = code;
    kube::Error::Api(status.boxed())
}

#[test]
fn deleted_status_target_is_terminal_but_other_api_errors_retry() {
    assert!(gateway_api_status_error_is_not_found(&api_error(
        404, "NotFound"
    )));
    assert!(!gateway_api_status_error_is_not_found(&api_error(
        409, "Conflict"
    )));
    assert!(!gateway_api_status_error_is_not_found(&api_error(
        504, "Timeout"
    )));
}
