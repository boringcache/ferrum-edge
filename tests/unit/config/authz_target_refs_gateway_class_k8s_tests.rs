//! External K8s translation regressions for AuthorizationPolicy `targetRefs`
//! against the cluster-scoped / ordering-sensitive parts of the resource graph
//! (issue #3226):
//!
//! * a supported waypoint class NAME alone must not accept when the
//!   cluster-scoped `GatewayClass` object is absent (fail closed);
//! * a `GatewayClass` attachment must be owned by a root-namespace policy;
//! * a deleted target withdraws the policy fail-closed on the next reconcile;
//! * `targetRefs` → `Gateway` resolution must not depend on informer/list order
//!   relative to the AuthorizationPolicy (the waypoint-binding pre-pass).

use std::collections::HashMap;

use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::modes::mesh::config::{PolicyScope, PolicyTargetAttachment};
use serde_json::{Value, json};

fn options_root(ns: &str) -> K8sTranslationOptions {
    options_ns_root(ns, ns)
}

fn options_ns_root(ns: &str, root: &str) -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        ns.to_string(),
        TrustDomain::new("cluster.local").expect("test trust domain"),
    )
    .with_istio_root_namespace(root.to_string())
}

/// A cluster-scoped `GatewayClass` (empty namespace). Presence — not Ferrum
/// ownership — is what a `targetRefs` attachment requires, so the controller
/// name is caller-chosen.
fn gateway_class(name: &str, controller: &str) -> K8sObject {
    object(
        "GatewayClass",
        "gateway.networking.k8s.io/v1",
        name,
        "",
        json!({ "controllerName": controller }),
    )
}

fn waypoint_gateway(name: &str, namespace: &str, class: &str) -> K8sObject {
    object(
        "Gateway",
        "gateway.networking.k8s.io/v1",
        name,
        namespace,
        json!({
            "gatewayClassName": class,
            "listeners": [{"name": "mesh", "port": 15008, "protocol": "HBONE"}]
        }),
    )
}

fn object(kind: &str, api_version: &str, name: &str, namespace: &str, spec: Value) -> K8sObject {
    K8sObject {
        api_version: api_version.to_string(),
        kind: kind.to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            uid: String::new(),
            namespace: namespace.to_string(),
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

#[test]
fn gateway_class_target_ref_rejects_supported_name_when_object_absent() {
    // A waypoint Gateway whose gatewayClassName is a supported class is not
    // enough: the cluster-scoped GatewayClass object itself must exist.
    let err = translate_k8s_objects(
        &[
            object(
                "Gateway",
                "gateway.networking.k8s.io/v1",
                "waypoint",
                "istio-system",
                json!({
                    "gatewayClassName": "istio-waypoint",
                    "listeners": [{
                        "name": "mesh",
                        "port": 15008,
                        "protocol": "HBONE"
                    }]
                }),
            ),
            object(
                "AuthorizationPolicy",
                "security.istio.io/v1",
                "class-deny",
                "istio-system",
                json!({
                    "targetRefs": [{
                        "group": "gateway.networking.k8s.io",
                        "kind": "GatewayClass",
                        "name": "istio-waypoint"
                    }],
                    "action": "DENY",
                    "rules": [{
                        "from": [{"source": {"namespaces": ["evil"]}}]
                    }]
                }),
            ),
        ],
        options_root("istio-system"),
    )
    .expect_err("supported-name GatewayClass targetRef without the object must fail closed");

    let message = err.to_string();
    assert!(
        message.contains("was not found"),
        "missing GatewayClass must fail closed with not-found diagnostics: {message}"
    );
    assert!(
        message.contains("istio-waypoint"),
        "error should name the missing class: {message}"
    );
}

/// `GatewayClass` is cluster-scoped: only a policy in the Istio root namespace
/// may attach class-wide.
#[test]
fn gateway_class_target_ref_requires_root_namespace_owner() {
    let err = translate_k8s_objects(
        &[
            gateway_class("istio-waypoint", "istio.io/gateway-controller"),
            waypoint_gateway("waypoint", "default", "istio-waypoint"),
            object(
                "AuthorizationPolicy",
                "security.istio.io/v1",
                "class-deny",
                "default",
                json!({
                    "targetRefs": [{
                        "group": "gateway.networking.k8s.io",
                        "kind": "GatewayClass",
                        "name": "istio-waypoint"
                    }],
                    "rules": [{}]
                }),
            ),
        ],
        options_ns_root("default", "istio-system"),
    )
    .expect_err("a non-root-namespace GatewayClass attachment must fail closed");

    assert!(
        err.to_string().contains("root namespace"),
        "diagnostic must state the root-namespace rule: {err}"
    );
}

/// Reload withdrawal: when the target resource disappears from a later
/// translation batch, the targeted policy must be withdrawn fail-closed rather
/// than silently surviving with an unresolvable attachment.
#[test]
fn target_ref_is_withdrawn_when_its_target_is_deleted() {
    let service = object(
        "Service",
        "v1",
        "reviews",
        "default",
        json!({"selector": {"app": "reviews"}, "ports": [{"port": 9080}]}),
    );
    let policy = object(
        "AuthorizationPolicy",
        "security.istio.io/v1",
        "reviews-deny",
        "default",
        json!({
            "targetRefs": [{"kind": "Service", "name": "reviews"}],
            "action": "DENY",
            "rules": [{"from": [{"source": {"namespaces": ["evil"]}}]}]
        }),
    );

    let present = translate_k8s_objects(
        &[service, policy.clone()],
        options_ns_root("default", "istio-system"),
    )
    .expect("the policy translates while its Service exists");
    assert_eq!(
        present
            .config
            .mesh
            .expect("mesh config")
            .mesh_policies
            .len(),
        1
    );

    // Next reconcile: the Service is gone.
    let err = translate_k8s_objects(&[policy], options_ns_root("default", "istio-system"))
        .expect_err("a deleted target must withdraw the policy fail-closed");
    assert!(
        err.to_string().contains("was not found"),
        "withdrawal must be reported as a missing target, not silently accepted: {err}"
    );
}

/// Resolution must not depend on informer/list order: the waypoint-binding
/// pre-pass collects Gateways before Istio translation, so an
/// AuthorizationPolicy listed BEFORE its target Gateway still resolves.
#[test]
fn gateway_target_ref_resolves_regardless_of_object_order() {
    let policy = object(
        "AuthorizationPolicy",
        "security.istio.io/v1",
        "wp-deny",
        "default",
        json!({
            "targetRefs": [{
                "group": "gateway.networking.k8s.io",
                "kind": "Gateway",
                "name": "waypoint"
            }],
            "action": "DENY",
            "rules": [{"from": [{"source": {"namespaces": ["evil"]}}]}]
        }),
    );
    let gateway = waypoint_gateway("waypoint", "default", "istio-waypoint");

    for objects in [vec![policy.clone(), gateway.clone()], vec![gateway, policy]] {
        let result = translate_k8s_objects(&objects, options_ns_root("default", "istio-system"))
            .expect("Gateway targetRef resolves in either order");
        let mesh = result.config.mesh.expect("mesh config");
        assert!(
            matches!(
                &mesh.mesh_policies[0].scope,
                PolicyScope::TargetRefs { attachments }
                    if matches!(
                        &attachments[0],
                        PolicyTargetAttachment::Gateway { namespace, name }
                            if namespace == "default" && name == "waypoint"
                    )
            ),
            "expected a resolved Gateway attachment, got {:?}",
            mesh.mesh_policies[0].scope
        );
        assert_eq!(
            mesh.waypoint_bindings[0].gateway_class_name.as_deref(),
            Some("istio-waypoint"),
            "the binding must carry the authoritative gateway class"
        );
    }
}
