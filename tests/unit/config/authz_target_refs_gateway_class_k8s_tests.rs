//! External K8s translation regression for AuthorizationPolicy GatewayClass
//! `targetRefs`: a supported waypoint class name alone must not accept when
//! the cluster-scoped GatewayClass object is absent (fail closed; issue #3226).

use std::collections::HashMap;

use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use serde_json::{Value, json};

fn options_root(ns: &str) -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        ns.to_string(),
        TrustDomain::new("cluster.local").expect("test trust domain"),
    )
    .with_istio_root_namespace(ns.to_string())
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
