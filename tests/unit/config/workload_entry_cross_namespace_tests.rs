//! Cross-namespace WorkloadEntry → Service attachment (issue #3244).
//!
//! Contract: a WorkloadEntry whose `spec.service` host resolves to a Service in
//! another namespace attaches only when a Gateway API ReferenceGrant in the
//! *target* Service namespace permits WorkloadEntry → Service and the Service
//! exists in the translated inventory. Same-namespace hosts keep prior
//! behavior. Missing, unauthorized, or stale targets fail closed.

use std::collections::HashMap;

use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use serde_json::{Value, json};

fn options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("trust domain"),
    )
    .with_source_namespaces(Vec::new())
    .with_pod_discovery_enabled(true)
}

fn object(api_version: &str, kind: &str, name: &str, namespace: &str, spec: Value) -> K8sObject {
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

fn service(name: &str, namespace: &str) -> K8sObject {
    object(
        "v1",
        "Service",
        name,
        namespace,
        json!({ "ports": [{ "port": 9080, "name": "http", "targetPort": 9080 }] }),
    )
}

fn reference_grant(from_namespace: &str, to_namespace: &str, service_name: &str) -> K8sObject {
    object(
        "gateway.networking.k8s.io/v1beta1",
        "ReferenceGrant",
        "allow-we",
        to_namespace,
        json!({
            "from": [{
                "group": "networking.istio.io",
                "kind": "WorkloadEntry",
                "namespace": from_namespace
            }],
            "to": [{
                "group": "",
                "kind": "Service",
                "name": service_name
            }]
        }),
    )
}

fn workload_entry(namespace: &str, service_host: &str, address: &str) -> K8sObject {
    object(
        "networking.istio.io/v1",
        "WorkloadEntry",
        "vm-reviews",
        namespace,
        json!({
            "address": address,
            "serviceAccount": "reviews-vm",
            "service": service_host,
            "ports": { "http": 9080 }
        }),
    )
}

#[test]
fn same_namespace_workload_entry_still_attaches_without_reference_grant() {
    let result = translate_k8s_objects(
        &[
            service("reviews", "default"),
            workload_entry("default", "reviews", "10.2.0.9"),
        ],
        options(),
    )
    .expect("same-namespace WorkloadEntry must remain valid without a ReferenceGrant");

    let mesh = result.config.mesh.expect("mesh");
    let workload = mesh
        .workloads
        .iter()
        .find(|workload| workload.addresses.iter().any(|a| a == "10.2.0.9"))
        .expect("workload");
    assert_eq!(workload.service_name, "reviews");
    assert_eq!(workload.service_namespace, None);
    assert_eq!(workload.attached_service_namespace(), "default");
    let service = mesh
        .services
        .iter()
        .find(|service| service.namespace == "default" && service.name == "reviews")
        .expect("service");
    assert!(
        service
            .workloads
            .iter()
            .any(|reference| reference.spiffe_id == workload.spiffe_id)
    );
}

#[test]
fn cross_namespace_workload_entry_attaches_only_to_granted_service() {
    let result = translate_k8s_objects(
        &[
            service("reviews", "prod"),
            service("reviews", "default"),
            reference_grant("vms", "prod", "reviews"),
            workload_entry("vms", "reviews.prod.svc.cluster.local", "10.9.0.5"),
        ],
        options(),
    )
    .expect("authorized cross-namespace WorkloadEntry");

    let mesh = result.config.mesh.expect("mesh");
    let workload = mesh
        .workloads
        .iter()
        .find(|workload| workload.addresses.iter().any(|a| a == "10.9.0.5"))
        .expect("workload");
    assert_eq!(workload.namespace, "vms");
    assert_eq!(workload.service_namespace.as_deref(), Some("prod"));
    assert_eq!(
        workload.spiffe_id.as_str(),
        "spiffe://cluster.local/ns/vms/sa/reviews-vm"
    );

    let prod = mesh
        .services
        .iter()
        .find(|service| service.namespace == "prod" && service.name == "reviews")
        .expect("prod service");
    assert_eq!(prod.workloads.len(), 1);
    assert_eq!(prod.workloads[0].spiffe_id, workload.spiffe_id);

    let local = mesh
        .services
        .iter()
        .find(|service| service.namespace == "default" && service.name == "reviews")
        .expect("default service");
    assert!(
        local.workloads.is_empty(),
        "must not attach to an unintended same-name Service"
    );
}

#[test]
fn cross_namespace_workload_entry_without_grant_is_rejected() {
    let err = translate_k8s_objects(
        &[
            service("reviews", "prod"),
            workload_entry("vms", "reviews.prod.svc.cluster.local", "10.9.0.5"),
        ],
        options(),
    )
    .expect_err("missing ReferenceGrant must fail closed");
    let err = err.to_string();
    assert!(err.contains("ReferenceGrant"), "{err}");
    assert!(err.contains("cross-namespace"), "{err}");
}

#[test]
fn cross_namespace_workload_entry_with_grant_but_missing_service_is_rejected() {
    let err = translate_k8s_objects(
        &[
            reference_grant("vms", "prod", "reviews"),
            workload_entry("vms", "reviews.prod.svc.cluster.local", "10.9.0.5"),
        ],
        options(),
    )
    .expect_err("missing Service must fail closed");
    assert!(
        err.to_string()
            .contains("not present in the translated inventory"),
        "{err}"
    );
}

#[test]
fn cross_namespace_workload_entry_delete_withdraws_service_attachment() {
    let objects_with_we = [
        service("reviews", "prod"),
        reference_grant("vms", "prod", "reviews"),
        workload_entry("vms", "reviews.prod.svc.cluster.local", "10.9.0.5"),
    ];
    let created = translate_k8s_objects(&objects_with_we, options()).expect("create");
    let mesh = created.config.mesh.as_ref().expect("mesh");
    assert_eq!(
        mesh.services
            .iter()
            .find(|service| service.namespace == "prod" && service.name == "reviews")
            .expect("service")
            .workloads
            .len(),
        1
    );

    let withdrawn = translate_k8s_objects(
        &[
            service("reviews", "prod"),
            reference_grant("vms", "prod", "reviews"),
        ],
        options(),
    )
    .expect("delete");
    let mesh = withdrawn.config.mesh.expect("mesh");
    assert!(
        mesh.workloads
            .iter()
            .all(|workload| !workload.addresses.iter().any(|a| a == "10.9.0.5"))
    );
    assert!(
        mesh.services
            .iter()
            .find(|service| service.namespace == "prod" && service.name == "reviews")
            .expect("service")
            .workloads
            .is_empty()
    );
}
