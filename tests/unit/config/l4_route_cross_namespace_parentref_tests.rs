//! Cross-namespace parentRefs for TCPRoute and TLSRoute (issue #3269).
//!
//! Contract: L4 attachment uses the same Gateway listener AllowedRoutes
//! namespace/kind gates as HTTPRoute. ReferenceGrant authorizes backendRefs
//! only — not parentRefs. Missing or unauthorized parents fail closed with
//! field-specific diagnostics; authorized parents materialize stream proxies
//! in the parent Gateway namespace and record exact status.ancestors ownership.

use std::collections::HashMap;

use ferrum_edge::config::types::BackendScheme;
use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
    translate_k8s_objects_collecting_skips,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::k8s_controller::status::plan_gateway_api_status_updates;
use serde_json::{Value, json};

fn options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("trust domain"),
    )
    .with_source_namespaces(vec!["apps".to_string(), "infra".to_string()])
}

fn object(kind: &str, name: &str, namespace: &str, spec: Value) -> K8sObject {
    let api_version = match kind {
        "TCPRoute" | "TLSRoute" => "gateway.networking.k8s.io/v1alpha2",
        _ => "gateway.networking.k8s.io/v1",
    };
    K8sObject {
        api_version: api_version.to_string(),
        kind: kind.to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            uid: String::new(),
            namespace: namespace.to_string(),
            generation: Some(1),
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
        "",
        json!({ "controllerName": "ferrum.io/gateway-controller" }),
    )
}

fn tcp_gateway(allowed_from: &str) -> K8sObject {
    object(
        "Gateway",
        "edge",
        "infra",
        json!({
            "gatewayClassName": "ferrum",
            "listeners": [{
                "name": "tcp",
                "port": 15432,
                "protocol": "TCP",
                "allowedRoutes": {
                    "namespaces": {"from": allowed_from},
                    "kinds": [{"kind": "TCPRoute"}]
                }
            }]
        }),
    )
}

fn tls_gateway(allowed_from: &str) -> K8sObject {
    object(
        "Gateway",
        "edge",
        "infra",
        json!({
            "gatewayClassName": "ferrum",
            "listeners": [{
                "name": "tls",
                "port": 15443,
                "protocol": "TLS",
                "tls": {"mode": "Passthrough"},
                "allowedRoutes": {
                    "namespaces": {"from": allowed_from},
                    "kinds": [{"kind": "TLSRoute"}]
                }
            }]
        }),
    )
}

fn find_condition<'a>(conditions: &'a [Value], condition_type: &str) -> &'a Value {
    conditions
        .iter()
        .find(|condition| condition["type"].as_str() == Some(condition_type))
        .unwrap_or_else(|| panic!("missing condition {condition_type}"))
}

#[test]
fn tcp_route_cross_namespace_parent_ref_materializes_in_gateway_namespace() {
    let route = object(
        "TCPRoute",
        "db",
        "apps",
        json!({
            "parentRefs": [{
                "name": "edge",
                "namespace": "infra",
                "sectionName": "tcp"
            }],
            "rules": [{"backendRefs": [{"name": "db", "port": 5432}]}]
        }),
    );

    let result = translate_k8s_objects(&[tcp_gateway("All"), route], options())
        .expect("All-namespaces TCP listener must admit cross-namespace parentRef");

    assert_eq!(result.config.proxies.len(), 1);
    let proxy = &result.config.proxies[0];
    assert_eq!(proxy.namespace, "infra");
    assert_eq!(proxy.listen_port, Some(15432));
    assert_eq!(proxy.backend_host, "db.apps.svc.cluster.local");
    assert_eq!(proxy.backend_scheme, Some(BackendScheme::Tcp));
    assert!(result.materialized_route_parents.iter().any(|parent| {
        parent.route.namespace == "apps"
            && parent.route.name == "db"
            && parent.parent_ref == "gateway.networking.k8s.io/Gateway/infra/edge/tcp/*"
    }));
}

#[test]
fn weighted_tcp_route_cross_namespace_parent_keeps_first_backend_behavior() {
    let route = object(
        "TCPRoute",
        "weighted-db",
        "apps",
        json!({
            "parentRefs": [{
                "name": "edge",
                "namespace": "infra",
                "sectionName": "tcp"
            }],
            "rules": [{
                "backendRefs": [
                    {"name": "db-primary", "port": 5432, "weight": 90},
                    {"name": "db-canary", "port": 5432, "weight": 10}
                ]
            }]
        }),
    );

    let result = translate_k8s_objects(&[tcp_gateway("All"), route], options())
        .expect("weighted cross-namespace parentRef must materialize");

    assert_eq!(result.config.proxies.len(), 1);
    assert!(result.config.upstreams.is_empty());
    let proxy = &result.config.proxies[0];
    assert_eq!(proxy.namespace, "infra");
    assert_eq!(proxy.backend_host, "db-primary.apps.svc.cluster.local");
    assert_eq!(proxy.backend_port, 5432);
    assert!(proxy.upstream_id.is_none());
}

#[test]
fn tls_route_cross_namespace_parent_ref_materializes_when_allowed() {
    let route = object(
        "TLSRoute",
        "secure-db",
        "apps",
        json!({
            "hostnames": ["db.example.com"],
            "parentRefs": [{
                "name": "edge",
                "namespace": "infra",
                "sectionName": "tls"
            }],
            "rules": [{"backendRefs": [{"name": "db", "port": 5432}]}]
        }),
    );

    let result = translate_k8s_objects(&[tls_gateway("All"), route], options())
        .expect("All-namespaces TLS listener must admit cross-namespace parentRef");

    assert_eq!(result.config.proxies.len(), 1);
    let proxy = &result.config.proxies[0];
    assert_eq!(proxy.namespace, "infra");
    assert_eq!(proxy.listen_port, Some(15443));
    assert_eq!(proxy.backend_scheme, Some(BackendScheme::Tcp));
    assert!(
        proxy.passthrough,
        "TLSRoute must preserve encrypted bytes for SNI passthrough"
    );
    assert!(
        !proxy.frontend_tls,
        "TLSRoute passthrough must not terminate frontend TLS"
    );
    assert_eq!(proxy.hosts, vec!["db.example.com".to_string()]);
}

#[test]
fn l4_route_same_namespace_parent_ref_still_requires_listener_allowance() {
    let gateway = object(
        "Gateway",
        "edge",
        "apps",
        json!({
            "gatewayClassName": "ferrum",
            "listeners": [{
                "name": "tcp",
                "port": 15432,
                "protocol": "TCP",
                "allowedRoutes": {
                    "namespaces": {"from": "Same"},
                    "kinds": [{"kind": "TCPRoute"}]
                }
            }]
        }),
    );
    let route = object(
        "TCPRoute",
        "db",
        "apps",
        json!({
            "parentRefs": [{"name": "edge", "sectionName": "tcp"}],
            "rules": [{"backendRefs": [{"name": "db", "port": 5432}]}]
        }),
    );

    let result = translate_k8s_objects(
        &[gateway, route],
        options().with_source_namespaces(vec!["apps".to_string()]),
    )
    .expect("same-namespace TCPRoute must keep attaching under Same");

    assert_eq!(result.config.proxies.len(), 1);
    assert_eq!(result.config.proxies[0].namespace, "apps");
    assert_eq!(result.config.proxies[0].listen_port, Some(15432));
}

#[test]
fn l4_route_rejects_cross_namespace_parent_ref_when_listener_is_same_only() {
    let route = object(
        "TCPRoute",
        "db",
        "apps",
        json!({
            "parentRefs": [{
                "name": "edge",
                "namespace": "infra",
                "sectionName": "tcp"
            }],
            "rules": [{"backendRefs": [{"name": "db", "port": 5432}]}]
        }),
    );

    let err = translate_k8s_objects(&[tcp_gateway("Same"), route], options())
        .expect_err("Same-only listener must fail closed");

    assert!(
        err.to_string()
            .contains("not permitted by the target Gateway listener"),
        "{err}"
    );
}

#[test]
fn l4_route_rejects_unknown_section_name_with_field_specific_diagnostic() {
    let route = object(
        "TCPRoute",
        "db",
        "apps",
        json!({
            "parentRefs": [{
                "name": "edge",
                "namespace": "infra",
                "sectionName": "missing"
            }],
            "rules": [{"backendRefs": [{"name": "db", "port": 5432}]}]
        }),
    );

    let err = translate_k8s_objects(&[tcp_gateway("All"), route], options())
        .expect_err("unknown sectionName must fail closed");

    assert!(
        err.to_string()
            .contains("does not match any known Gateway listener"),
        "{err}"
    );
}

#[test]
fn l4_route_materializes_for_each_allowed_parent_gateway_namespace() {
    let gateway_a = object(
        "Gateway",
        "edge",
        "infra",
        json!({
            "gatewayClassName": "ferrum",
            "listeners": [{
                "name": "tcp",
                "port": 15432,
                "protocol": "TCP",
                "allowedRoutes": {
                    "namespaces": {"from": "All"},
                    "kinds": [{"kind": "TCPRoute"}]
                }
            }]
        }),
    );
    let gateway_b = object(
        "Gateway",
        "edge",
        "apps",
        json!({
            "gatewayClassName": "ferrum",
            "listeners": [{
                "name": "tcp",
                "port": 15433,
                "protocol": "TCP",
                "allowedRoutes": {
                    "namespaces": {"from": "Same"},
                    "kinds": [{"kind": "TCPRoute"}]
                }
            }]
        }),
    );
    let route = object(
        "TCPRoute",
        "db",
        "apps",
        json!({
            "parentRefs": [
                {"name": "edge", "namespace": "infra", "sectionName": "tcp"},
                {"name": "edge", "sectionName": "tcp"}
            ],
            "rules": [{"backendRefs": [{"name": "db", "port": 5432}]}]
        }),
    );

    let result = translate_k8s_objects(&[gateway_a, gateway_b, route], options())
        .expect("route should attach to each allowed parent namespace");

    let mut namespaces: Vec<_> = result
        .config
        .proxies
        .iter()
        .map(|proxy| (proxy.namespace.as_str(), proxy.listen_port))
        .collect();
    namespaces.sort();
    assert_eq!(
        namespaces,
        vec![("apps", Some(15433)), ("infra", Some(15432))]
    );
    assert_ne!(result.config.proxies[0].id, result.config.proxies[1].id);
}

#[test]
fn l4_route_withdraws_when_allowed_routes_tighten_on_reload() {
    let route = object(
        "TCPRoute",
        "db",
        "apps",
        json!({
            "parentRefs": [{
                "name": "edge",
                "namespace": "infra",
                "sectionName": "tcp"
            }],
            "rules": [{"backendRefs": [{"name": "db", "port": 5432}]}]
        }),
    );

    let created = translate_k8s_objects(&[tcp_gateway("All"), route.clone()], options())
        .expect("create under All");
    assert_eq!(created.config.proxies.len(), 1);

    let (withdrawn, skipped) =
        translate_k8s_objects_collecting_skips(&[tcp_gateway("Same"), route], options())
            .expect("reload under Same must collect skip rather than crash");
    assert!(
        withdrawn.config.proxies.is_empty(),
        "tightened AllowedRoutes must withdraw the prior L4 proxy"
    );
    assert!(
        skipped.values().any(|error| {
            error
                .to_string()
                .contains("not permitted by the target Gateway listener")
        }),
        "skip diagnostics: {skipped:?}"
    );
}

#[test]
fn l4_route_delete_withdraws_materialized_stream_proxy() {
    let route = object(
        "TCPRoute",
        "db",
        "apps",
        json!({
            "parentRefs": [{
                "name": "edge",
                "namespace": "infra",
                "sectionName": "tcp"
            }],
            "rules": [{"backendRefs": [{"name": "db", "port": 5432}]}]
        }),
    );

    let created = translate_k8s_objects(&[tcp_gateway("All"), route], options()).expect("create");
    assert_eq!(created.config.proxies.len(), 1);

    let deleted = translate_k8s_objects(&[tcp_gateway("All")], options()).expect("delete route");
    assert!(
        deleted.config.proxies.is_empty(),
        "deleting the TCPRoute must withdraw its stream proxy"
    );
    assert!(deleted.materialized_route_parents.is_empty());
}

#[test]
fn tcp_route_status_reports_not_allowed_by_listeners_for_cross_namespace_parent_ref() {
    let route = object(
        "TCPRoute",
        "db",
        "apps",
        json!({
            "parentRefs": [{
                "group": "gateway.networking.k8s.io",
                "kind": "Gateway",
                "name": "edge",
                "namespace": "infra",
                "sectionName": "tcp"
            }],
            "rules": [{"backendRefs": [{"name": "db", "port": 5432}]}]
        }),
    );
    let objects = vec![gateway_class(), tcp_gateway("Same"), route];
    let updates = plan_gateway_api_status_updates(&objects, options(), &[]);

    let route_update = updates
        .iter()
        .find(|update| update.kind == "TCPRoute" && update.name == "db")
        .expect("TCPRoute status update");
    let parents = route_update.status["parents"]
        .as_array()
        .expect("parents array");
    assert_eq!(parents.len(), 1);
    assert_eq!(parents[0]["parentRef"]["namespace"].as_str(), Some("infra"));
    let conditions = parents[0]["conditions"].as_array().expect("conditions");
    assert_eq!(
        find_condition(conditions, "Accepted")["status"].as_str(),
        Some("False")
    );
    assert_eq!(
        find_condition(conditions, "Accepted")["reason"].as_str(),
        Some("NotAllowedByListeners")
    );
    assert_eq!(
        find_condition(conditions, "ResolvedRefs")["status"].as_str(),
        Some("True")
    );
    assert_eq!(
        find_condition(conditions, "Programmed")["status"].as_str(),
        Some("False")
    );
}

#[test]
fn tcp_route_status_reports_programmed_for_authorized_cross_namespace_parent_ref() {
    let route = object(
        "TCPRoute",
        "db",
        "apps",
        json!({
            "parentRefs": [{
                "group": "gateway.networking.k8s.io",
                "kind": "Gateway",
                "name": "edge",
                "namespace": "infra",
                "sectionName": "tcp"
            }],
            "rules": [{"backendRefs": [{"name": "db", "port": 5432}]}]
        }),
    );
    let objects = vec![gateway_class(), tcp_gateway("All"), route];
    let updates = plan_gateway_api_status_updates(&objects, options(), &[]);

    let route_update = updates
        .iter()
        .find(|update| update.kind == "TCPRoute" && update.name == "db")
        .expect("TCPRoute status update");
    let parents = route_update.status["parents"]
        .as_array()
        .expect("parents array");
    assert_eq!(parents.len(), 1);
    assert_eq!(
        parents[0]["controllerName"].as_str(),
        Some("ferrum.io/gateway-controller")
    );
    assert_eq!(parents[0]["parentRef"]["namespace"].as_str(), Some("infra"));
    assert_eq!(parents[0]["parentRef"]["sectionName"].as_str(), Some("tcp"));
    let conditions = parents[0]["conditions"].as_array().expect("conditions");
    assert_eq!(
        find_condition(conditions, "Accepted")["status"].as_str(),
        Some("True")
    );
    assert_eq!(
        find_condition(conditions, "ResolvedRefs")["status"].as_str(),
        Some("True")
    );
    assert_eq!(
        find_condition(conditions, "Programmed")["status"].as_str(),
        Some("True")
    );
}
