//! Gateway API `UDPRoute` translation, admission, and status coverage (#3275).
//!
//! A `UDPRoute` carries no request-level predicate, so the Gateway listener
//! port is the entire match and the rule's `backendRefs` entry is the datagram
//! peer. These tests pin the strict admission boundaries (backendRef port,
//! backend kind, ReferenceGrant, namespace, listener protocol/kind) and the
//! reload/delete behavior, not only first-start construction.

use ferrum_edge::config::types::BackendScheme;
use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::k8s_controller::status::{
    FERRUM_GATEWAY_CONTROLLER_NAME, GatewayApiStatusUpdate, plan_gateway_api_status_updates,
};
use serde_json::{Value, json};
use std::collections::HashMap;

const GATEWAY_API_SRC: &str = include_str!("../../../src/config_sources/k8s/gateway_api.rs");
const WATCHER_SRC: &str = include_str!("../../../src/k8s_controller/watcher.rs");
const STATUS_SRC: &str = include_str!("../../../src/k8s_controller/status.rs");

fn options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("test trust domain"),
    )
}

fn multi_namespace_options() -> K8sTranslationOptions {
    let namespaces = vec!["default".to_string(), "backends".to_string()];
    options().with_source_namespaces(namespaces)
}

fn object_in(kind: &str, version: &str, namespace: &str, name: &str, spec: Value) -> K8sObject {
    K8sObject {
        api_version: version.to_string(),
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

fn udp_route(name: &str, spec: Value) -> K8sObject {
    let version = "gateway.networking.k8s.io/v1alpha2";
    object_in("UDPRoute", version, "default", name, spec)
}

fn gateway_class() -> K8sObject {
    let spec = json!({"controllerName": FERRUM_GATEWAY_CONTROLLER_NAME});
    let version = "gateway.networking.k8s.io/v1";
    object_in("GatewayClass", version, "", "ferrum", spec)
}

/// A Ferrum-managed Gateway with one UDP listener on `port`.
fn udp_gateway(name: &str, listener: &str, port: u16) -> K8sObject {
    let spec = json!({
        "gatewayClassName": "ferrum",
        "listeners": [{
            "name": listener,
            "port": port,
            "protocol": "UDP",
            "allowedRoutes": {
                "kinds": [{"kind": "UDPRoute"}],
                "namespaces": {"from": "Same"}
            }
        }]
    });
    let version = "gateway.networking.k8s.io/v1";
    object_in("Gateway", version, "default", name, spec)
}

fn service(namespace: &str, name: &str, port: u16) -> K8sObject {
    let spec = json!({
        "ports": [{"name": "udp", "protocol": "UDP", "port": port, "targetPort": port}]
    });
    object_in("Service", "v1", namespace, name, spec)
}

fn simple_rule(backend: &str, port: u16) -> Value {
    json!({"rules": [{"backendRefs": [{"name": backend, "port": port}]}]})
}

fn attached_rule(parent: &str, section: &str, backend: &str, port: u16) -> Value {
    json!({
        "parentRefs": [{"name": parent, "sectionName": section}],
        "rules": [{"backendRefs": [{"name": backend, "port": port}]}]
    })
}

fn cross_namespace_rule(backend: &str, namespace: &str, port: u16) -> Value {
    json!({
        "rules": [{"backendRefs": [{
            "name": backend,
            "namespace": namespace,
            "port": port
        }]}]
    })
}

fn reference_grant(name: &str, from_kind: &str) -> K8sObject {
    let spec = json!({
        "from": [{
            "group": "gateway.networking.k8s.io",
            "kind": from_kind,
            "namespace": "default"
        }],
        "to": [{"group": "", "kind": "Service", "name": "coredns"}]
    });
    let version = "gateway.networking.k8s.io/v1beta1";
    object_in("ReferenceGrant", version, "backends", name, spec)
}

fn route_condition(
    updates: &[GatewayApiStatusUpdate],
    name: &str,
    condition: &str,
) -> Option<String> {
    let update = updates
        .iter()
        .find(|update| update.kind == "UDPRoute" && update.name == name)?;
    update
        .status
        .get("parents")?
        .as_array()?
        .iter()
        .filter_map(|parent| parent.get("conditions")?.as_array())
        .flatten()
        .find(|entry| entry.get("type").and_then(Value::as_str) == Some(condition))
        .and_then(|entry| entry.get("status").and_then(Value::as_str))
        .map(ToOwned::to_owned)
}

#[test]
fn udp_route_materializes_udp_stream_proxy_on_listener_port() {
    let route = udp_route("dns", attached_rule("edge", "dns", "coredns", 5353));
    let objects = [gateway_class(), udp_gateway("edge", "dns", 15353), route];

    let translated = translate_k8s_objects(&objects, options());
    let result = translated.expect("translation succeeds");

    assert_eq!(result.config.proxies.len(), 1);
    let proxy = &result.config.proxies[0];
    assert_eq!(proxy.backend_scheme, Some(BackendScheme::Udp));
    assert_eq!(proxy.listen_port, Some(15353));
    assert_eq!(proxy.backend_port, 5353);
    assert_eq!(proxy.backend_host, "coredns.default.svc.cluster.local");
    // Datagram semantics: no listen path, no host predicate, per-session idle.
    assert_eq!(proxy.listen_path, None);
    assert!(proxy.hosts.is_empty());
    assert!(proxy.udp_idle_timeout_seconds > 0);
}

#[test]
fn udp_route_without_materialized_listener_falls_back_to_backend_port() {
    let objects = [udp_route("dns", simple_rule("coredns", 5353))];

    let translated = translate_k8s_objects(&objects, options());
    let result = translated.expect("translation succeeds");

    assert_eq!(result.config.proxies.len(), 1);
    let proxy = &result.config.proxies[0];
    assert_eq!(proxy.listen_port, Some(5353));
    assert_eq!(proxy.backend_scheme, Some(BackendScheme::Udp));
}

#[test]
fn udp_route_backend_port_is_required() {
    let spec = json!({"rules": [{"backendRefs": [{"name": "coredns"}]}]});
    let objects = [udp_route("dns", spec)];

    let translated = translate_k8s_objects(&objects, options());
    let err = translated.expect_err("a portless backendRef fails closed");

    assert!(err.to_string().contains("UDPRoute backendRefs[].port"));
    assert!(err.to_string().contains("is required"));
}

#[test]
fn udp_route_backend_port_zero_fails_closed() {
    let objects = [udp_route("dns", simple_rule("coredns", 0))];

    let translated = translate_k8s_objects(&objects, options());
    let err = translated.expect_err("port 0 fails closed");

    assert!(err.to_string().contains("UDPRoute backendRefs[].port"));
}

#[test]
fn udp_route_backend_port_above_kubernetes_range_fails_closed() {
    let spec = json!({"rules": [{"backendRefs": [{"name": "dns", "port": 70000}]}]});
    let objects = [udp_route("dns", spec)];

    let translated = translate_k8s_objects(&objects, options());
    let err = translated.expect_err("port 70000 fails closed");

    assert!(err.to_string().contains("UDPRoute backendRefs[].port"));
    assert!(err.to_string().contains("70000"));
}

#[test]
fn udp_route_rejects_non_service_backend_kind() {
    let spec = json!({
        "rules": [{"backendRefs": [{
            "group": "example.com",
            "kind": "DatagramSink",
            "name": "sink",
            "port": 5353
        }]}]
    });
    let objects = [udp_route("dns", spec)];

    let translated = translate_k8s_objects(&objects, options());
    let err = translated.expect_err("only core Service backends");

    assert!(err.to_string().contains("only core Service backendRefs"));
}

#[test]
fn udp_route_hostnames_are_rejected_fail_closed() {
    // Gateway API defines no `hostnames` on UDPRoute, and a datagram carries no
    // name to match on. Accepting one would materialize an inert selector.
    let spec = json!({
        "hostnames": ["dns.example.com"],
        "rules": [{"backendRefs": [{"name": "coredns", "port": 5353}]}]
    });
    let objects = [udp_route("dns", spec)];

    let translated = translate_k8s_objects(&objects, options());
    let err = translated.expect_err("UDPRoute hostnames fail closed");

    assert!(err.to_string().contains("UDPRoute spec.hostnames"));
}

#[test]
fn udp_route_cross_namespace_backend_ref_requires_reference_grant() {
    let spec = cross_namespace_rule("coredns", "backends", 5353);
    let ungranted = [udp_route("dns", spec.clone())];

    let translated = translate_k8s_objects(&ungranted, multi_namespace_options());
    let err = translated.expect_err("an ungranted cross-namespace ref fails");

    assert!(err.to_string().contains("requires a matching ReferenceGrant"));

    let grant = reference_grant("allow-udproute", "UDPRoute");
    let granted = [udp_route("dns", spec), grant];

    let translated = translate_k8s_objects(&granted, multi_namespace_options());
    let result = translated.expect("a matching grant authorizes the ref");

    assert_eq!(
        result.config.proxies[0].backend_host,
        "coredns.backends.svc.cluster.local"
    );
}

#[test]
fn udp_route_reference_grant_for_another_kind_does_not_authorize() {
    let spec = cross_namespace_rule("coredns", "backends", 5353);
    let grant = reference_grant("allow-tcproute-only", "TCPRoute");
    let objects = [udp_route("dns", spec), grant];

    let translated = translate_k8s_objects(&objects, multi_namespace_options());
    let err = translated.expect_err("a TCPRoute grant is not a UDPRoute grant");

    assert!(err.to_string().contains("requires a matching ReferenceGrant"));
}

#[test]
fn udp_route_rejects_cross_namespace_parent_ref() {
    let mut gateway = udp_gateway("edge", "dns", 15353);
    gateway.metadata.namespace = "backends".to_string();
    gateway.spec["listeners"][0]["allowedRoutes"]["namespaces"]["from"] = json!("All");
    let spec = json!({
        "parentRefs": [{"name": "edge", "namespace": "backends"}],
        "rules": [{"backendRefs": [{"name": "coredns", "port": 5353}]}]
    });
    let objects = [gateway_class(), gateway, udp_route("dns", spec)];

    let translated = translate_k8s_objects(&objects, multi_namespace_options());
    let err = translated.expect_err("cross-namespace L4 parents fail closed");

    let message = err.to_string();
    assert!(message.contains("UDPRoute cross-namespace parentRefs"));
}

#[test]
fn udp_route_does_not_attach_to_a_tcp_listener() {
    let spec = json!({
        "gatewayClassName": "ferrum",
        "listeners": [{
            "name": "stream",
            "port": 15353,
            "protocol": "TCP",
            "allowedRoutes": {"kinds": [{"kind": "TCPRoute"}]}
        }]
    });
    let version = "gateway.networking.k8s.io/v1";
    let gateway = object_in("Gateway", version, "default", "edge", spec);
    let route = udp_route("dns", attached_rule("edge", "stream", "coredns", 5353));
    let objects = [gateway_class(), gateway, route];

    let translated = translate_k8s_objects(&objects, options());
    let err = translated.expect_err("a UDP route needs a UDP listener");

    assert!(err.to_string().contains("UDPRoute"));
}

#[test]
fn udp_route_rule_with_only_zero_weight_backends_materializes_nothing() {
    let spec = json!({
        "rules": [{"backendRefs": [{
            "name": "coredns",
            "port": 5353,
            "weight": 0
        }]}]
    });
    let objects = [udp_route("dns", spec)];

    let translated = translate_k8s_objects(&objects, options());
    let result = translated.expect("a zero-weight-only rule is accepted");

    assert!(result.config.proxies.is_empty());
    let warned = result
        .warnings
        .iter()
        .any(|warning| warning.contains("UDPRoute") && warning.contains("zero-weight"));
    assert!(warned, "expected a warning, got {:?}", result.warnings);
}

#[test]
fn udp_route_update_and_delete_regenerate_live_config() {
    let gateway = udp_gateway("edge", "dns", 15353);
    let route = udp_route("dns", attached_rule("edge", "dns", "coredns-b", 5353));
    let updated_objects = [gateway_class(), gateway.clone(), route];

    let translated = translate_k8s_objects(&updated_objects, options());
    let updated = translated.expect("translation succeeds");

    assert_eq!(
        updated.config.proxies[0].backend_host,
        "coredns-b.default.svc.cluster.local"
    );

    // Deletion is modeled by the route leaving the snapshot: the listener must
    // not survive as an orphaned UDP proxy.
    let deleted_objects = [gateway_class(), gateway];
    let translated = translate_k8s_objects(&deleted_objects, options());
    let deleted = translated.expect("translation succeeds without the route");

    assert!(deleted.config.proxies.is_empty());
}

#[test]
fn udp_route_status_reports_accepted_resolved_and_programmed() {
    let route = udp_route("dns", attached_rule("edge", "dns", "coredns", 5353));
    let objects = [
        gateway_class(),
        udp_gateway("edge", "dns", 15353),
        service("default", "coredns", 5353),
        route,
    ];

    let updates = plan_gateway_api_status_updates(&objects, options(), &[]);

    assert_eq!(
        route_condition(&updates, "dns", "Accepted").as_deref(),
        Some("True")
    );
    assert_eq!(
        route_condition(&updates, "dns", "ResolvedRefs").as_deref(),
        Some("True")
    );
    assert_eq!(
        route_condition(&updates, "dns", "Programmed").as_deref(),
        Some("True")
    );

    let gateway_update = updates
        .iter()
        .find(|update| update.kind == "Gateway")
        .expect("Gateway status update");
    let supported: Vec<&str> = gateway_update.status["listeners"][0]["supportedKinds"]
        .as_array()
        .expect("supportedKinds")
        .iter()
        .filter_map(|kind| kind.get("kind").and_then(Value::as_str))
        .collect();
    assert_eq!(supported, vec!["UDPRoute"]);
}

#[test]
fn udp_route_status_reports_unresolved_missing_backend() {
    let route = udp_route("dns", attached_rule("edge", "dns", "absent", 5353));
    let objects = [
        gateway_class(),
        udp_gateway("edge", "dns", 15353),
        service("default", "coredns", 5353),
        route,
    ];

    let updates = plan_gateway_api_status_updates(&objects, options(), &[]);

    assert_eq!(
        route_condition(&updates, "dns", "ResolvedRefs").as_deref(),
        Some("False")
    );
}

#[test]
fn udproute_is_wired_through_watch_translation_and_status() {
    // The three surfaces a route kind needs; a partial wiring silently drops
    // UDPRoute back to "watched but inert".
    assert!(WATCHER_SRC.contains("plural: \"udproutes\""));
    assert!(GATEWAY_API_SRC.contains("\"UDPRoute\" => {"));
    assert!(GATEWAY_API_SRC.contains("\"UDP\" => vec![\"UDPRoute\"]"));
    assert!(STATUS_SRC.contains("(\"UDPRoute\", \"v1alpha2\") => \"udproutes\""));
}
