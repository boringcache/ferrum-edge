//! Gateway API `ListenerSet` translation, attachment, and status coverage (#3277).
//!
//! Pins allowedListeners gating, parentRef attachment, listener merge/conflict
//! precedence, HTTPRoute parentRef to ListenerSet materialization, status
//! parity (`Accepted`/`Programmed`/`Conflicted`, Gateway `attachedListenerSets`),
//! and update/delete withdrawal — not only first-start construction.

use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::k8s_controller::status::{
    FERRUM_GATEWAY_CONTROLLER_NAME, plan_gateway_api_status_updates,
};
use serde_json::{Value, json};
use std::collections::HashMap;

const WATCHER_SRC: &str = include_str!("../../../src/k8s_controller/watcher.rs");
const RBAC_SRC: &str =
    include_str!("../../../charts/ferrum-mesh/templates/control-plane-rbac.yaml");

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
            uid: format!("uid-{name}"),
            namespace: "default".to_string(),
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

fn gateway_class() -> K8sObject {
    object(
        "GatewayClass",
        "ferrum",
        json!({ "controllerName": FERRUM_GATEWAY_CONTROLLER_NAME }),
    )
}

fn http_gateway(name: &str, allowed_from: Option<&str>) -> K8sObject {
    let mut spec = json!({
        "gatewayClassName": "ferrum",
        "listeners": [{
            "name": "http",
            "port": 80,
            "protocol": "HTTP",
            "hostname": "gateway.example.com",
            "allowedRoutes": { "namespaces": { "from": "Same" } }
        }]
    });
    if let Some(from) = allowed_from {
        spec.as_object_mut().unwrap().insert(
            "allowedListeners".to_string(),
            json!({ "namespaces": { "from": from } }),
        );
    }
    object("Gateway", name, spec)
}

fn listenerset(name: &str, gateway: &str, listeners: Value) -> K8sObject {
    object(
        "ListenerSet",
        name,
        json!({
            "parentRef": {
                "group": "gateway.networking.k8s.io",
                "kind": "Gateway",
                "name": gateway,
                "namespace": "default"
            },
            "listeners": listeners
        }),
    )
}

fn http_route(name: &str, parent_refs: Value, hostname: &str, path: &str) -> K8sObject {
    object(
        "HTTPRoute",
        name,
        json!({
            "parentRefs": parent_refs,
            "hostnames": [hostname],
            "rules": [{
                "matches": [{ "path": { "type": "PathPrefix", "value": path } }],
                "backendRefs": [{ "name": "backend", "port": 8080 }]
            }]
        }),
    )
}

fn service(name: &str) -> K8sObject {
    let mut svc = object(
        "Service",
        name,
        json!({
            "ports": [{ "port": 8080, "protocol": "TCP" }]
        }),
    );
    svc.api_version = "v1".to_string();
    svc
}

#[test]
fn watcher_and_rbac_cover_listenerset() {
    assert!(
        WATCHER_SRC.contains("kind: \"ListenerSet\""),
        "controller must optionally watch ListenerSet"
    );
    assert!(
        WATCHER_SRC.contains("plural: \"listenersets\""),
        "ListenerSet plural must be listenersets"
    );
    assert!(
        RBAC_SRC.contains("listenersets"),
        "chart RBAC must grant ListenerSet list/watch"
    );
    assert!(
        RBAC_SRC.contains("listenersets/status"),
        "chart RBAC must grant ListenerSet status patch"
    );
}

#[test]
fn listenerset_default_not_allowed() {
    let objects = vec![
        gateway_class(),
        http_gateway("edge", None),
        listenerset(
            "extra",
            "edge",
            json!([{
                "name": "extra-http",
                "port": 80,
                "protocol": "HTTP",
                "hostname": "extra.example.com",
                "allowedRoutes": { "namespaces": { "from": "Same" } }
            }]),
        ),
    ];
    let translation = translate_k8s_objects(&objects, options()).expect("translate");
    let status = translation
        .listenerset_statuses
        .iter()
        .find(|status| status.resource.name == "extra")
        .expect("listenerset status");
    assert!(!status.accepted);
    assert_eq!(status.accepted_reason, "NotAllowed");
    assert!(!status.attached);

    let updates = plan_gateway_api_status_updates(&objects, options(), &[]);
    let listenerset_update = updates
        .iter()
        .find(|update| update.kind == "ListenerSet" && update.name == "extra")
        .expect("ListenerSet status update");
    let accepted = listenerset_update.status["conditions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|condition| condition["type"] == "Accepted")
        .unwrap();
    assert_eq!(accepted["status"], "False");
    assert_eq!(accepted["reason"], "NotAllowed");
}

#[test]
fn listenerset_attaches_and_materializes_http_route() {
    let objects = vec![
        gateway_class(),
        http_gateway("edge", Some("Same")),
        listenerset(
            "extra",
            "edge",
            json!([{
                "name": "extra-http",
                "port": 80,
                "protocol": "HTTP",
                "hostname": "extra.example.com",
                "allowedRoutes": { "namespaces": { "from": "Same" } }
            }]),
        ),
        service("backend"),
        http_route(
            "via-listenerset",
            json!([{
                "group": "gateway.networking.k8s.io",
                "kind": "ListenerSet",
                "name": "extra",
                "namespace": "default"
            }]),
            "extra.example.com",
            "/via-set",
        ),
    ];
    let translation = translate_k8s_objects(&objects, options()).expect("translate");
    let status = translation
        .listenerset_statuses
        .iter()
        .find(|status| status.resource.name == "extra")
        .expect("listenerset status");
    assert!(status.accepted);
    assert!(status.attached);
    assert!(
        translation.config.proxies.iter().any(|proxy| {
            proxy.hosts.iter().any(|host| host == "extra.example.com")
                && proxy.listen_path.contains("via-set")
        }),
        "HTTPRoute parentRef to ListenerSet must materialize a proxy: {:?}",
        translation.config.proxies
    );
    assert!(
        translation.config.mesh.as_ref().is_some_and(|mesh| {
            mesh.services
                .iter()
                .any(|service| service.name == "extra-extra-http")
        }),
        "accepted ListenerSet listener must materialize a mesh service"
    );

    let updates =
        plan_gateway_api_status_updates(&objects, options(), &translation.route_conflicts);
    let gateway_update = updates
        .iter()
        .find(|update| update.kind == "Gateway" && update.name == "edge")
        .expect("Gateway status");
    assert_eq!(
        gateway_update.status["attachedListenerSets"].as_u64(),
        Some(1)
    );
    let listenerset_update = updates
        .iter()
        .find(|update| update.kind == "ListenerSet" && update.name == "extra")
        .expect("ListenerSet status");
    let accepted = listenerset_update.status["conditions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|condition| condition["type"] == "Accepted")
        .unwrap();
    assert_eq!(accepted["status"], "True");
}

#[test]
fn listenerset_invalid_parent_and_unmanaged_gateway_fail_closed() {
    let missing_parent = vec![
        gateway_class(),
        listenerset(
            "orphan",
            "missing",
            json!([{
                "name": "http",
                "port": 80,
                "protocol": "HTTP",
                "allowedRoutes": { "namespaces": { "from": "Same" } }
            }]),
        ),
    ];
    let translation = translate_k8s_objects(&missing_parent, options()).expect("translate");
    let status = translation
        .listenerset_statuses
        .iter()
        .find(|status| status.resource.name == "orphan")
        .expect("status");
    assert!(!status.accepted);
    assert_eq!(status.accepted_reason, "ParentNotAccepted");

    let mut other_class = object(
        "GatewayClass",
        "other",
        json!({ "controllerName": "example.com/other" }),
    );
    other_class.metadata.namespace.clear();
    let unmanaged = vec![
        other_class,
        {
            let mut gw = http_gateway("foreign", Some("Same"));
            gw.spec
                .as_object_mut()
                .unwrap()
                .insert("gatewayClassName".to_string(), json!("other"));
            gw
        },
        listenerset(
            "foreign-set",
            "foreign",
            json!([{
                "name": "http",
                "port": 80,
                "protocol": "HTTP",
                "allowedRoutes": { "namespaces": { "from": "Same" } }
            }]),
        ),
    ];
    let translation = translate_k8s_objects(&unmanaged, options()).expect("translate");
    let status = translation
        .listenerset_statuses
        .iter()
        .find(|status| status.resource.name == "foreign-set")
        .expect("status");
    assert!(!status.accepted);
    assert_eq!(status.accepted_reason, "ParentNotAccepted");
}

#[test]
fn listenerset_hostname_conflict_marks_loser_not_materialized() {
    let mut older = listenerset(
        "older",
        "edge",
        json!([{
            "name": "shared",
            "port": 80,
            "protocol": "HTTP",
            "hostname": "conflict.example.com",
            "allowedRoutes": { "namespaces": { "from": "Same" } }
        }]),
    );
    older.metadata.creation_timestamp = Some("2024-01-01T00:00:00Z".to_string());
    let mut newer = listenerset(
        "newer",
        "edge",
        json!([{
            "name": "shared",
            "port": 80,
            "protocol": "HTTP",
            "hostname": "conflict.example.com",
            "allowedRoutes": { "namespaces": { "from": "Same" } }
        }]),
    );
    newer.metadata.creation_timestamp = Some("2024-01-02T00:00:00Z".to_string());

    let objects = vec![
        gateway_class(),
        http_gateway("edge", Some("Same")),
        older,
        newer,
        service("backend"),
        http_route(
            "to-newer",
            json!([{
                "kind": "ListenerSet",
                "name": "newer",
                "namespace": "default"
            }]),
            "conflict.example.com",
            "/newer",
        ),
    ];
    let translation = translate_k8s_objects(&objects, options()).expect("translate");
    let newer_status = translation
        .listenerset_statuses
        .iter()
        .find(|status| status.resource.name == "newer")
        .expect("newer status");
    assert!(
        newer_status
            .listener_conflicts
            .iter()
            .any(|(name, reason)| name == "shared" && reason == "HostnameConflict"),
        "newer listener must report HostnameConflict: {:?}",
        newer_status.listener_conflicts
    );
    assert!(
        !translation.config.proxies.iter().any(|proxy| {
            proxy
                .hosts
                .iter()
                .any(|host| host == "conflict.example.com")
                && proxy.listen_path.contains("newer")
        }),
        "conflicted ListenerSet must not materialize route traffic"
    );

    let updates =
        plan_gateway_api_status_updates(&objects, options(), &translation.route_conflicts);
    let newer_update = updates
        .iter()
        .find(|update| update.kind == "ListenerSet" && update.name == "newer")
        .expect("newer status update");
    let listener = newer_update.status["listeners"]
        .as_array()
        .unwrap()
        .iter()
        .find(|listener| listener["name"] == "shared")
        .expect("listener status");
    let conflicted = listener["conditions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|condition| condition["type"] == "Conflicted")
        .unwrap();
    assert_eq!(conflicted["status"], "True");
    assert_eq!(conflicted["reason"], "HostnameConflict");
}

#[test]
fn listenerset_protocol_conflict_with_gateway_listener() {
    let objects = vec![
        gateway_class(),
        {
            let mut gw = http_gateway("edge", Some("Same"));
            gw.spec["listeners"] = json!([{
                "name": "http",
                "port": 80,
                "protocol": "HTTP",
                "hostname": "shared.example.com",
                "allowedRoutes": { "namespaces": { "from": "Same" } }
            }]);
            gw
        },
        listenerset(
            "tcp-conflict",
            "edge",
            json!([{
                "name": "tcp",
                "port": 80,
                "protocol": "TCP",
                "allowedRoutes": {
                    "kinds": [{ "kind": "TCPRoute" }],
                    "namespaces": { "from": "Same" }
                }
            }]),
        ),
    ];
    let translation = translate_k8s_objects(&objects, options()).expect("translate");
    let status = translation
        .listenerset_statuses
        .iter()
        .find(|status| status.resource.name == "tcp-conflict")
        .expect("status");
    assert!(
        status
            .listener_conflicts
            .iter()
            .any(|(name, reason)| name == "tcp" && reason == "ProtocolConflict")
    );
    assert!(!status.accepted);
    assert_eq!(status.accepted_reason, "ListenersNotValid");
}

/// Regression for upstream `HTTPRouteHTTPSListener`: a Gateway may declare an
/// HTTPS catch-all listener alongside hostname-specific HTTPS siblings on the
/// same port. ListenerSet conflict finalization must not treat those Gateway
/// siblings as HostnameConflict losers — otherwise a sectionName attachment to
/// the hostname listener reports Accepted=True/NoRules with no materialization.
#[test]
fn gateway_https_catch_all_and_hostname_siblings_stay_materializable() {
    let mut secret = object(
        "Secret",
        "edge-cert",
        json!({
            "type": "kubernetes.io/tls",
            "data": {
                "tls.crt": "Y2VydA==",
                "tls.key": "a2V5"
            }
        }),
    );
    secret.api_version = "v1".to_string();

    let gateway = object(
        "Gateway",
        "same-namespace-with-https-listener",
        json!({
            "gatewayClassName": "ferrum",
            "listeners": [
                {
                    "name": "https",
                    "port": 443,
                    "protocol": "HTTPS",
                    "allowedRoutes": { "namespaces": { "from": "Same" } },
                    "tls": {
                        "mode": "Terminate",
                        "certificateRefs": [{ "name": "edge-cert" }]
                    }
                },
                {
                    "name": "https-with-hostname",
                    "port": 443,
                    "hostname": "second-example.org",
                    "protocol": "HTTPS",
                    "allowedRoutes": { "namespaces": { "from": "Same" } },
                    "tls": {
                        "mode": "Terminate",
                        "certificateRefs": [{ "name": "edge-cert" }]
                    }
                }
            ]
        }),
    );

    let route_with_hostname = object(
        "HTTPRoute",
        "httproute-https-test",
        json!({
            "parentRefs": [{ "name": "same-namespace-with-https-listener" }],
            "hostnames": ["example.org"],
            "rules": [{
                "backendRefs": [{ "name": "backend", "port": 8080 }]
            }]
        }),
    );
    let route_no_hostname = object(
        "HTTPRoute",
        "httproute-https-test-no-hostname",
        json!({
            "parentRefs": [{
                "name": "same-namespace-with-https-listener",
                "sectionName": "https-with-hostname"
            }],
            "rules": [{
                "backendRefs": [{ "name": "backend", "port": 8080 }]
            }]
        }),
    );

    let objects = vec![
        gateway_class(),
        gateway,
        secret,
        service("backend"),
        route_with_hostname,
        route_no_hostname,
    ];
    let translation = translate_k8s_objects(&objects, options()).expect("translate");

    assert!(
        translation.config.proxies.iter().any(|proxy| {
            proxy.hosts.iter().any(|host| host == "example.org")
        }),
        "catch-all HTTPS listener must still materialize hostname routes"
    );
    assert!(
        translation.config.proxies.iter().any(|proxy| {
            proxy
                .hosts
                .iter()
                .any(|host| host == "second-example.org")
        }),
        "hostname-specific HTTPS sibling must stay materializable for sectionName routes"
    );

    let updates =
        plan_gateway_api_status_updates(&objects, options(), &translation.route_conflicts);
    let no_hostname_update = updates
        .iter()
        .find(|update| {
            update.kind == "HTTPRoute" && update.name == "httproute-https-test-no-hostname"
        })
        .expect("no-hostname route status");
    let conditions = no_hostname_update.status["parents"][0]["conditions"]
        .as_array()
        .expect("parent conditions");
    let accepted = conditions
        .iter()
        .find(|condition| condition["type"] == "Accepted")
        .expect("Accepted");
    let programmed = conditions
        .iter()
        .find(|condition| condition["type"] == "Programmed")
        .expect("Programmed");
    assert_eq!(accepted["status"], "True");
    assert_eq!(
        accepted["reason"], "Accepted",
        "must not report NoRules when the HTTPS sectionName listener materializes: {accepted}"
    );
    assert_eq!(programmed["status"], "True");
    assert_eq!(programmed["reason"], "Programmed");
}

#[test]
fn listenerset_section_name_and_allowed_routes_gates() {
    let objects = vec![
        gateway_class(),
        http_gateway("edge", Some("Same")),
        listenerset(
            "extra",
            "edge",
            json!([
                {
                    "name": "a",
                    "port": 80,
                    "protocol": "HTTP",
                    "hostname": "a.example.com",
                    "allowedRoutes": { "namespaces": { "from": "Same" } }
                },
                {
                    "name": "b",
                    "port": 80,
                    "protocol": "HTTP",
                    "hostname": "b.example.com",
                    "allowedRoutes": { "namespaces": { "from": "Same" } }
                }
            ]),
        ),
        service("backend"),
        http_route(
            "section-a",
            json!([{
                "kind": "ListenerSet",
                "name": "extra",
                "namespace": "default",
                "sectionName": "a"
            }]),
            "a.example.com",
            "/a",
        ),
        http_route(
            "bad-section",
            json!([{
                "kind": "ListenerSet",
                "name": "extra",
                "namespace": "default",
                "sectionName": "missing"
            }]),
            "a.example.com",
            "/missing",
        ),
    ];
    let translation = translate_k8s_objects(&objects, options()).expect("translate");
    assert!(translation.config.proxies.iter().any(|proxy| {
        proxy.hosts.iter().any(|host| host == "a.example.com") && proxy.listen_path.contains("/a")
    }));
    assert!(
        !translation
            .config
            .proxies
            .iter()
            .any(|proxy| proxy.listen_path.contains("missing")),
        "unknown sectionName must fail closed"
    );
}

#[test]
fn listenerset_update_and_delete_withdraw_materialization() {
    let base = vec![
        gateway_class(),
        http_gateway("edge", Some("Same")),
        listenerset(
            "extra",
            "edge",
            json!([{
                "name": "extra-http",
                "port": 80,
                "protocol": "HTTP",
                "hostname": "extra.example.com",
                "allowedRoutes": { "namespaces": { "from": "Same" } }
            }]),
        ),
        service("backend"),
        http_route(
            "via-listenerset",
            json!([{
                "kind": "ListenerSet",
                "name": "extra",
                "namespace": "default"
            }]),
            "extra.example.com",
            "/via-set",
        ),
    ];
    let first = translate_k8s_objects(&base, options()).expect("first translate");
    assert!(
        first
            .config
            .proxies
            .iter()
            .any(|proxy| { proxy.hosts.iter().any(|host| host == "extra.example.com") })
    );

    // Tighten allowedListeners to None and retranslate — ListenerSet withdraws.
    let mut tightened = base.clone();
    tightened[1] = http_gateway("edge", None);
    let second = translate_k8s_objects(&tightened, options()).expect("second translate");
    assert!(
        second
            .listenerset_statuses
            .iter()
            .any(|status| status.resource.name == "extra" && !status.accepted)
    );
    assert!(
        !second
            .config
            .proxies
            .iter()
            .any(|proxy| { proxy.hosts.iter().any(|host| host == "extra.example.com") }),
        "tightening allowedListeners must withdraw ListenerSet traffic"
    );

    // Delete ListenerSet entirely.
    let deleted: Vec<_> = base
        .into_iter()
        .filter(|object| object.kind != "ListenerSet")
        .collect();
    let third = translate_k8s_objects(&deleted, options()).expect("third translate");
    assert!(third.listenerset_statuses.is_empty());
    assert!(
        !third
            .config
            .proxies
            .iter()
            .any(|proxy| { proxy.hosts.iter().any(|host| host == "extra.example.com") }),
        "deleting ListenerSet must withdraw materialization"
    );
}

#[test]
fn listenerset_cross_namespace_secret_requires_listenerset_grant() {
    let mut secret = object(
        "Secret",
        "cert",
        json!({
            "type": "kubernetes.io/tls",
            "data": {
                "tls.crt": "Y2VydA==",
                "tls.key": "a2V5"
            }
        }),
    );
    secret.api_version = "v1".to_string();
    secret.metadata.namespace = "certs".to_string();

    let without_grant = vec![
        gateway_class(),
        http_gateway("edge", Some("All")),
        {
            let mut ls = listenerset(
                "tls-set",
                "edge",
                json!([{
                    "name": "https",
                    "port": 443,
                    "protocol": "HTTPS",
                    "hostname": "secure.example.com",
                    "allowedRoutes": { "namespaces": { "from": "Same" } },
                    "tls": {
                        "mode": "Terminate",
                        "certificateRefs": [{
                            "name": "cert",
                            "namespace": "certs"
                        }]
                    }
                }]),
            );
            ls
        },
        secret.clone(),
    ];
    let translation = translate_k8s_objects(&without_grant, options()).expect("translate");
    // Without a ListenerSet-scoped ReferenceGrant the HTTPS listener is not
    // materializable.
    assert!(
        translation
            .listenerset_statuses
            .iter()
            .any(|status| status.resource.name == "tls-set" && !status.accepted)
            || translation.warnings.iter().any(|warning| {
                warning.contains("tls-set") && warning.contains("unresolved TLS")
            })
            || translation.config.mesh.as_ref().is_none_or(|mesh| {
                !mesh
                    .services
                    .iter()
                    .any(|service| service.name == "tls-set-https")
            })
    );
}
