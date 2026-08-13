//! Gateway API `UDPResponseAmplificationPolicy` translation (#3836).
//!
//! Ordinary UDPRoute translation must never silently program unlimited
//! amplification. These tests pin the finite default, precedence, cross-namespace
//! authorization, invalid-value rejection, explicit unlimited override, GEP-713
//! oldest-wins, and update/delete returning to the safe posture.

use ferrum_edge::config::types::BackendScheme;
use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::k8s_controller::status::{
    FERRUM_GATEWAY_CONTROLLER_NAME, plan_gateway_api_status_updates,
};
use ferrum_edge::udp_amplification::{
    GATEWAY_API_UDP_AMPLIFICATION_DEFAULT_FACTOR, UDP_AMPLIFICATION_POLICY_KIND,
};
use serde_json::{Value, json};
use std::collections::HashMap;

fn options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("test trust domain"),
    )
}

fn multi_namespace_options() -> K8sTranslationOptions {
    options().with_source_namespaces(vec!["default".to_string(), "policies".to_string()])
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

fn gateway_class() -> K8sObject {
    object_in(
        "GatewayClass",
        "gateway.networking.k8s.io/v1",
        "",
        "ferrum",
        json!({"controllerName": FERRUM_GATEWAY_CONTROLLER_NAME}),
    )
}

fn gateway_class_with_parameters(ns: &str, name: &str) -> K8sObject {
    object_in(
        "GatewayClass",
        "gateway.networking.k8s.io/v1",
        "",
        "ferrum",
        json!({
            "controllerName": FERRUM_GATEWAY_CONTROLLER_NAME,
            "parametersRef": {
                "group": "gateway.ferrum.io",
                "kind": UDP_AMPLIFICATION_POLICY_KIND,
                "name": name,
                "namespace": ns
            }
        }),
    )
}

fn udp_gateway(name: &str, listener: &str, port: u16) -> K8sObject {
    object_in(
        "Gateway",
        "gateway.networking.k8s.io/v1",
        "default",
        name,
        json!({
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
        }),
    )
}

fn udp_route(name: &str) -> K8sObject {
    object_in(
        "UDPRoute",
        "gateway.networking.k8s.io/v1alpha2",
        "default",
        name,
        json!({
            "parentRefs": [{"name": "edge", "sectionName": "dns"}],
            "rules": [{"backendRefs": [{"name": "coredns", "port": 5353}]}]
        }),
    )
}

fn amp_policy(name: &str, spec: Value) -> K8sObject {
    object_in(
        UDP_AMPLIFICATION_POLICY_KIND,
        "gateway.ferrum.io/v1alpha1",
        "default",
        name,
        spec,
    )
}

fn amp_policy_at(name: &str, created_at: &str, spec: Value) -> K8sObject {
    let mut policy = amp_policy(name, spec);
    policy.metadata.creation_timestamp = Some(created_at.to_string());
    policy
}

fn finite_route_policy(name: &str, route: &str, factor: f64) -> K8sObject {
    amp_policy(
        name,
        json!({
            "targetRefs": [{
                "group": "gateway.networking.k8s.io",
                "kind": "UDPRoute",
                "name": route
            }],
            "mode": "Finite",
            "maxResponseAmplificationFactor": factor
        }),
    )
}

fn translated_factor(objects: &[K8sObject]) -> Option<f32> {
    let result = translate_k8s_objects(objects, options()).expect("translation succeeds");
    let proxy = result
        .config
        .proxies
        .iter()
        .find(|proxy| proxy.backend_scheme == Some(BackendScheme::Udp))
        .expect("UDP proxy");
    proxy.udp_max_response_amplification_factor
}

fn route_protection_reason(objects: &[K8sObject]) -> String {
    let updates = plan_gateway_api_status_updates(objects, options(), &[]);
    updates
        .iter()
        .find(|update| update.kind == "UDPRoute")
        .and_then(|update| update.status.get("parents")?.as_array()?.first())
        .and_then(|parent| parent.get("conditions")?.as_array())
        .into_iter()
        .flatten()
        .find(|entry| {
            entry.get("type").and_then(Value::as_str) == Some("UDPAmplificationProtection")
        })
        .and_then(|entry| entry.get("reason").and_then(Value::as_str))
        .unwrap_or("missing")
        .to_string()
}

#[test]
fn translated_udproute_gets_finite_controller_default() {
    let objects = [
        gateway_class(),
        udp_gateway("edge", "dns", 15353),
        udp_route("dns"),
    ];
    assert_eq!(
        translated_factor(&objects),
        Some(GATEWAY_API_UDP_AMPLIFICATION_DEFAULT_FACTOR)
    );
    assert_eq!(route_protection_reason(&objects), "FiniteDefault");
}

#[test]
fn route_policy_overrides_default() {
    let objects = [
        gateway_class(),
        udp_gateway("edge", "dns", 15353),
        udp_route("dns"),
        finite_route_policy("tight", "dns", 2.0),
    ];
    assert_eq!(translated_factor(&objects), Some(2.0));
    assert_eq!(route_protection_reason(&objects), "FinitePolicy");
}

#[test]
fn gateway_section_policy_overrides_gateway_and_class() {
    let class_default = amp_policy(
        "class-default",
        json!({
            "mode": "Finite",
            "maxResponseAmplificationFactor": 16.0
        }),
    );
    let gateway_policy = amp_policy(
        "gw",
        json!({
            "targetRefs": [{
                "group": "gateway.networking.k8s.io",
                "kind": "Gateway",
                "name": "edge"
            }],
            "mode": "Finite",
            "maxResponseAmplificationFactor": 4.0
        }),
    );
    let section_policy = amp_policy(
        "section",
        json!({
            "targetRefs": [{
                "group": "gateway.networking.k8s.io",
                "kind": "Gateway",
                "name": "edge",
                "sectionName": "dns"
            }],
            "mode": "Finite",
            "maxResponseAmplificationFactor": 3.0
        }),
    );
    let objects = [
        gateway_class_with_parameters("default", "class-default"),
        udp_gateway("edge", "dns", 15353),
        udp_route("dns"),
        class_default,
        gateway_policy,
        section_policy,
    ];
    assert_eq!(translated_factor(&objects), Some(3.0));
}

#[test]
fn gatewayclass_parameters_ref_overrides_controller_default() {
    let class_default = amp_policy(
        "class-default",
        json!({
            "mode": "Finite",
            "maxResponseAmplificationFactor": 16.0
        }),
    );
    let objects = [
        gateway_class_with_parameters("default", "class-default"),
        udp_gateway("edge", "dns", 15353),
        udp_route("dns"),
        class_default,
    ];
    assert_eq!(translated_factor(&objects), Some(16.0));
    assert_eq!(route_protection_reason(&objects), "FinitePolicy");
}

#[test]
fn invalid_zero_factor_falls_back_to_default() {
    let objects = [
        gateway_class(),
        udp_gateway("edge", "dns", 15353),
        udp_route("dns"),
        finite_route_policy("bad", "dns", 0.0),
    ];
    assert_eq!(
        translated_factor(&objects),
        Some(GATEWAY_API_UDP_AMPLIFICATION_DEFAULT_FACTOR)
    );
    assert_eq!(route_protection_reason(&objects), "FiniteDefault");
}

#[test]
fn invalid_negative_and_excessive_factors_fall_back_to_default() {
    for factor in [-1.0, 1025.0] {
        let objects = [
            gateway_class(),
            udp_gateway("edge", "dns", 15353),
            udp_route("dns"),
            finite_route_policy("bad", "dns", factor),
        ];
        assert_eq!(
            translated_factor(&objects),
            Some(GATEWAY_API_UDP_AMPLIFICATION_DEFAULT_FACTOR),
            "factor {factor} must not program the listener"
        );
    }
}

#[test]
fn unlimited_without_ack_falls_back_to_default() {
    let objects = [
        gateway_class(),
        udp_gateway("edge", "dns", 15353),
        udp_route("dns"),
        amp_policy(
            "open",
            json!({
                "targetRefs": [{
                    "group": "gateway.networking.k8s.io",
                    "kind": "UDPRoute",
                    "name": "dns"
                }],
                "mode": "Unlimited"
            }),
        ),
    ];
    assert_eq!(
        translated_factor(&objects),
        Some(GATEWAY_API_UDP_AMPLIFICATION_DEFAULT_FACTOR)
    );
}

#[test]
fn unlimited_with_ack_programs_none() {
    let objects = [
        gateway_class(),
        udp_gateway("edge", "dns", 15353),
        udp_route("dns"),
        amp_policy(
            "open",
            json!({
                "targetRefs": [{
                    "group": "gateway.networking.k8s.io",
                    "kind": "UDPRoute",
                    "name": "dns"
                }],
                "mode": "Unlimited",
                "acknowledgeUnsafeAmplification": true
            }),
        ),
    ];
    assert_eq!(translated_factor(&objects), None);
    assert_eq!(route_protection_reason(&objects), "ExplicitUnlimited");
}

#[test]
fn oldest_policy_wins_and_loser_is_conflicted() {
    let older = amp_policy_at(
        "older",
        "2024-01-01T00:00:00Z",
        json!({
            "targetRefs": [{
                "group": "gateway.networking.k8s.io",
                "kind": "UDPRoute",
                "name": "dns"
            }],
            "mode": "Finite",
            "maxResponseAmplificationFactor": 2.0
        }),
    );
    let newer = amp_policy_at(
        "newer",
        "2024-06-01T00:00:00Z",
        json!({
            "targetRefs": [{
                "group": "gateway.networking.k8s.io",
                "kind": "UDPRoute",
                "name": "dns"
            }],
            "mode": "Finite",
            "maxResponseAmplificationFactor": 32.0
        }),
    );
    let objects = [
        gateway_class(),
        udp_gateway("edge", "dns", 15353),
        udp_route("dns"),
        older,
        newer,
    ];
    assert_eq!(translated_factor(&objects), Some(2.0));
    let updates = plan_gateway_api_status_updates(&objects, options(), &[]);
    let loser = updates
        .iter()
        .find(|update| {
            update.kind == UDP_AMPLIFICATION_POLICY_KIND && update.name == "newer"
        })
        .expect("loser status");
    let accepted = loser
        .status
        .get("ancestors")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .flat_map(|ancestor| ancestor.get("conditions")?.as_array())
        .flatten()
        .find(|entry| entry.get("type").and_then(Value::as_str) == Some("Accepted"))
        .and_then(|entry| entry.get("reason").and_then(Value::as_str));
    assert_eq!(accepted, Some("Conflicted"));
}

#[test]
fn deleting_policy_returns_to_finite_default() {
    let with_policy = [
        gateway_class(),
        udp_gateway("edge", "dns", 15353),
        udp_route("dns"),
        finite_route_policy("tight", "dns", 2.0),
    ];
    let without_policy = [
        gateway_class(),
        udp_gateway("edge", "dns", 15353),
        udp_route("dns"),
    ];
    assert_eq!(translated_factor(&with_policy), Some(2.0));
    assert_eq!(
        translated_factor(&without_policy),
        Some(GATEWAY_API_UDP_AMPLIFICATION_DEFAULT_FACTOR)
    );
}

#[test]
fn updating_policy_factor_replaces_proxy_field_without_new_kind() {
    let before = [
        gateway_class(),
        udp_gateway("edge", "dns", 15353),
        udp_route("dns"),
        finite_route_policy("tight", "dns", 2.0),
    ];
    let after = [
        gateway_class(),
        udp_gateway("edge", "dns", 15353),
        udp_route("dns"),
        finite_route_policy("tight", "dns", 5.0),
    ];
    let before_id = translate_k8s_objects(&before, options())
        .expect("ok")
        .config
        .proxies[0]
        .id
        .clone();
    let after_translation = translate_k8s_objects(&after, options()).expect("ok");
    assert_eq!(after_translation.config.proxies[0].id, before_id);
    assert_eq!(
        after_translation.config.proxies[0].udp_max_response_amplification_factor,
        Some(5.0)
    );
}

#[test]
fn cross_namespace_policy_without_grant_falls_back_to_default() {
    let mut policy = finite_route_policy("tight", "dns", 2.0);
    policy.metadata.namespace = "policies".to_string();
    policy.spec["targetRefs"][0]["namespace"] = json!("default");
    let objects = [
        gateway_class(),
        udp_gateway("edge", "dns", 15353),
        udp_route("dns"),
        policy,
    ];
    let result = translate_k8s_objects(&objects, multi_namespace_options()).expect("ok");
    let factor = result.config.proxies[0].udp_max_response_amplification_factor;
    assert_eq!(factor, Some(GATEWAY_API_UDP_AMPLIFICATION_DEFAULT_FACTOR));
}

#[test]
fn cross_namespace_policy_with_matching_grant_applies() {
    let mut policy = finite_route_policy("tight", "dns", 2.0);
    policy.metadata.namespace = "policies".to_string();
    policy.spec["targetRefs"][0]["namespace"] = json!("default");
    let grant = object_in(
        "ReferenceGrant",
        "gateway.networking.k8s.io/v1beta1",
        "default",
        "allow-amp",
        json!({
            "from": [{
                "group": "gateway.ferrum.io",
                "kind": UDP_AMPLIFICATION_POLICY_KIND,
                "namespace": "policies"
            }],
            "to": [{
                "group": "gateway.networking.k8s.io",
                "kind": "UDPRoute",
                "name": "dns"
            }]
        }),
    );
    let objects = [
        gateway_class(),
        udp_gateway("edge", "dns", 15353),
        udp_route("dns"),
        policy,
        grant,
    ];
    let result = translate_k8s_objects(&objects, multi_namespace_options()).expect("ok");
    assert_eq!(
        result.config.proxies[0].udp_max_response_amplification_factor,
        Some(2.0)
    );
}

#[test]
fn missing_target_does_not_unprogram_the_route() {
    let objects = [
        gateway_class(),
        udp_gateway("edge", "dns", 15353),
        udp_route("dns"),
        finite_route_policy("tight", "missing-route", 2.0),
    ];
    assert_eq!(
        translated_factor(&objects),
        Some(GATEWAY_API_UDP_AMPLIFICATION_DEFAULT_FACTOR)
    );
    let result = translate_k8s_objects(&objects, options()).expect("ok");
    assert_eq!(result.config.proxies.len(), 1);
}
