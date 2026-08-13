//! Gateway API `UDPResponseAmplificationPolicy` translation (#3836).
//!
//! Ordinary UDPRoute translation must never silently program unlimited
//! amplification. These tests pin the finite default, precedence, cross-namespace
//! authorization, invalid-value rejection, explicit unlimited override, GEP-713
//! oldest-wins, and update/delete returning to the safe posture.

use ferrum_edge::config::types::BackendScheme;
use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
    udp_amplification_policy::GatewayApiUdpAmplificationPolicyStatus,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::k8s_controller::status::{
    FERRUM_GATEWAY_CONTROLLER_NAME, GatewayApiStatusUpdate, plan_gateway_api_status_updates,
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
    udp_route_on(name, "dns")
}

fn udp_route_on(name: &str, section: &str) -> K8sObject {
    object_in(
        "UDPRoute",
        "gateway.networking.k8s.io/v1alpha2",
        "default",
        name,
        json!({
            "parentRefs": [{"name": "edge", "sectionName": section}],
            "rules": [{"backendRefs": [{"name": "coredns", "port": 5353}]}]
        }),
    )
}

fn udp_gateway_two_listeners(name: &str) -> K8sObject {
    udp_gateway_two_listeners_in_order(name, ("dns", 15353), ("alt", 15354))
}

fn udp_gateway_two_listeners_in_order(
    name: &str,
    first: (&str, u16),
    second: (&str, u16),
) -> K8sObject {
    object_in(
        "Gateway",
        "gateway.networking.k8s.io/v1",
        "default",
        name,
        json!({
            "gatewayClassName": "ferrum",
            "listeners": [
                {
                    "name": first.0,
                    "port": first.1,
                    "protocol": "UDP",
                    "allowedRoutes": {
                        "kinds": [{"kind": "UDPRoute"}],
                        "namespaces": {"from": "Same"}
                    }
                },
                {
                    "name": second.0,
                    "port": second.1,
                    "protocol": "UDP",
                    "allowedRoutes": {
                        "kinds": [{"kind": "UDPRoute"}],
                        "namespaces": {"from": "Same"}
                    }
                }
            ]
        }),
    )
}

fn udp_route_wildcard_parent(name: &str) -> K8sObject {
    object_in(
        "UDPRoute",
        "gateway.networking.k8s.io/v1alpha2",
        "default",
        name,
        json!({
            "parentRefs": [{"name": "edge"}],
            "rules": [{"backendRefs": [{"name": "coredns", "port": 5353}]}]
        }),
    )
}

fn finite_gateway_section_policy(name: &str, section: &str, factor: f64) -> K8sObject {
    amp_policy(
        name,
        json!({
            "targetRefs": [{
                "group": "gateway.networking.k8s.io",
                "kind": "Gateway",
                "name": "edge",
                "sectionName": section
            }],
            "mode": "Finite",
            "maxResponseAmplificationFactor": factor
        }),
    )
}

fn unlimited_gateway_section_policy(name: &str, section: &str) -> K8sObject {
    amp_policy(
        name,
        json!({
            "targetRefs": [{
                "group": "gateway.networking.k8s.io",
                "kind": "Gateway",
                "name": "edge",
                "sectionName": section
            }],
            "mode": "Unlimited",
            "acknowledgeUnsafeAmplification": true
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
    translated_factor_on_port(objects, 15353)
}

fn translated_factor_on_port(objects: &[K8sObject], port: u16) -> Option<f32> {
    let result = translate_k8s_objects(objects, options()).expect("translation succeeds");
    let proxy = result
        .config
        .proxies
        .iter()
        .find(|proxy| {
            proxy.backend_scheme == Some(BackendScheme::Udp) && proxy.listen_port == Some(port)
        })
        .expect("UDP proxy");
    proxy.udp_max_response_amplification_factor
}

fn policy_status_named(
    objects: &[K8sObject],
    name: &str,
) -> GatewayApiUdpAmplificationPolicyStatus {
    let result = translate_k8s_objects(objects, options()).expect("translation succeeds");
    result
        .udp_amplification_policy_statuses
        .into_iter()
        .find(|status| status.policy.name == name)
        .expect("policy status")
}

fn route_protection_reason_named(objects: &[K8sObject], route: &str) -> String {
    let updates = plan_gateway_api_status_updates(objects, options(), &[]);
    updates
        .iter()
        .find(|update| update.kind == "UDPRoute" && update.name == route)
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

fn route_protection_reason(objects: &[K8sObject]) -> String {
    let updates = plan_gateway_api_status_updates(objects, options(), &[]);
    protection_condition(updates.iter().find(|update| update.kind == "UDPRoute"))
        .map(|(_, reason, _)| reason)
        .unwrap_or_else(|| "missing".to_string())
}

fn protection_condition(update: Option<&GatewayApiStatusUpdate>) -> Option<(bool, String, String)> {
    update
        .and_then(|update| update.status.get("parents")?.as_array()?.first())
        .and_then(|parent| parent.get("conditions")?.as_array())
        .into_iter()
        .flatten()
        .find(|entry| {
            entry.get("type").and_then(Value::as_str) == Some("UDPAmplificationProtection")
        })
        .and_then(|entry| {
            Some((
                entry.get("status").and_then(Value::as_str)? == "True",
                entry.get("reason").and_then(Value::as_str)?.to_string(),
                entry.get("message").and_then(Value::as_str)?.to_string(),
            ))
        })
}

fn route_protection_named(objects: &[K8sObject], route: &str) -> (bool, String, String) {
    let updates = plan_gateway_api_status_updates(objects, options(), &[]);
    protection_condition(
        updates
            .iter()
            .find(|update| update.kind == "UDPRoute" && update.name == route),
    )
    .unwrap_or((false, "missing".to_string(), String::new()))
}

fn route_protection_conditions_named(
    objects: &[K8sObject],
    route: &str,
) -> Vec<(bool, String, String)> {
    let updates = plan_gateway_api_status_updates(objects, options(), &[]);
    protection_conditions(
        updates
            .iter()
            .find(|update| update.kind == "UDPRoute" && update.name == route),
    )
}

fn protection_conditions(update: Option<&GatewayApiStatusUpdate>) -> Vec<(bool, String, String)> {
    update
        .and_then(|update| update.status.get("parents")?.as_array())
        .into_iter()
        .flatten()
        .flat_map(|parent| parent.get("conditions")?.as_array())
        .flatten()
        .filter(|entry| {
            entry.get("type").and_then(Value::as_str) == Some("UDPAmplificationProtection")
        })
        .filter_map(|entry| {
            Some((
                entry.get("status").and_then(Value::as_str)? == "True",
                entry.get("reason").and_then(Value::as_str)?.to_string(),
                entry.get("message").and_then(Value::as_str)?.to_string(),
            ))
        })
        .collect()
}

fn udp_route_multiple_rules(name: &str) -> K8sObject {
    object_in(
        "UDPRoute",
        "gateway.networking.k8s.io/v1alpha2",
        "default",
        name,
        json!({
            "parentRefs": [{"name": "edge", "sectionName": "dns"}],
            "rules": [
                {"backendRefs": [{"name": "coredns-a", "port": 5353}]},
                {"backendRefs": [{"name": "coredns-b", "port": 5354}]}
            ]
        }),
    )
}

fn with_stale_protection_true(mut route: K8sObject) -> K8sObject {
    let parent_ref = route
        .spec
        .get("parentRefs")
        .and_then(Value::as_array)
        .and_then(|refs| refs.first())
        .cloned()
        .unwrap_or_else(|| json!({"name": "edge", "sectionName": "dns"}));
    route.status = json!({
        "parents": [{
            "parentRef": parent_ref,
            "controllerName": FERRUM_GATEWAY_CONTROLLER_NAME,
            "conditions": [{
                "type": "UDPAmplificationProtection",
                "status": "True",
                "reason": "FiniteDefault",
                "message": "Ferrum applied a finite UDP response-amplification limit",
                "observedGeneration": 1,
                "lastTransitionTime": "2020-01-01T00:00:00Z"
            }]
        }]
    });
    route
}

fn assert_not_programmed(protected: bool, reason: &str, message: &str) {
    assert!(
        !protected,
        "unprogrammed parent must not claim UDPAmplificationProtection=True"
    );
    assert_eq!(reason, "NotProgrammed");
    assert_eq!(
        message,
        "Ferrum did not program a UDP response-amplification limit"
    );
    assert_no_numeric_factor(message);
    for leaked in [
        "dns",
        "edge",
        "coredns",
        "spec.rules",
        "UnsupportedValue",
        "sectionName",
        "FiniteDefault",
    ] {
        assert!(
            !message.contains(leaked),
            "UDPAmplificationProtection message must stay fixed/redacted, \
             leaked {leaked:?}: {message}"
        );
    }
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
    let (protected, reason, message) = route_protection_named(&objects, "dns");
    assert!(protected);
    assert_eq!(reason, "FiniteDefault");
    assert_eq!(
        message,
        "Ferrum applied a finite UDP response-amplification limit"
    );
    assert_no_numeric_factor(&message);
}

#[test]
fn translation_failure_reports_amplification_not_programmed() {
    let objects = [
        gateway_class(),
        udp_gateway("edge", "dns", 15353),
        udp_route_multiple_rules("dns"),
    ];
    let (protected, reason, message) = route_protection_named(&objects, "dns");
    assert_not_programmed(protected, &reason, &message);
}

#[test]
fn unmaterialized_parent_reports_amplification_not_programmed() {
    let objects = [
        gateway_class(),
        udp_gateway("edge", "dns", 15353),
        udp_route_on("dns", "missing"),
    ];
    assert_eq!(
        translate_k8s_objects(&objects, options())
            .expect("unmatched section still translates")
            .config
            .proxies
            .len(),
        0
    );
    let (protected, reason, message) = route_protection_named(&objects, "dns");
    assert_not_programmed(protected, &reason, &message);
}

#[test]
fn stale_true_amplification_condition_is_replaced_when_unprogrammed() {
    let failed = [
        gateway_class(),
        udp_gateway("edge", "dns", 15353),
        with_stale_protection_true(udp_route_multiple_rules("dns")),
    ];
    let failed_conditions = route_protection_conditions_named(&failed, "dns");
    assert_eq!(failed_conditions.len(), 1);
    assert_not_programmed(
        failed_conditions[0].0,
        &failed_conditions[0].1,
        &failed_conditions[0].2,
    );
    assert!(
        failed_conditions.iter().all(|(protected, _, _)| !protected),
        "stale True must not survive translation failure: {failed_conditions:?}"
    );

    let unmatched = [
        gateway_class(),
        udp_gateway("edge", "dns", 15353),
        with_stale_protection_true(udp_route_on("dns", "missing")),
    ];
    let unmatched_conditions = route_protection_conditions_named(&unmatched, "dns");
    assert_eq!(unmatched_conditions.len(), 1);
    assert_not_programmed(
        unmatched_conditions[0].0,
        &unmatched_conditions[0].1,
        &unmatched_conditions[0].2,
    );
    assert!(
        unmatched_conditions
            .iter()
            .all(|(protected, _, _)| !protected),
        "stale True must not survive an unmaterialized parent: {unmatched_conditions:?}"
    );
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
        .find(|update| update.kind == UDP_AMPLIFICATION_POLICY_KIND && update.name == "newer")
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

fn finite_route_spec(route: &str, extra: Value) -> Value {
    let mut spec = json!({
        "targetRefs": [{
            "group": "gateway.networking.k8s.io",
            "kind": "UDPRoute",
            "name": route
        }],
        "mode": "Finite",
        "maxResponseAmplificationFactor": 2.0
    });
    if let Value::Object(spec_map) = &mut spec
        && let Value::Object(extra_map) = extra
    {
        spec_map.extend(extra_map);
    }
    spec
}

fn assert_invalid_policy_falls_back(spec: Value, message: &str, forbidden: &str) {
    let objects = [
        gateway_class(),
        udp_gateway("edge", "dns", 15353),
        udp_route("dns"),
        amp_policy("bad", spec),
    ];
    assert_eq!(
        translated_factor(&objects),
        Some(GATEWAY_API_UDP_AMPLIFICATION_DEFAULT_FACTOR)
    );
    assert_eq!(route_protection_reason(&objects), "FiniteDefault");
    let status = policy_status_named(&objects, "bad");
    assert!(!status.accepted);
    assert_eq!(status.accepted_reason, "Invalid");
    assert_eq!(status.accepted_message, message);
    assert!(
        !status.accepted_message.contains(forbidden),
        "status must not echo hostile input"
    );
}

#[test]
fn malformed_optional_json_types_are_rejected_without_echoing_values() {
    let hostile = "do-not-echo-this-payload";
    assert_invalid_policy_falls_back(
        finite_route_spec(
            "dns",
            json!({"targetRefs": [{
                "group": {"evil": hostile},
                "kind": "UDPRoute",
                "name": "dns"
            }]}),
        ),
        "spec.targetRefs.group must be a string",
        hostile,
    );
    assert_invalid_policy_falls_back(
        finite_route_spec(
            "dns",
            json!({"targetRefs": [{
                "group": "gateway.networking.k8s.io",
                "kind": "UDPRoute",
                "name": "dns",
                "namespace": [hostile]
            }]}),
        ),
        "spec.targetRefs.namespace must be a string",
        hostile,
    );
    assert_invalid_policy_falls_back(
        json!({
            "targetRefs": [{
                "group": "gateway.networking.k8s.io",
                "kind": "Gateway",
                "name": "edge",
                "sectionName": {"evil": hostile}
            }],
            "mode": "Finite",
            "maxResponseAmplificationFactor": 2.0
        }),
        "spec.targetRefs.sectionName must be a string",
        hostile,
    );
    assert_invalid_policy_falls_back(
        finite_route_spec("dns", json!({"mode": 1})),
        "spec.mode must be a string",
        "1",
    );
    assert_invalid_policy_falls_back(
        finite_route_spec("dns", json!({"acknowledgeUnsafeAmplification": hostile})),
        "spec.acknowledgeUnsafeAmplification must be a bool",
        hostile,
    );
}

#[test]
fn duplicate_canonical_target_refs_are_rejected() {
    let objects = [
        gateway_class(),
        udp_gateway("edge", "dns", 15353),
        udp_route("dns"),
        amp_policy(
            "dup",
            json!({
                "targetRefs": [
                    {
                        "group": "gateway.networking.k8s.io",
                        "kind": "UDPRoute",
                        "name": "dns"
                    },
                    {
                        "kind": "UDPRoute",
                        "name": "dns",
                        "namespace": "default"
                    }
                ],
                "mode": "Finite",
                "maxResponseAmplificationFactor": 2.0
            }),
        ),
    ];
    assert_eq!(
        translated_factor(&objects),
        Some(GATEWAY_API_UDP_AMPLIFICATION_DEFAULT_FACTOR)
    );
    let status = policy_status_named(&objects, "dup");
    assert!(!status.accepted);
    assert_eq!(status.accepted_reason, "Invalid");
    assert_eq!(
        status.accepted_message,
        "spec.targetRefs entries must be unique by kind, namespace, name, and sectionName"
    );
    assert!(
        status.ancestors.is_empty(),
        "duplicate targetRefs must not emit duplicate ancestors"
    );
}

#[test]
fn typoed_gateway_section_falls_back_to_finite_default_and_is_rejected() {
    let objects = [
        gateway_class(),
        udp_gateway("edge", "dns", 15353),
        udp_route("dns"),
        amp_policy(
            "typo",
            json!({
                "targetRefs": [{
                    "group": "gateway.networking.k8s.io",
                    "kind": "Gateway",
                    "name": "edge",
                    "sectionName": "dnss"
                }],
                "mode": "Finite",
                "maxResponseAmplificationFactor": 2.0
            }),
        ),
    ];
    assert_eq!(
        translated_factor(&objects),
        Some(GATEWAY_API_UDP_AMPLIFICATION_DEFAULT_FACTOR)
    );
    assert_eq!(route_protection_reason(&objects), "FiniteDefault");
    let status = policy_status_named(&objects, "typo");
    assert!(!status.accepted);
    assert_eq!(status.accepted_reason, "TargetNotFound");
    assert_eq!(
        status.accepted_message,
        "UDPResponseAmplificationPolicy targetRef sectionName does not name a listener on the observed Gateway"
    );
}

#[test]
fn valid_gateway_section_policy_still_applies() {
    let objects = [
        gateway_class(),
        udp_gateway("edge", "dns", 15353),
        udp_route("dns"),
        amp_policy(
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
        ),
    ];
    assert_eq!(translated_factor(&objects), Some(3.0));
    assert_eq!(route_protection_reason(&objects), "FinitePolicy");
    let status = policy_status_named(&objects, "section");
    assert!(status.accepted);
}

#[test]
fn whole_gateway_target_does_not_require_a_section() {
    let objects = [
        gateway_class(),
        udp_gateway("edge", "dns", 15353),
        udp_route("dns"),
        amp_policy(
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
        ),
    ];
    assert_eq!(translated_factor(&objects), Some(4.0));
    let status = policy_status_named(&objects, "gw");
    assert!(status.accepted);
}

#[test]
fn conflicted_direct_policy_is_withdrawn_from_gatewayclass_lookup() {
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
    let conflicted_class_default = amp_policy_at(
        "class-default",
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
        gateway_class_with_parameters("default", "class-default"),
        udp_gateway_two_listeners("edge"),
        udp_route_on("dns", "dns"),
        udp_route_on("alt", "alt"),
        older,
        conflicted_class_default,
    ];
    assert_eq!(translated_factor_on_port(&objects, 15353), Some(2.0));
    assert_eq!(
        translated_factor_on_port(&objects, 15354),
        Some(GATEWAY_API_UDP_AMPLIFICATION_DEFAULT_FACTOR)
    );
    assert_eq!(
        route_protection_reason_named(&objects, "dns"),
        "FinitePolicy"
    );
    assert_eq!(
        route_protection_reason_named(&objects, "alt"),
        "FiniteDefault"
    );
    let loser = policy_status_named(&objects, "class-default");
    assert!(!loser.accepted);
    assert_eq!(loser.accepted_reason, "Conflicted");
}

fn udp_route_target(name: &str) -> Value {
    json!({
        "group": "gateway.networking.k8s.io",
        "kind": "UDPRoute",
        "name": name
    })
}

fn assert_no_numeric_factor(message: &str) {
    assert!(
        !message.chars().any(|ch| ch.is_ascii_digit()),
        "UDPAmplificationProtection message must not echo a numeric factor: {message}"
    );
}

fn assert_three_policy_cascade(objects: &[K8sObject], label: &str) {
    assert_eq!(
        translated_factor_on_port(objects, 15353),
        Some(4.0),
        "{label}: route a must take the promoted P2 factor"
    );
    assert_eq!(
        translated_factor_on_port(objects, 15354),
        Some(2.0),
        "{label}: route b must keep the oldest P0 factor"
    );
    let p0 = policy_status_named(objects, "p0");
    assert!(p0.accepted, "{label}: P0 must stay Accepted");
    assert_eq!(p0.accepted_reason, "Accepted", "{label}");
    let p1 = policy_status_named(objects, "p1");
    assert!(!p1.accepted, "{label}: P1 must be Conflicted");
    assert_eq!(p1.accepted_reason, "Conflicted", "{label}");
    let p2 = policy_status_named(objects, "p2");
    assert!(p2.accepted, "{label}: P2 must be promoted Accepted");
    assert_eq!(p2.accepted_reason, "Accepted", "{label}");
    let (on_a, reason_a, message_a) = route_protection_named(objects, "a");
    assert!(on_a, "{label}: route a protection must stay on");
    assert_eq!(reason_a, "FinitePolicy", "{label}");
    assert_no_numeric_factor(&message_a);
    let (on_b, reason_b, message_b) = route_protection_named(objects, "b");
    assert!(on_b, "{label}: route b protection must stay on");
    assert_eq!(reason_b, "FinitePolicy", "{label}");
    assert_no_numeric_factor(&message_b);
}

#[test]
fn atomic_multi_target_conflict_promotes_next_eligible_candidate() {
    // Oldest P0 owns B, middle P1 targets A+B and must lose atomically, newest
    // P2 must then govern A. Translation runs finalize_conflicts twice, so a
    // passing case also pins idempotent rebuild.
    let p0 = amp_policy_at(
        "p0",
        "2024-01-01T00:00:00Z",
        json!({
            "targetRefs": [udp_route_target("b")],
            "mode": "Finite",
            "maxResponseAmplificationFactor": 2.0
        }),
    );
    let p1 = amp_policy_at(
        "p1",
        "2024-02-01T00:00:00Z",
        json!({
            "targetRefs": [udp_route_target("a"), udp_route_target("b")],
            "mode": "Finite",
            "maxResponseAmplificationFactor": 32.0
        }),
    );
    let p2 = amp_policy_at(
        "p2",
        "2024-03-01T00:00:00Z",
        json!({
            "targetRefs": [udp_route_target("a")],
            "mode": "Finite",
            "maxResponseAmplificationFactor": 4.0
        }),
    );
    let policies = [p0, p1, p2];
    let orders = [
        [0usize, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];
    for order in orders {
        let mut objects = vec![
            gateway_class_with_parameters("default", "p1"),
            udp_gateway_two_listeners("edge"),
            udp_gateway("other", "dns", 15355),
            udp_route_on("a", "dns"),
            udp_route_on("b", "alt"),
            object_in(
                "UDPRoute",
                "gateway.networking.k8s.io/v1alpha2",
                "default",
                "c",
                json!({
                    "parentRefs": [{"name": "other", "sectionName": "dns"}],
                    "rules": [{"backendRefs": [{"name": "coredns", "port": 5353}]}]
                }),
            ),
        ];
        for index in order {
            objects.push(policies[index].clone());
        }
        assert_three_policy_cascade(&objects, &format!("order {order:?}"));
        assert_eq!(
            translated_factor_on_port(&objects, 15355),
            Some(GATEWAY_API_UDP_AMPLIFICATION_DEFAULT_FACTOR),
            "order {order:?}: conflicted P1 must not win through GatewayClass.parametersRef"
        );
        let (on_c, reason_c, message_c) = route_protection_named(&objects, "c");
        assert!(
            on_c,
            "order {order:?}: class-default fallback must stay protected"
        );
        assert_eq!(reason_c, "FiniteDefault", "order {order:?}");
        assert_no_numeric_factor(&message_c);
    }
}

type WildcardListener = (&'static str, u16);
type WildcardListenerOrder = (WildcardListener, WildcardListener);

fn wildcard_listener_orders() -> [WildcardListenerOrder; 2] {
    [
        (("dns", 15353), ("alt", 15354)),
        (("alt", 15354), ("dns", 15353)),
    ]
}

fn wildcard_parent_objects(
    listener_order: WildcardListenerOrder,
    policies: impl IntoIterator<Item = K8sObject>,
) -> Vec<K8sObject> {
    let mut objects = vec![
        gateway_class(),
        udp_gateway_two_listeners_in_order("edge", listener_order.0, listener_order.1),
        udp_route_wildcard_parent("wild"),
    ];
    objects.extend(policies);
    objects
}

#[test]
fn wildcard_parent_unlimited_listener_dominates_status_regardless_of_order() {
    let policy_orders = [
        vec![
            finite_gateway_section_policy("tight", "dns", 2.0),
            unlimited_gateway_section_policy("open", "alt"),
        ],
        vec![
            unlimited_gateway_section_policy("open", "alt"),
            finite_gateway_section_policy("tight", "dns", 2.0),
        ],
    ];
    for listeners in wildcard_listener_orders() {
        for policies in &policy_orders {
            let objects = wildcard_parent_objects(listeners, policies.clone());
            assert_eq!(
                translated_factor_on_port(&objects, 15353),
                Some(2.0),
                "dns listener must keep its finite policy"
            );
            assert_eq!(
                translated_factor_on_port(&objects, 15354),
                None,
                "alt listener must stay unlimited"
            );
            let (protected, reason, message) = route_protection_named(&objects, "wild");
            assert!(
                !protected,
                "any unlimited listener must make the parent unprotected"
            );
            assert_eq!(reason, "ExplicitUnlimited");
            assert_no_numeric_factor(&message);
        }
    }
}

#[test]
fn wildcard_parent_mixed_finite_and_default_reports_finite_default() {
    let section_policies = ["dns", "alt"];
    for listeners in wildcard_listener_orders() {
        for section in section_policies {
            let objects = wildcard_parent_objects(
                listeners,
                [finite_gateway_section_policy("tight", section, 2.0)],
            );
            let dns_factor = translated_factor_on_port(&objects, 15353);
            let alt_factor = translated_factor_on_port(&objects, 15354);
            if section == "dns" {
                assert_eq!(dns_factor, Some(2.0));
                assert_eq!(
                    alt_factor,
                    Some(GATEWAY_API_UDP_AMPLIFICATION_DEFAULT_FACTOR)
                );
            } else {
                assert_eq!(
                    dns_factor,
                    Some(GATEWAY_API_UDP_AMPLIFICATION_DEFAULT_FACTOR)
                );
                assert_eq!(alt_factor, Some(2.0));
            }
            let (protected, reason, message) = route_protection_named(&objects, "wild");
            assert!(protected, "mixed finite listeners must stay protection-on");
            assert_eq!(reason, "FiniteDefault");
            assert_no_numeric_factor(&message);
            assert_eq!(
                message,
                "Ferrum applied a finite UDP response-amplification limit"
            );
        }
    }
}

#[test]
fn wildcard_parent_all_finite_policies_report_finite_policy() {
    let policy_orders = [
        vec![
            finite_gateway_section_policy("dns-limit", "dns", 2.0),
            finite_gateway_section_policy("alt-limit", "alt", 4.0),
        ],
        vec![
            finite_gateway_section_policy("alt-limit", "alt", 4.0),
            finite_gateway_section_policy("dns-limit", "dns", 2.0),
        ],
    ];
    for listeners in wildcard_listener_orders() {
        for policies in &policy_orders {
            let objects = wildcard_parent_objects(listeners, policies.clone());
            assert_eq!(translated_factor_on_port(&objects, 15353), Some(2.0));
            assert_eq!(translated_factor_on_port(&objects, 15354), Some(4.0));
            let (protected, reason, message) = route_protection_named(&objects, "wild");
            assert!(protected);
            assert_eq!(reason, "FinitePolicy");
            assert_no_numeric_factor(&message);
        }
    }
}
