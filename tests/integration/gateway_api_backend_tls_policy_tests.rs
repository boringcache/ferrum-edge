//! Integration coverage for Gateway API `BackendTLSPolicy` translation onto
//! Service-backed HTTPRoute backends (issue #3276).
//!
//! Pins watch/index → route materialization: HTTPS scheme, upstream SNI/CA/SAN
//! projection, System well-known roots, invalid CA fail-closed, and policy
//! withdrawal on delete from the translated snapshot.

use ferrum_edge::config::types::BackendScheme;
use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::k8s_controller::status::{
    FERRUM_GATEWAY_CONTROLLER_NAME, GatewayApiStatusUpdate, plan_gateway_api_status_updates,
};
use ferrum_edge::tls::source::SYSTEM_TRUST_ROOTS_SOURCE;
use serde_json::Value;

fn options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("trust domain"),
    )
}

fn object(kind: &str, name: &str, spec: serde_json::Value) -> K8sObject {
    K8sObject {
        api_version: match kind {
            "Secret" | "ConfigMap" | "Service" => "v1".to_string(),
            "BackendTLSPolicy" => "gateway.networking.k8s.io/v1".to_string(),
            _ => "gateway.networking.k8s.io/v1".to_string(),
        },
        kind: kind.to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            uid: String::new(),
            namespace: "default".to_string(),
            generation: None,
            labels: Default::default(),
            creation_timestamp: None,
            deletion_timestamp: None,
            annotations: Default::default(),
        },
        spec,
        status: serde_json::Value::Object(serde_json::Map::new()),
    }
}

fn gateway_class() -> K8sObject {
    let mut gc = object(
        "GatewayClass",
        "ferrum",
        serde_json::json!({
            "controllerName": "ferrum.io/gateway-controller"
        }),
    );
    gc.metadata.namespace.clear();
    gc
}

fn gateway() -> K8sObject {
    object(
        "Gateway",
        "edge",
        serde_json::json!({
            "gatewayClassName": "ferrum",
            "listeners": [{
                "name": "http",
                "port": 80,
                "protocol": "HTTP",
                "allowedRoutes": { "namespaces": { "from": "Same" } }
            }]
        }),
    )
}

fn service(name: &str, port: u16, port_name: &str) -> K8sObject {
    object(
        "Service",
        name,
        serde_json::json!({
            "ports": [{
                "name": port_name,
                "port": port,
                "targetPort": port
            }]
        }),
    )
}

fn http_route(name: &str, service_name: &str, port: u16) -> K8sObject {
    object(
        "HTTPRoute",
        name,
        serde_json::json!({
            "parentRefs": [{ "name": "edge" }],
            "hostnames": ["app.example.com"],
            "rules": [{
                "matches": [{ "path": { "type": "PathPrefix", "value": "/api" } }],
                "backendRefs": [{
                    "name": service_name,
                    "port": port
                }]
            }]
        }),
    )
}

fn ca_configmap(name: &str) -> K8sObject {
    let pem = include_str!("../certs/server.crt");
    object(
        "ConfigMap",
        name,
        serde_json::json!({
            "data": {
                "ca.crt": pem
            }
        }),
    )
}

fn ca_secret(name: &str) -> K8sObject {
    use base64::Engine as _;
    let pem = include_str!("../certs/server.crt");
    object(
        "Secret",
        name,
        serde_json::json!({
            "type": "Opaque",
            "data": {
                "ca.crt": base64::engine::general_purpose::STANDARD.encode(pem)
            }
        }),
    )
}

fn backend_tls_policy_system(name: &str, service_name: &str) -> K8sObject {
    object(
        "BackendTLSPolicy",
        name,
        serde_json::json!({
            "targetRefs": [{
                "group": "",
                "kind": "Service",
                "name": service_name
            }],
            "validation": {
                "hostname": "backend.example.com",
                "wellKnownCACertificates": "System"
            }
        }),
    )
}

fn backend_tls_policy_configmap(
    name: &str,
    service_name: &str,
    configmap_name: &str,
    sans: &[(&str, &str)],
) -> K8sObject {
    let subject_alt_names: Vec<serde_json::Value> = sans
        .iter()
        .map(|(san_type, value)| match *san_type {
            "Hostname" => serde_json::json!({ "type": "Hostname", "hostname": value }),
            "URI" => serde_json::json!({ "type": "URI", "uri": value }),
            _ => panic!("unsupported SAN type in test fixture"),
        })
        .collect();
    object(
        "BackendTLSPolicy",
        name,
        serde_json::json!({
            "targetRefs": [{
                "group": "",
                "kind": "Service",
                "name": service_name
            }],
            "validation": {
                "hostname": "auth.example.com",
                "caCertificateRefs": [{
                    "group": "",
                    "kind": "ConfigMap",
                    "name": configmap_name
                }],
                "subjectAltNames": subject_alt_names
            }
        }),
    )
}

fn backend_tls_policy_secret(name: &str, service_name: &str, secret_name: &str) -> K8sObject {
    object(
        "BackendTLSPolicy",
        name,
        serde_json::json!({
            "targetRefs": [{
                "group": "",
                "kind": "Service",
                "name": service_name
            }],
            "validation": {
                "hostname": "secret-backend.example.com",
                "caCertificateRefs": [{
                    "group": "",
                    "kind": "Secret",
                    "name": secret_name
                }]
            }
        }),
    )
}

fn backend_tls_policy_missing_ca(name: &str, service_name: &str) -> K8sObject {
    object(
        "BackendTLSPolicy",
        name,
        serde_json::json!({
            "targetRefs": [{
                "group": "",
                "kind": "Service",
                "name": service_name
            }],
            "validation": {
                "hostname": "broken.example.com",
                "caCertificateRefs": [{
                    "group": "",
                    "kind": "ConfigMap",
                    "name": "missing-ca"
                }]
            }
        }),
    )
}

#[test]
fn backend_tls_policy_system_enables_https_sni_on_upstream() {
    let objects = vec![
        gateway_class(),
        gateway(),
        service("reviews", 8080, "http"),
        http_route("reviews-route", "reviews", 8080),
        backend_tls_policy_system("reviews-tls", "reviews"),
    ];
    let translated = translate_k8s_objects(&objects, options()).expect("translate");
    assert!(
        translated.config.upstreams.len() == 1,
        "BackendTLSPolicy should promote the single backend onto an Upstream for SNI: {:?}",
        translated.config.upstreams
    );
    let upstream = &translated.config.upstreams[0];
    assert_eq!(
        upstream.backend_tls_sni.as_deref(),
        Some("backend.example.com")
    );
    assert!(upstream.backend_tls_verify_server_cert);
    // `wellKnownCACertificates: System` must project the explicit system-roots
    // source, NOT an unset CA path: unset falls back to the cluster-global
    // FERRUM_TLS_CA_BUNDLE_PATH, so a private cluster CA would silently replace
    // the public roots the policy asked for.
    assert_eq!(
        upstream.backend_tls_server_ca_cert_path.as_deref(),
        Some(SYSTEM_TRUST_ROOTS_SOURCE)
    );
    assert!(
        translated
            .config
            .proxies
            .iter()
            .any(|proxy| proxy.backend_scheme == Some(BackendScheme::Https)
                && proxy.upstream_id.as_deref() == Some(upstream.id.as_str())),
        "HTTPRoute proxy must use HTTPS against the TLS-backed upstream"
    );
}

#[test]
fn backend_tls_policy_configmap_ca_and_sans_project_to_upstream() {
    let objects = vec![
        gateway_class(),
        gateway(),
        service("auth", 8443, "https"),
        ca_configmap("auth-cert"),
        http_route("auth-route", "auth", 8443),
        backend_tls_policy_configmap(
            "auth-tls",
            "auth",
            "auth-cert",
            &[
                ("Hostname", "auth.example.com"),
                ("URI", "spiffe://cluster.local/ns/default/sa/auth"),
            ],
        ),
    ];
    let translated = translate_k8s_objects(&objects, options()).expect("translate");
    let upstream = translated
        .config
        .upstreams
        .first()
        .expect("expected upstream");
    assert_eq!(
        upstream.backend_tls_sni.as_deref(),
        Some("auth.example.com")
    );
    let ca = upstream
        .backend_tls_server_ca_cert_path
        .as_deref()
        .expect("ConfigMap CA should be projected as inline PEM");
    assert!(
        ca.contains("BEGIN CERTIFICATE"),
        "expected inline PEM CA, got {ca}"
    );
    assert_eq!(
        upstream.backend_tls_san_allow_list,
        vec![
            "auth.example.com".to_string(),
            "spiffe://cluster.local/ns/default/sa/auth".to_string(),
        ]
    );
}

#[test]
fn backend_tls_policy_secret_ca_uses_k8s_uri() {
    let objects = vec![
        gateway_class(),
        gateway(),
        service("payments", 8443, "https"),
        ca_secret("payments-ca"),
        http_route("payments-route", "payments", 8443),
        backend_tls_policy_secret("payments-tls", "payments", "payments-ca"),
    ];
    let translated = translate_k8s_objects(&objects, options()).expect("translate");
    let upstream = translated
        .config
        .upstreams
        .first()
        .expect("expected upstream");
    let ca = upstream
        .backend_tls_server_ca_cert_path
        .as_deref()
        .expect("Secret CA should project a k8s:// URI");
    assert!(
        ca.starts_with("k8s://default/payments-ca#ca.crt?sha256="),
        "unexpected CA URI {ca}"
    );
    assert_eq!(
        upstream.backend_tls_sni.as_deref(),
        Some("secret-backend.example.com")
    );
}

#[test]
fn backend_tls_policy_missing_ca_fails_closed_with_fault_route() {
    let objects = vec![
        gateway_class(),
        gateway(),
        service("broken", 8080, "http"),
        http_route("broken-route", "broken", 8080),
        backend_tls_policy_missing_ca("broken-tls", "broken"),
    ];
    let translated = translate_k8s_objects(&objects, options()).expect("translate");
    assert!(
        translated.config.upstreams.is_empty(),
        "invalid BackendTLSPolicy must not create a TLS upstream"
    );
    assert!(
        translated
            .warnings
            .iter()
            .any(|warning| { warning.contains("BackendTLSPolicy") && warning.contains("invalid") }),
        "expected invalid-policy warning, got {:?}",
        translated.warnings
    );
    let proxy = translated
        .config
        .proxies
        .iter()
        .find(|proxy| proxy.listen_path.as_deref() == Some("/api"))
        .expect("fail-closed route should still capture traffic");
    let has_fault_plugin = translated.config.plugin_configs.iter().any(|plugin| {
        plugin.namespace == proxy.namespace
            && plugin.plugin_name == "mesh_route_dispatch"
            && plugin
                .config
                .get("rules")
                .and_then(|rules| rules.as_array())
                .into_iter()
                .flatten()
                .any(|rule| {
                    rule.get("fault")
                        .and_then(|fault| fault.get("abort"))
                        .and_then(|abort| abort.get("body"))
                        .and_then(|body| body.as_str())
                        .is_some_and(|body| body.contains("BackendTLSPolicy"))
                })
    });
    assert!(
        has_fault_plugin,
        "invalid BackendTLSPolicy should materialize an HTTP 500 fault abort"
    );
}

#[test]
fn backend_tls_policy_delete_withdraws_tls_overlay() {
    let with_policy = vec![
        gateway_class(),
        gateway(),
        service("reviews", 8080, "http"),
        http_route("reviews-route", "reviews", 8080),
        backend_tls_policy_system("reviews-tls", "reviews"),
    ];
    let active = translate_k8s_objects(&with_policy, options()).expect("translate with policy");
    assert_eq!(active.config.upstreams.len(), 1);
    assert!(
        active
            .config
            .proxies
            .iter()
            .any(|proxy| proxy.backend_scheme == Some(BackendScheme::Https))
    );

    let without_policy = vec![
        gateway_class(),
        gateway(),
        service("reviews", 8080, "http"),
        http_route("reviews-route", "reviews", 8080),
    ];
    let withdrawn =
        translate_k8s_objects(&without_policy, options()).expect("translate without policy");
    assert!(
        withdrawn.config.upstreams.is_empty(),
        "removing BackendTLSPolicy should restore the direct-backend HTTPRoute shape"
    );
    assert!(
        withdrawn
            .config
            .proxies
            .iter()
            .any(|proxy| proxy.backend_scheme == Some(BackendScheme::Http)
                && proxy.upstream_id.is_none()),
        "withdrawn policy must leave plaintext direct backends"
    );
}

// ---------------------------------------------------------------------------
// Mixed policy-covered / uncovered backend sets (fail closed)
// ---------------------------------------------------------------------------

fn split_http_route(name: &str, backends: &[(&str, u16, u32)]) -> K8sObject {
    let backend_refs: Vec<serde_json::Value> = backends
        .iter()
        .map(|(service, port, weight)| {
            serde_json::json!({ "name": service, "port": port, "weight": weight })
        })
        .collect();
    object(
        "HTTPRoute",
        name,
        serde_json::json!({
            "parentRefs": [{ "name": "edge" }],
            "hostnames": ["split.example.com"],
            "rules": [{
                "matches": [{ "path": { "type": "PathPrefix", "value": "/split" } }],
                "backendRefs": backend_refs
            }]
        }),
    )
}

fn fault_body_mentions(translated: &ferrum_edge::config_sources::k8s::K8sTranslation) -> bool {
    translated.config.plugin_configs.iter().any(|plugin| {
        plugin.plugin_name == "mesh_route_dispatch"
            && plugin
                .config
                .get("rules")
                .and_then(|rules| rules.as_array())
                .into_iter()
                .flatten()
                .any(|rule| {
                    rule.get("fault")
                        .and_then(|fault| fault.get("abort"))
                        .and_then(|abort| abort.get("status"))
                        .and_then(serde_json::Value::as_u64)
                        == Some(500)
                        && rule
                            .get("fault")
                            .and_then(|fault| fault.get("abort"))
                            .and_then(|abort| abort.get("body"))
                            .and_then(|body| body.as_str())
                            .is_some_and(|body| body.contains("BackendTLSPolicy"))
                })
    })
}

#[test]
fn backend_tls_policy_mixed_covered_and_uncovered_backends_fails_closed() {
    let objects = vec![
        gateway_class(),
        gateway(),
        service("reviews", 8080, "http"),
        service("ratings", 8080, "http"),
        split_http_route("split-route", &[("reviews", 8080, 1), ("ratings", 8080, 1)]),
        // Only `reviews` is covered. `ratings` has no policy at all.
        backend_tls_policy_system("reviews-tls", "reviews"),
    ];
    let translated = translate_k8s_objects(&objects, options()).expect("translate");

    assert!(
        translated.config.upstreams.is_empty(),
        "a partially covered backend set must not materialize a TLS upstream: {:?}",
        translated.config.upstreams
    );
    assert!(
        !translated
            .config
            .proxies
            .iter()
            .any(|proxy| proxy.backend_scheme == Some(BackendScheme::Https)),
        "the uncovered Service must never be promoted to HTTPS"
    );
    let warning = translated
        .warnings
        .iter()
        .find(|warning| warning.contains("mixes BackendTLSPolicy-covered and uncovered backends"))
        .unwrap_or_else(|| {
            panic!(
                "expected a field-specific mixed-coverage warning, got {:?}",
                translated.warnings
            )
        });
    assert!(
        warning.contains("spec.rules[].backendRefs"),
        "warning must name the offending field: {warning}"
    );
    assert!(
        warning.contains("Service default/reviews") && warning.contains("Service default/ratings"),
        "warning must identify both sides: {warning}"
    );
    assert!(
        fault_body_mentions(&translated),
        "mixed coverage must materialize an HTTP 500 fault abort"
    );
}

#[test]
fn backend_tls_policy_covering_every_backend_still_applies() {
    let objects = vec![
        gateway_class(),
        gateway(),
        service("reviews", 8080, "http"),
        service("ratings", 8080, "http"),
        split_http_route("split-route", &[("reviews", 8080, 1), ("ratings", 8080, 1)]),
        backend_tls_policy_system("reviews-tls", "reviews"),
        // Byte-identical validation, so both overlays compare equal and the
        // combined upstream carries one unambiguous TLS identity.
        backend_tls_policy_system("ratings-tls", "ratings"),
    ];
    let translated = translate_k8s_objects(&objects, options()).expect("translate");
    let upstream = translated
        .config
        .upstreams
        .first()
        .expect("uniformly covered backends should materialize one TLS upstream");
    assert_eq!(
        upstream.backend_tls_sni.as_deref(),
        Some("backend.example.com")
    );
    assert_eq!(
        upstream.backend_tls_server_ca_cert_path.as_deref(),
        Some(SYSTEM_TRUST_ROOTS_SOURCE)
    );
    assert!(
        translated
            .config
            .proxies
            .iter()
            .any(|proxy| proxy.backend_scheme == Some(BackendScheme::Https))
    );
}

#[test]
fn backend_tls_policy_zero_weight_uncovered_backend_does_not_fail_closed() {
    // A zero-weight backendRef receives no traffic, so it is not part of the
    // effective backend set and must not trip the mixed-coverage guard.
    let objects = vec![
        gateway_class(),
        gateway(),
        service("reviews", 8080, "http"),
        service("ratings", 8080, "http"),
        split_http_route("split-route", &[("reviews", 8080, 1), ("ratings", 8080, 0)]),
        backend_tls_policy_system("reviews-tls", "reviews"),
    ];
    let translated = translate_k8s_objects(&objects, options()).expect("translate");
    assert!(
        !translated
            .warnings
            .iter()
            .any(|warning| warning.contains("mixes BackendTLSPolicy-covered")),
        "zero-weight backends must not trip the mixed-coverage guard: {:?}",
        translated.warnings
    );
    let upstream = translated
        .config
        .upstreams
        .first()
        .expect("expected a TLS upstream for the only traffic-bearing backend");
    assert_eq!(
        upstream.backend_tls_server_ca_cert_path.as_deref(),
        Some(SYSTEM_TRUST_ROOTS_SOURCE)
    );
}

// ---------------------------------------------------------------------------
// targetRefs[].sectionName resolution
// ---------------------------------------------------------------------------

fn multi_port_service(name: &str) -> K8sObject {
    object(
        "Service",
        name,
        serde_json::json!({
            "ports": [
                { "name": "http", "port": 8080, "targetPort": 8080 },
                { "name": "https", "port": 8443, "targetPort": 8443 }
            ]
        }),
    )
}

fn sectioned_policy(name: &str, service_name: &str, section: &str, hostname: &str) -> K8sObject {
    object(
        "BackendTLSPolicy",
        name,
        serde_json::json!({
            "targetRefs": [{
                "group": "",
                "kind": "Service",
                "name": service_name,
                "sectionName": section
            }],
            "validation": {
                "hostname": hostname,
                "wellKnownCACertificates": "System"
            }
        }),
    )
}

#[test]
fn backend_tls_policy_section_name_matches_only_its_service_port() {
    let objects = vec![
        gateway_class(),
        gateway(),
        multi_port_service("api"),
        http_route("api-route", "api", 8443),
        sectioned_policy("api-tls", "api", "https", "secure.example.com"),
    ];
    let translated = translate_k8s_objects(&objects, options()).expect("translate");
    let upstream = translated
        .config
        .upstreams
        .first()
        .expect("sectionName-matched policy should apply");
    assert_eq!(
        upstream.backend_tls_sni.as_deref(),
        Some("secure.example.com")
    );
}

#[test]
fn backend_tls_policy_section_name_mismatch_leaves_backend_plaintext() {
    let objects = vec![
        gateway_class(),
        gateway(),
        multi_port_service("api"),
        // Route targets the `http` (8080) port; the policy is scoped to `https`.
        http_route("api-route", "api", 8080),
        sectioned_policy("api-tls", "api", "https", "secure.example.com"),
    ];
    let translated = translate_k8s_objects(&objects, options()).expect("translate");
    assert!(
        translated.config.upstreams.is_empty(),
        "a sectionName-scoped policy must not apply to a different Service port"
    );
    assert!(
        translated
            .config
            .proxies
            .iter()
            .any(|proxy| proxy.backend_scheme == Some(BackendScheme::Http)),
        "the unmatched port must stay plaintext"
    );
}

#[test]
fn backend_tls_policy_section_scoped_wins_over_unscoped_for_its_port() {
    let objects = vec![
        gateway_class(),
        gateway(),
        multi_port_service("api"),
        http_route("api-route", "api", 8443),
        sectioned_policy("api-tls-https", "api", "https", "secure.example.com"),
        backend_tls_policy_system("api-tls-any", "api"),
    ];
    let translated = translate_k8s_objects(&objects, options()).expect("translate");
    let upstream = translated
        .config
        .upstreams
        .first()
        .expect("expected an upstream");
    assert_eq!(
        upstream.backend_tls_sni.as_deref(),
        Some("secure.example.com"),
        "the port-scoped policy must win over the Service-wide one"
    );
}

// ---------------------------------------------------------------------------
// status.ancestors
// ---------------------------------------------------------------------------

fn policy_status_update(objects: &[K8sObject], name: &str) -> Option<GatewayApiStatusUpdate> {
    let translated = translate_k8s_objects(objects, options()).expect("translate");
    plan_gateway_api_status_updates(objects, options(), &translated.route_conflicts)
        .into_iter()
        .find(|update| update.kind == "BackendTLSPolicy" && update.name == name)
}

fn ferrum_ancestors(update: &GatewayApiStatusUpdate) -> Vec<Value> {
    update
        .status
        .get("ancestors")
        .and_then(Value::as_array)
        .expect("status.ancestors must be written")
        .iter()
        .filter(|ancestor| {
            ancestor.get("controllerName").and_then(Value::as_str)
                == Some(FERRUM_GATEWAY_CONTROLLER_NAME)
        })
        .cloned()
        .collect()
}

fn condition<'a>(ancestor: &'a Value, condition_type: &str) -> &'a Value {
    ancestor
        .get("conditions")
        .and_then(Value::as_array)
        .expect("conditions")
        .iter()
        .find(|condition| condition.get("type").and_then(Value::as_str) == Some(condition_type))
        .unwrap_or_else(|| panic!("missing {condition_type} condition in {ancestor}"))
}

#[test]
fn backend_tls_policy_status_reports_accepted_ancestor_gateway() {
    let objects = vec![
        gateway_class(),
        gateway(),
        service("reviews", 8080, "http"),
        http_route("reviews-route", "reviews", 8080),
        backend_tls_policy_system("reviews-tls", "reviews"),
    ];
    let update = policy_status_update(&objects, "reviews-tls").expect("policy status update");
    assert_eq!(update.api_version, "gateway.networking.k8s.io/v1");
    assert_eq!(update.namespace, "default");

    let ancestors = ferrum_ancestors(&update);
    assert_eq!(ancestors.len(), 1, "expected exactly one ancestor Gateway");
    let ancestor = &ancestors[0];
    assert_eq!(
        ancestor.get("ancestorRef"),
        Some(&serde_json::json!({
            "group": "gateway.networking.k8s.io",
            "kind": "Gateway",
            "namespace": "default",
            "name": "edge"
        }))
    );
    let accepted = condition(ancestor, "Accepted");
    assert_eq!(accepted.get("status").and_then(Value::as_str), Some("True"));
    assert_eq!(
        accepted.get("reason").and_then(Value::as_str),
        Some("Accepted")
    );
    let resolved = condition(ancestor, "ResolvedRefs");
    assert_eq!(resolved.get("status").and_then(Value::as_str), Some("True"));
    assert_eq!(
        resolved.get("reason").and_then(Value::as_str),
        Some("ResolvedRefs")
    );
}

#[test]
fn backend_tls_policy_status_reports_invalid_ca_certificate_ref() {
    let objects = vec![
        gateway_class(),
        gateway(),
        service("broken", 8080, "http"),
        http_route("broken-route", "broken", 8080),
        backend_tls_policy_missing_ca("broken-tls", "broken"),
    ];
    let update = policy_status_update(&objects, "broken-tls").expect("policy status update");
    let ancestors = ferrum_ancestors(&update);
    assert_eq!(ancestors.len(), 1);
    let ancestor = &ancestors[0];

    let accepted = condition(ancestor, "Accepted");
    assert_eq!(
        accepted.get("status").and_then(Value::as_str),
        Some("False")
    );
    assert_eq!(
        accepted.get("reason").and_then(Value::as_str),
        Some("NoValidCACertificate")
    );
    let resolved = condition(ancestor, "ResolvedRefs");
    assert_eq!(
        resolved.get("status").and_then(Value::as_str),
        Some("False")
    );
    assert_eq!(
        resolved.get("reason").and_then(Value::as_str),
        Some("InvalidCACertificateRef"),
        "a missing ConfigMap CA is a reference failure, not a body failure"
    );
    let message = resolved
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert!(
        message.contains("caCertificateRefs[0]") && message.contains("default/missing-ca"),
        "message must be field-specific: {message}"
    );
}

#[test]
fn backend_tls_policy_status_marks_precedence_loser_conflicted() {
    let mut older = backend_tls_policy_system("a-older", "reviews");
    older.metadata.creation_timestamp = Some("2026-01-01T00:00:00Z".to_string());
    older.spec["validation"]["hostname"] = serde_json::json!("older.example.com");
    let mut newer = backend_tls_policy_system("b-newer", "reviews");
    newer.metadata.creation_timestamp = Some("2026-01-02T00:00:00Z".to_string());
    newer.spec["validation"]["hostname"] = serde_json::json!("newer.example.com");
    let objects = vec![
        gateway_class(),
        gateway(),
        service("reviews", 8080, "http"),
        http_route("reviews-route", "reviews", 8080),
        newer,
        older,
    ];

    let translated = translate_k8s_objects(&objects, options()).expect("translate");
    let upstream = translated
        .config
        .upstreams
        .first()
        .expect("the precedence winner must still materialize TLS");
    assert_eq!(
        upstream.backend_tls_sni.as_deref(),
        Some("older.example.com"),
        "runtime and status must use the same oldest-policy winner"
    );

    let newer_update = policy_status_update(&objects, "b-newer").expect("loser status update");
    let newer_ancestors = ferrum_ancestors(&newer_update);
    let accepted = condition(&newer_ancestors[0], "Accepted");
    assert_eq!(
        accepted.get("status").and_then(Value::as_str),
        Some("False")
    );
    assert_eq!(
        accepted.get("reason").and_then(Value::as_str),
        Some("Conflicted")
    );

    let older_update = policy_status_update(&objects, "a-older").expect("winner status update");
    let older_ancestors = ferrum_ancestors(&older_update);
    assert_eq!(
        condition(&older_ancestors[0], "Accepted")
            .get("status")
            .and_then(Value::as_str),
        Some("True")
    );
}

#[test]
fn backend_tls_policy_status_reports_invalid_target_reference_kind() {
    let mut policy = backend_tls_policy_system("bad-target", "reviews");
    policy.spec["targetRefs"][0]["kind"] = serde_json::json!("Deployment");
    let translated = translate_k8s_objects(&[policy], options()).expect("translate");
    let status = translated
        .backend_tls_policy_statuses
        .first()
        .expect("policy status projection");
    assert!(!status.accepted);
    assert_eq!(status.accepted_reason, "Invalid");
    assert!(!status.resolved_refs);
    assert_eq!(status.resolved_refs_reason, "InvalidKind");
}

#[test]
fn backend_tls_policy_status_reports_cross_namespace_target_as_ref_not_permitted() {
    let mut policy = backend_tls_policy_system("cross-ns-target", "reviews");
    policy.spec["targetRefs"][0]["namespace"] = serde_json::json!("other");
    let translated = translate_k8s_objects(&[policy], options()).expect("translate");
    let status = translated
        .backend_tls_policy_statuses
        .first()
        .expect("policy status projection");
    assert!(!status.accepted);
    assert_eq!(status.accepted_reason, "Invalid");
    assert!(!status.resolved_refs);
    assert_eq!(status.resolved_refs_reason, "RefNotPermitted");
}

#[test]
fn backend_tls_policy_rejects_unrepresentable_or_malformed_optional_shapes() {
    let cases = [
        (
            "multiple-targets",
            serde_json::json!({
                "targetRefs": [
                    {"group": "", "kind": "Service", "name": "reviews"},
                    {"group": "", "kind": "Service", "name": "ratings"}
                ],
                "validation": {
                    "hostname": "backend.example.com",
                    "wellKnownCACertificates": "System"
                }
            }),
            "exactly one entry",
        ),
        (
            "empty-section",
            serde_json::json!({
                "targetRefs": [{
                    "group": "", "kind": "Service", "name": "reviews", "sectionName": ""
                }],
                "validation": {
                    "hostname": "backend.example.com",
                    "wellKnownCACertificates": "System"
                }
            }),
            "sectionName must not be empty",
        ),
        (
            "malformed-sans",
            serde_json::json!({
                "targetRefs": [{"group": "", "kind": "Service", "name": "reviews"}],
                "validation": {
                    "hostname": "backend.example.com",
                    "wellKnownCACertificates": "System",
                    "subjectAltNames": {"type": "Hostname", "hostname": "backend.example.com"}
                }
            }),
            "subjectAltNames must be an array",
        ),
        (
            "unsupported-options",
            serde_json::json!({
                "targetRefs": [{"group": "", "kind": "Service", "name": "reviews"}],
                "validation": {
                    "hostname": "backend.example.com",
                    "wellKnownCACertificates": "System"
                },
                "options": {"example.com/min-version": "TLS1.3"}
            }),
            "spec.options is not supported",
        ),
    ];

    for (name, spec, diagnostic) in cases {
        let objects = vec![
            gateway_class(),
            gateway(),
            service("reviews", 8080, "http"),
            service("ratings", 8080, "http"),
            http_route("reviews-route", "reviews", 8080),
            object("BackendTLSPolicy", name, spec),
        ];
        let translated = translate_k8s_objects(&objects, options()).expect("translate");
        assert!(
            translated
                .warnings
                .iter()
                .any(|warning| warning.contains(diagnostic)),
            "{name} must fail with a field-specific diagnostic: {:?}",
            translated.warnings
        );
        assert!(
            fault_body_mentions(&translated),
            "{name} must retain the affected route as a fail-closed HTTP 500 rather than silently broadening to plaintext"
        );
    }
}

#[test]
fn backend_tls_policy_status_never_exceeds_sixteen_ancestors() {
    let mut objects = vec![gateway_class(), service("reviews", 8080, "http")];
    for index in 0..17 {
        let gateway_name = format!("edge-{index:02}");
        let mut gateway = gateway();
        gateway.metadata.name = gateway_name.clone();
        let mut route = http_route(&format!("route-{index:02}"), "reviews", 8080);
        route.spec["parentRefs"][0]["name"] = serde_json::json!(gateway_name);
        route.spec["hostnames"][0] = serde_json::json!(format!("reviews-{index:02}.example.com"));
        objects.push(gateway);
        objects.push(route);
    }
    objects.push(backend_tls_policy_system("reviews-tls", "reviews"));

    let update = policy_status_update(&objects, "reviews-tls").expect("policy status update");
    assert_eq!(
        update
            .status
            .get("ancestors")
            .and_then(Value::as_array)
            .expect("ancestors")
            .len(),
        16,
        "Gateway API PolicyStatus has a hard MaxItems=16 contract"
    );
}

#[test]
fn backend_tls_policy_status_reports_unrepresentable_policy_as_invalid_only() {
    let mut policy = backend_tls_policy_system("bad-tls", "reviews");
    policy.spec["validation"]["wellKnownCACertificates"] = serde_json::json!("Unknown");
    let objects = vec![
        gateway_class(),
        gateway(),
        service("reviews", 8080, "http"),
        http_route("reviews-route", "reviews", 8080),
        policy,
    ];
    let update = policy_status_update(&objects, "bad-tls").expect("policy status update");
    let ancestors = ferrum_ancestors(&update);
    let ancestor = &ancestors[0];
    assert_eq!(
        condition(ancestor, "Accepted")
            .get("reason")
            .and_then(Value::as_str),
        Some("Invalid")
    );
    // The references were fine; only the policy body was unrepresentable.
    let resolved = condition(ancestor, "ResolvedRefs");
    assert_eq!(resolved.get("status").and_then(Value::as_str), Some("True"));
    assert_eq!(
        resolved.get("reason").and_then(Value::as_str),
        Some("ResolvedRefs")
    );
}

#[test]
fn backend_tls_policy_status_reports_target_not_found_when_service_is_absent() {
    // The route still names `reviews` (so the managed Gateway is an ancestor),
    // but no Service object exists, so the policy's targetRef never resolves.
    let objects = vec![
        gateway_class(),
        gateway(),
        http_route("reviews-route", "reviews", 8080),
        backend_tls_policy_system("reviews-tls", "reviews"),
    ];
    let update = policy_status_update(&objects, "reviews-tls").expect("policy status update");
    let ancestors = ferrum_ancestors(&update);
    assert_eq!(ancestors.len(), 1);
    let accepted = condition(&ancestors[0], "Accepted");
    assert_eq!(
        accepted.get("status").and_then(Value::as_str),
        Some("False")
    );
    assert_eq!(
        accepted.get("reason").and_then(Value::as_str),
        Some("TargetNotFound")
    );
}

#[test]
fn backend_tls_policy_status_preserves_third_party_ancestors_and_transition_times() {
    let mut policy = backend_tls_policy_system("reviews-tls", "reviews");
    policy.metadata.generation = Some(3);
    // Live status: one third-party ancestor Ferrum must never touch, plus a
    // stale Ferrum ancestor whose `Accepted` value is about to change and whose
    // `ResolvedRefs` value is not.
    policy.status = serde_json::json!({
        "ancestors": [
            {
                "ancestorRef": {
                    "group": "gateway.networking.k8s.io",
                    "kind": "Gateway",
                    "namespace": "default",
                    "name": "edge"
                },
                "controllerName": "example.com/other-controller",
                "conditions": [{
                    "type": "Accepted",
                    "status": "False",
                    "observedGeneration": 3,
                    "reason": "Invalid",
                    "message": "another controller's verdict",
                    "lastTransitionTime": "2020-01-01T00:00:00Z"
                }]
            },
            {
                "ancestorRef": {
                    "group": "gateway.networking.k8s.io",
                    "kind": "Gateway",
                    "namespace": "default",
                    "name": "edge"
                },
                "controllerName": FERRUM_GATEWAY_CONTROLLER_NAME,
                "conditions": [
                    {
                        "type": "Accepted",
                        "status": "False",
                        "observedGeneration": 2,
                        "reason": "Invalid",
                        "message": "a stale rejection",
                        "lastTransitionTime": "2021-02-03T04:05:06Z"
                    },
                    {
                        "type": "ResolvedRefs",
                        "status": "True",
                        "observedGeneration": 2,
                        "reason": "ResolvedRefs",
                        "message": "All BackendTLSPolicy references accepted by Ferrum",
                        "lastTransitionTime": "2021-02-03T04:05:06Z"
                    }
                ]
            }
        ]
    });
    let objects = vec![
        gateway_class(),
        gateway(),
        service("reviews", 8080, "http"),
        http_route("reviews-route", "reviews", 8080),
        policy,
    ];

    let update = policy_status_update(&objects, "reviews-tls").expect("policy status update");
    let all = update
        .status
        .get("ancestors")
        .and_then(Value::as_array)
        .expect("ancestors");
    assert_eq!(
        all.iter()
            .filter(|ancestor| {
                ancestor.get("controllerName").and_then(Value::as_str)
                    == Some("example.com/other-controller")
            })
            .count(),
        1,
        "a third-party controller's ancestor for the same Gateway must be preserved verbatim: {all:?}"
    );

    let ferrum = ferrum_ancestors(&update);
    assert_eq!(ferrum.len(), 1);
    let accepted = condition(&ferrum[0], "Accepted");
    assert_eq!(accepted.get("status").and_then(Value::as_str), Some("True"));
    assert_ne!(
        accepted.get("lastTransitionTime").and_then(Value::as_str),
        Some("2021-02-03T04:05:06Z"),
        "a changed condition must get a fresh transition time"
    );
    let resolved = condition(&ferrum[0], "ResolvedRefs");
    assert_eq!(
        resolved.get("lastTransitionTime").and_then(Value::as_str),
        Some("2021-02-03T04:05:06Z"),
        "an unchanged condition must keep its transition time"
    );
    assert_eq!(
        resolved.get("observedGeneration").and_then(Value::as_u64),
        Some(3),
        "observedGeneration must advance to the live spec generation"
    );
}

#[test]
fn backend_tls_policy_without_managed_ancestor_gets_no_status_update() {
    // No route reaches the Service, so no managed Gateway is an ancestor and
    // Ferrum must not claim policy status it cannot be responsible for.
    let objects = vec![
        gateway_class(),
        gateway(),
        service("orphan", 8080, "http"),
        backend_tls_policy_system("orphan-tls", "orphan"),
    ];
    assert!(policy_status_update(&objects, "orphan-tls").is_none());
}

#[test]
fn backend_tls_policy_both_ca_sources_fails_closed() {
    let mut policy = backend_tls_policy_system("bad-tls", "reviews");
    policy.spec["validation"]["caCertificateRefs"] = serde_json::json!([{
        "group": "",
        "kind": "ConfigMap",
        "name": "auth-cert"
    }]);
    let objects = vec![
        gateway_class(),
        gateway(),
        service("reviews", 8080, "http"),
        ca_configmap("auth-cert"),
        http_route("reviews-route", "reviews", 8080),
        policy,
    ];
    let translated = translate_k8s_objects(&objects, options()).expect("translate");
    assert!(translated.warnings.iter().any(|warning| {
        warning.contains("must not set both caCertificateRefs and wellKnownCACertificates")
    }));
    assert!(translated.config.upstreams.is_empty());
}
