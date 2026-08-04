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
    assert!(
        upstream.backend_tls_server_ca_cert_path.is_none(),
        "System roots leave CA path unset"
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
        .iter()
        .next()
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
        .iter()
        .next()
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
