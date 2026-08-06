//! Gateway API multi-certificate frontend TLS translation (issues #3267/#3268).
//!
//! Covers the translator's decisions over a whole snapshot: which certificates
//! a namespace ends up serving, which listener wins an SNI hostname collision,
//! which certificate is the deterministic fallback, and how reload/delete and
//! Secret rotation move that set. The runtime half — actually selecting a
//! certificate per ClientHello — lives in
//! `tests/integration/gateway_multi_cert_sni_tests.rs`.

use base64::Engine as _;
use ferrum_edge::config::types::{
    GatewayConfig, MAX_FRONTEND_TLS_CERTIFICATE_SOURCES, default_namespace,
};
use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslation, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use serde_json::{Value, json};
use std::collections::HashMap;

fn options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        default_namespace(),
        TrustDomain::new("cluster.local").expect("test trust domain"),
    )
}

fn object(kind: &str, namespace: &str, name: &str, spec: Value) -> K8sObject {
    K8sObject {
        api_version: if kind == "Secret" {
            "v1".to_string()
        } else {
            "gateway.networking.k8s.io/v1".to_string()
        },
        kind: kind.to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            uid: String::new(),
            namespace: namespace.to_string(),
            generation: Some(1),
            labels: HashMap::new(),
            annotations: HashMap::new(),
            creation_timestamp: None,
            deletion_timestamp: None,
        },
        spec,
        status: Value::Object(serde_json::Map::new()),
    }
}

fn created_at(mut object: K8sObject, timestamp: &str) -> K8sObject {
    object.metadata.creation_timestamp = Some(timestamp.to_string());
    object
}

fn tls_secret(name: &str, namespace: &str) -> K8sObject {
    object(
        "Secret",
        namespace,
        name,
        json!({
            "type": "kubernetes.io/tls",
            "data": {
                "tls.crt": base64::engine::general_purpose::STANDARD
                    .encode(include_str!("../../certs/server.crt")),
                "tls.key": base64::engine::general_purpose::STANDARD
                    .encode(include_str!("../../certs/server.key")),
            }
        }),
    )
}

/// Same Secret name, a different but equally VALID pair — the shape a
/// cert-manager rotation takes. Rotating to invalid bytes would only prove the
/// fail-closed path, not that a valid rotation moves the source digest.
fn rotated_tls_secret(name: &str, namespace: &str) -> K8sObject {
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("key pair");
    let params = rcgen::CertificateParams::new(vec!["rotated.example.com".to_string()])
        .expect("certificate params");
    let certificate = params.self_signed(&key_pair).expect("self-signed cert");
    let mut secret = tls_secret(name, namespace);
    let encode = base64::engine::general_purpose::STANDARD;
    secret.spec["data"]["tls.crt"] = json!(encode.encode(certificate.pem()));
    secret.spec["data"]["tls.key"] = json!(encode.encode(key_pair.serialize_pem()));
    secret
}

fn https_listener(name: &str, port: u64, hostname: Option<&str>, secrets: &[&str]) -> Value {
    let mut listener = json!({
        "name": name,
        "port": port,
        "protocol": "HTTPS",
        "tls": {
            "certificateRefs": secrets
                .iter()
                .map(|secret| json!({"name": secret}))
                .collect::<Vec<_>>()
        },
        "allowedRoutes": {"namespaces": {"from": "All"}}
    });
    if let Some(hostname) = hostname {
        listener["hostname"] = json!(hostname);
    }
    listener
}

fn gateway(namespace: &str, name: &str, listeners: Vec<Value>) -> K8sObject {
    object(
        "Gateway",
        namespace,
        name,
        json!({"gatewayClassName": "ferrum", "listeners": listeners}),
    )
}

fn route(namespace: &str, name: &str, gateway: &str, section: &str, path: &str) -> K8sObject {
    object(
        "HTTPRoute",
        namespace,
        name,
        json!({
            "parentRefs": [{"name": gateway, "sectionName": section}],
            "rules": [{
                "matches": [{"path": {"type": "PathPrefix", "value": path}}],
                "backendRefs": [{"name": "backend", "port": 8080}]
            }]
        }),
    )
}

fn translate(objects: &[K8sObject]) -> K8sTranslation {
    translate_k8s_objects(objects, options()).expect("translation succeeds")
}

fn cert_paths(config: &GatewayConfig) -> Vec<String> {
    config
        .frontend_tls_certificate_sources
        .iter()
        .map(|source| source.cert_path.clone())
        .collect()
}

#[test]
fn one_listener_serves_every_certificate_ref() {
    let result = translate(&[
        gateway(
            "ferrum",
            "edge",
            vec![https_listener(
                "https",
                443,
                None,
                &["rsa-cert", "ecdsa-cert"],
            )],
        ),
        tls_secret("rsa-cert", "ferrum"),
        tls_secret("ecdsa-cert", "ferrum"),
    ]);

    assert_eq!(result.config.frontend_tls_certificate_sources.len(), 2);
    assert!(
        cert_paths(&result.config)
            .iter()
            .any(|path| path.starts_with("k8s://ferrum/rsa-cert#tls.crt?sha256="))
    );
    assert!(
        cert_paths(&result.config)
            .iter()
            .any(|path| path.starts_with("k8s://ferrum/ecdsa-cert#tls.crt?sha256="))
    );
    assert!(
        result
            .config
            .frontend_tls_certificate_sources
            .iter()
            .all(|source| source.gateway == "edge" && source.listener == "https")
    );
}

#[test]
fn independent_gateways_in_one_namespace_each_keep_their_certificate() {
    let result = translate(&[
        gateway(
            "ferrum",
            "edge-a",
            vec![https_listener(
                "https",
                443,
                Some("a.example.com"),
                &["cert-a"],
            )],
        ),
        gateway(
            "ferrum",
            "edge-b",
            vec![https_listener(
                "https",
                8443,
                Some("b.example.com"),
                &["cert-b"],
            )],
        ),
        tls_secret("cert-a", "ferrum"),
        tls_secret("cert-b", "ferrum"),
        route("ferrum", "route-a", "edge-a", "https", "/a"),
        route("ferrum", "route-b", "edge-b", "https", "/b"),
    ]);

    assert_eq!(result.config.frontend_tls_certificate_sources.len(), 2);
    let gateways: Vec<&str> = result
        .config
        .frontend_tls_certificate_sources
        .iter()
        .map(|source| source.gateway.as_str())
        .collect();
    assert!(gateways.contains(&"edge-a") && gateways.contains(&"edge-b"));

    // Both listeners serve route traffic; issue #3268's symptom was the second
    // Gateway keeping status while its routes stayed unmaterialized.
    for route_name in ["route-a", "route-b"] {
        assert!(
            result
                .config
                .proxies
                .iter()
                .any(|proxy| proxy.id.contains(route_name)),
            "{route_name} should be materialized"
        );
    }
    assert!(
        !result
            .warnings
            .iter()
            .any(|warning| warning.contains("unmaterialized"))
    );
}

#[test]
fn listener_hostname_and_default_marker_are_deterministic() {
    let result = translate(&[
        gateway(
            "ferrum",
            "edge",
            vec![
                https_listener("named", 443, Some("API.Example.COM."), &["named-cert"]),
                https_listener("catch-all", 8443, None, &["catch-all-cert"]),
            ],
        ),
        tls_secret("named-cert", "ferrum"),
        tls_secret("catch-all-cert", "ferrum"),
    ]);

    let named = result
        .config
        .frontend_tls_certificate_sources
        .iter()
        .find(|source| source.listener == "named")
        .expect("named listener retained");
    // Hostnames are normalized the same way route hostnames are: trailing dot
    // stripped, ASCII-lowercased.
    assert_eq!(named.hostname.as_deref(), Some("api.example.com"));
    assert!(!named.default_certificate);

    let catch_all = result
        .config
        .frontend_tls_certificate_sources
        .iter()
        .find(|source| source.listener == "catch-all")
        .expect("catch-all listener retained");
    assert_eq!(catch_all.hostname, None);
    assert!(
        catch_all.default_certificate,
        "a catch-all listener takes the fallback slot over a hostname-scoped one"
    );
    assert_eq!(
        result.config.frontend_tls_cert_path.as_deref(),
        Some(catch_all.cert_path.as_str()),
        "the legacy fallback projection tracks the marked default"
    );
}

#[test]
fn hostname_collision_fails_the_younger_listener_closed() {
    let older = created_at(
        gateway(
            "ferrum",
            "edge-old",
            vec![https_listener(
                "https",
                443,
                Some("shop.example.com"),
                &["cert-a"],
            )],
        ),
        "2026-01-01T00:00:00Z",
    );
    let younger = created_at(
        gateway(
            "ferrum",
            "edge-new",
            vec![https_listener(
                "https",
                8443,
                Some("shop.example.com"),
                &["cert-b"],
            )],
        ),
        "2026-06-01T00:00:00Z",
    );

    let result = translate(&[
        // Deliberately listed younger-first: the winner must come from the
        // creation timestamp, never from informer/list order.
        younger,
        older,
        tls_secret("cert-a", "ferrum"),
        tls_secret("cert-b", "ferrum"),
        route("ferrum", "route-old", "edge-old", "https", "/"),
        route("ferrum", "route-new", "edge-new", "https", "/new"),
    ]);

    assert_eq!(result.config.frontend_tls_certificate_sources.len(), 1);
    assert_eq!(
        result.config.frontend_tls_certificate_sources[0].gateway, "edge-old",
        "the older Gateway wins the contested hostname"
    );
    assert!(
        result
            .warnings
            .iter()
            .any(|warning| warning.contains("edge-new")
                && warning.contains("shop.example.com")
                && warning.contains("unmaterialized"))
    );
    assert!(
        result
            .config
            .proxies
            .iter()
            .all(|proxy| !proxy.id.contains("route-new")),
        "the losing listener must not serve route traffic under an ambiguous certificate"
    );
}

#[test]
fn identical_certificate_on_one_hostname_is_not_a_collision() {
    let result = translate(&[
        gateway(
            "ferrum",
            "edge-a",
            vec![https_listener(
                "https",
                443,
                Some("shop.example.com"),
                &["shared-cert"],
            )],
        ),
        gateway(
            "ferrum",
            "edge-b",
            vec![https_listener(
                "https",
                8443,
                Some("shop.example.com"),
                &["shared-cert"],
            )],
        ),
        tls_secret("shared-cert", "ferrum"),
    ]);

    assert_eq!(result.config.frontend_tls_certificate_sources.len(), 2);
    assert!(
        !result
            .warnings
            .iter()
            .any(|warning| warning.contains("already served with a different certificate"))
    );
}

#[test]
fn catch_all_listeners_with_different_certificates_do_not_collide() {
    let result = translate(&[
        gateway(
            "ferrum",
            "edge-a",
            vec![https_listener("https", 443, None, &["cert-a"])],
        ),
        gateway(
            "ferrum",
            "edge-b",
            vec![https_listener("https", 8443, None, &["cert-b"])],
        ),
        tls_secret("cert-a", "ferrum"),
        tls_secret("cert-b", "ferrum"),
    ]);

    assert_eq!(result.config.frontend_tls_certificate_sources.len(), 2);
    assert_eq!(
        result
            .config
            .frontend_tls_certificate_sources
            .iter()
            .filter(|source| source.default_certificate)
            .count(),
        1,
        "one namespace has exactly one fallback certificate"
    );
}

#[test]
fn one_unresolved_reference_withdraws_only_its_own_listener() {
    let result = translate(&[
        gateway(
            "ferrum",
            "edge",
            vec![
                https_listener("good", 443, Some("good.example.com"), &["good-cert"]),
                // Second ref never exists: the whole listener fails closed
                // rather than serving a partial set.
                https_listener(
                    "partial",
                    8443,
                    Some("partial.example.com"),
                    &["good-cert", "missing-cert"],
                ),
            ],
        ),
        tls_secret("good-cert", "ferrum"),
    ]);

    assert_eq!(result.config.frontend_tls_certificate_sources.len(), 1);
    assert_eq!(
        result.config.frontend_tls_certificate_sources[0].listener,
        "good"
    );
    assert!(result.warnings.iter().any(|warning| {
        warning.contains("spec.listeners[].tls.certificateRefs") && warning.contains("partial")
    }));
}

#[test]
fn cross_namespace_secret_requires_a_reference_grant() {
    let gateway_object = gateway(
        "ferrum",
        "edge",
        vec![json!({
            "name": "https",
            "port": 443,
            "protocol": "HTTPS",
            "tls": {"certificateRefs": [{"name": "shared-cert", "namespace": "certs"}]}
        })],
    );
    let secret = tls_secret("shared-cert", "certs");
    let grant = object(
        "ReferenceGrant",
        "certs",
        "allow-edge",
        json!({
            "from": [{
                "group": "gateway.networking.k8s.io",
                "kind": "Gateway",
                "namespace": "ferrum"
            }],
            "to": [{"group": "", "kind": "Secret", "name": "shared-cert"}]
        }),
    );
    fn namespaces() -> K8sTranslationOptions {
        options().with_source_namespaces(vec!["ferrum".to_string(), "certs".to_string()])
    }

    let denied = translate_k8s_objects(&[gateway_object.clone(), secret.clone()], namespaces())
        .expect("translation succeeds");
    assert!(
        denied.config.frontend_tls_certificate_sources.is_empty(),
        "an unauthorized cross-namespace Secret must not be served"
    );

    let allowed = translate_k8s_objects(&[gateway_object, secret, grant], namespaces())
        .expect("translation succeeds");
    assert_eq!(allowed.config.frontend_tls_certificate_sources.len(), 1);
    assert!(
        allowed.config.frontend_tls_certificate_sources[0]
            .cert_path
            .starts_with("k8s://certs/shared-cert#tls.crt?sha256=")
    );
    assert_eq!(
        allowed.config.frontend_tls_certificate_sources[0].namespace, "ferrum",
        "ownership is the Gateway's namespace, never the Secret's"
    );
}

#[test]
fn secret_rotation_changes_only_the_rotated_certificate_source() {
    let objects = |rotate_b: bool| {
        vec![
            gateway(
                "ferrum",
                "edge",
                vec![
                    https_listener("a", 443, Some("a.example.com"), &["cert-a"]),
                    https_listener("b", 8443, Some("b.example.com"), &["cert-b"]),
                ],
            ),
            tls_secret("cert-a", "ferrum"),
            if rotate_b {
                rotated_tls_secret("cert-b", "ferrum")
            } else {
                tls_secret("cert-b", "ferrum")
            },
        ]
    };

    let before = translate(&objects(false));
    let after = translate(&objects(true));

    let source_for = |result: &K8sTranslation, listener: &str| {
        result
            .config
            .frontend_tls_certificate_sources
            .iter()
            .find(|source| source.listener == listener)
            .map(|source| source.cert_path.clone())
    };

    assert!(
        source_for(&after, "b").is_some(),
        "the rotated Secret stays valid"
    );
    assert_eq!(
        source_for(&before, "a"),
        source_for(&after, "a"),
        "an untouched certificate keeps its stable source string"
    );
    assert_ne!(
        source_for(&before, "b"),
        source_for(&after, "b"),
        "a rotated Secret must change its own source digest so the CP broadcasts it"
    );
}

#[test]
fn deleting_one_gateway_withdraws_only_its_own_certificates() {
    let all = translate(&[
        gateway(
            "ferrum",
            "edge-a",
            vec![https_listener(
                "https",
                443,
                Some("a.example.com"),
                &["cert-a"],
            )],
        ),
        gateway(
            "ferrum",
            "edge-b",
            vec![https_listener(
                "https",
                8443,
                Some("b.example.com"),
                &["cert-b"],
            )],
        ),
        tls_secret("cert-a", "ferrum"),
        tls_secret("cert-b", "ferrum"),
    ]);
    assert_eq!(all.config.frontend_tls_certificate_sources.len(), 2);

    // Reload with edge-b gone; edge-a's certificate is untouched.
    let remaining = translate(&[
        gateway(
            "ferrum",
            "edge-a",
            vec![https_listener(
                "https",
                443,
                Some("a.example.com"),
                &["cert-a"],
            )],
        ),
        tls_secret("cert-a", "ferrum"),
        tls_secret("cert-b", "ferrum"),
    ]);
    assert_eq!(remaining.config.frontend_tls_certificate_sources.len(), 1);
    assert_eq!(
        remaining.config.frontend_tls_certificate_sources[0].gateway,
        "edge-a"
    );

    // Reload with every Gateway gone: nothing is left to serve.
    let none = translate(&[tls_secret("cert-a", "ferrum")]);
    assert!(none.config.frontend_tls_certificate_sources.is_empty());
    assert_eq!(none.config.frontend_tls_cert_path, None);
    assert_eq!(none.config.frontend_tls_key_path, None);
}

#[test]
fn snapshot_certificate_count_is_capped() {
    let mut objects = vec![tls_secret("cert", "ferrum")];
    let listeners: Vec<Value> = (0..MAX_FRONTEND_TLS_CERTIFICATE_SOURCES + 5)
        .map(|index| {
            https_listener(
                &format!("listener-{index}"),
                (10000 + index) as u64,
                Some(&format!("host-{index}.example.com")),
                &["cert"],
            )
        })
        .collect();
    objects.push(gateway("ferrum", "edge", listeners));

    let result = translate(&objects);

    assert_eq!(
        result.config.frontend_tls_certificate_sources.len(),
        MAX_FRONTEND_TLS_CERTIFICATE_SOURCES
    );
    assert!(
        result
            .warnings
            .iter()
            .any(|warning| warning.contains("Gateway frontend TLS certificate limit"))
    );
}

#[test]
fn namespace_filter_retains_the_whole_owning_namespace_set() {
    let mut config = translate(&[
        gateway(
            "ferrum",
            "edge",
            vec![https_listener("https", 443, None, &["cert-a", "cert-b"])],
        ),
        tls_secret("cert-a", "ferrum"),
        tls_secret("cert-b", "ferrum"),
    ])
    .config;
    config.frontend_tls_certificate_sources.push(
        ferrum_edge::config::types::FrontendTlsCertificateSource {
            namespace: "other".to_string(),
            gateway: "foreign".to_string(),
            listener: "https".to_string(),
            hostname: Some("foreign.example.com".to_string()),
            cert_path: "k8s://other/foreign#tls.crt".to_string(),
            key_path: "k8s://other/foreign#tls.key".to_string(),
            default_certificate: true,
        },
    );

    let removed = config.filter_frontend_tls_to_namespace("ferrum");

    assert_eq!(removed, 1);
    assert_eq!(config.frontend_tls_certificate_sources.len(), 2);
    assert!(
        config
            .frontend_tls_certificate_sources
            .iter()
            .all(|source| source.namespace == "ferrum"),
        "a data plane must never observe another namespace's certificate"
    );
    assert_eq!(
        config
            .frontend_tls_certificate_sources
            .iter()
            .filter(|source| source.default_certificate)
            .count(),
        1,
        "the fallback marker is re-derived within the retained set"
    );
}

#[test]
fn namespace_filter_withdraws_a_foreign_owned_fallback() {
    let mut config = GatewayConfig {
        frontend_tls_cert_path: Some("k8s://other/foreign#tls.crt".to_string()),
        frontend_tls_key_path: Some("k8s://other/foreign#tls.key".to_string()),
        frontend_tls_source_namespace: Some("other".to_string()),
        ..GatewayConfig::default()
    };

    let removed = config.filter_frontend_tls_to_namespace("ferrum");

    assert_eq!(removed, 1);
    assert_eq!(config.frontend_tls_cert_path, None);
    assert_eq!(config.frontend_tls_key_path, None);
    assert_eq!(config.frontend_tls_source_namespace, None);
}

#[test]
fn namespace_filter_leaves_operator_material_alone() {
    let mut config = GatewayConfig {
        frontend_tls_cert_path: Some("/etc/ferrum/server.crt".to_string()),
        frontend_tls_key_path: Some("/etc/ferrum/server.key".to_string()),
        ..GatewayConfig::default()
    };

    assert_eq!(config.filter_frontend_tls_to_namespace("ferrum"), 0);
    assert_eq!(
        config.frontend_tls_cert_path.as_deref(),
        Some("/etc/ferrum/server.crt"),
        "material with no owning Gateway namespace is the operator's, not a tenant's"
    );
}
