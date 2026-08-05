//! Istio ServiceEntry + egress materialization conformance.
//!
//! Exercises:
//!   - `ServiceEntry` translation through `translate_k8s_objects`
//!     (`location: MESH_EXTERNAL` vs `MESH_INTERNAL`, multi-port, multi-host).
//!   - Egress gateway materialization of HTTP-family + stream-family
//!     ServiceEntries (T5-A, PR #907) via `prepare_gateway_config_for_mesh`.
//!   - `outboundTrafficPolicy: REGISTRY_ONLY` injects the
//!     `mesh_outbound_registry` plugin on topologies with an outbound capture
//!     listener (T5-B, PR #893).

use std::collections::HashMap;
use std::net::SocketAddr;

use ferrum_edge::capture::CaptureMode;
use ferrum_edge::config::types::{BackendScheme, GatewayConfig};
use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::modes::mesh::config::{
    AppProtocol, MeshConfig, OutboundTrafficPolicy, Resolution, ServiceEntry, ServiceEntryLocation,
    ServicePort,
};
use ferrum_edge::modes::mesh::{
    MESH_OUTBOUND_REGISTRY_PLUGIN_ID, MeshConfigProtocol, MeshRuntimeConfig, MeshTopology,
    prepare_gateway_config_for_mesh,
};
use serde_json::{Value, json};

use crate::conformance::registry::Status;

const CATEGORY: &str = "istio_service_entry_egress";

fn options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("test trust domain"),
    )
}

fn service_entry(name: &str, spec: Value) -> K8sObject {
    K8sObject {
        api_version: "networking.istio.io/v1beta1".to_string(),
        kind: "ServiceEntry".to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            namespace: "default".to_string(),
            ..K8sMetadata::default()
        },
        spec,
        status: Value::Object(serde_json::Map::new()),
    }
}

fn egress_runtime() -> MeshRuntimeConfig {
    MeshRuntimeConfig {
        node_id: "conformance-egress".to_string(),
        namespace: "default".to_string(),
        cp_urls: vec!["http://127.0.0.1:1".to_string()],
        config_protocol: MeshConfigProtocol::Native,
        file_config_path: None,
        topology: MeshTopology::EgressGateway,
        inbound_listen_addr: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
        outbound_listen_addr: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
        hbone_listen_addr: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
        east_west_listen_port: 15443,
        egress_hbone_port: 15008,
        egress_mtls_port: 15006,
        egress_listen_addr: "127.0.0.1:15090".parse::<SocketAddr>().unwrap(),
        workload_spiffe_id: None,
        waypoint_name: None,
        workload_svid_cert_path: None,
        workload_svid_key_path: None,
        workload_svid_trust_bundle_path: None,
        ca_backend: ferrum_edge::identity::ca::CaBackend::None,
        xds_node_cluster: "default".to_string(),
        xds_stream_channel_capacity: 32,
        xds_primary_retry_secs: 300,
        xds_connect_timeout_seconds: 10,
        trust_domain_aliases: Vec::new(),
        trusted_hbone_assertors: Vec::new(),
        workload_labels: HashMap::new(),
        dns_enabled: false,
        dns_listen_addr: "127.0.0.1:15053".parse::<SocketAddr>().unwrap(),
        dns_upstream_addr: "127.0.0.53:53".parse::<SocketAddr>().unwrap(),
        dns_ttl_seconds: 60,
        dns_max_concurrent_queries: 1024,
        dns_response_cache_max_entries: 4096,
        cluster_domain: "cluster.local".to_string(),
        capture_mode: CaptureMode::Explicit,
        outbound_traffic_policy: OutboundTrafficPolicy::AllowAny,
        outbound_registry_reject_status: 502,
        sidecar_enforced: false,
        sidecar_enforced_dry_run: false,
        sidecar_identity_narrowing: false,
        egress_stream_enabled: true,
        egress_stream_allow_plaintext: false,
        request_auth_require_exp: true,
        locality_lb_strict: false,
    }
}

fn sidecar_runtime_with_policy(policy: OutboundTrafficPolicy) -> MeshRuntimeConfig {
    let mut rt = egress_runtime();
    rt.topology = MeshTopology::Sidecar;
    rt.outbound_traffic_policy = policy;
    // mesh_outbound_registry plugin is only injected when at least one
    // outbound capture listener exists (mesh_outbound_registry_listen_ports
    // filters port != 0). Use the documented default sidecar capture port
    // 15001 so the plugin auto-injection path runs.
    rt.outbound_listen_addr = "127.0.0.1:15001".parse::<SocketAddr>().unwrap();
    rt
}

fn external_se(name: &str, hosts: Vec<&str>, port: u16, protocol: &str) -> K8sObject {
    service_entry(
        name,
        json!({
            "hosts": hosts,
            "location": "MESH_EXTERNAL",
            "resolution": "DNS",
            "ports": [{
                "number": port,
                "name": protocol.to_lowercase(),
                "protocol": protocol
            }]
        }),
    )
}

fn build_mesh_config_from(translation_input: &[K8sObject]) -> GatewayConfig {
    let translation =
        translate_k8s_objects(translation_input, options()).expect("translation succeeds");
    translation.config
}

/// `ServiceEntry` with `location: MESH_EXTERNAL` translates with the right
/// location tag.
#[test]
fn se_mesh_external_translates() {
    register_feature!(
        category = CATEGORY,
        feature = "location: MESH_EXTERNAL",
        status = Status::Supported,
        notes = "Marks the entry as eligible for egress gateway materialization.",
    );
    let config =
        build_mesh_config_from(&[external_se("api", vec!["api.external.com"], 443, "TLS")]);
    let mesh = config.mesh.expect("mesh config");
    let se = mesh.service_entries.first().expect("one SE");
    assert_eq!(se.location, ServiceEntryLocation::MeshExternal);
    assert_eq!(se.hosts, vec!["api.external.com".to_string()]);
    assert_eq!(se.ports[0].protocol, AppProtocol::Tls);
}

/// `ServiceEntry` with `location: MESH_INTERNAL` translates with the right
/// tag — and the egress materializer skips it.
#[test]
fn se_mesh_internal_skipped_by_egress() {
    register_feature!(
        category = CATEGORY,
        feature = "location: MESH_INTERNAL skipped by egress materialization",
        status = Status::Supported,
        notes = "Only MESH_EXTERNAL entries materialize as egress proxies; internal entries flow through the registry instead.",
    );
    let translation = translate_k8s_objects(
        &[service_entry(
            "internal",
            json!({
                "hosts": ["api.internal"],
                "location": "MESH_INTERNAL",
                "resolution": "DNS",
                "ports": [{"number": 8080, "name": "http", "protocol": "HTTP"}]
            }),
        )],
        options(),
    )
    .expect("translation succeeds");

    let prepared =
        prepare_gateway_config_for_mesh(translation.config, &egress_runtime()).expect("mesh apply");

    // No egress proxy for the internal entry. (The host `api.internal` would
    // encode into an egress id as `api_dot_internal` under the injective id
    // scheme; assert that token is absent.)
    assert!(
        prepared
            .proxies
            .iter()
            .all(|p| !p.id.contains("api_dot_internal")),
        "MESH_INTERNAL entry must not materialize as an egress proxy"
    );
}

/// HTTP-family ServiceEntry materializes one egress proxy per host on the
/// shared 15090 listener.
#[test]
fn se_http_egress_materializes() {
    register_feature!(
        category = CATEGORY,
        feature = "HTTP-family egress materialization",
        status = Status::Supported,
        notes = "TLS/HTTP/HTTP2/GRPC protocols map to one host-routed HTTP-family proxy on the shared egress listener.",
    );
    let translation = translate_k8s_objects(
        &[external_se("api", vec!["api.external.com"], 443, "TLS")],
        options(),
    )
    .expect("translation succeeds");
    let prepared =
        prepare_gateway_config_for_mesh(translation.config, &egress_runtime()).expect("mesh apply");

    let egress = prepared
        .proxies
        .iter()
        .find(|p| p.id.starts_with("mesh-egress"))
        .expect("HTTP egress proxy materialized");
    assert!(
        egress.hosts.iter().any(|h| h == "api.external.com"),
        "HTTP egress proxy must carry the SE host"
    );
    assert_eq!(egress.backend_scheme, Some(BackendScheme::Https));
    assert!(
        egress.listen_port.is_none(),
        "HTTP-family egress proxies route by host, not port"
    );
}

/// Stream-family ServiceEntry — T5-A (PR #907). `TCP` protocol materializes
/// as a TCP listener on the entry's own destination port.
#[test]
fn se_tcp_egress_materializes_as_stream_proxy() {
    register_feature!(
        category = CATEGORY,
        feature = "TCP ServiceEntry → stream egress proxy (T5-A)",
        status = Status::Supported,
        notes = "T5-A (PR #907): TCP protocols bind their own listen_port; backend_scheme=Tcp; hosts=[].",
    );
    let translation = translate_k8s_objects(
        &[external_se(
            "kafka",
            vec!["kafka.external.com"],
            9092,
            "TCP",
        )],
        options(),
    )
    .expect("translation succeeds");
    let prepared =
        prepare_gateway_config_for_mesh(translation.config, &egress_runtime()).expect("mesh apply");

    let stream = prepared
        .proxies
        .iter()
        .find(|p| p.listen_port == Some(9092))
        .expect("TCP stream egress proxy must bind on the SE port");
    assert_eq!(stream.backend_scheme, Some(BackendScheme::Tcp));
    assert!(stream.hosts.is_empty(), "stream proxies route by port");
    assert!(stream.listen_path.is_none());
}

/// Stream-family ServiceEntry: database protocols (Mongo, Mysql, Postgres,
/// Redis) all map to TCP egress per T5-A. Spot-check Mongo + Postgres.
#[test]
fn se_database_protocols_egress_materialize_as_stream_proxies() {
    register_feature!(
        category = CATEGORY,
        feature = "Mongo/Mysql/Postgres/Redis ServiceEntry → stream egress proxy (T5-A)",
        status = Status::Supported,
        notes = "T5-A (PR #907): each database protocol binds its own listen_port; no protocol-aware wire mediation (T5-C).",
    );
    let translation = translate_k8s_objects(
        &[
            external_se("mongo", vec!["mongo.external.com"], 27017, "MONGO"),
            external_se("pg", vec!["pg.external.com"], 5432, "POSTGRES"),
        ],
        options(),
    )
    .expect("translation succeeds");
    let prepared =
        prepare_gateway_config_for_mesh(translation.config, &egress_runtime()).expect("mesh apply");

    assert!(
        prepared
            .proxies
            .iter()
            .any(|p| p.listen_port == Some(27017)),
        "Mongo egress proxy on 27017"
    );
    assert!(
        prepared.proxies.iter().any(|p| p.listen_port == Some(5432)),
        "Postgres egress proxy on 5432"
    );
}

/// REGISTRY_ONLY policy injects the `mesh_outbound_registry` plugin on
/// Sidecar topology — T5-B (PR #893).
#[test]
fn outbound_traffic_policy_registry_only_injects_plugin() {
    register_feature!(
        category = CATEGORY,
        feature = "outboundTrafficPolicy: REGISTRY_ONLY injects mesh_outbound_registry",
        status = Status::Supported,
        notes = "T5-B (PR #893): plugin is auto-injected on topologies with an outbound capture listener and rejects unknown destinations.",
    );
    let config = GatewayConfig {
        mesh: Some(Box::new(MeshConfig {
            service_entries: vec![ServiceEntry {
                name: "known".to_string(),
                namespace: "default".to_string(),
                hosts: vec!["api.external.com".to_string()],
                endpoints: Vec::new(),
                resolution: Resolution::Dns,
                location: ServiceEntryLocation::MeshExternal,
                ports: vec![ServicePort {
                    port: 443,
                    protocol: AppProtocol::Tls,
                    name: Some("https".to_string()),
                    target_port: None,
                }],
                export_to: Vec::new(),
                workload_selector: None,
            }],
            ..MeshConfig::default()
        })),
        ..GatewayConfig::default()
    };

    let runtime = sidecar_runtime_with_policy(OutboundTrafficPolicy::RegistryOnly);
    let prepared = prepare_gateway_config_for_mesh(config, &runtime).expect("mesh apply succeeds");

    assert!(
        prepared
            .plugin_configs
            .iter()
            .any(|p| p.id == MESH_OUTBOUND_REGISTRY_PLUGIN_ID),
        "REGISTRY_ONLY must inject the mesh_outbound_registry plugin"
    );
}

/// AllowAny policy does NOT inject the registry plugin — default behavior.
#[test]
fn outbound_traffic_policy_allow_any_omits_plugin() {
    register_feature!(
        category = CATEGORY,
        feature = "outboundTrafficPolicy: ALLOW_ANY (default) — no registry plugin",
        status = Status::Supported,
        notes =
            "Default behavior: unknown destinations flow through unblocked when policy=ALLOW_ANY.",
    );
    let config = GatewayConfig {
        mesh: Some(Box::new(MeshConfig::default())),
        ..GatewayConfig::default()
    };
    let runtime = sidecar_runtime_with_policy(OutboundTrafficPolicy::AllowAny);
    let prepared = prepare_gateway_config_for_mesh(config, &runtime).expect("mesh apply succeeds");

    assert!(
        prepared
            .plugin_configs
            .iter()
            .all(|p| p.id != MESH_OUTBOUND_REGISTRY_PLUGIN_ID),
        "ALLOW_ANY must NOT inject the mesh_outbound_registry plugin"
    );
}

/// `ServiceEntry` host normalization: hosts are lowercased at admission per
/// `Proxy.normalize_fields()` invariant.
#[test]
fn se_host_normalization() {
    register_feature!(
        category = CATEGORY,
        feature = "ServiceEntry hosts ASCII-lowercased at admission",
        status = Status::Supported,
        notes = "Hostname normalization invariant (CLAUDE.md Domain Model): ASCII-lowercase at every entry point.",
    );
    let config = build_mesh_config_from(&[external_se("api", vec!["API.EXAMPLE.com"], 443, "TLS")]);
    let se = config.mesh.unwrap().service_entries[0].clone();
    assert_eq!(se.hosts, vec!["api.example.com".to_string()]);
}

/// Istio `Sidecar.outboundTrafficPolicy` overrides the mesh-wide policy for the
/// workloads that `Sidecar` selects — issue #3262.
///
/// Both directions are exercised: a workload-scoped `REGISTRY_ONLY` arms the
/// registry gate over an `ALLOW_ANY` mesh, and a workload-scoped `ALLOW_ANY`
/// disarms it over a `REGISTRY_ONLY` mesh.
#[test]
fn sidecar_outbound_traffic_policy_overrides_the_mesh_wide_policy() {
    register_feature!(
        category = CATEGORY,
        feature = "Sidecar.outboundTrafficPolicy overrides MeshConfig.outboundTrafficPolicy",
        status = Status::Supported,
        notes = "Issue #3262: the applicable Sidecar's mode wins for its selected workloads, in both directions, under FERRUM_MESH_SIDECAR_ENFORCED (dry-run excluded).",
    );

    for (mesh_wide, sidecar_mode, expect_plugin) in [
        (
            OutboundTrafficPolicy::AllowAny,
            OutboundTrafficPolicy::RegistryOnly,
            true,
        ),
        (
            OutboundTrafficPolicy::RegistryOnly,
            OutboundTrafficPolicy::AllowAny,
            false,
        ),
    ] {
        let config = GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                sidecars: vec![ferrum_edge::modes::mesh::config::MeshSidecar {
                    name: "default-sidecar".to_string(),
                    namespace: "default".to_string(),
                    workload_selector: None,
                    egress_inherits_defaults: false,
                    egress: vec![ferrum_edge::modes::mesh::config::MeshSidecarEgress {
                        hosts: vec!["*/*".to_string()],
                        port: None,
                    }],
                    ingress_declared: false,
                    ingress: Vec::new(),
                    outbound_traffic_policy: Some(sidecar_mode),
                }],
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        };
        let mut runtime = sidecar_runtime_with_policy(mesh_wide);
        runtime.namespace = "default".to_string();
        runtime.sidecar_enforced = true;
        let prepared =
            prepare_gateway_config_for_mesh(config, &runtime).expect("mesh apply succeeds");
        let injected = prepared
            .plugin_configs
            .iter()
            .any(|p| p.id == MESH_OUTBOUND_REGISTRY_PLUGIN_ID);
        assert_eq!(
            injected, expect_plugin,
            "mesh-wide {mesh_wide:?} + Sidecar {sidecar_mode:?} must \
             {} the registry gate",
            if expect_plugin { "arm" } else { "disarm" }
        );
    }
}

/// A present-but-unrepresentable `Sidecar.outboundTrafficPolicy` is accepted and
/// enforced as `REGISTRY_ONLY` rather than rejected — issue #3262.
///
/// Rejecting the resource would drop its `egress` narrowing as well, widening
/// both the workload's service view and the registry derived from it.
#[test]
fn sidecar_unrepresentable_outbound_traffic_policy_fails_closed() {
    register_feature!(
        category = CATEGORY,
        feature = "Sidecar.outboundTrafficPolicy unsupported variants fail closed to REGISTRY_ONLY",
        status = Status::Supported,
        notes = "Issue #3262: omitted/unknown/non-string mode, non-object block, and egressProxy all enforce REGISTRY_ONLY with a field-specific deferred_fields entry; the Sidecar itself stays accepted.",
    );

    let cases = [
        json!({}),
        json!({ "mode": "ALOW_ANY" }),
        json!({ "mode": 1 }),
        json!("REGISTRY_ONLY"),
        json!({
            "mode": "ALLOW_ANY",
            "egressProxy": { "host": "istio-egressgateway.istio-system.svc.cluster.local" },
        }),
    ];
    for policy in cases {
        let object = K8sObject {
            api_version: "networking.istio.io/v1".to_string(),
            kind: "Sidecar".to_string(),
            metadata: K8sMetadata {
                name: "degraded".to_string(),
                uid: String::new(),
                namespace: "default".to_string(),
                generation: Some(1),
                labels: HashMap::new(),
                annotations: HashMap::new(),
                creation_timestamp: None,
                deletion_timestamp: None,
            },
            spec: json!({
                "egress": [{ "hosts": ["*/*"] }],
                "outboundTrafficPolicy": policy,
            }),
            status: Value::Object(serde_json::Map::new()),
        };
        let translation = translate_k8s_objects(&[object], options()).expect("translation");
        let mesh = translation.config.mesh.as_deref().expect("mesh block");
        assert_eq!(
            mesh.sidecars.len(),
            1,
            "the Sidecar must survive translation for {policy}"
        );
        assert_eq!(
            mesh.sidecars[0].outbound_traffic_policy,
            Some(OutboundTrafficPolicy::RegistryOnly),
            "{policy} must fail closed to REGISTRY_ONLY"
        );
        assert_eq!(
            mesh.sidecars[0].egress.len(),
            1,
            "{policy} must not cost the Sidecar its egress narrowing"
        );
    }
}
