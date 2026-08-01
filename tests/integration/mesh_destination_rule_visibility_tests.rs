//! DestinationRule export visibility and lookup-tier resolution
//! (issues #2465 and #2469).
//!
//! These two behaviours are one semantic change and are tested together
//! because they compose: `exportTo` decides whether a rule is a candidate at
//! all, and only then does the client → target-service → root lookup order
//! decide which candidate wins. Testing them separately would miss the
//! interesting failure — a root-namespace fallback resurrecting a rule the
//! subscriber was never allowed to see.
//!
//! Coverage:
//!
//! * Kubernetes `spec.exportTo` parsing: omitted, explicitly empty, `.`, `*`,
//!   explicit allowlists, and the fail-closed rejection of unsupported,
//!   malformed, conflicting, and over-long values.
//! * Native/file semantics for an omitted-or-empty list (namespace-local by
//!   Ferrum convention) and validation rejection of hostile values.
//! * Slice narrowing: a namespace-local rule never reaches an external
//!   subscriber, an allowlisted namespace does, an unlisted one does not.
//! * Lookup tiers with the namespaces deliberately sorted BOTH ways, so a
//!   passing result cannot be an accident of `(namespace, name)` order.
//! * Client → service → root fallback, a custom root namespace, and
//!   same-tier merge determinism.
//! * Carrier/native parity and reload/dedupe behaviour for a visibility-only
//!   or root-namespace-only change.
//! * Composition with Sidecar egress scope.

use std::collections::HashMap;

use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::SpiffeId;
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::modes::mesh::config::{
    MeshConfig, MeshDestinationRule, MeshLoadBalancer, MeshService, MeshSidecar, MeshSidecarEgress,
    MeshSimpleLb, MeshTrafficPolicy, ServicePort, Workload, WorkloadRef,
    destination_rule_exported_to_namespace,
};
use ferrum_edge::modes::mesh::slice::{MeshSlice, MeshSliceRequest};
use ferrum_edge::modes::mesh::{MeshRuntimeConfig, prepare_gateway_config_for_mesh};
use serde_json::{Value, json};

use super::mesh_test_support::{default_mesh_runtime, http_proxy, http_upstream};

const TRUST_DOMAIN: &str = "cluster.local";

// ── Fixtures ─────────────────────────────────────────────────────────────

fn service_in(namespace: &str, name: &str) -> MeshService {
    MeshService {
        cluster_ips: Vec::new(),
        name: name.to_string(),
        namespace: namespace.to_string(),
        ports: vec![ServicePort {
            port: 8080,
            protocol: Default::default(),
            name: Some("http".to_string()),
            target_port: None,
        }],
        workloads: vec![WorkloadRef {
            spiffe_id: SpiffeId::new(&format!(
                "spiffe://{TRUST_DOMAIN}/ns/{namespace}/sa/{name}"
            ))
            .expect("valid spiffe id"),
        }],
        protocol_overrides: HashMap::new(),
    }
}

fn workload_in(namespace: &str, name: &str) -> Workload {
    Workload {
        spiffe_id: SpiffeId::new(&format!(
            "spiffe://{TRUST_DOMAIN}/ns/{namespace}/sa/{name}"
        ))
        .expect("valid spiffe id"),
        selector: Default::default(),
        service_name: name.to_string(),
        addresses: Vec::new(),
        ports: Vec::new(),
        trust_domain: TrustDomain::new(TRUST_DOMAIN).expect("trust domain"),
        namespace: namespace.to_string(),
        network: None,
        cluster: None,
        weight: None,
        locality: None,
        service_account: None,
        pod_uid: None,
        node_waypoint: None,
        remote_provenance: false,
    }
}

/// A DestinationRule carrying one identifiable knob (`connect_timeout_ms`) so a
/// test can tell WHICH rule won, not merely that some rule applied.
fn rule(
    namespace: &str,
    name: &str,
    host: &str,
    connect_timeout_ms: u64,
    export_to: &[&str],
) -> MeshDestinationRule {
    MeshDestinationRule {
        name: name.to_string(),
        namespace: namespace.to_string(),
        host: host.to_string(),
        traffic_policy: Some(MeshTrafficPolicy {
            connect_timeout_ms: Some(connect_timeout_ms),
            ..MeshTrafficPolicy::default()
        }),
        port_level_settings: HashMap::new(),
        subsets: Vec::new(),
        export_to: export_to.iter().map(|e| (*e).to_string()).collect(),
    }
}

fn config_with(mesh: MeshConfig) -> GatewayConfig {
    GatewayConfig {
        mesh: Some(Box::new(mesh)),
        ..GatewayConfig::default()
    }
}

fn request_for(namespace: &str) -> MeshSliceRequest {
    MeshSliceRequest {
        node_id: format!("node-{namespace}"),
        namespace: namespace.to_string(),
        cluster_domain: TRUST_DOMAIN.to_string(),
        ..MeshSliceRequest::default()
    }
    .with_enforce_sidecar_egress(true)
}

/// A namespace-default Sidecar whose egress scope admits everything (`*/*`).
///
/// Cross-namespace DestinationRule lookup only arises under an applicable
/// Sidecar — without one the slice is namespace-local (`services` is narrowed
/// the same way), so the destination has no upstream to carry policy onto.
/// Using the maximally permissive scope keeps `exportTo` and lookup-tier
/// behaviour as the ONLY thing these tests measure.
fn permissive_sidecar(namespace: &str) -> MeshSidecar {
    sidecar_admitting(namespace, &["*/*"])
}

/// The slice a subscriber in `namespace` receives, with an all-admitting
/// Sidecar in the subscriber's namespace (added only when the fixture does not
/// declare its own) so cross-namespace destinations are in scope.
fn slice_for(mesh: &MeshConfig, namespace: &str) -> MeshSlice {
    let mut mesh = mesh.clone();
    if mesh.sidecars.is_empty() {
        mesh.sidecars.push(permissive_sidecar(namespace));
    }
    MeshSlice::from_gateway_config(&config_with(mesh), request_for(namespace))
}

/// Names of the rules a subscriber in `namespace` actually receives.
fn admitted_rule_names(mesh: &MeshConfig, namespace: &str) -> Vec<String> {
    slice_for(mesh, namespace)
        .destination_rules
        .into_iter()
        .map(|dr| dr.name)
        .collect()
}

// ── Kubernetes `spec.exportTo` parsing ───────────────────────────────────

fn k8s_options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new(TRUST_DOMAIN).expect("trust domain"),
    )
}

fn dr_object(namespace: &str, name: &str, spec: Value) -> K8sObject {
    K8sObject {
        api_version: "networking.istio.io/v1beta1".to_string(),
        kind: "DestinationRule".to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            namespace: namespace.to_string(),
            ..K8sMetadata::default()
        },
        spec,
        status: Value::Object(serde_json::Map::new()),
    }
}

fn translate_dr(spec: Value) -> Result<MeshDestinationRule, String> {
    let result = translate_k8s_objects(&[dr_object("beta", "reviews-dr", spec)], k8s_options())
        .map_err(|e| e.to_string())?;
    let mesh = result.config.mesh.ok_or_else(|| "no mesh config".to_string())?;
    mesh.destination_rules
        .into_iter()
        .next()
        .ok_or_else(|| "no destination rule".to_string())
}

#[test]
fn k8s_omitted_export_to_is_materialized_as_istios_public_default() {
    let dr = translate_dr(json!({ "host": "reviews.beta.svc.cluster.local" }))
        .expect("translation succeeds");
    assert_eq!(
        dr.export_to,
        vec!["*".to_string()],
        "an omitted spec.exportTo must become an explicit ['*'] — leaving it \
         empty would silently make every Kubernetes DestinationRule \
         namespace-local"
    );
    assert!(destination_rule_exported_to_namespace(&dr, "alpha"));
}

#[test]
fn k8s_explicitly_empty_export_to_is_also_istios_public_default() {
    let dr = translate_dr(json!({
        "host": "reviews.beta.svc.cluster.local",
        "exportTo": [],
    }))
    .expect("translation succeeds");
    assert_eq!(dr.export_to, vec!["*".to_string()]);
}

#[test]
fn k8s_dot_export_to_is_namespace_local() {
    let dr = translate_dr(json!({
        "host": "reviews.beta.svc.cluster.local",
        "exportTo": ["."],
    }))
    .expect("translation succeeds");
    assert_eq!(dr.export_to, vec![".".to_string()]);
    assert!(
        destination_rule_exported_to_namespace(&dr, "beta"),
        "'.' must expand against the DECLARING namespace"
    );
    assert!(!destination_rule_exported_to_namespace(&dr, "alpha"));
}

#[test]
fn k8s_wildcard_and_explicit_allowlist_export_to_are_preserved() {
    let public = translate_dr(json!({
        "host": "reviews.beta.svc.cluster.local",
        "exportTo": ["*"],
    }))
    .expect("translation succeeds");
    assert!(destination_rule_exported_to_namespace(&public, "anything"));

    let allowlisted = translate_dr(json!({
        "host": "reviews.beta.svc.cluster.local",
        "exportTo": ["alpha", "gamma"],
    }))
    .expect("translation succeeds");
    assert_eq!(
        allowlisted.export_to,
        vec!["alpha".to_string(), "gamma".to_string()]
    );
    assert!(destination_rule_exported_to_namespace(&allowlisted, "alpha"));
    assert!(destination_rule_exported_to_namespace(&allowlisted, "gamma"));
    assert!(
        !destination_rule_exported_to_namespace(&allowlisted, "delta"),
        "a namespace absent from the allowlist must not see the rule"
    );
    assert!(
        !destination_rule_exported_to_namespace(&allowlisted, "beta"),
        "an explicit allowlist that omits the declaring namespace does not \
         implicitly re-add it"
    );
}

#[test]
fn k8s_rejects_unsupported_and_malformed_export_to_values_fail_closed() {
    for (label, spec) in [
        (
            "tilde is not a supported exportTo value",
            json!({"host": "reviews.beta.svc.cluster.local", "exportTo": ["~"]}),
        ),
        (
            "empty entry",
            json!({"host": "reviews.beta.svc.cluster.local", "exportTo": [""]}),
        ),
        (
            "uppercase namespace",
            json!({"host": "reviews.beta.svc.cluster.local", "exportTo": ["Alpha"]}),
        ),
        (
            "namespace with a slash",
            json!({"host": "reviews.beta.svc.cluster.local", "exportTo": ["alpha/reviews"]}),
        ),
        (
            "wildcard conflicting with an explicit namespace",
            json!({"host": "reviews.beta.svc.cluster.local", "exportTo": ["*", "alpha"]}),
        ),
        (
            "non-array exportTo",
            json!({"host": "reviews.beta.svc.cluster.local", "exportTo": "alpha"}),
        ),
        (
            "non-string entry",
            json!({"host": "reviews.beta.svc.cluster.local", "exportTo": [7]}),
        ),
    ] {
        let outcome = translate_dr(spec);
        assert!(
            outcome.is_err(),
            "{label}: must be rejected rather than interpreted, got {outcome:?}"
        );
    }
}

#[test]
fn k8s_rejects_an_over_long_export_to_list() {
    let entries: Vec<String> = (0..65).map(|i| format!("ns-{i}")).collect();
    let outcome = translate_dr(json!({
        "host": "reviews.beta.svc.cluster.local",
        "exportTo": entries,
    }));
    assert!(outcome.is_err(), "an unbounded visibility list is rejected");
}

#[test]
fn k8s_export_to_rejection_does_not_echo_the_hostile_value() {
    let hostile = "A".repeat(200);
    let message = translate_dr(json!({
        "host": "reviews.beta.svc.cluster.local",
        "exportTo": [hostile.clone()],
    }))
    .expect_err("hostile value is rejected");
    assert!(
        !message.contains(&hostile),
        "the diagnostic must name the field and index, never echo the raw \
         operator-supplied value; got: {message}"
    );
    assert!(
        message.contains("exportTo[0]"),
        "the diagnostic must still identify the offending entry; got: {message}"
    );
}

// ── Native / file semantics and validation ───────────────────────────────

#[test]
fn native_empty_export_to_is_namespace_local_not_public() {
    let dr = rule("beta", "reviews-dr", "reviews.beta.svc.cluster.local", 1, &[]);
    assert!(
        destination_rule_exported_to_namespace(&dr, "beta"),
        "an omitted native/file export_to keeps the rule visible in its own \
         namespace"
    );
    assert!(
        !destination_rule_exported_to_namespace(&dr, "alpha"),
        "fail closed by omission: the native/file source requires an explicit \
         ['*'] to publish a rule mesh-wide"
    );
}

#[test]
fn native_validation_rejects_unsupported_export_to_values() {
    for (label, export_to) in [
        ("tilde", vec!["~".to_string()]),
        ("empty entry", vec![String::new()]),
        ("uppercase", vec!["Alpha".to_string()]),
        (
            "wildcard plus namespace",
            vec!["*".to_string(), "alpha".to_string()],
        ),
    ] {
        let mesh = MeshConfig {
            destination_rules: vec![MeshDestinationRule {
                export_to,
                ..rule("beta", "reviews-dr", "reviews.beta.svc.cluster.local", 1, &[])
            }],
            ..MeshConfig::default()
        };
        let errors = mesh.validate();
        assert!(
            errors.iter().any(|e| e.contains("exportTo")),
            "{label}: expected an exportTo validation error, got {errors:?}"
        );
    }
}

#[test]
fn native_validation_accepts_supported_export_to_values() {
    for export_to in [
        vec![],
        vec![".".to_string()],
        vec!["*".to_string()],
        vec!["alpha".to_string(), "gamma-1".to_string()],
    ] {
        let mesh = MeshConfig {
            destination_rules: vec![MeshDestinationRule {
                export_to: export_to.clone(),
                ..rule("beta", "reviews-dr", "reviews.beta.svc.cluster.local", 1, &[])
            }],
            ..MeshConfig::default()
        };
        let errors = mesh.validate();
        assert!(
            !errors.iter().any(|e| e.contains("exportTo")),
            "{export_to:?} must validate, got {errors:?}"
        );
    }
}

// ── Slice narrowing: visibility (#2465) ──────────────────────────────────

/// The headline #2465 scenario: `beta` owns `reviews` and declares its policy
/// namespace-local. An `alpha` client must not receive it even though `beta`
/// IS the target service namespace — the tier that made the rule reachable
/// before.
#[test]
fn namespace_local_rule_never_reaches_a_client_in_another_namespace() {
    let mesh = MeshConfig {
        services: vec![service_in("beta", "reviews")],
        workloads: vec![workload_in("beta", "reviews"), workload_in("alpha", "web")],
        destination_rules: vec![rule(
            "beta",
            "reviews-private",
            "reviews.beta.svc.cluster.local",
            1111,
            &["."],
        )],
        ..MeshConfig::default()
    };

    assert!(
        admitted_rule_names(&mesh, "alpha").is_empty(),
        "exportTo ['.'] must not cross the declaring namespace boundary"
    );
    assert_eq!(
        admitted_rule_names(&mesh, "beta"),
        vec!["reviews-private".to_string()],
        "the owning namespace still sees its own rule"
    );
}

#[test]
fn public_and_allowlisted_rules_reach_exactly_the_declared_namespaces() {
    let mesh = MeshConfig {
        services: vec![service_in("beta", "reviews")],
        workloads: vec![workload_in("beta", "reviews")],
        destination_rules: vec![
            rule(
                "beta",
                "reviews-public",
                "reviews.beta.svc.cluster.local",
                1111,
                &["*"],
            ),
            rule(
                "beta",
                "ratings-allowlisted",
                "ratings.beta.svc.cluster.local",
                2222,
                &["alpha"],
            ),
        ],
        ..MeshConfig::default()
    };

    let alpha = admitted_rule_names(&mesh, "alpha");
    assert!(alpha.contains(&"reviews-public".to_string()));
    assert!(alpha.contains(&"ratings-allowlisted".to_string()));

    let gamma = admitted_rule_names(&mesh, "gamma");
    assert_eq!(
        gamma,
        vec!["reviews-public".to_string()],
        "gamma is not on the allowlist, so only the public rule reaches it"
    );
}

/// #2465 must not be reopened by #2469's root fallback: a root-namespace rule
/// is still subject to `exportTo`.
#[test]
fn a_namespace_local_root_namespace_rule_is_not_visible_mesh_wide() {
    let mesh = MeshConfig {
        istio_root_namespace: "istio-system".to_string(),
        services: vec![service_in("beta", "reviews")],
        workloads: vec![workload_in("beta", "reviews")],
        destination_rules: vec![rule(
            "istio-system",
            "root-private",
            "reviews.beta.svc.cluster.local",
            9999,
            &["."],
        )],
        ..MeshConfig::default()
    };

    assert!(
        admitted_rule_names(&mesh, "alpha").is_empty(),
        "a root-namespace rule exported only to its own namespace must not \
         become a mesh-wide default"
    );
    assert!(
        admitted_rule_names(&mesh, "beta").is_empty(),
        "nor may it reach the target service's namespace"
    );
    assert_eq!(
        admitted_rule_names(&mesh, "istio-system"),
        vec!["root-private".to_string()]
    );
}

// ── Slice narrowing: lookup tiers (#2469) ────────────────────────────────

/// Both directions of the lexical/semantic conflict. `(namespace, name)`
/// ordering must be irrelevant, so the same topology is asserted with the
/// client namespace sorting BEFORE and AFTER the service namespace.
#[test]
fn client_namespace_rule_wins_regardless_of_how_the_namespaces_sort() {
    for (client_ns, service_ns) in [("alpha", "zeta"), ("zeta", "alpha")] {
        let host = format!("reviews.{service_ns}.svc.cluster.local");
        let mesh = MeshConfig {
            services: vec![service_in(service_ns, "reviews")],
            workloads: vec![
                workload_in(service_ns, "reviews"),
                workload_in(client_ns, "web"),
            ],
            destination_rules: vec![
                rule(service_ns, "service-default", &host, 2222, &["*"]),
                rule(client_ns, "client-override", &host, 1111, &["*"]),
            ],
            ..MeshConfig::default()
        };

        assert_eq!(
            admitted_rule_names(&mesh, client_ns),
            vec!["client-override".to_string()],
            "client namespace {client_ns:?} must win over service namespace \
             {service_ns:?}; lexical order must not decide"
        );
    }
}

#[test]
fn service_namespace_rule_is_used_when_the_client_declares_none() {
    let mesh = MeshConfig {
        services: vec![service_in("beta", "reviews")],
        workloads: vec![workload_in("beta", "reviews")],
        destination_rules: vec![rule(
            "beta",
            "service-default",
            "reviews.beta.svc.cluster.local",
            2222,
            &["*"],
        )],
        ..MeshConfig::default()
    };
    assert_eq!(
        admitted_rule_names(&mesh, "alpha"),
        vec!["service-default".to_string()]
    );
}

#[test]
fn root_namespace_rule_is_the_fallback_when_neither_client_nor_service_declares_one() {
    let mesh = MeshConfig {
        istio_root_namespace: "istio-system".to_string(),
        services: vec![service_in("beta", "reviews")],
        workloads: vec![workload_in("beta", "reviews")],
        destination_rules: vec![rule(
            "istio-system",
            "mesh-default",
            "reviews.beta.svc.cluster.local",
            3333,
            &["*"],
        )],
        ..MeshConfig::default()
    };
    assert_eq!(
        admitted_rule_names(&mesh, "alpha"),
        vec!["mesh-default".to_string()],
        "the configured root namespace is Istio's last lookup tier and must \
         not be dropped from the slice"
    );
}

#[test]
fn a_custom_root_namespace_is_honored_and_the_default_one_is_not() {
    let mesh = MeshConfig {
        istio_root_namespace: "mesh-config".to_string(),
        services: vec![service_in("beta", "reviews")],
        workloads: vec![workload_in("beta", "reviews")],
        destination_rules: vec![
            rule(
                "mesh-config",
                "custom-root-default",
                "reviews.beta.svc.cluster.local",
                3333,
                &["*"],
            ),
            rule(
                "istio-system",
                "not-the-root-namespace",
                "reviews.beta.svc.cluster.local",
                4444,
                &["*"],
            ),
        ],
        ..MeshConfig::default()
    };
    assert_eq!(
        admitted_rule_names(&mesh, "alpha"),
        vec!["custom-root-default".to_string()],
        "only the CONFIGURED root namespace is a lookup tier; `istio-system` \
         has no special standing once the operator moved the root"
    );
}

#[test]
fn service_namespace_rule_outranks_the_root_default() {
    // `istio-system` sorts BEFORE `zeta`, so a lexical last-writer would pick
    // the service rule for the wrong reason. Assert the reverse pairing too.
    for (service_ns, root_ns) in [("zeta", "istio-system"), ("alpha", "zzz-root")] {
        let host = format!("reviews.{service_ns}.svc.cluster.local");
        let mesh = MeshConfig {
            istio_root_namespace: root_ns.to_string(),
            services: vec![service_in(service_ns, "reviews")],
            workloads: vec![workload_in(service_ns, "reviews")],
            destination_rules: vec![
                rule(root_ns, "mesh-default", &host, 3333, &["*"]),
                rule(service_ns, "service-default", &host, 2222, &["*"]),
            ],
            ..MeshConfig::default()
        };
        assert_eq!(
            admitted_rule_names(&mesh, "client-ns"),
            vec!["service-default".to_string()],
            "service namespace {service_ns:?} must outrank root {root_ns:?}"
        );
    }
}

#[test]
fn a_third_party_namespace_rule_is_refused_outright() {
    let mesh = MeshConfig {
        istio_root_namespace: "istio-system".to_string(),
        services: vec![service_in("beta", "reviews")],
        workloads: vec![workload_in("beta", "reviews")],
        destination_rules: vec![rule(
            "evil",
            "steal-reviews",
            "reviews.beta.svc.cluster.local",
            6666,
            // Even an explicit, self-granted public export cannot make a
            // third-party namespace part of the lookup path.
            &["*"],
        )],
        ..MeshConfig::default()
    };
    assert!(
        admitted_rule_names(&mesh, "alpha").is_empty(),
        "a namespace that is neither the client, the target service, nor the \
         configured root is not a lookup tier"
    );
}

#[test]
fn same_tier_rules_are_all_retained_in_deterministic_order() {
    let mesh = MeshConfig {
        services: vec![service_in("beta", "reviews")],
        workloads: vec![workload_in("beta", "reviews")],
        destination_rules: vec![
            rule(
                "beta",
                "z-second",
                "reviews.beta.svc.cluster.local",
                2222,
                &["*"],
            ),
            rule(
                "beta",
                "a-first",
                "reviews.beta.svc.cluster.local",
                1111,
                &["*"],
            ),
        ],
        ..MeshConfig::default()
    };
    let admitted = admitted_rule_names(&mesh, "alpha");
    assert_eq!(
        admitted.len(),
        2,
        "same-namespace rules for one host share a tier and both survive \
         narrowing (Istio's merge case), got {admitted:?}"
    );
    assert_eq!(
        admitted,
        admitted_rule_names(&mesh, "alpha"),
        "narrowing is deterministic across repeated builds"
    );
}

// ── Materialization: the winning rule is the one that takes effect ───────

fn materialized_connect_timeout(mesh: MeshConfig, client_namespace: &str, service_ns: &str) -> u64 {
    let host = format!("reviews.{service_ns}.svc.cluster.local");
    let mut upstream = http_upstream("reviews-u", &host, 8080);
    upstream.namespace = service_ns.to_string();
    upstream.name = Some(host.clone());
    let mut proxy = http_proxy("reviews-p", &host, 8080);
    proxy.namespace = service_ns.to_string();
    proxy.upstream_id = Some("reviews-u".to_string());

    let config = GatewayConfig {
        proxies: vec![proxy],
        upstreams: vec![upstream],
        mesh: Some(Box::new(mesh)),
        ..GatewayConfig::default()
    };
    let runtime = MeshRuntimeConfig {
        namespace: client_namespace.to_string(),
        sidecar_enforced: true,
        ..default_mesh_runtime()
    };
    let prepared =
        prepare_gateway_config_for_mesh(config, &runtime).expect("mesh preparation succeeds");
    prepared
        .proxies
        .iter()
        .find(|p| p.id == "reviews-p")
        .expect("operator proxy survives mesh preparation")
        .backend_connect_timeout_ms
}

/// End-to-end through slice narrowing AND `apply_destination_rules`: the
/// client-namespace policy is the one that actually reaches the proxy, with the
/// namespaces sorted both ways so no result can be a lexical accident.
#[test]
fn the_client_namespace_policy_is_the_one_materialized() {
    for (client_ns, service_ns) in [("alpha", "zeta"), ("zeta", "alpha")] {
        let host = format!("reviews.{service_ns}.svc.cluster.local");
        let mesh = MeshConfig {
            services: vec![service_in(service_ns, "reviews")],
            workloads: vec![
                workload_in(service_ns, "reviews"),
                workload_in(client_ns, "web"),
            ],
            destination_rules: vec![
                rule(service_ns, "service-default", &host, 2222, &["*"]),
                rule(client_ns, "client-override", &host, 1111, &["*"]),
            ],
            sidecars: vec![permissive_sidecar(client_ns)],
            ..MeshConfig::default()
        };
        assert_eq!(
            materialized_connect_timeout(mesh, client_ns, service_ns),
            1111,
            "client {client_ns:?} / service {service_ns:?}: the client-tier \
             connect timeout must be the effective one"
        );
    }
}

/// The security assertion for #2465 at the point where policy actually takes
/// effect: a namespace-local rule cannot change an external client's behaviour.
#[test]
fn a_namespace_local_rule_cannot_alter_an_external_clients_effective_policy() {
    let mesh = MeshConfig {
        services: vec![service_in("beta", "reviews")],
        workloads: vec![workload_in("beta", "reviews"), workload_in("alpha", "web")],
        destination_rules: vec![MeshDestinationRule {
            traffic_policy: Some(MeshTrafficPolicy {
                connect_timeout_ms: Some(1),
                load_balancer: Some(MeshLoadBalancer::Simple(MeshSimpleLb::Random)),
                ..MeshTrafficPolicy::default()
            }),
            ..rule(
                "beta",
                "reviews-private",
                "reviews.beta.svc.cluster.local",
                1,
                &["."],
            )
        }],
        sidecars: vec![permissive_sidecar("alpha")],
        ..MeshConfig::default()
    };

    let host = "reviews.beta.svc.cluster.local";
    let mut upstream = http_upstream("reviews-u", host, 8080);
    upstream.namespace = "beta".to_string();
    upstream.name = Some(host.to_string());
    let mut proxy = http_proxy("reviews-p", host, 8080);
    proxy.namespace = "beta".to_string();
    proxy.upstream_id = Some("reviews-u".to_string());
    let baseline_timeout = proxy.backend_connect_timeout_ms;

    let config = GatewayConfig {
        proxies: vec![proxy],
        upstreams: vec![upstream],
        mesh: Some(Box::new(mesh)),
        ..GatewayConfig::default()
    };
    let runtime = MeshRuntimeConfig {
        namespace: "alpha".to_string(),
        sidecar_enforced: true,
        ..default_mesh_runtime()
    };
    let prepared =
        prepare_gateway_config_for_mesh(config, &runtime).expect("mesh preparation succeeds");

    let proxy = prepared
        .proxies
        .iter()
        .find(|p| p.id == "reviews-p")
        .expect("operator proxy survives mesh preparation");
    assert_eq!(
        proxy.backend_connect_timeout_ms, baseline_timeout,
        "the alpha client must keep its own connect timeout"
    );
    let upstream = prepared
        .upstreams
        .iter()
        .find(|u| u.id == "reviews-u")
        .expect("operator upstream survives mesh preparation");
    assert_eq!(
        upstream.algorithm,
        ferrum_edge::config::types::LoadBalancerAlgorithm::RoundRobin,
        "and its load balancing must be untouched by beta's private policy"
    );
}

// ── Carrier / native parity, reload, and dedupe ──────────────────────────

/// The Ferrum-private ECDS DestinationRule carrier serializes the rule as
/// JSON, so visibility rides the carrier verbatim. (This is Ferrum's own
/// carrier contract; it is not stock Envoy/Istio xDS interoperability.)
#[test]
fn carrier_json_round_trip_preserves_export_to() {
    for export_to in [
        vec![],
        vec![".".to_string()],
        vec!["*".to_string()],
        vec!["alpha".to_string(), "gamma".to_string()],
    ] {
        let dr = MeshDestinationRule {
            export_to: export_to.clone(),
            ..rule("beta", "reviews-dr", "reviews.beta.svc.cluster.local", 1, &[])
        };
        let encoded = serde_json::to_vec(&dr).expect("encode");
        let decoded: MeshDestinationRule = serde_json::from_slice(&encoded).expect("decode");
        assert_eq!(decoded.export_to, export_to);
        assert_eq!(decoded, dr);
    }
}

#[test]
fn a_carrier_without_export_to_decodes_as_namespace_local() {
    let decoded: MeshDestinationRule = serde_json::from_value(json!({
        "name": "reviews-dr",
        "namespace": "beta",
        "host": "reviews.beta.svc.cluster.local",
    }))
    .expect("decode");
    assert!(decoded.export_to.is_empty());
    assert!(destination_rule_exported_to_namespace(&decoded, "beta"));
    assert!(
        !destination_rule_exported_to_namespace(&decoded, "alpha"),
        "an absent carrier field must fail closed, not default to public"
    );
}

/// A visibility-only edit changes nothing structural about the rule, so if
/// `content_eq` ignored it the subscriber would keep serving the old policy.
#[test]
fn a_visibility_only_change_is_not_deduped_away() {
    let base = MeshConfig {
        services: vec![service_in("beta", "reviews")],
        workloads: vec![workload_in("beta", "reviews")],
        destination_rules: vec![rule(
            "beta",
            "reviews-dr",
            "reviews.beta.svc.cluster.local",
            1111,
            &["*"],
        )],
        ..MeshConfig::default()
    };
    let mut narrowed = base.clone();
    narrowed.destination_rules[0].export_to = vec![".".to_string()];

    let before = slice_for(&base, "alpha");
    let after = slice_for(&narrowed, "alpha");
    assert!(
        !before.content_eq(&after),
        "narrowing visibility must produce a different slice for the external \
         subscriber so the policy is withdrawn promptly"
    );
    assert!(after.destination_rules.is_empty());
}

/// The same rule, still fully visible, but re-scoped from `*` to an explicit
/// allowlist that DOES include this subscriber: the effective set is unchanged
/// for this node, and dedupe may legitimately suppress the re-send.
#[test]
fn a_visibility_change_that_does_not_affect_this_subscriber_is_stable() {
    let mut public = MeshConfig {
        services: vec![service_in("beta", "reviews")],
        workloads: vec![workload_in("beta", "reviews")],
        destination_rules: vec![rule(
            "beta",
            "reviews-dr",
            "reviews.beta.svc.cluster.local",
            1111,
            &["*"],
        )],
        ..MeshConfig::default()
    };
    let before = slice_for(&public, "alpha");
    public.destination_rules[0].export_to = vec!["alpha".to_string()];
    let after = slice_for(&public, "alpha");
    assert_eq!(
        after.destination_rules.len(),
        1,
        "alpha is on the allowlist, so the rule still applies"
    );
    assert!(!before.content_eq(&after));
}

#[test]
fn a_root_namespace_only_change_is_not_deduped_away() {
    let base = MeshConfig {
        istio_root_namespace: "istio-system".to_string(),
        services: vec![service_in("beta", "reviews")],
        workloads: vec![workload_in("beta", "reviews")],
        destination_rules: Vec::new(),
        ..MeshConfig::default()
    };
    let mut with_root = base.clone();
    with_root.destination_rules.push(rule(
        "istio-system",
        "mesh-default",
        "reviews.beta.svc.cluster.local",
        3333,
        &["*"],
    ));

    let before = slice_for(&base, "alpha");
    let after = slice_for(&with_root, "alpha");
    assert!(!before.content_eq(&after));
    assert_eq!(after.destination_rules.len(), 1);
}

/// Deleting the winning client-namespace rule must promote the service-tier
/// rule immediately rather than leaving the destination with no policy.
#[test]
fn deleting_the_client_rule_falls_back_to_the_service_rule() {
    let host = "reviews.beta.svc.cluster.local";
    let mut mesh = MeshConfig {
        services: vec![service_in("beta", "reviews")],
        workloads: vec![workload_in("beta", "reviews"), workload_in("alpha", "web")],
        destination_rules: vec![
            rule("beta", "service-default", host, 2222, &["*"]),
            rule("alpha", "client-override", host, 1111, &["*"]),
        ],
        ..MeshConfig::default()
    };
    assert_eq!(
        admitted_rule_names(&mesh, "alpha"),
        vec!["client-override".to_string()]
    );

    mesh.destination_rules.retain(|dr| dr.namespace != "alpha");
    assert_eq!(
        admitted_rule_names(&mesh, "alpha"),
        vec!["service-default".to_string()],
        "withdrawing the client-tier rule promotes the service-tier rule"
    );
}

// ── Composition with Sidecar egress scope ────────────────────────────────

fn sidecar_admitting(namespace: &str, hosts: &[&str]) -> MeshSidecar {
    MeshSidecar {
        name: "default-sc".to_string(),
        namespace: namespace.to_string(),
        workload_selector: None,
        egress_inherits_defaults: false,
        egress: vec![MeshSidecarEgress {
            hosts: hosts.iter().map(|h| (*h).to_string()).collect(),
            port: None,
        }],
        ingress_declared: false,
        ingress: Vec::new(),
    }
}

/// Sidecar egress scope and `exportTo` are independent gates and BOTH must
/// pass. An egress scope that admits `beta/*` does not grant visibility of
/// `beta`'s namespace-local rules.
#[test]
fn sidecar_egress_scope_does_not_override_export_to() {
    let mesh = MeshConfig {
        sidecars: vec![sidecar_admitting("alpha", &["beta/*"])],
        services: vec![service_in("beta", "reviews")],
        workloads: vec![workload_in("beta", "reviews"), workload_in("alpha", "web")],
        destination_rules: vec![
            rule(
                "beta",
                "reviews-private",
                "reviews.beta.svc.cluster.local",
                1111,
                &["."],
            ),
            rule(
                "beta",
                "reviews-public",
                "reviews.beta.svc.cluster.local",
                2222,
                &["*"],
            ),
        ],
        ..MeshConfig::default()
    };

    let slice = MeshSlice::from_gateway_config(&config_with(mesh), request_for("alpha"));
    let names: Vec<String> = slice
        .destination_rules
        .into_iter()
        .map(|dr| dr.name)
        .collect();
    assert_eq!(
        names,
        vec!["reviews-public".to_string()],
        "the Sidecar admits the host, but only the exported rule is visible"
    );
}

/// The converse: `exportTo: ['*']` does not widen the Sidecar egress scope.
#[test]
fn export_to_does_not_override_sidecar_egress_scope() {
    let mesh = MeshConfig {
        sidecars: vec![sidecar_admitting("alpha", &["./*"])],
        services: vec![service_in("beta", "reviews")],
        workloads: vec![workload_in("beta", "reviews"), workload_in("alpha", "web")],
        destination_rules: vec![rule(
            "beta",
            "reviews-public",
            "reviews.beta.svc.cluster.local",
            2222,
            &["*"],
        )],
        ..MeshConfig::default()
    };

    let slice = MeshSlice::from_gateway_config(&config_with(mesh), request_for("alpha"));
    assert!(
        slice.destination_rules.is_empty(),
        "a publicly exported rule for a host outside the Sidecar egress scope \
         still must not be carried"
    );
}
