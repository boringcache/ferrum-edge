//! Kubernetes mesh-overlay withdrawal (issue #2452).
//!
//! Deleting the last mesh-contributing Kubernetes object used to leave the
//! previously published mesh live forever: the translator represented a
//! managed-but-empty mesh as `GatewayConfig.mesh == None`, and the reconciler
//! read that same `None` as "Kubernetes has no mesh update, keep the active
//! mesh". `GatewayConfig.k8s_mesh_overlay` now separates the two states:
//!
//!   * `NoAuthority`   — this source is not a mesh owner; leave other sources'
//!                       mesh state alone.
//!   * `Authoritative` — this source owns the mesh objects in the listed
//!                       namespaces, and an EMPTY list is a withdrawal.
//!
//! These tests cover both states end to end: real translations for Service /
//! Workload, AuthorizationPolicy / PeerAuthentication / RequestAuthentication,
//! ServiceEntry / WorkloadEntry, mixed-source ownership, drift (re-publication
//! without duplication), namespaces that leave the managed set, publication
//! atomicity, and repeated-empty idempotence.

use std::collections::{BTreeSet, HashMap};

use arc_swap::ArcSwap;
use ferrum_edge::_test_support::{
    compose_db_with_k8s_overlay, empty_k8s_overlay_slot, merge_k8s_translation,
    store_accepted_k8s_overlay, swap_merged_k8s_translation,
};
use ferrum_edge::config::types::{GatewayConfig, K8sMeshOverlay};
use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::modes::mesh::config::{MeshConfig, MeshService};
use serde_json::{Value, json};

// ── Fixtures ──────────────────────────────────────────────────────────────

/// Translation options for a controller that DOES watch mesh-contributing
/// kinds, i.e. an authoritative mesh owner.
fn authoritative_options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("test trust domain"),
    )
    .with_source_namespaces(Vec::new())
    .with_pod_discovery_enabled(true)
    .with_mesh_overlay_authority(true)
}

/// Translation options for a controller that watches no mesh-contributing
/// kind and therefore owns nothing.
fn non_authoritative_options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("test trust domain"),
    )
    .with_source_namespaces(Vec::new())
    .with_mesh_overlay_authority(false)
}

fn object(api_version: &str, kind: &str, namespace: &str, name: &str, spec: Value) -> K8sObject {
    K8sObject {
        api_version: api_version.to_string(),
        kind: kind.to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            uid: String::new(),
            namespace: namespace.to_string(),
            generation: None,
            labels: HashMap::new(),
            annotations: HashMap::new(),
            creation_timestamp: None,
            deletion_timestamp: None,
        },
        spec,
        status: Value::Object(serde_json::Map::new()),
    }
}

fn service() -> K8sObject {
    object(
        "v1",
        "Service",
        "default",
        "reviews",
        json!({
            "ports": [{
                "name": "http",
                "port": 9080,
                "targetPort": 9080,
                "appProtocol": "http"
            }]
        }),
    )
}

fn ready_pod() -> K8sObject {
    let mut pod = object(
        "v1",
        "Pod",
        "default",
        "reviews-v1",
        json!({
            "serviceAccountName": "reviews",
            "nodeName": "node-a",
            "containers": [{
                "ports": [{"name": "http", "containerPort": 9080, "protocol": "TCP"}]
            }]
        }),
    );
    pod.metadata
        .labels
        .insert("app".to_string(), "reviews".to_string());
    pod.status = json!({
        "phase": "Running",
        "podIP": "10.1.0.10",
        "conditions": [{"type": "Ready", "status": "True"}]
    });
    pod
}

fn endpoint_slice() -> K8sObject {
    let mut slice = object(
        "discovery.k8s.io/v1",
        "EndpointSlice",
        "default",
        "reviews-abc",
        json!({
            "addressType": "IPv4",
            "endpoints": [{
                "addresses": ["10.1.0.10"],
                "targetRef": {"kind": "Pod", "name": "reviews-v1", "namespace": "default"},
                "conditions": {"ready": true}
            }],
            "ports": [{"name": "http", "port": 9080}]
        }),
    );
    slice.metadata.labels.insert(
        "kubernetes.io/service-name".to_string(),
        "reviews".to_string(),
    );
    slice
}

fn authorization_policy(namespace: &str) -> K8sObject {
    object(
        "security.istio.io/v1",
        "AuthorizationPolicy",
        namespace,
        "allow-reviews",
        json!({
            "action": "ALLOW",
            "rules": [{"to": [{"operation": {"ports": ["9080"]}}]}]
        }),
    )
}

fn peer_authentication(namespace: &str) -> K8sObject {
    object(
        "security.istio.io/v1",
        "PeerAuthentication",
        namespace,
        "strict-mtls",
        json!({"mtls": {"mode": "STRICT"}}),
    )
}

fn request_authentication(namespace: &str) -> K8sObject {
    object(
        "security.istio.io/v1",
        "RequestAuthentication",
        namespace,
        "jwt",
        json!({
            "jwtRules": [{
                "issuer": "https://issuer.example.com",
                "jwksUri": "https://issuer.example.com/certs"
            }]
        }),
    )
}

fn service_entry(namespace: &str, name: &str, host: &str) -> K8sObject {
    object(
        "networking.istio.io/v1",
        "ServiceEntry",
        namespace,
        name,
        json!({
            "hosts": [host],
            "resolution": "DNS",
            "ports": [{"number": 443, "name": "https", "protocol": "TLS"}]
        }),
    )
}

fn workload_entry(namespace: &str) -> K8sObject {
    object(
        "networking.istio.io/v1",
        "WorkloadEntry",
        namespace,
        "vm-api",
        json!({
            "address": "vm-api.example",
            "serviceAccount": "api",
            "service": "api",
            "labels": {"app": "api"},
            "ports": {"http": 8080}
        }),
    )
}

/// Translate an authoritative Kubernetes snapshot into a `GatewayConfig`.
fn authoritative_translation(objects: &[K8sObject]) -> GatewayConfig {
    translate_k8s_objects(objects, authoritative_options())
        .expect("translation succeeds")
        .config
}

/// The authoritative EMPTY snapshot: every mesh-contributing object deleted.
fn authoritative_empty_translation() -> GatewayConfig {
    authoritative_translation(&[])
}

fn managed(namespaces: &[&str]) -> BTreeSet<String> {
    namespaces.iter().map(|ns| ns.to_string()).collect()
}

fn native_mesh_service(namespace: &str, name: &str) -> MeshService {
    MeshService {
        cluster_ips: Vec::new(),
        name: name.to_string(),
        namespace: namespace.to_string(),
        ports: Vec::new(),
        workloads: Vec::new(),
        protocol_overrides: HashMap::new(),
    }
}

// ── Translator: authority marking ─────────────────────────────────────────

#[test]
fn authoritative_translator_marks_an_empty_snapshot_as_authoritative() {
    let empty = authoritative_empty_translation();

    assert!(
        empty.mesh.is_none(),
        "an empty mesh must still serialize as `mesh: None`"
    );
    assert_eq!(
        empty.k8s_mesh_overlay,
        K8sMeshOverlay::Authoritative {
            owned_namespaces: BTreeSet::new(),
        },
        "an empty managed snapshot is an authoritative withdrawal, not a missing update"
    );
}

#[test]
fn authoritative_translator_records_the_namespaces_it_owns() {
    let translation = authoritative_translation(&[
        service_entry("alpha", "api", "api.example.com"),
        service_entry("beta", "cdn", "cdn.example.com"),
    ]);

    assert_eq!(
        translation.k8s_mesh_overlay,
        K8sMeshOverlay::Authoritative {
            owned_namespaces: managed(&["alpha", "beta"]),
        }
    );
}

#[test]
fn non_authoritative_translator_never_claims_mesh_ownership() {
    let translation = translate_k8s_objects(&[], non_authoritative_options())
        .expect("translation succeeds")
        .config;

    assert_eq!(translation.k8s_mesh_overlay, K8sMeshOverlay::NoAuthority);
    assert!(!translation.k8s_mesh_overlay.is_authoritative());
}

// ── Withdrawal by resource kind ───────────────────────────────────────────

#[test]
fn deleting_the_last_service_and_workload_withdraws_the_mesh_overlay() {
    let populated = authoritative_translation(&[service(), ready_pod(), endpoint_slice()]);
    let mesh = populated.mesh.as_deref().expect("mesh translated");
    assert_eq!(mesh.services.len(), 1);
    assert_eq!(mesh.workloads.len(), 1);

    let managed = managed(&["default"]);
    let active = merge_k8s_translation(&GatewayConfig::default(), &populated, &managed);
    assert!(active.mesh.is_some(), "the K8s mesh must publish first");

    let withdrawn = merge_k8s_translation(&active, &authoritative_empty_translation(), &managed);

    assert!(
        withdrawn.mesh.is_none(),
        "deleting the last Service/Pod/EndpointSlice must withdraw the mesh overlay"
    );
}

#[test]
fn deleting_the_last_policies_withdraws_the_mesh_overlay() {
    let populated = authoritative_translation(&[
        authorization_policy("default"),
        peer_authentication("default"),
        request_authentication("default"),
    ]);
    let mesh = populated.mesh.as_deref().expect("mesh translated");
    assert_eq!(mesh.mesh_policies.len(), 1);
    assert_eq!(mesh.peer_authentications.len(), 1);
    assert_eq!(mesh.request_authentications.len(), 1);

    let managed = managed(&["default"]);
    let active = merge_k8s_translation(&GatewayConfig::default(), &populated, &managed);
    assert!(active.mesh.is_some());

    let withdrawn = merge_k8s_translation(&active, &authoritative_empty_translation(), &managed);

    assert!(
        withdrawn.mesh.is_none(),
        "a deleted AuthorizationPolicy / PeerAuthentication / RequestAuthentication must not \
         keep governing traffic"
    );
}

#[test]
fn deleting_the_last_service_entry_and_workload_entry_withdraws_the_mesh_overlay() {
    let populated = authoritative_translation(&[
        service_entry("default", "api", "api.example.com"),
        workload_entry("default"),
    ]);
    let mesh = populated.mesh.as_deref().expect("mesh translated");
    assert_eq!(mesh.service_entries.len(), 1);
    assert_eq!(mesh.workloads.len(), 1);

    let managed = managed(&["default"]);
    let active = merge_k8s_translation(&GatewayConfig::default(), &populated, &managed);
    assert!(active.mesh.is_some());

    let withdrawn = merge_k8s_translation(&active, &authoritative_empty_translation(), &managed);

    assert!(
        withdrawn.mesh.is_none(),
        "a deleted ServiceEntry / WorkloadEntry must stop being routable"
    );
}

// ── Ownership boundaries ──────────────────────────────────────────────────

#[test]
fn withdrawal_preserves_mesh_state_owned_by_another_source() {
    // A native/file/xDS source owns `native/native-svc`; Kubernetes owns
    // `default/*`. Kubernetes withdrawing everything it owns must not touch
    // the other source's object.
    let mut active = GatewayConfig {
        mesh: Some(Box::new(MeshConfig {
            services: vec![native_mesh_service("native", "native-svc")],
            ..MeshConfig::default()
        })),
        ..GatewayConfig::default()
    };
    let managed = managed(&["default"]);
    active = merge_k8s_translation(
        &active,
        &authoritative_translation(&[service_entry("default", "api", "api.example.com")]),
        &managed,
    );
    let active_mesh = active.mesh.as_deref().expect("mesh after first publish");
    assert_eq!(active_mesh.services.len(), 1);
    assert_eq!(active_mesh.service_entries.len(), 1);

    let withdrawn = merge_k8s_translation(&active, &authoritative_empty_translation(), &managed);

    let mesh = withdrawn
        .mesh
        .as_deref()
        .expect("mesh owned by another source must survive a Kubernetes withdrawal");
    assert!(
        mesh.service_entries.is_empty(),
        "the Kubernetes-owned ServiceEntry must be withdrawn"
    );
    assert_eq!(
        mesh.services.len(),
        1,
        "the natively owned service must survive"
    );
    assert_eq!(mesh.services[0].namespace, "native");
}

#[test]
fn a_source_without_mesh_authority_never_withdraws_another_sources_mesh() {
    let active = GatewayConfig {
        mesh: Some(Box::new(MeshConfig {
            services: vec![native_mesh_service("default", "native-svc")],
            ..MeshConfig::default()
        })),
        ..GatewayConfig::default()
    };
    let no_authority = translate_k8s_objects(&[], non_authoritative_options())
        .expect("translation succeeds")
        .config;

    let merged = merge_k8s_translation(&active, &no_authority, &managed(&["default"]));

    let mesh = merged.mesh.as_deref().expect("mesh must be preserved");
    assert_eq!(
        mesh.services.len(),
        1,
        "a controller that watches no mesh kind owns nothing and may withdraw nothing"
    );
}

#[test]
fn withdrawal_covers_a_namespace_that_left_the_managed_set() {
    // `beta` is dropped from the watch scope between rounds. Its previously
    // published Kubernetes objects must still be withdrawn rather than
    // stranded, which is what the carried-forward owned-namespace set is for.
    let populated = authoritative_translation(&[
        service_entry("alpha", "api", "api.example.com"),
        service_entry("beta", "cdn", "cdn.example.com"),
    ]);
    let active = merge_k8s_translation(
        &GatewayConfig::default(),
        &populated,
        &managed(&["alpha", "beta"]),
    );
    assert_eq!(
        active
            .mesh
            .as_deref()
            .expect("mesh translated")
            .service_entries
            .len(),
        2
    );

    let withdrawn = merge_k8s_translation(
        &active,
        &authoritative_empty_translation(),
        &managed(&["alpha"]),
    );

    assert!(
        withdrawn.mesh.is_none(),
        "objects in a namespace that left the managed set must still be withdrawn"
    );
}

// ── Drift / idempotence ───────────────────────────────────────────────────

#[test]
fn republishing_the_same_snapshot_replaces_rather_than_duplicates() {
    let populated =
        authoritative_translation(&[service_entry("default", "api", "api.example.com")]);
    let managed = managed(&["default"]);

    let first = merge_k8s_translation(&GatewayConfig::default(), &populated, &managed);
    let second = merge_k8s_translation(&first, &populated, &managed);

    let mesh = second.mesh.as_deref().expect("mesh stays published");
    assert_eq!(
        mesh.service_entries.len(),
        1,
        "a re-published Kubernetes object must replace its predecessor, not stack on it"
    );
}

#[test]
fn repeated_empty_snapshots_are_idempotent_and_publish_once() {
    let populated =
        authoritative_translation(&[service_entry("default", "api", "api.example.com")]);
    let empty = authoritative_empty_translation();
    let managed = managed(&["default"]);

    let config_arc = ArcSwap::from_pointee(GatewayConfig::default());
    assert!(
        swap_merged_k8s_translation(&config_arc, &populated, &managed).is_some(),
        "the first non-empty publication must commit"
    );

    let withdrawal = swap_merged_k8s_translation(&config_arc, &empty, &managed)
        .expect("the withdrawal must commit exactly once");
    assert!(withdrawal.mesh.is_none());

    assert!(
        swap_merged_k8s_translation(&config_arc, &empty, &managed).is_none(),
        "a repeated empty snapshot is a no-op — no re-publication, no broadcast"
    );
    assert!(config_arc.load().mesh.is_none());
}

#[test]
fn withdrawal_publishes_one_complete_snapshot() {
    let populated =
        authoritative_translation(&[service_entry("default", "api", "api.example.com")]);
    let managed = managed(&["default"]);

    let config_arc = ArcSwap::from_pointee(GatewayConfig::default());
    swap_merged_k8s_translation(&config_arc, &populated, &managed).expect("initial publication");

    // An in-flight consumer holding the pre-withdrawal snapshot.
    let in_flight = config_arc.load_full();
    assert!(in_flight.mesh.is_some());

    swap_merged_k8s_translation(&config_arc, &authoritative_empty_translation(), &managed)
        .expect("withdrawal publication");

    assert!(
        in_flight.mesh.is_some(),
        "the in-flight snapshot must stay complete — never partially withdrawn"
    );
    assert!(
        config_arc.load().mesh.is_none(),
        "the next load must see the complete post-withdrawal snapshot"
    );
}

// ── CP full-reload re-merge (overlay slot) ────────────────────────────────

#[test]
fn overlay_slot_does_not_resurrect_an_authoritatively_withdrawn_mesh() {
    let overlay_slot = empty_k8s_overlay_slot();
    let managed = managed(&["default"]);

    store_accepted_k8s_overlay(
        &overlay_slot,
        authoritative_translation(&[service_entry("default", "api", "api.example.com")]),
        managed.clone(),
    );
    assert!(
        compose_db_with_k8s_overlay(&GatewayConfig::default(), &overlay_slot)
            .mesh
            .is_some(),
        "the accepted overlay must supply mesh on a CP full reload"
    );

    store_accepted_k8s_overlay(&overlay_slot, authoritative_empty_translation(), managed);

    assert!(
        compose_db_with_k8s_overlay(&GatewayConfig::default(), &overlay_slot)
            .mesh
            .is_none(),
        "a CP full reload must not resurrect a withdrawn Kubernetes mesh overlay"
    );
}

// ── Ownership-accounting coverage guard ───────────────────────────────────

/// Exhaustively destructures [`MeshConfig`] so a new field cannot be added
/// without deciding whether it participates in Kubernetes overlay ownership.
///
/// A new NAMESPACED collection must be added to all three of
/// `MeshConfig::object_namespaces`, `MeshConfig::retain_object_namespaces`, and
/// `MeshConfig::extend_objects_from`, or it will silently survive a Kubernetes
/// withdrawal. A new mesh-GLOBAL block is deliberately left alone by the merge
/// (the Kubernetes translator does not produce any).
#[test]
fn mesh_config_fields_are_accounted_for_in_overlay_ownership() {
    let MeshConfig {
        istio_root_namespace: _,
        // Namespaced, Kubernetes-ownable collections.
        workloads: _,
        services: _,
        mesh_policies: _,
        peer_authentications: _,
        service_entries: _,
        request_authentications: _,
        telemetry_resources: _,
        destination_rules: _,
        virtual_service_cors_policies: _,
        proxy_configs: _,
        sidecars: _,
        waypoint_bindings: _,
        // Mesh-global blocks: never produced by the Kubernetes translator and
        // therefore never withdrawn by it.
        trust_bundles: _,
        multi_cluster: _,
        outbound_traffic_policy: _,
        extension_configs: _,
        // Runtime-only back-projections: derived per slice, never source-owned,
        // always default on a control-plane snapshot.
        node_waypoint_assertors: _,
        node_waypoint_capture_destinations: _,
        node_waypoint_capture_peer_authentications: _,
        local_inbound_services: _,
        local_ingress_listeners: _,
        declared_ingress_http_ports: _,
        local_inbound_tcp_routes: _,
    } = MeshConfig::default();

    let mut mesh = MeshConfig {
        services: vec![native_mesh_service("owned", "svc")],
        ..MeshConfig::default()
    };
    assert_eq!(mesh.object_namespaces(), managed(&["owned"]));
    mesh.retain_object_namespaces(|namespace| namespace != "owned");
    assert!(mesh.is_empty_overlay());
}
