//! Issue #3262 — Istio `Sidecar.outboundTrafficPolicy` translation, selection,
//! propagation, and effective-policy resolution.
//!
//! Scope of this file (no mesh runtime, no sockets):
//!   - **Translation**: the supported `ALLOW_ANY` / `REGISTRY_ONLY` modes, and
//!     every fail-closed variant (omitted / unknown / non-string `mode`,
//!     non-object block, unsupported `egressProxy`). A degraded variant must
//!     still leave the `Sidecar` — and therefore its `egress` narrowing — in the
//!     translation, because dropping it would WIDEN the slice.
//!   - **Selection**: which `Sidecar` supplies the policy for a workload, and
//!     that an omitted block inherits rather than walking to a less-specific
//!     `Sidecar`.
//!   - **Gate**: the policy applies only under
//!     `enforce_sidecar_egress && !sidecar_egress_dry_run`.
//!   - **Effective precedence**: Sidecar → mesh-wide → runtime default.
//!   - **Serialization parity**: native JSON round-trip and the xDS ECDS
//!     carrier round-trip agree with the natively built slice.
//!   - **Update / delete**: editing only the mode, or deleting the `Sidecar`,
//!     changes the slice AND is visible to `content_eq` (so MeshSubscribe
//!     dedupe cannot keep a stale gate live).
//!
//! Live request-path enforcement is covered by
//! `tests/integration/mesh_sidecar_e2e_tests.rs`; CRD status reporting by
//! `tests/integration/k8s_controller_istio_status_tests.rs`.

use std::collections::HashMap;

use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::modes::mesh::config::{
    MeshConfig, MeshSidecar, MeshSidecarEgress, OutboundTrafficPolicy, WorkloadSelector,
};
use ferrum_edge::modes::mesh::slice::{MeshSlice, MeshSliceRequest};
use ferrum_edge::xds::carrier::{MeshSliceCarrier, apply_carrier, build_slice_carriers};
use serde_json::{Value, json};

// ── Kubernetes translation fixtures ───────────────────────────────────────

fn options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("test trust domain"),
    )
}

fn sidecar_object(name: &str, spec: Value) -> K8sObject {
    K8sObject {
        api_version: "networking.istio.io/v1".to_string(),
        kind: "Sidecar".to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            uid: String::new(),
            namespace: "default".to_string(),
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

/// Translate one `Sidecar` object and return the translated `MeshSidecar`.
/// Panics when the resource was rejected — every case in this file must be
/// ACCEPTED, which is itself the fail-closed property under test.
fn translate_one(spec: Value) -> MeshSidecar {
    let translation =
        translate_k8s_objects(&[sidecar_object("sc", spec)], options()).expect("translation");
    let mesh = translation
        .config
        .mesh
        .as_deref()
        .expect("mesh block")
        .clone();
    assert_eq!(
        mesh.sidecars.len(),
        1,
        "the Sidecar must survive translation; dropping it would also drop its \
         egress narrowing and widen the slice"
    );
    mesh.sidecars.into_iter().next().expect("sidecar")
}

/// A `spec` whose `egress` scope is meaningful, so a test can prove the scope
/// survived alongside a degraded `outboundTrafficPolicy`.
fn spec_with_egress_and_policy(policy: Option<Value>) -> Value {
    let mut spec = json!({
        "egress": [{ "hosts": ["./reviews"] }],
    });
    if let Some(policy) = policy {
        spec["outboundTrafficPolicy"] = policy;
    }
    spec
}

// ── Translation: supported modes ──────────────────────────────────────────

#[test]
fn omitted_outbound_traffic_policy_translates_to_inherit() {
    let sidecar = translate_one(spec_with_egress_and_policy(None));
    assert_eq!(
        sidecar.outbound_traffic_policy, None,
        "an omitted block must inherit the mesh-wide policy, not pin one"
    );
}

#[test]
fn allow_any_mode_translates_to_allow_any() {
    let sidecar = translate_one(spec_with_egress_and_policy(Some(
        json!({ "mode": "ALLOW_ANY" }),
    )));
    assert_eq!(
        sidecar.outbound_traffic_policy,
        Some(OutboundTrafficPolicy::AllowAny)
    );
}

#[test]
fn registry_only_mode_translates_to_registry_only() {
    let sidecar = translate_one(spec_with_egress_and_policy(Some(
        json!({ "mode": "REGISTRY_ONLY" }),
    )));
    assert_eq!(
        sidecar.outbound_traffic_policy,
        Some(OutboundTrafficPolicy::RegistryOnly)
    );
}

// ── Translation: fail-closed variants ─────────────────────────────────────

/// Every unrepresentable-but-present variant must resolve to the restrictive
/// mode AND leave the resource (with its egress scope) intact.
#[test]
fn unrepresentable_outbound_policy_variants_fail_closed_without_dropping_the_sidecar() {
    let cases: Vec<(&str, Value)> = vec![
        ("mode omitted (Istio proto zero value)", json!({})),
        (
            "egressProxy with no mode",
            json!({ "egressProxy": { "host": "istio-egressgateway.istio-system.svc.cluster.local" } }),
        ),
        ("unknown mode token", json!({ "mode": "ALOW_ANY" })),
        ("lowercase mode token", json!({ "mode": "allow_any" })),
        ("numeric proto form", json!({ "mode": 1 })),
        ("null mode", json!({ "mode": null })),
        (
            "egressProxy alongside an explicit ALLOW_ANY",
            json!({
                "mode": "ALLOW_ANY",
                "egressProxy": { "host": "istio-egressgateway.istio-system.svc.cluster.local" },
            }),
        ),
    ];
    for (label, policy) in cases {
        let sidecar = translate_one(spec_with_egress_and_policy(Some(policy)));
        assert_eq!(
            sidecar.outbound_traffic_policy,
            Some(OutboundTrafficPolicy::RegistryOnly),
            "{label} must fail closed to REGISTRY_ONLY"
        );
        assert_eq!(
            sidecar.egress.len(),
            1,
            "{label} must not cost the Sidecar its egress narrowing"
        );
    }
}

#[test]
fn non_object_outbound_traffic_policy_fails_closed() {
    for policy in [json!("REGISTRY_ONLY"), json!(["REGISTRY_ONLY"]), json!(7)] {
        let sidecar = translate_one(spec_with_egress_and_policy(Some(policy.clone())));
        assert_eq!(
            sidecar.outbound_traffic_policy,
            Some(OutboundTrafficPolicy::RegistryOnly),
            "a non-object outboundTrafficPolicy ({policy}) must fail closed"
        );
    }
}

#[test]
fn surrounding_whitespace_on_a_supported_mode_is_tolerated() {
    let sidecar = translate_one(spec_with_egress_and_policy(Some(
        json!({ "mode": "  ALLOW_ANY  " }),
    )));
    assert_eq!(
        sidecar.outbound_traffic_policy,
        Some(OutboundTrafficPolicy::AllowAny),
        "a padded but otherwise exact token is unambiguous and must not fail closed"
    );
}

// ── Slice fixtures ────────────────────────────────────────────────────────

fn sidecar(
    name: &str,
    namespace: &str,
    selector: Option<WorkloadSelector>,
    policy: Option<OutboundTrafficPolicy>,
) -> MeshSidecar {
    MeshSidecar {
        name: name.to_string(),
        namespace: namespace.to_string(),
        workload_selector: selector,
        egress_inherits_defaults: false,
        egress: vec![MeshSidecarEgress {
            hosts: vec!["*/*".to_string()],
            port: None,
        }],
        ingress_declared: false,
        ingress: Vec::new(),
        outbound_traffic_policy: policy,
    }
}

fn selector_for(app: &str, namespace: &str) -> WorkloadSelector {
    WorkloadSelector {
        labels: HashMap::from([("app".to_string(), app.to_string())]),
        namespace: Some(namespace.to_string()),
    }
}

fn config_with_sidecars(sidecars: Vec<MeshSidecar>) -> GatewayConfig {
    config_with_mesh(MeshConfig {
        sidecars,
        ..MeshConfig::default()
    })
}

fn config_with_mesh(mesh: MeshConfig) -> GatewayConfig {
    GatewayConfig {
        mesh: Some(Box::new(mesh)),
        ..GatewayConfig::default()
    }
}

/// Slice request for an `app=reviews` workload in `default`, with Sidecar
/// enforcement on and dry-run off (the gate the policy needs).
fn enforced_request() -> MeshSliceRequest {
    MeshSliceRequest {
        node_id: "node-a".to_string(),
        namespace: "default".to_string(),
        labels: [("app".to_string(), "reviews".to_string())]
            .into_iter()
            .collect(),
        enforce_sidecar_egress: true,
        ..MeshSliceRequest::default()
    }
}

fn slice_for(config: &GatewayConfig, request: MeshSliceRequest) -> MeshSlice {
    MeshSlice::from_gateway_config(config, request)
}

// ── Selection ─────────────────────────────────────────────────────────────

#[test]
fn workload_scoped_sidecar_policy_wins_over_the_namespace_default() {
    let config = config_with_sidecars(vec![
        sidecar(
            "ns-default",
            "default",
            None,
            Some(OutboundTrafficPolicy::AllowAny),
        ),
        sidecar(
            "reviews",
            "default",
            Some(selector_for("reviews", "default")),
            Some(OutboundTrafficPolicy::RegistryOnly),
        ),
    ]);
    let slice = slice_for(&config, enforced_request());
    assert_eq!(
        slice.sidecar_outbound_traffic_policy,
        Some(OutboundTrafficPolicy::RegistryOnly),
        "the most specific applicable Sidecar supplies the policy"
    );
}

#[test]
fn non_matching_workload_selector_does_not_supply_a_policy() {
    let config = config_with_sidecars(vec![sidecar(
        "ratings",
        "default",
        Some(selector_for("ratings", "default")),
        Some(OutboundTrafficPolicy::RegistryOnly),
    )]);
    let slice = slice_for(&config, enforced_request());
    assert_eq!(
        slice.sidecar_outbound_traffic_policy, None,
        "a Sidecar that does not select this workload must not gate its egress"
    );
}

#[test]
fn namespace_default_supplies_the_policy_when_no_workload_scoped_sidecar_matches() {
    let config = config_with_sidecars(vec![sidecar(
        "ns-default",
        "default",
        None,
        Some(OutboundTrafficPolicy::RegistryOnly),
    )]);
    let slice = slice_for(&config, enforced_request());
    assert_eq!(
        slice.sidecar_outbound_traffic_policy,
        Some(OutboundTrafficPolicy::RegistryOnly)
    );
}

#[test]
fn selected_sidecar_omitting_the_policy_inherits_instead_of_walking_to_a_less_specific_one() {
    // Istio resolves exactly ONE Sidecar per workload. The workload-scoped one
    // wins; because it omits `outboundTrafficPolicy`, the workload inherits the
    // mesh-wide value — it must NOT fall through to the namespace default's
    // REGISTRY_ONLY (that would be an `egress`-only inheritance rule applied
    // where Istio has none).
    let config = config_with_sidecars(vec![
        sidecar(
            "ns-default",
            "default",
            None,
            Some(OutboundTrafficPolicy::RegistryOnly),
        ),
        sidecar(
            "reviews",
            "default",
            Some(selector_for("reviews", "default")),
            None,
        ),
    ]);
    let slice = slice_for(&config, enforced_request());
    assert_eq!(
        slice.sidecar_outbound_traffic_policy, None,
        "an omitted block on the selected Sidecar inherits the mesh-wide policy"
    );
}

#[test]
fn same_tier_sidecars_resolve_deterministically_by_ascii_smallest_name() {
    let sidecars = vec![
        sidecar(
            "zzz-default",
            "default",
            None,
            Some(OutboundTrafficPolicy::AllowAny),
        ),
        sidecar(
            "aaa-default",
            "default",
            None,
            Some(OutboundTrafficPolicy::RegistryOnly),
        ),
    ];
    let forward = slice_for(&config_with_sidecars(sidecars.clone()), enforced_request());
    let reversed_input: Vec<MeshSidecar> = sidecars.into_iter().rev().collect();
    let reversed = slice_for(&config_with_sidecars(reversed_input), enforced_request());
    assert_eq!(
        forward.sidecar_outbound_traffic_policy,
        Some(OutboundTrafficPolicy::RegistryOnly),
        "the ASCII-smallest name wins within a tier"
    );
    assert_eq!(
        forward.sidecar_outbound_traffic_policy, reversed.sidecar_outbound_traffic_policy,
        "resolution must not depend on translator emission order"
    );
}

// ── Enforcement gate ──────────────────────────────────────────────────────

#[test]
fn sidecar_policy_is_not_applied_when_enforcement_is_off() {
    let config = config_with_sidecars(vec![sidecar(
        "ns-default",
        "default",
        None,
        Some(OutboundTrafficPolicy::RegistryOnly),
    )]);
    let slice = slice_for(
        &config,
        MeshSliceRequest {
            enforce_sidecar_egress: false,
            ..enforced_request()
        },
    );
    assert_eq!(
        slice.sidecar_outbound_traffic_policy, None,
        "FERRUM_MESH_SIDECAR_ENFORCED gates the workload-scoped policy"
    );
}

#[test]
fn sidecar_policy_is_not_applied_under_dry_run() {
    // Dry-run reports the egress scope that WOULD apply and changes nothing;
    // arming the registry gate is a live behavior change.
    let config = config_with_sidecars(vec![sidecar(
        "ns-default",
        "default",
        None,
        Some(OutboundTrafficPolicy::RegistryOnly),
    )]);
    let slice = slice_for(
        &config,
        MeshSliceRequest {
            sidecar_egress_dry_run: true,
            ..enforced_request()
        },
    );
    assert_eq!(
        slice.sidecar_outbound_traffic_policy, None,
        "dry-run must not arm the outbound registry gate"
    );
    assert!(
        slice.sidecar_egress_scope.is_some(),
        "dry-run still reports the egress scope"
    );
}

// ── Effective precedence ──────────────────────────────────────────────────

#[test]
fn effective_policy_prefers_sidecar_then_mesh_wide_then_runtime_default() {
    let mesh_wide = MeshSlice {
        outbound_traffic_policy: Some(OutboundTrafficPolicy::RegistryOnly),
        ..MeshSlice::default()
    };
    let sidecar_relaxes = MeshSlice {
        sidecar_outbound_traffic_policy: Some(OutboundTrafficPolicy::AllowAny),
        ..mesh_wide.clone()
    };
    let sidecar_tightens = MeshSlice {
        sidecar_outbound_traffic_policy: Some(OutboundTrafficPolicy::RegistryOnly),
        outbound_traffic_policy: Some(OutboundTrafficPolicy::AllowAny),
        ..MeshSlice::default()
    };
    let inherits_runtime = MeshSlice::default();

    assert_eq!(
        mesh_wide.effective_outbound_traffic_policy(OutboundTrafficPolicy::AllowAny),
        OutboundTrafficPolicy::RegistryOnly,
        "the mesh-wide policy overrides the runtime default"
    );
    assert_eq!(
        sidecar_relaxes.effective_outbound_traffic_policy(OutboundTrafficPolicy::AllowAny),
        OutboundTrafficPolicy::AllowAny,
        "a Sidecar ALLOW_ANY relaxes a mesh-wide REGISTRY_ONLY (Istio semantics)"
    );
    assert_eq!(
        sidecar_tightens.effective_outbound_traffic_policy(OutboundTrafficPolicy::AllowAny),
        OutboundTrafficPolicy::RegistryOnly,
        "a Sidecar REGISTRY_ONLY tightens an otherwise-permissive mesh"
    );
    assert_eq!(
        inherits_runtime.effective_outbound_traffic_policy(OutboundTrafficPolicy::RegistryOnly),
        OutboundTrafficPolicy::RegistryOnly,
        "with neither tier set, FERRUM_MESH_OUTBOUND_TRAFFIC_POLICY decides"
    );
    assert_eq!(
        inherits_runtime.effective_outbound_traffic_policy(OutboundTrafficPolicy::AllowAny),
        OutboundTrafficPolicy::AllowAny,
        "the shipped default stays AllowAny"
    );
}

// ── Update / delete ───────────────────────────────────────────────────────

#[test]
fn editing_only_the_mode_changes_the_slice_and_is_visible_to_content_eq() {
    let registry_only = slice_for(
        &config_with_sidecars(vec![sidecar(
            "ns-default",
            "default",
            None,
            Some(OutboundTrafficPolicy::RegistryOnly),
        )]),
        enforced_request(),
    );
    let allow_any = slice_for(
        &config_with_sidecars(vec![sidecar(
            "ns-default",
            "default",
            None,
            Some(OutboundTrafficPolicy::AllowAny),
        )]),
        enforced_request(),
    );
    assert_ne!(
        registry_only.sidecar_outbound_traffic_policy, allow_any.sidecar_outbound_traffic_policy,
        "the edit must reach the slice"
    );
    assert!(
        !registry_only.content_eq(&allow_any),
        "content_eq must see a mode-only edit, or MeshSubscribe dedupe keeps the stale gate live"
    );
}

#[test]
fn deleting_the_sidecar_falls_back_to_the_mesh_wide_policy() {
    let before = slice_for(
        &config_with_sidecars(vec![sidecar(
            "ns-default",
            "default",
            None,
            Some(OutboundTrafficPolicy::RegistryOnly),
        )]),
        enforced_request(),
    );
    let after = slice_for(&config_with_sidecars(Vec::new()), enforced_request());

    assert_eq!(
        before.sidecar_outbound_traffic_policy,
        Some(OutboundTrafficPolicy::RegistryOnly)
    );
    assert_eq!(
        after.sidecar_outbound_traffic_policy, None,
        "deleting the Sidecar withdraws its override"
    );
    assert!(
        !before.content_eq(&after),
        "the withdrawal must not be deduped away"
    );
    assert_eq!(
        after.effective_outbound_traffic_policy(OutboundTrafficPolicy::AllowAny),
        OutboundTrafficPolicy::AllowAny,
        "after deletion the workload falls back to the mesh-wide/runtime policy"
    );
}

#[test]
fn withdrawing_a_relaxing_sidecar_restores_the_mesh_wide_registry_gate() {
    // The security-relevant direction: a Sidecar ALLOW_ANY was masking a
    // mesh-wide REGISTRY_ONLY. Deleting it must re-arm the gate.
    let mesh_with_sidecar = MeshConfig {
        outbound_traffic_policy: Some(OutboundTrafficPolicy::RegistryOnly),
        sidecars: vec![sidecar(
            "ns-default",
            "default",
            None,
            Some(OutboundTrafficPolicy::AllowAny),
        )],
        ..MeshConfig::default()
    };
    let mesh_without_sidecar = MeshConfig {
        outbound_traffic_policy: Some(OutboundTrafficPolicy::RegistryOnly),
        ..MeshConfig::default()
    };
    let before = slice_for(&config_with_mesh(mesh_with_sidecar), enforced_request());
    let after = slice_for(&config_with_mesh(mesh_without_sidecar), enforced_request());

    assert_eq!(
        before.effective_outbound_traffic_policy(OutboundTrafficPolicy::AllowAny),
        OutboundTrafficPolicy::AllowAny
    );
    assert_eq!(
        after.effective_outbound_traffic_policy(OutboundTrafficPolicy::AllowAny),
        OutboundTrafficPolicy::RegistryOnly,
        "withdrawing the relaxing Sidecar must re-arm the mesh-wide gate"
    );
    assert!(!before.content_eq(&after));
}

// ── Serialization parity ──────────────────────────────────────────────────

#[test]
fn mesh_sidecar_outbound_policy_round_trips_through_native_json() {
    let original = sidecar(
        "ns-default",
        "default",
        None,
        Some(OutboundTrafficPolicy::RegistryOnly),
    );
    let encoded = serde_json::to_string(&original).expect("encode");
    assert!(
        encoded.contains("\"outbound_traffic_policy\":\"registry_only\""),
        "native/file encoding uses the snake_case enum: {encoded}"
    );
    let decoded: MeshSidecar = serde_json::from_str(&encoded).expect("decode");
    assert_eq!(decoded, original);

    // An omitted field is the inherit case and must stay omitted on the wire.
    let inheriting = sidecar("ns-default", "default", None, None);
    let encoded = serde_json::to_string(&inheriting).expect("encode");
    assert!(
        !encoded.contains("outbound_traffic_policy"),
        "the inherit case must not serialize a value: {encoded}"
    );
    let decoded: MeshSidecar = serde_json::from_str(&encoded).expect("decode");
    assert_eq!(decoded.outbound_traffic_policy, None);
}

#[test]
fn native_source_rejects_an_unknown_outbound_policy_value() {
    let malformed = json!({
        "name": "ns-default",
        "namespace": "default",
        "outbound_traffic_policy": "registry_onlyy",
    });
    let decoded: Result<MeshSidecar, _> = serde_json::from_value(malformed);
    assert!(
        decoded.is_err(),
        "the native/file source must fail closed on an unknown enum value rather \
         than silently defaulting"
    );
}

#[test]
fn slice_round_trips_the_sidecar_policy_through_the_xds_carriers() {
    let native = slice_for(
        &config_with_sidecars(vec![sidecar(
            "ns-default",
            "default",
            None,
            Some(OutboundTrafficPolicy::RegistryOnly),
        )]),
        enforced_request(),
    );
    assert_eq!(
        native.sidecar_outbound_traffic_policy,
        Some(OutboundTrafficPolicy::RegistryOnly)
    );

    let carriers = build_slice_carriers(&native);
    let policy_carrier = carriers
        .iter()
        .find(|c| matches!(c, MeshSliceCarrier::SidecarOutboundTrafficPolicy(_)))
        .expect("sidecar outbound policy carrier is emitted");
    assert_eq!(
        policy_carrier.resource_name(),
        "ferrum-mesh-carrier/sidecar-outbound-traffic-policy",
        "the reserved ECDS resource name is part of the DP's decode binding"
    );

    // Encode/decode exactly as the DP does, then apply onto a fresh slice.
    let mut recovered = MeshSlice::default();
    for carrier in &carriers {
        let bytes = carrier.encode_value().expect("encode");
        let decoded = MeshSliceCarrier::decode(carrier.type_url(), &bytes)
            .expect("decode does not error")
            .expect("a Ferrum slice carrier");
        apply_carrier(&mut recovered, decoded);
    }
    assert_eq!(
        recovered.sidecar_outbound_traffic_policy, native.sidecar_outbound_traffic_policy,
        "an xDS-built slice must resolve the same workload-scoped policy"
    );
    assert_eq!(
        recovered.effective_outbound_traffic_policy(OutboundTrafficPolicy::AllowAny),
        native.effective_outbound_traffic_policy(OutboundTrafficPolicy::AllowAny),
        "xDS and native slices must agree on the EFFECTIVE policy"
    );
}

#[test]
fn absent_sidecar_policy_carrier_is_the_wire_form_of_inherit() {
    // The DP rebuilds `RecoveredMeshSlice` per ECDS response, so a CP that stops
    // emitting the carrier (Sidecar deleted, or gate turned off) leaves the DP
    // with `None` and it falls back to the mesh-wide value. Nothing has to
    // publish an explicit "cleared" sentinel.
    let inheriting = slice_for(&config_with_sidecars(Vec::new()), enforced_request());
    let carriers = build_slice_carriers(&inheriting);
    assert!(
        !carriers
            .iter()
            .any(|c| matches!(c, MeshSliceCarrier::SidecarOutboundTrafficPolicy(_))),
        "no carrier is emitted when there is no workload-scoped override"
    );

    let mut recovered = MeshSlice::default();
    for carrier in &carriers {
        apply_carrier(&mut recovered, carrier.clone());
    }
    assert_eq!(recovered.sidecar_outbound_traffic_policy, None);
}

#[test]
fn sidecar_and_mesh_wide_policies_ride_distinct_carriers() {
    // Collapsing the two tiers onto one carrier would make a Sidecar ALLOW_ANY
    // indistinguishable from a mesh-wide ALLOW_ANY and break the
    // delete-falls-back-to-mesh-wide path.
    let mesh = MeshConfig {
        outbound_traffic_policy: Some(OutboundTrafficPolicy::AllowAny),
        sidecars: vec![sidecar(
            "ns-default",
            "default",
            None,
            Some(OutboundTrafficPolicy::RegistryOnly),
        )],
        ..MeshConfig::default()
    };
    let slice = slice_for(&config_with_mesh(mesh), enforced_request());
    let carriers = build_slice_carriers(&slice);

    let mesh_wide = carriers
        .iter()
        .find(|c| matches!(c, MeshSliceCarrier::OutboundTrafficPolicy(_)))
        .expect("mesh-wide carrier");
    let workload_scoped = carriers
        .iter()
        .find(|c| matches!(c, MeshSliceCarrier::SidecarOutboundTrafficPolicy(_)))
        .expect("workload-scoped carrier");
    assert_ne!(
        mesh_wide.type_url(),
        workload_scoped.type_url(),
        "the two precedence tiers must not share an inner type URL"
    );
    assert_ne!(
        mesh_wide.resource_name(),
        workload_scoped.resource_name(),
        "the two precedence tiers must not share an ECDS resource name"
    );
}

// ── End-to-end through the Kubernetes translator ──────────────────────────

#[test]
fn kubernetes_translated_sidecar_policy_reaches_the_slice() {
    let object = K8sObject {
        api_version: "networking.istio.io/v1".to_string(),
        kind: "Sidecar".to_string(),
        metadata: K8sMetadata {
            name: "reviews".to_string(),
            uid: String::new(),
            namespace: "default".to_string(),
            generation: Some(1),
            labels: HashMap::new(),
            annotations: HashMap::new(),
            creation_timestamp: None,
            deletion_timestamp: None,
        },
        spec: json!({
            "workloadSelector": { "labels": { "app": "reviews" } },
            "egress": [{ "hosts": ["*/*"] }],
            "outboundTrafficPolicy": { "mode": "REGISTRY_ONLY" },
        }),
        status: Value::Object(serde_json::Map::new()),
    };
    let translation = translate_k8s_objects(&[object], options()).expect("translation");
    let slice = slice_for(&translation.config, enforced_request());
    assert_eq!(
        slice.sidecar_outbound_traffic_policy,
        Some(OutboundTrafficPolicy::RegistryOnly),
        "the Kubernetes translation must reach the workload's slice"
    );
    assert_eq!(
        slice.effective_outbound_traffic_policy(OutboundTrafficPolicy::AllowAny),
        OutboundTrafficPolicy::RegistryOnly,
        "and override an otherwise-permissive runtime default"
    );
}
