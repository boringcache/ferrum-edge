//! External xDS round-trip coverage for AuthorizationPolicy GatewayClass
//! `targetRefs` (issue #3226 / PR #3602).
//!
//! Drives the real CP encode (`translate_mesh_slice_to_snapshot` /
//! `build_slice_carriers`) → ECDS TypedExtensionConfig wire → DP decode
//! (`MeshSliceCarrier::decode` / `apply_carrier`) path, then proves
//! `mesh_authz` retains the GatewayClass DENY policy only for an exact
//! matching class stamp. Malformed and oversized carriers are rejected, while
//! missing or removed carriers never invent or reuse a stale class stamp. The
//! DP's production reverse-translation tests separately pin rejection of an
//! enforcing GatewayClass policy whose authoritative carrier is missing.

use ferrum_edge::modes::mesh::config::{
    MAX_POLICY_TARGET_REF_NAME_LEN, MAX_POLICY_TARGET_REF_NAMESPACE_LEN,
    MAX_POLICY_TARGET_REF_SELECTOR_KEY_LEN, MAX_POLICY_TARGET_REF_SELECTOR_VALUE_LEN, MeshConfig,
    MeshPolicy, MeshRule, MeshService, PolicyAction, PolicyScope, PolicyTargetAttachment,
};
use ferrum_edge::modes::mesh::slice::MeshSlice;
use ferrum_edge::plugins::mesh::authz::MeshAuthz;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext};
use ferrum_edge::xds::proto;
use ferrum_edge::xds::{
    ECDS_TYPE_URL, FERRUM_ECDS_WAYPOINT_GATEWAY_CLASS_TYPE_URL,
    MAX_WAYPOINT_GATEWAY_CLASS_CARRIER_BYTES, MAX_WAYPOINT_GATEWAY_CLASS_LEN, MeshSliceCarrier,
    apply_carrier, build_slice_carriers, translate_mesh_slice_to_snapshot,
};
use prost::Message;
use serde_json::json;

fn gateway_class_deny_policy(class_name: &str) -> MeshPolicy {
    MeshPolicy {
        name: "deny-class".to_string(),
        namespace: "istio-system".to_string(),
        scope: PolicyScope::TargetRefs {
            attachments: vec![PolicyTargetAttachment::GatewayClass {
                name: class_name.to_string(),
            }],
        },
        rules: vec![MeshRule {
            action: PolicyAction::Deny,
            ..MeshRule::default()
        }],
    }
}

fn waypoint_slice(class: Option<&str>, policy_class: &str) -> MeshSlice {
    MeshSlice {
        node_id: "wp-node".to_string(),
        namespace: "default".to_string(),
        waypoint_name: Some("reviews-waypoint".to_string()),
        waypoint_gateway_class: class.map(str::to_string),
        mesh_policies: vec![gateway_class_deny_policy(policy_class)],
        version: "v1".to_string(),
        ..MeshSlice::default()
    }
}

/// Recover a slice from a CP snapshot the same way the DP folds ECDS carriers,
/// then stamp `waypoint_name` from the DP client config (name rides Node
/// metadata; class rides the dedicated carrier).
fn recover_from_snapshot(
    snapshot: &ferrum_edge::xds::XdsSnapshot,
    waypoint_name: Option<&str>,
) -> Result<MeshSlice, String> {
    let mut recovered = MeshSlice {
        node_id: "wp-node".to_string(),
        namespace: "default".to_string(),
        waypoint_name: waypoint_name.map(str::to_string),
        version: snapshot.version.clone(),
        ..MeshSlice::default()
    };
    let mut class_seen = false;
    for resource in snapshot.resources(ECDS_TYPE_URL) {
        let typed = proto::TypedExtensionConfig::decode(resource.value.as_slice())
            .map_err(|e| format!("TypedExtensionConfig decode: {e}"))?;
        let Some(inner) = typed.typed_config.as_ref() else {
            continue;
        };
        match MeshSliceCarrier::decode(&inner.type_url, &inner.value) {
            Ok(Some(carrier @ MeshSliceCarrier::WaypointGatewayClass(_))) => {
                if class_seen {
                    return Err(
                        "duplicate WaypointGatewayClass carrier; exactly one authoritative value required"
                            .to_string(),
                    );
                }
                class_seen = true;
                apply_carrier(&mut recovered, carrier);
            }
            Ok(Some(carrier)) => apply_carrier(&mut recovered, carrier),
            Ok(None) => {}
            Err(e) => {
                return Err(format!(
                    "carrier decode failed for '{}': {e}",
                    inner.type_url
                ));
            }
        }
    }
    Ok(recovered)
}

async fn gateway_class_policy_enforced(slice: &MeshSlice) -> bool {
    let plugin = MeshAuthz::new(&json!({ "mesh_slice": slice }))
        .expect("mesh_authz builds from recovered slice");
    let mut ctx = RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), "/".to_string());
    matches!(
        plugin.authorize(&mut ctx).await,
        PluginResult::Reject { .. }
    )
}

#[tokio::test]
async fn xds_round_trip_exact_matching_gateway_class_retains_authz_policy() {
    let native = waypoint_slice(Some("istio-waypoint"), "istio-waypoint");
    let snapshot = translate_mesh_slice_to_snapshot(&native);
    let recovered = recover_from_snapshot(&snapshot, Some("reviews-waypoint"))
        .expect("exact-class snapshot recovers");
    assert_eq!(
        recovered.waypoint_gateway_class.as_deref(),
        Some("istio-waypoint")
    );
    assert_eq!(recovered.mesh_policies, native.mesh_policies);
    assert!(
        gateway_class_policy_enforced(&recovered).await,
        "exact matching GatewayClass policy must survive mesh_authz retain"
    );
}

#[tokio::test]
async fn xds_round_trip_different_gateway_class_drops_authz_policy() {
    let native = waypoint_slice(Some("ferrum-waypoint"), "istio-waypoint");
    let snapshot = translate_mesh_slice_to_snapshot(&native);
    let recovered = recover_from_snapshot(&snapshot, Some("reviews-waypoint"))
        .expect("different-class snapshot recovers");
    assert_eq!(
        recovered.waypoint_gateway_class.as_deref(),
        Some("ferrum-waypoint")
    );
    assert!(
        !gateway_class_policy_enforced(&recovered).await,
        "mismatched GatewayClass must fail closed at mesh_authz retain"
    );
}

#[tokio::test]
async fn xds_round_trip_missing_gateway_class_carrier_does_not_invent_stamp() {
    let native = waypoint_slice(Some("istio-waypoint"), "istio-waypoint");
    let carriers: Vec<_> = build_slice_carriers(&native)
        .into_iter()
        .filter(|c| !matches!(c, MeshSliceCarrier::WaypointGatewayClass(_)))
        .collect();
    let mut recovered = MeshSlice {
        node_id: native.node_id.clone(),
        namespace: native.namespace.clone(),
        waypoint_name: native.waypoint_name.clone(),
        mesh_policies: native.mesh_policies.clone(),
        ..MeshSlice::default()
    };
    for carrier in carriers {
        apply_carrier(&mut recovered, carrier);
    }
    assert!(
        recovered.waypoint_gateway_class.is_none(),
        "missing carrier must not invent a class stamp"
    );
    assert!(!gateway_class_policy_enforced(&recovered).await);
}

#[test]
fn xds_round_trip_malformed_and_oversized_gateway_class_carrier_rejected() {
    assert!(
        MeshSliceCarrier::decode(FERRUM_ECDS_WAYPOINT_GATEWAY_CLASS_TYPE_URL, b"{not-json")
            .is_err()
    );
    assert!(
        MeshSliceCarrier::decode(FERRUM_ECDS_WAYPOINT_GATEWAY_CLASS_TYPE_URL, b"\"\"").is_err()
    );
    let oversized =
        serde_json::to_vec(&"a".repeat(MAX_WAYPOINT_GATEWAY_CLASS_LEN + 1)).expect("json");
    assert!(
        MeshSliceCarrier::decode(FERRUM_ECDS_WAYPOINT_GATEWAY_CLASS_TYPE_URL, &oversized).is_err()
    );
    let huge_payload = format!("\"{}\"", "x".repeat(MAX_WAYPOINT_GATEWAY_CLASS_CARRIER_BYTES));
    assert!(
        MeshSliceCarrier::decode(
            FERRUM_ECDS_WAYPOINT_GATEWAY_CLASS_TYPE_URL,
            huge_payload.as_bytes()
        )
        .is_err()
    );
}

#[tokio::test]
async fn xds_round_trip_gateway_class_change_updates_authz_and_content_eq() {
    let istio = waypoint_slice(Some("istio-waypoint"), "istio-waypoint");
    let ferrum = waypoint_slice(Some("ferrum-waypoint"), "istio-waypoint");
    assert!(
        !istio.content_eq(&ferrum),
        "class-only change must move MeshSlice::content_eq"
    );

    let istio_recovered = recover_from_snapshot(
        &translate_mesh_slice_to_snapshot(&istio),
        Some("reviews-waypoint"),
    )
    .expect("istio class recovers");
    let ferrum_recovered = recover_from_snapshot(
        &translate_mesh_slice_to_snapshot(&ferrum),
        Some("reviews-waypoint"),
    )
    .expect("ferrum class recovers");

    assert!(gateway_class_policy_enforced(&istio_recovered).await);
    assert!(
        !gateway_class_policy_enforced(&ferrum_recovered).await,
        "class change to a non-matching stamp must drop the policy"
    );
    assert!(!istio_recovered.content_eq(&ferrum_recovered));
}

#[tokio::test]
async fn xds_round_trip_gateway_class_carrier_removal_clears_stamp_and_policy() {
    let with_class = waypoint_slice(Some("istio-waypoint"), "istio-waypoint");
    let mut without_class = waypoint_slice(None, "istio-waypoint");
    without_class.mesh_policies.clear();
    assert!(!with_class.content_eq(&without_class));

    let removed = recover_from_snapshot(
        &translate_mesh_slice_to_snapshot(&without_class),
        Some("reviews-waypoint"),
    )
    .expect("class-less snapshot recovers");
    assert!(
        removed.waypoint_gateway_class.is_none(),
        "carrier removal must clear the class, not reuse a stale stamp"
    );
    assert!(!gateway_class_policy_enforced(&removed).await);

    assert!(
        !build_slice_carriers(&without_class)
            .iter()
            .any(|c| matches!(c, MeshSliceCarrier::WaypointGatewayClass(_)))
    );
    assert!(
        build_slice_carriers(&with_class)
            .iter()
            .any(|c| matches!(c, MeshSliceCarrier::WaypointGatewayClass(_)))
    );
}

#[test]
fn native_target_refs_reject_over_limit_hostile_strings() {
    let over_name = "n".repeat(MAX_POLICY_TARGET_REF_NAME_LEN + 1);
    let over_ns = "n".repeat(MAX_POLICY_TARGET_REF_NAMESPACE_LEN + 1);
    let over_key = "k".repeat(MAX_POLICY_TARGET_REF_SELECTOR_KEY_LEN + 1);
    let over_value = "v".repeat(MAX_POLICY_TARGET_REF_SELECTOR_VALUE_LEN + 1);

    let errors = MeshConfig {
        services: vec![MeshService {
            name: "reviews".to_string(),
            namespace: "default".to_string(),
            ports: Vec::new(),
            workloads: Vec::new(),
            protocol_overrides: Default::default(),
            cluster_ips: Vec::new(),
        }],
        mesh_policies: vec![MeshPolicy {
            name: "hostile".to_string(),
            namespace: "default".to_string(),
            scope: PolicyScope::TargetRefs {
                attachments: vec![
                    PolicyTargetAttachment::Service {
                        namespace: over_ns,
                        name: "reviews".to_string(),
                        selector_labels: [(over_key, over_value)].into_iter().collect(),
                    },
                    PolicyTargetAttachment::GatewayClass { name: over_name },
                ],
            },
            rules: vec![MeshRule {
                action: PolicyAction::Deny,
                ..MeshRule::default()
            }],
        }],
        ..MeshConfig::default()
    }
    .validate();

    assert!(
        errors
            .iter()
            .any(|e| e.contains("namespace") && e.contains("at most")),
        "over-limit namespace must reject: {errors:?}"
    );
    assert!(
        errors
            .iter()
            .any(|e| e.contains("name") && e.contains("at most")),
        "over-limit GatewayClass/name must reject: {errors:?}"
    );
    assert!(
        errors
            .iter()
            .any(|e| e.contains("selector_labels") && e.contains("at most")),
        "over-limit selector key/value must reject: {errors:?}"
    );
}
