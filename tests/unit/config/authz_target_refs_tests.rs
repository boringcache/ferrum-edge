//! Unit coverage for AuthorizationPolicy `targetRefs` destination matching.

use std::collections::HashMap;

use ferrum_edge::identity::spiffe::SpiffeId;
use ferrum_edge::modes::mesh::config::{
    MeshPolicy, MeshRule, PolicyAction, PolicyScope, PolicyTargetAttachment,
};
use ferrum_edge::modes::mesh::runtime::PolicyScopeCache;

fn spiffe(id: &str) -> SpiffeId {
    SpiffeId::new(id).expect("valid spiffe")
}

fn deny_policy(scope: PolicyScope) -> MeshPolicy {
    MeshPolicy {
        name: "deny-evil".to_string(),
        namespace: "default".to_string(),
        scope,
        rules: vec![MeshRule {
            action: PolicyAction::Deny,
            ..MeshRule::default()
        }],
    }
}

fn cache_with_labels(labels: HashMap<String, String>) -> PolicyScopeCache {
    PolicyScopeCache::new(
        spiffe("spiffe://cluster.local/ns/default/sa/reviews"),
        "default",
        labels,
    )
}

#[test]
fn service_target_ref_matches_destination_by_selector_labels() {
    let policy = deny_policy(PolicyScope::TargetRefs {
        attachments: vec![PolicyTargetAttachment::Service {
            namespace: "default".to_string(),
            name: "reviews".to_string(),
            selector_labels: HashMap::from([("app".to_string(), "reviews".to_string())]),
        }],
    });
    let matching = cache_with_labels(HashMap::from([("app".to_string(), "reviews".to_string())]));
    assert!(matching.policy_applies_for_destination(&policy));

    let other = cache_with_labels(HashMap::from([("app".to_string(), "ratings".to_string())]));
    assert!(!other.policy_applies_for_destination(&policy));
    // Bare label matching must not broaden targeted policies onto Sidecars.
    assert!(!matching.policy_applies(&policy));
}

#[test]
fn gateway_target_ref_applies_to_every_destination_at_waypoint() {
    let policy = deny_policy(PolicyScope::TargetRefs {
        attachments: vec![PolicyTargetAttachment::Gateway {
            namespace: "default".to_string(),
            name: "waypoint".to_string(),
        }],
    });
    let destination =
        cache_with_labels(HashMap::from([("app".to_string(), "reviews".to_string())]));
    assert!(destination.policy_applies_for_destination(&policy));
    assert!(!destination.policy_applies(&policy));
}

#[test]
fn selectorless_service_target_ref_requires_exact_service_membership() {
    let policy = deny_policy(PolicyScope::TargetRefs {
        attachments: vec![PolicyTargetAttachment::Service {
            namespace: "default".to_string(),
            name: "reviews".to_string(),
            selector_labels: HashMap::new(),
        }],
    });
    let mut member = cache_with_labels(HashMap::new());
    member.service_name = "reviews".to_string();
    member.service_namespace = "default".to_string();
    assert!(member.policy_applies_for_destination(&policy));

    let mut other = member.clone();
    other.service_name = "ratings".to_string();
    assert!(!other.policy_applies_for_destination(&policy));
}
