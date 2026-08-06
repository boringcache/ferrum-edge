//! Unit coverage for AuthorizationPolicy `targetRefs` attachment matching
//! and fail-closed config validation.

use std::collections::HashMap;

use ferrum_edge::identity::spiffe::SpiffeId;
use ferrum_edge::modes::mesh::config::{
    MeshConfig, MeshPolicy, MeshProxyConfig, MeshRequestAuthentication, MeshRule, MeshService,
    MeshWaypointBinding, PeerAuthentication, PolicyAction, PolicyScope, PolicyTargetAttachment,
    WorkloadSelector, policy_scope_applies_with_waypoint,
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

fn cache_with_service(
    labels: HashMap<String, String>,
    service_namespace: &str,
    service_name: &str,
) -> PolicyScopeCache {
    let mut cache = PolicyScopeCache::new(
        spiffe("spiffe://cluster.local/ns/default/sa/reviews"),
        "default",
        labels,
    );
    cache.service_namespace = service_namespace.to_string();
    cache.service_name = service_name.to_string();
    cache
}

#[test]
fn service_target_ref_matches_only_named_destination_not_shared_selector_labels() {
    let shared = HashMap::from([("app".to_string(), "backend".to_string())]);
    let policy = deny_policy(PolicyScope::TargetRefs {
        attachments: vec![PolicyTargetAttachment::Service {
            namespace: "default".to_string(),
            name: "reviews".to_string(),
            selector_labels: shared.clone(),
        }],
    });

    let reviews = cache_with_service(shared.clone(), "default", "reviews");
    assert!(reviews.policy_applies_for_destination(&policy));

    // Service B shares the same pod selector labels but is a different
    // destination resource — the policy must not attach.
    let ratings = cache_with_service(shared, "default", "ratings");
    assert!(!ratings.policy_applies_for_destination(&policy));

    // Bare source-scope matching must not broaden targeted policies.
    assert!(!reviews.policy_applies(&policy));
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
    let member = cache_with_service(HashMap::new(), "default", "reviews");
    assert!(member.policy_applies_for_destination(&policy));

    let mut other = member.clone();
    other.service_name = "ratings".to_string();
    assert!(!other.policy_applies_for_destination(&policy));

    // Missing destination identity fails closed.
    let mut anonymous = member;
    anonymous.service_name.clear();
    assert!(!anonymous.policy_applies_for_destination(&policy));
}

#[test]
fn gateway_target_ref_applies_to_every_destination_at_matching_waypoint() {
    let policy = deny_policy(PolicyScope::TargetRefs {
        attachments: vec![PolicyTargetAttachment::Gateway {
            namespace: "default".to_string(),
            name: "waypoint".to_string(),
        }],
    });
    let destination = cache_with_service(
        HashMap::from([("app".to_string(), "reviews".to_string())]),
        "default",
        "reviews",
    );
    assert!(destination.policy_applies_for_destination(&policy));
    assert!(!destination.policy_applies(&policy));

    let labels = HashMap::new();
    assert!(policy_scope_applies_with_waypoint(
        &policy,
        "default",
        &labels,
        Some("waypoint"),
        Some("istio-waypoint"),
    ));
    assert!(!policy_scope_applies_with_waypoint(
        &policy,
        "default",
        &labels,
        Some("other-waypoint"),
        Some("istio-waypoint"),
    ));
}

#[test]
fn gateway_class_target_ref_requires_exact_class_match() {
    let istio_policy = deny_policy(PolicyScope::TargetRefs {
        attachments: vec![PolicyTargetAttachment::GatewayClass {
            name: "istio-waypoint".to_string(),
        }],
    });
    let ferrum_policy = deny_policy(PolicyScope::TargetRefs {
        attachments: vec![PolicyTargetAttachment::GatewayClass {
            name: "ferrum-waypoint".to_string(),
        }],
    });
    let labels = HashMap::new();

    assert!(policy_scope_applies_with_waypoint(
        &istio_policy,
        "default",
        &labels,
        Some("wp"),
        Some("istio-waypoint"),
    ));
    assert!(!policy_scope_applies_with_waypoint(
        &istio_policy,
        "default",
        &labels,
        Some("wp"),
        Some("ferrum-waypoint"),
    ));
    assert!(policy_scope_applies_with_waypoint(
        &ferrum_policy,
        "default",
        &labels,
        Some("wp"),
        Some("ferrum-waypoint"),
    ));
    assert!(!policy_scope_applies_with_waypoint(
        &ferrum_policy,
        "default",
        &labels,
        Some("wp"),
        Some("istio-waypoint"),
    ));
    // Missing class evidence fails closed — never "any waypoint".
    assert!(!policy_scope_applies_with_waypoint(
        &istio_policy,
        "default",
        &labels,
        Some("wp"),
        None,
    ));
}

#[test]
fn multiple_target_refs_use_or_semantics() {
    let policy = deny_policy(PolicyScope::TargetRefs {
        attachments: vec![
            PolicyTargetAttachment::Service {
                namespace: "default".to_string(),
                name: "reviews".to_string(),
                selector_labels: HashMap::new(),
            },
            PolicyTargetAttachment::Service {
                namespace: "default".to_string(),
                name: "ratings".to_string(),
                selector_labels: HashMap::new(),
            },
        ],
    });
    assert!(
        cache_with_service(HashMap::new(), "default", "reviews")
            .policy_applies_for_destination(&policy)
    );
    assert!(
        cache_with_service(HashMap::new(), "default", "ratings")
            .policy_applies_for_destination(&policy)
    );
    assert!(
        !cache_with_service(HashMap::new(), "default", "details")
            .policy_applies_for_destination(&policy)
    );
}

#[test]
fn service_entry_target_ref_matches_exact_membership() {
    let policy = deny_policy(PolicyScope::TargetRefs {
        attachments: vec![PolicyTargetAttachment::ServiceEntry {
            namespace: "default".to_string(),
            name: "ext-api".to_string(),
            selector_labels: HashMap::from([("app".to_string(), "ext".to_string())]),
        }],
    });
    let member = cache_with_service(
        HashMap::from([("app".to_string(), "ext".to_string())]),
        "default",
        "ext-api",
    );
    assert!(member.policy_applies_for_destination(&policy));

    // Shared labels with a different ServiceEntry name must not match.
    let other = cache_with_service(
        HashMap::from([("app".to_string(), "ext".to_string())]),
        "default",
        "other-ext",
    );
    assert!(!other.policy_applies_for_destination(&policy));
}

#[test]
fn empty_target_refs_attachments_fail_closed_at_config_boundary() {
    let policy = deny_policy(PolicyScope::TargetRefs {
        attachments: Vec::new(),
    });
    let errors = MeshConfig {
        mesh_policies: vec![policy],
        ..MeshConfig::default()
    }
    .validate();
    assert!(
        errors
            .iter()
            .any(|error| error.contains("attachments must not be empty")),
        "expected empty-attachments error, got {errors:?}"
    );
}

#[test]
fn target_refs_rejected_on_shared_scope_consumers() {
    let target_refs = PolicyScope::TargetRefs {
        attachments: vec![PolicyTargetAttachment::Service {
            namespace: "default".to_string(),
            name: "reviews".to_string(),
            selector_labels: HashMap::new(),
        }],
    };
    let mesh = MeshConfig {
        services: vec![MeshService {
            name: "reviews".to_string(),
            namespace: "default".to_string(),
            ports: Vec::new(),
            workloads: Vec::new(),
            protocol_overrides: HashMap::new(),
            cluster_ips: Vec::new(),
        }],
        peer_authentications: vec![PeerAuthentication {
            name: "pa".to_string(),
            namespace: "default".to_string(),
            scope: Some(target_refs.clone()),
            selector: None,
            mtls_mode: Default::default(),
            port_overrides: HashMap::new(),
        }],
        request_authentications: vec![MeshRequestAuthentication {
            name: "ra".to_string(),
            namespace: "default".to_string(),
            scope: target_refs.clone(),
            jwt_rules: Vec::new(),
        }],
        proxy_configs: vec![MeshProxyConfig {
            name: "pc".to_string(),
            namespace: "default".to_string(),
            scope: target_refs.clone(),
            concurrency: None,
            image: None,
            environment: HashMap::new(),
            tracing_sampling: None,
        }],
        telemetry_resources: vec![ferrum_edge::modes::mesh::config::MeshTelemetryResource {
            name: "tel".to_string(),
            namespace: "default".to_string(),
            scope: target_refs,
            config: Default::default(),
        }],
        ..MeshConfig::default()
    };
    let errors = mesh.validate();
    for kind in [
        "PeerAuthentication",
        "MeshRequestAuthentication",
        "MeshProxyConfig",
        "MeshTelemetryResource",
    ] {
        assert!(
            errors
                .iter()
                .any(|error| error.contains(kind) && error.contains("target_refs is not supported")),
            "expected {kind} targetRefs rejection, got {errors:?}"
        );
    }
}

#[test]
fn mesh_policy_target_refs_require_referenced_service() {
    let policy = deny_policy(PolicyScope::TargetRefs {
        attachments: vec![PolicyTargetAttachment::Service {
            namespace: "default".to_string(),
            name: "missing".to_string(),
            selector_labels: HashMap::new(),
        }],
    });
    let errors = MeshConfig {
        mesh_policies: vec![policy],
        ..MeshConfig::default()
    }
    .validate();
    assert!(
        errors
            .iter()
            .any(|error| error.contains("Service 'default/missing' was not found")),
        "expected missing Service error, got {errors:?}"
    );
}

#[test]
fn mesh_policy_gateway_target_refs_require_waypoint_binding() {
    let policy = deny_policy(PolicyScope::TargetRefs {
        attachments: vec![PolicyTargetAttachment::Gateway {
            namespace: "default".to_string(),
            name: "waypoint".to_string(),
        }],
    });
    let with_binding = MeshConfig {
        mesh_policies: vec![policy.clone()],
        waypoint_bindings: vec![MeshWaypointBinding {
            name: "waypoint".to_string(),
            namespace: "default".to_string(),
            waypoint_for: "service".to_string(),
            gateway_class_name: Some("istio-waypoint".to_string()),
            services: Vec::new(),
        }],
        ..MeshConfig::default()
    };
    assert!(
        with_binding
            .validate()
            .iter()
            .all(|error| !error.contains("Gateway 'default/waypoint' was not found")),
        "present binding must validate: {:?}",
        with_binding.validate()
    );

    let missing = MeshConfig {
        mesh_policies: vec![policy],
        ..MeshConfig::default()
    }
    .validate();
    assert!(
        missing
            .iter()
            .any(|error| error.contains("Gateway 'default/waypoint' was not found")),
        "expected missing Gateway error, got {missing:?}"
    );
}

#[test]
fn workload_selector_still_matches_without_target_refs() {
    let policy = deny_policy(PolicyScope::WorkloadSelector {
        selector: WorkloadSelector {
            labels: HashMap::from([("app".to_string(), "reviews".to_string())]),
            namespace: Some("default".to_string()),
        },
    });
    let matching = PolicyScopeCache::new(
        spiffe("spiffe://cluster.local/ns/default/sa/reviews"),
        "default",
        HashMap::from([("app".to_string(), "reviews".to_string())]),
    );
    assert!(matching.policy_applies(&policy));
}
