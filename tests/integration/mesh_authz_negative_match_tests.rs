//! Integration coverage for `AuthorizationPolicy` negative-match fields
//! (`notMethods`, `notPaths`, `notHosts`, `notPorts`).
//!
//! Exercises the canonical Istio scenario end-to-end through the
//! `mesh_authz` plugin: an ALLOW policy that combines a positive `methods`
//! match with a negative `notPaths` match — the resulting rule must
//! authorise GET /api but deny BOTH GET /admin (negative match fires) AND
//! POST /admin (positive method match fails).
//!
//! This is the same scenario covered by inline policy.rs and istio.rs
//! tests; this integration test additionally drives it through the plugin
//! surface (`MeshAuthz::authorize`) so the wiring between the JSON
//! plugin-config schema, the policy evaluator, and the plugin's reject
//! semantics is validated together.
use ferrum_edge::identity::{SpiffeId, TrustDomain};
use ferrum_edge::modes::mesh::config::{
    ConditionMatch, MeshPolicy, MeshRule, PolicyAction, PolicyScope, PrincipalMatch, RequestMatch,
    SourceNegationMatch, WorkloadSelector,
};
use ferrum_edge::plugins::mesh::authz::MeshAuthz;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext};
use serde_json::json;

fn policy_allow_get_except_admin() -> MeshPolicy {
    MeshPolicy {
        name: "allow-get-except-admin".to_string(),
        namespace: "default".to_string(),
        scope: PolicyScope::WorkloadSelector {
            selector: WorkloadSelector::default(),
        },
        rules: vec![MeshRule {
            from: vec![PrincipalMatch {
                spiffe_id_pattern: Some("spiffe://cluster.local/ns/default/sa/client".to_string()),
                namespace_pattern: None,
                trust_domain: Some(TrustDomain::new("cluster.local").expect("trust domain")),
            }],
            to: vec![RequestMatch {
                methods: vec!["GET".to_string()],
                not_paths: vec!["/admin/*".to_string()],
                ..RequestMatch::default()
            }],
            when: Vec::new(),
            request_principals: Vec::new(),
            not_request_principals: Vec::new(),
            source_negation: Default::default(),
            never_matches: false,
            action: PolicyAction::Allow,
        }],
    }
}

fn request_context(method: &str, path: &str) -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        method.to_string(),
        path.to_string(),
    );
    ctx.peer_spiffe_id = Some(
        SpiffeId::new("spiffe://cluster.local/ns/default/sa/client").expect("valid spiffe id"),
    );
    ctx
}

fn policy_allow_example_except_admin_mixed_case_not_host() -> MeshPolicy {
    MeshPolicy {
        name: "allow-example-except-admin".to_string(),
        namespace: "default".to_string(),
        scope: PolicyScope::WorkloadSelector {
            selector: WorkloadSelector::default(),
        },
        rules: vec![MeshRule {
            from: vec![PrincipalMatch {
                spiffe_id_pattern: Some("spiffe://cluster.local/ns/default/sa/client".to_string()),
                namespace_pattern: None,
                trust_domain: Some(TrustDomain::new("cluster.local").expect("trust domain")),
            }],
            to: vec![RequestMatch {
                hosts: vec!["*.example.com".to_string()],
                not_hosts: vec!["Admin.Example.COM.".to_string()],
                ..RequestMatch::default()
            }],
            when: Vec::new(),
            request_principals: Vec::new(),
            not_request_principals: Vec::new(),
            source_negation: Default::default(),
            never_matches: false,
            action: PolicyAction::Allow,
        }],
    }
}

#[tokio::test]
async fn allow_with_methods_and_not_paths_authorizes_get_to_non_admin_path() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [policy_allow_get_except_admin()]
    }))
    .expect("plugin config");
    let mut ctx = request_context("GET", "/api/items");

    let result = plugin.authorize(&mut ctx).await;

    assert!(
        matches!(result, PluginResult::Continue),
        "GET /api should be allowed (positive method match + negative path mismatch), got {result:?}"
    );
}

#[tokio::test]
async fn allow_with_methods_and_not_paths_denies_get_to_admin_path() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [policy_allow_get_except_admin()]
    }))
    .expect("plugin config");
    let mut ctx = request_context("GET", "/admin/users");

    let result = plugin.authorize(&mut ctx).await;

    match result {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        other => panic!(
            "GET /admin should be rejected (negative path match → rule fails → \
             implicit deny), got {other:?}"
        ),
    }
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.deny_policy")
            .map(String::as_str),
        Some("implicit-deny")
    );
}

#[tokio::test]
async fn allow_with_methods_and_not_paths_denies_post_to_admin_path() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [policy_allow_get_except_admin()]
    }))
    .expect("plugin config");
    let mut ctx = request_context("POST", "/admin/users");

    let result = plugin.authorize(&mut ctx).await;

    match result {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        other => panic!(
            "POST /admin should be rejected (positive method does not match GET \
             → rule fails → implicit deny), got {other:?}"
        ),
    }
}

#[tokio::test]
async fn allow_with_methods_and_not_paths_denies_post_to_non_admin_path() {
    // Sanity: POST /api also fails because the positive method=GET predicate
    // does not match POST. This is independent of the negative-match logic
    // but locks in conjunctive-AND semantics across positive + negative.
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [policy_allow_get_except_admin()]
    }))
    .expect("plugin config");
    let mut ctx = request_context("POST", "/api/items");

    let result = plugin.authorize(&mut ctx).await;

    assert!(
        matches!(result, PluginResult::Reject { .. }),
        "POST /api should fall through to implicit-deny, got {result:?}"
    );
}

#[tokio::test]
async fn direct_plugin_config_normalizes_not_hosts() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [policy_allow_example_except_admin_mixed_case_not_host()]
    }))
    .expect("plugin config");
    let mut ctx = request_context("GET", "/api/items");
    ctx.headers
        .insert("host".to_string(), "admin.example.com".to_string());

    let result = plugin.authorize(&mut ctx).await;

    assert!(
        matches!(result, PluginResult::Reject { .. }),
        "admin.example.com should be denied because mixed-case/trailing-dot not_hosts must normalize, got {result:?}"
    );
}

// ── `when:` condition enforcement (previously fail-open) ──────────────────

fn deny_when_source_namespace(namespace: &str) -> MeshPolicy {
    MeshPolicy {
        name: "deny-source-namespace".to_string(),
        namespace: "default".to_string(),
        scope: PolicyScope::WorkloadSelector {
            selector: WorkloadSelector::default(),
        },
        rules: vec![MeshRule {
            when: vec![ConditionMatch {
                key: "source.namespace".to_string(),
                values: vec![namespace.to_string()],
                not_values: Vec::new(),
            }],
            action: PolicyAction::Deny,
            ..MeshRule::default()
        }],
    }
}

#[tokio::test]
async fn deny_gated_on_when_source_namespace_now_fires_through_plugin() {
    // Regression: `when:` conditions were inert because both authz entry
    // points hard-coded empty attributes. A DENY gated on the source
    // namespace must now actually deny a caller from that namespace.
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [deny_when_source_namespace("prod")]
    }))
    .expect("plugin config");

    // Caller SPIFFE id encodes ns/prod → source.namespace = "prod" → DENY.
    let mut prod_ctx = request_context("GET", "/api");
    prod_ctx.peer_spiffe_id =
        Some(SpiffeId::new("spiffe://cluster.local/ns/prod/sa/client").expect("spiffe"));
    let prod_result = plugin.authorize(&mut prod_ctx).await;
    assert!(
        matches!(
            prod_result,
            PluginResult::Reject {
                status_code: 403,
                ..
            }
        ),
        "caller in ns/prod must be denied by when-gated DENY, got {prod_result:?}"
    );

    // Caller in a different namespace is not denied (DENY does not fire, and
    // with no ALLOW policy the default decision is allow).
    let mut staging_ctx = request_context("GET", "/api");
    staging_ctx.peer_spiffe_id =
        Some(SpiffeId::new("spiffe://cluster.local/ns/staging/sa/client").expect("spiffe"));
    let staging_result = plugin.authorize(&mut staging_ctx).await;
    assert!(
        matches!(staging_result, PluginResult::Continue),
        "caller in ns/staging must not be denied, got {staging_result:?}"
    );
}

#[tokio::test]
async fn allow_with_not_namespaces_enforced_through_plugin() {
    // ALLOW gated by a source `notNamespaces` matcher: callers in the listed
    // namespace fall through to implicit deny; others are admitted.
    let allow = MeshPolicy {
        name: "allow-except-kube-system".to_string(),
        namespace: "default".to_string(),
        scope: PolicyScope::WorkloadSelector {
            selector: WorkloadSelector::default(),
        },
        rules: vec![MeshRule {
            source_negation: SourceNegationMatch {
                not_namespace_patterns: vec!["kube-system".to_string()],
                ..SourceNegationMatch::default()
            },
            action: PolicyAction::Allow,
            ..MeshRule::default()
        }],
    };
    let plugin = MeshAuthz::new(&json!({ "mesh_policies": [allow] })).expect("plugin config");

    let mut blocked = request_context("GET", "/api");
    blocked.peer_spiffe_id =
        Some(SpiffeId::new("spiffe://cluster.local/ns/kube-system/sa/probe").expect("spiffe"));
    assert!(
        matches!(
            plugin.authorize(&mut blocked).await,
            PluginResult::Reject { .. }
        ),
        "kube-system caller must be denied by notNamespaces"
    );

    let mut allowed = request_context("GET", "/api");
    allowed.peer_spiffe_id =
        Some(SpiffeId::new("spiffe://cluster.local/ns/default/sa/web").expect("spiffe"));
    assert!(
        matches!(plugin.authorize(&mut allowed).await, PluginResult::Continue),
        "default-namespace caller must be allowed"
    );
}

#[tokio::test]
async fn allow_with_remote_ip_blocks_enforced_through_plugin() {
    // ALLOW gated by a source `remoteIpBlocks` matcher resolved from the
    // gateway-computed client IP. In-range clients are admitted; others fall
    // through to implicit deny.
    let allow = MeshPolicy {
        name: "allow-from-corp-range".to_string(),
        namespace: "default".to_string(),
        scope: PolicyScope::WorkloadSelector {
            selector: WorkloadSelector::default(),
        },
        rules: vec![MeshRule {
            source_negation: SourceNegationMatch {
                remote_ip_blocks: vec!["203.0.113.0/24".to_string()],
                ..SourceNegationMatch::default()
            },
            action: PolicyAction::Allow,
            ..MeshRule::default()
        }],
    };
    let plugin = MeshAuthz::new(&json!({ "mesh_policies": [allow] })).expect("plugin config");

    let mut in_range = RequestContext::new(
        "203.0.113.45".to_string(),
        "GET".to_string(),
        "/api".to_string(),
    );
    in_range.peer_spiffe_id =
        Some(SpiffeId::new("spiffe://cluster.local/ns/default/sa/web").expect("spiffe"));
    assert!(
        matches!(
            plugin.authorize(&mut in_range).await,
            PluginResult::Continue
        ),
        "client in 203.0.113.0/24 must be allowed"
    );

    let mut out_of_range = RequestContext::new(
        "198.51.100.7".to_string(),
        "GET".to_string(),
        "/api".to_string(),
    );
    out_of_range.peer_spiffe_id =
        Some(SpiffeId::new("spiffe://cluster.local/ns/default/sa/web").expect("spiffe"));
    assert!(
        matches!(
            plugin.authorize(&mut out_of_range).await,
            PluginResult::Reject { .. }
        ),
        "client outside 203.0.113.0/24 must be denied"
    );
}
