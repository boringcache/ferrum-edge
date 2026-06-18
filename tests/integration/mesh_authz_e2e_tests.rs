//! End-to-end coverage for the `mesh_authz` plugin's request-path
//! behaviour.
//!
//! These tests construct `MeshAuthz` from the same plugin-config shape
//! `inject_mesh_global_plugins()` emits in production, then drive
//! requests through `Plugin::authorize` with realistic
//! `RequestContext` state. The focus is the cross-cutting policy
//! semantics that operators rely on:
//!
//! - DENY-first within a policy chain
//! - implicit deny when any ALLOW rule is present but no rule matches
//!   (Istio semantics)
//! - construction-time `PolicyScope` filter (WorkloadSelector /
//!   Namespace / MeshWide)
//! - principal globbing, request-match conjunction with negative-match
//!   predicates, condition matching, request-principal (JWT-derived)
//!   matching
//! - AUDIT action — counted, never blocks
//! - trust-domain alias acceptance for HBONE baggage
//!
//! Pure rule-matching helper coverage lives in inline `#[cfg(test)]`
//! modules under `src/modes/mesh/policy.rs`; these tests lock in the
//! observable plugin-surface behaviour those helpers compose into.

#![allow(clippy::too_many_arguments)]

use std::collections::HashMap;

use ferrum_edge::config::types::{BackendScheme, Consumer};
use ferrum_edge::consumer_index::ConsumerIndex;
use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain};
use ferrum_edge::modes::mesh::MeshTrafficDirection;
use ferrum_edge::modes::mesh::config::{
    ConditionMatch, MeshPolicy, MeshRule, PolicyAction, PolicyScope, PrincipalMatch, RequestMatch,
    WorkloadSelector,
};
use ferrum_edge::plugins::mesh::authz::MeshAuthz;
use ferrum_edge::plugins::{
    JwtAuthAttributeValue, Plugin, PluginResult, RequestContext, StreamConnectionContext,
};
use serde_json::json;
use std::sync::Arc;

use super::mesh_test_support::{
    DEFAULT_NAMESPACE, DEFAULT_TRUST_DOMAIN, default_mesh_runtime, mesh_config_with,
    policy_allow_principal, policy_deny_principal,
};
use ferrum_edge::modes::mesh::config::MeshConfig;
use ferrum_edge::modes::mesh::{MESH_AUTHZ_PLUGIN_ID, prepare_gateway_config_for_mesh};

const CLIENT_SPIFFE: &str = "spiffe://cluster.local/ns/default/sa/client";
const ROGUE_SPIFFE: &str = "spiffe://cluster.local/ns/default/sa/rogue";

fn spiffe(id: &str) -> SpiffeId {
    SpiffeId::new(id).expect("valid SPIFFE id")
}

/// Build a `RequestContext` with the supplied identity and request shape.
fn ctx_with_principal(method: &str, path: &str, principal: Option<&str>) -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        method.to_string(),
        path.to_string(),
    );
    if let Some(id) = principal {
        ctx.peer_spiffe_id = Some(spiffe(id));
    }
    ctx
}

/// Build a `MeshAuthz` plugin from the prepared mesh config for the given
/// workload identity. Mirrors what production does: build a
/// `GatewayConfig`, run `prepare_gateway_config_for_mesh`, then construct
/// the plugin from the injected `mesh_authz` plugin config. This is the
/// realistic path — tests that build `MeshAuthz` directly from
/// `{"mesh_policies": [...]}` bypass the scope-filter context the plugin
/// reads from `mesh_slice.namespace`/`labels`.
fn build_mesh_authz_for_workload(
    workload_labels: &[(&str, &str)],
    policies: Vec<MeshPolicy>,
) -> MeshAuthz {
    let mut runtime = default_mesh_runtime();
    for (k, v) in workload_labels {
        runtime.workload_labels.insert(k.to_string(), v.to_string());
    }
    let mesh = mesh_config_with(Vec::new(), Vec::new(), policies);
    let config = ferrum_edge::config::types::GatewayConfig {
        version: "test".to_string(),
        proxies: Vec::new(),
        upstreams: Vec::new(),
        consumers: Vec::new(),
        plugin_configs: Vec::new(),
        loaded_at: chrono::Utc::now(),
        known_namespaces: Vec::new(),
        trust_bundles: None,
        mesh: Some(Box::new(mesh)),
    };
    let prepared = prepare_gateway_config_for_mesh(config, &runtime).expect("mesh-prepared");
    let authz_config = prepared
        .plugin_configs
        .iter()
        .find(|p| p.id == MESH_AUTHZ_PLUGIN_ID)
        .expect("mesh_authz plugin injected")
        .config
        .clone();
    MeshAuthz::new(&authz_config).expect("authz plugin builds from injected config")
}

#[tokio::test]
async fn deny_policy_overrides_allow_policy_first_match_wins() {
    // Two policies: an ALLOW that admits the client, and a DENY that
    // blocks it. Istio semantics: DENY rules evaluate first and any
    // match wins immediately. The plugin must refuse the request even
    // though the matching ALLOW rule would otherwise permit it.
    let allow = policy_allow_principal(
        "client-allow",
        DEFAULT_NAMESPACE,
        PolicyScope::MeshWide,
        CLIENT_SPIFFE,
    );
    let deny = policy_deny_principal(
        "client-deny",
        DEFAULT_NAMESPACE,
        PolicyScope::MeshWide,
        CLIENT_SPIFFE,
    );
    let plugin = build_mesh_authz_for_workload(&[], vec![allow, deny]);
    let mut ctx = ctx_with_principal("GET", "/api/items", Some(CLIENT_SPIFFE));

    let result = plugin.authorize(&mut ctx).await;
    assert!(
        matches!(result, PluginResult::Reject { .. }),
        "DENY-first semantics: DENY rule must win over ALLOW, got {result:?}"
    );
}

#[tokio::test]
async fn implicit_deny_blocks_when_any_allow_present_and_no_match() {
    // The ALLOW rule admits a specific principal — rogue clients with
    // no matching rule must be rejected by implicit-deny, not allowed
    // through.
    let allow = policy_allow_principal(
        "client-only",
        DEFAULT_NAMESPACE,
        PolicyScope::MeshWide,
        CLIENT_SPIFFE,
    );
    let plugin = build_mesh_authz_for_workload(&[], vec![allow]);
    let mut ctx = ctx_with_principal("GET", "/api/items", Some(ROGUE_SPIFFE));

    let result = plugin.authorize(&mut ctx).await;
    match result {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        other => panic!(
            "rogue principal must be rejected by implicit deny when an ALLOW rule \
             is present, got {other:?}"
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
async fn no_policies_means_no_authorization_enforcement() {
    // Empty policy set: every request flows through. This is the
    // documented default state — operators add policies to opt in to
    // enforcement.
    let plugin = build_mesh_authz_for_workload(&[], Vec::new());
    let mut ctx = ctx_with_principal("GET", "/api/items", Some(ROGUE_SPIFFE));

    assert!(matches!(
        plugin.authorize(&mut ctx).await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn workload_selector_scope_filters_out_non_applicable_allow_policy() {
    // A `WorkloadSelector{app=ratings}` ALLOW policy targets a peer
    // workload that is NOT this proxy. After the construction-time
    // filter (which keys on this proxy's `app=reviews` labels), the
    // ratings-scoped policy is gone. With no policies left, the
    // request passes through.
    //
    // Without the scope filter, the ALLOW rule would be in effect and
    // would implicit-deny any request whose principal didn't match it
    // — exactly the bug the filter was added to fix.
    let ratings_only_allow = policy_allow_principal(
        "ratings-allow",
        DEFAULT_NAMESPACE,
        PolicyScope::WorkloadSelector {
            selector: WorkloadSelector {
                labels: HashMap::from([("app".to_string(), "ratings".to_string())]),
                namespace: Some(DEFAULT_NAMESPACE.to_string()),
            },
        },
        CLIENT_SPIFFE,
    );
    let plugin = build_mesh_authz_for_workload(&[("app", "reviews")], vec![ratings_only_allow]);
    let mut ctx = ctx_with_principal("GET", "/api/items", Some(ROGUE_SPIFFE));

    let result = plugin.authorize(&mut ctx).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "ratings-scoped ALLOW must not affect reviews workload after scope filter, \
         got {result:?}"
    );
}

#[tokio::test]
async fn namespace_scope_filters_out_other_namespace_policies() {
    // A `Namespace=production` DENY policy targets a different
    // namespace. Our `default`-namespace workload must not be blocked
    // by it.
    let other_ns_deny = policy_deny_principal(
        "prod-deny",
        DEFAULT_NAMESPACE,
        PolicyScope::Namespace {
            namespace: "production".to_string(),
        },
        CLIENT_SPIFFE,
    );
    let plugin = build_mesh_authz_for_workload(&[], vec![other_ns_deny]);
    let mut ctx = ctx_with_principal("GET", "/api/items", Some(CLIENT_SPIFFE));

    assert!(matches!(
        plugin.authorize(&mut ctx).await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn mesh_wide_policy_applies_to_every_workload() {
    // No matter the workload labels/namespace, a `MeshWide`-scoped DENY
    // applies. Locks in the default-scope behaviour Istio operators
    // expect from a root-namespace policy.
    let deny = policy_deny_principal(
        "global-deny",
        DEFAULT_NAMESPACE,
        PolicyScope::MeshWide,
        CLIENT_SPIFFE,
    );
    let plugin = build_mesh_authz_for_workload(&[("app", "reviews")], vec![deny]);
    let mut ctx = ctx_with_principal("GET", "/api/items", Some(CLIENT_SPIFFE));

    assert!(matches!(
        plugin.authorize(&mut ctx).await,
        PluginResult::Reject { .. }
    ));
}

#[tokio::test]
async fn principal_glob_matches_subpath_under_wildcard() {
    let plugin = build_mesh_authz_for_workload(
        &[],
        vec![policy_allow_principal(
            "ns-default-allow",
            DEFAULT_NAMESPACE,
            PolicyScope::MeshWide,
            "spiffe://cluster.local/ns/default/sa/*",
        )],
    );
    let mut ctx = ctx_with_principal(
        "GET",
        "/api",
        Some("spiffe://cluster.local/ns/default/sa/x"),
    );
    assert!(matches!(
        plugin.authorize(&mut ctx).await,
        PluginResult::Continue
    ));

    // Different namespace path → glob does NOT match → implicit deny.
    let mut deny_ctx =
        ctx_with_principal("GET", "/api", Some("spiffe://cluster.local/ns/other/sa/x"));
    assert!(matches!(
        plugin.authorize(&mut deny_ctx).await,
        PluginResult::Reject { .. }
    ));
}

#[tokio::test]
async fn negative_match_not_paths_blocks_subpath_but_admits_others() {
    // Allow GET on the matching principal EXCEPT /admin paths. The
    // negative-match form is Istio's documented way to say "everything
    // except".
    let allow_with_not_paths = MeshPolicy {
        name: "allow-except-admin".to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        scope: PolicyScope::MeshWide,
        rules: vec![MeshRule {
            from: vec![PrincipalMatch {
                spiffe_id_pattern: Some(CLIENT_SPIFFE.to_string()),
                namespace_pattern: None,
                trust_domain: Some(TrustDomain::new(DEFAULT_TRUST_DOMAIN).expect("trust domain")),
                trust_domain_pattern: None,
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
    };
    let plugin = build_mesh_authz_for_workload(&[], vec![allow_with_not_paths]);

    let mut ok_ctx = ctx_with_principal("GET", "/api/items", Some(CLIENT_SPIFFE));
    assert!(matches!(
        plugin.authorize(&mut ok_ctx).await,
        PluginResult::Continue
    ));

    let mut blocked_ctx = ctx_with_principal("GET", "/admin/users", Some(CLIENT_SPIFFE));
    assert!(
        matches!(
            plugin.authorize(&mut blocked_ctx).await,
            PluginResult::Reject { .. }
        ),
        "admin subpath must be rejected by negative-match → no rule fires → implicit deny"
    );
}

#[tokio::test]
async fn condition_match_on_request_header_enforces_match_and_no_match() {
    // `when[].key = request.headers[x-team]` only admits requests that
    // carry the expected header value.
    let allow_with_when = MeshPolicy {
        name: "allow-team-foo".to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        scope: PolicyScope::MeshWide,
        rules: vec![MeshRule {
            from: vec![PrincipalMatch {
                spiffe_id_pattern: Some(CLIENT_SPIFFE.to_string()),
                namespace_pattern: None,
                trust_domain: Some(TrustDomain::new(DEFAULT_TRUST_DOMAIN).expect("trust domain")),
                trust_domain_pattern: None,
            }],
            to: Vec::new(),
            when: vec![ConditionMatch {
                key: "request.headers[x-team]".to_string(),
                values: vec!["foo".to_string()],
                not_values: Vec::new(),
            }],
            request_principals: Vec::new(),
            not_request_principals: Vec::new(),
            source_negation: Default::default(),
            never_matches: false,
            action: PolicyAction::Allow,
        }],
    };
    let plugin = build_mesh_authz_for_workload(&[], vec![allow_with_when]);

    // Request WITH the right header
    let mut ok_ctx = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));
    ok_ctx
        .headers
        .insert("x-team".to_string(), "foo".to_string());
    assert!(matches!(
        plugin.authorize(&mut ok_ctx).await,
        PluginResult::Continue
    ));

    // Same principal, wrong header value → no rule matches → implicit
    // deny.
    let mut blocked_ctx = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));
    blocked_ctx
        .headers
        .insert("x-team".to_string(), "bar".to_string());
    assert!(matches!(
        plugin.authorize(&mut blocked_ctx).await,
        PluginResult::Reject { .. }
    ));
}

#[tokio::test]
async fn condition_match_on_connection_sni_enforces_match_and_no_match() {
    let deny_sni = MeshPolicy {
        name: "deny-admin-sni".to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        scope: PolicyScope::MeshWide,
        rules: vec![MeshRule {
            from: Vec::new(),
            to: Vec::new(),
            when: vec![ConditionMatch {
                key: "connection.sni".to_string(),
                values: vec!["admin.mesh.internal".to_string()],
                not_values: Vec::new(),
            }],
            request_principals: Vec::new(),
            not_request_principals: Vec::new(),
            source_negation: Default::default(),
            never_matches: false,
            action: PolicyAction::Deny,
        }],
    };
    let plugin = build_mesh_authz_for_workload(&[], vec![deny_sni]);

    let mut matched_ctx = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));
    matched_ctx.frontend_sni_hostname = Some("admin.mesh.internal".to_string());
    assert!(
        matches!(
            plugin.authorize(&mut matched_ctx).await,
            PluginResult::Reject { .. }
        ),
        "DENY policies gated on connection.sni must fire for HTTP TLS requests"
    );

    let mut other_ctx = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));
    other_ctx.frontend_sni_hostname = Some("public.mesh.internal".to_string());
    assert!(matches!(
        plugin.authorize(&mut other_ctx).await,
        PluginResult::Continue
    ));

    let mut missing_ctx = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));
    assert!(matches!(
        plugin.authorize(&mut missing_ctx).await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn condition_match_on_source_principal_uses_istio_format() {
    let deny_client = MeshPolicy {
        name: "deny-client-source-principal".to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        scope: PolicyScope::MeshWide,
        rules: vec![MeshRule {
            from: Vec::new(),
            to: Vec::new(),
            when: vec![ConditionMatch {
                key: "source.principal".to_string(),
                values: vec!["cluster.local/ns/default/sa/client".to_string()],
                not_values: Vec::new(),
            }],
            request_principals: Vec::new(),
            not_request_principals: Vec::new(),
            source_negation: Default::default(),
            never_matches: false,
            action: PolicyAction::Deny,
        }],
    };
    let plugin = build_mesh_authz_for_workload(&[], vec![deny_client]);

    let mut client_ctx = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));
    assert!(
        matches!(
            plugin.authorize(&mut client_ctx).await,
            PluginResult::Reject { .. }
        ),
        "source.principal conditions should see Istio's trust-domain/ns/... form"
    );

    let mut rogue_ctx = ctx_with_principal("GET", "/api", Some(ROGUE_SPIFFE));
    assert!(matches!(
        plugin.authorize(&mut rogue_ctx).await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn condition_match_on_jwt_list_claim_preserves_item_boundaries() {
    let allow_with_claim = MeshPolicy {
        name: "allow-ops-group".to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        scope: PolicyScope::MeshWide,
        rules: vec![MeshRule {
            from: Vec::new(),
            to: Vec::new(),
            when: vec![ConditionMatch {
                key: "request.auth.claims[groups]".to_string(),
                values: vec!["ops".to_string()],
                not_values: Vec::new(),
            }],
            request_principals: Vec::new(),
            not_request_principals: Vec::new(),
            source_negation: Default::default(),
            never_matches: false,
            action: PolicyAction::Allow,
        }],
    };
    let plugin = build_mesh_authz_for_workload(&[], vec![allow_with_claim]);

    let mut list_ctx = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));
    list_ctx.mesh_request_auth_claims.insert(
        "groups".to_string(),
        JwtAuthAttributeValue::StringList(vec!["dev".to_string(), "ops".to_string()]),
    );
    assert!(matches!(
        plugin.authorize(&mut list_ctx).await,
        PluginResult::Continue
    ));

    let mut scalar_ctx = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));
    scalar_ctx.mesh_request_auth_claims.insert(
        "groups".to_string(),
        JwtAuthAttributeValue::Scalar("dev,ops".to_string()),
    );
    assert!(
        matches!(
            plugin.authorize(&mut scalar_ctx).await,
            PluginResult::Reject { .. }
        ),
        "scalar claim containing a comma must not be split into list items"
    );
}

#[tokio::test]
async fn condition_match_on_request_auth_presenter_uses_azp_claim() {
    let allow_presenter = MeshPolicy {
        name: "allow-presenter".to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        scope: PolicyScope::MeshWide,
        rules: vec![MeshRule {
            from: Vec::new(),
            to: Vec::new(),
            when: vec![ConditionMatch {
                key: "request.auth.presenter".to_string(),
                values: vec!["client-app".to_string()],
                not_values: Vec::new(),
            }],
            request_principals: Vec::new(),
            not_request_principals: Vec::new(),
            source_negation: Default::default(),
            never_matches: false,
            action: PolicyAction::Allow,
        }],
    };
    let plugin = build_mesh_authz_for_workload(&[], vec![allow_presenter]);

    let mut presenter_ctx = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));
    presenter_ctx.mesh_request_auth_claims.insert(
        "azp".to_string(),
        JwtAuthAttributeValue::Scalar("client-app".to_string()),
    );
    assert!(matches!(
        plugin.authorize(&mut presenter_ctx).await,
        PluginResult::Continue
    ));

    let mut list_ctx = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));
    list_ctx.mesh_request_auth_claims.insert(
        "azp".to_string(),
        JwtAuthAttributeValue::StringList(vec!["client-app".to_string()]),
    );
    assert!(
        matches!(
            plugin.authorize(&mut list_ctx).await,
            PluginResult::Reject { .. }
        ),
        "request.auth.presenter should use only a scalar azp claim"
    );
}

#[tokio::test]
async fn condition_match_on_nested_jwt_claim_uses_bracket_path() {
    let deny_admin_role = MeshPolicy {
        name: "deny-admin-role".to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        scope: PolicyScope::MeshWide,
        rules: vec![MeshRule {
            from: Vec::new(),
            to: Vec::new(),
            when: vec![ConditionMatch {
                key: "request.auth.claims[realm_access][roles]".to_string(),
                values: vec!["admin".to_string()],
                not_values: Vec::new(),
            }],
            request_principals: Vec::new(),
            not_request_principals: Vec::new(),
            source_negation: Default::default(),
            never_matches: false,
            action: PolicyAction::Deny,
        }],
    };
    let plugin = build_mesh_authz_for_workload(&[], vec![deny_admin_role]);

    let mut admin_ctx = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));
    admin_ctx.mesh_request_auth_claims.insert(
        "realm_access][roles".to_string(),
        JwtAuthAttributeValue::StringList(vec!["reader".to_string(), "admin".to_string()]),
    );
    assert!(
        matches!(
            plugin.authorize(&mut admin_ctx).await,
            PluginResult::Reject { .. }
        ),
        "nested JWT claim list should be resolved for DENY conditions"
    );

    let mut reader_ctx = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));
    reader_ctx.mesh_request_auth_claims.insert(
        "realm_access][roles".to_string(),
        JwtAuthAttributeValue::StringList(vec!["reader".to_string()]),
    );
    assert!(matches!(
        plugin.authorize(&mut reader_ctx).await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn request_principal_match_from_jwks_auth_metadata() {
    // `jwks_auth` (when configured with `emit_mesh_request_principal_metadata`)
    // populates `metadata["mesh.request_principal"]` from the validated
    // JWT's `iss/sub`. `mesh_authz` reads that key and matches against
    // `rule.request_principals` globs — this is Istio's
    // `from[].source.requestPrincipals` semantics.
    //
    // Spec change (PR #933 / commit 209928da): the metadata key was
    // renamed from `jwks_auth.request_principal` to
    // `mesh.request_principal`, and emission is now opt-in via the plugin
    // config flag so non-mesh jwks_auth deployments don't leak the
    // identifier into transaction logs. The test simulates the emission
    // by inserting the metadata directly, mirroring what
    // `jwks_auth` does after `emit_mesh_request_principal_metadata`.
    let allow = MeshPolicy {
        name: "allow-jwt-issuer".to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        scope: PolicyScope::MeshWide,
        rules: vec![MeshRule {
            from: Vec::new(),
            to: Vec::new(),
            when: Vec::new(),
            request_principals: vec!["https://issuer.example.com/*".to_string()],
            not_request_principals: Vec::new(),
            source_negation: Default::default(),
            never_matches: false,
            action: PolicyAction::Allow,
        }],
    };
    let plugin = build_mesh_authz_for_workload(&[], vec![allow]);

    let mut ok_ctx = ctx_with_principal("GET", "/api", None);
    ok_ctx.metadata.insert(
        "mesh.request_principal".to_string(),
        "https://issuer.example.com/user-42".to_string(),
    );
    assert!(matches!(
        plugin.authorize(&mut ok_ctx).await,
        PluginResult::Continue
    ));

    // Different issuer → no rule matches → implicit deny.
    let mut blocked_ctx = ctx_with_principal("GET", "/api", None);
    blocked_ctx.metadata.insert(
        "mesh.request_principal".to_string(),
        "https://attacker.com/u".to_string(),
    );
    assert!(matches!(
        plugin.authorize(&mut blocked_ctx).await,
        PluginResult::Reject { .. }
    ));
}

#[tokio::test]
async fn audit_action_does_not_block_request() {
    // AUDIT is informational — it must surface metadata for transaction
    // logs but never reject. Istio's documented contract.
    let audit_policy = MeshPolicy {
        name: "audit-everything".to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        scope: PolicyScope::MeshWide,
        rules: vec![MeshRule {
            from: vec![PrincipalMatch {
                spiffe_id_pattern: Some(CLIENT_SPIFFE.to_string()),
                namespace_pattern: None,
                trust_domain: Some(TrustDomain::new(DEFAULT_TRUST_DOMAIN).expect("trust domain")),
                trust_domain_pattern: None,
            }],
            to: Vec::new(),
            when: Vec::new(),
            request_principals: Vec::new(),
            not_request_principals: Vec::new(),
            source_negation: Default::default(),
            never_matches: false,
            action: PolicyAction::Audit,
        }],
    };
    let plugin = build_mesh_authz_for_workload(&[], vec![audit_policy]);
    let mut ctx = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));

    let result = plugin.authorize(&mut ctx).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "AUDIT must never block, got {result:?}"
    );
}

#[tokio::test]
async fn unauthenticated_request_with_authorization_policy_set_is_implicit_denied() {
    // ALLOW policies are present but no peer principal — the request
    // matches no rule, so implicit-deny kicks in. This is the canonical
    // Istio behaviour: mesh policies enforce identity, and a request
    // with no identity cannot satisfy any principal-based rule.
    let allow = policy_allow_principal(
        "client-allow",
        DEFAULT_NAMESPACE,
        PolicyScope::MeshWide,
        CLIENT_SPIFFE,
    );
    let plugin = build_mesh_authz_for_workload(&[], vec![allow]);
    let mut ctx = ctx_with_principal("GET", "/api", None);

    let result = plugin.authorize(&mut ctx).await;
    assert!(
        matches!(result, PluginResult::Reject { .. }),
        "unauthenticated request must fall through to implicit deny, got {result:?}"
    );
}

#[tokio::test]
async fn istio_allow_without_rules_means_allow_nothing() {
    // `AuthorizationPolicy{action: ALLOW, rules: []}` is the Istio
    // "allow-nothing" sentinel. The translator emits a never-matching
    // rule so the plugin's implicit-deny path picks it up. Any request
    // — including from an otherwise-authorized principal — must be
    // rejected.
    let allow_nothing = MeshPolicy {
        name: "allow-nothing".to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        scope: PolicyScope::MeshWide,
        rules: vec![MeshRule {
            from: Vec::new(),
            to: Vec::new(),
            when: Vec::new(),
            request_principals: Vec::new(),
            not_request_principals: Vec::new(),
            source_negation: Default::default(),
            never_matches: true,
            action: PolicyAction::Allow,
        }],
    };
    let plugin = build_mesh_authz_for_workload(&[], vec![allow_nothing]);
    let mut ctx = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));

    assert!(matches!(
        plugin.authorize(&mut ctx).await,
        PluginResult::Reject { .. }
    ));
}

#[tokio::test]
async fn deny_without_rules_is_a_no_op() {
    // Counterpart to the previous test: `DENY{rules: []}` must NOT
    // block anything — the translator does not emit a never-matching
    // rule for this case, and the plugin therefore behaves as if the
    // policy didn't exist.
    let empty_deny = MeshPolicy {
        name: "empty-deny".to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        scope: PolicyScope::MeshWide,
        rules: Vec::new(),
        // action defaults to Allow on MeshPolicy; the no-op-deny
        // semantics are tested in inline policy.rs tests because the
        // translator decides whether to emit a never-matching rule.
        // Without rules of any kind the plugin sees an empty list →
        // pass-through.
    };
    let plugin = build_mesh_authz_for_workload(&[], vec![empty_deny]);
    let mut ctx = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));

    assert!(matches!(
        plugin.authorize(&mut ctx).await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn multiple_deny_policies_short_circuit_on_first_match() {
    // First DENY to match wins; the second DENY's principal pattern
    // would also have matched but is never consulted. Captures the
    // first-match contract for DENY chains (so adding policies is
    // additive — operators don't worry about ordering).
    let deny_glob = policy_deny_principal(
        "deny-default-ns",
        DEFAULT_NAMESPACE,
        PolicyScope::MeshWide,
        "spiffe://cluster.local/ns/default/sa/*",
    );
    let deny_specific = policy_deny_principal(
        "deny-client",
        DEFAULT_NAMESPACE,
        PolicyScope::MeshWide,
        CLIENT_SPIFFE,
    );
    let plugin = build_mesh_authz_for_workload(&[], vec![deny_glob, deny_specific]);
    let mut ctx = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));

    let result = plugin.authorize(&mut ctx).await;
    assert!(matches!(result, PluginResult::Reject { .. }));
    // The deny_policy metadata key indicates a matched DENY rule —
    // operators rely on this for audit trails.
    let deny_policy = ctx
        .metadata
        .get("mesh_authz.deny_policy")
        .cloned()
        .unwrap_or_default();
    assert!(
        deny_policy.contains("deny-default-ns") || deny_policy.contains("deny-client"),
        "deny_policy metadata should name the matched DENY rule, got {deny_policy:?}"
    );
}

#[tokio::test]
async fn allow_then_deny_for_different_principal_lets_target_through() {
    // ALLOW{client} + DENY{rogue}: the client must still flow.
    let allow = policy_allow_principal(
        "client-allow",
        DEFAULT_NAMESPACE,
        PolicyScope::MeshWide,
        CLIENT_SPIFFE,
    );
    let deny = policy_deny_principal(
        "rogue-deny",
        DEFAULT_NAMESPACE,
        PolicyScope::MeshWide,
        ROGUE_SPIFFE,
    );
    let plugin = build_mesh_authz_for_workload(&[], vec![allow, deny]);

    let mut client_ctx = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));
    assert!(matches!(
        plugin.authorize(&mut client_ctx).await,
        PluginResult::Continue
    ));

    let mut rogue_ctx = ctx_with_principal("GET", "/api", Some(ROGUE_SPIFFE));
    assert!(matches!(
        plugin.authorize(&mut rogue_ctx).await,
        PluginResult::Reject { .. }
    ));
}

#[test]
fn mesh_authz_construction_fails_when_selector_labels_set_but_workload_labels_missing() {
    // The plugin's construction-time scope filter requires workload
    // identity context. If a policy with a label-based selector is
    // injected but the slice carries no labels for this workload, the
    // plugin construction must error out — production catches the
    // misconfiguration at startup, not silently degrades into an
    // implicit-deny death-spiral.
    let policy = policy_allow_principal(
        "labels-required",
        DEFAULT_NAMESPACE,
        PolicyScope::WorkloadSelector {
            selector: WorkloadSelector {
                labels: HashMap::from([("app".to_string(), "ratings".to_string())]),
                namespace: Some(DEFAULT_NAMESPACE.to_string()),
            },
        },
        CLIENT_SPIFFE,
    );
    // Bypass the prepare path so we feed mesh_policies directly into
    // MeshAuthz::new — the construction-time validator must catch the
    // missing-labels condition without help from the upstream prepare
    // pipeline.
    let config = json!({
        "mesh_policies": [policy],
        "namespace": DEFAULT_NAMESPACE,
        // labels: intentionally omitted
    });
    let err = match MeshAuthz::new(&config) {
        Err(e) => e,
        Ok(_) => panic!("expected construction error"),
    };
    assert!(
        err.contains("no proxy labels are configured"),
        "construction error should mention missing proxy labels, got {err:?}"
    );
}

#[test]
fn mesh_authz_construction_filters_policies_for_workload_at_build_time() {
    // Verify the construction-time filter actually removes
    // non-applicable policies, not just at request time. Construct
    // with `app=reviews`, give it both reviews- and ratings-scoped
    // policies, then verify behaviour: a request that would match the
    // ratings ALLOW must NOT be admitted (since that policy is
    // filtered out — but the reviews ALLOW catches it instead). This
    // is a behavioural assert, not a private-field inspection.
    let reviews_allow = policy_allow_principal(
        "reviews-allow",
        DEFAULT_NAMESPACE,
        PolicyScope::WorkloadSelector {
            selector: WorkloadSelector {
                labels: HashMap::from([("app".to_string(), "reviews".to_string())]),
                namespace: Some(DEFAULT_NAMESPACE.to_string()),
            },
        },
        CLIENT_SPIFFE,
    );
    let ratings_only_allow = policy_allow_principal(
        "ratings-allow",
        DEFAULT_NAMESPACE,
        PolicyScope::WorkloadSelector {
            selector: WorkloadSelector {
                labels: HashMap::from([("app".to_string(), "ratings".to_string())]),
                namespace: Some(DEFAULT_NAMESPACE.to_string()),
            },
        },
        ROGUE_SPIFFE,
    );
    let plugin = build_mesh_authz_for_workload(
        &[("app", "reviews")],
        vec![reviews_allow, ratings_only_allow],
    );

    // Rogue principal is admitted only by the ratings-scoped ALLOW.
    // After scope filtering, that policy is gone — implicit deny.
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime");
    rt.block_on(async {
        let mut rogue_ctx = ctx_with_principal("GET", "/api", Some(ROGUE_SPIFFE));
        let result = plugin.authorize(&mut rogue_ctx).await;
        assert!(
            matches!(result, PluginResult::Reject { .. }),
            "ratings-scoped ALLOW was filtered out for reviews workload → \
             implicit deny, got {result:?}"
        );
    });
}

#[tokio::test]
async fn trust_domain_alias_accepts_baggage_principal_from_aliased_domain() {
    // HBONE baggage carries `source.principal` — only honoured when its
    // trust domain matches the peer cert's OR is listed in
    // `trust_domain_aliases`. Set up the plugin with an alias and
    // simulate a baggage-bearing request whose principal's trust
    // domain is the alias (peer cert trust domain stays `cluster.local`).
    //
    // We synthesise the HBONE shape by setting the `baggage` header
    // directly; the rest of the path mirrors what `hbone_proxy.rs`
    // does after the CONNECT terminates.
    let allow = policy_allow_principal(
        "alias-allow",
        DEFAULT_NAMESPACE,
        PolicyScope::MeshWide,
        "spiffe://aliased.local/ns/default/sa/client",
    );
    // Hand-build the plugin with an alias.
    let mut runtime = default_mesh_runtime();
    runtime
        .trust_domain_aliases
        .push(TrustDomain::new("aliased.local").expect("trust domain"));
    let mesh = mesh_config_with(Vec::new(), Vec::new(), vec![allow]);
    let config = ferrum_edge::config::types::GatewayConfig {
        version: "test".to_string(),
        proxies: Vec::new(),
        upstreams: Vec::new(),
        consumers: Vec::new(),
        plugin_configs: Vec::new(),
        loaded_at: chrono::Utc::now(),
        known_namespaces: Vec::new(),
        trust_bundles: None,
        mesh: Some(Box::new(mesh)),
    };
    let prepared = prepare_gateway_config_for_mesh(config, &runtime).expect("mesh-prepared");
    let authz_cfg = prepared
        .plugin_configs
        .iter()
        .find(|p| p.id == MESH_AUTHZ_PLUGIN_ID)
        .expect("mesh_authz injected")
        .config
        .clone();
    let plugin = MeshAuthz::new(&authz_cfg).expect("plugin builds with aliases");

    // Build a RequestContext that mimics a post-HBONE handoff: the
    // peer SPIFFE id is the ztunnel's identity (`cluster.local`), and
    // baggage carries the original workload principal in the aliased
    // domain. `mesh_authz` must accept the baggage identity because
    // the alias is configured.
    let mut ctx = ctx_with_principal(
        "GET",
        "/api",
        Some("spiffe://cluster.local/ns/istio-system/sa/ztunnel"),
    );
    // Synthesise the HBONE-authenticated shape — `mesh_authz` checks
    // this via the same `is_hbone_request` / `is_authenticated_hbone_request`
    // helpers the proxy populates. The minimum we need to flip both
    // predicates is a marked HBONE request with baggage attached.
    ctx.metadata
        .insert("hbone.connect_authority".to_string(), "default".to_string());
    ctx.metadata
        .insert("hbone.authenticated".to_string(), "true".to_string());
    ctx.headers.insert(
        "baggage".to_string(),
        "source.principal=spiffe://aliased.local/ns/default/sa/client".to_string(),
    );

    let _ = plugin.authorize(&mut ctx).await;
    // We don't assert Continue/Reject here because the HBONE
    // authenticated-baggage path is sensitive to how the proxy stamps
    // ctx state — what we lock in is the absence of the
    // `trust_domain_mismatch` flag, which would have fired if the
    // alias were not honoured.
    assert!(
        !ctx.metadata
            .contains_key("mesh_authz.ignored_baggage.trust_domain_mismatch"),
        "trust-domain alias must keep the baggage principal in scope, got metadata {:?}",
        ctx.metadata
    );
}

#[tokio::test]
async fn condition_not_values_on_jwt_claim_allows_absent_attribute() {
    // DENY with `not_values: ["admin"]` on `request.auth.claims[role]`:
    // the condition passes when the claim does NOT equal "admin", so the
    // DENY fires for non-admins. Admins (role=admin) fail the condition
    // and the DENY does not fire.
    let deny_except_admin = MeshPolicy {
        name: "deny-non-admin".to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        scope: PolicyScope::MeshWide,
        rules: vec![MeshRule {
            from: Vec::new(),
            to: Vec::new(),
            when: vec![ConditionMatch {
                key: "request.auth.claims[role]".to_string(),
                values: Vec::new(),
                not_values: vec!["admin".to_string()],
            }],
            request_principals: Vec::new(),
            not_request_principals: Vec::new(),
            source_negation: Default::default(),
            never_matches: false,
            action: PolicyAction::Deny,
        }],
    };
    let plugin = build_mesh_authz_for_workload(&[], vec![deny_except_admin]);

    // Claim present and matches not_values -> condition fails -> DENY
    // does NOT fire, so the admin is allowed through.
    let mut admin_ctx = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));
    admin_ctx.mesh_request_auth_claims.insert(
        "role".to_string(),
        JwtAuthAttributeValue::Scalar("admin".to_string()),
    );
    assert!(
        matches!(
            plugin.authorize(&mut admin_ctx).await,
            PluginResult::Continue
        ),
        "claim matching not_values should make the DENY condition fail (admin passes)"
    );

    // Claim present but does NOT match not_values -> condition passes ->
    // DENY fires, rejecting the non-admin.
    let mut user_ctx = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));
    user_ctx.mesh_request_auth_claims.insert(
        "role".to_string(),
        JwtAuthAttributeValue::Scalar("user".to_string()),
    );
    assert!(
        matches!(
            plugin.authorize(&mut user_ctx).await,
            PluginResult::Reject { .. }
        ),
        "claim not matching not_values should make the DENY condition pass (user denied)"
    );

    // Claim absent on a DENY rule with an HTTP-only key: missing attribute
    // returns true for the condition, so the DENY fires.
    let mut absent_ctx = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));
    absent_ctx.mesh_request_auth_claims.clear();
    assert!(
        matches!(
            plugin.authorize(&mut absent_ctx).await,
            PluginResult::Reject { .. }
        ),
        "absent claim on a DENY not_values-only condition should fire (fail-closed)"
    );
}

/// Build a `StreamConnectionContext` for an inbound captured raw-TCP stream
/// landing on `listen_port`, identifying the peer by SPIFFE id in metadata.
/// Mirrors what `proxy::mesh_tcp_inbound::handle_mesh_tcp_inbound` stamps before
/// running the `on_stream_connect` chain (mesh-inbound direction, the captured
/// APP port as the authorization destination).
fn inbound_stream_ctx(listen_port: u16, peer_spiffe: &str) -> StreamConnectionContext {
    let mut ctx = StreamConnectionContext {
        client_ip: "10.0.0.7".to_string(),
        proxy_id: "__mesh-in-tcp-relay-default-redis-6379".to_string(),
        proxy_name: Some("mesh raw-tcp inbound".to_string()),
        listen_port,
        backend_scheme: BackendScheme::Tcp,
        consumer_index: Arc::new(ConsumerIndex::new(&[] as &[Consumer])),
        identified_consumer: None,
        authenticated_identity: None,
        auth_method: None,
        metadata: None,
        tls_client_cert_der: None,
        tls_client_cert_chain_der: None,
        sni_hostname: None,
        mesh_direction: Some(MeshTrafficDirection::Inbound),
        node_waypoint_policy_scope: None,
        first_bytes: None,
        first_bytes_kind: None,
    };
    // `mesh_authz`'s stream path reads the source principal from the
    // `peer_spiffe_id` metadata key (parity with the HBONE/HTTP path).
    ctx.insert_metadata("peer_spiffe_id".to_string(), peer_spiffe.to_string());
    ctx
}

/// A DENY `AuthorizationPolicy` scoped to one destination port. Mirrors an
/// operator denying L4 access to e.g. a Redis service port.
fn deny_principal_on_port(name: &str, principal: &str, port: u16) -> MeshPolicy {
    MeshPolicy {
        name: name.to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        scope: PolicyScope::MeshWide,
        rules: vec![MeshRule {
            from: vec![PrincipalMatch {
                spiffe_id_pattern: Some(principal.to_string()),
                namespace_pattern: None,
                trust_domain: Some(TrustDomain::new(DEFAULT_TRUST_DOMAIN).expect("trust domain")),
                trust_domain_pattern: None,
            }],
            to: vec![RequestMatch {
                ports: vec![port],
                ..RequestMatch::default()
            }],
            when: Vec::new(),
            request_principals: Vec::new(),
            not_request_principals: Vec::new(),
            source_negation: Default::default(),
            never_matches: false,
            action: PolicyAction::Deny,
        }],
    }
}

/// A DENY scoped ONLY to a destination port (no `from` principal) — fires
/// against any source, including an unauthenticated one.
fn deny_any_source_on_port(name: &str, port: u16) -> MeshPolicy {
    MeshPolicy {
        name: name.to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        scope: PolicyScope::MeshWide,
        rules: vec![MeshRule {
            from: Vec::new(),
            to: vec![RequestMatch {
                ports: vec![port],
                ..RequestMatch::default()
            }],
            when: Vec::new(),
            request_principals: Vec::new(),
            not_request_principals: Vec::new(),
            source_negation: Default::default(),
            never_matches: false,
            action: PolicyAction::Deny,
        }],
    }
}

#[tokio::test]
async fn stream_port_only_deny_rejects_unauthenticated_inbound_raw_tcp() {
    // The captured-plaintext raw-TCP inbound path carries NO peer SVID (it is
    // not mTLS-terminated), so the source is anonymous. A port-only DENY (no
    // `from`) must still fire against it on the app port — the relay closes
    // before reaching loopback. This is the most faithful representation of the
    // real captured-plaintext L4 enforcement the handler must perform.
    let deny = deny_any_source_on_port("deny-redis-port", 6379);
    let plugin = build_mesh_authz_for_workload(&[], vec![deny]);

    // No `peer_spiffe_id` metadata: an unauthenticated captured stream.
    let mut ctx = inbound_stream_ctx(6379, CLIENT_SPIFFE);
    ctx.metadata = None;
    assert!(
        matches!(
            plugin.on_stream_connect(&mut ctx).await,
            PluginResult::Reject { .. }
        ),
        "a port-only L4 DENY must reject an unauthenticated captured raw-TCP \
         inbound stream on the app port"
    );
}

#[tokio::test]
async fn stream_port_scoped_deny_rejects_inbound_raw_tcp_on_app_port() {
    // Regression for the raw-TCP Sidecar inbound finding: the accept-loop relay
    // (`handle_mesh_tcp_inbound`) runs the `on_stream_connect` chain with the
    // captured APP port as the stream destination BEFORE connecting to loopback.
    // A `destination.port`-scoped DENY on that app port must therefore be
    // evaluated and reject the connection (the handler closes without relaying).
    let deny = deny_principal_on_port("deny-redis-l4", CLIENT_SPIFFE, 6379);
    let plugin = build_mesh_authz_for_workload(&[], vec![deny]);

    // Authorizing on the app port (6379) — the DENY fires.
    let mut ctx = inbound_stream_ctx(6379, CLIENT_SPIFFE);
    assert!(
        matches!(
            plugin.on_stream_connect(&mut ctx).await,
            PluginResult::Reject { .. }
        ),
        "a port-scoped L4 DENY on the app port must reject the captured raw-TCP \
         inbound stream so the relay never reaches loopback"
    );
}

#[tokio::test]
async fn stream_port_scoped_deny_ignores_non_matching_port_and_admits_relay() {
    // The DENY is scoped to a DIFFERENT port than the captured app port, so it
    // must NOT fire — the legitimate stream-only-port relay case proceeds. This
    // pins that authorizing on the real app port (not the shared :15006 capture
    // listener) is the discriminator: were the handler to authorize on :15006,
    // a 6379-scoped DENY would silently never apply.
    let deny = deny_principal_on_port("deny-other-port", CLIENT_SPIFFE, 5432);
    let plugin = build_mesh_authz_for_workload(&[], vec![deny]);

    let mut ctx = inbound_stream_ctx(6379, CLIENT_SPIFFE);
    assert!(
        matches!(
            plugin.on_stream_connect(&mut ctx).await,
            PluginResult::Continue
        ),
        "a DENY scoped to an unrelated port must not block the captured raw-TCP \
         inbound relay on the app port"
    );
}

#[allow(dead_code)]
fn _construct_mesh_config_with_explicit_root_ns() -> MeshConfig {
    // Documents that MeshConfig::default uses "istio-system" as
    // istio_root_namespace; this anchor keeps the call exercised so a
    // future change is caught here as well as in mesh_config_with's
    // call sites.
    MeshConfig {
        istio_root_namespace: "istio-system".to_string(),
        ..MeshConfig::default()
    }
}
