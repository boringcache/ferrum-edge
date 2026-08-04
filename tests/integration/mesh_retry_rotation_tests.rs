//! Behavioral retry-target rotation coverage for issue #3285.
//!
//! The live functional fixture exercises deterministic same-target replay over
//! sidecar SVID mTLS. This focused integration test separately exercises the
//! production load-balancer rotation primitive and the same
//! `direct_http_mesh_transport_refusal` screen the generic HTTP retry loop
//! consults before a plaintext dial, covering all three fail-closed shapes
//! (HBONE, sidecar mTLS, and cross-cluster-only).

use ferrum_edge::_test_support::direct_http_mesh_transport_refusal_for_test;
use ferrum_edge::LoadBalancerCache;
use ferrum_edge::config::types::{GatewayConfig, UpstreamTarget};

fn rotate_onto_second_target(upstream_json: serde_json::Value) -> UpstreamTarget {
    let mut config: GatewayConfig = serde_json::from_value(serde_json::json!({
        "version": "1",
        "proxies": [],
        "consumers": [],
        "plugin_configs": [],
        "upstreams": [upstream_json]
    }))
    .expect("retry rotation config should deserialize");
    config.normalize_fields();

    let previous = &config.upstreams[0].targets[0];
    let cache = LoadBalancerCache::new(&config);
    let snapshot = cache.load();
    LoadBalancerCache::select_next_target_from(
        &snapshot,
        "ferrum",
        config.upstreams[0].id.as_str(),
        "stable-retry-key",
        previous,
        None,
    )
    .expect("the remaining target should be selected for retry")
}

#[test]
fn retry_rotation_preserves_the_selected_targets_secure_mesh_transport() {
    let retry = rotate_onto_second_target(serde_json::json!({
        "id": "mesh-retry-mtls",
        "algorithm": "round_robin",
        "targets": [
            {
                "host": "first-attempt.local",
                "port": 8080
            },
            {
                "host": "secure-retry.local",
                "port": 15443,
                "tags": {
                    "mesh.mtls": "true",
                    "mesh.spiffe_id": "spiffe://cluster.local/ns/default/sa/backend"
                }
            }
        ]
    }));

    assert_eq!(retry.host, "secure-retry.local");
    assert_eq!(retry.port, 15443);
    assert_eq!(
        direct_http_mesh_transport_refusal_for_test(&retry),
        Some("Sidecar mTLS dispatch required for this backend target"),
        "rotation must not admit a plaintext direct dial for the mesh-mTLS target"
    );
}

#[test]
fn retry_rotation_refuses_hbone_tagged_target_for_direct_dial() {
    let retry = rotate_onto_second_target(serde_json::json!({
        "id": "mesh-retry-hbone",
        "algorithm": "round_robin",
        "targets": [
            {
                "host": "first-attempt.local",
                "port": 8080
            },
            {
                "host": "hbone-retry.local",
                "port": 15008,
                "tags": {
                    "mesh.hbone": "true",
                    "mesh.spiffe_id": "spiffe://cluster.local/ns/default/sa/backend"
                }
            }
        ]
    }));

    assert_eq!(retry.host, "hbone-retry.local");
    assert_eq!(
        direct_http_mesh_transport_refusal_for_test(&retry),
        Some("HBONE dispatch required for this backend target"),
        "rotation must not admit a plaintext direct dial for the HBONE target"
    );
}

#[test]
fn retry_rotation_refuses_cross_cluster_only_target_for_direct_dial() {
    // Regression for the generic HTTP retry loop: cross-cluster alone (no
    // mesh.hbone / mesh.mtls base tag) must still fail closed via the shared
    // refusal helper the loop consults before reqwest/H3 dial.
    let retry = rotate_onto_second_target(serde_json::json!({
        "id": "mesh-retry-cross-cluster",
        "algorithm": "round_robin",
        "targets": [
            {
                "host": "first-attempt.local",
                "port": 8080
            },
            {
                "host": "eastwest-gateway.remote",
                "port": 15443,
                "tags": {
                    "mesh.cross_cluster": "true",
                    "mesh.eastwest_sni": "svc.remote.svc.cluster.local",
                    "mesh.trust_domain": "remote.local"
                }
            }
        ]
    }));

    assert_eq!(retry.host, "eastwest-gateway.remote");
    assert_eq!(retry.port, 15443);
    assert_eq!(
        direct_http_mesh_transport_refusal_for_test(&retry),
        Some("cross-cluster mesh transport dispatch required for this backend target"),
        "cross-cluster-only rotation must not admit a plaintext direct dial"
    );
}
