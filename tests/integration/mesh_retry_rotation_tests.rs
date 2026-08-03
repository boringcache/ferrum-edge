//! Behavioral retry-target rotation coverage for issue #3285.
//!
//! The live functional fixture exercises deterministic same-target replay over
//! sidecar SVID mTLS. This focused integration test separately exercises the
//! production load-balancer rotation primitive and the direct-dispatch guard,
//! avoiding a timing-sensitive multi-listener functional fixture.

use ferrum_edge::_test_support::direct_http_mesh_transport_refusal_for_test;
use ferrum_edge::LoadBalancerCache;
use ferrum_edge::config::types::GatewayConfig;

#[test]
fn retry_rotation_preserves_the_selected_targets_secure_mesh_transport() {
    let mut config: GatewayConfig = serde_json::from_value(serde_json::json!({
        "version": "1",
        "proxies": [],
        "consumers": [],
        "plugin_configs": [],
        "upstreams": [{
            "id": "mesh-retry",
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
        }]
    }))
    .expect("retry rotation config should deserialize");
    config.normalize_fields();

    let previous = &config.upstreams[0].targets[0];
    let cache = LoadBalancerCache::new(&config);
    let snapshot = cache.load();
    let retry = LoadBalancerCache::select_next_target_from(
        &snapshot,
        "ferrum",
        "mesh-retry",
        "stable-retry-key",
        previous,
        None,
    )
    .expect("the remaining target should be selected for retry");

    assert_eq!(retry.host, "secure-retry.local");
    assert_eq!(retry.port, 15443);
    assert_eq!(
        direct_http_mesh_transport_refusal_for_test(&retry),
        Some("Sidecar mTLS dispatch required for this backend target"),
        "rotation must not admit a plaintext direct dial for the mesh-mTLS target"
    );
}
