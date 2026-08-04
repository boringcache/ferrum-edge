//! Behavioral retry-target rotation coverage for issue #3285.
//!
//! The live functional fixture exercises deterministic same-target replay over
//! sidecar SVID mTLS. This focused integration test separately exercises the
//! production load-balancer rotation primitive and the same
//! `direct_http_mesh_transport_refusal` screen the generic HTTP retry loop
//! consults before a plaintext dial, covering all three fail-closed shapes
//! (HBONE, sidecar mTLS, and cross-cluster-only).
//!
//! It also covers the replay-safety gate at the top of the same retry loop: a
//! first attempt that fails BEFORE request-body preparation (DNS resolution and
//! the backend egress screen both precede it) leaves nothing to replay, and the
//! loop must refuse rather than dispatch a body-less copy of a request the
//! client sent a body with.

use ferrum_edge::_test_support::{
    direct_http_mesh_transport_refusal_for_test, inbound_request_declares_body_for_test,
    retry_replay_preserves_request_body_for_test,
};
use ferrum_edge::LoadBalancerCache;
use ferrum_edge::config::types::{GatewayConfig, UpstreamTarget};
use ferrum_edge::plugins::RequestContext;
use http::HeaderMap;
use std::sync::Arc;

/// Returns the `Arc<UpstreamTarget>` the production load balancer hands the
/// retry planner — the LB shares targets by `Arc` rather than cloning them, so
/// keeping that shape here means the fixture exercises exactly what dispatch
/// sees. Deref coercion covers the `&UpstreamTarget` call sites below.
fn rotate_onto_second_target(upstream_json: serde_json::Value) -> Arc<UpstreamTarget> {
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

/// Build a request context carrying `raw` as its pristine inbound field lines,
/// materialized exactly as the proxy path does before plugins run.
fn request_ctx_with_raw_headers(method: &str, raw: HeaderMap) -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        method.to_string(),
        "/upload".to_string(),
    );
    ctx.set_raw_headers(raw);
    ctx.materialize_headers();
    ctx
}

fn raw_header(name: &'static str, value: &str) -> HeaderMap {
    let mut raw = HeaderMap::new();
    raw.insert(
        http::HeaderName::from_static(name),
        http::HeaderValue::from_str(value).expect("header value"),
    );
    raw
}

#[test]
fn declared_body_without_a_retained_copy_is_never_replayed() {
    // A POST whose first attempt died at DNS resolution — before
    // `prepare_mesh_request_body` / the reqwest collect ever ran — has no
    // retained body, but the client's body was already consumed. Replaying it
    // would truncate a non-idempotent request.
    let ctx = request_ctx_with_raw_headers("POST", raw_header("content-length", "1024"));
    let declares = inbound_request_declares_body_for_test(&ctx);
    assert!(declares, "content-length: 1024 declares a request body");
    assert!(
        !retry_replay_preserves_request_body_for_test(declares, false),
        "a declared body with nothing retained must refuse replay on every transport"
    );
}

#[test]
fn chunked_upload_without_a_retained_copy_is_never_replayed() {
    let ctx = request_ctx_with_raw_headers("POST", raw_header("transfer-encoding", "chunked"));
    let declares = inbound_request_declares_body_for_test(&ctx);
    assert!(declares, "a transfer-encoding field line declares a request body");
    assert!(
        !retry_replay_preserves_request_body_for_test(declares, false),
        "a chunked upload with nothing retained must refuse replay"
    );
}

#[test]
fn unparseable_content_length_refuses_replay_fail_closed() {
    // `check_protocol_headers` rejects malformed lengths before routing, so this
    // shape should be unreachable — the gate still fails closed rather than
    // treating an unparseable declaration as "no body".
    let ctx = request_ctx_with_raw_headers("POST", raw_header("content-length", "not-a-number"));
    let declares = inbound_request_declares_body_for_test(&ctx);
    assert!(declares, "an unparseable content-length is not a zero-length body");
    assert!(!retry_replay_preserves_request_body_for_test(declares, false));
}

#[test]
fn bodyless_request_still_retries_normally() {
    let ctx = request_ctx_with_raw_headers("GET", raw_header("accept", "application/json"));
    let declares = inbound_request_declares_body_for_test(&ctx);
    assert!(!declares);
    assert!(
        retry_replay_preserves_request_body_for_test(declares, false),
        "a request that declared no body must keep retrying pre-wire failures"
    );

    let zero_length = request_ctx_with_raw_headers("POST", raw_header("content-length", "0"));
    let zero_declares = inbound_request_declares_body_for_test(&zero_length);
    assert!(!zero_declares);
    assert!(retry_replay_preserves_request_body_for_test(zero_declares, false));
}

#[test]
fn declared_body_with_a_retained_copy_still_replays() {
    let ctx = request_ctx_with_raw_headers("POST", raw_header("content-length", "1024"));
    let declares = inbound_request_declares_body_for_test(&ctx);
    assert!(
        retry_replay_preserves_request_body_for_test(declares, true),
        "the ordinary post-buffering retry path must be unaffected by the gate"
    );
}
