//! External contract coverage for the H3 plain-HTTP / WebSocket mesh bridge
//! (issue #3620).
//!
//! Live transport peers for the shared HBONE / Sidecar mesh-mTLS pools already
//! live in `mesh_grpc_transport_tests.rs`. The H3 frontend keystone that
//! actually changes traffic behavior is the functional matrix in
//! `functional_mesh_mode_test.rs`. This module locks the *bridge wiring* and
//! the eligibility / refusal predicates the retry filters call, so a regression
//! that re-introduces mesh-tag fail-closed (or drops Unix filtering) fails here
//! without needing a full QUIC frontend.

use ferrum_edge::_test_support::{
    direct_http_mesh_transport_refusal_for_test, h3_bridge_transport_refusal_for_test,
    h3_dispatch_target_eligible_for_test, target_requires_http_mesh_egress_for_test,
};
use ferrum_edge::config::types::UpstreamTarget;
use ferrum_edge::proxy::hbone_pool::HBONE_TARGET_TAG;
use ferrum_edge::proxy::mesh_mtls_pool::MESH_MTLS_TARGET_TAG;
use ferrum_edge::proxy::unix_backend::MESH_UNIX_SOCKET_TAG;
use std::collections::HashMap;

fn target_with_tags(tags: &[(&str, &str)]) -> UpstreamTarget {
    UpstreamTarget {
        host: "127.0.0.1".to_string(),
        port: 9080,
        service_port_policy_key: None,
        weight: 1,
        tags: tags
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect::<HashMap<_, _>>(),
        locality: None,
        path: None,
    }
}

#[test]
fn h3_bridge_eligibility_matrix_matches_issue_3620_contract() {
    let plain = target_with_tags(&[]);
    let hbone = target_with_tags(&[(HBONE_TARGET_TAG, "true")]);
    let mtls = target_with_tags(&[(MESH_MTLS_TARGET_TAG, "true")]);
    let unix = target_with_tags(&[(MESH_UNIX_SOCKET_TAG, "/run/ferrum/app.sock")]);

    assert!(h3_dispatch_target_eligible_for_test(&plain));
    assert!(h3_dispatch_target_eligible_for_test(&hbone));
    assert!(h3_dispatch_target_eligible_for_test(&mtls));
    assert!(!h3_dispatch_target_eligible_for_test(&unix));

    assert_eq!(h3_bridge_transport_refusal_for_test(&plain), None);
    assert_eq!(h3_bridge_transport_refusal_for_test(&hbone), None);
    assert_eq!(h3_bridge_transport_refusal_for_test(&mtls), None);
    assert_eq!(
        h3_bridge_transport_refusal_for_test(&unix),
        Some("Unix socket dispatch required for this backend target")
    );

    assert!(!target_requires_http_mesh_egress_for_test(&plain));
    assert!(target_requires_http_mesh_egress_for_test(&hbone));
    assert!(target_requires_http_mesh_egress_for_test(&mtls));
    assert!(!target_requires_http_mesh_egress_for_test(&unix));

    // Native-only surfaces still refuse mesh tags; the H3 bridges do not.
    assert!(direct_http_mesh_transport_refusal_for_test(&hbone).is_some());
    assert!(direct_http_mesh_transport_refusal_for_test(&mtls).is_some());
    assert_eq!(direct_http_mesh_transport_refusal_for_test(&unix), None);
}

#[test]
fn h3_plain_bridge_source_routes_mesh_through_shared_helper() {
    let source = include_str!("../../src/http3/cross_protocol.rs");
    let plain = source
        .split("async fn dispatch_plain<S>(")
        .nth(1)
        .expect("H3→HTTP plain dispatcher")
        .split("async fn dispatch_grpc<S>(")
        .next()
        .expect("bounded plain dispatcher");
    assert!(
        plain.contains("h3_bridge_transport_refusal("),
        "plain bridge must refuse Unix, not all mesh tags"
    );
    assert!(
        plain.contains("proxy_h3_plain_http_mesh_buffered("),
        "mesh-tagged plain attempts must share the H1/H2 mesh helper"
    );
    assert!(
        plain.contains("h3_dispatch_target_eligible("),
        "mixed-upstream retry must filter H3-ineligible candidates"
    );
    assert!(
        plain.contains("run_after_proxy_hooks("),
        "mesh terminal writes must still run after_proxy"
    );
}

#[test]
fn h3_websocket_bridge_source_forks_shared_mesh_egress() {
    let src = include_str!("../../src/http3/websocket.rs");
    let loop_start = src
        .find("let backend_handshake = loop {")
        .expect("H3 WebSocket connect loop");
    let loop_tail = &src[loop_start..];
    assert!(
        loop_tail.contains("h3_bridge_transport_refusal("),
        "H3 WS must screen Unix before dial"
    );
    assert!(
        loop_tail.contains("connect_mesh_websocket_backend("),
        "H3 WS must reuse the shared mesh WS dialer"
    );
    assert!(
        loop_tail.contains("h3_dispatch_target_eligible("),
        "H3 WS retry must skip Unix-only candidates"
    );
}

#[test]
fn native_h3_forces_mesh_tagged_targets_onto_bridge() {
    let src = include_str!("../../src/http3/server.rs");
    assert!(
        src.contains("target_requires_http_mesh_egress")
            && src.contains("&& !mesh_egress_required"),
        "native H3 pool selection must force mesh onto the bridge"
    );
    assert!(
        src.contains("proxy_h3_plain_http_mesh_buffered("),
        "native buffered retry must dispatch mesh via the shared helper"
    );
}

#[test]
fn shared_mesh_plain_helper_never_plaintext_falls_back() {
    let src = include_str!("../../src/proxy/mod.rs");
    let helper = src
        .split("pub(crate) async fn proxy_h3_plain_http_mesh_buffered(")
        .nth(1)
        .expect("shared H3 plain mesh helper")
        .split("/// Proxy the request to the backend.")
        .next()
        .expect("bounded helper");
    assert!(
        helper.contains("proxy_to_backend_mesh_retry("),
        "helper must share H1/H2 mesh retry/security plumbing"
    );
    assert!(
        !helper.contains("proxy_to_backend_retry("),
        "helper must never fall back to the plaintext reqwest dial"
    );
}
