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
        plain.contains("run_plain_attempt_local_policy_or_reject("),
        "every plain attempt must pass through the local transport-policy gate"
    );
    let policy_gate = source
        .split("async fn run_plain_attempt_local_policy_or_reject")
        .nth(1)
        .expect("plain attempt local-policy gate must remain present")
        .split("fn record_plain_grpc_web_client_deadline(")
        .next()
        .expect("bounded plain attempt local-policy gate");
    assert!(
        policy_gate.contains("h3_bridge_transport_refusal("),
        "plain bridge must refuse Unix, not all mesh tags"
    );
    assert!(
        plain.contains("proxy_h3_plain_http_mesh_buffered("),
        "mesh-tagged plain attempts must share the H1/H2 mesh helper"
    );
    assert!(
        plain.contains("select_next_cross_protocol_retry_target("),
        "mixed-upstream retry must go through the shared cross-protocol selector"
    );
    let retry_selector = source
        .split("fn select_next_cross_protocol_retry_target(")
        .nth(1)
        .expect("cross-protocol retry selector must remain present")
        .split("async fn resolve_cross_protocol_backend_ip(")
        .next()
        .expect("bounded cross-protocol retry selector");
    assert!(
        retry_selector.contains("select_next_h3_eligible_retry_target("),
        "mixed-upstream retry must filter H3-ineligible candidates via the shared helper"
    );
    assert!(
        plain.contains("run_after_proxy_hooks("),
        "mesh terminal writes must still run after_proxy"
    );
}

/// Bounded source of the H3→HTTP plain dispatcher.
fn h3_plain_dispatcher_source() -> &'static str {
    let source = include_str!("../../src/http3/cross_protocol.rs");
    source
        .split("async fn dispatch_plain<S>(")
        .nth(1)
        .expect("H3→HTTP plain dispatcher")
        .split("async fn dispatch_grpc<S>(")
        .next()
        .expect("bounded plain dispatcher")
}

/// A terminal mesh response must reach the SAME client-facing response policy
/// pipeline as an ordinary buffered reqwest response: response inspection and
/// security policy may not depend on whether the selected target happened to be
/// mesh-tagged (issue #3620).
#[test]
fn h3_plain_bridge_mesh_response_shares_the_buffered_policy_pipeline() {
    let plain = h3_plain_dispatcher_source();

    assert!(
        plain.contains("break PlainBridgeResponse::MeshBuffered(PlainBridgeMeshResponse {"),
        "the terminal mesh attempt must leave the retry loop through the shared \
         plain-response pipeline instead of writing the client response itself"
    );
    assert!(
        plain.contains("PlainBridgeBodySource::MeshBuffered(body) => Ok(Ok(body)),"),
        "the buffered mesh body must feed the shared buffered-response pipeline"
    );
    assert!(
        plain.contains("matches!(body_source, PlainBridgeBodySource::MeshBuffered(_))"),
        "a mesh response must be pinned to the buffered (fully inspected) pipeline"
    );

    // Every plain-response policy phase must exist exactly once in the shared
    // pipeline; a second copy would mean the mesh arm forked its own.
    for phase in [
        "normalize_response_body_for_inspection(",
        ".on_response_body(",
        "crate::proxy::transform_buffered_response_body_with_deadline(",
        ".on_final_response_body(",
        "crate::proxy::run_deadline_bounded_response_committed_hooks(",
        "ClientResponseFraming::for_buffered_response(",
        "crate::http3::server::stamp_h3_original_response_metadata(",
        "crate::http3::server::inject_sticky_cookie_with_deadline_provenance(",
    ] {
        assert_eq!(
            plain.matches(phase).count(),
            1,
            "the plain bridge must have exactly one `{phase}` site shared by the \
             reqwest and mesh arms"
        );
    }

    // The terminal mesh arm itself must do nothing but hand the response over.
    let mesh_arm = plain
        .split("// Terminal mesh attempt.")
        .nth(1)
        .expect("terminal mesh attempt")
        .split("break PlainBridgeResponse::MeshBuffered(PlainBridgeMeshResponse {")
        .next()
        .expect("bounded terminal mesh attempt");
    assert!(
        !mesh_arm.contains("run_after_proxy_hooks(")
            && !mesh_arm.contains("inject_sticky_cookie_with_deadline_provenance(")
            && !mesh_arm.contains("write_reject_with_headers("),
        "the mesh arm must not re-run response hooks or write the client response \
         ahead of the shared pipeline"
    );
}

/// The mesh helper dispatches in buffered mode, so a streaming body variant is
/// structurally impossible. Both the dispatch arm and the streaming writer must
/// fail closed rather than publish a fabricated or uninspected body under the
/// backend's status.
#[test]
fn h3_plain_bridge_mesh_streaming_variants_fail_closed() {
    let plain = h3_plain_dispatcher_source();

    assert!(
        plain.contains("let crate::retry::ResponseBody::Buffered(mesh_body) = mesh_response_body"),
        "the mesh arm must accept only a buffered response body"
    );
    assert!(
        !plain.contains("Backend unavailable"),
        "an unexpected mesh body variant must not fabricate a body under the \
         backend's status"
    );
    assert!(
        plain.contains("PlainBridgeBodySource::MeshBuffered(_) => {"),
        "the streaming writer must handle the structurally unexpected mesh variant"
    );
    // Two fail-closed arms (unexpected body variant, mesh response reaching the
    // streaming writer), each writing a gateway error rather than a success.
    assert_eq!(
        plain.matches("failing closed").count(),
        2,
        "both unexpected-variant paths must fail closed"
    );
}

/// A mesh response can carry a real transport classification (for example a
/// connection failure represented as a buffered 502). Once established, a
/// later client deadline or disconnect must not overwrite that backend signal
/// with the health-neutral client-side terminal.
#[test]
fn h3_plain_bridge_preserves_mesh_outcomes_across_client_terminals() {
    let plain = h3_plain_dispatcher_source();

    assert_eq!(
        plain
            .matches("record_plain_grpc_web_client_deadline_after_backend_response(")
            .count(),
        3,
        "plugin, header-write, and body-write deadlines after a terminal \
         backend response must preserve its classification"
    );
    assert!(
        plain.contains("if terminal_connection_error || terminal_error_class.is_some() {")
            && plain.contains("outcome.connection_error = terminal_connection_error;")
            && plain.contains("outcome.error_class = terminal_error_class;"),
        "client write failures must keep backend transport classification on \
         accounting and the cross-protocol outcome"
    );
    assert!(
        plain.contains("let admission_error_class = terminal_error_class")
            && plain
                .contains(".or_else(|| (!body_completed).then_some(ErrorClass::ClientDisconnect))"),
        "a downstream body failure may supply the admission fallback only when \
         no backend classification already exists"
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
        loop_tail.contains("select_next_h3_eligible_retry_target("),
        "H3 WS retry must skip Unix-only candidates via the shared helper"
    );
    assert!(
        loop_tail.contains("(Some(_), Some(_), None)")
            && loop_tail.contains("WS_MESH_BACKEND_REQUEST_TARGET_INVALID"),
        "a mesh WS target with an invalid target-effective URI must fail closed, \
         not silently substitute `/`"
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
        helper.contains("boxed_proxy_to_backend_mesh_retry("),
        "H3 plain mesh dispatch must keep the large shared retry future out of the bridge frame"
    );
    assert!(
        src.contains("#[inline(never)]\nfn boxed_proxy_to_backend_mesh_retry<'a>("),
        "the H3-only boxing boundary must be constructed out of line"
    );
    assert!(
        src.contains("type MeshRetryDispatchOutcome = (")
            && src.contains("type BoxedMeshRetryDispatchFuture<'a> =")
            && src.contains(") -> BoxedMeshRetryDispatchFuture<'a> {"),
        "H3 boxed mesh retry must use the mesh-retry outcome, not the Unix dispatch tuple"
    );
    let boxed = src
        .split("fn boxed_proxy_to_backend_mesh_retry<'a>(")
        .nth(1)
        .expect("boxed mesh retry")
        .split("pub(crate) async fn proxy_h3_plain_http_mesh_buffered(")
        .next()
        .expect("bounded boxed mesh retry");
    assert!(
        !boxed.contains("BoxedBackendDispatchFuture"),
        "H3 boxed mesh retry must not reuse the Unix/reqwest BoxedBackendDispatchFuture"
    );
    assert!(
        helper.contains("request_body_exceeded")
            && helper.contains("streaming_h2_read_timeout_ms")
            && helper.contains("h3_mesh_buffered_retry_response("),
        "buffered H3 mesh dispatch must keep mesh-retry overflow and read-timeout fields"
    );
    assert!(
        !helper.contains("proxy_to_backend_retry("),
        "helper must never fall back to the plaintext reqwest dial"
    );
}
