//! Client-visible error-response headers: RFC 9110 `Allow` on 405 and
//! `X-Gateway-Error` on gateway-synthesized 5xx.

use ferrum_edge::_test_support::{
    PROTOCOL_LEVEL_405_ALLOW_FOR_TEST, allow_header_from_allowed_methods_for_test,
    x_gateway_error_for_backend_failure_for_test,
};

#[test]
fn x_gateway_error_maps_connect_timeout_and_backend_5xx() {
    assert_eq!(
        x_gateway_error_for_backend_failure_for_test(true, 502),
        Some("connection_failure")
    );
    assert_eq!(
        x_gateway_error_for_backend_failure_for_test(false, 504),
        Some("backend_timeout")
    );
    assert_eq!(
        x_gateway_error_for_backend_failure_for_test(false, 500),
        Some("backend_error")
    );
    assert_eq!(
        x_gateway_error_for_backend_failure_for_test(false, 503),
        Some("backend_error")
    );
    assert_eq!(
        x_gateway_error_for_backend_failure_for_test(false, 404),
        None
    );
}

#[test]
fn allow_header_uppercases_in_config_order() {
    let methods = vec!["get".to_string(), "HEAD".to_string(), "post".to_string()];
    assert_eq!(
        allow_header_from_allowed_methods_for_test(&methods),
        "GET, HEAD, POST"
    );
}

#[test]
fn protocol_level_405_allow_omits_trace_and_connect() {
    assert_eq!(
        PROTOCOL_LEVEL_405_ALLOW_FOR_TEST,
        "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS"
    );
    assert!(
        !PROTOCOL_LEVEL_405_ALLOW_FOR_TEST.contains("TRACE")
            && !PROTOCOL_LEVEL_405_ALLOW_FOR_TEST.contains("CONNECT")
    );
}

#[test]
fn protocol_level_405_sites_emit_static_allow() {
    let proxy = include_str!("../../../src/proxy/mod.rs");
    assert!(
        proxy.contains("fn build_method_not_allowed_response("),
        "H1/H2 TRACE/CONNECT 405s must share one Allow-bearing builder"
    );
    assert!(
        proxy.contains(".header(\"Allow\", PROTOCOL_LEVEL_405_ALLOW)"),
        "H1/H2 protocol-level 405 must attach the static Allow value"
    );
    let h3 = include_str!("../../../src/http3/server.rs");
    assert_eq!(
        h3.matches("send_h3_protocol_method_not_allowed(").count(),
        3,
        "H3 TRACE and CONNECT must both call send_h3_protocol_method_not_allowed (plus definition)"
    );
    let cross = include_str!("../../../src/http3/cross_protocol.rs");
    assert!(
        cross.contains("crate::proxy::PROTOCOL_LEVEL_405_ALLOW"),
        "unparseable-method 405 on the H3→HTTP bridge must advertise Allow"
    );
}

#[test]
fn circuit_breaker_open_sites_use_distinct_token() {
    for (name, src) in [
        ("H1/H2", include_str!("../../../src/proxy/mod.rs")),
        ("H3", include_str!("../../../src/http3/server.rs")),
        ("HBONE", include_str!("../../../src/proxy/hbone_proxy.rs")),
    ] {
        assert!(
            src.contains("circuit_breaker_open_reject_headers()"),
            "{name} open-breaker 503 must start from the precomputed header snapshot"
        );
        assert!(
            src.contains("X_GATEWAY_ERROR_CIRCUIT_BREAKER_OPEN"),
            "{name} must restore circuit_breaker_open after after_proxy"
        );
    }
}

#[test]
fn h3_cross_protocol_classified_failures_keep_typed_gateway_error() {
    let cross = include_str!("../../../src/http3/cross_protocol.rs");
    let mut classified_writes = 0usize;
    let mut search = cross;
    while let Some(idx) = search.find("reqwest_error_response_for_cross_protocol(") {
        let end = (idx + 2800).min(search.len());
        let window = &search[idx..end];
        if window.contains("fn reqwest_error_response_for_cross_protocol") {
            search = &search[idx + 1..];
            continue;
        }
        assert!(
            window.contains("write_classified_backend_dispatch_error("),
            "classified H3→HTTP dispatch failure must write via write_classified_backend_dispatch_error"
        );
        assert!(
            !window.contains(r#"{"error":"Bad Gateway"}"#),
            "classified H3→HTTP dispatch failure must not collapse to generic Bad Gateway"
        );
        classified_writes += 1;
        search = &search[idx + 1..];
    }
    assert_eq!(
        classified_writes, 2,
        "buffered-exhausted and streaming send failures must both keep classified status/body/header"
    );
}

#[test]
fn native_h3_dispatch_failures_send_typed_gateway_error() {
    let h3 = include_str!("../../../src/http3/server.rs");
    assert!(
        h3.contains("fn send_h3_backend_failure_response("),
        "native H3 dispatch failures must share one X-Gateway-Error writer"
    );
    assert!(
        h3.contains("fn h3_backend_failure_headers("),
        "buffered native-H3 dispatch failures must populate X-Gateway-Error before after_proxy"
    );
}
