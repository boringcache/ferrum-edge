//! Outbound X-Forwarded-For / X-Real-IP trust (issue #4034).
//!
//! An untrusted peer's inbound XFF must not reach a backend. The shared
//! composer (`build_xff_value`) is the HTTP-family source of truth; gRPC and
//! WebSocket go through `apply_effective_backend_scheme_headers` before their
//! collectors. Trusted peers must still honor and append the inbound chain.

use ferrum_edge::_test_support::{
    apply_effective_backend_scheme_headers_for_test, build_xff_value_for_test,
    collect_forwardable_websocket_headers_for_test,
};
use ferrum_edge::proxy::client_ip::TrustedProxies;
use ferrum_edge::proxy::headers::{
    is_untrusted_real_ip_header, merge_proxy_headers_and_strip_for_grpc,
};
use std::collections::HashMap;

fn none() -> TrustedProxies {
    TrustedProxies::none()
}

fn lb_trusted() -> TrustedProxies {
    TrustedProxies::parse_strict("10.0.0.7", "test").expect("valid trusted proxy list")
}

fn header_values<'a>(headers: &'a [(String, String)], name: &str) -> Vec<&'a str> {
    headers
        .iter()
        .filter(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
        .collect()
}

#[test]
fn untrusted_real_ip_header_predicate_is_case_insensitive() {
    assert!(is_untrusted_real_ip_header("x-real-ip", false));
    assert!(is_untrusted_real_ip_header("X-Real-IP", false));
    assert!(is_untrusted_real_ip_header("X-REAL-IP", false));
    assert!(!is_untrusted_real_ip_header("x-real-ip", true));
    assert!(!is_untrusted_real_ip_header("x-forwarded-for", false));
    // A configured real-IP header that is not X-Real-IP is not this strip.
    assert!(!is_untrusted_real_ip_header("cf-connecting-ip", false));
}

#[test]
fn empty_trust_list_drops_spoofed_inbound_xff() {
    // Default FERRUM_TRUSTED_PROXIES is empty: every peer is untrusted, so a
    // client-supplied chain must not appear in outbound XFF.
    assert_eq!(
        build_xff_value_for_test(
            Some("198.51.100.7"),
            "192.0.2.6",
            "192.0.2.6",
            &none(),
        ),
        "192.0.2.6"
    );
    assert_eq!(
        build_xff_value_for_test(
            Some("1.1.1.1, 198.51.100.7"),
            "192.0.2.6",
            "192.0.2.6",
            &none(),
        ),
        "192.0.2.6"
    );
}

#[test]
fn trusted_peer_appends_inbound_chain_including_multi_hop() {
    // Seeding (client, peer) cannot produce this three-hop result — the
    // inbound chain must have been honored.
    assert_eq!(
        build_xff_value_for_test(
            Some("1.1.1.1, 198.51.100.7"),
            "198.51.100.7",
            "10.0.0.7",
            &lb_trusted(),
        ),
        "1.1.1.1, 198.51.100.7, 10.0.0.7"
    );
}

#[test]
fn untrusted_peer_with_a_configured_trust_list_still_drops_spoofed_xff() {
    assert_eq!(
        build_xff_value_for_test(
            Some("6.6.6.6"),
            "192.0.2.6",
            "192.0.2.6",
            &lb_trusted(),
        ),
        "192.0.2.6"
    );
}

#[test]
fn websocket_and_grpc_drop_untrusted_xff_and_x_real_ip() {
    let mut proxy_headers = HashMap::from([
        ("host".to_string(), "api.example".to_string()),
        ("x-forwarded-for".to_string(), "198.51.100.7".to_string()),
        ("x-real-ip".to_string(), "8.8.8.8".to_string()),
    ]);
    apply_effective_backend_scheme_headers_for_test(
        &mut proxy_headers,
        "203.0.113.8",
        "203.0.113.8",
        &none(),
        true,
        true,
    );

    assert_eq!(
        proxy_headers.get("x-forwarded-for").map(String::as_str),
        Some("203.0.113.8")
    );
    assert!(
        proxy_headers
            .keys()
            .all(|name| !name.eq_ignore_ascii_case("x-real-ip")),
        "untrusted X-Real-IP must be stripped: {proxy_headers:?}"
    );

    let mut raw_headers = http::HeaderMap::new();
    raw_headers.insert(
        "x-forwarded-for",
        http::HeaderValue::from_static("198.51.100.7"),
    );
    raw_headers.insert("x-real-ip", http::HeaderValue::from_static("8.8.8.8"));

    let websocket_headers = collect_forwardable_websocket_headers_for_test(
        &raw_headers,
        &proxy_headers,
    );
    assert_eq!(
        header_values(&websocket_headers, "x-forwarded-for"),
        vec!["203.0.113.8"]
    );
    assert!(
        header_values(&websocket_headers, "x-real-ip").is_empty(),
        "WebSocket collector must not forward untrusted X-Real-IP: {websocket_headers:?}"
    );

    let mut grpc_headers = raw_headers;
    merge_proxy_headers_and_strip_for_grpc(&mut grpc_headers, &proxy_headers);
    assert_eq!(
        grpc_headers
            .get_all("x-forwarded-for")
            .iter()
            .map(|value| value.to_str().expect("valid generated gRPC XFF"))
            .collect::<Vec<_>>(),
        vec!["203.0.113.8"]
    );
    assert!(
        grpc_headers.get("x-real-ip").is_none(),
        "gRPC merge must not forward untrusted X-Real-IP: {grpc_headers:?}"
    );
}

#[test]
fn websocket_and_grpc_honor_trusted_peer_xff_chain() {
    let mut proxy_headers = HashMap::from([
        ("host".to_string(), "api.example".to_string()),
        (
            "x-forwarded-for".to_string(),
            "1.1.1.1, 198.51.100.7".to_string(),
        ),
        ("x-real-ip".to_string(), "1.1.1.1".to_string()),
    ]);
    apply_effective_backend_scheme_headers_for_test(
        &mut proxy_headers,
        "198.51.100.7",
        "10.0.0.7",
        &lb_trusted(),
        true,
        false,
    );

    assert_eq!(
        proxy_headers.get("x-forwarded-for").map(String::as_str),
        Some("1.1.1.1, 198.51.100.7, 10.0.0.7")
    );
    assert_eq!(
        proxy_headers.get("x-real-ip").map(String::as_str),
        Some("1.1.1.1")
    );

    let mut raw_headers = http::HeaderMap::new();
    raw_headers.insert(
        "x-forwarded-for",
        http::HeaderValue::from_static("1.1.1.1, 198.51.100.7"),
    );
    raw_headers.insert("x-real-ip", http::HeaderValue::from_static("1.1.1.1"));

    let websocket_headers = collect_forwardable_websocket_headers_for_test(
        &raw_headers,
        &proxy_headers,
    );
    assert_eq!(
        header_values(&websocket_headers, "x-forwarded-for"),
        vec!["1.1.1.1, 198.51.100.7, 10.0.0.7"]
    );
    assert_eq!(
        header_values(&websocket_headers, "x-real-ip"),
        vec!["1.1.1.1"]
    );

    let mut grpc_headers = raw_headers;
    merge_proxy_headers_and_strip_for_grpc(&mut grpc_headers, &proxy_headers);
    assert_eq!(
        grpc_headers
            .get_all("x-forwarded-for")
            .iter()
            .map(|value| value.to_str().expect("valid generated gRPC XFF"))
            .collect::<Vec<_>>(),
        vec!["1.1.1.1, 198.51.100.7, 10.0.0.7"]
    );
    assert_eq!(
        grpc_headers
            .get("x-real-ip")
            .and_then(|value| value.to_str().ok()),
        Some("1.1.1.1")
    );
}
