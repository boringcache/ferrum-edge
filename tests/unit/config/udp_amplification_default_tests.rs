//! UDP response-amplification is bounded by default on every configuration
//! source (issue #4515).
//!
//! `Proxy::normalize_fields()` is the single choke point every source passes
//! through — file loaders, DB/Mongo row parsing, admin CRUD, DP gRPC apply,
//! mesh materialization, and the k8s reconciler — so the finite default cannot
//! depend on who authored the proxy. `0` is the explicit operator opt-out.

use ferrum_edge::config::file_loader::load_config_from_file;
use ferrum_edge::config::types::{DispatchKind, Proxy};
use ferrum_edge::udp_amplification::{
    DEFAULT_UDP_AMPLIFICATION_FACTOR, MAX_UDP_AMPLIFICATION_FACTOR,
};
use std::io::Write;
use tempfile::NamedTempFile;

fn load_yaml(yaml: &str) -> ferrum_edge::config::types::GatewayConfig {
    let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
    write!(file, "{}", yaml).unwrap();
    load_config_from_file(
        file.path().to_str().unwrap(),
        30,
        &ferrum_edge::config::BackendEgressPolicy::unrestricted(),
        "ferrum",
    )
    .expect("config loads")
}

fn stream_proxy_yaml(scheme: &str, port: u16, factor_line: &str) -> String {
    format!(
        r#"
version: "1"
proxies:
  - id: "stream-1"
    backend_scheme: {scheme}
    listen_port: {port}
    backend_host: "localhost"
    backend_port: 5300
{factor_line}
plugin_configs: []
"#
    )
}

/// A file-mode `udp` proxy that names no factor is bounded, not unlimited.
#[test]
fn file_udp_proxy_without_factor_normalizes_to_the_finite_default() {
    let config = load_yaml(&stream_proxy_yaml("udp", 15353, ""));
    assert_eq!(
        config.proxies[0].udp_max_response_amplification_factor,
        Some(DEFAULT_UDP_AMPLIFICATION_FACTOR)
    );
}

/// DTLS is the same dispatch family and gets the same default.
#[test]
fn file_dtls_proxy_without_factor_normalizes_to_the_finite_default() {
    let config = load_yaml(&stream_proxy_yaml("dtls", 15354, ""));
    assert_eq!(
        config.proxies[0].udp_max_response_amplification_factor,
        Some(DEFAULT_UDP_AMPLIFICATION_FACTOR)
    );
}

/// An explicit finite factor is not overwritten by the default.
#[test]
fn file_udp_proxy_keeps_an_explicit_finite_factor() {
    let config = load_yaml(&stream_proxy_yaml(
        "udp",
        15355,
        "    udp_max_response_amplification_factor: 2.5",
    ));
    assert_eq!(
        config.proxies[0].udp_max_response_amplification_factor,
        Some(2.5)
    );
}

/// The `0` sentinel is the operator's explicit unlimited opt-out and must
/// survive normalization rather than being replaced by the default.
#[test]
fn file_udp_proxy_unlimited_sentinel_survives_normalization() {
    let config = load_yaml(&stream_proxy_yaml(
        "udp",
        15356,
        "    udp_max_response_amplification_factor: 0",
    ));
    assert_eq!(
        config.proxies[0].udp_max_response_amplification_factor,
        Some(0.0)
    );
}

/// TCP behavior is untouched: a `tcp` proxy still normalizes to `None`.
#[test]
fn file_tcp_proxy_is_not_given_an_amplification_factor() {
    let config = load_yaml(&stream_proxy_yaml("tcp", 15357, ""));
    assert_eq!(
        config.proxies[0].udp_max_response_amplification_factor,
        None
    );
}

/// An HTTP proxy is likewise untouched.
#[test]
fn file_http_proxy_is_not_given_an_amplification_factor() {
    let config = load_yaml(
        r#"
version: "1"
proxies:
  - id: "http-1"
    listen_path: "/api"
    backend_scheme: http
    backend_host: "localhost"
    backend_port: 3000
plugin_configs: []
"#,
    );
    assert_eq!(
        config.proxies[0].udp_max_response_amplification_factor,
        None
    );
}

// ---- normalize_fields directly: the call the admin CRUD, DB row parsing, DP
// gRPC apply, and mesh materialization paths all share ----

fn bare_stream_proxy(scheme: &str, port: u16) -> Proxy {
    // Deserialized exactly the way a DB/Mongo row, an admin POST body, a DP
    // gRPC apply, and a mesh materialization hand a `Proxy` to
    // `normalize_fields()`: `dispatch_kind` still unresolved.
    let proxy: Proxy = serde_json::from_value(serde_json::json!({
        "id": "stream-1",
        "backend_scheme": scheme,
        "listen_port": port,
        "backend_host": "localhost",
        "backend_port": 5300,
    }))
    .expect("proxy deserializes");
    assert_eq!(proxy.dispatch_kind, DispatchKind::default());
    proxy
}

#[test]
fn normalize_fields_bounds_a_row_parsed_udp_proxy() {
    let mut proxy = bare_stream_proxy("udp", 15358);
    proxy.normalize_fields();
    assert_eq!(proxy.dispatch_kind, DispatchKind::UdpRaw);
    assert_eq!(
        proxy.udp_max_response_amplification_factor,
        Some(DEFAULT_UDP_AMPLIFICATION_FACTOR)
    );
}

#[test]
fn normalize_fields_bounds_a_row_parsed_dtls_proxy() {
    let mut proxy = bare_stream_proxy("dtls", 15359);
    proxy.normalize_fields();
    assert_eq!(proxy.dispatch_kind, DispatchKind::UdpDtls);
    assert_eq!(
        proxy.udp_max_response_amplification_factor,
        Some(DEFAULT_UDP_AMPLIFICATION_FACTOR)
    );
}

#[test]
fn normalize_fields_leaves_a_tcp_proxy_field_unset() {
    let mut proxy = bare_stream_proxy("tcp", 15360);
    proxy.normalize_fields();
    assert_eq!(proxy.dispatch_kind, DispatchKind::TcpRaw);
    assert_eq!(proxy.udp_max_response_amplification_factor, None);
}

#[test]
fn normalize_fields_preserves_the_unlimited_sentinel() {
    let mut proxy = bare_stream_proxy("udp", 15361);
    proxy.udp_max_response_amplification_factor = Some(0.0);
    proxy.normalize_fields();
    assert_eq!(proxy.udp_max_response_amplification_factor, Some(0.0));
}

#[test]
fn normalize_fields_is_idempotent_for_udp() {
    let mut proxy = bare_stream_proxy("udp", 15362);
    proxy.normalize_fields();
    proxy.normalize_fields();
    assert_eq!(
        proxy.udp_max_response_amplification_factor,
        Some(DEFAULT_UDP_AMPLIFICATION_FACTOR)
    );
}

// ---- validation of the sentinel and the still-rejected values ----

/// Whether validation rejected the configured factor specifically. Other
/// unrelated field errors on a bare fixture must not decide these assertions.
fn factor_rejected(scheme: &str, factor: Option<f32>) -> bool {
    let mut proxy = bare_stream_proxy(scheme, 15363);
    proxy.udp_max_response_amplification_factor = factor;
    proxy
        .validate_fields()
        .err()
        .into_iter()
        .flatten()
        .any(|e| e.contains("udp_max_response_amplification_factor"))
}

#[test]
fn unlimited_sentinel_passes_validation_on_a_udp_proxy() {
    assert!(!factor_rejected("udp", Some(0.0)));
    assert!(!factor_rejected("dtls", Some(0.0)));
}

#[test]
fn unlimited_sentinel_is_rejected_on_a_non_udp_proxy() {
    assert!(
        factor_rejected("tcp", Some(0.0)),
        "0 is a UDP/DTLS-only sentinel"
    );
}

#[test]
fn hostile_factors_are_still_rejected_on_a_udp_proxy() {
    for factor in [
        -1.0f32,
        -0.5,
        f32::NAN,
        f32::INFINITY,
        f32::NEG_INFINITY,
        2000.0,
        MAX_UDP_AMPLIFICATION_FACTOR + 1.0,
    ] {
        assert!(
            factor_rejected("udp", Some(factor)),
            "factor {factor} must not be accepted"
        );
    }
}

#[test]
fn the_default_and_the_maximum_pass_validation() {
    assert!(!factor_rejected(
        "udp",
        Some(DEFAULT_UDP_AMPLIFICATION_FACTOR)
    ));
    assert!(!factor_rejected("udp", Some(MAX_UDP_AMPLIFICATION_FACTOR)));
}
