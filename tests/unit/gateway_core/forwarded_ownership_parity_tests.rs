//! Fail-closed RFC 7239 `Forwarded` ownership parity across transports
//! (issue #2952).
//!
//! When `FERRUM_ADD_FORWARDED_HEADER=true`, every primary request-construction
//! path must strip client `forwarded` before writing the gateway-owned value.
//! Reqwest appends; direct-H2/`HeaderMap::insert` replaces; H3 builders push
//! into a `Vec`. Divergent strip policy made backend-visible Forwarded shape
//! flip on capability-path changes.

use ferrum_edge::proxy::headers::is_proxy_owned_forwarding_header;

#[test]
fn owned_forwarding_predicate_fail_closes_forwarded_only_when_regenerating() {
    assert!(is_proxy_owned_forwarding_header("forwarded", true));
    // Mixed-case plugin keys must not bypass ownership (append/`Vec` paths).
    assert!(is_proxy_owned_forwarding_header("Forwarded", true));
    assert!(is_proxy_owned_forwarding_header("FORWARDED", true));
    assert!(!is_proxy_owned_forwarding_header("forwarded", false));
    assert!(!is_proxy_owned_forwarding_header("Forwarded", false));
    // XFF family remains always-owned (unchanged trusted-proxy contract).
    for name in ["x-forwarded-for", "x-forwarded-proto", "x-forwarded-host"] {
        assert!(is_proxy_owned_forwarding_header(name, false));
        assert!(is_proxy_owned_forwarding_header(name, true));
    }
}

#[test]
fn request_builders_share_owned_forwarding_strip_predicate() {
    // Structural parity: every transport copy-loop that regenerates Forwarded
    // must call the shared ownership predicate (not a local string arm that
    // can drift). Covers reqwest primary + retry, direct H2, HBONE, mesh-mTLS,
    // H1/H2→native-H3, and H3-frontend→H3-backend builders.
    let proxy_src = include_str!("../../../src/proxy/mod.rs");
    let h3_server_src = include_str!("../../../src/http3/server.rs");

    let sites = [
        (
            "proxy_to_backend_retry",
            proxy_src,
            "pub(crate) async fn proxy_to_backend_retry(",
            "async fn proxy_to_backend(",
        ),
        (
            "proxy_to_backend",
            proxy_src,
            "async fn proxy_to_backend(",
            "async fn proxy_to_backend_hbone(",
        ),
        (
            "proxy_to_backend_hbone",
            proxy_src,
            "async fn proxy_to_backend_hbone(",
            "async fn proxy_to_backend_mesh_mtls(",
        ),
        (
            "proxy_to_backend_mesh_mtls",
            proxy_src,
            "async fn proxy_to_backend_mesh_mtls(",
            "async fn proxy_to_backend_http2(",
        ),
        (
            "proxy_to_backend_http2",
            proxy_src,
            "async fn proxy_to_backend_http2(",
            "fn build_http3_backend_headers(",
        ),
        (
            "build_http3_backend_headers",
            proxy_src,
            "fn build_http3_backend_headers(",
            "async fn proxy_to_backend_http3(",
        ),
        (
            "build_h3_backend_headers",
            h3_server_src,
            "fn build_h3_backend_headers(",
            "pub(crate) fn inject_sticky_cookie(",
        ),
    ];

    for (label, src, start_marker, end_marker) in sites {
        let start = src
            .find(start_marker)
            .unwrap_or_else(|| panic!("{label}: missing start marker `{start_marker}`"));
        let end_rel = src[start..]
            .find(end_marker)
            .unwrap_or_else(|| panic!("{label}: missing end marker `{end_marker}`"));
        let region = &src[start..start + end_rel];
        assert!(
            region.contains("is_proxy_owned_forwarding_header"),
            "{label} must strip via is_proxy_owned_forwarding_header before regenerating Forwarded"
        );
        // Reqwest-style append paths previously used the XFF-only predicate and
        // left client Forwarded in place; forbid that regression.
        assert!(
            !region.contains("is_proxy_generated_forwarding_header(n)"),
            "{label} must not use the XFF-only predicate for primary ownership stripping"
        );
    }
}

#[test]
fn cross_protocol_bridge_always_strips_forwarded_before_regeneration() {
    // Cross-protocol already fail-closes by always omitting client `forwarded`
    // from the outbound map (then regenerates when the flag is on). Pin that
    // inventory so it cannot quietly drop the name.
    let src = include_str!("../../../src/http3/cross_protocol.rs");
    let start = src
        .find("fn should_skip_cross_protocol_backend_header(")
        .expect("cross-protocol skip helper must remain present");
    let region = src[start..]
        .split("#[cfg(test)]")
        .next()
        .expect("cross-protocol skip helper must be bounded");
    assert!(
        region.contains("| \"forwarded\""),
        "cross-protocol bridge must keep stripping client Forwarded"
    );
}
