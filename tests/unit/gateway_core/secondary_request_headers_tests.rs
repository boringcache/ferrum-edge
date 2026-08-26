//! Structural reuse guards for the shared secondary-request header sanitizer
//! used by `request_mirror` and `load_testing`.
//!
//! Secondary builders call the canonical strip predicates directly. The
//! `*_NAMES` inventories below are generated from the same source as those
//! predicates; these tests exercise the filter against that inventory rather
//! than maintaining a duplicate allowlist.

use ferrum_edge::plugins::RequestContext;
use ferrum_edge::proxy::headers::{
    BACKEND_REQUEST_STRIP_HEADER_NAMES, PROXY_GENERATED_FORWARDING_HEADER_NAMES,
    SecondaryRequestHostPolicy, filter_secondary_request_headers,
    is_secondary_request_strip_header, is_untrusted_real_ip_header,
    synthesize_grpc_te_trailers_if_needed,
};
use http::HeaderMap;
use std::collections::{HashMap, HashSet};

/// The immediate socket peer is in `FERRUM_TRUSTED_PROXIES`.
const PEER_TRUSTED: bool = true;
/// The immediate socket peer is NOT in `FERRUM_TRUSTED_PROXIES` — the default
/// edge deployment, where every client-asserted forwarding identity is refused.
const PEER_UNTRUSTED: bool = false;

#[test]
fn secondary_filter_strips_every_canonical_backend_and_forwarding_name() {
    // Structural reuse: filter_secondary_request_headers →
    // is_secondary_request_strip_header → is_backend_request_strip_header /
    // is_proxy_generated_forwarding_header. Enumerating the shared inventory
    // proves the filter path honors every documented name.
    for &name in BACKEND_REQUEST_STRIP_HEADER_NAMES {
        let mut headers = HashMap::new();
        headers.insert(name.to_string(), "x".to_string());
        headers.insert("x-keep".to_string(), "ok".to_string());
        let out = filter_secondary_request_headers(
            &headers,
            SecondaryRequestHostPolicy::Preserve,
            PEER_TRUSTED,
            &[],
        );
        assert!(
            !out.iter().any(|(k, _)| k.eq_ignore_ascii_case(name)),
            "secondary filter must strip canonical name `{name}`: {out:?}"
        );
        assert!(out.iter().any(|(k, _)| k == "x-keep"));
    }

    for &name in PROXY_GENERATED_FORWARDING_HEADER_NAMES {
        let mut headers = HashMap::new();
        headers.insert(name.to_string(), "spoofed".to_string());
        headers.insert("x-keep".to_string(), "ok".to_string());
        let out = filter_secondary_request_headers(
            &headers,
            SecondaryRequestHostPolicy::Preserve,
            PEER_TRUSTED,
            &[],
        );
        assert!(
            !out.iter().any(|(k, _)| k.eq_ignore_ascii_case(name)),
            "secondary filter must strip proxy-owned `{name}`: {out:?}"
        );
    }
}

#[test]
fn secondary_filter_parses_mixed_case_ows_and_malformed_connection_tokens() {
    let mut headers = HashMap::new();
    // Repeated / mixed-case Connection with OWS and a garbage token.
    headers.insert(
        "CONNECTION".to_string(),
        " X-Hop , , bad:token, Keep-Alive ".to_string(),
    );
    headers.insert("x-hop".to_string(), "per-connection".to_string());
    headers.insert("keep-alive".to_string(), "timeout=5".to_string());
    headers.insert("Trailer".to_string(), "X-Foo".to_string());
    headers.insert(
        "x-ferrum-original-content-encoding".to_string(),
        "br".to_string(),
    );
    headers.insert("x-grpc-web-mode".to_string(), "1".to_string());
    headers.insert("authorization".to_string(), "Bearer keep".to_string());
    headers.insert("x-keep".to_string(), "ok".to_string());

    let out = filter_secondary_request_headers(
        &headers,
        SecondaryRequestHostPolicy::Strip,
        PEER_UNTRUSTED,
        &[],
    );
    let names: HashSet<_> = out.iter().map(|(k, _)| k.to_ascii_lowercase()).collect();
    for forbidden in [
        "connection",
        "x-hop",
        "keep-alive",
        "trailer",
        "x-ferrum-original-content-encoding",
        "x-grpc-web-mode",
    ] {
        assert!(
            !names.contains(forbidden),
            "leaked `{forbidden}` from hostile H1 map: {out:?}"
        );
    }
    assert!(names.contains("authorization"));
    assert!(names.contains("x-keep"));
}

#[test]
fn secondary_filter_h2_h3_parity_strips_protocol_invalid_and_internal_markers() {
    // H2/H3 reject Connection at the frame layer, but Trailer + Ferrum markers
    // can still appear in the materialised plugin map (plugin synthesis).
    let mut headers = HashMap::new();
    headers.insert("trailer".to_string(), "grpc-status".to_string());
    headers.insert("te".to_string(), "trailers".to_string());
    headers.insert("transfer-encoding".to_string(), "chunked".to_string());
    headers.insert("content-length".to_string(), "12".to_string());
    headers.insert(
        "x-ferrum-original-content-encoding".to_string(),
        "gzip".to_string(),
    );
    headers.insert("x-grpc-web-mode".to_string(), "1".to_string());
    headers.insert("x-forwarded-proto".to_string(), "https".to_string());
    headers.insert("content-type".to_string(), "application/grpc".to_string());
    headers.insert("x-keep".to_string(), "ok".to_string());

    let mut out = filter_secondary_request_headers(
        &headers,
        SecondaryRequestHostPolicy::Strip,
        PEER_UNTRUSTED,
        &[],
    );
    synthesize_grpc_te_trailers_if_needed(&mut out);

    let names: HashSet<_> = out.iter().map(|(k, _)| k.to_ascii_lowercase()).collect();
    for forbidden in [
        "trailer",
        "transfer-encoding",
        "content-length",
        "x-ferrum-original-content-encoding",
        "x-grpc-web-mode",
        "x-forwarded-proto",
    ] {
        assert!(
            !names.contains(forbidden),
            "H2/H3 parity leaked `{forbidden}`: {out:?}"
        );
    }
    assert_eq!(
        out.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("te"))
            .map(|(_, v)| v.as_str()),
        Some("trailers"),
        "gRPC secondary requests must re-synthesise te: trailers: {out:?}"
    );
    assert!(names.contains("content-type"));
    assert!(names.contains("x-keep"));
}

#[test]
fn secondary_filter_host_policy_and_extra_excludes() {
    let mut headers = HashMap::new();
    headers.insert("host".to_string(), "gateway.example".to_string());
    headers.insert("x-loadtesting-key".to_string(), "secret".to_string());
    headers.insert("x-custom".to_string(), "keep".to_string());

    let stripped = filter_secondary_request_headers(
        &headers,
        SecondaryRequestHostPolicy::Strip,
        PEER_UNTRUSTED,
        &[],
    );
    assert!(!stripped.iter().any(|(k, _)| k.eq_ignore_ascii_case("host")));

    let preserved = filter_secondary_request_headers(
        &headers,
        SecondaryRequestHostPolicy::Preserve,
        PEER_UNTRUSTED,
        &["x-loadtesting-key"],
    );
    assert!(
        preserved
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("host") && v == "gateway.example")
    );
    assert!(
        !preserved
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("x-loadtesting-key"))
    );
    assert!(preserved.iter().any(|(k, _)| k == "x-custom"));
}

#[test]
fn synthesize_grpc_te_accepts_native_family_and_rejects_prefix_smuggling() {
    // Positive: exact, +suffix, parameters, trailing OWS, mixed case.
    for content_type in [
        "application/grpc",
        "APPLICATION/GRPC",
        "application/grpc+proto",
        "Application/Grpc+Json",
        "application/grpc;charset=utf-8",
        "application/grpc ; charset=utf-8",
        "application/grpc ",
        "application/grpc\t",
    ] {
        let mut headers = vec![
            ("content-type".to_string(), content_type.to_string()),
            ("te".to_string(), "gzip".to_string()),
            ("x-keep".to_string(), "ok".to_string()),
        ];
        synthesize_grpc_te_trailers_if_needed(&mut headers);
        assert_eq!(
            headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("te"))
                .map(|(_, v)| v.as_str()),
            Some("trailers"),
            "native gRPC content-type `{content_type}` must re-synthesise te: trailers: {headers:?}"
        );
        assert!(headers.iter().any(|(k, _)| k == "x-keep"));
    }

    // Negative: prefix smuggling and gRPC-Web must not inject te: trailers.
    for content_type in [
        "application/grpcfoo",
        "application/grpc-malicious",
        "application/grpc-web",
        "application/grpc-web+proto",
        "application/json",
        "text/plain",
    ] {
        let mut headers = vec![
            ("content-type".to_string(), content_type.to_string()),
            ("x-keep".to_string(), "ok".to_string()),
        ];
        synthesize_grpc_te_trailers_if_needed(&mut headers);
        assert!(
            !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("te")),
            "non-native content-type `{content_type}` must not inject te: trailers: {headers:?}"
        );
    }
}

#[test]
fn secondary_filter_strips_untrusted_x_real_ip_for_every_host_policy() {
    // Issue #4164: the primary backend builders drop an untrusted peer's
    // `X-Real-IP` (`is_untrusted_real_ip_header`). The secondary boundary must
    // apply the identical rule, or a mirror / load-test target is told a
    // client-chosen source address the real backend never saw.
    for host_policy in [
        SecondaryRequestHostPolicy::Strip,
        SecondaryRequestHostPolicy::Preserve,
    ] {
        for name in ["x-real-ip", "X-Real-IP", "X-REAL-IP"] {
            let mut headers = HashMap::new();
            headers.insert(name.to_string(), "10.0.0.7".to_string());
            headers.insert("x-keep".to_string(), "ok".to_string());

            let untrusted =
                filter_secondary_request_headers(&headers, host_policy, PEER_UNTRUSTED, &[]);
            assert!(
                !untrusted
                    .iter()
                    .any(|(k, _)| k.eq_ignore_ascii_case("x-real-ip")),
                "untrusted peer's `{name}` reached a secondary target \
                 ({host_policy:?}): {untrusted:?}"
            );
            assert!(
                untrusted.iter().any(|(k, v)| k == "x-keep" && v == "ok"),
                "ordinary application headers must still be forwarded: {untrusted:?}"
            );

            // No regression for the overwrite-only-proxy case the primary path
            // deliberately supports: a trusted peer's assertion still rides.
            let trusted =
                filter_secondary_request_headers(&headers, host_policy, PEER_TRUSTED, &[]);
            assert!(
                trusted
                    .iter()
                    .any(|(k, v)| k.eq_ignore_ascii_case("x-real-ip") && v == "10.0.0.7"),
                "trusted peer's `{name}` must survive ({host_policy:?}): {trusted:?}"
            );
        }
    }
}

#[test]
fn secondary_strip_predicate_matches_primary_untrusted_real_ip_rule() {
    // Structural reuse guard: the secondary predicate must delegate to the same
    // helper the primary builders call, not carry a forked name list.
    for peer_trusted in [PEER_UNTRUSTED, PEER_TRUSTED] {
        for name in ["x-real-ip", "X-Real-Ip"] {
            assert_eq!(
                is_secondary_request_strip_header(
                    name,
                    &[],
                    SecondaryRequestHostPolicy::Preserve,
                    peer_trusted,
                ),
                is_untrusted_real_ip_header(name, peer_trusted),
                "secondary predicate diverged from the primary real-IP rule for \
                 `{name}` (peer_trusted={peer_trusted})"
            );
        }
    }
}

#[test]
fn secondary_targets_never_receive_client_supplied_gateway_assertions() {
    // Companion to the `X-Real-IP` guard above: the reserved gateway-assertion
    // family reaches a secondary target only when the GATEWAY asserted it. A
    // client-supplied value is dropped one boundary earlier, at
    // `RequestContext::materialize_headers`, so a mirror / load-test target
    // cannot be told a forged consumer, GeoIP country, or path parameter.
    // `forwarding_peer_trusted` deliberately does NOT unlock these — a trusted
    // proxy is allowed to assert a source address, never an identity.
    let mut ctx = RequestContext::new("198.51.100.9".into(), "GET".into(), "/".into());
    let mut raw = HeaderMap::new();
    raw.insert("x-consumer-username", "forged-admin".parse().unwrap());
    raw.insert("x-consumer-custom-id", "forged-id".parse().unwrap());
    raw.insert("x-geo-country", "XX".parse().unwrap());
    raw.insert("x-path-param-user_id", "forged".parse().unwrap());
    raw.insert("x-real-ip", "10.0.0.7".parse().unwrap());
    raw.insert("x-app-correlation", "keep".parse().unwrap());
    ctx.set_raw_headers(raw);
    ctx.materialize_headers();
    ctx.forwarding_peer_trusted = PEER_TRUSTED;

    for host_policy in [
        SecondaryRequestHostPolicy::Strip,
        SecondaryRequestHostPolicy::Preserve,
    ] {
        let out = filter_secondary_request_headers(
            &ctx.headers,
            host_policy,
            ctx.forwarding_peer_trusted,
            &[],
        );
        for forged in [
            "x-consumer-username",
            "x-consumer-custom-id",
            "x-geo-country",
            "x-path-param-user_id",
        ] {
            assert!(
                !out.iter().any(|(k, _)| k.eq_ignore_ascii_case(forged)),
                "client-supplied `{forged}` reached a secondary target \
                 ({host_policy:?}): {out:?}"
            );
        }
        assert!(
            out.iter()
                .any(|(k, v)| k == "x-app-correlation" && v == "keep"),
            "ordinary application headers must still be forwarded: {out:?}"
        );
    }
}
