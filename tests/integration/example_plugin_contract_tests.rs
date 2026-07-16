//! Source-contract guards for the public custom-plugin lifecycle documentation.
//!
//! Runtime behavior is exercised by the hosted-only functional protocol matrix;
//! these guards make the routing and logging boundaries fail visibly if the
//! H1/H2 or H3 control-flow markers move without the public contract changing.

const PROXY_SOURCE: &str = include_str!("../../src/proxy/mod.rs");
const H3_SOURCE: &str = include_str!("../../src/http3/server.rs");
const TRAIT_SOURCE: &str = include_str!("../../src/plugins/mod.rs");
const EXAMPLE_SOURCE: &str = include_str!("../../custom_plugins/example_plugin.rs");
const AUDIT_EXAMPLE_SOURCE: &str = include_str!("../../custom_plugins/example_audit_plugin.rs");
const CUSTOM_PLUGIN_GUIDE: &str = include_str!("../../CUSTOM_PLUGINS.md");
const EXECUTION_ORDER_GUIDE: &str = include_str!("../../docs/plugin_execution_order.md");

fn assert_markers_in_order(source: &str, surface: &str, markers: &[&str]) {
    let mut offset = 0;
    for marker in markers {
        let relative = source[offset..]
            .find(marker)
            .unwrap_or_else(|| panic!("{surface} is missing lifecycle marker: {marker}"));
        offset += relative + marker.len();
    }
}

#[test]
fn h1_h2_route_miss_and_method_rejection_precede_request_hooks() {
    assert_markers_in_order(
        PROXY_SOURCE,
        "H1/H2 proxy",
        &[
            "No route matched for request path",
            "StatusCode::NOT_FOUND",
            "// Per-proxy HTTP method filtering (checked before plugins to save work)",
            "StatusCode::METHOD_NOT_ALLOWED",
            "let plugin_cache_view = epoch.plugin_cache.request_view(&proxy.id, request_protocol);",
            "match plugin.on_request_received(&mut ctx).await",
        ],
    );
}

#[test]
fn h3_route_miss_and_method_rejection_precede_request_hooks() {
    assert_markers_in_order(
        H3_SOURCE,
        "H3 proxy",
        &[
            "StatusCode::NOT_FOUND",
            "// Per-proxy HTTP method filtering (checked before plugins to save work)",
            "StatusCode::METHOD_NOT_ALLOWED",
            "let plugin_cache_view = epoch.plugin_cache.request_view(&proxy.id, request_protocol);",
            "match plugin.on_request_received(&mut ctx).await",
        ],
    );
}

#[test]
fn trait_example_and_guides_describe_the_same_request_boundary() {
    assert!(
        TRAIT_SOURCE
            .contains("Called after routing and per-proxy allowed-method admission succeed.")
    );
    assert!(
        EXAMPLE_SOURCE
            .contains("Called after a route matches and its allowed-method check succeeds.")
    );
    assert!(
        CUSTOM_PLUGIN_GUIDE.contains(
            "returns 404 without running any global or scoped `on_request_received` hook."
        )
    );
    assert!(
        CUSTOM_PLUGIN_GUIDE.contains(
            "matched request with a disallowed method returns 405 without running either"
        )
    );
    assert!(
        EXECUTION_ORDER_GUIDE
            .contains("`on_request_received` is therefore a post-route, post-allowed-method hook")
    );
}

#[test]
fn trait_example_and_guides_describe_buffered_streaming_and_h3_log_timing() {
    for source in [TRAIT_SOURCE, CUSTOM_PLUGIN_GUIDE, EXECUTION_ORDER_GUIDE] {
        assert!(
            source.contains("await"),
            "logging contract must name awaited hooks"
        );
        assert!(
            source.contains("sequential"),
            "logging contract must name sequential invocation"
        );
        assert!(
            source.contains("Native H3") || source.contains("native-H3"),
            "logging contract must distinguish native H3"
        );
    }
    assert!(EXAMPLE_SOURCE.contains("Hyper-owned streamed bodies spawn logging"));
    assert!(AUDIT_EXAMPLE_SOURCE.contains("bounded, plugin-owned queue"));
    assert!(!AUDIT_EXAMPLE_SOURCE.contains("logging hook (fire-and-forget)"));
    assert!(H3_SOURCE.contains("# Why H3 does not use `DeferredTransactionLogger`"));
    assert!(H3_SOURCE.contains("drives the\n/// QUIC send stream to completion synchronously"));
}
