//! Source-contract guards for the public custom-plugin lifecycle documentation.
//!
//! Runtime behavior is exercised by the hosted-only functional protocol matrix;
//! these guards make the routing and logging boundaries fail visibly if the
//! H1/H2 or H3 control-flow markers move without the public contract changing.
//! The separate `example_audit_plugin` persistence/lifecycle work owns its own
//! contracts, so this module deliberately does not pin that file's text.

const PROXY_SOURCE: &str = include_str!("../../src/proxy/mod.rs");
const H3_SOURCE: &str = include_str!("../../src/http3/server.rs");
const TRAIT_SOURCE: &str = include_str!("../../src/plugins/mod.rs");
const EXAMPLE_SOURCE: &str = include_str!("../../custom_plugins/example_plugin.rs");
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
            "// gRPC spec mandates POST method.",
            "StatusCode::BAD_REQUEST",
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
            "// gRPC spec mandates POST.",
            "StatusCode::BAD_REQUEST",
            "let plugin_cache_view = epoch.plugin_cache.request_view(&proxy.id, request_protocol);",
            "match plugin.on_request_received(&mut ctx).await",
        ],
    );
}

#[test]
fn h1_h2_buffered_terminal_logging_precedes_response_construction() {
    assert_markers_in_order(
        PROXY_SOURCE,
        "H1/H2 buffered terminal path",
        &[
            "let deferred_logger: Option<Arc<crate::proxy::deferred_log::DeferredTransactionLogger>> =",
            "if body_will_stream {",
            "DeferredTransactionLogger::new_with_start_time(",
            "} else {",
            "crate::plugins::log_with_mirror(&plugins, &summary, &ctx).await;",
            "record_request(&state, response_status);",
            "// Build final response",
            "let mut resp_builder = Response::builder()",
        ],
    );
}

#[test]
fn h3_buffered_terminal_logging_precedes_response_construction_and_send() {
    assert_markers_in_order(
        H3_SOURCE,
        "H3 buffered terminal path",
        &[
            "// ===== BUFFERED RESPONSE PATH =====",
            "let summary = TransactionSummary {",
            "crate::plugins::log_with_mirror(&plugins, &summary, &ctx).await;",
            "// Build and send buffered response",
            "apply_response_headers(Response::builder().status(status), &response_headers);",
            "stream.send_response(resp).await?;",
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
    for source in [
        TRAIT_SOURCE,
        EXAMPLE_SOURCE,
        CUSTOM_PLUGIN_GUIDE,
        EXECUTION_ORDER_GUIDE,
    ] {
        assert!(
            source.contains("Native gRPC requests must also use `POST` before this hook runs.")
        );
    }
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
    assert!(H3_SOURCE.contains("# Why H3 does not use `DeferredTransactionLogger`"));
    assert!(H3_SOURCE.contains("drives the\n/// QUIC send stream to completion synchronously"));
}
