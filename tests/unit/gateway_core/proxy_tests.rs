use chrono::Utc;
use ferrum_edge::config::types::{
    AuthMode, BackendScheme, DispatchKind, GatewayConfig, Proxy, UpstreamTarget,
};
use ferrum_edge::proxy::{
    build_backend_effective_path, build_backend_url, build_backend_url_with_target,
    retry_target_preserves_backend_path,
};
use ferrum_edge::router_cache::RouterCache;
use std::collections::HashMap;

fn test_proxy() -> Proxy {
    Proxy {
        id: "test".into(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: Some("Test Proxy".into()),
        hosts: vec![],
        listen_path: Some("/api/v1".to_string()),
        backend_scheme: Some(BackendScheme::Http),
        dispatch_kind: DispatchKind::from(BackendScheme::Http),
        backend_host: "backend.example.com".into(),
        backend_port: 3000,
        backend_path: None,
        strip_listen_path: true,
        preserve_host_header: false,
        backend_connect_timeout_ms: 5000,
        backend_read_timeout_ms: 30000,
        backend_write_timeout_ms: 30000,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        resolved_tls: Default::default(),
        dispatch_port_overrides: None,
        dispatch_port_override_fallback: None,
        dns_override: None,
        dns_cache_ttl_seconds: None,
        auth_mode: AuthMode::Single,
        plugins: vec![],

        pool_idle_timeout_seconds: None,
        pool_enable_http_keep_alive: None,
        pool_enable_http2: None,
        pool_tcp_keepalive_seconds: None,
        pool_http2_keep_alive_interval_seconds: None,
        pool_http2_keep_alive_timeout_seconds: None,
        pool_http2_initial_stream_window_size: None,
        pool_http2_initial_connection_window_size: None,
        pool_http2_adaptive_window: None,
        pool_http2_max_frame_size: None,
        pool_http2_max_concurrent_streams: None,
        pool_http3_connections_per_backend: None,
        h2_upgrade_policy: None,
        pool_max_requests_per_connection: None,
        pool_http1_max_pending_requests: None,
        upstream_id: None,
        upstream_subset: None,
        api_spec_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: Default::default(),
        listen_port: None,
        frontend_tls: false,
        passthrough: false,
        udp_idle_timeout_seconds: 60,
        tcp_idle_timeout_seconds: Some(300),
        websocket_idle_timeout_seconds: None,
        allowed_methods: None,
        allowed_ws_origins: vec![],
        udp_max_response_amplification_factor: None,
        stream_proxy_protocol: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

#[test]
fn test_build_backend_url_strip() {
    let proxy = test_proxy();
    let url = build_backend_url(
        &proxy,
        "/api/v1/users/123",
        "",
        proxy.listen_path.as_deref().map(str::len).unwrap_or(0),
    );
    assert_eq!(url, "http://backend.example.com:3000/users/123");
}

#[test]
fn test_build_backend_url_no_strip() {
    let mut proxy = test_proxy();
    proxy.strip_listen_path = false;
    let url = build_backend_url(
        &proxy,
        "/api/v1/users/123",
        "",
        proxy.listen_path.as_deref().map(str::len).unwrap_or(0),
    );
    assert_eq!(url, "http://backend.example.com:3000/api/v1/users/123");
}

#[test]
fn test_build_backend_url_with_backend_path() {
    let mut proxy = test_proxy();
    proxy.backend_path = Some("/internal".into());
    let url = build_backend_url(
        &proxy,
        "/api/v1/users",
        "",
        proxy.listen_path.as_deref().map(str::len).unwrap_or(0),
    );
    assert_eq!(url, "http://backend.example.com:3000/internal/users");
}

#[test]
fn test_build_backend_url_with_relative_backend_path() {
    let mut proxy = test_proxy();
    proxy.backend_path = Some("internal".into());
    let url = build_backend_url(
        &proxy,
        "/api/v1/users",
        "",
        proxy.listen_path.as_deref().map(str::len).unwrap_or(0),
    );
    assert_eq!(url, "http://backend.example.com:3000/internal/users");
}

#[test]
fn test_build_backend_url_with_query() {
    let proxy = test_proxy();
    let url = build_backend_url(
        &proxy,
        "/api/v1/search",
        "q=hello&page=1",
        proxy.listen_path.as_deref().map(str::len).unwrap_or(0),
    );
    assert_eq!(url, "http://backend.example.com:3000/search?q=hello&page=1");
}

#[test]
fn test_build_backend_url_target_path_overrides_backend_path() {
    let mut proxy = test_proxy();
    proxy.backend_path = Some("/v1".into());
    let url = build_backend_url_with_target(
        &proxy,
        "/api/v1/users",
        "",
        "target.example.com",
        9090,
        proxy.listen_path.as_deref().map(str::len).unwrap_or(0),
        Some("/v2"),
    );
    assert_eq!(url, "http://target.example.com:9090/v2/users");
}

#[test]
fn test_build_backend_url_target_path_none_uses_backend_path() {
    let mut proxy = test_proxy();
    proxy.backend_path = Some("/v1".into());
    let url = build_backend_url_with_target(
        &proxy,
        "/api/v1/users",
        "",
        "target.example.com",
        9090,
        proxy.listen_path.as_deref().map(str::len).unwrap_or(0),
        None,
    );
    assert_eq!(url, "http://target.example.com:9090/v1/users");
}

#[test]
fn test_build_backend_url_target_path_with_no_backend_path() {
    let proxy = test_proxy();
    let url = build_backend_url_with_target(
        &proxy,
        "/api/v1/users",
        "",
        "target.example.com",
        9090,
        proxy.listen_path.as_deref().map(str::len).unwrap_or(0),
        Some("/service"),
    );
    assert_eq!(url, "http://target.example.com:9090/service/users");
}

#[test]
fn test_build_backend_url_target_path_without_slashes_inserts_separator() {
    let mut proxy = test_proxy();
    proxy.listen_path = Some("/api/v1/".into());
    let url = build_backend_url_with_target(
        &proxy,
        "/api/v1/users",
        "",
        "target.example.com",
        9090,
        proxy.listen_path.as_deref().map(str::len).unwrap_or(0),
        Some("service"),
    );
    assert_eq!(url, "http://target.example.com:9090/service/users");
}

#[test]
fn test_build_backend_url_target_path_with_query() {
    let proxy = test_proxy();
    let url = build_backend_url_with_target(
        &proxy,
        "/api/v1/search",
        "q=hello",
        "target.example.com",
        9090,
        proxy.listen_path.as_deref().map(str::len).unwrap_or(0),
        Some("/svc"),
    );
    assert_eq!(url, "http://target.example.com:9090/svc/search?q=hello");
}

#[test]
fn test_backend_effective_grpc_path_uses_prefix_strip() {
    let mut proxy = test_proxy();
    proxy.listen_path = Some("/prefix".into());
    let path =
        build_backend_effective_path(&proxy, "/prefix/pkg.Service/Denied", "/prefix".len(), None);
    assert_eq!(path, "/pkg.Service/Denied");
}

#[test]
fn test_backend_effective_grpc_path_uses_exact_route_backend_path() {
    let mut proxy = test_proxy();
    proxy.listen_path = Some("=/public.Service/Allowed".into());
    proxy.backend_path = Some("/admin.Service/Delete".into());
    let incoming = "/public.Service/Allowed";
    let path = build_backend_effective_path(&proxy, incoming, incoming.len(), None);
    assert_eq!(path, "/admin.Service/Delete");
}

#[test]
fn test_backend_effective_grpc_path_uses_regex_match_length() {
    let mut proxy = test_proxy();
    proxy.listen_path = Some("~^/public\\.Service/Allowed$".into());
    proxy.backend_path = Some("/admin.Service/Delete".into());
    let incoming = "/public.Service/Allowed";
    let path = build_backend_effective_path(&proxy, incoming, incoming.len(), None);
    assert_eq!(path, "/admin.Service/Delete");
}

#[test]
fn test_backend_effective_grpc_path_uses_selected_target_path() {
    let mut proxy = test_proxy();
    proxy.backend_path = Some("/ignored.Service/Method".into());
    let incoming = "/api/v1";
    let path = build_backend_effective_path(
        &proxy,
        incoming,
        incoming.len(),
        Some("/selected.Service/Method"),
    );
    assert_eq!(path, "/selected.Service/Method");
}

#[test]
fn test_backend_effective_path_matches_backend_url_path_assembly() {
    let mut proxy = test_proxy();
    proxy.backend_path = Some("/backend.Service".into());
    let incoming = "/api/v1/Method";
    let strip_len = "/api/v1".len();
    let path = build_backend_effective_path(&proxy, incoming, strip_len, None);
    let url = build_backend_url_with_target(
        &proxy,
        incoming,
        "",
        "target.example.com",
        9090,
        strip_len,
        None,
    );
    assert_eq!(path, "/backend.Service/Method");
    assert_eq!(url, format!("http://target.example.com:9090{path}"));
}

fn retry_target(host: &str, path: Option<&str>) -> UpstreamTarget {
    UpstreamTarget {
        host: host.to_string(),
        port: 9090,
        service_port_policy_key: None,
        weight: 100,
        tags: HashMap::new(),
        locality: None,
        path: path.map(str::to_string),
    }
}

#[test]
fn test_backend_path_policy_pins_target_path_across_retries() {
    let mut proxy = test_proxy();
    proxy.backend_path = Some("/pkg.Service".to_string());
    let incoming = "/api/v1/Allowed";
    let strip_len = "/api/v1".len();
    let initial = retry_target("first.example.com", Some("/pkg.Service"));
    let same_method = retry_target("second.example.com", Some("/pkg.Service"));
    let different_method = retry_target("third.example.com", Some("/admin.Service"));
    let explicit_prefix = retry_target("fourth.example.com", Some("/pkg.Service"));
    let proxy_fallback = retry_target("fifth.example.com", None);
    let relative_prefix = retry_target("sixth.example.com", Some("pkg.Service"));

    assert!(retry_target_preserves_backend_path(
        true,
        &proxy,
        incoming,
        strip_len,
        &initial,
        &same_method
    ));
    assert!(!retry_target_preserves_backend_path(
        true,
        &proxy,
        incoming,
        strip_len,
        &initial,
        &different_method
    ));
    assert!(retry_target_preserves_backend_path(
        false,
        &proxy,
        incoming,
        strip_len,
        &initial,
        &different_method
    ));
    assert!(retry_target_preserves_backend_path(
        true,
        &proxy,
        incoming,
        strip_len,
        &explicit_prefix,
        &proxy_fallback
    ));
    assert!(retry_target_preserves_backend_path(
        true,
        &proxy,
        incoming,
        strip_len,
        &relative_prefix,
        &proxy_fallback
    ));
}

#[test]
fn test_backend_path_bound_retries_abort_in_every_h1_h2_dispatch_family() {
    let source = include_str!("../../../src/proxy/mod.rs");
    assert!(source.contains(
        "Aborting gRPC retry because the candidate would change the authorized backend method path"
    ));
    assert!(source.contains(
        "Aborting retry because the candidate would change the authorized backend method path"
    ));
    assert!(source.contains(
        "Aborting WebSocket retry because the candidate would change the authorized backend method path"
    ));
    assert!(source.contains("if retry_admitted_by_cb && !retry_path_mismatch"));
}

#[test]
fn test_side_effecting_before_proxy_hooks_run_after_backend_path_policy() {
    let source = include_str!("../../../src/proxy/mod.rs");
    let path_policy = source
        .rfind("if let Some(response) = run_backend_path_plugins_or_build_reject(")
        .expect("backend-path policy hook must remain present");
    let deferred = source
        .find("// Hooks that can dispatch external work or synthesize a terminal response")
        .expect("deferred before_proxy pass must remain present");
    assert!(path_policy < deferred);
    assert!(source.contains("BackendPathBeforeProxyPass::RoutingHeaderDeferred"));
    assert!(source.contains("BackendPathPolicyPhase::Preview"));
    assert!(source.contains("BackendPathPolicyPhase::Enforce"));
    assert!(
        !source.contains("backend_dispatch::upstream_selection_hash_key("),
        "an external deferred hook must not reselect an unpreviewed target"
    );
    assert!(source.contains("std::mem::replace(&mut ctx.path, original_request_path.clone())"));
    assert!(
        !source.contains(
            "if !matches!(deferred_result, PluginResult::Continue) {\n            break;"
        ),
        "a deferred routing-hook rejection must still reach final method enforcement"
    );

    let mirror = include_str!("../../../src/plugins/request_mirror.rs");
    assert!(mirror.contains("ctx.authorized_backend_path().unwrap_or(&ctx.path)"));

    for plugin_source in [
        include_str!("../../../src/plugins/fault_injection.rs"),
        include_str!("../../../src/plugins/grpc_deadline.rs"),
        include_str!("../../../src/plugins/request_mirror.rs"),
        include_str!("../../../src/plugins/response_mock.rs"),
        include_str!("../../../src/plugins/serverless_function.rs"),
        include_str!("../../../src/plugins/load_testing.rs"),
    ] {
        assert!(
            plugin_source
                .contains("fn defer_before_proxy_until_backend_path_resolved(&self) -> bool")
        );
    }

    let serverless = include_str!("../../../src/plugins/serverless_function.rs");
    assert!(
        serverless.contains("fn deferred_before_proxy_may_change_routing_headers(&self) -> bool")
    );
}

#[test]
fn test_h1_h2_route_rejects_keep_websocket_precedence_and_grpc_web_headers() {
    let source = include_str!("../../../src/proxy/mod.rs");
    let handler = source
        .find("async fn handle_proxy_request_inner(")
        .map(|start| &source[start..])
        .expect("H1/H2 request handler must remain present");
    let flavor = handler
        .find("let flavor = crate::proxy::backend_dispatch::detect_http_flavor(&req);")
        .expect("wire flavor classification must remain present");
    let websocket_precedence = handler
        .find("let grpc_web_response_content_type = if flavor == HttpFlavor::WebSocket")
        .expect("WebSocket must suppress hostile gRPC-Web Content-Type promotion");
    let routed = handler
        .find("ctx.matched_proxy = Some(Arc::clone(&proxy));")
        .expect("route selection must remain present");
    let protocol = handler
        .find("let request_protocol = match flavor")
        .expect("route-level protocol selection must remain present");

    assert!(flavor < websocket_precedence && websocket_precedence < routed && routed < protocol);
    assert!(
        !handler[routed..protocol].contains("let grpc_web_response_content_type"),
        "route-level rejects must reuse the WebSocket-safe strict classification"
    );
    assert!(handler.contains("build_grpc_web_reject_response("));
    assert!(source.contains(
        "finalize_grpc_web_error_response_headers(&mut translated, &[], Some(&reject.headers));"
    ));
    let finalizer = source
        .find("pub(crate) fn finalize_grpc_web_error_response_headers(")
        .map(|start| &source[start..])
        .expect("gRPC-Web error finalizer must remain present");
    assert!(finalizer.contains("\"grpc-status\","));
    assert!(finalizer.contains("\"grpc-message\","));
}

#[test]
fn test_backend_path_bound_retries_preflight_before_backoff() {
    let source = include_str!("../../../src/proxy/mod.rs");

    let grpc_retry = source
        .find("// Resolve and validate the next gRPC retry target before")
        .expect("direct gRPC retries must preflight the next target");
    let grpc_after_preflight = &source[grpc_retry..];
    let grpc_mismatch = grpc_after_preflight
        .find("Aborting gRPC retry because the candidate would change")
        .expect("direct gRPC retries must reject a path-changing target");
    let grpc_intermediate_record = grpc_after_preflight
        .find("record_grpc_backend_dispatch_outcome(")
        .expect("direct gRPC retry accounting must remain present");
    let grpc_backoff = grpc_after_preflight
        .find("let delay = retry::retry_delay(retry_config, grpc_attempt);")
        .expect("direct gRPC retry backoff must remain present");
    assert!(
        grpc_mismatch < grpc_intermediate_record
            && grpc_mismatch < grpc_backoff
            && grpc_after_preflight[grpc_mismatch..grpc_intermediate_record].contains("break;"),
        "direct gRPC path mismatch must abort before intermediate accounting and retry backoff"
    );

    let generic_retry = source
        .find("// Resolve and validate the next retry target before charging this")
        .expect("generic H1/H2 retries must preflight the next target");
    let generic_after_preflight = &source[generic_retry..];
    let generic_mismatch = generic_after_preflight
        .find("Aborting retry because the candidate would change")
        .expect("generic H1/H2 retries must reject a path-changing target");
    let generic_intermediate_record = generic_after_preflight
        .find("permits.record_backend_outcome(BackendAdmissionOutcome {")
        .expect("generic H1/H2 retry accounting must remain present");
    let generic_backoff = generic_after_preflight
        .find("let delay = retry::retry_delay(retry_config, attempt);")
        .expect("generic H1/H2 retry backoff must remain present");
    assert!(
        generic_mismatch < generic_intermediate_record
            && generic_mismatch < generic_backoff
            && generic_after_preflight[generic_mismatch..generic_intermediate_record]
                .contains("break;"),
        "generic H1/H2 path mismatch must abort before intermediate accounting and retry backoff"
    );
}

#[test]
fn test_deferred_hooks_cannot_spoof_backend_consumer_identity() {
    let source = include_str!("../../../src/proxy/mod.rs");
    let routing_hook = source
        .rfind("BackendPathBeforeProxyPass::RoutingHeaderDeferred")
        .expect("deferred routing-header hook must remain present");
    let after_routing_hook = &source[routing_hook..];
    let refresh = after_routing_hook
        .find("refresh_effective_backend_consumer_identity_headers(")
        .expect("identity headers must be refreshed after deferred routing hooks");
    let baggage_strip = after_routing_hook
        .find("hbone_proxy::strip_egress_baggage_in_proxy_headers(")
        .expect("egress baggage policy must run after deferred routing hooks");
    let remaining_hook = after_routing_hook
        .find("BackendPathBeforeProxyPass::RemainingDeferred")
        .expect("remaining deferred hook pass must remain present");
    assert!(
        refresh < baggage_strip && baggage_strip < remaining_hook,
        "gateway identity and baggage policy must be restored before final enforcement"
    );
    assert!(
        !after_routing_hook[..remaining_hook].contains("select_upstream_target("),
        "deferred headers must not steer the request to an unpreviewed target"
    );

    let remaining_hook = routing_hook + remaining_hook;
    assert!(
        source[remaining_hook..].contains("refresh_effective_backend_consumer_identity_headers("),
        "gateway identity must be restored after every deferred hook pass"
    );
    assert!(
        source[remaining_hook..].contains("hbone_proxy::strip_egress_baggage_in_proxy_headers("),
        "egress baggage policy must be restored after every deferred hook pass"
    );
    assert!(
        source.contains("name.eq_ignore_ascii_case(\"x-consumer-username\")")
            && source.contains("name.eq_ignore_ascii_case(\"x-consumer-custom-id\")"),
        "the shared scrub must reject case variants of reserved identity headers"
    );
}

#[test]
fn test_longest_prefix_match() {
    let config = GatewayConfig {
        version: "1".to_string(),
        proxies: vec![
            Proxy {
                listen_path: Some("/api".to_string()),
                id: "short".into(),
                namespace: ferrum_edge::config::types::default_namespace(),
                ..test_proxy()
            },
            Proxy {
                listen_path: Some("/api/v1".to_string()),
                id: "long".into(),
                namespace: ferrum_edge::config::types::default_namespace(),
                ..test_proxy()
            },
        ],
        consumers: vec![],
        plugin_configs: vec![],
        upstreams: vec![],
        loaded_at: Utc::now(),
        known_namespaces: Vec::new(),
        ..Default::default()
    };
    let router = RouterCache::new(&config, 10000);
    let matched = router.find_proxy(None, "/api/v1/users");
    assert!(matched.is_some());
    assert_eq!(matched.unwrap().proxy.id, "long");
}

#[test]
fn test_no_match() {
    let config = GatewayConfig {
        version: "1".to_string(),
        proxies: vec![Proxy {
            listen_path: Some("/api".to_string()),
            ..test_proxy()
        }],
        consumers: vec![],
        plugin_configs: vec![],
        upstreams: vec![],
        loaded_at: Utc::now(),
        known_namespaces: Vec::new(),
        ..Default::default()
    };
    let router = RouterCache::new(&config, 10000);
    let matched = router.find_proxy(None, "/other/path");
    assert!(matched.is_none());
}

// ── Internal proxy/mod.rs function tests (moved from inline) ─────────────────

use async_trait::async_trait;
use ferrum_edge::_test_support::{
    apply_request_body_plugins, can_dispatch_direct_http2_pool, can_use_direct_http2_pool,
    extract_grpc_reject_message, insert_grpc_error_metadata, map_http_reject_status_to_grpc_status,
    normalize_reject_response, request_may_have_body,
};
use ferrum_edge::config::types::Consumer;
use ferrum_edge::consumer_index::ConsumerIndex;
use ferrum_edge::plugins::{
    Plugin, PluginResult, RequestContext, basic_auth::BasicAuth, jwt_auth::JwtAuth,
    key_auth::KeyAuth,
};
use ferrum_edge::proxy::grpc_proxy::grpc_status;
use ferrum_edge::proxy::run_authentication_phase;
use hyper::StatusCode;
use serde_json::json;
use std::sync::Arc;

struct ExternalIdentityAuth;

const BASIC_AUTH_TEST_SECRET: &str = "test-hmac-secret-for-basic-auth-unit-tests";

fn basic_auth_dispatch_consumer() -> Consumer {
    use hmac::{KeyInit, Mac};

    type HmacSha256 = hmac::Hmac<sha2::Sha256>;
    let mut mac = HmacSha256::new_from_slice(BASIC_AUTH_TEST_SECRET.as_bytes()).unwrap();
    mac.update(b"password");
    let password_hash = format!("hmac_sha256:{}", hex::encode(mac.finalize().into_bytes()));

    Consumer {
        id: "basic-dispatch-consumer".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: "alice".to_string(),
        custom_id: None,
        credentials: HashMap::from([(
            "basicauth".to_string(),
            json!([{"password_hash": password_hash}]),
        )]),
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

#[async_trait]
impl Plugin for ExternalIdentityAuth {
    fn name(&self) -> &str {
        "external_identity_auth"
    }
    fn is_auth_plugin(&self) -> bool {
        true
    }
    async fn authenticate(
        &self,
        ctx: &mut RequestContext,
        _consumer_index: &ConsumerIndex,
    ) -> PluginResult {
        ctx.authenticated_identity = Some("external-user".to_string());
        ctx.authenticated_identity_header = Some("external@example.com".to_string());
        PluginResult::Continue
    }
}

struct RejectingAuth {
    body: &'static str,
}

struct StagedCookieRejectingAuth;

struct MixedCaseCookieRejectingAuth;

struct ScopedCookieStagingAuth {
    cookies: &'static str,
}

struct ScopedCookieSelectedAuth {
    cookies: &'static str,
}

#[async_trait]
impl Plugin for RejectingAuth {
    fn name(&self) -> &str {
        "rejecting_auth"
    }
    fn is_auth_plugin(&self) -> bool {
        true
    }
    async fn authenticate(
        &self,
        _ctx: &mut RequestContext,
        _consumer_index: &ConsumerIndex,
    ) -> PluginResult {
        PluginResult::Reject {
            status_code: 401,
            body: self.body.to_string(),
            headers: HashMap::new(),
        }
    }
}

#[async_trait]
impl Plugin for StagedCookieRejectingAuth {
    fn name(&self) -> &str {
        "staged_cookie_rejecting_auth"
    }

    fn is_auth_plugin(&self) -> bool {
        true
    }

    async fn authenticate(
        &self,
        ctx: &mut RequestContext,
        _consumer_index: &ConsumerIndex,
    ) -> PluginResult {
        ctx.metadata.insert(
            "auth.rejection_set_cookie".to_string(),
            "session=staged; Path=/staged; HttpOnly\nSession=case-sensitive; Path=/case\nstaged_only=1; Path=/staged\ndomain=staged; Domain=example.com; Path=/app\ndomain=staged-other; Domain=api.example.com; Path=/app\nhost_scope=staged; Path=/\nomitted=staged\nduplicate=staged; Path=/effective\nquoted=staged; Path=\"/quoted\"\nmalformed pair=staged; Path=/\nquoted_domain=staged; Domain=\".example.com\"; Path=/\ninvalid_path=staged; Path=\nvalue_space=staged; Path=/\nname_space=staged; Path=/"
                .to_string(),
        );
        PluginResult::Reject {
            status_code: 401,
            body: r#"{"error":"staged rejection"}"#.to_string(),
            headers: HashMap::new(),
        }
    }
}

#[async_trait]
impl Plugin for MixedCaseCookieRejectingAuth {
    fn name(&self) -> &str {
        "mixed_case_cookie_rejecting_auth"
    }

    fn is_auth_plugin(&self) -> bool {
        true
    }

    async fn authenticate(
        &self,
        _ctx: &mut RequestContext,
        _consumer_index: &ConsumerIndex,
    ) -> PluginResult {
        PluginResult::Reject {
            status_code: 403,
            body: r#"{"error":"mixed-case rejection"}"#.to_string(),
            headers: HashMap::from([
                (
                    "Set-Cookie".to_string(),
                    "session=selected-upper; Path=/upper; HttpOnly\nupper_only=1; Path=/upper\nshared=1; Path=/\nscoped=clear-root; Path=/\nscoped=clear-app; Path=/app\ndomain=selected; dOmAiN=.Example.COM; pAtH=/app\nhost_scope=selected; Domain=example.com; Path=/\nomitted=selected; Path=/\nduplicate=selected; Path=/ignored; PATH=/effective\nquoted=selected; Path=\"/quoted\"\nmalformed pair=selected; Path=/\nquoted_domain=selected; Domain=\".example.com\"; Path=/\ninvalid_path=selected; Path=\nvalue_space=selected ; Path=/\n name_space =selected; Path=/"
                        .to_string(),
                ),
                (
                    "set-cookie".to_string(),
                    "shared=1; Path=/\nlower_only=1; Path=/lower\nsession=selected-lower; Path=/lower; Secure; SameSite=Strict"
                        .to_string(),
                ),
                ("X-Rejection".to_string(), "selected".to_string()),
            ]),
        }
    }
}

#[async_trait]
impl Plugin for ScopedCookieStagingAuth {
    fn name(&self) -> &str {
        "scoped_cookie_staging_auth"
    }

    fn is_auth_plugin(&self) -> bool {
        true
    }

    async fn authenticate(
        &self,
        ctx: &mut RequestContext,
        _consumer_index: &ConsumerIndex,
    ) -> PluginResult {
        ctx.metadata.insert(
            "auth.rejection_set_cookie".to_string(),
            self.cookies.to_string(),
        );
        PluginResult::Reject {
            status_code: 401,
            body: r#"{"error":"staged rejection"}"#.to_string(),
            headers: HashMap::new(),
        }
    }
}

#[async_trait]
impl Plugin for ScopedCookieSelectedAuth {
    fn name(&self) -> &str {
        "scoped_cookie_selected_auth"
    }

    fn is_auth_plugin(&self) -> bool {
        true
    }

    async fn authenticate(
        &self,
        _ctx: &mut RequestContext,
        _consumer_index: &ConsumerIndex,
    ) -> PluginResult {
        PluginResult::Reject {
            status_code: 403,
            body: r#"{"error":"selected rejection"}"#.to_string(),
            headers: HashMap::from([("Set-Cookie".to_string(), self.cookies.to_string())]),
        }
    }
}

struct IdentityThenRejectAuth;

#[async_trait]
impl Plugin for IdentityThenRejectAuth {
    fn name(&self) -> &str {
        "identity_then_reject_auth"
    }

    fn is_auth_plugin(&self) -> bool {
        true
    }

    async fn authenticate(
        &self,
        ctx: &mut RequestContext,
        _consumer_index: &ConsumerIndex,
    ) -> PluginResult {
        ctx.authenticated_identity = Some("disabled-user".to_string());
        PluginResult::Reject {
            status_code: 403,
            body: r#"{"error":"account disabled"}"#.to_string(),
            headers: HashMap::new(),
        }
    }
}

struct PermissiveMissingMeshAuth;

#[async_trait]
impl Plugin for PermissiveMissingMeshAuth {
    fn name(&self) -> &str {
        "permissive_missing_mesh_auth"
    }

    fn is_auth_plugin(&self) -> bool {
        true
    }

    async fn authenticate(
        &self,
        ctx: &mut RequestContext,
        _consumer_index: &ConsumerIndex,
    ) -> PluginResult {
        ctx.metadata.insert(
            "mesh_request_auth.permissive_missing_token".to_string(),
            "true".to_string(),
        );
        PluginResult::Continue
    }
}

struct BodySuffixPlugin {
    suffix: &'static str,
}

struct MissingCredentialContinueAuth;

struct SkippedQueryCredentialAuth;

#[async_trait]
impl Plugin for SkippedQueryCredentialAuth {
    fn name(&self) -> &str {
        "skipped_query_credential_auth"
    }

    fn is_auth_plugin(&self) -> bool {
        true
    }

    fn mark_query_credentials_for_redaction(&self, ctx: &mut RequestContext) {
        if ctx.query_params.contains_key("custom_token") {
            ctx.metadata.insert(
                "auth.query_credential_param.custom_token".to_string(),
                "true".to_string(),
            );
        }
    }

    async fn authenticate(
        &self,
        _ctx: &mut RequestContext,
        _consumer_index: &ConsumerIndex,
    ) -> PluginResult {
        panic!("multi-auth should stop before the later query mechanism")
    }
}

#[async_trait]
impl Plugin for MissingCredentialContinueAuth {
    fn name(&self) -> &str {
        "missing_credential_continue_auth"
    }

    fn is_auth_plugin(&self) -> bool {
        true
    }

    async fn authenticate(
        &self,
        _ctx: &mut RequestContext,
        _consumer_index: &ConsumerIndex,
    ) -> PluginResult {
        PluginResult::Continue
    }
}

#[async_trait]
impl Plugin for BodySuffixPlugin {
    fn name(&self) -> &str {
        "body_suffix"
    }
    fn modifies_request_body(&self) -> bool {
        true
    }
    async fn transform_request_body(
        &self,
        body: &[u8],
        _content_type: Option<&str>,
        _request_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        let mut out = body.to_vec();
        out.extend_from_slice(self.suffix.as_bytes());
        Some(out)
    }
}

#[tokio::test]
async fn test_multi_auth_accepts_external_identity_without_consumer() {
    let external: Arc<dyn Plugin> = Arc::new(ExternalIdentityAuth);
    let rejecting: Arc<dyn Plugin> = Arc::new(RejectingAuth {
        body: r#"{"error":"Missing credentials"}"#,
    });
    let auth_plugins: Vec<Arc<dyn Plugin>> = vec![external, rejecting];
    let consumer_index = ConsumerIndex::new(&[]);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/jwks".to_string(),
    );

    let result =
        run_authentication_phase(AuthMode::Multi, &auth_plugins, &mut ctx, &consumer_index).await;

    assert!(result.is_none());
    assert_eq!(ctx.authenticated_identity.as_deref(), Some("external-user"));
    assert!(ctx.identified_consumer.is_none());
}

#[tokio::test]
async fn test_multi_auth_marks_query_credentials_before_first_success_short_circuits() {
    let external: Arc<dyn Plugin> = Arc::new(ExternalIdentityAuth);
    let skipped_query: Arc<dyn Plugin> = Arc::new(SkippedQueryCredentialAuth);
    let auth_plugins: Vec<Arc<dyn Plugin>> = vec![external, skipped_query];
    let consumer_index = ConsumerIndex::new(&[]);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/multi-auth".to_string(),
    );
    ctx.query_params
        .insert("custom_token".to_string(), "must-not-reach-opa".to_string());

    let result =
        run_authentication_phase(AuthMode::Multi, &auth_plugins, &mut ctx, &consumer_index).await;

    assert!(result.is_none());
    assert_eq!(
        ctx.metadata
            .get("auth.query_credential_param.custom_token")
            .map(String::as_str),
        Some("true")
    );
}

#[tokio::test]
async fn test_multi_auth_strips_skipped_key_auth_credentials_before_backend() {
    let external: Arc<dyn Plugin> = Arc::new(ExternalIdentityAuth);
    let header_key_auth: Arc<dyn Plugin> =
        Arc::new(KeyAuth::new(&json!({"key_location": "header:X-API-Key"})).unwrap());
    let query_key_auth: Arc<dyn Plugin> =
        Arc::new(KeyAuth::new(&json!({"key_location": "query:api_key"})).unwrap());
    let plugins = vec![external, header_key_auth, query_key_auth];
    let consumer_index = ConsumerIndex::new(&[]);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/multi-auth".to_string(),
    );
    ctx.headers.insert(
        "x-api-key".to_string(),
        "must-not-reach-backend".to_string(),
    );
    ctx.query_params
        .insert("api_key".to_string(), "must-not-reach-backend".to_string());

    let result =
        run_authentication_phase(AuthMode::Multi, &plugins, &mut ctx, &consumer_index).await;
    assert!(result.is_none(), "the earlier external auth should win");

    let mut backend_headers = ctx.headers.clone();
    for plugin in &plugins {
        assert!(matches!(
            plugin.before_proxy(&mut ctx, &mut backend_headers).await,
            PluginResult::Continue
        ));
    }

    assert!(!backend_headers.contains_key("x-api-key"));
    assert!(!ctx.query_params.contains_key("api_key"));
    assert_eq!(
        ctx.metadata
            .get("auth.strip_query_param.api_key")
            .map(String::as_str),
        Some("true")
    );
}

#[tokio::test]
async fn test_single_auth_missing_credentials_rejects_before_backend() {
    let key_auth: Arc<dyn Plugin> = Arc::new(KeyAuth::new(&json!({})).unwrap());
    let auth_plugins: Vec<Arc<dyn Plugin>> = vec![key_auth];
    let consumer_index = ConsumerIndex::new(&[]);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/key-auth".to_string(),
    );

    let result =
        run_authentication_phase(AuthMode::Single, &auth_plugins, &mut ctx, &consumer_index).await;

    let (status_code, body, headers) = result.expect("missing credentials should reject");
    assert_eq!(status_code, 401);
    assert_eq!(body, br#"{"error":"Authentication required"}"#);
    assert_eq!(
        headers.get("WWW-Authenticate").map(String::as_str),
        Some("ferrum-edge")
    );
    assert!(ctx.identified_consumer.is_none());
    assert!(ctx.authenticated_identity.is_none());
}

#[tokio::test]
async fn test_single_basic_auth_missing_credentials_uses_basic_challenge() {
    unsafe {
        std::env::set_var("FERRUM_BASIC_AUTH_HMAC_SECRET", BASIC_AUTH_TEST_SECRET);
    }
    let basic_auth: Arc<dyn Plugin> = Arc::new(BasicAuth::new(&json!({})).unwrap());
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/basic-auth".to_string(),
    );

    let result = run_authentication_phase(
        AuthMode::Single,
        &[basic_auth],
        &mut ctx,
        &ConsumerIndex::new(&[]),
    )
    .await;

    let (status, _body, headers) = result.expect("missing Basic credentials must reject");
    assert_eq!(status, 401);
    assert_eq!(
        headers.get("WWW-Authenticate").map(String::as_str),
        Some(r#"Basic realm="ferrum-edge", charset="UTF-8""#)
    );
}

#[tokio::test]
async fn test_multi_auth_missing_credentials_uses_first_available_challenge() {
    unsafe {
        std::env::set_var("FERRUM_BASIC_AUTH_HMAC_SECRET", BASIC_AUTH_TEST_SECRET);
    }
    let jwt: Arc<dyn Plugin> = Arc::new(JwtAuth::new(&json!({})).unwrap());
    let basic: Arc<dyn Plugin> = Arc::new(BasicAuth::new(&json!({})).unwrap());
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/mixed-auth".to_string(),
    );

    let result = run_authentication_phase(
        AuthMode::Multi,
        &[jwt, basic],
        &mut ctx,
        &ConsumerIndex::new(&[]),
    )
    .await;

    let (status, _body, headers) = result.expect("all-missing auth chain must reject");
    assert_eq!(status, 401);
    assert_eq!(
        headers.get("WWW-Authenticate").map(String::as_str),
        Some(r#"Basic realm="ferrum-edge", charset="UTF-8""#)
    );
}

#[tokio::test]
async fn test_single_auth_valid_basic_skips_earlier_jwt_scheme() {
    use base64::Engine;

    unsafe {
        std::env::set_var("FERRUM_BASIC_AUTH_HMAC_SECRET", BASIC_AUTH_TEST_SECRET);
    }
    let jwt: Arc<dyn Plugin> = Arc::new(JwtAuth::new(&json!({})).unwrap());
    let basic: Arc<dyn Plugin> = Arc::new(BasicAuth::new(&json!({})).unwrap());
    let auth_plugins = vec![jwt, basic];
    let consumer_index = ConsumerIndex::new(&[basic_auth_dispatch_consumer()]);
    let encoded = base64::engine::general_purpose::STANDARD.encode("alice:password");
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/mixed-auth".to_string(),
    );
    ctx.headers
        .insert("authorization".to_string(), format!("Basic {encoded}"));

    let result =
        run_authentication_phase(AuthMode::Single, &auth_plugins, &mut ctx, &consumer_index).await;

    assert!(result.is_none());
    assert_eq!(
        ctx.identified_consumer
            .as_ref()
            .map(|consumer| consumer.username.as_str()),
        Some("alice")
    );
}

#[tokio::test]
async fn test_single_auth_stops_before_later_reject_after_success() {
    let external: Arc<dyn Plugin> = Arc::new(ExternalIdentityAuth);
    let rejecting: Arc<dyn Plugin> = Arc::new(RejectingAuth {
        body: r#"{"error":"must not override success"}"#,
    });
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/mixed-auth".to_string(),
    );

    let result = run_authentication_phase(
        AuthMode::Single,
        &[external, rejecting],
        &mut ctx,
        &ConsumerIndex::new(&[]),
    )
    .await;

    assert!(result.is_none());
    assert_eq!(ctx.authenticated_identity.as_deref(), Some("external-user"));
}

#[tokio::test]
async fn test_single_auth_preserves_reject_from_plugin_that_sets_identity() {
    let plugin: Arc<dyn Plugin> = Arc::new(IdentityThenRejectAuth);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/mixed-auth".to_string(),
    );

    let result = run_authentication_phase(
        AuthMode::Single,
        &[plugin],
        &mut ctx,
        &ConsumerIndex::new(&[]),
    )
    .await;

    let (status, body, _headers) = result.expect("same-plugin rejection must remain terminal");
    assert_eq!(status, 403);
    assert_eq!(body, br#"{"error":"account disabled"}"#);
}

#[tokio::test]
async fn test_multi_auth_all_missing_credentials_rejects_before_backend() {
    let key_auth: Arc<dyn Plugin> = Arc::new(KeyAuth::new(&json!({})).unwrap());
    let rejecting: Arc<dyn Plugin> = Arc::new(
        KeyAuth::new(&json!({
            "key_location": "query:api_key"
        }))
        .unwrap(),
    );
    let auth_plugins: Vec<Arc<dyn Plugin>> = vec![key_auth, rejecting];
    let consumer_index = ConsumerIndex::new(&[]);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/key-auth".to_string(),
    );

    let result =
        run_authentication_phase(AuthMode::Multi, &auth_plugins, &mut ctx, &consumer_index).await;

    let (status_code, body, headers) = result.expect("all-missing multi-auth should reject");
    assert_eq!(status_code, 401);
    assert_eq!(body, br#"{"error":"Authentication required"}"#);
    assert_eq!(
        headers.get("WWW-Authenticate").map(String::as_str),
        Some("ferrum-edge")
    );
    assert!(ctx.identified_consumer.is_none());
    assert!(ctx.authenticated_identity.is_none());
}

#[tokio::test]
async fn test_multi_auth_preserves_specific_reject_when_surrounded_by_missing() {
    let missing_header: Arc<dyn Plugin> = Arc::new(KeyAuth::new(&json!({})).unwrap());
    let specific_reject: Arc<dyn Plugin> = Arc::new(RejectingAuth {
        body: r#"{"error":"Specific auth failure"}"#,
    });
    let missing_query: Arc<dyn Plugin> = Arc::new(
        KeyAuth::new(&json!({
            "key_location": "query:api_key"
        }))
        .unwrap(),
    );
    let auth_plugins: Vec<Arc<dyn Plugin>> = vec![missing_header, specific_reject, missing_query];
    let consumer_index = ConsumerIndex::new(&[]);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/key-auth".to_string(),
    );

    let result =
        run_authentication_phase(AuthMode::Multi, &auth_plugins, &mut ctx, &consumer_index).await;

    let (status_code, body, _headers) =
        result.expect("specific reject should win over generic missing fallback");
    assert_eq!(status_code, 401);
    assert_eq!(body, br#"{"error":"Specific auth failure"}"#);
    assert!(ctx.identified_consumer.is_none());
    assert!(ctx.authenticated_identity.is_none());
}

#[tokio::test]
async fn test_auth_rejection_merges_all_set_cookie_case_variants_deterministically() {
    let staged: Arc<dyn Plugin> = Arc::new(StagedCookieRejectingAuth);
    let selected: Arc<dyn Plugin> = Arc::new(MixedCaseCookieRejectingAuth);
    let auth_plugins = [staged, selected];
    let consumer_index = ConsumerIndex::new(&[]);
    let expected = "session=selected-upper; Path=/upper; HttpOnly\nupper_only=1; Path=/upper\nscoped=clear-root; Path=/\nscoped=clear-app; Path=/app\ndomain=selected; dOmAiN=.Example.COM; pAtH=/app\nhost_scope=selected; Domain=example.com; Path=/\nomitted=selected; Path=/\nduplicate=selected; Path=/ignored; PATH=/effective\nquoted=selected; Path=\"/quoted\"\nmalformed pair=selected; Path=/\nquoted_domain=selected; Domain=\".example.com\"; Path=/\ninvalid_path=selected; Path=\nvalue_space=selected ; Path=/\n name_space =selected; Path=/\nshared=1; Path=/\nlower_only=1; Path=/lower\nsession=selected-lower; Path=/lower; Secure; SameSite=Strict\nsession=staged; Path=/staged; HttpOnly\nSession=case-sensitive; Path=/case\nstaged_only=1; Path=/staged\ndomain=staged-other; Domain=api.example.com; Path=/app\nhost_scope=staged; Path=/\nmalformed pair=staged; Path=/\nquoted_domain=staged; Domain=\".example.com\"; Path=/";

    for _ in 0..32 {
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/mixed-cookie-rejection".to_string(),
        );
        let (status_code, body, headers) =
            run_authentication_phase(AuthMode::Multi, &auth_plugins, &mut ctx, &consumer_index)
                .await
                .expect("both auth attempts must reject");

        assert_eq!(status_code, 403);
        assert_eq!(body, br#"{"error":"mixed-case rejection"}"#);
        assert_eq!(
            headers.get("X-Rejection").map(String::as_str),
            Some("selected")
        );
        assert_eq!(
            headers.get("set-cookie").map(String::as_str),
            Some(expected)
        );
        assert_eq!(
            headers
                .keys()
                .filter(|name| name.eq_ignore_ascii_case("set-cookie"))
                .count(),
            1
        );
        assert_eq!(
            headers["set-cookie"]
                .split('\n')
                .filter(|cookie| *cookie == "shared=1; Path=/")
                .count(),
            1,
            "identical cookie lines must not multiply"
        );
        assert!(
            !ctx.metadata.contains_key("auth.rejection_set_cookie"),
            "the staged cookies must be consumed exactly once"
        );
    }
}

#[tokio::test]
async fn test_auth_rejection_cookie_storage_key_preserves_extended_scopes() {
    let staged: Arc<dyn Plugin> = Arc::new(ScopedCookieStagingAuth {
        cookies: "non_ldh=staged; Domain=foo_bar.example; Path=/\nip_literal=staged; Domain=[0:0:0:0:0:0:0:1]; Path=/\ninvalid_ip=staged; Domain=[not-an-ip]; Path=/\npartitioned_same=staged; Secure; pArTiTiOnEd; Path=/\npartitioned_split=staged; Secure; Path=/\npartitioned_reverse=staged; Secure; PARTITIONED; Path=/\ndot_scope=staged; Path=/\ntrailing_dot=staged; Path=/\ntrailing_dot_prior=staged; Domain=example.com; Path=/",
    });
    let selected: Arc<dyn Plugin> = Arc::new(ScopedCookieSelectedAuth {
        cookies: "non_ldh=selected; Domain=foo_bar.example; Path=/\nip_literal=selected; Domain=[::1]; Path=/\ninvalid_ip=selected; Domain=[not-an-ip]; Path=/\npartitioned_same=selected; Secure; Partitioned; Path=/\npartitioned_split=selected; Secure; Partitioned; Path=/\npartitioned_reverse=selected; Secure; Path=/\ndot_scope=selected; Domain=example.com; Path=/\ntrailing_dot=selected; Domain=example.com.; Path=/\ntrailing_dot_prior=selected; Domain=example.com; Domain=other.example.; Path=/",
    });
    let auth_plugins = [staged, selected];
    let consumer_index = ConsumerIndex::new(&[]);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/cookie-scope".to_string(),
    );

    let (_, _, headers) =
        run_authentication_phase(AuthMode::Multi, &auth_plugins, &mut ctx, &consumer_index)
            .await
            .expect("both auth attempts must reject");

    assert_eq!(
        headers.get("set-cookie").map(String::as_str),
        Some(
            "non_ldh=selected; Domain=foo_bar.example; Path=/\nip_literal=selected; Domain=[::1]; Path=/\ninvalid_ip=selected; Domain=[not-an-ip]; Path=/\npartitioned_same=selected; Secure; Partitioned; Path=/\npartitioned_split=selected; Secure; Partitioned; Path=/\npartitioned_reverse=selected; Secure; Path=/\ndot_scope=selected; Domain=example.com; Path=/\ntrailing_dot=selected; Domain=example.com.; Path=/\ntrailing_dot_prior=selected; Domain=example.com; Domain=other.example.; Path=/\ninvalid_ip=staged; Domain=[not-an-ip]; Path=/\npartitioned_split=staged; Secure; Path=/\npartitioned_reverse=staged; Secure; PARTITIONED; Path=/\ndot_scope=staged; Path=/"
        )
    );
}

#[tokio::test]
async fn test_auth_rejection_cookie_storage_key_preserves_host_only_state() {
    let staged: Arc<dyn Plugin> = Arc::new(ScopedCookieStagingAuth {
        cookies: "session=staged; Path=/",
    });
    let selected: Arc<dyn Plugin> = Arc::new(ScopedCookieSelectedAuth {
        cookies: "session=selected; Domain=example.com; Path=/",
    });
    let auth_plugins = [staged, selected];
    let consumer_index = ConsumerIndex::new(&[]);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/cookie-scope".to_string(),
    );
    let (_, _, headers) =
        run_authentication_phase(AuthMode::Multi, &auth_plugins, &mut ctx, &consumer_index)
            .await
            .expect("both auth attempts must reject");

    assert_eq!(
        headers.get("set-cookie").map(String::as_str),
        Some("session=selected; Domain=example.com; Path=/\nsession=staged; Path=/")
    );
}

#[tokio::test]
async fn test_auth_rejection_cookie_storage_key_matches_user_agent_value_parsing() {
    let staged: Arc<dyn Plugin> = Arc::new(ScopedCookieStagingAuth {
        cookies: "space=staged value; Path=/\ncomma=staged,value; Path=/\nquote=staged\"value; Path=/\nbackslash=staged\\value; Path=/\nunbalanced=staged; Path=/\ncontrol=staged; Path=/\ncarriage=staged; Path=/\ntab=staged; Path=/\ndel=staged; Path=/\npath_control=staged; Path=/",
    });
    let selected: Arc<dyn Plugin> = Arc::new(ScopedCookieSelectedAuth {
        cookies: "space=selected value; Path=/\ncomma=selected,value; Path=/\nquote=selected\"value; Path=/\nbackslash=selected\\value; Path=/\nunbalanced=\"selected; Path=/\ncontrol=selected\u{001f}value; Path=/\ncarriage=selected\rvalue; Path=/\ntab=selected\tvalue; Path=/\ndel=selected\u{007f}value; Path=/\npath_control=selected; Path=/app\rignored",
    });
    let auth_plugins = [staged, selected];
    let consumer_index = ConsumerIndex::new(&[]);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/cookie-scope".to_string(),
    );

    let (_, _, headers) =
        run_authentication_phase(AuthMode::Multi, &auth_plugins, &mut ctx, &consumer_index)
            .await
            .expect("both auth attempts must reject");

    assert_eq!(
        headers.get("set-cookie").map(String::as_str),
        Some(
            "space=selected value; Path=/\ncomma=selected,value; Path=/\nquote=selected\"value; Path=/\nbackslash=selected\\value; Path=/\nunbalanced=\"selected; Path=/\ncontrol=selected\u{001f}value; Path=/\ncarriage=selected\rvalue; Path=/\ntab=selected\tvalue; Path=/\ndel=selected\u{007f}value; Path=/\npath_control=selected; Path=/app\rignored\ncontrol=staged; Path=/\ncarriage=staged; Path=/\ntab=staged; Path=/\ndel=staged; Path=/\npath_control=staged; Path=/"
        )
    );
}

#[tokio::test]
async fn test_auth_rejection_cookie_storage_key_uses_non_root_default_path_and_cookie_ows() {
    let staged: Arc<dyn Plugin> = Arc::new(ScopedCookieStagingAuth {
        cookies: "same=staged; Path=/app\nroot=staged; Path=/\nslash=staged; Path=/app/\nnbsp=staged; Path=/app\nbare=staged; Path=/app",
    });
    let selected: Arc<dyn Plugin> = Arc::new(ScopedCookieSelectedAuth {
        cookies: "same=selected\nroot=selected\nslash=selected\nnbsp=selected; Path=\u{00a0}/ignored\nbare=selected; Path=/other; Path",
    });
    let auth_plugins = [staged, selected];
    let consumer_index = ConsumerIndex::new(&[]);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/app/login".to_string(),
    );

    let (_, _, headers) =
        run_authentication_phase(AuthMode::Multi, &auth_plugins, &mut ctx, &consumer_index)
            .await
            .expect("both auth attempts must reject");

    assert_eq!(
        headers.get("set-cookie").map(String::as_str),
        Some(
            "same=selected\nroot=selected\nslash=selected\nnbsp=selected; Path=\u{00a0}/ignored\nbare=selected; Path=/other; Path\nroot=staged; Path=/\nslash=staged; Path=/app/"
        )
    );
}

#[test]
fn test_request_context_effective_identity_prefers_consumer_then_external_identity() {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/jwks".to_string(),
    );
    assert_eq!(ctx.effective_identity(), None);

    ctx.authenticated_identity = Some("external-user".to_string());
    assert_eq!(ctx.effective_identity(), Some("external-user"));

    ctx.authenticated_identity = Some("   \t".to_string());
    assert_eq!(ctx.effective_identity(), None);

    ctx.authenticated_identity = Some("external-user".to_string());

    ctx.identified_consumer = Some(Arc::new(Consumer {
        id: "consumer-1".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: "mapped-consumer".to_string(),
        custom_id: None,
        credentials: HashMap::new(),
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }));
    assert_eq!(ctx.effective_identity(), Some("mapped-consumer"));
}

#[test]
fn test_request_context_backend_consumer_username_prefers_consumer_then_header_then_identity() {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/jwks".to_string(),
    );
    assert_eq!(ctx.backend_consumer_username(), None);

    ctx.authenticated_identity = Some("external-user".to_string());
    assert_eq!(ctx.backend_consumer_username(), Some("external-user"));

    ctx.authenticated_identity_header = Some("user@example.com".to_string());
    assert_eq!(ctx.backend_consumer_username(), Some("user@example.com"));

    ctx.authenticated_identity_header = Some("   ".to_string());
    assert_eq!(ctx.backend_consumer_username(), Some("external-user"));

    ctx.identified_consumer = Some(Arc::new(Consumer {
        id: "consumer-1".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: "mapped-consumer".to_string(),
        custom_id: Some("custom-123".to_string()),
        credentials: HashMap::new(),
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }));
    assert_eq!(ctx.backend_consumer_username(), Some("mapped-consumer"));
    assert_eq!(ctx.backend_consumer_custom_id(), Some("custom-123"));
}

#[test]
fn test_map_http_reject_status_to_grpc_status_uses_semantic_codes() {
    assert_eq!(
        map_http_reject_status_to_grpc_status(StatusCode::UNAUTHORIZED),
        grpc_status::UNAUTHENTICATED
    );
    assert_eq!(
        map_http_reject_status_to_grpc_status(StatusCode::FORBIDDEN),
        grpc_status::PERMISSION_DENIED
    );
    assert_eq!(
        map_http_reject_status_to_grpc_status(StatusCode::TOO_MANY_REQUESTS),
        grpc_status::RESOURCE_EXHAUSTED
    );
    assert_eq!(
        map_http_reject_status_to_grpc_status(StatusCode::BAD_GATEWAY),
        grpc_status::UNAVAILABLE
    );
}

#[test]
fn test_extract_grpc_reject_message_prefers_json_error_fields() {
    let body = br#"{"error":"Rate limit exceeded","details":"retry later"}"#;
    assert_eq!(
        extract_grpc_reject_message(body).as_deref(),
        Some("Rate limit exceeded")
    );
}

#[test]
fn test_normalize_reject_response_converts_grpc_requests_to_trailers_only_errors() {
    let mut headers = HashMap::new();
    headers.insert("x-ratelimit-limit".to_string(), "5".to_string());

    let normalized = normalize_reject_response(
        StatusCode::TOO_MANY_REQUESTS,
        br#"{"error":"Rate limit exceeded"}"#,
        &headers,
        true,
    );

    assert_eq!(normalized.http_status, StatusCode::OK);
    assert!(normalized.body.is_empty());
    assert_eq!(
        normalized.grpc_status,
        Some(grpc_status::RESOURCE_EXHAUSTED)
    );
    assert_eq!(
        normalized.grpc_message.as_deref(),
        Some("Rate limit exceeded")
    );
    assert_eq!(
        normalized.headers.get("content-type").map(|s| s.as_str()),
        Some("application/grpc")
    );
    assert_eq!(
        normalized.headers.get("grpc-status").map(|s| s.as_str()),
        Some("8")
    );
    assert_eq!(
        normalized
            .headers
            .get("x-ratelimit-limit")
            .map(|s| s.as_str()),
        Some("5")
    );
}

#[test]
fn test_insert_grpc_error_metadata_sanitizes_message() {
    let mut metadata = HashMap::new();
    insert_grpc_error_metadata(
        &mut metadata,
        grpc_status::UNAVAILABLE,
        "backend unavailable\nretry later",
    );
    assert_eq!(metadata.get("grpc_status").map(|s| s.as_str()), Some("14"));
    assert_eq!(
        metadata.get("grpc_message").map(|s| s.as_str()),
        Some("backend unavailable retry later")
    );
}

#[test]
fn test_direct_http2_pool_requires_http2_without_retries_or_request_buffering() {
    assert!(can_use_direct_http2_pool(true, false, false));
    assert!(!can_use_direct_http2_pool(false, false, false));
    assert!(!can_use_direct_http2_pool(true, true, false));
    assert!(!can_use_direct_http2_pool(true, false, true));
}

#[test]
fn test_direct_http2_pool_dispatch_disabled_by_body_limits() {
    assert!(can_dispatch_direct_http2_pool(true, false, false, 0, 0));
    assert!(!can_dispatch_direct_http2_pool(true, false, false, 1, 0));
    assert!(!can_dispatch_direct_http2_pool(true, false, false, 0, 1));
    assert!(!can_dispatch_direct_http2_pool(true, true, false, 0, 0));
}

#[test]
fn test_request_may_have_body_uses_method_and_body_headers() {
    let no_headers = HashMap::new();
    for method in ["GET", "HEAD", "OPTIONS"] {
        assert!(!request_may_have_body(method, &no_headers));
    }
    for method in ["DELETE", "PATCH", "POST", "PUT"] {
        assert!(request_may_have_body(method, &no_headers));
    }

    let content_length_zero = HashMap::from([("content-length".to_string(), "0".to_string())]);
    let chunked = HashMap::from([("transfer-encoding".to_string(), "chunked".to_string())]);
    for method in ["GET", "HEAD", "OPTIONS"] {
        assert!(request_may_have_body(method, &content_length_zero));
        assert!(request_may_have_body(method, &chunked));
    }
}

#[tokio::test]
async fn test_apply_request_body_plugins_preserves_plugin_order() {
    let first: Arc<dyn Plugin> = Arc::new(BodySuffixPlugin { suffix: "-first" });
    let second: Arc<dyn Plugin> = Arc::new(BodySuffixPlugin { suffix: "-second" });
    let headers = HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    let transformed =
        apply_request_body_plugins(&[first, second], &headers, b"body".to_vec()).await;
    assert_eq!(transformed, b"body-first-second");
}

#[tokio::test]
async fn test_single_auth_allows_mesh_request_auth_permissive_missing_token() {
    let mesh_request_auth: Arc<dyn Plugin> = Arc::new(PermissiveMissingMeshAuth);
    let auth_plugins: Vec<Arc<dyn Plugin>> = vec![mesh_request_auth];
    let consumer_index = ConsumerIndex::new(&[]);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/mesh".to_string(),
    );

    let result =
        run_authentication_phase(AuthMode::Single, &auth_plugins, &mut ctx, &consumer_index).await;

    assert!(result.is_none());
    assert!(ctx.identified_consumer.is_none());
    assert!(ctx.authenticated_identity.is_none());
}

#[tokio::test]
async fn test_multi_auth_clears_reject_when_later_plugin_authenticates() {
    // Multi-auth first-success-wins: when a later plugin succeeds, the earlier
    // reject is cleared and the request is allowed through.
    let specific_reject: Arc<dyn Plugin> = Arc::new(RejectingAuth {
        body: r#"{"error":"Invalid JWT"}"#,
    });
    let external: Arc<dyn Plugin> = Arc::new(ExternalIdentityAuth);
    let auth_plugins: Vec<Arc<dyn Plugin>> = vec![specific_reject, external];
    let consumer_index = ConsumerIndex::new(&[]);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/jwks".to_string(),
    );

    let result =
        run_authentication_phase(AuthMode::Multi, &auth_plugins, &mut ctx, &consumer_index).await;

    assert!(
        result.is_none(),
        "multi-auth first-success-wins: later plugin authenticated so request should pass"
    );
    assert_eq!(ctx.authenticated_identity.as_deref(), Some("external-user"));
}

#[tokio::test]
async fn test_multi_auth_allows_mesh_permissive_missing_token() {
    let mesh_request_auth: Arc<dyn Plugin> = Arc::new(PermissiveMissingMeshAuth);
    let auth_plugins: Vec<Arc<dyn Plugin>> = vec![mesh_request_auth];
    let consumer_index = ConsumerIndex::new(&[]);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/mesh".to_string(),
    );

    let result =
        run_authentication_phase(AuthMode::Multi, &auth_plugins, &mut ctx, &consumer_index).await;

    assert!(
        result.is_none(),
        "mesh permissive missing token should pass in multi mode when no other plugin rejects"
    );
    assert!(ctx.identified_consumer.is_none());
    assert!(ctx.authenticated_identity.is_none());
}

#[tokio::test]
async fn test_multi_auth_rejects_when_mandatory_plugin_rejects_despite_mesh_permissive_marker() {
    let rejecting_auth: Arc<dyn Plugin> = Arc::new(RejectingAuth {
        body: r#"{"error":"API key required"}"#,
    });
    let mesh_request_auth: Arc<dyn Plugin> = Arc::new(PermissiveMissingMeshAuth);
    let auth_plugins: Vec<Arc<dyn Plugin>> = vec![rejecting_auth, mesh_request_auth];
    let consumer_index = ConsumerIndex::new(&[]);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/mesh".to_string(),
    );

    let result =
        run_authentication_phase(AuthMode::Multi, &auth_plugins, &mut ctx, &consumer_index).await;

    assert!(
        result.is_some(),
        "mesh permissive marker must not bypass another plugin's rejection in Multi mode"
    );
    let (status, body, _headers) = result.unwrap();
    assert_eq!(status, 401);
    assert_eq!(
        String::from_utf8_lossy(&body),
        r#"{"error":"API key required"}"#
    );
}

#[tokio::test]
async fn test_single_auth_rejects_when_mesh_marker_present_with_other_missing_auth() {
    let mesh_request_auth: Arc<dyn Plugin> = Arc::new(PermissiveMissingMeshAuth);
    let missing_auth: Arc<dyn Plugin> = Arc::new(MissingCredentialContinueAuth);
    let auth_plugins: Vec<Arc<dyn Plugin>> = vec![mesh_request_auth, missing_auth];
    let consumer_index = ConsumerIndex::new(&[]);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/mesh".to_string(),
    );

    let result =
        run_authentication_phase(AuthMode::Single, &auth_plugins, &mut ctx, &consumer_index).await;

    assert!(result.is_some());
    let (status, body, _headers) = result.unwrap();
    assert_eq!(status, 401);
    assert_eq!(
        String::from_utf8_lossy(&body),
        r#"{"error":"Authentication required"}"#
    );
}

#[tokio::test]
async fn test_multi_auth_rejects_when_mesh_marker_present_with_other_missing_auth() {
    let mesh_request_auth: Arc<dyn Plugin> = Arc::new(PermissiveMissingMeshAuth);
    let missing_auth: Arc<dyn Plugin> = Arc::new(MissingCredentialContinueAuth);
    let auth_plugins: Vec<Arc<dyn Plugin>> = vec![mesh_request_auth, missing_auth];
    let consumer_index = ConsumerIndex::new(&[]);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/mesh".to_string(),
    );

    let result =
        run_authentication_phase(AuthMode::Multi, &auth_plugins, &mut ctx, &consumer_index).await;

    assert!(result.is_some());
    let (status, body, _headers) = result.unwrap();
    assert_eq!(status, 401);
    assert_eq!(
        String::from_utf8_lossy(&body),
        r#"{"error":"Authentication required"}"#
    );
}

#[tokio::test]
async fn test_single_auth_rejects_when_mandatory_plugin_rejects_despite_mesh_permissive_marker() {
    let rejecting_auth: Arc<dyn Plugin> = Arc::new(RejectingAuth {
        body: r#"{"error":"API key required"}"#,
    });
    let mesh_request_auth: Arc<dyn Plugin> = Arc::new(PermissiveMissingMeshAuth);
    let auth_plugins: Vec<Arc<dyn Plugin>> = vec![rejecting_auth, mesh_request_auth];
    let consumer_index = ConsumerIndex::new(&[]);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/mesh".to_string(),
    );

    let result =
        run_authentication_phase(AuthMode::Single, &auth_plugins, &mut ctx, &consumer_index).await;

    assert!(
        result.is_some(),
        "mesh permissive marker must not bypass another plugin's rejection in Single mode"
    );
    let (status, body, _headers) = result.unwrap();
    assert_eq!(status, 401);
    assert_eq!(
        String::from_utf8_lossy(&body),
        r#"{"error":"API key required"}"#
    );
}
