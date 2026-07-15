#[test]
fn h3_frontend_caps_retry_before_retry_dependent_decisions() {
    let source = include_str!("../../../src/http3/server.rs");
    let selection = source
        .find("let selection = crate::proxy::backend_dispatch::select_upstream_target(")
        .expect("H3 selected-target lookup must remain present");
    let after_selection = &source[selection..];

    let cap = after_selection
        .find("let selected_base_proxy =")
        .expect("H3 frontend must cap retry policy by selected target");
    let effective = after_selection
        .find("let effective_proxy = crate::proxy::resolve_effective_proxy_for_target(")
        .expect("H3 frontend must resolve selected-target effective proxy");
    assert!(
        after_selection[effective..].contains("&selected_base_proxy"),
        "H3 effective proxy resolution must use the retry-capped selected base proxy"
    );
    let has_retry = after_selection
        .find("let has_retry = match http_flavor")
        .expect("retry-dependent buffering decision must remain present");
    let native_h3_decision = after_selection
        .find("let backend_supports_native_h3 =")
        .expect("native-H3 dispatch decision must remain present");
    let circuit_breaker = after_selection
        .find("check_circuit_breaker(")
        .expect("H3 circuit-breaker check must remain present");

    assert!(
        cap < has_retry,
        "retry cap must run before retry-dependent buffering/native-H3 gates"
    );
    assert!(
        effective < native_h3_decision,
        "effective proxy must be resolved before native-H3 capability decisions"
    );
    assert!(
        effective < circuit_breaker,
        "effective proxy must be resolved before circuit-breaker/admission dispatch"
    );
}

#[test]
fn h3_plain_and_grpc_bridges_keep_unresolved_base_proxy_for_retries() {
    let source = include_str!("../../../src/http3/server.rs");
    let bridge_call = source
        .find(
            "crate::http3::cross_protocol::run(crate::http3::cross_protocol::CrossProtocolRequest",
        )
        .expect("H3 cross-protocol bridge call must remain present");
    let bridge = &source[bridge_call..];
    // Only Plain and Grpc reach this bridge (WebSocket returns via its
    // dedicated bridge earlier), and both resolve the effective proxy per
    // attempt inside their dispatch loops — so the capped, UNRESOLVED base
    // proxy must be passed unconditionally, with no flavor-forked fallback to
    // the first target's effective proxy.
    let proxy_field = bridge
        .find("proxy: selected_base_proxy.as_ref(),")
        .expect("H3 plain/gRPC bridge must pass the capped unresolved base proxy unconditionally");
    let stream_field = bridge
        .find("stream: &mut stream,")
        .expect("H3 cross-protocol request literal must remain present");
    assert!(
        proxy_field < stream_field,
        "the base-proxy field must belong to this CrossProtocolRequest literal"
    );
    assert!(
        !bridge[..stream_field].contains("proxy: if matches!"),
        "the flavor-forked proxy selection was dead code (WebSocket never reaches this bridge); \
         do not reintroduce it"
    );
}

#[test]
fn h3_native_retry_loop_resolves_effective_proxy_per_attempt() {
    let source = include_str!("../../../src/http3/server.rs");
    let retry_loop = source
        .find(") = if let Some(retry_config) = &proxy.retry {")
        .expect("buffered native-H3 retry loop must remain present");
    let loop_src = &source[retry_loop..];

    // Initial attempt: resolve from the retry-capped BASE proxy (never the
    // first target's effective proxy) before dispatching.
    let initial_resolve = loop_src
        .find("let attempt_dispatch_proxy = crate::proxy::resolve_effective_proxy_for_target(")
        .expect("native-H3 retry loop must resolve the attempt dispatch proxy");
    assert!(
        loop_src[initial_resolve..].contains("&selected_base_proxy"),
        "per-attempt resolution must feed from the retry-capped base proxy"
    );
    let initial_dispatch = loop_src
        .find("proxy_to_backend_h3(")
        .expect("buffered native-H3 dispatch must remain present");
    assert!(
        initial_resolve < initial_dispatch,
        "the initial native-H3 attempt must dispatch with the resolved attempt proxy"
    );
    assert!(
        loop_src[initial_dispatch..].contains("attempt_dispatch_proxy.as_ref(),"),
        "proxy_to_backend_h3 must receive the per-attempt resolved proxy"
    );

    // Rotated attempt: a rotation can cross from the SD fallback into a policy
    // port with its own per-port override (TLS/SNI/connectTimeout), so the
    // loop must RE-resolve after `select_next_retry_target` and before the
    // retried dispatch.
    let rotation = loop_src
        .find("select_next_retry_target(")
        .expect("native-H3 retry rotation must remain present");
    let re_resolve = loop_src[rotation..]
        .find("let attempt_dispatch_proxy = crate::proxy::resolve_effective_proxy_for_target(")
        .expect("rotated native-H3 retry attempts must re-resolve the effective proxy");
    let rotated_dispatch = loop_src[rotation..]
        .find("result = proxy_to_backend_h3(")
        .expect("rotated native-H3 dispatch must remain present");
    assert!(
        re_resolve < rotated_dispatch,
        "the rotated attempt must re-resolve the effective proxy before dispatching"
    );
}

#[test]
fn h3_frontend_exposes_retry_capped_base_proxy_to_plugins() {
    // H1/H2 parity: `handle_proxy_request_inner` assigns `ctx.matched_proxy`
    // the retry-capped BASE proxy (right after `cap_proxy_retry_for_target`),
    // so plugins/logging must not see per-port TLS/timeout overrides baked
    // into the proxy on the H3 frontend only.
    let source = include_str!("../../../src/http3/server.rs");
    assert!(
        source.contains("ctx.matched_proxy = Some(Arc::clone(&selected_base_proxy));"),
        "H3 must expose the retry-capped base proxy via ctx.matched_proxy (H1/H2 parity)"
    );
}

#[test]
fn h3_websocket_bridge_keeps_unresolved_base_proxy_for_retries() {
    let source = include_str!("../../../src/http3/server.rs");
    let websocket_call = source
        .find("crate::http3::websocket::handle_h3_websocket(")
        .expect("H3 WebSocket bridge call must remain present");
    let websocket_args = &source[websocket_call..];
    let proxy_arg = websocket_args
        .find("Arc::clone(&selected_base_proxy)")
        .expect("H3 WebSocket bridge must receive the capped unresolved base proxy");
    let effective_proxy_arg = websocket_args
        .find("\n            proxy,")
        .unwrap_or(usize::MAX);

    assert!(
        proxy_arg < effective_proxy_arg,
        "H3 WebSocket bridge must not inherit the first target's effective proxy"
    );
}

#[test]
fn h3_grpc_streaming_bridge_keeps_unresolved_base_proxy_for_selected_target() {
    let source = include_str!("../../../src/http3/server.rs");
    let streaming_call = source
        .find("crate::http3::cross_protocol::dispatch_grpc_streaming(")
        .expect("H3 streaming gRPC bridge call must remain present");
    let streaming_args = &source[streaming_call..];
    let base_proxy_arg = streaming_args
        .find("&selected_base_proxy")
        .expect("H3 streaming gRPC bridge must receive the capped unresolved base proxy");
    let effective_proxy_arg = streaming_args
        .find("\n                &proxy,")
        .unwrap_or(usize::MAX);

    assert!(
        base_proxy_arg < effective_proxy_arg,
        "H3 streaming gRPC bridge must not inherit the first target's effective proxy"
    );
}

#[test]
fn h3_backend_path_policy_runs_after_target_selection_and_before_dispatch() {
    let source = include_str!("../../../src/http3/server.rs");
    let selection = source
        .find("let selection = crate::proxy::backend_dispatch::select_upstream_target(")
        .expect("H3 selected-target lookup must remain present");
    let after_selection = &source[selection..];
    let path_policy = after_selection
        .find("let backend_path_plugins = plugin_cache_view.backend_path_plugins();")
        .expect("H3 must load the prefiltered backend-path policy list");
    let circuit_breaker = after_selection
        .find("check_circuit_breaker(")
        .expect("H3 circuit-breaker check must remain present");
    assert!(
        path_policy < circuit_breaker,
        "backend-effective path policy must run before circuit breaking or backend dispatch"
    );

    let policy_block = &after_selection[path_policy..circuit_breaker];
    assert!(
        policy_block.contains("crate::proxy::build_backend_effective_path("),
        "H3 policy must use the shared backend URL path assembler"
    );
    assert!(
        policy_block.contains("target.path.as_deref()"),
        "H3 policy must include the initially selected target path"
    );
    assert!(
        policy_block.contains("run_h3_backend_path_plugins_or_send_reject("),
        "H3 policy rejections must be emitted before dispatch"
    );

    let cross_protocol = include_str!("../../../src/http3/cross_protocol.rs");
    let retry_policy = cross_protocol
        .find("retry_target_preserves_backend_path(")
        .expect("cross-protocol H3 retry must retain the authorized target path");
    let retry_url = cross_protocol
        .find("let next_url = crate::proxy::build_backend_url_with_target(")
        .expect("cross-protocol retry URL reconstruction must remain present");
    assert!(
        retry_policy < retry_url,
        "retry target path policy must run before rebuilding the backend URL"
    );
}
