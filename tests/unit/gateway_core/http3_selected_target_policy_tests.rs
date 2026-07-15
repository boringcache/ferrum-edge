#[test]
fn h3_frontend_caps_retry_before_retry_dependent_decisions() {
    let source = include_str!("../../../src/http3/server.rs");
    let selection = source
        .find("let mut selection = crate::proxy::backend_dispatch::select_upstream_target(")
        .expect("H3 selected-target lookup must remain present");
    let after_selection = &source[selection..];

    let cap = after_selection
        .find("let mut selected_base_proxy =")
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
    assert!(
        websocket_args.contains("backend_path_is_policy_bound,"),
        "H3 WebSocket retries must receive the backend-path policy binding"
    );

    let websocket_source = include_str!("../../../src/http3/websocket.rs");
    assert!(
        websocket_source.contains("retry_target_preserves_backend_path("),
        "H3 WebSocket target rotation must preserve the authorized backend path"
    );
    assert!(
        websocket_source.contains("if retry_admitted_by_cb && !retry_path_mismatch"),
        "H3 WebSocket path mismatches must abort rather than retry the failed target"
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
    let backend_path_plugins = source
        .find("let backend_path_plugins = plugin_cache_view.backend_path_plugins();")
        .expect("H3 must load the prefiltered backend-path policy list");
    let selection = source
        .find("let mut selection = crate::proxy::backend_dispatch::select_upstream_target(")
        .expect("H3 selected-target lookup must remain present");
    assert!(
        backend_path_plugins < selection,
        "H3 must load the cached backend-path plugin view before target selection"
    );
    let after_selection = &source[selection..];
    let path_policy = after_selection
        .find("if backend_path_is_policy_bound {")
        .expect("H3 must enforce backend-path policy after selecting a target");
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
    assert!(
        source.contains("h3_plugin_protocol_for_request(http_flavor, grpc_web_request)"),
        "H3 gRPC-Web requests must load the gRPC plugin policy chain"
    );
    assert!(
        policy_block.contains("grpc_web_response_content_type.as_deref()"),
        "H3 backend-path rejects must retain the client's gRPC-Web response encoding"
    );
    assert!(
        source.contains("backend_dispatch::upstream_selection_hash_key("),
        "H3 must re-evaluate header-hash routing after deferred header mutations"
    );
    assert!(
        policy_block.contains("BackendPathPolicyPhase::Preview")
            && policy_block.contains("BackendPathPolicyPhase::Enforce"),
        "H3 must preview access before deferred routing and charge final policy only after it settles"
    );
    assert!(
        source.contains("BackendPathBeforeProxyPass::RemainingDeferred"),
        "H3 must keep remaining side-effect hooks behind any required reauthorization"
    );
    let native_retry = source
        .find("// Resolve and validate the retry target before charging this")
        .expect("native H3 retry path must preflight the candidate path");
    let after_native_retry = &source[native_retry..];
    let native_mismatch = after_native_retry
        .find("Aborting H3 retry because the candidate would change")
        .expect("native H3 retry must reject a path-changing candidate");
    let native_intermediate_record = after_native_retry
        .find("record_h3_backend_admission_outcome(")
        .expect("native H3 retry intermediate accounting must remain present");
    assert!(
        native_mismatch < native_intermediate_record
            && after_native_retry[native_mismatch..native_intermediate_record].contains("break;"),
        "native H3 path mismatch must abort before intermediate retry accounting"
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
    assert!(
        cross_protocol.contains("CrossProtocolRetryTarget::BackendPathMismatch"),
        "cross-protocol retries must distinguish a path mismatch from no target rotation"
    );
    let grpc_retry = cross_protocol
        .rfind("let retry_target = select_next_cross_protocol_retry_target(")
        .expect("cross-protocol gRPC retry selection must remain present");
    let after_grpc_retry = &cross_protocol[grpc_retry..];
    let mismatch = after_grpc_retry
        .find("CrossProtocolRetryTarget::BackendPathMismatch")
        .expect("cross-protocol gRPC retry must inspect the mismatch result");
    let failure_record = after_grpc_retry
        .find("let retry_error_class =")
        .expect("cross-protocol gRPC retry failure recording must remain present");
    assert!(
        mismatch < failure_record && after_grpc_retry[mismatch..failure_record].contains("break;"),
        "cross-protocol gRPC retries must abort before recording an intermediate retry attempt"
    );
}

#[test]
fn h3_grpc_web_initial_before_proxy_reject_uses_grpc_web_shape() {
    let source = include_str!("../../../src/http3/server.rs");
    let start = source
        .find("// before_proxy hooks — only clone headers")
        .expect("H3 initial before_proxy phase must remain present");
    let end = source[start..]
        .find("// Reserved consumer-identity headers are gateway-asserted")
        .map(|offset| start + offset)
        .expect("H3 initial before_proxy phase must have a bounded source block");
    let before_proxy = &source[start..end];

    assert!(
        before_proxy
            .matches("matches!(http_flavor, HttpFlavor::Grpc) || grpc_web_request")
            .count()
            >= 2,
        "both H3 header-handling branches must normalize gRPC-Web plugin rejects as gRPC"
    );
    assert!(
        before_proxy.matches("send_h3_grpc_web_reject(").count() >= 2,
        "both H3 header-handling branches must emit the gRPC-Web trailer-frame reject shape"
    );
}

#[test]
fn h3_deferred_hooks_cannot_spoof_backend_consumer_identity() {
    let source = include_str!("../../../src/http3/server.rs");
    let routing_hook = source
        .rfind("BackendPathBeforeProxyPass::RoutingHeaderDeferred")
        .expect("H3 deferred routing-header hook must remain present");
    let after_routing_hook = &source[routing_hook..];
    let refresh = after_routing_hook
        .find("refresh_backend_consumer_identity_headers(&ctx, &mut proxy_headers)")
        .expect("H3 must refresh identity after deferred routing hooks");
    let hash_selection = after_routing_hook
        .find("upstream_selection_hash_key(")
        .expect("H3 deferred headers must still drive target reselection");
    assert!(
        refresh < hash_selection,
        "H3 must restore gateway identity before header-hash target selection"
    );

    let remaining_hook = source
        .rfind("BackendPathBeforeProxyPass::RemainingDeferred")
        .expect("H3 remaining deferred hook pass must remain present");
    assert!(
        source[remaining_hook..]
            .contains("refresh_backend_consumer_identity_headers(&ctx, &mut proxy_headers)"),
        "H3 must restore gateway identity after every deferred hook pass"
    );
}
