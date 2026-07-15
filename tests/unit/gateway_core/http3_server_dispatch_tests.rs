#[test]
fn h3_native_mesh_refusal_screens_plain_and_grpc_before_dispatch() {
    let src = include_str!("../../../src/http3/server.rs");
    let native_gate = src
        .find("let native_h3_direct_dispatch = use_native_h3_pool || use_native_h3_grpc;")
        .expect("native H3 direct-dispatch gate must remain explicit");
    let after_gate = &src[native_gate..];
    let refusal = after_gate
        .find("direct_http_mesh_transport_refusal(")
        .expect("native H3 dispatch must screen mesh transport refusal");
    let native_grpc = after_gate
        .find("if use_native_h3_grpc")
        .expect("native H3 gRPC dispatch branch must remain present");
    let native_plain_bridge_bypass = after_gate
        .find("if !use_native_h3_pool")
        .expect("native plain H3 bridge-bypass branch must remain present");

    assert!(
        refusal < native_grpc,
        "mesh-transport-tagged gRPC targets must fail closed before native H3 gRPC dispatch can dial the QUIC pool"
    );
    assert!(
        refusal < native_plain_bridge_bypass,
        "mesh-transport-tagged plain targets must fail closed before native H3 plain dispatch can bypass the bridge"
    );
}

#[test]
fn h3_final_body_rejects_use_complete_synthetic_response_pipeline() {
    let src = include_str!("../../../src/http3/server.rs");
    let request_scoped_gate = src
        .find("let has_terminal_body_dispatch = capabilities")
        .expect("H3 terminal dispatch must retain a request-scoped applicability gate");
    let early_dispatch = src
        .find("if final_body_before_backend_dispatch {")
        .expect("H3 terminal final-body dispatch gate must remain present");
    let applicability = &src[request_scoped_gate..early_dispatch];
    assert!(applicability.contains("plugin.should_buffer_request_body(&ctx)"));
    assert!(applicability.contains("plugin.requires_final_request_body_before_backend_dispatch()"));

    let early_start = src
        .find("let raw_request_body_bytes = body_data.len() as u64;")
        .expect("H3 early request-body finalization must remain present");
    let early_end = src[early_start..]
        .find("// --- Upstream target selection and circuit breaker ---")
        .map(|offset| early_start + offset)
        .expect("H3 early finalization boundary must remain present");
    let early = &src[early_start..early_end];
    assert!(early.contains("apply_reject_after_proxy_and_synthetic_body_hooks("));
    assert!(!early.contains("apply_replaceable_after_proxy_hooks_to_rejection("));
    assert!(early.contains("matches!(http_flavor, HttpFlavor::Grpc)"));

    let late_start = src
        .find("// Skip the per-plugin context-aware dispatch")
        .expect("H3 late request-body finalization must remain present");
    let late_end = src[late_start..]
        .find("backend_admission_start = std::time::Instant::now();")
        .map(|offset| late_start + offset)
        .expect("H3 backend-admission boundary must remain present");
    let late = &src[late_start..late_end];
    assert!(late.contains("apply_reject_after_proxy_and_synthetic_body_hooks("));
    assert!(!late.contains("apply_replaceable_after_proxy_hooks_to_rejection("));
    assert!(late.contains("matches!(http_flavor, HttpFlavor::Grpc)"));
}
