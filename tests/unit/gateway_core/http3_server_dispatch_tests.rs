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
fn translated_h3_grpc_web_threads_preacquired_admission_into_grpc_dispatch() {
    let server = include_str!("../../../src/http3/server.rs");
    let bridge = server
        .find("crate::http3::cross_protocol::run(crate::http3::cross_protocol::CrossProtocolRequest")
        .expect("H3 cross-protocol bridge request must remain present");
    let bridge = &server[bridge..];
    assert!(
        bridge.contains("preacquired_backend_admission,"),
        "the H3 frontend must transfer its preacquired admission owner into the bridge"
    );

    let cross_protocol = include_str!("../../../src/http3/cross_protocol.rs");
    let run = cross_protocol
        .find("pub(crate) async fn run<S>(")
        .expect("cross-protocol run entry point must remain present");
    let grpc_arm = cross_protocol[run..]
        .find("HttpFlavor::Grpc => {")
        .map(|offset| run + offset)
        .expect("cross-protocol gRPC dispatch arm must remain present");
    let grpc_call = &cross_protocol[grpc_arm..];
    let call_end = grpc_call
        .find(".await\n        }")
        .expect("cross-protocol gRPC dispatch call must remain present");
    assert!(
        grpc_call[..call_end].contains("preacquired_backend_admission,"),
        "the gRPC arm must pass through the admission owner instead of dropping it"
    );

    let dispatch = cross_protocol
        .find("async fn dispatch_grpc<S>(")
        .expect("buffered cross-protocol gRPC dispatcher must remain present");
    let dispatch_body = &cross_protocol[dispatch..];
    let first_admission = dispatch_body
        .find("let mut backend_admission_permits =")
        .expect("initial gRPC backend admission must remain present");
    let initial = &dispatch_body[first_admission..];
    let consume = initial
        .find("preacquired_backend_admission.take_if_acquired()")
        .expect("initial gRPC dispatch must consume preacquired admission");
    let fallback = initial
        .find("run_cross_protocol_backend_admission_or_reject(")
        .expect("initial gRPC dispatch must retain an admission fallback");
    assert!(
        consume < fallback,
        "preacquired admission must be consumed before a fallback acquisition can run"
    );

    let retry = dispatch_body
        .find("Retrying cross-protocol H3→gRPC backend request")
        .expect("cross-protocol gRPC retry path must remain present");
    let retry_admission = &dispatch_body[retry..];
    let retry_admission_end = retry_admission
        .find("record_cross_protocol_connection_start")
        .expect("retry admission block must remain present");
    assert!(
        retry_admission[..retry_admission_end]
            .contains("run_cross_protocol_backend_admission_or_reject("),
        "a rotated retry target must acquire its own fresh admission"
    );
    assert!(
        !retry_admission[..retry_admission_end].contains("take_if_acquired"),
        "the initial target's preacquired permit must never be reused by a retry"
    );
}

#[test]
fn buffered_h3_deadline_replacements_keep_grpc_web_wire_flavor() {
    let server = include_str!("../../../src/http3/server.rs");
    let committed = server
        .find("// transform_response_body hooks — only for buffered responses.")
        .expect("buffered H3 response-hook pipeline must remain present");
    let committed = &server[committed..];
    let replacement = committed
        .find("replace_buffered_h3_response_with_grpc_deadline(")
        .expect("buffered H3 deadline replacement must remain flavor-aware");
    let response_write = committed
        .find("apply_response_headers(Response::builder().status(status), &response_headers)")
        .expect("buffered H3 direct response write must remain present");
    assert!(replacement < response_write);
    assert!(
        committed[..response_write]
            .contains("grpc_web_response_content_type.as_deref()"),
        "the direct H3 buffered writer must pass the original gRPC-Web flavor into replacement"
    );

    let cross_protocol = include_str!("../../../src/http3/cross_protocol.rs");
    let replacement = cross_protocol
        .find("fn replace_buffered_grpc_response_with_deadline(")
        .expect("cross-protocol buffered gRPC replacement must remain present");
    let replacement = &cross_protocol[replacement..];
    assert!(replacement.contains("is_grpc_web_content_type(content_type)"));
    assert!(replacement.contains("replace_buffered_h3_response_with_grpc_deadline("));
}

#[test]
fn h3_grpc_web_upload_deadlines_use_request_aware_writer() {
    let source = include_str!("../../../src/http3/cross_protocol.rs");
    let dispatch = source
        .find("async fn dispatch_grpc<S>(")
        .expect("buffered H3-to-gRPC dispatcher must remain present");
    let body = &source[dispatch..];
    let body_start = body
        .find("let body = if let Some(buffered)")
        .expect("H3 gRPC upload buffering must remain present");
    let body = &body[body_start..];
    let body_end = body
        .find("// Build the backend-facing header map")
        .expect("H3 gRPC upload buffering must remain bounded");
    let body = &body[..body_end];
    for error in ["H3RequestBodyReadError::TimedOut", "H3RequestBodyReadError::DeadlineExceeded"] {
        let branch = body
            .find(error)
            .unwrap_or_else(|| panic!("missing {error} upload branch"));
        let branch = &body[branch..];
        let branch_end = branch[1..]
            .find("H3RequestBodyReadError::")
            .map_or(branch.len(), |offset| offset + 1);
        let branch = &branch[..branch_end];
        assert!(branch.contains("write_grpc_error_for_request("));
        assert!(branch.contains("ctx,"));
    }

    let writer = source
        .find("async fn write_grpc_error_for_request<S>(")
        .expect("request-aware H3 gRPC error writer must remain present");
    let writer = &source[writer..];
    let writer_end = writer
        .find("async fn write_grpc_error_send<S>(")
        .expect("request-aware H3 gRPC error writer must remain bounded");
    let writer = &writer[..writer_end];
    assert!(writer.contains("translated_error_response("));
    assert!(writer.contains("write_reject_with_headers("));
}

#[test]
fn native_h3_client_deadlines_remain_health_neutral() {
    let source = include_str!("../../../src/http3/server.rs");
    let body_deadline = source
        .find("_ = &mut grpc_deadline_sleep, if grpc_deadline_active && !stream_done =>")
        .expect("native H3 body deadline branch must remain present");
    let body_deadline = &source[body_deadline..];
    let body_end = body_deadline
        .find("if stream_done {")
        .expect("native H3 body deadline branch must remain bounded");
    let body_deadline = &body_deadline[..body_end];
    assert_eq!(
        body_deadline
            .matches("Some(crate::retry::ErrorClass::ClientDisconnect)")
            .count(),
        3,
        "clean trailer, send failure, and post-DATA abort must all stay neutral"
    );
    assert!(!body_deadline.contains("ErrorClass::ReadWriteTimeout"));

    let trailer_deadline = source
        .find("Err(_) if trailer_timeout_is_deadline =>")
        .expect("native H3 trailer deadline branch must remain present");
    let trailer_deadline = &source[trailer_deadline..];
    let trailer_end = trailer_deadline
        .find("Err(_) =>")
        .expect("native H3 trailer deadline branch must remain bounded");
    let trailer_deadline = &trailer_deadline[..trailer_end];
    assert_eq!(
        trailer_deadline
            .matches("Some(crate::retry::ErrorClass::ClientDisconnect)")
            .count(),
        3,
        "clean trailer, send failure, and post-DATA abort must all stay neutral"
    );
    assert!(!trailer_deadline.contains("ErrorClass::ReadWriteTimeout"));
}

#[test]
fn preacquired_admission_has_exactly_once_outcome_and_release_ownership() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use ferrum_edge::_test_support::PreacquiredBackendAdmissionForTest;
    use ferrum_edge::plugins::{
        BackendAdmissionOutcome, BackendAdmissionPermit, BackendAdmissionPermitSet,
    };
    use ferrum_edge::retry::ErrorClass;

    #[derive(Default)]
    struct PermitState {
        outcomes: AtomicUsize,
        drops: AtomicUsize,
    }

    struct CountingPermit {
        state: Arc<PermitState>,
    }

    impl BackendAdmissionPermit for CountingPermit {
        fn record_backend_outcome(&self, _outcome: BackendAdmissionOutcome) {
            self.state.outcomes.fetch_add(1, Ordering::Relaxed);
        }
    }

    impl Drop for CountingPermit {
        fn drop(&mut self) {
            self.state.drops.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn owner() -> (PreacquiredBackendAdmissionForTest, Arc<PermitState>) {
        let state = Arc::new(PermitState::default());
        let permit: Arc<dyn BackendAdmissionPermit> = Arc::new(CountingPermit {
            state: Arc::clone(&state),
        });
        let permits = BackendAdmissionPermitSet::new(vec![permit])
            .expect("the counting permit set must be non-empty");
        (
            PreacquiredBackendAdmissionForTest::acquired(Some(permits)),
            state,
        )
    }

    for outcome in [
        BackendAdmissionOutcome {
            response_status: 200,
            connection_error: false,
            error_class: None,
            backend_elapsed: Duration::from_millis(5),
        },
        BackendAdmissionOutcome {
            response_status: 502,
            connection_error: true,
            error_class: Some(ErrorClass::ConnectionRefused),
            backend_elapsed: Duration::from_millis(5),
        },
    ] {
        let (mut owner, state) = owner();
        let permits = owner
            .take_if_acquired()
            .expect("preacquired admission must be consumable once")
            .expect("the preacquired permit set must be preserved");
        assert!(
            owner.take_if_acquired().is_none(),
            "a consumed admission owner must not yield a second acquisition"
        );
        permits.record_backend_outcome(outcome);
        drop(permits);
        drop(owner);
        assert_eq!(state.outcomes.load(Ordering::Relaxed), 1);
        assert_eq!(state.drops.load(Ordering::Relaxed), 1);
    }

    let (owner_before_reject, rejected_state) = owner();
    drop(owner_before_reject);
    assert_eq!(rejected_state.outcomes.load(Ordering::Relaxed), 0);
    assert_eq!(rejected_state.drops.load(Ordering::Relaxed), 1);

    let (mut owner_before_cancel, cancelled_state) = owner();
    let permits = owner_before_cancel
        .take_if_acquired()
        .expect("cancelled dispatch must first take ownership")
        .expect("cancelled dispatch must retain the permit set");
    drop(permits);
    drop(owner_before_cancel);
    assert_eq!(cancelled_state.outcomes.load(Ordering::Relaxed), 0);
    assert_eq!(cancelled_state.drops.load(Ordering::Relaxed), 1);

    let mut permitless = PreacquiredBackendAdmissionForTest::acquired(None);
    assert!(matches!(permitless.take_if_acquired(), Some(None)));
    assert!(permitless.take_if_acquired().is_none());
}
