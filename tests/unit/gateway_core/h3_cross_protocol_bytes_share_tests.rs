//! H3 cross-protocol reject boundaries must preserve shared `Bytes` identity from
//! cached synthetic hits through normalization and QUIC delivery.

use bytes::Bytes;
use ferrum_edge::_test_support::h3_normalize_reject_for_client_for_test;
use ferrum_edge::plugins::RequestContext;
use http::StatusCode;
use std::collections::HashMap;

fn large_cached_body() -> Bytes {
    Bytes::from(vec![0x5au8; 256 * 1024])
}

fn binary_headers() -> HashMap<String, String> {
    HashMap::from([(
        "content-type".to_string(),
        "application/octet-stream".to_string(),
    )])
}

#[test]
fn h3_normalize_reject_for_client_shares_cached_bytes_without_copy() {
    let cached = large_cached_body();
    let cached_ptr = cached.as_ptr() as usize;
    let mut ctx = RequestContext::new(
        "203.0.113.10".to_string(),
        "GET".to_string(),
        "/cached".into(),
    );
    let (normalized, _) = h3_normalize_reject_for_client_for_test(
        &mut ctx,
        StatusCode::OK,
        cached.clone(),
        &binary_headers(),
        false,
    );
    assert_eq!(normalized.body.len(), cached.len());
    assert_eq!(
        normalized.body.as_ptr() as usize,
        cached_ptr,
        "H3 cross-protocol reject normalization must not copy owned cached Bytes"
    );
}

#[test]
fn h3_cross_protocol_reject_boundaries_avoid_slice_copies_for_owned_bytes() {
    let cross = include_str!("../../../src/http3/cross_protocol.rs");

    let normalize = cross
        .split("fn normalize_reject_for_client(")
        .nth(1)
        .expect("H3 cross-protocol reject normalizer")
        .split("fn reject_committed_response_view(")
        .next()
        .expect("bounded H3 cross-protocol reject normalizer");
    assert!(
        normalize.contains("body: Bytes,"),
        "normalize_reject_for_client must accept owned Bytes"
    );
    assert!(
        !normalize.contains("copy_from_slice"),
        "normalize_reject_for_client must not copy an owned Bytes payload"
    );

    let writer = cross
        .split("async fn write_reject_with_headers_and_recv_halt<S>(")
        .nth(1)
        .expect("H3 cross-protocol reject writer")
        .split("struct RejectWriteAccounting")
        .next()
        .expect("bounded H3 cross-protocol reject writer");
    assert!(
        writer.contains("body: Bytes,"),
        "write_reject_with_headers_and_recv_halt must accept owned Bytes"
    );
    assert!(
        writer.contains("stream.send_data(body)"),
        "QUIC delivery must move/cloned Bytes rather than copy_from_slice"
    );
    assert!(
        !writer.contains("copy_from_slice"),
        "final plain H3 reject delivery must not copy owned Bytes"
    );

    let grpc_normalize = cross
        .split("fn normalize_h3_grpc_reject(")
        .nth(1)
        .expect("H3 gRPC reject normalizer")
        .split("fn apply_h3_grpc_reject_metadata(")
        .next()
        .expect("bounded H3 gRPC reject normalizer");
    assert!(
        grpc_normalize.contains("body: Bytes,"),
        "normalize_h3_grpc_reject must accept owned Bytes"
    );
    assert!(
        !grpc_normalize.contains("copy_from_slice"),
        "normalize_h3_grpc_reject must not copy owned Bytes"
    );

    let committed_hooks = cross
        .split("async fn run_cross_protocol_reject_committed_hooks(")
        .nth(1)
        .expect("H3 cross-protocol committed-hook runner")
        .split("async fn write_plain_gateway_error<S>(")
        .next()
        .expect("bounded H3 cross-protocol committed-hook runner");
    assert!(
        committed_hooks.contains("run_response_committed_hook_until_deadline("),
        "committed hooks must remain wired on the cross-protocol reject path"
    );
    assert!(
        !committed_hooks.contains("copy_from_slice"),
        "cross-protocol committed-hook handoff must not copy owned Bytes"
    );
}

#[test]
fn committed_hook_deadline_boundary_accepts_bytes_without_copy() {
    let proxy = include_str!("../../../src/proxy/mod.rs");
    let hook = proxy
        .split("pub(crate) async fn run_response_committed_hook_until_deadline(")
        .nth(1)
        .expect("response-committed deadline hook")
        .split("pub(crate) fn spawn_detached_response_committed_hooks(")
        .next()
        .expect("bounded response-committed deadline hook");
    assert!(
        hook.contains("response_body: Bytes,"),
        "deadline hook boundary must accept owned Bytes"
    );
    assert!(
        hook.contains("response_body.as_ref()"),
        "fast no-deadline hook path must borrow without forcing a full copy"
    );
    assert!(
        !hook.contains("copy_from_slice"),
        "owned deadline hook state must not copy an existing Bytes body"
    );
}

#[test]
fn buffered_backend_response_from_body_read_keeps_reqwest_bytes() {
    let proxy = include_str!("../../../src/proxy/mod.rs");
    let reader = proxy
        .split("fn buffered_backend_response_from_body_read(")
        .nth(1)
        .expect("buffered backend body reader")
        .split("fn eager_buffer_body_read_status_and_class(")
        .next()
        .expect("bounded buffered backend body reader");
    assert!(
        reader.contains("Result<bytes::Bytes, reqwest::Error>"),
        "successful reqwest body reads must stay as Bytes"
    );
    assert!(
        reader.contains("ResponseBody::buffered(b)"),
        "buffered backend responses must store Bytes directly"
    );
    assert!(
        !reader.contains("b.to_vec()"),
        "buffered backend responses must not force Vec conversion"
    );
}
