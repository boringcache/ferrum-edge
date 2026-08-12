//! RFC 9298 CONNECT-UDP over HTTP/3 — boundary parsing, destination admission,
//! and the RFC 9297 capsule codec (`src/http3/connect_udp.rs`).
//!
//! These exercise the production functions the H3 listener calls, not
//! re-implementations: `handle_h3_connect_udp` parses its target with
//! [`parse_connect_udp_target`], admits its destination with
//! [`destination_is_configured`], decodes the client stream with
//! [`CapsuleDecoder`], and frames target datagrams with
//! [`encode_udp_datagram_capsule`].

use ferrum_edge::config::types::{GatewayConfig, Proxy, Upstream};
use ferrum_edge::http3::connect_udp::{
    CONNECT_UDP_MAX_PAYLOAD_BYTES, CapsuleDecodeError, CapsuleDecoder, CapsuleEvent,
    ConnectUdpRequestRejection, ConnectUdpTargetRejection, H3ExtendedConnect, UdpSendFault,
    classify_h3_extended_connect, classify_udp_send_error, destination_is_configured,
    encode_udp_datagram_capsule, first_forbidden_capsule_protocol_field, parse_connect_udp_target,
    strip_forbidden_capsule_protocol_response_fields, validate_connect_udp_request_shape,
};
use ferrum_edge::load_balancer::{LoadBalancerCache, LoadBalancerCacheInner};

// ---------------------------------------------------------------------------
// URI Template parsing (RFC 9298 §2 / §3)
// ---------------------------------------------------------------------------

#[test]
fn parses_the_rfc9298_default_masque_template() {
    let target = parse_connect_udp_target("/.well-known/masque/udp/dns.example/853/")
        .expect("default template must parse");
    assert_eq!(target.host, "dns.example");
    assert_eq!(target.port, 853);
}

#[test]
fn parses_an_operator_prefixed_template() {
    let target = parse_connect_udp_target("/tenant-a/masque/udp/relay.internal/9000/")
        .expect("operator prefix must parse");
    assert_eq!(target.host, "relay.internal");
    assert_eq!(target.port, 9000);
}

#[test]
fn lowercases_the_target_host_so_admission_compares_exactly() {
    let target = parse_connect_udp_target("/udp/DNS.Example/53/").expect("must parse");
    assert_eq!(target.host, "dns.example");
}

#[test]
fn parses_ipv4_and_ipv6_literals_in_canonical_form() {
    let v4 = parse_connect_udp_target("/udp/192.0.2.10/443/").expect("ipv4 literal");
    assert_eq!(v4.host, "192.0.2.10");

    // RFC 9298 percent-encodes the colons; policy-path canonicalization has
    // already decoded them by the time the handler parses the path.
    let v6 = parse_connect_udp_target("/udp/2001:0db8:0000:0000:0000:0000:0000:0001/443/")
        .expect("ipv6 literal");
    assert_eq!(v6.host, "2001:db8::1");
}

#[test]
fn rejects_a_path_without_the_udp_anchor() {
    assert_eq!(
        parse_connect_udp_target("/.well-known/masque/tcp/dns.example/853/"),
        Err(ConnectUdpTargetRejection::TemplateAnchorMissing)
    );
    assert_eq!(
        parse_connect_udp_target("/dns.example/853/"),
        Err(ConnectUdpTargetRejection::TemplateAnchorMissing)
    );
}

#[test]
fn rejects_a_path_without_the_template_trailing_slash() {
    assert_eq!(
        parse_connect_udp_target("/udp/dns.example/853"),
        Err(ConnectUdpTargetRejection::TrailingSlashMissing)
    );
}

#[test]
fn rejects_empty_template_variables() {
    assert_eq!(
        parse_connect_udp_target("/udp//853/"),
        Err(ConnectUdpTargetRejection::TargetHostEmpty)
    );
    assert_eq!(
        parse_connect_udp_target("/udp/dns.example//"),
        Err(ConnectUdpTargetRejection::TargetPortEmpty)
    );
}

#[test]
fn rejects_an_oversized_target_host() {
    let host = "a".repeat(300);
    assert_eq!(
        parse_connect_udp_target(&format!("/udp/{host}/53/")),
        Err(ConnectUdpTargetRejection::TargetHostTooLong)
    );
}

#[test]
fn rejects_hostile_target_host_spellings() {
    // Not an LDH label; root dot; bracketed IPv6; zone identifier; leading and
    // trailing hyphen labels; empty label; whitespace; colon-bearing non-literal.
    for host in [
        "under_score.example",
        "trailing.dot.",
        "[2001:db8::1]",
        "2001:db8::1%eth0",
        "-leading.example",
        "trailing-.example",
        "double..dot",
        "sp ace.example",
        "not:an:ipv6",
    ] {
        assert_eq!(
            parse_connect_udp_target(&format!("/udp/{host}/53/")),
            Err(ConnectUdpTargetRejection::TargetHostMalformed),
            "host {host} must be refused"
        );
    }
}

#[test]
fn rejects_hostile_target_ports() {
    assert_eq!(
        parse_connect_udp_target("/udp/dns.example/0/"),
        Err(ConnectUdpTargetRejection::TargetPortOutOfRange)
    );
    assert_eq!(
        parse_connect_udp_target("/udp/dns.example/65536/"),
        Err(ConnectUdpTargetRejection::TargetPortOutOfRange)
    );
    for port in ["+53", "53a", "0x35", " 53", "999999"] {
        assert!(
            matches!(
                parse_connect_udp_target(&format!("/udp/dns.example/{port}/")),
                Err(ConnectUdpTargetRejection::TargetPortMalformed
                    | ConnectUdpTargetRejection::TargetPortOutOfRange)
            ),
            "port {port} must be refused"
        );
    }
}

#[test]
fn rejection_diagnostics_are_field_specific_and_echo_nothing() {
    let rejection = parse_connect_udp_target("/udp/under_score/53/").expect_err("must reject");
    assert_eq!(rejection.reason(), "target_host_malformed");
    assert!(rejection.client_error_body().contains("target_host"));
    assert!(!rejection.client_error_body().contains("under_score"));
}

// ---------------------------------------------------------------------------
// Destination admission
// ---------------------------------------------------------------------------

fn direct_proxy(host: &str, port: u16) -> Proxy {
    serde_json::from_value(serde_json::json!({
        "id": "connect-udp",
        "backend_host": host,
        "backend_port": port,
        "listen_path": "/.well-known/masque",
    }))
    .expect("minimal direct proxy")
}

fn upstream_proxy(upstream_id: &str) -> Proxy {
    serde_json::from_value(serde_json::json!({
        "id": "connect-udp",
        "backend_host": "unused.example",
        "backend_port": 1,
        "upstream_id": upstream_id,
        "listen_path": "/.well-known/masque",
    }))
    .expect("minimal upstream proxy")
}

fn upstream_with_targets(id: &str, targets: &[(&str, u16)]) -> Upstream {
    let targets: Vec<serde_json::Value> = targets
        .iter()
        .map(|(host, port)| serde_json::json!({ "host": host, "port": port }))
        .collect();
    serde_json::from_value(serde_json::json!({ "id": id, "targets": targets }))
        .expect("minimal upstream")
}

fn lb_cache(upstreams: Vec<Upstream>) -> LoadBalancerCache {
    let config = GatewayConfig {
        upstreams,
        ..GatewayConfig::default()
    };
    LoadBalancerCache::new(&config)
}

#[test]
fn admits_only_the_configured_direct_backend() {
    let cache = lb_cache(Vec::new());
    let guard = cache.load();
    let lb: &LoadBalancerCacheInner = &guard;
    let proxy = direct_proxy("dns.example", 853);

    assert!(destination_is_configured(&proxy, lb, "dns.example", 853));
    // Case-insensitive on the host, exact on the port.
    assert!(destination_is_configured(&proxy, lb, "DNS.example", 853));
    assert!(!destination_is_configured(&proxy, lb, "dns.example", 53));
    assert!(!destination_is_configured(
        &proxy,
        lb,
        "attacker.example",
        853
    ));
}

#[test]
fn admits_any_target_of_the_referenced_upstream_and_nothing_else() {
    let cache = lb_cache(vec![upstream_with_targets(
        "udp-pool",
        &[("relay-a.internal", 5353), ("relay-b.internal", 5353)],
    )]);
    let guard = cache.load();
    let lb: &LoadBalancerCacheInner = &guard;
    let proxy = upstream_proxy("udp-pool");

    assert!(destination_is_configured(
        &proxy,
        lb,
        "relay-a.internal",
        5353
    ));
    assert!(destination_is_configured(
        &proxy,
        lb,
        "relay-b.internal",
        5353
    ));
    // The proxy's own backend_host is NOT admitted once an upstream governs it.
    assert!(!destination_is_configured(&proxy, lb, "unused.example", 1));
    assert!(!destination_is_configured(
        &proxy,
        lb,
        "relay-a.internal",
        53
    ));
}

#[test]
fn a_withdrawn_upstream_admits_nothing() {
    // Exactly the reload/delete shape: the proxy still names an upstream, but
    // the published snapshot no longer contains it.
    let cache = lb_cache(Vec::new());
    let guard = cache.load();
    let lb: &LoadBalancerCacheInner = &guard;
    let proxy = upstream_proxy("udp-pool");

    assert!(!destination_is_configured(
        &proxy,
        lb,
        "relay-a.internal",
        5353
    ));
}

// ---------------------------------------------------------------------------
// Capsule codec (RFC 9297 §3, RFC 9298 §4/§5)
// ---------------------------------------------------------------------------

/// Hand-rolled DATAGRAM capsule so the decoder is tested against an
/// independently constructed encoding, not against its own encoder.
fn datagram_capsule(context_id: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x00]; // Capsule Type = 0x00
    let value_len = 1 + payload.len();
    assert!(value_len < 64, "helper only emits 1-byte length varints");
    out.push(value_len as u8);
    out.push(context_id);
    out.extend_from_slice(payload);
    out
}

fn drain(decoder: &mut CapsuleDecoder) -> Vec<CapsuleEvent> {
    let mut events = Vec::new();
    loop {
        match decoder.next().expect("no decode fault expected") {
            Some(event) => events.push(event),
            None => return events,
        }
    }
}

#[test]
fn decodes_a_context_zero_datagram_capsule() {
    let mut decoder = CapsuleDecoder::new(1200);
    decoder
        .push(&datagram_capsule(0, b"hello"))
        .expect("push must succeed");
    assert_eq!(
        drain(&mut decoder),
        vec![CapsuleEvent::UdpPayload(bytes::Bytes::from_static(
            b"hello"
        ))]
    );
}

#[test]
fn decodes_several_capsules_from_one_data_frame() {
    let mut decoder = CapsuleDecoder::new(1200);
    let mut wire = datagram_capsule(0, b"one");
    wire.extend_from_slice(&datagram_capsule(0, b"two"));
    decoder.push(&wire).expect("push must succeed");
    assert_eq!(
        drain(&mut decoder),
        vec![
            CapsuleEvent::UdpPayload(bytes::Bytes::from_static(b"one")),
            CapsuleEvent::UdpPayload(bytes::Bytes::from_static(b"two")),
        ]
    );
}

#[test]
fn reassembles_a_capsule_split_across_data_frames() {
    let wire = datagram_capsule(0, b"fragmented-payload");
    let mut decoder = CapsuleDecoder::new(1200);
    for split in 1..wire.len() {
        let mut decoder_at_split = CapsuleDecoder::new(1200);
        decoder_at_split.push(&wire[..split]).expect("first half");
        assert!(
            drain(&mut decoder_at_split).is_empty(),
            "a partial capsule must not yield an event at split {split}"
        );
        decoder_at_split.push(&wire[split..]).expect("second half");
        assert_eq!(
            drain(&mut decoder_at_split),
            vec![CapsuleEvent::UdpPayload(bytes::Bytes::from_static(
                b"fragmented-payload"
            ))],
            "split {split} must reassemble"
        );
    }
    // Byte-at-a-time is the same contract.
    for byte in &wire {
        decoder.push(&[*byte]).expect("byte push");
    }
    assert_eq!(drain(&mut decoder).len(), 1);
}

#[test]
fn drops_datagrams_naming_an_unregistered_context() {
    let mut decoder = CapsuleDecoder::new(1200);
    let mut wire = datagram_capsule(2, b"client-allocated");
    wire.extend_from_slice(&datagram_capsule(0, b"udp"));
    decoder.push(&wire).expect("push must succeed");
    assert_eq!(
        drain(&mut decoder),
        vec![
            CapsuleEvent::UnregisteredContext(2),
            CapsuleEvent::UdpPayload(bytes::Bytes::from_static(b"udp")),
        ],
        "an unregistered context must be reported as droppable, never proxied"
    );
}

#[test]
fn skips_unknown_capsule_types_and_keeps_parsing() {
    let mut decoder = CapsuleDecoder::new(1200);
    // Capsule Type = 0x17 (unregistered here), length 3, then a real datagram.
    let mut wire = vec![0x17, 0x03, 0xaa, 0xbb, 0xcc];
    wire.extend_from_slice(&datagram_capsule(0, b"after"));
    decoder.push(&wire).expect("push must succeed");
    assert_eq!(
        drain(&mut decoder),
        vec![
            CapsuleEvent::UnknownCapsuleType(0x17),
            CapsuleEvent::UdpPayload(bytes::Bytes::from_static(b"after")),
        ]
    );
}

#[test]
fn refuses_a_datagram_capsule_with_no_context_id() {
    let mut decoder = CapsuleDecoder::new(1200);
    // Type 0x00, length 0 — no room for the mandatory Context ID varint.
    decoder.push(&[0x00, 0x00]).expect("push must succeed");
    assert_eq!(
        decoder.next(),
        Err(CapsuleDecodeError::DatagramCapsuleTruncated)
    );
}

#[test]
fn refuses_a_capsule_declaring_a_length_above_the_ceiling() {
    let mut decoder = CapsuleDecoder::new(64);
    // Type 0x00, 2-byte varint length 0x4400 = 1024, far above 64 + slack.
    decoder
        .push(&[0x00, 0x44, 0x00])
        .expect("push must succeed");
    assert_eq!(decoder.next(), Err(CapsuleDecodeError::CapsuleTooLarge));
}

#[test]
fn refuses_a_context_zero_payload_above_the_configured_ceiling() {
    let mut decoder = CapsuleDecoder::new(4);
    // Fits under the capsule ceiling (4 + 8 slack) but exceeds the payload cap.
    decoder
        .push(&datagram_capsule(0, b"1234567"))
        .expect("push must succeed");
    assert_eq!(decoder.next(), Err(CapsuleDecodeError::PayloadTooLarge));
}

#[test]
fn refuses_a_push_that_would_exceed_the_transient_buffer_bound() {
    let mut decoder = CapsuleDecoder::new(64);
    let oversized = vec![0u8; decoder.feed_limit() * 2 + 1];
    assert_eq!(
        decoder.push(&oversized),
        Err(CapsuleDecodeError::BufferOverflow)
    );
}

#[test]
fn encodes_a_context_zero_datagram_capsule_on_the_wire() {
    let mut out = bytes::BytesMut::new();
    let capsule = encode_udp_datagram_capsule(&mut out, b"pong");
    assert_eq!(
        capsule.as_ref(),
        &[0x00, 0x05, 0x00, b'p', b'o', b'n', b'g']
    );
}

#[test]
fn encoder_and_decoder_round_trip_at_the_rfc_payload_ceiling() {
    let payload = vec![0x5a; CONNECT_UDP_MAX_PAYLOAD_BYTES];
    let mut out = bytes::BytesMut::new();
    let capsule = encode_udp_datagram_capsule(&mut out, &payload);

    let mut decoder = CapsuleDecoder::new(CONNECT_UDP_MAX_PAYLOAD_BYTES);
    let feed_limit = decoder.feed_limit();
    for chunk in capsule.chunks(feed_limit) {
        decoder.push(chunk).expect("push must succeed");
    }
    match decoder.next().expect("decode must succeed") {
        Some(CapsuleEvent::UdpPayload(decoded)) => assert_eq!(decoded.len(), payload.len()),
        other => panic!("expected a context-0 payload, got {other:?}"),
    }
}

#[test]
fn encoder_reuses_its_scratch_buffer_across_datagrams() {
    let mut out = bytes::BytesMut::new();
    let first = encode_udp_datagram_capsule(&mut out, b"a");
    let second = encode_udp_datagram_capsule(&mut out, b"b");
    assert_eq!(first.as_ref(), &[0x00, 0x02, 0x00, b'a']);
    assert_eq!(second.as_ref(), &[0x00, 0x02, 0x00, b'b']);
}

// ---------------------------------------------------------------------------
// Extended CONNECT classification
// ---------------------------------------------------------------------------

fn connect_request(protocol: Option<h3::ext::Protocol>) -> http::Request<()> {
    let mut req = http::Request::builder()
        .method(http::Method::CONNECT)
        .version(http::Version::HTTP_3)
        .uri("https://gateway.test/.well-known/masque/udp/dns.example/853/")
        .body(())
        .expect("request");
    if let Some(protocol) = protocol {
        req.extensions_mut().insert(protocol);
    }
    req
}

#[test]
fn classifies_the_two_dispatchable_extended_connect_profiles() {
    assert_eq!(
        classify_h3_extended_connect(&connect_request(Some(h3::ext::Protocol::CONNECT_UDP))),
        H3ExtendedConnect::ConnectUdp
    );
    assert_eq!(
        classify_h3_extended_connect(&connect_request(Some(h3::ext::Protocol::WEB_SOCKET))),
        H3ExtendedConnect::WebSocket
    );
}

#[test]
fn classifies_registered_but_unimplemented_protocols_as_unsupported() {
    assert_eq!(
        classify_h3_extended_connect(&connect_request(Some(h3::ext::Protocol::WEB_TRANSPORT))),
        H3ExtendedConnect::Unsupported,
        "webtransport must not be dispatched as a tunnel"
    );
}

#[test]
fn a_bare_connect_and_a_non_connect_request_are_not_extended_connect() {
    assert_eq!(
        classify_h3_extended_connect(&connect_request(None)),
        H3ExtendedConnect::None
    );

    let mut get = http::Request::builder()
        .method(http::Method::GET)
        .version(http::Version::HTTP_3)
        .uri("https://gateway.test/udp/dns.example/853/")
        .body(())
        .expect("request");
    // Even a spoofed `:protocol` extension on a non-CONNECT request must not
    // reach the tunnel dispatcher.
    get.extensions_mut().insert(h3::ext::Protocol::CONNECT_UDP);
    assert_eq!(classify_h3_extended_connect(&get), H3ExtendedConnect::None);
}

// ---------------------------------------------------------------------------
// RFC 9298 §3 request shape
// ---------------------------------------------------------------------------

fn uri(text: &str) -> http::Uri {
    text.parse().expect("test uri")
}

#[test]
fn accepts_the_rfc9298_https_bootstrap_shape() {
    validate_connect_udp_request_shape(&uri(
        "https://gateway.test/.well-known/masque/udp/dns.example/853/",
    ))
    .expect("the RFC 9298 §3 shape must be accepted");
}

#[test]
fn refuses_a_connect_udp_request_without_the_https_scheme() {
    // The classifier reads only :method and :protocol, so without this check
    // the handler would assume HTTPS and tunnel anyway.
    assert_eq!(
        validate_connect_udp_request_shape(&uri(
            "http://gateway.test/.well-known/masque/udp/dns.example/853/"
        )),
        Err(ConnectUdpRequestRejection::SchemeNotHttps)
    );
    assert_eq!(
        validate_connect_udp_request_shape(&uri(
            "ftp://gateway.test/.well-known/masque/udp/dns.example/853/"
        )),
        Err(ConnectUdpRequestRejection::SchemeNotHttps)
    );
    // An origin-form URI carries no :scheme at all.
    assert_eq!(
        validate_connect_udp_request_shape(&uri("/.well-known/masque/udp/dns.example/853/")),
        Err(ConnectUdpRequestRejection::SchemeMissing)
    );
}

#[test]
fn refuses_a_connect_udp_request_without_an_authority() {
    assert_eq!(
        validate_connect_udp_request_shape(&uri("https:///udp/dns.example/853/")),
        Err(ConnectUdpRequestRejection::AuthorityMissing)
    );
}

#[test]
fn request_shape_diagnostics_are_field_specific_and_echo_nothing() {
    let rejection = validate_connect_udp_request_shape(&uri(
        "http://secret-tenant.internal/udp/dns.example/853/",
    ))
    .expect_err("must reject");
    assert_eq!(rejection.reason(), "connect_udp_scheme_not_https");
    assert!(rejection.client_error_body().contains(":scheme"));
    assert!(
        !rejection
            .client_error_body()
            .contains("secret-tenant.internal")
    );
}

// ---------------------------------------------------------------------------
// RFC 9297 §3.2 forbidden fields
// ---------------------------------------------------------------------------

#[test]
fn refuses_every_field_the_capsule_protocol_forbids() {
    for (name, expected) in [
        ("content-length", ConnectUdpRequestRejection::ForbiddenContentLength),
        ("Content-Length", ConnectUdpRequestRejection::ForbiddenContentLength),
        ("content-type", ConnectUdpRequestRejection::ForbiddenContentType),
        ("CONTENT-TYPE", ConnectUdpRequestRejection::ForbiddenContentType),
        (
            "transfer-encoding",
            ConnectUdpRequestRejection::ForbiddenTransferEncoding,
        ),
        (
            "Transfer-Encoding",
            ConnectUdpRequestRejection::ForbiddenTransferEncoding,
        ),
    ] {
        assert_eq!(
            first_forbidden_capsule_protocol_field([name]),
            Some(expected),
            "{name} must be refused on a Capsule Protocol message"
        );
    }
}

#[test]
fn permits_the_fields_the_capsule_protocol_requires() {
    assert_eq!(
        first_forbidden_capsule_protocol_field(["capsule-protocol", "user-agent", "authorization"]),
        None
    );
}

#[test]
fn strips_forbidden_fields_a_response_policy_tried_to_author() {
    // A plugin/policy-finalized response map is the second half of the
    // boundary: rejecting only the client's headers would let
    // `response_transformer` put Content-Type on a Capsule Protocol message.
    let mut headers = std::collections::HashMap::from([
        ("content-length".to_string(), "42".to_string()),
        ("Content-Type".to_string(), "text/plain".to_string()),
        ("transfer-encoding".to_string(), "chunked".to_string()),
        ("x-tenant".to_string(), "keep-me".to_string()),
    ]);
    strip_forbidden_capsule_protocol_response_fields(&mut headers);
    assert_eq!(
        headers,
        std::collections::HashMap::from([("x-tenant".to_string(), "keep-me".to_string())]),
        "only the RFC 9297 §3.2 fields may be removed, and all of them must be"
    );
}

// ---------------------------------------------------------------------------
// RFC 9297 §3.3: a FIN mid-capsule is malformed, not EOF
// ---------------------------------------------------------------------------

#[test]
fn a_client_fin_on_a_capsule_boundary_is_a_clean_end_of_stream() {
    let mut decoder = CapsuleDecoder::new(1200);
    decoder
        .push(&datagram_capsule(0, b"complete"))
        .expect("push");
    assert_eq!(drain(&mut decoder).len(), 1);
    assert_eq!(decoder.buffered_len(), 0);
    decoder
        .finish_stream()
        .expect("a FIN with nothing buffered is an ordinary close");
}

#[test]
fn a_client_fin_inside_a_capsule_is_a_malformed_message_not_an_eof() {
    let mut decoder = CapsuleDecoder::new(1200);
    // Header declares 32 bytes of value; only 3 arrive.
    decoder.push(&[0x00, 0x20, 0x00, 0xde, 0xad]).expect("push");
    assert!(
        drain(&mut decoder).is_empty(),
        "an incomplete capsule must not yield an event"
    );
    assert!(
        decoder.buffered_len() > 0,
        "the partial capsule must still be buffered"
    );
    assert_eq!(
        decoder.finish_stream(),
        Err(CapsuleDecodeError::TruncatedAtStreamEnd),
        "RFC 9297 §3.3: a stream closed mid-capsule is malformed, never a clean EOF"
    );
    assert_eq!(
        CapsuleDecodeError::TruncatedAtStreamEnd.reason(),
        "capsule_truncated_at_stream_end"
    );
}

#[test]
fn a_dangling_capsule_header_prefix_is_also_a_truncated_stream() {
    let mut decoder = CapsuleDecoder::new(1200);
    // A 2-byte varint type whose second byte never arrives.
    decoder.push(&[0x40]).expect("push");
    assert!(drain(&mut decoder).is_empty());
    assert_eq!(
        decoder.finish_stream(),
        Err(CapsuleDecodeError::TruncatedAtStreamEnd)
    );
}

// ---------------------------------------------------------------------------
// RFC 9298 §3.1 socket behaviour
// ---------------------------------------------------------------------------

#[test]
fn an_oversized_datagram_is_dropped_but_an_unusable_socket_is_terminal() {
    // Portable, errno-free arms first: `io::Error::from(ErrorKind)` carries no
    // raw OS error, so these exercise the kind-based fallback directly.
    for kind in [
        std::io::ErrorKind::WouldBlock,
        std::io::ErrorKind::Interrupted,
        std::io::ErrorKind::ConnectionRefused,
        std::io::ErrorKind::HostUnreachable,
        std::io::ErrorKind::NetworkUnreachable,
        std::io::ErrorKind::NetworkDown,
    ] {
        assert_eq!(
            classify_udp_send_error(&std::io::Error::from(kind)),
            UdpSendFault::DropDatagram,
            "{kind:?} is per-datagram loss on a lossy-by-design transport"
        );
    }
    for kind in [
        std::io::ErrorKind::PermissionDenied,
        std::io::ErrorKind::BrokenPipe,
        std::io::ErrorKind::NotConnected,
        std::io::ErrorKind::Other,
    ] {
        assert_eq!(
            classify_udp_send_error(&std::io::Error::from(kind)),
            UdpSendFault::Terminal,
            "{kind:?} means the socket itself is unusable"
        );
    }

    // EMSGSIZE is the expected result of the RFC 9298 §3.1 do-not-fragment
    // policy for an over-path datagram, so it must NOT kill the tunnel. Spelled
    // numerically because the test crate does not link `libc`.
    #[cfg(target_os = "linux")]
    const EMSGSIZE: i32 = 90;
    #[cfg(target_vendor = "apple")]
    const EMSGSIZE: i32 = 40;
    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    {
        assert_eq!(
            classify_udp_send_error(&std::io::Error::from_raw_os_error(EMSGSIZE)),
            UdpSendFault::DropDatagram,
            "EMSGSIZE must drop one datagram, never tear down the tunnel"
        );
        // EBADF is 9 on both.
        assert_eq!(
            classify_udp_send_error(&std::io::Error::from_raw_os_error(9)),
            UdpSendFault::Terminal,
            "a closed descriptor is not per-datagram loss"
        );
    }

    assert_eq!(UdpSendFault::DropDatagram.as_str(), "datagram_dropped");
    assert_eq!(UdpSendFault::Terminal.as_str(), "socket_unusable");
}

#[cfg(unix)]
#[test]
fn the_do_not_fragment_option_installs_on_a_real_udp_socket() {
    use std::os::unix::io::AsRawFd;

    use ferrum_edge::socket_opts::{UDP_DONT_FRAGMENT_SUPPORTED, set_udp_dont_fragment};

    // The runtime contract the tunnel socket depends on: on a platform that
    // advertises the option, installing it on a freshly bound UDP socket must
    // succeed — the production path refuses the tunnel when it does not.
    for bind in ["127.0.0.1:0", "[::1]:0"] {
        let Ok(socket) = std::net::UdpSocket::bind(bind) else {
            // No IPv6 loopback on this runner; the IPv4 arm still runs.
            continue;
        };
        let is_ipv4 = socket.local_addr().expect("local addr").is_ipv4();
        let result = set_udp_dont_fragment(socket.as_raw_fd(), is_ipv4);
        if UDP_DONT_FRAGMENT_SUPPORTED {
            result.unwrap_or_else(|error| {
                panic!("do-not-fragment must install on {bind}: {error}");
            });
        } else {
            result.expect("the unsupported-platform shim never fails");
        }
    }
}
