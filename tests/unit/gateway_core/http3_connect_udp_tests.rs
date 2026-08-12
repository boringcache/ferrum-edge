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
    ConnectUdpTargetRejection, H3ExtendedConnect, classify_h3_extended_connect,
    destination_is_configured, encode_udp_datagram_capsule, parse_connect_udp_target,
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
    assert!(!destination_is_configured(&proxy, lb, "attacker.example", 853));
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

    assert!(destination_is_configured(&proxy, lb, "relay-a.internal", 5353));
    assert!(destination_is_configured(&proxy, lb, "relay-b.internal", 5353));
    // The proxy's own backend_host is NOT admitted once an upstream governs it.
    assert!(!destination_is_configured(&proxy, lb, "unused.example", 1));
    assert!(!destination_is_configured(&proxy, lb, "relay-a.internal", 53));
}

#[test]
fn a_withdrawn_upstream_admits_nothing() {
    // Exactly the reload/delete shape: the proxy still names an upstream, but
    // the published snapshot no longer contains it.
    let cache = lb_cache(Vec::new());
    let guard = cache.load();
    let lb: &LoadBalancerCacheInner = &guard;
    let proxy = upstream_proxy("udp-pool");

    assert!(!destination_is_configured(&proxy, lb, "relay-a.internal", 5353));
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
        vec![CapsuleEvent::UdpPayload(bytes::Bytes::from_static(b"hello"))]
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
    decoder.push(&[0x00, 0x44, 0x00]).expect("push must succeed");
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
    assert_eq!(capsule.as_ref(), &[0x00, 0x05, 0x00, b'p', b'o', b'n', b'g']);
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
