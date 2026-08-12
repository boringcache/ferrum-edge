//! Datagram client-address metadata gate (issue #3289).
//!
//! The gate is the whole trust boundary for `stream_proxy_protocol: true` on a
//! `udp` / `dtls` listener: it decides whether a datagram's asserted client
//! address may become `client_ip`, and it must refuse — never downgrade —
//! everything else. These tests pin the wire format, the trust decision, the
//! authentication decision, and each fail-closed refusal.

use std::net::SocketAddr;
use std::sync::Arc;

use ferrum_edge::fips::approved::HmacSha256Key;
use ferrum_edge::proxy::client_ip::TrustedProxies;
use ferrum_edge::proxy::datagram_client_address::{
    AUTH_TAG_LEN, AUTH_TLV_TYPE, DatagramClientAddressGate, DatagramClientIdentity,
    DatagramMetadataError, encode_datagram_with_metadata,
};

const SIG: &[u8; 12] = b"\r\n\r\n\x00\r\nQUIT\n";
const SECRET: &str = "0123456789abcdef0123456789abcdef";

fn addr(value: &str) -> SocketAddr {
    value.parse().expect("test socket address")
}

fn trusted(cidrs: &str) -> Arc<TrustedProxies> {
    Arc::new(TrustedProxies::parse_strict(cidrs, "test").expect("valid trust list"))
}

/// Gate trusting the load balancer at `10.0.0.0/8`, without authentication.
fn address_trust_gate() -> DatagramClientAddressGate {
    DatagramClientAddressGate::new(trusted("10.0.0.0/8,127.0.0.1"), None)
}

/// Gate trusting the same peers and additionally requiring the MAC tag.
fn authenticated_gate() -> DatagramClientAddressGate {
    DatagramClientAddressGate::new(trusted("10.0.0.0/8,127.0.0.1"), Some(SECRET))
}

fn key() -> HmacSha256Key {
    HmacSha256Key::new_from_slice(SECRET.as_bytes()).expect("hmac key")
}

/// The startup validator for the same variable the gate keys itself from.
fn validate_secret(secret: Option<&str>) -> Result<(), String> {
    ferrum_edge::config::env_config::validate_datagram_proxy_protocol_secret_value(secret)
}

/// Hand-build a header so tests can corrupt individual fields.
fn header(ver_cmd: u8, fam_transport: u8, block: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(SIG);
    out.push(ver_cmd);
    out.push(fam_transport);
    out.extend_from_slice(&(block.len() as u16).to_be_bytes());
    out.extend_from_slice(block);
    out.extend_from_slice(payload);
    out
}

fn inet_block(src: &str, dst: &str) -> Vec<u8> {
    let src = addr(src);
    let dst = addr(dst);
    let (std::net::IpAddr::V4(s), std::net::IpAddr::V4(d)) = (src.ip(), dst.ip()) else {
        panic!("ipv4 fixtures only");
    };
    let mut block = Vec::new();
    block.extend_from_slice(&s.octets());
    block.extend_from_slice(&d.octets());
    block.extend_from_slice(&src.port().to_be_bytes());
    block.extend_from_slice(&dst.port().to_be_bytes());
    block
}

#[test]
fn trusted_peer_with_valid_envelope_yields_forwarded_client_and_payload() {
    let gate = address_trust_gate();
    let datagram = encode_datagram_with_metadata(
        addr("203.0.113.9:41234"),
        addr("10.0.0.5:5353"),
        b"question",
        None,
    );

    let decoded = gate
        .decode(&datagram, &addr("10.0.0.1:60000"))
        .expect("valid envelope from a trusted peer is admitted");

    assert_eq!(decoded.forwarded, Some(addr("203.0.113.9:41234")));
    assert_eq!(decoded.payload, b"question");
}

#[test]
fn ipv6_envelope_round_trips() {
    let gate = address_trust_gate();
    let datagram = encode_datagram_with_metadata(
        addr("[2001:db8::10]:41234"),
        addr("[2001:db8::1]:5353"),
        b"v6",
        None,
    );

    let decoded = gate
        .decode(&datagram, &addr("10.0.0.1:60000"))
        .expect("ipv6 envelope is admitted");

    assert_eq!(decoded.forwarded, Some(addr("[2001:db8::10]:41234")));
    assert_eq!(decoded.payload, b"v6");
}

#[test]
fn untrusted_peer_is_refused_before_the_envelope_is_parsed() {
    let gate = address_trust_gate();
    let datagram = encode_datagram_with_metadata(
        addr("203.0.113.9:41234"),
        addr("10.0.0.5:5353"),
        b"spoofed",
        None,
    );

    // A well-formed envelope from an untrusted source is exactly the spoofing
    // case: refuse it rather than honoring the address it asserts.
    let error = gate
        .decode(&datagram, &addr("198.51.100.7:41234"))
        .expect_err("untrusted peer must be refused");
    assert_eq!(error, DatagramMetadataError::UntrustedPeer);
    assert_eq!(error.reason(), "untrusted_peer");
}

#[test]
fn bare_datagram_on_an_enabled_listener_is_refused_not_passed_through() {
    let gate = address_trust_gate();

    let error = gate
        .decode(b"no envelope here at all", &addr("10.0.0.1:60000"))
        .expect_err("a bare payload must not be forwarded");
    assert_eq!(error, DatagramMetadataError::InvalidSignature);

    let error = gate
        .decode(&SIG[..8], &addr("10.0.0.1:60000"))
        .expect_err("a truncated header must not be forwarded");
    assert!(matches!(
        error,
        DatagramMetadataError::TruncatedHeader { len: 8 }
    ));
}

#[test]
fn stream_transport_is_refused_on_the_datagram_path() {
    let gate = address_trust_gate();
    // A TCP PROXY v2 header (STREAM transport) replayed onto a UDP listener.
    let datagram = header(
        0x21,
        0x11,
        &inet_block("203.0.113.9:41234", "10.0.0.5:5353"),
        b"payload",
    );

    let error = gate
        .decode(&datagram, &addr("10.0.0.1:60000"))
        .expect_err("stream transport must not set a datagram client identity");
    assert_eq!(error, DatagramMetadataError::NonDatagramTransport(0x01));
}

#[test]
fn unsupported_family_and_command_are_refused() {
    let gate = address_trust_gate();

    // AF_UNIX cannot address a datagram client.
    let unix = header(0x21, 0x32, &[0u8; 20], b"payload");
    assert_eq!(
        gate.decode(&unix, &addr("10.0.0.1:60000"))
            .expect_err("AF_UNIX must be refused"),
        DatagramMetadataError::UnsupportedAddressFamily(0x03)
    );

    // Command 0x2 is undefined.
    let bad_command = header(
        0x22,
        0x12,
        &inet_block("203.0.113.9:41234", "10.0.0.5:5353"),
        b"payload",
    );
    assert_eq!(
        gate.decode(&bad_command, &addr("10.0.0.1:60000"))
            .expect_err("undefined command must be refused"),
        DatagramMetadataError::UnsupportedCommand(0x02)
    );

    // Version 1 binary framing is not a datagram envelope.
    let bad_version = header(
        0x11,
        0x12,
        &inet_block("203.0.113.9:41234", "10.0.0.5:5353"),
        b"payload",
    );
    assert_eq!(
        gate.decode(&bad_version, &addr("10.0.0.1:60000"))
            .expect_err("version 1 must be refused"),
        DatagramMetadataError::UnsupportedVersion(1)
    );
}

#[test]
fn truncated_and_oversized_address_blocks_are_refused() {
    let gate = address_trust_gate();

    // Declares 12 bytes of AF_INET but supplies 6.
    let mut truncated = Vec::new();
    truncated.extend_from_slice(SIG);
    truncated.push(0x21);
    truncated.push(0x12);
    truncated.extend_from_slice(&12u16.to_be_bytes());
    truncated.extend_from_slice(&[0u8; 6]);
    assert!(matches!(
        gate.decode(&truncated, &addr("10.0.0.1:60000"))
            .expect_err("truncated address block must be refused"),
        DatagramMetadataError::TruncatedAddressBlock {
            declared: 12,
            available: 6
        }
    ));

    // Declares more than the in-memory cap, so the length itself is refused
    // before any allocation decision follows from it.
    let mut oversized = Vec::new();
    oversized.extend_from_slice(SIG);
    oversized.push(0x21);
    oversized.push(0x12);
    oversized.extend_from_slice(&4096u16.to_be_bytes());
    assert_eq!(
        gate.decode(&oversized, &addr("10.0.0.1:60000"))
            .expect_err("oversized address block must be refused"),
        DatagramMetadataError::AddressBlockTooLong(4096)
    );

    // AF_INET6 declared but only an AF_INET-sized block supplied.
    let short_family = header(
        0x21,
        0x22,
        &inet_block("203.0.113.9:41234", "10.0.0.5:5353"),
        b"payload",
    );
    assert!(matches!(
        gate.decode(&short_family, &addr("10.0.0.1:60000"))
            .expect_err("family/length mismatch must be refused"),
        DatagramMetadataError::AddressBlockTooShortForFamily { family: 0x02, .. }
    ));
}

#[test]
fn local_command_keeps_the_socket_peer_as_the_identity() {
    let gate = address_trust_gate();
    // A balancer health probe: LOCAL command, no forwarded address.
    let datagram = header(0x20, 0x00, &[], b"probe");

    let decoded = gate
        .decode(&datagram, &addr("10.0.0.1:60000"))
        .expect("LOCAL probes are admitted");
    assert_eq!(decoded.forwarded, None);
    assert_eq!(decoded.payload, b"probe");

    // With no forwarded address the resolved identity is the socket peer.
    let identity = DatagramClientIdentity {
        socket_peer: addr("10.0.0.1:60000"),
        forwarded: decoded.forwarded,
    };
    assert_eq!(identity.resolved(), addr("10.0.0.1:60000"));
}

#[test]
fn local_command_never_carries_a_client_identity_even_with_addresses() {
    let gate = address_trust_gate();
    // LOCAL + a populated AF_INET block: the balancer is speaking for itself,
    // so the addresses must not become a client identity.
    let datagram = header(
        0x20,
        0x12,
        &inet_block("203.0.113.9:41234", "10.0.0.5:5353"),
        b"probe",
    );

    let decoded = gate
        .decode(&datagram, &addr("10.0.0.1:60000"))
        .expect("LOCAL is admitted");
    assert_eq!(decoded.forwarded, None);
}

#[test]
fn authenticated_gate_admits_a_correctly_tagged_datagram() {
    let gate = authenticated_gate();
    assert!(gate.requires_authentication());

    let datagram = encode_datagram_with_metadata(
        addr("203.0.113.9:41234"),
        addr("10.0.0.5:5353"),
        b"authenticated",
        Some(&key()),
    );

    let decoded = gate
        .decode(&datagram, &addr("10.0.0.1:60000"))
        .expect("valid tag is admitted");
    assert_eq!(decoded.forwarded, Some(addr("203.0.113.9:41234")));
    assert_eq!(decoded.payload, b"authenticated");
}

#[test]
fn authenticated_gate_refuses_an_untagged_datagram() {
    let gate = authenticated_gate();
    let datagram = encode_datagram_with_metadata(
        addr("203.0.113.9:41234"),
        addr("10.0.0.5:5353"),
        b"unsigned",
        None,
    );

    assert_eq!(
        gate.decode(&datagram, &addr("10.0.0.1:60000"))
            .expect_err("an untagged datagram must not be admitted"),
        DatagramMetadataError::MissingAuthenticationTag
    );
}

#[test]
fn authenticated_gate_refuses_a_tag_minted_under_another_secret() {
    let gate = authenticated_gate();
    let other = HmacSha256Key::new_from_slice(b"ffffffffffffffffffffffffffffffff").expect("key");
    let datagram = encode_datagram_with_metadata(
        addr("203.0.113.9:41234"),
        addr("10.0.0.5:5353"),
        b"forged",
        Some(&other),
    );

    assert_eq!(
        gate.decode(&datagram, &addr("10.0.0.1:60000"))
            .expect_err("a foreign tag must not verify"),
        DatagramMetadataError::AuthenticationTagMismatch
    );
}

#[test]
fn tag_binds_the_forwarded_address_and_the_payload() {
    let gate = authenticated_gate();
    let key = key();
    let original = encode_datagram_with_metadata(
        addr("203.0.113.9:41234"),
        addr("10.0.0.5:5353"),
        b"payload",
        Some(&key),
    );

    // Rewrite the forwarded source address in place: the tag must fail.
    let mut swapped_address = original.clone();
    swapped_address[16] = 198;
    swapped_address[17] = 51;
    swapped_address[18] = 100;
    swapped_address[19] = 7;
    assert_eq!(
        gate.decode(&swapped_address, &addr("10.0.0.1:60000"))
            .expect_err("address substitution must break the tag"),
        DatagramMetadataError::AuthenticationTagMismatch
    );

    // Rewrite the payload in place: the tag must fail there too.
    let mut swapped_payload = original.clone();
    let last = swapped_payload.len() - 1;
    swapped_payload[last] ^= 0xff;
    assert_eq!(
        gate.decode(&swapped_payload, &addr("10.0.0.1:60000"))
            .expect_err("payload substitution must break the tag"),
        DatagramMetadataError::AuthenticationTagMismatch
    );

    // Unmodified, it still verifies — so the two refusals above are about the
    // substitution and not about the fixture.
    assert!(gate.decode(&original, &addr("10.0.0.1:60000")).is_ok());
}

#[test]
fn duplicate_and_wrong_length_tags_are_refused() {
    let gate = authenticated_gate();
    let fixed = inet_block("203.0.113.9:41234", "10.0.0.5:5353");

    let mut two_tags = fixed.clone();
    for _ in 0..2 {
        two_tags.push(AUTH_TLV_TYPE);
        two_tags.extend_from_slice(&(AUTH_TAG_LEN as u16).to_be_bytes());
        two_tags.extend_from_slice(&[0u8; AUTH_TAG_LEN]);
    }
    assert_eq!(
        gate.decode(
            &header(0x21, 0x12, &two_tags, b"payload"),
            &addr("10.0.0.1:60000"),
        )
        .expect_err("two tags are ambiguous and must be refused"),
        DatagramMetadataError::DuplicateAuthenticationTag
    );

    let mut short_tag = fixed.clone();
    short_tag.push(AUTH_TLV_TYPE);
    short_tag.extend_from_slice(&4u16.to_be_bytes());
    short_tag.extend_from_slice(&[0u8; 4]);
    assert_eq!(
        gate.decode(
            &header(0x21, 0x12, &short_tag, b"payload"),
            &addr("10.0.0.1:60000"),
        )
        .expect_err("a short tag must be refused"),
        DatagramMetadataError::InvalidAuthenticationTagLength(4)
    );
}

#[test]
fn malformed_tlv_is_refused() {
    let gate = address_trust_gate();
    let mut block = inet_block("203.0.113.9:41234", "10.0.0.5:5353");
    // TLV declaring 64 value bytes with only 2 present inside the block.
    block.push(0x05);
    block.extend_from_slice(&64u16.to_be_bytes());
    block.extend_from_slice(&[0u8; 2]);

    assert_eq!(
        gate.decode(
            &header(0x21, 0x12, &block, b"payload"),
            &addr("10.0.0.1:60000"),
        )
        .expect_err("a TLV running past the address block must be refused"),
        DatagramMetadataError::MalformedTlv
    );
}

#[test]
fn unauthenticated_gate_does_not_honor_a_supplied_tag_as_proof() {
    // With no secret configured a tag is unverifiable. It must not be treated
    // as authentication, and it must not leak into the payload either.
    let gate = address_trust_gate();
    assert!(!gate.requires_authentication());
    let datagram = encode_datagram_with_metadata(
        addr("203.0.113.9:41234"),
        addr("10.0.0.5:5353"),
        b"payload",
        Some(&key()),
    );

    let decoded = gate
        .decode(&datagram, &addr("10.0.0.1:60000"))
        .expect("address trust still applies");
    assert_eq!(decoded.payload, b"payload");
    assert_eq!(decoded.forwarded, Some(addr("203.0.113.9:41234")));
}

#[test]
fn empty_trust_list_admits_nothing() {
    let gate = DatagramClientAddressGate::new(trusted(""), None);
    assert!(!gate.has_trusted_peers());
    let datagram = encode_datagram_with_metadata(
        addr("203.0.113.9:41234"),
        addr("10.0.0.5:5353"),
        b"payload",
        None,
    );
    assert_eq!(
        gate.decode(&datagram, &addr("10.0.0.1:60000"))
            .expect_err("with no trusted peers nothing may assert a client identity"),
        DatagramMetadataError::UntrustedPeer
    );
}

#[test]
fn session_binding_rejects_a_changed_forwarded_client() {
    let first = DatagramClientIdentity {
        socket_peer: addr("10.0.0.1:60000"),
        forwarded: Some(addr("203.0.113.9:41234")),
    };
    let second = DatagramClientIdentity {
        socket_peer: addr("10.0.0.1:60000"),
        forwarded: Some(addr("198.51.100.7:41234")),
    };

    assert!(first.matches_session(Some(addr("203.0.113.9:41234"))));
    assert!(!second.matches_session(Some(addr("203.0.113.9:41234"))));
    // A gate-less listener binds `None` on both sides and always matches.
    assert!(DatagramClientIdentity::direct(addr("10.0.0.1:60000")).matches_session(None));
}

#[test]
fn direct_identity_reports_the_socket_peer_for_both_roles() {
    let identity = DatagramClientIdentity::direct(addr("198.51.100.7:41234"));
    assert_eq!(identity.socket_peer, addr("198.51.100.7:41234"));
    assert_eq!(identity.resolved(), addr("198.51.100.7:41234"));
    assert_eq!(identity.forwarded, None);
}

#[test]
fn diagnostics_are_field_specific_and_carry_no_payload() {
    let gate = authenticated_gate();
    let datagram = encode_datagram_with_metadata(
        addr("203.0.113.9:41234"),
        addr("10.0.0.5:5353"),
        b"super-secret-payload",
        None,
    );
    let error = gate
        .decode(&datagram, &addr("10.0.0.1:60000"))
        .expect_err("untagged");
    let rendered = error.to_string();

    assert!(
        rendered.contains("FERRUM_DATAGRAM_PROXY_PROTOCOL_SECRET"),
        "diagnostic must name the field that failed: {rendered}"
    );
    assert!(
        !rendered.contains("super-secret-payload"),
        "diagnostic must not echo payload bytes: {rendered}"
    );
    assert!(
        !rendered.contains(SECRET),
        "diagnostic must not echo the secret: {rendered}"
    );
}

#[test]
fn a_configured_secret_is_used_verbatim_and_always_requires_authentication() {
    // Whitespace is key material, not decoration. Trimming these would either
    // key the listener with different bytes than `EnvConfig` validated, or —
    // for the whitespace-only value — silently drop the authentication
    // requirement the operator configured.
    for secret in [
        "  0123456789abcdef0123456789abcdef  ",
        "\t0123456789abcdef0123456789abcdef\n",
        "                                ",
    ] {
        let gate = DatagramClientAddressGate::new(trusted("10.0.0.0/8"), Some(secret));
        assert!(
            gate.requires_authentication(),
            "a nonempty secret must always require authentication: {secret:?}"
        );

        // The key is exactly the configured bytes: a tag minted over them
        // verifies, and one minted over the trimmed form does not.
        let exact = HmacSha256Key::new_from_slice(secret.as_bytes()).expect("hmac key");
        let datagram = encode_datagram_with_metadata(
            addr("203.0.113.9:41234"),
            addr("10.0.0.5:5353"),
            b"payload",
            Some(&exact),
        );
        assert_eq!(
            gate.decode(&datagram, &addr("10.0.0.1:60000"))
                .expect("the exact configured bytes must be the key")
                .forwarded,
            Some(addr("203.0.113.9:41234"))
        );

        let trimmed_bytes = secret.trim().as_bytes().to_vec();
        if trimmed_bytes != secret.as_bytes() {
            let trimmed = HmacSha256Key::new_from_slice(&trimmed_bytes).expect("hmac key");
            let forged = encode_datagram_with_metadata(
                addr("203.0.113.9:41234"),
                addr("10.0.0.5:5353"),
                b"payload",
                Some(&trimmed),
            );
            assert_eq!(
                gate.decode(&forged, &addr("10.0.0.1:60000"))
                    .expect_err("a tag over the trimmed secret must not verify"),
                DatagramMetadataError::AuthenticationTagMismatch
            );
        }
    }
}

#[test]
fn only_an_absent_or_empty_secret_leaves_the_unauthenticated_posture() {
    for secret in [None, Some("")] {
        let gate = DatagramClientAddressGate::new(trusted("10.0.0.0/8"), secret);
        assert!(
            !gate.requires_authentication(),
            "{secret:?} is the documented address-trust posture"
        );
        let datagram = encode_datagram_with_metadata(
            addr("203.0.113.9:41234"),
            addr("10.0.0.5:5353"),
            b"payload",
            None,
        );
        assert_eq!(
            gate.decode(&datagram, &addr("10.0.0.1:60000"))
                .expect("address trust admits an untagged datagram")
                .forwarded,
            Some(addr("203.0.113.9:41234"))
        );
    }
}

#[test]
fn a_short_secret_is_a_startup_error_that_reports_neither_value_nor_length() {
    // Startup validation is what stops a weak MAC key from ever reaching a
    // listener; the gate itself has no length opinion.
    let short = "0123456789abcdef";
    let error =
        validate_secret(Some(short)).expect_err("a secret below the minimum must fail startup");
    assert!(
        error.contains("FERRUM_DATAGRAM_PROXY_PROTOCOL_SECRET"),
        "the diagnostic must name the variable: {error}"
    );
    assert!(
        !error.contains(short),
        "the diagnostic must not echo the secret: {error}"
    );
    assert!(
        !error.contains(&short.len().to_string()),
        "the diagnostic must not report the secret's length: {error}"
    );

    // Exactly the minimum, and the absent/empty postures, are accepted.
    for accepted in [None, Some(""), Some(SECRET)] {
        assert!(
            validate_secret(accepted).is_ok(),
            "{accepted:?} must pass startup validation"
        );
    }
}

#[test]
fn a_proxy_command_must_declare_the_datagram_transport_even_with_af_unspec() {
    let gate = address_trust_gate();

    // A TCP `STREAM` header whose family nibble is zeroed: without the
    // transport check on `AF_UNSPEC` this would be admitted verbatim on a
    // udp/dtls listener, which is exactly the replay the module refuses.
    let stream_unspec = header(0x21, 0x01, &[], b"payload");
    assert_eq!(
        gate.decode(&stream_unspec, &addr("10.0.0.1:60000"))
            .expect_err("a STREAM header must not be laundered through AF_UNSPEC"),
        DatagramMetadataError::NonDatagramTransport(0x01)
    );

    // `UNSPEC` transport is refused on the same grounds: a PROXY envelope must
    // state that it describes a datagram flow.
    let unspec_transport = header(0x21, 0x00, &[], b"payload");
    assert_eq!(
        gate.decode(&unspec_transport, &addr("10.0.0.1:60000"))
            .expect_err("a PROXY envelope must declare DGRAM"),
        DatagramMetadataError::NonDatagramTransport(0x00)
    );

    // The well-formed address-less shape is still admitted, with the socket
    // peer left as the only identity.
    let dgram_unspec = header(0x21, 0x02, &[], b"probe");
    let decoded = gate
        .decode(&dgram_unspec, &addr("10.0.0.1:60000"))
        .expect("PROXY + AF_UNSPEC + DGRAM is a valid address-less envelope");
    assert_eq!(decoded.forwarded, None);
    assert_eq!(decoded.payload, b"probe");

    // `LOCAL` keeps the spec's convention: it never sets an identity, so the
    // conventional `0x00` transport byte stays valid.
    let local = header(0x20, 0x00, &[], b"probe");
    assert_eq!(
        gate.decode(&local, &addr("10.0.0.1:60000"))
            .expect("LOCAL probes remain admitted")
            .forwarded,
        None
    );
}
