//! Datagram client-address metadata gate (issues #3289, #3856, #3862).
//!
//! The gate is the whole trust boundary for `stream_proxy_protocol: true` on a
//! `udp` / `dtls` listener: it decides whether a datagram's asserted client
//! address may become `client_ip`, and it must refuse — never downgrade —
//! everything else. These tests pin the wire format, the trust decision, the
//! authentication decision, the **listener-domain binding** that keeps one
//! process-global secret from making an envelope portable between listeners,
//! the **bounded authenticated freshness / anti-replay** contract, and each
//! fail-closed refusal.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use ferrum_edge::fips::approved::HmacSha256Key;
use ferrum_edge::proxy::client_ip::TrustedProxies;
use ferrum_edge::proxy::datagram_client_address::{
    AUTH_TAG_LEN, AUTH_TLV_TYPE, DatagramClientAddressGate, DatagramClientIdentity,
    DatagramEnvelopeAuth, DatagramEnvelopeForm, DatagramFreshness, DatagramListenerBinding,
    DatagramListenerProtocol, DatagramMetadataError, FRESHNESS_HORIZON_MS, FRESHNESS_TLV_LEN,
    FRESHNESS_TLV_TYPE, FRESHNESS_VALUE_LEN, MAX_REPLAY_SENDERS, MIN_DATAGRAM_SECRET_BYTES,
    REPLAY_WINDOW_BITS, encode_datagram_with_metadata, unix_now_millis,
};

const SIG: &[u8; 12] = b"\r\n\r\n\x00\r\nQUIT\n";
const SECRET: &str = "0123456789abcdef0123456789abcdef";
/// Destination port encoded by the unit-test fixtures (`10.0.0.5:5353`).
const LISTENER_PORT: u16 = 5353;
/// A second listener in the same process, sharing the one root secret.
const OTHER_LISTENER_PORT: u16 = 5354;

fn addr(value: &str) -> SocketAddr {
    value.parse().expect("test socket address")
}

/// The balancer's socket peer in every fixture.
fn peer() -> SocketAddr {
    addr("10.0.0.1:60000")
}

fn trusted(cidrs: &str) -> Arc<TrustedProxies> {
    Arc::new(TrustedProxies::parse_strict(cidrs, "test").expect("valid trust list"))
}

/// The canonical bind address the fixtures use: a specific IPv4 address, so the
/// wildcard-bind cases below are visibly a different domain.
fn bind_ip() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))
}

/// Binding for a plain-UDP listener on `port` at the fixture bind address.
fn udp_binding(port: u16) -> DatagramListenerBinding {
    DatagramListenerBinding::new(DatagramListenerProtocol::Udp, bind_ip(), port)
}

fn gate_for(binding: DatagramListenerBinding, secret: Option<&str>) -> DatagramClientAddressGate {
    DatagramClientAddressGate::new(trusted("10.0.0.0/8,127.0.0.1"), secret, binding, 0)
}

/// Gate trusting the load balancer at `10.0.0.0/8`, without authentication.
fn address_trust_gate() -> DatagramClientAddressGate {
    gate_for(udp_binding(LISTENER_PORT), None)
}

/// Gate trusting the same peers and additionally requiring the MAC tag and the
/// authenticated freshness record.
fn authenticated_gate() -> DatagramClientAddressGate {
    gate_for(udp_binding(LISTENER_PORT), Some(SECRET))
}

fn key() -> HmacSha256Key {
    HmacSha256Key::new_from_slice(SECRET.as_bytes()).expect("hmac key")
}

/// The startup validator for the same variable the gate keys itself from.
fn validate_secret(secret: Option<&str>) -> Result<(), String> {
    ferrum_edge::config::env_config::validate_datagram_proxy_protocol_secret_value(secret)
}

/// A sender's authenticated freshness counter, as a real datagram balancer would
/// keep it: one stable id, one epoch, a monotonic sequence.
struct Sender {
    key: HmacSha256Key,
    sender_id: u32,
    epoch: u64,
    next_sequence: u64,
    timestamp_ms: u64,
}

impl Sender {
    fn new(sender_id: u32) -> Self {
        Self::with_key(sender_id, key())
    }

    fn with_key(sender_id: u32, key: HmacSha256Key) -> Self {
        Self {
            key,
            sender_id,
            epoch: 7,
            next_sequence: 0,
            timestamp_ms: unix_now_millis(),
        }
    }

    /// Mint one authenticated datagram for `binding` at an explicit sequence.
    fn at(
        &self,
        binding: &DatagramListenerBinding,
        form: DatagramEnvelopeForm,
        payload: &[u8],
        sequence: u64,
    ) -> Vec<u8> {
        let freshness = DatagramFreshness {
            sender_id: self.sender_id,
            epoch: self.epoch,
            sequence,
            timestamp_ms: self.timestamp_ms,
        };
        let auth = DatagramEnvelopeAuth {
            key: &self.key,
            binding,
            freshness,
        };
        encode_datagram_with_metadata(form, payload, Some(&auth))
    }

    /// Mint one authenticated datagram, consuming the next sequence.
    fn next(
        &mut self,
        binding: &DatagramListenerBinding,
        form: DatagramEnvelopeForm,
        payload: &[u8],
    ) -> Vec<u8> {
        let sequence = self.next_sequence;
        self.next_sequence += 1;
        self.at(binding, form, payload, sequence)
    }
}

/// The address-bearing IPv4 form, declaring `port` as its destination.
fn v4_form(port: u16) -> DatagramEnvelopeForm {
    DatagramEnvelopeForm::Forwarded {
        source: addr("203.0.113.9:41234"),
        destination: SocketAddr::new(bind_ip(), port),
    }
}

/// The address-bearing IPv6 form, declaring `port` as its destination.
fn v6_form(port: u16) -> DatagramEnvelopeForm {
    DatagramEnvelopeForm::Forwarded {
        source: addr("[2001:db8::10]:41234"),
        destination: addr(&format!("[2001:db8::1]:{port}")),
    }
}

/// The four envelope forms an authenticated sender may emit, by label. Selected
/// through a helper rather than a table so every form-parameterized test reads
/// the same way.
fn envelope_form(label: &str, port: u16) -> DatagramEnvelopeForm {
    match label {
        "LOCAL" => DatagramEnvelopeForm::Local,
        "AF_UNSPEC" => DatagramEnvelopeForm::Unspec,
        "IPv4" => v4_form(port),
        "IPv6" => v6_form(port),
        other => panic!("unknown envelope form {other}"),
    }
}

/// Every envelope form, for tests that must cover all four.
const ALL_FORMS: [&str; 4] = ["LOCAL", "AF_UNSPEC", "IPv4", "IPv6"];

/// An unauthenticated envelope: the documented address-trust posture, which has
/// neither cryptographic authenticity nor freshness.
fn plain(form: DatagramEnvelopeForm, payload: &[u8]) -> Vec<u8> {
    encode_datagram_with_metadata(form, payload, None)
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

/// Byte offset of the freshness TLV inside an authenticated IPv4 envelope:
/// 16-byte fixed header + 12-byte AF_INET block.
const FRESHNESS_TLV_AT: usize = 16 + 12;
/// Byte offset of the freshness TLV *value* in the same envelope.
const FRESHNESS_VALUE_AT: usize = FRESHNESS_TLV_AT + 3;

// ===========================================================================
// Wire format, trust, and fail-closed parsing (issue #3289)
// ===========================================================================

#[test]
fn trusted_peer_with_valid_envelope_yields_forwarded_client_and_payload() {
    let gate = address_trust_gate();
    let datagram = plain(v4_form(LISTENER_PORT), b"question");

    let decoded = gate
        .decode(&datagram, &peer())
        .expect("valid envelope from a trusted peer is admitted");

    assert_eq!(decoded.forwarded, Some(addr("203.0.113.9:41234")));
    assert_eq!(decoded.payload, b"question");
}

#[test]
fn ipv6_envelope_round_trips() {
    let gate = address_trust_gate();
    let datagram = plain(v6_form(LISTENER_PORT), b"v6");

    let decoded = gate
        .decode(&datagram, &peer())
        .expect("ipv6 envelope is admitted");

    assert_eq!(decoded.forwarded, Some(addr("[2001:db8::10]:41234")));
    assert_eq!(decoded.payload, b"v6");
}

#[test]
fn ipv4_mapped_forwarded_client_is_canonicalized_for_session_identity() {
    let gate = address_trust_gate();
    let source = "::ffff:203.0.113.9"
        .parse::<std::net::Ipv6Addr>()
        .expect("mapped source");
    let destination = "2001:db8::1"
        .parse::<std::net::Ipv6Addr>()
        .expect("IPv6 destination");
    let mut block = Vec::new();
    block.extend_from_slice(&source.octets());
    block.extend_from_slice(&destination.octets());
    block.extend_from_slice(&41234u16.to_be_bytes());
    block.extend_from_slice(&LISTENER_PORT.to_be_bytes());
    let datagram = header(0x21, 0x22, &block, b"mapped");

    let decoded = gate
        .decode(&datagram, &peer())
        .expect("mapped IPv4 envelope is admitted");

    assert_eq!(decoded.forwarded, Some(addr("203.0.113.9:41234")));
    assert_eq!(decoded.payload, b"mapped");
}

#[test]
fn untrusted_peer_is_refused_before_the_envelope_is_parsed() {
    let gate = address_trust_gate();
    let datagram = plain(v4_form(LISTENER_PORT), b"spoofed");

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
        .decode(b"no envelope here at all", &peer())
        .expect_err("a bare payload must not be forwarded");
    assert_eq!(error, DatagramMetadataError::InvalidSignature);

    let error = gate
        .decode(&SIG[..8], &peer())
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
        .decode(&datagram, &peer())
        .expect_err("stream transport must not set a datagram client identity");
    assert_eq!(error, DatagramMetadataError::NonDatagramTransport(0x01));
}

#[test]
fn unsupported_family_and_command_are_refused() {
    let gate = address_trust_gate();

    // AF_UNIX cannot address a datagram client.
    let unix = header(0x21, 0x32, &[0u8; 20], b"payload");
    assert_eq!(
        gate.decode(&unix, &peer())
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
        gate.decode(&bad_command, &peer())
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
        gate.decode(&bad_version, &peer())
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
        gate.decode(&truncated, &peer())
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
        gate.decode(&oversized, &peer())
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
        gate.decode(&short_family, &peer())
            .expect_err("family/length mismatch must be refused"),
        DatagramMetadataError::AddressBlockTooShortForFamily { family: 0x02, .. }
    ));
}

#[test]
fn local_command_keeps_the_socket_peer_as_the_identity() {
    let gate = address_trust_gate();
    // A balancer health probe: LOCAL command, no forwarded address.
    let datagram = plain(DatagramEnvelopeForm::Local, b"probe");

    let decoded = gate
        .decode(&datagram, &peer())
        .expect("LOCAL probes are admitted");
    assert_eq!(decoded.forwarded, None);
    assert_eq!(decoded.payload, b"probe");

    // With no forwarded address the resolved identity is the socket peer.
    let identity = DatagramClientIdentity {
        socket_peer: peer(),
        forwarded: decoded.forwarded,
    };
    assert_eq!(identity.resolved(), peer());
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

    let decoded = gate.decode(&datagram, &peer()).expect("LOCAL is admitted");
    assert_eq!(decoded.forwarded, None);
}

#[test]
fn malformed_tlv_is_refused() {
    let gate = address_trust_gate();
    let mut block = inet_block("203.0.113.9:41234", "10.0.0.5:5353");
    // TLV declaring 64 value bytes with only 2 present inside the block.
    block.push(0x05);
    block.extend_from_slice(&64u16.to_be_bytes());
    block.extend_from_slice(&[0u8; 2]);
    let datagram = header(0x21, 0x12, &block, b"payload");

    assert_eq!(
        gate.decode(&datagram, &peer())
            .expect_err("a TLV running past the address block must be refused"),
        DatagramMetadataError::MalformedTlv
    );
}

#[test]
fn empty_trust_list_admits_nothing() {
    let binding = udp_binding(LISTENER_PORT);
    let gate = DatagramClientAddressGate::new(trusted(""), None, binding, 0);
    assert!(!gate.has_trusted_peers());
    let datagram = plain(v4_form(LISTENER_PORT), b"payload");
    assert_eq!(
        gate.decode(&datagram, &peer())
            .expect_err("with no trusted peers nothing may assert a client identity"),
        DatagramMetadataError::UntrustedPeer
    );
}

#[test]
fn session_binding_rejects_a_changed_forwarded_client() {
    let first = DatagramClientIdentity {
        socket_peer: peer(),
        forwarded: Some(addr("203.0.113.9:41234")),
    };
    let second = DatagramClientIdentity {
        socket_peer: peer(),
        forwarded: Some(addr("198.51.100.7:41234")),
    };

    assert!(first.matches_session(Some(addr("203.0.113.9:41234"))));
    assert!(!second.matches_session(Some(addr("203.0.113.9:41234"))));
    // A gate-less listener binds `None` on both sides and always matches.
    assert!(DatagramClientIdentity::direct(peer()).matches_session(None));
}

#[test]
fn direct_identity_reports_the_socket_peer_for_both_roles() {
    let identity = DatagramClientIdentity::direct(addr("198.51.100.7:41234"));
    assert_eq!(identity.socket_peer, addr("198.51.100.7:41234"));
    assert_eq!(identity.resolved(), addr("198.51.100.7:41234"));
    assert_eq!(identity.forwarded, None);
}

#[test]
fn a_proxy_command_must_declare_the_datagram_transport_even_with_af_unspec() {
    let gate = address_trust_gate();

    // A TCP `STREAM` header whose family nibble is zeroed: without the
    // transport check on `AF_UNSPEC` this would be admitted verbatim on a
    // udp/dtls listener, which is exactly the replay the module refuses.
    let stream_unspec = header(0x21, 0x01, &[], b"payload");
    assert_eq!(
        gate.decode(&stream_unspec, &peer())
            .expect_err("a STREAM header must not be laundered through AF_UNSPEC"),
        DatagramMetadataError::NonDatagramTransport(0x01)
    );

    // `UNSPEC` transport is refused on the same grounds: a PROXY envelope must
    // state that it describes a datagram flow.
    let unspec_transport = header(0x21, 0x00, &[], b"payload");
    assert_eq!(
        gate.decode(&unspec_transport, &peer())
            .expect_err("a PROXY envelope must declare DGRAM"),
        DatagramMetadataError::NonDatagramTransport(0x00)
    );

    // The well-formed address-less shape is still admitted, with the socket
    // peer left as the only identity.
    let dgram_unspec = plain(DatagramEnvelopeForm::Unspec, b"probe");
    let decoded = gate
        .decode(&dgram_unspec, &peer())
        .expect("PROXY + AF_UNSPEC + DGRAM is a valid address-less envelope");
    assert_eq!(decoded.forwarded, None);
    assert_eq!(decoded.payload, b"probe");

    // `LOCAL` keeps the spec's convention: it never sets an identity, so the
    // conventional `0x00` transport byte stays valid.
    let local = plain(DatagramEnvelopeForm::Local, b"probe");
    assert_eq!(
        gate.decode(&local, &peer())
            .expect("LOCAL probes remain admitted")
            .forwarded,
        None
    );
}

// ===========================================================================
// Authentication (issue #3289)
// ===========================================================================

#[test]
fn authenticated_gate_admits_a_correctly_tagged_and_fresh_datagram() {
    let gate = authenticated_gate();
    assert!(gate.requires_authentication());
    let binding = udp_binding(LISTENER_PORT);
    let mut sender = Sender::new(1);
    let datagram = sender.next(&binding, v4_form(LISTENER_PORT), b"authenticated");

    let decoded = gate
        .decode(&datagram, &peer())
        .expect("valid tag and freshness are admitted");
    assert_eq!(decoded.forwarded, Some(addr("203.0.113.9:41234")));
    assert_eq!(decoded.payload, b"authenticated");
}

#[test]
fn authenticated_gate_refuses_an_untagged_datagram() {
    let gate = authenticated_gate();
    let datagram = plain(v4_form(LISTENER_PORT), b"unsigned");

    assert_eq!(
        gate.decode(&datagram, &peer())
            .expect_err("an untagged datagram must not be admitted"),
        DatagramMetadataError::MissingAuthenticationTag
    );
}

#[test]
fn authenticated_gate_refuses_a_tag_minted_under_another_secret() {
    let gate = authenticated_gate();
    let binding = udp_binding(LISTENER_PORT);
    let other = HmacSha256Key::new_from_slice(b"ffffffffffffffffffffffffffffffff").expect("key");
    let mut sender = Sender::with_key(1, other);
    let datagram = sender.next(&binding, v4_form(LISTENER_PORT), b"forged");

    assert_eq!(
        gate.decode(&datagram, &peer())
            .expect_err("a foreign tag must not verify"),
        DatagramMetadataError::AuthenticationTagMismatch
    );
}

#[test]
fn tag_binds_the_forwarded_address_the_payload_and_the_freshness_record() {
    let gate = authenticated_gate();
    let binding = udp_binding(LISTENER_PORT);
    let sender = Sender::new(1);
    let original = sender.at(&binding, v4_form(LISTENER_PORT), b"payload", 0);

    // Rewrite the forwarded source address in place: the tag must fail.
    let mut swapped_address = original.clone();
    swapped_address[16] = 198;
    swapped_address[17] = 51;
    swapped_address[18] = 100;
    swapped_address[19] = 7;
    assert_eq!(
        gate.decode(&swapped_address, &peer())
            .expect_err("address substitution must break the tag"),
        DatagramMetadataError::AuthenticationTagMismatch
    );

    // Rewrite the payload in place: the tag must fail there too.
    let mut swapped_payload = original.clone();
    let last = swapped_payload.len() - 1;
    swapped_payload[last] ^= 0xff;
    assert_eq!(
        gate.decode(&swapped_payload, &peer())
            .expect_err("payload substitution must break the tag"),
        DatagramMetadataError::AuthenticationTagMismatch
    );

    // Re-number the authenticated sequence: freshness must be inside the MAC,
    // or an attacker could renumber a captured datagram to walk straight past
    // the replay window without ever holding the secret.
    let mut renumbered = original.clone();
    renumbered[FRESHNESS_VALUE_AT + 20] ^= 0xff;
    assert_eq!(
        gate.decode(&renumbered, &peer())
            .expect_err("re-numbering the sequence must break the tag"),
        DatagramMetadataError::AuthenticationTagMismatch
    );

    // Unmodified, it still verifies — so the refusals above are about the
    // substitution and not about the fixture.
    assert!(gate.decode(&original, &peer()).is_ok());
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
    let two_tags = header(0x21, 0x12, &two_tags, b"payload");
    assert_eq!(
        gate.decode(&two_tags, &peer())
            .expect_err("two tags are ambiguous and must be refused"),
        DatagramMetadataError::DuplicateAuthenticationTag
    );

    let mut short_tag = fixed.clone();
    short_tag.push(AUTH_TLV_TYPE);
    short_tag.extend_from_slice(&4u16.to_be_bytes());
    short_tag.extend_from_slice(&[0u8; 4]);
    let short_tag = header(0x21, 0x12, &short_tag, b"payload");
    assert_eq!(
        gate.decode(&short_tag, &peer())
            .expect_err("a short tag must be refused"),
        DatagramMetadataError::InvalidAuthenticationTagLength(4)
    );
}

#[test]
fn unauthenticated_gate_does_not_honor_a_supplied_tag_or_freshness_as_proof() {
    // With no secret configured a tag is unverifiable. It must not be treated
    // as authentication, and neither it nor the freshness record may leak into
    // the payload.
    let gate = address_trust_gate();
    assert!(!gate.requires_authentication());
    let binding = udp_binding(LISTENER_PORT);
    let sender = Sender::new(1);
    let datagram = sender.at(&binding, v4_form(LISTENER_PORT), b"payload", 0);

    let decoded = gate
        .decode(&datagram, &peer())
        .expect("address trust still applies");
    assert_eq!(decoded.payload, b"payload");
    assert_eq!(decoded.forwarded, Some(addr("203.0.113.9:41234")));

    // No replay state is created either: the unauthenticated posture has no
    // freshness contract at all, which is exactly what the docs must say.
    assert_eq!(gate.tracked_replay_senders(), 0);
    assert!(
        gate.decode(&datagram, &peer()).is_ok(),
        "the address-trust posture deliberately admits a verbatim repeat"
    );
}

#[test]
fn diagnostics_are_field_specific_and_carry_no_payload() {
    let gate = authenticated_gate();
    let datagram = plain(v4_form(LISTENER_PORT), b"super-secret-payload");
    let error = gate.decode(&datagram, &peer()).expect_err("untagged");
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
    let binding = udp_binding(LISTENER_PORT);
    for secret in [
        "  0123456789abcdef0123456789abcdef  ",
        "\t0123456789abcdef0123456789abcdef\n",
        "                                ",
    ] {
        let gate = gate_for(binding, Some(secret));
        assert!(
            gate.requires_authentication(),
            "a nonempty secret must always require authentication: {secret:?}"
        );

        // The key is exactly the configured bytes: a tag minted over them
        // verifies, and one minted over the trimmed form does not.
        let exact = HmacSha256Key::new_from_slice(secret.as_bytes()).expect("hmac key");
        let sender = Sender::with_key(1, exact);
        let datagram = sender.at(&binding, v4_form(LISTENER_PORT), b"payload", 0);
        assert_eq!(
            gate.decode(&datagram, &peer())
                .expect("the exact configured bytes must be the key")
                .forwarded,
            Some(addr("203.0.113.9:41234"))
        );

        let trimmed_bytes = secret.trim().as_bytes().to_vec();
        if trimmed_bytes != secret.as_bytes() {
            let trimmed = HmacSha256Key::new_from_slice(&trimmed_bytes).expect("hmac key");
            let forger = Sender::with_key(2, trimmed);
            let forged = forger.at(&binding, v4_form(LISTENER_PORT), b"payload", 0);
            assert_eq!(
                gate.decode(&forged, &peer())
                    .expect_err("a tag over the trimmed secret must not verify"),
                DatagramMetadataError::AuthenticationTagMismatch
            );
        }
    }
}

#[test]
fn only_an_absent_or_empty_secret_leaves_the_unauthenticated_posture() {
    for secret in [None, Some("")] {
        let gate = gate_for(udp_binding(LISTENER_PORT), secret);
        assert!(
            !gate.requires_authentication(),
            "{secret:?} is the documented address-trust posture"
        );
        let datagram = plain(v4_form(LISTENER_PORT), b"payload");
        assert_eq!(
            gate.decode(&datagram, &peer())
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

// ===========================================================================
// Exact listener-domain binding (issue #3856)
// ===========================================================================

/// The core #3856 contract. With one process-global root secret, an unchanged
/// envelope minted for listener A must never authenticate on listener B — for
/// **every** command and family, including the two forms that carry no
/// forwarded identity and therefore have no declared destination to compare.
#[test]
fn every_authenticated_envelope_form_is_bound_to_the_receiving_listener() {
    let binding_a = udp_binding(LISTENER_PORT);
    let binding_b = udp_binding(OTHER_LISTENER_PORT);
    let gate_a = gate_for(binding_a, Some(SECRET));
    let gate_b = gate_for(binding_b, Some(SECRET));

    for (sequence, &label) in ALL_FORMS.iter().enumerate() {
        let sequence = sequence as u64;
        let form_a = envelope_form(label, LISTENER_PORT);
        let form_b = envelope_form(label, OTHER_LISTENER_PORT);
        let sender = Sender::new(11);
        let for_a = sender.at(&binding_a, form_a, b"payload", sequence);

        // Admitted on the listener it was minted for.
        gate_a
            .decode(&for_a, &peer())
            .unwrap_or_else(|error| panic!("{label} must be admitted on A: {error}"));

        // Byte-for-byte on listener B — only the outer UDP destination port
        // changed, which is outside the envelope — it must be refused.
        let error = gate_b
            .decode(&for_a, &peer())
            .expect_err("a cross-listener envelope must not authenticate");
        assert!(
            matches!(
                error,
                DatagramMetadataError::AuthenticationTagMismatch
                    | DatagramMetadataError::ListenerBindingMismatch
            ),
            "{label} cross-listener replay must fail closed, got {error:?}"
        );

        // A correctly minted envelope for B is still admitted, so the refusal
        // above is about the binding and not about listener B being broken.
        let sender_b = Sender::new(12);
        let for_b = sender_b.at(&binding_b, form_b, b"payload", sequence);
        gate_b
            .decode(&for_b, &peer())
            .unwrap_or_else(|error| panic!("{label} must be admitted on B: {error}"));
    }
}

/// Numeric port alone is not the listener identity. Two listeners sharing one
/// numeric port but differing in receive-boundary protocol or in bind address
/// are different cryptographic domains, and wildcard versus specific binds have
/// an explicit canonical identity.
#[test]
fn listener_identity_covers_protocol_and_bind_address_not_just_the_port() {
    let udp = udp_binding(LISTENER_PORT);
    let dtls =
        DatagramListenerBinding::new(DatagramListenerProtocol::Dtls, bind_ip(), LISTENER_PORT);
    let wildcard_v4 = DatagramListenerBinding::new(
        DatagramListenerProtocol::Udp,
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        LISTENER_PORT,
    );
    let wildcard_v6 = DatagramListenerBinding::new(
        DatagramListenerProtocol::Udp,
        "::".parse().expect("v6 wildcard"),
        LISTENER_PORT,
    );
    let other_specific = DatagramListenerBinding::new(
        DatagramListenerProtocol::Udp,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 6)),
        LISTENER_PORT,
    );

    // Every canonical domain must be distinct, so no pair of these listeners
    // could ever verify each other's envelopes.
    let all = [udp, dtls, wildcard_v4, wildcard_v6, other_specific];
    for (i, left) in all.iter().enumerate() {
        for (j, right) in all.iter().enumerate() {
            if i == j {
                continue;
            }
            assert_ne!(
                left.canonical_domain(),
                right.canonical_domain(),
                "listener domains {i} and {j} collide"
            );
        }
    }

    // The cryptographic consequence: a DTLS-boundary envelope for this port does
    // not verify on the plain-UDP listener sharing the same numeric port.
    let sender = Sender::new(21);
    let for_dtls = sender.at(&dtls, v4_form(LISTENER_PORT), b"p", 0);
    assert_eq!(
        gate_for(udp, Some(SECRET))
            .decode(&for_dtls, &peer())
            .expect_err("a DTLS-boundary envelope must not verify on the UDP boundary"),
        DatagramMetadataError::AuthenticationTagMismatch
    );

    // A wildcard bind is likewise a different domain from a specific bind.
    let for_wildcard = sender.at(&wildcard_v4, v4_form(LISTENER_PORT), b"p", 1);
    assert_eq!(
        gate_for(udp, Some(SECRET))
            .decode(&for_wildcard, &peer())
            .expect_err("a wildcard-bind envelope must not verify on a specific bind"),
        DatagramMetadataError::AuthenticationTagMismatch
    );
}

/// The bind address is canonicalized, so an IPv4-mapped IPv6 bind and the plain
/// IPv4 bind of the same address are one domain rather than two — otherwise a
/// dual-stack listener's reload could silently change the key domain.
#[test]
fn canonical_listener_identity_folds_ipv4_mapped_bind_addresses() {
    let plain_v4 = udp_binding(LISTENER_PORT);
    let mapped = DatagramListenerBinding::new(
        DatagramListenerProtocol::Udp,
        "::ffff:10.0.0.5".parse().expect("mapped bind"),
        LISTENER_PORT,
    );
    assert_eq!(plain_v4.canonical_domain(), mapped.canonical_domain());
    assert_eq!(plain_v4.bind_addr(), mapped.bind_addr());
    assert_eq!(mapped.protocol(), DatagramListenerProtocol::Udp);
    assert_eq!(mapped.port(), LISTENER_PORT);

    let sender = Sender::new(22);
    let datagram = sender.at(&mapped, v4_form(LISTENER_PORT), b"p", 0);
    gate_for(plain_v4, Some(SECRET))
        .decode(&datagram, &peer())
        .expect("an IPv4-mapped bind is the same domain as the plain IPv4 bind");
}

/// The declared-destination check is retained as defense in depth, and is what
/// gives an address-bearing cross-listener envelope the specific
/// `listener_binding_mismatch` reason.
#[test]
fn identity_bearing_envelope_must_declare_the_receiving_listener_port() {
    let datagram = plain(v4_form(LISTENER_PORT), b"payload");

    address_trust_gate()
        .decode(&datagram, &peer())
        .expect("matching destination port is admitted");

    let error = gate_for(udp_binding(OTHER_LISTENER_PORT), None)
        .decode(&datagram, &peer())
        .expect_err("a valid envelope for another listener port must be refused");
    assert_eq!(error, DatagramMetadataError::ListenerBindingMismatch);
    assert_eq!(error.reason(), "listener_binding_mismatch");
}

#[test]
fn ipv6_destination_port_is_bound_to_the_receiving_listener() {
    let datagram = plain(v6_form(LISTENER_PORT), b"v6");

    address_trust_gate()
        .decode(&datagram, &peer())
        .expect("matching IPv6 destination port is admitted");

    assert_eq!(
        gate_for(udp_binding(9), None)
            .decode(&datagram, &peer())
            .expect_err("IPv6 dest-port mismatch must be refused"),
        DatagramMetadataError::ListenerBindingMismatch
    );
}

/// Ordering contract: the declared-destination check runs before the MAC, so a
/// cross-listener address-bearing envelope reports the specific binding reason
/// rather than a generic tag failure — while a same-listener envelope with no
/// tag still reports the missing tag.
#[test]
fn binding_check_precedes_the_tag_without_masking_a_same_listener_tag_failure() {
    let gate = authenticated_gate();

    let cross = plain(v4_form(OTHER_LISTENER_PORT), b"replay");
    assert_eq!(
        gate.decode(&cross, &peer())
            .expect_err("a cross-listener envelope reports the binding mismatch"),
        DatagramMetadataError::ListenerBindingMismatch
    );

    let same = plain(v4_form(LISTENER_PORT), b"unsigned");
    assert_eq!(
        gate.decode(&same, &peer())
            .expect_err("a same-listener untagged envelope reports the missing tag"),
        DatagramMetadataError::MissingAuthenticationTag
    );
}

/// `LOCAL` and `AF_UNSPEC` carry no declared destination, so the
/// defense-in-depth comparison cannot apply to them — which is precisely why the
/// cryptographic binding must, and does (see
/// `every_authenticated_envelope_form_is_bound_to_the_receiving_listener`). In
/// the unauthenticated posture they remain admitted with no identity.
#[test]
fn local_and_af_unspec_have_no_declared_destination_to_compare() {
    let gate = gate_for(udp_binding(9), None);

    let local_with_addresses = header(
        0x20,
        0x12,
        &inet_block("203.0.113.9:41234", "10.0.0.5:5353"),
        b"probe",
    );
    let decoded = gate
        .decode(&local_with_addresses, &peer())
        .expect("LOCAL ignores the address block, including dest port");
    assert_eq!(decoded.forwarded, None);

    let unspec = plain(DatagramEnvelopeForm::Unspec, b"probe");
    let decoded = gate
        .decode(&unspec, &peer())
        .expect("AF_UNSPEC still confers no identity and needs no dest port");
    assert_eq!(decoded.forwarded, None);
}

#[test]
fn listener_binding_mismatch_diagnostic_is_material_free() {
    let binding = udp_binding(LISTENER_PORT);
    let sender = Sender::new(31);
    let form = v4_form(LISTENER_PORT);
    let datagram = sender.at(&binding, form, b"super-secret-payload", 0);
    let error = gate_for(udp_binding(8080), Some(SECRET))
        .decode(&datagram, &peer())
        .expect_err("wrong listener");
    let rendered = error.to_string();

    assert_eq!(error.reason(), "listener_binding_mismatch");
    assert!(
        rendered.contains("destination port"),
        "diagnostic must name the field: {rendered}"
    );
    assert!(
        !rendered.contains("5353") && !rendered.contains("8080"),
        "diagnostic must not echo dest or listener ports: {rendered}"
    );
    assert!(
        !rendered.contains("203.0.113.9") && !rendered.contains("10.0.0.5"),
        "diagnostic must not echo envelope addresses: {rendered}"
    );
    assert!(
        !rendered.contains("super-secret-payload") && !rendered.contains(SECRET),
        "diagnostic must not echo payload or secret: {rendered}"
    );
}

// ===========================================================================
// Bounded authenticated freshness / anti-replay (issue #3862)
// ===========================================================================

/// The authenticated wire layout the sender contract depends on. Pinned so a
/// future reordering cannot silently move the fields the offsets above assume.
#[test]
fn authenticated_envelope_layout_is_the_documented_one() {
    let binding = udp_binding(LISTENER_PORT);
    let sender = Sender::new(41);
    let form = v4_form(LISTENER_PORT);
    let datagram = sender.at(&binding, form, b"payload", 3);

    assert_eq!(&datagram[..12], SIG);
    assert_eq!(datagram[12], 0x21, "version 2, PROXY command");
    assert_eq!(datagram[13], 0x12, "AF_INET + DGRAM");
    let addr_len = u16::from_be_bytes([datagram[14], datagram[15]]) as usize;
    assert_eq!(
        addr_len,
        12 + FRESHNESS_TLV_LEN + 3 + AUTH_TAG_LEN,
        "the address block covers the addresses, the freshness TLV, and the tag"
    );

    assert_eq!(datagram[FRESHNESS_TLV_AT], FRESHNESS_TLV_TYPE);
    let declared = u16::from_be_bytes([
        datagram[FRESHNESS_TLV_AT + 1],
        datagram[FRESHNESS_TLV_AT + 2],
    ]);
    assert_eq!(declared as usize, FRESHNESS_VALUE_LEN);

    let value = &datagram[FRESHNESS_VALUE_AT..FRESHNESS_VALUE_AT + FRESHNESS_VALUE_LEN];
    assert_eq!(value[0], 1, "freshness record version");
    let sender_id = u32::from_be_bytes(value[1..5].try_into().expect("sender id"));
    assert_eq!(sender_id, 41);
    let epoch = u64::from_be_bytes(value[5..13].try_into().expect("epoch"));
    assert_eq!(epoch, 7);
    let sequence = u64::from_be_bytes(value[13..21].try_into().expect("sequence"));
    assert_eq!(sequence, 3);

    let auth_tlv = FRESHNESS_VALUE_AT + FRESHNESS_VALUE_LEN;
    assert_eq!(datagram[auth_tlv], AUTH_TLV_TYPE);
    assert_eq!(
        16 + addr_len,
        auth_tlv + 3 + AUTH_TAG_LEN,
        "the payload starts immediately after the tag TLV"
    );
    assert_eq!(&datagram[16 + addr_len..], b"payload");
}

/// The headline #3862 acceptance criterion: a byte-for-byte replay on the
/// correct listener is admitted exactly once.
#[test]
fn exact_replay_on_the_same_listener_is_admitted_exactly_once() {
    let gate = authenticated_gate();
    let binding = udp_binding(LISTENER_PORT);
    let sender = Sender::new(51);
    let form = v4_form(LISTENER_PORT);
    let datagram = sender.at(&binding, form, b"action", 0);

    gate.decode(&datagram, &peer())
        .expect("the genuine datagram is admitted");
    let error = gate
        .decode(&datagram, &peer())
        .expect_err("the verbatim replay must be refused");
    assert_eq!(error, DatagramMetadataError::ReplayDuplicate);
    assert_eq!(error.reason(), "replay_duplicate");

    // Repeating it never degrades into acceptance, and never grows state.
    for _ in 0..8 {
        assert_eq!(
            gate.decode(&datagram, &peer())
                .expect_err("every further replay is refused"),
            DatagramMetadataError::ReplayDuplicate
        );
    }
    assert_eq!(gate.tracked_replay_senders(), 1);
}

/// Every envelope form shares one freshness contract when authenticated.
#[test]
fn all_envelope_forms_share_the_freshness_contract() {
    let binding = udp_binding(LISTENER_PORT);
    for label in ALL_FORMS {
        let form = envelope_form(label, LISTENER_PORT);
        let gate = authenticated_gate();
        let sender = Sender::new(52);
        let datagram = sender.at(&binding, form, b"payload", 0);
        gate.decode(&datagram, &peer())
            .unwrap_or_else(|error| panic!("{label} must be admitted once: {error}"));
        assert_eq!(
            gate.decode(&datagram, &peer()).expect_err("replay refused"),
            DatagramMetadataError::ReplayDuplicate,
            "{label} must be replay-protected like every other form"
        );

        // And the same form without a freshness record is refused outright.
        let unfresh = plain(form, b"payload");
        assert!(
            gate.decode(&unfresh, &peer()).is_err(),
            "{label} without authentication must not be admitted"
        );
    }
}

/// Bounded reordering inside the window is admitted once each; a duplicate
/// inside the window and a sequence behind it are both refused.
#[test]
fn in_window_reordering_is_admitted_once_each_and_older_sequences_are_stale() {
    let gate = authenticated_gate();
    let binding = udp_binding(LISTENER_PORT);
    let sender = Sender::new(53);
    let form = v4_form(LISTENER_PORT);

    // Arrive out of order but inside the window.
    for sequence in [200u64, 198, 202, 199, 201] {
        let datagram = sender.at(&binding, form, b"p", sequence);
        gate.decode(&datagram, &peer())
            .unwrap_or_else(|error| panic!("unique sequence {sequence}: {error}"));
    }
    // Every one is now a duplicate, including the ones below the high watermark
    // that only the bitmap can remember.
    for sequence in [200u64, 198, 202, 199, 201] {
        let datagram = sender.at(&binding, form, b"p", sequence);
        assert_eq!(
            gate.decode(&datagram, &peer())
                .expect_err("in-window duplicate must be refused"),
            DatagramMetadataError::ReplayDuplicate,
            "sequence {sequence}"
        );
    }

    // A never-seen sequence still inside the window is admitted.
    let unseen = sender.at(&binding, form, b"p", 197);
    gate.decode(&unseen, &peer())
        .expect("an unseen in-window sequence is admitted");

    // The far edge of the window is representable...
    let edge = 202 - REPLAY_WINDOW_BITS;
    let at_edge = sender.at(&binding, form, b"p", edge);
    gate.decode(&at_edge, &peer())
        .expect("the oldest in-window sequence is admitted once");
    assert_eq!(
        gate.decode(&at_edge, &peer())
            .expect_err("and then refused as a duplicate"),
        DatagramMetadataError::ReplayDuplicate
    );

    // ...and one step beyond it is stale.
    let past_edge = sender.at(&binding, form, b"p", edge - 1);
    let error = gate
        .decode(&past_edge, &peer())
        .expect_err("a sequence past the window must be stale");
    assert_eq!(error, DatagramMetadataError::ReplayStale);
    assert_eq!(error.reason(), "replay_stale");
}

/// A jump past the window keeps protection: the sequences it left behind become
/// stale rather than silently re-admissible.
#[test]
fn a_jump_past_the_window_leaves_no_reopened_sequences() {
    let gate = authenticated_gate();
    let binding = udp_binding(LISTENER_PORT);
    let sender = Sender::new(54);
    let form = v4_form(LISTENER_PORT);

    let low = sender.at(&binding, form, b"p", 5);
    let high = sender.at(&binding, form, b"p", 5_000);
    gate.decode(&low, &peer()).expect("first sequence admitted");
    gate.decode(&high, &peer())
        .expect("a far-forward sequence advances the window");

    assert_eq!(
        gate.decode(&low, &peer())
            .expect_err("an admitted sequence must not reopen after a jump"),
        DatagramMetadataError::ReplayStale
    );
    assert_eq!(
        gate.decode(&high, &peer())
            .expect_err("the highest sequence stays a duplicate"),
        DatagramMetadataError::ReplayDuplicate
    );
}

/// Boundary sequences: the first one a sender ever sends, the largest usable
/// one, and the reserved wrap sentinel.
#[test]
fn sequence_boundaries_and_the_reserved_wrap_value() {
    let gate = authenticated_gate();
    let binding = udp_binding(LISTENER_PORT);
    let sender = Sender::new(55);
    let form = v4_form(LISTENER_PORT);

    // Sequence 0 is a legitimate first value, and is replay-protected.
    let first = sender.at(&binding, form, b"p", 0);
    gate.decode(&first, &peer())
        .expect("sequence 0 is admissible");
    assert_eq!(
        gate.decode(&first, &peer())
            .expect_err("and replay-protected"),
        DatagramMetadataError::ReplayDuplicate
    );

    // The largest usable sequence is admitted.
    let last = sender.at(&binding, form, b"p", u64::MAX - 1);
    gate.decode(&last, &peer())
        .expect("u64::MAX - 1 is the last usable sequence");

    // `u64::MAX` is reserved: a sender must roll its epoch instead of wrapping.
    let sentinel = sender.at(&binding, form, b"p", u64::MAX);
    let error = gate
        .decode(&sentinel, &peer())
        .expect_err("the wrap sentinel must be refused");
    assert_eq!(error, DatagramMetadataError::ReplaySequenceExhausted);
    assert_eq!(error.reason(), "replay_sequence_exhausted");

    // And it is refused for a brand-new sender before any state is reserved.
    let fresh = authenticated_gate();
    assert_eq!(
        fresh
            .decode(&sentinel, &peer())
            .expect_err("refused before state is allocated"),
        DatagramMetadataError::ReplaySequenceExhausted
    );
    assert_eq!(fresh.tracked_replay_senders(), 0);
}

/// Sender restart semantics: a higher epoch reseeds the window, and the retired
/// epoch's sequences are refused rather than reusable.
#[test]
fn a_higher_sender_epoch_reseeds_and_the_retired_epoch_is_refused() {
    let gate = authenticated_gate();
    let binding = udp_binding(LISTENER_PORT);
    let mut sender = Sender::new(56);
    let form = v4_form(LISTENER_PORT);

    let before = sender.next(&binding, form, b"before");
    gate.decode(&before, &peer())
        .expect("pre-restart datagram admitted");

    // Restart: strictly higher epoch, sequence counter restarted at 0.
    sender.epoch += 1;
    sender.next_sequence = 0;
    let after = sender.next(&binding, form, b"after");
    gate.decode(&after, &peer())
        .expect("a restarted sender's new epoch is admitted");
    assert_eq!(
        gate.decode(&after, &peer())
            .expect_err("and is itself replay-protected"),
        DatagramMetadataError::ReplayDuplicate
    );

    // The pre-restart datagram — same sequence number, retired epoch — must not
    // become valid again just because the window was reseeded.
    let error = gate
        .decode(&before, &peer())
        .expect_err("a retired epoch must be refused");
    assert_eq!(error, DatagramMetadataError::ReplayEpochStale);
    assert_eq!(error.reason(), "replay_epoch_stale");

    // A sender that regresses its epoch is refused too, and epoch cardinality
    // costs no extra state: one record per sender.
    sender.epoch -= 1;
    sender.next_sequence = 99;
    let regressed = sender.next(&binding, form, b"regressed");
    assert_eq!(
        gate.decode(&regressed, &peer())
            .expect_err("an epoch regression must be refused"),
        DatagramMetadataError::ReplayEpochStale
    );
    assert_eq!(gate.tracked_replay_senders(), 1);
}

/// A correctly tagged envelope carrying no freshness TLV is the pre-#3862
/// authenticated format. It must be refused rather than accepted as a legacy
/// shape, or the whole anti-replay contract is opt-out on the wire.
#[test]
fn a_correctly_tagged_envelope_without_freshness_is_refused() {
    let gate = authenticated_gate();
    let binding = udp_binding(LISTENER_PORT);

    let mut block = inet_block("203.0.113.9:41234", "10.0.0.5:5353");
    block.push(AUTH_TLV_TYPE);
    block.extend_from_slice(&(AUTH_TAG_LEN as u16).to_be_bytes());
    let tag_at = 16 + block.len();
    block.extend_from_slice(&[0u8; AUTH_TAG_LEN]);
    let mut datagram = header(0x21, 0x12, &block, b"p");
    // Sign it exactly the way the encoder would, so the only thing wrong with
    // this datagram is the absent freshness record.
    let mut mac = key().begin();
    mac.update(binding.canonical_domain());
    mac.update(&datagram[..tag_at]);
    mac.update(&datagram[tag_at + AUTH_TAG_LEN..]);
    let tag = mac.finalize().into_bytes();
    datagram[tag_at..tag_at + AUTH_TAG_LEN].copy_from_slice(&tag);

    let error = gate
        .decode(&datagram, &peer())
        .expect_err("a tagged legacy envelope must still be refused");
    assert_eq!(error, DatagramMetadataError::MissingFreshness);
    assert_eq!(error.reason(), "missing_freshness");
}

/// Duplicated, wrong-length, and unknown-version freshness data all fail closed
/// with their own fixed-cardinality reason.
#[test]
fn duplicate_malformed_and_unsupported_freshness_are_refused() {
    let gate = authenticated_gate();
    let binding = udp_binding(LISTENER_PORT);
    let sender = Sender::new(57);
    let form = v4_form(LISTENER_PORT);
    let good = sender.at(&binding, form, b"p", 0);

    // Duplicated: which sequence was asserted would be ambiguous.
    let mut duplicated = Vec::new();
    duplicated.extend_from_slice(&good[..FRESHNESS_TLV_AT]);
    let tlv = &good[FRESHNESS_TLV_AT..FRESHNESS_TLV_AT + FRESHNESS_TLV_LEN];
    duplicated.extend_from_slice(tlv);
    duplicated.extend_from_slice(&good[FRESHNESS_TLV_AT..]);
    let widened = u16::from_be_bytes([good[14], good[15]]) + FRESHNESS_TLV_LEN as u16;
    duplicated[14..16].copy_from_slice(&widened.to_be_bytes());
    let error = gate
        .decode(&duplicated, &peer())
        .expect_err("two freshness TLVs must be refused");
    assert_eq!(error, DatagramMetadataError::DuplicateFreshness);
    assert_eq!(error.reason(), "duplicate_freshness");

    // Wrong length: refused in the TLV walk, before any value is interpreted.
    let mut block = inet_block("203.0.113.9:41234", "10.0.0.5:5353");
    block.push(FRESHNESS_TLV_TYPE);
    block.extend_from_slice(&4u16.to_be_bytes());
    block.extend_from_slice(&[0u8; 4]);
    let short = header(0x21, 0x12, &block, b"p");
    let error = gate
        .decode(&short, &peer())
        .expect_err("a short freshness TLV must be refused");
    assert_eq!(error, DatagramMetadataError::MalformedFreshness);
    assert_eq!(error.reason(), "malformed_freshness");

    // The version byte is inside the MAC, so editing it breaks the tag first —
    // which is the point. The dedicated reason exists for a genuinely newer
    // sender that holds the secret.
    let mut wrong_version = good.clone();
    wrong_version[FRESHNESS_VALUE_AT] = 0x02;
    assert_eq!(
        gate.decode(&wrong_version, &peer())
            .expect_err("an edited version byte must not verify"),
        DatagramMetadataError::AuthenticationTagMismatch
    );
    let unsupported = DatagramMetadataError::UnsupportedFreshnessVersion(0x02);
    assert_eq!(unsupported.reason(), "unsupported_freshness_version");
}

/// The authenticated timestamp horizon, in both directions. This is the bound
/// the cross-reload / cross-restart / cross-replica guarantee is stated in.
#[test]
fn a_timestamp_outside_the_horizon_is_refused_in_both_directions() {
    let binding = udp_binding(LISTENER_PORT);
    let form = v4_form(LISTENER_PORT);
    let sent_at = 1_760_000_000_000u64;

    let outside = [
        ("stale", sent_at + FRESHNESS_HORIZON_MS + 1),
        ("skewed into the future", sent_at - FRESHNESS_HORIZON_MS - 1),
    ];
    for (label, receiver_now) in outside {
        let gate = authenticated_gate();
        let mut sender = Sender::new(58);
        sender.timestamp_ms = sent_at;
        let datagram = sender.at(&binding, form, b"p", 0);
        let error = gate
            .decode_at(&datagram, &peer(), receiver_now)
            .expect_err("a timestamp outside the horizon must be refused");
        assert_eq!(
            error,
            DatagramMetadataError::FreshnessOutsideHorizon,
            "{label} timestamp must be refused"
        );
        assert_eq!(error.reason(), "freshness_outside_horizon");
        // Refused before any state is reserved for the sender.
        assert_eq!(gate.tracked_replay_senders(), 0);
    }

    // The horizon edge itself is inside the accepted window, so the refusals
    // above are about being outside it rather than about the fixture.
    let edges = [
        sent_at + FRESHNESS_HORIZON_MS,
        sent_at - FRESHNESS_HORIZON_MS,
    ];
    for receiver_now in edges {
        let gate = authenticated_gate();
        let mut sender = Sender::new(58);
        sender.timestamp_ms = sent_at;
        let datagram = sender.at(&binding, form, b"p", 0);
        gate.decode_at(&datagram, &peer(), receiver_now)
            .expect("the horizon edge is inside the accepted window");
    }
}

/// Check-and-mark must be one synchronization event: with many workers racing
/// the same `(sender, epoch, sequence)`, exactly one may be admitted.
#[test]
fn concurrent_admission_of_one_sequence_admits_exactly_one() {
    let gate = authenticated_gate();
    let binding = udp_binding(LISTENER_PORT);
    let sender = Sender::new(59);
    let form = v4_form(LISTENER_PORT);
    let datagram = sender.at(&binding, form, b"once", 0);

    let admitted = AtomicU64::new(0);
    let duplicates = AtomicU64::new(0);
    std::thread::scope(|scope| {
        for _ in 0..16 {
            scope.spawn(|| {
                let outcome = gate.decode(&datagram, &peer());
                match outcome {
                    Ok(_) => {
                        admitted.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(DatagramMetadataError::ReplayDuplicate) => {
                        duplicates.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(other) => panic!("unexpected refusal under contention: {other}"),
                }
            });
        }
    });
    assert_eq!(
        admitted.load(Ordering::Relaxed),
        1,
        "exactly one worker may admit a given sequence"
    );
    assert_eq!(duplicates.load(Ordering::Relaxed), 15);

    // A concurrent burst of *distinct* sequences must all be admitted exactly
    // once, so the atomicity above is not achieved by over-refusing.
    let wide = authenticated_gate();
    let distinct: Vec<Vec<u8>> = (1..=32u64)
        .map(|sequence| sender.at(&binding, form, b"n", sequence))
        .collect();
    let accepted = AtomicU64::new(0);
    let wide_ref = &wide;
    let accepted_ref = &accepted;
    std::thread::scope(|scope| {
        for datagram in &distinct {
            scope.spawn(move || {
                if wide_ref.decode(datagram, &peer()).is_ok() {
                    accepted_ref.fetch_add(1, Ordering::Relaxed);
                }
            });
        }
    });
    assert_eq!(
        accepted.load(Ordering::Relaxed),
        32,
        "every distinct in-window sequence must be admitted once"
    );
}

/// Hostile sender cardinality is bounded, and exhaustion refuses rather than
/// evicting live protection.
#[test]
fn hostile_sender_cardinality_is_bounded_and_refuses_rather_than_evicting() {
    let gate = authenticated_gate();
    let binding = udp_binding(LISTENER_PORT);
    let form = v4_form(LISTENER_PORT);

    // Fill replay state to capacity with distinct authenticated sender ids.
    for sender_id in 0..MAX_REPLAY_SENDERS as u32 {
        let sender = Sender::new(sender_id);
        let datagram = sender.at(&binding, form, b"p", 0);
        gate.decode(&datagram, &peer())
            .unwrap_or_else(|error| panic!("sender {sender_id}: {error}"));
    }
    assert_eq!(gate.tracked_replay_senders(), MAX_REPLAY_SENDERS);

    // One more distinct sender, with nothing reclaimable: refused, and the
    // bound holds.
    let overflow = Sender::new(MAX_REPLAY_SENDERS as u32);
    let datagram = overflow.at(&binding, form, b"p", 0);
    let error = gate
        .decode(&datagram, &peer())
        .expect_err("state capacity must refuse rather than evict");
    assert_eq!(error, DatagramMetadataError::ReplayStateCapacity);
    assert_eq!(error.reason(), "replay_state_capacity");
    assert_eq!(
        gate.tracked_replay_senders(),
        MAX_REPLAY_SENDERS,
        "capacity refusal must not grow or shuffle state"
    );

    // Crucially, senders already protected stay protected: a replay of an
    // admitted datagram is still a duplicate, not a fresh admission.
    let established = Sender::new(0);
    let replay = established.at(&binding, form, b"p", 0);
    assert_eq!(
        gate.decode(&replay, &peer())
            .expect_err("capacity pressure must not reopen an admitted sequence"),
        DatagramMetadataError::ReplayDuplicate
    );

    // Wild sequence jumps for a known sender cost no extra state either: one
    // record per sender, whatever the sequences are.
    for sequence in [1u64, 1 << 20, 1 << 40, u64::MAX - 1] {
        let datagram = established.at(&binding, form, b"p", sequence);
        let _ = gate.decode(&datagram, &peer());
    }
    assert_eq!(gate.tracked_replay_senders(), MAX_REPLAY_SENDERS);
}

/// Concurrent first-seen sender admission must not overshoot the hard
/// cardinality cap: many distinct unseen identities racing near capacity all
/// observe a below-cap length unless insertion itself is serialized.
#[test]
fn concurrent_first_seen_senders_cannot_overshoot_the_hard_cardinality_cap() {
    let gate = authenticated_gate();
    let binding = udp_binding(LISTENER_PORT);
    let form = v4_form(LISTENER_PORT);
    let now_ms = 1_760_000_000_000u64;
    // Leave a few vacant slots so every racer can pass a lock-free length
    // check, then race far more distinct identities than remaining capacity.
    const REMAINING: usize = 8;
    const OCCUPIED: usize = MAX_REPLAY_SENDERS - REMAINING;
    const RACERS: usize = 64;

    for sender_id in 0..OCCUPIED as u32 {
        let mut sender = Sender::new(sender_id);
        sender.timestamp_ms = now_ms;
        let datagram = sender.at(&binding, form, b"p", 0);
        gate.decode_at(&datagram, &peer(), now_ms)
            .unwrap_or_else(|error| panic!("sender {sender_id}: {error}"));
    }
    assert_eq!(gate.tracked_replay_senders(), OCCUPIED);

    let newcomers: Vec<Vec<u8>> = (0..RACERS as u32)
        .map(|offset| {
            let mut sender = Sender::new(OCCUPIED as u32 + offset);
            sender.timestamp_ms = now_ms;
            sender.at(&binding, form, b"p", 0)
        })
        .collect();
    let admitted = AtomicUsize::new(0);
    let capacity = AtomicUsize::new(0);
    let peak = AtomicUsize::new(OCCUPIED);
    let barrier = std::sync::Barrier::new(RACERS);
    let admitted_ref = &admitted;
    let capacity_ref = &capacity;
    let peak_ref = &peak;
    let gate_ref = &gate;
    let barrier_ref = &barrier;
    std::thread::scope(|scope| {
        for datagram in &newcomers {
            scope.spawn(move || {
                barrier_ref.wait();
                let outcome = gate_ref.decode_at(datagram, &peer(), now_ms);
                peak_ref.fetch_max(gate_ref.tracked_replay_senders(), Ordering::Relaxed);
                match outcome {
                    Ok(_) => {
                        admitted_ref.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(DatagramMetadataError::ReplayStateCapacity) => {
                        capacity_ref.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(other) => panic!("unexpected first-seen refusal: {other}"),
                }
            });
        }
    });

    let admitted = admitted.load(Ordering::Relaxed);
    let capacity = capacity.load(Ordering::Relaxed);
    let live = gate.tracked_replay_senders();
    let peak = peak.load(Ordering::Relaxed);
    assert_eq!(
        admitted + capacity,
        RACERS,
        "every racer must admit or refuse"
    );
    assert_eq!(
        admitted, REMAINING,
        "only the remaining vacant slots may admit a new sender"
    );
    assert_eq!(
        capacity,
        RACERS - REMAINING,
        "excess first-seen identities must fail closed with the capacity error"
    );
    assert_eq!(live, MAX_REPLAY_SENDERS);
    assert!(
        peak <= MAX_REPLAY_SENDERS,
        "live cardinality sampled during the race must never exceed the hard maximum (peak={peak})"
    );
    assert!(
        live <= MAX_REPLAY_SENDERS,
        "live cardinality must never exceed the hard maximum"
    );

    // Live protection is intact: an established sender's admitted sequence is
    // still a duplicate, not reopened by the concurrent overflow.
    let mut established = Sender::new(0);
    established.timestamp_ms = now_ms;
    let replay = established.at(&binding, form, b"p", 0);
    assert_eq!(
        gate.decode_at(&replay, &peer(), now_ms)
            .expect_err("concurrent overflow must not reopen an admitted sequence"),
        DatagramMetadataError::ReplayDuplicate
    );
}

/// Idle reclaim frees capacity without reopening anything: a record is only
/// reclaimable once every envelope that could have belonged to it is already
/// outside the authenticated horizon.
#[test]
fn idle_reclaim_frees_capacity_without_reopening_an_admitted_sequence() {
    let gate = authenticated_gate();
    let binding = udp_binding(LISTENER_PORT);
    let form = v4_form(LISTENER_PORT);
    let sent_at = 1_760_000_000_000u64;

    for sender_id in 0..MAX_REPLAY_SENDERS as u32 {
        let mut sender = Sender::new(sender_id);
        sender.timestamp_ms = sent_at;
        let datagram = sender.at(&binding, form, b"p", 0);
        gate.decode_at(&datagram, &peer(), sent_at)
            .expect("fill to capacity");
    }
    assert_eq!(gate.tracked_replay_senders(), MAX_REPLAY_SENDERS);

    // Well past the idle threshold — which is deliberately greater than twice
    // the horizon — a new sender is admitted because stale records are
    // reclaimed.
    let much_later = sent_at + 5 * FRESHNESS_HORIZON_MS;
    let mut newcomer = Sender::new(9_999);
    newcomer.timestamp_ms = much_later;
    let fresh = newcomer.at(&binding, form, b"p", 0);
    gate.decode_at(&fresh, &peer(), much_later)
        .expect("idle reclaim must free capacity for a live sender");
    assert!(gate.tracked_replay_senders() <= MAX_REPLAY_SENDERS);

    // And a replay of a reclaimed sender's datagram is still refused — by the
    // horizon, which is precisely what makes reclaiming safe.
    let mut reclaimed = Sender::new(0);
    reclaimed.timestamp_ms = sent_at;
    let stale = reclaimed.at(&binding, form, b"p", 0);
    let error = gate
        .decode_at(&stale, &peer(), much_later)
        .expect_err("a reclaimed sender's old datagram must not be re-admitted");
    assert_eq!(error, DatagramMetadataError::FreshnessOutsideHorizon);
}

/// Listener reload, receiver process restart, and a second Ferrum replica all
/// share one semantics: a fresh gate has a fresh window, so the guarantee is
/// *bounded to the horizon* rather than absolute. This is exactly what the
/// documentation claims, and it must not silently be weaker.
#[test]
fn a_fresh_gate_bounds_replay_to_the_authenticated_horizon() {
    let binding = udp_binding(LISTENER_PORT);
    let form = v4_form(LISTENER_PORT);
    let sent_at = 1_760_000_000_000u64;
    let mut sender = Sender::new(60);
    sender.timestamp_ms = sent_at;
    let captured = sender.at(&binding, form, b"p", 0);

    let before_reload = authenticated_gate();
    before_reload
        .decode_at(&captured, &peer(), sent_at)
        .expect("admitted by the pre-reload listener");
    assert_eq!(
        before_reload
            .decode_at(&captured, &peer(), sent_at)
            .expect_err("and replay-protected there"),
        DatagramMetadataError::ReplayDuplicate
    );

    // Reload / restart / a second replica: inside the horizon the capture is
    // admitted once more. Documented, bounded, and asserted so the bound cannot
    // silently widen.
    let edge = sent_at + FRESHNESS_HORIZON_MS;
    let after_reload = authenticated_gate();
    after_reload
        .decode_at(&captured, &peer(), edge)
        .expect("inside the horizon a fresh receiver admits it once");
    assert_eq!(
        after_reload
            .decode_at(&captured, &peer(), edge)
            .expect_err("the fresh receiver then protects it"),
        DatagramMetadataError::ReplayDuplicate
    );

    // Past the horizon no receiver will take it, restarted or not.
    let much_later = authenticated_gate();
    assert_eq!(
        much_later
            .decode_at(&captured, &peer(), edge + 1)
            .expect_err("outside the horizon the capture is dead everywhere"),
        DatagramMetadataError::FreshnessOutsideHorizon
    );
}

/// A cross-listener replay and a same-listener duplicate are independent
/// refusals: satisfying one does not make the other admissible (#3856 together
/// with #3862).
#[test]
fn listener_binding_and_replay_window_are_independent_refusals() {
    let binding_a = udp_binding(LISTENER_PORT);
    let binding_b = udp_binding(OTHER_LISTENER_PORT);
    let gate_a = gate_for(binding_a, Some(SECRET));
    let gate_b = gate_for(binding_b, Some(SECRET));
    let sender = Sender::new(61);

    // An address-less form, so only the cryptographic binding can refuse it.
    let form = DatagramEnvelopeForm::Unspec;
    let for_a = sender.at(&binding_a, form, b"p", 0);
    gate_a
        .decode(&for_a, &peer())
        .expect("admitted on its own listener");
    assert_eq!(
        gate_b
            .decode(&for_a, &peer())
            .expect_err("never admitted on another listener"),
        DatagramMetadataError::AuthenticationTagMismatch
    );
    assert_eq!(
        gate_a
            .decode(&for_a, &peer())
            .expect_err("and never twice on its own"),
        DatagramMetadataError::ReplayDuplicate
    );
    // Listener B allocated no replay state for the envelope it refused.
    assert_eq!(gate_b.tracked_replay_senders(), 0);
}

/// Refusal reasons are a closed, fixed-cardinality set with no attacker-shaped
/// content, and no diagnostic echoes secret, payload, tag, or address material.
#[test]
fn refusal_reasons_are_fixed_cardinality_and_material_free() {
    let cases = [
        DatagramMetadataError::UntrustedPeer,
        DatagramMetadataError::TruncatedHeader { len: 3 },
        DatagramMetadataError::InvalidSignature,
        DatagramMetadataError::UnsupportedVersion(1),
        DatagramMetadataError::UnsupportedCommand(3),
        DatagramMetadataError::AddressBlockTooLong(4096),
        DatagramMetadataError::TruncatedAddressBlock {
            declared: 12,
            available: 4,
        },
        DatagramMetadataError::UnsupportedAddressFamily(3),
        DatagramMetadataError::NonDatagramTransport(1),
        DatagramMetadataError::AddressBlockTooShortForFamily { family: 2, len: 12 },
        DatagramMetadataError::MalformedTlv,
        DatagramMetadataError::DuplicateAuthenticationTag,
        DatagramMetadataError::MissingAuthenticationTag,
        DatagramMetadataError::InvalidAuthenticationTagLength(4),
        DatagramMetadataError::AuthenticationTagMismatch,
        DatagramMetadataError::AuthenticationKeyUnavailable,
        DatagramMetadataError::ForwardedClientChanged,
        DatagramMetadataError::ListenerBindingMismatch,
        DatagramMetadataError::MissingFreshness,
        DatagramMetadataError::DuplicateFreshness,
        DatagramMetadataError::MalformedFreshness,
        DatagramMetadataError::UnsupportedFreshnessVersion(9),
        DatagramMetadataError::FreshnessOutsideHorizon,
        DatagramMetadataError::ReplayDuplicate,
        DatagramMetadataError::ReplayStale,
        DatagramMetadataError::ReplayEpochStale,
        DatagramMetadataError::ReplaySequenceExhausted,
        DatagramMetadataError::ReplayStateCapacity,
    ];

    // The #3856 / #3862 reasons an operator has to be able to tell apart must
    // all be present and distinct.
    let reasons: std::collections::BTreeSet<&str> =
        cases.iter().map(|error| error.reason()).collect();
    let required = [
        "listener_binding_mismatch",
        "replay_duplicate",
        "replay_stale",
        "replay_epoch_stale",
        "missing_freshness",
        "malformed_freshness",
        "duplicate_freshness",
        "unsupported_freshness_version",
        "freshness_outside_horizon",
        "replay_state_capacity",
        "replay_sequence_exhausted",
    ];
    for reason in required {
        assert!(reasons.contains(reason), "reason {reason} must exist");
    }
    assert_eq!(
        reasons.len(),
        cases.len(),
        "every refusal must have its own fixed-cardinality reason"
    );

    for error in cases {
        let reason = error.reason();
        assert!(
            reason
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_'),
            "reason {reason} must be a fixed snake_case label"
        );
        let rendered = error.to_string();
        assert!(
            !rendered.contains(SECRET),
            "diagnostic must not echo the secret: {rendered}"
        );
        assert!(
            !rendered.contains("203.0.113.9") && !rendered.contains("41234"),
            "diagnostic must not echo asserted addresses: {rendered}"
        );
    }
}

/// The freshness record round-trips through the normative sender surface, so a
/// balancer implementer can rely on the encoding.
#[test]
fn freshness_record_round_trips_through_the_encoder() {
    let freshness = DatagramFreshness {
        sender_id: 0xdead_beef,
        epoch: 0x0102_0304_0506_0708,
        sequence: u64::MAX - 1,
        timestamp_ms: 1_760_000_000_000,
    };
    let tlv = freshness.encode_tlv();
    assert_eq!(tlv.len(), FRESHNESS_TLV_LEN);
    assert_eq!(tlv[0], FRESHNESS_TLV_TYPE);
    let declared = u16::from_be_bytes([tlv[1], tlv[2]]) as usize;
    assert_eq!(declared, FRESHNESS_VALUE_LEN);

    let value = freshness.encode_value();
    assert_eq!(tlv[3..], value);
    assert_eq!(value[0], 1);
    let sender_id = u32::from_be_bytes(value[1..5].try_into().expect("sender"));
    assert_eq!(sender_id, 0xdead_beef);
    let epoch = u64::from_be_bytes(value[5..13].try_into().expect("epoch"));
    assert_eq!(epoch, 0x0102_0304_0506_0708);
    let sequence = u64::from_be_bytes(value[13..21].try_into().expect("sequence"));
    assert_eq!(sequence, u64::MAX - 1);
    let timestamp = u64::from_be_bytes(value[21..29].try_into().expect("timestamp"));
    assert_eq!(timestamp, 1_760_000_000_000);
}

// ===========================================================================
// FIPS parity and cross-parser spec alignment
// ===========================================================================

/// FIPS parity: authenticity, the listener-domain binding, and freshness all
/// ride the ONE approved primitive. The binding is a versioned byte prefix
/// absorbed into the same HMAC-SHA-256 input and freshness is a plaintext
/// record inside that same MAC, so there is no key-derivation function, no
/// per-listener subkey, and no second construction — the root secret stays the
/// single full-strength HMAC key on every listener.
#[test]
fn datagram_envelope_uses_only_the_approved_hmac_primitive() {
    let source = include_str!("../../../src/proxy/datagram_client_address.rs");
    assert!(
        source.contains("use crate::fips::approved::HmacSha256Key;"),
        "the envelope must key through the approved HMAC module"
    );
    for banned in ["Hkdf", "hkdf", "Sha1", "Md5", "HmacSha512", "blake3"] {
        assert!(
            !source.contains(banned),
            "the envelope must not introduce {banned}"
        );
    }

    // The FIPS key-strength gate must still name the variable, and the startup
    // minimum must still be the SP 800-107 floor.
    let policy = include_str!("../../../src/fips/policy.rs");
    assert!(
        policy.contains("FERRUM_DATAGRAM_PROXY_PROTOCOL_SECRET"),
        "the FIPS HMAC key-strength list must still cover the datagram secret"
    );
    assert_eq!(MIN_DATAGRAM_SECRET_BYTES, 32);
    assert!(validate_secret(Some(&"a".repeat(31))).is_err());
    assert!(validate_secret(Some(&"a".repeat(32))).is_ok());
}

#[test]
fn datagram_and_tcp_proxy_v2_parsers_share_spec_constants() {
    let datagram = include_str!("../../../src/proxy/datagram_client_address.rs");
    let tcp = include_str!("../../../src/proxy/proxy_protocol.rs");

    let signature = r#"b"\r\n\r\n\x00\r\nQUIT\n""#;
    assert!(
        datagram.contains(signature) && tcp.contains(signature),
        "both parsers must keep the PROXY v2 signature"
    );
    assert!(
        datagram.contains("MAX_ADDR_BLOCK_LEN: u16 = 512")
            && tcp.contains("V2_MAX_ADDR_LEN: u16 = 512"),
        "both parsers must keep the 512-byte address-block cap"
    );
    assert!(
        datagram.contains("INET_ADDR_LEN: usize = 12")
            && tcp.contains("V2_INET_ADDR_LEN: usize = 12"),
        "both parsers must keep the AF_INET fixed block size"
    );
    assert!(
        datagram.contains("INET6_ADDR_LEN: usize = 36")
            && tcp.contains("V2_INET6_ADDR_LEN: usize = 36"),
        "both parsers must keep the AF_INET6 fixed block size"
    );
    assert!(
        datagram.contains("crate::proxy::proxy_protocol"),
        "datagram parser must cross-reference the TCP parser"
    );
    assert!(
        tcp.contains("datagram_client_address"),
        "TCP parser must cross-reference the datagram parser"
    );
}
