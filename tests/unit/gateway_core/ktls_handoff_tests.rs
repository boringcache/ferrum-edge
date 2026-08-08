//! Deterministic coverage for the frontend-TLS kTLS handoff admission gate
//! ([issue #3619](https://github.com/ferrum-edge/ferrum-edge/issues/3619),
//! superseding the refuse-closed buffered gate of issue #2955).
//!
//! The handshake itself now runs on rustls's unbuffered API and only hands off
//! after reaching `WriteTraffic`, which is what makes the record alignment
//! provable. What decides *whether* that path is entered at all is
//! [`ClientHelloKtlsFacts`], computed from a peeked ClientHello while the
//! socket is still pristine — so every refusal here is a clean fall-back to
//! the buffered tokio-rustls accept, not a dropped connection.
//!
//! These tests pin the two properties that keep the fallback safe:
//!
//! 1. A TLS 1.3 offer is refused. The kernel holds a static traffic secret and
//!    KeyUpdate (RFC 8446 §4.6.3) is not handled, so TLS 1.3 must never reach
//!    the handoff.
//! 2. Anything unprovable is refused. Truncated, malformed, or non-TLS input,
//!    and any offer set containing a suite this kernel cannot install, all
//!    decline rather than gamble on rustls's suite choice.
//!
//! ClientHello bytes come from real rustls client connections so the parser is
//! exercised against authentic wire encodings rather than hand-rolled blobs.

use std::sync::Arc;

use ferrum_edge::proxy::sni::{ClientHelloKtlsFacts, client_hello_ktls_facts};
use ferrum_edge::tls::NoVerifier;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection};

/// Produce a real ClientHello for a client restricted to `versions`.
fn client_hello_for(versions: &[&'static rustls::SupportedProtocolVersion]) -> Vec<u8> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .expect("requested protocol versions are supported")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
    let mut conn = ClientConnection::new(
        Arc::new(config),
        ServerName::try_from("ktls.example.com").expect("valid SNI"),
    )
    .expect("client connection");

    let mut hello = Vec::new();
    conn.write_tls(&mut hello)
        .expect("ClientHello is written to an in-memory buffer");
    assert!(!hello.is_empty(), "rustls must emit a ClientHello");
    hello
}

/// Every per-cipher kernel probe passing (Linux 5.11+ shape).
const ALL_CIPHERS: (bool, bool, bool) = (true, true, true);

fn eligible(facts: &ClientHelloKtlsFacts, probes: (bool, bool, bool)) -> bool {
    facts.ktls_eligible(probes.0, probes.1, probes.2)
}

#[test]
fn tls13_capable_client_is_refused_before_any_handshake_work() {
    let hello = client_hello_for(&[&rustls::version::TLS13, &rustls::version::TLS12]);
    let facts = client_hello_ktls_facts(&hello).expect("complete ClientHello parses");

    assert!(
        facts.offers_tls13,
        "a TLS 1.3-capable client must be detected through supported_versions"
    );
    assert!(
        !eligible(&facts, ALL_CIPHERS),
        "TLS 1.3 must never reach the kernel handoff: KeyUpdate is not handled"
    );
}

#[test]
fn tls13_only_client_is_refused() {
    let hello = client_hello_for(&[&rustls::version::TLS13]);
    let facts = client_hello_ktls_facts(&hello).expect("complete ClientHello parses");

    assert!(facts.offers_tls13);
    assert!(!eligible(&facts, ALL_CIPHERS));
}

#[test]
fn tls12_only_client_is_eligible_when_every_offered_suite_is_installable() {
    let hello = client_hello_for(&[&rustls::version::TLS12]);
    let facts = client_hello_ktls_facts(&hello).expect("complete ClientHello parses");

    assert!(
        !facts.offers_tls13,
        "a TLS 1.2-only rustls client must not advertise TLS 1.3"
    );
    assert!(
        facts.offers_aes128_gcm || facts.offers_aes256_gcm || facts.offers_chacha20_poly1305,
        "rustls TLS 1.2 always offers at least one AEAD suite"
    );
    assert!(
        eligible(&facts, ALL_CIPHERS),
        "a TLS 1.2 client whose whole offer set is installable is eligible"
    );
}

#[test]
fn a_single_uninstallable_offered_suite_declines_the_whole_connection() {
    let hello = client_hello_for(&[&rustls::version::TLS12]);
    let facts = client_hello_ktls_facts(&hello).expect("complete ClientHello parses");
    assert!(
        facts.offers_chacha20_poly1305,
        "rustls TLS 1.2 offers ChaCha20-Poly1305"
    );

    // Linux 4.17-5.10 shape: AES-GCM kTLS exists, ChaCha20-Poly1305 does not.
    // rustls's suite choice is not predicted here, so the connection declines.
    assert!(
        !eligible(&facts, (true, true, false)),
        "an offer set containing a suite the kernel cannot install must decline"
    );
}

#[test]
fn no_kernel_cipher_support_declines() {
    let hello = client_hello_for(&[&rustls::version::TLS12]);
    let facts = client_hello_ktls_facts(&hello).expect("complete ClientHello parses");

    assert!(!eligible(&facts, (false, false, false)));
}

#[test]
fn a_hello_offering_no_selectable_suite_declines() {
    // No TLS 1.2 AEAD suite rustls can select: nothing to install, so the
    // handoff must not be attempted even though TLS 1.3 was not offered.
    let facts = ClientHelloKtlsFacts::default();
    assert!(!eligible(&facts, ALL_CIPHERS));
}

#[test]
fn truncated_client_hello_is_unprovable_and_refused() {
    let hello = client_hello_for(&[&rustls::version::TLS13, &rustls::version::TLS12]);
    assert!(hello.len() > 32, "sanity: hello is longer than its header");

    // A prefix that stops before the extension block could hide
    // supported_versions and make a TLS 1.3 client look like TLS 1.2. Parsing
    // must refuse rather than answer from a partial view.
    for cut in [5usize, 16, 40, hello.len() - 4] {
        assert!(
            client_hello_ktls_facts(&hello[..cut]).is_none(),
            "a ClientHello truncated at {cut} bytes must not yield facts"
        );
    }
}

#[test]
fn non_handshake_and_empty_inputs_are_refused() {
    assert!(client_hello_ktls_facts(&[]).is_none());
    assert!(client_hello_ktls_facts(b"GET / HTTP/1.1\r\n").is_none());
    // Handshake record whose message type is ServerHello, not ClientHello.
    let server_hello = [0x16u8, 0x03, 0x01, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00];
    assert!(client_hello_ktls_facts(&server_hello).is_none());
}

#[test]
fn sni_used_for_the_ktls_relay_identity_comes_from_the_same_hello() {
    // The kTLS branch has no `ServerConnection::server_name()` to read, so it
    // takes SNI from the peeked ClientHello. Pin that the same bytes that
    // prove eligibility also yield the hostname.
    let hello = client_hello_for(&[&rustls::version::TLS12]);
    assert!(client_hello_ktls_facts(&hello).is_some());
    assert_eq!(
        ferrum_edge::proxy::sni::extract_sni_from_client_hello(&hello).as_deref(),
        Some("ktls.example.com")
    );
}
