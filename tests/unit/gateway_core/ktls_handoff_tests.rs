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
//!
//! The file additionally pins three properties of the handed-off connection
//! itself, all of which were wrong in the first cut of #3619:
//!
//! * a kTLS `splice(2)` `EINVAL` is classified from the record it actually
//!   left queued, and only a warning-level `close_notify` is clean EOF;
//! * the relay emits a real TLS `close_notify` (not a bare `shutdown(SHUT_WR)`)
//!   through the `SOL_TLS`/`TLS_SET_RECORD_TYPE` ancillary contract; and
//! * `FERRUM_FRONTEND_TLS_HANDSHAKE_TIMEOUT_SECONDS` is one end-to-end
//!   admission budget, not one allowance per admission stage.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ferrum_edge::proxy::ktls_record::{
    CLOSE_NOTIFY_ALERT_BODY, KtlsControlRecord, TLS_ALERT_DESCRIPTION_CLOSE_NOTIFY,
    TLS_ALERT_LEVEL_FATAL, TLS_ALERT_LEVEL_WARNING, TLS_RECORD_TYPE_ALERT,
    TLS_RECORD_TYPE_APPLICATION_DATA, TLS_RECORD_TYPE_CHANGE_CIPHER_SPEC,
    TLS_RECORD_TYPE_HANDSHAKE, classify_ktls_control_record,
};
use ferrum_edge::proxy::sni::{ClientHelloKtlsFacts, client_hello_ktls_facts};
use ferrum_edge::tls::{NoVerifier, accept_with_optional_deadline, frontend_tls_handshake_deadline};
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

// ---------------------------------------------------------------------------
// kTLS control-record classification
//
// `splice(2)` on a kTLS receive side answers `EINVAL` for EVERY non-application
// record and leaves it queued, so `EINVAL` alone proves nothing. The relay
// consumes the pending record and classifies it here. Exactly one shape is a
// clean end of stream; everything else must stay an attributed relay error so a
// fatal alert or a renegotiation attempt cannot be laundered into a
// successful-looking connection.
// ---------------------------------------------------------------------------

#[test]
fn warning_close_notify_is_the_only_clean_eof() {
    let record = classify_ktls_control_record(TLS_RECORD_TYPE_ALERT, &CLOSE_NOTIFY_ALERT_BODY);
    assert_eq!(record, KtlsControlRecord::CloseNotify);
    assert!(record.is_clean_eof());
    assert_eq!(
        CLOSE_NOTIFY_ALERT_BODY,
        [TLS_ALERT_LEVEL_WARNING, TLS_ALERT_DESCRIPTION_CLOSE_NOTIFY],
        "close_notify is warning(1), close_notify(0)"
    );
}

#[test]
fn fatal_close_notify_is_not_a_clean_eof() {
    // Same description, fatal level. A fatal alert ends the session abnormally
    // and must not be reported as a graceful close.
    let body = [TLS_ALERT_LEVEL_FATAL, TLS_ALERT_DESCRIPTION_CLOSE_NOTIFY];
    let record = classify_ktls_control_record(TLS_RECORD_TYPE_ALERT, &body);
    let KtlsControlRecord::Alert { level, description } = record else {
        panic!("a fatal alert must classify as Alert, got {record}");
    };
    assert_eq!(level, TLS_ALERT_LEVEL_FATAL);
    assert_eq!(description, TLS_ALERT_DESCRIPTION_CLOSE_NOTIFY);
    assert!(!record.is_clean_eof());
}

#[test]
fn other_alerts_of_either_severity_are_errors() {
    // fatal bad_record_mac(20), fatal handshake_failure(40), and the
    // warning-level user_canceled(90) that is explicitly NOT a close.
    for (level, description) in [
        (TLS_ALERT_LEVEL_FATAL, 20u8),
        (TLS_ALERT_LEVEL_FATAL, 40u8),
        (TLS_ALERT_LEVEL_WARNING, 90u8),
    ] {
        let record = classify_ktls_control_record(TLS_RECORD_TYPE_ALERT, &[level, description]);
        let KtlsControlRecord::Alert { level: l, description: d } = record else {
            panic!("alert {level}/{description} must classify as Alert, got {record}");
        };
        assert_eq!((l, d), (level, description));
        assert!(
            !record.is_clean_eof(),
            "alert {level}/{description} must not be swallowed as EOF"
        );
    }
}

#[test]
fn non_alert_control_records_are_errors() {
    // Mid-stream renegotiation / ChangeCipherSpec cannot be honored once the
    // keys live in the kernel, so they end the relay rather than being ignored.
    for record_type in [
        TLS_RECORD_TYPE_HANDSHAKE,
        TLS_RECORD_TYPE_CHANGE_CIPHER_SPEC,
        TLS_RECORD_TYPE_APPLICATION_DATA,
        0u8,
        255u8,
    ] {
        let record = classify_ktls_control_record(record_type, &[0x01]);
        let KtlsControlRecord::NonAlert { record_type: seen } = record else {
            panic!("record type {record_type} must classify as NonAlert, got {record}");
        };
        assert_eq!(seen, record_type);
        assert!(!record.is_clean_eof());
    }
}

#[test]
fn malformed_alert_bodies_fail_closed() {
    // A TLS 1.2 alert is exactly two bytes. Anything else is a malformed peer;
    // guessing at a truncated or padded body is how a close gets forged.
    let three = [TLS_ALERT_LEVEL_WARNING, TLS_ALERT_DESCRIPTION_CLOSE_NOTIFY, 0];
    for body in [&[][..], &[TLS_ALERT_LEVEL_WARNING][..], &three[..]] {
        let record = classify_ktls_control_record(TLS_RECORD_TYPE_ALERT, body);
        let KtlsControlRecord::MalformedAlert { len } = record else {
            panic!("a {}-byte alert body must fail closed, got {record}", body.len());
        };
        assert_eq!(len, body.len());
        assert!(!record.is_clean_eof());
    }
}

#[test]
fn only_close_notify_reports_itself_as_a_clean_close() {
    // Guard the whole variant space: nothing but CloseNotify may answer true,
    // and the rendered description never claims a graceful close.
    let cases = [
        classify_ktls_control_record(TLS_RECORD_TYPE_ALERT, &[TLS_ALERT_LEVEL_FATAL, 40]),
        classify_ktls_control_record(TLS_RECORD_TYPE_ALERT, &[]),
        classify_ktls_control_record(TLS_RECORD_TYPE_HANDSHAKE, &[0x01]),
    ];
    for record in cases {
        assert!(!record.is_clean_eof());
        assert!(
            !record.to_string().contains("close_notify"),
            "{record} must not read as a graceful close"
        );
    }
}

// ---------------------------------------------------------------------------
// close_notify transmit: the ancillary-message construction seam
//
// The kernel decides an outgoing record's content type solely from the
// `SOL_TLS`/`TLS_SET_RECORD_TYPE` control message. If it is absent or
// malformed, the two alert bytes go out as ordinary APPLICATION DATA — a
// silent stream corruption rather than a shutdown. These tests read the
// constructed message back without needing a kTLS-capable kernel.
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn control_for(record_type: u8) -> ferrum_edge::proxy::ktls_record::TlsRecordTypeControl {
    ferrum_edge::proxy::ktls_record::TlsRecordTypeControl::new(record_type)
        .expect("CMSG_SPACE(1) fits the inline control buffer")
}

#[cfg(target_os = "linux")]
#[test]
fn close_notify_control_message_sets_the_alert_record_type() {
    use ferrum_edge::proxy::ktls_record::TLS_SET_RECORD_TYPE;
    use ferrum_edge::socket_opts::ktls::SOL_TLS;

    let control = control_for(TLS_RECORD_TYPE_ALERT);
    let (level, kind, record_type) = control.parsed().expect("well formed");

    assert_eq!(level, SOL_TLS, "record type is set at the SOL_TLS level");
    assert_eq!(kind, TLS_SET_RECORD_TYPE);
    assert_eq!(
        record_type,
        TLS_RECORD_TYPE_ALERT,
        "an absent or wrong record type would emit the alert as application data"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn control_message_length_matches_the_kernel_cmsg_layout() {
    let control = control_for(TLS_RECORD_TYPE_ALERT);
    // SAFETY: `CMSG_SPACE` is pure arithmetic over its length argument.
    let expected = unsafe { libc::CMSG_SPACE(1) } as usize;
    assert_eq!(control.as_bytes().len(), expected);
}

#[cfg(target_os = "linux")]
#[test]
fn each_record_type_round_trips_through_the_control_message() {
    for record_type in [
        TLS_RECORD_TYPE_ALERT,
        TLS_RECORD_TYPE_HANDSHAKE,
        TLS_RECORD_TYPE_APPLICATION_DATA,
    ] {
        let control = control_for(record_type);
        assert_eq!(control.parsed().expect("well formed").2, record_type);
    }
}

// ---------------------------------------------------------------------------
// One frontend-TLS handshake budget across every admission stage
//
// The kTLS attempt peeks the ClientHello and runs an unbuffered handshake
// before the buffered tokio-rustls accept can take over. Giving each stage its
// own `FERRUM_FRONTEND_TLS_HANDSHAKE_TIMEOUT_SECONDS` would let a peer that
// dribbles a partial hello hold a frontend slot for twice the configured
// seconds, so the deadline is computed once and shared.
// ---------------------------------------------------------------------------

fn test_acceptor() -> tokio_rustls::TlsAcceptor {
    let ecdsa = &rcgen::PKCS_ECDSA_P256_SHA256;
    let key = rcgen::KeyPair::generate_for(ecdsa).expect("leaf key");
    let names = vec!["localhost".to_string()];
    let params = rcgen::CertificateParams::new(names).expect("params");
    let cert = params.self_signed(&key).expect("self-signed leaf");

    let certs = rustls_pemfile::certs(&mut cert.pem().as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .expect("parse test leaf certificate");
    let private_key = rustls_pemfile::private_key(&mut key.serialize_pem().as_bytes())
        .expect("parse test leaf key")
        .expect("test leaf key present");

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("test TLS protocol versions")
        .with_no_client_auth()
        .with_single_cert(certs, private_key)
        .expect("test TLS server config");
    tokio_rustls::TlsAcceptor::from(Arc::new(config))
}

fn test_peer() -> SocketAddr {
    "203.0.113.7:44321".parse().expect("valid peer address")
}

/// Run the buffered fallback against a peer that completes a TCP connection and
/// then says nothing, bounded by `deadline`. `_client` is held for the whole
/// call so the server side blocks on a live-but-idle stream rather than EOF.
async fn accept_from_idle_peer(deadline: Option<tokio::time::Instant>) -> std::io::Error {
    let acceptor = test_acceptor();
    let peer = test_peer();
    let (_client, server) = tokio::io::duplex(4096);
    accept_with_optional_deadline(&acceptor, server, deadline, 10, &peer, false)
        .await
        .expect_err("an idle peer must not complete the handshake")
}

#[test]
fn a_disabled_handshake_clock_yields_no_deadline() {
    // `0` keeps the historical "no timeout" behavior; a stage must not
    // synthesize one of its own.
    assert!(frontend_tls_handshake_deadline(0).is_none());
}

#[tokio::test(start_paused = true)]
async fn the_fallback_inherits_the_remaining_budget_not_a_fresh_one() {
    // Budget is opened once, then an earlier admission stage (ClientHello peek
    // + unbuffered kTLS handshake attempt) burns 7 of its 10 seconds.
    let deadline = frontend_tls_handshake_deadline(10);
    tokio::time::sleep(Duration::from_secs(7)).await;

    let started = tokio::time::Instant::now();
    let err = accept_from_idle_peer(deadline).await;
    let spent = tokio::time::Instant::now() - started;

    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    assert_eq!(
        spent,
        Duration::from_secs(3),
        "the fallback must consume only the 3s left in the shared budget"
    );
}

#[tokio::test(start_paused = true)]
async fn an_exhausted_budget_refuses_the_fallback_immediately() {
    let deadline = frontend_tls_handshake_deadline(10);
    tokio::time::sleep(Duration::from_secs(10)).await;

    let started = tokio::time::Instant::now();
    let err = accept_from_idle_peer(deadline).await;
    let spent = tokio::time::Instant::now() - started;

    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    assert_eq!(
        spent,
        Duration::ZERO,
        "an elapsed deadline must not grant any further time"
    );
}

#[tokio::test(start_paused = true)]
async fn an_untouched_budget_still_grants_the_whole_configured_timeout() {
    // The shared-deadline change must not shorten the ordinary path.
    let deadline = frontend_tls_handshake_deadline(10);

    let started = tokio::time::Instant::now();
    let err = accept_from_idle_peer(deadline).await;
    let spent = tokio::time::Instant::now() - started;

    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    assert_eq!(spent, Duration::from_secs(10));
}
