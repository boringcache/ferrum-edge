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
use ferrum_edge::tls::{
    NoVerifier, accept_with_optional_deadline, frontend_tls_handshake_deadline,
};
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
fn every_aes_offer_requires_the_receive_window_to_be_pinned_before_handshake() {
    let aes128 = ClientHelloKtlsFacts {
        offers_aes128_gcm: true,
        ..ClientHelloKtlsFacts::default()
    };
    let aes256_and_chacha = ClientHelloKtlsFacts {
        offers_aes256_gcm: true,
        offers_chacha20_poly1305: true,
        ..ClientHelloKtlsFacts::default()
    };
    let chacha_only = ClientHelloKtlsFacts {
        offers_chacha20_poly1305: true,
        ..ClientHelloKtlsFacts::default()
    };

    assert!(aes128.requires_receive_window_pin());
    assert!(aes256_and_chacha.requires_receive_window_pin());
    assert!(
        !chacha_only.requires_receive_window_pin(),
        "the unlimited suite must retain receive autotuning"
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
        let KtlsControlRecord::Alert {
            level: l,
            description: d,
        } = record
        else {
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
    let three = [
        TLS_ALERT_LEVEL_WARNING,
        TLS_ALERT_DESCRIPTION_CLOSE_NOTIFY,
        0,
    ];
    for body in [&[][..], &[TLS_ALERT_LEVEL_WARNING][..], &three[..]] {
        let record = classify_ktls_control_record(TLS_RECORD_TYPE_ALERT, body);
        let KtlsControlRecord::MalformedAlert { len } = record else {
            panic!(
                "a {}-byte alert body must fail closed, got {record}",
                body.len()
            );
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
        record_type, TLS_RECORD_TYPE_ALERT,
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
// Ancillary buffers are aligned, not assumed
//
// `CMSG_FIRSTHDR`/`CMSG_NXTHDR` hand back `*mut cmsghdr` pointers into the
// control buffer and both the writer and the reader dereference them. Backing
// that buffer with a bare `[u8; N]` (alignment 1) is undefined behaviour no
// matter how a given stack frame happens to be laid out, so every control
// buffer in `ktls_record` is an `AlignedCmsgBuf`. These tests pin the two
// properties the `CMSG_*` contract actually depends on — alignment and
// capacity — without needing a kTLS-capable kernel.
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[test]
fn ancillary_storage_is_aligned_and_sized_for_cmsghdr() {
    use ferrum_edge::proxy::ktls_record::AlignedCmsgBuf;

    let cmsg_align = std::mem::align_of::<libc::cmsghdr>();
    let buf_align = std::mem::align_of::<AlignedCmsgBuf>();
    assert_eq!(buf_align, cmsg_align, "must carry cmsghdr's alignment");

    // `CMSG_FIRSTHDR` returns a header pointer whenever `msg_controllen`
    // covers one `cmsghdr`, so the buffer has to be able to hold one.
    let header = std::mem::size_of::<libc::cmsghdr>();
    let capacity = AlignedCmsgBuf::CAPACITY;
    assert!(capacity >= header, "must hold one cmsghdr ({header} bytes)");

    // SAFETY: `CMSG_SPACE` is pure arithmetic over its length argument.
    let space = unsafe { libc::CMSG_SPACE(1) } as usize;
    // SAFETY: same.
    let len = unsafe { libc::CMSG_LEN(1) } as usize;
    assert!(
        space >= len,
        "CMSG_SPACE(1)={space} must cover CMSG_LEN(1)={len}"
    );
    assert!(
        space <= capacity,
        "CMSG_SPACE(1)={space} must fit {capacity}"
    );

    let mut buf = AlignedCmsgBuf::zeroed();
    let ptr = buf.as_mut_ptr() as usize;
    assert_eq!(ptr % cmsg_align, 0, "msg_control must be cmsghdr-aligned");

    // The byte view must clamp instead of over-reading past the storage.
    let clamped = buf.bytes(capacity + 64).len();
    assert_eq!(clamped, capacity, "the byte view must clamp to the buffer");
}

#[cfg(target_os = "linux")]
#[test]
fn constructed_control_message_is_cmsghdr_aligned() {
    let control = control_for(TLS_RECORD_TYPE_ALERT);
    let addr = control.as_bytes().as_ptr() as usize;
    // The bytes handed to `sendmsg` must still satisfy the CMSG_* contract.
    assert_eq!(
        addr % std::mem::align_of::<libc::cmsghdr>(),
        0,
        "stays aligned"
    );
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

// ── Traffic-key confidentiality budget ──────────────────────────────────────
//
// `dangerous_into_kernel_connection` ends rustls's own message accounting: its
// `kernel` module states that a `KernelConnection` cannot track how many
// messages a traffic key has protected and that aborting before the suite's
// `CipherSuiteCommon::confidentiality_limit` becomes the caller's job. In the
// pinned providers that limit is `1 << 24` for both TLS 1.2 AES-GCM suites and
// `u64::MAX` for ChaCha20-Poly1305.
//
// These tests pin the enforcement arithmetic and its fail-closed edges without
// a kernel: the syscall is injected as a closure, so "the counter is
// unreadable", "the counter went backwards", and "one more syscall cannot be
// proven safe" are all deterministic here. The live half — that a real kernel
// actually reports those counters, and that they already include the
// handshake's own records — is `proxy::ktls_live_kernel_tests`.

mod confidentiality {
    use ferrum_edge::proxy::ktls_confidentiality::{
        KTLS_CONFIDENTIALITY_RESERVE_RECORDS, KTLS_RECEIVE_QUEUE_OVERSHOOT_BYTES,
        KtlsConfidentialityError, KtlsConfidentialityGuard,
        KtlsConfidentialityPolicy, KtlsDirection, KtlsObservation, KtlsSessionLimits,
        MAX_TLS_PLAINTEXT_BYTES, MIN_TLS12_AEAD_RECORD_WIRE_BYTES, charge_or_observe,
        receive_record_bound, stable_receive_ceiling, transmit_record_bound,
    };
    use ferrum_edge::socket_opts::ktls::KtlsCipher;

    /// The AES-GCM confidentiality limit both pinned rustls providers carry.
    const AES_GCM_LIMIT: u64 = 1 << 24;

    fn aes_limits() -> KtlsSessionLimits {
        KtlsSessionLimits {
            cipher: KtlsCipher::Aes128Gcm,
            tls_version: 0x0303,
            confidentiality_limit: AES_GCM_LIMIT,
        }
    }

    fn aes_policy(tx_seq: u64, rx_seq: u64) -> KtlsConfidentialityPolicy {
        KtlsConfidentialityPolicy {
            limits: aes_limits(),
            initial_transmit_seq: tx_seq,
            initial_receive_seq: rx_seq,
            stable_receive_ceiling: 128 * 1024,
        }
    }

    fn guard_for(direction: KtlsDirection, seq: u64) -> KtlsConfidentialityGuard {
        let threshold = aes_limits().threshold();
        let guard = KtlsConfidentialityGuard::new(direction, threshold, seq, 1);
        guard.expect("a fresh session is inside its budget")
    }

    fn guard_with(threshold: u64, seq: u64, step: u64) -> KtlsConfidentialityGuard {
        let direction = KtlsDirection::Receive;
        let guard = KtlsConfidentialityGuard::new(direction, threshold, seq, step);
        guard.expect("a fresh session is inside its budget")
    }

    #[test]
    fn a_transmit_write_is_bounded_by_full_records_plus_one_partial() {
        // A write cannot produce more records than it has full ones, plus the
        // record an earlier write may have left partially filled.
        assert_eq!(transmit_record_bound(0), 1);
        assert_eq!(transmit_record_bound(1), 2);
        assert_eq!(transmit_record_bound(MAX_TLS_PLAINTEXT_BYTES), 2);
        assert_eq!(transmit_record_bound(MAX_TLS_PLAINTEXT_BYTES + 1), 3);
        assert_eq!(transmit_record_bound(128 * 1024), 9);
    }

    #[test]
    fn a_receive_is_bounded_by_the_buffer_ceiling_not_by_plaintext_bytes() {
        // This is the property plaintext byte counters cannot supply: a peer
        // choosing minimum-size records still cannot exceed
        // ceiling / 29 records, because that is all the buffer can hold.
        let ceiling = 64 * 1024u64;
        let expected = ceiling.div_ceil(MIN_TLS12_AEAD_RECORD_WIRE_BYTES) + 1;
        assert_eq!(receive_record_bound(ceiling), expected);
        assert!(
            receive_record_bound(ceiling) > ceiling / MAX_TLS_PLAINTEXT_BYTES,
            "the bound must not assume maximally sized records"
        );
        assert_eq!(receive_record_bound(0), 1);
    }

    #[test]
    fn the_stable_ceiling_covers_the_pinned_buffer_and_the_queue_behind_it() {
        // Once `SO_RCVBUF` is pinned the kernel only admits more data while the
        // queue sits below the pinned size, so every later instant satisfies
        // `queued <= max(queued_at_pin, pinned)`. Summing the two terms is a
        // strict over-approximation of that maximum, and the overshoot headroom
        // covers the one super-frame Linux may admit past the limit.
        let pinned = 425_984u64;
        let queued = 12_000u64;
        assert_eq!(
            stable_receive_ceiling(pinned, queued),
            pinned + queued + KTLS_RECEIVE_QUEUE_OVERSHOOT_BYTES
        );
        // Data queued under the old, unknowable buffer size is what the
        // `FIONREAD` term exists for: a large pre-pin queue must raise the
        // ceiling even when the pin came out small.
        let shrunk = stable_receive_ceiling(64 * 1024, 8 * 1024 * 1024);
        assert!(
            shrunk >= 8 * 1024 * 1024,
            "a queue larger than the pinned buffer must still be covered, got {shrunk}"
        );
        // Both terms are attacker-influenced only upwards, so the arithmetic
        // must saturate rather than wrap into a tiny ceiling.
        assert_eq!(stable_receive_ceiling(u64::MAX, u64::MAX), u64::MAX);
    }

    #[test]
    fn the_pinned_request_is_a_preference_and_never_the_bound() {
        // The request is only what `setsockopt` is asked for; Linux clamps it to
        // `net.core.rmem_max` and then doubles it, so the readback — modelled
        // here as an arbitrary pinned value unrelated to the request — is what
        // the ceiling is built from.
        let clamped_far_below_the_request = 64 * 1024u64;
        assert_eq!(
            stable_receive_ceiling(clamped_far_below_the_request, 0),
            clamped_far_below_the_request + KTLS_RECEIVE_QUEUE_OVERSHOOT_BYTES,
            "the ceiling must follow the kernel readback, not the requested size"
        );
    }

    #[test]
    fn the_handshakes_own_records_are_already_spent() {
        // A TLS 1.2 server has protected at least its `Finished` record in
        // each direction before handoff. Seeding the budget at zero would
        // overstate the headroom by exactly those records.
        let threshold = aes_limits().threshold();
        let fresh = guard_for(KtlsDirection::Transmit, 0);
        let after_handshake = guard_for(KtlsDirection::Transmit, 7);
        assert_eq!(fresh.allowance(), threshold);
        assert_eq!(after_handshake.allowance(), threshold - 7);
        assert_eq!(after_handshake.observed(), 7);
    }

    #[test]
    fn the_reserve_stops_the_relay_short_of_the_cipher_limit() {
        let limits = aes_limits();
        assert_eq!(
            limits.threshold(),
            AES_GCM_LIMIT - KTLS_CONFIDENTIALITY_RESERVE_RECORDS
        );
        assert!(limits.requires_enforcement());
    }

    #[test]
    fn a_session_already_past_its_budget_never_starts_relaying() {
        let threshold = aes_limits().threshold();
        let direction = KtlsDirection::Receive;
        let guard = KtlsConfidentialityGuard::new(direction, threshold, threshold, 1);
        let err = guard.expect_err("a session at its threshold must refuse");
        assert!(matches!(
            err,
            KtlsConfidentialityError::LimitReached {
                direction: KtlsDirection::Receive,
                ..
            }
        ));
        let spent_tx = aes_policy(threshold, 0);
        let spent_rx = aes_policy(0, threshold);
        assert!(spent_tx.guard(KtlsDirection::Transmit).is_err());
        assert!(spent_rx.guard(KtlsDirection::Receive).is_err());
    }

    #[test]
    fn both_directions_get_independent_budgets() {
        let policy = aes_policy(3, 11);
        let tx = policy
            .guard(KtlsDirection::Transmit)
            .expect("transmit guard builds")
            .expect("AES-GCM is enforced");
        let rx = policy
            .guard(KtlsDirection::Receive)
            .expect("receive guard builds")
            .expect("AES-GCM is enforced");
        assert_eq!(tx.direction(), KtlsDirection::Transmit);
        assert_eq!(rx.direction(), KtlsDirection::Receive);
        assert_eq!(tx.observed(), 3);
        assert_eq!(rx.observed(), 11);
        assert_ne!(
            tx.allowance(),
            rx.allowance(),
            "the two directions must not share one counter"
        );
        // The receive window is sized from the buffer ceiling; the transmit
        // window is charged per write.
        assert_eq!(
            rx.step_records(),
            receive_record_bound(policy.stable_receive_ceiling)
        );
    }

    #[test]
    fn an_unlimited_suite_is_not_penalised() {
        // ChaCha20-Poly1305 carries `confidentiality_limit: u64::MAX` in both
        // pinned providers. Enforcing nothing there is the correct posture.
        let cipher = KtlsCipher::Chacha20Poly1305;
        let policy = KtlsConfidentialityPolicy::unlimited(cipher, 0x0303);
        assert!(!policy.limits.requires_enforcement());
        let tx = policy.guard(KtlsDirection::Transmit);
        let rx = policy.guard(KtlsDirection::Receive);
        assert!(tx.expect("no error").is_none());
        assert!(rx.expect("no error").is_none());
    }

    #[test]
    fn charges_under_the_window_never_touch_the_kernel() {
        // The whole point of pre-charging: relaying must not add a syscall per
        // splice, let alone per byte.
        let mut guard = guard_for(KtlsDirection::Transmit, 0);
        let mut observations = 0usize;
        for _ in 0..10_000 {
            charge_or_observe(&mut guard, transmit_record_bound(128 * 1024), || {
                observations += 1;
                Ok(KtlsObservation { record_seq: 0 })
            })
            .expect("well inside the budget");
        }
        assert_eq!(observations, 0, "no observation should have been needed");
        assert_eq!(guard.allowance(), guard.threshold() - 10_000 * 9);
    }

    #[test]
    fn an_exhausted_window_observes_once_and_reopens() {
        let threshold = aes_limits().threshold();
        let mut guard = guard_with(threshold, 0, 4);
        // Burn the window down to nothing.
        assert!(guard.charge(threshold));
        let mut observations = 0usize;
        charge_or_observe(&mut guard, 4, || {
            observations += 1;
            Ok(KtlsObservation { record_seq: 1_000 })
        })
        .expect("the kernel counter proves headroom remains");
        assert_eq!(observations, 1);
        assert_eq!(guard.observed(), 1_000);
        assert_eq!(guard.allowance(), threshold - 1_000 - 4);
    }

    #[test]
    fn an_unreadable_kernel_counter_fails_closed() {
        let mut guard = guard_for(KtlsDirection::Receive, 0);
        assert!(guard.charge(guard.allowance()));
        let err = charge_or_observe(&mut guard, 1, || {
            Err(KtlsConfidentialityError::Unobservable {
                direction: KtlsDirection::Receive,
                detail: "ENOPROTOOPT".to_string(),
            })
        })
        .expect_err("an unreadable counter must not be treated as headroom");
        assert!(matches!(
            err,
            KtlsConfidentialityError::Unobservable {
                direction: KtlsDirection::Receive,
                ..
            }
        ));
        assert!(err.to_string().contains("receive"));
    }

    #[test]
    fn a_counter_that_moves_backwards_fails_closed() {
        let mut guard = guard_for(KtlsDirection::Transmit, 5_000);
        let err = guard
            .refresh(4_999)
            .expect_err("a regressing counter cannot bound anything");
        assert!(matches!(
            err,
            KtlsConfidentialityError::NonMonotonic {
                direction: KtlsDirection::Transmit,
                previous: 5_000,
                observed: 4_999,
            }
        ));
        // A counter that stands still is legitimate (an idle direction).
        guard.refresh(5_000).expect("a static counter is monotonic");
    }

    #[test]
    fn reaching_the_threshold_ends_the_relay() {
        let threshold = aes_limits().threshold();
        let mut guard = guard_for(KtlsDirection::Transmit, 0);
        assert!(guard.charge(guard.allowance()));
        let err = charge_or_observe(&mut guard, 1, || {
            Ok(KtlsObservation {
                record_seq: threshold,
            })
        })
        .expect_err("the traffic key must not be used past its bound");
        let text = err.to_string();
        assert!(text.contains("transmit"));
        assert!(
            text.contains("confidentiality limit"),
            "the relay failure must name the cause it will be attributed with"
        );
        match &err {
            KtlsConfidentialityError::LimitReached {
                direction,
                observed,
                threshold: reported,
            } => {
                assert_eq!(*direction, KtlsDirection::Transmit);
                assert_eq!(*observed, threshold);
                assert_eq!(*reported, threshold);
            }
            other => panic!("expected LimitReached, got {other:?}"),
        }
    }

    #[test]
    fn a_window_larger_than_the_remaining_budget_fails_closed() {
        // Near the threshold the next syscall's worst case may no longer fit.
        // That cannot be relayed "just this once": it is a refusal.
        let threshold = 1_000u64;
        let mut guard = guard_with(threshold, 0, 10);
        assert!(guard.charge(threshold));
        let err = charge_or_observe(&mut guard, 10, || Ok(KtlsObservation { record_seq: 995 }))
            .expect_err("a step that could cross the threshold must be refused");
        assert!(matches!(
            err,
            KtlsConfidentialityError::WindowExceedsBudget {
                direction: KtlsDirection::Receive,
                step_records: 10,
                remaining: 5,
            }
        ));
    }

    #[test]
    fn an_observation_reopens_the_window_but_never_resizes_the_step() {
        // The receive step is fixed at handoff against a kernel-pinned ceiling.
        // An observation may only move the sequence number; if it could also
        // widen the per-syscall bound, the mutable-ceiling hazard this design
        // removes would be back — a socket could be charged against one size and
        // then splice against a larger one.
        let policy = aes_policy(0, 0);
        let mut guard = policy
            .guard(KtlsDirection::Receive)
            .expect("receive guard builds")
            .expect("AES-GCM is enforced");
        let step = guard.step_records();
        assert_eq!(step, receive_record_bound(policy.stable_receive_ceiling));
        assert!(guard.charge(guard.allowance()));
        charge_or_observe(&mut guard, step, || Ok(KtlsObservation { record_seq: 10 }))
            .expect("headroom remains");
        assert_eq!(
            guard.step_records(),
            step,
            "no observation may resize the pinned receive window"
        );
        assert_eq!(guard.allowance(), guard.threshold() - 10 - step);
    }

    #[test]
    fn a_receive_step_is_charged_before_every_syscall_at_the_pinned_size() {
        // The pre-charge is what keeps `true_seq <= observed_seq + charges`, so
        // the number of splices a single observation window covers must follow
        // the pinned ceiling exactly — not a value re-measured later.
        let policy = KtlsConfidentialityPolicy {
            limits: aes_limits(),
            initial_transmit_seq: 0,
            initial_receive_seq: 0,
            stable_receive_ceiling: stable_receive_ceiling(425_984, 0),
        };
        let mut guard = policy
            .guard(KtlsDirection::Receive)
            .expect("receive guard builds")
            .expect("AES-GCM is enforced");
        let step = guard.step_records();
        let expected_charges = guard.allowance() / step;
        let mut observations = 0usize;
        for _ in 0..expected_charges {
            charge_or_observe(&mut guard, step, || {
                observations += 1;
                Ok(KtlsObservation { record_seq: 0 })
            })
            .expect("inside the first window");
        }
        assert_eq!(observations, 0, "the pinned window covers every splice");
        // The next charge no longer fits, so exactly one observation is paid
        // for — and a counter that has not moved reopens the full window.
        charge_or_observe(&mut guard, step, || {
            observations += 1;
            Ok(KtlsObservation { record_seq: 0 })
        })
        .expect("a static counter proves the budget is untouched");
        assert_eq!(observations, 1);
    }

    #[test]
    fn every_failure_names_the_direction_it_will_be_attributed_to() {
        // The relay maps a receive-budget failure to the client->backend read
        // side and a transmit-budget failure to the backend->client write
        // side, so the direction must survive into the error text.
        for direction in [KtlsDirection::Transmit, KtlsDirection::Receive] {
            let err = KtlsConfidentialityError::LimitReached {
                direction,
                observed: 1,
                threshold: 1,
            };
            assert!(err.to_string().contains(direction.as_str()));
            assert_eq!(
                direction.is_transmit(),
                direction == KtlsDirection::Transmit
            );
        }
    }
}
