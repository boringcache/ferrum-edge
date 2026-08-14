//! The accepted frontend TLS candidate binds verifier and trust identity
//! (issue #3857).
//!
//! The HTTP/3 endpoint applies a reload asynchronously, so it is the one
//! listener that cannot reassemble "the accepted generation" from parts. It
//! used to install a verifier rebuilt from a re-read client-CA source plus the
//! **startup** CRL clone, and then publish `ProxyFrontend`'s latest material as
//! its own generation. An accepted CRL rotation therefore advanced the H3
//! generation — retiring established H3 connections — while the verifier QUIC
//! kept handshaking with still had the old CRLs, so the very certificate the
//! rotation revoked could simply reconnect.
//!
//! These tests pin the replacement contract on the exact objects the H3 reload
//! arm consumes:
//!
//! - one accepted candidate carries the verifier AND the identity of the same
//!   client-CA bytes and CRLs;
//! - a CRL rotation produces a candidate whose verifier actually refuses the
//!   newly revoked client certificate, which is what makes a reconnect meet the
//!   new verifier rather than only tearing down the old connection;
//! - publishing that candidate's identity is a `Withdrawn`, and publishing the
//!   identity of a candidate that did not narrow authority is not;
//! - a malformed later candidate never becomes a candidate at all, so the
//!   last-good verifier, identity and generation are retained.
//!
//! No sleeps and no source races: every assertion is driven by loading a
//! candidate from files this test wrote, and by calling the verifier directly.

use std::sync::OnceLock;

use ferrum_edge::config::EnvConfig;
use ferrum_edge::tls::client_trust::{self, ClientTrustPublicationOutcome, ClientTrustScope};
use ferrum_edge::tls::{
    AcceptedClientTrust, ClientTrustMaterial, CrlList, TlsPolicy,
    load_frontend_tls_candidate_from_paths,
};
use rustls::pki_types::{CertificateDer, UnixTime};

// The trust registry is process-global and `reset_for_test` clears every scope,
// so this file shares the sibling suite's lock rather than taking its own.
use super::client_trust_tests::isolated_registry;

/// A serial that belongs to no certificate in these tests, so a CRL carrying
/// only it revokes nothing that is being verified.
const UNRELATED_SERIAL: u64 = 0xdead_beef;

fn ensure_crypto_provider() {
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn tls_policy() -> TlsPolicy {
    ensure_crypto_provider();
    TlsPolicy::from_env_config(&EnvConfig::default()).expect("tls policy")
}

/// A client CA plus one client certificate issued under it.
struct TestPki {
    ca_pem: String,
    client_der: Vec<u8>,
    client_serial: u64,
    issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
    server_cert_pem: String,
    server_key_pem: String,
}

fn build_pki() -> TestPki {
    ensure_crypto_provider();

    let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("CA key");
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("CA params");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Frontend Client CA");
    ca_params
        .key_usages
        .push(rcgen::KeyUsagePurpose::KeyCertSign);
    ca_params.key_usages.push(rcgen::KeyUsagePurpose::CrlSign);
    let ca_cert = ca_params.self_signed(&ca_key).expect("self-signed CA");
    let ca_pem = ca_cert.pem();
    let issuer = rcgen::Issuer::new(ca_params, ca_key);

    // The client certificate must carry the clientAuth EKU or webpki refuses it
    // before revocation is ever consulted, which would make the CRL assertions
    // vacuous.
    let client_serial = 0x3857u64;
    let client_key =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("client key");
    let mut client_params =
        rcgen::CertificateParams::new(Vec::<String>::new()).expect("client params");
    client_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "frontend-client");
    client_params
        .extended_key_usages
        .push(rcgen::ExtendedKeyUsagePurpose::ClientAuth);
    client_params
        .key_usages
        .push(rcgen::KeyUsagePurpose::DigitalSignature);
    client_params.serial_number = Some(rcgen::SerialNumber::from(client_serial));
    let client_cert = client_params
        .signed_by(&client_key, &issuer)
        .expect("client cert");
    let client_der = client_cert.der().to_vec();

    // An unrelated self-signed server identity; the frontend loader validates
    // it, but none of these assertions depend on it.
    let server_key =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("server key");
    let server_params =
        rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("server params");
    let server_cert = server_params
        .self_signed(&server_key)
        .expect("self-signed server cert");

    TestPki {
        ca_pem,
        client_der,
        client_serial,
        issuer,
        server_cert_pem: server_cert.pem(),
        server_key_pem: server_key.serialize_pem(),
    }
}

impl TestPki {
    /// A CRL revoking `serials`, re-issued at `crl_number`.
    fn crl_pem(&self, serials: &[u64], crl_number: u64) -> String {
        let now = time::OffsetDateTime::now_utc();
        rcgen::CertificateRevocationListParams {
            this_update: now,
            next_update: now + time::Duration::days(30),
            crl_number: rcgen::SerialNumber::from(crl_number),
            issuing_distribution_point: None,
            revoked_certs: serials
                .iter()
                .map(|serial| rcgen::RevokedCertParams {
                    serial_number: rcgen::SerialNumber::from(*serial),
                    revocation_time: now,
                    reason_code: Some(rcgen::RevocationReason::KeyCompromise),
                    invalidity_date: None,
                })
                .collect(),
            key_identifier_method: rcgen::KeyIdMethod::Sha256,
        }
        .signed_by(&self.issuer)
        .expect("sign CRL")
        .pem()
        .expect("CRL PEM")
    }

    fn client_cert(&self) -> CertificateDer<'static> {
        CertificateDer::from(self.client_der.clone())
    }
}

fn parse_crls(pem: &str) -> CrlList {
    std::sync::Arc::new(
        rustls_pemfile::crls(&mut pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .expect("parse CRLs"),
    )
}

/// Load one accepted frontend candidate exactly as the reload pipeline does.
fn load_candidate(
    dir: &std::path::Path,
    pki: &TestPki,
    crls: &CrlList,
) -> Result<AcceptedClientTrust, anyhow::Error> {
    let cert_path = dir.join("server-cert.pem");
    let key_path = dir.join("server-key.pem");
    let ca_path = dir.join("client-ca.pem");
    std::fs::write(&cert_path, pki.server_cert_pem.as_bytes()).expect("write server cert");
    std::fs::write(&key_path, pki.server_key_pem.as_bytes()).expect("write server key");
    std::fs::write(&ca_path, pki.ca_pem.as_bytes()).expect("write client CA");

    load_frontend_tls_candidate_from_paths(
        cert_path.to_str().expect("utf8 cert path"),
        key_path.to_str().expect("utf8 key path"),
        Some(ca_path.to_str().expect("utf8 ca path")),
        None,
        false,
        &tls_policy(),
        30,
        crls,
    )
    .map(|candidate| candidate.client_trust)
}

/// Whether the candidate's verifier admits the client certificate.
fn admits_client(trust: &AcceptedClientTrust, pki: &TestPki) -> bool {
    trust
        .verifier
        .as_ref()
        .expect("a configured client CA must yield a verifier")
        .verify_client_cert(&pki.client_cert(), &[], UnixTime::now())
        .is_ok()
}

/// The heart of the finding: an accepted CRL rotation must reach the verifier a
/// reconnecting HTTP/3 client meets, not merely retire the old connection.
///
/// The H3 reload arm installs `AcceptedClientTrust::verifier` and publishes
/// `AcceptedClientTrust::material` from ONE value, so proving the rotated
/// candidate's verifier refuses the revoked certificate proves the reconnect is
/// refused too. Under the old code the H3 verifier was rebuilt with the startup
/// CRL clone, which is exactly the `before` candidate here — it still admits the
/// certificate the rotation revoked.
#[test]
fn an_accepted_crl_rotation_changes_the_verifier_a_reconnect_meets() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pki = build_pki();

    // Generation 1: a CRL that revokes an unrelated serial. Non-empty on
    // purpose — an empty revocation list is a needless encoding edge case, and
    // the point here is only that the client's own serial is not on it.
    let startup_crls = parse_crls(&pki.crl_pem(&[UNRELATED_SERIAL], 1));
    let before = load_candidate(dir.path(), &pki, &startup_crls).expect("startup candidate");
    assert!(
        admits_client(&before, &pki),
        "the startup verifier must admit a client certificate no CRL revokes"
    );

    // Generation 2: the operator revokes the client's serial.
    let rotated_crls = parse_crls(&pki.crl_pem(&[UNRELATED_SERIAL, pki.client_serial], 2));
    let after = load_candidate(dir.path(), &pki, &rotated_crls).expect("rotated candidate");
    assert!(
        !admits_client(&after, &pki),
        "the accepted candidate's verifier must refuse the newly revoked client certificate; \
         reusing the startup CRL clone here is what let a revoked client reconnect over HTTP/3"
    );

    // ...and the identity published alongside it describes those same CRLs, so
    // the generation cannot advance ahead of what the verifier enforces.
    assert_eq!(
        after.material,
        ClientTrustMaterial::from_parts(Some(pki.ca_pem.as_bytes()), &rotated_crls)
            .expect("summarize rotated material"),
        "the candidate's identity must describe the CRLs compiled into its verifier"
    );
    assert_ne!(
        before.material, after.material,
        "a new revocation is a semantically different accepted generation"
    );
}

/// The published generation is derived from the adopted candidate, so a
/// withdrawal is reported exactly when the adopted verifier narrowed.
#[test]
fn publishing_the_adopted_candidates_identity_reports_the_withdrawal_it_enforces() {
    let _guard = isolated_registry();
    let dir = tempfile::tempdir().expect("tempdir");
    let pki = build_pki();

    let startup_crls = parse_crls(&pki.crl_pem(&[UNRELATED_SERIAL], 1));
    let before = load_candidate(dir.path(), &pki, &startup_crls).expect("startup candidate");
    // The H3 listener arms its own scope from the verifier it installed.
    let armed =
        client_trust::publish_accepted_material(ClientTrustScope::ProxyH3, before.material.clone());
    assert_eq!(armed.outcome, ClientTrustPublicationOutcome::Armed);

    // A connection admitted under that verifier.
    let session = client_trust::capture(ClientTrustScope::ProxyH3)
        .expect("armed")
        .register(true)
        .expect("client-certificate transport");

    // A routine CRL re-issue over the same revocation set is not a withdrawal:
    // the verifier still admits the same principals, so nothing is churned.
    let reissued_crls = parse_crls(&pki.crl_pem(&[UNRELATED_SERIAL], 2));
    let reissued = load_candidate(dir.path(), &pki, &reissued_crls).expect("re-issued candidate");
    assert!(
        admits_client(&reissued, &pki),
        "a re-issued CRL over the same set must still admit the client"
    );
    let unchanged =
        client_trust::publish_accepted_material(ClientTrustScope::ProxyH3, reissued.material);
    assert_eq!(
        unchanged.outcome,
        ClientTrustPublicationOutcome::Unchanged,
        "an additive/no-op trust change must not churn sessions"
    );
    assert!(!session.session().is_retired());

    // The real revocation narrows authority: the adopted verifier refuses the
    // certificate, and the generation published for it retires the transport
    // that was admitted under the old one.
    let rotated_crls = parse_crls(&pki.crl_pem(&[UNRELATED_SERIAL, pki.client_serial], 3));
    let rotated = load_candidate(dir.path(), &pki, &rotated_crls).expect("rotated candidate");
    assert!(!admits_client(&rotated, &pki));
    let withdrawn =
        client_trust::publish_accepted_material(ClientTrustScope::ProxyH3, rotated.material);
    assert!(
        withdrawn.withdrew(),
        "adopting a verifier that revokes a live peer must publish a withdrawal"
    );
    assert_eq!(withdrawn.retired_sessions, 1);
    assert!(
        session.session().is_retired(),
        "the established transport admitted under the previous verifier is retired"
    );

    // A transport that reconnects now captures the new generation, and the
    // verifier it meets is the one that refuses it — the two halves cannot
    // disagree because they came from one candidate.
    let reconnected = client_trust::capture(ClientTrustScope::ProxyH3)
        .expect("armed")
        .register(true)
        .expect("client-certificate transport");
    assert!(
        !reconnected.session().is_retired(),
        "a reconnect is admitted by the fence and refused by the verifier, not the reverse"
    );
}

/// A malformed later candidate never produces an `AcceptedClientTrust`, so the
/// H3 reload arm has nothing to install or publish and keeps the last-good
/// verifier, identity, generation and sessions. mTLS is never downgraded.
#[test]
fn a_malformed_later_candidate_retains_the_last_good_trust() {
    let _guard = isolated_registry();
    let dir = tempfile::tempdir().expect("tempdir");
    let pki = build_pki();

    let rotated_crls = parse_crls(&pki.crl_pem(&[pki.client_serial], 1));
    let good = load_candidate(dir.path(), &pki, &rotated_crls).expect("accepted candidate");
    client_trust::publish_accepted_material(ClientTrustScope::ProxyH3, good.material.clone());
    let session = client_trust::capture(ClientTrustScope::ProxyH3)
        .expect("armed")
        .register(true)
        .expect("client-certificate transport");

    // The client-CA source is truncated mid-rotation.
    let ca_path = dir.path().join("client-ca.pem");
    std::fs::write(&ca_path, b"-----BEGIN CERTIFICATE-----\nnot base64\n").expect("truncate CA");
    let refused = load_frontend_tls_candidate_from_paths(
        dir.path()
            .join("server-cert.pem")
            .to_str()
            .expect("utf8 cert path"),
        dir.path()
            .join("server-key.pem")
            .to_str()
            .expect("utf8 key path"),
        Some(ca_path.to_str().expect("utf8 ca path")),
        None,
        false,
        &tls_policy(),
        30,
        &rotated_crls,
    );
    assert!(
        refused.is_err(),
        "an unloadable client-CA candidate must fail closed rather than yield an empty trust set"
    );
    client_trust::record_rejected_candidate(ClientTrustScope::ProxyH3);

    // Last-good state is intact: the verifier still refuses the revoked client,
    // the generation did not advance, and no session was touched.
    assert!(!admits_client(&good, &pki));
    assert_eq!(
        client_trust::current_material(ClientTrustScope::ProxyH3),
        Some(good.material),
        "a refused candidate retains the last accepted identity"
    );
    assert!(!session.session().is_retired());
}
