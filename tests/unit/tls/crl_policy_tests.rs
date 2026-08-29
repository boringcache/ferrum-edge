//! One CRL policy for every verifier Ferrum builds (issues #4297 and #4298).
//!
//! Two defects shared a call site. Every CRL-enabled verifier selected rustls's
//! leaf-only revocation depth, so an intermediate CA revoked by its own issuer
//! kept authenticating the certificates it had signed (#4298); and no verifier
//! enabled `enforce_revocation_expiration()` while admission stopped at PEM
//! parsing, so a CRL that had passed `nextUpdate` — or one that had never
//! declared a `nextUpdate` at all — stayed authoritative forever (#4297).
//!
//! These tests pin the replacement on three levels:
//!
//! 1. **The temporal rule**, on `crl_policy` directly, at each boundary, with an
//!    injected instant rather than a sleep.
//! 2. **The admission paths**, on `tls::load_crls` — the single choke point that
//!    startup, config load, and every live reload share — so an unusable record
//!    refuses the whole candidate and the caller keeps its last good state.
//! 3. **The verifiers themselves**, on the production builders, using a real
//!    `root -> intermediate -> leaf` PKI: a revoked intermediate stops its
//!    leaves, a sibling branch is untouched, an uncovered chain is still
//!    accepted, and an already-built verifier stops authorizing once the clock
//!    passes the CRL's `nextUpdate`.
//!
//! A static inventory closes the loop over the surfaces whose full handshake
//! fixtures would be pure duplication (frontend/admin mTLS, mesh operator-CA,
//! DTLS, the LDAP and logging sinks): no production call site may reintroduce
//! the leaf-only option, construct a CRL-enabled verifier outside the shared
//! policy, or admit CRLs through a second validator.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use arc_swap::ArcSwap;
use ferrum_edge::config::types::BackendTlsConfig;
use ferrum_edge::health_check::build_probe_server_verifier_for_test;
use ferrum_edge::identity::{SpiffeId, SvidBundle, TrustBundle, TrustBundleSet, TrustDomain};
use ferrum_edge::tls::crl_policy::{
    self, CrlWindowRejection, apply_client_crl_policy, classify_crl_window, validate_crl_windows_at,
};
use ferrum_edge::tls::{
    build_client_cert_verifier, build_server_verifier_with_crls, build_spiffe_client_cert_verifier,
    load_crls,
};
use rcgen::string::Ia5String;
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, DnType,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, RevocationReason,
    RevokedCertParams, SanType, SerialNumber,
};
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, ServerName, UnixTime};
use rustls::server::danger::ClientCertVerifier;
use rustls::{CertificateError, Error as RustlsError};
use tempfile::TempDir;
use time::{Duration as TimeDuration, OffsetDateTime};

fn ensure_crypto_provider() {
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

// ── PKI fixtures ─────────────────────────────────────────────────────────

const INTERMEDIATE_A_SERIAL: u64 = 0x4298_00a1;
const INTERMEDIATE_B_SERIAL: u64 = 0x4298_00b1;
const LEAF_A_SERIAL: u64 = 0x4298_00a2;
const LEAF_B_SERIAL: u64 = 0x4298_00b2;
/// A serial no certificate in this file carries, so a CRL holding only it
/// revokes nothing under verification.
const UNRELATED_SERIAL: u64 = 0x4297_dead;

const LEAF_A_DNS: &str = "leaf-a.crl-policy.test";
const LEAF_B_DNS: &str = "leaf-b.crl-policy.test";
const TRUST_DOMAIN: &str = "crl-policy.test";

/// `root -> intermediate A -> leaf A` and `root -> intermediate B -> leaf B`
/// under one root, plus an unrelated CA whose CRLs are authoritative for
/// nothing here.
struct ChainPki {
    root_pem: String,
    root_der: CertificateDer<'static>,
    root_issuer: Issuer<'static, KeyPair>,
    intermediate_a_der: CertificateDer<'static>,
    intermediate_a_issuer: Issuer<'static, KeyPair>,
    intermediate_b_der: CertificateDer<'static>,
    leaf_a_der: CertificateDer<'static>,
    leaf_b_der: CertificateDer<'static>,
    spiffe_leaf_a_der: CertificateDer<'static>,
    unrelated_issuer: Issuer<'static, KeyPair>,
}

fn ca_params(common_name: &str, serial: Option<u64>) -> CertificateParams {
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    params.key_usages.push(KeyUsagePurpose::CrlSign);
    params.serial_number = serial.map(SerialNumber::from);
    params
}

/// A leaf carrying both EKUs, so the same fixture can be driven through the
/// client-certificate verifier and the server-certificate verifier.
fn leaf_params(dns: &str, common_name: &str, serial: u64) -> CertificateParams {
    let mut params = CertificateParams::new(vec![dns.to_string()]).expect("leaf params");
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ClientAuth);
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params.serial_number = Some(SerialNumber::from(serial));
    params
}

fn ecdsa_key() -> KeyPair {
    KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("ecdsa key")
}

fn build_chain_pki() -> ChainPki {
    ensure_crypto_provider();

    let root_key = ecdsa_key();
    let root_params = ca_params("CRL Policy Root", None);
    let root_cert = root_params
        .self_signed(&root_key)
        .expect("self-signed root");
    let root_pem = root_cert.pem();
    let root_der = CertificateDer::from(root_cert.der().to_vec());
    let root_issuer = Issuer::new(root_params, root_key);

    let intermediate_a_key = ecdsa_key();
    let intermediate_a_params = ca_params("CRL Policy Intermediate A", Some(INTERMEDIATE_A_SERIAL));
    let intermediate_a_cert = intermediate_a_params
        .signed_by(&intermediate_a_key, &root_issuer)
        .expect("intermediate A");
    let intermediate_a_der = CertificateDer::from(intermediate_a_cert.der().to_vec());
    let intermediate_a_issuer = Issuer::new(intermediate_a_params, intermediate_a_key);

    let intermediate_b_key = ecdsa_key();
    let intermediate_b_params = ca_params("CRL Policy Intermediate B", Some(INTERMEDIATE_B_SERIAL));
    let intermediate_b_cert = intermediate_b_params
        .signed_by(&intermediate_b_key, &root_issuer)
        .expect("intermediate B");
    let intermediate_b_der = CertificateDer::from(intermediate_b_cert.der().to_vec());
    let intermediate_b_issuer = Issuer::new(intermediate_b_params, intermediate_b_key);

    let leaf_a_key = ecdsa_key();
    let leaf_a_cert = leaf_params(LEAF_A_DNS, "leaf-a", LEAF_A_SERIAL)
        .signed_by(&leaf_a_key, &intermediate_a_issuer)
        .expect("leaf A");
    let leaf_a_der = CertificateDer::from(leaf_a_cert.der().to_vec());

    let leaf_b_key = ecdsa_key();
    let leaf_b_cert = leaf_params(LEAF_B_DNS, "leaf-b", LEAF_B_SERIAL)
        .signed_by(&leaf_b_key, &intermediate_b_issuer)
        .expect("leaf B");
    let leaf_b_der = CertificateDer::from(leaf_b_cert.der().to_vec());

    // The SPIFFE verifier identifies a peer by its URI SAN, so its leaf needs
    // one; it is otherwise the same `intermediate A` branch.
    let spiffe_leaf_key = ecdsa_key();
    let mut spiffe_leaf_params =
        CertificateParams::new(Vec::<String>::new()).expect("spiffe leaf params");
    spiffe_leaf_params
        .distinguished_name
        .push(DnType::CommonName, "spiffe-leaf-a");
    spiffe_leaf_params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ClientAuth);
    spiffe_leaf_params
        .key_usages
        .push(KeyUsagePurpose::DigitalSignature);
    spiffe_leaf_params.serial_number = Some(SerialNumber::from(LEAF_A_SERIAL));
    let spiffe_uri = format!("spiffe://{TRUST_DOMAIN}/ns/test/sa/peer");
    let spiffe_uri = Ia5String::try_from(spiffe_uri).expect("spiffe uri is IA5");
    spiffe_leaf_params
        .subject_alt_names
        .push(SanType::URI(spiffe_uri));
    let spiffe_leaf_cert = spiffe_leaf_params
        .signed_by(&spiffe_leaf_key, &intermediate_a_issuer)
        .expect("spiffe leaf A");
    let spiffe_leaf_a_der = CertificateDer::from(spiffe_leaf_cert.der().to_vec());

    let unrelated_key = ecdsa_key();
    let unrelated_params = ca_params("CRL Policy Unrelated CA", None);
    let unrelated_issuer = Issuer::new(unrelated_params, unrelated_key);

    ChainPki {
        root_pem,
        root_der,
        root_issuer,
        intermediate_a_der,
        intermediate_a_issuer,
        intermediate_b_der,
        leaf_a_der,
        leaf_b_der,
        spiffe_leaf_a_der,
        unrelated_issuer,
    }
}

/// A properly signed CRL revoking `serials`, valid from `this_update` until
/// `next_update`.
fn signed_crl_der(
    issuer: &Issuer<'static, KeyPair>,
    serials: &[u64],
    this_update: OffsetDateTime,
    next_update: OffsetDateTime,
) -> Vec<u8> {
    let revoked_certs = serials
        .iter()
        .map(|serial| RevokedCertParams {
            serial_number: SerialNumber::from(*serial),
            revocation_time: this_update,
            reason_code: Some(RevocationReason::KeyCompromise),
            invalidity_date: None,
        })
        .collect();
    let params = CertificateRevocationListParams {
        this_update,
        next_update,
        crl_number: SerialNumber::from(1u64),
        issuing_distribution_point: None,
        revoked_certs,
        key_identifier_method: rcgen::KeyIdMethod::Sha256,
    };
    params.signed_by(issuer).expect("sign CRL").der().to_vec()
}

fn crl_list(ders: Vec<Vec<u8>>) -> Vec<CertificateRevocationListDer<'static>> {
    ders.into_iter()
        .map(CertificateRevocationListDer::from)
        .collect()
}

/// A CRL that is comfortably inside its own validity window right now.
fn fresh_crl(issuer: &Issuer<'static, KeyPair>, serials: &[u64]) -> Vec<u8> {
    let now = OffsetDateTime::now_utc();
    signed_crl_der(
        issuer,
        serials,
        now - TimeDuration::hours(1),
        now + TimeDuration::days(30),
    )
}

// ── DER surgery for the temporal edge cases ──────────────────────────────

fn der_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len <= 0xff {
        vec![0x81, len as u8]
    } else if len <= 0xffff {
        vec![0x82, (len >> 8) as u8, (len & 0xff) as u8]
    } else {
        panic!("test CRL is unexpectedly large");
    }
}

/// Split one DER TLV off the front of `input`, returning
/// `(tag, content, rest)`.
fn read_tlv(input: &[u8]) -> (u8, &[u8], &[u8]) {
    assert!(input.len() >= 2, "truncated DER");
    let tag = input[0];
    let first = input[1] as usize;
    let (len, header) = if first < 0x80 {
        (first, 2)
    } else {
        let count = first & 0x7f;
        assert!(count > 0 && count <= 4, "unsupported DER length form");
        let mut len = 0usize;
        for byte in &input[2..2 + count] {
            len = (len << 8) | *byte as usize;
        }
        (len, 2 + count)
    };
    assert!(input.len() >= header + len, "truncated DER value");
    (tag, &input[header..header + len], &input[header + len..])
}

fn wrap(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(der_len(content.len()));
    out.extend_from_slice(content);
    out
}

fn utc_time_tlv(at: OffsetDateTime) -> Vec<u8> {
    let text = format!(
        "{:02}{:02}{:02}{:02}{:02}{:02}Z",
        at.year() % 100,
        u8::from(at.month()),
        at.day(),
        at.hour(),
        at.minute(),
        at.second()
    );
    wrap(0x17, text.as_bytes())
}

/// Rebuild a real CRL with different `thisUpdate` / `nextUpdate` values.
///
/// The two `Time` fields of `tbsCertList` are the only things replaced; every
/// other field and the signature are carried through byte for byte. `None` for
/// `next_update` drops the field entirely — the one shape `rcgen` cannot emit,
/// and the shape RFC 5280 §5.1.2.5 forbids conforming issuers from emitting.
/// The signature no longer matches the rewritten body, which is exactly right
/// for these tests: admission validates the temporal window before any signer
/// is known, and every verifier test below uses a properly signed CRL.
fn retime_crl(
    crl_der: &[u8],
    this_update: OffsetDateTime,
    next_update: Option<OffsetDateTime>,
) -> Vec<u8> {
    let (outer_tag, outer, outer_rest) = read_tlv(crl_der);
    assert_eq!(outer_tag, 0x30, "a CRL is a SEQUENCE");
    assert!(outer_rest.is_empty(), "trailing bytes after the CRL");

    let (tbs_tag, tbs, after_tbs) = read_tlv(outer);
    assert_eq!(tbs_tag, 0x30, "tbsCertList is a SEQUENCE");

    let mut rebuilt: Vec<u8> = Vec::new();
    let mut rest = tbs;
    let mut times_seen = 0;
    while !rest.is_empty() {
        let (tag, _content, next) = read_tlv(rest);
        let element = &rest[..rest.len() - next.len()];
        if tag == 0x17 || tag == 0x18 {
            times_seen += 1;
            match times_seen {
                1 => rebuilt.extend(utc_time_tlv(this_update)),
                2 => {
                    if let Some(next_update) = next_update {
                        rebuilt.extend(utc_time_tlv(next_update));
                    }
                }
                _ => rebuilt.extend_from_slice(element),
            }
        } else {
            rebuilt.extend_from_slice(element);
        }
        rest = next;
    }
    assert_eq!(
        times_seen, 2,
        "an rcgen CRL carries exactly thisUpdate and nextUpdate at the top level"
    );

    let mut outer_content = wrap(0x30, &rebuilt);
    outer_content.extend_from_slice(after_tbs);
    wrap(0x30, &outer_content)
}

fn crl_pem(der: &[u8]) -> String {
    use base64::Engine as _;

    let body = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::from("-----BEGIN X509 CRL-----\n");
    for chunk in body.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ascii"));
        out.push('\n');
    }
    out.push_str("-----END X509 CRL-----\n");
    out
}

fn unix(at: OffsetDateTime) -> i64 {
    at.unix_timestamp()
}

/// An explicit verification instant, so a test can move a handshake across a
/// CRL boundary without sleeping.
fn at(unix_seconds: i64) -> UnixTime {
    UnixTime::since_unix_epoch(Duration::from_secs(unix_seconds as u64))
}

// ── 1. The temporal rule and its boundaries (issue #4297) ────────────────

#[test]
fn a_crl_inside_its_validity_window_is_admitted() {
    let pki = build_chain_pki();
    let crls = crl_list(vec![fresh_crl(&pki.root_issuer, &[UNRELATED_SERIAL])]);
    let now = unix(OffsetDateTime::now_utc());

    validate_crl_windows_at(&crls, "test-source", now).expect("a fresh CRL is admitted");
}

#[test]
fn a_crl_whose_this_update_is_in_the_future_is_refused() {
    let pki = build_chain_pki();
    let base = OffsetDateTime::now_utc();
    let der = retime_crl(
        &fresh_crl(&pki.root_issuer, &[UNRELATED_SERIAL]),
        base + TimeDuration::hours(1),
        Some(base + TimeDuration::days(30)),
    );
    let crls = crl_list(vec![der]);

    assert_eq!(
        classify_crl_window(&crls[0], unix(base)),
        Err(CrlWindowRejection::NotYetValid),
    );
    let error = validate_crl_windows_at(&crls, "test-source", unix(base))
        .expect_err("a not-yet-valid CRL is refused");
    assert!(error.contains("not yet valid"), "unexpected error: {error}");
}

#[test]
fn this_update_exactly_at_the_admission_instant_is_admitted() {
    let pki = build_chain_pki();
    let base = OffsetDateTime::now_utc();
    let der = retime_crl(
        &fresh_crl(&pki.root_issuer, &[UNRELATED_SERIAL]),
        base,
        Some(base + TimeDuration::days(30)),
    );
    let crls = crl_list(vec![der]);

    // `thisUpdate > now` is the refusal, so equality is inside the window.
    assert_eq!(classify_crl_window(&crls[0], unix(base)), Ok(()));
}

#[test]
fn a_crl_past_its_next_update_is_refused() {
    let pki = build_chain_pki();
    let base = OffsetDateTime::now_utc();
    let der = retime_crl(
        &fresh_crl(&pki.root_issuer, &[UNRELATED_SERIAL]),
        base - TimeDuration::days(30),
        Some(base - TimeDuration::days(1)),
    );
    let crls = crl_list(vec![der]);

    assert_eq!(
        classify_crl_window(&crls[0], unix(base)),
        Err(CrlWindowRejection::Expired),
    );
    let error = validate_crl_windows_at(&crls, "test-source", unix(base))
        .expect_err("an expired CRL is refused");
    assert!(error.contains("has expired"), "unexpected error: {error}");
}

#[test]
fn the_next_update_boundary_matches_what_rustls_enforces() {
    let pki = build_chain_pki();
    let base = OffsetDateTime::now_utc();
    let next_update = base + TimeDuration::hours(1);
    let der = retime_crl(
        &fresh_crl(&pki.root_issuer, &[UNRELATED_SERIAL]),
        base - TimeDuration::hours(1),
        Some(next_update),
    );
    let crls = crl_list(vec![der]);

    // webpki refuses on `now >= nextUpdate`. Admission uses the same test, so a
    // candidate admission accepts is always one the handshake path can use.
    assert_eq!(
        classify_crl_window(&crls[0], unix(next_update) - 1),
        Ok(()),
        "one second before nextUpdate is still inside the window"
    );
    assert_eq!(
        classify_crl_window(&crls[0], unix(next_update)),
        Err(CrlWindowRejection::Expired),
        "nextUpdate itself is already outside the window"
    );
}

#[test]
fn a_crl_without_a_next_update_is_refused() {
    let pki = build_chain_pki();
    let base = OffsetDateTime::now_utc();
    let der = retime_crl(
        &fresh_crl(&pki.root_issuer, &[UNRELATED_SERIAL]),
        base - TimeDuration::hours(1),
        None,
    );
    let crls = crl_list(vec![der]);

    assert_eq!(
        classify_crl_window(&crls[0], unix(base)),
        Err(CrlWindowRejection::MissingNextUpdate),
    );
    let error = validate_crl_windows_at(&crls, "test-source", unix(base))
        .expect_err("a CRL with no declared expiry is refused");
    assert!(error.contains("nextUpdate"), "unexpected error: {error}");
}

#[test]
fn a_record_that_is_not_a_crl_is_refused() {
    let crls = crl_list(vec![b"not a CRL at all".to_vec()]);

    assert_eq!(
        classify_crl_window(&crls[0], unix(OffsetDateTime::now_utc())),
        Err(CrlWindowRejection::Unparseable),
    );
}

#[test]
fn refusal_diagnostics_carry_no_crl_contents() {
    let pki = build_chain_pki();
    let base = OffsetDateTime::now_utc();
    let der = retime_crl(
        &fresh_crl(&pki.root_issuer, &[UNRELATED_SERIAL]),
        base - TimeDuration::days(30),
        Some(base - TimeDuration::days(1)),
    );
    let crls = crl_list(vec![der]);
    let error = validate_crl_windows_at(&crls, "redacted-source", unix(base))
        .expect_err("expired CRL is refused");

    // Only the record index, the caller's already-redacted display id, and a
    // fixed reason. No issuer name, no serials, no timestamps.
    assert_eq!(
        error,
        "CRL record #1 in 'redacted-source' has expired (nextUpdate has passed)"
    );
    assert!(!error.contains("CRL Policy Root"));
    assert!(!error.contains(&base.year().to_string()));
}

// ── 2. Admission is atomic and shared ────────────────────────────────────

#[test]
fn one_unusable_record_refuses_the_whole_multi_crl_candidate() {
    let pki = build_chain_pki();
    let base = OffsetDateTime::now_utc();
    let good = fresh_crl(&pki.root_issuer, &[UNRELATED_SERIAL]);
    let expired = retime_crl(
        &fresh_crl(&pki.unrelated_issuer, &[UNRELATED_SERIAL]),
        base - TimeDuration::days(30),
        Some(base - TimeDuration::days(1)),
    );

    let good_then_expired = crl_list(vec![good.clone(), expired.clone()]);
    let error = validate_crl_windows_at(&good_then_expired, "bundle", unix(base))
        .expect_err("a usable prefix does not rescue the candidate");
    assert!(error.contains("record #2"), "unexpected error: {error}");

    let expired_then_good = crl_list(vec![expired, good]);
    let error = validate_crl_windows_at(&expired_then_good, "bundle", unix(base))
        .expect_err("a usable suffix does not rescue the candidate either");
    assert!(error.contains("record #1"), "unexpected error: {error}");
}

#[test]
fn load_crls_admits_a_fresh_source_and_refuses_an_expired_one() {
    let pki = build_chain_pki();
    let base = OffsetDateTime::now_utc();
    let dir = TempDir::new().expect("temp dir");

    let fresh_path = dir.path().join("fresh.crl.pem");
    std::fs::write(
        &fresh_path,
        crl_pem(&fresh_crl(&pki.root_issuer, &[UNRELATED_SERIAL])),
    )
    .expect("write fresh CRL");
    let loaded = load_crls(Some(fresh_path.to_str().expect("utf-8 path")))
        .expect("a fresh CRL source loads");
    assert_eq!(loaded.len(), 1);

    let expired_der = retime_crl(
        &fresh_crl(&pki.root_issuer, &[UNRELATED_SERIAL]),
        base - TimeDuration::days(30),
        Some(base - TimeDuration::days(1)),
    );
    let expired_path = dir.path().join("expired.crl.pem");
    std::fs::write(&expired_path, crl_pem(&expired_der)).expect("write expired CRL");
    let error = load_crls(Some(expired_path.to_str().expect("utf-8 path")))
        .expect_err("an expired CRL source is refused at admission")
        .to_string();
    assert!(error.contains("has expired"), "unexpected error: {error}");

    // The refusal is what preserves last-known-good state: every startup,
    // config-load, and live-reload caller propagates this `Err` instead of
    // publishing a new generation.
    let missing_next_update = retime_crl(
        &fresh_crl(&pki.root_issuer, &[UNRELATED_SERIAL]),
        base - TimeDuration::hours(1),
        None,
    );
    let no_expiry_path = dir.path().join("no-next-update.crl.pem");
    std::fs::write(&no_expiry_path, crl_pem(&missing_next_update)).expect("write CRL");
    let error = load_crls(Some(no_expiry_path.to_str().expect("utf-8 path")))
        .expect_err("a CRL with no declared expiry is refused")
        .to_string();
    assert!(error.contains("nextUpdate"), "unexpected error: {error}");
}

#[test]
fn load_crls_refuses_a_bundle_whose_second_record_expired() {
    let pki = build_chain_pki();
    let base = OffsetDateTime::now_utc();
    let dir = TempDir::new().expect("temp dir");

    let mut bundle = crl_pem(&fresh_crl(&pki.root_issuer, &[UNRELATED_SERIAL]));
    bundle.push_str(&crl_pem(&retime_crl(
        &fresh_crl(&pki.unrelated_issuer, &[UNRELATED_SERIAL]),
        base - TimeDuration::days(30),
        Some(base - TimeDuration::days(1)),
    )));
    let path = dir.path().join("bundle.crl.pem");
    std::fs::write(&path, bundle).expect("write bundle");

    let error = load_crls(Some(path.to_str().expect("utf-8 path")))
        .expect_err("the usable first record must not be published on its own")
        .to_string();
    assert!(error.contains("record #2"), "unexpected error: {error}");
}

// ── 3. The verifiers (issues #4297 and #4298) ────────────────────────────

fn client_verifier(
    pki: &ChainPki,
    crls: &[CertificateRevocationListDer<'static>],
) -> (TempDir, Arc<dyn ClientCertVerifier>) {
    let dir = TempDir::new().expect("temp dir");
    let ca_path = dir.path().join("root.pem");
    std::fs::write(&ca_path, &pki.root_pem).expect("write root");
    let verifier = build_client_cert_verifier(ca_path.to_str().expect("utf-8 path"), crls)
        .expect("client certificate verifier");
    (dir, verifier)
}

fn server_verifier(
    pki: &ChainPki,
    crls: &[CertificateRevocationListDer<'static>],
) -> Arc<rustls::client::WebPkiServerVerifier> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(pki.root_der.clone()).expect("add root");
    build_server_verifier_with_crls(roots, crls).expect("server certificate verifier")
}

fn verify_server(
    verifier: &rustls::client::WebPkiServerVerifier,
    leaf: &CertificateDer<'static>,
    intermediate: &CertificateDer<'static>,
    dns: &str,
    at: UnixTime,
) -> Result<(), RustlsError> {
    let name = ServerName::try_from(dns).expect("server name");
    verifier
        .verify_server_cert(leaf, std::slice::from_ref(intermediate), &name, &[], at)
        .map(|_| ())
}

#[test]
fn a_revoked_intermediate_stops_the_leaves_it_issued() {
    let pki = build_chain_pki();
    let crls = crl_list(vec![fresh_crl(&pki.root_issuer, &[INTERMEDIATE_A_SERIAL])]);
    let (_dir, verifier) = client_verifier(&pki, &crls);

    let error = verifier
        .verify_client_cert(
            &pki.leaf_a_der,
            std::slice::from_ref(&pki.intermediate_a_der),
            UnixTime::now(),
        )
        .expect_err("a chain through a revoked intermediate must be refused");
    assert!(
        matches!(
            error,
            RustlsError::InvalidCertificate(CertificateError::Revoked)
        ),
        "expected a revocation refusal, got {error:?}"
    );
}

#[test]
fn a_sibling_intermediate_branch_is_untouched_by_the_revocation() {
    let pki = build_chain_pki();
    let crls = crl_list(vec![fresh_crl(&pki.root_issuer, &[INTERMEDIATE_A_SERIAL])]);
    let (_dir, verifier) = client_verifier(&pki, &crls);

    verifier
        .verify_client_cert(
            &pki.leaf_b_der,
            std::slice::from_ref(&pki.intermediate_b_der),
            UnixTime::now(),
        )
        .expect("intermediate B is not revoked, so leaf B still authenticates");
}

#[test]
fn a_chain_no_configured_crl_covers_is_still_accepted() {
    let pki = build_chain_pki();
    // Authoritative for nothing in this PKI: unknown revocation status.
    let crls = crl_list(vec![fresh_crl(
        &pki.unrelated_issuer,
        &[INTERMEDIATE_A_SERIAL, LEAF_A_SERIAL],
    )]);
    let (_dir, verifier) = client_verifier(&pki, &crls);

    verifier
        .verify_client_cert(
            &pki.leaf_a_der,
            std::slice::from_ref(&pki.intermediate_a_der),
            UnixTime::now(),
        )
        .expect("unknown revocation status remains tolerated");
}

#[test]
fn an_empty_crl_list_leaves_revocation_checking_off() {
    let pki = build_chain_pki();
    let (_dir, verifier) = client_verifier(&pki, &[]);

    verifier
        .verify_client_cert(
            &pki.leaf_a_der,
            std::slice::from_ref(&pki.intermediate_a_der),
            UnixTime::now(),
        )
        .expect("with no CRL configured the chain is accepted unchanged");
}

#[test]
fn a_loaded_crl_stops_authorizing_once_its_next_update_passes() {
    let pki = build_chain_pki();
    let now = OffsetDateTime::now_utc();
    let next_update = now + TimeDuration::hours(1);
    let der = signed_crl_der(
        &pki.root_issuer,
        &[UNRELATED_SERIAL],
        now - TimeDuration::hours(1),
        next_update,
    );
    let crls = crl_list(vec![der]);
    let (_dir, verifier) = client_verifier(&pki, &crls);

    // Same verifier object, two instants. No sleeping, no reload.
    verifier
        .verify_client_cert(
            &pki.leaf_a_der,
            std::slice::from_ref(&pki.intermediate_a_der),
            at(unix(now)),
        )
        .expect("inside the CRL's validity window the chain authenticates");

    let error = verifier
        .verify_client_cert(
            &pki.leaf_a_der,
            std::slice::from_ref(&pki.intermediate_a_der),
            at(unix(next_update) + 1),
        )
        .expect_err("past nextUpdate the same verifier must stop authorizing");
    assert!(
        matches!(
            error,
            RustlsError::InvalidCertificate(CertificateError::ExpiredRevocationListContext { .. })
        ),
        "expected an expired-CRL refusal, got {error:?}"
    );
}

#[test]
fn the_backend_server_verifier_enforces_the_same_policy() {
    let pki = build_chain_pki();
    let now = OffsetDateTime::now_utc();

    let revoked = crl_list(vec![fresh_crl(&pki.root_issuer, &[INTERMEDIATE_A_SERIAL])]);
    let error = verify_server(
        &server_verifier(&pki, &revoked),
        &pki.leaf_a_der,
        &pki.intermediate_a_der,
        LEAF_A_DNS,
        UnixTime::now(),
    )
    .expect_err("a backend chain through a revoked intermediate must be refused");
    assert!(
        matches!(
            error,
            RustlsError::InvalidCertificate(CertificateError::Revoked)
        ),
        "expected a revocation refusal, got {error:?}"
    );

    verify_server(
        &server_verifier(&pki, &revoked),
        &pki.leaf_b_der,
        &pki.intermediate_b_der,
        LEAF_B_DNS,
        UnixTime::now(),
    )
    .expect("the sibling backend branch still verifies");

    let next_update = now + TimeDuration::hours(1);
    let expiring = crl_list(vec![signed_crl_der(
        &pki.root_issuer,
        &[UNRELATED_SERIAL],
        now - TimeDuration::hours(1),
        next_update,
    )]);
    let verifier = server_verifier(&pki, &expiring);
    verify_server(
        &verifier,
        &pki.leaf_a_der,
        &pki.intermediate_a_der,
        LEAF_A_DNS,
        at(unix(now)),
    )
    .expect("inside the window the backend chain verifies");
    let error = verify_server(
        &verifier,
        &pki.leaf_a_der,
        &pki.intermediate_a_der,
        LEAF_A_DNS,
        at(unix(next_update) + 1),
    )
    .expect_err("past nextUpdate the backend verifier stops authorizing");
    assert!(
        matches!(
            error,
            RustlsError::InvalidCertificate(CertificateError::ExpiredRevocationListContext { .. })
        ),
        "expected an expired-CRL refusal, got {error:?}"
    );
}

fn probe_verifier(
    pki: &ChainPki,
    crls: &[CertificateRevocationListDer<'static>],
    san_allow_list: Vec<String>,
) -> (TempDir, Arc<dyn ServerCertVerifier>) {
    let dir = TempDir::new().expect("temp dir");
    let ca_path = dir.path().join("root.pem");
    std::fs::write(&ca_path, &pki.root_pem).expect("write root");
    let mut tls = BackendTlsConfig::default_verify();
    tls.server_ca_cert_path = Some(ca_path.to_str().expect("utf-8 path").to_string());
    tls.san_allow_list = san_allow_list;
    let verifier =
        build_probe_server_verifier_for_test(&tls, None, crls).expect("probe server verifier");
    (dir, verifier)
}

fn verify_probe(
    verifier: &dyn ServerCertVerifier,
    leaf: &CertificateDer<'static>,
    intermediate: &CertificateDer<'static>,
    dns: &str,
) -> Result<(), RustlsError> {
    let name = ServerName::try_from(dns).expect("server name");
    verifier
        .verify_server_cert(
            leaf,
            std::slice::from_ref(intermediate),
            &name,
            &[],
            UnixTime::now(),
        )
        .map(|_| ())
}

fn assert_revoked(error: RustlsError, context: &str) {
    assert!(
        matches!(
            error,
            RustlsError::InvalidCertificate(CertificateError::Revoked)
        ),
        "{context}: expected CertificateError::Revoked, got {error:?}"
    );
}

#[test]
fn health_probe_verifier_refuses_a_revoked_intermediate() {
    let pki = build_chain_pki();
    let crls = crl_list(vec![fresh_crl(&pki.root_issuer, &[INTERMEDIATE_A_SERIAL])]);
    let (_dir, verifier) = probe_verifier(&pki, &crls, Vec::new());

    let error = verify_probe(
        verifier.as_ref(),
        &pki.leaf_a_der,
        &pki.intermediate_a_der,
        LEAF_A_DNS,
    )
    .expect_err("a probe chain through a revoked intermediate must be refused");
    assert_revoked(error, "health probe intermediate revocation");

    verify_probe(
        verifier.as_ref(),
        &pki.leaf_b_der,
        &pki.intermediate_b_der,
        LEAF_B_DNS,
    )
    .expect("the sibling probe branch must still verify");
}

#[test]
fn health_probe_verifier_refuses_a_revoked_leaf() {
    let pki = build_chain_pki();
    let crls = crl_list(vec![fresh_crl(
        &pki.intermediate_a_issuer,
        &[LEAF_A_SERIAL],
    )]);
    let (_dir, verifier) = probe_verifier(&pki, &crls, Vec::new());

    let error = verify_probe(
        verifier.as_ref(),
        &pki.leaf_a_der,
        &pki.intermediate_a_der,
        LEAF_A_DNS,
    )
    .expect_err("a revoked probe leaf must be refused");
    assert_revoked(error, "health probe leaf revocation");

    verify_probe(
        verifier.as_ref(),
        &pki.leaf_b_der,
        &pki.intermediate_b_der,
        LEAF_B_DNS,
    )
    .expect("an unrevoked sibling leaf must still verify");
}

#[test]
fn health_probe_verifier_accepts_an_unrevoked_chain_with_an_empty_crl_list() {
    let pki = build_chain_pki();
    let (_dir, verifier) = probe_verifier(&pki, &[], Vec::new());
    verify_probe(
        verifier.as_ref(),
        &pki.leaf_a_der,
        &pki.intermediate_a_der,
        LEAF_A_DNS,
    )
    .expect("with no CRL the probe chain verifies");
}

#[test]
fn health_probe_san_wrap_still_enforces_revocation() {
    let pki = build_chain_pki();
    let crls = crl_list(vec![fresh_crl(&pki.root_issuer, &[INTERMEDIATE_A_SERIAL])]);
    let (_dir, verifier) = probe_verifier(&pki, &crls, vec![LEAF_A_DNS.to_string()]);

    let error = verify_probe(
        verifier.as_ref(),
        &pki.leaf_a_der,
        &pki.intermediate_a_der,
        LEAF_A_DNS,
    )
    .expect_err("SAN wrapping must not bypass CRL enforcement");
    assert_revoked(error, "SAN-wrapped health probe revocation");
}

#[test]
fn the_spiffe_peer_verifier_enforces_the_same_policy() {
    let pki = build_chain_pki();
    let trust_domain = TrustDomain::new(TRUST_DOMAIN).expect("trust domain");
    let bundle = SvidBundle {
        spiffe_id: SpiffeId::from_parts(&trust_domain, "ns/test/sa/gateway").expect("spiffe id"),
        cert_chain_der: vec![pki.root_der.as_ref().to_vec()],
        private_key_pkcs8_der: ecdsa_key().serialize_der().into(),
        trust_bundles: TrustBundleSet::local_only(TrustBundle {
            trust_domain,
            x509_authorities: vec![pki.root_der.as_ref().to_vec()],
            jwt_authorities: vec![],
            refresh_hint_seconds: None,
        }),
    };
    let slot = Arc::new(ArcSwap::new(Arc::new(Some(bundle))));

    let permissive = build_spiffe_client_cert_verifier(slot.clone(), true, Arc::new(Vec::new()));
    permissive
        .verify_client_cert(
            &pki.spiffe_leaf_a_der,
            std::slice::from_ref(&pki.intermediate_a_der),
            UnixTime::now(),
        )
        .expect("with no CRL the mesh peer chain verifies");

    let crls = Arc::new(crl_list(vec![fresh_crl(
        &pki.root_issuer,
        &[INTERMEDIATE_A_SERIAL],
    )]));
    let enforcing = build_spiffe_client_cert_verifier(slot, true, crls);
    let error = enforcing
        .verify_client_cert(
            &pki.spiffe_leaf_a_der,
            std::slice::from_ref(&pki.intermediate_a_der),
            UnixTime::now(),
        )
        .expect_err("a mesh peer chained through a revoked intermediate must be refused")
        .to_string();
    // The SPIFFE verifier flattens rustls errors into `Error::General`, so match
    // on the rendered cause rather than the variant. Asserting it names the
    // revocation keeps the test from passing on an unrelated CRL-attributable
    // failure (a rejected CRL signature, a non-cRLSign issuer) that would leave
    // issue #4298 unproven on this surface.
    assert!(
        error.contains("Revoked"),
        "expected a revocation refusal, got {error}"
    );
}

#[test]
fn applying_the_policy_to_an_empty_crl_list_is_a_no_op() {
    let pki = build_chain_pki();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(pki.root_der.clone()).expect("add root");
    let builder = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(rustls::crypto::ring::default_provider()),
    );

    apply_client_crl_policy(builder, &[])
        .build()
        .expect("an untouched builder still builds");
}

// ── 4. Static inventory: no surface may drift off the shared policy ──────

/// rustls's leaf-only revocation depth. Naming it here — and nowhere under
/// `src/` — is what makes the pin below unambiguous.
const LEAF_ONLY_REVOCATION_OPTION: &str = "only_check_end_entity_revocation";

const SHARED_POLICY_MODULE: &str = "src/tls/crl_policy.rs";

/// Every module that builds or consumes a CRL-enabled verifier. Each must reach
/// the shared policy, either directly or through `build_server_verifier_with_crls`.
const CRL_VERIFIER_SURFACES: &[&str] = &[
    "src/tls/mod.rs",
    "src/tls/spiffe.rs",
    "src/tls/backend.rs",
    "src/dtls/mod.rs",
    "src/health_check.rs",
    "src/modes/mesh/config_consumer/native_tls.rs",
    "src/notifications/channels/email.rs",
    "src/plugins/ldap_auth.rs",
    "src/plugins/tcp_logging.rs",
    "src/plugins/udp_logging.rs",
    "src/plugins/ws_logging.rs",
];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn walk_rust_sources(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

fn relative(path: &Path) -> String {
    path.strip_prefix(repo_root())
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn read_source(relative_path: &str) -> String {
    let path = repo_root().join(relative_path);
    std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {relative_path}: {error}"))
}

#[test]
fn no_production_verifier_reintroduces_the_leaf_only_revocation_option() {
    let offenders: Vec<String> = walk_rust_sources(&repo_root().join("src"))
        .into_iter()
        .filter(|path| {
            std::fs::read_to_string(path)
                .map(|text| text.contains(LEAF_ONLY_REVOCATION_OPTION))
                .unwrap_or(false)
        })
        .map(|path| relative(&path))
        .collect();

    assert!(
        offenders.is_empty(),
        "issue #4298: leaf-only CRL checking lets a revoked intermediate keep \
         issuing accepted certificates. Reintroduced in: {offenders:?}"
    );
}

#[test]
fn every_crl_enabled_verifier_is_built_through_the_shared_policy() {
    let mut offenders: Vec<String> = Vec::new();
    for path in walk_rust_sources(&repo_root().join("src")) {
        let relative_path = relative(&path);
        if relative_path == SHARED_POLICY_MODULE {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        // `build_server_verifier_with_crls` is the shared helper's own name and
        // ends in the same characters; strip it before looking for the builder
        // method itself.
        let text = text.replace("build_server_verifier_with_crls", "");
        if text.contains("with_crls(") {
            offenders.push(relative_path);
        }
    }

    assert!(
        offenders.is_empty(),
        "a CRL list may only be attached to a verifier inside {SHARED_POLICY_MODULE}, \
         so one policy decision covers every surface. Bypassed in: {offenders:?}"
    );
}

#[test]
fn the_shared_policy_pairs_every_crl_list_with_the_full_policy() {
    let text = read_source(SHARED_POLICY_MODULE);
    let method_call_count = |method: &str| {
        text.lines()
            .filter(|line| line.trim_start().starts_with(method))
            .count()
    };
    let attachments = method_call_count(".with_crls(");
    assert_eq!(
        attachments, 2,
        "expected exactly the client and server verifier policies"
    );
    assert_eq!(
        method_call_count(".allow_unknown_revocation_status()"),
        attachments,
        "the deliberate unknown-status tolerance must stay on every policy"
    );
    assert_eq!(
        method_call_count(".enforce_revocation_expiration()"),
        attachments,
        "issue #4297: every CRL-enabled verifier must enforce the CRL's own \
         validity window"
    );
    assert!(
        !text.contains(LEAF_ONLY_REVOCATION_OPTION),
        "issue #4298: the shared policy must keep rustls's full-chain default"
    );
}

#[test]
fn every_verifier_builder_site_is_inside_a_known_crl_surface() {
    let mut builder_sites: BTreeSet<String> = BTreeSet::new();
    for path in walk_rust_sources(&repo_root().join("src")) {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        if text.contains("WebPkiClientVerifier::builder")
            || text.contains("WebPkiServerVerifier::builder")
        {
            builder_sites.insert(relative(&path));
        }
    }

    let expected: BTreeSet<String> = ["src/tls/mod.rs", "src/tls/spiffe.rs", "src/dtls/mod.rs"]
        .into_iter()
        .map(str::to_string)
        .collect();
    assert_eq!(
        builder_sites, expected,
        "a new webpki verifier builder appeared outside the reviewed set; route \
         it through tls::crl_policy and add it here"
    );
    for site in &builder_sites {
        let text = read_source(site);
        assert!(
            text.contains("crl_policy::apply_"),
            "{site} builds a webpki verifier without applying the shared CRL policy"
        );
    }
}

#[test]
fn every_crl_consuming_surface_reaches_the_shared_policy() {
    for surface in CRL_VERIFIER_SURFACES {
        let text = read_source(surface);
        assert!(
            text.contains("crl_policy::apply_") || text.contains("build_server_verifier_with_crls"),
            "{surface} consumes CRLs without reaching tls::crl_policy"
        );
    }
}

#[test]
fn health_probes_pass_the_admitted_crl_snapshot_not_an_empty_literal() {
    let text = read_source("src/health_check.rs");
    let probe_builder = text
        .split("fn build_probe_server_verifier(")
        .nth(1)
        .expect("build_probe_server_verifier must exist");
    let probe_builder = probe_builder.split("\nfn ").next().expect("function body");
    assert!(
        probe_builder.contains("build_server_verifier_with_crls"),
        "probe verifiers must reach the shared helper"
    );
    assert!(
        probe_builder.contains("crls"),
        "probe verifiers must pass the admitted CRL snapshot, not a hardcoded list"
    );
    assert!(
        !probe_builder.contains("&[]"),
        "issue #4298: an empty CRL literal would let a revoked backend probe healthy"
    );
    let production = read_source("src/proxy/mod.rs");
    assert!(
        production.contains("with_pool_config_and_shared_crls"),
        "production HealthChecker construction must receive the shared CRL list"
    );
}

#[test]
fn config_and_admin_crl_admission_share_one_validator() {
    for admission in ["src/tls/mod.rs", "src/admin/tls_management.rs"] {
        let text = read_source(admission);
        assert!(
            text.contains("crl_policy::validate_crl_windows("),
            "{admission} admits CRLs without the shared temporal validator, so an \
             expired or endless CRL could be published on that path (issue #4297)"
        );
    }
}

#[test]
fn the_shared_validator_is_reachable_as_a_public_seam() {
    // Guards against the validator being narrowed to a private helper, which
    // would let a future admission path quietly grow its own copy.
    let pki = build_chain_pki();
    let crls = crl_list(vec![fresh_crl(&pki.root_issuer, &[UNRELATED_SERIAL])]);
    crl_policy::validate_crl_windows(&crls, "public-seam").expect("fresh CRL admitted");
}
