//! Focused unit coverage for the PKCS#11 public-key reconstruction helpers.
//!
//! These are the parsing/encoding paths behind the token-key ↔ leaf-certificate
//! proof added for issue #2406. They need no token, so they run wherever the
//! `pkcs11` feature is built.

use ferrum_edge::tls::pkcs11::{leaf_rsa_public_key_der, rsa_public_key_der, rsa_spki_der};
use rustls::pki_types::{CertificateDer, pem::PemObject};

/// 1.2.840.113549.1.1.1 (rsaEncryption) with NULL parameters, as it appears
/// inside a SubjectPublicKeyInfo AlgorithmIdentifier.
const RSA_ENCRYPTION_ALG_ID: &[u8] = &[
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
];

#[test]
fn encodes_short_modulus_and_exponent_as_a_der_sequence() {
    let encoded = rsa_public_key_der(&[0x01, 0x02], &[0x01, 0x00, 0x01]).expect("encodes");
    assert_eq!(
        encoded,
        vec![
            0x30, 0x0a, // SEQUENCE, 10 bytes
            0x02, 0x02, 0x01, 0x02, // INTEGER 0x0102
            0x02, 0x04, 0x00, 0x01, 0x00, 0x01, // INTEGER 0x010001
        ]
    );
}

#[test]
fn pads_a_high_bit_modulus_so_the_integer_stays_positive() {
    let encoded = rsa_public_key_der(&[0xff, 0x01], &[0x03]).expect("encodes");
    // 0x02 0x03 0x00 0xff 0x01 -> the leading zero keeps the INTEGER unsigned.
    assert_eq!(&encoded[2..7], &[0x02, 0x03, 0x00, 0xff, 0x01]);
}

#[test]
fn strips_leading_zero_padding_returned_by_a_token() {
    let padded = rsa_public_key_der(&[0x00, 0x00, 0x7f, 0x01], &[0x00, 0x03]).expect("encodes");
    let compact = rsa_public_key_der(&[0x7f, 0x01], &[0x03]).expect("encodes");
    assert_eq!(padded, compact);
}

#[test]
fn uses_der_long_form_lengths_for_a_realistic_modulus() {
    let modulus = vec![0xc4; 256];
    let encoded = rsa_public_key_der(&modulus, &[0x01, 0x00, 0x01]).expect("encodes");
    // SEQUENCE holding a 257-byte padded INTEGER (4 header bytes) plus a
    // 5-byte exponent INTEGER = 266 content bytes, so a two-byte long form.
    assert_eq!(&encoded[..4], &[0x30, 0x82, 0x01, 0x0a]);
    // INTEGER, two-byte long-form length, one pad byte, then the modulus.
    assert_eq!(&encoded[4..8], &[0x02, 0x82, 0x01, 0x01]);
    assert_eq!(encoded[8], 0x00);
    assert_eq!(&encoded[9..9 + 256], modulus.as_slice());
    assert_eq!(encoded.len(), 4 + 266);
}

#[test]
fn rejects_an_empty_or_zero_modulus() {
    let error = rsa_public_key_der(&[], &[0x01, 0x00, 0x01]).expect_err("empty modulus");
    assert!(error.to_string().contains("RSA modulus"));

    let error = rsa_public_key_der(&[0x00, 0x00], &[0x01, 0x00, 0x01]).expect_err("zero modulus");
    assert!(error.to_string().contains("RSA modulus"));
}

#[test]
fn rejects_an_empty_or_zero_public_exponent() {
    let error = rsa_public_key_der(&[0x01, 0x02], &[]).expect_err("empty exponent");
    assert!(error.to_string().contains("RSA public exponent"));

    let error = rsa_public_key_der(&[0x01, 0x02], &[0x00]).expect_err("zero exponent");
    assert!(error.to_string().contains("RSA public exponent"));
}

#[test]
fn rejects_an_implausibly_large_modulus() {
    let modulus = vec![0x01; 1025];
    let error = rsa_public_key_der(&modulus, &[0x01, 0x00, 0x01]).expect_err("oversized modulus");
    assert!(error.to_string().contains("RSA modulus is larger"));
}

#[test]
fn rejects_an_implausibly_large_public_exponent() {
    let exponent = vec![0x01; 17];
    let error = rsa_public_key_der(&[0x01, 0x02], &exponent).expect_err("oversized exponent");
    assert!(error.to_string().contains("RSA public exponent is larger"));
}

#[test]
fn wraps_the_public_key_in_an_rsa_encryption_spki() {
    let spki = rsa_spki_der(&[0x7f, 0x01], &[0x01, 0x00, 0x01]).expect("encodes");
    let public_key = rsa_public_key_der(&[0x7f, 0x01], &[0x01, 0x00, 0x01]).expect("encodes");

    assert_eq!(spki[0], 0x30);
    assert!(
        spki.windows(RSA_ENCRYPTION_ALG_ID.len())
            .any(|window| window == RSA_ENCRYPTION_ALG_ID),
        "SPKI must carry the rsaEncryption algorithm identifier"
    );
    // BIT STRING with zero unused bits, wrapping the RSAPublicKey verbatim.
    let bit_string_start = spki.len() - public_key.len() - 1;
    assert_eq!(spki[bit_string_start], 0x00);
    assert_eq!(&spki[bit_string_start + 1..], public_key.as_slice());
}

#[test]
fn spki_round_trips_against_a_real_rsa_certificate() {
    let certificate = rsa_test_certificate();
    let leaf_public_key = leaf_rsa_public_key_der(&certificate).expect("RSA leaf public key");

    // Re-encoding the certificate's own modulus/exponent must reproduce the
    // certificate's SubjectPublicKeyInfo byte for byte — that equality is what
    // `CertifiedKey::keys_match` compares a token key against.
    let (_, parsed) =
        x509_parser::parse_x509_certificate(certificate.as_ref()).expect("parse certificate");
    let spki_bytes = parsed.public_key().raw.to_vec();
    let rsa = match parsed.public_key().parsed().expect("parsed public key") {
        x509_parser::public_key::PublicKey::RSA(rsa) => rsa,
        _ => panic!("the checked-in test certificate must carry an RSA public key"),
    };

    assert_eq!(
        rsa_spki_der(rsa.modulus, rsa.exponent).expect("rebuild SPKI"),
        spki_bytes
    );
    assert_eq!(
        rsa_public_key_der(rsa.modulus, rsa.exponent).expect("rebuild key"),
        leaf_public_key
    );
}

#[test]
fn rejects_a_non_rsa_leaf_certificate() {
    let certificate = ecdsa_test_certificate();
    let error = leaf_rsa_public_key_der(&certificate).expect_err("EC leaf is not RSA");
    assert!(
        error
            .to_string()
            .contains("does not carry an RSA public key")
    );
}

#[test]
fn rejects_an_unparseable_leaf_certificate() {
    let certificate = CertificateDer::from(vec![0x30, 0x03, 0x02, 0x01, 0x01]);
    let error = leaf_rsa_public_key_der(&certificate).expect_err("garbage DER");
    assert!(error.to_string().contains("not parseable X.509 DER"));
}

/// The checked-in `tests/certs/server.crt` fixture is RSA, so it exercises the
/// real encoding path without needing an RSA generator in the test build.
fn rsa_test_certificate() -> CertificateDer<'static> {
    let pem = include_bytes!("../../certs/server.crt");
    CertificateDer::from_pem_slice(pem)
        .expect("RSA test certificate PEM")
        .into_owned()
}

fn ecdsa_test_certificate() -> CertificateDer<'static> {
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .expect("generate ECDSA key pair");
    let mut params =
        rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("certificate params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "ferrum-pkcs11-test");
    let certificate = params
        .self_signed(&key_pair)
        .expect("self-signed certificate");
    CertificateDer::from_pem_slice(certificate.pem().as_bytes())
        .expect("certificate PEM")
        .into_owned()
}
