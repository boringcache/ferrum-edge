//! PEM bundle parse and trust-root admission diagnostics must not echo malformed
//! PEM lines, DER bytes, or rustls library error text.

use ferrum_edge::tls::{build_client_cert_verifier, check_cert_expiry};
use rcgen::{CertificateParams, KeyPair};
use tempfile::TempDir;

const PEM_MARKER: &str = "SECRET_MARKER_DO_NOT_LEAK_12345";

fn write_pem(dir: &TempDir, name: &str, data: &str) -> String {
    let path = dir.path().join(name);
    std::fs::write(&path, data).unwrap();
    path.to_str().unwrap().to_string()
}

fn generate_self_signed_cert(sans: &[&str]) -> String {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let san_strings: Vec<String> = sans.iter().map(|s| s.to_string()).collect();
    let params = CertificateParams::new(san_strings).unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    cert.pem()
}

#[test]
fn malformed_pem_record_error_withholds_marker_bearing_input() {
    let dir = TempDir::new().unwrap();
    let valid_pem = generate_self_signed_cert(&["localhost"]);
    let bundle = format!(
        "{valid_pem}-----BEGIN CERTIFICATE-----\n{PEM_MARKER}\n-----END CERTIFICATE-----\n"
    );
    let path = write_pem(&dir, "malformed-later.pem", &bundle);

    let error = check_cert_expiry(&path, "expiry bundle", 30)
        .expect_err("malformed later record must reject the bundle")
        .to_string();

    assert!(
        !error.contains(PEM_MARKER),
        "malformed PEM input must not echo in diagnostics: {error}"
    );
    assert!(error.contains("expiry bundle"), "got: {error}");
    assert!(error.contains("record #2"), "got: {error}");
    assert!(error.contains("malformed-later.pem"), "got: {error}");
    assert!(
        error.contains("malformed PEM certificate record"),
        "got: {error}"
    );
}

#[test]
fn malformed_pem_section_start_error_withholds_marker_bearing_line() {
    let dir = TempDir::new().unwrap();
    let valid_pem = generate_self_signed_cert(&["localhost"]);
    let bundle = format!("{valid_pem}-----BEGIN {PEM_MARKER}-----\n");
    let path = write_pem(&dir, "illegal-section.pem", &bundle);

    let error = check_cert_expiry(&path, "expiry bundle", 30)
        .expect_err("illegal section start must reject the bundle")
        .to_string();

    assert!(
        !error.contains(PEM_MARKER),
        "malformed PEM line must not echo in diagnostics: {error}"
    );
    assert!(error.contains("expiry bundle"), "got: {error}");
    assert!(error.contains("record #2"), "got: {error}");
    assert!(error.contains("illegal-section.pem"), "got: {error}");
    assert!(
        error.contains("malformed PEM certificate record"),
        "got: {error}"
    );
}

#[test]
fn unusable_trust_root_error_withholds_rejected_certificate_material() {
    const UNUSABLE_CERT_BASE64: &str = "AQIDBA==";

    let dir = TempDir::new().unwrap();
    let bundle =
        format!("-----BEGIN CERTIFICATE-----\n{UNUSABLE_CERT_BASE64}\n-----END CERTIFICATE-----\n");
    let path = write_pem(&dir, "unusable-root.pem", &bundle);

    let error = build_client_cert_verifier(&path, &[])
        .expect_err("unusable PEM certificate must not be admitted as a trust root")
        .to_string();

    assert!(
        !error.contains(UNUSABLE_CERT_BASE64),
        "rejected certificate material must not echo in diagnostics: {error}"
    );
    assert!(error.contains("client CA bundle"), "got: {error}");
    assert!(error.contains("record #1"), "got: {error}");
    assert!(error.contains("unusable-root.pem"), "got: {error}");
    assert!(
        error.contains("certificate failed trust-anchor admission"),
        "got: {error}"
    );
}
