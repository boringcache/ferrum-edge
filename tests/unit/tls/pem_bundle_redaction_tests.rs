//! PEM bundle parse and trust-root admission diagnostics must not echo malformed
//! PEM lines, DER bytes, or rustls library error text.

use ferrum_edge::tls::{build_client_cert_verifier, check_cert_expiry};
use rcgen::{CertificateParams, Issuer, KeyPair, KeyUsagePurpose};
use std::sync::Once;
use tempfile::TempDir;

static INIT_CRYPTO: Once = Once::new();

fn ensure_crypto_provider() {
    INIT_CRYPTO.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

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

fn generate_ca() -> (Issuer<'static, KeyPair>, String) {
    use rcgen::{BasicConstraints, DnType, IsCa};
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(DnType::CommonName, "Test CA");
    params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    params.key_usages.push(KeyUsagePurpose::CrlSign);
    let cert = params.self_signed(&key_pair).unwrap();
    let cert_pem = cert.pem();
    (Issuer::new(params, key_pair), cert_pem)
}

fn generate_signed_leaf(ca_issuer: &Issuer<'static, KeyPair>, sans: &[&str]) -> String {
    use rcgen::DnType;
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let san_strings: Vec<String> = sans.iter().map(|s| s.to_string()).collect();
    let mut params = CertificateParams::new(san_strings).unwrap();
    params
        .distinguished_name
        .push(DnType::CommonName, "Test Leaf");
    let cert = params.signed_by(&key_pair, ca_issuer).unwrap();
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
        error.contains("invalid PEM base64 encoding"),
        "got: {error}"
    );
}

#[test]
fn malformed_pem_section_start_error_withholds_marker_bearing_line() {
    let dir = TempDir::new().unwrap();
    let valid_pem = generate_self_signed_cert(&["localhost"]);
    let bundle = format!("{valid_pem}{PEM_MARKER}\n");
    let path = write_pem(&dir, "illegal-section.pem", &bundle);

    let error = check_cert_expiry(&path, "expiry bundle", 30)
        .expect_err("illegal section start must reject the bundle")
        .to_string();

    assert!(
        !error.contains(PEM_MARKER),
        "malformed PEM line must not echo in diagnostics: {error}"
    );
    assert!(error.contains("record #2"), "got: {error}");
    assert!(
        error.contains("illegal PEM section start"),
        "got: {error}"
    );
}

#[test]
fn unusable_trust_root_error_withholds_rejected_certificate_material() {
    ensure_crypto_provider();

    let dir = TempDir::new().unwrap();
    let (ca_issuer, _ca_pem) = generate_ca();
    let leaf_pem = generate_signed_leaf(&ca_issuer, &["client.example"]);
    // Leaf certificates are valid PEM but cannot be admitted as trust roots.
    let path = write_pem(&dir, "leaf-only-ca.pem", &leaf_pem);

    let error = build_client_cert_verifier(&path, &[])
        .expect_err("leaf certificate must not be admitted as a trust root")
        .to_string();

    let leaf_der_marker = leaf_pem
        .lines()
        .find(|line| !line.starts_with("-----"))
        .expect("leaf PEM must contain base64 body");
    assert!(
        !error.contains(leaf_der_marker),
        "rejected certificate material must not echo in diagnostics: {error}"
    );
    assert!(
        !error.contains("BasicConstraints"),
        "rustls admission diagnostics must not echo: {error}"
    );
    assert!(error.contains("client CA bundle"), "got: {error}");
    assert!(error.contains("record #1"), "got: {error}");
    assert!(error.contains("leaf-only-ca.pem"), "got: {error}");
    assert!(
        error.contains("certificate failed trust-anchor admission"),
        "got: {error}"
    );
}
