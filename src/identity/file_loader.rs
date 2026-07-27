//! File-based X.509-SVID loading for gateway identities.
//!
//! Mesh mode can obtain SVIDs from the Workload API / rotation machinery. Edge
//! gateway deployments often receive their SVID material as mounted files, so
//! this loader turns a leaf-first PEM chain, a PKCS#8 private key, and a PEM
//! trust bundle into the same [`SvidBundle`] shape used by SPIFFE TLS.

use std::path::Path;

use rcgen::PublicKeyData;
use x509_parser::prelude::*;

use crate::identity::spiffe::{SpiffeId, UriSanError, extract_spiffe_id_from_cert};
use crate::identity::{SvidBundle, TrustBundle, TrustBundleSet};
use crate::tls::source::{CertSource, MaterialKind, load_material_blocking};
use crate::tls::spiffe::SpiffeTlsError;

pub fn load_svid_bundle_from_files(
    cert_path: &Path,
    key_path: &Path,
    trust_bundle_path: &Path,
    explicit_spiffe_id: Option<&str>,
) -> Result<SvidBundle, SpiffeTlsError> {
    let cert_source = cert_path.to_string_lossy();
    let key_source = key_path.to_string_lossy();
    let trust_bundle_source = trust_bundle_path.to_string_lossy();
    load_svid_bundle_from_sources(
        cert_source.as_ref(),
        key_source.as_ref(),
        trust_bundle_source.as_ref(),
        explicit_spiffe_id,
    )
}

pub fn load_svid_bundle_from_sources(
    cert_source: &str,
    key_source: &str,
    trust_bundle_source: &str,
    explicit_spiffe_id: Option<&str>,
) -> Result<SvidBundle, SpiffeTlsError> {
    let cert_chain_der = read_cert_chain_source(
        cert_source,
        MaterialKind::Cert,
        "gateway SVID certificate chain",
    )?;
    let private_key_pkcs8_der = read_pkcs8_key_source(key_source)?;
    let x509_authorities = read_cert_chain_source(
        trust_bundle_source,
        MaterialKind::CaBundle,
        "gateway SVID trust bundle",
    )?;

    let leaf = cert_chain_der
        .first()
        .ok_or(SpiffeTlsError::NoLeafCert)?
        .as_slice();
    validate_cert_is_current(leaf, "gateway SVID leaf certificate")?;
    validate_leaf_is_not_ca(leaf)?;
    for (idx, intermediate) in cert_chain_der.iter().enumerate().skip(1) {
        validate_cert_is_current(
            intermediate,
            &format!("gateway SVID intermediate certificate #{idx}"),
        )?;
    }
    validate_certificate_chain_order(&cert_chain_der, "gateway SVID certificate chain")?;
    for (idx, ca) in x509_authorities.iter().enumerate() {
        validate_cert_is_current(ca, &format!("gateway SVID trust bundle cert #{}", idx + 1))?;
    }

    let spiffe_id = match extract_spiffe_id_from_cert(leaf) {
        Ok(id) => id,
        Err(UriSanError::NoSanExtension | UriSanError::NoSpiffeUri) => {
            let Some(explicit) = explicit_spiffe_id else {
                return Err(SpiffeTlsError::BadKeyMaterial(
                    "gateway SVID leaf certificate does not contain a SPIFFE URI SAN and FERRUM_GATEWAY_SPIFFE_ID is unset"
                        .to_string(),
                ));
            };
            SpiffeId::new(explicit.to_string()).map_err(|e| {
                SpiffeTlsError::BadKeyMaterial(format!(
                    "FERRUM_GATEWAY_SPIFFE_ID '{explicit}' is invalid: {e}"
                ))
            })?
        }
        Err(err) => {
            return Err(SpiffeTlsError::BadKeyMaterial(format!(
                "gateway SVID leaf certificate SPIFFE URI SAN is invalid: {err}"
            )));
        }
    };

    verify_leaf_key_match(leaf, &private_key_pkcs8_der)?;

    Ok(SvidBundle {
        trust_bundles: TrustBundleSet::local_only(TrustBundle {
            trust_domain: spiffe_id.trust_domain().clone(),
            x509_authorities,
            jwt_authorities: Vec::new(),
            refresh_hint_seconds: None,
        }),
        spiffe_id,
        cert_chain_der,
        private_key_pkcs8_der: private_key_pkcs8_der.into(),
    })
}

fn read_cert_chain_source(
    source_value: &str,
    kind: MaterialKind,
    label: &str,
) -> Result<Vec<Vec<u8>>, SpiffeTlsError> {
    let source = CertSource::parse(source_value, kind);
    let material = load_material_blocking(&source, kind)
        .map_err(|e| SpiffeTlsError::BadKeyMaterial(format!("{label}: {e}")))?;
    let source_id = material.display_source_id.clone();
    let certificates = crate::tls::parse_pem_certificate_bundle(
        material.bytes.expose_secret(),
        label,
        &source_id,
    )
    .map_err(|error| SpiffeTlsError::BadKeyMaterial(error.to_string()))?;
    if kind == MaterialKind::CaBundle {
        crate::tls::root_cert_store_from_certificates(
            certificates.iter().cloned(),
            label,
            &source_id,
        )
        .map_err(|error| SpiffeTlsError::BadKeyMaterial(error.to_string()))?;
    }
    Ok(certificates
        .into_iter()
        .map(|certificate| certificate.as_ref().to_vec())
        .collect())
}

fn read_pkcs8_key_source(source_value: &str) -> Result<Vec<u8>, SpiffeTlsError> {
    let source = CertSource::parse(source_value, MaterialKind::Key);
    let material = load_material_blocking(&source, MaterialKind::Key)
        .map_err(|e| SpiffeTlsError::BadKeyMaterial(format!("gateway SVID key: {e}")))?;
    let source_id = material.display_source_id.clone();
    let key = crate::tls::parse_pem_private_key(
        material.bytes.expose_secret(),
        "gateway SVID key",
        &source_id,
    )
    .map_err(|error| SpiffeTlsError::BadKeyMaterial(error.to_string()))?;
    match key {
        rustls::pki_types::PrivateKeyDer::Pkcs8(key) => Ok(key.secret_pkcs8_der().to_vec()),
        _ => Err(SpiffeTlsError::BadKeyMaterial(format!(
            "gateway SVID key: '{}' must contain a PKCS#8 private key",
            source_id
        ))),
    }
}

pub(crate) fn validate_cert_is_current(cert_der: &[u8], label: &str) -> Result<(), SpiffeTlsError> {
    let (_, cert) = X509Certificate::from_der(cert_der).map_err(|_error| {
        SpiffeTlsError::BadKeyMaterial(format!("{label}: certificate failed X.509 validation"))
    })?;
    let validity = cert.validity();
    if validity.is_valid() {
        return Ok(());
    }

    let now_ts = x509_parser::time::ASN1Time::now().timestamp();
    if now_ts < validity.not_before.timestamp() {
        Err(SpiffeTlsError::BadKeyMaterial(format!(
            "{label}: certificate is not yet valid"
        )))
    } else {
        Err(SpiffeTlsError::BadKeyMaterial(format!(
            "{label}: certificate has expired"
        )))
    }
}

pub(crate) fn validate_leaf_is_not_ca(leaf_der: &[u8]) -> Result<(), SpiffeTlsError> {
    let (_, leaf) = X509Certificate::from_der(leaf_der).map_err(|_error| {
        SpiffeTlsError::BadKeyMaterial(
            "gateway SVID leaf certificate failed X.509 validation".to_string(),
        )
    })?;
    let basic_constraints = leaf.basic_constraints().map_err(|_error| {
        SpiffeTlsError::BadKeyMaterial(
            "gateway SVID leaf certificate basic constraints are invalid".to_string(),
        )
    })?;

    if basic_constraints.is_some_and(|ext| ext.value.ca) {
        return Err(SpiffeTlsError::BadKeyMaterial(
            "gateway SVID leaf certificate must not be a CA certificate".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn verify_leaf_key_match(leaf_der: &[u8], key_der: &[u8]) -> Result<(), SpiffeTlsError> {
    let (_, leaf) = X509Certificate::from_der(leaf_der).map_err(|_error| {
        SpiffeTlsError::BadKeyMaterial(
            "gateway SVID leaf certificate failed X.509 validation".to_string(),
        )
    })?;
    let key_pair = rcgen::KeyPair::try_from(key_der).map_err(|_error| {
        SpiffeTlsError::BadKeyMaterial("gateway SVID private key is invalid".to_string())
    })?;
    // Compare canonical DER SubjectPublicKeyInfo bytes. x509-parser preserves
    // the certificate SPKI DER and rcgen emits canonical SPKI DER for the key.
    let cert_spki = leaf.tbs_certificate.subject_pki.raw;
    let key_spki = key_pair.subject_public_key_info();
    if cert_spki != key_spki.as_slice() {
        return Err(SpiffeTlsError::BadKeyMaterial(
            "gateway SVID certificate public key does not match the supplied private key"
                .to_string(),
        ));
    }
    Ok(())
}

/// Require every certificate after the leaf to be its immediate issuer.
///
/// The final root may be omitted, as is conventional for TLS presentation
/// chains. Issuer/subject equality plus signature verification prevents an
/// otherwise parseable but reordered or unrelated chain from being published.
pub(crate) fn validate_certificate_chain_order(
    chain_der: &[Vec<u8>],
    label: &str,
) -> Result<(), SpiffeTlsError> {
    for (index, pair) in chain_der.windows(2).enumerate() {
        let (_, child) = X509Certificate::from_der(&pair[0]).map_err(|_error| {
            SpiffeTlsError::BadKeyMaterial(format!(
                "{label}: certificate record #{} failed X.509 validation",
                index + 1
            ))
        })?;
        let (_, issuer) = X509Certificate::from_der(&pair[1]).map_err(|_error| {
            SpiffeTlsError::BadKeyMaterial(format!(
                "{label}: certificate record #{} failed X.509 validation",
                index + 2
            ))
        })?;
        if child.issuer() != issuer.subject()
            || child.verify_signature(Some(issuer.public_key())).is_err()
        {
            return Err(SpiffeTlsError::BadKeyMaterial(format!(
                "{label}: certificate record #{} is not issued by record #{}",
                index + 1,
                index + 2
            )));
        }
    }
    Ok(())
}
