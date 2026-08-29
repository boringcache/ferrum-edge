//! Certificate-bound OCSP staple validation (issue #4300).
//!
//! Ferrum used to accept any non-empty byte string as a stapled OCSP response.
//! These tests pin the replacement contract on real, deterministically
//! constructed fixtures: every positive case is a genuine `BasicOCSPResponse`
//! signed with a real ECDSA P-256 key over the exact `tbsResponseData` bytes
//! the validator hashes, and every negative case differs from that fixture in
//! exactly one respect.
//!
//! The builder below is a plain DER encoder rather than an OCSP responder
//! library on purpose: the point of a negative case is to emit the *malformed*
//! or *mis-bound* encoding a responder would never produce, which a responder
//! library will not let a test express.

use std::sync::{Arc, OnceLock};

use ferrum_edge::config::EnvConfig;
use ferrum_edge::tls::TlsPolicy;
use ferrum_edge::tls::multi_cert::{GatewayCertificateInput, load_gateway_multi_cert_tls_config};
use ferrum_edge::tls::ocsp::{
    MAX_OCSP_RESPONSE_BYTES, OCSP_CLOCK_SKEW_SECONDS, validate_stapled_response_at,
    validate_structure,
};
use ferrum_edge::tls::{frontend_tls_slot_with, load_frontend_tls_candidate_from_paths};
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair as _};
use rustls::pki_types::CertificateDer;
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;

// ── DER encoding helpers ───────────────────────────────────────────────────

/// Encode one DER TLV. Lengths above 127 use the long form, which every
/// fixture here stays well inside for the header but not for the content.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let first = bytes
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(bytes.len() - 1);
        let significant = &bytes[first..];
        out.push(0x80 | significant.len() as u8);
        out.extend_from_slice(significant);
    }
    out.extend_from_slice(content);
    out
}

fn sequence(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

fn explicit(number: u8, content: &[u8]) -> Vec<u8> {
    tlv(0xa0 | number, content)
}

fn octet_string(content: &[u8]) -> Vec<u8> {
    tlv(0x04, content)
}

fn oid(content: &[u8]) -> Vec<u8> {
    tlv(0x06, content)
}

fn enumerated(value: u8) -> Vec<u8> {
    tlv(0x0a, &[value])
}

fn der_null() -> Vec<u8> {
    tlv(0x05, &[])
}

fn bit_string(content: &[u8]) -> Vec<u8> {
    bit_string_with_unused(0, content)
}

fn bit_string_with_unused(unused_bits: u8, content: &[u8]) -> Vec<u8> {
    let mut body = vec![unused_bits];
    body.extend_from_slice(content);
    tlv(0x03, &body)
}

fn generalized_time(unix: i64) -> Vec<u8> {
    let datetime =
        time::OffsetDateTime::from_unix_timestamp(unix).expect("representable GeneralizedTime");
    let rendered = format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}Z",
        datetime.year(),
        u8::from(datetime.month()),
        datetime.day(),
        datetime.hour(),
        datetime.minute(),
        datetime.second()
    );
    tlv(0x18, rendered.as_bytes())
}

const OID_SHA1: &[u8] = &[0x2b, 0x0e, 0x03, 0x02, 0x1a];
const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
const OID_ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const OID_OCSP_BASIC: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];
/// `id-pkix-ocsp-nonce` (1.3.6.1.5.5.7.48.1.2): a real OCSP extension Ferrum
/// does not implement, used here as the stand-in unknown extension.
const OID_OCSP_NONCE: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02];

/// One `Extension`. DER omits `critical` when it is FALSE.
fn extension(oid_bytes: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
    let mut parts = vec![oid(oid_bytes)];
    if critical {
        parts.push(tlv(0x01, &[0xff]));
    }
    parts.push(octet_string(value));
    sequence(&parts)
}

/// `[n] EXPLICIT Extensions`, the shape both `responseExtensions` and
/// `singleExtensions` use.
fn extensions_field(number: u8, entries: &[Vec<u8>]) -> Vec<u8> {
    explicit(number, &sequence(entries))
}

/// A `responseExtensions` / `singleExtensions` field holding one unimplemented
/// extension, critical or not.
fn one_extension_field(number: u8, critical: bool) -> Vec<u8> {
    extensions_field(number, &[extension(OID_OCSP_NONCE, critical, b"nonce")])
}

/// Minimal positive-INTEGER content bytes for a serial number.
fn serial_bytes(serial: u64) -> Vec<u8> {
    let mut bytes = serial.to_be_bytes().to_vec();
    while bytes.len() > 1 && bytes[0] == 0 {
        bytes.remove(0);
    }
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0);
    }
    bytes
}

fn parse_certificate(der: &[u8]) -> X509Certificate<'_> {
    let (_, parsed) = X509Certificate::from_der(der).expect("parseable certificate");
    parsed
}

fn algorithm_identifier(oid_bytes: &[u8]) -> Vec<u8> {
    algorithm_identifier_with_params(oid_bytes, None)
}

fn algorithm_identifier_with_params(oid_bytes: &[u8], params: Option<&[u8]>) -> Vec<u8> {
    match params {
        Some(params) => sequence(&[oid(oid_bytes), params.to_vec()]),
        None => sequence(&[oid(oid_bytes)]),
    }
}

fn sha1(data: &[u8]) -> Vec<u8> {
    let algorithm = &ring::digest::SHA1_FOR_LEGACY_USE_ONLY;
    ring::digest::digest(algorithm, data).as_ref().to_vec()
}

fn sha256(data: &[u8]) -> Vec<u8> {
    let algorithm = &ring::digest::SHA256;
    ring::digest::digest(algorithm, data).as_ref().to_vec()
}

// ── Test PKI ───────────────────────────────────────────────────────────────

fn ensure_crypto_provider() {
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// The PKCS#8 form of an rcgen key pair, retained so the same key that issued a
/// certificate can also sign raw `tbsResponseData` bytes.
///
/// `rcgen::Issuer::new` consumes its `KeyPair`, so the PKCS#8 bytes are taken
/// before the pair is moved and every OCSP signature is produced from them.
struct SigningKey {
    pkcs8: Vec<u8>,
}

impl SigningKey {
    fn sign(&self, message: &[u8]) -> Vec<u8> {
        let rng = SystemRandom::new();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &self.pkcs8, &rng)
            .expect("ECDSA signing key");
        // Touch the public key so an accidental key/certificate mismatch in a
        // fixture surfaces here rather than as an opaque verification failure.
        assert!(!key.public_key().as_ref().is_empty());
        key.sign(&rng, message).expect("sign").as_ref().to_vec()
    }
}

/// A fresh P-256 key pair plus its PKCS#8 copy.
fn new_key() -> (rcgen::KeyPair, SigningKey) {
    let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("key pair");
    let pkcs8 = pair.serialize_der();
    (pair, SigningKey { pkcs8 })
}

const LEAF_SERIAL: u64 = 0x4300;
const OTHER_SERIAL: u64 = 0x4301;

struct TestPki {
    issuer_key: SigningKey,
    issuer_der: Vec<u8>,
    issuer_pem: String,
    leaf_der: Vec<u8>,
    leaf_pem: String,
    leaf_key_pem: String,
    /// A delegated OCSP responder: issued by the CA, carrying
    /// `id-kp-OCSPSigning`.
    delegate_key: SigningKey,
    delegate_der: Vec<u8>,
    /// A responder certificate with the OCSP-signing EKU that the CA never
    /// issued.
    rogue_key: SigningKey,
    rogue_der: Vec<u8>,
    /// A certificate issued by the CA that lacks `id-kp-OCSPSigning`.
    no_eku_key: SigningKey,
    no_eku_der: Vec<u8>,
    /// A delegated responder carrying an explicit `KeyUsage` that includes
    /// `digitalSignature`.
    signing_ku_key: SigningKey,
    signing_ku_der: Vec<u8>,
    /// A delegated responder whose present `KeyUsage` withholds
    /// `digitalSignature`.
    no_digital_signature_key: SigningKey,
    no_digital_signature_der: Vec<u8>,
    /// A second, unrelated CA and a leaf beneath it.
    other_issuer_der: Vec<u8>,
    /// A certificate carrying the CA's exact subject name over a different key.
    /// It never signed the leaf.
    impostor_issuer_der: Vec<u8>,
    /// A certificate whose subject equals its issuer name but whose signature
    /// was made by a *different* key of that name: self-issued, not
    /// self-signed.
    self_issued_not_self_signed_der: Vec<u8>,
}

fn build_pki() -> TestPki {
    ensure_crypto_provider();

    let (issuer_pair, issuer_key) = new_key();
    let mut issuer_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
    issuer_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    issuer_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Ferrum OCSP Test CA");
    issuer_params
        .key_usages
        .push(rcgen::KeyUsagePurpose::KeyCertSign);
    let issuer_cert = issuer_params
        .self_signed(&issuer_pair)
        .expect("self-signed CA");
    let issuer_der = issuer_cert.der().to_vec();
    let issuer_pem = issuer_cert.pem();
    let issuer_handle = rcgen::Issuer::new(issuer_params, issuer_pair);

    let (leaf_pair, _leaf_key) = new_key();
    let mut leaf_params =
        rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("leaf params");
    leaf_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "ferrum-ocsp-leaf");
    leaf_params.serial_number = Some(rcgen::SerialNumber::from(LEAF_SERIAL));
    leaf_params
        .extended_key_usages
        .push(rcgen::ExtendedKeyUsagePurpose::ServerAuth);
    let leaf_cert = leaf_params
        .signed_by(&leaf_pair, &issuer_handle)
        .expect("leaf cert");
    let leaf_key_pem = leaf_pair.serialize_pem();

    // A delegated responder: issued by the CA and carrying id-kp-OCSPSigning.
    let (delegate_pair, delegate_key) = new_key();
    let mut delegate_params =
        rcgen::CertificateParams::new(Vec::<String>::new()).expect("delegate params");
    delegate_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Ferrum OCSP Responder");
    delegate_params
        .extended_key_usages
        .push(rcgen::ExtendedKeyUsagePurpose::OcspSigning);
    let delegate_cert = delegate_params
        .signed_by(&delegate_pair, &issuer_handle)
        .expect("delegate cert");

    // Issued by the same CA, but without the OCSP-signing EKU.
    let (no_eku_pair, no_eku_key) = new_key();
    let mut no_eku_params =
        rcgen::CertificateParams::new(Vec::<String>::new()).expect("no-eku params");
    no_eku_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Ferrum Non-Responder");
    let no_eku_cert = no_eku_params
        .signed_by(&no_eku_pair, &issuer_handle)
        .expect("no-eku cert");

    // Self-signed with the OCSP-signing EKU, but never issued by the CA.
    let (rogue_pair, rogue_key) = new_key();
    let mut rogue_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("rogue");
    rogue_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Ferrum Rogue Responder");
    rogue_params
        .extended_key_usages
        .push(rcgen::ExtendedKeyUsagePurpose::OcspSigning);
    let rogue_cert = rogue_params.self_signed(&rogue_pair).expect("rogue cert");

    // Issued by the CA with id-kp-OCSPSigning and a KeyUsage that permits a
    // digital signature.
    let (signing_ku_pair, signing_ku_key) = new_key();
    let mut signing_ku_params =
        rcgen::CertificateParams::new(Vec::<String>::new()).expect("signing-ku params");
    signing_ku_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Ferrum OCSP Responder KU");
    signing_ku_params
        .extended_key_usages
        .push(rcgen::ExtendedKeyUsagePurpose::OcspSigning);
    signing_ku_params
        .key_usages
        .push(rcgen::KeyUsagePurpose::DigitalSignature);
    let signing_ku_cert = signing_ku_params
        .signed_by(&signing_ku_pair, &issuer_handle)
        .expect("signing-ku cert");

    // Same, but the present KeyUsage withholds digitalSignature.
    let (no_ds_pair, no_digital_signature_key) = new_key();
    let mut no_ds_params =
        rcgen::CertificateParams::new(Vec::<String>::new()).expect("no-ds params");
    no_ds_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Ferrum OCSP Responder No DS");
    no_ds_params
        .extended_key_usages
        .push(rcgen::ExtendedKeyUsagePurpose::OcspSigning);
    no_ds_params
        .key_usages
        .push(rcgen::KeyUsagePurpose::KeyEncipherment);
    let no_ds_cert = no_ds_params
        .signed_by(&no_ds_pair, &issuer_handle)
        .expect("no-ds cert");

    // The CA's exact subject name over a foreign key. Nothing it holds signed
    // the leaf, so it must never be selected as the issuer.
    let (impostor_pair, _impostor_key) = new_key();
    let mut impostor_params =
        rcgen::CertificateParams::new(Vec::<String>::new()).expect("impostor params");
    impostor_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    impostor_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Ferrum OCSP Test CA");
    impostor_params
        .key_usages
        .push(rcgen::KeyUsagePurpose::KeyCertSign);
    let impostor_cert = impostor_params
        .self_signed(&impostor_pair)
        .expect("impostor CA cert");

    // A CA named "Ferrum Self Issued" issuing a certificate that carries the
    // same subject name but its own, different key: subject == issuer, yet the
    // signature is not verifiable under the certificate's own key.
    let (masquerade_pair, _masquerade_key) = new_key();
    let mut masquerade_params =
        rcgen::CertificateParams::new(Vec::<String>::new()).expect("masquerade params");
    masquerade_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    masquerade_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Ferrum Self Issued");
    masquerade_params
        .key_usages
        .push(rcgen::KeyUsagePurpose::KeyCertSign);
    let _masquerade_cert = masquerade_params
        .self_signed(&masquerade_pair)
        .expect("masquerade CA cert");
    let masquerade_handle = rcgen::Issuer::new(masquerade_params, masquerade_pair);

    let (self_issued_pair, _self_issued_key) = new_key();
    let mut self_issued_params =
        rcgen::CertificateParams::new(Vec::<String>::new()).expect("self-issued params");
    self_issued_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Ferrum Self Issued");
    let self_issued_cert = self_issued_params
        .signed_by(&self_issued_pair, &masquerade_handle)
        .expect("self-issued cert");

    let (other_pair, _other_key) = new_key();
    let mut other_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("other CA");
    other_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    other_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Ferrum Unrelated CA");
    let other_cert = other_params
        .self_signed(&other_pair)
        .expect("other CA cert");

    TestPki {
        issuer_key,
        issuer_der,
        issuer_pem,
        leaf_pem: leaf_cert.pem(),
        leaf_der: leaf_cert.der().to_vec(),
        leaf_key_pem,
        delegate_key,
        delegate_der: delegate_cert.der().to_vec(),
        rogue_key,
        rogue_der: rogue_cert.der().to_vec(),
        no_eku_key,
        no_eku_der: no_eku_cert.der().to_vec(),
        signing_ku_key,
        signing_ku_der: signing_ku_cert.der().to_vec(),
        no_digital_signature_key,
        no_digital_signature_der: no_ds_cert.der().to_vec(),
        other_issuer_der: other_cert.der().to_vec(),
        impostor_issuer_der: impostor_cert.der().to_vec(),
        self_issued_not_self_signed_der: self_issued_cert.der().to_vec(),
    }
}

// ── OCSP response builder ──────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
enum Status {
    Good,
    Revoked,
    Unknown,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ResponderIdKind {
    ByName,
    ByKey,
}

struct ResponseBuilder<'a> {
    /// Certificate whose subject/public key names the responder.
    responder_cert: &'a [u8],
    /// Key that actually signs `tbsResponseData`.
    signing_key: &'a SigningKey,
    responder_id: ResponderIdKind,
    /// Certificate whose subject name and public key the `CertID` hashes.
    cert_id_issuer: &'a [u8],
    serial: u64,
    hash_oid: &'static [u8],
    status: Status,
    this_update: i64,
    next_update: Option<i64>,
    embedded_certs: Vec<&'a [u8]>,
    corrupt_signature: bool,
    response_status: u8,
    response_type_oid: &'static [u8],
    /// Raw replacement for the `producedAt` element.
    produced_at: Option<Vec<u8>>,
    /// Raw elements appended to `ResponseData` after `responses`.
    response_data_tail: Vec<Vec<u8>>,
    /// Raw replacement for everything after `thisUpdate` in each
    /// `SingleResponse`. `None` emits the default optional `nextUpdate`.
    single_tail: Option<Vec<Vec<u8>>>,
    /// Raw replacement for the `certStatus` element.
    cert_status: Option<Vec<u8>>,
    /// Emit a second entry for the same serial under this `CertID` hash OID.
    duplicate_hash_oid: Option<&'static [u8]>,
    /// Emit a leading entry for an unrelated serial.
    leading_serial: Option<u64>,
    /// Raw element prepended to `ResponseData`, for `version [0]` fixtures.
    version_field: Option<Vec<u8>>,
    /// Tag byte of the `CertID` `serialNumber`. `0x02` is the universal
    /// INTEGER; `0x82` reuses tag *number* 2 in the context-specific class.
    serial_tag: u8,
    /// Encode the `CertID` `issuerNameHash` as a constructed OCTET STRING
    /// (`0x24`) wrapping a primitive segment, which DER forbids.
    constructed_name_hash: bool,
    /// Tag byte of the `responses` container. `0x30` is the universal
    /// constructed SEQUENCE; `0x10` is the primitive form DER forbids.
    responses_tag: u8,
    /// Unused-bit count in the signature BIT STRING. Canonical DER uses 0.
    signature_unused_bits: u8,
    /// Raw INTEGER content for every `CertID` `serialNumber`. `None` uses the
    /// canonical encoding of `serial`.
    serial_content: Option<Vec<u8>>,
    /// Raw ENUMERATED content for `responseStatus`. `None` uses
    /// `response_status` as a single content octet.
    response_status_content: Option<Vec<u8>>,
    /// Raw `AlgorithmIdentifier` parameters TLV for each `CertID` hash
    /// algorithm. `None` omits parameters, the usual encoding.
    hash_algorithm_parameters: Option<Vec<u8>>,
    /// Raw `AlgorithmIdentifier` parameters TLV for `signatureAlgorithm`.
    signature_algorithm_parameters: Option<Vec<u8>>,
}

impl<'a> ResponseBuilder<'a> {
    fn new(pki: &'a TestPki, now: i64) -> Self {
        Self {
            responder_cert: pki.issuer_der.as_slice(),
            signing_key: &pki.issuer_key,
            responder_id: ResponderIdKind::ByName,
            cert_id_issuer: pki.issuer_der.as_slice(),
            serial: LEAF_SERIAL,
            hash_oid: OID_SHA1,
            status: Status::Good,
            this_update: now - 3_600,
            next_update: Some(now + 3_600),
            embedded_certs: Vec::new(),
            corrupt_signature: false,
            response_status: 0,
            response_type_oid: OID_OCSP_BASIC,
            produced_at: None,
            response_data_tail: Vec::new(),
            single_tail: None,
            cert_status: None,
            duplicate_hash_oid: None,
            leading_serial: None,
            version_field: None,
            serial_tag: 0x02,
            constructed_name_hash: false,
            responses_tag: 0x30,
            signature_unused_bits: 0,
            serial_content: None,
            response_status_content: None,
            hash_algorithm_parameters: None,
            signature_algorithm_parameters: None,
        }
    }

    /// One `SingleResponse` for `serial`, with the `CertID` hashed under
    /// `hash_oid`.
    fn single_response(&self, serial: u64, hash_oid: &[u8]) -> Vec<u8> {
        let cert_id_issuer = parse_certificate(self.cert_id_issuer);
        let hash = |data: &[u8]| -> Vec<u8> {
            if hash_oid == OID_SHA256 {
                sha256(data)
            } else {
                sha1(data)
            }
        };
        let name_hash = hash(cert_id_issuer.subject().as_raw());
        let key_hash = hash(cert_id_issuer.public_key().subject_public_key.data.as_ref());
        let encoded_name_hash = if self.constructed_name_hash {
            tlv(0x24, &octet_string(&name_hash))
        } else {
            octet_string(&name_hash)
        };
        let serial_content = self
            .serial_content
            .clone()
            .unwrap_or_else(|| serial_bytes(serial));
        let cert_id = sequence(&[
            algorithm_identifier_with_params(
                hash_oid,
                self.hash_algorithm_parameters.as_deref(),
            ),
            encoded_name_hash,
            octet_string(&key_hash),
            tlv(self.serial_tag, &serial_content),
        ]);

        let default_status = match self.status {
            // good [0] IMPLICIT NULL
            Status::Good => tlv(0x80, &[]),
            // revoked [1] IMPLICIT RevokedInfo { revocationTime GeneralizedTime }
            Status::Revoked => tlv(0xa1, &generalized_time(self.this_update)),
            // unknown [2] IMPLICIT UnknownInfo (NULL)
            Status::Unknown => tlv(0x82, &[]),
        };
        let cert_status = self.cert_status.clone().unwrap_or(default_status);

        let mut parts = vec![cert_id, cert_status, generalized_time(self.this_update)];
        match &self.single_tail {
            Some(tail) => parts.extend(tail.iter().cloned()),
            None => {
                if let Some(next_update) = self.next_update {
                    parts.push(explicit(0, &generalized_time(next_update)));
                }
            }
        }
        sequence(&parts)
    }

    fn build(&self) -> Vec<u8> {
        let responder = parse_certificate(self.responder_cert);
        let responder_id = match self.responder_id {
            ResponderIdKind::ByName => explicit(1, responder.subject().as_raw()),
            ResponderIdKind::ByKey => {
                let key = responder.public_key().subject_public_key.data.as_ref();
                explicit(2, &octet_string(&sha1(key)))
            }
        };

        let mut singles = Vec::new();
        if let Some(serial) = self.leading_serial {
            singles.push(self.single_response(serial, self.hash_oid));
        }
        singles.push(self.single_response(self.serial, self.hash_oid));
        if let Some(hash_oid) = self.duplicate_hash_oid {
            singles.push(self.single_response(self.serial, hash_oid));
        }

        let default_produced_at = generalized_time(self.this_update);
        let produced_at = self.produced_at.clone().unwrap_or(default_produced_at);

        let responses = tlv(self.responses_tag, &singles.concat());
        let mut response_data_parts = match &self.version_field {
            Some(version) => vec![version.clone(), responder_id, produced_at, responses],
            None => vec![responder_id, produced_at, responses],
        };
        response_data_parts.extend(self.response_data_tail.iter().cloned());
        let response_data = sequence(&response_data_parts);

        let mut signature = self.signing_key.sign(&response_data);
        if self.corrupt_signature {
            let last = signature.len() - 1;
            signature[last] ^= 0xff;
        }

        let mut basic_parts = vec![
            response_data,
            algorithm_identifier_with_params(
                OID_ECDSA_SHA256,
                self.signature_algorithm_parameters.as_deref(),
            ),
            bit_string_with_unused(self.signature_unused_bits, &signature),
        ];
        if !self.embedded_certs.is_empty() {
            let certs: Vec<Vec<u8>> = self.embedded_certs.iter().map(|d| d.to_vec()).collect();
            basic_parts.push(explicit(0, &sequence(&certs)));
        }
        let basic = sequence(&basic_parts);

        let status_element = match &self.response_status_content {
            Some(content) => tlv(0x0a, content),
            None => enumerated(self.response_status),
        };
        if self.response_status != 0 {
            return sequence(&[status_element]);
        }

        sequence(&[
            status_element,
            explicit(
                0,
                &sequence(&[oid(self.response_type_oid), octet_string(&basic)]),
            ),
        ])
    }
}

fn chain(pki: &TestPki) -> Vec<CertificateDer<'static>> {
    vec![
        CertificateDer::from(pki.leaf_der.clone()),
        CertificateDer::from(pki.issuer_der.clone()),
    ]
}

/// Evaluation instant for every fixture.
///
/// Real wall-clock time, because the load-path tests go through the production
/// entry points, which take their own `SystemTime::now()`. Every fixture is
/// built relative to this value, so the behaviour under test stays
/// deterministic even though the instant does not.
fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs() as i64
}

/// A complete, correctly signed OCSP response over a freshly built test PKI.
///
/// Shared with the managed-TLS admin tests so their fixture is a response that
/// actually satisfies the issue #4300 structural gate rather than a placeholder
/// byte string that only happened to be non-empty.
pub(crate) fn signed_ocsp_response_fixture() -> Vec<u8> {
    let pki = build_pki();
    ResponseBuilder::new(&pki, now()).build()
}

// ── Structural admission (the admin boundary) ──────────────────────────────

#[test]
fn structural_validation_accepts_a_well_formed_basic_response() {
    let pki = build_pki();
    let der = ResponseBuilder::new(&pki, now()).build();

    let structure = validate_structure(&der).expect("structurally valid");
    assert_eq!(structure.der_len, der.len());
    assert_eq!(structure.single_responses, 1);
}

#[test]
fn structural_validation_rejects_arbitrary_bytes() {
    // The exact fixture the pre-#4300 unit test called a valid OCSP response.
    let error = validate_structure(&[1, 2, 3]).expect_err("must reject");
    assert!(
        error.contains("malformed DER") || error.contains("SEQUENCE"),
        "{error}"
    );

    let empty = validate_structure(&[]).expect_err("empty response");
    assert!(empty.contains("empty"), "{empty}");
}

#[test]
fn structural_validation_rejects_an_unsuccessful_envelope() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.response_status = 3;
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("tryLater(3)"), "{error}");
}

#[test]
fn structural_validation_rejects_a_non_basic_response_type() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.response_type_oid = OID_SHA256;
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("id-pkix-ocsp-basic"), "{error}");
}

#[test]
fn size_bound_is_enforced_before_parsing() {
    let oversized = vec![0x30_u8; MAX_OCSP_RESPONSE_BYTES + 1];
    let error = validate_structure(&oversized).expect_err("must reject");
    assert!(error.contains("exceeds"), "{error}");

    let pki = build_pki();
    let error =
        validate_stapled_response_at(&oversized, &chain(&pki), now()).expect_err("must reject");
    assert!(error.contains("exceeds"), "{error}");
}

// ── Certificate-bound validation ───────────────────────────────────────────

#[test]
fn a_fresh_issuer_signed_response_for_the_configured_leaf_is_accepted() {
    let pki = build_pki();
    let der = ResponseBuilder::new(&pki, now()).build();

    let acceptance =
        validate_stapled_response_at(&der, &chain(&pki), now()).expect("accepted staple");
    assert_eq!(acceptance.der_len, der.len());
    assert_eq!(acceptance.this_update, now() - 3_600);
    assert_eq!(acceptance.next_update, now() + 3_600);
    assert!(!acceptance.delegated_responder);
}

#[test]
fn a_responder_id_by_key_hash_is_accepted() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.responder_id = ResponderIdKind::ByKey;

    validate_stapled_response_at(&builder.build(), &chain(&pki), now()).expect("accepted staple");
}

#[test]
fn a_sha256_cert_id_is_accepted() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.hash_oid = OID_SHA256;

    validate_stapled_response_at(&builder.build(), &chain(&pki), now()).expect("accepted staple");
}

#[test]
fn a_corrupted_signature_is_rejected() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.corrupt_signature = true;

    let error = validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect_err("must reject");
    assert!(error.contains("signature"), "{error}");
}

#[test]
fn a_response_signed_by_an_unrelated_key_is_rejected() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    // Named as the issuer, signed by someone else entirely.
    builder.signing_key = &pki.rogue_key;

    let error = validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect_err("must reject");
    assert!(
        error.contains("signature") || error.contains("responder"),
        "{error}"
    );
}

#[test]
fn a_properly_delegated_responder_is_accepted() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.responder_cert = pki.delegate_der.as_slice();
    builder.signing_key = &pki.delegate_key;
    builder.embedded_certs = vec![pki.delegate_der.as_slice()];

    let acceptance = validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect("accepted staple");
    assert!(acceptance.delegated_responder);
}

#[test]
fn a_delegated_responder_without_the_ocsp_signing_eku_is_rejected() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.responder_cert = pki.no_eku_der.as_slice();
    builder.signing_key = &pki.no_eku_key;
    builder.embedded_certs = vec![pki.no_eku_der.as_slice()];

    let error = validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect_err("must reject");
    assert!(error.contains("not authorized"), "{error}");
}

#[test]
fn a_self_signed_responder_the_issuer_never_issued_is_rejected() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.responder_cert = pki.rogue_der.as_slice();
    builder.signing_key = &pki.rogue_key;
    builder.embedded_certs = vec![pki.rogue_der.as_slice()];

    let error = validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect_err("must reject");
    assert!(error.contains("not authorized"), "{error}");
}

#[test]
fn a_response_for_a_different_serial_is_rejected() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.serial = OTHER_SERIAL;

    let error = validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect_err("must reject");
    assert!(
        error.contains("no entry for the configured certificate"),
        "{error}"
    );
}

#[test]
fn a_response_bound_to_a_different_issuer_is_rejected() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.cert_id_issuer = pki.other_issuer_der.as_slice();

    let error = validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect_err("must reject");
    assert!(error.contains("not the configured issuer"), "{error}");
}

#[test]
fn a_revoked_status_is_rejected() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.status = Status::Revoked;

    let error = validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect_err("must reject");
    assert!(error.contains("certStatus revoked"), "{error}");
}

#[test]
fn an_unknown_status_is_rejected() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.status = Status::Unknown;

    let error = validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect_err("must reject");
    assert!(error.contains("certStatus unknown"), "{error}");
}

#[test]
fn an_expired_response_is_rejected_and_the_skew_window_is_bounded() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.this_update = now() - 7_200;
    builder.next_update = Some(now() - OCSP_CLOCK_SKEW_SECONDS - 60);

    let error = validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect_err("must reject");
    assert!(error.contains("expired"), "{error}");

    // Just inside the skew allowance the same shape is still served.
    builder.next_update = Some(now() - OCSP_CLOCK_SKEW_SECONDS + 60);
    validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect("within the documented skew allowance");
}

#[test]
fn a_future_response_is_rejected_and_the_skew_window_is_bounded() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.this_update = now() + OCSP_CLOCK_SKEW_SECONDS + 60;
    builder.next_update = Some(now() + 86_400);

    let error = validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect_err("must reject");
    assert!(error.contains("future"), "{error}");

    builder.this_update = now() + OCSP_CLOCK_SKEW_SECONDS - 60;
    validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect("within the documented skew allowance");
}

#[test]
fn a_response_without_next_update_is_rejected() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.next_update = None;

    let error = validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect_err("must reject");
    assert!(error.contains("omits nextUpdate"), "{error}");
}

#[test]
fn a_chain_without_the_issuer_cannot_bind_a_staple() {
    let pki = build_pki();
    let der = ResponseBuilder::new(&pki, now()).build();
    let leaf_only = vec![CertificateDer::from(pki.leaf_der.clone())];

    let error = validate_stapled_response_at(&der, &leaf_only, now()).expect_err("must reject");
    assert!(
        error.contains("does not contain the leaf's issuer"),
        "{error}"
    );
}

// ── ResponseData grammar ───────────────────────────────────────────────────

#[test]
fn a_malformed_produced_at_value_is_rejected() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    // Correctly tagged GeneralizedTime, but the value is not a time.
    builder.produced_at = Some(tlv(0x18, b"not-a-timestamp"));

    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("producedAt"), "{error}");
    let error = validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect_err("must reject");
    assert!(error.contains("producedAt"), "{error}");
}

#[test]
fn a_produced_at_with_the_wrong_tag_is_rejected() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.produced_at = Some(octet_string(b"20260101000000Z"));

    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(
        error.contains("producedAt is not a GeneralizedTime"),
        "{error}"
    );
}

#[test]
fn an_unknown_trailing_field_in_response_data_is_rejected() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    // [3] is not a field of ResponseData at all.
    builder.response_data_tail = vec![explicit(3, &octet_string(b"surprise"))];

    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(
        error.contains("unexpected field after responses"),
        "{error}"
    );
}

#[test]
fn a_duplicate_response_extensions_field_is_rejected() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    let entry = one_extension_field(1, false);
    builder.response_data_tail = vec![entry.clone(), entry];

    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(
        error.contains("trailing fields after responseExtensions"),
        "{error}"
    );
}

#[test]
fn a_non_critical_response_extension_is_parsed_and_ignored() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.response_data_tail = vec![one_extension_field(1, false)];

    validate_structure(&builder.build()).expect("structurally valid");
    validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect("a non-critical extension is ignored");
}

#[test]
fn a_critical_response_extension_is_rejected() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.response_data_tail = vec![one_extension_field(1, true)];

    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("critical extension"), "{error}");
    let error = validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect_err("must reject");
    assert!(error.contains("critical extension"), "{error}");
}

#[test]
fn a_malformed_extensions_container_is_rejected() {
    let pki = build_pki();

    // Not a SEQUENCE OF Extension: an OCTET STRING where the container belongs.
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.response_data_tail = vec![explicit(1, &octet_string(b"not-extensions"))];
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(
        error.contains("responseExtensions is not a SEQUENCE"),
        "{error}"
    );

    // An Extension whose extnValue is not an OCTET STRING.
    let mut builder = ResponseBuilder::new(&pki, now());
    let malformed = sequence(&[oid(OID_OCSP_NONCE), tlv(0x02, &[0x01])]);
    builder.response_data_tail = vec![extensions_field(1, &[malformed])];
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("extnValue"), "{error}");

    // DER omits `critical` when FALSE, so an encoded FALSE is not DER.
    let mut builder = ResponseBuilder::new(&pki, now());
    let explicit_false = sequence(&[
        oid(OID_OCSP_NONCE),
        tlv(0x01, &[0x00]),
        octet_string(b"nonce"),
    ]);
    builder.response_data_tail = vec![extensions_field(1, &[explicit_false])];
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("DEFAULT FALSE"), "{error}");

    // An empty Extensions container is not `SIZE (1..MAX)`.
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.response_data_tail = vec![extensions_field(1, &[])];
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("empty SEQUENCE"), "{error}");
}

// ── SingleResponse grammar ─────────────────────────────────────────────────

#[test]
fn a_duplicate_next_update_is_rejected() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    // The second [0] used to silently overwrite the first, so a responder could
    // sign one window and have Ferrum enforce another.
    builder.single_tail = Some(vec![
        explicit(0, &generalized_time(now() + 3_600)),
        explicit(0, &generalized_time(now() + 86_400)),
    ]);

    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(
        error.contains("unexpected field after thisUpdate"),
        "{error}"
    );
}

#[test]
fn misordered_single_response_fields_are_rejected() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    // singleExtensions [1] before nextUpdate [0].
    builder.single_tail = Some(vec![
        one_extension_field(1, false),
        explicit(0, &generalized_time(now() + 3_600)),
    ]);

    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(
        error.contains("trailing fields after singleExtensions"),
        "{error}"
    );
}

#[test]
fn an_unknown_trailing_field_in_a_single_response_is_rejected() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.single_tail = Some(vec![
        explicit(0, &generalized_time(now() + 3_600)),
        explicit(2, &octet_string(b"surprise")),
    ]);

    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(
        error.contains("unexpected field after thisUpdate"),
        "{error}"
    );
}

#[test]
fn single_extensions_follow_the_same_criticality_rule() {
    let pki = build_pki();

    let mut builder = ResponseBuilder::new(&pki, now());
    builder.single_tail = Some(vec![
        explicit(0, &generalized_time(now() + 3_600)),
        one_extension_field(1, false),
    ]);
    validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect("a non-critical singleExtension is ignored");

    let mut builder = ResponseBuilder::new(&pki, now());
    builder.single_tail = Some(vec![
        explicit(0, &generalized_time(now() + 3_600)),
        one_extension_field(1, true),
    ]);
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("singleExtensions"), "{error}");
    assert!(error.contains("critical extension"), "{error}");
}

// ── CertStatus CHOICE encoding ─────────────────────────────────────────────

#[test]
fn a_constructed_or_non_empty_good_status_is_rejected() {
    let pki = build_pki();

    let mut builder = ResponseBuilder::new(&pki, now());
    // Constructed [0] instead of the primitive IMPLICIT NULL.
    builder.cert_status = Some(tlv(0xa0, &[]));
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("certStatus good"), "{error}");

    let mut builder = ResponseBuilder::new(&pki, now());
    // Primitive, but carrying content an IMPLICIT NULL cannot have.
    builder.cert_status = Some(tlv(0x80, &[0x00]));
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("certStatus good"), "{error}");
}

#[test]
fn a_malformed_unknown_status_is_rejected_structurally() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.cert_status = Some(tlv(0x82, &[0x05, 0x00]));

    // Structurally malformed before serving policy ever sees `unknown`.
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("certStatus unknown"), "{error}");
    assert!(error.contains("IMPLICIT NULL"), "{error}");
}

#[test]
fn a_malformed_revoked_status_is_rejected_structurally() {
    let pki = build_pki();

    // revoked encoded as a primitive, but RevokedInfo is a SEQUENCE.
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.cert_status = Some(tlv(0x81, &generalized_time(now())));
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("revoked is primitive"), "{error}");

    // Constructed, but revocationTime is missing its GeneralizedTime.
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.cert_status = Some(tlv(0xa1, &octet_string(b"20260101000000Z")));
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("revocationTime"), "{error}");

    // A revocationReason that is not an ENUMERATED.
    let mut builder = ResponseBuilder::new(&pki, now());
    let mut revoked = generalized_time(now() - 60);
    revoked.extend_from_slice(&explicit(0, &octet_string(b"keyCompromise")));
    builder.cert_status = Some(tlv(0xa1, &revoked));
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("revocationReason"), "{error}");

    // A well-formed RevokedInfo still fails closed on serving policy, and does
    // so with the status reason rather than a structural one.
    let mut builder = ResponseBuilder::new(&pki, now());
    let mut revoked = generalized_time(now() - 60);
    revoked.extend_from_slice(&explicit(0, &enumerated(1)));
    builder.cert_status = Some(tlv(0xa1, &revoked));
    validate_structure(&builder.build()).expect("structurally well formed");
    let error = validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect_err("must reject");
    assert!(error.contains("certStatus revoked"), "{error}");
}

#[test]
fn an_unrecognized_cert_status_alternative_is_rejected() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.cert_status = Some(tlv(0x83, &[]));

    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("unrecognized alternative"), "{error}");
}

// ── CertID ambiguity ───────────────────────────────────────────────────────

#[test]
fn duplicate_matching_cert_ids_are_rejected_as_ambiguous() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.duplicate_hash_oid = Some(OID_SHA1);

    let error = validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect_err("must reject");
    assert!(error.contains("more than one SingleResponse"), "{error}");
}

#[test]
fn a_second_matching_cert_id_under_another_hash_algorithm_is_also_ambiguous() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    // A strict client that derives SHA-256 CertIDs would select this second
    // entry, so Ferrum must not silently serve the first.
    builder.duplicate_hash_oid = Some(OID_SHA256);

    let error = validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect_err("must reject");
    assert!(error.contains("more than one SingleResponse"), "{error}");
}

#[test]
fn a_leading_entry_for_another_certificate_still_resolves_the_configured_one() {
    let pki = build_pki();
    let at = now();
    let mut builder = ResponseBuilder::new(&pki, at);
    builder.leading_serial = Some(OTHER_SERIAL);

    let acceptance = validate_stapled_response_at(&builder.build(), &chain(&pki), at)
        .expect("one unambiguous match");
    assert_eq!(acceptance.next_update, at + 3_600);
}

// ── Issuer selection ───────────────────────────────────────────────────────

#[test]
fn a_same_subject_non_issuer_chain_candidate_cannot_stand_in_for_the_issuer() {
    let pki = build_pki();
    let der = ResponseBuilder::new(&pki, now()).build();
    let impostor = vec![
        CertificateDer::from(pki.leaf_der.clone()),
        CertificateDer::from(pki.impostor_issuer_der.clone()),
    ];

    let error = validate_stapled_response_at(&der, &impostor, now()).expect_err("must reject");
    assert!(
        error.contains("no certificate whose key signed the leaf"),
        "{error}"
    );
}

#[test]
fn the_scan_continues_past_a_same_subject_impostor_to_the_real_issuer() {
    let pki = build_pki();
    let der = ResponseBuilder::new(&pki, now()).build();
    let with_impostor = vec![
        CertificateDer::from(pki.leaf_der.clone()),
        CertificateDer::from(pki.impostor_issuer_der.clone()),
        CertificateDer::from(pki.issuer_der.clone()),
    ];

    validate_stapled_response_at(&der, &with_impostor, now())
        .expect("the real issuer is still found behind a same-name impostor");
}

#[test]
fn a_self_issued_leaf_that_is_not_self_signed_cannot_bind_a_staple() {
    let pki = build_pki();
    let der = ResponseBuilder::new(&pki, now()).build();
    let masquerade = pki.self_issued_not_self_signed_der.clone();
    let self_issued = vec![CertificateDer::from(masquerade)];

    let error = validate_stapled_response_at(&der, &self_issued, now()).expect_err("must reject");
    assert!(
        error.contains("no certificate whose key signed the leaf"),
        "{error}"
    );
}

// ── Delegated responder key usage ──────────────────────────────────────────

#[test]
fn a_delegated_responder_with_digital_signature_key_usage_is_accepted() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.responder_cert = pki.signing_ku_der.as_slice();
    builder.signing_key = &pki.signing_ku_key;
    builder.embedded_certs = vec![pki.signing_ku_der.as_slice()];

    let acceptance = validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect("accepted staple");
    assert!(acceptance.delegated_responder);
}

#[test]
fn a_delegated_responder_whose_key_usage_excludes_digital_signature_is_rejected() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.responder_cert = pki.no_digital_signature_der.as_slice();
    builder.signing_key = &pki.no_digital_signature_key;
    builder.embedded_certs = vec![pki.no_digital_signature_der.as_slice()];

    let error = validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect_err("must reject");
    assert!(error.contains("not authorized"), "{error}");
}

// ── DER class and primitive/constructed form ───────────────────────────────

#[test]
fn a_context_specific_element_reusing_a_universal_tag_number_is_rejected() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    // `[2] IMPLICIT` primitive: the same tag *number* as a universal INTEGER,
    // and the same content bytes, in a different class. A parser that compares
    // only the tag number would decode it as the serial number and bind the
    // response to the configured certificate.
    builder.serial_tag = 0x82;

    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("serialNumber"), "{error}");
    let error = validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect_err("must reject");
    assert!(error.contains("serialNumber"), "{error}");
}

#[test]
fn a_constructed_octet_string_is_rejected() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    // A constructed OCTET STRING carrying one primitive segment holds the same
    // octets as the DER form, so a tag-number-only check would hash-compare it
    // against the issuer name and accept the binding.
    builder.constructed_name_hash = true;

    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(
        error.contains("issuerNameHash") || error.contains("malformed DER"),
        "{error}"
    );
}

#[test]
fn a_primitive_sequence_is_rejected() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    // Universal tag number 16 in the primitive form. DER has no such encoding,
    // so `responses` must be refused rather than walked as a container.
    builder.responses_tag = 0x10;

    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(
        error.contains("responses is not a SEQUENCE") || error.contains("malformed DER"),
        "{error}"
    );
}

#[test]
fn an_explicitly_encoded_default_version_is_rejected() {
    let pki = build_pki();

    // DER omits a DEFAULT value, so `[0] EXPLICIT INTEGER 0` is a second
    // encoding of the same signed object: a strict client refuses it, and
    // Ferrum must not staple what a strict client refuses.
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.version_field = Some(explicit(0, &tlv(0x02, &[0x00])));
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("DEFAULT value"), "{error}");
    let error = validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect_err("must reject");
    assert!(error.contains("DEFAULT value"), "{error}");

    // A non-default version is unsupported, and still reported as such.
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.version_field = Some(explicit(0, &tlv(0x02, &[0x01])));
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("unsupported version 1"), "{error}");
}

// ── Primitive DER type constraints ─────────────────────────────────────────

#[test]
fn a_valid_signature_with_nonzero_unused_bits_is_rejected() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    // Cryptographically valid payload bytes; only the unused-bit count differs
    // from the canonical octet-aligned BIT STRING. x509-parser's verifier
    // ignores unused_bits, so this is the encoding that would still verify.
    builder.signature_unused_bits = 1;

    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("unused_bits=1"), "{error}");
    let error = validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect_err("must reject");
    assert!(error.contains("unused_bits=1"), "{error}");
}

#[test]
fn a_signature_bit_string_with_an_invalid_unused_bit_count_is_rejected() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.signature_unused_bits = 8;

    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("unused_bits=8"), "{error}");
}

#[test]
fn empty_nonminimal_and_negative_cert_id_serials_are_rejected() {
    let pki = build_pki();

    let mut builder = ResponseBuilder::new(&pki, now());
    builder.serial_content = Some(Vec::new());
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("serialNumber"), "{error}");
    assert!(error.contains("empty"), "{error}");

    let mut builder = ResponseBuilder::new(&pki, now());
    let mut padded = vec![0x00];
    padded.extend_from_slice(&serial_bytes(LEAF_SERIAL));
    builder.serial_content = Some(padded);
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("serialNumber"), "{error}");
    assert!(error.contains("minimal"), "{error}");
    let error = validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect_err("must reject");
    assert!(error.contains("serialNumber"), "{error}");

    let mut builder = ResponseBuilder::new(&pki, now());
    builder.serial_content = Some(vec![0x80]);
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("serialNumber"), "{error}");
    assert!(error.contains("negative"), "{error}");
}

#[test]
fn malformed_and_noncanonical_extension_oids_are_rejected() {
    let pki = build_pki();

    let mut builder = ResponseBuilder::new(&pki, now());
    builder.response_data_tail = vec![extensions_field(1, &[extension(&[], false, b"nonce")])];
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("extnID"), "{error}");
    assert!(error.contains("empty"), "{error}");

    let mut unterminated = OID_OCSP_NONCE.to_vec();
    let last = unterminated.len() - 1;
    unterminated[last] |= 0x80;
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.response_data_tail = vec![extensions_field(
        1,
        &[extension(&unterminated, false, b"nonce")],
    )];
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("extnID"), "{error}");
    assert!(error.contains("terminated"), "{error}");

    let mut redundant = vec![OID_OCSP_NONCE[0], 0x80];
    redundant.extend_from_slice(&OID_OCSP_NONCE[1..]);
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.response_data_tail = vec![extensions_field(
        1,
        &[extension(&redundant, false, b"nonce")],
    )];
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("extnID"), "{error}");
    assert!(error.contains("0x80"), "{error}");
}

#[test]
fn noncanonical_successful_response_status_encodings_are_rejected() {
    let pki = build_pki();

    let mut builder = ResponseBuilder::new(&pki, now());
    builder.response_status_content = Some(Vec::new());
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("responseStatus"), "{error}");
    assert!(error.contains("empty"), "{error}");

    let mut builder = ResponseBuilder::new(&pki, now());
    builder.response_status_content = Some(vec![0x00, 0x00]);
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("responseStatus"), "{error}");
    assert!(error.contains("minimal"), "{error}");
}

#[test]
fn noncanonical_revocation_reason_encodings_are_rejected() {
    let pki = build_pki();

    let mut revoked = generalized_time(now() - 60);
    revoked.extend_from_slice(&explicit(0, &tlv(0x0a, &[])));
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.cert_status = Some(tlv(0xa1, &revoked));
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("revocationReason"), "{error}");
    assert!(error.contains("empty"), "{error}");

    let mut revoked = generalized_time(now() - 60);
    revoked.extend_from_slice(&explicit(0, &tlv(0x0a, &[0x00, 0x01])));
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.cert_status = Some(tlv(0xa1, &revoked));
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("revocationReason"), "{error}");
    assert!(error.contains("minimal"), "{error}");
}

#[test]
fn a_cert_id_hash_algorithm_with_null_parameters_is_still_accepted() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.hash_algorithm_parameters = Some(der_null());
    builder.signature_algorithm_parameters = Some(der_null());

    validate_structure(&builder.build()).expect("structurally valid");
    validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect("absent-vs-NULL AlgorithmIdentifier parameters are both canonical");
}

#[test]
fn algorithm_identifier_parameters_that_are_not_absent_or_null_are_rejected() {
    let pki = build_pki();

    let mut builder = ResponseBuilder::new(&pki, now());
    builder.hash_algorithm_parameters = Some(tlv(0x02, &[0x00]));
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("hashAlgorithm"), "{error}");
    assert!(error.contains("parameters"), "{error}");

    let mut builder = ResponseBuilder::new(&pki, now());
    builder.hash_algorithm_parameters = Some(tlv(0x05, &[0x00]));
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("hashAlgorithm"), "{error}");
    assert!(error.contains("parameters"), "{error}");

    let mut builder = ResponseBuilder::new(&pki, now());
    builder.signature_algorithm_parameters = Some(tlv(0x02, &[0x00]));
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("signatureAlgorithm"), "{error}");
    assert!(error.contains("parameters"), "{error}");
}

// ── Embedded responder certificates ────────────────────────────────────────

#[test]
fn a_malformed_embedded_certificate_is_rejected() {
    let pki = build_pki();
    let malformed = sequence(&[octet_string(b"not a certificate")]);
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.embedded_certs = vec![malformed.as_slice()];

    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("parseable X.509 certificate"), "{error}");
}

#[test]
fn a_malformed_unused_embedded_certificate_is_still_rejected() {
    let pki = build_pki();
    let malformed = sequence(&[octet_string(b"not a certificate")]);
    // The response is signed by the issuing CA itself, and the first carried
    // entry is a valid certificate, so the malformed one is never consulted
    // for authorization. Structural admission must still refuse the whole
    // response: bytes this parser cannot account for sit inside what the
    // responder signed.
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.embedded_certs = vec![pki.signing_ku_der.as_slice(), malformed.as_slice()];

    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("parseable X.509 certificate"), "{error}");
    let error = validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect_err("must reject");
    assert!(error.contains("parseable X.509 certificate"), "{error}");
}

#[test]
fn a_well_formed_embedded_certificate_is_still_accepted() {
    let pki = build_pki();
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.embedded_certs = vec![pki.signing_ku_der.as_slice()];

    validate_structure(&builder.build()).expect("structurally valid");
    validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect("an issuer-signed response is accepted alongside a carried certificate");
}

// ── Extension identity ─────────────────────────────────────────────────────

#[test]
fn duplicate_extension_oids_are_rejected() {
    let pki = build_pki();

    // X.509 forbids repeating one extension type. Ferrum ignores a supported
    // non-critical extension, so admitting the repetition would let Ferrum and
    // a strict client disagree about the same signed bytes.
    let repeated = [
        extension(OID_OCSP_NONCE, false, b"first"),
        extension(OID_OCSP_NONCE, false, b"second"),
    ];
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.response_data_tail = vec![extensions_field(1, &repeated)];
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("repeats an extension OID"), "{error}");

    // The same rule applies inside a SingleResponse.
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.single_tail = Some(vec![
        explicit(0, &generalized_time(now() + 3_600)),
        extensions_field(1, &repeated),
    ]);
    let error = validate_structure(&builder.build()).expect_err("must reject");
    assert!(error.contains("repeats an extension OID"), "{error}");
}

#[test]
fn distinct_extension_oids_are_still_accepted() {
    let pki = build_pki();
    let distinct = [
        extension(OID_OCSP_NONCE, false, b"nonce"),
        extension(OID_SHA256, false, b"other"),
    ];
    let mut builder = ResponseBuilder::new(&pki, now());
    builder.response_data_tail = vec![extensions_field(1, &distinct)];

    validate_structure(&builder.build()).expect("structurally valid");
    validate_stapled_response_at(&builder.build(), &chain(&pki), now())
        .expect("distinct non-critical extensions are ignored");
}

// ── Load-path integration ──────────────────────────────────────────────────

fn tls_policy() -> TlsPolicy {
    ensure_crypto_provider();
    TlsPolicy::from_env_config(&EnvConfig::default()).expect("tls policy")
}

/// Materialize the served chain (leaf + issuer) and key as files, plus an OCSP
/// DER file, and return their paths.
fn write_material(dir: &std::path::Path, pki: &TestPki, ocsp: &[u8]) -> (String, String, String) {
    let cert_path = dir.join("server.crt");
    let key_path = dir.join("server.key");
    let ocsp_path = dir.join("staple.der");
    std::fs::write(&cert_path, format!("{}{}", pki.leaf_pem, pki.issuer_pem)).expect("write cert");
    std::fs::write(&key_path, &pki.leaf_key_pem).expect("write key");
    std::fs::write(&ocsp_path, ocsp).expect("write ocsp");
    (
        cert_path.to_string_lossy().into_owned(),
        key_path.to_string_lossy().into_owned(),
        ocsp_path.to_string_lossy().into_owned(),
    )
}

#[test]
fn the_single_certificate_loader_admits_a_valid_staple_and_refuses_an_invalid_one() {
    let pki = build_pki();
    let dir = tempfile::tempdir().expect("tempdir");
    let valid = ResponseBuilder::new(&pki, now()).build();
    let (cert_path, key_path, ocsp_path) = write_material(dir.path(), &pki, &valid);
    let policy = tls_policy();

    load_frontend_tls_candidate_from_paths(
        &cert_path,
        &key_path,
        None,
        Some(&ocsp_path),
        false,
        &policy,
        30,
        &[],
        None,
    )
    .expect("valid staple is admitted");

    // The pre-#4300 accepted-anything fixture must now fail the whole load.
    std::fs::write(&ocsp_path, [1_u8, 2, 3]).expect("rewrite ocsp");
    let error = match load_frontend_tls_candidate_from_paths(
        &cert_path,
        &key_path,
        None,
        Some(&ocsp_path),
        false,
        &policy,
        30,
        &[],
        None,
    ) {
        Err(error) => error,
        Ok(_) => panic!("garbage staple is refused"),
    };
    let rendered = format!("{error:#}");
    assert!(rendered.contains("was rejected"), "{rendered}");
    // Diagnostics stay redacted: no certificate or response bytes leak.
    assert!(!rendered.contains("BEGIN CERTIFICATE"), "{rendered}");
}

/// A reload that produces an invalid staple must never reach the published
/// slot: the candidate fails to build, so the atomic `ArcSwap` publication has
/// nothing to swap in and the last-known-good `ServerConfig` keeps serving.
#[test]
fn a_reload_with_a_bad_staple_leaves_the_last_known_good_material_in_service() {
    let pki = build_pki();
    let dir = tempfile::tempdir().expect("tempdir");
    let valid = ResponseBuilder::new(&pki, now()).build();
    let (cert_path, key_path, ocsp_path) = write_material(dir.path(), &pki, &valid);
    let policy = tls_policy();

    let rebuild = || {
        load_frontend_tls_candidate_from_paths(
            &cert_path,
            &key_path,
            None,
            Some(&ocsp_path),
            false,
            &policy,
            30,
            &[],
            None,
        )
    };

    let accepted = rebuild().expect("first load");
    let published = frontend_tls_slot_with(Arc::clone(&accepted.config));
    let before = published.load_full();

    // A revoked response is exactly the shape that used to be published
    // silently. Each of these rebuilds must fail, so the reload task has no
    // candidate to publish.
    for builder in [
        {
            let mut builder = ResponseBuilder::new(&pki, now());
            builder.status = Status::Revoked;
            builder
        },
        {
            let mut builder = ResponseBuilder::new(&pki, now());
            builder.next_update = Some(now() - OCSP_CLOCK_SKEW_SECONDS - 3_600);
            builder
        },
        {
            let mut builder = ResponseBuilder::new(&pki, now());
            builder.corrupt_signature = true;
            builder
        },
    ] {
        std::fs::write(&ocsp_path, builder.build()).expect("rewrite ocsp");
        let rebuilt = rebuild();
        assert!(
            rebuilt.is_err(),
            "an invalid staple must not produce a candidate"
        );
        if let Ok(candidate) = rebuilt {
            published.store(Arc::new(Some(candidate.config)));
        }
    }

    let after = published.load_full();
    assert!(
        Arc::ptr_eq(&before, &after),
        "a refused staple must leave the published ServerConfig untouched"
    );

    // The original, still-valid response reloads cleanly, so the refusal was
    // about the staple and not about the surrounding material.
    std::fs::write(&ocsp_path, &valid).expect("restore ocsp");
    rebuild().expect("the last-known-good staple still reloads");
}

#[test]
fn the_multi_certificate_loader_binds_the_staple_to_its_single_certificate() {
    let pki = build_pki();
    let dir = tempfile::tempdir().expect("tempdir");
    let valid = ResponseBuilder::new(&pki, now()).build();
    let (cert_path, key_path, ocsp_path) = write_material(dir.path(), &pki, &valid);
    let policy = tls_policy();

    let inputs = vec![GatewayCertificateInput {
        cert_source: cert_path.clone(),
        key_source: key_path.clone(),
        hostname: Some("localhost".to_string()),
        identity: "ns/gw/listener".to_string(),
        is_default: true,
    }];

    load_gateway_multi_cert_tls_config(&inputs, None, Some(&ocsp_path), &policy, 30, &[])
        .expect("valid staple is admitted");

    let mut builder = ResponseBuilder::new(&pki, now());
    builder.serial = OTHER_SERIAL;
    std::fs::write(&ocsp_path, builder.build()).expect("rewrite ocsp");
    let error =
        load_gateway_multi_cert_tls_config(&inputs, None, Some(&ocsp_path), &policy, 30, &[])
            .expect_err("wrong-certificate staple is refused");
    let rendered = format!("{error:#}");
    assert!(rendered.contains("rejected"), "{rendered}");
}
