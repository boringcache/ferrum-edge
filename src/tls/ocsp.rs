//! Certificate-bound validation of stapled OCSP responses (issue #4300).
//!
//! Ferrum used to accept any non-empty byte string as a stapled OCSP response
//! and attach it to the served `CertifiedKey`. Strict TLS clients abort the
//! handshake when the staple is malformed, expired, not yet valid, signed by an
//! unauthorized responder, or bound to a different certificate, so a config
//! reload or an admin mutation could turn a "loaded successfully" log line into
//! a protocol-wide outage. This module is the single validation path shared by
//! every source (file, inline, provider URI, Kubernetes Secret, managed store)
//! and by both the single-certificate and multi-certificate frontends.
//!
//! # What is enforced
//!
//! 1. **Bounded size.** The DER is rejected before any parsing when it exceeds
//!    [`MAX_OCSP_RESPONSE_BYTES`]. A stapled response is a small object; the
//!    generic TLS material cap ([`crate::tls::source`]) is sized for
//!    certificate bundles and is far too permissive to be the only bound in
//!    front of an ASN.1 parser.
//! 2. **A successful envelope.** `OCSPResponse.responseStatus` must be
//!    `successful(0)` and `responseBytes.responseType` must be
//!    `id-pkix-ocsp-basic`, carrying a `BasicOCSPResponse` (RFC 6960 §4.2.1).
//! 3. **`CertID` binding.** The single response for the configured leaf must
//!    match the leaf serial number and the `issuerNameHash` / `issuerKeyHash`
//!    of the configured issuer, recomputed under the `CertID` hash algorithm.
//!    A response that carries only *other* certificates' entries is rejected as
//!    wrong-certificate data rather than stapled.
//! 4. **Signature and responder authorization.** The `tbsResponseData`
//!    signature is verified against a responder that is either the issuer
//!    itself or a certificate carried in the response that is signed by the
//!    issuer, currently time-valid, and carries the `id-kp-OCSPSigning`
//!    extended key usage (RFC 6960 §4.2.2.2). Delegation to anything else is
//!    refused.
//! 5. **Time bounds.** `thisUpdate` must not be in the future and `nextUpdate`
//!    must not be in the past, each widened by [`OCSP_CLOCK_SKEW`]. A response
//!    without `nextUpdate` has no defined validity window and is refused: RFC
//!    6960 §2.4 makes an absent `nextUpdate` mean "newer information is
//!    available at all times", which is precisely the property a *stapled*
//!    (cached, re-served) response cannot have.
//! 6. **Status.** Only `good` is stapled. `revoked` and `unknown` fail closed:
//!    serving them is strictly worse than serving no staple at all, because a
//!    client that honours the staple will refuse the connection, and a reload
//!    must not be able to publish that state silently.
//!
//! # Clock-skew policy
//!
//! Both time bounds are widened by [`OCSP_CLOCK_SKEW`] (5 minutes) in the
//! permissive direction only. The window Ferrum accepts is therefore
//! `thisUpdate - skew <= now <= nextUpdate + skew`. The skew is deliberately
//! not configurable: it exists to absorb ordinary NTP drift between the
//! responder and the gateway, not to let an operator extend the life of a stale
//! staple, which is what a large configurable value would really be for.
//!
//! # Diagnostics
//!
//! Every error is a short, structural description. No certificate bytes, no
//! response bytes, no key material, and no source URI are interpolated into the
//! message: callers add the already-redacted source identifier themselves.

use std::time::{SystemTime, UNIX_EPOCH};

use rustls::pki_types::CertificateDer;
use x509_parser::asn1_rs::{Any, BitString, Class, Enumerated, FromDer, GeneralizedTime, Oid, Tag};
use x509_parser::certificate::X509Certificate;
use x509_parser::oid_registry::{
    OID_HASH_SHA1, OID_NIST_HASH_SHA256, OID_NIST_HASH_SHA384, OID_NIST_HASH_SHA512,
};
use x509_parser::x509::{AlgorithmIdentifier, SubjectPublicKeyInfo};

use crate::fips::backend::digest;

/// Maximum accepted size of a stapled OCSP response, in bytes.
///
/// Enforced *before* DER parsing. Real responses are a few hundred bytes to a
/// couple of kilobytes even when they embed a delegated responder certificate;
/// 64 KiB leaves generous headroom while keeping an unbounded ASN.1 walk off
/// the reload path.
pub const MAX_OCSP_RESPONSE_BYTES: usize = 64 * 1024;

/// Clock skew allowed on `thisUpdate` and `nextUpdate`, in seconds.
///
/// See the module documentation: permissive in both directions, fixed, and
/// deliberately not operator-tunable.
pub const OCSP_CLOCK_SKEW_SECONDS: i64 = 300;

/// DER content bytes of `id-pkix-ocsp-basic` (1.3.6.1.5.5.7.48.1.1).
const OID_PKIX_OCSP_BASIC_BYTES: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];

/// Outcome of the certificate-independent structural pass.
///
/// This is what the admin boundary can prove about a stored OCSP record before
/// anyone has said which certificate it belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OcspStructure {
    /// Length of the validated DER, in bytes.
    pub der_len: usize,
    /// Number of `SingleResponse` entries in the `BasicOCSPResponse`.
    pub single_responses: usize,
}

/// Outcome of full, certificate-bound validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OcspAcceptance {
    /// Length of the validated DER, in bytes.
    pub der_len: usize,
    /// `thisUpdate` of the matched `SingleResponse`, as a Unix timestamp.
    pub this_update: i64,
    /// `nextUpdate` of the matched `SingleResponse`, as a Unix timestamp.
    pub next_update: i64,
    /// `true` when the response was signed by a delegated responder rather than
    /// by the issuing CA directly.
    pub delegated_responder: bool,
}

/// Current wall-clock time as a Unix timestamp, saturating at the epoch.
fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

/// Reject an over-large response before it reaches the DER parser.
fn enforce_size_bound(der: &[u8]) -> Result<(), String> {
    if der.is_empty() {
        return Err("OCSP response is empty".to_string());
    }
    if der.len() > MAX_OCSP_RESPONSE_BYTES {
        return Err(format!(
            "OCSP response is {} bytes, which exceeds the {MAX_OCSP_RESPONSE_BYTES}-byte maximum",
            der.len()
        ));
    }
    Ok(())
}

/// Parse exactly one DER TLV, returning the object, its complete encoding, and
/// the remaining input.
fn take_tlv(input: &[u8]) -> Result<(Any<'_>, &[u8], &[u8]), String> {
    let (rest, any) = Any::from_der(input).map_err(|error| format!("malformed DER: {error}"))?;
    let consumed = input.len() - rest.len();
    Ok((any, &input[..consumed], rest))
}

/// The context-specific tag number of `any`, or `None` when it is not a
/// context-specific element.
fn context_tag(any: &Any<'_>) -> Option<u32> {
    if any.class() == Class::ContextSpecific {
        Some(any.tag().0)
    } else {
        None
    }
}

/// Parse a context-specific `[n] EXPLICIT` wrapper and return its content.
fn explicit_context<'a>(any: &Any<'a>, tag: u32, field: &str) -> Result<&'a [u8], String> {
    if any.class() != Class::ContextSpecific || any.tag() != Tag(tag) || !any.header.constructed {
        return Err(format!("OCSP {field} is not a constructed [{tag}] element"));
    }
    Ok(any.data)
}

/// A parsed `BasicOCSPResponse`, retaining the byte ranges signature
/// verification needs.
struct BasicResponse<'a> {
    /// Complete DER encoding of `tbsResponseData`, which is what is signed.
    tbs_raw: &'a [u8],
    /// Decoded `ResponseData`.
    response_data: ResponseData<'a>,
    signature_algorithm: AlgorithmIdentifier<'a>,
    signature: BitString<'a>,
    /// DER of each certificate carried in the optional `certs` field.
    certs: Vec<&'a [u8]>,
}

struct ResponseData<'a> {
    responder_id: ResponderId<'a>,
    single_responses: Vec<SingleResponse<'a>>,
}

enum ResponderId<'a> {
    /// Complete DER encoding of the responder's `Name`.
    ByName(&'a [u8]),
    /// SHA-1 hash of the responder's public-key BIT STRING contents.
    ByKey(&'a [u8]),
}

struct SingleResponse<'a> {
    cert_id: CertId<'a>,
    status: CertStatus,
    this_update: i64,
    next_update: Option<i64>,
}

struct CertId<'a> {
    hash_algorithm: Oid<'a>,
    issuer_name_hash: &'a [u8],
    issuer_key_hash: &'a [u8],
    /// Content bytes of the `serialNumber` INTEGER.
    serial_number: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CertStatus {
    Good,
    Revoked,
    Unknown,
}

impl CertStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Good => "good",
            Self::Revoked => "revoked",
            Self::Unknown => "unknown",
        }
    }
}

/// Unwrap `OCSPResponse` and return the `BasicOCSPResponse` DER.
fn basic_response_der(der: &[u8]) -> Result<&[u8], String> {
    let (outer, _, trailing) = take_tlv(der)?;
    if !trailing.is_empty() {
        return Err("OCSP response has trailing bytes after the outer SEQUENCE".to_string());
    }
    if outer.tag() != Tag::Sequence || outer.class() != Class::Universal {
        return Err("OCSP response is not a SEQUENCE".to_string());
    }

    let (status_any, _, rest) = take_tlv(outer.data)?;
    let status = Enumerated::try_from(&status_any)
        .map_err(|_| "OCSP responseStatus is not an ENUMERATED".to_string())?;
    if status.0 != 0 {
        return Err(format!(
            "OCSP responseStatus is {}, not successful(0)",
            response_status_name(status.0)
        ));
    }

    let (bytes_any, _, rest) = take_tlv(rest)
        .map_err(|_| "OCSP response is successful but carries no responseBytes".to_string())?;
    if !rest.is_empty() {
        return Err("OCSP response has trailing fields after responseBytes".to_string());
    }
    let response_bytes = explicit_context(&bytes_any, 0, "responseBytes")?;

    let (bytes_seq, _, trailing) = take_tlv(response_bytes)?;
    if !trailing.is_empty() {
        return Err("OCSP responseBytes has trailing bytes".to_string());
    }
    if bytes_seq.tag() != Tag::Sequence {
        return Err("OCSP responseBytes is not a SEQUENCE".to_string());
    }

    let (type_any, _, rest) = take_tlv(bytes_seq.data)?;
    let response_type = type_any
        .as_oid()
        .map_err(|_| "OCSP responseType is not an OBJECT IDENTIFIER".to_string())?;
    if response_type.as_bytes() != OID_PKIX_OCSP_BASIC_BYTES {
        return Err("OCSP responseType is not id-pkix-ocsp-basic".to_string());
    }

    let (response_any, _, rest) = take_tlv(rest)?;
    if !rest.is_empty() {
        return Err("OCSP responseBytes has trailing fields after response".to_string());
    }
    if response_any.tag() != Tag::OctetString || response_any.header.constructed {
        return Err("OCSP response field is not a primitive OCTET STRING".to_string());
    }
    Ok(response_any.data)
}

fn response_status_name(value: u32) -> &'static str {
    match value {
        1 => "malformedRequest(1)",
        2 => "internalError(2)",
        3 => "tryLater(3)",
        5 => "sigRequired(5)",
        6 => "unauthorized(6)",
        _ => "an unrecognized status",
    }
}

fn parse_basic_response(der: &[u8]) -> Result<BasicResponse<'_>, String> {
    let (basic, _, trailing) = take_tlv(der)?;
    if !trailing.is_empty() {
        return Err("BasicOCSPResponse has trailing bytes".to_string());
    }
    if basic.tag() != Tag::Sequence {
        return Err("BasicOCSPResponse is not a SEQUENCE".to_string());
    }

    let (tbs_any, tbs_raw, rest) = take_tlv(basic.data)?;
    if tbs_any.tag() != Tag::Sequence {
        return Err("OCSP tbsResponseData is not a SEQUENCE".to_string());
    }
    let response_data = parse_response_data(tbs_any.data)?;

    let (rest, signature_algorithm) = AlgorithmIdentifier::from_der(rest)
        .map_err(|_| "OCSP signatureAlgorithm is malformed".to_string())?;

    let (signature_any, _, rest) = take_tlv(rest)?;
    let signature = BitString::try_from(&signature_any)
        .map_err(|_| "OCSP signature is not a BIT STRING".to_string())?;

    let mut certs = Vec::new();
    if !rest.is_empty() {
        let (certs_any, _, trailing) = take_tlv(rest)?;
        if !trailing.is_empty() {
            return Err("BasicOCSPResponse has trailing fields after certs".to_string());
        }
        let certs_content = explicit_context(&certs_any, 0, "certs")?;
        let (certs_seq, _, trailing) = take_tlv(certs_content)?;
        if !trailing.is_empty() {
            return Err("OCSP certs has trailing bytes".to_string());
        }
        if certs_seq.tag() != Tag::Sequence {
            return Err("OCSP certs is not a SEQUENCE".to_string());
        }
        let mut cursor = certs_seq.data;
        while !cursor.is_empty() {
            let (_, raw, rest) = take_tlv(cursor)?;
            certs.push(raw);
            cursor = rest;
            if certs.len() > MAX_RESPONDER_CERTS {
                return Err(format!(
                    "OCSP response carries more than {MAX_RESPONDER_CERTS} responder certificates"
                ));
            }
        }
    }

    Ok(BasicResponse {
        tbs_raw,
        response_data,
        signature_algorithm,
        signature,
        certs,
    })
}

/// Bound on the certificates a response may carry, and on the `SingleResponse`
/// entries it may contain. Both are walked linearly, so both need a ceiling
/// that does not depend on the (already bounded) byte length alone.
const MAX_RESPONDER_CERTS: usize = 16;
const MAX_SINGLE_RESPONSES: usize = 64;

fn parse_response_data(input: &[u8]) -> Result<ResponseData<'_>, String> {
    let (first, _, rest) = take_tlv(input)?;

    // version [0] EXPLICIT Version DEFAULT v1
    let carries_version = context_tag(&first) == Some(0);
    let (responder_any, rest) = if carries_version {
        let version_content = explicit_context(&first, 0, "version")?;
        let (version_any, _, trailing) = take_tlv(version_content)?;
        if !trailing.is_empty() {
            return Err("OCSP version has trailing bytes".to_string());
        }
        let version = version_any
            .as_u32()
            .map_err(|_| "OCSP version is not an INTEGER".to_string())?;
        if version != 0 {
            return Err(format!(
                "OCSP response declares unsupported version {version}"
            ));
        }
        let (responder_any, _, rest) = take_tlv(rest)?;
        (responder_any, rest)
    } else {
        (first, rest)
    };

    let responder_id = match context_tag(&responder_any) {
        Some(1) => {
            let content = explicit_context(&responder_any, 1, "responderID")?;
            let (name_any, name_raw, trailing) = take_tlv(content)?;
            if !trailing.is_empty() {
                return Err("OCSP responderID byName has trailing bytes".to_string());
            }
            if name_any.tag() != Tag::Sequence {
                return Err("OCSP responderID byName is not a Name SEQUENCE".to_string());
            }
            ResponderId::ByName(name_raw)
        }
        Some(2) => {
            let content = explicit_context(&responder_any, 2, "responderID")?;
            let (hash_any, _, trailing) = take_tlv(content)?;
            if !trailing.is_empty() {
                return Err("OCSP responderID byKey has trailing bytes".to_string());
            }
            if hash_any.tag() != Tag::OctetString {
                return Err("OCSP responderID byKey is not an OCTET STRING".to_string());
            }
            ResponderId::ByKey(hash_any.data)
        }
        _ => {
            return Err("OCSP responderID is neither byName [1] nor byKey [2]".to_string());
        }
    };

    // producedAt GeneralizedTime — parsed for well-formedness only; the serving
    // decision is made from thisUpdate/nextUpdate.
    let (produced_any, _, rest) = take_tlv(rest)?;
    if produced_any.tag() != Tag::GeneralizedTime {
        return Err("OCSP producedAt is not a GeneralizedTime".to_string());
    }

    let (responses_any, _, _rest) = take_tlv(rest)?;
    if responses_any.tag() != Tag::Sequence {
        return Err("OCSP responses is not a SEQUENCE".to_string());
    }

    let mut single_responses = Vec::new();
    let mut cursor = responses_any.data;
    while !cursor.is_empty() {
        let (single_any, _, next) = take_tlv(cursor)?;
        if single_any.tag() != Tag::Sequence {
            return Err("OCSP SingleResponse is not a SEQUENCE".to_string());
        }
        single_responses.push(parse_single_response(single_any.data)?);
        cursor = next;
        if single_responses.len() > MAX_SINGLE_RESPONSES {
            return Err(format!(
                "OCSP response carries more than {MAX_SINGLE_RESPONSES} SingleResponse entries"
            ));
        }
    }
    if single_responses.is_empty() {
        return Err("OCSP response carries no SingleResponse entries".to_string());
    }

    Ok(ResponseData {
        responder_id,
        single_responses,
    })
}

fn parse_single_response(input: &[u8]) -> Result<SingleResponse<'_>, String> {
    let (cert_id_any, _, rest) = take_tlv(input)?;
    if cert_id_any.tag() != Tag::Sequence {
        return Err("OCSP CertID is not a SEQUENCE".to_string());
    }
    let cert_id = parse_cert_id(cert_id_any.data)?;

    let (status_any, _, rest) = take_tlv(rest)?;
    let status = match context_tag(&status_any) {
        Some(0) => CertStatus::Good,
        Some(1) => CertStatus::Revoked,
        Some(2) => CertStatus::Unknown,
        Some(_) => {
            return Err("OCSP certStatus uses an unrecognized alternative".to_string());
        }
        None => {
            return Err("OCSP certStatus is not a context-specific CHOICE".to_string());
        }
    };

    let (this_update_any, this_update_raw, rest) = take_tlv(rest)?;
    if this_update_any.tag() != Tag::GeneralizedTime {
        return Err("OCSP thisUpdate is not a GeneralizedTime".to_string());
    }
    let this_update = generalized_time_unix(this_update_raw, "thisUpdate")?;

    let mut next_update = None;
    let mut cursor = rest;
    while !cursor.is_empty() {
        let (field, _, next) = take_tlv(cursor)?;
        if context_tag(&field) == Some(0) {
            let content = explicit_context(&field, 0, "nextUpdate")?;
            let (time_any, time_raw, trailing) = take_tlv(content)?;
            if !trailing.is_empty() {
                return Err("OCSP nextUpdate has trailing bytes".to_string());
            }
            if time_any.tag() != Tag::GeneralizedTime {
                return Err("OCSP nextUpdate is not a GeneralizedTime".to_string());
            }
            next_update = Some(generalized_time_unix(time_raw, "nextUpdate")?);
        }
        cursor = next;
    }

    Ok(SingleResponse {
        cert_id,
        status,
        this_update,
        next_update,
    })
}

fn parse_cert_id(input: &[u8]) -> Result<CertId<'_>, String> {
    let (rest, hash_algorithm) = AlgorithmIdentifier::from_der(input)
        .map_err(|_| "OCSP CertID hashAlgorithm is malformed".to_string())?;

    let (name_hash_any, _, rest) = take_tlv(rest)?;
    if name_hash_any.tag() != Tag::OctetString {
        return Err("OCSP CertID issuerNameHash is not an OCTET STRING".to_string());
    }
    let (key_hash_any, _, rest) = take_tlv(rest)?;
    if key_hash_any.tag() != Tag::OctetString {
        return Err("OCSP CertID issuerKeyHash is not an OCTET STRING".to_string());
    }
    let (serial_any, _, trailing) = take_tlv(rest)?;
    if serial_any.tag() != Tag::Integer {
        return Err("OCSP CertID serialNumber is not an INTEGER".to_string());
    }
    if !trailing.is_empty() {
        return Err("OCSP CertID has trailing fields".to_string());
    }

    Ok(CertId {
        hash_algorithm: hash_algorithm.algorithm,
        issuer_name_hash: name_hash_any.data,
        issuer_key_hash: key_hash_any.data,
        serial_number: serial_any.data,
    })
}

fn generalized_time_unix(raw: &[u8], field: &str) -> Result<i64, String> {
    let (_, time) = GeneralizedTime::from_der(raw)
        .map_err(|_| format!("OCSP {field} is not a valid GeneralizedTime"))?;
    let datetime = time
        .utc_datetime()
        .map_err(|_| format!("OCSP {field} is not a representable instant"))?;
    Ok(datetime.unix_timestamp())
}

/// Bounded, certificate-independent structural validation.
///
/// This is what the admin boundary can prove about stored OCSP bytes before any
/// certificate context exists: the size bound, a successful basic envelope, and
/// a well-formed `BasicOCSPResponse` with at least one `SingleResponse`. It is
/// deliberately *not* sufficient to serve: activation always re-validates
/// through [`validate_stapled_response`] against the leaf and issuer actually
/// configured.
pub fn validate_structure(der: &[u8]) -> Result<OcspStructure, String> {
    enforce_size_bound(der)?;
    let basic_der = basic_response_der(der)?;
    let basic = parse_basic_response(basic_der)?;
    Ok(OcspStructure {
        der_len: der.len(),
        single_responses: basic.response_data.single_responses.len(),
    })
}

/// Full, certificate-bound validation against the chain that will be served.
///
/// `chain` is leaf-first, exactly as it is handed to rustls. The issuer is the
/// chain member whose subject matches the leaf's issuer; a self-issued leaf is
/// its own issuer. When neither holds, the response cannot be bound to anything
/// and is refused — an operator stapling a response must publish the issuer in
/// the served chain, which is what an OCSP-checking client needs anyway.
pub fn validate_stapled_response(
    der: &[u8],
    chain: &[CertificateDer<'_>],
) -> Result<OcspAcceptance, String> {
    validate_stapled_response_at(der, chain, now_unix())
}

/// [`validate_stapled_response`] with an explicit evaluation instant.
pub fn validate_stapled_response_at(
    der: &[u8],
    chain: &[CertificateDer<'_>],
    now: i64,
) -> Result<OcspAcceptance, String> {
    enforce_size_bound(der)?;

    let leaf_der = chain
        .first()
        .ok_or_else(|| "cannot validate an OCSP response against an empty chain".to_string())?;
    let (_, leaf) = X509Certificate::from_der(leaf_der.as_ref())
        .map_err(|_| "server certificate is not parseable X.509 DER".to_string())?;

    let issuer_der = select_issuer_der(&leaf, chain)?;
    let (_, issuer) = X509Certificate::from_der(issuer_der)
        .map_err(|_| "issuer certificate is not parseable X.509 DER".to_string())?;

    let basic_der = basic_response_der(der)?;
    let basic = parse_basic_response(basic_der)?;

    let single = match_single_response(&basic, &leaf, &issuer)?;

    let delegated_responder = verify_signature_and_authorization(&basic, issuer_der, &issuer, now)?;

    match single.status {
        CertStatus::Good => {}
        status => {
            return Err(format!(
                "OCSP response reports certStatus {} for the configured certificate",
                status.as_str()
            ));
        }
    }

    let Some(next_update) = single.next_update else {
        let message = "OCSP response omits nextUpdate, so it has no validity window and cannot \
                       be stapled";
        return Err(message.to_string());
    };
    if next_update <= single.this_update {
        return Err("OCSP nextUpdate is not after thisUpdate".to_string());
    }
    if single.this_update > now.saturating_add(OCSP_CLOCK_SKEW_SECONDS) {
        return Err(format!(
            "OCSP thisUpdate is {} seconds in the future, beyond the {OCSP_CLOCK_SKEW_SECONDS}-second skew allowance",
            single.this_update.saturating_sub(now)
        ));
    }
    if next_update < now.saturating_sub(OCSP_CLOCK_SKEW_SECONDS) {
        return Err(format!(
            "OCSP nextUpdate expired {} seconds ago, beyond the {OCSP_CLOCK_SKEW_SECONDS}-second skew allowance",
            now.saturating_sub(next_update)
        ));
    }

    Ok(OcspAcceptance {
        der_len: der.len(),
        this_update: single.this_update,
        next_update,
        delegated_responder,
    })
}

/// Locate the issuer of `leaf` inside the served chain.
fn select_issuer_der<'a>(
    leaf: &X509Certificate<'_>,
    chain: &'a [CertificateDer<'_>],
) -> Result<&'a [u8], String> {
    let leaf_issuer = leaf.issuer().as_raw();
    for candidate in chain.iter().skip(1) {
        let Ok((_, parsed)) = X509Certificate::from_der(candidate.as_ref()) else {
            continue;
        };
        if parsed.subject().as_raw() == leaf_issuer {
            return Ok(candidate.as_ref());
        }
    }
    // A self-issued leaf is its own issuer; this is the ordinary shape for the
    // self-signed certificates used in tests and single-node deployments.
    if leaf.subject().as_raw() == leaf_issuer {
        return Ok(chain[0].as_ref());
    }
    let message = "the served certificate chain does not contain the leaf's issuer, so a stapled \
                   OCSP response cannot be bound to it";
    Err(message.to_string())
}

/// Find the `SingleResponse` whose `CertID` names the configured leaf.
fn match_single_response<'a, 'b>(
    basic: &'a BasicResponse<'b>,
    leaf: &X509Certificate<'_>,
    issuer: &X509Certificate<'_>,
) -> Result<&'a SingleResponse<'b>, String> {
    let leaf_serial = normalize_serial(leaf.raw_serial());
    let issuer_name = issuer.subject().as_raw();
    let issuer_key = issuer.public_key().subject_public_key.data.as_ref();

    let mut serial_matched = false;
    for single in &basic.response_data.single_responses {
        if normalize_serial(single.cert_id.serial_number) != leaf_serial {
            continue;
        }
        serial_matched = true;
        let algorithm = cert_id_digest(&single.cert_id.hash_algorithm)?;
        if digest::digest(algorithm, issuer_name).as_ref() != single.cert_id.issuer_name_hash {
            continue;
        }
        if digest::digest(algorithm, issuer_key).as_ref() != single.cert_id.issuer_key_hash {
            continue;
        }
        return Ok(single);
    }

    let message = if serial_matched {
        "OCSP response CertID matches the certificate serial but not the configured issuer \
         name/key, so it was issued for a different certificate"
    } else {
        "OCSP response contains no entry for the configured certificate's serial number"
    };
    Err(message.to_string())
}

/// Strip the leading zero padding DER uses to keep an INTEGER positive, so two
/// encodings of the same serial compare equal.
fn normalize_serial(raw: &[u8]) -> &[u8] {
    let mut trimmed = raw;
    while trimmed.len() > 1 && trimmed[0] == 0 {
        trimmed = &trimmed[1..];
    }
    trimmed
}

fn cert_id_digest(oid: &Oid<'_>) -> Result<&'static digest::Algorithm, String> {
    if *oid == OID_HASH_SHA1 {
        Ok(&digest::SHA1_FOR_LEGACY_USE_ONLY)
    } else if *oid == OID_NIST_HASH_SHA256 {
        Ok(&digest::SHA256)
    } else if *oid == OID_NIST_HASH_SHA384 {
        Ok(&digest::SHA384)
    } else if *oid == OID_NIST_HASH_SHA512 {
        Ok(&digest::SHA512)
    } else {
        Err("OCSP CertID uses an unsupported hash algorithm".to_string())
    }
}

/// Verify the `BasicOCSPResponse` signature against an authorized responder.
///
/// Returns `true` when a delegated responder certificate was used.
fn verify_signature_and_authorization(
    basic: &BasicResponse<'_>,
    issuer_der: &[u8],
    issuer: &X509Certificate<'_>,
    now: i64,
) -> Result<bool, String> {
    let issuer_key = issuer.public_key();

    // The issuing CA signing its own responses is the common case, and is
    // authorized by construction.
    if responder_matches(&basic.response_data.responder_id, issuer)
        && verify_basic_signature(basic, issuer_key).is_ok()
    {
        return Ok(false);
    }

    let mut saw_named_delegate = false;
    for candidate_der in &basic.certs {
        // A carried copy of the issuer is not a delegation; it was already
        // tried above, and re-trying it here would report it as delegated.
        if *candidate_der == issuer_der {
            continue;
        }
        let Ok((_, candidate)) = X509Certificate::from_der(candidate_der) else {
            continue;
        };
        if !responder_matches(&basic.response_data.responder_id, &candidate) {
            continue;
        }
        saw_named_delegate = true;

        // RFC 6960 §4.2.2.2: a delegated responder must be issued by the same
        // CA as the certificate being checked and must carry id-kp-OCSPSigning.
        if candidate.issuer().as_raw() != issuer.subject().as_raw() {
            continue;
        }
        let has_ocsp_signing = candidate
            .extended_key_usage()
            .ok()
            .flatten()
            .is_some_and(|eku| eku.value.ocsp_signing);
        if !has_ocsp_signing {
            continue;
        }
        if candidate.verify_signature(Some(issuer_key)).is_err() {
            continue;
        }
        let validity = candidate.validity();
        if now.saturating_add(OCSP_CLOCK_SKEW_SECONDS) < validity.not_before.timestamp()
            || now.saturating_sub(OCSP_CLOCK_SKEW_SECONDS) > validity.not_after.timestamp()
        {
            continue;
        }
        if verify_basic_signature(basic, candidate.public_key()).is_ok() {
            return Ok(true);
        }
    }

    let message = if saw_named_delegate {
        "OCSP response was signed by a responder that is not authorized for this issuer: it is \
         not the issuing CA and no carried certificate is an issuer-signed, currently valid \
         id-kp-OCSPSigning delegate whose signature verifies"
    } else {
        "OCSP response signature could not be verified against the configured issuer and the \
         response carries no matching authorized responder certificate"
    };
    Err(message.to_string())
}

fn responder_matches(responder_id: &ResponderId<'_>, candidate: &X509Certificate<'_>) -> bool {
    match responder_id {
        ResponderId::ByName(name) => candidate.subject().as_raw() == *name,
        ResponderId::ByKey(key_hash) => {
            let key = candidate.public_key().subject_public_key.data.as_ref();
            let hash = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, key);
            hash.as_ref() == *key_hash
        }
    }
}

fn verify_basic_signature(
    basic: &BasicResponse<'_>,
    public_key: &SubjectPublicKeyInfo<'_>,
) -> Result<(), String> {
    x509_parser::verify::verify_signature(
        public_key,
        &basic.signature_algorithm,
        &basic.signature,
        basic.tbs_raw,
    )
    .map_err(|error| format!("OCSP signature verification failed: {error}"))
}
