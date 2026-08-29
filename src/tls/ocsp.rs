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
//! 3. **A fully consumed grammar.** `ResponseData` and each `SingleResponse`
//!    are parsed to their last byte. Every optional field must appear at most
//!    once, in its defined position; unknown, duplicate, misordered, or
//!    trailing elements are refused rather than skipped, because a field this
//!    parser ignores is still inside the bytes the responder signed. Every
//!    `GeneralizedTime` is decoded, not merely tagged. An `Extensions`
//!    container is parsed structurally and must not repeat an extension OID,
//!    and because Ferrum implements no OCSP response extension, a *critical*
//!    one is refused (RFC 6960 §4.4); a non-critical one is ignored after that
//!    strict parse.
//! 4. **A strict DER encoding, not merely a plausible one.** Every field
//!    boundary checks the ASN.1 *class* and the primitive/constructed bit as
//!    well as the tag number, so a context-specific element that reuses a
//!    universal tag number, a primitive "SEQUENCE", or a constructed OCTET
//!    STRING is refused instead of being decoded as the field it imitates.
//!    `ResponseData.version` must be absent: DER omits a `DEFAULT` value, so an
//!    explicit `[0] INTEGER 0` would be a second encoding of one signed object,
//!    and any other version is unsupported. Every certificate carried in
//!    `certs` must parse as one complete X.509 `Certificate` with nothing left
//!    over — a malformed entry is refused even when a *different* carried
//!    certificate would have authorized the response.
//! 5. **A proven issuer.** The issuer is the chain member whose key actually
//!    signed the leaf, not merely one whose subject name matches the leaf's
//!    issuer name; same-name candidates are scanned until one verifies, and a
//!    self-issued leaf must be genuinely self-signed. This is what makes RFC
//!    6960's "CA that issued the certificate" explicit, and it is the same key
//!    a delegated responder must chain to.
//! 6. **`CertID` binding.** The single response for the configured leaf must
//!    match the leaf serial number and the `issuerNameHash` / `issuerKeyHash`
//!    of the configured issuer, recomputed under the `CertID` hash algorithm.
//!    A response that carries only *other* certificates' entries is rejected as
//!    wrong-certificate data rather than stapled, and a response carrying more
//!    than one entry for that certificate is rejected as ambiguous: a strict
//!    client re-derives the `CertID` itself and might select the other one.
//! 7. **Signature and responder authorization.** The `tbsResponseData`
//!    signature is verified against a responder that is either the issuer
//!    itself or a certificate carried in the response that is signed by the
//!    issuer, currently time-valid, carries the `id-kp-OCSPSigning` extended
//!    key usage (RFC 6960 §4.2.2.2), and — when it carries a `KeyUsage` at all
//!    — permits `digitalSignature`. Delegation to anything else is refused.
//! 8. **Time bounds.** `thisUpdate` must not be in the future and `nextUpdate`
//!    must not be in the past, each widened by [`OCSP_CLOCK_SKEW`]. A response
//!    without `nextUpdate` has no defined validity window and is refused: RFC
//!    6960 §2.4 makes an absent `nextUpdate` mean "newer information is
//!    available at all times", which is precisely the property a *stapled*
//!    (cached, re-served) response cannot have.
//! 9. **Status.** Only `good` is stapled. `revoked` and `unknown` fail closed:
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
    if any.class() != Class::ContextSpecific || any.tag() != Tag(tag) || !any.header.constructed() {
        return Err(format!("OCSP {field} is not a constructed [{tag}] element"));
    }
    Ok(any.data)
}

/// Require a universal, constructed SEQUENCE and return its content bytes.
///
/// `Any` keeps the tag *number* separate from the class and the
/// primitive/constructed bit, so comparing `tag()` alone would admit a
/// context-specific element that happens to reuse tag number 16 as well as a
/// primitive "SEQUENCE" that DER does not allow at all. Every SEQUENCE
/// boundary in this module goes through this helper so the audit is complete
/// by construction rather than by inspection.
fn expect_sequence<'a>(any: &Any<'a>, field: &str) -> Result<&'a [u8], String> {
    if any.class() != Class::Universal || any.tag() != Tag::Sequence || !any.header.constructed() {
        return Err(format!("OCSP {field} is not a SEQUENCE"));
    }
    Ok(any.data)
}

/// Name of a universal tag, for diagnostics only.
fn tag_name(tag: Tag) -> &'static str {
    if tag == Tag::Boolean {
        "BOOLEAN"
    } else if tag == Tag::Integer {
        "INTEGER"
    } else if tag == Tag::BitString {
        "BIT STRING"
    } else if tag == Tag::OctetString {
        "OCTET STRING"
    } else if tag == Tag::Oid {
        "OBJECT IDENTIFIER"
    } else if tag == Tag::Enumerated {
        "ENUMERATED"
    } else if tag == Tag::GeneralizedTime {
        "GeneralizedTime"
    } else {
        "element"
    }
}

/// Require a universal, primitive element carrying `tag` and return its content
/// bytes.
///
/// The counterpart of [`expect_sequence`] for the leaf types this grammar uses:
/// a constructed OCTET STRING, a context-specific element reusing a universal
/// tag number, or an INTEGER that is really a constructed impostor is refused
/// here rather than silently decoded.
fn expect_primitive<'a>(any: &Any<'a>, tag: Tag, field: &str) -> Result<&'a [u8], String> {
    if any.class() != Class::Universal || any.tag() != tag || any.header.constructed() {
        return Err(format!("OCSP {field} is not a primitive {}", tag_name(tag)));
    }
    Ok(any.data)
}

/// Require a universal, primitive `GeneralizedTime` and decode it.
///
/// Every instant in this grammar is both tag-checked and *decoded*: an
/// unparseable instant is a malformed response even when the serving decision
/// does not read that particular field.
fn expect_generalized_time(any: &Any<'_>, raw: &[u8], field: &str) -> Result<i64, String> {
    if any.class() != Class::Universal
        || any.tag() != Tag::GeneralizedTime
        || any.header.constructed()
    {
        return Err(format!("OCSP {field} is not a GeneralizedTime"));
    }
    generalized_time_unix(raw, field)
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
    let outer_content = expect_sequence(&outer, "response")?;

    let (status_any, _, rest) = take_tlv(outer_content)?;
    expect_primitive(&status_any, Tag::Enumerated, "responseStatus")?;
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
    let bytes_seq_content = expect_sequence(&bytes_seq, "responseBytes")?;

    let (type_any, _, rest) = take_tlv(bytes_seq_content)?;
    expect_primitive(&type_any, Tag::Oid, "responseType")?;
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
    expect_primitive(&response_any, Tag::OctetString, "response field")
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
    let basic_content = expect_sequence(&basic, "BasicOCSPResponse")?;

    let (tbs_any, tbs_raw, rest) = take_tlv(basic_content)?;
    let tbs_content = expect_sequence(&tbs_any, "tbsResponseData")?;
    let response_data = parse_response_data(tbs_content)?;

    let (rest, signature_algorithm) = AlgorithmIdentifier::from_der(rest)
        .map_err(|_| "OCSP signatureAlgorithm is malformed".to_string())?;

    let (signature_any, _, rest) = take_tlv(rest)?;
    expect_primitive(&signature_any, Tag::BitString, "signature")?;
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
        let certs_seq_content = expect_sequence(&certs_seq, "certs")?;
        let mut cursor = certs_seq_content;
        while !cursor.is_empty() {
            let (cert_any, raw, rest) = take_tlv(cursor)?;
            cursor = rest;
            if certs.len() == MAX_RESPONDER_CERTS {
                return Err(format!(
                    "OCSP response carries more than {MAX_RESPONDER_CERTS} responder certificates"
                ));
            }
            // `certs` is `SEQUENCE OF Certificate`, so structural admission has
            // to prove every carried entry really is one complete X.509
            // certificate. Recording an arbitrary TLV here and skipping the
            // unparseable ones at authorization time would fail open twice
            // over: a response whose bytes this parser cannot account for would
            // still be admitted by the admin boundary, and it could still be
            // authorized as long as some *other* carried certificate verified.
            expect_sequence(&cert_any, "certs entry")?;
            let (trailing, _) = X509Certificate::from_der(raw).map_err(|_| {
                "OCSP certs carries an entry that is not a parseable X.509 certificate".to_string()
            })?;
            if !trailing.is_empty() {
                return Err(
                    "OCSP certs carries a certificate with trailing bytes after its encoding"
                        .to_string(),
                );
            }
            certs.push(raw);
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
    //
    // DER forbids encoding a DEFAULT value, so a conformant `ResponseData`
    // omits this field entirely: v1 must be absent, and every other version is
    // unsupported. Accepting an explicit `[0] INTEGER 0` would give one
    // response two valid-looking encodings under a single signature, which is
    // exactly the ambiguity a strict client would resolve differently.
    if context_tag(&first) == Some(0) {
        let version_content = explicit_context(&first, 0, "version")?;
        let (version_any, _, trailing) = take_tlv(version_content)?;
        if !trailing.is_empty() {
            return Err("OCSP version has trailing bytes".to_string());
        }
        expect_primitive(&version_any, Tag::Integer, "version")?;
        let version = version_any
            .as_u32()
            .map_err(|_| "OCSP version is not an INTEGER".to_string())?;
        if version == 0 {
            return Err(
                "OCSP ResponseData encodes version v1 explicitly, but DER omits a DEFAULT value"
                    .to_string(),
            );
        }
        return Err(format!(
            "OCSP response declares unsupported version {version}"
        ));
    }
    let responder_any = first;

    let responder_id = match context_tag(&responder_any) {
        Some(1) => {
            let content = explicit_context(&responder_any, 1, "responderID")?;
            let (name_any, name_raw, trailing) = take_tlv(content)?;
            if !trailing.is_empty() {
                return Err("OCSP responderID byName has trailing bytes".to_string());
            }
            expect_sequence(&name_any, "responderID byName Name")?;
            ResponderId::ByName(name_raw)
        }
        Some(2) => {
            let content = explicit_context(&responder_any, 2, "responderID")?;
            let (hash_any, _, trailing) = take_tlv(content)?;
            if !trailing.is_empty() {
                return Err("OCSP responderID byKey has trailing bytes".to_string());
            }
            let hash = expect_primitive(&hash_any, Tag::OctetString, "responderID byKey")?;
            ResponderId::ByKey(hash)
        }
        _ => {
            return Err("OCSP responderID is neither byName [1] nor byKey [2]".to_string());
        }
    };

    // producedAt GeneralizedTime. The value is decoded, not merely tagged: an
    // unparseable instant is a malformed response even though the serving
    // decision itself is made from thisUpdate/nextUpdate.
    let (produced_any, produced_raw, rest) = take_tlv(rest)?;
    expect_generalized_time(&produced_any, produced_raw, "producedAt")?;

    let (responses_any, _, rest) = take_tlv(rest)?;
    let responses_content = expect_sequence(&responses_any, "responses")?;

    let mut single_responses = Vec::new();
    let mut cursor = responses_content;
    while !cursor.is_empty() {
        let (single_any, _, next) = take_tlv(cursor)?;
        let single_content = expect_sequence(&single_any, "SingleResponse")?;
        single_responses.push(parse_single_response(single_content)?);
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

    // responseExtensions [1] EXPLICIT Extensions OPTIONAL is the only field the
    // grammar allows after `responses`, at most once. Anything else — an
    // unknown context tag, a second [1], or a stray universal element — means
    // the encoder and this parser disagree about what was signed, so it is
    // refused rather than skipped.
    if !rest.is_empty() {
        let (extensions_any, _, trailing) = take_tlv(rest)?;
        if context_tag(&extensions_any) != Some(1) {
            return Err(
                "OCSP tbsResponseData carries an unexpected field after responses".to_string(),
            );
        }
        if !trailing.is_empty() {
            return Err(
                "OCSP tbsResponseData has trailing fields after responseExtensions".to_string(),
            );
        }
        let content = explicit_context(&extensions_any, 1, "responseExtensions")?;
        validate_extensions(content, "responseExtensions")?;
    }

    Ok(ResponseData {
        responder_id,
        single_responses,
    })
}

fn parse_single_response(input: &[u8]) -> Result<SingleResponse<'_>, String> {
    let (cert_id_any, _, rest) = take_tlv(input)?;
    let cert_id_content = expect_sequence(&cert_id_any, "CertID")?;
    let cert_id = parse_cert_id(cert_id_content)?;

    let (status_any, _, rest) = take_tlv(rest)?;
    let status = parse_cert_status(&status_any)?;

    let (this_update_any, this_update_raw, rest) = take_tlv(rest)?;
    let this_update = expect_generalized_time(&this_update_any, this_update_raw, "thisUpdate")?;

    // The remaining grammar is exactly `[0] nextUpdate OPTIONAL` followed by
    // `[1] singleExtensions OPTIONAL`, each at most once and in that order. A
    // permissive loop here would let a second `[0]` silently overwrite the
    // validity window the signature was meant to bind.
    let mut next_update = None;
    let mut cursor = rest;
    if !cursor.is_empty() {
        let (field, _, next) = take_tlv(cursor)?;
        if context_tag(&field) == Some(0) {
            let content = explicit_context(&field, 0, "nextUpdate")?;
            let (time_any, time_raw, trailing) = take_tlv(content)?;
            if !trailing.is_empty() {
                return Err("OCSP nextUpdate has trailing bytes".to_string());
            }
            next_update = Some(expect_generalized_time(&time_any, time_raw, "nextUpdate")?);
            cursor = next;
        }
    }
    if !cursor.is_empty() {
        let (field, _, next) = take_tlv(cursor)?;
        if context_tag(&field) != Some(1) {
            return Err(
                "OCSP SingleResponse carries an unexpected field after thisUpdate".to_string(),
            );
        }
        let content = explicit_context(&field, 1, "singleExtensions")?;
        validate_extensions(content, "singleExtensions")?;
        cursor = next;
    }
    if !cursor.is_empty() {
        return Err("OCSP SingleResponse has trailing fields after singleExtensions".to_string());
    }

    Ok(SingleResponse {
        cert_id,
        status,
        this_update,
        next_update,
    })
}

/// Validate the `CertStatus` CHOICE encoding, not merely its context tag.
///
/// ```text
/// CertStatus ::= CHOICE {
///     good    [0] IMPLICIT NULL,
///     revoked [1] IMPLICIT RevokedInfo,
///     unknown [2] IMPLICIT UnknownInfo }
/// ```
///
/// `UnknownInfo` is `NULL`, so both `good` and `unknown` are primitive and
/// empty. `revoked` is a constructed `RevokedInfo`. `revoked` and `unknown` are
/// refused later by serving policy, but a malformed encoding of either is a
/// structural failure that must be reported as such: a strict client parses the
/// same bytes, and Ferrum must not admit an entry it cannot fully account for.
fn parse_cert_status(any: &Any<'_>) -> Result<CertStatus, String> {
    let Some(tag) = context_tag(any) else {
        return Err("OCSP certStatus is not a context-specific CHOICE".to_string());
    };
    match tag {
        0 | 2 => {
            let (name, status) = if tag == 0 {
                ("good", CertStatus::Good)
            } else {
                ("unknown", CertStatus::Unknown)
            };
            if any.header.constructed() {
                return Err(format!(
                    "OCSP certStatus {name} is constructed, but it is an IMPLICIT NULL"
                ));
            }
            if !any.data.is_empty() {
                return Err(format!(
                    "OCSP certStatus {name} carries content, but it is an IMPLICIT NULL"
                ));
            }
            Ok(status)
        }
        1 => {
            if !any.header.constructed() {
                return Err("OCSP certStatus revoked is primitive, not a SEQUENCE".to_string());
            }
            parse_revoked_info(any.data)?;
            Ok(CertStatus::Revoked)
        }
        _ => Err("OCSP certStatus uses an unrecognized alternative".to_string()),
    }
}

/// Validate `RevokedInfo ::= SEQUENCE { revocationTime GeneralizedTime,
/// revocationReason [0] EXPLICIT CRLReason OPTIONAL }`.
fn parse_revoked_info(input: &[u8]) -> Result<(), String> {
    let (time_any, time_raw, rest) = take_tlv(input)?;
    expect_generalized_time(&time_any, time_raw, "revocationTime")?;

    if rest.is_empty() {
        return Ok(());
    }
    let (reason_any, _, trailing) = take_tlv(rest)?;
    if !trailing.is_empty() {
        return Err("OCSP RevokedInfo has trailing fields after revocationReason".to_string());
    }
    let content = explicit_context(&reason_any, 0, "revocationReason")?;
    let (value_any, _, trailing) = take_tlv(content)?;
    if !trailing.is_empty() {
        return Err("OCSP revocationReason has trailing bytes".to_string());
    }
    expect_primitive(&value_any, Tag::Enumerated, "revocationReason")?;
    Ok(())
}

/// Bound on the entries one `Extensions` container may carry.
const MAX_EXTENSIONS: usize = 32;

/// Diagnostic for an `Extension` whose `extnID` is not an OID.
fn oid_error(field: &str) -> String {
    format!("OCSP {field} extnID is not an OBJECT IDENTIFIER")
}

/// Decode the `critical` flag of an `Extension`.
///
/// DER omits a `DEFAULT` value, so an encoded `FALSE` is not DER at all: it
/// would let the same extension be encoded two ways under one signature.
fn der_critical_flag(any: &Any<'_>, field: &str) -> Result<bool, String> {
    if any.header.constructed() || any.data.len() != 1 {
        return Err(format!("OCSP {field} critical flag is not a DER BOOLEAN"));
    }
    match any.data[0] {
        0xff => Ok(true),
        0x00 => Err(format!(
            "OCSP {field} encodes critical DEFAULT FALSE, which DER omits"
        )),
        _ => Err(format!("OCSP {field} critical flag is not a DER BOOLEAN")),
    }
}

/// Structurally validate an `Extensions` container and enforce RFC 6960 §4.4
/// criticality.
///
/// ```text
/// Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension
/// Extension  ::= SEQUENCE { extnID OBJECT IDENTIFIER,
///                           critical BOOLEAN DEFAULT FALSE,
///                           extnValue OCTET STRING }
/// ```
///
/// Ferrum implements no OCSP response extension, so a *critical* extension is
/// by definition one it cannot process and must not admit; a non-critical one
/// is ignored, but only after it has been parsed strictly enough to prove the
/// container really is an `Extensions` and nothing else is hiding inside the
/// signed bytes.
fn validate_extensions(content: &[u8], field: &str) -> Result<(), String> {
    let (container, _, trailing) = take_tlv(content)?;
    if !trailing.is_empty() {
        return Err(format!("OCSP {field} has trailing bytes"));
    }
    let container_content = expect_sequence(&container, field)?;
    if container_content.is_empty() {
        return Err(format!("OCSP {field} is an empty SEQUENCE"));
    }

    let mut cursor = container_content;
    let mut seen = 0usize;
    // X.509 forbids repeating one extension type inside an `Extensions`
    // container. Ferrum ignores supported non-critical extensions, so admitting
    // a duplicate would let the response mean one thing here and another to a
    // strict client that rejects the repetition or keeps the other copy. The
    // fixed-size table is bounded by `MAX_EXTENSIONS`, so the linear scan costs
    // at most a few hundred slice comparisons and cannot be driven quadratic.
    let mut seen_ids: [&[u8]; MAX_EXTENSIONS] = [&[]; MAX_EXTENSIONS];
    while !cursor.is_empty() {
        let (extension, _, next) = take_tlv(cursor)?;
        cursor = next;
        seen += 1;
        if seen > MAX_EXTENSIONS {
            return Err(format!(
                "OCSP {field} carries more than {MAX_EXTENSIONS} extensions"
            ));
        }
        if extension.class() != Class::Universal
            || extension.tag() != Tag::Sequence
            || !extension.header.constructed()
        {
            return Err(format!("OCSP {field} contains a non-SEQUENCE Extension"));
        }

        let (id_any, _, rest) = take_tlv(extension.data)?;
        if id_any.class() != Class::Universal
            || id_any.tag() != Tag::Oid
            || id_any.header.constructed()
        {
            return Err(oid_error(field));
        }
        id_any.as_oid().map_err(|_| oid_error(field))?;
        let id_bytes = id_any.data;
        if seen_ids[..seen - 1].contains(&id_bytes) {
            return Err(format!(
                "OCSP {field} repeats an extension OID, which X.509 Extensions must not do"
            ));
        }
        seen_ids[seen - 1] = id_bytes;

        let (second_any, _, tail) = take_tlv(rest)?;
        let mut critical = false;
        let mut value_any = second_any;
        let mut rest = tail;
        if value_any.tag() == Tag::Boolean && value_any.class() == Class::Universal {
            critical = der_critical_flag(&value_any, field)?;
            let (parsed, _, next) = take_tlv(rest)?;
            value_any = parsed;
            rest = next;
        }

        if !rest.is_empty() {
            return Err(format!("OCSP {field} Extension has trailing fields"));
        }
        if value_any.class() != Class::Universal
            || value_any.tag() != Tag::OctetString
            || value_any.header.constructed()
        {
            return Err(format!(
                "OCSP {field} extnValue is not a primitive OCTET STRING"
            ));
        }
        if critical {
            return Err(format!(
                "OCSP {field} contains a critical extension Ferrum does not implement"
            ));
        }
    }
    Ok(())
}

fn parse_cert_id(input: &[u8]) -> Result<CertId<'_>, String> {
    let (rest, hash_algorithm) = AlgorithmIdentifier::from_der(input)
        .map_err(|_| "OCSP CertID hashAlgorithm is malformed".to_string())?;

    let (name_hash_any, _, rest) = take_tlv(rest)?;
    let issuer_name_hash = expect_primitive(&name_hash_any, Tag::OctetString, "issuerNameHash")?;
    let (key_hash_any, _, rest) = take_tlv(rest)?;
    let issuer_key_hash = expect_primitive(&key_hash_any, Tag::OctetString, "issuerKeyHash")?;
    let (serial_any, _, trailing) = take_tlv(rest)?;
    let serial_number = expect_primitive(&serial_any, Tag::Integer, "serialNumber")?;
    if !trailing.is_empty() {
        return Err("OCSP CertID has trailing fields".to_string());
    }

    Ok(CertId {
        hash_algorithm: hash_algorithm.algorithm,
        issuer_name_hash,
        issuer_key_hash,
        serial_number,
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
/// chain member whose key is proven to have signed the leaf; a self-signed leaf
/// is its own issuer. When neither holds, the response cannot be bound to anything
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
///
/// A matching subject name is *not* enough. RFC 6960 binds a `CertID` to "the
/// CA that issued the certificate", and the same binding is what authorizes a
/// delegated responder, so the selected certificate must be proven to hold the
/// key that actually signed the leaf. A name match alone would let any
/// same-named certificate in the served bundle — an old CA generation, a
/// cross-signed sibling, or an operator-supplied impostor — decide which
/// issuer key hash a `CertID` is compared against. Same-name candidates are
/// therefore scanned until one verifies, and a self-issued leaf is accepted as
/// its own issuer only when it is genuinely self-*signed*.
fn select_issuer_der<'a>(
    leaf: &X509Certificate<'_>,
    chain: &'a [CertificateDer<'_>],
) -> Result<&'a [u8], String> {
    let leaf_issuer = leaf.issuer().as_raw();
    let mut saw_name_match = false;
    for candidate in chain.iter().skip(1) {
        let Ok((_, parsed)) = X509Certificate::from_der(candidate.as_ref()) else {
            continue;
        };
        if parsed.subject().as_raw() != leaf_issuer {
            continue;
        }
        saw_name_match = true;
        if leaf.verify_signature(Some(parsed.public_key())).is_err() {
            continue;
        }
        return Ok(candidate.as_ref());
    }
    // A self-issued leaf is its own issuer; this is the ordinary shape for the
    // self-signed certificates used in tests and single-node deployments. It
    // still has to verify under its own key: self-issued is a name property,
    // self-signed is the key property the binding actually needs.
    if leaf.subject().as_raw() == leaf_issuer {
        saw_name_match = true;
        if leaf.verify_signature(None).is_ok() {
            return Ok(chain[0].as_ref());
        }
    }
    let message = if saw_name_match {
        "the served certificate chain carries the leaf's issuer name but no certificate whose key \
         signed the leaf, so a stapled OCSP response cannot be bound to it"
    } else {
        "the served certificate chain does not contain the leaf's issuer, so a stapled OCSP \
         response cannot be bound to it"
    };
    Err(message.to_string())
}

/// Find the one `SingleResponse` whose `CertID` names the configured leaf.
///
/// More than one match is an ambiguity, not a preference. A strict client
/// re-derives the `CertID` itself and may pick a different entry than Ferrum
/// did — including an entry that reuses another supported hash algorithm — so
/// admitting the first `good` while a second entry says `revoked` would staple
/// exactly the response that makes the handshake fail. The whole response is
/// refused instead.
fn match_single_response<'a, 'b>(
    basic: &'a BasicResponse<'b>,
    leaf: &X509Certificate<'_>,
    issuer: &X509Certificate<'_>,
) -> Result<&'a SingleResponse<'b>, String> {
    let leaf_serial = normalize_serial(leaf.raw_serial());
    let issuer_name = issuer.subject().as_raw();
    let issuer_key = issuer.public_key().subject_public_key.data.as_ref();

    let mut serial_matched = false;
    let mut matched: Option<&'a SingleResponse<'b>> = None;
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
        if matched.is_some() {
            let message = "OCSP response carries more than one SingleResponse for the configured \
                           certificate, so the status a strict client would select is ambiguous";
            return Err(message.to_string());
        }
        matched = Some(single);
    }
    if let Some(single) = matched {
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
        // Structural admission already proved every carried entry is one
        // complete X.509 certificate, so this cannot skip an entry: failing
        // closed here keeps that guarantee explicit rather than re-introducing
        // a silent skip if the admission pass ever loosens.
        let (_, candidate) = X509Certificate::from_der(candidate_der).map_err(|_| {
            "OCSP response carries an unparseable responder certificate".to_string()
        })?;
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
        // A responder that is allowed to sign OCSP responses still has to be
        // allowed to produce a digital signature at all. KeyUsage is optional,
        // but a present one that withholds digitalSignature contradicts the EKU
        // and fails closed; an unparseable KeyUsage is likewise not proof.
        match candidate.key_usage() {
            Ok(Some(key_usage)) if !key_usage.value.digital_signature() => continue,
            Ok(_) => {}
            Err(_) => continue,
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
         id-kp-OCSPSigning delegate permitting digitalSignature whose signature verifies"
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
