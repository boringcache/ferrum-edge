//! Stream (TCP/UDP) inspection for the WAF plugin.
//!
//! Extends the WAF beyond HTTP-family traffic to raw TCP streams and UDP
//! datagrams. Two capabilities, both gated by the top-level `mode`
//! (`enforce` blocks, `monitor` only records):
//!
//! 1. `tcp_require_tls` — reject a TCP connection whose opening bytes are not a
//!    TLS ClientHello. A transport-shape guard for ports that must only carry
//!    TLS. It inspects raw wire bytes, so it applies to plain TCP and
//!    passthrough proxies; on TLS-terminating frontends the handshake already
//!    proved the transport, so it is a no-op there.
//! 2. `signatures` — byte-pattern (regex) matching over *plaintext application*
//!    bytes: the opening bytes of a plain TCP stream, the first decrypted bytes
//!    of a TLS-terminated stream, or a (decrypted) UDP/DTLS datagram. Encrypted
//!    passthrough bytes are forwarded ciphertext the gateway never decrypts and
//!    are therefore never L7-scanned.
//!
//! Content inspection requires the bytes to traverse userspace, so a TCP proxy
//! with stream inspection enabled falls back from the kTLS-splice fast path to a
//! userspace relay for the connections it inspects.

use regex::bytes::RegexSet as BytesRegexSet;
use serde_json::{Map, Value};
use std::collections::HashSet;

use super::rules::{RuleAction, Severity, parse_rule_action};
use super::{optional_bool, optional_string, parse_severity};

/// One compiled stream signature's metadata, indexed in lockstep with the
/// `RegexSet` so a match index maps straight back to its id/severity/action.
#[derive(Debug)]
pub(super) struct StreamSignatureMeta {
    pub(super) id: String,
    pub(super) severity: Severity,
    pub(super) action: RuleAction,
}

/// Compiled stream signatures: a single bytes `RegexSet` (linear-time match
/// regardless of pattern count) plus parallel per-pattern metadata.
#[derive(Debug)]
pub(super) struct CompiledStreamSignatures {
    set: BytesRegexSet,
    meta: Vec<StreamSignatureMeta>,
}

impl CompiledStreamSignatures {
    /// Metadata for every signature matching `data`.
    pub(super) fn matches<'a>(&'a self, data: &[u8]) -> Vec<&'a StreamSignatureMeta> {
        if self.meta.is_empty() {
            return Vec::new();
        }
        self.set
            .matches(data)
            .into_iter()
            .map(|i| &self.meta[i])
            .collect()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.meta.is_empty()
    }
}

/// Parsed `stream` sub-config for the WAF plugin.
#[derive(Debug)]
pub(super) struct StreamWafConfig {
    pub(super) tcp_require_tls: bool,
    pub(super) inspect_tcp: bool,
    pub(super) inspect_udp: bool,
    pub(super) inspect_response: bool,
    pub(super) signatures: CompiledStreamSignatures,
}

impl StreamWafConfig {
    /// Whether the TCP proxy must capture the opening client bytes for this
    /// config — either to signature-scan them or to run the TLS-shape guard.
    pub(super) fn needs_tcp_first_bytes(&self) -> bool {
        self.tcp_require_tls || (self.inspect_tcp && !self.signatures.is_empty())
    }

    /// Whether per-datagram UDP hooks are needed for this config.
    pub(super) fn needs_udp_datagrams(&self) -> bool {
        self.inspect_udp && !self.signatures.is_empty()
    }
}

/// Parse the optional `stream` config block. Returns `Ok(None)` when absent or
/// when it carries no actionable inspection, so a WAF without real stream rules
/// stays HTTP-only and never attaches to stream proxies.
pub(super) fn parse_stream_config(
    object: &Map<String, Value>,
) -> Result<Option<StreamWafConfig>, String> {
    let Some(raw) = object.get("stream") else {
        return Ok(None);
    };
    if raw.is_null() {
        return Ok(None);
    }
    let stream = raw
        .as_object()
        .ok_or_else(|| "waf: 'stream' must be an object".to_string())?;

    let tcp_require_tls = optional_bool(stream, "tcp_require_tls")?.unwrap_or(false);
    let inspect_tcp = optional_bool(stream, "inspect_tcp")?.unwrap_or(true);
    let inspect_udp = optional_bool(stream, "inspect_udp")?.unwrap_or(true);
    let inspect_response = optional_bool(stream, "inspect_response")?.unwrap_or(false);

    let signatures = compile_stream_signatures(stream)?;

    // A `stream` block with neither signatures nor the TLS-shape guard is a
    // no-op; treat it as absent so the plugin does not attach to stream proxies
    // for nothing.
    if signatures.is_empty() && !tcp_require_tls {
        return Ok(None);
    }

    Ok(Some(StreamWafConfig {
        tcp_require_tls,
        inspect_tcp,
        inspect_udp,
        inspect_response,
        signatures,
    }))
}

fn compile_stream_signatures(
    stream: &Map<String, Value>,
) -> Result<CompiledStreamSignatures, String> {
    let mut patterns: Vec<String> = Vec::new();
    let mut meta: Vec<StreamSignatureMeta> = Vec::new();

    if let Some(value) = stream.get("signatures").filter(|v| !v.is_null()) {
        let array = value
            .as_array()
            .ok_or_else(|| "waf: 'stream.signatures' must be an array".to_string())?;
        let mut seen_ids = HashSet::new();
        for (idx, entry) in array.iter().enumerate() {
            let obj = entry
                .as_object()
                .ok_or_else(|| format!("waf: 'stream.signatures[{idx}]' must be an object"))?;
            let id = optional_string(obj, "id")?
                .ok_or_else(|| format!("waf: 'stream.signatures[{idx}]' requires 'id'"))?;
            if !seen_ids.insert(id.clone()) {
                return Err(format!("waf: duplicate stream signature id '{id}'"));
            }
            let pattern = optional_string(obj, "pattern")?
                .ok_or_else(|| format!("waf: stream signature '{id}' requires 'pattern'"))?;
            // Compile each pattern individually first so the error names the
            // offending signature rather than a combined-set position.
            regex::bytes::Regex::new(&pattern)
                .map_err(|e| format!("waf: stream signature '{id}' has invalid pattern: {e}"))?;
            let severity = match optional_string(obj, "severity")? {
                Some(s) => parse_severity(&s).ok_or_else(|| {
                    format!("waf: stream signature '{id}' has invalid severity '{s}'")
                })?,
                None => Severity::Medium,
            };
            let action = match optional_string(obj, "action")? {
                Some(a) => parse_rule_action(&a, "stream.signatures.action")?,
                None => RuleAction::Enforce,
            };
            patterns.push(pattern);
            meta.push(StreamSignatureMeta {
                id,
                severity,
                action,
            });
        }
    }

    // `RegexSet::new` over an empty pattern list yields a set that matches
    // nothing, which is exactly what we want when only `tcp_require_tls` is set.
    let set = BytesRegexSet::new(&patterns)
        .map_err(|e| format!("waf: failed to build stream signature set: {e}"))?;

    Ok(CompiledStreamSignatures { set, meta })
}

/// Heuristic: do these raw wire bytes look like the start of a TLS or DTLS
/// ClientHello handshake record? Backs `tcp_require_tls`.
///
/// A (D)TLS record begins with content-type `0x16` (handshake) followed by a
/// two-byte legacy record version: `0x03 0x0n` for TLS 1.x, or `0xfe 0xfd` /
/// `0xfe 0xff` for DTLS 1.2 / 1.0.
pub(super) fn looks_like_tls_client_hello(data: &[u8]) -> bool {
    if data.len() < 3 || data[0] != 0x16 {
        return false;
    }
    matches!(
        (data[1], data[2]),
        (0x03, 0x00..=0x04) | (0xfe, 0xfd) | (0xfe, 0xff)
    )
}
