//! Adversarial-parser entry points for the `fuzz/` cargo-fuzz workspace.
//!
//! This module is intentionally narrow: it exposes pure decode/validate helpers
//! with explicit input, recursion, allocation, and iteration budgets so the
//! fuzz lane can exercise hostile inputs without widening the production API.

use bytes::{Bytes, BytesMut};
use serde_json::Value;

use crate::config::BackendEgressPolicy;
use crate::config::file_loader::decode_and_validate_config_document;
use crate::config_sources::k8s::{K8sObject, K8sTranslationOptions, translate_k8s_objects};
use crate::identity::spiffe::TrustDomain;
use crate::plugins::otel_tracing::{OtelTracing, build_traceparent};
use crate::plugins::validate_plugin_config;
use crate::proxy::mesh_udp_frame::{MAX_FRAME_PAYLOAD, encode_datagram, pop_framed_datagram};
use crate::proxy::proxy_protocol::parse_proxy_protocol_header_bytes;

/// Hard cap on arbitrary fuzz input bytes passed into a single target invocation.
pub const MAX_FUZZ_INPUT_BYTES: usize = 64 * 1024;

/// Maximum JSON/YAML nesting depth accepted before decode is rejected fail-closed.
pub const MAX_JSON_DEPTH: usize = 64;

/// Maximum number of Kubernetes objects deserialized from one fuzz input.
pub const MAX_K8S_OBJECTS: usize = 32;

/// Maximum framed datagrams drained from one fuzz input stream.
pub const MAX_MESH_UDP_FRAMES: usize = 256;

/// Plugin names exercised by the structured plugin-config fuzz target.
pub const FUZZ_PLUGIN_NAMES: &[&str] = &[
    "cors",
    "rate_limiting",
    "correlation_id",
    "otel_tracing",
    "security_headers",
    "ip_restriction",
    "request_size_limiting",
    "body_validator",
];

/// Reject inputs that exceed the global fuzz byte budget.
pub fn enforce_input_budget(data: &[u8]) -> Result<&[u8], ()> {
    if data.len() > MAX_FUZZ_INPUT_BYTES {
        return Err(());
    }
    Ok(data)
}

/// Measure structural depth of a parsed JSON value.
pub fn json_value_depth(value: &Value) -> usize {
    match value {
        Value::Array(items) => 1 + items.iter().map(json_value_depth).max().unwrap_or(0),
        Value::Object(map) => 1 + map.values().map(json_value_depth).max().unwrap_or(0),
        _ => 1,
    }
}

/// Fail closed when nesting exceeds [`MAX_JSON_DEPTH`].
pub fn reject_excessive_json_depth(value: &Value) -> Result<(), ()> {
    if json_value_depth(value) > MAX_JSON_DEPTH {
        return Err(());
    }
    Ok(())
}

/// Parse a W3C `traceparent` header. Invalid input returns `None` (fail closed).
pub fn parse_traceparent_header(value: &str) -> Option<()> {
    OtelTracing::parse_traceparent(value).map(|_| ())
}

/// Round-trip invariant: a header accepted by the parser must re-encode to an
/// equivalent accepted header when sampled flags are preserved.
pub fn traceparent_round_trip_invariant(value: &str) -> bool {
    let Some(parsed) = OtelTracing::parse_traceparent(value) else {
        return true;
    };
    let rebuilt = build_traceparent("00", parsed.trace_id, parsed.parent_span_id, parsed.flags);
    OtelTracing::parse_traceparent(&rebuilt).is_some()
}

/// Decode and validate a config document from UTF-8 bytes. Errors are expected
/// for hostile input; panics are not.
pub fn fuzz_decode_config_document(content: &str) -> Result<(), String> {
    decode_and_validate_config_document(content, 30, &BackendEgressPolicy::unrestricted())
        .map(|_| ())
        .map_err(|error| error.to_string())
}

/// Parse a complete PROXY protocol header from bytes.
pub fn fuzz_parse_proxy_protocol(data: &[u8]) -> Result<(), String> {
    parse_proxy_protocol_header_bytes(data)
        .map(|_| ())
        .map_err(|error| error.to_string())
}

/// Drain length-prefixed mesh UDP frames from a byte stream with a hard frame cap.
pub fn fuzz_drain_mesh_udp_frames(data: &[u8]) -> Result<Vec<Bytes>, String> {
    let mut buf = BytesMut::from(data);
    let mut frames = Vec::new();
    while let Some(frame) = pop_framed_datagram(&mut buf) {
        if frames.len() >= MAX_MESH_UDP_FRAMES {
            return Err("mesh UDP frame iteration budget exceeded".to_string());
        }
        frames.push(frame);
    }
    Ok(frames)
}

/// Encode then decode round-trip for a single payload (deterministic invariant).
pub fn mesh_udp_frame_round_trip(payload: &[u8]) -> Result<(), String> {
    if payload.len() > MAX_FRAME_PAYLOAD {
        return Ok(());
    }
    let mut wire = BytesMut::new();
    encode_datagram(&mut wire, payload).map_err(|error| error.to_string())?;
    let mut buf = wire;
    let decoded =
        pop_framed_datagram(&mut buf).ok_or_else(|| "round-trip frame missing".to_string())?;
    if decoded.as_ref() != payload {
        return Err("round-trip payload mismatch".to_string());
    }
    if pop_framed_datagram(&mut buf).is_some() {
        return Err("round-trip produced trailing frame".to_string());
    }
    Ok(())
}

/// Deserialize and translate Kubernetes objects from JSON bytes.
pub fn fuzz_translate_k8s_json(data: &[u8]) -> Result<(), String> {
    let value: Value = serde_json::from_slice(data).map_err(|error| error.to_string())?;
    reject_excessive_json_depth(&value).map_err(|()| "json depth budget exceeded".to_string())?;
    if value
        .as_array()
        .is_some_and(|objects| objects.len() > MAX_K8S_OBJECTS)
    {
        return Err("k8s object count budget exceeded".to_string());
    }
    let objects: Vec<K8sObject> = if value.is_array() {
        serde_json::from_value(value).map_err(|error| error.to_string())?
    } else {
        vec![serde_json::from_value(value).map_err(|error| error.to_string())?]
    };
    let options = K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").map_err(|error| error.to_string())?,
    );
    translate_k8s_objects(&objects, options)
        .map(|_| ())
        .map_err(|error| format!("{error:?}"))
}

/// Validate a plugin configuration JSON blob against a representative plugin set.
pub fn fuzz_validate_plugin_config(data: &[u8]) -> Result<(), String> {
    let Some((&selector, payload)) = data.split_first() else {
        return Ok(());
    };
    if payload.is_empty() {
        return Ok(());
    }
    let value: Value = serde_json::from_slice(payload).map_err(|error| error.to_string())?;
    reject_excessive_json_depth(&value).map_err(|()| "json depth budget exceeded".to_string())?;
    let plugin_idx = selector as usize % FUZZ_PLUGIN_NAMES.len();
    let plugin_name = FUZZ_PLUGIN_NAMES[plugin_idx];
    validate_plugin_config(plugin_name, &value).map_err(|error| error)
}

/// Deterministic smoke helper used by hosted CI property checks.
pub fn smoke_invariants() -> Result<(), String> {
    let valid = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    if parse_traceparent_header(valid).is_none() {
        return Err("valid traceparent rejected".to_string());
    }
    if !traceparent_round_trip_invariant(valid) {
        return Err("traceparent round-trip failed".to_string());
    }
    mesh_udp_frame_round_trip(b"smoke")?;
    let proxy_v1 = b"PROXY TCP4 127.0.0.1 10.0.0.1 12345 443\r\n";
    fuzz_parse_proxy_protocol(proxy_v1)?;
    let config =
        r#"{"version":"1","proxies":[],"consumers":[],"plugin_configs":[],"upstreams":[]}"#;
    fuzz_decode_config_document(config)?;
    fuzz_validate_plugin_config(b"0{\"allowed_origins\":[\"*\"]}")?;
    Ok(())
}
