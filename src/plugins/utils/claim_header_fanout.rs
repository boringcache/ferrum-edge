use std::collections::HashMap;

use http::header::HeaderName;
use serde_json::{Map, Value};

use crate::plugins::RequestContext;

use super::auth_attempt::AuthenticationAttempt;
use super::claim_resolver::{parse_claim_path_value, resolve_claim_path};

#[derive(Clone, Debug)]
pub struct ClaimHeaderMapping {
    pub claim_path: String,
    pub metadata_key: String,
    /// Normalized (lowercase) request-header name this mapping owns. Retained
    /// alongside `metadata_key` so the request path never has to strip the
    /// metadata prefix to learn which destination is gateway-owned.
    pub destination_header: String,
}

/// The complete set of request-header destinations one plugin instance owns
/// through `claim_headers`, including every provider override.
///
/// `claim_headers` destinations are **gateway-owned**: after a successful
/// authentication the gateway is the only party allowed to assert them. The set
/// is precomputed at plugin construction so the request path performs no
/// configuration walk and no per-request name normalization.
#[derive(Clone, Debug, Default)]
pub struct ClaimHeaderDestinations {
    /// Deduplicated, sorted, lowercase destination header names.
    names: Vec<String>,
}

impl ClaimHeaderDestinations {
    /// Union every destination reachable from one plugin instance. Callers pass
    /// the plugin-level mappings plus each provider's override mappings, so a
    /// provider that only overrides some destinations still contributes to the
    /// owned set and cannot leave a stale client value behind.
    pub fn from_mapping_groups<'a, I>(mapping_groups: I) -> Self
    where
        I: IntoIterator<Item = &'a [ClaimHeaderMapping]>,
    {
        let mut names: Vec<String> = mapping_groups
            .into_iter()
            .flatten()
            .map(|mapping| mapping.destination_header.clone())
            .collect();
        names.sort_unstable();
        names.dedup();
        Self { names }
    }

    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    pub fn names(&self) -> &[String] {
        &self.names
    }
}

pub fn parse_claim_headers(
    config: &Map<String, Value>,
    field: &str,
    plugin: &str,
    metadata_prefix: &str,
) -> Result<Vec<ClaimHeaderMapping>, String> {
    let Some(value) = config.get(field) else {
        return Ok(Vec::new());
    };
    let object = value
        .as_object()
        .ok_or_else(|| format!("{plugin}: '{field}' must be an object, got: {value}"))?;
    let mut mappings = Vec::with_capacity(object.len());
    for (claim_path, header_value) in object {
        let parsed_claim_path = parse_claim_path_value(
            &format!("{field}.{claim_path}"),
            &Value::String(claim_path.clone()),
            plugin,
        )?;
        let raw_header = header_value.as_str().ok_or_else(|| {
            format!(
                "{plugin}: '{field}.{claim_path}' must be a header name string, got: {header_value}"
            )
        })?;
        let header_name = normalize_allowed_header(raw_header, plugin, field)?;
        let metadata_key = format!("{metadata_prefix}{header_name}");
        mappings.push(ClaimHeaderMapping {
            claim_path: parsed_claim_path,
            metadata_key,
            destination_header: header_name,
        });
    }
    Ok(mappings)
}

pub fn emit_claim_headers_to_attempt(
    attempt: &mut AuthenticationAttempt,
    claims: &Value,
    mappings: &[ClaimHeaderMapping],
    separator: &str,
) {
    for mapping in mappings {
        let Some(value) = claim_value_for_header(claims, &mapping.claim_path, separator) else {
            continue;
        };
        attempt.stage_claim_header(mapping.metadata_key.clone(), value);
    }
}

/// Install verified claim values into the backend request headers.
///
/// `claim_headers` destinations are gateway-owned and always sanitized: every
/// destination this plugin instance owns is removed case-insensitively (covering
/// duplicate and case-variant client headers) *before* any verified value is
/// installed. A claim that is missing, null, empty, of an unusable type, or that
/// belongs to a principal this instance did not authenticate therefore leaves the
/// destination **absent** rather than preserving attacker-controlled client
/// input.
///
/// Sanitization is claimed once per destination per request. The first instance
/// that owns a destination strips the client value; a later instance that shares
/// the same destination will not erase a value an earlier instance already
/// installed, and no instance ever touches a destination it does not own.
pub fn apply_claim_headers_from_context(
    ctx: &mut RequestContext,
    headers: &mut HashMap<String, String>,
    metadata_prefix: &str,
    destinations: &ClaimHeaderDestinations,
) {
    sanitize_owned_claim_header_destinations(ctx, headers, destinations);
    let keys: Vec<String> = ctx
        .pending_claim_headers
        .keys()
        .filter(|key| key.starts_with(metadata_prefix))
        .cloned()
        .collect();
    for key in keys {
        let Some(header_name) = key.strip_prefix(metadata_prefix) else {
            continue;
        };
        if let Some(value) = ctx.pending_claim_headers.remove(&key) {
            headers.insert(header_name.to_string(), value);
        }
    }
}

/// Remove every gateway-owned destination this instance still has to claim.
///
/// Runs before installation so an absent, wrong-type, or unusable claim can
/// never leave a client-supplied value in place. Case-insensitive removal is
/// required because `RequestContext::headers` preserves the client's original
/// header casing, so a lowercase insert alone would leave a `X-Authenticated-Email`
/// variant beside the gateway's value.
fn sanitize_owned_claim_header_destinations(
    ctx: &mut RequestContext,
    headers: &mut HashMap<String, String>,
    destinations: &ClaimHeaderDestinations,
) {
    if destinations.is_empty() {
        return;
    }
    let unclaimed: Vec<&str> = destinations
        .names()
        .iter()
        .map(String::as_str)
        .filter(|name| !ctx.sanitized_claim_header_destinations.contains(*name))
        .collect();
    if unclaimed.is_empty() {
        return;
    }
    headers.retain(|name, _| {
        !unclaimed
            .iter()
            .any(|destination| name.eq_ignore_ascii_case(destination))
    });
    for destination in unclaimed {
        ctx.sanitized_claim_header_destinations
            .insert(destination.to_string());
    }
}

pub fn parse_separator(
    config: &Map<String, Value>,
    field: &str,
    plugin: &str,
    default_value: &str,
) -> Result<String, String> {
    let Some(value) = config.get(field) else {
        return Ok(default_value.to_string());
    };
    let raw = value
        .as_str()
        .ok_or_else(|| format!("{plugin}: '{field}' must be a string, got: {value}"))?;
    if raw.is_empty() {
        return Err(format!("{plugin}: '{field}' must not be empty"));
    }
    Ok(raw.to_string())
}

/// Resolve one mapped claim into a header value, or `None` when the claim is
/// absent, null, of an unusable type, or carries no non-whitespace content.
///
/// Returning `None` is what makes the destination absent after sanitization, so
/// an empty or blank claim must never yield `Some("")` — a backend that trusts
/// the destination would otherwise see a gateway-asserted empty identity.
fn claim_value_for_header(claims: &Value, claim_path: &str, separator: &str) -> Option<String> {
    let value = match resolve_claim_path(claims, claim_path)? {
        Value::String(value) => value.clone(),
        Value::Array(values) => {
            let parts: Vec<&str> = values
                .iter()
                .filter_map(Value::as_str)
                .filter(|part| !part.trim().is_empty())
                .collect();
            if parts.is_empty() {
                return None;
            }
            parts.join(separator)
        }
        _ => return None,
    };
    (!value.trim().is_empty()).then_some(value)
}

fn normalize_allowed_header(raw_header: &str, plugin: &str, field: &str) -> Result<String, String> {
    let trimmed = raw_header.trim();
    if trimmed.is_empty() {
        return Err(format!("{plugin}: '{field}' header name must not be empty"));
    }
    let header = HeaderName::from_bytes(trimmed.as_bytes())
        .map_err(|e| format!("{plugin}: '{field}' header name is invalid: {e}"))?
        .as_str()
        .to_string();
    if is_reserved_header(&header) {
        return Err(format!(
            "{plugin}: '{field}' cannot target reserved header '{header}'"
        ));
    }
    Ok(header)
}

pub fn is_reserved_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "x-consumer-username"
            | "x-consumer-custom-id"
            | "host"
            | "connection"
            | "te"
            | "keep-alive"
            | "transfer-encoding"
            | "upgrade"
            | "proxy-authorization"
            | "authorization"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rejects_reserved_header_target() {
        let config = json!({"claim_headers": {"sub": "Authorization"}});
        let err = parse_claim_headers(
            config.as_object().expect("object"),
            "claim_headers",
            "test",
            "test.",
        )
        .expect_err("reserved header should reject");
        assert!(err.contains("reserved"));
    }

    #[test]
    fn emits_string_and_array_claims() {
        let mapping = vec![
            ClaimHeaderMapping {
                claim_path: "email".to_string(),
                metadata_key: "p.x-user-email".to_string(),
                destination_header: "x-user-email".to_string(),
            },
            ClaimHeaderMapping {
                claim_path: "roles".to_string(),
                metadata_key: "p.x-user-roles".to_string(),
                destination_header: "x-user-roles".to_string(),
            },
        ];
        let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/".into());
        let mut attempt = AuthenticationAttempt::new();
        emit_claim_headers_to_attempt(
            &mut attempt,
            &json!({"email": "a@example.com", "roles": ["admin", "editor"]}),
            &mapping,
            ",",
        );
        crate::plugins::utils::auth_flow::commit_authentication_attempt(
            &mut ctx,
            attempt,
            crate::plugins::utils::auth_flow::VerifyOutcome::success(
                None,
                Some("accepted-principal".to_string()),
                None,
            ),
            "test_auth",
            true,
        )
        .expect("attempt commits");
        assert_eq!(
            ctx.pending_claim_headers
                .get("p.x-user-email")
                .map(String::as_str),
            Some("a@example.com")
        );
        assert_eq!(
            ctx.pending_claim_headers
                .get("p.x-user-roles")
                .map(String::as_str),
            Some("admin,editor")
        );
    }
}
