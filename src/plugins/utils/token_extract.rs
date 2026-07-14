use crate::plugins::RequestContext;

use super::auth_flow::ExtractedCredential;

/// Metadata-key prefix marking a query parameter that carried the auth token and
/// must be stripped from the URL forwarded upstream. It is shared by every auth
/// plugin that supports query-param token locations and is consumed by the proxy
/// (`query_string_after_plugin_strips`), which is the only place that can rewrite
/// the forwarded query string. Per-plugin prefixes would be silently ignored
/// there, leaking the token to the backend.
pub(crate) const STRIP_QUERY_PARAM_METADATA_PREFIX: &str = "auth.strip_query_param.";

#[derive(Clone)]
pub struct TokenHeaderLocation {
    pub name: String,
    pub prefix: Option<String>,
}

#[derive(Clone)]
pub enum TokenLocation {
    Header(TokenHeaderLocation),
    QueryParam(String),
}

pub enum TokenLocationExtract {
    Missing,
    Credential(ExtractedCredential),
}

pub fn extract_authorization_bearer(ctx: &RequestContext) -> ExtractedCredential {
    match ctx.headers.get("authorization") {
        None => ExtractedCredential::Missing,
        Some(value) => match value.split_once(' ') {
            Some((scheme, token)) if scheme.eq_ignore_ascii_case("bearer") => {
                if token.is_empty() {
                    ExtractedCredential::InvalidFormat(
                        r#"{"error":"Empty bearer token"}"#.to_string(),
                    )
                } else {
                    ExtractedCredential::BearerToken(token.to_string())
                }
            }
            _ => ExtractedCredential::InvalidFormat(
                r#"{"error":"Missing Bearer token"}"#.to_string(),
            ),
        },
    }
}

pub fn extract_from_location(
    location: &TokenLocation,
    ctx: &RequestContext,
) -> TokenLocationExtract {
    match location {
        TokenLocation::Header(header) => match ctx.headers.get(&header.name) {
            Some(value) => extract_location_value(value, header.prefix.as_deref()),
            None => TokenLocationExtract::Missing,
        },
        TokenLocation::QueryParam(name) => match ctx.query_params.get(name) {
            Some(value) => extract_location_value(value, None),
            None => TokenLocationExtract::Missing,
        },
    }
}

pub fn provider_locations_extract_token(
    token_locations: &[TokenLocation],
    ctx: &RequestContext,
    expected_token: &str,
) -> bool {
    token_locations
        .iter()
        .any(|location| match extract_from_location(location, ctx) {
            TokenLocationExtract::Credential(ExtractedCredential::BearerToken(token)) => {
                token == expected_token
            }
            _ => false,
        })
}

pub fn mark_original_token_stripping_metadata(
    ctx: &mut RequestContext,
    token_locations: &[TokenLocation],
    strip_authorization_metadata_key: &str,
    strip_header_metadata_prefix: &str,
    strip_query_param_metadata_prefix: &str,
) {
    if token_locations.is_empty() {
        ctx.metadata.insert(
            strip_authorization_metadata_key.to_string(),
            "true".to_string(),
        );
        return;
    }

    for location in token_locations {
        match location {
            TokenLocation::Header(header) => {
                ctx.metadata.insert(
                    format!("{strip_header_metadata_prefix}{}", header.name),
                    "true".to_string(),
                );
            }
            TokenLocation::QueryParam(name) => {
                ctx.metadata.insert(
                    format!("{strip_query_param_metadata_prefix}{name}"),
                    "true".to_string(),
                );
                ctx.query_params.remove(name);
            }
        }
    }
}

fn extract_location_value(value: &str, prefix: Option<&str>) -> TokenLocationExtract {
    let token = match prefix {
        Some(prefix) => match value.strip_prefix(prefix) {
            Some(token) => token,
            None => return TokenLocationExtract::Missing,
        },
        None => value,
    };

    if token.is_empty() {
        return TokenLocationExtract::Credential(ExtractedCredential::InvalidFormat(
            r#"{"error":"Empty token"}"#.to_string(),
        ));
    }

    TokenLocationExtract::Credential(ExtractedCredential::BearerToken(token.to_string()))
}
