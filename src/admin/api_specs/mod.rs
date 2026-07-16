//! Admin API for OpenAPI/Swagger spec ingestion + retrieval.
//!
//! v1 supports OpenAPI 2.0 (Swagger), 3.0.x, 3.1.x, 3.2.x in JSON or YAML.

pub mod extractor;
pub mod handlers;

pub use extractor::{
    ExtractError, ExtractedBundle, SpecFormat, SpecMetadata, extract,
    extract_declared_proxy_plugin_association_ids, hash_resource_bundle,
};

/// Recover the proxy/plugin associations explicitly declared by a stored API
/// spec. Replacement uses this set to distinguish spec-declared associations
/// from manual associations that must survive PUT.
///
/// Stored metadata is best-effort here to preserve the existing replacement
/// contract: an unsupported encoding or unreadable legacy document is warned
/// about and treated as declaring no external associations.
pub(crate) fn declared_proxy_plugin_association_ids_from_stored_spec(
    spec: &crate::config::types::ApiSpec,
) -> std::collections::HashSet<String> {
    if spec.content_encoding != "gzip" {
        tracing::warn!(
            "api_spec '{}' uses unsupported content_encoding '{}'",
            spec.id,
            spec.content_encoding
        );
        return std::collections::HashSet::new();
    }
    let cap = usize::try_from(spec.uncompressed_size).unwrap_or(usize::MAX);
    let body = match crate::admin::spec_codec::decompress_gzip_capped(&spec.spec_content, cap) {
        Ok(body) => body,
        Err(error) => {
            tracing::warn!(
                "failed to decompress stored api_spec '{}' proxy plugin associations: {}",
                spec.id,
                error
            );
            return std::collections::HashSet::new();
        }
    };
    match extract_declared_proxy_plugin_association_ids(&body, Some(spec.spec_format)) {
        Ok(ids) => ids.into_iter().collect(),
        Err(error) => {
            tracing::warn!(
                "failed to parse stored api_spec '{}' proxy plugin associations: {}",
                spec.id,
                error
            );
            std::collections::HashSet::new()
        }
    }
}
