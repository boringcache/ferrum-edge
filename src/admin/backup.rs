use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use crate::config::types::{ApiSpec, Consumer, GatewayConfig, PluginConfig, Proxy, SpecFormat, Upstream};

/// Version of the `api_specs` backup section contract.
///
/// Bump when the section shape or restore semantics change in a
/// non-backward-compatible way. Older backups that omit the section entirely
/// remain restorable via the explicit deletion-confirmation preflight.
pub(crate) const API_SPECS_BACKUP_SECTION_VERSION: &str = "1";

pub(crate) fn parse_backup_resources(query: Option<&str>) -> Option<HashSet<&str>> {
    let query = query?;
    for pair in query.split('&') {
        let mut parts = pair.splitn(2, '=');
        if let (Some(key), Some(val)) = (parts.next(), parts.next())
            && key == "resources"
        {
            return Some(
                val.split(',')
                    .map(str::trim)
                    .filter(|resource| !resource.is_empty())
                    .collect(),
            );
        }
    }
    None
}

pub(crate) fn parse_restore_confirm(query: Option<&str>) -> bool {
    parse_query_flag(query, "confirm")
}

/// Explicit confirmation that a restore of a legacy backup (no `api_specs`
/// section) may permanently delete API specs present in the target namespace.
pub(crate) fn parse_confirm_api_spec_deletion(query: Option<&str>) -> bool {
    parse_query_flag(query, "confirm_api_spec_deletion")
}

fn parse_query_flag(query: Option<&str>, flag: &str) -> bool {
    let query = match query {
        Some(query) => query,
        None => return false,
    };
    for pair in query.split('&') {
        let mut parts = pair.splitn(2, '=');
        if let (Some(key), Some(val)) = (parts.next(), parts.next())
            && key == flag
            && val == "true"
        {
            return true;
        }
    }
    false
}

#[derive(Serialize)]
pub(crate) struct BackupPayload<'a> {
    pub(crate) version: &'a str,
    pub(crate) ferrum_version: &'static str,
    pub(crate) exported_at: String,
    pub(crate) source: &'static str,
    pub(crate) counts: BackupCounts,
    pub(crate) proxies: &'a [Proxy],
    pub(crate) consumers: &'a [Consumer],
    pub(crate) plugin_configs: &'a [PluginConfig],
    pub(crate) upstreams: &'a [Upstream],
    /// Versioned admin-only API spec section. Always present on database-backed
    /// full exports (possibly with an empty `items` array). Omitted only when
    /// specs could not be loaded (cached fallback without a reachable primary).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) api_specs: Option<&'a ApiSpecsBackupSection>,
}

#[derive(Serialize)]
pub(crate) struct BackupCounts {
    pub(crate) proxies: usize,
    pub(crate) consumers: usize,
    pub(crate) plugin_configs: usize,
    pub(crate) upstreams: usize,
    pub(crate) api_specs: usize,
}

/// Versioned backup/restore section for raw API spec documents and ownership
/// metadata required to reproduce generated-resource relationships.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct ApiSpecsBackupSection {
    pub(crate) section_version: String,
    pub(crate) items: Vec<ApiSpecBackupItem>,
}

impl ApiSpecsBackupSection {
    pub(crate) fn empty() -> Self {
        Self {
            section_version: API_SPECS_BACKUP_SECTION_VERSION.to_string(),
            items: Vec::new(),
        }
    }

    pub(crate) fn from_specs(specs: &[ApiSpec]) -> Self {
        Self {
            section_version: API_SPECS_BACKUP_SECTION_VERSION.to_string(),
            items: specs.iter().map(ApiSpecBackupItem::from_api_spec).collect(),
        }
    }

    pub(crate) fn to_api_specs(&self) -> Result<Vec<ApiSpec>, String> {
        self.items
            .iter()
            .map(ApiSpecBackupItem::to_api_spec)
            .collect()
    }
}

/// Wire form of one API spec in a backup/restore payload.
///
/// `spec_content_base64` carries the gzip-compressed original document so JSON
/// backups stay compact and never emit a hostile multi-megabyte number array.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct ApiSpecBackupItem {
    pub(crate) id: String,
    #[serde(default = "default_namespace")]
    pub(crate) namespace: String,
    pub(crate) proxy_id: String,
    pub(crate) spec_version: String,
    pub(crate) spec_format: SpecFormat,
    pub(crate) spec_content_base64: String,
    pub(crate) content_encoding: String,
    pub(crate) uncompressed_size: u64,
    pub(crate) content_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) info_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) contact_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) contact_email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) license_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) license_identifier: Option<String>,
    #[serde(default)]
    pub(crate) tags: Vec<String>,
    #[serde(default)]
    pub(crate) server_urls: Vec<String>,
    #[serde(default)]
    pub(crate) operation_count: u32,
    #[serde(default)]
    pub(crate) resource_hash: String,
    pub(crate) created_at: chrono::DateTime<chrono::Utc>,
    pub(crate) updated_at: chrono::DateTime<chrono::Utc>,
}

fn default_namespace() -> String {
    "ferrum".to_string()
}

impl ApiSpecBackupItem {
    pub(crate) fn from_api_spec(spec: &ApiSpec) -> Self {
        Self {
            id: spec.id.clone(),
            namespace: spec.namespace.clone(),
            proxy_id: spec.proxy_id.clone(),
            spec_version: spec.spec_version.clone(),
            spec_format: spec.spec_format,
            spec_content_base64: base64::engine::general_purpose::STANDARD.encode(&spec.spec_content),
            content_encoding: spec.content_encoding.clone(),
            uncompressed_size: spec.uncompressed_size,
            content_hash: spec.content_hash.clone(),
            title: spec.title.clone(),
            info_version: spec.info_version.clone(),
            description: spec.description.clone(),
            contact_name: spec.contact_name.clone(),
            contact_email: spec.contact_email.clone(),
            license_name: spec.license_name.clone(),
            license_identifier: spec.license_identifier.clone(),
            tags: spec.tags.clone(),
            server_urls: spec.server_urls.clone(),
            operation_count: spec.operation_count,
            resource_hash: spec.resource_hash.clone(),
            created_at: spec.created_at,
            updated_at: spec.updated_at,
        }
    }

    pub(crate) fn to_api_spec(&self) -> Result<ApiSpec, String> {
        let spec_content = base64::engine::general_purpose::STANDARD
            .decode(self.spec_content_base64.as_bytes())
            .map_err(|error| format!("api_spec '{}': invalid spec_content_base64: {error}", self.id))?;
        Ok(ApiSpec {
            id: self.id.clone(),
            namespace: self.namespace.clone(),
            proxy_id: self.proxy_id.clone(),
            spec_version: self.spec_version.clone(),
            spec_format: self.spec_format,
            spec_content,
            content_encoding: self.content_encoding.clone(),
            uncompressed_size: self.uncompressed_size,
            content_hash: self.content_hash.clone(),
            title: self.title.clone(),
            info_version: self.info_version.clone(),
            description: self.description.clone(),
            contact_name: self.contact_name.clone(),
            contact_email: self.contact_email.clone(),
            license_name: self.license_name.clone(),
            license_identifier: self.license_identifier.clone(),
            tags: self.tags.clone(),
            server_urls: self.server_urls.clone(),
            operation_count: self.operation_count,
            resource_hash: self.resource_hash.clone(),
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

#[derive(Deserialize)]
pub(crate) struct RestorePayload {
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub proxies: Vec<Proxy>,
    #[serde(default)]
    pub consumers: Vec<Consumer>,
    #[serde(default)]
    pub plugin_configs: Vec<PluginConfig>,
    #[serde(default)]
    pub upstreams: Vec<Upstream>,
    /// Present when the backup includes the versioned `api_specs` section.
    /// `None` means a legacy backup that omitted the section entirely.
    #[serde(default)]
    pub api_specs: Option<ApiSpecsBackupSection>,
}

pub(crate) fn filter_config_by_namespace(config: &GatewayConfig, namespace: &str) -> GatewayConfig {
    GatewayConfig {
        version: config.version.clone(),
        proxies: config
            .proxies
            .iter()
            .filter(|proxy| proxy.namespace == namespace)
            .cloned()
            .collect(),
        consumers: config
            .consumers
            .iter()
            .filter(|consumer| consumer.namespace == namespace)
            .cloned()
            .collect(),
        plugin_configs: config
            .plugin_configs
            .iter()
            .filter(|plugin_config| plugin_config.namespace == namespace)
            .cloned()
            .collect(),
        upstreams: config
            .upstreams
            .iter()
            .filter(|upstream| upstream.namespace == namespace)
            .cloned()
            .collect(),
        ..config.clone()
    }
}

/// Validate the versioned `api_specs` backup section without logging document
/// contents or hashes that could leak source-spec material into operator logs.
pub(crate) fn validate_restore_api_specs_section(
    section: &ApiSpecsBackupSection,
    proxies: &[Proxy],
    upstreams: &[Upstream],
    plugin_configs: &[PluginConfig],
    max_spec_body_mib: usize,
) -> Result<Vec<ApiSpec>, Vec<String>> {
    let mut errors = Vec::new();
    if section.section_version != API_SPECS_BACKUP_SECTION_VERSION {
        errors.push(format!(
            "Unsupported api_specs.section_version '{}'; expected '{}'",
            section.section_version, API_SPECS_BACKUP_SECTION_VERSION
        ));
        return Err(errors);
    }

    let max_uncompressed = max_spec_body_mib.saturating_mul(1024 * 1024);
    // Compressed payload bound: reject absurd base64 that would decode past the
    // admin body ceiling even before gzip expansion.
    let max_compressed = max_uncompressed.saturating_mul(2).max(1024 * 1024);
    let mut seen_ids = HashSet::new();
    let mut seen_proxy_ids = HashSet::new();
    let proxy_by_id: HashMap<&str, &Proxy> =
        proxies.iter().map(|proxy| (proxy.id.as_str(), proxy)).collect();

    let mut specs = Vec::with_capacity(section.items.len());
    for item in &section.items {
        if let Err(error) = crate::config::types::validate_resource_id(&item.id) {
            errors.push(format!("api_spec id: {error}"));
            continue;
        }
        if let Err(error) = crate::config::types::validate_resource_id(&item.proxy_id) {
            errors.push(format!("api_spec '{}': proxy_id: {error}", item.id));
            continue;
        }
        if !seen_ids.insert(item.id.clone()) {
            errors.push(format!("duplicate api_spec id '{}'", item.id));
            continue;
        }
        if !seen_proxy_ids.insert(item.proxy_id.clone()) {
            errors.push(format!(
                "api_spec '{}': duplicate proxy_id '{}'",
                item.id, item.proxy_id
            ));
            continue;
        }
        if item.content_encoding != "gzip" {
            errors.push(format!(
                "api_spec '{}': unsupported content_encoding (expected gzip)",
                item.id
            ));
            continue;
        }
        if item.uncompressed_size as usize > max_uncompressed {
            errors.push(format!(
                "api_spec '{}': uncompressed_size exceeds admin spec body limit",
                item.id
            ));
            continue;
        }
        // Bound base64 length before decode to avoid hostile allocation.
        let max_b64_len = max_compressed
            .saturating_mul(4)
            .saturating_div(3)
            .saturating_add(8);
        if item.spec_content_base64.len() > max_b64_len {
            errors.push(format!(
                "api_spec '{}': spec_content_base64 exceeds size limit",
                item.id
            ));
            continue;
        }
        let spec = match item.to_api_spec() {
            Ok(spec) => spec,
            Err(message) => {
                errors.push(message);
                continue;
            }
        };
        if spec.spec_content.len() > max_compressed {
            errors.push(format!(
                "api_spec '{}': compressed content exceeds size limit",
                item.id
            ));
            continue;
        }
        let decompressed = match crate::admin::spec_codec::decompress_gzip_capped(
            &spec.spec_content,
            max_uncompressed,
        ) {
            Ok(bytes) => bytes,
            Err(_) => {
                errors.push(format!(
                    "api_spec '{}': compressed content is corrupt or oversized",
                    item.id
                ));
                continue;
            }
        };
        if decompressed.len() as u64 != spec.uncompressed_size {
            errors.push(format!(
                "api_spec '{}': uncompressed_size does not match decompressed content",
                item.id
            ));
            continue;
        }
        let actual_hash = crate::admin::spec_codec::sha256_hex(&decompressed);
        if actual_hash != spec.content_hash {
            errors.push(format!(
                "api_spec '{}': content_hash does not match decompressed content",
                item.id
            ));
            continue;
        }
        match proxy_by_id.get(spec.proxy_id.as_str()) {
            Some(proxy) if proxy.api_spec_id.as_deref() == Some(spec.id.as_str()) => {}
            Some(_) => {
                errors.push(format!(
                    "api_spec '{}': owning proxy '{}' must carry api_spec_id '{}'",
                    spec.id, spec.proxy_id, spec.id
                ));
                continue;
            }
            None => {
                errors.push(format!(
                    "api_spec '{}': owning proxy '{}' is missing from the restore payload",
                    spec.id, spec.proxy_id
                ));
                continue;
            }
        }
        specs.push(spec);
    }

    // Owned resources must not reference specs absent from the section.
    for proxy in proxies {
        if let Some(spec_id) = proxy.api_spec_id.as_deref()
            && !seen_ids.contains(spec_id)
        {
            errors.push(format!(
                "proxy '{}': api_spec_id '{}' is not present in api_specs.items",
                proxy.id, spec_id
            ));
        }
    }
    for upstream in upstreams {
        if let Some(spec_id) = upstream.api_spec_id.as_deref()
            && !seen_ids.contains(spec_id)
        {
            errors.push(format!(
                "upstream '{}': api_spec_id '{}' is not present in api_specs.items",
                upstream.id, spec_id
            ));
        }
    }
    for plugin in plugin_configs {
        if let Some(spec_id) = plugin.api_spec_id.as_deref()
            && !seen_ids.contains(spec_id)
        {
            errors.push(format!(
                "plugin_config '{}': api_spec_id '{}' is not present in api_specs.items",
                plugin.id, spec_id
            ));
        }
    }

    if errors.is_empty() {
        Ok(specs)
    } else {
        Err(errors)
    }
}

/// Clear ownership tags so restored resources become hand-managed after a
/// confirmed legacy restore that permanently deletes API specs.
pub(crate) fn clear_api_spec_ownership_tags(payload: &mut RestorePayload) {
    for proxy in &mut payload.proxies {
        proxy.api_spec_id = None;
    }
    for upstream in &mut payload.upstreams {
        upstream.api_spec_id = None;
    }
    for plugin in &mut payload.plugin_configs {
        plugin.api_spec_id = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_config() -> GatewayConfig {
        serde_json::from_value(json!({
            "version": "1",
            "known_namespaces": ["tenant-a", "tenant-b"],
            "proxies": [
                {
                    "id": "proxy-a",
                    "namespace": "tenant-a",
                    "listen_path": "/a",
                    "backend_scheme": "http",
                    "backend_host": "a.internal",
                    "backend_port": 8080
                },
                {
                    "id": "proxy-b",
                    "namespace": "tenant-b",
                    "listen_path": "/b",
                    "backend_scheme": "http",
                    "backend_host": "b.internal",
                    "backend_port": 8080
                }
            ],
            "consumers": [
                {"id": "consumer-a", "username": "alice", "namespace": "tenant-a"},
                {"id": "consumer-b", "username": "bob", "namespace": "tenant-b"}
            ],
            "plugin_configs": [
                {
                    "id": "plugin-a",
                    "plugin_name": "key_auth",
                    "namespace": "tenant-a",
                    "scope": "global",
                    "config": {}
                },
                {
                    "id": "plugin-b",
                    "plugin_name": "key_auth",
                    "namespace": "tenant-b",
                    "scope": "global",
                    "config": {}
                }
            ],
            "upstreams": [
                {"id": "upstream-a", "name": "up-a", "namespace": "tenant-a", "targets": []},
                {"id": "upstream-b", "name": "up-b", "namespace": "tenant-b", "targets": []}
            ]
        }))
        .expect("sample config should deserialize")
    }

    #[test]
    fn parse_backup_resources_absent_query_is_unfiltered() {
        assert!(parse_backup_resources(None).is_none());
        assert!(parse_backup_resources(Some("page=1")).is_none());
    }

    #[test]
    fn parse_backup_resources_trims_and_ignores_empty_tokens() {
        let resources =
            parse_backup_resources(Some("download=true&resources=proxies, upstreams,,"))
                .expect("resources filter should parse");

        assert!(resources.contains("proxies"));
        assert!(resources.contains("upstreams"));
        assert_eq!(resources.len(), 2);
    }

    #[test]
    fn parse_restore_confirm_requires_true_value() {
        assert!(!parse_restore_confirm(None));
        assert!(!parse_restore_confirm(Some("confirm=false")));
        assert!(!parse_restore_confirm(Some("confirm=True")));
        assert!(parse_restore_confirm(Some("dry_run=false&confirm=true")));
    }

    #[test]
    fn parse_confirm_api_spec_deletion_requires_true_value() {
        assert!(!parse_confirm_api_spec_deletion(None));
        assert!(!parse_confirm_api_spec_deletion(Some(
            "confirm=true&confirm_api_spec_deletion=false"
        )));
        assert!(parse_confirm_api_spec_deletion(Some(
            "confirm=true&confirm_api_spec_deletion=true"
        )));
    }

    #[test]
    fn filter_config_by_namespace_keeps_only_matching_resources() {
        let filtered = filter_config_by_namespace(&sample_config(), "tenant-a");

        assert_eq!(filtered.version, "1");
        assert_eq!(filtered.known_namespaces, vec!["tenant-a", "tenant-b"]);
        assert_eq!(filtered.proxies.len(), 1);
        assert_eq!(filtered.proxies[0].id, "proxy-a");
        assert_eq!(filtered.consumers.len(), 1);
        assert_eq!(filtered.consumers[0].id, "consumer-a");
        assert_eq!(filtered.plugin_configs.len(), 1);
        assert_eq!(filtered.plugin_configs[0].id, "plugin-a");
        assert_eq!(filtered.upstreams.len(), 1);
        assert_eq!(filtered.upstreams[0].id, "upstream-a");
    }

    #[test]
    fn filter_config_by_namespace_returns_empty_resource_sets_for_miss() {
        let filtered = filter_config_by_namespace(&sample_config(), "tenant-c");

        assert!(filtered.proxies.is_empty());
        assert!(filtered.consumers.is_empty());
        assert!(filtered.plugin_configs.is_empty());
        assert!(filtered.upstreams.is_empty());
        assert_eq!(filtered.known_namespaces, vec!["tenant-a", "tenant-b"]);
    }

    #[test]
    fn api_spec_backup_item_round_trips_base64_content() {
        let content = br#"{"openapi":"3.1.0","info":{"title":"t","version":"1"},"x-ferrum-proxy":{"id":"p"}}"#;
        let compressed = crate::admin::spec_codec::compress_gzip(content).expect("compress");
        let spec = ApiSpec {
            id: "spec-1".to_string(),
            namespace: "ferrum".to_string(),
            proxy_id: "proxy-1".to_string(),
            spec_version: "3.1.0".to_string(),
            spec_format: SpecFormat::Json,
            spec_content: compressed.clone(),
            content_encoding: "gzip".to_string(),
            uncompressed_size: content.len() as u64,
            content_hash: crate::admin::spec_codec::sha256_hex(content),
            title: Some("t".to_string()),
            info_version: Some("1".to_string()),
            description: None,
            contact_name: None,
            contact_email: None,
            license_name: None,
            license_identifier: None,
            tags: vec!["a".to_string()],
            server_urls: vec![],
            operation_count: 0,
            resource_hash: "abc".to_string(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let item = ApiSpecBackupItem::from_api_spec(&spec);
        let restored = item.to_api_spec().expect("decode");
        assert_eq!(restored.spec_content, compressed);
        assert_eq!(restored.content_hash, spec.content_hash);
        assert!(!item.spec_content_base64.is_empty());
        assert!(!item.spec_content_base64.starts_with('['));
    }

    #[test]
    fn restore_payload_distinguishes_omitted_api_specs_section() {
        let legacy: RestorePayload = serde_json::from_value(json!({
            "proxies": []
        }))
        .expect("legacy payload");
        assert!(legacy.api_specs.is_none());

        let present: RestorePayload = serde_json::from_value(json!({
            "proxies": [],
            "api_specs": {
                "section_version": "1",
                "items": []
            }
        }))
        .expect("present section");
        assert!(present.api_specs.is_some());
        assert!(present.api_specs.as_ref().unwrap().items.is_empty());
    }

    fn sample_owned_proxy(spec_id: &str, proxy_id: &str) -> Proxy {
        serde_json::from_value(json!({
            "id": proxy_id,
            "namespace": "ferrum",
            "backend_host": "backend.example.com",
            "backend_port": 443,
            "listen_path": format!("/{proxy_id}"),
            "api_spec_id": spec_id
        }))
        .expect("proxy")
    }

    fn sample_spec_item(spec_id: &str, proxy_id: &str, raw: &[u8]) -> ApiSpecBackupItem {
        let compressed = crate::admin::spec_codec::compress_gzip(raw).expect("compress");
        ApiSpecBackupItem {
            id: spec_id.to_string(),
            namespace: "ferrum".to_string(),
            proxy_id: proxy_id.to_string(),
            spec_version: "3.1.0".to_string(),
            spec_format: SpecFormat::Json,
            spec_content_base64: base64::engine::general_purpose::STANDARD.encode(&compressed),
            content_encoding: "gzip".to_string(),
            uncompressed_size: raw.len() as u64,
            content_hash: crate::admin::spec_codec::sha256_hex(raw),
            title: Some("t".to_string()),
            info_version: Some("1".to_string()),
            description: None,
            contact_name: None,
            contact_email: None,
            license_name: None,
            license_identifier: None,
            tags: vec![],
            server_urls: vec![],
            operation_count: 0,
            resource_hash: "hash".to_string(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn validate_api_specs_section_accepts_json_and_yaml_round_trip_items() {
        let json_raw = br#"{"openapi":"3.1.0","info":{"title":"j","version":"1"},"paths":{}}"#;
        let yaml_raw = b"openapi: \"3.0.3\"\ninfo:\n  title: y\n  version: \"1\"\npaths: {}\n";
        let section = ApiSpecsBackupSection {
            section_version: API_SPECS_BACKUP_SECTION_VERSION.to_string(),
            items: vec![
                sample_spec_item("spec-json", "proxy-json", json_raw),
                {
                    let mut item = sample_spec_item("spec-yaml", "proxy-yaml", yaml_raw);
                    item.spec_format = SpecFormat::Yaml;
                    item.spec_version = "3.0.3".to_string();
                    item
                },
            ],
        };
        let proxies = vec![
            sample_owned_proxy("spec-json", "proxy-json"),
            sample_owned_proxy("spec-yaml", "proxy-yaml"),
        ];
        let specs = validate_restore_api_specs_section(&section, &proxies, &[], &[], 25)
            .expect("valid section");
        assert_eq!(specs.len(), 2);
        assert_eq!(specs[0].spec_format, SpecFormat::Json);
        assert_eq!(specs[1].spec_format, SpecFormat::Yaml);
    }

    #[test]
    fn validate_api_specs_section_rejects_hostile_size_and_shape() {
        let raw = br#"{"openapi":"3.1.0","info":{"title":"t","version":"1"},"paths":{}}"#;
        let mut item = sample_spec_item("spec-1", "proxy-1", raw);
        item.spec_content_base64 = "!!!not-base64!!!".to_string();
        let section = ApiSpecsBackupSection {
            section_version: API_SPECS_BACKUP_SECTION_VERSION.to_string(),
            items: vec![item],
        };
        let proxies = vec![sample_owned_proxy("spec-1", "proxy-1")];
        let err = validate_restore_api_specs_section(&section, &proxies, &[], &[], 25)
            .expect_err("bad base64");
        assert!(err.iter().any(|e| e.contains("invalid spec_content_base64")));

        let mut oversized = sample_spec_item("spec-2", "proxy-2", raw);
        oversized.uncompressed_size = 50 * 1024 * 1024;
        let section = ApiSpecsBackupSection {
            section_version: API_SPECS_BACKUP_SECTION_VERSION.to_string(),
            items: vec![oversized],
        };
        let proxies = vec![sample_owned_proxy("spec-2", "proxy-2")];
        let err = validate_restore_api_specs_section(&section, &proxies, &[], &[], 1)
            .expect_err("oversized");
        assert!(
            err.iter()
                .any(|e| e.contains("uncompressed_size exceeds admin spec body limit"))
        );

        let mut wrong_hash = sample_spec_item("spec-3", "proxy-3", raw);
        wrong_hash.content_hash = "0".repeat(64);
        let section = ApiSpecsBackupSection {
            section_version: API_SPECS_BACKUP_SECTION_VERSION.to_string(),
            items: vec![wrong_hash],
        };
        let proxies = vec![sample_owned_proxy("spec-3", "proxy-3")];
        let err = validate_restore_api_specs_section(&section, &proxies, &[], &[], 25)
            .expect_err("hash mismatch");
        assert!(err.iter().any(|e| e.contains("content_hash does not match")));

        let section = ApiSpecsBackupSection {
            section_version: "99".to_string(),
            items: vec![],
        };
        let err = validate_restore_api_specs_section(&section, &[], &[], &[], 25)
            .expect_err("bad version");
        assert!(err.iter().any(|e| e.contains("Unsupported api_specs.section_version")));
    }

    #[test]
    fn validate_api_specs_section_rejects_orphan_ownership_tags() {
        let raw = br#"{"openapi":"3.1.0","info":{"title":"t","version":"1"},"paths":{}}"#;
        let section = ApiSpecsBackupSection {
            section_version: API_SPECS_BACKUP_SECTION_VERSION.to_string(),
            items: vec![sample_spec_item("spec-1", "proxy-1", raw)],
        };
        let proxies = vec![sample_owned_proxy("spec-1", "proxy-1")];
        let mut upstream: Upstream = serde_json::from_value(json!({
            "id": "up-1",
            "name": "up-1",
            "namespace": "ferrum",
            "targets": [],
            "api_spec_id": "missing-spec"
        }))
        .expect("upstream");
        let err = validate_restore_api_specs_section(&section, &proxies, &[upstream.clone()], &[], 25)
            .expect_err("orphan upstream tag");
        assert!(err.iter().any(|e| e.contains("upstream 'up-1'")));

        upstream.api_spec_id = Some("spec-1".to_string());
        let plugin: PluginConfig = serde_json::from_value(json!({
            "id": "plug-1",
            "plugin_name": "key_auth",
            "namespace": "ferrum",
            "scope": "proxy",
            "proxy_id": "proxy-1",
            "config": {},
            "api_spec_id": "missing-spec"
        }))
        .expect("plugin");
        let err =
            validate_restore_api_specs_section(&section, &proxies, &[upstream], &[plugin], 25)
                .expect_err("orphan plugin tag");
        assert!(err.iter().any(|e| e.contains("plugin_config 'plug-1'")));
    }

    #[test]
    fn clear_api_spec_ownership_tags_strips_all_resource_types() {
        let mut payload: RestorePayload = serde_json::from_value(json!({
            "proxies": [{
                "id": "p1",
                "listen_path": "/p",
                "backend_scheme": "http",
                "backend_host": "localhost",
                "backend_port": 8080,
                "api_spec_id": "s1"
            }],
            "upstreams": [{
                "id": "u1",
                "name": "u1",
                "targets": [],
                "api_spec_id": "s1"
            }],
            "plugin_configs": [{
                "id": "c1",
                "plugin_name": "key_auth",
                "scope": "global",
                "config": {},
                "api_spec_id": "s1"
            }]
        }))
        .expect("payload");
        clear_api_spec_ownership_tags(&mut payload);
        assert!(payload.proxies[0].api_spec_id.is_none());
        assert!(payload.upstreams[0].api_spec_id.is_none());
        assert!(payload.plugin_configs[0].api_spec_id.is_none());
    }
}
