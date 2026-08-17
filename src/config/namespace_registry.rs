//! First-class namespace registry (issue #3955).
//!
//! Historically `GET /namespaces` was a DISTINCT union over resource tables.
//! This module is the durable registry so an empty tenant can exist before any
//! proxy, consumer, plugin, upstream, or trust bundle is written, and so
//! rename/delete have a single object to operate on.
//!
//! `GET /namespaces` remains a paginated list of **name strings**
//! (`data: string[]`) for Foundry and other existing clients. Detail and write
//! operations use [`NamespaceRecord`].

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::config::types::{DEFAULT_NAMESPACE, validate_namespace};

/// Maximum length for an optional namespace description.
pub const MAX_NAMESPACE_DESCRIPTION_LENGTH: usize = 1024;

/// Durable registry row for one tenant namespace.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NamespaceRecord {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl NamespaceRecord {
    pub fn new(name: String, description: Option<String>, now: DateTime<Utc>) -> Self {
        Self {
            name,
            description,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn audit_body(&self) -> serde_json::Value {
        serde_json::json!({
            "name": self.name,
            "description": self.description,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        })
    }
}

/// POST /namespaces body.
#[derive(Debug, Clone, Deserialize)]
pub struct CreateNamespaceRequest {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
}

/// PUT /namespaces/:name body. Omitted fields are left unchanged; JSON
/// `description: null` (or an empty string) clears it.
#[derive(Debug, Clone, Deserialize)]
pub struct UpdateNamespaceBody {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<serde_json::Value>,
}

impl UpdateNamespaceBody {
    pub fn description_update(&self) -> Option<Option<String>> {
        match &self.description {
            None => None,
            Some(serde_json::Value::Null) => Some(None),
            Some(serde_json::Value::String(s)) => {
                let trimmed = s.trim();
                if trimmed.is_empty() {
                    Some(None)
                } else {
                    Some(Some(trimmed.to_string()))
                }
            }
            Some(_) => Some(None),
        }
    }
}

/// Resource tables whose `namespace` column participates in derived listing
/// and rename/delete occupancy. Keep in sync with SQL unions and Mongo
/// `distinct_namespaces` scans.
pub const DERIVED_NAMESPACE_RESOURCE_TABLES: &[&str] = &[
    "proxies",
    "consumers",
    "plugin_configs",
    "upstreams",
    "gateway_trust_bundles",
];

/// Occupancy tables that block an unconfirmed DELETE. Broader than the
/// derived-list union: API specs are admin-only metadata that still live
/// under the tenant.
pub const NAMESPACE_OCCUPANCY_TABLES: &[&str] = &[
    "proxies",
    "consumers",
    "plugin_configs",
    "upstreams",
    "gateway_trust_bundles",
    "api_specs",
];

/// Tables whose `namespace` column is rewritten on rename (SQL). Lock rows
/// that are the admission lease itself (`config_admission_locks`) are
/// excluded — the handler holds both source and target leases.
pub const NAMESPACE_RENAME_SIMPLE_TABLES: &[&str] = &[
    "proxies",
    "plugin_configs",
    "upstreams",
    "api_specs",
    "audit_events",
    "config_changes",
];

pub fn normalize_description(description: Option<String>) -> Result<Option<String>, String> {
    let Some(raw) = description else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.len() > MAX_NAMESPACE_DESCRIPTION_LENGTH {
        return Err(format!(
            "description must be at most {MAX_NAMESPACE_DESCRIPTION_LENGTH} characters"
        ));
    }
    Ok(Some(trimmed.to_string()))
}

pub fn validate_namespace_name(name: &str) -> Result<(), String> {
    validate_namespace(name)
}

/// Process default namespace: `FERRUM_NAMESPACE` when set, otherwise `ferrum`.
pub fn process_default_namespace() -> String {
    std::env::var("FERRUM_NAMESPACE")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_NAMESPACE.to_string())
}

/// Typed persist errors so admin handlers can map to 409 without inspecting
/// driver text.
#[derive(Debug)]
pub enum NamespaceRegistryError {
    NameInUse { name: String },
    NotFound { name: String },
    NotEmpty { name: String },
    Protected { name: String, reason: &'static str },
}

impl std::fmt::Display for NamespaceRegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NameInUse { name } => {
                write!(f, "namespace '{name}' already exists")
            }
            Self::NotFound { name } => write!(f, "namespace '{name}' not found"),
            Self::NotEmpty { name } => write!(
                f,
                "namespace '{name}' still has resources; pass ?confirm=true to cascade-delete them"
            ),
            Self::Protected { name, reason } => {
                write!(f, "namespace '{name}' cannot be deleted: {reason}")
            }
        }
    }
}

impl std::error::Error for NamespaceRegistryError {}

pub fn is_namespace_registry_error(error: &anyhow::Error) -> Option<&NamespaceRegistryError> {
    error.downcast_ref::<NamespaceRegistryError>()
}
