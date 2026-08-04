//! Gateway API `BackendTLSPolicy` watch/index/apply helpers.
//!
//! Policies attach to same-namespace Services and overlay Ferrum upstream
//! `backend_tls_*` fields (SNI, CA trust, SAN allow-list) for Service-backed
//! HTTPRoute/GRPCRoute backends. Invalid or unrepresentable policies fail
//! closed for backends that target the affected Service.

use std::cmp::Ordering;
use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::config::types::{
    Upstream, validate_backend_tls_san_allow_list_entry, validate_backend_tls_sni,
};

use super::{K8sAccumulator, K8sObject, K8sTranslateError, RouteBackend, string_field};

/// Resolved BackendTLSPolicy overlay projected onto an Upstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct BackendTlsPolicyOverlay {
    pub hostname: String,
    /// `None` means `wellKnownCACertificates: System` (webpki/system roots).
    pub ca_bundle_source: Option<String>,
    pub subject_alt_names: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum BackendTlsPolicyRecord {
    Valid(BackendTlsPolicyOverlay),
    Invalid { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IndexedBackendTlsPolicy {
    policy_namespace: String,
    policy_name: String,
    /// Optional Service port name (`targetRefs[].sectionName`).
    section_name: Option<String>,
    creation_timestamp: Option<DateTime<Utc>>,
    record: BackendTlsPolicyRecord,
}

#[derive(Debug, Default)]
pub(super) struct BackendTlsPolicyIndex {
    /// `(service_namespace, service_name)` → candidate policies.
    by_service: HashMap<(String, String), Vec<IndexedBackendTlsPolicy>>,
}

impl BackendTlsPolicyIndex {
    fn insert(
        &mut self,
        service_namespace: String,
        service_name: String,
        entry: IndexedBackendTlsPolicy,
    ) {
        self.by_service
            .entry((service_namespace, service_name))
            .or_default()
            .push(entry);
    }
}

/// Collect one BackendTLSPolicy into the accumulator index.
///
/// Structural and validation failures are recorded as warnings and indexed as
/// `Invalid` (or skipped) so a single bad policy cannot abort the whole
/// Kubernetes snapshot translation.
pub(super) fn collect(
    acc: &mut K8sAccumulator,
    object: &K8sObject,
) -> Result<(), K8sTranslateError> {
    let Some(target_refs) = object.spec.get("targetRefs").and_then(Value::as_array) else {
        acc.warnings.push(format!(
            "Gateway API BackendTLSPolicy {}/{} ignored: spec.targetRefs is required",
            object.metadata.namespace, object.metadata.name
        ));
        return Ok(());
    };
    if target_refs.is_empty() {
        acc.warnings.push(format!(
            "Gateway API BackendTLSPolicy {}/{} ignored: spec.targetRefs must contain at least one entry",
            object.metadata.namespace, object.metadata.name
        ));
        return Ok(());
    }

    let record = match object.spec.get("validation") {
        None => {
            let reason = "spec.validation is required".to_string();
            acc.warnings.push(format!(
                "Gateway API BackendTLSPolicy {}/{} is invalid: {reason}",
                object.metadata.namespace, object.metadata.name
            ));
            BackendTlsPolicyRecord::Invalid { reason }
        }
        Some(validation) => match parse_validation(acc, object, validation) {
            Ok(overlay) => BackendTlsPolicyRecord::Valid(overlay),
            Err(reason) => {
                acc.warnings.push(format!(
                    "Gateway API BackendTLSPolicy {}/{} is invalid: {reason}",
                    object.metadata.namespace, object.metadata.name
                ));
                BackendTlsPolicyRecord::Invalid { reason }
            }
        },
    };

    let creation_timestamp = object
        .metadata
        .creation_timestamp
        .as_deref()
        .and_then(|ts| DateTime::parse_from_rfc3339(ts).ok())
        .map(|ts| ts.with_timezone(&Utc));

    for target_ref in target_refs {
        match parse_service_target_ref(acc, object, target_ref) {
            Ok(Some((service_name, section_name))) => {
                acc.backend_tls_policies.insert(
                    object.metadata.namespace.clone(),
                    service_name,
                    IndexedBackendTlsPolicy {
                        policy_namespace: object.metadata.namespace.clone(),
                        policy_name: object.metadata.name.clone(),
                        section_name,
                        creation_timestamp,
                        record: record.clone(),
                    },
                );
            }
            Ok(None) => {}
            Err(message) => {
                acc.warnings.push(format!(
                    "Gateway API BackendTLSPolicy {}/{} targetRef skipped: {message}",
                    object.metadata.namespace, object.metadata.name
                ));
            }
        }
    }
    Ok(())
}

fn parse_service_target_ref(
    acc: &mut K8sAccumulator,
    object: &K8sObject,
    target_ref: &Value,
) -> Result<Option<(String, Option<String>)>, String> {
    let group = string_field(target_ref, "group").unwrap_or("");
    let kind = string_field(target_ref, "kind").unwrap_or("Service");
    if !group.is_empty() || kind != "Service" {
        acc.warnings.push(format!(
            "Gateway API BackendTLSPolicy {}/{} ignores unsupported targetRef group='{group}' kind='{kind}' (only core Service)",
            object.metadata.namespace, object.metadata.name
        ));
        return Ok(None);
    }
    if let Some(namespace) = string_field(target_ref, "namespace")
        && namespace != object.metadata.namespace
    {
        return Err(
            "spec.targetRefs[].namespace must match the BackendTLSPolicy namespace (cross-namespace targets are invalid)"
                .to_string(),
        );
    }
    let name = string_field(target_ref, "name")
        .ok_or_else(|| "spec.targetRefs[].name is required for Service targets".to_string())?;
    let section_name = string_field(target_ref, "sectionName")
        .filter(|name| !name.is_empty())
        .map(str::to_string);
    Ok(Some((name.to_string(), section_name)))
}

fn parse_validation(
    acc: &K8sAccumulator,
    object: &K8sObject,
    validation: &Value,
) -> Result<BackendTlsPolicyOverlay, String> {
    let hostname = string_field(validation, "hostname")
        .ok_or_else(|| "spec.validation.hostname is required".to_string())?;
    validate_backend_tls_sni(hostname).map_err(|e| format!("spec.validation.hostname: {e}"))?;

    let well_known = string_field(validation, "wellKnownCACertificates");
    let ca_refs = validation
        .get("caCertificateRefs")
        .and_then(Value::as_array);
    let has_ca_refs = ca_refs.is_some_and(|refs| !refs.is_empty());

    let ca_bundle_source = if let Some(value) = well_known.filter(|value| !value.is_empty()) {
        if has_ca_refs {
            return Err(
                "spec.validation must not set both caCertificateRefs and wellKnownCACertificates"
                    .to_string(),
            );
        }
        if value != "System" {
            return Err(format!(
                "spec.validation.wellKnownCACertificates value '{value}' is unsupported (only System)"
            ));
        }
        None
    } else if let Some(refs) = ca_refs.filter(|refs| !refs.is_empty()) {
        if refs.len() > 8 {
            return Err(
                "spec.validation.caCertificateRefs must have at most 8 entries".to_string(),
            );
        }
        // Ferrum projects a single exclusive CA bundle path today. Multiple
        // refs are accepted only when they resolve to one usable source; more
        // than one distinct source fails closed rather than silently merging.
        let mut sources = Vec::new();
        for (index, reference) in refs.iter().enumerate() {
            match resolve_ca_certificate_ref(acc, object, reference) {
                Ok(source) => sources.push(source),
                Err(reason) => {
                    return Err(format!(
                        "spec.validation.caCertificateRefs[{index}]: {reason}"
                    ));
                }
            }
        }
        sources.sort();
        sources.dedup();
        if sources.len() != 1 {
            return Err(
                "spec.validation.caCertificateRefs must resolve to exactly one CA bundle source"
                    .to_string(),
            );
        }
        Some(sources.remove(0))
    } else {
        return Err(
            "spec.validation requires caCertificateRefs or wellKnownCACertificates".to_string(),
        );
    };

    let subject_alt_names = parse_subject_alt_names(validation)?;

    Ok(BackendTlsPolicyOverlay {
        hostname: hostname.to_ascii_lowercase(),
        ca_bundle_source,
        subject_alt_names,
    })
}

fn resolve_ca_certificate_ref(
    acc: &K8sAccumulator,
    object: &K8sObject,
    reference: &Value,
) -> Result<String, String> {
    let group = string_field(reference, "group").unwrap_or("");
    if !group.is_empty() {
        return Err(format!(
            "group '{group}' is unsupported (only core ConfigMap/Secret)"
        ));
    }
    let kind = string_field(reference, "kind").unwrap_or("ConfigMap");
    let name = string_field(reference, "name").ok_or_else(|| "name is required".to_string())?;
    if let Some(namespace) = string_field(reference, "namespace")
        && namespace != object.metadata.namespace
    {
        return Err(
            "cross-namespace caCertificateRefs are invalid; omit namespace or match the policy namespace"
                .to_string(),
        );
    }
    let namespace = object.metadata.namespace.as_str();

    match kind {
        "ConfigMap" => {
            let pem = acc.configmap_ca_bundle_pem(namespace, name).ok_or_else(|| {
                format!(
                    "ConfigMap '{namespace}/{name}' is missing or has no usable data.ca.crt PEM bundle"
                )
            })?;
            Ok(pem.to_string())
        }
        "Secret" => {
            let digest = acc.secret_ca_bundle_digest(namespace, name).ok_or_else(|| {
                format!(
                    "Secret '{namespace}/{name}' is missing or has no usable data.ca.crt PEM bundle"
                )
            })?;
            Ok(format!("k8s://{namespace}/{name}#ca.crt?sha256={digest}"))
        }
        other => Err(format!(
            "kind '{other}' is unsupported (only ConfigMap or Secret)"
        )),
    }
}

fn parse_subject_alt_names(validation: &Value) -> Result<Vec<String>, String> {
    let Some(entries) = validation.get("subjectAltNames").and_then(Value::as_array) else {
        return Ok(Vec::new());
    };
    if entries.len() > 5 {
        return Err("spec.validation.subjectAltNames must have at most 5 entries".to_string());
    }
    let mut out = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let san_type = string_field(entry, "type").unwrap_or_default();
        let value = match san_type {
            "Hostname" => string_field(entry, "hostname")
                .ok_or_else(|| {
                    format!("spec.validation.subjectAltNames[{index}].hostname is required")
                })?
                .to_string(),
            "URI" => string_field(entry, "uri")
                .ok_or_else(|| format!("spec.validation.subjectAltNames[{index}].uri is required"))?
                .to_string(),
            other => {
                return Err(format!(
                    "spec.validation.subjectAltNames[{index}].type '{other}' is unsupported"
                ));
            }
        };
        validate_backend_tls_san_allow_list_entry(&value)
            .map_err(|e| format!("spec.validation.subjectAltNames[{index}]: {e}"))?;
        out.push(value);
    }
    Ok(out)
}

/// Lookup outcome for backends that reference a Service with BackendTLSPolicy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum BackendTlsPolicyLookup {
    /// No policy targets this Service/port.
    None,
    /// Apply this overlay (enables HTTPS + SNI/CA/SAN).
    Apply(BackendTlsPolicyOverlay),
    /// A policy targets this Service/port but is invalid or conflicting.
    Fault { reason: String },
}

fn compare_creation_timestamps(
    left: &Option<DateTime<Utc>>,
    right: &Option<DateTime<Utc>>,
) -> Ordering {
    match (left, right) {
        (Some(left_ts), Some(right_ts)) => left_ts.cmp(right_ts),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

pub(super) fn lookup_for_service(
    acc: &K8sAccumulator,
    service_namespace: &str,
    service_name: &str,
    service_port: Option<u16>,
) -> BackendTlsPolicyLookup {
    let Some(entries) = acc
        .backend_tls_policies
        .by_service
        .get(&(service_namespace.to_string(), service_name.to_string()))
    else {
        return BackendTlsPolicyLookup::None;
    };
    if entries.is_empty() {
        return BackendTlsPolicyLookup::None;
    }

    let port_name = service_port
        .and_then(|port| acc.lookup_service_port_name(service_namespace, service_name, port));

    let mut matching: Vec<&IndexedBackendTlsPolicy> = entries
        .iter()
        .filter(|entry| match (entry.section_name.as_deref(), port_name) {
            (None, _) => true,
            (Some(section), Some(name)) => section == name,
            (Some(_), None) => false,
        })
        .collect();

    if matching.is_empty() {
        // sectionName-scoped policies exist but none match this port — treat as
        // no policy for this backend rather than applying a mismatched port TLS
        // identity.
        return BackendTlsPolicyLookup::None;
    }

    matching.sort_by(|left, right| {
        // Prefer section-scoped policies over wildcard (no sectionName).
        let left_specific = left.section_name.is_some();
        let right_specific = right.section_name.is_some();
        match (left_specific, right_specific) {
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            _ => compare_creation_timestamps(&left.creation_timestamp, &right.creation_timestamp)
                .then_with(|| {
                    (&left.policy_namespace, &left.policy_name)
                        .cmp(&(&right.policy_namespace, &right.policy_name))
                }),
        }
    });

    let winner = matching[0];
    match &winner.record {
        BackendTlsPolicyRecord::Valid(overlay) => BackendTlsPolicyLookup::Apply(overlay.clone()),
        BackendTlsPolicyRecord::Invalid { reason } => BackendTlsPolicyLookup::Fault {
            reason: format!(
                "BackendTLSPolicy {}/{}: {reason}",
                winner.policy_namespace, winner.policy_name
            ),
        },
    }
}

/// Resolve a single BackendTLSPolicy overlay for a set of route backends.
///
/// Returns `None` when no Service-backed backend carries a policy. Conflicting
/// valid overlays or any invalid policy on a referenced Service fail closed.
pub(super) fn resolve_backends_tls_policy(
    acc: &mut K8sAccumulator,
    backends: &[RouteBackend],
) -> BackendTlsPolicyLookup {
    let mut selected: Option<BackendTlsPolicyOverlay> = None;
    for backend in backends {
        let (Some(namespace), Some(name)) = (
            backend.service_namespace.as_deref(),
            backend.service_name.as_deref(),
        ) else {
            continue;
        };
        match lookup_for_service(acc, namespace, name, backend.service_port) {
            BackendTlsPolicyLookup::None => {}
            BackendTlsPolicyLookup::Fault { reason } => {
                acc.warnings.push(format!(
                    "Gateway API BackendTLSPolicy for Service {namespace}/{name} fails closed: {reason}"
                ));
                return BackendTlsPolicyLookup::Fault { reason };
            }
            BackendTlsPolicyLookup::Apply(overlay) => match &selected {
                None => selected = Some(overlay),
                Some(existing) if existing == &overlay => {}
                Some(_) => {
                    let reason = format!(
                        "conflicting BackendTLSPolicy overlays across backends including Service {namespace}/{name}"
                    );
                    acc.warnings.push(format!(
                        "Gateway API BackendTLSPolicy fails closed: {reason}"
                    ));
                    return BackendTlsPolicyLookup::Fault { reason };
                }
            },
        }
    }
    match selected {
        Some(overlay) => BackendTlsPolicyLookup::Apply(overlay),
        None => BackendTlsPolicyLookup::None,
    }
}

pub(super) fn apply_to_upstream(upstream: &mut Upstream, overlay: &BackendTlsPolicyOverlay) {
    upstream.backend_tls_verify_server_cert = true;
    upstream.backend_tls_client_cert_path = None;
    upstream.backend_tls_client_key_path = None;
    upstream.backend_tls_server_ca_cert_path = overlay.ca_bundle_source.clone();
    upstream.backend_tls_sni = Some(overlay.hostname.clone());
    upstream.backend_tls_san_allow_list = overlay.subject_alt_names.clone();
}
