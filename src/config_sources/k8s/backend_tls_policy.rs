//! Gateway API `BackendTLSPolicy` watch/index/apply helpers.
//!
//! Policies attach to same-namespace Services and overlay Ferrum upstream
//! `backend_tls_*` fields (SNI, CA trust, SAN allow-list) for Service-backed
//! HTTPRoute/GRPCRoute backends. Invalid or unrepresentable policies fail
//! closed for backends that target the affected Service.
//!
//! Two boundaries are load-bearing and deliberately explicit here:
//!
//! * `wellKnownCACertificates: System` projects the first-class
//!   [`SYSTEM_TRUST_ROOTS_SOURCE`] sentinel, never `None`. `None` means "no
//!   backend CA configured", which Ferrum's documented trust chain resolves to
//!   the cluster-global `FERRUM_TLS_CA_BUNDLE_PATH` — so a cluster-wide private
//!   CA would silently replace the public trust anchors the policy asked for.
//! * A route whose backend set MIXES policy-covered and uncovered targets fails
//!   closed. Ferrum encodes one backend scheme and one TLS identity per
//!   `Upstream`, so applying the overlay to the combined upstream would
//!   originate TLS (with the covered Service's SNI and trust) to a Service that
//!   no policy covers.

use std::cmp::Ordering;
use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::config::types::{
    Upstream, validate_backend_tls_san_allow_list_entry, validate_backend_tls_sni,
};
use crate::tls::source::SYSTEM_TRUST_ROOTS_SOURCE;

use super::{
    GatewayApiBackendTlsPolicyStatus, K8sAccumulator, K8sObject, K8sResourceKey, K8sTranslateError,
    RouteBackend, string_field,
};

/// Maximum admitted `caCertificateRefs` entries. Bounds hostile input before
/// any ConfigMap/Secret resolution work.
const MAX_CA_CERTIFICATE_REFS: usize = 8;
/// Maximum admitted `subjectAltNames` entries, matching Ferrum's own
/// `backend_tls_san_allow_list` ceiling.
const MAX_SUBJECT_ALT_NAMES: usize = 5;

/// Resolved BackendTLSPolicy overlay projected onto an Upstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct BackendTlsPolicyOverlay {
    pub hostname: String,
    /// Configured backend CA source. Either resolved ConfigMap/Secret material
    /// or [`SYSTEM_TRUST_ROOTS_SOURCE`] for `wellKnownCACertificates: System`.
    /// Never `None` — see the module docs.
    pub ca_bundle_source: String,
    pub subject_alt_names: Vec<String>,
}

/// Why a BackendTLSPolicy could not be represented, classified against the
/// Gateway API `PolicyCondition` reason vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BackendTlsPolicyRejection {
    /// The policy itself is malformed or unrepresentable
    /// (`Accepted=False`, `reason: Invalid`).
    Invalid,
    /// A `caCertificateRefs` entry names a ConfigMap/Secret that is missing or
    /// carries no usable `ca.crt` PEM bundle
    /// (`ResolvedRefs=False`, `reason: InvalidCACertificateRef`).
    InvalidCaCertificateRef,
    /// A `caCertificateRefs` entry names an unsupported group/kind
    /// (`ResolvedRefs=False`, `reason: InvalidKind`).
    InvalidKind,
    /// A cross-namespace reference Ferrum does not permit
    /// (`ResolvedRefs=False`, `reason: RefNotPermitted`).
    RefNotPermitted,
}

impl BackendTlsPolicyRejection {
    /// Whether this rejection is about a *reference* (surfaces on
    /// `ResolvedRefs`) rather than the policy body (surfaces on `Accepted`).
    fn is_reference_failure(self) -> bool {
        !matches!(self, Self::Invalid)
    }

    fn resolved_refs_reason(self) -> &'static str {
        match self {
            Self::Invalid => "ResolvedRefs",
            Self::InvalidCaCertificateRef => "InvalidCACertificateRef",
            Self::InvalidKind => "InvalidKind",
            Self::RefNotPermitted => "RefNotPermitted",
        }
    }
}

/// A classified parse failure: the condition reason plus a sanitized,
/// field-specific message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct BackendTlsPolicyError {
    kind: BackendTlsPolicyRejection,
    message: String,
}

impl BackendTlsPolicyError {
    fn invalid(message: impl Into<String>) -> Self {
        Self {
            kind: BackendTlsPolicyRejection::Invalid,
            message: message.into(),
        }
    }

    fn of(kind: BackendTlsPolicyRejection, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum BackendTlsPolicyRecord {
    Valid(BackendTlsPolicyOverlay),
    Invalid(BackendTlsPolicyError),
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
/// Kubernetes snapshot translation. Every outcome also records a status
/// projection so the Gateway API status writer can report it on
/// `status.ancestors` without retranslating.
pub(super) fn collect(
    acc: &mut K8sAccumulator,
    object: &K8sObject,
) -> Result<(), K8sTranslateError> {
    let Some(target_refs) = object.spec.get("targetRefs").and_then(Value::as_array) else {
        let message = "spec.targetRefs is required".to_string();
        acc.warnings.push(format!(
            "Gateway API BackendTLSPolicy {}/{} is invalid: {message}",
            object.metadata.namespace, object.metadata.name
        ));
        record_status(
            acc,
            object,
            Err(&BackendTlsPolicyError::invalid(message)),
            Vec::new(),
            false,
        );
        return Ok(());
    };
    if target_refs.is_empty() {
        let message = "spec.targetRefs must contain at least one entry".to_string();
        acc.warnings.push(format!(
            "Gateway API BackendTLSPolicy {}/{} is invalid: {message}",
            object.metadata.namespace, object.metadata.name
        ));
        record_status(
            acc,
            object,
            Err(&BackendTlsPolicyError::invalid(message)),
            Vec::new(),
            false,
        );
        return Ok(());
    }

    let parsed = match object.spec.get("validation") {
        None => Err(BackendTlsPolicyError::invalid(
            "spec.validation is required",
        )),
        Some(validation) => parse_validation(acc, object, validation),
    };
    if let Err(error) = &parsed {
        acc.warnings.push(format!(
            "Gateway API BackendTLSPolicy {}/{} is invalid: {}",
            object.metadata.namespace, object.metadata.name, error.message
        ));
    }
    let record = match &parsed {
        Ok(overlay) => BackendTlsPolicyRecord::Valid(overlay.clone()),
        Err(error) => BackendTlsPolicyRecord::Invalid(error.clone()),
    };

    let creation_timestamp = object
        .metadata
        .creation_timestamp
        .as_deref()
        .and_then(|ts| DateTime::parse_from_rfc3339(ts).ok())
        .map(|ts| ts.with_timezone(&Utc));

    let mut target_services: Vec<(String, String)> = Vec::new();
    let mut any_target_resolved = false;
    for target_ref in target_refs {
        match parse_service_target_ref(acc, object, target_ref) {
            Ok(Some((service_name, section_name))) => {
                any_target_resolved = true;
                let namespace = object.metadata.namespace.clone();
                if !target_services
                    .iter()
                    .any(|(ns, name)| ns == &namespace && name == &service_name)
                {
                    target_services.push((namespace.clone(), service_name.clone()));
                }
                acc.backend_tls_policies.insert(
                    namespace.clone(),
                    service_name,
                    IndexedBackendTlsPolicy {
                        policy_namespace: namespace,
                        policy_name: object.metadata.name.clone(),
                        section_name,
                        creation_timestamp,
                        record: record.clone(),
                    },
                );
            }
            Ok(None) => {}
            Err(error) => {
                acc.warnings.push(format!(
                    "Gateway API BackendTLSPolicy {}/{} targetRef skipped: {}",
                    object.metadata.namespace, object.metadata.name, error.message
                ));
            }
        }
    }

    record_status(
        acc,
        object,
        parsed.as_ref().map(|_| ()),
        target_services,
        any_target_resolved,
    );
    Ok(())
}

/// Project one policy's translation outcome into the status the Gateway API
/// status writer publishes on `status.ancestors[].conditions`.
fn record_status(
    acc: &mut K8sAccumulator,
    object: &K8sObject,
    parsed: Result<(), &BackendTlsPolicyError>,
    target_services: Vec<(String, String)>,
    any_target_resolved: bool,
) {
    let targets_exist = target_services
        .iter()
        .any(|(namespace, name)| acc.service_exists(namespace, name));
    let status = match parsed {
        Ok(()) if !any_target_resolved => GatewayApiBackendTlsPolicyStatus {
            policy: K8sResourceKey::from_object(object),
            accepted: false,
            accepted_reason: "TargetNotFound".to_string(),
            accepted_message:
                "Ferrum found no supported core Service targetRef on this BackendTLSPolicy"
                    .to_string(),
            resolved_refs: true,
            resolved_refs_reason: "ResolvedRefs".to_string(),
            resolved_refs_message: "All BackendTLSPolicy references accepted by Ferrum".to_string(),
            target_services,
        },
        Ok(()) if !targets_exist => GatewayApiBackendTlsPolicyStatus {
            policy: K8sResourceKey::from_object(object),
            accepted: false,
            accepted_reason: "TargetNotFound".to_string(),
            accepted_message:
                "Ferrum did not observe any Service named by this BackendTLSPolicy targetRefs"
                    .to_string(),
            resolved_refs: true,
            resolved_refs_reason: "ResolvedRefs".to_string(),
            resolved_refs_message: "All BackendTLSPolicy references accepted by Ferrum".to_string(),
            target_services,
        },
        Ok(()) => GatewayApiBackendTlsPolicyStatus {
            policy: K8sResourceKey::from_object(object),
            accepted: true,
            accepted_reason: "Accepted".to_string(),
            accepted_message: "Ferrum accepted this BackendTLSPolicy".to_string(),
            resolved_refs: true,
            resolved_refs_reason: "ResolvedRefs".to_string(),
            resolved_refs_message: "All BackendTLSPolicy references accepted by Ferrum".to_string(),
            target_services,
        },
        Err(error) => {
            let reference_failure = error.kind.is_reference_failure();
            GatewayApiBackendTlsPolicyStatus {
                policy: K8sResourceKey::from_object(object),
                accepted: false,
                accepted_reason: "Invalid".to_string(),
                accepted_message: format!(
                    "Ferrum rejected this BackendTLSPolicy and fails matching backends closed: {}",
                    error.message
                ),
                resolved_refs: !reference_failure,
                resolved_refs_reason: error.kind.resolved_refs_reason().to_string(),
                resolved_refs_message: if reference_failure {
                    error.message.clone()
                } else {
                    "All BackendTLSPolicy references accepted by Ferrum".to_string()
                },
                target_services,
            }
        }
    };
    acc.record_backend_tls_policy_status(status);
}

fn parse_service_target_ref(
    acc: &mut K8sAccumulator,
    object: &K8sObject,
    target_ref: &Value,
) -> Result<Option<(String, Option<String>)>, BackendTlsPolicyError> {
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
        return Err(BackendTlsPolicyError::of(
            BackendTlsPolicyRejection::RefNotPermitted,
            "spec.targetRefs[].namespace must match the BackendTLSPolicy namespace (cross-namespace targets are invalid)",
        ));
    }
    let name = string_field(target_ref, "name").ok_or_else(|| {
        BackendTlsPolicyError::invalid("spec.targetRefs[].name is required for Service targets")
    })?;
    let section_name = string_field(target_ref, "sectionName")
        .filter(|name| !name.is_empty())
        .map(str::to_string);
    Ok(Some((name.to_string(), section_name)))
}

fn parse_validation(
    acc: &K8sAccumulator,
    object: &K8sObject,
    validation: &Value,
) -> Result<BackendTlsPolicyOverlay, BackendTlsPolicyError> {
    let hostname = string_field(validation, "hostname")
        .ok_or_else(|| BackendTlsPolicyError::invalid("spec.validation.hostname is required"))?;
    validate_backend_tls_sni(hostname)
        .map_err(|e| BackendTlsPolicyError::invalid(format!("spec.validation.hostname: {e}")))?;

    let well_known = string_field(validation, "wellKnownCACertificates");
    let ca_refs = validation
        .get("caCertificateRefs")
        .and_then(Value::as_array);
    let has_ca_refs = ca_refs.is_some_and(|refs| !refs.is_empty());

    let ca_bundle_source = if let Some(value) = well_known.filter(|value| !value.is_empty()) {
        if has_ca_refs {
            return Err(BackendTlsPolicyError::invalid(
                "spec.validation must not set both caCertificateRefs and wellKnownCACertificates",
            ));
        }
        if value != "System" {
            return Err(BackendTlsPolicyError::invalid(format!(
                "spec.validation.wellKnownCACertificates value '{value}' is unsupported (only System)"
            )));
        }
        // `System` is a distinct trust posture, not "unset". Projecting `None`
        // here would let Ferrum's backend CA chain fall through to the
        // cluster-global `FERRUM_TLS_CA_BUNDLE_PATH`, so a cluster-wide private
        // CA could silently replace the public roots this policy demanded.
        SYSTEM_TRUST_ROOTS_SOURCE.to_string()
    } else if let Some(refs) = ca_refs.filter(|refs| !refs.is_empty()) {
        if refs.len() > MAX_CA_CERTIFICATE_REFS {
            return Err(BackendTlsPolicyError::invalid(format!(
                "spec.validation.caCertificateRefs must have at most {MAX_CA_CERTIFICATE_REFS} entries"
            )));
        }
        // Ferrum projects a single exclusive CA bundle path today. Multiple
        // refs are accepted only when they resolve to one usable source; more
        // than one distinct source fails closed rather than silently merging.
        let mut sources = Vec::new();
        for (index, reference) in refs.iter().enumerate() {
            match resolve_ca_certificate_ref(acc, object, reference) {
                Ok(source) => sources.push(source),
                Err(error) => {
                    return Err(BackendTlsPolicyError::of(
                        error.kind,
                        format!(
                            "spec.validation.caCertificateRefs[{index}]: {}",
                            error.message
                        ),
                    ));
                }
            }
        }
        sources.sort();
        sources.dedup();
        if sources.len() != 1 {
            return Err(BackendTlsPolicyError::invalid(
                "spec.validation.caCertificateRefs must resolve to exactly one CA bundle source",
            ));
        }
        sources.remove(0)
    } else {
        return Err(BackendTlsPolicyError::invalid(
            "spec.validation requires caCertificateRefs or wellKnownCACertificates",
        ));
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
) -> Result<String, BackendTlsPolicyError> {
    let group = string_field(reference, "group").unwrap_or("");
    if !group.is_empty() {
        return Err(BackendTlsPolicyError::of(
            BackendTlsPolicyRejection::InvalidKind,
            format!("group '{group}' is unsupported (only core ConfigMap/Secret)"),
        ));
    }
    let kind = string_field(reference, "kind").unwrap_or("ConfigMap");
    let name = string_field(reference, "name").ok_or_else(|| {
        BackendTlsPolicyError::of(BackendTlsPolicyRejection::InvalidKind, "name is required")
    })?;
    if let Some(namespace) = string_field(reference, "namespace")
        && namespace != object.metadata.namespace
    {
        return Err(BackendTlsPolicyError::of(
            BackendTlsPolicyRejection::RefNotPermitted,
            "cross-namespace caCertificateRefs are invalid; omit namespace or match the policy namespace",
        ));
    }
    let namespace = object.metadata.namespace.as_str();

    match kind {
        "ConfigMap" => {
            let pem = acc.configmap_ca_bundle_pem(namespace, name).ok_or_else(|| {
                BackendTlsPolicyError::of(
                    BackendTlsPolicyRejection::InvalidCaCertificateRef,
                    format!(
                        "ConfigMap '{namespace}/{name}' is missing or has no usable data.ca.crt PEM bundle"
                    ),
                )
            })?;
            Ok(pem.to_string())
        }
        "Secret" => {
            let digest = acc.secret_ca_bundle_digest(namespace, name).ok_or_else(|| {
                BackendTlsPolicyError::of(
                    BackendTlsPolicyRejection::InvalidCaCertificateRef,
                    format!(
                        "Secret '{namespace}/{name}' is missing or has no usable data.ca.crt PEM bundle"
                    ),
                )
            })?;
            Ok(format!("k8s://{namespace}/{name}#ca.crt?sha256={digest}"))
        }
        other => Err(BackendTlsPolicyError::of(
            BackendTlsPolicyRejection::InvalidKind,
            format!("kind '{other}' is unsupported (only ConfigMap or Secret)"),
        )),
    }
}

fn parse_subject_alt_names(validation: &Value) -> Result<Vec<String>, BackendTlsPolicyError> {
    let Some(entries) = validation.get("subjectAltNames").and_then(Value::as_array) else {
        return Ok(Vec::new());
    };
    if entries.len() > MAX_SUBJECT_ALT_NAMES {
        return Err(BackendTlsPolicyError::invalid(format!(
            "spec.validation.subjectAltNames must have at most {MAX_SUBJECT_ALT_NAMES} entries"
        )));
    }
    let mut out = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let san_type = string_field(entry, "type").unwrap_or_default();
        let value = match san_type {
            "Hostname" => string_field(entry, "hostname")
                .ok_or_else(|| {
                    BackendTlsPolicyError::invalid(format!(
                        "spec.validation.subjectAltNames[{index}].hostname is required"
                    ))
                })?
                .to_string(),
            "URI" => string_field(entry, "uri")
                .ok_or_else(|| {
                    BackendTlsPolicyError::invalid(format!(
                        "spec.validation.subjectAltNames[{index}].uri is required"
                    ))
                })?
                .to_string(),
            other => {
                return Err(BackendTlsPolicyError::invalid(format!(
                    "spec.validation.subjectAltNames[{index}].type '{other}' is unsupported"
                )));
            }
        };
        validate_backend_tls_san_allow_list_entry(&value).map_err(|e| {
            BackendTlsPolicyError::invalid(format!("spec.validation.subjectAltNames[{index}]: {e}"))
        })?;
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
    /// A policy targets this Service/port but is invalid, conflicting, or
    /// covers only part of the rule's backend set.
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
        BackendTlsPolicyRecord::Invalid(error) => BackendTlsPolicyLookup::Fault {
            reason: format!(
                "BackendTLSPolicy {}/{}: {}",
                winner.policy_namespace, winner.policy_name, error.message
            ),
        },
    }
}

/// Human-readable identity of a route backend for a sanitized diagnostic.
///
/// Only translator-derived identity (Service coordinates, or the resolved
/// backend host/port) is emitted — never raw spec text.
fn backend_target_label(backend: &RouteBackend) -> String {
    match (
        backend.service_namespace.as_deref(),
        backend.service_name.as_deref(),
    ) {
        (Some(namespace), Some(name)) => match backend.service_port {
            Some(port) => format!("Service {namespace}/{name}:{port}"),
            None => format!("Service {namespace}/{name}"),
        },
        _ => format!("backend {}:{}", backend.host, backend.port),
    }
}

/// Resolve a single BackendTLSPolicy overlay for a set of route backends.
///
/// Returns `None` when no backend carries a policy. Any of the following fails
/// closed instead of silently widening or narrowing TLS:
///
/// * an invalid/unrepresentable policy on a referenced Service;
/// * two backends whose valid overlays disagree (one Upstream carries one TLS
///   identity);
/// * a **mixed** set where at least one backend is policy-covered and at least
///   one is not. Ferrum folds a rule's backends into one `Upstream` with one
///   `backend_scheme` and one `backend_tls_*` identity, so applying the overlay
///   would originate TLS — with the covered Service's SNI and trust anchors —
///   to a Service no policy covers, and dropping it would silently ignore an
///   explicitly requested TLS policy. Neither is safe, so the rule aborts.
pub(super) fn resolve_backends_tls_policy(
    acc: &mut K8sAccumulator,
    backends: &[RouteBackend],
) -> BackendTlsPolicyLookup {
    let mut selected: Option<BackendTlsPolicyOverlay> = None;
    let mut covered_label: Option<String> = None;
    let mut uncovered_label: Option<String> = None;
    for backend in backends {
        let lookup = match (
            backend.service_namespace.as_deref(),
            backend.service_name.as_deref(),
        ) {
            (Some(namespace), Some(name)) => {
                lookup_for_service(acc, namespace, name, backend.service_port)
            }
            // A backend Ferrum could not resolve to a Service identity can
            // never be policy-covered, so it counts as uncovered rather than
            // being skipped: skipping it is exactly how a mixed set used to
            // become uniformly HTTPS.
            _ => BackendTlsPolicyLookup::None,
        };
        match lookup {
            BackendTlsPolicyLookup::None => {
                if uncovered_label.is_none() {
                    uncovered_label = Some(backend_target_label(backend));
                }
            }
            BackendTlsPolicyLookup::Fault { reason } => {
                acc.warnings.push(format!(
                    "Gateway API BackendTLSPolicy for {} fails closed: {reason}",
                    backend_target_label(backend)
                ));
                return BackendTlsPolicyLookup::Fault { reason };
            }
            BackendTlsPolicyLookup::Apply(overlay) => {
                if covered_label.is_none() {
                    covered_label = Some(backend_target_label(backend));
                }
                match &selected {
                    None => selected = Some(overlay),
                    Some(existing) if existing == &overlay => {}
                    Some(_) => {
                        let reason = format!(
                            "conflicting BackendTLSPolicy overlays across backends including {}",
                            backend_target_label(backend)
                        );
                        acc.warnings.push(format!(
                            "Gateway API BackendTLSPolicy fails closed: {reason}"
                        ));
                        return BackendTlsPolicyLookup::Fault { reason };
                    }
                }
            }
        }
    }

    match (selected, covered_label, uncovered_label) {
        (Some(_), Some(covered), Some(uncovered)) => {
            let reason = format!(
                "spec.rules[].backendRefs mixes BackendTLSPolicy-covered and uncovered backends ({covered} is covered, {uncovered} is not); Ferrum cannot encode per-backend TLS identity in one upstream"
            );
            acc.warnings.push(format!(
                "Gateway API BackendTLSPolicy fails closed: {reason}"
            ));
            BackendTlsPolicyLookup::Fault { reason }
        }
        (Some(overlay), _, _) => BackendTlsPolicyLookup::Apply(overlay),
        (None, _, _) => BackendTlsPolicyLookup::None,
    }
}

pub(super) fn apply_to_upstream(upstream: &mut Upstream, overlay: &BackendTlsPolicyOverlay) {
    upstream.backend_tls_verify_server_cert = true;
    upstream.backend_tls_client_cert_path = None;
    upstream.backend_tls_client_key_path = None;
    upstream.backend_tls_server_ca_cert_path = Some(overlay.ca_bundle_source.clone());
    upstream.backend_tls_sni = Some(overlay.hostname.clone());
    upstream.backend_tls_san_allow_list = overlay.subject_alt_names.clone();
}
