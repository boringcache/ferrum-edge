//! Typed Gateway API `backendRef` kind resolution.
//!
//! Route translation and Gateway API `ResolvedRefs` status share this adapter
//! boundary so status cannot claim support that traffic does not receive.
//! Resolution and materialization run at reconcile/load time only.

use serde_json::Value;

use super::{
    K8sAccumulator, K8sObject, K8sTranslateError, RouteBackend, invalid_resource, service_dns_name,
    string_field,
};

/// MCS Multi-Cluster Services API group for `ServiceImport` (GEP-1748).
pub(crate) const SERVICE_IMPORT_GROUP: &str = "multicluster.x-k8s.io";
pub(crate) const SERVICE_IMPORT_KIND: &str = "ServiceImport";

/// Fixed MCS ClusterSet DNS suffix. Unlike cluster-local Services, this is not
/// derived from `cluster_domain` — MCS DNS publishes `*.svc.clusterset.local`.
pub(crate) const SERVICE_IMPORT_CLUSTERSET_DOMAIN: &str = "clusterset.local";

/// Supported Gateway API `backendRef` target kinds Ferrum can materialize.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BackendKind {
    /// Core Kubernetes `Service` (`group: ""`, `kind: Service`).
    Service,
    /// MCS `ServiceImport` (`group: multicluster.x-k8s.io`, GEP-1748 Extended).
    ServiceImport,
}

impl BackendKind {
    pub(crate) fn group(self) -> &'static str {
        match self {
            Self::Service => "",
            Self::ServiceImport => SERVICE_IMPORT_GROUP,
        }
    }

    pub(crate) fn kind(self) -> &'static str {
        match self {
            Self::Service => "Service",
            Self::ServiceImport => SERVICE_IMPORT_KIND,
        }
    }
}

/// Classify a `backendRef` `(group, kind)` pair.
///
/// Unknown combinations remain fail-closed; callers map [`Err`] to
/// `InvalidKind` for both translation faults and route status.
pub(crate) fn classify_backend_kind(group: &str, kind: &str) -> Result<BackendKind, ()> {
    match (group, kind) {
        ("", "Service") => Ok(BackendKind::Service),
        (SERVICE_IMPORT_GROUP, SERVICE_IMPORT_KIND) => Ok(BackendKind::ServiceImport),
        _ => Err(()),
    }
}

/// Field-specific diagnostics for an unsupported `backendRef` target kind.
pub(crate) fn unsupported_backend_kind_message(group: &str, kind: &str) -> String {
    format!(
        "unsupported backendRef target group '{group}' kind '{kind}'; \
         supported kinds are core Service and {SERVICE_IMPORT_GROUP}/{SERVICE_IMPORT_KIND}"
    )
}

/// Stable tokens matched by status/translator fault classification. Keep these
/// substrings stable — Gateway API `ResolvedRefs` reason mapping depends on them.
pub(crate) fn message_is_unsupported_backend_kind(message: &str) -> bool {
    message.contains("unsupported backendRef target group")
}

pub(crate) fn message_is_backend_not_found(message: &str) -> bool {
    message.contains("backendRef Service")
        || message.contains("backendRef ServiceImport")
        || message.contains("backendRef target")
        || (message.contains("backendRef") && message.contains("was not found"))
}

/// Authorize a cross-namespace `backendRef` and return its resolved namespace.
///
/// Same-namespace refs skip ReferenceGrant. Cross-namespace refs require an
/// exact grant for the typed `(group, kind)` pair. Unknown kinds fail closed
/// before grant evaluation so an overly broad grant cannot bless them.
pub(crate) fn checked_backend_namespace(
    object: &K8sObject,
    backend_ref: &Value,
    acc: &K8sAccumulator,
    from_kind: &str,
) -> Result<(BackendKind, String), K8sTranslateError> {
    let backend_namespace =
        string_field(backend_ref, "namespace").unwrap_or(&object.metadata.namespace);
    let to_group = string_field(backend_ref, "group").unwrap_or_default();
    let to_kind = string_field(backend_ref, "kind").unwrap_or("Service");
    let backend_kind = classify_backend_kind(to_group, to_kind).map_err(|()| {
        invalid_resource(object, unsupported_backend_kind_message(to_group, to_kind))
    })?;

    if backend_namespace == object.metadata.namespace {
        return Ok((backend_kind, backend_namespace.to_string()));
    }

    if acc.reference_grant_allows(
        &object.metadata.namespace,
        api_group(&object.api_version),
        from_kind,
        backend_namespace,
        backend_kind.group(),
        backend_kind.kind(),
        string_field(backend_ref, "name"),
    ) {
        Ok((backend_kind, backend_namespace.to_string()))
    } else {
        Err(invalid_resource(
            object,
            format!(
                "{from_kind} backendRef to {} in namespace '{backend_namespace}' requires a matching ReferenceGrant",
                backend_kind.kind()
            ),
        ))
    }
}

fn api_group(api_version: &str) -> &str {
    api_version
        .split_once('/')
        .map(|(group, _version)| group)
        .unwrap_or_default()
}

/// DNS hostname for a resolved backend target.
pub(crate) fn backend_dns_name(
    kind: BackendKind,
    name: &str,
    namespace: &str,
    cluster_domain: &str,
) -> String {
    match kind {
        BackendKind::Service => service_dns_name(name, namespace, cluster_domain),
        BackendKind::ServiceImport => {
            format!("{name}.{namespace}.svc.{SERVICE_IMPORT_CLUSTERSET_DOMAIN}")
        }
    }
}

/// Whether a typed backend target exists with the requested port.
///
/// * `Service` keeps the historical soft check: when no Services were observed
///   in the snapshot (common in focused unit fixtures), existence is not
///   enforced and DNS materialization proceeds.
/// * `ServiceImport` is always enforced against the collected index so a missing
///   MCS import cannot silently become a clusterset DNS blackhole while the
///   rest of the inventory is present — and so an absent MCS CRD (empty index)
///   fails closed.
pub(crate) fn backend_target_missing(
    acc: &K8sAccumulator,
    kind: BackendKind,
    namespace: &str,
    name: &str,
    port: u16,
) -> bool {
    match kind {
        BackendKind::Service => {
            acc.has_observed_services()
                && (!acc.service_exists(namespace, name)
                    || !acc.service_port_exists(namespace, name, port))
        }
        BackendKind::ServiceImport => {
            !acc.service_import_exists(namespace, name)
                || !acc.service_import_port_exists(namespace, name, port)
        }
    }
}

/// Materialize one authorized, port-resolved backend into route backends.
///
/// Service targets may expand onto ready EndpointSlice addresses when pod
/// discovery is enabled. ServiceImport targets expand onto MCS-labeled
/// EndpointSlices when present; otherwise they use ClusterSet DNS.
pub(crate) fn materialize_backend(
    acc: &K8sAccumulator,
    kind: BackendKind,
    namespace: &str,
    name: &str,
    port: u16,
    weight: u32,
) -> Vec<RouteBackend> {
    match kind {
        BackendKind::Service => {
            let endpoint_backends =
                acc.endpoint_route_backends_for_service(namespace, name, port, weight);
            if !endpoint_backends.is_empty() {
                return endpoint_backends;
            }
            vec![RouteBackend {
                host: backend_dns_name(kind, name, namespace, &acc.options.cluster_domain),
                port,
                weight,
                service_namespace: Some(namespace.to_string()),
                service_name: Some(name.to_string()),
                service_port: Some(port),
            }]
        }
        BackendKind::ServiceImport => {
            let endpoint_backends =
                acc.endpoint_route_backends_for_service_import(namespace, name, port, weight);
            if !endpoint_backends.is_empty() {
                return endpoint_backends;
            }
            // Do not stamp Service identity tags: BackendTLSPolicy /
            // BackendLBPolicy attach to core Services only, and a same-named
            // local Service must not inherit policy from an Import backend.
            vec![RouteBackend {
                host: backend_dns_name(kind, name, namespace, &acc.options.cluster_domain),
                port,
                weight,
                service_namespace: None,
                service_name: None,
                service_port: None,
            }]
        }
    }
}

/// Status-side view of backend inventories used by `ResolvedRefs` planning.
///
/// Mirrors translator indexes so status and traffic share one predicate.
pub(crate) struct BackendRefStatusInventory<'a> {
    pub services_by_ns_name: &'a std::collections::HashMap<(&'a str, &'a str), &'a K8sObject>,
    pub service_imports_by_ns_name:
        &'a std::collections::HashMap<(&'a str, &'a str), &'a K8sObject>,
    pub has_any_service: bool,
}

/// Shared `ResolvedRefs` reason for one non-zero-weight `backendRef`.
///
/// Returns `None` when the ref is resolved. Reasons match Gateway API
/// `RouteConditionReason` vocabulary (`InvalidKind`, `RefNotPermitted`,
/// `BackendNotFound`).
///
/// `reference_grant_allows` receives `(to_namespace, to_group, to_kind, to_name)`.
pub(crate) fn unresolved_backend_ref_reason<'a, F>(
    route: &K8sObject,
    backend_ref: &Value,
    inventory: &BackendRefStatusInventory<'a>,
    mut reference_grant_allows: F,
) -> Option<&'static str>
where
    F: FnMut(&str, &str, &str, Option<&str>) -> bool,
{
    let to_group = backend_ref
        .get("group")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let to_kind = backend_ref
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("Service");
    let Ok(backend_kind) = classify_backend_kind(to_group, to_kind) else {
        return Some("InvalidKind");
    };

    let backend_namespace = backend_ref
        .get("namespace")
        .and_then(Value::as_str)
        .unwrap_or(&route.metadata.namespace);
    let backend_name = backend_ref.get("name").and_then(Value::as_str);

    if backend_namespace != route.metadata.namespace
        && !reference_grant_allows(
            backend_namespace,
            backend_kind.group(),
            backend_kind.kind(),
            backend_name,
        )
    {
        return Some("RefNotPermitted");
    }

    let backend_port = backend_ref
        .get("port")
        .and_then(Value::as_u64)
        .and_then(|port| u16::try_from(port).ok())
        .unwrap_or(if route.kind == "GRPCRoute" { 50051 } else { 80 });

    match backend_kind {
        BackendKind::Service => {
            if !inventory.has_any_service {
                return None;
            }
            let Some(backend_name) = backend_name else {
                return Some("BackendNotFound");
            };
            let Some(service) = inventory
                .services_by_ns_name
                .get(&(backend_namespace, backend_name))
            else {
                return Some("BackendNotFound");
            };
            if !object_has_numeric_port(service, backend_port) {
                return Some("BackendNotFound");
            }
        }
        BackendKind::ServiceImport => {
            let Some(backend_name) = backend_name else {
                return Some("BackendNotFound");
            };
            let Some(import) = inventory
                .service_imports_by_ns_name
                .get(&(backend_namespace, backend_name))
            else {
                return Some("BackendNotFound");
            };
            if !object_has_numeric_port(import, backend_port) {
                return Some("BackendNotFound");
            }
        }
    }

    None
}

fn object_has_numeric_port(object: &K8sObject, port: u16) -> bool {
    object
        .spec
        .get("ports")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|entry| entry.get("port").and_then(Value::as_u64) == Some(u64::from(port)))
}

/// Collect MCS `ServiceImport` port inventory for backendRef resolution.
pub(crate) fn collect_service_import(
    acc: &mut K8sAccumulator,
    object: &K8sObject,
) -> Result<(), K8sTranslateError> {
    let ports = object
        .spec
        .get("ports")
        .and_then(Value::as_array)
        .map(|arr| arr.as_slice())
        .unwrap_or(&[]);
    let mut port_numbers = std::collections::HashSet::new();
    for port_entry in ports {
        let Some(raw) = port_entry.get("port").and_then(Value::as_u64) else {
            continue;
        };
        // Reuse the same 1..=65535 port gate as Service collection.
        let port = super::port_from_u64(object, raw, "ServiceImport.spec.ports[].port")?;
        port_numbers.insert(port);
    }
    acc.record_service_import_ports(
        object.metadata.namespace.clone(),
        object.metadata.name.clone(),
        port_numbers,
    );
    Ok(())
}
