//! Every CRD the Gateway API controller watches must be granted by the chart's
//! control-plane ClusterRole.
//!
//! A watched-but-ungranted kind is not a quiet degradation: the watcher starts
//! unconditionally once the CRD group is discovered, the API server rejects
//! each list `403`, and the reflector retries for the life of the process. That
//! retry pressure competes with every other scope's relist generation, and a
//! reflector store that cannot finish relisting keeps serving its previous
//! object set — including a `Namespace` set whose labels predate the operator's
//! last edit, which silently denies `allowedRoutes.namespaces.from: Selector`
//! attachments.
//!
//! Static `include_str!` / const inspection only — no Kubernetes runtime.

use ferrum_edge::k8s_controller::watcher::{GATEWAY_API_CRDS, K8S_NAMESPACE_RESOURCES};

const CONTROL_PLANE_RBAC: &str =
    include_str!("../../../charts/ferrum-mesh/templates/control-plane-rbac.yaml");

/// Plurals whose `status` subresource the Gateway API status writer patches.
/// `ServiceImport` is read-only (GEP-1748 backendRef resolution).
const STATUS_WRITTEN_PLURALS: &[&str] = &[
    "gatewayclasses",
    "gateways",
    "httproutes",
    "grpcroutes",
    "tlsroutes",
    "tcproutes",
    "udproutes",
    "backendtlspolicies",
    "backendlbpolicies",
    "xbackendtrafficpolicies",
    "listenersets",
];

fn grants_resource(plural: &str) -> bool {
    CONTROL_PLANE_RBAC.lines().any(|line| {
        line.trim()
            .strip_prefix("- ")
            .is_some_and(|resource| resource == plural)
    })
}

fn grants_api_group(group: &str) -> bool {
    CONTROL_PLANE_RBAC.contains(&format!("apiGroups: [\"{group}\"]"))
}

#[test]
fn every_watched_gateway_api_crd_is_granted_by_the_control_plane_cluster_role() {
    for crd in GATEWAY_API_CRDS {
        assert!(
            grants_api_group(crd.group),
            "chart RBAC must name apiGroup {} for watched kind {}",
            crd.group,
            crd.kind
        );
        assert!(
            grants_resource(crd.plural),
            "chart RBAC must grant list/watch on {} ({}) or its watcher 403-loops for the \
             life of the control plane",
            crd.plural,
            crd.group
        );
    }
}

#[test]
fn every_status_written_gateway_api_kind_is_granted_its_status_subresource() {
    for plural in STATUS_WRITTEN_PLURALS {
        assert!(
            GATEWAY_API_CRDS.iter().any(|crd| crd.plural == *plural),
            "{plural} is claimed as status-written but is not watched"
        );
        assert!(
            grants_resource(&format!("{plural}/status")),
            "chart RBAC must grant the {plural} status subresource"
        );
    }
}

/// `allowedRoutes.namespaces.from: Selector` is evaluated against the labels of
/// the route's own `Namespace` object, so the cluster-scoped Namespace watch is
/// part of the Gateway API authorization boundary rather than an optimization.
#[test]
fn the_namespace_watch_backing_allowed_routes_selectors_is_granted() {
    assert!(
        K8S_NAMESPACE_RESOURCES
            .iter()
            .any(|resource| resource.kind == "Namespace" && !resource.namespaced),
        "the Namespace watch must stay cluster-scoped"
    );
    assert!(
        grants_resource("namespaces"),
        "chart RBAC must grant the cluster-scoped Namespace watch that \
         allowedRoutes namespace selectors resolve against"
    );
}
