//! Ferrum mesh-slice ECDS carriers (GAP-1a: xDS native-parity).
//!
//! Standard Envoy xDS resources (CDS/EDS/LDS/RDS/SDS) are name-only on the
//! wire for Ferrum's purposes — they round-trip service-port discovery but
//! carry NONE of the security- and policy-bearing slice fields
//! (authorization policies, PeerAuthentication mTLS posture, effective
//! workload labels for selector matching, request authentication / JWT rules,
//! ServiceEntry shape, SPIFFE trust bundles, outbound traffic policy,
//! ProxyConfig, and per-pod workload endpoints).
//!
//! Without this module, `FERRUM_MESH_CONFIG_PROTOCOL=xds` produced an
//! UNPROTECTED mesh: the DP rebuilt the slice with every one of those fields
//! emptied. This module makes the xDS path carry the FULL slice by reusing
//! the same typed-extension-config (ECDS) carrier mechanism that already
//! ships DestinationRule JSON (`FERRUM_ECDS_DESTINATION_RULE_TYPE_URL`).
//!
//! ## Wire format and interop boundary
//!
//! Each non-empty slice field group is serialized to JSON and wrapped in an
//! `envoy.config.core.v3.TypedExtensionConfig` whose inner `type_url` is a
//! Ferrum-specific marker under `type.googleapis.com/ferrum.config.extension.v3.*`.
//! These carriers flow on the standard ECDS (`TypedExtensionConfig`) ADS
//! resource stream alongside the name-only CDS/EDS/LDS/RDS resources.
//!
//! This is a **Ferrum-specific carrier**, NOT a third-party-Envoy-interoperable
//! format: a stock Envoy or Istio control plane neither emits nor understands
//! these inner type_urls. A Ferrum CP talks to a Ferrum DP. The benefit of
//! riding ECDS rather than inventing a new resource type is that the ADS
//! subscription lifecycle, nonce/ACK handling, and snapshot/version machinery
//! are shared verbatim with the rest of the xDS path.
//!
//! ## Single source of truth
//!
//! Encode (CP side, `translator::translate_mesh_slice_carriers`) and decode
//! (DP side, `xds_client::reverse_translate`) both go through the
//! [`MeshSliceCarrier`] enum here so the two halves cannot drift. Adding a new
//! carried field is a single edit: add a variant + its `type_url` + its
//! encode/decode arm, and the round-trip test in this module will fail until
//! both halves are wired.

use serde::Serialize;
use serde::de::DeserializeOwned;
use std::collections::BTreeMap;

use crate::modes::mesh::config::{
    MeshPolicy, MeshProxyConfig, MeshRequestAuthentication, MeshService, MeshTelemetryResource,
    MultiClusterConfig, OutboundTrafficPolicy, PeerAuthentication, ServiceEntry, TrustBundleSet,
    Workload,
};
use crate::modes::mesh::slice::{MeshEgressScopeSnapshot, MeshSlice};

/// Common inner `type_url` prefix for every Ferrum mesh-slice carrier.
pub const FERRUM_CARRIER_TYPE_URL_PREFIX: &str = "type.googleapis.com/ferrum.config.extension.v3.";

/// Inner `type_url` for the full `MeshService` carrier (protocol + per-service
/// workload refs that the name-only CDS/EDS reconstruction cannot express).
pub const FERRUM_ECDS_SERVICES_TYPE_URL: &str =
    "type.googleapis.com/ferrum.config.extension.v3.ServicesCarrier";
/// Inner `type_url` for the inbound-only view of the local workload's own
/// service(s), captured un-narrowed by Sidecar egress scope. Distinct from
/// `ServicesCarrier` (the egress/outbound-narrowed view) so egress scope never
/// gates inbound serving and the outbound registry is not widened.
pub const FERRUM_ECDS_LOCAL_INBOUND_SERVICES_TYPE_URL: &str =
    "type.googleapis.com/ferrum.config.extension.v3.LocalInboundServicesCarrier";
/// Inner `type_url` for the inbound-only view of the local workload(s), captured
/// un-narrowed by Sidecar egress/identity narrowing so the inbound materializer
/// can find the local pod (and its container ports for backend resolution) even
/// when identity narrowing drops it from the `Workloads` carrier.
pub const FERRUM_ECDS_LOCAL_INBOUND_WORKLOADS_TYPE_URL: &str =
    "type.googleapis.com/ferrum.config.extension.v3.LocalInboundWorkloadsCarrier";
/// Inner `type_url` for the per-pod workload / endpoint carrier.
pub const FERRUM_ECDS_WORKLOADS_TYPE_URL: &str =
    "type.googleapis.com/ferrum.config.extension.v3.WorkloadsCarrier";
/// Inner `type_url` for the effective workload-label context carrier.
pub const FERRUM_ECDS_LABELS_TYPE_URL: &str =
    "type.googleapis.com/ferrum.config.extension.v3.WorkloadLabelsCarrier";
/// Inner `type_url` for the authorization-policy carrier (`MeshPolicy` list).
pub const FERRUM_ECDS_MESH_POLICIES_TYPE_URL: &str =
    "type.googleapis.com/ferrum.config.extension.v3.MeshPoliciesCarrier";
/// Inner `type_url` for the PeerAuthentication carrier.
pub const FERRUM_ECDS_PEER_AUTH_TYPE_URL: &str =
    "type.googleapis.com/ferrum.config.extension.v3.PeerAuthenticationsCarrier";
/// Inner `type_url` for the RequestAuthentication (JWT) carrier.
pub const FERRUM_ECDS_REQUEST_AUTH_TYPE_URL: &str =
    "type.googleapis.com/ferrum.config.extension.v3.RequestAuthenticationsCarrier";
/// Inner `type_url` for the ServiceEntry carrier.
pub const FERRUM_ECDS_SERVICE_ENTRIES_TYPE_URL: &str =
    "type.googleapis.com/ferrum.config.extension.v3.ServiceEntriesCarrier";
/// Inner `type_url` for the Telemetry-resource carrier.
pub const FERRUM_ECDS_TELEMETRY_TYPE_URL: &str =
    "type.googleapis.com/ferrum.config.extension.v3.TelemetryResourcesCarrier";
/// Inner `type_url` for the ProxyConfig carrier.
pub const FERRUM_ECDS_PROXY_CONFIGS_TYPE_URL: &str =
    "type.googleapis.com/ferrum.config.extension.v3.ProxyConfigsCarrier";
/// Inner `type_url` for the SPIFFE trust-bundle carrier.
pub const FERRUM_ECDS_TRUST_BUNDLES_TYPE_URL: &str =
    "type.googleapis.com/ferrum.config.extension.v3.TrustBundlesCarrier";
/// Inner `type_url` for the mesh-wide outbound-traffic-policy carrier.
pub const FERRUM_ECDS_OUTBOUND_POLICY_TYPE_URL: &str =
    "type.googleapis.com/ferrum.config.extension.v3.OutboundTrafficPolicyCarrier";
/// Inner `type_url` for the multi-cluster-config carrier.
pub const FERRUM_ECDS_MULTI_CLUSTER_TYPE_URL: &str =
    "type.googleapis.com/ferrum.config.extension.v3.MultiClusterCarrier";
/// Inner `type_url` for the Sidecar egress-scope snapshot carrier.
pub const FERRUM_ECDS_SIDECAR_EGRESS_SCOPE_TYPE_URL: &str =
    "type.googleapis.com/ferrum.config.extension.v3.SidecarEgressScopeCarrier";

/// Stable ECDS resource name for each slice carrier. The CP emits exactly one
/// ECDS resource per non-empty carrier under these names; the DP requires
/// both the reserved resource name and the inner `type_url` when decoding so
/// operator-defined ECDS configs cannot impersonate internal slice carriers.
pub const FERRUM_CARRIER_RESOURCE_NAME_PREFIX: &str = "ferrum-mesh-carrier/";

/// One decoded Ferrum slice carrier. Each variant owns the field group it
/// reconstructs on the DP side. The encode/decode round-trip is pinned by the
/// `slice_carrier_round_trip` test below.
#[derive(Debug, Clone, PartialEq)]
pub enum MeshSliceCarrier {
    Services(Vec<MeshService>),
    LocalInboundServices(Vec<MeshService>),
    LocalInboundWorkloads(Vec<Workload>),
    Workloads(Vec<Workload>),
    WorkloadLabels(BTreeMap<String, String>),
    MeshPolicies(Vec<MeshPolicy>),
    PeerAuthentications(Vec<PeerAuthentication>),
    RequestAuthentications(Vec<MeshRequestAuthentication>),
    ServiceEntries(Vec<ServiceEntry>),
    TelemetryResources(Vec<MeshTelemetryResource>),
    ProxyConfigs(Vec<MeshProxyConfig>),
    TrustBundles(TrustBundleSet),
    OutboundTrafficPolicy(OutboundTrafficPolicy),
    MultiCluster(MultiClusterConfig),
    SidecarEgressScope(MeshEgressScopeSnapshot),
}

impl MeshSliceCarrier {
    /// Inner `type_url` marker for this carrier variant.
    pub fn type_url(&self) -> &'static str {
        match self {
            MeshSliceCarrier::Services(_) => FERRUM_ECDS_SERVICES_TYPE_URL,
            MeshSliceCarrier::LocalInboundServices(_) => {
                FERRUM_ECDS_LOCAL_INBOUND_SERVICES_TYPE_URL
            }
            MeshSliceCarrier::LocalInboundWorkloads(_) => {
                FERRUM_ECDS_LOCAL_INBOUND_WORKLOADS_TYPE_URL
            }
            MeshSliceCarrier::Workloads(_) => FERRUM_ECDS_WORKLOADS_TYPE_URL,
            MeshSliceCarrier::WorkloadLabels(_) => FERRUM_ECDS_LABELS_TYPE_URL,
            MeshSliceCarrier::MeshPolicies(_) => FERRUM_ECDS_MESH_POLICIES_TYPE_URL,
            MeshSliceCarrier::PeerAuthentications(_) => FERRUM_ECDS_PEER_AUTH_TYPE_URL,
            MeshSliceCarrier::RequestAuthentications(_) => FERRUM_ECDS_REQUEST_AUTH_TYPE_URL,
            MeshSliceCarrier::ServiceEntries(_) => FERRUM_ECDS_SERVICE_ENTRIES_TYPE_URL,
            MeshSliceCarrier::TelemetryResources(_) => FERRUM_ECDS_TELEMETRY_TYPE_URL,
            MeshSliceCarrier::ProxyConfigs(_) => FERRUM_ECDS_PROXY_CONFIGS_TYPE_URL,
            MeshSliceCarrier::TrustBundles(_) => FERRUM_ECDS_TRUST_BUNDLES_TYPE_URL,
            MeshSliceCarrier::OutboundTrafficPolicy(_) => FERRUM_ECDS_OUTBOUND_POLICY_TYPE_URL,
            MeshSliceCarrier::MultiCluster(_) => FERRUM_ECDS_MULTI_CLUSTER_TYPE_URL,
            MeshSliceCarrier::SidecarEgressScope(_) => FERRUM_ECDS_SIDECAR_EGRESS_SCOPE_TYPE_URL,
        }
    }

    /// Stable ECDS resource name for this carrier variant.
    pub fn resource_name(&self) -> String {
        let suffix = match self {
            MeshSliceCarrier::Services(_) => "services",
            MeshSliceCarrier::LocalInboundServices(_) => "local-inbound-services",
            MeshSliceCarrier::LocalInboundWorkloads(_) => "local-inbound-workloads",
            MeshSliceCarrier::Workloads(_) => "workloads",
            MeshSliceCarrier::WorkloadLabels(_) => "workload-labels",
            MeshSliceCarrier::MeshPolicies(_) => "mesh-policies",
            MeshSliceCarrier::PeerAuthentications(_) => "peer-authentications",
            MeshSliceCarrier::RequestAuthentications(_) => "request-authentications",
            MeshSliceCarrier::ServiceEntries(_) => "service-entries",
            MeshSliceCarrier::TelemetryResources(_) => "telemetry-resources",
            MeshSliceCarrier::ProxyConfigs(_) => "proxy-configs",
            MeshSliceCarrier::TrustBundles(_) => "trust-bundles",
            MeshSliceCarrier::OutboundTrafficPolicy(_) => "outbound-traffic-policy",
            MeshSliceCarrier::MultiCluster(_) => "multi-cluster",
            MeshSliceCarrier::SidecarEgressScope(_) => "sidecar-egress-scope",
        };
        format!("{FERRUM_CARRIER_RESOURCE_NAME_PREFIX}{suffix}")
    }

    /// JSON-encode the carried field group into the inner `Any.value` bytes.
    pub fn encode_value(&self) -> Result<Vec<u8>, serde_json::Error> {
        match self {
            MeshSliceCarrier::Services(value) => encode(value),
            MeshSliceCarrier::LocalInboundServices(value) => encode(value),
            MeshSliceCarrier::LocalInboundWorkloads(value) => encode(value),
            MeshSliceCarrier::Workloads(value) => encode(value),
            MeshSliceCarrier::WorkloadLabels(value) => encode(value),
            MeshSliceCarrier::MeshPolicies(value) => encode(value),
            MeshSliceCarrier::PeerAuthentications(value) => encode(value),
            MeshSliceCarrier::RequestAuthentications(value) => encode(value),
            MeshSliceCarrier::ServiceEntries(value) => encode(value),
            MeshSliceCarrier::TelemetryResources(value) => encode(value),
            MeshSliceCarrier::ProxyConfigs(value) => encode(value),
            MeshSliceCarrier::TrustBundles(value) => encode(value),
            MeshSliceCarrier::OutboundTrafficPolicy(value) => encode(value),
            MeshSliceCarrier::MultiCluster(value) => encode(value),
            MeshSliceCarrier::SidecarEgressScope(value) => encode(value),
        }
    }

    /// Decode a carrier from its inner `type_url` and `Any.value` bytes.
    ///
    /// Returns `Ok(None)` for any `type_url` that is not a Ferrum slice
    /// carrier — this keeps unrelated ECDS payloads (e.g. the
    /// DestinationRule carrier, or operator-defined extension configs) from
    /// erroring the decode loop.
    ///
    /// A recognized carrier whose JSON fails to parse returns `Err` — this is
    /// FAIL-CLOSED behavior: the caller (`recover_slice_carriers`) propagates
    /// the error up through `try_build_mesh_slice`, which causes
    /// `handle_ads_response` to NACK the ECDS response and restore the
    /// previous accumulator snapshot, retaining the last accepted slice
    /// instead of applying a partial or cleared one.
    pub fn decode(type_url: &str, value: &[u8]) -> Result<Option<Self>, serde_json::Error> {
        let carrier = match type_url {
            FERRUM_ECDS_SERVICES_TYPE_URL => MeshSliceCarrier::Services(decode_json(value)?),
            FERRUM_ECDS_LOCAL_INBOUND_SERVICES_TYPE_URL => {
                MeshSliceCarrier::LocalInboundServices(decode_json(value)?)
            }
            FERRUM_ECDS_LOCAL_INBOUND_WORKLOADS_TYPE_URL => {
                MeshSliceCarrier::LocalInboundWorkloads(decode_json(value)?)
            }
            FERRUM_ECDS_WORKLOADS_TYPE_URL => MeshSliceCarrier::Workloads(decode_json(value)?),
            FERRUM_ECDS_LABELS_TYPE_URL => MeshSliceCarrier::WorkloadLabels(decode_json(value)?),
            FERRUM_ECDS_MESH_POLICIES_TYPE_URL => {
                MeshSliceCarrier::MeshPolicies(decode_json(value)?)
            }
            FERRUM_ECDS_PEER_AUTH_TYPE_URL => {
                MeshSliceCarrier::PeerAuthentications(decode_json(value)?)
            }
            FERRUM_ECDS_REQUEST_AUTH_TYPE_URL => {
                MeshSliceCarrier::RequestAuthentications(decode_json(value)?)
            }
            FERRUM_ECDS_SERVICE_ENTRIES_TYPE_URL => {
                MeshSliceCarrier::ServiceEntries(decode_json(value)?)
            }
            FERRUM_ECDS_TELEMETRY_TYPE_URL => {
                MeshSliceCarrier::TelemetryResources(decode_json(value)?)
            }
            FERRUM_ECDS_PROXY_CONFIGS_TYPE_URL => {
                MeshSliceCarrier::ProxyConfigs(decode_json(value)?)
            }
            FERRUM_ECDS_TRUST_BUNDLES_TYPE_URL => {
                MeshSliceCarrier::TrustBundles(decode_json(value)?)
            }
            FERRUM_ECDS_OUTBOUND_POLICY_TYPE_URL => {
                MeshSliceCarrier::OutboundTrafficPolicy(decode_json(value)?)
            }
            FERRUM_ECDS_MULTI_CLUSTER_TYPE_URL => {
                MeshSliceCarrier::MultiCluster(decode_json(value)?)
            }
            FERRUM_ECDS_SIDECAR_EGRESS_SCOPE_TYPE_URL => {
                MeshSliceCarrier::SidecarEgressScope(decode_json(value)?)
            }
            _ => return Ok(None),
        };
        Ok(Some(carrier))
    }
}

/// Return the reserved ECDS resource name for a Ferrum mesh-slice carrier
/// `type_url`, or `None` when the URL is not an internal slice carrier.
pub fn carrier_resource_name_for_type_url(type_url: &str) -> Option<&'static str> {
    match type_url {
        FERRUM_ECDS_SERVICES_TYPE_URL => Some("ferrum-mesh-carrier/services"),
        FERRUM_ECDS_LOCAL_INBOUND_SERVICES_TYPE_URL => {
            Some("ferrum-mesh-carrier/local-inbound-services")
        }
        FERRUM_ECDS_LOCAL_INBOUND_WORKLOADS_TYPE_URL => {
            Some("ferrum-mesh-carrier/local-inbound-workloads")
        }
        FERRUM_ECDS_WORKLOADS_TYPE_URL => Some("ferrum-mesh-carrier/workloads"),
        FERRUM_ECDS_LABELS_TYPE_URL => Some("ferrum-mesh-carrier/workload-labels"),
        FERRUM_ECDS_MESH_POLICIES_TYPE_URL => Some("ferrum-mesh-carrier/mesh-policies"),
        FERRUM_ECDS_PEER_AUTH_TYPE_URL => Some("ferrum-mesh-carrier/peer-authentications"),
        FERRUM_ECDS_REQUEST_AUTH_TYPE_URL => Some("ferrum-mesh-carrier/request-authentications"),
        FERRUM_ECDS_SERVICE_ENTRIES_TYPE_URL => Some("ferrum-mesh-carrier/service-entries"),
        FERRUM_ECDS_TELEMETRY_TYPE_URL => Some("ferrum-mesh-carrier/telemetry-resources"),
        FERRUM_ECDS_PROXY_CONFIGS_TYPE_URL => Some("ferrum-mesh-carrier/proxy-configs"),
        FERRUM_ECDS_TRUST_BUNDLES_TYPE_URL => Some("ferrum-mesh-carrier/trust-bundles"),
        FERRUM_ECDS_OUTBOUND_POLICY_TYPE_URL => Some("ferrum-mesh-carrier/outbound-traffic-policy"),
        FERRUM_ECDS_MULTI_CLUSTER_TYPE_URL => Some("ferrum-mesh-carrier/multi-cluster"),
        FERRUM_ECDS_SIDECAR_EGRESS_SCOPE_TYPE_URL => {
            Some("ferrum-mesh-carrier/sidecar-egress-scope")
        }
        _ => None,
    }
}

fn decode_json<T: DeserializeOwned>(value: &[u8]) -> Result<T, serde_json::Error> {
    serde_json::from_slice(value)
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(value)
}

/// Build every slice carrier for `slice`.
///
/// Empty `Vec`/`None` field groups are skipped so a slice with, say, no
/// PeerAuthentications does not pay for an empty carrier resource on the wire
/// (and so the DP's "field absent" and "field empty" states stay
/// indistinguishable, matching native-protocol behavior where an empty list
/// and an absent list are equivalent). Effective labels are the exception:
/// an empty label map is meaningful selector context and must override any
/// local DP labels during xDS recovery.
///
/// Both CDS/EDS (name-only, Envoy-shaped cluster discovery) AND the
/// `Services`/`ServiceEntries` carriers are emitted. The name-only path keeps
/// Envoy-compatible service-port discovery working; the carriers recover the
/// FULL `MeshService`/`ServiceEntry` shape (protocol, per-service workload
/// refs, hosts, resolution, location) that the name-only resources cannot
/// express. The DP prefers the carried full shapes and only falls back to the
/// CDS/EDS reconstruction when no slice carrier is present (e.g. an older
/// Ferrum-shaped xDS CP used in tests).
pub fn build_slice_carriers(slice: &MeshSlice) -> Vec<MeshSliceCarrier> {
    let mut carriers = Vec::new();
    if !slice.services.is_empty() {
        carriers.push(MeshSliceCarrier::Services(slice.services.clone()));
    }
    if !slice.local_inbound_services.is_empty() {
        carriers.push(MeshSliceCarrier::LocalInboundServices(
            slice.local_inbound_services.clone(),
        ));
    }
    if !slice.local_inbound_workloads.is_empty() {
        carriers.push(MeshSliceCarrier::LocalInboundWorkloads(
            slice.local_inbound_workloads.clone(),
        ));
    }
    if !slice.workloads.is_empty() {
        carriers.push(MeshSliceCarrier::Workloads(slice.workloads.clone()));
    }
    // Emitted UNCONDITIONALLY (unlike the other field groups, which are gated
    // on non-empty), even when `slice.labels` is empty. This push is
    // load-bearing: it is what makes `recovered.slice_carrier_seen` reliably
    // true for any Ferrum CP, which is the DP's "this CP is carrier-aware"
    // sentinel that selects the carried `services` over the name-only CDS/EDS
    // reconstruction (see `reverse_translate`). Do NOT make this conditional
    // (e.g. "skip when empty") without introducing an explicit carrier-aware
    // flag — otherwise a Ferrum CP with empty labels AND empty services would
    // set `slice_carrier_seen=false` and silently fall back to reconstructing
    // services the carrier path intended to be empty.
    carriers.push(MeshSliceCarrier::WorkloadLabels(slice.labels.clone()));
    if !slice.mesh_policies.is_empty() {
        carriers.push(MeshSliceCarrier::MeshPolicies(slice.mesh_policies.clone()));
    }
    if !slice.peer_authentications.is_empty() {
        carriers.push(MeshSliceCarrier::PeerAuthentications(
            slice.peer_authentications.clone(),
        ));
    }
    if !slice.request_authentications.is_empty() {
        carriers.push(MeshSliceCarrier::RequestAuthentications(
            slice.request_authentications.clone(),
        ));
    }
    if !slice.service_entries.is_empty() {
        carriers.push(MeshSliceCarrier::ServiceEntries(
            slice.service_entries.clone(),
        ));
    }
    if !slice.telemetry_resources.is_empty() {
        carriers.push(MeshSliceCarrier::TelemetryResources(
            slice.telemetry_resources.clone(),
        ));
    }
    if !slice.proxy_configs.is_empty() {
        carriers.push(MeshSliceCarrier::ProxyConfigs(slice.proxy_configs.clone()));
    }
    if let Some(trust_bundles) = slice.trust_bundles.as_ref() {
        carriers.push(MeshSliceCarrier::TrustBundles(trust_bundles.clone()));
    }
    if let Some(policy) = slice.outbound_traffic_policy {
        carriers.push(MeshSliceCarrier::OutboundTrafficPolicy(policy));
    }
    if let Some(multi_cluster) = slice.multi_cluster.as_ref() {
        carriers.push(MeshSliceCarrier::MultiCluster(multi_cluster.clone()));
    }
    if let Some(scope) = slice.sidecar_egress_scope.as_ref() {
        carriers.push(MeshSliceCarrier::SidecarEgressScope(scope.clone()));
    }
    carriers
}

/// Apply a decoded carrier onto the in-progress reverse-translated slice.
///
/// The DP collects every carrier it decodes off the ECDS stream, then applies
/// them onto the slice it is rebuilding from CDS/EDS/LDS/RDS. Each variant
/// overwrites the corresponding slice field; a slice never sees a partially
/// applied carrier because apply happens after the whole ECDS resource list is
/// decoded.
pub fn apply_carrier(slice: &mut MeshSlice, carrier: MeshSliceCarrier) {
    match carrier {
        MeshSliceCarrier::Services(value) => slice.services = value,
        MeshSliceCarrier::LocalInboundServices(value) => slice.local_inbound_services = value,
        MeshSliceCarrier::LocalInboundWorkloads(value) => slice.local_inbound_workloads = value,
        MeshSliceCarrier::Workloads(value) => slice.workloads = value,
        MeshSliceCarrier::WorkloadLabels(value) => slice.labels = value,
        MeshSliceCarrier::MeshPolicies(value) => slice.mesh_policies = value,
        MeshSliceCarrier::PeerAuthentications(value) => slice.peer_authentications = value,
        MeshSliceCarrier::RequestAuthentications(value) => slice.request_authentications = value,
        MeshSliceCarrier::ServiceEntries(value) => slice.service_entries = value,
        MeshSliceCarrier::TelemetryResources(value) => slice.telemetry_resources = value,
        MeshSliceCarrier::ProxyConfigs(value) => slice.proxy_configs = value,
        MeshSliceCarrier::TrustBundles(value) => slice.trust_bundles = Some(value),
        MeshSliceCarrier::OutboundTrafficPolicy(value) => {
            slice.outbound_traffic_policy = Some(value)
        }
        MeshSliceCarrier::MultiCluster(value) => slice.multi_cluster = Some(value),
        MeshSliceCarrier::SidecarEgressScope(value) => slice.sidecar_egress_scope = Some(value),
    }
}

/// Workload identity a Ferrum DP communicates to the CP via the xDS
/// `Node.metadata` bytes shim (the minimal proto carries `bytes`, a placeholder
/// for Envoy's `google.protobuf.Struct`). JSON-encoded so it stays
/// forward-compatible if more node attributes are added later. The CP uses
/// `workload_spiffe_id` to compute Sidecar-aware narrowing and the un-narrowed
/// local-inbound-service view for that DP — without it, a hostname `Node.id`
/// leaves the CP unable to identify the workload (`from_xds_node` only derives a
/// SPIFFE from a `spiffe://` node id).
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct XdsNodeMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_spiffe_id: Option<String>,
}

/// Encode `Node.metadata` bytes for an outgoing DP request. Returns empty when
/// there is nothing to carry, matching the prior no-metadata wire shape.
pub fn encode_node_metadata(workload_spiffe_id: Option<&str>) -> Vec<u8> {
    match workload_spiffe_id {
        Some(spiffe) if !spiffe.is_empty() => serde_json::to_vec(&XdsNodeMetadata {
            workload_spiffe_id: Some(spiffe.to_string()),
        })
        .unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// Decode `Node.metadata` bytes received from a DP request. Empty or malformed
/// metadata decodes to the default (no identity) rather than erroring — node
/// metadata is advisory and must never reject a stream.
pub fn decode_node_metadata(bytes: &[u8]) -> XdsNodeMetadata {
    if bytes.is_empty() {
        return XdsNodeMetadata::default();
    }
    serde_json::from_slice(bytes).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::spiffe::TrustDomain;
    use crate::modes::mesh::config::TrustBundle;

    fn sample_trust_bundle_set() -> TrustBundleSet {
        TrustBundleSet {
            local: TrustBundle {
                trust_domain: TrustDomain::new("cluster.local").expect("trust domain"),
                x509_authorities: Vec::new(),
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            },
            federated: Vec::new(),
        }
    }

    /// Every carrier variant round-trips through its own `type_url` and JSON
    /// bytes. If a future variant forgets to wire a decode arm, this fails.
    #[test]
    fn slice_carrier_round_trip() {
        let carriers = vec![
            MeshSliceCarrier::Services(Vec::new()),
            MeshSliceCarrier::LocalInboundServices(Vec::new()),
            MeshSliceCarrier::LocalInboundWorkloads(Vec::new()),
            MeshSliceCarrier::Workloads(Vec::new()),
            MeshSliceCarrier::WorkloadLabels(BTreeMap::from([(
                "app".to_string(),
                "api".to_string(),
            )])),
            MeshSliceCarrier::MeshPolicies(Vec::new()),
            MeshSliceCarrier::PeerAuthentications(Vec::new()),
            MeshSliceCarrier::RequestAuthentications(Vec::new()),
            MeshSliceCarrier::ServiceEntries(Vec::new()),
            MeshSliceCarrier::TelemetryResources(Vec::new()),
            MeshSliceCarrier::ProxyConfigs(Vec::new()),
            MeshSliceCarrier::TrustBundles(sample_trust_bundle_set()),
            MeshSliceCarrier::OutboundTrafficPolicy(OutboundTrafficPolicy::RegistryOnly),
            MeshSliceCarrier::MultiCluster(MultiClusterConfig::default()),
            MeshSliceCarrier::SidecarEgressScope(MeshEgressScopeSnapshot::default()),
        ];
        for carrier in carriers {
            let type_url = carrier.type_url();
            let bytes = carrier.encode_value().expect("encode");
            let decoded = MeshSliceCarrier::decode(type_url, &bytes)
                .expect("decode does not error")
                .expect("recognized carrier");
            assert_eq!(decoded, carrier, "round trip for {type_url}");
            assert!(
                type_url.starts_with(FERRUM_CARRIER_TYPE_URL_PREFIX),
                "type_url {type_url} must use the Ferrum carrier prefix"
            );
        }
    }

    #[test]
    fn unrecognized_type_url_decodes_to_none() {
        let decoded =
            MeshSliceCarrier::decode("type.googleapis.com/some.other.Type", b"{}").expect("no err");
        assert!(decoded.is_none());
    }

    #[test]
    fn dr_carrier_type_url_is_not_a_slice_carrier() {
        // The DestinationRule carrier rides the same ECDS stream; the slice
        // carrier decoder must NOT claim it (the DR path decodes it
        // separately).
        let decoded = MeshSliceCarrier::decode(
            super::super::translator::FERRUM_ECDS_DESTINATION_RULE_TYPE_URL,
            b"{}",
        )
        .expect("no err");
        assert!(decoded.is_none());
    }

    #[test]
    fn recognized_carrier_bad_json_errors() {
        let err = MeshSliceCarrier::decode(FERRUM_ECDS_MESH_POLICIES_TYPE_URL, b"{not json}");
        assert!(err.is_err());
    }

    #[test]
    fn node_metadata_round_trips_workload_spiffe() {
        let spiffe = "spiffe://cluster.local/ns/default/sa/reviews";
        let bytes = encode_node_metadata(Some(spiffe));
        assert!(!bytes.is_empty());
        assert_eq!(
            decode_node_metadata(&bytes).workload_spiffe_id.as_deref(),
            Some(spiffe)
        );
        // Absent / empty identity encodes to empty bytes (prior no-metadata
        // wire shape) and decodes to no identity.
        assert!(encode_node_metadata(None).is_empty());
        assert!(encode_node_metadata(Some("")).is_empty());
        assert_eq!(decode_node_metadata(&[]).workload_spiffe_id, None);
        // Malformed metadata never errors/panics — it is advisory, so it
        // decodes to no identity rather than rejecting the stream.
        assert_eq!(decode_node_metadata(b"{garbage").workload_spiffe_id, None);
    }

    #[test]
    fn resource_names_are_unique_per_variant() {
        let carriers = [
            MeshSliceCarrier::Services(Vec::new()),
            MeshSliceCarrier::LocalInboundServices(Vec::new()),
            MeshSliceCarrier::LocalInboundWorkloads(Vec::new()),
            MeshSliceCarrier::Workloads(Vec::new()),
            MeshSliceCarrier::WorkloadLabels(BTreeMap::from([(
                "app".to_string(),
                "api".to_string(),
            )])),
            MeshSliceCarrier::MeshPolicies(Vec::new()),
            MeshSliceCarrier::PeerAuthentications(Vec::new()),
            MeshSliceCarrier::RequestAuthentications(Vec::new()),
            MeshSliceCarrier::ServiceEntries(Vec::new()),
            MeshSliceCarrier::TelemetryResources(Vec::new()),
            MeshSliceCarrier::ProxyConfigs(Vec::new()),
            MeshSliceCarrier::TrustBundles(sample_trust_bundle_set()),
            MeshSliceCarrier::OutboundTrafficPolicy(OutboundTrafficPolicy::AllowAny),
            MeshSliceCarrier::MultiCluster(MultiClusterConfig::default()),
            MeshSliceCarrier::SidecarEgressScope(MeshEgressScopeSnapshot::default()),
        ];
        let mut names: Vec<String> = carriers.iter().map(|c| c.resource_name()).collect();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), carriers.len(), "resource names must be unique");
        for carrier in carriers {
            let resource_name = carrier.resource_name();
            assert_eq!(
                carrier_resource_name_for_type_url(carrier.type_url()),
                Some(resource_name.as_str())
            );
        }
    }

    // `encode` helper is exercised indirectly by translator; keep a direct
    // smoke test so the function is not dead in test builds.
    #[test]
    fn encode_helper_matches_carrier_encode() {
        let workloads: Vec<Workload> = Vec::new();
        let direct = encode(&workloads).expect("encode");
        let via_carrier = MeshSliceCarrier::Workloads(workloads)
            .encode_value()
            .expect("encode");
        assert_eq!(direct, via_carrier);
    }
}
