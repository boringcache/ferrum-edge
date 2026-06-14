//! Response builder for `GET /mesh/remote-clusters` (F7.2).
//!
//! Operators previously inferred remote-cluster state only indirectly: a
//! healthy cross-cluster discovery shows up as a bump in
//! `GET /mesh/config-drift`'s workload/service `resources` counts, and a
//! stuck one shows up as those counts going flat — neither tells you *which*
//! remote cluster is contributing, nor distinguishes "configured but never
//! successfully polled" from "not configured at all". This endpoint surfaces
//! the data plane's own view of multicluster east-west discovery directly.
//!
//! Two views are returned, kept deliberately separate because they answer
//! different questions:
//!
//!   - `discovered`: the live
//!     [`crate::modes::mesh::multicluster::RemoteEndpointStore`] snapshot —
//!     remote clusters this DP has actually fetched endpoints from, keyed by
//!     cluster name, with per-cluster workload/service counts and the fetch
//!     timestamp + derived age. This is the authoritative "what is this DP
//!     merging into its local registry right now" answer. An empty map means
//!     discovery is disabled (`FERRUM_MESH_REMOTE_DISCOVERY_POLL_INTERVAL_SECONDS`
//!     is `0`), no remote cluster is trust-eligible yet, or no poll has
//!     succeeded.
//!   - `configured`: the remote clusters declared in the **accepted** slice's
//!     `MultiClusterConfig` (name, trust domain, network, and whether a
//!     `control_plane_url` / `federation_endpoint` is set). A cluster that is
//!     `configured` but absent from `discovered` is the exact "I declared it
//!     but nothing is coming back" signal operators want — without it, a
//!     misconfigured / unreachable remote cluster is invisible.
//!
//! Like the other `/mesh/*` introspection endpoints, the handler in
//! `admin/mod.rs` returns `404` when the process is not in mesh mode (no mesh
//! runtime state wired), and the surface is JWT-authenticated. The payload is
//! a topology-shape summary — counts and provenance, never raw workload
//! addresses, SPIFFE IDs, or control-plane URLs — so the sensitive detail that
//! `/mesh/config-drift` keeps off `/metrics` stays off this surface too, while
//! the JWT still gates the topology shape it does reveal.
//!
//! See `docs/mesh.md` "Cross-Cluster Endpoint Discovery" for the operator
//! playbook.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::identity::TrustDomain;
use crate::modes::mesh::config::MultiClusterConfig;
use crate::modes::mesh::multicluster::RemoteEndpointSnapshot;

/// One remote cluster this DP has successfully fetched endpoints from. Counts
/// (not the endpoints themselves) are surfaced so the payload describes the
/// shape of cross-cluster discovery without re-exporting every workload
/// address / identity — mirroring `/mesh/config-drift`'s per-kind `resources`
/// counts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredRemoteCluster {
    /// Operator-facing remote cluster name (the `RemoteEndpointSnapshot` key,
    /// validated unique). Repeated in the body so each entry is
    /// self-describing.
    pub cluster_name: String,
    /// SPIFFE trust domain the remote cluster's endpoints were ingested under.
    pub trust_domain: String,
    /// Istio network label of the remote cluster, used to default remote
    /// workload locality for multi-network routing. Absent when the remote
    /// cluster declares no network.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    /// Number of remote workloads merged into the local registry from this
    /// cluster.
    pub workload_count: usize,
    /// Number of remote services merged into the local registry from this
    /// cluster.
    pub service_count: usize,
    /// Unix timestamp (seconds) of the most recent successful poll of this
    /// cluster.
    pub fetched_at_unix_seconds: u64,
    /// `now - fetched_at_unix_seconds`, clamped to `0`. Operators alert on
    /// this exceeding a few poll intervals to spot a remote cluster whose
    /// discovery has wedged while keeping its last-good endpoints.
    pub age_seconds: u64,
}

/// One remote cluster declared in the accepted slice's `MultiClusterConfig`.
/// Reveals only the shape of the configuration — never the control-plane /
/// federation URLs themselves (those are surfaced as booleans), keeping
/// endpoint detail off the wire while still letting operators confirm a
/// cluster is configured for discovery (`control_plane_url`) and/or trust
/// federation (`federation_endpoint`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfiguredRemoteCluster {
    /// Operator-facing remote cluster name.
    pub cluster_name: String,
    /// SPIFFE trust domain declared for the remote cluster.
    pub trust_domain: String,
    /// Istio network label, when declared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    /// Whether a `control_plane_url` is configured — i.e. whether this cluster
    /// is a candidate for cross-cluster endpoint discovery at all. `false`
    /// means the cluster is federation-only and will never appear under
    /// `discovered`.
    pub control_plane_configured: bool,
    /// Whether a `federation_endpoint` is configured for SPIFFE trust-bundle
    /// exchange with this cluster.
    pub federation_endpoint_configured: bool,
    /// `true` when a cluster of this name is present in the live `discovered`
    /// map — a quick "is configured discovery actually returning anything?"
    /// flag so operators don't have to cross-reference the two lists by hand.
    pub discovered: bool,
}

/// Top-level response shape. The handler in `admin/mod.rs` is a thin wrapper
/// that stages [`MeshRemoteClustersInputs`] and serializes this struct.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshRemoteClustersResponse {
    /// `true` when cross-cluster endpoint discovery is enabled
    /// (`FERRUM_MESH_REMOTE_DISCOVERY_POLL_INTERVAL_SECONDS > 0`). When
    /// `false`, `discovered` is always empty regardless of configuration —
    /// surfaced so an operator can tell "discovery off" apart from "discovery
    /// on but nothing fetched yet".
    pub discovery_enabled: bool,
    /// Remote clusters this DP has fetched endpoints from, sorted by
    /// `cluster_name` for stable byte-identical responses across polls.
    pub discovered: Vec<DiscoveredRemoteCluster>,
    /// Remote clusters declared in the accepted slice, sorted by
    /// `cluster_name`. Empty when no slice has been accepted or the accepted
    /// slice declares no `MultiClusterConfig`.
    pub configured: Vec<ConfiguredRemoteCluster>,
}

/// Inputs for the response builder. Kept as a struct so the unit tests can
/// stage state without constructing a `MeshRuntimeState` / `EnvConfig`, and so
/// the handler is one literal away from a JSON response.
pub struct MeshRemoteClustersInputs<'a> {
    /// Live remote-endpoint snapshot from
    /// [`crate::modes::mesh::multicluster::RemoteEndpointStore::snapshot`].
    pub snapshot: &'a RemoteEndpointSnapshot,
    /// The accepted slice's `MultiClusterConfig`, if any. `None` when no slice
    /// has been accepted or the slice carries no multicluster config — the
    /// `configured` list is then empty.
    pub multi_cluster: Option<&'a MultiClusterConfig>,
    /// Whether discovery is enabled (poll interval > 0). Passed in rather than
    /// derived from the snapshot because an enabled-but-not-yet-converged
    /// discovery has an empty snapshot, indistinguishable from disabled.
    pub discovery_enabled: bool,
    /// Wall-clock "now" as a Unix timestamp (seconds) used to compute
    /// `age_seconds`. Injected so unit tests are deterministic.
    pub now_unix_seconds: u64,
}

/// Build the response from staged inputs. Pure function — no I/O, no clock
/// reads. Unit-tested directly to lock down the shape.
///
/// Both views are derived from the **accepted** slice's `MultiClusterConfig`.
/// The discovery store is fed from the *received* slice, which can transiently
/// diverge from the accepted one during a rejected-slice window: the store
/// could hold clusters declared by a slice the proxy REJECTED. Surfacing those
/// would make an invalid slice look like live cross-cluster discovery, so a
/// discovered cluster is scoped to the accepted config — matched by **cluster
/// name and declared trust domain** — and a cluster absent from the accepted
/// config (or present under a different trust domain) is **omitted** from
/// `discovered`. Fail closed: when no slice is accepted (or it carries no
/// `MultiClusterConfig`), the accepted set is empty and `discovered` is empty
/// regardless of what the store holds.
pub fn build_response(inputs: MeshRemoteClustersInputs<'_>) -> MeshRemoteClustersResponse {
    // Accepted remote-cluster set: name → declared trust domain. Discovery
    // entries are only surfaced when they match an accepted (name, trust
    // domain) pair, so a rejected slice's clusters never appear as live
    // discovery. Empty when no slice / no multicluster config is accepted.
    let accepted: HashMap<&str, &TrustDomain> = inputs
        .multi_cluster
        .map(|mc| {
            mc.remote_clusters
                .iter()
                .map(|remote| (remote.name.as_str(), &remote.trust_domain))
                .collect()
        })
        .unwrap_or_default();

    // Discovered view: one entry per fetched cluster, counts only — filtered to
    // the accepted slice's clusters (by name AND trust domain), so a
    // received-but-rejected slice's clusters are not reported as discovered.
    let mut discovered: Vec<DiscoveredRemoteCluster> = inputs
        .snapshot
        .clusters
        .values()
        .filter(|entry| {
            accepted
                .get(entry.cluster_name.as_str())
                .is_some_and(|accepted_td| **accepted_td == entry.trust_domain)
        })
        .map(|entry| DiscoveredRemoteCluster {
            cluster_name: entry.cluster_name.clone(),
            trust_domain: entry.trust_domain.as_str().to_string(),
            network: entry.network.clone(),
            workload_count: entry.endpoints.workloads.len(),
            service_count: entry.endpoints.services.len(),
            fetched_at_unix_seconds: entry.fetched_at_unix_seconds,
            // Saturating sub: a fetch timestamp ahead of `now` (clock skew on
            // the remote CP's clock vs ours) maps to `0` rather than wrapping.
            age_seconds: inputs
                .now_unix_seconds
                .saturating_sub(entry.fetched_at_unix_seconds),
        })
        .collect();
    discovered.sort_by(|a, b| a.cluster_name.cmp(&b.cluster_name));

    // Names that survived the accepted-scope filter, so the `configured`
    // view's `discovered` flag reflects the SAME scoped set the operator sees
    // under `discovered` (never a rejected-slice cluster).
    let discovered_names: HashSet<&str> =
        discovered.iter().map(|d| d.cluster_name.as_str()).collect();

    // Configured view: one entry per declared remote cluster. `discovered`
    // flag cross-references the scoped discovered set so operators see at a
    // glance which configured clusters are actually returning endpoints.
    let configured: Vec<ConfiguredRemoteCluster> = inputs
        .multi_cluster
        .map(|mc| {
            let mut entries: Vec<ConfiguredRemoteCluster> = mc
                .remote_clusters
                .iter()
                .map(|remote| ConfiguredRemoteCluster {
                    cluster_name: remote.name.clone(),
                    trust_domain: remote.trust_domain.as_str().to_string(),
                    network: remote.network.clone(),
                    control_plane_configured: remote
                        .control_plane_url
                        .as_deref()
                        .is_some_and(|url| !url.trim().is_empty()),
                    federation_endpoint_configured: remote
                        .federation_endpoint
                        .as_deref()
                        .is_some_and(|url| !url.trim().is_empty()),
                    discovered: discovered_names.contains(remote.name.as_str()),
                })
                .collect();
            entries.sort_by(|a, b| a.cluster_name.cmp(&b.cluster_name));
            entries
        })
        .unwrap_or_default();

    MeshRemoteClustersResponse {
        discovery_enabled: inputs.discovery_enabled,
        discovered,
        configured,
    }
}
