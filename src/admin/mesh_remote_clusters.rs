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

use serde::{Deserialize, Serialize};

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
pub fn build_response(inputs: MeshRemoteClustersInputs<'_>) -> MeshRemoteClustersResponse {
    // Discovered view: one entry per fetched cluster, counts only.
    let mut discovered: Vec<DiscoveredRemoteCluster> = inputs
        .snapshot
        .clusters
        .values()
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

    // Configured view: one entry per declared remote cluster. `discovered`
    // flag cross-references the live snapshot so operators see at a glance
    // which configured clusters are actually returning endpoints.
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
                    discovered: inputs.snapshot.clusters.contains_key(&remote.name),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::TrustDomain;
    use crate::modes::mesh::config::{
        MeshService, RemoteCluster, ServicePort, Workload, WorkloadRef, WorkloadSelector,
    };
    use crate::modes::mesh::multicluster::{RemoteClusterEndpoints, RemoteClusterEntry};
    use std::collections::HashMap;

    fn td(raw: &str) -> TrustDomain {
        TrustDomain::new(raw).expect("trust domain")
    }

    fn spiffe(raw: &str) -> crate::identity::SpiffeId {
        crate::identity::SpiffeId::new(raw.to_string()).expect("spiffe id")
    }

    fn workload(spiffe_id: &str, service: &str, address: &str) -> Workload {
        let id = spiffe(spiffe_id);
        let trust_domain = id.trust_domain().clone();
        Workload {
            spiffe_id: id,
            selector: WorkloadSelector::default(),
            service_name: service.to_string(),
            addresses: vec![address.to_string()],
            ports: vec![],
            trust_domain,
            namespace: "default".to_string(),
            network: None,
            cluster: None,
            weight: None,
            locality: None,
            service_account: None,
            pod_uid: None,
        }
    }

    fn service(name: &str) -> MeshService {
        MeshService {
            cluster_ips: Vec::new(),
            name: name.to_string(),
            namespace: "default".to_string(),
            ports: vec![ServicePort {
                port: 8080,
                protocol: Default::default(),
                name: Some("http".to_string()),
                target_port: None,
            }],
            workloads: vec![WorkloadRef {
                spiffe_id: spiffe("spiffe://remote.local/ns/default/sa/reviews"),
            }],
            protocol_overrides: HashMap::new(),
        }
    }

    fn snapshot_with(entries: Vec<RemoteClusterEntry>) -> RemoteEndpointSnapshot {
        let mut clusters = HashMap::new();
        for entry in entries {
            clusters.insert(entry.cluster_name.clone(), entry);
        }
        RemoteEndpointSnapshot { clusters }
    }

    fn entry(
        cluster: &str,
        trust_domain: &str,
        network: Option<&str>,
        workloads: Vec<Workload>,
        services: Vec<MeshService>,
        fetched_at: u64,
    ) -> RemoteClusterEntry {
        RemoteClusterEntry {
            cluster_name: cluster.to_string(),
            trust_domain: td(trust_domain),
            network: network.map(str::to_string),
            endpoints: RemoteClusterEndpoints {
                workloads,
                services,
            },
            fetched_at_unix_seconds: fetched_at,
        }
    }

    #[test]
    fn empty_when_no_discovery_and_no_config() {
        let snapshot = RemoteEndpointSnapshot::default();
        let resp = build_response(MeshRemoteClustersInputs {
            snapshot: &snapshot,
            multi_cluster: None,
            discovery_enabled: false,
            now_unix_seconds: 1_000,
        });
        assert!(!resp.discovery_enabled);
        assert!(resp.discovered.is_empty());
        assert!(resp.configured.is_empty());
    }

    #[test]
    fn discovered_surfaces_counts_and_age() {
        let snapshot = snapshot_with(vec![entry(
            "remote-east",
            "remote.local",
            Some("net2"),
            vec![
                workload(
                    "spiffe://remote.local/ns/default/sa/reviews",
                    "reviews",
                    "10.9.0.1",
                ),
                workload(
                    "spiffe://remote.local/ns/default/sa/reviews",
                    "reviews",
                    "10.9.0.2",
                ),
            ],
            vec![service("reviews")],
            900,
        )]);
        let resp = build_response(MeshRemoteClustersInputs {
            snapshot: &snapshot,
            multi_cluster: None,
            discovery_enabled: true,
            now_unix_seconds: 1_000,
        });

        assert!(resp.discovery_enabled);
        assert_eq!(resp.discovered.len(), 1);
        let d = &resp.discovered[0];
        assert_eq!(d.cluster_name, "remote-east");
        assert_eq!(d.trust_domain, "remote.local");
        assert_eq!(d.network.as_deref(), Some("net2"));
        assert_eq!(d.workload_count, 2);
        assert_eq!(d.service_count, 1);
        assert_eq!(d.fetched_at_unix_seconds, 900);
        assert_eq!(d.age_seconds, 100);
        // No config → no configured view even when discovery returned data.
        assert!(resp.configured.is_empty());
    }

    #[test]
    fn discovered_is_sorted_by_cluster_name() {
        let snapshot = snapshot_with(vec![
            entry("zulu", "z.local", None, vec![], vec![], 10),
            entry("alpha", "a.local", None, vec![], vec![], 10),
            entry("mike", "m.local", None, vec![], vec![], 10),
        ]);
        let resp = build_response(MeshRemoteClustersInputs {
            snapshot: &snapshot,
            multi_cluster: None,
            discovery_enabled: true,
            now_unix_seconds: 10,
        });
        let names: Vec<&str> = resp
            .discovered
            .iter()
            .map(|d| d.cluster_name.as_str())
            .collect();
        assert_eq!(names, vec!["alpha", "mike", "zulu"]);
    }

    #[test]
    fn future_fetch_timestamp_clamps_age_to_zero() {
        // Clock skew: the remote CP stamped a fetch time ahead of our `now`.
        let snapshot = snapshot_with(vec![entry(
            "remote-east",
            "remote.local",
            None,
            vec![],
            vec![],
            2_000,
        )]);
        let resp = build_response(MeshRemoteClustersInputs {
            snapshot: &snapshot,
            multi_cluster: None,
            discovery_enabled: true,
            now_unix_seconds: 1_000,
        });
        assert_eq!(resp.discovered[0].age_seconds, 0);
    }

    fn multi_cluster_with(remotes: Vec<RemoteCluster>) -> MultiClusterConfig {
        MultiClusterConfig {
            local_cluster: Some("local".to_string()),
            federation_endpoint: None,
            remote_clusters: remotes,
            east_west_gateways: Vec::new(),
        }
    }

    #[test]
    fn configured_reflects_declared_remotes_with_url_booleans() {
        let mc = multi_cluster_with(vec![
            RemoteCluster {
                name: "remote-east".to_string(),
                trust_domain: td("remote.local"),
                network: Some("net2".to_string()),
                control_plane_url: Some("grpcs://cp.remote.local:50051".to_string()),
                federation_endpoint: Some("https://spire.remote.local/bundle".to_string()),
            },
            RemoteCluster {
                name: "remote-west".to_string(),
                trust_domain: td("west.local"),
                network: None,
                // Federation-only cluster: no control plane, never discoverable.
                control_plane_url: None,
                federation_endpoint: Some("https://spire.west.local/bundle".to_string()),
            },
        ]);
        // Only remote-east has been discovered.
        let snapshot = snapshot_with(vec![entry(
            "remote-east",
            "remote.local",
            Some("net2"),
            vec![workload(
                "spiffe://remote.local/ns/default/sa/reviews",
                "reviews",
                "10.9.0.1",
            )],
            vec![],
            900,
        )]);

        let resp = build_response(MeshRemoteClustersInputs {
            snapshot: &snapshot,
            multi_cluster: Some(&mc),
            discovery_enabled: true,
            now_unix_seconds: 1_000,
        });

        assert_eq!(resp.configured.len(), 2);
        // Sorted: remote-east before remote-west.
        let east = &resp.configured[0];
        assert_eq!(east.cluster_name, "remote-east");
        assert_eq!(east.trust_domain, "remote.local");
        assert_eq!(east.network.as_deref(), Some("net2"));
        assert!(east.control_plane_configured);
        assert!(east.federation_endpoint_configured);
        assert!(east.discovered, "remote-east is in the snapshot");

        let west = &resp.configured[1];
        assert_eq!(west.cluster_name, "remote-west");
        assert!(!west.control_plane_configured);
        assert!(west.federation_endpoint_configured);
        assert!(
            !west.discovered,
            "remote-west is configured (federation-only) but not discovered"
        );
    }

    #[test]
    fn configured_treats_blank_urls_as_unset() {
        // Whitespace-only URLs are not real configuration — the poller's
        // `poll_targets_for_multi_cluster` trims-and-drops them, so the
        // introspection view must agree (`control_plane_configured: false`).
        let mc = multi_cluster_with(vec![RemoteCluster {
            name: "remote-blank".to_string(),
            trust_domain: td("blank.local"),
            network: None,
            control_plane_url: Some("   ".to_string()),
            federation_endpoint: Some(String::new()),
        }]);
        let snapshot = RemoteEndpointSnapshot::default();
        let resp = build_response(MeshRemoteClustersInputs {
            snapshot: &snapshot,
            multi_cluster: Some(&mc),
            discovery_enabled: true,
            now_unix_seconds: 0,
        });
        assert_eq!(resp.configured.len(), 1);
        assert!(!resp.configured[0].control_plane_configured);
        assert!(!resp.configured[0].federation_endpoint_configured);
        assert!(!resp.configured[0].discovered);
    }

    #[test]
    fn response_round_trips_and_omits_absent_network() {
        // The serialized shape must be stable for dashboards: `network` is
        // elided when absent (skip_serializing_if), counts are always present.
        let snapshot = snapshot_with(vec![entry(
            "remote-east",
            "remote.local",
            None,
            vec![],
            vec![],
            500,
        )]);
        let resp = build_response(MeshRemoteClustersInputs {
            snapshot: &snapshot,
            multi_cluster: None,
            discovery_enabled: true,
            now_unix_seconds: 500,
        });
        let value = serde_json::to_value(&resp).expect("serialize");
        assert_eq!(value["discovery_enabled"], true);
        assert!(value["discovered"][0].get("network").is_none());
        assert_eq!(value["discovered"][0]["workload_count"], 0);
        assert_eq!(value["discovered"][0]["service_count"], 0);
        assert_eq!(value["discovered"][0]["age_seconds"], 0);
        // `configured` is always an array (possibly empty), never null.
        assert!(value["configured"].is_array());
    }
}
