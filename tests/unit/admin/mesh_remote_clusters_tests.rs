//! Unit coverage for `GET /mesh/remote-clusters`' pure response builder
//! (`ferrum_edge::admin::mesh_remote_clusters::build_response`, F7.2).
//!
//! The builder takes a staged `RemoteEndpointSnapshot` + the accepted slice's
//! `MultiClusterConfig` and produces the JSON response shape, so the whole
//! contract — discovered/configured views, counts-only payload (no raw
//! addresses/SPIFFE/URLs), age math, sorting, and the accepted-slice scoping —
//! is exercised here without standing up a `MeshRuntimeState`, an admin
//! listener, or mutating any runtime store. The integration suite
//! (`tests/integration/admin_mesh_remote_clusters_tests.rs`) covers only what
//! genuinely needs a live gateway: JWT gating, the not-in-mesh-mode 404, and
//! the empty-discovered + configured-from-accepted-slice path.

use ferrum_edge::admin::mesh_remote_clusters::{MeshRemoteClustersInputs, build_response};
use ferrum_edge::identity::{SpiffeId, TrustDomain};
use ferrum_edge::modes::mesh::config::{
    MeshService, MultiClusterConfig, RemoteCluster, ServicePort, Workload, WorkloadRef,
    WorkloadSelector,
};
use ferrum_edge::modes::mesh::multicluster::{
    RemoteClusterEndpoints, RemoteClusterEntry, RemoteEndpointSnapshot,
};
use std::collections::HashMap;

fn td(raw: &str) -> TrustDomain {
    TrustDomain::new(raw).expect("trust domain")
}

fn spiffe(raw: &str) -> SpiffeId {
    SpiffeId::new(raw.to_string()).expect("spiffe id")
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

fn snapshot_with(entries: Vec<RemoteClusterEntry>) -> RemoteEndpointSnapshot {
    let mut clusters = HashMap::new();
    for e in entries {
        clusters.insert(e.cluster_name.clone(), e);
    }
    RemoteEndpointSnapshot { clusters }
}

fn remote_cluster(
    name: &str,
    trust_domain: &str,
    network: Option<&str>,
    control_plane_url: Option<&str>,
    federation_endpoint: Option<&str>,
) -> RemoteCluster {
    RemoteCluster {
        name: name.to_string(),
        trust_domain: td(trust_domain),
        network: network.map(str::to_string),
        control_plane_url: control_plane_url.map(str::to_string),
        federation_endpoint: federation_endpoint.map(str::to_string),
    }
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
    // A discovered cluster only surfaces when it is part of the ACCEPTED slice,
    // so the config must declare it (matching name + trust domain).
    let mc = multi_cluster_with(vec![remote_cluster(
        "remote-east",
        "remote.local",
        Some("net2"),
        Some("grpcs://cp.remote.local:50051"),
        None,
    )]);
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
        multi_cluster: Some(&mc),
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
}

#[test]
fn discovered_payload_carries_no_raw_addresses_or_identities() {
    // Counts-only: the serialized discovered entry must never leak raw workload
    // addresses or SPIFFE IDs (parity with the sensitive detail kept off
    // /metrics).
    let mc = multi_cluster_with(vec![remote_cluster(
        "remote-east",
        "remote.local",
        None,
        Some("grpcs://cp.remote.local:50051"),
        None,
    )]);
    let snapshot = snapshot_with(vec![entry(
        "remote-east",
        "remote.local",
        None,
        vec![workload(
            "spiffe://remote.local/ns/default/sa/reviews",
            "reviews",
            "10.9.0.1",
        )],
        vec![service("reviews")],
        900,
    )]);
    let resp = build_response(MeshRemoteClustersInputs {
        snapshot: &snapshot,
        multi_cluster: Some(&mc),
        discovery_enabled: true,
        now_unix_seconds: 1_000,
    });
    let serialized = serde_json::to_string(&resp).expect("serialize");
    assert!(
        !serialized.contains("10.9.0.1") && !serialized.contains("spiffe://"),
        "payload must not expose raw addresses or SPIFFE IDs: {serialized}"
    );
    // Control-plane URL must never appear either.
    assert!(
        !serialized.contains("grpcs://"),
        "payload must not expose control-plane URLs: {serialized}"
    );
}

#[test]
fn discovered_is_sorted_by_cluster_name() {
    let mc = multi_cluster_with(vec![
        remote_cluster("zulu", "z.local", None, Some("grpcs://z:1"), None),
        remote_cluster("alpha", "a.local", None, Some("grpcs://a:1"), None),
        remote_cluster("mike", "m.local", None, Some("grpcs://m:1"), None),
    ]);
    let snapshot = snapshot_with(vec![
        entry("zulu", "z.local", None, vec![], vec![], 10),
        entry("alpha", "a.local", None, vec![], vec![], 10),
        entry("mike", "m.local", None, vec![], vec![], 10),
    ]);
    let resp = build_response(MeshRemoteClustersInputs {
        snapshot: &snapshot,
        multi_cluster: Some(&mc),
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
    let mc = multi_cluster_with(vec![remote_cluster(
        "remote-east",
        "remote.local",
        None,
        Some("grpcs://cp:1"),
        None,
    )]);
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
        multi_cluster: Some(&mc),
        discovery_enabled: true,
        now_unix_seconds: 1_000,
    });
    assert_eq!(resp.discovered[0].age_seconds, 0);
}

#[test]
fn configured_reflects_declared_remotes_with_url_booleans() {
    let mc = multi_cluster_with(vec![
        remote_cluster(
            "remote-east",
            "remote.local",
            Some("net2"),
            Some("grpcs://cp.remote.local:50051"),
            Some("https://spire.remote.local/bundle"),
        ),
        // Federation-only cluster: no control plane, never discoverable.
        remote_cluster(
            "remote-west",
            "west.local",
            None,
            None,
            Some("https://spire.west.local/bundle"),
        ),
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
    let mc = multi_cluster_with(vec![remote_cluster(
        "remote-blank",
        "blank.local",
        None,
        Some("   "),
        Some(""),
    )]);
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
    // The serialized shape must be stable for dashboards: `network` is elided
    // when absent (skip_serializing_if), counts are always present.
    let mc = multi_cluster_with(vec![remote_cluster(
        "remote-east",
        "remote.local",
        None,
        Some("grpcs://cp:1"),
        None,
    )]);
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
        multi_cluster: Some(&mc),
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

// ── Finding 3: discovered clusters are scoped to the ACCEPTED slice ──────────

#[test]
fn discovered_is_scoped_to_accepted_slice_clusters() {
    // The discovery store holds two clusters, but the ACCEPTED slice declares
    // only `remote-east`. `remote-rejected` is not in the accepted config and
    // MUST NOT appear as live discovery. (The store is now reconciled from the
    // accepted slice, so such an entry should not arise in production; this
    // belt-and-suspenders filter keeps it out even if it somehow does.)
    let snapshot = snapshot_with(vec![
        entry(
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
        ),
        entry(
            "remote-rejected",
            "rejected.local",
            None,
            vec![workload(
                "spiffe://rejected.local/ns/default/sa/evil",
                "evil",
                "10.6.6.6",
            )],
            vec![],
            900,
        ),
    ]);
    let mc = multi_cluster_with(vec![remote_cluster(
        "remote-east",
        "remote.local",
        Some("net2"),
        Some("grpcs://cp.remote.local:50051"),
        None,
    )]);

    let resp = build_response(MeshRemoteClustersInputs {
        snapshot: &snapshot,
        multi_cluster: Some(&mc),
        discovery_enabled: true,
        now_unix_seconds: 1_000,
    });

    let names: Vec<&str> = resp
        .discovered
        .iter()
        .map(|d| d.cluster_name.as_str())
        .collect();
    assert_eq!(
        names,
        vec!["remote-east"],
        "a discovered cluster absent from the accepted slice must be omitted"
    );
    // The configured view (one entry, remote-east) reports discovered: true.
    assert_eq!(resp.configured.len(), 1);
    assert!(resp.configured[0].discovered);
}

#[test]
fn discovered_scoping_matches_trust_domain_not_just_name() {
    // A rejected slice could reuse an accepted cluster NAME under a different
    // (attacker-chosen) trust domain. The accepted config pins `remote-east`
    // to `remote.local`; a discovered entry of the same name under
    // `evil.local` must be omitted — fail closed on the (name, trust domain)
    // pair, not the name alone.
    let snapshot = snapshot_with(vec![entry(
        "remote-east",
        "evil.local",
        None,
        vec![workload(
            "spiffe://evil.local/ns/default/sa/evil",
            "evil",
            "10.6.6.6",
        )],
        vec![],
        900,
    )]);
    let mc = multi_cluster_with(vec![remote_cluster(
        "remote-east",
        "remote.local",
        None,
        Some("grpcs://cp.remote.local:50051"),
        None,
    )]);

    let resp = build_response(MeshRemoteClustersInputs {
        snapshot: &snapshot,
        multi_cluster: Some(&mc),
        discovery_enabled: true,
        now_unix_seconds: 1_000,
    });

    assert!(
        resp.discovered.is_empty(),
        "a discovered cluster whose trust domain differs from the accepted config must be omitted"
    );
    // remote-east IS configured, but its discovered flag is false because the
    // store's same-name entry is under a different (rejected) trust domain.
    assert_eq!(resp.configured.len(), 1);
    assert!(
        !resp.configured[0].discovered,
        "the discovered flag must follow the same (name, trust domain) scoping"
    );
}

#[test]
fn discovered_filter_alone_cannot_catch_diverged_poll_identity() {
    // Codex F7.2 round-3: the admin-side filter matches only (name, trust
    // domain). A store entry that keeps the accepted name + trust domain but
    // diverges on its poll identity (`network` here, and `control_plane_url`
    // which this response shape does not even carry) therefore PASSES the
    // filter — and is reported with the STORE's network, not the accepted
    // config's. This test pins that gap to document WHY the real fix lives in
    // the discovery reconciler: it now reconciles from the *accepted* slice
    // (`start_remote_cluster_discovery_reconcile_task` →
    // `RemoteEndpointStore`), so a rejected slice that only changed
    // network/control_plane_url never starts a poller and the store can never
    // hold such an entry in the first place. The filter is belt-and-suspenders;
    // it is not, on its own, sufficient.
    let snapshot = snapshot_with(vec![entry(
        "remote-east",
        "remote.local",
        // Diverged network: the accepted config below declares `net-accepted`.
        Some("net-rejected"),
        vec![workload(
            "spiffe://remote.local/ns/default/sa/reviews",
            "reviews",
            "10.9.0.1",
        )],
        vec![],
        900,
    )]);
    let mc = multi_cluster_with(vec![remote_cluster(
        "remote-east",
        "remote.local",
        Some("net-accepted"),
        // Accepted control_plane_url v1; a rejected slice could carry v2 with
        // the same name + trust domain, and the response shape carries no URL
        // to filter on at all.
        Some("grpcs://cp-v1.remote.local:50051"),
        None,
    )]);

    let resp = build_response(MeshRemoteClustersInputs {
        snapshot: &snapshot,
        multi_cluster: Some(&mc),
        discovery_enabled: true,
        now_unix_seconds: 1_000,
    });

    // The name+trust-domain filter passes, so the diverged entry is surfaced —
    // and with the STORE's (rejected) network, not the accepted one. This is
    // the leak the reconcile-from-accepted fix prevents upstream of this filter.
    assert_eq!(resp.discovered.len(), 1);
    assert_eq!(resp.discovered[0].cluster_name, "remote-east");
    assert_eq!(
        resp.discovered[0].network.as_deref(),
        Some("net-rejected"),
        "the filter cannot tell an accepted poll identity from a diverged one; \
         the store must therefore never be fed a rejected target"
    );
}

#[test]
fn no_accepted_slice_means_no_discovered_clusters() {
    // Fail closed: with no accepted MultiClusterConfig, nothing the store holds
    // is the DP's effective discovery — `discovered` is empty even when the
    // store is populated (e.g. from a slice that was received but rejected).
    let snapshot = snapshot_with(vec![entry(
        "remote-east",
        "remote.local",
        None,
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
        multi_cluster: None,
        discovery_enabled: true,
        now_unix_seconds: 1_000,
    });
    assert!(
        resp.discovered.is_empty(),
        "no accepted multicluster config → no discovered clusters"
    );
    assert!(resp.configured.is_empty());
}
