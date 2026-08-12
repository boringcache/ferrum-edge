//! NodeWaypoint UDP/DTLS scoped `AuthorizationPolicy` end to end (issue #3286).
//!
//! The TCP path scopes a stream's source pod through the socket-cookie bridge;
//! UDP/DTLS cannot (one shared frontend socket, one cookie, no UDP capture
//! hooks). This suite covers the replacement channel and the slice-preparation
//! change that depends on it:
//!
//!   - the reconcile loop turning the node-agent registry + resolved host-side
//!     interfaces into a published attribution generation, across add / update /
//!     delete;
//!   - `NodeWaypointUdpSourceScoping::resolve` joining an attributed pod to the
//!     LIVE slice's per-pod `PolicyScopeCache`, including the fail-closed case
//!     where the workload has left the slice;
//!   - a policy CHANGE (a new slice generation) taking effect for already-
//!     attributed pods;
//!   - and the per-pod policy filter `mesh_authz` runs, so a namespace-scoped
//!     DENY applies to the source pod it names and not to its neighbour.
//!
//! The matching slice-preparation change — NodeWaypoint no longer strips
//! UDP/DTLS service ports, proxies, upstreams, or DNS visibility where this
//! channel exists — is pinned beside that code in `src/modes/mesh/mod.rs`.

use std::collections::HashMap;
use std::sync::Arc;

use ferrum_edge::identity::{SpiffeId, TrustDomain};
use ferrum_edge::modes::mesh::config::{
    MeshPolicy, MeshRule, PolicyAction, PolicyScope, Workload, WorkloadSelector,
};
use ferrum_edge::modes::mesh::hbone::UdpSourceIdentity;
use ferrum_edge::modes::mesh::node_waypoint::NodeWaypointIdentityResolver;
use ferrum_edge::proxy::host_udp_capture::ResolvedInterface;
use ferrum_edge::proxy::netns_capture::{PodCaptureSource, PodCaptureSourceIps, PodCaptureTarget};
use ferrum_edge::proxy::node_waypoint_udp_identity::{
    NodeWaypointUdpDatagramVerdict, NodeWaypointUdpInterfaceResolver, NodeWaypointUdpSourceIndex,
    NodeWaypointUdpSourceIndexManager, NodeWaypointUdpSourceRefusal, NodeWaypointUdpSourceScoping,
};

const POD_A: &str = "11111111-1111-1111-1111-111111111111";
const POD_B: &str = "22222222-2222-2222-2222-222222222222";
const SPIFFE_A: &str = "spiffe://cluster.local/ns/team-a/sa/api";
const SPIFFE_B: &str = "spiffe://cluster.local/ns/team-b/sa/api";
const IP_A: &str = "10.244.1.7";
const IP_B: &str = "10.244.1.8";
const IFINDEX_A: u32 = 71;
const IFINDEX_B: u32 = 82;

fn spiffe(raw: &str) -> SpiffeId {
    SpiffeId::new(raw).expect("valid test SPIFFE ID")
}

fn labels(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn workload(
    spiffe_id: &str,
    namespace: &str,
    labels: HashMap<String, String>,
    pod_uid: &str,
) -> Workload {
    Workload {
        spiffe_id: spiffe(spiffe_id),
        selector: WorkloadSelector {
            labels,
            namespace: Some(namespace.to_string()),
        },
        service_name: "api".to_string(),
        service_namespace: None,
        addresses: Vec::new(),
        ports: Vec::new(),
        trust_domain: TrustDomain::new("cluster.local").expect("valid trust domain"),
        namespace: namespace.to_string(),
        network: None,
        cluster: None,
        weight: None,
        locality: None,
        service_account: None,
        pod_uid: Some(pod_uid.to_string()),
        node_waypoint: None,
        remote_provenance: false,
    }
}

fn registry_target(pod_uid: &str, spiffe_id: &str, ipv4: &str) -> PodCaptureTarget {
    PodCaptureTarget {
        pod_uid: pod_uid.to_string(),
        cgroup_path: format!("/sys/fs/cgroup/kubepods/pod{pod_uid}"),
        source_identity: UdpSourceIdentity::new(spiffe(spiffe_id), pod_uid.to_string()),
        source_ips: PodCaptureSourceIps {
            ipv4: Some(ipv4.parse().expect("valid v4")),
            ipv6: None,
        },
    }
}

/// In-memory stand-in for the node-agent-published registry directory.
#[derive(Default)]
struct FakeRegistry {
    targets: std::sync::Mutex<Vec<PodCaptureTarget>>,
}

impl FakeRegistry {
    fn set(&self, targets: Vec<PodCaptureTarget>) {
        *self.targets.lock().expect("registry lock") = targets;
    }
}

impl PodCaptureSource for FakeRegistry {
    fn list_targets(&self) -> Vec<PodCaptureTarget> {
        self.targets.lock().expect("registry lock").clone()
    }
}

/// Stand-in for host-side veth resolution. Production reads the pod netns view
/// and the host route table; the reconcile logic under test is independent of
/// how a name/index was obtained.
#[derive(Default)]
struct FakeInterfaces {
    by_pod: std::sync::Mutex<HashMap<String, ResolvedInterface>>,
}

impl FakeInterfaces {
    fn set(&self, entries: &[(&str, &str, u32)]) {
        let mut map = self.by_pod.lock().expect("interface lock");
        map.clear();
        for (pod_uid, name, ifindex) in entries {
            map.insert(
                (*pod_uid).to_string(),
                ResolvedInterface {
                    name: (*name).to_string(),
                    ifindex: *ifindex,
                },
            );
        }
    }
}

/// Local newtype so the resolver trait is implemented on a type this crate
/// owns (the orphan rule forbids `impl ForeignTrait for Arc<Local>`).
struct FakeInterfaceResolver(Arc<FakeInterfaces>);

impl NodeWaypointUdpInterfaceResolver for FakeInterfaceResolver {
    fn resolve_interface(&self, target: &PodCaptureTarget) -> Result<ResolvedInterface, String> {
        self.0
            .by_pod
            .lock()
            .expect("interface lock")
            .get(&target.pod_uid)
            .cloned()
            .ok_or_else(|| "unresolved".to_string())
    }
}

struct Fixture {
    registry: Arc<FakeRegistry>,
    interfaces: Arc<FakeInterfaces>,
    index: Arc<NodeWaypointUdpSourceIndex>,
    resolver: Arc<NodeWaypointIdentityResolver>,
    manager: NodeWaypointUdpSourceIndexManager<FakeInterfaceResolver>,
}

impl Fixture {
    /// Both pods enrolled on their own interfaces, both present in the slice.
    fn new() -> Self {
        let registry = Arc::new(FakeRegistry::default());
        registry.set(vec![
            registry_target(POD_A, SPIFFE_A, IP_A),
            registry_target(POD_B, SPIFFE_B, IP_B),
        ]);
        let interfaces = Arc::new(FakeInterfaces::default());
        interfaces.set(&[(POD_A, "vethA", IFINDEX_A), (POD_B, "vethB", IFINDEX_B)]);

        let index = Arc::new(NodeWaypointUdpSourceIndex::new());
        let resolver = Arc::new(NodeWaypointIdentityResolver::new(0));
        resolver.install_policy_scopes_from_workloads(&[
            workload(SPIFFE_A, "team-a", labels(&[("app", "api")]), POD_A),
            workload(SPIFFE_B, "team-b", labels(&[("app", "api")]), POD_B),
        ]);

        let manager = NodeWaypointUdpSourceIndexManager::new(
            registry.clone(),
            FakeInterfaceResolver(interfaces.clone()),
            index.clone(),
            std::time::Duration::from_secs(2),
        );
        Self {
            registry,
            interfaces,
            index,
            resolver,
            manager,
        }
    }

    fn scoping(&self) -> NodeWaypointUdpSourceScoping {
        NodeWaypointUdpSourceScoping {
            index: self.index.clone(),
            resolver: self.resolver.clone(),
        }
    }
}

fn ip(addr: &str) -> std::net::IpAddr {
    addr.parse().expect("valid address")
}

fn namespace_deny(name: &str, namespace: &str) -> MeshPolicy {
    MeshPolicy {
        name: name.to_string(),
        namespace: "istio-system".to_string(),
        scope: PolicyScope::Namespace {
            namespace: namespace.to_string(),
        },
        rules: vec![MeshRule {
            action: PolicyAction::Deny,
            ..MeshRule::default()
        }],
    }
}

/// The whole chain a UDP session runs at admission: attribute the datagram to a
/// pod from its ingress interface + source address, then resolve THAT pod's
/// per-pod scope out of the live slice.
#[test]
fn a_reconciled_registry_scopes_each_pods_datagrams_to_its_own_policy_scope() {
    let fixture = Fixture::new();
    fixture.manager.reconcile_once();
    let scoping = fixture.scoping();

    let a = scoping
        .resolve(Some(IFINDEX_A), ip(IP_A))
        .expect("pod A's datagram resolves");
    assert_eq!(a.scope.namespace, "team-a");
    assert_eq!(a.binding.principal, spiffe(SPIFFE_A));

    let b = scoping
        .resolve(Some(IFINDEX_B), ip(IP_B))
        .expect("pod B's datagram resolves");
    assert_eq!(b.scope.namespace, "team-b");
    assert_eq!(b.binding.principal, spiffe(SPIFFE_B));
}

/// The per-pod filter `mesh_authz` applies once the session carries a scope: a
/// namespace-scoped DENY must bind to the source pod it names and leave its
/// neighbour alone. Without the attribution above, both sessions would carry no
/// scope and be denied wholesale.
#[test]
fn a_namespace_scoped_deny_binds_to_the_attributed_source_pod_only() {
    let fixture = Fixture::new();
    fixture.manager.reconcile_once();
    let scoping = fixture.scoping();
    let deny_team_a = namespace_deny("team-a-deny", "team-a");

    let a = scoping
        .resolve(Some(IFINDEX_A), ip(IP_A))
        .expect("pod A resolves");
    let b = scoping
        .resolve(Some(IFINDEX_B), ip(IP_B))
        .expect("pod B resolves");

    assert!(
        a.scope.policy_applies(&deny_team_a),
        "the DENY names team-a, and pod A's session is attributed to a team-a workload"
    );
    assert!(
        !b.scope.policy_applies(&deny_team_a),
        "pod B is in team-b; a team-a-scoped DENY must not suppress its UDP session"
    );
}

/// A spoofed source address does not become another tenant's scope: the
/// interface it arrived on is the anchor, and that interface's pod does not own
/// the forged address.
#[test]
fn one_pod_cannot_obtain_another_pods_scope_by_forging_its_source_address() {
    let fixture = Fixture::new();
    fixture.manager.reconcile_once();
    let scoping = fixture.scoping();

    let refusal = scoping
        .resolve(Some(IFINDEX_B), ip(IP_A))
        .err()
        .expect("pod B forging pod A's address must not resolve");
    assert_eq!(refusal, NodeWaypointUdpSourceRefusal::SourceAddressMismatch);
}

/// A pod that is attributable but whose workload has left the live slice has no
/// per-pod scope. That is a fail-closed outcome, not a fall-through: the caller
/// leaves the session unscoped and `mesh_authz` denies it while scoped policies
/// exist.
#[test]
fn a_pod_that_left_the_live_slice_resolves_no_scope() {
    let fixture = Fixture::new();
    fixture.manager.reconcile_once();

    // A new slice generation that no longer carries pod B's workload.
    fixture
        .resolver
        .install_policy_scopes_from_workloads(&[workload(
            SPIFFE_A,
            "team-a",
            labels(&[("app", "api")]),
            POD_A,
        )]);

    let scoping = fixture.scoping();
    assert!(
        scoping.resolve(Some(IFINDEX_A), ip(IP_A)).is_ok(),
        "the workload still in the slice keeps resolving"
    );
    assert_eq!(
        scoping
            .resolve(Some(IFINDEX_B), ip(IP_B))
            .err()
            .expect("a removed workload must not resolve a stale scope"),
        NodeWaypointUdpSourceRefusal::PodNotInSlice
    );
}

/// A registry generation and a slice generation are independent publications.
/// If the slice re-attests the same pod UID under a new SPIFFE identity before
/// the registry catches up, the stale registry principal must not be paired
/// with the new workload's scope.
#[test]
fn a_stale_registry_principal_cannot_borrow_a_re_attested_pods_scope() {
    let fixture = Fixture::new();
    fixture.manager.reconcile_once();
    let pinned = fixture
        .scoping()
        .resolve(Some(IFINDEX_A), ip(IP_A))
        .expect("initial registry and slice generations agree")
        .binding;

    fixture
        .resolver
        .install_policy_scopes_from_workloads(&[workload(
            SPIFFE_B,
            "team-a",
            labels(&[("app", "api")]),
            POD_A,
        )]);

    let scoping = fixture.scoping();
    assert_eq!(
        scoping
            .resolve(Some(IFINDEX_A), ip(IP_A))
            .err()
            .expect("a stale principal must fail admission"),
        NodeWaypointUdpSourceRefusal::PodNotInSlice
    );
    assert_eq!(
        scoping
            .revalidate(&pinned, Some(IFINDEX_A), ip(IP_A))
            .expect_err("a live session must fail when the slice re-attests its pod"),
        NodeWaypointUdpSourceRefusal::PodNotInSlice
    );
}

/// Reload/update, not just first construction: a workload whose labels change
/// in a new slice generation must be scoped by the NEW labels for sessions
/// admitted after the change.
#[test]
fn a_policy_relevant_label_change_takes_effect_on_the_next_admission() {
    let fixture = Fixture::new();
    fixture.manager.reconcile_once();
    let selector_deny = MeshPolicy {
        name: "canary-deny".to_string(),
        namespace: "istio-system".to_string(),
        scope: PolicyScope::WorkloadSelector {
            selector: WorkloadSelector {
                labels: labels(&[("release", "canary")]),
                namespace: Some("team-a".to_string()),
            },
        },
        rules: vec![MeshRule {
            action: PolicyAction::Deny,
            ..MeshRule::default()
        }],
    };

    let before = fixture
        .scoping()
        .resolve(Some(IFINDEX_A), ip(IP_A))
        .expect("pod A resolves");
    assert!(
        !before.scope.policy_applies(&selector_deny),
        "pod A is not labelled release=canary yet"
    );

    fixture
        .resolver
        .install_policy_scopes_from_workloads(&[workload(
            SPIFFE_A,
            "team-a",
            labels(&[("app", "api"), ("release", "canary")]),
            POD_A,
        )]);

    let after = fixture
        .scoping()
        .resolve(Some(IFINDEX_A), ip(IP_A))
        .expect("pod A still resolves");
    assert!(
        after.scope.policy_applies(&selector_deny),
        "the selector-scoped DENY must apply once the new slice generation labels the workload"
    );
}

/// Delete: a pod removed from the registry stops being attributable on the very
/// next reconcile, and sessions pinned to its old binding stop revalidating.
#[test]
fn deleting_a_pod_from_the_registry_retracts_its_attribution() {
    let fixture = Fixture::new();
    fixture.manager.reconcile_once();
    let pinned = fixture
        .index
        .authorize(Some(IFINDEX_B), ip(IP_B))
        .expect("pod B admitted");

    fixture
        .registry
        .set(vec![registry_target(POD_A, SPIFFE_A, IP_A)]);
    fixture.manager.reconcile_once();

    assert!(
        fixture.index.authorize(Some(IFINDEX_B), ip(IP_B)).is_err(),
        "a removed pod must not keep admitting new sessions"
    );
    assert_eq!(
        fixture
            .index
            .revalidate(&pinned, Some(IFINDEX_B), ip(IP_B))
            .expect_err("its live session must stop too"),
        NodeWaypointUdpSourceRefusal::UnenrolledInterface
    );
    assert!(
        fixture.index.authorize(Some(IFINDEX_A), ip(IP_A)).is_ok(),
        "the surviving pod is undisturbed by its neighbour's removal"
    );
}

/// Update: the same pod moving to a new veth (a restart under the same UID)
/// republishes on the new index and stops answering on the old one.
#[test]
fn a_pod_moving_to_a_new_interface_is_attributed_on_the_new_one_only() {
    let fixture = Fixture::new();
    fixture.manager.reconcile_once();

    fixture
        .interfaces
        .set(&[(POD_A, "vethA2", 91), (POD_B, "vethB", IFINDEX_B)]);
    fixture.manager.reconcile_once();

    assert!(
        fixture.index.authorize(Some(91), ip(IP_A)).is_ok(),
        "the pod is attributable on its new host-side interface"
    );
    assert_eq!(
        fixture
            .index
            .authorize(Some(IFINDEX_A), ip(IP_A))
            .expect_err("the stale interface must attribute nothing"),
        NodeWaypointUdpSourceRefusal::UnenrolledInterface
    );
}

/// Unresolvable source: an enrolled pod whose host-side interface cannot be
/// resolved this pass is refused rather than admitted unattributed, and its
/// neighbour is unaffected.
#[test]
fn an_unresolvable_pod_interface_refuses_only_that_pod() {
    let fixture = Fixture::new();
    fixture.interfaces.set(&[(POD_B, "vethB", IFINDEX_B)]);

    let published = fixture.manager.reconcile_once();

    assert_eq!(published.len(), 1);
    assert_eq!(published[0].pod_uid, POD_B);
    assert!(
        fixture.index.authorize(Some(IFINDEX_A), ip(IP_A)).is_err(),
        "an unresolvable pod is never attributable"
    );
    assert!(
        fixture.scoping().resolve(Some(IFINDEX_B), ip(IP_B)).is_ok(),
        "its neighbour keeps working"
    );
}

/// A shared interface (bridge CNI, or a stale registry entry pointing at a
/// recycled veth) refuses BOTH claimants. Attribution under a guessed identity
/// is precisely the cross-tenant confusion this channel must not have.
#[test]
fn a_shared_interface_refuses_every_claimant() {
    let fixture = Fixture::new();
    fixture
        .interfaces
        .set(&[(POD_A, "cni0", 5), (POD_B, "cni0", 5)]);

    let published = fixture.manager.reconcile_once();

    assert!(published.is_empty());
    assert!(fixture.index.authorize(Some(5), ip(IP_A)).is_err());
    assert!(fixture.index.authorize(Some(5), ip(IP_B)).is_err());
}

/// A UDP session is keyed by a source address and port that anything able to
/// put a packet on the wire can forge — a neighbouring pod with `CAP_NET_RAW`,
/// or an off-node sender. Such a datagram must be REFUSED (never forwarded),
/// but it must not be able to tear down the session it names: the interface it
/// actually arrived on proves it is somebody else's traffic, and the session's
/// own pinned evidence is untouched by it. Otherwise one pod could keep killing
/// a neighbour's UDP sessions at will.
#[test]
fn a_forged_datagram_from_another_interface_is_dropped_without_ending_the_session() {
    let fixture = Fixture::new();
    fixture.manager.reconcile_once();
    let scoping = fixture.scoping();
    let pinned = scoping
        .resolve(Some(IFINDEX_A), ip(IP_A))
        .expect("pod A's session is admitted")
        .binding;

    // Pod B forges pod A's source address, naming pod A's session.
    assert_eq!(
        scoping
            .revalidate_datagram(&pinned, Some(IFINDEX_A), Some(IFINDEX_B), ip(IP_A))
            .expect_err("a forged datagram must never be forwarded"),
        NodeWaypointUdpDatagramVerdict::DropDatagram(
            NodeWaypointUdpSourceRefusal::SourceAddressMismatch,
        ),
        "the forged datagram is dropped; pod A's session keeps its own still-vouched-for evidence"
    );

    // Off-node traffic on the node uplink, and a datagram that carried no
    // ingress-interface cmsg at all, are the same shape.
    assert_eq!(
        scoping
            .revalidate_datagram(&pinned, Some(IFINDEX_A), Some(9_999), ip(IP_A))
            .expect_err("an unenrolled interface must never be forwarded"),
        NodeWaypointUdpDatagramVerdict::DropDatagram(
            NodeWaypointUdpSourceRefusal::UnenrolledInterface,
        )
    );
    assert_eq!(
        scoping
            .revalidate_datagram(&pinned, Some(IFINDEX_A), None, ip(IP_A))
            .expect_err("an unattributable datagram must never be forwarded"),
        NodeWaypointUdpDatagramVerdict::DropDatagram(
            NodeWaypointUdpSourceRefusal::NoIngressInterface,
        )
    );

    // And the session itself is still serving.
    scoping
        .revalidate_datagram(&pinned, Some(IFINDEX_A), Some(IFINDEX_A), ip(IP_A))
        .expect("pod A's own datagrams keep flowing");
}

/// The other half of the same split: when the refusal is a property of the
/// SESSION rather than of one datagram, the session must end. Both directions
/// are pinned here so a future change cannot collapse them back together.
#[test]
fn an_attribution_change_on_the_sessions_own_interface_ends_the_session() {
    let fixture = Fixture::new();
    fixture.manager.reconcile_once();
    let pinned = fixture
        .scoping()
        .resolve(Some(IFINDEX_A), ip(IP_A))
        .expect("pod A's session is admitted")
        .binding;

    // ABA: pod B reuses pod A's interface and address.
    fixture
        .registry
        .set(vec![registry_target(POD_B, SPIFFE_B, IP_A)]);
    fixture.interfaces.set(&[(POD_B, "vethA", IFINDEX_A)]);
    fixture.manager.reconcile_once();

    assert_eq!(
        fixture
            .scoping()
            .revalidate_datagram(&pinned, Some(IFINDEX_A), Some(IFINDEX_A), ip(IP_A))
            .expect_err("the replacement pod must not inherit the session"),
        NodeWaypointUdpDatagramVerdict::CloseSession(
            NodeWaypointUdpSourceRefusal::AttributionChanged,
        )
    );

    // Registry removal is the same verdict, and stays so even when the datagram
    // that observes it arrived on a different interface — the pinned evidence
    // is gone either way, so there is nothing left to keep serving.
    fixture.registry.set(Vec::new());
    fixture.interfaces.set(&[]);
    fixture.manager.reconcile_once();

    assert_eq!(
        fixture
            .scoping()
            .revalidate_datagram(&pinned, Some(IFINDEX_A), Some(IFINDEX_A), ip(IP_A))
            .expect_err("a removed pod's session must stop")
            .refusal(),
        NodeWaypointUdpSourceRefusal::UnenrolledInterface
    );
    assert!(
        fixture
            .scoping()
            .revalidate_datagram(&pinned, Some(IFINDEX_A), Some(IFINDEX_B), ip(IP_A))
            .expect_err("a removed pod's session must stop")
            .closes_session(),
        "a datagram-specific mismatch must not mask the pinned evidence being gone"
    );
}

/// Cleanup: shutting the manager down retracts the generation, so a listener
/// still draining its socket cannot attribute a late datagram to a pod nobody
/// is tracking any more.
#[tokio::test]
async fn manager_shutdown_retracts_the_published_generation() {
    let fixture = Fixture::new();
    fixture.manager.reconcile_once();
    assert!(fixture.index.authorize(Some(IFINDEX_A), ip(IP_A)).is_ok());

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let index = fixture.index.clone();
    let handle = tokio::spawn(async move { fixture.manager.run(shutdown_rx).await });
    shutdown_tx.send(true).expect("signal shutdown");
    handle.await.expect("manager task completes");

    assert_eq!(
        index
            .authorize(Some(IFINDEX_A), ip(IP_A))
            .expect_err("a retracted index attributes nothing"),
        NodeWaypointUdpSourceRefusal::IndexUnavailable
    );
}

/// The manager is security-critical background state, not merely a cache
/// warmer. If its task is aborted (the same future-drop path a panic takes),
/// the last published identity generation must become unavailable immediately
/// instead of remaining trusted forever.
#[tokio::test]
async fn manager_task_abort_retracts_the_published_generation() {
    let fixture = Fixture::new();
    fixture.manager.reconcile_once();
    let before_run = fixture.index.generation();
    let index = fixture.index.clone();
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let handle = tokio::spawn(async move { fixture.manager.run(shutdown_rx).await });

    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while index.generation() == before_run {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("manager should enter its reconcile loop");

    handle.abort();
    assert!(
        handle
            .await
            .expect_err("aborted manager must not complete")
            .is_cancelled(),
        "the test must exercise future-drop retraction"
    );
    assert_eq!(
        index
            .authorize(Some(IFINDEX_A), ip(IP_A))
            .expect_err("an aborted manager must leave no trusted attribution"),
        NodeWaypointUdpSourceRefusal::IndexUnavailable
    );
}
