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

/// Established UDP/DTLS sessions carry the plugin chain and workload scope
/// from admission. Even an accepted slice whose workload projection is
/// unchanged may add or revoke AuthorizationPolicy, so the coherent slice
/// generation must fence that old authorization lifetime.
#[test]
fn an_attributed_session_stops_revalidating_after_any_accepted_slice_generation() {
    let fixture = Fixture::new();
    fixture.manager.reconcile_once();
    let scoping = fixture.scoping();
    let admitted = scoping
        .resolve(Some(IFINDEX_A), ip(IP_A))
        .expect("pod A resolves in the admitted generation");

    fixture.resolver.install_policy_scopes_from_workloads(&[
        workload(SPIFFE_A, "team-a", labels(&[("app", "api")]), POD_A),
        workload(SPIFFE_B, "team-b", labels(&[("app", "api")]), POD_B),
    ]);

    assert_eq!(
        scoping
            .revalidate_at_policy_generation(
                &admitted.binding,
                admitted.policy_generation,
                Some(IFINDEX_A),
                ip(IP_A),
            )
            .expect_err("the old stream-admission generation must be retired"),
        NodeWaypointUdpSourceRefusal::PolicyGenerationChanged
    );
}

/// A mesh-wide-only generation may admit an unattributable source, but that
/// miss must still be pinned. Otherwise adding the first scoped policy would
/// leave the established session on the old plugin generation forever because
/// it has no workload binding to revalidate.
#[test]
fn an_unattributable_session_is_also_fenced_by_policy_generation() {
    let fixture = Fixture::new();
    fixture.manager.reconcile_once();
    let scoping = fixture.scoping();
    let (policy_generation, admission) = scoping.resolve_observed(Some(999), ip("192.0.2.10"));
    let refusal = admission
        .err()
        .expect("off-node interface is not attributable");
    assert_eq!(refusal, NodeWaypointUdpSourceRefusal::UnenrolledInterface);

    fixture.resolver.install_policy_scopes_from_workloads(&[
        workload(SPIFFE_A, "team-a", labels(&[("app", "api")]), POD_A),
        workload(SPIFFE_B, "team-b", labels(&[("app", "api")]), POD_B),
    ]);

    assert_eq!(
        scoping
            .revalidate_unattributed(policy_generation, refusal, Some(999), ip("192.0.2.10"),)
            .expect_err("the old mesh-wide-only admission must be retired"),
        NodeWaypointUdpSourceRefusal::PolicyGenerationChanged
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

// ── NodeWaypoint UDP/DTLS listener materialization (issue #3286) ──────────
//
// The attribution channel above is only reachable if a NodeWaypoint can
// actually CREATE a UDP/DTLS listener. `materialize_node_waypoint_udp_listeners`
// is that surface: it turns each in-mesh service's UDP-family port into a real
// stream listener proxy + upstream in the prepared `GatewayConfig`, which is
// exactly what `StreamListenerManager` binds and what
// `NodeWaypointUdpSourceScoping` then scopes. These tests pin first
// construction, reload/update/withdrawal, the fail-closed refusals, and the
// UDP-vs-DTLS split.

use ferrum_edge::config::types::{DispatchKind, GatewayConfig};
use ferrum_edge::modes::mesh::config::{
    AppProtocol, MeshService, NodeWaypointEndpoint, ServicePort, WorkloadRef,
};
use ferrum_edge::modes::mesh::{
    MESH_NODE_WAYPOINT_UDP_PROXY_ID_PREFIX, MESH_NODE_WAYPOINT_UDP_UPSTREAM_ID_PREFIX,
    MeshRuntimeConfig, MeshTopology, node_waypoint_udp_proxy_id, node_waypoint_udp_upstream_id,
    prepare_gateway_config_for_mesh,
};

use super::mesh_test_support::{
    DEFAULT_NAMESPACE, gateway_config_with_mesh, mesh_config_with, runtime_for_topology,
    workload_for,
};

const UDP_LISTENERS_ENV: &str = "FERRUM_MESH_NODE_WAYPOINT_UDP_LISTENERS_ENABLED";
const K8S_NODE_NAME_ENV: &str = "FERRUM_K8S_NODE_NAME";
const LOCAL_NODE_NAME: &str = "worker-a";

/// Serializes the listener-switch and node-name environment mutations in this
/// test binary and restores their previous values on drop.
static UDP_LISTENER_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct UdpListenerEnvGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
    saved_enabled: Option<String>,
    saved_node_name: Option<String>,
}

impl UdpListenerEnvGuard {
    fn set(value: Option<&str>) -> Self {
        Self::set_with_node(value, Some(LOCAL_NODE_NAME))
    }

    fn set_with_node(value: Option<&str>, node_name: Option<&str>) -> Self {
        let lock = UDP_LISTENER_ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let saved_enabled = std::env::var(UDP_LISTENERS_ENV).ok();
        let saved_node_name = std::env::var(K8S_NODE_NAME_ENV).ok();
        // SAFETY: `_lock` serializes every mutation of both variables in this
        // test binary, and the guard restores both snapshots on drop.
        unsafe {
            match value {
                Some(value) => std::env::set_var(UDP_LISTENERS_ENV, value),
                None => std::env::remove_var(UDP_LISTENERS_ENV),
            }
            match node_name {
                Some(node_name) => std::env::set_var(K8S_NODE_NAME_ENV, node_name),
                None => std::env::remove_var(K8S_NODE_NAME_ENV),
            }
        }
        Self {
            _lock: lock,
            saved_enabled,
            saved_node_name,
        }
    }
}

impl Drop for UdpListenerEnvGuard {
    fn drop(&mut self) {
        // SAFETY: the guard still holds `UDP_LISTENER_ENV_LOCK`.
        unsafe {
            match self.saved_enabled.as_deref() {
                Some(value) => std::env::set_var(UDP_LISTENERS_ENV, value),
                None => std::env::remove_var(UDP_LISTENERS_ENV),
            }
            match self.saved_node_name.as_deref() {
                Some(value) => std::env::set_var(K8S_NODE_NAME_ENV, value),
                None => std::env::remove_var(K8S_NODE_NAME_ENV),
            }
        }
    }
}

fn udp_service(
    name: &str,
    port: u16,
    protocol: AppProtocol,
    workloads: &[&Workload],
) -> MeshService {
    MeshService {
        cluster_ips: vec!["10.96.0.10".to_string()],
        name: name.to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        ports: vec![ServicePort {
            port,
            protocol,
            name: Some(name.to_string()),
            target_port: None,
        }],
        workloads: workloads
            .iter()
            .map(|w| WorkloadRef {
                spiffe_id: w.spiffe_id.clone(),
            })
            .collect(),
        protocol_overrides: HashMap::new(),
        uid: None,
    }
}

fn node_waypoint_runtime() -> MeshRuntimeConfig {
    runtime_for_topology(MeshTopology::NodeWaypoint)
}

fn prepare(
    runtime: &MeshRuntimeConfig,
    services: Vec<MeshService>,
    mut workloads: Vec<Workload>,
) -> GatewayConfig {
    for workload in &mut workloads {
        if workload.node_waypoint.is_none() {
            workload.node_waypoint = Some(NodeWaypointEndpoint {
                address: "192.0.2.10".to_string(),
                hbone_port: 15008,
                spiffe_id: workload.spiffe_id.clone(),
                node_name: Some(LOCAL_NODE_NAME.to_string()),
                node_uid: None,
                network: None,
                cluster: None,
            });
        }
    }
    let mesh = mesh_config_with(workloads, services, Vec::new());
    let config = gateway_config_with_mesh(Vec::new(), Vec::new(), mesh);
    prepare_gateway_config_for_mesh(config, runtime).expect("mesh config preparation must succeed")
}

fn udp_listeners(config: &GatewayConfig) -> Vec<&ferrum_edge::config::types::Proxy> {
    config
        .proxies
        .iter()
        .filter(|proxy| proxy.id.starts_with(MESH_NODE_WAYPOINT_UDP_PROXY_ID_PREFIX))
        .collect()
}

#[test]
fn a_udp_service_port_materializes_a_node_waypoint_datagram_listener() {
    let _env = UdpListenerEnvGuard::set(Some("true"));
    let runtime = node_waypoint_runtime();
    let backend = workload_for("dns", DEFAULT_NAMESPACE, [("app", "udp")], ["10.244.3.11"]);
    let config = prepare(
        &runtime,
        vec![udp_service("dns", 5353, AppProtocol::Udp, &[&backend])],
        vec![backend],
    );

    let listeners = udp_listeners(&config);
    assert_eq!(
        listeners.len(),
        1,
        "exactly one NodeWaypoint UDP listener must materialize"
    );
    let proxy = listeners[0];
    assert_eq!(
        proxy.id,
        node_waypoint_udp_proxy_id(DEFAULT_NAMESPACE, "dns", 5353)
    );
    assert_eq!(proxy.listen_port, Some(5353));
    assert_eq!(
        proxy.dispatch_kind,
        DispatchKind::UdpRaw,
        "a `udp` service port relays opaque datagrams"
    );
    assert!(
        !proxy.frontend_tls,
        "a `udp` port must not terminate frontend DTLS"
    );
    assert!(
        !proxy.passthrough,
        "the listener must run the on_stream_connect chain so mesh_authz evaluates the \
         attributed source pod"
    );
    assert!(
        proxy.hosts.is_empty() && proxy.stream_match.is_none(),
        "a datagram listener carries neither SNI hosts nor an L4 matcher"
    );

    let upstream_id = node_waypoint_udp_upstream_id(DEFAULT_NAMESPACE, "dns", 5353);
    assert_eq!(proxy.upstream_id.as_deref(), Some(upstream_id.as_str()));
    let upstream = config
        .upstreams
        .iter()
        .find(|upstream| upstream.id == upstream_id)
        .expect("the listener's upstream must be materialized");
    assert!(
        upstream
            .id
            .starts_with(MESH_NODE_WAYPOINT_UDP_UPSTREAM_ID_PREFIX)
    );
    assert_eq!(
        upstream
            .targets
            .iter()
            .map(|target| (target.host.as_str(), target.port))
            .collect::<Vec<_>>(),
        vec![("10.244.3.11", 5353)],
        "the listener forwards to the service's backing pod on its resolved target port"
    );

    // The whole point of the surface: the prepared config passes the same
    // stream-proxy validation the runtime applies before binding.
    config
        .validate_stream_proxies()
        .expect("a materialized NodeWaypoint UDP listener must be a valid stream proxy");
}

#[test]
fn a_dtls_service_port_materializes_a_frontend_dtls_terminating_listener() {
    let _env = UdpListenerEnvGuard::set(Some("true"));
    let runtime = node_waypoint_runtime();
    let backend = workload_for("coap", DEFAULT_NAMESPACE, [("app", "udp")], ["10.244.3.12"]);
    let config = prepare(
        &runtime,
        vec![udp_service("coap", 5684, AppProtocol::Dtls, &[&backend])],
        vec![backend],
    );

    let listeners = udp_listeners(&config);
    assert_eq!(listeners.len(), 1);
    let proxy = listeners[0];
    assert_eq!(proxy.listen_port, Some(5684));
    assert!(
        proxy.frontend_tls,
        "a `dtls` service port must terminate frontend DTLS on the listener"
    );
    assert_eq!(
        proxy.dispatch_kind,
        DispatchKind::UdpRaw,
        "the BACKEND leg stays plaintext UDP; only the frontend terminates DTLS"
    );
    config
        .validate_stream_proxies()
        .expect("a DTLS listener must also be a valid stream proxy");
}

#[test]
fn node_waypoint_udp_listeners_are_off_by_default() {
    let _env = UdpListenerEnvGuard::set(None);
    let runtime = node_waypoint_runtime();
    let backend = workload_for("dns", DEFAULT_NAMESPACE, [("app", "udp")], ["10.244.3.11"]);
    let config = prepare(
        &runtime,
        vec![udp_service("dns", 5353, AppProtocol::Udp, &[&backend])],
        vec![backend],
    );
    assert!(
        udp_listeners(&config).is_empty(),
        "a NodeWaypoint runs on the host network, so claiming node-wide UDP ports is opt-in"
    );
}

#[test]
fn a_malformed_listener_switch_is_rejected_rather_than_silently_disabling_listeners() {
    let _env = UdpListenerEnvGuard::set(Some("yes-please"));
    let runtime = node_waypoint_runtime();
    assert!(
        runtime
            .validate_node_waypoint_udp_listener_settings()
            .is_err(),
        "an unparseable switch must abort mesh startup instead of serving no listeners"
    );
    // Non-NodeWaypoint topologies never consume the switch, so a stray value
    // there is inert rather than a startup error.
    assert!(
        runtime_for_topology(MeshTopology::Ambient)
            .validate_node_waypoint_udp_listener_settings()
            .is_ok()
    );
}

#[test]
fn enabled_listener_surface_requires_the_current_node_name() {
    let _env = UdpListenerEnvGuard::set_with_node(Some("true"), None);
    let runtime = node_waypoint_runtime();
    assert!(
        runtime
            .validate_node_waypoint_udp_listener_settings()
            .is_err(),
        "serving must fail closed when same-node target ownership cannot be established"
    );

    let backend = workload_for("dns", DEFAULT_NAMESPACE, [("app", "udp")], ["10.244.3.11"]);
    let config = prepare(
        &runtime,
        vec![udp_service("dns", 5353, AppProtocol::Udp, &[&backend])],
        vec![backend],
    );
    assert!(
        udp_listeners(&config).is_empty(),
        "infallible read-only preparation must not widen to every cluster endpoint"
    );
}

#[test]
fn node_waypoint_udp_targets_are_restricted_to_this_exact_node() {
    let _env = UdpListenerEnvGuard::set(Some("true"));
    let runtime = node_waypoint_runtime();
    let local = workload_for("dns", DEFAULT_NAMESPACE, [("app", "udp")], ["10.244.3.11"]);
    let mut remote = local.clone();
    remote.addresses = vec!["10.244.4.12".to_string()];
    remote.node_waypoint = Some(NodeWaypointEndpoint {
        address: "192.0.2.11".to_string(),
        hbone_port: 15008,
        spiffe_id: remote.spiffe_id.clone(),
        node_name: Some("worker-b".to_string()),
        node_uid: None,
        network: None,
        cluster: None,
    });
    let mut unowned = local.clone();
    unowned.addresses = vec!["10.244.5.13".to_string()];
    unowned.node_waypoint = Some(NodeWaypointEndpoint {
        address: "192.0.2.12".to_string(),
        hbone_port: 15008,
        spiffe_id: unowned.spiffe_id.clone(),
        node_name: None,
        node_uid: None,
        network: None,
        cluster: None,
    });
    let config = prepare(
        &runtime,
        vec![udp_service(
            "dns",
            5353,
            AppProtocol::Udp,
            &[&local, &remote, &unowned],
        )],
        vec![local, remote, unowned],
    );

    let upstream_id = node_waypoint_udp_upstream_id(DEFAULT_NAMESPACE, "dns", 5353);
    let upstream = config
        .upstreams
        .iter()
        .find(|upstream| upstream.id == upstream_id)
        .expect("the same-node endpoint keeps the listener reachable");
    assert_eq!(
        upstream
            .targets
            .iter()
            .map(|target| target.host.as_str())
            .collect::<Vec<_>>(),
        vec!["10.244.3.11"],
        "another node's pod or a pod with missing node ownership must not be selected by a \
         node-local marked UDP socket"
    );
}

#[test]
fn only_the_node_waypoint_topology_materializes_udp_listeners() {
    let _env = UdpListenerEnvGuard::set(Some("true"));
    let backend = workload_for("dns", DEFAULT_NAMESPACE, [("app", "udp")], ["10.244.3.11"]);
    for topology in [
        MeshTopology::Ambient,
        MeshTopology::Sidecar,
        MeshTopology::ServiceWaypoint,
    ] {
        let runtime = runtime_for_topology(topology);
        let config = prepare(
            &runtime,
            vec![udp_service("dns", 5353, AppProtocol::Udp, &[&backend])],
            vec![backend.clone()],
        );
        assert!(
            udp_listeners(&config).is_empty(),
            "{topology:?} has no per-datagram source-attribution channel and must not bind \
             a NodeWaypoint UDP listener"
        );
    }
}

#[test]
fn two_services_claiming_one_udp_port_materialize_no_listener() {
    let _env = UdpListenerEnvGuard::set(Some("true"));
    let runtime = node_waypoint_runtime();
    let a = workload_for(
        "dns-a",
        DEFAULT_NAMESPACE,
        [("app", "udp")],
        ["10.244.3.11"],
    );
    let b = workload_for(
        "dns-b",
        DEFAULT_NAMESPACE,
        [("app", "udp")],
        ["10.244.3.12"],
    );
    let config = prepare(
        &runtime,
        vec![
            udp_service("dns-a", 5353, AppProtocol::Udp, &[&a]),
            udp_service("dns-b", 5353, AppProtocol::Udp, &[&b]),
        ],
        vec![a, b],
    );
    assert!(
        udp_listeners(&config).is_empty(),
        "a datagram carries no host or SNI, so a contested port must refuse BOTH claimants \
         rather than let materialization order pick a winner"
    );
}

#[test]
fn a_udp_service_port_with_no_reachable_endpoint_materializes_no_listener() {
    let _env = UdpListenerEnvGuard::set(Some("true"));
    let runtime = node_waypoint_runtime();
    let orphan = workload_for("dns", DEFAULT_NAMESPACE, [("app", "udp")], ["10.244.3.11"]);
    // The service references the workload, but the slice carries no workloads.
    let config = prepare(
        &runtime,
        vec![udp_service("dns", 5353, AppProtocol::Udp, &[&orphan])],
        Vec::new(),
    );
    assert!(
        udp_listeners(&config).is_empty(),
        "a listener with no backend would be a black hole; refuse it instead"
    );
}

#[test]
fn ipv6_workload_addresses_materialize_listener_targets() {
    let _env = UdpListenerEnvGuard::set(Some("true"));
    let runtime = node_waypoint_runtime();
    let backend = workload_for("dns", DEFAULT_NAMESPACE, [("app", "udp")], ["fd00::1234"]);
    let config = prepare(
        &runtime,
        vec![udp_service("dns", 5353, AppProtocol::Udp, &[&backend])],
        vec![backend],
    );
    let upstream_id = node_waypoint_udp_upstream_id(DEFAULT_NAMESPACE, "dns", 5353);
    let upstream = config
        .upstreams
        .iter()
        .find(|upstream| upstream.id == upstream_id)
        .expect("an IPv6-only service must still materialize its upstream");
    assert_eq!(
        upstream
            .targets
            .iter()
            .map(|target| target.host.as_str())
            .collect::<Vec<_>>(),
        vec!["fd00::1234"]
    );
}

#[test]
fn a_reload_updates_endpoints_and_withdraws_a_removed_service() {
    let _env = UdpListenerEnvGuard::set(Some("true"));
    let runtime = node_waypoint_runtime();

    let first_backend = workload_for("dns", DEFAULT_NAMESPACE, [("app", "udp")], ["10.244.3.11"]);
    let first = prepare(
        &runtime,
        vec![udp_service(
            "dns",
            5353,
            AppProtocol::Udp,
            &[&first_backend],
        )],
        vec![first_backend],
    );
    assert_eq!(udp_listeners(&first).len(), 1);

    // Source pod recreation / endpoint change: same service, new pod address.
    let replaced_backend =
        workload_for("dns", DEFAULT_NAMESPACE, [("app", "udp")], ["10.244.3.99"]);
    let updated = prepare(
        &runtime,
        vec![udp_service(
            "dns",
            5353,
            AppProtocol::Udp,
            &[&replaced_backend],
        )],
        vec![replaced_backend],
    );
    let upstream_id = node_waypoint_udp_upstream_id(DEFAULT_NAMESPACE, "dns", 5353);
    assert_eq!(
        updated
            .upstreams
            .iter()
            .find(|upstream| upstream.id == upstream_id)
            .expect("upstream")
            .targets
            .iter()
            .map(|target| target.host.as_str())
            .collect::<Vec<_>>(),
        vec!["10.244.3.99"],
        "an endpoint change must be reflected in the next prepared generation"
    );

    // Withdrawal: the service leaves the slice entirely.
    let withdrawn = prepare(&runtime, Vec::new(), Vec::new());
    assert!(
        udp_listeners(&withdrawn).is_empty(),
        "withdrawing the service must withdraw its listener"
    );
    assert!(
        !withdrawn
            .upstreams
            .iter()
            .any(|upstream| upstream.id == upstream_id),
        "withdrawing the service must withdraw its upstream too"
    );
}

#[test]
fn a_udp_port_already_claimed_by_a_stream_proxy_is_refused() {
    let _env = UdpListenerEnvGuard::set(Some("true"));
    let runtime = node_waypoint_runtime();
    let backend = workload_for("dns", DEFAULT_NAMESPACE, [("app", "udp")], ["10.244.3.11"]);

    // An operator TCP stream proxy already owns 5353 in this generation.
    let mut existing = super::mesh_test_support::http_proxy("operator-tcp", "example.test", 9000);
    existing.backend_scheme = Some(ferrum_edge::config::types::BackendScheme::Tcp);
    existing.hosts = Vec::new();
    existing.listen_path = None;
    existing.listen_port = Some(5353);

    let mesh = mesh_config_with(
        vec![backend.clone()],
        vec![udp_service("dns", 5353, AppProtocol::Udp, &[&backend])],
        Vec::new(),
    );
    let config = gateway_config_with_mesh(vec![existing], Vec::new(), mesh);
    let prepared = prepare_gateway_config_for_mesh(config, &runtime)
        .expect("mesh config preparation must succeed");

    assert!(
        udp_listeners(&prepared).is_empty(),
        "a port already claimed by a stream proxy must not be re-claimed by a datagram listener"
    );
}

#[test]
fn preparation_attaches_desired_steering_metadata_without_publishing_the_live_plan() {
    use ferrum_edge::proxy::node_waypoint_udp_steering::{
        NodeWaypointUdpSteerBackend, NodeWaypointUdpSteering, published_plan,
    };

    struct NoopBackend;
    impl NodeWaypointUdpSteerBackend for NoopBackend {
        fn run_script(&self, _script: &str) -> Result<(), String> {
            Ok(())
        }
    }

    let _env = UdpListenerEnvGuard::set(Some("true"));
    let runtime = node_waypoint_runtime();
    let backend = workload_for("dns", DEFAULT_NAMESPACE, [("app", "udp")], ["10.244.3.11"]);

    let serving = NodeWaypointUdpSteering::new(std::sync::Arc::new(NoopBackend));
    let prior = vec![ferrum_edge::capture::NodeWaypointUdpSteerDestination {
        ip: "10.96.0.99".parse().expect("ip"),
        port: 9999,
    }];
    serving.set_bound_destinations(prior.clone(), Some(&["veth0".to_string()]));
    let before_global = published_plan();

    let config = prepare(
        &runtime,
        vec![udp_service("dns", 5353, AppProtocol::Udp, &[&backend])],
        vec![backend],
    );

    assert_eq!(
        config.node_waypoint_udp_steer_destinations,
        vec![ferrum_edge::capture::NodeWaypointUdpSteerDestination {
            ip: "10.96.0.10".parse().expect("cluster ip"),
            port: 5353,
        }],
        "preparation must carry desired destinations on the candidate"
    );
    assert_eq!(
        serving.bound_destinations(),
        prior,
        "a rejected or merely inspected candidate must leave the serving plan untouched"
    );
    assert_eq!(
        published_plan().as_ref(),
        before_global.as_ref(),
        "read-only preparation must not mutate the process-global diagnostic plan"
    );
    std::mem::forget(serving);
}

#[test]
fn a_withdrawn_or_disabled_generation_clears_desired_steering_metadata() {
    let enabled_env = UdpListenerEnvGuard::set(Some("true"));
    let runtime = node_waypoint_runtime();
    let backend = workload_for("dns", DEFAULT_NAMESPACE, [("app", "udp")], ["10.244.3.11"]);
    let prepared = prepare(
        &runtime,
        vec![udp_service("dns", 5353, AppProtocol::Udp, &[&backend])],
        vec![backend],
    );
    assert!(
        !prepared.node_waypoint_udp_steer_destinations.is_empty(),
        "a materialized ClusterIP listener must carry desired steering metadata"
    );

    let withdrawn = prepare(&runtime, Vec::new(), Vec::new());
    assert!(
        withdrawn.node_waypoint_udp_steer_destinations.is_empty(),
        "withdrawing every UDP service must clear desired steering metadata"
    );

    // Release the enabled guard BEFORE taking the disabled one.
    // `UdpListenerEnvGuard` holds `UDP_LISTENER_ENV_LOCK`, a non-reentrant
    // `std::sync::Mutex`, for its whole lifetime, so two overlapping guards on
    // one thread deadlock the test outright.
    drop(enabled_env);
    let _off = UdpListenerEnvGuard::set(None);
    let backend = workload_for("dns", DEFAULT_NAMESPACE, [("app", "udp")], ["10.244.3.11"]);
    let disabled = prepare(
        &runtime,
        vec![udp_service("dns", 5353, AppProtocol::Udp, &[&backend])],
        vec![backend],
    );
    assert!(
        disabled.node_waypoint_udp_steer_destinations.is_empty(),
        "disabling the listener switch must clear desired steering metadata"
    );
}

// ── Reply-source authorization reconciliation (issue #3286) ────────────────
//
// The materialized listener's reply is source-PINNED to the address the client
// addressed. On the Service path that is the Service ClusterIP, which is never
// a configured node IP, so `tc_inbound`'s enrolled-destination guard dropped
// every steered reply — the datapath the live gate's
// `node_waypoint.udp.service_path_allow_attributed_source` exercises.
//
// The repair is an exact, lifecycle-bound authorization: the serving proxy
// publishes `(address, port)` claims into the pod registry directory, and the
// node-agent — still the sole writer of every BPF map, because the proxy's
// bpffs mount is deliberately read-only — reconciles them into
// `FERRUM_UDP_REPLY_SOURCES` / `FERRUM_UDP_REPLY_SOURCES6`. These tests pin the
// node-agent half of that contract end to end, against the real publisher.

use dashmap::DashMap;
use ferrum_edge::capture::{CaptureConfig, CaptureMode, NodeWaypointUdpSteerDestination};
use ferrum_edge::ebpf::{
    CaptureContract, FallbackMode, MockEbpfBackend, NodeAgentProxyMode, PodAttachmentState,
};
use ferrum_edge::modes::node_agent::{
    NodeAgentConfig, NodeWaypointUdpReplySourceState,
    node_waypoint_udp_reply_source_reconcile_enabled, reconcile_node_waypoint_udp_reply_sources,
};
use ferrum_edge::proxy::node_waypoint_udp_reply_source::{
    NODE_WAYPOINT_UDP_REPLY_SOURCE_DIR, NodeWaypointUdpReplySourcePublisher,
    RegistryDirReplySourcePublisher,
};

fn reply_source(ip: &str, port: u16) -> NodeWaypointUdpSteerDestination {
    NodeWaypointUdpSteerDestination {
        ip: ip.parse().expect("reply source address"),
        port,
    }
}

fn node_waypoint_config(registry_dir: Option<&std::path::Path>) -> NodeAgentConfig {
    let mut capture_config = CaptureConfig::explicit(15006, 15001);
    capture_config.mode = CaptureMode::Ebpf;
    let mut capture_contract = CaptureContract::local_pod_defaults();
    capture_contract.proxy_mode = NodeAgentProxyMode::NodeWaypoint;
    NodeAgentConfig {
        node_name: "node-a".to_string(),
        capture_config,
        cgroup_root: "/nonexistent".to_string(),
        bpf_fs_path: "/nonexistent".to_string(),
        fallback_mode: FallbackMode::Fail,
        excluded_namespaces: std::collections::HashSet::new(),
        capture_contract,
        trust_domain: "cluster.local".to_string(),
        node_waypoint_pod_registry_dir: registry_dir.map(|dir| dir.to_path_buf()),
    }
}

fn enrolled_pod(uid: &str, pod_ip: &str) -> PodAttachmentState {
    PodAttachmentState {
        pod_uid: uid.to_string(),
        pod_name: "enrolled".to_string(),
        namespace: "team-a".to_string(),
        pod_ip: Some(pod_ip.parse().expect("pod ip")),
        pod_ip6: None,
        cgroup_path: None,
        veth_iface: Some("veth-mock".to_string()),
        attached: true,
        include_ports_cgroup_ids: Vec::new(),
        include_ports_policy: None,
        workload_identity_cgroup_ids: Vec::new(),
        node_probe_ports: Vec::new(),
        inbound_redirect_ports: Vec::new(),
    }
}

fn authorized(backend: &MockEbpfBackend) -> Vec<(std::net::IpAddr, u16)> {
    let mut sources: Vec<(std::net::IpAddr, u16)> =
        backend.udp_reply_sources.iter().copied().collect();
    sources.sort();
    sources
}

/// The reconciliation the live Service path depends on: what the serving proxy
/// published is exactly what becomes authorized, on BOTH families.
#[test]
fn published_claims_become_the_authorized_reply_source_set() {
    let registry = tempfile::tempdir().expect("registry dir");
    let publisher = RegistryDirReplySourcePublisher::new(registry.path());
    let v4 = reply_source("10.96.0.10", 5300);
    let v6 = reply_source("fd00:10:96::a", 5300);
    publisher.publish(&[v4, v6]).expect("publication");

    let mut backend = MockEbpfBackend::default();
    let pods = DashMap::new();
    let config = node_waypoint_config(Some(registry.path()));
    let mut state = NodeWaypointUdpReplySourceState::default();
    reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);

    assert_eq!(authorized(&backend), {
        let mut expected = vec![(v4.ip, v4.port), (v6.ip, v6.port)];
        expected.sort();
        expected
    });
}

/// Retraction is the security-relevant half. A listener that stopped serving
/// must lose its authorization; retaining it would leave a ClusterIP admissible
/// to enrolled pods with no socket behind it.
#[test]
fn withdrawing_a_claim_revokes_its_authorization() {
    let registry = tempfile::tempdir().expect("registry dir");
    let publisher = RegistryDirReplySourcePublisher::new(registry.path());
    let kept = reply_source("10.96.0.11", 5301);
    publisher
        .publish(&[reply_source("10.96.0.10", 5300), kept])
        .expect("publication");

    let mut backend = MockEbpfBackend::default();
    let pods = DashMap::new();
    let config = node_waypoint_config(Some(registry.path()));
    let mut state = NodeWaypointUdpReplySourceState::default();
    reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);
    assert_eq!(authorized(&backend).len(), 2);

    publisher.publish(&[kept]).expect("withdrawal");
    reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);
    assert_eq!(
        authorized(&backend),
        vec![(kept.ip, kept.port)],
        "a withdrawn reply source must lose its authorization"
    );

    publisher.publish(&[]).expect("full retraction");
    reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);
    assert!(
        authorized(&backend).is_empty(),
        "a full retraction must leave nothing authorized"
    );
}

/// Containment: the relay may authorize a Service address, never a workload's
/// own. Otherwise a compromised or buggy proxy could authorize itself to answer
/// enrolled pods AS one of the pods this guard exists to protect.
#[test]
fn a_claim_naming_an_enrolled_pod_address_is_refused() {
    let registry = tempfile::tempdir().expect("registry dir");
    let publisher = RegistryDirReplySourcePublisher::new(registry.path());
    let service = reply_source("10.96.0.10", 5300);
    let pod_address = reply_source("10.244.1.7", 5300);
    publisher
        .publish(&[service, pod_address])
        .expect("publication");

    let mut backend = MockEbpfBackend::default();
    let pods = DashMap::new();
    pods.insert(
        POD_A.to_string(),
        enrolled_pod(POD_A, "10.244.1.7"),
    );
    let config = node_waypoint_config(Some(registry.path()));
    let mut state = NodeWaypointUdpReplySourceState::default();
    reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);

    assert_eq!(
        authorized(&backend),
        vec![(service.ip, service.port)],
        "an enrolled pod address must never become an authorized reply source"
    );
}

/// Nothing published means nothing authorized — and a directory that has never
/// existed is exactly that, not an error that would make the agent retain a
/// previous generation's set.
#[test]
fn an_absent_claim_directory_authorizes_nothing() {
    let registry = tempfile::tempdir().expect("registry dir");
    let publisher = RegistryDirReplySourcePublisher::new(registry.path());
    publisher
        .publish(&[reply_source("10.96.0.10", 5300)])
        .expect("publication");

    let mut backend = MockEbpfBackend::default();
    let pods = DashMap::new();
    let config = node_waypoint_config(Some(registry.path()));
    let mut state = NodeWaypointUdpReplySourceState::default();
    reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);
    assert_eq!(authorized(&backend).len(), 1);

    // The proxy's whole claim directory disappears (a restart wiping its
    // scratch state, a remount). Authorization must not survive it.
    std::fs::remove_dir_all(registry.path().join(NODE_WAYPOINT_UDP_REPLY_SOURCE_DIR))
        .expect("remove claim dir");
    reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);
    assert!(
        authorized(&backend).is_empty(),
        "authorization must not outlive the claims that justified it"
    );
}

/// A map write that failed is not evidence of anything, so the reconcile must
/// not record it as converged — the next pass has to rewrite from scratch.
#[test]
fn a_failed_map_write_is_retried_on_the_next_pass() {
    let registry = tempfile::tempdir().expect("registry dir");
    let publisher = RegistryDirReplySourcePublisher::new(registry.path());
    let service = reply_source("10.96.0.10", 5300);
    publisher.publish(&[service]).expect("publication");

    let mut backend = MockEbpfBackend {
        fail_replace_udp_reply_sources: true,
        ..MockEbpfBackend::default()
    };
    let pods = DashMap::new();
    let config = node_waypoint_config(Some(registry.path()));
    let mut state = NodeWaypointUdpReplySourceState::default();
    reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);
    assert!(authorized(&backend).is_empty());

    backend.fail_replace_udp_reply_sources = false;
    reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);
    assert_eq!(
        authorized(&backend),
        vec![(service.ip, service.port)],
        "a failed write must be retried rather than recorded as applied"
    );
}

/// The reconcile runs on a 250 ms poll, so an unchanged claim set must issue no
/// map calls at all.
#[test]
fn a_quiet_poll_issues_no_map_write() {
    let registry = tempfile::tempdir().expect("registry dir");
    let publisher = RegistryDirReplySourcePublisher::new(registry.path());
    publisher
        .publish(&[reply_source("10.96.0.10", 5300)])
        .expect("publication");

    let mut backend = MockEbpfBackend::default();
    let pods = DashMap::new();
    let config = node_waypoint_config(Some(registry.path()));
    let mut state = NodeWaypointUdpReplySourceState::default();
    for _ in 0..4 {
        reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);
    }
    assert_eq!(
        backend.udp_reply_source_updates.len(),
        1,
        "only the first pass may write; the rest are already converged"
    );
}

/// The channel exists for one topology. A local-pod node-agent has no
/// NodeWaypoint UDP/DTLS relay whose replies could need authorizing, and
/// without a registry directory there is no channel to read.
#[test]
fn the_reconcile_is_node_waypoint_and_registry_scoped() {
    let registry = tempfile::tempdir().expect("registry dir");
    assert!(node_waypoint_udp_reply_source_reconcile_enabled(
        &node_waypoint_config(Some(registry.path()))
    ));
    assert!(!node_waypoint_udp_reply_source_reconcile_enabled(
        &node_waypoint_config(None)
    ));

    let mut local_pod = node_waypoint_config(Some(registry.path()));
    local_pod.capture_contract.proxy_mode = NodeAgentProxyMode::LocalPod;
    assert!(!node_waypoint_udp_reply_source_reconcile_enabled(&local_pod));
}
