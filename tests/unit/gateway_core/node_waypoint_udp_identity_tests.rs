//! NodeWaypoint per-datagram UDP/DTLS source-workload attribution (issue #3286).
//!
//! These pin the anti-spoofing boundary itself: which datagrams may be
//! attributed to which enrolled pod, what is refused, and how an admitted
//! session's attribution is invalidated by churn. Everything that cannot be
//! attributed must leave the session without a per-pod policy scope, which is
//! what makes `mesh_authz` deny it while namespace/selector-scoped policies
//! exist.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ferrum_edge::identity::SpiffeId;
use ferrum_edge::modes::mesh::hbone::UdpSourceIdentity;
use ferrum_edge::proxy::host_udp_capture::{HostUdpPodBinding, ResolvedInterface};
use ferrum_edge::proxy::netns_capture::{PodCaptureSourceIps, PodCaptureTarget};
use ferrum_edge::proxy::node_waypoint_udp_identity::{
    NodeWaypointUdpSourceIndex, NodeWaypointUdpSourceRefusal, plan_node_waypoint_udp_bindings,
};

const UID_A: &str = "11111111-1111-1111-1111-111111111111";
const UID_B: &str = "22222222-2222-2222-2222-222222222222";

fn spiffe(sa: &str) -> SpiffeId {
    SpiffeId::new(format!("spiffe://cluster.local/ns/payments/sa/{sa}")).expect("valid SPIFFE ID")
}

fn binding(
    uid: &str,
    sa: &str,
    ifindex: u32,
    ipv4: Option<&str>,
    ipv6: Option<&str>,
) -> HostUdpPodBinding {
    HostUdpPodBinding {
        pod_uid: uid.to_string(),
        iface: format!("veth{ifindex}"),
        ifindex,
        ipv4: ipv4.map(|addr| addr.parse::<Ipv4Addr>().expect("valid v4")),
        ipv6: ipv6.map(|addr| addr.parse::<Ipv6Addr>().expect("valid v6")),
        identity: UdpSourceIdentity::new(spiffe(sa), uid).expect("valid source identity"),
    }
}

fn target(uid: &str, sa: Option<&str>, ipv4: Option<&str>, ipv6: Option<&str>) -> PodCaptureTarget {
    PodCaptureTarget {
        pod_uid: uid.to_string(),
        cgroup_path: format!("/sys/fs/cgroup/kubepods/pod{uid}"),
        source_identity: sa.and_then(|sa| UdpSourceIdentity::new(spiffe(sa), uid.to_string())),
        source_ips: PodCaptureSourceIps {
            ipv4: ipv4.map(|addr| addr.parse().expect("valid v4")),
            ipv6: ipv6.map(|addr| addr.parse().expect("valid v6")),
        },
    }
}

fn iface(name: &str, ifindex: u32) -> ResolvedInterface {
    ResolvedInterface {
        name: name.to_string(),
        ifindex,
    }
}

fn ip(addr: &str) -> IpAddr {
    addr.parse().expect("valid address")
}

// ───────────────────────────────────────────────────────────────────────────
// Per-datagram admission
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn a_datagram_on_its_pods_interface_with_its_own_source_resolves_that_pod() {
    let index = NodeWaypointUdpSourceIndex::new();
    index.publish(&[binding(UID_A, "ledger", 7, Some("10.244.1.7"), None)]);

    let resolved = index
        .authorize(Some(7), ip("10.244.1.7"))
        .expect("an enrolled pod's own datagram must be attributable");
    assert_eq!(resolved.principal, spiffe("ledger"));
    assert_eq!(resolved.pod_uid_text, UID_A);
}

/// The whole point of the channel: source addresses are attacker-controlled,
/// ingress interfaces are not. A pod that forges a neighbour's source address
/// still arrives on its OWN interface, so the forged address does not match the
/// interface's registered pod and the datagram is refused rather than relayed
/// under the neighbour's identity.
#[test]
fn a_spoofed_source_address_is_refused_rather_than_attributed_to_the_impersonated_pod() {
    let index = NodeWaypointUdpSourceIndex::new();
    index.publish(&[
        binding(UID_A, "ledger", 7, Some("10.244.1.7"), None),
        binding(UID_B, "reports", 8, Some("10.244.1.8"), None),
    ]);

    // Pod B (interface 8) claims pod A's address.
    let refusal = index
        .authorize(Some(8), ip("10.244.1.7"))
        .expect_err("a forged source address must not resolve");
    assert_eq!(refusal, NodeWaypointUdpSourceRefusal::SourceAddressMismatch);

    // And the reverse direction is equally refused, so this is not an ordering
    // artifact of the published map.
    assert_eq!(
        index
            .authorize(Some(7), ip("10.244.1.8"))
            .expect_err("the mirrored forgery must not resolve"),
        NodeWaypointUdpSourceRefusal::SourceAddressMismatch
    );
}

#[test]
fn a_datagram_with_no_ingress_interface_is_refused_not_attributed() {
    let index = NodeWaypointUdpSourceIndex::new();
    index.publish(&[binding(UID_A, "ledger", 7, Some("10.244.1.7"), None)]);

    assert_eq!(
        index
            .authorize(None, ip("10.244.1.7"))
            .expect_err("no cmsg means no attribution"),
        NodeWaypointUdpSourceRefusal::NoIngressInterface
    );
    assert_eq!(
        index
            .authorize(Some(0), ip("10.244.1.7"))
            .expect_err("interface index 0 is not an attribution key"),
        NodeWaypointUdpSourceRefusal::NoIngressInterface
    );
}

/// Off-node traffic reaches the proxy on the node uplink, which belongs to no
/// enrolled pod. It must not fall through to an unscoped session.
#[test]
fn an_interface_no_enrolled_pod_owns_is_refused() {
    let index = NodeWaypointUdpSourceIndex::new();
    index.publish(&[binding(UID_A, "ledger", 7, Some("10.244.1.7"), None)]);

    assert_eq!(
        index
            .authorize(Some(2), ip("10.244.1.7"))
            .expect_err("the node uplink belongs to no enrolled pod"),
        NodeWaypointUdpSourceRefusal::UnenrolledInterface
    );
}

/// An index that has never published is NOT "no pods enrolled" — it is "no
/// evidence at all", and must refuse rather than look like an empty allow-list.
#[test]
fn an_unpublished_index_refuses_every_datagram() {
    let index = NodeWaypointUdpSourceIndex::new();
    assert_eq!(
        index
            .authorize(Some(7), ip("10.244.1.7"))
            .expect_err("nothing may be attributed before the first generation"),
        NodeWaypointUdpSourceRefusal::IndexUnavailable
    );
}

/// Shutdown retraction: a socket still draining must not attribute a late
/// datagram under a generation nobody maintains any more.
#[test]
fn clearing_the_index_retracts_every_binding_and_refuses_as_unavailable() {
    let index = NodeWaypointUdpSourceIndex::new();
    index.publish(&[binding(UID_A, "ledger", 7, Some("10.244.1.7"), None)]);
    assert!(index.authorize(Some(7), ip("10.244.1.7")).is_ok());

    index.clear();

    assert_eq!(
        index
            .authorize(Some(7), ip("10.244.1.7"))
            .expect_err("a retracted index attributes nothing"),
        NodeWaypointUdpSourceRefusal::IndexUnavailable
    );
    assert!(index.is_empty());
}

#[test]
fn ipv6_and_ipv4_mapped_sources_resolve_on_the_same_footing() {
    let index = NodeWaypointUdpSourceIndex::new();
    index.publish(&[binding(
        UID_A,
        "ledger",
        7,
        Some("10.244.1.7"),
        Some("fd00::7"),
    )]);

    assert!(
        index.authorize(Some(7), ip("fd00::7")).is_ok(),
        "a native IPv6 source must resolve"
    );
    assert!(
        index.authorize(Some(7), ip("::ffff:10.244.1.7")).is_ok(),
        "a dual-stack listener reports IPv4 senders as v4-mapped; canonicalization \
         must not turn that into an unattributable datagram"
    );
    assert_eq!(
        index
            .authorize(Some(7), ip("fd00::9"))
            .expect_err("an unregistered v6 source is still refused"),
        NodeWaypointUdpSourceRefusal::SourceAddressMismatch
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Session revalidation: churn, reuse, ABA
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn an_unchanged_republish_does_not_invalidate_a_live_session() {
    let index = NodeWaypointUdpSourceIndex::new();
    index.publish(&[binding(UID_A, "ledger", 7, Some("10.244.1.7"), None)]);
    let pinned = index
        .authorize(Some(7), ip("10.244.1.7"))
        .expect("session admitted");

    index.publish(&[binding(UID_A, "ledger", 7, Some("10.244.1.7"), None)]);

    index
        .revalidate(&pinned, Some(7), ip("10.244.1.7"))
        .expect("a republish that changed nothing must leave live sessions alone");
}

/// The ABA case. The pod at 10.244.1.7 on veth7 is replaced by a DIFFERENT
/// workload that reuses both the address and the interface. A session admitted
/// under the old pod must stop, not silently continue relaying under a pod
/// identity nobody vouched for.
#[test]
fn address_and_interface_reuse_by_a_different_pod_invalidates_the_pinned_session() {
    let index = NodeWaypointUdpSourceIndex::new();
    index.publish(&[binding(UID_A, "ledger", 7, Some("10.244.1.7"), None)]);
    let pinned = index
        .authorize(Some(7), ip("10.244.1.7"))
        .expect("session admitted under the original pod");

    // Same address, same interface, different pod UID and identity.
    index.publish(&[binding(UID_B, "reports", 7, Some("10.244.1.7"), None)]);

    assert_eq!(
        index
            .revalidate(&pinned, Some(7), ip("10.244.1.7"))
            .expect_err("the replacement pod must not inherit the old session"),
        NodeWaypointUdpSourceRefusal::AttributionChanged
    );
}

/// Same pod UID, same address, but the workload's attested identity changed
/// (re-issued under a different service account). That is still a different
/// authorization subject.
#[test]
fn a_changed_attested_identity_invalidates_the_pinned_session() {
    let index = NodeWaypointUdpSourceIndex::new();
    index.publish(&[binding(UID_A, "ledger", 7, Some("10.244.1.7"), None)]);
    let pinned = index
        .authorize(Some(7), ip("10.244.1.7"))
        .expect("session admitted");

    index.publish(&[binding(UID_A, "reports", 7, Some("10.244.1.7"), None)]);

    assert_eq!(
        index
            .revalidate(&pinned, Some(7), ip("10.244.1.7"))
            .expect_err("a re-attested identity is a different authorization subject"),
        NodeWaypointUdpSourceRefusal::AttributionChanged
    );
}

#[test]
fn removing_a_pod_from_the_registry_invalidates_its_live_sessions() {
    let index = NodeWaypointUdpSourceIndex::new();
    index.publish(&[
        binding(UID_A, "ledger", 7, Some("10.244.1.7"), None),
        binding(UID_B, "reports", 8, Some("10.244.1.8"), None),
    ]);
    let pinned = index
        .authorize(Some(7), ip("10.244.1.7"))
        .expect("session admitted");

    // Pod A leaves; pod B is untouched.
    index.publish(&[binding(UID_B, "reports", 8, Some("10.244.1.8"), None)]);

    assert_eq!(
        index
            .revalidate(&pinned, Some(7), ip("10.244.1.7"))
            .expect_err("a removed pod's session must not keep relaying"),
        NodeWaypointUdpSourceRefusal::UnenrolledInterface
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Planning: which enrolled pods become attributable at all
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn an_interface_two_enrolled_pods_claim_refuses_both_rather_than_guessing() {
    let targets = vec![
        target(UID_A, Some("ledger"), Some("10.244.1.7"), None),
        target(UID_B, Some("reports"), Some("10.244.1.8"), None),
    ];
    let resolved = HashMap::from([
        (UID_A.to_string(), iface("cni0", 5)),
        (UID_B.to_string(), iface("cni0", 5)),
    ]);

    let state = plan_node_waypoint_udp_bindings(&targets, &resolved);

    assert!(
        state.bindings.is_empty(),
        "a shared bridge interface makes attribution impossible; capturing under a guessed \
         identity is exactly the cross-tenant confusion this channel exists to prevent"
    );
    assert_eq!(
        state.refused.len(),
        2,
        "both claimants are refused, not one"
    );
}

#[test]
fn an_enrolled_pod_with_no_attested_identity_or_no_address_is_not_attributable() {
    let targets = vec![
        target(UID_A, None, Some("10.244.1.7"), None),
        target(UID_B, Some("reports"), None, None),
    ];
    let resolved = HashMap::from([
        (UID_A.to_string(), iface("veth7", 7)),
        (UID_B.to_string(), iface("veth8", 8)),
    ]);

    let state = plan_node_waypoint_udp_bindings(&targets, &resolved);

    assert!(
        state.bindings.is_empty(),
        "a registry entry with no attested SPIFFE ID or no published address cannot bind a \
         datagram to a workload"
    );
    assert_eq!(state.refused.len(), 2);
}

#[test]
fn a_pod_whose_interface_cannot_be_resolved_is_not_attributable() {
    let targets = vec![target(UID_A, Some("ledger"), Some("10.244.1.7"), None)];

    let state = plan_node_waypoint_udp_bindings(&targets, &HashMap::new());

    assert!(state.bindings.is_empty());
    assert_eq!(state.refused.len(), 1);
}

/// A pod UID the scope index cannot key on is dropped at publish: the parsed
/// `[u8; 16]` is the per-pod policy-scope key, so an unparseable UID could only
/// ever produce an unscoped session.
#[test]
fn a_binding_whose_pod_uid_does_not_parse_is_never_published() {
    let index = NodeWaypointUdpSourceIndex::new();
    let mut malformed = binding(UID_A, "ledger", 7, Some("10.244.1.7"), None);
    malformed.pod_uid = "not-a-uuid".to_string();

    index.publish(&[malformed]);

    assert_eq!(
        index
            .authorize(Some(7), ip("10.244.1.7"))
            .expect_err("an unscopeable pod UID must not become an attributable binding"),
        NodeWaypointUdpSourceRefusal::UnenrolledInterface
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Bounded diagnostics
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn refusal_reasons_are_a_closed_label_set_and_are_counted_per_reason() {
    let index = NodeWaypointUdpSourceIndex::new();
    index.publish(&[binding(UID_A, "ledger", 7, Some("10.244.1.7"), None)]);

    let _ = index.authorize(None, ip("10.244.1.7"));
    let _ = index.authorize(Some(9), ip("10.244.1.7"));
    let _ = index.authorize(Some(7), ip("10.244.1.9"));
    let _ = index.authorize(Some(7), ip("10.244.1.9"));

    let counts: HashMap<&str, u64> = index.refusal_counts().into_iter().collect();
    assert_eq!(counts.get("no_ingress_interface"), Some(&1));
    assert_eq!(counts.get("unenrolled_interface"), Some(&1));
    assert_eq!(counts.get("source_address_mismatch"), Some(&2));
    assert_eq!(
        counts.len(),
        6,
        "the label set is a closed enum; no registry- or peer-supplied value may become a label"
    );
}

#[test]
fn repeated_refusal_warns_are_rate_limited_and_report_the_suppressed_count() {
    let index = NodeWaypointUdpSourceIndex::new();
    index.publish(&[binding(UID_A, "ledger", 7, Some("10.244.1.7"), None)]);

    for _ in 0..5 {
        index.warn_refusal(
            "udp-proxy",
            "10.244.1.9",
            NodeWaypointUdpSourceRefusal::UnenrolledInterface,
        );
    }

    assert_eq!(
        index.suppressed_warn_count(NodeWaypointUdpSourceRefusal::UnenrolledInterface),
        4,
        "one warn per window is emitted and the remainder is folded into a suppressed count, so \
         a hostile flood cannot become a log flood"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Live kernel: the ingress-interface fact must actually be observable
// ───────────────────────────────────────────────────────────────────────────

/// The entire anti-spoofing argument rests on the kernel reporting an ingress
/// interface index per datagram. This exercises that on the real kernel the
/// tests run on: bind a UDP socket with `IP_PKTINFO`, send it a datagram, and
/// read the index back through the same `RecvMmsgBatch` reader the UDP and DTLS
/// datapaths use. It then drives the published index with the observed index to
/// prove that a matching source resolves and a forged one does not.
#[cfg(target_os = "linux")]
#[test]
fn live_kernel_reports_an_ingress_interface_that_drives_attribution() {
    use std::os::fd::AsRawFd;

    let receiver = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind loopback receiver");
    let receiver_addr = receiver.local_addr().expect("receiver addr");
    if ferrum_edge::socket_opts::set_ip_pktinfo(receiver.as_raw_fd()).is_err() {
        // A kernel without IP_PKTINFO cannot serve this channel at all; the
        // datapath already fails closed there, so there is nothing to prove.
        return;
    }

    let sender = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind loopback sender");
    sender
        .send_to(b"ferrum", receiver_addr)
        .expect("send loopback datagram");

    let mut batch = ferrum_edge::proxy::udp_batch::RecvMmsgBatch::new(4, false);
    receiver
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .expect("set read timeout");
    let received = batch
        .recv(receiver.as_raw_fd(), 4)
        .expect("recvmmsg returns the loopback datagram");
    assert!(received >= 1, "the datagram must be received");

    let (payload, peer) = batch.datagram(0);
    assert_eq!(payload, b"ferrum");
    let ingress_ifindex = batch
        .local_addr(0)
        .map(|local| local.ifindex)
        .filter(|index| *index != 0)
        .expect("the kernel must report a non-zero ingress interface index via IP_PKTINFO");

    // Now prove the index turns that kernel fact into (and only into) the right
    // workload. The sender's real address is registered; a forged one is not.
    let sender_v4 = match peer.ip() {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(v6) => v6.to_ipv4().expect("loopback peer is IPv4"),
    };
    let index = NodeWaypointUdpSourceIndex::new();
    index.publish(&[HostUdpPodBinding {
        pod_uid: UID_A.to_string(),
        iface: "lo".to_string(),
        ifindex: ingress_ifindex,
        ipv4: Some(sender_v4),
        ipv6: None,
        identity: UdpSourceIdentity::new(spiffe("ledger"), UID_A).expect("identity"),
    }]);

    assert_eq!(
        index
            .authorize(Some(ingress_ifindex), IpAddr::V4(sender_v4))
            .expect("the observed interface + registered source must resolve")
            .principal,
        spiffe("ledger")
    );
    assert_eq!(
        index
            .authorize(Some(ingress_ifindex), ip("10.244.9.9"))
            .expect_err("a source the interface's pod does not own must be refused"),
        NodeWaypointUdpSourceRefusal::SourceAddressMismatch
    );
    assert_eq!(
        index
            .authorize(
                Some(ingress_ifindex.wrapping_add(1_000)),
                IpAddr::V4(sender_v4)
            )
            .expect_err("an interface no enrolled pod owns must be refused"),
        NodeWaypointUdpSourceRefusal::UnenrolledInterface
    );
}
