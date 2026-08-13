//! Exact destination routing for shared same-port NodeWaypoint UDP listeners
//! (issue #3861).
//!
//! These cover the datapath half of the contract: a datagram selects exactly one
//! Service route from the kernel-reported local destination address, a missing
//! or unknown destination is refused before anything is allocated, and one
//! client tuple addressing two ClusterIPs on one port produces two independent
//! session identities.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use ferrum_edge::config::db_backend::NamespacedResourceId;
use ferrum_edge::proxy::node_waypoint_udp_destination::{
    NodeWaypointUdpDestinationPublishError, NodeWaypointUdpDestinationRefusal,
    NodeWaypointUdpDestinationRoute, NodeWaypointUdpDestinationRouter, canonical_destination_ip,
    destination_ip_is_admissible,
};
use ferrum_edge::proxy::udp_proxy::UdpSessionKey;

fn ip(text: &str) -> IpAddr {
    text.parse().expect("valid ip")
}

fn route(destination: &str, port: u16, proxy: &str) -> NodeWaypointUdpDestinationRoute {
    NodeWaypointUdpDestinationRoute {
        destination: ip(destination),
        listen_port: port,
        proxy: NamespacedResourceId::new("ferrum", proxy),
        terminates_dtls: false,
    }
}

#[test]
fn an_exact_destination_selects_only_its_own_service_route() {
    let router = NodeWaypointUdpDestinationRouter::new(5353);
    router
        .publish(vec![
            route("10.96.0.10", 5353, "__mesh-nw-udp-team-a-dns-a-5353"),
            route("10.96.0.11", 5353, "__mesh-nw-udp-team-b-dns-b-5353"),
        ])
        .expect("exact routes publish");

    let (a, _) = router
        .resolve(Some(ip("10.96.0.10")))
        .expect("ClusterIP A resolves");
    assert_eq!(a.proxy.id, "__mesh-nw-udp-team-a-dns-a-5353");
    let (b, _) = router
        .resolve(Some(ip("10.96.0.11")))
        .expect("ClusterIP B resolves");
    assert_eq!(b.proxy.id, "__mesh-nw-udp-team-b-dns-b-5353");
}

/// There is no fallback route. An unrecognized local destination and an absent
/// pktinfo capture are BOTH refused, so nothing is forwarded, no session slot is
/// reserved, and no backend socket is opened for them.
#[test]
fn unknown_and_missing_destinations_are_refused_with_closed_reasons() {
    let router = NodeWaypointUdpDestinationRouter::new(5353);
    router
        .publish(vec![route(
            "10.96.0.10",
            5353,
            "__mesh-nw-udp-team-a-dns-a-5353",
        )])
        .expect("route publishes");

    let (refusal, _) = router
        .resolve(Some(ip("10.96.0.99")))
        .expect_err("an unclaimed destination must never select a route");
    assert_eq!(
        refusal,
        NodeWaypointUdpDestinationRefusal::UnknownDestination
    );
    assert_eq!(refusal.as_str(), "unknown_destination");

    let (refusal, _) = router
        .resolve(None)
        .expect_err("a datagram with no local-destination cmsg must be dropped");
    assert_eq!(
        refusal,
        NodeWaypointUdpDestinationRefusal::MissingLocalDestination
    );
    assert_eq!(refusal.as_str(), "missing_local_destination");
}

/// A retracted (empty) table is a positive fail-closed statement, not a
/// wildcard: nothing resolves through a listener whose routes have left service.
#[test]
fn a_retracted_table_resolves_nothing() {
    let router = NodeWaypointUdpDestinationRouter::new(5353);
    router
        .publish(vec![route(
            "10.96.0.10",
            5353,
            "__mesh-nw-udp-team-a-dns-a-5353",
        )])
        .expect("route publishes");
    assert!(router.resolve(Some(ip("10.96.0.10"))).is_ok());

    router.retract();
    let (refusal, _) = router
        .resolve(Some(ip("10.96.0.10")))
        .expect_err("a withdrawn generation must serve nothing");
    assert_eq!(refusal, NodeWaypointUdpDestinationRefusal::NoRoutes);
}

/// Adding a route republishes a COMPLETE table under the running socket, and
/// removing one retracts only that one.
#[test]
fn republishing_adds_and_removes_routes_without_disturbing_the_others() {
    let router = NodeWaypointUdpDestinationRouter::new(5353);
    let first = router
        .publish(vec![route(
            "10.96.0.10",
            5353,
            "__mesh-nw-udp-team-a-dns-a-5353",
        )])
        .expect("first generation");

    let second = router
        .publish(vec![
            route("10.96.0.10", 5353, "__mesh-nw-udp-team-a-dns-a-5353"),
            route("10.96.0.11", 5353, "__mesh-nw-udp-team-b-dns-b-5353"),
        ])
        .expect("second generation");
    assert!(second > first);
    assert!(
        router.resolve(Some(ip("10.96.0.10"))).is_ok(),
        "adding B must not withdraw A"
    );
    assert!(router.resolve(Some(ip("10.96.0.11"))).is_ok());

    router
        .publish(vec![route(
            "10.96.0.11",
            5353,
            "__mesh-nw-udp-team-b-dns-b-5353",
        )])
        .expect("third generation");
    assert!(
        router.resolve(Some(ip("10.96.0.10"))).is_err(),
        "removing A retracts A's route"
    );
    assert!(
        router.resolve(Some(ip("10.96.0.11"))).is_ok(),
        "removing A must not interrupt B"
    );
}

/// A duplicate exact claim or an inadmissible address refuses the WHOLE
/// publication and retains the previous accepted table — never a partially
/// exact one.
#[test]
fn a_refused_publication_retains_the_previous_accepted_table() {
    let router = NodeWaypointUdpDestinationRouter::new(5353);
    router
        .publish(vec![route(
            "10.96.0.10",
            5353,
            "__mesh-nw-udp-team-a-dns-a-5353",
        )])
        .expect("baseline");

    let error = router
        .publish(vec![
            route("10.96.0.20", 5353, "__mesh-nw-udp-team-a-x-5353"),
            route("10.96.0.20", 5353, "__mesh-nw-udp-team-b-y-5353"),
        ])
        .expect_err("a duplicate exact claim is refused");
    assert_eq!(
        error,
        NodeWaypointUdpDestinationPublishError::DuplicateDestination
    );

    let error = router
        .publish(vec![route(
            "127.0.0.1",
            5353,
            "__mesh-nw-udp-team-a-x-5353",
        )])
        .expect_err("loopback can never be a Service destination");
    assert_eq!(
        error,
        NodeWaypointUdpDestinationPublishError::InadmissibleDestination
    );

    let error = router
        .publish(vec![route(
            "10.96.0.30",
            5354,
            "__mesh-nw-udp-team-a-x-5354",
        )])
        .expect_err("a route for another port never belongs to this listener");
    assert_eq!(
        error,
        NodeWaypointUdpDestinationPublishError::PortMismatch
    );

    let (surviving, _) = router
        .resolve(Some(ip("10.96.0.10")))
        .expect("the previously accepted table is retained in full");
    assert_eq!(surviving.proxy.id, "__mesh-nw-udp-team-a-dns-a-5353");
}

/// A dual-stack `[::]` bind reports an IPv4 datagram's local destination as
/// `::ffff:a.b.c.d`. Both spellings must resolve to the one route.
#[test]
fn ipv4_mapped_destinations_canonicalize_onto_their_ipv4_form() {
    assert_eq!(
        canonical_destination_ip(ip("::ffff:10.96.0.10")),
        ip("10.96.0.10")
    );
    assert_eq!(canonical_destination_ip(ip("fd00::1")), ip("fd00::1"));

    let router = NodeWaypointUdpDestinationRouter::new(5353);
    router
        .publish(vec![
            route("10.96.0.10", 5353, "__mesh-nw-udp-team-a-dns-a-5353"),
            route("fd00:96::10", 5353, "__mesh-nw-udp-team-b-dns-b-5353"),
        ])
        .expect("dual-stack routes publish");

    let (mapped, _) = router
        .resolve(Some(ip("::ffff:10.96.0.10")))
        .expect("mapped spelling resolves to the IPv4 route");
    assert_eq!(mapped.proxy.id, "__mesh-nw-udp-team-a-dns-a-5353");
    let (v6, _) = router
        .resolve(Some(ip("fd00:96::10")))
        .expect("a genuine IPv6 ClusterIP resolves independently");
    assert_eq!(v6.proxy.id, "__mesh-nw-udp-team-b-dns-b-5353");
}

#[test]
fn unspecified_loopback_multicast_and_broadcast_are_never_destinations() {
    for text in [
        "0.0.0.0",
        "127.0.0.1",
        "224.0.0.1",
        "255.255.255.255",
        "::",
        "::1",
        "ff02::1",
    ] {
        assert!(
            !destination_ip_is_admissible(ip(text)),
            "{text} must not be admissible as a Service destination"
        );
    }
    for text in ["10.96.0.10", "fd00:96::10"] {
        assert!(destination_ip_is_admissible(ip(text)));
    }
}

/// The core same-port isolation property: ONE client tuple concurrently
/// addressing ClusterIP A and ClusterIP B on one port produces two distinct
/// session identities, so their sessions can never collide or reuse each
/// other's state.
#[test]
fn one_client_tuple_addressing_two_destinations_yields_two_session_identities() {
    let client: SocketAddr = "10.244.3.99:41000".parse().expect("client addr");
    let to_a = UdpSessionKey {
        client,
        destination: Some(ip("10.96.0.10")),
        listener_generation: 7,
    };
    let to_b = UdpSessionKey {
        client,
        destination: Some(ip("10.96.0.11")),
        listener_generation: 7,
    };
    assert_ne!(to_a, to_b);

    let mut map = std::collections::HashMap::new();
    map.insert(to_a, "service-a");
    map.insert(to_b, "service-b");
    assert_eq!(map.len(), 2, "the two destinations must not collide");
    assert_eq!(map.get(&to_a), Some(&"service-a"));
    assert_eq!(map.get(&to_b), Some(&"service-b"));

    // A route-less listener (ordinary UDP, or a single-claimant NodeWaypoint
    // listener on the direct-node-address boundary) keeps the historical
    // client-tuple identity, distinct from either routed key.
    let undestined = UdpSessionKey::undestined(client, 7);
    assert_ne!(undestined, to_a);
    assert_ne!(undestined, to_b);

    // The listener generation is part of the identity, so a session can never
    // outlive the bound socket that created it.
    let rebound = UdpSessionKey {
        listener_generation: 8,
        ..to_a
    };
    assert_ne!(rebound, to_a);
}

/// Refusals are bounded and label-free: a closed reason string plus a counter,
/// never a Service name, client address, or registry-supplied value.
#[test]
fn refusals_are_counted_and_bounded() {
    let router = NodeWaypointUdpDestinationRouter::new(5353);
    router
        .publish(vec![route(
            "10.96.0.10",
            5353,
            "__mesh-nw-udp-team-a-dns-a-5353",
        )])
        .expect("route publishes");
    assert_eq!(router.refusals(), 0);
    for _ in 0..3 {
        let (refusal, _) = router
            .resolve(Some(ip("10.96.0.99")))
            .expect_err("unknown destination");
        router.warn_refusal("__mesh-nw-udp-team-a-dns-a-5353", refusal);
    }
    assert_eq!(router.refusals(), 3);
}

/// The published table is an immutable snapshot: an in-flight reader keeps
/// resolving through the generation it loaded even while a newer one is
/// published (lock-free reads on the receive hot path).
#[test]
fn a_published_table_snapshot_is_immutable() {
    let router = NodeWaypointUdpDestinationRouter::new(5353);
    router
        .publish(vec![route(
            "10.96.0.10",
            5353,
            "__mesh-nw-udp-team-a-dns-a-5353",
        )])
        .expect("first generation");
    let snapshot: Arc<_> = router.snapshot();
    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot.listen_port(), 5353);
    assert_eq!(snapshot.destinations(), vec![ip("10.96.0.10")]);

    router.retract();
    assert_eq!(
        snapshot.len(),
        1,
        "an already-loaded snapshot is immutable across a republication"
    );
    assert!(router.snapshot().is_empty());
    assert!(snapshot.generation() < router.snapshot().generation());
    assert_eq!(
        snapshot.owners(),
        vec![NamespacedResourceId::new(
            "ferrum",
            "__mesh-nw-udp-team-a-dns-a-5353"
        )]
    );
}
