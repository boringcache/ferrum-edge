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
    route_in("ferrum", destination, port, proxy)
}

fn route_in(
    namespace: &str,
    destination: &str,
    port: u16,
    proxy: &str,
) -> NodeWaypointUdpDestinationRoute {
    NodeWaypointUdpDestinationRoute::new(
        ip(destination),
        port,
        NamespacedResourceId::new(namespace, proxy),
        false,
    )
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
    assert_eq!(error, NodeWaypointUdpDestinationPublishError::PortMismatch);

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
    let owner_a = Arc::new(NamespacedResourceId::new(
        "ferrum",
        "__mesh-nw-udp-team-a-dns-a-5353",
    ));
    let owner_b = Arc::new(NamespacedResourceId::new(
        "ferrum",
        "__mesh-nw-udp-team-b-dns-b-5353",
    ));
    let to_a = UdpSessionKey {
        client,
        destination: Some(ip("10.96.0.10")),
        destination_owner: Some(Arc::clone(&owner_a)),
        listener_generation: 7,
    };
    let to_b = UdpSessionKey {
        client,
        destination: Some(ip("10.96.0.11")),
        destination_owner: Some(Arc::clone(&owner_b)),
        listener_generation: 7,
    };
    assert_ne!(to_a, to_b);

    let mut map = std::collections::HashMap::new();
    map.insert(to_a.clone(), "service-a");
    map.insert(to_b.clone(), "service-b");
    assert_eq!(map.len(), 2, "the two destinations must not collide");
    assert_eq!(map.get(&to_a), Some(&"service-a"));
    assert_eq!(map.get(&to_b), Some(&"service-b"));

    // A route-less listener (ordinary UDP, or a single-claimant NodeWaypoint
    // listener on the direct-node-address boundary) keeps the historical
    // client-tuple identity, distinct from either routed key.
    let undestined = UdpSessionKey::undestined(client, 7);
    assert_ne!(undestined, to_a);
    assert_ne!(undestined, to_b);
    assert!(undestined.destination_owner.is_none());

    // The listener generation is part of the identity, so a session can never
    // outlive the bound socket that created it.
    let rebound = UdpSessionKey {
        listener_generation: 8,
        ..to_a.clone()
    };
    assert_ne!(rebound, to_a);
}

/// If exact destination X changes ownership from namespaced Service A to
/// namespaced Service B without restarting the listener, the same
/// `(client, destination, listener generation)` MUST be a distinct pending,
/// session, and last-client identity. Otherwise B's datagram would reuse A's
/// upstream, policy, plugins, accounting, and reply context.
#[test]
fn same_destination_under_distinct_owners_cannot_share_session_identity() {
    let client: SocketAddr = "10.244.3.99:41000".parse().expect("client addr");
    let destination = ip("10.96.0.10");
    let owner_a = Arc::new(NamespacedResourceId::new(
        "ferrum",
        "__mesh-nw-udp-team-a-dns-a-5353",
    ));
    let owner_b = Arc::new(NamespacedResourceId::new(
        "ferrum",
        "__mesh-nw-udp-team-b-dns-b-5353",
    ));
    let key_a = UdpSessionKey {
        client,
        destination: Some(destination),
        destination_owner: Some(Arc::clone(&owner_a)),
        listener_generation: 7,
    };
    let key_b = UdpSessionKey {
        client,
        destination: Some(destination),
        destination_owner: Some(Arc::clone(&owner_b)),
        listener_generation: 7,
    };
    assert_ne!(
        key_a, key_b,
        "owner A and owner B must not share a session identity"
    );

    let mut pending = std::collections::HashMap::new();
    pending.insert(key_a.clone(), "pending-a");
    pending.insert(key_b.clone(), "pending-b");
    assert_eq!(pending.len(), 2);
    assert_eq!(pending.get(&key_a), Some(&"pending-a"));
    assert_eq!(pending.get(&key_b), Some(&"pending-b"));

    let mut sessions = std::collections::HashMap::new();
    sessions.insert(key_a.clone(), "session-a");
    sessions.insert(key_b.clone(), "session-b");
    assert_eq!(sessions.get(&key_a), Some(&"session-a"));
    assert_eq!(sessions.get(&key_b), Some(&"session-b"));

    let mut last_client = Some((key_a.clone(), Arc::new("session-a")));
    assert!(
        ferrum_edge::_test_support::take_udp_last_client_if_live_keyed_for_test(
            &mut last_client,
            key_b.clone(),
            |_| false,
        )
        .is_none(),
        "owner B must not hit owner A's last-client cache"
    );
    assert!(
        ferrum_edge::_test_support::take_udp_last_client_if_live_keyed_for_test(
            &mut last_client,
            key_a,
            |_| false,
        )
        .is_some(),
        "owner A's last-client cache remains keyed to A"
    );
}

/// Adding or removing an unrelated route republishes the table under a new
/// generation, but the surviving owner's session key must remain equal.
/// Equality compares the namespaced identity, not Arc pointer identity, so
/// a fresh publication of the same owner cannot miss the previous key.
#[test]
fn equivalent_owner_identity_survives_route_table_republication() {
    let router = NodeWaypointUdpDestinationRouter::new(5353);
    router
        .publish(vec![route(
            "10.96.0.10",
            5353,
            "__mesh-nw-udp-team-a-dns-a-5353",
        )])
        .expect("first generation");
    let (first, first_generation) = router
        .resolve(Some(ip("10.96.0.10")))
        .expect("A resolves before republish");

    let second_generation = router
        .publish(vec![
            route("10.96.0.10", 5353, "__mesh-nw-udp-team-a-dns-a-5353"),
            route("10.96.0.11", 5353, "__mesh-nw-udp-team-b-dns-b-5353"),
        ])
        .expect("second generation");
    assert!(second_generation > first_generation);
    let (second, _) = router
        .resolve(Some(ip("10.96.0.10")))
        .expect("A still resolves after B is added");

    assert!(
        !Arc::ptr_eq(&first.proxy, &second.proxy),
        "a republication allocates a new owner Arc; equality must not depend on the pointer"
    );

    let client: SocketAddr = "10.244.3.99:41000".parse().expect("client addr");
    let key_before = UdpSessionKey::for_route(client, first.as_ref(), 7);
    let key_after = UdpSessionKey::for_route(client, second.as_ref(), 7);
    assert_eq!(
        key_before, key_after,
        "an equivalent namespaced owner must remain equal across republication"
    );

    let mut map = std::collections::HashMap::new();
    map.insert(key_before, "session-a");
    assert_eq!(
        map.get(&key_after),
        Some(&"session-a"),
        "the republished owner must hit the same session/pending/cache slot"
    );
}

/// Namespace is part of owner identity: the same proxy id in two namespaces
/// must never share a session, pending, or last-client key.
#[test]
fn destination_owner_identity_includes_namespace() {
    let client: SocketAddr = "10.244.3.99:41000".parse().expect("client addr");
    let destination = ip("10.96.0.10");
    let same_id = "__mesh-nw-udp-dns-5353";
    let team_a = UdpSessionKey {
        client,
        destination: Some(destination),
        destination_owner: Some(Arc::new(NamespacedResourceId::new("team-a", same_id))),
        listener_generation: 7,
    };
    let team_b = UdpSessionKey {
        client,
        destination: Some(destination),
        destination_owner: Some(Arc::new(NamespacedResourceId::new("team-b", same_id))),
        listener_generation: 7,
    };
    assert_ne!(team_a, team_b);

    let mut map = std::collections::HashMap::new();
    map.insert(team_a.clone(), "team-a");
    map.insert(team_b.clone(), "team-b");
    assert_eq!(map.len(), 2);
    assert_eq!(map.get(&team_a), Some(&"team-a"));
    assert_eq!(map.get(&team_b), Some(&"team-b"));

    let router = NodeWaypointUdpDestinationRouter::new(5353);
    router
        .publish(vec![
            route_in("team-a", "10.96.0.10", 5353, same_id),
            route_in("team-b", "10.96.0.11", 5353, same_id),
        ])
        .expect("same id in two namespaces publishes as two owners");
    let (resolved_a, _) = router
        .resolve(Some(ip("10.96.0.10")))
        .expect("team-a destination");
    let (resolved_b, _) = router
        .resolve(Some(ip("10.96.0.11")))
        .expect("team-b destination");
    assert_eq!(resolved_a.proxy.namespace, "team-a");
    assert_eq!(resolved_b.proxy.namespace, "team-b");
    assert_eq!(resolved_a.proxy.id, resolved_b.proxy.id);
    assert_ne!(
        UdpSessionKey::for_route(client, resolved_a.as_ref(), 7),
        UdpSessionKey::for_route(client, resolved_b.as_ref(), 7)
    );
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

/// One bound UDP client socket sending sequentially to two same-port ClusterIPs
/// must produce two destination-scoped LB keys. A client-only key would alias
/// Service B onto A's Round-Robin slot (hosted
/// `node_waypoint.udp.same_port_demux_shared_client_tuple`).
#[test]
fn one_source_socket_two_same_port_destinations_cannot_share_lb_identity() {
    let client = ip("10.244.2.6");
    let dest_a = ip("10.96.36.42");
    let dest_b = ip("10.96.36.43");
    let key_a = ferrum_edge::_test_support::udp_session_lb_hash_key_for_test(client, Some(dest_a));
    let key_b = ferrum_edge::_test_support::udp_session_lb_hash_key_for_test(client, Some(dest_b));
    let undestined = ferrum_edge::_test_support::udp_session_lb_hash_key_for_test(client, None);

    assert_ne!(
        key_a, key_b,
        "two same-port ClusterIPs from one client tuple must not share an LB key"
    );
    assert_ne!(key_a, undestined);
    assert_ne!(key_b, undestined);
    assert_eq!(undestined, "10.244.2.6");
    assert!(
        key_a.contains('|') && key_b.contains('|'),
        "destination-routed keys use the pool-key `|` delimiter: {key_a} / {key_b}"
    );
    assert_eq!(
        ferrum_edge::_test_support::udp_session_lb_hash_key_for_test(
            "::ffff:10.244.2.6".parse().expect("mapped client"),
            Some(dest_a),
        ),
        key_a,
        "IPv4-mapped clients must canonicalize before the dest suffix"
    );
}

#[test]
fn udp_backend_host_family_matches_literal_destination() {
    let dest_v4 = ip("10.96.36.42");
    let dest_v6 = ip("fd00:96::42");
    assert!(
        ferrum_edge::_test_support::udp_backend_host_matches_destination_family_for_test(
            "10.244.2.9", dest_v4,
        )
    );
    assert!(
        !ferrum_edge::_test_support::udp_backend_host_matches_destination_family_for_test(
            "fd00:10:244:2::9", dest_v4,
        )
    );
    assert!(
        ferrum_edge::_test_support::udp_backend_host_matches_destination_family_for_test(
            "fd00:10:244:2::9", dest_v6,
        )
    );
    assert!(
        ferrum_edge::_test_support::udp_backend_host_matches_destination_family_for_test(
            "echo.svc.cluster.local", dest_v4,
        ),
        "hostnames are admitted here; DNS matching_family filters later"
    );
        "hostnames are admitted here; DNS matching_family filters later"
    );
}

/// Dual-stack NodeWaypoint upstreams publish every pod address. Round-Robin
/// advancing to the IPv6 slot must not be used for an IPv4 ClusterIP: UDP
/// connect to IPv6 succeeds then ICMP-refuses, which the live shared-tuple
/// probe observed as TIMEOUT / hits_b=0.
#[test]
fn mixed_family_round_robin_cannot_give_ipv4_dest_an_ipv6_backend() {
    let (proxy, cache, health) = mixed_family_udp_upstream();
    let snapshot = cache.load();
    let dest = Some(ip("10.96.36.42"));
    let key =
        ferrum_edge::_test_support::udp_session_lb_hash_key_for_test(ip("10.244.2.6"), dest);

    let (first, port) =
        ferrum_edge::_test_support::resolve_udp_backend_target_for_destination_for_test(
            &proxy, &snapshot, &health, &key, dest,
        )
        .expect("IPv4 dest must select a backend");
    let (second, _) =
        ferrum_edge::_test_support::resolve_udp_backend_target_for_destination_for_test(
            &proxy, &snapshot, &health, &key, dest,
        )
        .expect("second select from the same source socket must still match family");

    assert_eq!(port, 15355);
    for host in [&first, &second] {
        let backend: IpAddr = host.parse().expect("literal backend");
        assert!(
            backend.is_ipv4(),
            "IPv4 ClusterIP must not dial IPv6 backend {host}"
        );
        assert_ne!(host.as_str(), "fd00:10:244:2::9");
    }

    let dest_b = Some(ip("10.96.36.43"));
    let key_b =
        ferrum_edge::_test_support::udp_session_lb_hash_key_for_test(ip("10.244.2.6"), dest_b);
    let (host_b, _) =
        ferrum_edge::_test_support::resolve_udp_backend_target_for_destination_for_test(
            &proxy, &snapshot, &health, &key_b, dest_b,
        )
        .expect("second destination from the same client tuple");
    let backend_b: IpAddr = host_b.parse().expect("literal backend");
    assert!(
        backend_b.is_ipv4(),
        "Service B from the shared client tuple must not inherit an IPv6 RR winner"
    );
}

#[test]
fn mixed_family_round_robin_ipv6_dest_stays_on_ipv6_backends() {
    let (proxy, cache, health) = mixed_family_udp_upstream();
    let snapshot = cache.load();
    let dest = Some(ip("fd00:96::42"));
    let key =
        ferrum_edge::_test_support::udp_session_lb_hash_key_for_test(ip("10.244.2.6"), dest);
    let (host, _) =
        ferrum_edge::_test_support::resolve_udp_backend_target_for_destination_for_test(
            &proxy, &snapshot, &health, &key, dest,
        )
        .expect("IPv6 dest must select a backend");
    let backend: IpAddr = host.parse().expect("literal backend");
    assert!(
        backend.is_ipv6(),
        "IPv6 ClusterIP must stay on IPv6 backends"
    );
}

#[test]
fn mixed_family_round_robin_fails_closed_without_same_family_backend() {
    let mut config: ferrum_edge::config::types::GatewayConfig = serde_json::from_value(
        serde_json::json!({
            "version": "1",
            "proxies": [{
                "id": "udp-proxy",
                "backend_scheme": "udp",
                "backend_host": "unused.local",
                "backend_port": 0,
                "listen_port": 15355,
                "upstream_id": "demux-b",
            }],
            "consumers": [],
            "plugin_configs": [],
            "upstreams": [{
                "id": "demux-b",
                "algorithm": "round_robin",
                "targets": [
                    { "host": "fd00:10:244:2::9", "port": 15355 }
                ]
            }]
        }),
    )
    .expect("gateway config should deserialize");
    config.resolve_dispatch_port_overrides();
    let proxy = config.proxies[0].clone();
    let cache = ferrum_edge::load_balancer::LoadBalancerCache::new(&config);
    let snapshot = cache.load();
    let health = ferrum_edge::health_check::HealthChecker::new();
    let dest = Some(ip("10.96.36.42"));
    let key =
        ferrum_edge::_test_support::udp_session_lb_hash_key_for_test(ip("10.244.2.6"), dest);
    let err = ferrum_edge::_test_support::resolve_udp_backend_target_for_destination_for_test(
        &proxy, &snapshot, &health, &key, dest,
    )
    .expect_err("IPv4 dest with only IPv6 backends must fail closed");
    assert!(
        err.contains("destination family"),
        "fail-closed error should name the family gap: {err}"
    );
}

fn mixed_family_udp_upstream() -> (
    ferrum_edge::config::types::Proxy,
    ferrum_edge::load_balancer::LoadBalancerCache,
    ferrum_edge::health_check::HealthChecker,
) {
    let mut config: ferrum_edge::config::types::GatewayConfig = serde_json::from_value(
        serde_json::json!({
            "version": "1",
            "proxies": [{
                "id": "udp-proxy",
                "backend_scheme": "udp",
                "backend_host": "unused.local",
                "backend_port": 0,
                "listen_port": 15355,
                "upstream_id": "demux-b",
            }],
            "consumers": [],
            "plugin_configs": [],
            "upstreams": [{
                "id": "demux-b",
                "algorithm": "round_robin",
                "targets": [
                    { "host": "10.244.2.9", "port": 15355 },
                    { "host": "fd00:10:244:2::9", "port": 15355 }
                ]
            }]
        }),
    )
    .expect("gateway config should deserialize");
    config.resolve_dispatch_port_overrides();
    let proxy = config.proxies[0].clone();
    let cache = ferrum_edge::load_balancer::LoadBalancerCache::new(&config);
    (
        proxy,
        cache,
        ferrum_edge::health_check::HealthChecker::new(),
    )
}
