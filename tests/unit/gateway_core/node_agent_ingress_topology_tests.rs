//! External unit coverage for NodeWaypoint ingress-interface topology proof.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ferrum_edge::ebpf::ingress_topology::{
    IngressTopologyReason, IngressTopologyState, IpCidr, LinkState, RouteEntry,
    TopologyRequirements, validate_topology_snapshot,
};

fn cidr(raw: &str) -> IpCidr {
    IpCidr::parse(raw).expect("valid test CIDR")
}

fn route(raw: &str, interface: &str, metric: u32) -> RouteEntry {
    RouteEntry {
        destination: cidr(raw),
        interface: interface.to_string(),
        metric,
        usable: true,
    }
}

fn up_link() -> LinkState {
    LinkState {
        exists: true,
        up: true,
        loopback: false,
        supported: true,
    }
}

fn v4_requirements() -> TopologyRequirements {
    TopologyRequirements {
        remote_pod_cidrs: vec![cidr("10.244.2.0/24")],
        remote_node_addresses: vec![IpAddr::V4(Ipv4Addr::new(172, 18, 0, 3))],
        require_ipv4: true,
        require_ipv6: false,
    }
}

#[test]
fn exact_single_uplink_ipv4_topology_is_ready() {
    let links = BTreeMap::from([("eth0".to_string(), up_link())]);
    let routes = vec![
        route("10.244.2.0/24", "eth0", 0),
        route("172.18.0.0/16", "eth0", 0),
    ];
    let outcome = validate_topology_snapshot(
        &["eth0".to_string()],
        &v4_requirements(),
        &routes,
        &links,
    );

    assert_eq!(outcome.status.state, IngressTopologyState::Ready);
    assert_eq!(outcome.status.reason, IngressTopologyReason::Valid);
    assert_eq!(outcome.status.expected_interfaces, 1);
    assert!(outcome.status.ipv4_covered);
    assert!(!outcome.status.ipv6_required);
}

#[test]
fn existing_but_wrong_interface_is_unavailable() {
    let links = BTreeMap::from([
        ("eth0".to_string(), up_link()),
        ("mgmt0".to_string(), up_link()),
    ]);
    let routes = vec![
        route("10.244.2.0/24", "eth0", 0),
        route("172.18.0.0/16", "eth0", 0),
    ];
    let outcome = validate_topology_snapshot(
        &["mgmt0".to_string()],
        &v4_requirements(),
        &routes,
        &links,
    );

    assert_eq!(outcome.status.state, IngressTopologyState::Unavailable);
    assert_eq!(outcome.status.reason, IngressTopologyReason::WrongInterface);
    assert_eq!(outcome.status.configured_interfaces, 1);
    assert_eq!(outcome.status.expected_interfaces, 1);
}

#[test]
fn down_and_loopback_devices_are_rejected_before_route_evidence() {
    let routes = vec![
        route("10.244.2.0/24", "eth0", 0),
        route("172.18.0.0/16", "eth0", 0),
    ];
    let down = BTreeMap::from([(
        "eth0".to_string(),
        LinkState {
            up: false,
            ..up_link()
        },
    )]);
    assert_eq!(
        validate_topology_snapshot(
            &["eth0".to_string()],
            &v4_requirements(),
            &routes,
            &down,
        )
        .status
        .reason,
        IngressTopologyReason::DeviceDown,
    );

    let loopback = BTreeMap::from([(
        "lo".to_string(),
        LinkState {
            loopback: true,
            ..up_link()
        },
    )]);
    assert_eq!(
        validate_topology_snapshot(
            &["lo".to_string()],
            &v4_requirements(),
            &routes,
            &loopback,
        )
        .status
        .reason,
        IngressTopologyReason::Loopback,
    );
}

#[test]
fn missing_invalid_and_unsupported_devices_are_rejected() {
    let routes = vec![
        route("10.244.2.0/24", "eth0", 0),
        route("172.18.0.0/16", "eth0", 0),
    ];
    assert_eq!(
        validate_topology_snapshot(
            &["missing0".to_string()],
            &v4_requirements(),
            &routes,
            &BTreeMap::new(),
        )
        .status
        .reason,
        IngressTopologyReason::DeviceMissing,
    );
    assert_eq!(
        validate_topology_snapshot(
            &["bad/name".to_string()],
            &v4_requirements(),
            &routes,
            &BTreeMap::new(),
        )
        .status
        .reason,
        IngressTopologyReason::InvalidInterfaceName,
    );
    let unsupported = BTreeMap::from([(
        "eth0".to_string(),
        LinkState {
            supported: false,
            ..up_link()
        },
    )]);
    assert_eq!(
        validate_topology_snapshot(
            &["eth0".to_string()],
            &v4_requirements(),
            &routes,
            &unsupported,
        )
        .status
        .reason,
        IngressTopologyReason::UnsupportedDevice,
    );
}

#[test]
fn dual_stack_requires_complete_family_coverage() {
    let requirements = TopologyRequirements {
        remote_pod_cidrs: vec![cidr("10.244.2.0/24"), cidr("fd00:10:244:2::/64")],
        remote_node_addresses: vec![
            IpAddr::V4(Ipv4Addr::new(172, 18, 0, 3)),
            IpAddr::V6("fd00::3".parse::<Ipv6Addr>().expect("test IPv6")),
        ],
        require_ipv4: true,
        require_ipv6: true,
    };
    let links = BTreeMap::from([("eth0".to_string(), up_link())]);
    let incomplete = vec![
        route("10.244.2.0/24", "eth0", 0),
        route("172.18.0.0/16", "eth0", 0),
    ];
    assert_eq!(
        validate_topology_snapshot(
            &["eth0".to_string()],
            &requirements,
            &incomplete,
            &links,
        )
        .status
        .reason,
        IngressTopologyReason::RouteMissing,
    );

    let complete = [
        incomplete,
        vec![
            route("fd00:10:244:2::/64", "eth0", 0),
            route("fd00::/64", "eth0", 0),
        ],
    ]
    .concat();
    let outcome = validate_topology_snapshot(
        &["eth0".to_string()],
        &requirements,
        &complete,
        &links,
    );
    assert_eq!(outcome.status.state, IngressTopologyState::Ready);
    assert!(outcome.status.ipv4_covered);
    assert!(outcome.status.ipv6_covered);
}

#[test]
fn multi_uplink_requires_the_complete_exact_set() {
    let requirements = TopologyRequirements {
        remote_pod_cidrs: vec![cidr("10.244.2.0/24"), cidr("10.244.3.0/24")],
        remote_node_addresses: vec![
            IpAddr::V4(Ipv4Addr::new(172, 18, 0, 3)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3)),
        ],
        require_ipv4: true,
        require_ipv6: false,
    };
    let links = BTreeMap::from([
        ("eth0".to_string(), up_link()),
        ("eth1".to_string(), up_link()),
    ]);
    let routes = vec![
        route("10.244.2.0/24", "eth0", 0),
        route("172.18.0.0/16", "eth0", 0),
        route("10.244.3.0/24", "eth1", 0),
        route("192.0.2.0/24", "eth1", 0),
    ];

    let incomplete = validate_topology_snapshot(
        &["eth0".to_string()],
        &requirements,
        &routes,
        &links,
    );
    assert_eq!(
        incomplete.status.reason,
        IngressTopologyReason::IncompleteInterfaceSet,
    );

    let complete = validate_topology_snapshot(
        &["eth0".to_string(), "eth1".to_string()],
        &requirements,
        &routes,
        &links,
    );
    assert_eq!(complete.status.state, IngressTopologyState::Ready);
    assert_eq!(complete.status.expected_interfaces, 2);
}

#[test]
fn equal_cost_or_split_routes_are_ambiguous() {
    let links = BTreeMap::from([
        ("eth0".to_string(), up_link()),
        ("eth1".to_string(), up_link()),
    ]);
    let routes = vec![
        route("10.244.2.0/24", "eth0", 0),
        route("10.244.2.0/24", "eth1", 0),
        route("172.18.0.0/16", "eth0", 0),
    ];
    assert_eq!(
        validate_topology_snapshot(
            &["eth0".to_string(), "eth1".to_string()],
            &v4_requirements(),
            &routes,
            &links,
        )
        .status
        .reason,
        IngressTopologyReason::RouteAmbiguous,
    );
}

#[test]
fn rejected_subprefix_disproves_complete_route_coverage() {
    let links = BTreeMap::from([("eth0".to_string(), up_link())]);
    let mut rejected = route("10.244.2.128/25", "lo", 0);
    rejected.usable = false;
    let routes = vec![
        route("10.244.2.0/24", "eth0", 0),
        rejected,
        route("172.18.0.0/16", "eth0", 0),
    ];

    assert_eq!(
        validate_topology_snapshot(
            &["eth0".to_string()],
            &v4_requirements(),
            &routes,
            &links,
        )
        .status
        .reason,
        IngressTopologyReason::RouteAmbiguous,
    );
}

#[test]
fn route_drift_withdraws_a_previously_valid_proof() {
    let links = BTreeMap::from([
        ("eth0".to_string(), up_link()),
        ("eth1".to_string(), up_link()),
    ]);
    let initial_routes = vec![
        route("10.244.2.0/24", "eth0", 0),
        route("172.18.0.0/16", "eth0", 0),
    ];
    assert_eq!(
        validate_topology_snapshot(
            &["eth0".to_string()],
            &v4_requirements(),
            &initial_routes,
            &links,
        )
        .status
        .state,
        IngressTopologyState::Ready,
    );

    let drifted_routes = vec![
        route("10.244.2.0/24", "eth1", 0),
        route("172.18.0.0/16", "eth1", 0),
    ];
    let drifted = validate_topology_snapshot(
        &["eth0".to_string()],
        &v4_requirements(),
        &drifted_routes,
        &links,
    );
    assert_eq!(drifted.status.state, IngressTopologyState::Unavailable);
    assert_eq!(drifted.status.reason, IngressTopologyReason::WrongInterface);
}
