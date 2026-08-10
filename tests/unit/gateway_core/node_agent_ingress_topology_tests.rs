//! External unit coverage for NodeWaypoint ingress-interface topology proof.

use std::collections::BTreeMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ferrum_edge::ebpf::ingress_topology::{
    IngressTopologyReason, IngressTopologyState, IpCidr, LinkState, NodeWatchCacheDecision,
    NodeWatchCacheRecovery, RouteEntry, TopologyRequirements, parse_ipv4_route_file,
    parse_ipv6_route_file, read_link_state_from_root, requirements_from_nodes,
    validate_host_topology_from_roots, validate_topology_snapshot,
};
use k8s_openapi::api::core::v1::Node;
use serde_json::json;
use tempfile::tempdir;

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

fn node(
    name: &str,
    pod_cidrs: &[&str],
    ready: Option<&str>,
    unschedulable: bool,
    addresses: &[(&str, &str)],
) -> Node {
    let conditions = ready.map(|status| {
        json!([{
            "type": "Ready",
            "status": status,
            "lastHeartbeatTime": null,
            "lastTransitionTime": null
        }])
    });
    serde_json::from_value(json!({
        "apiVersion": "v1",
        "kind": "Node",
        "metadata": { "name": name },
        "spec": {
            "podCIDRs": pod_cidrs,
            "unschedulable": unschedulable
        },
        "status": {
            "conditions": conditions,
            "addresses": addresses.iter().map(|(kind, address)| {
                json!({ "type": kind, "address": address })
            }).collect::<Vec<_>>()
        }
    }))
    .expect("valid test Node")
}

fn write_link(root: &std::path::Path, name: &str, ifindex: u32, iflink: u32) {
    let link = root.join(name);
    fs::create_dir_all(link.join("device")).expect("create test link");
    fs::write(link.join("flags"), "0x1\n").expect("write flags");
    fs::write(link.join("operstate"), "up\n").expect("write operstate");
    fs::write(link.join("carrier"), "1\n").expect("write carrier");
    fs::write(link.join("type"), "1\n").expect("write type");
    fs::write(link.join("ifindex"), format!("{ifindex}\n")).expect("write ifindex");
    fs::write(link.join("iflink"), format!("{iflink}\n")).expect("write iflink");
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
    let outcome =
        validate_topology_snapshot(&["eth0".to_string()], &v4_requirements(), &routes, &links);

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
    let outcome =
        validate_topology_snapshot(&["mgmt0".to_string()], &v4_requirements(), &routes, &links);

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
        validate_topology_snapshot(&["eth0".to_string()], &v4_requirements(), &routes, &down,)
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
        validate_topology_snapshot(&["lo".to_string()], &v4_requirements(), &routes, &loopback,)
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
        validate_topology_snapshot(&["eth0".to_string()], &requirements, &incomplete, &links,)
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
    let outcome =
        validate_topology_snapshot(&["eth0".to_string()], &requirements, &complete, &links);
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

    let incomplete =
        validate_topology_snapshot(&["eth0".to_string()], &requirements, &routes, &links);
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
        validate_topology_snapshot(&["eth0".to_string()], &v4_requirements(), &routes, &links,)
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

#[test]
fn proc_route_parsers_preserve_endianness_metrics_flags_and_negative_evidence() {
    let ipv4 = concat!(
        "Iface\tDestination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n",
        "eth0\t0002F40A 00000000 0001 0 0 7 00FFFFFF 0 0 0\n",
        "lo\t8002F40A 00000000 0201 0 0 0 80FFFFFF 0 0 0\n",
        "eth9\t00000000 00000000 0000 0 0 0 00000000 0 0 0\n",
    );
    let routes = parse_ipv4_route_file(ipv4).expect("parse IPv4 proc route file");
    assert_eq!(routes.len(), 2);
    assert_eq!(routes[0].destination, cidr("10.244.2.0/24"));
    assert_eq!(routes[0].metric, 7);
    assert!(routes[0].usable);
    assert_eq!(routes[1].destination, cidr("10.244.2.128/25"));
    assert!(!routes[1].usable);

    let ipv6 = concat!(
        "fd001024000200000000000000000000 40 00000000000000000000000000000000 00 ",
        "00000000000000000000000000000000 00000005 00000000 00000000 00000001 eth0\n",
        "fd001024000280000000000000000000 41 fd000000000000000000000000000000 40 ",
        "00000000000000000000000000000000 00000000 00000000 00000000 00000001 eth0\n",
        "fd0010240002c0000000000000000000 42 00000000000000000000000000000000 00 ",
        "00000000000000000000000000000000 00000000 00000000 00000000 00000201 lo\n",
    );
    let routes = parse_ipv6_route_file(ipv6).expect("parse IPv6 proc route file");
    assert_eq!(routes.len(), 3);
    assert_eq!(routes[0].destination, cidr("fd00:1024:2::/64"));
    assert_eq!(routes[0].metric, 5);
    assert!(routes[0].usable);
    assert!(
        !routes[1].usable,
        "source-specific route is negative evidence"
    );
    assert!(!routes[2].usable, "reject route is negative evidence");
}

#[test]
fn malformed_ipv6_hex_is_rejected_without_utf8_indexing() {
    // Exactly 32 bytes with a multibyte scalar crossing the old byte-slice
    // boundary. The parser must return a closed error, never panic.
    let destination = format!("0é{}", "0".repeat(29));
    let non_ascii = format!(
        "{destination} 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000000 00000000 00000001 eth0\n"
    );
    assert_eq!(
        parse_ipv6_route_file(&non_ascii),
        Err(IngressTopologyReason::RouteTableInvalid),
    );
    let malformed = "gg000000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000000 00000000 00000001 eth0\n";
    assert_eq!(
        parse_ipv6_route_file(malformed),
        Err(IngressTopologyReason::RouteTableInvalid),
    );
}

#[test]
fn real_procfs_and_sysfs_ingestion_proves_ipv4_and_ipv6_only_topologies() {
    let fixture = tempdir().expect("temporary topology fixture");
    let proc_root = fixture.path().join("proc");
    let sys_root = fixture.path().join("sys/class/net");
    fs::create_dir_all(proc_root.join("net")).expect("create proc net");
    fs::create_dir_all(&sys_root).expect("create sys net");
    write_link(&sys_root, "eth0", 2, 1);
    fs::write(
        proc_root.join("net/route"),
        concat!(
            "Iface\tDestination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n",
            "eth0\t0002F40A 00000000 0001 0 0 0 00FFFFFF 0 0 0\n",
            "eth0\t000012AC 00000000 0001 0 0 0 0000FFFF 0 0 0\n",
        ),
    )
    .expect("write IPv4 routes");
    let ipv4 = validate_host_topology_from_roots(
        &["eth0".to_string()],
        &v4_requirements(),
        &proc_root,
        &sys_root,
    );
    assert_eq!(ipv4.status.state, IngressTopologyState::Ready);

    fs::remove_file(proc_root.join("net/route")).expect("remove unused IPv4 table");
    fs::write(
        proc_root.join("net/ipv6_route"),
        concat!(
            "fd001024000200000000000000000000 40 00000000000000000000000000000000 00 ",
            "00000000000000000000000000000000 00000000 00000000 00000000 00000001 eth0\n",
            "fd000000000000000000000000000000 40 00000000000000000000000000000000 00 ",
            "00000000000000000000000000000000 00000000 00000000 00000000 00000001 eth0\n",
        ),
    )
    .expect("write IPv6 routes");
    let ipv6_requirements = TopologyRequirements {
        remote_pod_cidrs: vec![cidr("fd00:1024:2::/64")],
        remote_node_addresses: vec!["fd00::3".parse().expect("IPv6 InternalIP")],
        require_ipv4: false,
        require_ipv6: true,
    };
    let ipv6 = validate_host_topology_from_roots(
        &["eth0".to_string()],
        &ipv6_requirements,
        &proc_root,
        &sys_root,
    );
    assert_eq!(ipv6.status.state, IngressTopologyState::Ready);
}

#[test]
fn real_route_ingestion_rejects_non_utf8_oversized_and_excessive_line_input() {
    let fixture = tempdir().expect("temporary topology fixture");
    let proc_root = fixture.path().join("proc");
    let sys_root = fixture.path().join("sys/class/net");
    fs::create_dir_all(proc_root.join("net")).expect("create proc net");
    fs::create_dir_all(&sys_root).expect("create sys net");
    write_link(&sys_root, "eth0", 2, 1);

    fs::write(proc_root.join("net/route"), [0xff, 0xfe]).expect("write non-UTF8 route");
    assert_eq!(
        validate_host_topology_from_roots(
            &["eth0".to_string()],
            &v4_requirements(),
            &proc_root,
            &sys_root,
        )
        .status
        .reason,
        IngressTopologyReason::RouteTableInvalid,
    );

    let oversized = fs::File::create(proc_root.join("net/route")).expect("create route file");
    oversized.set_len(1_048_577).expect("extend route file");
    assert_eq!(
        validate_host_topology_from_roots(
            &["eth0".to_string()],
            &v4_requirements(),
            &proc_root,
            &sys_root,
        )
        .status
        .reason,
        IngressTopologyReason::RouteTableTooLarge,
    );

    fs::write(proc_root.join("net/route"), "\n".repeat(4_098))
        .expect("write excessive route lines");
    assert_eq!(
        validate_host_topology_from_roots(
            &["eth0".to_string()],
            &v4_requirements(),
            &proc_root,
            &sys_root,
        )
        .status
        .reason,
        IngressTopologyReason::RouteTableTooLarge,
    );
}

#[test]
fn sysfs_link_ingestion_classifies_physical_peer_loopback_and_unsafe_shapes() {
    let fixture = tempdir().expect("temporary sysfs fixture");
    let root = fixture.path();
    write_link(root, "physical0", 2, 2);
    assert!(read_link_state_from_root(root, "physical0").supported);

    write_link(root, "veth0", 3, 9);
    fs::remove_dir(root.join("veth0/device")).expect("remove physical marker");
    assert!(read_link_state_from_root(root, "veth0").supported);

    write_link(root, "dummy0", 4, 4);
    fs::remove_dir(root.join("dummy0/device")).expect("remove physical marker");
    assert!(!read_link_state_from_root(root, "dummy0").supported);

    write_link(root, "bridge0", 5, 5);
    fs::create_dir(root.join("bridge0/bridge")).expect("create bridge marker");
    assert!(!read_link_state_from_root(root, "bridge0").supported);

    write_link(root, "tun0", 6, 7);
    fs::create_dir(root.join("tun0/tun_flags")).expect("create tunnel marker");
    assert!(!read_link_state_from_root(root, "tun0").supported);

    write_link(root, "down0", 7, 1);
    fs::write(root.join("down0/carrier"), "0\n").expect("drop carrier");
    assert!(!read_link_state_from_root(root, "down0").up);

    write_link(root, "lo", 1, 1);
    fs::write(root.join("lo/type"), "772\n").expect("write loopback type");
    assert!(read_link_state_from_root(root, "lo").loopback);
    assert!(!read_link_state_from_root(root, "missing0").exists);
}

#[test]
fn node_requirements_are_ready_internal_ip_only_and_fail_closed_when_incomplete() {
    let local = node("local", &[], None, false, &[]);
    let ready = node(
        "remote",
        &["10.244.2.0/24"],
        Some("True"),
        false,
        &[("InternalIP", "172.18.0.3"), ("ExternalIP", "203.0.113.3")],
    );
    let requirements = requirements_from_nodes(&[local.clone(), ready], "local", true)
        .expect("complete Ready Node evidence");
    assert_eq!(
        requirements.remote_node_addresses,
        [IpAddr::V4(Ipv4Addr::new(172, 18, 0, 3))]
    );
    assert!(requirements.require_ipv4);
    assert!(!requirements.require_ipv6);

    for incomplete in [
        node(
            "remote",
            &[],
            Some("True"),
            false,
            &[("InternalIP", "172.18.0.3")],
        ),
        node(
            "remote",
            &["10.244.2.0/24"],
            None,
            false,
            &[("InternalIP", "172.18.0.3")],
        ),
        node(
            "remote",
            &["10.244.2.0/24"],
            Some("Unknown"),
            false,
            &[("InternalIP", "172.18.0.3")],
        ),
        node(
            "remote",
            &["10.244.2.0/24"],
            Some("True"),
            false,
            &[("ExternalIP", "203.0.113.3")],
        ),
    ] {
        assert_eq!(
            requirements_from_nodes(&[local.clone(), incomplete], "local", true),
            Err(IngressTopologyReason::NodeTopologyIncomplete),
        );
    }
}

#[test]
fn only_positively_not_ready_unschedulable_nodes_may_be_ignored() {
    let local = node("local", &[], None, false, &[]);
    let ready = node(
        "ready",
        &["10.244.2.0/24"],
        Some("True"),
        false,
        &[("InternalIP", "172.18.0.3")],
    );
    let dormant = node("new", &[], Some("False"), true, &[]);
    assert!(
        requirements_from_nodes(&[local.clone(), ready.clone(), dormant], "local", false).is_ok()
    );
    let schedulable = node("new", &[], Some("False"), false, &[]);
    assert_eq!(
        requirements_from_nodes(&[local.clone(), ready.clone(), schedulable], "local", false),
        Err(IngressTopologyReason::NodeTopologyIncomplete),
    );
    let allocated = node(
        "allocated",
        &["10.244.9.0/24"],
        Some("False"),
        true,
        &[("InternalIP", "172.18.0.9")],
    );
    assert_eq!(
        requirements_from_nodes(&[local, ready, allocated], "local", false),
        Err(IngressTopologyReason::NodeTopologyIncomplete),
    );
}

#[test]
fn node_family_derivation_handles_ipv4_dual_stack_and_ipv6_only_capture() {
    let local = node("local", &[], None, false, &[]);
    let ipv4 = node(
        "v4",
        &["10.244.2.0/24"],
        Some("True"),
        false,
        &[("InternalIP", "172.18.0.3")],
    );
    let v4_requirements = requirements_from_nodes(&[local.clone(), ipv4], "local", true)
        .expect("IPv4 cluster with dual-capable listener");
    assert!(v4_requirements.require_ipv4);
    assert!(!v4_requirements.require_ipv6);

    let dual = node(
        "dual",
        &["10.244.2.0/24", "fd00:10:244:2::/64"],
        Some("True"),
        false,
        &[("InternalIP", "172.18.0.3"), ("InternalIP", "fd00::3")],
    );
    let dual_requirements =
        requirements_from_nodes(&[local.clone(), dual], "local", true).expect("dual-stack cluster");
    assert!(dual_requirements.require_ipv4);
    assert!(dual_requirements.require_ipv6);

    let dual_without_ipv6_internal_ip = node(
        "dual-v4-capture",
        &["10.244.2.0/24", "fd00:10:244:2::/64"],
        Some("True"),
        false,
        &[("InternalIP", "172.18.0.3")],
    );
    let v4_capture_requirements = requirements_from_nodes(
        &[local.clone(), dual_without_ipv6_internal_ip],
        "local",
        false,
    )
    .expect("dual-stack cluster intersected with IPv4-only capture");
    assert!(v4_capture_requirements.require_ipv4);
    assert!(!v4_capture_requirements.require_ipv6);

    let ipv6 = node(
        "v6",
        &["fd00:10:244:2::/64"],
        Some("True"),
        false,
        &[("InternalIP", "fd00::3")],
    );
    let ipv6_requirements = requirements_from_nodes(&[local.clone(), ipv6.clone()], "local", true)
        .expect("IPv6-only cluster with IPv6-capable listener");
    assert!(!ipv6_requirements.require_ipv4);
    assert!(ipv6_requirements.require_ipv6);
    assert_eq!(
        requirements_from_nodes(&[local, ipv6], "local", false),
        Err(IngressTopologyReason::FamilyUnproved),
    );
}

#[test]
fn node_and_aggregate_requirement_bounds_have_distinct_closed_reasons() {
    let too_many_nodes: Vec<Node> = (0..257)
        .map(|index| node(&format!("node-{index}"), &[], Some("False"), true, &[]))
        .collect();
    assert_eq!(
        requirements_from_nodes(&too_many_nodes, "node-0", true),
        Err(IngressTopologyReason::NodeSetTooLarge),
    );

    let local = node("local", &[], None, false, &[]);
    let cidrs: Vec<String> = (0..1_025)
        .map(|index| format!("fd00::{index:x}/128"))
        .collect();
    let cidr_refs: Vec<&str> = cidrs.iter().map(String::as_str).collect();
    let oversized = node(
        "remote",
        &cidr_refs,
        Some("True"),
        false,
        &[("InternalIP", "fd00::ffff")],
    );
    assert_eq!(
        requirements_from_nodes(&[local, oversized], "local", true),
        Err(IngressTopologyReason::RequirementSetTooLarge),
    );
}

#[test]
fn invalid_node_cache_never_allows_ready_from_incremental_events() {
    let mut recovery = NodeWatchCacheRecovery::new();
    assert_eq!(
        recovery.on_incremental_invalid(IngressTopologyReason::NodeSetTooLarge),
        NodeWatchCacheDecision::ForceRelist { backoff_secs: 1 },
    );
    assert_eq!(
        recovery.invalid_reason(),
        Some(IngressTopologyReason::NodeSetTooLarge),
    );

    // Deletes/Applies after an authoritative overflow must stay suppressed.
    // Ready may only return through a later complete valid snapshot.
    for _ in 0..8 {
        assert_eq!(
            recovery.on_incremental(),
            NodeWatchCacheDecision::SuppressIncremental {
                reason: IngressTopologyReason::NodeSetTooLarge,
            },
        );
    }
    assert_ne!(
        recovery.on_incremental(),
        NodeWatchCacheDecision::AllowIncremental,
    );
    assert_ne!(
        recovery.on_incremental(),
        NodeWatchCacheDecision::CommitSnapshot,
    );
}

#[test]
fn node_cache_recovery_requires_complete_valid_replacement_snapshot() {
    let mut recovery = NodeWatchCacheRecovery::new();
    assert_eq!(
        recovery.on_init(),
        NodeWatchCacheDecision::StartInitializing,
    );
    assert_eq!(
        recovery.on_invalid_snapshot(IngressTopologyReason::NodeSetTooLarge),
        NodeWatchCacheDecision::ForceRelist { backoff_secs: 1 },
    );
    assert_eq!(
        recovery.on_incremental(),
        NodeWatchCacheDecision::SuppressIncremental {
            reason: IngressTopologyReason::NodeSetTooLarge,
        },
    );

    // A fresh Init withdraws readiness again but still does not authorize
    // incremental repair of the previous invalid generation.
    assert_eq!(
        recovery.on_init(),
        NodeWatchCacheDecision::StartInitializing,
    );
    assert_eq!(
        recovery.on_incremental(),
        NodeWatchCacheDecision::SuppressIncremental {
            reason: IngressTopologyReason::KubernetesUnavailable,
        },
    );

    assert_eq!(
        recovery.on_valid_snapshot(),
        NodeWatchCacheDecision::CommitSnapshot,
    );
    assert_eq!(recovery.invalid_reason(), None);
    assert_eq!(
        recovery.on_incremental(),
        NodeWatchCacheDecision::AllowIncremental,
    );
    assert_eq!(recovery.relist_backoff_secs(), 1);
}

#[test]
fn repeated_invalid_node_cache_snapshots_stay_bounded_without_spinning() {
    let mut recovery = NodeWatchCacheRecovery::new();
    let mut observed = Vec::new();
    for _ in 0..8 {
        match recovery.on_invalid_snapshot(IngressTopologyReason::NodeSetTooLarge) {
            NodeWatchCacheDecision::ForceRelist { backoff_secs } => {
                observed.push(backoff_secs);
            }
            other => panic!("expected paced ForceRelist, got {other:?}"),
        }
        // Incremental noise between forced relists must not clear the failure
        // or authorize Ready from partial state.
        assert_eq!(
            recovery.on_incremental(),
            NodeWatchCacheDecision::SuppressIncremental {
                reason: IngressTopologyReason::NodeSetTooLarge,
            },
        );
    }

    assert_eq!(observed, vec![1, 2, 4, 8, 16, 30, 30, 30]);
    assert_eq!(recovery.relist_backoff_secs(), 30);

    // A successful replacement snapshot is the only path that resets pacing.
    assert_eq!(
        recovery.on_valid_snapshot(),
        NodeWatchCacheDecision::CommitSnapshot,
    );
    assert_eq!(recovery.relist_backoff_secs(), 1);
    assert_eq!(
        recovery.on_invalid_snapshot(IngressTopologyReason::NodeTopologyIncomplete),
        NodeWatchCacheDecision::ForceRelist { backoff_secs: 1 },
    );
}

#[test]
fn ended_node_watch_forces_a_paced_fresh_snapshot() {
    let mut recovery = NodeWatchCacheRecovery::new();
    assert_eq!(
        recovery.on_stream_end(),
        NodeWatchCacheDecision::ForceRelist { backoff_secs: 1 },
    );
    assert_eq!(
        recovery.invalid_reason(),
        Some(IngressTopologyReason::KubernetesUnavailable),
    );
    assert_eq!(
        recovery.on_incremental(),
        NodeWatchCacheDecision::SuppressIncremental {
            reason: IngressTopologyReason::KubernetesUnavailable,
        },
    );
    assert_eq!(
        recovery.on_stream_end(),
        NodeWatchCacheDecision::ForceRelist { backoff_secs: 2 },
    );

    assert_eq!(
        recovery.on_valid_snapshot(),
        NodeWatchCacheDecision::CommitSnapshot,
    );
    assert_eq!(recovery.relist_backoff_secs(), 1);
}
