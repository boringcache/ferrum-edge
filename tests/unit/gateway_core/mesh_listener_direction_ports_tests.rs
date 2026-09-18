//! Mesh listener direction/port validation (PR #5595). The request direction
//! gate is the security boundary; startup also refuses ambiguous TCP scopes.

use ferrum_edge::config::{EnvConfig, OperatingMode};
use ferrum_edge::modes::mesh::{MeshListenerKind, MeshRuntimeConfig, MeshTrafficDirection};

use crate::unit::env_lock::EnvGuard;

fn mesh_env_config() -> EnvConfig {
    EnvConfig {
        mode: OperatingMode::Mesh,
        dp_cp_grpc_urls: vec!["http://127.0.0.1:1".to_string()],
        ..EnvConfig::default()
    }
}

const INBOUND_SETTINGS: &[(&str, &str)] = &[
    ("sidecar", "FERRUM_MESH_INBOUND_LISTEN_ADDR"),
    ("ambient", "FERRUM_MESH_HBONE_LISTEN_ADDR"),
];

#[test]
fn mesh_runtime_rejects_equal_tcp_ports_on_different_addresses() {
    let env = EnvGuard::new(&[]);
    for &(topology, inbound_setting) in INBOUND_SETTINGS {
        env.set("FERRUM_MESH_TOPOLOGY", topology);
        env.set(inbound_setting, "10.0.0.5:15008");
        env.set("FERRUM_MESH_OUTBOUND_LISTEN_ADDR", "127.0.0.1:15008");
        let error = MeshRuntimeConfig::from_env_config(&mesh_env_config())
            .expect_err("distinct addresses must not hide an inbound/outbound port collision");
        assert_eq!(
            error,
            format!(
                "`{inbound_setting}` (\"10.0.0.5:15008\") must use a different TCP port number from \
                 `FERRUM_MESH_OUTBOUND_LISTEN_ADDR` (\"127.0.0.1:15008\"); both use port \"15008\""
            )
        );
        env.unset(inbound_setting);
    }
}

#[test]
fn mesh_runtime_accepts_disjoint_tcp_ports() {
    let env = EnvGuard::new(&[]);
    for &(topology, inbound_setting) in INBOUND_SETTINGS {
        env.set("FERRUM_MESH_TOPOLOGY", topology);
        env.set(inbound_setting, "10.0.0.5:15008");
        env.set("FERRUM_MESH_OUTBOUND_LISTEN_ADDR", "127.0.0.1:15001");
        let runtime = MeshRuntimeConfig::from_env_config(&mesh_env_config())
            .expect("disjoint port numbers must pass runtime admission");
        runtime.validate_listener_direction_ports().unwrap();
        env.unset(inbound_setting);
    }
}

#[test]
fn mesh_runtime_allows_udp_capture_on_an_inbound_tcp_port() {
    let env = EnvGuard::new(&[]);
    env.set("FERRUM_MESH_TOPOLOGY", "sidecar");
    env.set("FERRUM_MESH_CAPTURE_UDP_ENABLED", "true");
    env.set("FERRUM_MESH_CAPTURE_UDP_PORT", "15006");
    let runtime = MeshRuntimeConfig::from_env_config(&mesh_env_config())
        .expect("UDP capture can share an inbound TCP port number");
    let plan = runtime.listener_plan();
    assert!(plan.iter().any(|listener| {
        listener.direction == MeshTrafficDirection::Outbound
            && listener.kind == MeshListenerKind::PlaintextUdpCapture
            && listener.addr.port() == 15006
    }));
    assert!(plan.iter().any(|listener| {
        listener.direction == MeshTrafficDirection::Inbound
            && listener.kind == MeshListenerKind::MtlsTermination
            && listener.addr.port() == 15006
    }));
    runtime.validate_listener_direction_ports().unwrap();
}

#[test]
fn mesh_runtime_direction_port_validation_ignores_zero() {
    let env = EnvGuard::new(&[]);
    for &(topology, inbound_setting) in INBOUND_SETTINGS {
        env.set("FERRUM_MESH_TOPOLOGY", topology);
        for (inbound_port, outbound_port) in [(0, 0), (0, 15008), (15008, 0)] {
            env.set(inbound_setting, &format!("10.0.0.5:{inbound_port}"));
            env.set(
                "FERRUM_MESH_OUTBOUND_LISTEN_ADDR",
                &format!("127.0.0.1:{outbound_port}"),
            );
            let runtime = MeshRuntimeConfig::from_env_config(&mesh_env_config())
                .expect("port zero is not an overlapping TCP scope");
            runtime.validate_listener_direction_ports().unwrap();
        }
        env.unset(inbound_setting);
    }
}

#[test]
fn mesh_runtime_checks_only_listeners_in_the_topology_plan() {
    let env = EnvGuard::new(&[]);
    env.set("FERRUM_MESH_TOPOLOGY", "node_waypoint");
    env.set("FERRUM_MESH_HBONE_LISTEN_ADDR", "10.0.0.5:15008");
    env.set("FERRUM_MESH_OUTBOUND_LISTEN_ADDR", "127.0.0.1:15008");
    let runtime = MeshRuntimeConfig::from_env_config(&mesh_env_config())
        .expect("no outbound TCP listener exists in this topology plan");
    assert!(
        runtime
            .listener_plan()
            .iter()
            .all(|listener| listener.direction == MeshTrafficDirection::Inbound)
    );
    runtime.validate_listener_direction_ports().unwrap();
}

#[test]
fn mesh_direction_port_validation_covers_validate_and_direct_serving() {
    let cli = include_str!("../../../src/cli.rs");
    assert!(cli.contains("MeshRuntimeConfig::from_env_config(&env_config)"));
    let mesh = include_str!("../../../src/modes/mesh/mod.rs");
    let construction = mesh
        .split_once("pub fn from_env_config(env_config: &EnvConfig)")
        .unwrap()
        .1
        .split_once("fn native_client_config(")
        .unwrap()
        .0;
    assert!(construction.contains("runtime.validate_listener_direction_ports()?;"));
    let preparation = mesh
        .split_once("fn prepare_mesh_runtime_before_owner(")
        .unwrap()
        .1;
    let gate = preparation
        .find(".validate_listener_direction_ports()")
        .unwrap();
    let resources = preparation.find("let dns_cache =").unwrap();
    assert!(
        gate < resources,
        "direct serving must validate before acquiring resources"
    );
}
