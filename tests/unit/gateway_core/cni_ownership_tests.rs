//! External coverage for durable Ferrum CNI GC ownership (#3225 repair).
//!
//! Focuses on the node-local ownership store: socket-bound path identity,
//! crash-safe round-trip of cleanup snapshots, fail-closed rejection of
//! malformed / hostile durable state, TOCTOU-safe regular-file loads, and
//! encoder uniqueness for `(container_id, ifname)` without echoing
//! attacker-controlled identifiers.

use std::net::Ipv4Addr;
use std::path::PathBuf;

use ferrum_edge::cni::ownership::{
    CNI_OWNERSHIP_STORE_FILENAME_PREFIX, CNI_OWNERSHIP_STORE_FILENAME_SUFFIX,
    DurableCniCleanupSnapshot, DurableCniOwnershipRecord, MAX_CNI_OWNERSHIP_STORE_BYTES,
    configure_cni_ownership_store, load_durable_cni_ownership, ownership_store_id_for_socket,
    ownership_store_path_for_socket, parse_durable_cni_ownership_bytes,
    reset_cni_ownership_store_for_tests, store_durable_cni_ownership,
};
use ferrum_edge::cni::spec::MAX_CNI_ATTACHMENT_FIELD_BYTES;

fn sample_cleanup() -> DurableCniCleanupSnapshot {
    DurableCniCleanupSnapshot {
        attached: true,
        pod_ip: Some(Ipv4Addr::new(10, 0, 0, 9)),
        pod_ip6: None,
        include_ports_cgroup_ids: vec![11],
        workload_identity_cgroup_ids: vec![22],
        node_probe_ports: vec![8080],
        inbound_redirect_ports: vec![80],
    }
}

#[test]
fn ownership_store_path_is_bound_to_exact_socket_path_identity() {
    let a = ownership_store_path_for_socket("/var/run/ferrum/node-agent-cni.sock")
        .expect("socket parent");
    let b =
        ownership_store_path_for_socket("/var/run/ferrum/other-cni.sock").expect("socket parent");
    assert_ne!(
        a, b,
        "distinct sockets in the same parent must not share a durable store file"
    );
    assert_eq!(a.parent(), b.parent());
    let id_a = ownership_store_id_for_socket("/var/run/ferrum/node-agent-cni.sock").expect("id");
    assert!(
        a.file_name().and_then(|n| n.to_str()).is_some_and(|name| {
            name.starts_with(CNI_OWNERSHIP_STORE_FILENAME_PREFIX)
                && name.ends_with(CNI_OWNERSHIP_STORE_FILENAME_SUFFIX)
                && name.contains(&id_a)
                && !name.contains("node-agent-cni.sock")
        }),
        "store filename must embed a digest identity without raw socket path bytes: {a:?}"
    );
    assert_eq!(
        a,
        PathBuf::from("/var/run/ferrum").join(format!(
            "{CNI_OWNERSHIP_STORE_FILENAME_PREFIX}{id_a}{CNI_OWNERSHIP_STORE_FILENAME_SUFFIX}"
        ))
    );
    assert!(ownership_store_path_for_socket("").is_none());
    assert!(ownership_store_path_for_socket("node-agent-cni.sock").is_none());
}

#[test]
fn durable_ownership_round_trip_persists_cleanup_snapshot() {
    reset_cni_ownership_store_for_tests();
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("cni-owned-attachments.test.v2");
    let records = vec![
        DurableCniOwnershipRecord {
            network_name: "ferrum-mesh".into(),
            container_id: "ctr-a".into(),
            ifname: "eth0".into(),
            pod_uid: "pod-uid-1".into(),
            cleanup: sample_cleanup(),
        },
        DurableCniOwnershipRecord {
            network_name: "ferrum-mesh".into(),
            container_id: "ctr-b".into(),
            ifname: "eth1".into(),
            pod_uid: "pod-uid-2".into(),
            cleanup: DurableCniCleanupSnapshot {
                attached: false,
                pod_ip: None,
                pod_ip6: None,
                include_ports_cgroup_ids: Vec::new(),
                workload_identity_cgroup_ids: Vec::new(),
                node_probe_ports: Vec::new(),
                inbound_redirect_ports: Vec::new(),
            },
        },
    ];
    store_durable_cni_ownership(&path, &records).expect("store");
    let loaded = load_durable_cni_ownership(&path).expect("load");
    assert_eq!(loaded, records);
    assert!(loaded[0].cleanup.attached);
    assert_eq!(loaded[0].cleanup.pod_ip, Some(Ipv4Addr::new(10, 0, 0, 9)));
    assert_eq!(loaded[0].cleanup.include_ports_cgroup_ids, vec![11]);
    assert_eq!(loaded[0].cleanup.workload_identity_cgroup_ids, vec![22]);
    assert_eq!(loaded[0].cleanup.node_probe_ports, vec![8080]);
    assert_eq!(loaded[0].cleanup.inbound_redirect_ports, vec![80]);

    // Missing file is empty ownership, not an error.
    let missing = dir.path().join("missing.v2");
    assert!(
        load_durable_cni_ownership(&missing)
            .expect("missing")
            .is_empty()
    );

    configure_cni_ownership_store(Some(path));
    reset_cni_ownership_store_for_tests();
}

#[test]
fn encoder_rejects_duplicate_attachment_identity() {
    let dup = vec![
        DurableCniOwnershipRecord {
            network_name: "ferrum-mesh".into(),
            container_id: "ctr-a".into(),
            ifname: "eth0".into(),
            pod_uid: "pod-uid-1".into(),
            cleanup: sample_cleanup(),
        },
        DurableCniOwnershipRecord {
            network_name: "ferrum-mesh".into(),
            container_id: "ctr-a".into(),
            ifname: "eth0".into(),
            pod_uid: "pod-uid-2".into(),
            cleanup: sample_cleanup(),
        },
    ];
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("dup.v2");
    let err = store_durable_cni_ownership(&path, &dup).expect_err("duplicate");
    assert!(
        err.to_string().contains("invalid"),
        "duplicate attachment identity must fail closed, got: {err}"
    );
    assert!(
        !path.exists(),
        "failed encode must not leave a durable file"
    );
}

#[test]
fn ownership_identity_is_network_scoped_and_shared_pod_cleanup_must_agree() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("network-scoped.v2");
    let mut second_network = DurableCniOwnershipRecord {
        network_name: "network-b".into(),
        container_id: "ctr-a".into(),
        ifname: "eth0".into(),
        pod_uid: "pod-uid-1".into(),
        cleanup: sample_cleanup(),
    };
    let records = vec![
        DurableCniOwnershipRecord {
            network_name: "network-a".into(),
            ..second_network.clone()
        },
        second_network.clone(),
    ];
    store_durable_cni_ownership(&path, &records)
        .expect("the same attachment tuple in distinct networks is not a duplicate");
    assert_eq!(
        load_durable_cni_ownership(&path)
            .expect("load network-scoped claims")
            .len(),
        2
    );

    second_network.cleanup.node_probe_ports.push(9090);
    let inconsistent = vec![records[0].clone(), second_network];
    let err = store_durable_cni_ownership(&path, &inconsistent)
        .expect_err("one pod cannot carry conflicting cleanup authority");
    assert!(err.to_string().contains("invalid"));
}

#[test]
fn malformed_oversized_and_hostile_durable_state_fail_closed_without_echo() {
    let oversized_id = "a".repeat(MAX_CNI_ATTACHMENT_FIELD_BYTES + 1);
    let oversized = format!(
        "{{\"version\":2,\"attachments\":[{{\"network_name\":\"ferrum-mesh\",\"container_id\":\"{oversized_id}\",\"ifname\":\"eth0\",\"pod_uid\":\"uid\",\"cleanup\":{{\"attached\":true}}}}]}}"
    );
    let err = parse_durable_cni_ownership_bytes(oversized.as_bytes()).expect_err("reject");
    assert!(!err.to_string().contains(&oversized_id));

    let path_like = br#"{"version":2,"attachments":[{"network_name":"ferrum-mesh","container_id":"../escape","ifname":"eth0","pod_uid":"uid","cleanup":{"attached":true}}]}"#;
    let err = parse_durable_cni_ownership_bytes(path_like).expect_err("reject");
    assert!(!err.to_string().contains("../escape"));

    let truncated = br#"{"version":2,"attachments":[{"container_id":"ctr""#;
    assert!(parse_durable_cni_ownership_bytes(truncated).is_err());

    let legacy_v1 =
        br#"{"version":1,"attachments":[{"container_id":"ctr","ifname":"eth0","pod_uid":"uid"}]}"#;
    assert!(
        parse_durable_cni_ownership_bytes(legacy_v1).is_err(),
        "replaced schema must fail closed on legacy identity-only documents"
    );

    let too_big = vec![b'x'; MAX_CNI_OWNERSHIP_STORE_BYTES + 1];
    let err = parse_durable_cni_ownership_bytes(&too_big).expect_err("size");
    assert!(err.to_string().contains("size") || err.to_string().contains("cap"));
}

#[cfg(unix)]
#[test]
fn symlinked_durable_ownership_store_is_rejected() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join("target");
    std::fs::write(&target, b"{}").expect("seed");
    let path = dir.path().join("cni-owned-attachments.link.v2");
    symlink(&target, &path).expect("symlink");
    let err = load_durable_cni_ownership(&path).expect_err("symlink");
    assert!(
        err.to_string().contains("symlink") || err.to_string().contains("non-regular"),
        "expected symlink rejection, got: {err}"
    );
}

#[cfg(unix)]
#[test]
fn hard_linked_durable_ownership_store_is_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("cni-owned-attachments.hl.v2");
    let records = vec![DurableCniOwnershipRecord {
        network_name: "ferrum-mesh".into(),
        container_id: "ctr-a".into(),
        ifname: "eth0".into(),
        pod_uid: "pod-uid-1".into(),
        cleanup: sample_cleanup(),
    }];
    store_durable_cni_ownership(&path, &records).expect("store");
    let link = dir.path().join("hardlink.v2");
    std::fs::hard_link(&path, &link).expect("hardlink");
    let write_err = store_durable_cni_ownership(&path, &records).expect_err("hardlink write");
    assert!(
        write_err.to_string().contains("hard-linked")
            || write_err.to_string().contains("non-regular"),
        "expected hard-link write rejection, got: {write_err}"
    );
    let err = load_durable_cni_ownership(&path).expect_err("hardlink");
    assert!(
        err.to_string().contains("hard-linked") || err.to_string().contains("non-regular"),
        "expected hard-link rejection, got: {err}"
    );
}
