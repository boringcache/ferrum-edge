//! External coverage for durable Ferrum CNI GC ownership (#3225 repair).
//!
//! Focuses on the node-local ownership store: path derivation, crash-safe
//! round-trip, and fail-closed rejection of malformed / hostile durable state
//! without echoing attacker-controlled identifiers.

use std::path::PathBuf;

use ferrum_edge::cni::ownership::{
    CNI_OWNERSHIP_STORE_FILENAME, DurableCniOwnershipRecord, MAX_CNI_OWNERSHIP_STORE_BYTES,
    configure_cni_ownership_store, load_durable_cni_ownership, ownership_store_path_for_socket,
    parse_durable_cni_ownership_bytes, reset_cni_ownership_store_for_tests,
    store_durable_cni_ownership,
};
use ferrum_edge::cni::spec::MAX_CNI_ATTACHMENT_FIELD_BYTES;

#[test]
fn ownership_store_path_is_sibling_of_configured_cni_socket() {
    let path = ownership_store_path_for_socket("/var/run/ferrum/node-agent-cni.sock")
        .expect("socket parent");
    assert_eq!(
        path,
        PathBuf::from("/var/run/ferrum").join(CNI_OWNERSHIP_STORE_FILENAME)
    );
    assert!(ownership_store_path_for_socket("").is_none());
    assert!(ownership_store_path_for_socket("node-agent-cni.sock").is_none());
}

#[test]
fn durable_ownership_round_trip_is_crash_safe_and_bounded() {
    reset_cni_ownership_store_for_tests();
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(CNI_OWNERSHIP_STORE_FILENAME);
    let records = vec![
        DurableCniOwnershipRecord {
            container_id: "ctr-a".into(),
            ifname: "eth0".into(),
            pod_uid: "pod-uid-1".into(),
        },
        DurableCniOwnershipRecord {
            container_id: "ctr-b".into(),
            ifname: "eth1".into(),
            pod_uid: "pod-uid-2".into(),
        },
    ];
    store_durable_cni_ownership(&path, &records).expect("store");
    let loaded = load_durable_cni_ownership(&path).expect("load");
    assert_eq!(loaded, records);

    // Missing file is empty ownership, not an error.
    let missing = dir.path().join("missing.v1");
    assert!(load_durable_cni_ownership(&missing)
        .expect("missing")
        .is_empty());

    configure_cni_ownership_store(Some(path));
    reset_cni_ownership_store_for_tests();
}

#[test]
fn malformed_oversized_and_hostile_durable_state_fail_closed_without_echo() {
    let oversized_id = "a".repeat(MAX_CNI_ATTACHMENT_FIELD_BYTES + 1);
    let oversized = format!(
        "{{\"version\":1,\"attachments\":[{{\"container_id\":\"{oversized_id}\",\"ifname\":\"eth0\",\"pod_uid\":\"uid\"}}]}}"
    );
    let err = parse_durable_cni_ownership_bytes(oversized.as_bytes()).expect_err("reject");
    assert!(!err.to_string().contains(&oversized_id));

    let path_like = br#"{"version":1,"attachments":[{"container_id":"../escape","ifname":"eth0","pod_uid":"uid"}]}"#;
    let err = parse_durable_cni_ownership_bytes(path_like).expect_err("reject");
    assert!(!err.to_string().contains("../escape"));

    let truncated = br#"{"version":1,"attachments":[{"container_id":"ctr""#;
    assert!(parse_durable_cni_ownership_bytes(truncated).is_err());

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
    let path = dir.path().join(CNI_OWNERSHIP_STORE_FILENAME);
    symlink(&target, &path).expect("symlink");
    let err = load_durable_cni_ownership(&path).expect_err("symlink");
    assert!(
        err.to_string().contains("symlink"),
        "expected symlink rejection, got: {err}"
    );
}
