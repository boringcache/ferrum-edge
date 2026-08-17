//! NodeWaypoint UDP listener proxy/upstream id encoding (issues #3286/#3861).
//!
//! Generated listeners are inserted in one runtime namespace, so a lossy
//! `{namespace}-{name}-{port}` join would let `a-b/c` overwrite `a/b-c` at the
//! same port. These ids are forward-only: they are never parsed back.

use ferrum_edge::modes::mesh::{
    MESH_NODE_WAYPOINT_UDP_PROXY_ID_PREFIX, MESH_NODE_WAYPOINT_UDP_UPSTREAM_ID_PREFIX,
    is_node_waypoint_udp_listener_id, node_waypoint_udp_proxy_id, node_waypoint_udp_upstream_id,
};

const MAX_ID_LENGTH: usize = 254;
const K8S_IDENTITY_MAX_BYTES: usize = 63;

fn proxy_id(namespace: &str, name: &str, port: u16) -> String {
    node_waypoint_udp_proxy_id(namespace, name, port)
        .expect("admitted Kubernetes namespace/service identity")
}

fn upstream_id(namespace: &str, name: &str, port: u16) -> String {
    node_waypoint_udp_upstream_id(namespace, name, port)
        .expect("admitted Kubernetes namespace/service identity")
}

fn assert_id_safe(id: &str, prefix: &str) {
    assert!(
        id.starts_with(prefix),
        "generated id must keep its reserved prefix: {id}"
    );
    assert!(
        id.len() <= MAX_ID_LENGTH,
        "generated id must fit the resource-id ceiling: {} bytes",
        id.len()
    );
    assert!(
        id.chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-')),
        "generated id must stay inside the validate_resource_id alphabet: {id}"
    );
    // Reserved mesh prefixes start with `_`, so the full id is trusted rather
    // than operator-authored. The encoded payload after the prefix must still
    // be a valid continuation of that grammar (unpadded URL-safe base64).
    let payload = &id[prefix.len()..];
    assert!(
        !payload.is_empty(),
        "encoded identity payload must not be empty"
    );
    assert!(
        payload
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_')),
        "encoded payload must be unpadded URL-safe base64: {payload}"
    );
}

#[test]
fn hyphenated_service_tuples_generate_distinct_proxy_and_upstream_ids() {
    let proxy_ab_c = proxy_id("a-b", "c", 5353);
    let proxy_a_bc = proxy_id("a", "b-c", 5353);
    let upstream_ab_c = upstream_id("a-b", "c", 5353);
    let upstream_a_bc = upstream_id("a", "b-c", 5353);

    let lossy = |namespace: &str, name: &str, port: u16| {
        format!("__mesh-nw-udp-{namespace}-{name}-{port}").replace(['/', '.'], "-")
    };
    assert_eq!(
        lossy("a-b", "c", 5353),
        lossy("a", "b-c", 5353),
        "the previous hyphen join is the collision this encoding exists to close"
    );

    assert_ne!(proxy_ab_c, proxy_a_bc);
    assert_ne!(upstream_ab_c, upstream_a_bc);
    assert_ne!(proxy_ab_c, upstream_ab_c);
    assert_ne!(proxy_a_bc, upstream_a_bc);
    assert_ne!(
        proxy_id("a/b", "c", 5353),
        proxy_id("a-b", "c", 5353),
        "slash folding must not recreate the hyphen collision class"
    );

    assert_id_safe(&proxy_ab_c, MESH_NODE_WAYPOINT_UDP_PROXY_ID_PREFIX);
    assert_id_safe(&proxy_a_bc, MESH_NODE_WAYPOINT_UDP_PROXY_ID_PREFIX);
    assert_id_safe(&upstream_ab_c, MESH_NODE_WAYPOINT_UDP_UPSTREAM_ID_PREFIX);
    assert_id_safe(&upstream_a_bc, MESH_NODE_WAYPOINT_UDP_UPSTREAM_ID_PREFIX);

    assert!(is_node_waypoint_udp_listener_id(&proxy_ab_c));
    assert!(is_node_waypoint_udp_listener_id(&proxy_a_bc));
    assert!(
        !is_node_waypoint_udp_listener_id("ordinary-udp"),
        "listener detection is an exact reserved prefix, never a parse of tenant names"
    );
}

#[test]
fn admitted_kubernetes_identities_fit_the_resource_id_ceiling() {
    let namespace = "n".repeat(K8S_IDENTITY_MAX_BYTES);
    let name = "s".repeat(K8S_IDENTITY_MAX_BYTES);
    let proxy = proxy_id(&namespace, &name, u16::MAX);
    let upstream = upstream_id(&namespace, &name, u16::MAX);
    assert_id_safe(&proxy, MESH_NODE_WAYPOINT_UDP_PROXY_ID_PREFIX);
    assert_id_safe(&upstream, MESH_NODE_WAYPOINT_UDP_UPSTREAM_ID_PREFIX);
    assert_ne!(proxy, upstream);
}

#[test]
fn identities_outside_admitted_bounds_do_not_mint_a_resource() {
    assert!(node_waypoint_udp_proxy_id("", "dns", 5353).is_none());
    assert!(node_waypoint_udp_upstream_id("default", "", 5353).is_none());
    let oversized = "x".repeat(K8S_IDENTITY_MAX_BYTES + 1);
    assert!(node_waypoint_udp_proxy_id(&oversized, "dns", 5353).is_none());
    assert!(node_waypoint_udp_upstream_id("default", &oversized, 5353).is_none());
    // Truncation is forbidden: the 63-byte prefix encodes, the 64-byte name does not.
    let truncated = proxy_id(&oversized[..K8S_IDENTITY_MAX_BYTES], "dns", 5353);
    assert!(!truncated.is_empty());
    assert_ne!(
        node_waypoint_udp_proxy_id(&oversized, "dns", 5353).as_deref(),
        Some(truncated.as_str())
    );
}
