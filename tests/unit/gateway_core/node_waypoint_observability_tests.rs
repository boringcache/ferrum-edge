//! Unit coverage for NodeWaypoint ADR observability counters (issue #3334).

use ferrum_edge::modes::mesh::node_waypoint_observability::{
    self, NodeWaypointAssertedIdentityRejectReason, NodeWaypointDestinationPolicyRejectReason,
    NodeWaypointHboneHandshakePhase,
};
use ferrum_edge::plugins::prometheus_metrics::MetricsRegistry;

#[test]
fn reason_enums_expose_stable_label_strings() {
    assert_eq!(
        NodeWaypointHboneHandshakePhase::InboundTls.as_str(),
        "inbound_tls"
    );
    assert_eq!(
        NodeWaypointHboneHandshakePhase::InboundConnect.as_str(),
        "inbound_connect"
    );
    assert_eq!(
        NodeWaypointHboneHandshakePhase::OutboundDial.as_str(),
        "outbound_dial"
    );
    assert_eq!(
        NodeWaypointAssertedIdentityRejectReason::UntrustedAssertor.as_str(),
        "untrusted_assertor"
    );
    assert_eq!(
        NodeWaypointDestinationPolicyRejectReason::AuthzDeny.as_str(),
        "authz_deny"
    );
}

#[test]
fn disabled_producers_do_not_increment() {
    node_waypoint_observability::set_enabled(false);
    let before = node_waypoint_observability::snapshot();

    node_waypoint_observability::record_hbone_handshake(
        NodeWaypointHboneHandshakePhase::InboundTls,
        false,
    );
    node_waypoint_observability::record_asserted_identity_accepted();
    node_waypoint_observability::record_missing_destination_metadata();
    node_waypoint_observability::record_plaintext_fallback_attempt();

    let after = node_waypoint_observability::snapshot();
    assert_eq!(after.hbone_handshakes, before.hbone_handshakes);
    assert_eq!(after.asserted_identity, before.asserted_identity);
    assert_eq!(
        after.missing_destination_metadata,
        before.missing_destination_metadata
    );
    assert_eq!(
        after.plaintext_fallback_attempts,
        before.plaintext_fallback_attempts
    );
    assert!(!after.enabled);
}

#[test]
fn enabled_producers_increment_and_render_bounded_labels() {
    node_waypoint_observability::set_enabled(true);
    let before = node_waypoint_observability::snapshot();

    node_waypoint_observability::record_hbone_handshake(
        NodeWaypointHboneHandshakePhase::InboundTls,
        true,
    );
    node_waypoint_observability::record_hbone_handshake(
        NodeWaypointHboneHandshakePhase::InboundTls,
        false,
    );
    node_waypoint_observability::record_hbone_handshake(
        NodeWaypointHboneHandshakePhase::InboundConnect,
        true,
    );
    node_waypoint_observability::record_hbone_handshake(
        NodeWaypointHboneHandshakePhase::OutboundDial,
        false,
    );
    node_waypoint_observability::record_asserted_identity_accepted();
    node_waypoint_observability::record_asserted_identity_rejected(
        NodeWaypointAssertedIdentityRejectReason::UntrustedAssertor,
    );
    node_waypoint_observability::record_destination_policy_rejection(
        NodeWaypointDestinationPolicyRejectReason::AuthzDeny,
    );
    node_waypoint_observability::record_missing_destination_metadata();
    node_waypoint_observability::record_plaintext_fallback_attempt();

    let after = node_waypoint_observability::snapshot();
    assert!(after.enabled);
    assert_eq!(
        after.hbone_handshakes.inbound_tls_success,
        before.hbone_handshakes.inbound_tls_success + 1
    );
    assert_eq!(
        after.hbone_handshakes.inbound_tls_failure,
        before.hbone_handshakes.inbound_tls_failure + 1
    );
    assert_eq!(
        after.hbone_handshakes.inbound_connect_success,
        before.hbone_handshakes.inbound_connect_success + 1
    );
    assert_eq!(
        after.hbone_handshakes.outbound_dial_failure,
        before.hbone_handshakes.outbound_dial_failure + 1
    );
    assert_eq!(
        after.asserted_identity.accepted,
        before.asserted_identity.accepted + 1
    );
    assert_eq!(
        after.asserted_identity.rejected_untrusted_assertor,
        before.asserted_identity.rejected_untrusted_assertor + 1
    );
    assert_eq!(
        after.destination_policy_rejections.authz_deny,
        before.destination_policy_rejections.authz_deny + 1
    );
    assert_eq!(
        after.missing_destination_metadata,
        before.missing_destination_metadata + 1
    );
    assert_eq!(
        after.plaintext_fallback_attempts,
        before.plaintext_fallback_attempts + 1
    );

    let registry = MetricsRegistry::new();
    let output = registry.render();
    assert!(output.contains("# TYPE ferrum_mesh_node_waypoint_hbone_handshakes_total counter"));
    assert!(output.contains(
        "ferrum_mesh_node_waypoint_hbone_handshakes_total{phase=\"inbound_tls\",result=\"failure\"}"
    ));
    assert!(output.contains("# TYPE ferrum_mesh_node_waypoint_asserted_identity_total counter"));
    assert!(output.contains(
        "ferrum_mesh_node_waypoint_asserted_identity_total{result=\"rejected\",reason=\"untrusted_assertor\"}"
    ));
    assert!(
        output.contains(
            "# TYPE ferrum_mesh_node_waypoint_destination_policy_rejections_total counter"
        )
    );
    assert!(
        output.contains(
            "# TYPE ferrum_mesh_node_waypoint_missing_destination_metadata_total counter"
        )
    );
    assert!(
        output
            .contains("# TYPE ferrum_mesh_node_waypoint_plaintext_fallback_attempts_total counter")
    );
    // Cardinality contract: no identity/IP/URL label keys.
    for forbidden in [
        "spiffe_id=",
        "pod=",
        "workload=",
        "service=",
        "node=",
        "url=",
        "remote=",
    ] {
        assert!(
            !output
                .lines()
                .filter(|line| line.contains("ferrum_mesh_node_waypoint_"))
                .any(|line| line.contains(forbidden)),
            "forbidden label key {forbidden} in NodeWaypoint ADR metrics"
        );
    }

    // Leave enabled for other tests that may race in parallel; producers are
    // additive and snapshots compare deltas.
}

/// `/metrics` must observe NodeWaypoint ADR counter movement even when the
/// MetricsRegistry render cache would otherwise serve a body generated before
/// the increment (default TTL is 5s; the live harness scrapes before/after
/// within that window).
#[test]
fn node_waypoint_inbound_tls_failure_bypasses_metrics_render_cache() {
    node_waypoint_observability::set_enabled(true);
    let registry = MetricsRegistry::new();
    // Keep the registry body cached across the producer increment.
    registry.configure(5, 3600, 60_000, "ferrum");

    let before_output = registry.render();
    let before_failure = prometheus_counter_value(
        &before_output,
        "ferrum_mesh_node_waypoint_hbone_handshakes_total{phase=\"inbound_tls\",result=\"failure\"}",
    );

    node_waypoint_observability::record_hbone_handshake(
        NodeWaypointHboneHandshakePhase::InboundTls,
        false,
    );

    let after_output = registry.render();
    let after_failure = prometheus_counter_value(
        &after_output,
        "ferrum_mesh_node_waypoint_hbone_handshakes_total{phase=\"inbound_tls\",result=\"failure\"}",
    );
    assert_eq!(
        after_failure,
        before_failure + 1,
        "cached /metrics render must still reflect a fresh inbound_tls failure"
    );
}

fn prometheus_counter_value(output: &str, series_prefix: &str) -> u64 {
    for line in output.lines() {
        if line.starts_with('#') || !line.starts_with(series_prefix) {
            continue;
        }
        let Some(value) = line.rsplit_once(' ').map(|(_, v)| v) else {
            continue;
        };
        if let Ok(parsed) = value.parse::<u64>() {
            return parsed;
        }
    }
    0
}

#[test]
fn handshake_phase_ownership_is_independent() {
    node_waypoint_observability::set_enabled(true);
    let before = node_waypoint_observability::snapshot();

    // One TLS failure must not also bump inbound_connect.
    node_waypoint_observability::record_hbone_handshake(
        NodeWaypointHboneHandshakePhase::InboundTls,
        false,
    );
    let after_tls = node_waypoint_observability::snapshot();
    assert_eq!(
        after_tls.hbone_handshakes.inbound_tls_failure,
        before.hbone_handshakes.inbound_tls_failure + 1
    );
    assert_eq!(
        after_tls.hbone_handshakes.inbound_connect_failure,
        before.hbone_handshakes.inbound_connect_failure
    );

    // One CONNECT failure must not also bump inbound_tls.
    node_waypoint_observability::record_hbone_handshake(
        NodeWaypointHboneHandshakePhase::InboundConnect,
        false,
    );
    let after_connect = node_waypoint_observability::snapshot();
    assert_eq!(
        after_connect.hbone_handshakes.inbound_connect_failure,
        before.hbone_handshakes.inbound_connect_failure + 1
    );
    assert_eq!(
        after_connect.hbone_handshakes.inbound_tls_failure,
        after_tls.hbone_handshakes.inbound_tls_failure
    );
}
