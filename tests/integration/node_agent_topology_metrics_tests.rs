//! Integration coverage for topology validation state through the shared
//! node-agent Prometheus model.

use std::sync::Arc;

use ferrum_edge::ebpf::ingress_topology::{
    IngressTopologyReason, IngressTopologyState, IngressTopologyStatus,
};
use ferrum_edge::ebpf::{
    NODE_AGENT_CAPTURE_STATE_INTERFACE_TOPOLOGY_UNAVAILABLE, NodeAgentMetrics,
};
use ferrum_edge::plugins::prometheus_metrics::MetricsRegistry;

#[test]
fn unavailable_topology_renders_only_closed_labels_and_bounded_counts() {
    let registry = MetricsRegistry::new();
    let metrics = Arc::new(NodeAgentMetrics::default());
    metrics.set_capture_state(NODE_AGENT_CAPTURE_STATE_INTERFACE_TOPOLOGY_UNAVAILABLE);
    metrics.set_ingress_topology(IngressTopologyStatus {
        state: IngressTopologyState::Unavailable,
        reason: IngressTopologyReason::WrongInterface,
        configured_interfaces: 2,
        expected_interfaces: 1,
        ipv4_required: true,
        ipv4_covered: false,
        ipv6_required: true,
        ipv6_covered: false,
    });
    registry.set_node_agent_metrics(metrics);

    let output = registry.render_uncached();
    assert!(
        output.contains(
            "ferrum_node_agent_capture_state{state=\"interface_topology_unavailable\"} 1"
        )
    );
    assert!(output.contains(
        "ferrum_node_agent_ingress_interface_topology{state=\"unavailable\",reason=\"wrong_interface\"} 1"
    ));
    assert!(output.contains("ferrum_node_agent_ingress_interface_configured_count 2"));
    assert!(output.contains("ferrum_node_agent_ingress_interface_expected_count 1"));
    assert!(
        output.contains("ferrum_node_agent_ingress_interface_family_required{family=\"ipv6\"} 1")
    );
    assert!(
        output.contains("ferrum_node_agent_ingress_interface_family_covered{family=\"ipv6\"} 0")
    );
    assert!(!output.contains("eth0"));
    assert!(!output.contains("mgmt0"));
}
