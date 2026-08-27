//! Kubernetes controller diagnostic metrics (#4239).
//!
//! Route parent-status publication latency is measured from the object's
//! Kubernetes `creationTimestamp` to a successful Ferrum status patch. kube-rs
//! does not expose a watch-event timestamp, so this is the wait the Gateway API
//! conformance suite observes rather than a reflector-observation clock.

use std::sync::atomic::Ordering;

use ferrum_edge::k8s_controller::metrics::{
    ControllerMetrics, record_route_status_publication, route_status_publish_latency_ms,
};

#[test]
fn route_status_publish_latency_is_creation_to_publish() {
    // 1970-01-01T00:00:00Z is unix epoch, so published_unix_ms is the latency.
    assert_eq!(
        route_status_publish_latency_ms(Some("1970-01-01T00:00:00Z"), 60_020),
        Some(60_020)
    );
}

#[test]
fn route_status_publish_latency_skips_missing_or_invalid_timestamps() {
    assert_eq!(route_status_publish_latency_ms(None, 1_000), None);
    assert_eq!(
        route_status_publish_latency_ms(Some("not-rfc3339"), 1_000),
        None
    );
}

#[test]
fn route_status_publish_latency_saturates_when_publish_is_before_create() {
    assert_eq!(
        route_status_publish_latency_ms(Some("1970-01-01T00:01:00Z"), 0),
        Some(0)
    );
}

#[test]
fn record_route_status_publication_ignores_non_route_kinds() {
    let metrics = ControllerMetrics::new();
    record_route_status_publication(
        &metrics,
        "Gateway",
        "ns",
        "edge",
        Some("1970-01-01T00:00:00Z"),
        60_020,
    );
    assert_eq!(
        metrics.route_status_publications.load(Ordering::Relaxed),
        0
    );
    assert_eq!(
        metrics
            .last_route_status_publish_latency_ms
            .load(Ordering::Relaxed),
        0
    );
}

#[test]
fn record_route_status_publication_stores_latency_and_counts() {
    let metrics = ControllerMetrics::new();
    record_route_status_publication(
        &metrics,
        "HTTPRoute",
        "gateway-conformance-infra",
        "invalid-backendref-unknown-kind",
        Some("1970-01-01T00:00:00Z"),
        60_020,
    );
    let snap = metrics.snapshot();
    assert_eq!(snap.route_status_publications, 1);
    assert_eq!(snap.last_route_status_publish_latency_ms, 60_020);
}

#[test]
fn record_route_status_publication_counts_even_without_creation_timestamp() {
    let metrics = ControllerMetrics::new();
    record_route_status_publication(&metrics, "TCPRoute", "ns", "echo", None, 1);
    assert_eq!(
        metrics.route_status_publications.load(Ordering::Relaxed),
        1
    );
    assert_eq!(
        metrics
            .last_route_status_publish_latency_ms
            .load(Ordering::Relaxed),
        0
    );
}
