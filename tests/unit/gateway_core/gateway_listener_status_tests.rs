//! Bounded dynamic Gateway API listener realization status (issue #3810).
//!
//! The manager already refuses traffic fail-closed for an unbindable listener
//! port and retries it forever; these tests pin the *observability* contract
//! that turns that into an operator-visible, recoverable, fixed-cardinality
//! signal:
//!
//! * a failure appears with a bounded category, protocol half, and origin;
//! * a repeat observation ages the entry instead of re-counting a new failure;
//! * a recovery clears the entry and counts a recovery;
//! * a stale config generation cannot overwrite the current generation;
//! * the retained set and every detail string are hard-bounded;
//! * the Prometheus surface has fixed cardinality and never carries a port,
//!   config generation, or error text.

use ferrum_edge::proxy::gateway_listener_status::{
    GatewayListenerFailureCategory, GatewayListenerFailureObservation, GatewayListenerFailureOrigin,
    GatewayListenerProtocolHalf, GatewayListenerStatus, MAX_DETAIL_CHARS, MAX_TRACKED_FAILURES,
};

const NS_LABEL: &str = ",namespace=\"ferrum\"";

fn is_printable_ascii(text: &str) -> bool {
    text.chars().all(|ch| ch == ' ' || ch.is_ascii_graphic())
}

fn tcp_bind_failure(port: u16) -> GatewayListenerFailureObservation {
    GatewayListenerFailureObservation::new(
        port,
        GatewayListenerProtocolHalf::Tcp,
        GatewayListenerFailureCategory::BindFailed,
        format!("port {port} bind failed: Address already in use (os error 48)"),
    )
}

fn quic_bind_failure(port: u16) -> GatewayListenerFailureObservation {
    GatewayListenerFailureObservation::new(
        port,
        GatewayListenerProtocolHalf::Quic,
        GatewayListenerFailureCategory::BindFailed,
        format!("port {port} HTTP/3 listener bind failed"),
    )
}

fn cumulative_failures(
    status: &GatewayListenerStatus,
    protocol: GatewayListenerProtocolHalf,
    category: GatewayListenerFailureCategory,
) -> u64 {
    status
        .cumulative()
        .failures_total
        .iter()
        .find(|series| series.protocol == protocol && series.category == category)
        .map_or(0, |series| series.value)
}

fn cumulative_recoveries(
    status: &GatewayListenerStatus,
    protocol: GatewayListenerProtocolHalf,
    category: GatewayListenerFailureCategory,
) -> u64 {
    status
        .cumulative()
        .recoveries_total
        .iter()
        .find(|series| series.protocol == protocol && series.category == category)
        .map_or(0, |series| series.value)
}

/// An occupied TCP port must appear as one bounded, structured, active failure
/// while the healthy listeners on the same generation stay counted as active.
#[test]
fn an_occupied_tcp_port_is_published_as_a_bounded_active_failure() {
    let status = GatewayListenerStatus::new();
    assert!(status.publish(7, 3, 2, vec![tcp_bind_failure(8443)], 1_000));

    let snapshot = status.snapshot();
    assert_eq!(snapshot.config_generation, 7);
    assert_eq!(snapshot.desired_listeners, 3);
    assert_eq!(snapshot.active_listeners, 2);
    assert_eq!(snapshot.failed_ports, 1);
    assert_eq!(snapshot.active_failures, 1);
    assert_eq!(snapshot.retained_failures, 1);
    assert!(!snapshot.truncated);
    assert!(snapshot.degraded());

    let entry = &snapshot.failures[0];
    assert_eq!(entry.port, 8443);
    assert_eq!(entry.protocol, GatewayListenerProtocolHalf::Tcp);
    assert_eq!(entry.category, GatewayListenerFailureCategory::BindFailed);
    assert_eq!(entry.origin, GatewayListenerFailureOrigin::Runtime);
    assert_eq!(entry.config_generation, 7);
    assert_eq!(entry.first_observed_unix_ms, 1_000);
    assert_eq!(entry.last_observed_unix_ms, 1_000);
    assert_eq!(entry.observations, 1);

    assert_eq!(
        cumulative_failures(
            &status,
            GatewayListenerProtocolHalf::Tcp,
            GatewayListenerFailureCategory::BindFailed,
        ),
        1
    );
}

/// A retry that keeps failing is the SAME failure: it ages the entry rather
/// than inflating the cumulative failure counter, so an alert on
/// `increase(ferrum_gateway_listener_failures_total)` reports onsets, not the
/// 30s retry cadence.
#[test]
fn a_repeated_failure_ages_the_entry_without_recounting_the_onset() {
    let status = GatewayListenerStatus::new();
    assert!(status.publish(1, 1, 0, vec![tcp_bind_failure(8443)], 1_000));
    assert!(status.publish(1, 1, 0, vec![tcp_bind_failure(8443)], 31_000));
    assert!(status.publish(1, 1, 0, vec![tcp_bind_failure(8443)], 61_000));

    let snapshot = status.snapshot();
    assert_eq!(snapshot.active_failures, 1);
    let entry = &snapshot.failures[0];
    assert_eq!(entry.first_observed_unix_ms, 1_000);
    assert_eq!(entry.last_observed_unix_ms, 61_000);
    assert_eq!(entry.observations, 3);

    assert_eq!(
        cumulative_failures(
            &status,
            GatewayListenerProtocolHalf::Tcp,
            GatewayListenerFailureCategory::BindFailed,
        ),
        1,
        "a still-failing retry must not count as a new failure"
    );
    assert_eq!(
        cumulative_recoveries(
            &status,
            GatewayListenerProtocolHalf::Tcp,
            GatewayListenerFailureCategory::BindFailed,
        ),
        0
    );
}

/// Releasing the port clears the active failure on the next reconcile and
/// counts a recovery. This is the whole reason the status is separate from the
/// sticky `serving_listener_failures` surface.
#[test]
fn a_recovered_listener_clears_the_active_failure_and_counts_a_recovery() {
    let status = GatewayListenerStatus::new();
    assert!(status.publish(1, 1, 0, vec![tcp_bind_failure(8443)], 1_000));
    assert!(status.snapshot().degraded());

    assert!(status.publish(1, 1, 1, Vec::new(), 31_000));

    let snapshot = status.snapshot();
    assert!(!snapshot.degraded(), "recovery must clear the active failure");
    assert_eq!(snapshot.active_failures, 0);
    assert_eq!(snapshot.failed_ports, 0);
    assert_eq!(snapshot.active_listeners, 1);
    assert!(snapshot.failures.is_empty());
    assert!(snapshot.active_by_category.is_empty());

    assert_eq!(
        cumulative_recoveries(
            &status,
            GatewayListenerProtocolHalf::Tcp,
            GatewayListenerFailureCategory::BindFailed,
        ),
        1
    );
    assert_eq!(
        cumulative_failures(
            &status,
            GatewayListenerProtocolHalf::Tcp,
            GatewayListenerFailureCategory::BindFailed,
        ),
        1,
        "the cumulative failure counter is monotonic across a recovery"
    );

    // A later relapse is a NEW onset.
    assert!(status.publish(1, 1, 0, vec![tcp_bind_failure(8443)], 61_000));
    assert_eq!(
        cumulative_failures(
            &status,
            GatewayListenerProtocolHalf::Tcp,
            GatewayListenerFailureCategory::BindFailed,
        ),
        2
    );
    assert_eq!(status.snapshot().failures[0].first_observed_unix_ms, 61_000);
}

/// A reconcile pass that awaited socket retirement can finish after a newer
/// config generation was published. Its decision must be dropped whole — no
/// snapshot replacement and no counter movement.
#[test]
fn a_stale_generation_cannot_overwrite_the_current_generation() {
    let status = GatewayListenerStatus::new();
    assert!(status.publish(9, 2, 2, Vec::new(), 1_000));

    let stale = status.publish(8, 1, 0, vec![tcp_bind_failure(8443)], 2_000);
    assert!(!stale, "a stale generation must be refused");

    let snapshot = status.snapshot();
    assert_eq!(snapshot.config_generation, 9);
    assert_eq!(snapshot.active_listeners, 2);
    assert!(!snapshot.degraded());
    assert_eq!(
        cumulative_failures(
            &status,
            GatewayListenerProtocolHalf::Tcp,
            GatewayListenerFailureCategory::BindFailed,
        ),
        0,
        "a refused publication must not move any counter"
    );

    // The same generation is still accepted: the supervisor re-reconciles the
    // current generation on every retry tick, and that is how a recovery lands.
    assert!(status.publish(9, 1, 0, vec![tcp_bind_failure(8443)], 3_000));
    assert!(status.snapshot().degraded());
    // And a newer generation is accepted.
    assert!(status.publish(10, 1, 1, Vec::new(), 4_000));
    assert_eq!(status.snapshot().config_generation, 10);
}

/// The TCP and QUIC halves of one TLS-class listener fail independently. A
/// QUIC-only failure must never read as "this port is unavailable".
#[test]
fn a_quic_only_failure_is_distinguished_from_the_tcp_half() {
    let status = GatewayListenerStatus::new();
    assert!(status.publish(1, 2, 2, vec![quic_bind_failure(8443)], 1_000));

    let snapshot = status.snapshot();
    assert_eq!(snapshot.active_listeners, 2, "the TCP half is still serving");
    assert_eq!(snapshot.active_failures, 1);
    assert_eq!(
        snapshot.failures[0].protocol,
        GatewayListenerProtocolHalf::Quic
    );
    assert_eq!(snapshot.active_by_category.len(), 1);
    assert_eq!(
        snapshot.active_by_category[0].protocol,
        GatewayListenerProtocolHalf::Quic
    );

    let rendered = render(&status);
    let quic_active = "ferrum_gateway_listener_failures_active{protocol=\"quic\",reason=\"bind_failed\",namespace=\"ferrum\"} 1";
    let tcp_active = "ferrum_gateway_listener_failures_active{protocol=\"tcp\",reason=\"bind_failed\",namespace=\"ferrum\"} 0";
    assert!(rendered.contains(quic_active), "{rendered}");
    assert!(rendered.contains(tcp_active), "{rendered}");
}

/// Both halves of the same port are tracked separately and both are reported.
#[test]
fn mixed_healthy_and_failed_listeners_preserve_the_healthy_count() {
    let status = GatewayListenerStatus::new();
    assert!(status.publish(
        4,
        4,
        3,
        vec![
            tcp_bind_failure(8080),
            quic_bind_failure(8443),
            GatewayListenerFailureObservation::new(
                9090,
                GatewayListenerProtocolHalf::Tcp,
                GatewayListenerFailureCategory::StreamPortCollision,
                "port 9090 is claimed by a TCP/TLS stream proxy in the same config",
            ),
        ],
        1_000,
    ));

    let snapshot = status.snapshot();
    assert_eq!(snapshot.active_listeners, 3);
    assert_eq!(snapshot.active_failures, 3);
    assert_eq!(snapshot.failed_ports, 3);
    // Ordered by (port, protocol, category) so the surface is stable.
    let ports: Vec<u16> = snapshot.failures.iter().map(|entry| entry.port).collect();
    assert_eq!(ports, vec![8080, 8443, 9090]);
    assert_eq!(
        snapshot.failures[2].origin,
        GatewayListenerFailureOrigin::Admission,
        "a stream-port collision is repaired in the configuration, not the environment"
    );
}

/// Retention is hard-bounded, but the counts and the fixed-cardinality
/// breakdown still account for everything observed — truncation loses per-port
/// detail, never the signal.
#[test]
fn the_retained_failure_set_is_hard_bounded() {
    let status = GatewayListenerStatus::new();
    let observations: Vec<_> = (0..(MAX_TRACKED_FAILURES as u16 + 25))
        .map(|index| tcp_bind_failure(20_000 + index))
        .collect();
    let total = observations.len();
    assert!(status.publish(1, total, 0, observations, 1_000));

    let snapshot = status.snapshot();
    assert_eq!(snapshot.active_failures, total);
    assert_eq!(snapshot.retained_failures, MAX_TRACKED_FAILURES);
    assert_eq!(snapshot.failures.len(), MAX_TRACKED_FAILURES);
    assert!(snapshot.truncated);
    assert_eq!(snapshot.active_by_category.len(), 1);
    assert_eq!(snapshot.active_by_category[0].count, total as u64);
}

/// A detail string is sanitized to printable ASCII and truncated, so a
/// pathological error can neither corrupt an operator's terminal nor grow the
/// snapshot.
#[test]
fn detail_is_sanitized_and_bounded() {
    let status = GatewayListenerStatus::new();
    let hostile = format!(
        "bind failed\n\r\tline two \u{1b}[31m red \u{202e}rtl {}",
        "A".repeat(400)
    );
    assert!(status.publish(
        1,
        1,
        0,
        vec![GatewayListenerFailureObservation::new(
            8443,
            GatewayListenerProtocolHalf::Tcp,
            GatewayListenerFailureCategory::BindFailed,
            hostile,
        )],
        1_000,
    ));

    let snapshot = status.snapshot();
    let detail = &snapshot.failures[0].detail;
    assert!(
        detail.chars().count() <= MAX_DETAIL_CHARS + 3,
        "detail must be bounded, got {} chars",
        detail.chars().count()
    );
    assert!(
        is_printable_ascii(detail),
        "detail must be printable ASCII: {detail:?}"
    );
    assert!(detail.starts_with("bind failed line two"));
    assert!(detail.ends_with("..."), "truncation must be visible");
}

fn render(status: &GatewayListenerStatus) -> String {
    let mut out = String::new();
    ferrum_edge::proxy::gateway_listener_status::render_prometheus(
        &mut out,
        NS_LABEL,
        Some(status),
    );
    out
}

/// The Prometheus surface is fixed-cardinality: two protocol halves times nine
/// bounded reasons, plus three unlabeled process gauges — regardless of how
/// many listener ports the configuration declares or how many of them fail.
#[test]
fn the_metric_surface_has_fixed_cardinality_and_leaks_no_listener_identity() {
    let status = GatewayListenerStatus::new();
    let observations: Vec<_> = (0..40u16)
        .map(|index| tcp_bind_failure(30_000 + index))
        .collect();
    assert!(status.publish(12_345, 41, 1, observations, 1_000));

    let rendered = render(&status);
    let sample_lines: Vec<&str> = rendered
        .lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty())
        .collect();
    let count = |name: &str| {
        sample_lines
            .iter()
            .filter(|line| line.starts_with(&format!("{name}{{")))
            .count()
    };
    assert_eq!(count("ferrum_gateway_listeners_desired"), 1);
    assert_eq!(count("ferrum_gateway_listeners_active"), 1);
    assert_eq!(count("ferrum_gateway_listener_failed_ports"), 1);
    assert_eq!(count("ferrum_gateway_listener_failures_active"), 18);
    assert_eq!(count("ferrum_gateway_listener_failures_total"), 18);
    assert_eq!(count("ferrum_gateway_listener_recoveries_total"), 18);
    assert_eq!(sample_lines.len(), 3 + 18 * 3);

    // No port, config generation, or error text may reach a label.
    for forbidden in [
        "30000", "30039", "12345", "Address already in use", "os error", "port=",
    ] {
        assert!(
            !rendered.contains(forbidden),
            "metric exposition leaked {forbidden:?}:\n{rendered}"
        );
    }
    // Only the three closed label keys appear.
    for line in &sample_lines {
        let Some(open) = line.find('{') else {
            continue;
        };
        let close = line.rfind('}').expect("label block closes");
        for pair in line[open + 1..close].split(',') {
            let key = pair.split('=').next().expect("label key");
            assert!(
                matches!(key, "protocol" | "reason" | "namespace"),
                "unexpected label key {key:?} in {line}"
            );
        }
    }
}

/// A process that binds no dynamic Gateway listeners advertises nothing, so
/// modes without this manager do not grow an empty family set.
#[test]
fn no_installed_status_renders_no_families() {
    let mut out = String::new();
    ferrum_edge::proxy::gateway_listener_status::render_prometheus(&mut out, NS_LABEL, None);
    assert!(out.is_empty());
}

/// Every bounded category maps to a stable label token and a stable origin.
#[test]
fn every_category_has_a_stable_label_and_origin() {
    let expected = [
        ("port_reserved", GatewayListenerFailureOrigin::Admission),
        (
            "process_global_class_mismatch",
            GatewayListenerFailureOrigin::Admission,
        ),
        (
            "stream_port_collision",
            GatewayListenerFailureOrigin::Admission,
        ),
        (
            "udp_stream_collision",
            GatewayListenerFailureOrigin::Admission,
        ),
        ("class_conflict", GatewayListenerFailureOrigin::Admission),
        (
            "frontend_tls_missing",
            GatewayListenerFailureOrigin::Admission,
        ),
        ("bind_failed", GatewayListenerFailureOrigin::Runtime),
        ("listener_task_ended", GatewayListenerFailureOrigin::Runtime),
        ("retirement_pending", GatewayListenerFailureOrigin::Runtime),
    ];
    let categories = GatewayListenerFailureCategory::ALL;
    assert_eq!(categories.len(), expected.len());
    for (category, (label, origin)) in categories.into_iter().zip(expected) {
        assert_eq!(category.as_str(), label);
        assert_eq!(category.origin(), origin);
        assert!(
            category
                .as_str()
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b == b'_'),
            "a metric label value must stay a stable snake_case token"
        );
    }
    assert_eq!(GatewayListenerProtocolHalf::Tcp.as_str(), "tcp");
    assert_eq!(GatewayListenerProtocolHalf::Quic.as_str(), "quic");
}
