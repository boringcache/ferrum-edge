//! Honest `__mesh_bpf_metrics` contract coverage (#2218/#2220/#2224/#2229).
//!
//! Validates the public Prometheus surface, ABI decode rules, and pin-rotation
//! dropped-baseline seeding without requiring a live BPF load.

use ferrum_ebpf_common::{
    SOCK_OPS_DIRECTION_RECEIVED, SOCK_OPS_DIRECTION_SENT, SOCK_OPS_DROP_BYPASS_UID_HIT,
    SOCK_OPS_DROP_EXCLUDE_CIDR_HIT, SOCK_OPS_DROP_EXCLUDE_PORT_HIT,
    SOCK_OPS_DROP_NOT_IN_INCLUDE_CIDR, SOCK_OPS_EVENT_ACCEPT_TO_FIRST_BYTE_LATENCY,
    SOCK_OPS_EVENT_DROP_REASON, SOCK_OPS_EVENT_RST, SockOpsRecord,
};
use ferrum_edge::ebpf::bpf_metrics::{BpfDropReason, BpfMetricsState, TcpDirection};
use ferrum_edge::ebpf::event_consumer::{
    PollOutcome, SockOpsConsumer, SockOpsEvent, seed_dropped_baseline,
};
use ferrum_edge::plugins::mesh::bpf_metrics::MeshBpfMetrics;
use serde_json::json;

fn render_with(state: std::sync::Arc<BpfMetricsState>) -> String {
    MeshBpfMetrics::with_state(&json!({}), state)
        .expect("plugin config")
        .exporter()
        .render_prometheus()
}

#[test]
fn prometheus_surface_uses_nondirectional_rst_and_omits_accept_to_first_byte() {
    let state = BpfMetricsState::new();
    state.record_connect();
    state.record_rst();
    state.record_drop(BpfDropReason::ExcludePortHit);
    state.record_syn_to_ack(40);
    let text = render_with(state);

    assert!(text.contains("ferrum_mesh_bpf_tcp_events_total{event=\"rst\"} 1"));
    assert!(
        !text.contains("rst_sent") && !text.contains("rst_received"),
        "directional RST labels must not appear: {text}"
    );
    assert!(
        !text.contains("accept_to_first_byte"),
        "unsupported accept-to-first-byte family must not appear: {text}"
    );
    assert!(text.contains("ferrum_mesh_bpf_drops_total{reason=\"exclude_port_hit\"} 1"));
    assert!(text.contains("ferrum_mesh_bpf_syn_to_ack_microseconds_count 1"));
    assert!(
        text.contains("without sent/received") || text.contains("cannot distinguish direction"),
        "HELP must disclose non-directional RST: {text}"
    );
}

#[test]
fn all_four_drop_reasons_render_at_zero_when_unset() {
    let text = render_with(BpfMetricsState::new());
    for reason in [
        "bypass_uid_hit",
        "exclude_cidr_hit",
        "not_in_include_cidr",
        "exclude_port_hit",
    ] {
        assert!(
            text.contains(&format!(
                "ferrum_mesh_bpf_drops_total{{reason=\"{reason}\"}} 0"
            )),
            "missing zero series for {reason}: {text}"
        );
    }
}

#[test]
fn abi_drop_reason_and_rst_decode_contract() {
    fn rec(event: u32, direction: u32, drop_reason: u32) -> SockOpsRecord {
        SockOpsRecord {
            event_type: event,
            direction,
            drop_reason,
            _pad: 0,
            value: 0,
        }
    }

    assert_eq!(
        SockOpsEvent::from_record(rec(SOCK_OPS_EVENT_RST, 0, 0)),
        Some(SockOpsEvent::Rst)
    );
    assert_eq!(
        SockOpsEvent::from_record(rec(SOCK_OPS_EVENT_RST, SOCK_OPS_DIRECTION_SENT, 0)),
        Some(SockOpsEvent::Rst)
    );
    assert_eq!(
        SockOpsEvent::from_record(rec(SOCK_OPS_EVENT_RST, SOCK_OPS_DIRECTION_RECEIVED, 0)),
        Some(SockOpsEvent::Rst)
    );
    assert!(
        SockOpsEvent::from_record(rec(SOCK_OPS_EVENT_ACCEPT_TO_FIRST_BYTE_LATENCY, 0, 0)).is_none(),
        "reserved accept-to-first-byte discriminant must be ignored"
    );

    for (raw, expected) in [
        (SOCK_OPS_DROP_BYPASS_UID_HIT, BpfDropReason::BypassUidHit),
        (
            SOCK_OPS_DROP_EXCLUDE_CIDR_HIT,
            BpfDropReason::ExcludeCidrHit,
        ),
        (
            SOCK_OPS_DROP_NOT_IN_INCLUDE_CIDR,
            BpfDropReason::NotInIncludeCidr,
        ),
        (
            SOCK_OPS_DROP_EXCLUDE_PORT_HIT,
            BpfDropReason::ExcludePortHit,
        ),
    ] {
        assert_eq!(
            SockOpsEvent::from_record(rec(SOCK_OPS_EVENT_DROP_REASON, 0, raw)),
            Some(SockOpsEvent::DropReason(expected))
        );
    }
}

#[test]
fn pin_rotation_seed_preserves_cumulative_state() {
    let consumer = SockOpsConsumer::new(BpfMetricsState::new());
    consumer.handle_event(SockOpsEvent::Connect);
    consumer.handle_event(SockOpsEvent::Fin {
        direction: TcpDirection::Sent,
    });
    consumer.handle_event(SockOpsEvent::DropReason(BpfDropReason::BypassUidHit));

    // First map generation with no pre-existing drops.
    assert_eq!(seed_dropped_baseline(&consumer, 0), 0);
    let mid = consumer.metrics().snapshot();
    assert_eq!(mid.connect, 1);
    assert_eq!(mid.fin_sent, 1);
    assert_eq!(mid.drop_bypass_uid_hit, 1);
    assert_eq!(mid.ringbuf_overruns, 0);
    assert!(!mid.in_overrun_regime);

    // Replacement map generation already lost events before reattach.
    assert_eq!(seed_dropped_baseline(&consumer, 7), 7);
    let after = consumer.metrics().snapshot();
    assert_eq!(after.connect, 1, "userspace cumulative state must survive");
    assert_eq!(after.fin_sent, 1);
    assert_eq!(after.drop_bypass_uid_hit, 1);
    assert_eq!(after.ringbuf_overruns, 1);
    assert!(after.in_overrun_regime);

    // Subsequent poll-style overruns still advance the counter.
    let mut consecutive = 0u32;
    consumer.observe_poll(PollOutcome::Overrun, &mut consecutive, 3);
    assert_eq!(consumer.metrics().snapshot().ringbuf_overruns, 2);
}

#[test]
fn ringbuf_overrun_help_documents_reattach_seeding() {
    let text = render_with(BpfMetricsState::new());
    assert!(
        text.contains("re-attaching") || text.contains("pin rotation"),
        "overrun HELP must document pin-rotation seeding: {text}"
    );
}
