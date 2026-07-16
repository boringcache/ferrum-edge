use ferrum_edge::proxy::mesh_udp_capture::{CapturedUdpOutcome, CapturedUdpOutcomeSignal};

#[tokio::test]
async fn captured_udp_idle_sweep_before_relay_cleanup_keeps_idle_outcome() {
    let signal = CapturedUdpOutcomeSignal::new();
    let (sender, mut receiver) = tokio::sync::mpsc::channel::<()>(1);

    // This is the production ordering: publish the reason before `retain`
    // drops the map-owned sender. The lifecycle Drop fallback uses this same
    // resolution if producer shutdown aborts the relay before it wakes.
    signal.mark_idle_timeout();
    drop(sender);

    assert!(receiver.recv().await.is_none());
    assert_eq!(
        signal.resolve_egress_completion(true),
        CapturedUdpOutcome::IdleTimeout
    );
}

#[tokio::test]
async fn captured_udp_watchdog_before_idle_sweep_converges_on_idle_outcome() {
    // When the watchdog select arm wins first it reports IdleTimeout directly.
    // A concurrent cleanup sweep may subsequently publish the same reason and
    // close the sender; both interleavings must remain normal idle cleanup.
    let signal = CapturedUdpOutcomeSignal::new();
    let (sender, mut receiver) = tokio::sync::mpsc::channel::<()>(1);
    let watchdog_outcome = tokio::select! {
        biased;
        _ = std::future::ready(()) => CapturedUdpOutcome::IdleTimeout,
        _ = receiver.recv() => signal.resolve_egress_completion(true),
    };
    signal.mark_idle_timeout();
    drop(sender);

    assert_eq!(watchdog_outcome, CapturedUdpOutcome::IdleTimeout);
    assert_eq!(
        signal.resolve_egress_completion(true),
        CapturedUdpOutcome::IdleTimeout
    );
}

#[test]
fn captured_udp_signal_preserves_failures_and_shutdown_precedence() {
    let signal = CapturedUdpOutcomeSignal::new();
    signal.mark_idle_timeout();

    // A tunnel write failure is a true egress termination, regardless of a
    // concurrent sweep signal.
    assert_eq!(
        signal.resolve_egress_completion(false),
        CapturedUdpOutcome::EgressPathEnded
    );

    // Producer cancellation wins over a simultaneous idle sweep so listener
    // replacement/gateway shutdown stays graceful even when tasks are aborted.
    signal.mark_producer_shutdown();
    assert_eq!(
        signal.resolve_egress_completion(true),
        CapturedUdpOutcome::ProducerShutdown
    );

    let unexpected_close = CapturedUdpOutcomeSignal::new();
    assert_eq!(
        unexpected_close.resolve_egress_completion(true),
        CapturedUdpOutcome::EgressPathEnded
    );
}
