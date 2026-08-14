//! External regression coverage for DTLS demux identity-aware session removal
//! (issue #2959).
//!
//! A stale generation-1 cleanup for a peer address must not evict a newer
//! generation-2 live session inserted at that same address. Counters must stay
//! balanced when the stale path no-ops and when the matching path wins once.

#[test]
fn dtls_stale_generation_cleanup_cannot_remove_newer_session() {
    ferrum_edge::_test_support::dtls_stale_session_removal_preserves_newer_generation_for_test()
        .expect("generation-1 cleanup must not evict generation-2 demux entry");
}

/// The DTLS demuxer is a distinct path from plain UDP's `process_datagram`, so
/// it needs its own proof that a refusal flood cannot become a log flood
/// (issue #3289). Every refused datagram must still move the shared drop
/// counter, and the record that follows a closed window must report what was
/// withheld — otherwise the bound would silently hide the volume.
#[test]
fn dtls_client_address_metadata_refusals_are_counted_and_rate_limited() {
    let refusals_in_window = 4u64;
    let (drops, records, suppressed) =
        ferrum_edge::_test_support::dtls_datagram_metadata_refusal_accounting_for_test(
            refusals_in_window,
        )
        .expect("refusal accounting harness");

    assert_eq!(
        drops,
        refusals_in_window + 1,
        "every refused datagram must be counted, emitted or not"
    );
    assert_eq!(
        records, 2,
        "one record for the first refusal, one after the window elapsed"
    );
    assert_eq!(
        suppressed,
        refusals_in_window - 1,
        "the second record must report the refusals the limiter withheld"
    );
}
