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

/// Handshake records that are not the initial ClientHello fragment must not
/// open a frontend DTLS demux session. After a refused client certificate the
/// peer retransmits Certificate/Finished (`content-type 0x16`); treating those
/// as a new handshake reserved a slot that a later client at the same 4-tuple
/// was then folded into.
#[test]
fn dtls_demux_rejects_non_client_hello_handshake_records() {
    fn handshake_record(msg_type: u8, fragment_offset: u32) -> Vec<u8> {
        let body = [0u8; 16];
        let mut handshake = Vec::new();
        handshake.push(msg_type);
        handshake.push(0);
        handshake.push(0);
        handshake.push(body.len() as u8);
        handshake.extend_from_slice(&[0x00, 0x00]);
        handshake.push(((fragment_offset >> 16) & 0xff) as u8);
        handshake.push(((fragment_offset >> 8) & 0xff) as u8);
        handshake.push((fragment_offset & 0xff) as u8);
        handshake.push(0);
        handshake.push(0);
        handshake.push(body.len() as u8);
        handshake.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0xfe, 0xfd]);
        record.extend_from_slice(&[0x00, 0x00]);
        record.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    let opens = ferrum_edge::_test_support::dtls_datagram_opens_session_for_test;
    assert!(
        !opens(&[0x16; 12]),
        "a truncated DTLS record header must not open a session"
    );
    assert!(
        !opens(&[0x16; 32]),
        "handshake content-type without a ClientHello header must not open a session"
    );
    assert!(
        !opens(&handshake_record(0x0b, 0)),
        "a Certificate record must not open a session for an unknown peer"
    );
    assert!(
        !opens(&handshake_record(0x14, 0)),
        "a Finished record must not open a session for an unknown peer"
    );
    assert!(
        !opens(&handshake_record(0x01, 16)),
        "a ClientHello continuation fragment must not open a session"
    );
    assert!(
        opens(&handshake_record(0x01, 0)),
        "the initial ClientHello fragment is the only datagram that opens a session"
    );
    let mut truncated = handshake_record(0x01, 0);
    truncated.pop();
    assert!(
        !opens(&truncated),
        "a record shorter than its declared length must not open a session"
    );
    let mut nonzero_epoch = handshake_record(0x01, 0);
    nonzero_epoch[4] = 1;
    assert!(
        !opens(&nonzero_epoch),
        "a ClientHello record outside epoch zero must not open a session"
    );
    let mut empty_fragment = handshake_record(0x01, 0);
    empty_fragment[22..25].copy_from_slice(&[0, 0, 0]);
    assert!(
        !opens(&empty_fragment),
        "an empty ClientHello fragment must not reserve a session"
    );
    let mut oversized_fragment = handshake_record(0x01, 0);
    oversized_fragment[22..25].copy_from_slice(&[0, 0, 17]);
    assert!(
        !opens(&oversized_fragment),
        "a fragment longer than the record payload must not open a session"
    );
    let mut fragment_exceeds_message = handshake_record(0x01, 0);
    fragment_exceeds_message[14..17].copy_from_slice(&[0, 0, 15]);
    assert!(
        !opens(&fragment_exceeds_message),
        "a fragment longer than its declared handshake message must not open a session"
    );
    let mut ccs = handshake_record(0x01, 0);
    ccs[0] = 0x14;
    assert!(
        !opens(&ccs),
        "ChangeCipherSpec must not open a session for an unknown peer"
    );
}
