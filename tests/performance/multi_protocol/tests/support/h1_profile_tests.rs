use std::sync::Arc;

use multi_protocol_perf::h1_profile::{Counters, ObservedTls, RecordParser, Snapshot};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[test]
fn tls_records_survive_every_header_and_payload_split() {
    let wire = [
        22, 3, 3, 0, 2, 1, 2, 23, 3, 3, 0, 3, 7, 8, 9, 23, 3, 3, 0, 0,
    ];
    for chunk in 1..=wire.len() {
        let counters = Arc::new(Counters::default());
        let mut parser = RecordParser::default();
        for bytes in wire.chunks(chunk) {
            parser.observe(bytes, &counters);
        }
        let snapshot = Snapshot::capture(&[counters]);
        assert_eq!(snapshot.tls_records, 3);
        assert_eq!(snapshot.tls_record_bytes, wire.len() as u64);
        assert_eq!(snapshot.tls_parse_errors, 0);
    }
}

#[test]
fn partial_records_and_invalid_headers_do_not_manufacture_counts() {
    let counters = Arc::new(Counters::default());
    let mut parser = RecordParser::default();
    parser.observe(&[23, 3, 3, 0, 2, 7], &counters);
    assert_eq!(
        Snapshot::capture(std::slice::from_ref(&counters)).tls_records,
        0
    );
    parser.observe(&[8], &counters);
    let start = Snapshot::capture(std::slice::from_ref(&counters));
    parser.observe(&[99, 3, 3, 0, 0], &counters);
    parser.observe(&[23, 3, 3, 0, 0], &counters);
    let delta = Snapshot::capture(&[counters]).delta(&start);
    assert_eq!(delta.tls_records, 0);
    assert_eq!(delta.tls_parse_errors, 1);
}

#[tokio::test]
async fn observer_preserves_reads_writes_flush_and_half_close() {
    let (left, mut right) = tokio::io::duplex(64);
    let counters = Arc::new(Counters::default());
    let mut observed = ObservedTls::new(left, counters.clone());
    observed.write_all(b"request").await.unwrap();
    observed.flush().await.unwrap();
    observed.shutdown().await.unwrap();
    let mut request = Vec::new();
    right.read_to_end(&mut request).await.unwrap();
    assert_eq!(request, b"request");
    let wire = [23, 3, 3, 0, 2, 7, 8];
    right.write_all(&wire).await.unwrap();
    right.shutdown().await.unwrap();
    let mut response = Vec::new();
    observed.read_to_end(&mut response).await.unwrap();
    assert_eq!(response, wire);
    assert_eq!(Snapshot::capture(&[counters]).tls_records, 1);
}
