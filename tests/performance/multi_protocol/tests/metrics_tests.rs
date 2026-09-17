use multi_protocol_perf::metrics::{BenchMetrics, collect_results};

#[tokio::test]
async fn failed_and_panicked_workers_are_counted_alongside_completed_work() {
    let successful = tokio::spawn(async {
        let mut metrics = BenchMetrics::new();
        metrics.record(100, 1024);
        metrics.record_error();
        Ok(metrics)
    });
    let failed = tokio::spawn(async { Err(anyhow::anyhow!("connect failed")) });
    let panicked = tokio::spawn(async { panic!("worker panic") });
    let combined = collect_results(vec![successful, failed, panicked]).await;
    assert_eq!(combined.total_requests, 1);
    assert_eq!(combined.total_bytes, 1024);
    assert_eq!(combined.total_errors, 3);
}

#[tokio::test]
async fn all_failed_workers_cannot_report_zero_errors() {
    let handles = (0..4)
        .map(|_| tokio::spawn(async { Err(anyhow::anyhow!("TLS handshake failed")) }))
        .collect();
    let combined = collect_results(handles).await;
    assert_eq!(combined.total_requests, 0);
    assert_eq!(combined.total_errors, 4);
}
