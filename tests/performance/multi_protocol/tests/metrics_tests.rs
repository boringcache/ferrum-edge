use multi_protocol_perf::metrics::{BenchMetrics, collect_results};
use multi_protocol_perf::phases::{CompletionPhase, Phases, classify_completion};
use std::time::{Duration, Instant};

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

#[test]
fn deadline_is_exclusive_and_warmup_is_separate() {
    let start = Instant::now();
    let end = start + Duration::from_secs(1);
    assert_eq!(classify_completion(None, start), CompletionPhase::Warmup);
    assert_eq!(
        classify_completion(Some((start, end)), start),
        CompletionPhase::Measurement,
    );
    assert_eq!(
        classify_completion(Some((start, end)), end),
        CompletionPhase::Drain,
    );
    assert_eq!(
        classify_completion(Some((start, end)), end + Duration::from_secs(10)),
        CompletionPhase::Drain,
    );
}

#[tokio::test]
async fn slow_setup_and_warmup_do_not_spend_the_measurement_interval() {
    let mut phases = Phases::new(Duration::from_millis(80));
    let mut metrics = phases.worker();
    let connections = phases.connections();
    let handle = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(30)).await;
        let _connection = connections.opened();
        assert!(metrics.next_request().await);
        metrics.admitted();
        tokio::time::sleep(Duration::from_millis(30)).await;
        metrics.record(30_000, 64);
        assert!(metrics.next_request().await);
        // Leave a real client admission queue long enough for observation.
        tokio::time::sleep(Duration::from_millis(20)).await;
        metrics.admitted();
        metrics.admitted(); // body frame polls must not count twice
        metrics.record(20_000, 64);
        assert!(metrics.next_request().await);
        metrics.admitted();
        tokio::time::sleep(Duration::from_millis(100)).await;
        metrics.record(100_000, 64); // successful, but outside measurement
        assert!(!metrics.next_request().await);
        Ok(metrics.finish_worker())
    });
    let combined = tokio::time::timeout(Duration::from_secs(2), phases.finish(vec![handle]))
        .await
        .unwrap();
    assert_eq!(combined.warmup_requests, 1);
    assert_eq!(combined.total_requests, 1);
    assert_eq!(combined.total_bytes, 64);
    assert_eq!(combined.drain_requests, 1);
    assert_eq!(combined.drain_bytes, 64);
    let timing = combined.phases.as_ref().unwrap();
    assert!(timing.setup_secs >= 0.03);
    assert!(timing.warmup_secs >= 0.03);
    assert_eq!(timing.measurement_secs, 0.08);
    assert!(!timing.timed_out);
    let observed = combined.observed.as_ref().unwrap();
    assert_eq!(observed.workers_at_barrier, 1);
    assert_eq!(observed.active_connections.min, 1);
    assert_eq!(observed.active_streams.max, 1);
    assert_eq!(observed.queued_requests.max, 1);
    assert_eq!(observed.admissions, 2);
    assert!(observed.queue_time_ns >= 20_000_000);
    let report = serde_json::to_value(combined.to_json_report("test", "test", 1, 1)).unwrap();
    assert_eq!(report["drain_requests"], 1);
    assert_eq!(report["observed"]["workers_at_barrier"], 1);
}

#[tokio::test]
async fn setup_failure_and_measured_worker_loss_release_barriers_and_reduce_observations() {
    let mut phases = Phases::new(Duration::from_millis(80));
    let failed_metrics = phases.worker();
    let failed = tokio::spawn(async move {
        drop(failed_metrics);
        Err(anyhow::anyhow!("setup failed"))
    });
    let mut metrics = phases.worker();
    let connections = phases.connections();
    let retired = tokio::spawn(async move {
        let _connection = connections.opened();
        assert!(metrics.next_request().await);
        metrics.admitted();
        metrics.record(1, 64);
        assert!(metrics.next_request().await);
        metrics.admitted();
        tokio::time::sleep(Duration::from_millis(25)).await;
        metrics.record_error();
        Ok(metrics.finish_worker())
    });
    let combined =
        tokio::time::timeout(Duration::from_secs(2), phases.finish(vec![failed, retired]))
            .await
            .unwrap();
    assert_eq!(combined.total_errors, 2);
    let observed = combined.observed.unwrap();
    assert_eq!(observed.workers_at_barrier, 1);
    assert_eq!(observed.active_workers.min, 0);
    assert_eq!(observed.active_workers.max, 1);
    assert_eq!(observed.active_connections.min, 0);
    assert_eq!(observed.active_connections.max, 1);
    assert_eq!(observed.workers_retired_before_deadline, 2);
}

#[tokio::test]
async fn request_body_admission_occurs_only_when_transport_polls_it() {
    use http_body_util::BodyExt;
    use multi_protocol_perf::transport::request_body;

    let mut phases = Phases::new(Duration::from_millis(80));
    let mut metrics = phases.worker();
    let worker = tokio::spawn(async move {
        assert!(metrics.next_request().await);
        metrics.admitted();
        metrics.record(1, 64);
        assert!(metrics.next_request().await);
        let body = request_body(bytes::Bytes::from_static(b"echo"), metrics.admission());
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert_eq!(body.collect().await.unwrap().to_bytes(), b"echo".as_slice());
        tokio::time::sleep(Duration::from_millis(100)).await;
        metrics.record(100_000, 4);
        Ok(metrics.finish_worker())
    });
    let combined = phases.finish(vec![worker]).await;
    let observed = combined.observed.unwrap();
    assert_eq!(observed.queued_requests.max, 1);
    assert_eq!(observed.active_streams.max, 1);
    assert_eq!(observed.admissions, 1);
}

#[tokio::test]
async fn tcp_echo_makes_full_duplex_progress_beyond_socket_capacity() {
    use multi_protocol_perf::transport::echo_exchange;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (client, server) = tokio::io::duplex(64);
    let server = tokio::spawn(async move {
        let (mut read, mut write) = tokio::io::split(server);
        let mut buffer = [0; 31];
        loop {
            let n = read.read(&mut buffer).await.unwrap();
            if n == 0 {
                break;
            }
            write.write_all(&buffer[..n]).await.unwrap();
        }
    });
    let payload: Vec<_> = (0..131_072).map(|i| i as u8).collect();
    let mut response = vec![0; payload.len()];
    let (mut read, mut write) = tokio::io::split(client);
    for _ in 0..2 {
        tokio::time::timeout(
            Duration::from_secs(5),
            echo_exchange(&mut read, &mut write, &payload, &mut response),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(response, payload);
    }
    write.shutdown().await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn tcp_partial_echo_remains_an_io_failure() {
    use multi_protocol_perf::transport::echo_exchange;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (client, mut server) = tokio::io::duplex(4);
    let peer = tokio::spawn(async move {
        let mut request = [0; 4];
        server.read_exact(&mut request).await.unwrap();
        server.write_all(b"ab").await.unwrap();
    });
    let (mut read, mut write) = tokio::io::split(client);
    let mut response = [0; 4];
    let result = echo_exchange(&mut read, &mut write, b"abcd", &mut response).await;
    assert!(result.is_err());
    peer.await.unwrap();
}

#[tokio::test]
async fn every_worker_finishes_setup_and_warmup_before_measurement_starts() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let setup_done = Arc::new(AtomicBool::new(false));
    let warmup_done = Arc::new(AtomicBool::new(false));
    let mut phases = Phases::new(Duration::from_millis(40));
    let mut handles = Vec::new();
    for slow in [false, true] {
        let setup_done = setup_done.clone();
        let warmup_done = warmup_done.clone();
        let mut metrics = phases.worker();
        handles.push(tokio::spawn(async move {
            if slow {
                tokio::time::sleep(Duration::from_millis(20)).await;
                setup_done.store(true, Ordering::SeqCst);
            }
            assert!(metrics.next_request().await);
            assert!(setup_done.load(Ordering::SeqCst));
            metrics.admitted();
            if slow {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            metrics.record(1, 64);
            if slow {
                warmup_done.store(true, Ordering::SeqCst);
            }
            assert!(metrics.next_request().await);
            assert!(warmup_done.load(Ordering::SeqCst));
            metrics.admitted();
            tokio::time::sleep(Duration::from_millis(60)).await;
            metrics.record(60_000, 64);
            Ok(metrics.finish_worker())
        }));
    }
    let combined = tokio::time::timeout(Duration::from_secs(2), phases.finish(handles))
        .await
        .unwrap();
    assert_eq!(combined.total_errors, 0);
    assert_eq!(combined.warmup_requests, 2);
    assert_eq!(combined.drain_requests, 2);
}
