//! Deterministic delivery-lifecycle tests for notification dispatch +
//! proxy_alerts pending-state / generation retirement contracts (#2448).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ferrum_edge::notifications::channels::email::{SmtpFailure, SmtpPhase};
use ferrum_edge::notifications::channels::{NotificationChannel, parse_channels};
use ferrum_edge::notifications::dispatch::{DeliveryRetryPolicy, dispatch_one};
use ferrum_edge::notifications::generation::{DispatchGeneration, DispatchSettle};
use ferrum_edge::notifications::metrics::DeliveryMetrics;
use ferrum_edge::notifications::outcome::{
    FailureClass, classify_http_status, classify_smtp_failure,
};
use ferrum_edge::notifications::{EventAction, Notification, NotificationField, Severity};
use ferrum_edge::plugins::proxy_alerts::ProxyAlerts;
use ferrum_edge::plugins::proxy_alerts::cooldown::RuleState;
use ferrum_edge::plugins::proxy_alerts::windows::monotonic_now_ms;
use ferrum_edge::plugins::utils::http_client::PluginHttpClient;
use ferrum_edge::plugins::{Plugin, TransactionSummary};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, Semaphore, oneshot};
use tokio::time::timeout;

fn fixed_notification() -> Notification {
    Notification {
        title: "x".to_string(),
        body: "y".to_string(),
        severity: Severity::High,
        event_action: EventAction::Trigger,
        source: None,
        subject_id: None,
        namespace: None,
        fired_at: chrono::Utc::now(),
        fields: vec![NotificationField::new("k", "v")],
    }
}

fn webhook_channel_to(url: String) -> Arc<NotificationChannel> {
    let map = parse_channels(&json!({
        "delivery_test": {
            "type": "webhook",
            "url": url,
            "body_template": "{}",
        }
    }))
    .unwrap();
    map.into_values().next().unwrap()
}

async fn read_request_headers(socket: &mut TcpStream) {
    let mut request = Vec::new();
    let mut buf = [0; 1024];
    loop {
        let n = socket.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        request.extend_from_slice(&buf[..n]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") || request.len() > 8192 {
            break;
        }
    }
}

async fn spawn_status_sequence_server(
    statuses: Vec<u16>,
) -> (
    SocketAddr,
    Arc<AtomicUsize>,
    Arc<Notify>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let notify = Arc::new(Notify::new());
    let server_count = Arc::clone(&count);
    let server_notify = Arc::clone(&notify);

    let handle = tokio::spawn(async move {
        for status in statuses {
            let (mut socket, _) = listener.accept().await.unwrap();
            read_request_headers(&mut socket).await;
            server_count.fetch_add(1, Ordering::SeqCst);
            server_notify.notify_waiters();
            let body =
                format!("HTTP/1.1 {status} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            socket.write_all(body.as_bytes()).await.unwrap();
        }
    });

    (addr, count, notify, handle)
}

async fn wait_for_count(count: &AtomicUsize, notify: &Notify, expected: usize) {
    let wait = async {
        loop {
            // Register before checking the counter so notify_waiters cannot
            // land in the gap between the authoritative observation and the
            // waiter registration. Unlike notify_one, notify_waiters does not
            // retain a permit when no waiter is present.
            let notified = notify.notified();
            if count.load(Ordering::SeqCst) >= expected {
                break;
            }
            notified.await;
        }
    };
    timeout(Duration::from_secs(3), wait)
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {expected} requests"));
}

#[test]
fn http_status_classification_is_bounded_and_stable() {
    assert_eq!(
        classify_http_status(reqwest::StatusCode::TOO_MANY_REQUESTS),
        FailureClass::Transient
    );
    assert_eq!(
        classify_http_status(reqwest::StatusCode::REQUEST_TIMEOUT),
        FailureClass::Transient
    );
    assert_eq!(
        classify_http_status(reqwest::StatusCode::INTERNAL_SERVER_ERROR),
        FailureClass::Transient
    );
    assert_eq!(
        classify_http_status(reqwest::StatusCode::BAD_REQUEST),
        FailureClass::Permanent
    );
    assert_eq!(
        classify_http_status(reqwest::StatusCode::UNAUTHORIZED),
        FailureClass::Permanent
    );
    assert_eq!(
        classify_smtp_failure(&SmtpFailure::UnexpectedCode {
            phase: SmtpPhase::Data,
            code: 451,
        }),
        FailureClass::Transient
    );
    assert_eq!(
        classify_smtp_failure(&SmtpFailure::UnexpectedCode {
            phase: SmtpPhase::Data,
            code: 550,
        }),
        FailureClass::Permanent
    );
}

#[test]
fn prometheus_contract_emits_fixed_channel_type_series() {
    let text = ferrum_edge::notifications::render_delivery_prometheus();
    for kind in ["slack", "teams", "discord", "webhook", "email"] {
        assert!(
            text.contains(&format!(
                "ferrum_notification_delivery_attempted_total{{channel_type=\"{kind}\"}}"
            )),
            "missing attempted series for {kind}"
        );
        assert!(
            text.contains(&format!(
                "ferrum_notification_delivery_in_flight{{channel_type=\"{kind}\"}}"
            )),
            "missing in-flight gauge for {kind}"
        );
    }
    assert!(text.contains("# HELP ferrum_notification_delivery_abandoned_at_deadline_total"));
    assert!(text.contains("# HELP ferrum_notification_delivery_backpressure_dropped_total"));
    assert!(!text.contains("channel_name="));
}

#[tokio::test]
async fn semaphore_exhaustion_increments_backpressure_and_skips_send() {
    let metrics = Arc::new(DeliveryMetrics::new());
    let generation = DispatchGeneration::with_metrics(42, Arc::clone(&metrics));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let sem = Arc::new(Semaphore::new(0));
    let channel = webhook_channel_to(format!("http://{addr}/notify"));
    let notification = Arc::new(fixed_notification());

    let admitted = dispatch_one(
        notification,
        Arc::new(Default::default()),
        channel,
        sem,
        PluginHttpClient::default(),
        generation,
        DeliveryRetryPolicy {
            max_retries: 0,
            ..DeliveryRetryPolicy::DEFAULT
        },
        "test",
        Some(Arc::new(|_| panic!("callback panic must be contained"))),
    );
    assert!(!admitted);
    assert_eq!(metrics.channel_snapshot("webhook").backpressure_dropped, 1);
    assert!(
        timeout(Duration::from_millis(100), listener.accept())
            .await
            .is_err(),
        "exhausted semaphore must not connect"
    );
}

#[tokio::test]
async fn transient_retry_then_success() {
    let metrics = Arc::new(DeliveryMetrics::new());
    let generation = DispatchGeneration::with_metrics(7, Arc::clone(&metrics));
    let (addr, count, notify, server) = spawn_status_sequence_server(vec![503, 200]).await;
    let sem = Arc::new(Semaphore::new(1));
    let channel = webhook_channel_to(format!("http://{addr}/notify"));
    let settled = Arc::new(tokio::sync::Mutex::new(None));
    let settled_cb = Arc::clone(&settled);

    assert!(dispatch_one(
        Arc::new(fixed_notification()),
        Arc::new(Default::default()),
        channel,
        sem,
        PluginHttpClient::default(),
        Arc::clone(&generation),
        DeliveryRetryPolicy {
            max_retries: 2,
            base_delay: Duration::from_millis(10),
            max_delay: Duration::from_millis(20),
        },
        "test",
        Some(Arc::new(move |s| {
            let settled_cb = Arc::clone(&settled_cb);
            tokio::spawn(async move {
                *settled_cb.lock().await = Some(s);
            });
        })),
    ));

    wait_for_count(&count, &notify, 2).await;
    server.await.unwrap();
    timeout(
        Duration::from_secs(2),
        generation.wait_drain(Duration::from_secs(2)),
    )
    .await
    .unwrap();
    // Allow callback task to land.
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(*settled.lock().await, Some(DispatchSettle::Succeeded));
    let snap = metrics.channel_snapshot("webhook");
    assert_eq!(snap.attempted, 1);
    assert_eq!(snap.succeeded, 1);
    assert_eq!(snap.failed_transient, 0);
}

#[tokio::test]
async fn permanent_failure_does_not_retry() {
    let metrics = Arc::new(DeliveryMetrics::new());
    let generation = DispatchGeneration::with_metrics(8, Arc::clone(&metrics));
    let (addr, count, notify, server) = spawn_status_sequence_server(vec![401]).await;
    let sem = Arc::new(Semaphore::new(1));
    let channel = webhook_channel_to(format!("http://{addr}/notify"));

    assert!(dispatch_one(
        Arc::new(fixed_notification()),
        Arc::new(Default::default()),
        channel,
        sem,
        PluginHttpClient::default(),
        Arc::clone(&generation),
        DeliveryRetryPolicy {
            max_retries: 3,
            base_delay: Duration::from_millis(10),
            max_delay: Duration::from_millis(20),
        },
        "test",
        None,
    ));

    wait_for_count(&count, &notify, 1).await;
    // Give a moment; a buggy retry would produce a second accept.
    assert!(
        timeout(Duration::from_millis(80), async {
            loop {
                if count.load(Ordering::SeqCst) > 1 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .is_err(),
        "permanent 401 must not be retried"
    );
    drop(server);
    timeout(
        Duration::from_secs(2),
        generation.wait_drain(Duration::from_secs(2)),
    )
    .await
    .unwrap();
    let snap = metrics.channel_snapshot("webhook");
    assert_eq!(snap.attempted, 1);
    assert_eq!(snap.failed_permanent, 1);
    assert_eq!(snap.succeeded, 0);
}

#[tokio::test]
async fn proxy_alerts_failed_trigger_releases_cooldown_and_pending_state() {
    let (addr, _count, _notify, server) = spawn_status_sequence_server(vec![500]).await;
    let cfg = json!({
        "max_concurrent_dispatches": 2,
        "max_delivery_retries": 0,
        "channels": {
            "c": { "type": "webhook", "url": format!("http://{addr}/alert"), "body_template": "x" }
        },
        "rules": [
            { "name": "status", "type": "status_code_count",
              "status_codes": [500], "threshold_count": 1,
              "cooldown_seconds": 60, "channels": ["c"] }
        ]
    });
    let plugin = ProxyAlerts::new(&cfg, PluginHttpClient::default()).unwrap();
    let summary = TransactionSummary {
        namespace: "ferrum".to_string(),
        proxy_id: Some("p1".to_string()),
        proxy_name: Some("api".to_string()),
        response_status_code: 500,
        ..TransactionSummary::default()
    };
    plugin.log(&summary).await;

    timeout(Duration::from_secs(3), async {
        loop {
            match plugin.recovery_state_for_test(0, "ferrum|p1", 0) {
                Some(RuleState::PendingTrigger { .. }) => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Some(RuleState::Healthy) | None => break,
                Some(RuleState::Active { .. }) => {
                    panic!("failed trigger must not permanently mark Active")
                }
                other => panic!("unexpected state {other:?}"),
            }
        }
    })
    .await
    .expect("pending trigger should settle");

    assert!(
        plugin.try_acquire_cooldown_for_test(0, "ferrum|p1", 0, 60_000, monotonic_now_ms(), 0,),
        "failed trigger must release cooldown"
    );
    drop(server);
}

#[tokio::test]
async fn proxy_alerts_successful_trigger_commits_active_and_cooldown() {
    let (addr, count, notify, server) = spawn_status_sequence_server(vec![204]).await;
    let cfg = json!({
        "max_concurrent_dispatches": 2,
        "max_delivery_retries": 0,
        "channels": {
            "c": { "type": "webhook", "url": format!("http://{addr}/alert"), "body_template": "x" }
        },
        "rules": [
            { "name": "status", "type": "status_code_count",
              "status_codes": [500], "threshold_count": 1,
              "cooldown_seconds": 60, "channels": ["c"] }
        ]
    });
    let plugin = ProxyAlerts::new(&cfg, PluginHttpClient::default()).unwrap();
    let summary = TransactionSummary {
        namespace: "ferrum".to_string(),
        proxy_id: Some("p1".to_string()),
        proxy_name: Some("api".to_string()),
        response_status_code: 500,
        ..TransactionSummary::default()
    };
    plugin.log(&summary).await;
    wait_for_count(&count, &notify, 1).await;
    server.await.unwrap();

    timeout(Duration::from_secs(3), async {
        loop {
            if matches!(
                plugin.recovery_state_for_test(0, "ferrum|p1", 0),
                Some(RuleState::Active { .. })
            ) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("successful trigger should become Active");

    assert!(
        !plugin.try_acquire_cooldown_for_test(0, "ferrum|p1", 0, 60_000, monotonic_now_ms(), 0,),
        "successful trigger must consume cooldown"
    );
}

/// An endpoint that answers `preface` statuses and then accepts one more
/// request which it never answers, deliberately stalling the dispatch future
/// inside `transport.dispatch`.
struct StalledEndpoint {
    addr: SocketAddr,
    /// Fires once the stalled request's headers have been read server-side —
    /// the barrier proving the dispatch future was actually polled and put
    /// bytes on the wire before the test cancels.
    stalled_request_started: oneshot::Receiver<()>,
    /// Fires when the stalled connection reaches EOF. An unanswered request
    /// can never be pooled or reused, so the only way this socket closes is
    /// the in-flight transport future being dropped: a deterministic drop
    /// witness that does not depend on any timeout.
    stalled_connection_closed: oneshot::Receiver<()>,
    requests: Arc<AtomicUsize>,
    server: tokio::task::JoinHandle<()>,
}

async fn spawn_stalled_endpoint(preface: Vec<u16>) -> StalledEndpoint {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let server_requests = Arc::clone(&requests);
    let (started_tx, stalled_request_started) = oneshot::channel();
    let (closed_tx, stalled_connection_closed) = oneshot::channel();

    let server = tokio::spawn(async move {
        for status in preface {
            let (mut socket, _) = listener.accept().await.unwrap();
            read_request_headers(&mut socket).await;
            server_requests.fetch_add(1, Ordering::SeqCst);
            let response =
                format!("HTTP/1.1 {status} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            socket.write_all(response.as_bytes()).await.unwrap();
        }
        let (mut socket, _) = listener.accept().await.unwrap();
        read_request_headers(&mut socket).await;
        server_requests.fetch_add(1, Ordering::SeqCst);
        let _ = started_tx.send(());
        // Never respond. Drain until the peer hangs up.
        let mut buf = [0u8; 256];
        loop {
            match socket.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
        let _ = closed_tx.send(());
        // Keep serving so a post-cancellation retry is observable as an extra
        // counted request rather than a silent connection refusal.
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            read_request_headers(&mut socket).await;
            server_requests.fetch_add(1, Ordering::SeqCst);
        }
    });

    StalledEndpoint {
        addr,
        stalled_request_started,
        stalled_connection_closed,
        requests,
        server,
    }
}

/// Cancelling a generation must abandon an attempt that is stalled *inside*
/// the transport call, not merely one sitting between attempts. The endpoint
/// never responds, so before the fix the task stayed alive until the 60s
/// `PluginHttpClient` request timeout; every bound below is orders of
/// magnitude under that, so passing proves preemption rather than expiry.
#[tokio::test]
async fn reload_retirement_cancels_stalled_in_flight_dispatch_and_settles_abandoned_once() {
    let mut endpoint = spawn_stalled_endpoint(Vec::new()).await;
    let metrics = Arc::new(DeliveryMetrics::new());
    let generation = DispatchGeneration::with_metrics(99, Arc::clone(&metrics));
    let sem = Arc::new(Semaphore::new(1));
    let addr = endpoint.addr;
    let channel = webhook_channel_to(format!("http://{addr}/slow"));
    let settles = Arc::new(std::sync::Mutex::new(Vec::new()));
    let callback_settles = Arc::clone(&settles);
    let notification = Arc::new(fixed_notification());
    let extras: Arc<HashMap<String, String>> = Arc::new(HashMap::new());

    assert!(dispatch_one(
        Arc::clone(&notification),
        Arc::clone(&extras),
        channel,
        sem,
        PluginHttpClient::default(),
        Arc::clone(&generation),
        // A retry budget is configured on purpose: cancellation must also
        // suppress the retry this transient stall would otherwise earn.
        DeliveryRetryPolicy {
            max_retries: 3,
            base_delay: Duration::from_millis(10),
            max_delay: Duration::from_millis(20),
        },
        "test",
        Some(Arc::new(move |settle| {
            callback_settles
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(settle);
        })),
    ));

    timeout(Duration::from_secs(5), &mut endpoint.stalled_request_started)
        .await
        .expect("server must observe the live transport attempt before retirement")
        .expect("stall barrier sender must not be dropped");
    assert_eq!(generation.in_flight(), 1, "the attempt must be accounted");
    assert_eq!(metrics.channel_snapshot("webhook").in_flight, 1);

    generation.cancel();
    assert!(!generation.is_admitting());
    assert!(
        generation.wait_drain(Duration::from_secs(5)).await,
        "retirement must abandon a stalled attempt promptly, not wait out the transport timeout"
    );
    timeout(
        Duration::from_secs(5),
        &mut endpoint.stalled_connection_closed,
    )
    .await
    .expect("the cancelled dispatch future must be dropped, closing the stalled connection")
    .expect("close witness sender must not be dropped");

    let rejected = dispatch_one(
        Arc::new(fixed_notification()),
        Arc::new(Default::default()),
        webhook_channel_to(format!("http://{addr}/slow2")),
        Arc::new(Semaphore::new(8)),
        PluginHttpClient::default(),
        Arc::clone(&generation),
        DeliveryRetryPolicy::DEFAULT,
        "test",
        None,
    );
    assert!(!rejected, "retired generation must not admit new work");
    assert_eq!(
        endpoint.requests.load(Ordering::SeqCst),
        1,
        "a cancelled attempt must not be retried"
    );

    let snapshot = metrics.channel_snapshot("webhook");
    assert_eq!(snapshot.attempted, 1);
    assert_eq!(snapshot.abandoned_at_deadline, 1);
    assert_eq!(snapshot.succeeded, 0);
    assert_eq!(snapshot.failed_transient, 0);
    assert_eq!(snapshot.failed_permanent, 0);
    assert_eq!(snapshot.in_flight, 0);
    assert_eq!(generation.in_flight(), 0);
    assert_eq!(
        *settles
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()),
        vec![DispatchSettle::Abandoned],
        "retirement must roll producer state back exactly once"
    );
    // A drained generation means the dispatch future itself is gone, not just
    // that the transport returned: nothing still holds its captured payload.
    assert_eq!(Arc::strong_count(&notification), 1);
    assert_eq!(Arc::strong_count(&extras), 1);
    endpoint.server.abort();
}

/// The same preemption must hold for a *retried* attempt, so cancellation
/// cannot be escaped by a transient failure re-entering the transport.
#[tokio::test]
async fn retirement_cancels_stalled_retry_attempt_after_transient_failure() {
    let mut endpoint = spawn_stalled_endpoint(vec![503]).await;
    let metrics = Arc::new(DeliveryMetrics::new());
    let generation = DispatchGeneration::with_metrics(101, Arc::clone(&metrics));
    let settles = Arc::new(std::sync::Mutex::new(Vec::new()));
    let callback_settles = Arc::clone(&settles);
    let addr = endpoint.addr;

    assert!(dispatch_one(
        Arc::new(fixed_notification()),
        Arc::new(Default::default()),
        webhook_channel_to(format!("http://{addr}/retry-then-stall")),
        Arc::new(Semaphore::new(1)),
        PluginHttpClient::default(),
        Arc::clone(&generation),
        DeliveryRetryPolicy {
            max_retries: 5,
            base_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(5),
        },
        "test",
        Some(Arc::new(move |settle| {
            callback_settles
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(settle);
        })),
    ));

    timeout(Duration::from_secs(5), &mut endpoint.stalled_request_started)
        .await
        .expect("the retry attempt must reach the endpoint before retirement")
        .expect("stall barrier sender must not be dropped");
    assert_eq!(
        endpoint.requests.load(Ordering::SeqCst),
        2,
        "the transient 503 must have been retried before the stall"
    );

    generation.cancel();
    assert!(
        generation.wait_drain(Duration::from_secs(5)).await,
        "retirement must abandon a stalled retry attempt promptly"
    );
    timeout(
        Duration::from_secs(5),
        &mut endpoint.stalled_connection_closed,
    )
    .await
    .expect("the cancelled retry future must be dropped, closing the stalled connection")
    .expect("close witness sender must not be dropped");

    assert_eq!(
        endpoint.requests.load(Ordering::SeqCst),
        2,
        "cancellation must not schedule a further retry"
    );
    let snapshot = metrics.channel_snapshot("webhook");
    assert_eq!(snapshot.attempted, 1, "retries share one admitted task");
    assert_eq!(snapshot.abandoned_at_deadline, 1);
    assert_eq!(snapshot.failed_transient, 0);
    assert_eq!(snapshot.succeeded, 0);
    assert_eq!(snapshot.in_flight, 0);
    assert_eq!(
        *settles
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()),
        vec![DispatchSettle::Abandoned],
        "a cancelled retry must settle exactly once"
    );
    endpoint.server.abort();
}

/// The cancel signal is edge-triggered, so an in-flight attempt observes
/// retirement on a task wakeup rather than a polling cadence. Registration
/// happens before the flag re-read, so a cancel racing the waiter is not lost.
#[tokio::test]
async fn generation_cancelled_future_resolves_without_polling_cadence() {
    let generation = DispatchGeneration::new(5);
    let waiter = Arc::clone(&generation);
    let observed = tokio::spawn(async move {
        waiter.cancelled().await;
        waiter.is_cancelled()
    });

    // Not cancelled: the future must stay pending.
    assert!(
        timeout(Duration::from_millis(50), generation.cancelled())
            .await
            .is_err(),
        "a live generation must never resolve its cancel future"
    );

    generation.cancel();
    assert!(
        timeout(Duration::from_secs(2), observed)
            .await
            .expect("cancel must wake a registered waiter")
            .expect("waiter task must not panic"),
        "a woken waiter must observe the published cancel flag"
    );
    // Already cancelled: resolves immediately on the first poll.
    timeout(Duration::from_millis(500), generation.cancelled())
        .await
        .expect("an already-cancelled generation must resolve immediately");
}

#[tokio::test]
async fn proxy_alerts_drop_cancels_dispatch_generation() {
    let cfg = json!({
        "max_concurrent_dispatches": 1,
        "max_delivery_retries": 0,
        "channels": {
            "c": { "type": "webhook", "url": "http://127.0.0.1:9/alert", "body_template": "x" }
        },
        "rules": [
            { "name": "status", "type": "status_code_count",
              "status_codes": [500], "threshold_count": 1,
              "cooldown_seconds": 1, "channels": ["c"] }
        ]
    });
    let plugin = ProxyAlerts::new(&cfg, PluginHttpClient::default()).unwrap();
    plugin.cancel_dispatch_generation_for_test();
    assert_eq!(plugin.dispatch_in_flight_for_test(), 0);
}
