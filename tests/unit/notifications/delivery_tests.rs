//! Deterministic delivery-lifecycle tests for notification dispatch +
//! proxy_alerts pending-state / generation retirement contracts (#2448).

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
use tokio::sync::{Notify, Semaphore};
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

#[tokio::test]
async fn reload_retirement_drain_times_out_then_settles_abandoned_once() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    // Accept but never respond — keep the dispatch in-flight.
    let request_started = Arc::new(Notify::new());
    let request_started_on_server = Arc::clone(&request_started);
    let blocker = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        read_request_headers(&mut socket).await;
        request_started_on_server.notify_one();
        tokio::time::sleep(Duration::from_secs(30)).await;
    });

    let metrics = Arc::new(DeliveryMetrics::new());
    let generation = DispatchGeneration::with_metrics(99, Arc::clone(&metrics));
    let sem = Arc::new(Semaphore::new(1));
    let channel = webhook_channel_to(format!("http://{addr}/slow"));
    let settles = Arc::new(std::sync::Mutex::new(Vec::new()));
    let callback_settles = Arc::clone(&settles);

    assert!(dispatch_one(
        Arc::new(fixed_notification()),
        Arc::new(Default::default()),
        channel,
        sem,
        PluginHttpClient::default(),
        Arc::clone(&generation),
        DeliveryRetryPolicy {
            max_retries: 0,
            ..DeliveryRetryPolicy::DEFAULT
        },
        "test",
        Some(Arc::new(move |settle| {
            callback_settles
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(settle);
        })),
    ));

    timeout(Duration::from_secs(2), request_started.notified())
    .await
    .expect("server must observe the live transport attempt before retirement");

    generation.cancel();
    assert!(!generation.is_admitting());
    assert!(
        !generation.wait_drain(Duration::from_millis(25)).await,
        "a live transport attempt must report a bounded drain timeout"
    );
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
    blocker.abort();
    assert!(
        generation.wait_drain(Duration::from_secs(2)).await,
        "closing the in-flight transport must complete generation drain"
    );
    let snapshot = metrics.channel_snapshot("webhook");
    assert_eq!(snapshot.abandoned_at_deadline, 1);
    assert_eq!(snapshot.in_flight, 0);
    assert_eq!(
        *settles
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()),
        vec![DispatchSettle::Abandoned],
        "retirement must roll producer state back exactly once"
    );
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
