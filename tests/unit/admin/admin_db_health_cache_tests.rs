//! Concurrency coverage for the single-flight DB health cache behind
//! `/health` and `/status`: many simultaneous cold/expired-cache callers must
//! collapse to one backend probe per refresh window, fresh-cache hits must not
//! probe at all, and a hung probe must be abandoned at the explicit timeout.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use ferrum_edge::admin::{CachedDbHealthResult, cached_db_health_connected};

/// Deliberately generous relative to the work each test performs: the
/// assertions below count probes, never elapsed time, so a wide freshness
/// window only removes the chance that runner preemption between two bursts
/// expires an entry the test expects to still be fresh.
const TTL: Duration = Duration::from_secs(2);
const PROBE_TIMEOUT: Duration = Duration::from_secs(4);

type HealthCache = ArcSwap<Option<CachedDbHealthResult>>;

struct DropFlag(Arc<AtomicBool>);

impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

async fn ok_probe(probe_calls: Arc<AtomicUsize>, latency: Duration) -> Result<(), std::io::Error> {
    probe_calls.fetch_add(1, Ordering::SeqCst);
    tokio::time::sleep(latency).await;
    Ok(())
}

async fn burst(
    cache: &HealthCache,
    refresh_lock: &tokio::sync::Mutex<()>,
    factory_calls: &Arc<AtomicUsize>,
    probe_calls: &Arc<AtomicUsize>,
) {
    let results = futures::future::join_all((0..8).map(|_| {
        let factory_calls = Arc::clone(factory_calls);
        let probe_calls = Arc::clone(probe_calls);
        cached_db_health_connected(cache, refresh_lock, TTL, PROBE_TIMEOUT, move || {
            factory_calls.fetch_add(1, Ordering::SeqCst);
            ok_probe(probe_calls, Duration::ZERO)
        })
    }))
    .await;
    assert!(results.iter().all(|connected| *connected));
}

#[tokio::test]
async fn concurrent_cold_cache_callers_share_one_probe() {
    let cache: HealthCache = ArcSwap::new(Arc::new(None));
    let refresh_lock = tokio::sync::Mutex::new(());
    let factory_calls = Arc::new(AtomicUsize::new(0));
    let probe_calls = Arc::new(AtomicUsize::new(0));

    let results = futures::future::join_all((0..16).map(|_| {
        let factory_calls = Arc::clone(&factory_calls);
        let probe_calls = Arc::clone(&probe_calls);
        cached_db_health_connected(
            &cache,
            &refresh_lock,
            TTL,
            PROBE_TIMEOUT,
            // Slow enough that every caller observes the empty cache before
            // the first refresh completes.
            move || {
                factory_calls.fetch_add(1, Ordering::SeqCst);
                ok_probe(probe_calls, Duration::from_millis(100))
            },
        )
    }))
    .await;

    assert!(results.iter().all(|connected| *connected));
    assert_eq!(
        factory_calls.load(Ordering::SeqCst),
        1,
        "only the refresh owner may invoke its lazy probe factory"
    );
    assert_eq!(
        probe_calls.load(Ordering::SeqCst),
        1,
        "16 concurrent cold-cache callers must collapse to one probe"
    );

    // A follow-up burst within the TTL is served from the fresh cache and
    // never constructs a boxed async-trait probe future or reaches the database.
    burst(&cache, &refresh_lock, &factory_calls, &probe_calls).await;
    burst(&cache, &refresh_lock, &factory_calls, &probe_calls).await;
    assert_eq!(
        factory_calls.load(Ordering::SeqCst),
        1,
        "fresh-cache hits must not invoke the probe factory"
    );
    assert_eq!(
        probe_calls.load(Ordering::SeqCst),
        1,
        "fresh-cache hits must not probe"
    );
}

#[tokio::test]
async fn expired_cache_refreshes_once_per_window() {
    let cache: HealthCache = ArcSwap::new(Arc::new(None));
    let refresh_lock = tokio::sync::Mutex::new(());
    let factory_calls = Arc::new(AtomicUsize::new(0));
    let probe_calls = Arc::new(AtomicUsize::new(0));

    // First window: cold cache elects a single refresher.
    burst(&cache, &refresh_lock, &factory_calls, &probe_calls).await;
    assert_eq!(factory_calls.load(Ordering::SeqCst), 1);
    assert_eq!(probe_calls.load(Ordering::SeqCst), 1);

    // Let the entry expire, then confirm the next burst runs exactly one
    // refresh for the new window.
    tokio::time::sleep(TTL * 2).await;
    burst(&cache, &refresh_lock, &factory_calls, &probe_calls).await;
    assert_eq!(factory_calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        probe_calls.load(Ordering::SeqCst),
        2,
        "an expired entry must refresh exactly once per window"
    );

    // The refreshed entry is immediately fresh again.
    burst(&cache, &refresh_lock, &factory_calls, &probe_calls).await;
    assert_eq!(factory_calls.load(Ordering::SeqCst), 2);
    assert_eq!(probe_calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn failed_probe_caches_failure_for_the_window() {
    let cache: HealthCache = ArcSwap::new(Arc::new(None));
    let refresh_lock = tokio::sync::Mutex::new(());
    let probe_calls = Arc::new(AtomicUsize::new(0));

    let failing_probe = |probe_calls: Arc<AtomicUsize>| async move {
        probe_calls.fetch_add(1, Ordering::SeqCst);
        Err(std::io::Error::other("database unreachable"))
    };

    let results = futures::future::join_all((0..8).map(|_| {
        let probe_calls = Arc::clone(&probe_calls);
        cached_db_health_connected(&cache, &refresh_lock, TTL, PROBE_TIMEOUT, move || {
            failing_probe(probe_calls)
        })
    }))
    .await;
    assert!(results.iter().all(|connected| !*connected));
    assert_eq!(probe_calls.load(Ordering::SeqCst), 1);

    // The failure result is cached like a success: callers within the window
    // get the coarse not-connected signal without re-hitting the database.
    let results = futures::future::join_all((0..8).map(|_| {
        let probe_calls = Arc::clone(&probe_calls);
        cached_db_health_connected(&cache, &refresh_lock, TTL, PROBE_TIMEOUT, move || {
            failing_probe(probe_calls)
        })
    }))
    .await;
    assert!(results.iter().all(|connected| !*connected));
    assert_eq!(probe_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn hung_probe_is_abandoned_at_the_timeout() {
    let cache: HealthCache = ArcSwap::new(Arc::new(None));
    let refresh_lock = tokio::sync::Mutex::new(());
    let probe_calls = Arc::new(AtomicUsize::new(0));
    let probe_cancelled = Arc::new(AtomicBool::new(false));
    let probe_timeout = Duration::from_millis(100);

    let started = tokio::time::Instant::now();
    let probe_calls_for_factory = Arc::clone(&probe_calls);
    let probe_cancelled_for_factory = Arc::clone(&probe_cancelled);
    let connected = cached_db_health_connected(
        &cache,
        &refresh_lock,
        TTL,
        probe_timeout,
        move || async move {
            probe_calls_for_factory.fetch_add(1, Ordering::SeqCst);
            let _drop_flag = DropFlag(probe_cancelled_for_factory);
            std::future::pending::<Result<(), std::io::Error>>().await
        },
    )
    .await;

    assert!(!connected, "a hung probe must report not-connected");
    assert_eq!(probe_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        started.elapsed(),
        probe_timeout,
        "paused time must advance by exactly the configured per-call timeout"
    );
    assert!(
        probe_cancelled.load(Ordering::SeqCst),
        "timing out must drop and cancel the in-flight probe future"
    );

    // The timeout outcome is cached for the window, so a follow-up caller is
    // answered without another doomed probe.
    let connected = cached_db_health_connected(&cache, &refresh_lock, TTL, PROBE_TIMEOUT, || {
        ok_probe(Arc::clone(&probe_calls), Duration::ZERO)
    })
    .await;
    assert!(!connected);
    assert_eq!(probe_calls.load(Ordering::SeqCst), 1);
}
