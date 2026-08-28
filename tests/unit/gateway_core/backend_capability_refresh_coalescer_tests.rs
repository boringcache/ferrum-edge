//! External coverage for `RefreshCoalescer` wakeup ordering and detached
//! runner ownership.
//!
//! Issues #4262 / #4263: `wait_until_idle` used to load flags before
//! registering on `Notify`, and `request()` handed out a bare bool with no
//! owner Drop. Those combine to freeze DP readiness and every later refresh.
//! Production now always detaches the drain loop so cancelling a caller
//! cannot cancel the runner; guard Drop is last-resort only.

use ferrum_edge::proxy::backend_capabilities::{
    RefreshCoalescer, RefreshRole, RefreshRunnerGuard, install_idle_wait_observe_hook,
};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Waker};

struct ClearIdleWaitHook;

impl Drop for ClearIdleWaitHook {
    fn drop(&mut self) {
        install_idle_wait_observe_hook(None);
    }
}

#[derive(Default)]
struct CountingWaker {
    wakes: AtomicUsize,
}

impl std::task::Wake for CountingWaker {
    fn wake(self: Arc<Self>) {
        self.wakes.fetch_add(1, Ordering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.wakes.fetch_add(1, Ordering::SeqCst);
    }
}

fn take_runner(coalescer: &Arc<RefreshCoalescer>) -> RefreshRunnerGuard {
    match coalescer.request() {
        RefreshRole::Runner(guard) => guard,
        RefreshRole::Joined => panic!("expected to acquire the runner role"),
    }
}

async fn drain_with_guard(coalescer: Arc<RefreshCoalescer>, mut guard: RefreshRunnerGuard) {
    loop {
        while coalescer.take_pending() {}
        if coalescer.try_finish() {
            coalescer.signal_idle();
            guard.disarm();
            break;
        }
    }
}

fn spawn_detached_probe(
    coalescer: Arc<RefreshCoalescer>,
    mut guard: RefreshRunnerGuard,
    started: Arc<AtomicBool>,
    mut release: tokio::sync::watch::Receiver<bool>,
    drained: Arc<AtomicUsize>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if coalescer.take_pending() {
            drained.fetch_add(1, Ordering::SeqCst);
            started.store(true, Ordering::Release);
            let _ = release.wait_for(|released| *released).await;
        }
        loop {
            while coalescer.take_pending() {
                drained.fetch_add(1, Ordering::SeqCst);
            }
            if coalescer.try_finish() {
                coalescer.signal_idle();
                guard.disarm();
                break;
            }
        }
    })
}

#[test]
fn wait_until_idle_cannot_lose_wakeup_between_register_and_recheck() {
    let _clear = ClearIdleWaitHook;
    let coalescer = Arc::new(RefreshCoalescer::new());
    let runner = take_runner(&coalescer);
    assert!(
        coalescer.take_pending(),
        "consume the request's pending flag"
    );
    let guard_slot = Arc::new(Mutex::new(Some(runner)));

    let hook_slot = Arc::clone(&guard_slot);
    install_idle_wait_observe_hook(Some(Arc::new(move || {
        drop(hook_slot.lock().expect("guard slot").take());
    })));

    let mut idle = std::pin::pin!(coalescer.wait_until_idle());
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    assert!(
        idle.as_mut().poll(&mut cx).is_ready(),
        "register-before-recheck must observe the idle transition that lands \
         after enable() and before the Acquire loads"
    );
    assert!(
        !coalescer.runner_is_active() && !coalescer.has_pending_refresh(),
        "cancelled owner must leave the coalescer idle when no rerun is queued"
    );
}

#[test]
fn wait_until_idle_wakes_a_parked_waiter_after_runner_finishes() {
    let coalescer = Arc::new(RefreshCoalescer::new());
    let runner = take_runner(&coalescer);
    assert!(coalescer.take_pending());

    let mut idle = std::pin::pin!(coalescer.wait_until_idle());
    let counter = Arc::new(CountingWaker::default());
    let waker = Waker::from(Arc::clone(&counter));
    let mut cx = Context::from_waker(&waker);
    assert!(
        idle.as_mut().poll(&mut cx).is_pending(),
        "waiter must park while a runner is active"
    );
    assert_eq!(counter.wakes.load(Ordering::SeqCst), 0);

    assert!(coalescer.try_finish());
    coalescer.signal_idle();
    runner.disarm();

    assert!(
        counter.wakes.load(Ordering::SeqCst) >= 1,
        "signal_idle must wake a waiter registered by the first poll"
    );
    assert!(
        idle.as_mut().poll(&mut cx).is_ready(),
        "parked wait_until_idle must resolve after the idle signal"
    );
}

#[tokio::test]
async fn dropping_a_runner_future_lets_a_later_request_reacquire() {
    let coalescer = Arc::new(RefreshCoalescer::new());
    let hold = Arc::new(tokio::sync::Notify::new());
    let hold_for_runner = Arc::clone(&hold);
    let runner_coalescer = Arc::clone(&coalescer);
    let started = Arc::new(AtomicBool::new(false));
    let started_for_runner = Arc::clone(&started);

    let runner = tokio::spawn(async move {
        let mut guard = take_runner(&runner_coalescer);
        assert!(runner_coalescer.take_pending());
        started_for_runner.store(true, Ordering::Release);
        hold_for_runner.notified().await;
        if runner_coalescer.try_finish() {
            runner_coalescer.signal_idle();
            guard.disarm();
        }
    });

    while !started.load(Ordering::Acquire) {
        tokio::task::yield_now().await;
    }

    let idle = tokio::spawn({
        let coalescer = Arc::clone(&coalescer);
        async move {
            coalescer.wait_until_idle().await;
        }
    });

    runner.abort();
    assert!(runner.await.unwrap_err().is_cancelled());

    let mut next = take_runner(&coalescer);
    assert!(
        coalescer.take_pending() || !coalescer.has_pending_refresh(),
        "cancelled owner must not freeze pending/running so a later request can run"
    );
    while coalescer.take_pending() {}
    assert!(coalescer.try_finish());
    coalescer.signal_idle();
    next.disarm();

    tokio::time::timeout(std::time::Duration::from_secs(2), idle)
        .await
        .expect("wait_until_idle hung after runner cancel + reacquire")
        .expect("idle waiter task");
    assert!(!coalescer.runner_is_active());
    assert!(!coalescer.has_pending_refresh());
}

#[tokio::test]
async fn aborting_the_caller_does_not_cancel_the_detached_runner() {
    let coalescer = Arc::new(RefreshCoalescer::new());
    let started = Arc::new(AtomicBool::new(false));
    let drained = Arc::new(AtomicUsize::new(0));
    let (release_tx, release_rx) = tokio::sync::watch::channel(false);
    let guard = take_runner(&coalescer);
    let owner = spawn_detached_probe(
        Arc::clone(&coalescer),
        guard,
        Arc::clone(&started),
        release_rx,
        Arc::clone(&drained),
    );

    while !started.load(Ordering::Acquire) {
        tokio::task::yield_now().await;
    }
    assert!(coalescer.runner_is_active());

    let caller = tokio::spawn({
        let coalescer = Arc::clone(&coalescer);
        async move {
            coalescer.wait_until_idle().await;
        }
    });
    caller.abort();
    assert!(
        caller.await.unwrap_err().is_cancelled(),
        "aborting the waiter must not be treated as runner completion"
    );
    assert!(
        coalescer.runner_is_active(),
        "detached drain loop must survive caller abort"
    );

    let joiner = tokio::spawn({
        let coalescer = Arc::clone(&coalescer);
        async move {
            coalescer.wait_until_idle().await;
        }
    });

    release_tx.send(true).expect("release detached probe");
    owner.await.expect("detached runner");

    tokio::time::timeout(std::time::Duration::from_secs(2), joiner)
        .await
        .expect("queued joiner stranded after detached drain")
        .expect("joiner task");
    assert!(drained.load(Ordering::SeqCst) >= 1);
    assert!(!coalescer.runner_is_active());
    assert!(!coalescer.has_pending_refresh());
}

#[tokio::test]
async fn queued_joiners_finish_after_detached_owner_drains() {
    let coalescer = Arc::new(RefreshCoalescer::new());
    let started = Arc::new(AtomicBool::new(false));
    let drained = Arc::new(AtomicUsize::new(0));
    let (release_tx, release_rx) = tokio::sync::watch::channel(false);
    let guard = take_runner(&coalescer);
    let owner = spawn_detached_probe(
        Arc::clone(&coalescer),
        guard,
        Arc::clone(&started),
        release_rx,
        Arc::clone(&drained),
    );

    while !started.load(Ordering::Acquire) {
        tokio::task::yield_now().await;
    }
    assert!(matches!(coalescer.request(), RefreshRole::Joined));
    assert!(coalescer.has_pending_refresh());

    let mut joiners = Vec::new();
    for _ in 0..8 {
        let coalescer = Arc::clone(&coalescer);
        joiners.push(tokio::spawn(async move {
            coalescer.wait_until_idle().await;
        }));
    }

    release_tx.send(true).expect("release detached probe");
    owner.await.expect("detached owner");

    for joiner in joiners {
        tokio::time::timeout(std::time::Duration::from_secs(2), joiner)
            .await
            .expect("queued joiner hung")
            .expect("joiner task");
    }
    assert!(
        drained.load(Ordering::SeqCst) >= 2,
        "detached owner must drain the coalesced pending rerun"
    );
    assert!(!coalescer.runner_is_active());
    assert!(!coalescer.has_pending_refresh());
}

#[tokio::test]
async fn cancel_with_pending_checked_fallback_lets_next_request_unstrand_joiners() {
    let coalescer = Arc::new(RefreshCoalescer::new());
    let mut runner = take_runner(&coalescer);
    assert!(coalescer.take_pending());
    assert!(matches!(coalescer.request(), RefreshRole::Joined));

    let joiner = tokio::spawn({
        let coalescer = Arc::clone(&coalescer);
        async move {
            coalescer.wait_until_idle().await;
        }
    });

    drop(runner);
    assert!(
        !coalescer.runner_is_active(),
        "checked cancel transition must clear running"
    );
    assert!(
        coalescer.has_pending_refresh(),
        "checked cancel must not drop the queued rerun"
    );

    let next = take_runner(&coalescer);
    drain_with_guard(Arc::clone(&coalescer), next).await;

    tokio::time::timeout(std::time::Duration::from_secs(2), joiner)
        .await
        .expect("joiner stranded after checked pending cancel")
        .expect("joiner task");
}

#[test]
fn last_resort_guard_drop_without_runtime_does_not_spawn() {
    let coalescer = Arc::new(RefreshCoalescer::new());
    let runner = take_runner(&coalescer);
    assert!(matches!(coalescer.request(), RefreshRole::Joined));
    // No Tokio runtime: Drop must not call `tokio::spawn`.
    drop(runner);
    assert!(
        !coalescer.runner_is_active(),
        "last-resort Drop must release running"
    );
    assert!(
        coalescer.has_pending_refresh(),
        "queued pending must survive last-resort Drop"
    );

    let mut next = take_runner(&coalescer);
    while coalescer.take_pending() {}
    assert!(coalescer.try_finish());
    coalescer.signal_idle();
    next.disarm();
    assert!(!coalescer.runner_is_active());
    assert!(!coalescer.has_pending_refresh());
}

#[test]
fn guard_drop_during_runtime_teardown_does_not_recursively_spawn() {
    let coalescer = Arc::new(RefreshCoalescer::new());
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on({
        let coalescer = Arc::clone(&coalescer);
        async move {
            let guard = take_runner(&coalescer);
            assert!(matches!(coalescer.request(), RefreshRole::Joined));
            let parked = Arc::new(tokio::sync::Notify::new());
            let parked_for_task = Arc::clone(&parked);
            tokio::spawn(async move {
                let _guard = guard;
                parked_for_task.notified().await;
            });
        }
    });
    drop(runtime);

    assert!(
        !coalescer.runner_is_active(),
        "runtime teardown must release running without re-arming a runner"
    );
    assert!(
        coalescer.has_pending_refresh(),
        "queued pending must survive cross-thread teardown Drop"
    );

    let mut next = take_runner(&coalescer);
    while coalescer.take_pending() {}
    assert!(coalescer.try_finish());
    coalescer.signal_idle();
    next.disarm();
    assert!(!coalescer.runner_is_active());
    assert!(!coalescer.has_pending_refresh());
}

#[tokio::test]
async fn concurrent_requests_coalesce_to_one_runner_and_one_pending() {
    let coalescer = Arc::new(RefreshCoalescer::new());
    let runners = Arc::new(AtomicUsize::new(0));
    let drains = Arc::new(AtomicUsize::new(0));

    let mut joiners = Vec::new();
    let mut first_guard = None;
    for _ in 0..16 {
        match coalescer.request() {
            RefreshRole::Runner(guard) => {
                runners.fetch_add(1, Ordering::SeqCst);
                first_guard = Some(guard);
            }
            RefreshRole::Joined => {}
        }
        let coalescer = Arc::clone(&coalescer);
        joiners.push(tokio::spawn(async move {
            coalescer.wait_until_idle().await;
        }));
    }
    assert_eq!(runners.load(Ordering::SeqCst), 1, "at most one runner");
    assert!(coalescer.has_pending_refresh() || coalescer.runner_is_active());

    let mut guard = first_guard.expect("one request must become runner");
    let parked = Arc::new(tokio::sync::Notify::new());
    let parked_for_loop = Arc::clone(&parked);
    let release = Arc::new(tokio::sync::Notify::new());
    let release_for_loop = Arc::clone(&release);
    let loop_coalescer = Arc::clone(&coalescer);
    let drains_for_loop = Arc::clone(&drains);
    let owner = tokio::spawn(async move {
        loop {
            while loop_coalescer.take_pending() {
                drains_for_loop.fetch_add(1, Ordering::SeqCst);
                parked_for_loop.notify_one();
                release_for_loop.notified().await;
            }
            if loop_coalescer.try_finish() {
                loop_coalescer.signal_idle();
                guard.disarm();
                break;
            }
        }
    });

    parked.notified().await;
    release.notify_one();
    owner.await.expect("runner loop");

    for joiner in joiners {
        tokio::time::timeout(std::time::Duration::from_secs(2), joiner)
            .await
            .expect("coalesced joiner hung")
            .expect("joiner task");
    }
    assert!(drains.load(Ordering::SeqCst) >= 1);
    assert!(
        drains.load(Ordering::SeqCst) <= 2,
        "at most one pending rerun"
    );
    assert!(!coalescer.runner_is_active());
    assert!(!coalescer.has_pending_refresh());
}

#[test]
fn request_role_is_unambiguous() {
    let coalescer = Arc::new(RefreshCoalescer::new());
    let runner = coalescer.request();
    assert!(runner.is_runner());
    assert!(
        matches!(&runner, RefreshRole::Runner(_)),
        "match by reference so the live guard is not dropped"
    );
    let joined = coalescer.request();
    assert!(!joined.is_runner());
    assert!(matches!(joined, RefreshRole::Joined));

    let mut guard = match runner {
        RefreshRole::Runner(guard) => guard,
        RefreshRole::Joined => panic!("first request must remain the runner"),
    };
    while coalescer.take_pending() {}
    assert!(coalescer.try_finish());
    coalescer.signal_idle();
    guard.disarm();
    assert!(!coalescer.runner_is_active());
    assert!(!coalescer.has_pending_refresh());
}
