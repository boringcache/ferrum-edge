//! Service-discovery task lifecycle integration coverage
//! (issues #3717 / #3721 / #3722).
//!
//! Exercises the production supervisor, reconcile keep/replace decisions, and
//! the bounded-staleness expiry policy against the live `LoadBalancerCache`.
//!
//! The discovery health registry is process-global, so every test here runs
//! under one serializing mutex and resets the registry before it starts.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use ferrum_edge::config::types::{
    GatewayConfig, LoadBalancerAlgorithm, MeshSdConfig, SdProvider, SdStalePolicy,
    ServiceDiscoveryConfig, Upstream, UpstreamTarget, default_namespace,
};
use ferrum_edge::consumer_index::ConsumerIndex;
use ferrum_edge::dns::DnsCache;
use ferrum_edge::health_check::HealthChecker;
use ferrum_edge::load_balancer::LoadBalancerCache;
use ferrum_edge::plugin_cache::PluginCache;
use ferrum_edge::plugins::PluginHttpClient;
use ferrum_edge::request_epoch::RequestEpochStore;
use ferrum_edge::service_discovery::health;
use ferrum_edge::service_discovery::{
    DiscoverySnapshot, ServiceDiscoverer, ServiceDiscoveryManager,
    spawn_supervised_discovery_task_for_test,
};

/// The health registry and the Prometheus registry are process-global.
static REGISTRY_GUARD: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn isolated() -> tokio::sync::MutexGuard<'static, ()> {
    let guard = REGISTRY_GUARD.lock().await;
    health::reset_for_test();
    guard
}

// ── Fixtures ──────────────────────────────────────────────────────────

fn target(host: &str, port: u16) -> UpstreamTarget {
    UpstreamTarget {
        host: host.to_string(),
        port,
        service_port_policy_key: None,
        weight: 1,
        tags: HashMap::new(),
        locality: None,
        path: None,
    }
}

fn mesh_sd_config(service_name: &str, poll_interval_seconds: u64) -> ServiceDiscoveryConfig {
    ServiceDiscoveryConfig {
        provider: SdProvider::Mesh,
        dns_sd: None,
        kubernetes: None,
        consul: None,
        mesh: Some(MeshSdConfig {
            service_name: service_name.to_string(),
            namespace: None,
            port: Some(8080),
            poll_interval_seconds,
            topology: Default::default(),
        }),
        default_weight: 1,
        max_stale_seconds: None,
        stale_policy: None,
    }
}

fn upstream_with_sd(
    id: &str,
    static_targets: Vec<UpstreamTarget>,
    sd: Option<ServiceDiscoveryConfig>,
) -> Upstream {
    Upstream {
        id: id.to_string(),
        namespace: default_namespace(),
        name: None,
        targets: static_targets,
        algorithm: LoadBalancerAlgorithm::RoundRobin,
        hash_on: None,
        hash_on_cookie_config: None,
        health_checks: None,
        service_discovery: sd,
        subsets: None,
        port_overrides: HashMap::new(),
        source_locality: None,
        source_labels: Default::default(),
        locality_lb_strict: false,
        locality_lb_setting: None,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        backend_tls_sni: None,
        backend_tls_san_allow_list: Vec::new(),
        resolved_subset_tls: HashMap::new(),
        dispatch_port_override_fallback: None,
        api_spec_id: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

fn config_with(upstreams: Vec<Upstream>) -> GatewayConfig {
    GatewayConfig {
        upstreams,
        ..Default::default()
    }
}

fn epoch_store(config: &GatewayConfig) -> Arc<RequestEpochStore> {
    let plugin_cache = PluginCache::new(config).expect("plugin cache");
    let consumer_index = ConsumerIndex::new(&config.consumers);
    let lb_cache = LoadBalancerCache::new(config);
    Arc::new(RequestEpochStore::from_runtime_parts(
        config.clone(),
        &plugin_cache,
        &consumer_index,
        &lb_cache,
    ))
}

fn manager(config: &GatewayConfig) -> ServiceDiscoveryManager {
    ServiceDiscoveryManager::new(
        Arc::new(LoadBalancerCache::new(config)),
        DnsCache::new(Default::default()),
        Arc::new(HealthChecker::new()),
        PluginHttpClient::default(),
        Some(epoch_store(config)),
    )
}

fn task_key(id: &str) -> String {
    format!("{}|{}", default_namespace(), id)
}

/// Hosts currently installed in the load balancer for `id`.
fn lb_hosts(lb_cache: &LoadBalancerCache, id: &str) -> Vec<String> {
    lb_cache
        .get_upstream(&default_namespace(), id)
        .map(|upstream| {
            upstream
                .targets
                .iter()
                .map(|target| target.host.clone())
                .collect()
        })
        .unwrap_or_default()
}

/// Discoverer under full test control: it can return targets, fail, or panic.
struct ScriptedDiscoverer {
    calls: Arc<AtomicU64>,
    targets: std::sync::Mutex<Vec<UpstreamTarget>>,
    fail: Arc<AtomicBool>,
    hang: Arc<AtomicBool>,
    panic_until_call: u64,
}

impl ScriptedDiscoverer {
    fn new(targets: Vec<UpstreamTarget>) -> Self {
        Self {
            calls: Arc::new(AtomicU64::new(0)),
            targets: std::sync::Mutex::new(targets),
            fail: Arc::new(AtomicBool::new(false)),
            hang: Arc::new(AtomicBool::new(false)),
            panic_until_call: 0,
        }
    }

    fn panicking(panic_until_call: u64) -> Self {
        Self {
            panic_until_call,
            ..Self::new(vec![target("recovered.local", 8080)])
        }
    }
}

#[async_trait::async_trait]
impl ServiceDiscoverer for ScriptedDiscoverer {
    async fn discover(&self) -> Result<DiscoverySnapshot, anyhow::Error> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if call <= self.panic_until_call {
            panic!("scripted discovery panic on call {call}");
        }
        if self.fail.load(Ordering::SeqCst) {
            return Err(anyhow::anyhow!("scripted discovery failure"));
        }
        if self.hang.load(Ordering::SeqCst) {
            std::future::pending::<()>().await;
        }
        let targets = self.targets.lock().expect("targets lock").clone();
        Ok(DiscoverySnapshot::from_targets(targets))
    }

    fn provider_name(&self) -> &str {
        "scripted"
    }
}

async fn wait_for(mut predicate: impl FnMut() -> bool) -> bool {
    for _ in 0..600 {
        if predicate() {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    predicate()
}

// ── #3722: reconcile keeps unchanged tasks ────────────────────────────

#[tokio::test]
async fn reconcile_keeps_unchanged_discovery_tasks() {
    let _guard = isolated().await;

    let config = config_with(vec![
        upstream_with_sd("keep-me", Vec::new(), Some(mesh_sd_config("svc-a", 30))),
        upstream_with_sd("keep-me-too", Vec::new(), Some(mesh_sd_config("svc-b", 30))),
    ]);
    let manager = manager(&config);
    manager.start(&config, None);

    let first = health::generation_for_test(&task_key("keep-me")).expect("task registered");
    let second = health::generation_for_test(&task_key("keep-me-too")).expect("task registered");

    // An unrelated reconcile of an identical config must not churn the pollers:
    // restarting them would drop provider cursors and re-hit every registry.
    manager.reconcile(&config, None);

    assert_eq!(
        health::generation_for_test(&task_key("keep-me")),
        Some(first),
        "an unchanged upstream must keep its running task generation"
    );
    assert_eq!(
        health::generation_for_test(&task_key("keep-me-too")),
        Some(second)
    );

    manager.stop();
}

#[tokio::test]
async fn reconcile_replaces_only_the_upstream_whose_discovery_config_changed() {
    let _guard = isolated().await;

    let config = config_with(vec![
        upstream_with_sd("stable", Vec::new(), Some(mesh_sd_config("svc-a", 30))),
        upstream_with_sd("churned", Vec::new(), Some(mesh_sd_config("svc-b", 30))),
    ]);
    let manager = manager(&config);
    manager.start(&config, None);

    let stable = health::generation_for_test(&task_key("stable")).expect("task registered");
    let churned = health::generation_for_test(&task_key("churned")).expect("task registered");

    let changed = config_with(vec![
        upstream_with_sd("stable", Vec::new(), Some(mesh_sd_config("svc-a", 30))),
        // Only the poll interval moves.
        upstream_with_sd("churned", Vec::new(), Some(mesh_sd_config("svc-b", 15))),
    ]);
    manager.reconcile(&changed, None);

    assert_eq!(
        health::generation_for_test(&task_key("stable")),
        Some(stable),
        "an untouched upstream must not be restarted by another upstream's change"
    );
    assert_ne!(
        health::generation_for_test(&task_key("churned")),
        Some(churned),
        "a changed discovery configuration must replace exactly that task"
    );

    manager.stop();
}

#[tokio::test]
async fn reconcile_replaces_a_task_whose_static_targets_changed() {
    let _guard = isolated().await;

    let config = config_with(vec![upstream_with_sd(
        "mixed",
        vec![target("static-a.local", 8080)],
        Some(mesh_sd_config("svc-a", 30)),
    )]);
    let manager = manager(&config);
    manager.start(&config, None);
    let before = health::generation_for_test(&task_key("mixed")).expect("task registered");

    // Static targets are merged under every published snapshot, so they are part
    // of the task's material specification.
    let changed = config_with(vec![upstream_with_sd(
        "mixed",
        vec![target("static-b.local", 8080)],
        Some(mesh_sd_config("svc-a", 30)),
    )]);
    manager.reconcile(&changed, None);

    assert_ne!(
        health::generation_for_test(&task_key("mixed")),
        Some(before)
    );

    manager.stop();
}

#[tokio::test]
async fn reconcile_stops_only_the_removed_upstream() {
    let _guard = isolated().await;

    let config = config_with(vec![
        upstream_with_sd("kept", Vec::new(), Some(mesh_sd_config("svc-a", 30))),
        upstream_with_sd("removed", Vec::new(), Some(mesh_sd_config("svc-b", 30))),
    ]);
    let manager = manager(&config);
    manager.start(&config, None);
    let kept = health::generation_for_test(&task_key("kept")).expect("task registered");
    assert!(health::generation_for_test(&task_key("removed")).is_some());

    let reduced = config_with(vec![upstream_with_sd(
        "kept",
        Vec::new(),
        Some(mesh_sd_config("svc-a", 30)),
    )]);
    manager.reconcile(&reduced, None);

    assert_eq!(health::generation_for_test(&task_key("kept")), Some(kept));
    assert!(
        wait_for(|| health::generation_for_test(&task_key("removed")).is_none()).await,
        "a removed upstream's task must be stopped and deregistered"
    );

    manager.stop();
}

// ── #3721: supervision ────────────────────────────────────────────────

#[tokio::test]
async fn a_panicking_poller_is_restarted_and_recovers() {
    let _guard = isolated().await;

    let config = config_with(vec![upstream_with_sd("supervised", Vec::new(), None)]);
    let lb_cache = Arc::new(LoadBalancerCache::new(&config));
    let discoverer = Arc::new(ScriptedDiscoverer::panicking(1));
    let calls = Arc::clone(&discoverer.calls);
    let metrics = ferrum_edge::plugins::prometheus_metrics::global_registry();
    let panics_before = metrics.service_discovery_task_panics_total();
    let restarts_before = metrics.service_discovery_task_restarts_total();

    let task = spawn_supervised_discovery_task_for_test(
        &default_namespace(),
        "supervised",
        "scripted",
        discoverer,
        Arc::clone(&lb_cache),
        None,
        Arc::new(HealthChecker::new()),
        DnsCache::new(Default::default()),
        Vec::new(),
        LoadBalancerAlgorithm::RoundRobin,
        1,
        60,
        SdStalePolicy::Withdraw,
        1,
    );

    // The first poll panics; the supervisor must restart the poller and the
    // second poll must publish.
    assert!(
        wait_for(|| calls.load(Ordering::SeqCst) >= 2).await,
        "supervisor did not restart the poller after a panic"
    );
    assert!(
        wait_for(|| {
            health::snapshot()
                .upstreams
                .iter()
                .any(|u| u.upstream == task.key && u.restarts >= 1)
        })
        .await,
        "the restart must be visible in per-upstream health"
    );

    assert!(
        metrics.service_discovery_task_panics_total() > panics_before,
        "a panicking poller must be counted as a panic, not a graceful stop"
    );
    assert!(metrics.service_discovery_task_restarts_total() > restarts_before);

    let status = health::snapshot()
        .upstreams
        .into_iter()
        .find(|u| u.upstream == task.key)
        .expect("task health present");
    assert_ne!(
        status.state, "stopped",
        "a restarted poller must not be reported as stopped"
    );

    let _ = task.cancel_tx.send(true);
    let _ = task.handle.await;
}

#[tokio::test]
async fn a_clean_cancel_is_not_counted_as_a_crash() {
    let _guard = isolated().await;

    let config = config_with(vec![upstream_with_sd("cancelled", Vec::new(), None)]);
    let lb_cache = Arc::new(LoadBalancerCache::new(&config));
    let metrics = ferrum_edge::plugins::prometheus_metrics::global_registry();
    let panics_before = metrics.service_discovery_task_panics_total();
    let restarts_before = metrics.service_discovery_task_restarts_total();

    let task = spawn_supervised_discovery_task_for_test(
        &default_namespace(),
        "cancelled",
        "scripted",
        Arc::new(ScriptedDiscoverer::new(vec![target("a.local", 8080)])),
        lb_cache,
        None,
        Arc::new(HealthChecker::new()),
        DnsCache::new(Default::default()),
        Vec::new(),
        LoadBalancerAlgorithm::RoundRobin,
        1,
        60,
        SdStalePolicy::Withdraw,
        7,
    );

    let _ = task.cancel_tx.send(true);
    task.handle
        .await
        .expect("supervisor exits cleanly on cancel");

    assert_eq!(
        metrics.service_discovery_task_panics_total(),
        panics_before,
        "cancellation must not increment the panic counter"
    );
    assert_eq!(
        metrics.service_discovery_task_restarts_total(),
        restarts_before,
        "cancellation must not increment the restart counter"
    );
}

#[tokio::test]
async fn a_superseded_generation_neither_restarts_nor_publishes() {
    let _guard = isolated().await;

    let config = config_with(vec![upstream_with_sd("superseded", Vec::new(), None)]);
    let lb_cache = Arc::new(LoadBalancerCache::new(&config));
    let discoverer = Arc::new(ScriptedDiscoverer::panicking(u64::MAX));
    let calls = Arc::clone(&discoverer.calls);

    let task = spawn_supervised_discovery_task_for_test(
        &default_namespace(),
        "superseded",
        "scripted",
        discoverer,
        lb_cache,
        None,
        Arc::new(HealthChecker::new()),
        DnsCache::new(Default::default()),
        Vec::new(),
        LoadBalancerAlgorithm::RoundRobin,
        1,
        60,
        SdStalePolicy::Withdraw,
        1,
    );

    assert!(
        wait_for(|| calls.load(Ordering::SeqCst) >= 1).await,
        "poller never ran"
    );

    // A reconcile registers a newer generation under the same key while the old
    // supervisor is inside its restart backoff.
    health::register_task_for_test(
        &task.key,
        99,
        "scripted",
        health::resolve_staleness(60, SdStalePolicy::Withdraw, 1),
    );

    task.handle
        .await
        .expect("superseded supervisor exits instead of restarting");

    assert_eq!(
        health::generation_for_test(&task.key),
        Some(99),
        "the superseded supervisor must not have overwritten the newer generation"
    );
}

// ── #3721: the publication fence ──────────────────────────────────────
//
// The invariant is stronger than "check ownership before publishing": a bare
// check followed by a publication leaves a window in which a reconcile can
// register the replacement generation, after which the superseded task still
// overwrites the replacement's load-balancer / request-epoch state. These tests
// pin the atomicity of the check and the publication.

fn scripted_staleness() -> health::DiscoveryStaleness {
    health::resolve_staleness(60, SdStalePolicy::Withdraw, 1)
}

/// Spin until `predicate` holds. Used only to hand off between the fence
/// holder and the thread standing in for a reconcile.
fn spin_until(predicate: impl Fn() -> bool) {
    while !predicate() {
        std::thread::yield_now();
    }
}

#[tokio::test]
async fn a_replacement_generation_cannot_register_between_the_fence_check_and_the_publish() {
    let _guard = isolated().await;

    let key = task_key("fenced-publish");
    health::register_task_for_test(&key, 1, "scripted", scripted_staleness());

    let entered = Arc::new(AtomicBool::new(false));
    let replacement_started = Arc::new(AtomicBool::new(false));
    let published = Arc::new(AtomicBool::new(false));

    let holder = {
        let key = key.clone();
        let entered = Arc::clone(&entered);
        let replacement_started = Arc::clone(&replacement_started);
        let published = Arc::clone(&published);
        std::thread::spawn(move || {
            health::publish_under_fence_for_test(&key, 1, || {
                entered.store(true, Ordering::SeqCst);
                // Hold the fence across the whole window in which a reconcile
                // tries to install the replacement generation.
                spin_until(|| replacement_started.load(Ordering::SeqCst));
                std::thread::sleep(std::time::Duration::from_millis(200));
                published.store(true, Ordering::SeqCst);
            })
            .is_some()
        })
    };

    spin_until(|| entered.load(Ordering::SeqCst));
    replacement_started.store(true, Ordering::SeqCst);
    // Stands in for the reconcile that registers the replacement. It must not
    // be able to complete while the superseded generation is mid-publication.
    health::register_task_for_test(&key, 2, "scripted", scripted_staleness());

    assert!(
        published.load(Ordering::SeqCst),
        "a replacement generation registered while the fenced publication was still running; \
         the ownership check and the publication are not atomic"
    );
    assert!(
        holder.join().expect("fence thread"),
        "the fence must admit the generation that still owned the key"
    );
    assert_eq!(health::generation_for_test(&key), Some(2));

    // Past the replacement, the superseded generation is refused outright.
    let ran = Arc::new(AtomicBool::new(false));
    let refused = health::publish_under_fence_for_test(&key, 1, || {
        ran.store(true, Ordering::SeqCst);
    });
    assert!(refused.is_none(), "a superseded generation must be refused");
    assert!(
        !ran.load(Ordering::SeqCst),
        "a superseded generation must not run its publication at all"
    );
}

/// Drive the production apply pipeline bound to a supervised generation.
#[allow(clippy::too_many_arguments)]
async fn apply_under_generation(
    upstream_id: &str,
    lifecycle_key: &str,
    generation: u64,
    discovered: Vec<UpstreamTarget>,
    state: &mut ferrum_edge::_test_support::DiscoveryLoopStateForTest,
    lb_cache: &LoadBalancerCache,
    dns_cache: &DnsCache,
    health_checker: &HealthChecker,
    cancel_rx: &tokio::sync::watch::Receiver<bool>,
) -> ferrum_edge::_test_support::DiscoveryApplyControlForTest {
    ferrum_edge::_test_support::apply_service_discovery_snapshot_for_generation_for_test(
        &default_namespace(),
        upstream_id,
        "scripted",
        DiscoverySnapshot::from_targets(discovered),
        state,
        lb_cache,
        &None,
        &[],
        LoadBalancerAlgorithm::RoundRobin,
        &None,
        cancel_rx,
        &None,
        dns_cache,
        health_checker,
        lifecycle_key,
        generation,
    )
    .await
}

#[tokio::test]
async fn a_superseded_generation_publishes_no_discovered_snapshot() {
    let _guard = isolated().await;

    let config = config_with(vec![upstream_with_sd("fenced-snapshot", Vec::new(), None)]);
    let lb_cache = LoadBalancerCache::new(&config);
    let dns_cache = DnsCache::new(Default::default());
    let health_checker = HealthChecker::new();
    let (_cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    let key = task_key("fenced-snapshot");

    health::register_task_for_test(&key, 1, "scripted", scripted_staleness());
    let mut state = ferrum_edge::_test_support::DiscoveryLoopStateForTest::new();

    // Current generation: the fence admits the publication.
    let control = apply_under_generation(
        "fenced-snapshot",
        &key,
        1,
        vec![target("first.local", 8080)],
        &mut state,
        &lb_cache,
        &dns_cache,
        &health_checker,
        &cancel_rx,
    )
    .await;
    assert_eq!(
        control,
        ferrum_edge::_test_support::DiscoveryApplyControlForTest::Continue
    );
    assert_eq!(lb_hosts(&lb_cache, "fenced-snapshot"), vec!["first.local"]);

    // A reconcile installs the replacement generation.
    health::register_task_for_test(&key, 2, "scripted", scripted_staleness());

    let control = apply_under_generation(
        "fenced-snapshot",
        &key,
        1,
        vec![target("superseded.local", 8080)],
        &mut state,
        &lb_cache,
        &dns_cache,
        &health_checker,
        &cancel_rx,
    )
    .await;

    assert_eq!(
        control,
        ferrum_edge::_test_support::DiscoveryApplyControlForTest::Stop,
        "a superseded generation must stop instead of publishing"
    );
    assert_eq!(
        lb_hosts(&lb_cache, "fenced-snapshot"),
        vec!["first.local"],
        "a superseded generation must not overwrite the replacement's load-balancer state"
    );
}

#[tokio::test]
async fn a_superseded_generation_publishes_no_staleness_withdrawal() {
    let _guard = isolated().await;

    let key = task_key("fenced-withdrawal");
    health::register_task_for_test(&key, 1, "scripted", scripted_staleness());

    // While current, the fenced withdrawal publishes and claims the episode.
    let published = health::publish_withdrawal_under_fence_for_test(&key, 1, || Ok(()))
        .expect("the current generation may withdraw");
    assert!(published.0.is_ok());
    assert!(published.1, "the current generation claims its episode");
    assert_eq!(health::expiry_applied_for_test(&key), Some(true));

    // A second withdrawal in the same episode publishes but does not re-claim,
    // so the operator warning and metric stay one-per-episode.
    let repeat = health::publish_withdrawal_under_fence_for_test(&key, 1, || Ok(()))
        .expect("still the current generation");
    assert!(!repeat.1, "an episode must be claimed exactly once");

    // A reconcile installs the replacement generation.
    health::register_task_for_test(&key, 2, "scripted", scripted_staleness());

    let ran = Arc::new(AtomicBool::new(false));
    let refused = health::publish_withdrawal_under_fence_for_test(&key, 1, || {
        ran.store(true, Ordering::SeqCst);
        Ok(())
    });
    assert!(
        refused.is_none(),
        "a superseded generation must not publish a static-only withdrawal"
    );
    assert!(
        !ran.load(Ordering::SeqCst),
        "the withdrawal publication must not run at all for a superseded generation"
    );
    assert_eq!(
        health::expiry_applied_for_test(&key),
        Some(false),
        "a superseded generation must not consume the replacement's expiry episode"
    );
}

#[tokio::test]
async fn a_replacement_generation_cannot_register_during_a_fenced_withdrawal() {
    let _guard = isolated().await;

    let key = task_key("fenced-withdrawal-race");
    health::register_task_for_test(&key, 1, "scripted", scripted_staleness());

    let entered = Arc::new(AtomicBool::new(false));
    let replacement_started = Arc::new(AtomicBool::new(false));
    let published = Arc::new(AtomicBool::new(false));

    let holder = {
        let key = key.clone();
        let entered = Arc::clone(&entered);
        let replacement_started = Arc::clone(&replacement_started);
        let published = Arc::clone(&published);
        std::thread::spawn(move || {
            health::publish_withdrawal_under_fence_for_test(&key, 1, || {
                entered.store(true, Ordering::SeqCst);
                spin_until(|| replacement_started.load(Ordering::SeqCst));
                std::thread::sleep(std::time::Duration::from_millis(200));
                published.store(true, Ordering::SeqCst);
                Ok(())
            })
            .is_some()
        })
    };

    spin_until(|| entered.load(Ordering::SeqCst));
    replacement_started.store(true, Ordering::SeqCst);
    health::register_task_for_test(&key, 2, "scripted", scripted_staleness());

    assert!(
        published.load(Ordering::SeqCst),
        "a replacement generation registered while a staleness withdrawal was mid-publication"
    );
    assert!(holder.join().expect("fence thread"));
    assert_eq!(health::generation_for_test(&key), Some(2));
    assert_eq!(
        health::expiry_applied_for_test(&key),
        Some(false),
        "the replacement's fresh entry must not inherit the superseded episode claim"
    );
}

#[tokio::test]
async fn a_superseded_supervisor_does_not_withdraw_when_its_staleness_bound_elapses() {
    let _guard = isolated().await;

    let statics = vec![target("static.local", 9000)];
    let config = config_with(vec![upstream_with_sd(
        "superseded-stale",
        statics.clone(),
        None,
    )]);
    let lb_cache = Arc::new(LoadBalancerCache::new(&config));
    let discoverer = Arc::new(ScriptedDiscoverer::new(vec![target(
        "discovered.local",
        8080,
    )]));
    let hang = Arc::clone(&discoverer.hang);
    let calls = Arc::clone(&discoverer.calls);
    let metrics = ferrum_edge::plugins::prometheus_metrics::global_registry();
    let withdrawals_before = metrics.service_discovery_stale_withdrawals_total();

    let task = spawn_supervised_discovery_task_for_test(
        &default_namespace(),
        "superseded-stale",
        "scripted",
        discoverer,
        Arc::clone(&lb_cache),
        None,
        Arc::new(HealthChecker::new()),
        DnsCache::new(Default::default()),
        statics,
        LoadBalancerAlgorithm::RoundRobin,
        1,
        3,
        SdStalePolicy::Withdraw,
        1,
    );

    assert!(
        wait_for(|| {
            lb_hosts(&lb_cache, "superseded-stale").contains(&"discovered.local".to_string())
        })
        .await,
        "initial discovered snapshot must publish"
    );
    // Park the poller inside discover() so the registry stops answering, then
    // supersede it exactly as a reconcile would — before its 3s staleness bound
    // elapses. A deadline armed before the replacement registered still reaches
    // the expiry path, where the fence must refuse it.
    hang.store(true, Ordering::SeqCst);
    health::register_task_for_test(&task.key, 99, "scripted", scripted_staleness());
    assert!(
        calls.load(Ordering::SeqCst) >= 1,
        "the poller must have run before it was superseded"
    );

    // Well past the effective staleness bound: nothing may be withdrawn.
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    assert!(
        lb_hosts(&lb_cache, "superseded-stale").contains(&"discovered.local".to_string()),
        "a superseded generation must not withdraw discovered targets"
    );
    assert_eq!(
        health::expiry_applied_for_test(&task.key),
        Some(false),
        "a superseded generation must not claim the replacement's expiry episode"
    );
    assert_eq!(
        metrics.service_discovery_stale_withdrawals_total(),
        withdrawals_before,
        "no withdrawal may be recorded for a superseded generation"
    );

    let _ = task.cancel_tx.send(true);
    let _ = task.handle.await;
}

// ── #3717: bounded staleness ──────────────────────────────────────────

#[tokio::test]
async fn expiry_withdraws_discovered_targets_and_retains_static_targets() {
    let _guard = isolated().await;

    let statics = vec![target("static.local", 9000)];
    let config = config_with(vec![upstream_with_sd("stale-mixed", statics.clone(), None)]);
    let lb_cache = Arc::new(LoadBalancerCache::new(&config));
    let discoverer = Arc::new(ScriptedDiscoverer::new(vec![target(
        "discovered.local",
        8080,
    )]));
    let fail = Arc::clone(&discoverer.fail);
    let metrics = ferrum_edge::plugins::prometheus_metrics::global_registry();
    let withdrawals_before = metrics.service_discovery_stale_withdrawals_total();

    let task = spawn_supervised_discovery_task_for_test(
        &default_namespace(),
        "stale-mixed",
        "scripted",
        discoverer,
        Arc::clone(&lb_cache),
        None,
        Arc::new(HealthChecker::new()),
        DnsCache::new(Default::default()),
        statics,
        LoadBalancerAlgorithm::RoundRobin,
        1,
        3,
        SdStalePolicy::Withdraw,
        1,
    );

    // Publish once, then stop answering.
    assert!(
        wait_for(|| {
            health::snapshot()
                .upstreams
                .iter()
                .any(|u| u.upstream == task.key && u.last_success_age_seconds.is_some())
        })
        .await,
        "initial snapshot never published"
    );
    fail.store(true, Ordering::SeqCst);

    // Force the staleness anchor past the effective window instead of sleeping.
    assert!(health::age_anchor_for_test(&task.key, 600));

    assert!(
        wait_for(|| {
            health::snapshot()
                .upstreams
                .iter()
                .any(|u| u.upstream == task.key && u.withdrawn)
        })
        .await,
        "expired discovered targets were never withdrawn"
    );

    assert!(metrics.service_discovery_stale_withdrawals_total() > withdrawals_before);

    let aggregate = health::aggregate();
    assert_eq!(aggregate.withdrawn, 1);
    assert!(
        aggregate.degraded(),
        "a withdrawn upstream must degrade coarse health"
    );
    assert!(
        aggregate.ready(),
        "the withdraw policy removes unsafe routes without failing gateway readiness"
    );

    let _ = task.cancel_tx.send(true);
    let _ = task.handle.await;
}

#[tokio::test]
async fn expiry_recovers_and_republishes_without_a_config_reload() {
    let _guard = isolated().await;

    let config = config_with(vec![upstream_with_sd("recovering", Vec::new(), None)]);
    let lb_cache = Arc::new(LoadBalancerCache::new(&config));
    let discoverer = Arc::new(ScriptedDiscoverer::new(vec![target(
        "discovered.local",
        8080,
    )]));
    let fail = Arc::clone(&discoverer.fail);
    let metrics = ferrum_edge::plugins::prometheus_metrics::global_registry();
    let recoveries_before = metrics.service_discovery_stale_recoveries_total();

    let task = spawn_supervised_discovery_task_for_test(
        &default_namespace(),
        "recovering",
        "scripted",
        discoverer,
        lb_cache,
        None,
        Arc::new(HealthChecker::new()),
        DnsCache::new(Default::default()),
        Vec::new(),
        LoadBalancerAlgorithm::RoundRobin,
        1,
        3,
        SdStalePolicy::Withdraw,
        1,
    );

    assert!(
        wait_for(|| {
            health::snapshot()
                .upstreams
                .iter()
                .any(|u| u.upstream == task.key && u.last_success_age_seconds.is_some())
        })
        .await
    );
    fail.store(true, Ordering::SeqCst);
    assert!(health::age_anchor_for_test(&task.key, 600));
    assert!(
        wait_for(|| {
            health::snapshot()
                .upstreams
                .iter()
                .any(|u| u.upstream == task.key && u.withdrawn)
        })
        .await,
        "expiry never applied"
    );

    // Registry comes back.
    fail.store(false, Ordering::SeqCst);

    assert!(
        wait_for(|| {
            health::snapshot()
                .upstreams
                .iter()
                .any(|u| u.upstream == task.key && !u.withdrawn && !u.stale)
        })
        .await,
        "a recovered registry must clear stale/withdrawn state without a reload"
    );
    assert!(metrics.service_discovery_stale_recoveries_total() > recoveries_before);

    let _ = task.cancel_tx.send(true);
    let _ = task.handle.await;
}

#[tokio::test]
async fn expiry_withdrawal_is_not_blocked_by_a_hung_discovery_call() {
    let _guard = isolated().await;

    let config = config_with(vec![upstream_with_sd("hung-registry", Vec::new(), None)]);
    let lb_cache = Arc::new(LoadBalancerCache::new(&config));
    let discoverer = Arc::new(ScriptedDiscoverer::new(vec![target(
        "discovered.local",
        8080,
    )]));
    let calls = Arc::clone(&discoverer.calls);
    let hang = Arc::clone(&discoverer.hang);

    let task = spawn_supervised_discovery_task_for_test(
        &default_namespace(),
        "hung-registry",
        "scripted",
        discoverer,
        lb_cache,
        None,
        Arc::new(HealthChecker::new()),
        DnsCache::new(Default::default()),
        Vec::new(),
        LoadBalancerAlgorithm::RoundRobin,
        1,
        3,
        SdStalePolicy::Withdraw,
        1,
    );

    assert!(
        wait_for(|| {
            health::snapshot().upstreams.iter().any(|upstream| {
                upstream.upstream == task.key && upstream.last_success_age_seconds.is_some()
            })
        })
        .await,
        "initial discovered snapshot must publish"
    );
    hang.store(true, Ordering::SeqCst);
    assert!(
        wait_for(|| calls.load(Ordering::SeqCst) >= 2).await,
        "second discovery call must enter the scripted hang"
    );

    assert!(
        wait_for(|| {
            health::snapshot()
                .upstreams
                .iter()
                .any(|upstream| upstream.upstream == task.key && upstream.withdrawn)
        })
        .await,
        "staleness withdrawal must fire while discovery remains pending"
    );

    let _ = task.cancel_tx.send(true);
    let _ = task.handle.await;
}

#[tokio::test]
async fn failed_expiry_publication_retries_and_fails_readiness_closed() {
    let _guard = isolated().await;

    let config = config_with(vec![upstream_with_sd("withdraw-retry", Vec::new(), None)]);
    let lb_cache = Arc::new(LoadBalancerCache::new(&config));
    let base_store = epoch_store(&config);
    let exhausted_store = Arc::new(
        ferrum_edge::_test_support::request_epoch_store_with_lb_generation_for_test(
            &base_store,
            u64::MAX - 1,
        ),
    );
    let discoverer = Arc::new(ScriptedDiscoverer::new(vec![target(
        "stale-discovered.local",
        8080,
    )]));

    let task = spawn_supervised_discovery_task_for_test(
        &default_namespace(),
        "withdraw-retry",
        "scripted",
        discoverer,
        lb_cache,
        Some(exhausted_store),
        Arc::new(HealthChecker::new()),
        DnsCache::new(Default::default()),
        Vec::new(),
        LoadBalancerAlgorithm::RoundRobin,
        1,
        3,
        SdStalePolicy::Withdraw,
        1,
    );

    assert!(
        wait_for(|| {
            health::snapshot().upstreams.iter().any(|upstream| {
                upstream.upstream == task.key && upstream.last_success_age_seconds.is_some()
            })
        })
        .await,
        "initial discovered snapshot must publish before LB generation exhaustion"
    );
    assert!(health::age_anchor_for_test(&task.key, 600));
    assert!(
        wait_for(|| health::expiry_retry_attempts_for_test(&task.key).is_some_and(|n| n >= 2))
            .await,
        "a failed withdrawal publication must be retried with bounded delay"
    );

    let snapshot = health::snapshot();
    let status = snapshot
        .upstreams
        .iter()
        .find(|upstream| upstream.upstream == task.key)
        .expect("task health remains registered");
    assert!(status.stale);
    assert!(!status.withdrawn);
    assert_eq!(status.last_error, Some("publish_failed"));
    assert!(
        !snapshot.aggregate.ready(),
        "withdraw policy must fail readiness while stale targets remain installed"
    );

    let _ = task.cancel_tx.send(true);
    let _ = task.handle.await;
}

#[tokio::test]
async fn fail_readiness_policy_degrades_readiness_until_recovery() {
    let _guard = isolated().await;

    let config = config_with(vec![upstream_with_sd("critical", Vec::new(), None)]);
    let lb_cache = Arc::new(LoadBalancerCache::new(&config));
    let discoverer = Arc::new(ScriptedDiscoverer::new(vec![target(
        "discovered.local",
        8080,
    )]));
    let fail = Arc::clone(&discoverer.fail);

    let task = spawn_supervised_discovery_task_for_test(
        &default_namespace(),
        "critical",
        "scripted",
        discoverer,
        lb_cache,
        None,
        Arc::new(HealthChecker::new()),
        DnsCache::new(Default::default()),
        Vec::new(),
        LoadBalancerAlgorithm::RoundRobin,
        1,
        3,
        SdStalePolicy::FailReadiness,
        1,
    );

    assert!(
        wait_for(|| {
            health::snapshot()
                .upstreams
                .iter()
                .any(|u| u.upstream == task.key && u.last_success_age_seconds.is_some())
        })
        .await
    );
    assert!(health::aggregate().ready(), "healthy discovery is ready");

    fail.store(true, Ordering::SeqCst);
    assert!(health::age_anchor_for_test(&task.key, 600));

    assert!(
        wait_for(|| !health::aggregate().ready()).await,
        "an expired fail_readiness upstream must fail gateway readiness"
    );

    fail.store(false, Ordering::SeqCst);
    assert!(
        wait_for(|| health::aggregate().ready()).await,
        "readiness must restore after a fresh snapshot"
    );

    let _ = task.cancel_tx.send(true);
    let _ = task.handle.await;
}

#[tokio::test]
async fn retain_policy_keeps_targets_but_still_reports_staleness() {
    let _guard = isolated().await;

    let config = config_with(vec![upstream_with_sd("legacy", Vec::new(), None)]);
    let lb_cache = Arc::new(LoadBalancerCache::new(&config));
    let discoverer = Arc::new(ScriptedDiscoverer::new(vec![target(
        "discovered.local",
        8080,
    )]));
    let fail = Arc::clone(&discoverer.fail);

    let task = spawn_supervised_discovery_task_for_test(
        &default_namespace(),
        "legacy",
        "scripted",
        discoverer,
        lb_cache,
        None,
        Arc::new(HealthChecker::new()),
        DnsCache::new(Default::default()),
        Vec::new(),
        LoadBalancerAlgorithm::RoundRobin,
        1,
        3,
        SdStalePolicy::Retain,
        1,
    );

    assert!(
        wait_for(|| {
            health::snapshot()
                .upstreams
                .iter()
                .any(|u| u.upstream == task.key && u.last_success_age_seconds.is_some())
        })
        .await
    );
    fail.store(true, Ordering::SeqCst);
    assert!(health::age_anchor_for_test(&task.key, 600));

    assert!(
        wait_for(|| health::aggregate().stale == 1).await,
        "retain must still report staleness"
    );

    let status = health::snapshot()
        .upstreams
        .into_iter()
        .find(|u| u.upstream == task.key)
        .expect("task health present");
    assert!(
        !status.withdrawn,
        "retain must not withdraw discovered targets"
    );
    assert_eq!(status.policy, "retain");
    assert!(
        health::aggregate().ready(),
        "retain never fails gateway readiness"
    );

    let _ = task.cancel_tx.send(true);
    let _ = task.handle.await;
}

#[tokio::test]
async fn per_upstream_unbounded_retention_falls_back_to_the_bounded_default() {
    let _guard = isolated().await;

    // No unsafe opt-in installed for this process: an upstream asking for
    // unbounded retention must not get it.
    let staleness = health::resolve_upstream_staleness("risky", Some(0), None, 30);

    assert!(
        staleness.max_stale.is_some(),
        "unbounded retention must not be reachable by editing one upstream"
    );
}

#[tokio::test]
async fn per_upstream_unbounded_retention_is_honored_under_the_opt_in() {
    let _guard = isolated().await;

    health::override_discovery_staleness_policy_for_test(Some(
        ferrum_edge::config::env_config::DiscoveryStalenessPolicy {
            max_stale_seconds: 300,
            policy: SdStalePolicy::Withdraw,
            allow_unbounded: true,
        },
    ));

    let staleness = health::resolve_upstream_staleness("risky", Some(0), None, 30);
    health::override_discovery_staleness_policy_for_test(None);

    assert_eq!(staleness.max_stale, None);
}
