//! Concurrent WRR fairness, recovery, lane isolation, cardinality, and
//! multi-fingerprint cache regression coverage for issue #2413.
//!
//! Throughput against single-lane serialization is gated by the hosted
//! Criterion microbenchmark + `.github/scripts/verify_wrr_selection_benchmark.py`,
//! not by wall-clock assertions in this ordinary unit suite.

use dashmap::DashMap;
use ferrum_edge::config::types::{
    LoadBalancerAlgorithm, SubsetDefinition, SubsetTrafficPolicy, UpstreamTarget,
};
use ferrum_edge::load_balancer::{HealthContext, LoadBalancer, target_key};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;

const UPSTREAM: &str = "wrr-concurrency";

fn active_health_ctx(active: &DashMap<String, u64>) -> HealthContext<'_> {
    HealthContext {
        active_unhealthy: active,
        proxy_passive: None,
        max_ejection_percent: None,
    }
}

fn weighted_targets(weights: &[u32]) -> Vec<UpstreamTarget> {
    weights
        .iter()
        .enumerate()
        .map(|(i, &weight)| UpstreamTarget {
            host: format!("host{i}"),
            port: 8080,
            service_port_policy_key: None,
            weight,
            tags: HashMap::new(),
            locality: None,
            path: None,
        })
        .collect()
}

fn tagged_target(host: &str, version: &str, weight: u32) -> UpstreamTarget {
    UpstreamTarget {
        host: host.into(),
        port: 8080,
        service_port_policy_key: None,
        weight,
        tags: HashMap::from([("version".to_string(), version.to_string())]),
        locality: None,
        path: None,
    }
}

#[test]
fn wrr_source_no_longer_guards_lane_state_with_mutex_vec() {
    let source = std::fs::read_to_string("src/load_balancer.rs")
        .expect("load_balancer.rs must be readable from crate root");
    assert!(
        source.contains("struct WrrLaneState"),
        "expected contention-bounded WrrLaneState"
    );
    assert!(
        !source.contains("wrr_state: std::sync::Mutex<Vec<i64>>"),
        "reintroduction of per-selection Mutex<Vec<i64>> would serialize the WRR hot path"
    );
    assert!(
        source.contains("WRR_SCHEDULE_CACHE_SLOTS"),
        "steady-state WRR must retain a bounded multi-fingerprint schedule cache"
    );
    assert!(
        !source.contains("invalidate: AtomicBool"),
        "racy invalidate boolean must not return; schedules are fingerprint-pure"
    );
    assert!(
        source.contains("try_lock"),
        "schedule publish must use try_lock so misses stay contention-bounded"
    );
}

#[test]
fn wrr_concurrent_fairness_matches_configured_weights() {
    let targets = weighted_targets(&[5, 1, 2]);
    let lb = Arc::new(LoadBalancer::new(
        UPSTREAM,
        LoadBalancerAlgorithm::WeightedRoundRobin,
        &targets,
        None,
    ));

    let thread_count = 8usize;
    let per_thread = 3_000usize;
    let mut handles = Vec::with_capacity(thread_count);
    for _ in 0..thread_count {
        let lb = Arc::clone(&lb);
        handles.push(thread::spawn(move || {
            let mut local = HashMap::new();
            for _ in 0..per_thread {
                let sel = lb.select("", None).expect("selection");
                *local.entry(sel.target.host.clone()).or_insert(0u64) += 1;
            }
            local
        }));
    }

    let mut counts = HashMap::new();
    for handle in handles {
        for (host, count) in handle.join().expect("worker") {
            *counts.entry(host).or_insert(0u64) += count;
        }
    }

    let total = (thread_count * per_thread) as f64;
    let host0 = *counts.get("host0").unwrap_or(&0) as f64 / total;
    let host1 = *counts.get("host1").unwrap_or(&0) as f64 / total;
    let host2 = *counts.get("host2").unwrap_or(&0) as f64 / total;
    // Ideal shares: 5/8, 1/8, 2/8.
    assert!(
        (host0 - 0.625).abs() < 0.05,
        "host0 share {host0} outside tolerance"
    );
    assert!(
        (host1 - 0.125).abs() < 0.05,
        "host1 share {host1} outside tolerance"
    );
    assert!(
        (host2 - 0.250).abs() < 0.05,
        "host2 share {host2} outside tolerance"
    );
}

#[test]
fn wrr_unhealthy_targets_excluded_and_recovered_targets_rejoin() {
    let targets = weighted_targets(&[3, 1]);
    let lb = LoadBalancer::new(
        UPSTREAM,
        LoadBalancerAlgorithm::WeightedRoundRobin,
        &targets,
        None,
    );

    let unhealthy: DashMap<String, u64> = DashMap::new();
    unhealthy.insert(target_key(UPSTREAM, &targets[0]), 1);

    for _ in 0..50 {
        let sel = lb
            .select("", Some(&active_health_ctx(&unhealthy)))
            .expect("selection");
        assert_eq!(sel.target.host, "host1");
        assert!(!sel.is_fallback);
    }

    unhealthy.clear();
    lb.reset_recovered_target_latency(&targets[0]);

    let mut seen_heavy = false;
    for _ in 0..40 {
        let sel = lb.select("", None).expect("selection");
        if sel.target.host == "host0" {
            seen_heavy = true;
            break;
        }
    }
    assert!(
        seen_heavy,
        "recovered heavy target must re-enter WRR rotation"
    );
}

#[test]
fn wrr_subset_lanes_are_isolated_under_concurrency() {
    let targets = vec![
        tagged_target("v1-a", "v1", 5),
        tagged_target("v1-b", "v1", 1),
        tagged_target("v2-a", "v2", 1),
        tagged_target("v2-b", "v2", 5),
    ];
    let subsets = vec![
        SubsetDefinition {
            name: "v1".into(),
            labels: HashMap::from([("version".into(), "v1".into())]),
            traffic_policy: Some(SubsetTrafficPolicy {
                load_balancer_algorithm: Some(LoadBalancerAlgorithm::WeightedRoundRobin),
                hash_on: None,
                tls: None,
                connect_timeout_ms: None,
                passive_health_check: None,
            }),
        },
        SubsetDefinition {
            name: "v2".into(),
            labels: HashMap::from([("version".into(), "v2".into())]),
            traffic_policy: Some(SubsetTrafficPolicy {
                load_balancer_algorithm: Some(LoadBalancerAlgorithm::WeightedRoundRobin),
                hash_on: None,
                tls: None,
                connect_timeout_ms: None,
                passive_health_check: None,
            }),
        },
    ];
    let lb = Arc::new(LoadBalancer::with_subsets(
        UPSTREAM,
        LoadBalancerAlgorithm::WeightedRoundRobin,
        &targets,
        None,
        Some(&subsets),
    ));

    let v1_counts = Arc::new((AtomicU64::new(0), AtomicU64::new(0)));
    let v2_counts = Arc::new((AtomicU64::new(0), AtomicU64::new(0)));
    let mut handles = Vec::new();
    for lane in ["v1", "v2"] {
        for _ in 0..4 {
            let lb = Arc::clone(&lb);
            let v1_counts = Arc::clone(&v1_counts);
            let v2_counts = Arc::clone(&v2_counts);
            handles.push(thread::spawn(move || {
                for _ in 0..2_000 {
                    let sel = lb
                        .select_from_subset("", lane, None)
                        .expect("subset selection");
                    match (lane, sel.target.host.as_str()) {
                        ("v1", "v1-a") => {
                            v1_counts.0.fetch_add(1, Ordering::Relaxed);
                        }
                        ("v1", "v1-b") => {
                            v1_counts.1.fetch_add(1, Ordering::Relaxed);
                        }
                        ("v2", "v2-a") => {
                            v2_counts.0.fetch_add(1, Ordering::Relaxed);
                        }
                        ("v2", "v2-b") => {
                            v2_counts.1.fetch_add(1, Ordering::Relaxed);
                        }
                        ("v1", other) => panic!("v1 lane leaked {other}"),
                        ("v2", other) => panic!("v2 lane leaked {other}"),
                        _ => unreachable!(),
                    }
                }
            }));
        }
    }
    for handle in handles {
        handle.join().expect("worker");
    }

    let v1_a = v1_counts.0.load(Ordering::Relaxed) as f64;
    let v1_b = v1_counts.1.load(Ordering::Relaxed) as f64;
    let v2_a = v2_counts.0.load(Ordering::Relaxed) as f64;
    let v2_b = v2_counts.1.load(Ordering::Relaxed) as f64;
    assert!(
        v1_a / (v1_a + v1_b) > 0.7,
        "v1 lane should prefer weight-5 target"
    );
    assert!(
        v2_b / (v2_a + v2_b) > 0.7,
        "v2 lane should prefer weight-5 target"
    );
}

#[test]
fn wrr_cardinality_paths_preserve_weights_for_small_and_large_sets() {
    for n in [2usize, 8, 64, 129] {
        let weights: Vec<u32> = (0..n).map(|i| if i == 0 { 5 } else { 1 }).collect();
        let targets = weighted_targets(&weights);
        let lb = LoadBalancer::new(
            UPSTREAM,
            LoadBalancerAlgorithm::WeightedRoundRobin,
            &targets,
            None,
        );

        let samples = (n * 200).max(2_000);
        let mut heavy = 0u64;
        for _ in 0..samples {
            let sel = lb.select("", None).expect("selection");
            if sel.target.host == "host0" {
                heavy += 1;
            }
        }
        let share = heavy as f64 / samples as f64;
        let ideal = 5.0 / (5.0 + (n as f64 - 1.0));
        assert!(
            (share - ideal).abs() < 0.08,
            "n={n}: heavy share {share} vs ideal {ideal}"
        );
    }
}

#[test]
fn wrr_alternating_exclusion_fingerprints_become_steady_cache_hits() {
    // Shared upstream + retry exclusions (or per-proxy health) alternate
    // fingerprints. A single-slot cache rebuilds on every switch; the bounded
    // multi-slot cache must keep both fingerprints on the wait-free hit path.
    let targets = weighted_targets(&[5, 3, 2, 1]);
    let lb = Arc::new(LoadBalancer::new(
        UPSTREAM,
        LoadBalancerAlgorithm::WeightedRoundRobin,
        &targets,
        None,
    ));

    // Warm both exclusion-derived fingerprints.
    for _ in 0..64 {
        let t = lb
            .select_excluding("", &targets[0], None)
            .expect("exclude host0");
        assert_ne!(t.host, "host0");
        let t = lb
            .select_excluding("", &targets[1], None)
            .expect("exclude host1");
        assert_ne!(t.host, "host1");
    }
    let (hits_warm, rebuilds_warm) = lb.wrr_lane_cache_stats();
    assert!(
        rebuilds_warm >= 2,
        "expected both exclusion fingerprints to publish at least once, got {rebuilds_warm}"
    );
    assert!(hits_warm > 0, "warmup should record steady hits");

    let threads = 8usize;
    let per_thread = 1_000usize;
    let mut handles = Vec::with_capacity(threads);
    for tid in 0..threads {
        let lb = Arc::clone(&lb);
        let exclude = if tid % 2 == 0 {
            targets[0].clone()
        } else {
            targets[1].clone()
        };
        let forbidden = exclude.host.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..per_thread {
                let t = lb
                    .select_excluding("", &exclude, None)
                    .expect("exclusion selection");
                assert_ne!(t.host, forbidden);
            }
        }));
    }
    for handle in handles {
        handle.join().expect("worker");
    }

    let (hits_after, rebuilds_after) = lb.wrr_lane_cache_stats();
    assert_eq!(
        rebuilds_after, rebuilds_warm,
        "alternating warmed fingerprints must not republish schedules \
         (rebuilds stayed {rebuilds_after}, warm was {rebuilds_warm})"
    );
    assert!(
        hits_after >= hits_warm + (threads * per_thread) as u64,
        "every alternating selection must be a cache hit \
         (hits_after={hits_after} hits_warm={hits_warm})"
    );
}

#[test]
fn wrr_alternating_active_health_fingerprints_become_steady_cache_hits() {
    let targets = weighted_targets(&[4, 3, 2, 1]);
    let lb = Arc::new(LoadBalancer::new(
        UPSTREAM,
        LoadBalancerAlgorithm::WeightedRoundRobin,
        &targets,
        None,
    ));

    let eject0 = Arc::new(DashMap::<String, u64>::new());
    eject0.insert(target_key(UPSTREAM, &targets[0]), 1);
    let eject1 = Arc::new(DashMap::<String, u64>::new());
    eject1.insert(target_key(UPSTREAM, &targets[1]), 1);

    for _ in 0..64 {
        let sel = lb
            .select("", Some(&active_health_ctx(&eject0)))
            .expect("eject0");
        assert_ne!(sel.target.host, "host0");
        let sel = lb
            .select("", Some(&active_health_ctx(&eject1)))
            .expect("eject1");
        assert_ne!(sel.target.host, "host1");
    }
    let (hits_warm, rebuilds_warm) = lb.wrr_lane_cache_stats();
    assert!(rebuilds_warm >= 2);

    let threads = 8usize;
    let per_thread = 800usize;
    let mut handles = Vec::with_capacity(threads);
    for tid in 0..threads {
        let lb = Arc::clone(&lb);
        let map = if tid % 2 == 0 {
            Arc::clone(&eject0)
        } else {
            Arc::clone(&eject1)
        };
        let forbidden = if tid % 2 == 0 { "host0" } else { "host1" };
        handles.push(thread::spawn(move || {
            for _ in 0..per_thread {
                let ctx = active_health_ctx(&map);
                let sel = lb.select("", Some(&ctx)).expect("health selection");
                assert_ne!(sel.target.host, forbidden);
            }
        }));
    }
    for handle in handles {
        handle.join().expect("worker");
    }

    let (hits_after, rebuilds_after) = lb.wrr_lane_cache_stats();
    assert_eq!(
        rebuilds_after, rebuilds_warm,
        "alternating health fingerprints must stay cached"
    );
    assert!(hits_after >= hits_warm + (threads * per_thread) as u64);
}

#[test]
fn wrr_vec_path_alternating_exclusions_become_steady_cache_hits() {
    // >128 targets exercise the vec fingerprint path with the same bounded cache.
    let n = 129usize;
    let weights: Vec<u32> = (0..n).map(|i| if i < 4 { 3 } else { 1 }).collect();
    let targets = weighted_targets(&weights);
    let lb = Arc::new(LoadBalancer::new(
        UPSTREAM,
        LoadBalancerAlgorithm::WeightedRoundRobin,
        &targets,
        None,
    ));

    for _ in 0..32 {
        let t = lb
            .select_excluding("", &targets[0], None)
            .expect("exclude 0");
        assert_ne!(t.host, "host0");
        let t = lb
            .select_excluding("", &targets[1], None)
            .expect("exclude 1");
        assert_ne!(t.host, "host1");
    }
    let (hits_warm, rebuilds_warm) = lb.wrr_lane_cache_stats();
    assert!(rebuilds_warm >= 2);

    let threads = 6usize;
    let per_thread = 200usize;
    let mut handles = Vec::with_capacity(threads);
    for tid in 0..threads {
        let lb = Arc::clone(&lb);
        let exclude = if tid % 2 == 0 {
            targets[0].clone()
        } else {
            targets[1].clone()
        };
        let forbidden = exclude.host.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..per_thread {
                let t = lb
                    .select_excluding("", &exclude, None)
                    .expect("vec exclusion");
                assert_ne!(t.host, forbidden);
            }
        }));
    }
    for handle in handles {
        handle.join().expect("worker");
    }

    let (hits_after, rebuilds_after) = lb.wrr_lane_cache_stats();
    assert_eq!(rebuilds_after, rebuilds_warm);
    assert!(hits_after >= hits_warm + (threads * per_thread) as u64);
}

#[test]
fn wrr_recovery_reuses_cached_fingerprint_schedule() {
    let targets = weighted_targets(&[5, 1, 1]);
    let lb = LoadBalancer::new(
        UPSTREAM,
        LoadBalancerAlgorithm::WeightedRoundRobin,
        &targets,
        None,
    );

    // Publish full-set schedule.
    for _ in 0..16 {
        let _ = lb.select("", None);
    }
    let unhealthy: DashMap<String, u64> = DashMap::new();
    unhealthy.insert(target_key(UPSTREAM, &targets[0]), 1);
    for _ in 0..16 {
        let sel = lb
            .select("", Some(&active_health_ctx(&unhealthy)))
            .expect("unhealthy");
        assert_ne!(sel.target.host, "host0");
    }
    let (_, rebuilds_mid) = lb.wrr_lane_cache_stats();

    unhealthy.clear();
    lb.reset_recovered_target_latency(&targets[0]);

    let (hits_before, rebuilds_before) = lb.wrr_lane_cache_stats();
    assert_eq!(rebuilds_before, rebuilds_mid);
    for _ in 0..32 {
        let _ = lb.select("", None);
    }
    let (hits_after, rebuilds_after) = lb.wrr_lane_cache_stats();
    assert_eq!(
        rebuilds_after, rebuilds_before,
        "restored full healthy fingerprint must reuse the cached schedule"
    );
    assert!(hits_after > hits_before);
}
