//! Concurrent WRR fairness, recovery, lane isolation, cardinality, and
//! single-lane serialization regression coverage for issue #2413.

use dashmap::DashMap;
use ferrum_edge::config::types::{
    LoadBalancerAlgorithm, SubsetDefinition, SubsetTrafficPolicy, UpstreamTarget,
};
use ferrum_edge::load_balancer::{HealthContext, LoadBalancer, target_key};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Instant;

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
        source.contains("schedule: ArcSwap<WrrSchedule>"),
        "steady-state WRR must use a precomputed ArcSwap schedule"
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
fn wrr_concurrent_throughput_exceeds_single_lane_serialization_floor() {
    // A single blocking mutex on the lane serializes N threads to ~1× the
    // single-thread rate. The wait-free schedule path must show clear
    // multi-thread speedup on hosted multi-core runners. Threshold stays
    // conservative (1.25× with 4 threads) to avoid flakes on 2-vCPU CI hosts
    // while still failing hard under full single-lane mutex serialization.
    let targets = weighted_targets(&[5, 3, 2, 1]);
    let lb = Arc::new(LoadBalancer::new(
        UPSTREAM,
        LoadBalancerAlgorithm::WeightedRoundRobin,
        &targets,
        None,
    ));

    let warmup = 10_000usize;
    for _ in 0..warmup {
        let _ = lb.select("", None);
    }

    let iterations = 80_000usize;
    let started = Instant::now();
    for _ in 0..iterations {
        let _ = lb.select("", None);
    }
    let serial_secs = started.elapsed().as_secs_f64().max(1e-9);
    let serial_rate = iterations as f64 / serial_secs;

    let threads = 4usize;
    let per_thread = iterations / threads;
    let started = Instant::now();
    let mut handles = Vec::with_capacity(threads);
    for _ in 0..threads {
        let lb = Arc::clone(&lb);
        handles.push(thread::spawn(move || {
            for _ in 0..per_thread {
                let _ = lb.select("", None);
            }
        }));
    }
    for handle in handles {
        handle.join().expect("worker");
    }
    let parallel_secs = started.elapsed().as_secs_f64().max(1e-9);
    let parallel_rate = (per_thread * threads) as f64 / parallel_secs;
    let speedup = parallel_rate / serial_rate;

    assert!(
        speedup >= 1.25,
        "WRR concurrent speedup {speedup:.3}× below serialization-regression floor 1.25× \
         (serial_rate={serial_rate:.0}/s parallel_rate={parallel_rate:.0}/s). \
         Reintroducing a single-lane mutex typically collapses speedup near 1.0×."
    );
}
