//! Concurrent WRR selection microbenchmark for hosted CI regression (#2413).
//!
//! Measures single-thread and multi-thread smooth weighted round-robin
//! selection across small and large target cardinalities.
//!
//! Each Criterion custom iteration's mean is wall-clock time for:
//!   - 1 thread:  ITERATIONS_PER_THREAD selections
//!   - N threads: N * ITERATIONS_PER_THREAD selections
//! The verify script converts those wall times into throughput speedup
//! (`N * serial_ns / parallel_ns`) and asserts against a serialization floor
//! that a single-lane `Mutex` hot path cannot clear on multi-core runners.

use std::collections::HashMap;
use std::hint::black_box;
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use ferrum_edge::config::types::{LoadBalancerAlgorithm, UpstreamTarget};
use ferrum_edge::load_balancer::LoadBalancer;

const TARGET_CARDINALITIES: [usize; 3] = [4, 32, 129];
const THREAD_COUNTS: [usize; 2] = [1, 4];
const ITERATIONS_PER_THREAD: usize = 50_000;

fn make_targets(n: usize) -> Vec<UpstreamTarget> {
    (0..n)
        .map(|i| UpstreamTarget {
            host: format!("host{i}"),
            port: 8080,
            service_port_policy_key: None,
            weight: if i == 0 { 5 } else { 1 },
            tags: HashMap::new(),
            locality: None,
            path: None,
        })
        .collect()
}

fn run_selections(lb: &LoadBalancer, iterations: usize) {
    for _ in 0..iterations {
        black_box(lb.select("", None));
    }
}

fn bench_wrr_selection(c: &mut Criterion) {
    let mut group = c.benchmark_group("wrr_selection");
    for targets in TARGET_CARDINALITIES {
        for threads in THREAD_COUNTS {
            let fixture = make_targets(targets);
            let lb = Arc::new(LoadBalancer::new(
                "bench-wrr",
                LoadBalancerAlgorithm::WeightedRoundRobin,
                &fixture,
                None,
            ));
            // Warm the schedule so measured iterations stay on the wait-free path.
            run_selections(&lb, 2_048);

            group.throughput(Throughput::Elements(
                (ITERATIONS_PER_THREAD * threads) as u64,
            ));
            group.bench_function(
                format!("{targets}_targets_{threads}_threads"),
                |b| {
                    b.iter_custom(|iters| {
                        let mut total = std::time::Duration::ZERO;
                        for _ in 0..iters {
                            let started = Instant::now();
                            if threads == 1 {
                                run_selections(&lb, ITERATIONS_PER_THREAD);
                            } else {
                                let mut handles = Vec::with_capacity(threads);
                                for _ in 0..threads {
                                    let lb = Arc::clone(&lb);
                                    handles.push(thread::spawn(move || {
                                        run_selections(&lb, ITERATIONS_PER_THREAD);
                                    }));
                                }
                                for handle in handles {
                                    handle.join().expect("bench worker");
                                }
                            }
                            total += started.elapsed();
                        }
                        total
                    });
                },
            );
        }
    }
    group.finish();
}

criterion_group!(benches, bench_wrr_selection);
criterion_main!(benches);
