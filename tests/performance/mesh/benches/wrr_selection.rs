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
//!
//! Multi-thread samples keep a long-lived worker pool synchronized with
//! barriers. Spawning and joining threads inside every Criterion sample was a
//! measurement defect: for the ~1.5 ms bitset fixtures, spawn/join overhead
//! dominated the selection work and collapsed reported speedup below 1.0x even
//! when the production path was wait-free.

use std::collections::HashMap;
use std::hint::black_box;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

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

/// Steady-state parallel batch: workers are spawned once per Criterion
/// `iter_custom` call and reused across samples so wall time measures
/// selection contention, not thread create/teardown.
fn measure_parallel_batches(
    lb: &Arc<LoadBalancer>,
    threads: usize,
    batches: u64,
) -> Duration {
    use std::sync::atomic::AtomicU64;

    let start_line = Arc::new(Barrier::new(threads + 1));
    let end_line = Arc::new(Barrier::new(threads + 1));
    let stop = Arc::new(AtomicBool::new(false));
    // Max per-worker selection-loop elapsed for the current batch. Workers start
    // together at `start_line`, so max elapsed ≈ batch wall time without
    // including barrier/mutex harness overhead in the sample.
    let batch_ns = Arc::new(AtomicU64::new(0));

    let mut handles = Vec::with_capacity(threads);
    for _ in 0..threads {
        let lb = Arc::clone(lb);
        let start_line = Arc::clone(&start_line);
        let end_line = Arc::clone(&end_line);
        let stop = Arc::clone(&stop);
        let batch_ns = Arc::clone(&batch_ns);
        handles.push(thread::spawn(move || {
            loop {
                start_line.wait();
                if stop.load(Ordering::Acquire) {
                    end_line.wait();
                    break;
                }
                let started = Instant::now();
                run_selections(&lb, ITERATIONS_PER_THREAD);
                let elapsed_ns = started.elapsed().as_nanos() as u64;
                batch_ns.fetch_max(elapsed_ns, Ordering::Relaxed);
                end_line.wait();
            }
        }));
    }

    // Untimed prime so the first measured sample is not cold-scheduled.
    batch_ns.store(0, Ordering::Relaxed);
    start_line.wait();
    end_line.wait();

    let mut total = Duration::ZERO;
    for _ in 0..batches {
        batch_ns.store(0, Ordering::Relaxed);
        start_line.wait();
        end_line.wait();
        total += Duration::from_nanos(batch_ns.load(Ordering::Relaxed));
    }

    stop.store(true, Ordering::Release);
    start_line.wait();
    end_line.wait();
    for handle in handles {
        handle.join().expect("bench worker");
    }
    total
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
                        if threads == 1 {
                            let mut total = Duration::ZERO;
                            for _ in 0..iters {
                                let started = Instant::now();
                                run_selections(&lb, ITERATIONS_PER_THREAD);
                                total += started.elapsed();
                            }
                            total
                        } else {
                            measure_parallel_batches(&lb, threads, iters)
                        }
                    });
                },
            );
        }
    }
    group.finish();
}

criterion_group!(benches, bench_wrr_selection);
criterion_main!(benches);
