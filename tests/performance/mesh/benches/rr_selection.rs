//! Concurrent RoundRobin selection microbenchmark for hosted CI (#2947).
//!
//! Detects reintroduction of a single shared RR counter by comparing, in the
//! **same Criterion invocation** under the same barrier-synchronized worker
//! shape:
//!
//! - `sharded`: the exact RoundRobin selection seam with one explicit
//!   CachePadded shard per worker
//! - `shared`: the same selection seam with every worker deliberately pinned
//!   to shard zero
//!
//! The gate is `shared_wall_ns / sharded_wall_ns` (equal element counts), not
//! absolute 1-thread vs N-thread speedup. Hosted runners vary in core count and
//! scheduling; the old 1-vs-8 absolute speedup on a 2-target fixture also
//! concentrated Arc refcount traffic onto two lines and was observed to swing
//! from ~1.50x to 0.44x without an RR code change. Both sides of this comparison
//! now execute the same ticket, modulo, target lookup, and Arc clone operations;
//! only the selected counter shard differs.
//!
//! Thread count matches the WRR contention bench (4) so the gate is calibrated
//! to typical GitHub-hosted vCPU counts rather than oversubscribing an 8-wide
//! pool on a 2–4 core runner.

use std::collections::HashMap;
use std::hint::black_box;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use ferrum_edge::_test_support::select_round_robin_from_shard_for_test;
use ferrum_edge::config::types::{LoadBalancerAlgorithm, UpstreamTarget};
use ferrum_edge::load_balancer::LoadBalancer;

/// Issue #2947 regression fixture: small healthy set where an unsharded counter
/// is the throughput ceiling, and where Arc clones concentrate on two targets.
const TARGET_COUNT: usize = 2;
/// Parallel workers for the gated equal-work comparison (matches WRR hosted
/// calibration; avoids 8-wide oversubscription on 2–4 vCPU runners).
const PARALLEL_THREADS: usize = 4;
const ITERATIONS_PER_THREAD: usize = 50_000;

fn make_targets(n: usize) -> Vec<UpstreamTarget> {
    (0..n)
        .map(|i| UpstreamTarget {
            host: format!("host{i}"),
            port: 8080,
            service_port_policy_key: None,
            weight: 1,
            tags: HashMap::new(),
            locality: None,
            path: None,
        })
        .collect()
}

fn run_rr_selections(lb: &LoadBalancer, shard: usize, iterations: usize) {
    for _ in 0..iterations {
        black_box(select_round_robin_from_shard_for_test(lb, shard));
    }
}

fn measure_parallel_batches<F, M>(threads: usize, batches: u64, make_body: M) -> Duration
where
    F: FnMut() + Send + 'static,
    M: Fn(usize) -> F,
{
    let start_line = Arc::new(Barrier::new(threads + 1));
    let end_line = Arc::new(Barrier::new(threads + 1));
    let stop = Arc::new(AtomicBool::new(false));

    let mut handles = Vec::with_capacity(threads);
    for worker in 0..threads {
        let start_line = Arc::clone(&start_line);
        let end_line = Arc::clone(&end_line);
        let stop = Arc::clone(&stop);
        let mut body = make_body(worker);
        handles.push(thread::spawn(move || {
            loop {
                start_line.wait();
                if stop.load(Ordering::Acquire) {
                    end_line.wait();
                    break;
                }
                body();
                end_line.wait();
            }
        }));
    }

    // Untimed prime so the first measured sample is not cold-scheduled.
    start_line.wait();
    end_line.wait();

    let mut total = Duration::ZERO;
    for _ in 0..batches {
        start_line.wait();
        let started = Instant::now();
        end_line.wait();
        total += started.elapsed();
    }

    stop.store(true, Ordering::Release);
    start_line.wait();
    end_line.wait();
    for handle in handles {
        handle.join().expect("bench worker");
    }
    total
}

fn bench_rr_selection(c: &mut Criterion) {
    let mut group = c.benchmark_group("rr_selection");
    let fixture = make_targets(TARGET_COUNT);
    let lb = Arc::new(LoadBalancer::new(
        "bench-rr",
        LoadBalancerAlgorithm::RoundRobin,
        &fixture,
        None,
    ));
    for shard in 0..PARALLEL_THREADS {
        run_rr_selections(&lb, shard, 512);
    }

    let elements = (ITERATIONS_PER_THREAD * PARALLEL_THREADS) as u64;
    group.throughput(Throughput::Elements(elements));

    // Production sharded path under contention.
    group.bench_function(
        format!("{TARGET_COUNT}_targets_sharded_{PARALLEL_THREADS}_threads"),
        |b| {
            b.iter_custom(|iters| {
                let lb = Arc::clone(&lb);
                measure_parallel_batches(PARALLEL_THREADS, iters, move |worker| {
                    let lb = Arc::clone(&lb);
                    move || run_rr_selections(&lb, worker, ITERATIONS_PER_THREAD)
                })
            });
        },
    );

    // Deliberately contended baseline: identical selection work, one shard.
    group.bench_function(
        format!("{TARGET_COUNT}_targets_shared_{PARALLEL_THREADS}_threads"),
        |b| {
            b.iter_custom(|iters| {
                let lb = Arc::clone(&lb);
                measure_parallel_batches(PARALLEL_THREADS, iters, move |_| {
                    let lb = Arc::clone(&lb);
                    move || run_rr_selections(&lb, 0, ITERATIONS_PER_THREAD)
                })
            });
        },
    );

    // Diagnostic-only serial sample for log continuity (not gated).
    group.throughput(Throughput::Elements(ITERATIONS_PER_THREAD as u64));
    group.bench_function(format!("{TARGET_COUNT}_targets_sharded_1_threads"), |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let started = Instant::now();
                run_rr_selections(&lb, 0, ITERATIONS_PER_THREAD);
                total += started.elapsed();
            }
            total
        });
    });

    group.finish();
}

criterion_group!(benches, bench_rr_selection);
criterion_main!(benches);
