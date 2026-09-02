//! Concurrent RoundRobin selection microbenchmark for hosted CI (#2947).
//!
//! Guards the sharded / CachePadded RR selection counters against a regression
//! back to a single shared `AtomicU64` (or a mutex) on the selection path.
//! Fixture contract matches the WRR contention bench pattern (long-lived
//! barrier-synchronized workers; Criterion custom-iteration wall time covers
//! `threads * ITERATIONS_PER_THREAD` operations).
//!
//! # Shared-counter control (issue #4484)
//!
//! The 2-target selection fixture does not speed up with thread count even when
//! the counters are correctly sharded: `LoadBalancer::select` also touches
//! per-call shared state (snapshot load, refcounts) whose cache lines bounce
//! across cores. Hosted runs measure roughly 0.6x-0.7x parallel throughput on a
//! healthy tree, so a *speedup floor* on this fixture asserts a property the
//! workload does not have.
//!
//! `shared_counter_control_{1,8}_threads` runs the same barrier-synchronized
//! worker pool at the same thread counts over one genuinely shared
//! `AtomicU64`. That is the cost the sharded counters exist to avoid, measured
//! on the same runner in the same run, so the verifier can compare the
//! selection path's per-operation contention cost against a contemporaneous
//! shared-line reference instead of against a fixed speedup constant. See
//! `.github/scripts/verify_rr_selection_benchmark.py`.

use std::collections::HashMap;
use std::hint::black_box;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use ferrum_edge::config::types::{LoadBalancerAlgorithm, UpstreamTarget};
use ferrum_edge::load_balancer::LoadBalancer;

/// Issue #2947 regression fixture: small healthy set where an unsharded counter
/// is the throughput ceiling.
const TARGET_COUNT: usize = 2;
const THREAD_COUNTS: [usize; 2] = [1, 8];
const ITERATIONS_PER_THREAD: usize = 50_000;

/// Issue #4484 reference workload: every worker advances this one counter, so
/// the whole batch serializes on a single cache line.
static SHARED_CONTROL_COUNTER: AtomicU64 = AtomicU64::new(0);

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

fn run_selections(lb: &LoadBalancer, iterations: usize) {
    for _ in 0..iterations {
        black_box(lb.select("", None));
    }
}

fn run_shared_counter(iterations: usize) {
    for _ in 0..iterations {
        black_box(SHARED_CONTROL_COUNTER.fetch_add(1, Ordering::Relaxed));
    }
}

/// One measured batch: `ITERATIONS_PER_THREAD` operations on the calling thread.
type Workload = Arc<dyn Fn() + Send + Sync>;

fn measure_serial_batches(work: &Workload, batches: u64) -> Duration {
    let mut total = Duration::ZERO;
    for _ in 0..batches {
        let started = Instant::now();
        work();
        total += started.elapsed();
    }
    total
}

fn measure_parallel_batches(work: &Workload, threads: usize, batches: u64) -> Duration {
    let start_line = Arc::new(Barrier::new(threads + 1));
    let end_line = Arc::new(Barrier::new(threads + 1));
    let stop = Arc::new(AtomicBool::new(false));

    let mut handles = Vec::with_capacity(threads);
    for _ in 0..threads {
        let work = Arc::clone(work);
        let start_line = Arc::clone(&start_line);
        let end_line = Arc::clone(&end_line);
        let stop = Arc::clone(&stop);
        handles.push(thread::spawn(move || {
            loop {
                start_line.wait();
                if stop.load(Ordering::Acquire) {
                    end_line.wait();
                    break;
                }
                work();
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

fn bench_workload(
    group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
    prefix: &str,
    work: Workload,
) {
    for threads in THREAD_COUNTS {
        group.throughput(Throughput::Elements(
            (ITERATIONS_PER_THREAD * threads) as u64,
        ));
        let work = Arc::clone(&work);
        group.bench_function(format!("{prefix}_{threads}_threads"), |b| {
            b.iter_custom(|iters| {
                if threads == 1 {
                    measure_serial_batches(&work, iters)
                } else {
                    measure_parallel_batches(&work, threads, iters)
                }
            });
        });
    }
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
    run_selections(&lb, 2_048);

    let selection: Workload = {
        let lb = Arc::clone(&lb);
        Arc::new(move || run_selections(&lb, ITERATIONS_PER_THREAD))
    };
    bench_workload(&mut group, &format!("{TARGET_COUNT}_targets"), selection);

    run_shared_counter(2_048);
    let control: Workload = Arc::new(|| run_shared_counter(ITERATIONS_PER_THREAD));
    bench_workload(&mut group, "shared_counter_control", control);

    group.finish();
}

criterion_group!(benches, bench_rr_selection);
criterion_main!(benches);
