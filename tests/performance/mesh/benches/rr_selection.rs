//! Concurrent RoundRobin selection microbenchmark for hosted CI (#2947).
//!
//! Detects reintroduction of a single shared RR counter by comparing, in the
//! **same Criterion run** under the same barrier-synchronized worker pool:
//!
//! - `sharded`: production `LoadBalancer::select` RoundRobin (CachePadded
//!   per-worker shards from issue #2947)
//! - `shared`: deliberately contended control that advances one bare
//!   `AtomicU64` and clones the same 2-target Arc set
//!
//! The gate is `shared_wall_ns / sharded_wall_ns` (equal element counts), not
//! absolute 1-thread vs N-thread speedup. Hosted runners vary in core count and
//! scheduling; the old 1-vs-8 absolute speedup on a 2-target fixture also
//! concentrated Arc refcount traffic onto two lines and was observed to swing
//! from ~1.50x to 0.44x without an RR code change. A same-run shared control
//! cancels that shared work and isolates counter-line bounce.
//!
//! Thread count matches the WRR contention bench (4) so the gate is calibrated
//! to typical GitHub-hosted vCPU counts rather than oversubscribing an 8-wide
//! pool on a 2–4 core runner.

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
/// is the throughput ceiling, and where Arc clones concentrate on two targets.
const TARGET_COUNT: usize = 2;
/// Parallel workers for the gated same-run comparison (matches WRR hosted
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

fn run_sharded_selections(lb: &LoadBalancer, iterations: usize) {
    for _ in 0..iterations {
        black_box(lb.select("", None));
    }
}

/// Like-for-like Arc traffic with a single shared ticket counter — the
/// pre-#2947 contention shape the gate must keep detecting.
fn run_shared_selections(
    counter: &AtomicU64,
    targets: &[Arc<UpstreamTarget>],
    iterations: usize,
) {
    let n = targets.len();
    debug_assert!(n > 0);
    for _ in 0..iterations {
        let ticket = counter.fetch_add(1, Ordering::Relaxed);
        black_box(Arc::clone(&targets[ticket as usize % n]));
    }
}

fn measure_parallel_batches<F>(threads: usize, batches: u64, body: F) -> Duration
where
    F: FnMut() + Send + Clone + 'static,
{
    let start_line = Arc::new(Barrier::new(threads + 1));
    let end_line = Arc::new(Barrier::new(threads + 1));
    let stop = Arc::new(AtomicBool::new(false));

    let mut handles = Vec::with_capacity(threads);
    for _ in 0..threads {
        let start_line = Arc::clone(&start_line);
        let end_line = Arc::clone(&end_line);
        let stop = Arc::clone(&stop);
        let mut body = body.clone();
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

/// Collect the production LoadBalancer's own `Arc<UpstreamTarget>` pointers so
/// the shared control clones the identical refcount lines `select` bumps.
fn production_target_arcs(lb: &LoadBalancer, want: usize) -> Vec<Arc<UpstreamTarget>> {
    let mut out = Vec::with_capacity(want);
    for _ in 0..(want.saturating_mul(16).max(16)) {
        let Some(selection) = lb.select("", None) else {
            break;
        };
        if !out
            .iter()
            .any(|existing| Arc::ptr_eq(existing, &selection.target))
        {
            out.push(selection.target);
        }
        if out.len() == want {
            return out;
        }
    }
    panic!(
        "expected {want} distinct production target Arcs for the shared control, got {}",
        out.len()
    );
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
    let target_arcs: Arc<Vec<Arc<UpstreamTarget>>> =
        Arc::new(production_target_arcs(&lb, TARGET_COUNT));
    let shared_counter = Arc::new(AtomicU64::new(0));

    run_sharded_selections(&lb, 2_048);
    run_shared_selections(&shared_counter, &target_arcs, 2_048);

    let elements = (ITERATIONS_PER_THREAD * PARALLEL_THREADS) as u64;
    group.throughput(Throughput::Elements(elements));

    // Production sharded path under contention.
    group.bench_function(
        format!("{TARGET_COUNT}_targets_sharded_{PARALLEL_THREADS}_threads"),
        |b| {
            b.iter_custom(|iters| {
                let lb = Arc::clone(&lb);
                measure_parallel_batches(PARALLEL_THREADS, iters, move || {
                    run_sharded_selections(&lb, ITERATIONS_PER_THREAD);
                })
            });
        },
    );

    // Same-run deliberately contended baseline (single AtomicU64 + same Arcs).
    group.bench_function(
        format!("{TARGET_COUNT}_targets_shared_{PARALLEL_THREADS}_threads"),
        |b| {
            b.iter_custom(|iters| {
                let targets = Arc::clone(&target_arcs);
                let counter = Arc::clone(&shared_counter);
                measure_parallel_batches(PARALLEL_THREADS, iters, move || {
                    run_shared_selections(&counter, &targets, ITERATIONS_PER_THREAD);
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
                run_sharded_selections(&lb, ITERATIONS_PER_THREAD);
                total += started.elapsed();
            }
            total
        });
    });

    group.finish();
}

criterion_group!(benches, bench_rr_selection);
criterion_main!(benches);
