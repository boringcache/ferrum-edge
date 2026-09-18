//! Shared closed-loop phases. Setup and warmup never consume measurement time.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tokio::sync::watch;

use crate::metrics::{BenchMetrics, collect_results};

const SETUP: usize = 0;
const READY: usize = 1;
const WARMUP: usize = 2;
const BARRIER: usize = 3;
const MEASURING: usize = 4;
const DONE: usize = 5;

#[derive(Clone, Copy, Debug)]
enum Phase {
    Setup,
    Warmup,
    Measure { start: Instant, end: Instant },
    Stop,
}

#[derive(Default)]
struct Slot {
    state: AtomicUsize,
    queued: AtomicUsize,
    active: AtomicUsize,
    queue_ns: AtomicU64,
    admissions: AtomicU64,
    retired_early: AtomicBool,
}

/// Actual client transport lifetime, independent of requested worker count.
pub struct ConnectionGuard(Arc<AtomicUsize>);

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Clone)]
pub struct Connections(Arc<AtomicUsize>);

impl Connections {
    pub fn opened(&self) -> ConnectionGuard {
        self.0.fetch_add(1, Ordering::Relaxed);
        ConnectionGuard(self.0.clone())
    }
}

/// Clone into a request body; mark admission on its first transport poll.
#[derive(Clone)]
pub struct Admission {
    slot: Arc<Slot>,
    queued_at: Instant,
    measured: bool,
}

impl Admission {
    pub fn admitted(&self) {
        if self.slot.queued.swap(0, Ordering::Relaxed) != 0 {
            self.slot.active.store(1, Ordering::Relaxed);
            if self.measured {
                self.slot.queue_ns.fetch_add(
                    self.queued_at.elapsed().as_nanos() as u64,
                    Ordering::Relaxed,
                );
                self.slot.admissions.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

pub struct Worker {
    slot: Arc<Slot>,
    phase: watch::Receiver<Phase>,
    window: Option<(Instant, Instant)>,
    offered_at: Instant,
    warmup_offered: bool,
}

impl Worker {
    pub async fn next_request(&mut self) -> bool {
        self.slot.active.store(0, Ordering::Relaxed);
        self.slot.queued.store(0, Ordering::Relaxed);
        // The published measurement interval never changes. Avoid taking the
        // watch receiver's read lock on every measured request.
        if let Some((_, end)) = self.window {
            if Instant::now() >= end {
                self.slot.state.store(DONE, Ordering::Release);
                return false;
            }
            self.offered_at = Instant::now();
            self.slot.queued.store(1, Ordering::Relaxed);
            return true;
        }
        if self.slot.state.load(Ordering::Relaxed) == SETUP {
            self.slot.state.store(READY, Ordering::Release);
        } else if self.warmup_offered && self.window.is_none() {
            self.slot.state.store(BARRIER, Ordering::Release);
        }
        loop {
            let phase = *self.phase.borrow_and_update();
            match phase {
                Phase::Warmup if !self.warmup_offered => {
                    self.warmup_offered = true;
                    self.slot.state.store(WARMUP, Ordering::Release);
                    break;
                }
                Phase::Measure { start, end } => {
                    if Instant::now() >= end {
                        self.slot.state.store(DONE, Ordering::Release);
                        return false;
                    }
                    self.window = Some((start, end));
                    self.slot.state.store(MEASURING, Ordering::Release);
                    break;
                }
                Phase::Stop => return false,
                _ => {
                    if self.phase.changed().await.is_err() {
                        return false;
                    }
                }
            }
        }
        self.offered_at = Instant::now();
        self.slot.queued.store(1, Ordering::Relaxed);
        true
    }

    pub fn admission(&self) -> Admission {
        Admission {
            slot: self.slot.clone(),
            queued_at: self.offered_at,
            measured: self.window.is_some(),
        }
    }

    pub fn completion_phase(&self, at: Instant) -> CompletionPhase {
        classify_completion(self.window, at)
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        if self.window.is_none_or(|(_, end)| Instant::now() < end) {
            self.slot.retired_early.store(true, Ordering::Relaxed);
        }
        self.slot.queued.store(0, Ordering::Relaxed);
        self.slot.active.store(0, Ordering::Relaxed);
        self.slot.state.store(DONE, Ordering::Release);
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum CompletionPhase {
    Warmup,
    Measurement,
    Drain,
}

pub fn classify_completion(window: Option<(Instant, Instant)>, at: Instant) -> CompletionPhase {
    match window {
        None => CompletionPhase::Warmup,
        Some((start, end)) if at >= start && at < end => CompletionPhase::Measurement,
        Some(_) => CompletionPhase::Drain,
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Gauge {
    pub min: usize,
    pub max: usize,
    pub mean: f64,
}

impl Gauge {
    fn observe(&mut self, value: usize, count: usize) {
        self.min = if count == 1 { value } else { self.min.min(value) };
        self.max = self.max.max(value);
        self.mean += (value as f64 - self.mean) / count as f64;
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Observed {
    pub samples: usize,
    pub sampling_interval_ms: u64,
    pub active_workers: Gauge,
    pub active_connections: Gauge,
    pub active_streams: Gauge,
    pub queued_requests: Gauge,
    pub queue_time_ns: u64,
    pub admissions: u64,
    pub workers_at_barrier: usize,
    pub workers_retired_before_deadline: usize,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct PhaseReport {
    pub setup_secs: f64,
    pub warmup_secs: f64,
    pub barrier_secs: f64,
    pub measurement_secs: f64,
    pub measurement_start_unix_secs: Option<f64>,
    pub drain_secs: f64,
    pub transport_close_secs: f64,
    pub timed_out: bool,
}

pub struct Phases {
    created: Instant,
    duration: Duration,
    phase: watch::Sender<Phase>,
    slots: Vec<Arc<Slot>>,
    connections: Connections,
}

impl Phases {
    pub fn new(duration: Duration) -> Self {
        let (phase, _) = watch::channel(Phase::Setup);
        Self {
            created: Instant::now(),
            duration,
            phase,
            slots: Vec::new(),
            connections: Connections(Arc::new(AtomicUsize::new(0))),
        }
    }

    pub fn connections(&self) -> Connections {
        self.connections.clone()
    }

    /// Register before spawning, so even a setup panic releases the barrier.
    pub fn worker(&mut self) -> BenchMetrics {
        let slot = Arc::new(Slot::default());
        self.slots.push(slot.clone());
        BenchMetrics::with_worker(Worker {
            slot,
            phase: self.phase.subscribe(),
            window: None,
            offered_at: Instant::now(),
            warmup_offered: false,
        })
    }

    async fn wait_for(&self, state: usize) {
        while self.slots.iter().any(|slot| {
            let actual = slot.state.load(Ordering::Acquire);
            actual != state && actual != DONE
        }) {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    pub async fn finish(
        self,
        handles: Vec<tokio::task::JoinHandle<anyhow::Result<BenchMetrics>>>,
    ) -> BenchMetrics {
        let aborts: Vec<_> = handles.iter().map(|handle| handle.abort_handle()).collect();
        // Collection runs during preflight too: a returned worker drops its
        // registration here, even if it failed before reaching either barrier.
        let collector = tokio::spawn(collect_results(handles));
        let mut collection = Box::pin(async {
            match collector.await {
                Ok(metrics) => metrics,
                Err(error) => {
                    eprintln!("collector failed: {error}");
                    let mut metrics = BenchMetrics::new();
                    metrics.record_error();
                    metrics
                }
            }
        });
        let mut phases = PhaseReport::default();
        let mut observed = Observed {
            sampling_interval_ms: 10,
            ..Observed::default()
        };
        let preflight = async {
            self.wait_for(READY).await;
            phases.setup_secs = self.created.elapsed().as_secs_f64();
            let warmup = Instant::now();
            self.phase.send_replace(Phase::Warmup);
            self.wait_for(BARRIER).await;
            phases.warmup_secs = warmup.elapsed().as_secs_f64();
        };
        if tokio::time::timeout(Duration::from_secs(30), preflight)
            .await
            .is_err()
        {
            phases.timed_out = true;
        } else {
            let barrier = Instant::now();
            observed.workers_at_barrier = self
                .slots
                .iter()
                .filter(|slot| slot.state.load(Ordering::Acquire) == BARRIER)
                .count();
            let start = Instant::now();
            let end = start + self.duration;
            phases.barrier_secs = start.duration_since(barrier).as_secs_f64();
            phases.measurement_secs = self.duration.as_secs_f64();
            phases.measurement_start_unix_secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .map(|elapsed| elapsed.as_secs_f64());
            self.phase.send_replace(Phase::Measure { start, end });
            // Sample independently of worker joins, including after worker loss.
            while Instant::now() < end {
                let mut workers = 0;
                let mut streams = 0;
                let mut queued = 0;
                for slot in &self.slots {
                    let state = slot.state.load(Ordering::Acquire);
                    workers += usize::from(state == BARRIER || state == MEASURING);
                    streams += slot.active.load(Ordering::Relaxed);
                    queued += slot.queued.load(Ordering::Relaxed);
                }
                observed.samples += 1;
                observed.active_workers.observe(workers, observed.samples);
                observed.active_connections.observe(
                    self.connections.0.load(Ordering::Relaxed),
                    observed.samples,
                );
                observed.active_streams.observe(streams, observed.samples);
                observed.queued_requests.observe(queued, observed.samples);
                tokio::time::sleep_until(
                    (Instant::now() + Duration::from_millis(10)).min(end).into(),
                )
                .await;
            }
        }
        self.phase.send_replace(Phase::Stop);
        let drain = Instant::now();
        // Abort only after a bounded drain. Join every task; never detach it.
        if phases.timed_out {
            for handle in &aborts {
                handle.abort();
            }
        }
        let mut combined =
            match tokio::time::timeout(Duration::from_secs(30), &mut collection).await {
                Ok(metrics) => metrics,
                Err(_) => {
                    phases.timed_out = true;
                    for handle in aborts {
                        handle.abort();
                    }
                    collection.await
                }
            };
        phases.drain_secs = drain.elapsed().as_secs_f64();
        for slot in &self.slots {
            observed.queue_time_ns += slot.queue_ns.load(Ordering::Relaxed);
            observed.admissions += slot.admissions.load(Ordering::Relaxed);
            observed.workers_retired_before_deadline +=
                usize::from(slot.retired_early.load(Ordering::Relaxed));
        }
        combined.phases = Some(phases);
        combined.observed = Some(observed);
        combined
    }
}
