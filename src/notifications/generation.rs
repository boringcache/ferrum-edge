//! Per-plugin-generation tracking for notification dispatch tasks.
//!
//! Each producer (today: `proxy_alerts`) owns one [`DispatchGeneration`]. While
//! the generation is admitting, new work may be spawned through the process
//! observability delivery registry. On reload/`Drop` the generation stops
//! admitting and cooperatively cancels in-flight work; tasks that observe the
//! cancel flag settle as [`DispatchSettle::Abandoned`]. Process shutdown
//! drains the same tasks under the global observability budget and aborts
//! whatever remains when the deadline expires — those aborts also settle as
//! abandoned via [`DeliveryTaskGuard`].

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use tokio::sync::Notify;

use super::metrics::{DeliveryMetrics, global as global_metrics};

/// Tracks in-flight dispatch tasks for one plugin-instance generation.
#[derive(Debug)]
pub struct DispatchGeneration {
    id: u64,
    admitting: AtomicBool,
    /// Cooperative cancel: set on retire/Drop so retry loops stop.
    cancelled: AtomicBool,
    in_flight: AtomicUsize,
    drained: Notify,
    metrics: Arc<DeliveryMetrics>,
    next_task_id: AtomicU64,
}

impl DispatchGeneration {
    pub fn new(id: u64) -> Arc<Self> {
        Self::with_metrics(id, Arc::clone(global_metrics()))
    }

    pub fn with_metrics(id: u64, metrics: Arc<DeliveryMetrics>) -> Arc<Self> {
        Arc::new(Self {
            id,
            admitting: AtomicBool::new(true),
            cancelled: AtomicBool::new(false),
            in_flight: AtomicUsize::new(0),
            drained: Notify::new(),
            metrics,
            next_task_id: AtomicU64::new(1),
        })
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn is_admitting(&self) -> bool {
        self.admitting.load(Ordering::Acquire)
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    pub fn metrics(&self) -> &Arc<DeliveryMetrics> {
        &self.metrics
    }

    pub fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::Acquire)
    }

    /// Stop admitting new work without cancelling in-flight tasks.
    pub fn close_admission(&self) {
        self.admitting.store(false, Ordering::Release);
    }

    /// Stop admitting and signal cooperative cancel to every in-flight task.
    pub fn cancel(&self) {
        self.admitting.store(false, Ordering::Release);
        self.cancelled.store(true, Ordering::Release);
    }

    fn begin_task(&self) {
        self.in_flight.fetch_add(1, Ordering::AcqRel);
    }

    fn end_task(&self) {
        let prev = self.in_flight.fetch_sub(1, Ordering::AcqRel);
        if prev <= 1 {
            self.drained.notify_waiters();
        }
    }

    /// Wait until in-flight reaches zero or `timeout` elapses.
    pub async fn wait_drain(&self, timeout: std::time::Duration) -> bool {
        if self.in_flight.load(Ordering::Acquire) == 0 {
            return true;
        }
        let wait = async {
            loop {
                if self.in_flight.load(Ordering::Acquire) == 0 {
                    return true;
                }
                self.drained.notified().await;
            }
        };
        matches!(tokio::time::timeout(timeout, wait).await, Ok(true))
    }

    /// Spawn a dispatch future into the global observability delivery registry.
    ///
    /// Returns `false` when this generation is closed or the global registry
    /// rejects admission (shutdown / capacity). Rejection is a visible drop —
    /// never queued. On rejection the caller is responsible for any
    /// pending-state rollback; metrics record `abandoned_at_deadline`.
    pub fn spawn<F>(self: &Arc<Self>, channel_type: &'static str, future: F) -> bool
    where
        F: Future<Output = DispatchSettle> + Send + 'static,
    {
        if !self.is_admitting() || self.is_cancelled() {
            return false;
        }
        let generation = Arc::clone(self);
        let _task_id = self.next_task_id.fetch_add(1, Ordering::Relaxed);

        // Reserve local in-flight + attempted before asking the global registry
        // so a successful handoff cannot race a zero in-flight read on Drop.
        generation.begin_task();
        generation.metrics.record_attempted(channel_type);

        let (start_tx, start_rx) = tokio::sync::oneshot::channel::<()>();
        let admitted = crate::observability_delivery::spawn_terminal({
            let generation = Arc::clone(&generation);
            async move {
                if start_rx.await.is_err() {
                    // Caller rolled back admission; do not settle again.
                    return;
                }
                let mut guard = DeliveryTaskGuard {
                    generation: Arc::clone(&generation),
                    channel_type,
                    settled: false,
                };
                let settle = if generation.is_cancelled() {
                    DispatchSettle::Abandoned
                } else {
                    future.await
                };
                guard.settle(settle);
            }
        });

        if !admitted {
            // Reverse attempted/in-flight. The terminal future was dropped
            // without polling, so its guard never ran.
            generation.metrics.record_abandoned_at_deadline(channel_type);
            generation.end_task();
            drop(start_tx);
            return false;
        }
        let _ = start_tx.send(());
        true
    }
}

/// Terminal settle outcome recorded exactly once per dispatch task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchSettle {
    Succeeded,
    FailedTransient,
    FailedPermanent,
    Abandoned,
}

/// Ensures a cancelled/aborted dispatch task still decrements in-flight and
/// records abandonment when the future is dropped without settling.
struct DeliveryTaskGuard {
    generation: Arc<DispatchGeneration>,
    channel_type: &'static str,
    settled: bool,
}

impl DeliveryTaskGuard {
    fn settle(&mut self, outcome: DispatchSettle) {
        if self.settled {
            return;
        }
        self.settled = true;
        match outcome {
            DispatchSettle::Succeeded => {
                self.generation.metrics.record_succeeded(self.channel_type);
            }
            DispatchSettle::FailedTransient => {
                self.generation
                    .metrics
                    .record_failed_transient(self.channel_type);
            }
            DispatchSettle::FailedPermanent => {
                self.generation
                    .metrics
                    .record_failed_permanent(self.channel_type);
            }
            DispatchSettle::Abandoned => {
                self.generation
                    .metrics
                    .record_abandoned_at_deadline(self.channel_type);
            }
        }
        self.generation.end_task();
    }
}

impl Drop for DeliveryTaskGuard {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        // Hard abort (shutdown deadline) or panic: count as abandoned.
        self.generation
            .metrics
            .record_abandoned_at_deadline(self.channel_type);
        self.generation.end_task();
    }
}
