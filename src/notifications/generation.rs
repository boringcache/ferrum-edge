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

/// Optional completion callback invoked exactly once after a delivery settles.
///
/// The generation owns this callback, rather than the user future, so a task
/// rejected during admission or hard-aborted before its first poll still rolls
/// back producer state.
pub type DeliveryCallback = Arc<dyn Fn(DispatchSettle) + Send + Sync>;

/// Tracks in-flight dispatch tasks for one plugin-instance generation.
#[derive(Debug)]
pub struct DispatchGeneration {
    id: u64,
    admitting: AtomicBool,
    /// Cooperative cancel: set on retire/Drop so retry loops stop.
    cancelled: AtomicBool,
    /// Spawn calls between method entry and completed registry handoff/reject.
    /// Drain waits for these registrations so closing admission cannot race a
    /// caller that observed the old `admitting=true` value but has not yet
    /// incremented `in_flight`.
    active_spawns: AtomicUsize,
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
            active_spawns: AtomicUsize::new(0),
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

    fn end_spawn(&self) {
        let prev = self.active_spawns.fetch_sub(1, Ordering::AcqRel);
        if prev <= 1 {
            self.drained.notify_waiters();
        }
    }

    fn is_drained(&self) -> bool {
        self.active_spawns.load(Ordering::Acquire) == 0
            && self.in_flight.load(Ordering::Acquire) == 0
    }

    /// Wait until spawn handoffs and in-flight tasks reach zero or `timeout`
    /// elapses.
    pub async fn wait_drain(&self, timeout: std::time::Duration) -> bool {
        if self.is_drained() {
            return true;
        }
        let wait = async {
            loop {
                // Construct the notification future before checking the
                // counters so a zero transition cannot land between the check
                // and waiter registration.
                let notified = self.drained.notified();
                if self.is_drained() {
                    return true;
                }
                notified.await;
            }
        };
        matches!(tokio::time::timeout(timeout, wait).await, Ok(true))
    }

    /// Spawn a dispatch future into the global observability delivery registry.
    ///
    /// Returns `false` when this generation is closed or the global registry
    /// rejects admission (shutdown / capacity). Rejection is a visible drop —
    /// never queued. The generation invokes `on_settle(Abandoned)` on every
    /// rejection path; admitted attempts also record `abandoned_at_deadline`.
    pub fn spawn<F>(
        self: &Arc<Self>,
        channel_type: &'static str,
        on_settle: Option<DeliveryCallback>,
        future: F,
    ) -> bool
    where
        F: Future<Output = DispatchSettle> + Send + 'static,
    {
        self.active_spawns.fetch_add(1, Ordering::AcqRel);
        let _spawn_registration = SpawnRegistration {
            generation: self.as_ref(),
        };
        if !self.is_admitting() || self.is_cancelled() {
            if let Some(callback) = on_settle {
                invoke_delivery_callback(&callback, DispatchSettle::Abandoned, channel_type);
            }
            return false;
        }
        let generation = Arc::clone(self);
        let _task_id = self.next_task_id.fetch_add(1, Ordering::Relaxed);

        // Reserve local in-flight + attempted before asking the global registry
        // so a successful handoff cannot race a zero in-flight read on Drop.
        generation.begin_task();
        generation.metrics.record_attempted(channel_type);

        // Construct the settlement guard before handing the future to the
        // process registry. If admission rejects, shutdown aborts the task
        // before its first poll, or the task panics, dropping the captured guard
        // still records abandonment and invokes the producer callback.
        let settlement = Arc::new(DeliveryTaskSettlement {
            generation: Arc::clone(&generation),
            channel_type,
            on_settle,
            settled: AtomicBool::new(false),
        });
        let guard = DeliveryTaskGuard {
            settlement: Arc::clone(&settlement),
        };
        let admitted = crate::observability_delivery::spawn_terminal({
            let generation = Arc::clone(&generation);
            async move {
                let settle = if generation.is_cancelled() {
                    DispatchSettle::Abandoned
                } else {
                    future.await
                };
                guard.settle(settle);
            }
        });

        if !admitted {
            // The registry may drop/abort its future asynchronously. Settle
            // synchronously here; the captured guard is protected by the same
            // atomic exactly-once edge and becomes a no-op when it is dropped.
            settlement.settle(DispatchSettle::Abandoned);
            return false;
        }
        true
    }
}

struct SpawnRegistration<'a> {
    generation: &'a DispatchGeneration,
}

impl Drop for SpawnRegistration<'_> {
    fn drop(&mut self) {
        self.generation.end_spawn();
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

/// Shared exactly-once settlement edge. The caller keeps a reference until the
/// process registry confirms admission; the task guard owns the other reference.
struct DeliveryTaskSettlement {
    generation: Arc<DispatchGeneration>,
    channel_type: &'static str,
    on_settle: Option<DeliveryCallback>,
    settled: AtomicBool,
}

impl DeliveryTaskSettlement {
    fn settle(&self, outcome: DispatchSettle) {
        if self
            .settled
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
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
        if let Some(callback) = self.on_settle.as_ref() {
            invoke_delivery_callback(callback, outcome, self.channel_type);
        }
        // A drained generation guarantees producer settlement is complete, not
        // merely that the transport future returned.
        self.generation.end_task();
    }
}

fn invoke_delivery_callback(
    callback: &DeliveryCallback,
    outcome: DispatchSettle,
    channel_type: &'static str,
) {
    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| callback(outcome))).is_err() {
        tracing::warn!(
            channel_type,
            ?outcome,
            "notification delivery settle callback panicked; state rollback may be incomplete"
        );
    }
}

/// Ensures a cancelled/aborted dispatch task still decrements in-flight,
/// records abandonment, and rolls back producer state when its future is
/// dropped without returning a settle outcome.
struct DeliveryTaskGuard {
    settlement: Arc<DeliveryTaskSettlement>,
}

impl DeliveryTaskGuard {
    fn settle(&self, outcome: DispatchSettle) {
        self.settlement.settle(outcome);
    }
}

impl Drop for DeliveryTaskGuard {
    fn drop(&mut self) {
        // Hard abort (shutdown deadline) or panic: count as abandoned.
        self.settlement.settle(DispatchSettle::Abandoned);
    }
}
