//! Bounded-concurrency notification dispatch with classified retries.
//!
//! `dispatch` / `dispatch_one` fan a [`Notification`] out under a caller-supplied
//! `Semaphore`. Each channel send runs on a detached task admitted through
//! [`crate::observability_delivery`] so process shutdown can drain it under the
//! global budget. When the semaphore is exhausted the alert is dropped with a
//! `warn!` (and a backpressure metric) rather than queued.
//!
//! Transient transport/HTTP failures retry inside the same task with a bounded,
//! jittered backoff while holding the semaphore permit — retries never enqueue
//! additional work and never block the caller's request-hook thread.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::warn;

use crate::plugins::utils::http_client::PluginHttpClient;

use super::channels::NotificationChannel;
use super::generation::{DispatchGeneration, DispatchSettle};
use super::metrics::global as global_metrics;
use super::notification::Notification;
use super::outcome::{DeliveryAttempt, FailureClass};

/// Default retry policy for notification channels.
///
/// `max_retries` is the number of *re*-attempts after the initial try
/// (so `max_retries = 2` means up to 3 total attempts).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeliveryRetryPolicy {
    pub max_retries: u32,
    pub base_delay: Duration,
    pub max_delay: Duration,
}

impl DeliveryRetryPolicy {
    pub const DEFAULT: Self = Self {
        max_retries: 2,
        base_delay: Duration::from_millis(100),
        max_delay: Duration::from_millis(2_000),
    };

    /// Compute the sleep after a failed attempt `attempt` (1-based).
    ///
    /// Exponential backoff `base * 2^(attempt-1)` capped at `max_delay`, with
    /// full jitter in `[0, capped]` (same strategy as the batching logger).
    pub fn backoff_delay(self, attempt: u32) -> Duration {
        const MAX_TOKIO_SLEEP_MS: u64 = 60_000;
        let base_ms = self.base_delay.as_millis().min(u128::from(MAX_TOKIO_SLEEP_MS)) as u64;
        let cap_ms = self
            .max_delay
            .as_millis()
            .min(u128::from(MAX_TOKIO_SLEEP_MS))
            .max(u128::from(base_ms)) as u64;
        let shift = attempt.saturating_sub(1).min(63);
        let grown = base_ms.saturating_mul(1u64 << shift);
        let capped = grown.min(cap_ms);
        let final_ms = if capped > 0 {
            let counter = JITTER_COUNTER
                .fetch_add(1, Ordering::Relaxed)
                .wrapping_add(*JITTER_SEED);
            let hash = counter
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            hash % capped.saturating_add(1)
        } else {
            0
        };
        Duration::from_millis(final_ms)
    }
}

impl Default for DeliveryRetryPolicy {
    fn default() -> Self {
        Self::DEFAULT
    }
}

static JITTER_COUNTER: AtomicU64 = AtomicU64::new(1);
static JITTER_SEED: std::sync::LazyLock<u64> = std::sync::LazyLock::new(|| {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0xA5A5_A5A5_A5A5_A5A5)
});

/// Optional completion callback invoked after the final delivery settle
/// (success, permanent failure, exhausted transient retries, or abandon).
///
/// Used by `proxy_alerts` to arm cooldown / commit incident state only on a
/// defined outcome. The callback must not await and must not take locks that
/// the request hot path also holds across awaits.
pub type DeliveryCallback = Arc<dyn Fn(DispatchSettle) + Send + Sync>;

/// Fan `notification` out to every channel in `targets`.
///
/// Legacy helper for non-plugin callers. Uses process-global metrics and a
/// one-shot anonymous generation so tasks still participate in shutdown drain.
#[allow(dead_code)]
pub fn dispatch(
    notification: Arc<Notification>,
    targets: &[Arc<NotificationChannel>],
    sem: &Arc<Semaphore>,
    http: &PluginHttpClient,
    log_source: &'static str,
) {
    let generation = DispatchGeneration::new(0);
    let extras = Arc::new(std::collections::HashMap::new());
    for channel in targets {
        let _ = dispatch_one(
            Arc::clone(&notification),
            Arc::clone(extras),
            Arc::clone(channel),
            Arc::clone(sem),
            http.clone(),
            Arc::clone(&generation),
            DeliveryRetryPolicy::DEFAULT,
            log_source,
            None,
        );
    }
}

/// Attempt to acquire a permit and spawn one channel delivery.
///
/// Returns `false` when the semaphore was exhausted, the generation rejected
/// admission, or the global delivery registry rejected the task. In every
/// rejection case the alert is dropped (never queued) and metrics/logs record
/// the drop.
#[allow(clippy::too_many_arguments)]
pub fn dispatch_one(
    notification: Arc<Notification>,
    extras: Arc<std::collections::HashMap<String, String>>,
    channel: Arc<NotificationChannel>,
    sem: Arc<Semaphore>,
    http: PluginHttpClient,
    generation: Arc<DispatchGeneration>,
    retry: DeliveryRetryPolicy,
    log_source: &'static str,
    on_settle: Option<DeliveryCallback>,
) -> bool {
    let channel_type = channel.kind();
    let permit = match Arc::clone(&sem).try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            global_metrics().record_backpressure_dropped(channel_type);
            warn!(
                source = log_source,
                channel = %channel.name(),
                channel_type,
                "notification dispatch backpressure: dropping notification"
            );
            if let Some(cb) = on_settle.as_ref() {
                // Backpressure is not a delivery attempt; surface as abandoned
                // so callers that reserved pending state can roll it back.
                cb(DispatchSettle::Abandoned);
            }
            return false;
        }
    };

    let spawned = generation.spawn(channel_type, {
        let channel = Arc::clone(&channel);
        let generation = Arc::clone(&generation);
        let on_settle = on_settle.clone();
        async move {
            let settle =
                run_with_retries(channel, notification, extras, http, permit, retry, &generation, log_source)
                    .await;
            if let Some(cb) = on_settle {
                cb(settle);
            }
            settle
        }
    });

    if !spawned {
        warn!(
            source = log_source,
            channel = %channel.name(),
            channel_type,
            "notification dispatch rejected by delivery generation or shutdown registry"
        );
        if let Some(cb) = on_settle {
            cb(DispatchSettle::Abandoned);
        }
        return false;
    }
    true
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_with_retries(
    channel: Arc<NotificationChannel>,
    notification: Arc<Notification>,
    extras: Arc<std::collections::HashMap<String, String>>,
    http: PluginHttpClient,
    permit: OwnedSemaphorePermit,
    retry: DeliveryRetryPolicy,
    generation: &DispatchGeneration,
    log_source: &'static str,
) -> DispatchSettle {
    let _permit = permit;
    let max_attempts = retry.max_retries.saturating_add(1).max(1);
    let mut attempt = 0u32;
    loop {
        if generation.is_cancelled() {
            return DispatchSettle::Abandoned;
        }
        attempt = attempt.saturating_add(1);
        let outcome = channel
            .dispatch_classified(&notification, &extras, &http)
            .await;
        match outcome {
            DeliveryAttempt::Success => return DispatchSettle::Succeeded,
            DeliveryAttempt::Failed { class, message } => {
                let retryable = class == FailureClass::Transient && attempt < max_attempts;
                if retryable {
                    warn!(
                        source = log_source,
                        channel = %channel.name(),
                        channel_type = channel.kind(),
                        attempt,
                        max_attempts,
                        error = %message,
                        "notification dispatch transient failure; retrying"
                    );
                    let delay = retry.backoff_delay(attempt);
                    tokio::select! {
                        _ = tokio::time::sleep(delay) => {}
                        _ = cancel_wait(generation) => {
                            return DispatchSettle::Abandoned;
                        }
                    }
                    continue;
                }
                warn!(
                    source = log_source,
                    channel = %channel.name(),
                    channel_type = channel.kind(),
                    attempt,
                    failure_class = class.as_str(),
                    error = %message,
                    "notification dispatch failed"
                );
                return match class {
                    FailureClass::Transient => DispatchSettle::FailedTransient,
                    FailureClass::Permanent => DispatchSettle::FailedPermanent,
                };
            }
        }
    }
}

async fn cancel_wait(generation: &DispatchGeneration) {
    while !generation.is_cancelled() {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}
