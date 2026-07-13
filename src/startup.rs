use std::fmt::Display;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use tokio::sync::oneshot;

const SANITIZED_LISTENER_FAILURE: &str = "listener serve task exited after successful bind";

/// Durable, lock-free snapshot of serving listeners that exited after bind.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ServingListenerFailure {
    pub listener: String,
    pub listen_port: u16,
    pub error: String,
    pub kind: ServingListenerFailureKind,
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServingListenerFailureKind {
    ServeFailed,
}

#[derive(Debug, serde::Serialize)]
pub struct ServingListenerFailureSnapshot {
    pub failures_total: usize,
    pub failures: Vec<ServingListenerFailure>,
}

/// Failure-path-only recorder shared by listener tasks and authenticated admin
/// observability. Entries are monotonic for the process lifetime, matching the
/// sticky serving-degraded readiness signal.
#[derive(Debug)]
pub struct ServingListenerFailures {
    failures: arc_swap::ArcSwap<Vec<ServingListenerFailure>>,
}

impl Default for ServingListenerFailures {
    fn default() -> Self {
        Self {
            failures: arc_swap::ArcSwap::from_pointee(Vec::new()),
        }
    }
}

impl ServingListenerFailures {
    pub fn record(&self, listener: &str, listen_port: u16) {
        self.failures.rcu(|current| {
            if current
                .iter()
                .any(|failure| failure.listener == listener && failure.listen_port == listen_port)
            {
                return Arc::clone(current);
            }
            let mut updated = current.as_ref().clone();
            updated.push(ServingListenerFailure {
                listener: listener.to_string(),
                listen_port,
                // Never retain the underlying error: listener errors may carry
                // operator-controlled paths or metadata. The structured log is
                // the transient diagnostic; this durable surface is sanitized.
                error: SANITIZED_LISTENER_FAILURE.to_string(),
                kind: ServingListenerFailureKind::ServeFailed,
            });
            Arc::new(updated)
        });
    }

    pub fn snapshot(&self) -> ServingListenerFailureSnapshot {
        let failures = self.failures.load_full();
        ServingListenerFailureSnapshot {
            failures_total: failures.len(),
            failures: failures.as_ref().clone(),
        }
    }
}

/// Record that a serving listener/server task exited with an error after
/// startup and durably drive the shared readiness flags to not-ready.
///
/// Listener task closures (proxy HTTP/HTTPS/H3, admin HTTP/HTTPS, CP gRPC)
/// historically only logged the serve error and then returned, leaving the
/// process reporting `ready` on `/health` while a serving surface was silently
/// dead. Calling this on the error path emits a structured error log and drives
/// two flags:
///
/// * `serving_degraded` — a **sticky** monotonic signal set to `true` and never
///   unset. The `/health` readiness computation reports not-ready when this is
///   `true` OR `startup_ready` is `false`. It exists because `startup_ready`
///   alone is not durable: a mode's main startup path stores `startup_ready =
///   true` after the flip could already have fired (CP: the gRPC serve future
///   can error between the start signal and the main task's `store(true)`; DP:
///   every CP-reconnect snapshot re-stores `true`), which would re-mask the
///   outage. Because `serving_degraded` is never unset, a post-start serve
///   failure stays visible on `/health` across those later `store(true)` calls.
/// * `startup_ready` — flipped to `false` as a best-effort fast path so a probe
///   racing in before the next readiness read still observes not-ready
///   immediately. This store may be clobbered by a later `store(true)`; the
///   sticky `serving_degraded` flag is the durable guarantee.
///
/// Both stores use `Release` to pair with the `/health` `Acquire` loads, giving
/// the probe cross-task visibility of the flip.
pub fn flip_ready_off_on_listener_failure<E: Display>(
    startup_ready: &AtomicBool,
    serving_degraded: &AtomicBool,
    listener: &str,
    err: &E,
) {
    // Sticky: set once, never unset, so a later `startup_ready.store(true)`
    // on the mode's main startup path cannot re-mask this outage.
    serving_degraded.store(true, Ordering::Release);
    // Best-effort fast path; the durable guarantee is `serving_degraded`.
    startup_ready.store(false, Ordering::Release);
    tracing::error!(
        listener = listener,
        error = %err,
        "Serving listener task exited with an error; marked serving degraded and flipped readiness to not-ready"
    );
}

/// Record a durable sanitized listener-failure snapshot and flip readiness via
/// the shared sticky degradation mechanism.
pub fn record_post_start_listener_failure<E: Display>(
    startup_ready: &AtomicBool,
    serving_degraded: &AtomicBool,
    failures: &ServingListenerFailures,
    listener: &str,
    listen_port: u16,
    err: &E,
) {
    failures.record(listener, listen_port);
    flip_ready_off_on_listener_failure(startup_ready, serving_degraded, listener, err);
}

/// Wait for one or more listener startup signals.
///
/// Each signal should be sent only after the listener has successfully bound
/// and is ready to accept traffic.
pub async fn wait_for_start_signals(
    signals: Vec<(String, oneshot::Receiver<()>)>,
    timeout: Duration,
) -> Result<(), anyhow::Error> {
    let deadline = tokio::time::Instant::now() + timeout;

    for (name, rx) in signals {
        let Some(remaining) = deadline.checked_duration_since(tokio::time::Instant::now()) else {
            return Err(anyhow::anyhow!(
                "Timed out waiting for {} to complete startup",
                name
            ));
        };

        match tokio::time::timeout(remaining, rx).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                return Err(anyhow::anyhow!("{} exited before completing startup", name));
            }
            Err(_) => {
                return Err(anyhow::anyhow!(
                    "Timed out waiting for {} to complete startup",
                    name
                ));
            }
        }
    }

    Ok(())
}
