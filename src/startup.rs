use std::fmt::Display;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::sync::oneshot;

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
