use std::fmt::Display;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::sync::oneshot;

/// Record that a serving listener/server task exited with an error after
/// startup and flip the shared readiness flag to not-ready.
///
/// Listener task closures (proxy HTTP/HTTPS/H3, admin HTTP/HTTPS, CP gRPC)
/// historically only logged the serve error and then returned, leaving the
/// process reporting `ready` on `/health` while a serving surface was silently
/// dead. Calling this on the error path flips `startup_ready` back to `false`
/// (the `Release` store pairs with the `/health` `Acquire` load, giving the
/// probe cross-task visibility of the flip) and emits a structured error log so
/// the outage is honest instead of silent.
///
/// The flag is only ever flipped *off* here; per-mode startup paths flip it
/// *on* exactly once after the initial config/listeners are proven, so a
/// post-startup serve failure is never re-masked by a later readiness flip.
pub fn flip_ready_off_on_listener_failure<E: Display>(
    startup_ready: &AtomicBool,
    listener: &str,
    err: &E,
) {
    startup_ready.store(false, Ordering::Release);
    tracing::error!(
        listener = listener,
        error = %err,
        "Serving listener task exited with an error; flipped readiness to not-ready"
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
