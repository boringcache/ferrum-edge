//! Capacity-one, latest-wins handoff for Workload API rotation streams.
//!
//! SPIFFE Workload API rotation notifications represent *current state*, not a
//! loss-sensitive event log. An accumulating FIFO therefore buys nothing while
//! retaining superseded private-key-bearing `X509SVID` payloads when a consumer
//! stops polling (HTTP/2 flow control, stalled sidecar, etc.).
//!
//! This primitive keeps at most one unread value:
//!
//! - [`LatestWinsSender::publish`] replaces any unread prior value in place so
//!   the superseded payload is dropped immediately (no clone of the discard).
//! - Dropping the receiver drops any pending value and wakes the sender's
//!   [`LatestWinsSender::closed`] waiters so rotation tasks exit promptly.
//! - Dropping the sender lets the receiver drain a final pending value, then
//!   end the stream cleanly with `None`.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use futures_util::stream::BoxStream;
use tokio::sync::Notify;

/// Create a capacity-one latest-wins channel.
pub fn channel<T>() -> (LatestWinsSender<T>, LatestWinsReceiver<T>) {
    let inner = Arc::new(Inner {
        slot: Mutex::new(Slot {
            value: None,
            sender_alive: true,
        }),
        data: Notify::new(),
        receiver_gone: AtomicBool::new(false),
        receiver_gone_notify: Notify::new(),
        pending: AtomicUsize::new(0),
    });
    (
        LatestWinsSender {
            inner: Arc::clone(&inner),
        },
        LatestWinsReceiver { inner },
    )
}

#[derive(Debug)]
struct Slot<T> {
    value: Option<T>,
    sender_alive: bool,
}

struct Inner<T> {
    slot: Mutex<Slot<T>>,
    data: Notify,
    receiver_gone: AtomicBool,
    receiver_gone_notify: Notify,
    pending: AtomicUsize,
}

/// Producer handle. One rotation task owns the send side so drop unambiguously
/// ends the stream after any final pending value is drained.
pub struct LatestWinsSender<T> {
    inner: Arc<Inner<T>>,
}

/// Consumer handle. Values are moved out of the slot (no clone of
/// secret-bearing payloads on delivery).
pub struct LatestWinsReceiver<T> {
    inner: Arc<Inner<T>>,
}

impl<T> LatestWinsSender<T> {
    /// Publish `value`, replacing any unread prior value.
    ///
    /// Returns `false` when the receiver is gone (caller should stop producing).
    /// A replaced prior value is dropped before this returns.
    pub fn publish(&self, value: T) -> bool {
        if self.inner.receiver_gone.load(Ordering::Acquire) {
            return false;
        }
        {
            let mut slot = self
                .inner
                .slot
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if self.inner.receiver_gone.load(Ordering::Acquire) {
                return false;
            }
            let replaced = slot.value.replace(value).is_some();
            if !replaced {
                self.inner.pending.fetch_add(1, Ordering::Release);
            }
        }
        // Notify after releasing the lock so a woken receiver can take the slot.
        self.inner.data.notify_one();
        true
    }

    /// Resolves when the receiver has been dropped (stream cancelled / client
    /// gone). Rotation tasks select on this so producer shutdown does not wait
    /// on a slow consumer.
    pub async fn closed(&self) {
        let notified = self.inner.receiver_gone_notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if self.inner.receiver_gone.load(Ordering::Acquire) {
            return;
        }
        notified.await;
    }
}

impl<T> Drop for LatestWinsSender<T> {
    fn drop(&mut self) {
        {
            let mut slot = self
                .inner
                .slot
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            slot.sender_alive = false;
        }
        self.inner.data.notify_waiters();
    }
}

impl<T> LatestWinsReceiver<T> {
    /// Number of unread values currently retained (0 or 1).
    pub fn pending_len(&self) -> usize {
        self.inner.pending.load(Ordering::Acquire)
    }

    /// Take the newest unread value, waiting until one is published or the
    /// sender ends the stream.
    pub async fn recv(&mut self) -> Option<T> {
        loop {
            let notified = self.inner.data.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            if let Some(value) = self.try_take() {
                return Some(value);
            }
            {
                let slot = self
                    .inner
                    .slot
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if !slot.sender_alive && slot.value.is_none() {
                    return None;
                }
            }
            notified.await;
        }
    }

    /// Convert into a boxed [`futures_util::Stream`] that yields moved values
    /// until the sender ends.
    ///
    /// Boxed so the returned stream is `Unpin`: `stream::unfold`'s async-block
    /// state future is never `Unpin`, and callers across the crate use
    /// `StreamExt::next` on the returned value.
    pub fn into_stream(self) -> BoxStream<'static, T>
    where
        T: Send + 'static,
    {
        Box::pin(futures_util::stream::unfold(self, |mut rx| async move {
            rx.recv().await.map(|item| (item, rx))
        }))
    }

    fn try_take(&self) -> Option<T> {
        let mut slot = self
            .inner
            .slot
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let value = slot.value.take()?;
        self.inner.pending.store(0, Ordering::Release);
        Some(value)
    }
}

impl<T> Drop for LatestWinsReceiver<T> {
    fn drop(&mut self) {
        {
            let mut slot = self
                .inner
                .slot
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            // Drop any pending secret-bearing payload promptly on cancel.
            slot.value = None;
            self.inner.pending.store(0, Ordering::Release);
        }
        self.inner.receiver_gone.store(true, Ordering::Release);
        self.inner.receiver_gone_notify.notify_waiters();
        self.inner.data.notify_waiters();
    }
}
