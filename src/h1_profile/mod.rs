//! Default-off hosted H1 measurement. See docs/h1_internal_profile.md.
mod allocator;
pub mod io;
pub mod schema;
mod store;

use std::fmt::Write;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body::Frame;

pub use allocator::{ForwardingAllocator, Scope, in_scope};
pub use store::{Snapshot, current_thread_counters, publish_current_thread, snapshot};

static ALLOCATOR_INSTALLED: AtomicBool = AtomicBool::new(false);

/// Register the process allocator only from a binary that declares
/// `ForwardingAllocator` as its global allocator. Linking the library or using
/// a forwarding allocator locally does not establish process-wide coverage.
pub fn register_global_allocator() {
    ALLOCATOR_INSTALLED.store(true, Ordering::Relaxed);
}

pub fn count(counter: usize, amount: usize) {
    store::with_local(|local| local.add(counter, amount as u64));
}

/// 0: reqwest direct input; 1: reqwest coalesced input; 2: all ProxyBody output.
pub fn body_poll<E>(boundary: usize, result: &Poll<Option<Result<Frame<Bytes>, E>>>) {
    if boundary > 2 {
        count(schema::OVERFLOW, 1);
        return;
    }
    store::with_local(|local| {
        let base = schema::BODY_BASE + boundary * schema::BODY_FIELDS;
        local.add(base, 1);
        match result {
            Poll::Pending => local.add(base + 6, 1),
            Poll::Ready(None) => local.add(base + 5, 1),
            Poll::Ready(Some(Err(_))) => local.add(base + 4, 1),
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    local.add(base + 1, 1);
                    local.add(base + 2, data.len() as u64);
                    let bucket = match data.len() {
                        0 => 7,
                        1..=1024 => 8,
                        1025..=16384 => 9,
                        16385..=131072 => 10,
                        131073..=1048576 => 11,
                        _ => 12,
                    };
                    local.add(base + bucket, 1);
                } else {
                    local.add(base + 3, 1);
                }
            }
        }
    });
}

pub struct ObservedStream<S> {
    inner: S,
    boundary: usize,
}

impl<S> ObservedStream<S> {
    pub fn new(inner: S, boundary: usize) -> Self {
        Self { inner, boundary }
    }
}

impl<S, E> futures_util::Stream for ObservedStream<S>
where
    S: futures_util::Stream<Item = Result<Frame<Bytes>, E>> + Unpin,
{
    type Item = S::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let result = in_scope(Scope::BodyInput, || Pin::new(&mut this.inner).poll_next(cx));
        body_poll(this.boundary, &result);
        result
    }
}

/// Fixed metrics on the existing authenticated endpoint. Export allocations
/// themselves remain in process totals, outside explicitly instrumented scopes.
pub fn render_prometheus() -> String {
    let snapshot = snapshot();
    let mut text = String::new();
    let metadata = [
        ("schema", schema::SCHEMA_VERSION),
        ("pid", u64::from(std::process::id())),
        ("registered_slots", snapshot.registered_slots),
        ("missing_slots", snapshot.missing_slots),
        ("unpublished_events", snapshot.unpublished_events),
        ("lost_events", snapshot.lost_events),
        ("slot_capacity", store::THREAD_SLOTS as u64),
        (
            "allocator_installed",
            u64::from(ALLOCATOR_INSTALLED.load(Ordering::Relaxed)),
        ),
    ];
    for (name, value) in metadata {
        let _ = writeln!(text, "ferrum_h1_profile_{name} {value}");
    }
    for (name, value) in schema::NAMES.iter().zip(snapshot.values) {
        let _ = writeln!(text, "ferrum_h1_profile_{name} {value}");
    }
    text
}
