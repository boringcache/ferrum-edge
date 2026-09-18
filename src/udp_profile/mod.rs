//! Default-off UDP source-site measurements; see docs/udp_internal_profile.md.
pub mod schema;
mod store;

use std::fmt::Write;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

pub use schema::{BatchField, Counter, Direction, Operation};
pub use store::{Snapshot, current_thread_counters, publish_current_thread, snapshot};

pub fn count(counter: Counter, amount: u64) {
    store::with_local(|local| local.add(counter as usize, amount));
}

/// Executes exactly once, synchronously. No attribution or timer crosses await.
/// Every 64th call per operation per OS thread is timed, starting with the first.
pub fn timed<T>(operation: Operation, f: impl FnOnce() -> T) -> T {
    let op = operation as usize;
    let base = schema::OP_BASE + op * schema::OP_FIELDS;
    let mut sampled = false;
    store::with_local(|local| {
        local.add(base, 1);
        sampled = local.samples[op] == 0;
        local.samples[op] = (local.samples[op] + 1) % schema::SAMPLE_EVERY;
    });
    let start = sampled.then(Instant::now);
    let result = f();
    if let Some(start) = start {
        let elapsed = start.elapsed().as_nanos();
        let nanos = u64::try_from(elapsed).unwrap_or(u64::MAX);
        let bucket = match nanos {
            0..=100 => 6,
            101..=500 => 7,
            501..=1000 => 8,
            1001..=5000 => 9,
            5001..=20000 => 10,
            20001..=100000 => 11,
            100001..=1000000 => 12,
            _ => 13,
        };
        store::with_local(|local| {
            local.add(base + 4, 1);
            local.add(base + 5, nanos);
            local.add(base + bucket, 1);
            if elapsed > u128::from(u64::MAX) {
                local.add(Counter::CounterOverflow as usize, 1);
            }
        });
    }
    result
}

pub fn lookup_outcome(operation: Operation, hit: bool) {
    let index = schema::OP_BASE + operation as usize * schema::OP_FIELDS;
    store::with_local(|local| local.add(index + if hit { 1 } else { 2 }, 1));
}

pub fn operation_error(operation: Operation) {
    let index = schema::OP_BASE + operation as usize * schema::OP_FIELDS + 3;
    store::with_local(|local| local.add(index, 1));
}

fn bucket(slots: usize) -> usize {
    match slots {
        0 => 0,
        1 => 1,
        2..=4 => 2,
        5..=8 => 3,
        9..=16 => 4,
        17..=32 => 5,
        33..=64 => 6,
        _ => 7,
    }
}

pub fn batch_count(direction: Direction, field: BatchField, amount: usize) {
    let base = schema::BATCH_BASE + direction as usize * schema::BATCH_FIELDS;
    store::with_local(|local| local.add(base + field as usize, amount as u64));
}

/// Called only for an actual recvmmsg invocation, before ancillary parsing.
pub fn recvmmsg(direction: Direction, requested: usize, result: &std::io::Result<usize>) {
    let base = schema::BATCH_BASE + direction as usize * schema::BATCH_FIELDS;
    store::with_local(|local| {
        local.add(base, 1);
        local.add(base + 1, requested as u64);
        local.add(base + 39 + bucket(requested), 1);
        match result {
            Ok(returned) => {
                local.add(base + 2, *returned as u64);
                local.add(base + 47 + bucket(*returned), 1);
            }
            Err(error) => {
                let field = if error.kind() == std::io::ErrorKind::WouldBlock {
                    8
                } else {
                    9
                };
                local.add(base + field, 1);
            }
        }
    });
}

/// Occupancy is the actual syscall input, including remaining slots on retries.
pub fn sendmmsg(
    direction: Direction,
    requested: usize,
    result: &std::io::Result<usize>,
    sent_bytes: usize,
) {
    let base = schema::BATCH_BASE + direction as usize * schema::BATCH_FIELDS;
    store::with_local(|local| {
        local.add(base + 11, 1);
        local.add(base + 12, requested as u64);
        local.add(base + 55 + bucket(requested), 1);
        match result {
            Ok(sent) => {
                local.add(base + 13, *sent as u64);
                local.add(base + 14, sent_bytes as u64);
                local.add(base + 63 + bucket(*sent), 1);
                if *sent < requested {
                    local.add(base + 15, 1);
                    local.add(base + 16, (requested - sent) as u64);
                }
            }
            Err(error) => {
                local.add(base + 17, requested as u64);
                let field = if error.kind() == std::io::ErrorKind::WouldBlock {
                    18
                } else {
                    19
                };
                local.add(base + field, 1);
            }
        }
    });
}

pub fn gso(
    direction: Direction,
    segments: usize,
    bytes: usize,
    segment_bytes: usize,
    result: &std::io::Result<usize>,
) {
    let base = schema::BATCH_BASE + direction as usize * schema::BATCH_FIELDS;
    store::with_local(|local| {
        local.add(base + 20, 1);
        local.add(base + 21, segments as u64);
        local.add(base + 22, bytes as u64);
        local.add(base + 23, segment_bytes as u64);
        local.add(base + 71 + bucket(segments), 1);
        match result {
            Ok(sent) => {
                local.add(base + 25, *sent as u64);
                if *sent == bytes {
                    local.add(base + 24, segments as u64);
                } else {
                    // Do not invent accepted segments for a short byte result.
                    local.add(base + 27, 1);
                }
            }
            Err(_) => local.add(base + 26, 1),
        }
    });
}

/// Poll events are not scheduler wakes. Pinning adds no heap allocation.
pub async fn observe_polls<F: Future>(future: F, reply: bool) -> F::Output {
    let mut future = std::pin::pin!(future);
    std::future::poll_fn(|cx| {
        let result = future.as_mut().poll(cx);
        let base = schema::POLL_BASE + if reply { 3 } else { 0 };
        store::with_local(|local| {
            local.add(base, 1);
            let outcome = if result.is_pending() { 1 } else { 2 };
            local.add(base + outcome, 1);
        });
        result
    })
    .await
}

/// Logical direct-send future, not a count of Tokio's internal syscall retries.
pub async fn observe_direct_send<F>(future: F) -> std::io::Result<usize>
where
    F: Future<Output = std::io::Result<usize>>,
{
    batch_count(Direction::Reply, BatchField::DirectCalls, 1);
    let result = future.await;
    direct_outcome(&result);
    result
}

pub fn direct_outcome(result: &std::io::Result<usize>) {
    match result {
        Ok(bytes) => {
            batch_count(Direction::Reply, BatchField::DirectSuccess, 1);
            batch_count(Direction::Reply, BatchField::DirectBytes, *bytes);
        }
        Err(_) => batch_count(Direction::Reply, BatchField::DirectError, 1),
    }
}

pub fn render_prometheus() -> String {
    static SNAPSHOTS: AtomicU64 = AtomicU64::new(0);
    let snapshot = snapshot();
    let mut text = String::new();
    let metadata = [
        ("schema", schema::VERSION),
        ("pid", u64::from(std::process::id())),
        ("sample_every", schema::SAMPLE_EVERY),
        ("publication_interval", store::PUBLICATION_INTERVAL),
        ("slot_capacity", store::THREAD_SLOTS as u64),
        ("registered_slots", snapshot.registered_slots),
        ("missing_slots", snapshot.missing_slots),
        ("unpublished_event_bound", snapshot.unpublished_event_bound),
        ("lost_events", snapshot.lost_events),
        ("snapshot_sequence", SNAPSHOTS.fetch_add(1, Ordering::Relaxed)),
    ];
    for (name, value) in metadata {
        let _ = writeln!(text, "ferrum_udp_profile_{name} {value}");
    }
    for (name, value) in schema::NAMES.iter().zip(snapshot.values) {
        let _ = writeln!(text, "ferrum_udp_profile_{name} {value}");
    }
    text
}
