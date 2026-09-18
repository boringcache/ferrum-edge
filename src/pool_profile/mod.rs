//! Sampled pool acquisition diagnostics. No TLS attribution survives a poll.
//! Inclusive synchronous phase snapshots overlap; never sum them as CPU time.
pub mod schema;
mod store;

use std::cell::Cell;
use std::fmt::Write;
use std::future::{Future, poll_fn};
use std::marker::PhantomData;
use std::pin::pin;
use std::rc::Rc;
use std::time::Instant;

pub use schema::{Event, Family, Phase, Purpose};
pub use store::{current_thread_counters, publish_current_thread, snapshot};

thread_local! {
    static ACTIVE: Cell<Option<usize>> = const { Cell::new(None) };
    static PROBES: Cell<u64> = const { Cell::new(0) };
}

fn active() -> Option<usize> {
    ACTIVE.try_with(Cell::get).ok().flatten()
}

fn add(group: usize, field: usize, amount: u64) {
    store::with_local(|local| local.add(group * schema::STRIDE + field, amount));
}

pub fn event(event: Event) {
    if let Some(group) = active() {
        add(group, event as usize, 1);
        if matches!(event, Event::Probe) {
            let _ = PROBES.try_with(|value| value.set(value.get().saturating_add(1)));
        }
    }
}

// Non-Send and private. Exists only inside a synchronous poll/closure.
struct PollScope {
    previous: Option<usize>,
    probes: u64,
    _thread_bound: PhantomData<Rc<()>>,
}

impl PollScope {
    fn enter(group: Option<usize>) -> Self {
        Self {
            previous: ACTIVE.with(|value| value.replace(group)),
            probes: PROBES.with(|value| value.replace(0)),
            _thread_bound: PhantomData,
        }
    }
}

impl Drop for PollScope {
    fn drop(&mut self) {
        ACTIVE.with(|value| value.set(self.previous));
        PROBES.with(|value| value.set(self.probes));
    }
}

fn nanos(duration: std::time::Duration) -> u64 {
    match u64::try_from(duration.as_nanos()) {
        Ok(value) => value,
        Err(_) => {
            store::with_local(|local| local.add(schema::OVERFLOW, 1));
            u64::MAX
        }
    }
}

/// Snapshot existing H1 process allocator counters on THIS thread. No new
/// allocator callback, global allocator, scope index or H1 meaning is added.
fn allocator_snapshot() -> [u64; 10] {
    let counters = crate::h1_profile::current_thread_counters();
    if counters[crate::h1_profile::schema::OVERFLOW] != 0 {
        store::with_local(|local| local.add(schema::OVERFLOW, 1));
    }
    std::array::from_fn(|i| counters[i])
}

pub fn measure<R>(phase: Phase, operation: impl FnOnce() -> R) -> R {
    let Some(group) = active() else {
        return operation();
    };
    let observer_start = Instant::now();
    let before = allocator_snapshot();
    let start = Instant::now();
    let result = operation();
    let elapsed = nanos(start.elapsed());
    let after = allocator_snapshot();
    let observer = nanos(observer_start.elapsed()).saturating_sub(elapsed);
    let base = schema::EVENTS.len() + phase as usize * schema::FIELDS.len();
    store::with_local(|local| {
        let base = group * schema::STRIDE + base;
        local.add(base, 1);
        local.add(base + 1, elapsed);
        local.add(base + 2, observer);
        for (i, (after, before)) in after.into_iter().zip(before).enumerate() {
            if let Some(delta) = after.checked_sub(before) {
                local.add(base + 3 + i, delta);
            } else {
                local.add(schema::OVERFLOW, 1);
            }
        }
    });
    result
}

pub fn readiness<T, E>(operation: impl FnOnce() -> Option<Result<T, E>>) -> Option<Result<T, E>> {
    let result = measure(Phase::Readiness, operation);
    event(match &result {
        Some(Ok(_)) => Event::Ready,
        Some(Err(_)) => Event::ReadinessError,
        None => Event::Pending,
    });
    result
}

/// Wrap an existing future without adding a readiness poll, wait or wakeup.
pub async fn phase_future<F: Future>(phase: Phase, future: F) -> F::Output {
    let mut future = pin!(future);
    poll_fn(|cx| measure(phase, || future.as_mut().poll(cx))).await
}

struct Acquisition {
    group: usize,
    start: Option<Instant>,
    complete: bool,
    probes: u64,
}

impl Drop for Acquisition {
    fn drop(&mut self) {
        if let Some(start) = self.start {
            add(self.group, Event::WallNs as usize, nanos(start.elapsed()));
            if !self.complete {
                add(self.group, Event::Cancelled as usize, 1);
            }
            let bucket = match self.probes {
                0 => 0,
                1 => 1,
                2..=4 => 2,
                5..=16 => 3,
                _ => 4,
            };
            let base = schema::EVENTS.len() + schema::PHASES.len() * schema::FIELDS.len();
            add(self.group, base + bucket, 1);
        }
    }
}

pub async fn acquisition<T, E>(
    family: Family,
    purpose: Purpose,
    future: impl Future<Output = Result<T, E>>,
) -> Result<T, E> {
    let group = family as usize * 2 + purpose as usize;
    let mut sampled = false;
    store::with_local(|local| {
        let sequence = local.selections[group];
        sampled = sequence.is_multiple_of(schema::SAMPLE_EVERY);
        local.selections[group] = sequence.wrapping_add(1);
        local.add(group * schema::STRIDE + Event::Acquisitions as usize, 1);
    });
    let mut acquisition = Acquisition {
        group,
        start: sampled.then(Instant::now),
        complete: false,
        probes: 0,
    };
    if sampled {
        add(group, Event::Sampled as usize, 1);
    }
    let mut future = pin!(future);
    let result = poll_fn(|cx| {
        let _scope = PollScope::enter(sampled.then_some(group));
        if sampled {
            measure(Phase::EmptyBracket, || ());
        }
        let result = measure(Phase::Poll, || future.as_mut().poll(cx));
        event(if result.is_ready() {
            Event::PollReady
        } else {
            Event::PollPending
        });
        acquisition.probes = acquisition.probes.saturating_add(PROBES.with(Cell::get));
        result
    })
    .await;
    acquisition.complete = true;
    if sampled {
        add(group, Event::Completed as usize, 1);
        if result.is_err() {
            add(group, Event::Errors as usize, 1);
        }
    }
    result
}

/// Fixed integer-only fields appended to the existing authenticated /metrics.
pub fn render_prometheus() -> String {
    let snapshot = snapshot();
    let allocator = crate::h1_profile::snapshot();
    let mut text = String::new();
    for (name, value) in [
        ("schema", 1),
        ("sample_every", schema::SAMPLE_EVERY),
        ("pid", u64::from(std::process::id())),
        ("allocator_installed", u64::from(!cfg!(windows))),
        ("registered_slots", snapshot.registered_slots),
        ("slot_capacity", store::THREAD_SLOTS as u64),
        ("missing_slots", snapshot.missing_slots),
        ("unpublished_events", snapshot.unpublished_events),
        ("lost_events", snapshot.lost_events),
        ("counter_overflow", snapshot.values[schema::OVERFLOW]),
        ("allocator_lost_events", allocator.lost_events),
        (
            "allocator_overflow",
            allocator.values[crate::h1_profile::schema::OVERFLOW],
        ),
    ] {
        let _ = writeln!(text, "ferrum_pool_profile_{name} {value}");
    }
    for (family, family_name) in schema::FAMILIES.iter().enumerate() {
        for (purpose, purpose_name) in schema::PURPOSES.iter().enumerate() {
            let mut index = (family * 2 + purpose) * schema::STRIDE;
            let prefix = format!("ferrum_pool_profile_{family_name}_{purpose_name}");
            for event in schema::EVENTS {
                let _ = writeln!(text, "{prefix}_{event} {}", snapshot.values[index]);
                index += 1;
            }
            for phase in schema::PHASES {
                for field in schema::FIELDS {
                    let _ = writeln!(text, "{prefix}_{phase}_{field} {}", snapshot.values[index]);
                    index += 1;
                }
            }
            for bucket in schema::PROBES {
                let _ = writeln!(text, "{prefix}_{bucket} {}", snapshot.values[index]);
                index += 1;
            }
        }
    }
    text
}
