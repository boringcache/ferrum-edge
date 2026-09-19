//! Temporary #5588 hosted observer. No payloads, peer names, or Debug errors.
//! Compiled only by the separately prepared dependency, never the shipping graph.
use std::sync::atomic::{AtomicU64, Ordering};

pub(super) const TARGET: &str = "ferrum_h2_guard";

#[derive(Debug)]
pub(super) struct Limit {
    used: AtomicU64,
    pub(super) suppressed: AtomicU64,
    cap: u64,
}

impl Limit {
    pub(super) const fn new(cap: u64) -> Self {
        Self {
            used: AtomicU64::new(0),
            suppressed: AtomicU64::new(0),
            cap,
        }
    }

    pub(super) fn take(&self) -> Result<u64, u64> {
        match self.used.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
            (n < self.cap).then_some(n + 1)
        }) {
            Ok(n) => Ok(n + 1),
            Err(_) => {
                let old = self.suppressed.fetch_update(
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                    |n| Some(n.saturating_add(1)),
                );
                // The closure always returns Some: both arms avoid a panic.
                Err(old.unwrap_or_else(|n| n).saturating_add(1))
            }
        }
    }
}

static CONNECTIONS: Limit = Limit::new(4096);
static LIFECYCLE: Limit = Limit::new(4096);
static FAILURES: Limit = Limit::new(256);
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub(super) fn admit(limit: &Limit, scope: u8) -> Option<u64> {
    match limit.take() {
        Ok(id) => Some(id),
        Err(n) => {
            // At most 64 notices per scope, saturation cannot repeat a notice
            // because u64::MAX is not a power of two. These are lower bounds after the last notice.
            if n.is_power_of_two() {
                let seq = SEQUENCE.fetch_add(1, Ordering::Relaxed) + 1;
                tracing::debug!(target: TARGET, parent: None,
                    "H2_GUARD_LIMIT_V1 seq={} scope={} suppressed={}", seq, scope, n);
            }
            None
        }
    }
}

#[derive(Debug)]
pub(super) struct Observation {
    cid: u64,
    role: u8,
    initial_max: usize,
    pub(super) initial_target: u32,
    pub(super) target: u32,
    peak_target: u32,
    pub(super) target_updates: u64,
    pub(super) initial_stream: u32,
    pub(super) stream_window: u32,
    stream_updates: u64,
    pub(super) wire_window: u32,
    pub(super) byte_available: isize,
    pub(super) in_flight: u32,
    // zero, small(1..255), medium(256..16383), large(>=16384), final,
    // queued, ignored local reset, ignored released, empty unqueued,
    // receive rejected, untracked stream, polled, cleared, released credit.
    pub(super) counters: [u64; 14],
    frames: u64,
    bytes: u64,
    pub(super) last_stream: u32,
    pub(super) trigger_stream: u32,
    last_len: usize,
    last_flow: usize,
    last_end: bool,
    pub(super) disposition: u8,
    pub(super) branch: u8,
    reason: u32,
}

impl Observation {
    pub(super) fn new(server: bool, budget: usize) -> Option<Self> {
        if !tracing::enabled!(target: TARGET, tracing::Level::DEBUG) {
            return None;
        }
        Some(Self {
            cid: admit(&CONNECTIONS, 1)?,
            role: u8::from(!server),
            initial_max: budget,
            initial_target: 65535,
            target: 65535,
            peak_target: 65535,
            target_updates: 0,
            initial_stream: 65535,
            stream_window: 65535,
            stream_updates: 0,
            wire_window: 65535,
            byte_available: 65535,
            in_flight: 0,
            counters: [0; 14],
            frames: 0,
            bytes: 0,
            last_stream: 0,
            trigger_stream: 0,
            last_len: 0,
            last_flow: 0,
            last_end: false,
            disposition: 0,
            branch: 0,
            reason: 0,
        })
    }

    pub(super) fn frame(&mut self, id: u32, len: usize, flow: usize, end: bool) {
        self.frames = self.frames.saturating_add(1);
        self.bytes = self.bytes.saturating_add(len as u64);
        self.last_stream = id;
        self.last_len = len;
        self.last_flow = flow;
        self.last_end = end;
        self.disposition = 0;
        self.inc(match len {
            0 => 0,
            1..=255 => 1,
            256..=16383 => 2,
            _ => 3,
        }, 1);
        if end {
            self.inc(4, 1);
        }
    }

    pub(super) fn inc(&mut self, index: usize, value: u64) {
        self.counters[index] = self.counters[index].saturating_add(value);
    }

    pub(super) fn disposition(&mut self, code: u8) {
        // 1 queued, 2 local reset, 3 released, 4 empty nonfinal,
        // 5 recv rejected, 6 no tracked stream (guard bypass).
        self.disposition = code;
        self.inc(usize::from(code) + 4, 1);
    }

    pub(super) fn target(&mut self, size: u32) {
        if self.target_updates == 0 {
            self.initial_target = size;
        }
        self.target_updates = self.target_updates.saturating_add(1);
        self.target = size;
        self.peak_target = self.peak_target.max(size);
    }

    pub(super) fn stream_window(&mut self, size: u32) {
        if self.stream_updates == 0 {
            self.initial_stream = size;
        }
        self.stream_updates = self.stream_updates.saturating_add(1);
        self.stream_window = size;
    }

    pub(super) fn emit(&mut self, event: u8, branch: u8, reason: u32, state: [usize; 7]) {
        if event == 1 {
            self.branch = branch;
            self.reason = reason;
        }
        let (limit, scope) = if event == 1 { (&FAILURES, 3) } else { (&LIFECYCLE, 2) };
        if admit(limit, scope).is_none() {
            return;
        }
        let seq = SEQUENCE.fetch_add(1, Ordering::Relaxed) + 1;
        let c = &self.counters;
        // Fixed numeric schema, no inherited tracing span fields. Counters
        // saturate; quotas are process-wide and failure capacity is reserved.
        tracing::debug!(target: TARGET, parent: None,
            "H2_GUARD_V1 seq={} cid={} role={} event={} branch={} reason={} initial_max={} initial_available={} max={} available={} empty={} send={} recv={} error_resets={} remote_resets={} initial_target={} target={} peak_target={} target_updates={} initial_stream={} stream_window={} stream_updates={} wire_window={} byte_available={} in_flight={} frames={} bytes={} zero={} small={} medium={} large={} final={} queued={} ignored_reset={} ignored_release={} empty_unqueued={} rejected={} untracked={} polled={} cleared={} returned_credit={} last_stream={} trigger_stream={} last_len={} last_flow={} last_end={} disposition={} suppressed_connections={} suppressed_lifecycle={} suppressed_failures={}",
            seq, self.cid, self.role, event, self.branch, self.reason,
            self.initial_max, self.initial_max, state[0], state[1], state[2],
            state[3], state[4], state[5], state[6], self.initial_target,
            self.target, self.peak_target, self.target_updates, self.initial_stream,
            self.stream_window, self.stream_updates, self.wire_window,
            self.byte_available, self.in_flight, self.frames, self.bytes,
            c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7], c[8], c[9],
            c[10], c[11], c[12], c[13], self.last_stream, self.trigger_stream, self.last_len,
            self.last_flow, u8::from(self.last_end), self.disposition,
            CONNECTIONS.suppressed.load(Ordering::Relaxed),
            LIFECYCLE.suppressed.load(Ordering::Relaxed),
            FAILURES.suppressed.load(Ordering::Relaxed));
    }
}
