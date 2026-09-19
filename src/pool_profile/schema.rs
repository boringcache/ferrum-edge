//! Fixed dimensions, independent of the H1 allocator schema.
pub const SAMPLE_EVERY: u64 = 64;
pub const FAMILIES: [&str; 2] = ["h2", "grpc"];
pub const PURPOSES: [&str; 2] = ["request", "capability"];
pub const EVENTS: [&str; 25] = [
    "acquisitions",
    "sampled",
    "completed",
    "errors",
    "cancelled",
    "wall_ns",
    "poll_ready",
    "poll_pending",
    "warm_hit",
    "fallback",
    "probe",
    "cache_miss",
    "unhealthy",
    "sender_clone",
    "ready",
    "pending",
    "readiness_error",
    "recovery",
    "recovered",
    "create_owner",
    "coalesced_wait",
    "create_success",
    "create_error",
    "miss_fallback",
    "busy_fallback",
];
pub const PHASES: [&str; 9] = [
    "poll",
    "phase1",
    "rr",
    "probe",
    "readiness",
    "creation_poll",
    "wait_poll",
    "empty_bracket",
    "fallback_poll",
];
pub const FIELDS: [&str; 13] = [
    "calls",
    "ns",
    "observer_ns",
    "alloc",
    "alloc_zeroed",
    "realloc",
    "dealloc",
    "requested_bytes",
    "successful_bytes",
    "failed",
    "realloc_old_bytes",
    "realloc_new_bytes",
    "dealloc_bytes",
];
// Disjoint probe-count buckets per sampled acquisition: 0, 1, 2-4, 5-16, >16.
pub const PROBES: [&str; 5] = [
    "probes_0",
    "probes_1",
    "probes_2_4",
    "probes_5_16",
    "probes_gt16",
];
pub const STRIDE: usize = EVENTS.len() + PHASES.len() * FIELDS.len() + PROBES.len();
pub const OVERFLOW: usize = 4 * STRIDE;
pub const COUNTERS: usize = OVERFLOW + 1;

#[derive(Clone, Copy)]
pub enum Family {
    H2,
    Grpc,
}

#[derive(Clone, Copy)]
pub enum Purpose {
    Request,
    Capability,
}

#[derive(Clone, Copy)]
pub enum Phase {
    Poll,
    Phase1,
    Rr,
    Probe,
    Readiness,
    CreationPoll,
    WaitPoll,
    EmptyBracket,
    FallbackPoll,
}

#[derive(Clone, Copy)]
pub enum Event {
    Acquisitions,
    Sampled,
    Completed,
    Errors,
    Cancelled,
    WallNs,
    PollReady,
    PollPending,
    WarmHit,
    Fallback,
    Probe,
    CacheMiss,
    Unhealthy,
    SenderClone,
    Ready,
    Pending,
    ReadinessError,
    Recovery,
    Recovered,
    CreateOwner,
    CoalescedWait,
    CreateSuccess,
    CreateError,
    MissFallback,
    BusyFallback,
}
