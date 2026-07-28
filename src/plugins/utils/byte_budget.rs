//! Shared retained-byte budgets for plugin-owned queues, caches, and snapshots.
//!
//! Count caps alone cannot bound attacker-shaped retained values. Callers
//! reserve a provisional lease before cloning, serializing, or constructing
//! retained data; shrink it to the exact retained size after measurement; and
//! release it on drop (or when ownership moves downstream).

use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use serde_json::Value;
use tracing::warn;

/// Default process-wide retained-byte ceiling shared by every observability
/// sink instance (256 MiB — one instance's `HARD_MAX_BUFFER_MAX_BYTES`).
pub const PROCESS_MAX_RETAINED_BYTES_DEFAULT: usize = 268_435_456;
/// Smallest admitted process ceiling. Below this a single default-configured
/// sink could not retain one maximum record.
pub const PROCESS_MAX_RETAINED_BYTES_MIN: usize = 1_048_576;
/// Largest admitted process ceiling (2 GiB).
pub const PROCESS_MAX_RETAINED_BYTES_MAX: usize = 2_147_483_648;

/// A retained-byte ceiling: a shared `used`/`max` pair with rejection and
/// high-water accounting.
///
/// One `'static` instance ([`process_ceiling`]) is the process-wide ceiling
/// every observability sink reserves against. The type is public so external
/// tests can exercise saturation against their *own* leaked instance without
/// perturbing the process-global counter that concurrently running tests in
/// the same binary depend on.
#[derive(Debug)]
pub struct RetainedByteCeiling {
    used: AtomicUsize,
    max: AtomicUsize,
    rejections: AtomicU64,
    high_water: AtomicUsize,
}

impl RetainedByteCeiling {
    pub const fn new(max_bytes: usize) -> Self {
        Self {
            used: AtomicUsize::new(0),
            max: AtomicUsize::new(max_bytes),
            rejections: AtomicU64::new(0),
            high_water: AtomicUsize::new(0),
        }
    }

    /// Install a new ceiling. Values outside the documented clamp are brought
    /// into range rather than rejected.
    pub fn set_max(&self, max_bytes: usize) {
        self.max.store(
            max_bytes.clamp(
                PROCESS_MAX_RETAINED_BYTES_MIN,
                PROCESS_MAX_RETAINED_BYTES_MAX,
            ),
            Ordering::Release,
        );
    }

    /// Install an exact ceiling with no clamping. Test-only: saturation
    /// coverage needs ceilings far below the production minimum.
    // The binary target never calls this; external unit tests do.
    #[allow(dead_code)]
    pub fn set_max_unclamped_for_test(&self, max_bytes: usize) {
        self.max.store(max_bytes, Ordering::Release);
    }

    pub fn used(&self) -> usize {
        self.used.load(Ordering::Acquire)
    }

    pub fn max(&self) -> usize {
        self.max.load(Ordering::Acquire)
    }

    pub fn rejections(&self) -> u64 {
        self.rejections.load(Ordering::Relaxed)
    }

    pub fn high_water(&self) -> usize {
        self.high_water.load(Ordering::Acquire)
    }

    /// Reserve `bytes` against this ceiling. Returns `None` once the ceiling is
    /// reached; the caller must not retain the payload.
    pub fn try_acquire(&'static self, bytes: usize) -> Option<ProcessByteReservation> {
        if bytes == 0 {
            return Some(ProcessByteReservation {
                ceiling: self,
                bytes: AtomicUsize::new(0),
            });
        }
        let max = self.max.load(Ordering::Acquire);
        match self
            .used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes).filter(|next| *next <= max)
            }) {
            Ok(previous) => {
                self.high_water
                    .fetch_max(previous.saturating_add(bytes), Ordering::AcqRel);
                Some(ProcessByteReservation {
                    ceiling: self,
                    bytes: AtomicUsize::new(bytes),
                })
            }
            Err(_) => {
                self.rejections.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }
}

/// The process-wide retained-byte ceiling shared by every observability sink.
static PROCESS_CEILING: RetainedByteCeiling =
    RetainedByteCeiling::new(PROCESS_MAX_RETAINED_BYTES_DEFAULT);

/// Handle on the process-wide ceiling.
// The binary target reaches the ceiling through the wrappers below; external
// tests use this handle directly.
#[allow(dead_code)]
pub fn process_ceiling() -> &'static RetainedByteCeiling {
    &PROCESS_CEILING
}

/// Install the process-wide retained-byte ceiling.
///
/// Called once from `main` before mode dispatch, alongside
/// [`crate::observability_delivery::initialize`]. Values outside the
/// documented clamp are brought into range rather than rejected, matching the
/// pre-existing task-budget behavior; the admin/plugin configuration surfaces
/// that operators actually author still fail closed on unsafe values.
pub fn initialize_process_retained_byte_ceiling(max_bytes: usize) {
    PROCESS_CEILING.set_max(max_bytes);
}

/// Bytes retained across all observability sinks right now.
pub fn process_retained_bytes() -> usize {
    PROCESS_CEILING.used()
}

/// Configured process-wide retained-byte ceiling.
pub fn process_max_retained_bytes() -> usize {
    PROCESS_CEILING.max()
}

/// Admissions refused because the process ceiling — not the per-instance
/// budget — was exhausted.
pub fn process_ceiling_rejections() -> u64 {
    PROCESS_CEILING.rejections()
}

/// Peak process-wide retention observed since startup.
pub fn process_retained_bytes_high_water() -> usize {
    PROCESS_CEILING.high_water()
}

/// One reservation against a [`RetainedByteCeiling`].
///
/// Every observability sink budget — the shared [`ByteBudget`] and the
/// sink-private budgets in `loki_logging`, `ws_logging`, `kafka_logging`, and
/// `otel_tracing` — reserves against the process ceiling in addition to its own
/// per-instance budget, so N configured instances cannot multiply past the
/// process total. Release is on drop, so cancellation and rejected-handoff
/// paths cannot leak the reservation.
#[derive(Debug)]
pub struct ProcessByteReservation {
    ceiling: &'static RetainedByteCeiling,
    bytes: AtomicUsize,
}

impl ProcessByteReservation {
    /// Reserve `bytes` against the process-wide ceiling.
    pub fn try_acquire(bytes: usize) -> Option<Self> {
        PROCESS_CEILING.try_acquire(bytes)
    }

    /// Shrink a provisional reservation down to the exact retained size.
    pub fn shrink_to(&self, exact: usize) {
        let current = self.bytes.load(Ordering::Acquire);
        if exact >= current {
            return;
        }
        if self
            .bytes
            .compare_exchange(current, exact, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.ceiling
                .used
                .fetch_sub(current - exact, Ordering::AcqRel);
        }
    }

    /// Explicitly release the remaining reservation (idempotent).
    pub fn release(&self) {
        let bytes = self.bytes.swap(0, Ordering::AcqRel);
        if bytes != 0 {
            self.ceiling.used.fetch_sub(bytes, Ordering::AcqRel);
        }
    }

    /// Bytes still held by this reservation.
    // Read by external unit tests only.
    #[allow(dead_code)]
    pub fn reserved(&self) -> usize {
        self.bytes.load(Ordering::Acquire)
    }
}

impl Drop for ProcessByteReservation {
    fn drop(&mut self) {
        self.release();
    }
}

/// Default per-entry retained-byte ceiling for summary log sinks.
pub const DEFAULT_MAX_ENTRY_BYTES: usize = 65_536;
/// Hard maximum for a single admitted observability record.
pub const HARD_MAX_ENTRY_BYTES: usize = 1_048_576;
/// Default aggregate retained-content budget across one sink instance.
pub const DEFAULT_BUFFER_MAX_BYTES: usize = 16_777_216;
/// Hard maximum aggregate retained-content budget for one sink instance.
pub const HARD_MAX_BUFFER_MAX_BYTES: usize = 268_435_456;
/// Minimum admitted `max_entry_bytes` (keeps truncating serializers useful).
pub const MIN_MAX_ENTRY_BYTES: usize = 1_024;
/// Retained copies charged for a queued summary and its contiguous delivery
/// payload. Retries share the queued `Arc<str>` and run sequentially.
pub const SUMMARY_ENTRY_RETAINED_COPIES: usize = 2;
/// Per-record JSON array / NDJSON framing allowance.
pub const SUMMARY_ENTRY_FRAMING_BYTES: usize = 1;

const DROP_WARN_EVERY: u64 = 100;

/// Atomic aggregate byte budget with lease-based release.
///
/// Every reservation is charged twice: once against this per-instance budget
/// and once against the shared `ceiling`. The instance budget bounds one sink;
/// the ceiling bounds the sum across all of them.
#[derive(Debug)]
pub struct ByteBudget {
    used_bytes: Arc<AtomicUsize>,
    max_bytes: usize,
    drops: AtomicU64,
    plugin_name: &'static str,
    ceiling: &'static RetainedByteCeiling,
}

impl ByteBudget {
    pub fn new(plugin_name: &'static str, max_bytes: usize) -> Self {
        Self::with_ceiling(plugin_name, max_bytes, process_ceiling())
    }

    /// Construct a budget bound to an explicit ceiling.
    ///
    /// Production always uses [`process_ceiling`]. External tests pass their
    /// own leaked ceiling so saturation and byte-accounting assertions stay
    /// exact while other tests in the same binary run concurrently.
    // The binary target only calls `new`; external unit tests use this.
    #[allow(dead_code)]
    pub fn with_ceiling(
        plugin_name: &'static str,
        max_bytes: usize,
        ceiling: &'static RetainedByteCeiling,
    ) -> Self {
        Self {
            used_bytes: Arc::new(AtomicUsize::new(0)),
            max_bytes: max_bytes.max(1),
            drops: AtomicU64::new(0),
            plugin_name,
            ceiling,
        }
    }

    pub fn max_bytes(&self) -> usize {
        self.max_bytes
    }

    pub fn used(&self) -> usize {
        self.used_bytes.load(Ordering::Acquire)
    }

    // Read by external unit tests; the binary target compiles this shared
    // module separately and cannot observe those callers.
    #[allow(dead_code)]
    pub fn drops_total(&self) -> u64 {
        self.drops.load(Ordering::Relaxed)
    }

    /// Reserve `bytes` against the aggregate budget. Returns `None` on
    /// saturation; callers must not retain the payload.
    pub fn try_acquire(&self, bytes: usize) -> Option<Arc<ByteLease>> {
        if bytes == 0 {
            return Some(Arc::new(ByteLease {
                used_bytes: Arc::clone(&self.used_bytes),
                bytes: AtomicUsize::new(0),
                process: self.ceiling.try_acquire(0)?,
            }));
        }
        // The shared ceiling is taken first so a per-instance reservation is
        // never left held while the aggregate reservation fails.
        let Some(process) = self.ceiling.try_acquire(bytes) else {
            self.record_drop("process-wide retained-byte ceiling exhausted");
            return None;
        };
        let reserved = self
            .used_bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes)
                    .filter(|next| *next <= self.max_bytes)
            });
        if reserved.is_err() {
            drop(process);
            self.record_drop("retained-byte budget exhausted");
            return None;
        }
        Some(Arc::new(ByteLease {
            used_bytes: Arc::clone(&self.used_bytes),
            bytes: AtomicUsize::new(bytes),
            process,
        }))
    }

    pub fn record_drop(&self, reason: &'static str) {
        let dropped = self.drops.fetch_add(1, Ordering::Relaxed) + 1;
        if dropped == 1 || dropped.is_multiple_of(DROP_WARN_EVERY) {
            warn!(
                plugin = self.plugin_name,
                "{}: dropping retained admission because {} ({} dropped total; logging every {} drops)",
                self.plugin_name,
                reason,
                dropped,
                DROP_WARN_EVERY,
            );
        }
    }
}

/// One retained-byte lease. Cloning the `Arc` shares ownership; the budget is
/// released only when the last handle drops (or [`ByteLease::release`] runs).
#[derive(Debug)]
pub struct ByteLease {
    used_bytes: Arc<AtomicUsize>,
    bytes: AtomicUsize,
    /// Matching reservation against the process-wide ceiling. Shrunk and
    /// released in lockstep with the per-instance reservation.
    process: ProcessByteReservation,
}

impl ByteLease {
    /// Shrink a provisional reservation down to the exact retained size.
    pub fn shrink_to(&self, exact: usize) {
        let current = self.bytes.load(Ordering::Acquire);
        if exact >= current {
            return;
        }
        let release = current - exact;
        match self
            .bytes
            .compare_exchange(current, exact, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => {
                self.used_bytes.fetch_sub(release, Ordering::AcqRel);
                self.process.shrink_to(exact);
            }
            Err(_) => {
                // Concurrent shrink/release already moved the lease; ignore.
            }
        }
    }

    /// Explicitly release remaining bytes (idempotent).
    pub fn release(&self) {
        let bytes = self.bytes.swap(0, Ordering::AcqRel);
        if bytes != 0 {
            self.used_bytes.fetch_sub(bytes, Ordering::AcqRel);
        }
        self.process.release();
    }
}

impl Drop for ByteLease {
    fn drop(&mut self) {
        self.release();
    }
}

/// JSON writer that fails closed once `max_bytes` would be exceeded.
#[derive(Debug)]
pub struct BoundedJsonWriter {
    pub bytes: Vec<u8>,
    max_bytes: usize,
    pub limit_exceeded: bool,
}

impl BoundedJsonWriter {
    pub fn new(max_bytes: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(max_bytes.min(4096)),
            max_bytes,
            limit_exceeded: false,
        }
    }
}

impl Write for BoundedJsonWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.len() > self.max_bytes.saturating_sub(self.bytes.len()) {
            self.limit_exceeded = true;
            return Err(std::io::Error::other(
                "serialized observability entry exceeded its byte limit",
            ));
        }
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Admitted `max_entry_bytes` / `buffer_max_bytes` pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmittedByteLimits {
    pub max_entry_bytes: usize,
    pub buffer_max_bytes: usize,
}

/// Conservative bytes charged for one serialized summary while it is queued
/// and copied into a contiguous HTTP/TCP/UDP delivery payload.
pub const fn accounted_summary_bytes(serialized_bytes: usize) -> usize {
    serialized_bytes
        .saturating_add(SUMMARY_ENTRY_FRAMING_BYTES)
        .saturating_mul(SUMMARY_ENTRY_RETAINED_COPIES)
}

/// Parse shared per-entry and aggregate byte budgets from plugin config.
pub fn admit_byte_limits(
    config: &Value,
    plugin_name: &'static str,
) -> Result<AdmittedByteLimits, String> {
    let max_entry_bytes = match config.get("max_entry_bytes") {
        None => DEFAULT_MAX_ENTRY_BYTES as u64,
        Some(value) => {
            let Some(parsed) = value.as_u64() else {
                return Err(format!(
                    "{plugin_name}: 'max_entry_bytes' must be an unsigned integer"
                ));
            };
            parsed
        }
    };
    if max_entry_bytes < MIN_MAX_ENTRY_BYTES as u64 {
        return Err(format!(
            "{plugin_name}: 'max_entry_bytes' must be >= {MIN_MAX_ENTRY_BYTES}"
        ));
    }
    if max_entry_bytes > HARD_MAX_ENTRY_BYTES as u64 {
        return Err(format!(
            "{plugin_name}: 'max_entry_bytes' must be <= {HARD_MAX_ENTRY_BYTES}"
        ));
    }

    let buffer_max_bytes = match config.get("buffer_max_bytes") {
        None => DEFAULT_BUFFER_MAX_BYTES as u64,
        Some(value) => {
            let Some(parsed) = value.as_u64() else {
                return Err(format!(
                    "{plugin_name}: 'buffer_max_bytes' must be an unsigned integer"
                ));
            };
            parsed
        }
    };
    let minimum_buffer_bytes = accounted_summary_bytes(max_entry_bytes as usize) as u64;
    if buffer_max_bytes < minimum_buffer_bytes {
        return Err(format!(
            "{plugin_name}: 'buffer_max_bytes' must be greater than or equal to \
             {SUMMARY_ENTRY_RETAINED_COPIES} * ('max_entry_bytes' + \
             {SUMMARY_ENTRY_FRAMING_BYTES})"
        ));
    }
    if buffer_max_bytes > HARD_MAX_BUFFER_MAX_BYTES as u64 {
        return Err(format!(
            "{plugin_name}: 'buffer_max_bytes' must be <= {HARD_MAX_BUFFER_MAX_BYTES}"
        ));
    }

    Ok(AdmittedByteLimits {
        max_entry_bytes: max_entry_bytes as usize,
        buffer_max_bytes: buffer_max_bytes as usize,
    })
}
