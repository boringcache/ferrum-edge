//! Fail-closed bounds for response bodies the gateway retains in memory.
//!
//! Response-body buffering is entered whenever an active plugin needs the
//! complete representation (`response_transformer` body rules,
//! `response_caching`, `waf` body inspection, …) or the operator forced
//! [`crate::config::types::ResponseBodyMode::Buffer`]. Two properties have to
//! hold for that to be safe against a remote client that can pick the backend
//! response (GHSA-pwcm-6rh8-f2gh):
//!
//! * **Per response.** The legacy `FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES`
//!   documents `0` as "unlimited". That is a defensible *streaming* policy —
//!   nothing is retained — but on a buffered path it means one response can
//!   grow a `Vec` until the process dies. [`buffered_response_body_ceiling`]
//!   folds a finite fail-closed fallback in for exactly that case, and only for
//!   buffered collection: streaming enforcement keeps `0 = unlimited`.
//! * **Across concurrent responses.** A finite per-response ceiling still
//!   multiplies by concurrency. [`ResponseBufferReservation`] charges retained
//!   bytes against one process-wide budget, so total retained buffered-response
//!   bytes stay bounded no matter how many clients arrive at once.
//!
//! The budget is a `tokio::sync::Semaphore` denominated in
//! [`RESERVATION_UNIT_BYTES`] blocks. A collector reserves as it grows, so a
//! small response costs a single block and never pre-charges the ceiling.
//! Acquisition is non-blocking (`try_acquire_many_owned`): a collector that
//! cannot reserve fails the response with
//! [`RESPONSE_BUFFER_OVERLOAD_STATUS`] rather than queueing behind other
//! buffers and burning the client's deadline. Permits are held by the
//! reservation value and returned on `Drop`, which covers success, size
//! rejection, backend error, deadline expiry, and task cancellation alike.
//!
//! No lock is taken on the streaming hot path — a released response never
//! constructs a reservation — and the state is one process-global semaphore, so
//! there is no per-route or per-client cardinality.

use std::sync::Arc;
use std::sync::OnceLock;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Granularity of one budget block. Retained bytes are charged in whole blocks,
/// so a typical small JSON response costs exactly one.
pub(crate) const RESERVATION_UNIT_BYTES: usize = 64 * 1024;

/// Per-response ceiling applied when the effective response-body limit is `0`
/// and the body is being retained rather than streamed.
pub(crate) const DEFAULT_BUFFERED_RESPONSE_FALLBACK_BYTES: usize = 10 * 1024 * 1024;

/// Aggregate ceiling on bytes retained by concurrent buffered responses.
pub(crate) const DEFAULT_RESPONSE_BUFFER_TOTAL_BYTES: usize = 256 * 1024 * 1024;

/// Status returned when the aggregate budget cannot admit another buffered
/// response. `503` (not `502`) because the backend behaved correctly and the
/// condition is transient gateway capacity.
pub(crate) const RESPONSE_BUFFER_OVERLOAD_STATUS: u16 = 503;

/// Client-visible body for an aggregate-budget refusal. Fixed bytes: it names
/// no route, header, credential, or response content.
pub(crate) const RESPONSE_BUFFER_OVERLOAD_BODY: &str =
    r#"{"error":"Response buffering capacity exceeded"}"#;

struct Budget {
    fallback_per_response_bytes: usize,
    permits: Arc<Semaphore>,
}

static BUDGET: OnceLock<Budget> = OnceLock::new();

fn budget() -> &'static Budget {
    BUDGET.get_or_init(|| {
        Budget::new(
            DEFAULT_BUFFERED_RESPONSE_FALLBACK_BYTES,
            DEFAULT_RESPONSE_BUFFER_TOTAL_BYTES,
        )
    })
}

impl Budget {
    fn new(fallback_per_response_bytes: usize, total_bytes: usize) -> Self {
        // A zero/short total would refuse every buffered response and take the
        // proxy down, so the aggregate budget is clamped to at least one
        // per-response ceiling: the strictest useful value still admits one
        // response at a time instead of none.
        let fallback_per_response_bytes =
            fallback_per_response_bytes.clamp(RESERVATION_UNIT_BYTES, usize::MAX / 2);
        let total_bytes = total_bytes.max(fallback_per_response_bytes);
        let blocks = total_bytes.div_ceil(RESERVATION_UNIT_BYTES);
        Self {
            fallback_per_response_bytes,
            permits: Arc::new(Semaphore::new(blocks.min(Semaphore::MAX_PERMITS))),
        }
    }
}

/// Publish the operator-configured bounds. Called once during startup, before
/// any listener accepts traffic. Later calls are ignored: the semaphore backs
/// live reservations, so resizing it under them is not expressible — changing
/// these values requires a restart, like the other process-global limits.
pub(crate) fn init(fallback_per_response_bytes: usize, total_bytes: usize) {
    let _ = BUDGET.set(Budget::new(fallback_per_response_bytes, total_bytes));
}

/// The effective ceiling for a response the gateway is about to *retain*.
///
/// `effective_limit` is the already-folded strictest active limit (global +
/// route). A configured value is honored verbatim. `0` — documented as
/// "unlimited" for streaming — becomes the finite fallback here, because an
/// unlimited retained buffer is not a policy the gateway can honor safely.
pub(crate) fn buffered_response_body_ceiling(effective_limit: usize) -> usize {
    if effective_limit > 0 {
        effective_limit
    } else {
        budget().fallback_per_response_bytes
    }
}

/// A growing claim on the process-wide buffered-response budget.
///
/// Construct one before collecting a response body, then call
/// [`Self::reserve`] with the running retained length. Dropping it returns
/// every block, so there is no path — success, rejection, error, cancellation —
/// that leaks budget.
#[derive(Default)]
pub(crate) struct ResponseBufferReservation {
    /// Merged permits for `blocks` reserved blocks. `None` while nothing is
    /// reserved yet.
    permit: Option<OwnedSemaphorePermit>,
    blocks: u32,
}

impl ResponseBufferReservation {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Charge `retained_bytes` against the budget, acquiring more blocks when
    /// the collector has grown past what is already reserved.
    ///
    /// Returns `false` when the aggregate budget cannot cover the growth; the
    /// caller must then abandon collection and surface
    /// [`RESPONSE_BUFFER_OVERLOAD_STATUS`]. Already-held blocks stay held until
    /// this value drops.
    pub(crate) fn reserve(&mut self, retained_bytes: usize) -> bool {
        let wanted = u32::try_from(retained_bytes.div_ceil(RESERVATION_UNIT_BYTES).max(1))
            .unwrap_or(u32::MAX);
        if wanted <= self.blocks {
            return true;
        }
        let additional = wanted - self.blocks;
        match Arc::clone(&budget().permits).try_acquire_many_owned(additional) {
            Ok(acquired) => {
                match self.permit.as_mut() {
                    Some(held) => held.merge(acquired),
                    None => self.permit = Some(acquired),
                }
                self.blocks = wanted;
                true
            }
            Err(_) => false,
        }
    }
}

/// Blocks a degenerate configuration would leave available, for external tests.
/// Exercises the same clamp production uses without touching the process-global
/// budget.
#[allow(dead_code)]
pub(crate) fn available_blocks_for_config(
    fallback_per_response_bytes: usize,
    total_bytes: usize,
) -> usize {
    Budget::new(fallback_per_response_bytes, total_bytes)
        .permits
        .available_permits()
}
