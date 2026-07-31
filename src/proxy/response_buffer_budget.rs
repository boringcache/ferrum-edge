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
//! # Charge lifetime
//!
//! The budget is only a bound if a permit outlives the allocation it paid for.
//! A collector-local reservation does not: collection finishes, the local
//! drops, and the bytes stay resident in `BackendResponse` / `GrpcResponse` /
//! `H3BufferedResponse`, in retry state, through the response-plugin phases,
//! inside a `response_caching` entry, and all the way down to the wire. Many
//! responses could therefore each pass admission, release, and remain resident
//! at once — which is exactly the bypass this module exists to prevent.
//!
//! So the charge is not a collector local. [`charged_bytes`] moves the retained
//! `Vec<u8>` *and* its permit into one owner and hands back a
//! [`bytes::Bytes`] view of it ([`bytes::Bytes::from_owner`], `O(1)`, no copy).
//! From then on:
//!
//! * every cheap clone (cache store, dedup replay, concurrent delivery) shares
//!   the one owner, so the allocation is charged **exactly once** no matter how
//!   many handles exist — a clone never mints a second permit;
//! * the permit is returned when the **last** handle drops, which covers
//!   success, retry abandonment, plugin replacement, response conversion,
//!   deadline expiry, client disconnect, and task cancellation identically,
//!   because they are all just drops;
//! * nothing has to remember to release, so no path can leak the budget and no
//!   path can release early while the bytes are still resident.
//!
//! A plugin phase that *replaces* the body installs a different allocation,
//! which the collector's charge does not cover. Those go through
//! [`charge_replacement_body`], which fails closed when the added retained
//! bytes cannot be reserved. Dropping the old `Bytes` returns its permit, so a
//! replacement is a move of the charge rather than a second one.
//!
//! # Preallocation
//!
//! Capacity reserved before the first DATA frame is resident memory just like
//! bytes already written, so the native-H3 and gRPC collectors charge their
//! `Vec::with_capacity` hint **before** allocating it (headers-only, empty, or
//! stalled responses therefore cannot accumulate uncharged capacity under
//! concurrency). Growth afterwards is charged as a delta against the same
//! reservation, so a preallocated response is never charged twice.
//!
//! # Admission
//!
//! Acquisition is non-blocking (`try_acquire_many_owned`): a collector that
//! cannot reserve fails the response immediately rather than queueing behind
//! other buffers and burning the client's deadline. The refusal is
//! *gateway-local transient capacity*, not a backend fault, so every transport
//! surfaces it through the constants below —
//! [`RESPONSE_BUFFER_OVERLOAD_STATUS`] / [`RESPONSE_BUFFER_OVERLOAD_GRPC_STATUS`]
//! with the health-neutral [`RESPONSE_BUFFER_OVERLOAD_ERROR_CLASS`] — and never
//! as a backend `502` / `ResponseBodyTooLarge` that would poison circuit
//! breaker, passive health, and adaptive-concurrency accounting.
//!
//! No lock is taken on the streaming hot path — a released response never
//! constructs a reservation — and the state is one process-global semaphore, so
//! there is no per-route or per-client cardinality.

use std::sync::Arc;
use std::sync::OnceLock;

use bytes::Bytes;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::retry::ErrorClass;

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

/// gRPC status for the same refusal. `RESOURCE_EXHAUSTED` is the resource/
/// capacity status; `UNAVAILABLE` would suggest the backend is down and
/// `INTERNAL` would suggest a gateway defect.
pub(crate) const RESPONSE_BUFFER_OVERLOAD_GRPC_STATUS: u32 =
    crate::proxy::grpc_proxy::grpc_status::RESOURCE_EXHAUSTED;

/// Client-visible body for an aggregate-budget refusal. Fixed bytes: it names
/// no route, header, credential, or response content.
pub(crate) const RESPONSE_BUFFER_OVERLOAD_BODY: &str =
    r#"{"error":"Response buffering capacity exceeded"}"#;

/// Fixed `grpc-message` for the same refusal. Redaction-safe for the same
/// reason: fixed cardinality, no request or response content.
pub(crate) const RESPONSE_BUFFER_OVERLOAD_GRPC_MESSAGE: &str =
    "Response buffering capacity exceeded";

/// Telemetry/retry class for the refusal. Gateway-local by construction, so it
/// is a `client_side_no_backend_signal` class: neutral to the circuit breaker,
/// passive health, and adaptive concurrency, and never retried (another
/// upstream would hit the same process-global budget).
pub(crate) const RESPONSE_BUFFER_OVERLOAD_ERROR_CLASS: ErrorClass =
    ErrorClass::GatewayBufferCapacity;

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
        // proxy down, so the aggregate budget is floored at the FALLBACK
        // per-response ceiling — and at nothing else.
        //
        // Stated exactly, because the difference is load-bearing: the floor
        // guarantees the gateway can always admit one *fallback-ceiling-sized*
        // response. It does NOT guarantee that an arbitrarily large configured
        // or route-effective per-response ceiling is admissible. If an operator
        // configures a 4 GiB per-response ceiling under a 256 MiB aggregate
        // budget, responses above the aggregate budget are refused with
        // [`RESPONSE_BUFFER_OVERLOAD_STATUS`] — the aggregate cap is not
        // silently widened to fit one huge response, because that would hand
        // the memory bound back to whoever picks the response.
        let fallback_per_response_bytes =
            fallback_per_response_bytes.clamp(RESERVATION_UNIT_BYTES, usize::MAX / 2);
        let total_bytes = total_bytes.max(fallback_per_response_bytes);
        let blocks = total_bytes.div_ceil(RESERVATION_UNIT_BYTES);
        Self {
            fallback_per_response_bytes,
            permits: Arc::new(Semaphore::new(blocks.min(Semaphore::MAX_PERMITS))),
        }
    }

    fn ceiling(&self, effective_limit: usize) -> usize {
        if effective_limit > 0 {
            effective_limit
        } else {
            self.fallback_per_response_bytes
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
///
/// Note that a configured ceiling larger than the aggregate budget is honored
/// as a *ceiling* but is not thereby admissible: the aggregate reservation
/// below still refuses what will not fit. See [`Budget::new`].
pub(crate) fn buffered_response_body_ceiling(effective_limit: usize) -> usize {
    budget().ceiling(effective_limit)
}

/// A growing claim on the process-wide buffered-response budget.
///
/// Construct one before collecting a response body, call [`Self::reserve`] with
/// the running retained length (and with the preallocated capacity *before*
/// allocating it), then hand it to [`charged_bytes`] together with the bytes it
/// paid for so the charge outlives the collector. Dropping it without doing so
/// returns every block, which is what makes rejection, error, and cancellation
/// leak-free.
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

    /// Charge `retained_bytes` against the process-wide budget, acquiring more
    /// blocks when the collector has grown past what is already reserved.
    ///
    /// Returns `false` when the aggregate budget cannot cover the growth; the
    /// caller must then abandon collection and surface
    /// [`RESPONSE_BUFFER_OVERLOAD_STATUS`]. Already-held blocks stay held until
    /// this value drops.
    pub(crate) fn reserve(&mut self, retained_bytes: usize) -> bool {
        self.reserve_against(budget(), retained_bytes)
    }

    fn reserve_against(&mut self, budget: &Budget, retained_bytes: usize) -> bool {
        let wanted = u32::try_from(retained_bytes.div_ceil(RESERVATION_UNIT_BYTES).max(1))
            .unwrap_or(u32::MAX);
        if wanted <= self.blocks {
            return true;
        }
        let additional = wanted - self.blocks;
        match Arc::clone(&budget.permits).try_acquire_many_owned(additional) {
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

    /// Bytes currently reserved (whole blocks). Diagnostics only.
    pub(crate) fn reserved_bytes(&self) -> usize {
        self.blocks as usize * RESERVATION_UNIT_BYTES
    }

    fn into_permit(self) -> Option<OwnedSemaphorePermit> {
        self.permit
    }
}

/// One retained buffered-response allocation and the budget permit that paid
/// for it, owned together so neither can outlive the other.
struct ChargedBuffer {
    data: Vec<u8>,
    /// Released on drop. `None` only for the degenerate empty case, which is
    /// never charged.
    _permit: Option<OwnedSemaphorePermit>,
}

impl AsRef<[u8]> for ChargedBuffer {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

/// Publish a collected retained body as cheaply cloneable [`Bytes`] whose
/// budget charge is released exactly when the last clone drops.
///
/// `O(1)`: the `Vec` is moved, never copied, and `reservation` is moved into the
/// same owner. Every clone shares that owner, so the allocation stays charged
/// exactly once for as long as any handle to it exists.
pub(crate) fn charged_bytes(data: Vec<u8>, reservation: ResponseBufferReservation) -> Bytes {
    if data.is_empty() {
        // Nothing is retained, so nothing should stay charged. Dropping the
        // reservation here returns the (at most one) block a zero-length
        // collection rounded up to.
        return Bytes::new();
    }
    Bytes::from_owner(ChargedBuffer {
        data,
        _permit: reservation.into_permit(),
    })
}

/// Charge a retained body that was produced without a collector reservation —
/// a plugin phase that replaced or rewrote the buffered representation.
///
/// Returns `None` when the aggregate budget cannot admit the new allocation;
/// the caller must fail closed with [`RESPONSE_BUFFER_OVERLOAD_STATUS`] rather
/// than retaining uncharged bytes. Dropping the body being replaced returns its
/// own permit, so a same-size rewrite settles back to one charge.
pub(crate) fn charge_replacement_body(data: Vec<u8>) -> Option<Bytes> {
    charge_replacement_body_against(budget(), data)
}

fn charge_replacement_body_against(budget: &Budget, data: Vec<u8>) -> Option<Bytes> {
    if data.is_empty() {
        return Some(Bytes::new());
    }
    let mut reservation = ResponseBufferReservation::new();
    if !reservation.reserve_against(budget, data.len()) {
        return None;
    }
    Some(charged_bytes(data, reservation))
}

/// An isolated budget with the same construction, clamping, reservation, and
/// charge-attachment code the process-global one uses.
///
/// External tests need to observe admission and release deterministically,
/// which a shared process-global semaphore cannot offer under a parallel test
/// binary. This is the *same* [`Budget`] type and the *same* reservation path —
/// only the semaphore differs — so a test cannot pass against a parallel
/// implementation of the rules.
pub(crate) struct IsolatedBudget(Budget);

impl IsolatedBudget {
    pub(crate) fn new(fallback_per_response_bytes: usize, total_bytes: usize) -> Self {
        Self(Budget::new(fallback_per_response_bytes, total_bytes))
    }

    /// Currently unreserved capacity, in bytes.
    pub(crate) fn available_bytes(&self) -> usize {
        self.0.permits.available_permits() * RESERVATION_UNIT_BYTES
    }

    pub(crate) fn buffered_response_body_ceiling(&self, effective_limit: usize) -> usize {
        self.0.ceiling(effective_limit)
    }

    /// Reserve `bytes` before allocating them, exactly as the H3 / gRPC
    /// preallocation sites do.
    pub(crate) fn try_reserve(&self, bytes: usize) -> Option<ResponseBufferReservation> {
        let mut reservation = ResponseBufferReservation::new();
        let admitted = reservation.reserve_against(&self.0, bytes);
        if admitted { Some(reservation) } else { None }
    }

    /// Grow an existing reservation, exactly as a collector does per chunk.
    pub(crate) fn grow(&self, reservation: &mut ResponseBufferReservation, bytes: usize) -> bool {
        reservation.reserve_against(&self.0, bytes)
    }

    /// Collect-and-publish: reserve, then attach the charge to the retained
    /// bytes so it survives the collector's return.
    pub(crate) fn charge_retained_body(&self, data: Vec<u8>) -> Option<Bytes> {
        charge_replacement_body_against(&self.0, data)
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
