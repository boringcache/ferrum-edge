//! Per-direction traffic-key confidentiality budget for kTLS sessions
//! (issue #3619).
//!
//! # Why this module exists
//!
//! rustls normally counts the messages each traffic key has protected and
//! refuses to keep going once the negotiated suite's
//! `CipherSuiteCommon::confidentiality_limit` is reached. Handing the keys to
//! the kernel with `dangerous_into_kernel_connection` ends that: the rustls
//! `kernel` module states plainly that a `KernelConnection` "has no way to
//! track this" and that tracking approximately how many messages have been
//! sent — and aborting before the limit — becomes the caller's job.
//!
//! In the pinned providers (`rustls 0.23.40`, aws-lc-rs and ring alike) the
//! TLS 1.2 AES-GCM suites carry `confidentiality_limit: 1 << 24` and
//! ChaCha20-Poly1305 carries `u64::MAX`. So an AES-GCM kTLS session must be
//! torn down before 2^24 records in **either** direction, while ChaCha keeps
//! its genuinely unlimited posture and pays nothing here.
//!
//! # Why plaintext byte counters are not a record bound
//!
//! A peer chooses its own record sizing. A hostile client can emit minimum- or
//! zero-length records, so "bytes relayed / 2^14" understates the record count
//! by an unbounded factor. The only trustworthy record counter is the kernel's
//! own: the TLS ULP keeps the live per-direction record sequence number in
//! `cipher_context.rec_seq` and returns it from
//! `getsockopt(SOL_TLS, TLS_TX | TLS_RX)`, already including whatever the
//! handshake consumed before handoff. [`crate::socket_opts::ktls::read_ktls_record_seq`]
//! reads and validates that value; this module decides when to read it and what
//! it means.
//!
//! # Why polling it is not a per-byte syscall
//!
//! Reading the counter before every relayed byte would be absurd, and reading
//! it once per `splice(2)` would still add a syscall to the hot path. Instead
//! the guard runs a **pre-charged watchdog**: before every relay syscall it
//! reserves that syscall's *pessimistic upper bound* on records out of the
//! remaining budget, and only when the reservation no longer fits does it pay
//! for a fresh kernel observation. Because the reservation happens **before**
//! the syscall, the true sequence number can never pass the threshold between
//! two observations:
//!
//! > `true_seq ≤ observed_seq + (charges since the observation) ≤ threshold`
//!
//! The two bounds are:
//!
//! * **Transmit** — [`transmit_record_bound`]. The kernel packs a write into
//!   at most `ceil(bytes / 2^14)` full records, plus one for a record left
//!   partially filled by an earlier write.
//! * **Receive** — [`receive_record_bound`]. One non-blocking receive can only
//!   consume records the kernel has already queued, and queued data is capped
//!   by the socket receive buffer, so the record count is capped by
//!   `receive-ceiling / minimum-record-wire-size`.
//!
//! With a multi-megabyte ceiling that is roughly one `getsockopt` per few dozen
//! splice calls, and with a quiet socket it is one per several hundred
//! megabytes.
//!
//! # Why the receive ceiling has to be *pinned*, not merely measured
//!
//! The receive bound is only as good as the claim "the kernel cannot hold more
//! than this". A live `SO_RCVBUF` reading does not support that claim: TCP
//! receive autotuning rewrites `sk_rcvbuf` while the connection runs, bounded by
//! `net.ipv4.tcp_rmem[2]` — a sysctl an operator can raise at any moment. Taking
//! the maximum of a live reading, a cached `/proc` snapshot, and a constant does
//! not fix that: every one of those three is either stale or arbitrary, so a
//! socket could autotune above the charged bound and a single nonblocking
//! `splice(2)` could then consume more minimum-size records than were reserved,
//! crossing the AES-GCM confidentiality threshold before the next observation.
//!
//! So the ceiling is made immutable in the kernel instead of estimated in
//! userspace. Before the rustls session is consumed,
//! [`crate::socket_opts::ktls::pin_socket_receive_buffer`] issues
//! `setsockopt(SO_RCVBUF)`, which sets `SOCK_RCVBUF_LOCK` on the socket; every
//! kernel path that raises `sk_rcvbuf` is gated on that flag being clear, so
//! from that instant `sk_rcvbuf` is frozen for the life of this connection no
//! matter what the sysctls do afterwards. The `getsockopt` readback — not the
//! request — is the pinned value, which is how Linux's clamp-to-`rmem_max` and
//! doubling-for-overhead semantics are accounted for without predicting them.
//!
//! Data that was *already* queued when the pin took effect was admitted under
//! the old, unknown `sk_rcvbuf`, so it is measured directly with `FIONREAD`
//! after the pin and added in ([`stable_receive_ceiling`]). Afterwards the
//! kernel only admits data while the queue is below the pinned size, so for
//! every later instant `queued ≤ max(queued_at_pin, pinned)`, and the ceiling
//! bounds both terms plus [`KTLS_RECEIVE_QUEUE_OVERSHOOT_BYTES`] of headroom
//! for the one super-frame Linux may admit past the limit and for the TLS
//! strparser's partial-record anchor.
//!
//! That single value is computed once at handoff and never revised: an
//! observation refreshes the *sequence number*, never the window's size, so
//! there is no seam through which a mutable process-global could widen it.
//!
//! # Fail closed
//!
//! Every uncertainty ends the relay rather than relaxing the bound: an
//! unreadable or malformed kernel counter ([`KtlsConfidentialityError::Unobservable`]),
//! a counter that moves backwards ([`KtlsConfidentialityError::NonMonotonic`]),
//! a single observation window that cannot be proven to fit in the remaining
//! budget ([`KtlsConfidentialityError::WindowExceedsBudget`]), and of course
//! reaching the threshold itself ([`KtlsConfidentialityError::LimitReached`]).
//! Ciphers whose limit is enforceable are additionally refused *before the
//! handshake is consumed* when the kernel cannot expose the counter at all, and
//! a receive window that cannot be pinned and read back refuses the handoff
//! while the rustls session is still intact — see `proxy::ktls_accept`.

use crate::socket_opts::ktls::KtlsCipher;

/// Records held back below the negotiated suite's confidentiality limit.
///
/// The pre-charge discipline already keeps the true sequence number at or
/// below the threshold, so this is pure headroom: it absorbs the handful of
/// records teardown may still emit (the `close_notify` alert) and any kernel
/// accounting subtlety, at a cost of 0.4% of an AES-GCM budget.
pub const KTLS_CONFIDENTIALITY_RESERVE_RECORDS: u64 = 1 << 16;

/// Largest `TLSPlaintext.length` (2^14) — the record granularity the kernel
/// packs transmitted plaintext into.
pub const MAX_TLS_PLAINTEXT_BYTES: u64 = 16_384;

/// Fewest wire bytes a TLS 1.2 AEAD record can occupy: a 5-byte record header,
/// the 8-byte explicit nonce, and the 16-byte AEAD tag, with an empty payload.
///
/// This is what makes a receive-side record count boundable at all: a peer may
/// choose the payload size, but it cannot make a record cheaper than this on
/// the wire, and the kernel cannot hold more unread wire bytes than the socket
/// receive buffer allows.
pub const MIN_TLS12_AEAD_RECORD_WIRE_BYTES: u64 = 29;

/// Receive-buffer size requested when pinning a kTLS socket.
///
/// Pinning necessarily disables receive autotuning, so the request is chosen to
/// be comfortably above the default autotuned working set rather than minimal.
/// The kernel clamps it to `net.core.rmem_max` and then doubles it, and the
/// readback is what the bound actually uses, so this value is a preference for
/// throughput and never part of the safety argument.
pub const KTLS_PINNED_RECEIVE_BUFFER_REQUEST_BYTES: u64 = 4 * 1024 * 1024;

/// Headroom added on top of the pinned buffer and the measured queue.
///
/// Linux admits an incoming segment when the receive queue is *below*
/// `sk_rcvbuf`, so the queue may end up one super-frame past it (GRO, and larger
/// still with BIG TCP), and the kTLS strparser may hold one partial record in
/// its anchor outside that accounting. One mebibyte covers both with room to
/// spare. Overstating the ceiling only buys extra `getsockopt` calls;
/// understating it would break the bound.
pub const KTLS_RECEIVE_QUEUE_OVERSHOOT_BYTES: u64 = 1024 * 1024;

/// Which traffic key a budget belongs to.
///
/// The two directions have independent keys and independent record sequence
/// numbers, so they get independent budgets — and, because each relay
/// direction owns its own guard, no lock is shared between them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KtlsDirection {
    /// Gateway → client: records the kernel encrypts on write.
    Transmit,
    /// Client → gateway: records the kernel decrypts on read.
    Receive,
}

impl KtlsDirection {
    /// Stable label for logs and error text.
    #[inline]
    pub fn as_str(self) -> &'static str {
        match self {
            KtlsDirection::Transmit => "transmit",
            KtlsDirection::Receive => "receive",
        }
    }

    /// Whether this direction maps to the kernel's `TLS_TX` option.
    #[inline]
    pub fn is_transmit(self) -> bool {
        matches!(self, KtlsDirection::Transmit)
    }
}

impl std::fmt::Display for KtlsDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a kTLS relay direction must stop.
///
/// Every variant is terminal. None of them may be downgraded to a warning:
/// continuing past any of them means relaying records this process cannot
/// prove are still inside the cipher's confidentiality bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KtlsConfidentialityError {
    /// The traffic key has protected as many records as it safely can.
    LimitReached {
        /// Direction whose budget ran out.
        direction: KtlsDirection,
        /// Kernel record sequence number at the refusal.
        observed: u64,
        /// Sequence number at which relaying stops.
        threshold: u64,
    },
    /// The kernel record sequence number moved backwards, so it cannot be
    /// trusted as a monotonic message counter.
    NonMonotonic {
        /// Direction whose counter regressed.
        direction: KtlsDirection,
        /// Previously observed value.
        previous: u64,
        /// Value just read.
        observed: u64,
    },
    /// The counter could not be read, or did not match the layout/version/
    /// cipher this session installed.
    Unobservable {
        /// Direction that could not be observed.
        direction: KtlsDirection,
        /// Kernel or validation detail.
        detail: String,
    },
    /// One observation window's pessimistic record bound does not fit in the
    /// remaining budget, so no further syscall can be proven safe.
    WindowExceedsBudget {
        /// Direction that could not be charged.
        direction: KtlsDirection,
        /// Records the next syscall could consume in the worst case.
        step_records: u64,
        /// Records left below the threshold.
        remaining: u64,
    },
}

impl std::fmt::Display for KtlsConfidentialityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KtlsConfidentialityError::LimitReached {
                direction,
                observed,
                threshold,
            } => write!(
                f,
                "kTLS {direction} side: cipher confidentiality limit reached \
                 (record {observed} of {threshold}); ending the connection so the \
                 traffic key is not used beyond its safe bound"
            ),
            KtlsConfidentialityError::NonMonotonic {
                direction,
                previous,
                observed,
            } => write!(
                f,
                "kTLS {direction} side: kernel record sequence went backwards \
                 ({previous} then {observed}); the confidentiality budget cannot be trusted"
            ),
            KtlsConfidentialityError::Unobservable { direction, detail } => write!(
                f,
                "kTLS {direction} side: kernel record sequence is unreadable ({detail}); \
                 the confidentiality budget cannot be enforced"
            ),
            KtlsConfidentialityError::WindowExceedsBudget {
                direction,
                step_records,
                remaining,
            } => write!(
                f,
                "kTLS {direction} side: next relay step could consume {step_records} records \
                 but only {remaining} remain below the confidentiality limit"
            ),
        }
    }
}

impl std::error::Error for KtlsConfidentialityError {}

/// Upper bound on the records one write of `bytes` plaintext can produce.
///
/// The kernel fills a record to `MAX_TLS_PLAINTEXT_BYTES` before emitting it,
/// so `bytes` produce at most `ceil(bytes / 2^14)` records — plus one, because
/// this write may also complete a record an earlier write left partially
/// filled.
#[inline]
pub fn transmit_record_bound(bytes: u64) -> u64 {
    bytes.div_ceil(MAX_TLS_PLAINTEXT_BYTES).saturating_add(1)
}

/// Upper bound on the records one non-blocking receive can consume.
///
/// A receive only sees records the kernel already holds, and what it holds is
/// capped by [`stable_receive_ceiling`]. Every record costs at least
/// [`MIN_TLS12_AEAD_RECORD_WIRE_BYTES`] there, so the count cannot exceed
/// `ceiling / 29`. The `+ 1` covers a record straddling the accounting edge.
#[inline]
pub fn receive_record_bound(receive_ceiling_bytes: u64) -> u64 {
    receive_ceiling_bytes
        .div_ceil(MIN_TLS12_AEAD_RECORD_WIRE_BYTES)
        .saturating_add(1)
}

/// The immutable receive ceiling a whole kTLS session is bounded with.
///
/// `pinned_receive_buffer_bytes` is the `getsockopt(SO_RCVBUF)` readback taken
/// *after* `SOCK_RCVBUF_LOCK` was set, so the kernel cannot raise it again for
/// this socket. `queued_bytes` is the `FIONREAD` measurement taken *after* the
/// same pin, which is what bounds data admitted under the old, unknown buffer
/// size — a quantity no post-hoc observation could otherwise reconstruct.
///
/// Because the kernel only admits more data while the queue is below the pinned
/// size, at every later instant `queued ≤ max(queued_at_pin, pinned)`; summing
/// the two terms and adding [`KTLS_RECEIVE_QUEUE_OVERSHOOT_BYTES`] is therefore
/// a strict over-approximation that holds for the life of the connection.
#[inline]
pub fn stable_receive_ceiling(pinned_receive_buffer_bytes: u64, queued_bytes: u64) -> u64 {
    pinned_receive_buffer_bytes
        .saturating_add(queued_bytes)
        .saturating_add(KTLS_RECEIVE_QUEUE_OVERSHOOT_BYTES)
}

/// One reading of a direction's kernel record sequence number.
///
/// An observation carries the sequence number and nothing else, deliberately.
/// The per-syscall record bound is fixed at handoff from the pinned receive
/// ceiling, so there is no field here through which a later reading could
/// widen the window — which is exactly the hazard a re-measured, autotuning-
/// or sysctl-derived bound reintroduces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KtlsObservation {
    /// Live `rec_seq` for the direction.
    pub record_seq: u64,
}

/// Everything about a handed-off session that decides whether — and how — the
/// confidentiality limit is enforced.
#[derive(Debug, Clone, Copy)]
pub struct KtlsSessionLimits {
    /// Kernel cipher family installed on the socket.
    pub cipher: KtlsCipher,
    /// Wire version installed on the socket (TLS 1.2 today).
    pub tls_version: u16,
    /// The negotiated suite's `CipherSuiteCommon::confidentiality_limit`, read
    /// from rustls rather than hardcoded, so a provider change cannot silently
    /// leave this stale.
    pub confidentiality_limit: u64,
}

impl KtlsSessionLimits {
    /// Whether this suite has a finite record budget to enforce.
    ///
    /// `u64::MAX` is rustls's encoding of "no confidentiality limit applies"
    /// (ChaCha20-Poly1305), and enforcing nothing there is the correct posture,
    /// not an omission.
    #[inline]
    pub fn requires_enforcement(&self) -> bool {
        self.confidentiality_limit != u64::MAX
    }

    /// Sequence number at which relaying must stop.
    #[inline]
    pub fn threshold(&self) -> u64 {
        self.confidentiality_limit
            .saturating_sub(KTLS_CONFIDENTIALITY_RESERVE_RECORDS)
    }
}

/// The per-connection budget seed produced by the kTLS accept.
///
/// The initial sequence numbers are the kernel's own readback taken right
/// after the keys were installed, so they already account for every record the
/// handshake consumed (a TLS 1.2 server has at minimum encrypted and decrypted
/// one `Finished` record before handoff).
#[derive(Debug, Clone, Copy)]
pub struct KtlsConfidentialityPolicy {
    /// Cipher, version, and limit for this session.
    pub limits: KtlsSessionLimits,
    /// Kernel `TLS_TX` `rec_seq` observed immediately after key install.
    pub initial_transmit_seq: u64,
    /// Kernel `TLS_RX` `rec_seq` observed immediately after key install.
    pub initial_receive_seq: u64,
    /// The pinned, kernel-enforced receive ceiling this session is bounded
    /// with. Established once at handoff from a locked `SO_RCVBUF` plus the
    /// queue measured behind it, and never revised — every receive observation
    /// window for the life of the connection is sized from this one value.
    pub stable_receive_ceiling: u64,
}

impl KtlsConfidentialityPolicy {
    /// A policy for a suite rustls reports as unlimited.
    ///
    /// No guard is ever built from it, so no receive window is ever sized: the
    /// ceiling is zero because such a session never pins its receive buffer at
    /// all, which is also why an unlimited suite keeps ordinary TCP receive
    /// autotuning.
    pub fn unlimited(cipher: KtlsCipher, tls_version: u16) -> Self {
        Self {
            limits: KtlsSessionLimits {
                cipher,
                tls_version,
                confidentiality_limit: u64::MAX,
            },
            initial_transmit_seq: 0,
            initial_receive_seq: 0,
            stable_receive_ceiling: 0,
        }
    }

    /// Build the guard for one direction.
    ///
    /// `Ok(None)` means the suite carries no confidentiality limit. An `Err`
    /// means the session is already at or beyond its budget at handoff, which
    /// must fail the connection rather than start a relay.
    pub fn guard(
        &self,
        direction: KtlsDirection,
    ) -> Result<Option<KtlsConfidentialityGuard>, KtlsConfidentialityError> {
        if !self.limits.requires_enforcement() {
            return Ok(None);
        }
        let ceiling = self.stable_receive_ceiling;
        let seq = match direction {
            KtlsDirection::Transmit => self.initial_transmit_seq,
            KtlsDirection::Receive => self.initial_receive_seq,
        };
        let step = match direction {
            KtlsDirection::Transmit => transmit_record_bound(MAX_TLS_PLAINTEXT_BYTES),
            KtlsDirection::Receive => receive_record_bound(ceiling),
        };
        let threshold = self.limits.threshold();
        let guard = KtlsConfidentialityGuard::new(direction, threshold, seq, step)?;
        Ok(Some(guard))
    }
}

/// A single direction's record budget.
///
/// Owned outright by the relay future for that direction — never shared, never
/// locked, never allocated per byte.
#[derive(Debug, Clone)]
pub struct KtlsConfidentialityGuard {
    direction: KtlsDirection,
    threshold: u64,
    observed: u64,
    allowance: u64,
    step_records: u64,
}

impl KtlsConfidentialityGuard {
    /// Seed a guard from an authoritative kernel observation.
    pub fn new(
        direction: KtlsDirection,
        threshold: u64,
        initial_seq: u64,
        step_records: u64,
    ) -> Result<Self, KtlsConfidentialityError> {
        if initial_seq >= threshold {
            return Err(KtlsConfidentialityError::LimitReached {
                direction,
                observed: initial_seq,
                threshold,
            });
        }
        Ok(Self {
            direction,
            threshold,
            observed: initial_seq,
            allowance: threshold - initial_seq,
            step_records: step_records.max(1),
        })
    }

    /// Direction this budget belongs to.
    #[inline]
    pub fn direction(&self) -> KtlsDirection {
        self.direction
    }

    /// Sequence number at which the relay stops.
    #[inline]
    pub fn threshold(&self) -> u64 {
        self.threshold
    }

    /// Most recent kernel observation.
    #[inline]
    pub fn observed(&self) -> u64 {
        self.observed
    }

    /// Records still reservable before a fresh observation is required.
    #[inline]
    pub fn allowance(&self) -> u64 {
        self.allowance
    }

    /// Pessimistic record bound charged for the next relay syscall.
    ///
    /// Fixed for the life of the guard. On the receive side it is derived from
    /// the pinned receive ceiling at handoff; there is intentionally no setter,
    /// so no later observation can enlarge it.
    #[inline]
    pub fn step_records(&self) -> u64 {
        self.step_records
    }

    /// Reserve `records` against the current window.
    ///
    /// Returns `false` when the reservation does not fit, which means a fresh
    /// kernel observation is required *before* the syscall runs.
    #[inline]
    pub fn charge(&mut self, records: u64) -> bool {
        if records > self.allowance {
            return false;
        }
        self.allowance -= records;
        true
    }

    /// Adopt a fresh kernel observation.
    ///
    /// Rejects a counter that regressed and a counter that has reached the
    /// threshold; otherwise the window reopens at `threshold - record_seq`.
    pub fn refresh(&mut self, record_seq: u64) -> Result<(), KtlsConfidentialityError> {
        if record_seq < self.observed {
            return Err(KtlsConfidentialityError::NonMonotonic {
                direction: self.direction,
                previous: self.observed,
                observed: record_seq,
            });
        }
        if record_seq >= self.threshold {
            return Err(KtlsConfidentialityError::LimitReached {
                direction: self.direction,
                observed: record_seq,
                threshold: self.threshold,
            });
        }
        self.observed = record_seq;
        self.allowance = self.threshold - record_seq;
        Ok(())
    }
}

/// Reserve `records`, paying for one kernel observation if the current window
/// cannot cover them.
///
/// This is the whole enforcement loop, kept free of syscalls so it can be
/// driven deterministically from tests: `observe` is only invoked when the
/// pre-charge fails, and a reservation that still does not fit afterwards is a
/// terminal refusal rather than a retry.
///
/// An observation reopens the window at `threshold - record_seq` and nothing
/// more. It cannot change what a step costs, because the receive step was fixed
/// against a kernel-pinned ceiling before the first relayed byte.
pub fn charge_or_observe<F>(
    guard: &mut KtlsConfidentialityGuard,
    records: u64,
    observe: F,
) -> Result<(), KtlsConfidentialityError>
where
    F: FnOnce() -> Result<KtlsObservation, KtlsConfidentialityError>,
{
    if guard.charge(records) {
        return Ok(());
    }
    let observation = observe()?;
    guard.refresh(observation.record_seq)?;
    if guard.charge(records) {
        return Ok(());
    }
    Err(KtlsConfidentialityError::WindowExceedsBudget {
        direction: guard.direction(),
        step_records: records,
        remaining: guard.allowance(),
    })
}

#[cfg(target_os = "linux")]
mod linux {
    use std::os::unix::io::RawFd;

    use super::{
        KTLS_PINNED_RECEIVE_BUFFER_REQUEST_BYTES, KtlsConfidentialityError, KtlsDirection,
        KtlsObservation, KtlsSessionLimits, stable_receive_ceiling,
    };
    use crate::socket_opts::ktls;

    /// Read one direction's live kernel record sequence number.
    ///
    /// Validation lives in [`ktls::read_ktls_record_seq`]: the returned option
    /// length must match the cipher's `tls12_crypto_info_*` layout exactly and
    /// the echoed version/cipher type must be the ones this session installed,
    /// so a kernel that answers with a different structure fails closed here
    /// instead of yielding a garbage counter.
    pub fn observe_record_seq(
        fd: RawFd,
        limits: &KtlsSessionLimits,
        direction: KtlsDirection,
    ) -> Result<KtlsObservation, KtlsConfidentialityError> {
        let is_tx = direction.is_transmit();
        let cipher = limits.cipher;
        let version = limits.tls_version;
        let observed = ktls::read_ktls_record_seq(fd, cipher, version, is_tx);
        let record_seq = observed.map_err(|e| KtlsConfidentialityError::Unobservable {
            direction,
            detail: e.to_string(),
        })?;
        // Deliberately nothing else: the receive window's size was fixed
        // against a kernel-pinned ceiling at handoff, so re-measuring a
        // mutable buffer size here is precisely what must not happen.
        Ok(KtlsObservation { record_seq })
    }

    /// Freeze this socket's receive window and return the immutable ceiling the
    /// whole session's receive bound is built on.
    ///
    /// Must be called while the rustls session is still intact, because failure
    /// has to be a refusal rather than a relay that cannot be bounded. Both
    /// steps are setup-time syscalls on a cold path; the relay itself pays
    /// nothing for them.
    ///
    /// The `FIONREAD` measurement is taken *after* the pin on purpose. Anything
    /// queued before the pin was admitted under a buffer size that is no longer
    /// knowable, and reading the queue afterwards captures all of it; reading it
    /// first would leave the bytes that arrived in between unaccounted for.
    pub fn pin_receive_window(fd: RawFd) -> std::io::Result<u64> {
        let request = KTLS_PINNED_RECEIVE_BUFFER_REQUEST_BYTES;
        let pinned = ktls::pin_socket_receive_buffer(fd, request)?;
        let queued = ktls::socket_receive_queue_bytes(fd)?;
        Ok(stable_receive_ceiling(pinned, queued))
    }
}

#[cfg(target_os = "linux")]
pub use linux::{observe_record_seq, pin_receive_window};
