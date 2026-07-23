//! Shared SOCK_OPS ringbuf publish helpers.
//!
//! Used by `ferrum_sock_ops` and by the `connect4`/`connect6` capture hooks so
//! bypass decisions and TCP-lifecycle events share one producer surface,
//! including the same ring-buffer-full → per-CPU dropped counter contract.

use ferrum_ebpf_common::{
    SockOpsRecord, SOCK_OPS_EVENT_DROP_REASON, SOCK_OPS_STATS_EVENTS_DROPPED,
};

use crate::maps::{FERRUM_SOCK_OPS_EVENTS, FERRUM_SOCK_OPS_STATS};

/// Publish one [`SockOpsRecord`] to the SOCK_OPS events ringbuf.
///
/// When the ringbuf cannot reserve space, bumps
/// `FERRUM_SOCK_OPS_STATS[SOCK_OPS_STATS_EVENTS_DROPPED]` so userspace can
/// enter the overrun regime. Never blocks the hot path.
#[inline(always)]
pub fn emit(record: SockOpsRecord) {
    match FERRUM_SOCK_OPS_EVENTS.reserve::<SockOpsRecord>(0) {
        Some(mut entry) => {
            entry.write(record);
            entry.submit(0);
        }
        None => {
            // Ringbuf full — bump the per-CPU kernel-side dropped counter
            // so the userspace consumer can flip into the overrun regime.
            // PerCpuArray slots are CPU-local, so a non-atomic increment
            // is safe (no other CPU touches this slot until userspace
            // reads). Userspace sums across CPUs when polling.
            if let Some(slot) = FERRUM_SOCK_OPS_STATS.get_ptr_mut(SOCK_OPS_STATS_EVENTS_DROPPED) {
                // Safety: `slot` points into a per-CPU array slot the
                // verifier already proved valid for the current CPU.
                unsafe {
                    *slot = (*slot).wrapping_add(1);
                }
            }
        }
    }
}

/// Emit a capture-bypass decision (`SOCK_OPS_EVENT_DROP_REASON`).
///
/// `reason` must be one of the `SOCK_OPS_DROP_*` discriminants. Best-effort:
/// ringbuf failure only increments the dropped counter (same as [`emit`]).
#[inline(always)]
pub fn emit_drop_reason(reason: u32) {
    emit(SockOpsRecord {
        event_type: SOCK_OPS_EVENT_DROP_REASON,
        direction: 0,
        drop_reason: reason,
        _pad: 0,
        value: 0,
    });
}
