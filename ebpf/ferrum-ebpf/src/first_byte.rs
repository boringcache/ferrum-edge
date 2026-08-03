//! Verifier-safe first-application-data observation for captured TCP accepts.
//!
//! SOCK_OPS timestamps passive-established and enrolls the accepted socket in
//! a bounded sockhash. This SK_SKB stream parser runs only for those sockets,
//! atomically consumes confirmed correlation evidence on the first non-empty
//! receive buffer, and emits accept-to-first-byte latency. Userspace removes
//! the socket from the sockhash after a bounded grace period that lets this
//! parser and the paired verdict return. The verdict program always returns
//! SK_PASS; no payload byte is read, copied, logged, or modified.

use aya_ebpf::helpers::{bpf_get_socket_cookie, bpf_ktime_get_ns};
use aya_ebpf::macros::{stream_parser, stream_verdict};
use aya_ebpf::programs::SkBuffContext;
use aya_ebpf::EbpfContext;
use ferrum_ebpf_common::{accept_to_first_byte_us, SockOpsRecord};

use crate::maps::FERRUM_ACCEPT_FIRST_BYTE_STATE;
use crate::sock_ops_emit::emit;

#[stream_parser]
pub fn ferrum_first_byte_parser(ctx: SkBuffContext) -> u32 {
    let len = ctx.len();
    if len == 0 {
        return 0;
    }

    let cookie = unsafe { bpf_get_socket_cookie(ctx.as_ptr()) };
    let Some(state) = (unsafe { FERRUM_ACCEPT_FIRST_BYTE_STATE.get(&cookie) }).copied() else {
        // A consumed/evicted generation can still receive queued callbacks
        // until userspace processes the ringbuf record. Never manufacture a
        // second latency sample.
        return len;
    };

    // Map deletion is the verifier-safe single-consumer claim. Concurrent
    // queued callbacks may both read the value, but only one delete succeeds.
    // Confirmation uses BPF_EXIST and therefore cannot recreate deleted state.
    let claimed = FERRUM_ACCEPT_FIRST_BYTE_STATE.remove(&cookie).is_ok();
    if claimed && state.is_confirmed() {
        let accepted_ns = state.accepted_ns;
        let now_ns = unsafe { bpf_ktime_get_ns() };
        if let Some(us) = accept_to_first_byte_us(accepted_ns, now_ns) {
            emit(SockOpsRecord::accept_to_first_byte_latency(us, cookie));
        }
    }

    len
}

#[stream_verdict]
pub fn ferrum_first_byte_verdict(_ctx: SkBuffContext) -> u32 {
    // SK_PASS from include/uapi/linux/bpf.h. The parser is observability-only.
    1
}
