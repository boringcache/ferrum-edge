//! cgroup/getpeername6 — return original IPv6 destination.
//!
//! Same as getpeername4 but for IPv6 sockets.

use aya_ebpf::macros::cgroup_sock_addr;
use aya_ebpf::programs::SockAddrContext;
use aya_ebpf::EbpfContext;

use crate::maps::FERRUM_ORIG_DST6;
use ferrum_ebpf_common::{host_port_to_sock_addr_user_port, OrigDstKey};

#[cgroup_sock_addr(getpeername6)]
pub fn ferrum_getpeername6(ctx: SockAddrContext) -> i32 {
    match try_getpeername6(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

#[inline(always)]
fn try_getpeername6(ctx: &SockAddrContext) -> Result<i32, i64> {
    let cookie = unsafe { aya_ebpf::helpers::bpf_get_socket_cookie(ctx.as_ptr()) };
    let key = OrigDstKey { cookie };

    if let Some(orig) = unsafe { FERRUM_ORIG_DST6.get(&key) } {
        let sock_addr = unsafe { &mut *ctx.sock_addr };
        // Per-element store: the cgroup/getpeername6 ctx only allows direct
        // scalar field stores at constant offsets, not a whole-array `[u32; 4]`
        // copy (which the verifier rejects as a modified-ctx-ptr dereference).
        sock_addr.user_ip6[0] = orig.addr[0];
        sock_addr.user_ip6[1] = orig.addr[1];
        sock_addr.user_ip6[2] = orig.addr[2];
        sock_addr.user_ip6[3] = orig.addr[3];
        // host byte order -> network byte order in the low 16 bits (see getpeername4).
        sock_addr.user_port = host_port_to_sock_addr_user_port(orig.port as u16);
    }

    Ok(1)
}
