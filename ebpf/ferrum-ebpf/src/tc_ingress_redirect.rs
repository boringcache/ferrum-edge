//! tc **ingress** redirect — steer inbound traffic for enrolled NodeWaypoint
//! workloads into the node's local HBONE relay.
//!
//! This is the eBPF-owned replacement for the node-global `nat PREROUTING -j
//! REDIRECT` rule that the iptables fallback installs. Where that rule rewrites
//! the destination of *every* TCP packet traversing the node, this program acts
//! only on a packet whose destination is an **enrolled** pod IP that has
//! explicitly opted in (`POD_CAPTURE_FLAG_INBOUND_REDIRECT`) on a **declared**
//! inbound application port (`FERRUM_POD_INBOUND_PORTS` /
//! `FERRUM_POD_INBOUND_PORTS6`). Everything else is returned untouched.
//!
//! ## Mechanism: `bpf_sk_assign`, not NAT
//!
//! The packet's addresses are **never rewritten**. Instead the program looks up
//! the NodeWaypoint inbound listener and attaches it to the skb with
//! `bpf_sk_assign()`, then stamps `skb->mark` with the configured redirect mark
//! so the node-agent's policy-routing rule (`ip rule fwmark <mark> lookup
//! <table>` + `ip route add local default dev lo table <table>`) delivers the
//! packet locally instead of forwarding it on to the pod.
//!
//! Preserving the addresses is what preserves the **original destination
//! metadata** for free: the relay's accepted socket reports the workload's real
//! `podIP:appPort` from `getsockname()`, with no conntrack table, no reverse
//! NAT, and no checksum rewriting. The listener must be bound
//! `IP_TRANSPARENT`/`IPV6_TRANSPARENT` so its replies may be sourced from the
//! pod address it is terminating on behalf of.
//!
//! ## Ordering: existing flow first, listener second
//!
//! An already-established connection is assigned back to **its own** socket
//! (`bpf_skc_lookup_tcp` on the packet tuple) before the listener is even
//! considered, so mid-flow packets are never re-dispatched to the listener.
//! Only when no established socket matches does the program fall through to the
//! wildcard listener lookup, mirroring the kernel's own `sk_assign` reference
//! datapath.
//!
//! ## Loop and self-capture prevention
//!
//! Three independent guards, any one of which returns the packet untouched:
//!
//! 1. `skb->mark == node_waypoint_inbound_auth_mark` — the relay's own
//!    authorized dial back down to the local backend pod. Redirecting it would
//!    feed the relay its own traffic forever.
//! 2. `skb->mark == node_waypoint_ingress_redirect_mark` — this program already
//!    handled the packet (or a peer hook did); never redirect twice.
//! 3. `dst_port == hbone_redirect_port` — traffic already aimed at the relay
//!    listener, including peer-to-peer HBONE, must reach it directly.
//!
//! ## Fail-closed
//!
//! A packet that IS in scope (enrolled pod, opted in, declared port) but for
//! which no relay socket can be found is **dropped**, not delivered. Delivering
//! it would silently bypass `mesh_authz` for exactly the traffic the operator
//! asked to capture. Out-of-scope packets are never dropped by this program —
//! the pre-existing `ferrum_tc_inbound` direct-pod guard remains the authority
//! for those.
//!
//! ## Disarmed by default
//!
//! A zero `node_waypoint_ingress_redirect_mark` (the default, and what
//! local-pod mode always carries) makes every path return `TC_ACT_OK` before a
//! single map lookup, so a node that has not been explicitly opted in behaves
//! exactly as it did before this program existed.

use core::mem;

use aya_ebpf::bindings::{
    bpf_sock_tuple, BPF_F_CURRENT_NETNS, BPF_TCP_LISTEN, TC_ACT_OK, TC_ACT_SHOT,
};
use aya_ebpf::helpers::{bpf_sk_assign, bpf_sk_release, bpf_skc_lookup_tcp};
use aya_ebpf::macros::classifier;
use aya_ebpf::programs::TcContext;
use ferrum_ebpf_common::{
    BpfCaptureConfig, CidrKey6, InboundRedirectKey4, InboundRedirectKey6, FERRUM_CAPTURE_CONFIG_KEY,
};

use crate::maps::{
    FERRUM_CAPTURE_CONFIG, FERRUM_POD_INBOUND_PORTS, FERRUM_POD_INBOUND_PORTS6, FERRUM_POD_IPS,
    FERRUM_POD_IPS6,
};

const ETH_HDR_LEN: usize = 14;
const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const IPPROTO_TCP: u8 = 6;

/// Size of the IPv4 arm of `bpf_sock_tuple` (2 addresses + 2 ports = 12 bytes).
/// The kernel validates `tuple_size` against exactly this, so it is derived
/// from the binding rather than hardcoded.
#[inline(always)]
fn tuple_len_v4() -> u32 {
    mem::size_of::<aya_ebpf::bindings::bpf_sock_tuple__bindgen_ty_1__bindgen_ty_1>() as u32
}

/// Size of the IPv6 arm of `bpf_sock_tuple` (2 addresses + 2 ports = 36 bytes).
#[inline(always)]
fn tuple_len_v6() -> u32 {
    mem::size_of::<aya_ebpf::bindings::bpf_sock_tuple__bindgen_ty_1__bindgen_ty_2>() as u32
}

#[classifier]
pub fn ferrum_tc_ingress_redirect(ctx: TcContext) -> i32 {
    let mut ctx = ctx;
    match try_ingress_redirect(&mut ctx) {
        Ok(action) => action,
        // A parse failure on an in-scope decision is never reached: every
        // fallible load below happens before scope is established, so an
        // unparseable packet is simply passed on to the direct-pod guard.
        Err(_) => TC_ACT_OK,
    }
}

/// Resolved, armed redirect settings. Constructed only when the operator has
/// opted the node in; its existence is the proof the datapath is live.
///
/// The decision predicates themselves live in `ferrum-ebpf-common`
/// (`BpfCaptureConfig::ingress_redirect_{armed,bypass}` and
/// `ingress_redirect_action`) so the host-side unit tests exercise the very same
/// truth table this program evaluates — the kernel side only parses packets and
/// looks maps up.
#[derive(Clone, Copy)]
struct RedirectConfig {
    config: BpfCaptureConfig,
    relay_port: u16,
    redirect_mark: u32,
}

/// Load and validate the redirect configuration.
///
/// Returns `None` — meaning "do nothing at all" — when the capture config is
/// absent (stale ELF / node-agent not yet initialized) or the redirect is
/// disarmed. Both are the disabled posture, not an error: the direct-pod guard
/// is still in force and this program must not perturb the datapath.
#[inline(always)]
fn redirect_config() -> Option<RedirectConfig> {
    let config = unsafe { FERRUM_CAPTURE_CONFIG.get(&FERRUM_CAPTURE_CONFIG_KEY) }?;
    if !config.ingress_redirect_armed() {
        return None;
    }
    Some(RedirectConfig {
        config: *config,
        relay_port: config.hbone_redirect_port as u16,
        redirect_mark: config.node_waypoint_ingress_redirect_mark,
    })
}

/// The three loop / self-capture guards. `true` means "leave this packet
/// alone" — it is either already relayed, already redirected, or addressed to
/// the relay listener itself. Delegates to the shared, unit-tested predicate.
#[inline(always)]
fn is_already_owned_by_the_relay(mark: u32, dst_port: u16, config: &RedirectConfig) -> bool {
    config.config.ingress_redirect_bypass(mark, dst_port)
}

#[inline(always)]
fn try_ingress_redirect(ctx: &mut TcContext) -> Result<i32, i64> {
    let Some(config) = redirect_config() else {
        return Ok(TC_ACT_OK);
    };

    let eth_type: u16 = ctx.load(12).map_err(|_| -1i64)?;
    match u16::from_be(eth_type) {
        ETH_P_IP => redirect_ipv4(ctx, &config),
        ETH_P_IPV6 => redirect_ipv6(ctx, &config),
        _ => Ok(TC_ACT_OK),
    }
}

#[inline(always)]
fn redirect_ipv4(ctx: &mut TcContext, config: &RedirectConfig) -> Result<i32, i64> {
    let protocol: u8 = ctx.load(ETH_HDR_LEN + 9).map_err(|_| -1i64)?;
    if protocol != IPPROTO_TCP {
        return Ok(TC_ACT_OK);
    }

    // Honor the IHL so options-bearing headers still locate the TCP ports.
    let version_ihl: u8 = ctx.load(ETH_HDR_LEN).map_err(|_| -1i64)?;
    let ihl = ((version_ihl & 0x0f) as usize) * 4;
    if ihl < 20 {
        return Ok(TC_ACT_OK);
    }

    let src_ip: u32 = ctx.load(ETH_HDR_LEN + 12).map_err(|_| -1i64)?;
    let dst_ip: u32 = ctx.load(ETH_HDR_LEN + 16).map_err(|_| -1i64)?;
    let src_port_be: u16 = ctx.load(ETH_HDR_LEN + ihl).map_err(|_| -1i64)?;
    let dst_port_be: u16 = ctx.load(ETH_HDR_LEN + ihl + 2).map_err(|_| -1i64)?;
    let dst_port = u16::from_be(dst_port_be);

    if is_already_owned_by_the_relay(skb_mark(ctx), dst_port, config) {
        return Ok(TC_ACT_OK);
    }

    // Ownership: the destination must be an enrolled pod that opted in.
    match unsafe { FERRUM_POD_IPS.get(&dst_ip) } {
        Some(info) if info.inbound_redirect_enabled() => {}
        _ => return Ok(TC_ACT_OK),
    }
    // Scope: and the destination port must be one of its declared inbound
    // application ports.
    if unsafe { FERRUM_POD_INBOUND_PORTS.get(&InboundRedirectKey4::new(dst_ip, dst_port)) }
        .is_none()
    {
        return Ok(TC_ACT_OK);
    }

    // In scope from here on: the packet is either assigned to a relay socket or
    // dropped. It is never delivered to the pod unredirected.
    let mut tuple: bpf_sock_tuple = unsafe { mem::zeroed() };
    tuple.__bindgen_anon_1.ipv4.saddr = src_ip;
    tuple.__bindgen_anon_1.ipv4.daddr = dst_ip;
    tuple.__bindgen_anon_1.ipv4.sport = src_port_be;
    tuple.__bindgen_anon_1.ipv4.dport = dst_port_be;

    let established = lookup_socket(ctx, &mut tuple, tuple_len_v4());
    if !established.is_null() {
        if unsafe { (*established).state } != BPF_TCP_LISTEN {
            return Ok(assign_and_release(ctx, established, config));
        }
        unsafe {
            bpf_sk_release(established as *mut _);
        }
    }

    // Wildcard listener lookup: a zero destination address matches a listener
    // bound to `0.0.0.0`, which is how the relay's inbound listener binds.
    let mut listen_tuple: bpf_sock_tuple = unsafe { mem::zeroed() };
    listen_tuple.__bindgen_anon_1.ipv4.saddr = 0;
    listen_tuple.__bindgen_anon_1.ipv4.daddr = 0;
    listen_tuple.__bindgen_anon_1.ipv4.sport = 0;
    listen_tuple.__bindgen_anon_1.ipv4.dport = config.relay_port.to_be();

    let listener = lookup_socket(ctx, &mut listen_tuple, tuple_len_v4());
    Ok(assign_listener_or_drop(ctx, listener, config))
}

#[inline(always)]
fn redirect_ipv6(ctx: &mut TcContext, config: &RedirectConfig) -> Result<i32, i64> {
    // Only a bare TCP next-header is redirected. An IPv6 extension chain is
    // left to the direct-pod guard, which already fails it closed for enrolled
    // destinations — guessing a transport offset here would be the one way to
    // misattribute a packet.
    let next_header: u8 = ctx.load(ETH_HDR_LEN + 6).map_err(|_| -1i64)?;
    if next_header != IPPROTO_TCP {
        return Ok(TC_ACT_OK);
    }

    // Read the v6 address words element-by-element at explicit offsets, the
    // same verifier-safe technique `connect6` and the sock_ops bridge use.
    let src_words = [
        ctx.load::<u32>(ETH_HDR_LEN + 8).map_err(|_| -1i64)?,
        ctx.load::<u32>(ETH_HDR_LEN + 12).map_err(|_| -1i64)?,
        ctx.load::<u32>(ETH_HDR_LEN + 16).map_err(|_| -1i64)?,
        ctx.load::<u32>(ETH_HDR_LEN + 20).map_err(|_| -1i64)?,
    ];
    let dst_words = [
        ctx.load::<u32>(ETH_HDR_LEN + 24).map_err(|_| -1i64)?,
        ctx.load::<u32>(ETH_HDR_LEN + 28).map_err(|_| -1i64)?,
        ctx.load::<u32>(ETH_HDR_LEN + 32).map_err(|_| -1i64)?,
        ctx.load::<u32>(ETH_HDR_LEN + 36).map_err(|_| -1i64)?,
    ];

    let src_port_be: u16 = ctx.load(ETH_HDR_LEN + 40).map_err(|_| -1i64)?;
    let dst_port_be: u16 = ctx.load(ETH_HDR_LEN + 40 + 2).map_err(|_| -1i64)?;
    let dst_port = u16::from_be(dst_port_be);

    if is_already_owned_by_the_relay(skb_mark(ctx), dst_port, config) {
        return Ok(TC_ACT_OK);
    }

    let dst_key = CidrKey6 { addr: dst_words };
    match unsafe { FERRUM_POD_IPS6.get(&dst_key) } {
        Some(info) if info.inbound_redirect_enabled() => {}
        _ => return Ok(TC_ACT_OK),
    }
    if unsafe { FERRUM_POD_INBOUND_PORTS6.get(&InboundRedirectKey6::new(dst_words, dst_port)) }
        .is_none()
    {
        return Ok(TC_ACT_OK);
    }

    let mut tuple: bpf_sock_tuple = unsafe { mem::zeroed() };
    tuple.__bindgen_anon_1.ipv6.saddr = src_words;
    tuple.__bindgen_anon_1.ipv6.daddr = dst_words;
    tuple.__bindgen_anon_1.ipv6.sport = src_port_be;
    tuple.__bindgen_anon_1.ipv6.dport = dst_port_be;

    let established = lookup_socket(ctx, &mut tuple, tuple_len_v6());
    if !established.is_null() {
        if unsafe { (*established).state } != BPF_TCP_LISTEN {
            return Ok(assign_and_release(ctx, established, config));
        }
        unsafe {
            bpf_sk_release(established as *mut _);
        }
    }

    let mut listen_tuple: bpf_sock_tuple = unsafe { mem::zeroed() };
    listen_tuple.__bindgen_anon_1.ipv6.saddr = [0u32; 4];
    listen_tuple.__bindgen_anon_1.ipv6.daddr = [0u32; 4];
    listen_tuple.__bindgen_anon_1.ipv6.sport = 0;
    listen_tuple.__bindgen_anon_1.ipv6.dport = config.relay_port.to_be();

    let listener = lookup_socket(ctx, &mut listen_tuple, tuple_len_v6());
    Ok(assign_listener_or_drop(ctx, listener, config))
}

/// Socket lookup in the **current** network namespace. The tc hook runs in the
/// host netns where the NodeWaypoint relay listens, so `BPF_F_CURRENT_NETNS`
/// scopes the lookup to exactly the relay this node owns — never a socket in a
/// pod netns.
#[inline(always)]
fn lookup_socket(
    ctx: &TcContext,
    tuple: *mut bpf_sock_tuple,
    tuple_len: u32,
) -> *mut aya_ebpf::bindings::bpf_sock {
    unsafe {
        bpf_skc_lookup_tcp(
            ctx.skb.skb as *mut _,
            tuple,
            tuple_len,
            BPF_F_CURRENT_NETNS as i64 as u64,
            0,
        )
    }
}

/// Assign a resolved socket to the skb and stamp the local-delivery mark.
///
/// The reference is always released, on both the success and failure paths, so
/// the verifier's reference-leak check is satisfied on every branch. An assign
/// failure is fail-closed (`TC_ACT_SHOT`): the packet was already determined to
/// be in scope, so delivering it to the pod would be a silent policy bypass.
#[inline(always)]
fn assign_and_release(
    ctx: &mut TcContext,
    sk: *mut aya_ebpf::bindings::bpf_sock,
    config: &RedirectConfig,
) -> i32 {
    let assigned = unsafe { bpf_sk_assign(ctx.skb.skb as *mut _, sk as *mut _, 0) };
    unsafe {
        bpf_sk_release(sk as *mut _);
    }
    if assigned != 0 {
        return TC_ACT_SHOT;
    }
    // Stamped last so the mark is only ever visible on a packet that really
    // carries an assigned socket; the node-agent's `ip rule` keys on it to
    // deliver locally instead of forwarding to the pod.
    ctx.set_mark(config.redirect_mark);
    TC_ACT_OK
}

/// Assign the relay's **listening** socket, or drop.
///
/// A null lookup (relay not listening yet, or listening on a different port
/// than the capture config claims) and a non-listening result are both hard
/// failures for an in-scope packet: there is no safe way to deliver it.
#[inline(always)]
fn assign_listener_or_drop(
    ctx: &mut TcContext,
    listener: *mut aya_ebpf::bindings::bpf_sock,
    config: &RedirectConfig,
) -> i32 {
    if listener.is_null() {
        return TC_ACT_SHOT;
    }
    if unsafe { (*listener).state } != BPF_TCP_LISTEN {
        unsafe {
            bpf_sk_release(listener as *mut _);
        }
        return TC_ACT_SHOT;
    }
    assign_and_release(ctx, listener, config)
}

#[inline(always)]
fn skb_mark(ctx: &TcContext) -> u32 {
    unsafe { (*ctx.skb.skb).mark }
}
