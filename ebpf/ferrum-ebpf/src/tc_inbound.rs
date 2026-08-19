//! tc ingress/egress — direct-pod guard for enrolled destination pods.
//!
//! Attached to the host-side veth interface of enrolled pods. Parses each
//! IPv4/IPv6 packet and checks whether the destination IP is enrolled in
//! `FERRUM_POD_IPS` / `FERRUM_POD_IPS6`. Direct TCP connection attempts to
//! enrolled pod IPs are dropped unless they come from an explicitly trusted
//! local-node source and carry the NodeWaypoint relay's authorized socket
//! mark; non-initial TCP packets are allowed so replies for
//! intentionally bypassed outbound flows can return to the pod. Direct UDP is
//! failed closed for NodeWaypoint except the relay's own datagrams and DNS
//! responses from source port 53 to high pod-originated client ports (>=32768).
//!
//! # Why UDP relay admission needs a sender proof (issues #3956, #3957)
//!
//! The TCP arm admits `configured node source + relay socket mark`. Both of
//! those are attributes of a packet, and under this datapath's threat model —
//! a same-node workload in the HOST network namespace holding only
//! SOCKET-level privilege (`CAP_NET_RAW` suffices for `IP_TRANSPARENT`, and
//! for `SO_MARK` since Linux 5.17; `CAP_NET_ADMIN` grants both on any kernel) —
//! both are attacker-chosen: `SO_MARK` sets the mark, and binding a node-local
//! address (or `IP_TRANSPARENT` plus any address at all) sets the source. The
//! same is true of an exact `(source address, source port)` reply-source claim:
//! it names an address the attacker can equally well bind, and because the map
//! is listener-wide it replays against ANY enrolled destination. So neither a
//! node source nor a reply-source tuple is an authorization on its own, and
//! neither is their disjunction — swapping one forgeable lane for the other
//! moves the bypass, it does not close it.
//!
//! Every UDP admission here therefore requires a proof the packet's emitter
//! cannot choose: `bpf_skb_cgroup_id()`, the cgroup-v2 id of the SOCKET that
//! generated the skb, matched against `FERRUM_UDP_RELAY_CGROUPS` — the
//! node-agent's host-side rendering of the NodeWaypoint relay pod's own cgroup
//! subtree. The kernel records that cgroup at socket creation from the creating
//! task, so presenting it means already running inside the waypoint's cgroup.
//! Zero (no socket on the skb: forwarded traffic, another netns, the tc INGRESS
//! hook) denies, as does a closed gate or an absent entry.
//!
//! On top of that sender proof the two ORIGINAL source lanes are kept, because
//! they still narrow what the relay itself may do and the relay needs both: its
//! BACKEND dial leaves from a configured node address, while its REPLY is not
//! route-selected but source-PINNED to the local address the client addressed —
//! on the Service path the Service ClusterIP, which is never a node IP — and is
//! admitted only by an exact, live `(address, port)` entry in
//! `FERRUM_UDP_REPLY_SOURCES` / `FERRUM_UDP_REPLY_SOURCES6`. Admission is thus
//! `relay cgroup AND relay mark AND (node source OR exact reply source)`; the
//! disjunction is between two narrowing statements about the trusted sender,
//! never between two ways of being trusted.
//!
//! The relay auth mark is still required in every case, and TCP semantics are
//! byte-for-byte unchanged: explicitly configured local node source IPs bypass
//! the TCP guard with the relay mark, or for enrolled Kubernetes probe ports
//! without it, and the TCP arm reads none of the three UDP maps.
//!
//! # What this guard does NOT claim (issue #4021)
//!
//! The threat model above is stated at SOCKET-level privilege deliberately:
//! that is the strongest claim which holds on every kernel this loader
//! supports, and it is exactly what the live forger pod exercises. An attacker
//! who ALSO holds `CAP_NET_ADMIN` in the host netns gains no way to forge a
//! cgroup id — the kernel stamps it at socket creation from the creating task
//! — but where this classifier is attached through the legacy `clsact` qdisc
//! rather than TCX, that attacker can `tc qdisc del dev <pod veth> clsact` and
//! remove the guard outright, which needs no forgery at all. `attach_tc`
//! (`src/ebpf/loader.rs`) calls aya's `SchedClassifier::attach`, which uses a
//! TCX link on kernel >= 6.6 and falls back to netlink/`clsact` below it; on
//! the TCX path a `CAP_NET_ADMIN`-only attacker cannot preempt this program,
//! because loading a competing one requires `CAP_BPF`. So: cgroup-id forgery
//! is refused on every supported kernel, while guard REMOVAL by a
//! `CAP_NET_ADMIN` host-netns workload is out of scope below kernel 6.6.
//!
//! The same classifier closes Ambient UDP enrollment: pod-IP metadata is
//! inserted with UDP-not-ready before registry publication, so pod-originated
//! UDP is dropped until the per-netns producer publishes readiness after its
//! TPROXY socket and rules are live.

use aya_ebpf::bindings::{TC_ACT_OK, TC_ACT_PIPE, TC_ACT_SHOT};
use aya_ebpf::helpers::bpf_skb_cgroup_id;
use aya_ebpf::macros::classifier;
use aya_ebpf::programs::TcContext;
use ferrum_ebpf_common::{
    CidrKey6, NodeProbePortKey4, NodeProbePortKey6, UdpReplySourceKey4, UdpReplySourceKey6,
    FERRUM_CAPTURE_CONFIG_KEY, UDP_REPLY_SOURCE_GATE_ENABLED, UDP_REPLY_SOURCE_GATE_KEY,
};

use crate::maps::{
    FERRUM_CAPTURE_CONFIG, FERRUM_NODE_IPS, FERRUM_NODE_IPS6, FERRUM_NODE_PROBE_PORTS,
    FERRUM_NODE_PROBE_PORTS6, FERRUM_POD_IPS, FERRUM_POD_IPS6, FERRUM_UDP_RELAY_CGROUPS,
    FERRUM_UDP_REPLY_SOURCES, FERRUM_UDP_REPLY_SOURCES6, FERRUM_UDP_REPLY_SOURCE_GATE,
};

const ETH_HDR_LEN: usize = 14;
const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_FRAGMENT: u8 = 44;
const IPPROTO_ESP: u8 = 50;
const IPPROTO_AH: u8 = 51;
const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_ACK: u8 = 0x10;
const DNS_PORT: u16 = 53;
const MIN_DNS_CLIENT_PORT: u16 = 32768;

#[classifier]
pub fn ferrum_tc_inbound(ctx: TcContext) -> i32 {
    match try_tc_inbound(&ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_OK,
    }
}

#[inline(always)]
fn try_tc_inbound(ctx: &TcContext) -> Result<i32, i64> {
    let eth_type: u16 = ctx.load(12).map_err(|_| -1i64)?;
    match u16::from_be(eth_type) {
        ETH_P_IP => guard_ipv4(ctx),
        ETH_P_IPV6 => guard_ipv6(ctx),
        _ => Ok(TC_ACT_OK),
    }
}

#[inline(always)]
fn guard_ipv4(ctx: &TcContext) -> Result<i32, i64> {
    // Load `protocol` first and keep the pod-source UDP not-ready SHOT check
    // ahead of the `dst` early-return (pod→external UDP must stay droppable
    // during the enrollment window). Defer the `src_ip` load into the UDP arm so
    // the common non-pod-destined TCP packet early-returns after a single
    // `dst_ip` load — as it did before the readiness guard was added — instead
    // of paying an unconditional source-IP load on every classified packet.
    let protocol: u8 = ctx.load(ETH_HDR_LEN + 9).map_err(|_| -1i64)?;
    if protocol == IPPROTO_UDP {
        let src_ip: u32 = ctx.load(ETH_HDR_LEN + 12).map_err(|_| -1i64)?;
        if matches!(
            unsafe { FERRUM_POD_IPS.get(&src_ip) },
            Some(info) if info.udp_capture_not_ready()
        ) {
            return Ok(TC_ACT_SHOT);
        }
    }

    let dst_ip: u32 = ctx.load(ETH_HDR_LEN + 16).map_err(|_| -1i64)?;
    if unsafe { FERRUM_POD_IPS.get(&dst_ip) }.is_none() {
        return Ok(TC_ACT_OK);
    }

    // Reaching here means the destination is enrolled; the source IP is needed
    // for TCP's node-source check and UDP's exact reply-source lookup below.
    let src_ip: u32 = ctx.load(ETH_HDR_LEN + 12).map_err(|_| -1i64)?;
    let source_is_node = unsafe { FERRUM_NODE_IPS.get(&src_ip) }.is_some();
    match protocol {
        IPPROTO_TCP => {
            let (dst_port, flags) = match tcp_dst_port_and_flags4(ctx) {
                Ok(parsed) => parsed,
                Err(_) => return guard_enrolled_destination(ctx, source_is_node),
            };
            if source_is_node && node_probe_port4_allowed(dst_ip, dst_port) {
                return Ok(TC_ACT_OK);
            }
            if enrolled_destination_authorized(ctx, source_is_node) {
                return Ok(TC_ACT_PIPE);
            }
            if !tcp_initial_syn(flags) {
                return Ok(TC_ACT_OK);
            }
            guard_enrolled_destination(ctx, source_is_node)
        }
        IPPROTO_UDP => {
            // The NodeWaypoint's own UDP relay (issue #3286) is admitted by
            // THREE conjoined proofs, checked BEFORE the DNS carve-out so a
            // relay datagram never depends on port heuristics.
            //
            // 1. The SENDER: `bpf_skb_cgroup_id()` must name the relay pod's
            //    own cgroup. This is the only one of the three the emitter
            //    cannot choose, so it is evaluated first and gates both source
            //    lanes below — without it a `CAP_NET_ADMIN` host-netns workload
            //    forges its way in through either lane (issues #3956, #3957).
            // 2. The MARK: `node_waypoint_inbound_auth_mark`, the same socket
            //    mark proof the TCP arm uses, inside
            //    `enrolled_destination_authorized`.
            // 3. The SOURCE, narrowing what the trusted relay may claim: the
            //    backend dial leaves from a configured node address, exactly
            //    like the TCP relay; the reply does not — it is source-PINNED
            //    to the local address the client addressed, which on the
            //    Service path is the Service ClusterIP, so it is admitted only
            //    by an exact, live `(address, port)` reply-source authorization
            //    the serving listener published.
            //
            // The two source proofs stay on separate arms.
            // `source_is_node || reply_source_authorized` is two map-lookup
            // `.is_some()` results; LLVM lowers that as `pointer |= pointer`,
            // which the kernel verifier rejects. Each helper below collapses
            // its own lookup to a `bool` before returning for the same reason.
            //
            // UDP ports are parsed ONLY after `udp_relay_sender_authorized`
            // returns. Binding a `Result`/port value across `bpf_skb_cgroup_id`
            // lets LLVM keep that state live on the helper-zero path; the
            // kernel verifier then rejects the classifier (`R9 !read_ok`).
            // The node-source lane needs no ports. The reply-source lane and
            // the DNS carve-out each parse after the helper has returned.
            if udp_relay_sender_authorized(ctx) {
                if enrolled_destination_authorized(ctx, source_is_node) {
                    return Ok(TC_ACT_PIPE);
                }
                if let Ok((src_port, _)) = udp_ports4(ctx) {
                    if enrolled_destination_authorized(
                        ctx,
                        udp_reply_source4_allowed(src_ip, src_port),
                    ) {
                        return Ok(TC_ACT_PIPE);
                    }
                }
            }
            match udp_ports4(ctx) {
                Ok((src_port, dst_port)) if dns_response_allowed(src_port, dst_port) => {
                    Ok(TC_ACT_OK)
                }
                _ => drop_unsupported_enrolled_destination(),
            }
        }
        _ => Ok(TC_ACT_OK),
    }
}

#[inline(always)]
fn guard_ipv6(ctx: &TcContext) -> Result<i32, i64> {
    let src_ip = CidrKey6 {
        addr: [
            ctx.load(ETH_HDR_LEN + 8).map_err(|_| -1i64)?,
            ctx.load(ETH_HDR_LEN + 12).map_err(|_| -1i64)?,
            ctx.load(ETH_HDR_LEN + 16).map_err(|_| -1i64)?,
            ctx.load(ETH_HDR_LEN + 20).map_err(|_| -1i64)?,
        ],
    };
    let next_header: u8 = ctx.load(ETH_HDR_LEN + 6).map_err(|_| -1i64)?;
    // Resolve bounded IPv6 extension chains before applying the source-side
    // UDP readiness gate. Treating any first extension header as UDP would
    // black-hole valid TCP/ICMPv6 with Hop-by-Hop/Routing/Destination Options;
    // a malformed or overlong chain still fails closed for a not-ready source.
    let source_is_udp = match ipv6_transport_protocol(ctx, next_header) {
        Ok(protocol) => protocol == IPPROTO_UDP,
        Err(_) => true,
    };
    if source_is_udp
        && matches!(
            unsafe { FERRUM_POD_IPS6.get(&src_ip) },
            Some(info) if info.udp_capture_not_ready()
        )
    {
        return Ok(TC_ACT_SHOT);
    }

    let dst_ip = CidrKey6 {
        addr: [
            ctx.load(ETH_HDR_LEN + 24).map_err(|_| -1i64)?,
            ctx.load(ETH_HDR_LEN + 28).map_err(|_| -1i64)?,
            ctx.load(ETH_HDR_LEN + 32).map_err(|_| -1i64)?,
            ctx.load(ETH_HDR_LEN + 36).map_err(|_| -1i64)?,
        ],
    };

    if unsafe { FERRUM_POD_IPS6.get(&dst_ip) }.is_none() {
        return Ok(TC_ACT_OK);
    }

    let source_is_node = unsafe { FERRUM_NODE_IPS6.get(&src_ip) }.is_some();
    match next_header {
        IPPROTO_TCP => {
            let (dst_port, flags) = match tcp_dst_port_and_flags6(ctx) {
                Ok(parsed) => parsed,
                Err(_) => return guard_enrolled_destination(ctx, source_is_node),
            };
            if source_is_node && node_probe_port6_allowed(dst_ip.addr, dst_port) {
                return Ok(TC_ACT_OK);
            }
            if enrolled_destination_authorized(ctx, source_is_node) {
                return Ok(TC_ACT_PIPE);
            }
            if !tcp_initial_syn(flags) {
                return Ok(TC_ACT_OK);
            }
            guard_enrolled_destination(ctx, source_is_node)
        }
        IPPROTO_UDP => {
            // IPv6 mirror of the v4 arm, at exact parity: the same
            // non-forgeable relay-cgroup sender proof gates the same two source
            // lanes under the same mark. The sender proof is family-agnostic —
            // one socket, one cgroup — so a dual-stack waypoint cannot end up
            // trusted on one family and forgeable on the other, and a waypoint
            // that admitted only one family would black-hole the other. Same
            // separate-arm source proofs as IPv4; do not reintroduce `||`.
            // Same verifier-safe port ordering as IPv4: no UDP-port Result is
            // live across `bpf_skb_cgroup_id`.
            if udp_relay_sender_authorized(ctx) {
                if enrolled_destination_authorized(ctx, source_is_node) {
                    return Ok(TC_ACT_PIPE);
                }
                if let Ok((src_port, _)) = udp_ports6(ctx) {
                    if enrolled_destination_authorized(
                        ctx,
                        udp_reply_source6_allowed(src_ip.addr, src_port),
                    ) {
                        return Ok(TC_ACT_PIPE);
                    }
                }
            }
            match udp_ports6(ctx) {
                Ok((src_port, dst_port)) if dns_response_allowed(src_port, dst_port) => {
                    Ok(TC_ACT_OK)
                }
                _ => drop_unsupported_enrolled_destination(),
            }
        }
        header if ipv6_extension_header(header) => drop_unsupported_enrolled_destination(),
        _ => Ok(TC_ACT_OK),
    }
}

#[inline(always)]
fn guard_enrolled_destination(ctx: &TcContext, source_is_node: bool) -> Result<i32, i64> {
    let Some(config) = (unsafe { FERRUM_CAPTURE_CONFIG.get(&FERRUM_CAPTURE_CONFIG_KEY) }) else {
        return Ok(TC_ACT_SHOT);
    };
    if config.node_waypoint_inbound_auth_mark == 0 {
        return Ok(TC_ACT_OK);
    }
    if source_is_node && skb_mark(ctx) == config.node_waypoint_inbound_auth_mark {
        return Ok(TC_ACT_PIPE);
    }
    Ok(TC_ACT_SHOT)
}

/// Two-part admission for a packet to an enrolled pod: the NodeWaypoint relay's
/// socket mark AND an authorized source.
///
/// `source_authorized` is ONE source-side proof. TCP passes exactly
/// `source_is_node` (unchanged). The UDP arms call this twice on separate
/// arms — first the node-source lookup, then an exact live reply-source
/// authorization — because combining those `.is_some()` results with `||`
/// is lowered as `pointer |= pointer`. Neither half admits anything on
/// its own. Unparseable UDP ports skip the reply-source attempt (no
/// authorization), matching the prior fail-closed parse-miss.
///
/// On the UDP arms this is reached ONLY inside a successful
/// [`udp_relay_sender_authorized`] check, so the mark and the source there are
/// narrowing statements about an already-proven sender rather than the
/// authorization itself. Do not hoist a UDP call out of that guard.
#[inline(always)]
fn enrolled_destination_authorized(ctx: &TcContext, source_authorized: bool) -> bool {
    if !source_authorized {
        return false;
    }
    let Some(config) = (unsafe { FERRUM_CAPTURE_CONFIG.get(&FERRUM_CAPTURE_CONFIG_KEY) }) else {
        return false;
    };
    config.node_waypoint_inbound_auth_mark != 0
        && skb_mark(ctx) == config.node_waypoint_inbound_auth_mark
}

#[inline(always)]
fn drop_unsupported_enrolled_destination() -> Result<i32, i64> {
    let Some(config) = (unsafe { FERRUM_CAPTURE_CONFIG.get(&FERRUM_CAPTURE_CONFIG_KEY) }) else {
        return Ok(TC_ACT_SHOT);
    };
    if config.node_waypoint_inbound_auth_mark == 0 {
        return Ok(TC_ACT_OK);
    }
    Ok(TC_ACT_SHOT)
}

#[inline(always)]
fn node_probe_port4_allowed(dst_ip: u32, port: u16) -> bool {
    let key = NodeProbePortKey4::new(dst_ip, port);
    unsafe { FERRUM_NODE_PROBE_PORTS.get(&key) }.is_some()
}

#[inline(always)]
fn node_probe_port6_allowed(dst_ip: [u32; 4], port: u16) -> bool {
    let key = NodeProbePortKey6::new(dst_ip, port);
    unsafe { FERRUM_NODE_PROBE_PORTS6.get(&key) }.is_some()
}

/// The non-forgeable half of UDP relay admission: did the NodeWaypoint relay
/// itself emit this datagram?
///
/// `bpf_skb_cgroup_id()` returns the cgroup-v2 id of the socket attached to the
/// skb — recorded by the kernel when that socket was created, from the creating
/// task's own cgroup. It is not a header field, it is not settable through any
/// socket option, and it cannot be rewritten in flight, so unlike the socket
/// mark and the source address it cannot be presented by a workload that is not
/// running inside the relay's cgroup.
///
/// Three ways this returns `false`, all fail-closed:
///
/// * the shared gate is closed, so no generation is coherently applied;
/// * the helper reports `0` — there is no socket on the skb. That is every
///   FORWARDED packet (another pod's, another node's: `skb_scrub_packet` drops
///   the socket when the skb crosses a network namespace) and every packet on
///   the tc INGRESS hook, where the socket has not been looked up yet. The
///   relay's own datagrams travel host-netns → pod, i.e. the EGRESS hook of the
///   enrolled pod's host-side veth, which is precisely where the socket is
///   still attached, so nothing legitimate is lost;
/// * the id is not in `FERRUM_UDP_RELAY_CGROUPS` — some other local process
///   sent it, including a `CAP_NET_ADMIN` host-netns workload that set the
///   relay mark and bound a node address or a Service ClusterIP.
///
/// The lookup collapses to a `bool` inside this function so no caller ever
/// combines two `PTR_TO_MAP_VALUE_OR_NULL` results with `&&`/`||`, which the
/// kernel verifier rejects.
#[inline(always)]
fn udp_relay_sender_authorized(ctx: &TcContext) -> bool {
    if !udp_reply_sources_enabled() {
        return false;
    }
    let cgroup_id = unsafe { bpf_skb_cgroup_id(ctx.skb.skb) };
    if cgroup_id == 0 {
        return false;
    }
    unsafe { FERRUM_UDP_RELAY_CGROUPS.get(&cgroup_id) }.is_some()
}

/// Exact IPv4 reply-source authorization lookup. Address AND port must both
/// match a live entry; there is no prefix, range, or port-blind form.
///
/// Reached only inside [`udp_relay_sender_authorized`]: on its own an entry
/// here is a listener-wide `(address, port)` tuple that any host-netns workload
/// could bind and replay against an arbitrary enrolled destination (#3957).
#[inline(always)]
fn udp_reply_source4_allowed(src_ip: u32, src_port: u16) -> bool {
    if !udp_reply_sources_enabled() {
        return false;
    }
    let key = UdpReplySourceKey4::new(src_ip, src_port);
    unsafe { FERRUM_UDP_REPLY_SOURCES.get(&key) }.is_some()
}

/// IPv6 counterpart to [`udp_reply_source4_allowed`], with the same
/// sender-proof precondition.
#[inline(always)]
fn udp_reply_source6_allowed(src_ip: [u32; 4], src_port: u16) -> bool {
    if !udp_reply_sources_enabled() {
        return false;
    }
    let key = UdpReplySourceKey6::new(src_ip, src_port);
    unsafe { FERRUM_UDP_REPLY_SOURCES6.get(&key) }.is_some()
}

/// The ONE shared generation gate for every UDP relay authorization map —
/// both reply-source families and `FERRUM_UDP_RELAY_CGROUPS`. Closed means no
/// coherent generation is applied, so the sender proof and the source proof are
/// both unavailable and every UDP relay lane is refused together.
#[inline(always)]
fn udp_reply_sources_enabled() -> bool {
    matches!(
        FERRUM_UDP_REPLY_SOURCE_GATE.get(UDP_REPLY_SOURCE_GATE_KEY),
        Some(value) if *value == UDP_REPLY_SOURCE_GATE_ENABLED
    )
}

#[inline(always)]
fn tcp_dst_port_and_flags4(ctx: &TcContext) -> Result<(u16, u8), i64> {
    let version_ihl: u8 = ctx.load(ETH_HDR_LEN).map_err(|_| -1i64)?;
    let ihl = ((version_ihl & 0x0f) as usize) * 4;
    if ihl < 20 {
        return Err(-1i64);
    }
    let port: u16 = ctx.load(ETH_HDR_LEN + ihl + 2).map_err(|_| -1i64)?;
    let flags: u8 = ctx.load(ETH_HDR_LEN + ihl + 13).map_err(|_| -1i64)?;
    Ok((u16::from_be(port), flags))
}

#[inline(always)]
fn tcp_dst_port_and_flags6(ctx: &TcContext) -> Result<(u16, u8), i64> {
    let port: u16 = ctx.load(ETH_HDR_LEN + 40 + 2).map_err(|_| -1i64)?;
    let flags: u8 = ctx.load(ETH_HDR_LEN + 40 + 13).map_err(|_| -1i64)?;
    Ok((u16::from_be(port), flags))
}

#[inline(always)]
fn udp_ports4(ctx: &TcContext) -> Result<(u16, u16), i64> {
    let version_ihl: u8 = ctx.load(ETH_HDR_LEN).map_err(|_| -1i64)?;
    let ihl = ((version_ihl & 0x0f) as usize) * 4;
    if ihl < 20 {
        return Err(-1i64);
    }
    let src_port: u16 = ctx.load(ETH_HDR_LEN + ihl).map_err(|_| -1i64)?;
    let dst_port: u16 = ctx.load(ETH_HDR_LEN + ihl + 2).map_err(|_| -1i64)?;
    Ok((u16::from_be(src_port), u16::from_be(dst_port)))
}

#[inline(always)]
fn udp_ports6(ctx: &TcContext) -> Result<(u16, u16), i64> {
    let src_port: u16 = ctx.load(ETH_HDR_LEN + 40).map_err(|_| -1i64)?;
    let dst_port: u16 = ctx.load(ETH_HDR_LEN + 40 + 2).map_err(|_| -1i64)?;
    Ok((u16::from_be(src_port), u16::from_be(dst_port)))
}

#[inline(always)]
fn dns_response_allowed(src_port: u16, dst_port: u16) -> bool {
    src_port == DNS_PORT && dst_port >= MIN_DNS_CLIENT_PORT
}

#[inline(always)]
fn tcp_initial_syn(flags: u8) -> bool {
    flags & TCP_FLAG_SYN != 0 && flags & TCP_FLAG_ACK == 0
}

#[inline(always)]
fn ipv6_extension_header(next_header: u8) -> bool {
    matches!(
        next_header,
        0 | 43 | 44 | 50 | 51 | 60 | 135 | 139 | 140 | 253 | 254
    )
}

/// Resolve the transport protocol behind a bounded IPv6 extension chain.
///
/// Six headers comfortably cover legitimate chains while keeping verifier
/// state bounded. ESP is opaque and is returned as non-UDP; malformed,
/// truncated, or still-extended chains return an error so the readiness caller
/// can fail closed without misclassifying valid extension-header TCP.
#[inline(always)]
fn ipv6_transport_protocol(ctx: &TcContext, first_header: u8) -> Result<u8, i64> {
    let mut protocol = first_header;
    let mut offset = ETH_HDR_LEN + 40;
    let mut parsed = 0u8;
    while parsed < 6 {
        match protocol {
            // Hop-by-Hop, Routing, Destination Options, Mobility, HIP, Shim6,
            // and the two experimental extension-header values share the
            // 8-octet-unit Hdr Ext Len shape.
            0 | 43 | 60 | 135 | 139 | 140 | 253 | 254 => {
                protocol = ctx.load(offset).map_err(|_| -1i64)?;
                let extension_len: u8 = ctx.load(offset + 1).map_err(|_| -1i64)?;
                offset += (extension_len as usize + 1) * 8;
            }
            IPPROTO_FRAGMENT => {
                protocol = ctx.load(offset).map_err(|_| -1i64)?;
                offset += 8;
            }
            IPPROTO_AH => {
                protocol = ctx.load(offset).map_err(|_| -1i64)?;
                let payload_len: u8 = ctx.load(offset + 1).map_err(|_| -1i64)?;
                offset += (payload_len as usize + 2) * 4;
            }
            IPPROTO_ESP => return Ok(IPPROTO_ESP),
            _ => return Ok(protocol),
        }
        parsed += 1;
    }
    if ipv6_extension_header(protocol) {
        Err(-1i64)
    } else {
        Ok(protocol)
    }
}

#[inline(always)]
fn skb_mark(ctx: &TcContext) -> u32 {
    unsafe { (*ctx.skb.skb).mark }
}
