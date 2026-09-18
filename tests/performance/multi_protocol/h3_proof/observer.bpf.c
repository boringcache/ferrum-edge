// SPDX-License-Identifier: GPL-2.0
// No payload, packet header, address, program instruction or kernel pointer export.
#include <linux/bpf.h>
#include "core_types.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "contract.h"

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
    __type(key, __u32); __type(value, struct config);
} config SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 512);
    __type(key, struct key); __type(value, struct value);
} counts SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, LOSS_MAX);
    __type(key, __u32); __type(value, __u64);
} losses SEC(".maps");

static __always_inline void loss(__u32 n)
{
    __u64 *v = bpf_map_lookup_elem(&losses, &n);
    if (v) __sync_fetch_and_add(v, 1);
}

static __always_inline __u64 identity(struct sock *sk)
{
    __u32 zero = 0, ns = 0;
    __u64 cookie = 0;
    struct net *net = 0;
    struct config *c = bpf_map_lookup_elem(&config, &zero);
    if (!sk || !c) return 0;
    if (BPF_CORE_READ_INTO(&net, sk, __sk_common.skc_net.net) ||
        BPF_CORE_READ_INTO(&ns, net, ns.inum)) {
        loss(READ_FAILED); return 0;
    }
    if (ns != c->netns) return 0;
    // sk_cookie is a kernel C macro, not a BTF member of struct sock.
    if (BPF_CORE_READ_INTO(&cookie, sk, __sk_common.skc_cookie.counter)) {
        loss(READ_FAILED); return 0;
    }
    // SO_COOKIE in the fixture assigns it before any traffic. Never join zero.
    if (!cookie) loss(UNKNOWN_COOKIE);
    return cookie;
}

static __always_inline void record(struct key *key)
{
    struct value *v, initial = {};
    __u64 now = bpf_ktime_get_ns();
    key->cpu = bpf_get_smp_processor_id(); // CPU, never a receiving worker ID.
    loss(ATTEMPTS);
    v = bpf_map_lookup_elem(&counts, key);
    if (!v) {
        initial.first_ns = now;
        bpf_map_update_elem(&counts, key, &initial, BPF_NOEXIST);
        v = bpf_map_lookup_elem(&counts, key);
    }
    if (!v) { loss(MAP_FULL); return; }
    __sync_fetch_and_add(&v->count, 1);
    v->last_ns = now;
    loss(RECORDED);
}

struct tx { __u64 cookie; __u32 length, segment, seen, flags, depth; };
struct {
    __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 64);
    __type(key, __u64); __type(value, struct tx);
} tx_pending SEC(".maps");

SEC("fentry/udp_sendmsg") int t_enter(__u64 *ctx)
{
    __u64 tid = bpf_get_current_pid_tgid();
    struct tx t = {.cookie = identity((void *)ctx[0]), .length = ctx[2]};
    if (!t.cookie) return 0;
    if (BPF_CORE_READ_INTO(&t.flags, (struct msghdr *)ctx[1], msg_flags)) {
        loss(READ_FAILED); return 0;
    }
    struct tx *previous = bpf_map_lookup_elem(&tx_pending, &tid);
    if (previous) { loss(NESTED); previous->depth++; previous->flags |= 0x8000; return 0; }
    if (bpf_map_update_elem(&tx_pending, &tid, &t, BPF_NOEXIST)) loss(MAP_FULL);
    return 0;
}

// The effective segment size after socket defaults and u16 UDP_SEGMENT cmsg
// validation, in the actual IPv4 submission path. Missing/inlined site => unsupported.
SEC("fentry/udp_send_skb") int t_effective(__u64 *ctx)
{
    __u64 tid = bpf_get_current_pid_tgid();
    struct tx *t = bpf_map_lookup_elem(&tx_pending, &tid);
    struct sock *sk = 0;
    __u16 segment = 0;
    if (!t) return 0;
    if (BPF_CORE_READ_INTO(&sk, (struct sk_buff *)ctx[0], sk) ||
        BPF_CORE_READ_INTO(&segment, (struct inet_cork *)ctx[2], gso_size)) {
        loss(READ_FAILED); return 0;
    }
    if (identity(sk) != t->cookie) { loss(UNMATCHED); return 0; }
    t->segment = segment;
    t->seen++;
    return 0;
}

SEC("fexit/udp_sendmsg") int t_exit(__u64 *ctx)
{
    __u64 tid = bpf_get_current_pid_tgid();
    struct tx *t = bpf_map_lookup_elem(&tx_pending, &tid);
    if (!t) return 0;
    if (t->depth) { t->depth--; return 0; }
    struct key k = {.cookie = t->cookie, .length = t->length,
                    .segment = t->segment, .result = (int)ctx[3]};
    if (k.result < 0) k.kind = TX_ERROR;
    else if (k.result != t->length || t->seen != 1 || (t->flags & 0x8000))
        k.kind = TX_UNCOVERED; // partial result, cork/MSG_MORE, nested submission
    else k.kind = t->segment && t->length > t->segment ? TX_GSO : TX_ORDINARY;
    record(&k);
    bpf_map_delete_elem(&tx_pending, &tid);
    return 0;
}

// Native Linux amd64 only. Loader checks sizeof(struct msghdr) and target arch.
// Read only ABI metadata and the allowlisted native-int UDP_GRO value.
struct user_msg {
    __u64 name; __u32 namelen, pad;
    __u64 iov, iovlen, control, controllen;
    __u32 flags, pad2;
};
struct user_cmsg { __u64 length; int level, type; };
struct enter { __u64 common; long id; __u64 args[6]; };
struct leave { __u64 common; long id; long ret; };
struct rx { __u64 hdr, control, capacity, cookie; __u32 flags; };
struct {
    __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 64);
    __type(key, __u64); __type(value, struct rx);
} rx_pending SEC(".maps");

// Namespace filtering here prevents collecting unrelated process metadata.
static __always_inline int local_task(void)
{
    __u32 zero = 0, ns = 0;
    struct config *c = bpf_map_lookup_elem(&config, &zero);
    struct task_struct *task = (void *)bpf_get_current_task();
    if (!c) return 0;
    if (BPF_CORE_READ_INTO(&ns, task, nsproxy, net_ns, ns.inum)) {
        loss(READ_FAILED); return 0;
    }
    return ns == c->netns;
}

SEC("tp/syscalls/sys_enter_recvmsg") int r_enter(struct enter *ctx)
{
    __u64 tid = bpf_get_current_pid_tgid();
    struct rx r = {.hdr = ctx->args[1], .flags = ctx->args[2]};
    struct user_msg h = {};
    if (!local_task()) return 0;
    if (bpf_probe_read_user(&h, sizeof(h), (void *)r.hdr)) {
        loss(READ_FAILED); return 0;
    }
    r.control = h.control; r.capacity = h.controllen;
    if (bpf_map_lookup_elem(&rx_pending, &tid)) { loss(NESTED); return 0; }
    if (bpf_map_update_elem(&rx_pending, &tid, &r, BPF_NOEXIST)) loss(MAP_FULL);
    return 0;
}

SEC("fentry/udp_recvmsg") int r_socket(__u64 *ctx)
{
    __u64 cookie = identity((void *)ctx[0]);
    __u64 tid = bpf_get_current_pid_tgid();
    struct rx *r;
    if (!cookie) return 0;
    r = bpf_map_lookup_elem(&rx_pending, &tid);
    if (!r) { loss(EXCLUDED_API); return 0; } // recvfrom/read/recvmmsg not claimed
    r->cookie = cookie;
    return 0;
}

SEC("tp/syscalls/sys_exit_recvmsg") int r_exit(struct leave *ctx)
{
    __u64 tid = bpf_get_current_pid_tgid(), offset = 0;
    struct rx *r = bpf_map_lookup_elem(&rx_pending, &tid);
    struct user_msg h = {};
    struct key k = {.result = ctx->ret};
    if (!r) return 0;
    if (!r->cookie) goto done;
    k.cookie = r->cookie;
    if (ctx->ret < 0) { k.kind = RX_ERROR; goto emit; }
    k.length = ctx->ret;
    if (bpf_probe_read_user(&h, sizeof(h), (void *)r->hdr)) goto unreadable;
    if (h.control != r->control || h.controllen > r->capacity || h.controllen > 256)
        goto unreadable;
    if (h.flags & (8 | 32)) { k.kind = RX_TRUNCATED; goto emit; }
    if (r->flags & 2) { k.kind = RX_PEEK; goto emit; }
    k.kind = RX_ORDINARY;
    // At most eight control headers, never payload, addresses or other cmsg values.
    for (int i = 0; i < 8; i++) {
        struct user_cmsg c = {};
        int segment = 0;
        if (offset == h.controllen) break;
        if (offset + sizeof(c) > h.controllen) goto unreadable;
        if (bpf_probe_read_user(&c, sizeof(c), (void *)(h.control + offset)))
            goto unreadable;
        if (c.length < sizeof(c) || c.length > h.controllen - offset)
            goto unreadable;
        if (c.level == 17 && c.type == 104) {
            if (c.length != sizeof(c) + sizeof(int) || k.segment) goto unreadable;
            if (bpf_probe_read_user(&segment, sizeof(segment),
                                    (void *)(h.control + offset + sizeof(c))))
                goto unreadable;
            if (segment <= 0 || segment > 65535) goto unreadable;
            k.segment = segment;
        }
        offset += (c.length + 7) & ~7ULL;
        if (offset > h.controllen && offset - h.controllen < 8) offset = h.controllen;
    }
    if (offset != h.controllen) goto unreadable;
    if (k.segment && k.length > k.segment) k.kind = RX_GRO;
emit:
    record(&k);
    goto done;
unreadable:
    loss(READ_FAILED);
done:
    bpf_map_delete_elem(&rx_pending, &tid);
    return 0;
}

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, 1);
    __type(key, __u32); __type(value, struct selection);
} selection SEC(".maps");

SEC("fentry/reuseport_select_sock") int c_enter(__u64 *ctx)
{
    __u32 zero = 0;
    struct selection *s = bpf_map_lookup_elem(&selection, &zero);
    __u64 cookie = identity((void *)ctx[0]);
    if (!s || !cookie) return 0;
    if (s->active) { loss(NESTED); s->active = 2; return 0; }
    s->anchor = cookie; s->inner = 0; s->selected = 0; s->active = 1;
    return 0;
}

SEC("fexit/run_bpf_filter") int c_filter(__u64 *ctx)
{
    __u32 zero = 0;
    struct selection *s = bpf_map_lookup_elem(&selection, &zero);
    struct sock *first = 0;
    struct key k = {};
    if (!s || s->active != 1) return 0;
    if (BPF_CORE_READ_INTO(&first, (struct sock_reuseport *)ctx[0], socks[0])) {
        loss(READ_FAILED); return 0;
    }
    // The lookup socket can be ANY member, so do not compare it to slot zero.
    k.cookie = identity(first);
    if (!k.cookie) return 0;
    k.peer = identity((void *)ctx[5]);
    if (ctx[5] && !k.peer) return 0;
    k.kind = k.peer ? CLASSIC_SELECTED : CLASSIC_NULL;
    s->inner = 1; s->selected = k.peer;
    record(&k);
    return 0;
}

SEC("fexit/reuseport_select_sock") int c_exit(__u64 *ctx)
{
    __u32 zero = 0;
    struct selection *s = bpf_map_lookup_elem(&selection, &zero);
    if (!s || !s->active) return 0;
    if (identity((void *)ctx[0]) != s->anchor) return 0;
    if (s->active == 1 && s->inner) {
        struct key k = {.cookie = s->anchor, .peer = identity((void *)ctx[4]),
                        .kind = s->selected ? SELECTOR_SELECTED : SELECTOR_FALLBACK};
        record(&k);
    } else loss(UNMATCHED);
    s->active = 0;
    return 0;
}

SEC("fexit/reuseport_attach_prog") int c_attach(__u64 *ctx)
{
    struct key k = {.cookie = identity((void *)ctx[0]), .result = (int)ctx[2]};
    if (!k.cookie) return 0;
    k.kind = k.result == 0 ? ATTACH_OK : ATTACH_ERROR;
    record(&k);
    return 0;
}
char LICENSE[] SEC("license") = "GPL";
