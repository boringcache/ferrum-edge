// SPDX-License-Identifier: GPL-2.0
// Included by the shared object; h_* programs/maps are disabled in H3 modes.
#include "h1_contract.h"
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
    __type(key, __u32); __type(value, struct h1_config); } h_config SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, H1_CAPACITY);
    __type(key, struct h1_key); __type(value, struct h1_value); } h_counts SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1024);
    __type(key, __u32); __type(value, __u64); } h_census SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 512);
    __type(key, __u32); __type(value, struct h1_value); } h_totals SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, H_LOSS_MAX);
    __type(key, __u32); __type(value, __u64); } h_losses SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
    __type(key, __u32); __type(value, __u64); } h_sequence SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, H1_PENDING);
    __type(key, __u64); __type(value, struct h1_pending); } h_pending SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 512 * 1024); } h_events SEC(".maps");

static __always_inline void h_loss(__u32 n)
{
    __u64 *v = bpf_map_lookup_elem(&h_losses, &n);
    if (v) __sync_fetch_and_add(v, 1);
}
static __always_inline void h_add(__u64 *value, __u64 amount)
{
    __u64 previous = __sync_fetch_and_add(value, amount);
    if (amount > ~0ULL - previous) h_loss(H_OVERFLOW);
}
static __always_inline int h_owned(void)
{
    __u32 zero = 0;
    struct h1_config *c = bpf_map_lookup_elem(&h_config, &zero);
    __u64 pt = bpf_get_current_pid_tgid();
    if (!c || !c->pid || c->pid != pt >> 32) return 0;
    struct task_struct *task = (void *)bpf_get_current_task();
    __u64 ns = 0;
    if (BPF_CORE_READ_INTO(&ns, task, group_leader, start_boottime)) { h_loss(H_READ_FAILED); return 0; }
    // USER_HZ is admitted as 100 by the native amd64 supervisor/loader.
    if (c->hz != 100 || ns / 10000000ULL != c->start_ticks ||
        bpf_get_current_cgroup_id() != c->cgroup) { h_loss(H_GENERATION); return 0; }
    return 1;
}
static __always_inline int h_data(__u32 id)
{
    return id == 0 || id == 1 || id == 19 || id == 20 || id == 44 || id == 45 ||
           id == 46 || id == 47 || id == 299 || id == 307;
}
static __always_inline int h_life(__u32 id)
{
    return id == 3 || id == 32 || id == 33 || id == 41 || id == 42 || id == 43 ||
           id == 48 || id == 53 || id == 72 || id == 288 || id == 292 || id == 436 ||
           id == 272 || id == 438;
}
static __always_inline int h_unsupported(__u32 id)
{
    return id == 17 || id == 18 || id == 40 || id == 275 || id == 276 || id == 278 ||
           id == 295 || id == 296 || id == 327 || id == 328 || id == 425 || id == 426 || id == 427;
}
// Only read native length metadata; never iov_base, control, names or payload.
static __noinline int h_iov(__u64 pointer, __u64 count, __u64 *sum)
{
    if (count > H1_VECTOR) { h_loss(H_VECTOR_BOUND); return 0; }
    __u64 total = 0;
    for (__u32 i = 0; i < H1_VECTOR; i++) {
        if (i >= count) break;
        __u64 length = 0;
        if (bpf_probe_read_user(&length, 8, (void *)(pointer + i * 16 + 8))) {
            h_loss(H_READ_FAILED); return 0;
        }
        if (length > 0x7fffffffffffffffULL - total) { h_loss(H_OVERFLOW); return 0; }
        total += length;
    }
    *sum = total; return 1;
}
static __noinline int h_msg(__u64 pointer, __u64 *sum)
{
    struct { __u64 iov, count; } metadata = {};
    if (bpf_probe_read_user(&metadata, sizeof(metadata), (void *)(pointer + 16))) {
        h_loss(H_READ_FAILED); return 0;
    }
    return h_iov(metadata.iov, metadata.count, sum);
}
static __noinline void h_offer(struct h1_pending *p, __u64 ptr, __u64 length)
{
    __u32 id = p->key.id;
    p->known = 1;
    if (id == 19 || id == 20) p->known = h_iov(ptr, length, &p->offered);
    else if (id == 46 || id == 47) p->known = h_msg(ptr, &p->offered);
    else if (p->batch) {
        p->known = 0;
        if (length > H1_VECTOR) { h_loss(H_VECTOR_BOUND); return; }
        __u64 total = 0;
        for (__u32 i = 0; i < H1_VECTOR; i++) {
            if (i >= length) break;
            __u64 offered = 0;
            if (!h_msg(ptr + i * 64, &offered)) return;
            if (offered > 0x7fffffffffffffffULL - total) { h_loss(H_OVERFLOW); return; }
            total += offered;
        }
        p->known = 1; p->offered = total;
    } else p->offered = length;
}
static __always_inline void h_emit(struct h1_pending *p, __s64 ret, __u64 bytes, __u32 known, __u32 kind)
{
    // The stream is diagnostic witnesses, never the authoritative event total.
    // Its bounded omission is independent from aggregate-map loss.
    if (p->sequence >= H1_EVENTS && kind == 1) { h_loss(H_WITNESS_CAP); return; }
    struct h1_event *e = bpf_ringbuf_reserve(&h_events, sizeof(*e), 0);
    if (!e) { h_loss(H_RING_FULL); return; }
    __builtin_memset(e, 0, sizeof(*e));
    e->key = p->key; e->thread_ns = p->thread_ns; e->sequence = p->sequence;
    e->entered_ns = p->entered_ns; e->exited_ns = bpf_ktime_get_ns();
    e->offered = p->offered; e->accepted = bytes; e->effective = p->effective;
    e->inner_bytes = p->inner_bytes; e->inner_calls = p->inner_calls; e->inner_errors = p->inner_errors;
    e->result = ret; e->tid = (__u32)bpf_get_current_pid_tgid(); e->kind = kind;
    e->flags = p->flags; e->kernel_flags = p->kernel_flags; e->known = p->known; e->accepted_known = known;
    e->vlen = p->vlen; e->seen = p->seen; e->metadata_error = p->metadata_error; e->fd = p->fd;
    // Only lifecycle scalar flags/FDs; no syscall buffer addresses.
    e->arg1 = p->arg1; e->arg2 = p->arg2;
    bpf_ringbuf_submit(e, 0);
}
SEC("raw_tp/sys_enter") int h_enter(struct bpf_raw_tracepoint_args *ctx)
{
    if (!h_owned()) return 0;
    struct pt_regs *regs = (void *)ctx->args[0];
    __u64 id64 = ctx->args[1], cs = 0;
    if (BPF_CORE_READ_INTO(&cs, regs, cs)) { h_loss(H_READ_FAILED); return 0; }
    // Long-mode user CS plus no x32 bit; ia32 syscall numbers must never alias H1.
    if (cs != 0x33 || id64 >= 512) { h_loss(H_COMPAT); return 0; }
    __u32 id = id64;
    __u64 *count = bpf_map_lookup_elem(&h_census, &id);
    if (count) __sync_fetch_and_add(count, 1);
    if (h_unsupported(id)) h_loss(H_UNSUPPORTED);
    if (!h_data(id) && !h_life(id)) return 0;
    __u64 tid = bpf_get_current_pid_tgid();
    struct task_struct *task = (void *)bpf_get_current_task();
    struct h1_pending p = {.key = {.pid = tid >> 32, .id = id,
        .cgroup = bpf_get_current_cgroup_id()}, .entered_ns = bpf_ktime_get_ns()};
    p.key.process_ns = BPF_CORE_READ(task, group_leader, start_boottime);
    p.thread_ns = BPF_CORE_READ(task, start_boottime);
    p.key.direction = id == 1 || id == 20 || id == 44 || id == 46 || id == 307;
    __u64 ptr = 0, length = 0, fd = 0, flags = 0;
    if (BPF_CORE_READ_INTO(&fd, regs, di) || BPF_CORE_READ_INTO(&ptr, regs, si) ||
        BPF_CORE_READ_INTO(&length, regs, dx) || BPF_CORE_READ_INTO(&flags, regs, r10)) {
        h_loss(H_READ_FAILED); return 0;
    }
    p.fd = fd; p.batch = id == 299 || id == 307; p.vlen = p.batch ? length : 0;
    p.flags = (id == 46 || id == 47) ? length : (id == 44 || id == 45 || p.batch) ? flags : 0;
    p.message_ptr = p.batch ? ptr : 0;
    __u32 zero = 0;
    __u64 *seq = bpf_map_lookup_elem(&h_sequence, &zero);
    if (seq) p.sequence = __sync_fetch_and_add(seq, 1);
    if (h_data(id)) {
        h_offer(&p, ptr, length); p.metadata_error = !p.known;
        struct h1_value *v = bpf_map_lookup_elem(&h_totals, &id);
        if (v) h_add(&v->attempts, 1);
    } else {
        // Safe numeric arguments only. socketpair's output array is not read.
        if (id == 33 || id == 292 || id == 72 || id == 436 || id == 48 || id == 41) p.arg1 = ptr;
        if (id == 292 || id == 436 || id == 41 || (id == 72 && (ptr == 0 || ptr == 1030))) p.arg2 = length;
    }
    if (bpf_map_lookup_elem(&h_pending, &tid)) h_loss(H_NESTED);
    if (bpf_map_update_elem(&h_pending, &tid, &p, BPF_ANY)) h_loss(H_MAP_FULL);
    return 0;
}
static __always_inline struct h1_pending *h_current(void)
{
    __u64 tid = bpf_get_current_pid_tgid();
    struct h1_pending *p = bpf_map_lookup_elem(&h_pending, &tid);
    struct task_struct *task = (void *)bpf_get_current_task();
    if (!p) return NULL;
    if (p->thread_ns != BPF_CORE_READ(task, start_boottime)) { h_loss(H_GENERATION); return NULL; }
    return p;
}
static __noinline void h_tcp(struct sock *sk, __u64 length, __u32 flags)
{
    struct h1_pending *p = h_current();
    if (!p || !h_data(p->key.id)) return;
    __u64 cookie = 0; __u32 netns = 0, peer = 0;
    __u16 family = 0, local_port = 0, peer_port = 0;
    if (BPF_CORE_READ_INTO(&cookie, sk, __sk_common.skc_cookie.counter) ||
        BPF_CORE_READ_INTO(&netns, sk, __sk_common.skc_net.net, ns.inum) ||
        BPF_CORE_READ_INTO(&family, sk, __sk_common.skc_family) ||
        BPF_CORE_READ_INTO(&local_port, sk, __sk_common.skc_num) ||
        BPF_CORE_READ_INTO(&peer_port, sk, __sk_common.skc_dport) ||
        BPF_CORE_READ_INTO(&peer, sk, __sk_common.skc_daddr)) { h_loss(H_READ_FAILED); return; }
    if (!cookie) h_loss(H_UNKNOWN_COOKIE);
    if (p->seen && (cookie != p->key.cookie || netns != p->key.netns)) {
        h_loss(H_MULTI_SOCKET); p->metadata_error = 1; p->key.role = 0; p->key.cookie = 0;
    } else if (!p->metadata_error) {
        p->key.cookie = cookie; p->key.netns = netns;
        // The supervisor admits only this exact checked-in runtime configuration.
        // IPv6 remains explicitly unknown, even when the IPv4 listener is dual stack.
        __u32 zero = 0;
        struct h1_config *c = bpf_map_lookup_elem(&h_config, &zero);
        if (cookie && c && netns == c->netns && family == 2) {
            if (local_port == 8443) p->key.role = p->key.direction ? 1 : 2;
            else if (bpf_ntohs(peer_port) == 3447 && peer == bpf_htonl(0x7f000001))
                p->key.role = p->key.direction ? 3 : 4;
            else p->key.role = 5; // proven target process, excluded socket role
        }
    }
    p->seen++; p->effective += length; p->inner_active++;
    p->kernel_flags = flags;
}
SEC("fentry/tcp_sendmsg") int BPF_PROG(h_send, struct sock *sk, struct msghdr *msg, unsigned long len)
{
    __u32 flags = 0;
    if (BPF_CORE_READ_INTO(&flags, msg, msg_flags)) { if (h_current()) h_loss(H_READ_FAILED); return 0; }
    h_tcp(sk, len, flags); return 0;
}
SEC("fentry/tcp_recvmsg") int BPF_PROG(h_recv, struct sock *sk, struct msghdr *msg, unsigned long len, int flags, int *addr_len)
{
    (void)msg; (void)addr_len; h_tcp(sk, len, flags); return 0;
}
static __always_inline void h_inner(__s64 ret)
{
    struct h1_pending *p = h_current();
    if (!p) return;
    if (!p->inner_active) { h_loss(H_INNER_UNMATCHED); return; }
    p->inner_active--; p->inner_calls++;
    if (ret > 0) p->inner_bytes += ret;
    else if (ret < 0) p->inner_errors++;
}
SEC("fexit/tcp_sendmsg") int h_send_exit(__u64 *ctx) { h_inner((int)ctx[3]); return 0; }
SEC("fexit/tcp_recvmsg") int h_recv_exit(__u64 *ctx) { h_inner((int)ctx[5]); return 0; }
static __noinline void h_accumulate(struct h1_value *v, struct h1_pending *p, __s64 ret,
                                   __u64 accepted, __u32 known)
{
    __u64 now = bpf_ktime_get_ns();
    __u64 previous = __sync_fetch_and_add(&v->exits, 1);
    if (previous == ~0ULL) h_loss(H_OVERFLOW);
    if (!previous) { v->first_ns = p->entered_ns; v->min_return = ret; v->max_return = ret; }
    // Min/max/timestamps are approximate under concurrent writers; totals atomic.
    if (ret < v->min_return) v->min_return = ret;
    if (ret > v->max_return) v->max_return = ret;
    v->last_ns = now;
    if (ret > 0) { h_add(&v->positive, 1); h_add(&v->return_sum, ret); }
    else if (!ret) h_add(&v->zero, 1);
    else if (ret == -512 || ret == -513 || ret == -514 || ret == -516) h_add(&v->restarts, 1);
    else h_add(&v->errors, 1);
    if (p->known) { h_add(&v->offered_known, 1); h_add(&v->offered, p->offered); }
    if (known) { h_add(&v->accepted_known, 1); h_add(&v->accepted_bytes, accepted); }
    if (!ret && !p->batch && !p->key.direction && p->seen && p->known && p->offered)
        h_add(&v->eof, 1);
    if (ret > 0 && ((p->batch && (__u64)ret < p->vlen) ||
        (!p->batch && p->known && (__u64)ret < (p->seen == 1 ? p->effective : p->offered))))
        h_add(&v->short_calls, 1);
    h_add(&v->effective_bytes, p->effective);
    h_add(&v->inner_calls, p->inner_calls);
    h_add(&v->inner_bytes, p->inner_bytes);
    h_add(&v->inner_errors, p->inner_errors);
    h_add(&v->elapsed_ns, now - p->entered_ns);
}
SEC("raw_tp/sys_exit") int h_exit(struct bpf_raw_tracepoint_args *ctx)
{
    if (!h_owned()) return 0;
    __u64 tid = bpf_get_current_pid_tgid();
    struct h1_pending *p = h_current();
    if (!p) {
        struct pt_regs *r = (void *)ctx->args[0];
        __u64 id = BPF_CORE_READ(r, orig_ax);
        if (id < 512 && h_data(id)) h_loss(H_UNMATCHED);
        return 0;
    }
    __s64 ret = ctx->args[1];
    __u64 bytes = ret > 0 ? ret : 0;
    __u32 known = 1;
    if (p->batch && ret > 0) {
        bytes = 0;
        if (ret > H1_VECTOR || ret > p->vlen) { known = 0; h_loss(H_VECTOR_BOUND); }
        else for (__u32 i = 0; i < H1_VECTOR; i++) {
            if (i >= ret) break;
            __u32 length = 0;
            if (bpf_probe_read_user(&length, 4, (void *)(p->message_ptr + i * 64 + 56))) {
                known = 0; h_loss(H_READ_FAILED); break;
            }
            bytes += length;
        }
        if (!known) bytes = 0;
    }
    if (h_data(p->key.id)) {
        __u32 id = p->key.id;
        struct h1_value *total = bpf_map_lookup_elem(&h_totals, &id);
        if (total) h_accumulate(total, p, ret, bytes, known);
        p->key.outcome = ret < 0 ? ret : ret > 0 ? 1 : 0;
        struct h1_value *v = bpf_map_lookup_elem(&h_counts, &p->key);
        if (!v) {
            struct h1_value initial = {};
            bpf_map_update_elem(&h_counts, &p->key, &initial, BPF_NOEXIST);
            v = bpf_map_lookup_elem(&h_counts, &p->key);
        }
        if (v) h_accumulate(v, p, ret, bytes, known); else h_loss(H_MAP_FULL);
        h_emit(p, ret, bytes, known, 1);
    } else h_emit(p, ret, 0, 0, 2);
    bpf_map_delete_elem(&h_pending, &tid); return 0;
}
SEC("tp_btf/sched_process_fork") int BPF_PROG(h_fork, struct task_struct *parent, struct task_struct *child)
{
    (void)parent;
    if (!h_owned()) return 0;
    struct h1_pending p = {.key = {.pid = BPF_CORE_READ(child, tgid),
        .process_ns = BPF_CORE_READ(child, group_leader, start_boottime)},
        .thread_ns = BPF_CORE_READ(child, start_boottime), .entered_ns = bpf_ktime_get_ns(),
        .arg1 = BPF_CORE_READ(child, pid)};
    h_emit(&p, 0, 0, 0, 3); return 0;
}
SEC("tp_btf/sched_process_exec") int BPF_PROG(h_exec, struct task_struct *task)
{
    (void)task;
    if (!h_owned()) return 0;
    h_loss(H_EXEC);
    __u32 zero = 0;
    struct h1_config *c = bpf_map_lookup_elem(&h_config, &zero);
    if (c) c->pid = 0; // exec invalidates executable identity even without PID reuse.
    return 0;
}
SEC("tp_btf/sched_process_exit") int BPF_PROG(h_death, struct task_struct *task)
{
    (void)task;
    if (!h_owned()) return 0;
    __u64 tid = bpf_get_current_pid_tgid();
    struct h1_pending *p = h_current();
    if (p) { h_loss(H_ABANDONED); h_emit(p, 0, 0, 0, 4); }
    else {
        struct h1_pending ended = {.key = {.pid = tid >> 32}, .entered_ns = bpf_ktime_get_ns()};
        ended.thread_ns = BPF_CORE_READ(task, start_boottime);
        ended.key.process_ns = BPF_CORE_READ(task, group_leader, start_boottime);
        h_emit(&ended, 0, 0, 0, 4);
    }
    bpf_map_delete_elem(&h_pending, &tid); return 0;
}
