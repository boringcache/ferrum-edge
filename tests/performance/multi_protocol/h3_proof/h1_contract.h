/* Isolated native amd64 H1 metadata ABI; no payload or pointer fields exported. */
#ifndef H1_TRACE_CONTRACT_H
#define H1_TRACE_CONTRACT_H
#include <linux/types.h>
#define H1_CAPACITY 8192
#define H1_PENDING 512
#define H1_VECTOR 16
#define H1_EVENTS 4096
enum h1_loss { H_MAP_FULL, H_READ_FAILED, H_UNKNOWN_COOKIE, H_NESTED,
    H_UNMATCHED, H_ABANDONED, H_RING_FULL, H_WITNESS_CAP, H_COMPAT,
    H_GENERATION, H_EXEC, H_VECTOR_BOUND, H_OVERFLOW, H_MULTI_SOCKET,
    H_INNER_UNMATCHED, H_UNSUPPORTED, H_LOSS_MAX };
struct h1_config { __u64 start_ticks, cgroup, netns; __u32 pid, hz; };
struct h1_key { __u64 process_ns, cgroup, cookie; __u32 pid, netns, id, role;
    __s32 outcome; __u32 direction; };
/* Signed returns remain in witnesses and min/max; errno/restart in outcome.
 * mmsg return_sum is MESSAGES, accepted_bytes is returned-prefix msg_len. */
struct h1_value {
    __u64 attempts, exits, positive, zero, errors, restarts, eof, short_calls;
    __u64 offered, offered_known, accepted_bytes, accepted_known, return_sum;
    __u64 effective_bytes, inner_calls, inner_bytes, inner_errors, elapsed_ns;
    __u64 first_ns, last_ns;
    __s64 min_return, max_return;
};
struct h1_pending {
    struct h1_key key;
    __u64 thread_ns, sequence, entered_ns, offered, effective, message_ptr;
    __u64 inner_bytes, inner_calls, inner_errors, inner_active;
    __u64 arg1, arg2;
    __s32 fd; __u32 flags, kernel_flags, vlen, known, batch, seen, metadata_error;
};
struct h1_event {
    struct h1_key key;
    __u64 thread_ns, sequence, entered_ns, exited_ns, offered, accepted;
    __u64 effective, inner_bytes, inner_calls, inner_errors, arg1, arg2;
    __s64 result;
    __u32 tid, kind, flags, kernel_flags, known, accepted_known, vlen, seen, metadata_error;
    __s32 fd; __u32 pad;
};
#endif
