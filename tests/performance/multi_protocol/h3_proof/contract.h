#ifndef H3_PROOF_CONTRACT_H
#define H3_PROOF_CONTRACT_H
#include <linux/types.h>
enum kind {
    TX_GSO = 1, TX_ORDINARY, TX_ERROR, TX_UNCOVERED,
    RX_GRO, RX_ORDINARY, RX_ERROR, RX_TRUNCATED, RX_PEEK,
    CLASSIC_SELECTED, CLASSIC_NULL, SELECTOR_SELECTED, SELECTOR_FALLBACK,
    ATTACH_OK, ATTACH_ERROR, RX_ZERO, RX_BATCH, SOCKET_BIRTH, SOCKET_BIND,
    SOCKET_RETIRE, SOCKET_OBSERVED, PROCESS_EXIT, GROUP_ALLOC, GROUP_ADD, GROUP_DETACH, PROGRAM_DETACH, PROCESS_FORK, PROCESS_EXEC, PROCESS_DEATH,
};
enum loss { MAP_FULL, READ_FAILED, UNKNOWN_COOKIE, NESTED, UNMATCHED,
            ATTEMPTS, RECORDED, EXCLUDED_API, ABANDONED, RING_FULL, WITNESS_FULL,
            IDENTITY_FULL, BATCH_PARTIAL, INNER_ERROR, LOSS_MAX };
struct key {
    __u64 cookie, peer;
    __s64 result;
    __u32 kind, length, segment, cpu;
};
struct value { __u64 count, first_ns, last_ns; };
struct config { __u64 netns, start_ns; __u32 live; };
struct endpoint { __u32 address; __u16 port, family; };
struct identity_event {
    __u64 cookie, at_ns, cgroup, process_start_ns, thread_start_ns;
    __u64 pid_tgid, peer_cookie, instruction_digest, attachment_generation;
    __u32 program_type, instruction_count, digest_valid, reserved;
    struct endpoint local, peer;
    __u32 kind, netns, rcvbuf, sndbuf, drops;
    __s32 result;
};
struct witness { struct key key; __u64 at_ns, pid_tgid, process_start_ns, thread_start_ns; };
struct rx_slot { __u64 hdr, control, capacity; __u32 readable, pad; };
struct rx {
    __u64 generation, cookie, hdr;
    __u32 flags, vlen, batch, entries, invalid, active, inner_errors, pad;
    struct rx_slot slots[32];
};
struct selection { __u64 anchor, selected; __u32 active, inner; };
#endif
