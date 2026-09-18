#ifndef H3_PROOF_CONTRACT_H
#define H3_PROOF_CONTRACT_H
#include <linux/types.h>
enum kind {
    TX_GSO = 1, TX_ORDINARY, TX_ERROR, TX_UNCOVERED,
    RX_GRO, RX_ORDINARY, RX_ERROR, RX_TRUNCATED, RX_PEEK,
    CLASSIC_SELECTED, CLASSIC_NULL, SELECTOR_SELECTED, SELECTOR_FALLBACK,
    ATTACH_OK, ATTACH_ERROR,
};
enum loss { MAP_FULL, READ_FAILED, UNKNOWN_COOKIE, NESTED, UNMATCHED,
            ATTEMPTS, RECORDED, EXCLUDED_API, LOSS_MAX };
struct key {
    __u64 cookie, peer;
    __s64 result;
    __u32 kind, length, segment, cpu;
};
struct value { __u64 count, first_ns, last_ns; };
struct config { __u64 netns; };
struct selection { __u64 anchor, selected; __u32 active, inner; };
#endif
