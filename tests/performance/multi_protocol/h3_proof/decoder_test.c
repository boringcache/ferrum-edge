/* Hosted tests of the exact metadata predicates used by the BPF decoder. */
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include "rx_contract.h"
int main(void)
{
    _Static_assert(sizeof(struct user_msg) == 56, "native header");
    _Static_assert(offsetof(struct user_msg, flags) == 48, "returned flags");
    _Static_assert(sizeof(struct user_cmsg) == 16, "native control header");
    assert(h3_native_call(299, 1, 32));
    assert(!h3_native_call(299, 1, 33));
    assert(!h3_native_call(299, 1, 0));
    assert(!h3_native_call(0x40000000 | 299, 1, 32));
    assert(!h3_native_call(337, 1, 32));
    assert(h3_native_call(47, 0, 1));
    assert(h3_control_bounds(4096, 64, 4096, 24));
    assert(!h3_control_bounds(4096, 16, 4096, 24));
    assert(!h3_control_bounds(4096, 512, 4096, 257));
    assert(!h3_control_bounds(4096, 64, 8192, 24));
    assert(!h3_control_bounds(UINT64_MAX - 3, 64, UINT64_MAX - 3, 24));
    struct user_cmsg c = {20, 17, 104};
    assert(h3_cmsg_shape(&c, 24, 0));
    assert(!h3_cmsg_shape(&c, 24, 512)); /* duplicate GRO */
    assert(!h3_cmsg_shape(&c, 19, 0));
    c.length = 18; assert(!h3_cmsg_shape(&c, 24, 0)); /* u16 is TX ABI, not RX */
    c.length = 0; assert(!h3_cmsg_shape(&c, 24, 0));
    c.length = UINT64_MAX; assert(!h3_cmsg_shape(&c, 24, 0));
    assert(!h3_segment_valid(0)); assert(!h3_segment_valid(-1));
    assert(!h3_segment_valid(65536)); assert(h3_segment_valid(512));
    assert(h3_delivered_gro(2048, 512, 0, 0));
    assert(!h3_delivered_gro(512, 512, 0, 0));
    assert(!h3_delivered_gro(0, 512, 0, 0));
    assert(!h3_delivered_gro(2048, 512, 8, 0));
    assert(!h3_delivered_gro(2048, 512, 32, 0));
    assert(!h3_delivered_gro(2048, 512, 0, 2));
    assert(!h3_delivered_gro(2048, 512, 0, 8192));
    assert(h3_prefix_valid(1, 32, 2));
    assert(!h3_prefix_valid(-14, 32, 2)); /* timeout/header copyout */
    assert(!h3_prefix_valid(0, 32, 2));
    assert(!h3_prefix_valid(2, 1, 2));
    assert(!h3_prefix_valid(2, 32, 1));
    return 0;
}
