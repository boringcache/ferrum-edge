/* Hosted tests of the metadata predicates used by the BPF observer. */
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include "rx_contract.h"
#include "socket_contract.h"

static void listener_churn(void)
{
    /* d19 live smoke: backend cookie 4097, port 3445, alternating sendmsg
     * peers. 4075 of the first 4096 destroy events belonged to this socket;
     * the stream filled before any required retirement. Reproduce more than
     * the unchanged cap for BOTH listeners and both enrollment orders.
     */
    const unsigned short ports[] = {3445, 8443};
    const unsigned int peers[] = {1, 4, 21, 26}; /* Ferrum, Envoy, direct, cap-4 */
    for (unsigned int p = 0; p < sizeof(ports) / sizeof(ports[0]); p++) {
        for (unsigned int n = 0; n < sizeof(peers) / sizeof(peers[0]); n++) {
            for (int receive_first = 0; receive_first < 2; receive_first++) {
                struct identity_event e = {.cookie = 4097, .kind = SOCKET_OBSERVED,
                    .pid_tgid = (2624ULL << 32) | 2625, .process_start_ns = 55590000000ULL,
                    .local = {.address = 0x0100007f, .port = ports[p], .family = 2},
                    .peer = {.address = 0x0100007f, .port = 50676, .family = 2},
                    .rcvbuf = 4194304, .sndbuf = 4194304};
                struct identity_event previous = e;
                if (receive_first) previous.peer.port = 0;
                unsigned int rows = 1;
                assert(!h3_same_socket_observation(&e, NULL));
                for (unsigned int i = 0; i < 8192; i++) {
                    e.peer.port = 40000 + i % peers[n];
                    e.pid_tgid = (2624ULL << 32) | (2625 + i % 4);
                    if (!h3_same_socket_observation(&e, &previous)) {
                        previous = e;
                        rows++;
                    }
                }
                assert(rows == 1); /* Traffic cannot consume lifecycle rows. */
                e.kind = SOCKET_RETIRE;
                assert(!h3_same_socket_observation(&e, &previous));
                rows++;
                assert(rows < 4096); /* The real loader cap is unchanged. */
            }
        }
    }
}

static void socket_changes(void)
{
    struct identity_event base = {.cookie = 1, .kind = SOCKET_OBSERVED,
        .pid_tgid = (10ULL << 32) | 11, .process_start_ns = 100,
        .local = {.address = 0x0100007f, .port = 3445, .family = 2},
        .peer = {.address = 0x0100007f, .port = 40000, .family = 2},
        .rcvbuf = 4194304, .sndbuf = 4194304};
    struct identity_event changed;
    /* Lifecycle events, process generations, autobind and buffers survive. */
    const unsigned int kinds[] = {SOCKET_BIRTH, SOCKET_BIND, SOCKET_RETIRE, ATTACH_OK, ATTACH_ERROR};
    for (unsigned int i = 0; i < sizeof(kinds) / sizeof(kinds[0]); i++) {
        changed = base; changed.kind = kinds[i];
        assert(!h3_same_socket_observation(&changed, &base));
    }
    changed = base; changed.pid_tgid += 1ULL << 32;
    assert(!h3_same_socket_observation(&changed, &base));
    changed = base; changed.process_start_ns++;
    assert(!h3_same_socket_observation(&changed, &base));
    changed = base; changed.local.address = 0;
    assert(!h3_same_socket_observation(&changed, &base));
    changed = base; changed.local.port = 8443;
    assert(!h3_same_socket_observation(&changed, &base));
    changed = base; changed.local.port = 0;
    assert(!h3_same_socket_observation(&base, &changed));
    changed = base; changed.rcvbuf /= 2;
    assert(!h3_same_socket_observation(&changed, &base));
    changed = base; changed.sndbuf /= 2;
    assert(!h3_same_socket_observation(&changed, &base));
    /* A client/upstream socket's destination changes still supply evidence. */
    base.local.port = 40001; base.peer.port = 3445;
    changed = base; changed.peer.port = 8443;
    assert(!h3_same_socket_observation(&changed, &base));
    changed = base; changed.peer.address++;
    assert(!h3_same_socket_observation(&changed, &base));
}

int main(void)
{
    listener_churn();
    socket_changes();
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
