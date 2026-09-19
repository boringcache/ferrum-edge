#ifndef H3_PROOF_SOCKET_CONTRACT_H
#define H3_PROOF_SOCKET_CONTRACT_H
#include "contract.h"

/* Same-cookie observations only: callers look up previous by e->cookie.
 * The fixed H3 backend (3445) and frontend (8443) multiplex peers on one
 * listener. Their sendmsg destination is a representative observation, not a
 * socket identity change or an inventory of connections. Upstream/client
 * destinations still matter; backend connection logs supply the peer join.
 */
static __inline __attribute__((always_inline)) int h3_same_socket_observation(
    const struct identity_event *e, const struct identity_event *previous)
{
    return e->kind == SOCKET_OBSERVED && previous &&
        (previous->pid_tgid >> 32) == (e->pid_tgid >> 32) &&
        previous->process_start_ns == e->process_start_ns &&
        previous->local.address == e->local.address && previous->local.port == e->local.port &&
        ((previous->peer.address == e->peer.address && previous->peer.port == e->peer.port) ||
         e->local.port == 3445 || e->local.port == 8443) &&
        previous->rcvbuf == e->rcvbuf && previous->sndbuf == e->sndbuf;
}
#endif
