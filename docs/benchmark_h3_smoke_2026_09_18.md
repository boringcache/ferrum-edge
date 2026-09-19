# H3 live smoke lifecycle loss at d19abaa3

The [failed smoke run 35410602485, job 105816411525](https://github.com/ferrum-edge/ferrum-edge/actions/runs/35410602485/job/105816411525)
ran revision `d19abaa3c4fbb40af6136cb577a1ed7e82bf8529`. Prepare and
[preflight 35410602443](https://github.com/ferrum-edge/ferrum-edge/actions/runs/35410602443)
passed after the attachment verifier logging repair. Artifact `10573924412`
contains 219 retained files. This report and the
[data extraction](benchmark_h3_smoke_2026_09_18_results.json) analyze those files
without executing repository code. The extraction includes raw-file SHA-256
hashes, lifecycle timestamps, role joins and loss counters. It does not replace
or modify the failed artifacts or the [earlier capability report](benchmark_h3_preflight_2026_09_18.md).

All four arms ran for two seconds with 200 workers and a 10240-byte body. All
clients returned zero, reported zero errors, and returned exactly
`total_requests * 10240` bytes. Ferrum alone passed live smoke admission. Direct
failed the backend/client lifecycle requirement; both Envoy arms failed all four
roles. Operation coverage and role joins existed for every required role. Every
role-associated cookie had a birth record; the missing half was retirement.
This is observer evidence failure, not evidence of a new production proxy failure.

## Raw evidence and producer site

| Arm | TX lifecycle rows / omitted | Destroy lifecycle rows / omitted | Backend rows in TX / destroy | TX / destroy ring loss |
|---|---:|---:|---:|---:|
| Direct | 4096 / 71722 | 4096 / 71701 | 4075 / 4075 | 3941 / 4021 |
| Ferrum | 24 / 0 | 54 / 0 | 1 / 3 | 0 / 0 |
| Envoy, upstream 100 | 4096 / 13773 | 4096 / 13811 | 4067 / 4065 | 0 / 0 |
| Envoy, upstream 4 | 4096 / 13998 | 4096 / 14066 | 4045 / 4043 | 0 / 0 |

The saturated TX streams contain only kind 21 (`SOCKET_OBSERVED`). Direct's
destroy stream also contains only kind 21. Each Envoy destroy stream contains
4094 kind-21 rows and two early kind-20 retirements of unbound sockets; neither
retirement belongs to a required role. The lifetime family retained 24/29/34/56
births for direct/Ferrum/Envoy/Envoy-4, respectively. Ferrum retained all 29
retirements, including every required role.

The high-volume rows share backend port 3445 and a single cookie per arm:
direct `4097`, Ferrum `8200`, Envoy `12302`, Envoy-4 `8212`. Their nonzero
send destinations span 21/1/4/26 peer ports, respectively. For example, direct
cookie `4097` repeats peers `50676`, `45644`, then `50676` at kernel timestamps
`56276352730`, `56277413108`, `56277464963` in `destroy.jsonl`. PID `2624`,
local port 3445 and both 4194304-byte buffers stay unchanged. Threads vary,
which the existing same-process predicate already permits.

`t_enter` at `fentry/udp_sendmsg` and `d_enroll` at that same site pass the
message destination into `socket_event`. `d_receive` at `fentry/udp_recvmsg`
also enrolls the socket for destruction outside workload context. The shared
predicate compares each send's peer with the last stored peer. It exempts port
8443, but omitted the shared backend listener at 3445. Thus ordinary backend
responses to alternating clients became lifecycle events. Ferrum's one backend
peer did not churn that field, explaining the arm difference without a
performance hypothesis.

`observer.c::event` retains only the first 4096 lifecycle rows per family. The
direct stream filled about 0.11 seconds into measurement; both Envoy streams
filled about 0.50 seconds in. Subsequent `udp_destroy_sock` observations could
not reach the retained stream. Direct also overflowed the ring. The raw counters
prove loss; they cannot recover which particular omitted records were
retirements, or establish that every missing retirement hook fired.

## Repair and gates

The shared metadata predicate now applies the same peer-churn rule to **both
fixed H3 listener ports**, 3445 and 8443, before map update and ring output. Its
source is shared with the hosted C regression. TX, RX and destroy enrollment
use this one predicate. Process generation, local tuple/autobind, buffer changes
and all non-observation kinds still emit. Client/upstream destination changes
still emit. A listener's retained peer is representative metadata, not a full
peer inventory; `live.py::proof` continues to join upstream destinations to
actual backend connection-log peers, and frontend roles still require the owned
process generation and successful bind. No role is assigned merely by this
deduplication rule.

There are no new maps or larger bounds. The 4096-row cap, 512 KiB live ring per
family, identity/pending/witness limits and artifact/RSS budgets remain unchanged.
The verifier logging repair in `observer.c` is unchanged. Birth and retirement
still require their kernel sites; FD closure is not a substitute. Admission now
also rejects lifecycle output omissions or ring loss even if some complete
role lifetimes survived. Witness sampling remains explicitly partial.

`decoder_test.c` replays 8192 peer rotations for both ports, fanouts 1/4/21/26,
both RX-first and TX-first enrollment, and changing worker TIDs. It requires
one observation plus an unsuppressed retirement within the unchanged cap. It
also checks actual identity/tuple/buffer changes and non-listener destinations.
Python admission regressions reject either cap or ring loss, across every
observer family, even with otherwise complete role evidence. Both hosted
workflows already compile/run these contracts; the existing real four-arm H3
smoke remains the kernel/load/traffic/lifecycle gate. The C replay is a metadata
regression, not evidence that a repaired BPF program has loaded or that a real
socket has retired.

Only static review, data-only artifact analysis and `git diff --check` were
performed locally. Hosted compilation, contracts, verifier/fixture checks and
the repaired four-arm smoke are **pending**. The failed d19 run remains failed;
no retry, full measurement campaign, speedup, complete topology, exact loss total
or production optimization is claimed. Classic execution may remain unavailable
on the hosted kernel. Root owns CI review and landing; issue #5588 remains open.
