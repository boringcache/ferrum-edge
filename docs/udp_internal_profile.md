# UDP internal profiling (#5588)

`bench-udp-profile` is a default-off, dependency-free diagnostic feature. It
does not optimize session lookup, change forwarding policy, or close #5588.
The H1 feature, allocator, and schema are unchanged. UDP does not install an
allocator. With both features selected, H1 continues to forward to Jemalloc.
The FIPS inventory explicitly includes UDP alone and UDP with H1; these
features introduce no crypto providers or runtime-policy exemptions.

## Fixed authenticated contract

The existing gated `/metrics` response gains `ferrum_udp_profile_*` fields only
in feature builds. Admin JWT, metrics bearer token, and allowed source CIDR
checks are unchanged. There are no dynamic labels, addresses, namespaces,
destination identities, credentials, or payloads in this family. The literal
allowlist is `tests/performance/multi_protocol/udp_profile_schema.json` and
`src/udp_profile/schema.rs`; hosted tests require exact parity.

Counters accumulate per OS thread in fixed TLS storage. At most 128 slots are
claimed once and never reused, including after thread exit. Ordinary updates
use no profiling locks, global atomics, allocation, or logging. Every 2048
update groups, the owner publishes cumulative fields through per-slot atomic
storage with a bounded sequence-checked read. A dirty marker is written once
per interval, not once per packet. Exceptional registration exhaustion, TLS
reentry/teardown, or sequence overflow increments `lost_events`. Counter and
aggregate overflow saturate and remain explicit. Missing snapshots are never
substituted with zero. Publication overhead must be calibrated.

Thread exit publishes its tail when TLS destructors run; abrupt process exit
can lose it. Scraping flushes only the scraper's current thread. Other dirty
slots contribute 2048 each to `unpublished_event_bound`. This bounds local
update groups at each slot's capture in the absence of loss, **not packets, bytes, nanoseconds, or
global point-in-time skew**. Idle workers can leave tails indefinitely. Nonzero
tails, missing slots, loss, overflow, or a reset prevent complete-profile status;
published deltas remain useful partial observations. No remote worker flush,
per-packet publication, or global barrier is added to forwarding.

`sample_every=64` means the first and every 64th call of each operation on each
OS thread receives two monotonic `Instant` reads. Sampling is deterministic,
not random; task migration changes the sample sequence. Timers enclose only
synchronous calls and never cross `.await`. Nested timers are inclusive. Clock
resolution is platform dependent and timer/observer overhead is not subtracted.
Disjoint timing bins end at 100, 500, 1000, 5000, 20000, 100000, 1000000 ns,
then infinity. Occupancy bins are 0, 1, 2–4, 5–8, 9–16, 17–32, 33–64, 65+.

## Attribution and limits

| Observation | Meaning and coverage |
|---|---|
| Metadata decode / destination resolve | Existing authenticated envelope decode when enabled, then exact route resolution; ordinary echo has no metadata/NodeWaypoint workload. |
| Pending / last-client / established lookup | Attempts and hit/miss outcomes, plus sampled synchronous time. Cache expiry is counted at the original expired check; established expiry is a feature-only observation of the returned entry's flag. A hit does not imply later policy admission. These are software lookup outcomes, not hardware cache misses. |
| Second pending race gate | Existing occupied/vacant/error outcomes and sampled insertion-call time; the defensive follow-up lookup has separate attempt/hit/miss timing fields. Pending entries have no independent expiry field. |
| Pending queue | Accepted/tail-dropped datagrams, retained bytes, batches removed for FIFO drain, empty gate removal and aborted queue residuals. Drained means removed for processing, not successfully forwarded. Residuals already moved into a drain batch and later refused are not separately enumerated. |
| Shared updates | Calls at request-size/budget publication, finite amplification charge, fast-path activity/byte updates, queue admission charges, normal listener and reply metric publication. These are source-level operations, not successful CAS counts, retries, contention time, or every shutdown/rollback/hook/DTLS counter update. |
| Borrowed / queued send | Successful borrowed backend sends and returned bytes, WouldBlock/errors, egress enqueue/drop/dequeue, and successful authorization-aware queued commits. Queue admission is not a send. Setup/hook asynchronous backend sends remain outside these send totals. |
| Poll / readiness / notify | Egress receiver/commit polls, reply receive polls, Pending/Ready outcomes, frontend `readable()` returns, drain WouldBlock outcomes, reply-stop/hook notify calls. No scheduler wake, context switch, or CPU-contention claim. Egress poll totals combine queue receive and commit; they are not whole-task poll counts. |
| `ingress_rx_*` | Actual frontend `recvmmsg` requested/returned occupied slots; error/WouldBlock counts; raw returned bytes; logical packets from parsed GRO segment sizes. Parsing failure, payload/control truncation and invalid GRO segment size are explicit and leave logical-packet coverage incomplete. Zero-length datagrams count as packets. Tokio's cached not-ready path does not count as an actual syscall. |
| `reply_tx_*` | Actual `sendmmsg` occupied input slots, accepted slots/bytes, partial calls/remainders, error slots, and explicit discard/oversize outcomes. Retries count the remaining requested slots again. Errors clear the original queue; partial sends retain it in original order. |
| `reply_gso_*` | Occupied segments/bytes/segment-size sum, full accepted segments and returned bytes, errors/short results, fallback segments handed to sendmmsg or direct send, explicit discards. A fallback handoff is not acceptance; final mmsg/direct outcomes are separate. Single-segment success alone does not prove batching. Kernel acceptance does not prove NIC offload. |
| `reply_direct_*` | Logical Tokio send futures or explicit pktinfo attempts, accepted bytes and errors. Tokio internal syscall retries are opaque. A canceled future can leave calls without a terminal outcome. |

Directions are attached to batch owners and survive task migration. `other_*`
isolates shared batch helpers used by mesh capture/DTLS instead of pretending
those calls belong to the plain UDP listener. Plain UDP backend receives are
individual `recv`/`try_recv`, and borrowed client-to-backend sends do not use
sendmmsg/GSO. Thus reply recvmmsg and ingress mmsg/GSO are unexercised in this
path, not evidence of missing syscalls in those directions. Quinn HTTP/3,
DTLS crypto drivers, mesh identity revalidation, native allocations, complete
copy traffic, queue delay, whole-task scheduling, and CPU stacks are opaque.
GRO logical counts describe ancillary-derived packets before later admission;
they are not useful-work totals. Unused operation hit/miss/error fields remain
zero and are not additional coverage claims.

The pending map still precedes last-client and established lookup. Session
publication still occurs before the pending FIFO drain finishes; established
first would permit overtaking. No lock, authorization, generation/namespace,
destination ownership, expiry/revocation, amplification, pktinfo source,
queue, retry, or notification ownership rule is relaxed.

## Hosted checks and bounded campaign

The new `UDP Internal Profile` workflow has a pull-request feature-on lane for
formatting, clippy, build, attribution/publication/batch tests, and existing
setup/FIFO/auth/source/amplification/generation regressions. It also checks the
observer-off path, combined H1 build and parent collector contracts. All
execution is hosted. No workflow was dispatched by this implementation.

Manual dispatch builds symbolized observer off/on twins from the same checked
out revision, retaining release optimization, fat LTO, one codegen unit,
crypto-ring and Jemalloc. It archives source/lockfiles, flags, binary hashes,
build IDs/debug files, image identities, runner CPU/kernel/boot ID, effective
Ferrum configs, per-process resource records, and all raw samples/errors.
Prerequisites include `libcurl4-openssl-dev`.

The independent manifest declares two campaigns, each with four same-host,
counterbalanced pairs and a fresh direct control per pair:

1. **Calibration:** observer-on Ferrum versus same-revision observer-off Ferrum.
2. **Profile:** observer-on Ferrum versus unchanged `kong/kong-gateway:3.10.0.0`.

Both use existing UDP 1024-byte echo, 200 offered workers, and 15-second
measurement phases. Equal offered work means the same workers, payload, and
timed closed-loop workload, not equal completed packet counts. Client socket
lifetime gauges must show 200 throughout measurement. The report keeps raw
errors/bytes/phase/process validity independent from profile completeness.
No throughput result or optimization benefit is asserted.

`udp_internal_profile.py` validates every fixed metric, schema/sample rate,
capture clock/sample sequence, `/proc` host PID/start ticks mapped to namespace
PID, unchanged processes, cumulative counter monotonicity, and measurement
brackets (at most two seconds total slack). Scrapes retain raw family text,
response hash/size, malformed/truncated data and HTTP failure status. An append
JSONL companion retains each scrape even if the sampler later fails; it is not
promoted to a complete campaign. Failed/missing repetitions stay in the full
expected matrix. All-zero lookup deltas cannot produce a profile success.
The CLI fails invalid traffic; complete-profile eligibility is a separate
explicit report field and is expected to remain false when worker tails exist.

Ordinary `experiment.json` stays disabled. H1, H2/gRPC and H3 schema/manifests
and the frozen benchmark workflow remain unchanged. Locality, burst and churn
scenarios are **not implemented**: the manifest records the required fixed or
seeded send schedule, socket creation/retirement hooks, equal offered packet
counts/rate, and observed socket lifetime requirements. Existing echo does not
exercise controlled churn or establish a prescribed cache miss rate.

Kong image metadata is retained on the hosted campaign. Exact enterprise
NGINX/OpenResty vendor correspondence remains unestablished; public Kong tags
do not establish it. The recorded official changelog correction for .0/.1's
OpenResty connection pooling bug is in 3.10.0.2, with UDP applicability still
unestablished. The baseline is unchanged and no causal inference is made.
Root owns final provenance, syscall/CPU tracing, hosted dispatch, parent
integration, and any subsequent decision about optimization or tracker closure.
