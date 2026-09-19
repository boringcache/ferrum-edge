# Hosted H1 internal profiling foundation (#5588)

`bench-h1-profile` is a **default-off diagnostic feature**, accompanied by
hosted regression fixtures. It does not change coalescing, Content-Length, body limits,
timeouts, retries, offered load, TLS verification, release optimization settings,
or forwarding policy. #5600's client frame/chunk/TLS observations and `/proc/io`
remain distinct sources. This branch starts at #5602 head
`5e32b808af5631978cedc525d0dff7a29aedbb4c`; root must settle that dependency and
preserve its error campaign. There are no new performance results here. The prior
cutoff campaign demonstrated no gain; its failed 5 MiB observations remain valid
failure evidence and are not replaced by this foundation.

The feature introduces no dependency or crypto-provider edge. `fips,bench-h1-profile`
is explicitly included in the FIPS optional-profile inventory, so the existing
hosted resolved-graph audit and compile matrix cover that combination. This is
functional build coverage, not a separate cryptographic certification claim.

## Allocator safety and publication contract

`src/main.rs` wraps the existing `tikv_jemallocator::Jemalloc` on non-Windows
platforms only when the feature is enabled. The default allocator declaration is
otherwise unchanged. Windows does not install this observer and exports
`allocator_installed=0`; the hosted collector rejects that as missing coverage.
The library alone does not replace an embedding application's allocator.

`src/h1_profile/allocator.rs::ForwardingAllocator` forwards alloc, alloc_zeroed,
realloc and dealloc exactly once with unchanged pointer/layout/size. The return
pointer is unchanged. A failed realloc leaves ownership of the old allocation
with its caller. Requested bytes include attempted allocations/zeroed allocations
and **new requested sizes** for realloc. Successful requested bytes exclude null
returns. Realloc old/new sizes and deallocation bytes are separate fields.
Deallocation is attributed where it executes, not to its original allocation.
These counters are neither live memory nor RSS, and realloc sizes are not copy
volume. Jemalloc internals, native-library allocations bypassing Rust's allocator,
kernel storage and hidden memcpy/memmove are outside coverage.

Callbacks use fixed arrays, const non-destructible TLS, `RefCell::try_borrow_mut`,
checked arithmetic and atomics only. They do not allocate, acquire locks, log,
format, dereference caller storage, or panic. Non-destructible TLS avoids lazy
destructor registration inside callbacks. `try_with` failure, reentrant borrow
failure, exhausted registration and publication version exhaustion increment
`lost_events` on the exceptional path. Saturation is sticky; counter overflow is
exported and invalidates completeness. Internal array indices are constants or
bounded enum/registration results. This contract depends on the backing
allocator's `GlobalAlloc` contract and Rust's const TLS implementation; root
should review these unsafe/concurrency seams explicitly.

There are 128 cache-aligned, never-reused thread slots, each with 206 fixed
counters. Registration uses bounded atomic compare-exchange over static storage.
Normal accounting mutates only the calling thread's TLS and stores an event
watermark into its own slot; there is no shared process-total atomic increment
per allocation. Every 1024 observer events (allocator calls, body/write events
and scope transitions) publish that thread's entire cumulative snapshot.
Frontend observer drop and the scraper's own thread also publish explicitly.
There is no hot-path clock or stack capture.

Publication has one writer per slot. The writer makes a sequence odd, stores
atomic counter fields and the published event watermark, then makes it even.
All these operations are SeqCst. Readers accept only an unchanged even version,
with at most three attempts. Payloads are atomic: **no plain-memory seqlock data
race**. Busy slots increment `missing_slots`; they are not silently accepted as
zero. Version exhaustion freezes that slot and reports loss. Cross-thread sums
are not a simultaneous stop-the-world snapshot.

This is intentionally a bounded minimum: idle/exited threads can retain an
unpublished tail. No TLS destructor flush is promised. Their event watermarks
remain in unrecycled static slots, so `unpublished_events` stays visible even
after thread exit. A tail may contain an arbitrarily large requested allocation;
its byte residual cannot be bounded from its event count. Abrupt termination
also loses unsampled data. The collector keeps published deltas but sets
`complete=false` when a tail, missing slot, overflow, reset, or loss exists.
Do not present these partial sums as exact process totals. Thread churn beyond
128 lifetime registrations requires a separately reviewed extension.

The process view covers all observed Rust allocator calls, including runtime,
administration and metrics export. Four **synchronous execution** scopes cover
`ProxyBody::poll_kind`, the two reqwest input polls, plaintext write/flush/shutdown
polls and ciphertext write/flush/shutdown polls. A closure installs/restores TLS
on every poll, including Pending and error. A private non-Send guard never escapes
the closure and never survives await. Nested inclusive scope counters count once
per active scope; exclusive attribution goes only to the innermost scope.
Inclusive views overlap and must not be summed. Detached tasks, TLS reads,
handshake orchestration, header construction, dispatch, and background Hyper
drivers are not exhaustively scoped. Scope calls are not request IDs or sampled
CPU time. Unscoped process traffic can be derived only from a complete snapshot.

## Source coverage inventory

| Source site | Exact observation | Boundary / limitation |
| --- | --- | --- |
| `body.rs::direct_streaming_body` reqwest byte stream | input DATA/frame bytes, poll/Pending/error/EOF, disjoint size buckets | response input only; reqwest has already adapted wire framing |
| `body.rs::coalescing_body` reqwest byte stream | same, separate counters | input before aggregation; no direct-H2/H3/upload coverage claimed |
| `body.rs::ProxyBody::poll_frame` | output DATA/non-DATA, bytes, poll/Pending/error/EOF, size buckets | shared output across protocols, not H1-only; known EOF may let Hyper skip a final poll |
| `CoalesceBuffer::push`, Single promotion, both `extend_from_slice` calls | `first.len()` plus `data.len()` copied, after each executed call | exact explicit source copies, all coalescer users |
| `CoalesceBuffer::push`, Merged `extend_from_slice` | appended `data.len()` copied | reserve/growth may additionally move old storage; not counted as payload copy |
| CoalesceBuffer/Coalescing | single holds, spare reuse, new region, capacity growth, large bypass, nonempty flush | aggregate flush count only, not a complete flush-reason classification |
| `handle_connection` above TCP | cleartext AsyncWrite observations | H1/h2c mixed; upgrades can outlive HTTP |
| `handle_tls_connection`, above TLS | plaintext AsyncWrite observations, non-h2 ALPN versus ALPN h2 | non-h2 includes absent ALPN (not proof of negotiated H1); accepted bytes can still be buffered in rustls |
| `handle_tls_connection`, below TLS before accept | ciphertext AsyncWrite observations and TLS framing | mixed ALPN/handshake/control traffic; ALPN unknown during handshake |

Size buckets are disjoint: 0, 1–1024, 1025–16384, 16385–131072,
131073–1048576 and larger bytes. `Bytes` clones, Single ownership transfer,
large-frame bypass, split/freeze, and retained spare ownership count **zero payload
copies** at those sites. The five-byte TLS parser's own header copy is observer
work, not a response-payload copy counter.

The AsyncWrite adapter forwards exactly one inner call with the original buffer
or slice vector, preserving vector order/empty entries, `is_write_vectored`,
partial success, zero success, Pending, errors, flush and shutdown. Reads are
delegated unchanged. Requested byte totals count repeated poll offers and must
not be used as successfully transferred bytes. It adds no retry, await or flush.
Only the accepted ciphertext prefix enters the incremental parser, including
partial vectored writes. It retains five header bytes, never payload. Complete
TLS records and wire bytes include encrypted control records; parser faults and
incomplete terminal records are separate counters. At mid-stream sample
boundaries, client receive counts and gateway accepted counts can disagree.

No new listener or endpoint exists. Export appends fixed `ferrum_h1_profile_*`
fields to the existing authenticated `/metrics` response. There are no request
labels, paths, addresses, headers, credentials or body contents. Admin/sampler
connections are outside the frontend write wrappers but their allocations remain
in process totals. This build should run an isolated H1 workload; shared body,
coalescer and mixed-wire counters must not be relabeled H1 under mixed traffic.

## Hosted checks and exact root dispatch

No repository code, build, formatter, lint, test, benchmark, container or server
was executed locally for this implementation. Static inspection and
`git diff --check` are the only local validation. The new
`.github/workflows/h1-internal-profile.yml` registers a PR/manual hosted lane for
feature-enabled clippy/binary compilation, registered external observer tests,
private publication-seam tests located under `tests/unit/gateway_core/`, existing
coalescer contracts with observers on/off, existing live functional streaming
contracts, the explicit H1 cadence/safety matrix below, supported-protocol
trailer gates, and H1 schema/completeness tests. The independent Benchmark Harness
Tests discovery also runs the new Python tests. These are registrations, not
claims of passing execution.

Root dispatches after reviewing this branch and settling dependencies (worker
does not dispatch). Once the workflow is available to GitHub Actions:

```sh
gh workflow run h1-internal-profile.yml \
  --ref codex/20260918-5588-h1-profile -f payloads=all
```

The sole input is `payloads`: `all` (default), `10240`, `71680`, `512000`,
`1048576`, or `5242880`. Root can budget separate size dispatches; all five remain
required. Each comparison's two arms and repeated direct controls share one VM.
No worker dispatch, PR, review, merge or issue write is part of this task.

The manual job builds observer-off/on binaries at the **same checked-out SHA**,
default `crypto-ring` features, Linux Jemalloc, release opt-level 3, fat LTO,
one codegen unit and abort panic. Both diagnostic twins add debug info and retain
symbols using job-local profile overrides; production Cargo profiles are
unchanged. No forced frame pointers. The ordinary release binary is not a third
arm, so calibration applies to these diagnostic twins, not historical release
rates. Source-tree/lock/config hashes, compiler/build flags, image IDs, binary
hashes/build IDs, matching debug artifacts, kernel/hardware/boot identity and
effective safe runtime settings are retained. The shared harness retains raw
traffic samples, startup logs, phase boundaries, process CPU/RSS and concurrency.

Calibration first measures on/off at cutoff 0; cutoff then compares 0/1 with
identical observers. Both use four counterbalanced pairs, repeated direct
controls, 15-second measurement, five sizes and 200/200/200/100/50 offered workers.
Existing warmup, drain, error, timeout, retry and TLS policy are preserved. The
new H1 selector bypasses but never edits `experiment.json` or `experiment_arms.py`.
Shared runner/sampler edits are isolated behind `--h1-profile`; root should
coordinate those two file overlaps with #5602. The frozen benchmark job and its
policy verifier are untouched.

`h1_internal_profile.py` retains bounded integer-only snapshots with sample IDs,
timestamps, scrape duration/CPU, process identity and measurement boundary slack.
It rejects missing/malformed/decreasing counters, reused process identities,
missing slots, loss and overflow. Idle-thread tails explicitly prevent complete
allocation coverage. Useful traffic validity is separate from profile
completeness. Every expected arm/pair/size is retained, including missing samples
and failed 5 MiB observations. No surviving-worker average, guessed observer
overhead subtraction, or gain claim is produced. Raw on/off measurements are the
overhead calibration; shared-host process CPU is not isolated proxy cost, and RSS
is not allocation traffic. Scrape overhead is included in the gateway process and
sampler timings, not analytically subtracted.

## Live cadence and safety gate

`tests/functional/h1_cadence_tests.rs` is registered in the functional binary on
Linux and explicitly selected by the dedicated `cadence` job. The existing
`functional_streaming` filter does not select it. Each observer-off/on matrix
job compiles and lints the functional target, builds and copies its external
binary, pins `FERRUM_EDGE_TEST_BIN`, and retains the revision, binary SHA-256,
test output and failures in `h1-cadence-{off,on}-<sha>` artifacts. No implicit
harness rebuild is allowed. Measurement now depends on both cadence jobs as
well as the existing checks. PR events run these gates without measurements;
manual dispatch uses the unchanged `payloads` input and command above, and
also runs the calibration/measurement job. These are hosted registrations;
no passing execution is claimed by this implementation.

Each of five tests runs cutoffs **0 and 1**, with cleartext H1 on both hops and
with **verified TLS on both hops**. The TLS backend uses the existing `TestCa`
and scripted `TlsConfig` with H1-only ALPN; the client trusts only that CA.
Leased sockets and `TestGateway` supply listener ownership, child-authenticated
readiness and cleanup. The existing scripted steps have no release barrier, so
this module owns a small channel-driven script without changing shared runners.

| Contract | Observable assertion |
| --- | --- |
| Tiny/delayed ordinary DATA and mixed tiny/256 KiB/tiny body | Exact ordered bytes for every released marker before the next release; first DATA and complete-marker arrival recorded |
| One tiny frame followed by idle | Complete DATA arrives with backend EOF still withheld; no extra bytes or terminal event during the idle gate |
| Declared-length and chunked truncation | After observed prefix, clean transport shutdown with incomplete HTTP framing causes a body error; clean EOF and client timeout cannot pass |
| Cancellation after observed DATA | Active request count is first 1; dropping the response yields backend peer EOF/reset and a joined task within 10 seconds, followed by accounting returning to 0 within 10 seconds |
| Delayed allowed-prefix/blocked policy window | Exact allowed SSE prefix arrives first; the later lexical leakage window yields only the exact policy error event and its `[DONE]` marker, clean downstream EOF, backend cessation and accounting release |

There are 24 scenarios per observer build (truncation has two framing cases).
All release/readiness/terminal waits are bounded. A sequence-numbered backend
notification follows each flushed write, and only client-observed exact bytes
authorize the next release or EOF. A **5-second** release-to-client scheduling
tolerance covers both the write acknowledgement and complete marker; explicit
elapsed checks complement async timeouts. The **200 ms** idle dwell starts only
after readiness or observed DATA. The backend read timeout is **60 seconds**,
so it cannot satisfy the cancellation bound. These are progress guards, not
latency benchmarks. HTTP-decoded bytes may split or combine arbitrarily across
TCP reads, TLS records and DATA callbacks.

The lane checks the child executable through `/proc/<pid>/exe`, safe selected
environment values, the exact file config, the authenticated effective route,
and presence/absence of observer schema metrics (including child PID when on).
An empty settings file and cleared child environment prevent inherited config
from selecting another path. Size limiting and latency tracking are disabled.
The fixture uses one gateway runtime worker so the existing metrics publication
seam exposes positive direct/coalesced input evidence after completion; the
opposite branch must stay unused. This proves branch selection, not complete
profile accounting or coverage of multithreaded scheduling. Observer-off uses
the same pinned source/config and direct/coalescing selection predicates.

The policy case exercises `inspected_streaming_body`, which intentionally
bypasses coalescing. It reuses the existing semantic-firewall lexical leakage
policy and `on_error: warn` with a leased unavailable embedding provider for
the allowed prefix; it does not establish successful embedding-provider
inspection or ordinary-body policy semantics. The configured lexical violation
must still block the later window. No production behavior is changed.

H1 trailer preservation remains **unproven and unsupported by this adapter**:
`body.rs::{direct_streaming_body,coalescing_body}` map reqwest `bytes_stream()`
items to `Frame::data`; they cannot forward trailer frames. No H1 trailer pass
is claimed. The lane explicitly retains the existing H2/gRPC hop-by-hop trailer
filter, H2-frontend/H3-backend streaming trailer policy, and delayed-FIN trailer
forwarding cases with both builds. These supported-protocol gates remain
necessary for future shared-coalescer work; root must disposition the H1
adapter limitation separately.

## Open obligations before any optimization

Actual syscall collection is **not implemented**. AsyncWrite polls, TLS records,
logical body frames and `/proc/io` accounting are four different quantities.
The artifact explicitly records syscall collection unavailable, permission not
probed and loss unknown. A separately budgeted intrusive pass must establish
capabilities/permissions, PID/TID and socket/FD lifetime attribution, successful
write/writev/send* returns, lost events and measured tracing overhead. No inference
from a zero field or missing trace closes that obligation. Sampled CPU stacks and
native/hidden copy completeness also remain open.

The live cadence/safety gates above must pass on the exact reviewed head before
any later aggregation/adapter optimization. They cover only their declared
contracts, not H1 trailers, all policy modes, full native memory/copy coverage,
syscalls, sampled CPU, backpressure saturation or performance. Syscall/CPU
tracing remains later work after the H3 foundation settles.
Review allocator safety/publication, the nondefault feature's hosted results,
calibration, partial-profile residuals, all-size traffic failures and source
coverage before interpreting measurements. #5588 is not closed by instrumentation.
