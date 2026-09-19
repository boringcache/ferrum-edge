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
  --ref codex/20260918-5588-h1-profile -f payloads=all -f diagnostic_only=true
```

`diagnostic_only=true` is the default: it runs the bounded slice below, then
stops. Root must pin and verify the dispatched head against the pushed branch
before interpreting artifacts; the command selects a ref, not an immutable SHA.
For full profiles after reviewing the slice, root uses the same command with
`-f diagnostic_only=false`. That dispatch includes its own diagnostic slice;
there is no automatic rerun. `payloads` is `all` (default), `10240`, `71680`,
`512000`, `1048576`, or `5242880` and applies only to full profiles. Root can
budget separate size dispatches; all five remain required. Each comparison's two arms and repeated direct controls share one VM.
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

`h1_internal_profile.py` requires schema-2 traffic samples bound to the expected
pair, gateway, payload and nonempty campaign host ID. The runner manifest records
the H1 mode, `http1-tls` selection, 15-second duration and base 200 workers; each
sample must carry the producer's `HTTP/1.1+TLS` protocol, 15-second measurement
phase and both worker fields matching the committed 200/200/200/100/50 size table.
Legacy samples, copied rows, aggregate samples, wrong-host samples and substituted
workloads remain failed observations. Invalid/missing manifest selections retain
the full expected matrix; valid budgeted payload subsets retain every selected
pair/arm/size and do not satisfy the separate all-five-size campaign obligation.

Profile brackets have a **two-second total boundary-slack limit**, including the
last scrape's duration, and a **one-second maximum start-to-start sampling gap**
for the fixed 500 ms sampler / 200 ms HTTP timeout. They require an observation
inside measurement, nonnegative integer sample IDs increasing consecutively,
strictly increasing finite wall/monotonic timestamps, nonoverlapping captures,
and wall/monotonic elapsed agreement within **50 ms of the first bracket sample**.
Process observations must precede their scrape by at most one second. These are
fixed acceptance limits, not bounds enlarged to rescue scheduling stalls. Excess
slack, skipped samples and discontinuities retain available published deltas as
partial evidence. Each accepted row needs present, finite, nonnegative numeric
sampler CPU (booleans excluded); invalid overhead remains null with an issue,
never silently zero. A measured zero CPU value is valid.

The runner retains the owned container's full ID, host init PID/start ticks,
host-network mode and fixed `http://127.0.0.1:9000/metrics` endpoint. The sampler
checks that record against the selected container ID. Before **and** after each
scrape it rereads `/proc` start ticks and `NSpid`, requires exactly one observed
gateway, and joins the unique IPv4 loopback port-9000 LISTEN inode to that
process's fd table. The stored namespace PID must equal the exported metrics PID
at every accepted row; before/after and successive bindings must agree with the
retained runtime. This distinguishes unrelated containers exporting PID 1.
Missing permissions/ownership records, reuse, restarts, stale mappings and
ambiguous listeners produce partial profiles. This is bounded listener ownership
evidence, not a new syscall/connection tracing facility or a cryptographic artifact
attestation. Older captures without the binding cannot become complete retroactively.

The fixed export remains **206 counters + eight metadata fields (214 total)**.
The consumer requires positive metrics PID, capacity 128, and 1–128 registered
slots that never decrease. Successful traffic requires positive advancement of
`body_proxy_output_all_data_bytes`, the guaranteed response DATA boundary for
this H1 workload. It does not require optional coalescing, copy, vectored-write
or EOF counters to advance, nor equate bracket bytes with measured client bytes.
Missing/malformed/decreasing counters, missing slots, loss and overflow remain
failures. Idle-thread tails explicitly prevent complete allocation coverage.
Useful traffic validity is separate from profile completeness. Every expected
arm/pair/size is retained, including missing samples and failed 5 MiB observations.
The hosted H1 Python suite exercises complete producer-shaped campaigns and
negative campaign, timing, identity, metadata/work and CPU cases, including
written full-matrix reports and the capture-to-sampler ownership path.
No surviving-worker average, guessed observer
overhead subtraction, or gain claim is produced. Raw on/off measurements are the
overhead calibration; shared-host process CPU is not isolated proxy cost, and RSS
is not allocation traffic. Scrape overhead is included in the gateway process and
sampler timings, not analytically subtracted.

## Bounded H1 request-drain diagnostic

The retained three 5 MiB drain failures and slow 1 MiB tails still have **no
proven cause or repair**. Process write accounting near 79 kB/s does not identify
socket throughput, TCP pacing, a TLS flush, or an HTTP body boundary. This mode
adds evidence at the client boundary; a clean run alone cannot resolve those
failures. No production `src/`, allocator, body/counter, H3 observer or global
clock implementation is changed by this diagnostic addition. Backend upload EOF,
upstream identity joins, syscall and CPU traces remain later observations; no
cross-hop request identity is inferred from the client IDs.

`proto_bench http1 --h1-diagnostic` is default off. It wraps the existing
`ObservedBody` admission and response `collect()` with last-state observations;
the first transport body poll still admits work, and the existing status/exact
bytes/content check still determines useful completion. It adds no warmup,
retry, request deadline, flush or measurement extension. The existing `Phases`
coordinator (the harness phase coordinator) supplies the narrow phase/snapshot
hooks; the real connection still owns the existing `ConnectionGuard`.

The parent-owned registry survives cancelled worker futures. Each registered
worker has a numeric worker ID and one latest request record, with globally
increasing numeric request and connection IDs within that diagnostic session.
Connection records retain numeric local/peer socket tuples when available;
missing tuples are null, never fabricated. Request-body first poll, accepted
body bytes, last progress and body end; response status/version, parsed
Content-Length and framing flags; response DATA bytes, last progress, end/error
class and validation completion are separate observations. No paths, arbitrary
header values, payloads or credentials enter this registry. Header flags are
meaningful only when the headers timestamp is present. Null completion/end/error
means unobserved, not success. Errors use bounded classes, not arbitrary error
strings. Lifetime offered/admitted/completion/error counters survive cancellation;
they do not reconstruct the lost worker's measured histogram or silently replace
useful-work totals. A stale body cannot update a newer request's record: that
update is counted as capture loss.

Every timestamp carries session microseconds plus phase name and phase-relative
microseconds in `client_process_diagnostic_session_instant_microseconds`, from
one client `std::time::Instant` epoch. Snapshots and the final report name that
clock domain and client PID explicitly. This is **not host CLOCK_MONOTONIC** and
cannot be directly compared with backend, BPF, perf or another process's times.
Measurement/drain classification follows the existing fixed deadline. Session
origin is diagnostic creation, not the generic harness monotonic origin; existing
wall timestamps remain approximate cross-process context only. Generic clocks
are left for root and the separate H3 repair.

At warmup +10 seconds, if workers have not reached the barrier, the coordinator
captures one `delayed_warmup` snapshot without extending its existing preflight
bound. It snapshots immediately before preflight/drain worker abortion, then
after request collection and after separate driver retirement. Last await and
stage-entry time remain intact on worker drop; lifecycle becomes
`dropped_without_return`, which deliberately does not guess cancellation versus
panic. Snapshot copying briefly serializes diagnostic updates, so this mode is
intrusive and is excluded from the full off/on performance comparison.

Bounds per client invocation: 256 worker records, 512 connection records, four
snapshots, fixed-size fields and no per-packet/request history. Omitted records,
stale/unrecordable updates, snapshot overflow and poisoned locks are explicit
loss counters; any loss makes diagnostic completeness fail. Numeric socket
addresses and static enums bound strings. Compact serialized diagnostic state is bounded below 4 MiB at these capacities;
the hosted capacity regression checks the compact report. Budget up to 16 MiB
for the pretty-printed diagnostic report in stdout and 4 MiB for the four compact
stderr snapshots per invocation; the single slice has three client invocations. Existing process/startup logs and build/debug artifacts retain their
existing bounds and are not covered by that diagnostic byte budget. Snapshots
are emitted immediately as `H1_DIAGNOSTIC` JSON lines, then included in
`phases.h1_diagnostic`, so an outer timeout need not erase pre-abort evidence.

Only when enabled, driver handles are owned in a bounded `JoinSet`, finished
handles are reaped during connection registration, and remaining handles are
reaped **after all request workers join**. At most 512 live/unreaped driver
handles are accepted; capacity rejection is an explicit failed worker and a
retirement error, never a silent detach or a valid workload sample. Connection
metadata overflow alone does not stop admission. The declared 50-worker slice
fits both capacities; the bounds are diagnostic resource guards, not tuning.
Retirement allows 5 seconds, then requests abort and allows 1 second to reap;
any remaining handles are counted `unreaped_after_abort` and dropped with abort
requested. Normal completion, Hyper error, cancellation, panic, pending/aborted
and unreaped counts are distinct. `completed_ok` means the Hyper driver returned
`Ok`, not peer FIN, TLS close_notify or successful request completion. In
[Hyper 1.8.1's dispatcher](https://github.com/hyperium/hyper/blob/v1.8.1/src/proto/h1/dispatch.rs#L306),
a response parse error delivered to `SendRequest` can be followed by driver
`Ok`; the malformed-header regression asserts both observations separately. The old
H1 `transport_close_secs=0`/false defaults are still **unobserved** when this mode
is off. They must never be interpreted as successful transport closure. The
new retirement report is authoritative only when present; driver retirement
never increments useful request completions or replaces request-drain timing.

The existing manual workflow builds its same-revision twins and common harness,
then runs exactly one direct/cutoff-0/cutoff-1 pass using the observer-off gateway
image and diagnostic-on client. Each arm uses 5 MiB, 50 workers (the unchanged
200-base scaling), one full-payload warmup, 30-second measurement, 30-second
request drain, and unchanged timeout/guard/TLS policies. Preflight remains
70 seconds and the runner's existing outer bound remains 190 seconds per arm;
the selected campaign budget is 900 seconds. No optional 1 MiB control, automatic
retry or adaptive extension is added. Failed diagnostics block full profiles on
that dispatch. The runner retains original/partial client stdout as
`diagnostics/<arm>_5242880_client.raw.json` and exit status before writing any
error placeholder or metadata; stderr, each sample, runtime config, process
usage, image identity, gateway/backend logs, and the diagnostic report are all
retained in `h1-profile-evidence/diagnostic/`. Upload remains unconditional,
14 days, in `h1-internal-profile-<sha>-<payloads>`. The three-arm report includes
missing/failed arms and always sets `comparison_eligible=false`.

Hosted registration: `metrics_tests::h1_diagnostic_tests` exercises actual plain
and rustls H1 worker paths, opt-in/off useful-work parity, clean responses,
length/chunk truncation, malformed headers, the unchanged delayed warmup and
30-second pre-abort hooks, cancellation-preserved counters, capacity/stale-update
loss and separately timed driver cancellation. It is selected explicitly in the
existing H1 checks job and included by the existing Benchmark Harness Tests
`metrics_tests` target. Python selection/report/registration regressions run in
both existing Python discovery gates. All cadence and supported-trailer gates
remain registered unchanged. These are registrations only: no repository code,
formatter, linter, test, build or benchmark was executed locally.

## Live cadence and safety gate

`tests/functional/h1_cadence_tests.rs` is registered in the functional binary on
Linux and explicitly selected by the dedicated `cadence` job. The existing
`functional_streaming` filter does not select it. Each observer-off/on matrix
job compiles and lints the functional target, builds and copies its external
binary, pins `FERRUM_EDGE_TEST_BIN`, and retains the revision, binary SHA-256,
test output and failures in `h1-cadence-{off,on}-<sha>` artifacts. No implicit
harness rebuild is allowed. Measurement now depends on both cadence jobs as
well as the existing checks. PR events run these gates without measurements;
manual dispatch uses the inputs and command above. Full calibration/measurement
requires `diagnostic_only=false` and a successful diagnostic slice. These are hosted registrations;
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
