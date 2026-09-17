# Gateway benchmark audit — 17 September 2026

Ferrum's strongest repeatable losses are HTTPS/1.1 at medium and large payloads,
1 MiB WebSocket messages, and UDP. Small HTTP/2 and gRPC requests merit attention,
but correctness problems make several apparent wins and losses provisional.
The Envoy HTTP/3 stream cap is an unequal workload restriction. Removing it
passed the local correctness checks described below, without establishing a
consistent throughput improvement. There is no evidence yet that one change
will make Ferrum faster than every competitor.

**Evidence and scope.** [Run 35071334026](https://github.com/ferrum-edge/ferrum-edge/actions/runs/35071334026)
tested `ff96f30468517706695538ffc74bc6770014ab07`, 15 seconds, base concurrency
200, three iterations. I downloaded and inspected all 359 JSON samples and
their stderr files. There are 141 distinct gateway/protocol/payload groups;
direct baselines run only in iteration 1. Concurrency scales to 100 at 1 MiB
and 50 at 5 MiB. The 512000-byte payload is **500 KiB**, despite some older
comments calling it 512 KiB. [Extracted measurements](benchmark_audit_2026_09_17_results.json)
retain per-iteration rates, error counts, byte totals, and p99 latency.

[Run 35195212169](https://github.com/ferrum-edge/ferrum-edge/actions/runs/35195212169)
tests `d8a37c6911aba89112fd2571e9364118964e7955`. Its results were still pending
when this initial analysis was written. Its benchmark files are identical to
the earlier run; changes between the two commits affect Ferrum. The source
audit used local checkout `29b751eef` and checked differences against the run's
commit. The body, TCP relay, UDP relay, and direct-H2 pool findings below apply
to the run's revision too.

**Clean losses worth pursuing.** Values below are means across all three
iterations; both named gateways completed work with zero reported errors and
correct byte totals in all three. Other competitors in the same scenario may
have failed, so these are pairwise observations, not a complete scoreboard.
Percentages mean competitor RPS / Ferrum RPS minus one. Small differences need
interleaved replication before they justify architectural changes.

| Protocol | Payload | Ferrum RPS | Competitor RPS | Competitor lead |
|---|---:|---:|---:|---:|
| HTTPS/1.1 | 10 KiB | 24,802 | Envoy 26,512 | 6.9% |
| HTTPS/1.1 | 500 KiB | 1,053 | Envoy 1,286 | 22.2% |
| HTTPS/1.1 | 1 MiB | 546 | Tyk 636 | 16.5% |
| HTTPS/1.1 | 1 MiB | 546 | Envoy 616 | 12.8% |
| HTTPS/1.1 | 5 MiB | 125 | Tyk 140 | 12.0% |
| HTTPS/1.1 | 5 MiB | 125 | Envoy 131 | 4.4% |
| HTTP/2 TLS | 10 KiB | 13,300 | Envoy 13,878 | 4.4% |
| WSS | 500 KiB | 976 | Tyk 990 | 1.4% |
| WSS | 1 MiB | 466 | Tyk 523 | 12.3% |
| UDP | 1 KiB | 77,681 | Kong 81,643 | 5.1% |

KrakenD's HTTPS/1.1 means are 1,459 / 778 / 178 RPS at 500 KiB / 1 MiB /
5 MiB, roughly 39–43% above Ferrum. Every one of those groups contains errors;
only the third 5 MiB sample is clean. This is an optimization lead, not an
error-free victory. Envoy's 10 KiB gRPC mean is 13,855 versus Ferrum's 11,494
(20.5% higher), but Ferrum's second iteration recorded 159 errors. Both clean
Ferrum iterations also trail Envoy; first diagnose the failing iteration.

Ferrum already leads Envoy on larger HTTP/2 and gRPC payloads, larger TCP/TLS
payloads, and smaller WSS messages. Protect those paths during optimization.
The reported HTTP/3 lead is approximately 3.2–4.7 times, but the old Envoy cap
prevents treating that as an equal-concurrency comparison.

**Correctness and measurement problems.** Forty-seven of 359 samples are
invalid under the common requirements of positive successful work, zero
errors, and `total_bytes == total_requests * payload_size`.

| Ferrum case | Errors in iterations 1 / 2 / 3 | Evidence |
|---|---:|---|
| HTTP/2, 70 KiB | 177 / 168 / 0 | stderr includes HTTP 502 responses |
| gRPC TLS, 10 KiB | 0 / 159 / 0 | JSON error counters |
| gRPC TLS, 70 KiB | 195 / 0 / 0 | JSON error counters |
| WSS, 5 MiB | 20 / 15 / 11 | 30-second echo timeouts in every iteration |

Kong TCP/TLS iterations 2 and 3 report zero requests **and zero errors** at
every payload. The shared `collect_results` discarded failed task outcomes
after logging them. Kong also has gRPC wall-clock timeout placeholders.
The old summary averaged these observations and displayed only the last
iteration's error count; its scoreboard did not exclude positive-RPS rows
with errors. Re-rendering the artifacts with the revised validity rules
excludes 16 of 31 opposed scenarios. The remaining 15 still include old H3
measurements: passing validity checks does not prove configuration parity.

The following limitations remain even after the reporting repair:

- Client, backend, and gateway share a runner. Throughput includes their CPU,
  memory, scheduling, and TLS costs. Direct/gateway RPS differences are useful
  diagnostic ratios, not measurements of proxy CPU overhead.
- Gateway order is fixed and direct baselines are not repeated. Runners differ
  between protocols: the logs show EPYC 9V45, 9V74, and 7763 machines. Compare
  competitors within a job; use paired/interleaved runs for revision comparisons.
- The H3 deadline starts before sequential connection establishment. Successful
  requests admitted before the deadline can finish afterward, yet RPS divides
  by the nominal duration. Short, slow runs are particularly sensitive to this.
  Establish connections, warm up, synchronize workers, then measure a common
  interval and report drain time separately.
- Failed workers retire, so concurrency can fall during a sample. The JSON's
  `effective_concurrency` is a requested worker count, not observed active
  streams. Record worker loss and actual concurrency/queueing in a future
  harness revision; invalidate any failed sample rather than retrying it away.

**Envoy HTTP/3 history and repair.** The configuration history is unusually
helpful: [PR #533](https://github.com/ferrum-edge/ferrum-edge/pull/533),
[PR #552](https://github.com/ferrum-edge/ferrum-edge/pull/552), and
[PR #554](https://github.com/ferrum-edge/ferrum-edge/pull/554).
The first changes adjusted windows and buffers after resets. The last combined
four-stream limits, disabled route timeout, strict status/body validation, and
an actual TLS fix: explicit `sni: localhost`. Its investigation observed local
503 replies because the upstream hostname was empty. Older higher numbers
therefore cannot automatically be interpreted as useful successful throughput.

At concurrency 200 the client's 21 QUIC connections can offer about ten streams
each, while Envoy's four-stream setting admits at most 84 simultaneously. At
concurrency 100 the limit is 44; at concurrency 50 it is 24. The fixed client
pool cannot create extra downstream connections to compensate. Envoy's
[v1.33.5 upstream pool](https://github.com/envoyproxy/envoy/blob/v1.33.5/source/common/http/http3/conn_pool.cc)
also uses the configured stream limit for upstream client capacity.

The old rationale, `4 * 6 MiB = 24 MiB`, is not a QUIC safety requirement.
Connection and stream flow-control credit advances as data is consumed; a
connection need not have credit for every whole body simultaneously.
Backpressure must operate when credit is exhausted.
[RFC 9000 §4](https://www.rfc-editor.org/rfc/rfc9000.html#section-4)
and [Envoy's QUIC integration](https://github.com/envoyproxy/envoy/blob/v1.33.5/source/docs/quiche_integration.md)
describe these mechanisms. The [v1.33.5 protocol options](https://github.com/envoyproxy/envoy/blob/v1.33.5/api/envoy/config/core/v3/protocol.proto)
do cap the connection window at 24 MiB; that fact alone does not justify four streams.

The candidate uses Envoy's normal **100-stream** limit on both legs, retaining
6 MiB stream windows, 24 MiB connection windows, 128 MiB connection buffers,
disabled route timeout, trusted CA, explicit SNI, and byte-for-byte HTTP 200
echo validation. It introduces no retries, buffering filter, or protocol fallback.

Local validation used the unchanged benchmark client/backend:

- Native macOS Envoy 1.37.1: limits 4, 16, and 100; all five payloads; 200/100/50
  workers as in the workflow; five seconds per sample. All 15 samples completed
  with zero errors and exact byte totals.
- Pinned Linux Envoy 1.33.5: limits 4 and 100; all five payloads; the same scaled
  worker counts; ten seconds per sample. All ten samples completed with zero
  errors and exact byte totals. Config validation passed for both settings.
  Envoy ran natively as ARM64 in Colima; the x86 client/backend ran under
  emulation in a container sharing its network namespace. Initial attempts to
  emulate Envoy itself failed at socket-option setup and were discarded as
  environment failures. Neither architecture is the hosted x86 runner.

The local rate changes were mixed, without a consistent improvement from
lifting the cap. These checks justify removing the artificial admission
restriction; they do **not** prove it accounts for Envoy's throughput deficit
or guarantee a clean hosted run. A hosted rerun of the candidate remains the
performance and correctness acceptance check.

**Hot-path findings and ranked experiments.** These are source-supported
mechanisms and testable hypotheses, not claims from a CPU profile.

1. **Fix buffered-writer progress before tuning WSS.**
   `src/proxy/tcp_proxy.rs::poll_copy_direction` switches back to reading after
   `poll_write` accepts bytes and returns `Pending` on an idle reader without
   flushing the writer. A buffered writer may have accepted plaintext while
   retaining ciphertext. `tokio-rustls` 0.26.4 explicitly allows that outcome.
   Tokio's own `CopyBuffer::poll_copy` flushes when reads are pending to prevent
   the corresponding deadlock. I reproduced the omission using the exact
   extracted Ferrum polling function, replacing only its buffer allocator and
   inactive timing/error helpers: five bytes accepted into a `BufWriter`, zero
   bytes delivered while the client stayed open, immediate exact delivery after
   explicit flush. This proves the generic relay defect, not its responsibility
   for each CI timeout. Reproduce through actual rustls backpressure next.
   The shared helper serves WSS tunnel mode and userspace TCP/TLS; H2 byte
   tunnels also need parity checks. Preserve idle/write deadlines, half-close
   behavior, cancellation and error attribution when adding flush progress.

2. **Measure HTTP/1.1 framing and TLS write cadence.**
   Ferrum's benchmark already disables response buffering and body-size limits,
   selecting `direct_streaming_body`; recommending “turn on streaming” or
   removing its coalescer would miss the actual tested path. Streaming response
   framing removes Content-Length and advertises an unknown body length, so
   HTTP/1.1 uses chunked transfer. The typed body is adapted through reqwest,
   error/deadline wrappers, and the final proxy body. In comparison,
   KrakenD/Lura's no-op path retains a response reader and forwards headers
   into `io.Copy`; Tyk uses a reusable body-copy buffer. Profile frames, TLS
   records, writes, copied bytes, and allocations at 10/70/500 KiB and 1/5 MiB.
   A promising experiment is bounded aggregation matched to TLS record cadence,
   with a zero-copy single-frame path and prompt flushes. A narrowly scoped
   first A/B is `FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES=0` versus `1`: all measured
   bodies exceed one byte, so the latter selects the existing coalescer without
   fully buffering these responses. Another experiment is a dedicated
   H1 sender/body path to reduce adapter and header conversion overhead. Do not
   restore an unverified or plugin-authored Content-Length: truncation, trailers,
   and late policy rejection must remain observable.

3. **Reduce shared pool work for small HTTP/2 and gRPC requests.**
   Envoy owns connection pools per worker, keeping pool operations local to
   its event loop. Ferrum's direct-H2 and gRPC acquisition already reuse a
   thread-local key buffer, but still resolve a shared round-robin counter,
   increment it, probe shared pool shards, clone senders, and test readiness.
   Measure this cost before changing architecture. Test a generation-bound,
   route-owned pool handle or a carefully invalidated worker-local hot cache.
   Preserve every transport-affecting key dimension, TLS/SVID generation,
   reload atomicity, and sender readiness. Tokio tasks can migrate; a naive
   thread-local async connection pool is not equivalent to Envoy's model.
   Diagnose the 70 KiB 502/gRPC failures before accepting an RPS improvement.

4. **Reduce repeated UDP session bookkeeping; measure occupied batch size.**
   Ferrum already uses recvmmsg, sendmmsg/GSO machinery, a last-client cache,
   and nonblocking upstream `try_send`. It is not missing basic batching.
   The datagram path nevertheless checks the pending-session map before the
   established-session cache/map and updates shared counters/budgets. With
   200 interleaved clients, a one-entry last-client cache has limited locality.
   NGINX's stream proxy keeps per-session buffers and upstream state in its
   worker event loop. Profile lookup/cache misses and wakeups, then test a
   small cache keyed by the complete destination/owner/generation identity,
   or established-session-first lookup with explicit setup-race coverage.
   Retain authorization expiry, destination revocation, amplification budgets,
   pktinfo/source address semantics, and per-session ordering. A 5% observed
   gap does not justify weakening any of these boundaries.

Relevant primary source implementations:
[Envoy buffer slice move/coalescing](https://github.com/envoyproxy/envoy/blob/v1.33.5/source/common/buffer/buffer_impl.cc),
[Envoy connection-pool model](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/connection_pooling),
[Tyk v5.3.0 HTTP copy and upgrade relay](https://github.com/TykTechnologies/tyk/blob/v5.3.0/gateway/reverse_proxy.go),
[Lura v2.14.1 no-op response parser](https://github.com/luraproject/lura/blob/v2.14.1/proxy/http_response.go),
[Lura no-op renderer](https://github.com/luraproject/lura/blob/v2.14.1/router/gin/render.go),
[KrakenD v2.13.2 dependency pins](https://github.com/krakend/krakend-ce/blob/v2.13.2/go.mod),
and [upstream NGINX stream relay](https://github.com/nginx/nginx/blob/release-1.27.1/src/stream/ngx_stream_proxy_module.c).
The NGINX source illustrates the underlying design; its precise correspondence
to every Kong vendor patch has not been established.

**Changes prepared from this audit.** The benchmark now counts failed/panicked
workers, checks H3 request-finish errors, reports validity across every iteration,
withholds scenario wins when a measured competitor is invalid or incomplete,
and excludes exact ties. A manifest records the requested matrix before startup
so a gateway that never starts cannot disappear from the comparison. Raw
observations remain available. Backend logs,
gateway logs and Envoy counters are captured after each timed sample, outside
the JSON summary glob, so future failures can be diagnosed. The Envoy H3 cap
is lifted as described above. These are harness changes; the proxy performance
experiments and the production relay fix remain follow-up work.

Acceptance for performance work: reproduce the failure first, preserve strict
status/body/trailer validation, run at least three interleaved baseline/candidate
measurements on the same runner, retain all errors, and record proxy/client/
backend CPU separately. Require zero errors in every accepted iteration and
check p99 alongside useful throughput. Include realistic smaller HTTP payloads
and long-lived streams as well as this large echo workload.
