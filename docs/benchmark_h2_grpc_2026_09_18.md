# H2/gRPC adaptive-window observation — 18 September 2026

The controlled campaign reproduced request failures in one adaptive H2 sample
and one adaptive gRPC sample. Fixed-window samples had no request errors, but
these observations do **not** establish a throughput improvement or a production
fix. Issue [#5588](https://github.com/ferrum-edge/ferrum-edge/issues/5588) remains
open for protocol diagnosis and the separate profiling/fairness work.

## Reproduction and provenance

[Hosted run 35393243172](https://github.com/ferrum-edge/ferrum-edge/actions/runs/35393243172)
measured exact revision `d4d7b7c7110c48cf3945837cb0762e489f52a8f4`.
The two benchmark jobs completed successfully; their success means the campaign
and artifact collection completed, not that every request or comparison passed.
The extracted [36 observations](benchmark_h2_grpc_2026_09_18_results.json) retain
failures, phase boundaries, observed concurrency, p50/p99, process CPU/RSS,
config/sample hashes, bounded event groups and the runner's paired decisions.

Raw artifacts on that run are named:

- `gateways-protocol-bench-http2-d4d7b7c7110c48cf3945837cb0762e489f52a8f4`
- `gateways-protocol-bench-grpcs-d4d7b7c7110c48cf3945837cb0762e489f52a8f4`

Canonical samples are `run_1/pairs/pair_*/*.json`. The root
`run_1/<gateway>_<protocol>_<size>.json` files are four-pair aggregate summaries:
they contain the canonical records in `samples`, summed request/error/byte/
duration fields, aggregate rates and conservative per-sample latency maxima
(with a request-weighted average latency). Some inherited metadata, including
the root `h2_observation`, comes from the last sample. These summaries must not
be counted as additional independent observations. Each canonical sample has
stderr and cumulative gateway/backend diagnostics; the artifacts also contain
the actual route YAML, manifests, order balance, image identities and runner log.

Each protocol used four counterbalanced pairs, a repeated direct control,
15-second measurement windows and 200 offered workers. H2 used 71,680 bytes;
gRPC used 10,240 and 71,680 bytes. Every sample reached the 200-worker barrier,
observed 21 client physical connections, and accounted for exact successful
payload bytes. Neither failed sample may be accepted based on its remaining
successful requests. There were no reported phase/close timeouts, stalled
workers, client/backend event suppression, capture errors or incomplete process
CPU brackets in these 36 samples. Tonic's detached backend driver remains
unobserved; an empty backend event list does not certify transport health.

The campaign records contain no client gRPC reconnects. The subsequent observer
repair makes failed/cancelled reconnects and socket retirement invalidate the
current physical identity while retaining the channel ID. It does not change
these measured failure counts or their existing connection attribution, and
does not establish a throughput gain or a production transport fix.

Both hosted VMs reported four visible CPUs, AMD EPYC 9V74, Microsoft hypervisor,
15 GiB displayed memory and Ubuntu runner image `20260907.300.1`. The initial
five-second CPU-steal check reported 0%; it does not characterize the whole run.
All arms share a VM and image **within each protocol**. H2 and gRPC used different
VMs/images, so their rates cannot form cross-protocol paired comparisons:

| Protocol | Host ID | Ferrum image ID |
|---|---|---|
| H2 | `9975e30b-371c-4ccb-8f8a-bf6b5d6e9dbf` | `sha256:a3eeee033d464190ff08182c267aa2203b97e2977273bb8c53f6ccaa354767fb` |
| gRPC | `7047265a-1835-4102-846f-b7b5197f092c` | `sha256:748ade80e0fa2b064b2eedfc99b89f05fcbb4d5a2100dd13087ba3dd4a64b205` |

Root verified each of the 16 mounted route-file hashes against its manifest.
The only route difference between Ferrum arms is adaptive-window true/false.
Both retain configured 8 MiB stream / 32 MiB connection windows, 1 MiB maximum
frames, 1,000 stream setting, configured pool width 16 and 5/30/30-second backend
timeouts. Hyper's adaptive builder resets the initial windows to 65,535;
the fixed arm retains the configured sizes. These are builder inputs, not
observed negotiated credit. Both arms retain the same TLS verification, offered
load, validation, retries and protocol defenses. See the
[harness contract](../tests/performance/multi_protocol/README.md#h2grpc-transport-observation-campaign-5588-section-3).

## Retained failures and comparison decisions

| Protocol / payload | Adaptive request errors, pairs 1–4 | Fixed request errors, pairs 1–4 | Direct request errors, pairs 1–4 |
|---|---|---|---|
| H2 / 70 KiB | 361, 0, 0, 0 | 0, 0, 0, 0 | 0, 0, 0, 0 |
| gRPC / 10 KiB | 0, 0, 0, 0 | 0, 0, 0, 0 | 0, 0, 0, 0 |
| gRPC / 70 KiB | 0, 0, 156, 0 | 0, 0, 0, 0 | 0, 0, 0, 0 |

**H2, adaptive pair 1.** There were 57,600 successful requests and 361 errors:
310 client-observed remote `RST_STREAM` errors with reason 11
(`ENHANCE_YOUR_CALM`), plus 51 HTTP 502 validation failures. Fifty-one workers
retired; mean active workers fell to 149.55 (minimum 149). The first client
error occurred at Unix time `1789766517.5857959`, about 52 ms after measurement
began. The captured burst ended at `1789766517.7421758`.

The backend's `diagnostics/ferrum_71680_backend.log`, connection 47, records a
remote GOAWAY reason 11 at `1789766517.7281408`, with debug subtype
`too_many_data_frames`. This identifies a Ferrum-side receive DATA-frame guard
on that connection; the backend is reporting a GOAWAY received from Ferrum.
It occurs after the first client errors and does not establish one-to-one
causality for all 361 failures. Process-local connection IDs are not cross-hop
identities; cross-process wall-clock skew was not measured. Gateway terminal
records in this sample occurred after measurement and do not expose the reqwest
backend driver's cause.

All H2 proxy arms also showed backend connection churn during warmup, including
broken-pipe terminations. Adaptive warmup opens/terminations were 45/44, 55/54,
89/88 and 74/73; fixed were 22/21, 55/54, 43/42 and 85/84. The failing adaptive
sample additionally had 46 opens/terminations during measurement. These counts
are retained separately from request errors. Direct pair 2 also had a backend
broken-pipe close event. The strict paired validator rejects all three H2
comparisons because captured transport errors invalidate declared repetitions.
There is no accepted H2 throughput comparison, including fixed versus direct.

**gRPC, adaptive pair 3 / 70 KiB.** There were 54,437 successful requests and
156 errors: 152 typed remote stream resets with reason 11 and four `Unavailable`
responses saying `Backend unavailable`. Each error retired a worker; mean active
workers fell to 52.31 (minimum 44). Measurement began at `1789766564.9467857`;
client errors occurred at `1789766565.793415`–`1789766565.8021455`.

The gateway logged `backend_grpc_tls` connection 23 terminating at
`2026-09-18T21:22:45.791196Z`, with kind `goaway`, reason `ENHANCE_YOUR_CALM`, and
initiator `local_library`. This places a locally generated upstream GOAWAY near
the client failure burst. The diagnostic deliberately excludes debug bytes,
and tonic backend-driver results are unavailable; the H2 DATA-frame subtype
is not established for this gRPC connection.

Gateway logs are cumulative across payloads within an arm. The 21 earlier
frontend terminal records in the 70 KiB log belong before that sample's
measurement, and another 21 occur afterward. Only the upstream event above
falls inside its measurement window. No other sample has a captured gateway
terminal event inside its measurement window; this bounded observation is not
proof of fault-free transport.

All adaptive-involving gRPC 70 KiB comparisons are rejected. The valid gRPC
10 KiB fixed/adaptive paired ratio is 1.0313, with 95% interval
0.9267–1.1476: uncertainty overlaps no gain. The direct-control ratios are in
the extracted JSON; all processes and observers share the VM, so those ratios
are not isolated proxy CPU costs. The fixed 70 KiB results justify further
controlled diagnosis, not accepting the failed adaptive comparison or changing
production defaults.

## Source-derived guard limits

The relevant lockfile chain is h2 0.4.19 / Hyper 1.9.0. The pinned
[h2 counter implementation](https://github.com/hyperium/h2/blob/v0.4.19/src/proto/streams/counts.rs#L80)
has two distinct triggers behind
[`too_many_data_frames`](https://github.com/hyperium/h2/blob/v0.4.19/src/proto/streams/streams.rs#L639):
small non-final DATA frames can exhaust a framing-overhead budget, and a
separate lifetime counter rejects the 101st empty non-final DATA frame. Final
DATA frames are exempt. Polling or clearing queued small frames returns their
charge; sufficiently large frames also replenish credit. The artifacts do not
record which branch triggered.

The [initial automatic budget](https://github.com/hyperium/h2/blob/v0.4.19/src/proto/connection.rs#L89)
is half the initial connection window, with a minimum of 25,600. Consequently
these builder settings imply 32,767 for adaptive versus 16,777,216 for fixed.
These are limits, not observed memory allocations. Hyper's later BDP window
updates change byte flow control without resizing this initial framing ceiling.
A larger framing budget would not solve the separate empty-frame limit. This
source relationship is a diagnosis lead; no DATA sequence was captured to
prove that the smaller budget caused either observed burst.

The 51 failed H2 header requests use the unique `Backend request failed`
reqwest dispatch log site in `src/proxy/mod.rs`; this identifies their transport
path, not every request in the sample. Reqwest applies the same initial-window /
adaptive builder sequence in `src/connection_pool.rs`. The direct-H2 pool's
resident entry may serve other work, including a capability probe; its precise
use in this run was not logged.

## What this observation does not resolve

The configured 16 shards are not 16 observed active upstream connections.
Resident direct-H2 entries and client-local active streams do not measure the
reqwest backend path or per-backend stream occupancy. The H2 resident gauge was
one in both Ferrum arms; that fact cannot establish actual request multiplexing.

The next bounded observation must distinguish DATA sizes, final versus non-final
frames, empty non-final frame counts, framing-budget debits/credits, and the
specific local guard that emits GOAWAY. Preserve the same offered load and
security/resource limits, including the frame/reset/flood guards. Trace the
reqwest backend driver as well as native gRPC, and investigate warmup churn
separately. Do not disable the guard or raise a budget merely to obtain a clean
benchmark. A deterministic protocol regression and fresh hosted measurements
are required before claiming a repair.

The experiment manifest is disabled after recording this campaign, so ordinary
benchmark dispatches do not silently select these special arms. The measured
revision and raw enabled manifest remain pinned above. Allocation/copy/syscall
profiles, H2 pool-acquisition costs, UDP occupied batches/session work, corrected
Envoy H3 and exercised kernel/offload evidence remain separate #5588 work.
