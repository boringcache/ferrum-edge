# WSS and TCP/TLS missing-payload audit — 19 September 2026

[Compact machine-readable results](benchmark_wss_tcp_2026_09_19_results.json) preserve all 72 samples, all 542 artifact-file hashes, validation dispositions, resource summaries and paired intervals. Paths in this report refer to files inside the [combined raw artifact](https://github.com/ferrum-edge/ferrum-edge/actions/runs/35416659065/artifacts/10577855089). The raw artifact is subject to GitHub retention; its absence must never be interpreted as successful revalidation. The committed compact results omit raw process timelines, individual transport records and full logs.

All **72 expected canonical samples are present and pass the independently checked client useful-work, phase, identity, and required process-bracket conditions**: 40 WSS and 32 TCP/TLS. None reports a client error, lost worker, measurement timeout, byte mismatch, or unaccounted admitted exchange. This is a qualified same-host observational comparison, not proof of completely clean transport, a production fix, or a revision gain. Tyk startup errors and Envoy connection-destruction/reset counters remain in the evidence and are discussed below.

This read-only analysis addresses [issue #5588](https://github.com/ferrum-edge/ferrum-edge/issues/5588) using [hosted run 35416659065](https://github.com/ferrum-edge/ferrum-edge/actions/runs/35416659065), attempt 1, workflow run number 36, and [combined artifact 10577855089](https://github.com/ferrum-edge/ferrum-edge/actions/runs/35416659065/artifacts/10577855089). The run completed successfully on `main` at `f9b9d053f9401335f9ad1d72283d0cb122fa0bd2`; it was created `2026-09-19T02:46:39Z` and last updated `2026-09-19T03:45:38Z`. Workflow success is only the execution outcome: the [harness explicitly allows individual samples to fail](https://github.com/ferrum-edge/ferrum-edge/blob/f9b9d053f9401335f9ad1d72283d0cb122fa0bd2/tests/performance/multi_protocol/run_gateway_protocol_bench.sh#L27).

The evidence identities and integrity checks are as follows. SHA-256 digests are full digests, not display abbreviations. The artifact inventory digest hashes UTF-8 JSON of the sorted `{path, bytes, sha256}` records with sorted keys and compact separators. Canonical object hashes use the same JSON encoding. The ZIP was fetched through a read-only GitHub API request into memory and every member was matched to the supplied extraction; no archive member was executed.

| Evidence | Identity / result |
|---|---|
| Combined artifact | `gateways-protocol-bench-combined-f9b9d053f9401335f9ad1d72283d0cb122fa0bd2`; 803,037 compressed bytes |
| API and independently downloaded ZIP SHA-256 | `81b51c731a7148ae598482268fe8421961c4ecf1da6775cf1d33ed5a52b9e904`; exact match |
| Extraction | 542 files, 4,699,063 bytes; 0 missing, 0 extra, 0 hash mismatches |
| Sorted input inventory SHA-256 | `ad1f36f1e20c97d267139a772bfa5fb07abfc48f1032c6d64fbfe0e40f8425f1` |
| Inspected source inventory SHA-256 | `9de5349f5cb2fe35769cbe284e9709395f285de22b83beadcc03fdf04dbc50f5` |
| Hosted log archive SHA-256 | `242d088eb9404a7072e9906519fde57d973d39c82ee21e54359e21c213e78f36` |
| observed-samples.json | `bb790665199de4b00f5aa3efbf1b1369fc2c65e2a321e4b17a9ba4af9248c5b7` |
| paired-comparisons.json | `48c6136b5cf1a9d91d165729ba3b403473f8878756d3e0cc59c89c5b543253ab` |
| 512000-byte deterministic payload SHA-256 | `a5a3ca4f72b40a5317e7e5aee4678733d2018b9b71cc72ae7f651b8cdb8574e5` |
| 1048576-byte deterministic payload SHA-256 | `9a5b0b8b2b7f4049e458505a368e23bef57a341a49da6b7f74f92d8c35f026bc` |

Each of the 72 pair-directory JSON objects matches exactly one flattened `observed-samples.json` object after removing its `matrix_protocol` annotation, and exactly one child in its run summary. The index does **not** include run/block provenance; matching only `(host, pair, gateway, payload)` would collide across the two blocks. This audit restores block identity using the unique full-object match and canonical path. There are 36 aggregate summary files, each containing two samples, not 36 extra experiments. Their sums, nominal-duration RPS, and maximum-per-sample quantiles reconcile. The 48 existing per-block comparison estimates and their rounded-t intervals also recompute exactly. No failed row was discarded or selected away.

Within each protocol, both blocks ran on one host; the two protocols used different hosts. Equal CPU model names do not make them the same experimental host. The compact JSON retains machine identities; the linked hosted job logs contain the runner metadata and health-check output.

| Protocol | Hosted job / runner | Boot identity | Measurement starts (UTC) |
|---|---|---|---|
| wss | [105826518680](https://github.com/ferrum-edge/ferrum-edge/actions/runs/35416659065/job/105826518680) / `GitHub Actions 1000657963` | `10910aaa-85de-4143-8f5c-a1a6776a68d5` | 2026-09-19T03:28:26.428089+00:00 to 2026-09-19T03:40:12.941790+00:00 |
| tcp-tls | [105826518594](https://github.com/ferrum-edge/ferrum-edge/actions/runs/35416659065/job/105826518594) / `GitHub Actions 1000657955` | `28e5f3fd-79f7-4788-83ae-7192222342e0` | 2026-09-19T03:35:13.109675+00:00 to 2026-09-19T03:44:53.925347+00:00 |

Both hosted VMs report AMD EPYC 9V74 80-Core Processor, **4 allocated vCPUs**, 15.61 GiB memory, Ubuntu 24.04.5 LTS, kernel `6.17.0-1022-azure`, Docker 28.0.4, and Microsoft hypervisor. The health check reported average steal 0.0% before the build. It is not measurement-period host utilization evidence. Client, backend, gateway, sampler, and for Tyk Redis share the runner; there is no CPU-affinity isolation or measurement-bracketed host contention profile in these artifacts.

Gateway order is forward in pair 1 and reversed in pair 2, repeated in block 2. WSS positions average 3 for every arm; TCP/TLS positions average 2.5. This balances mean arm position but does not randomize adjacency or payload order: 500 KiB always precedes 1 MiB. Direct is refreshed once in each pair, serving all gateways in that pair rather than appearing immediately beside each gateway. Direct-relative measurement-start offsets extend from −145.509 to +148.265 seconds for WSS and −111.155 to +115.864 seconds for TCP/TLS. There are 36 distinct backend `(host, PID, start_ticks)` identities, one per arm/pair, each reused for that arm’s two payloads, and 72 distinct client identities. All eight direct arm/pair backends are fresh. The [orchestration contract](https://github.com/ferrum-edge/ferrum-edge/blob/f9b9d053f9401335f9ad1d72283d0cb122fa0bd2/tests/performance/multi_protocol/run_gateway_protocol_bench.sh#L1059) agrees with those observed identities.

Image provenance is recorded below. Ferrum builds use the same Git revision but have different image bytes across the two hosts; each host reuses its own image across both blocks. `images.txt` records only Ferrum and Envoy. Kong, Tyk, and Redis digests were recovered from the hosted pre-pull logs, which establish the pulled version but do not substitute for per-sample container image inspection. No executable hash is supplied for the native client/backend.

| Image | Full digest and provenance |
|---|---|
| ferrum_wss | `ferrum-edge:bench`; config_id: `sha256:90227bf139221776ab1818fa318381ac889915de41c5e5f81d443002a3b55cb9`; build_manifest: `sha256:0865030e9bdda26db9c95890d6ca8e3151d6c7e35ff91b6a6613fa221f952b0a` |
| ferrum_tcp_tls | `ferrum-edge:bench`; config_id: `sha256:84842280fc51ab3644961b9347cae0bd06f99df65acad8ba8817bb04283f2b78`; build_manifest: `sha256:951e988f1b74c610c91cb268956a56b2c642964ad1471ecc2f0e5d86ef2569c3` |
| envoy | `envoyproxy/envoy:v1.33.5`; config_id: `sha256:0f705ccdd71dd2e5bc39350553f411f856ef113e17e5ff9dbcb48621a53b8eab`; repo_digest: `sha256:7684e69b9cf0af4008d851ec85bfd2874145ed61a1890dd3ff13d359306f923e` |
| kong | `kong/kong-gateway:3.10.0.0`; pull_digest: `sha256:ad58cd7175a0571b1e7c226f88ade0164e5fd50b12f4da8d373e0acc82547495` |
| tyk | `tykio/tyk-gateway:v5.3.0`; pull_digest: `sha256:ac38225052829da509bb327320f7781f638d935ad14ec236350b08d6f3ce5e02` |
| redis | `redis:7.4.1-alpine`; pull_digest: `sha256:c1e88455c85225310bbea54816e9c3f4b5295815e6dbf80c34d40afc6df28275` |

The [WSS configuration](https://github.com/ferrum-edge/ferrum-edge/blob/f9b9d053f9401335f9ad1d72283d0cb122fa0bd2/tests/performance/multi_protocol/configs/wss_e2e_perf.yaml) and [TCP/TLS configuration](https://github.com/ferrum-edge/ferrum-edge/blob/f9b9d053f9401335f9ad1d72283d0cb122fa0bd2/tests/performance/multi_protocol/configs/tcp_tls_e2e_perf.yaml) specify TLS on both gateway legs, upstream CA trust, and 30-second backend read/write timeouts. The [launch contract](https://github.com/ferrum-edge/ferrum-edge/blob/f9b9d053f9401335f9ad1d72283d0cb122fa0bd2/tests/performance/multi_protocol/run_gateway_protocol_bench.sh#L347) enables Ferrum WebSocket byte-tunnel mode, removes benchmark body/connection limits, and sets 30-second TCP idle and half-close bounds. Kong uses its native WSS frame path with an 8 MiB payload limit set through pre-function; its TCP path terminates and re-originates TLS. Tyk’s WSS API is keyless with upstream certificate verification enabled, and its launch installs the generated CA into the container trust store. Envoy uses HTTP/1 WebSocket upgrade or the TCP network filter with upstream TLS and a configured CA. Its archived configs contain no explicit upstream SNI or SAN matcher; this report does not infer equivalent authenticated-identity policy across implementations.

All eight archived Envoy runtime configs are byte-identical to the expected exact-revision templates after the three certificate-path substitutions. Ferrum/Kong/Tyk materialized configs, full container environment/inspection records, and generated certificate fingerprints are absent; their descriptions above are static launch/source contracts, not archived runtime attestations. The client itself uses insecure benchmark certificate verification for both WSS and TCP/TLS. This is not a production TLS-security comparison. The input-file inventory and exact source hashes preserve the boundary between recorded and inferred configuration evidence.

Workload identity also reconciles. WSS direct targets `wss://127.0.0.1:3446` and gateway targets `wss://127.0.0.1:8443/ws`; the proxy configurations strip/rewrite that route to the backend root. TCP/TLS direct targets `127.0.0.1:3444`, gateway targets `127.0.0.1:5001`, with `--tls`. Canonical protocol labels `WebSocket` and `TCP+TLS` are normalized to matrix names `wss` and `tcp-tls`. These are intentional routing differences, not mismatched payloads. The [target mapping](https://github.com/ferrum-edge/ferrum-edge/blob/f9b9d053f9401335f9ad1d72283d0cb122fa0bd2/tests/performance/multi_protocol/run_gateway_protocol_bench.sh#L215) and [deterministic payload generator](https://github.com/ferrum-edge/ferrum-edge/blob/f9b9d053f9401335f9ad1d72283d0cb122fa0bd2/tests/performance/multi_protocol/proto_bench.rs#L277) establish the source contract; payload hashes above independently reproduce the bytes as data.

WSS offers HTTP/1.1 ALPN, one binary echo per worker, and accepts only an exact-length, exact-content binary response; text/close/error frames and 30-second read timeouts fail the echo. TCP/TLS offers one full-duplex echo per worker, writes 64 KiB chunks with flush/yield, reads concurrently, and validates exact echoed bytes with a 15-second exchange timeout. TCP write shutdown has a 5-second bound. See the [WSS client](https://github.com/ferrum-edge/ferrum-edge/blob/f9b9d053f9401335f9ad1d72283d0cb122fa0bd2/tests/performance/multi_protocol/proto_bench.rs#L1014), [TCP client](https://github.com/ferrum-edge/ferrum-edge/blob/f9b9d053f9401335f9ad1d72283d0cb122fa0bd2/tests/performance/multi_protocol/proto_bench.rs#L1294), and [full-duplex exchange](https://github.com/ferrum-edge/ferrum-edge/blob/f9b9d053f9401335f9ad1d72283d0cb122fa0bd2/tests/performance/multi_protocol/src/transport.rs#L18). This equal closed-loop offered concurrency does not mean equal total submitted request counts: faster completions cause more offers.

The measurements include distinct setup, one validated warmup echo per worker, common barrier, exclusive 15-second deadline, and bounded drain. Only validated completions before the deadline enter useful throughput and latency; late successes enter drain totals. Across every row, `admissions = total_requests + drain_requests`, `total_bytes = total_requests × payload`, and `drain_bytes = drain_requests × payload`. Warmup and drain each equal 200 or 100 echoes as appropriate. WSS totals are 605,634 useful echoes / 419,607,818,240 bytes, plus 6,000 warmup and 6,000 drain echoes; TCP/TLS totals are 402,602 useful echoes / 277,932,531,712 bytes, plus 4,800 warmup and 4,800 drain echoes. These sums describe this matrix, not independent events for statistical inference. The [phase controller](https://github.com/ferrum-edge/ferrum-edge/blob/f9b9d053f9401335f9ad1d72283d0cb122fa0bd2/tests/performance/multi_protocol/src/phases.rs#L415) and [completion classification](https://github.com/ferrum-edge/ferrum-edge/blob/f9b9d053f9401335f9ad1d72283d0cb122fa0bd2/tests/performance/multi_protocol/src/metrics.rs#L98) support the interpretation.

| Phase / capture property | WSS observed range | TCP/TLS observed range |
|---|---:|---:|
| Setup seconds | 0.056345–0.164542 | 0.068568–0.158759 |
| Warmup seconds | 0.129300–0.585284 | 0.117191–0.473841 |
| Barrier seconds | 0.000018–0.001093 | 0.001072–0.001153 |
| Coordinator measurement elapsed seconds | 15.000165–15.029103 | 15.000053–15.007973 |
| Drain seconds | 0.019821–1.784410 | 0.055168–2.797354 |
| Concurrency observation count (requested 10 ms cadence) | 549–1,348 | 1,224–1,354 |
| Mean client-local in-flight exchanges / offered workers | 99.755–99.926% | 99.919–99.927% |
| Maximum observed passive process sample gap | 0.689847 s | 0.511888 s |

All sampled active-worker and active-connection minima, means, and maxima equal the offered 200/100 count. Early retirements are zero; sampled client admission queues peak at one. The nominal 10 ms observer is scheduler-delayed and its means are sample means, not exact time-weighted utilization. WSS/TCP admission is marked locally immediately before sending/exchanging; it does not prove simultaneous server processing or measure socket/flow-control queues. The JSON retains every gauge, queue-time total, admission count, phase timestamp, and PID identity. No explicit client-drop counter or measurement-bracketed kernel/socket-drop delta exists; those quantities are **unknown**, not zero.

All 72 client stderr files and all 16 Envoy stats stderr files are present and empty; all 72 sampler stop files exist and are empty. There are 192 gateway/backend process brackets plus 72 client brackets. Every gateway/backend bracket was independently recalculated from its full timeline using stable PID/start-tick identity, last sample at or before start, first sample at or after deadline, continuity at every intervening tick, CPU delta, within-window RSS maximum, and monotonic I/O deltas. All match the stamped records exactly. No required role or listed PID is missing. Kong contributes five gateway PIDs; Ferrum, Envoy, and Tyk contribute one each. Client CPU is the client’s own `getrusage` boundary delta and is checked for identity/internal consistency; the raw start/end `getrusage` values are not archived, so its delta cannot be independently rederived from those endpoints. Sampled client `/proc` lifetime deltas intentionally differ and are not substituted.

The failure and diagnostic record is not empty. The following findings are preserved without promoting a plausible explanation to causal proof.

- **Tyk startup failures, all four sessions.** Each startup has eight structured Redis/storage errors, six warnings, and one TLS-handshake EOF. The first startup log (`gateways-protocol-bench-wss-f9b9d053f9401335f9ad1d72283d0cb122fa0bd2/run_1/pairs/pair_001/diagnostics/tyk_startup.log`) has `storage: Redis is either down or was not configured` at lines 5, 7, 8, 11, 14; failed version/poller operations at lines 6 and 9; a Redis reconnect-in-10s error at line 12; and handshake EOF at line 16. Both post-payload logs are byte-identical to their session’s startup log, so these copies are not new errors. The last logged event precedes 500 KiB measurement by 1.459–1.469 seconds and 1 MiB measurement by 17.147–17.224 seconds. No measured echo failure is observed. The source waits for Redis PONG before starting Tyk and readiness opens/closes a raw TCP socket; that makes a readiness-related TLS EOF plausible, but no connection trace proves the match. Redis configuration/initialization/recovery cannot be resolved without Redis logs and state, which are absent. The warnings include insecure-config allowance, session lifetime, descriptor limit, control port, and legacy path. Tyk rows remain qualified observations, not clean startup evidence.
- **Envoy WSS resets/destruction.** All eight WSS snapshots, example here (`gateways-protocol-bench-wss-f9b9d053f9401335f9ad1d72283d0cb122fa0bd2/run_1/pairs/pair_001/diagnostics/envoy_512000_stats.json`) contain nonzero `cluster.backend_ws.upstream_cx_destroy_local_with_active_rq`, `cluster.backend_ws.upstream_cx_destroy_with_active_rq`, `http.ingress_wss.downstream_cx_destroy_active_rq`, `http.ingress_wss.downstream_cx_destroy_remote_active_rq`, and `http.ingress_wss.downstream_rq_rx_reset`. Each is 200 after 500 KiB and cumulatively 300 after 1 MiB in every arm/pair. Those are overlapping counters, not five independent failure populations. They align with the cumulative 200 + 100 connections; WSS client code drops the stream after drained echoes without an explicit WebSocket close handshake. Teardown is a plausible explanation, but absent phase-boundary deltas/timestamps prevent assigning all counters to teardown. Do not sum the 200 and 300 snapshots, equate them to lost echoes, or claim no resets occurred.
- **Envoy TCP/TLS destruction.** All eight TCP snapshots, example here (`gateways-protocol-bench-tcp-tls-f9b9d053f9401335f9ad1d72283d0cb122fa0bd2/run_1/pairs/pair_001/diagnostics/envoy_512000_stats.json`) similarly report `cluster.backend_tcp.upstream_cx_destroy_remote_with_active_rq` and `cluster.backend_tcp.upstream_cx_destroy_with_active_rq` as 200 then 300 per session. End-of-connection accounting is plausible for a TCP proxy, but event timing is missing. The scan retains every counter whose name contains error/fail/drop/timeout/overflow/reset or active-request destruction; apart from the named counters, those captured error-like values are zero. This does not measure kernel drops or unavailable counters.
- **Kong warnings and stream records.** Two root/user-directive warning lines occur per startup across eight sessions. TCP logs contain 401 stream-status entries after 500 KiB and cumulatively 601 after 1 MiB (`gateways-protocol-bench-tcp-tls-f9b9d053f9401335f9ad1d72283d0cb122fa0bd2/run_1/pairs/pair_001/diagnostics/kong_1048576.log`), all status 200, including a zero-byte readiness connection. The logs cover multiple forwarding legs and TLS/plaintext byte scopes; they are not useful-echo counts and must not be added to the client’s byte totals. No non-200 stream entry or additional measured failure is observed.
- **Silent logs are limited evidence.** All 72 backend logs contain startup banners only. Ferrum and Envoy’s 24 gateway/startup logs each are empty. Backend WSS handlers silently return on TLS/upgrade failures and end their loop on read/send failure; TCP handlers ignore copy/shutdown errors. Envoy runs at error log level. Therefore these logs cannot prove absence of backend or gateway transport failures. `transport_events=[]` and zero close-event fields in these WSS/TCP records are not instrumented complete transport histories; WSS has no explicit close capture. TCP’s shutdown flag and empty stderr supply narrower closure evidence.

The independent admissibility decision is therefore: **72/72 valid for descriptive paired client useful-throughput comparisons with stated diagnostics and topology limits; 0/72 establish fully verified transport cleanliness; no sample establishes a causal code improvement.** Envoy and Tyk caveats travel with every comparison involving those arms. If a proposed claim requires clean startup, measured-phase attribution of every reset, equal security policy, isolated proxy cost, or baseline/candidate revision causality, that stronger comparison is not admissible from this dataset. No production repair is proposed from these correlations.

Paired ratios below are `candidate RPS / baseline RPS`. Each of the four observations matches protocol, host, block, pair, payload, duration, and effective concurrency. We compute `l_i = log(candidate_i / baseline_i)` and report `exp(mean(l_i))`. The four-repeat 95% interval is `exp(mean(l) ± 3.182446305284263 × sd(l)/sqrt(4))`. A sensitivity interval first averages the two log ratios in each block, then uses `12.706204736432095 × sd(block means)/sqrt(2)`. Original n=2 per-block estimates, individual log ratios, means and SDs are all retained in JSON. No row exclusion, retry substitution, outlier trimming, or pooling across payloads/protocol hosts is used.

These are conditional descriptive Student-t intervals: four repeats on one host per protocol, only two blocks, unverified distribution/independence assumptions, and no multiplicity adjustment. The block intervals are a sensitivity analysis, not independent-host replication. A narrow interval can reflect repeated conditions on one VM rather than generalizable precision. Direct has one TLS leg while a gateway path has two, and removes the proxy’s competition for shared CPU; a direct ratio is not isolated proxy overhead or efficiency.

| Protocol / bytes | Candidate / baseline | Geometric ratio | Four-repeat 95% interval | Two-block sensitivity 95% interval |
|---|---|---:|---:|---:|
| tcp-tls / 512000 | ferrum / direct | 0.4634 | [0.4394, 0.4888] | [0.3823, 0.5618] |
| tcp-tls / 512000 | envoy / direct | 0.4317 | [0.4202, 0.4434] | [0.3798, 0.4906] |
| tcp-tls / 512000 | kong / direct | 0.3381 | [0.3344, 0.3418] | [0.3214, 0.3556] |
| tcp-tls / 512000 | envoy / ferrum | 0.9314 | [0.9045, 0.9592] | [0.8733, 0.9935] |
| tcp-tls / 512000 | kong / ferrum | 0.7295 | [0.6876, 0.7740] | [0.5721, 0.9301] |
| tcp-tls / 1048576 | ferrum / direct | 0.4651 | [0.4591, 0.4713] | [0.4295, 0.5037] |
| tcp-tls / 1048576 | envoy / direct | 0.4400 | [0.4366, 0.4434] | [0.4383, 0.4417] |
| tcp-tls / 1048576 | kong / direct | 0.3444 | [0.3435, 0.3453] | [0.3387, 0.3501] |
| tcp-tls / 1048576 | envoy / ferrum | 0.9459 | [0.9342, 0.9577] | [0.8701, 1.0282] |
| tcp-tls / 1048576 | kong / ferrum | 0.7403 | [0.7292, 0.7517] | [0.6724, 0.8151] |
| wss / 512000 | ferrum / direct | 0.4814 | [0.4570, 0.5071] | [0.4254, 0.5448] |
| wss / 512000 | envoy / direct | 0.4248 | [0.4107, 0.4393] | [0.3830, 0.4710] |
| wss / 512000 | kong / direct | 0.1800 | [0.1779, 0.1821] | [0.1672, 0.1937] |
| wss / 512000 | tyk / direct | 0.4878 | [0.4678, 0.5087] | [0.4179, 0.5695] |
| wss / 512000 | envoy / ferrum | 0.8823 | [0.8645, 0.9005] | [0.8646, 0.9004] |
| wss / 512000 | kong / ferrum | 0.3738 | [0.3526, 0.3963] | [0.3069, 0.4554] |
| wss / 512000 | tyk / ferrum | 1.0133 | [0.9704, 1.0580] | [0.7670, 1.3386] |
| wss / 1048576 | ferrum / direct | 0.4683 | [0.4592, 0.4776] | [0.4361, 0.5030] |
| wss / 1048576 | envoy / direct | 0.4228 | [0.4143, 0.4315] | [0.3962, 0.4512] |
| wss / 1048576 | kong / direct | 0.1830 | [0.1800, 0.1861] | [0.1761, 0.1902] |
| wss / 1048576 | tyk / direct | 0.5136 | [0.5056, 0.5218] | [0.5001, 0.5276] |
| wss / 1048576 | envoy / ferrum | 0.9029 | [0.8794, 0.9269] | [0.8971, 0.9086] |
| wss / 1048576 | kong / ferrum | 0.3908 | [0.3774, 0.4047] | [0.3501, 0.4362] |
| wss / 1048576 | tyk / ferrum | 1.0968 | [1.0612, 1.1335] | [0.9943, 1.2098] |

For the historical WSS priority, Tyk/Ferrum is 1.0133 at 500 KiB, four-repeat interval [0.9704, 1.0580], which does not resolve a difference. At 1 MiB it is 1.0968, four-repeat interval [1.0612, 1.1335], but two-block sensitivity [0.9943, 1.2098] includes parity. Neither supports a revision gain or a production causal claim. Envoy/Ferrum and Kong/Ferrum observed ratios are below one at both payloads in both protocols, but their configuration, transport, shared-host and low-replication limitations still apply. The TCP 1 MiB Envoy/Ferrum block sensitivity also includes parity. These results identify observations to explain, not measured optimization effects.

The following table summarizes the four raw samples per arm/payload. RPS is the geometric mean of useful RPS. Latency columns show ranges of the **per-sample** p50/p99 in milliseconds; quantiles are not pooled or averaged into a whole-run percentile. Failed completions would not contribute latency, but there are no reported client-error samples in this matrix. Setup and drain are excluded from these latency histograms.

| Protocol / bytes | Arm | Useful RPS geometric mean | p50 range ms | p99 range ms |
|---|---|---:|---:|---:|
| tcp-tls / 512000 | direct | 2005.64 | 96.767–99.135 | 191.487–198.271 |
| tcp-tls / 1048576 | direct | 991.42 | 96.255–97.151 | 194.431–199.295 |
| tcp-tls / 512000 | envoy | 865.76 | 196.479–210.943 | 525.311–611.327 |
| tcp-tls / 1048576 | envoy | 436.19 | 198.783–221.951 | 382.207–544.255 |
| tcp-tls / 512000 | ferrum | 929.48 | 200.319–218.111 | 408.831–455.935 |
| tcp-tls / 1048576 | ferrum | 461.16 | 199.807–205.823 | 428.543–444.415 |
| tcp-tls / 512000 | kong | 678.05 | 262.655–297.215 | 512.255–633.343 |
| tcp-tls / 1048576 | kong | 341.42 | 238.847–270.591 | 573.951–897.535 |
| wss / 512000 | direct | 2599.32 | 70.975–72.511 | 174.463–179.455 |
| wss / 1048576 | direct | 1314.54 | 66.431–67.839 | 210.303–224.511 |
| wss / 512000 | envoy | 1104.08 | 174.079–176.895 | 278.271–452.351 |
| wss / 1048576 | envoy | 555.82 | 172.671–181.247 | 298.751–345.599 |
| wss / 512000 | ferrum | 1251.36 | 144.511–157.055 | 322.559–385.535 |
| wss / 1048576 | ferrum | 615.63 | 153.215–158.463 | 283.135–313.855 |
| wss / 512000 | kong | 467.80 | 365.567–424.703 | 727.039–1017.343 |
| wss / 1048576 | kong | 240.60 | 356.607–373.503 | 883.711–1245.183 |
| wss / 512000 | tyk | 1267.95 | 145.151–154.367 | 292.607–331.007 |
| wss / 1048576 | tyk | 675.21 | 135.551–138.367 | 360.191–387.839 |

Resource means below use the four samples, sum all gateway PIDs, and keep client/backend/gateway scopes distinct. CPU entries are CPU-seconds, not host percent; a multithreaded process may exceed 15 CPU-seconds in 15 wall seconds. Gateway/backend endpoint brackets extend 0.049505–0.721380 seconds beyond the nominal window and can include adjacent warmup/drain work. Client bracket slack is 0.000053–0.029103 seconds. The gateway/backend RSS column is the sum of individual within-window sampled peaks, not necessarily simultaneous peaks or unique physical memory; Kong shared pages can be counted in multiple PIDs. JSON additionally records simultaneous sampled sums per row. Client RSS is the process-lifetime high-water mark at measurement end, including earlier setup/warmup allocations. Redis, Docker, sampler and kernel costs are not charged to the gateway role. None of these means is an isolated proxy CPU-cost estimate.

| Protocol / bytes | Arm | CPU s gateway / backend / client | RSS MiB gateway / backend / client |
|---|---|---:|---:|
| tcp-tls / 512000 | direct | — / 33.645 / 26.106 | — / 19.74 / 238.83 |
| tcp-tls / 1048576 | direct | — / 34.320 / 25.650 | — / 20.19 / 226.23 |
| tcp-tls / 512000 | envoy | 33.255 / 13.273 / 13.244 | 169.34 / 18.34 / 241.57 |
| tcp-tls / 1048576 | envoy | 33.817 / 13.025 / 13.395 | 171.64 / 18.43 / 228.00 |
| tcp-tls / 512000 | ferrum | 28.520 / 15.058 / 15.445 | 127.27 / 19.21 / 238.63 |
| tcp-tls / 1048576 | ferrum | 30.110 / 13.588 / 16.271 | 170.31 / 17.84 / 226.53 |
| tcp-tls / 512000 | kong | 34.642 / 13.630 / 11.155 | 1327.10 / 19.57 / 241.50 |
| tcp-tls / 1048576 | kong | 35.655 / 13.875 / 11.131 | 1328.29 / 17.62 / 228.15 |
| wss / 512000 | direct | — / 29.280 / 30.350 | — / 244.38 / 353.24 |
| wss / 1048576 | direct | — / 29.265 / 30.616 | — / 254.08 / 347.31 |
| wss / 512000 | envoy | 33.300 / 13.338 / 13.523 | 177.88 / 248.33 / 352.25 |
| wss / 1048576 | envoy | 33.680 / 12.923 / 13.950 | 181.45 / 236.24 / 344.90 |
| wss / 512000 | ferrum | 28.698 / 15.370 / 15.451 | 192.41 / 251.16 / 353.28 |
| wss / 1048576 | ferrum | 29.188 / 15.395 / 15.866 | 211.15 / 244.14 / 348.82 |
| wss / 512000 | kong | 47.697 / 6.430 / 6.773 | 2345.75 / 255.02 / 348.66 |
| wss / 1048576 | kong | 47.600 / 6.350 / 6.791 | 2345.20 / 233.76 / 339.69 |
| wss / 512000 | tyk | 30.903 / 14.385 / 14.405 | 121.45 / 250.34 / 354.65 |
| wss / 1048576 | tyk | 31.445 / 14.027 / 14.756 | 146.97 / 242.80 / 350.03 |

Resource allocation differs substantially: for example WSS/1 MiB Ferrum averages 29.188 gateway CPU-seconds versus Tyk 31.445, while the request rates and backend/client CPU also differ. This does not prove a gateway algorithm is responsible. Kong’s multiple resident processes make its summed RSS especially unsuitable as a unique-memory comparison. No allocation/copy profile, per-worker CPU attribution, packet trace, syscall trace, TLS-record analysis, or relay-state capture establishes a performance cause.

Historical comparisons below use only the retained exact-revision [audit results JSON](https://github.com/ferrum-edge/ferrum-edge/blob/f9b9d053f9401335f9ad1d72283d0cb122fa0bd2/docs/benchmark_audit_2026_09_17_results.json) and [audit narrative](https://github.com/ferrum-edge/ferrum-edge/blob/f9b9d053f9401335f9ad1d72283d0cb122fa0bd2/docs/benchmark_audit_2026_09_17.md#L149), whose full SHA-256 values are in the source inventory. Historical raw artifacts were not re-audited in this bounded task. The values are historical arithmetic means and error arrays, not eligible current paired baselines.

| Historical run / revision | Retained observation | Current bounded observation and limit |
|---|---|---|
| [35071334026](https://github.com/ferrum-edge/ferrum-edge/actions/runs/35071334026) / `ff96f30468517706695538ffc74bc6770014ab07` | WSS 500 KiB Ferrum 976.378, Tyk 989.600 RPS; 1 MiB Ferrum 466.178, Tyk 523.289; all three error counts zero for these pairs. Ferrum TCP 500 KiB errors [4,2,0], 1 MiB [0,0,0]. | Current selected payloads have zero client errors; historical WSS 1 MiB priority remains an observational direction, not a quantified revision improvement. |
| [35195212169](https://github.com/ferrum-edge/ferrum-edge/actions/runs/35195212169) / `d8a37c6911aba89112fd2571e9364118964e7955` | WSS 500 KiB Ferrum 979.222, Tyk 990.556 RPS; 1 MiB Ferrum 458.911, Tyk 523.356; zero errors for these pairs. Ferrum TCP 500 KiB and 1 MiB each errors [0,0,1]. | Those historical TCP errors did not recur here; this does not prove their cause or repair. The TCP workload changed from unbounded pipelining to one full-duplex echo per worker. |
| Both retained historical runs, Ferrum WSS 5 MiB | Errors [20,15,11] and [23,33,5], respectively; narrative identifies 30-second echo timeouts. | 5 MiB was explicitly skipped in this run. These failures are not retested or cleared by the present 72 rows. |

The retained CPU table gives EPYC 7763 for both old WSS runs and EPYC 9V74 then EPYC 7763 for old TCP/TLS. The current hosts report EPYC 9V74. In addition to host differences, the current harness separates phases, repeats direct and changes the TCP workload. Even matching CPU labels would not supply a controlled historical pair. No cross-run percent gain, error-rate improvement, or causal attribution is calculated.

The issue body’s flush-progress checkbox is historical context and does not describe the exact current implementation. At this revision, [`poll_copy_direction`](https://github.com/ferrum-edge/ferrum-edge/blob/f9b9d053f9401335f9ad1d72283d0cb122fa0bd2/src/proxy/tcp_proxy.rs#L8672) already tracks `needs_flush`, flushes accepted bytes before parking on a pending reader, and preserves pending-flush/half-close deadline and error handling. The retained [repair account](https://github.com/ferrum-edge/ferrum-edge/blob/f9b9d053f9401335f9ad1d72283d0cb122fa0bd2/docs/benchmark_audit_2026_09_17.md#L851) and [actual-rustls regression source](https://github.com/ferrum-edge/ferrum-edge/blob/f9b9d053f9401335f9ad1d72283d0cb122fa0bd2/tests/unit/gateway_core/relay_flush_progress_tests.rs#L532) describe a 4 KiB transport window with an 8 KiB payload through the production loop. Git history includes merged PR #5599 at `66bf34284bd5a31e2621de9ba9ec08d48b379480`. This static observation is evidence that the repair and specific regression exist; the analyst did not execute the test or newly verify its hosted check results.

The same retained narrative reports separate-host runs 35327641299 (`606b898a4`) and 35327635467 (`c9a0c3d5c`), WSS/5 MiB errors 24/24 versus 0/0, and explicitly limits the finding to corroboration rather than proof that the defect caused every hosted timeout. Those are the narrative’s abbreviated revision identifiers, not expanded or invented full SHAs. This current missing-payload campaign contains no unfixed arm, production relay trace or timed failure, so it cannot add specific causal proof of the historical timeouts. It also cannot diagnose Tyk Redis or attribute Envoy destruction counters to a particular internal failure. Plausible teardown/configuration explanations remain hypotheses.

Every canonical row is listed below. The canonical identifier names protocol, block, pair, arm and exact payload. Its JSON entry records the artifact-relative sample path and SHA-256. Host is determined by the protocol identity table above. Every row has 15 measured seconds, nominal offered base 200, effective workers 200 at 512000 bytes or 100 at 1048576, warmup equal to effective workers, zero client errors, zero early retirements, and `timed_out=false`. `A` is admitted exchanges, `D` is validated drain echoes. `PASS` means the qualified descriptive comparison criteria pass; `E` preserves Envoy’s cumulative transport-counter caveat, `T` preserves Tyk startup/Redis caveats, and `K` preserves Kong warnings. Raw per-row latency averages/maxima, p50–p99, CPU/RSS, phases, process identities, all hashes, and explicit missing-evidence flags are in JSON. The table retains every row, including diagnostic caveats; no row is omitted.

| Canonical identity / source | Useful requests | Exact useful bytes | RPS | p50 / p99 ms | A / D | Audit |
|---|---:|---:|---:|---:|---:|---|
| tcp-tls/b1/p1/direct/512000 | 29676 | 15194112000 | 1978.400 | 99.135 / 198.271 | 29876 / 200 | PASS |
| tcp-tls/b1/p1/direct/1048576 | 14859 | 15580790784 | 990.600 | 96.383 / 199.295 | 14959 / 100 | PASS |
| tcp-tls/b1/p1/ferrum/512000 | 13081 | 6697472000 | 872.067 | 218.111 / 455.935 | 13281 / 200 | PASS |
| tcp-tls/b1/p1/ferrum/1048576 | 6927 | 7263485952 | 461.800 | 201.215 / 444.415 | 7027 / 100 | PASS |
| tcp-tls/b1/p1/envoy/512000 | 12505 | 6402560000 | 833.667 | 210.943 / 611.327 | 12705 / 200 | PASS E |
| tcp-tls/b1/p1/envoy/1048576 | 6512 | 6828326912 | 434.133 | 215.039 / 481.791 | 6612 / 100 | PASS E |
| tcp-tls/b1/p1/kong/512000 | 10084 | 5163008000 | 672.267 | 276.991 / 610.303 | 10284 / 200 | PASS K |
| tcp-tls/b1/p1/kong/1048576 | 5108 | 5356126208 | 340.533 | 270.591 / 573.951 | 5208 / 100 | PASS K |
| tcp-tls/b1/p2/direct/512000 | 30263 | 15494656000 | 2017.533 | 96.767 / 198.143 | 30463 / 200 | PASS |
| tcp-tls/b1/p2/direct/1048576 | 14854 | 15575547904 | 990.267 | 97.151 / 194.431 | 14954 / 100 | PASS |
| tcp-tls/b1/p2/ferrum/512000 | 14305 | 7324160000 | 953.667 | 200.319 / 410.111 | 14505 / 200 | PASS |
| tcp-tls/b1/p2/ferrum/1048576 | 6981 | 7320109056 | 465.400 | 199.807 / 430.335 | 7081 / 100 | PASS |
| tcp-tls/b1/p2/envoy/512000 | 13115 | 6714880000 | 874.333 | 205.183 / 525.311 | 13315 / 200 | PASS E |
| tcp-tls/b1/p2/envoy/1048576 | 6557 | 6875512832 | 437.133 | 221.951 / 382.207 | 6657 / 100 | PASS E |
| tcp-tls/b1/p2/kong/512000 | 10260 | 5253120000 | 684.000 | 271.359 / 600.063 | 10460 / 200 | PASS K |
| tcp-tls/b1/p2/kong/1048576 | 5111 | 5359271936 | 340.733 | 252.543 / 828.927 | 5211 / 100 | PASS K |
| tcp-tls/b2/p1/direct/512000 | 30177 | 15450624000 | 2011.800 | 97.535 / 193.151 | 30377 / 200 | PASS |
| tcp-tls/b2/p1/direct/1048576 | 14864 | 15586033664 | 990.933 | 97.023 / 195.967 | 14964 / 100 | PASS |
| tcp-tls/b2/p1/ferrum/512000 | 14204 | 7272448000 | 946.933 | 202.495 / 415.231 | 14404 / 200 | PASS |
| tcp-tls/b2/p1/ferrum/1048576 | 6854 | 7186939904 | 456.933 | 205.823 / 440.063 | 6954 / 100 | PASS |
| tcp-tls/b2/p1/envoy/512000 | 13225 | 6771200000 | 881.667 | 201.215 / 578.559 | 13425 / 200 | PASS E |
| tcp-tls/b2/p1/envoy/1048576 | 6511 | 6827278336 | 434.067 | 220.799 / 421.631 | 6611 / 100 | PASS E |
| tcp-tls/b2/p1/kong/512000 | 10098 | 5170176000 | 673.200 | 297.215 / 512.255 | 10298 / 200 | PASS K |
| tcp-tls/b2/p1/kong/1048576 | 5128 | 5377097728 | 341.867 | 262.143 / 665.599 | 5228 / 100 | PASS K |
| tcp-tls/b2/p2/direct/512000 | 30226 | 15475712000 | 2015.067 | 97.279 / 191.487 | 30426 / 200 | PASS |
| tcp-tls/b2/p2/direct/1048576 | 14908 | 15632171008 | 993.867 | 96.255 / 199.167 | 15008 / 100 | PASS |
| tcp-tls/b2/p2/ferrum/512000 | 14216 | 7278592000 | 947.733 | 201.983 / 408.831 | 14416 / 200 | PASS |
| tcp-tls/b2/p2/ferrum/1048576 | 6908 | 7243563008 | 460.533 | 201.343 / 428.543 | 7008 / 100 | PASS |
| tcp-tls/b2/p2/envoy/512000 | 13113 | 6713856000 | 874.200 | 196.479 / 582.655 | 13313 / 200 | PASS E |
| tcp-tls/b2/p2/envoy/1048576 | 6592 | 6912212992 | 439.467 | 198.783 / 544.255 | 6692 / 100 | PASS E |
| tcp-tls/b2/p2/kong/512000 | 10242 | 5243904000 | 682.800 | 262.655 / 633.343 | 10442 / 200 | PASS K |
| tcp-tls/b2/p2/kong/1048576 | 5138 | 5387583488 | 342.533 | 238.847 / 897.535 | 5238 / 100 | PASS K |
| wss/b1/p1/direct/512000 | 38535 | 19729920000 | 2569.000 | 72.511 / 178.047 | 38735 / 200 | PASS |
| wss/b1/p1/direct/1048576 | 19623 | 20576206848 | 1308.200 | 66.879 / 219.903 | 19723 / 100 | PASS |
| wss/b1/p1/ferrum/512000 | 17717 | 9071104000 | 1181.133 | 157.055 / 385.535 | 17917 / 200 | PASS |
| wss/b1/p1/ferrum/1048576 | 9081 | 9522118656 | 605.400 | 158.463 / 292.863 | 9181 / 100 | PASS |
| wss/b1/p1/envoy/512000 | 15862 | 8121344000 | 1057.467 | 175.999 / 452.351 | 16062 / 200 | PASS E |
| wss/b1/p1/envoy/1048576 | 8165 | 8561623040 | 544.333 | 177.279 / 345.599 | 8265 / 100 | PASS E |
| wss/b1/p1/kong/512000 | 6992 | 3579904000 | 466.133 | 424.703 / 727.039 | 7192 / 200 | PASS K |
| wss/b1/p1/kong/1048576 | 3642 | 3818913792 | 242.800 | 356.607 / 1086.463 | 3742 / 100 | PASS K |
| wss/b1/p1/tyk/512000 | 18518 | 9481216000 | 1234.533 | 154.239 / 331.007 | 18718 / 200 | PASS T |
| wss/b1/p1/tyk/1048576 | 10214 | 10710155264 | 680.933 | 135.551 / 387.839 | 10314 / 100 | PASS T |
| wss/b1/p2/direct/512000 | 38912 | 19922944000 | 2594.133 | 71.807 / 174.463 | 39112 / 200 | PASS |
| wss/b1/p2/direct/1048576 | 19770 | 20730347520 | 1318.000 | 66.495 / 221.951 | 19870 / 100 | PASS |
| wss/b1/p2/ferrum/512000 | 19237 | 9849344000 | 1282.467 | 144.511 / 338.175 | 19437 / 200 | PASS |
| wss/b1/p2/ferrum/1048576 | 9265 | 9715056640 | 617.667 | 154.239 / 309.759 | 9365 / 100 | PASS |
| wss/b1/p2/envoy/512000 | 16780 | 8591360000 | 1118.667 | 175.615 / 278.271 | 16980 / 200 | PASS E |
| wss/b1/p2/envoy/1048576 | 8408 | 8816427008 | 560.533 | 181.247 / 312.319 | 8508 / 100 | PASS E |
| wss/b1/p2/kong/512000 | 7027 | 3597824000 | 468.467 | 365.567 / 1017.343 | 7227 / 200 | PASS K |
| wss/b1/p2/kong/1048576 | 3590 | 3764387840 | 239.333 | 365.055 / 1245.183 | 3690 / 100 | PASS K |
| wss/b1/p2/tyk/512000 | 19743 | 10108416000 | 1316.200 | 145.151 / 312.575 | 19943 / 200 | PASS T |
| wss/b1/p2/tyk/1048576 | 10063 | 10551820288 | 670.867 | 138.239 / 366.847 | 10163 / 100 | PASS T |
| wss/b2/p1/direct/512000 | 39130 | 20034560000 | 2608.667 | 71.103 / 179.455 | 39330 / 200 | PASS |
| wss/b2/p1/direct/1048576 | 19700 | 20656947200 | 1313.333 | 67.839 / 210.303 | 19800 / 100 | PASS |
| wss/b2/p1/ferrum/512000 | 19210 | 9835520000 | 1280.667 | 147.071 / 322.559 | 19410 / 200 | PASS |
| wss/b2/p1/ferrum/1048576 | 9175 | 9620684800 | 611.667 | 155.263 / 313.855 | 9275 / 100 | PASS |
| wss/b2/p1/envoy/512000 | 16779 | 8590848000 | 1118.600 | 174.079 / 305.663 | 16979 / 200 | PASS E |
| wss/b2/p1/envoy/1048576 | 8444 | 8854175744 | 562.933 | 173.311 / 298.751 | 8544 / 100 | PASS E |
| wss/b2/p1/kong/512000 | 7022 | 3595264000 | 468.133 | 393.215 / 983.039 | 7222 / 200 | PASS K |
| wss/b2/p1/kong/1048576 | 3614 | 3789553664 | 240.933 | 373.503 / 883.711 | 3714 / 100 | PASS K |
| wss/b2/p1/tyk/512000 | 18891 | 9672192000 | 1259.400 | 153.983 / 302.847 | 19091 / 200 | PASS T |
| wss/b2/p1/tyk/1048576 | 10134 | 10626269184 | 675.600 | 137.727 / 371.967 | 10234 / 100 | PASS T |
| wss/b2/p2/direct/512000 | 39387 | 20166144000 | 2625.800 | 70.975 / 174.463 | 39587 / 200 | PASS |
| wss/b2/p2/direct/1048576 | 19780 | 20740833280 | 1318.667 | 66.431 / 224.511 | 19880 / 100 | PASS |
| wss/b2/p2/ferrum/512000 | 18960 | 9707520000 | 1264.000 | 146.943 / 345.087 | 19160 / 200 | PASS |
| wss/b2/p2/ferrum/1048576 | 9420 | 9877585920 | 628.000 | 153.215 / 283.135 | 9520 / 100 | PASS |
| wss/b2/p2/envoy/512000 | 16844 | 8624128000 | 1122.933 | 176.895 / 283.647 | 17044 / 200 | PASS E |
| wss/b2/p2/envoy/1048576 | 8335 | 8739880960 | 555.667 | 172.671 / 311.039 | 8435 / 100 | PASS E |
| wss/b2/p2/kong/512000 | 7027 | 3597824000 | 468.467 | 381.183 / 945.663 | 7227 / 200 | PASS K |
| wss/b2/p2/kong/1048576 | 3590 | 3764387840 | 239.333 | 365.311 / 1222.655 | 3690 / 100 | PASS K |
| wss/b2/p2/tyk/512000 | 18946 | 9700352000 | 1263.067 | 154.367 / 292.607 | 19146 / 200 | PASS T |
| wss/b2/p2/tyk/1048576 | 10102 | 10592714752 | 673.467 | 138.367 / 360.191 | 10202 / 100 | PASS T |

The remaining obligations for issue #5588 are bounded by this evidence:

- Keep #5588 open: this bounded missing-payload audit does not complete the tracker.
- WSS 5 MiB failure signature and smaller payload/long-lived-stream behavior are outside this 512000/1048576 matrix; do not claim their repair from these rows.
- Reconcile tracker historical flush checkbox with existing repair and retained rustls test; causal mapping of historical hosted timeouts still requires separate exact evidence, not these observational rates.
- Retain and resolve the Tyk startup/Redis and Envoy teardown/reset uncertainties; obtain phase-qualified transport/drop and missing service capture if required for a transport-clean comparison.
- Same-host baseline/candidate revision experiment and sufficiently replicated host/block uncertainty remain absent; four gateway repeats do not substitute for a code A/B.
- No kernel/socket-drop, per-worker CPU, syscall/allocation/copy/TLS-record or relay-state profiling here; no new production change is justified by correlation.
- Broader issue H1 framing, H2/gRPC failure/guard, H3 transport fairness and UDP directions remain governed by their own evidence; not assessed or closed here.

The observed selected-payload matrix is complete; missing transport, runtime-attestation, historical-causality and independent-host evidence remain explicitly unresolved.
