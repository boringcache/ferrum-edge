# Hosted H3 proof and corrected-image comparison

This directory implements the finite `corrected-v1` follow-up for #5588 in draft
PR #5615. It changes the benchmark/observer, not production forwarding. Committing
it does not assert a passing verifier, workload result, performance gain or issue
closure. Execute this code only on GitHub-hosted Linux amd64 runners.

The original `16a981d5` capability evidence is retained **unchanged** in
[the preflight report](../../../../docs/benchmark_h3_preflight_2026_09_18.md) and
[its extraction](../../../../docs/benchmark_h3_preflight_2026_09_18_results.json).
That report describes its original source, including preassigned fixture cookies,
excluded recvmmsg, both earlier failures, and absent classic execution helper.
The new implementation must acquire its own hosted evidence. Do not relabel the
old observations with these new capabilities.

## Fixed comparison

`live_campaign.json` declares all experimental inputs before dispatch:

- Official Envoy Linux amd64 image
  `docker.io/envoyproxy/envoy@sha256:79c4e987d386b176721638187b511fb4d7041695f7a78e422ed27edd707b3eeb`,
  source `d7809ba2b07fd869d49bfb122b27f6a7977b4d94`, as approved in root's plan.
  No Envoy compilation or source-build comparison occurs.
- Direct, Ferrum, Envoy upstream 100 and **the same** Envoy upstream 4; actual
  downstream listener admission and HCM settings stay at 100. A parsed semantic
  config comparison requires exactly one changed upstream admission field.
- Payloads 10240/71680/512000/1048576/5242880, workers 200/200/200/100/50,
  client connections 21/21/21/11/6, 30 seconds, four counterbalanced pairs:
  **80 main samples** across five shards, one payload and one boot per shard.
- Effective kernel receive/send buffers 4194304. Envoy requests half that value
  because Linux doubles explicit requests. Cookie-joined readback of actual
  owned sockets is required for comparison acceptance. Missing brackets remain
  incomplete. SNI `localhost`, upstream CA validation, both H3 hops, strict
  HTTP 200/exact body, no retry/fallback, phase and endpoint-drain contracts stay
  in force. Existing client frontend TLS verification remains explicitly insecure.

The new `.github/workflows/h3-live-comparison.yml` has read-only permissions and
pinned actions. PR checks compile features, run semantic contracts and real
fixtures, then a short real four-arm gateway smoke. Its manual job reuses that
same workflow's compiled and hashed Ferrum/harness/observer artifacts after the
smoke. Ferrum is packaged once as an image; its image configuration ID, source
revision, binary/build ID and artifact hashes are retained. The local packaged
image ID is not represented as a registry manifest digest. The approved Envoy
manifest/config IDs, actual binary SHA/build ID, generated config and effective
runtime response are retained separately.

Root must merge/register the new workflow before dispatching it. The ordinary
`experiment.json` stays disabled; frozen workflows, gates, policies and the
existing H1/H2 paths are unchanged. The runner's only new selector is:

```text
run_gateway_protocol_bench.sh http3 --h3-live corrected-v1 {smoke|10240|71680|512000|1048576|5242880} --output-dir PATH
```

The privileged entrypoint admits only hosted Linux amd64. All launches resolve
through literal `live_commands.sh` commands; user data never supplies executable
text. Fresh root-owned staging rejects reuse and checks source/object hash parity.
Native workloads run as UID/GID 65534 without capabilities and with no-new-privs;
both Docker gateways additionally use the same default seccomp, read-only root
and host network. They have no Docker socket or writable observer maps. Only the
provisioner/observer is privileged. Process privilege records are retained and
checked. Socket budgets are set on the disposable runner before workload birth.

## Calibration and raw retention

For each payload/arm, two paired off/on pilots reverse treatment order. Both
retain the same passive sampler. Predeclared tolerances are 2% useful RPS and 5%
p99; paired log-ratio Student-t intervals (df=1) retain the very large uncertainty
possible with two pairs. Every arm must resolve within both tolerances to use
active observation in the main comparison. Missing metrics, invalid traffic or
failed observers never pass calibration.

Otherwise all four main pairs run without the active observer, followed after
each pair by a matched traced diagnostic pair. Proof belongs to those diagnostic
samples only. No observer overhead is subtracted. Every raw failed/malformed
benchmark output, stderr, readiness record and partial snapshot remains in its
original file; derived metadata is separate. Failure metadata exists before
startup and workflows always upload results. A timeout is never replaced with
an `rps: 0` benchmark. Useful-traffic validity and proof completeness are separate.

## Observer contract

- Native amd64 IPv4 recvmsg and recvmmsg only. Runtime syscall formats and
  msghdr/mmsghdr/cmsghdr sizes/offsets are checked. Native syscall numbers reject
  compat/x32 decoding. Recvmmsg vectors are bounded at 32 in map values, never
  a 32-entry BPF stack array. Larger vectors are explicitly excluded.
- Entry captures original control pointer/capacity per slot and syscall
  generation. UDP entries associate one consistent actual cookie; matching
  inner errors and abandoned/nested/mismatched calls remain counted.
- Only the outer syscall's successful returned prefix is decoded. Per-message
  `msg_len` is separate from the batch count (`RX_BATCH` stores requested vlen
  in `length`, kernel entries in `segment`, returned message count in `result`).
  Zero/error/restart returns never decode stale slots. Read failures in later
  slots do not erase earlier valid deliveries. Timeout-copyout EFAULT is an
  error even when the kernel consumed a datagram.
- The returned ancillary decoder reads at most 256 bytes/eight headers, and only
  UDP_GRO's native four-byte integer. Pointer/capacity/length/alignment/duplicate
  checks, truncation, peek, error queue and zero datagrams are explicit.
  A positive witness requires returned bytes greater than positive stride and
  successful delivery. No packet payload or CID is read.
- Typed tracing contexts and direct BTF field access supply
  `bpf_get_socket_cookie(sk)`. A scalar reconstructed by probe-read is not used
  as a helper argument. Fixtures leave cookies unassigned before first observed
  bind/attachment/traffic, then compare actual observer cookies with SO_COOKIE
  and sock-diag. Verifier rejections are errors, not unsupported successes.
- Birth/bind, TX/RX, retirement, process fork/exec/exit, reuseport attachment,
  membership and classic execution load independently. The attach family does
  not require `run_bpf_filter`. Exact classic execution remains unavailable on
  the retained Azure kernel; an outer selector hit is insufficient. No guessed
  JIT offsets, steering replacement or alternate kernel is introduced.
- Successful attachment retains a bounded original-classic instruction FNV-1a
  digest (at most 64 instructions; explicitly noncryptographic), type and an
  observer generation. Missing original instructions leave an invalid digest,
  not invented bytes. Actual group add/alloc/detach operations carry member
  cookies; postprocessing does not infer groups from common ports. Replacement
  and detach remain separate from instruction execution.
- An owned cgroup subtree exists and every family reports readiness/capability
  before backend/gateway/client creation. Process start generation, host PID/TID,
  cgroup, boot and held netns lifetime accompany cookies. Frontend requires the
  owned process and successful full-endpoint bind. Upstream requires actual
  connected/sendmsg destination and owned backend connection peer evidence.
  First-send autobind updates the tuple without changing identity. A cookie can
  carry multiple QUIC connections. Softirq CPU is never labelled as a worker.
- `udp_destroy_sock` retains final buffers/drop metadata where observed. A closed
  alias, process exit or disappearance from a diagnostic dump is not retirement.
  Missing birth uses first-observed time; missing retirement/end counters stay
  null. Descriptor numbers remain annotations, not socket identity.

The upstream references for these contracts are Linux v6.17
[returned-prefix and copyout logic](https://github.com/torvalds/linux/blob/v6.17/net/socket.c),
[typed cookie helper](https://github.com/torvalds/linux/blob/v6.17/net/core/filter.c),
and [reuseport lifecycle](https://github.com/torvalds/linux/blob/v6.17/net/core/sock_reuseport.c).
The running hosted BTF/verifier/fixtures, rather than a source version assumption,
determine availability.

## Bounds and remaining evidence limits

A live arm is limited to 300 seconds, at most 64 snapshots including final, and
10-second checkpoints plus explicit phase boundaries. Stop detaches writers
before final stable map iteration; signals/parent death, missing final, forced
stop and snapshot failure are explicit. Each independently loaded family has
bounded maps (1024 identities, 256 pending operations, 4096 bucket rows/witnesses).
Eight 512 KiB lifecycle rings share a 4 MiB ring reservation. Exact witnesses are
limited to 128 per 10-second window, so startup cannot consume every later window.
Fixed outcome/segment-count buckets exclude exact lengths and CPU from live keys.
Sampling omissions, map/ring/read loss and unknown identity are retained.

The 64 MiB arm artifact cap is enforced after collection and each observer stream
has a 10 MiB cap. Observer RSS is sampled against a 32 MiB reservation, with the
other half of the proposed 64 MiB budget reserved for bounded kernel maps. This
is a conservative allocation design to validate on hosted load, not a measured
kernel allocator capacity claim. Kernel allocation overhead is not directly
measured. Concurrent checkpoints are non-atomic; only final snapshots are stable.
No absence or exact-total claim follows even from zero reported map loss.

Real fixtures include mixed and partial 32-entry recvmmsg, EAGAIN/EINTR/EBADF,
zero datagrams, WAITFORONE, peek then consumption, data/control truncation,
protected header/control/sockaddr/flags/controllen/msg_len/timeout copyout faults,
a fault after a successful prefix, attachment replacement/detach, surviving dup,
real FD reuse, count-map saturation, missing-BTF/symbol and denied-privilege paths.
Process/netns generations and final socket lifetimes are also retained in the
live smoke. This does not implement a general FD emulator or certify every
close_range/namespace/restart interleaving. Short process/FD lifetimes between
passive samples and unobserved retirement remain partial coverage; supported
hooks with missing records are not relabelled as host capability failures.

Both off/on treatments retain process/thread CPU/RSS, capture cost, host CPU and
softirq snapshots. PMU opening in the original preflight is only event availability;
no sampled CPU stacks or hardware contention claim is made here. Envoy's corrected
cumulative counter semantics stay separate from kernel/socket drop deltas. Root
owns hosted result review, final integration of #5602, workflow dispatch and the
artifact audit. #5588 remains open.
