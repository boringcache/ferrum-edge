# H3 observer capability results — 2026-09-18

The repaired observer compiled and passed its 11 contract tests and real
isolated fixtures in [hosted run 35403203245](https://github.com/ferrum-edge/ferrum-edge/actions/runs/35403203245),
job [105787388199](https://github.com/ferrum-edge/ferrum-edge/actions/runs/35403203245/job/105787388199).
It positively observed successful IPv4 GSO sends and returned GRO data.
Classic reuseport kernel observation was unavailable. This is a capability
prerequisite for #5588, not a gateway benchmark, performance result, or tracker
closure. No Ferrum or Envoy process ran.

The [retained extraction](benchmark_h3_preflight_2026_09_18_results.json) includes
all 11 cases, both observer snapshots where present, fixture operations and
socket lifetimes, loss/coverage assessments, PMU results, source/object hashes,
and hashes of every original JSON artifact. Repeated fixture stdout is omitted
from process metadata because its parsed contents are retained as `fixture`.
The workflow artifact also contains complete logs, package provenance, source
files and compiled objects; its retention is 14 days. No repository code or
project tooling was executed locally to obtain or inspect these results.

## Provenance

The PR head was `16a981d58c28d509b7b5be210be3271ffa40001b`, based on
`ea86b00db1aee93d25db37b7de42666bb04ca34b`. GitHub tested synthetic merge
`42a4e305e6250a32b90d8f9bb33fd0ad4a0f2676`. Every retained observer source file
matches that head's checkout, and the recorded compiled-object hashes match
the downloaded objects. Staged source and object inventories match the build
inventories byte for byte.

Runner: GitHub-hosted Ubuntu 24.04 image `20260907.300.1`, Linux amd64 kernel
`6.17.0-1022-azure`, kernel build ID
`69f86991943f21a6e5450266c913374d52c1dbf3`. The BTF SHA-256 is
`95782433dc426daf8ebeb0acc1b04aed8f87168f67c1266f4d267aba7c22a8bf`.
Fixtures ran on isolated loopback under UID/GID 65534, all capability sets empty,
and `NoNewPrivs: 1`. The separately privileged observer retained the same network
namespace identity. Positive observation requires matching socket cookies and
fixture lifetimes; CPU numbers are not gateway worker identities.

## Observations

| Case | Retained result |
|---|---|
| TX offload | Nine attempts and nine recorded outcomes, no reported capture loss: six successful multi-segment GSO sends, two ordinary sends, and one invalid four-byte ancillary rejection (`EINVAL`). Both socket-default 1024-byte segmentation and the 512-byte per-message override were observed. |
| RX offload | Ten attempts and ten recorded outcomes, no reported capture loss: four qualifying GRO receives, two ordinary receives, two truncation cases, one peek, and one `EAGAIN`. Truncation and peek never became positive GRO witnesses. |
| Partial sendmmsg | The fixture requested two messages and sent one. TX retained the successful 2048-byte/512-byte-segment send and the second message's `EINVAL`; batch return counts were not treated as byte counts. |
| Partial recvmmsg | The fixture returned one of two requested messages. The RX observer reported two excluded API entries and no positive evidence. Coverage remains partial. |
| RX failures | An unreadable header incremented read loss. Failed sockaddr copyout retained outer `EFAULT` and no GRO witness. A successful inner kernel receive was not accepted as successful userspace delivery. |
| Capacity-one map | The first positive GRO witness survived; nine later map-update losses were explicit. The case remained partial coverage. |
| Classic selection and fallback | Both userspace fixtures attached classic reuseport filters successfully and received traffic. Kernel observation returned `unsupported` because the required BTF helper/prototype was unavailable; `run_bpf_filter` was absent from available attach functions. Userspace selection does not substitute for observed kernel program execution. |
| Injected unavailable paths | Missing BTF and missing symbol remained unsupported. The unprivileged observer was denied ftrace function visibility (`EACCES`) before a later attach stage could be tested. |

All supported snapshots bracket their fixtures and end after descriptor closure.
FD duplication retained one cookie; an actually reused FD received a fresh
cookie. No map-read error, diagnostic truncation, nested operation or pending
operation remained in these cases. These are bounded positive witnesses, not an
absence proof or a claim to exact totals for every possible socket API.

The privileged PMU probe opened a software CPU-clock event and read 272,714 with
273,526 ns enabled/running. Hardware cycles were unavailable (`ENOENT`). The
unprivileged fixture could open neither event (`EACCES`). These results establish
event availability only: no sampled stacks, hardware contention, or gateway CPU
attribution was collected.

## Remaining work

The overall result is `partial_coverage`. IPv6, recvmmsg/read/recvfrom RX
attribution, compatibility syscalls, gateway process lineage/socket retirement,
frontend/upstream role joins, observer overhead calibration, and the five-payload
four-pair gateway campaign remain open. Classic routing proof requires a
supported observation path. Host capability and successful synthetic offload
cannot establish that Envoy or Quinn exercised those paths during a benchmark.

The initial attempt at head `ee7a0cc3` compiled and passed its contract tests but
failed because the unprivileged fixture could not traverse the checkout path
and CO-RE referenced a macro alias instead of the kernel's actual cookie member.
The retained repair uses root-owned staging and `__sk_common.skc_cookie.counter`;
it leaves the missing classic helper explicitly unsupported. Neither failure was
rerun blindly or reclassified as successful coverage.
