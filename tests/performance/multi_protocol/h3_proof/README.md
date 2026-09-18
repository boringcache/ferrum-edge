# H3 observer capability prerequisite (#5588)

This independent hosted lane asks what the runner and a bounded observer can
actually observe. It launches only synthetic IPv4 UDP fixtures. It does not run
Ferrum, Envoy, an HTTP/3 client, a benchmark, or a release build. It neither proves
gateway behavior nor closes #5588. Dependency PR #5602 and the existing H3 1.33.5
observations retain their original limits. Shared harness and production files
are deliberately outside this directory's integration contract.

## Hosted registration and root commands

`.github/workflows/h3-proof-preflight.yml` registers **H3 observer compile and
hosted self-tests** on `pull_request` when this directory or that workflow changes.
It compiles the standalone C/libbpf observer, runs Python syntax/contract tests,
then runs the real fixtures. This does not depend on a newly added manual
workflow already being registered on the default branch. It does not add a
branch-protection requirement or modify the immutable existing workflows.

Root can later explicitly dispatch the registered workflow (this implementer
does not dispatch it):

```sh
gh workflow run h3-proof-preflight.yml \
  --ref codex/20260918-5588-h3-proof-preflight -f suite=capability-v1
```

The only input is the fixed choice `suite=capability-v1`; PR and manual execution
use identical committed inputs. Runner: `ubuntu-24.04`, Linux amd64, maximum
15 minutes. No shell input, image override, arbitrary PID, arbitrary script,
gateway privilege flag or campaign input exists. Permissions are `contents: read`;
checkout and artifact actions use full commit pins, checkout credentials are not
persisted. No action publishes a build or changes a PR/issue.

All compile commands are in the new workflow. Ubuntu packages are resolved at
install time; the lane retains the full binary/source package/version inventory,
APT origins and exact-version package records (including archive SHA256 when
available), install logs, compiler versions and hashes. This is resolved package
provenance, **not** a claim that a moving hosted image is reproducible. There is
no downloaded source build or unpinned executable action. Repository SHA, source
and object SHA256, ELF build IDs, runner ImageOS/ImageVersion, kernel release,
GNU kernel build ID, BTF hash, kernel config availability, capability/LSM/lockdown/
seccomp/sysctl/memlock evidence accompany every completed capability attempt.

Hosted-only driver, after the workflow's compile commands:

```sh
sudo --preserve-env=GITHUB_ACTIONS,ImageOS,ImageVersion,RUNNER_OS,RUNNER_ARCH,GITHUB_SHA,GITHUB_RUN_ID,GITHUB_RUN_ATTEMPT \
  python3 tests/performance/multi_protocol/h3_proof/hosted.py \
  --suite capability-v1 --output "$RUNNER_TEMP/h3-proof"
```

Never run these commands locally under this assignment. No hosted result is
asserted by committing this implementation. Root must inspect exact-head CI
and artifacts before relying on any capability.

## What the probes establish

| Family | Attach sites | Positive criterion and scope |
|---|---|---|
| IPv4 TX | `fentry/udp_sendmsg`, `fentry/udp_send_skb`, `fexit/udp_sendmsg` | Exactly one submission, effective `inet_cork.gso_size`, payload length greater than segment size, and successful full `udp_sendmsg` return. Includes per-message paths inside `sendmmsg`; syscall batch count is never treated as bytes. |
| Native IPv4 RX | `sys_enter_recvmsg`, `fentry/udp_recvmsg`, `sys_exit_recvmsg` | Actual socket cookie plus successful **outer syscall** return, returned native-int `SOL_UDP/UDP_GRO`, and returned bytes greater than stride. No `MSG_TRUNC`, `MSG_CTRUNC`, `MSG_PEEK`, failed header read or failed copyout qualifies. |
| Classic reuseport | `fexit/reuseport_attach_prog`, `fentry/fexit/reuseport_select_sock`, `fexit/run_bpf_filter` | Fixture successfully attaches `SO_ATTACH_REUSEPORT_CBPF`; non-null inner classic-helper return proves selection through that branch, joined to the selected socket's cookie and actual fixture receipt. An outer selector hit alone is never positive execution evidence. |

The loader checks the **running** BTF function prototypes and exact ftrace
function availability before loading each family. CO-RE relocates the small
named-field declarations against that kernel's BTF; declarations are not hardcoded
kernel offsets. RX also checks the exposed syscall tracepoint field offsets and
sizes against its native amd64 ABI. Missing/inlined/renamed functions, unsupported
prototypes, unavailable tracepoint metadata, missing BTF or denied permission
produce an explicit unavailable path with stage, errno, and diagnostics. There
is no guessed instruction offset, assumed 6.8 binary layout, kprobe search
framework or outer-selector substitution. A relocation/verifier rejection is
an **error** needing root investigation, not automatically an unsupported pass.

The code's semantic reference is the upstream
[reuseport helper](https://github.com/torvalds/linux/blob/v6.8/net/core/sock_reuseport.c),
[IPv4 UDP path](https://github.com/torvalds/linux/blob/v6.8/net/ipv4/udp.c),
[returned GRO integer](https://github.com/torvalds/linux/blob/v6.8/include/linux/udp.h),
[outer recvmsg copyout](https://github.com/torvalds/linux/blob/v6.8/net/socket.c), and
[syscall tracepoint metadata](https://github.com/torvalds/linux/blob/v6.8/kernel/trace/trace_syscalls.c).
These links explain the selected sites; the hosted BTF/attach checks and actual
fixtures determine whether that runner supports them. TX ancillary is **u16**;
RX ancillary is **native int**. The TX probe reads the effective kernel value
after socket-default/cmsg resolution, not an arbitrary userspace control value.

The fallback fixture installs a constant out-of-range classic return and receives
the resulting packet on one group member. An observed inner null followed by
outer non-null confirms the fallback path. **Inner null alone does not prove the
classic instructions ran** (the helper has earlier failure exits). Its assessment
therefore remains partial; the separate valid-selection fixture supplies the
positive execution witness. Classic filters need not appear in `bpftool prog show`.

## Synthetic runtime tests and identity

The driver enters disposable network and mount namespaces, enables only their
loopback interface and attempts to expose tracefs in that private mount namespace.
The observer runs privileged. Fixtures run separately under UID/GID 65534 with
empty supplementary groups, no capabilities in any set, and `no_new_privs`.
Their effective capability/seccomp state is retained. No gateway is launched
under observer privilege; later integration must preserve this separation.

Runtime cases assert socket/path attribution, not just source text:

- Classic constant selection of slot 1, separate invalid-index/hash fallback,
  successful userspace and kernel attachment, selected-cookie/receive agreement.
- Real 4096/1024 socket-default and 2048/512 cmsg-override GSO sends and returned
  multi-segment GRO; ordinary 256-byte sends with explicit cmsg override to zero.
- Invalid four-byte TX cmsg rejection, empty-receiver EAGAIN, data/control
  truncation, peek versus consumed receive, shared FD and real FD reuse.
- A real partial `sendmmsg` (one valid message then invalid control) and partial
  `recvmmsg`. TX observes each kernel send; RX records excluded API coverage and
  makes no `recvmmsg` GRO claim.
- Unreadable recvmsg header and successful kernel receive followed by failed
  sockaddr copyout, preventing a false positive from kernel return alone.
- A real count-map capacity of **one**, forcing map-update overflow after the
  first positive example. Loss must be reported and that example must survive.
- Missing-BTF path, absent-symbol lookup and a capability-stripped observer
  attempt. Actual host restrictions are retained, even if they block testing a
  later failure stage; these injection cases are labelled in their filenames.

Every fixture assigns `SO_COOKIE` **before** bind, attachment or traffic. Evidence
identity is boot ID + network namespace inode + socket cookie within the recorded
fixture lifetime. Socket rows retain PID/start ticks and FD generation, opening
and descriptor-close times. Duplicate descriptors share a cookie; reused FDs get
a fresh cookie. The observer exports no FD, port-only identity, packet address,
raw pointer or decoded program instructions. Softirq matching uses the actual
socket/netns; classic state is per CPU, with nesting failures recorded. `cpu`
means CPU, never gateway worker PID. Kernel destruction and arbitrary-process
FD/lineage tracking are **not implemented**; descriptor close is not presented as
a kernel destruction timestamp. A zero/unassigned cookie is unknown and counted
as lost identity, never joined by port or substituted with a published pointer.

## Bounds, lifecycle and results

Root's later integration can own stdin/stdout of the compiled observer:

```text
observer OBJECT {tx|rx|classic} NETNS {512|1} {normal|missing-btf|missing-symbol}
stdout: one JSON ready record after every required link is attached
stdin:  s = snapshot (at most four), q = stop
stdout: final JSON snapshot after detach; SIGTERM also requests orderly stop
```

Start the observer before fixture sockets exist, wait for `ready`, retain it
through descriptor closure, then stop and read `final`. Each family has its own
readiness and coverage; no failed family invalidates another working family's
positive evidence. The current 30-second observer limit is deliberately too
small for a campaign and must be reviewed before harness integration. In-flight
operations at detach remain pending and invalidate complete interval coverage.

The maps have 512 distinct metadata keys and 64 pending operations per direction,
plus one selector state per possible CPU. There is no eviction, packet stream,
ring buffer or unbounded per-packet log. Rows aggregate counts and first/last
monotonic timestamps for cookie/selected cookie/kind/length/stride/return/CPU.
They serve as bounded positive examples. Control parsing is limited to eight
headers and 256 bytes; only the allowlisted GRO integer is decoded. Overflow,
unknown cookies, failed reads, nesting, unmatched contexts, excluded RX APIs,
record attempts, successful records, map read failures and outstanding operations
are retained. Ring loss and event-sequence gaps are inapplicable to count maps
and represented as null/reason, never invented zeros. Unobservable kernel tracing
recursion/misses are not quantified, so even apparently clean fixture snapshots
do not authorize global absence, exact totals or complete routing distribution.

Verifier diagnostics are capped at 768 KiB per case and address-like diagnostics
are redacted. Command output has explicit truncation flags. The artifact budget
is 64 MiB; exceeding it fails the lane. No packet payload/header, QUIC key,
arbitrary ancillary value, socket address or runtime kernel pointer is retained.
Source code, objects and fixture classic-instruction hashes are retained as
provenance, not as captured traffic. Incomplete evidence keeps positive witnesses
while refusing absence/totals claims.

`summary.json` indexes individual case JSON/log files. Status meanings:

| Status | Meaning / CI behavior |
|---|---|
| `supported` | A case's declared limited surface ran and its runtime assertions passed. Not universal H3 proof. |
| `unsupported` | Exact unavailable capability/stage/errno, or missing positive loopback GRO delivery, with available fixture/provenance evidence retained. Does not fail CI by itself. |
| `partial_coverage` | Positive evidence can survive a gap, excluded API, forced overflow or fallback execution ambiguity. No exact totals/absence/distribution claim. |
| `error` | Compile, verifier, attach implementation error, attribution/assertion failure, timeout, broken protocol, map read failure or artifact-budget failure. CI fails. |

The aggregate is at best `partial_coverage` because the implementation deliberately
excludes other surfaces. The injected unavailable cases never zero-fill counters.
Software CPU-clock and hardware-cycle `perf_event_open` attempts run independently
at observer and fixture privilege levels, recording open/read errors and actual
enabled/running time. Unavailable PMUs have `value: null`; they do not invalidate
working socket probes and never become zero cycles or a contention diagnosis.

## Remaining root-owned work

IPv6, compat syscalls, `recvmmsg`/read/recvfrom RX proof, arbitrary socket lifecycle,
process/container lineage, group replacement/membership churn and per-operation
gateway peer/role attribution are unsupported by this initial observer. Userspace
control metadata also assumes the fixture's single thread owns its receive buffer;
concurrent mutation of another process's returned control buffer is not addressed.
TX evidence is kernel acceptance, not delivery, physical NIC segmentation or a
successful outer `sendmmsg` result-buffer copyout. Batches retain independent
fixture returns. Loopback GRO/GSO is software transport evidence, not NIC offload.

After root reviews actual hosted capabilities, integrate only supported paths,
calibrate observer-off/on overhead on the same host, and implement gateway
identity/coverage before claiming workload exercise. Envoy upstream's non-GSO
writer remains an explicit implementation disposition. Ferrum single/shared Quinn
endpoints do not require Envoy reuseport steering. Do not change either gateway
to manufacture positive events.

The later approved comparison uses corrected official Envoy **1.34.0 Linux amd64**
`docker.io/envoyproxy/envoy@sha256:79c4e987d386b176721638187b511fb4d7041695f7a78e422ed27edd707b3eeb`,
as verified in root's static plan, with cap100/cap4 on identical image, config
and budget across all five payloads and four pairs. This lane neither downloads
nor re-verifies that image. No source-build twins, counter-fix throughput
attribution, expensive campaign or reinterpretation of historical 1.33 results
is part of this prerequisite. Root owns integration, PRs, dispatch, exact-head
review and all conclusions for #5588 / dependency PR #5602.
