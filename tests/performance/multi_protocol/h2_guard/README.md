# Temporary H2 receive-guard observation

This hosted-only diagnostic follows the failures recorded in
[`docs/benchmark_h2_grpc_2026_09_18.md`](../../../../docs/benchmark_h2_grpc_2026_09_18.md)
for issue #5588. It distinguishes the two DATA guards and the other local
reason-11 reset guards on the actual reqwest/native Hyper dependency paths.
It is observation work; no production repair or throughput improvement is
established by this change.

The ordinary Cargo manifests, lockfiles, vendored inventory and published
images continue to use the existing dependency graph. `prepare.py` requires a
GitHub-hosted Linux runner, copies the checkout into a new temporary directory,
verifies the immutable h2 0.4.19 archive/revision and every modified preimage,
applies the reviewed patch without fuzz, verifies postimages and injected
assets, and selects the result only in that copy. The generated Dockerfile
retains the ordinary stages/features and adds `--locked` to its Cargo builds.
The manual job loads its image locally and does not publish it or export its
cache. Graph verification requires both transport paths to select the patched
crate. `source.json` is the exact source, patch and asset identity record.

All existing guards, budgets, thresholds, return values, receive ordering and
credit-return operations remain intact. The patch adds bounded numeric
observations only when the narrow `ferrum_h2_guard=debug` target is enabled.
It never logs payloads, headers, peers or arbitrary dependency error strings.
The existing `ferrum_h2_observe=debug` target remains enabled in both arms.

The branch codes are:

| Code | Existing guard |
|---|---|
| 1 | Nonempty, nonfinal DATA framing-credit exhaustion |
| 2 | Empty, nonfinal DATA lifetime count |
| 3 | Local error-reset count in the send path |
| 4 | Local error-reset count in the receive-error path |
| 5 | Remotely reset pending-accept streams |

IDs are local to one gateway process. `last_stream`, `last_len`, `last_flow`
and `last_end` describe the last observed DATA frame; `trigger_stream` names
the stream involved in a guard event, which can differ for reset guards.
There is no claimed cross-hop, request, reqwest-pool or native-gRPC mapping.
Window fields describe local state and API updates, not independently observed
peer negotiation. The initial constructor record precedes later window
updates; inspect a failure/terminal snapshot for those updates. Lifetime
counters include earlier payloads. A record's phase is its emission time,
not a per-frame timeline, and cross-process clock skew is not measured.

Each process admits at most 4,096 observed connections, 4,096 lifecycle
records and 256 reserved failure records. Suppression notices occur only at
powers of two and therefore provide lower bounds after the last notice.
The parser bounds record count/bytes and reports malformed records, sequence
gaps, sampled logger-drop counters and suppression as explicit coverage
limitations. Captures end before forced container removal; live connections
may have no terminal record. Partial capture can establish a positively
observed guard, but cannot establish absence, exact complete totals or the
cause of every client error. Every instrumented sample is excluded from
ordinary accepted performance comparisons, including error-free samples.

## Hosted validation and dispatch

Pull requests touching the assets run `H2 pinned guard regressions`. The job
verifies/prepares the source, formats the generated dependency on the runner,
compiles/lints it, exercises its real receive/poll/clear paths and existing
budget tests, checks both dependency chains, and runs the harness tests.
Artifacts retain the input archive, patch/assets, generated source, selection
diff, compiler identities and logs. No local project execution is required.

After the workflow is registered on the default branch, root can dispatch
`h2-guard-observation.yml` at the reviewed ref with `run_campaign=true`.
The default `false` runs checks only. The campaign uses the explicitly selected
`h2_guard/experiment.json`; ordinary `experiment.json` remains disabled.
HTTP/2 has 12 canonical samples (70 KiB); gRPC has 24 (10/70 KiB): four
counterbalanced pairs of direct/adaptive/fixed arms, 15 seconds and 200 offered
workers. Existing CA/name, exact status/body/protobuf, phase, failed-sample,
hardware and configuration checks remain in force. The original guard build
is shared between both arms; only the declared window policy differs.
`guard-evidence-index.json` retains every expected sample and reports missing
or incomplete observations. Request errors are evidence and are never retried
away or silently discarded. Results require root inspection of raw artifacts.

## Ownership and retirement

Owner: Ferrum Edge maintainers, tracked by issue #5588. This is an unshipped,
temporary diagnostic patch rather than a new entry in the production vendored
crate inventory. No upstream repair has been proposed by this change.
Reassess at each campaign and remove the workflow, patch and selection/parser
seams once the observed guard mechanism has a recorded disposition and any
necessary correction has its own regression and normal review/CI path.
An h2 version change fails preparation until its source and observations are
reviewed anew. Promoting a dependency repair to a shipping graph requires the
normal dependency lifecycle inventory, retirement plan and behavioral gates;
this diagnostic lane does not authorize that promotion.
