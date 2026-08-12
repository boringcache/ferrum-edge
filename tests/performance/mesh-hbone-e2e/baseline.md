# Mesh HBONE E2E Baseline Numbers

**Directional reference numbers only.** Absolute RPS/latency depend on the
GitHub-hosted runner class and are not universal product targets. Prefer the
same-run overhead percent (and self-relative CI guardrails elsewhere) over raw
RPS when interpreting regressions.

> **Publication status (issue #3332):** every result cell remains `_TBD_` until
> a hosted `Mesh Performance Baselines` run completes with zero errors across
> ≥3 clean repetitions and those aggregates are copied here. Local laptop runs
> must not be published as baselines.

## Test environment

| Field | Value |
|---|---|
| CPU | _TBD_ |
| RAM | _TBD_ |
| OS / kernel | _TBD_ |
| Architecture | _TBD_ |
| Ferrum Edge revision | _TBD_ |
| Runner class | `ubuntu-24.04` (GitHub-hosted Linux; pinned) |
| Rust / harness versions | from artifact `provenance.json` |
| Build profile | `--release` |
| Feature flags | default (no `--features`) |
| Non-default Ferrum/env settings | harness `run.sh` file-mode + `FERRUM_GATEWAY_SVID_*` SPIFFE material |
| Warmup / repetitions | steady-state loadgen after gateway ready; **≥3 clean repetitions** per row |
| Commands | see below |
| Raw artifacts | `mesh-performance-baselines-<sha>` → `hbone/**/run_*.txt` + `summary.json` |

## Overhead formula

```text
overhead_percent = ((direct_rps - gateway_hbone_rps) / direct_rps) * 100
```

Computed from the mean RPS across clean repetitions of the same scenario.
Latency p50/p95/p99 are means of per-run quantiles and are **not** inputs to the
overhead percent.

## Commands

```bash
# Hosted (required for publication):
# Actions → "Mesh Performance Baselines" → suites=hbone|all, iterations=3

# Row-shaped invocations (used by the workflow after one release build):
cd tests/performance/mesh-hbone-e2e
./run.sh --skip-build --json --duration 30 --concurrency 50 --payload-size 1024
./run.sh --skip-build --json --duration 30 --concurrency 50 --payload-size 16384
./run.sh --skip-build --json --duration 60 --concurrency 100 --payload-size 262144
```

## 1 KiB payload, concurrency 50, 30 s

| Path              | RPS    | p50    | p95    | p99    | Overhead vs direct |
|-------------------|--------|--------|--------|--------|--------------------|
| Direct baseline   | _TBD_  | _TBD_  | _TBD_  | _TBD_  | —                  |
| Gateway + HBONE   | _TBD_  | _TBD_  | _TBD_  | _TBD_  | _TBD_ %            |

## 16 KiB payload, concurrency 50, 30 s

| Path              | RPS    | p50    | p95    | p99    | Overhead vs direct |
|-------------------|--------|--------|--------|--------|--------------------|
| Direct baseline   | _TBD_  | _TBD_  | _TBD_  | _TBD_  | —                  |
| Gateway + HBONE   | _TBD_  | _TBD_  | _TBD_  | _TBD_  | _TBD_ %            |

## 256 KiB payload, concurrency 100, 60 s

| Path              | RPS    | p50    | p95    | p99    | Overhead vs direct |
|-------------------|--------|--------|--------|--------|--------------------|
| Direct baseline   | _TBD_  | _TBD_  | _TBD_  | _TBD_  | —                  |
| Gateway + HBONE   | _TBD_  | _TBD_  | _TBD_  | _TBD_  | _TBD_ %            |

## Rerun procedure

1. Trigger **Mesh Performance Baselines** on the candidate SHA (`suites=hbone` or `all`).
2. Download `mesh-performance-baselines-<sha>`.
3. Require `summary.json` → `acceptance_gate.hbone_complete` and `hbone_errors_ok`.
4. Require `repetition_evidence` showing 3–5 clean gateway and direct samples per
   scenario (matching the bounded workflow input).
5. Require `runner_health_ok` (CPU steal ≤ 5.0% in `runner_health.json` and
   per-run probes); reject the collection for publication when exceeded.
6. Reject any repetition with non-zero `total_errors`; do not average failures away.
7. Publish mean RPS / latency across remaining clean runs and the overhead percent
   from the formula above.
8. Attach or link the raw `hbone/**/run_*.txt` JSON blobs from the artifact.

## Bottleneck review

Before treating Gateway+HBONE RPS as “gateway capacity”:

- Topology is localhost loadgen → file-mode gateway → stub sidecar → echo backend.
- mTLS + H2 CONNECT setup is amortized; numbers are steady-state, not handshake cost.
- Direct baseline bypasses gateway **and** sidecar; overhead includes tunnel relay,
  not only `ferrum-edge` proxy overhead.
- Shared GitHub runners can show CPU steal; publication fails closed when steal
  exceeds **5.0%** (re-run rather than publishing impaired numbers).
- Userspace HBONE relay (no `splice` fast path through TLS) dominates large payloads.

## Refresh cadence

Refresh after HBONE pool / mTLS / outbound mesh-tag routing changes, harness
dependency SYNC bumps (`rustls`/`h2`), runner-class changes, or each minor
release train. Always re-collect on GitHub-hosted runners via
`.github/workflows/mesh-performance-baselines.yml`.
