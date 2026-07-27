# Protocol Performance Regression

Scheduled and manually runnable multi-protocol performance regression for
Ferrum Edge. This lane tracks throughput, error rate, and latency percentiles
across the supported protocol matrix, plus connection churn, long-lived soak /
resource plateaus, and reload-under-load coverage.

It is **not** a required pull-request check for the scheduled multi-protocol
benchmark itself. Required PR CI does run lightweight static contracts for this
lane inside the `Performance Regression Check` job in `.github/workflows/ci.yml`
(workflow verifier self-test + repository contract, evaluator self-test, and a
`python3 -m py_compile` check of the scenario harness) before optional
benchmark/build gating. That PR job has read-only contents permission and does
not persist checkout credentials while running PR-controlled code. The
lightweight HTTP/1 overhead gate in `ci.yml`
remains the PR path for measured overhead. Noisy shared-runner microbenchmarks
stay out of branch protection.

## Documented runner and build profile

| Setting | Value | Notes |
|---|---|---|
| Runner class | `ubuntu-latest` | GitHub-hosted; expect noisy-neighbor variance |
| Gateway build profile | `ci-release` | Stable CI-oriented release profile from root `Cargo.toml` |
| Harness build profile | `release` | `tests/performance/multi_protocol` is not a workspace member and uses its local `release` profile |
| Workflow | `.github/workflows/protocol-perf-regression.yml` | `schedule` (Sundays 05:00 UTC) + `workflow_dispatch` |

Do not treat numbers from this lane as production SLOs until absolute floors are
filled in after measured runner variance.

## What it records

Per supported protocol (gateway path):

- Throughput (RPS)
- Error rate
- Latency p50 / p95 / p99

Additional scenarios from
`tests/performance/multi_protocol/run_protocol_regression_scenarios.py`:

- **Connection churn** — HTTP/1 with keep-alive / idle pool disabled
- **Long-lived soak** — `proto_bench saturate` hold window
- **Resource plateau** — RSS, FD count, and task/thread samples from `/proc`
  after the connection ramp, comparing early/late three-sample medians
- **Reload under load** — file-mode `SIGHUP` while traffic is flowing

## Budgets and trends

Versioned budgets live in
`tests/performance/multi_protocol/protocol_perf_budgets.json`.

- `enforcement` starts as `alert` (warnings only for **measured** budget
  breaches; soft product regressions stay green) so shared-runner variance
  does not block the schedule.
- **Harness / data-completeness failures are always hard failures**, even
  while `enforcement` is `alert`: missing expected protocol samples,
  missing per-iteration RPS/error/p50/p95/p99 fields, zero-total/invalid
  metrics, non-finite or malformed numeric fields (NaN, Infinity, non-numeric
  counts/rates/plateau arrays), missing or malformed runner-health/history
  evidence, nonzero scenario benchmark exits, an undelivered reload `SIGHUP`,
  missing required scenario output, and insufficient RSS/FD/task sampling all
  fail the job.
  Finite measured product regressions such as zero RPS or large latency stay
  alert-only under `enforcement=alert`.
- Absolute `min_gateway_rps` / `max_p*_us` floors are intentionally `null`
  until operators measure variance on `ubuntu-latest` + `ci-release` and fill
  them in. Do not invent floors from unexecuted local runs.
- When prior trend artifacts exist, the evaluator also applies a rolling
  median ± MAD comparison (`rolling` block in the budgets file). History is
  accepted only from the newest successful `main` run, validated against schema
  version 1, filtered to the same runner/build profile, and bounded to the
  configured rolling window.
- Each run publishes machine-readable artifacts:
  - `combined_results.json`
  - `budget_report.json`
  - `protocol_perf_trends.json`
  - `runner_health.json` / `runner_health.log`

Evaluator:
`tests/performance/multi_protocol/evaluate_protocol_perf_budgets.py`.

## Distinguishing product regressions from noisy neighbors

Retain and inspect:

- `runner_health.json` — CPU steal sample, scheduler jitter, `nproc`
- Multi-iteration matrix outputs (`matrix_run*.json`)
- Budget alerts vs hard failures (`enforcement`)
- Scenario resource series under `scenarios/resource_plateau`

If steal/jitter is elevated or CV across iterations is high, treat throughput
and latency alerts as provisional.

## Manual dispatch

Actions → **Protocol Performance Regression** → Run workflow.

Optional inputs: duration, concurrency, iterations, and one protocol selection
(or `all` for the complete matrix).

## Local static checks (no benchmarks)

```bash
python3 .github/scripts/verify_protocol_perf_regression_workflow.py --self-test
python3 .github/scripts/verify_protocol_perf_regression_workflow.py
python3 tests/performance/multi_protocol/evaluate_protocol_perf_budgets.py --self-test
python3 -m py_compile tests/performance/multi_protocol/run_protocol_regression_scenarios.py
```

Full-mode PR CI runs the same static set in `Performance Regression Check`
immediately after checkout.

## Related surfaces

- Manual exploratory matrix: `.github/workflows/perf-benchmark.yml`
- PR overhead gate: `tests/performance/ci_overhead_bench.py` via `ci.yml`
- Connection saturation headlines: `docs/connection_saturation_benchmark.md`
- Suite index: `tests/performance/README.md`
- Scheduled lane details: this document (performance suite READMEs stay
  unchanged so trusted Cross automation digests are not rewritten)
