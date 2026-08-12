# Mesh Performance Baseline

**Directional reference numbers only.** Hardware-specific absolute values are
not universal product targets. Only defensible normalized/self-relative
guardrails (for example the hosted `ip_restriction` scaling ceilings already
enforced in CI) become gates. Treat the tables below as a same-runner reference
shape, not a laptop SLA.

> **Publication status (issue #3332):** result cells remain `_TBD_` until a
> GitHub-hosted `Mesh Performance Baselines` workflow run produces zero-error
> Criterion artifacts and those numbers are copied into this file. Do not fill
> cells from local machines.

## Reference environment (filled from hosted provenance)

| Field | Value |
|---|---|
| Ferrum commit SHA | _TBD_ (from `provenance.json`) |
| Runner class | `ubuntu-24.04` (GitHub-hosted Linux; pinned) |
| CPU model / topology | _TBD_ |
| RAM | _TBD_ |
| OS / kernel / arch | _TBD_ |
| Rust toolchain | `rust-toolchain.toml` → `stable` (exact `rustc --version --verbose` in artifact) |
| Criterion / harness | `tests/performance/mesh` (`criterion` pin in that crate's lockfile) |
| Build profile / features | Criterion `bench` profile inherits `release`; default features |
| Non-default settings | none beyond harness defaults |
| Warmup / measurement | `--warm-up-time 3 --measurement-time 15` per bench |
| Raw artifacts | Actions artifact `mesh-performance-baselines-<sha>` → `mesh/criterion/**` + `summary.json` |

## Commands

```bash
# Preferred: hosted collection
# Actions → "Mesh Performance Baselines" → suites=all (or mesh)

# Equivalent Criterion invocation used by the workflow:
cargo bench --manifest-path tests/performance/mesh/Cargo.toml --bench authz_match \
  -- --warm-up-time 3 --measurement-time 15
cargo bench --manifest-path tests/performance/mesh/Cargo.toml --bench ip_restriction \
  -- --warm-up-time 3 --measurement-time 15
cargo bench --manifest-path tests/performance/mesh/Cargo.toml --bench slice_apply \
  -- --warm-up-time 3 --measurement-time 15
cargo bench --manifest-path tests/performance/mesh/Cargo.toml --bench xds_translation \
  -- --warm-up-time 3 --measurement-time 15
```

## authz_match

`policy::evaluate_mesh_authorization_policies` over N synthetic ALLOW policies, request that misses every rule (worst case — every policy is fully traversed before the implicit-deny return).

| Policies (N) | Mean per call | Notes |
|---|---|---|
| 10 | _TBD_ | |
| 100 | _TBD_ | |
| 1 000 | _TBD_ | |
| 10 000 | _TBD_ | Worth tracking — fleets ship 1k–10k AuthorizationPolicy resources in larger Istio installations. |

## ip_restriction

`IpRestriction::on_request_received` over 10,000 sparse exact IPv4 intervals.
The authoritative client IP cache is initialized before timing so the result
isolates the async plugin hook and compiled interval lookup. The hosted
`Performance Regression Check` runs all four cases, pairs each with a 100-rule
same-run reference, enforces the guardrails below, and retains Criterion output.

| Decision shape | Instances | Mean per iteration | Notes |
|---|---:|---|---|
| Deny miss above every interval | 1 | _TBD_ | Worst-case ordered miss. |
| Deny miss above every interval | 4 | _TBD_ | Supported multiple scoped-instance composition. |
| Allow match in final interval | 1 | _TBD_ | High-address match. |
| Allow match in final interval | 4 | _TBD_ | High-address match across multiple instances. |

Hosted guardrails are intentionally generous and separate from the directional
reference numbers in this file. For each decision shape and instance count, the
10,000-rule Criterion mean must be at most 8x its 100-rule same-run mean and at
most 10 microseconds per plugin instance. The self-relative limit detects a
return to rule-count-proportional scans; the absolute ceiling also catches a
catastrophic regression in the cached client-IP or constant-time hook overhead.

## slice_apply

`MeshSlice::from_gateway_config(&GatewayConfig, MeshSliceRequest)` over N synthetic workloads + matching MeshService rows.

| Workloads (N) | Mean per call | Notes |
|---|---|---|
| 100 | _TBD_ | |
| 1 000 | _TBD_ | |
| 5 000 | _TBD_ | |

## xds_translation

`xds::translator::translate_mesh_slice_to_snapshot(&MeshSlice)` over a slice with N workloads + 1 service each.

| Workloads (N) | Mean per call | Notes |
|---|---|---|
| 100 | _TBD_ | |
| 1 000 | _TBD_ | |
| 5 000 | _TBD_ | |

## Overhead formula

These microbenchmarks have no direct-vs-gateway comparison. For E2E suites the
shared throughput overhead definition is:

`overhead_percent = ((direct_throughput - gateway_throughput) / direct_throughput) * 100`

where throughput is RPS (HBONE) or QPS (DNS upstream-forward). Latency quantiles
are reported beside the overhead column and are not folded into it.

## Rerun procedure

1. Push the candidate SHA (or use the PR branch).
2. Run Actions → **Mesh Performance Baselines** → `suites=mesh` or `all`.
3. Download artifact `mesh-performance-baselines-<sha>`.
4. Confirm `summary.json` → `acceptance_gate.mesh_complete == true` and
   `runner_health_ok == true` (CPU steal ≤ 5.0% across the pre-collection
   vmstat sample and each selected E2E workload-interval `/proc/stat` steal
   delta; see `runner_health.json` and `logs/runner_health_probes.jsonl`).
5. Copy Criterion means (and σ / CI from `estimates.json`) into the tables above.
6. Link the artifact (or commit a companion `summary.json` excerpt) from the
   reference-environment table.
7. Re-check interpretation notes below for harness bottlenecks before treating
   numbers as gateway capacity.

## Bottleneck review

- These are **single-threaded** Criterion micro-benches. Production paths can
  amortise across cores; per-call times are a per-CPU upper bound, not aggregate
  throughput.
- `authz_match` measures the worst-case linear scan. The plugin layer caches
  PolicyScope filter results per-request; that cache is _not_ exercised here.
- `ip_restriction` measures the compiled O(log n) lookup after canonical
  client-IP caching; policy construction and rule parsing are outside the timed
  loop.
- `slice_apply` measures the cold rebuild. The ArcSwap swap itself is ~constant
  time and is not included in the bench window.
- `xds_translation` runs on the CP side; DP fingerprint-dedup downstream means
  most translations get reused, so production hit rate is high.

## Refresh cadence

Refresh this table when any of the following land on `main`:

- Material changes to mesh authz evaluation, `ip_restriction` lookup, slice
  apply, or xDS translation hot paths.
- Criterion / harness dependency bumps that change measurement semantics.
- Runner-class changes for the hosted collection workflow.
- At least once per minor release train, or sooner if a sustained CI
  self-relative guardrail alert fires.

Re-run via `.github/workflows/mesh-performance-baselines.yml` and publish only
zero-error hosted results.
