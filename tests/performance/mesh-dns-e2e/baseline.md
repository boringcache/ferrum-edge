# Mesh DNS Proxy E2E Baseline

**Directional reference numbers only.** Hardware-specific absolute QPS/latency
are not universal product targets. Use same-run direct-stub comparisons and
self-relative trends; do not promote opportunistic laptop numbers into CI floors.

> **Publication status (issue #3332):** UDP/TCP gateway and direct-stub cells
> remain `_TBD_` until a hosted `Mesh Performance Baselines` workflow run yields
> ≥3 clean zero-error repetitions and those aggregates are copied here.

## Reference environment (filled from hosted provenance)

| Field | Value |
|---|---|
| Ferrum commit SHA | _TBD_ |
| Runner class | `ubuntu-latest` (GitHub-hosted Linux) |
| CPU / RAM / OS / kernel / arch | _TBD_ (see `provenance.json`) |
| Rust / harness versions | from artifact provenance |
| Build profile / features | `--release`, default features |
| Non-default settings | `run.sh` mesh-mode DNS env (`FERRUM_MESH_DNS_*`, stub CP/upstream) |
| Warmup / repetitions | listener ready then loadgen; **≥3 clean repetitions** |
| Command | `./run.sh --skip-build --json --duration 60 --concurrency 100 --protocol both` |
| Raw artifacts | `mesh-performance-baselines-<sha>` → `dns/run_*.txt` + `summary.json` |

## Overhead formula

For the upstream-forward class only:

```text
overhead_percent = ((direct_stub_qps - gateway_upstream_forward_qps) / direct_stub_qps) * 100
```

Mesh-internal and mesh-wildcard names exist only inside the gateway resolution
table, so those rows are absolute gateway measurements (no direct baseline).

Latency p50/p90/p99 are means across clean repetitions and are not folded into
the overhead percent.

## Commands

```bash
# Hosted (required for publication):
# Actions → "Mesh Performance Baselines" → suites=dns|all, iterations=3

cd tests/performance/mesh-dns-e2e
./run.sh --skip-build --json --duration 60 --concurrency 100 --protocol both
```

## Via gateway (127.0.0.1:15053)

UDP transport:

| Name class | qps | p50 | p90 | p99 | Notes |
|---|---|---|---|---|---|
| mesh-internal | _TBD_ | _TBD_ | _TBD_ | _TBD_ | exact `DnsResolutionTable.exact` hit |
| mesh-wildcard | _TBD_ | _TBD_ | _TBD_ | _TBD_ | one-label wildcard suffix match |
| upstream-forward | _TBD_ | _TBD_ | _TBD_ | _TBD_ | UDP forward to `dns_upstream_stub` |

TCP transport (RFC 1035 §4.2.2 length-framed):

| Name class | qps | p50 | p90 | p99 | Notes |
|---|---|---|---|---|---|
| mesh-internal | _TBD_ | _TBD_ | _TBD_ | _TBD_ | |
| mesh-wildcard | _TBD_ | _TBD_ | _TBD_ | _TBD_ | |
| upstream-forward | _TBD_ | _TBD_ | _TBD_ | _TBD_ | |

## Direct baseline (dns_upstream_stub)

Only the upstream-forward class is meaningful here (mesh-internal / mesh-wildcard names exist only inside the gateway).

| Class | Transport | qps | p50 | p90 | p99 |
|---|---|---|---|---|---|
| upstream-forward | UDP | _TBD_ | _TBD_ | _TBD_ | _TBD_ |
| upstream-forward | TCP | _TBD_ | _TBD_ | _TBD_ | _TBD_ |

## Rerun procedure

1. Trigger **Mesh Performance Baselines** (`suites=dns` or `all`, `iterations≥3`).
2. Download `mesh-performance-baselines-<sha>`.
3. Require `summary.json` → `dns_complete` and `dns_errors_ok`.
4. Discard any repetition with unexplained non-zero `total_errors`.
5. Publish mean qps/latency into the tables and record upstream-forward overhead
   with the formula above.
6. Link the artifact paths for raw JSON blobs.

## Bottleneck review

- **Mesh-internal hit latency** measures `DnsResolutionTable::resolve` exact-path
  plus response template construction. Should be dominated by the `DashMap`
  cache hit on the second-and-later identical queries (`cached_mesh_response`).
- **Mesh-wildcard latency** adds a one-label suffix scan (sorted by suffix
  length) — expect a small p99 bump versus exact matches.
- **Upstream-forward latency** = round-trip to `dns_upstream_stub` + gateway
  txid rewriting cost. Subtract the direct-stub baseline to attribute gateway
  overhead.
- Localhost-only topology; Linux `recvmmsg` vs other OS UDP paths differ —
  publish per runner OS/class.
- CP stub publishes one slice; slice-churn cost belongs to `mesh/slice_apply`,
  not these rows.
- Shared-runner CPU steal can inflate p99; re-run when health checks warn.

## Refresh cadence

Refresh after DNS proxy, resolution-table, or mesh CP subscribe changes; after
harness SYNC dependency bumps; after runner-class changes; and at least once per
minor release train. Collect only via
`.github/workflows/mesh-performance-baselines.yml` on GitHub-hosted Linux.
