# Production Readiness Ledger — Ferrum Edge

Maintained by the production-readiness orchestration epic (started 2026-07-12).
Status values: `OPEN`, `IN-PROGRESS (PR #N / agent)`, `FIXED (PR #N)`, `TRACKED (issue #N)`,
`OUT-OF-SCOPE (rationale)`, `NEEDS HUMAN DECISION`.

## Launch gate summary

| Gate | Status |
|------|--------|
| Feature set implemented or proven out of scope | AUDITING |
| All deferral markers resolved or tracked | AUDITING |
| Critical/high/medium bugs fixed | AUDITING |
| Docs truthful vs code | AUDITING |
| Security posture verified | AUDITING |
| Deployment/CI/release readiness | AUDITING |

## Baseline (2026-07-12)

- main @ 7d4c017e2, CI green as of merge of #2103.
- Open PRs: none. Open issues: #2104 (live two-cluster gate firewall proof — test-fixture hardening).
- ~259 deferral-style markers in `src/` + `custom_plugins/` pending triage (many likely benign
  rustdoc references; audit in progress).
- Known intentional trade-offs (do NOT "fix"): WAF body gates, JWKS retain guard, dedup try_lock
  eviction, MCP serve-stale-templates-during-refresh-outage, H3 streaming-trailer accepted
  limitation, SD rework rejection. See repo history and `.claude/rules/*`.

## Findings ledger

| ID | Area | Finding | Severity | Status |
|----|------|---------|----------|--------|
| PR-001 | mesh live gate | Issue #2104: Ambient row east-west traversal not firewall-proven | Medium (test integrity) | FIXED (PR #2105 merged 2026-07-12; codex clean, CI green) |
| PR-002 | mesh TLS | Outbound mesh SPIFFE verification skips CRL revocation (src/tls/spiffe.rs:441-445); inbound-only asymmetry, undocumented | Medium (security) | IN-PROGRESS (PR #2113; codex P2 confirmed: mesh pools must consume SharedCrlList live-reload slot, not startup snapshot — fix round dispatched) |
| PR-003 | identity CA | InternalCa CSR path lacks PoP; UDS-only-safe today (internal.rs:267-285) | Low (hardening) | IN-PROGRESS (issue #2108, opus agent) |
| PR-004 | identity | SPIFFE Workload API JWT-SVID unimplemented; X.509 complete | Low | TRACKED (#2110) |
| PR-005 | k8s controller | Merge-Patch status writes (SSA TODO, TOCTOU); naming-convention proxy-id reconstruction | Low | TRACKED (#2110) |
| PR-006 | k8s controller | Stale "F3 §3.3 UDP not implemented" message (istio_status.rs:923) | Low (accuracy) | IN-PROGRESS (issue #2108) |
| PR-007 | logging | Log schema not applied to WsDisconnectLogEntry; documented fallback | Low | TRACKED (#2110) |
| PR-008 | CI | Main redness driven by flakes #2057/#2060 + port races | Medium (ops) | RESOLVED-MONITOR (fixes merged + #2103 hardening, flake issues closed 2026-07-10; monitor main through epic) |
| PR-009 | release | release.yml lacked tag↔Cargo-version guard | Medium (ops) | FIXED (PR #2109 merged 2026-07-12) |
| PR-010 | release | No CHANGELOG/policy | Medium (ops) | FIXED (PR #2109 merged 2026-07-12) |
| PR-011 | security | Admin JWT lacks optional `aud` validation | Low (hardening) | IN-PROGRESS (issue #2108) |
| PR-012 | ops | Dockerfile.release FERRUM_LOG_LEVEL=error hides startup warns | Low | IN-PROGRESS (issue #2108) |
| PR-013 | ops | No Helm chart for core gateway modes | Low | TRACKED (#2110) |
| PR-014 | ops | Stress tests excluded from CI; no scheduled scaling guard | Low | TRACKED (#2110) |
| PR-015 | docs | REFACTORING_PLAN.md stale (~400 PRs behind); WEBSOCKET.md missing tunnel-mode; admin_api.md LB list incomplete | Medium (stale root doc) | FIXED (PR #2112 merged 2026-07-12) |
| PR-016 | docs | 11 documented feature deferrals (docs audit) — all accurately labeled, graceful behavior | Low | TRACKED (#2110; mesh retry re-screen already #2008) |

Docs audit: ZERO overclaims across README/FEATURES/62 docs; configuration.md↔env_config.rs parity clean
(no dead vars); openapi.yaml 1:1 with admin dispatch; all 82 plugins in openapi; priorities match
plugin_execution_order.md.

Security audit: 0 critical/high/medium. Verified strong: admin single JWT gate + tiered observability,
JWT validate_exp/nbf + fixed alg, constant-time comparisons, mesh authz fail-closed, no secret logging,
smuggling guards, anchored resource ids, recursive credential rejection in extractor, deny.toml ignores
all rationaled+expiry, SSRF/DNS-rebinding posture intact.
Ops audit OK highlights: no always()-aggregator escape in CI gate; #[ignore] tests run via nextest
--run-ignored=all; shard-coverage gates active; injector/node_agent/migrate all have functional tests;
licenses consistent.

## Needs human decision

(none yet)
