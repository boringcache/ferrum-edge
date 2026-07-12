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
| PR-001 | mesh live gate | Issue #2104: Ambient row east-west traversal not firewall-proven | Medium (test integrity) | IN-PROGRESS (sol agent) |

## Needs human decision

(none yet)
