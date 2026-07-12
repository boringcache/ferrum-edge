# Agent Task Board — Production Readiness Epic

Cap: ≤6 active subagents (≈3 sol + 3 Opus). CI is the gate; no local builds/tests.

## Active

| Slot | Agent | Task | State |
|------|-------|------|-------|
| S1 | sol (medium) | Issue #2104 → PR #2105 opened; codex round 1 triggered | awaiting codex/CI (orchestrator watching) |
| O1 | opus discovery | Deferral-marker triage audit — DONE: 0 high / 1 med (outbound CRL asymmetry) / 6 low | complete |
| O2 | opus discovery | Docs-truth audit — DONE: 0 overclaims, 3 stale, 11 tracked deferrals | complete |
| S4 | sol (medium) | Issue #2111 → PR #2112; orchestrator review done (approved; tunnel-mode doc verified vs code) | awaiting codex/CI |
| O3 | opus discovery | Security audit — DONE: 0 crit/high/med, 2 low | complete |
| O4 | opus discovery | Ops/CI/release audit — DONE: 0 high, 3 med, 5 low | complete |

| S2 | sol (high) | Issue #2106 → PR #2113; orchestrator review done (approved) | awaiting codex/CI |
| S3 | sol (medium) | Issue #2107 → PR #2109; orchestrator review done (approved) | awaiting codex/CI |
| O5 | opus impl | Issue #2108: hardening sweep (CSR guard, JWT aud, stale msg, log level) | running |

## Queue

- Await docs-truth audit (O2) → triage into ledger, spawn fixes.
- PR #2105: await codex verdict + CI; merge when clean+green+reviewed.
- Decide disposition for PR-008 (CI flakes — likely TRACKED via #2057/#2060 + monitor), PR-004/005/013/014 (file tracking issues).

## Done

(none yet)
