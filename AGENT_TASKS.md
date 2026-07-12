# Agent Task Board — Production Readiness Epic

Cap: ≤6 active subagents (≈3 sol + 3 Opus). CI is the gate; no local builds/tests.

## Active

| Slot | Agent | Task | State |
|------|-------|------|-------|
| S2 | sol (high) | PR #2113 round 3: CRL reload-race pooling guards + unknown-revocation doc narrowing (round-1 SharedCrlList fix + orchestrator compile fix f2d921d landed) | running |
| O5 | opus impl | Issue #2108 → PR #2114; codex P2 rebutted-with-fix by orchestrator (strict aud default kept, docs corrected, pinning test a1bc9fbb); round 2 triggered | awaiting codex/CI |

## Queue

- Merge #2113 and #2114 when codex clean + CI green.
- Final pass: re-verify launch gates, main CI health post-merges, close ledger.

## Done

- Discovery audits complete (4/4): deferrals, docs-truth, security, ops. Issues #2106–#2108, #2110–#2111 filed.
- PR #2105 merged (issue #2104 — live XC gate firewall proof).
- PR #2109 merged (issue #2107 — release tag↔version guard + CHANGELOG policy).
- PR #2112 merged (issue #2111 — REFACTORING_PLAN retired, WEBSOCKET.md tunnel mode, admin_api.md LB list).
