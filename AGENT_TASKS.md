# Agent Task Board — Production Readiness Epic

Cap: ≤6 active subagents (≈3 sol + 3 Opus). CI is the gate; no local builds/tests.

## Active

| Slot | Agent | Task | State |
|------|-------|------|-------|
| S1 | sol (medium) | Implement issue #2104 (live XC gate firewall hardening) | dispatched |
| O1 | opus discovery | Deferral-marker triage audit (src/, custom_plugins/, tests/) | dispatched |
| O2 | opus discovery | Docs-vs-code truth audit (README/FEATURES/docs/) | dispatched |
| O3 | opus discovery | Security & production-posture audit | dispatched |
| O4 | opus discovery | Deployment/CI/release/test-gap audit | dispatched |

## Queue

- Triage discovery outputs into findings ledger; spawn fix agents per severity.

## Done

(none yet)
