# Launch readiness gate

Fail-closed release-governance for Ferrum Edge. The live launch verdict is
computed by `scripts/check_launch_readiness.py` from GitHub issue/advisory state
and the checked-in policy; it is **not** the historical static-audit prose in
`PRODUCTION_READINESS.md`.

## Authoritative inputs

| Input | Role |
|-------|------|
| [`docs/launch-blocker-policy.json`](launch-blocker-policy.json) | Machine-readable blocker contract: labels, tiers, state machine, tracked inventory, private-advisory redaction rules |
| [`docs/launch-exemptions.json`](launch-exemptions.json) | Structured, expiring exemptions (owner, approver, rationale, compensating control, expiry) |
| Live GitHub issues API (paginated) | Open/closed state, `state_reason`, labels, linked in-flight PRs |
| Live repo security-advisories API (paginated) | Private/draft blockers as a **redacted count only** (falls back to the opaque `private_advisories.opaque_input` count when the Actions token cannot list advisories; stale opaque input is UNKNOWN) |

Issue bodies, PR bodies, and advisory text are treated as untrusted data: never
executed, never echoed into logs beyond opaque identifiers already allowed by
policy (public issue numbers only).

## Classification

1. **Label discovery:** issues carrying `launch-blocker` plus a
   `severity:{critical,high,medium}` label enter the candidate set.
2. **Tracked inventory:** `tracked_blockers` in the policy is an explicit,
   CODEOWNERS-reviewed list evaluated even before labels are applied.
3. **States:**
   - `open` — blocking
   - `in_flight` — open issue with open implementation PR(s); still blocking
   - `merged_awaiting_issue_close` — linked PR merged, issue still open; still blocking
   - `closed_completed` — `state_reason=completed`; cleared
   - `closed_other` — `duplicate` / `not_planned` / missing reason; **not** a fix
   - `exempted` — valid, unexpired structured exemption for the selected tier
4. **Private advisories:** unpublished/`draft`/`triage` advisories whose severity
   blocks the selected tier contribute only a redacted count. Confidential
   fields are never printed; advisories are never published by this tooling.

## Verdicts

| Verdict | Meaning |
|---------|---------|
| `PASS` | No blocking public issues and zero redacted private blockers for the tier |
| `FAIL` | At least one blocking public issue or redacted private blocker |
| `UNKNOWN` | Missing token, API/rate-limit/pagination/schema/staleness failure |

`UNKNOWN` fails the hosted check. A manually claimed `PASS` in
`PRODUCTION_READINESS.md` that disagrees with the computed verdict fails the
check.

## Hosted enforcement

- `.github/workflows/launch-readiness.yml` — PR, `main` push, schedule, and
  `workflow_dispatch`; always runs synthetic `--self-test` then live verify.
- `.github/workflows/release.yml` — tag releases evaluate the **exact tag SHA**
  with `--require-pass` (release cannot proceed on `FAIL`/`UNKNOWN`).

## Local / CI invocation

Hosted CI is the only execution gate. The checker supports:

```bash
python3 scripts/check_launch_readiness.py --self-test
python3 scripts/check_launch_readiness.py --verify --launch-tier ga --target-sha "$GITHUB_SHA"
python3 scripts/check_launch_readiness.py --verify --require-pass --launch-tier ga --target-sha "$GITHUB_SHA"
```
