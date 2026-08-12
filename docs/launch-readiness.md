# Launch readiness gate

Fail-closed release governance for Ferrum Edge. The live launch verdict is
computed by `scripts/check_launch_readiness.py` from GitHub issue and advisory
state plus the checked-in policy; it is **not** the historical static-audit prose
in `PRODUCTION_READINESS.md`.

Two checks with different jobs (issue #3803):

| Check | Question | Required on PRs? | Red when blockers are open? |
|---|---|---|---|
| `Launch Readiness Integrity` | Did this revision preserve the gate contract? | **Yes** | No |
| `Launch Readiness Gate` | Is the product launchable right now? | No — release/tag blocking | Yes, truthfully |

Keeping them separate is what makes enforcement possible: a truthful go/no-go
verdict is `FAIL` while any blocker is open, so requiring *it* on every pull
request would deadlock the very pull requests that fix blockers. The integrity
check never reads live issue or advisory state, so it stays green for a normal
blocker-fix change and red only when the governance contract itself is weakened.

## Authoritative inputs

| Input | Role |
|-------|------|
| [`docs/launch-blocker-policy.json`](launch-blocker-policy.json) | Machine-readable blocker contract: labels, tiers, state machine, tracked inventory, private-advisory redaction rules and freshness ceiling |
| [`docs/launch-exemptions.json`](launch-exemptions.json) | Structured, expiring exemptions (owner, approver, rationale, compensating control, expiry) |
| Live GitHub issues API (paginated) | Open/closed state, `state_reason`, labels, linked in-flight PRs |
| Live repository security-advisories API (paginated) | Private/draft blockers as a **redacted count only**, when a dedicated advisory token is available |
| Repository Actions variables `LAUNCH_PRIVATE_BLOCKER_COUNT` / `LAUNCH_PRIVATE_ADVISORY_AS_OF` | Externally maintained redacted count and audit timestamp used when no advisory token is available |

Issue bodies, PR bodies, and advisory text are untrusted data: never executed,
never echoed. Only public issue numbers and severity/state categories are
printed. Advisory identifiers, summaries, descriptions, links, and any other
confidential field are never read into the record, and the summary printer
refuses to emit output containing them.

The checked-in tree can never assert that private advisories are clear. The
policy file defines only the freshness ceiling; a count or an as-of value inside
it is rejected by schema validation precisely because a pull request could edit
it.

## Classification

1. **Label discovery:** the whole `launch-blocker` label set is walked with
   pagination. Pull-request nodes are excluded. Each remaining issue must carry
   exactly one configured `severity:{critical,high,medium}` label; zero, several,
   or malformed severity is `UNKNOWN`, never a silent omission.
2. **Tracked inventory:** `tracked_blockers` in the policy is an explicit,
   CODEOWNERS-reviewed list evaluated even before labels are applied. The tracked
   severity is the contract: a live severity label that disagrees with it is a
   schema mismatch (`UNKNOWN`), never a downgrade or a silent replacement. A
   matching label is accepted; an absent label uses the tracked severity.
3. **States:**
   - `open` — blocking
   - `in_flight` — open issue with open implementation PR(s); still blocking
   - `merged_awaiting_issue_close` — linked PR merged, issue still open; still blocking
   - `closed_completed` — `state_reason=completed`; cleared
   - `closed_other` — `duplicate` / `not_planned` / missing reason; **not** a fix
   - `exempted` — valid, unexpired structured exemption for the selected tier
   An unrecognized close reason is `UNKNOWN`. The `launch-exempted` label without
   an active structured exemption is `UNKNOWN`; the bare label never clears a
   blocker, and an expired exemption returns the issue to the blocker set.
4. **Private advisories:** unpublished (`draft`/`triage`) advisories whose
   severity blocks the selected tier contribute only a redacted count. A
   non-object entry, a missing/unknown `state`, an unknown `severity`, or an
   incomplete pagination walk is `UNKNOWN` — malformed rows are never dropped.

## Verdicts

| Verdict | Meaning | Exit |
|---------|---------|------|
| `PASS` | No blocking public issues and zero redacted private blockers for the tier | 0 (only when the checked-in snapshot agrees) |
| `FAIL` | At least one blocking public issue or redacted private blocker | non-zero |
| `UNKNOWN` | Missing token, API/rate-limit/pagination/schema/staleness failure | non-zero |

Only a computed `PASS` can make the hosted job green. A checked-in `FAIL`
snapshot that agrees with a computed `FAIL` is still a non-zero exit: while real
launch blockers are open this check is expected to be red, and that redness is
never traded for a "parity" success. A claimed `PASS` that disagrees with the
computed verdict also fails.

The snapshot inside the `launch-readiness` markers in `PRODUCTION_READINESS.md`
is a reviewed record, not an input: it may only agree with the live evaluation.
Refresh it from the workflow's printed record, which carries the exact target SHA
and as-of UTC, whenever the blocker set changes.

## Private advisory access — setup and maintenance

Repository security advisories are behind a **separate GitHub permission**. The
Actions `GITHUB_TOKEN` cannot list them, and the workflow `security-events: read`
permission does **not** grant that access — it covers code-scanning alerts. A run
that relied on it would receive `403`. Both workflows therefore omit it.

Two supported sources, in order:

1. **Live API (preferred).** Provision a read-only credential that can list this
   repository's security advisories and store it as the repository secret
   `LAUNCH_ADVISORY_READ_TOKEN`. It is exposed **only** to trusted executions
   (`push` to `main`, tags, `schedule`, `workflow_dispatch`, and the release
   workflow). Pull-request and merge-group runs are given an empty value by
   construction, so untrusted code never sees a privileged advisory token. Any
   live failure — denial, rate limit, transport, pagination, or schema — is
   `UNKNOWN`; it never falls back to a weaker source.
2. **Externally maintained redacted variables.** When no advisory token is
   configured, the checker reads the repository *variables*
   `LAUNCH_PRIVATE_BLOCKER_COUNT` (a non-negative decimal count) and
   `LAUNCH_PRIVATE_ADVISORY_AS_OF` (an ISO-8601 UTC timestamp such as
   `2026-08-11T12:00:00Z`). Repository variables are set by a maintainer in
   repository settings; a pull request can read them but cannot change them,
   which is the only reason a zero there may substantiate a clean private state.
   Missing, malformed, future-dated, or older than
   `private_advisories.trusted_fallback.max_age_seconds` (7 days) ⇒ `UNKNOWN`.
   A maintainer with advisory access re-audits the private queue within that
   window and updates both variables together. Record **only** the count and the
   timestamp: never a GHSA identifier, summary, link, or any other detail.

No credential is stored in this repository, and none is printed.

## Hosted enforcement

- `.github/workflows/launch-readiness.yml` — pull requests, `merge_group`,
  `main` pushes, `v*` tags, a daily schedule, and `workflow_dispatch`. It runs
  the deterministic self-tests, then verifies the live verdict for the exact
  commit under test (PR head, merge-group head, or pushed SHA) and asserts that
  the checkout is that commit. This is the go/no-go signal and is expected to be
  red while blockers are open; it is not a required pull-request context.
- `.github/workflows/launch-integrity.yml` — the required
  `Launch Readiness Integrity` context on every pull request and merge group.
  See [Trusted integrity check](#trusted-integrity-check) below.
- `.github/workflows/release.yml` — the `validate-launch-readiness` job gates
  every tag release on a computed `PASS` for the tagged commit resolved from the
  checked-out tag ref. Every other release job is downstream of it, which the
  integrity verifier re-checks as a `needs` reachability property.
- All keep `persist-credentials: false` and least permissions.
- `.github/CODEOWNERS` covers the policy, the exemptions, the checker, both
  workflows, the integrity verifier, `PRODUCTION_READINESS.md`, and itself.

## Trusted integrity check

`Launch Readiness Integrity` exists because the gate previously judged itself:
the workflow checked out the candidate head and ran that checkout's evaluator
and that checkout's self-tests, so one change could weaken the checker, its
policy, and its tests together.

**Trust anchor.** The workflow triggers on `pull_request_target` (loaded and
checked out from the base branch) and on `merge_group` (the synthesized queue
commit, whose entry already cleared this same check on its pull request). It
resolves and pins a trusted commit — the live `main` tip for a pull request,
authenticated as a descendant of the event base; the queue `base_sha` for a
merge group — and reads `.github/scripts/verify_launch_integrity.py` from that
commit. That file is the only code the job executes.

**Candidate as inert data.** The candidate revision is never checked out into
the execution path. Each governed file is extracted with `git show` into a fixed
slot name under `$RUNNER_TEMP`, after its tree entry is confirmed to be a
regular non-symlink blob, so no candidate-controlled path component is ever
joined into a filesystem path. The candidate checker is read with `ast.parse`,
which never runs module code, and nothing from the candidate is imported. A
missing slot is the signal that a protected file was deleted or renamed.

**Permissions.** `contents: read`, `persist-credentials: false`, no secrets at
all. `.github/scripts/verify_required_ci.py` re-asserts those properties, the
`merge_group` trigger, and the exact check name so the required context cannot
be silently renamed or downgraded.

**Self-protection.** `.github/workflows/launch-integrity.yml` and
`.github/scripts/verify_launch_integrity.py` must be byte-identical to the
trusted base. Changing the judge is therefore an administrative action, not an
ordinary pull request — the same posture as `Trusted Cross Build Policy`. The
proposed copy still gets hosted execution of its own fixtures in the isolated
`trusted-policy-candidate.yml` lane, which produces nothing another job reads.

On the single adoption commit the trusted base carries no verifier at all, so
there is no protected contract to preserve and nothing trustworthy to execute:
that run reports success with an explicit `::notice::` instead of pretending to
have enforced anything. Every later revision takes the enforcing path, and once
the base carries the anchor neither deletion nor modification is accepted.

### What the verifier enforces

- **Deletion/rename:** every protected gate path is still present and non-empty.
- **Checker semantics:** frozen constants (state machine, closed-reason sets,
  never-emit fields, banned output tokens, forbidden policy keys, severity and
  verdict vocabularies, API origin), ceilings that may tighten but never loosen
  (`MAX_FALLBACK_AGE_SECONDS`, `MAX_FALLBACK_COUNT`, `MAX_PAGES`), the required
  function set, and the fail-closed text each evaluator function must still
  carry (for example `evaluation.verdict != "PASS"`).
- **Unconditional success:** a required function reduced to `pass`,
  `return 0/True/None/"PASS"`, or `sys.exit(0)` is rejected, as is any
  module-level statement that could short-circuit evaluation before it runs.
- **Dependency surface:** the checker's imports must stay within the recorded
  allowlist, so an evaluator cannot grow a shell-out or exfiltration path.
- **Candidate-test rewriting:** the self-test corpus may not fall below its
  assertion floor and must keep every named adversarial fixture (state-machine
  downgrade, merged-PR clearing, duplicate-as-completed, fallback age ceiling,
  redaction, pagination truncation, and the rest).
- **Policy downgrade:** frozen state machine and reason sets; GA blocking every
  severity; no tier dropping a severity the trusted base blocked; the label
  contract unchanged (a rename silently empties the blocker set); private
  advisories enabled, redacted-count-only, unpublished states blocking, the
  never-emit set intact, the freshness window never widened, and no
  checked-in count/as-of key anywhere in the file.
- **Exemption schema:** required fields, ISO timestamps, unique ids, at least
  one launch tier, and an expiry strictly after approval.
- **Document markers:** exactly one begin/end/historical marker, in order, with
  the marker contract itself unchanged from the trusted base.
- **Workflow bypass:** the gate workflow keeps its triggers, unfiltered
  `pull_request` / `merge_group` events, job id and check name, least
  permissions, and the byte-frozen ref/target-SHA/self-test/verify lines; the
  release workflow keeps `validate-launch-readiness` and every other job stays
  downstream of it.
- **Secret exposure:** the privileged advisory token may appear only in
  `launch-readiness.yml` (inside the frozen expression that hands
  pull-request and merge-group runs an empty value) and in `release.yml`.
- **Check-run producer identity:** the required check names may be produced by
  exactly one workflow file each, so a candidate cannot add a second workflow
  that reports an identically named, trivially green context.
- **Ownership evasion:** every governed path still has an owner in
  `.github/CODEOWNERS`, and no trusted-base owner was removed. GitHub evaluates
  CODEOWNERS from the base branch, so editing that file inside a pull request
  cannot relax that pull request's own review requirement; this check keeps the
  coverage from being dropped on the way in.

What it deliberately does **not** judge: live issue/advisory state, and the
*content* of the tracked-blocker inventory or the exemption list. Those are
governed by CODEOWNER review; the verifier only enforces their schema so a
malformed or unbounded entry cannot slip through.

### Required repository settings (root-only)

These cannot be set from a pull request and must be applied by a repository
administrator:

1. Add the required status check `Launch Readiness Integrity` (source app
   **GitHub Actions**, app id `15368`) to the `main` ruleset and to the merge
   queue's required checks. Do **not** add `Launch Readiness Gate`.
2. Set `pull_request.require_code_owner_review = true` for `main` (or add a
   narrower path-scoped ruleset) so the CODEOWNERS entries for
   `PRODUCTION_READINESS.md`, `docs/launch-blocker-policy.json`,
   `docs/launch-exemptions.json`, `docs/launch-readiness.md`,
   `scripts/check_launch_readiness.py`,
   `.github/workflows/launch-readiness.yml`,
   `.github/workflows/launch-integrity.yml`,
   `.github/scripts/verify_launch_integrity.py`,
   `.github/workflows/release.yml`, and `.github/CODEOWNERS` are enforced rather
   than advisory.
3. Keep the organization-admin bypass auditable: an emergency merge that skips
   the integrity context should be followed by a post-merge run on `main`.

Until step 1 and step 2 are applied the check is advisory. Drift in either is
detectable by re-querying the ruleset; the repository-side half of the control
(workflow, verifier, contracts, ownership map) is enforced in-tree.

## Determinism

Every freshness decision is made against an explicitly injected clock: production
passes the real UTC clock, and the fixture suite passes fixed instants. There is
no test-only bypass of production freshness — the tests simply supply their own
consistent `now`, so a fixture verdict can never be collapsed by the wall clock.

## Local / CI invocation

Hosted CI is the execution gate; the deterministic self-test is offline.

```bash
python3 scripts/check_launch_readiness.py --self-test
python3 scripts/check_launch_readiness.py --verify --launch-tier ga --target-sha "$GITHUB_SHA"
python3 .github/scripts/verify_launch_integrity.py --self-test
```

`--verify` requires a computed `PASS`; `--require-pass` is accepted for release
wiring and is implied. `--verify-checkout` additionally asserts that the working
tree HEAD is the supplied target commit. With no target supplied, the checked-out
HEAD is the target.
