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
joined into a filesystem path. Nothing from the candidate is imported, parsed as
code, or executed — every governed file is compared or schema-checked as text. A
missing slot is the signal that a protected file was deleted or renamed.

**Permissions.** `contents: read`, `persist-credentials: false`, no secrets at
all. `.github/scripts/verify_required_ci.py` re-asserts those properties, the
`merge_group` trigger, and the exact check name so the required context cannot
be silently renamed or downgraded.

**Byte-frozen executable gate code.** Every file that *executes* as part of the
launch/release gate must be byte-identical to the trusted base:

| Anchored path | Frozen from |
|---|---|
| `scripts/check_launch_readiness.py` | always |
| `.github/workflows/launch-readiness.yml` | always |
| `.github/workflows/release.yml` | always |
| `.github/workflows/launch-integrity.yml` | always |
| `.github/scripts/verify_launch_integrity.py` | always |
| `.github/workflows/launch-advisory-trust.yml` | once the trusted base carries it (issue #3802) |
| `.github/scripts/verify_launch_advisory_trust.py` | once the trusted base carries it (issue #3802) |

The two optional rows are treated as absent only while the trusted base also
lacks them; the moment the base carries one, deleting it or changing a byte
fails. A trusted base that is missing a *required* anchor is a broken or
tampered extraction and fails closed rather than skipping enforcement.

This is a deliberate replacement for a semantic contract. An earlier revision of
this verifier tried to *permit* checker edits that "still looked fail-closed":
it rejected a function whose body was reduced to a single success statement and
separately required certain marker strings to appear somewhere in the function.
Both are trivially defeated by prepending `return "PASS"`, `return 0`,
`sys.exit(0)`, or `if True: return []` above the original body — every previous
statement and every marker string is still present in the file, merely
unreachable. No source-level or YAML-level heuristic can prove arbitrary
executable gate code is still equivalent to what was reviewed, so byte identity
is the enforced property and the heuristics are gone.

**Consequences for contributors.**

- An ordinary pull request cannot change any anchored file. If a change is
  needed, it is an explicit administrative / root-orchestrator update: land it on
  protected `main` through an auditable bypass and re-run the integrity workflow
  (and `Launch Readiness Gate`) on `main` immediately afterwards, so the new
  bytes are the enforced anchor for everything queued behind it.
- A pull request whose branch predates such an update will go red on the anchor
  it is stale against; merging the latest protected base fixes it. The merge
  queue re-runs the same check against the synthesized commit, so the queue is
  the authoritative enforcement point.
- The proposed copy of the verifier still gets hosted execution of its own
  fixtures in the isolated `trusted-policy-candidate.yml` lane, which produces
  nothing another job reads — the same posture as `Trusted Cross Build Policy`.

On the single adoption commit the trusted base carries no verifier at all, so
there is no protected contract to preserve and nothing trustworthy to execute:
that run reports success with an explicit `::notice::` instead of pretending to
have enforced anything. Every later revision takes the enforcing path.

### What the verifier enforces

- **Byte anchors:** the table above. Deletion, rename, a whitespace-only edit, a
  comment-only edit, an early `return`/`sys.exit(0)` with the old body retained
  below it, or a YAML rewrite that keeps every historically frozen substring
  (`if: false` on the gate job, `continue-on-error: true` on the release gate)
  are all rejected on bytes alone.
- **Deletion/rename:** every protected gate path is still present and non-empty.
- **Policy downgrade:** frozen state machine and reason sets; GA blocking every
  severity; no tier dropping a severity the trusted base blocked; only
  severities the checker knows; a `default_launch_tier` the policy actually
  defines; the exact label schema, with distinct severity labels and the label
  contract unchanged (a rename silently empties the blocker set); non-empty
  policy/classification versions; the repository identity format-checked and
  pinned to the trusted base; every tracked blocker carrying a note; and no
  checked-in count/as-of key anywhere in the file.
- **Private-advisory downgrade:** enabled, redacted-count-only, unpublished
  states blocking, blocking and closed state sets disjoint and jointly covering
  every known advisory state, per-tier advisory severities covering exactly the
  policy tiers with only known severities, GA still blocking
  critical/high/medium, no tier dropping a severity the trusted base blocked,
  the never-emit set intact, the freshness window never widened, and the
  credential (`live_api.token_env`) and fallback evidence variables
  format-checked, mutually distinct, and pinned to the trusted-base names so a
  pull request cannot point the checker at a source it controls.
- **Exemption schema:** required fields; a positive issue number; owner and
  approver matching the checker's principal grammar; non-empty rationale and
  compensating control; unique non-empty ids; at least one launch tier and no
  tier the candidate policy does not define; ISO-8601 timestamps compared as
  *instants*, so an expiry strictly after approval cannot be faked with a
  timezone offset whose lexical order is the reverse of its chronological order.
  The candidate policy's tier set is passed into this check as inert parsed
  data; no candidate code is imported or executed.
- **Document markers:** exactly one begin/end/historical marker, in order, with
  the marker contract itself unchanged from the trusted base.
- **Secret exposure:** the privileged advisory token may be named only by a
  workflow that is itself an anchor (`launch-readiness.yml`, `release.yml`,
  `launch-advisory-trust.yml`). A workflow a candidate *adds* may not reference
  it at all.
- **Check-run producer identity:** the required check names may be produced by
  exactly one workflow file each, so a candidate cannot add a second workflow
  that reports an identically named, trivially green context.
- **Ownership evasion:** every governed path still has an owner in
  `.github/CODEOWNERS`, and no trusted-base owner was removed. GitHub evaluates
  CODEOWNERS from the base branch, so editing that file inside a pull request
  cannot relax that pull request's own review requirement; this check keeps the
  coverage from being dropped on the way in.

The last three run over the *whole* extracted workflow directory, including
workflows the candidate adds. They are defense in depth against a bypass built
beside the gate; they are explicitly **not** the permission model for changing
an anchored file — that is the byte anchor and nothing else.

The policy and exemption checks are held to the frozen production checker's own
schema (`scripts/check_launch_readiness.py`). The checker's bytes are anchored,
but the data it consumes is candidate-editable and is consumed from `main` the
moment a data-only edit lands, so anything the checker would reject — or any
narrowing of what it will block — has to be refused here, at pull-request time.
A trusted-base policy copy that cannot be read fails closed rather than
silently disabling every base comparison.

What it deliberately does **not** judge: live issue/advisory state, and the
*content* of the tracked-blocker inventory or the exemption list. Those are
governed by CODEOWNER review; the verifier only enforces their schema so a
malformed or unbounded entry cannot slip through. It also no longer inspects
checker semantics, workflow triggers, frozen `run:` lines, or release `needs:`
reachability: those properties are now implied by byte identity, and enforcing
them a second time from a hand-maintained contract table would only produce
false reds whenever an administrative update legitimately changed them.

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
4. Land every change to an anchored file (the byte-frozen table above) the same
   way: an explicit administrative update on protected `main` using an auditable
   bypass, immediately followed by a hosted post-merge run of
   `launch-integrity.yml` and `launch-readiness.yml` on the new `main` tip. The
   new bytes become the anchor for every pull request queued behind it, so a
   broken administrative update is visible on the very next run rather than at
   release time.

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
