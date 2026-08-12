# Launch readiness gate

Fail-closed release governance for Ferrum Edge. The live launch verdict is
computed by `scripts/check_launch_readiness.py` from GitHub issue and advisory
state plus the checked-in policy; it is **not** the historical static-audit prose
in `PRODUCTION_READINESS.md`.

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

1. **Live API (preferred), from trusted code only.** Provision a read-only
   credential that can list this repository's security advisories and store it
   as an **environment** secret named `LAUNCH_ADVISORY_READ_TOKEN` inside the
   protected `launch-advisory` environment. It is referenced by exactly one
   workflow, `.github/workflows/launch-advisory-trust.yml`, and only after that
   workflow's secretless job has established the candidate commit's provenance.
   Any live failure — denial, rate limit, transport, pagination, or schema — is
   `UNKNOWN`; it never falls back to a weaker source.

   A tag event is **not** a trusted execution. See "Trusted execution boundary"
   below: this used to be modelled the other way round, and that was the defect
   in issue #3802.
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

## Trusted execution boundary

A `v*` tag can be created at **any** commit. For a `push` event GitHub loads the
workflow definition *and* every file the workflow executes from that tag target,
so a tag-triggered job is candidate-controlled code. A tag name is therefore
never evidence that its target came through protected `main`, and a job that
both runs tag code and holds the advisory credential hands the credential to an
arbitrary commit before any provenance exists (issue #3802).

The boundary is drawn by *which code executes*, not by which event fired:

| Surface | Code source | Credential |
|---------|-------------|------------|
| `launch-readiness.yml` (PR, `merge_group`, `main` push, `v*` tag, schedule, dispatch) | the ref under test — untrusted | **never**, on any event |
| `release.yml` (`v*` tag push) | the tag target — untrusted | **never** |
| `launch-advisory-trust.yml` (`workflow_run: in_progress`, `schedule`) | protected default branch, always | yes, after provenance |

`workflow_run` and `schedule` resolve this workflow from the default branch,
which is what makes
`launch-advisory-trust.yml` an immutable trust anchor a tag cannot rewrite.
`workflow_dispatch` is deliberately absent: its API accepts a caller-selected
branch or tag ref, so a manual dispatch is not intrinsically trusted code.

### How a release obtains a private-advisory verdict

1. A `v*` tag push starts `Release`. That run holds no credential.
2. The `Release` run's `workflow_run: in_progress` event triggers
   `launch-advisory-trust.yml` from protected `main`, carrying the Release run
   ID and run attempt. `in_progress` rather than `requested`: GitHub documents
   that `requested` does not fire when a run is re-run, so a re-run Release
   attempt would never obtain its own verdict and would fail closed forever.
3. `establish-trust` holds no secret. It checks out the literal `refs/heads/main`,
   pins the resolved trusted anchor commit, then treats the candidate purely as
   data: normalized tag format, exactly one unambiguous remote tag ref, tag
   resolution to exactly one commit, agreement with the triggering event's head
   (a tag moved after the event is refused as stale), reachability from
   protected `main`, and successful **push** `ci.yml` + `coverage.yml` runs for
   that exact SHA. Anything missing, ambiguous, or stale fails closed.
4. `advisory-verdict` re-checks out `refs/heads/main`, detaches onto the same
   pinned anchor commit, and runs the default-branch checker with
   `--trusted-execution --trusted-tree-sha <anchor>`. The checker re-asserts the
   pin itself and **refuses the credential outright** in any invocation that did
   not declare a trusted execution, so the tag's own copy of the checker cannot
   use a credential even if one were somehow present. The candidate reaches this
   job only as `LAUNCH_TARGET_SHA`; no candidate byte is fetched, imported, or
   run. The credential comes from the protected `launch-advisory` environment.
5. `publish-verdict` holds no secret and posts a fixed-text commit status on the
   candidate SHA under the context
   `trusted-launch-advisory-gate/release-<run id>-attempt-<attempt>`. Neither
   the credential nor any advisory identifier appears in the status, the logs,
   or any artifact.
6. `release.yml`'s `validate-launch-readiness` job derives the identical context
   from its own `github.run_id` and `github.run_attempt`, waits for **only that
   context** on the commit its tag resolves to, and fails closed if it is
   absent, `failure`, or `error`. The release still cannot proceed without a
   computed `PASS`; the decision simply moved to code a tag cannot rewrite.

### Why the verdict is bound to a run attempt

Commit statuses are commit-wide. A single constant
`trusted-launch-advisory-gate` context would be replayable: the daily audit of
protected `main`, an earlier tag release on the same commit, or an earlier
attempt of the same Release run would already have posted a success, and a
release started afterwards would consume it before its own trusted evaluation
had run. A blocker opened in between would be invisible.

So every release verdict carries a context unique to one Release run **and** one
run attempt:

| Lane | Context |
|------|---------|
| Release (`workflow_run: in_progress`) | `trusted-launch-advisory-gate/release-<run id>-attempt-<attempt>` |
| Scheduled default-branch audit | `trusted-launch-advisory-gate/main-audit` |

Both operands are validated as strict positive decimals (`^[1-9][0-9]{0,17}$`)
on both sides, and the whole derived context is re-checked against the admitted
shape before it is published, so no payload or input value can lengthen or
reshape it. The audit context is not of the release shape, so an audit verdict
can never satisfy a release gate.

Every one of those preconditions fails closed. If the triggering payload does
not carry a usable tag name, run ID, or run attempt, if the tag is ambiguous, if
it moved after the event, or if it is not reachable from protected `main`, no
credential is released and no verdict is published, so the release times out red
rather than proceeding.

To recover a stuck evaluation, rerun the trusted workflow itself. To reevaluate
after a Release rerun, rerun the Release workflow; its new run attempt emits a
fresh `workflow_run: in_progress` event and receives a distinct verdict context.
There is no manual-dispatch lane because its caller-selected ref would weaken
the trusted-code proof.

Because the policy, the exemptions, and `PRODUCTION_READINESS.md` are all read
from the trusted anchor, the reviewed snapshot compared against the live verdict
is protected `main`'s — never the candidate's copy of it.

`.github/scripts/verify_launch_advisory_trust.py --self-test` is the checked-in
proof. It runs an adversarial fixture table — a malicious tagged workflow that
claims the credential, a newly added tag-triggered consumer, a credential-bearing
job redirected at a candidate checker, a candidate-tree checkout, a tag-reachable
trust workflow, a dropped environment binding, a dropped provenance edge, an
unpinned action, a constant commit-wide status context, an omitted run-attempt
binding, a `requested`-only trigger, a default-branch audit sharing the release
context namespace, a release gate that accepts another run's status, and a
release gate that stops requiring the trusted verdict — and then applies the
same contract to the real `.github/workflows` tree. It runs on every pull
request from `launch-readiness.yml`.

### Required repository settings (root/admin only, not code)

The code above removes the credential from every candidate-reachable job, but
repository *settings* decide whether an attacker-authored workflow could still
name the secret. These are administrator actions and are deliberately not
automated here.

**Verified live state at the time of writing:** no repository secret named
`LAUNCH_ADVISORY_READ_TOKEN` is provisioned, and no `launch-advisory`
environment exists. There is therefore nothing to delete and **no rotation is
currently required** — the checker falls back to the redacted repository
variables, and the trusted workflow's advisory read is inert until a credential
is provisioned. The code boundary is still worth keeping: it is what makes a
future provisioning safe rather than exploitable.

1. **Create and protect the environment first.** Create a `launch-advisory`
   environment and restrict its deployment branch/tag policy to the default
   branch only, so a tag-triggered workflow naming the environment is refused
   before any step runs. Add required reviewers if manual release approval is
   wanted. Do this *before* step 2: referencing a not-yet-existing environment
   auto-creates an **unprotected** one, and provisioning the secret into an
   unprotected environment would reopen the hole.
2. **Only then provision the credential as an environment secret.** Add a newly
   issued, narrowly scoped advisory-read credential as
   `LAUNCH_ADVISORY_READ_TOKEN` in that protected environment — never in
   repository-secret scope, where any workflow, including one authored by a
   `v*` tag, can name it. Prefer a short-lived GitHub App installation token or
   a fine-grained credential scoped to repository advisory read on this
   repository only.
3. **If audit history later shows a credential was independently provisioned or
   used**, treat that one as disclosed — the pre-#3802 design cannot prove it
   was never handed to an arbitrary tag target — and revoke and reissue it under
   step 2. Absent such evidence, the verified no-secret state means there is
   nothing to rotate.
4. **Protect release tags.** Create an active ruleset targeting `refs/tags/v*`
   that restricts creation to a narrow release principal, blocks update and
   deletion, and audits any bypass. Consider requiring signed annotated tags.
   Tag protection is defense in depth: trusted-code execution is still required
   because a privileged release actor can be compromised.
5. **Keep `main` protected.** The whole boundary rests on `refs/heads/main`
   being a protected default branch whose required checks cannot be bypassed.

## Hosted enforcement

- `.github/workflows/launch-readiness.yml` — pull requests, `merge_group`,
  `main` pushes, `v*` tags, a daily schedule, and `workflow_dispatch`. It runs
  the deterministic self-tests and the trust-boundary self-test, then verifies
  the live verdict for the exact commit under test (PR head, merge-group head,
  or pushed SHA) and asserts that the checkout is that commit. It holds no
  advisory credential on any event and reads only the redacted variables.
- `.github/workflows/launch-advisory-trust.yml` — the sole credential holder,
  reachable only from `workflow_run` (`in_progress`) and `schedule`. Its daily
  schedule is the live private-advisory re-audit
  of protected `main`, published under the separate `.../main-audit` context.
- `.github/workflows/release.yml` — the `validate-launch-readiness` job gates
  every tag release on the trusted
  `trusted-launch-advisory-gate/release-<run id>-attempt-<attempt>` verdict for
  the commit its tag resolves to, accepting no other context, and holds no
  credential.
- All keep `persist-credentials: false` and least permissions.
- `.github/CODEOWNERS` covers the policy, the exemptions, the checker, the
  workflows, the trust-boundary verifier, and `PRODUCTION_READINESS.md`.

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
python3 .github/scripts/verify_launch_advisory_trust.py --self-test
```

`--verify` requires a computed `PASS`; `--require-pass` is accepted for release
wiring and is implied. `--verify-checkout` additionally asserts that the working
tree HEAD is the supplied target commit. With no target supplied, the checked-out
HEAD is the target.

`--trusted-execution --trusted-tree-sha <sha>` is the credential contract. It
declares that the invocation is executing protected default-branch code and
requires the evaluation target to be supplied explicitly, so the commit under
evaluation is data and the executing tree is the pinned anchor. Without it an
advisory credential in the environment is refused before any advisory request is
made, and the refusal never echoes the credential.
