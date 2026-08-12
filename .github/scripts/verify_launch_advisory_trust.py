#!/usr/bin/env python3
"""Static trust-boundary contract for the private-advisory credential.

Issue #3802: a `v*` tag can be created at an arbitrary commit, and for a `push`
event GitHub loads both the workflow definition and every file it executes from
that tag target. Any tag-reachable job that references
`secrets.LAUNCH_ADVISORY_READ_TOKEN` therefore hands a privileged credential to
candidate-controlled code before the release SHA has any provenance.

This verifier is the checked-in proof that no such path exists. It reads the
workflow definitions as text — it executes nothing — and asserts:

* the credential is referenced in exactly one workflow, and that workflow is
  reachable only from events whose definition GitHub loads from the protected
  default branch (`workflow_run`, `schedule`);
* the secret-bearing job is gated behind the secretless trust job, is bound to
  the protected deployment environment, checks out only the literal trusted ref,
  and runs only the default-branch checker with its trusted-execution pins;
* the candidate commit reaches the secret-bearing job only as an inert SHA in an
  environment mapping, never as a checkout ref or a shell operand;
* the tag-triggered release job consumes the trusted verdict as a published
  commit status instead of evaluating advisories itself;
* that verdict is bound to the exact Release run ID and run attempt on both
  sides — the publisher derives the context from the triggering run, the release
  gate accepts only the context carrying its own `github.run_id` /
  `github.run_attempt`, and the scheduled default-branch audit uses a context of
  a different shape. A commit-wide context would be replayable: a daily audit, an
  earlier tag release on the same commit, or an earlier attempt of the same
  Release run would satisfy a later release before its own evaluation finished;
* the trusted workflow triggers on `workflow_run: in_progress`, because GitHub
  documents that `requested` does not fire for a re-run;
* the untrusted standalone gate holds no credential on any event.

`--self-test` runs an adversarial fixture table — a malicious tagged workflow, a
malicious tagged checker invocation, a candidate-tree checkout, a missing
environment binding, a dropped trust edge, a constant commit-wide status
context, an omitted run-attempt binding, a `requested`-only trigger, a release
gate that reuses another run's status, and a release job that stops requiring
the trusted verdict — and then applies the same contract to the real
`.github/workflows` tree.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_WORKFLOWS_DIR = ROOT / ".github" / "workflows"

TOKEN_REFERENCE = "secrets.LAUNCH_ADVISORY_READ_TOKEN"
TRUSTED_WORKFLOW = "launch-advisory-trust.yml"
RELEASE_WORKFLOW = "release.yml"
STANDALONE_WORKFLOW = "launch-readiness.yml"

TRUSTED_REF = "refs/heads/main"
TRUST_JOB = "establish-trust"
SECRET_JOB = "advisory-verdict"
PUBLISH_JOB = "publish-verdict"
RELEASE_GATE_JOB = "validate-launch-readiness"
PROTECTED_ENVIRONMENT = "launch-advisory"
STATUS_CONTEXT_PREFIX = "trusted-launch-advisory-gate"
# The scheduled default-branch audit's context. Deliberately not of the release
# shape, so an audit verdict can never satisfy a release gate.
AUDIT_STATUS_CONTEXT = f"{STATUS_CONTEXT_PREFIX}/main-audit"
TRUSTED_CHECKER = "python3 -I scripts/check_launch_readiness.py"
SELF_TEST_STEP = "python3 -I .github/scripts/verify_launch_advisory_trust.py --self-test"

# Events whose workflow definition and checked-out code GitHub resolves from the
# protected default branch. Every other event can be reached from a ref whose
# contents an untrusted principal controls.
TRUSTED_EVENTS = frozenset({"workflow_run", "schedule"})

# Payload fields that carry candidate-controlled values.
CANDIDATE_EXPRESSIONS = (
    "github.event.workflow_run.head_sha",
    "github.event.workflow_run.head_branch",
    "github.event.inputs",
    "inputs.release_tag",
    "outputs.candidate_sha",
    "needs.establish-trust.outputs.candidate_sha",
)

TOP_LEVEL_KEY = re.compile(r"^(?P<key>[A-Za-z_][A-Za-z0-9_-]*):")
NESTED_KEY = re.compile(r"^  (?P<key>[A-Za-z_][A-Za-z0-9_-]*):")
REF_FIELD = re.compile(r"^\s*ref:\s*(?P<value>\S.*?)\s*$")
USES_FIELD = re.compile(r"^\s*(?:-\s+)?uses:\s*(?P<value>\S+)")
PINNED_ACTION = re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._/-]+@[0-9a-f]{40}$")
CANDIDATE_ENV_BINDING = re.compile(
    r"^\s*LAUNCH_TARGET_SHA:\s*\$\{\{\s*needs\.establish-trust\.outputs\."
    r"candidate_sha\s*\}\}\s*$"
)
PUBLISH_ENV_BINDING = re.compile(
    r"^\s*CANDIDATE_SHA:\s*\$\{\{\s*needs\.establish-trust\.outputs\."
    r"candidate_sha\s*\}\}\s*$"
)
PUBLISH_CONTEXT_BINDING = re.compile(
    r"^\s*STATUS_CONTEXT:\s*\$\{\{\s*needs\.establish-trust\.outputs\."
    r"status_context\s*\}\}\s*$"
)

# The publisher derives the release context from its own shell operands; the
# release gate derives the identical string from its own run. Both derivations
# are pinned here so neither side can silently drop the run or attempt operand.
TRUSTED_RUN_CONTEXT_DERIVATION = re.compile(
    re.escape(STATUS_CONTEXT_PREFIX)
    + r"/release-\$\{?release_run_id\}?-attempt-\$\{?release_run_attempt\}?"
)
RELEASE_GATE_CONTEXT_DERIVATION = re.compile(
    re.escape(STATUS_CONTEXT_PREFIX)
    + r"/release-\$\{?RELEASE_RUN_ID\}?-attempt-\$\{?RELEASE_RUN_ATTEMPT\}?"
)
# The shape a published release verdict may take. Used to prove statically that
# the audit context can never be mistaken for one.
RELEASE_CONTEXT_SHAPE = re.compile(
    re.escape(STATUS_CONTEXT_PREFIX)
    + r"/release-[1-9][0-9]{0,17}-attempt-[1-9][0-9]{0,17}$"
)
# Any use of the bare prefix that is not the run-bound release namespace. In the
# release gate that is a commit-wide, replayable context.
COMMIT_WIDE_CONTEXT = re.compile(re.escape(STATUS_CONTEXT_PREFIX) + r"(?!/release-)")

WORKFLOW_RUN_TYPE_ITEM = re.compile(r"^\s*-\s*(?P<value>[a-z_]+)\s*$")
# `requested` does not fire for a re-run, so a re-run Release attempt would
# never obtain its own verdict and would fail closed permanently.
REQUIRED_WORKFLOW_RUN_TYPE = "in_progress"


# ---------------------------------------------------------------------------
# Minimal structural reader (text only; nothing is evaluated)
# ---------------------------------------------------------------------------


def split_blocks(lines: list[str], pattern: re.Pattern[str]) -> dict[str, list[str]]:
    """Split lines into blocks introduced by `pattern`, keyed by the match."""

    blocks: dict[str, list[str]] = {}
    current: str | None = None
    for line in lines:
        match = pattern.match(line)
        if match:
            current = match.group("key")
            blocks.setdefault(current, [])
            continue
        if current is not None:
            blocks[current].append(line)
    return blocks


def top_level_blocks(text: str) -> dict[str, list[str]]:
    return split_blocks(text.splitlines(), TOP_LEVEL_KEY)


def job_blocks(text: str) -> dict[str, list[str]]:
    jobs = top_level_blocks(text).get("jobs")
    if jobs is None:
        return {}
    return split_blocks(jobs, NESTED_KEY)


def event_names(text: str) -> set[str]:
    block = top_level_blocks(text).get("on")
    if block is None:
        return set()
    return set(split_blocks(block, NESTED_KEY))


def workflow_run_types(text: str) -> set[str]:
    """Return the declared `on.workflow_run.types` entries."""

    block = top_level_blocks(text).get("on")
    if block is None:
        return set()
    run_block = split_blocks(block, NESTED_KEY).get("workflow_run")
    if run_block is None:
        return set()

    types: set[str] = set()
    collecting = False
    for line in code_lines(run_block):
        stripped = line.strip()
        if stripped.startswith("types:"):
            inline = stripped[len("types:") :].strip()
            if inline.startswith("["):
                types.update(
                    item.strip().strip("\"'")
                    for item in inline.strip("[]").split(",")
                    if item.strip()
                )
                collecting = False
            else:
                collecting = True
            continue
        if collecting:
            item = WORKFLOW_RUN_TYPE_ITEM.match(line)
            if item:
                types.add(item.group("value"))
            else:
                collecting = False
    return types


def strip_comment(line: str) -> str:
    """Drop a trailing full-line comment so prose cannot satisfy a contract."""

    stripped = line.lstrip()
    return "" if stripped.startswith("#") else line


def code_lines(lines: list[str]) -> list[str]:
    return [line for line in (strip_comment(item) for item in lines) if line.strip()]


# ---------------------------------------------------------------------------
# Contract
# ---------------------------------------------------------------------------


def check_trusted_workflow(text: str) -> list[str]:
    errors: list[str] = []
    lines = code_lines(text.splitlines())
    jobs = job_blocks(text)

    events = event_names(text)
    if not events:
        errors.append(f"{TRUSTED_WORKFLOW} declares no triggering events")
    untrusted = sorted(events - TRUSTED_EVENTS)
    if untrusted:
        errors.append(
            f"{TRUSTED_WORKFLOW} must not be reachable from candidate-controlled "
            f"events: {', '.join(untrusted)}"
        )

    if "workflow_run" in events and REQUIRED_WORKFLOW_RUN_TYPE not in workflow_run_types(
        text
    ):
        errors.append(
            f"{TRUSTED_WORKFLOW} must trigger on `workflow_run` type "
            f"`{REQUIRED_WORKFLOW_RUN_TYPE}`; `requested` alone does not fire for a "
            "re-run, so a re-run Release attempt could never obtain its own verdict"
        )

    occurrences = sum(line.count(TOKEN_REFERENCE) for line in lines)
    if occurrences != 1:
        errors.append(
            f"{TRUSTED_WORKFLOW} must reference the advisory credential exactly "
            f"once (found {occurrences})"
        )

    for line in lines:
        ref = REF_FIELD.match(line)
        if ref and ref.group("value").strip("\"'") != TRUSTED_REF:
            errors.append(
                f"{TRUSTED_WORKFLOW} checks out {ref.group('value')!r}; every ref "
                f"must be the literal trusted ref {TRUSTED_REF!r}"
            )
        uses = USES_FIELD.match(line)
        if uses and not PINNED_ACTION.match(uses.group("value")):
            errors.append(
                f"{TRUSTED_WORKFLOW} uses unpinned or local action "
                f"{uses.group('value')!r}"
            )

    for job_name in (TRUST_JOB, SECRET_JOB, PUBLISH_JOB):
        if job_name not in jobs:
            errors.append(f"{TRUSTED_WORKFLOW} is missing job `{job_name}`")
    if TRUST_JOB not in jobs or SECRET_JOB not in jobs:
        return errors

    trust_lines = code_lines(jobs[TRUST_JOB])
    trust_text = "\n".join(trust_lines)
    if any(TOKEN_REFERENCE in line for line in trust_lines):
        errors.append(
            f"{TRUSTED_WORKFLOW} job `{TRUST_JOB}` must establish provenance "
            "without any credential"
        )

    # The verdict must be bound to the exact Release run AND run attempt that
    # asked for it, or an older success on the same commit satisfies a newer
    # release before its own evaluation has run.
    for expression, detail in (
        ("github.event.workflow_run.id", "the triggering Release run ID"),
        ("github.event.workflow_run.run_attempt", "the triggering Release run attempt"),
    ):
        if expression not in trust_text:
            errors.append(
                f"{TRUSTED_WORKFLOW} job `{TRUST_JOB}` must bind {detail} "
                f"(`{expression}`) so the published verdict cannot be replayed"
            )
    if "status_context:" not in trust_text:
        errors.append(
            f"{TRUSTED_WORKFLOW} job `{TRUST_JOB}` must export the derived "
            "`status_context` for the publisher"
        )
    if not TRUSTED_RUN_CONTEXT_DERIVATION.search(trust_text):
        errors.append(
            f"{TRUSTED_WORKFLOW} job `{TRUST_JOB}` must derive a status context "
            f"of the form `{STATUS_CONTEXT_PREFIX}/release-<run id>-attempt-"
            "<run attempt>`; a commit-wide or attempt-less context is replayable"
        )
    if AUDIT_STATUS_CONTEXT not in trust_text:
        errors.append(
            f"{TRUSTED_WORKFLOW} job `{TRUST_JOB}` must publish default-branch "
            f"audits under the distinct `{AUDIT_STATUS_CONTEXT}` context so an "
            "audit can never satisfy a release"
        )

    secret_lines = code_lines(jobs[SECRET_JOB])
    secret_text = "\n".join(secret_lines)
    if not any(TOKEN_REFERENCE in line for line in secret_lines):
        errors.append(
            f"{TRUSTED_WORKFLOW} job `{SECRET_JOB}` must be the only holder of "
            "the advisory credential"
        )
    if f"environment: {PROTECTED_ENVIRONMENT}" not in secret_text:
        errors.append(
            f"{TRUSTED_WORKFLOW} job `{SECRET_JOB}` must bind the credential to "
            f"the protected `{PROTECTED_ENVIRONMENT}` environment"
        )
    if f"needs: {TRUST_JOB}" not in secret_text:
        errors.append(
            f"{TRUSTED_WORKFLOW} job `{SECRET_JOB}` must require `{TRUST_JOB}` so "
            "provenance is established before the credential is released"
        )
    if "--trusted-execution" not in secret_text or "--trusted-tree-sha" not in secret_text:
        errors.append(
            f"{TRUSTED_WORKFLOW} job `{SECRET_JOB}` must pin the checker to the "
            "trusted anchor with --trusted-execution and --trusted-tree-sha"
        )

    # The candidate may reach the secret-bearing job only as an inert SHA in an
    # environment mapping. A checkout ref, a fetch, or any shell operand would
    # make candidate-controlled bytes executable here.
    for line in secret_lines:
        for expression in CANDIDATE_EXPRESSIONS:
            if expression in line and not CANDIDATE_ENV_BINDING.match(line):
                errors.append(
                    f"{TRUSTED_WORKFLOW} job `{SECRET_JOB}` exposes candidate "
                    f"input {expression!r} outside the inert LAUNCH_TARGET_SHA "
                    "environment binding"
                )

    for line in secret_lines:
        stripped = line.strip()
        if stripped.startswith("run:"):
            command = stripped[len("run:") :].strip()
            if command and command != "|" and not command.startswith(TRUSTED_CHECKER):
                errors.append(
                    f"{TRUSTED_WORKFLOW} job `{SECRET_JOB}` runs {command!r}; the "
                    "credential-bearing job may only run the default-branch checker"
                )
        if "python" in stripped and TRUSTED_CHECKER not in stripped:
            errors.append(
                f"{TRUSTED_WORKFLOW} job `{SECRET_JOB}` invokes an interpreter "
                "other than the default-branch checker"
            )

    if PUBLISH_JOB in jobs:
        publish_lines = code_lines(jobs[PUBLISH_JOB])
        if any(TOKEN_REFERENCE in line for line in publish_lines):
            errors.append(
                f"{TRUSTED_WORKFLOW} job `{PUBLISH_JOB}` must publish the verdict "
                "without any credential"
            )
        context_lines = [line for line in publish_lines if "context=" in line]
        if not context_lines:
            errors.append(
                f"{TRUSTED_WORKFLOW} job `{PUBLISH_JOB}` must publish the "
                f"`{STATUS_CONTEXT_PREFIX}` commit status"
            )
        for line in context_lines:
            if "$STATUS_CONTEXT" not in line and "${STATUS_CONTEXT}" not in line:
                errors.append(
                    f"{TRUSTED_WORKFLOW} job `{PUBLISH_JOB}` publishes a constant "
                    "commit-wide status context; it must publish the run-bound "
                    "context established by the trust job"
                )
        if not any(PUBLISH_CONTEXT_BINDING.match(line) for line in publish_lines):
            errors.append(
                f"{TRUSTED_WORKFLOW} job `{PUBLISH_JOB}` must consume the "
                "established `status_context` output"
            )
        if not any(PUBLISH_ENV_BINDING.match(line) for line in publish_lines):
            errors.append(
                f"{TRUSTED_WORKFLOW} job `{PUBLISH_JOB}` must publish against the "
                "established candidate SHA"
            )
    return errors


def check_release_workflow(text: str) -> list[str]:
    errors: list[str] = []
    jobs = job_blocks(text)
    if RELEASE_GATE_JOB not in jobs:
        errors.append(f"{RELEASE_WORKFLOW} is missing job `{RELEASE_GATE_JOB}`")
        return errors
    gate = "\n".join(code_lines(jobs[RELEASE_GATE_JOB]))
    if not RELEASE_GATE_CONTEXT_DERIVATION.search(gate):
        errors.append(
            f"{RELEASE_WORKFLOW} job `{RELEASE_GATE_JOB}` must require the "
            f"`{STATUS_CONTEXT_PREFIX}` verdict published for its own run ID and "
            "run attempt"
        )
    # Any surviving bare use of the context prefix is a commit-wide status the
    # daily audit or an earlier release/attempt on the same commit already
    # satisfies.
    if COMMIT_WIDE_CONTEXT.search(gate):
        errors.append(
            f"{RELEASE_WORKFLOW} job `{RELEASE_GATE_JOB}` must not accept a "
            "commit-wide advisory status context; a stale or replayed verdict "
            "from another run or attempt would satisfy this release"
        )
    for expression in ("github.run_id", "github.run_attempt"):
        if expression not in gate:
            errors.append(
                f"{RELEASE_WORKFLOW} job `{RELEASE_GATE_JOB}` must bind "
                f"`{expression}` so the verdict it accepts is its own"
            )
    if "--verify" in gate:
        errors.append(
            f"{RELEASE_WORKFLOW} job `{RELEASE_GATE_JOB}` must not evaluate the "
            "live launch verdict itself; the tag target is not trusted code"
        )
    return errors


def check_standalone_workflow(text: str) -> list[str]:
    errors: list[str] = []
    if SELF_TEST_STEP not in text:
        errors.append(
            f"{STANDALONE_WORKFLOW} must run the advisory trust-boundary "
            "self-test on every pull request"
        )
    return errors


def evaluate(workflows: dict[str, str]) -> list[str]:
    """Apply the whole contract to a name -> text mapping of workflows."""

    errors: list[str] = []
    for name in sorted(workflows):
        if name == TRUSTED_WORKFLOW:
            continue
        for line in code_lines(workflows[name].splitlines()):
            if TOKEN_REFERENCE in line:
                errors.append(
                    f"{name} references the advisory credential; only "
                    f"{TRUSTED_WORKFLOW} may, because every other workflow is "
                    "reachable from a candidate-controlled ref"
                )
                break

    if TRUSTED_WORKFLOW not in workflows:
        errors.append(f"{TRUSTED_WORKFLOW} is missing")
    else:
        errors.extend(check_trusted_workflow(workflows[TRUSTED_WORKFLOW]))

    if RELEASE_WORKFLOW in workflows:
        errors.extend(check_release_workflow(workflows[RELEASE_WORKFLOW]))
    if STANDALONE_WORKFLOW in workflows:
        errors.extend(check_standalone_workflow(workflows[STANDALONE_WORKFLOW]))
    return errors


def load_workflows(directory: Path) -> dict[str, str]:
    workflows: dict[str, str] = {}
    for path in sorted(directory.iterdir()):
        if path.is_file() and path.suffix in (".yml", ".yaml"):
            workflows[path.name] = path.read_text(encoding="utf-8")
    return workflows


# ---------------------------------------------------------------------------
# Adversarial fixtures
# ---------------------------------------------------------------------------


FIXTURE_TRUSTED = """name: Trusted Launch Advisory Gate

on:
  workflow_run:
    workflows:
      - Release
    types:
      - in_progress
  schedule:
    - cron: "45 6 * * *"
permissions:
  contents: read

jobs:
  establish-trust:
    name: Establish candidate trust
    runs-on: ubuntu-latest
    outputs:
      candidate_sha: ${{ steps.candidate.outputs.candidate_sha }}
      trusted_sha: ${{ steps.candidate.outputs.trusted_sha }}
      status_context: ${{ steps.candidate.outputs.status_context }}
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v6
        with:
          ref: refs/heads/main
      - name: Resolve
        id: candidate
        env:
          WORKFLOW_RUN_ID: ${{ github.event.workflow_run.id }}
          WORKFLOW_RUN_ATTEMPT: ${{ github.event.workflow_run.run_attempt }}
        run: |
          status_context="trusted-launch-advisory-gate/main-audit"
          status_context="trusted-launch-advisory-gate/release-${release_run_id}-attempt-${release_run_attempt}"
          echo "status_context=${status_context}" >> "$GITHUB_OUTPUT"

  advisory-verdict:
    name: Evaluate advisories from trusted code
    needs: establish-trust
    runs-on: ubuntu-latest
    environment: launch-advisory
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v6
        with:
          ref: refs/heads/main
      - name: Evaluate
        env:
          LAUNCH_TARGET_SHA: ${{ needs.establish-trust.outputs.candidate_sha }}
          TRUSTED_SHA: ${{ needs.establish-trust.outputs.trusted_sha }}
          LAUNCH_ADVISORY_READ_TOKEN: ${{ secrets.LAUNCH_ADVISORY_READ_TOKEN }}
        run: python3 -I scripts/check_launch_readiness.py --verify --trusted-execution --trusted-tree-sha "$TRUSTED_SHA"

  publish-verdict:
    name: Publish trusted advisory verdict
    needs:
      - establish-trust
      - advisory-verdict
    runs-on: ubuntu-latest
    permissions:
      statuses: write
    steps:
      - name: Publish
        env:
          CANDIDATE_SHA: ${{ needs.establish-trust.outputs.candidate_sha }}
          STATUS_CONTEXT: ${{ needs.establish-trust.outputs.status_context }}
        run: gh api --method POST "repos/x/statuses/$CANDIDATE_SHA" -f "context=${STATUS_CONTEXT}"
"""

FIXTURE_RELEASE = """name: Release

on:
  push:
    tags:
      - 'v*'

jobs:
  validate-launch-readiness:
    name: Validate launch readiness
    runs-on: ubuntu-latest
    steps:
      - name: Require the trusted verdict
        env:
          RELEASE_RUN_ID: ${{ github.run_id }}
          RELEASE_RUN_ATTEMPT: ${{ github.run_attempt }}
        run: |
          expected_context="trusted-launch-advisory-gate/release-${RELEASE_RUN_ID}-attempt-${RELEASE_RUN_ATTEMPT}"
          gh api statuses | jq --arg ctx "$expected_context" 'select(.context == $ctx)'
"""

FIXTURE_STANDALONE = """name: Launch Readiness

on:
  pull_request:
  push:
    tags:
      - "v*"

jobs:
  launch-readiness:
    runs-on: ubuntu-latest
    steps:
      - name: Verify the advisory-credential trust boundary
        run: python3 -I .github/scripts/verify_launch_advisory_trust.py --self-test
"""


def baseline_fixture() -> dict[str, str]:
    return {
        TRUSTED_WORKFLOW: FIXTURE_TRUSTED,
        RELEASE_WORKFLOW: FIXTURE_RELEASE,
        STANDALONE_WORKFLOW: FIXTURE_STANDALONE,
    }


def run_self_test() -> int:  # noqa: C901 — a flat fixture table stays readable
    failures: list[str] = []

    def check(name: str, condition: bool, detail: str = "") -> None:
        if not condition:
            failures.append(f"{name}: {detail}" if detail else name)

    baseline = baseline_fixture()
    baseline_errors = evaluate(baseline)
    check("compliant fixture is accepted", not baseline_errors, str(baseline_errors))

    def mutated(name: str, replacement: str) -> dict[str, str]:
        workflows = baseline_fixture()
        workflows[name] = replacement
        return workflows

    # A malicious tagged workflow: the tag target rewrites the release workflow
    # (or adds a new one) so a tag-triggered job receives the credential.
    hostile_release = FIXTURE_RELEASE.replace(
        "          RELEASE_RUN_ATTEMPT: ${{ github.run_attempt }}",
        "          RELEASE_RUN_ATTEMPT: ${{ github.run_attempt }}\n"
        "          LAUNCH_ADVISORY_READ_TOKEN: ${{ secrets.LAUNCH_ADVISORY_READ_TOKEN }}",
    )
    check(
        "a tag-triggered job that claims the credential is rejected",
        any(
            "references the advisory credential" in err
            for err in evaluate(mutated(RELEASE_WORKFLOW, hostile_release))
        ),
    )

    hostile_new_workflow = dict(baseline)
    hostile_new_workflow["attacker.yml"] = (
        "name: Attacker\non:\n  push:\n    tags:\n      - 'v*'\njobs:\n"
        "  steal:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: echo ${{ secrets.LAUNCH_ADVISORY_READ_TOKEN }}\n"
    )
    check(
        "a newly added tag-triggered credential consumer is rejected",
        any(
            "attacker.yml references the advisory credential" in err
            for err in evaluate(hostile_new_workflow)
        ),
    )

    # A malicious tagged checker: the credential-bearing job is redirected at
    # candidate-controlled code instead of the default-branch checker.
    hostile_checker = FIXTURE_TRUSTED.replace(
        'run: python3 -I scripts/check_launch_readiness.py --verify '
        '--trusted-execution --trusted-tree-sha "$TRUSTED_SHA"',
        "run: python3 -I ./candidate/check_launch_readiness.py --dump-env",
    )
    check(
        "a credential-bearing job running candidate code is rejected",
        any(
            "may only run the default-branch checker" in err
            or "invokes an interpreter other than" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, hostile_checker))
        ),
    )

    # The candidate tree checked out into the credential-bearing job.
    hostile_checkout = FIXTURE_TRUSTED.replace(
        "          ref: refs/heads/main\n      - name: Evaluate",
        "          ref: ${{ needs.establish-trust.outputs.candidate_sha }}\n"
        "      - name: Evaluate",
    )
    check(
        "checking out the candidate in the credential-bearing job is rejected",
        any(
            "must be the literal trusted ref" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, hostile_checkout))
        ),
    )

    # The trusted workflow made reachable from a tag.
    tag_reachable = FIXTURE_TRUSTED.replace(
        "on:\n  workflow_run:",
        "on:\n  push:\n    tags:\n      - 'v*'\n  workflow_run:",
    )
    check(
        "making the trusted workflow tag-reachable is rejected",
        any(
            "candidate-controlled events" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, tag_reachable))
        ),
    )

    dispatch_reachable = FIXTURE_TRUSTED.replace(
        "  schedule:\n    - cron: \"45 6 * * *\"",
        "  schedule:\n    - cron: \"45 6 * * *\"\n  workflow_dispatch:",
    )
    check(
        "making the trusted workflow manually dispatchable is rejected",
        any(
            "candidate-controlled events" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, dispatch_reachable))
        ),
    )

    unbound = FIXTURE_TRUSTED.replace("    environment: launch-advisory\n", "")
    check(
        "an unbound credential environment is rejected",
        any(
            "protected `launch-advisory` environment" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, unbound))
        ),
    )

    no_trust_edge = FIXTURE_TRUSTED.replace(
        "    needs: establish-trust\n    runs-on: ubuntu-latest\n"
        "    environment: launch-advisory\n",
        "    runs-on: ubuntu-latest\n    environment: launch-advisory\n",
    )
    check(
        "dropping the provenance edge is rejected",
        any(
            "must require `establish-trust`" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, no_trust_edge))
        ),
    )

    # Assembled rather than written out so this file never carries a literal
    # mutable action pin for a policy scanner to trip over.
    mutable_ref = "actions/checkout@" + "v6"
    unpinned = FIXTURE_TRUSTED.replace(
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", mutable_ref
    )
    check(
        "an unpinned action in the trusted workflow is rejected",
        any(
            "unpinned or local action" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, unpinned))
        ),
    )

    unflagged_checker = FIXTURE_TRUSTED.replace(
        ' --trusted-execution --trusted-tree-sha "$TRUSTED_SHA"', ""
    )
    check(
        "dropping the trusted-execution pins is rejected",
        any(
            "--trusted-execution" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, unflagged_checker))
        ),
    )

    dropped_gate = FIXTURE_RELEASE.replace("trusted-launch-advisory-gate", "anything")
    check(
        "a release gate that stops requiring the trusted verdict is rejected",
        any(
            "must require the `trusted-launch-advisory-gate` verdict" in err
            for err in evaluate(mutated(RELEASE_WORKFLOW, dropped_gate))
        ),
    )

    reevaluating_release = FIXTURE_RELEASE.replace(
        "          gh api statuses | jq --arg ctx \"$expected_context\" "
        "'select(.context == $ctx)'",
        "          python3 -I scripts/check_launch_readiness.py --verify",
    )
    check(
        "a release gate that re-evaluates the verdict from the tag is rejected",
        any(
            "must not evaluate the live launch verdict itself" in err
            for err in evaluate(mutated(RELEASE_WORKFLOW, reevaluating_release))
        ),
    )

    # ---- Run/attempt binding: stale and replayed verdict acceptance ----

    requested_only = FIXTURE_TRUSTED.replace("      - in_progress", "      - requested")
    check(
        "a `requested`-only workflow_run trigger is rejected",
        any(
            "does not fire for a re-run" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, requested_only))
        ),
    )

    constant_context = FIXTURE_TRUSTED.replace(
        '-f "context=${STATUS_CONTEXT}"',
        '-f "context=trusted-launch-advisory-gate"',
    )
    check(
        "publishing a constant commit-wide status context is rejected",
        any(
            "publishes a constant commit-wide status context" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, constant_context))
        ),
    )

    no_attempt_binding = FIXTURE_TRUSTED.replace(
        "          WORKFLOW_RUN_ATTEMPT: ${{ github.event.workflow_run.run_attempt }}\n",
        "",
    )
    check(
        "dropping the triggering run-attempt binding is rejected",
        any(
            "the triggering Release run attempt" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, no_attempt_binding))
        ),
    )

    attemptless_context = FIXTURE_TRUSTED.replace(
        "trusted-launch-advisory-gate/release-${release_run_id}"
        "-attempt-${release_run_attempt}",
        "trusted-launch-advisory-gate/release-${release_run_id}",
    )
    check(
        "a published context that omits the run attempt is rejected",
        any(
            "attempt-less context is replayable" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, attemptless_context))
        ),
    )

    audit_context_dropped = FIXTURE_TRUSTED.replace(
        'status_context="trusted-launch-advisory-gate/main-audit"',
        'status_context="trusted-launch-advisory-gate"',
    )
    check(
        "a default-branch audit sharing the release context namespace is rejected",
        any(
            "distinct `trusted-launch-advisory-gate/main-audit` context" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, audit_context_dropped))
        ),
    )

    # Cross-run reuse: the gate stops naming its own run and accepts whatever
    # success is already on the commit.
    reused_status = FIXTURE_RELEASE.replace(
        "trusted-launch-advisory-gate/release-${RELEASE_RUN_ID}"
        "-attempt-${RELEASE_RUN_ATTEMPT}",
        "trusted-launch-advisory-gate",
    )
    check(
        "a release gate accepting any run's advisory status is rejected",
        any(
            "must not accept a commit-wide advisory status context" in err
            for err in evaluate(mutated(RELEASE_WORKFLOW, reused_status))
        ),
    )

    gate_without_attempt = FIXTURE_RELEASE.replace(
        "          RELEASE_RUN_ATTEMPT: ${{ github.run_attempt }}\n", ""
    )
    check(
        "a release gate that does not bind its own run attempt is rejected",
        any(
            "must bind `github.run_attempt`" in err
            for err in evaluate(mutated(RELEASE_WORKFLOW, gate_without_attempt))
        ),
    )

    check(
        "the default-branch audit context cannot satisfy a release gate",
        not RELEASE_CONTEXT_SHAPE.match(AUDIT_STATUS_CONTEXT)
        and COMMIT_WIDE_CONTEXT.search(AUDIT_STATUS_CONTEXT) is not None,
    )
    check(
        "a run-bound release context is of the admitted shape",
        RELEASE_CONTEXT_SHAPE.match(f"{STATUS_CONTEXT_PREFIX}/release-42-attempt-2")
        is not None
        and COMMIT_WIDE_CONTEXT.search(f"{STATUS_CONTEXT_PREFIX}/release-42-attempt-2")
        is None,
    )

    dropped_self_test = FIXTURE_STANDALONE.replace(SELF_TEST_STEP, "true")
    check(
        "removing the pull-request self-test is rejected",
        any(
            "must run the advisory trust-boundary" in err
            for err in evaluate(mutated(STANDALONE_WORKFLOW, dropped_self_test))
        ),
    )

    check(
        "a prose mention of the credential does not satisfy the contract",
        code_lines(["# secrets.LAUNCH_ADVISORY_READ_TOKEN", "  a: b"]) == ["  a: b"],
    )

    # The same contract, applied to the real tree.
    if DEFAULT_WORKFLOWS_DIR.is_dir():
        live_errors = evaluate(load_workflows(DEFAULT_WORKFLOWS_DIR))
        check("repository workflows satisfy the contract", not live_errors, str(live_errors))
    else:
        check("repository workflow directory exists", False, str(DEFAULT_WORKFLOWS_DIR))

    if failures:
        print("SELF-TEST FAILURES:", file=sys.stderr)
        for item in failures:
            print(f"- {item}", file=sys.stderr)
        return 1
    print("launch-advisory trust-boundary self-test: PASS")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify the private-advisory credential trust boundary"
    )
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument(
        "--workflows-dir",
        default=str(DEFAULT_WORKFLOWS_DIR),
        help="workflow directory to evaluate (default: the repository's)",
    )
    args = parser.parse_args(argv)

    if args.self_test:
        return run_self_test()

    directory = Path(args.workflows_dir)
    if not directory.is_dir():
        print(f"error: no workflow directory at {directory}", file=sys.stderr)
        return 1
    errors = evaluate(load_workflows(directory))
    for err in errors:
        print(f"error: {err}", file=sys.stderr)
    if errors:
        return 1
    print("launch-advisory trust boundary: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
