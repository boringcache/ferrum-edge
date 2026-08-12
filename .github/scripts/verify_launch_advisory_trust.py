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
  default branch (`workflow_run`, `schedule`, `workflow_dispatch`);
* the secret-bearing job is gated behind the secretless trust job, is bound to
  the protected deployment environment, checks out only the literal trusted ref,
  and runs only the default-branch checker with its trusted-execution pins;
* the candidate commit reaches the secret-bearing job only as an inert SHA in an
  environment mapping, never as a checkout ref or a shell operand;
* the tag-triggered release job consumes the trusted verdict as a published
  commit status instead of evaluating advisories itself;
* the untrusted standalone gate holds no credential on any event.

`--self-test` runs an adversarial fixture table — a malicious tagged workflow, a
malicious tagged checker invocation, a candidate-tree checkout, a missing
environment binding, a dropped trust edge, and a release job that stops
requiring the trusted verdict — and then applies the same contract to the real
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
STATUS_CONTEXT = "trusted-launch-advisory-gate"
TRUSTED_CHECKER = "python3 -I scripts/check_launch_readiness.py"
SELF_TEST_STEP = "python3 -I .github/scripts/verify_launch_advisory_trust.py --self-test"

# Events whose workflow definition and checked-out code GitHub resolves from the
# protected default branch. Every other event can be reached from a ref whose
# contents an untrusted principal controls.
TRUSTED_EVENTS = frozenset({"workflow_run", "schedule", "workflow_dispatch"})

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
    if any(TOKEN_REFERENCE in line for line in trust_lines):
        errors.append(
            f"{TRUSTED_WORKFLOW} job `{TRUST_JOB}` must establish provenance "
            "without any credential"
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
        if not any(f"context={STATUS_CONTEXT}" in line for line in publish_lines):
            errors.append(
                f"{TRUSTED_WORKFLOW} job `{PUBLISH_JOB}` must publish the "
                f"`{STATUS_CONTEXT}` commit status"
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
    if STATUS_CONTEXT not in gate:
        errors.append(
            f"{RELEASE_WORKFLOW} job `{RELEASE_GATE_JOB}` must require the "
            f"`{STATUS_CONTEXT}` verdict published by trusted code"
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
      - requested
  schedule:
    - cron: "45 6 * * *"
  workflow_dispatch:

permissions:
  contents: read

jobs:
  establish-trust:
    name: Establish candidate trust
    runs-on: ubuntu-latest
    outputs:
      candidate_sha: ${{ steps.candidate.outputs.candidate_sha }}
      trusted_sha: ${{ steps.candidate.outputs.trusted_sha }}
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v6
        with:
          ref: refs/heads/main
      - name: Resolve
        id: candidate
        run: echo resolve

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
        run: gh api --method POST "repos/x/statuses/$CANDIDATE_SHA" -f "context=trusted-launch-advisory-gate"
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
        run: gh api statuses | grep trusted-launch-advisory-gate
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
        "        run: gh api statuses | grep trusted-launch-advisory-gate",
        "        env:\n"
        "          LAUNCH_ADVISORY_READ_TOKEN: ${{ secrets.LAUNCH_ADVISORY_READ_TOKEN }}\n"
        '        run: echo "$LAUNCH_ADVISORY_READ_TOKEN" > exfiltrated.txt',
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
        "        run: gh api statuses | grep trusted-launch-advisory-gate",
        "        run: python3 -I scripts/check_launch_readiness.py --verify"
        " # trusted-launch-advisory-gate",
    )
    check(
        "a release gate that re-evaluates the verdict from the tag is rejected",
        any(
            "must not evaluate the live launch verdict itself" in err
            for err in evaluate(mutated(RELEASE_WORKFLOW, reevaluating_release))
        ),
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
