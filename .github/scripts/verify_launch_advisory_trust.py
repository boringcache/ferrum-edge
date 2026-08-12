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
* the secret-bearing job is gated behind the secretless trust job and is bound to
  the protected deployment environment;
* that job is a *closed step sequence*: exactly two steps, the first being the
  pinned `actions/checkout` at the trusted anchor commit the secretless job
  already established (with a closed set of inputs), the second being the one
  credential-bearing checker invocation. Step scoping alone is not enough. A
  secretless step needs no credential and no candidate expression to be
  dangerous: it shares the credential job's workspace, so it can read the
  candidate from `$GITHUB_EVENT_PATH`, the API, or `printenv`, fetch candidate
  bytes, or simply overwrite `scripts/check_launch_readiness.py` — and the exact
  credential command would then execute the replaced file with the credential
  bound. So no arbitrary executable step may exist in that job at all, before or
  after the credential step;
* the credential is delivered to exactly one *step*, identified structurally by
  parsing the job's `steps:` list, that step is the second and final one, and it
  is a plain single-line `run:` step whose whole command is the default-branch
  checker with its trusted-execution pins. A `run: |` block on the credential
  step would let arbitrary shell run beside the checker with the credential
  already in the environment;
* the trusted anchor is proved fail-closed in the secretless job: derived from
  the literal protected-branch checkout, validated as a 40-hex commit, and
  required to be reachable from protected `main` before it is exported;
* the candidate commit reaches the secret-bearing job only as an inert SHA in an
  environment mapping, never as a checkout ref, and no candidate-derived
  environment variable is ever expanded on an executable line anywhere in that
  job — including inside a multiline block of a secretless step;
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
malicious tagged checker invocation, a candidate-tree checkout, a credential
step turned into a `run: |` block that checks out or sources candidate material
before calling the checker, a second command chained onto the credential
invocation, a command substitution in the trusted-tree pin, an action added as a
second execution surface on the credential step, a job-level credential binding,
candidate environment expansion in a secretless step, an *indirect* pre-credential
step that extracts the candidate from `$GITHUB_EVENT_PATH` and replaces the
checker without naming any candidate expression, an extra step appended after the
credential step, a swapped or unpinned checkout action, a redirected checkout
ref, a dropped or altered checkout input, a checkout step that also runs a
command, a swapped step order, a job-level `defaults:` working directory, the
self-test moved back into the credential job, a dropped trusted-anchor ancestry
proof, a missing environment binding, a dropped trust edge, a constant
commit-wide status context, an omitted run-attempt binding, a `requested`-only
trigger, a release gate that reuses another run's status, and a release job that
stops requiring the trusted verdict — and then applies the same contract to the
real `.github/workflows` tree.
Comments are stripped before every contract decision, so prose can neither
satisfy a requirement nor stand in for a rejected command.
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
# The secretless checker self-test. It belongs to the trust job: hosted in the
# credential-bearing job it would be an executable step sharing that job's
# workspace with the credential step.
CHECKER_SELF_TEST_STEP = f"{TRUSTED_CHECKER} --self-test"

# The credential-bearing job checks out the anchor commit the secretless job
# already established from the literal protected branch, so no in-job command is
# needed to move HEAD onto it. Bumping the checkout pin means bumping this
# constant; see docs/dependency-policy.md on coordinated action-pin bumps.
CHECKOUT_ACTION_PIN = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
TRUSTED_SHA_REF_EXPRESSION = "${{ needs.establish-trust.outputs.trusted_sha }}"

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

# ---------------------------------------------------------------------------
# Step-level structure for the credential-bearing job
# ---------------------------------------------------------------------------

STEPS_KEY = re.compile(r"^(?P<indent> *)steps:\s*$")
STEP_ITEM = re.compile(r"^(?P<lead> *)-(?P<gap> +)(?=\S)")
KEY_LINE = re.compile(r"^(?P<indent> *)(?P<key>[A-Za-z_][A-Za-z0-9_-]*):(?P<rest>.*)$")
# `|`, `>`, `|-`, `>+`, `|2` … every YAML block-scalar indicator. A credential
# step written as a block can carry any number of extra shell commands, which is
# exactly the bypass this module must refuse.
BLOCK_SCALAR = re.compile(r"^[|>][+-]?[0-9]*[+-]?$")

# The only keys the credential-bearing step may declare. `uses`, `shell`, and
# `working-directory` are each a way to redirect or duplicate the execution
# surface while the credential is already bound to the step.
CREDENTIAL_STEP_ALLOWED_KEYS = frozenset({"name", "id", "if", "env", "run"})

# The credential-bearing job is a closed sequence: the trusted-anchor checkout
# and then the credential step. Nothing else may run in that workspace.
CREDENTIAL_JOB_STEP_COUNT = 2
# The checkout step is declarative only: no `run`, no `env`, no `if` that could
# skip it, no `id` another step could consume.
CREDENTIAL_CHECKOUT_ALLOWED_KEYS = frozenset({"name", "uses", "with"})
# Exactly these inputs, exactly these values. `path`/`repository`/`token`/
# `submodules`/`sparse-checkout`/`clean` would each change what lands in the
# workspace the credential step then executes.
CREDENTIAL_CHECKOUT_INPUTS = {
    "ref": TRUSTED_SHA_REF_EXPRESSION,
    "fetch-depth": "1",
    "persist-credentials": "false",
}
# Job-level keys admitted on the credential job. `defaults:`, `container:`,
# `services:`, `strategy:`, `env:`, and `uses:` would each add a surface — a
# working-directory rewrite, a foreign image, a matrix, a job-wide credential, or
# a whole reusable workflow — outside the two verified steps.
CREDENTIAL_JOB_ALLOWED_KEYS = frozenset(
    {
        "name",
        "needs",
        "runs-on",
        "timeout-minutes",
        "environment",
        "permissions",
        "steps",
    }
)
JOB_KEY = re.compile(r"^    (?P<key>[A-Za-z_][A-Za-z0-9_-]*):")
MAPPING_ENTRY = re.compile(
    r"^\s*(?P<key>[A-Za-z_][A-Za-z0-9_-]*):\s*(?P<value>.*?)\s*$"
)

# The trusted anchor must be proved, not asserted: taken from the literal
# protected-branch checkout, validated as a commit, and required to be reachable
# from protected `main` before it is exported to the credential job.
TRUST_ANCHOR_PROOFS = (
    (
        re.compile(r'trusted_sha="\$\(git rev-parse HEAD\)"'),
        "derive the trusted anchor from the literal protected-branch checkout "
        '(`trusted_sha="$(git rev-parse HEAD)"`)',
    ),
    (
        re.compile(r'\[\[\s*"\$trusted_sha"\s*=~\s*\^\[0-9a-f\]\{40\}\$\s*\]\]'),
        "validate the trusted anchor as a 40-hex commit",
    ),
    (
        re.compile(r'git merge-base --is-ancestor "\$trusted_sha" "\$main_tip"'),
        "require the trusted anchor to be reachable from protected `main`",
    ),
)
TRUSTED_SHA_OUTPUT_BINDING = re.compile(
    r"^\s*trusted_sha:\s*\$\{\{\s*steps\.[A-Za-z0-9_-]+\.outputs\.trusted_sha\s*\}\}\s*$"
)

# The complete command the credential-bearing step may execute, anchored at both
# ends. Anchoring is the contract: no leading `cd`, no trailing `&& …`, no `;`,
# no pipe, no command substitution, no alternate interpreter, and no alternate
# path to the checker can survive it, and the trusted-tree pin must be the
# literal environment reference the anchor-pin step already validated.
CREDENTIAL_RUN_COMMAND = re.compile(
    r"^python3 -I scripts/check_launch_readiness\.py"
    r"(?: --(?:verify|require-pass|trusted-execution))+"
    r' --trusted-tree-sha "\$TRUSTED_SHA"$'
)
CREDENTIAL_REQUIRED_FLAGS = ("--verify", "--trusted-execution")

# Environment variables in the credential-bearing job that carry the candidate
# commit. The checker reads them from the process environment; any *shell*
# expansion of one puts candidate-derived bytes on an executable line, so it is
# refused in every step of that job, block scalars included.
CANDIDATE_ENV_NAMES = ("LAUNCH_TARGET_SHA", "CANDIDATE_SHA")
_CANDIDATE_ENV_ALTERNATION = "|".join(CANDIDATE_ENV_NAMES)
CANDIDATE_ENV_EXPANSION = re.compile(
    r"\$(?:\{\{\s*env\.(?:"
    + _CANDIDATE_ENV_ALTERNATION
    + r")\s*\}\}|\{(?:"
    + _CANDIDATE_ENV_ALTERNATION
    + r")[:\-\}]|(?:"
    + _CANDIDATE_ENV_ALTERNATION
    + r")\b)"
)

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
    # Comments are removed before any structure is derived, so a commented-out
    # key can neither introduce nor terminate a block.
    return split_blocks(
        [strip_comment(line) for line in text.splitlines()], TOP_LEVEL_KEY
    )


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


def job_steps(job_lines: list[str]) -> list[list[str]]:
    """Split a job block into its `steps:` items by indentation.

    Each returned step is the list of its code lines, starting with the `- `
    item line. This is what makes the credential's *step* scope visible: a
    secret bound by a step's `env:` is readable only by that step's command, so
    the contract has to be applied to the step, not to the job.
    """

    lines = code_lines(job_lines)
    start: int | None = None
    steps_indent = 0
    for index, line in enumerate(lines):
        match = STEPS_KEY.match(line)
        if match:
            start = index
            steps_indent = len(match.group("indent"))
            break
    if start is None:
        return []

    steps: list[list[str]] = []
    item_indent: int | None = None
    for line in lines[start + 1 :]:
        indent = len(line) - len(line.lstrip())
        if indent <= steps_indent:
            break
        item = STEP_ITEM.match(line)
        # A `- ` at the item indent opens a new step. Anything deeper — including
        # a shell line inside a block scalar that happens to start with `-` —
        # belongs to the step already open.
        if item and (item_indent is None or len(item.group("lead")) == item_indent):
            item_indent = len(item.group("lead"))
            steps.append([line])
            continue
        if steps:
            steps[-1].append(line)
    return steps


def step_entries(step_lines: list[str]) -> list[tuple[str, str, list[str]]]:
    """Return `(key, inline value, body lines)` for each top-level step key."""

    if not step_lines:
        return []
    item = STEP_ITEM.match(step_lines[0])
    if item is None:
        return []
    key_indent = len(item.group(0))
    # Rewrite the `- ` marker as plain indentation so the first key is read the
    # same way as every later one.
    normalized = [" " * key_indent + step_lines[0][key_indent:], *step_lines[1:]]

    entries: list[tuple[str, str, list[str]]] = []
    current: tuple[str, str, list[str]] | None = None
    for line in normalized:
        match = KEY_LINE.match(line)
        if match and len(match.group("indent")) == key_indent:
            current = (match.group("key"), match.group("rest").strip(), [])
            entries.append(current)
            continue
        if current is not None:
            current[2].append(line)
    return entries


def step_run_text(step_lines: list[str]) -> str:
    """Every executable line of every `run:` in a step, inline value and body."""

    parts: list[str] = []
    for key, value, body in step_entries(step_lines):
        if key != "run":
            continue
        if not BLOCK_SCALAR.match(value):
            parts.append(value)
        parts.extend(body)
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Contract
# ---------------------------------------------------------------------------


def inline_value(value: str) -> str:
    """A step/mapping scalar with a trailing comment and quotes removed."""

    text = value.split(" #", 1)[0].strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        text = text[1:-1]
    return text.strip()


def check_trusted_checkout_step(step_lines: list[str]) -> list[str]:
    """The first step of the credential job: the trusted-anchor checkout.

    This step is what makes the credential job's workspace trustworthy without
    any in-job command. It is held to an exact action pin, an exact ref
    expression, and a closed input set, and it may declare nothing executable.
    """

    where = f"{TRUSTED_WORKFLOW} job `{SECRET_JOB}`"
    entries = step_entries(step_lines)
    if not entries:
        return [f"{where} first step is not parseable as a step"]

    errors: list[str] = []
    disallowed = sorted(
        {key for key, _, _ in entries if key not in CREDENTIAL_CHECKOUT_ALLOWED_KEYS}
    )
    if disallowed:
        errors.append(
            f"{where} trusted-anchor checkout step declares {', '.join(disallowed)}; "
            "only name/uses/with are admitted, so it can neither run a command in "
            "this workspace nor be conditionally skipped"
        )

    uses = [inline_value(value) for key, value, _ in entries if key == "uses"]
    if uses != [CHECKOUT_ACTION_PIN]:
        errors.append(
            f"{where} must begin with exactly one `uses: {CHECKOUT_ACTION_PIN}` "
            f"step (found {uses}); the credential job's workspace must come from "
            "the pinned checkout action and nothing else"
        )

    with_bodies = [body for key, _, body in entries if key == "with"]
    if len(with_bodies) != 1:
        errors.append(
            f"{where} trusted-anchor checkout must declare exactly one `with:` "
            f"input mapping (found {len(with_bodies)})"
        )
        return errors

    inputs: dict[str, str] = {}
    for line in with_bodies[0]:
        entry = MAPPING_ENTRY.match(line)
        if entry:
            inputs[entry.group("key")] = inline_value(entry.group("value"))
    if inputs != CREDENTIAL_CHECKOUT_INPUTS:
        errors.append(
            f"{where} trusted-anchor checkout declares inputs {inputs!r}; it must "
            f"declare exactly {CREDENTIAL_CHECKOUT_INPUTS!r} — the established "
            "anchor commit, a single-commit fetch, and no persisted credential — "
            "so no other ref, repository, path, or credential can reach the "
            "workspace the credential step executes"
        )
    return errors


def check_credential_job_steps(steps: list[list[str]]) -> list[str]:
    """The closed step-sequence contract for the credential-bearing job.

    Step scoping bounds who can *read* the credential; it does not bound who can
    change what the credential step *executes*. Any additional step in this job
    shares its workspace, needs no secret, and needs no candidate expression: it
    can read `.workflow_run.head_sha` from `$GITHUB_EVENT_PATH`, ask the API, or
    read `printenv`, then fetch candidate bytes or overwrite
    `scripts/check_launch_readiness.py`, and the exact credential command would
    execute the replaced file with the credential bound. So the sequence itself
    is verified: a pinned trusted-anchor checkout, then the credential step, and
    nothing before, between, or after.
    """

    errors: list[str] = []
    where = f"{TRUSTED_WORKFLOW} job `{SECRET_JOB}`"

    # Executable candidate data anywhere in the job, block scalars included. The
    # checker receives the candidate SHA through the process environment and
    # never through the shell, so any expansion here is a new execution path.
    # This survives as defence in depth; the closed sequence below is what makes
    # an *indirectly* derived candidate unreachable too.
    for step in steps:
        run_text = step_run_text(step)
        match = CANDIDATE_ENV_EXPANSION.search(run_text)
        if match:
            errors.append(
                f"{where} expands candidate-derived {match.group(0)!r} on an "
                "executable line; the candidate commit may only be read from the "
                "process environment by the trusted checker, never by shell"
            )

    if len(steps) != CREDENTIAL_JOB_STEP_COUNT:
        errors.append(
            f"{where} must consist of exactly {CREDENTIAL_JOB_STEP_COUNT} steps — "
            f"the pinned `{CHECKOUT_ACTION_PIN}` checkout of the established "
            "trusted anchor, immediately followed by the one credential-bearing "
            f"checker invocation — but declares {len(steps)}. Any other step "
            "shares this job's workspace and can replace the checker (or derive "
            "the candidate from $GITHUB_EVENT_PATH, the API, or printenv) before "
            "the credential is used, with no secret and no candidate expression "
            "of its own"
        )
    if not steps:
        return errors

    errors.extend(check_trusted_checkout_step(steps[0]))

    positions = [
        index
        for index, step in enumerate(steps)
        if any(TOKEN_REFERENCE in line for line in step)
    ]
    if positions and (
        positions != [CREDENTIAL_JOB_STEP_COUNT - 1] or positions[0] != len(steps) - 1
    ):
        errors.append(
            f"{where} credential-bearing step must be step "
            f"{CREDENTIAL_JOB_STEP_COUNT} of {CREDENTIAL_JOB_STEP_COUNT} — "
            "immediately after the trusted-anchor checkout and the last step of "
            f"the job (found at step {positions[0] + 1} of {len(steps)})"
        )
    errors.extend(check_credential_step(steps))
    return errors


def check_credential_step(steps: list[list[str]]) -> list[str]:
    """The step-scoped contract for the step that receives the credential.

    A secret bound by one step's `env:` is visible only to that step's command,
    so this contract is applied to the step that actually receives it.
    """

    errors: list[str] = []
    where = f"{TRUSTED_WORKFLOW} job `{SECRET_JOB}`"

    bearing = [step for step in steps if any(TOKEN_REFERENCE in line for line in step)]
    if len(bearing) != 1:
        errors.append(
            f"{where} must deliver the advisory credential to exactly one step "
            f"(found {len(bearing)}); a job-level or workflow-level binding would "
            "hand the credential to every command in the job"
        )
        return errors

    entries = step_entries(bearing[0])
    if not entries:
        errors.append(f"{where} credential-bearing step is not parseable as a step")
        return errors

    disallowed = sorted(
        {key for key, _, _ in entries if key not in CREDENTIAL_STEP_ALLOWED_KEYS}
    )
    if disallowed:
        errors.append(
            f"{where} credential-bearing step declares {', '.join(disallowed)}; "
            "only name/id/if/env/run are admitted, so no action, shell override, "
            "or working directory can add or redirect an execution surface while "
            "the credential is bound"
        )

    runs = [(value, body) for key, value, body in entries if key == "run"]
    if len(runs) != 1:
        errors.append(
            f"{where} credential-bearing step must have exactly one `run:` "
            f"execution surface (found {len(runs)})"
        )
        return errors

    value, body = runs[0]
    if BLOCK_SCALAR.match(value) or body or not value:
        errors.append(
            f"{where} credential-bearing step uses a multiline `run:` block; it "
            "must be a single-line invocation of the default-branch checker so "
            "no other shell command — a candidate checkout, a `source`, or any "
            "other statement — can run beside it with the credential already in "
            "the environment"
        )
        return errors

    if not CREDENTIAL_RUN_COMMAND.match(value):
        errors.append(
            f"{where} credential-bearing step runs {value!r}; it may run only "
            f'`{TRUSTED_CHECKER} [--verify] [--require-pass] --trusted-execution '
            '--trusted-tree-sha "$TRUSTED_SHA"` with no other command, operator, '
            "substitution, interpreter, or path"
        )
    missing = [flag for flag in CREDENTIAL_REQUIRED_FLAGS if flag not in value]
    if missing:
        errors.append(
            f"{where} credential-bearing step omits {', '.join(missing)}; without "
            "the trusted-execution pins the checker will not prove the executing "
            "tree is the trusted anchor before using the credential"
        )
    return errors


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
        uses = USES_FIELD.match(line)
        if uses and not PINNED_ACTION.match(uses.group("value")):
            errors.append(
                f"{TRUSTED_WORKFLOW} uses unpinned or local action "
                f"{uses.group('value')!r}"
            )

    # Checkout refs are judged per job. Every secretless job may check out only
    # the literal protected branch; the credential-bearing job checks out the
    # anchor commit that literal checkout already established, so its workspace
    # is trusted without running any command of its own.
    declared_refs = sum(1 for line in lines if REF_FIELD.match(line))
    scanned_refs = 0
    for job_name in sorted(jobs):
        for line in code_lines(jobs[job_name]):
            ref = REF_FIELD.match(line)
            if not ref:
                continue
            scanned_refs += 1
            value = inline_value(ref.group("value"))
            if job_name == SECRET_JOB:
                if value != TRUSTED_SHA_REF_EXPRESSION:
                    errors.append(
                        f"{TRUSTED_WORKFLOW} job `{SECRET_JOB}` checks out "
                        f"{value!r}; it must check out exactly "
                        f"{TRUSTED_SHA_REF_EXPRESSION!r}, the anchor commit the "
                        "literal protected-branch checkout already established"
                    )
            elif value != TRUSTED_REF:
                errors.append(
                    f"{TRUSTED_WORKFLOW} job `{job_name}` checks out {value!r}; "
                    f"every secretless ref must be the literal trusted ref "
                    f"{TRUSTED_REF!r}"
                )
    if scanned_refs != declared_refs:
        errors.append(
            f"{TRUSTED_WORKFLOW} declares a checkout ref outside any job block"
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

    # The credential job executes whatever the trusted anchor names, so the
    # anchor itself must be proved here: taken from the literal protected-branch
    # checkout, validated as a commit, reachable from protected `main`, and
    # exported from that step's own output.
    for pattern, detail in TRUST_ANCHOR_PROOFS:
        if not pattern.search(trust_text):
            errors.append(
                f"{TRUSTED_WORKFLOW} job `{TRUST_JOB}` must {detail}; the "
                f"`{SECRET_JOB}` job checks that anchor out directly and executes "
                "it with the credential bound"
            )
    if not any(TRUSTED_SHA_OUTPUT_BINDING.match(line) for line in trust_lines):
        errors.append(
            f"{TRUSTED_WORKFLOW} job `{TRUST_JOB}` must export `trusted_sha` from "
            "the step that resolved and validated it"
        )

    # Secretless prerequisites belong here, not in the credential job, whose
    # workspace must reach the credential step untouched by any other step.
    if CHECKER_SELF_TEST_STEP not in trust_text:
        errors.append(
            f"{TRUSTED_WORKFLOW} job `{TRUST_JOB}` must run the secretless checker "
            f"self-test `{CHECKER_SELF_TEST_STEP}`; it cannot live in "
            f"`{SECRET_JOB}`, where it would be an executable step sharing the "
            "credential step's workspace"
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
        if "python" in stripped and TRUSTED_CHECKER not in stripped:
            errors.append(
                f"{TRUSTED_WORKFLOW} job `{SECRET_JOB}` invokes an interpreter "
                "other than the default-branch checker"
            )

    declared_job_keys = sorted(
        {
            match.group("key")
            for match in (JOB_KEY.match(line) for line in secret_lines)
            if match
        }
        - CREDENTIAL_JOB_ALLOWED_KEYS
    )
    if declared_job_keys:
        errors.append(
            f"{TRUSTED_WORKFLOW} job `{SECRET_JOB}` declares "
            f"{', '.join(declared_job_keys)}; only "
            f"{'/'.join(sorted(CREDENTIAL_JOB_ALLOWED_KEYS))} are admitted, so no "
            "job-wide credential, working-directory rewrite, container, matrix, "
            "or reusable workflow can add a surface outside the two verified steps"
        )

    errors.extend(check_credential_job_steps(job_steps(jobs[SECRET_JOB])))

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
    # Comment-stripped: a commented-out or merely documented invocation must not
    # satisfy the requirement that the self-test actually runs.
    if not any(SELF_TEST_STEP in line for line in code_lines(text.splitlines())):
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
      - name: Synthetic policy/checker self-tests
        run: python3 -I scripts/check_launch_readiness.py --self-test
      - name: Resolve
        id: candidate
        env:
          WORKFLOW_RUN_ID: ${{ github.event.workflow_run.id }}
          WORKFLOW_RUN_ATTEMPT: ${{ github.event.workflow_run.run_attempt }}
        run: |
          trusted_sha="$(git rev-parse HEAD)"
          [[ "$trusted_sha" =~ ^[0-9a-f]{40}$ ]] || exit 1
          git merge-base --is-ancestor "$trusted_sha" "$main_tip" || exit 1
          status_context="trusted-launch-advisory-gate/main-audit"
          status_context="trusted-launch-advisory-gate/release-${release_run_id}-attempt-${release_run_attempt}"
          echo "trusted_sha=${trusted_sha}" >> "$GITHUB_OUTPUT"
          echo "status_context=${status_context}" >> "$GITHUB_OUTPUT"

  advisory-verdict:
    name: Evaluate advisories from trusted code
    needs: establish-trust
    runs-on: ubuntu-latest
    environment: launch-advisory
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v6
        with:
          ref: ${{ needs.establish-trust.outputs.trusted_sha }}
          fetch-depth: 1
          persist-credentials: false
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
            "credential-bearing step runs" in err
            or "invokes an interpreter other than" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, hostile_checker))
        ),
    )

    # ---- Step-scoped credential contract -------------------------------------
    #
    # Every fixture below is accepted by a verifier that inspects only the first
    # line of a `run:`, which is precisely why each one is here: with the
    # credential already bound to the step, the extra shell runs beside the
    # checker and can check out, source, or otherwise execute candidate material.

    credential_run = (
        "run: python3 -I scripts/check_launch_readiness.py --verify "
        '--trusted-execution --trusted-tree-sha "$TRUSTED_SHA"'
    )

    block_checkout = FIXTURE_TRUSTED.replace(
        credential_run,
        "run: |\n"
        '          git checkout "$LAUNCH_TARGET_SHA"\n'
        "          python3 -I scripts/check_launch_readiness.py --verify "
        '--trusted-execution --trusted-tree-sha "$TRUSTED_SHA"',
    )
    block_checkout_errors = evaluate(mutated(TRUSTED_WORKFLOW, block_checkout))
    check(
        "a credential-bearing `run: |` block that checks out the candidate is rejected",
        any("must be a single-line invocation" in err for err in block_checkout_errors),
        str(block_checkout_errors),
    )
    check(
        "the candidate checkout in that block is itself reported",
        any(
            "on an executable line" in err and "LAUNCH_TARGET_SHA" in err
            for err in block_checkout_errors
        ),
        str(block_checkout_errors),
    )

    block_source = FIXTURE_TRUSTED.replace(
        credential_run,
        "run: |\n"
        '          . "./candidate/${LAUNCH_TARGET_SHA}.env"\n'
        "          python3 -I scripts/check_launch_readiness.py --verify "
        '--trusted-execution --trusted-tree-sha "$TRUSTED_SHA"',
    )
    check(
        "a credential-bearing block that sources candidate material is rejected",
        any(
            "must be a single-line invocation" in err or "on an executable line" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, block_source))
        ),
    )

    chained_command = FIXTURE_TRUSTED.replace(
        credential_run, credential_run + " && sh ./candidate/postscript.sh"
    )
    check(
        "a second command chained onto the credential invocation is rejected",
        any(
            "credential-bearing step runs" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, chained_command))
        ),
    )

    substituted_pin = FIXTURE_TRUSTED.replace(
        '--trusted-tree-sha "$TRUSTED_SHA"',
        '--trusted-tree-sha "$(git rev-parse HEAD)"',
    )
    check(
        "a command substitution in the trusted-tree pin is rejected",
        any(
            "credential-bearing step runs" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, substituted_pin))
        ),
    )

    second_surface = FIXTURE_TRUSTED.replace(
        "      - name: Evaluate\n        env:\n",
        "      - name: Evaluate\n"
        "        uses: actions/github-script@3d3c42e5aac5ba805825da76410c181273ba90b1\n"
        "        env:\n",
    )
    check(
        "an action added as a second execution surface on the credential step is "
        "rejected",
        any(
            "only name/id/if/env/run are admitted" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, second_surface))
        ),
    )

    job_level_credential = FIXTURE_TRUSTED.replace(
        "    environment: launch-advisory\n    steps:\n",
        "    environment: launch-advisory\n"
        "    env:\n"
        "      LAUNCH_ADVISORY_READ_TOKEN: ${{ secrets.LAUNCH_ADVISORY_READ_TOKEN }}\n"
        "    steps:\n",
    ).replace(
        "          LAUNCH_ADVISORY_READ_TOKEN: "
        "${{ secrets.LAUNCH_ADVISORY_READ_TOKEN }}\n",
        "",
    )
    check(
        "widening the credential from the step to the whole job is rejected",
        any(
            "exactly one step (found 0)" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, job_level_credential))
        ),
    )

    # ---- Closed step sequence for the credential-bearing job -----------------
    #
    # Step scoping bounds who can *read* the credential. It does not bound who
    # can change what the credential step *executes*: every fixture below is a
    # secretless step sharing that job's workspace, and each one was accepted by
    # a verifier that only closed the credential step's own command.

    before_evaluate = "          persist-credentials: false\n      - name: Evaluate"
    checkout_block = (
        "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v6\n"
        "        with:\n"
        "          ref: ${{ needs.establish-trust.outputs.trusted_sha }}\n"
        "          fetch-depth: 1\n"
        "          persist-credentials: false\n"
    )

    candidate_in_secretless_step = FIXTURE_TRUSTED.replace(
        before_evaluate,
        "          persist-credentials: false\n"
        "      - name: Pin\n"
        "        env:\n"
        "          LAUNCH_TARGET_SHA: "
        "${{ needs.establish-trust.outputs.candidate_sha }}\n"
        "        run: |\n"
        '          git checkout --detach "$LAUNCH_TARGET_SHA"\n'
        "      - name: Evaluate",
    )
    check(
        "candidate execution in a secretless step of the credential job is rejected",
        any(
            "on an executable line" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, candidate_in_secretless_step))
        ),
    )

    # The accepted bypass this contract exists for: a secretless step that names
    # no candidate expression at all, derives the candidate indirectly from the
    # event payload, and replaces the checker the credential step then executes.
    indirect_replacement = FIXTURE_TRUSTED.replace(
        before_evaluate,
        "          persist-credentials: false\n"
        "      - name: Prepare the workspace\n"
        "        run: |\n"
        "          head=$(jq -r '.workflow_run.head_sha' \"$GITHUB_EVENT_PATH\")\n"
        '          git fetch --depth 1 origin "$head"\n'
        '          git show "$head:scripts/check_launch_readiness.py" '
        "> scripts/check_launch_readiness.py\n"
        "      - name: Evaluate",
    )
    indirect_errors = evaluate(mutated(TRUSTED_WORKFLOW, indirect_replacement))
    check(
        "a pre-credential step that rebuilds the checker from $GITHUB_EVENT_PATH is "
        "rejected",
        any("must consist of exactly 2 steps" in err for err in indirect_errors),
        str(indirect_errors),
    )
    check(
        "that bypass expands no candidate variable and names no candidate "
        "expression, so only the closed sequence catches it",
        not any(
            "on an executable line" in err or "exposes candidate input" in err
            for err in indirect_errors
        ),
        str(indirect_errors),
    )

    trailing_step = FIXTURE_TRUSTED.replace(
        credential_run,
        credential_run + "\n"
        "      - name: Post\n"
        "        run: sh ./candidate/postscript.sh",
    )
    trailing_errors = evaluate(mutated(TRUSTED_WORKFLOW, trailing_step))
    check(
        "a step appended after the credential step is rejected",
        any("must consist of exactly 2 steps" in err for err in trailing_errors),
        str(trailing_errors),
    )
    check(
        "the credential step must be the last step of its job",
        any("must be step 2 of 2" in err for err in trailing_errors),
        str(trailing_errors),
    )

    swapped_order = FIXTURE_TRUSTED.replace(checkout_block, "").replace(
        credential_run, credential_run + "\n" + checkout_block.rstrip("\n")
    )
    check(
        "running the credential step before the trusted-anchor checkout is rejected",
        any(
            "must be step 2 of 2" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, swapped_order))
        ),
    )

    # A block-scalar body line that begins with `- ` must not fragment the step
    # list; the extra step still has to be visible to the sequence contract.
    dash_body_step = FIXTURE_TRUSTED.replace(
        before_evaluate,
        "          persist-credentials: false\n"
        "      - name: Prepare\n"
        "        run: |\n"
        "          printf '%s\\n' \\\n"
        "            - one \\\n"
        "            - two > scripts/check_launch_readiness.py\n"
        "      - name: Evaluate",
    )
    check(
        "a block-scalar line starting with `- ` does not hide an extra step",
        any(
            "must consist of exactly 2 steps" in err and "declares 3" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, dash_body_step))
        ),
        str(evaluate(mutated(TRUSTED_WORKFLOW, dash_body_step))),
    )

    self_test_in_credential_job = FIXTURE_TRUSTED.replace(
        "      - name: Synthetic policy/checker self-tests\n"
        f"        run: {CHECKER_SELF_TEST_STEP}\n",
        "",
    ).replace(
        "      - name: Evaluate",
        "      - name: Synthetic policy/checker self-tests\n"
        f"        run: {CHECKER_SELF_TEST_STEP}\n"
        "      - name: Evaluate",
    )
    self_test_errors = evaluate(mutated(TRUSTED_WORKFLOW, self_test_in_credential_job))
    check(
        "hosting the secretless self-test inside the credential job is rejected",
        any("must consist of exactly 2 steps" in err for err in self_test_errors),
        str(self_test_errors),
    )
    check(
        "dropping the self-test from the secretless trust job is rejected",
        any(
            "must run the secretless checker self-test" in err
            for err in self_test_errors
        ),
        str(self_test_errors),
    )

    # ---- The trusted-anchor checkout itself ----------------------------------

    redirected_checkout = FIXTURE_TRUSTED.replace(
        checkout_block,
        checkout_block.replace(
            TRUSTED_SHA_REF_EXPRESSION,
            "${{ needs.establish-trust.outputs.candidate_sha }}",
        ),
    )
    check(
        "redirecting the credential job's checkout at the candidate is rejected",
        any(
            "it must check out exactly" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, redirected_checkout))
        ),
    )

    dropped_input = FIXTURE_TRUSTED.replace(
        checkout_block, checkout_block.replace("          persist-credentials: false\n", "")
    )
    check(
        "dropping a trusted-anchor checkout input is rejected",
        any(
            "it must declare exactly" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, dropped_input))
        ),
    )

    extra_input = FIXTURE_TRUSTED.replace(
        checkout_block, checkout_block + "          path: candidate\n"
    )
    check(
        "an extra trusted-anchor checkout input is rejected",
        any(
            "it must declare exactly" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, extra_input))
        ),
    )

    swapped_action = FIXTURE_TRUSTED.replace(
        checkout_block,
        checkout_block.replace(
            CHECKOUT_ACTION_PIN,
            "actions/github-script@3d3c42e5aac5ba805825da76410c181273ba90b1",
        ),
    )
    check(
        "swapping the credential job's checkout for another action is rejected",
        any(
            "must begin with exactly one `uses:" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, swapped_action))
        ),
    )

    executable_checkout = FIXTURE_TRUSTED.replace(
        checkout_block, checkout_block + "        run: sh ./candidate/pre.sh\n"
    )
    check(
        "a trusted-anchor checkout step that also runs a command is rejected",
        any(
            "only name/uses/with are admitted" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, executable_checkout))
        ),
    )

    skippable_checkout = FIXTURE_TRUSTED.replace(
        checkout_block, checkout_block + "        if: ${{ false }}\n"
    )
    check(
        "a conditionally skippable trusted-anchor checkout is rejected",
        any(
            "only name/uses/with are admitted" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, skippable_checkout))
        ),
    )

    job_defaults = FIXTURE_TRUSTED.replace(
        "    environment: launch-advisory\n    steps:\n",
        "    environment: launch-advisory\n"
        "    defaults:\n"
        "      run:\n"
        "        working-directory: ./candidate\n"
        "    steps:\n",
    )
    check(
        "a job-level working-directory rewrite on the credential job is rejected",
        any(
            "declares defaults" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, job_defaults))
        ),
    )

    unproven_anchor = FIXTURE_TRUSTED.replace(
        '          git merge-base --is-ancestor "$trusted_sha" "$main_tip" || exit 1\n',
        "",
    )
    check(
        "an exported trusted anchor with no protected-main ancestry proof is rejected",
        any(
            "reachable from protected `main`" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, unproven_anchor))
        ),
    )

    unvalidated_anchor = FIXTURE_TRUSTED.replace(
        '          trusted_sha="$(git rev-parse HEAD)"\n', "          trusted_sha=x\n"
    )
    check(
        "a trusted anchor not taken from the protected-branch checkout is rejected",
        any(
            "literal protected-branch checkout" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, unvalidated_anchor))
        ),
    )

    commented_credential = FIXTURE_TRUSTED.replace(
        "          LAUNCH_ADVISORY_READ_TOKEN: "
        "${{ secrets.LAUNCH_ADVISORY_READ_TOKEN }}\n",
        "          # LAUNCH_ADVISORY_READ_TOKEN: "
        "${{ secrets.LAUNCH_ADVISORY_READ_TOKEN }}\n",
    )
    check(
        "a commented-out credential binding does not satisfy the contract",
        any(
            "exactly once (found 0)" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, commented_credential))
        ),
    )

    commented_self_test = FIXTURE_STANDALONE.replace(
        f"        run: {SELF_TEST_STEP}",
        f"        # run: {SELF_TEST_STEP}\n        run: true",
    )
    check(
        "a self-test that survives only as a comment is rejected",
        any(
            "must run the advisory trust-boundary" in err
            for err in evaluate(mutated(STANDALONE_WORKFLOW, commented_self_test))
        ),
    )

    # The candidate tree checked out into a secretless job of the trusted
    # workflow, whose refs must stay the literal protected branch.
    hostile_trust_checkout = FIXTURE_TRUSTED.replace(
        "          ref: refs/heads/main\n", "          ref: refs/tags/v9.9.9\n"
    )
    check(
        "checking out a tag in the secretless trust job is rejected",
        any(
            "must be the literal trusted ref" in err
            for err in evaluate(mutated(TRUSTED_WORKFLOW, hostile_trust_checkout))
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
