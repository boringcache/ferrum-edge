#!/usr/bin/env python3
"""Trusted launch-readiness integrity verifier (issue #3803).

This program answers one question: *did the candidate revision preserve the
launch/release governance contract?* It deliberately does **not** compute a
launch verdict, so a truthful `FAIL` from open launch blockers never makes the
integrity check red and blocker-fix pull requests can still merge.

Trust model
-----------
The caller (`.github/workflows/launch-integrity.yml`) runs on
`pull_request_target` / `merge_group`, checks out the *trusted base*, and loads
this file from a pinned trusted-base commit. Candidate content is extracted
with `git show` into a confined directory and is only ever read as inert data:
nothing from the candidate is imported, executed, or evaluated. The candidate
checker is parsed with `ast.parse`, which never runs module code.

Two roots are supplied:

* `--base-dir` — the extraction of the pinned trusted base commit.
* `--candidate-dir` — the extraction of the pull-request head or merge-group
  head commit.

Each root uses a fixed, flat layout so no candidate-controlled path component
is ever joined into a filesystem path:

    <root>/check_launch_readiness.py
    <root>/verify_launch_integrity.py
    <root>/launch-blocker-policy.json
    <root>/launch-exemptions.json
    <root>/PRODUCTION_READINESS.md
    <root>/CODEOWNERS
    <root>/launch-integrity.yml
    <root>/workflows/<workflow file>
    <root>/tree.txt

A slot file that is absent means the path is absent from that commit, which is
how deletion and renaming are detected. Everything else fails closed: an
unreadable, unparsable, or unexpected input is an error, never a pass.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterable


# ---------------------------------------------------------------------------
# Frozen contract
# ---------------------------------------------------------------------------

CHECKER_PATH = "scripts/check_launch_readiness.py"
VERIFIER_PATH = ".github/scripts/verify_launch_integrity.py"
POLICY_PATH = "docs/launch-blocker-policy.json"
EXEMPTIONS_PATH = "docs/launch-exemptions.json"
DOCUMENT_PATH = "PRODUCTION_READINESS.md"
CODEOWNERS_PATH = ".github/CODEOWNERS"
READINESS_WORKFLOW = ".github/workflows/launch-readiness.yml"
INTEGRITY_WORKFLOW = ".github/workflows/launch-integrity.yml"
RELEASE_WORKFLOW = ".github/workflows/release.yml"

# Slot name -> repository path. Slots are flat file names inside a root.
FILE_SLOTS = {
    "checker": CHECKER_PATH,
    "verifier": VERIFIER_PATH,
    "policy": POLICY_PATH,
    "exemptions": EXEMPTIONS_PATH,
    "document": DOCUMENT_PATH,
    "codeowners": CODEOWNERS_PATH,
}
SLOT_FILENAMES = {
    "checker": "check_launch_readiness.py",
    "verifier": "verify_launch_integrity.py",
    "policy": "launch-blocker-policy.json",
    "exemptions": "launch-exemptions.json",
    "document": "PRODUCTION_READINESS.md",
    "codeowners": "CODEOWNERS",
}

# Deleting or renaming any of these is an integrity failure on its own.
PROTECTED_PATHS = (
    CHECKER_PATH,
    VERIFIER_PATH,
    POLICY_PATH,
    EXEMPTIONS_PATH,
    DOCUMENT_PATH,
    CODEOWNERS_PATH,
    READINESS_WORKFLOW,
    INTEGRITY_WORKFLOW,
    RELEASE_WORKFLOW,
)

# The candidate may not edit the anchor that judges it. Changing either file
# requires a trusted-base update rather than an ordinary pull request.
ANCHOR_PATHS = (VERIFIER_PATH, INTEGRITY_WORKFLOW)

# Required check contexts, keyed by the workflow file that must own them. A
# candidate may not move, duplicate, or re-home a required check name: the
# check-run producer is part of the contract.
CHECK_RUN_OWNERS = {
    "Launch Readiness Integrity": "launch-integrity.yml",
    "Launch Readiness Gate": "launch-readiness.yml",
}

CODEOWNERS_GOVERNED_PATHS = (
    "/PRODUCTION_READINESS.md",
    "/docs/launch-blocker-policy.json",
    "/docs/launch-exemptions.json",
    "/docs/launch-readiness.md",
    "/scripts/check_launch_readiness.py",
    "/.github/workflows/launch-readiness.yml",
    "/.github/workflows/launch-integrity.yml",
    "/.github/workflows/release.yml",
    "/.github/scripts/verify_launch_integrity.py",
    "/.github/CODEOWNERS",
)

# --- checker source contract ----------------------------------------------

REQUIRED_STATE_MACHINE = {
    "open": "blocking",
    "in_flight": "blocking",
    "merged_awaiting_issue_close": "blocking",
    "closed_completed": "cleared",
    "closed_other": "blocking",
    "exempted": "cleared_for_listed_tiers",
}
REQUIRED_CHECKER_CONSTANTS: dict[str, Any] = {
    "SEVERITIES": ("critical", "high", "medium"),
    "VERDICTS": ("PASS", "FAIL", "UNKNOWN"),
    "ADVISORY_STATES": ("triage", "draft", "published", "closed", "withdrawn"),
    "ADVISORY_SEVERITIES": ("critical", "high", "medium", "low"),
    "REQUIRED_STATE_MACHINE": REQUIRED_STATE_MACHINE,
    "BELOW_TIER": "below_tier",
    "REQUIRED_CLOSED_COMPLETED_REASONS": ("completed",),
    "REQUIRED_CLOSED_OTHER_REASONS": ("not_planned", "duplicate", None),
    "REQUIRED_NEVER_EMIT_FIELDS": (
        "summary",
        "description",
        "ghsa_id",
        "cve_id",
        "html_url",
        "url",
        "vulnerabilities",
        "identifiers",
        "cvss",
        "cwes",
        "credits",
    ),
    "BANNED_OUTPUT_TOKENS": (
        "ghsa_id",
        "GHSA-",
        "cve_id",
        "CVE-",
        "html_url",
        "vulnerabilities",
        "identifiers",
        "credits",
        "cvss",
        "cwes",
    ),
    "FORBIDDEN_POLICY_KEYS": (
        "opaque_input",
        "redacted_blocking_count",
        "as_of",
        "private_blocker_count",
    ),
    "API_ORIGIN": "https://api.github.com/",
}

# Integer constants spelled as arithmetic (`1 << 20`) rather than as literals.
REQUIRED_CHECKER_NUMBERS = {
    "MAX_RESPONSE_BYTES": 1 << 20,
    "PER_PAGE": 100,
}

# Ceilings, not tunables: the candidate may tighten them and never loosen them,
# and may never exceed the frozen ceiling even if the trusted base did.
CHECKER_CEILINGS = {
    "MAX_FALLBACK_AGE_SECONDS": 30 * 24 * 60 * 60,
    "MAX_FALLBACK_COUNT": 100000,
    "MAX_PAGES": 50,
}

REQUIRED_CHECKER_FUNCTIONS = (
    "validate_policy",
    "validate_private_advisory_policy",
    "validate_exemptions",
    "severity_from_labels",
    "classify_issue",
    "blocking_classifications",
    "issue_public_summary",
    "fetch_advisories",
    "count_private_blockers",
    "resolve_trusted_fallback",
    "resolve_private_blockers",
    "compute_verdict",
    "build_evaluation",
    "unknown_evaluation",
    "evaluate_live",
    "extract_document_claim",
    "assert_document_historical_separation",
    "verify_claim_against_evaluation",
    "safe_summary_text",
    "print_safe_summary",
    "resolve_checked_out_sha",
    "http_get_json",
    "paginate",
    "verify_errors",
    "verify_exit_code",
    "run_verify",
    "run_self_test",
    "main",
)

# A candidate may not widen the checker's dependency surface: a new import is
# how an evaluator grows an exfiltration or shell-out path.
ALLOWED_CHECKER_IMPORTS = frozenset(
    {
        "__future__",
        "argparse",
        "json",
        "os",
        "re",
        "sys",
        "urllib",
        "urllib.error",
        "urllib.parse",
        "urllib.request",
        "dataclasses",
        "datetime",
        "pathlib",
        "typing",
    }
)

# Behavioural text each evaluator function must still carry. These are the
# exact fail-closed decisions an "always PASS" rewrite has to delete.
REQUIRED_FUNCTION_MARKERS = {
    "compute_verdict": ('"UNKNOWN"', '"FAIL"', '"PASS"'),
    "verify_errors": ('evaluation.verdict != "PASS"', "errors.append"),
    "verify_exit_code": ("verify_errors(", "return 1 if"),
    "run_verify": ("verify_errors(", "return 1 if errors else 0"),
    "run_self_test": ("failures", "return 1"),
    "main": ("run_self_test()", "run_verify(", "return 1"),
    "resolve_trusted_fallback": ("GateError", "max_age_seconds"),
    "resolve_private_blockers": ("token_env", "resolve_trusted_fallback("),
}

# Adversarial fixtures the candidate self-test corpus must keep. Deleting a row
# here is how "checker and tests weakened together" starts.
REQUIRED_SELF_TEST_CASES = (
    "base policy validates",
    "repository policy validates",
    "repository exemptions validate",
    "state machine downgrade",
    "in-flight clears blocker",
    "merged clears blocker",
    "duplicate counted as completed",
    "severity label coverage",
    "never_emit incomplete",
    "fallback age ceiling",
    "advisories disabled",
    "checked-in private count",
    "security-events sufficiency claim",
    "tracked critical fails",
    "labeled blocker fails",
    "open PR does not clear",
    "closed completed clears",
    "expired exemption blocks",
    "fresh external positive fails",
    "fresh external zero clears",
    "live draft advisory fails",
    "no advisory identifier emitted",
    "issue API failure is UNKNOWN",
    "missing issue token is UNKNOWN",
    "unscoped clean claim rejected",
    "missing git dir fails closed",
    "non-GitHub request refused",
    "pagination rejects truncation",
)
MIN_SELF_TEST_CHECKS = 80

# --- workflow contract ------------------------------------------------------

READINESS_JOB = "launch-readiness"
READINESS_JOB_NAME = "Launch Readiness Gate"
INTEGRITY_JOB_NAME = "Launch Readiness Integrity"
RELEASE_GATE_JOB = "validate-launch-readiness"

# Byte-frozen lines (compared after stripping indentation). Each encodes a
# decision that cannot be re-spelled without review: which commit is evaluated,
# and that a privileged advisory token is never handed to candidate-triggered
# runs.
READINESS_FROZEN_LINES = (
    "ref: ${{ github.event_name == 'pull_request' && "
    "github.event.pull_request.head.sha || github.event_name == 'merge_group' "
    "&& github.event.merge_group.head_sha || github.sha }}",
    "LAUNCH_TARGET_SHA: ${{ github.event_name == 'pull_request' && "
    "github.event.pull_request.head.sha || github.event_name == 'merge_group' "
    "&& github.event.merge_group.head_sha || github.sha }}",
    "LAUNCH_ADVISORY_READ_TOKEN: ${{ (github.event_name != 'pull_request' && "
    "github.event_name != 'merge_group') && "
    "secrets.LAUNCH_ADVISORY_READ_TOKEN || '' }}",
    "persist-credentials: false",
    "run: python3 -I scripts/check_launch_readiness.py --self-test",
    "run: python3 -I scripts/check_launch_readiness.py --verify --verify-checkout",
)
READINESS_REQUIRED_EVENTS = (
    "pull_request",
    "merge_group",
    "push",
    "schedule",
    "workflow_dispatch",
)
RELEASE_FROZEN_LINES = (
    "run: python3 -I scripts/check_launch_readiness.py --self-test",
    "run: python3 -I scripts/check_launch_readiness.py --verify --require-pass",
)
INTEGRITY_REQUIRED_EVENTS = ("pull_request_target", "merge_group")

ADVISORY_SECRET = "secrets.LAUNCH_ADVISORY_READ_TOKEN"
CANDIDATE_TRIGGERED_EVENTS = (
    "pull_request",
    "pull_request_target",
    "merge_group",
    "workflow_run",
    "issue_comment",
)

WORKFLOW_FILENAME_RE = re.compile(r"^[A-Za-z0-9._+@~ -]+\.(?:yml|yaml)$")
ISO_Z_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)
SEVERITY_ORDER = {"critical": 3, "high": 2, "medium": 1, "low": 0}


class IntegrityError(Exception):
    """An input could not be read at all: fail closed, never pass."""


# ---------------------------------------------------------------------------
# Root loading
# ---------------------------------------------------------------------------


class Root:
    """One extracted commit, read as inert data."""

    def __init__(self, label: str, directory: Path) -> None:
        self.label = label
        self.directory = directory
        if not directory.is_dir():
            raise IntegrityError(f"{label} extraction root is missing")
        self.files: dict[str, str | None] = {}
        for slot, filename in SLOT_FILENAMES.items():
            self.files[slot] = read_optional(directory / filename, f"{label}/{slot}")
        self.workflows: dict[str, str] = {}
        workflow_dir = directory / "workflows"
        if workflow_dir.is_dir():
            for entry in sorted(workflow_dir.iterdir()):
                if not entry.is_file():
                    raise IntegrityError(
                        f"{label} workflow extraction holds a non-file entry"
                    )
                if not WORKFLOW_FILENAME_RE.match(entry.name):
                    raise IntegrityError(
                        f"{label} workflow extraction holds an unsupported name"
                    )
                text = read_optional(entry, f"{label}/workflows/{entry.name}")
                if text is None:
                    raise IntegrityError(
                        f"{label} workflow {entry.name} could not be read"
                    )
                self.workflows[entry.name] = text
        listing = read_optional(directory / "tree.txt", f"{label}/tree")
        if listing is None:
            raise IntegrityError(f"{label} tree listing is missing")
        self.tree = {line.strip() for line in listing.splitlines() if line.strip()}
        if not self.tree:
            raise IntegrityError(f"{label} tree listing is empty")

    def text(self, slot: str) -> str | None:
        return self.files.get(slot)


def read_optional(path: Path, label: str) -> str | None:
    if not path.exists():
        return None
    if not path.is_file() or path.is_symlink():
        raise IntegrityError(f"{label} is not a regular file")
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:  # pragma: no cover - fail closed
        raise IntegrityError(f"{label} could not be decoded: {exc}") from exc


# ---------------------------------------------------------------------------
# Minimal, layout-strict workflow reading
# ---------------------------------------------------------------------------


def declared_events(workflow: str) -> set[str]:
    """Return the top-level `on:` event names of a block-style workflow."""

    lines = workflow.splitlines()
    headers = [index for index, line in enumerate(lines) if line.rstrip() == "on:"]
    if len(headers) != 1:
        return set()
    start = headers[0]
    end = next(
        (
            index
            for index in range(start + 1, len(lines))
            if re.match(r"^[A-Za-z0-9_-]+:", lines[index])
        ),
        len(lines),
    )
    events: set[str] = set()
    for line in lines[start + 1 : end]:
        match = re.match(r"^  ([A-Za-z0-9_-]+):", line)
        if match:
            events.add(match.group(1))
    return events


def event_body(workflow: str, event: str) -> str | None:
    lines = workflow.splitlines(keepends=True)
    headers = [
        index for index, line in enumerate(lines) if line.rstrip("\r\n") == "on:"
    ]
    if len(headers) != 1:
        return None
    start = headers[0]
    end = next(
        (
            index
            for index in range(start + 1, len(lines))
            if re.match(r"^[A-Za-z0-9_-]+:", lines[index])
        ),
        len(lines),
    )
    event_headers = [
        index
        for index in range(start + 1, end)
        if lines[index].rstrip("\r\n") == f"  {event}:"
    ]
    if len(event_headers) != 1:
        return None
    event_start = event_headers[0]
    event_end = next(
        (
            index
            for index in range(event_start + 1, end)
            if re.match(r"^  [A-Za-z0-9_-]+:", lines[index])
        ),
        end,
    )
    return "".join(lines[event_start + 1 : event_end])


def job_blocks(workflow: str) -> dict[str, str]:
    """Split `jobs:` into `job id -> block text` for a block-style workflow."""

    lines = workflow.splitlines(keepends=True)
    headers = [
        index for index, line in enumerate(lines) if line.rstrip("\r\n") == "jobs:"
    ]
    if len(headers) != 1:
        return {}
    start = headers[0]
    blocks: dict[str, str] = {}
    current: str | None = None
    body: list[str] = []
    for line in lines[start + 1 :]:
        if re.match(r"^[A-Za-z0-9_-]+:", line):
            break
        match = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if match:
            if current is not None:
                blocks[current] = "".join(body)
            current = match.group(1)
            body = []
            continue
        if current is not None:
            body.append(line)
    if current is not None:
        blocks[current] = "".join(body)
    return blocks


def job_display_name(job_id: str, block: str) -> str:
    match = re.search(r"(?m)^    name:[ \t]*(.+?)[ \t]*$", block)
    if not match:
        return job_id
    return match.group(1).strip().strip("'\"")


def job_needs(block: str) -> set[str]:
    scalar = re.search(r"(?m)^    needs:[ \t]*([A-Za-z0-9_-]+)[ \t]*$", block)
    if scalar:
        return {scalar.group(1)}
    flow = re.search(r"(?m)^    needs:[ \t]*\[(?P<items>[^\]]*)\][ \t]*$", block)
    if flow:
        return {
            item.strip().strip("'\"")
            for item in flow.group("items").split(",")
            if item.strip()
        }
    listed = re.search(r"(?m)^    needs:[ \t]*\n(?P<items>(?:^      - [^\n]+\n)+)", block)
    if listed:
        return {
            line.strip().removeprefix("- ").strip().strip("'\"")
            for line in listed.group("items").splitlines()
            if line.strip().startswith("- ")
        }
    return set()


def stripped_lines(text: str) -> set[str]:
    return {line.strip() for line in text.splitlines()}


def non_comment_text(text: str) -> str:
    """Drop `#` comments so prose about a check name is not read as YAML."""

    return "\n".join(line.split("#", 1)[0] for line in text.splitlines())


# ---------------------------------------------------------------------------
# Candidate checker source contract
# ---------------------------------------------------------------------------


def module_constants(tree: ast.Module) -> dict[str, ast.expr]:
    values: dict[str, ast.expr] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    values[target.id] = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.value is not None:
                values[node.target.id] = node.value
    return values


def literal(node: ast.expr) -> Any:
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
        return _UNREADABLE


class _Unreadable:
    def __repr__(self) -> str:  # pragma: no cover - diagnostic only
        return "<unreadable>"


_UNREADABLE = _Unreadable()


def safe_number(node: ast.expr) -> int | None:
    """Read an integer constant that may be spelled as plain arithmetic.

    `MAX_FALLBACK_AGE_SECONDS = 30 * 24 * 60 * 60` and `1 << 20` are ordinary
    declarations, but `ast.literal_eval` refuses them. Only integer literals
    combined with a fixed operator set are accepted, so nothing is executed and
    a computed value (a call, a name, a comprehension) stays unreadable.
    """

    if isinstance(node, ast.Constant):
        if isinstance(node.value, int) and not isinstance(node.value, bool):
            return node.value
        return None
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        inner = safe_number(node.operand)
        return None if inner is None else -inner
    if isinstance(node, ast.BinOp):
        left = safe_number(node.left)
        right = safe_number(node.right)
        if left is None or right is None:
            return None
        if isinstance(node.op, ast.Add):
            return left + right
        if isinstance(node.op, ast.Sub):
            return left - right
        if isinstance(node.op, ast.Mult):
            return left * right
        if isinstance(node.op, ast.LShift) and 0 <= right <= 64:
            return left << right
        if isinstance(node.op, ast.FloorDiv) and right != 0:
            return left // right
    return None


def normalized(value: Any) -> Any:
    """Compare list/tuple spellings by content, mappings by items."""

    if isinstance(value, (list, tuple)):
        return tuple(normalized(item) for item in value)
    if isinstance(value, dict):
        return {key: normalized(item) for key, item in value.items()}
    return value


def function_nodes(tree: ast.Module) -> dict[str, ast.AST]:
    return {
        node.name: node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def effective_body(node: Any) -> list[ast.stmt]:
    body = list(node.body)
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        body = body[1:]
    return body


def returns_unconditional_success(node: Any) -> bool:
    """Detect a body rewritten to an unconditional pass/zero/None result."""

    body = effective_body(node)
    if not body:
        return True
    if len(body) != 1:
        return False
    statement = body[0]
    if isinstance(statement, ast.Pass):
        return True
    if isinstance(statement, ast.Return):
        if statement.value is None:
            return True
        value = literal(statement.value)
        if value is _UNREADABLE:
            return False
        # `1 == True` in Python, so success constants are matched by identity
        # and type rather than by membership: `return 1` is a failure result.
        if value is None or value is True:
            return True
        if isinstance(value, int) and not isinstance(value, bool) and value == 0:
            return True
        if isinstance(value, str) and value in ("PASS", ""):
            return True
        if isinstance(value, (list, tuple, dict, set)) and not value:
            return True
        return False
    if isinstance(statement, ast.Expr):
        call = statement.value
        if (
            isinstance(call, ast.Call)
            and isinstance(call.func, ast.Attribute)
            and call.func.attr == "exit"
            and isinstance(call.func.value, ast.Name)
            and call.func.value.id == "sys"
            and len(call.args) == 1
            and literal(call.args[0]) in (0, None)
        ):
            return True
    return False


def source_segment(source_lines: list[str], node: Any) -> str:
    start = max(getattr(node, "lineno", 1) - 1, 0)
    end = getattr(node, "end_lineno", start + 1)
    return "".join(source_lines[start:end])


def import_names(tree: ast.Module) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            names.add(node.module or "")
    return names


def checker_errors(candidate: str | None, base: str | None) -> list[str]:
    errors: list[str] = []
    if candidate is None:
        return [f"{CHECKER_PATH} is missing from the candidate revision"]
    try:
        tree = ast.parse(candidate)
    except SyntaxError as exc:
        return [f"{CHECKER_PATH} does not parse: {exc.msg} (line {exc.lineno})"]
    source_lines = candidate.splitlines(keepends=True)

    # Module level must stay declarative. A top-level `sys.exit(0)` or any other
    # statement could short-circuit every evaluation below it.
    for node in tree.body:
        if isinstance(
            node,
            (
                ast.Import,
                ast.ImportFrom,
                ast.Assign,
                ast.AnnAssign,
                ast.FunctionDef,
                ast.AsyncFunctionDef,
                ast.ClassDef,
            ),
        ):
            continue
        if (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            continue
        if isinstance(node, ast.If):
            test = node.test
            if (
                isinstance(test, ast.Compare)
                and isinstance(test.left, ast.Name)
                and test.left.id == "__name__"
                and len(test.comparators) == 1
                and literal(test.comparators[0]) == "__main__"
            ):
                continue
        errors.append(
            f"{CHECKER_PATH} has a module-level statement on line "
            f"{getattr(node, 'lineno', 0)} that can short-circuit evaluation"
        )

    unexpected = sorted(import_names(tree) - ALLOWED_CHECKER_IMPORTS)
    for name in unexpected:
        errors.append(f"{CHECKER_PATH} imports `{name}`, which is not in the contract")

    constants = module_constants(tree)
    for name, expected in REQUIRED_CHECKER_CONSTANTS.items():
        if name not in constants:
            errors.append(f"{CHECKER_PATH} no longer defines `{name}`")
            continue
        value = literal(constants[name])
        if value is _UNREADABLE:
            errors.append(f"{CHECKER_PATH} computes `{name}` instead of declaring it")
            continue
        if normalized(value) != normalized(expected):
            errors.append(f"{CHECKER_PATH} changed the frozen contract value `{name}`")

    for name, expected_number in REQUIRED_CHECKER_NUMBERS.items():
        if name not in constants:
            errors.append(f"{CHECKER_PATH} no longer defines `{name}`")
            continue
        if safe_number(constants[name]) != expected_number:
            errors.append(f"{CHECKER_PATH} changed the frozen contract value `{name}`")

    base_constants: dict[str, int | None] = {}
    if base is not None:
        try:
            base_constants = {
                name: safe_number(node)
                for name, node in module_constants(ast.parse(base)).items()
            }
        except SyntaxError:
            base_constants = {}
    for name, ceiling in CHECKER_CEILINGS.items():
        if name not in constants:
            errors.append(f"{CHECKER_PATH} no longer defines `{name}`")
            continue
        value = safe_number(constants[name])
        if value is None or value <= 0:
            errors.append(f"{CHECKER_PATH} `{name}` is not a positive integer")
            continue
        if value > ceiling:
            errors.append(f"{CHECKER_PATH} `{name}` exceeds the frozen ceiling")
            continue
        base_value = base_constants.get(name)
        if base_value is not None and value > base_value:
            errors.append(f"{CHECKER_PATH} `{name}` is looser than the trusted base")

    functions = function_nodes(tree)
    for name in REQUIRED_CHECKER_FUNCTIONS:
        node = functions.get(name)
        if node is None:
            errors.append(f"{CHECKER_PATH} no longer defines `{name}()`")
            continue
        if returns_unconditional_success(node):
            errors.append(f"{CHECKER_PATH} `{name}()` was reduced to an unconditional pass")
    for name, markers in REQUIRED_FUNCTION_MARKERS.items():
        node = functions.get(name)
        if node is None:
            continue
        segment = source_segment(source_lines, node)
        for marker in markers:
            if marker not in segment:
                errors.append(
                    f"{CHECKER_PATH} `{name}()` no longer carries `{marker}`"
                )

    self_test = functions.get("run_self_test")
    if self_test is not None:
        segment = source_segment(source_lines, self_test)
        assertions = segment.count("check(")
        if assertions < MIN_SELF_TEST_CHECKS:
            errors.append(
                f"{CHECKER_PATH} self-test corpus shrank to {assertions} assertions "
                f"(minimum {MIN_SELF_TEST_CHECKS})"
            )
        for case in REQUIRED_SELF_TEST_CASES:
            if case not in segment:
                errors.append(
                    f"{CHECKER_PATH} self-test no longer covers `{case}`"
                )
    return errors


# ---------------------------------------------------------------------------
# Policy, exemptions, document
# ---------------------------------------------------------------------------


def load_json(text: str | None, path: str, errors: list[str]) -> Any:
    if text is None:
        errors.append(f"{path} is missing from the candidate revision")
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        errors.append(f"{path} is not valid JSON: {exc.msg} (line {exc.lineno})")
        return None


def contains_key(value: Any, keys: Iterable[str]) -> str | None:
    stack = [value]
    wanted = set(keys)
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            for key, item in current.items():
                if key in wanted:
                    return key
                stack.append(item)
        elif isinstance(current, list):
            stack.extend(current)
    return None


def policy_errors(candidate_text: str | None, base_text: str | None) -> list[str]:
    errors: list[str] = []
    policy = load_json(candidate_text, POLICY_PATH, errors)
    if not isinstance(policy, dict):
        if policy is not None:
            errors.append(f"{POLICY_PATH} is not a JSON object")
        return errors
    base: dict[str, Any] = {}
    if base_text is not None and base_text.strip():
        try:
            loaded = json.loads(base_text)
        except json.JSONDecodeError:
            loaded = None
        if isinstance(loaded, dict):
            base = loaded

    forbidden = contains_key(policy, REQUIRED_CHECKER_CONSTANTS["FORBIDDEN_POLICY_KEYS"])
    if forbidden is not None:
        errors.append(
            f"{POLICY_PATH} carries pull-request-controlled advisory evidence "
            f"`{forbidden}`"
        )

    if normalized(policy.get("state_machine")) != normalized(REQUIRED_STATE_MACHINE):
        errors.append(f"{POLICY_PATH} state machine differs from the frozen contract")
    if normalized(policy.get("closed_completed_reasons")) != ("completed",):
        errors.append(f"{POLICY_PATH} closed_completed_reasons is not `[completed]`")
    if normalized(policy.get("closed_other_reasons")) != ("not_planned", "duplicate", None):
        errors.append(f"{POLICY_PATH} closed_other_reasons was narrowed")
    if policy.get("in_flight_clears_blocker") is not False:
        errors.append(f"{POLICY_PATH} lets an in-flight PR clear a blocker")
    if policy.get("merged_pr_clears_blocker_before_issue_close") is not False:
        errors.append(f"{POLICY_PATH} lets a merged PR clear a blocker before close")

    tiers = policy.get("tiers")
    if not isinstance(tiers, dict) or not tiers:
        errors.append(f"{POLICY_PATH} has no tier table")
        tiers = {}
    ga = tiers.get("ga")
    ga_severities = ga.get("blocking_severities") if isinstance(ga, dict) else None
    if normalized(ga_severities) != ("critical", "high", "medium"):
        errors.append(f"{POLICY_PATH} GA tier no longer blocks every severity")
    base_tiers = base.get("tiers") if isinstance(base.get("tiers"), dict) else {}
    for tier, entry in tiers.items():
        severities = entry.get("blocking_severities") if isinstance(entry, dict) else None
        if not isinstance(severities, list) or not severities:
            errors.append(f"{POLICY_PATH} tier `{tier}` has no blocking severities")
            continue
        base_entry = base_tiers.get(tier)
        base_severities = (
            base_entry.get("blocking_severities") if isinstance(base_entry, dict) else None
        )
        if isinstance(base_severities, list) and not set(base_severities) <= set(severities):
            errors.append(
                f"{POLICY_PATH} tier `{tier}` dropped a blocking severity the "
                "trusted base enforced"
            )

    labels = policy.get("labels")
    base_labels = base.get("labels")
    if not isinstance(labels, dict):
        errors.append(f"{POLICY_PATH} has no label table")
    elif isinstance(base_labels, dict) and normalized(labels) != normalized(base_labels):
        errors.append(
            f"{POLICY_PATH} label contract differs from the trusted base; a label "
            "rename silently empties the blocker set"
        )

    advisories = policy.get("private_advisories")
    base_advisories = base.get("private_advisories")
    if not isinstance(advisories, dict):
        errors.append(f"{POLICY_PATH} has no private-advisory contract")
        advisories = {}
    if advisories.get("enabled") is not True:
        errors.append(f"{POLICY_PATH} disables the private-advisory contract")
    if advisories.get("representation") != "redacted_count_only":
        errors.append(f"{POLICY_PATH} private advisories are no longer redacted-count-only")
    blocking_states = advisories.get("blocking_states")
    if not isinstance(blocking_states, list) or not {"triage", "draft"} <= set(
        blocking_states
    ):
        errors.append(f"{POLICY_PATH} unpublished advisory states no longer block")
    never_emit = advisories.get("never_emit_fields")
    required_never_emit = set(REQUIRED_CHECKER_CONSTANTS["REQUIRED_NEVER_EMIT_FIELDS"])
    if not isinstance(never_emit, list) or not required_never_emit <= set(never_emit):
        errors.append(f"{POLICY_PATH} never_emit_fields dropped a confidential field")
    live_api = advisories.get("live_api")
    if not isinstance(live_api, dict) or live_api.get(
        "actions_security_events_permission_is_insufficient"
    ) is not True:
        errors.append(
            f"{POLICY_PATH} claims the Actions token can list private advisories"
        )
    fallback = advisories.get("trusted_fallback")
    if not isinstance(fallback, dict):
        errors.append(f"{POLICY_PATH} has no trusted advisory fallback contract")
    else:
        max_age = fallback.get("max_age_seconds")
        if not isinstance(max_age, int) or isinstance(max_age, bool) or max_age <= 0:
            errors.append(f"{POLICY_PATH} fallback max_age_seconds is not a positive int")
        else:
            if max_age > CHECKER_CEILINGS["MAX_FALLBACK_AGE_SECONDS"]:
                errors.append(
                    f"{POLICY_PATH} fallback max_age_seconds exceeds the frozen ceiling"
                )
            base_fallback = (
                base_advisories.get("trusted_fallback")
                if isinstance(base_advisories, dict)
                else None
            )
            base_age = (
                base_fallback.get("max_age_seconds")
                if isinstance(base_fallback, dict)
                else None
            )
            if isinstance(base_age, int) and not isinstance(base_age, bool):
                if max_age > base_age:
                    errors.append(
                        f"{POLICY_PATH} widened the private-advisory freshness window"
                    )
        for key in ("count_variable", "as_of_variable"):
            if not isinstance(fallback.get(key), str) or not fallback.get(key):
                errors.append(f"{POLICY_PATH} fallback `{key}` is missing")

    tracked = policy.get("tracked_blockers")
    if not isinstance(tracked, list):
        errors.append(f"{POLICY_PATH} tracked_blockers is not a list")
    else:
        seen: set[int] = set()
        for entry in tracked:
            if not isinstance(entry, dict):
                errors.append(f"{POLICY_PATH} tracked_blockers holds a non-object entry")
                continue
            issue = entry.get("issue")
            severity = entry.get("severity")
            if not isinstance(issue, int) or isinstance(issue, bool) or issue <= 0:
                errors.append(f"{POLICY_PATH} tracked blocker has no usable issue number")
                continue
            if issue in seen:
                errors.append(f"{POLICY_PATH} tracked blocker {issue} is duplicated")
            seen.add(issue)
            if severity not in SEVERITY_ORDER or severity == "low":
                errors.append(
                    f"{POLICY_PATH} tracked blocker {issue} has an unusable severity"
                )

    document = policy.get("document")
    base_document = base.get("document")
    if not isinstance(document, dict):
        errors.append(f"{POLICY_PATH} has no document contract")
    else:
        if document.get("path") != DOCUMENT_PATH:
            errors.append(f"{POLICY_PATH} document path is not {DOCUMENT_PATH}")
        for key in ("marker_begin", "marker_end", "historical_marker"):
            if not isinstance(document.get(key), str) or not document.get(key):
                errors.append(f"{POLICY_PATH} document `{key}` is missing")
        if isinstance(base_document, dict) and normalized(document) != normalized(
            base_document
        ):
            errors.append(
                f"{POLICY_PATH} document marker contract differs from the trusted base"
            )
    if policy.get("exemptions_path") != EXEMPTIONS_PATH:
        errors.append(f"{POLICY_PATH} exemptions_path is not {EXEMPTIONS_PATH}")
    return errors


EXEMPTION_REQUIRED_KEYS = (
    "id",
    "issue",
    "launch_tiers",
    "owner",
    "approver",
    "rationale",
    "compensating_control",
    "approved_at",
    "expires_at",
)


def exemption_errors(candidate_text: str | None) -> list[str]:
    errors: list[str] = []
    data = load_json(candidate_text, EXEMPTIONS_PATH, errors)
    if data is None:
        return errors
    if not isinstance(data, dict):
        return [f"{EXEMPTIONS_PATH} is not a JSON object"]
    if not isinstance(data.get("exemptions_version"), str):
        errors.append(f"{EXEMPTIONS_PATH} has no exemptions_version")
    entries = data.get("exemptions")
    if not isinstance(entries, list):
        return errors + [f"{EXEMPTIONS_PATH} exemptions is not a list"]
    identifiers: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            errors.append(f"{EXEMPTIONS_PATH} holds a non-object exemption")
            continue
        missing = [key for key in EXEMPTION_REQUIRED_KEYS if key not in entry]
        if missing:
            errors.append(
                f"{EXEMPTIONS_PATH} exemption is missing {sorted(missing)}"
            )
            continue
        identifier = entry["id"]
        if not isinstance(identifier, str) or not identifier:
            errors.append(f"{EXEMPTIONS_PATH} exemption id is not a string")
            continue
        if identifier in identifiers:
            errors.append(f"{EXEMPTIONS_PATH} exemption `{identifier}` is duplicated")
        identifiers.add(identifier)
        for key in ("approved_at", "expires_at"):
            value = entry[key]
            if not isinstance(value, str) or not ISO_Z_RE.match(value):
                errors.append(
                    f"{EXEMPTIONS_PATH} exemption `{identifier}` has a malformed {key}"
                )
        approved = entry["approved_at"]
        expires = entry["expires_at"]
        if (
            isinstance(approved, str)
            and isinstance(expires, str)
            and ISO_Z_RE.match(approved)
            and ISO_Z_RE.match(expires)
            and expires <= approved
        ):
            errors.append(
                f"{EXEMPTIONS_PATH} exemption `{identifier}` never expires after approval"
            )
        tiers = entry["launch_tiers"]
        if not isinstance(tiers, list) or not tiers or not all(
            isinstance(tier, str) and tier for tier in tiers
        ):
            errors.append(
                f"{EXEMPTIONS_PATH} exemption `{identifier}` has no launch tiers"
            )
    return errors


def document_errors(candidate_text: str | None, policy_text: str | None) -> list[str]:
    errors: list[str] = []
    if candidate_text is None:
        return [f"{DOCUMENT_PATH} is missing from the candidate revision"]
    markers = {
        "marker_begin": "<!-- launch-readiness:begin -->",
        "marker_end": "<!-- launch-readiness:end -->",
        "historical_marker": "<!-- launch-readiness:historical -->",
    }
    if policy_text is not None:
        try:
            policy = json.loads(policy_text)
        except json.JSONDecodeError:
            policy = None
        if isinstance(policy, dict) and isinstance(policy.get("document"), dict):
            for key in markers:
                value = policy["document"].get(key)
                if isinstance(value, str) and value:
                    markers[key] = value
    positions: dict[str, int] = {}
    for key, marker in markers.items():
        occurrences = candidate_text.count(marker)
        if occurrences != 1:
            errors.append(
                f"{DOCUMENT_PATH} must contain exactly one `{key}` marker "
                f"(found {occurrences})"
            )
            continue
        positions[key] = candidate_text.index(marker)
    if {"marker_begin", "marker_end"} <= positions.keys():
        if positions["marker_begin"] >= positions["marker_end"]:
            errors.append(f"{DOCUMENT_PATH} snapshot markers are out of order")
    return errors


# ---------------------------------------------------------------------------
# Workflow contracts
# ---------------------------------------------------------------------------


def readiness_workflow_errors(workflows: dict[str, str]) -> list[str]:
    errors: list[str] = []
    workflow = workflows.get("launch-readiness.yml")
    if workflow is None:
        return [f"{READINESS_WORKFLOW} is missing from the candidate revision"]
    events = declared_events(workflow)
    for event in READINESS_REQUIRED_EVENTS:
        if event not in events:
            errors.append(f"{READINESS_WORKFLOW} no longer runs on `{event}`")
    push = event_body(workflow, "push")
    if push is None or "main" not in push or 'v*' not in push:
        errors.append(f"{READINESS_WORKFLOW} push trigger lost `main` or `v*` coverage")
    for event in ("pull_request", "merge_group"):
        body = event_body(workflow, event)
        if body is not None and re.search(r"(?m)^    paths(?:-ignore)?:", body):
            errors.append(f"{READINESS_WORKFLOW} path-filtered its `{event}` trigger")
    lines = stripped_lines(workflow)
    for frozen in READINESS_FROZEN_LINES:
        if frozen not in lines:
            errors.append(f"{READINESS_WORKFLOW} no longer carries `{frozen}`")
    jobs = job_blocks(workflow)
    block = jobs.get(READINESS_JOB)
    if block is None:
        errors.append(f"{READINESS_WORKFLOW} no longer defines jobs.{READINESS_JOB}")
    else:
        if job_display_name(READINESS_JOB, block) != READINESS_JOB_NAME:
            errors.append(
                f"{READINESS_WORKFLOW} jobs.{READINESS_JOB} must keep check name "
                f"`{READINESS_JOB_NAME}`"
            )
        if re.search(r"(?m)^\s+contents:\s+write\s*$", block):
            errors.append(f"{READINESS_WORKFLOW} grants contents: write")
    if re.search(r"(?m)^\s+(?:contents|packages|id-token|actions):\s+write\s*$", workflow):
        errors.append(f"{READINESS_WORKFLOW} grants a write permission")
    return errors


def release_workflow_errors(workflows: dict[str, str]) -> list[str]:
    errors: list[str] = []
    workflow = workflows.get("release.yml")
    if workflow is None:
        return [f"{RELEASE_WORKFLOW} is missing from the candidate revision"]
    jobs = job_blocks(workflow)
    gate = jobs.get(RELEASE_GATE_JOB)
    if gate is None:
        return errors + [
            f"{RELEASE_WORKFLOW} no longer defines jobs.{RELEASE_GATE_JOB}"
        ]
    gate_lines = stripped_lines(gate)
    for frozen in RELEASE_FROZEN_LINES:
        if frozen not in gate_lines:
            errors.append(
                f"{RELEASE_WORKFLOW} jobs.{RELEASE_GATE_JOB} no longer runs `{frozen}`"
            )
    # Every publishing job must remain downstream of the go/no-go gate.
    graph = {job: job_needs(block) for job, block in jobs.items()}
    reachable: set[str] = set()
    changed = True
    while changed:
        changed = False
        for job, needs in graph.items():
            if job in reachable:
                continue
            if RELEASE_GATE_JOB in needs or needs & reachable:
                reachable.add(job)
                changed = True
    exempt = {RELEASE_GATE_JOB, *graph.get(RELEASE_GATE_JOB, set())}
    for job in sorted(set(graph) - exempt - reachable):
        errors.append(
            f"{RELEASE_WORKFLOW} jobs.{job} is not downstream of "
            f"`{RELEASE_GATE_JOB}`"
        )
    return errors


def integrity_workflow_errors(workflows: dict[str, str]) -> list[str]:
    errors: list[str] = []
    workflow = workflows.get("launch-integrity.yml")
    if workflow is None:
        return [f"{INTEGRITY_WORKFLOW} is missing from the candidate revision"]
    events = declared_events(workflow)
    for event in INTEGRITY_REQUIRED_EVENTS:
        if event not in events:
            errors.append(f"{INTEGRITY_WORKFLOW} no longer runs on `{event}`")
    for event in INTEGRITY_REQUIRED_EVENTS:
        body = event_body(workflow, event)
        if body is not None and re.search(r"(?m)^    paths(?:-ignore)?:", body):
            errors.append(f"{INTEGRITY_WORKFLOW} path-filtered its `{event}` trigger")
    if ADVISORY_SECRET in workflow or "secrets." in workflow:
        errors.append(f"{INTEGRITY_WORKFLOW} must never consume a repository secret")
    if re.search(r"(?m)^\s+(?:contents|packages|id-token|actions):\s+write\s*$", workflow):
        errors.append(f"{INTEGRITY_WORKFLOW} grants a write permission")
    if "persist-credentials: false" not in workflow:
        errors.append(f"{INTEGRITY_WORKFLOW} must keep persist-credentials disabled")
    if "merge_group base_sha missing or malformed" not in workflow:
        errors.append(
            f"{INTEGRITY_WORKFLOW} must fail closed on a malformed merge_group base"
        )
    return errors


def check_run_identity_errors(workflows: dict[str, str]) -> list[str]:
    """A required check name must be produced by exactly one known workflow."""

    errors: list[str] = []
    owners: dict[str, list[str]] = {name: [] for name in CHECK_RUN_OWNERS}
    for filename, workflow in sorted(workflows.items()):
        for job_id, block in job_blocks(workflow).items():
            display = job_display_name(job_id, block)
            if display in owners:
                owners[display].append(filename)
    for name, expected in CHECK_RUN_OWNERS.items():
        found = owners[name]
        if found != [expected]:
            errors.append(
                f"required check `{name}` must be produced only by {expected} "
                f"(found {found or 'no producer'})"
            )
        # Block-mapping job parsing can be evaded with flow syntax, so the
        # comment-stripped text is checked too: a required check name may not
        # appear in any other workflow file's live YAML at all.
        for filename, workflow in sorted(workflows.items()):
            if filename != expected and name in non_comment_text(workflow):
                errors.append(
                    f".github/workflows/{filename} must not mention the required "
                    f"check name `{name}`"
                )
    return errors


def secret_exposure_errors(workflows: dict[str, str]) -> list[str]:
    errors: list[str] = []
    allowed = {"launch-readiness.yml", "release.yml"}
    for filename, workflow in sorted(workflows.items()):
        if ADVISORY_SECRET not in workflow:
            continue
        if filename not in allowed:
            errors.append(
                f".github/workflows/{filename} must not reference the advisory token"
            )
            continue
        if filename == "launch-readiness.yml":
            continue
        events = declared_events(workflow)
        exposed = sorted(events & set(CANDIDATE_TRIGGERED_EVENTS))
        if exposed:
            errors.append(
                f".github/workflows/{filename} exposes the advisory token to "
                f"candidate-triggered events {exposed}"
            )
    return errors


# ---------------------------------------------------------------------------
# Anchor, presence, ownership
# ---------------------------------------------------------------------------


def presence_errors(candidate: Root) -> list[str]:
    errors: list[str] = []
    for path in PROTECTED_PATHS:
        if path not in candidate.tree:
            errors.append(f"protected gate file {path} was deleted or renamed")
    for slot, path in FILE_SLOTS.items():
        text = candidate.text(slot)
        if path in candidate.tree and (text is None or not text.strip()):
            errors.append(f"protected gate file {path} is empty or unreadable")
    return errors


def anchor_errors(candidate: Root, base: Root) -> list[str]:
    errors: list[str] = []
    pairs = (
        (VERIFIER_PATH, candidate.text("verifier"), base.text("verifier")),
        (
            INTEGRITY_WORKFLOW,
            candidate.workflows.get("launch-integrity.yml"),
            base.workflows.get("launch-integrity.yml"),
        ),
    )
    for path, candidate_text, base_text in pairs:
        if base_text is None:
            # Adoption: the trusted base does not carry this anchor yet, so
            # there is no protected content to preserve. Once the base has it,
            # neither deletion nor modification is accepted below. The workflow
            # cannot even load a verifier in this state, so this branch is only
            # reachable on the one-time adoption commit.
            continue
        if candidate_text is None:
            errors.append(f"the integrity anchor {path} was deleted")
            continue
        if candidate_text != base_text:
            errors.append(
                f"the integrity anchor {path} cannot be changed by a pull request"
            )
    return errors


def codeowners_map(text: str | None) -> dict[str, set[str]]:
    owners: dict[str, set[str]] = {}
    if text is None:
        return owners
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        owners[parts[0]] = {part for part in parts[1:] if part.startswith("@")}
    return owners


def codeowners_errors(candidate_text: str | None, base_text: str | None) -> list[str]:
    errors: list[str] = []
    if candidate_text is None:
        return [f"{CODEOWNERS_PATH} is missing from the candidate revision"]
    candidate = codeowners_map(candidate_text)
    base = codeowners_map(base_text)
    for path in CODEOWNERS_GOVERNED_PATHS:
        assigned = candidate.get(path, set())
        if not assigned:
            errors.append(f"{CODEOWNERS_PATH} no longer assigns an owner to {path}")
            continue
        expected = base.get(path, set())
        if expected and not expected <= assigned:
            errors.append(
                f"{CODEOWNERS_PATH} removed a trusted-base owner from {path}"
            )
    return errors


# ---------------------------------------------------------------------------
# Verification entry point
# ---------------------------------------------------------------------------


def verify(base: Root, candidate: Root) -> list[str]:
    errors: list[str] = []
    errors.extend(presence_errors(candidate))
    errors.extend(anchor_errors(candidate, base))
    errors.extend(checker_errors(candidate.text("checker"), base.text("checker")))
    errors.extend(policy_errors(candidate.text("policy"), base.text("policy")))
    errors.extend(exemption_errors(candidate.text("exemptions")))
    errors.extend(document_errors(candidate.text("document"), candidate.text("policy")))
    errors.extend(readiness_workflow_errors(candidate.workflows))
    errors.extend(integrity_workflow_errors(candidate.workflows))
    errors.extend(release_workflow_errors(candidate.workflows))
    errors.extend(check_run_identity_errors(candidate.workflows))
    errors.extend(secret_exposure_errors(candidate.workflows))
    errors.extend(
        codeowners_errors(candidate.text("codeowners"), base.text("codeowners"))
    )
    return list(dict.fromkeys(errors))


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------


def _fixture_checker() -> str:
    """A synthetic checker that satisfies the frozen source contract."""

    constants = [
        "SEVERITIES = ('critical', 'high', 'medium')",
        "VERDICTS = ('PASS', 'FAIL', 'UNKNOWN')",
        "ADVISORY_STATES = ('triage', 'draft', 'published', 'closed', 'withdrawn')",
        "ADVISORY_SEVERITIES = ('critical', 'high', 'medium', 'low')",
        f"REQUIRED_STATE_MACHINE = {REQUIRED_STATE_MACHINE!r}",
        "BELOW_TIER = 'below_tier'",
        "REQUIRED_CLOSED_COMPLETED_REASONS = ('completed',)",
        "REQUIRED_CLOSED_OTHER_REASONS = ('not_planned', 'duplicate', None)",
        "REQUIRED_NEVER_EMIT_FIELDS = "
        + repr(REQUIRED_CHECKER_CONSTANTS["REQUIRED_NEVER_EMIT_FIELDS"]),
        "BANNED_OUTPUT_TOKENS = "
        + repr(REQUIRED_CHECKER_CONSTANTS["BANNED_OUTPUT_TOKENS"]),
        "FORBIDDEN_POLICY_KEYS = "
        + repr(REQUIRED_CHECKER_CONSTANTS["FORBIDDEN_POLICY_KEYS"]),
        "MAX_RESPONSE_BYTES = 1 << 20",
        "PER_PAGE = 100",
        "API_ORIGIN = 'https://api.github.com/'",
        "MAX_FALLBACK_AGE_SECONDS = 30 * 24 * 60 * 60",
        "MAX_FALLBACK_COUNT = 100000",
        "MAX_PAGES = 50",
    ]
    bodies = {
        "compute_verdict": [
            "    if unknown_reasons:",
            '        return "UNKNOWN"',
            "    if records:",
            '        return "FAIL"',
            '    return "PASS"',
        ],
        "verify_errors": [
            "    errors = []",
            '    if evaluation.verdict != "PASS":',
            '        errors.append("fail closed")',
            "    return errors",
        ],
        "verify_exit_code": [
            "    return 1 if verify_errors(claim, evaluation) else 0",
        ],
        "run_verify": [
            "    errors = verify_errors(claim, evaluation)",
            "    return 1 if errors else 0",
        ],
        "main": [
            "    if argv:",
            "        return run_self_test()",
            "    if not argv:",
            "        return run_verify(argv)",
            "    return 1",
        ],
        "resolve_trusted_fallback": [
            "    if not policy:",
            "        raise GateError('private_fallback', 'missing')",
            "    limit = policy['max_age_seconds']",
            "    return limit",
        ],
        "resolve_private_blockers": [
            "    token_env = policy['token_env']",
            "    if not token_env:",
            "        return resolve_trusted_fallback(policy)",
            "    return 0",
        ],
    }
    lines = ['"""Synthetic launch checker fixture."""', "", "import json", "import re", ""]
    lines.extend(constants)
    lines.append("")
    lines.append("class GateError(Exception):")
    lines.append("    pass")
    lines.append("")
    for name in REQUIRED_CHECKER_FUNCTIONS:
        if name == "run_self_test":
            continue
        lines.append(f"def {name}(*args, **kwargs):")
        body = bodies.get(name)
        if body is None:
            lines.append("    if args:")
            lines.append("        return list(args)")
            lines.append("    return kwargs")
        else:
            lines.extend(body)
        lines.append("")
    lines.append("def run_self_test():")
    lines.append("    failures = []")
    lines.append("    def check(name, cond):")
    lines.append("        if not cond:")
    lines.append("            failures.append(name)")
    for index, case in enumerate(REQUIRED_SELF_TEST_CASES):
        lines.append(f'    check("{case}", {index} >= 0)')
    for index in range(MIN_SELF_TEST_CHECKS + 4 - len(REQUIRED_SELF_TEST_CASES)):
        lines.append(f'    check("fixture case {index}", True)')
    lines.append("    if failures:")
    lines.append("        return 1")
    lines.append("    return 0")
    lines.append("")
    lines.append('if __name__ == "__main__":')
    lines.append("    raise SystemExit(main())")
    return "\n".join(lines) + "\n"


_FIXTURE_POLICY = {
    "policy_version": "2",
    "classification_version": "launch-blocker-v2",
    "repository": "ferrum-edge/ferrum-edge",
    "default_launch_tier": "ga",
    "labels": {
        "launch_blocker": "launch-blocker",
        "launch_exempted": "launch-exempted",
        "severity": {
            "critical": "severity:critical",
            "high": "severity:high",
            "medium": "severity:medium",
        },
    },
    "tiers": {
        "ga": {"blocking_severities": ["critical", "high", "medium"]},
        "beta": {"blocking_severities": ["critical", "high"]},
        "experimental": {"blocking_severities": ["critical"]},
    },
    "state_machine": dict(REQUIRED_STATE_MACHINE),
    "closed_completed_reasons": ["completed"],
    "closed_other_reasons": ["not_planned", "duplicate", None],
    "in_flight_clears_blocker": False,
    "merged_pr_clears_blocker_before_issue_close": False,
    "tracked_blockers": [{"issue": 4242, "severity": "high", "note": "fixture"}],
    "private_advisories": {
        "enabled": True,
        "blocking_states": ["triage", "draft"],
        "closed_states": ["published", "closed", "withdrawn"],
        "blocking_severities_by_tier": {
            "ga": ["critical", "high", "medium"],
            "beta": ["critical", "high"],
            "experimental": ["critical"],
        },
        "representation": "redacted_count_only",
        "never_emit_fields": list(
            REQUIRED_CHECKER_CONSTANTS["REQUIRED_NEVER_EMIT_FIELDS"]
        ),
        "live_api": {
            "token_env": "LAUNCH_ADVISORY_READ_TOKEN",
            "actions_security_events_permission_is_insufficient": True,
        },
        "trusted_fallback": {
            "count_variable": "LAUNCH_PRIVATE_BLOCKER_COUNT",
            "as_of_variable": "LAUNCH_PRIVATE_ADVISORY_AS_OF",
            "max_age_seconds": 604800,
        },
    },
    "document": {
        "path": DOCUMENT_PATH,
        "marker_begin": "<!-- launch-readiness:begin -->",
        "marker_end": "<!-- launch-readiness:end -->",
        "historical_marker": "<!-- launch-readiness:historical -->",
    },
    "exemptions_path": EXEMPTIONS_PATH,
}

_FIXTURE_DOCUMENT = (
    "# Fixture ledger\n\n"
    "<!-- launch-readiness:begin -->\n"
    '```json\n{"verdict": "FAIL"}\n```\n'
    "<!-- launch-readiness:end -->\n\n"
    "<!-- launch-readiness:historical -->\n"
)

_FIXTURE_CODEOWNERS = "\n".join(
    f"{path}   @owner" for path in CODEOWNERS_GOVERNED_PATHS
) + "\n"

_FIXTURE_READINESS_WORKFLOW = """name: Launch Readiness

on:
  pull_request:
  merge_group:
  push:
    branches:
      - main
    tags:
      - "v*"
  schedule:
    - cron: "15 6 * * *"
  workflow_dispatch:

permissions:
  contents: read

jobs:
  launch-readiness:
    name: Launch Readiness Gate
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@0000000000000000000000000000000000000000
        with:
          persist-credentials: false
          ref: ${{ github.event_name == 'pull_request' && github.event.pull_request.head.sha || github.event_name == 'merge_group' && github.event.merge_group.head_sha || github.sha }}

      - name: Synthetic policy/checker self-tests
        run: python3 -I scripts/check_launch_readiness.py --self-test

      - name: Verify live launch verdict
        env:
          LAUNCH_TARGET_SHA: ${{ github.event_name == 'pull_request' && github.event.pull_request.head.sha || github.event_name == 'merge_group' && github.event.merge_group.head_sha || github.sha }}
          LAUNCH_ADVISORY_READ_TOKEN: ${{ (github.event_name != 'pull_request' && github.event_name != 'merge_group') && secrets.LAUNCH_ADVISORY_READ_TOKEN || '' }}
        run: python3 -I scripts/check_launch_readiness.py --verify --verify-checkout
"""

_FIXTURE_INTEGRITY_WORKFLOW = """name: Launch Readiness Integrity

on:
  pull_request_target:
    branches:
      - main
  merge_group:
    types:
      - checks_requested

permissions:
  contents: read

jobs:
  verify:
    name: Launch Readiness Integrity
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@0000000000000000000000000000000000000000
        with:
          persist-credentials: false

      - name: Enforce the launch governance contract
        run: |
          echo "merge_group base_sha missing or malformed" > /dev/null
"""

_FIXTURE_RELEASE_WORKFLOW = """name: Release

on:
  push:
    tags:
      - 'v*'

jobs:
  validate-release-version:
    name: Validate release version
    runs-on: ubuntu-latest
    steps:
      - run: echo version

  validate-launch-readiness:
    name: Validate launch readiness
    needs: validate-release-version
    runs-on: ubuntu-latest
    steps:
      - name: Synthetic policy/checker self-tests
        run: python3 -I scripts/check_launch_readiness.py --self-test

      - name: Require live launch PASS for the exact tag commit
        run: python3 -I scripts/check_launch_readiness.py --verify --require-pass

  validate-release-sha:
    name: Validate release SHA
    needs:
      - validate-release-version
      - validate-launch-readiness
    runs-on: ubuntu-latest
    steps:
      - run: echo sha

  publish:
    name: Publish
    needs: validate-release-sha
    runs-on: ubuntu-latest
    steps:
      - run: echo publish
"""


def _write_root(directory: Path, files: dict[str, str], workflows: dict[str, str]) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "workflows").mkdir(exist_ok=True)
    for name, text in files.items():
        (directory / name).write_text(text, encoding="utf-8")
    for name, text in workflows.items():
        (directory / "workflows" / name).write_text(text, encoding="utf-8")
    tree = list(PROTECTED_PATHS) + [
        f".github/workflows/{name}" for name in workflows
    ]
    (directory / "tree.txt").write_text("\n".join(sorted(set(tree))) + "\n", "utf-8")


def _fixture_files(verifier_text: str) -> dict[str, str]:
    return {
        SLOT_FILENAMES["checker"]: _fixture_checker(),
        SLOT_FILENAMES["verifier"]: verifier_text,
        SLOT_FILENAMES["policy"]: json.dumps(_FIXTURE_POLICY, indent=2) + "\n",
        SLOT_FILENAMES["exemptions"]: json.dumps(
            {"exemptions_version": "1", "exemptions": []}, indent=2
        )
        + "\n",
        SLOT_FILENAMES["document"]: _FIXTURE_DOCUMENT,
        SLOT_FILENAMES["codeowners"]: _FIXTURE_CODEOWNERS,
    }


def _fixture_workflows() -> dict[str, str]:
    return {
        "launch-readiness.yml": _FIXTURE_READINESS_WORKFLOW,
        "launch-integrity.yml": _FIXTURE_INTEGRITY_WORKFLOW,
        "release.yml": _FIXTURE_RELEASE_WORKFLOW,
    }


def run_self_test() -> int:
    """Adversarial fixtures for every weakening this check must refuse."""

    failures: list[str] = []
    verifier_text = "# trusted anchor fixture\n"

    def evaluate(
        mutate_files: Any = None,
        mutate_workflows: Any = None,
    ) -> list[str]:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base_files = _fixture_files(verifier_text)
            base_workflows = _fixture_workflows()
            _write_root(root / "base", base_files, base_workflows)
            files = _fixture_files(verifier_text)
            workflows = _fixture_workflows()
            if mutate_files is not None:
                mutate_files(files)
            if mutate_workflows is not None:
                mutate_workflows(workflows)
            _write_root(root / "candidate", files, workflows)
            return verify(Root("base", root / "base"), Root("candidate", root / "candidate"))

    def expect_clean(name: str, errors: list[str]) -> None:
        if errors:
            failures.append(f"{name}: expected no findings, got {errors}")

    def expect_rejected(name: str, errors: list[str]) -> None:
        if not errors:
            failures.append(f"{name}: expected a finding, got none")

    expect_clean("pristine candidate", evaluate())

    # 1. Checker deletion.
    def delete_checker(files: dict[str, str]) -> None:
        files.pop(SLOT_FILENAMES["checker"])

    expect_rejected("checker deleted", evaluate(delete_checker))

    # 2. Unconditional PASS rewrites.
    def always_pass(files: dict[str, str]) -> None:
        files[SLOT_FILENAMES["checker"]] = files[SLOT_FILENAMES["checker"]].replace(
            "def compute_verdict(*args, **kwargs):\n"
            "    if unknown_reasons:\n"
            '        return "UNKNOWN"\n'
            "    if records:\n"
            '        return "FAIL"\n'
            '    return "PASS"\n',
            'def compute_verdict(*args, **kwargs):\n    return "PASS"\n',
        )

    expect_rejected("compute_verdict always PASS", evaluate(always_pass))

    def exit_zero(files: dict[str, str]) -> None:
        files[SLOT_FILENAMES["checker"]] = files[SLOT_FILENAMES["checker"]].replace(
            "def main(*args, **kwargs):", "def main(*args, **kwargs):\n    return 0\n\ndef _unused(*args, **kwargs):"
        )

    expect_rejected("main returns zero unconditionally", evaluate(exit_zero))

    def top_level_exit(files: dict[str, str]) -> None:
        files[SLOT_FILENAMES["checker"]] = (
            "import sys\nsys.exit(0)\n" + files[SLOT_FILENAMES["checker"]]
        )

    expect_rejected("module-level short circuit", evaluate(top_level_exit))

    def new_import(files: dict[str, str]) -> None:
        files[SLOT_FILENAMES["checker"]] = (
            "import subprocess\n" + files[SLOT_FILENAMES["checker"]]
        )

    expect_rejected("checker grows a process dependency", evaluate(new_import))

    # 3. Candidate self-test rewriting.
    def gut_self_test(files: dict[str, str]) -> None:
        source = files[SLOT_FILENAMES["checker"]]
        head, _, _ = source.partition("def run_self_test():")
        files[SLOT_FILENAMES["checker"]] = (
            head
            + "def run_self_test():\n    failures = []\n    if failures:\n"
            "        return 1\n    return 0\n\n"
            'if __name__ == "__main__":\n    raise SystemExit(main())\n'
        )

    expect_rejected("self-test corpus emptied", evaluate(gut_self_test))

    def drop_one_case(files: dict[str, str]) -> None:
        files[SLOT_FILENAMES["checker"]] = files[SLOT_FILENAMES["checker"]].replace(
            '    check("fresh external positive fails", 18 >= 0)\n',
            '    check("fixture replacement", True)\n',
        )

    expect_rejected("adversarial fixture removed", evaluate(drop_one_case))

    # 4. Policy downgrades.
    def state_machine_downgrade(files: dict[str, str]) -> None:
        policy = json.loads(files[SLOT_FILENAMES["policy"]])
        policy["state_machine"]["in_flight"] = "cleared"
        files[SLOT_FILENAMES["policy"]] = json.dumps(policy, indent=2)

    expect_rejected("state machine downgraded", evaluate(state_machine_downgrade))

    def tier_downgrade(files: dict[str, str]) -> None:
        policy = json.loads(files[SLOT_FILENAMES["policy"]])
        policy["tiers"]["ga"]["blocking_severities"] = ["critical"]
        files[SLOT_FILENAMES["policy"]] = json.dumps(policy, indent=2)

    expect_rejected("GA severity tier narrowed", evaluate(tier_downgrade))

    def stale_window(files: dict[str, str]) -> None:
        policy = json.loads(files[SLOT_FILENAMES["policy"]])
        policy["private_advisories"]["trusted_fallback"]["max_age_seconds"] = 604801
        files[SLOT_FILENAMES["policy"]] = json.dumps(policy, indent=2)

    expect_rejected("advisory freshness widened", evaluate(stale_window))

    def checked_in_count(files: dict[str, str]) -> None:
        policy = json.loads(files[SLOT_FILENAMES["policy"]])
        policy["private_advisories"]["opaque_input"] = {"redacted_blocking_count": 0}
        files[SLOT_FILENAMES["policy"]] = json.dumps(policy, indent=2)

    expect_rejected("checked-in advisory evidence", evaluate(checked_in_count))

    def label_rename(files: dict[str, str]) -> None:
        policy = json.loads(files[SLOT_FILENAMES["policy"]])
        policy["labels"]["launch_blocker"] = "launch-blocker-unused"
        files[SLOT_FILENAMES["policy"]] = json.dumps(policy, indent=2)

    expect_rejected("blocker label renamed", evaluate(label_rename))

    def never_emit_narrowed(files: dict[str, str]) -> None:
        policy = json.loads(files[SLOT_FILENAMES["policy"]])
        policy["private_advisories"]["never_emit_fields"] = ["summary"]
        files[SLOT_FILENAMES["policy"]] = json.dumps(policy, indent=2)

    expect_rejected("never_emit narrowed", evaluate(never_emit_narrowed))

    def open_ended_exemption(files: dict[str, str]) -> None:
        files[SLOT_FILENAMES["exemptions"]] = json.dumps(
            {
                "exemptions_version": "1",
                "exemptions": [
                    {
                        "id": "ex-1",
                        "issue": 1,
                        "launch_tiers": ["ga"],
                        "owner": "o",
                        "approver": "a",
                        "rationale": "r",
                        "compensating_control": "c",
                        "approved_at": "2026-08-01T00:00:00Z",
                        "expires_at": "2026-08-01T00:00:00Z",
                    }
                ],
            },
            indent=2,
        )

    expect_rejected("exemption never expires", evaluate(open_ended_exemption))

    def marker_removed(files: dict[str, str]) -> None:
        files[SLOT_FILENAMES["document"]] = files[SLOT_FILENAMES["document"]].replace(
            "<!-- launch-readiness:historical -->\n", ""
        )

    expect_rejected("document marker removed", evaluate(marker_removed))

    # 5. Workflow bypass.
    def remove_gate_workflow(workflows: dict[str, str]) -> None:
        workflows.pop("launch-readiness.yml")

    expect_rejected("gate workflow deleted", evaluate(None, remove_gate_workflow))

    def drop_verify_step(workflows: dict[str, str]) -> None:
        workflows["launch-readiness.yml"] = workflows["launch-readiness.yml"].replace(
            "        run: python3 -I scripts/check_launch_readiness.py "
            "--verify --verify-checkout\n",
            "        run: echo skipped\n",
        )

    expect_rejected("live verdict step removed", evaluate(None, drop_verify_step))

    def leak_secret(workflows: dict[str, str]) -> None:
        workflows["launch-readiness.yml"] = workflows["launch-readiness.yml"].replace(
            "LAUNCH_ADVISORY_READ_TOKEN: ${{ (github.event_name != 'pull_request'"
            " && github.event_name != 'merge_group') && "
            "secrets.LAUNCH_ADVISORY_READ_TOKEN || '' }}",
            "LAUNCH_ADVISORY_READ_TOKEN: ${{ secrets.LAUNCH_ADVISORY_READ_TOKEN }}",
        )

    expect_rejected("advisory token exposed to candidates", evaluate(None, leak_secret))

    def rename_gate_job(workflows: dict[str, str]) -> None:
        workflows["launch-readiness.yml"] = workflows["launch-readiness.yml"].replace(
            "    name: Launch Readiness Gate", "    name: Launch Readiness Advisory"
        )

    expect_rejected("required check renamed", evaluate(None, rename_gate_job))

    def duplicate_check_name(workflows: dict[str, str]) -> None:
        workflows["shadow.yml"] = (
            "name: Shadow\n\non:\n  pull_request:\n\njobs:\n"
            "  shadow:\n    name: Launch Readiness Integrity\n"
            "    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n"
        )

    expect_rejected("check-run producer spoofed", evaluate(None, duplicate_check_name))

    def sever_release_needs(workflows: dict[str, str]) -> None:
        workflows["release.yml"] = workflows["release.yml"].replace(
            "    needs:\n      - validate-release-version\n"
            "      - validate-launch-readiness\n",
            "    needs: validate-release-version\n",
        )

    expect_rejected("release gate unbound", evaluate(None, sever_release_needs))

    def weaken_integrity_workflow(workflows: dict[str, str]) -> None:
        workflows["launch-integrity.yml"] = workflows["launch-integrity.yml"].replace(
            "  pull_request_target:\n    branches:\n      - main\n",
            "  pull_request_target:\n    paths:\n      - docs/**\n",
        )

    expect_rejected("integrity anchor edited", evaluate(None, weaken_integrity_workflow))

    # 6. Ownership evasion.
    def drop_owner(files: dict[str, str]) -> None:
        files[SLOT_FILENAMES["codeowners"]] = "\n".join(
            line
            for line in files[SLOT_FILENAMES["codeowners"]].splitlines()
            if not line.startswith("/scripts/check_launch_readiness.py")
        ) + "\n"

    expect_rejected("governance owner removed", evaluate(drop_owner))

    for failure in failures:
        print(f"self-test failure: {failure}", file=sys.stderr)
    if failures:
        return 1
    print("launch-integrity self-test: PASS")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Launch readiness integrity verifier")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--base-dir", default="")
    parser.add_argument("--candidate-dir", default="")
    args = parser.parse_args(argv)

    if args.self_test:
        code = run_self_test()
        if code != 0:
            return code
    if not args.base_dir and not args.candidate_dir:
        if args.self_test:
            return 0
        print("error: --base-dir and --candidate-dir are required", file=sys.stderr)
        return 2
    if not args.base_dir or not args.candidate_dir:
        print("error: both --base-dir and --candidate-dir are required", file=sys.stderr)
        return 2

    try:
        base = Root("trusted base", Path(args.base_dir))
        candidate = Root("candidate", Path(args.candidate_dir))
        errors = verify(base, candidate)
    except IntegrityError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    for error in errors:
        print(f"::error::launch integrity: {error}", file=sys.stderr)
    if errors:
        print(f"launch integrity: {len(errors)} finding(s)", file=sys.stderr)
        return 1
    print("launch integrity: the candidate preserves the launch governance contract")
    return 0


if __name__ == "__main__":
    sys.exit(main())
