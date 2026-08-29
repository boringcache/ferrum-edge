#!/usr/bin/env python3
"""Publish-blocking required-check contract (issue #4302).

`.github/required-publication-checks.json` is the ONE canonical, machine-consumed
inventory of the repository-required product checks that must be successful, for
the exact product SHA, under trusted workflow identity, before anything is
published: the mutable `latest` GitHub prerelease, the mutable `latest` /
`main-<sha>` Docker tags, and the immutable version-tag release artifacts.

This module is the only consumer of that inventory. It provides two things:

* a STATIC contract (`contract_errors`) that proves, by construction, that the
  branch-protection required set, ci.yml's frozen `main-publish-gate` polling
  array, the `main-publication-required-checks` job, and release.yml's
  `validate-release-sha` step are set-equal to the inventory. Adding a required
  context without publication coverage makes that contract fail, which is what
  `.github/scripts/verify_required_ci.py` runs on every pull request.
* a RUNTIME gate (`enforce`) that both publication paths execute. It resolves
  each required workflow by its canonical file, workflow id, path, and name, and
  then requires EVERY matching run to have completed successfully for the exact
  SHA under the expected event and branch. Each polling sweep re-evaluates the
  complete selected set; a success observed while another context is still
  pending is never cached, and the permitting sweep revalidates workflow
  identity before returning. Missing, queued, in-progress, waiting, failed,
  cancelled, skipped, timed-out, stale, neutral, and unknown results are all
  blocking, as are wrong-SHA, wrong-event, wrong-branch, wrong-path,
  wrong-workflow-id, and fork/untrusted runs. A display name alone is never an
  identity.

Why publication cannot simply be one gate: ci.yml's `main-publish-gate` job and
the `needs`/`if` of `latest-release`, `docker`, and `docker-manifest` are frozen
byte-for-byte by `.github/scripts/verify_cross_build_policy.py`, a protected
trusted-policy file no pull request may modify. The frozen array therefore keeps
carrying three of the eight contexts, and the remaining ones are carried by the
`main-publication-required-checks` job hosted in `gateway-api-conformance.yml` --
a workflow whose RUN CONCLUSION the frozen array already requires to be
successful for the exact SHA. The static contract above is what proves the two
halves partition the inventory exactly, with no drift and no independent
hard-coded subset.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

INVENTORY_PATH = ".github/required-publication-checks.json"
CI_WORKFLOW_PATH = ".github/workflows/ci.yml"
PUBLICATION_GATE_WORKFLOW_PATH = ".github/workflows/gateway-api-conformance.yml"
PUBLICATION_GATE_JOB = "main-publication-required-checks"
RELEASE_WORKFLOW_PATH = ".github/workflows/release.yml"
RELEASE_GATE_JOB = "validate-release-sha"
CHECKOUT_USES = (
    "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
)

# Direct fields of the hosted publication gate. Comments are ignored; extra,
# missing, duplicate, reordered, flow-spelled, or opaque fields fail closed.
# The unique job itself is proven over the whole `jobs:` mapping: quoted,
# escaped, or opaque YAML-equivalent duplicates of the protected key fail.
PUBLICATION_GATE_FIELDS = (
    "name",
    "if",
    "runs-on",
    "timeout-minutes",
    "permissions",
    "steps",
)
PUBLICATION_GATE_NAME = "Main Publication Required Checks"
PUBLICATION_GATE_IF = (
    "github.event_name == 'push' && github.ref == 'refs/heads/main'"
)
PUBLICATION_GATE_RUNS_ON = "ubuntu-latest"
PUBLICATION_GATE_TIMEOUT = "110"
PUBLICATION_GATE_PERMISSIONS = (("contents", "read"), ("actions", "read"))
PUBLICATION_GATE_STEP_NAME = (
    "Prove every publish-blocking required check passed for this SHA"
)
PUBLICATION_GATE_CHECKOUT_FIELDS = ("uses",)
PUBLICATION_GATE_PROOF_FIELDS = ("name", "env", "run")
PUBLICATION_GATE_ENV = (
    ("GH_TOKEN", "${{ secrets.GITHUB_TOKEN }}"),
    ("PUBLICATION_GATE_REPOSITORY", "${{ github.repository }}"),
    ("PUBLICATION_GATE_SHA", "${{ github.sha }}"),
)
PUBLICATION_GATE_ACTIVE_COMMANDS = (
    "set -euo pipefail",
    "python3 .github/scripts/verify_publication_gate.py --self-test",
    "python3 .github/scripts/verify_publication_gate.py --enforce main "
    "--deadline-seconds 6000",
)

# Direct fields of the version-release SHA gate. Same closed-set rule: a
# write permission, `continue-on-error`, or other control beside this list
# cannot hide behind a substring match. The unique job is proven over the
# whole `jobs:` mapping, matching the hosted publication gate.
RELEASE_GATE_FIELDS = (
    "name",
    "needs",
    "runs-on",
    "timeout-minutes",
    "permissions",
    "steps",
)
RELEASE_GATE_NAME = "Validate release SHA"
RELEASE_GATE_NEEDS = "validate-release-version"
RELEASE_GATE_RUNS_ON = "ubuntu-latest"
RELEASE_GATE_TIMEOUT = "350"
RELEASE_GATE_PERMISSIONS = (("actions", "read"), ("contents", "read"))
RELEASE_GATE_STEP_NAME = (
    "Require every publish-blocking check for the tag target"
)
RELEASE_GATE_CHECKOUT_FIELDS = ("uses", "with")
RELEASE_GATE_CHECKOUT_WITH = (("fetch-depth", "0"),)
RELEASE_GATE_PROOF_FIELDS = ("name", "env", "run")
RELEASE_GATE_ENV = (
    ("GH_TOKEN", "${{ github.token }}"),
    ("PUBLICATION_GATE_REPOSITORY", "${{ github.repository }}"),
    ("TAG_NAME", "${{ github.ref_name }}"),
)
RELEASE_GATE_ACTIVE_COMMANDS = (
    "set -euo pipefail",
    'if [[ ! "$TAG_NAME" =~ ^v[0-9]+\\.[0-9]+\\.[0-9]+([-.][0-9A-Za-z.]+)?$ ]]; then',
    'echo "Invalid release tag format: $TAG_NAME" >&2',
    "exit 1",
    "fi",
    'release_sha="$(git rev-list -n 1 "$TAG_NAME")"',
    'if [[ ! "$release_sha" =~ ^[0-9a-f]{40}$ ]]; then',
    'echo "::error::release tag ${TAG_NAME} did not resolve to a commit" >&2',
    "exit 1",
    "fi",
    'echo "Release tag ${TAG_NAME} resolves to ${release_sha}"',
    "git fetch --no-tags origin +refs/heads/main:refs/remotes/origin/main",
    'if ! git merge-base --is-ancestor "$release_sha" refs/remotes/origin/main; then',
    'echo "::error title=Release target is not on main::${release_sha} is not an ancestor of origin/main" >&2',
    "exit 1",
    "fi",
    "{",
    'echo "## Release Validation"',
    'echo ""',
    'echo "Tag: \\`${TAG_NAME}\\`"',
    'echo ""',
    'echo "Commit: \\`${release_sha}\\`"',
    'echo ""',
    '} >> "$GITHUB_STEP_SUMMARY"',
    'export PUBLICATION_GATE_SHA="$release_sha"',
    "python3 .github/scripts/verify_publication_gate.py --self-test",
    "python3 .github/scripts/verify_publication_gate.py --enforce release "
    "--deadline-seconds 9600",
)

# `main_publication` says which publication control carries a context on the
# `main` publishing path. The three values partition the inventory.
MAIN_PUBLICATION_MODES = (
    # Proven in-run: the publishing jobs declare `needs: <job>` on it and
    # require `success`, so no Actions API evidence is involved.
    "ci_job_dependency",
    # Carried by the frozen `main-publish-gate` same-SHA polling array.
    "ci_main_publish_gate",
    # Carried by the `main-publication-required-checks` job, whose run
    # conclusion the frozen array requires for the same SHA.
    "publication_gate_job",
)

# `evidence` says how a run is bound to the exact product SHA.
EVIDENCE_MODES = ("push_main", "merge_group_head")

REQUIRED_ENTRY_FIELDS = (
    "context",
    "workflow_file",
    "workflow_path",
    "workflow_name",
    "job",
    "main_publication",
    "evidence",
    "rationale",
)

API_ROOT = "https://api.github.com"
API_VERSION = "2022-11-28"
PAGE_SIZE = 100
MAX_PAGES = 20
TRANSIENT_ATTEMPTS = 3
# The Actions token is rate limited per repository, and these gates can poll for
# well over an hour. Poll once a minute and reuse a workflow-identity lookup
# while any selected context is still pending, so a long wait on one slow suite
# cannot exhaust the budget the gate itself depends on. A completed success is
# never cached across sweeps: GitHub permits rerunning a completed workflow, so
# the run record can return to queued/in_progress and later fail while this
# wait is still in progress. Every sweep re-lists every selected context under
# the same bounded pagination; the sweep that would permit then re-resolves
# canonical workflow id/path/name/active state and re-observes the complete set
# before returning.
POLL_SECONDS = 60

# Anything that is not a completed success blocks. Statuses are listed only so
# a diagnostic can say "still running" rather than "unknown"; an unrecognized
# status is treated as pending and therefore still never permits publication.
PENDING_STATUSES = frozenset(
    {"queued", "in_progress", "waiting", "pending", "requested"}
)


class ContractError(RuntimeError):
    """The inventory or a consumer of it is malformed."""


class ApiFailure(RuntimeError):
    """The Actions API could not be read; the gate fails closed."""


# ---------------------------------------------------------------------------
# Inventory
# ---------------------------------------------------------------------------


def parse_inventory(text: str) -> dict:
    try:
        inventory = json.loads(text)
    except json.JSONDecodeError as error:  # pragma: no cover - defensive
        raise ContractError(f"{INVENTORY_PATH} is not valid JSON: {error}") from error
    if not isinstance(inventory, dict):
        raise ContractError(f"{INVENTORY_PATH} must be a JSON object")
    return inventory


def load_inventory(root: Path | None = None) -> dict:
    base = Path(".") if root is None else root
    return parse_inventory((base / INVENTORY_PATH).read_text(encoding="utf-8"))


def entries(inventory: dict) -> list[dict]:
    checks = inventory.get("required_checks")
    if not isinstance(checks, list):
        raise ContractError(f"{INVENTORY_PATH} must carry a `required_checks` list")
    return checks


def inventory_errors(inventory: dict) -> list[str]:
    """Reject a malformed, ambiguous, or incomplete inventory."""

    errors: list[str] = []
    if inventory.get("version") != 1:
        errors.append(f"{INVENTORY_PATH} must declare `version: 1`")
    if inventory.get("main_branch") != "main":
        errors.append(f"{INVENTORY_PATH} must declare `main_branch: main`")
    prefix = inventory.get("merge_queue_branch_prefix")
    if not isinstance(prefix, str) or not prefix.startswith("gh-readonly-queue/"):
        errors.append(
            f"{INVENTORY_PATH} must declare the `gh-readonly-queue/` merge-queue "
            "branch prefix used to bind merge-group evidence"
        )
    try:
        checks = entries(inventory)
    except ContractError as error:
        return [*errors, str(error)]
    if not checks:
        errors.append(f"{INVENTORY_PATH} must not be empty")

    seen_contexts: set[str] = set()
    seen_paths: set[str] = set()
    for index, entry in enumerate(checks):
        located = f"{INVENTORY_PATH}[{index}]"
        if not isinstance(entry, dict):
            errors.append(f"{located} must be an object")
            continue
        missing = [field for field in REQUIRED_ENTRY_FIELDS if field not in entry]
        if missing:
            errors.append(f"{located} is missing {sorted(missing)}")
            continue
        extra = sorted(set(entry) - set(REQUIRED_ENTRY_FIELDS))
        if extra:
            errors.append(f"{located} carries unknown fields {extra}")
        if not all(isinstance(entry[field], str) for field in REQUIRED_ENTRY_FIELDS):
            errors.append(f"{located} fields must all be strings")
            continue
        context = entry["context"]
        if context in seen_contexts:
            errors.append(f"{located} duplicates required context {context!r}")
        seen_contexts.add(context)
        workflow_path = entry["workflow_path"]
        if workflow_path in seen_paths:
            errors.append(f"{located} duplicates workflow {workflow_path!r}")
        seen_paths.add(workflow_path)
        if workflow_path != f".github/workflows/{entry['workflow_file']}":
            errors.append(
                f"{located} workflow_path {workflow_path!r} must be "
                f".github/workflows/{entry['workflow_file']}"
            )
        if entry["main_publication"] not in MAIN_PUBLICATION_MODES:
            errors.append(
                f"{located} main_publication must be one of "
                f"{list(MAIN_PUBLICATION_MODES)}"
            )
        if entry["evidence"] not in EVIDENCE_MODES:
            errors.append(f"{located} evidence must be one of {list(EVIDENCE_MODES)}")
        if not entry["rationale"].strip():
            errors.append(f"{located} must carry a non-empty rationale")
    return errors


def by_mode(inventory: dict, mode: str) -> list[dict]:
    return [entry for entry in entries(inventory) if entry["main_publication"] == mode]


# ---------------------------------------------------------------------------
# Static contract
# ---------------------------------------------------------------------------

_JOB_BODY = "(?ms)^  {job}:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\\Z)"
_SIMPLE_MAPPING_KEY = re.compile(
    r"^(?P<indent> *)(?P<key>[A-Za-z0-9_-]+|'(?:[^']|'')*'|"
    r'"(?:[^"\\]|\\.)*")\s*:(.*)$'
)
_CANONICAL_JOB_HEADER = re.compile(r"^  ([A-Za-z0-9_-]+):\s*(#.*)?$")


def job_body(contents: str, job: str) -> str | None:
    match = re.search(_JOB_BODY.format(job=re.escape(job)), contents)
    return None if match is None else match.group("body")


class StructuralError(RuntimeError):
    """Non-canonical YAML that the static contract refuses to guess at."""


_MAPPING_KEY = re.compile(r"^([A-Za-z0-9_-]+):(.*)$")
_SEQUENCE_ITEM = re.compile(r"^- ([A-Za-z0-9_-]+):(.*)$")


def _is_comment_line(line: str) -> bool:
    return line.lstrip(" ").startswith("#")


def _indent_spaces(line: str) -> int:
    indent = 0
    for character in line:
        if character == " ":
            indent += 1
            continue
        if character == "\t":
            raise StructuralError("tab indentation is opaque")
        break
    return indent


def _strip_inline_comment(raw: str) -> str:
    """Remove a plain-scalar YAML comment without cutting quoted `#` data."""

    quote: str | None = None
    index = 0
    while index < len(raw):
        character = raw[index]
        if quote == '"' and character == "\\" and index + 1 < len(raw):
            index += 2
            continue
        if quote is not None:
            if character == quote:
                if quote == "'" and index + 1 < len(raw) and raw[index + 1] == "'":
                    index += 2
                    continue
                quote = None
            index += 1
            continue
        if character in "'\"":
            quote = character
        elif character == "#" and (index == 0 or raw[index - 1].isspace()):
            return raw[:index].strip()
        index += 1
    return raw.strip()


def _classify_value(rest: str) -> tuple[str, str]:
    without_comment = _strip_inline_comment(rest)
    if not without_comment:
        return ("nested", "")
    if without_comment[0] in "{[":
        return ("flow", without_comment)
    if without_comment[0] in "&*":
        return ("opaque", without_comment)
    if without_comment == "|":
        return ("block", "|")
    if without_comment[0] in "|>":
        return ("opaque", without_comment)
    return ("scalar", without_comment)


def _collect_children(
    lines: list[str], start: int, parent_indent: int
) -> tuple[list[str], int]:
    collected: list[str] = []
    index = start
    while index < len(lines):
        line = lines[index]
        if not line.strip():
            collected.append(line)
            index += 1
            continue
        if _indent_spaces(line) <= parent_indent:
            break
        collected.append(line)
        index += 1
    return collected, index


def _dedent_block(lines: list[str], parent_indent: int) -> str:
    nonblank = [line for line in lines if line.strip()]
    if not nonblank:
        return ""
    indents = [_indent_spaces(line) for line in nonblank]
    if any(indent <= parent_indent for indent in indents):
        raise StructuralError("block scalar is not indented under its key")
    strip = min(indents)
    body: list[str] = []
    for line in lines:
        if not line.strip():
            body.append("")
            continue
        indent = _indent_spaces(line)
        if indent < strip:
            raise StructuralError("block scalar indent is inconsistent")
        body.append(line[strip:])
    return "\n".join(body)


def _parse_mapping(
    lines: list[str], key_indent: int
) -> dict[str, tuple[str, object]]:
    result: dict[str, tuple[str, object]] = {}
    index = 0
    while index < len(lines):
        line = lines[index]
        if not line.strip() or _is_comment_line(line):
            index += 1
            continue
        indent = _indent_spaces(line)
        if indent < key_indent:
            raise StructuralError(
                "unconsumed lower-indentation content is opaque"
            )
        if indent > key_indent:
            raise StructuralError("orphaned content is opaque")
        match = _MAPPING_KEY.match(line[key_indent:])
        if match is None:
            raise StructuralError("direct fields must be canonical block keys")
        key, rest = match.group(1), match.group(2)
        if key in result:
            raise StructuralError(f"duplicate key {key!r}")
        kind, payload = _classify_value(rest)
        if kind in {"flow", "opaque"}:
            raise StructuralError(
                f"{key!r} uses a flow, duplicate, or opaque spelling"
            )
        if kind == "scalar":
            result[key] = ("scalar", payload)
            index += 1
            continue
        children, index = _collect_children(lines, index + 1, key_indent)
        if kind == "block":
            result[key] = ("block", _dedent_block(children, key_indent))
            continue
        result[key] = _parse_nested(children, key_indent + 2)
    return result


def _parse_nested(children: list[str], child_indent: int) -> tuple[str, object]:
    for line in children:
        if not line.strip() or _is_comment_line(line):
            continue
        indent = _indent_spaces(line)
        if indent != child_indent:
            raise StructuralError("nested value uses a non-canonical indent")
        content = line[child_indent:]
        if content.startswith("- "):
            return ("sequence", _parse_sequence(children, child_indent))
        if _MAPPING_KEY.match(content):
            return ("mapping", _parse_mapping(children, child_indent))
        raise StructuralError("nested value is opaque")
    raise StructuralError("nested value is empty")


def _parse_sequence(
    lines: list[str], item_indent: int
) -> list[dict[str, tuple[str, object]]]:
    items: list[dict[str, tuple[str, object]]] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        if not line.strip() or _is_comment_line(line):
            index += 1
            continue
        indent = _indent_spaces(line)
        if indent != item_indent:
            raise StructuralError("sequence item indent is opaque")
        match = _SEQUENCE_ITEM.match(line[item_indent:])
        if match is None:
            raise StructuralError(
                "sequence items must start with a same-line `- key:` scalar"
            )
        first_key, rest = match.group(1), match.group(2)
        kind, payload = _classify_value(rest)
        if kind != "scalar":
            raise StructuralError(
                f"sequence item {first_key!r} must be a same-line scalar"
            )
        item: dict[str, tuple[str, object]] = {first_key: ("scalar", payload)}
        children, index = _collect_children(lines, index + 1, item_indent)
        rest_mapping = (
            _parse_mapping(children, item_indent + 2) if children else {}
        )
        for rest_key, rest_value in rest_mapping.items():
            if rest_key in item:
                raise StructuralError(f"duplicate key {rest_key!r}")
            item[rest_key] = rest_value
        items.append(item)
    if not items:
        raise StructuralError("sequence is empty")
    return items


def _parse_job(body: str) -> dict[str, tuple[str, object]]:
    return _parse_mapping(body.splitlines(), 4)


def _decode_simple_mapping_key(line: str) -> tuple[int, str] | None:
    """Return `(indent, decoded_key)` for a proven simple mapping key.

    Canonical bare keys and single- or double-quoted scalars GitHub YAML
    treats as the same key are decoded. Anything this dependency-free parser
    cannot prove -- tags, explicit keys, aliases, flow keys, multiline
    quotes, or YAML-only escapes -- returns None so callers fail closed.
    """

    match = _SIMPLE_MAPPING_KEY.match(line)
    if match is None:
        return None
    raw = match.group("key")
    if raw.startswith("'"):
        key = raw[1:-1].replace("''", "'")
    elif raw.startswith('"'):
        try:
            decoded = json.loads(raw)
        except json.JSONDecodeError:
            return None
        if not isinstance(decoded, str):
            return None
        key = decoded
    else:
        key = raw
    return len(match.group("indent")), key


def _protected_job_body(contents: str, job: str) -> str:
    """Return the unique canonical protected job body, or fail closed.

    The whole top-level `jobs:` mapping is scanned. A quoted, escaped, or
    otherwise YAML-equivalent duplicate of `job`, or any opaque job-key
    spelling that cannot be proven distinct, is rejected even when a
    safe-looking bare decoy is present.
    """

    lines = contents.splitlines()
    jobs_headers: list[tuple[int, str]] = []
    for index, line in enumerate(lines):
        if not line.strip() or _is_comment_line(line):
            continue
        indent = _indent_spaces(line)
        if indent != 0:
            continue
        decoded = _decode_simple_mapping_key(line)
        if decoded is None:
            raise StructuralError("top-level key is opaque")
        if decoded == (0, "jobs"):
            jobs_headers.append((index, line.rstrip("\r\n")))
    canonical_jobs = [
        index for index, text in jobs_headers if text.strip() == "jobs:"
    ]
    if len(jobs_headers) != 1 or len(canonical_jobs) != 1:
        raise StructuralError(
            "must contain exactly one canonical top-level `jobs:` mapping"
        )

    jobs_index = canonical_jobs[0]
    jobs_end = len(lines)
    for index in range(jobs_index + 1, len(lines)):
        line = lines[index]
        if not line.strip() or _is_comment_line(line):
            continue
        if _indent_spaces(line) == 0:
            jobs_end = index
            break

    headers: list[tuple[int, str, bool]] = []
    for index in range(jobs_index + 1, jobs_end):
        line = lines[index]
        if not line.strip() or _is_comment_line(line):
            continue
        indent = _indent_spaces(line)
        if indent > 2:
            continue
        if indent < 2:
            raise StructuralError(
                "jobs mapping contains unconsumed lower-indentation content"
            )
        decoded = _decode_simple_mapping_key(line)
        if decoded is None or decoded[0] != 2:
            raise StructuralError("job key is opaque")
        name = decoded[1]
        canonical = _CANONICAL_JOB_HEADER.match(line) is not None
        headers.append((index, name, canonical))

    matching = [header for header in headers if header[1] == job]
    canonical_matching = [header for header in matching if header[2]]
    if len(matching) != 1 or len(canonical_matching) != 1:
        raise StructuralError(
            "must be the unique canonical job key; quoted, escaped, or "
            "opaque YAML-equivalent duplicates are rejected"
        )

    start = canonical_matching[0][0] + 1
    end = jobs_end
    for index, _name, _canonical in headers:
        if index > canonical_matching[0][0]:
            end = index
            break
    return "\n".join(lines[start:end])


def _scalar(mapping: dict[str, tuple[str, object]], key: str) -> str | None:
    value = mapping.get(key)
    if value is None or value[0] != "scalar":
        return None
    return str(value[1])


def _mapping(
    mapping: dict[str, tuple[str, object]], key: str
) -> dict[str, tuple[str, object]] | None:
    value = mapping.get(key)
    if value is None or value[0] != "mapping":
        return None
    payload = value[1]
    if not isinstance(payload, dict):
        return None
    return payload


def _sequence(
    mapping: dict[str, tuple[str, object]], key: str
) -> list[dict[str, tuple[str, object]]] | None:
    value = mapping.get(key)
    if value is None or value[0] != "sequence":
        return None
    payload = value[1]
    if not isinstance(payload, list):
        return None
    return payload


def _block(mapping: dict[str, tuple[str, object]], key: str) -> str | None:
    value = mapping.get(key)
    if value is None or value[0] != "block":
        return None
    return str(value[1])


def _mapping_pairs(
    mapping: dict[str, tuple[str, object]]
) -> tuple[tuple[str, str], ...] | None:
    pairs: list[tuple[str, str]] = []
    for key, (kind, payload) in mapping.items():
        if kind != "scalar":
            return None
        pairs.append((key, str(payload)))
    return tuple(pairs)


def _active_shell_lines(script: str) -> list[str]:
    active: list[str] = []
    for raw in script.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        active.append(stripped)
    return active


def _checkout_step_errors(
    step: dict[str, tuple[str, object]],
    located: str,
    expected_fields: tuple[str, ...],
    expected_with: tuple[tuple[str, str], ...] | None,
) -> list[str]:
    errors: list[str] = []
    if tuple(step) != expected_fields:
        errors.append(
            f"{located} pinned checkout step fields must be exactly "
            f"{expected_fields!r} in order, found {tuple(step)!r}"
        )
    if _scalar(step, "uses") != CHECKOUT_USES:
        errors.append(
            f"{located} checkout must pin `{CHECKOUT_USES}` as an active "
            "`uses:` value, not a comment or a different action"
        )
    if expected_with is None:
        return errors
    with_mapping = _mapping(step, "with")
    if with_mapping is None or _mapping_pairs(with_mapping) != expected_with:
        errors.append(
            f"{located} checkout `with:` must be exactly {expected_with!r}"
        )
    return errors


def _proof_step_errors(
    step: dict[str, tuple[str, object]],
    located: str,
    expected_name: str,
    expected_fields: tuple[str, ...],
    expected_env: tuple[tuple[str, str], ...],
    expected_commands: tuple[str, ...],
) -> list[str]:
    errors: list[str] = []
    if tuple(step) != expected_fields:
        errors.append(
            f"{located} named proof step fields must be exactly "
            f"{expected_fields!r} in order, found {tuple(step)!r}"
        )
    if _scalar(step, "name") != expected_name:
        errors.append(
            f"{located} proof step must be the active named step "
            f"{expected_name!r}"
        )
    env = _mapping(step, "env")
    if env is None or _mapping_pairs(env) != expected_env:
        errors.append(
            f"{located} proof step must own the exact env mapping "
            f"{expected_env!r}"
        )
    script = _block(step, "run")
    if script is None:
        errors.append(
            f"{located} proof step must use a literal `run: |` block"
        )
    elif tuple(_active_shell_lines(script)) != expected_commands:
        errors.append(
            f"{located} proof step active command sequence must be exactly "
            "the required gate invocations; comments and other steps do not "
            "count"
        )
    return errors


def parse_main_publish_gate_specs(ci_yml: str) -> tuple[tuple[str, str, str], ...]:
    """Return the frozen `main-publish-gate` polling array as parsed records."""

    body = job_body(ci_yml, "main-publish-gate")
    if body is None:
        raise ContractError(f"{CI_WORKFLOW_PATH} has no `main-publish-gate` job")
    match = re.search(
        r"(?ms)^\s*required_workflow_specs=\(\n(?P<rows>.*?)^\s*\)\n",
        body,
    )
    if match is None:
        raise ContractError(
            f"{CI_WORKFLOW_PATH} `main-publish-gate` has no "
            "`required_workflow_specs` array to compare with the inventory"
        )
    specs: list[tuple[str, str, str]] = []
    for line in match.group("rows").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not (stripped.startswith('"') and stripped.endswith('"')):
            raise ContractError(
                f"{CI_WORKFLOW_PATH} `main-publish-gate` array row {stripped!r} "
                "is not a plain double-quoted record"
            )
        fields = stripped[1:-1].split("|")
        if len(fields) != 3:
            raise ContractError(
                f"{CI_WORKFLOW_PATH} `main-publish-gate` array row {stripped!r} "
                "must be `file|path|display name`"
            )
        specs.append((fields[0], fields[1], fields[2]))
    return tuple(specs)


def required_context_parity_errors(
    required_contexts: dict[str, str],
    inventory: dict,
) -> list[str]:
    """Prove the branch-protection required set and the inventory are set-equal.

    `required_contexts` maps a workflow path to the required status-check name
    that workflow owns. A context added there without a publication inventory
    entry -- and an inventory entry that is not actually required -- are both
    errors, which is what makes "a newly required context with no publication
    coverage" fail policy CI.
    """

    errors: list[str] = []
    inventory_by_path = {entry["workflow_path"]: entry for entry in entries(inventory)}
    for workflow_path, context in sorted(required_contexts.items()):
        entry = inventory_by_path.get(workflow_path)
        if entry is None:
            errors.append(
                f"required check {context!r} ({workflow_path}) has no "
                f"{INVENTORY_PATH} entry, so publication would not be gated on it"
            )
            continue
        if entry["context"] != context:
            errors.append(
                f"{INVENTORY_PATH} binds {workflow_path} to context "
                f"{entry['context']!r}, but branch protection requires {context!r}"
            )
    for workflow_path, entry in sorted(inventory_by_path.items()):
        if workflow_path not in required_contexts:
            errors.append(
                f"{INVENTORY_PATH} lists {workflow_path} as publish-blocking but it "
                "owns no branch-protection-required check"
            )
    return errors


def main_publish_gate_parity_errors(ci_yml: str, inventory: dict) -> list[str]:
    """Prove the frozen ci.yml array equals the `ci_main_publish_gate` subset."""

    try:
        specs = parse_main_publish_gate_specs(ci_yml)
    except ContractError as error:
        return [str(error)]
    actual = set(specs)
    if len(actual) != len(specs):
        return [
            f"{CI_WORKFLOW_PATH} `main-publish-gate` array has duplicate records"
        ]
    expected = {
        (entry["workflow_file"], entry["workflow_path"], entry["workflow_name"])
        for entry in by_mode(inventory, "ci_main_publish_gate")
    }
    if actual == expected:
        return []
    errors = []
    for spec in sorted(expected - actual):
        errors.append(
            f"{CI_WORKFLOW_PATH} `main-publish-gate` does not wait for "
            f"{spec[1]} (`{spec[2]}`), which {INVENTORY_PATH} marks "
            "`ci_main_publish_gate`"
        )
    for spec in sorted(actual - expected):
        errors.append(
            f"{CI_WORKFLOW_PATH} `main-publish-gate` waits for {spec[1]} "
            f"(`{spec[2]}`), which is not a `ci_main_publish_gate` entry of "
            f"{INVENTORY_PATH}"
        )
    return errors


def ci_job_dependency_errors(ci_yml: str, inventory: dict) -> list[str]:
    """Prove every in-run entry is a hard `needs` of each publishing job."""

    errors: list[str] = []
    publishers = ("main-publish-gate", "latest-release", "docker")
    for entry in by_mode(inventory, "ci_job_dependency"):
        if entry["workflow_path"] != CI_WORKFLOW_PATH:
            errors.append(
                f"{INVENTORY_PATH} entry {entry['context']!r} is "
                "`ci_job_dependency` but is not owned by ci.yml, so no in-run "
                "dependency can carry it"
            )
            continue
        job = entry["job"]
        for publisher in publishers:
            body = job_body(ci_yml, publisher)
            if body is None:
                errors.append(f"{CI_WORKFLOW_PATH} has no `{publisher}` job")
                continue
            if not re.search(rf"(?m)^    needs:(?:.*[\[, ])?{re.escape(job)}\b", body) and not re.search(
                rf"(?m)^      - {re.escape(job)}$", body
            ):
                errors.append(
                    f"{CI_WORKFLOW_PATH} jobs.{publisher} must declare "
                    f"`needs: {job}` for in-run required check "
                    f"{entry['context']!r}"
                )
            if f"needs.{job}.result == 'success'" not in body:
                errors.append(
                    f"{CI_WORKFLOW_PATH} jobs.{publisher} must require "
                    f"`needs.{job}.result == 'success'`"
                )
    return errors


def publication_gate_job_errors(gateway_yml: str, inventory: dict) -> list[str]:
    """Prove the hosted publication gate by exact active structure."""

    errors: list[str] = []
    located = f"{PUBLICATION_GATE_WORKFLOW_PATH} jobs.{PUBLICATION_GATE_JOB}"
    try:
        body = _protected_job_body(gateway_yml, PUBLICATION_GATE_JOB)
        job = _parse_job(body)
    except StructuralError as error:
        errors.append(f"{located} {error}")
        return errors
    if tuple(job) != PUBLICATION_GATE_FIELDS:
        errors.append(
            f"{located} direct fields must be exactly "
            f"{PUBLICATION_GATE_FIELDS!r} in order, found {tuple(job)!r}"
        )
    if _scalar(job, "name") != PUBLICATION_GATE_NAME:
        errors.append(f"{located} must keep name {PUBLICATION_GATE_NAME!r}")
    if _scalar(job, "if") != PUBLICATION_GATE_IF:
        errors.append(f"{located} must stay scoped by `{PUBLICATION_GATE_IF}`")
    if _scalar(job, "runs-on") != PUBLICATION_GATE_RUNS_ON:
        errors.append(f"{located} must run on `{PUBLICATION_GATE_RUNS_ON}`")
    if _scalar(job, "timeout-minutes") != PUBLICATION_GATE_TIMEOUT:
        errors.append(
            f"{located} must keep the bounded timeout-minutes "
            f"{PUBLICATION_GATE_TIMEOUT}"
        )
    permissions = _mapping(job, "permissions")
    if (
        permissions is None
        or _mapping_pairs(permissions) != PUBLICATION_GATE_PERMISSIONS
    ):
        errors.append(
            f"{located} permissions must be the exact least-privilege mapping "
            f"{PUBLICATION_GATE_PERMISSIONS!r}; write scopes, extra keys, "
            "duplicates, and flow spellings do not count"
        )
    steps = _sequence(job, "steps")
    if steps is None or len(steps) != 2:
        errors.append(
            f"{located} must have exactly two active steps: the pinned "
            "checkout, then the named publication proof"
        )
    else:
        errors.extend(
            _checkout_step_errors(
                steps[0],
                located,
                PUBLICATION_GATE_CHECKOUT_FIELDS,
                None,
            )
        )
        errors.extend(
            _proof_step_errors(
                steps[1],
                located,
                PUBLICATION_GATE_STEP_NAME,
                PUBLICATION_GATE_PROOF_FIELDS,
                PUBLICATION_GATE_ENV,
                PUBLICATION_GATE_ACTIVE_COMMANDS,
            )
        )
    if not by_mode(inventory, "publication_gate_job"):
        errors.append(
            f"{INVENTORY_PATH} marks no context `publication_gate_job`, so the "
            "hosted gate would prove nothing"
        )
    # The frozen `main-publish-gate` array must itself wait for the workflow
    # that hosts the gate; otherwise the hosted verdict never blocks anything.
    hosting = [
        entry
        for entry in by_mode(inventory, "ci_main_publish_gate")
        if entry["workflow_path"] == PUBLICATION_GATE_WORKFLOW_PATH
    ]
    if not hosting:
        errors.append(
            f"{PUBLICATION_GATE_WORKFLOW_PATH} hosts the publication gate, so it "
            f"must itself be a `ci_main_publish_gate` entry of {INVENTORY_PATH}"
        )
    return errors


def release_gate_errors(release_yml: str, inventory: dict) -> list[str]:
    """Prove the version-release verifier by exact active structure."""

    errors: list[str] = []
    located = f"{RELEASE_WORKFLOW_PATH} jobs.{RELEASE_GATE_JOB}"
    try:
        body = _protected_job_body(release_yml, RELEASE_GATE_JOB)
        job = _parse_job(body)
    except StructuralError as error:
        return [f"{located} {error}"]
    if tuple(job) != RELEASE_GATE_FIELDS:
        errors.append(
            f"{located} direct fields must be exactly "
            f"{RELEASE_GATE_FIELDS!r} in order, found {tuple(job)!r}"
        )
    if _scalar(job, "name") != RELEASE_GATE_NAME:
        errors.append(f"{located} must keep name {RELEASE_GATE_NAME!r}")
    if _scalar(job, "needs") != RELEASE_GATE_NEEDS:
        errors.append(f"{located} must keep `needs: {RELEASE_GATE_NEEDS}`")
    if _scalar(job, "runs-on") != RELEASE_GATE_RUNS_ON:
        errors.append(f"{located} must run on `{RELEASE_GATE_RUNS_ON}`")
    if _scalar(job, "timeout-minutes") != RELEASE_GATE_TIMEOUT:
        errors.append(
            f"{located} must keep the bounded timeout-minutes "
            f"{RELEASE_GATE_TIMEOUT}"
        )
    permissions = _mapping(job, "permissions")
    if (
        permissions is None
        or _mapping_pairs(permissions) != RELEASE_GATE_PERMISSIONS
    ):
        errors.append(
            f"{located} permissions must be the exact least-privilege mapping "
            f"{RELEASE_GATE_PERMISSIONS!r}; write scopes, extra keys, "
            "duplicates, and flow spellings do not count"
        )
    steps = _sequence(job, "steps")
    if steps is None or len(steps) != 2:
        errors.append(
            f"{located} must have exactly two active steps: the pinned "
            f"checkout, then {RELEASE_GATE_STEP_NAME!r}"
        )
    else:
        errors.extend(
            _checkout_step_errors(
                steps[0],
                located,
                RELEASE_GATE_CHECKOUT_FIELDS,
                RELEASE_GATE_CHECKOUT_WITH,
            )
        )
        errors.extend(
            _proof_step_errors(
                steps[1],
                located,
                RELEASE_GATE_STEP_NAME,
                RELEASE_GATE_PROOF_FIELDS,
                RELEASE_GATE_ENV,
                RELEASE_GATE_ACTIVE_COMMANDS,
            )
        )
        proof_script = _block(steps[1], "run") if len(steps) > 1 else None
        active = (
            _active_shell_lines(proof_script) if proof_script is not None else []
        )
        if any("wait_for_success" in line for line in active):
            errors.append(
                f"{located} must not keep a hard-coded per-workflow wait list "
                "beside the canonical inventory"
            )
    if not entries(inventory):
        errors.append(f"{INVENTORY_PATH} carries no publish-blocking context")
    return errors


def workflow_identity_errors(inventory: dict, read: object) -> list[str]:
    """Prove each inventoried workflow exists with the declared name and job."""

    errors: list[str] = []
    for entry in entries(inventory):
        try:
            contents = read(entry["workflow_path"])  # type: ignore[operator]
        except FileNotFoundError:
            errors.append(
                f"{INVENTORY_PATH} names missing workflow {entry['workflow_path']}"
            )
            continue
        if not re.search(
            rf"(?m)^name: {re.escape(entry['workflow_name'])}$",
            contents,
        ):
            errors.append(
                f"{entry['workflow_path']} must keep workflow name "
                f"`{entry['workflow_name']}`; the publication gate binds runs by "
                "workflow id, path, AND name"
            )
        if job_body(contents, entry["job"]) is None:
            errors.append(
                f"{entry['workflow_path']} must keep job `{entry['job']}`, which "
                f"owns required check {entry['context']!r}"
            )
        if entry["evidence"] == "push_main":
            if not re.search(
                r"(?ms)^  push:\n(?:    #[^\n]*\n)*    branches:\n"
                r"(?:      #[^\n]*\n)*      - main\n",
                contents,
            ):
                errors.append(
                    f"{entry['workflow_path']} must declare an unconditional "
                    "`push:` trigger on `main` to yield exact-main-SHA "
                    "publication evidence"
                )
            if re.search(r"(?ms)^  push:\n(?:[ ]{4}[^\n]*\n)*?[ ]{4}paths", contents):
                errors.append(
                    f"{entry['workflow_path']} must not filter its `push:` "
                    "trigger by path; a filtered required gate can make "
                    "publication evidence absent"
                )
        elif entry["evidence"] == "merge_group_head":
            if not re.search(r"(?m)^  merge_group:$", contents):
                errors.append(
                    f"{entry['workflow_path']} must declare a `merge_group:` "
                    "trigger to yield merge-queue publication evidence"
                )
    return errors


def contract_errors(
    inventory: dict,
    required_contexts: dict[str, str],
    read: object,
) -> list[str]:
    """Run every static proof that keeps the contract free of drift."""

    errors = list(inventory_errors(inventory))
    if errors:
        return errors
    errors.extend(required_context_parity_errors(required_contexts, inventory))
    errors.extend(workflow_identity_errors(inventory, read))
    errors.extend(main_publish_gate_parity_errors(read(CI_WORKFLOW_PATH), inventory))
    errors.extend(ci_job_dependency_errors(read(CI_WORKFLOW_PATH), inventory))
    errors.extend(
        publication_gate_job_errors(read(PUBLICATION_GATE_WORKFLOW_PATH), inventory)
    )
    errors.extend(release_gate_errors(read(RELEASE_WORKFLOW_PATH), inventory))
    # The three modes must partition the inventory: nothing uncovered, and no
    # entry covered by a mode that does not exist.
    covered = {
        entry["context"]
        for mode in MAIN_PUBLICATION_MODES
        for entry in by_mode(inventory, mode)
    }
    everything = {entry["context"] for entry in entries(inventory)}
    for context in sorted(everything - covered):
        errors.append(
            f"required context {context!r} has no publication coverage mode"
        )
    return list(dict.fromkeys(errors))


# ---------------------------------------------------------------------------
# Runtime evidence
# ---------------------------------------------------------------------------


def http_get(token: str):
    """Return a JSON GET callable bound to an Actions API token."""

    def get(path: str) -> object:
        request = urllib.request.Request(f"{API_ROOT}{path}")
        request.add_header("Accept", "application/vnd.github+json")
        request.add_header("X-GitHub-Api-Version", API_VERSION)
        if token:
            request.add_header("Authorization", f"Bearer {token}")
        last: Exception | None = None
        for attempt in range(1, TRANSIENT_ATTEMPTS + 1):
            try:
                with urllib.request.urlopen(request, timeout=60) as response:
                    return json.loads(response.read().decode("utf-8"))
            except (urllib.error.URLError, OSError, ValueError) as error:
                last = error
                if attempt < TRANSIENT_ATTEMPTS:
                    time.sleep(attempt * 5)
        raise ApiFailure(f"GET {path} failed after {TRANSIENT_ATTEMPTS} attempts: {last}")

    return get


def resolve_workflow(get, repository: str, entry: dict) -> dict:
    """Resolve and authenticate the canonical workflow record."""

    path = f"/repos/{repository}/actions/workflows/{entry['workflow_file']}"
    record = get(path)
    if not isinstance(record, dict):
        raise ApiFailure(f"{path} did not return a workflow object")
    identifier = record.get("id")
    if not isinstance(identifier, int):
        raise ApiFailure(f"{path} returned no workflow id")
    if record.get("path") != entry["workflow_path"]:
        raise ApiFailure(
            f"workflow {entry['workflow_file']} resolves to path "
            f"{record.get('path')!r}, not {entry['workflow_path']!r}"
        )
    if record.get("name") != entry["workflow_name"]:
        raise ApiFailure(
            f"workflow {entry['workflow_path']} reports name {record.get('name')!r}, "
            f"not {entry['workflow_name']!r}"
        )
    if record.get("state") != "active":
        raise ApiFailure(
            f"workflow {entry['workflow_path']} is {record.get('state')!r}; a "
            "disabled required gate can never produce publication evidence"
        )
    return {"id": identifier}


def list_runs(
    get,
    repository: str,
    entry: dict,
    sha: str,
    event: str,
    *,
    page_size: int = PAGE_SIZE,
    max_pages: int = MAX_PAGES,
) -> list[dict]:
    """Return every workflow run for this SHA and event, or fail closed.

    A short page is the only proof that the listing ended. Exhausting
    `max_pages` on a full page would otherwise let a later failed duplicate
    go unseen, so truncated evidence never counts as "every matching run
    succeeded". Non-object `workflow_runs` members are rejected rather than
    silently dropped. The query is always bound to exact `head_sha` and
    `event`.
    """

    runs: list[dict] = []
    for page in range(1, max_pages + 1):
        query = urllib.parse.urlencode(
            {
                "head_sha": sha,
                "event": event,
                "per_page": page_size,
                "page": page,
            }
        )
        path = (
            f"/repos/{repository}/actions/workflows/"
            f"{entry['workflow_file']}/runs?{query}"
        )
        payload = get(path)
        if not isinstance(payload, dict):
            raise ApiFailure(f"{path} did not return a run listing")
        page_runs = payload.get("workflow_runs")
        if not isinstance(page_runs, list):
            raise ApiFailure(f"{path} returned no `workflow_runs` array")
        for index, run in enumerate(page_runs):
            if not isinstance(run, dict):
                raise ApiFailure(
                    f"{path} workflow_runs[{index}] is not a run object"
                )
            runs.append(run)
        if len(page_runs) < page_size:
            return runs
    raise ApiFailure(
        f"/repos/{repository}/actions/workflows/{entry['workflow_file']}/runs "
        f"exhausted {max_pages} pages of {page_size} runs without a short page; "
        "refusing to treat truncated evidence as complete"
    )


def run_identity_errors(
    run: dict,
    entry: dict,
    workflow_id: int,
    repository: str,
    sha: str,
    event: str,
    queue_prefix: str,
) -> list[str]:
    """Reject a run that is not the canonical workflow's run for this SHA."""

    problems: list[str] = []
    if run.get("workflow_id") != workflow_id:
        problems.append(
            f"workflow_id {run.get('workflow_id')!r} != {workflow_id}"
        )
    if run.get("path") != entry["workflow_path"]:
        problems.append(f"path {run.get('path')!r} != {entry['workflow_path']!r}")
    if run.get("name") != entry["workflow_name"]:
        problems.append(f"name {run.get('name')!r} != {entry['workflow_name']!r}")
    if run.get("head_sha") != sha:
        problems.append(f"head_sha {run.get('head_sha')!r} != {sha!r}")
    if run.get("event") != event:
        problems.append(f"event {run.get('event')!r} != {event!r}")
    # Both identity objects must positively prove they are dictionaries whose
    # full_name equals this repository. Missing, null, string, list, or other
    # malformed values are a fork mismatch, not a skip.
    for field in ("repository", "head_repository"):
        value = run.get(field)
        if not isinstance(value, dict):
            problems.append(f"{field} is missing or malformed")
            continue
        full_name = value.get("full_name")
        if full_name != repository:
            problems.append(f"{field} {full_name!r} is not {repository!r}")
    branch = run.get("head_branch")
    if event == "push":
        if branch != "main":
            problems.append(f"head_branch {branch!r} != 'main'")
    else:
        if not isinstance(branch, str) or not branch.startswith(queue_prefix):
            problems.append(
                f"head_branch {branch!r} is not a {queue_prefix!r} merge-queue branch"
            )
    return problems


def evaluate_entry(
    get,
    repository: str,
    sha: str,
    entry: dict,
    queue_prefix: str,
    resolved: dict[str, dict] | None = None,
) -> tuple[str, str]:
    """Return ("success" | "pending" | "blocked", diagnostic) for one context.

    `resolved` caches canonical workflow id/path/name/active lookups so a long
    pending wait does not re-GET identity every minute. That cache is not a
    permitting proof: `enforce` drops it and re-observes the complete selected
    set before returning success, because a record resolved at the start of the
    wait can drift (rename, relocate, disable) during the same window a run
    can be rerun.
    """

    event = "push" if entry["evidence"] == "push_main" else "merge_group"
    if resolved is None:
        resolved = {}
    workflow = resolved.get(entry["workflow_path"])
    if workflow is None:
        workflow = resolve_workflow(get, repository, entry)
        resolved[entry["workflow_path"]] = workflow
    workflow_id = workflow["id"]
    runs = list_runs(get, repository, entry, sha, event)

    matching: list[dict] = []
    for run in runs:
        problems = run_identity_errors(
            run,
            entry,
            workflow_id,
            repository,
            sha,
            event,
            queue_prefix,
        )
        if problems:
            # A returned run that does not authenticate is never silently
            # ignored: the workflow-scoped endpoint should not produce one, so
            # treat it as identity drift and fail closed.
            return (
                "blocked",
                f"{entry['context']}: untrusted or mismatched run "
                f"{run.get('html_url') or run.get('id')}: {'; '.join(problems)}",
            )
        matching.append(run)

    if not matching:
        return (
            "pending",
            f"{entry['context']}: no {event} run of {entry['workflow_path']} for "
            f"{sha} yet",
        )

    pending: list[str] = []
    for run in matching:
        status = run.get("status")
        conclusion = run.get("conclusion")
        if status != "completed":
            if status not in PENDING_STATUSES:
                pending.append(f"unrecognized status {status!r}")
            else:
                pending.append(str(status))
            continue
        if conclusion != "success":
            return (
                "blocked",
                f"{entry['context']}: {entry['workflow_path']} concluded "
                f"{conclusion or 'unknown'} for {sha} "
                f"({run.get('html_url') or run.get('id')})",
            )
    if pending:
        return (
            "pending",
            f"{entry['context']}: {entry['workflow_path']} is "
            f"{', '.join(sorted(set(pending)))} for {sha}",
        )
    return ("success", f"{entry['context']}: {entry['workflow_path']} passed for {sha}")


def ancestry_errors(get, repository: str, sha: str) -> list[str]:
    """Prove the product SHA is `main` itself or an ancestor of it."""

    path = f"/repos/{repository}/compare/main...{sha}"
    payload = get(path)
    if not isinstance(payload, dict):
        raise ApiFailure(f"{path} did not return a comparison")
    status = payload.get("status")
    if status not in {"identical", "behind"}:
        return [
            f"{sha} is {status!r} relative to `main`; only a commit that is on "
            "`main` may publish"
        ]
    return []


def enforce(
    get,
    repository: str,
    sha: str,
    inventory: dict,
    selected: list[dict],
    deadline_seconds: int,
    *,
    sleep=time.sleep,
    monotonic=time.monotonic,
    log=print,
) -> int:
    """Poll until one complete sweep observes every selected context successful.

    A prior successful observation is never reused. GitHub allows a completed
    workflow run to be rerun, so its API record can return to queued /
    in_progress and later fail while another required context is still
    pending. Publication is permitted only when a single sweep sees the entire
    selected set successful, and that permitting sweep freshly revalidates
    canonical workflow identity before returning.
    """

    queue_prefix = str(inventory.get("merge_queue_branch_prefix"))
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        log(f"::error::refusing to gate publication on non-canonical SHA {sha!r}")
        return 1
    for error in ancestry_errors(get, repository, sha):
        log(f"::error::{error}")
        return 1
    if not selected:
        log("::error::no required contexts selected; the gate would prove nothing")
        return 1

    start = monotonic()
    resolved: dict[str, dict] = {}

    def observe(*, refresh_identities: bool) -> tuple[str, list[str]]:
        """Re-evaluate every selected entry. Never skip a context.

        Returns ("blocked" | "pending" | "success", messages). A blocked
        entry fails immediately. Identity lookups may be reused while
        waiting; the permitting path must call this with
        `refresh_identities=True` so canonical id/path/name/active state
        is not a record resolved many minutes earlier.
        """

        if refresh_identities:
            resolved.clear()
        pending_messages: list[str] = []
        success_messages: list[str] = []
        for entry in selected:
            verdict, message = evaluate_entry(
                get,
                repository,
                sha,
                entry,
                queue_prefix,
                resolved,
            )
            if verdict == "blocked":
                return ("blocked", [message])
            if verdict == "pending":
                pending_messages.append(message)
            else:
                success_messages.append(message)
        if pending_messages:
            return ("pending", pending_messages)
        return ("success", success_messages)

    while True:
        outcome, messages = observe(refresh_identities=False)
        if outcome == "blocked":
            log(f"::error::{messages[0]}")
            return 1
        if outcome == "success":
            outcome, messages = observe(refresh_identities=True)
            if outcome == "blocked":
                log(f"::error::{messages[0]}")
                return 1
            if outcome == "success":
                for message in messages:
                    log(message)
                log(
                    f"All {len(selected)} publish-blocking required checks "
                    f"passed for {sha}."
                )
                return 0
        for message in messages:
            log(f"Waiting: {message}")
        if monotonic() - start >= deadline_seconds:
            log(
                "::error::timed out waiting for publish-blocking required checks "
                f"for {sha}: {'; '.join(messages)}"
            )
            return 1
        sleep(POLL_SECONDS)


def select_entries(inventory: dict, mode: str) -> list[dict]:
    """Return the contexts a given publication path must prove through the API.

    `main` proves exactly the contexts the frozen ci.yml controls cannot carry.
    `release` proves the COMPLETE inventory, because the version-release
    verifier has no in-run relationship with any of them.
    """

    if mode == "release":
        return list(entries(inventory))
    if mode == "main":
        return by_mode(inventory, "publication_gate_job")
    raise ContractError(f"unknown enforcement mode {mode!r}")


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------


def _fixture_inventory() -> dict:
    return {
        "version": 1,
        "documentation": "self-test",
        "main_branch": "main",
        "merge_queue_branch_prefix": "gh-readonly-queue/main/",
        "required_checks": [
            {
                "context": "Alpha",
                "workflow_file": "alpha.yml",
                "workflow_path": ".github/workflows/alpha.yml",
                "workflow_name": "Alpha Workflow",
                "job": "gate",
                "main_publication": "publication_gate_job",
                "evidence": "push_main",
                "rationale": "self-test",
            },
            {
                "context": "Beta",
                "workflow_file": "beta.yml",
                "workflow_path": ".github/workflows/beta.yml",
                "workflow_name": "Beta Workflow",
                "job": "verify",
                "main_publication": "publication_gate_job",
                "evidence": "merge_group_head",
                "rationale": "self-test",
            },
        ],
    }


_SHA = "a" * 40


def _run(
    *,
    workflow_id: int = 11,
    path: str = ".github/workflows/alpha.yml",
    name: str = "Alpha Workflow",
    head_sha: str = _SHA,
    event: str = "push",
    branch: str = "main",
    status: str = "completed",
    conclusion: str | None = "success",
    repository: str = "ferrum-edge/ferrum-edge",
    run_id: int = 1,
) -> dict:
    return {
        "id": run_id,
        "html_url": f"https://example.invalid/run/{run_id}",
        "workflow_id": workflow_id,
        "path": path,
        "name": name,
        "head_sha": head_sha,
        "event": event,
        "head_branch": branch,
        "status": status,
        "conclusion": conclusion,
        "repository": {"full_name": repository},
        "head_repository": {"full_name": repository},
    }


def _transport(runs_by_file: dict[str, list[dict]], *, compare_status: str = "behind"):
    workflows = {
        "alpha.yml": {
            "id": 11,
            "path": ".github/workflows/alpha.yml",
            "name": "Alpha Workflow",
            "state": "active",
        },
        "beta.yml": {
            "id": 22,
            "path": ".github/workflows/beta.yml",
            "name": "Beta Workflow",
            "state": "active",
        },
    }

    def get(path: str) -> object:
        if "/compare/" in path:
            return {"status": compare_status}
        match = re.search(r"/actions/workflows/([^/?]+)(/runs)?", path)
        if match is None:  # pragma: no cover - defensive
            raise ApiFailure(f"unexpected path {path}")
        workflow_file = match.group(1)
        if match.group(2) is None:
            return workflows[workflow_file]
        query = urllib.parse.parse_qs(urllib.parse.urlparse(path).query)
        page = int((query.get("page") or ["1"])[0])
        per_page = int((query.get("per_page") or [str(PAGE_SIZE)])[0])
        all_runs = list(runs_by_file.get(workflow_file, []))
        start = (page - 1) * per_page
        return {"workflow_runs": all_runs[start : start + per_page]}

    return get


def _enforce(runs_by_file, **kwargs) -> int:
    inventory = _fixture_inventory()
    return enforce(
        _transport(runs_by_file, **kwargs),
        "ferrum-edge/ferrum-edge",
        _SHA,
        inventory,
        select_entries(inventory, "main"),
        deadline_seconds=0,
        sleep=lambda _seconds: None,
        monotonic=lambda: 1.0,
        log=lambda *_args, **_kwargs: None,
    )


def _enforce_across_sweeps(
    sweep_runs: list[dict[str, list[dict]]],
    *,
    workflow_mutations: list[dict[str, dict]] | None = None,
    deadline_seconds: int = 90,
    compare_status: str = "behind",
) -> tuple[int, list[float]]:
    """Drive `enforce` across successive API snapshots advanced by `sleep`.

    Index 0 is the first polling sweep. `sleep` advances both the monotonic
    clock by the requested interval and the snapshot index, matching the
    production one-minute cadence. Workflow-identity GETs in sweep *i* see
    `workflow_mutations[i]` overlaid on the canonical fixture records when
    that list is provided.
    """

    inventory = _fixture_inventory()
    state = {"sweep": 0, "t": 0.0}
    slept: list[float] = []
    workflows = {
        "alpha.yml": {
            "id": 11,
            "path": ".github/workflows/alpha.yml",
            "name": "Alpha Workflow",
            "state": "active",
        },
        "beta.yml": {
            "id": 22,
            "path": ".github/workflows/beta.yml",
            "name": "Beta Workflow",
            "state": "active",
        },
    }

    def get(path: str) -> object:
        index = min(state["sweep"], len(sweep_runs) - 1)
        if "/compare/" in path:
            return {"status": compare_status}
        match = re.search(r"/actions/workflows/([^/?]+)(/runs)?", path)
        if match is None:  # pragma: no cover - defensive
            raise ApiFailure(f"unexpected path {path}")
        workflow_file = match.group(1)
        if match.group(2) is None:
            payload = dict(workflows[workflow_file])
            if workflow_mutations is not None and index < len(workflow_mutations):
                payload.update(workflow_mutations[index].get(workflow_file, {}))
            return payload
        query = urllib.parse.parse_qs(urllib.parse.urlparse(path).query)
        page = int((query.get("page") or ["1"])[0])
        per_page = int((query.get("per_page") or [str(PAGE_SIZE)])[0])
        all_runs = list(sweep_runs[index].get(workflow_file, []))
        start = (page - 1) * per_page
        return {"workflow_runs": all_runs[start : start + per_page]}

    def sleep(seconds: float) -> None:
        slept.append(seconds)
        state["t"] += seconds
        state["sweep"] += 1

    try:
        code = enforce(
            get,
            "ferrum-edge/ferrum-edge",
            _SHA,
            inventory,
            select_entries(inventory, "main"),
            deadline_seconds,
            sleep=sleep,
            monotonic=lambda: state["t"],
            log=lambda *_args, **_kwargs: None,
        )
    except ApiFailure:
        code = 1
    return code, slept


def _beta_run(**overrides) -> dict:
    defaults = {
        "workflow_id": 22,
        "path": ".github/workflows/beta.yml",
        "name": "Beta Workflow",
        "event": "merge_group",
        "branch": "gh-readonly-queue/main/pr-1-abc",
    }
    defaults.update(overrides)
    return _run(**defaults)


def _complete_runs() -> dict[str, list[dict]]:
    return {"alpha.yml": [_run()], "beta.yml": [_beta_run()]}


def _gate_inventory() -> dict:
    inventory = _fixture_inventory()
    inventory["required_checks"] = [
        *inventory["required_checks"],
        {
            "context": "Gateway API Conformance",
            "workflow_file": "gateway-api-conformance.yml",
            "workflow_path": PUBLICATION_GATE_WORKFLOW_PATH,
            "workflow_name": "Gateway API Conformance",
            "job": "gate",
            "main_publication": "ci_main_publish_gate",
            "evidence": "push_main",
            "rationale": "self-test hosting workflow",
        },
    ]
    return inventory


def _wrap_publication_job(body: str) -> str:
    if not body.endswith("\n"):
        body += "\n"
    return f"jobs:\n  {PUBLICATION_GATE_JOB}:\n{body}"


def _wrap_release_job(body: str) -> str:
    if not body.endswith("\n"):
        body += "\n"
    return f"jobs:\n  {RELEASE_GATE_JOB}:\n{body}  next-job:\n    runs-on: ubuntu-latest\n"


_CONFORMING_PUBLICATION_JOB = """    name: Main Publication Required Checks
    if: github.event_name == 'push' && github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    # The gate stops at its own deadline below, so this ceiling is only a
    # backstop against a wedged runner.
    timeout-minutes: 110
    permissions:
      contents: read
      actions: read
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v6

      - name: Prove every publish-blocking required check passed for this SHA
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          PUBLICATION_GATE_REPOSITORY: ${{ github.repository }}
          PUBLICATION_GATE_SHA: ${{ github.sha }}
        run: |
          set -euo pipefail

          # The commit and repository travel in the environment so this argv
          # stays fully literal: a trusted-policy scan can read exactly what
          # this step executes without resolving a shell expansion.
          python3 .github/scripts/verify_publication_gate.py --self-test
          python3 .github/scripts/verify_publication_gate.py --enforce main --deadline-seconds 6000
"""

_CONFORMING_RELEASE_JOB = """    name: Validate release SHA
    needs: validate-release-version
    runs-on: ubuntu-latest
    timeout-minutes: 350
    permissions:
      actions: read
      contents: read
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v6
        with:
          fetch-depth: 0

      # Issue #4302. The complete, repository-required product check set --
      # `.github/required-publication-checks.json`, the one canonical inventory
      # the `main` publisher is also proven set-equal to -- must be successful
      # for the EXACT tag target under trusted workflow identity before any
      # immutable version-tag artifact is built. The previous implementation
      # kept an independent hard-coded subset here that omitted Gateway API
      # Conformance, Ambient Host UDP, and the trusted build policy, and
      # accepted "some successful push run" rather than requiring every matching
      # run to have concluded successfully.
      - name: Require every publish-blocking check for the tag target
        env:
          GH_TOKEN: ${{ github.token }}
          PUBLICATION_GATE_REPOSITORY: ${{ github.repository }}
          TAG_NAME: ${{ github.ref_name }}
        run: |
          set -euo pipefail

          if [[ ! "$TAG_NAME" =~ ^v[0-9]+\\.[0-9]+\\.[0-9]+([-.][0-9A-Za-z.]+)?$ ]]; then
            echo "Invalid release tag format: $TAG_NAME" >&2
            exit 1
          fi

          release_sha="$(git rev-list -n 1 "$TAG_NAME")"
          if [[ ! "$release_sha" =~ ^[0-9a-f]{40}$ ]]; then
            echo "::error::release tag ${TAG_NAME} did not resolve to a commit" >&2
            exit 1
          fi
          echo "Release tag ${TAG_NAME} resolves to ${release_sha}"

          # A tag may point anywhere. Publication evidence is only meaningful
          # for a commit that is on `main`, so prove ancestry from the trusted
          # remote branch before any check result is trusted. The shared gate
          # re-proves this through the compare API as well.
          git fetch --no-tags origin +refs/heads/main:refs/remotes/origin/main
          if ! git merge-base --is-ancestor "$release_sha" refs/remotes/origin/main; then
            echo "::error title=Release target is not on main::${release_sha} is not an ancestor of origin/main" >&2
            exit 1
          fi

          {
            echo "## Release Validation"
            echo ""
            echo "Tag: \\`${TAG_NAME}\\`"
            echo ""
            echo "Commit: \\`${release_sha}\\`"
            echo ""
          } >> "$GITHUB_STEP_SUMMARY"

          # The tag target travels in the environment so this argv stays fully
          # literal for the trusted-policy scanners.
          export PUBLICATION_GATE_SHA="$release_sha"
          python3 .github/scripts/verify_publication_gate.py --self-test
          python3 .github/scripts/verify_publication_gate.py --enforce release --deadline-seconds 9600
"""


def _publication_errors(body: str) -> list[str]:
    return publication_gate_job_errors(
        _wrap_publication_job(body), _gate_inventory()
    )


def _release_errors(body: str) -> list[str]:
    return release_gate_errors(_wrap_release_job(body), _gate_inventory())


def self_test() -> list[str]:
    """Adversarial proofs. Returns a list of failure descriptions."""

    failures: list[str] = []

    def expect(condition: bool, description: str) -> None:
        if not condition:
            failures.append(description)

    # The complete, exact-SHA, trusted set is the ONLY permitting case.
    expect(_enforce(_complete_runs()) == 0, "the complete exact-SHA set must publish")

    # Every non-success run state blocks, for every required workflow.
    for state in (
        {"status": "queued", "conclusion": None},
        {"status": "in_progress", "conclusion": None},
        {"status": "waiting", "conclusion": None},
        {"status": "completed", "conclusion": "failure"},
        {"status": "completed", "conclusion": "cancelled"},
        {"status": "completed", "conclusion": "skipped"},
        {"status": "completed", "conclusion": "timed_out"},
        {"status": "completed", "conclusion": "stale"},
        {"status": "completed", "conclusion": "neutral"},
        {"status": "completed", "conclusion": "action_required"},
        {"status": "completed", "conclusion": "startup_failure"},
        {"status": "completed", "conclusion": None},
        {"status": "surprising", "conclusion": None},
    ):
        runs = _complete_runs()
        runs["alpha.yml"] = [_run(**state)]
        expect(
            _enforce(runs) == 1,
            f"alpha {state} must block publication",
        )
        runs = _complete_runs()
        runs["beta.yml"] = [_beta_run(**state)]
        expect(
            _enforce(runs) == 1,
            f"beta {state} must block publication",
        )

    # A missing run blocks, for each workflow independently.
    for absent in ("alpha.yml", "beta.yml"):
        runs = _complete_runs()
        runs[absent] = []
        expect(_enforce(runs) == 1, f"a missing {absent} run must block publication")

    # One passing duplicate must never mask a failed run of the same workflow.
    runs = _complete_runs()
    runs["alpha.yml"] = [_run(), _run(conclusion="failure")]
    expect(_enforce(runs) == 1, "a failed duplicate run must block publication")

    # Time-of-check/time-of-use: a completed success observed while another
    # required context is still pending must not be cached. GitHub permits
    # rerunning a completed workflow, so the first context can return to
    # queued or fail as the second becomes successful. Both sequences would
    # incorrectly permit under a permanent `proven` set.
    pending_then_success_alpha = _complete_runs()
    pending_then_success_alpha["beta.yml"] = [
        _beta_run(status="in_progress", conclusion=None)
    ]
    later_complete = _complete_runs()
    code, slept = _enforce_across_sweeps(
        [pending_then_success_alpha, later_complete]
    )
    expect(
        code == 0,
        "a later complete exact-SHA sweep must publish after a pending wait",
    )
    expect(
        slept == [POLL_SECONDS],
        "a pending wait must keep the one-minute poll cadence",
    )

    queued_after_success = _complete_runs()
    queued_after_success["alpha.yml"] = [_run(status="queued", conclusion=None)]
    code, slept = _enforce_across_sweeps(
        [pending_then_success_alpha, queued_after_success]
    )
    expect(
        code == 1,
        "a previously successful context that returns to queued while another "
        "succeeds must block publication",
    )
    expect(
        slept and all(interval == POLL_SECONDS for interval in slept),
        "a queued regression must keep waiting at the one-minute cadence",
    )

    failed_after_success = _complete_runs()
    failed_after_success["alpha.yml"] = [_run(conclusion="failure")]
    code, slept = _enforce_across_sweeps(
        [pending_then_success_alpha, failed_after_success]
    )
    expect(
        code == 1,
        "a previously successful context that fails while another succeeds "
        "must block publication",
    )
    expect(
        slept == [POLL_SECONDS],
        "a failure regression must fail closed after one pending wait",
    )

    duplicate_at_permit = _complete_runs()
    duplicate_at_permit["alpha.yml"] = [_run(), _run(conclusion="failure")]
    code, _slept = _enforce_across_sweeps(
        [pending_then_success_alpha, duplicate_at_permit]
    )
    expect(
        code == 1,
        "a failed duplicate that appears only on the permitting sweep must block",
    )

    # Workflow identity cached while pending is not a permitting proof. The
    # all-green path must re-resolve canonical id/path/name/active state; a
    # rename or disable that lands during the wait must fail closed.
    code, _slept = _enforce_across_sweeps(
        [pending_then_success_alpha, later_complete],
        workflow_mutations=[
            {},
            {"alpha.yml": {"name": "Alpha Workflow v2"}},
        ],
    )
    expect(
        code == 1,
        "a workflow renamed after a pending wait must not permit on cached identity",
    )
    code, _slept = _enforce_across_sweeps(
        [pending_then_success_alpha, later_complete],
        workflow_mutations=[
            {},
            {"alpha.yml": {"state": "disabled_manually"}},
        ],
    )
    expect(
        code == 1,
        "a workflow disabled after a pending wait must not permit on cached identity",
    )

    # Identity: wrong SHA, event, branch, path, workflow id, and name.
    for label, override in (
        ("wrong sha", {"head_sha": "b" * 40}),
        ("wrong event", {"event": "workflow_dispatch"}),
        ("wrong branch", {"branch": "release-1.0"}),
        ("wrong path", {"path": ".github/workflows/decoy.yml"}),
        ("wrong workflow id", {"workflow_id": 99}),
        ("display-name-only match", {"name": "Alpha Workflow (mirror)"}),
    ):
        runs = _complete_runs()
        runs["alpha.yml"] = [_run(**override)]
        expect(_enforce(runs) == 1, f"{label} must block publication")

    # Repository identity must be proven independently on both objects.
    # Missing or malformed values block exactly like a fork mismatch.
    _absent = object()
    for field in ("repository", "head_repository"):
        for label, value in (
            ("absent", _absent),
            ("null", None),
            ("string", "ferrum-edge/ferrum-edge"),
            ("list", [{"full_name": "ferrum-edge/ferrum-edge"}]),
            ("empty object", {}),
            ("mismatch", {"full_name": "attacker/ferrum-edge"}),
        ):
            runs = _complete_runs()
            run = _run()
            if value is _absent:
                del run[field]
            else:
                run[field] = value
            runs["alpha.yml"] = [run]
            expect(
                _enforce(runs) == 1,
                f"{label} {field} must block publication",
            )

    # Pagination: collect every page, fail closed on a full ceiling page, and
    # reject malformed listing members. Queries stay bound to exact SHA/event.
    listing_entry = _fixture_inventory()["required_checks"][0]
    requested_paths: list[str] = []

    def _paged_get(pages: list[list[object]]):
        requested_paths.clear()

        def get(path: str) -> object:
            requested_paths.append(path)
            query = urllib.parse.parse_qs(urllib.parse.urlparse(path).query)
            page = int((query.get("page") or ["1"])[0])
            if page > len(pages):
                return {"workflow_runs": []}
            return {"workflow_runs": pages[page - 1]}

        return get

    page_one = [_run(run_id=1), _run(run_id=2)]
    page_two = [_run(run_id=3)]
    collected = list_runs(
        _paged_get([page_one, page_two]),
        "ferrum-edge/ferrum-edge",
        listing_entry,
        _SHA,
        "push",
        page_size=2,
        max_pages=5,
    )
    expect(
        [run["id"] for run in collected] == [1, 2, 3],
        "ordinary multi-page collection must return every run",
    )
    expect(
        all(
            f"head_sha={_SHA}" in path and "event=push" in path
            for path in requested_paths
        ),
        "run listing must stay bound to exact head_sha and expected event",
    )

    extra = _complete_runs()
    extra["alpha.yml"] = [_run(run_id=index) for index in range(PAGE_SIZE + 1)]
    expect(
        _enforce(extra) == 0,
        "ordinary multi-page exact-SHA success must still publish",
    )
    later_failure = _complete_runs()
    later_failure["alpha.yml"] = [
        *[_run(run_id=index) for index in range(PAGE_SIZE)],
        _run(run_id=PAGE_SIZE, conclusion="failure"),
    ]
    expect(
        _enforce(later_failure) == 1,
        "a failed run beyond the first listing page must block publication",
    )

    full_pages = [
        [_run(run_id=page * 2), _run(run_id=page * 2 + 1)] for page in range(3)
    ]
    try:
        list_runs(
            _paged_get(full_pages),
            "ferrum-edge/ferrum-edge",
            listing_entry,
            _SHA,
            "push",
            page_size=2,
            max_pages=3,
        )
        ceiling_blocked = False
    except ApiFailure:
        ceiling_blocked = True
    expect(
        ceiling_blocked,
        "a full final allowed listing page must fail closed",
    )

    for label, member in (
        ("string", "not-a-run"),
        ("null", None),
        ("list", [_run()]),
        ("integer", 1),
    ):
        try:
            list_runs(
                _paged_get([[_run(), member]]),
                "ferrum-edge/ferrum-edge",
                listing_entry,
                _SHA,
                "push",
                page_size=10,
                max_pages=5,
            )
            malformed_listing = False
        except ApiFailure:
            malformed_listing = True
        expect(
            malformed_listing,
            f"a {label} workflow_runs member must fail closed",
        )
        runs = _complete_runs()
        runs["alpha.yml"] = [_run(), member]
        try:
            code = _enforce(runs)
        except ApiFailure:
            code = 1
        expect(code == 1, f"a {label} workflow_runs member must block publication")

    # Merge-group evidence must come from a merge-queue branch for main.
    runs = _complete_runs()
    runs["beta.yml"] = [_beta_run(branch="gh-readonly-queue/release/pr-1-abc")]
    expect(_enforce(runs) == 1, "a non-main merge-queue branch must block publication")
    runs = _complete_runs()
    runs["beta.yml"] = [_beta_run(branch="main", event="push")]
    expect(_enforce(runs) == 1, "a push run must not satisfy merge-group evidence")

    # Ancestry: only a commit on `main` may publish.
    for status in ("ahead", "diverged", None):
        expect(
            _enforce(_complete_runs(), compare_status=status) == 1,
            f"compare status {status!r} must block publication",
        )

    # A renamed, deleted, or disabled workflow fails closed rather than passing.
    def broken_transport(mutation):
        base = _transport(_complete_runs())

        def get(path: str) -> object:
            payload = base(path)
            if (
                isinstance(payload, dict)
                and "workflow_runs" not in payload
                and "status" not in payload
            ):
                payload = dict(payload)
                payload.update(mutation)
            return payload

        return get

    for label, mutation in (
        ("disabled workflow", {"state": "disabled_manually"}),
        ("renamed workflow", {"name": "Alpha Workflow v2"}),
        ("relocated workflow", {"path": ".github/workflows/moved.yml"}),
    ):
        inventory = _fixture_inventory()
        try:
            code = enforce(
                broken_transport(mutation),
                "ferrum-edge/ferrum-edge",
                _SHA,
                inventory,
                select_entries(inventory, "main"),
                deadline_seconds=0,
                sleep=lambda _seconds: None,
                monotonic=lambda: 1.0,
                log=lambda *_args, **_kwargs: None,
            )
        except ApiFailure:
            code = 1
        expect(code == 1, f"{label} must block publication")

    # A malformed SHA never reaches the API.
    inventory = _fixture_inventory()
    expect(
        enforce(
            _transport(_complete_runs()),
            "ferrum-edge/ferrum-edge",
            "not-a-sha",
            inventory,
            select_entries(inventory, "main"),
            deadline_seconds=0,
            sleep=lambda _seconds: None,
            monotonic=lambda: 1.0,
            log=lambda *_args, **_kwargs: None,
        )
        == 1,
        "a malformed SHA must block publication",
    )

    # `release` enforcement covers the COMPLETE inventory, not a subset.
    expect(
        {entry["context"] for entry in select_entries(inventory, "release")}
        == {entry["context"] for entry in entries(inventory)},
        "release enforcement must cover every inventory entry",
    )
    expect(
        {entry["context"] for entry in select_entries(inventory, "main")}
        == {
            entry["context"]
            for entry in entries(inventory)
            if entry["main_publication"] == "publication_gate_job"
        },
        "main enforcement must select exactly the hosted-gate contexts",
    )

    # Static contract: a newly required context with no inventory entry fails.
    real = _fixture_inventory()
    required = {
        ".github/workflows/alpha.yml": "Alpha",
        ".github/workflows/beta.yml": "Beta",
    }
    expect(
        required_context_parity_errors(required, real) == [],
        "the matching required set must produce no parity error",
    )
    expect(
        required_context_parity_errors(
            {**required, ".github/workflows/gamma.yml": "Gamma"},
            real,
        )
        != [],
        "a newly required context missing from the inventory must fail",
    )
    expect(
        required_context_parity_errors(
            {".github/workflows/alpha.yml": "Alpha"},
            real,
        )
        != [],
        "an inventory entry that is not branch-protection-required must fail",
    )
    expect(
        required_context_parity_errors(
            {
                ".github/workflows/alpha.yml": "Alpha renamed",
                ".github/workflows/beta.yml": "Beta",
            },
            real,
        )
        != [],
        "a renamed required context must fail parity",
    )

    # Static contract: the frozen ci.yml array must equal the inventory subset.
    gate_inventory = {
        **real,
        "required_checks": [
            {
                "context": "Alpha",
                "workflow_file": "alpha.yml",
                "workflow_path": ".github/workflows/alpha.yml",
                "workflow_name": "Alpha Workflow",
                "job": "gate",
                "main_publication": "ci_main_publish_gate",
                "evidence": "push_main",
                "rationale": "self-test",
            }
        ],
    }
    conforming_ci = (
        "jobs:\n"
        "  main-publish-gate:\n"
        "    steps:\n"
        "      - run: |\n"
        "          required_workflow_specs=(\n"
        '            "alpha.yml|.github/workflows/alpha.yml|Alpha Workflow"\n'
        "          )\n"
        "  next-job:\n"
        "    steps: []\n"
    )
    expect(
        main_publish_gate_parity_errors(conforming_ci, gate_inventory) == [],
        "a matching main-publish-gate array must produce no error",
    )
    expect(
        main_publish_gate_parity_errors(
            conforming_ci.replace("Alpha Workflow\"", "Decoy Workflow\""),
            gate_inventory,
        )
        != [],
        "a display-name drift in the frozen array must fail",
    )
    expect(
        main_publish_gate_parity_errors(
            conforming_ci.replace(
                '            "alpha.yml|.github/workflows/alpha.yml|Alpha Workflow"\n',
                "",
            ),
            gate_inventory,
        )
        != [],
        "an emptied main-publish-gate array must fail",
    )
    expect(
        main_publish_gate_parity_errors(
            "jobs:\n  other:\n    steps: []\n",
            gate_inventory,
        )
        != [],
        "a missing main-publish-gate job must fail",
    )

    # Static contract: inventory schema defects are rejected.
    for label, mutation in (
        ("unknown mode", {"main_publication": "somewhere_else"}),
        ("unknown evidence", {"evidence": "trust_me"}),
        ("empty rationale", {"rationale": "  "}),
        ("path mismatch", {"workflow_path": ".github/workflows/other.yml"}),
    ):
        broken = _fixture_inventory()
        broken["required_checks"][0].update(mutation)
        expect(inventory_errors(broken) != [], f"{label} must fail the schema")
    duplicated = _fixture_inventory()
    duplicated["required_checks"].append(dict(duplicated["required_checks"][0]))
    expect(inventory_errors(duplicated) != [], "a duplicate context must fail")
    expect(inventory_errors(_fixture_inventory()) == [], "the fixture must be valid")

    # Static contract: hosted publication-gate and release-gate jobs are
    # proven by exact active structure, not raw substring search.
    expect(
        _publication_errors(_CONFORMING_PUBLICATION_JOB) == [],
        "the exact hosted publication-gate job must pass",
    )
    expect(
        _release_errors(_CONFORMING_RELEASE_JOB) == [],
        "the exact validate-release-sha job must pass",
    )

    commented_enforce = _CONFORMING_PUBLICATION_JOB.replace(
        "          python3 .github/scripts/verify_publication_gate.py --enforce main --deadline-seconds 6000\n",
        "          # python3 .github/scripts/verify_publication_gate.py --enforce main --deadline-seconds 6000\n",
    )
    expect(
        _publication_errors(commented_enforce) != [],
        "a comment-only enforce command must fail the publication-gate job",
    )
    commented_scope = _CONFORMING_PUBLICATION_JOB.replace(
        "    if: github.event_name == 'push' && github.ref == 'refs/heads/main'\n",
        "    # if: github.event_name == 'push' && github.ref == 'refs/heads/main'\n"
        "    if: always()\n",
    )
    expect(
        _publication_errors(commented_scope) != [],
        "a comment-only main-push scope must fail the publication-gate job",
    )
    commented_permissions = _CONFORMING_PUBLICATION_JOB.replace(
        "    permissions:\n      contents: read\n      actions: read\n",
        "    permissions:\n      contents: write\n      actions: write\n"
        "      # contents: read\n      # actions: read\n",
    )
    expect(
        _publication_errors(commented_permissions) != [],
        "comment-only read permissions must fail the publication-gate job",
    )
    unrelated_step = _CONFORMING_PUBLICATION_JOB.replace(
        "      - name: Prove every publish-blocking required check passed for this SHA\n"
        "        env:\n"
        "          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n"
        "          PUBLICATION_GATE_REPOSITORY: ${{ github.repository }}\n"
        "          PUBLICATION_GATE_SHA: ${{ github.sha }}\n"
        "        run: |\n"
        "          set -euo pipefail\n"
        "\n"
        "          # The commit and repository travel in the environment so this argv\n"
        "          # stays fully literal: a trusted-policy scan can read exactly what\n"
        "          # this step executes without resolving a shell expansion.\n"
        "          python3 .github/scripts/verify_publication_gate.py --self-test\n"
        "          python3 .github/scripts/verify_publication_gate.py --enforce main --deadline-seconds 6000\n",
        "      - name: Unrelated decoy\n"
        "        run: |\n"
        "          python3 .github/scripts/verify_publication_gate.py --self-test\n"
        "          python3 .github/scripts/verify_publication_gate.py --enforce main --deadline-seconds 6000\n"
        "      - name: Prove every publish-blocking required check passed for this SHA\n"
        "        env:\n"
        "          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n"
        "          PUBLICATION_GATE_REPOSITORY: ${{ github.repository }}\n"
        "          PUBLICATION_GATE_SHA: ${{ github.sha }}\n"
        "        run: |\n"
        "          set -euo pipefail\n"
        "          echo skipped\n",
    )
    expect(
        _publication_errors(unrelated_step) != [],
        "a required command in an unrelated step must fail the publication-gate job",
    )
    missing_enforce = _CONFORMING_PUBLICATION_JOB.replace(
        "          python3 .github/scripts/verify_publication_gate.py --enforce main --deadline-seconds 6000\n",
        "",
    )
    expect(
        _publication_errors(missing_enforce) != [],
        "a missing active enforce command must fail the publication-gate job",
    )
    altered_deadline = _CONFORMING_PUBLICATION_JOB.replace(
        "--deadline-seconds 6000",
        "--deadline-seconds 1",
    )
    expect(
        _publication_errors(altered_deadline) != [],
        "an altered enforce deadline must fail the publication-gate job",
    )
    extra_write = _CONFORMING_PUBLICATION_JOB.replace(
        "      contents: read\n      actions: read\n",
        "      contents: read\n      actions: read\n      packages: write\n",
    )
    expect(
        _publication_errors(extra_write) != [],
        "an extra write permission must fail the publication-gate job",
    )
    continue_on_error = _CONFORMING_PUBLICATION_JOB.replace(
        "    timeout-minutes: 110\n",
        "    timeout-minutes: 110\n    continue-on-error: true\n",
    )
    expect(
        _publication_errors(continue_on_error) != [],
        "continue-on-error on the publication-gate job must fail",
    )
    duplicate_permissions = _CONFORMING_PUBLICATION_JOB.replace(
        "    permissions:\n      contents: read\n      actions: read\n",
        "    permissions:\n      contents: read\n      actions: read\n"
        "    permissions:\n      contents: write\n      actions: write\n",
    )
    expect(
        _publication_errors(duplicate_permissions) != [],
        "duplicate permissions mappings must fail the publication-gate job",
    )
    flow_permissions = _CONFORMING_PUBLICATION_JOB.replace(
        "    permissions:\n      contents: read\n      actions: read\n",
        "    permissions: { contents: read, actions: read }\n",
    )
    expect(
        _publication_errors(flow_permissions) != [],
        "flow-spelled permissions must fail the publication-gate job",
    )
    opaque_permissions = _CONFORMING_PUBLICATION_JOB.replace(
        "    permissions:\n      contents: read\n      actions: read\n",
        "    permissions: read-all\n",
    )
    expect(
        _publication_errors(opaque_permissions) != [],
        "opaque permissions: read-all must fail the publication-gate job",
    )
    reordered_permissions = _CONFORMING_PUBLICATION_JOB.replace(
        "      contents: read\n      actions: read\n",
        "      actions: read\n      contents: read\n",
    )
    expect(
        _publication_errors(reordered_permissions) != [],
        "reordered permission keys must fail the publication-gate job",
    )
    job_level_env = _CONFORMING_PUBLICATION_JOB.replace(
        "    timeout-minutes: 110\n",
        "    timeout-minutes: 110\n"
        "    env:\n"
        "      GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n"
        "      PUBLICATION_GATE_REPOSITORY: ${{ github.repository }}\n"
        "      PUBLICATION_GATE_SHA: ${{ github.sha }}\n",
    ).replace(
        "        env:\n"
        "          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n"
        "          PUBLICATION_GATE_REPOSITORY: ${{ github.repository }}\n"
        "          PUBLICATION_GATE_SHA: ${{ github.sha }}\n",
        "",
    )
    expect(
        _publication_errors(job_level_env) != [],
        "env owned by the job instead of the named proof step must fail",
    )
    wrong_sha_env = _CONFORMING_PUBLICATION_JOB.replace(
        "PUBLICATION_GATE_SHA: ${{ github.sha }}",
        "PUBLICATION_GATE_SHA: ${{ github.event.pull_request.head.sha }}",
    )
    expect(
        _publication_errors(wrong_sha_env) != [],
        "a wrong proof-step env value must fail the publication-gate job",
    )
    missing_checkout = _CONFORMING_PUBLICATION_JOB.replace(
        "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v6\n\n",
        "",
    )
    expect(
        _publication_errors(missing_checkout) != [],
        "a missing checkout step must fail the publication-gate job",
    )
    wrong_pin = _CONFORMING_PUBLICATION_JOB.replace(
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
        "actions/checkout@v6",
    )
    expect(
        _publication_errors(wrong_pin) != [],
        "a wrong checkout pin must fail the publication-gate job",
    )
    folded_run = _CONFORMING_PUBLICATION_JOB.replace("        run: |\n", "        run: >\n")
    expect(
        _publication_errors(folded_run) != [],
        "a folded run block must fail the publication-gate job",
    )

    release_commented_enforce = _CONFORMING_RELEASE_JOB.replace(
        "          python3 .github/scripts/verify_publication_gate.py --enforce release --deadline-seconds 9600\n",
        "          # python3 .github/scripts/verify_publication_gate.py --enforce release --deadline-seconds 9600\n",
    )
    expect(
        _release_errors(release_commented_enforce) != [],
        "a comment-only release enforce command must fail",
    )
    release_unrelated = _CONFORMING_RELEASE_JOB.replace(
        "      - name: Require every publish-blocking check for the tag target\n",
        "      - name: Unrelated decoy\n"
        "        run: |\n"
        "          python3 .github/scripts/verify_publication_gate.py --self-test\n"
        "          python3 .github/scripts/verify_publication_gate.py --enforce release --deadline-seconds 9600\n"
        "      - name: Require every publish-blocking check for the tag target\n",
    )
    expect(
        _release_errors(release_unrelated) != [],
        "a required release command in an unrelated step must fail",
    )
    release_missing_export = _CONFORMING_RELEASE_JOB.replace(
        '          export PUBLICATION_GATE_SHA="$release_sha"\n',
        "",
    )
    expect(
        _release_errors(release_missing_export) != [],
        "a missing active SHA export must fail the release gate",
    )
    release_extra_write = _CONFORMING_RELEASE_JOB.replace(
        "      actions: read\n      contents: read\n",
        "      actions: read\n      contents: read\n      packages: write\n",
    )
    expect(
        _release_errors(release_extra_write) != [],
        "an extra write permission must fail the release gate",
    )
    release_continue = _CONFORMING_RELEASE_JOB.replace(
        "    timeout-minutes: 350\n",
        "    timeout-minutes: 350\n    continue-on-error: true\n",
    )
    expect(
        _release_errors(release_continue) != [],
        "continue-on-error on validate-release-sha must fail",
    )
    release_flow_permissions = _CONFORMING_RELEASE_JOB.replace(
        "    permissions:\n      actions: read\n      contents: read\n",
        "    permissions: { actions: read, contents: read }\n",
    )
    expect(
        _release_errors(release_flow_permissions) != [],
        "flow-spelled release permissions must fail",
    )
    release_duplicate = _CONFORMING_RELEASE_JOB.replace(
        "    permissions:\n      actions: read\n      contents: read\n",
        "    permissions:\n      actions: read\n      contents: read\n"
        "    permissions:\n      contents: write\n",
    )
    expect(
        _release_errors(release_duplicate) != [],
        "duplicate release permission mappings must fail",
    )
    release_wrong_env = _CONFORMING_RELEASE_JOB.replace(
        "PUBLICATION_GATE_REPOSITORY: ${{ github.repository }}",
        "PUBLICATION_GATE_REPOSITORY: ${{ github.event.pull_request.head.repo.full_name }}",
    )
    expect(
        _release_errors(release_wrong_env) != [],
        "a wrong release proof-step env value must fail",
    )
    release_job_env = _CONFORMING_RELEASE_JOB.replace(
        "    timeout-minutes: 350\n",
        "    timeout-minutes: 350\n"
        "    env:\n"
        "      GH_TOKEN: ${{ github.token }}\n"
        "      PUBLICATION_GATE_REPOSITORY: ${{ github.repository }}\n"
        "      TAG_NAME: ${{ github.ref_name }}\n",
    ).replace(
        "        env:\n"
        "          GH_TOKEN: ${{ github.token }}\n"
        "          PUBLICATION_GATE_REPOSITORY: ${{ github.repository }}\n"
        "          TAG_NAME: ${{ github.ref_name }}\n",
        "",
    )
    expect(
        _release_errors(release_job_env) != [],
        "release env owned by the job instead of the named step must fail",
    )
    release_missing_checkout = _CONFORMING_RELEASE_JOB.replace(
        "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v6\n"
        "        with:\n"
        "          fetch-depth: 0\n\n",
        "",
    )
    expect(
        _release_errors(release_missing_checkout) != [],
        "a missing release checkout must fail",
    )
    release_wrong_pin = _CONFORMING_RELEASE_JOB.replace(
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
        "actions/checkout@0000000000000000000000000000000000000000",
    )
    expect(
        _release_errors(release_wrong_pin) != [],
        "a wrong release checkout pin must fail",
    )
    release_opaque_timeout = _CONFORMING_RELEASE_JOB.replace(
        "    timeout-minutes: 350\n",
        "    timeout-minutes: |\n      350\n",
    )
    expect(
        _release_errors(release_opaque_timeout) != [],
        "an opaque release timeout spelling must fail",
    )
    missing_ancestry = _CONFORMING_RELEASE_JOB.replace(
        '          if ! git merge-base --is-ancestor "$release_sha" refs/remotes/origin/main; then\n',
        '          if ! true; then\n',
    )
    expect(
        _release_errors(missing_ancestry) != [],
        "a missing active ancestry proof must fail the release gate",
    )

    # Whole-jobs mapping: YAML-equivalent or opaque protected job keys fail
    # closed even when a canonical decoy is the only header the old regex
    # would inspect. `_publication_errors` / `_release_errors` wrap the
    # canonical job; extra sibling keys are appended at the `jobs:` indent.
    quoted_publication_after = _CONFORMING_PUBLICATION_JOB + (
        f'  "{PUBLICATION_GATE_JOB}":\n    name: Attack\n    if: always()\n'
    )
    expect(
        _publication_errors(quoted_publication_after) != [],
        "a quoted duplicate immediately after the publication-gate job must fail",
    )
    single_quoted_publication_after = _CONFORMING_PUBLICATION_JOB + (
        f"  '{PUBLICATION_GATE_JOB}':\n    name: Attack\n    if: always()\n"
    )
    expect(
        _publication_errors(single_quoted_publication_after) != [],
        "a single-quoted duplicate immediately after the publication-gate job must fail",
    )
    escaped_publication_after = _CONFORMING_PUBLICATION_JOB + (
        '  "main-publication-required-check\\u0073":\n    name: Attack\n'
    )
    expect(
        _publication_errors(escaped_publication_after) != [],
        "an escaped quoted duplicate of the publication-gate job must fail",
    )
    publication_after_intervening = _CONFORMING_PUBLICATION_JOB + (
        "  ordinary-job:\n    runs-on: ubuntu-latest\n"
        f'  "{PUBLICATION_GATE_JOB}":\n    name: Attack\n    if: always()\n'
    )
    expect(
        _publication_errors(publication_after_intervening) != [],
        "a quoted publication-gate duplicate after an intervening job must fail",
    )
    publication_quoted_before = (
        f'jobs:\n  "{PUBLICATION_GATE_JOB}":\n    name: Attack\n    if: always()\n'
        f"  {PUBLICATION_GATE_JOB}:\n{_CONFORMING_PUBLICATION_JOB}"
    )
    expect(
        publication_gate_job_errors(publication_quoted_before, _gate_inventory())
        != [],
        "a quoted publication-gate duplicate before the canonical job must fail",
    )
    publication_quoted_only = (
        f'jobs:\n  "{PUBLICATION_GATE_JOB}":\n{_CONFORMING_PUBLICATION_JOB}'
    )
    expect(
        publication_gate_job_errors(publication_quoted_only, _gate_inventory()) != [],
        "a quoted-only replacement of the publication-gate job must fail",
    )
    publication_opaque_key = _CONFORMING_PUBLICATION_JOB + (
        f"  ? {PUBLICATION_GATE_JOB}\n  :\n    name: Attack\n"
    )
    expect(
        _publication_errors(publication_opaque_key) != [],
        "an opaque explicit-key duplicate of the publication-gate job must fail",
    )
    try:
        _parse_job(
            _CONFORMING_PUBLICATION_JOB + '  "smuggled":\n    name: Attack\n'
        )
        publication_unconsumed = False
    except StructuralError:
        publication_unconsumed = True
    expect(
        publication_unconsumed,
        "unconsumed lower-indentation content in a publication job region must fail",
    )

    quoted_release_after = _CONFORMING_RELEASE_JOB + (
        f'  "{RELEASE_GATE_JOB}":\n    name: Attack\n'
    )
    expect(
        _release_errors(quoted_release_after) != [],
        "a quoted duplicate immediately after validate-release-sha must fail",
    )
    release_after_intervening = _wrap_release_job(_CONFORMING_RELEASE_JOB) + (
        f'  "{RELEASE_GATE_JOB}":\n    name: Attack\n'
    )
    expect(
        release_gate_errors(release_after_intervening, _gate_inventory()) != [],
        "a quoted validate-release-sha duplicate after an intervening job must fail",
    )
    release_quoted_before = (
        f'jobs:\n  "{RELEASE_GATE_JOB}":\n    name: Attack\n'
        f"  {RELEASE_GATE_JOB}:\n{_CONFORMING_RELEASE_JOB}"
        "  next-job:\n    runs-on: ubuntu-latest\n"
    )
    expect(
        release_gate_errors(release_quoted_before, _gate_inventory()) != [],
        "a quoted validate-release-sha duplicate before the canonical job must fail",
    )
    release_opaque_key = _CONFORMING_RELEASE_JOB + (
        f"  ? {RELEASE_GATE_JOB}\n  :\n    name: Attack\n"
    )
    expect(
        _release_errors(release_opaque_key) != [],
        "an opaque explicit-key duplicate of validate-release-sha must fail",
    )
    try:
        _parse_job(_CONFORMING_RELEASE_JOB + '  "smuggled":\n    name: Attack\n')
        release_unconsumed = False
    except StructuralError:
        release_unconsumed = True
    expect(
        release_unconsumed,
        "unconsumed lower-indentation content in a release job region must fail",
    )

    return failures


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def repository_contract_errors(
    required_contexts: dict[str, str],
    root: Path | None = None,
) -> list[str]:
    """Run the static contract against the real repository files.

    `required_contexts` is supplied by the caller -- `verify_required_ci.py`
    passes its own branch-protection required table -- so the parity proof is
    never self-referential.
    """

    base = Path(".") if root is None else root

    def read(path: str) -> str:
        return (base / path).read_text(encoding="utf-8")

    return contract_errors(load_inventory(base), required_contexts, read)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--enforce", choices=("main", "release"))
    # Both operands are read from the environment so every invocation in a
    # workflow keeps a fully literal argv. The flags exist for ad-hoc use.
    parser.add_argument(
        "--sha",
        default=os.environ.get("PUBLICATION_GATE_SHA", ""),
    )
    parser.add_argument(
        "--repository",
        default=(
            os.environ.get("PUBLICATION_GATE_REPOSITORY")
            or os.environ.get("GITHUB_REPOSITORY")
            or ""
        ),
    )
    parser.add_argument("--deadline-seconds", type=int, default=3600)
    arguments = parser.parse_args(argv)

    if arguments.self_test:
        failures = self_test()
        for failure in failures:
            print(f"::error::publication gate self-test: {failure}", file=sys.stderr)
        if failures:
            return 1
        print("publication gate self-test passed")
        if arguments.enforce is None:
            return 0

    if arguments.enforce is None:
        return 0

    if not arguments.sha or not arguments.repository:
        print(
            "::error::--enforce requires PUBLICATION_GATE_SHA/--sha and "
            "PUBLICATION_GATE_REPOSITORY/--repository",
            file=sys.stderr,
        )
        return 1

    inventory = load_inventory()
    schema_errors = inventory_errors(inventory)
    for error in schema_errors:
        print(f"::error::{error}", file=sys.stderr)
    if schema_errors:
        return 1

    selected = select_entries(inventory, arguments.enforce)
    try:
        return enforce(
            http_get(
                os.environ.get("GH_TOKEN")
                or os.environ.get("GITHUB_TOKEN")
                or ""
            ),
            arguments.repository,
            arguments.sha,
            inventory,
            selected,
            arguments.deadline_seconds,
        )
    except (ApiFailure, ContractError) as error:
        print(f"::error::{error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
