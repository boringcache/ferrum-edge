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
  SHA under the expected event and branch. Missing, queued, in-progress, waiting,
  failed, cancelled, skipped, timed-out, stale, neutral, and unknown results are
  all blocking, as are wrong-SHA, wrong-event, wrong-branch, wrong-path,
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
# well over an hour. Poll once a minute, resolve each workflow's identity once,
# and stop querying a context after it is proven, so a long wait on one slow
# suite cannot exhaust the budget the gate itself depends on.
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


def job_body(contents: str, job: str) -> str | None:
    match = re.search(_JOB_BODY.format(job=re.escape(job)), contents)
    return None if match is None else match.group("body")


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
    """Prove the hosted publication gate exists, is main-scoped, and fails closed."""

    errors: list[str] = []
    body = job_body(gateway_yml, PUBLICATION_GATE_JOB)
    if body is None:
        errors.append(
            f"{PUBLICATION_GATE_WORKFLOW_PATH} must define the "
            f"`{PUBLICATION_GATE_JOB}` job that carries every "
            "`publication_gate_job` required context"
        )
        return errors
    for marker in (
        "github.event_name == 'push'",
        "github.ref == 'refs/heads/main'",
    ):
        if marker not in body:
            errors.append(
                f"{PUBLICATION_GATE_WORKFLOW_PATH} jobs.{PUBLICATION_GATE_JOB} "
                f"must stay scoped by `{marker}`"
            )
    if "contents: read" not in body or "actions: read" not in body:
        errors.append(
            f"{PUBLICATION_GATE_WORKFLOW_PATH} jobs.{PUBLICATION_GATE_JOB} must "
            "request the least-privilege pair `contents: read` (checkout) and "
            "`actions: read` (run conclusions)"
        )
    for argument in (
        "python3 .github/scripts/verify_publication_gate.py --self-test",
        "python3 .github/scripts/verify_publication_gate.py --enforce main",
        "PUBLICATION_GATE_REPOSITORY: ${{ github.repository }}",
    ):
        if argument not in body:
            errors.append(
                f"{PUBLICATION_GATE_WORKFLOW_PATH} jobs.{PUBLICATION_GATE_JOB} "
                f"must run the shared gate with `{argument}`"
            )
    if "PUBLICATION_GATE_SHA: ${{ github.sha }}" not in body:
        errors.append(
            f"{PUBLICATION_GATE_WORKFLOW_PATH} jobs.{PUBLICATION_GATE_JOB} must "
            "bind the gate to `github.sha`, the exact product commit"
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
    """Prove the version-release verifier consumes the same inventory."""

    errors: list[str] = []
    body = job_body(release_yml, RELEASE_GATE_JOB)
    if body is None:
        return [f"{RELEASE_WORKFLOW_PATH} must define `{RELEASE_GATE_JOB}`"]
    for argument in (
        "python3 .github/scripts/verify_publication_gate.py --self-test",
        "python3 .github/scripts/verify_publication_gate.py --enforce release",
        'export PUBLICATION_GATE_SHA="$release_sha"',
        "PUBLICATION_GATE_REPOSITORY: ${{ github.repository }}",
    ):
        if argument not in body:
            errors.append(
                f"{RELEASE_WORKFLOW_PATH} jobs.{RELEASE_GATE_JOB} must run the "
                f"shared publication gate with `{argument}`"
            )
    if "git merge-base --is-ancestor" not in body:
        errors.append(
            f"{RELEASE_WORKFLOW_PATH} jobs.{RELEASE_GATE_JOB} must prove the tag "
            "target is an ancestor of `main` before trusting any evidence"
        )
    if "contents: read" not in body or "actions: read" not in body:
        errors.append(
            f"{RELEASE_WORKFLOW_PATH} jobs.{RELEASE_GATE_JOB} must keep the "
            "least-privilege pair `contents: read` (checkout) and "
            "`actions: read` (run conclusions)"
        )
    # Nothing may re-introduce an independent hard-coded subset next to the
    # inventory-driven gate.
    if "wait_for_success" in body:
        errors.append(
            f"{RELEASE_WORKFLOW_PATH} jobs.{RELEASE_GATE_JOB} must not keep a "
            "hard-coded per-workflow wait list beside the canonical inventory"
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
    """Return ("success" | "pending" | "blocked", diagnostic) for one context."""

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
    """Poll until every selected context is proven successful, or fail closed."""

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
    proven: set[str] = set()
    while True:
        pending: list[str] = []
        for entry in selected:
            if entry["context"] in proven:
                continue
            verdict, message = evaluate_entry(
                get,
                repository,
                sha,
                entry,
                queue_prefix,
                resolved,
            )
            if verdict == "blocked":
                log(f"::error::{message}")
                return 1
            if verdict == "pending":
                pending.append(message)
            else:
                proven.add(entry["context"])
                log(message)
        if not pending:
            log(
                f"All {len(selected)} publish-blocking required checks passed for {sha}."
            )
            return 0
        for message in pending:
            log(f"Waiting: {message}")
        if monotonic() - start >= deadline_seconds:
            log(
                "::error::timed out waiting for publish-blocking required checks "
                f"for {sha}: {'; '.join(pending)}"
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
