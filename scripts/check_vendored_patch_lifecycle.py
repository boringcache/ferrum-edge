#!/usr/bin/env python3
"""Validate vendored-patch lifecycle inventory parity and upstream status.

The canonical inventory lives in docs/vendored-patch-lifecycle.json. CI runs the
default parity mode on every PR (dependency-audit job) and the weekly
dependency-audit workflow runs --upstream-status after parity passes.

Parity mode fails closed when the lifecycle contract drifts from:
  - root Cargo.toml [patch.crates-io]
  - tests/performance/mesh/Cargo.toml mirrored [patch.crates-io]
  - vendor/*-ferrum-patched directories
  - scripts/check_vendored_patch_status.sh safe wrapper delegation
  - docs/dependency-policy.md inventory Lifecycle ID set
  - per-patch README.md paths

Upstream mode queries filed upstream PRs via the GitHub REST API and reports deliberate forks
that still need filing or dated owner reaffirmation before the first stable
release checkpoint (docs/dependency-policy.md).

--self-test exercises shape/wrapper/policy-ID validators with synthetic fixtures
only (no network, no repository mutation).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.request
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
LIFECYCLE_PATH = ROOT / "docs" / "vendored-patch-lifecycle.json"
POLICY_PATH = ROOT / "docs" / "dependency-policy.md"
ROOT_CARGO = ROOT / "Cargo.toml"
MESH_PERF_CARGO = ROOT / "tests" / "performance" / "mesh" / "Cargo.toml"
PATCH_STATUS_SCRIPT = ROOT / "scripts" / "check_vendored_patch_status.sh"
VENDOR_ROOT = ROOT / "vendor"

COMPATIBLE_RELEASE_STATUSES = frozenset(
    {"not_started", "in_progress", "passed", "failed", "blocked"}
)
UPSTREAM_FILINGS = frozenset({"filed", "deliberate_fork_unfiled"})
REQUIRED_PATCH_STRING_FIELDS = (
    "id",
    "label",
    "crate",
    "vendored_version",
    "vendor_path",
    "docs_path",
    "owner",
    "reason",
)
REAFFIRMATION_RE = re.compile(
    r"re-affirmed\s+(\d{4}-\d{2}-\d{2})\s+by\s+([^:\n]+):\s*(.+)",
    re.IGNORECASE,
)
# Inventory rows: | `lifecycle-id` | `crate` | ver | Patch | Upstream | Owner | Reason | Removal | Docs |
INVENTORY_ROW_RE = re.compile(
    r"^\|\s*`([^`]+)`\s*\|\s*`[^`]+`\s*\|\s*[^|\n]+\|\s*[^|\n]+\|\s*[^|\n]+\|\s*[^|\n]+\|\s*[^|\n]+\|\s*[^|\n]+\|\s*\["
)
GITHUB_REPO_RE = re.compile(r"^[\w.-]+/[\w.-]+$")
WRAPPER_DIR_ASSIGN_RE = re.compile(
    r'^SCRIPT_DIR="\$\(CDPATH= cd -- "\$\(dirname -- "\$0"\)" && pwd\)"$'
)
WRAPPER_EXEC_RE = re.compile(
    r'^exec python3 "\$SCRIPT_DIR/check_vendored_patch_lifecycle\.py" --upstream-status$'
)
USER_AGENT = "ferrum-edge-dependency-audit (github.com/ferrum-edge/ferrum-edge)"


def load_lifecycle() -> dict[str, Any]:
    with LIFECYCLE_PATH.open(encoding="utf-8") as handle:
        data = json.load(handle)
    if data.get("schema_version") != 1:
        raise ValueError(f"unsupported schema_version in {LIFECYCLE_PATH}")
    return data


def parse_patch_crates_io(cargo_path: Path) -> dict[str, str]:
    """Return crate -> vendor path for each [patch.crates-io] entry."""
    text = cargo_path.read_text(encoding="utf-8")
    in_block = False
    patches: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "[patch.crates-io]":
            in_block = True
            continue
        if in_block:
            if stripped.startswith("[") and stripped.endswith("]"):
                break
            match = re.match(
                r'^(\w[\w-]*)\s*=\s*\{\s*path\s*=\s*"([^"]+)"\s*\}', stripped
            )
            if match:
                patches[match.group(1)] = match.group(2)
    return patches


def readme_candidates(docs_path: str) -> list[Path]:
    rel = docs_path.rstrip("/")
    return [ROOT / rel / "README.md", ROOT / rel / "readme.md"]


def find_readme(docs_path: str) -> Path | None:
    for candidate in readme_candidates(docs_path):
        if candidate.is_file():
            return candidate
    return None


def parse_readme_reaffirmation(readme_path: Path) -> dict[str, str] | None:
    text = readme_path.read_text(encoding="utf-8", errors="replace")
    match = REAFFIRMATION_RE.search(text)
    if not match:
        return None
    return {
        "date": match.group(1),
        "owner": match.group(2).strip(),
        "reason": match.group(3).strip(),
    }


def vendor_patch_dirs() -> set[str]:
    if not VENDOR_ROOT.is_dir():
        return set()
    return {
        f"vendor/{entry.name}"
        for entry in VENDOR_ROOT.iterdir()
        if entry.is_dir() and entry.name.endswith("-ferrum-patched")
    }


def _is_nonempty_str(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _is_positive_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _require_nonempty_str(value: Any, path: str, errors: list[str]) -> None:
    if not _is_nonempty_str(value):
        errors.append(f"{path}: must be a non-empty string")


def _require_nonempty_str_list(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, list) or not value:
        errors.append(f"{path}: must be a non-empty list")
        return
    for index, item in enumerate(value):
        if not _is_nonempty_str(item):
            errors.append(f"{path}[{index}]: must be a non-empty string")


def validate_lifecycle_shape(data: Any) -> list[str]:
    """Fail-closed structural validation for the lifecycle contract."""
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["lifecycle inventory must be a JSON object"]

    patches = data.get("patches")
    if not isinstance(patches, list) or not patches:
        errors.append("patches must be a non-empty list")
        patches = []

    for index, patch in enumerate(patches):
        if not isinstance(patch, dict):
            errors.append(f"patches[{index}]: must be an object")
            continue

        pid = patch.get("id")
        prefix = pid.strip() if _is_nonempty_str(pid) else f"patches[{index}]"

        for field in REQUIRED_PATCH_STRING_FIELDS:
            _require_nonempty_str(patch.get(field), f"{prefix}.{field}", errors)

        upstream = patch.get("upstream")
        if not isinstance(upstream, dict):
            errors.append(f"{prefix}.upstream: must be an object")
        else:
            filing = upstream.get("filing")
            if filing not in UPSTREAM_FILINGS:
                errors.append(f"{prefix}: unknown upstream.filing {filing!r}")

            repo = upstream.get("github_repo")
            if not _is_nonempty_str(repo) or not GITHUB_REPO_RE.fullmatch(str(repo)):
                errors.append(
                    f"{prefix}.upstream.github_repo: must match owner/repo form"
                )

            pr_number = upstream.get("pr_number")
            if filing == "filed":
                if not _is_positive_int(pr_number):
                    errors.append(
                        f"{prefix}: filing=filed requires a positive integer pr_number"
                    )
            elif filing == "deliberate_fork_unfiled":
                if pr_number is not None:
                    errors.append(
                        f"{prefix}: filing=deliberate_fork_unfiled must not carry a pr_number"
                    )

            issue_number = upstream.get("issue_number")
            if issue_number is not None and not _is_positive_int(issue_number):
                errors.append(
                    f"{prefix}.upstream.issue_number: must be a positive integer when present"
                )

        _require_nonempty_str_list(
            patch.get("regression_tests"), f"{prefix}.regression_tests", errors
        )

        retirement = patch.get("retirement")
        if not isinstance(retirement, dict):
            errors.append(f"{prefix}.retirement: must be an object")
        else:
            _require_nonempty_str(
                retirement.get("trigger"), f"{prefix}.retirement.trigger", errors
            )
            compatible = retirement.get("compatible_release_test")
            if not isinstance(compatible, dict):
                errors.append(
                    f"{prefix}.retirement.compatible_release_test: must be an object"
                )
            else:
                status = compatible.get("status")
                if status not in COMPATIBLE_RELEASE_STATUSES:
                    errors.append(
                        f"{prefix}: invalid compatible_release_test.status {status!r}"
                    )

    checklist = data.get("retirement_checklist")
    _require_nonempty_str_list(checklist, "retirement_checklist", errors)
    return errors


def executable_wrapper_lines(script_text: str) -> list[str]:
    lines: list[str] = []
    for raw in script_text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        lines.append(stripped)
    return lines


def wrapper_delegation_errors(script_text: str) -> list[str]:
    """Validate safe, directory-local delegation to the Python upstream checker."""
    errors: list[str] = []
    lines = executable_wrapper_lines(script_text)
    if not lines:
        return ["scripts/check_vendored_patch_status.sh has no executable lines"]

    if not any(line == "set -uo pipefail" or line == "set -euo pipefail" for line in lines):
        errors.append(
            "scripts/check_vendored_patch_status.sh must enable nounset/pipefail "
            "(set -uo pipefail or set -euo pipefail)"
        )

    dir_assigns = [line for line in lines if line.startswith("SCRIPT_DIR=")]
    if len(dir_assigns) != 1 or not WRAPPER_DIR_ASSIGN_RE.fullmatch(dir_assigns[0]):
        errors.append(
            "scripts/check_vendored_patch_status.sh must assign SCRIPT_DIR from "
            'the wrapper path via: SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"'
        )

    exec_lines = [line for line in lines if line.startswith("exec ")]
    if len(exec_lines) != 1 or not WRAPPER_EXEC_RE.fullmatch(exec_lines[0]):
        errors.append(
            "scripts/check_vendored_patch_status.sh must delegate with: "
            'exec python3 "$SCRIPT_DIR/check_vendored_patch_lifecycle.py" --upstream-status'
        )

    # Reject cwd-relative or unquoted invocation forms that bypass the safe pattern.
    joined = "\n".join(lines)
    if "scripts/check_vendored_patch_lifecycle.py" in joined:
        errors.append(
            "scripts/check_vendored_patch_status.sh must not invoke the checker via a "
            "cwd-relative scripts/ path"
        )
    if re.search(r"exec\s+python3\s+\$SCRIPT_DIR/", joined):
        errors.append(
            "scripts/check_vendored_patch_status.sh must quote $SCRIPT_DIR when "
            "invoking the lifecycle checker"
        )
    if "eval " in joined or "`" in joined:
        errors.append(
            "scripts/check_vendored_patch_status.sh must not use eval or backtick substitution"
        )
    return errors


def policy_lifecycle_ids(policy_text: str) -> tuple[list[str], list[str]]:
    """Extract inventory Lifecycle IDs; report duplicate rows as errors."""
    ids: list[str] = []
    errors: list[str] = []
    seen: set[str] = set()
    for line in policy_text.splitlines():
        match = INVENTORY_ROW_RE.match(line)
        if not match:
            continue
        lifecycle_id = match.group(1)
        if lifecycle_id in seen:
            errors.append(
                f"duplicate lifecycle id in dependency-policy.md inventory: {lifecycle_id!r}"
            )
        else:
            seen.add(lifecycle_id)
        ids.append(lifecycle_id)
    return ids, errors


def policy_id_parity_errors(
    policy_text: str, lifecycle_ids: set[str]
) -> list[str]:
    errors: list[str] = []
    policy_ids, dup_errors = policy_lifecycle_ids(policy_text)
    errors.extend(dup_errors)
    policy_set = set(policy_ids)
    # set() collapses duplicates for missing/extra reporting; dup_errors already
    # covers repeated rows.
    for missing in sorted(lifecycle_ids - policy_set):
        errors.append(
            f"docs/dependency-policy.md inventory missing lifecycle id {missing!r}"
        )
    for extra in sorted(policy_set - lifecycle_ids):
        errors.append(
            f"docs/dependency-policy.md inventory has unknown lifecycle id {extra!r}"
        )
    return errors


def parity_errors(data: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    shape_errors = validate_lifecycle_shape(data)
    errors.extend(shape_errors)

    if PATCH_STATUS_SCRIPT.is_file():
        errors.extend(
            wrapper_delegation_errors(
                PATCH_STATUS_SCRIPT.read_text(encoding="utf-8", errors="replace")
            )
        )
    else:
        errors.append("missing scripts/check_vendored_patch_status.sh wrapper")

    patches_raw = data.get("patches")
    usable_patches = isinstance(patches_raw, list) and all(
        isinstance(patch, dict) for patch in patches_raw
    )
    if not usable_patches:
        return errors

    patches: list[dict[str, Any]] = patches_raw
    patch_ids = [
        patch["id"]
        for patch in patches
        if _is_nonempty_str(patch.get("id"))
    ]
    if len(patch_ids) != len(set(patch_ids)):
        errors.append("duplicate patch id in lifecycle inventory")

    if POLICY_PATH.is_file():
        policy_text = POLICY_PATH.read_text(encoding="utf-8")
        errors.extend(policy_id_parity_errors(policy_text, set(patch_ids)))
        for patch in patches:
            docs_path = patch.get("docs_path")
            if not _is_nonempty_str(docs_path):
                continue
            docs_fragment = str(docs_path).removeprefix("docs/").rstrip("/")
            if docs_fragment not in policy_text:
                pid = patch.get("id", "<unknown>")
                errors.append(
                    f"{pid}: docs path fragment {docs_fragment!r} missing from dependency-policy.md"
                )
    else:
        errors.append("missing docs/dependency-policy.md")

    # Remaining parity assumes a well-formed contract; stop early on shape failures
    # so malformed inventories surface as parity errors instead of exceptions.
    if shape_errors:
        return errors

    for patch in patches:
        pid = patch["id"]
        docs_path = patch["docs_path"]
        if not find_readme(docs_path):
            errors.append(f"{pid}: missing README under {docs_path}")

        reaffirmation = patch.get("reaffirmation")
        readme = find_readme(docs_path)
        if readme is not None:
            readme_reaffirm = parse_readme_reaffirmation(readme)
            if reaffirmation is None and readme_reaffirm is not None:
                errors.append(
                    f"{pid}: README contains dated reaffirmation but lifecycle.reaffirmation is null"
                )
            if reaffirmation is not None and readme_reaffirm is None:
                errors.append(
                    f"{pid}: lifecycle.reaffirmation set but README lacks matching dated reaffirmation"
                )
            if reaffirmation is not None and readme_reaffirm is not None:
                for key in ("date", "owner", "reason"):
                    if str(reaffirmation.get(key, "")).strip() != readme_reaffirm[key]:
                        errors.append(
                            f"{pid}: lifecycle reaffirmation {key!r} does not match README"
                        )

    declared_groups = data.get("co_retirement_groups", [])
    known_ids = set(patch_ids)
    patch_declared_group = {
        patch["id"]: patch["retirement"].get("co_retirement_group") for patch in patches
    }
    group_members: dict[str, list[str]] = {}
    seen_group_ids: set[str] = set()
    patch_group_membership: dict[str, str] = {}

    if not isinstance(declared_groups, list):
        errors.append("co_retirement_groups must be a list when present")
        declared_groups = []

    for group in declared_groups:
        if not isinstance(group, dict):
            errors.append("co_retirement_groups entry must be an object")
            continue
        gid = group.get("id")
        if not isinstance(gid, str) or not gid.strip():
            errors.append("co_retirement_groups entry missing id")
            continue
        if gid in seen_group_ids:
            errors.append(f"duplicate co_retirement_group id {gid!r}")
        seen_group_ids.add(gid)

        members = group.get("patch_ids")
        if not isinstance(members, list) or not members:
            errors.append(
                f"co_retirement_groups.{gid}: patch_ids must be a non-empty list"
            )
            continue
        if len(members) != len(set(members)):
            errors.append(
                f"co_retirement_groups.{gid}: duplicate patch id in patch_ids"
            )

        group_members[gid] = members
        for member in members:
            if member not in known_ids:
                errors.append(
                    f"co_retirement_groups.{gid}: unknown patch id {member!r}"
                )
                continue
            prior = patch_group_membership.get(member)
            if prior is not None and prior != gid:
                errors.append(
                    f"{member}: listed in multiple co_retirement_groups "
                    f"({prior!r} and {gid!r})"
                )
            else:
                patch_group_membership[member] = gid
            if patch_declared_group.get(member) != gid:
                errors.append(
                    f"co_retirement_groups.{gid}: member {member!r} "
                    f"declares co_retirement_group {patch_declared_group.get(member)!r}"
                )

    for patch in patches:
        pid = patch["id"]
        group = patch_declared_group[pid]
        if group is not None:
            if group not in group_members:
                errors.append(f"{pid}: unknown co_retirement_group {group!r}")
            elif pid not in group_members.get(group, []):
                errors.append(f"{pid}: not listed in co_retirement_group {group!r}")

    lifecycle_vendor_paths = {patch["vendor_path"] for patch in patches}
    on_disk_vendor_paths = vendor_patch_dirs()
    for path in sorted(lifecycle_vendor_paths - on_disk_vendor_paths):
        errors.append(f"lifecycle references missing vendor directory {path}")
    for path in sorted(on_disk_vendor_paths - lifecycle_vendor_paths):
        errors.append(f"vendor directory {path} is not referenced by lifecycle inventory")

    root_patches = parse_patch_crates_io(ROOT_CARGO)
    expected_crates = {patch["crate"] for patch in patches}
    if set(root_patches) != expected_crates:
        errors.append(
            "root Cargo.toml [patch.crates-io] crates "
            f"{sorted(root_patches)} != lifecycle crates {sorted(expected_crates)}"
        )
    for patch in patches:
        crate = patch["crate"]
        expected_path = patch["vendor_path"]
        actual_path = root_patches.get(crate)
        if actual_path != expected_path:
            errors.append(
                f"{patch['id']}: root [patch.crates-io].{crate} path "
                f"{actual_path!r} != lifecycle {expected_path!r}"
            )

    if MESH_PERF_CARGO.is_file():
        mesh_patches = parse_patch_crates_io(MESH_PERF_CARGO)
        if set(mesh_patches) != set(root_patches):
            errors.append(
                "tests/performance/mesh/Cargo.toml [patch.crates-io] crates "
                f"{sorted(mesh_patches)} != root crates {sorted(root_patches)}"
            )
        for crate, path in root_patches.items():
            mesh_path = mesh_patches.get(crate)
            if mesh_path is None:
                errors.append(
                    f"tests/performance/mesh/Cargo.toml missing [patch.crates-io] entry for {crate}"
                )
            elif Path(mesh_path) != Path("../../../" + path):
                errors.append(
                    f"tests/performance/mesh/Cargo.toml {crate} path {mesh_path!r} "
                    f"does not mirror root {path!r}"
                )
    else:
        errors.append("missing tests/performance/mesh/Cargo.toml patch mirror")

    return errors


def github_auth_headers() -> dict[str, str]:
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/vnd.github+json",
    }
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def github_pr_state(repo: str, pr_number: int) -> str | None:
    if not GITHUB_REPO_RE.fullmatch(repo) or pr_number <= 0:
        return None
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repo}/pulls/{pr_number}",
        headers=github_auth_headers(),
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = json.load(response)
    except Exception:
        return None
    if payload.get("merged_at"):
        return "MERGED"
    state = payload.get("state")
    if state == "open":
        return "OPEN"
    if state == "closed":
        return "CLOSED"
    return None


def crates_io_latest(crate: str) -> str | None:
    request = urllib.request.Request(
        f"https://crates.io/api/v1/crates/{crate}",
        headers={"User-Agent": USER_AGENT},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = json.load(response)
    except Exception:
        return None
    version = payload.get("crate", {}).get("max_stable_version")
    return version if isinstance(version, str) and version else None


def run_upstream_status(data: dict[str, Any]) -> int:
    retire_signal = 0
    query_failed = 0
    print("## Vendored patch upstream status")
    print("")
    for patch in data["patches"]:
        upstream = patch["upstream"]
        print(f"### {patch['label']}")
        print(
            f"- patch id: `{patch['id']}`; crate: `{patch['crate']}` "
            f"(vendored {patch['vendored_version']}); owner: {patch['owner']}"
        )
        print(f"- docs: {patch['docs_path']}")
        print(f"- retirement trigger: {patch['retirement']['trigger']}")
        group = patch["retirement"].get("co_retirement_group")
        if group:
            print(f"- co-retirement group: {group}")
        test_status = patch["retirement"]["compatible_release_test"]["status"]
        print(f"- compatible-release test: {test_status}")

        issue = upstream.get("issue_number")
        if issue is not None:
            print(f"- upstream issue: {upstream['github_repo']}#{issue}")

        latest = crates_io_latest(patch["crate"])
        if latest:
            print(f"- crates.io latest stable: {latest}")

        pr = upstream.get("pr_number")
        filing = upstream["filing"]
        if filing == "deliberate_fork_unfiled" and pr is None:
            fork_ref = upstream.get("fork_ref")
            if fork_ref:
                print(f"- deliberate fork staging ref: {fork_ref}")
            reaffirmation = patch.get("reaffirmation")
            if reaffirmation:
                print(
                    "- deliberate fork reaffirmation: "
                    f"{reaffirmation['date']} by {reaffirmation['owner']}: "
                    f"{reaffirmation['reason']}"
                )
            else:
                print(
                    "- upstream PR: NOT YET FILED — deliberate fork; needs upstream "
                    "issue/PR or explicit dated owner reaffirmation before the first "
                    "stable release (docs/dependency-policy.md)"
                )
                print(
                    f"  ::warning::{patch['id']} is an unfiled deliberate fork without a "
                    "dated reaffirmation in the lifecycle inventory."
                )
        elif pr is not None:
            state = github_pr_state(upstream["github_repo"], pr)
            if not state:
                print(
                    f"  ::warning::could not query upstream PR "
                    f"{upstream['github_repo']}#{pr} — failing closed."
                )
                query_failed = 1
            else:
                print(f"- upstream PR {upstream['github_repo']}#{pr}: state={state}")
                if state == "MERGED":
                    print(
                        f"  ::warning::ACTION — {patch['crate']} PR "
                        f"{upstream['github_repo']}#{pr} merged upstream. Run the "
                        "compatible-release test on a branch without the patch before "
                        f"retiring per {patch['docs_path']}."
                    )
                    retire_signal = 1
                elif state == "CLOSED":
                    print(
                        f"  ::warning::{patch['crate']} PR {upstream['github_repo']}#{pr} "
                        f"was CLOSED without merge — revisit the patch strategy."
                    )
        else:
            print(f"  ::warning::{patch['id']} has filing={filing!r} but no pr_number")
            query_failed = 1
        print("")

    if retire_signal:
        print(
            "::error::One or more vendored patches merged upstream. Run compatible-release "
            "tests and follow docs/vendored-patch-lifecycle.json retirement_checklist before "
            "removing vendor copies."
        )
        return 1
    if query_failed:
        print(
            "::error::One or more upstream PR statuses could not be queried; failing closed."
        )
        return 1
    print("No vendored patch has merged upstream yet; nothing to retire.")
    return 0


def run_parity(data: dict[str, Any]) -> int:
    errors = parity_errors(data)
    if errors:
        for message in errors:
            print(f"::error::{message}")
        print("")
        print(
            "Vendored-patch lifecycle parity failed. Update docs/vendored-patch-lifecycle.json "
            "and every linked surface together (docs/dependency-policy.md, per-patch READMEs, "
            "Cargo.toml [patch.crates-io], scripts/check_vendored_patch_lifecycle.py, vendor/)."
        )
        return 1
    print(
        f"ok: lifecycle inventory covers {len(data['patches'])} patches with parity across "
        "Cargo.toml, vendor/, policy docs, and per-patch READMEs."
    )
    return 0


def _valid_patch(**overrides: Any) -> dict[str, Any]:
    patch: dict[str, Any] = {
        "id": "example-001",
        "label": "example patch",
        "crate": "example",
        "vendored_version": "1.0.0",
        "vendor_path": "vendor/example-1.0.0-ferrum-patched",
        "docs_path": "docs/upstream-example-patches/001/",
        "owner": "Ferrum Edge maintainers",
        "reason": "synthetic self-test patch",
        "upstream": {
            "filing": "filed",
            "github_repo": "example/example",
            "pr_number": 1,
            "issue_number": None,
            "fork_ref": None,
        },
        "reaffirmation": None,
        "retirement": {
            "trigger": "upstream ships a compatible release",
            "co_retirement_group": None,
            "compatible_release_test": {
                "status": "not_started",
                "notes": None,
            },
        },
        "regression_tests": ["tests/example.rs"],
    }
    for key, value in overrides.items():
        if key in {"upstream", "retirement"} and isinstance(value, dict):
            merged = dict(patch[key])
            nested = value
            if key == "retirement" and "compatible_release_test" in nested:
                compatible = dict(merged.get("compatible_release_test") or {})
                compatible.update(nested["compatible_release_test"])
                nested = dict(nested)
                nested["compatible_release_test"] = compatible
            merged.update(nested)
            patch[key] = merged
        else:
            patch[key] = value
    return patch


def _inventory_row(lifecycle_id: str, crate: str = "example") -> str:
    return (
        f"| `{lifecycle_id}` | `{crate}` | 1.0.0 | patch | upstream | owner | reason | "
        f"trigger | [docs](path/{lifecycle_id}/README.md) |"
    )


GOOD_WRAPPER = """#!/usr/bin/env bash
# comment
set -uo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
exec python3 "$SCRIPT_DIR/check_vendored_patch_lifecycle.py" --upstream-status
"""


def run_self_test() -> int:
    """Deterministic static tests; never touches repository files or the network."""
    failures: list[str] = []

    def expect_contains(errors: list[str], needle: str, label: str) -> None:
        if not any(needle in message for message in errors):
            failures.append(f"{label}: expected error containing {needle!r}, got {errors!r}")

    def expect_empty(errors: list[str], label: str) -> None:
        if errors:
            failures.append(f"{label}: unexpected errors {errors!r}")

    base = {
        "schema_version": 1,
        "retirement_checklist": ["retire carefully"],
        "patches": [_valid_patch()],
    }
    expect_empty(validate_lifecycle_shape(base), "valid minimal inventory")

    filed_missing_pr = {
        **base,
        "patches": [
            _valid_patch(upstream={"filing": "filed", "pr_number": None}),
        ],
    }
    expect_contains(
        validate_lifecycle_shape(filed_missing_pr),
        "filing=filed requires a positive integer pr_number",
        "filed without pr_number",
    )

    filed_bad_pr = {
        **base,
        "patches": [_valid_patch(upstream={"filing": "filed", "pr_number": 0})],
    }
    expect_contains(
        validate_lifecycle_shape(filed_bad_pr),
        "filing=filed requires a positive integer pr_number",
        "filed with non-positive pr_number",
    )

    unfiled_with_pr = {
        **base,
        "patches": [
            _valid_patch(
                upstream={
                    "filing": "deliberate_fork_unfiled",
                    "pr_number": 9,
                    "github_repo": "example/example",
                }
            )
        ],
    }
    expect_contains(
        validate_lifecycle_shape(unfiled_with_pr),
        "must not carry a pr_number",
        "unfiled with pr_number",
    )

    bad_repo = {
        **base,
        "patches": [
            _valid_patch(upstream={"filing": "filed", "pr_number": 1, "github_repo": "bad"})
        ],
    }
    expect_contains(
        validate_lifecycle_shape(bad_repo),
        "github_repo",
        "invalid github_repo",
    )

    empty_regression = {
        **base,
        "patches": [_valid_patch(regression_tests=[])],
    }
    expect_contains(
        validate_lifecycle_shape(empty_regression),
        "regression_tests",
        "empty regression_tests",
    )

    blank_regression_item = {
        **base,
        "patches": [_valid_patch(regression_tests=["  "])],
    }
    expect_contains(
        validate_lifecycle_shape(blank_regression_item),
        "regression_tests[0]",
        "blank regression_tests item",
    )

    empty_checklist = {**base, "retirement_checklist": []}
    expect_contains(
        validate_lifecycle_shape(empty_checklist),
        "retirement_checklist",
        "empty retirement_checklist",
    )

    blank_checklist_item = {**base, "retirement_checklist": [""]}
    expect_contains(
        validate_lifecycle_shape(blank_checklist_item),
        "retirement_checklist[0]",
        "blank retirement_checklist item",
    )

    bad_status = {
        **base,
        "patches": [
            _valid_patch(
                retirement={"compatible_release_test": {"status": "maybe"}}
            )
        ],
    }
    expect_contains(
        validate_lifecycle_shape(bad_status),
        "compatible_release_test.status",
        "invalid compatible_release_test status",
    )

    missing_trigger = {
        **base,
        "patches": [_valid_patch(retirement={"trigger": ""})],
    }
    expect_contains(
        validate_lifecycle_shape(missing_trigger),
        "retirement.trigger",
        "empty retirement.trigger",
    )

    bad_issue = {
        **base,
        "patches": [
            _valid_patch(
                upstream={"filing": "filed", "pr_number": 1, "issue_number": -3}
            )
        ],
    }
    expect_contains(
        validate_lifecycle_shape(bad_issue),
        "issue_number",
        "non-positive issue_number",
    )

    non_object_patch = {**base, "patches": ["nope"]}
    expect_contains(
        validate_lifecycle_shape(non_object_patch),
        "must be an object",
        "non-object patch entry",
    )

    expect_empty(wrapper_delegation_errors(GOOD_WRAPPER), "good wrapper")

    cwd_relative = """#!/usr/bin/env bash
set -uo pipefail
exec python3 scripts/check_vendored_patch_lifecycle.py --upstream-status
"""
    expect_contains(
        wrapper_delegation_errors(cwd_relative),
        "cwd-relative",
        "cwd-relative wrapper",
    )

    unquoted = """#!/usr/bin/env bash
set -uo pipefail
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
exec python3 $SCRIPT_DIR/check_vendored_patch_lifecycle.py --upstream-status
"""
    expect_contains(
        wrapper_delegation_errors(unquoted),
        "quote $SCRIPT_DIR",
        "unquoted SCRIPT_DIR wrapper",
    )

    noop = """#!/usr/bin/env bash
set -uo pipefail
true
"""
    expect_contains(
        wrapper_delegation_errors(noop),
        "must delegate with",
        "no-op wrapper",
    )

    matching_policy = "\n".join(
        [
            "| Lifecycle ID | Crate | Vendored ver. | Patch | Upstream issue / PR | Owner | Reason | Removal trigger | Docs |",
            _inventory_row("example-001"),
            _inventory_row("example-002", "other"),
        ]
    )
    expect_empty(
        policy_id_parity_errors(matching_policy, {"example-001", "example-002"}),
        "matching policy IDs",
    )

    missing_policy = "\n".join(
        [
            "| Lifecycle ID | Crate | Vendored ver. | Patch | Upstream issue / PR | Owner | Reason | Removal trigger | Docs |",
            _inventory_row("example-001"),
        ]
    )
    expect_contains(
        policy_id_parity_errors(missing_policy, {"example-001", "example-002"}),
        "missing lifecycle id 'example-002'",
        "missing policy ID",
    )

    extra_policy = "\n".join(
        [
            "| Lifecycle ID | Crate | Vendored ver. | Patch | Upstream issue / PR | Owner | Reason | Removal trigger | Docs |",
            _inventory_row("example-001"),
            _inventory_row("example-extra"),
        ]
    )
    expect_contains(
        policy_id_parity_errors(extra_policy, {"example-001"}),
        "unknown lifecycle id 'example-extra'",
        "extra policy ID",
    )

    duplicate_policy = "\n".join(
        [
            "| Lifecycle ID | Crate | Vendored ver. | Patch | Upstream issue / PR | Owner | Reason | Removal trigger | Docs |",
            _inventory_row("example-001"),
            _inventory_row("example-001"),
        ]
    )
    expect_contains(
        policy_id_parity_errors(duplicate_policy, {"example-001"}),
        "duplicate lifecycle id",
        "duplicate policy ID",
    )

    if failures:
        for message in failures:
            print(f"::error::{message}")
        print("Vendored-patch lifecycle self-test failed.")
        return 1
    print("ok: vendored-patch lifecycle self-test passed.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--upstream-status",
        action="store_true",
        help="Report upstream PR state and deliberate-fork reaffirmation gaps (weekly workflow).",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run deterministic static validator self-tests (no network, no repo mutation).",
    )
    args = parser.parse_args()

    if args.self_test:
        return run_self_test()

    if not LIFECYCLE_PATH.is_file():
        print(f"::error::missing lifecycle inventory at {LIFECYCLE_PATH}")
        return 1

    try:
        data = load_lifecycle()
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"::error::failed to load lifecycle inventory: {exc}")
        return 1

    parity_code = run_parity(data)
    if parity_code != 0:
        return parity_code
    if args.upstream_status:
        return run_upstream_status(data)
    return 0


if __name__ == "__main__":
    sys.exit(main())
