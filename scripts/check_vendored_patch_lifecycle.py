#!/usr/bin/env python3
"""Validate vendored-patch lifecycle inventory parity and upstream status.

The canonical inventory lives in docs/vendored-patch-lifecycle.json. CI runs the
default parity mode on every PR (dependency-audit job) and the weekly
dependency-audit workflow runs --upstream-status after parity passes.

Parity mode fails closed when the lifecycle contract drifts from:
  - root Cargo.toml [patch.crates-io]
  - tests/performance/mesh/Cargo.toml mirrored [patch.crates-io]
  - vendor/*-ferrum-patched directories
  - scripts/check_vendored_patch_status.sh wrapper
  - docs/dependency-policy.md inventory table rows
  - per-patch README.md paths

Upstream mode queries filed upstream PRs via the GitHub REST API and reports deliberate forks
that still need filing or dated owner reaffirmation before the first stable
release checkpoint (docs/dependency-policy.md).
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
REAFFIRMATION_RE = re.compile(
    r"re-affirmed\s+(\d{4}-\d{2}-\d{2})\s+by\s+([^:\n]+):\s*(.+)",
    re.IGNORECASE,
)
PATCH_TABLE_RE = re.compile(
    r"^\|\s*`([^`]+)`\s*\|\s*[^|]+\|\s*[^|]+\|\s*[^|]+\|\s*[^|]+\|\s*[^|]+\|\s*[^|]+\|\s*\["
)


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


def count_policy_inventory_rows(policy_text: str) -> int:
    count = 0
    for line in policy_text.splitlines():
        if PATCH_TABLE_RE.match(line):
            count += 1
    return count


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


def parity_errors(data: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    patches: list[dict[str, Any]] = data["patches"]
    patch_ids = [patch["id"] for patch in patches]
    if len(patch_ids) != len(set(patch_ids)):
        errors.append("duplicate patch id in lifecycle inventory")

    for patch in patches:
        pid = patch["id"]
        owner = patch.get("owner")
        if not owner or not str(owner).strip():
            errors.append(f"{pid}: missing owner")

        filing = patch["upstream"]["filing"]
        if filing not in UPSTREAM_FILINGS:
            errors.append(f"{pid}: unknown upstream.filing {filing!r}")

        status = patch["retirement"]["compatible_release_test"]["status"]
        if status not in COMPATIBLE_RELEASE_STATUSES:
            errors.append(f"{pid}: invalid compatible_release_test.status {status!r}")

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

    for group in declared_groups:
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

    if not PATCH_STATUS_SCRIPT.is_file():
        errors.append("missing scripts/check_vendored_patch_status.sh wrapper")

    policy_text = POLICY_PATH.read_text(encoding="utf-8")
    inventory_rows = count_policy_inventory_rows(policy_text)
    if inventory_rows != len(patches):
        errors.append(
            "docs/dependency-policy.md inventory rows "
            f"({inventory_rows}) != lifecycle patches ({len(patches)})"
        )
    for patch in patches:
        docs_fragment = patch["docs_path"].removeprefix("docs/").rstrip("/")
        if docs_fragment not in policy_text:
            errors.append(
                f"{patch['id']}: docs path fragment {docs_fragment!r} missing from dependency-policy.md"
            )

    checklist = data.get("retirement_checklist", [])
    if not checklist:
        errors.append("retirement_checklist must not be empty")

    return errors


GITHUB_REPO_RE = re.compile(r"^[\w.-]+/[\w.-]+$")
USER_AGENT = "ferrum-edge-dependency-audit (github.com/ferrum-edge/ferrum-edge)"


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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--upstream-status",
        action="store_true",
        help="Report upstream PR state and deliberate-fork reaffirmation gaps (weekly workflow).",
    )
    args = parser.parse_args()

    if not LIFECYCLE_PATH.is_file():
        print(f"::error::missing lifecycle inventory at {LIFECYCLE_PATH}")
        return 1

    data = load_lifecycle()
    parity_code = run_parity(data)
    if parity_code != 0:
        return parity_code
    if args.upstream_status:
        return run_upstream_status(data)
    return 0


if __name__ == "__main__":
    sys.exit(main())
