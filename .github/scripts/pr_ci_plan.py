#!/usr/bin/env python3
"""Select full or lightweight CI for a pull request's changed files."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


# These files cannot affect the Rust workspace, build/release inputs, runtime
# configuration, test harnesses, or GitHub Actions. Keep this allow-list narrow:
# an unrecognized path intentionally fails over to the full CI matrix.
LIGHTWEIGHT_PATTERNS = [
    re.compile(r"^\.agents/"),
    re.compile(r"^\.claude/"),
    re.compile(r"^docs/"),
    re.compile(r"(^|/)[^/]+\.md$"),
    re.compile(r"^LICENSE(?:-[^/]+)?$"),
]

# Markdown under vendor/ participates in VENDOR_INTEGRITY.sha256 and must run
# the vendored-patch and integration guards even when a manifest update was
# accidentally omitted.
FULL_CI_PREFIXES = ("vendor/",)

# These files deliberately trigger one or more live datapath suites. The
# required-CI verifier mechanically checks this set against both
# live_suite_path_filter.py and node-waypoint-ebpf-live.yml.
FULL_CI_DOCUMENTATION_PATHS = frozenset(
    {
        "docs/ci_cd.md",
        "docs/configuration.md",
        "docs/mesh.md",
        "docs/mesh_multicluster_federation_runbook.md",
        "docs/mesh_supported_matrix.md",
        "docs/node_agent.md",
        "docs/plans/node_waypoint_transport_adr.md",
        "docs/spire_deployment.md",
    }
)


def is_lightweight_path(path: str) -> bool:
    if path.startswith(FULL_CI_PREFIXES) or path in FULL_CI_DOCUMENTATION_PATHS:
        return False
    return any(pattern.search(path) for pattern in LIGHTWEIGHT_PATTERNS)


def select_mode(event_name: str, changed_files: list[str]) -> tuple[str, str]:
    if event_name != "pull_request":
        return "full", f"full CI is required for {event_name}"

    # Fail closed when the diff cannot be established. An empty PR diff is
    # unusual, and running full validation is safer than silently skipping it.
    if not changed_files:
        return "full", "no changed files were detected; defaulting to full CI"

    full_ci_files = [path for path in changed_files if not is_lightweight_path(path)]
    if full_ci_files:
        return "full", f"full-CI input changed: {full_ci_files[0]}"

    return "light", "only documentation, license, or agent-instruction files changed"


def read_changed_files(path: Path | None) -> list[str]:
    if path is None:
        return []
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def self_test() -> int:
    cases = [
        ("pull_request", ["docs/admin_api.md"], "light"),
        ("pull_request", ["README.md", "LICENSE-COMMERCIAL.md"], "light"),
        ("pull_request", [".agents/skills/opus-agents/scripts/dispatch-agent.sh"], "light"),
        ("pull_request", [".claude/rules/testing.md"], "light"),
        ("pull_request", ["docs/mesh.md"], "full"),
        ("pull_request", ["docs/configuration.md"], "full"),
        ("pull_request", ["docs/plans/node_waypoint_transport_adr.md"], "full"),
        (
            "pull_request",
            ["vendor/tungstenite-0.29.0-ferrum-patched/README.md"],
            "full",
        ),
        ("pull_request", ["src/proxy/legacy.rs", "notes.md"], "full"),
        ("pull_request", ["src/proxy/mod.rs"], "full"),
        ("pull_request", ["docs/admin_api.md", "Cargo.lock"], "full"),
        ("pull_request", [".github/workflows/ci.yml"], "full"),
        ("pull_request", ["tests/README.md", "tests/unit_tests.rs"], "full"),
        ("pull_request", [], "full"),
        ("push", ["docs/ci_cd.md"], "full"),
        ("workflow_dispatch", [], "full"),
    ]
    failures: list[str] = []
    for event_name, changed, expected in cases:
        mode, _ = select_mode(event_name, changed)
        if mode != expected:
            failures.append(
                f"{event_name} {changed!r}: expected {expected}, selected {mode}"
            )
    for failure in failures:
        print(f"::error::{failure}", file=sys.stderr)
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--event-name")
    parser.add_argument("--changed-files", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        return self_test()
    if not args.event_name:
        parser.error("--event-name is required unless --self-test is used")

    changed_files = read_changed_files(args.changed_files)
    mode, reason = select_mode(args.event_name, changed_files)
    print(f"mode={mode}")
    print(f"reason={reason}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
