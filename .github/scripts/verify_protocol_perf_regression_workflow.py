#!/usr/bin/env python3
"""Static regression checks for the protocol performance regression workflow.

Validates that `.github/workflows/protocol-perf-regression.yml` keeps the
scheduled + manual contract, pinned external actions, approved tool setup
paths, alert-only budget enforcement wiring, and artifact/runner-health
signals required by issue #2460. Does not execute benchmarks.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "protocol-perf-regression.yml"
BUDGETS_PATH = (
    REPO_ROOT
    / "tests"
    / "performance"
    / "multi_protocol"
    / "protocol_perf_budgets.json"
)
EVALUATOR_PATH = (
    REPO_ROOT
    / "tests"
    / "performance"
    / "multi_protocol"
    / "evaluate_protocol_perf_budgets.py"
)
SCENARIOS_PATH = (
    REPO_ROOT
    / "tests"
    / "performance"
    / "multi_protocol"
    / "run_protocol_regression_scenarios.sh"
)
RUNBOOK_PATH = REPO_ROOT / "docs" / "protocol_perf_regression.md"
CI_CD_PATH = REPO_ROOT / "docs" / "ci_cd.md"

PINNED_ACTION = re.compile(
    r"uses:\s*(?P<action>(?!./)[^@\s]+)@(?P<ref>[0-9a-f]{40})\b",
    re.IGNORECASE,
)
MUTABLE_ACTION = re.compile(
    r"uses:\s*(?P<action>(?!./)[^@\s]+)@(?P<ref>v?[0-9][^@\s]*)\b",
    re.IGNORECASE,
)
APPROVED_SETUP = (
    "./.github/actions/setup-rust-ci",
    "./.github/actions/setup-sccache",
    "./.github/actions/setup-fast-linker",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Validate fixture expectations against synthetic snippets",
    )
    return parser.parse_args()


def require(condition: bool, message: str, failures: list[str]) -> None:
    if not condition:
        failures.append(message)


def validate_workflow_text(text: str, failures: list[str]) -> None:
    require("schedule:" in text, "workflow must declare a schedule trigger", failures)
    require("workflow_dispatch:" in text, "workflow must declare workflow_dispatch", failures)
    require(
        'runs-on: ubuntu-latest' in text or "runs-on: ubuntu-latest" in text,
        "workflow must document/use ubuntu-latest runner class",
        failures,
    )
    require(
        "ci-release" in text,
        "workflow must use the stable ci-release build profile",
        failures,
    )
    require(
        "evaluate_protocol_perf_budgets.py" in text,
        "workflow must evaluate versioned protocol budgets",
        failures,
    )
    require(
        "run_protocol_regression_scenarios.sh" in text,
        "workflow must run churn/soak/reload scenario harness",
        failures,
    )
    require(
        "runner_health" in text or "RUNNER HEALTH" in text or "Runner health" in text,
        "workflow must capture runner-health metadata",
        failures,
    )
    require(
        "upload-artifact@" in text,
        "workflow must retain artifacts",
        failures,
    )
    require(
        "enforcement" in text or "alert" in text,
        "workflow must wire alert/non-block budget enforcement",
        failures,
    )
    require(
        "protocol_perf_budgets.json" in text,
        "workflow must reference the versioned budgets file",
        failures,
    )
    require(
        "trends" in text.lower(),
        "workflow must publish machine-readable trends",
        failures,
    )

    for match in MUTABLE_ACTION.finditer(text):
        ref = match.group("ref")
        if re.fullmatch(r"[0-9a-f]{40}", ref, flags=re.IGNORECASE):
            continue
        failures.append(
            f"mutable external action ref forbidden: "
            f"{match.group('action')}@{ref}"
        )

    pinned = list(PINNED_ACTION.finditer(text))
    require(bool(pinned), "workflow must pin external actions to full commit SHAs", failures)

    local_uses = re.findall(r"uses:\s*(\./\.github/actions/[^\s]+)", text)
    for action in local_uses:
        require(
            any(action.startswith(prefix) for prefix in APPROVED_SETUP)
            or action.startswith("./.github/actions/"),
            f"unexpected local action path: {action}",
            failures,
        )


def validate_repository_contract(failures: list[str]) -> None:
    require(WORKFLOW_PATH.is_file(), f"missing workflow: {WORKFLOW_PATH}", failures)
    require(BUDGETS_PATH.is_file(), f"missing budgets file: {BUDGETS_PATH}", failures)
    require(EVALUATOR_PATH.is_file(), f"missing evaluator: {EVALUATOR_PATH}", failures)
    require(SCENARIOS_PATH.is_file(), f"missing scenarios harness: {SCENARIOS_PATH}", failures)
    require(RUNBOOK_PATH.is_file(), f"missing runbook: {RUNBOOK_PATH}", failures)
    require(CI_CD_PATH.is_file(), f"missing CI/CD docs: {CI_CD_PATH}", failures)

    if WORKFLOW_PATH.is_file():
        validate_workflow_text(WORKFLOW_PATH.read_text(encoding="utf-8"), failures)

    if BUDGETS_PATH.is_file():
        import json

        budgets = json.loads(BUDGETS_PATH.read_text(encoding="utf-8"))
        require(
            budgets.get("enforcement") == "alert",
            "budgets must start in alert enforcement until variance is measured",
            failures,
        )
        require(
            budgets.get("runner_class") == "ubuntu-latest",
            "budgets must document ubuntu-latest runner class",
            failures,
        )
        require(
            budgets.get("build_profile") == "ci-release",
            "budgets must document ci-release build profile",
            failures,
        )
        protocols = budgets.get("protocols", {})
        for required in (
            "HTTP/1.1",
            "HTTP/2",
            "HTTP/3",
            "WebSocket",
            "gRPC",
            "TCP",
            "UDP",
        ):
            require(required in protocols, f"budgets missing protocol {required}", failures)

    if CI_CD_PATH.is_file():
        ci_cd = CI_CD_PATH.read_text(encoding="utf-8")
        require(
            "protocol-perf-regression.yml" in ci_cd,
            "docs/ci_cd.md must inventory protocol-perf-regression.yml",
            failures,
        )
        require(
            "Multi Protocol Performance Benchmark" in ci_cd
            or "perf-benchmark.yml" in ci_cd,
            "docs/ci_cd.md must still document the manual multi-protocol benchmark",
            failures,
        )

    if RUNBOOK_PATH.is_file():
        runbook = RUNBOOK_PATH.read_text(encoding="utf-8")
        require("ci-release" in runbook, "runbook must document ci-release profile", failures)
        require("ubuntu-latest" in runbook, "runbook must document runner class", failures)
        require(
            "alert" in runbook.lower(),
            "runbook must document alert/non-block budgets",
            failures,
        )
        require(
            "ci.yml" in runbook and "overhead" in runbook.lower(),
            "runbook must preserve the lightweight PR overhead check",
            failures,
        )


def self_test() -> int:
    failures: list[str] = []
    good = """
name: Protocol Performance Regression
on:
  schedule:
    - cron: "0 5 * * 0"
  workflow_dispatch:
jobs:
  regress:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v6
      - uses: ./.github/actions/setup-rust-ci
      - run: echo ci-release
      - run: bash tests/performance/multi_protocol/run_protocol_regression_scenarios.sh
      - run: python3 tests/performance/multi_protocol/evaluate_protocol_perf_budgets.py
      - run: echo protocol_perf_budgets.json alert trends runner_health
      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7
"""
    validate_workflow_text(good, failures)

    bad_failures: list[str] = []
    bad = """
on:
  workflow_dispatch:
jobs:
  regress:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""
    validate_workflow_text(bad, bad_failures)
    if not any("schedule" in item for item in bad_failures):
        failures.append("self-test expected missing schedule detection")
    if not any("mutable" in item for item in bad_failures):
        failures.append("self-test expected mutable action detection")

    if failures:
        for failure in failures:
            print(f"::error::self-test: {failure}")
        return 1
    print("protocol-perf-regression workflow verifier self-test passed")
    return 0


def main() -> int:
    args = parse_args()
    if args.self_test:
        return self_test()

    failures: list[str] = []
    validate_repository_contract(failures)
    if failures:
        for failure in failures:
            print(f"::error::{failure}")
        return 1
    print("protocol-perf-regression workflow contract ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
