#!/usr/bin/env python3
"""Static regression checks for the protocol performance regression workflow.

Validates that `.github/workflows/protocol-perf-regression.yml` keeps the
scheduled + manual contract, pinned external actions, approved tool setup
paths, alert-only budget enforcement wiring, harness data-completeness gates,
and artifact/runner-health signals required by issue #2460. Does not execute
benchmarks.
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
    / "run_protocol_regression_scenarios.py"
)
RUNBOOK_PATH = REPO_ROOT / "docs" / "protocol_perf_regression.md"
CI_CD_PATH = REPO_ROOT / "docs" / "ci_cd.md"
CI_WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "ci.yml"

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

# Bench JSON redirects that must not be silenced with `|| true` in shell form,
# or with swallowed return codes when authored as Python subprocess helpers.
BENCH_JSON_SWALLOWED = re.compile(
    r"--json\s*>\s*\"\$\{OUTPUT_DIR\}/(?:connection_churn|soak|reload_under_load)\.json\""
    r"[^\n]*\|\|\s*true",
)
WAIT_BENCH_SWALLOWED = re.compile(r"wait\s+\"\$\{BENCH_PID\}\"\s*\|\|\s*true")
PY_BENCH_SWALLOWED = re.compile(
    r"subprocess\.(?:run|Popen)\([^\n]*(?:connection_churn|soak|reload_under_load)"
    r"[^\n]*\|\|\s*true"
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
        "run_protocol_regression_scenarios.py" in text,
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


def validate_evaluator_contract(text: str, failures: list[str]) -> None:
    require(
        "resolve_expected_protocols" in text,
        "evaluator must resolve expected protocols for all vs subset selection",
        failures,
    )
    require(
        "missing expected gateway measurement" in text,
        "evaluator must hard-fail when an expected protocol sample is missing",
        failures,
    )
    require(
        "invalid/zero-total" in text or "zero-total" in text,
        "evaluator must reject zero-total/invalid metric samples",
        failures,
    )
    require(
        "parse_finite_number" in text and "math.isfinite" in text,
        "evaluator must reject non-finite metric values",
        failures,
    )
    require(
        "parse_unit_rate" in text,
        "evaluator must validate scenario rates as finite unit intervals",
        failures,
    )
    require(
        "validate_required_scenarios" in text,
        "evaluator must validate required scenario output",
        failures,
    )
    require(
        "hard_fail" in text,
        "evaluator must hard-fail data-completeness independently of enforcement",
        failures,
    )
    require(
        "insufficient" in text and "resource_plateau" in text,
        "evaluator must hard-fail insufficient RSS/FD/task sampling",
        failures,
    )
    for needle, label in (
        ("missing expected protocol should hard-fail", "missing-protocol self-test"),
        ("zero-total gateway sample should hard-fail", "zero-total self-test"),
        ("missing scenarios should hard-fail", "missing-scenario self-test"),
        ("http1 subset should not require HTTP/2", "subset self-test"),
        ("measured regression must not hard-fail under alert enforcement", "alert-only self-test"),
        ("NaN rps should hard-fail", "non-finite rps self-test"),
        ("malformed total_requests should hard-fail", "malformed counts self-test"),
        (
            "sample_total must reject adversarially large counts",
            "oversized counts self-test",
        ),
        ("NaN heartbeat_success_rate should hard-fail", "non-finite heartbeat self-test"),
        ("NaN saturate rps should hard-fail", "non-finite saturate rps self-test"),
        ("non-finite resource plateau values should hard-fail", "non-finite plateau self-test"),
        ("finite zero-RPS should alert-only under alert enforcement", "zero-RPS alert-only self-test"),
    ):
        require(needle in text, f"evaluator self-test missing coverage: {label}", failures)


def validate_scenarios_contract(text: str, failures: list[str]) -> None:
    require(
        not BENCH_JSON_SWALLOWED.search(text),
        "scenarios harness must not swallow churn/soak/reload bench failures with || true",
        failures,
    )
    require(
        not WAIT_BENCH_SWALLOWED.search(text),
        "scenarios harness must not swallow reload wait failures with || true",
        failures,
    )
    require(
        not PY_BENCH_SWALLOWED.search(text),
        "scenarios harness must not swallow bench failures with || true",
        failures,
    )
    require(
        "missing usable measurement sample" in text,
        "scenarios harness must validate usable measurement samples",
        failures,
    )
    require(
        "insufficient" in text and "resource_plateau" in text,
        "scenarios harness must fail on insufficient resource sampling",
        failures,
    )
    require(
        ("churn_rc" in text and "soak_rc" in text and "reload_rc" in text)
        or ("CHURN_RC" in text and "SOAK_RC" in text and "RELOAD_RC" in text),
        "scenarios harness must capture churn/soak/reload exit codes",
        failures,
    )
    require(
        "subprocess.run" in text or "subprocess.Popen" in text,
        "scenarios harness must launch proto_bench via subprocess",
        failures,
    )
    require(
        '["./target/release/proto_bench"' in text
        or "['./target/release/proto_bench'" in text,
        "scenarios harness must use literal proto_bench argv lists",
        failures,
    )


def validate_pr_ci_contract(text: str, failures: list[str]) -> None:
    """Required PR CI must run lightweight protocol-perf validators without benches."""
    require(
        "Verify protocol-perf contracts (static)" in text,
        "ci.yml Performance Regression Check must run protocol-perf static contracts",
        failures,
    )
    require(
        "verify_protocol_perf_regression_workflow.py --self-test" in text,
        "ci.yml must run the protocol-perf workflow verifier self-test",
        failures,
    )
    require(
        "verify_protocol_perf_regression_workflow.py\n" in text
        or "verify_protocol_perf_regression_workflow.py" in text,
        "ci.yml must run repository-contract verification for protocol-perf",
        failures,
    )
    require(
        "evaluate_protocol_perf_budgets.py --self-test" in text,
        "ci.yml must run the protocol-perf evaluator self-test",
        failures,
    )
    require(
        "python3 -m py_compile tests/performance/multi_protocol/run_protocol_regression_scenarios.py"
        in text,
        "ci.yml must syntax-check the protocol regression scenario harness",
        failures,
    )
    # Ensure the static gate is not buried behind optional benchmark path filters.
    checkout_idx = text.find("performance-regression:")
    static_idx = text.find("Verify protocol-perf contracts (static)")
    detect_idx = text.find("Detect performance-sensitive changes")
    require(
        checkout_idx != -1 and static_idx != -1 and detect_idx != -1,
        "ci.yml must contain performance-regression, static protocol-perf, and path detect steps",
        failures,
    )
    if checkout_idx != -1 and static_idx != -1 and detect_idx != -1:
        require(
            checkout_idx < static_idx < detect_idx,
            "ci.yml must run protocol-perf static contracts after checkout and before "
            "optional benchmark path gating",
            failures,
        )


def validate_repository_contract(failures: list[str]) -> None:
    require(WORKFLOW_PATH.is_file(), f"missing workflow: {WORKFLOW_PATH}", failures)
    require(BUDGETS_PATH.is_file(), f"missing budgets file: {BUDGETS_PATH}", failures)
    require(EVALUATOR_PATH.is_file(), f"missing evaluator: {EVALUATOR_PATH}", failures)
    require(SCENARIOS_PATH.is_file(), f"missing scenarios harness: {SCENARIOS_PATH}", failures)
    require(RUNBOOK_PATH.is_file(), f"missing runbook: {RUNBOOK_PATH}", failures)
    require(CI_CD_PATH.is_file(), f"missing CI/CD docs: {CI_CD_PATH}", failures)
    require(CI_WORKFLOW_PATH.is_file(), f"missing CI workflow: {CI_WORKFLOW_PATH}", failures)

    if WORKFLOW_PATH.is_file():
        validate_workflow_text(WORKFLOW_PATH.read_text(encoding="utf-8"), failures)

    if EVALUATOR_PATH.is_file():
        validate_evaluator_contract(EVALUATOR_PATH.read_text(encoding="utf-8"), failures)

    if SCENARIOS_PATH.is_file():
        validate_scenarios_contract(SCENARIOS_PATH.read_text(encoding="utf-8"), failures)

    if CI_WORKFLOW_PATH.is_file():
        validate_pr_ci_contract(CI_WORKFLOW_PATH.read_text(encoding="utf-8"), failures)

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
        global_cfg = budgets.get("global", {})
        require(
            int(global_cfg.get("min_resource_samples", 0)) >= 2,
            "budgets must require a minimum resource sample count",
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
        require(
            "protocol-perf" in ci_cd.lower() and "static" in ci_cd.lower(),
            "docs/ci_cd.md must document protocol-perf static PR CI validation",
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
            "hard" in runbook.lower()
            and ("completeness" in runbook.lower() or "harness" in runbook.lower()),
            "runbook must document hard harness/data-completeness failures",
            failures,
        )
        require(
            "non-finite" in runbook.lower() or "nan" in runbook.lower(),
            "runbook must document non-finite/malformed metric hard failures",
            failures,
        )
        require(
            "ci.yml" in runbook and "overhead" in runbook.lower(),
            "runbook must preserve the lightweight PR overhead check",
            failures,
        )
        require(
            "Performance Regression Check" in runbook
            or "protocol-perf contracts" in runbook.lower(),
            "runbook must document PR CI static protocol-perf contract checks",
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
      - run: python3 tests/performance/multi_protocol/run_protocol_regression_scenarios.py
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

    swallow_failures: list[str] = []
    swallowed = """
proto_bench http1 --json > "${OUTPUT_DIR}/connection_churn.json" 2>"${OUTPUT_DIR}/connection_churn.log" || true
wait "${BENCH_PID}" || true
"""
    validate_scenarios_contract(swallowed, swallow_failures)
    if not any("swallow" in item for item in swallow_failures):
        failures.append("self-test expected || true swallow detection for scenario benches")

    good_scenarios = """
churn_rc = 0
soak_rc = 0
reload_rc = 0
subprocess.run(
    ["./target/release/proto_bench", "http1", "--json"],
    check=False,
)
# no || true after json redirects
missing usable measurement sample
resource_plateau insufficient rss_bytes sampling
"""
    good_scenario_failures: list[str] = []
    validate_scenarios_contract(good_scenarios, good_scenario_failures)
    if good_scenario_failures:
        failures.append(
            f"self-test unexpectedly rejected good scenarios snippet: {good_scenario_failures}"
        )

    pr_ci_good = """
  performance-regression:
    name: Performance Regression Check
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v6
      - name: Verify protocol-perf contracts (static)
        run: |
          python3 .github/scripts/verify_protocol_perf_regression_workflow.py --self-test
          python3 .github/scripts/verify_protocol_perf_regression_workflow.py
          python3 tests/performance/multi_protocol/evaluate_protocol_perf_budgets.py --self-test
          python3 -m py_compile tests/performance/multi_protocol/run_protocol_regression_scenarios.py
      - name: Detect performance-sensitive changes
        run: echo detect
"""
    pr_ci_failures: list[str] = []
    validate_pr_ci_contract(pr_ci_good, pr_ci_failures)
    if pr_ci_failures:
        failures.append(
            f"self-test unexpectedly rejected good PR CI snippet: {pr_ci_failures}"
        )

    pr_ci_bad_failures: list[str] = []
    validate_pr_ci_contract(
        """
  performance-regression:
    steps:
      - name: Detect performance-sensitive changes
        run: echo detect
""",
        pr_ci_bad_failures,
    )
    if not any("static" in item for item in pr_ci_bad_failures):
        failures.append("self-test expected missing protocol-perf static PR CI detection")

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
