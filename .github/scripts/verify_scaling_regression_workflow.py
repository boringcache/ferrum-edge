#!/usr/bin/env python3
"""Static contracts for Scheduled Scaling Regression (issue #3892).

Pins the weekly 180-minute matrix, workflow-sized admin JWT policy in both
affected harnesses, documented-only namespace-fence batch retries, and the
fail-closed scaling-gate signal / freshness notification. Does not execute
tests or mint tokens.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "scaling-regression.yml"
FRESHNESS_PATH = REPO_ROOT / ".github" / "workflows" / "scaling-gate-freshness.yml"
SIGNAL_PATH = REPO_ROOT / ".github" / "scripts" / "publish_scaling_gate_signal.py"
HELPER_PATH = REPO_ROOT / "tests" / "common" / "scheduled_scaling.rs"
SCALE_PATH = REPO_ROOT / "tests" / "functional" / "functional_scale_perf_test.rs"
LOAD_PATH = REPO_ROOT / "tests" / "functional" / "functional_load_stress_test.rs"
CI_CD_PATH = REPO_ROOT / "docs" / "ci_cd.md"

EXTERNAL_ACTION = re.compile(
    r"uses:\s*(?P<action>(?!\./)[^@\s]+)@(?P<ref>[^\s#]+)",
    re.IGNORECASE,
)
REQUIRED_CHECK_NAMES = (
    "Launch Readiness Gate",
    "Launch Readiness Integrity",
)
REQUIRED_LATEST_RUN_SELF_TESTS = (
    "newer failure plus older fresh success",
    "latest in-progress plus older success",
    "latest fresh success",
    "stale latest success",
    "malformed latest item",
    "future timestamp",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args()


def require(condition: bool, message: str, failures: list[str]) -> None:
    if not condition:
        failures.append(message)


def job_blocks(workflow: str) -> dict[str, str]:
    lines = workflow.splitlines(keepends=True)
    headers = [index for index, line in enumerate(lines) if line.rstrip("\r\n") == "jobs:"]
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


def validate_workflow_text(text: str, failures: list[str]) -> None:
    require("schedule:" in text, "workflow must declare a schedule trigger", failures)
    require('cron: "0 4 * * 6"' in text, "workflow must keep the Saturday 04:00 UTC cron", failures)
    require("workflow_dispatch:" in text, "workflow must declare workflow_dispatch", failures)
    require(
        "pull_request:" not in text and "pull_request_target:" not in text,
        "scaling workflow must not execute untrusted pull-request code",
        failures,
    )
    require("timeout-minutes: 180" in text, "matrix jobs must keep the 180-minute timeout", failures)
    require("permissions:" in text, "workflow must declare explicit permissions", failures)
    require("contents: read" in text, "workflow must use contents: read", failures)
    require(
        "LAUNCH_ADVISORY_READ_TOKEN" not in text,
        "scaling workflow must not reference the advisory token",
        failures,
    )
    for name in REQUIRED_CHECK_NAMES:
        live = re.sub(r"#.*", "", text)
        require(
            name not in live,
            f"scaling workflow must not mention required check name {name}",
            failures,
        )

    blocks = job_blocks(text)
    require(
        "scaling-regression" in blocks,
        "workflow must keep the scaling-regression matrix job",
        failures,
    )
    require(
        "scaling-gate-signal" in blocks,
        "workflow must publish the scaling-gate signal job",
        failures,
    )
    matrix = blocks.get("scaling-regression", "")
    signal = blocks.get("scaling-gate-signal", "")
    require(
        "issues: write" not in matrix,
        "matrix job must not receive issues: write",
        failures,
    )
    require(
        "actions: write" not in matrix,
        "matrix job must not receive actions: write",
        failures,
    )
    require("issues: write" in signal, "signal job must request issues: write", failures)
    require("actions: read" in signal, "signal job must request actions: read", failures)
    require("contents: write" not in signal, "signal job must not request contents: write", failures)
    require("if: always()" in signal, "signal job must run after matrix failure", failures)
    require(
        "publish_scaling_gate_signal.py" in signal,
        "signal job must run the scaling-gate publisher",
        failures,
    )
    require(
        "SCALING_JOB_RESULT: ${{ needs.scaling-regression.result }}" in signal,
        "signal job must bind to the matrix job result",
        failures,
    )
    require(
        "verify_scaling_regression_workflow.py --self-test" in text,
        "workflow must self-test this verifier",
        failures,
    )

    for match in EXTERNAL_ACTION.finditer(text):
        ref = match.group("ref")
        require(
            bool(re.fullmatch(r"[0-9a-f]{40}", ref, flags=re.IGNORECASE)),
            f"mutable external action ref forbidden: {match.group('action')}@{ref}",
            failures,
        )


def validate_freshness_text(text: str, failures: list[str]) -> None:
    require("schedule:" in text, "freshness workflow must declare a schedule trigger", failures)
    require('cron: "0 12 * * *"' in text, "freshness workflow must run daily at 12:00 UTC", failures)
    require(
        "pull_request:" not in text and "pull_request_target:" not in text,
        "freshness workflow must not execute untrusted pull-request code",
        failures,
    )
    require("issues: write" in text, "freshness workflow must request issues: write", failures)
    require("actions: read" in text, "freshness workflow must request actions: read", failures)
    require("contents: write" not in text, "freshness workflow must not request contents: write", failures)
    require(
        "cargo test" not in text and "cargo build" not in text,
        "freshness workflow must not run the 10k/30k suites",
        failures,
    )
    require(
        "publish_scaling_gate_signal.py" in text,
        "freshness workflow must run the scaling-gate publisher",
        failures,
    )
    require(
        "LAUNCH_ADVISORY_READ_TOKEN" not in text,
        "freshness workflow must not reference the advisory token",
        failures,
    )
    live = re.sub(r"#.*", "", text)
    for name in REQUIRED_CHECK_NAMES:
        require(
            name not in live,
            f"freshness workflow must not mention required check name {name}",
            failures,
        )
    for match in EXTERNAL_ACTION.finditer(text):
        ref = match.group("ref")
        require(
            bool(re.fullmatch(r"[0-9a-f]{40}", ref, flags=re.IGNORECASE)),
            f"mutable external action ref forbidden: {match.group('action')}@{ref}",
            failures,
        )


def validate_signal_text(text: str, failures: list[str]) -> None:
    require("MAX_AGE_SECONDS = 8 * 24 * 60 * 60" in text, "signal must keep the 8-day ceiling", failures)
    require('ISSUE_LABELS = ("severity:high",)' in text, "signal must label the issue severity:high", failures)
    require("ferrum-scaling-gate-signal" in text, "signal must use a stable issue marker", failures)
    require("pull_request" in text, "signal must refuse pull-request events", failures)
    require('ref == "refs/heads/main"' in text, "signal must mutate issues only on main", failures)
    require("fail-closed" in text or "fail_job" in text, "signal must fail closed on unknown history", failures)
    require("def self_test" in text, "signal publisher must have a self-test", failures)
    require("search/issues" not in text, "signal must not use full-text issue search", failures)
    require('SIGNAL_AUTHOR = "github-actions[bot]"' in text, "signal must require the Actions bot author", failures)
    require('"state": "all"' in text, "signal must list issues with state=all", failures)
    production, sep, self_test_src = text.partition("def self_test")
    require(sep == "def self_test", "signal must define self_test", failures)
    require(
        "def latest_run_on_main" in production,
        "signal must inspect the latest scaling-regression run on main",
        failures,
    )
    require(
        '"status": "success"' not in production,
        "freshness must not query only successful workflow runs",
        failures,
    )
    require(
        "out of order" in production,
        "signal must fail closed on out-of-order workflow run history",
        failures,
    )
    require(
        "in_progress" in production,
        "signal must fail closed when the latest scaling run is still in progress",
        failures,
    )
    for label in REQUIRED_LATEST_RUN_SELF_TESTS:
        require(
            label in self_test_src,
            f"signal self-test must cover {label}",
            failures,
        )
    for name in REQUIRED_CHECK_NAMES:
        require(
            name not in text,
            f"signal publisher must not mention required check name {name}",
            failures,
        )


def validate_helper_text(text: str, failures: list[str]) -> None:
    require(
        "SCHEDULED_SCALING_ADMIN_JWT_TTL_SECS: i64 = 4 * 60 * 60" in text,
        "helper must pin the 4-hour admin JWT TTL",
        failures,
    )
    require(
        'NAMESPACE_FENCE_RETRY_MESSAGE: &str =\n    "Namespace mutation is temporarily unavailable; retry later"'
        in text
        or '"Namespace mutation is temporarily unavailable; retry later"' in text,
        "helper must pin the documented namespace-fence message",
        failures,
    )
    require("classify_admin_batch_response" in text, "helper must classify batch responses", failures)
    require("status == 503" in text, "helper must require HTTP 503", failures)
    require("NAMESPACE_FENCE_MAX_ATTEMPTS" in text, "helper must bound retries", failures)
    require("transport error" in text, "helper must not retry transport errors", failures)
    require("unreadable body" in text, "helper must not retry malformed bodies", failures)


def validate_harness_text(name: str, text: str, failures: list[str]) -> None:
    require(
        "SCHEDULED_SCALING_ADMIN_JWT_TTL_SECS" in text,
        f"{name} must mint admin JWTs with the workflow-sized TTL",
        failures,
    )
    require(
        "FERRUM_ADMIN_JWT_MAX_TTL" in text,
        f"{name} must configure the gateway to accept that TTL",
        failures,
    )
    require(
        "post_admin_batch" in text,
        f"{name} must use the shared atomic batch helper",
        failures,
    )
    require(
        text.count("post_admin_batch(") >= 3,
        f"{name} must wrap every batch-provisioning phase",
        failures,
    )
    require(
        ".post(format!(\"{}/batch\"" not in text and '.post(format!("{}/batch"' not in text,
        f"{name} must not call POST /batch outside the shared helper",
        failures,
    )


def validate_load_consumer_separation(text: str, failures: list[str]) -> None:
    require(
        "fn generate_consumer_jwt" in text,
        "load-stress must keep a dedicated consumer JWT helper",
        failures,
    )
    require(
        'chrono::Duration::seconds(3600)' in text,
        "consumer JWTs must remain on the 1-hour mint path",
        failures,
    )
    require(
        "SCHEDULED_SCALING_ADMIN_JWT_TTL_SECS" in text.split("fn generate_consumer_jwt", 1)[0]
        or "generate_admin_token" in text,
        "admin TTL must not be the only token lifetime in the load harness",
        failures,
    )
    consumer_fn = text.split("fn generate_consumer_jwt", 1)[1].split("fn ", 1)[0]
    require(
        "SCHEDULED_SCALING_ADMIN_JWT_TTL_SECS" not in consumer_fn,
        "consumer JWT minting must not reuse the admin workflow TTL",
        failures,
    )


def validate_repository_contract(failures: list[str]) -> None:
    require(WORKFLOW_PATH.is_file(), f"missing workflow: {WORKFLOW_PATH}", failures)
    require(FRESHNESS_PATH.is_file(), f"missing freshness workflow: {FRESHNESS_PATH}", failures)
    require(SIGNAL_PATH.is_file(), f"missing signal publisher: {SIGNAL_PATH}", failures)
    require(HELPER_PATH.is_file(), f"missing helper: {HELPER_PATH}", failures)
    require(SCALE_PATH.is_file(), f"missing scale harness: {SCALE_PATH}", failures)
    require(LOAD_PATH.is_file(), f"missing load harness: {LOAD_PATH}", failures)

    if WORKFLOW_PATH.is_file():
        validate_workflow_text(WORKFLOW_PATH.read_text(encoding="utf-8"), failures)
    if FRESHNESS_PATH.is_file():
        validate_freshness_text(FRESHNESS_PATH.read_text(encoding="utf-8"), failures)
    if SIGNAL_PATH.is_file():
        validate_signal_text(SIGNAL_PATH.read_text(encoding="utf-8"), failures)
    if HELPER_PATH.is_file():
        validate_helper_text(HELPER_PATH.read_text(encoding="utf-8"), failures)
    if SCALE_PATH.is_file():
        validate_harness_text("scale harness", SCALE_PATH.read_text(encoding="utf-8"), failures)
    if LOAD_PATH.is_file():
        load = LOAD_PATH.read_text(encoding="utf-8")
        validate_harness_text("load harness", load, failures)
        validate_load_consumer_separation(load, failures)
    if CI_CD_PATH.is_file():
        ci_cd = CI_CD_PATH.read_text(encoding="utf-8")
        require(
            "scaling-gate-freshness.yml" in ci_cd,
            "docs/ci_cd.md must record the scaling-gate freshness workflow",
            failures,
        )


def self_test() -> int:
    failures: list[str] = []
    good_workflow = """
name: Scheduled Scaling Regression
on:
  schedule:
    - cron: "0 4 * * 6"
  workflow_dispatch:
permissions:
  contents: read
jobs:
  scaling-regression:
    timeout-minutes: 180
    steps:
      - name: Verify workflow contract (static)
        run: python3 -I .github/scripts/verify_scaling_regression_workflow.py --self-test
  scaling-gate-signal:
    if: always()
    permissions:
      contents: read
      actions: read
      issues: write
    steps:
      - run: python3 -I .github/scripts/publish_scaling_gate_signal.py
        env:
          SCALING_JOB_RESULT: ${{ needs.scaling-regression.result }}
"""
    workflow_failures: list[str] = []
    validate_workflow_text(good_workflow, workflow_failures)
    if workflow_failures:
        failures.append(f"self-test unexpectedly rejected good workflow: {workflow_failures}")

    bad_workflow_failures: list[str] = []
    validate_workflow_text("on:\n  pull_request:\n", bad_workflow_failures)
    if not bad_workflow_failures:
        failures.append("self-test expected pull_request workflow to fail")

    good_signal = """
MAX_AGE_SECONDS = 8 * 24 * 60 * 60
ISSUE_LABELS = ("severity:high",)
ferrum-scaling-gate-signal
pull_request
ref == "refs/heads/main"
fail-closed
SIGNAL_AUTHOR = "github-actions[bot]"
"state": "all"
def latest_run_on_main
in_progress
out of order
def self_test
newer failure plus older fresh success
latest in-progress plus older success
latest fresh success
stale latest success
malformed latest item
future timestamp
"""
    signal_failures: list[str] = []
    validate_signal_text(good_signal, signal_failures)
    if signal_failures:
        failures.append(f"self-test unexpectedly rejected good signal: {signal_failures}")

    success_only_failures: list[str] = []
    validate_signal_text(
        good_signal.replace(
            "def latest_run_on_main",
            '"status": "success"\ndef latest_run_on_main',
        ),
        success_only_failures,
    )
    if not any("successful workflow runs" in item for item in success_only_failures):
        failures.append("self-test expected status=success freshness query to fail")

    missing_label_failures: list[str] = []
    validate_signal_text(
        good_signal.replace("newer failure plus older fresh success\n", ""),
        missing_label_failures,
    )
    if not any("newer failure plus older fresh success" in item for item in missing_label_failures):
        failures.append("self-test expected missing latest-run self-test label to fail")

    if failures:
        for failure in failures:
            print(f"::error::self-test: {failure}")
        return 1
    print("scaling-regression workflow verifier self-test passed")
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
    print("scaling-regression workflow contract ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
