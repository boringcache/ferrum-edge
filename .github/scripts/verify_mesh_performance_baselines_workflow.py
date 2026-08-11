#!/usr/bin/env python3
"""Static contract checks for the mesh performance baselines workflow (#3332).

Does not execute benchmarks. Validates workflow wiring, pinned actions, suite
coverage, provenance/summary scripts, ubuntu-24.04 pin, acceptance step, and
docs inventory pointers.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "mesh-performance-baselines.yml"
PERF_BENCHMARK_PATH = REPO_ROOT / ".github" / "workflows" / "perf-benchmark.yml"
PROVENANCE_SCRIPT = REPO_ROOT / ".github" / "scripts" / "collect_mesh_baseline_provenance.py"
SUMMARY_SCRIPT = REPO_ROOT / ".github" / "scripts" / "summarize_mesh_baseline_results.py"
PROTOCOL_DOC = REPO_ROOT / "docs" / "protocol_perf_regression.md"
CI_CD_DOC = REPO_ROOT / "docs" / "ci_cd.md"
MESH_BASELINE = REPO_ROOT / "tests" / "performance" / "mesh" / "baseline.md"
HBONE_BASELINE = REPO_ROOT / "tests" / "performance" / "mesh-hbone-e2e" / "baseline.md"
DNS_BASELINE = REPO_ROOT / "tests" / "performance" / "mesh-dns-e2e" / "baseline.md"

EXTERNAL_ACTION = re.compile(
    r"uses:\s*(?P<action>(?!\./)[^@\s]+)@(?P<ref>[^\s#]+)",
    re.IGNORECASE,
)
APPROVED_SETUP = (
    "./.github/actions/setup-rust-ci",
    "./.github/actions/setup-sccache",
    "./.github/actions/setup-fast-linker",
)
PINNED_SHA = re.compile(r"^[0-9a-f]{40}$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args()


def require(condition: bool, message: str, failures: list[str]) -> None:
    if not condition:
        failures.append(message)


def check_workflow(text: str, failures: list[str]) -> None:
    require("name: Mesh Performance Baselines" in text, "workflow display name missing", failures)
    require("workflow_dispatch:" in text, "workflow_dispatch trigger required", failures)
    require("runs-on: ubuntu-24.04" in text, "collection must pin runs-on ubuntu-24.04", failures)
    require("BENCH_RUNNER_CLASS: ubuntu-24.04" in text, "BENCH_RUNNER_CLASS must be ubuntu-24.04", failures)
    require("ubuntu-24.04" in text, "default runner class must be ubuntu-24.04", failures)
    require("inputs:\n      runner:" not in text and "runner:" not in _workflow_inputs_block(text), "arbitrary runner input must be removed", failures)
    require(
        "runs-on: self-hosted" not in text.lower()
        and "runs-on: [self-hosted" not in text.lower()
        and "- self-hosted" not in text.lower(),
        "must not dispatch to self-hosted runners",
        failures,
    )
    require("workflow_call:" in text, "workflow_call required for PR-branch dispatch via perf-benchmark.yml", failures)
    require("BENCH_BUILD_PROFILE: release" in text, "release profile required", failures)
    require("BENCH_MAX_CPU_STEAL_PERCENT: \"5.0\"" in text or "BENCH_MAX_CPU_STEAL_PERCENT: '5.0'" in text, "documented CPU steal threshold required", failures)
    require("runner_health.json" in text, "machine-readable runner_health.json required", failures)
    require("runner_health_probes.jsonl" in text, "per-E2E runner health probes required", failures)
    require("--check-acceptance" in text, "selected-suite acceptance step required", failures)
    require("authz_match" in text and "ip_restriction" in text, "mesh benches incomplete", failures)
    require("slice_apply" in text and "xds_translation" in text, "mesh benches incomplete", failures)
    require("1kib_c50_30s" in text and "16kib_c50_30s" in text, "HBONE scenarios incomplete", failures)
    require("256kib_c100_60s" in text, "HBONE 256 KiB scenario missing", failures)
    require("--duration 60 --concurrency 100" in text, "DNS documented row params missing", failures)
    require("collect_mesh_baseline_provenance.py" in text, "provenance script not wired", failures)
    require("summarize_mesh_baseline_results.py" in text, "summary script not wired", failures)
    require("actions/upload-artifact@" in text, "artifact upload required", failures)
    require("mesh-performance-baselines-${{ github.sha }}" in text, "artifact name must include SHA", failures)
    require("permissions:\n  contents: read" in text, "contents: read permission required", failures)
    # Upload must remain available after acceptance failure.
    upload_idx = text.find("Upload mesh baseline artifacts")
    accept_idx = text.find("Enforce selected-suite acceptance gates")
    require(upload_idx != -1 and accept_idx != -1, "acceptance + upload steps required", failures)
    require(accept_idx < upload_idx, "acceptance step must precede artifact upload", failures)
    require(
        "if: always()" in text[upload_idx : upload_idx + 200],
        "artifact upload must use if: always()",
        failures,
    )

    for match in EXTERNAL_ACTION.finditer(text):
        action = match.group("action")
        ref = match.group("ref")
        require(
            PINNED_SHA.match(ref) is not None,
            f"external action {action} must be pinned to a 40-char SHA (got {ref})",
            failures,
        )

    for setup in APPROVED_SETUP:
        # setup-rust-ci is required; the others may appear transitively.
        pass
    require("./.github/actions/setup-rust-ci" in text, "must use setup-rust-ci", failures)


def _workflow_inputs_block(text: str) -> str:
    """Return concatenated workflow_dispatch + workflow_call inputs sections."""
    blocks: list[str] = []
    for trigger in ("workflow_dispatch:", "workflow_call:"):
        start = text.find(trigger)
        if start == -1:
            continue
        # Capture until permissions/concurrency/env/jobs at top level-ish.
        chunk = text[start : start + 1200]
        blocks.append(chunk)
    return "\n".join(blocks)


def check_caller_and_scripts(failures: list[str]) -> None:
    require(PROVENANCE_SCRIPT.is_file(), "provenance script missing", failures)
    require(SUMMARY_SCRIPT.is_file(), "summary script missing", failures)
    require(WORKFLOW_PATH.is_file(), "workflow missing", failures)

    provenance = PROVENANCE_SCRIPT.read_text(encoding="utf-8")
    require("ubuntu-24.04" in provenance, "provenance default runner class must be ubuntu-24.04", failures)

    summary = SUMMARY_SCRIPT.read_text(encoding="utf-8")
    require("repetition_evidence" in summary, "summarizer must expose repetition_evidence", failures)
    require("MAX_CPU_STEAL_PERCENT" in summary, "summarizer must document steal threshold", failures)
    require("DNS_GATEWAY_ROWS" in summary, "summarizer must enumerate required DNS gateway rows", failures)
    require("--check-acceptance" in summary, "summarizer must support acceptance check", failures)
    require("undersampling" in summary or "one gateway" in summary, "summarizer self-test must cover undersampling", failures)

    if PERF_BENCHMARK_PATH.is_file():
        caller = PERF_BENCHMARK_PATH.read_text(encoding="utf-8")
        if "mesh-performance-baselines.yml" in caller:
            require(
                "runner:" not in caller.split("mesh-performance-baselines.yml", 1)[1].split("benchmark:", 1)[0],
                "perf-benchmark mesh_baselines caller must not pass runner input",
                failures,
            )


def check_docs_and_baselines(failures: list[str]) -> None:
    protocol = PROTOCOL_DOC.read_text(encoding="utf-8")
    require("mesh-performance-baselines.yml" in protocol, "protocol_perf_regression.md missing workflow pointer", failures)
    require("#3332" in protocol, "protocol_perf_regression.md must keep #3332 pointer", failures)
    require("ubuntu-24.04" in protocol, "protocol_perf_regression.md must document ubuntu-24.04 pin", failures)

    ci_cd = CI_CD_DOC.read_text(encoding="utf-8")
    require("mesh-performance-baselines.yml" in ci_cd, "ci_cd.md inventory missing workflow row", failures)

    for path in (MESH_BASELINE, HBONE_BASELINE, DNS_BASELINE):
        text = path.read_text(encoding="utf-8")
        require("Overhead formula" in text or "overhead formula" in text.lower(), f"{path} missing overhead formula", failures)
        require("Rerun procedure" in text or "rerun procedure" in text.lower(), f"{path} missing rerun procedure", failures)
        require("refresh" in text.lower() or "cadence" in text.lower(), f"{path} missing refresh cadence", failures)
        require("directional" in text.lower(), f"{path} missing directional hardware caveat", failures)
        require("bottleneck" in text.lower(), f"{path} missing bottleneck review note", failures)
        require("ubuntu-24.04" in text, f"{path} must pin runner class ubuntu-24.04", failures)
        require("_TBD_" in text, f"{path} must keep stage-1 TBD cells (no fabricated numbers)", failures)
        require("5.0%" in text or "5%" in text, f"{path} must document CPU steal publication threshold", failures)


def self_test() -> int:
    sample = """
name: Mesh Performance Baselines
on:
  workflow_dispatch:
    inputs:
      suites:
        default: "all"
      iterations:
        default: "3"
  workflow_call:
    inputs:
      suites:
        default: "all"
        type: string
      iterations:
        default: "3"
        type: string
permissions:
  contents: read
env:
  BENCH_BUILD_PROFILE: release
  BENCH_RUNNER_CLASS: ubuntu-24.04
  BENCH_MAX_CPU_STEAL_PERCENT: "5.0"
jobs:
  collect:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
      - uses: ./.github/actions/setup-rust-ci
      - run: authz_match ip_restriction slice_apply xds_translation
      - run: 1kib_c50_30s 16kib_c50_30s 256kib_c100_60s
      - run: ./run.sh --duration 60 --concurrency 100
      - run: collect_mesh_baseline_provenance.py
      - run: summarize_mesh_baseline_results.py
      - run: runner_health.json runner_health_probes.jsonl
      - name: Enforce selected-suite acceptance gates
        if: always()
        run: --check-acceptance
      - name: Upload mesh baseline artifacts
        if: always()
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a
        with:
          name: mesh-performance-baselines-${{ github.sha }}
"""
    failures: list[str] = []
    check_workflow(sample, failures)
    # Intentionally skip docs checks in self-test.
    if failures:
        print("self-test failures:", *failures, sep="\n- ")
        return 1
    print("verify_mesh_performance_baselines_workflow self-test passed")
    return 0


def main() -> int:
    args = parse_args()
    if args.self_test:
        return self_test()

    failures: list[str] = []
    text = WORKFLOW_PATH.read_text(encoding="utf-8")
    check_workflow(text, failures)
    check_caller_and_scripts(failures)
    check_docs_and_baselines(failures)
    if failures:
        for failure in failures:
            print(f"::error::{failure}")
        return 1
    print("Mesh performance baselines workflow contract OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
