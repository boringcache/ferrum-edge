#!/usr/bin/env python3
"""Static contract checks for the mesh performance baselines workflow (#3332).

Does not execute benchmarks. Validates workflow wiring, pinned actions, suite
coverage, provenance/summary scripts, and docs inventory pointers.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "mesh-performance-baselines.yml"
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
    require("runs-on: ${{ inputs.runner" in text, "named runner input must drive runs-on", failures)
    require("ubuntu-latest" in text, "default runner class must be ubuntu-latest", failures)
    require("workflow_call:" in text, "workflow_call required for PR-branch dispatch via perf-benchmark.yml", failures)
    require("BENCH_BUILD_PROFILE: release" in text, "release profile required", failures)
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


def check_docs_and_baselines(failures: list[str]) -> None:
    require(PROVENANCE_SCRIPT.is_file(), "provenance script missing", failures)
    require(SUMMARY_SCRIPT.is_file(), "summary script missing", failures)
    require(WORKFLOW_PATH.is_file(), "workflow missing", failures)

    protocol = PROTOCOL_DOC.read_text(encoding="utf-8")
    require("mesh-performance-baselines.yml" in protocol, "protocol_perf_regression.md missing workflow pointer", failures)
    require("#3332" in protocol, "protocol_perf_regression.md must keep #3332 pointer", failures)

    ci_cd = CI_CD_DOC.read_text(encoding="utf-8")
    require("mesh-performance-baselines.yml" in ci_cd, "ci_cd.md inventory missing workflow row", failures)

    for path in (MESH_BASELINE, HBONE_BASELINE, DNS_BASELINE):
        text = path.read_text(encoding="utf-8")
        require("Overhead formula" in text or "overhead formula" in text.lower(), f"{path} missing overhead formula", failures)
        require("Rerun procedure" in text or "rerun procedure" in text.lower(), f"{path} missing rerun procedure", failures)
        require("refresh" in text.lower() or "cadence" in text.lower(), f"{path} missing refresh cadence", failures)
        require("directional" in text.lower(), f"{path} missing directional hardware caveat", failures)
        require("bottleneck" in text.lower(), f"{path} missing bottleneck review note", failures)


def self_test() -> int:
    sample = """
name: Mesh Performance Baselines
on:
  workflow_dispatch:
    inputs:
      runner:
        default: "ubuntu-latest"
  workflow_call:
    inputs:
      runner:
        default: "ubuntu-latest"
        type: string
permissions:
  contents: read
env:
  BENCH_BUILD_PROFILE: release
jobs:
  collect:
    runs-on: ${{ inputs.runner || 'ubuntu-latest' }}
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
      - uses: ./.github/actions/setup-rust-ci
      - run: authz_match ip_restriction slice_apply xds_translation
      - run: 1kib_c50_30s 16kib_c50_30s 256kib_c100_60s
      - run: ./run.sh --duration 60 --concurrency 100
      - run: collect_mesh_baseline_provenance.py
      - run: summarize_mesh_baseline_results.py
      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a
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
    check_docs_and_baselines(failures)
    if failures:
        for failure in failures:
            print(f"::error::{failure}")
        return 1
    print("Mesh performance baselines workflow contract OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
