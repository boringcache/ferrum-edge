#!/usr/bin/env python3
"""Verify that the CI aggregate waits on every required validation job."""

from __future__ import annotations

import re
import sys
from pathlib import Path


REQUIRED_JOBS = {
    "ci-plan",
    "fmt",
    "test-unit",
    "test-lib",
    "test-secrets",
    "test-service-integration",
    "test-pkcs11-softhsm",
    "build-integration-tests-archive",
    "test-integration",
    "test-integration-coverage",
    "test-conformance",
    "dependency-audit",
    "test-vendor-patches",
    "build-gateway-binary",
    "build-functional-tests-archive",
    "test-functional",
    "plugin-hardening-redis-regression",
    "gateway-api-conformance",
    "coverage-gate",
    "mesh-multicluster-federation",
    "mesh-e2e-sidecar",
    "mesh-e2e-sidecar-live",
    "helm-chart",
    "lint",
    "detect-ebpf-live-changes",
    "build-ebpf",
    "build-ebpf-userspace",
    "ebpf-live",
    "netns-capture-live",
    "two-cluster-mesh-live",
    "performance-regression",
    "build-binaries",
}

# These jobs do not depend on another full-CI validation job, so each must
# directly depend on the planner and enforce full mode. Other required jobs are
# downstream of one of these roots and are skipped transitively in light mode.
DIRECT_FULL_CI_JOBS = {
    "fmt",
    "test-unit",
    "test-lib",
    "test-secrets",
    "test-service-integration",
    "test-pkcs11-softhsm",
    "build-integration-tests-archive",
    "test-conformance",
    "dependency-audit",
    "test-vendor-patches",
    "build-gateway-binary",
    "build-functional-tests-archive",
    "gateway-api-conformance",
    "coverage-gate",
    "mesh-e2e-sidecar-live",
    "lint",
    "detect-ebpf-live-changes",
    "build-ebpf",
    "build-ebpf-userspace",
    "performance-regression",
    "build-binaries",
}


def extract_test_needs(ci_yml: str) -> set[str]:
    match = re.search(r"(?ms)^  test:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)", ci_yml)
    if not match:
        raise RuntimeError("could not find jobs.test in ci.yml")

    body = match.group("body")
    needs_match = re.search(r"(?m)^    needs:\n(?P<needs>(?:^      - [^\n]+\n)+)", body)
    if not needs_match:
        raise RuntimeError("could not find jobs.test.needs in ci.yml")

    return {
        line.strip().removeprefix("- ").strip()
        for line in needs_match.group("needs").splitlines()
        if line.strip().startswith("- ")
    }


def extract_job_body(ci_yml: str, job: str) -> str:
    match = re.search(
        rf"(?ms)^  {re.escape(job)}:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
        ci_yml,
    )
    if not match:
        raise RuntimeError(f"could not find jobs.{job} in ci.yml")
    return match.group("body")


def main() -> int:
    ci_path = Path(".github/workflows/ci.yml")
    ci_yml = ci_path.read_text(encoding="utf-8")
    needs = extract_test_needs(ci_yml)
    missing = sorted(REQUIRED_JOBS - needs)
    extra = sorted(needs - REQUIRED_JOBS)

    planner_errors: list[str] = []
    for job in sorted(DIRECT_FULL_CI_JOBS):
        body = extract_job_body(ci_yml, job)
        if not re.search(r"(?m)^    needs: ci-plan$", body):
            planner_errors.append(f"jobs.{job} must directly need ci-plan")
        if "needs.ci-plan.outputs.mode == 'full'" not in body:
            planner_errors.append(f"jobs.{job} must require full CI mode")

    if not missing and not extra and not planner_errors:
        print(
            f"Required CI aggregate covers {len(REQUIRED_JOBS)} jobs; "
            f"{len(DIRECT_FULL_CI_JOBS)} roots enforce the CI plan."
        )
        return 0

    for job in missing:
        print(f"::error::jobs.test.needs is missing required job `{job}`", file=sys.stderr)
    for job in extra:
        print(
            f"::error::jobs.test.needs includes `{job}` but verify_required_ci.py does not document it",
            file=sys.stderr,
        )
    for error in planner_errors:
        print(f"::error::{error}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
