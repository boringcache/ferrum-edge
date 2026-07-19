#!/usr/bin/env python3
"""Verify that the CI aggregate waits on every required validation job."""

from __future__ import annotations

import re
import sys
from pathlib import Path

from live_suite_path_filter import (
    LIVE_SUITE_DOCUMENTATION_PATHS,
    SUITE_PATTERNS,
    exact_path_patterns,
)
from pr_ci_plan import FULL_CI_DOCUMENTATION_PATHS


REQUIRED_JOBS = {
    "ci-plan",
    "test-unit",
    "test-secrets",
    "test-service-integration",
    "test-pkcs11-softhsm",
    "build-test-artifacts",
    "test-integration",
    "test-conformance",
    "dependency-audit",
    "test-vendor-patches",
    "test-functional",
    "plugin-hardening-redis-regression",
    "mesh-multicluster-federation",
    "mesh-e2e-sidecar",
    "helm-chart",
    "lint",
    "build-ebpf",
    "build-ebpf-userspace",
    "ebpf-live",
    "netns-capture-live",
    "two-cluster-mesh-live",
    "performance-regression",
    "build-binaries",
    "build-arm64-cross",
}

# These jobs do not depend on another full-CI validation job, so each must
# directly depend on the planner and enforce full mode. Other required jobs are
# downstream of one of these roots and are skipped transitively in light mode.
DIRECT_FULL_CI_JOBS = {
    "test-unit",
    "test-secrets",
    "test-service-integration",
    "test-pkcs11-softhsm",
    "build-test-artifacts",
    "test-conformance",
    "dependency-audit",
    "lint",
    "build-ebpf-userspace",
    "performance-regression",
    "build-binaries",
    "build-arm64-cross",
}

PATH_GATED_JOBS = {
    "mesh-multicluster-federation": "run_mesh_federation",
    "mesh-e2e-sidecar": "run_mesh_sidecar_smoke",
    "helm-chart": "run_helm",
    "build-ebpf": "run_ebpf_build",
    "ebpf-live": "run_ebpf_live",
    "netns-capture-live": "run_ebpf_live",
    "two-cluster-mesh-live": "run_ebpf_live",
}

REMOVED_JOBS = {
    "fmt",
    "test-lib",
    "build-integration-tests-archive",
    "test-integration-coverage",
    "build-gateway-binary",
    "build-functional-tests-archive",
    "detect-ebpf-live-changes",
}

REMOVED_MIRROR_JOBS = {
    "coverage-gate",
    "gateway-api-conformance",
    "mesh-e2e-sidecar-live",
}

DEDICATED_REQUIRED_CHECKS = {
    ".github/workflows/coverage.yml": {
        "job": "coverage-merge",
        "name": "Merge Coverage",
        "needs": {"coverage-plan", "coverage-shard"},
        "contract": {
            "needs.coverage-plan.result != 'success'",
            "needs.coverage-plan.outputs.mode == 'skip'",
            "needs.coverage-plan.outputs.mode == 'full' && needs.coverage-shard.result != 'success'",
            "!contains(fromJSON('[\"skip\", \"plugin\", \"full\"]'), needs.coverage-plan.outputs.mode)",
        },
    },
    ".github/workflows/gateway-api-conformance.yml": {
        "job": "gate",
        "name": "Gateway API Conformance",
        "needs": {"changes", "gateway-api-conformance"},
        "contract": {
            '${{ needs.changes.result }}" != "success"',
            '${{ needs.changes.outputs.relevant }}" = "false"',
            '${{ needs.changes.outputs.relevant }}" != "true"',
            '${{ needs.gateway-api-conformance.result }}" != "success"',
        },
    },
    ".github/workflows/mesh-e2e-sidecar-live.yml": {
        "job": "gate",
        "name": "Mesh E2E Sidecar Live",
        "needs": {"changes", "mesh-e2e-sidecar-live"},
        "contract": {
            '${{ needs.changes.result }}" != "success"',
            '${{ needs.changes.outputs.relevant }}" = "false"',
            '${{ needs.changes.outputs.relevant }}" != "true"',
            '${{ needs.mesh-e2e-sidecar-live.result }}" != "success"',
        },
    },
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


def job_needs(body: str, dependency: str) -> bool:
    scalar = re.search(rf"(?m)^    needs: {re.escape(dependency)}$", body)
    inline = re.search(
        rf"(?m)^    needs: \[[^\n]*\b{re.escape(dependency)}\b[^\n]*\]$", body
    )
    block = re.search(rf"(?m)^      - {re.escape(dependency)}$", body)
    return bool(scalar or inline or block)

def extract_job_needs(job_body: str) -> set[str]:
    list_match = re.search(
        r"(?m)^    needs:\n(?P<needs>(?:^      - [^\n]+\n)+)", job_body
    )
    if list_match:
        return {
            line.strip().removeprefix("- ").strip()
            for line in list_match.group("needs").splitlines()
            if line.strip().startswith("- ")
        }

    scalar_match = re.search(r"(?m)^    needs: ([A-Za-z0-9_-]+)$", job_body)
    if scalar_match:
        return {scalar_match.group(1)}
    return set()


def pull_request_trigger_is_unconditional(workflow_yml: str) -> bool:
    workflow_header = workflow_yml.split("\njobs:\n", maxsplit=1)[0]
    pull_request = re.search(
        r"(?ms)^  pull_request:(?P<body>.*?)(?=^  [A-Za-z_]+:|\Z)",
        workflow_header,
    )
    if not pull_request:
        return False
    body = pull_request.group("body")
    return not re.search(r"(?m)^    paths(?:-ignore)?:", body)


def extract_documentation_paths(workflow_yml: str) -> set[str]:
    paths = set(
        re.findall(
            r"(?m)^\s+-\s+[\"']?(docs/[^\"'\s]+)[\"']?\s*$",
            workflow_yml,
        )
    )
    if not paths:
        raise RuntimeError("could not find documentation paths in live workflow")
    return paths


def main() -> int:
    ci_path = Path(".github/workflows/ci.yml")
    ci_yml = ci_path.read_text(encoding="utf-8")
    needs = extract_test_needs(ci_yml)
    missing = sorted(REQUIRED_JOBS - needs)
    extra = sorted(needs - REQUIRED_JOBS)

    planner_errors: list[str] = []
    aggregate_body = extract_job_body(ci_yml, "test")
    for job in sorted(REQUIRED_JOBS):
        if f"needs.{job}.result" not in aggregate_body:
            planner_errors.append(
                f"jobs.test must report and enforce the result of `{job}`"
            )

    for job in sorted(REMOVED_MIRROR_JOBS):
        if re.search(rf"(?m)^  {re.escape(job)}:$", ci_yml):
            planner_errors.append(f"jobs.{job} must remain removed from ci.yml")
    if "(CI mirror)" in ci_yml:
        planner_errors.append("ci.yml must not contain runner-holding CI mirror jobs")

    for job in sorted(DIRECT_FULL_CI_JOBS):
        body = extract_job_body(ci_yml, job)
        if not job_needs(body, "ci-plan"):
            planner_errors.append(f"jobs.{job} must directly need ci-plan")
        if "needs.ci-plan.outputs.mode == 'full'" not in body:
            planner_errors.append(f"jobs.{job} must require full CI mode")

    for job, output in sorted(PATH_GATED_JOBS.items()):
        body = extract_job_body(ci_yml, job)
        if not job_needs(body, "ci-plan"):
            planner_errors.append(f"jobs.{job} must directly need ci-plan")
        if "needs.ci-plan.outputs.mode == 'full'" not in body:
            planner_errors.append(f"jobs.{job} must require full CI mode")
        if f"needs.ci-plan.outputs.{output} == 'true'" not in body:
            planner_errors.append(
                f"jobs.{job} must use the ci-plan `{output}` path gate"
            )
        if f"needs.ci-plan.outputs.{output}" not in aggregate_body:
            planner_errors.append(
                f"jobs.test must enforce the ci-plan `{output}` path gate"
            )

    for job in sorted(REMOVED_JOBS):
        if re.search(rf"(?m)^  {re.escape(job)}:$", ci_yml):
            planner_errors.append(f"consolidated jobs.{job} must not remain in ci.yml")

    for workflow_path, required_check in DEDICATED_REQUIRED_CHECKS.items():
        workflow_yml = Path(workflow_path).read_text(encoding="utf-8")
        if not pull_request_trigger_is_unconditional(workflow_yml):
            planner_errors.append(
                f"{workflow_path} must trigger on every pull request without path filters"
            )

        job = str(required_check["job"])
        body = extract_job_body(workflow_yml, job)
        expected_name = str(required_check["name"])
        if not re.search(rf"(?m)^    name: {re.escape(expected_name)}$", body):
            planner_errors.append(
                f"{workflow_path} jobs.{job} must keep required check name `{expected_name}`"
            )
        if not re.search(r"(?m)^    if: always\(\)$", body):
            planner_errors.append(f"{workflow_path} jobs.{job} must run with if: always()")
        if not re.search(r"(?m)^    runs-on: ubuntu-latest$", body):
            planner_errors.append(
                f"{workflow_path} jobs.{job} must use the dedicated required-check runner"
            )

        expected_needs = set(required_check["needs"])
        actual_needs = extract_job_needs(body)
        if actual_needs != expected_needs:
            planner_errors.append(
                f"{workflow_path} jobs.{job}.needs must be {sorted(expected_needs)}"
            )

        for contract in sorted(required_check["contract"]):
            if contract not in body:
                planner_errors.append(
                    f"{workflow_path} jobs.{job} is missing fail-closed contract `{contract}`"
                )

    ci_plan_body = extract_job_body(ci_yml, "ci-plan")
    if 'git diff --name-only --no-renames "${base_ref}...HEAD"' not in ci_plan_body:
        planner_errors.append(
            "jobs.ci-plan must disable rename detection when collecting changed files"
        )
    for output in sorted(set(PATH_GATED_JOBS.values())):
        if not re.search(rf"(?m)^      {re.escape(output)}:", ci_plan_body):
            planner_errors.append(f"jobs.ci-plan must publish `{output}`")
    if "cargo fmt --all -- --check" not in ci_plan_body:
        planner_errors.append("jobs.ci-plan must run the Rust formatting gate")
    if "integration-coverage.diff" not in ci_plan_body:
        planner_errors.append(
            "jobs.ci-plan must run the integration shard-coverage gate"
        )

    node_waypoint_yml = Path(
        ".github/workflows/node-waypoint-ebpf-live.yml"
    ).read_text(encoding="utf-8")
    required_full_ci_docs = LIVE_SUITE_DOCUMENTATION_PATHS | extract_documentation_paths(
        node_waypoint_yml
    )
    configured_live_doc_patterns = {
        pattern
        for patterns in SUITE_PATTERNS.values()
        for pattern in patterns
        if "docs/" in pattern
    }
    declared_live_doc_patterns = set(
        exact_path_patterns(LIVE_SUITE_DOCUMENTATION_PATHS)
    )
    if configured_live_doc_patterns != declared_live_doc_patterns:
        planner_errors.append(
            "live-suite documentation patterns must use the shared exact-path sets"
        )
    for path in sorted(required_full_ci_docs - FULL_CI_DOCUMENTATION_PATHS):
        planner_errors.append(
            f"PR planner must keep live-suite documentation `{path}` on full CI"
        )

    if not missing and not extra and not planner_errors:
        print(
            f"Required CI aggregate covers {len(REQUIRED_JOBS)} jobs; "
            f"{len(DIRECT_FULL_CI_JOBS)} roots and "
            f"{len(required_full_ci_docs)} live-suite docs enforce the CI plan."
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
