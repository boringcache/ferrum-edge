#!/usr/bin/env python3
"""Static contract checks for production-image and FIPS CI runtime caching (#3888).

Does not compile Rust or build images. Proves workflow permission/caching
boundaries, pinned actions, fail-closed planning, preserved live contracts,
and telemetry redaction.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from ci_runtime_plan import self_test as plan_self_test
from ci_runtime_telemetry import self_test as telemetry_self_test


REPO_ROOT = Path(__file__).resolve().parents[2]
FIPS_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "fips-build.yml"
NODE_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "node-waypoint-ebpf-live.yml"
DOCKERFILE = REPO_ROOT / "Dockerfile"
SETUP_RUST = REPO_ROOT / ".github" / "actions" / "setup-rust-ci" / "action.yml"
SETUP_SCCACHE = REPO_ROOT / ".github" / "actions" / "setup-sccache" / "action.yml"
CI_CD_DOC = REPO_ROOT / "docs" / "ci_cd.md"
FIPS_DOC = REPO_ROOT / "docs" / "fips.md"
COVERAGE_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "coverage.yml"

CHECKOUT = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
RUST_TOOLCHAIN = "dtolnay/rust-toolchain@29eef336d9b2848a0b548edc03f92a220660cdb8"
RUST_CACHE = "Swatinem/rust-cache@6323deb102c322ba6fcbdcafc7e3dddab59af2b6"
BUILDX = "docker/setup-buildx-action@bb05f3f5519dd87d3ba754cc423b652a5edd6d2c"
BUILD_PUSH = "docker/build-push-action@53b7df96c91f9c12dcc8a07bcb9ccacbed38856a"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
USES = re.compile(
    r"^\s*(?:-\s*)?uses:\s*(?P<ref>\S+)",
    re.MULTILINE,
)
PINNED_REMOTE = re.compile(
    r"^(?P<name>(?!\./)[^@\s]+)@(?P<pin>[0-9a-f]{40})$"
)


def require(condition: bool, message: str, failures: list[str]) -> None:
    if not condition:
        failures.append(message)


def extract_job(workflow: str, job: str) -> str:
    match = re.search(
        rf"(?ms)^  {re.escape(job)}:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
        workflow,
    )
    if match is None:
        return ""
    return match.group("body")


def remote_uses(text: str) -> list[str]:
    refs: list[str] = []
    for match in USES.finditer(text):
        ref = match.group("ref")
        if ref.startswith("./") or ref.startswith("${{"):
            continue
        refs.append(ref.split("#", 1)[0].strip())
    return refs


def pin_errors(text: str, source: str) -> list[str]:
    failures: list[str] = []
    for ref in remote_uses(text):
        parsed = PINNED_REMOTE.fullmatch(ref)
        if parsed is None:
            failures.append(f"{source} has an unpinned or mutable uses ref: {ref}")
        elif not SHA40.fullmatch(parsed.group("pin")):
            failures.append(f"{source} pin is not a 40-char SHA: {ref}")
    return failures


def builder_arg_features_is_after_apt(dockerfile: str) -> bool:
    marker = "FROM rust:latest AS builder\n"
    start = dockerfile.find(marker)
    if start < 0:
        return False
    rest = dockerfile[start + len(marker) :]
    next_from = rest.find("\nFROM ")
    body = rest if next_from < 0 else rest[:next_from]
    apt = body.find("apt-get update")
    features = body.find("ARG FEATURES")
    return apt >= 0 and features > apt


def check_common_trust(text: str, source: str, failures: list[str]) -> None:
    require(
        re.search(r"(?m)^permissions:\n  contents: read\s*$", text) is not None,
        f"{source} must keep workflow contents: read",
        failures,
    )
    require(
        "ACTIONS_RUNTIME_TOKEN" not in text
        or "GITHUB_ENV" not in text.split("ACTIONS_RUNTIME_TOKEN", 1)[-1][:400],
        f"{source} must not export ACTIONS_RUNTIME_TOKEN into GITHUB_ENV",
        failures,
    )
    require(
        "SCCACHE_GHA_ENABLED=true" not in text,
        f"{source} must not enable the sccache GHA backend",
        failures,
    )
    failures.extend(pin_errors(text, source))


def check_fips(workflow: str, failures: list[str]) -> None:
    require(
        'name: FIPS Build Policy' in workflow.splitlines()[0]
        or workflow.startswith("name: FIPS Build Policy"),
        "fips-build.yml must keep workflow name FIPS Build Policy",
        failures,
    )
    require(
        re.search(r"(?m)^    name: FIPS Feature Policy$", workflow) is not None,
        "FIPS Feature Policy job name must be preserved",
        failures,
    )
    require(
        re.search(r"(?m)^    name: FIPS Build & Test$", workflow) is not None,
        "FIPS Build & Test required-check name must be preserved",
        failures,
    )
    require(
        "shared-key: ci-fips" in workflow or 'shared-key: "ci-fips"' in workflow,
        "FIPS compile consumers must share rust-cache key ci-fips",
        failures,
    )
    require(
        "cache-on-failure: \"true\"" in workflow or "cache-on-failure: 'true'" in workflow
        or "cache-on-failure: true" in workflow,
        "FIPS rust-cache must save on failure so runner-loss retries reuse compile work",
        failures,
    )
    require(
        "./.github/actions/setup-sccache" in workflow,
        "FIPS jobs must install sccache through the local action",
        failures,
    )
    require(
        "FERRUM_CUSTOM_PLUGINS" not in workflow,
        "FIPS jobs must not opt example plugins into the cryptographic artifact",
        failures,
    )
    require(
        "cargo build --locked --no-default-features --features fips --bin ferrum-edge"
        in workflow,
        "FIPS compile must still build the locked fips binary",
        failures,
    )
    require(
        "--list-claimed-profiles" in workflow,
        "FIPS claimed-profile enumeration must stay driven by the policy checker",
        failures,
    )
    require(
        "cargo clippy --locked --no-default-features --features fips" in workflow,
        "FIPS clippy must still lint the fips profile",
        failures,
    )
    require("-D warnings" in workflow, "FIPS clippy must keep -D warnings", failures)
    require(
        "tls::fips_policy_tests" in workflow,
        "FIPS policy tests must remain in the live gate",
        failures,
    )
    require(
        "tls::fips_key_admission_tests" in workflow,
        "FIPS key-admission tests must remain in the live gate",
        failures,
    )
    require(
        "frontend_and_backend_builders_complete_a_real_tls_handshake" in workflow,
        "FIPS frontend/backend handshake coverage must remain",
        failures,
    )
    require(
        "legitimate_data_plane_connects_once_a_permit_is_released" in workflow,
        "FIPS CP/DP handshake coverage must remain",
        failures,
    )
    require(
        "python3 -I" in workflow and "ci_runtime_plan.py" in workflow,
        "FIPS planner must execute an isolated trusted-base copy",
        failures,
    )
    require(
        "relevant=true" in workflow and "trusted base has not adopted" in workflow,
        "FIPS planner must fail closed toward running when the trusted copy is missing",
        failures,
    )
    require(
        "force_cold_cache" in workflow,
        "FIPS workflow must expose a cold-cache dispatch input",
        failures,
    )
    compile_job = extract_job(workflow, "fips-compile")
    clippy_job = extract_job(workflow, "fips-clippy")
    test_job = extract_job(workflow, "fips-test")
    aggregate = extract_job(workflow, "fips-build")
    require(bool(compile_job), "fips-compile job is missing", failures)
    require(bool(clippy_job), "fips-clippy job is missing", failures)
    require(bool(test_job), "fips-test job is missing", failures)
    require(
        "needs.fips-plan.outputs.relevant == 'true'" in compile_job,
        "fips-compile must be bound to the trusted planner",
        failures,
    )
    require(
        "needs: fips-compile" in clippy_job or "needs:\n      - fips-compile" in clippy_job,
        "fips-clippy must wait for the compile cache to be saved",
        failures,
    )
    require(
        "needs: fips-compile" in test_job or "needs:\n      - fips-compile" in test_job,
        "fips-test must wait for the compile cache to be saved",
        failures,
    )
    require(
        re.search(r"(?m)^    if: always\(\)$", aggregate) is not None,
        "FIPS Build & Test aggregate must run with if: always()",
        failures,
    )
    require(
        RUST_CACHE in workflow,
        "FIPS workflow must pin Swatinem/rust-cache",
        failures,
    )
    require(
        RUST_TOOLCHAIN in workflow,
        "FIPS workflow must pin dtolnay/rust-toolchain",
        failures,
    )


def check_production_smoke(workflow: str, failures: list[str]) -> None:
    require(
        re.search(r"(?m)^    name: Production Dockerfile eBPF image smoke$", workflow)
        is not None,
        "Production Dockerfile eBPF image smoke check name must be preserved",
        failures,
    )
    default_job = extract_job(workflow, "production-dockerfile-smoke-default")
    ebpf_job = extract_job(workflow, "production-dockerfile-smoke-ebpf")
    aggregate = extract_job(workflow, "production-dockerfile-smoke")
    require(bool(default_job), "default production-image job is missing", failures)
    require(bool(ebpf_job), "eBPF production-image job is missing", failures)
    require(
        BUILDX in default_job and BUILD_PUSH in default_job,
        "default production-image job must use pinned buildx and build-push-action",
        failures,
    )
    require(
        BUILDX in ebpf_job and BUILD_PUSH in ebpf_job,
        "eBPF production-image job must use pinned buildx and build-push-action",
        failures,
    )
    require(
        "target: runtime" in default_job or "target: runtime\n" in default_job,
        "default production-image job must build the ordinary runtime target",
        failures,
    )
    require(
        "target: runtime-ebpf" in ebpf_job,
        "eBPF production-image job must build runtime-ebpf",
        failures,
    )
    require(
        "FEATURES=cloud-secrets,ebpf" in ebpf_job,
        "eBPF production-image job must keep FEATURES=cloud-secrets,ebpf",
        failures,
    )
    require(
        "github.event.pull_request.head.repo.fork" in default_job
        and "github.event.pull_request.head.repo.fork" in ebpf_job,
        "production-image jobs must omit cache-to on fork pull requests",
        failures,
    )
    require(
        "cache-from:" in default_job and "type=gha,scope=production-dockerfile-smoke" in default_job,
        "default production-image job must restore a scoped BuildKit GHA cache",
        failures,
    )
    require(
        "type=gha,scope=production-dockerfile-smoke" in ebpf_job,
        "eBPF production-image job must restore a scoped BuildKit GHA cache",
        failures,
    )
    require(
        "run: |\n          docker build" not in default_job
        and "run: |\n          docker build" not in ebpf_job,
        "production-image jobs must not fall back to sequential plain docker build",
        failures,
    )
    require(
        "usr/sbin/ip" in default_job and "ordinary runtime unexpectedly contains" in default_job,
        "ordinary image must still prove it does not ship eBPF-only ip",
        failures,
    )
    require(
        "grep -Fxq usr/sbin/ip" in ebpf_job,
        "eBPF image must still prove it ships ip",
        failures,
    )
    for forbidden in (
        "bin/sh",
        "usr/bin/bash",
        "usr/bin/apt-get",
        "usr/sbin/iptables",
    ):
        require(
            forbidden in default_job and forbidden in ebpf_job,
            f"both production images must still forbid /{forbidden}",
            failures,
        )
    require(
        re.search(r"(?m)^    if: always\(\)$", aggregate) is not None,
        "production-image aggregate must run with if: always()",
        failures,
    )
    require(
        "python3 -I" in workflow and "ci_runtime_plan.py" in workflow,
        "production-image planner must execute an isolated trusted-base copy",
        failures,
    )
    require(
        "force_cold_cache" in workflow,
        "node-waypoint workflow must expose a cold-cache dispatch input",
        failures,
    )


def check_shared_actions(failures: list[str]) -> None:
    rust_ci = SETUP_RUST.read_text(encoding="utf-8")
    sccache = SETUP_SCCACHE.read_text(encoding="utf-8")
    require(
        "cache-on-failure:" in rust_ci and "true" in rust_ci,
        "setup-rust-ci must save rust-cache on failure for runner-loss retries",
        failures,
    )
    require(
        "cache-hit:" in rust_ci,
        "setup-rust-ci must expose rust-cache hit/miss as an action output",
        failures,
    )
    require(
        "ACTIONS_RUNTIME_TOKEN" in sccache and "GITHUB_ENV" in sccache,
        "setup-sccache must keep documenting why the GHA cache token stays out of GITHUB_ENV",
        failures,
    )
    require(
        "unset SCCACHE_GHA_ENABLED" in sccache,
        "setup-sccache must keep the GHA backend disabled",
        failures,
    )
    require(
        RUST_CACHE in rust_ci,
        "setup-rust-ci must keep the pinned rust-cache action",
        failures,
    )


def check_docs_and_coverage(failures: list[str]) -> None:
    ci_cd = CI_CD_DOC.read_text(encoding="utf-8")
    fips_doc = FIPS_DOC.read_text(encoding="utf-8")
    coverage = COVERAGE_WORKFLOW.read_text(encoding="utf-8")
    require(
        "`fips-build.yml`" in ci_cd or "fips-build.yml" in ci_cd,
        "docs/ci_cd.md must inventory fips-build.yml",
        failures,
    )
    require(
        "30 minutes" in ci_cd and "45 minutes" in ci_cd,
        "docs/ci_cd.md must document the warm PR runtime targets",
        failures,
    )
    require(
        "force_cold_cache" in ci_cd,
        "docs/ci_cd.md must document the hosted cold-cache proof path",
        failures,
    )
    require(
        "cache-on-failure" in ci_cd or "runner-loss" in ci_cd or "retry amplification" in ci_cd,
        "docs/ci_cd.md must document retry amplification / runner-loss cache reuse",
        failures,
    )
    require(
        "trusted" in fips_doc.lower() and "cache" in fips_doc.lower(),
        "docs/fips.md must describe the FIPS CI cache trust boundary",
        failures,
    )
    require(
        "--lib" in coverage and "--test unit_tests" in coverage,
        "coverage lib-unit shard must still collect lib and unit_tests coverage",
        failures,
    )
    lib_unit = coverage
    require(
        re.search(
            r"cargo llvm-cov --no-report\s+\\\s*\n\s*--lib\s+\\\s*\n\s*--test unit_tests",
            lib_unit,
        )
        is not None,
        "coverage lib-unit must compile lib and unit_tests in one llvm-cov invocation",
        failures,
    )


def check_dockerfile(failures: list[str]) -> None:
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    require(
        builder_arg_features_is_after_apt(dockerfile),
        "Dockerfile builder ARG FEATURES must come after apt-get so ordinary and "
        "eBPF production builds share the compiler toolchain layer",
        failures,
    )
    require(
        "FROM runtime-common AS runtime" in dockerfile,
        "ordinary runtime must remain the default final target",
        failures,
    )
    require(
        "FROM runtime-common AS runtime-ebpf" in dockerfile,
        "runtime-ebpf target must remain",
        failures,
    )


def self_test() -> int:
    failures: list[str] = []
    require(
        builder_arg_features_is_after_apt(
            "FROM rust:latest AS builder\n"
            "RUN apt-get update && apt-get install -y pkg-config\n"
            "ARG FEATURES\n"
            "RUN cargo build --features \"${FEATURES}\"\n"
        ),
        "self-test: ARG FEATURES after apt should pass",
        failures,
    )
    require(
        not builder_arg_features_is_after_apt(
            "FROM rust:latest AS builder\n"
            "ARG FEATURES\n"
            "RUN apt-get update && apt-get install -y pkg-config\n"
        ),
        "self-test: ARG FEATURES before apt should fail",
        failures,
    )
    sample = (
        "name: demo\n"
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  x:\n"
        "    steps:\n"
        f"      - uses: {CHECKOUT} # v6\n"
    )
    require(not pin_errors(sample, "self-test"), "self-test: pinned checkout should pass", failures)
    require(
        bool(pin_errors("uses: actions/checkout@v6\n", "self-test")),
        "self-test: floating tag should fail",
        failures,
    )
    for failure in failures:
        print(f"::error::{failure}", file=sys.stderr)
    return 1 if failures else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    failures: list[str] = []
    if self_test() != 0:
        failures.append("verify_ci_runtime_cache internal self-test failed")
    if plan_self_test() != 0:
        failures.append("ci_runtime_plan.py self-test failed")
    if telemetry_self_test() != 0:
        failures.append("ci_runtime_telemetry.py self-test failed")
    if args.self_test:
        for failure in failures:
            print(f"::error::{failure}", file=sys.stderr)
        return 1 if failures else 0

    fips = FIPS_WORKFLOW.read_text(encoding="utf-8")
    node = NODE_WORKFLOW.read_text(encoding="utf-8")
    check_common_trust(fips, "fips-build.yml", failures)
    check_common_trust(node, "node-waypoint-ebpf-live.yml", failures)
    check_fips(fips, failures)
    check_production_smoke(node, failures)
    check_shared_actions(failures)
    check_docs_and_coverage(failures)
    check_dockerfile(failures)
    for failure in failures:
        print(f"::error::{failure}", file=sys.stderr)
    if failures:
        return 1
    print(
        "CI runtime cache contracts hold for production-image and FIPS gates "
        "(permissions, pins, planner, live assertions, telemetry)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
