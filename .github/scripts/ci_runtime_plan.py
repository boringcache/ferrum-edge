#!/usr/bin/env python3
"""Fail-closed path planner for expensive production-image and FIPS CI gates.

Hosted workflows extract this file from the trusted base commit before
execution so a pull request cannot widen skip patterns. Uncertainty, a missing
trusted copy, or an unknown suite must run the gate rather than skip it.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

SUITE_PATTERNS: dict[str, tuple[str, ...]] = {
    # Production Dockerfile smoke builds the ordinary `runtime` image and the
    # distroless `runtime-ebpf` image from the root Dockerfile. Skip only when
    # the diff cannot change that image, its build context, or this planner.
    "production-dockerfile-smoke": (
        r"^Dockerfile$",
        r"^\.dockerignore$",
        r"^Cargo\.(toml|lock)$",
        r"^rust-toolchain\.toml$",
        r"^\.cargo/",
        r"^vendor/",
        r"^build\.rs$",
        r"^proto/",
        r"^src/",
        r"^custom_plugins/",
        r"^ebpf/",
        r"^\.github/scripts/stage_iproute2_runtime\.sh$",
        r"^\.github/workflows/node-waypoint-ebpf-live\.yml$",
        r"^\.github/scripts/ci_runtime_plan\.py$",
        r"^\.github/scripts/ci_runtime_telemetry\.py$",
        r"^\.github/scripts/verify_ci_runtime_cache\.py$",
    ),
    # FIPS compile/clippy/test rebuilds the aws-lc-fips-sys module and the
    # unit/integration binaries that carry the handshake and key-admission
    # assertions. Feature-policy stays cheap and always runs.
    "fips-build": (
        r"^Cargo\.(toml|lock)$",
        r"^rust-toolchain\.toml$",
        r"^\.cargo/",
        r"^vendor/",
        r"^build\.rs$",
        r"^proto/",
        r"^src/",
        r"^custom_plugins/",
        r"^ebpf/",
        r"^tests/unit/",
        r"^tests/integration/",
        r"^docs/fips\.md$",
        r"^\.github/workflows/fips-build\.yml$",
        r"^\.github/scripts/check_fips_feature_policy\.py$",
        r"^\.github/scripts/ci_runtime_plan\.py$",
        r"^\.github/scripts/ci_runtime_telemetry\.py$",
        r"^\.github/scripts/verify_ci_runtime_cache\.py$",
        r"^\.github/actions/setup-sccache/",
        r"^\.github/actions/setup-fast-linker/",
        r"^\.github/actions/setup-rust-ci/",
    ),
}

COMPILED = {
    suite: tuple(re.compile(pattern) for pattern in patterns)
    for suite, patterns in SUITE_PATTERNS.items()
}


def read_changed_files(path: Path) -> list[str]:
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def matched_files(suite: str, changed_files: list[str]) -> list[str]:
    if suite not in COMPILED:
        raise ValueError(f"unknown CI runtime suite: {suite}")
    patterns = COMPILED[suite]
    return [
        path for path in changed_files if any(pattern.search(path) for pattern in patterns)
    ]


def write_summary(
    suite: str, relevant: bool, changed: list[str], matched: list[str], reason: str
) -> None:
    title = suite.replace("-", " ").title()
    print(f"## {title} Runtime Path Plan")
    print()
    print(f"Relevant: **{str(relevant).lower()}**")
    print()
    print(reason)
    print()
    print("### Matched Files")
    print()
    if matched:
        for path in matched:
            print(f"- `{path}`")
    else:
        print("(none)")
    print()
    print("### Changed Files")
    print()
    if changed:
        for path in changed:
            print(f"- `{path}`")
    else:
        print("(none)")


def self_test() -> int:
    cases: list[tuple[str, list[str], bool]] = [
        ("production-dockerfile-smoke", ["Dockerfile"], True),
        ("production-dockerfile-smoke", [".dockerignore"], True),
        ("production-dockerfile-smoke", ["src/main.rs"], True),
        ("production-dockerfile-smoke", ["Cargo.lock"], True),
        ("production-dockerfile-smoke", ["vendor/foo/src/lib.rs"], True),
        ("production-dockerfile-smoke", ["ebpf/src/lib.rs"], True),
        ("production-dockerfile-smoke", ["custom_plugins/mod.rs"], True),
        ("production-dockerfile-smoke", ["proto/ferrum.proto"], True),
        ("production-dockerfile-smoke", ["build.rs"], True),
        (
            "production-dockerfile-smoke",
            [".github/scripts/stage_iproute2_runtime.sh"],
            True,
        ),
        (
            "production-dockerfile-smoke",
            [".github/workflows/node-waypoint-ebpf-live.yml"],
            True,
        ),
        (
            "production-dockerfile-smoke",
            [".github/scripts/ci_runtime_plan.py"],
            True,
        ),
        (
            "production-dockerfile-smoke",
            ["tests/k8s/node_waypoint_ebpf_live/run.sh"],
            False,
        ),
        ("production-dockerfile-smoke", ["docs/ci_cd.md"], False),
        ("production-dockerfile-smoke", ["docs/mesh.md"], False),
        ("production-dockerfile-smoke", ["charts/ferrum-mesh/values.yaml"], False),
        ("production-dockerfile-smoke", ["README.md"], False),
        ("production-dockerfile-smoke", ["Dockerfile.release"], False),
        ("production-dockerfile-smoke", ["Dockerfile.iproute2-layer"], False),
        ("fips-build", ["src/tls/mod.rs"], True),
        ("fips-build", ["tests/unit/tls/fips_policy_tests.rs"], True),
        ("fips-build", ["tests/integration/cp_grpc_handshake_admission_tests.rs"], True),
        ("fips-build", ["Cargo.toml"], True),
        ("fips-build", ["docs/fips.md"], True),
        ("fips-build", [".github/workflows/fips-build.yml"], True),
        ("fips-build", [".github/scripts/check_fips_feature_policy.py"], True),
        ("fips-build", [".github/actions/setup-sccache/action.yml"], True),
        ("fips-build", ["docs/ci_cd.md"], False),
        ("fips-build", ["README.md"], False),
        ("fips-build", ["tests/functional/functional_admin_test.rs"], False),
        ("fips-build", ["tests/k8s/mesh_e2e_sidecar/run.sh"], False),
        ("fips-build", ["charts/ferrum-mesh/values.yaml"], False),
        ("production-dockerfile-smoke", [], False),
        ("fips-build", [], False),
    ]
    failures: list[str] = []
    for suite, changed, expected in cases:
        relevant = bool(matched_files(suite, changed))
        if relevant != expected:
            failures.append(
                f"{suite} {changed!r}: expected relevant={expected}, got {relevant}"
            )
    try:
        matched_files("not-a-suite", ["src/main.rs"])
        failures.append("unknown suite must raise rather than skip")
    except ValueError:
        pass
    for failure in failures:
        print(f"::error::{failure}", file=sys.stderr)
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=sorted(SUITE_PATTERNS))
    parser.add_argument("--changed-files", type=Path)
    parser.add_argument("--force-run", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        return self_test()
    if not args.suite or not args.changed_files:
        parser.error(
            "--suite and --changed-files are required unless --self-test is used"
        )

    changed = read_changed_files(args.changed_files)
    try:
        matched = matched_files(args.suite, changed)
    except ValueError as error:
        print(f"::error::{error}", file=sys.stderr)
        return 1
    relevant = args.force_run or bool(matched)
    if args.force_run:
        reason = "Forced run (push, merge_group, dispatch, or cold-cache proof)."
    elif matched:
        reason = "Diff matches a production-image or FIPS-sensitive path; running the live gate."
    else:
        reason = (
            "No sensitive paths matched. The cheap feature-policy / reporting "
            "jobs still run; the expensive compile/image jobs are skipped."
        )
    print(f"relevant={str(relevant).lower()}")
    print(f"matched_count={len(matched)}")
    write_summary(args.suite, relevant, changed, matched, reason)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
