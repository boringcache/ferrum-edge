#!/usr/bin/env python3
"""Select full or lightweight CI for a pull request's changed files."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from live_suite_path_filter import matched_files, self_test as live_suite_self_test


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

# Pull-request-only job gates. Keep these allow-lists narrow: a path must be
# known to affect the expensive suite before the planner schedules it. An
# unavailable/empty diff fails closed in select_job_gates() and schedules all
# gated jobs.
HELM_PATTERNS = [
    re.compile(pattern)
    for pattern in (
        r"^charts/",
        r"^\.github/workflows/ci\.yml$",
        r"^\.github/actions/",
        r"^\.cargo/",
        r"^vendor/",
        r"^Dockerfile(?:\..*)?$",
        r"^\.dockerignore$",
        r"^Cargo\.(?:toml|lock)$",
        r"^rust-toolchain\.toml$",
        r"^build\.rs$",
        r"^proto/",
        r"^ferrum\.conf$",
        r"^src/lib\.rs$",
        r"^src/overload\.rs$",
        r"^src/runtime_metrics\.rs$",
        r"^src/(?:main|startup|cli)\.rs$",
        r"^src/config/",
        r"^src/config_sources/k8s/",
        r"^src/logging/",
        r"^src/modes/(?:control_plane|database|migrate|mod|tls_reload|grpc_tls_reload|db_tls_reload)\.rs$",
        r"^src/modes/mesh/",
        r"^src/admin/",
        r"^src/dns/",
        r"^src/grpc/",
        r"^src/identity/",
        r"^src/k8s_controller/",
        r"^src/proxy/client_ip\.rs$",
        r"^src/secrets/",
        r"^src/tls/",
        r"^src/util/sharding\.rs$",
        r"^src/xds/",
    )
]

EBPF_LIVE_PATTERNS = [
    re.compile(pattern)
    for pattern in (
        r"^\.github/workflows/(?:ci|node-waypoint-ebpf-live)\.yml$",
        r"^\.github/actions/(?:setup-rust-ci|setup-sccache|setup-fast-linker|setup-kubernetes-tools|package-ferrum-runtime-image)/",
        r"^Cargo\.(?:toml|lock)$",
        r"^\.cargo/",
        r"^rust-toolchain\.toml$",
        r"^build\.rs$",
        r"^proto/",
        r"^ebpf/",
        r"^src/capture/",
        r"^src/ebpf/",
        r"^src/grpc/",
        r"^src/identity/",
        r"^src/k8s_controller/",
        r"^src/modes/control_plane\.rs$",
        r"^src/modes/mesh/",
        r"^src/modes/(?:node_agent|node_agent_cni_server)\.rs$",
        r"^src/plugins/mesh/",
        r"^src/plugins/prometheus_metrics\.rs$",
        r"^src/proxy/(?:backend_dispatch|grpc_proxy|hbone_pool|hbone_proxy|mesh_mtls_pool|mesh_tcp_egress|mesh_tcp_inbound|mesh_udp_capture|mesh_udp_frame|mod|netns_capture|netns_udp_capture|tcp_proxy|udp_batch)\.rs$",
        r"^src/(?:router_cache|socket_opts)\.rs$",
        r"^src/service_discovery/",
        r"^src/tls/",
        r"^tests/functional/functional_mesh_mode_test\.rs$",
        r"^tests/functional/fixtures/",
        r"^tests/k8s/lib/",
        r"^tests/k8s/node_waypoint_ebpf_live/",
        r"^tests/.*(?:capture|ebpf|netns|node_waypoint).*",
    )
]

JOB_GATE_NAMES = (
    "run_helm",
    "run_mesh_federation",
    "run_mesh_sidecar_smoke",
    "run_ebpf_live",
    "run_ebpf_build",
)

# Scripts whose logic controls the gate decisions themselves. Changing either
# force-runs every gated suite (see select_job_gates).
GATE_CONTROLLER_PATHS = frozenset(
    {
        ".github/scripts/pr_ci_plan.py",
        ".github/scripts/live_suite_path_filter.py",
        ".github/scripts/verify_action_pinning.py",
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


def any_path_matches(patterns: list[re.Pattern[str]], changed_files: list[str]) -> bool:
    return any(pattern.search(path) for path in changed_files for pattern in patterns)


def select_job_gates(event_name: str, changed_files: list[str]) -> dict[str, bool]:
    if event_name != "pull_request" or not changed_files:
        return {name: True for name in JOB_GATE_NAMES}

    # These scripts decide which gated suites run. A PR that edits them is
    # evaluated by the TRUSTED base-branch copy (which cannot see its own
    # replacement's behavior), so force every gated suite on: a broken gate
    # change must prove the suites it controls still run before it can start
    # suppressing them on subsequent PRs.
    if any(path in GATE_CONTROLLER_PATHS for path in changed_files):
        return {name: True for name in JOB_GATE_NAMES}

    return {
        "run_helm": any_path_matches(HELM_PATTERNS, changed_files),
        "run_mesh_federation": bool(
            matched_files("mesh-federation", changed_files)
        ),
        "run_mesh_sidecar_smoke": bool(
            matched_files("mesh-e2e-sidecar", changed_files)
        ),
        "run_ebpf_live": any_path_matches(EBPF_LIVE_PATTERNS, changed_files),
        "run_ebpf_build": any(path.startswith("ebpf/") for path in changed_files),
    }


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

    gate_cases = [
        (
            "pull_request",
            ["charts/ferrum-gateway/values.yaml"],
            {"run_helm": True},
        ),
        (
            "pull_request",
            ["tests/k8s/multicluster-federation/run.sh"],
            {"run_mesh_federation": True},
        ),
        (
            "pull_request",
            ["src/backend_conn_limit.rs"],
            {"run_mesh_sidecar_smoke": True},
        ),
        (
            "pull_request",
            ["src/socket_opts.rs"],
            {"run_ebpf_live": True},
        ),
        (
            "pull_request",
            ["ebpf/ferrum-ebpf/src/main.rs"],
            {"run_ebpf_build": True, "run_ebpf_live": True},
        ),
        (
            "pull_request",
            ["docs/admin_api.md"],
            {name: False for name in JOB_GATE_NAMES},
        ),
        (
            "pull_request",
            [".github/scripts/pr_ci_plan.py"],
            {name: True for name in JOB_GATE_NAMES},
        ),
        (
            "pull_request",
            [".github/scripts/live_suite_path_filter.py"],
            {name: True for name in JOB_GATE_NAMES},
        ),
        (
            "pull_request",
            [".github/scripts/verify_action_pinning.py"],
            {name: True for name in JOB_GATE_NAMES},
        ),
        (
            "pull_request",
            [".github/actions/setup-kubernetes-tools/action.yml"],
            {"run_ebpf_live": True, "run_helm": True},
        ),
        (
            "pull_request",
            [],
            {name: True for name in JOB_GATE_NAMES},
        ),
        ("push", ["docs/admin_api.md"], {name: True for name in JOB_GATE_NAMES}),
        ("workflow_dispatch", [], {name: True for name in JOB_GATE_NAMES}),
    ]
    for event_name, changed, expected in gate_cases:
        selected = select_job_gates(event_name, changed)
        for gate, expected_value in expected.items():
            if selected[gate] != expected_value:
                failures.append(
                    f"{event_name} {changed!r}: expected {gate}={expected_value}, "
                    f"selected {selected[gate]}"
                )

    if live_suite_self_test() != 0:
        failures.append("live-suite path-filter self-test failed")
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
    for name, enabled in select_job_gates(args.event_name, changed_files).items():
        print(f"{name}={str(enabled).lower()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
