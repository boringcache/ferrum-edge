#!/usr/bin/env python3
"""Static contract checks for production-image and FIPS CI runtime caching (#3888).

Does not compile Rust or build images. Proves workflow permission/caching
boundaries, pinned actions, fail-closed NUL-delimited planning, preserved live
contracts, telemetry redaction, evidence-backed cache restore bytes, schema-
and architecture-scoped BuildKit keys, exact-hit restore-only vs partial/miss
publish, fail-closed cache-save preparation, fork restore-only / no-save
steps, rust-cache save-if so fork PRs cannot save, FIPS producer/consumer key
equality with unique attempt scoping and stable fallback isolation, rejection
of ignored rust-cache `key` wiring, checksum-pinned sccache install without
credential-exporting installers, and hosted cache-token absence assertions.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from ci_runtime_plan import (
    SUITE_PATTERNS,
    decide_relevance,
    self_test as plan_self_test,
)
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
CACHE_RESTORE = "actions/cache/restore@374a27f26986edd8c430f386d152a856e179c0ae"
CACHE_SAVE = "actions/cache/save@374a27f26986edd8c430f386d152a856e179c0ae"
FIPS_CONTRACT_HASHFILES = (
    "hashFiles('Cargo.toml', 'Cargo.lock', '.cargo/config.toml', 'build.rs', "
    "'.github/workflows/fips-build.yml', "
    "'.github/scripts/check_fips_feature_policy.py', "
    "'src/fips/**', 'vendor/**')"
)
FIPS_SHARED_KEY = "ci-fips-contract-${{ " + FIPS_CONTRACT_HASHFILES + " }}"
FIPS_PRODUCER_KEY_EXPR = (
    "fips-producer-${{ github.sha }}-${{ github.run_id }}-"
    "${{ github.run_attempt }}"
)
FIPS_PRODUCER_RESTORE_PREFIX_EXPR = (
    "fips-producer-${{ github.sha }}-${{ github.run_id }}-"
)
FIPS_PRODUCER_PATHS = (
    "${{ github.workspace }}/target",
    "${{ github.workspace }}/.cache/sccache",
)
SCCACHE_EXPORTERS = ("mozilla-actions/sccache-action",)
SCCACHE_PINNED_VERSION = "0.17.0"
SCCACHE_RELEASE_DOWNLOAD = "https://github.com/mozilla/sccache/releases/download/"
CREDENTIAL_ASSERT_VARS = (
    "ACTIONS_RUNTIME_TOKEN",
    "ACTIONS_RESULTS_URL",
)
BUILDKIT_CACHE_SCHEMA = "v1"
CACHE_KIND_EXACT = "steps.cache-kind.outputs.kind == 'exact'"
CACHE_KIND_PUBLISH = "steps.cache-kind.outputs.publish == 'true'"
NUL_DIFF = 'git diff --name-only --no-renames -z "${trusted_sha}...HEAD"'
LINE_DIFF = 'git diff --name-only --no-renames "${trusted_sha}...HEAD"'
NODE_WAYPOINT_PLANNER_OUTPUT = (
    "needs.production-dockerfile-plan.outputs.node_waypoint_relevant"
)
NODE_WAYPOINT_LIVE_IF = (
    "always() && "
    "needs.production-dockerfile-plan.outputs.node_waypoint_relevant != 'false'"
)
SHA40 = re.compile(r"^[0-9a-f]{40}$")
USES = re.compile(
    r"^\s*(?:-\s*)?uses:\s*(?P<ref>\S+)",
    re.MULTILINE,
)
PINNED_REMOTE = re.compile(
    r"^(?P<name>(?!\./)[^@\s]+)@(?P<pin>[0-9a-f]{40})$"
)


def extract_pull_request_paths(workflow: str) -> list[str]:
    match = re.search(
        r"(?ms)^  pull_request:\n    paths:\n(?P<paths>(?:      - .+\n)+)",
        workflow,
    )
    if match is None:
        return []
    paths: list[str] = []
    for line in match.group("paths").splitlines():
        stripped = line.strip()
        if stripped.startswith("- "):
            paths.append(stripped[2:].strip().strip('"').strip("'"))
    return paths


def gh_path_filter_matches(filter_pattern: str, file_path: str) -> bool:
    pattern = filter_pattern.strip().lstrip("/")
    path = file_path.strip().lstrip("/")
    if pattern.endswith("/**"):
        prefix = pattern[:-3]
        return path == prefix or path.startswith(prefix + "/")
    if pattern.endswith("**"):
        prefix = pattern[:-2]
        return path == prefix or path.startswith(prefix)
    if "**" in pattern or "*" in pattern:
        escaped = re.escape(pattern).replace(r"\*\*", ".*").replace(r"\*", "[^/]*")
        return re.fullmatch(escaped, path) is not None
    return path == pattern


def production_dockerfile_probe_paths() -> list[str]:
    probes: list[str] = []
    for pattern in SUITE_PATTERNS["production-dockerfile-smoke"]:
        if pattern == r"^Dockerfile$":
            probes.append("Dockerfile")
        elif pattern == r"^\.dockerignore$":
            probes.append(".dockerignore")
        elif pattern == r"^Cargo\.(toml|lock)$":
            probes.extend(["Cargo.toml", "Cargo.lock"])
        elif pattern == r"^rust-toolchain\.toml$":
            probes.append("rust-toolchain.toml")
        elif pattern == r"^\.cargo/":
            probes.append(".cargo/config.toml")
        elif pattern == r"^vendor/":
            probes.append("vendor/foo/lib.rs")
        elif pattern == r"^build\.rs$":
            probes.append("build.rs")
        elif pattern == r"^proto/":
            probes.append("proto/ferrum.proto")
        elif pattern == r"^src/":
            probes.append("src/main.rs")
        elif pattern == r"^custom_plugins/":
            probes.append("custom_plugins/foo.rs")
        elif pattern == r"^ebpf/":
            probes.append("ebpf/src/lib.rs")
        elif pattern == r"^\.github/scripts/stage_iproute2_runtime\.sh$":
            probes.append(".github/scripts/stage_iproute2_runtime.sh")
        elif pattern == r"^\.github/workflows/node-waypoint-ebpf-live\.yml$":
            probes.append(".github/workflows/node-waypoint-ebpf-live.yml")
        elif pattern == r"^\.github/scripts/ci_runtime_plan\.py$":
            probes.append(".github/scripts/ci_runtime_plan.py")
        elif pattern == r"^\.github/scripts/ci_runtime_telemetry\.py$":
            probes.append(".github/scripts/ci_runtime_telemetry.py")
        elif pattern == r"^\.github/scripts/verify_ci_runtime_cache\.py$":
            probes.append(".github/scripts/verify_ci_runtime_cache.py")
        else:
            probes.append(f"unmapped-production-pattern:{pattern}")
    return probes


def check_production_trigger_superset(
    workflow: str,
    source: str,
    failures: list[str],
) -> None:
    trigger_paths = extract_pull_request_paths(workflow)
    require(
        bool(trigger_paths),
        f"{source} must declare pull_request.paths so production-image changes "
        "can reach the trusted planner",
        failures,
    )
    uncovered: list[str] = []
    for probe in production_dockerfile_probe_paths():
        if probe.startswith("unmapped-production-pattern:"):
            failures.append(
                f"{source} verifier must map every production-dockerfile-smoke "
                f"planner pattern ({probe[26:]})"
            )
            continue
        if not any(
            gh_path_filter_matches(trigger, probe) for trigger in trigger_paths
        ):
            uncovered.append(probe)
    require(
        not uncovered,
        f"{source} pull_request.paths must be a superset of production-dockerfile-smoke "
        f"sensitive inputs; uncovered probes: {', '.join(uncovered)}",
        failures,
    )


def job_if(job_body: str) -> str:
    match = re.search(r"(?m)^    if:\s*(.+)\s*$", job_body)
    if match:
        return match.group(1).strip()
    return ""


def node_waypoint_probe_paths() -> list[str]:
    probes: list[str] = []
    for pattern in SUITE_PATTERNS["node-waypoint-ebpf-live"]:
        if pattern == r"^\.github/workflows/node-waypoint-ebpf-live\.yml$":
            probes.append(".github/workflows/node-waypoint-ebpf-live.yml")
        elif pattern == r"^\.dockerignore$":
            probes.append(".dockerignore")
        elif pattern == r"^\.github/actions/package-ferrum-runtime-image/":
            probes.append(".github/actions/package-ferrum-runtime-image/action.yml")
        elif pattern == r"^\.github/actions/setup-kubernetes-tools/":
            probes.append(".github/actions/setup-kubernetes-tools/action.yml")
        elif pattern == r"^Cargo\.(toml|lock)$":
            probes.extend(["Cargo.toml", "Cargo.lock"])
        elif pattern == r"^Dockerfile$":
            probes.append("Dockerfile")
        elif pattern == r"^Dockerfile\.iproute2-layer$":
            probes.append("Dockerfile.iproute2-layer")
        elif pattern == r"^Dockerfile\.release$":
            probes.append("Dockerfile.release")
        elif pattern == r"^\.github/scripts/stage_iproute2_runtime\.sh$":
            probes.append(".github/scripts/stage_iproute2_runtime.sh")
        elif pattern == r"^build\.rs$":
            probes.append("build.rs")
        elif pattern == r"^proto/":
            probes.append("proto/ferrum.proto")
        elif pattern == r"^ebpf/":
            probes.append("ebpf/src/lib.rs")
        elif pattern == r"^src/capture/":
            probes.append("src/capture/mod.rs")
        elif pattern == r"^src/ebpf/":
            probes.append("src/ebpf/mod.rs")
        elif pattern == r"^src/grpc/":
            probes.append("src/grpc/mod.rs")
        elif pattern == r"^src/identity/":
            probes.append("src/identity/mod.rs")
        elif pattern == r"^src/k8s_controller/":
            probes.append("src/k8s_controller/mod.rs")
        elif pattern == r"^src/modes/control_plane\.rs$":
            probes.append("src/modes/control_plane.rs")
        elif pattern == r"^src/modes/mesh/":
            probes.append("src/modes/mesh/mod.rs")
        elif pattern == r"^src/modes/node_agent\.rs$":
            probes.append("src/modes/node_agent.rs")
        elif pattern == r"^src/plugins/mesh/":
            probes.append("src/plugins/mesh/mod.rs")
        elif pattern == r"^src/plugins/prometheus_metrics\.rs$":
            probes.append("src/plugins/prometheus_metrics.rs")
        elif pattern == r"^src/proxy/hbone_pool\.rs$":
            probes.append("src/proxy/hbone_pool.rs")
        elif pattern == r"^src/proxy/mesh_tcp_egress\.rs$":
            probes.append("src/proxy/mesh_tcp_egress.rs")
        elif pattern == r"^src/proxy/mod\.rs$":
            probes.append("src/proxy/mod.rs")
        elif pattern == r"^src/proxy/hbone_proxy\.rs$":
            probes.append("src/proxy/hbone_proxy.rs")
        elif pattern == r"^src/proxy/netns_capture\.rs$":
            probes.append("src/proxy/netns_capture.rs")
        elif pattern == r"^src/proxy/tcp_proxy\.rs$":
            probes.append("src/proxy/tcp_proxy.rs")
        elif pattern == r"^src/router_cache\.rs$":
            probes.append("src/router_cache.rs")
        elif pattern == r"^src/socket_opts\.rs$":
            probes.append("src/socket_opts.rs")
        elif pattern == r"^charts/ferrum-mesh/":
            probes.append("charts/ferrum-mesh/values.yaml")
        elif pattern == r"^tests/k8s/lib/":
            probes.append("tests/k8s/lib/helpers.sh")
        elif pattern == r"^tests/k8s/node_waypoint_ebpf_live/":
            probes.append("tests/k8s/node_waypoint_ebpf_live/run.sh")
        elif pattern == r"^docs/mesh\.md$":
            probes.append("docs/mesh.md")
        elif pattern == r"^docs/mesh_supported_matrix\.md$":
            probes.append("docs/mesh_supported_matrix.md")
        elif pattern == r"^docs/node_agent\.md$":
            probes.append("docs/node_agent.md")
        elif pattern == r"^docs/ci_cd\.md$":
            probes.append("docs/ci_cd.md")
        elif pattern == r"^docs/plans/node_waypoint_transport_adr\.md$":
            probes.append("docs/plans/node_waypoint_transport_adr.md")
        else:
            probes.append(f"unmapped-node-waypoint-pattern:{pattern}")
    return probes


NODE_WAYPOINT_PRODUCTION_ONLY_PROBES = (
    "src/main.rs",
    "src/admin/mod.rs",
    "src/modes/database.rs",
    "src/plugins/cors.rs",
    "vendor/foo/src/lib.rs",
    ".cargo/config.toml",
    "rust-toolchain.toml",
    "custom_plugins/foo.rs",
)


def check_node_waypoint_live_job(
    workflow: str,
    source: str,
    failures: list[str],
) -> None:
    plan_job = extract_job(workflow, "production-dockerfile-plan")
    live_job = extract_job(workflow, "node-waypoint-ebpf-live")
    require(bool(plan_job), f"{source} production-dockerfile-plan job is missing", failures)
    require(bool(live_job), f"{source} node-waypoint-ebpf-live job is missing", failures)
    require(
        "node_waypoint_relevant: ${{ steps.filter.outputs.node_waypoint_relevant }}"
        in plan_job
        or "node_waypoint_relevant: ${{ steps.filter.outputs.node_waypoint_relevant }}"
        in workflow,
        f"{source} plan job must expose node_waypoint_relevant as a job output",
        failures,
    )
    require(
        "node_waypoint_relevant=true" in plan_job
        and "trusted base has not adopted" in plan_job,
        f"{source} must fail closed toward running NodeWaypoint when the trusted "
        "planner is missing",
        failures,
    )
    require(
        "--suite" in plan_job and "node-waypoint-ebpf-live" in plan_job,
        f"{source} must evaluate the node-waypoint-ebpf-live planner suite from "
        "the trusted-base copy",
        failures,
    )
    require(
        "needs: production-dockerfile-plan" in live_job
        or "needs:\n      - production-dockerfile-plan" in live_job,
        f"{source} live job must depend on the trusted planner job",
        failures,
    )
    live_condition = job_if(live_job)
    require(
        bool(live_condition),
        f"{source} live job must declare a single-line if condition",
        failures,
    )
    require(
        live_condition == NODE_WAYPOINT_LIVE_IF,
        f"{source} live job must skip only on exact {NODE_WAYPOINT_PLANNER_OUTPUT} "
        f"!= 'false' under always(); found: {live_condition}",
        failures,
    )
    require(
        "always()" in live_condition,
        f"{source} live job must use always() so a planner failure cannot skip",
        failures,
    )
    require(
        f"{NODE_WAYPOINT_PLANNER_OUTPUT} != 'false'" in live_condition,
        f"{source} live job skip must be exact-false-only",
        failures,
    )
    require(
        "== 'true'" not in live_condition,
        f"{source} live job must not treat blank/malformed output as a skip",
        failures,
    )
    require(
        "result == 'success'" not in live_condition,
        f"{source} live job must not require planner success to run "
        "(planner failure must fail closed toward running)",
        failures,
    )
    require(
        "outputs.relevant" not in live_condition,
        f"{source} live job must not reuse the production-image relevant output",
        failures,
    )
    require(
        "kind create cluster" in live_job,
        f"{source} live job must still create the Kind cluster",
        failures,
    )
    require(
        "tests/k8s/node_waypoint_ebpf_live/run.sh" in live_job,
        f"{source} live job must still run the NodeWaypoint harness",
        failures,
    )
    require(
        'ferrum_mesh_bpf_drops_total{reason="exclude_port_hit"}' in live_job
        or "ferrum_mesh_bpf_drops_total" in live_job,
        f"{source} live job must still assert a real BPF bypass metric",
        failures,
    )
    require(
        "timeout-minutes: 120" in live_job,
        f"{source} live job must keep the 120-minute Kind/eBPF timeout",
        failures,
    )
    unmapped = [
        probe
        for probe in node_waypoint_probe_paths()
        if probe.startswith("unmapped-node-waypoint-pattern:")
    ]
    require(
        not unmapped,
        f"{source} verifier must map every node-waypoint-ebpf-live planner "
        f"pattern ({', '.join(item[32:] for item in unmapped)})",
        failures,
    )
    for probe in node_waypoint_probe_paths():
        if probe.startswith("unmapped-node-waypoint-pattern:"):
            continue
        relevant, _reason, _matched = decide_relevance("node-waypoint-ebpf-live", [probe])
        require(
            relevant,
            f"{source} prior-scope path {probe} must run the NodeWaypoint live job",
            failures,
        )
    for probe in NODE_WAYPOINT_PRODUCTION_ONLY_PROBES:
        node_relevant, _reason, _matched = decide_relevance(
            "node-waypoint-ebpf-live", [probe]
        )
        prod_relevant, _, _ = decide_relevance("production-dockerfile-smoke", [probe])
        require(
            not node_relevant,
            f"{source} production-only path {probe} must skip the NodeWaypoint live job",
            failures,
        )
        require(
            prod_relevant,
            f"{source} production-only path {probe} must still trigger production-image smoke",
            failures,
        )
    empty_relevant, _, _ = decide_relevance("node-waypoint-ebpf-live", [])
    require(
        empty_relevant,
        f"{source} empty NodeWaypoint diff must fail closed toward running",
        failures,
    )
    unknown_relevant, _, _ = decide_relevance(
        "node-waypoint-ebpf-live", ["brand-new-crate/src/lib.rs"]
    )
    require(
        unknown_relevant,
        f"{source} unknown NodeWaypoint path must fail closed toward running",
        failures,
    )


def check_aggregate_planner_contract(
    aggregate_body: str,
    planner_job: str,
    source: str,
    failures: list[str],
) -> None:
    planner_result = f"needs.{planner_job}.result"
    planner_relevant = f"needs.{planner_job}.outputs.relevant"
    skip_steps = [
        step
        for step in job_steps(aggregate_body)
        if re.search(r"(?m)^      - name: Skip", step)
    ]
    require(
        len(skip_steps) == 1,
        f"{source} aggregate must declare exactly one skip step",
        failures,
    )
    skip_if = step_if(skip_steps[0]) if skip_steps else ""
    require(
        bool(skip_if),
        f"{source} aggregate skip step must declare a single-line if condition",
        failures,
    )
    if skip_if:
        require(
            skip_if == f"{planner_relevant} == 'false'",
            f"{source} aggregate skip must use exact {planner_relevant} == 'false', "
            f"found: {skip_if}",
            failures,
        )
        require(
            "!= 'true'" not in skip_if,
            f"{source} aggregate skip must not use != 'true'",
            failures,
        )
    require(
        f"{planner_result} != 'success'" in aggregate_body,
        f"{source} aggregate must fail when planning fails",
        failures,
    )
    require(
        f"{planner_result} == 'success'" in aggregate_body
        and f"{planner_relevant} != 'true'" in aggregate_body
        and f"{planner_relevant} != 'false'" in aggregate_body,
        f"{source} aggregate must fail closed when planner output is neither "
        "exact true nor exact false",
        failures,
    )
    require(
        f"{planner_relevant} == 'true'" in aggregate_body,
        f"{source} aggregate must gate expensive jobs on exact "
        f"{planner_relevant} == 'true'",
        failures,
    )


def require(condition: bool, message: str, failures: list[str]) -> None:
    if not condition:
        failures.append(message)


FORK_IS_TRUE = "github.event.pull_request.head.repo.fork == true"
FORK_NOT_TRUE = "github.event.pull_request.head.repo.fork != true"
COLD_IS_TRUE = "github.event.inputs.force_cold_cache == 'true'"
COLD_NOT_TRUE = "github.event.inputs.force_cold_cache != 'true'"
SAVE_IF_NON_FORK = re.compile(
    r"(?m)^[ \t]*save-if:\s*(?:['\"]?)(?:\$\{\{\s*)?"
    r"github\.event\.pull_request\.head\.repo\.fork\s*!=\s*true"
    r"(?:\s*\}\})?(?:['\"]?)\s*(?:#.*)?$"
)
SAVE_IF_FALSE = re.compile(
    r"(?m)^[ \t]*save-if:\s*(?:['\"]?)(?:\$\{\{\s*)?false"
    r"(?:\s*\}\})?(?:['\"]?)\s*(?:#.*)?$"
)
RUST_CACHE_BARE_KEY = re.compile(r"(?m)^[ \t]*key:")
RUST_CACHE_ADD_JOB_ID = re.compile(r"(?m)^[ \t]*add-job-id-key:")
TOKEN_ECHO = re.compile(
    r"""echo\s+["']?\$\{?(?:ACTIONS_RUNTIME_TOKEN|ACTIONS_RESULTS_URL|ACTIONS_CACHE_URL)"""
)


def extract_job(workflow: str, job: str) -> str:
    match = re.search(
        rf"(?ms)^  {re.escape(job)}:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
        workflow,
    )
    if match is None:
        return ""
    return match.group("body")


def job_steps(job_body: str) -> list[str]:
    match = re.search(r"(?ms)^    steps:\n(.*)\Z", job_body)
    if match is None:
        return []
    chunks = re.split(r"(?m)^(?=      - )", match.group(1))
    return [chunk for chunk in chunks if chunk.lstrip().startswith("- ")]


def step_if(step: str) -> str:
    match = re.search(r"(?m)^      (?:- )?if:\s*(.+)\s*$", step)
    if match:
        return match.group(1).strip()
    match = re.search(r"(?m)^        if:\s*(.+)\s*$", step)
    if match:
        return match.group(1).strip()
    return ""


def step_uses(step: str) -> str:
    match = re.search(r"(?m)^      (?:- )?uses:\s*(\S+)", step)
    if match is None:
        match = re.search(r"(?m)^        uses:\s*(\S+)", step)
    if match is None:
        return ""
    return match.group(1).split("#", 1)[0].strip()


def step_with(step: str) -> str:
    match = re.search(r"(?m)^        with:\n", step)
    if match is None:
        return ""
    lines: list[str] = []
    for line in step[match.end() :].splitlines(keepends=True):
        if line.strip() == "":
            lines.append(line)
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent >= 10:
            lines.append(line)
            continue
        break
    return "".join(lines)


def with_has_key(with_block: str, key: str) -> bool:
    return re.search(rf"(?m)^[ \t]*{re.escape(key)}:", with_block) is not None


def rust_cache_with_blocks(text: str) -> list[str]:
    blocks: list[str] = []
    for chunk in re.split(r"(?m)^(?=[ ]{2,}- )", text):
        if RUST_CACHE not in chunk or not re.search(r"(?m)^[ ]{2,}- ", chunk):
            continue
        with_match = re.search(
            r"(?ms)^[ \t]+with:\n((?:[ \t]+[^\n]*\n)*)",
            chunk,
        )
        blocks.append(with_match.group(1) if with_match else "")
    return blocks


def check_rust_cache_uses_shared_key_only(
    with_block: str,
    source: str,
    failures: list[str],
    *,
    expected_shared_key: str,
) -> None:
    require(
        expected_shared_key in with_block,
        f"{source} rust-cache shared-key must be {expected_shared_key}",
        failures,
    )
    require(
        RUST_CACHE_BARE_KEY.search(with_block) is None,
        f"{source} must not set rust-cache `key:` (ignored when shared-key is set)",
        failures,
    )
    require(
        RUST_CACHE_ADD_JOB_ID.search(with_block) is None,
        f"{source} must not set rust-cache add-job-id-key (unused with shared-key)",
        failures,
    )
    require(
        "github.sha" not in with_block
        and "github.run_id" not in with_block
        and "github.run_attempt" not in with_block,
        f"{source} stable rust-cache shared-key must not include sha/run_id/"
        "run_attempt (those belong on the producer channel)",
        failures,
    )
    require(
        re.search(
            r"(?m)^[ \t]*add-rust-environment-hash-key:\s*['\"]?false",
            with_block,
        )
        is None,
        f"{source} must preserve automatic rust environment/manifest/lock hashing",
        failures,
    )


def check_credential_absence_assertion(
    text: str,
    source: str,
    failures: list[str],
) -> None:
    require(
        "Assert cache-service credentials are absent" in text,
        f"{source} must declare a hosted cache-credential absence assertion",
        failures,
    )
    for var in CREDENTIAL_ASSERT_VARS:
        require(
            var in text,
            f"{source} credential assertion must check {var}",
            failures,
        )
    require(
        '[ -n "${!var:-}" ]' in text or "[ -n \"${!var:-}\" ]" in text,
        f"{source} must test credential presence via ${{!var:-}} without "
        "printing values",
        failures,
    )
    require(
        TOKEN_ECHO.search(text) is None,
        f"{source} must not print cache-service credential values",
        failures,
    )
    require(
        "refusing to execute later PR-controlled build steps" in text
        or "refusing to execute PR-controlled" in text,
        f"{source} credential assertion must fail closed",
        failures,
    )


def check_no_sccache_credential_exporter(
    text: str,
    source: str,
    failures: list[str],
) -> None:
    for exporter in SCCACHE_EXPORTERS:
        require(
            re.search(
                rf"(?m)^[ \t]*(?:-\s*)?uses:\s*{re.escape(exporter)}@",
                text,
            )
            is None,
            f"{source} must not invoke credential-exporting installer {exporter}",
            failures,
        )
    require(
        "core.exportVariable" not in text,
        f"{source} must not call core.exportVariable (ACTIONS_RUNTIME_TOKEN leak)",
        failures,
    )


def check_fips_producer_channel(
    workflow: str,
    failures: list[str],
) -> None:
    require(
        f"FIPS_PRODUCER_KEY: {FIPS_PRODUCER_KEY_EXPR}" in workflow,
        "FIPS workflow env must define FIPS_PRODUCER_KEY as "
        f"{FIPS_PRODUCER_KEY_EXPR}",
        failures,
    )
    require(
        f"FIPS_PRODUCER_RESTORE_PREFIX: {FIPS_PRODUCER_RESTORE_PREFIX_EXPR}"
        in workflow,
        "FIPS workflow env must define FIPS_PRODUCER_RESTORE_PREFIX as "
        f"{FIPS_PRODUCER_RESTORE_PREFIX_EXPR}",
        failures,
    )
    compile_job = extract_job(workflow, "fips-compile")
    clippy_job = extract_job(workflow, "fips-clippy")
    test_job = extract_job(workflow, "fips-test")
    compile_saves = [
        step for step in job_steps(compile_job) if step_uses(step).startswith(CACHE_SAVE)
    ]
    compile_restores = [
        step
        for step in job_steps(compile_job)
        if step_uses(step).startswith(CACHE_RESTORE)
    ]
    require(
        len(compile_saves) == 1,
        f"fips-compile must have exactly one pinned actions/cache/save producer "
        f"step, found {len(compile_saves)}",
        failures,
    )
    require(
        not compile_restores,
        "fips-compile must publish the producer archive and not restore it",
        failures,
    )
    if compile_saves:
        condition = step_if(compile_saves[0])
        with_block = step_with(compile_saves[0])
        require(
            COLD_NOT_TRUE in condition,
            "fips-compile producer save must skip force_cold_cache",
            failures,
        )
        require(
            FORK_NOT_TRUE in condition and FORK_IS_TRUE not in condition,
            "fips-compile producer save must exclude fork PRs",
            failures,
        )
        require(
            "key: ${{ env.FIPS_PRODUCER_KEY }}" in with_block,
            "fips-compile producer save must use env.FIPS_PRODUCER_KEY",
            failures,
        )
        for path in FIPS_PRODUCER_PATHS:
            require(
                path in with_block,
                f"fips-compile producer save must include {path}",
                failures,
            )
    for job_body, job_name in (
        (clippy_job, "fips-clippy"),
        (test_job, "fips-test"),
    ):
        restores = [
            step
            for step in job_steps(job_body)
            if step_uses(step).startswith(CACHE_RESTORE)
        ]
        saves = [
            step for step in job_steps(job_body) if step_uses(step).startswith(CACHE_SAVE)
        ]
        require(
            not saves,
            f"{job_name} must be a producer-cache consumer and must not save",
            failures,
        )
        require(
            len(restores) == 1,
            f"{job_name} must have exactly one pinned actions/cache/restore "
            f"producer step, found {len(restores)}",
            failures,
        )
        if restores:
            condition = step_if(restores[0])
            with_block = step_with(restores[0])
            require(
                COLD_NOT_TRUE in condition,
                f"{job_name} producer restore must skip force_cold_cache",
                failures,
            )
            require(
                "key: ${{ env.FIPS_PRODUCER_KEY }}" in with_block,
                f"{job_name} producer restore key must equal compile's "
                "env.FIPS_PRODUCER_KEY",
                failures,
            )
            require(
                "restore-keys:" in with_block
                and "${{ env.FIPS_PRODUCER_RESTORE_PREFIX }}" in with_block,
                f"{job_name} producer restore-keys must use the sha+run_id prefix",
                failures,
            )
            require(
                "fail-on-cache-miss:" in with_block
                and "github.event.pull_request.head.repo.fork != true" in with_block,
                f"{job_name} must fail closed on a producer miss for non-fork runs",
                failures,
            )
            for path in FIPS_PRODUCER_PATHS:
                require(
                    path in with_block,
                    f"{job_name} producer restore must include {path}",
                    failures,
                )
        require(
            "Require this-run FIPS producer cache" in job_body,
            f"{job_name} must fail closed when the this-run producer key is missing",
            failures,
        )
        require(
            "FIPS_PRODUCER_RESTORE_PREFIX" in job_body
            and "refusing to claim compile-to-consumer reuse" in job_body,
            f"{job_name} producer requirement must match the sha+run_id prefix",
            failures,
        )
        require(
            "Drop stable target before producer restore" in job_body,
            f"{job_name} must drop rust-cache target/sccache before restoring "
            "the SHA-scoped producer archive",
            failures,
        )
        require(
            "layer=producer" in job_body and "classify-restore" in job_body,
            f"{job_name} must classify producer restore separately from "
            "stable fallback",
            failures,
        )
        rust_blocks = rust_cache_with_blocks(job_body)
        if rust_blocks:
            require(
                SAVE_IF_FALSE.search(rust_blocks[0]) is not None,
                f"{job_name} rust-cache must set save-if false so consumers "
                "cannot publish",
                failures,
            )
            require(
                SAVE_IF_NON_FORK.search(rust_blocks[0]) is None,
                f"{job_name} rust-cache must not use the compile producer save-if",
                failures,
            )


def check_rust_cache_fork_save_if(
    text: str,
    source: str,
    failures: list[str],
    *,
    expected_count: int,
) -> None:
    blocks = rust_cache_with_blocks(text)
    require(
        len(blocks) == expected_count,
        f"{source} must have exactly {expected_count} pinned rust-cache "
        f"site(s), found {len(blocks)}",
        failures,
    )
    for index, block in enumerate(blocks, 1):
        require(
            SAVE_IF_NON_FORK.search(block) is not None,
            f"{source} rust-cache site {index} must set save-if so fork PRs "
            "restore only",
            failures,
        )
        require(
            "cache-on-failure:" in block and "true" in block,
            f"{source} rust-cache site {index} must keep cache-on-failure true",
            failures,
        )


def buildkit_cache_key(scope: str) -> str:
    return (
        f"{scope}-{BUILDKIT_CACHE_SCHEMA}-"
        f"${{{{ runner.os }}}}-${{{{ runner.arch }}}}-${{{{ github.sha }}}}"
    )


def buildkit_cache_prefix(scope: str) -> str:
    return (
        f"{scope}-{BUILDKIT_CACHE_SCHEMA}-"
        f"${{{{ runner.os }}}}-${{{{ runner.arch }}}}-"
    )


def check_buildkit_cache_boundary(
    job_body: str,
    source: str,
    failures: list[str],
) -> None:
    steps = [
        step
        for step in job_steps(job_body)
        if step_uses(step).startswith(BUILD_PUSH)
    ]
    trusted_publish = []
    trusted_exact = []
    fork_restore = []
    cold = []
    for step in steps:
        condition = step_if(step)
        with_block = step_with(step)
        has_from = with_has_key(with_block, "cache-from")
        has_to = with_has_key(with_block, "cache-to")
        if FORK_IS_TRUE in condition and FORK_NOT_TRUE not in condition:
            require(
                COLD_NOT_TRUE in condition,
                f"{source} fork restore-only BuildKit step must not run on "
                "force_cold_cache",
                failures,
            )
            require(
                has_from,
                f"{source} fork restore-only BuildKit step must restore cache-from",
                failures,
            )
            require(
                not has_to,
                f"{source} must omit cache-to on the fork restore-only BuildKit step",
                failures,
            )
            require(
                CACHE_KIND_EXACT not in condition,
                f"{source} fork restore-only BuildKit step must not be exact-hit-only",
                failures,
            )
            fork_restore.append(step)
        elif COLD_IS_TRUE in condition and COLD_NOT_TRUE not in condition:
            require(
                not has_from and not has_to,
                f"{source} force-cold BuildKit step must omit cache-from and cache-to",
                failures,
            )
            cold.append(step)
        elif has_to:
            require(
                FORK_NOT_TRUE in condition and FORK_IS_TRUE not in condition,
                f"{source} must exclude fork PRs from every cache-to BuildKit step",
                failures,
            )
            require(
                COLD_NOT_TRUE in condition,
                f"{source} cache-to BuildKit step must not run on force_cold_cache",
                failures,
            )
            require(
                has_from,
                f"{source} trusted-publish BuildKit step must restore cache-from",
                failures,
            )
            require(
                CACHE_KIND_PUBLISH in condition,
                f"{source} trusted-publish BuildKit step must run only on a "
                "partial match or miss (publish == true)",
                failures,
            )
            require(
                CACHE_KIND_EXACT not in condition,
                f"{source} must never export cache-to on an exact github.sha hit",
                failures,
            )
            trusted_publish.append(step)
        elif has_from and not has_to:
            require(
                FORK_NOT_TRUE in condition and FORK_IS_TRUE not in condition,
                f"{source} trusted exact-hit restore-only BuildKit step must "
                "exclude fork PRs",
                failures,
            )
            require(
                COLD_NOT_TRUE in condition,
                f"{source} trusted exact-hit restore-only BuildKit step must "
                "not run on force_cold_cache",
                failures,
            )
            require(
                CACHE_KIND_EXACT in condition,
                f"{source} trusted exact-hit restore-only BuildKit step must "
                "require an exact github.sha hit",
                failures,
            )
            require(
                CACHE_KIND_PUBLISH not in condition,
                f"{source} trusted exact-hit restore-only BuildKit step must "
                "not be the publishing path",
                failures,
            )
            trusted_exact.append(step)
        else:
            failures.append(
                f"{source} has a pinned build-push step that is not a trusted "
                "exact-hit restore-only, trusted-publish, fork restore-only, "
                "or force-cold path"
            )
    require(
        bool(trusted_exact),
        f"{source} must provide a trusted exact-hit restore-only BuildKit step "
        "(cache-from, no cache-to, exact github.sha hit)",
        failures,
    )
    require(
        bool(trusted_publish),
        f"{source} must provide a trusted-publish BuildKit step "
        "(cache-from + cache-to, excluding fork PRs and exact hits)",
        failures,
    )
    require(
        bool(fork_restore),
        f"{source} must provide a fork restore-only BuildKit step "
        "(cache-from, no cache-to, fork PRs only)",
        failures,
    )
    require(
        bool(cold),
        f"{source} must provide a force-cold BuildKit step with neither cache-from "
        "nor cache-to",
        failures,
    )
    require(
        "type=gha" not in job_body,
        f"{source} must not use the BuildKit GHA cache backend",
        failures,
    )


def check_nul_delimited_plan(plan_job: str, source: str, failures: list[str]) -> None:
    require(
        NUL_DIFF in plan_job,
        f"{source} must generate a NUL-delimited trusted diff",
        failures,
    )
    require(
        LINE_DIFF not in plan_job,
        f"{source} must not use line-delimited git diff --name-only",
        failures,
    )
    require(
        "| sort" not in plan_job,
        f"{source} must not pass pathname bytes through sort",
        failures,
    )


def check_local_cache_actions(
    job_body: str,
    source: str,
    failures: list[str],
    *,
    scope: str,
) -> None:
    restore_steps = [
        step for step in job_steps(job_body) if step_uses(step).startswith(CACHE_RESTORE)
    ]
    save_steps = [
        step for step in job_steps(job_body) if step_uses(step).startswith(CACHE_SAVE)
    ]
    require(
        len(restore_steps) == 1,
        f"{source} must have exactly one pinned actions/cache/restore step, "
        f"found {len(restore_steps)}",
        failures,
    )
    require(
        len(save_steps) == 1,
        f"{source} must have exactly one pinned actions/cache/save step, "
        f"found {len(save_steps)}",
        failures,
    )
    key = buildkit_cache_key(scope)
    prefix = buildkit_cache_prefix(scope)
    if restore_steps:
        condition = step_if(restore_steps[0])
        with_block = step_with(restore_steps[0])
        require(
            COLD_NOT_TRUE in condition,
            f"{source} cache restore must skip force_cold_cache",
            failures,
        )
        require(
            FORK_IS_TRUE not in condition or FORK_NOT_TRUE in condition,
            f"{source} cache restore may run for forks but must not be fork-only "
            "in a way that skips trusted restores",
            failures,
        )
        require(
            f"key: {key}" in with_block,
            f"{source} cache restore must use exact key {key}",
            failures,
        )
        require(
            "restore-keys:" in with_block and prefix in with_block,
            f"{source} cache restore must use restore prefix {prefix}",
            failures,
        )
        require(
            "${{ runner.arch }}" in with_block,
            f"{source} cache restore must be architecture-scoped",
            failures,
        )
        require(
            BUILDKIT_CACHE_SCHEMA in with_block,
            f"{source} cache restore must include schema {BUILDKIT_CACHE_SCHEMA}",
            failures,
        )
    if save_steps:
        condition = step_if(save_steps[0])
        with_block = step_with(save_steps[0])
        require(
            COLD_NOT_TRUE in condition,
            f"{source} cache save must skip force_cold_cache",
            failures,
        )
        require(
            FORK_NOT_TRUE in condition and FORK_IS_TRUE not in condition,
            f"{source} must exclude fork PRs from cache save / publication",
            failures,
        )
        require(
            CACHE_KIND_PUBLISH in condition,
            f"{source} cache save must run only after a partial match or miss",
            failures,
        )
        require(
            CACHE_KIND_EXACT not in condition,
            f"{source} must never save an immutable cache on an exact github.sha hit",
            failures,
        )
        require(
            f"key: {key}" in with_block,
            f"{source} cache save must use exact key {key}",
            failures,
        )


def check_cache_save_preparation(
    job_body: str,
    source: str,
    failures: list[str],
    *,
    scope: str,
) -> None:
    prepare_steps = [
        step
        for step in job_steps(job_body)
        if "Prepare BuildKit cache for save" in step
    ]
    require(
        len(prepare_steps) == 1,
        f"{source} must have exactly one Prepare BuildKit cache for save step, "
        f"found {len(prepare_steps)}",
        failures,
    )
    if not prepare_steps:
        return
    step = prepare_steps[0]
    condition = step_if(step)
    require(
        COLD_NOT_TRUE in condition,
        f"{source} cache-save preparation must skip force_cold_cache",
        failures,
    )
    require(
        FORK_NOT_TRUE in condition and FORK_IS_TRUE not in condition,
        f"{source} cache-save preparation must exclude fork PRs",
        failures,
    )
    require(
        CACHE_KIND_PUBLISH in condition,
        f"{source} cache-save preparation must run only after a partial match or miss",
        failures,
    )
    require(
        CACHE_KIND_EXACT not in condition,
        f"{source} cache-save preparation must not run on an exact github.sha hit",
        failures,
    )
    out_dir = f"{scope}-out"
    require(
        out_dir in step,
        f"{source} cache-save preparation must require the fresh {out_dir} directory",
        failures,
    )
    require(
        'if [ ! -d "$out" ]' in step or "if [ ! -d \"$out\" ]" in step,
        f"{source} cache-save preparation must fail when the fresh export is absent",
        failures,
    )
    require(
        "refusing to save" in step and "stale" in step,
        f"{source} cache-save preparation must refuse to relabel a stale restore",
        failures,
    )
    require(
        "present=true" not in step,
        f"{source} cache-save preparation must not mark a stale destination as present",
        failures,
    )


def check_cache_telemetry_evidence(job_body: str, source: str, failures: list[str]) -> None:
    require(
        '--hit ""' not in job_body and "--hit ''" not in job_body,
        f"{source} must not pass empty --hit (unknown is not a miss)",
        failures,
    )
    require(
        "--hit true" not in job_body,
        f"{source} must not fabricate a cache hit literal",
        failures,
    )
    require(
        "cache-hit" in job_body and "cache-matched-key" in job_body,
        f"{source} must record restore evidence from action outputs",
        failures,
    )
    require(
        "classify-restore" in job_body,
        f"{source} must classify actions/cache/restore v4 outputs via classify-restore",
        failures,
    )
    require(
        "id: cache-kind" in job_body,
        f"{source} must expose cache-kind outputs for exact vs publish gating",
        failures,
    )
    require(
        "--path" in job_body,
        f"{source} must measure restored bytes from the restored directory",
        failures,
    )
    require(
        "--phase cache-restore" in job_body
        and "--phase image-build" in job_body
        and "--phase cache-save" in job_body,
        f"{source} must time cache-restore, image-build, and cache-save separately",
        failures,
    )


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
        f"shared-key: {FIPS_SHARED_KEY}" in workflow,
        "FIPS jobs must share rust-cache shared-key ci-fips-contract-${{ hashFiles(...) }}",
        failures,
    )
    require(
        "shared-key: ci-fips\n" not in workflow
        and 'shared-key: "ci-fips"' not in workflow
        and "shared-key: ci-fips\r" not in workflow,
        "FIPS rust-cache must not use the old ignored shared-key: ci-fips + key: shape",
        failures,
    )
    fips_contract_inputs = (
        "'Cargo.toml'",
        "'Cargo.lock'",
        "'.cargo/config.toml'",
        "'build.rs'",
        "'.github/workflows/fips-build.yml'",
        "'.github/scripts/check_fips_feature_policy.py'",
        "'src/fips/**'",
        "'vendor/**'",
    )
    for job_body, job_name in (
        (extract_job(workflow, "fips-compile"), "fips-compile"),
        (extract_job(workflow, "fips-clippy"), "fips-clippy"),
        (extract_job(workflow, "fips-test"), "fips-test"),
    ):
        blocks = rust_cache_with_blocks(job_body)
        require(
            len(blocks) == 1,
            f"{job_name} must expose one auditable rust-cache contract key",
            failures,
        )
        if len(blocks) == 1:
            block = blocks[0]
            check_rust_cache_uses_shared_key_only(
                block,
                job_name,
                failures,
                expected_shared_key=FIPS_SHARED_KEY,
            )
            for contract_input in fips_contract_inputs:
                require(
                    contract_input in block,
                    f"{job_name} FIPS cache contract key must include {contract_input}",
                    failures,
                )
    require(
        "cache-on-failure: \"true\"" in workflow or "cache-on-failure: 'true'" in workflow
        or "cache-on-failure: true" in workflow,
        "FIPS rust-cache must save after ordinary failures when post-job cleanup still runs",
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
        re.search(r"(?m)--test unit_tests tls::fips_\s*$", workflow) is not None,
        "FIPS unit tests must use one tls::fips_ TESTNAME prefix",
        failures,
    )
    require(
        re.search(
            r"cargo test[^\n]*tls::fips_policy_tests[^\n]+tls::fips_key_admission_tests",
            workflow,
        )
        is None,
        "FIPS unit tests must not pass two Cargo TESTNAME filters to one invocation",
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
        re.search(
            r"cargo test[^\n]*frontend_and_backend_builders_complete_a_real_tls_handshake"
            r"[^\n]+legitimate_data_plane_connects_once_a_permit_is_released",
            workflow,
        )
        is None,
        "FIPS handshake tests must not pass two Cargo TESTNAME filters to one invocation",
        failures,
    )
    require(
        "python3 -I" in workflow and "ci_runtime_plan.py" in workflow,
        "FIPS planner must execute an isolated trusted-base copy",
        failures,
    )
    plan_job = extract_job(workflow, "fips-plan")
    check_nul_delimited_plan(plan_job, "FIPS planner", failures)
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
    check_aggregate_planner_contract(
        aggregate,
        "fips-plan",
        "FIPS Build & Test",
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
    check_rust_cache_fork_save_if(
        compile_job,
        "fips-compile",
        failures,
        expected_count=1,
    )
    check_fips_producer_channel(workflow, failures)
    check_no_sccache_credential_exporter(workflow, "fips-build.yml", failures)
    for job_body, job_name in (
        (compile_job, "fips-compile"),
        (clippy_job, "fips-clippy"),
        (test_job, "fips-test"),
    ):
        check_credential_absence_assertion(job_body, job_name, failures)
        cargo_idx = job_body.find("cargo ")
        assert_idx = job_body.find("Assert cache-service credentials are absent")
        require(
            assert_idx != -1 and cargo_idx != -1 and assert_idx < cargo_idx,
            f"{job_name} must assert cache credentials are absent before cargo",
            failures,
        )
        require(
            "sccache-directory-subset" in job_body
            and "not exposed" in job_body
            and "layer=stable-fallback" in job_body,
            f"{job_name} must label rust-cache as stable-fallback and state that "
            "archive bytes are not exposed",
            failures,
        )
        require(
            "--name rust-cache" in job_body,
            f"{job_name} may still record rust-cache hit/miss from the action output",
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
    check_buildkit_cache_boundary(
        default_job,
        "production-dockerfile-smoke-default",
        failures,
    )
    check_buildkit_cache_boundary(
        ebpf_job,
        "production-dockerfile-smoke-ebpf",
        failures,
    )
    require(
        "trusted-publish" in default_job
        and "fork-restore-only" in default_job
        and "trusted-publish" in ebpf_job
        and "fork-restore-only" in ebpf_job,
        "production-image telemetry must name the trusted-publish and "
        "fork-restore-only cache-to policies",
        failures,
    )
    require(
        "type=local" in default_job
        and buildkit_cache_key("production-dockerfile-smoke-default") in default_job,
        "default production-image job must restore a schema- and architecture-scoped "
        "local BuildKit cache",
        failures,
    )
    require(
        "type=local" in ebpf_job
        and buildkit_cache_key("production-dockerfile-smoke-ebpf") in ebpf_job,
        "eBPF production-image job must restore a schema- and architecture-scoped "
        "local BuildKit cache",
        failures,
    )
    check_local_cache_actions(
        default_job,
        "production-dockerfile-smoke-default",
        failures,
        scope="production-dockerfile-smoke-default",
    )
    check_local_cache_actions(
        ebpf_job,
        "production-dockerfile-smoke-ebpf",
        failures,
        scope="production-dockerfile-smoke-ebpf",
    )
    check_cache_save_preparation(
        default_job,
        "production-dockerfile-smoke-default",
        failures,
        scope="production-dockerfile-smoke-default",
    )
    check_cache_save_preparation(
        ebpf_job,
        "production-dockerfile-smoke-ebpf",
        failures,
        scope="production-dockerfile-smoke-ebpf",
    )
    check_cache_telemetry_evidence(
        default_job,
        "production-dockerfile-smoke-default",
        failures,
    )
    check_cache_telemetry_evidence(
        ebpf_job,
        "production-dockerfile-smoke-ebpf",
        failures,
    )
    plan_job = extract_job(workflow, "production-dockerfile-plan")
    check_nul_delimited_plan(plan_job, "production-image planner", failures)
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
    check_aggregate_planner_contract(
        aggregate,
        "production-dockerfile-plan",
        "Production Dockerfile eBPF image smoke",
        failures,
    )
    check_production_trigger_superset(
        workflow,
        "node-waypoint-ebpf-live.yml",
        failures,
    )
    check_node_waypoint_live_job(
        workflow,
        "node-waypoint-ebpf-live.yml",
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
        "setup-rust-ci must save rust-cache after ordinary failures when post-job cleanup still runs",
        failures,
    )
    require(
        "cache-hit:" in rust_ci,
        "setup-rust-ci must expose rust-cache hit/miss as an action output",
        failures,
    )
    check_no_sccache_credential_exporter(sccache, "setup-sccache", failures)
    check_credential_absence_assertion(sccache, "setup-sccache", failures)
    require(
        SCCACHE_RELEASE_DOWNLOAD in sccache,
        "setup-sccache must download a pinned mozilla/sccache GitHub release",
        failures,
    )
    require(
        f'default: "{SCCACHE_PINNED_VERSION}"' in sccache
        or f"default: '{SCCACHE_PINNED_VERSION}'" in sccache,
        f"setup-sccache must pin sccache {SCCACHE_PINNED_VERSION}",
        failures,
    )
    for digest_input in (
        "linux-amd64-sha256",
        "linux-arm64-sha256",
        "macos-amd64-sha256",
        "macos-arm64-sha256",
        "windows-amd64-sha256",
    ):
        require(
            f"{digest_input}:" in sccache,
            f"setup-sccache must pin {digest_input}",
            failures,
        )
        require(
            re.search(
                rf"{re.escape(digest_input)}:[\s\S]{{0,200}}default: \"[0-9a-f]{{64}}\"",
                sccache,
            )
            is not None,
            f"setup-sccache {digest_input} must default to a 64-char SHA-256",
            failures,
        )
    require(
        "Linux-X64" in sccache
        and "macOS-ARM64" in sccache
        and "macOS-X64" in sccache
        and "Windows-X64" in sccache,
        "setup-sccache must cover Linux/macOS/Windows architectures used by callers",
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
        "SCCACHE_CACHE_SIZE=2G" in sccache or "SCCACHE_CACHE_SIZE=2G" in sccache,
        "setup-sccache must keep the 2 GiB local cache cap",
        failures,
    )
    require(
        "SCCACHE_IDLE_TIMEOUT=0" in sccache,
        "setup-sccache must keep the idle timeout disabled",
        failures,
    )
    require(
        "lazily after cache restore" in sccache
        or "AFTER the cache restore" in sccache
        or "after cache restore" in sccache,
        "setup-sccache must still start the server lazily after cache restore",
        failures,
    )
    require(
        "continue-on-error: true" in sccache,
        "setup-sccache install must remain a graceful fallback",
        failures,
    )
    require(
        "CARGO_BUILD_RUSTC_WRAPPER=" in sccache,
        "setup-sccache must clear the rustc wrapper when sccache is unavailable",
        failures,
    )
    require(
        RUST_CACHE in rust_ci,
        "setup-rust-ci must keep the pinned rust-cache action",
        failures,
    )
    check_rust_cache_fork_save_if(
        rust_ci,
        "setup-rust-ci",
        failures,
        expected_count=1,
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
        "save-if" in ci_cd and "fork" in ci_cd.lower(),
        "docs/ci_cd.md must document rust-cache save-if for fork pull requests",
        failures,
    )
    require(
        "fips-producer" in ci_cd
        and "github.sha" in ci_cd
        and "run_id" in ci_cd
        and "run_attempt" in ci_cd,
        "docs/ci_cd.md must document the SHA/run_id/run_attempt FIPS producer key",
        failures,
    )
    require(
        "shared-key" in ci_cd and "ignored" in ci_cd.lower(),
        "docs/ci_cd.md must document that pinned rust-cache ignores key when shared-key is set",
        failures,
    )
    require(
        "save-if: false" in ci_cd or "save-if: false" in ci_cd.replace("`", ""),
        "docs/ci_cd.md must document that FIPS clippy/test rust-cache does not save",
        failures,
    )
    require(
        "mozilla-actions/sccache-action" in ci_cd
        and "ACTIONS_RUNTIME_TOKEN" in ci_cd,
        "docs/ci_cd.md must name the rejected sccache installer and token boundary",
        failures,
    )
    require(
        "actions/cache/restore" in ci_cd
        and "actions/cache/save" in ci_cd
        and "restore-only" in ci_cd,
        "docs/ci_cd.md must document pinned cache restore/save and fork restore-only",
        failures,
    )
    require(
        "runner.arch" in ci_cd and BUILDKIT_CACHE_SCHEMA in ci_cd,
        "docs/ci_cd.md must document schema- and architecture-scoped BuildKit cache keys",
        failures,
    )
    require(
        "exact" in ci_cd.lower() and "partial" in ci_cd.lower(),
        "docs/ci_cd.md must document exact-hit restore-only vs partial/miss publish",
        failures,
    )
    require(
        "sccache-directory" in ci_cd or "sccache directory subset" in ci_cd.lower(),
        "docs/ci_cd.md must document that FIPS telemetry measures the sccache subset",
        failures,
    )
    require(
        "type=local" in ci_cd and "restored bytes" in ci_cd.lower(),
        "docs/ci_cd.md must document local BuildKit cache restore-byte measurement",
        failures,
    )
    require(
        "--name-only --no-renames -z" in ci_cd or "NUL-delimited" in ci_cd,
        "docs/ci_cd.md must document NUL-delimited trusted path planning",
        failures,
    )
    require(
        "pull_request.paths" in ci_cd or "trigger superset" in ci_cd.lower(),
        "docs/ci_cd.md must document production-image trigger superset over planner inputs",
        failures,
    )
    require(
        "relevant == 'false'" in ci_cd or "exact false" in ci_cd.lower(),
        "docs/ci_cd.md must document exact-boolean aggregate planner gating",
        failures,
    )
    require(
        "node_waypoint_relevant" in ci_cd and "always()" in ci_cd,
        "docs/ci_cd.md must document the NodeWaypoint job-level always() exact-false skip",
        failures,
    )
    require(
        "prior" in ci_cd.lower()
        and ("nodewaypoint" in ci_cd.lower() or "node-waypoint" in ci_cd.lower()),
        "docs/ci_cd.md must document NodeWaypoint prior-scope scheduling vs "
        "the production-image trigger superset",
        failures,
    )
    require(
        "trusted" in fips_doc.lower() and "cache" in fips_doc.lower(),
        "docs/fips.md must describe the FIPS CI cache trust boundary",
        failures,
    )
    require(
        "save-if" in fips_doc,
        "docs/fips.md must document rust-cache save-if so fork PRs cannot save",
        failures,
    )
    require(
        "fips-producer" in fips_doc
        and "github.sha" in fips_doc
        and "run_attempt" in fips_doc,
        "docs/fips.md must document the exact producer cache key",
        failures,
    )
    require(
        "mozilla-actions/sccache-action" in fips_doc,
        "docs/fips.md must name the rejected sccache installer",
        failures,
    )
    require(
        "shared-key" in fips_doc and "ignored" in fips_doc.lower(),
        "docs/fips.md must document pinned rust-cache shared-key vs ignored key",
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

    build_push = (
        f"        uses: {BUILD_PUSH} # v7\n"
        "        with:\n"
        "          cache-from: type=local,src=/tmp/production-dockerfile-smoke-default\n"
    )
    good_buildkit = (
        "    steps:\n"
        "      - name: Build ordinary production runtime (trusted exact-hit restore-only)\n"
        f"        if: {COLD_NOT_TRUE} && {FORK_NOT_TRUE} && {CACHE_KIND_EXACT}\n"
        f"{build_push}"
        "      - name: Build ordinary production runtime\n"
        f"        if: {COLD_NOT_TRUE} && {FORK_NOT_TRUE} && {CACHE_KIND_PUBLISH}\n"
        f"{build_push}"
        "          cache-to: type=local,dest=/tmp/production-dockerfile-smoke-default-out,mode=max\n"
        "      - name: Build ordinary production runtime (fork restore-only)\n"
        f"        if: {COLD_NOT_TRUE} && {FORK_IS_TRUE}\n"
        f"{build_push}"
        "      - name: Build ordinary production runtime (cold cache)\n"
        f"        if: {COLD_IS_TRUE}\n"
        f"        uses: {BUILD_PUSH} # v7\n"
        "        with:\n"
        "          provenance: false\n"
    )
    good_buildkit_failures: list[str] = []
    check_buildkit_cache_boundary(
        good_buildkit,
        "self-test-good-buildkit",
        good_buildkit_failures,
    )
    require(
        not good_buildkit_failures,
        "self-test: structurally split BuildKit cache paths should pass: "
        + "; ".join(good_buildkit_failures),
        failures,
    )

    substring_false_positive = (
        "    steps:\n"
        "      - name: Record BuildKit cache restore policy\n"
        "        env:\n"
        "          FORK_PR: ${{ github.event.pull_request.head.repo.fork }}\n"
        "        run: echo telemetry-only\n"
        "      - name: Build ordinary production runtime\n"
        f"        if: {COLD_NOT_TRUE}\n"
        f"{build_push}"
        "          cache-to: type=gha,mode=max,scope=production-dockerfile-smoke-default\n"
        "      - name: Build ordinary production runtime (cold cache)\n"
        f"        if: {COLD_IS_TRUE}\n"
        f"        uses: {BUILD_PUSH} # v7\n"
        "        with:\n"
        "          provenance: false\n"
    )
    require(
        "github.event.pull_request.head.repo.fork" in substring_false_positive,
        "self-test fixture must include the fork substring the old check trusted",
        failures,
    )
    substring_failures: list[str] = []
    check_buildkit_cache_boundary(
        substring_false_positive,
        "self-test-unconditional-cache-to",
        substring_failures,
    )
    require(
        any("exclude fork PRs from every cache-to" in item for item in substring_failures)
        and any("fork restore-only BuildKit step" in item for item in substring_failures),
        "self-test: fork substring plus unconditional cache-to must fail structurally",
        failures,
    )

    fork_cache_to = (
        "    steps:\n"
        "      - name: Build ordinary production runtime (trusted exact-hit restore-only)\n"
        f"        if: {COLD_NOT_TRUE} && {FORK_NOT_TRUE} && {CACHE_KIND_EXACT}\n"
        f"{build_push}"
        "      - name: Build ordinary production runtime\n"
        f"        if: {COLD_NOT_TRUE} && {FORK_NOT_TRUE} && {CACHE_KIND_PUBLISH}\n"
        f"{build_push}"
        "          cache-to: type=local,dest=/tmp/production-dockerfile-smoke-default-out,mode=max\n"
        "      - name: Build ordinary production runtime (fork restore-only)\n"
        f"        if: {COLD_NOT_TRUE} && {FORK_IS_TRUE}\n"
        f"{build_push}"
        "          cache-to: type=local,dest=/tmp/production-dockerfile-smoke-default-out,mode=max\n"
        "      - name: Build ordinary production runtime (cold cache)\n"
        f"        if: {COLD_IS_TRUE}\n"
        f"        uses: {BUILD_PUSH} # v7\n"
        "        with:\n"
        "          provenance: false\n"
    )
    fork_cache_to_failures: list[str] = []
    check_buildkit_cache_boundary(
        fork_cache_to,
        "self-test-fork-cache-to",
        fork_cache_to_failures,
    )
    require(
        any(
            "omit cache-to on the fork restore-only BuildKit step" in item
            for item in fork_cache_to_failures
        ),
        "self-test: reintroducing cache-to on a fork path must fail",
        failures,
    )

    exact_hit_export = (
        "    steps:\n"
        "      - name: Build ordinary production runtime (trusted exact-hit restore-only)\n"
        f"        if: {COLD_NOT_TRUE} && {FORK_NOT_TRUE} && {CACHE_KIND_EXACT}\n"
        f"{build_push}"
        "          cache-to: type=local,dest=/tmp/production-dockerfile-smoke-default-out,mode=max\n"
        "      - name: Build ordinary production runtime\n"
        f"        if: {COLD_NOT_TRUE} && {FORK_NOT_TRUE} && {CACHE_KIND_PUBLISH}\n"
        f"{build_push}"
        "          cache-to: type=local,dest=/tmp/production-dockerfile-smoke-default-out,mode=max\n"
        "      - name: Build ordinary production runtime (fork restore-only)\n"
        f"        if: {COLD_NOT_TRUE} && {FORK_IS_TRUE}\n"
        f"{build_push}"
        "      - name: Build ordinary production runtime (cold cache)\n"
        f"        if: {COLD_IS_TRUE}\n"
        f"        uses: {BUILD_PUSH} # v7\n"
        "        with:\n"
        "          provenance: false\n"
    )
    exact_hit_export_failures: list[str] = []
    check_buildkit_cache_boundary(
        exact_hit_export,
        "self-test-exact-hit-export",
        exact_hit_export_failures,
    )
    require(
        any(
            "never export cache-to on an exact github.sha hit" in item
            for item in exact_hit_export_failures
        ),
        "self-test: exact-hit cache-to/export must fail",
        failures,
    )

    rust_step = (
        "      - name: Cache FIPS Rust\n"
        f"        uses: {RUST_CACHE} # v2\n"
        "        with:\n"
        "          shared-key: ci-fips\n"
        "          cache-on-failure: \"true\"\n"
    )
    good_rust = rust_step + (
        "          save-if: ${{ github.event.pull_request.head.repo.fork != true }}\n"
    )
    good_rust_failures: list[str] = []
    check_rust_cache_fork_save_if(
        good_rust,
        "self-test-good-rust-cache",
        good_rust_failures,
        expected_count=1,
    )
    require(
        not good_rust_failures,
        "self-test: rust-cache save-if for non-fork should pass: "
        + "; ".join(good_rust_failures),
        failures,
    )

    missing_save_if_failures: list[str] = []
    check_rust_cache_fork_save_if(
        rust_step,
        "self-test-missing-save-if",
        missing_save_if_failures,
        expected_count=1,
    )
    require(
        any("save-if so fork PRs restore only" in item for item in missing_save_if_failures),
        "self-test: removing rust-cache save-if must fail",
        failures,
    )

    inverted_save_if = rust_step + (
        "          save-if: ${{ github.event.pull_request.head.repo.fork == true }}\n"
    )
    inverted_failures: list[str] = []
    check_rust_cache_fork_save_if(
        inverted_save_if,
        "self-test-inverted-save-if",
        inverted_failures,
        expected_count=1,
    )
    require(
        any("save-if so fork PRs restore only" in item for item in inverted_failures),
        "self-test: inverted rust-cache save-if must fail",
        failures,
    )

    ignored_key_block = (
        "          shared-key: ci-fips\n"
        "          key: fips-contract-${{ hashFiles('Cargo.toml') }}\n"
        "          add-job-id-key: \"false\"\n"
    )
    ignored_key_failures: list[str] = []
    check_rust_cache_uses_shared_key_only(
        ignored_key_block,
        "self-test-ignored-key",
        ignored_key_failures,
        expected_shared_key=FIPS_SHARED_KEY,
    )
    require(
        any("must not set rust-cache `key:`" in item for item in ignored_key_failures)
        and any("add-job-id-key" in item for item in ignored_key_failures)
        and any("shared-key must be" in item for item in ignored_key_failures),
        "self-test: shared-key plus ignored key/add-job-id-key must fail",
        failures,
    )

    sha_in_stable = (
        f"          shared-key: {FIPS_SHARED_KEY}-${{{{ github.sha }}}}\n"
    )
    sha_stable_failures: list[str] = []
    check_rust_cache_uses_shared_key_only(
        sha_in_stable,
        "self-test-sha-in-stable",
        sha_stable_failures,
        expected_shared_key=FIPS_SHARED_KEY,
    )
    require(
        any("must not include sha/run_id" in item for item in sha_stable_failures),
        "self-test: SHA on the stable rust-cache key must fail",
        failures,
    )

    good_shared = f"          shared-key: {FIPS_SHARED_KEY}\n"
    good_shared_failures: list[str] = []
    check_rust_cache_uses_shared_key_only(
        good_shared,
        "self-test-good-shared-key",
        good_shared_failures,
        expected_shared_key=FIPS_SHARED_KEY,
    )
    require(
        not good_shared_failures,
        "self-test: contract shared-key without ignored key should pass: "
        + "; ".join(good_shared_failures),
        failures,
    )

    exporter_failures: list[str] = []
    check_no_sccache_credential_exporter(
        "uses: mozilla-actions/sccache-action@1583d6b38d7be47f593cb472781bbb21cab4321e\n",
        "self-test-sccache-exporter",
        exporter_failures,
    )
    require(
        any("must not invoke credential-exporting installer" in item for item in exporter_failures),
        "self-test: mozilla-actions/sccache-action must fail",
        failures,
    )

    missing_assert_failures: list[str] = []
    check_credential_absence_assertion(
        "run: cargo test\n",
        "self-test-missing-assert",
        missing_assert_failures,
    )
    require(
        any("cache-credential absence assertion" in item for item in missing_assert_failures),
        "self-test: missing credential assertion must fail",
        failures,
    )

    echo_token = (
        "      - name: Assert cache-service credentials are absent\n"
        "        run: |\n"
        "          echo \"$ACTIONS_RUNTIME_TOKEN\"\n"
        "          echo \"$ACTIONS_RESULTS_URL\"\n"
        '          if [ -n "${!var:-}" ]; then echo refusing to execute later PR-controlled build steps; fi\n'
    )
    echo_token_failures: list[str] = []
    check_credential_absence_assertion(
        echo_token,
        "self-test-echo-token",
        echo_token_failures,
    )
    require(
        any("must not print cache-service credential values" in item for item in echo_token_failures),
        "self-test: echoing ACTIONS_RUNTIME_TOKEN must fail",
        failures,
    )

    consumer_save = (
        "name: demo\n"
        "env:\n"
        f"  FIPS_PRODUCER_KEY: {FIPS_PRODUCER_KEY_EXPR}\n"
        f"  FIPS_PRODUCER_RESTORE_PREFIX: {FIPS_PRODUCER_RESTORE_PREFIX_EXPR}\n"
        "jobs:\n"
        "  fips-compile:\n"
        "    steps:\n"
        f"      - uses: {CACHE_SAVE} # v4.2.4\n"
        f"        if: {COLD_NOT_TRUE} && {FORK_NOT_TRUE}\n"
        "        with:\n"
        "          path: |\n"
        f"            {FIPS_PRODUCER_PATHS[0]}\n"
        f"            {FIPS_PRODUCER_PATHS[1]}\n"
        "          key: ${{ env.FIPS_PRODUCER_KEY }}\n"
        "  fips-clippy:\n"
        "    steps:\n"
        f"      - uses: {CACHE_SAVE} # v4.2.4\n"
        f"        if: {COLD_NOT_TRUE} && {FORK_NOT_TRUE}\n"
        "        with:\n"
        "          key: ${{ env.FIPS_PRODUCER_KEY }}\n"
        "  fips-test:\n"
        "    steps:\n"
        f"      - uses: {CACHE_RESTORE} # v4.2.4\n"
        f"        if: {COLD_NOT_TRUE}\n"
        "        with:\n"
        "          key: ${{ env.FIPS_PRODUCER_KEY }}\n"
    )
    consumer_save_failures: list[str] = []
    check_fips_producer_channel(consumer_save, consumer_save_failures)
    require(
        any("must be a producer-cache consumer and must not save" in item for item in consumer_save_failures),
        "self-test: clippy producer save must fail",
        failures,
    )

    gha_backend = good_buildkit.replace("type=local", "type=gha")
    gha_failures: list[str] = []
    check_buildkit_cache_boundary(
        gha_backend,
        "self-test-gha-backend",
        gha_failures,
    )
    require(
        any("must not use the BuildKit GHA cache backend" in item for item in gha_failures),
        "self-test: reintroducing type=gha must fail",
        failures,
    )

    scope = "production-dockerfile-smoke-default"
    restore_step = (
        "      - name: Restore BuildKit local cache\n"
        f"        if: {COLD_NOT_TRUE}\n"
        f"        uses: {CACHE_RESTORE} # v4.2.4\n"
        "        with:\n"
        f"          path: /tmp/{scope}\n"
        f"          key: {buildkit_cache_key(scope)}\n"
        "          restore-keys: |\n"
        f"            {buildkit_cache_prefix(scope)}\n"
    )
    save_step = (
        "      - name: Save BuildKit local cache\n"
        f"        if: {COLD_NOT_TRUE} && {FORK_NOT_TRUE} && {CACHE_KIND_PUBLISH}\n"
        f"        uses: {CACHE_SAVE} # v4.2.4\n"
        "        with:\n"
        f"          path: /tmp/{scope}\n"
        f"          key: {buildkit_cache_key(scope)}\n"
    )
    good_local = "    steps:\n" + restore_step + save_step
    good_local_failures: list[str] = []
    check_local_cache_actions(
        good_local,
        "self-test-good-local-cache",
        good_local_failures,
        scope=scope,
    )
    require(
        not good_local_failures,
        "self-test: pinned restore/save should pass: "
        + "; ".join(good_local_failures),
        failures,
    )

    fork_save = good_local.replace(
        f"if: {COLD_NOT_TRUE} && {FORK_NOT_TRUE} && {CACHE_KIND_PUBLISH}\n        uses: {CACHE_SAVE}",
        f"if: {COLD_NOT_TRUE} && {FORK_IS_TRUE} && {CACHE_KIND_PUBLISH}\n        uses: {CACHE_SAVE}",
    )
    fork_save_failures: list[str] = []
    check_local_cache_actions(
        fork_save,
        "self-test-fork-save",
        fork_save_failures,
        scope=scope,
    )
    require(
        any("exclude fork PRs from cache save" in item for item in fork_save_failures),
        "self-test: fork cache publication must fail",
        failures,
    )

    cold_restore = good_local.replace(
        f"if: {COLD_NOT_TRUE}\n        uses: {CACHE_RESTORE}",
        f"if: {COLD_IS_TRUE}\n        uses: {CACHE_RESTORE}",
    )
    cold_restore_failures: list[str] = []
    check_local_cache_actions(
        cold_restore,
        "self-test-cold-restore",
        cold_restore_failures,
        scope=scope,
    )
    require(
        any("restore must skip force_cold_cache" in item for item in cold_restore_failures),
        "self-test: force-cold restore must fail",
        failures,
    )

    cold_save = good_local.replace(
        f"if: {COLD_NOT_TRUE} && {FORK_NOT_TRUE} && {CACHE_KIND_PUBLISH}\n        uses: {CACHE_SAVE}",
        f"if: {COLD_IS_TRUE} && {FORK_NOT_TRUE} && {CACHE_KIND_PUBLISH}\n        uses: {CACHE_SAVE}",
    )
    cold_save_failures: list[str] = []
    check_local_cache_actions(
        cold_save,
        "self-test-cold-save",
        cold_save_failures,
        scope=scope,
    )
    require(
        any("save must skip force_cold_cache" in item for item in cold_save_failures),
        "self-test: force-cold save must fail",
        failures,
    )

    exact_hit_save = good_local.replace(
        f"if: {COLD_NOT_TRUE} && {FORK_NOT_TRUE} && {CACHE_KIND_PUBLISH}\n        uses: {CACHE_SAVE}",
        f"if: {COLD_NOT_TRUE} && {FORK_NOT_TRUE} && {CACHE_KIND_EXACT}\n        uses: {CACHE_SAVE}",
    )
    exact_hit_save_failures: list[str] = []
    check_local_cache_actions(
        exact_hit_save,
        "self-test-exact-hit-save",
        exact_hit_save_failures,
        scope=scope,
    )
    require(
        any(
            "never save an immutable cache on an exact github.sha hit" in item
            or "run only after a partial match or miss" in item
            for item in exact_hit_save_failures
        ),
        "self-test: exact-hit cache save must fail",
        failures,
    )

    good_prepare = (
        "    steps:\n"
        "      - name: Prepare BuildKit cache for save\n"
        f"        if: {COLD_NOT_TRUE} && {FORK_NOT_TRUE} && {CACHE_KIND_PUBLISH}\n"
        "        run: |\n"
        "          set -euo pipefail\n"
        f'          out="${{RUNNER_TEMP}}/{scope}-out"\n'
        f'          dest="${{RUNNER_TEMP}}/{scope}"\n'
        '          if [ ! -d "$out" ]; then\n'
        '            echo "::error::fresh BuildKit cache export is missing; refusing to save a stale restore" >&2\n'
        "            exit 1\n"
        "          fi\n"
        '          rm -rf "$dest"\n'
        '          mv "$out" "$dest"\n'
    )
    good_prepare_failures: list[str] = []
    check_cache_save_preparation(
        good_prepare,
        "self-test-good-prepare",
        good_prepare_failures,
        scope=scope,
    )
    require(
        not good_prepare_failures,
        "self-test: fail-closed cache-save preparation should pass: "
        + "; ".join(good_prepare_failures),
        failures,
    )

    stale_dest_fallback = (
        "    steps:\n"
        "      - name: Prepare BuildKit cache for save\n"
        f"        if: {COLD_NOT_TRUE} && {FORK_NOT_TRUE} && {CACHE_KIND_PUBLISH}\n"
        "        run: |\n"
        "          set -euo pipefail\n"
        f'          out="${{RUNNER_TEMP}}/{scope}-out"\n'
        f'          dest="${{RUNNER_TEMP}}/{scope}"\n'
        '          if [ -d "$out" ]; then\n'
        '            rm -rf "$dest"\n'
        '            mv "$out" "$dest"\n'
        "          fi\n"
        '          if [ -d "$dest" ]; then\n'
        '            echo "present=true" >> "$GITHUB_OUTPUT"\n'
        "          else\n"
        '            echo "present=false" >> "$GITHUB_OUTPUT"\n'
        "          fi\n"
    )
    stale_dest_failures: list[str] = []
    check_cache_save_preparation(
        stale_dest_fallback,
        "self-test-stale-destination",
        stale_dest_failures,
        scope=scope,
    )
    require(
        any("fail when the fresh export is absent" in item for item in stale_dest_failures)
        and any("stale destination as present" in item for item in stale_dest_failures),
        "self-test: stale-destination fallback must fail",
        failures,
    )

    empty_hit = (
        "    steps:\n"
        "      - name: Record BuildKit cache restore\n"
        "        run: python3 .github/scripts/ci_runtime_telemetry.py cache --hit \"\"\n"
    )
    empty_hit_failures: list[str] = []
    check_cache_telemetry_evidence(
        empty_hit,
        "self-test-empty-hit",
        empty_hit_failures,
    )
    require(
        any("must not pass empty --hit" in item for item in empty_hit_failures),
        "self-test: empty --hit must fail",
        failures,
    )

    fabricated_hit = (
        "    steps:\n"
        "      - name: Record BuildKit cache restore\n"
        "        run: python3 .github/scripts/ci_runtime_telemetry.py cache --hit true --bytes 12\n"
    )
    fabricated_failures: list[str] = []
    check_cache_telemetry_evidence(
        fabricated_hit,
        "self-test-fabricated-hit",
        fabricated_failures,
    )
    require(
        any("must not fabricate a cache hit literal" in item for item in fabricated_failures),
        "self-test: fabricated --hit true must fail",
        failures,
    )

    missing_measurement = (
        "    steps:\n"
        "      - name: Record BuildKit cache restore\n"
        "        env:\n"
        "          CACHE_HIT: ${{ steps.buildkit-cache.outputs.cache-hit }}\n"
        "          CACHE_MATCHED: ${{ steps.buildkit-cache.outputs.cache-matched-key }}\n"
        "        run: |\n"
        "          python3 .github/scripts/ci_runtime_telemetry.py cache --hit \"$CACHE_HIT\"\n"
        "          echo produced no hit/miss evidence\n"
    )
    missing_measurement_failures: list[str] = []
    check_cache_telemetry_evidence(
        missing_measurement,
        "self-test-missing-bytes",
        missing_measurement_failures,
    )
    require(
        any("must measure restored bytes" in item for item in missing_measurement_failures),
        "self-test: missing restored-byte measurement must fail",
        failures,
    )

    line_diff_plan = (
        "    steps:\n"
        "      - name: Check for production Dockerfile smoke changes\n"
        "        run: |\n"
        '            git diff --name-only --no-renames "${trusted_sha}...HEAD" \\\n'
        '              | sort > "$changed_files"\n'
    )
    line_diff_failures: list[str] = []
    check_nul_delimited_plan(
        line_diff_plan,
        "self-test-line-diff",
        line_diff_failures,
    )
    require(
        any("must not use line-delimited git diff --name-only" in item for item in line_diff_failures)
        and any("must not pass pathname bytes through sort" in item for item in line_diff_failures),
        "self-test: line-delimited git diff --name-only must fail",
        failures,
    )

    incomplete_trigger = (
        "name: demo\n"
        "on:\n"
        "  pull_request:\n"
        "    paths:\n"
        "      - Dockerfile\n"
        "      - Cargo.toml\n"
    )
    incomplete_trigger_failures: list[str] = []
    check_production_trigger_superset(
        incomplete_trigger,
        "self-test-incomplete-trigger",
        incomplete_trigger_failures,
    )
    require(
        any("must be a superset of production-dockerfile-smoke" in item for item in incomplete_trigger_failures),
        "self-test: incomplete pull_request.paths must fail trigger superset check",
        failures,
    )

    good_trigger = (
        "name: demo\n"
        "on:\n"
        "  pull_request:\n"
        "    paths:\n"
        "      - Dockerfile\n"
        "      - .dockerignore\n"
        "      - Cargo.toml\n"
        "      - Cargo.lock\n"
        "      - rust-toolchain.toml\n"
        "      - .cargo/**\n"
        "      - vendor/**\n"
        "      - build.rs\n"
        "      - proto/**\n"
        "      - src/**\n"
        "      - custom_plugins/**\n"
        "      - ebpf/**\n"
        "      - .github/scripts/stage_iproute2_runtime.sh\n"
        "      - .github/workflows/node-waypoint-ebpf-live.yml\n"
        "      - .github/scripts/ci_runtime_plan.py\n"
        "      - .github/scripts/ci_runtime_telemetry.py\n"
        "      - .github/scripts/verify_ci_runtime_cache.py\n"
    )
    good_trigger_failures: list[str] = []
    check_production_trigger_superset(
        good_trigger,
        "self-test-good-trigger",
        good_trigger_failures,
    )
    require(
        not good_trigger_failures,
        "self-test: complete production trigger superset should pass: "
        + "; ".join(good_trigger_failures),
        failures,
    )

    loose_skip_aggregate = (
        "    steps:\n"
        "      - name: Fail when production-image planning fails\n"
        "        if: needs.production-dockerfile-plan.result != 'success'\n"
        "        run: exit 1\n"
        "      - name: Skip production-image smoke for unrelated changes\n"
        "        if: needs.production-dockerfile-plan.outputs.relevant != 'true'\n"
        "        run: echo skip\n"
        "      - name: Fail when the ordinary production image did not succeed\n"
        "        if: needs.production-dockerfile-plan.outputs.relevant == 'true'\n"
        "        run: exit 1\n"
    )
    loose_skip_failures: list[str] = []
    check_aggregate_planner_contract(
        loose_skip_aggregate,
        "production-dockerfile-plan",
        "self-test-loose-skip",
        loose_skip_failures,
    )
    require(
        any("skip must use exact" in item for item in loose_skip_failures)
        or any("skip must not use != 'true'" in item for item in loose_skip_failures),
        "self-test: aggregate skip on != 'true' must fail",
        failures,
    )

    good_aggregate = (
        "    steps:\n"
        "      - name: Fail when production-image planning fails\n"
        "        if: needs.production-dockerfile-plan.result != 'success'\n"
        "        run: exit 1\n"
        "      - name: Fail when production-image planner output is unusable\n"
        "        if: needs.production-dockerfile-plan.result == 'success' && "
        "needs.production-dockerfile-plan.outputs.relevant != 'true' && "
        "needs.production-dockerfile-plan.outputs.relevant != 'false'\n"
        "        run: exit 1\n"
        "      - name: Skip production-image smoke for unrelated changes\n"
        "        if: needs.production-dockerfile-plan.outputs.relevant == 'false'\n"
        "        run: echo skip\n"
        "      - name: Fail when the ordinary production image did not succeed\n"
        "        if: needs.production-dockerfile-plan.outputs.relevant == 'true'\n"
        "        run: exit 1\n"
    )
    good_aggregate_failures: list[str] = []
    check_aggregate_planner_contract(
        good_aggregate,
        "production-dockerfile-plan",
        "self-test-good-aggregate",
        good_aggregate_failures,
    )
    require(
        not good_aggregate_failures,
        "self-test: exact-boolean aggregate contract should pass: "
        + "; ".join(good_aggregate_failures),
        failures,
    )

    greedy_skip_capture_aggregate = (
        "    steps:\n"
        "      - name: Fail when production-image planning fails\n"
        "        if: needs.production-dockerfile-plan.result != 'success'\n"
        "        run: exit 1\n"
        "      - name: Fail when production-image planner output is unusable\n"
        "        if: needs.production-dockerfile-plan.result == 'success' && "
        "needs.production-dockerfile-plan.outputs.relevant != 'true' && "
        "needs.production-dockerfile-plan.outputs.relevant != 'false'\n"
        "        run: exit 1\n"
        "      - name: Skip production-image smoke for unrelated changes\n"
        "        if: needs.production-dockerfile-plan.outputs.relevant == 'false'\n"
        "        run: echo skip\n"
        "      - name: Fail when the ordinary production image did not succeed\n"
        "        if: needs.production-dockerfile-plan.outputs.relevant == 'true'\n"
        "        run: exit 1\n"
        "      - name: Poison for greedy skip-if capture\n"
        "        if: needs.production-dockerfile-plan.outputs.relevant != 'true'\n"
        "        run: echo must-not-be-in-skip-if\n"
    )
    greedy_skip_capture_failures: list[str] = []
    check_aggregate_planner_contract(
        greedy_skip_capture_aggregate,
        "production-dockerfile-plan",
        "self-test-greedy-skip-capture",
        greedy_skip_capture_failures,
    )
    require(
        not greedy_skip_capture_failures,
        "self-test: post-skip steps must not pollute skip-if extraction: "
        + "; ".join(greedy_skip_capture_failures),
        failures,
    )

    missing_unusable_aggregate = (
        "    steps:\n"
        "      - name: Fail when production-image planning fails\n"
        "        if: needs.production-dockerfile-plan.result != 'success'\n"
        "        run: exit 1\n"
        "      - name: Skip production-image smoke for unrelated changes\n"
        "        if: needs.production-dockerfile-plan.outputs.relevant == 'false'\n"
        "        run: echo skip\n"
        "      - name: Fail when the ordinary production image did not succeed\n"
        "        if: needs.production-dockerfile-plan.outputs.relevant == 'true'\n"
        "        run: exit 1\n"
    )
    missing_unusable_failures: list[str] = []
    check_aggregate_planner_contract(
        missing_unusable_aggregate,
        "production-dockerfile-plan",
        "self-test-missing-unusable",
        missing_unusable_failures,
    )
    require(
        any("fail closed when planner output is neither" in item for item in missing_unusable_failures),
        "self-test: aggregate without unusable-output guard must fail",
        failures,
    )

    def _live_workflow(live_if: str) -> str:
        return (
            "  production-dockerfile-plan:\n"
            "    outputs:\n"
            "      relevant: ${{ steps.filter.outputs.relevant }}\n"
            "      node_waypoint_relevant: ${{ steps.filter.outputs.node_waypoint_relevant }}\n"
            "    steps:\n"
            "      - name: Check\n"
            "        run: |\n"
            '          echo "node_waypoint_relevant=true" >> "$GITHUB_OUTPUT"\n'
            "          echo trusted base has not adopted filter\n"
            '          python3 -I "$trusted_filter" --suite "$suite"\n'
            "          emit_suite_verdict node-waypoint-ebpf-live node_waypoint_relevant\n"
            "  node-waypoint-ebpf-live:\n"
            "    name: NodeWaypoint eBPF live datapath\n"
            "    needs: production-dockerfile-plan\n"
            f"    if: {live_if}\n"
            "    runs-on: ubuntu-24.04\n"
            "    timeout-minutes: 120\n"
            "    steps:\n"
            "      - run: kind create cluster --name demo\n"
            "      - run: tests/k8s/node_waypoint_ebpf_live/run.sh\n"
            "      - run: echo ferrum_mesh_bpf_drops_total\n"
            "        if: always()\n"
        )

    good_live_failures: list[str] = []
    check_node_waypoint_live_job(
        _live_workflow(NODE_WAYPOINT_LIVE_IF),
        "self-test-good-live",
        good_live_failures,
    )
    require(
        not good_live_failures,
        "self-test: exact-false NodeWaypoint live skip should pass: "
        + "; ".join(good_live_failures),
        failures,
    )

    exact_true_failures: list[str] = []
    check_node_waypoint_live_job(
        _live_workflow(
            "always() && needs.production-dockerfile-plan.outputs.node_waypoint_relevant == 'true'"
        ),
        "self-test-live-exact-true",
        exact_true_failures,
    )
    require(
        any("must not treat blank/malformed output as a skip" in item for item in exact_true_failures)
        or any("skip only on exact" in item for item in exact_true_failures),
        "self-test: NodeWaypoint live job gated on == 'true' must fail",
        failures,
    )

    no_always_failures: list[str] = []
    check_node_waypoint_live_job(
        _live_workflow(
            "needs.production-dockerfile-plan.outputs.node_waypoint_relevant != 'false'"
        ),
        "self-test-live-no-always",
        no_always_failures,
    )
    require(
        any("always()" in item for item in no_always_failures),
        "self-test: NodeWaypoint live job without always() must fail",
        failures,
    )

    success_required_failures: list[str] = []
    check_node_waypoint_live_job(
        _live_workflow(
            "always() && needs.production-dockerfile-plan.result == 'success' && "
            "needs.production-dockerfile-plan.outputs.node_waypoint_relevant != 'false'"
        ),
        "self-test-live-success-required",
        success_required_failures,
    )
    require(
        any("must not require planner success" in item for item in success_required_failures)
        or any("skip only on exact" in item for item in success_required_failures),
        "self-test: NodeWaypoint live job requiring planner success must fail",
        failures,
    )

    unbound_failures: list[str] = []
    unbound_workflow = _live_workflow(NODE_WAYPOINT_LIVE_IF).replace(
        "    needs: production-dockerfile-plan\n",
        "",
    )
    check_node_waypoint_live_job(
        unbound_workflow,
        "self-test-live-unbound",
        unbound_failures,
    )
    require(
        any("must depend on the trusted planner job" in item for item in unbound_failures),
        "self-test: NodeWaypoint live job without needs must fail",
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
