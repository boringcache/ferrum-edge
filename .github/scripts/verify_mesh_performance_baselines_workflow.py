#!/usr/bin/env python3
"""Static contract checks for the mesh performance baselines workflow (#3332).

Does not execute benchmarks. Validates workflow wiring, pinned actions, suite
coverage, provenance/summary scripts, ubuntu-24.04 pin, acceptance step,
mesh/HBONE/DNS interval evidence, and docs inventory pointers.
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
LEDGER_SCRIPT = REPO_ROOT / ".github" / "scripts" / "mesh_baseline_ledger.py"
HEALTH_SCRIPT = REPO_ROOT / ".github" / "scripts" / "mesh_baseline_runner_health.py"
STEP_SUMMARY_SCRIPT = REPO_ROOT / ".github" / "scripts" / "mesh_baseline_step_summary.py"
CI_YML = REPO_ROOT / ".github" / "workflows" / "ci.yml"
PROTOCOL_DOC = REPO_ROOT / "docs" / "protocol_perf_regression.md"
CI_CD_DOC = REPO_ROOT / "docs" / "ci_cd.md"
MESH_BASELINE = REPO_ROOT / "tests" / "performance" / "mesh" / "baseline.md"
HBONE_BASELINE = REPO_ROOT / "tests" / "performance" / "mesh-hbone-e2e" / "baseline.md"
DNS_BASELINE = REPO_ROOT / "tests" / "performance" / "mesh-dns-e2e" / "baseline.md"
HBONE_LOADGEN = (
    REPO_ROOT / "tests" / "performance" / "mesh-hbone-e2e" / "src" / "bin" / "hbone_loadgen.rs"
)
DNS_LOADGEN = (
    REPO_ROOT / "tests" / "performance" / "mesh-dns-e2e" / "src" / "bin" / "dns_loadgen.rs"
)

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
HBONE_BACKEND_ALLOW_IPS_VAR = "FERRUM_BACKEND_ALLOW_IPS"
HBONE_BACKEND_ALLOW_IPS_VALUE = "private"
ALLOW_IPS_ASSIGN_RE = re.compile(
    rf"{re.escape(HBONE_BACKEND_ALLOW_IPS_VAR)}="
    r'(?:"(?P<dq>[^"]*)"|\'(?P<sq>[^\']*)\'|(?P<bare>[^\s\\&|;]+))'
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args(argv)


def require(condition: bool, message: str, failures: list[str]) -> None:
    if not condition:
        failures.append(message)


def _strip_shell_comment(value: str) -> str:
    """Remove an unquoted shell comment while preserving quoted ``#`` data."""
    quote: str | None = None
    escaped = False
    for index, character in enumerate(value):
        if escaped:
            escaped = False
            continue
        if character == "\\" and quote != "'":
            escaped = True
            continue
        if quote is not None:
            if character == quote:
                quote = None
            continue
        if character in "'\"":
            quote = character
            continue
        if character == "#" and (index == 0 or value[index - 1].isspace()):
            return value[:index]
    return value


def _logical_shell_lines(text: str) -> list[str]:
    """Join backslash-continued shell lines into one logical command line."""
    logical: list[str] = []
    parts: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if line.endswith("\\"):
            parts.append(line[:-1].rstrip())
            continue
        parts.append(line)
        logical.append(" ".join(parts))
        parts = []
    if parts:
        logical.append(" ".join(parts))
    return logical


def _active_backend_allow_ips_assignments(text: str) -> list[str]:
    """Return values from active ``FERRUM_BACKEND_ALLOW_IPS`` shell assignments."""
    values: list[str] = []
    for logical_line in _logical_shell_lines(text):
        active = _strip_shell_comment(logical_line).strip()
        if not active or active.startswith("#"):
            continue
        for match in ALLOW_IPS_ASSIGN_RE.finditer(active):
            value = match.group("dq")
            if value is None:
                value = match.group("sq")
            if value is None:
                value = match.group("bare")
            values.append(value)
    return values


def _check_hbone_backend_allow_ips(hbone_run: str, failures: list[str]) -> None:
    """Require exactly one active ``FERRUM_BACKEND_ALLOW_IPS="private"`` assignment."""
    values = _active_backend_allow_ips_assignments(hbone_run)
    if not values:
        failures.append(
            f'HBONE harness must set exactly one active '
            f'{HBONE_BACKEND_ALLOW_IPS_VAR}="{HBONE_BACKEND_ALLOW_IPS_VALUE}" assignment'
        )
        return
    if len(values) != 1:
        failures.append(
            f"HBONE harness must have exactly one active {HBONE_BACKEND_ALLOW_IPS_VAR} assignment "
            f"(found {len(values)}: {values!r})"
        )
        return
    value = values[0]
    if value != HBONE_BACKEND_ALLOW_IPS_VALUE:
        failures.append(
            f'HBONE harness must set {HBONE_BACKEND_ALLOW_IPS_VAR}="{HBONE_BACKEND_ALLOW_IPS_VALUE}" '
            f"for loopback/private backends (found active assignment {value!r})"
        )


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
    require("workflow_call:" in text, "trusted reusable entry point required", failures)
    require("cancel-in-progress: false" in text, "collection must serialize without cancelling in-progress runs", failures)
    require("cancel-in-progress: true" not in text, "collection must not cancel in-progress runs", failures)
    require("BENCH_BUILD_PROFILE: release" in text, "release profile required", failures)
    require("BENCH_MAX_CPU_STEAL_PERCENT: \"5.0\"" in text or "BENCH_MAX_CPU_STEAL_PERCENT: '5.0'" in text, "documented CPU steal threshold required", failures)
    require("runner_health_probes.jsonl" in text, "per-E2E runner health probes required", failures)
    require(
        "mesh_baseline_runner_health.py" in text,
        "runner health capture must be wired to the approved automation script",
        failures,
    )
    require(
        "mesh_baseline_runner_health.py --self-test" in text,
        "workflow must run the runner health hosted self-test",
        failures,
    )
    require("--interval-begin" in text, "health probes must snapshot interval begin", failures)
    require("--interval-end" in text, "health probes must snapshot interval end", failures)
    require("MESH_BASELINE_DIAG_DIR" in text, "hosted collection must set an opt-in diagnostic log destination", failures)
    require("sysstat" not in text, "sysstat is unused by selected harnesses and must not be installed", failures)
    require(
        "libcurl4-openssl-dev" not in text,
        "collection must not reinstall libcurl4-openssl-dev; setup-rust-ci already provides it",
        failures,
    )
    require("protobuf-compiler" in text and "lsof" in text, "retain protobuf-compiler and lsof prerequisites", failures)
    require(
        "harness_status" in text and "PIPESTATUS" in text,
        "E2E interval-end must preserve the original harness exit status",
        failures,
    )
    # The trusted Cross build policy refuses a new workflow that carries a
    # dynamic executable surface. Inline interpreter bodies are exactly that:
    # a heredoc program or an awk/bc one-liner is a command the static scan
    # cannot resolve to a literal argument vector. Keep those computations in
    # .github/scripts/ instead of reintroducing them here.
    require(
        re.search(r"(?<!<)<<(?!<)", text) is None,
        "no inline heredoc programs in this workflow",
        failures,
    )
    require(
        not re.search(r"(?<![A-Za-z0-9_-])(awk|bc|gawk|mawk|perl|node|ruby)(?![A-Za-z0-9_.-])", text),
        "no inline non-shell interpreters in this workflow",
        failures,
    )
    require("--check-acceptance" in text, "selected-suite acceptance step required", failures)
    require(
        "unsupported suites value" in text,
        "workflow must reject unsupported suites at the boundary",
        failures,
    )
    require(
        "all|mesh|hbone|dns" in text or 'supported = {"all", "mesh", "hbone", "dns"}' in text,
        "workflow suite allowlist must be all|mesh|hbone|dns",
        failures,
    )
    require(
        "BENCH_ITERATIONS must be an integer from 3 to 5" in text
        and "ITERATIONS > 5" in text,
        "workflow must reject E2E repetition counts outside 3..5",
        failures,
    )
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
        if setup == "./.github/actions/setup-rust-ci":
            require(setup in text, "must use setup-rust-ci", failures)

    mesh_step = _named_step(text, "Collect mesh Criterion microbenchmarks")
    hbone_step = _named_step(text, "Collect HBONE E2E baselines (3+ repetitions)")
    dns_step = _named_step(text, "Collect DNS E2E baselines (3+ repetitions)")
    require(bool(mesh_step), "mesh Criterion collection step required", failures)
    require(bool(hbone_step), "HBONE E2E collection step required", failures)
    require(bool(dns_step), "DNS E2E collection step required", failures)
    require(
        "--phase mesh" in mesh_step
        and "--interval-begin" in mesh_step
        and "--interval-end" in mesh_step
        and "authz_match" in mesh_step,
        "mesh Criterion health probes must snapshot /proc/stat around each selected bench",
        failures,
    )
    for body, label, harness, forbidden_cd in (
        (
            hbone_step,
            "HBONE",
            "./tests/performance/mesh-hbone-e2e/run.sh",
            "cd tests/performance/mesh-hbone-e2e",
        ),
        (
            dns_step,
            "DNS",
            "./tests/performance/mesh-dns-e2e/run.sh",
            "cd tests/performance/mesh-dns-e2e",
        ),
    ):
        begin = body.find("--interval-begin")
        run = body.find(harness)
        end = body.find("--interval-end")
        require(
            begin != -1 and run != -1 and end != -1 and begin < run < end,
            f"{label} health probes must snapshot /proc/stat around the workload interval",
            failures,
        )
        require(
            forbidden_cd not in body,
            f"{label} collection must invoke the harness by repository-root path "
            "without changing directory",
            failures,
        )
        require(
            "harness_status" in body and "PIPESTATUS" in body,
            f"{label} must preserve harness exit status around interval-end",
            failures,
        )
        require(
            "set +e" in body,
            f"{label} must attempt interval-end even when the harness exits nonzero",
            failures,
        )
        require(
            "MESH_BASELINE_DIAG_DIR" in body,
            f"{label} must set MESH_BASELINE_DIAG_DIR so failure logs upload",
            failures,
        )


def _named_step(text: str, name: str) -> str:
    """Return the workflow step body starting at `- name: {name}`."""
    marker = f"- name: {name}"
    start = text.find(marker)
    if start == -1:
        return ""
    next_step = text.find("\n      - name:", start + len(marker))
    if next_step == -1:
        return text[start:]
    return text[start:next_step]


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


def check_scripts(failures: list[str]) -> None:
    require(PROVENANCE_SCRIPT.is_file(), "provenance script missing", failures)
    require(SUMMARY_SCRIPT.is_file(), "summary script missing", failures)
    require(WORKFLOW_PATH.is_file(), "workflow missing", failures)

    require(LEDGER_SCRIPT.is_file(), "suite command ledger script missing", failures)
    require(HEALTH_SCRIPT.is_file(), "runner health script missing", failures)
    require(STEP_SUMMARY_SCRIPT.is_file(), "step summary script missing", failures)

    provenance = PROVENANCE_SCRIPT.read_text(encoding="utf-8")
    require("ubuntu-24.04" in provenance, "provenance default runner class must be ubuntu-24.04", failures)
    require("::error::suite command ledger" in provenance, "provenance must fail closed on malformed suite ledgers", failures)
    require("::error::BENCH_ITERATIONS" in provenance, "provenance must fail closed on malformed BENCH_ITERATIONS", failures)
    require(
        'int(os.environ.get("BENCH_ITERATIONS"' not in provenance,
        "provenance must not unguardedly convert BENCH_ITERATIONS",
        failures,
    )

    ledger = LEDGER_SCRIPT.read_text(encoding="utf-8")
    require(
        'SUPPORTED_SUITES = ("all", "mesh", "hbone", "dns")' in ledger,
        "ledger suite allowlist must be all|mesh|hbone|dns",
        failures,
    )
    require(
        "BENCH_ITERATIONS must be an integer from 3 to 5" in ledger,
        "ledger must reject E2E repetition counts outside 3..5",
        failures,
    )
    require(
        "1kib_c50_30s" in ledger and "16kib_c50_30s" in ledger and "256kib_c100_60s" in ledger,
        "ledger HBONE scenarios incomplete",
        failures,
    )
    require(
        all(bench in ledger for bench in ("authz_match", "ip_restriction", "slice_apply", "xds_translation")),
        "ledger mesh benches incomplete",
        failures,
    )
    require(
        "./tests/performance/mesh-hbone-e2e/run.sh" in ledger,
        "ledger HBONE commands must invoke the harness by repository-root path",
        failures,
    )
    require(
        "./tests/performance/mesh-dns-e2e/run.sh" in ledger,
        "ledger DNS commands must invoke the harness by repository-root path",
        failures,
    )

    health = HEALTH_SCRIPT.read_text(encoding="utf-8")
    require("runner_health.json" in health, "machine-readable runner_health.json required", failures)
    require("runner_health.log" in health, "runner_health.log audit trail required", failures)
    require("runner_health_probes.jsonl" in health, "per-E2E runner health probes required", failures)
    require(
        "BENCH_MAX_CPU_STEAL_PERCENT" in health,
        "runner health script must honour the documented steal threshold",
        failures,
    )
    require(
        '["vmstat", "1", "6"]' in health,
        "pre-collection runner health sampling must use a literal vmstat command vector",
        failures,
    )
    require(
        '["vmstat", "1", "3"]' not in health,
        "E2E probes must not use a short pre-run vmstat sample",
        failures,
    )
    require("/proc/stat" in health, "E2E interval probes must snapshot /proc/stat", failures)
    require(
        "interval-begin" in health and "interval-end" in health,
        "interval probes must expose begin/end snapshots",
        failures,
    )
    require('"mesh"' in health or "mesh" in health, "runner health script must accept mesh Criterion probes", failures)
    require("--self-test" in health, "runner health script must provide hosted self-tests", failures)
    require(
        "parse failure cannot become healthy evidence" in health,
        "runner health self-test must prove parse failure cannot become healthy evidence",
        failures,
    )
    require(
        "successful exact-interval evidence" in health,
        "runner health self-test must cover successful exact-interval evidence",
        failures,
    )
    require(
        "end-without-start" in health,
        "runner health self-test must cover end-without-start evidence",
        failures,
    )
    require("excessive steal" in health, "runner health self-test must cover excessive steal", failures)
    require(
        "return 0.0" not in health,
        "runner health parse failure must not return 0.0 as a healthy steal sample",
        failures,
    )
    require("check=True" not in health, "runner health must not use uncaught check=True subprocess failures", failures)
    require("::error::" in health, "runner health vmstat failures must emit controlled ::error:: diagnostics", failures)

    summary = SUMMARY_SCRIPT.read_text(encoding="utf-8")
    require("repetition_evidence" in summary, "summarizer must expose repetition_evidence", failures)
    require("MAX_CPU_STEAL_PERCENT" in summary, "summarizer must document steal threshold", failures)
    require("DNS_GATEWAY_ROWS" in summary, "summarizer must enumerate required DNS gateway rows", failures)
    require("--check-acceptance" in summary, "summarizer must support acceptance check", failures)
    require("undersampling" in summary or "one gateway" in summary, "summarizer self-test must cover undersampling", failures)
    require("SUPPORTED_SUITES" in summary, "summarizer must define SUPPORTED_SUITES", failures)
    require("suites_supported" in summary, "summarizer must gate on suites_supported", failures)
    require("expected_run_paths" in summary, "summarizer must count distinct expected run files", failures)
    require("unexpected_run_paths" in summary, "summarizer must reject extra or misnumbered run files", failures)
    require("classify_dns_target" in summary, "summarizer must classify DNS targets fail-closed", failures)
    require("duplicate relevant blobs" in summary, "summarizer self-test must cover duplicate blobs", failures)
    require("malformed relevant blobs alongside" in summary, "summarizer self-test must cover malformed mixed runs", failures)
    require("missing counterpart" in summary, "summarizer self-test must cover missing counterpart data", failures)
    require("unexpected DNS target" in summary, "summarizer self-test must cover unexpected DNS targets", failures)
    require("unsupported suite selection" in summary, "summarizer self-test must cover invalid suites", failures)
    require("shape_failures" in summary, "summarizer must track per-run shape failures", failures)
    require("provenance_complete" in summary, "summarizer must gate incomplete provenance", failures)
    require("expected_health_probe_ids" in summary, "summarizer must gate every selected-suite health probe", failures)
    require("MESH_BENCHES" in summary, "summarizer must enumerate mesh Criterion benches", failures)
    require('("mesh", bench, 1)' in summary, "summarizer must require mesh Criterion interval probe IDs", failures)
    require("total_nxdomain" in summary, "summarizer must parse DNS NXDOMAIN counts", failures)
    require("total_nxdomain_sum" in summary, "summarizer must aggregate DNS NXDOMAIN counts", failures)
    require("nonzero NXDOMAIN" in summary, "summarizer self-test must cover NXDOMAIN fail-closed behavior", failures)
    require("dns_nxdomain_partial" in summary, "summarizer self-test must cover partial NXDOMAIN", failures)
    require("dns_nxdomain_all" in summary, "summarizer self-test must cover all-NXDOMAIN", failures)
    require("mesh Criterion windows require" in summary, "summarizer self-test must require mesh interval evidence", failures)
    require("workload_interval" in summary, "summarizer must require workload-interval probe coverage", failures)
    require(
        "successful exact-interval evidence" in summary,
        "summarizer self-test must cover successful exact-interval evidence",
        failures,
    )
    require(
        "parse failure cannot become healthy evidence" in summary,
        "summarizer self-test must prove parse failure cannot become healthy evidence",
        failures,
    )
    require(
        "end-without-start" in summary,
        "summarizer self-test must cover end-without-start evidence",
        failures,
    )
    require(
        "excessive steal" in summary,
        "summarizer self-test must cover excessive steal",
        failures,
    )
    require("payload_size" in summary, "summarizer must validate HBONE scenario parameters", failures)
    require("DNS_DURATION_SECS" in summary, "summarizer must validate DNS scenario parameters", failures)

    hbone_run = (REPO_ROOT / "tests" / "performance" / "mesh-hbone-e2e" / "run.sh").read_text(encoding="utf-8")
    dns_run = (REPO_ROOT / "tests" / "performance" / "mesh-dns-e2e" / "run.sh").read_text(encoding="utf-8")
    require("MESH_BASELINE_DIAG_DIR" in hbone_run, "HBONE harness must honour MESH_BASELINE_DIAG_DIR", failures)
    require("MESH_BASELINE_DIAG_DIR" in dns_run, "DNS harness must honour MESH_BASELINE_DIAG_DIR", failures)
    require("archive_failure_diagnostics" in hbone_run, "HBONE harness must copy logs before deleting runtime", failures)
    require("archive_failure_diagnostics" in dns_run, "DNS harness must copy logs into the artifact destination", failures)
    require("certs" in hbone_run and "Never copy certs" in hbone_run, "HBONE diagnostics must not archive certs", failures)
    _check_hbone_backend_allow_ips(hbone_run, failures)

    hbone_loadgen = HBONE_LOADGEN.read_text(encoding="utf-8")
    dns_loadgen = DNS_LOADGEN.read_text(encoding="utf-8")
    require(
        "worker_join_failed" in hbone_loadgen
        and "one or more HBONE load-generator workers failed" in hbone_loadgen,
        "HBONE load-generator worker join failures must fail the collection",
        failures,
    )
    require(
        "worker_join_failed" in dns_loadgen
        and "one or more DNS load-generator workers failed" in dns_loadgen,
        "DNS load-generator worker join failures must fail the collection",
        failures,
    )


def check_pr_ci_wiring(failures: list[str]) -> None:
    ci = CI_YML.read_text(encoding="utf-8")
    match = re.search(
        r"(?ms)^  performance-regression:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
        ci,
    )
    body = match.group("body") if match else ""
    require(
        bool(body),
        "ci.yml performance-regression job required for mesh baseline contract host",
        failures,
    )
    require(
        "verify_mesh_performance_baselines_workflow.py --self-test" in body,
        "jobs.performance-regression must self-test the mesh baselines workflow verifier",
        failures,
    )
    require(
        "python3 .github/scripts/verify_mesh_performance_baselines_workflow.py" in body,
        "jobs.performance-regression must run the mesh baselines workflow verifier",
        failures,
    )
    static_idx = ci.find("Verify mesh performance baselines workflow contract")
    detect_idx = ci.find("Detect performance-sensitive changes")
    require(
        static_idx != -1 and detect_idx != -1 and static_idx < detect_idx,
        "ci.yml must run mesh baseline workflow contracts after checkout and "
        "before optional benchmark path gating",
        failures,
    )

def check_docs_and_baselines(failures: list[str]) -> None:
    protocol = PROTOCOL_DOC.read_text(encoding="utf-8")
    require("mesh-performance-baselines.yml" in protocol, "protocol_perf_regression.md missing workflow pointer", failures)
    require("#3332" in protocol, "protocol_perf_regression.md must keep #3332 pointer", failures)
    require("ubuntu-24.04" in protocol, "protocol_perf_regression.md must document ubuntu-24.04 pin", failures)
    require(
        "workload-interval" in protocol,
        "protocol_perf_regression.md must describe per-E2E workload-interval steal probes",
        failures,
    )
    require(
        "mesh Criterion" in protocol or "Criterion window" in protocol,
        "protocol_perf_regression.md must document mesh Criterion steal windows",
        failures,
    )

    ci_cd = CI_CD_DOC.read_text(encoding="utf-8")
    require("mesh-performance-baselines.yml" in ci_cd, "ci_cd.md inventory missing workflow row", failures)
    mesh_row = next(
        (line for line in ci_cd.splitlines() if "mesh-performance-baselines.yml" in line),
        "",
    )
    require(
        "workflow_dispatch" in mesh_row,
        "ci_cd.md mesh baselines row must describe workflow_dispatch",
        failures,
    )
    require(
        "workflow_call" in mesh_row,
        "ci_cd.md mesh baselines row must describe workflow_call",
        failures,
    )

    dns_text = DNS_BASELINE.read_text(encoding="utf-8")
    require(
        "acceptance_gate.dns_complete" in dns_text,
        "DNS baseline.md must reference acceptance_gate.dns_complete",
        failures,
    )
    require(
        "acceptance_gate.runner_health_ok" in dns_text,
        "DNS baseline.md must reference acceptance_gate.runner_health_ok",
        failures,
    )
    require(
        "edns" in dns_text.lower() or "EDNS" in dns_text,
        "DNS baseline.md must document the EDNS(0) rerun option",
        failures,
    )
    require(
        "nxdomain" in dns_text.lower(),
        "DNS baseline.md must document NXDOMAIN fail-closed publication",
        failures,
    )

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
        require(
            "workload-interval" in text.lower() or "workload interval" in text.lower(),
            f"{path} must document workload-interval steal coverage",
            failures,
        )


def _self_test_hbone_backend_allow_ips(failures: list[str]) -> None:
    """Prove active-assignment parsing rejects comment camouflage and widening."""
    good = """
    env \\
        FERRUM_BACKEND_ALLOW_IPS="private" \\
        ./target/release/ferrum-edge
"""
    good_failures: list[str] = []
    _check_hbone_backend_allow_ips(good, good_failures)
    require(not good_failures, "active private assignment must pass", failures)

    cases = (
        (
            """
# FERRUM_BACKEND_ALLOW_IPS="private"
    env \\
        FERRUM_BACKEND_ALLOW_IPS="public" \\
        ./target/release/ferrum-edge
""",
            "comment camouflage",
        ),
        (
            """
    env \\
        FERRUM_BACKEND_ALLOW_IPS="both" \\
        ./target/release/ferrum-edge
""",
            "both widening",
        ),
        (
            """
    env \\
        FERRUM_BACKEND_ALLOW_IPS="10.0.0.0/8" \\
        ./target/release/ferrum-edge
""",
            "CIDR literal",
        ),
        (
            """
    env \\
        FERRUM_BACKEND_ALLOW_IPS="private" \\
        FERRUM_BACKEND_ALLOW_IPS="private" \\
        ./target/release/ferrum-edge
""",
            "duplicate assignment",
        ),
        (
            """
    env \\
        ./target/release/ferrum-edge
""",
            "missing assignment",
        ),
        (
            """
    env \\
        FERRUM_BACKEND_ALLOW_IPS="public" # FERRUM_BACKEND_ALLOW_IPS="private"
        ./target/release/ferrum-edge
""",
            "inline comment camouflage",
        ),
    )
    for sample, label in cases:
        case_failures: list[str] = []
        _check_hbone_backend_allow_ips(sample, case_failures)
        require(case_failures, f"{label} must be rejected", failures)


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
concurrency:
  group: mesh-performance-baselines-ref
  cancel-in-progress: false
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
      - run: sudo apt-get install -y protobuf-compiler lsof curl
      - run: authz_match ip_restriction slice_apply xds_translation
      - run: 1kib_c50_30s 16kib_c50_30s 256kib_c100_60s
      - run: ./tests/performance/mesh-hbone-e2e/run.sh --duration 60 --concurrency 100
      - run: collect_mesh_baseline_provenance.py
      - run: summarize_mesh_baseline_results.py
      - run: runner_health.json runner_health_probes.jsonl
      - run: python3 .github/scripts/mesh_baseline_runner_health.py --self-test
      - run: python3 .github/scripts/mesh_baseline_runner_health.py --phase pre_collection
      - run: |
          case "${SUITES}" in
            all|mesh|hbone|dns) ;;
            *)
              echo "::error::unsupported suites value"
              exit 1
              ;;
          esac
          if [[ ! "${ITERATIONS}" =~ ^[0-9]+$ ]] || ((ITERATIONS < 3 || ITERATIONS > 5)); then
            echo "::error::BENCH_ITERATIONS must be an integer from 3 to 5"
            exit 1
          fi
      - name: Collect mesh Criterion microbenchmarks
        run: |
          python3 .github/scripts/mesh_baseline_runner_health.py --phase mesh --interval-begin
          set +e
          cargo bench --bench authz_match
          harness_status=${PIPESTATUS[0]}
          python3 .github/scripts/mesh_baseline_runner_health.py --phase mesh --interval-end
      - name: Collect HBONE E2E baselines (3+ repetitions)
        run: |
          python3 .github/scripts/mesh_baseline_runner_health.py --interval-begin
          set +e
          export MESH_BASELINE_DIAG_DIR=mesh-baseline-results/logs/hbone/run_1
          ./tests/performance/mesh-hbone-e2e/run.sh --duration 60 --concurrency 100
          harness_status=${PIPESTATUS[0]}
          python3 .github/scripts/mesh_baseline_runner_health.py --interval-end
      - name: Collect DNS E2E baselines (3+ repetitions)
        run: |
          python3 .github/scripts/mesh_baseline_runner_health.py --interval-begin
          set +e
          export MESH_BASELINE_DIAG_DIR=mesh-baseline-results/logs/dns/run_1
          ./tests/performance/mesh-dns-e2e/run.sh --duration 60 --concurrency 100
          harness_status=${PIPESTATUS[0]}
          python3 .github/scripts/mesh_baseline_runner_health.py --interval-end
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
    _self_test_hbone_backend_allow_ips(failures)
    # Intentionally skip docs checks in self-test.
    if failures:
        print("self-test failures:", *failures, sep="\n- ")
        return 1
    print("verify_mesh_performance_baselines_workflow self-test passed")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return self_test()

    failures: list[str] = []
    text = WORKFLOW_PATH.read_text(encoding="utf-8")
    check_workflow(text, failures)
    check_scripts(failures)
    check_docs_and_baselines(failures)
    check_pr_ci_wiring(failures)
    if failures:
        for failure in failures:
            print(f"::error::{failure}")
        return 1
    print("Mesh performance baselines workflow contract OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
