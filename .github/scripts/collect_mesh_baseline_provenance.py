#!/usr/bin/env python3
"""Capture runner/toolchain provenance for mesh performance baseline collection.

Pure inspection: reads environment and host facts, writes JSON. Does not build,
bench, or mutate repository sources.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def run_capture(command: list[str]) -> str:
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return f"<unavailable: {error}>"
    if completed.returncode != 0:
        stderr = (completed.stderr or "").strip()
        return f"<failed rc={completed.returncode}: {stderr[:200]}>"
    return (completed.stdout or "").strip()


def first_matching_line(text: str, needle: str) -> str | None:
    for line in text.splitlines():
        if needle.lower() in line.lower():
            return line.strip()
    return None


def parse_meminfo_kib(meminfo: str, key: str) -> int | None:
    prefix = f"{key}:"
    for line in meminfo.splitlines():
        if line.startswith(prefix):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                return int(parts[1])
    return None


def cargo_pkg_version(manifest: Path, package: str) -> str | None:
    if not manifest.is_file():
        return None
    text = manifest.read_text(encoding="utf-8")
    # Prefer lockfile identity when present; fall back to Cargo.toml pin.
    lock = manifest.with_name("Cargo.lock")
    if lock.is_file():
        lock_text = lock.read_text(encoding="utf-8")
        marker = f'name = "{package}"'
        idx = lock_text.find(marker)
        if idx != -1:
            window = lock_text[idx : idx + 200]
            for line in window.splitlines():
                if line.startswith("version = "):
                    return line.split("=", 1)[1].strip().strip('"')
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith(f"{package} ") or stripped.startswith(f"{package}="):
            # criterion = { version = "0.5", ... }
            if "version" in stripped:
                start = stripped.find('"')
                end = stripped.find('"', start + 1) if start != -1 else -1
                if start != -1 and end != -1:
                    return stripped[start + 1 : end]
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--suite-commands",
        type=Path,
        help="Optional JSON file listing exact suite commands that will run",
    )
    args = parser.parse_args()

    lscpu = run_capture(["lscpu"])
    uname_a = run_capture(["uname", "-a"])
    free_h = run_capture(["free", "-h"])
    meminfo = run_capture(["cat", "/proc/meminfo"])
    rustc_v = run_capture(["rustc", "--version", "--verbose"])
    cargo_v = run_capture(["cargo", "--version", "--verbose"])
    nproc = run_capture(["nproc"])

    mem_total_kib = parse_meminfo_kib(meminfo, "MemTotal")
    suite_commands = []
    if args.suite_commands and args.suite_commands.is_file():
        suite_commands = json.loads(args.suite_commands.read_text(encoding="utf-8"))

    repo_root = Path(__file__).resolve().parents[2]
    mesh_manifest = repo_root / "tests" / "performance" / "mesh" / "Cargo.toml"
    hbone_manifest = repo_root / "tests" / "performance" / "mesh-hbone-e2e" / "Cargo.toml"
    dns_manifest = repo_root / "tests" / "performance" / "mesh-dns-e2e" / "Cargo.toml"

    provenance = {
        "schema_version": 1,
        "collected_at_utc": datetime.now(timezone.utc).isoformat(),
        "commit_sha": os.environ.get("GITHUB_SHA") or run_capture(["git", "rev-parse", "HEAD"]),
        "github": {
            "run_id": os.environ.get("GITHUB_RUN_ID"),
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
            "workflow": os.environ.get("GITHUB_WORKFLOW"),
            "job": os.environ.get("GITHUB_JOB"),
            "repository": os.environ.get("GITHUB_REPOSITORY"),
            "ref": os.environ.get("GITHUB_REF"),
            "server_url": os.environ.get("GITHUB_SERVER_URL", "https://github.com"),
        },
        "runner": {
            "class": os.environ.get("BENCH_RUNNER_CLASS", "ubuntu-24.04"),
            "name": os.environ.get("RUNNER_NAME"),
            "os": os.environ.get("RUNNER_OS") or platform.system(),
            "arch": os.environ.get("RUNNER_ARCH") or platform.machine(),
            "nproc": nproc,
            "cpu_model": first_matching_line(lscpu, "Model name"),
            "cpu_topology": {
                "cpus": first_matching_line(lscpu, "CPU(s):"),
                "threads_per_core": first_matching_line(lscpu, "Thread(s) per core"),
                "cores_per_socket": first_matching_line(lscpu, "Core(s) per socket"),
                "sockets": first_matching_line(lscpu, "Socket(s):"),
                "hypervisor": first_matching_line(lscpu, "Hypervisor"),
                "virtualization": first_matching_line(lscpu, "Virtualization"),
            },
            "lscpu_raw": lscpu,
            "ram": {
                "memtotal_kib": mem_total_kib,
                "memtotal_gib": round(mem_total_kib / (1024 * 1024), 2)
                if mem_total_kib
                else None,
                "free_h": free_h,
            },
            "uname": uname_a,
            "kernel": platform.release(),
            "platform": platform.platform(),
        },
        "toolchain": {
            "rustc_verbose": rustc_v,
            "cargo_verbose": cargo_v,
            "rust_toolchain_file": "rust-toolchain.toml channel=stable",
        },
        "build": {
            "gateway_profile": os.environ.get("BENCH_BUILD_PROFILE", "release"),
            "gateway_features": os.environ.get("BENCH_GATEWAY_FEATURES", "default (no --features)"),
            "harness_profile": "release",
            "non_default_settings_note": (
                "Suites use each harness run.sh defaults plus the documented "
                "baseline row parameters. Mesh DNS sets explicit FERRUM_MESH_DNS_* "
                "env vars inside tests/performance/mesh-dns-e2e/run.sh."
            ),
        },
        "dependency_harness_versions": {
            "mesh_criterion": cargo_pkg_version(mesh_manifest, "criterion"),
            "mesh_crate": "mesh-perf (tests/performance/mesh)",
            "hbone_crate": "mesh-hbone-e2e-perf (tests/performance/mesh-hbone-e2e)",
            "dns_crate": "mesh-dns-e2e-perf (tests/performance/mesh-dns-e2e)",
            "hdrhistogram_hbone": cargo_pkg_version(hbone_manifest, "hdrhistogram"),
            "hdrhistogram_dns": cargo_pkg_version(dns_manifest, "hdrhistogram"),
        },
        "warmup_and_repetitions": {
            "mesh_microbench": (
                "Criterion default warm-up plus configured --warm-up-time / "
                "--measurement-time flags recorded in suite_commands"
            ),
            "e2e_repetitions": int(os.environ.get("BENCH_ITERATIONS", "3")),
            "e2e_policy": (
                "At least three clean repetitions (configured count, never below "
                "three); discard/fail publication if any retained row has non-zero "
                "unexplained errors or if CPU steal exceeds 5.0%"
            ),
        },
        "suite_commands": suite_commands,
        "overhead_formula": {
            "hbone_rps_overhead_percent": (
                "((direct_rps - gateway_hbone_rps) / direct_rps) * 100"
            ),
            "dns_upstream_forward_overhead_percent": (
                "((direct_stub_qps - gateway_upstream_forward_qps) / direct_stub_qps) * 100"
            ),
            "notes": (
                "Overhead is throughput loss versus the same-run direct path. "
                "Latency deltas are reported separately and are not folded into "
                "the overhead percent column."
            ),
        },
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote provenance to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
