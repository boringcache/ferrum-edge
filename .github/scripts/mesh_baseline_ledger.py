#!/usr/bin/env python3
"""Write the mesh baseline suite-command ledger (#3332).

Pure inspection and JSON emission: validates the selected suite filter and the
E2E repetition count, then records the exact commands the collection workflow
will run. Dispatches no processes and mutates no repository sources.

This lives in an approved automation root instead of an inline workflow heredoc
so the collection workflow keeps a literal, reviewable command surface.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

SUPPORTED_SUITES = ("all", "mesh", "hbone", "dns")
MIN_ITERATIONS = 3
MAX_ITERATIONS = 5
MESH_BENCHES = ("authz_match", "ip_restriction", "slice_apply", "xds_translation")
HBONE_SCENARIOS = (
    {"key": "1kib_c50_30s", "payload": 1024, "concurrency": 50, "duration": 30},
    {"key": "16kib_c50_30s", "payload": 16384, "concurrency": 50, "duration": 30},
    {"key": "256kib_c100_60s", "payload": 262144, "concurrency": 100, "duration": 60},
)
DNS_DURATION_SECS = 60
DNS_CONCURRENCY = 100


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suites", required=True)
    parser.add_argument("--iterations", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def validated_suites(value: str) -> str:
    suites = value.strip()
    if suites not in SUPPORTED_SUITES:
        raise SystemExit(
            f"::error::unsupported suites value '{suites}' "
            "(expected all|mesh|hbone|dns)"
        )
    return suites


def validated_iterations(value: str) -> int:
    message = "BENCH_ITERATIONS must be an integer from 3 to 5"
    try:
        iterations = int(value.strip())
    except ValueError as exc:
        raise SystemExit(f"::error::{message} (got {value!r})") from exc
    if not MIN_ITERATIONS <= iterations <= MAX_ITERATIONS:
        raise SystemExit(f"::error::{message} (got {iterations})")
    return iterations


def build_ledger(suites: str, iterations: int) -> list[dict[str, object]]:
    commands: list[dict[str, object]] = []
    if suites in ("all", "mesh"):
        for bench in MESH_BENCHES:
            commands.append(
                {
                    "suite": "mesh",
                    "command": (
                        "cargo bench --manifest-path "
                        "tests/performance/mesh/Cargo.toml "
                        f"--bench {bench} -- --warm-up-time 3 --measurement-time 15"
                    ),
                }
            )
    if suites in ("all", "hbone"):
        commands.append(
            {
                "suite": "hbone",
                "command": (
                    "cargo build --release --bin ferrum-edge && "
                    "(cd tests/performance/mesh-hbone-e2e && cargo build --release)"
                ),
            }
        )
        for scenario in HBONE_SCENARIOS:
            for run in range(1, iterations + 1):
                commands.append(
                    {
                        "suite": "hbone",
                        "scenario": scenario["key"],
                        "repetition": run,
                        "command": (
                            "./run.sh --skip-build --json "
                            f"--duration {scenario['duration']} "
                            f"--concurrency {scenario['concurrency']} "
                            f"--payload-size {scenario['payload']}"
                        ),
                    }
                )
    if suites in ("all", "dns"):
        commands.append(
            {
                "suite": "dns",
                "command": (
                    "cargo build --release --bin ferrum-edge && "
                    "(cd tests/performance/mesh-dns-e2e && cargo build --release)"
                ),
            }
        )
        for run in range(1, iterations + 1):
            commands.append(
                {
                    "suite": "dns",
                    "repetition": run,
                    "command": (
                        "./run.sh --skip-build --json "
                        f"--duration {DNS_DURATION_SECS} "
                        f"--concurrency {DNS_CONCURRENCY} --protocol both"
                    ),
                }
            )
    return commands


def main() -> int:
    args = parse_args()
    suites = validated_suites(args.suites)
    iterations = validated_iterations(args.iterations)
    commands = build_ledger(suites, iterations)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(commands, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {len(commands)} ledger entries for suites={suites} to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
