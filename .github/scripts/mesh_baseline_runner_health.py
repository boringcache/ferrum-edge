#!/usr/bin/env python3
"""Capture machine-readable CPU-steal evidence for mesh baseline collection.

Samples `vmstat` with a fixed literal argument vector, averages the steal
column, and records either the pre-collection `runner_health.json` snapshot or
one per-repetition line in `logs/runner_health_probes.jsonl`. Steal above the
documented threshold is a warning here; the summarizer's publication gate is
what fails closed on it.

This lives in an approved automation root instead of an inline workflow heredoc
so the collection workflow keeps a literal, reviewable command surface.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path

DEFAULT_THRESHOLD_PERCENT = 5.0
STEAL_COLUMN = "st"
# procs/memory/swap/io/system/cpu layout: `st` is the 17th field on every
# vmstat release Ferrum targets. Used only when the header cannot be read.
STEAL_COLUMN_FALLBACK_INDEX = 16
PRE_COLLECTION_SAMPLES_KEPT = 5
PROBE_SAMPLES_KEPT = 2


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-root", type=Path, required=True)
    parser.add_argument(
        "--phase",
        required=True,
        choices=("pre_collection", "hbone", "dns"),
    )
    parser.add_argument("--scenario", default="")
    parser.add_argument("--repetition", type=int, default=None)
    args = parser.parse_args()
    if args.phase in ("hbone", "dns"):
        if args.repetition is None or args.repetition < 1:
            parser.error("--repetition must be a positive integer for E2E probes")
        if args.phase == "hbone" and not args.scenario:
            parser.error("--scenario is required for HBONE probes")
    return args


def sample_vmstat(phase: str) -> str:
    """Return raw vmstat output. Both argument vectors are literal by policy."""

    if phase == "pre_collection":
        completed = subprocess.run(
            ["vmstat", "1", "6"],
            check=True,
            capture_output=True,
            text=True,
        )
        return completed.stdout
    completed = subprocess.run(
        ["vmstat", "1", "3"],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout


def steal_column_index(lines: list[str]) -> int:
    for line in lines[:2]:
        fields = line.split()
        if STEAL_COLUMN in fields:
            return fields.index(STEAL_COLUMN)
    return STEAL_COLUMN_FALLBACK_INDEX


def data_rows(lines: list[str]) -> list[list[str]]:
    rows: list[list[str]] = []
    for line in lines:
        fields = line.split()
        if not fields:
            continue
        if not fields[0].lstrip("-").isdigit():
            continue
        rows.append(fields)
    return rows


def average_steal_percent(output: str, kept: int) -> float:
    lines = output.splitlines()
    index = steal_column_index(lines)
    rows = data_rows(lines)
    # The first sample is a since-boot average, so the retained window is the
    # tail exactly as the previous `tail -n <kept>` shell pipeline took it.
    retained = rows[-kept:] if kept else rows
    values: list[float] = []
    for row in retained:
        if index >= len(row):
            continue
        try:
            values.append(float(row[index]))
        except ValueError:
            continue
    if not values:
        return 0.0
    return float(f"{sum(values) / len(values):.1f}")


def threshold_percent() -> float:
    raw = os.environ.get("BENCH_MAX_CPU_STEAL_PERCENT", "")
    try:
        return float(raw)
    except ValueError:
        return DEFAULT_THRESHOLD_PERCENT


def write_pre_collection(
    results_root: Path,
    output: str,
    steal: float,
    threshold: float,
) -> dict[str, object]:
    logs_dir = results_root / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    (logs_dir / "vmstat_pre.txt").write_text(output, encoding="utf-8")
    health = {
        "runner_class": os.environ.get("BENCH_RUNNER_CLASS", "ubuntu-24.04"),
        "build_profile": os.environ.get("BENCH_BUILD_PROFILE", "release"),
        "commit_sha": os.environ.get("GITHUB_SHA"),
        "avg_steal_percent": steal,
        "threshold_percent": threshold,
        "nproc": os.cpu_count(),
        "phase": "pre_collection",
    }
    (results_root / "runner_health.json").write_text(
        json.dumps(health, indent=2) + "\n",
        encoding="utf-8",
    )
    (logs_dir / "runner_health.log").write_text(
        "\n".join(
            (
                "==========================================",
                "  RUNNER HEALTH - MESH BASELINE COLLECTION",
                "==========================================",
                f"runner_class={health['runner_class']}",
                f"build_profile={health['build_profile']}",
                f"max_cpu_steal_percent={threshold}",
                f"commit={health['commit_sha']}",
                "",
                output.rstrip(),
                "",
                f"Average CPU steal over {PRE_COLLECTION_SAMPLES_KEPT}s: {steal}%",
                json.dumps(health, indent=2),
            )
        )
        + "\n",
        encoding="utf-8",
    )
    return health


def write_probe(
    results_root: Path,
    phase: str,
    scenario: str,
    repetition: int,
    steal: float,
    threshold: float,
) -> dict[str, object]:
    probe: dict[str, object] = {
        "phase": phase,
        "repetition": repetition,
        "avg_steal_percent": steal,
        "threshold_percent": threshold,
    }
    if phase == "hbone":
        probe["scenario"] = scenario
    logs_dir = results_root / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    probes_path = logs_dir / "runner_health_probes.jsonl"
    with probes_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(probe) + "\n")
    return probe


def main() -> int:
    args = parse_args()
    threshold = threshold_percent()
    output = sample_vmstat(args.phase)
    if args.phase == "pre_collection":
        steal = average_steal_percent(output, PRE_COLLECTION_SAMPLES_KEPT)
        record = write_pre_collection(args.results_root, output, steal, threshold)
        label = "pre-collection"
    else:
        steal = average_steal_percent(output, PROBE_SAMPLES_KEPT)
        record = write_probe(
            args.results_root,
            args.phase,
            args.scenario,
            args.repetition,
            steal,
            threshold,
        )
        label = f"{args.phase} {args.scenario} run {args.repetition}".replace("  ", " ")
    print(json.dumps(record, indent=2))
    if steal > threshold:
        print(
            f"::warning::{label}: CPU steal {steal}% (> {threshold}%) "
            "— publication gate will fail closed"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
