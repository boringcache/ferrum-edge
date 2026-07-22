#!/usr/bin/env python3
"""Fail CI when WRR selection reintroduces single-lane serialization."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path


TARGET_COUNTS = (4, 32, 129)
PARALLEL_THREADS = 4


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--criterion-root", type=Path, required=True)
    parser.add_argument(
        "--min-parallel-speedup",
        type=float,
        required=True,
        help="Minimum (4-thread rate / 1-thread rate) required to pass.",
    )
    return parser.parse_args()


def mean_point_estimate(criterion_root: Path, targets: int, threads: int) -> float:
    estimates_path = (
        criterion_root
        / "wrr_selection"
        / f"{targets}_targets_{threads}_threads"
        / "new"
        / "estimates.json"
    )
    try:
        estimates = json.loads(estimates_path.read_text(encoding="utf-8"))
        point_estimate = float(estimates["mean"]["point_estimate"])
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read Criterion mean from {estimates_path}: {error}") from error

    if not math.isfinite(point_estimate) or point_estimate <= 0:
        raise ValueError(
            f"Criterion mean in {estimates_path} must be finite and positive, got {point_estimate}"
        )
    return point_estimate


def main() -> int:
    args = parse_args()
    failures: list[str] = []

    if args.min_parallel_speedup <= 1:
        failures.append("--min-parallel-speedup must be greater than 1")

    for targets in TARGET_COUNTS:
        try:
            serial_ns = mean_point_estimate(args.criterion_root, targets, 1)
            parallel_ns = mean_point_estimate(args.criterion_root, targets, PARALLEL_THREADS)
        except ValueError as error:
            failures.append(str(error))
            continue

        # Criterion reports wall time for the custom iteration. Throughput is
        # proportional to 1/time for a fixed element count; speedup is serial/parallel.
        speedup = serial_ns / parallel_ns
        print(
            f"{targets}_targets: "
            f"1_thread={serial_ns:.2f} ns, "
            f"{PARALLEL_THREADS}_threads={parallel_ns:.2f} ns, "
            f"speedup={speedup:.2f}x"
        )
        if speedup < args.min_parallel_speedup:
            failures.append(
                f"{targets}_targets parallel speedup {speedup:.2f}x "
                f"below floor {args.min_parallel_speedup:.2f}x "
                "(single-lane mutex serialization typically collapses near 1.0x)"
            )

    if failures:
        for failure in failures:
            print(f"::error::{failure}")
        return 1

    print("WRR selection benchmark is within hosted contention guardrails.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
