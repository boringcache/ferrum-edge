#!/usr/bin/env python3
"""Fail CI when WRR selection reintroduces single-lane serialization.

Criterion fixture contract (see tests/performance/mesh/benches/wrr_selection.rs):
  - Each measured custom iteration runs ITERATIONS_PER_THREAD selections per
    worker thread (currently 50_000).
  - The 1-thread case therefore performs 50_000 selections per iteration.
  - The 4-thread case performs 4 * 50_000 selections per iteration.
  - Multi-thread samples reuse a long-lived barrier-synchronized worker pool;
    Criterion's mean is the wall time from barrier release until every worker
    completes the selection loop, not thread spawn/join overhead.
  - Criterion's mean point estimate is elapsed wall-clock nanoseconds for that
    whole custom iteration (not ns/selection).

Throughput speedup is therefore:

  speedup = (PARALLEL_THREADS * serial_ns) / parallel_ns

because rates are (elements / wall_ns) and the parallel iteration does
PARALLEL_THREADS times more work. A single-lane mutex collapses this toward
1.0x; healthy wait-free scaling sits well above the hosted floor.

The 4-target fixture remains recorded but is diagnostic-only. At that
cardinality four workers repeatedly clone/drop the same small set of returned
target Arcs, so cache-line placement and hosted CPU topology can make its
parallel throughput range from above the floor to below serial throughput even
though the WRR selection state itself is unchanged and wait-free. The
32-target fixture gates the same <=128-target bitset path with enough returned
targets to avoid that refcount hotspot; 129 targets independently gates the
Vec-fallback path. A single-lane WRR mutex collapses both gated fixtures.
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path


TARGET_COUNTS = (4, 32, 129)
DIAGNOSTIC_TARGET_COUNTS = frozenset((4,))
GATED_TARGET_COUNTS = frozenset((32, 129))
PARALLEL_THREADS = 4
HOSTED_CONTENTION_FLOOR = 1.10
# Must match tests/performance/mesh/benches/wrr_selection.rs
ITERATIONS_PER_THREAD = 50_000


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Verify hosted WRR selection Criterion results. "
            "Speedup units: parallel_throughput / serial_throughput, where "
            f"each custom iteration wall time covers "
            f"{ITERATIONS_PER_THREAD} selections per thread."
        )
    )
    parser.add_argument("--criterion-root", type=Path, required=False)
    parser.add_argument(
        "--min-parallel-speedup",
        type=float,
        required=False,
        help=(
            "Minimum (4-thread throughput / 1-thread throughput) required to "
            "pass. Throughput normalizes Criterion wall time by element count "
            f"({PARALLEL_THREADS} * serial_ns / parallel_ns)."
        ),
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run synthetic unit checks for the speedup formula and exit.",
    )
    return parser.parse_args()


def throughput_speedup(serial_ns: float, parallel_ns: float, parallel_threads: int) -> float:
    """Return parallel/serial selection throughput from Criterion wall times.

    `serial_ns` / `parallel_ns` are mean wall-clock durations for one custom
    iteration. The parallel iteration performs `parallel_threads` times as many
    selections as the serial iteration when each thread runs the same element
    count.
    """
    if serial_ns <= 0 or parallel_ns <= 0 or parallel_threads < 1:
        raise ValueError(
            f"invalid timing inputs serial_ns={serial_ns} parallel_ns={parallel_ns} "
            f"parallel_threads={parallel_threads}"
        )
    return (parallel_threads * serial_ns) / parallel_ns


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


def self_test() -> int:
    failures: list[str] = []

    # Equal wall time + N× work ⇒ N× throughput.
    got = throughput_speedup(100.0, 100.0, PARALLEL_THREADS)
    if not math.isclose(got, float(PARALLEL_THREADS)):
        failures.append(f"perfect scaling expected {PARALLEL_THREADS}.0, got {got}")

    # Fully serialized: N× work takes N× wall time ⇒ ~1.0× throughput.
    got = throughput_speedup(100.0, 100.0 * PARALLEL_THREADS, PARALLEL_THREADS)
    if not math.isclose(got, 1.0):
        failures.append(f"serialized path expected 1.0, got {got}")

    # Naive serial_ns/parallel_ns must NOT be used: perfect scaling would look
    # like 1.0× and fail to distinguish from a mutex.
    naive = 100.0 / 100.0
    correct = throughput_speedup(100.0, 100.0, PARALLEL_THREADS)
    if math.isclose(naive, correct):
        failures.append("naive wall-ratio must differ from throughput speedup under equal wall time")

    # Floor gate: serialized 1.0 fails; modest parallel clears the hosted
    # threshold. Production selection necessarily shares target Arc refcounts,
    # so the guard is intentionally just above serialization rather than an
    # assumption of near-linear four-core scaling on variable hosted runners.
    if throughput_speedup(100.0, 400.0, 4) >= HOSTED_CONTENTION_FLOOR:
        failures.append(
            f"serialized 1.0x must stay below the {HOSTED_CONTENTION_FLOOR:.2f} hosted floor"
        )
    if throughput_speedup(100.0, 200.0, 4) < HOSTED_CONTENTION_FLOOR:
        failures.append(
            f"2.0x throughput must clear the {HOSTED_CONTENTION_FLOOR:.2f} hosted floor"
        )

    if DIAGNOSTIC_TARGET_COUNTS & GATED_TARGET_COUNTS:
        failures.append("diagnostic and gated target cardinalities must be disjoint")
    if (DIAGNOSTIC_TARGET_COUNTS | GATED_TARGET_COUNTS) != frozenset(TARGET_COUNTS):
        failures.append("every measured target cardinality must be diagnostic or gated")

    if failures:
        for failure in failures:
            print(f"::error::self-test: {failure}")
        return 1

    print(
        "WRR verifier self-test passed "
        f"(throughput speedup = {PARALLEL_THREADS} * serial_wall_ns / parallel_wall_ns)."
    )
    return 0


def main() -> int:
    args = parse_args()
    if args.self_test:
        return self_test()

    if args.criterion_root is None or args.min_parallel_speedup is None:
        print("::error::--criterion-root and --min-parallel-speedup are required unless --self-test")
        return 2

    failures: list[str] = []

    if args.min_parallel_speedup <= 1:
        failures.append("--min-parallel-speedup must be greater than 1")

    for targets in TARGET_COUNTS:
        try:
            serial_ns = mean_point_estimate(args.criterion_root, targets, 1)
            parallel_ns = mean_point_estimate(args.criterion_root, targets, PARALLEL_THREADS)
            speedup = throughput_speedup(serial_ns, parallel_ns, PARALLEL_THREADS)
        except ValueError as error:
            failures.append(str(error))
            continue

        serial_elements = ITERATIONS_PER_THREAD
        parallel_elements = ITERATIONS_PER_THREAD * PARALLEL_THREADS
        print(
            f"{targets}_targets: "
            f"1_thread wall={serial_ns:.2f} ns / {serial_elements} selections, "
            f"{PARALLEL_THREADS}_threads wall={parallel_ns:.2f} ns / {parallel_elements} selections, "
            f"throughput_speedup={speedup:.2f}x "
            f"(= {PARALLEL_THREADS} * serial_wall / parallel_wall), "
            f"gate={'required' if targets in GATED_TARGET_COUNTS else 'diagnostic-only'}"
        )
        if targets in GATED_TARGET_COUNTS and speedup < args.min_parallel_speedup:
            failures.append(
                f"{targets}_targets throughput speedup {speedup:.2f}x "
                f"below floor {args.min_parallel_speedup:.2f}x "
                "(single-lane mutex serialization typically collapses near 1.0x)"
            )

    if failures:
        for failure in failures:
            print(f"::error::{failure}")
        return 1

    print(
        "WRR selection benchmark is within hosted contention guardrails "
        "(32-target bitset and 129-target Vec paths are gated; "
        "the Arc-refcount-concentrated 4-target fixture is diagnostic-only)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
