#!/usr/bin/env python3
"""Fail CI when RoundRobin selection reintroduces single-line counter contention.

Criterion fixture contract (see tests/performance/mesh/benches/rr_selection.rs):
  - Each measured custom iteration runs ITERATIONS_PER_THREAD selections per
    worker thread (currently 50_000).
  - The 1-thread case therefore performs 50_000 selections per iteration.
  - The 8-thread case performs 8 * 50_000 selections per iteration.
  - Multi-thread samples reuse a long-lived barrier-synchronized worker pool;
    Criterion's mean is the wall time from barrier release until every worker
    completes the selection loop, not thread spawn/join overhead.
  - Criterion's mean point estimate is elapsed wall-clock nanoseconds for that
    whole custom iteration (not ns/selection).

Throughput speedup is therefore:

  speedup = (PARALLEL_THREADS * serial_ns) / parallel_ns

A single shared `AtomicU64` on a 2-target RR upstream collapses this toward
1.0x (or below); sharded CachePadded counters clear the hosted floor.

Hosted runners can also collapse *independent* work below the floor when the
machine is oversubscribed (issue #4108). A genuine selection regression is
distinguished from that noise by an embarrassingly-parallel process-pool
control at the same thread count: if the control also misses the floor, the
selection miss is advisory. If the control clears the floor, the selection
miss is still a hard failure. The floor value itself is not lowered.
"""

from __future__ import annotations

import argparse
import json
import math
import statistics
import time
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path


TARGET_COUNT = 2
PARALLEL_THREADS = 8
HOSTED_CONTENTION_FLOOR = 1.10
# Must match tests/performance/mesh/benches/rr_selection.rs
ITERATIONS_PER_THREAD = 50_000
# Independent CPU control (issue #4108): median of N process-pool speedups.
CONTROL_REPEATS = 5
CONTROL_ITERS = 6_000_000


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Verify hosted RoundRobin selection Criterion results. "
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
            "Minimum (8-thread throughput / 1-thread throughput) required to "
            "pass. Throughput normalizes Criterion wall time by element count "
            f"({PARALLEL_THREADS} * serial_ns / parallel_ns). A miss is a hard "
            "failure only when an independent-process CPU control at the same "
            "thread count still clears this floor."
        ),
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run synthetic unit checks for the speedup formula and exit.",
    )
    return parser.parse_args()


def throughput_speedup(serial_ns: float, parallel_ns: float, parallel_threads: int) -> float:
    """Return parallel/serial selection throughput from Criterion wall times."""
    if serial_ns <= 0 or parallel_ns <= 0 or parallel_threads < 1:
        raise ValueError(
            f"invalid timing inputs serial_ns={serial_ns} parallel_ns={parallel_ns} "
            f"parallel_threads={parallel_threads}"
        )
    return (parallel_threads * serial_ns) / parallel_ns


def classify_parallel_floor(
    selection_speedup: float,
    control_speedup: float | None,
    min_parallel_speedup: float,
) -> str:
    """Classify a parallel-floor reading.

    Returns:
      pass — selection cleared the floor
      regression — selection missed and the control still scaled (or was
        unavailable: fail closed)
      runner_contention — both selection and the independent-work control
        missed, so the runner is oversubscribed and the reading is not a
        load-balancer signal
    """
    if selection_speedup >= min_parallel_speedup:
        return "pass"
    if control_speedup is None:
        return "regression"
    if control_speedup < min_parallel_speedup:
        return "runner_contention"
    return "regression"


def apply_runner_contention_guard(
    failures: list[str],
    control_speedup: float | None,
    min_parallel_speedup: float,
) -> tuple[list[str], list[str]]:
    """Demote parallel-floor failures when the independent-work control also missed."""
    notes: list[str] = []
    floor_failures = [
        item for item in failures if "throughput speedup" in item and "below floor" in item
    ]
    other = [item for item in failures if item not in floor_failures]
    if not floor_failures:
        return failures, notes
    if control_speedup is None:
        notes.append(
            "independent-work control unavailable; enforcing parallel floor (fail closed)"
        )
        return failures, notes
    notes.append(
        f"independent-work control throughput_speedup={control_speedup:.2f}x "
        f"(median of {CONTROL_REPEATS} repeats, {PARALLEL_THREADS} processes)"
    )
    if control_speedup < min_parallel_speedup:
        notes.append(
            f"::warning::runner oversubscription: control {control_speedup:.2f}x "
            f"is below floor {min_parallel_speedup:.2f}x; selection parallel-floor "
            "misses are advisory (no signal about src/load_balancer.rs)"
        )
        for item in floor_failures:
            notes.append(f"::warning::{item}")
        return other, notes
    return failures, notes


def _independent_cpu_work(iterations: int) -> int:
    acc = 0
    for i in range(iterations):
        acc = (acc + (i * 1_103_515_245) + 12_345) & 0x7FFFFFFF
    return acc


def measure_independent_speedup(parallel_threads: int) -> float:
    """Median throughput speedup of independent CPU work at `parallel_threads`."""
    speedups: list[float] = []
    with ProcessPoolExecutor(max_workers=parallel_threads) as pool:
        list(pool.map(_independent_cpu_work, [CONTROL_ITERS] * parallel_threads))
        for _ in range(CONTROL_REPEATS):
            started = time.perf_counter()
            _independent_cpu_work(CONTROL_ITERS)
            serial = time.perf_counter() - started
            started = time.perf_counter()
            list(pool.map(_independent_cpu_work, [CONTROL_ITERS] * parallel_threads))
            parallel = time.perf_counter() - started
            speedups.append(throughput_speedup(serial, parallel, parallel_threads))
    return statistics.median(speedups)


def mean_point_estimate(criterion_root: Path, targets: int, threads: int) -> float:
    estimates_path = (
        criterion_root
        / "rr_selection"
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

    got = throughput_speedup(100.0, 100.0, PARALLEL_THREADS)
    if not math.isclose(got, float(PARALLEL_THREADS)):
        failures.append(f"perfect scaling expected {PARALLEL_THREADS}.0, got {got}")

    got = throughput_speedup(100.0, 100.0 * PARALLEL_THREADS, PARALLEL_THREADS)
    if not math.isclose(got, 1.0):
        failures.append(f"serialized path expected 1.0, got {got}")

    naive = 100.0 / 100.0
    correct = throughput_speedup(100.0, 100.0, PARALLEL_THREADS)
    if math.isclose(naive, correct):
        failures.append("naive wall-ratio must differ from throughput speedup under equal wall time")

    if throughput_speedup(100.0, 800.0, 8) >= HOSTED_CONTENTION_FLOOR:
        failures.append(
            f"serialized 1.0x must stay below the {HOSTED_CONTENTION_FLOOR:.2f} hosted floor"
        )
    if throughput_speedup(100.0, 400.0, 8) < HOSTED_CONTENTION_FLOOR:
        failures.append(
            f"2.0x throughput must clear the {HOSTED_CONTENTION_FLOOR:.2f} hosted floor"
        )

    if classify_parallel_floor(2.0, 3.0, HOSTED_CONTENTION_FLOOR) != "pass":
        failures.append("healthy selection must pass regardless of control")
    if classify_parallel_floor(1.0, 3.0, HOSTED_CONTENTION_FLOOR) != "regression":
        failures.append("serialized 1.0x with a healthy control must be a regression")
    if classify_parallel_floor(0.48, 0.50, HOSTED_CONTENTION_FLOOR) != "runner_contention":
        failures.append(
            "0.48x selection with 0.50x control is runner contention, not a regression"
        )
    if classify_parallel_floor(0.48, None, HOSTED_CONTENTION_FLOOR) != "regression":
        failures.append("missing control must fail closed and enforce the floor")
    if statistics.median([0.4, 3.0, 3.2]) < HOSTED_CONTENTION_FLOOR:
        failures.append("median-of-N must not follow a single oversubscribed sample")

    hosted_noise = [
        f"{TARGET_COUNT}_targets throughput speedup 0.48x below floor "
        f"{HOSTED_CONTENTION_FLOOR:.2f}x "
        "(shared AtomicU64 cache-line bounce typically collapses near 1.0x)"
    ]
    demoted, notes = apply_runner_contention_guard(
        hosted_noise, control_speedup=0.50, min_parallel_speedup=HOSTED_CONTENTION_FLOOR
    )
    if demoted:
        failures.append("0.48x selection with 0.50x control must not remain a hard failure")
    if not any("runner oversubscription" in line for line in notes):
        failures.append("contention guard must emit an oversubscription warning")

    real_collapse = [
        f"{TARGET_COUNT}_targets throughput speedup 1.00x below floor "
        f"{HOSTED_CONTENTION_FLOOR:.2f}x "
        "(shared AtomicU64 cache-line bounce typically collapses near 1.0x)"
    ]
    kept, _ = apply_runner_contention_guard(
        real_collapse, control_speedup=3.0, min_parallel_speedup=HOSTED_CONTENTION_FLOOR
    )
    if kept != real_collapse:
        failures.append("serialized 1.0x with a 3.0x control must remain a hard failure")

    closed, closed_notes = apply_runner_contention_guard(
        real_collapse, control_speedup=None, min_parallel_speedup=HOSTED_CONTENTION_FLOOR
    )
    if closed != real_collapse:
        failures.append("unavailable control must fail closed and keep the floor failure")
    if not any("fail closed" in line for line in closed_notes):
        failures.append("unavailable control must be logged as fail closed")

    if failures:
        for failure in failures:
            print(f"::error::self-test: {failure}")
        return 1

    print(
        "RR verifier self-test passed "
        f"(throughput speedup = {PARALLEL_THREADS} * serial_wall_ns / parallel_wall_ns; "
        "parallel floor is hard only when an independent-work control still scales)."
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

    try:
        serial_ns = mean_point_estimate(args.criterion_root, TARGET_COUNT, 1)
        parallel_ns = mean_point_estimate(args.criterion_root, TARGET_COUNT, PARALLEL_THREADS)
        speedup = throughput_speedup(serial_ns, parallel_ns, PARALLEL_THREADS)
    except ValueError as error:
        failures.append(str(error))
        speedup = None
        serial_ns = parallel_ns = 0.0

    if speedup is not None:
        serial_elements = ITERATIONS_PER_THREAD
        parallel_elements = ITERATIONS_PER_THREAD * PARALLEL_THREADS
        print(
            f"{TARGET_COUNT}_targets: "
            f"1_thread wall={serial_ns:.2f} ns / {serial_elements} selections, "
            f"{PARALLEL_THREADS}_threads wall={parallel_ns:.2f} ns / {parallel_elements} selections, "
            f"throughput_speedup={speedup:.2f}x "
            f"(= {PARALLEL_THREADS} * serial_wall / parallel_wall)"
        )
        if speedup < args.min_parallel_speedup:
            failures.append(
                f"{TARGET_COUNT}_targets throughput speedup {speedup:.2f}x "
                f"below floor {args.min_parallel_speedup:.2f}x "
                "(shared AtomicU64 cache-line bounce typically collapses near 1.0x)"
            )

    if any("throughput speedup" in item and "below floor" in item for item in failures):
        try:
            control_speedup = measure_independent_speedup(PARALLEL_THREADS)
        except (OSError, RuntimeError, ValueError) as error:
            print(f"::warning::control measurement failed ({error}); enforcing floor")
            control_speedup = None
        failures, notes = apply_runner_contention_guard(
            failures, control_speedup, args.min_parallel_speedup
        )
        for line in notes:
            print(line)

    if failures:
        for failure in failures:
            print(f"::error::{failure}")
        return 1

    print(
        "RR selection benchmark is within hosted contention guardrails "
        "(throughput speedup normalizes Criterion wall time by element count; "
        "parallel floor is hard only when independent-work still scales)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
