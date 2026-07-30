#!/usr/bin/env python3
"""Fail CI when RoundRobin selection reintroduces single-line counter contention.

Criterion fixture contract (see tests/performance/mesh/benches/rr_selection.rs):
  - Each measured custom iteration runs ITERATIONS_PER_THREAD selections per
    worker thread (currently 50_000).
  - The gated comparison uses PARALLEL_THREADS workers for both:
      * `sharded`: production LoadBalancer::select RoundRobin
      * `shared`: deliberately contended bare AtomicU64 + the same 2-target
        Arc clone traffic
  - Multi-thread samples reuse a long-lived barrier-synchronized worker pool;
    Criterion's mean is the wall time from barrier release until every worker
    completes the selection loop, not thread spawn/join overhead.
  - Criterion's mean point estimate is elapsed wall-clock nanoseconds for that
    whole custom iteration (not ns/selection).
  - A diagnostic 1-thread sharded sample is recorded for logs only.

Contended advantage (same-run, equal element counts):

  advantage = shared_wall_ns / sharded_wall_ns

A production path that has regressed to one shared `AtomicU64` collapses this
toward 1.0x (sharded ≈ shared). Healthy CachePadded sharding keeps the shared
control slower under the same Arc/scheduler load, clearing the hosted floor.
Absolute 1-thread vs N-thread speedup is intentionally not gated: hosted
runners and 2-target Arc refcount concentration made that ratio swing from
~1.50x to 0.44x without an RR code change.
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path


TARGET_COUNT = 2
PARALLEL_THREADS = 4
HOSTED_CONTENTION_FLOOR = 1.10
# Must match tests/performance/mesh/benches/rr_selection.rs
ITERATIONS_PER_THREAD = 50_000


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Verify hosted RoundRobin selection Criterion results. "
            "Gates same-run shared-AtomicU64 control wall time over production "
            "sharded RoundRobin wall time under identical worker counts."
        )
    )
    parser.add_argument("--criterion-root", type=Path, required=False)
    parser.add_argument(
        "--min-contended-advantage",
        type=float,
        required=False,
        help=(
            "Minimum (shared_wall_ns / sharded_wall_ns) required to pass. "
            "Both walls cover the same "
            f"{PARALLEL_THREADS} * {ITERATIONS_PER_THREAD} selections."
        ),
    )
    # Back-compat alias used by older workflow snippets.
    parser.add_argument(
        "--min-parallel-speedup",
        type=float,
        required=False,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run synthetic unit checks for the advantage formula and exit.",
    )
    return parser.parse_args()


def contended_advantage(sharded_ns: float, shared_ns: float) -> float:
    """Return shared/sharded wall ratio for equal-work same-run samples."""
    if sharded_ns <= 0 or shared_ns <= 0:
        raise ValueError(
            f"invalid timing inputs sharded_ns={sharded_ns} shared_ns={shared_ns}"
        )
    return shared_ns / sharded_ns


def mean_point_estimate(criterion_root: Path, label: str) -> float:
    estimates_path = (
        criterion_root / "rr_selection" / label / "new" / "estimates.json"
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

    got = contended_advantage(100.0, 100.0)
    if not math.isclose(got, 1.0):
        failures.append(f"identical walls expected 1.0 advantage, got {got}")

    got = contended_advantage(100.0, 200.0)
    if not math.isclose(got, 2.0):
        failures.append(f"shared twice as slow expected 2.0, got {got}")

    # Naive parallel/serial wall ratio must NOT be the gate: equal walls under
    # N× work look like perfect scaling, which is the opposite of this check.
    if math.isclose(contended_advantage(100.0, 100.0), float(PARALLEL_THREADS)):
        failures.append("contended advantage must not equal parallel thread count")

    if contended_advantage(100.0, 100.0) >= HOSTED_CONTENTION_FLOOR:
        failures.append(
            f"regressed shared≈sharded 1.0x must stay below the "
            f"{HOSTED_CONTENTION_FLOOR:.2f} hosted floor"
        )
    if contended_advantage(100.0, 200.0) < HOSTED_CONTENTION_FLOOR:
        failures.append(
            f"2.0x shared/sharded advantage must clear the "
            f"{HOSTED_CONTENTION_FLOOR:.2f} hosted floor"
        )

    # Absolute 1-vs-N collapse must not be sufficient to fail by itself once
    # the same-run control still shows sharding wins.
    absolute_collapse = (PARALLEL_THREADS * 100.0) / 900.0  # ~0.44x style
    if absolute_collapse >= HOSTED_CONTENTION_FLOOR:
        failures.append("synthetic absolute collapse fixture must stay below 1.10")
    if contended_advantage(100.0, 150.0) < HOSTED_CONTENTION_FLOOR:
        failures.append(
            "same-run 1.50x shared/sharded advantage must still clear the floor "
            "even when absolute 1-vs-N speedup would look collapsed"
        )

    if failures:
        for failure in failures:
            print(f"::error::self-test: {failure}")
        return 1

    print(
        "RR verifier self-test passed "
        f"(contended advantage = shared_wall_ns / sharded_wall_ns; "
        f"{PARALLEL_THREADS}-thread same-run control)."
    )
    return 0


def main() -> int:
    args = parse_args()
    if args.self_test:
        return self_test()

    min_advantage = args.min_contended_advantage
    if min_advantage is None:
        min_advantage = args.min_parallel_speedup
    if args.criterion_root is None or min_advantage is None:
        print(
            "::error::--criterion-root and --min-contended-advantage "
            "are required unless --self-test"
        )
        return 2

    failures: list[str] = []

    if min_advantage <= 1:
        failures.append("--min-contended-advantage must be greater than 1")

    sharded_label = f"{TARGET_COUNT}_targets_sharded_{PARALLEL_THREADS}_threads"
    shared_label = f"{TARGET_COUNT}_targets_shared_{PARALLEL_THREADS}_threads"
    serial_label = f"{TARGET_COUNT}_targets_sharded_1_threads"

    try:
        sharded_ns = mean_point_estimate(args.criterion_root, sharded_label)
        shared_ns = mean_point_estimate(args.criterion_root, shared_label)
        advantage = contended_advantage(sharded_ns, shared_ns)
    except ValueError as error:
        failures.append(str(error))
        advantage = None
        sharded_ns = shared_ns = 0.0

    if advantage is not None:
        elements = ITERATIONS_PER_THREAD * PARALLEL_THREADS
        print(
            f"{TARGET_COUNT}_targets: "
            f"sharded_{PARALLEL_THREADS}_threads wall={sharded_ns:.2f} ns / {elements} selections, "
            f"shared_{PARALLEL_THREADS}_threads wall={shared_ns:.2f} ns / {elements} selections, "
            f"contended_advantage={advantage:.2f}x (= shared_wall / sharded_wall), "
            f"gate=required"
        )
        if advantage < min_advantage:
            failures.append(
                f"{TARGET_COUNT}_targets contended advantage {advantage:.2f}x "
                f"below floor {min_advantage:.2f}x "
                "(shared AtomicU64 control should remain slower than sharded RR "
                "under the same Arc/scheduler load; collapse near 1.0x means the "
                "production path is again bouncing one counter line)"
            )

        # Diagnostic absolute speedup for log continuity; never gated.
        try:
            serial_ns = mean_point_estimate(args.criterion_root, serial_label)
            absolute = (PARALLEL_THREADS * serial_ns) / sharded_ns
            print(
                f"{TARGET_COUNT}_targets diagnostic: "
                f"1_thread wall={serial_ns:.2f} ns / {ITERATIONS_PER_THREAD} selections, "
                f"absolute_throughput_speedup={absolute:.2f}x "
                f"(= {PARALLEL_THREADS} * serial_wall / sharded_parallel_wall), "
                f"gate=diagnostic-only"
            )
        except ValueError as error:
            print(f"::warning::diagnostic serial sample unavailable: {error}")

    if failures:
        for failure in failures:
            print(f"::error::{failure}")
        return 1

    print(
        "RR selection benchmark is within hosted contention guardrails "
        f"(same-run shared AtomicU64 control vs sharded RR at {PARALLEL_THREADS} "
        "threads; absolute 1-thread/N-thread speedup is diagnostic-only)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
