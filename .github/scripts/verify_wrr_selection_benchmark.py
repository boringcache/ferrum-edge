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
  - Every fixture uses the intentional 5:1:…:1 weight skew from the bench.

Throughput speedup is therefore:

  speedup = (PARALLEL_THREADS * serial_ns) / parallel_ns

because rates are (elements / wall_ns) and the parallel iteration does
PARALLEL_THREADS times more work. A single-lane schedule mutex collapses this
toward 1.0x on fixtures where schedule work dominates output-Arc traffic.

Topology-aware gate (hosted evidence, run 31000740063):
  - 4 targets / 5:1:1:1 → heavy Arc share 5/8. Concurrent clone/drop of the
    same returned `Arc<UpstreamTarget>` produces cross-core strong-count
    bouncing that can push measured speedup *below* 1.0x (observed 0.80x)
    even on the wait-free sharded path. A mutex would sit near 1.0x, so a
    universal >1.10 floor is not a valid single-lane-mutex detector here.
  - 32 targets / 5:1:…:1 → heavy share 5/36. Observed 1.22x; mutex ~1.0x
    fails the hosted floor.
  - 129 targets → heavier per-pick work + heavy share 5/133. Observed 2.23x;
    mutex ~1.0x fails the hosted floor.

Therefore:
  - MANDATORY_SERIALIZATION_TARGETS (32, 129) must clear --min-parallel-speedup.
  - SMALL_CARDINALITY_SECONDARY_TARGETS (4) must still be measured and reported;
    parallel speedup is informational for Arc-hotspot regime, while the
    small-cardinality serial signal requires 4-target 1-thread wall time to
    stay within SMALL_CARDINALITY_SERIAL_RATIO_CEILING of the 32-target
    1-thread wall (same iteration count; hosted ratio ≈ 1.01).
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path


# Must match tests/performance/mesh/benches/wrr_selection.rs cardinalities.
TARGET_COUNTS = (4, 32, 129)
# Fixtures whose parallel speedup still discriminates a schedule Mutex.
MANDATORY_SERIALIZATION_TARGETS = (32, 129)
# Skewed small set: measured always; parallel speedup is secondary/informational.
SMALL_CARDINALITY_SECONDARY_TARGETS = (4,)
PARALLEL_THREADS = 4
HOSTED_CONTENTION_FLOOR = 1.10
# Must match tests/performance/mesh/benches/wrr_selection.rs
ITERATIONS_PER_THREAD = 50_000
# Bench weight for target 0; remaining targets use weight 1.
HEAVY_TARGET_WEIGHT = 5
# Hosted 4- vs 32-target 1-thread means were within ~1%; allow runner noise
# while still catching a small-cardinality path that blew up relative to 32.
SMALL_CARDINALITY_SERIAL_RATIO_CEILING = 2.0


def heavy_arc_share(target_count: int) -> float:
    """Long-run fraction of selections that clone the weight-5 target Arc."""
    if target_count < 1:
        raise ValueError(f"target_count must be >= 1, got {target_count}")
    total_weight = HEAVY_TARGET_WEIGHT + (target_count - 1)
    return HEAVY_TARGET_WEIGHT / total_weight


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Verify hosted WRR selection Criterion results. "
            "Speedup units: parallel_throughput / serial_throughput, where "
            f"each custom iteration wall time covers "
            f"{ITERATIONS_PER_THREAD} selections per thread. "
            f"Mandatory serialization floor applies to "
            f"{MANDATORY_SERIALIZATION_TARGETS}; "
            f"{SMALL_CARDINALITY_SECONDARY_TARGETS} stays measured with a "
            "secondary small-cardinality serial-ratio contract."
        )
    )
    parser.add_argument("--criterion-root", type=Path, required=False)
    parser.add_argument(
        "--min-parallel-speedup",
        type=float,
        required=False,
        help=(
            "Minimum (4-thread throughput / 1-thread throughput) required for "
            f"mandatory serialization fixtures {MANDATORY_SERIALIZATION_TARGETS}. "
            "Throughput normalizes Criterion wall time by element count "
            f"({PARALLEL_THREADS} * serial_ns / parallel_ns). "
            f"Does not gate informational parallel speedup on "
            f"{SMALL_CARDINALITY_SECONDARY_TARGETS} (Arc strong-count hotspot "
            "under 5:1:1:1 skew)."
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


def evaluate_results(
    timings: dict[int, tuple[float, float]],
    min_parallel_speedup: float,
) -> tuple[list[str], list[str]]:
    """Evaluate fixture timings against the topology-aware contract.

    `timings` maps target_count → (serial_ns, parallel_ns). Returns
    (failures, log_lines). Missing fixtures are failures. Parallel speedup
    below `min_parallel_speedup` fails only for MANDATORY_SERIALIZATION_TARGETS.
    """
    failures: list[str] = []
    logs: list[str] = []

    if min_parallel_speedup <= 1:
        failures.append("--min-parallel-speedup must be greater than 1")

    serial_by_targets: dict[int, float] = {}
    for targets in TARGET_COUNTS:
        if targets not in timings:
            failures.append(f"missing Criterion timings for {targets}_targets")
            continue
        serial_ns, parallel_ns = timings[targets]
        try:
            speedup = throughput_speedup(serial_ns, parallel_ns, PARALLEL_THREADS)
        except ValueError as error:
            failures.append(str(error))
            continue

        serial_by_targets[targets] = serial_ns
        serial_elements = ITERATIONS_PER_THREAD
        parallel_elements = ITERATIONS_PER_THREAD * PARALLEL_THREADS
        role = (
            "mandatory_serialization"
            if targets in MANDATORY_SERIALIZATION_TARGETS
            else "secondary_small_cardinality"
        )
        logs.append(
            f"{targets}_targets ({role}): "
            f"1_thread wall={serial_ns:.2f} ns / {serial_elements} selections, "
            f"{PARALLEL_THREADS}_threads wall={parallel_ns:.2f} ns / {parallel_elements} selections, "
            f"throughput_speedup={speedup:.2f}x "
            f"(= {PARALLEL_THREADS} * serial_wall / parallel_wall), "
            f"heavy_arc_share={heavy_arc_share(targets):.3f}"
        )

        if targets in MANDATORY_SERIALIZATION_TARGETS:
            if speedup < min_parallel_speedup:
                failures.append(
                    f"{targets}_targets throughput speedup {speedup:.2f}x "
                    f"below floor {min_parallel_speedup:.2f}x "
                    "(single-lane mutex serialization typically collapses near 1.0x)"
                )
        elif targets in SMALL_CARDINALITY_SECONDARY_TARGETS:
            logs.append(
                f"{targets}_targets parallel speedup is informational under "
                f"5:1:1:1 Arc strong-count hotspot (heavy_arc_share="
                f"{heavy_arc_share(targets):.3f}); mandatory mutex detection "
                f"uses {MANDATORY_SERIALIZATION_TARGETS}."
            )

    # Small-cardinality serial signal: 4-target 1-thread work must stay within
    # a bounded ratio of 32-target 1-thread (same element count). Hosted means
    # were nearly identical; a blown-up small path would inflate this ratio.
    if 4 in serial_by_targets and 32 in serial_by_targets:
        serial_ratio = serial_by_targets[4] / serial_by_targets[32]
        logs.append(
            f"4_targets/32_targets 1_thread serial_wall_ratio={serial_ratio:.2f}x "
            f"(ceiling {SMALL_CARDINALITY_SERIAL_RATIO_CEILING:.2f}x)"
        )
        if serial_ratio > SMALL_CARDINALITY_SERIAL_RATIO_CEILING:
            failures.append(
                f"4_targets 1_thread wall is {serial_ratio:.2f}x the 32_targets "
                f"1_thread wall (ceiling {SMALL_CARDINALITY_SERIAL_RATIO_CEILING:.2f}x); "
                "small-cardinality selection path regressed relative to mid-cardinality"
            )

    return failures, logs


def self_test() -> int:
    failures: list[str] = []

    if MANDATORY_SERIALIZATION_TARGETS != (32, 129):
        failures.append(
            f"MANDATORY_SERIALIZATION_TARGETS must be (32, 129), got "
            f"{MANDATORY_SERIALIZATION_TARGETS}"
        )
    if SMALL_CARDINALITY_SECONDARY_TARGETS != (4,):
        failures.append(
            f"SMALL_CARDINALITY_SECONDARY_TARGETS must be (4,), got "
            f"{SMALL_CARDINALITY_SECONDARY_TARGETS}"
        )
    if set(MANDATORY_SERIALIZATION_TARGETS) | set(SMALL_CARDINALITY_SECONDARY_TARGETS) != set(
        TARGET_COUNTS
    ):
        failures.append("secondary + mandatory fixtures must cover TARGET_COUNTS exactly")
    if 4 in MANDATORY_SERIALIZATION_TARGETS:
        failures.append("4_targets must not use the universal serialization floor")

    # Topology math behind the split gate.
    if not math.isclose(heavy_arc_share(4), 5.0 / 8.0):
        failures.append(f"4-target heavy Arc share expected 0.625, got {heavy_arc_share(4)}")
    if not math.isclose(heavy_arc_share(32), 5.0 / 36.0):
        failures.append(f"32-target heavy Arc share expected 5/36, got {heavy_arc_share(32)}")
    if not math.isclose(heavy_arc_share(129), 5.0 / 133.0):
        failures.append(f"129-target heavy Arc share expected 5/133, got {heavy_arc_share(129)}")
    if heavy_arc_share(4) <= heavy_arc_share(32):
        failures.append("4-target Arc hotspot share must exceed 32-target share")

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

    # Floor gate on mandatory fixtures: serialized 1.0 fails; modest parallel
    # clears the hosted threshold. Production selection necessarily shares
    # target Arc refcounts, so the guard is intentionally just above
    # serialization rather than near-linear four-core scaling.
    if throughput_speedup(100.0, 400.0, 4) >= HOSTED_CONTENTION_FLOOR:
        failures.append(
            f"serialized 1.0x must stay below the {HOSTED_CONTENTION_FLOOR:.2f} hosted floor"
        )
    if throughput_speedup(100.0, 200.0, 4) < HOSTED_CONTENTION_FLOOR:
        failures.append(
            f"2.0x throughput must clear the {HOSTED_CONTENTION_FLOOR:.2f} hosted floor"
        )

    # Hosted-shaped timings: Arc-hotspot 4-target at 0.80x must not fail the
    # gate when mandatory fixtures clear the floor (run 31000740063 means).
    hosted_ok = {
        4: (1_945_764.45, 9_693_357.96),  # 0.80x informational
        32: (1_928_306.15, 6_312_748.40),  # 1.22x mandatory
        129: (8_920_264.93, 16_006_697.49),  # 2.23x mandatory
    }
    ok_failures, _ = evaluate_results(hosted_ok, HOSTED_CONTENTION_FLOOR)
    if ok_failures:
        failures.append(
            "hosted-shaped wait-free timings must pass the split gate, "
            f"got failures={ok_failures}"
        )

    # Fully serialized on every fixture (~1.0x) must fail via 32/129, not via 4.
    serialized = {
        4: (100.0, 400.0),
        32: (100.0, 400.0),
        129: (100.0, 400.0),
    }
    ser_failures, _ = evaluate_results(serialized, HOSTED_CONTENTION_FLOOR)
    if not any("32_targets" in f for f in ser_failures):
        failures.append("serialized 1.0x must fail the 32_targets mandatory floor")
    if not any("129_targets" in f for f in ser_failures):
        failures.append("serialized 1.0x must fail the 129_targets mandatory floor")
    if any("4_targets throughput speedup" in f for f in ser_failures):
        failures.append(
            "serialized 4_targets must not be rejected by the parallel floor "
            "(Arc-hotspot fixture is not a mutex detector)"
        )

    # A green 4-target parallel speedup must not mask serialized mandatory fixtures.
    masked = {
        4: (100.0, 100.0),  # 4.0x
        32: (100.0, 400.0),  # 1.0x serialized
        129: (100.0, 400.0),  # 1.0x serialized
    }
    mask_failures, _ = evaluate_results(masked, HOSTED_CONTENTION_FLOOR)
    if not mask_failures:
        failures.append(
            "gate must not accept a fully serialized implementation just because "
            "4_targets parallel speedup looks healthy"
        )
    if any("4_targets throughput speedup" in f for f in mask_failures):
        failures.append("4_targets parallel speedup must remain non-gating")

    # Small-cardinality serial regression vs mid-cardinality must fail.
    serial_blowup = {
        4: (5_000.0, 5_000.0),
        32: (100.0, 200.0),  # 2.0x clears floor
        129: (100.0, 200.0),
    }
    blow_failures, _ = evaluate_results(serial_blowup, HOSTED_CONTENTION_FLOOR)
    if not any("4_targets 1_thread wall" in f for f in blow_failures):
        failures.append(
            "4_targets serial wall >> 32_targets serial wall must fail the "
            "small-cardinality serial-ratio ceiling"
        )

    if failures:
        for failure in failures:
            print(f"::error::self-test: {failure}")
        return 1

    print(
        "WRR verifier self-test passed "
        f"(mandatory serialization floors on {MANDATORY_SERIALIZATION_TARGETS}; "
        f"4_targets secondary under heavy_arc_share={heavy_arc_share(4):.3f}; "
        f"throughput speedup = {PARALLEL_THREADS} * serial_wall_ns / parallel_wall_ns)."
    )
    return 0


def main() -> int:
    args = parse_args()
    if args.self_test:
        return self_test()

    if args.criterion_root is None or args.min_parallel_speedup is None:
        print("::error::--criterion-root and --min-parallel-speedup are required unless --self-test")
        return 2

    timings: dict[int, tuple[float, float]] = {}
    read_failures: list[str] = []
    for targets in TARGET_COUNTS:
        try:
            serial_ns = mean_point_estimate(args.criterion_root, targets, 1)
            parallel_ns = mean_point_estimate(args.criterion_root, targets, PARALLEL_THREADS)
            timings[targets] = (serial_ns, parallel_ns)
        except ValueError as error:
            read_failures.append(str(error))

    failures, logs = evaluate_results(timings, args.min_parallel_speedup)
    failures = read_failures + failures
    for line in logs:
        print(line)

    if failures:
        for failure in failures:
            print(f"::error::{failure}")
        return 1

    print(
        "WRR selection benchmark is within hosted contention guardrails "
        f"(mandatory {MANDATORY_SERIALIZATION_TARGETS} throughput speedup; "
        "4_targets secondary Arc-hotspot + serial-ratio contracts)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
