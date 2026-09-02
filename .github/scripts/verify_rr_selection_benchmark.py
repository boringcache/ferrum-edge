#!/usr/bin/env python3
"""Fail CI when RoundRobin selection reintroduces single-line counter contention.

Criterion fixture contract (see tests/performance/mesh/benches/rr_selection.rs):
  - Each measured custom iteration runs ITERATIONS_PER_THREAD operations per
    worker thread (currently 50_000).
  - The 1-thread case therefore performs 50_000 operations per iteration.
  - The 8-thread case performs 8 * 50_000 operations per iteration.
  - Multi-thread samples reuse a long-lived barrier-synchronized worker pool;
    Criterion's mean is the wall time from barrier release until every worker
    completes its loop, not thread spawn/join overhead.
  - Criterion's mean point estimate is elapsed wall-clock nanoseconds for that
    whole custom iteration (not ns/operation).
  - Two workloads are measured at both thread counts: `2_targets` runs
    `LoadBalancer::select` on a 2-target RoundRobin upstream, and
    `shared_counter_control` runs one genuinely shared `AtomicU64::fetch_add`.

What this gate asserts (issue #4484)
------------------------------------
It does NOT assert a parallel *speedup* on the selection fixture. That fixture
is dominated by a shared-line hotspot: hosted runs measure roughly 0.6x-0.7x on
a healthy tree, which is what the sibling WRR verifier already treats as
informational for its small-cardinality fixture. A floor above the workload's
own typical value ejected green pull requests from the merge queue.

Instead the gate bounds the selection path's **per-selection contention cost**:

  contention_ratio = parallel_ns / (PARALLEL_THREADS * serial_ns)
                   = parallel ns/selection ÷ serial ns/selection

`contention_ratio` is 1.0 for a perfectly scaling workload and rises toward
PARALLEL_THREADS as the batch serializes on one cache line. The reference for
"serialized on one cache line" is measured on the same runner in the same run
by the `shared_counter_control` fixture, so an oversubscribed or
coherence-degraded runner inflates both readings together and does not flip the
verdict:

  pass  iff  selection_ratio <= SHARED_COUNTER_BUDGET * control_ratio

If the control itself resolves no shared-line penalty (control_ratio below
MIN_CONTROL_CONTENTION_RATIO) the runner cannot measure contention right now,
so the comparison has no resolving power. The gate then falls back to the wide
absolute backstop MAX_CONTENTION_LATENCY_RATIO and emits a `::warning::`. The
same backstop applies fail-closed when the control fixture is unreadable.

The 8-thread throughput speedup and `--min-parallel-speedup` are still printed
for continuity, but are informational for this fixture.
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path


TARGET_COUNT = 2
PARALLEL_THREADS = 8
# Must match tests/performance/mesh/benches/rr_selection.rs
ITERATIONS_PER_THREAD = 50_000
SELECTION_FIXTURE = f"{TARGET_COUNT}_targets"
CONTROL_FIXTURE = "shared_counter_control"

# Fraction of the contemporaneous single-shared-`AtomicU64` contention cost that
# the sharded selection path is allowed to spend. A regression that puts every
# worker back on one line lands at (or above) the control itself; healthy hosted
# runs sit near a quarter of it.
SHARED_COUNTER_BUDGET = 0.50
# Below this the control shows no measurable shared-line penalty at all, so it
# cannot distinguish sharded counters from a shared one on this runner.
MIN_CONTROL_CONTENTION_RATIO = 2.00
# Fail-closed backstop used when there is no usable control reading. Healthy
# hosted readings are ~1.3x-1.7x; a fully serialized batch is >= 8x.
MAX_CONTENTION_LATENCY_RATIO = 4.00


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Verify hosted RoundRobin selection Criterion results. The gate "
            "bounds per-selection contention cost against a same-run shared-"
            f"`AtomicU64` control at {PARALLEL_THREADS} threads; parallel "
            "speedup is informational for this fixture."
        )
    )
    parser.add_argument("--criterion-root", type=Path, required=False)
    parser.add_argument(
        "--min-parallel-speedup",
        type=float,
        required=False,
        help=(
            "Informational parallel-speedup reference for the "
            f"{SELECTION_FIXTURE} fixture. This fixture is dominated by a "
            "shared-line hotspot and is not expected to scale, so a miss is "
            "reported, not failed. The enforced condition is the per-selection "
            f"contention bound against the {CONTROL_FIXTURE} fixture."
        ),
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run synthetic unit checks for the contention model and exit.",
    )
    return parser.parse_args()


def throughput_speedup(serial_ns: float, parallel_ns: float, parallel_threads: int) -> float:
    """Return parallel/serial throughput from Criterion wall times."""
    if serial_ns <= 0 or parallel_ns <= 0 or parallel_threads < 1:
        raise ValueError(
            f"invalid timing inputs serial_ns={serial_ns} parallel_ns={parallel_ns} "
            f"parallel_threads={parallel_threads}"
        )
    return (parallel_threads * serial_ns) / parallel_ns


def contention_ratio(serial_ns: float, parallel_ns: float, parallel_threads: int) -> float:
    """Per-operation cost under `parallel_threads` divided by the serial cost.

    1.0 is perfect scaling; `parallel_threads` is full serialization on one
    cache line. This is the reciprocal of :func:`throughput_speedup` and uses
    only measurements the fixture already records.
    """
    return 1.0 / throughput_speedup(serial_ns, parallel_ns, parallel_threads)


def classify_contention(
    selection_ratio: float,
    control_ratio: float | None,
    budget: float = SHARED_COUNTER_BUDGET,
    min_control_ratio: float = MIN_CONTROL_CONTENTION_RATIO,
    backstop: float = MAX_CONTENTION_LATENCY_RATIO,
) -> str:
    """Classify a per-selection contention reading.

    Returns:
      pass — selection cost is within budget of the same-run shared-counter
        control
      regression — selection cost reached the shared-line reference (or, with
        no usable control, blew past the absolute backstop)
      control_unresolved — the control resolved no shared-line penalty, so the
        comparison has no signal; the wide absolute backstop was applied and
        cleared
      control_missing — no control reading at all; the absolute backstop was
        applied fail-closed and cleared
    """
    if control_ratio is None:
        return "control_missing" if selection_ratio <= backstop else "regression"
    if control_ratio < min_control_ratio:
        return "control_unresolved" if selection_ratio <= backstop else "regression"
    return "pass" if selection_ratio <= budget * control_ratio else "regression"


def mean_point_estimate(criterion_root: Path, fixture: str, threads: int) -> float:
    estimates_path = (
        criterion_root / "rr_selection" / f"{fixture}_{threads}_threads" / "new" / "estimates.json"
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


def fixture_ratio(criterion_root: Path, fixture: str) -> tuple[float, float, float]:
    """Return `(serial_ns, parallel_ns, contention_ratio)` for one fixture."""
    serial_ns = mean_point_estimate(criterion_root, fixture, 1)
    parallel_ns = mean_point_estimate(criterion_root, fixture, PARALLEL_THREADS)
    return serial_ns, parallel_ns, contention_ratio(serial_ns, parallel_ns, PARALLEL_THREADS)


def describe(fixture: str, serial_ns: float, parallel_ns: float, ratio: float) -> str:
    serial_elements = ITERATIONS_PER_THREAD
    parallel_elements = ITERATIONS_PER_THREAD * PARALLEL_THREADS
    return (
        f"{fixture}: "
        f"1_thread wall={serial_ns:.2f} ns / {serial_elements} ops, "
        f"{PARALLEL_THREADS}_threads wall={parallel_ns:.2f} ns / {parallel_elements} ops, "
        f"contention_ratio={ratio:.2f}x "
        f"(= parallel_ns / ({PARALLEL_THREADS} * serial_ns); 1.00x scales perfectly, "
        f"{PARALLEL_THREADS}.00x is fully serialized), "
        f"throughput_speedup={1.0 / ratio:.2f}x"
    )


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

    if not math.isclose(contention_ratio(100.0, 100.0, PARALLEL_THREADS), 1.0 / PARALLEL_THREADS):
        failures.append("perfect scaling must give a 1/threads contention ratio")
    if not math.isclose(
        contention_ratio(100.0, 100.0 * PARALLEL_THREADS, PARALLEL_THREADS), 1.0
    ):
        failures.append("flat throughput must give a 1.0x contention ratio")
    if not math.isclose(
        contention_ratio(100.0, 800.0 * PARALLEL_THREADS, PARALLEL_THREADS),
        float(PARALLEL_THREADS),
    ):
        failures.append(
            f"fully serialized batch must give a {PARALLEL_THREADS}.0x contention ratio"
        )

    # Issue #4484: the three hosted readings that ejected #4466 (0.61x, 0.69x,
    # 0.72x throughput speedup) must pass against a healthy shared-counter
    # control, and must not depend on a fixed speedup floor.
    for speedup in (0.61, 0.69, 0.72, 0.79):
        selection = 1.0 / speedup
        if classify_contention(selection, control_ratio=6.0) != "pass":
            failures.append(
                f"hosted reading {speedup:.2f}x speedup (ratio {selection:.2f}x) with a "
                "6.00x shared-counter control must pass"
            )

    # A real regression puts selection back on the shared line: its cost reaches
    # the control's, whatever absolute value the runner produces that day.
    if classify_contention(6.0, control_ratio=6.0) != "regression":
        failures.append("selection cost matching the shared-counter control must be a regression")
    if classify_contention(3.1, control_ratio=6.0) != "regression":
        failures.append("selection cost above half the control must be a regression")
    if classify_contention(2.9, control_ratio=6.0) != "pass":
        failures.append("selection cost below half the control must pass")

    # Self-calibration: a coherence-degraded runner inflates both readings, so a
    # healthy tree keeps the same verdict instead of flipping red.
    healthy = 1.45
    if classify_contention(healthy, control_ratio=6.0) != "pass":
        failures.append("healthy tree on a quiet runner must pass")
    if classify_contention(healthy * 2.5, control_ratio=6.0 * 2.5) != "pass":
        failures.append("proportionally degraded coherence must not flip the verdict")
    if classify_contention(6.0 * 2.5, control_ratio=6.0 * 2.5) != "regression":
        failures.append("a degraded runner must still catch a shared-line regression")

    # Control with no resolving power falls back to the absolute backstop.
    if classify_contention(1.45, control_ratio=1.05) != "control_unresolved":
        failures.append("an unresolved control must fall back to the absolute backstop")
    if classify_contention(MAX_CONTENTION_LATENCY_RATIO + 0.5, control_ratio=1.05) != "regression":
        failures.append("an unresolved control must still enforce the absolute backstop")

    # Missing control fails closed on the same backstop.
    if classify_contention(1.45, control_ratio=None) != "control_missing":
        failures.append("a missing control must apply the backstop and pass a healthy reading")
    if classify_contention(MAX_CONTENTION_LATENCY_RATIO + 0.5, control_ratio=None) != "regression":
        failures.append("a missing control must fail closed above the backstop")

    if SHARED_COUNTER_BUDGET * MIN_CONTROL_CONTENTION_RATIO >= 1.0 / 0.79:
        failures.append(
            "the weakest admissible control must still leave room for the documented "
            "hosted collapse near 1.0x throughput speedup"
        )
    if MAX_CONTENTION_LATENCY_RATIO >= PARALLEL_THREADS:
        failures.append("the absolute backstop must stay below full serialization")

    line = describe(SELECTION_FIXTURE, 1_357_021.24, 15_740_761.94, contention_ratio(
        1_357_021.24, 15_740_761.94, PARALLEL_THREADS
    ))
    if "contention_ratio=1.45x" not in line or "throughput_speedup=0.69x" not in line:
        failures.append(f"reporting line must show both metrics, got: {line}")

    if failures:
        for failure in failures:
            print(f"::error::self-test: {failure}")
        return 1

    print(
        "RR verifier self-test passed (contention_ratio = parallel_ns / "
        f"({PARALLEL_THREADS} * serial_ns); the enforced bound is "
        f"{SHARED_COUNTER_BUDGET:.2f} x the same-run {CONTROL_FIXTURE} reading, "
        f"with a {MAX_CONTENTION_LATENCY_RATIO:.2f}x fail-closed backstop; "
        "parallel speedup is informational for this fixture)."
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

    selection_ratio: float | None = None
    try:
        serial_ns, parallel_ns, selection_ratio = fixture_ratio(
            args.criterion_root, SELECTION_FIXTURE
        )
        print(describe(SELECTION_FIXTURE, serial_ns, parallel_ns, selection_ratio))
    except ValueError as error:
        failures.append(str(error))

    control_ratio: float | None = None
    try:
        control_serial_ns, control_parallel_ns, control_ratio = fixture_ratio(
            args.criterion_root, CONTROL_FIXTURE
        )
        print(
            describe(CONTROL_FIXTURE, control_serial_ns, control_parallel_ns, control_ratio)
        )
    except ValueError as error:
        print(f"::warning::shared-counter control unavailable ({error}); enforcing the "
              f"{MAX_CONTENTION_LATENCY_RATIO:.2f}x absolute backstop (fail closed)")

    if selection_ratio is not None:
        # Informational only: this fixture is dominated by a shared-line hotspot
        # and is not expected to scale (issue #4484).
        speedup = 1.0 / selection_ratio
        if speedup < args.min_parallel_speedup:
            print(
                f"::notice::{SELECTION_FIXTURE} throughput speedup {speedup:.2f}x is below the "
                f"informational reference {args.min_parallel_speedup:.2f}x; this fixture is "
                "dominated by a shared-line hotspot and typically collapses near 1.0x, so the "
                f"enforced condition is the contention bound against {CONTROL_FIXTURE}"
            )

        verdict = classify_contention(selection_ratio, control_ratio)
        if verdict == "regression":
            if control_ratio is None:
                failures.append(
                    f"{SELECTION_FIXTURE} per-selection contention {selection_ratio:.2f}x "
                    f"exceeds the {MAX_CONTENTION_LATENCY_RATIO:.2f}x absolute backstop with no "
                    "shared-counter control available (fail closed)"
                )
            elif control_ratio < MIN_CONTROL_CONTENTION_RATIO:
                failures.append(
                    f"{SELECTION_FIXTURE} per-selection contention {selection_ratio:.2f}x "
                    f"exceeds the {MAX_CONTENTION_LATENCY_RATIO:.2f}x absolute backstop "
                    f"(shared-counter control {control_ratio:.2f}x resolved no shared-line "
                    "penalty, so the relative bound was unusable)"
                )
            else:
                failures.append(
                    f"{SELECTION_FIXTURE} per-selection contention {selection_ratio:.2f}x "
                    f"is above {SHARED_COUNTER_BUDGET:.2f} x the same-run {CONTROL_FIXTURE} "
                    f"reading {control_ratio:.2f}x (budget "
                    f"{SHARED_COUNTER_BUDGET * control_ratio:.2f}x): selection is paying "
                    "single-shared-`AtomicU64` cost, i.e. the sharded/CachePadded counters "
                    "regressed"
                )
        elif verdict == "control_unresolved":
            print(
                f"::warning::shared-counter control {control_ratio:.2f}x is below "
                f"{MIN_CONTROL_CONTENTION_RATIO:.2f}x: this runner cannot resolve shared-line "
                f"contention right now, so the relative bound has no signal. Applied the "
                f"{MAX_CONTENTION_LATENCY_RATIO:.2f}x absolute backstop instead."
            )
        elif verdict == "control_missing":
            print(
                f"::warning::no shared-counter control reading; {SELECTION_FIXTURE} cleared the "
                f"{MAX_CONTENTION_LATENCY_RATIO:.2f}x absolute backstop"
            )

    if failures:
        for failure in failures:
            print(f"::error::{failure}")
        return 1

    print(
        "RR selection benchmark is within hosted contention guardrails "
        "(per-selection contention cost bounded against a same-run shared-`AtomicU64` "
        "reference; parallel speedup is informational for this fixture)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
