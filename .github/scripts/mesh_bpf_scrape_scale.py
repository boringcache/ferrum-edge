#!/usr/bin/env python3
"""Common factor of the cumulative ``ferrum_mesh_bpf_*`` counters in one scrape.

When the ambient proxy's ringbuf consumer stops making forward progress it
re-counts the same resident records on every wakeup, so the whole family of
counters reads ``underlying x N`` for one ``N`` that climbs with wall-clock
time (issue #5502). This prints that common factor, the greatest common
divisor of every positive counter in the family. On a healthy consumer the
independent counters share no factor and the result is 1. The always-1 gauges
are excluded because they would pin the result at 1 and hide the rescale.

Standard library only; no repository imports. Usage::

    python3 .github/scripts/mesh_bpf_scrape_scale.py SCRAPE_FILE

The live NodeWaypoint eBPF assertion divides each scrape by its own factor and
requires the underlying bypass-decision count to move.
"""

from __future__ import annotations

import math
import sys

FAMILY_PREFIX = "ferrum_mesh_bpf_"
EXCLUDED_NAME_FRAGMENTS = (
    "drop_reasons",
    "ringbuf_overruns_total",
    "ringbuf_in_overrun_regime",
)


def split_sample(line: str) -> tuple[str, str] | None:
    """Return ``(series, value)`` for one exposition line, or ``None``.

    The series keeps its label set. A label value may contain spaces, so the
    split happens after the closing brace rather than at the first space.
    """

    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    if stripped.startswith(FAMILY_PREFIX) and "{" in stripped:
        close = stripped.find("}")
        if close < 0:
            return None
        series = stripped[: close + 1]
        rest = stripped[close + 1 :].split()
    else:
        parts = stripped.split()
        if len(parts) < 2:
            return None
        series, rest = parts[0], parts[1:]
    if not rest:
        return None
    return series, rest[0]


def scrape_scale(lines) -> int:
    """Greatest common divisor of the positive family counters, at least 1."""

    scale = 0
    for line in lines:
        sample = split_sample(line)
        if sample is None:
            continue
        series, value = sample
        if not series.startswith(FAMILY_PREFIX):
            continue
        if any(fragment in series for fragment in EXCLUDED_NAME_FRAGMENTS):
            continue
        if not value or any(char not in "0123456789" for char in value):
            continue
        number = int(value)
        if number > 0:
            scale = number if scale == 0 else math.gcd(scale, number)
    return scale if scale >= 1 else 1


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: mesh_bpf_scrape_scale.py SCRAPE_FILE", file=sys.stderr)
        return 2
    try:
        with open(argv[1], encoding="utf-8", errors="replace") as handle:
            print(scrape_scale(handle))
    except OSError as error:
        print(f"mesh_bpf_scrape_scale: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
