"""Deterministic same-host pairs and additive summary records for the frozen lane."""

import json
import math
import statistics
from pathlib import Path

from benchmark_validity import sample_issues
from process_usage import measurement_usage


def stamp_sample(path, gateway, payload, concurrency, pair, position, host, usage_path, order):
    """Attach metadata and passive process observations after the client exits."""
    path = Path(path)
    try:
        sample = json.loads(path.read_text())
    except (OSError, ValueError):
        sample = {"rps": 0, "error": "unparseable"}
    sample.update(gateway=gateway, payload_size=int(payload), effective_concurrency=int(concurrency),
                  sample_schema=2, pair=int(pair), order_position=int(position),
                  host_id=host, gateway_order=order.split())
    try:
        usage = json.loads(Path(usage_path).read_text())
        if usage.get("capture_complete") is not True:
            raise ValueError("process capture incomplete")
        usage["measurement"] = measurement_usage(usage, sample.get("phases") or {})
        usage.pop("timeline", None)  # full series stays in the diagnostic file
        sample["process_usage"] = usage
    except (OSError, ValueError):
        sample["process_usage"] = {"error": "process capture unavailable/incomplete"}
    path.write_text(json.dumps(sample, indent=2) + "\n")


def gateway_order(gateways, pair):
    """Alternating forward/reverse blocks; rotate each block's first gateway."""
    if pair < 1 or len(gateways) != len(set(gateways)):
        raise ValueError("pair must be positive and gateways unique")
    if not gateways:
        return []
    offset = ((pair - 1) // 2) % len(gateways)
    order = gateways[offset:] + gateways[:offset]
    return list(reversed(order)) if pair % 2 == 0 else order


def paired_comparison(baseline, candidate, expected_pairs):
    """Student-t interval over paired log ratios; never discard a failed pair."""
    result = {"expected_pairs": expected_pairs, "accepted": False}
    if len(baseline) != expected_pairs or len(candidate) != expected_pairs:
        return dict(result, reason="incomplete pairs")
    expected_ids = list(range(1, expected_pairs + 1))
    if any([row.get("pair") for row in rows] != expected_ids for rows in (baseline, candidate)):
        return dict(result, reason="missing/duplicate/out-of-order pair IDs")
    if len({row.get("host_id") for row in baseline + candidate}) != 1:
        return dict(result, reason="pairs span multiple hosts")
    ratios = []
    for left, right in zip(baseline, candidate):
        if sample_issues(left) or sample_issues(right):
            return dict(result, reason="invalid pair")
        for field in ("pair", "host_id", "payload_size", "duration_secs",
                      "effective_concurrency"):
            if field not in left or left[field] != right.get(field):
                return dict(result, reason=f"unmatched {field}")
        ratios.append(math.log(right["rps"] / left["rps"]))
    if expected_pairs < 3:
        return dict(result, reason="at least three pairs required")
    # Exact two-sided 95% t critical values for n=3..7; conservative above 7.
    critical = {3: 4.303, 4: 3.182, 5: 2.776, 6: 2.571, 7: 2.447}
    mean = statistics.mean(ratios)
    margin = critical.get(expected_pairs, 2.447) * statistics.stdev(ratios) / math.sqrt(
        expected_pairs)
    uncertain = abs(mean) <= margin
    return dict(result, accepted=True, ratio=math.exp(mean),
                ci95_low=math.exp(mean - margin), ci95_high=math.exp(mean + margin),
                needs_more_measurement=uncertain,
                reason="uncertainty overlaps no gain" if uncertain else "paired interval")


def summarize(samples, expected_pairs):
    """Keep legacy scalar consumers working and retain EVERY constituent record."""
    summary = dict(samples[-1]) if samples else {}
    summary["samples"] = samples
    summary["expected_pairs"] = expected_pairs
    summary["sample_schema"] = 2
    summary.pop("phases", None)
    summary.pop("observed", None)
    summary.pop("process_usage", None)
    summary.pop("pair", None)
    summary.pop("order_position", None)
    for field in ("total_requests", "total_errors", "total_bytes", "duration_secs",
                  "warmup_requests", "drain_requests", "drain_bytes"):
        summary[field] = sum(sample.get(field, 0) for sample in samples)
    duration = summary["duration_secs"]
    summary["rps"] = summary["total_requests"] / duration if duration else 0
    summary["throughput_mbps"] = summary["total_bytes"] * 8 / (1_000_000 * duration) if duration else 0
    # Quantiles cannot be merged without histograms. Keep conservative maxima
    # and identify that policy explicitly for legacy budget consumers.
    for field in ("p50_us", "p75_us", "p90_us", "p95_us", "p99_us", "latency_max_us"):
        summary[field] = max((sample.get(field, 0) for sample in samples), default=0)
    summary["latency_summary"] = "maximum per-sample quantiles; see samples"
    requests = summary["total_requests"]
    summary["latency_avg_us"] = int(sum(
        sample.get("latency_avg_us", 0) * sample.get("total_requests", 0)
        for sample in samples) / requests) if requests else 0
    summary["latency_stdev_us"] = max(
        (sample.get("latency_stdev_us", 0) for sample in samples), default=0)
    if len(samples) != expected_pairs or any(sample_issues(sample) for sample in samples):
        summary["error"] = "invalid or incomplete paired samples"
    return summary


def write_summaries(directory, protocol, gateways, sizes, pairs):
    directory = Path(directory)
    buckets = {}
    for gateway in gateways:
        for size in sizes:
            name = f"{gateway}_{protocol}_{size}.json"
            samples = []
            for pair in range(1, pairs + 1):
                path = directory / "pairs" / f"pair_{pair:03d}" / name
                try:
                    sample = json.loads(path.read_text())
                except (OSError, ValueError):
                    sample = {"error": "missing/unparseable paired sample", "pair": pair}
                samples.append(sample)
            buckets[gateway, size] = samples
            summary = summarize(samples, pairs)
            summary.update(gateway=gateway, protocol=protocol, payload_size=size)
            (directory / name).write_text(json.dumps(summary, indent=2) + "\n")
    comparisons = []
    references = ["direct"]
    references += ["ferrum-baseline"] if "ferrum-baseline" in gateways else ["ferrum"]
    for reference in references:
        if reference not in gateways:
            continue
        for gateway in gateways:
            if gateway in (reference, "direct"):
                continue
            for size in sizes:
                comparison = paired_comparison(
                    buckets[reference, size], buckets[gateway, size], pairs)
                comparisons.append(dict(comparison, baseline=reference, candidate=gateway,
                                        payload_size=size))
    (directory / "paired_comparisons.json").write_text(json.dumps(comparisons, indent=2) + "\n")
    return any(row.get("needs_more_measurement") for row in comparisons)


if __name__ == "__main__":
    import sys

    command, *args = sys.argv[1:]
    if command == "order":
        print(" ".join(gateway_order(args[1].split(), int(args[0]))))
    elif command == "summarize":
        directory, protocol, gateways, sizes, pairs = args
        needs_more = write_summaries(directory, protocol, gateways.split(),
                                     [int(size) for size in sizes.split()], int(pairs))
        print("extend" if needs_more else "done")
    elif command == "stamp":
        stamp_sample(*args)
    else:
        raise SystemExit("unknown plan command")
