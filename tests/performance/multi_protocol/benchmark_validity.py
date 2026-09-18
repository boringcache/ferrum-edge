"""Validity rules shared by the protocol summaries and combined scoreboard.

Retain failed observations for diagnosis; never select only the clean iterations
of a flaky competitor to manufacture an error-free mean.
"""

import json
import math


def _is_number(value):
    """`bool` is a subclass of `int`; a JSON `true` is not a measurement."""
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def sample_issues(sample):
    issues = []
    if sample.get("error"):
        issues.append(str(sample["error"]))
    errors = sample.get("total_errors")
    if not isinstance(errors, int) or isinstance(errors, bool) or errors < 0:
        issues.append("missing/invalid error count")
    elif errors:
        issues.append(f"{errors} errors")
    requests = sample.get("total_requests")
    if not isinstance(requests, int) or isinstance(requests, bool) or requests <= 0:
        issues.append("no successful requests")
    else:
        size = sample.get("payload_size")
        if not isinstance(size, int) or size <= 0 or sample.get("total_bytes") != requests * size:
            issues.append("echo byte accounting mismatch")
    rps = sample.get("rps")
    if not _is_number(rps) or not math.isfinite(rps) or rps <= 0:
        issues.append("non-positive/invalid throughput")
    return issues


def bucket_issues(samples, expected_iterations):
    issues = []
    if len(samples) != expected_iterations:
        issues.append(f"{len(samples)}/{expected_iterations} iterations")
    for iteration, sample in enumerate(samples, 1):
        issues.extend(f"run {iteration}: {issue}" for issue in sample_issues(sample))
    return issues


def throughput_value(sample):
    """Keep malformed/non-finite measurements out of display arithmetic too."""
    value = sample.get("rps")
    return float(value) if _is_number(value) and math.isfinite(value) and value > 0 else 0.0


def expected_rows(run_directory):
    """New runs record the plan before startup, including gateways that fail.

    Return ``None`` when the plan is unavailable so callers can retain observed
    rows for diagnosis without treating them as a complete benchmark matrix.
    """
    manifest = run_directory / "manifest.json"
    try:
        plan = json.loads(manifest.read_text())
        gateways = plan["gateways"]
        sizes = plan["payload_sizes"]
        if not isinstance(gateways, list) or not all(
                isinstance(gateway, str) and gateway for gateway in gateways):
            raise ValueError("invalid gateway plan")
        if not isinstance(sizes, list) or not all(
                isinstance(size, int) and not isinstance(size, bool) and size > 0
                for size in sizes):
            raise ValueError("invalid payload-size plan")
    except (OSError, ValueError, TypeError, KeyError):
        return None
    return [(gateway, size) for gateway in gateways for size in sizes]
