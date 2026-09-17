"""Validity rules shared by the protocol summaries and combined scoreboard.

Retain failed observations for diagnosis; never select only the clean iterations
of a flaky competitor to manufacture an error-free mean.
"""

import json
import math


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
    if not isinstance(rps, (int, float)) or not math.isfinite(rps) or rps <= 0:
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
    return float(value) if isinstance(value, (int, float)) and math.isfinite(value) and value > 0 else 0.0


def expected_rows(run_directory):
    """New runs record the plan before startup, including gateways that fail."""
    manifest = run_directory / "manifest.json"
    if not manifest.exists():
        return []  # Older artifacts can still be inspected.
    plan = json.loads(manifest.read_text())
    return [(gateway, size) for gateway in plan["gateways"] for size in plan["payload_sizes"]]
