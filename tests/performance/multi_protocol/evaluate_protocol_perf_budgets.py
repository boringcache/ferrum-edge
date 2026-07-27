#!/usr/bin/env python3
"""Evaluate multi-protocol regression results against versioned budgets.

Publishes machine-readable trends and compares the current run against:
  * explicit per-protocol budgets in protocol_perf_budgets.json
  * a rolling median ± MAD baseline when prior trend samples are present

Enforcement defaults to alert-only for measured product regressions so
shared-runner variance does not fail the scheduled job until absolute floors
are filled in. Data-completeness / harness failures are always hard failures
independent of enforcement mode.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import statistics
import sys
from pathlib import Path
from typing import Any


GATEWAY_PORT_MARKERS = (":8000", ":8443", ":5010", ":5001", ":5003", ":5004")
MAX_METRIC_COUNT = (1 << 63) - 1

# CLI / workflow_dispatch aliases -> budget protocol names emitted by proto_bench.
PROTOCOL_ALIASES: dict[str, str] = {
    "http1": "HTTP/1.1",
    "http1-tls": "HTTP/1.1+TLS",
    "http2": "HTTP/2",
    "http3": "HTTP/3",
    "ws": "WebSocket",
    "websocket": "WebSocket",
    "grpc": "gRPC",
    "tcp": "TCP",
    "tcp-tls": "TCP+TLS",
    "udp": "UDP",
    "udp-dtls": "UDP+DTLS",
}

REQUIRED_SCENARIOS = (
    "connection_churn",
    "reload_under_load",
    "soak",
    "resource_plateau",
)

DEFAULT_MIN_RESOURCE_SAMPLES = 3


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, help="Combined results JSON from the workflow")
    parser.add_argument("--budgets", type=Path, help="Versioned protocol budget file")
    parser.add_argument(
        "--history",
        type=Path,
        help="Optional prior trends JSON for rolling baseline comparison",
    )
    parser.add_argument("--trends-out", type=Path, help="Write machine-readable trends JSON")
    parser.add_argument("--report-out", type=Path, help="Write evaluation report JSON")
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run synthetic unit checks and exit",
    )
    return parser.parse_args()


def is_gateway_target(target: str) -> bool:
    return any(marker in target for marker in GATEWAY_PORT_MARKERS)


def parse_finite_number(value: Any) -> float | None:
    """Parse a finite float, or None when missing/malformed/non-finite."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        try:
            number = float(value)
        except OverflowError:
            return None
    elif isinstance(value, float):
        number = value
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            number = float(text)
        except ValueError:
            return None
    else:
        return None
    if not math.isfinite(number):
        return None
    return number


def parse_nonnegative_number(value: Any) -> float | None:
    number = parse_finite_number(value)
    if number is None or number < 0.0:
        return None
    return number


def parse_nonnegative_int(value: Any) -> int | None:
    """Parse a nonnegative integral count without raising on malformed input."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        number = value
    elif isinstance(value, float):
        if not math.isfinite(value) or not value.is_integer():
            return None
        number = int(value)
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            number = int(text, 10)
        except ValueError:
            try:
                parsed = float(text)
            except (ValueError, OverflowError):
                return None
            if not math.isfinite(parsed) or not parsed.is_integer():
                return None
            number = int(parsed)
    else:
        return None
    if number < 0 or number > MAX_METRIC_COUNT:
        return None
    return number


def parse_unit_rate(value: Any) -> float | None:
    """Parse a finite rate in [0, 1], or None when malformed."""
    number = parse_finite_number(value)
    if number is None or number < 0.0 or number > 1.0:
        return None
    return number


def sample_total(sample: dict[str, Any]) -> int | None:
    """Return request+error total, or None when counts are malformed."""
    requests = parse_nonnegative_int(sample.get("total_requests", 0))
    errors = parse_nonnegative_int(sample.get("total_errors", 0))
    if requests is None or errors is None:
        return None
    return requests + errors


def error_rate(sample: dict[str, Any]) -> float | None:
    """Return error rate, or None when activity is zero or counts are malformed."""
    total = sample_total(sample)
    if total is None or total <= 0:
        return None
    errors = parse_nonnegative_int(sample.get("total_errors", 0))
    if errors is None:
        return None
    return float(errors) / float(total)


def normalize_protocol_name(name: str) -> str:
    return name.strip()


def resolve_protocol_token(token: str, budget_protocols: set[str]) -> str:
    raw = token.strip()
    if not raw:
        raise ValueError("empty protocol token")
    lowered = raw.lower()
    if lowered in PROTOCOL_ALIASES:
        return PROTOCOL_ALIASES[lowered]
    if raw in budget_protocols:
        return raw
    # Case-insensitive match against budget keys.
    for name in budget_protocols:
        if name.lower() == lowered:
            return name
    raise ValueError(f"unknown protocol selection {raw!r}")


def resolve_expected_protocols(
    requested: str | None, budget_protocols: dict[str, Any]
) -> list[str]:
    """Map workflow selection (`all` or subset) to budget protocol names."""
    names = set(budget_protocols.keys())
    selection = (requested or "all").strip()
    if not selection or selection.lower() == "all":
        return sorted(names)

    tokens = [tok for tok in re.split(r"[,;\s]+", selection) if tok]
    if not tokens:
        return sorted(names)

    expected: list[str] = []
    seen: set[str] = set()
    for token in tokens:
        resolved = resolve_protocol_token(token, names)
        if resolved not in seen:
            expected.append(resolved)
            seen.add(resolved)
    return expected


def is_valid_gateway_sample(sample: dict[str, Any]) -> bool:
    """Reject zero-total, non-finite, and structurally invalid metric samples."""
    if not isinstance(sample, dict):
        return False
    if not is_gateway_target(str(sample.get("target", ""))):
        return False
    if not str(sample.get("protocol", "")).strip():
        return False
    total = sample_total(sample)
    if total is None or total <= 0:
        return False
    # Zero RPS / large but finite latency remain valid measured outcomes.
    if parse_nonnegative_number(sample.get("rps")) is None:
        return False
    for key in ("p50_us", "p99_us"):
        if parse_nonnegative_number(sample.get(key, 0)) is None:
            return False
    for key in ("p95_us", "p90_us"):
        if key in sample and sample.get(key) is not None:
            if parse_nonnegative_number(sample.get(key)) is None:
                return False
    return True


def extract_gateway_samples(results: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Return protocol -> list of gateway benchmark samples across runs."""
    by_protocol: dict[str, list[dict[str, Any]]] = {}
    runs = results.get("runs", {})
    if isinstance(runs, dict) and runs:
        iterable = runs.values()
    else:
        iterable = [results.get("benchmarks", [])]

    for run_benchmarks in iterable:
        if not isinstance(run_benchmarks, list):
            continue
        for sample in run_benchmarks:
            if not isinstance(sample, dict):
                continue
            if not is_gateway_target(str(sample.get("target", ""))):
                continue
            proto = normalize_protocol_name(str(sample.get("protocol", "unknown")))
            by_protocol.setdefault(proto, []).append(sample)
    return by_protocol


def median(values: list[float]) -> float:
    return float(statistics.median(values))


def mad(values: list[float], center: float) -> float:
    if not values:
        return 0.0
    return float(statistics.median([abs(v - center) for v in values]))


def rolling_breach(
    current: float,
    history: list[float],
    *,
    mad_multiplier: float,
    min_samples: int,
    higher_is_worse: bool,
) -> str | None:
    if len(history) < min_samples:
        return None
    center = median(history)
    spread = mad(history, center)
    # Floor the MAD so near-zero historical variance does not create brittle gates.
    spread = max(spread, abs(center) * 0.05, 1.0)
    if higher_is_worse:
        limit = center + mad_multiplier * spread
        if current > limit:
            return (
                f"current={current:.3f} exceeds rolling upper bound {limit:.3f} "
                f"(median={center:.3f}, MAD={spread:.3f})"
            )
    else:
        limit = center - mad_multiplier * spread
        if current < limit:
            return (
                f"current={current:.3f} below rolling lower bound {limit:.3f} "
                f"(median={center:.3f}, MAD={spread:.3f})"
            )
    return None


def history_metric(
    history_doc: dict[str, Any] | None, protocol: str, metric: str
) -> list[float]:
    if not history_doc:
        return []
    points = history_doc.get("points", [])
    values: list[float] = []
    for point in points:
        protocols = point.get("protocols", {})
        sample = protocols.get(protocol)
        if not isinstance(sample, dict):
            continue
        if metric not in sample or sample[metric] is None:
            continue
        values.append(float(sample[metric]))
    return values


def hard_fail(failures: list[str], message: str) -> None:
    """Data-completeness / harness errors always fail the job."""
    failures.append(message)


def scenario_request_sample_usable(sample: Any) -> bool:
    if not isinstance(sample, dict):
        return False
    for key in ("rps", "p50_us", "p90_us", "p95_us", "p99_us"):
        if key in sample and sample.get(key) is not None:
            if parse_nonnegative_number(sample.get(key)) is None:
                return False
    total = sample_total(sample)
    if total is not None and total > 0:
        return True
    # Malformed request/error counts are never usable.
    if total is None and (
        "total_requests" in sample or "total_errors" in sample
    ):
        return False
    # Saturate reports connect/heartbeat rates instead of request totals.
    has_heartbeat = "heartbeat_success_rate" in sample
    has_connect = "connect_success_rate" in sample
    if not (has_heartbeat or has_connect):
        return False
    if has_heartbeat and parse_unit_rate(sample.get("heartbeat_success_rate")) is None:
        return False
    if has_connect and parse_unit_rate(sample.get("connect_success_rate")) is None:
        return False
    return True


def resource_series_structurally_valid(series: Any, *, min_samples: int) -> str | None:
    """Return an error fragment when a plateau series is short or non-numeric."""
    if not isinstance(series, list):
        return "not a list"
    if len(series) < min_samples:
        return f"insufficient sampling (need >= {min_samples}, got {len(series)})"
    for index, item in enumerate(series):
        if parse_nonnegative_number(item) is None:
            return (
                f"non-finite/malformed value at index {index} "
                "(require nonnegative finite numbers)"
            )
    return None


def validate_required_scenarios(
    scenarios: Any,
    *,
    min_resource_samples: int,
    failures: list[str],
) -> None:
    if not isinstance(scenarios, dict) or not scenarios:
        hard_fail(
            failures,
            "scenarios: missing required scenario output "
            f"(expected {', '.join(REQUIRED_SCENARIOS)})",
        )
        return

    for key in REQUIRED_SCENARIOS:
        if key not in scenarios or not isinstance(scenarios.get(key), dict):
            hard_fail(failures, f"scenarios: missing required scenario {key}")

    for key in ("connection_churn", "reload_under_load"):
        block = scenarios.get(key)
        if not isinstance(block, dict):
            continue
        sample = block.get("sample")
        if not scenario_request_sample_usable(sample):
            hard_fail(
                failures,
                f"scenarios: {key} missing usable measurement sample "
                "(zero-total/invalid harness output)",
            )
        if "error_rate" in block and parse_unit_rate(block.get("error_rate")) is None:
            hard_fail(
                failures,
                f"scenarios: {key} has non-finite/malformed error_rate "
                "(require finite rate in [0, 1])",
            )

    soak = scenarios.get("soak")
    if isinstance(soak, dict) and not scenario_request_sample_usable(soak.get("sample")):
        hard_fail(
            failures,
            "scenarios: soak missing usable measurement sample "
            "(zero-total/invalid harness output)",
        )

    plateau = scenarios.get("resource_plateau")
    if isinstance(plateau, dict):
        for resource in ("rss_bytes", "fd_count", "task_count"):
            series = plateau.get(resource, [])
            problem = resource_series_structurally_valid(
                series, min_samples=min_resource_samples
            )
            if problem is None:
                continue
            if problem.startswith("insufficient"):
                hard_fail(
                    failures,
                    f"scenarios: resource_plateau insufficient {resource} sampling "
                    f"(need >= {min_resource_samples}, got "
                    f"{len(series) if isinstance(series, list) else 0})",
                )
            else:
                hard_fail(
                    failures,
                    f"scenarios: resource_plateau {resource} {problem}",
                )


def evaluate(
    results: dict[str, Any],
    budgets: dict[str, Any],
    history_doc: dict[str, Any] | None,
) -> dict[str, Any]:
    enforcement = str(budgets.get("enforcement", "alert")).lower()
    global_cfg = budgets.get("global", {})
    rolling_cfg = budgets.get("rolling", {})
    mad_multiplier = float(rolling_cfg.get("mad_multiplier", 5.0))
    min_samples = int(rolling_cfg.get("min_samples", 3))
    window = int(rolling_cfg.get("window", 8))
    min_resource_samples = int(
        global_cfg.get("min_resource_samples", DEFAULT_MIN_RESOURCE_SAMPLES)
    )

    budget_protocols = budgets.get("protocols", {})
    if not isinstance(budget_protocols, dict):
        budget_protocols = {}

    alerts: list[str] = []
    failures: list[str] = []
    protocol_summary: dict[str, Any] = {}

    def note(message: str) -> None:
        """Measured budget regressions: alert-only unless enforcement=gate."""
        alerts.append(message)
        if enforcement == "gate":
            failures.append(message)

    try:
        expected = resolve_expected_protocols(
            results.get("protocols") if isinstance(results.get("protocols"), str) else None,
            budget_protocols,
        )
    except ValueError as exc:
        hard_fail(failures, f"protocols: invalid selection: {exc}")
        expected = []

    gateway = extract_gateway_samples(results)

    # Surface invalid/zero-total gateway samples as harness failures even when
    # a sibling valid sample for the same protocol exists.
    for proto, samples in sorted(gateway.items()):
        invalid = [s for s in samples if not is_valid_gateway_sample(s)]
        if invalid:
            hard_fail(
                failures,
                f"{proto}: {len(invalid)} invalid/zero-total gateway sample(s) "
                "(harness data-quality failure)",
            )

    for proto in expected:
        samples = [s for s in gateway.get(proto, []) if is_valid_gateway_sample(s)]
        if not samples:
            hard_fail(
                failures,
                f"{proto}: missing expected gateway measurement "
                "(require at least one valid sample)",
            )
            continue

        rps_vals = [
            value
            for value in (parse_nonnegative_number(s.get("rps", 0.0)) for s in samples)
            if value is not None
        ]
        p50_vals = [
            value
            for value in (parse_nonnegative_number(s.get("p50_us", 0)) for s in samples)
            if value is not None
        ]
        p95_vals = []
        for sample in samples:
            raw = sample.get("p95_us")
            if raw is None:
                raw = sample.get("p90_us", 0)
            parsed = parse_nonnegative_number(raw)
            if parsed is not None:
                p95_vals.append(parsed)
        p99_vals = [
            value
            for value in (parse_nonnegative_number(s.get("p99_us", 0)) for s in samples)
            if value is not None
        ]
        err_vals = [rate for rate in (error_rate(s) for s in samples) if rate is not None]

        if not rps_vals or not p50_vals or not p99_vals:
            hard_fail(
                failures,
                f"{proto}: gateway samples failed finite metric extraction "
                "(harness data-quality failure)",
            )
            continue

        summary = {
            "samples": len(samples),
            "rps": median(rps_vals),
            "error_rate": median(err_vals) if err_vals else 0.0,
            "p50_us": median(p50_vals),
            "p95_us": median(p95_vals) if p95_vals else 0.0,
            "p99_us": median(p99_vals),
        }
        protocol_summary[proto] = summary

        proto_budget = budget_protocols.get(proto, {})
        max_error = proto_budget.get("max_error_rate", global_cfg.get("max_error_rate"))
        if max_error is not None and summary["error_rate"] > float(max_error):
            note(
                f"{proto}: error_rate {summary['error_rate']:.4f} exceeds budget {float(max_error):.4f}"
            )

        for key, metric, higher_is_worse in (
            ("min_gateway_rps", "rps", False),
            ("max_p50_us", "p50_us", True),
            ("max_p95_us", "p95_us", True),
            ("max_p99_us", "p99_us", True),
        ):
            budget_value = proto_budget.get(key)
            if budget_value is None:
                continue
            current = float(summary[metric])
            limit = float(budget_value)
            if higher_is_worse and current > limit:
                note(f"{proto}: {metric}={current:.1f} exceeds budget {limit:.1f}")
            if not higher_is_worse and current < limit:
                note(f"{proto}: {metric}={current:.1f} below budget {limit:.1f}")

        for metric, higher_is_worse in (
            ("rps", False),
            ("p50_us", True),
            ("p95_us", True),
            ("p99_us", True),
            ("error_rate", True),
        ):
            breach = rolling_breach(
                float(summary[metric]),
                history_metric(history_doc, proto, metric)[-window:],
                mad_multiplier=mad_multiplier,
                min_samples=min_samples,
                higher_is_worse=higher_is_worse,
            )
            if breach:
                note(f"{proto}: rolling {metric} regression: {breach}")

    scenarios = results.get("scenarios", {})
    validate_required_scenarios(
        scenarios,
        min_resource_samples=min_resource_samples,
        failures=failures,
    )

    if isinstance(scenarios, dict):
        plateau = scenarios.get("resource_plateau", {})
        if isinstance(plateau, dict) and plateau:
            for resource, growth_key in (
                ("rss_bytes", "max_rss_growth_ratio"),
                ("fd_count", "max_fd_growth_ratio"),
                ("task_count", "max_task_growth_ratio"),
            ):
                series = plateau.get(resource, [])
                if resource_series_structurally_valid(series, min_samples=2) is not None:
                    continue
                start = parse_nonnegative_number(series[0])
                end = parse_nonnegative_number(series[-1])
                if start is None or end is None or start <= 0:
                    continue
                growth = end / start
                limit = float(global_cfg.get(growth_key, 2.5))
                if growth > limit:
                    note(
                        f"resource_plateau: {resource} grew {growth:.2f}x "
                        f"({start:.0f} -> {end:.0f}), limit {limit:.2f}x"
                    )

        reload = scenarios.get("reload_under_load", {})
        if isinstance(reload, dict) and reload.get("sample") is not None:
            rate = parse_unit_rate(reload.get("error_rate", 0.0))
            if rate is None:
                hard_fail(
                    failures,
                    "scenarios: reload_under_load has non-finite/malformed error_rate "
                    "(require finite rate in [0, 1])",
                )
            else:
                limit = float(global_cfg.get("reload_max_error_rate", 0.15))
                if rate > limit:
                    note(f"reload_under_load: error_rate {rate:.4f} exceeds {limit:.4f}")

        churn = scenarios.get("connection_churn", {})
        if isinstance(churn, dict) and churn.get("sample") is not None:
            rate = parse_unit_rate(churn.get("error_rate", 0.0))
            if rate is None:
                hard_fail(
                    failures,
                    "scenarios: connection_churn has non-finite/malformed error_rate "
                    "(require finite rate in [0, 1])",
                )
            else:
                limit = float(global_cfg.get("max_error_rate", 0.05))
                if rate > limit:
                    note(f"connection_churn: error_rate {rate:.4f} exceeds {limit:.4f}")

    status = "failed" if failures else ("alert" if alerts else "ok")
    return {
        "budget_version": budgets.get("budget_version"),
        "enforcement": enforcement,
        "status": status,
        "alerts": alerts,
        "failures": failures,
        "expected_protocols": expected,
        "protocols": protocol_summary,
        "scenarios": scenarios if isinstance(scenarios, dict) else {},
        "runner_health": results.get("runner_health", {}),
    }


def build_trends_point(
    results: dict[str, Any], evaluation: dict[str, Any]
) -> dict[str, Any]:
    return {
        "commit": results.get("commit"),
        "run_id": results.get("run_id"),
        "timestamp": results.get("timestamp"),
        "runner_class": results.get("runner_class"),
        "build_profile": results.get("build_profile"),
        "budget_version": evaluation.get("budget_version"),
        "protocols": evaluation.get("protocols", {}),
        "scenarios": {
            key: value
            for key, value in evaluation.get("scenarios", {}).items()
            if key in {"connection_churn", "reload_under_load", "resource_plateau", "soak"}
        },
        "runner_health": evaluation.get("runner_health", {}),
    }


def merge_history(
    history_doc: dict[str, Any] | None, point: dict[str, Any], window: int
) -> dict[str, Any]:
    points = []
    if history_doc and isinstance(history_doc.get("points"), list):
        points.extend(history_doc["points"])
    points.append(point)
    return {
        "schema_version": 1,
        "points": points[-window:],
    }


def _clean_results_fixture() -> dict[str, Any]:
    return {
        "protocols": "http1",
        "runs": {
            "run_1": [
                {
                    "protocol": "HTTP/1.1",
                    "target": "http://127.0.0.1:8000/echo",
                    "rps": 1000.0,
                    "total_requests": 1000,
                    "total_errors": 0,
                    "p50_us": 100,
                    "p95_us": 200,
                    "p99_us": 300,
                }
            ]
        },
        "scenarios": {
            "resource_plateau": {
                "rss_bytes": [100, 110, 120],
                "fd_count": [20, 21, 22],
                "task_count": [10, 10, 11],
                "sample_count": 3,
            },
            "reload_under_load": {
                "error_rate": 0.01,
                "sample": {
                    "total_requests": 100,
                    "total_errors": 1,
                    "rps": 10.0,
                },
            },
            "connection_churn": {
                "error_rate": 0.01,
                "sample": {
                    "total_requests": 100,
                    "total_errors": 1,
                    "rps": 10.0,
                },
            },
            "soak": {
                "sample": {
                    "heartbeat_success_rate": 0.99,
                    "connect_success_rate": 0.99,
                },
            },
        },
    }


def self_test() -> int:
    failures: list[str] = []

    budgets = {
        "budget_version": "test",
        "enforcement": "alert",
        "rolling": {"window": 8, "mad_multiplier": 5.0, "min_samples": 3},
        "global": {
            "max_error_rate": 0.05,
            "max_rss_growth_ratio": 2.0,
            "max_fd_growth_ratio": 2.0,
            "max_task_growth_ratio": 2.0,
            "reload_max_error_rate": 0.1,
            "min_resource_samples": 3,
        },
        "protocols": {
            "HTTP/1.1": {
                "min_gateway_rps": None,
                "max_p50_us": None,
                "max_p95_us": None,
                "max_p99_us": None,
                "max_error_rate": 0.05,
            },
            "HTTP/2": {
                "min_gateway_rps": None,
                "max_p50_us": None,
                "max_p95_us": None,
                "max_p99_us": None,
                "max_error_rate": 0.05,
            },
        },
    }
    results = _clean_results_fixture()
    evaluation = evaluate(results, budgets, None)
    if evaluation["status"] != "ok":
        failures.append(
            f"clean run expected ok, got {evaluation['status']}: "
            f"alerts={evaluation['alerts']} failures={evaluation['failures']}"
        )

    # Missing expected protocol (selection=all) must hard-fail.
    missing = json.loads(json.dumps(results))
    missing["protocols"] = "all"
    evaluation = evaluate(missing, budgets, None)
    if evaluation["status"] != "failed":
        failures.append("missing expected protocol should hard-fail")
    if not any("HTTP/2" in msg and "missing expected" in msg for msg in evaluation["failures"]):
        failures.append("missing HTTP/2 should be reported as hard failure")

    # Subset selection must not require unselected protocols.
    subset = json.loads(json.dumps(results))
    subset["protocols"] = "http1"
    evaluation = evaluate(subset, budgets, None)
    if evaluation["status"] != "ok":
        failures.append(
            f"http1 subset should not require HTTP/2, got {evaluation['status']}: "
            f"{evaluation['failures']}"
        )
    if evaluation.get("expected_protocols") != ["HTTP/1.1"]:
        failures.append(
            f"http1 subset expected_protocols mismatch: {evaluation.get('expected_protocols')}"
        )

    # Zero-total / invalid metrics must hard-fail.
    zero_total = json.loads(json.dumps(results))
    zero_total["runs"]["run_1"][0]["total_requests"] = 0
    zero_total["runs"]["run_1"][0]["total_errors"] = 0
    evaluation = evaluate(zero_total, budgets, None)
    if evaluation["status"] != "failed":
        failures.append("zero-total gateway sample should hard-fail")
    if not any("invalid/zero-total" in msg or "missing expected" in msg for msg in evaluation["failures"]):
        failures.append("zero-total should produce data-quality failure text")

    if error_rate({"total_requests": 0, "total_errors": 0}) is not None:
        failures.append("error_rate must return None for zero-total samples")

    # Non-finite / malformed gateway metrics must hard-fail without raising.
    nan_rps = json.loads(json.dumps(results))
    nan_rps["runs"]["run_1"][0]["rps"] = float("nan")
    try:
        evaluation = evaluate(nan_rps, budgets, None)
    except Exception as exc:  # pragma: no cover - defensive self-test
        failures.append(f"NaN rps must not raise, got {type(exc).__name__}: {exc}")
    else:
        if evaluation["status"] != "failed":
            failures.append("NaN rps should hard-fail")
        if not any(
            "invalid/zero-total" in msg or "missing expected" in msg or "data-quality" in msg
            for msg in evaluation["failures"]
        ):
            failures.append("NaN rps should produce data-quality failure text")

    inf_p99 = json.loads(json.dumps(results))
    inf_p99["runs"]["run_1"][0]["p99_us"] = float("inf")
    try:
        evaluation = evaluate(inf_p99, budgets, None)
    except Exception as exc:  # pragma: no cover - defensive self-test
        failures.append(f"Infinity p99 must not raise, got {type(exc).__name__}: {exc}")
    else:
        if evaluation["status"] != "failed":
            failures.append("Infinity p99 should hard-fail")

    malformed_counts = json.loads(json.dumps(results))
    malformed_counts["runs"]["run_1"][0]["total_requests"] = "not-a-number"
    try:
        evaluation = evaluate(malformed_counts, budgets, None)
    except Exception as exc:  # pragma: no cover - defensive self-test
        failures.append(
            f"malformed total_requests must not raise, got {type(exc).__name__}: {exc}"
        )
    else:
        if evaluation["status"] != "failed":
            failures.append("malformed total_requests should hard-fail")
        if not any(
            "invalid/zero-total" in msg or "missing expected" in msg or "data-quality" in msg
            for msg in evaluation["failures"]
        ):
            failures.append("malformed total_requests should produce data-quality failure text")

    null_errors = json.loads(json.dumps(results))
    null_errors["runs"]["run_1"][0]["total_errors"] = None
    try:
        evaluation = evaluate(null_errors, budgets, None)
    except Exception as exc:  # pragma: no cover - defensive self-test
        failures.append(f"null total_errors must not raise, got {type(exc).__name__}: {exc}")
    else:
        if evaluation["status"] != "failed":
            failures.append("null total_errors should hard-fail")

    if sample_total({"total_requests": "bad", "total_errors": 1}) is not None:
        failures.append("sample_total must return None for malformed counts")
    oversized_sample = {"total_requests": 10**1000, "total_errors": 1}
    if sample_total(oversized_sample) is not None:
        failures.append("sample_total must reject adversarially large counts")
    if parse_finite_number(float("nan")) is not None:
        failures.append("parse_finite_number must reject NaN")
    if parse_unit_rate(1.5) is not None:
        failures.append("parse_unit_rate must reject rates above 1")

    # Finite zero-RPS / large latency remain alert-only measured outcomes.
    zero_rps = json.loads(json.dumps(results))
    zero_rps["runs"]["run_1"][0]["rps"] = 0.0
    zero_rps_budgets = json.loads(json.dumps(budgets))
    zero_rps_budgets["protocols"]["HTTP/1.1"]["min_gateway_rps"] = 100.0
    evaluation = evaluate(zero_rps, zero_rps_budgets, None)
    if evaluation["status"] != "alert":
        failures.append(
            "finite zero-RPS should alert-only under alert enforcement, got "
            f"{evaluation['status']}: {evaluation['failures']}"
        )
    if evaluation["failures"]:
        failures.append("finite zero-RPS must not hard-fail under alert enforcement")

    huge_latency = json.loads(json.dumps(results))
    huge_latency["runs"]["run_1"][0]["p99_us"] = 50_000_000.0
    huge_latency_budgets = json.loads(json.dumps(budgets))
    huge_latency_budgets["protocols"]["HTTP/1.1"]["max_p99_us"] = 1_000.0
    evaluation = evaluate(huge_latency, huge_latency_budgets, None)
    if evaluation["status"] != "alert":
        failures.append(
            "finite large latency should alert-only under alert enforcement, got "
            f"{evaluation['status']}: {evaluation['failures']}"
        )
    if evaluation["failures"]:
        failures.append("finite large latency must not hard-fail under alert enforcement")

    # Required scenario absence / invalid sample must hard-fail.
    no_scenarios = json.loads(json.dumps(results))
    no_scenarios["scenarios"] = {}
    evaluation = evaluate(no_scenarios, budgets, None)
    if evaluation["status"] != "failed":
        failures.append("missing scenarios should hard-fail")
    if not any("missing required scenario" in msg for msg in evaluation["failures"]):
        failures.append("missing scenarios should mention required scenario output")

    bad_churn = json.loads(json.dumps(results))
    bad_churn["scenarios"]["connection_churn"]["sample"] = None
    evaluation = evaluate(bad_churn, budgets, None)
    if evaluation["status"] != "failed":
        failures.append("null connection_churn sample should hard-fail")

    nan_heartbeat = json.loads(json.dumps(results))
    nan_heartbeat["scenarios"]["soak"]["sample"] = {
        "heartbeat_success_rate": float("nan"),
        "connect_success_rate": 0.99,
    }
    evaluation = evaluate(nan_heartbeat, budgets, None)
    if evaluation["status"] != "failed":
        failures.append("NaN heartbeat_success_rate should hard-fail")
    if not any("soak" in msg and "usable" in msg for msg in evaluation["failures"]):
        failures.append("NaN heartbeat should report soak sample usability failure")

    nan_saturate_rps = json.loads(json.dumps(results))
    nan_saturate_rps["scenarios"]["soak"]["sample"] = {
        "rps": float("nan"),
        "heartbeat_success_rate": 0.99,
        "connect_success_rate": 0.99,
    }
    evaluation = evaluate(nan_saturate_rps, budgets, None)
    if evaluation["status"] != "failed":
        failures.append("NaN saturate rps should hard-fail")
    if not any("soak" in msg and "usable" in msg for msg in evaluation["failures"]):
        failures.append("NaN saturate rps should report soak sample usability failure")

    nan_error_rate = json.loads(json.dumps(results))
    nan_error_rate["scenarios"]["connection_churn"]["error_rate"] = float("nan")
    evaluation = evaluate(nan_error_rate, budgets, None)
    if evaluation["status"] != "failed":
        failures.append("NaN scenario error_rate should hard-fail")
    if not any("error_rate" in msg for msg in evaluation["failures"]):
        failures.append("NaN scenario error_rate should mention malformed error_rate")

    thin_plateau = json.loads(json.dumps(results))
    thin_plateau["scenarios"]["resource_plateau"]["rss_bytes"] = [100]
    thin_plateau["scenarios"]["resource_plateau"]["fd_count"] = [20]
    thin_plateau["scenarios"]["resource_plateau"]["task_count"] = [10]
    evaluation = evaluate(thin_plateau, budgets, None)
    if evaluation["status"] != "failed":
        failures.append("insufficient resource sampling should hard-fail")
    if not any("insufficient rss_bytes" in msg for msg in evaluation["failures"]):
        failures.append("insufficient RSS sampling should be reported")

    nan_plateau = json.loads(json.dumps(results))
    nan_plateau["scenarios"]["resource_plateau"]["rss_bytes"] = [100, float("nan"), 120]
    evaluation = evaluate(nan_plateau, budgets, None)
    if evaluation["status"] != "failed":
        failures.append("non-finite resource plateau values should hard-fail")
    if not any(
        "rss_bytes" in msg and ("non-finite" in msg or "malformed" in msg)
        for msg in evaluation["failures"]
    ):
        failures.append("non-finite RSS plateau should mention malformed/non-finite values")

    # Complete measured regression remains alert-only under enforcement=alert.
    noisy = json.loads(json.dumps(results))
    noisy["runs"]["run_1"][0]["total_errors"] = 200
    noisy["runs"]["run_1"][0]["total_requests"] = 800
    evaluation = evaluate(noisy, budgets, None)
    if evaluation["status"] != "alert":
        failures.append(
            f"high error rate should alert under alert enforcement, got {evaluation['status']}: "
            f"{evaluation['failures']}"
        )
    if not evaluation["alerts"]:
        failures.append("high error rate should produce alerts")
    if evaluation["failures"]:
        failures.append("measured regression must not hard-fail under alert enforcement")

    gate_budgets = json.loads(json.dumps(budgets))
    gate_budgets["enforcement"] = "gate"
    evaluation = evaluate(noisy, gate_budgets, None)
    if evaluation["status"] != "failed" or not evaluation["failures"]:
        failures.append("gate enforcement should fail on budget breach")

    history = {
        "points": [
            {"protocols": {"HTTP/1.1": {"rps": 1000.0, "p99_us": 300.0, "error_rate": 0.0}}},
            {"protocols": {"HTTP/1.1": {"rps": 1010.0, "p99_us": 310.0, "error_rate": 0.0}}},
            {"protocols": {"HTTP/1.1": {"rps": 990.0, "p99_us": 290.0, "error_rate": 0.0}}},
        ]
    }
    collapsed = json.loads(json.dumps(results))
    collapsed["runs"]["run_1"][0]["rps"] = 100.0
    evaluation = evaluate(collapsed, budgets, history)
    if evaluation["status"] != "alert":
        failures.append("collapsed RPS should remain alert-only under alert enforcement")
    if not any("rolling rps regression" in alert for alert in evaluation["alerts"]):
        failures.append("collapsed RPS should trip rolling baseline alert")

    leaky = json.loads(json.dumps(results))
    leaky["scenarios"]["resource_plateau"]["rss_bytes"] = [100, 400, 500]
    evaluation = evaluate(leaky, budgets, None)
    if evaluation["status"] != "alert":
        failures.append("RSS growth should alert-only under alert enforcement")
    if not any("rss_bytes" in alert for alert in evaluation["alerts"]):
        failures.append("RSS plateau growth should alert")

    if error_rate({"total_requests": 90, "total_errors": 10}) != 0.1:
        failures.append("error_rate calculation mismatch")

    if not math.isclose(mad([1.0, 2.0, 3.0], 2.0), 1.0):
        failures.append("MAD calculation mismatch")

    if resolve_expected_protocols("http1,http2", budgets["protocols"]) != [
        "HTTP/1.1",
        "HTTP/2",
    ]:
        failures.append("resolve_expected_protocols comma-subset mismatch")

    if failures:
        for failure in failures:
            print(f"::error::self-test: {failure}")
        return 1

    print("protocol budget evaluator self-test passed")
    return 0


def main() -> int:
    args = parse_args()
    if args.self_test:
        return self_test()

    missing = [
        name
        for name, value in (
            ("--results", args.results),
            ("--budgets", args.budgets),
            ("--trends-out", args.trends_out),
            ("--report-out", args.report_out),
        )
        if value is None
    ]
    if missing:
        print(f"::error::missing required args: {', '.join(missing)}")
        return 2

    results = json.loads(args.results.read_text(encoding="utf-8"))
    budgets = json.loads(args.budgets.read_text(encoding="utf-8"))
    history_doc = None
    if args.history and args.history.is_file():
        history_doc = json.loads(args.history.read_text(encoding="utf-8"))

    evaluation = evaluate(results, budgets, history_doc)
    point = build_trends_point(results, evaluation)
    window = int(budgets.get("rolling", {}).get("window", 8))
    trends = merge_history(history_doc, point, window)

    args.report_out.parent.mkdir(parents=True, exist_ok=True)
    args.trends_out.parent.mkdir(parents=True, exist_ok=True)
    args.report_out.write_text(json.dumps(evaluation, indent=2) + "\n", encoding="utf-8")
    args.trends_out.write_text(json.dumps(trends, indent=2) + "\n", encoding="utf-8")

    print(json.dumps(evaluation, indent=2))
    for alert in evaluation["alerts"]:
        print(f"::warning::{alert}")
    if evaluation["failures"]:
        for failure in evaluation["failures"]:
            print(f"::error::{failure}")
        return 1

    print(
        f"protocol budget evaluation status={evaluation['status']} "
        f"enforcement={evaluation['enforcement']} "
        f"budget_version={evaluation.get('budget_version')}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
