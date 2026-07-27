#!/usr/bin/env python3
"""Evaluate multi-protocol regression results against versioned budgets.

Publishes machine-readable trends and compares the current run against:
  * explicit per-protocol budgets in protocol_perf_budgets.json
  * a rolling median ± MAD baseline when prior trend samples are present

Enforcement defaults to alert-only so shared-runner variance does not fail the
scheduled job until absolute floors are filled in after measured variance.
"""

from __future__ import annotations

import argparse
import json
import math
import statistics
import sys
from pathlib import Path
from typing import Any


GATEWAY_PORT_MARKERS = (":8000", ":8443", ":5010", ":5001", ":5003", ":5004")


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


def error_rate(sample: dict[str, Any]) -> float:
    total = int(sample.get("total_requests", 0)) + int(sample.get("total_errors", 0))
    if total <= 0:
        return 0.0
    return float(sample.get("total_errors", 0)) / float(total)


def normalize_protocol_name(name: str) -> str:
    return name.strip()


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

    gateway = extract_gateway_samples(results)
    alerts: list[str] = []
    failures: list[str] = []
    protocol_summary: dict[str, Any] = {}

    def note(message: str) -> None:
        alerts.append(message)
        if enforcement == "gate":
            failures.append(message)

    for proto, samples in sorted(gateway.items()):
        rps_vals = [float(s.get("rps", 0.0)) for s in samples]
        p50_vals = [float(s.get("p50_us", 0)) for s in samples]
        p95_vals = [
            float(s["p95_us"]) if s.get("p95_us") is not None else float(s.get("p90_us", 0))
            for s in samples
        ]
        p99_vals = [float(s.get("p99_us", 0)) for s in samples]
        err_vals = [error_rate(s) for s in samples]

        summary = {
            "samples": len(samples),
            "rps": median(rps_vals) if rps_vals else 0.0,
            "error_rate": median(err_vals) if err_vals else 0.0,
            "p50_us": median(p50_vals) if p50_vals else 0.0,
            "p95_us": median(p95_vals) if p95_vals else 0.0,
            "p99_us": median(p99_vals) if p99_vals else 0.0,
        }
        protocol_summary[proto] = summary

        proto_budget = budgets.get("protocols", {}).get(proto, {})
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
    if isinstance(scenarios, dict):
        plateau = scenarios.get("resource_plateau", {})
        if isinstance(plateau, dict) and plateau:
            for resource, growth_key in (
                ("rss_bytes", "max_rss_growth_ratio"),
                ("fd_count", "max_fd_growth_ratio"),
                ("task_count", "max_task_growth_ratio"),
            ):
                series = plateau.get(resource, [])
                if len(series) < 2:
                    continue
                start = float(series[0])
                end = float(series[-1])
                if start <= 0:
                    continue
                growth = end / start
                limit = float(global_cfg.get(growth_key, 2.5))
                if growth > limit:
                    note(
                        f"resource_plateau: {resource} grew {growth:.2f}x "
                        f"({start:.0f} -> {end:.0f}), limit {limit:.2f}x"
                    )

        reload = scenarios.get("reload_under_load", {})
        if isinstance(reload, dict) and reload:
            rate = float(reload.get("error_rate", 0.0))
            limit = float(global_cfg.get("reload_max_error_rate", 0.15))
            if rate > limit:
                note(f"reload_under_load: error_rate {rate:.4f} exceeds {limit:.4f}")

        churn = scenarios.get("connection_churn", {})
        if isinstance(churn, dict) and churn:
            rate = float(churn.get("error_rate", 0.0))
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
        },
        "protocols": {
            "HTTP/1.1": {
                "min_gateway_rps": None,
                "max_p50_us": None,
                "max_p95_us": None,
                "max_p99_us": None,
                "max_error_rate": 0.05,
            }
        },
    }
    results = {
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
            },
            "reload_under_load": {"error_rate": 0.01},
            "connection_churn": {"error_rate": 0.01},
        },
    }
    evaluation = evaluate(results, budgets, None)
    if evaluation["status"] != "ok":
        failures.append(f"clean run expected ok, got {evaluation['status']}: {evaluation['alerts']}")

    noisy = json.loads(json.dumps(results))
    noisy["runs"]["run_1"][0]["total_errors"] = 200
    noisy["runs"]["run_1"][0]["total_requests"] = 800
    evaluation = evaluate(noisy, budgets, None)
    if evaluation["status"] != "alert":
        failures.append("high error rate should alert under alert enforcement")
    if not evaluation["alerts"]:
        failures.append("high error rate should produce alerts")

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
    if not any("rolling rps regression" in alert for alert in evaluation["alerts"]):
        failures.append("collapsed RPS should trip rolling baseline alert")

    leaky = json.loads(json.dumps(results))
    leaky["scenarios"]["resource_plateau"]["rss_bytes"] = [100, 400]
    evaluation = evaluate(leaky, budgets, None)
    if not any("rss_bytes" in alert for alert in evaluation["alerts"]):
        failures.append("RSS plateau growth should alert")

    if error_rate({"total_requests": 90, "total_errors": 10}) != 0.1:
        failures.append("error_rate calculation mismatch")

    if not math.isclose(mad([1.0, 2.0, 3.0], 2.0), 1.0):
        failures.append("MAD calculation mismatch")

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
