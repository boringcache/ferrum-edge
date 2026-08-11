#!/usr/bin/env python3
"""Summarize hosted mesh/HBONE/DNS baseline artifacts into machine-readable JSON.

Reads Criterion estimates.json trees and E2E JSON blobs produced by the
mesh-performance-baselines workflow. Never fabricates measurements: missing
inputs become explicit null/incomplete entries. Publication gates fail closed
on undersampling, missing DNS rows, malformed metrics, nonzero errors, or
excessive CPU steal.
"""

from __future__ import annotations

import argparse
import json
import math
import statistics
import sys
import tempfile
from pathlib import Path
from typing import Any


AUTHZ_SIZES = (10, 100, 1_000, 10_000)
SLICE_SIZES = (100, 1_000, 5_000)
IP_CASES = (
    ("deny_miss", 1),
    ("deny_miss", 4),
    ("high_match", 1),
    ("high_match", 4),
)
HBONE_SCENARIOS = (
    {"key": "1kib_c50_30s", "payload": 1024, "concurrency": 50, "duration": 30},
    {"key": "16kib_c50_30s", "payload": 16384, "concurrency": 50, "duration": 30},
    {"key": "256kib_c100_60s", "payload": 262144, "concurrency": 100, "duration": 60},
)
DNS_GATEWAY_ROWS = (
    ("mesh-internal", "udp"),
    ("mesh-internal", "tcp"),
    ("mesh-wildcard", "udp"),
    ("mesh-wildcard", "tcp"),
    ("upstream-forward", "udp"),
    ("upstream-forward", "tcp"),
)
DNS_DIRECT_ROWS = (
    ("upstream-forward", "udp"),
    ("upstream-forward", "tcp"),
)
MIN_E2E_REPETITIONS = 3
# Documented publication threshold: same 5.0% CPU-steal ceiling used across
# Ferrum hosted perf workflows. Collections above this are not publication-ready.
MAX_CPU_STEAL_PERCENT = 5.0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-root", type=Path)
    parser.add_argument("--provenance", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--draft-markdown-dir", type=Path)
    parser.add_argument(
        "--expected-repetitions",
        type=int,
        default=None,
        help="Configured E2E repetition count (floored at 3)",
    )
    parser.add_argument(
        "--suites",
        default="all",
        help="Selected suite filter: all | mesh | hbone | dns",
    )
    parser.add_argument(
        "--check-acceptance",
        action="store_true",
        help="Exit non-zero when selected-suite publication gates fail",
    )
    parser.add_argument(
        "--summary",
        type=Path,
        help="Existing summary.json path for --check-acceptance",
    )
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.check_acceptance:
        if args.summary is None:
            parser.error("--check-acceptance requires --summary")
        return args
    if not args.self_test:
        missing = [
            name
            for name in (
                "results_root",
                "provenance",
                "output",
                "draft_markdown_dir",
            )
            if getattr(args, name) is None
        ]
        if missing:
            parser.error(
                "the following arguments are required unless --self-test: "
                + ", ".join(f"--{name.replace('_', '-')}" for name in missing)
            )
    return args


def required_repetitions(configured: int | None) -> int:
    if configured is None:
        return MIN_E2E_REPETITIONS
    return max(MIN_E2E_REPETITIONS, int(configured))


def load_json(path: Path) -> Any | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def fmt_duration_ns(ns: float) -> str:
    if not math.isfinite(ns) or ns < 0:
        return "n/a"
    if ns >= 1_000_000_000:
        return f"{ns / 1_000_000_000:.3f} s"
    if ns >= 1_000_000:
        return f"{ns / 1_000_000:.3f} ms"
    if ns >= 1_000:
        return f"{ns / 1_000:.3f} µs"
    return f"{ns:.1f} ns"


def fmt_us(us: float | int | None) -> str:
    if us is None:
        return "n/a"
    try:
        us_f = float(us)
    except (TypeError, ValueError):
        return "n/a"
    if not math.isfinite(us_f):
        return "n/a"
    if us_f >= 1_000_000:
        return f"{us_f / 1_000_000:.2f}s"
    if us_f >= 1_000:
        return f"{us_f / 1_000:.2f}ms"
    return f"{us_f:.0f}µs"


def fmt_rps(v: float | None) -> str:
    if v is None:
        return "n/a"
    if not math.isfinite(v):
        return "n/a"
    return f"{v:,.0f}"


def fmt_pct(v: float | None) -> str:
    if v is None:
        return "n/a"
    if not math.isfinite(v):
        return "n/a"
    return f"{v:.1f}%"


def mean_stdev(values: list[float]) -> tuple[float | None, float | None, float | None, float | None]:
    if not values:
        return None, None, None, None
    mean_v = statistics.mean(values)
    stdev_v = statistics.stdev(values) if len(values) > 1 else 0.0
    return mean_v, stdev_v, min(values), max(values)


def parse_finite_number(value: Any, *, positive: bool = False, non_negative: bool = False) -> float | None:
    """Parse a finite number; reject bools, strings that coerce poorly, NaN/Inf."""
    if isinstance(value, bool) or value is None:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(number):
        return None
    if positive and number <= 0:
        return None
    if non_negative and number < 0:
        return None
    return number


def parse_non_negative_int(value: Any) -> int | None:
    number = parse_finite_number(value, non_negative=True)
    if number is None:
        return None
    if abs(number - round(number)) > 1e-9:
        return None
    return int(round(number))


def criterion_mean(path: Path) -> dict[str, Any] | None:
    data = load_json(path)
    if not isinstance(data, dict):
        return None
    mean = data.get("mean")
    std_dev = data.get("std_dev")
    if not isinstance(mean, dict):
        return None
    if std_dev is not None and not isinstance(std_dev, dict):
        return None
    point = parse_finite_number(mean.get("point_estimate"), positive=True)
    if point is None:
        return None
    ci = mean.get("confidence_interval")
    if ci is not None and not isinstance(ci, dict):
        return None
    ci = ci or {}
    lower = parse_finite_number(ci.get("lower_bound", point), non_negative=True)
    upper = parse_finite_number(ci.get("upper_bound", point), non_negative=True)
    stdev = parse_finite_number(
        (std_dev or {}).get("point_estimate", 0.0),
        non_negative=True,
    )
    if lower is None or upper is None or stdev is None:
        return None
    return {
        "mean_ns": point,
        "stdev_ns": stdev,
        "ci_lower_ns": lower,
        "ci_upper_ns": upper,
        "mean_display": fmt_duration_ns(point),
        "stdev_display": fmt_duration_ns(stdev),
        "source": str(path),
    }


def extract_json_blobs(text: str) -> list[Any]:
    decoder = json.JSONDecoder()
    blobs: list[Any] = []
    i = 0
    while i < len(text):
        idx = text.find("{", i)
        if idx == -1:
            break
        try:
            obj, end = decoder.raw_decode(text, idx)
            blobs.append(obj)
            i = end
        except json.JSONDecodeError:
            i = idx + 1
    return blobs


def summarize_mesh(criterion_root: Path) -> dict[str, Any]:
    authz = {}
    for size in AUTHZ_SIZES:
        estimates = (
            criterion_root
            / "authz_match"
            / "policies"
            / str(size)
            / "new"
            / "estimates.json"
        )
        authz[str(size)] = criterion_mean(estimates)

    ip_rows = {}
    for decision, instances in IP_CASES:
        key = f"{decision}_{instances}"
        estimates = (
            criterion_root
            / "ip_restriction_lookup"
            / f"{decision}_10000_rules_{instances}_instances"
            / "new"
            / "estimates.json"
        )
        ip_rows[key] = criterion_mean(estimates)

    slice_rows = {}
    for size in SLICE_SIZES:
        estimates = (
            criterion_root
            / "slice_apply"
            / "workloads"
            / str(size)
            / "new"
            / "estimates.json"
        )
        slice_rows[str(size)] = criterion_mean(estimates)

    xds_rows = {}
    for size in SLICE_SIZES:
        estimates = (
            criterion_root
            / "xds_translation"
            / "workloads"
            / str(size)
            / "new"
            / "estimates.json"
        )
        xds_rows[str(size)] = criterion_mean(estimates)

    return {
        "authz_match": authz,
        "ip_restriction": ip_rows,
        "slice_apply": slice_rows,
        "xds_translation": xds_rows,
    }


def classify_hbone_blob(blob: dict[str, Any]) -> str | None:
    target = str(blob.get("target", ""))
    label = str(blob.get("label", "")).lower()
    if ":18000" in target or "gateway" in label or "hbone" in label:
        return "gateway"
    if "direct" in label or ("127.0.0.1:" in target and ":18000" not in target):
        return "direct"
    return None


def parse_hbone_sample(blob: dict[str, Any], source: str) -> dict[str, Any] | None:
    """Fail closed on malformed / non-finite / non-positive HBONE metrics."""
    if "rps" not in blob:
        return None
    rps = parse_finite_number(blob.get("rps"), positive=True)
    p50 = parse_finite_number(blob.get("p50_us"), non_negative=True)
    p95 = parse_finite_number(blob.get("p95_us"), non_negative=True)
    p99 = parse_finite_number(blob.get("p99_us"), non_negative=True)
    errors = parse_non_negative_int(blob.get("total_errors", 0))
    if None in (rps, p50, p95, p99, errors):
        return None
    kind = classify_hbone_blob(blob)
    if kind is None:
        return None
    return {
        "kind": kind,
        "rps": rps,
        "p50_us": p50,
        "p95_us": p95,
        "p99_us": p99,
        "total_errors": errors,
        "source": source,
    }


def parse_dns_report(report: dict[str, Any], source: str) -> dict[str, Any] | None:
    """Fail closed on malformed / non-finite / non-positive DNS report rows."""
    class_name = report.get("name_class")
    transport = report.get("transport")
    if not isinstance(class_name, str) or not class_name:
        return None
    if not isinstance(transport, str) or not transport:
        return None
    qps = parse_finite_number(report.get("qps"), positive=True)
    p50 = parse_finite_number(report.get("p50_us"), non_negative=True)
    p90 = parse_finite_number(report.get("p90_us"), non_negative=True)
    p99 = parse_finite_number(report.get("p99_us"), non_negative=True)
    errors = parse_non_negative_int(report.get("total_errors", 0))
    if None in (qps, p50, p90, p99, errors):
        return None
    return {
        "name_class": class_name,
        "transport": transport,
        "qps": qps,
        "p50_us": p50,
        "p95_us": p90,  # retained for draft compatibility naming
        "p90_us": p90,
        "p99_us": p99,
        "total_errors": errors,
        "source": source,
    }


def aggregate_throughput_samples(
    samples: list[dict[str, Any]],
    *,
    rate_key: str,
    latency_keys: tuple[str, ...],
) -> dict[str, Any] | None:
    if not samples:
        return None
    rate_vals = [s[rate_key] for s in samples]
    mean_rate, stdev_rate, min_rate, max_rate = mean_stdev(rate_vals)
    out: dict[str, Any] = {
        "repetitions": len(samples),
        f"{rate_key}_mean": mean_rate,
        f"{rate_key}_stdev": stdev_rate,
        f"{rate_key}_min": min_rate,
        f"{rate_key}_max": max_rate,
        "total_errors_sum": sum(s["total_errors"] for s in samples),
        "samples": samples,
    }
    for key in latency_keys:
        out[f"{key}_mean"] = statistics.mean(s[key] for s in samples)
    return out


def repetition_evidence(actual: int, required: int) -> dict[str, Any]:
    return {
        "actual": actual,
        "required": required,
        "ok": actual >= required,
    }


def summarize_hbone(hbone_root: Path, required_reps: int) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for scenario in HBONE_SCENARIOS:
        key = scenario["key"]
        scenario_dir = hbone_root / key
        run_stats: dict[str, list[dict[str, Any]]] = {"gateway": [], "direct": []}
        rejected = 0
        if scenario_dir.is_dir():
            for run_path in sorted(scenario_dir.glob("run_*.txt")):
                text = run_path.read_text(encoding="utf-8", errors="replace")
                for blob in extract_json_blobs(text):
                    if not isinstance(blob, dict):
                        rejected += 1
                        continue
                    sample = parse_hbone_sample(blob, str(run_path))
                    if sample is None:
                        if "rps" in blob or "target" in blob or "label" in blob:
                            rejected += 1
                        continue
                    kind = sample.pop("kind")
                    run_stats[kind].append(sample)

        gateway = aggregate_throughput_samples(
            run_stats["gateway"],
            rate_key="rps",
            latency_keys=("p50_us", "p95_us", "p99_us"),
        )
        direct = aggregate_throughput_samples(
            run_stats["direct"],
            rate_key="rps",
            latency_keys=("p50_us", "p95_us", "p99_us"),
        )
        gateway_reps = gateway["repetitions"] if gateway else 0
        direct_reps = direct["repetitions"] if direct else 0
        gateway_evidence = repetition_evidence(gateway_reps, required_reps)
        direct_evidence = repetition_evidence(direct_reps, required_reps)
        overhead = None
        if (
            gateway
            and direct
            and gateway["rps_mean"] is not None
            and direct["rps_mean"] is not None
            and direct["rps_mean"] > 0
            and math.isfinite(gateway["rps_mean"])
            and math.isfinite(direct["rps_mean"])
        ):
            overhead = (
                (direct["rps_mean"] - gateway["rps_mean"]) / direct["rps_mean"]
            ) * 100.0
        complete = gateway_evidence["ok"] and direct_evidence["ok"]
        errors_ok = bool(
            gateway
            and direct
            and gateway["total_errors_sum"] == 0
            and direct["total_errors_sum"] == 0
        )
        out[key] = {
            "scenario": scenario,
            "gateway": gateway,
            "direct": direct,
            "overhead_percent_mean": overhead,
            "complete": complete,
            "errors_ok": errors_ok,
            "rejected_blobs": rejected,
            "repetition_evidence": {
                "required": required_reps,
                "gateway": gateway_evidence,
                "direct": direct_evidence,
            },
        }
    return out


def summarize_dns(dns_root: Path, required_reps: int) -> dict[str, Any]:
    gateway_rows: dict[tuple[str, str], list[dict[str, Any]]] = {}
    direct_rows: dict[tuple[str, str], list[dict[str, Any]]] = {}
    rejected = 0

    if dns_root.is_dir():
        for run_path in sorted(dns_root.glob("run_*.txt")):
            text = run_path.read_text(encoding="utf-8", errors="replace")
            for blob in extract_json_blobs(text):
                if not isinstance(blob, dict) or "reports" not in blob:
                    continue
                reports = blob.get("reports")
                if not isinstance(reports, list):
                    rejected += 1
                    continue
                target = str(blob.get("target", ""))
                is_direct = ":17053" in target
                bucket = direct_rows if is_direct else gateway_rows
                for report in reports:
                    if not isinstance(report, dict):
                        rejected += 1
                        continue
                    sample = parse_dns_report(report, str(run_path))
                    if sample is None:
                        rejected += 1
                        continue
                    key = (sample["name_class"], sample["transport"])
                    bucket.setdefault(key, []).append(
                        {
                            "qps": sample["qps"],
                            "p50_us": sample["p50_us"],
                            "p90_us": sample["p90_us"],
                            "p99_us": sample["p99_us"],
                            "total_errors": sample["total_errors"],
                            "source": sample["source"],
                        }
                    )

    def aggregate(samples: list[dict[str, Any]]) -> dict[str, Any] | None:
        return aggregate_throughput_samples(
            samples,
            rate_key="qps",
            latency_keys=("p50_us", "p90_us", "p99_us"),
        )

    gateway_summary: dict[str, Any] = {}
    gateway_evidence: dict[str, Any] = {}
    for cls, transport in DNS_GATEWAY_ROWS:
        row_key = f"{cls}/{transport}"
        samples = gateway_rows.get((cls, transport), [])
        agg = aggregate(samples)
        gateway_summary[row_key] = agg
        gateway_evidence[row_key] = repetition_evidence(
            agg["repetitions"] if agg else 0,
            required_reps,
        )

    direct_summary: dict[str, Any] = {}
    direct_evidence: dict[str, Any] = {}
    for cls, transport in DNS_DIRECT_ROWS:
        row_key = f"{cls}/{transport}"
        samples = direct_rows.get((cls, transport), [])
        agg = aggregate(samples)
        direct_summary[row_key] = agg
        direct_evidence[row_key] = repetition_evidence(
            agg["repetitions"] if agg else 0,
            required_reps,
        )

    overhead = {}
    for transport in ("udp", "tcp"):
        g_key = f"upstream-forward/{transport}"
        d_key = f"upstream-forward/{transport}"
        g = gateway_summary.get(g_key)
        d = direct_summary.get(d_key)
        if (
            g
            and d
            and g.get("qps_mean") is not None
            and d.get("qps_mean") is not None
            and d["qps_mean"] > 0
            and math.isfinite(g["qps_mean"])
            and math.isfinite(d["qps_mean"])
        ):
            overhead[transport] = (
                (d["qps_mean"] - g["qps_mean"]) / d["qps_mean"]
            ) * 100.0
        else:
            overhead[transport] = None

    row_complete = all(v["ok"] for v in gateway_evidence.values()) and all(
        v["ok"] for v in direct_evidence.values()
    )
    errors_ok = all(
        (row or {}).get("total_errors_sum", 1) == 0
        for row in list(gateway_summary.values()) + list(direct_summary.values())
        if row is not None
    ) and row_complete

    return {
        "gateway": gateway_summary,
        "direct_stub": direct_summary,
        "upstream_forward_overhead_percent": overhead,
        "complete": row_complete,
        "errors_ok": errors_ok,
        "rejected_blobs": rejected,
        "repetition_evidence": {
            "required": required_reps,
            "gateway": gateway_evidence,
            "direct_stub": direct_evidence,
        },
    }


def mesh_complete(mesh: dict[str, Any]) -> bool:
    for section in mesh.values():
        for value in section.values():
            if value is None:
                return False
    return True


def load_runner_health(results_root: Path) -> dict[str, Any]:
    health_path = results_root / "runner_health.json"
    probes_path = results_root / "logs" / "runner_health_probes.jsonl"
    health = load_json(health_path)
    if not isinstance(health, dict):
        health = {}
    probes: list[dict[str, Any]] = []
    if probes_path.is_file():
        for line in probes_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                probes.append({"parse_error": True, "raw": line[:200]})
                continue
            if isinstance(obj, dict):
                probes.append(obj)
            else:
                probes.append({"parse_error": True, "raw": line[:200]})
    steal_values: list[float] = []
    pre = parse_finite_number(health.get("avg_steal_percent"), non_negative=True)
    if pre is not None:
        steal_values.append(pre)
    for probe in probes:
        if probe.get("parse_error"):
            continue
        steal = parse_finite_number(probe.get("avg_steal_percent"), non_negative=True)
        if steal is not None:
            steal_values.append(steal)
    max_steal = max(steal_values) if steal_values else None
    # Missing health evidence fails closed: publication requires machine-readable
    # steal samples from the pre-collection probe at minimum.
    evidence_ok = pre is not None and not any(p.get("parse_error") for p in probes)
    steal_ok = (
        evidence_ok
        and max_steal is not None
        and max_steal <= MAX_CPU_STEAL_PERCENT
    )
    return {
        "path": str(health_path) if health_path.is_file() else None,
        "pre_collection": health,
        "probes": probes,
        "threshold_percent": MAX_CPU_STEAL_PERCENT,
        "max_steal_percent": max_steal,
        "evidence_present": evidence_ok,
        "ok": steal_ok,
    }


def selected_suite_gates(
    acceptance: dict[str, Any],
    suites: str,
) -> dict[str, bool]:
    suites = (suites or "all").strip().lower()
    required: dict[str, bool] = {"runner_health_ok": bool(acceptance.get("runner_health_ok"))}
    if suites in ("all", "mesh"):
        required["mesh_complete"] = bool(acceptance.get("mesh_complete"))
    if suites in ("all", "hbone"):
        required["hbone_complete"] = bool(acceptance.get("hbone_complete"))
        required["hbone_errors_ok"] = bool(acceptance.get("hbone_errors_ok"))
    if suites in ("all", "dns"):
        required["dns_complete"] = bool(acceptance.get("dns_complete"))
        required["dns_errors_ok"] = bool(acceptance.get("dns_errors_ok"))
    if suites == "all":
        required["ready_to_publish_baselines"] = bool(
            acceptance.get("ready_to_publish_baselines")
        )
    return required


def selected_suite_accepted(acceptance: dict[str, Any], suites: str) -> bool:
    gates = selected_suite_gates(acceptance, suites)
    return all(gates.values())


def write_draft_markdown(
    draft_dir: Path,
    provenance: dict[str, Any],
    mesh: dict[str, Any],
    hbone: dict[str, Any],
    dns: dict[str, Any],
) -> None:
    draft_dir.mkdir(parents=True, exist_ok=True)
    runner = provenance.get("runner", {})
    commit = provenance.get("commit_sha", "unknown")
    run_id = (provenance.get("github") or {}).get("run_id")
    artifact_note = (
        f"GitHub Actions run `{run_id}` artifact "
        f"`mesh-performance-baselines-{commit}`"
        if run_id
        else "hosted workflow artifact (run id pending)"
    )

    mesh_lines = [
        "# Mesh Performance Baseline (draft from hosted collection)",
        "",
        "**Directional reference numbers only.** Hardware-specific — GitHub-hosted",
        f"`{runner.get('class', 'ubuntu-24.04')}` results are not universal product targets.",
        "",
        "## Reference environment",
        "",
        f"- Ferrum commit: `{commit}`",
        f"- Runner class: `{runner.get('class')}`",
        f"- CPU: `{runner.get('cpu_model')}`",
        f"- Topology: `{json.dumps(runner.get('cpu_topology', {}))}`",
        f"- RAM: `{(runner.get('ram') or {}).get('memtotal_gib')} GiB`",
        f"- OS/kernel/arch: `{runner.get('uname')}` / `{runner.get('arch')}`",
        f"- Build profile: `{(provenance.get('build') or {}).get('gateway_profile', 'release')}`",
        f"- Raw artifacts: {artifact_note}",
        "",
        "## authz_match",
        "",
        "| Policies (N) | Mean per call | Notes |",
        "|---|---|---|",
    ]
    for size in AUTHZ_SIZES:
        row = mesh["authz_match"].get(str(size))
        mean = row["mean_display"] if row else "_INCOMPLETE_"
        stdev = row["stdev_display"] if row else "n/a"
        mesh_lines.append(f"| {size:,} | {mean} (σ {stdev}) | Criterion mean |")
    mesh_lines.extend(
        [
            "",
            "## ip_restriction",
            "",
            "| Decision shape | Instances | Mean per iteration | Notes |",
            "|---|---:|---|---|",
        ]
    )
    labels = {
        ("deny_miss", 1): "Deny miss above every interval",
        ("deny_miss", 4): "Deny miss above every interval",
        ("high_match", 1): "Allow match in final interval",
        ("high_match", 4): "Allow match in final interval",
    }
    for decision, instances in IP_CASES:
        row = mesh["ip_restriction"].get(f"{decision}_{instances}")
        mean = row["mean_display"] if row else "_INCOMPLETE_"
        mesh_lines.append(
            f"| {labels[(decision, instances)]} | {instances} | {mean} | 10,000 rules |"
        )
    mesh_lines.extend(
        [
            "",
            "## slice_apply",
            "",
            "| Workloads (N) | Mean per call | Notes |",
            "|---|---|---|",
        ]
    )
    for size in SLICE_SIZES:
        row = mesh["slice_apply"].get(str(size))
        mean = row["mean_display"] if row else "_INCOMPLETE_"
        mesh_lines.append(f"| {size:,} | {mean} | Criterion mean |")
    mesh_lines.extend(
        [
            "",
            "## xds_translation",
            "",
            "| Workloads (N) | Mean per call | Notes |",
            "|---|---|---|",
        ]
    )
    for size in SLICE_SIZES:
        row = mesh["xds_translation"].get(str(size))
        mean = row["mean_display"] if row else "_INCOMPLETE_"
        mesh_lines.append(f"| {size:,} | {mean} | Criterion mean |")
    (draft_dir / "mesh_baseline_draft.md").write_text(
        "\n".join(mesh_lines) + "\n", encoding="utf-8"
    )

    hbone_lines = [
        "# Mesh HBONE E2E Baseline (draft from hosted collection)",
        "",
        f"- Ferrum revision: `{commit}`",
        f"- CPU: `{runner.get('cpu_model')}`",
        f"- RAM: `{(runner.get('ram') or {}).get('memtotal_gib')} GiB`",
        f"- OS / kernel: `{runner.get('uname')}`",
        "- Build profile: `--release`",
        f"- Raw artifacts: {artifact_note}",
        "",
        "Overhead formula: `((direct_rps - gateway_hbone_rps) / direct_rps) * 100`.",
        "",
    ]
    titles = {
        "1kib_c50_30s": "## 1 KiB payload, concurrency 50, 30 s",
        "16kib_c50_30s": "## 16 KiB payload, concurrency 50, 30 s",
        "256kib_c100_60s": "## 256 KiB payload, concurrency 100, 60 s",
    }
    for key, title in titles.items():
        row = hbone.get(key) or {}
        direct = row.get("direct") or {}
        gateway = row.get("gateway") or {}
        hbone_lines.extend(
            [
                title,
                "",
                "| Path              | RPS    | p50    | p95    | p99    | Overhead vs direct |",
                "|-------------------|--------|--------|--------|--------|--------------------|",
                f"| Direct baseline   | {fmt_rps(direct.get('rps_mean'))}  | {fmt_us(direct.get('p50_us_mean'))}  | {fmt_us(direct.get('p95_us_mean'))}  | {fmt_us(direct.get('p99_us_mean'))}  | —                  |",
                f"| Gateway + HBONE   | {fmt_rps(gateway.get('rps_mean'))}  | {fmt_us(gateway.get('p50_us_mean'))}  | {fmt_us(gateway.get('p95_us_mean'))}  | {fmt_us(gateway.get('p99_us_mean'))}  | {fmt_pct(row.get('overhead_percent_mean'))}            |",
                "",
            ]
        )
    (draft_dir / "hbone_baseline_draft.md").write_text(
        "\n".join(hbone_lines) + "\n", encoding="utf-8"
    )

    dns_lines = [
        "# Mesh DNS Proxy E2E Baseline (draft from hosted collection)",
        "",
        f"- Ferrum commit: `{commit}`",
        f"- Runner: `{runner.get('class')}` / `{runner.get('cpu_model')}`",
        f"- Raw artifacts: {artifact_note}",
        "",
        "Upstream-forward overhead formula: "
        "`((direct_stub_qps - gateway_qps) / direct_stub_qps) * 100`.",
        "",
        "## Via gateway (127.0.0.1:15053)",
        "",
        "UDP transport:",
        "",
        "| Name class | qps | p50 | p90 | p99 | Notes |",
        "|---|---|---|---|---|---|",
    ]
    gateway = dns.get("gateway") or {}
    for cls in ("mesh-internal", "mesh-wildcard", "upstream-forward"):
        row = gateway.get(f"{cls}/udp") or {}
        dns_lines.append(
            f"| {cls} | {fmt_rps(row.get('qps_mean'))} | {fmt_us(row.get('p50_us_mean'))} | "
            f"{fmt_us(row.get('p90_us_mean'))} | {fmt_us(row.get('p99_us_mean'))} | |"
        )
    dns_lines.extend(
        [
            "",
            "TCP transport:",
            "",
            "| Name class | qps | p50 | p90 | p99 | Notes |",
            "|---|---|---|---|---|---|",
        ]
    )
    for cls in ("mesh-internal", "mesh-wildcard", "upstream-forward"):
        row = gateway.get(f"{cls}/tcp") or {}
        dns_lines.append(
            f"| {cls} | {fmt_rps(row.get('qps_mean'))} | {fmt_us(row.get('p50_us_mean'))} | "
            f"{fmt_us(row.get('p90_us_mean'))} | {fmt_us(row.get('p99_us_mean'))} | |"
        )
    direct = dns.get("direct_stub") or {}
    dns_lines.extend(
        [
            "",
            "## Direct baseline (dns_upstream_stub)",
            "",
            "| Class | Transport | qps | p50 | p90 | p99 |",
            "|---|---|---|---|---|---|",
        ]
    )
    for transport in ("udp", "tcp"):
        row = direct.get(f"upstream-forward/{transport}") or {}
        dns_lines.append(
            f"| upstream-forward | {transport.upper()} | {fmt_rps(row.get('qps_mean'))} | "
            f"{fmt_us(row.get('p50_us_mean'))} | {fmt_us(row.get('p90_us_mean'))} | "
            f"{fmt_us(row.get('p99_us_mean'))} |"
        )
    (draft_dir / "dns_baseline_draft.md").write_text(
        "\n".join(dns_lines) + "\n", encoding="utf-8"
    )


def _write_hbone_run(path: Path, *, gateway_rps: float, direct_rps: float, errors: int = 0) -> None:
    gateway = {
        "label": "gateway-hbone",
        "target": "127.0.0.1:18000",
        "rps": gateway_rps,
        "p50_us": 100,
        "p95_us": 200,
        "p99_us": 300,
        "total_errors": errors,
    }
    direct = {
        "label": "direct",
        "target": "127.0.0.1:19000",
        "rps": direct_rps,
        "p50_us": 80,
        "p95_us": 160,
        "p99_us": 240,
        "total_errors": errors,
    }
    path.write_text(
        json.dumps(gateway) + "\n" + json.dumps(direct) + "\n",
        encoding="utf-8",
    )


def _dns_blob(*, target: str, rows: list[tuple[str, str, float]], errors: int = 0) -> dict[str, Any]:
    return {
        "target": target,
        "reports": [
            {
                "name_class": cls,
                "transport": transport,
                "qps": qps,
                "p50_us": 50,
                "p90_us": 90,
                "p99_us": 120,
                "total_errors": errors,
            }
            for cls, transport, qps in rows
        ],
    }


def _write_full_dns_run(path: Path, *, errors: int = 0) -> None:
    gateway_rows = [
        (cls, transport, 1000.0 + i)
        for i, (cls, transport) in enumerate(DNS_GATEWAY_ROWS)
    ]
    direct_rows = [
        (cls, transport, 2000.0 + i)
        for i, (cls, transport) in enumerate(DNS_DIRECT_ROWS)
    ]
    text = (
        json.dumps(_dns_blob(target="127.0.0.1:15053", rows=gateway_rows, errors=errors))
        + "\n"
        + json.dumps(_dns_blob(target="127.0.0.1:17053", rows=direct_rows, errors=errors))
        + "\n"
    )
    path.write_text(text, encoding="utf-8")


def _write_criterion_estimate(path: Path, mean_ns: float) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "mean": {
                    "point_estimate": mean_ns,
                    "confidence_interval": {
                        "lower_bound": mean_ns * 0.9,
                        "upper_bound": mean_ns * 1.1,
                    },
                },
                "std_dev": {"point_estimate": mean_ns * 0.05},
            }
        )
        + "\n",
        encoding="utf-8",
    )


def _populate_valid_mesh(criterion_root: Path) -> None:
    for size in AUTHZ_SIZES:
        _write_criterion_estimate(
            criterion_root / "authz_match" / "policies" / str(size) / "new" / "estimates.json",
            1000.0 * size,
        )
    for decision, instances in IP_CASES:
        _write_criterion_estimate(
            criterion_root
            / "ip_restriction_lookup"
            / f"{decision}_10000_rules_{instances}_instances"
            / "new"
            / "estimates.json",
            500.0 * instances,
        )
    for size in SLICE_SIZES:
        _write_criterion_estimate(
            criterion_root / "slice_apply" / "workloads" / str(size) / "new" / "estimates.json",
            2000.0 * size,
        )
        _write_criterion_estimate(
            criterion_root
            / "xds_translation"
            / "workloads"
            / str(size)
            / "new"
            / "estimates.json",
            3000.0 * size,
        )


def self_test() -> int:
    assert abs((((100.0 - 80.0) / 100.0) * 100.0) - 20.0) < 1e-9
    assert "µs" in fmt_duration_ns(1500.0) or "us" in fmt_duration_ns(1500.0)
    assert required_repetitions(None) == 3
    assert required_repetitions(2) == 3
    assert required_repetitions(5) == 5
    assert parse_finite_number("nan", positive=True) is None
    assert parse_finite_number(-1.0, positive=True) is None
    assert parse_finite_number(0.0, positive=True) is None
    assert parse_finite_number(1.5, positive=True) == 1.5
    assert parse_non_negative_int(1.5) is None
    assert parse_non_negative_int(2) == 2

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        drafts = root / "drafts"
        prov_path = root / "provenance.json"
        out_path = root / "summary.json"
        prov_path.write_text(
            json.dumps(
                {
                    "commit_sha": "deadbeef",
                    "runner": {"class": "ubuntu-24.04", "cpu_model": "test"},
                }
            )
            + "\n",
            encoding="utf-8",
        )
        (root / "runner_health.json").write_text(
            json.dumps(
                {
                    "runner_class": "ubuntu-24.04",
                    "avg_steal_percent": 1.0,
                    "threshold_percent": MAX_CPU_STEAL_PERCENT,
                }
            )
            + "\n",
            encoding="utf-8",
        )
        (root / "logs").mkdir(parents=True)

        # --- undersampling: one gateway + one direct must not be complete ---
        under = root / "under"
        for scenario in HBONE_SCENARIOS:
            scenario_dir = under / "hbone" / scenario["key"]
            scenario_dir.mkdir(parents=True)
            _write_hbone_run(scenario_dir / "run_1.txt", gateway_rps=80.0, direct_rps=100.0)
        hbone_under = summarize_hbone(under / "hbone", required_repetitions(3))
        assert all(not row["complete"] for row in hbone_under.values())
        evidence = hbone_under["1kib_c50_30s"]["repetition_evidence"]
        assert evidence["required"] == 3
        assert evidence["gateway"]["actual"] == 1
        assert evidence["direct"]["actual"] == 1
        assert evidence["gateway"]["ok"] is False

        # --- missing DNS rows ---
        dns_missing = root / "dns_missing"
        dns_missing.mkdir()
        partial = {
            "target": "127.0.0.1:15053",
            "reports": [
                {
                    "name_class": "mesh-internal",
                    "transport": "udp",
                    "qps": 100.0,
                    "p50_us": 1,
                    "p90_us": 2,
                    "p99_us": 3,
                    "total_errors": 0,
                }
            ],
        }
        for i in range(1, 4):
            (dns_missing / f"run_{i}.txt").write_text(json.dumps(partial) + "\n", encoding="utf-8")
        dns_partial = summarize_dns(dns_missing, required_repetitions(3))
        assert dns_partial["complete"] is False
        assert dns_partial["repetition_evidence"]["gateway"]["mesh-internal/udp"]["ok"] is True
        assert dns_partial["repetition_evidence"]["gateway"]["mesh-wildcard/udp"]["ok"] is False
        assert dns_partial["repetition_evidence"]["direct_stub"]["upstream-forward/udp"]["ok"] is False

        # --- bad metrics rejected (NaN / non-positive / invalid latency) ---
        bad = root / "bad_metrics" / "hbone" / "1kib_c50_30s"
        bad.mkdir(parents=True)
        bad_blob = {
            "label": "gateway-hbone",
            "target": "127.0.0.1:18000",
            "rps": "not-a-number",
            "p50_us": 1,
            "p95_us": 2,
            "p99_us": 3,
            "total_errors": 0,
        }
        nan_blob = {
            "label": "direct",
            "target": "127.0.0.1:19000",
            "rps": float("nan"),
            "p50_us": 1,
            "p95_us": 2,
            "p99_us": 3,
            "total_errors": 0,
        }
        zero_blob = {
            "label": "direct",
            "target": "127.0.0.1:19000",
            "rps": 0.0,
            "p50_us": 1,
            "p95_us": 2,
            "p99_us": 3,
            "total_errors": 0,
        }
        (bad / "run_1.txt").write_text(
            "\n".join(json.dumps(x) for x in (bad_blob, nan_blob, zero_blob)) + "\n",
            encoding="utf-8",
        )
        assert parse_hbone_sample(bad_blob, "x") is None
        assert parse_hbone_sample(nan_blob, "x") is None
        assert parse_hbone_sample(zero_blob, "x") is None
        assert parse_dns_report(
            {
                "name_class": "mesh-internal",
                "transport": "udp",
                "qps": -5,
                "p50_us": 1,
                "p90_us": 2,
                "p99_us": 3,
                "total_errors": 0,
            },
            "x",
        ) is None
        assert criterion_mean(Path("/no/such/estimates.json")) is None

        # --- nonzero errors fail errors_ok ---
        err_root = root / "errors"
        for scenario in HBONE_SCENARIOS:
            scenario_dir = err_root / "hbone" / scenario["key"]
            scenario_dir.mkdir(parents=True)
            for run in range(1, 4):
                _write_hbone_run(
                    scenario_dir / f"run_{run}.txt",
                    gateway_rps=80.0,
                    direct_rps=100.0,
                    errors=1,
                )
        hbone_err = summarize_hbone(err_root / "hbone", required_repetitions(3))
        assert all(row["complete"] for row in hbone_err.values())
        assert all(not row["errors_ok"] for row in hbone_err.values())

        dns_err = root / "dns_errors"
        dns_err.mkdir()
        for run in range(1, 4):
            _write_full_dns_run(dns_err / f"run_{run}.txt", errors=2)
        dns_err_summary = summarize_dns(dns_err, required_repetitions(3))
        assert dns_err_summary["complete"] is True
        assert dns_err_summary["errors_ok"] is False

        # --- valid three-run shape with healthy steal is publication-ready ---
        valid = root / "valid"
        _populate_valid_mesh(valid / "mesh" / "criterion")
        for scenario in HBONE_SCENARIOS:
            scenario_dir = valid / "hbone" / scenario["key"]
            scenario_dir.mkdir(parents=True)
            for run in range(1, 4):
                _write_hbone_run(
                    scenario_dir / f"run_{run}.txt",
                    gateway_rps=80.0 + run,
                    direct_rps=100.0 + run,
                )
        (valid / "dns").mkdir(parents=True)
        for run in range(1, 4):
            _write_full_dns_run(valid / "dns" / f"run_{run}.txt")
        (valid / "runner_health.json").write_text(
            json.dumps({"avg_steal_percent": 2.5, "runner_class": "ubuntu-24.04"}) + "\n",
            encoding="utf-8",
        )
        (valid / "logs").mkdir(parents=True, exist_ok=True)
        (valid / "logs" / "runner_health_probes.jsonl").write_text(
            json.dumps(
                {
                    "phase": "hbone",
                    "scenario": "1kib_c50_30s",
                    "repetition": 1,
                    "avg_steal_percent": 3.0,
                }
            )
            + "\n"
            + json.dumps(
                {
                    "phase": "dns",
                    "repetition": 1,
                    "avg_steal_percent": 2.0,
                }
            )
            + "\n",
            encoding="utf-8",
        )
        (valid / "provenance.json").write_text(prov_path.read_text(encoding="utf-8"), encoding="utf-8")
        summary = build_summary(
            valid,
            load_json(valid / "provenance.json") or {},
            required_repetitions(3),
            suites="all",
        )
        assert summary["acceptance_gate"]["mesh_complete"] is True
        assert summary["acceptance_gate"]["hbone_complete"] is True
        assert summary["acceptance_gate"]["hbone_errors_ok"] is True
        assert summary["acceptance_gate"]["dns_complete"] is True
        assert summary["acceptance_gate"]["dns_errors_ok"] is True
        assert summary["acceptance_gate"]["runner_health_ok"] is True
        assert summary["ready_to_publish_baselines"] is True
        assert summary["hbone"]["1kib_c50_30s"]["repetition_evidence"]["gateway"]["actual"] == 3
        assert summary["dns"]["repetition_evidence"]["gateway"]["upstream-forward/tcp"]["actual"] == 3
        write_draft_markdown(drafts, summary["provenance"], summary["mesh"], summary["hbone"], summary["dns"])
        assert (drafts / "mesh_baseline_draft.md").is_file()

        # excessive steal fails publication even with complete metrics
        (valid / "runner_health.json").write_text(
            json.dumps({"avg_steal_percent": 9.0}) + "\n",
            encoding="utf-8",
        )
        summary_steal = build_summary(
            valid,
            load_json(valid / "provenance.json") or {},
            required_repetitions(3),
            suites="all",
        )
        assert summary_steal["acceptance_gate"]["runner_health_ok"] is False
        assert summary_steal["ready_to_publish_baselines"] is False

        # partial-suite acceptance only requires selected gates
        partial_gates = selected_suite_gates(
            {
                "mesh_complete": False,
                "hbone_complete": True,
                "hbone_errors_ok": True,
                "dns_complete": False,
                "dns_errors_ok": False,
                "runner_health_ok": True,
                "ready_to_publish_baselines": False,
            },
            "hbone",
        )
        assert partial_gates["hbone_complete"] is True
        assert "mesh_complete" not in partial_gates
        assert selected_suite_accepted(
            {
                "mesh_complete": False,
                "hbone_complete": True,
                "hbone_errors_ok": True,
                "dns_complete": False,
                "dns_errors_ok": False,
                "runner_health_ok": True,
                "ready_to_publish_baselines": False,
            },
            "hbone",
        )
        assert not selected_suite_accepted(
            {
                "mesh_complete": True,
                "hbone_complete": False,
                "hbone_errors_ok": True,
                "dns_complete": True,
                "dns_errors_ok": True,
                "runner_health_ok": True,
                "ready_to_publish_baselines": False,
            },
            "hbone",
        )

        # write + check-acceptance path
        out_path.write_text(json.dumps(summary) + "\n", encoding="utf-8")
        assert check_acceptance(out_path, "all") == 0

    print("summarize_mesh_baseline_results self-test passed")
    return 0


def build_summary(
    results_root: Path,
    provenance: dict[str, Any],
    required_reps: int,
    *,
    suites: str,
) -> dict[str, Any]:
    mesh = summarize_mesh(results_root / "mesh" / "criterion")
    hbone = summarize_hbone(results_root / "hbone", required_reps)
    dns = summarize_dns(results_root / "dns", required_reps)
    runner_health = load_runner_health(results_root)

    acceptance = {
        "mesh_complete": mesh_complete(mesh),
        "hbone_complete": all(v.get("complete") for v in hbone.values()) if hbone else False,
        "hbone_errors_ok": all(v.get("errors_ok") for v in hbone.values()) if hbone else False,
        "dns_complete": bool(dns.get("complete")),
        "dns_errors_ok": bool(dns.get("errors_ok")),
        "runner_health_ok": bool(runner_health.get("ok")),
        "expected_e2e_repetitions": required_reps,
        "min_e2e_repetitions": MIN_E2E_REPETITIONS,
        "max_cpu_steal_percent": MAX_CPU_STEAL_PERCENT,
    }
    ready = all(
        [
            acceptance["mesh_complete"],
            acceptance["hbone_complete"],
            acceptance["hbone_errors_ok"],
            acceptance["dns_complete"],
            acceptance["dns_errors_ok"],
            acceptance["runner_health_ok"],
        ]
    )
    acceptance["ready_to_publish_baselines"] = ready
    selected = selected_suite_gates(acceptance, suites)
    return {
        "schema_version": 2,
        "provenance": provenance,
        "suites_selected": suites,
        "mesh": mesh,
        "hbone": hbone,
        "dns": dns,
        "runner_health": runner_health,
        "acceptance_gate": acceptance,
        "selected_suite_gates": selected,
        "selected_suite_accepted": all(selected.values()),
        "ready_to_publish_baselines": ready,
    }


def check_acceptance(summary_path: Path, suites: str) -> int:
    summary = load_json(summary_path)
    if not isinstance(summary, dict):
        print(f"::error::missing or malformed summary at {summary_path}")
        return 1
    acceptance = summary.get("acceptance_gate")
    if not isinstance(acceptance, dict):
        print("::error::summary.acceptance_gate missing")
        return 1
    # Prefer gates recomputed for the suites argument so callers can override.
    gates = selected_suite_gates(acceptance, suites)
    print(json.dumps({"suites": suites, "selected_suite_gates": gates}, indent=2))
    if not all(gates.values()):
        failed = [name for name, ok in gates.items() if not ok]
        print(f"::error::selected suite acceptance failed: {', '.join(failed)}")
        return 1
    print(f"selected suite acceptance OK for suites={suites}")
    return 0


def main() -> int:
    args = parse_args()
    if args.self_test:
        return self_test()
    if args.check_acceptance:
        return check_acceptance(args.summary, args.suites)

    required_reps = required_repetitions(args.expected_repetitions)
    provenance = load_json(args.provenance) or {}
    summary = build_summary(
        args.results_root,
        provenance,
        required_reps,
        suites=args.suites,
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    write_draft_markdown(
        args.draft_markdown_dir,
        provenance,
        summary["mesh"],
        summary["hbone"],
        summary["dns"],
    )
    print(json.dumps(summary["acceptance_gate"], indent=2))
    print(json.dumps(summary["selected_suite_gates"], indent=2))
    print(f"selected_suite_accepted={summary['selected_suite_accepted']}")
    print(f"ready_to_publish_baselines={summary['ready_to_publish_baselines']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
