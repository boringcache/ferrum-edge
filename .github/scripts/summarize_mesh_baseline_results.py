#!/usr/bin/env python3
"""Summarize hosted mesh/HBONE/DNS baseline artifacts into machine-readable JSON.

Reads Criterion estimates.json trees and E2E JSON blobs produced by the
mesh-performance-baselines workflow. Never fabricates measurements: missing
inputs become explicit null/incomplete entries.
"""

from __future__ import annotations

import argparse
import json
import math
import statistics
import sys
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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-root", type=Path)
    parser.add_argument("--provenance", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--draft-markdown-dir", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
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
    us_f = float(us)
    if us_f >= 1_000_000:
        return f"{us_f / 1_000_000:.2f}s"
    if us_f >= 1_000:
        return f"{us_f / 1_000:.2f}ms"
    return f"{us_f:.0f}µs"


def fmt_rps(v: float | None) -> str:
    if v is None:
        return "n/a"
    return f"{v:,.0f}"


def fmt_pct(v: float | None) -> str:
    if v is None:
        return "n/a"
    return f"{v:.1f}%"


def mean_stdev(values: list[float]) -> tuple[float | None, float | None, float | None, float | None]:
    if not values:
        return None, None, None, None
    mean_v = statistics.mean(values)
    stdev_v = statistics.stdev(values) if len(values) > 1 else 0.0
    return mean_v, stdev_v, min(values), max(values)


def criterion_mean(path: Path) -> dict[str, Any] | None:
    data = load_json(path)
    if not isinstance(data, dict):
        return None
    mean = data.get("mean") or {}
    std_dev = data.get("std_dev") or {}
    try:
        point = float(mean["point_estimate"])
        lower = float(mean.get("confidence_interval", {}).get("lower_bound", point))
        upper = float(mean.get("confidence_interval", {}).get("upper_bound", point))
        stdev = float(std_dev.get("point_estimate", 0.0))
    except (KeyError, TypeError, ValueError):
        return None
    if not math.isfinite(point) or point <= 0:
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


def summarize_hbone(hbone_root: Path) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for scenario in HBONE_SCENARIOS:
        key = scenario["key"]
        scenario_dir = hbone_root / key
        run_stats: dict[str, list[dict[str, Any]]] = {"gateway": [], "direct": []}
        for run_path in sorted(scenario_dir.glob("run_*.txt")):
            text = run_path.read_text(encoding="utf-8", errors="replace")
            for blob in extract_json_blobs(text):
                if not isinstance(blob, dict) or "rps" not in blob:
                    continue
                kind = classify_hbone_blob(blob)
                if kind is None:
                    continue
                run_stats[kind].append(
                    {
                        "rps": float(blob.get("rps", 0.0)),
                        "p50_us": int(blob.get("p50_us", 0)),
                        "p95_us": int(blob.get("p95_us", 0)),
                        "p99_us": int(blob.get("p99_us", 0)),
                        "total_errors": int(blob.get("total_errors", 0)),
                        "source": str(run_path),
                    }
                )

        def aggregate(samples: list[dict[str, Any]]) -> dict[str, Any] | None:
            if not samples:
                return None
            rps_vals = [s["rps"] for s in samples]
            mean_rps, stdev_rps, min_rps, max_rps = mean_stdev(rps_vals)
            err_total = sum(s["total_errors"] for s in samples)
            return {
                "repetitions": len(samples),
                "rps_mean": mean_rps,
                "rps_stdev": stdev_rps,
                "rps_min": min_rps,
                "rps_max": max_rps,
                "p50_us_mean": statistics.mean(s["p50_us"] for s in samples),
                "p95_us_mean": statistics.mean(s["p95_us"] for s in samples),
                "p99_us_mean": statistics.mean(s["p99_us"] for s in samples),
                "total_errors_sum": err_total,
                "samples": samples,
            }

        gateway = aggregate(run_stats["gateway"])
        direct = aggregate(run_stats["direct"])
        overhead = None
        if gateway and direct and direct["rps_mean"] and direct["rps_mean"] > 0:
            overhead = (
                (direct["rps_mean"] - gateway["rps_mean"]) / direct["rps_mean"]
            ) * 100.0
        out[key] = {
            "scenario": scenario,
            "gateway": gateway,
            "direct": direct,
            "overhead_percent_mean": overhead,
            "complete": gateway is not None and direct is not None,
            "errors_ok": bool(
                gateway
                and direct
                and gateway["total_errors_sum"] == 0
                and direct["total_errors_sum"] == 0
            ),
        }
    return out


def summarize_dns(dns_root: Path) -> dict[str, Any]:
    gateway_rows: dict[tuple[str, str], list[dict[str, Any]]] = {}
    direct_rows: dict[tuple[str, str], list[dict[str, Any]]] = {}

    for run_path in sorted(dns_root.glob("run_*.txt")):
        text = run_path.read_text(encoding="utf-8", errors="replace")
        for blob in extract_json_blobs(text):
            if not isinstance(blob, dict) or "reports" not in blob:
                continue
            target = str(blob.get("target", ""))
            is_direct = ":17053" in target
            bucket = direct_rows if is_direct else gateway_rows
            for report in blob.get("reports") or []:
                if not isinstance(report, dict):
                    continue
                class_name = str(report.get("name_class", ""))
                transport = str(report.get("transport", ""))
                key = (class_name, transport)
                bucket.setdefault(key, []).append(
                    {
                        "qps": float(report.get("qps", 0.0)),
                        "p50_us": int(report.get("p50_us", 0)),
                        "p90_us": int(report.get("p90_us", 0)),
                        "p99_us": int(report.get("p99_us", 0)),
                        "total_errors": int(report.get("total_errors", 0)),
                        "source": str(run_path),
                    }
                )

    def aggregate(samples: list[dict[str, Any]]) -> dict[str, Any] | None:
        if not samples:
            return None
        qps_vals = [s["qps"] for s in samples]
        mean_qps, stdev_qps, min_qps, max_qps = mean_stdev(qps_vals)
        return {
            "repetitions": len(samples),
            "qps_mean": mean_qps,
            "qps_stdev": stdev_qps,
            "qps_min": min_qps,
            "qps_max": max_qps,
            "p50_us_mean": statistics.mean(s["p50_us"] for s in samples),
            "p90_us_mean": statistics.mean(s["p90_us"] for s in samples),
            "p99_us_mean": statistics.mean(s["p99_us"] for s in samples),
            "total_errors_sum": sum(s["total_errors"] for s in samples),
            "samples": samples,
        }

    gateway_summary = {
        f"{cls}/{transport}": aggregate(samples)
        for (cls, transport), samples in sorted(gateway_rows.items())
    }
    direct_summary = {
        f"{cls}/{transport}": aggregate(samples)
        for (cls, transport), samples in sorted(direct_rows.items())
    }

    overhead = {}
    for transport in ("udp", "tcp"):
        g_key = f"upstream-forward/{transport}"
        d_key = f"upstream-forward/{transport}"
        g = gateway_summary.get(g_key)
        d = direct_summary.get(d_key)
        if g and d and d["qps_mean"] and d["qps_mean"] > 0:
            overhead[transport] = (
                (d["qps_mean"] - g["qps_mean"]) / d["qps_mean"]
            ) * 100.0
        else:
            overhead[transport] = None

    return {
        "gateway": gateway_summary,
        "direct_stub": direct_summary,
        "upstream_forward_overhead_percent": overhead,
        "complete": bool(gateway_summary) and bool(direct_summary),
        "errors_ok": all(
            (row or {}).get("total_errors_sum", 1) == 0
            for row in list(gateway_summary.values()) + list(direct_summary.values())
            if row is not None
        ),
    }


def mesh_complete(mesh: dict[str, Any]) -> bool:
    for section in mesh.values():
        for value in section.values():
            if value is None:
                return False
    return True


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
        f"`{runner.get('class', 'ubuntu-latest')}` results are not universal product targets.",
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


def self_test() -> int:
    # Overhead math + duration formatting only; no fabricated suite claims.
    assert abs((((100.0 - 80.0) / 100.0) * 100.0) - 20.0) < 1e-9
    assert fmt_duration_ns(1500.0).endswith("µs") or "us" in fmt_duration_ns(1500.0)
    print("summarize_mesh_baseline_results self-test passed")
    return 0


def main() -> int:
    args = parse_args()
    if args.self_test:
        return self_test()

    provenance = load_json(args.provenance) or {}
    mesh = summarize_mesh(args.results_root / "mesh" / "criterion")
    hbone = summarize_hbone(args.results_root / "hbone")
    dns = summarize_dns(args.results_root / "dns")

    summary = {
        "schema_version": 1,
        "provenance": provenance,
        "mesh": mesh,
        "hbone": hbone,
        "dns": dns,
        "acceptance_gate": {
            "mesh_complete": mesh_complete(mesh),
            "hbone_complete": all(v.get("complete") for v in hbone.values()) if hbone else False,
            "hbone_errors_ok": all(v.get("errors_ok") for v in hbone.values()) if hbone else False,
            "dns_complete": bool(dns.get("complete")),
            "dns_errors_ok": bool(dns.get("errors_ok")),
        },
    }
    acceptance = summary["acceptance_gate"]
    summary["ready_to_publish_baselines"] = all(
        [
            acceptance["mesh_complete"],
            acceptance["hbone_complete"],
            acceptance["hbone_errors_ok"],
            acceptance["dns_complete"],
            acceptance["dns_errors_ok"],
        ]
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    write_draft_markdown(args.draft_markdown_dir, provenance, mesh, hbone, dns)
    print(json.dumps(summary["acceptance_gate"], indent=2))
    print(f"ready_to_publish_baselines={summary['ready_to_publish_baselines']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
