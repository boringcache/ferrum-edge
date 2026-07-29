#!/usr/bin/env python3
"""Hosted CI checks for the DOC-10 Prometheus metric contract.

Validates the checked-in inventory JSON, the operator reference markdown, and
bundled PrometheusRule / Grafana metric references. Intentionally static: no
promtool binary is required by repository policy (operators may still run
promtool against a rendered rule file in their own clusters).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

VALID_TYPES = {"counter", "gauge", "histogram", "summary"}
VALID_BUNDLED = {"alert", "dashboard", "alert_and_dashboard", "documented_only"}
VALID_EMISSION = {
    "always",
    "conditional",
    "when_series_present",
    "when_plugin_enabled",
    "when_process_initialized",
}
EXTERNAL_ALLOWLIST = {"apiserver_admission_webhook_rejection_count"}
REQUIRED_FAMILIES = {
    "ferrum_database_delta_consecutive_identical_rejections",
    "ferrum_mesh_tcp_egress_connections_total",
    "ferrum_mesh_remote_discovery_poll_failures_total",
    "ferrum_mesh_remote_discovery_poll_successes_total",
    "ferrum_mesh_remote_discovery_last_success_timestamp_seconds",
    "ferrum_mesh_remote_discovery_endpoint_age_seconds",
}


def fail(title: str, detail: str) -> None:
    print(f"::error title={title}::{detail}")
    raise SystemExit(1)


def base_name(name: str) -> str:
    for suffix in ("_bucket", "_sum", "_count"):
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def ferrum_names(text: str) -> set[str]:
    names: set[str] = set()
    for match in re.finditer(r"\b(?:ferrum_[a-z0-9_]+|chargeback_sink_[a-z0-9_]+)\b", text):
        names.add(base_name(match.group(0)))
    return names


def load_contract(root: Path) -> list[dict]:
    path = root / "docs" / "prometheus_metric_contract.json"
    items = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(items, list) or not items:
        fail("Empty metric contract", str(path))
    names = [item.get("name") for item in items]
    if names != sorted(names):
        fail("Metric contract unsorted", "family names must be strictly sorted")
    if len(names) != len(set(names)):
        fail("Metric contract duplicates", "family names must be unique")
    for item in items:
        name = item.get("name")
        if not isinstance(name, str) or not name:
            fail("Invalid metric contract row", "missing name")
        if item.get("type") not in VALID_TYPES:
            fail("Invalid metric type", f"{name}: {item.get('type')}")
        if not item.get("help"):
            fail("Missing metric help", name)
        if not isinstance(item.get("labels"), list):
            fail("Missing metric labels", name)
        if item.get("bundled") not in VALID_BUNDLED:
            fail("Invalid bundled classification", f"{name}: {item.get('bundled')}")
        if item.get("emission") not in VALID_EMISSION:
            fail("Invalid emission classification", f"{name}: {item.get('emission')}")
        if not item.get("subsystem"):
            fail("Missing subsystem", name)
        if item.get("export_surface") != "/metrics":
            fail("Unexpected export surface", f"{name}: {item.get('export_surface')}")
    missing = REQUIRED_FAMILIES.difference(names)
    if missing:
        fail("DOC-10 required families missing", ", ".join(sorted(missing)))
    return items


def validate_reference(root: Path, items: list[dict]) -> None:
    doc = (root / "docs" / "prometheus_metrics.md").read_text(encoding="utf-8")
    if "# Prometheus Metrics Contract (DOC-10)" not in doc:
        fail("Missing DOC-10 reference title", "docs/prometheus_metrics.md")
    for section in (
        "Database rejected-delta polling",
        "Mesh remote-cluster endpoint discovery",
        "Raw-TCP mesh egress",
        "Poll-failure runbook",
        "Endpoint-age runbook",
    ):
        if section not in doc:
            fail("Missing runbook section", section)
    for item in items:
        needle = f"| `{item['name']}` |"
        if needle not in doc:
            fail("Reference missing inventory row", item["name"])
    print("prometheus metrics reference ok")


def validate_bundled(root: Path, items: list[dict]) -> None:
    by_name = {item["name"]: item for item in items}
    alert_text = (
        root / "charts" / "ferrum-mesh" / "templates" / "alerts-prometheusrule.yaml"
    ).read_text(encoding="utf-8")
    dash_text = ""
    dash_dir = root / "charts" / "ferrum-mesh" / "dashboards"
    for path in sorted(dash_dir.glob("*.json")):
        dash_text += path.read_text(encoding="utf-8")

    alert_names = ferrum_names(alert_text)
    dash_names = ferrum_names(dash_text)
    referenced = alert_names | dash_names

    unknown = sorted(
        name
        for name in referenced
        if name not in by_name and name not in EXTERNAL_ALLOWLIST
    )
    if unknown:
        fail("Bundled query unknown family", ", ".join(unknown))

    for item in items:
        name = item["name"]
        is_ref = name in referenced
        bundled = item["bundled"]
        if bundled == "documented_only" and is_ref:
            fail(
                "documented_only family referenced by charts",
                name,
            )
        if bundled != "documented_only" and not is_ref:
            fail(
                "bundled classification missing chart reference",
                f"{name} classified as {bundled}",
            )
        if bundled == "alert" and name not in alert_names:
            fail("alert classification missing PrometheusRule ref", name)
        if bundled == "dashboard" and name not in dash_names:
            fail("dashboard classification missing Grafana ref", name)
        if bundled == "alert_and_dashboard" and not (
            name in alert_names and name in dash_names
        ):
            fail("alert_and_dashboard missing both surfaces", name)

    print("bundled prometheus/grafana metric refs ok")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root",
        type=Path,
        default=REPO_ROOT,
        help="Repository root (defaults to ferrum-edge checkout)",
    )
    args = parser.parse_args()
    root = args.root.resolve()
    items = load_contract(root)
    validate_reference(root, items)
    validate_bundled(root, items)
    print(f"DOC-10 prometheus metric contract ok ({len(items)} families)")


if __name__ == "__main__":
    main()
