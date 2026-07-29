#!/usr/bin/env python3
"""Hosted CI checks for the DOC-10 Prometheus metric contract.

Validates the checked-in inventory JSON, the operator reference markdown, and
bundled PrometheusRule / Grafana metric references. This script is intentionally
static; the hosted Helm job separately renders the PrometheusRule and runs
``promtool check rules`` against its extracted rule groups.

Also scans production Rust string-literal ``# TYPE`` declarations and rejects
any literal exported family absent from the inventory (or any type mismatch).
Dynamic families built via ``format!("# TYPE {name} …")`` remain inventoried
explicitly rather than rediscovered by identifier/comment heuristics.
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
BASE_CONTRACT_FIELDS = {
    "name",
    "type",
    "help",
    "labels",
    "subsystem",
    "export_surface",
    "bundled",
    "emission",
}
DYNAMIC_CONTRACT_FIELDS = {"name_template", "default_prefix"}
EXTERNAL_ALLOWLIST = {"apiserver_admission_webhook_rejection_count"}
REQUIRED_FAMILIES = {
    "ferrum_database_delta_consecutive_identical_rejections",
    "ferrum_mesh_tcp_egress_connections_total",
    "ferrum_mesh_remote_discovery_poll_failures_total",
    "ferrum_mesh_remote_discovery_poll_successes_total",
    "ferrum_mesh_remote_discovery_last_success_timestamp_seconds",
    "ferrum_mesh_remote_discovery_endpoint_age_seconds",
    "ferrum_api_chargeable_calls_total",
    "ferrum_api_charges_total",
    "ferrum_api_bandwidth_charges_total",
    "ferrum_api_chargeback_registry_entries",
}

TYPE_LITERAL_RE = re.compile(
    r"# TYPE\s+(ferrum_[a-z0-9_]+|chargeback_sink_[a-z0-9_]+)\s+"
    r"(counter|gauge|histogram|summary)\b"
)
METRIC_TOKEN_RE = re.compile(r"\b(?:ferrum_[a-z0-9_]+|chargeback_sink_[a-z0-9_]+)\b")
METRIC_NAME_RE = re.compile(r"^(?:ferrum_|chargeback_sink_)[a-z0-9_]+$")
LABEL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
SUBSYSTEM_RE = re.compile(r"^[a-z][a-z0-9_]*$")
SAMPLE_SUFFIXES = ("_bucket", "_sum", "_count")


def fail(title: str, detail: str) -> None:
    print(f"::error title={title}::{detail}")
    raise SystemExit(1)


def normalize_family_name(name: str, by_name: dict[str, dict]) -> str:
    """Map a token to its inventoried family.

    Inventoried families that legitimately end in ``_bucket`` / ``_sum`` /
    ``_count`` (for example the ``ferrum_database_delta_backoff_bucket`` gauge)
    stay themselves. A suffix is stripped only when the exact name is not
    inventoried and the stripped candidate is an inventoried histogram/summary.
    """
    if name in by_name:
        return name
    for suffix in SAMPLE_SUFFIXES:
        if name.endswith(suffix):
            candidate = name[: -len(suffix)]
            item = by_name.get(candidate)
            if item is not None and item.get("type") in {"histogram", "summary"}:
                return candidate
    return name


def ferrum_names(text: str, by_name: dict[str, dict]) -> set[str]:
    names: set[str] = set()
    for match in METRIC_TOKEN_RE.finditer(text):
        names.add(normalize_family_name(match.group(0), by_name))
    return names


def extract_rust_string_literal_contents(text: str) -> list[str]:
    """Best-effort extraction of Rust string literal contents.

    Skips line/block comments so identifiers and prose cannot be mistaken for
    exported ``# TYPE`` declarations. Handles ordinary ``"…"`` strings (with
    escapes and line continuations) and raw strings ``r#"…"#``.
    """
    out: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "/" and i + 1 < n:
            nxt = text[i + 1]
            if nxt == "/":
                i += 2
                while i < n and text[i] != "\n":
                    i += 1
                continue
            if nxt == "*":
                end = text.find("*/", i + 2)
                i = n if end < 0 else end + 2
                continue
        if ch == "r" and i + 1 < n and text[i + 1] in "#\"":
            j = i + 1
            hashes = 0
            while j < n and text[j] == "#":
                hashes += 1
                j += 1
            if j < n and text[j] == '"':
                j += 1
                end_pat = '"' + ("#" * hashes)
                end = text.find(end_pat, j)
                if end < 0:
                    break
                out.append(text[j:end])
                i = end + len(end_pat)
                continue
        if ch == '"':
            j = i + 1
            buf: list[str] = []
            while j < n:
                c = text[j]
                if c == "\\":
                    if j + 1 >= n:
                        break
                    esc = text[j + 1]
                    if esc == "\n":
                        j += 2
                        continue
                    if esc == "n":
                        buf.append("\n")
                    elif esc == "t":
                        buf.append("\t")
                    elif esc == "r":
                        buf.append("\r")
                    elif esc in {'"', "\\", "0"}:
                        buf.append("" if esc == "0" else esc)
                    else:
                        buf.append(esc)
                    j += 2
                    continue
                if c == '"':
                    out.append("".join(buf))
                    j += 1
                    break
                buf.append(c)
                j += 1
            i = j
            continue
        i += 1
    return out


def scan_production_type_literals(root: Path) -> dict[str, set[str]]:
    """Return ``{family: {types…}}`` from production Rust string literals."""
    found: dict[str, set[str]] = {}
    src = root / "src"
    for path in sorted(src.rglob("*.rs")):
        text = path.read_text(encoding="utf-8")
        for literal in extract_rust_string_literal_contents(text):
            for match in TYPE_LITERAL_RE.finditer(literal):
                name, ty = match.group(1), match.group(2)
                found.setdefault(name, set()).add(ty)
    return found


def load_contract(root: Path) -> list[dict]:
    path = root / "docs" / "prometheus_metric_contract.json"
    items = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(items, list) or not items:
        fail("Empty metric contract", str(path))
    names: list[str] = []
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            fail("Invalid metric contract row", f"row {index} must be an object")
        dynamic_fields = DYNAMIC_CONTRACT_FIELDS.intersection(item)
        expected_fields = set(BASE_CONTRACT_FIELDS)
        if dynamic_fields:
            expected_fields.update(DYNAMIC_CONTRACT_FIELDS)
        if set(item) != expected_fields:
            fail(
                "Invalid metric contract schema",
                f"row {index}: expected fields {sorted(expected_fields)}, "
                f"got {sorted(item)}",
            )
        name = item["name"]
        if not isinstance(name, str) or METRIC_NAME_RE.fullmatch(name) is None:
            fail("Invalid metric family name", f"row {index}: {name!r}")
        names.append(name)
    if names != sorted(names):
        fail("Metric contract unsorted", "family names must be strictly sorted")
    if len(names) != len(set(names)):
        fail("Metric contract duplicates", "family names must be unique")
    for item in items:
        name = item["name"]
        if item["type"] not in VALID_TYPES:
            fail("Invalid metric type", f"{name}: {item['type']}")
        help_text = item["help"]
        if (
            not isinstance(help_text, str)
            or not help_text
            or help_text != help_text.strip()
            or "\n" in help_text
            or help_text.endswith("\\n")
            or "|" in help_text
        ):
            fail("Missing metric help", name)
        labels = item["labels"]
        if not isinstance(labels, list) or any(
            not isinstance(label, str) or LABEL_NAME_RE.fullmatch(label) is None
            for label in labels
        ):
            fail("Missing metric labels", name)
        if len(labels) != len(set(labels)):
            fail("Duplicate metric labels", name)
        subsystem = item["subsystem"]
        if not isinstance(subsystem, str) or SUBSYSTEM_RE.fullmatch(subsystem) is None:
            fail("Missing subsystem", name)
        if item["bundled"] not in VALID_BUNDLED:
            fail("Invalid bundled classification", f"{name}: {item['bundled']}")
        if item["emission"] not in VALID_EMISSION:
            fail("Invalid emission classification", f"{name}: {item['emission']}")
        if item["export_surface"] != "/metrics":
            fail("Unexpected export surface", f"{name}: {item['export_surface']}")
        if "name_template" in item:
            template = item["name_template"]
            prefix = item["default_prefix"]
            if (
                not isinstance(template, str)
                or template.count("{prefix}") != 1
                or not isinstance(prefix, str)
                or METRIC_NAME_RE.fullmatch(prefix + "_sentinel") is None
                or template.replace("{prefix}", prefix) != name
            ):
                fail(
                    "Invalid dynamic metric family",
                    f"{name}: name_template/default_prefix do not reproduce the family",
                )
    missing = REQUIRED_FAMILIES.difference(names)
    if missing:
        fail("DOC-10 required families missing", ", ".join(sorted(missing)))
    return items


def reference_row(item: dict) -> str:
    labels = (
        ", ".join(f"`{label}`" for label in item["labels"])
        if item["labels"]
        else "—"
    )
    return (
        f"| `{item['name']}` | {item['type']} | {labels} | "
        f"`{item['subsystem']}` | `{item['bundled']}` | `{item['emission']}` | "
        f"{item['help']} |"
    )


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
    section_marker = "## Complete family inventory"
    next_marker = "## Bundled observability surfaces"
    if section_marker not in doc or next_marker not in doc:
        fail("Missing complete inventory section", "docs/prometheus_metrics.md")
    inventory_section = doc.split(section_marker, 1)[1].split(next_marker, 1)[0]
    actual_rows = [
        line for line in inventory_section.splitlines() if line.startswith("| `")
    ]
    expected_rows = [reference_row(item) for item in items]
    if actual_rows != expected_rows:
        mismatch = next(
            (
                index
                for index, (actual, expected) in enumerate(
                    zip(actual_rows, expected_rows, strict=False)
                )
                if actual != expected
            ),
            min(len(actual_rows), len(expected_rows)),
        )
        fail(
            "Prometheus reference diverges from inventory",
            f"first mismatch at generated row {mismatch + 1}; "
            f"expected {len(expected_rows)} rows, found {len(actual_rows)}",
        )
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

    alert_names = ferrum_names(alert_text, by_name)
    dash_names = ferrum_names(dash_text, by_name)
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


def validate_source_type_literals(root: Path, items: list[dict]) -> None:
    by_name = {item["name"]: item for item in items}
    found = scan_production_type_literals(root)
    if not found:
        fail("No production # TYPE literals", "expected Ferrum metric TYPE strings under src/")

    missing = sorted(name for name in found if name not in by_name)
    if missing:
        fail(
            "Production # TYPE family missing from inventory",
            ", ".join(missing),
        )

    mismatches: list[str] = []
    for name, types in sorted(found.items()):
        contract_type = by_name[name]["type"]
        if types != {contract_type}:
            mismatches.append(f"{name}: contract={contract_type} source={sorted(types)}")
    if mismatches:
        fail("Production # TYPE type mismatch", "; ".join(mismatches))

    # Negative/mutation regression: a synthetic undocumented literal must be detected.
    synthetic = 'output.push_str("# TYPE ferrum_contract_mutation_missing_total counter\\n");'
    synthetic_types: dict[str, set[str]] = {}
    for literal in extract_rust_string_literal_contents(synthetic):
        for match in TYPE_LITERAL_RE.finditer(literal):
            synthetic_types.setdefault(match.group(1), set()).add(match.group(2))
    if "ferrum_contract_mutation_missing_total" not in synthetic_types:
        fail(
            "TYPE literal scanner regression",
            "synthetic undocumented # TYPE literal was not detected",
        )
    if "ferrum_contract_mutation_missing_total" in by_name:
        fail(
            "TYPE literal scanner regression",
            "mutation sentinel unexpectedly present in inventory",
        )
    # Comment/identifier noise must not be treated as an export.
    noise = (
        "// # TYPE ferrum_comment_noise_total counter\n"
        "let ferrum_identifier_noise_total = 1;\n"
        "/* # TYPE ferrum_block_comment_noise_total gauge */\n"
    )
    for literal in extract_rust_string_literal_contents(noise):
        if TYPE_LITERAL_RE.search(literal):
            fail(
                "TYPE literal scanner false positive",
                "comment/identifier noise parsed as a metric TYPE literal",
            )

    print(f"production # TYPE literal inventory coverage ok ({len(found)} families)")


def validate_suffix_normalization(items: list[dict]) -> None:
    by_name = {item["name"]: item for item in items}
    if "ferrum_database_delta_backoff_bucket" not in by_name:
        fail(
            "Missing backoff bucket gauge",
            "ferrum_database_delta_backoff_bucket must remain inventoried",
        )
    if by_name["ferrum_database_delta_backoff_bucket"]["type"] != "gauge":
        fail(
            "Backoff bucket type drift",
            "ferrum_database_delta_backoff_bucket must be a gauge",
        )
    assert (
        normalize_family_name("ferrum_database_delta_backoff_bucket", by_name)
        == "ferrum_database_delta_backoff_bucket"
    )
    histogram = next(
        (item["name"] for item in items if item["type"] == "histogram"),
        None,
    )
    if histogram is None:
        fail("Missing histogram family", "contract must inventory at least one histogram")
    assert normalize_family_name(f"{histogram}_bucket", by_name) == histogram
    assert normalize_family_name(f"{histogram}_sum", by_name) == histogram
    assert normalize_family_name(f"{histogram}_count", by_name) == histogram
    print("sample-suffix normalization ok")


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
    validate_source_type_literals(root, items)
    validate_suffix_normalization(items)
    print(f"DOC-10 prometheus metric contract ok ({len(items)} families)")


if __name__ == "__main__":
    main()
