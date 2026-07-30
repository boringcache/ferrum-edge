#!/usr/bin/env python3
"""Extract Helm-rendered PrometheusRule groups for promtool validation."""

from __future__ import annotations

import sys
from pathlib import Path

import yaml


MAX_RENDERED_BYTES = 16 * 1024 * 1024


def fail(message: str) -> None:
    raise SystemExit(f"::error::{message}")


def load_rule_groups(rendered_path: Path) -> list[object]:
    try:
        rendered_size = rendered_path.stat().st_size
    except OSError as error:
        fail(f"cannot stat rendered Helm output: {error}")
    if rendered_size > MAX_RENDERED_BYTES:
        fail(
            "rendered Helm output exceeds the "
            f"{MAX_RENDERED_BYTES}-byte validation limit"
        )

    try:
        rendered = rendered_path.read_text(encoding="utf-8")
        documents = list(yaml.safe_load_all(rendered))
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        fail(f"cannot load rendered Helm output: {error}")

    groups: list[object] = []
    for document in documents:
        if not isinstance(document, dict) or document.get("kind") != "PrometheusRule":
            continue
        spec = document.get("spec")
        if not isinstance(spec, dict) or not isinstance(spec.get("groups"), list):
            fail("rendered PrometheusRule is missing spec.groups")
        groups.extend(spec["groups"])

    if not groups:
        fail("Helm render produced no PrometheusRule groups")
    return groups


def main(argv: list[str]) -> None:
    if len(argv) != 3:
        fail(
            "usage: extract_rendered_prometheus_rules.py "
            "<rendered-helm-yaml> <prometheus-rules-yaml>"
        )

    rendered_path = Path(argv[1])
    rules_path = Path(argv[2])
    groups = load_rule_groups(rendered_path)
    try:
        rules_path.write_text(
            yaml.safe_dump({"groups": groups}, sort_keys=False),
            encoding="utf-8",
        )
    except OSError as error:
        fail(f"cannot write extracted Prometheus rules: {error}")


if __name__ == "__main__":
    main(sys.argv)
