#!/usr/bin/env python3
"""Render the mesh baseline collection job summary (#3332).

Reads the provenance and summary JSON the collection job produced and writes a
Markdown digest to `GITHUB_STEP_SUMMARY`. Dispatches no processes.

This lives in an approved automation root instead of an inline workflow heredoc
so the collection workflow keeps a literal, reviewable command surface.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-root", type=Path, required=True)
    return parser.parse_args()


def load_json(path: Path) -> dict[str, object] | None:
    if not path.is_file():
        return None
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return loaded if isinstance(loaded, dict) else None


def render(results_root: Path) -> list[str]:
    lines = ["## Mesh Performance Baselines", ""]
    provenance = load_json(results_root / "provenance.json")
    if provenance is not None:
        runner = provenance.get("runner")
        runner = runner if isinstance(runner, dict) else {}
        ram = runner.get("ram")
        ram = ram if isinstance(ram, dict) else {}
        lines.append(f"- Commit: `{provenance.get('commit_sha')}`")
        lines.append(f"- Runner class: `{runner.get('class')}`")
        lines.append(f"- CPU: `{runner.get('cpu_model')}`")
        lines.append(f"- RAM GiB: `{ram.get('memtotal_gib')}`")
        lines.append(f"- Kernel: `{runner.get('uname')}`")
        lines.append("")
    summary = load_json(results_root / "summary.json")
    if summary is None:
        lines.append("No summary.json produced.")
        return lines

    gate = summary.get("acceptance_gate")
    gate = gate if isinstance(gate, dict) else {}
    selected = summary.get("selected_suite_gates")
    selected = selected if isinstance(selected, dict) else {}
    health = summary.get("runner_health")
    health = health if isinstance(health, dict) else {}
    lines.append(f"- Suites selected: `{summary.get('suites_selected')}`")
    lines.append(
        f"- Selected suite accepted: **{summary.get('selected_suite_accepted')}**"
    )
    lines.append(
        f"- Ready to publish baselines: **{summary.get('ready_to_publish_baselines')}**"
    )
    lines.append(
        f"- Runner health ok: **{gate.get('runner_health_ok')}** "
        f"(max steal `{health.get('max_steal_percent')}`% / "
        f"threshold `{health.get('threshold_percent')}`%)"
    )
    lines.append("")
    lines.append("| Gate | Value |")
    lines.append("|---|---|")
    for key, value in gate.items():
        lines.append(f"| `{key}` | `{value}` |")
    lines.append("")
    lines.append("| Selected suite gate | Value |")
    lines.append("|---|---|")
    for key, value in selected.items():
        lines.append(f"| `{key}` | `{value}` |")
    lines.append("")
    lines.append(
        "Draft markdown for stage-2 publication lives in the artifact under "
        "`drafts/`. Do not treat incomplete/errorful rows as baselines."
    )
    return lines


def main() -> int:
    args = parse_args()
    lines = render(args.results_root)
    body = "\n".join(lines) + "\n"
    destination = os.environ.get("GITHUB_STEP_SUMMARY", "")
    if destination:
        with open(destination, "a", encoding="utf-8") as handle:
            handle.write(body)
    print(body)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
