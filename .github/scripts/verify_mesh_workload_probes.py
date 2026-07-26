#!/usr/bin/env python3
"""Hosted CI checks for mesh workload startup/liveness/readiness probes (#2450).

Kept out of `.github/workflows/ci.yml` shell so the trusted ARM64 build-policy
gate can compare unprotected workflow surfaces without freezing routine
probe-shape assertions into the workflow. Process launches (`helm template`)
stay in the trusted workflow shell; this script only statically parses captured
results and the declarative expectations fixture beside it.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_EXPECTATIONS = Path(__file__).with_name(
    "mesh_workload_probes_expectations.json"
)

PROBE_KEYS = ("startupProbe", "livenessProbe", "readinessProbe")


def fail(title: str, detail: str) -> None:
    print(f"::error title={title}::{detail}")
    raise SystemExit(1)


def load_expectations(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail("Mesh probe expectations unreadable", f"{path}: {exc}")
    if not isinstance(data, dict):
        fail("Mesh probe expectations invalid", f"{path} must be a JSON object")
    return data


def require_capture(results_dir: Path, relative: str) -> Path:
    path = results_dir / relative
    if not path.is_file():
        fail(
            "Missing mesh probe capture",
            f"workflow must write {relative} under {results_dir} before this script",
        )
    return path


def split_documents(rendered: str) -> list[str]:
    return [doc for doc in re.split(r"(?m)^---\s*$", rendered) if doc.strip()]


def resource_document(rendered: str, name: str, kind: str) -> str:
    for doc in split_documents(rendered):
        if not re.search(rf"(?m)^kind:\s*{re.escape(kind)}\s*$", doc):
            continue
        if re.search(rf"(?m)^  name:\s*{re.escape(name)}\s*$", doc):
            return doc
    fail(
        "Mesh workload missing from render",
        f"{kind}/{name} must appear in the captured Helm render",
    )
    raise AssertionError("unreachable")


def extract_probe(resource: str, probe_key: str) -> str | None:
    """Return the indented probe block for probe_key, or None if absent."""

    match = re.search(
        rf"(?m)^(?P<indent>[ \t]+){re.escape(probe_key)}:\s*(?P<body>.*)$",
        resource,
    )
    if match is None:
        return None
    indent = match.group("indent")
    indent_len = len(indent)
    lines = [match.group(0) + "\n"]
    rest = resource[match.end() :]
    if rest.startswith("\n"):
        rest = rest[1:]
    # Inline body on the same line is uncommon for probes but keep it.
    for line in rest.splitlines(keepends=True):
        if not line.strip():
            lines.append(line)
            continue
        current_indent = len(line) - len(line.lstrip(" \t"))
        if current_indent <= indent_len:
            break
        lines.append(line)
    return "".join(lines)


def require_probe(resource: str, name: str, probe_key: str) -> str:
    block = extract_probe(resource, probe_key)
    if block is None:
        fail(
            "Mesh probe missing",
            f"{name} must render {probe_key} by default",
        )
    return block


def assert_admin_health_pair(name: str, live: str, ready: str) -> None:
    if "health" not in live or "--live" not in live:
        fail(
            "Admin liveness not process-only",
            f"{name} startup/liveness must run ferrum-edge health --live",
        )
    if "health" not in ready:
        fail(
            "Admin readiness missing health",
            f"{name} readiness must run ferrum-edge health",
        )
    if "--live" in ready:
        fail(
            "Admin readiness coupled to liveness",
            f"{name} readiness must probe /health without --live",
        )


def assert_tcp_port(name: str, block: str, port: str) -> None:
    if "tcpSocket:" not in block or not re.search(
        rf"(?m)^\s+port:\s*{re.escape(port)}\s*$", block
    ):
        fail(
            "TCP probe port mismatch",
            f"{name} must default to tcpSocket on {port}",
        )


def validate_defaults(results_dir: Path, expectations: dict) -> None:
    captures = expectations["captures"]
    rendered = require_capture(results_dir, captures["default"]).read_text(
        encoding="utf-8"
    )
    for workload in expectations["workloads"]:
        name = workload["name"]
        resource = resource_document(rendered, name, workload["kind"])
        startup = require_probe(resource, name, "startupProbe")
        liveness = require_probe(resource, name, "livenessProbe")
        readiness = require_probe(resource, name, "readinessProbe")
        handler = workload["handler"]
        if handler == "admin_health":
            assert_admin_health_pair(name, startup, readiness)
            assert_admin_health_pair(name, liveness, readiness)
        elif handler == "tcp":
            port = workload["tcp_port"]
            assert_tcp_port(name, startup, port)
            assert_tcp_port(name, liveness, port)
            assert_tcp_port(name, readiness, port)
        else:
            fail("Unknown probe handler kind", f"{name}: {handler!r}")
    print("mesh probe defaults ok")


def validate_disabled(results_dir: Path, expectations: dict) -> None:
    captures = expectations["captures"]
    rendered = require_capture(results_dir, captures["disabled"]).read_text(
        encoding="utf-8"
    )
    for probe_key in PROBE_KEYS:
        if re.search(rf"(?m)^\s*{re.escape(probe_key)}:\s*$", rendered):
            fail(
                "Disabled mesh probes still rendered",
                f"enabled=false must omit {probe_key} for every first-class workload",
            )
    print("mesh probe disabled ok")


def validate_override(results_dir: Path, expectations: dict) -> None:
    captures = expectations["captures"]
    rendered = require_capture(results_dir, captures["override"]).read_text(
        encoding="utf-8"
    )
    resource = resource_document(
        rendered, "ferrum-mesh-control-plane", "Deployment"
    )
    liveness = require_probe(resource, "ferrum-mesh-control-plane", "livenessProbe")
    readiness = require_probe(resource, "ferrum-mesh-control-plane", "readinessProbe")
    startup = require_probe(resource, "ferrum-mesh-control-plane", "startupProbe")
    if "httpGet:" not in liveness or not re.search(
        r"(?m)^\s+path:\s*/live\s*$", liveness
    ):
        fail(
            "Per-probe liveness override missing",
            "controlPlane.probes.liveness.override must replace the liveness handler",
        )
    # Startup shares the liveness handler, so the override reaches startup too.
    if "httpGet:" not in startup or not re.search(
        r"(?m)^\s+path:\s*/live\s*$", startup
    ):
        fail(
            "Startup did not inherit liveness override",
            "startupProbe must use the overridden liveness handler",
        )
    if "httpGet:" in readiness or re.search(r"(?m)^\s+path:\s*/live\s*$", readiness):
        fail(
            "Per-probe override leaked into readiness",
            "liveness.override must not replace the readiness handler",
        )
    if "health" not in readiness or "--live" in readiness:
        fail(
            "Readiness drifted after liveness override",
            "control-plane readiness must remain health without --live",
        )
    print("mesh probe override ok")


def validate_coupled_rejected(results_dir: Path, expectations: dict) -> None:
    captures = expectations["captures"]
    err_path = require_capture(results_dir, captures["coupled_err"])
    err_text = err_path.read_text(encoding="utf-8")
    if not err_text.strip():
        fail(
            "Coupled mesh probe override accepted",
            "controlPlane.probes.override must fail schema validation",
        )
    # Helm JSON schema wording varies slightly; require a property/additional hint.
    if not re.search(
        r"override|additional propert|Additional propert",
        err_text,
        re.IGNORECASE,
    ):
        fail(
            "Coupled override rejection message drift",
            "stderr must mention the rejected shared probes.override shape",
        )
    print("mesh probe coupled override rejected ok")


def validate_node_agent_port0(results_dir: Path, expectations: dict) -> None:
    captures = expectations["captures"]
    rendered = require_capture(results_dir, captures["node_agent_port0"]).read_text(
        encoding="utf-8"
    )
    resource = resource_document(
        rendered, "ferrum-mesh-node-agent", "DaemonSet"
    )
    if extract_probe(resource, "readinessProbe") is not None:
        fail(
            "Node-agent port 0 still ready",
            "admin port 0 must omit readinessProbe",
        )
    print("mesh probe node-agent port 0 ok")


def validate_node_waypoint_ambient(results_dir: Path, expectations: dict) -> None:
    captures = expectations["captures"]
    rendered = require_capture(results_dir, captures["node_waypoint"]).read_text(
        encoding="utf-8"
    )
    ambient = expectations["node_waypoint_ambient"]
    resource = resource_document(rendered, ambient["name"], ambient["kind"])
    readiness = require_probe(resource, ambient["name"], "readinessProbe")
    liveness = require_probe(resource, ambient["name"], "livenessProbe")
    port = ambient["admin_port"]
    if not re.search(rf'(?m)^\s+-\s+"{re.escape(port)}"\s*$', readiness):
        fail(
            "NodeWaypoint ambient readiness regress",
            f"ambient readiness must dial admin port {port}",
        )
    if "health" not in readiness or "--live" in readiness:
        fail(
            "NodeWaypoint ambient readiness regress",
            "ambient readiness must keep admin /health without --live",
        )
    if "health" not in liveness or "--live" not in liveness:
        fail(
            "Ambient liveness not process-only",
            "ambient livenessProbe must run health --live",
        )
    print("mesh probe NodeWaypoint ambient ok")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=REPO_ROOT,
        help="Repository root (defaults to the checkout containing this script)",
    )
    parser.add_argument(
        "--results-dir",
        type=Path,
        required=True,
        help="Directory with helm template stdout/stderr captures from the workflow",
    )
    parser.add_argument(
        "--expectations",
        type=Path,
        default=DEFAULT_EXPECTATIONS,
        help="Declarative JSON fixture of workload/probe expectations",
    )
    args = parser.parse_args(argv)
    _ = args.root.resolve()
    results_dir = args.results_dir.resolve()
    expectations = load_expectations(args.expectations.resolve())

    validate_defaults(results_dir, expectations)
    validate_disabled(results_dir, expectations)
    validate_override(results_dir, expectations)
    validate_coupled_rejected(results_dir, expectations)
    validate_node_agent_port0(results_dir, expectations)
    validate_node_waypoint_ambient(results_dir, expectations)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
