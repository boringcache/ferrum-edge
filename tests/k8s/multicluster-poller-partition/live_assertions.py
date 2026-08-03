#!/usr/bin/env python3
"""Write and enforce this fixture's live-assertion artifact."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def init(path: Path, commit: str, platform_profile: str) -> None:
    payload = {
        "schema_version": 1,
        "suite": "multicluster-poller-partition",
        "commit": commit,
        "platform_profile": platform_profile,
        "created_at": timestamp(),
        "assertions": [],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def record(
    path: Path,
    assertion_id: str,
    status: str,
    outcome: str,
    diagnostics_csv: str,
) -> None:
    if status not in {"pass", "fail", "skip"}:
        raise SystemExit(
            f"invalid live assertion status for {assertion_id}: {status}"
        )
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload.setdefault("assertions", []).append(
        {
            "id": assertion_id,
            "status": status,
            "source_workload": "mesh-dp",
            "destination_workload": "mesh-dp",
            "observed_outcome": outcome or None,
            "observed_source_spiffe_id": None,
            "observed_destination_spiffe_id": None,
            "configuration_generation": None,
            "timestamp": timestamp(),
            "diagnostic_artifact_paths": [
                item for item in diagnostics_csv.split(",") if item
            ],
        }
    )
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def require(path: Path, required: list[str]) -> None:
    payload = json.loads(path.read_text(encoding="utf-8"))
    observed = {entry.get("id"): entry for entry in payload.get("assertions", [])}
    missing = [assertion_id for assertion_id in required if assertion_id not in observed]
    failed = [
        assertion_id
        for assertion_id in required
        if assertion_id in observed and observed[assertion_id].get("status") != "pass"
    ]
    if missing:
        print("missing live assertions: " + ", ".join(missing), file=sys.stderr)
    if failed:
        print("non-passing live assertions: " + ", ".join(failed), file=sys.stderr)
    if missing or failed:
        raise SystemExit(1)


def main(argv: list[str]) -> None:
    if len(argv) < 3:
        raise SystemExit("usage: live_assertions.py {init|record|require} OUTPUT ...")
    operation, path = argv[1], Path(argv[2])
    if operation == "init" and len(argv) == 5:
        init(path, argv[3], argv[4])
    elif operation == "record" and len(argv) == 7:
        record(path, argv[3], argv[4], argv[5], argv[6])
    elif operation == "require" and len(argv) > 3:
        require(path, argv[3:])
    else:
        raise SystemExit(f"invalid live assertion operation or arguments: {operation}")


if __name__ == "__main__":
    main(sys.argv)
