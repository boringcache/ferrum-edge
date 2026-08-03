#!/usr/bin/env python3
"""Pure data helpers for the multicluster poller-partition fixture."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sys
import time
import uuid
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


def read_stdin_json() -> object:
    return json.load(sys.stdin)


def mint_admin_jwt(secret: str) -> None:
    now = int(time.time())

    def encode(value: object) -> str:
        encoded = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
        return base64.urlsafe_b64encode(encoded).rstrip(b"=").decode()

    header = encode({"alg": "HS256", "typ": "JWT"})
    claims = encode(
        {
            "iss": "ferrum-edge",
            "sub": "poller-live",
            "iat": now,
            "nbf": now - 1,
            "exp": now + 3600,
            "jti": str(uuid.uuid4()),
            "role": "admin",
        }
    )
    payload = f"{header}.{claims}"
    signature = base64.urlsafe_b64encode(
        hmac.new(secret.encode(), payload.encode(), hashlib.sha256).digest()
    ).rstrip(b"=")
    print(f"{payload}.{signature.decode()}")


def state_matches(
    peer: str,
    discovered: str,
    trust_source: str,
    outbound: str,
    inbound: str,
) -> None:
    payload = read_stdin_json()
    if not isinstance(payload, dict):
        raise SystemExit(1)
    configured = payload.get("configured")
    if not isinstance(configured, list):
        raise SystemExit(1)
    rows = [row for row in configured if row.get("cluster_name") == peer]
    expected = {
        "discovered": discovered == "true",
        "trust_source": trust_source,
        "outbound_trust_active": outbound == "true",
        "inbound_trust_active": inbound == "true",
    }
    if len(rows) != 1 or any(
        rows[0].get(key) != value for key, value in expected.items()
    ):
        raise SystemExit(1)


def no_configured_state() -> None:
    payload = read_stdin_json()
    if (
        not isinstance(payload, dict)
        or payload.get("configured")
        or payload.get("discovered")
    ):
        raise SystemExit(1)


def remote_ages(peer: str) -> tuple[int, int]:
    payload = read_stdin_json()
    if not isinstance(payload, dict):
        raise SystemExit(1)
    configured = next(
        row for row in payload.get("configured", []) if row.get("cluster_name") == peer
    )
    discovered = next(
        row for row in payload.get("discovered", []) if row.get("cluster_name") == peer
    )
    return (
        int(configured["trust_bundle_age_seconds"]),
        int(discovered["age_seconds"]),
    )


def ages_between(peer: str, low: int, high: int) -> None:
    trust_age, endpoint_age = remote_ages(peer)
    if not (low <= trust_age < high and low <= endpoint_age < high):
        raise SystemExit(1)


def metric_value(text: str, name: str, labels: dict[str, str]) -> float:
    for line in text.splitlines():
        if line.startswith(name + "{") and all(
            f'{key}="{value}"' in line for key, value in labels.items()
        ):
            return float(line.rsplit(" ", 1)[1])
    raise SystemExit(f"missing {name}")


def assert_metric_admin_parity(
    json_path: Path,
    metrics_path: Path,
    peer: str,
    trust_domain: str,
) -> None:
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    text = metrics_path.read_text(encoding="utf-8")
    configured = next(
        row for row in payload["configured"] if row["cluster_name"] == peer
    )
    discovered = next(
        row for row in payload["discovered"] if row["cluster_name"] == peer
    )
    federation_age = metric_value(
        text,
        "ferrum_mesh_federation_bundle_age_seconds",
        {"trust_domain": trust_domain},
    )
    endpoint_age = metric_value(
        text,
        "ferrum_mesh_remote_discovery_endpoint_age_seconds",
        {"cluster": peer, "trust_domain": trust_domain},
    )
    if abs(federation_age - configured["trust_bundle_age_seconds"]) > 2 or abs(
        endpoint_age - discovered["age_seconds"]
    ) > 2:
        raise SystemExit("admin/metric cache-age parity exceeded 2s")
    if (
        'endpoint="redacted"' not in text
        and "ferrum_mesh_federation_poll_failures_total" in text
    ):
        raise SystemExit("federation endpoint label not redacted")
    if (
        'control_plane="redacted"' not in text
        and "ferrum_mesh_remote_discovery_poll_failures_total" in text
    ):
        raise SystemExit("control-plane label not redacted")
    families = {
        "ferrum_mesh_federation_poll_failures_total": f'trust_domain="{trust_domain}"',
        "ferrum_mesh_federation_bundle_age_seconds": f'trust_domain="{trust_domain}"',
        "ferrum_mesh_remote_discovery_poll_failures_total": f'cluster="{peer}"',
        "ferrum_mesh_remote_discovery_poll_successes_total": f'cluster="{peer}"',
        "ferrum_mesh_remote_discovery_endpoint_age_seconds": f'cluster="{peer}"',
    }
    for family, selector in families.items():
        matches = [
            line
            for line in text.splitlines()
            if line.startswith(family + "{") and selector in line
        ]
        if len(matches) != 1:
            raise SystemExit(
                f"bounded cardinality violated for {family}: {len(matches)}"
            )


def redact_toxiproxy() -> None:
    payload = read_stdin_json()
    if not isinstance(payload, dict):
        raise SystemExit(1)
    for proxy in payload.values():
        if not isinstance(proxy, dict):
            raise SystemExit(1)
        proxy["upstream"] = "redacted"
        proxy["listen"] = "redacted"
    print(json.dumps(payload, indent=2, sort_keys=True))


def main(argv: list[str]) -> None:
    if len(argv) < 2:
        raise SystemExit("fixture helper operation is required")
    operation = argv[1]
    if operation == "mint-admin-jwt" and len(argv) == 3:
        mint_admin_jwt(argv[2])
    elif operation == "proxy-count" and len(argv) == 2:
        payload = read_stdin_json()
        if not isinstance(payload, dict):
            raise SystemExit(1)
        print(len(payload))
    elif operation == "bundle-json" and len(argv) == 4:
        print(
            json.dumps(
                {
                    "trust_domain": argv[2],
                    "x509_authorities": argv[3].splitlines(),
                    "jwt_authorities": [],
                }
            )
        )
    elif operation == "state-matches" and len(argv) == 7:
        state_matches(*argv[2:])
    elif operation == "no-configured-state" and len(argv) == 2:
        no_configured_state()
    elif operation == "ages-between" and len(argv) == 5:
        ages_between(argv[2], int(argv[3]), int(argv[4]))
    elif operation == "admin-ages" and len(argv) == 3:
        print(*remote_ages(argv[2]))
    elif operation == "assert-metric-admin-parity" and len(argv) == 6:
        assert_metric_admin_parity(Path(argv[2]), Path(argv[3]), argv[4], argv[5])
    elif operation == "redact-toxiproxy" and len(argv) == 2:
        redact_toxiproxy()
    elif len(argv) < 3:
        raise SystemExit("live assertion operation requires an output path")
    elif operation == "init" and len(argv) == 5:
        path = Path(argv[2])
        init(path, argv[3], argv[4])
    elif operation == "record" and len(argv) == 7:
        path = Path(argv[2])
        record(path, argv[3], argv[4], argv[5], argv[6])
    elif operation == "require" and len(argv) > 3:
        path = Path(argv[2])
        require(path, argv[3:])
    else:
        raise SystemExit(f"invalid live assertion operation or arguments: {operation}")


if __name__ == "__main__":
    main(sys.argv)
