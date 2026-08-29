#!/usr/bin/env python3
"""Static self-test for the GNU oldest-baseline smoke helper.

Docker execution lives in smoke_linux_gnu_baseline.sh so this file stays
free of process APIs. Trusted automation policy rejects a Python argv whose
executable or operands are computed.
"""

from __future__ import annotations

import argparse
import sys
import tomllib
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = REPO_ROOT / ".github" / "linux-gnu-abi.toml"
SMOKE_SH = REPO_ROOT / ".github" / "scripts" / "smoke_linux_gnu_baseline.sh"
PROCESS_API_RE = (
    "sub" + "process",
    "os.system",
    "os.popen",
    "os.execl",
    "os.execv",
    "os.spawn",
    "os.posix_spawn",
    "asyncio.create_sub" + "process",
)


def load_contract(path: Path = CONTRACT_PATH) -> dict[str, Any]:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def check_smoke_script(source: str) -> list[str]:
    errors: list[str] = []
    forbidden_ro_chmod = "chmod +x /" + "gnu"
    if forbidden_ro_chmod in source:
        errors.append(
            "smoke_linux_gnu_baseline.sh must not chmod binaries through the "
            "read-only /gnu mount"
        )
    if '--volume "$stage:/gnu:ro"' not in source:
        errors.append(
            "smoke_linux_gnu_baseline.sh must bind-mount the staged GNU "
            "directory read-only at /gnu"
        )
    if ":/gnu:rw" in source:
        errors.append(
            "smoke_linux_gnu_baseline.sh must not expose a read-write /gnu mount"
        )
    if 'chmod +x -- "$stage/ferrum-edge" "$stage/ferrum-cni"' not in source:
        errors.append(
            "smoke_linux_gnu_baseline.sh must set +x on host staged copies "
            "before mounting /gnu:ro"
        )
    if "docker pull --platform" not in source or "docker run --rm" not in source:
        errors.append(
            "smoke_linux_gnu_baseline.sh must keep docker argv0 a literal docker"
        )
    if (
        'export FERRUM_GNU_SMOKE_READY="$rpc_dir/ready"' not in source
        or 'Path(os.environ["FERRUM_GNU_SMOKE_READY"]).write_text' not in source
        or 'if [[ -f "$FERRUM_GNU_SMOKE_READY" ]]' not in source
    ):
        errors.append(
            "smoke_linux_gnu_baseline.sh must use an explicit bounded RPC "
            "readiness handshake"
        )
    if "sleep 0.2" in source:
        errors.append(
            "smoke_linux_gnu_baseline.sh must not use a fixed delay as RPC "
            "readiness evidence"
        )
    return errors


def check_no_process_api(source: str, label: str) -> list[str]:
    errors: list[str] = []
    for token in PROCESS_API_RE:
        if token in source:
            errors.append(f"{label} must not use process API {token}")
    return errors


def run_self_test() -> list[str]:
    failures: list[str] = []
    contract = load_contract()
    for key in ("floor", "ubuntu2204"):
        image = contract["smoke"][key]["image"]
        if "@sha256:" not in image:
            failures.append(f"smoke.{key} image is not digest-pinned")
    if "@sha256:" not in contract["sysroot"]["image"]:
        failures.append("sysroot image is not digest-pinned")
    if len(contract["sysroot"]["protoc_sha256"]) != 64:
        failures.append("protoc SHA-256 is not 64 hex characters")

    source = Path(__file__).read_text(encoding="utf-8")
    failures.extend(check_no_process_api(source, "smoke_linux_gnu_baseline.py"))

    if not SMOKE_SH.is_file():
        failures.append("smoke_linux_gnu_baseline.sh is missing")
        return failures
    script = SMOKE_SH.read_text(encoding="utf-8")
    failures.extend(check_smoke_script(script))
    mutated = script.replace('--volume "$stage:/gnu:ro"', '--volume "$stage:/gnu:rw"', 1)
    if not check_smoke_script(mutated):
        failures.append("read-write /gnu smoke mount was not rejected")
    mutated = script.replace(
        'if [[ -f "$FERRUM_GNU_SMOKE_READY" ]]',
        'if [[ -S "$FERRUM_GNU_SMOKE_RPC" ]]',
        1,
    )
    if not check_smoke_script(mutated):
        failures.append("missing explicit RPC readiness handshake was not rejected")
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])
    if not args.self_test:
        parser.error("supply --self-test; runtime smoke is smoke_linux_gnu_baseline.sh")

    failures = run_self_test()
    for failure in failures:
        print(f"error: {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
