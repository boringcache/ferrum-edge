#!/usr/bin/env python3
"""Fail-closed GNU ABI gate for published ferrum-edge and ferrum-cni binaries.

The scanner reads DT_NEEDED and GNU version-need records from an ELF, rejects
GLIBC symbol versions above the declared floor, and rejects unexpected shared
libraries. It is the hosted artifact gate for issue #4301: a moving
ubuntu-latest glibc floor must not ship.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = REPO_ROOT / ".github" / "linux-gnu-abi.toml"
RELEASE_YML = REPO_ROOT / ".github" / "workflows" / "release.yml"
CI_YML = REPO_ROOT / ".github" / "workflows" / "ci.yml"
README = REPO_ROOT / "README.md"
CLI_MD = REPO_ROOT / "docs" / "cli.md"
CI_CD_MD = REPO_ROOT / "docs" / "ci_cd.md"

GLIBC_VERSION_RE = re.compile(r"\bGLIBC_(\d+(?:\.\d+)*)\b")
NEEDED_RE = re.compile(r"\(NEEDED\)\s+Shared library:\s+\[([^\]]+)\]")
LINUX_GNU_ASSETS = (
    "ferrum-edge-linux-x86_64",
    "ferrum-cni-linux-x86_64",
    "ferrum-edge-linux-aarch64",
    "ferrum-cni-linux-aarch64",
)


def load_contract(path: Path = CONTRACT_PATH) -> dict[str, Any]:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def parse_version(text: str) -> tuple[int, ...]:
    parts = text.split(".")
    if not parts or any(not part.isdigit() for part in parts):
        raise ValueError(f"invalid version {text!r}")
    return tuple(int(part) for part in parts)


def version_exceeds(observed: tuple[int, ...], ceiling: tuple[int, ...]) -> bool:
    return observed > ceiling


def glibc_versions_from_readelf(text: str) -> list[str]:
    return sorted(set(GLIBC_VERSION_RE.findall(text)))


def needed_libraries_from_readelf(text: str) -> list[str]:
    return sorted(set(NEEDED_RE.findall(text)))


def run_readelf(binary: Path, *args: str) -> str:
    readelf = shutil.which("readelf")
    if readelf is None:
        raise RuntimeError("readelf is required for the GNU ABI gate")
    completed = subprocess.run(
        [readelf, *args, str(binary)],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        stderr = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(f"readelf {' '.join(args)} failed for {binary}: {stderr}")
    return completed.stdout


def scan_binary(binary: Path, contract: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if not binary.is_file() or binary.is_symlink():
        return [f"{binary} is not a regular file"]

    header = binary.read_bytes()[:4]
    if header != b"\x7fELF":
        return [f"{binary} is not an ELF file"]

    version_text = run_readelf(binary, "-V")
    dynamic_text = run_readelf(binary, "-d")
    versions = glibc_versions_from_readelf(version_text)
    needed = needed_libraries_from_readelf(dynamic_text)
    ceiling = parse_version(str(contract["glibc_max_version"]))
    allowed = set(contract["allowed_needed"])

    if not versions:
        errors.append(f"{binary} has no GLIBC version-need records")
    else:
        observed = [parse_version(item) for item in versions]
        maximum = max(observed)
        if version_exceeds(maximum, ceiling):
            pretty = ".".join(str(part) for part in maximum)
            errors.append(
                f"{binary} requires GLIBC_{pretty}, above the declared floor "
                f"GLIBC_{contract['glibc_max_version']}"
            )

    if "libc.so.6" not in needed:
        errors.append(f"{binary} is missing libc.so.6 (GNU artifacts must be dynamically linked)")

    unexpected = [name for name in needed if name not in allowed]
    if unexpected:
        errors.append(
            f"{binary} dynamically links unexpected libraries: {', '.join(unexpected)}"
        )
    return errors


def scan_assets(paths: list[Path], contract: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if not paths:
        return ["no GNU binaries were supplied to the ABI gate"]
    for path in paths:
        errors.extend(scan_binary(path, contract))
    return errors


def workflow_contains(workflow: str, token: str) -> bool:
    return token in workflow


def check_release_wiring(contract: dict[str, Any], release_yml: str, ci_yml: str) -> list[str]:
    errors: list[str] = []
    sysroot_image = contract["sysroot"]["image"]
    smoke_floor = contract["smoke"]["floor"]["image"]
    smoke_ubuntu = contract["smoke"]["ubuntu2204"]["image"]
    protoc_sha = contract["sysroot"]["protoc_sha256"]

    for token, label in (
        (sysroot_image, "pinned GNU sysroot image"),
        (smoke_floor, "oldest-baseline smoke image"),
        (smoke_ubuntu, "Ubuntu 22.04 smoke image"),
        (protoc_sha, "pinned protoc SHA-256"),
        ("verify-linux-gnu-abi:", "verify-linux-gnu-abi job"),
        (
            "  verify-linux-gnu-abi:\n"
            "    name: Verify Linux GNU ABI\n"
            "    needs: [build-release-binaries, build-release-arm64-cross]\n",
            "verify-linux-gnu-abi needs both GNU build jobs",
        ),
        ("linux-gnu-abi-release-gate:", "linux-gnu-abi-release-gate job"),
        (
            "    needs: [create-release, verify-linux-gnu-abi]\n",
            "ABI join-gate needs",
        ),
        ("    needs: [create-release, attest-release-images]\n", "frozen attestation-gate needs"),
        ("ubuntu-24.04-arm", "ARM64 GNU ABI/smoke runner"),
        ("python3 -I .github/scripts/verify_linux_gnu_abi.py --self-test", "ABI self-test"),
        ("python3 -I .github/scripts/verify_linux_gnu_abi.py --check-contract", "ABI contract check"),
        ("python3 -I .github/scripts/smoke_linux_gnu_baseline.py", "baseline smoke invocation"),
        ("build_linux_gnu_sysroot.sh", "sysroot build helper"),
        ("LIBZ_SYS_STATIC=1", "static zlib for the GNU sysroot build"),
    ):
        if not workflow_contains(release_yml, token):
            errors.append(f"release.yml is missing required {label} ({token})")

    # Publication still consumes the historical GNU asset names.
    for asset in LINUX_GNU_ASSETS:
        if asset not in release_yml:
            errors.append(f"release.yml must keep publishing {asset}")

    # Frozen create-release needs must not grow an ABI edge; the join gate is
    # the admitted place to fail-close after those frozen jobs.
    if (
        "needs: [build-release-binaries, build-release-arm64-cross, "
        "docker-manifest, docker-ebpf-manifest, docker-ebpf-tools-manifest]"
        not in release_yml
    ):
        errors.append("release.yml changed the frozen create-release needs graph")

    for token, label in (
        (sysroot_image, "pinned GNU sysroot image"),
        ("build_linux_gnu_sysroot.sh", "sysroot build helper"),
        ("python3 -I .github/scripts/verify_linux_gnu_abi.py --self-test", "ABI self-test"),
        ("LIBZ_SYS_STATIC=1", "static zlib for the GNU sysroot build"),
    ):
        if not workflow_contains(ci_yml, token):
            errors.append(f"ci.yml is missing required {label} ({token})")

    return errors


def check_operator_docs(readme: str, cli_md: str, ci_cd_md: str, contract: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    floor = f"GLIBC_{contract['glibc_max_version']}"
    for label, text in (("README.md", readme), ("docs/cli.md", cli_md), ("docs/ci_cd.md", ci_cd_md)):
        for token in (floor, "AlmaLinux 8.10", "libgcc_s.so.1", "libz.so.1"):
            if token not in text:
                errors.append(f"{label} must document {token}")
        if "ferrum-edge-linux-x86_64" not in text:
            errors.append(f"{label} must keep the GNU x86_64 artifact name")
    return errors


def check_repository() -> list[str]:
    contract = load_contract()
    errors: list[str] = []
    if str(contract.get("glibc_max_version")) != "2.34":
        errors.append("declared GLIBC floor must be 2.34")
    errors.extend(
        check_release_wiring(
            contract,
            RELEASE_YML.read_text(encoding="utf-8"),
            CI_YML.read_text(encoding="utf-8"),
        )
    )
    errors.extend(
        check_operator_docs(
            README.read_text(encoding="utf-8"),
            CLI_MD.read_text(encoding="utf-8"),
            CI_CD_MD.read_text(encoding="utf-8"),
            contract,
        )
    )
    return errors


READELF_FLOOR_FIXTURE = """\
Version symbols section '.gnu.version' contains 4 entries:
  0x0060:   Name: GLIBC_2.2.5  Flags: none  Version: 2
  0x0070:   Name: GLIBC_2.34  Flags: none  Version: 3
Dynamic section at offset 0x0 contains 4 entries:
  0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]
  0x0000000000000001 (NEEDED)             Shared library: [libgcc_s.so.1]
  0x0000000000000001 (NEEDED)             Shared library: [ld-linux-x86-64.so.2]
"""

READELF_TOO_NEW_FIXTURE = """\
Version symbols section '.gnu.version' contains 4 entries:
  0x0060:   Name: GLIBC_2.2.5  Flags: none  Version: 2
  0x0070:   Name: GLIBC_2.39  Flags: none  Version: 3
Dynamic section at offset 0x0 contains 3 entries:
  0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]
  0x0000000000000001 (NEEDED)             Shared library: [libz.so.1]
"""

READELF_UNEXPECTED_LIB_FIXTURE = """\
Version symbols section '.gnu.version' contains 2 entries:
  0x0060:   Name: GLIBC_2.17  Flags: none  Version: 2
Dynamic section at offset 0x0 contains 3 entries:
  0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]
  0x0000000000000001 (NEEDED)             Shared library: [libssl.so.3]
"""


def evaluate_readelf_fixture(text: str, contract: dict[str, Any], label: str) -> list[str]:
    errors: list[str] = []
    versions = glibc_versions_from_readelf(text)
    needed = needed_libraries_from_readelf(text)
    ceiling = parse_version(str(contract["glibc_max_version"]))
    allowed = set(contract["allowed_needed"])
    if versions:
        maximum = max(parse_version(item) for item in versions)
        if version_exceeds(maximum, ceiling):
            pretty = ".".join(str(part) for part in maximum)
            errors.append(
                f"{label} requires GLIBC_{pretty}, above the declared floor "
                f"GLIBC_{contract['glibc_max_version']}"
            )
    else:
        errors.append(f"{label} has no GLIBC version-need records")
    if "libc.so.6" not in needed:
        errors.append(f"{label} is missing libc.so.6")
    unexpected = [name for name in needed if name not in allowed]
    if unexpected:
        errors.append(f"{label} dynamically links unexpected libraries: {', '.join(unexpected)}")
    return errors


def run_self_test() -> list[str]:
    failures: list[str] = []
    contract = load_contract()
    ceiling = parse_version("2.34")

    if parse_version("2.34") > ceiling:
        failures.append("equal floor version was treated as too new")
    if not version_exceeds(parse_version("2.39"), ceiling):
        failures.append("GLIBC_2.39 was not rejected against the 2.34 floor")
    if version_exceeds(parse_version("2.17"), ceiling):
        failures.append("GLIBC_2.17 was rejected against the 2.34 floor")
    if not version_exceeds(parse_version("2.34.1"), ceiling):
        failures.append("GLIBC_2.34.1 was not rejected against the 2.34 floor")

    if evaluate_readelf_fixture(READELF_FLOOR_FIXTURE, contract, "floor-fixture"):
        failures.append("in-floor GLIBC_2.34 fixture was rejected")
    too_new = evaluate_readelf_fixture(READELF_TOO_NEW_FIXTURE, contract, "too-new-fixture")
    if not any("GLIBC_2.39" in item for item in too_new):
        failures.append("GLIBC_2.39 fixture was not rejected")
    unexpected = evaluate_readelf_fixture(
        READELF_UNEXPECTED_LIB_FIXTURE, contract, "unexpected-lib-fixture"
    )
    if not any("libssl.so.3" in item for item in unexpected):
        failures.append("unexpected SONAME fixture was not rejected")

    with tempfile.TemporaryDirectory() as tmp:
        missing = Path(tmp) / "missing"
        missing_errors = scan_binary(missing, contract)
        if not missing_errors:
            failures.append("missing binary was accepted")
        not_elf = Path(tmp) / "not-elf"
        not_elf.write_bytes(b"not an elf")
        not_elf_errors = scan_binary(not_elf, contract)
        if not any("not an ELF file" in item for item in not_elf_errors):
            failures.append("non-ELF file was not rejected")

    mutated_release = RELEASE_YML.read_text(encoding="utf-8").replace(
        contract["sysroot"]["image"], "almalinux:latest", 1
    )
    if not check_release_wiring(
        contract, mutated_release, CI_YML.read_text(encoding="utf-8")
    ):
        failures.append("unpinned sysroot image in release.yml was not rejected")

    mutated_docs = README.read_text(encoding="utf-8").replace("GLIBC_2.34", "GLIBC_2.39", 1)
    if not check_operator_docs(
        mutated_docs,
        CLI_MD.read_text(encoding="utf-8"),
        CI_CD_MD.read_text(encoding="utf-8"),
        contract,
    ):
        failures.append("README GLIBC floor regression was not rejected")

    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--check-contract", action="store_true")
    parser.add_argument("binaries", nargs="*", type=Path)
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    failures: list[str] = []
    if args.self_test:
        failures.extend(run_self_test())
    if args.check_contract:
        failures.extend(check_repository())
    if args.binaries:
        failures.extend(scan_assets(args.binaries, load_contract()))
    if not args.self_test and not args.check_contract and not args.binaries:
        parser.error("supply binaries, --self-test, and/or --check-contract")

    for failure in failures:
        print(f"error: {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
