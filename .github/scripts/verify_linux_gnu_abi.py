#!/usr/bin/env python3
"""Fail-closed GNU ABI gate for published ferrum-edge and ferrum-cni binaries.

The scanner reads DT_NEEDED and GNU version-need records from an ELF, rejects
GLIBC symbol versions above the declared floor, and rejects unexpected shared
libraries. It is the hosted artifact gate for issue #4301: a moving
ubuntu-latest glibc floor must not ship. Parsing stays in-process so trusted
automation policy can inspect this file; computed process argv fails closed.
"""

from __future__ import annotations

import argparse
import re
import struct
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = REPO_ROOT / ".github" / "linux-gnu-abi.toml"
RELEASE_YML = REPO_ROOT / ".github" / "workflows" / "release.yml"
CI_YML = REPO_ROOT / ".github" / "workflows" / "ci.yml"
SMOKE_PY = REPO_ROOT / ".github" / "scripts" / "smoke_linux_gnu_baseline.py"
SMOKE_SH = REPO_ROOT / ".github" / "scripts" / "smoke_linux_gnu_baseline.sh"
PT_LOAD = 1
PT_DYNAMIC = 2
DT_NEEDED = 1
DT_STRTAB = 5
DT_VERNEED = 0x6FFFFFFE
DT_VERNEEDNUM = 0x6FFFFFFF
SYSROOT_BUILD_SH = REPO_ROOT / ".github" / "scripts" / "build_linux_gnu_sysroot.sh"
PROCESS_API_TOKENS = (
    "import sub" + "process",
    "from sub" + "process",
    "sub" + "process.run",
    "sub" + "process.Popen",
    "os.system(",
    "os.popen(",
    "asyncio.create_sub" + "process",
)
README = REPO_ROOT / "README.md"
CLI_MD = REPO_ROOT / "docs" / "cli.md"
CI_CD_MD = REPO_ROOT / "docs" / "ci_cd.md"

DEDICATED_SYSROOT_TARGET_DIR = "/src/target/linux-gnu-sysroot"
PR_LINUX_GNU_JOB = "verify-pr-linux-gnu-abi"
PR_LINUX_GNU_JOB_HEADER = (
    "  verify-pr-linux-gnu-abi:\n"
    "    name: Verify PR Linux GNU ABI\n"
)
PR_LINUX_GNU_SCAN_BOTH = (
    "          python3 -I .github/scripts/verify_linux_gnu_abi.py \\\n"
    "            target/x86_64-unknown-linux-gnu/release/ferrum-edge \\\n"
    "            target/x86_64-unknown-linux-gnu/release/ferrum-cni"
)

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


def _elf_unpack(fmt: str, data: bytes, offset: int) -> tuple[int, ...]:
    size = struct.calcsize(fmt)
    if offset < 0 or offset + size > len(data):
        raise ValueError("is a truncated ELF")
    return struct.unpack_from(fmt, data, offset)


def _elf_read_cstring(data: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(data):
        raise ValueError("string table offset is outside the ELF")
    end = data.find(b"\x00", offset)
    if end < 0:
        raise ValueError("unterminated ELF string")
    return data[offset:end].decode("ascii", "replace")


def _elf_va_to_offset(loads: list[tuple[int, int, int]], virtual_addr: int) -> int:
    for file_offset, virtual_base, file_size in loads:
        if virtual_base <= virtual_addr < virtual_base + file_size:
            return file_offset + (virtual_addr - virtual_base)
    raise ValueError(f"virtual address 0x{virtual_addr:x} is not in a PT_LOAD segment")


def _collect_verneed_versions(
    data: bytes,
    verneed_offset: int,
    verneed_count: int,
    strtab: int,
    endian: str,
) -> set[str]:
    versions: set[str] = set()
    cursor = verneed_offset
    for _ in range(max(verneed_count, 0)):
        if cursor + 16 > len(data):
            raise ValueError("truncated GNU verneed table")
        _vn_version, vn_cnt, _vn_file, vn_aux, vn_next = struct.unpack_from(
            f"{endian}HHIII", data, cursor
        )
        aux = cursor + vn_aux
        for _unused in range(vn_cnt):
            if aux + 16 > len(data):
                raise ValueError("truncated GNU vernaux table")
            _vna_hash, _vna_flags, _vna_other, vna_name, vna_next = struct.unpack_from(
                f"{endian}IHHII", data, aux
            )
            name = _elf_read_cstring(data, strtab + vna_name)
            match = GLIBC_VERSION_RE.search(name)
            if match is not None:
                versions.add(match.group(1))
            if vna_next == 0:
                break
            aux += vna_next
        if vn_next == 0:
            break
        cursor += vn_next
    return versions


def parse_elf_abi(data: bytes) -> tuple[list[str], list[str]]:
    """Return GLIBC version-need names and DT_NEEDED SONAMEs from an ELF.

    The scanner stays in-process so trusted automation policy can statically
    inspect this file. Computed process argv fails closed.
    """

    if data[:4] != b"\x7fELF":
        raise ValueError("is not an ELF file")
    if len(data) < 52:
        raise ValueError("is a truncated ELF header")

    elf_class = data[4]
    encoding = data[5]
    if elf_class not in {1, 2}:
        raise ValueError("has an unsupported ELF class")
    if encoding not in {1, 2}:
        raise ValueError("has an unsupported ELF encoding")

    elf64 = elf_class == 2
    endian = "<" if encoding == 1 else ">"
    u32 = f"{endian}I"
    u64 = f"{endian}Q"

    if elf64:
        phoff = _elf_unpack(u64, data, 32)[0]
        phentsize, phnum = _elf_unpack(f"{endian}HH", data, 54)
    else:
        phoff = _elf_unpack(u32, data, 28)[0]
        phentsize, phnum = _elf_unpack(f"{endian}HH", data, 42)

    loads: list[tuple[int, int, int]] = []
    dynamic_offset = -1
    dynamic_size = 0
    for index in range(phnum):
        start = phoff + index * phentsize
        p_type = _elf_unpack(u32, data, start)[0]
        if elf64:
            p_offset, p_vaddr, _p_paddr, p_filesz = _elf_unpack(
                f"{endian}QQQQ", data, start + 8
            )
        else:
            p_offset, p_vaddr, _p_paddr, p_filesz = _elf_unpack(
                f"{endian}IIII", data, start + 4
            )
        if p_type == PT_LOAD:
            loads.append((p_offset, p_vaddr, p_filesz))
        elif p_type == PT_DYNAMIC:
            dynamic_offset = p_offset
            dynamic_size = p_filesz

    if dynamic_offset < 0:
        raise ValueError("has no PT_DYNAMIC segment")

    dyn_entry = 16 if elf64 else 8
    needed_offsets: list[int] = []
    strtab_va = -1
    verneed_va = -1
    verneed_count = 0
    cursor = dynamic_offset
    dyn_end = dynamic_offset + dynamic_size
    tag_fmt = f"{endian}q" if elf64 else f"{endian}i"
    val_fmt = f"{endian}Q" if elf64 else f"{endian}I"
    tag_size = 8 if elf64 else 4
    while cursor + dyn_entry <= dyn_end:
        tag = _elf_unpack(tag_fmt, data, cursor)[0]
        value = _elf_unpack(val_fmt, data, cursor + tag_size)[0]
        if tag == 0:
            break
        if tag == DT_NEEDED:
            needed_offsets.append(value)
        elif tag == DT_STRTAB:
            strtab_va = value
        elif tag == DT_VERNEED:
            verneed_va = value
        elif tag == DT_VERNEEDNUM:
            verneed_count = value
        cursor += dyn_entry

    if strtab_va < 0:
        raise ValueError("is missing DT_STRTAB")
    strtab = _elf_va_to_offset(loads, strtab_va)
    needed = sorted(
        {_elf_read_cstring(data, strtab + offset) for offset in needed_offsets}
    )

    versions: set[str] = set()
    if verneed_va >= 0 and verneed_count:
        verneed_offset = _elf_va_to_offset(loads, verneed_va)
        versions = _collect_verneed_versions(
            data, verneed_offset, verneed_count, strtab, endian
        )

    return sorted(versions), needed


def scan_binary(binary: Path, contract: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if not binary.is_file() or binary.is_symlink():
        return [f"{binary} is not a regular file"]

    payload = binary.read_bytes()
    if payload[:4] != b"\x7fELF":
        return [f"{binary} is not an ELF file"]

    try:
        versions, needed = parse_elf_abi(payload)
    except ValueError as error:
        return [f"{binary} {error}"]
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
        ("python3 -I .github/scripts/smoke_linux_gnu_baseline.py --self-test", "baseline smoke self-test"),
        ("bash .github/scripts/smoke_linux_gnu_baseline.sh", "baseline smoke invocation"),
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
        (smoke_floor, "oldest-baseline smoke image"),
        (smoke_ubuntu, "Ubuntu 22.04 smoke image"),
        (protoc_sha, "pinned protoc SHA-256"),
        ("build_linux_gnu_sysroot.sh", "sysroot build helper"),
        ("python3 -I .github/scripts/verify_linux_gnu_abi.py --self-test", "ABI self-test"),
        ("python3 -I .github/scripts/verify_linux_gnu_abi.py --check-contract", "ABI contract check"),
        ("python3 -I .github/scripts/smoke_linux_gnu_baseline.py --self-test", "baseline smoke self-test"),
        ("bash .github/scripts/smoke_linux_gnu_baseline.sh", "baseline smoke invocation"),
        ("LIBZ_SYS_STATIC=1", "static zlib for the GNU sysroot build"),
        ("ubuntu-24.04-arm", "ARM64 GNU ABI/smoke runner"),
        (
            "  verify-latest-linux-gnu-abi:\n"
            "    name: Verify latest Linux GNU ABI\n",
            "verify-latest-linux-gnu-abi job",
        ),
        (
            "    needs: [build-binaries, build-arm64-cross]\n",
            "verify-latest-linux-gnu-abi needs both GNU build jobs",
        ),
        (
            "          name: binary-x86_64-unknown-linux-gnu\n",
            "latest-path x86_64 GNU artifact name",
        ),
        (
            "          name: binary-aarch64-unknown-linux-gnu\n",
            "latest-path ARM64 GNU artifact name",
        ),
        (
            "  linux-gnu-abi-latest-gate:\n"
            "    name: Gate latest release on Linux GNU ABI\n",
            "linux-gnu-abi-latest-gate job",
        ),
        (
            "    needs: [latest-release, verify-latest-linux-gnu-abi]\n",
            "linux-gnu-abi-latest-gate join after latest-release",
        ),
        (
            "    if: always() && github.event_name == 'push' && github.ref == 'refs/heads/main'\n",
            "linux-gnu-abi-latest-gate main-push fail-closed if",
        ),
        ("targetCommitish", "latest retraction proves release target"),
        ("$GITHUB_SHA", "latest retraction proves current SHA"),
        (
            'echo "::error::latest publication is blocked until verify-latest-linux-gnu-abi succeeds',
            "latest ABI fail-closed error",
        ),
        (
            'echo "::error::latest-release did not succeed',
            "latest publication fail-closed error",
        ),
        (PR_LINUX_GNU_JOB_HEADER, "verify-pr-linux-gnu-abi job"),
        ("build_linux_gnu_sysroot.sh", "sysroot build helper on the PR path"),
    ):
        if not workflow_contains(ci_yml, token):
            errors.append(f"ci.yml is missing required {label} ({token})")

    # Frozen latest-release cannot gain an ABI needs edge; the join gate is
    # the admitted place to fail-close after that frozen publisher.
    if (
        "    needs: [test, build-binaries, build-arm64-cross, "
        "main-publish-gate]\n"
        not in ci_yml
    ):
        errors.append("ci.yml changed the frozen latest-release needs graph")
    if "verify-latest-linux-gnu-abi" in _job_needs(ci_yml, "latest-release"):
        errors.append("ci.yml must not add an ABI needs edge to frozen latest-release")
    if "verify-linux-gnu-abi" in _job_needs(ci_yml, "main-publish-gate"):
        errors.append("ci.yml must not add an ABI needs edge to frozen main-publish-gate")
    if "verify-latest-linux-gnu-abi" in _job_needs(ci_yml, "build-arm64-cross"):
        errors.append("ci.yml must not add an ABI needs edge to frozen build-arm64-cross")
    if PR_LINUX_GNU_JOB in _job_needs(ci_yml, "latest-release"):
        errors.append("ci.yml must not add the PR GNU ABI job to frozen latest-release")
    if PR_LINUX_GNU_JOB in _job_needs(ci_yml, "main-publish-gate"):
        errors.append("ci.yml must not add the PR GNU ABI job to frozen main-publish-gate")
    if PR_LINUX_GNU_JOB in _job_needs(ci_yml, "build-arm64-cross"):
        errors.append("ci.yml must not add the PR GNU ABI job to frozen build-arm64-cross")

    errors.extend(check_pr_linux_gnu_job(ci_yml))
    return errors


def _job_body(workflow: str, job: str) -> str:
    match = re.search(
        rf"(?ms)^  {re.escape(job)}:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
        workflow,
    )
    return match.group("body") if match else ""


def _job_needs(workflow: str, job: str) -> set[str]:
    body = _job_body(workflow, job)
    if not body:
        return set()
    inline = re.search(
        r"(?m)^    needs: \[(?P<needs>[A-Za-z0-9_-]+(?:, [A-Za-z0-9_-]+)*)\]$",
        body,
    )
    if inline:
        return set(inline.group("needs").split(", "))
    listed = re.search(r"(?m)^    needs:\n(?P<needs>(?:^      - [^\n]+\n)+)", body)
    if listed:
        return {
            line.strip().removeprefix("- ").strip()
            for line in listed.group("needs").splitlines()
            if line.strip().startswith("- ")
        }
    scalar = re.search(r"(?m)^    needs: ([A-Za-z0-9_-]+)$", body)
    if scalar:
        return {scalar.group(1)}
    return set()


def check_no_process_api(source: str, label: str) -> list[str]:
    errors: list[str] = []
    for token in PROCESS_API_TOKENS:
        if token in source:
            errors.append(f"{label} must not use process API {token}")
    return errors


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
    if 'chmod +x -- "$stage/ferrum-edge" "$stage/ferrum-cni"' not in source:
        errors.append(
            "smoke_linux_gnu_baseline.sh must set +x on host staged copies "
            "before mounting /gnu:ro"
        )
    if "docker pull --platform" not in source or "docker run --rm" not in source:
        errors.append(
            "smoke_linux_gnu_baseline.sh must keep docker argv0 a literal docker"
        )
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
    for token in ("verify-linux-gnu-abi", "linux-gnu-abi-release-gate"):
        if token not in ci_cd_md:
            errors.append(f"docs/ci_cd.md must document the versioned-release GNU ABI job {token}")
    for token in ("verify-latest-linux-gnu-abi", "linux-gnu-abi-latest-gate"):
        if token not in ci_cd_md:
            errors.append(f"docs/ci_cd.md must document the moving-latest GNU ABI job {token}")
    if "verify-pr-linux-gnu-abi" not in ci_cd_md:
        errors.append("docs/ci_cd.md must document the pull-request GNU ABI job verify-pr-linux-gnu-abi")
    if "linux-gnu-sysroot" not in ci_cd_md:
        errors.append("docs/ci_cd.md must document the isolated sysroot CARGO_TARGET_DIR")
    return errors


def check_sysroot_builder(source: str) -> list[str]:
    errors: list[str] = []
    dedicated = DEDICATED_SYSROOT_TARGET_DIR
    if f"--env CARGO_TARGET_DIR={dedicated}" not in source:
        errors.append(
            "sysroot builder must pin docker CARGO_TARGET_DIR to "
            f"{dedicated} with no host fallback"
        )
    if f'[[ "${{CARGO_TARGET_DIR:-}}" != "{dedicated}" ]]' not in source:
        errors.append(
            "sysroot builder must fail closed unless CARGO_TARGET_DIR is "
            f"exactly {dedicated}"
        )
    if f"--target-dir {dedicated}" not in source:
        errors.append(
            f"sysroot builder must pass cargo --target-dir {dedicated}"
        )
    if '--env CARGO_TARGET_DIR="$CARGO_TARGET_DIR"' in source:
        errors.append("sysroot builder must not pass host CARGO_TARGET_DIR into the container")
    if re.search(r"(?m)^\s+/src/target\s*$", source):
        errors.append("sysroot builder must not chown or otherwise use the whole /src/target tree")
    chown_dedicated = (
        '    chown -R "${HOST_UID}:${HOST_GID}" \\\n'
        f"      {dedicated} \\\n"
    )
    if chown_dedicated not in source:
        errors.append(
            "sysroot builder must scope host ownership repair to "
            f"{dedicated}"
        )
    if '[[ -L "$src" ]]' not in source or '[[ -L "$dest" ]]' not in source:
        errors.append(
            "sysroot builder must reject symlink sources and canonical destinations"
        )
    if "copy_sysroot_binary ferrum-edge" not in source:
        errors.append("sysroot builder must copy ferrum-edge to the canonical path")
    if "copy_sysroot_binary ferrum-cni" not in source:
        errors.append("sysroot builder must copy ferrum-cni to the canonical path")
    if "cp -f --" not in source:
        errors.append("sysroot builder must copy proven binaries with cp -f --")
    return errors


def check_pr_linux_gnu_job(ci_yml: str) -> list[str]:
    errors: list[str] = []
    if PR_LINUX_GNU_JOB_HEADER not in ci_yml:
        errors.append("ci.yml is missing the verify-pr-linux-gnu-abi job")
        return errors
    body = _job_body(ci_yml, PR_LINUX_GNU_JOB)
    if not body:
        errors.append("ci.yml verify-pr-linux-gnu-abi job body is missing")
        return errors
    if _job_needs(ci_yml, PR_LINUX_GNU_JOB) != {"ci-plan"}:
        errors.append("verify-pr-linux-gnu-abi must need only ci-plan")
    if "needs.ci-plan.outputs.mode == 'full'" not in body:
        errors.append("verify-pr-linux-gnu-abi must require full CI mode")
    if "github.event_name == 'pull_request'" not in body:
        errors.append("verify-pr-linux-gnu-abi must run on pull_request")
    if "contents: read" not in body:
        errors.append("verify-pr-linux-gnu-abi must use contents: read")
    if re.search(r"(?m)^\s+contents:\s+write\s*$", body):
        errors.append("verify-pr-linux-gnu-abi must not grant contents: write")
    if "persist-credentials: false" not in body:
        errors.append("verify-pr-linux-gnu-abi must disable persist-credentials")
    if "timeout-minutes:" not in body:
        errors.append("verify-pr-linux-gnu-abi must set a job timeout")
    if "build_linux_gnu_sysroot.sh" not in body:
        errors.append("verify-pr-linux-gnu-abi must invoke the isolated sysroot builder")
    if "cargo build" in body:
        errors.append("verify-pr-linux-gnu-abi must not cargo-build on the native runner")
    if PR_LINUX_GNU_SCAN_BOTH not in body:
        errors.append("verify-pr-linux-gnu-abi must ABI-scan both x86_64 GNU binaries")
    if "--edge target/x86_64-unknown-linux-gnu/release/ferrum-edge" not in body:
        errors.append("verify-pr-linux-gnu-abi must smoke ferrum-edge by exact path")
    if "--cni target/x86_64-unknown-linux-gnu/release/ferrum-cni" not in body:
        errors.append("verify-pr-linux-gnu-abi must smoke ferrum-cni by exact path")
    if "python3 -I .github/scripts/smoke_linux_gnu_baseline.py --self-test" not in body:
        errors.append("verify-pr-linux-gnu-abi must invoke baseline smoke self-test")
    if "bash .github/scripts/smoke_linux_gnu_baseline.sh" not in body:
        errors.append("verify-pr-linux-gnu-abi must invoke baseline smoke")
    if "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1" not in body:
        errors.append("verify-pr-linux-gnu-abi must pin actions/checkout")
    if "dtolnay/rust-toolchain@29eef336d9b2848a0b548edc03f92a220660cdb8" not in body:
        errors.append("verify-pr-linux-gnu-abi must pin dtolnay/rust-toolchain")
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
    errors.extend(check_no_process_api(Path(__file__).read_text(encoding="utf-8"), "verify_linux_gnu_abi.py"))
    errors.extend(check_no_process_api(SMOKE_PY.read_text(encoding="utf-8"), "smoke_linux_gnu_baseline.py"))
    if not SMOKE_SH.is_file():
        errors.append("smoke_linux_gnu_baseline.sh is missing")
    else:
        errors.extend(check_smoke_script(SMOKE_SH.read_text(encoding="utf-8")))
    errors.extend(check_sysroot_builder(SYSROOT_BUILD_SH.read_text(encoding="utf-8")))
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


def _synthetic_dynamic_elf64(needed: list[str], glibc_names: list[str]) -> bytes:
    """Build a little-endian ELF64 with DT_NEEDED and GNU verneed records."""

    strings = ["", *needed, *glibc_names]
    strtab = b"".join(item.encode("ascii") + b"\x00" for item in strings)
    offsets: dict[str, int] = {}
    cursor = 0
    for item in strings:
        offsets[item] = cursor
        cursor += len(item) + 1

    ehdr_size = 64
    phdr_size = 56
    phnum = 2
    dyn_count = len(needed) + 4  # STRTAB, VERNEED, VERNEEDNUM, NULL
    dyn_size = dyn_count * 16
    verneed_size = 16 + 16 * len(glibc_names)
    phoff = ehdr_size
    dyn_off = phoff + phdr_size * phnum
    strtab_off = dyn_off + dyn_size
    verneed_off = strtab_off + len(strtab)
    file_size = verneed_off + verneed_size

    ident = bytes([0x7F, 0x45, 0x4C, 0x46, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        ident,
        3,
        62,
        1,
        0,
        phoff,
        0,
        0,
        ehdr_size,
        phdr_size,
        phnum,
        0,
        0,
        0,
    )
    load = struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, file_size, file_size, 1)
    dynamic = struct.pack(
        "<IIQQQQQQ", 2, 4, dyn_off, dyn_off, dyn_off, dyn_size, dyn_size, 8
    )
    dyn_entries = bytearray()
    for name in needed:
        dyn_entries.extend(struct.pack("<qQ", DT_NEEDED, offsets[name]))
    dyn_entries.extend(struct.pack("<qQ", DT_STRTAB, strtab_off))
    dyn_entries.extend(struct.pack("<qQ", DT_VERNEED, verneed_off))
    dyn_entries.extend(struct.pack("<qQ", DT_VERNEEDNUM, 1))
    dyn_entries.extend(struct.pack("<qQ", 0, 0))

    aux_offset = 16
    verneed = struct.pack(
        "<HHIII",
        1,
        len(glibc_names),
        offsets[needed[0]] if needed else 0,
        aux_offset,
        0,
    )
    vernaux = bytearray()
    for index, name in enumerate(glibc_names):
        next_off = 16 if index + 1 < len(glibc_names) else 0
        vernaux.extend(struct.pack("<IHHII", 0, 0, index + 2, offsets[name], next_off))

    return bytes(ehdr + load + dynamic + dyn_entries + strtab + verneed + vernaux)


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

        floor_elf = Path(tmp) / "floor.elf"
        floor_elf.write_bytes(
            _synthetic_dynamic_elf64(["libc.so.6", "libgcc_s.so.1"], ["GLIBC_2.2.5", "GLIBC_2.34"])
        )
        if scan_binary(floor_elf, contract):
            failures.append("in-floor synthetic ELF was rejected")

        too_new_elf = Path(tmp) / "too-new.elf"
        too_new_elf.write_bytes(
            _synthetic_dynamic_elf64(["libc.so.6", "libz.so.1"], ["GLIBC_2.2.5", "GLIBC_2.39"])
        )
        too_new_elf_errors = scan_binary(too_new_elf, contract)
        if not any("GLIBC_2.39" in item for item in too_new_elf_errors):
            failures.append("synthetic GLIBC_2.39 ELF was not rejected")

        unexpected_elf = Path(tmp) / "unexpected.elf"
        unexpected_elf.write_bytes(
            _synthetic_dynamic_elf64(["libc.so.6", "libssl.so.3"], ["GLIBC_2.17"])
        )
        unexpected_elf_errors = scan_binary(unexpected_elf, contract)
        if not any("libssl.so.3" in item for item in unexpected_elf_errors):
            failures.append("synthetic unexpected SONAME ELF was not rejected")

    scanner_source = Path(__file__).read_text(encoding="utf-8")
    if not check_no_process_api(
        "import " + "subprocess\n" + scanner_source,
        "verify_linux_gnu_abi.py",
    ):
        failures.append("subprocess import in ABI scanner was not rejected")
    if not check_no_process_api(
        "import " + "subprocess\n" + SMOKE_PY.read_text(encoding="utf-8"),
        "smoke_linux_gnu_baseline.py",
    ):
        failures.append("subprocess import in smoke self-test was not rejected")

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

    ci_yml = CI_YML.read_text(encoding="utf-8")
    mutated_latest_job = ci_yml.replace(
        "verify-latest-linux-gnu-abi:", "verify-latest-linux-gnu-abi-missing:", 1
    )
    if not check_release_wiring(contract, RELEASE_YML.read_text(encoding="utf-8"), mutated_latest_job):
        failures.append("missing latest GNU ABI job in ci.yml was not rejected")

    mutated_latest_gate = ci_yml.replace(
        "linux-gnu-abi-latest-gate:", "linux-gnu-abi-latest-gate-missing:", 1
    )
    if not check_release_wiring(contract, RELEASE_YML.read_text(encoding="utf-8"), mutated_latest_gate):
        failures.append("missing latest GNU ABI join gate in ci.yml was not rejected")

    mutated_frozen_needs = ci_yml.replace(
        "    needs: [test, build-binaries, build-arm64-cross, main-publish-gate]\n",
        "    needs: [test, build-binaries, build-arm64-cross, main-publish-gate, verify-latest-linux-gnu-abi]\n",
        1,
    )
    if not check_release_wiring(contract, RELEASE_YML.read_text(encoding="utf-8"), mutated_frozen_needs):
        failures.append("ABI needs edge on frozen latest-release was not rejected")

    mutated_ci_cd = CI_CD_MD.read_text(encoding="utf-8").replace(
        "verify-latest-linux-gnu-abi", "verify-linux-gnu-abi-on-latest"
    )
    if not check_operator_docs(
        README.read_text(encoding="utf-8"),
        CLI_MD.read_text(encoding="utf-8"),
        mutated_ci_cd,
        contract,
    ):
        failures.append("docs/ci_cd.md latest GNU ABI job regression was not rejected")

    mutated_smoke = SMOKE_SH.read_text(encoding="utf-8").replace(
        '--volume "$stage:/gnu:ro"',
        '--volume "$stage:/gnu:rw"',
        1,
    )
    if not check_smoke_script(mutated_smoke):
        failures.append("read-write /gnu smoke mount was not rejected")

    builder = SYSROOT_BUILD_SH.read_text(encoding="utf-8")
    mutated_target_dir = builder.replace(
        "--env CARGO_TARGET_DIR=/src/target/linux-gnu-sysroot",
        "--env CARGO_TARGET_DIR=/src/target",
        1,
    )
    if not check_sysroot_builder(mutated_target_dir):
        failures.append("unisolated CARGO_TARGET_DIR in sysroot builder was not rejected")

    mutated_host_override = builder.replace(
        "--env CARGO_TARGET_DIR=/src/target/linux-gnu-sysroot",
        '--env CARGO_TARGET_DIR="$CARGO_TARGET_DIR"',
        1,
    )
    if not check_sysroot_builder(mutated_host_override):
        failures.append("host CARGO_TARGET_DIR passthrough in sysroot builder was not rejected")

    mutated_chown = builder.replace(
        '    chown -R "${HOST_UID}:${HOST_GID}" \\\n'
        "      /src/target/linux-gnu-sysroot \\\n"
        "      /opt/cargo \\\n",
        '    chown -R "${HOST_UID}:${HOST_GID}" \\\n'
        "      /src/target \\\n"
        "      /opt/cargo \\\n",
        1,
    )
    if not check_sysroot_builder(mutated_chown):
        failures.append("whole /src/target chown in sysroot builder was not rejected")

    mutated_symlink = builder.replace('[[ -L "$src" ]]', '[[ -d "$src" ]]', 1)
    if not check_sysroot_builder(mutated_symlink):
        failures.append("sysroot builder without symlink rejection was not rejected")

    mutated_cni_copy = builder.replace("copy_sysroot_binary ferrum-cni\n", "", 1)
    if not check_sysroot_builder(mutated_cni_copy):
        failures.append("sysroot builder missing ferrum-cni canonical copy was not rejected")

    mutated_pr_job = ci_yml.replace(
        "verify-pr-linux-gnu-abi:", "verify-pr-linux-gnu-abi-missing:", 1
    )
    if not check_release_wiring(contract, RELEASE_YML.read_text(encoding="utf-8"), mutated_pr_job):
        failures.append("missing PR GNU ABI job in ci.yml was not rejected")

    pr_body = _job_body(ci_yml, PR_LINUX_GNU_JOB)
    mutated_pr_smoke = ci_yml.replace(
        pr_body,
        pr_body.replace(
            "bash .github/scripts/smoke_linux_gnu_baseline.sh",
            "bash .github/scripts/smoke_linux_gnu_baseline_missing.sh",
        ),
        1,
    )
    if not check_pr_linux_gnu_job(mutated_pr_smoke):
        failures.append("PR GNU ABI job without baseline smoke was not rejected")

    mutated_pr_scan = ci_yml.replace(
        pr_body,
        pr_body.replace(PR_LINUX_GNU_SCAN_BOTH, PR_LINUX_GNU_SCAN_BOTH.replace("ferrum-cni", "ferrum-edge")),
        1,
    )
    if not check_pr_linux_gnu_job(mutated_pr_scan):
        failures.append("PR GNU ABI job that does not scan ferrum-cni was not rejected")

    mutated_pr_native = ci_yml.replace(
        pr_body,
        pr_body.replace(
            "bash .github/scripts/build_linux_gnu_sysroot.sh",
            "cargo build --release --target x86_64-unknown-linux-gnu",
            1,
        ),
        1,
    )
    if not check_pr_linux_gnu_job(mutated_pr_native):
        failures.append("PR GNU ABI job native cargo build fallback was not rejected")

    mutated_pr_docs = CI_CD_MD.read_text(encoding="utf-8").replace(
        "verify-pr-linux-gnu-abi", "verify-linux-gnu-abi-on-pr"
    )
    if not check_operator_docs(
        README.read_text(encoding="utf-8"),
        CLI_MD.read_text(encoding="utf-8"),
        mutated_pr_docs,
        contract,
    ):
        failures.append("docs/ci_cd.md PR GNU ABI job regression was not rejected")

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
