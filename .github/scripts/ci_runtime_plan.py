#!/usr/bin/env python3
"""Fail-closed path planner for expensive production-image and FIPS CI gates.

Hosted workflows extract this file from the trusted base commit before
execution so a pull request cannot widen skip patterns. Uncertainty, a missing
trusted copy, or an unknown suite must run the gate rather than skip it.
"""

from __future__ import annotations

import argparse
import re
import sys
import tempfile
from pathlib import Path, PurePosixPath

SUITE_PATTERNS: dict[str, tuple[str, ...]] = {
    # Production Dockerfile smoke builds the ordinary `runtime` image and the
    # distroless `runtime-ebpf` image from the root Dockerfile. Skip only when
    # the diff cannot change that image, its build context, or this planner.
    "production-dockerfile-smoke": (
        r"^Dockerfile$",
        r"^\.dockerignore$",
        r"^Cargo\.(toml|lock)$",
        r"^rust-toolchain\.toml$",
        r"^\.cargo/",
        r"^vendor/",
        r"^build\.rs$",
        r"^proto/",
        r"^src/",
        r"^custom_plugins/",
        r"^ebpf/",
        r"^\.github/scripts/stage_iproute2_runtime\.sh$",
        r"^\.github/workflows/node-waypoint-ebpf-live\.yml$",
        r"^\.github/scripts/ci_runtime_plan\.py$",
        r"^\.github/scripts/ci_runtime_telemetry\.py$",
        r"^\.github/scripts/verify_ci_runtime_cache\.py$",
    ),
    # FIPS compile/clippy/test rebuilds the aws-lc-fips-sys module and the
    # unit/integration binaries that carry the handshake and key-admission
    # assertions. Feature-policy stays cheap and always runs.
    "fips-build": (
        r"^Cargo\.(toml|lock)$",
        r"^rust-toolchain\.toml$",
        r"^\.cargo/",
        r"^vendor/",
        r"^build\.rs$",
        r"^proto/",
        r"^src/",
        r"^custom_plugins/",
        r"^ebpf/",
        r"^tests/unit/",
        r"^tests/integration/",
        r"^docs/fips\.md$",
        r"^\.github/workflows/fips-build\.yml$",
        r"^\.github/scripts/check_fips_feature_policy\.py$",
        r"^\.github/scripts/ci_runtime_plan\.py$",
        r"^\.github/scripts/ci_runtime_telemetry\.py$",
        r"^\.github/scripts/verify_ci_runtime_cache\.py$",
        r"^\.github/actions/setup-sccache/",
        r"^\.github/actions/setup-fast-linker/",
        r"^\.github/actions/setup-rust-ci/",
    ),
}

COMPILED = {
    suite: tuple(re.compile(pattern) for pattern in patterns)
    for suite, patterns in SUITE_PATTERNS.items()
}

# Tab and newline are valid Git path bytes. Other C0 / DEL controls cannot be
# trusted for a skip decision: a quoted or split hostile name must never hide a
# Docker/FIPS-sensitive prefix.
_ALLOWED_CONTROLS = frozenset({ord("\t"), ord("\n")})


class ChangedFilesError(Exception):
    """Malformed or unavailable diff. The planner must fail closed."""


class UnsafeChangedFiles(Exception):
    """Decoded paths that cannot be skipped. Force the live gate to run."""

    def __init__(self, paths: list[str], reason: str) -> None:
        super().__init__(reason)
        self.paths = paths
        self.reason = reason


def unsafe_path_reason(path: str) -> str | None:
    if not path:
        return "empty path"
    if path.startswith(("/", "\\")):
        return "absolute path"
    for char in path:
        code = ord(char)
        if code < 32 and code not in _ALLOWED_CONTROLS:
            return "control character"
        if code == 127:
            return "control character"
    posix = PurePosixPath(path)
    if posix.is_absolute():
        return "absolute path"
    if ".." in posix.parts:
        return "path traversal"
    return None


def read_changed_files(path: Path) -> list[str]:
    """Parse a NUL-delimited `git diff --name-only --no-renames -z` listing.

    A truncated, undecodable, or unavailable listing fails closed. A decoded
    but structurally unsafe name (absolute, traversal, disallowed controls)
    raises UnsafeChangedFiles so the caller can force the suite to run rather
    than report a successful skip. A valid Git filename containing a newline
    is one path and is matched against suite prefixes as-is.
    """
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise ChangedFilesError(f"cannot read changed-files: {error}") from error

    if raw == b"":
        return []
    if not raw.endswith(b"\0"):
        raise ChangedFilesError(
            "changed-files NUL stream is truncated (missing final NUL)"
        )

    records = raw.split(b"\0")
    if records and records[-1] == b"":
        records = records[:-1]
    if not records:
        return []

    paths: list[str] = []
    unsafe_reason: str | None = None
    for record in records:
        if record == b"":
            raise ChangedFilesError("changed-files contains an empty NUL record")
        try:
            text = record.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ChangedFilesError(
                f"changed-files is not valid UTF-8: {error}"
            ) from error
        reason = unsafe_path_reason(text)
        if reason is not None:
            unsafe_reason = reason
        paths.append(text)
    if unsafe_reason is not None:
        raise UnsafeChangedFiles(paths, unsafe_reason)
    return paths


def matched_files(suite: str, changed_files: list[str]) -> list[str]:
    if suite not in COMPILED:
        raise ValueError(f"unknown CI runtime suite: {suite}")
    patterns = COMPILED[suite]
    return [
        path for path in changed_files if any(pattern.search(path) for pattern in patterns)
    ]


def write_summary(
    suite: str, relevant: bool, changed: list[str], matched: list[str], reason: str
) -> None:
    title = suite.replace("-", " ").title()
    print(f"## {title} Runtime Path Plan")
    print()
    print(f"Relevant: **{str(relevant).lower()}**")
    print()
    print(reason)
    print()
    print("### Matched Files")
    print()
    if matched:
        for path in matched:
            print(f"- `{path}`")
    else:
        print("(none)")
    print()
    print("### Changed Files")
    print()
    if changed:
        for path in changed:
            print(f"- `{path}`")
    else:
        print("(none)")


def self_test() -> int:
    cases: list[tuple[str, list[str], bool]] = [
        ("production-dockerfile-smoke", ["Dockerfile"], True),
        ("production-dockerfile-smoke", [".dockerignore"], True),
        ("production-dockerfile-smoke", ["src/main.rs"], True),
        ("production-dockerfile-smoke", ["Cargo.lock"], True),
        ("production-dockerfile-smoke", ["vendor/foo/src/lib.rs"], True),
        ("production-dockerfile-smoke", ["ebpf/src/lib.rs"], True),
        ("production-dockerfile-smoke", ["custom_plugins/mod.rs"], True),
        ("production-dockerfile-smoke", ["proto/ferrum.proto"], True),
        ("production-dockerfile-smoke", ["build.rs"], True),
        (
            "production-dockerfile-smoke",
            [".github/scripts/stage_iproute2_runtime.sh"],
            True,
        ),
        (
            "production-dockerfile-smoke",
            [".github/workflows/node-waypoint-ebpf-live.yml"],
            True,
        ),
        (
            "production-dockerfile-smoke",
            [".github/scripts/ci_runtime_plan.py"],
            True,
        ),
        (
            "production-dockerfile-smoke",
            ["tests/k8s/node_waypoint_ebpf_live/run.sh"],
            False,
        ),
        ("production-dockerfile-smoke", ["docs/ci_cd.md"], False),
        ("production-dockerfile-smoke", ["docs/mesh.md"], False),
        ("production-dockerfile-smoke", ["charts/ferrum-mesh/values.yaml"], False),
        ("production-dockerfile-smoke", ["README.md"], False),
        ("production-dockerfile-smoke", ["Dockerfile.release"], False),
        ("production-dockerfile-smoke", ["Dockerfile.iproute2-layer"], False),
        ("fips-build", ["src/tls/mod.rs"], True),
        ("fips-build", ["tests/unit/tls/fips_policy_tests.rs"], True),
        ("fips-build", ["tests/integration/cp_grpc_handshake_admission_tests.rs"], True),
        ("fips-build", ["Cargo.toml"], True),
        ("fips-build", ["docs/fips.md"], True),
        ("fips-build", [".github/workflows/fips-build.yml"], True),
        ("fips-build", [".github/scripts/check_fips_feature_policy.py"], True),
        ("fips-build", [".github/actions/setup-sccache/action.yml"], True),
        ("fips-build", ["docs/ci_cd.md"], False),
        ("fips-build", ["README.md"], False),
        ("fips-build", ["tests/functional/functional_admin_test.rs"], False),
        ("fips-build", ["tests/k8s/mesh_e2e_sidecar/run.sh"], False),
        ("fips-build", ["charts/ferrum-mesh/values.yaml"], False),
        ("production-dockerfile-smoke", [], False),
        ("fips-build", [], False),
        (
            "production-dockerfile-smoke",
            ["src/\nmain.rs"],
            True,
        ),
        (
            "fips-build",
            ["src/\nmain.rs"],
            True,
        ),
        (
            "production-dockerfile-smoke",
            ['"src/main.rs"'],
            False,
        ),
        (
            "production-dockerfile-smoke",
            ['"Dockerfile"'],
            False,
        ),
        (
            "fips-build",
            ["README.md"],
            False,
        ),
    ]
    failures: list[str] = []
    for suite, changed, expected in cases:
        relevant = bool(matched_files(suite, changed))
        if relevant != expected:
            failures.append(
                f"{suite} {changed!r}: expected relevant={expected}, got {relevant}"
            )
    try:
        matched_files("not-a-suite", ["src/main.rs"])
        failures.append("unknown suite must raise rather than skip")
    except ValueError:
        pass

    def _write(payload: bytes) -> Path:
        handle = tempfile.NamedTemporaryFile(delete=False)
        handle.write(payload)
        handle.close()
        return Path(handle.name)

    empty = _write(b"")
    try:
        if read_changed_files(empty) != []:
            failures.append("empty diff must parse as no changed files")
    finally:
        empty.unlink(missing_ok=True)

    newline_path = "src/\nmain.rs"
    newline_file = _write(newline_path.encode("utf-8") + b"\0")
    try:
        parsed = read_changed_files(newline_file)
        if parsed != [newline_path]:
            failures.append(f"newline path must stay one record, got {parsed!r}")
        elif not matched_files("production-dockerfile-smoke", parsed):
            failures.append("newline path under src/ must not evade the Docker gate")
        elif not matched_files("fips-build", parsed):
            failures.append("newline path under src/ must not evade the FIPS gate")
    finally:
        newline_file.unlink(missing_ok=True)

    quoted = _write(b'"src/main.rs"\0')
    try:
        parsed = read_changed_files(quoted)
        if parsed != ['"src/main.rs"']:
            failures.append(f"Git quote-like text must stay literal, got {parsed!r}")
        elif matched_files("production-dockerfile-smoke", parsed):
            failures.append("quoted src/ text must not be unquoted into a sensitive path")
    finally:
        quoted.unlink(missing_ok=True)

    invalid_utf8 = _write(b"src/\xffmain.rs\0")
    try:
        read_changed_files(invalid_utf8)
        failures.append("invalid UTF-8 must fail closed rather than skip")
    except ChangedFilesError:
        pass
    finally:
        invalid_utf8.unlink(missing_ok=True)

    truncated = _write(b"src/main.rs")
    try:
        read_changed_files(truncated)
        failures.append("missing final NUL must fail closed rather than skip")
    except ChangedFilesError:
        pass
    finally:
        truncated.unlink(missing_ok=True)

    traversal = _write(b"../Dockerfile\0")
    try:
        read_changed_files(traversal)
        failures.append("traversal path must not parse as a skippable listing")
    except UnsafeChangedFiles as error:
        if "traversal" not in error.reason:
            failures.append(f"traversal reason missing: {error.reason}")
    except ChangedFilesError as error:
        failures.append(f"traversal should force-run, not fail parse: {error}")
    finally:
        traversal.unlink(missing_ok=True)

    absolute = _write(b"/etc/passwd\0")
    try:
        read_changed_files(absolute)
        failures.append("absolute path must not parse as a skippable listing")
    except UnsafeChangedFiles as error:
        if "absolute" not in error.reason:
            failures.append(f"absolute reason missing: {error.reason}")
    except ChangedFilesError as error:
        failures.append(f"absolute should force-run, not fail parse: {error}")
    finally:
        absolute.unlink(missing_ok=True)

    missing = Path(tempfile.mkdtemp()) / "missing-changed-files"
    try:
        read_changed_files(missing)
        failures.append("unavailable diff must fail closed rather than skip")
    except ChangedFilesError:
        pass

    for failure in failures:
        print(f"::error::{failure}", file=sys.stderr)
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=sorted(SUITE_PATTERNS))
    parser.add_argument("--changed-files", type=Path)
    parser.add_argument("--force-run", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        return self_test()
    if not args.suite or not args.changed_files:
        parser.error(
            "--suite and --changed-files are required unless --self-test is used"
        )

    force_unsafe = False
    unsafe_reason = ""
    try:
        changed = read_changed_files(args.changed_files)
    except ChangedFilesError as error:
        print(f"::error::{error}", file=sys.stderr)
        return 1
    except UnsafeChangedFiles as error:
        changed = error.paths
        force_unsafe = True
        unsafe_reason = error.reason
    try:
        matched = matched_files(args.suite, changed)
    except ValueError as error:
        print(f"::error::{error}", file=sys.stderr)
        return 1
    relevant = args.force_run or force_unsafe or bool(matched)
    if args.force_run:
        reason = "Forced run (push, merge_group, dispatch, or cold-cache proof)."
    elif force_unsafe:
        reason = (
            f"Diff contained an unsafe path ({unsafe_reason}); running the live "
            "gate rather than risking a false skip."
        )
    elif matched:
        reason = "Diff matches a production-image or FIPS-sensitive path; running the live gate."
    else:
        reason = (
            "No sensitive paths matched. The cheap feature-policy / reporting "
            "jobs still run; the expensive compile/image jobs are skipped."
        )
    print(f"relevant={str(relevant).lower()}")
    print(f"matched_count={len(matched)}")
    write_summary(args.suite, relevant, changed, matched, reason)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
