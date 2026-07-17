#!/usr/bin/env python3
"""Enforce fixed architecture inputs for privileged ARM64 cross-image setup."""

from __future__ import annotations

import argparse
import sys
import tomllib
from pathlib import Path
from typing import Any


TARGET = "aarch64-unknown-linux-gnu"
EXPECTED_PRIVILEGED_COMMANDS = (
    "dpkg --add-architecture 'arm64'",
    "apt-get update && apt-get install --assume-yes perl make "
    "'libcurl4-openssl-dev:arm64' cmake software-properties-common wget gnupg unzip",
    "multiarch=$(dpkg-architecture -a 'arm64' -qDEB_HOST_MULTIARCH) && "
    'ln -sfn -- "/usr/include/${multiarch}/curl" '
    '"/usr/${multiarch}/include/curl"',
)

ATTACK_PAYLOADS = {
    "whitespace": "arm64 amd64",
    "leading option": "--help",
    "shell metacharacter": "arm64; touch /tmp/cross-policy-marker",
    "command substitution": "$(touch /tmp/cross-policy-marker)",
}


def validate_pre_build(value: Any) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        return [f"target.{TARGET}.pre-build must be an array of strings"]

    errors: list[str] = []
    if any("CROSS_DEB_ARCH" in command for command in value):
        errors.append("CROSS_DEB_ARCH must not reach any ARM64 pre-build command")

    if len(value) < len(EXPECTED_PRIVILEGED_COMMANDS):
        errors.append("ARM64 pre-build is missing a privileged setup command")

    for index, expected in enumerate(EXPECTED_PRIVILEGED_COMMANDS):
        if index >= len(value):
            break
        if value[index] != expected:
            errors.append(
                f"pre-build command {index + 1} must use the fixed, safely bounded "
                "arm64 form"
            )

    return errors


def load_pre_build(path: Path) -> tuple[Any, list[str]]:
    try:
        parsed = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        return None, [f"cannot parse {path}: {error}"]

    try:
        return parsed["target"][TARGET]["pre-build"], []
    except (KeyError, TypeError):
        return None, [f"{path} is missing target.{TARGET}.pre-build"]


def unsafe_commands(payload: str) -> list[str]:
    return [
        f"dpkg --add-architecture {payload}",
        "apt-get update && apt-get install --assume-yes perl make "
        f"libcurl4-openssl-dev:{payload} cmake software-properties-common wget gnupg unzip",
        f"multiarch=$(dpkg-architecture -a{payload} -qDEB_HOST_MULTIARCH) && "
        'ln -sfn "/usr/include/${multiarch}/curl" '
        '"/usr/${multiarch}/include/curl"',
    ]


def self_test() -> list[str]:
    failures: list[str] = []

    if validate_pre_build(list(EXPECTED_PRIVILEGED_COMMANDS)):
        failures.append("normal fixed arm64 commands were rejected")

    for name, payload in ATTACK_PAYLOADS.items():
        if not validate_pre_build(unsafe_commands(payload)):
            failures.append(f"{name} payload was not rejected")

    legacy = [
        "dpkg --add-architecture $CROSS_DEB_ARCH",
        "apt-get install --assume-yes libcurl4-openssl-dev:$CROSS_DEB_ARCH",
        "dpkg-architecture -a$CROSS_DEB_ARCH -qDEB_HOST_MULTIARCH",
    ]
    if not validate_pre_build(legacy):
        failures.append("CROSS_DEB_ARCH interpolation was not rejected")

    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=Path("Cross.toml"))
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    failures = self_test() if args.self_test else []
    pre_build, load_failures = load_pre_build(args.config)
    failures.extend(load_failures)
    if not load_failures:
        failures.extend(validate_pre_build(pre_build))

    for failure in failures:
        print(f"::error::{failure}", file=sys.stderr)
    if failures:
        return 1

    print("ARM64 cross-build commands use fixed, safely bounded architecture inputs.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
