#!/usr/bin/env python3
"""Enforce the complete trusted ARM64 Cross 0.2.5 policy boundary."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import shlex
import sys
import tomllib
from pathlib import Path, PurePosixPath
from typing import Any


TARGET = "aarch64-unknown-linux-gnu"
EXPECTED_IMAGE = "ghcr.io/cross-rs/aarch64-unknown-linux-gnu:0.2.5"
EXPECTED_PRE_BUILD_COMMANDS = (
    "dpkg --add-architecture 'arm64'",
    "apt-get update && apt-get install --assume-yes perl make "
    "'libcurl4-openssl-dev:arm64' cmake software-properties-common wget gnupg unzip",
    "multiarch=$(dpkg-architecture -a 'arm64' -qDEB_HOST_MULTIARCH) && "
    'ln -sfn -- "/usr/include/${multiarch}/curl" '
    '"/usr/${multiarch}/include/curl"',
    "wget -qO /tmp/protoc.zip "
    "https://github.com/protocolbuffers/protobuf/releases/download/v25.1/"
    "protoc-25.1-linux-x86_64.zip && unzip -o /tmp/protoc.zip -d /usr/local "
    "bin/protoc && chmod +x /usr/local/bin/protoc && rm /tmp/protoc.zip",
    "wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -",
    "add-apt-repository "
    "'deb http://apt.llvm.org/xenial/ llvm-toolchain-xenial-6.0 main'",
    "apt-get update && apt-get install --assume-yes clang-6.0 libclang-6.0-dev",
)
EXPECTED_PASSTHROUGH = (
    "LIBCLANG_PATH=/usr/lib/llvm-6.0/lib",
    "RUSTC_WRAPPER=",
    "CARGO_BUILD_RUSTC_WRAPPER=",
    "RUSTFLAGS=",
    "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=cc",
    "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc",
    "CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc",
    "CXX_aarch64_unknown_linux_gnu=aarch64-linux-gnu-g++",
    "AR_aarch64_unknown_linux_gnu=aarch64-linux-gnu-ar",
)
EXPECTED_CARGO_BUILD = {
    "rustc-wrapper": "sccache",
    "incremental": False,
}
EXPECTED_CARGO_TARGETS = {
    "x86_64-unknown-linux-gnu": {
        "linker": "clang",
        "rustflags": ["-C", "link-arg=-fuse-ld=mold"],
    },
    "aarch64-unknown-linux-gnu": {
        "linker": "clang",
        "rustflags": ["-C", "link-arg=-fuse-ld=mold"],
    },
    "aarch64-apple-darwin": {
        "rustflags": ["-C", "link-arg=-fuse-ld=lld"],
    },
    "x86_64-apple-darwin": {
        "rustflags": ["-C", "link-arg=-fuse-ld=lld"],
    },
}

# These hashes cover the isolated jobs that prepare and invoke Cross, the
# top-level env mappings inherited by those jobs, and the workflow triggers
# that schedule them. The trusted
# pull_request_target guard compares those blocks at the PR merge base too, so
# unrelated workflow edits and later base-only changes remain allowed while any
# PR-authored mutation of an invocation input fails closed.
WORKFLOW_CONTRACTS = (
    (
        "CI workflow",
        "build-arm64-cross",
        "cf21166e1e4513915055ab9a1a6260a580105b5143d460fe38defd3f4751f12b",
        "143872ebf5dd925529b785273f180671bcc3bbd612d74ef0b88e1b8dce86c774",
        "d775752cb399db3b0660e26e0d9bdb32d7d72cf4ed47694066ccbf629e87e80f",
    ),
    (
        "release workflow",
        "build-release-arm64-cross",
        "0aede8bfa17c33009a588bf1d3202df52c58168eb1d1c173add01e1f76c32cc1",
        "1d5104bd955d0ef4c397cb7be08f37d2d829a822ff9efe43eb26bdac1133bc0a",
        "2a9e77c5946c27cbf1f055f20adf283e159ffd3735e2dcc90edded2c35563c3b",
    ),
)

# Only the publication-control fields that consume the protected ARM64
# artifacts are frozen. The rest of each publishing job remains editable.
PUBLISH_CONTROL_CONTRACTS = {
    "CI workflow": {
        "latest-release": {
            "needs": "    needs: [test, build-binaries, build-arm64-cross]\n",
            "if": (
                "    if: always() && needs.test.result == 'success' && "
                "needs.build-binaries.result == 'success' && "
                "needs.build-arm64-cross.result == 'success' && "
                "github.event_name == 'push' && github.ref == 'refs/heads/main'\n"
            ),
        },
        "docker": {
            "needs": "    needs: [test, build-binaries, build-arm64-cross]\n",
            "if": (
                "    if: always() && needs.test.result == 'success' && "
                "needs.build-binaries.result == 'success' && "
                "needs.build-arm64-cross.result == 'success' && "
                "github.event_name == 'push' && github.ref == 'refs/heads/main'\n"
            ),
        },
    },
    "release workflow": {
        "create-release": {
            "needs": (
                "    needs: [build-release-binaries, build-release-arm64-cross, "
                "docker-manifest, docker-ebpf-manifest]\n"
            ),
        },
        "docker": {
            "needs": (
                "    needs: [build-release-binaries, "
                "build-release-arm64-cross]\n"
            ),
        },
    },
}

ATTACK_PAYLOADS = {
    "whitespace": "arm64 amd64",
    "leading option": "--help",
    "shell metacharacter": "arm64; touch /tmp/cross-policy-marker",
    "command substitution": "$(touch /tmp/cross-policy-marker)",
}

STANDALONE_CROSS = re.compile(r"(?<![A-Za-z0-9_-])cross(?![A-Za-z0-9_-])")
CROSS_ENVIRONMENT = re.compile(
    r"(?<![A-Za-z0-9_])(?:CROSS_[A-Z0-9_]*|DOCKER_OPTS|QEMU_STRACE|"
    r"CARGO_BUILD_TARGET)(?![A-Za-z0-9_])"
)
SHELL_INTERPRETER_NAMES = frozenset({"ash", "bash", "dash", "ksh", "sh", "zsh"})
PYTHON_INTERPRETER = re.compile(r"^(?:python(?:\d+(?:\.\d+)*)?|pypy\d*)$")
# An executable word may be spelled with a leading directory path
# (`/usr/bin/cargo cross`, `~/.cargo/bin/cross`, `./tools/cross`). Absorbing the
# path prefix at every command-word position keeps the whole scanner
# path-agnostic instead of recognizing only bare tool names.
TOOL_PATH_PREFIX = r"(?:[~.]{0,2}(?:/[A-Za-z0-9_.$@{}+-]+)*/)?"
# `sh -c '<script>'` starts a nested shell whose first word is an executable.
# The trailing quote is optional because a flattened Python argv
# (`subprocess.run(['sh', '-c', 'cross build ...'])`) loses its quoting before
# it reaches this scanner. `-lc` and `-l -c` are the same end-of-flags form.
SHELL_C_CONTEXT = (
    rf"(?<![A-Za-z0-9_-]){TOOL_PATH_PREFIX}(?:bash|sh|dash|ksh|zsh|ash)"
    r"(?:\s+-[A-Za-z]+)*\s+-[A-Za-z]*c[A-Za-z]*\s+['\"]?"
)
# `case $x in *) cross build ...;; esac` puts the executable straight after a
# pattern terminator. Anchoring on the preceding `in`/`;;` keeps ordinary
# parenthesized prose such as `see (note) cross builds` out of the slot.
CASE_ARM_CONTEXT = r"(?:\bin|;;)\s+\(?\s*[^\s;&|()]+(?:\s*\|\s*[^\s;&|()]+)*\)\s+"
# A command word can start a new statement after an operator, at the start of a
# line, or immediately inside a function body/group. `{` matters because a
# one-line function such as `f(){ cross build ...; }` places the executable
# directly after the brace with no other separator. Bash requires blank space
# after that brace, and requiring it here keeps ordinary `{"cross": ...}` data
# out of the executable slot. A bare `(` is deliberately still not a context: a
# real subshell is already covered by the optional `\(` that follows each
# context, whereas a bare `(` also appears literally inside quoted prose.
# `$(`, a backtick, and `<(`/`>(` are unambiguous executable slots, so an
# assignment such as `out=$(cross build ...)` is one.
COMMAND_START_CONTEXT = (
    r"(?:^\s*|(?:run|shell):\s*|(?:&&|\|\||;;|;|&|\|)\s*|\{\s+|"
    r"\$\(\s*|`\s*|[<>]\(\s*|"
    rf"{CASE_ARM_CONTEXT}|{SHELL_C_CONTEXT}|"
    r"\b(?:if|elif|while|until|then|do|else)\s+)"
    r"(?:!\s*)?"
)
# `env` and the ordinary command wrappers accept options whose operand is a
# separate word (`env -u FOO cross`, `sudo -u builder cross`, `timeout 30
# cross`). Enumerate the operand-taking forms before the self-contained ones so
# the operand is consumed with its flag instead of being mistaken for the
# executable.
# A bare `--` ends option parsing, so `env -- cross` and `sudo -- cross` place
# the executable in the very next word. Enumerating it first stops the scanner
# from halting on the marker instead of consuming it.
ENV_OPTION = (
    r"(?:--(?=\s)|"
    r"-[uCS]\s+[^\s]+|"
    r"--(?:unset|chdir|split-string|block-signal|default-signal|ignore-signal)"
    r"(?:=[^\s]+|\s+[^\s]+)|"
    r"--?[^\s]+|"
    r"[A-Za-z_][A-Za-z0-9_]*=[^\s]+)"
)
ENV_PREFIX = rf"(?:{TOOL_PATH_PREFIX}env(?:\s+{ENV_OPTION})*\s+)"
WRAPPER_OPTION = (
    r"(?:--(?=\s)|"
    r"-[nupgEC]\s+[^\s]+|"
    r"--(?:user|group|chdir|niceness|priority|signal|kill-after)"
    r"(?:=[^\s]+|\s+[^\s]+)|"
    r"--?[A-Za-z0-9][A-Za-z0-9-]*(?:=[^\s]+)?|"
    r"[0-9]+(?:\.[0-9]+)?[smhd]?)"
)
# `command -v`/`-V` only looks a name up and prints it; it does not execute the
# operand, so it must not open an executable slot.
WRAPPER_PREFIX = (
    rf"(?:{TOOL_PATH_PREFIX}(?!command\s+-[vV]\b)"
    r"(?:command|exec|nohup|sudo|time|timeout|stdbuf|nice|ionice|setsid)"
    rf"(?:\s+{WRAPPER_OPTION})*\s+)*"
)
# Every Cross spelling shares one command-start prefix, including the
# `cargo install cross` form. Anchoring that form keeps benign prose such as
# `echo "run cargo install cross locally"` or a comment out of the executable
# slot instead of freezing unrelated edits to the file that mentions it.
CROSS_EXECUTABLE = (
    rf"(?:{ENV_PREFIX}?(?:{TOOL_PATH_PREFIX}cargo(?:\s+\+[^\s]+)?\s+)?"
    rf"{TOOL_PATH_PREFIX}(?<![A-Za-z0-9_-])cross(?![A-Za-z0-9_-])(?=\s+\S)|"
    rf"{ENV_PREFIX}?{TOOL_PATH_PREFIX}cargo(?:\s+\+[^\s]+)?\s+install"
    r"(?:\s+--[^\s=]+(?:=[^\s]+|\s+(?!cross\b)[^\s]+)?)*"
    r"\s+cross(?![A-Za-z0-9_-]))"
)
CROSS_COMMAND_CONTEXT = re.compile(
    COMMAND_START_CONTEXT
    + WRAPPER_PREFIX
    + r"(?:[A-Za-z_][A-Za-z0-9_]*=[^\s]+\s+)*"
    r"(?:\(\s*)?"
    + CROSS_EXECUTABLE
)
WRAPPED_LITERAL_CROSS = re.compile(
    r"(?:\b(?:bash|sh)\s+-c\s+['\"][^'\"]*\bcross\s+|"
    r"(?:^|\s)(?:/[^\s'\"]+)+/cross\s+)"
)
SHELL_INTERPOLATION = re.compile(
    r"\$\{[^{}\n]*\}|`[^`\n]*`|"
    r"\$[A-Za-z_][A-Za-z0-9_]*|\$[0-9@*#?$!-]"
)
WORKFLOW_FILENAME = re.compile(r"^[A-Za-z0-9._-]+\.(?:yml|yaml)$")
PROTECTED_WORKFLOW_FILENAMES = frozenset({"ci.yml", "release.yml"})
APPROVED_AUTOMATION_ROOTS = (
    ".github/scripts/",
    "comparison/",
    "scripts/",
    "tests/k8s/",
    "tests/performance/",
)
GENERATED_COMMAND_PATHS = frozenset(
    {
        "target/ci-release/ferrum-edge",
        "tests/performance/target/release/backend_server",
        "target/release/ferrum-edge",
        "target/release/proto_backend",
        "ferrum-edge-linux-x86_64",
        "conformance",
    }
)
GENERATED_SCRIPT_PREFIXES = (
    "RUNNER_TEMP/",
    "trusted_dir/",
    "target/",
    "results/",
    "coverage-report/",
    "benchmark-results/",
    "comparison-results/",
    "tmp/",
)
IGNORED_AUTOMATION_SUFFIXES = frozenset(
    {".gif", ".jpeg", ".jpg", ".pdf", ".png", ".pyc", ".webp"}
)
IGNORED_AUTOMATION_DIRECTORIES = frozenset({"__pycache__"})
LOCAL_ACTION_REFERENCE = re.compile(
    r"^\s*(?:-\s*)?(?:uses|'uses'|\"uses\")\s*:\s*"
    r"(?P<quote>['\"]?)(?P<path>\./[A-Za-z0-9._/-]+)"
    r"(?P=quote)\s*(?:#.*)?$"
)
LOCAL_ACTION_CANDIDATE = re.compile(
    r"^\s*(?:-\s*)?(?:uses|'uses'|\"uses\")\s*:\s*['\"]?\./"
)
LOCAL_COMMAND_REFERENCE = re.compile(
    r"(?:^\s*|(?:run|shell):\s*|(?:&&|\|\||;;|;|&|\|)\s*|\$\(\s*|"
    r"(?:<|>)\(\s*|\{\s+|"
    r"\b(?:if|elif|while|until|then|do|else)\s+)"
    r"(?:!\s*)?"
    r"(?:[A-Za-z_][A-Za-z0-9_]*=[^\s]+\s+)*"
    r"(?:\(\s*)?"
    + WRAPPER_PREFIX
    + ENV_PREFIX
    + r"?"
    r"(?:(?:bash|sh|python|python3|ruby|node)"
    r"(?:\s+--?[^\s]+)*\s*(?:[0-9]+)?<(?![<&])\s*"
    r"(?P<redirected>(?:\$(?:[A-Za-z_][A-Za-z0-9_]*|"
    r"\{[A-Za-z_][A-Za-z0-9_]*\})/)?"
    r"(?:[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)+|"
    r"[A-Za-z0-9._-]+\.(?:sh|py|rb)))|"
    r"(?:bash|sh|python|python3|ruby|node|source|\.)"
    r"(?:\s+--?[^\s]+)*\s+"
    r"(?P<interpreted>(?:\$(?:[A-Za-z_][A-Za-z0-9_]*|"
    r"\{[A-Za-z_][A-Za-z0-9_]*\})/)?"
    r"(?:[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)+|"
    r"[A-Za-z0-9._-]+\.(?:sh|py|rb)))|"
    r"(?P<direct>\./[A-Za-z0-9._/-]+)|"
    r"(?P<bare>[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)+\.(?:sh|py|rb)))"
)
YAML_RUN_FIELD = re.compile(
    r"^(?P<indent> *)(?:-\s*)?"
    r"(?P<key>run|'run'|\"run\"|shell|'shell'|\"shell\")"
    r"\s*:\s*(?P<value>.*)$"
)
YAML_DYNAMIC_COMMAND_FIELD = re.compile(
    r"^\s*(?:-\s*)?"
    r"(?:run|'run'|\"run\"|shell|'shell'|\"shell\")\s*:\s*[*!&]"
)
YAML_DYNAMIC_USES_FIELD = re.compile(
    r"^\s*(?:-\s*)?(?:uses|'uses'|\"uses\")\s*:\s*[*!&]"
)
HEREDOC_START = re.compile(
    r"<<-?\s*(?P<quote>['\"]?)(?P<delimiter>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?P=quote)"
)
BLOCK_SCALAR_HEADER = re.compile(
    r"^[|>](?:(?:[1-9][+-]?)|(?:[+-][1-9]?))?(?:\s+#.*)?$"
)
HEREDOC_EXECUTABLE = re.compile(
    r"(?:^\s*|(?:&&|\|\||;;|;|&|\|)\s*|\$\(\s*|\{\s+|"
    r"\b(?:if|elif|while|until|then|do|else)\s+)"
    r"(?:!\s*)?"
    r"(?:[A-Za-z_][A-Za-z0-9_]*=[^\s]+\s+)*"
    + WRAPPER_PREFIX
    + ENV_PREFIX
    + r"?"
    r"(?P<interpreter>bash|sh|python|python3)\b"
)
OPAQUE_INLINE_SHELL = re.compile(
    r"(?:\b(?:bash|sh)\s+-c\s+[^\n]*\$\(|"
    r"\beval\s+[^\n]*\$\(|"
    r"(?:\bsource|(?<!\S)\.)\s+<\()"
)
# One command word may be assembled from several adjacent expansions, with or
# without literal letters between them (`${x}${y}`, `$x$y`, `${x}o${y}`,
# `$(printf cr)${y}`). Any such word driving an ARM64 cross build is an opaque
# executable.
OPAQUE_EXPANSION = (
    r"(?:\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$[A-Za-z_][A-Za-z0-9_]*|"
    r"\$\([^()\n]*\)|`[^`\n]*`)"
)
OPAQUE_ARM_CROSS_EXECUTION = re.compile(
    r"(?:^\s*|(?:&&|\|\||;;|;|&|\|)\s*|\{\s+|\b(?:then|do|else)\s+)"
    r"(?:\(\s*)?['\"]?"
    rf"(?:[A-Za-z]*{OPAQUE_EXPANSION}['\"]?)+[A-Za-z]*['\"]?\s+"
    r"(?:\+[^\s]+\s+)?(?:build|rustc|run|test|check|clippy|doc|bench)\b"
    r"[^\n]*--target(?:=|\s+)aarch64-unknown-linux-gnu\b",
    # The leading context anchors on a line start, so this must match every
    # line of a multi-line script, not only the first.
    re.MULTILINE,
)
NON_PYTHON_PROCESS_DISPATCH = re.compile(
    r"(?:(?:\bchild_process|require\(['\"]child_process['\"]\))\s*\.\s*"
    r"(?:exec|execFile|fork|spawn)(?:Sync)?\s*\(|"
    r"\b(?:Bun\.spawn|Deno\.Command)\s*\(|"
    r"\b(?:Process\.spawn|IO\.popen|Open3\.[A-Za-z_]+|system|exec)\s*\(|"
    r"\b(?:os\.execute|io\.popen)\s*\()"
)
# A Bash helper that enables `expand_aliases` and binds a short name to Cross
# runs Cross through a word that never appears as a literal executable. Both
# the alias body and every command-start use of the alias name are command text.
SHELL_ALIAS_DEFINITION = re.compile(
    r"(?:^[ \t]*|(?:&&|\|\||;;|;|&|\|)\s*|\{\s+|\b(?:then|do|else)\s+)"
    r"alias\s+(?:-p\s+)*(?P<name>[A-Za-z_][A-Za-z0-9_-]*)="
    r"(?P<value>'[^'\n]*'|\"[^\"\n]*\"|[^\s;&|]*)",
    # Definitions are scanned over whole files, so the line-start context must
    # match every line rather than only the first.
    re.MULTILINE,
)
MAXIMUM_TRACKED_ALIASES = 64
# A repo-controlled dispatcher runs recipes from a manifest the workflow never
# names, so `run: make arm64` can reach Cross with no Cross token in the
# workflow. Each dispatcher is mapped to the manifests it can execute; the
# manifest is then followed and frozen exactly like a referenced script.
DISPATCHER_MANIFESTS = {
    "make": ("Makefile", "makefile", "GNUmakefile"),
    "gmake": ("Makefile", "makefile", "GNUmakefile"),
    "npm": ("package.json",),
    "pnpm": ("package.json",),
    "yarn": ("package.json",),
    "just": ("justfile", "Justfile", ".justfile"),
    "task": ("Taskfile.yml", "Taskfile.yaml"),
}
DISPATCHER_MANIFEST_NAMES = frozenset(
    name for names in DISPATCHER_MANIFESTS.values() for name in names
)
BUILD_DISPATCHER = re.compile(
    COMMAND_START_CONTEXT
    + WRAPPER_PREFIX
    + r"(?:[A-Za-z_][A-Za-z0-9_]*=[^\s]+\s+)*"
    + ENV_PREFIX
    + r"?"
    + TOOL_PATH_PREFIX
    + r"(?P<dispatcher>" + "|".join(sorted(DISPATCHER_MANIFESTS)) + r")"
    r"(?![A-Za-z0-9_-])(?P<arguments>[^\n;&|]*)"
)
# `make -C build`, `just --justfile tools/justfile`, and `npm --prefix web run`
# relocate the manifest the dispatcher reads.
DISPATCHER_DIRECTORY = re.compile(
    r"(?:^|\s)(?:-C|--directory|--prefix|--cwd|--dir)(?:=|\s+)"
    r"(?P<quote>['\"]?)(?P<path>[^\s'\";&|]+)(?P=quote)"
)
DISPATCHER_WORKSPACE = re.compile(
    r"(?:^|\s)(?:-w|--workspace)(?:=|\s+)"
    r"(?P<quote>['\"]?)(?P<path>[^\s'\";&|]+)(?P=quote)"
)
DISPATCHER_WORKSPACE_OPTION = re.compile(
    r"(?:^|\s)(?:-w|--workspace)(?==|\s|$)|(?:^|\s)-w[^\s=]+"
)
DISPATCHER_ALL_WORKSPACES = re.compile(r"(?:^|\s)--workspaces(?:\s|$)")
DISPATCHER_MANIFEST_OPTION = re.compile(
    r"(?:^|\s)(?:-f|--file|--makefile|--justfile|--taskfile)(?:=|\s+)"
    r"(?P<quote>['\"]?)(?P<path>[^\s'\";&|]+)(?P=quote)"
)
CD_COMMAND = re.compile(
    r"(?:^\s*|(?:&&|\|\||;;|;|&|\|)\s*|\{\s+|\b(?:then|do|else)\s+)"
    r"cd(?:\s+--)?\s+"
    r"(?P<quote>['\"]?)(?P<path>[^\s;&|]+)(?P=quote)"
)


def exact_keys(value: Any, expected: set[str], location: str) -> list[str]:
    if not isinstance(value, dict):
        return [f"{location} must be a table"]

    actual = set(value)
    if actual == expected:
        return []

    unexpected = sorted(actual - expected)
    missing = sorted(expected - actual)
    details: list[str] = []
    if unexpected:
        details.append(f"unexpected keys: {', '.join(unexpected)}")
    if missing:
        details.append(f"missing keys: {', '.join(missing)}")
    return [f"{location} must have exactly the approved keys ({'; '.join(details)})"]


def validate_pre_build(value: Any) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        return [f"target.{TARGET}.pre-build must be an array of strings"]

    errors: list[str] = []
    if any("CROSS_DEB_ARCH" in command for command in value):
        errors.append("CROSS_DEB_ARCH must not reach any ARM64 pre-build command")

    # Cross 0.2.5 joins every entry with newlines and evaluates the result in a
    # Dockerfile RUN command. The complete ordered list must therefore be
    # allowlisted; validating only a privileged prefix leaves later commands
    # executable without review.
    if tuple(value) != EXPECTED_PRE_BUILD_COMMANDS:
        errors.append(
            f"target.{TARGET}.pre-build must exactly match all "
            f"{len(EXPECTED_PRE_BUILD_COMMANDS)} approved commands in order"
        )

    return errors


def validate_cross_configuration(parsed: Any) -> list[str]:
    errors = exact_keys(parsed, {"target"}, "Cross.toml root")
    if errors:
        return errors

    targets = parsed["target"]
    errors.extend(exact_keys(targets, {TARGET}, "Cross.toml target table"))
    if errors:
        return errors

    target = targets[TARGET]
    errors.extend(
        exact_keys(target, {"image", "pre-build", "env"}, f"target.{TARGET}")
    )
    if errors:
        return errors

    if target["image"] != EXPECTED_IMAGE:
        errors.append(f"target.{TARGET}.image must be exactly {EXPECTED_IMAGE!r}")
    errors.extend(validate_pre_build(target["pre-build"]))

    target_env = target["env"]
    errors.extend(exact_keys(target_env, {"passthrough"}, f"target.{TARGET}.env"))
    if not errors:
        passthrough = target_env["passthrough"]
        if not isinstance(passthrough, list) or not all(
            isinstance(item, str) for item in passthrough
        ):
            errors.append(f"target.{TARGET}.env.passthrough must be an array of strings")
        elif tuple(passthrough) != EXPECTED_PASSTHROUGH:
            errors.append(
                f"target.{TARGET}.env.passthrough must exactly match the approved fixed values"
            )

    return errors


def validate_cargo_configuration(parsed: Any) -> list[str]:
    if not isinstance(parsed, dict):
        return ["Cargo.toml root must be a table"]

    if not isinstance(parsed.get("package"), dict):
        return ["Cargo.toml package must be a table"]

    errors: list[str] = []
    for owner in ("package", "workspace"):
        owner_table = parsed.get(owner)
        if owner_table is None:
            continue
        if not isinstance(owner_table, dict):
            errors.append(f"Cargo.toml {owner} must be a table")
            continue
        metadata = owner_table.get("metadata")
        if metadata is None:
            continue
        if not isinstance(metadata, dict):
            errors.append(f"Cargo.toml {owner}.metadata must be a table")
            continue
        if "cross" in metadata:
            errors.append(
                f"Cargo.toml {owner}.metadata.cross is forbidden; all Cross "
                "configuration must be present in the fully allowlisted Cross.toml"
            )
    return errors


def validate_cargo_tool_configuration(parsed: Any) -> list[str]:
    """Allowlist Cargo config fields that the protected Cross build consumes."""

    errors = exact_keys(parsed, {"build", "target", "net", "http"}, ".cargo config")
    if errors:
        return errors

    build = parsed["build"]
    errors.extend(exact_keys(build, set(EXPECTED_CARGO_BUILD), ".cargo config build"))
    if not errors and build != EXPECTED_CARGO_BUILD:
        errors.append(
            ".cargo config build must retain the approved rustc-wrapper and "
            "incremental values"
        )

    targets = parsed["target"]
    errors.extend(
        exact_keys(targets, set(EXPECTED_CARGO_TARGETS), ".cargo config target")
    )
    if not errors and targets != EXPECTED_CARGO_TARGETS:
        errors.append(
            ".cargo config target tables must exactly match the approved linker/"
            "rustflags contract"
        )

    net = parsed["net"]
    errors.extend(exact_keys(net, {"git-fetch-with-cli", "retry"}, ".cargo config net"))
    if not errors:
        if net["git-fetch-with-cli"] is not True:
            errors.append(".cargo config net.git-fetch-with-cli must remain true")
        retry = net["retry"]
        if isinstance(retry, bool) or not isinstance(retry, int) or not 0 <= retry <= 100:
            errors.append(".cargo config net.retry must be an integer from 0 through 100")

    http = parsed["http"]
    errors.extend(exact_keys(http, {"multiplexing"}, ".cargo config http"))
    if not errors and not isinstance(http["multiplexing"], bool):
        errors.append(".cargo config http.multiplexing must be a boolean")
    return errors


def parse_toml(contents: str, source: str) -> tuple[Any, list[str]]:
    try:
        return tomllib.loads(contents), []
    except tomllib.TOMLDecodeError as error:
        return None, [f"cannot parse {source}: {error}"]


def load_text(path: Path) -> tuple[str | None, list[str]]:
    try:
        return path.read_text(encoding="utf-8"), []
    except (OSError, UnicodeError) as error:
        return None, [f"cannot read {path}: {error}"]


def load_toml(path: Path) -> tuple[Any, list[str]]:
    contents, failures = load_text(path)
    if failures:
        return None, failures
    assert contents is not None
    return parse_toml(contents, str(path))


def unsafe_commands(payload: str) -> list[str]:
    commands = list(EXPECTED_PRE_BUILD_COMMANDS)
    commands[:3] = [
        f"dpkg --add-architecture {payload}",
        "apt-get update && apt-get install --assume-yes perl make "
        f"libcurl4-openssl-dev:{payload} cmake software-properties-common wget gnupg unzip",
        f"multiarch=$(dpkg-architecture -a{payload} -qDEB_HOST_MULTIARCH) && "
        'ln -sfn "/usr/include/${multiarch}/curl" '
        '"/usr/${multiarch}/include/curl"',
    ]
    return commands


def decode_simple_yaml_key(line: str) -> tuple[int, str] | None:
    """Decode the simple mapping-key forms accepted in the guarded workflows."""

    match = re.match(
        r"^(?P<indent> *)(?P<key>[A-Za-z0-9_-]+|'(?:[^']|'')*'|\"(?:[^\"\\]|\\.)*\")\s*:",
        line,
    )
    if match is None:
        return None

    raw = match.group("key")
    if raw.startswith("'"):
        key = raw[1:-1].replace("''", "'")
    elif raw.startswith('"'):
        try:
            key = json.loads(raw)
        except json.JSONDecodeError:
            return None
    else:
        key = raw
    return len(match.group("indent")), key


def extract_job_block(
    contents: str,
    source: str,
    job_name: str,
    *,
    required: bool,
) -> tuple[str | None, list[str]]:
    lines = contents.splitlines(keepends=True)
    jobs_headers = [
        index
        for index, line in enumerate(lines)
        if decode_simple_yaml_key(line.rstrip("\r\n")) == (0, "jobs")
    ]
    if len(jobs_headers) != 1:
        return None, [f"{source} must contain exactly one top-level jobs mapping"]

    jobs_index = jobs_headers[0]
    if lines[jobs_index].rstrip("\r\n") != "jobs:":
        return None, [f"{source} must use the canonical top-level jobs: mapping"]

    jobs_end = len(lines)
    for index in range(jobs_index + 1, len(lines)):
        line = lines[index]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        decoded = decode_simple_yaml_key(line.rstrip("\r\n"))
        if decoded is not None and decoded[0] == 0:
            jobs_end = index
            break

    matches = [
        index
        for index in range(jobs_index + 1, jobs_end)
        if decode_simple_yaml_key(lines[index].rstrip("\r\n")) == (2, job_name)
    ]
    if not matches:
        if required:
            return None, [f"{source} is missing protected job {job_name!r}"]
        return None, []
    if len(matches) != 1:
        return None, [f"{source} must contain protected job {job_name!r} exactly once"]

    start = matches[0]
    end = jobs_end
    for index in range(start + 1, jobs_end):
        decoded = decode_simple_yaml_key(lines[index].rstrip("\r\n"))
        if decoded is not None and decoded[0] == 2:
            end = index
            break

    block = "".join(lines[start:end]).rstrip() + "\n"
    return block, []


def extract_job_field_block(
    contents: str,
    source: str,
    job_name: str,
    field_name: str,
    *,
    required: bool,
) -> tuple[str | None, list[str]]:
    """Extract one direct job field without freezing the rest of the job."""

    job_block, failures = extract_job_block(
        contents,
        source,
        job_name,
        required=required,
    )
    if failures or job_block is None:
        return None, failures

    lines = job_block.splitlines(keepends=True)
    matches = [
        index
        for index, line in enumerate(lines)
        if decode_simple_yaml_key(line.rstrip("\r\n")) == (4, field_name)
    ]
    if not matches and not required:
        return None, []
    if len(matches) != 1:
        return None, [
            f"{source} job {job_name!r} must contain direct field "
            f"{field_name!r} exactly once"
        ]

    start = matches[0]
    end = len(lines)
    for index in range(start + 1, len(lines)):
        decoded = decode_simple_yaml_key(lines[index].rstrip("\r\n"))
        if decoded is not None and decoded[0] <= 4:
            end = index
            break
    return "".join(lines[start:end]).rstrip() + "\n", []


def validate_publish_control_contract(contents: str, source: str) -> list[str]:
    contracts = PUBLISH_CONTROL_CONTRACTS.get(source, {})
    errors: list[str] = []
    for job_name, fields in contracts.items():
        for field_name, expected in fields.items():
            actual, failures = extract_job_field_block(
                contents,
                source,
                job_name,
                field_name,
                required=True,
            )
            errors.extend(failures)
            if not failures and actual != expected:
                errors.append(
                    f"{source} job {job_name!r} field {field_name!r} differs "
                    "from the trusted ARM64 publication dependency contract"
                )
    return errors


def compare_pr_publish_control_contract(
    merge_base_contents: str,
    proposed_contents: str,
    source: str,
) -> list[str]:
    contracts = PUBLISH_CONTROL_CONTRACTS.get(source, {})
    errors: list[str] = []
    for job_name, fields in contracts.items():
        for field_name in fields:
            baseline, baseline_failures = extract_job_field_block(
                merge_base_contents,
                f"merge-base {source}",
                job_name,
                field_name,
                required=False,
            )
            proposed, proposed_failures = extract_job_field_block(
                proposed_contents,
                f"proposed {source}",
                job_name,
                field_name,
                required=False,
            )
            errors.extend(baseline_failures)
            errors.extend(proposed_failures)
            if not baseline_failures and not proposed_failures:
                if baseline != proposed:
                    errors.append(
                        f"{source} job {job_name!r} ARM64 publication field "
                        f"{field_name!r} cannot be changed by a pull request"
                    )
    return errors


def extract_top_level_block(
    contents: str,
    source: str,
    key_name: str,
    *,
    required: bool = True,
) -> tuple[str | None, list[str]]:
    lines = contents.splitlines(keepends=True)
    matches = [
        index
        for index, line in enumerate(lines)
        if decode_simple_yaml_key(line.rstrip("\r\n")) == (0, key_name)
    ]
    if not matches and not required:
        return None, []
    if len(matches) != 1:
        return None, [f"{source} must contain exactly one top-level {key_name} mapping"]

    start = matches[0]
    if lines[start].rstrip("\r\n") != f"{key_name}:":
        return None, [f"{source} must use the canonical top-level {key_name}: mapping"]

    end = len(lines)
    for index in range(start + 1, len(lines)):
        line = lines[index]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        decoded = decode_simple_yaml_key(line.rstrip("\r\n"))
        if decoded is not None and decoded[0] == 0:
            end = index
            break

    block = "".join(lines[start:end]).rstrip() + "\n"
    return block, []


def interpolation_literal(raw: str) -> str:
    """Extract a literal/default fragment while treating unknown expansion as empty."""

    if raw.startswith("${{"):
        inner = raw[3:-2].strip()
        if len(inner) >= 2 and inner[0] == inner[-1] and inner[0] in "'\"":
            return inner[1:-1]
        formatted = github_format_literal(inner)
        if formatted is not None:
            return formatted
        return ""

    if raw.startswith("${"):
        inner = raw[2:-1]
        default = re.match(r"^[A-Za-z_][A-Za-z0-9_]*(?::?[-+?=])(.*)$", inner)
        return default.group(1) if default is not None else ""

    if raw.startswith("$("):
        inner = raw[2:-1]
    else:
        inner = raw[1:-1]
    words = re.findall(r"[A-Za-z]+", inner)
    return next((word for word in reversed(words) if word in "cross"), "")


def expression_string_arguments(value: str) -> tuple[str, ...] | None:
    """Parse a comma-separated list containing only quoted expression strings."""

    arguments: list[str] = []
    cursor = 0
    while cursor < len(value):
        while cursor < len(value) and value[cursor].isspace():
            cursor += 1
        if cursor == len(value) or value[cursor] not in "'\"":
            return None

        quote = value[cursor]
        cursor += 1
        characters: list[str] = []
        while cursor < len(value):
            character = value[cursor]
            if character == quote:
                if quote == "'" and cursor + 1 < len(value) and value[cursor + 1] == "'":
                    characters.append("'")
                    cursor += 2
                    continue
                cursor += 1
                break
            if character == "\\" and quote == '"' and cursor + 1 < len(value):
                characters.append(value[cursor + 1])
                cursor += 2
                continue
            characters.append(character)
            cursor += 1
        else:
            return None

        arguments.append("".join(characters))
        while cursor < len(value) and value[cursor].isspace():
            cursor += 1
        if cursor == len(value):
            break
        if value[cursor] != ",":
            return None
        cursor += 1
    return tuple(arguments)


def github_format_literal(inner: str) -> str | None:
    """Evaluate GitHub format() only when every input is a static string."""

    match = re.fullmatch(r"format\s*\((.*)\)", inner)
    if match is None:
        return None
    arguments = expression_string_arguments(match.group(1))
    if arguments is None or not arguments:
        return None
    try:
        return arguments[0].format(*arguments[1:])
    except (IndexError, KeyError, ValueError):
        return None


def github_expression_spans(line: str) -> tuple[tuple[int, int], ...]:
    """Locate outer GitHub expression spans while allowing braces in strings."""

    spans: list[tuple[int, int]] = []
    cursor = 0
    while (start := line.find("${{", cursor)) >= 0:
        quote: str | None = None
        closed = False
        index = start + 3
        while index < len(line):
            character = line[index]
            if quote is not None:
                if quote == "'" and line.startswith("''", index):
                    index += 2
                    continue
                if character == "\\" and quote == '"':
                    index += 2
                    continue
                if character == quote:
                    quote = None
                index += 1
                continue
            if character in "'\"":
                quote = character
                index += 1
                continue
            if line.startswith("}}", index):
                index += 2
                closed = True
                break
            index += 1

        end = index if closed else len(line)
        spans.append((start, end))
        cursor = end
    return tuple(spans)


def replace_github_expressions(line: str, *, literal: bool) -> str:
    spans = github_expression_spans(line)
    if not spans:
        return line

    parts: list[str] = []
    cursor = 0
    for start, end in spans:
        parts.append(line[cursor:start])
        raw = line[start:end]
        parts.append(
            interpolation_literal(raw)
            if literal and raw.endswith("}}")
            else ""
        )
        cursor = end
    parts.append(line[cursor:])
    return "".join(parts)


def command_substitution_spans(line: str) -> tuple[tuple[int, int], ...]:
    """Locate complete outer $(...) spans, including nested parentheses."""

    spans: list[tuple[int, int]] = []
    cursor = 0
    while (start := line.find("$(", cursor)) >= 0:
        depth = 1
        quote: str | None = None
        index = start + 2
        while index < len(line) and depth:
            character = line[index]
            if quote is not None:
                if character == "\\" and quote == '"':
                    index += 2
                    continue
                if character == quote:
                    quote = None
                index += 1
                continue
            if character in "'\"":
                quote = character
            elif character == "\\":
                index += 2
                continue
            elif character == "(":
                depth += 1
            elif character == ")":
                depth -= 1
            index += 1

        # An unterminated substitution cannot execute as a valid shell word,
        # but consume it to the line end so partial content is not trusted.
        end = index if depth == 0 else len(line)
        spans.append((start, end))
        cursor = end
    return tuple(spans)


def replace_command_substitutions(line: str, *, literal: bool) -> str:
    spans = command_substitution_spans(line)
    if not spans:
        return line

    parts: list[str] = []
    cursor = 0
    for start, end in spans:
        parts.append(line[cursor:start])
        raw = line[start:end]
        parts.append(interpolation_literal(raw) if literal and raw.endswith(")") else "")
        cursor = end
    parts.append(line[cursor:])
    return "".join(parts)


def shell_tokens(value: str) -> tuple[str, ...] | None:
    """Tokenize one shell program without turning quoted prose into commands."""

    try:
        lexer = shlex.shlex(value, posix=True, punctuation_chars=";&|()<>")
        lexer.whitespace_split = True
        lexer.commenters = "#"
        return tuple(lexer)
    except ValueError:
        return None


def tool_name(value: str) -> str:
    """Return the executable basename for a literal shell word."""

    return PurePosixPath(value).name


def dynamic_shell_word(value: str) -> bool:
    return bool(
        re.search(r"\$\{|\$\(|\$[A-Za-z_0-9@*#?$!-]|`|\$\{\{", value)
    )


def redirection_token(value: str) -> bool:
    return bool(value) and ("<" in value or ">" in value) and not set(value) - set(
        "<>&"
    )


def skip_redirections_and_assignments(
    tokens: tuple[str, ...],
    index: int,
) -> int:
    """Skip shell prefixes that may legally precede a command word."""

    while index < len(tokens):
        token = tokens[index]
        if token in {"!", "(", "{"} or token in {
            "if",
            "elif",
            "while",
            "until",
            "then",
            "do",
            "else",
        }:
            index += 1
            continue
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", token, re.DOTALL):
            index += 1
            continue
        if token.isdigit() and index + 1 < len(tokens) and redirection_token(
            tokens[index + 1]
        ):
            index += 1
            token = tokens[index]
        if redirection_token(token):
            index += 1
            if index < len(tokens):
                index += 1
            continue
        break
    return index


def skip_env_prefix(tokens: tuple[str, ...], index: int) -> int:
    """Return the command operand after a quote-aware `env` prefix."""

    option_operands = {
        "-C",
        "-S",
        "-u",
        "--block-signal",
        "--chdir",
        "--default-signal",
        "--ignore-signal",
        "--split-string",
        "--unset",
    }
    while index < len(tokens):
        token = tokens[index]
        if token in {"-", "--"}:
            index += 1
            if token == "--":
                break
            continue
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", token, re.DOTALL):
            index += 1
            continue
        if token in option_operands:
            index += 2
            continue
        if token.startswith("--") and "=" in token:
            index += 1
            continue
        if token.startswith("-"):
            index += 1
            continue
        break
    return index


def skip_wrapper_prefixes(tokens: tuple[str, ...], index: int) -> tuple[int, bool]:
    """Unwrap commands that execute their final command operand."""

    wrappers = {
        "command",
        "exec",
        "ionice",
        "nice",
        "nohup",
        "setsid",
        "stdbuf",
        "sudo",
        "time",
        "timeout",
    }
    option_operands = {
        "-C",
        "-E",
        "-g",
        "-k",
        "-n",
        "-p",
        "-S",
        "-u",
        "--chdir",
        "--group",
        "--kill-after",
        "--niceness",
        "--priority",
        "--signal",
        "--user",
    }
    while index < len(tokens) and tool_name(tokens[index]) in wrappers:
        wrapper = tool_name(tokens[index])
        index += 1
        if wrapper == "command" and index < len(tokens) and tokens[index] in {
            "-V",
            "-v",
        }:
            return len(tokens), False
        while index < len(tokens):
            option = tokens[index]
            if option == "--":
                index += 1
                break
            if option in option_operands:
                index += 2
                continue
            if option.startswith("-"):
                index += 1
                continue
            break
        if wrapper == "timeout" and index < len(tokens):
            # The mandatory duration precedes timeout's command operand.
            index += 1
        index = skip_redirections_and_assignments(tokens, index)
    return index, True


def executable_index(tokens: tuple[str, ...], start: int = 0) -> tuple[int, bool]:
    """Locate a command word after assignments, redirections, and wrappers."""

    index = skip_redirections_and_assignments(tokens, start)
    index, executes = skip_wrapper_prefixes(tokens, index)
    index = skip_redirections_and_assignments(tokens, index)
    if index < len(tokens) and tool_name(tokens[index]) == "env":
        index = skip_env_prefix(tokens, index + 1)
        index = skip_redirections_and_assignments(tokens, index)
        index, executes = skip_wrapper_prefixes(tokens, index)
        index = skip_redirections_and_assignments(tokens, index)
    return index, executes


def cargo_cross_command(tokens: tuple[str, ...], index: int) -> bool:
    """Parse Cargo's optional toolchain and documented global-option layer."""

    index += 1
    if index < len(tokens) and tokens[index].startswith("+"):
        index += 1
    options_with_operands = {"--color", "--config", "--explain", "-C", "-Z"}
    while index < len(tokens) and tokens[index].startswith("-"):
        option = tokens[index]
        index += 1
        if option == "--":
            break
        if option in options_with_operands:
            if index >= len(tokens):
                return False
            index += 1
    if index >= len(tokens):
        return False
    subcommand = tool_name(tokens[index])
    if subcommand == "cross":
        return command_has_argument(tokens, index)
    if subcommand != "install":
        return False

    index += 1
    install_option_operands = {
        "--bin",
        "--color",
        "--config",
        "--features",
        "--git",
        "--index",
        "--jobs",
        "--path",
        "--profile",
        "--registry",
        "--root",
        "--tag",
        "--target",
        "--version",
        "--branch",
        "-F",
        "-j",
    }
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            index += 1
            break
        if token in install_option_operands:
            index += 2
            continue
        if token.startswith("-"):
            index += 1
            continue
        break
    return index < len(tokens) and tokens[index] == "cross"


def xargs_command_index(tokens: tuple[str, ...], index: int) -> int:
    """Return xargs' optional command operand after its option layer."""

    options_with_operands = {
        "--arg-file",
        "--delimiter",
        "--eof",
        "--max-args",
        "--max-chars",
        "--max-lines",
        "--max-procs",
        "--replace",
        "-a",
        "-d",
        "-E",
        "-I",
        "-L",
        "-n",
        "-P",
        "-s",
    }
    index += 1
    while index < len(tokens):
        option = tokens[index]
        if option == "--":
            return index + 1
        if option in options_with_operands:
            index += 2
            continue
        if option.startswith("-"):
            index += 1
            continue
        break
    return index


def command_has_argument(tokens: tuple[str, ...], index: int) -> bool:
    """Return whether an executable has a real operand before shell syntax."""

    if index + 1 >= len(tokens):
        return False
    following = tokens[index + 1]
    return following not in {"&", "&&", ")", ";", ";;", "|", "||", "}"} and (
        not redirection_token(following)
    )


def literal_producer_output(tokens: tuple[str, ...]) -> str | None:
    """Fold the bounded literal producers used to feed a shell on stdin."""

    index, executes = executable_index(tokens)
    if not executes or index >= len(tokens):
        return None
    producer = tool_name(tokens[index])
    arguments = list(tokens[index + 1 :])
    if any(dynamic_shell_word(argument) for argument in arguments):
        return None
    if producer == "echo":
        while arguments and arguments[0] in {"-e", "-E", "-n"}:
            arguments.pop(0)
        return " ".join(arguments)
    if producer != "printf" or not arguments:
        return None
    if arguments[0] in {"%s", "%s\\n"}:
        return "".join(arguments[1:])
    if "%" not in arguments[0]:
        return arguments[0]
    return None


def shell_stdin_program(
    segment: tuple[str, ...],
) -> tuple[str | None, bool]:
    """Return literal shell stdin, or whether the stdin program is opaque."""

    index, executes = executable_index(segment)
    if not executes or index >= len(segment):
        return None, False
    if tool_name(segment[index]) not in SHELL_INTERPRETER_NAMES:
        return None, False

    arguments = segment[index + 1 :]
    for position, token in enumerate(arguments):
        if token == "<<<":
            if position + 1 >= len(arguments):
                return None, True
            program = arguments[position + 1]
            return (None, True) if dynamic_shell_word(program) else (program, False)
        if token == "<" and position + 1 < len(arguments):
            if arguments[position + 1] == "<(" or (
                position + 2 < len(arguments)
                and arguments[position + 1] == "<"
                and arguments[position + 2] == "("
            ):
                body_start = position + (
                    2 if arguments[position + 1] == "<(" else 3
                )
                depth = 1
                end = body_start
                while end < len(arguments) and depth:
                    if arguments[end] == "(":
                        depth += 1
                    elif arguments[end] == ")":
                        depth -= 1
                    end += 1
                if depth:
                    return None, True
                output = literal_producer_output(
                    tuple(arguments[body_start : end - 1])
                )
                return (output, output is None)

    option_index = 0
    while option_index < len(arguments) and arguments[option_index].startswith("-"):
        option = arguments[option_index]
        if "c" in option.lstrip("-"):
            return None, False
        option_index += 1
    if option_index < len(arguments) and not redirection_token(
        arguments[option_index]
    ):
        # A literal script operand, rather than stdin, supplies this shell's code.
        return None, False
    return None, True


def split_shell_pipeline(tokens: tuple[str, ...]) -> tuple[tuple[str, ...], ...]:
    segments: list[tuple[str, ...]] = []
    current: list[str] = []
    depth = 0
    for token in tokens:
        if token == "(":
            depth += 1
        elif token == ")" and depth:
            depth -= 1
        if token in {"|", "|&"} and depth == 0:
            segments.append(tuple(current))
            current = []
        else:
            current.append(token)
    segments.append(tuple(current))
    return tuple(segment for segment in segments if segment)


def token_command_has_cross(
    tokens: tuple[str, ...],
    *,
    include_opaque_shell_executable: bool,
    depth: int,
) -> bool:
    if depth > 8:
        return include_opaque_shell_executable
    index, executes = executable_index(tokens)
    if not executes or index >= len(tokens):
        return False
    command = tool_name(tokens[index])
    if command == "cross":
        return command_has_argument(tokens, index)
    if command == "cargo":
        return cargo_cross_command(tokens, index)
    if command == "xargs":
        nested = xargs_command_index(tokens, index)
        return nested < len(tokens) and token_command_has_cross(
            tokens[nested:],
            include_opaque_shell_executable=include_opaque_shell_executable,
            depth=depth + 1,
        )
    if command == "find":
        for nested in range(index + 1, len(tokens)):
            if tokens[nested] not in {"-exec", "-execdir", "-ok", "-okdir"}:
                continue
            end = nested + 1
            while end < len(tokens) and tokens[end] not in {";", "+"}:
                end += 1
            if token_command_has_cross(
                tokens[nested + 1 : end],
                include_opaque_shell_executable=include_opaque_shell_executable,
                depth=depth + 1,
            ):
                return True
        return False
    if command == "eval":
        arguments = tokens[index + 1 :]
        if any(dynamic_shell_word(argument) for argument in arguments):
            return include_opaque_shell_executable
        return shell_program_has_cross(
            " ".join(arguments),
            include_opaque_shell_executable=include_opaque_shell_executable,
            depth=depth + 1,
        )
    if command in SHELL_INTERPRETER_NAMES:
        for position, option in enumerate(tokens[index + 1 :], start=index + 1):
            if option.startswith("-") and "c" in option.lstrip("-"):
                if position + 1 >= len(tokens):
                    return include_opaque_shell_executable
                program = tokens[position + 1]
                if dynamic_shell_word(program):
                    return include_opaque_shell_executable
                return shell_program_has_cross(
                    program,
                    include_opaque_shell_executable=include_opaque_shell_executable,
                    depth=depth + 1,
                )
    return False


def shell_program_has_cross(
    value: str,
    *,
    include_opaque_shell_executable: bool = False,
    depth: int = 0,
) -> bool:
    """Inspect literal shell command positions and nested stdin programs."""

    tokens = shell_tokens(value)
    if tokens is None:
        return include_opaque_shell_executable and bool(
            STANDALONE_CROSS.search(value) or CROSS_ENVIRONMENT.search(value)
        )
    yaml_shell_field = bool(tokens and tokens[0] == "shell:")
    if tokens and tokens[0] in {"run:", "shell:"}:
        tokens = tokens[1:]

    statements: list[tuple[str, ...]] = []
    current: list[str] = []
    depth_count = 0
    for token in tokens:
        if token == "(":
            depth_count += 1
        elif token == ")" and depth_count:
            depth_count -= 1
        if token in {";", ";;", "&&", "||", "&"} and depth_count == 0:
            if current:
                statements.append(tuple(current))
            current = []
        else:
            current.append(token)
    if current:
        statements.append(tuple(current))

    for statement in statements:
        pipeline = split_shell_pipeline(statement)
        for segment in pipeline:
            if token_command_has_cross(
                segment,
                include_opaque_shell_executable=include_opaque_shell_executable,
                depth=depth,
            ):
                return True
        if yaml_shell_field:
            continue
        for position, segment in enumerate(pipeline):
            stdin_program, opaque = shell_stdin_program(segment)
            if stdin_program is not None and shell_program_has_cross(
                stdin_program,
                include_opaque_shell_executable=include_opaque_shell_executable,
                depth=depth + 1,
            ):
                return True
            if opaque and position > 0:
                producer = literal_producer_output(pipeline[position - 1])
                if producer is not None:
                    if shell_program_has_cross(
                        producer,
                        include_opaque_shell_executable=include_opaque_shell_executable,
                        depth=depth + 1,
                    ):
                        return True
                elif include_opaque_shell_executable:
                    return True
            elif opaque and include_opaque_shell_executable:
                return True
    return False


def strip_shell_comment(value: str) -> str:
    """Remove an unquoted shell comment while preserving quoted `#` data."""

    quote: str | None = None
    escaped = False
    for index, character in enumerate(value):
        if escaped:
            escaped = False
            continue
        if character == "\\" and quote != "'":
            escaped = True
            continue
        if quote is not None:
            if character == quote:
                quote = None
            continue
        if character in "'\"":
            quote = character
            continue
        if character == "#" and (index == 0 or value[index - 1].isspace()):
            return value[:index]
    return value


def has_cross_command_context(
    candidate: str,
    *,
    include_opaque_shell_executable: bool = False,
) -> bool:
    """Recognize Cross in an executable slot, including ordinary shell quotes."""

    executable_text = strip_shell_comment(candidate)
    return shell_program_has_cross(
        executable_text,
        include_opaque_shell_executable=include_opaque_shell_executable,
    ) or any(
        CROSS_COMMAND_CONTEXT.search(variant)
        for variant in (
            executable_text,
            re.sub(r"[\\'\"]", "", executable_text),
        )
    )


CROSS_FRAGMENTS = frozenset(
    "cross"[start:end]
    for start in range(len("cross"))
    for end in range(start + 1, len("cross") + 1)
)


def opaque_word_spans(line: str, spans: tuple[tuple[int, int], ...]) -> tuple[tuple[int, int], ...]:
    """Merge back-to-back substitutions into the single word the shell builds.

    `${x}${y}` and `$x$y` are one command word once expanded, so evaluating each
    interpolation in isolation would miss an executable assembled from adjacent
    expansions. Literal letters between two substitutions belong to the same
    word and are absorbed into the merged span as well.
    """

    merged: list[list[int]] = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
            continue
        if merged and re.fullmatch(r"[A-Za-z]*", line[merged[-1][1] : start]):
            merged[-1][1] = max(merged[-1][1], end)
            continue
        merged.append([start, end])
    return tuple((start, end) for start, end in merged)


def opaque_executable_variants(
    line: str,
    spans: tuple[tuple[int, int], ...],
) -> tuple[str, ...]:
    """Substitute Cross into every opaque word that could hold the executable."""

    variants: list[str] = []
    for start, end in opaque_word_spans(line, spans):
        prefix_match = re.search(r"[A-Za-z]+$", line[:start])
        suffix_match = re.match(r"[A-Za-z]+", line[end:])
        prefix = prefix_match.group() if prefix_match is not None else ""
        suffix = suffix_match.group() if suffix_match is not None else ""
        for fragment in CROSS_FRAGMENTS:
            if f"{prefix}{fragment}{suffix}" == "cross":
                candidate = line[:start] + fragment + line[end:]
                if has_cross_command_context(candidate):
                    variants.append(candidate)
        if not prefix and not suffix:
            candidate = line[:start] + "cross" + line[end:]
            if has_cross_command_context(candidate):
                variants.append(candidate)
    return tuple(variants)


def opaque_command_completion_variants(line: str) -> tuple[str, ...]:
    """Expose opaque substitutions that can complete a literal Cross token."""

    return opaque_executable_variants(line, command_substitution_spans(line))


def opaque_github_expression_variants(line: str) -> tuple[str, ...]:
    """Fail closed when a dynamic expression occupies a Cross command slot."""

    dynamic_spans: list[tuple[int, int]] = []
    for start, end in github_expression_spans(line):
        raw = line[start:end]
        if not raw.endswith("}}"):
            continue
        inner = raw[3:-2].strip()
        is_quoted_literal = (
            len(inner) >= 2
            and inner[0] == inner[-1]
            and inner[0] in "'\""
        )
        if is_quoted_literal or github_format_literal(inner) is not None:
            continue
        dynamic_spans.append((start, end))
    return opaque_executable_variants(line, tuple(dynamic_spans))


def opaque_shell_interpolation_variants(line: str) -> tuple[str, ...]:
    """Expose a shell interpolation that can occupy a Cross executable word."""

    # Command substitutions participate in the same word as parameter
    # expansions, so `$(a)${b}` is considered alongside `${a}${b}`.
    spans = tuple(
        [match.span() for match in SHELL_INTERPOLATION.finditer(line)]
        + list(command_substitution_spans(line))
    )
    return opaque_executable_variants(line, spans)


def decode_ansi_c_body(value: str) -> str:
    """Decode the Bash ANSI-C escapes relevant to executable construction."""

    decoded: list[str] = []
    cursor = 0
    simple_escapes = {
        "a": "\a",
        "b": "\b",
        "e": "\x1b",
        "E": "\x1b",
        "f": "\f",
        "n": "\n",
        "r": "\r",
        "t": "\t",
        "v": "\v",
        "\\": "\\",
        "'": "'",
        '"': '"',
    }
    while cursor < len(value):
        if value[cursor] != "\\" or cursor + 1 == len(value):
            decoded.append(value[cursor])
            cursor += 1
            continue
        cursor += 1
        escape = value[cursor]
        if escape in "01234567":
            end = cursor + 1
            while end < len(value) and end < cursor + 3 and value[end] in "01234567":
                end += 1
            decoded.append(chr(int(value[cursor:end], 8)))
            cursor = end
            continue
        if escape == "x":
            end = cursor + 1
            while end < len(value) and end < cursor + 3 and value[end] in "0123456789abcdefABCDEF":
                end += 1
            if end > cursor + 1:
                decoded.append(chr(int(value[cursor + 1 : end], 16)))
                cursor = end
                continue
        decoded.append(simple_escapes.get(escape, escape))
        cursor += 1
    return "".join(decoded)


def ansi_c_quoted_variants(line: str) -> tuple[str, ...]:
    variants: list[str] = []
    for match in re.finditer(r"\$'((?:[^'\\]|\\.)*)'", line):
        variants.append(
            line[: match.start()]
            + decode_ansi_c_body(match.group(1))
            + line[match.end() :]
        )
    return tuple(variants)


def brace_options(value: str) -> tuple[str, ...] | None:
    """Return bounded Bash brace-expansion choices for one innermost group."""

    if "," in value:
        return tuple(value.split(","))

    character_range = re.fullmatch(r"([A-Za-z])\.\.([A-Za-z])(?:\.\.(-?\d+))?", value)
    if character_range is not None:
        start = ord(character_range.group(1))
        end = ord(character_range.group(2))
        default_step = 1 if end >= start else -1
        step = int(character_range.group(3) or default_step)
        if step == 0 or (end - start) * step < 0:
            return None
        stop = end + (1 if step > 0 else -1)
        choices = tuple(chr(point) for point in range(start, stop, step))
        return choices if len(choices) <= 256 else None

    integer_range = re.fullmatch(r"(-?\d+)\.\.(-?\d+)(?:\.\.(-?\d+))?", value)
    if integer_range is not None:
        start = int(integer_range.group(1))
        end = int(integer_range.group(2))
        default_step = 1 if end >= start else -1
        step = int(integer_range.group(3) or default_step)
        if step == 0 or (end - start) * step < 0:
            return None
        stop = end + (1 if step > 0 else -1)
        choices = tuple(str(number) for number in range(start, stop, step))
        return choices if len(choices) <= 256 else None
    return None


def brace_expansion_variants(value: str) -> tuple[str, ...]:
    """Enumerate bounded Bash brace expansions and fail closed on explosion."""

    variants = [value]
    while True:
        expanded: list[str] = []
        changed = False
        for variant in variants:
            expandable = next(
                (
                    (match, options)
                    for match in re.finditer(r"\{([^{}\n]*)\}", variant)
                    if (options := brace_options(match.group(1))) is not None
                ),
                None,
            )
            if expandable is None:
                expanded.append(variant)
                continue
            match, options = expandable
            changed = True
            for option in options:
                expanded.append(
                    variant[: match.start()] + option + variant[match.end() :]
                )
                if len(expanded) > 256:
                    # A deliberately explosive shell expansion is an unknown
                    # executable surface and therefore fails closed.
                    return tuple([*dict.fromkeys(variants), "cross"])
        variants = list(dict.fromkeys(expanded))
        if not changed:
            return tuple(variants)


def scan_variants(
    line: str,
    *,
    include_opaque_shell_executable: bool = False,
) -> tuple[str, ...]:
    """Expose ordinary YAML/shell quoting variants to the lexical boundary."""

    variants = [line]
    variants.extend(opaque_command_completion_variants(line))
    variants.extend(opaque_github_expression_variants(line))
    if include_opaque_shell_executable:
        variants.extend(opaque_shell_interpolation_variants(line))
    variants.extend(ansi_c_quoted_variants(line))
    collapsed = re.sub(r"[\\'\"]", "", line)
    if collapsed != line:
        variants.append(collapsed)

    without_commands = replace_command_substitutions(line, literal=False)
    without_github = replace_github_expressions(without_commands, literal=False)
    without_interpolation = SHELL_INTERPOLATION.sub("", without_github)
    if without_interpolation != line:
        variants.append(without_interpolation)
    with_literal_commands = replace_command_substitutions(line, literal=True)
    with_literal_github = replace_github_expressions(
        with_literal_commands,
        literal=True,
    )
    with_literal_defaults = SHELL_INTERPOLATION.sub(
        lambda match: interpolation_literal(match.group()),
        with_literal_github,
    )
    if with_literal_defaults != line:
        variants.append(with_literal_defaults)

    for match in re.finditer(r'"(?:[^"\\]|\\.)*"', line):
        try:
            decoded = json.loads(match.group())
        except json.JSONDecodeError:
            continue
        if isinstance(decoded, str):
            variants.append(
                line[: match.start()] + decoded + line[match.end() :]
            )

    expanded_variants = [
        expanded
        for variant in variants
        for expanded in brace_expansion_variants(variant)
    ]
    return tuple(dict.fromkeys(expanded_variants))


def shell_alias_variants(contents: str) -> tuple[str, ...]:
    """Expose the command text a Bash alias expands to at a command start."""

    aliases: dict[str, str] = {}
    for match in SHELL_ALIAS_DEFINITION.finditer(contents):
        value = match.group("value")
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        if value:
            aliases[match.group("name")] = value
        if len(aliases) >= MAXIMUM_TRACKED_ALIASES:
            # A deliberately huge alias table is an unknown executable surface,
            # so stop expanding and fail closed instead of skipping the rest.
            return (f"cross build --target {TARGET}",)
    if not aliases:
        return ()

    # An alias body is a command line in its own right, which covers
    # `alias c='cross build ...'` even with no use site in the same file.
    variants: list[str] = list(aliases.values())
    for name, value in aliases.items():
        expansion = re.compile(
            COMMAND_START_CONTEXT + re.escape(name) + r"(?![A-Za-z0-9_-])"
        )
        for line in contents.splitlines():
            # The match ends with the alias name, so replacing that suffix keeps
            # the command-start context that preceded it intact.
            expanded = expansion.sub(
                lambda use, alias=name, body=value: use.group()[: -len(alias)] + body,
                line,
            )
            if expanded != line:
                variants.append(expanded)
    return tuple(dict.fromkeys(variants))


def logical_scan_lines(contents: str) -> tuple[str, ...]:
    """Return every command line to scan, including Bash alias expansions."""

    return (*contents.splitlines(), *shell_alias_variants(contents))


def contains_cross_surface(
    contents: str,
    *,
    include_opaque_shell_executable: bool = False,
) -> bool:
    """Return whether lexical normalization exposes a Cross-controlled input."""

    logical_contents = re.sub(r"\\\r?\n[ \t]*", "", contents)
    if OPAQUE_INLINE_SHELL.search(logical_contents) or (
        OPAQUE_ARM_CROSS_EXECUTION.search(logical_contents)
    ):
        return True
    return any(
        has_cross_command_context(
            variant,
            include_opaque_shell_executable=include_opaque_shell_executable,
        )
        or CROSS_ENVIRONMENT.search(variant)
        for line in logical_scan_lines(logical_contents)
        for variant in scan_variants(
            line,
            include_opaque_shell_executable=include_opaque_shell_executable,
        )
    )


def unprotected_cross_surfaces(
    contents: str,
    source: str,
    job_name: str,
    *,
    required_job: bool,
    include_opaque_shell_executable: bool = False,
) -> tuple[tuple[str, ...], list[str]]:
    """Return Cross executable/config tokens outside the isolated trusted job."""

    block, failures = extract_job_block(
        contents,
        source,
        job_name,
        required=required_job,
    )
    if failures:
        return (), failures

    outside = contents
    if block is not None:
        block_start = contents.find(block)
        if block_start < 0:
            return (), [f"{source} protected job {job_name!r} cannot be isolated"]
        outside = contents[:block_start] + contents[block_start + len(block) :]

    lines = outside.splitlines(keepends=True)
    jobs_index = next(
        index
        for index, line in enumerate(lines)
        if decode_simple_yaml_key(line.rstrip("\r\n")) == (0, "jobs")
    )
    jobs_end = next(
        (
            index
            for index in range(jobs_index + 1, len(lines))
            if (decoded := decode_simple_yaml_key(lines[index].rstrip("\r\n")))
            is not None
            and decoded[0] == 0
        ),
        len(lines),
    )
    job_starts = [
        (index, decoded[1])
        for index in range(jobs_index + 1, jobs_end)
        if (decoded := decode_simple_yaml_key(lines[index].rstrip("\r\n")))
        is not None
        and decoded[0] == 2
    ]
    job_names = [name for _, name in job_starts]
    if len(job_names) != len(set(job_names)):
        return (), [f"{source} must not contain duplicate job keys"]

    line_jobs: list[str | None] = [None] * len(lines)
    job_digests: dict[str, str] = {}
    sensitive_jobs: set[str] = set()
    for position, (start, name) in enumerate(job_starts):
        end = job_starts[position + 1][0] if position + 1 < len(job_starts) else jobs_end
        for index in range(start, end):
            line_jobs[index] = name
        block_contents = "".join(lines[start:end]).rstrip() + "\n"
        job_digests[name] = hashlib.sha256(block_contents.encode("utf-8")).hexdigest()

        logical_contents = re.sub(
            r"\\\r?\n[ \t]*",
            "",
            yaml_command_augmented(block_contents),
        )
        if OPAQUE_INLINE_SHELL.search(logical_contents) or (
            OPAQUE_ARM_CROSS_EXECUTION.search(logical_contents)
        ):
            sensitive_jobs.add(name)
            continue
        for logical_line in logical_scan_lines(logical_contents):
            for variant in scan_variants(
                logical_line,
                include_opaque_shell_executable=include_opaque_shell_executable,
            ):
                if has_cross_command_context(
                    variant,
                    include_opaque_shell_executable=include_opaque_shell_executable,
                ) or CROSS_ENVIRONMENT.search(variant):
                    sensitive_jobs.add(name)
                    break
            if name in sensitive_jobs:
                break

    top_level_surfaces: list[str] = []
    for index, line in enumerate(lines):
        line_surfaces: set[str] = set()
        if OPAQUE_INLINE_SHELL.search(line) or OPAQUE_ARM_CROSS_EXECUTION.search(
            line
        ):
            line_surfaces.add("opaque-inline-shell")
        for variant in scan_variants(
            line,
            include_opaque_shell_executable=include_opaque_shell_executable,
        ):
            normalized = re.sub(r"\s+", " ", variant).strip()
            if has_cross_command_context(
                variant,
                include_opaque_shell_executable=include_opaque_shell_executable,
            ):
                line_surfaces.add(f"executable:{normalized}")
            if CROSS_ENVIRONMENT.search(variant):
                line_surfaces.add(f"environment:{normalized}")
        if not line_surfaces:
            continue
        job_name_for_line = line_jobs[index]
        if job_name_for_line is None:
            top_level_surfaces.extend(sorted(line_surfaces))
        else:
            sensitive_jobs.add(job_name_for_line)

    job_surfaces = [
        f"job:{name}:{job_digests[name]}"
        for _, name in job_starts
        if name in sensitive_jobs
    ]
    return tuple([*top_level_surfaces, *job_surfaces]), []


def yaml_command_augmented(contents: str) -> str:
    """Append the shell text that YAML `run`/`shell` scalars actually produce.

    Raw-text scanning misses a folded (`run: >`) block whose executable and
    arguments live on different source lines. Appending only the folded scalars
    keeps the original text intact and leaves every other line scanned once.
    """

    try:
        scripts = workflow_command_scripts(contents, folded_only=True)
    except (RecursionError, ValueError):
        return contents
    if not scripts:
        return contents
    return "\n".join([contents, *scripts])


def generic_workflow_cross_surfaces(
    contents: str,
    source: str,
    *,
    include_opaque_shell_executable: bool = False,
) -> tuple[tuple[str, ...], list[str]]:
    """Scan a workflow that must not contain any Cross-controlled surface."""

    # Avoid imposing a YAML layout contract on unrelated workflows. As soon as
    # a Cross token is exposed, however, parse the job layout conservatively so
    # malformed, duplicate, and alias-shaped jobs fail closed.
    if not contains_cross_surface(
        yaml_command_augmented(contents),
        include_opaque_shell_executable=include_opaque_shell_executable,
    ):
        return (), []
    return unprotected_cross_surfaces(
        contents,
        source,
        "__no_unprotected_cross_job__",
        required_job=False,
        include_opaque_shell_executable=include_opaque_shell_executable,
    )


def validate_workflow_collection(
    workflows: dict[str, str],
    source: str,
) -> list[str]:
    """Reject Cross inputs in every workflow except the two hashed contracts."""

    errors: list[str] = []
    for name, contents in sorted(workflows.items()):
        if name in PROTECTED_WORKFLOW_FILENAMES:
            continue
        surfaces, failures = generic_workflow_cross_surfaces(
            contents,
            f"{source}/{name}",
        )
        errors.extend(failures)
        if surfaces:
            errors.append(
                f"{source}/{name} contains an unprotected Cross executable or "
                "configuration input"
            )
    return errors


def compare_pr_workflow_collection(
    merge_base_workflows: dict[str, str],
    proposed_workflows: dict[str, str],
    source: str,
) -> list[str]:
    """Permit safe workflow edits while rejecting new or changed Cross inputs."""

    errors: list[str] = []
    names = sorted(
        (set(merge_base_workflows) | set(proposed_workflows))
        - PROTECTED_WORKFLOW_FILENAMES
    )
    for name in names:
        baseline_contents = merge_base_workflows.get(name, "")
        proposed_contents = proposed_workflows.get(name, "")
        baseline_surfaces, baseline_failures = generic_workflow_cross_surfaces(
            baseline_contents,
            f"merge-base {source}/{name}",
            include_opaque_shell_executable=True,
        )
        proposed_surfaces, proposed_failures = generic_workflow_cross_surfaces(
            proposed_contents,
            f"proposed {source}/{name}",
            include_opaque_shell_executable=True,
        )
        errors.extend(baseline_failures)
        errors.extend(proposed_failures)
        if not baseline_failures and not proposed_failures:
            if baseline_surfaces != proposed_surfaces:
                errors.append(
                    f"{source}/{name} cannot add or change Cross executable/"
                    "configuration surfaces"
                )
    return errors


def generic_action_cross_surfaces(
    contents: str,
    *,
    name: str = "",
    include_opaque_shell_executable: bool = False,
) -> tuple[str, ...]:
    """Represent every Cross-sensitive local-action file by its full digest."""

    logical_contents = re.sub(r"\\\r?\n[ \t]*", "", yaml_command_augmented(contents))
    runtime_sensitive, runtime_errors = action_file_runtime_surface(
        name,
        contents,
        include_opaque_shell_executable=include_opaque_shell_executable,
    )
    sensitive = (
        runtime_sensitive
        or bool(runtime_errors)
        or OPAQUE_INLINE_SHELL.search(logical_contents) is not None
        or WRAPPED_LITERAL_CROSS.search(logical_contents) is not None
        or any(
            has_cross_command_context(
                variant,
                include_opaque_shell_executable=include_opaque_shell_executable,
            )
            or CROSS_ENVIRONMENT.search(variant)
            for line in logical_scan_lines(logical_contents)
            for variant in scan_variants(
                line,
                include_opaque_shell_executable=include_opaque_shell_executable,
            )
        )
    )
    if not sensitive:
        return ()
    digest = hashlib.sha256(contents.encode("utf-8")).hexdigest()
    return (f"file:{digest}",)


def contains_literal_executable_cross(contents: str) -> bool:
    """Recognize a literal Cross command or environment input in executable text."""

    logical_contents = re.sub(r"\\\r?\n[ \t]*", "", contents)
    return any(
        has_cross_command_context(variant) or CROSS_ENVIRONMENT.search(variant)
        for line in logical_scan_lines(logical_contents)
        for variant in scan_variants(
            line,
            include_opaque_shell_executable=False,
        )
    )


def is_dispatcher_manifest(name: str) -> bool:
    return PurePosixPath(name).name in DISPATCHER_MANIFEST_NAMES


def dispatcher_manifest_scripts(name: str, contents: str) -> tuple[str, ...]:
    """Return the shell text a repo build-dispatcher manifest can execute."""

    if PurePosixPath(name).name == "package.json":
        try:
            parsed = json.loads(contents)
        except json.JSONDecodeError:
            # An unparsable manifest is an unknown surface, so scan it whole.
            return (contents,)
        scripts = parsed.get("scripts") if isinstance(parsed, dict) else None
        if not isinstance(scripts, dict):
            return ()
        return tuple(value for value in scripts.values() if isinstance(value, str))
    # Make/just/task recipe lines are shell, but carry `@`, `-`, and `+` prefixes
    # that would otherwise sit between the command start and the executable.
    return (re.sub(r"(?m)^(\s+)[-@+]+", r"\1", contents),)


def dispatcher_manifest_cross_surface(name: str, contents: str) -> bool:
    """Return whether a dispatcher manifest recipe can execute Cross."""

    return any(
        contains_literal_executable_cross(script)
        or WRAPPED_LITERAL_CROSS.search(script)
        or OPAQUE_ARM_CROSS_EXECUTION.search(re.sub(r"\\\r?\n[ \t]*", "", script))
        for script in dispatcher_manifest_scripts(name, contents)
    )


def automation_file_cross_surfaces(name: str, contents: str) -> tuple[str, ...]:
    """Protect Cross tokens plus opaque Python process-dispatch files."""

    surfaces = list(
        generic_action_cross_surfaces(
            contents,
            name=name,
            include_opaque_shell_executable=True,
        )
    )
    if is_dispatcher_manifest(name) and dispatcher_manifest_cross_surface(
        name,
        contents,
    ):
        digest = hashlib.sha256(contents.encode("utf-8")).hexdigest()
        surfaces.append(f"dispatcher-manifest-cross:{digest}")
    language = automation_language(name, contents)
    if language == "python":
        process_commands, process_failures = python_command_scripts(
            contents,
            name,
            reject_dynamic_commands=True,
        )
        if process_failures:
            digest = hashlib.sha256(contents.encode("utf-8")).hexdigest()
            surfaces.append(f"opaque-python-process:{digest}")
        if any(
            contains_literal_executable_cross(command)
            for command in process_commands
        ):
            digest = hashlib.sha256(contents.encode("utf-8")).hexdigest()
            surfaces.append(f"literal-python-cross:{digest}")
    elif language == "unknown":
        digest = hashlib.sha256(contents.encode("utf-8")).hexdigest()
        surfaces.append(f"opaque-automation-interpreter:{digest}")
    elif name.endswith((".js", ".mjs", ".cjs", ".rb", ".lua")) and (
        NON_PYTHON_PROCESS_DISPATCH.search(contents)
    ):
        digest = hashlib.sha256(contents.encode("utf-8")).hexdigest()
        surfaces.append(f"opaque-non-python-process:{digest}")
    return tuple(surfaces)


def validate_action_collection(actions: dict[str, str], source: str) -> list[str]:
    """Reject Cross executable/configuration inputs in repo-local actions."""

    errors: list[str] = []
    for name, contents in sorted(actions.items()):
        if generic_action_cross_surfaces(contents, name=name):
            errors.append(
                f"{source}/{name} contains an unprotected Cross executable or "
                "configuration input"
            )
    return errors


def compare_pr_action_collection(
    merge_base_actions: dict[str, str],
    proposed_actions: dict[str, str],
    source: str,
) -> list[str]:
    """Permit benign local-action edits while freezing Cross-sensitive files."""

    errors: list[str] = []
    for name in sorted(set(merge_base_actions) | set(proposed_actions)):
        baseline_surfaces = automation_file_cross_surfaces(
            name,
            merge_base_actions.get(name, ""),
        )
        proposed_surfaces = automation_file_cross_surfaces(
            name,
            proposed_actions.get(name, ""),
        )
        if baseline_surfaces != proposed_surfaces:
            errors.append(
                f"{source}/{name} cannot add or change Cross executable/"
                "configuration surfaces"
            )
    return errors


def normalize_repository_path(raw: str) -> str | None:
    variable_prefix = re.match(
        r"^\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[A-Za-z_][A-Za-z0-9_]*\})/",
        raw,
    )
    if variable_prefix is not None:
        return None
    value = raw[2:] if raw.startswith("./") else raw
    candidate = PurePosixPath(value)
    if (
        not value
        or candidate.is_absolute()
        or any(part in {"", ".", ".."} for part in candidate.parts)
    ):
        return None
    return candidate.as_posix()


def repository_command_line(line: str) -> str:
    """Reduce only the trusted workspace expression to its repository-relative form."""

    return re.sub(
        r"\$\{\{\s*github\.workspace\s*\}\}/?",
        "",
        line,
        flags=re.IGNORECASE,
    )


def shell_command_lines(contents: str) -> tuple[str, ...]:
    """Return shell command lines while excluding literal here-document data."""

    logical_contents = re.sub(r"\\\r?\n[ \t]*", "", contents)
    commands: list[str] = []
    heredoc_delimiter: str | None = None
    for line in logical_contents.splitlines():
        if heredoc_delimiter is not None:
            if line.strip() == heredoc_delimiter:
                heredoc_delimiter = None
            continue
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        commands.append(line)
        heredoc = HEREDOC_START.search(line)
        if heredoc is not None:
            heredoc_delimiter = heredoc.group("delimiter")
    return tuple(commands)


def folded_block_text(lines: list[str]) -> str:
    """Join a YAML folded scalar the way the shell finally receives it.

    Blank lines separate paragraphs; every other run of lines collapses to one
    command line. More-indented lines are folded too, which can only expose an
    additional command word and never hide one.
    """

    paragraphs: list[str] = []
    current: list[str] = []
    for line in lines:
        if line.strip():
            current.append(line.strip())
            continue
        if current:
            paragraphs.append(" ".join(current))
            current = []
    if current:
        paragraphs.append(" ".join(current))
    return "\n".join(paragraphs)


def yaml_command_fields(
    contents: str,
) -> tuple[tuple[int, int, bool, str, str, str], ...]:
    """Extract run/shell scalar metadata without evaluating hostile YAML."""

    lines = contents.splitlines()
    fields: list[tuple[int, int, bool, str, str, str]] = []
    index = 0
    while index < len(lines):
        match = YAML_RUN_FIELD.match(lines[index])
        if match is None:
            index += 1
            continue
        line_number = index
        field_indent = len(match.group("indent"))
        sequence_field = lines[index][field_indent:].startswith("-")
        mapping_indent = field_indent + (2 if sequence_field else 0)
        key = match.group("key").strip("'\"")
        value = match.group("value").strip()
        if BLOCK_SCALAR_HEADER.fullmatch(value) is None:
            if len(value) >= 2 and value[0] == value[-1] == "'":
                value = value[1:-1].replace("''", "'")
            elif len(value) >= 2 and value[0] == value[-1] == '"':
                try:
                    decoded = json.loads(value)
                except json.JSONDecodeError:
                    decoded = value
                if isinstance(decoded, str):
                    value = decoded
            fields.append(
                (line_number, field_indent, sequence_field, key, value, value)
            )
            index += 1
            continue

        indent_header = re.match(
            r"^[|>](?:(?P<leading>[1-9])[+-]?|[+-](?P<trailing>[1-9])?)?",
            value,
        )
        indent_digit = (
            indent_header.group("leading") or indent_header.group("trailing")
            if indent_header is not None
            else None
        )
        explicit_indent = (
            field_indent + int(indent_digit) if indent_digit is not None else None
        )
        block: list[str] = []
        index += 1
        while index < len(lines):
            line = lines[index]
            if line.strip():
                indentation = len(line) - len(line.lstrip(" "))
                if (
                    explicit_indent is not None
                    and indentation < explicit_indent
                ) or (
                    explicit_indent is None
                    and indentation <= mapping_indent
                ):
                    break
                block.append(line)
            else:
                block.append("")
            index += 1
        nonblank_indents = [
            len(line) - len(line.lstrip(" ")) for line in block if line.strip()
        ]
        block_indent = explicit_indent or min(
            nonblank_indents,
            default=mapping_indent + 2,
        )
        dedented = [line[block_indent:] if line.strip() else "" for line in block]
        literal = "\n".join(dedented)
        rendered = folded_block_text(dedented) if value.startswith(">") else literal
        fields.append(
            (line_number, field_indent, sequence_field, key, literal, rendered)
        )
    return tuple(fields)


def workflow_command_scripts(
    contents: str,
    *,
    folded_only: bool = False,
) -> tuple[str, ...]:
    """Extract literal run and shell scalars from workflows and actions.

    With `folded_only`, return just the folded (`run: >`) blocks rendered the
    way YAML joins them. Those are the only scalars whose text differs from the
    raw source, so scanning them adds coverage without rescanning everything.
    """

    scripts: list[str] = []
    folded_scripts: list[str] = []
    for _, _, _, _, literal, rendered in yaml_command_fields(contents):
        scripts.append(literal)
        if rendered != literal:
            # A folded scalar joins successive lines with a space before the
            # shell ever sees them, so `cross` on one line and its `--target`
            # arguments on the next are a single command.
            folded_scripts.append(rendered)
    return tuple(folded_scripts if folded_only else scripts)


def interpreter_kind(words: tuple[str, ...] | None) -> str | None:
    """Classify a literal interpreter command as shell, Python, or unknown."""

    if not words:
        return None
    index = 0
    if tool_name(words[index]) == "env":
        index += 1
        while index < len(words):
            word = words[index]
            if word == "--":
                index += 1
                break
            if word == "-S":
                # shlex has already split the `env -S` string for the static
                # command forms accepted here.
                index += 1
                break
            if word in {"-C", "-u", "--chdir", "--unset"}:
                index += 2
                continue
            if word == "-" or word.startswith("-") or re.fullmatch(
                r"[A-Za-z_][A-Za-z0-9_]*=.*", word, re.DOTALL
            ):
                index += 1
                continue
            break
    if index >= len(words) or dynamic_shell_word(words[index]):
        return None
    executable = tool_name(words[index])
    if executable in SHELL_INTERPRETER_NAMES:
        return "shell"
    if PYTHON_INTERPRETER.fullmatch(executable):
        return "python"
    return None


def automation_language(name: str, contents: str) -> str | None:
    """Classify automation by a robust shebang first, then a known suffix."""

    first_line = contents.splitlines()[0] if contents.splitlines() else ""
    if first_line.startswith("#!"):
        words = shell_tokens(first_line[2:].strip())
        return interpreter_kind(words) or "unknown"
    suffix = PurePosixPath(name).suffix.lower()
    if suffix == ".py":
        return "python"
    if suffix in {".bash", ".sh"}:
        return "shell"
    return None


def action_run_programs(
    contents: str,
    source: str,
) -> tuple[list[tuple[str, str]], list[str]]:
    """Associate each composite-action run scalar with its sibling shell."""

    lines = contents.splitlines()
    fields = yaml_command_fields(contents)

    def step_start(line_number: int, field_indent: int) -> tuple[int, int] | None:
        for candidate in range(line_number, -1, -1):
            match = re.match(r"^(?P<indent> *)-\s+", lines[candidate])
            if match is None:
                continue
            indent = len(match.group("indent"))
            if indent <= field_indent:
                return candidate, indent
        return None

    grouped: dict[tuple[int, int], list[tuple[str, str]]] = {}
    for line_number, field_indent, _, key, _, rendered in fields:
        step = step_start(line_number, field_indent)
        if step is not None:
            grouped.setdefault(step, []).append((key, rendered))

    programs: list[tuple[str, str]] = []
    errors: list[str] = []
    for step, step_fields in sorted(grouped.items()):
        run_values = [value for key, value in step_fields if key == "run"]
        if not run_values:
            continue
        shell_values = [value for key, value in step_fields if key == "shell"]
        if len(run_values) != 1 or len(shell_values) != 1:
            errors.append(
                f"{source}:{step[0] + 1} composite run steps require exactly one "
                "literal run and shell scalar"
            )
            continue
        language = interpreter_kind(shell_tokens(shell_values[0]))
        if language is None:
            errors.append(
                f"{source}:{step[0] + 1} uses an unsupported or dynamic action shell"
            )
            continue
        programs.append((language, run_values[0]))
    return programs, errors


def dockerfile_programs(
    contents: str,
    source: str,
) -> tuple[list[tuple[str, str]], list[str]]:
    """Extract executable Dockerfile instructions under the active SHELL."""

    logical_lines: list[str] = []
    pending = ""
    for physical in contents.splitlines():
        stripped = physical.rstrip()
        pending += stripped[:-1] + " " if stripped.endswith("\\") else stripped
        if stripped.endswith("\\"):
            continue
        logical_lines.append(pending)
        pending = ""
    if pending:
        logical_lines.append(pending)

    programs: list[tuple[str, str]] = []
    errors: list[str] = []
    run_language = "shell"
    for line_number, line in enumerate(logical_lines, start=1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = re.match(
            r"^\s*(?P<instruction>RUN|CMD|ENTRYPOINT|SHELL)\s+(?P<body>.*)$",
            line,
            re.IGNORECASE,
        )
        if match is None:
            continue
        instruction = match.group("instruction").upper()
        body = match.group("body").strip()
        parsed_words: tuple[str, ...] | None = None
        if body.startswith("["):
            try:
                parsed = json.loads(body)
            except json.JSONDecodeError:
                errors.append(f"{source}:{line_number} has malformed JSON instruction")
                continue
            if not isinstance(parsed, list) or not all(
                isinstance(item, str) for item in parsed
            ):
                errors.append(
                    f"{source}:{line_number} JSON instruction must be a string array"
                )
                continue
            parsed_words = tuple(parsed)

        if instruction == "SHELL":
            run_language = interpreter_kind(parsed_words) or "unknown"
            if run_language == "unknown":
                errors.append(
                    f"{source}:{line_number} selects an unsupported Dockerfile shell"
                )
            continue

        if instruction == "RUN":
            while body.startswith("--"):
                option, separator, remainder = body.partition(" ")
                if not separator or "=" not in option:
                    break
                body = remainder.lstrip()
            if parsed_words is None:
                if run_language == "unknown":
                    errors.append(
                        f"{source}:{line_number} runs through an unsupported shell"
                    )
                else:
                    programs.append((run_language, body))
                continue

        if parsed_words is not None:
            language = interpreter_kind(parsed_words)
            if language == "python" and "-c" in parsed_words:
                command_index = parsed_words.index("-c") + 1
                if command_index < len(parsed_words):
                    programs.append(("python", parsed_words[command_index]))
                    continue
            programs.append(
                ("shell", " ".join(shlex.quote(word) for word in parsed_words))
            )
        else:
            programs.append(("shell", body))
    return programs, errors


def executable_heredocs(contents: str) -> tuple[tuple[str, str], ...]:
    """Return heredoc programs consumed by a literal shell or Python command."""

    programs: list[tuple[str, str]] = []
    delimiter: str | None = None
    interpreter: str | None = None
    body: list[str] = []
    for line in contents.splitlines():
        if delimiter is not None:
            if line.strip() == delimiter:
                if interpreter is not None:
                    programs.append((interpreter, "\n".join(body) + "\n"))
                delimiter = None
                interpreter = None
                body = []
            else:
                body.append(line)
            continue

        heredoc = HEREDOC_START.search(line)
        if heredoc is None:
            continue
        delimiter = heredoc.group("delimiter")
        interpreters = [
            match.group("interpreter") for match in HEREDOC_EXECUTABLE.finditer(line)
        ]
        interpreter = interpreters[-1] if interpreters else None
    return tuple(programs)


DYNAMIC_DISPATCH_NAMES = frozenset(
    {
        "__import__",
        "compile",
        "eval",
        "exec",
        "getattr",
        "globals",
        "locals",
        "vars",
    }
)


def literal_string(node: ast.expr) -> str | None:
    """Fold a statically known Python string, including split constructions.

    `'cr' + 'oss'`, an f-string with no substitutions, and `''.join([...])` all
    denote a constant executable name, so they must resolve rather than being
    treated as opaque and skipped.
    """

    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = literal_string(node.left)
        right = literal_string(node.right)
        return None if left is None or right is None else left + right
    if isinstance(node, ast.JoinedStr):
        parts = [literal_string(value) for value in node.values]
        return None if any(part is None for part in parts) else "".join(parts)
    if (
        isinstance(node, ast.FormattedValue)
        and node.conversion in (-1, ord("s"))
        and node.format_spec is None
    ):
        return literal_string(node.value)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "join"
        and len(node.args) == 1
        and isinstance(node.args[0], (ast.List, ast.Tuple))
    ):
        separator = literal_string(node.func.value)
        elements = [literal_string(element) for element in node.args[0].elts]
        if separator is None or any(element is None for element in elements):
            return None
        return separator.join(elements)
    return None


def shell_argv_reads_stdin_program(words: tuple[str, ...]) -> bool:
    """Return whether a literal process argv makes a shell execute stdin."""

    if not words or tool_name(words[0]) not in SHELL_INTERPRETER_NAMES:
        return False
    for argument in words[1:]:
        if argument.startswith("-"):
            if "c" in argument.lstrip("-"):
                return False
            continue
        # A non-option operand names a script; bare shells and `-s` consume code
        # from stdin instead.
        return False
    return True


def python_command_scripts(
    contents: str,
    source: str,
    *,
    reject_dynamic_commands: bool = False,
) -> tuple[list[str], list[str]]:
    """Extract literal commands passed to standard Python process APIs."""

    try:
        tree = ast.parse(contents)
    except SyntaxError as error:
        return [], [f"{source} cannot be parsed as Python: {error}"]

    commands: list[str] = []
    errors: list[str] = []
    process_calls = {
        "os.execl",
        "os.execle",
        "os.execlp",
        "os.execlpe",
        "os.execv",
        "os.execve",
        "os.execvp",
        "os.execvpe",
        "os.popen",
        "os.spawnl",
        "os.spawnle",
        "os.spawnlp",
        "os.spawnlpe",
        "os.spawnv",
        "os.spawnve",
        "os.spawnvp",
        "os.spawnvpe",
        "os.system",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.Popen",
        "subprocess.run",
        "subprocess.getoutput",
        "subprocess.getstatusoutput",
        "os.posix_spawn",
        "os.posix_spawnp",
    }
    imported_names: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in {"os", "subprocess"}:
                    imported_names[alias.asname or alias.name] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module in {"os", "subprocess"}:
            for alias in node.names:
                imported_names[alias.asname or alias.name] = (
                    f"{node.module}.{alias.name}"
                )

    def static_name(node: ast.expr) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = static_name(node.value)
            return f"{parent}.{node.attr}" if parent is not None else None
        return None

    def resolve_import_alias(raw: str | None) -> str | None:
        if raw is None:
            return None
        parts = raw.split(".", 1)
        head = imported_names.get(parts[0], parts[0])
        return f"{head}.{parts[1]}" if len(parts) == 2 else head

    def call_name(node: ast.expr) -> str | None:
        """Resolve a callee, including literal dynamic import/attribute lookup."""

        if isinstance(node, (ast.Name, ast.Attribute)) and not isinstance(
            getattr(node, "value", None), ast.Call
        ):
            return static_name(node)
        if isinstance(node, ast.Attribute):
            parent = call_name(node.value)
            return f"{parent}.{node.attr}" if parent is not None else None
        if isinstance(node, ast.Call):
            inner = static_name(node.func)
            if inner == "__import__" or (
                inner is not None and inner.endswith("import_module")
            ):
                return literal_string(node.args[0]) if node.args else None
            if inner == "getattr" and len(node.args) >= 2:
                base = call_name(node.args[0])
                attribute = literal_string(node.args[1])
                if base is not None and attribute is not None:
                    return f"{base}.{attribute}"
            return None
        return None

    def dynamic_dispatch_root(node: ast.expr) -> str | None:
        """Name the dynamic primitive that selects an unresolvable callee."""

        if isinstance(node, (ast.Attribute, ast.Subscript)):
            return dynamic_dispatch_root(node.value)
        if isinstance(node, ast.Call):
            inner = static_name(node.func)
            if inner in DYNAMIC_DISPATCH_NAMES or (
                inner is not None and inner.endswith("import_module")
            ):
                return inner
            return dynamic_dispatch_root(node.func)
        return None

    def references_process_module(node: ast.expr) -> bool:
        for descendant in ast.walk(node):
            if isinstance(descendant, ast.Name) and imported_names.get(
                descendant.id, descendant.id
            ) in {"os", "subprocess"}:
                return True
            if isinstance(descendant, ast.Call) and static_name(
                descendant.func
            ) == "__import__" and descendant.args:
                if literal_string(descendant.args[0]) in {"os", "subprocess"}:
                    return True
        return False

    # `run = subprocess.run` and `sp = subprocess` reach exactly the same
    # process API as a direct call, so a local alias must resolve to what it
    # names instead of being skipped as an unknown local variable. Chained
    # aliases settle in a bounded number of passes.
    opaque_process_aliases: set[str] = set()
    for _ in range(8):
        rebound = False
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign) or len(node.targets) != 1:
                continue
            target = node.targets[0]
            if not isinstance(target, ast.Name):
                continue
            aliased = resolve_import_alias(call_name(node.value))
            if aliased is None or aliased == target.id:
                if (
                    dynamic_dispatch_root(node.value) is not None
                    and references_process_module(node.value)
                ):
                    opaque_process_aliases.add(target.id)
                continue
            if aliased not in process_calls and aliased not in {"os", "subprocess"}:
                continue
            if imported_names.get(target.id) != aliased:
                imported_names[target.id] = aliased
                opaque_process_aliases.discard(target.id)
                rebound = True
        if not rebound:
            break

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        raw_name = call_name(node.func)
        if raw_name is None:
            # A callee chosen through dynamic import or attribute lookup can
            # reach any process API, so it is an unknown executable surface.
            primitive = dynamic_dispatch_root(node.func)
            if primitive is not None:
                errors.append(
                    f"{source} must not dispatch calls through dynamic "
                    f"import or attribute lookup ({primitive})"
                )
            continue
        name_parts = raw_name.split(".", 1)
        if name_parts[0] in opaque_process_aliases:
            errors.append(
                f"{source} calls an opaque dynamically selected process API "
                f"({name_parts[0]})"
            )
            continue
        resolved_name = imported_names.get(name_parts[0], name_parts[0])
        if len(name_parts) == 2:
            resolved_name = f"{resolved_name}.{name_parts[1]}"
        if resolved_name not in process_calls:
            continue
        if any(isinstance(argument, ast.Starred) for argument in node.args) or any(
            keyword.arg is None for keyword in node.keywords
        ):
            errors.append(
                f"{source} process calls must not expand positional or keyword "
                "arguments"
            )
            continue
        positional_index = 1 if resolved_name.startswith("os.spawn") else 0
        command: ast.expr | None = (
            node.args[positional_index]
            if len(node.args) > positional_index
            else None
        )
        command_from_keyword = False
        if command is None:
            if resolved_name.startswith("subprocess."):
                keyword_names = {"args"}
            elif resolved_name == "os.system":
                keyword_names = {"command"}
            elif resolved_name == "os.popen":
                keyword_names = {"cmd"}
            else:
                keyword_names = {"file", "path"}
            command = next(
                (
                    keyword.value
                    for keyword in node.keywords
                    if keyword.arg in keyword_names
                ),
                None,
            )
            command_from_keyword = command is not None

        command_text: str | None = None
        command_words: tuple[str, ...] | None = None
        if command is not None:
            command_text = literal_string(command)
            if command_text is None and isinstance(command, (ast.List, ast.Tuple)):
                elements = [literal_string(element) for element in command.elts]
                if all(element is not None for element in elements):
                    command_words = tuple(
                        element for element in elements if element is not None
                    )
                    command_text = " ".join(command_words)
            elif command_text is not None and not re.search(r"\s", command_text):
                command_words = (command_text,)

        # `subprocess.run(['build', ...], executable='cross')` runs `cross` even
        # though the executable never appears in `args`, so the override is the
        # command word that must be inspected.
        override: str | None = None
        override_opaque = False
        if resolved_name.startswith("subprocess."):
            executable = next(
                (
                    keyword.value
                    for keyword in node.keywords
                    if keyword.arg == "executable"
                ),
                None,
            )
            if executable is not None:
                override = literal_string(executable)
                override_opaque = override is None
        if override is not None:
            # Keep an argument word even when the positional args are opaque so
            # the override is still recognized as an executable, not a bare noun.
            commands.append(f"{override} {command_text or '${ARGS}'}")
        elif override_opaque and reject_dynamic_commands:
            errors.append(f"{source} has an opaque process executable override")

        if command is None:
            if reject_dynamic_commands and override is None:
                errors.append(f"{source} has an opaque process command")
            continue
        if command_text is not None:
            commands.append(command_text)
        elif command_from_keyword:
            errors.append(
                f"{source} keyword process commands must be literal strings or "
                "string arrays"
            )
        elif reject_dynamic_commands:
            errors.append(f"{source} has an opaque process command")

        process_input = next(
            (
                keyword.value
                for keyword in node.keywords
                if keyword.arg == "input"
            ),
            None,
        )
        if process_input is not None and command_words is not None and (
            shell_argv_reads_stdin_program(command_words)
        ):
            input_text = literal_string(process_input)
            if input_text is not None:
                commands.append(input_text)
            elif reject_dynamic_commands:
                errors.append(f"{source} has opaque shell process input")
    return commands, errors


def runtime_program_cross_surface(
    programs: list[tuple[str, str]],
    source: str,
    *,
    include_opaque_shell_executable: bool,
) -> tuple[bool, list[str]]:
    """Inspect programs after their actual action/Docker interpreter is known."""

    sensitive = False
    errors: list[str] = []
    for language, program in programs:
        if language == "shell":
            if shell_program_has_cross(
                program,
                include_opaque_shell_executable=include_opaque_shell_executable,
            ) or OPAQUE_ARM_CROSS_EXECUTION.search(program):
                sensitive = True
            continue
        if language == "python":
            commands, failures = python_command_scripts(
                program,
                source,
                reject_dynamic_commands=include_opaque_shell_executable,
            )
            errors.extend(failures)
            if any(contains_literal_executable_cross(command) for command in commands):
                sensitive = True
            continue
        errors.append(f"{source} uses an unsupported executable interpreter")
    return sensitive, errors


def action_file_runtime_surface(
    name: str,
    contents: str,
    *,
    include_opaque_shell_executable: bool,
) -> tuple[bool, list[str]]:
    """Inspect composite run interpreters and Docker action Dockerfiles."""

    basename = PurePosixPath(name).name.lower()
    if basename in {"action.yaml", "action.yml"}:
        programs, errors = action_run_programs(contents, name)
        if re.search(
            r"(?m)^\s*using\s*:\s*['\"]?docker['\"]?\s*(?:#.*)?$",
            contents,
        ):
            images = re.findall(
                r"(?m)^\s*image\s*:\s*['\"]?([^\s'\"#]+)['\"]?\s*(?:#.*)?$",
                contents,
            )
            image_path = PurePosixPath(images[0]) if len(images) == 1 else None
            if (
                image_path is None
                or image_path.is_absolute()
                or any(part in {"", ".", ".."} for part in image_path.parts)
                or images[0].startswith("docker://")
                or dynamic_shell_word(images[0])
            ):
                errors.append(
                    f"{name} Docker actions require one literal repository Dockerfile"
                )
    elif (
        basename == "dockerfile"
        or basename.startswith("dockerfile.")
        or re.search(r"(?im)^\s*(?:ARG|FROM)\s+", contents)
    ):
        programs, errors = dockerfile_programs(contents, name)
    else:
        return False, []
    sensitive, program_errors = runtime_program_cross_surface(
        programs,
        name,
        include_opaque_shell_executable=include_opaque_shell_executable,
    )
    return sensitive, [*errors, *program_errors]


def automation_command_scripts(
    contents: str,
    source: str,
    *,
    workflow_source: bool,
) -> tuple[list[str], list[str]]:
    if workflow_source:
        return list(workflow_command_scripts(contents)), []
    if is_dispatcher_manifest(source):
        # Recipes are shell, so a manifest can chain into scripts and further
        # dispatchers exactly like any other reached automation file.
        return list(dispatcher_manifest_scripts(source, contents)), []
    language = automation_language(source, contents)
    if language == "python":
        return python_command_scripts(contents, source)
    if language == "shell":
        return [contents], []
    if language == "unknown" or contents.startswith("#!"):
        return [], [f"{source} has an unsupported executable shebang"]
    return [], [f"{source} is executable automation with no scannable interpreter"]


def local_automation_references(
    contents: str,
    source: str,
    *,
    workflow_source: bool,
) -> tuple[set[str], set[str], list[str]]:
    """Collect canonical repo scripts and reject unscanned local actions/commands.

    Returns the literal script references, the build-dispatcher manifest
    candidate groups (`"Makefile|makefile|GNUmakefile"`), and any failures.
    """

    references: set[str] = set()
    dispatcher_groups: set[str] = set()
    errors: list[str] = []
    if workflow_source:
        for line_number, line in enumerate(contents.splitlines(), start=1):
            command_field = YAML_RUN_FIELD.match(line)
            if command_field is not None:
                command_value = command_field.group("value").strip()
                command_key = command_field.group("key").strip("'\"")
                if command_value.startswith(("|", ">")) and (
                    BLOCK_SCALAR_HEADER.fullmatch(command_value) is None
                ):
                    errors.append(
                        f"{source}:{line_number} has a malformed YAML block-scalar "
                        "header"
                    )
                if command_key == "shell" and (
                    github_expression_spans(command_value)
                    or SHELL_INTERPOLATION.search(command_value)
                    or "`" in command_value
                ):
                    errors.append(
                        f"{source}:{line_number} shell templates must be literal"
                    )
            if YAML_DYNAMIC_COMMAND_FIELD.search(line):
                errors.append(
                    f"{source}:{line_number} run and shell commands must not use YAML "
                    "tags, anchors, or aliases"
                )
            if YAML_DYNAMIC_USES_FIELD.search(line):
                errors.append(
                    f"{source}:{line_number} action references must not use YAML "
                    "tags, anchors, or aliases"
                )
            if not LOCAL_ACTION_CANDIDATE.search(line):
                continue
            match = LOCAL_ACTION_REFERENCE.search(line)
            if match is None:
                errors.append(
                    f"{source}:{line_number} has a non-canonical local action reference"
                )
            else:
                action_path = normalize_repository_path(match.group("path"))
                if action_path is None or not action_path.startswith(
                    ".github/actions/"
                ):
                    errors.append(
                        f"{source}:{line_number} local actions must be under "
                        ".github/actions"
                    )

    command_scripts, command_failures = automation_command_scripts(
        contents,
        source,
        workflow_source=workflow_source,
    )
    errors.extend(command_failures)
    for command_script in command_scripts:
        pending_programs: list[tuple[str, str]] = [("shell", command_script)]
        command_lines: list[str] = []
        while pending_programs:
            language, program = pending_programs.pop()
            if language in {"python", "python3"}:
                python_commands, python_failures = python_command_scripts(
                    program,
                    f"{source} executable heredoc",
                )
                errors.extend(python_failures)
                pending_programs.extend(
                    ("shell", command) for command in python_commands
                )
                continue
            command_lines.extend(shell_command_lines(program))
            pending_programs.extend(executable_heredocs(program))

        working_directory: str | None = ""
        for line_number, line in enumerate(command_lines, start=1):
            normalized_line = repository_command_line(line)
            for directory_match in CD_COMMAND.finditer(normalized_line):
                directory = normalize_repository_path(directory_match.group("path"))
                working_directory = directory

            for match in LOCAL_COMMAND_REFERENCE.finditer(normalized_line):
                raw_command_path = (
                    match.group("redirected")
                    or match.group("interpreted")
                    or match.group("direct")
                    or match.group("bare")
                )
                if raw_command_path.endswith("/"):
                    continue
                command_path = normalize_repository_path(raw_command_path)
                if command_path is None:
                    errors.append(
                        f"{source}:{line_number} has a non-canonical repository command"
                    )
                    continue
                if command_path in GENERATED_COMMAND_PATHS:
                    continue
                if "/" not in command_path and working_directory:
                    command_path = (
                        PurePosixPath(working_directory) / command_path
                    ).as_posix()
                if command_path in GENERATED_COMMAND_PATHS:
                    continue
                if command_path.startswith(GENERATED_SCRIPT_PREFIXES):
                    continue
                if command_path.startswith(APPROVED_AUTOMATION_ROOTS):
                    references.add(command_path)
                else:
                    errors.append(
                        f"{source}:{line_number} repository command {command_path!r} "
                        "is outside the scanned automation roots"
                    )

            for match in BUILD_DISPATCHER.finditer(normalized_line):
                arguments = match.group("arguments")
                dispatcher = match.group("dispatcher")
                base = working_directory or ""
                directory = DISPATCHER_DIRECTORY.search(arguments)
                if directory is not None:
                    relocated = normalize_repository_path(directory.group("path"))
                    if relocated is None:
                        errors.append(
                            f"{source}:{line_number} build dispatcher directory "
                            f"{directory.group('path')!r} is not a repository path"
                        )
                        continue
                    base = relocated

                workspace_matches = list(DISPATCHER_WORKSPACE.finditer(arguments))
                workspace_options = list(
                    DISPATCHER_WORKSPACE_OPTION.finditer(arguments)
                )
                if DISPATCHER_ALL_WORKSPACES.search(arguments):
                    errors.append(
                        f"{source}:{line_number} build dispatcher must select one "
                        "literal workspace manifest"
                    )
                    continue
                if len(workspace_options) != len(workspace_matches) or len(
                    workspace_matches
                ) > 1:
                    errors.append(
                        f"{source}:{line_number} build dispatcher workspace "
                        "selectors must resolve to one literal directory"
                    )
                    continue
                workspace = workspace_matches[0] if workspace_matches else None
                if workspace is not None:
                    if dispatcher not in {"npm", "pnpm", "yarn"}:
                        errors.append(
                            f"{source}:{line_number} unsupported workspace selector "
                            f"for {dispatcher}"
                        )
                        continue
                    workspace_path = workspace.group("path")
                    relocated = normalize_repository_path(workspace_path)
                    if (
                        relocated is None
                        or dynamic_shell_word(workspace_path)
                        or relocated == "package.json"
                    ):
                        errors.append(
                            f"{source}:{line_number} build dispatcher workspace "
                            f"{workspace_path!r} is not a literal repository directory"
                        )
                        continue
                    base = relocated

                explicit = DISPATCHER_MANIFEST_OPTION.search(arguments)
                if explicit is not None:
                    manifest = normalize_repository_path(explicit.group("path"))
                    if manifest is None:
                        errors.append(
                            f"{source}:{line_number} build dispatcher manifest "
                            f"{explicit.group('path')!r} is not a repository path"
                        )
                        continue
                    names: tuple[str, ...] = (manifest,)
                else:
                    names = DISPATCHER_MANIFESTS[dispatcher]
                candidates = tuple(
                    (PurePosixPath(base) / name).as_posix() if base else name
                    for name in names
                )
                dispatcher_groups.add("|".join(candidates))
    return references, dispatcher_groups, errors


def reachable_automation_references(
    sources: dict[str, str],
    automation: dict[str, str],
    label: str,
) -> tuple[set[str], list[str]]:
    """Follow literal repo-script execution edges from workflows and actions."""

    reachable: set[str] = set()
    errors: list[str] = []
    pending: list[str] = []

    def follow_dispatchers(groups: set[str], origin: str) -> None:
        """Resolve each dispatcher to whichever of its manifests exists."""

        for group in sorted(groups):
            candidates = group.split("|")
            present = [name for name in candidates if name in automation]
            if present:
                pending.extend(present)
                continue
            errors.append(
                f"{origin} runs a repository build dispatcher whose manifest "
                f"({candidates[0]!r}) is missing from the scanned automation "
                "roots"
            )

    for name, contents in sorted(sources.items()):
        references, dispatchers, failures = local_automation_references(
            contents,
            f"{label}/{name}",
            workflow_source=True,
        )
        errors.extend(failures)
        pending.extend(sorted(references))
        follow_dispatchers(dispatchers, f"{label}/{name}")

    while pending:
        name = pending.pop()
        if name in reachable:
            continue
        reachable.add(name)
        contents = automation.get(name)
        if contents is None:
            errors.append(f"{label} references missing automation file {name!r}")
            continue
        references, dispatchers, failures = local_automation_references(
            contents,
            f"{label}/{name}",
            workflow_source=False,
        )
        errors.extend(failures)
        pending.extend(sorted(references - reachable))
        follow_dispatchers(dispatchers, f"{label}/{name}")
    return reachable, errors


def validate_automation_collection(
    workflows: dict[str, str],
    actions: dict[str, str],
    automation: dict[str, str],
    source: str,
) -> list[str]:
    sources = {
        **{f"workflows/{name}": contents for name, contents in workflows.items()},
        **{f"actions/{name}": contents for name, contents in actions.items()},
    }
    reachable, errors = reachable_automation_references(sources, automation, source)
    for name in sorted(reachable):
        contents = automation.get(name)
        language = automation_language(name, contents) if contents is not None else None
        if (
            contents is not None
            and language == "shell"
            and (
                contains_literal_executable_cross(contents)
                or WRAPPED_LITERAL_CROSS.search(contents)
                # An executable word assembled from shell expansions is opaque,
                # so an ARM64 cross build driven by one fails closed here too.
                or OPAQUE_ARM_CROSS_EXECUTION.search(
                    re.sub(r"\\\r?\n[ \t]*", "", contents)
                )
            )
        ):
            errors.append(
                f"{source}/{name} contains an unprotected Cross executable or "
                "generated inline shell surface"
            )
        elif (
            contents is not None
            and is_dispatcher_manifest(name)
            and dispatcher_manifest_cross_surface(name, contents)
        ):
            errors.append(
                f"{source}/{name} contains an unprotected Cross executable in a "
                "build-dispatcher recipe"
            )
        elif contents is not None and language == "python":
            process_commands, process_failures = python_command_scripts(
                contents,
                f"{source}/{name}",
            )
            errors.extend(process_failures)
            if any(
                contains_literal_executable_cross(command)
                for command in process_commands
            ):
                errors.append(
                    f"{source}/{name} contains an unprotected literal Python "
                    "Cross process call"
                )
    return errors


def compare_pr_automation_collection(
    merge_base_workflows: dict[str, str],
    proposed_workflows: dict[str, str],
    merge_base_actions: dict[str, str],
    proposed_actions: dict[str, str],
    merge_base_automation: dict[str, str],
    proposed_automation: dict[str, str],
    source: str,
) -> list[str]:
    """Reject new Cross surfaces in transitively invoked repository scripts."""

    baseline_sources = {
        **{
            f"workflows/{name}": contents
            for name, contents in merge_base_workflows.items()
        },
        **{f"actions/{name}": contents for name, contents in merge_base_actions.items()},
    }
    proposed_sources = {
        **{f"workflows/{name}": contents for name, contents in proposed_workflows.items()},
        **{f"actions/{name}": contents for name, contents in proposed_actions.items()},
    }
    _, baseline_errors = reachable_automation_references(
        baseline_sources,
        merge_base_automation,
        f"merge-base {source}",
    )
    _, proposed_errors = reachable_automation_references(
        proposed_sources,
        proposed_automation,
        f"proposed {source}",
    )
    errors = [*baseline_errors, *proposed_errors]
    if errors:
        return errors

    # Compare every file in the narrowly approved automation roots. This also
    # covers scripts selected through an existing trusted variable or sourced
    # transitively without freezing files whose Cross surface remains empty.
    for name in sorted(set(merge_base_automation) | set(proposed_automation)):
        baseline_surfaces = automation_file_cross_surfaces(
            name,
            merge_base_automation.get(name, ""),
        )
        proposed_surfaces = automation_file_cross_surfaces(
            name,
            proposed_automation.get(name, ""),
        )
        if baseline_surfaces != proposed_surfaces:
            errors.append(
                f"{source}/{name} cannot add or change Cross executable/"
                "configuration surfaces"
            )
    return errors


def validate_ci_planner_isolation(contents: str, source: str) -> list[str]:
    """Require every trusted planner execution to use isolated Python."""

    block, failures = extract_job_block(contents, source, "ci-plan", required=True)
    if failures:
        return failures
    assert block is not None
    logical = re.sub(r"\\\r?\n[ \t]*", " ", block)
    invocations = [
        line
        for line in logical.splitlines()
        if "$planner" in line and re.search(r"\bpython3\b", line)
    ]
    errors: list[str] = []
    if len(invocations) != 2:
        errors.append(
            f"{source} ci-plan must contain exactly the trusted planner self-test "
            "and planning invocations"
        )
        return errors
    for invocation in invocations:
        if re.search(r"\bpython3\s+-I\s+\"\$planner\"", invocation) is None:
            errors.append(
                f"{source} trusted planner invocations must use python3 -I"
            )
    if not any("--self-test" in invocation for invocation in invocations):
        errors.append(f"{source} ci-plan is missing the isolated planner self-test")
    if not any("--event-name" in invocation for invocation in invocations):
        errors.append(f"{source} ci-plan is missing the isolated planning invocation")
    return errors


def validate_workflow_contract(
    contents: str,
    source: str,
    job_name: str,
    expected_sha256: str,
    expected_env_sha256: str,
    expected_trigger_sha256: str,
) -> list[str]:
    block, failures = extract_job_block(contents, source, job_name, required=True)
    if failures:
        return failures
    assert block is not None
    actual = hashlib.sha256(block.encode("utf-8")).hexdigest()
    errors: list[str] = []
    if actual != expected_sha256:
        errors.append(
            f"{source} protected job {job_name!r} differs from the trusted "
            f"ARM64 invocation contract (expected SHA-256 {expected_sha256}, got {actual})"
        )

    env_block, env_failures = extract_top_level_block(contents, source, "env")
    errors.extend(env_failures)
    if not env_failures:
        assert env_block is not None
        actual_env = hashlib.sha256(env_block.encode("utf-8")).hexdigest()
        if actual_env != expected_env_sha256:
            errors.append(
                f"{source} top-level env differs from the trusted ARM64 host "
                f"environment contract (expected SHA-256 {expected_env_sha256}, "
                f"got {actual_env})"
            )

    trigger_block, trigger_failures = extract_top_level_block(contents, source, "on")
    errors.extend(trigger_failures)
    if not trigger_failures:
        assert trigger_block is not None
        actual_trigger = hashlib.sha256(trigger_block.encode("utf-8")).hexdigest()
        if actual_trigger != expected_trigger_sha256:
            errors.append(
                f"{source} trigger differs from the trusted ARM64 scheduling "
                f"contract (expected SHA-256 {expected_trigger_sha256}, "
                f"got {actual_trigger})"
            )

    surfaces, surface_failures = unprotected_cross_surfaces(
        contents,
        source,
        job_name,
        required_job=True,
        include_opaque_shell_executable=False,
    )
    errors.extend(surface_failures)
    if surfaces:
        errors.append(
            f"{source} contains Cross executable or configuration input outside "
            f"protected job {job_name!r}"
        )
    errors.extend(validate_publish_control_contract(contents, source))
    if source == "CI workflow":
        errors.extend(validate_ci_planner_isolation(contents, source))
    return errors


def compare_pr_workflow_job(
    merge_base_contents: str,
    proposed_contents: str,
    source: str,
    job_name: str,
) -> list[str]:
    baseline, failures = extract_job_block(
        merge_base_contents,
        f"merge-base {source}",
        job_name,
        required=False,
    )
    proposed, proposed_failures = extract_job_block(
        proposed_contents,
        f"proposed {source}",
        job_name,
        required=False,
    )
    failures.extend(proposed_failures)
    if failures:
        return failures
    errors: list[str] = []
    if source == "CI workflow":
        errors.extend(validate_ci_planner_isolation(proposed_contents, source))
    if baseline != proposed:
        errors.append(
            f"{source} protected job {job_name!r} cannot be changed by a pull request"
        )

    baseline_env, baseline_env_failures = extract_top_level_block(
        merge_base_contents, f"merge-base {source}", "env", required=False
    )
    proposed_env, proposed_env_failures = extract_top_level_block(
        proposed_contents, f"proposed {source}", "env", required=False
    )
    errors.extend(baseline_env_failures)
    errors.extend(proposed_env_failures)
    if not baseline_env_failures and not proposed_env_failures:
        if baseline_env != proposed_env:
            errors.append(
                f"{source} top-level env cannot be changed by a pull request because "
                "it is inherited by the protected ARM64 invocation"
            )

    baseline_trigger, baseline_trigger_failures = extract_top_level_block(
        merge_base_contents, f"merge-base {source}", "on", required=False
    )
    proposed_trigger, proposed_trigger_failures = extract_top_level_block(
        proposed_contents, f"proposed {source}", "on", required=False
    )
    errors.extend(baseline_trigger_failures)
    errors.extend(proposed_trigger_failures)
    if not baseline_trigger_failures and not proposed_trigger_failures:
        if baseline_trigger != proposed_trigger:
            errors.append(
                f"{source} workflow trigger cannot be changed by a pull request "
                "because it schedules the protected ARM64 invocation"
            )

    baseline_surfaces, baseline_surface_failures = unprotected_cross_surfaces(
        merge_base_contents,
        f"merge-base {source}",
        job_name,
        required_job=False,
        include_opaque_shell_executable=True,
    )
    proposed_surfaces, proposed_surface_failures = unprotected_cross_surfaces(
        proposed_contents,
        f"proposed {source}",
        job_name,
        required_job=False,
        include_opaque_shell_executable=True,
    )
    errors.extend(baseline_surface_failures)
    errors.extend(proposed_surface_failures)
    if not baseline_surface_failures and not proposed_surface_failures:
        if baseline_surfaces != proposed_surfaces:
            errors.append(
                f"{source} cannot add or change Cross executable/configuration "
                "surfaces outside the protected ARM64 job"
            )
    errors.extend(
        compare_pr_publish_control_contract(
            merge_base_contents,
            proposed_contents,
            source,
        )
    )
    return errors


def self_test() -> list[str]:
    failures: list[str] = []

    expected = list(EXPECTED_PRE_BUILD_COMMANDS)
    if validate_pre_build(expected):
        failures.append("valid exact ARM64 pre-build configuration was rejected")

    unapproved = "touch /tmp/untrusted-command"
    changed_later = expected.copy()
    changed_later[3] = f"{changed_later[3]} && {unapproved}"
    changed_quoting = expected.copy()
    changed_quoting[0] = "dpkg --add-architecture arm64"
    reordered = expected.copy()
    reordered[3], reordered[4] = reordered[4], reordered[3]
    invalid_sequences = {
        "command before approved list": [unapproved, *expected],
        "command inserted fourth": [*expected[:3], unapproved, *expected[3:]],
        "command inserted between later entries": [
            *expected[:5],
            unapproved,
            *expected[5:],
        ],
        "command appended after approved list": [*expected, unapproved],
        "changed later command": changed_later,
        "changed shell quoting": changed_quoting,
        "reordered commands": reordered,
        "removed command": [*expected[:4], *expected[5:]],
    }
    for name, commands in invalid_sequences.items():
        if not validate_pre_build(commands):
            failures.append(f"{name} was not rejected")

    invalid_shapes: dict[str, Any] = {
        "single-string pre-build": unapproved,
        "integer pre-build": 1,
        "inline-table pre-build": {"command": unapproved},
        "mixed-type pre-build array": [*expected, 1],
        "nested pre-build array": [expected],
    }
    for name, value in invalid_shapes.items():
        if not validate_pre_build(value):
            failures.append(f"{name} was not rejected")

    for name, payload in ATTACK_PAYLOADS.items():
        if not validate_pre_build(unsafe_commands(payload)):
            failures.append(f"{name} payload was not rejected")

    legacy = expected.copy()
    legacy[:3] = [
        "dpkg --add-architecture $CROSS_DEB_ARCH",
        "apt-get install --assume-yes libcurl4-openssl-dev:$CROSS_DEB_ARCH",
        "dpkg-architecture -a$CROSS_DEB_ARCH -qDEB_HOST_MULTIARCH",
    ]
    if not validate_pre_build(legacy):
        failures.append("CROSS_DEB_ARCH interpolation was not rejected")

    valid_cross: dict[str, Any] = {
        "target": {
            TARGET: {
                "image": EXPECTED_IMAGE,
                "pre-build": expected,
                "env": {"passthrough": list(EXPECTED_PASSTHROUGH)},
            }
        }
    }
    if validate_cross_configuration(valid_cross):
        failures.append("valid complete Cross.toml policy was rejected")

    cross_bypasses = {
        "global build configuration": {**valid_cross, "build": {"xargo": True}},
        "global dockerfile": {**valid_cross, "build": {"dockerfile": "Dockerfile"}},
        "global pre-build": {**valid_cross, "build": {"pre-build": ["id"]}},
        "global environment": {
            **valid_cross,
            "build": {"env": {"passthrough": ["CROSS_CONFIG"]}},
        },
        "global default target": {
            **valid_cross,
            "build": {"default-target": TARGET},
        },
        "extra target": {
            "target": {**valid_cross["target"], "x86_64-unknown-linux-gnu": {}}
        },
        "custom image": {
            "target": {
                TARGET: {**valid_cross["target"][TARGET], "image": "attacker/image"}
            }
        },
        "target dockerfile": {
            "target": {
                TARGET: {**valid_cross["target"][TARGET], "dockerfile": "Dockerfile"}
            }
        },
        "target runner": {
            "target": {
                TARGET: {**valid_cross["target"][TARGET], "runner": "evil-runner"}
            }
        },
        "target build-std": {
            "target": {
                TARGET: {**valid_cross["target"][TARGET], "build-std": True}
            }
        },
        "target xargo": {
            "target": {TARGET: {**valid_cross["target"][TARGET], "xargo": True}}
        },
        "target volume": {
            "target": {
                TARGET: {
                    **valid_cross["target"][TARGET],
                    "env": {
                        **valid_cross["target"][TARGET]["env"],
                        "volumes": ["/tmp:/host"],
                    },
                }
            }
        },
        "extra passthrough": {
            "target": {
                TARGET: {
                    **valid_cross["target"][TARGET],
                    "env": {
                        "passthrough": [*EXPECTED_PASSTHROUGH, "CROSS_CONFIG"]
                    },
                }
            }
        },
    }
    for name, value in cross_bypasses.items():
        if not validate_cross_configuration(value):
            failures.append(f"{name} was not rejected")

    valid_cross_toml = f'''
["target"."{TARGET}"]
image = "{EXPECTED_IMAGE}"
pre-build = {json.dumps(expected)}

["target"."{TARGET}"."env"]
passthrough = {json.dumps(list(EXPECTED_PASSTHROUGH))}
'''
    parsed_valid, parse_failures = parse_toml(valid_cross_toml, "self-test quoted keys")
    if parse_failures or validate_cross_configuration(parsed_valid):
        failures.append("equivalent quoted Cross.toml keys were rejected")

    invalid_cross_toml = {
        "duplicate pre-build key": f'''
[target.{TARGET}]
pre-build = []
pre-build = []
''',
        "duplicate target table": f'''
[target.{TARGET}]
pre-build = []
[target.{TARGET}]
''',
        "underscore alias": f'''
[target.{TARGET}]
image = "{EXPECTED_IMAGE}"
pre_build = []
''',
        "global dockerfile": "[build]\ndockerfile = 'Dockerfile'\n",
    }
    for name, contents in invalid_cross_toml.items():
        parsed, parse_failures = parse_toml(contents, f"self-test {name}")
        if not parse_failures and not validate_cross_configuration(parsed):
            failures.append(f"{name} was not rejected")

    benign_cargo, cargo_failures = parse_toml(
        "[package]\nname='example'\nversion='1.0.1'\n"
        "[package.metadata.release]\ntag-prefix='v'\n"
        "[workspace.metadata.release]\nshared=true\n"
        "[dependencies]\nserde='1'\n",
        "self-test benign Cargo.toml",
    )
    if cargo_failures or validate_cargo_configuration(benign_cargo):
        failures.append("benign Cargo.toml dependency/version edit was rejected")

    cargo_bypasses = {
        "cross metadata table": "[package]\nname='x'\n[package.metadata.cross.build]\nxargo=true\n",
        "cross metadata inline table": (
            "[package]\nname='x'\n"
            f'metadata={{ cross={{ target={{ "{TARGET}"={{ '
            'dockerfile="Dockerfile" }} }} }} }\n'
        ),
        "cross metadata dotted key": (
            "package.name='x'\npackage.metadata.cross.target."
            f"'{TARGET}'.image='attacker/image'\n"
        ),
        "cross metadata quoted key": (
            "[package]\nname='x'\n[package.metadata.\"cross\"]\n"
            "build-std=true\n"
        ),
        "workspace cross metadata table": (
            "[package]\nname='x'\n[workspace.metadata.cross.build]\n"
            "dockerfile='Dockerfile'\n"
        ),
        "workspace cross metadata inline table": (
            "[package]\nname='x'\n[workspace]\n"
            "metadata={cross={build={pre-build=['id']}}}\n"
        ),
    }
    for name, contents in cargo_bypasses.items():
        parsed, parse_failures = parse_toml(contents, f"self-test {name}")
        if not parse_failures and not validate_cargo_configuration(parsed):
            failures.append(f"{name} was not rejected")

    malformed_cargo = {
        "duplicate Cargo cross table": (
            "[package]\nname='x'\n[package.metadata.cross]\n"
            "[package.metadata.cross]\n"
        ),
        "duplicate Cargo metadata key": (
            "[package]\nname='x'\nmetadata={cross={}}\nmetadata={}\n"
        ),
        "duplicate workspace Cross table": (
            "[package]\nname='x'\n[workspace.metadata.cross]\n"
            "[workspace.metadata.cross]\n"
        ),
    }
    for name, contents in malformed_cargo.items():
        _, parse_failures = parse_toml(contents, f"self-test {name}")
        if not parse_failures:
            failures.append(f"{name} was not rejected")

    valid_cargo_tool: dict[str, Any] = {
        "build": dict(EXPECTED_CARGO_BUILD),
        "target": {
            name: {
                key: list(value) if isinstance(value, list) else value
                for key, value in settings.items()
            }
            for name, settings in EXPECTED_CARGO_TARGETS.items()
        },
        "net": {"git-fetch-with-cli": True, "retry": 10},
        "http": {"multiplexing": False},
    }
    if validate_cargo_tool_configuration(valid_cargo_tool):
        failures.append("valid .cargo/config.toml policy was rejected")
    benign_cargo_tool = {
        **valid_cargo_tool,
        "net": {**valid_cargo_tool["net"], "retry": 20},
        "http": {"multiplexing": True},
    }
    if validate_cargo_tool_configuration(benign_cargo_tool):
        failures.append("benign Cargo transport tuning was rejected")

    cargo_tool_bypasses = {
        "custom rustc": {
            **valid_cargo_tool,
            "build": {**valid_cargo_tool["build"], "rustc": "./ci/rustc"},
        },
        "workspace rustc wrapper": {
            **valid_cargo_tool,
            "build": {
                **valid_cargo_tool["build"],
                "rustc-workspace-wrapper": "./ci/wrapper",
            },
        },
        "default build target": {
            **valid_cargo_tool,
            "build": {**valid_cargo_tool["build"], "target": TARGET},
        },
        "target runner": {
            **valid_cargo_tool,
            "target": {
                **valid_cargo_tool["target"],
                TARGET: {
                    **valid_cargo_tool["target"][TARGET],
                    "runner": "./ci/runner",
                },
            },
        },
        "changed target linker": {
            **valid_cargo_tool,
            "target": {
                **valid_cargo_tool["target"],
                TARGET: {
                    **valid_cargo_tool["target"][TARGET],
                    "linker": "./ci/linker",
                },
            },
        },
        "Cargo environment table": {
            **valid_cargo_tool,
            "env": {"CROSS_CONFIG": "attacker.toml"},
        },
        "Cargo alias table": {
            **valid_cargo_tool,
            "alias": {"build": "cross build"},
        },
    }
    for name, parsed in cargo_tool_bypasses.items():
        if not validate_cargo_tool_configuration(parsed):
            failures.append(f"{name} Cargo config bypass was not rejected")

    malformed_cargo_tool = {
        "duplicate Cargo build table": (
            "[build]\nrustc-wrapper='sccache'\n[build]\nincremental=false\n"
        ),
        "duplicate Cargo rustc key": (
            "[build]\nrustc-wrapper='sccache'\nrustc-wrapper='./ci/wrapper'\n"
        ),
    }
    for name, contents in malformed_cargo_tool.items():
        _, parse_failures = parse_toml(contents, f"self-test {name}")
        if not parse_failures:
            failures.append(f"{name} was not rejected")

    protected_block = """  protected-arm:
    runs-on: ubuntu-latest
    defaults:
      run:
        shell: bash
    steps:
      - name: Build with an empty environment
        run: env -i /trusted/cross build --target aarch64-unknown-linux-gnu
"""
    protected_hash = hashlib.sha256(protected_block.encode()).hexdigest()
    protected_env = "env:\n  FIXED_INPUT: approved\n"
    protected_env_hash = hashlib.sha256(protected_env.encode()).hexdigest()
    protected_trigger = "on:\n  push:\n    branches: [main]\n"
    protected_trigger_hash = hashlib.sha256(protected_trigger.encode()).hexdigest()
    workflow = (
        "name: fixture\n\n"
        f"{protected_trigger}\n"
        f"{protected_env}\n"
        "jobs:\n"
        f"{protected_block}"
        "\n  unrelated:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo safe\n"
    )
    if validate_workflow_contract(
        workflow,
        "self-test workflow",
        "protected-arm",
        protected_hash,
        protected_env_hash,
        protected_trigger_hash,
    ):
        failures.append("valid protected workflow job was rejected")

    benign_workflow = workflow.replace("echo safe", "echo unrelated-edit")
    if validate_workflow_contract(
        benign_workflow,
        "self-test benign workflow",
        "protected-arm",
        protected_hash,
        protected_env_hash,
        protected_trigger_hash,
    ):
        failures.append("unrelated workflow job edit was rejected")

    workflow_bypasses = {
        "job environment override": workflow.replace(
            "    steps:\n", "    env: { CROSS_CONFIG: attacker.toml }\n    steps:\n", 1
        ),
        "step environment override": workflow.replace(
            "        run: env -i",
            "        env:\n          CROSS_TARGET_AARCH64_UNKNOWN_LINUX_GNU_IMAGE: attacker\n"
            "        run: env -i",
        ),
        "GITHUB_ENV override step": workflow.replace(
            "      - name: Build with an empty environment",
            "      - run: echo override >> $GITHUB_ENV\n"
            "      - name: Build with an empty environment",
        ),
        "changed cross command": workflow.replace("env -i", "env"),
        "quoted environment spelling": workflow.replace(
            "    steps:\n", '    env: { "CROSS_CONFIG": attacker.toml }\n    steps:\n', 1
        ),
        "build alias environment override": workflow.replace(
            "    steps:\n",
            "    env: { CROSS_BUILD_PRE_BUILD: 'id' }\n    steps:\n",
            1,
        ),
        "custom toolchain environment override": workflow.replace(
            "    steps:\n",
            "    env: { CROSS_CUSTOM_TOOLCHAIN: '1' }\n    steps:\n",
            1,
        ),
        "legacy container option override": workflow.replace(
            "    steps:\n", "    env: { DOCKER_OPTS: '--privileged' }\n    steps:\n", 1
        ),
        "Cargo target environment override": workflow.replace(
            "    steps:\n",
            f"    env: {{ CARGO_BUILD_TARGET: {TARGET} }}\n    steps:\n",
            1,
        ),
        "job container": workflow.replace(
            "    runs-on: ubuntu-latest\n",
            "    runs-on: ubuntu-latest\n    container: attacker/image\n",
            1,
        ),
        "merge alias": workflow.replace(
            "  protected-arm:\n", "  protected-arm:\n    <<: *attacker\n"
        ),
        "renamed protected job": workflow.replace("protected-arm", "renamed-arm", 1),
        "duplicate protected job": workflow
        + "  protected-arm:\n    runs-on: ubuntu-latest\n",
        "duplicate jobs mapping": workflow + "jobs:\n  attacker: {}\n",
        "flow-style jobs mapping": "name: fixture\njobs: { protected-arm: {} }\n",
        "global loader override": workflow.replace(
            "  FIXED_INPUT: approved\n",
            "  FIXED_INPUT: approved\n  BASH_ENV: ./attacker.sh\n",
        ),
        "global linker preload": workflow.replace(
            "  FIXED_INPUT: approved\n",
            "  FIXED_INPUT: approved\n  LD_PRELOAD: ./attacker.so\n",
        ),
        "changed workflow trigger": workflow.replace(
            "branches: [main]", "branches: [attacker]"
        ),
        "quoted workflow trigger": workflow.replace("on:\n", "'on':\n", 1),
        "flow-style workflow trigger": workflow.replace(
            protected_trigger,
            "on: { push: { branches: [main] } }\n",
        ),
        "duplicate workflow trigger": workflow
        + "on:\n  push:\n    branches: [attacker]\n",
        "unprotected Cross job": workflow
        + "  unprotected-cross-on-pr:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: cross build --target aarch64-unknown-linux-gnu\n",
        "unprotected absolute Cross executable": workflow.replace(
            "echo safe",
            "/home/runner/.cargo/bin/cross build --target aarch64-unknown-linux-gnu",
        ),
        "unprotected Cross install": workflow.replace(
            "echo safe", "cargo install cross"
        ),
        "unprotected quoted Cross executable": workflow.replace(
            "echo safe", '"\\u0063ross build --target aarch64-unknown-linux-gnu"'
        ),
        "unprotected split-quoted Cross executable": workflow.replace(
            "echo safe", 'cr"oss build --target aarch64-unknown-linux-gnu'
        ),
        "unprotected empty shell expansion": workflow.replace(
            "echo safe",
            "cr${UNSET:-}oss build --target aarch64-unknown-linux-gnu",
        ),
        "unprotected default shell expansion": workflow.replace(
            "echo safe",
            "cr${UNSET:-o}ss build --target aarch64-unknown-linux-gnu",
        ),
        "unprotected command substitution": workflow.replace(
            "echo safe",
            "cr$(printf o)ss build --target aarch64-unknown-linux-gnu",
        ),
        "unprotected nested command substitution": workflow.replace(
            "echo safe",
            "cr$(python3 -c 'print(\"o\")')ss build "
            "--target aarch64-unknown-linux-gnu",
        ),
        "unprotected opaque command substitution": workflow.replace(
            "echo safe",
            "cargo install cr$(printf '\\157')ss && "
            "cr$(printf '\\157')ss build --target aarch64-unknown-linux-gnu",
        ),
        "unprotected env-wrapped command substitution": workflow.replace(
            "echo safe",
            "env -i cr$(printf '\\157')ss build "
            "--target aarch64-unknown-linux-gnu",
        ),
        "unprotected assignment-wrapped command substitution": workflow.replace(
            "echo safe",
            "SAFE=value cr$(printf '\\157')ss build "
            "--target aarch64-unknown-linux-gnu",
        ),
        "unprotected Cargo-wrapped command substitution": workflow.replace(
            "echo safe",
            "cargo cr$(printf '\\157')ss build "
            "--target aarch64-unknown-linux-gnu",
        ),
        "unprotected whole command substitution": workflow.replace(
            "echo safe",
            "cargo install $(printf '\\143\\162\\157\\163\\163') && "
            "$(printf '\\143\\162\\157\\163\\163') build "
            "--target aarch64-unknown-linux-gnu",
        ),
        "unprotected GitHub interpolation": workflow.replace(
            "echo safe",
            "cr${{ 'o' }}ss build --target aarch64-unknown-linux-gnu",
        ),
        "unprotected GitHub format expression": workflow.replace(
            "echo safe",
            "${{ format('cr{0}ss', 'o') }} build "
            "--target aarch64-unknown-linux-gnu",
        ),
        "unprotected dynamic GitHub expression": workflow.replace(
            "echo safe",
            "${{ github.event.pull_request.title }} build "
            "--target aarch64-unknown-linux-gnu",
        ),
        "unprotected dynamic GitHub rustc expression": workflow.replace(
            "echo safe",
            "${{ github.event.pull_request.title }} rustc "
            "--target aarch64-unknown-linux-gnu",
        ),
        "unprotected dynamic GitHub toolchain expression": workflow.replace(
            "echo safe",
            "${{ github.event.pull_request.title }} +nightly build "
            "--target aarch64-unknown-linux-gnu",
        ),
        "unprotected Bash brace expansion": workflow.replace(
            "echo safe",
            "cr{o,}ss build --target aarch64-unknown-linux-gnu",
        ),
        "unprotected Bash ANSI-C quote": workflow.replace(
            "echo safe",
            "$'cr\\157ss' build --target aarch64-unknown-linux-gnu",
        ),
        "unprotected positional shell expansion": workflow.replace(
            "echo safe",
            "cr$1oss build --target aarch64-unknown-linux-gnu",
        ),
        "unprotected continued Cross executable": workflow.replace(
            "echo safe",
            "|\n          cr\\\n          oss build --target aarch64-unknown-linux-gnu",
        ),
        "unprotected flow environment alias": workflow.replace(
            "  unrelated:\n",
            "  unrelated:\n    env: { CROSS_CONFIG: attacker.toml }\n",
        ),
    }
    for name, contents in workflow_bypasses.items():
        if not validate_workflow_contract(
            contents,
            f"self-test {name}",
            "protected-arm",
            protected_hash,
            protected_env_hash,
            protected_trigger_hash,
        ):
            failures.append(f"{name} was not rejected")

    merge_base_without_job = (
        "name: stale\nenv:\n  FIXED_INPUT: approved\njobs:\n"
        "  unrelated:\n    runs-on: ubuntu-latest\n"
    )
    proposed_without_job = merge_base_without_job.replace("ubuntu-latest", "ubuntu-24.04")
    if compare_pr_workflow_job(
        merge_base_without_job,
        proposed_without_job,
        "stale workflow",
        "protected-arm",
    ):
        failures.append("stale branch unrelated workflow edit was rejected")
    stale_cross_workflow = (
        "name: stale\nenv:\n  FIXED_INPUT: approved\njobs:\n"
        "  legacy-cross:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: cross build --target aarch64-unknown-linux-gnu\n"
        "  unrelated:\n"
        "    runs-on: ubuntu-22.04\n"
    )
    proposed_stale_cross = stale_cross_workflow.replace(
        "ubuntu-22.04", "ubuntu-24.04"
    )
    if compare_pr_workflow_job(
        stale_cross_workflow,
        proposed_stale_cross,
        "stale workflow",
        "protected-arm",
    ):
        failures.append("stale branch unchanged legacy Cross surface was rejected")
    if compare_pr_workflow_job(
        workflow,
        benign_workflow,
        "current workflow",
        "protected-arm",
    ):
        failures.append("merge-base comparison rejected an unrelated job edit")
    changed_protected = workflow.replace("env -i", "env", 1)
    if not compare_pr_workflow_job(
        workflow,
        changed_protected,
        "current workflow",
        "protected-arm",
    ):
        failures.append("merge-base comparison allowed a protected job edit")
    changed_global_env = workflow.replace("FIXED_INPUT: approved", "FIXED_INPUT: attacker")
    if not compare_pr_workflow_job(
        workflow,
        changed_global_env,
        "current workflow",
        "protected-arm",
    ):
        failures.append("merge-base comparison allowed a protected top-level env edit")
    changed_trigger = workflow.replace("branches: [main]", "branches: [attacker]")
    if not compare_pr_workflow_job(
        workflow,
        changed_trigger,
        "current workflow",
        "protected-arm",
    ):
        failures.append("merge-base comparison allowed a protected workflow trigger edit")
    changed_unprotected_cross = benign_workflow.replace(
        "echo unrelated-edit",
        "cross build --target aarch64-unknown-linux-gnu",
    )
    if not compare_pr_workflow_job(
        workflow,
        changed_unprotected_cross,
        "current workflow",
        "protected-arm",
    ):
        failures.append("merge-base comparison allowed an unprotected Cross invocation")
    changed_shell_variable_cross = benign_workflow.replace(
        "echo unrelated-edit",
        "|\n          cmd=$(printf '\\143\\162\\157\\163\\163')\n"
        '          "$cmd" build --target aarch64-unknown-linux-gnu',
    )
    if not compare_pr_workflow_job(
        workflow,
        changed_shell_variable_cross,
        "current workflow",
        "protected-arm",
    ):
        failures.append(
            "merge-base comparison allowed a shell-variable Cross executable"
        )
    if not validate_workflow_contract(
        changed_shell_variable_cross,
        "self-test workflow",
        "protected-arm",
        protected_hash,
        protected_env_hash,
        protected_trigger_hash,
    ):
        failures.append("trusted revalidation allowed an opaque Cross executable")
    changed_parenthesized_shell_cross = benign_workflow.replace(
        "echo unrelated-edit",
        "|\n          cmd=$(printf '\\143\\162\\157\\163\\163')\n"
        '          ( "$cmd" rustc --target aarch64-unknown-linux-gnu )',
    )
    if not compare_pr_workflow_job(
        workflow,
        changed_parenthesized_shell_cross,
        "current workflow",
        "protected-arm",
    ):
        failures.append(
            "merge-base comparison allowed a parenthesized variable Cross executable"
        )
    if not compare_pr_workflow_job(
        merge_base_without_job,
        workflow,
        "stale workflow",
        "protected-arm",
    ):
        failures.append("merge-base comparison allowed a newly added protected job")

    safe_extra_workflow = (
        "name: Coverage\n"
        "on: [pull_request]\n"
        "jobs:\n"
        "  coverage:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo safe\n"
    )
    benign_extra_edit = safe_extra_workflow.replace("echo safe", "echo still-safe")
    if validate_workflow_collection(
        {"coverage.yml": safe_extra_workflow},
        "self-test workflow directory",
    ):
        failures.append("safe additional workflow was rejected")
    benign_embedded_substitutions = safe_extra_workflow.replace(
        "echo safe",
        'echo "packaging $(grep -c x files) files '
        '($(grep -c y files) profraw)"',
    )
    if validate_workflow_collection(
        {"coverage.yml": benign_embedded_substitutions},
        "self-test workflow directory",
    ):
        failures.append("benign embedded command substitutions were rejected")
    if compare_pr_workflow_collection(
        {"coverage.yml": safe_extra_workflow},
        {
            "coverage.yml": benign_extra_edit,
            "new-benign.yaml": safe_extra_workflow,
        },
        "self-test workflow directory",
    ):
        failures.append("benign workflow collection edits were rejected")

    added_cross_workflow = safe_extra_workflow.replace(
        "echo safe",
        "cross build --target aarch64-unknown-linux-gnu",
    )
    if not compare_pr_workflow_collection(
        {"coverage.yml": safe_extra_workflow},
        {"coverage.yml": safe_extra_workflow, "attacker.yml": added_cross_workflow},
        "self-test workflow directory",
    ):
        failures.append("new workflow Cross invocation was not rejected")

    malformed_cross_workflow = (
        added_cross_workflow
        + "jobs:\n"
        + "  duplicate:\n"
        + "    runs-on: ubuntu-latest\n"
    )
    if not validate_workflow_collection(
        {"malformed.yml": malformed_cross_workflow},
        "self-test workflow directory",
    ):
        failures.append("malformed Cross workflow was not rejected")

    safe_action = (
        "name: Safe local action\n"
        "runs:\n"
        "  using: composite\n"
        "  steps:\n"
        "    - shell: bash\n"
        "      run: echo safe\n"
    )
    benign_action_edit = safe_action.replace("echo safe", "echo still-safe")
    if validate_action_collection(
        {"setup/action.yml": safe_action},
        "self-test local-action directory",
    ):
        failures.append("safe local action was rejected")
    if compare_pr_action_collection(
        {"setup/action.yml": safe_action},
        {"setup/action.yml": benign_action_edit},
        "self-test local-action directory",
    ):
        failures.append("benign local-action edit was rejected")

    cross_action = safe_action.replace(
        "echo safe",
        "cross build --target aarch64-unknown-linux-gnu",
    )
    if not validate_action_collection(
        {"setup/action.yml": cross_action},
        "self-test local-action directory",
    ):
        failures.append("local-action Cross invocation was not rejected")
    if not compare_pr_action_collection(
        {"setup/action.yml": safe_action},
        {"setup/action.yml": cross_action},
        "self-test local-action directory",
    ):
        failures.append("merge-base comparison allowed local-action Cross invocation")

    for label, command in {
        "wrapped Cross": "bash -c 'cross build --target aarch64-unknown-linux-gnu'",
        "valued cargo install": "cargo install --version 0.2.5 cross",
    }.items():
        proposed_action = safe_action.replace("echo safe", command)
        if not compare_pr_action_collection(
            {"setup/action.yml": safe_action},
            {"setup/action.yml": proposed_action},
            "self-test local-action directory",
        ):
            failures.append(f"merge-base comparison allowed {label}")

    cross_action_environment = safe_action.replace(
        "echo safe",
        "echo CROSS_CONFIG=attacker.toml >> $GITHUB_ENV",
    )
    if not compare_pr_action_collection(
        {"setup/action.yml": safe_action},
        {"setup/action.yml": cross_action_environment},
        "self-test local-action directory",
    ):
        failures.append("merge-base comparison allowed local-action Cross environment")

    dynamic_action = safe_action.replace(
        "echo safe",
        "${{ github.event.pull_request.title }} rustc "
        "--target aarch64-unknown-linux-gnu",
    )
    if not compare_pr_action_collection(
        {"setup/action.yml": safe_action},
        {"setup/action.yml": dynamic_action},
        "self-test local-action directory",
    ):
        failures.append("merge-base comparison allowed dynamic local-action Cross")

    variable_action = safe_action.replace(
        "echo safe",
        "|\n        cmd=$(printf '\\143\\162\\157\\163\\163')\n"
        '        "$cmd" build --target aarch64-unknown-linux-gnu',
    )
    if not compare_pr_action_collection(
        {"setup/action.yml": safe_action},
        {"setup/action.yml": variable_action},
        "self-test local-action directory",
    ):
        failures.append("merge-base comparison allowed variable local-action Cross")

    referenced_workflow = (
        "name: Referenced automation\n"
        "jobs:\n"
        "  safe:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: ./.github/actions/setup\n"
        "      - run: bash scripts/safe.sh\n"
    )
    safe_automation = {"scripts/safe.sh": "#!/bin/sh\necho safe\n"}
    if validate_automation_collection(
        {"ci.yml": referenced_workflow},
        {"setup/action.yml": safe_action},
        safe_automation,
        "self-test automation directory",
    ):
        failures.append("safe referenced automation was rejected")

    quoted_run_workflow = referenced_workflow.replace(
        "run: bash scripts/safe.sh",
        'run: "bash scripts/safe.sh"',
    )
    if validate_automation_collection(
        {"ci.yml": quoted_run_workflow},
        {"setup/action.yml": safe_action},
        safe_automation,
        "self-test automation directory",
    ):
        failures.append("quoted safe automation command was rejected")

    aliased_run_workflow = referenced_workflow.replace(
        "run: bash scripts/safe.sh",
        "run: *external_command",
    )
    if not validate_automation_collection(
        {"ci.yml": aliased_run_workflow},
        {"setup/action.yml": safe_action},
        safe_automation,
        "self-test automation directory",
    ):
        failures.append("YAML-aliased automation command was not rejected")

    custom_shell_workflow = referenced_workflow.replace(
        "      - run: bash scripts/safe.sh\n",
        "      - run: echo safe\n"
        "        shell: ./ci/run-cross.sh {0}\n",
    )
    if not validate_automation_collection(
        {"ci.yml": custom_shell_workflow},
        {"setup/action.yml": safe_action},
        safe_automation,
        "self-test automation directory",
    ):
        failures.append("custom repository shell template was not rejected")

    dynamic_shell_workflow = referenced_workflow.replace(
        "      - run: bash scripts/safe.sh\n",
        "      - run: echo safe\n"
        "        shell: ${{ matrix.shell }}\n",
    )
    if not validate_automation_collection(
        {"ci.yml": dynamic_shell_workflow},
        {"setup/action.yml": safe_action},
        safe_automation,
        "self-test automation directory",
    ):
        failures.append("dynamic shell template was not rejected")

    indented_block_workflow = referenced_workflow.replace(
        "run: bash scripts/safe.sh",
        "run: |2-\n        bash ci/arm64.sh",
    )
    if not validate_automation_collection(
        {"ci.yml": indented_block_workflow},
        {"setup/action.yml": safe_action},
        safe_automation,
        "self-test automation directory",
    ):
        failures.append("explicit-indent block scalar escaped automation scanning")

    malformed_block_workflow = referenced_workflow.replace(
        "run: bash scripts/safe.sh",
        "run: |22\n        echo safe",
    )
    if not validate_automation_collection(
        {"ci.yml": malformed_block_workflow},
        {"setup/action.yml": safe_action},
        safe_automation,
        "self-test automation directory",
    ):
        failures.append("malformed block-scalar header was not rejected")

    redirected_script_workflow = referenced_workflow.replace(
        "bash scripts/safe.sh",
        "bash 0< ci/arm64.sh",
    )
    if not validate_automation_collection(
        {"ci.yml": redirected_script_workflow},
        {"setup/action.yml": safe_action},
        safe_automation,
        "self-test automation directory",
    ):
        failures.append("interpreter input redirection escaped automation scanning")

    executable_heredoc_workflow = referenced_workflow.replace(
        "run: bash scripts/safe.sh",
        "run: |\n"
        "          bash <<'SHELL'\n"
        "          ci/arm64.sh\n"
        "          SHELL",
    )
    if not validate_automation_collection(
        {"ci.yml": executable_heredoc_workflow},
        {"setup/action.yml": safe_action},
        safe_automation,
        "self-test automation directory",
    ):
        failures.append("executable shell heredoc escaped automation scanning")

    external_action_workflow = referenced_workflow.replace(
        "./.github/actions/setup",
        "./ci/cross-action",
    )
    if not validate_automation_collection(
        {"ci.yml": external_action_workflow},
        {"setup/action.yml": safe_action},
        safe_automation,
        "self-test automation directory",
    ):
        failures.append("local action outside .github/actions was not rejected")

    external_script_workflow = referenced_workflow.replace(
        "bash scripts/safe.sh",
        "./ci/arm64.sh",
    )
    if not validate_automation_collection(
        {"ci.yml": external_script_workflow},
        {"setup/action.yml": safe_action},
        safe_automation,
        "self-test automation directory",
    ):
        failures.append("repository script outside scanned roots was not rejected")

    benign_heredoc_workflow = referenced_workflow.replace(
        "bash scripts/safe.sh",
        "python3 - <<'PY'\n"
        "          print('| GCP/Azure | src/plugins/mod.rs | n/a |')\n"
        "          print('attacker.sh is fixture data, not a command')\n"
        "          PY",
    )
    if validate_automation_collection(
        {"ci.yml": benign_heredoc_workflow},
        {"setup/action.yml": safe_action},
        safe_automation,
        "self-test automation directory",
    ):
        failures.append("benign inline-program data was treated as an executable path")

    benign_python_automation = {
        "scripts/safe.py": (
            "FIXTURES = ('./ci/arm64.sh', 'scripts/missing.sh')\n"
            "print(FIXTURES)\n"
        )
    }
    python_workflow = referenced_workflow.replace(
        "bash scripts/safe.sh",
        "python3 scripts/safe.py",
    )
    if validate_automation_collection(
        {"ci.yml": python_workflow},
        {"setup/action.yml": safe_action},
        benign_python_automation,
        "self-test automation directory",
    ):
        failures.append("benign Python fixture strings were treated as commands")

    external_python_automation = {
        "scripts/safe.py": (
            "from subprocess import run as execute\n"
            "execute(args=['python3', 'ci/arm64.py'], check=True)\n"
        )
    }
    if not validate_automation_collection(
        {"ci.yml": python_workflow},
        {"setup/action.yml": safe_action},
        external_python_automation,
        "self-test automation directory",
    ):
        failures.append("Python process API escaped the scanned automation roots")

    literal_cross_python = {
        "scripts/safe.py": (
            "import subprocess\n"
            "subprocess.run(['cross', 'build', '--target', "
            "'aarch64-unknown-linux-gnu'])\n"
        )
    }
    if not compare_pr_automation_collection(
        {"ci.yml": python_workflow},
        {"ci.yml": python_workflow},
        {"setup/action.yml": safe_action},
        {"setup/action.yml": safe_action},
        benign_python_automation,
        literal_cross_python,
        "self-test automation directory",
    ):
        failures.append("literal Python subprocess Cross was not rejected")

    expanded_python_automation = {
        "scripts/safe.py": (
            "import subprocess\n"
            "options = {'args': ['python3', 'ci/arm64.py']}\n"
            "subprocess.run(**options)\n"
        )
    }
    if not validate_automation_collection(
        {"ci.yml": python_workflow},
        {"setup/action.yml": safe_action},
        expanded_python_automation,
        "self-test automation directory",
    ):
        failures.append("expanded Python process arguments were not rejected")

    opaque_python_baseline = {
        "scripts/safe.py": (
            "import subprocess\n"
            "command = ['echo', 'safe']\n"
            "subprocess.run(command, check=True)\n"
        )
    }
    opaque_python_proposed = {
        "scripts/safe.py": (
            "import subprocess\n"
            "command = ['bash', 'ci/arm64.sh']\n"
            "subprocess.run(command, check=True)\n"
        )
    }
    if not compare_pr_automation_collection(
        {"ci.yml": python_workflow},
        {"ci.yml": python_workflow},
        {"setup/action.yml": safe_action},
        {"setup/action.yml": safe_action},
        opaque_python_baseline,
        opaque_python_proposed,
        "self-test automation directory",
    ):
        failures.append("opaque Python process dispatch was not protected")

    benign_automation_edit = {"scripts/safe.sh": "#!/bin/sh\necho still-safe\n"}
    if compare_pr_automation_collection(
        {"ci.yml": referenced_workflow},
        {"ci.yml": referenced_workflow},
        {"setup/action.yml": safe_action},
        {"setup/action.yml": safe_action},
        safe_automation,
        benign_automation_edit,
        "self-test automation directory",
    ):
        failures.append("benign referenced-script edit was rejected")

    cross_automation = {
        "scripts/safe.sh": (
            "#!/bin/sh\ncross build --target aarch64-unknown-linux-gnu\n"
        )
    }
    if not compare_pr_automation_collection(
        {"ci.yml": referenced_workflow},
        {"ci.yml": referenced_workflow},
        {"setup/action.yml": safe_action},
        {"setup/action.yml": safe_action},
        safe_automation,
        cross_automation,
        "self-test automation directory",
    ):
        failures.append("referenced-script Cross invocation was not rejected")
    if not validate_automation_collection(
        {"ci.yml": referenced_workflow},
        {"setup/action.yml": safe_action},
        cross_automation,
        "self-test automation directory",
    ):
        failures.append("trusted revalidation allowed reached Cross automation")

    hostname_automation = {
        "scripts/safe.sh": "#!/bin/sh\necho cross.blackbox.example\n"
    }
    hostname_automation_edit = {
        "scripts/safe.sh": "#!/bin/sh\n# benign\necho cross.blackbox.example\n"
    }
    if compare_pr_automation_collection(
        {"ci.yml": referenced_workflow},
        {"ci.yml": referenced_workflow},
        {"setup/action.yml": safe_action},
        {"setup/action.yml": safe_action},
        hostname_automation,
        hostname_automation_edit,
        "self-test automation directory",
    ):
        failures.append("non-executable cross hostname blocked a benign edit")

    variable_prefix_workflow = referenced_workflow.replace(
        "bash scripts/safe.sh",
        "bash $RUNNER_TEMP/scripts/safe.sh",
    )
    if not validate_automation_collection(
        {"ci.yml": variable_prefix_workflow},
        {"setup/action.yml": safe_action},
        safe_automation,
        "self-test automation directory",
    ):
        failures.append("variable-prefixed script path was not rejected")

    generated_shell_workflow = referenced_workflow.replace(
        "bash scripts/safe.sh",
        "bash -c \"$(printf '\\143\\162\\157\\163\\163 build')\"",
    )
    if not compare_pr_workflow_collection(
        {"safe.yml": referenced_workflow},
        {"safe.yml": generated_shell_workflow},
        "self-test automation directory",
    ):
        failures.append("generated inline shell was not rejected")

    node_workflow = referenced_workflow.replace(
        "bash scripts/safe.sh",
        "node scripts/safe.js",
    )
    node_baseline = {"scripts/safe.js": "console.log('safe');\n"}
    node_proposed = {
        "scripts/safe.js": (
            "require('child_process').spawnSync('cr' + 'oss', ['build']);\n"
        )
    }
    if not compare_pr_automation_collection(
        {"ci.yml": node_workflow},
        {"ci.yml": node_workflow},
        {"setup/action.yml": safe_action},
        {"setup/action.yml": safe_action},
        node_baseline,
        node_proposed,
        "self-test automation directory",
    ):
        failures.append("non-Python process dispatch was not protected")

    transitive_workflow = referenced_workflow.replace(
        "scripts/safe.sh",
        "scripts/parent.sh",
    )
    baseline_transitive = {
        "scripts/parent.sh": "#!/bin/sh\nbash scripts/child.sh\n",
        "scripts/child.sh": "#!/bin/sh\necho safe\n",
    }
    proposed_transitive = {
        **baseline_transitive,
        "scripts/child.sh": (
            "#!/bin/sh\ncross build --target aarch64-unknown-linux-gnu\n"
        ),
    }
    if not compare_pr_automation_collection(
        {"ci.yml": transitive_workflow},
        {"ci.yml": transitive_workflow},
        {"setup/action.yml": safe_action},
        {"setup/action.yml": safe_action},
        baseline_transitive,
        proposed_transitive,
        "self-test automation directory",
    ):
        failures.append("transitive referenced-script Cross invocation was not rejected")

    python_workflow = referenced_workflow.replace(
        "bash scripts/safe.sh",
        "python3 scripts/safe.py",
    )
    python_baseline = {"scripts/safe.py": "print('safe')\n"}

    def python_automation_escapes(label: str, body: str) -> None:
        """Both the PR comparison and current-tree validation must fail closed."""

        proposed = {"scripts/safe.py": body}
        if not compare_pr_automation_collection(
            {"ci.yml": python_workflow},
            {"ci.yml": python_workflow},
            {"setup/action.yml": safe_action},
            {"setup/action.yml": safe_action},
            python_baseline,
            proposed,
            "self-test automation directory",
        ):
            failures.append(f"{label} was not rejected by PR comparison")
        if not validate_automation_collection(
            {"ci.yml": python_workflow},
            {"setup/action.yml": safe_action},
            proposed,
            "self-test automation directory",
        ):
            failures.append(f"{label} was not rejected by tree validation")

    arm_arguments = "'build', '--target', 'aarch64-unknown-linux-gnu'"
    python_automation_escapes(
        "dynamic __import__ process dispatch",
        f"__import__('subprocess').run(['cr' + 'oss', {arm_arguments}])\n",
    )
    python_automation_escapes(
        "importlib dynamic process dispatch",
        "import importlib\n"
        "importlib.import_module('subprocess').run(\n"
        f"    ['cross', {arm_arguments}]\n"
        ")\n",
    )
    python_automation_escapes(
        "getattr process dispatch",
        "import subprocess\n"
        f"getattr(subprocess, 'run')(['cross', {arm_arguments}])\n",
    )
    python_automation_escapes(
        "f-string assembled Cross executable",
        "import subprocess\n"
        f"subprocess.run([f'cr{{\"oss\"}}', {arm_arguments}])\n",
    )
    python_automation_escapes(
        "joined Cross executable",
        "import subprocess\n"
        f"subprocess.run([''.join(['cr', 'oss']), {arm_arguments}])\n",
    )
    python_automation_escapes(
        "subprocess executable override",
        "import subprocess\n"
        f"subprocess.run([{arm_arguments}], executable='cross')\n",
    )
    python_automation_escapes(
        "opaque dynamic dispatch",
        "import subprocess\n"
        "name = 'run'\n"
        f"getattr(subprocess, name)(['cross', {arm_arguments}])\n",
    )
    python_automation_escapes(
        "shell-wrapper subprocess",
        "import subprocess\n"
        "subprocess.run(['sh', '-c', 'cross build --target "
        f"{TARGET}'])\n",
    )
    python_automation_escapes(
        "login-shell-wrapper subprocess",
        "import subprocess\n"
        "subprocess.run(['bash', '-lc', 'cross build --target "
        f"{TARGET}'])\n",
    )
    python_automation_escapes(
        "absolute Cross executable path",
        "import subprocess\n"
        f"subprocess.run(['/home/runner/.cargo/bin/cross', {arm_arguments}])\n",
    )
    python_automation_escapes(
        "absolute Cargo path before Cross",
        "import subprocess\n"
        f"subprocess.run(['/usr/bin/cargo', 'cross', {arm_arguments}])\n",
    )
    python_automation_escapes(
        "aliased process function",
        "import subprocess\n"
        "run = subprocess.run\n"
        f"run(['cross', {arm_arguments}])\n",
    )
    python_automation_escapes(
        "aliased process module",
        "import subprocess\n"
        "sp = subprocess\n"
        f"sp.run(['cross', {arm_arguments}])\n",
    )
    python_automation_escapes(
        "chained process alias",
        "import subprocess\n"
        "run = subprocess.run\n"
        "launch = run\n"
        f"launch(['cross', {arm_arguments}])\n",
    )
    python_automation_escapes(
        "aliased shell-wrapper subprocess",
        "import subprocess\n"
        "run = subprocess.run\n"
        f"run(['sh', '-c', 'cross build --target {TARGET}'])\n",
    )

    benign_python = {
        "scripts/safe.py": (
            "import subprocess\n"
            "# cross-compilation notes live at cross.example.invalid\n"
            "# the handbook says to run cargo install cross locally\n"
            "subprocess.run(['cargo', 'build', '--locked'])\n"
            "subprocess.run(['cargo', 'test'], executable='/usr/bin/cargo')\n"
            "subprocess.run(['sh', '-c', 'cargo build --locked'])\n"
            "subprocess.run(['/usr/bin/cargo', 'build', '--locked'])\n"
            "runner = subprocess.run\n"
            "runner(['cargo', 'test', '--locked'])\n"
        )
    }
    if compare_pr_automation_collection(
        {"ci.yml": python_workflow},
        {"ci.yml": python_workflow},
        {"setup/action.yml": safe_action},
        {"setup/action.yml": safe_action},
        python_baseline,
        benign_python,
        "self-test automation directory",
    ):
        failures.append("benign Python automation edit was rejected")

    def shell_automation_escapes(label: str, body: str) -> None:
        proposed = {"scripts/safe.sh": f"#!/bin/sh\n{body}\n"}
        if not compare_pr_automation_collection(
            {"ci.yml": referenced_workflow},
            {"ci.yml": referenced_workflow},
            {"setup/action.yml": safe_action},
            {"setup/action.yml": safe_action},
            safe_automation,
            proposed,
            "self-test automation directory",
        ):
            failures.append(f"{label} was not rejected by PR comparison")
        if not validate_automation_collection(
            {"ci.yml": referenced_workflow},
            {"setup/action.yml": safe_action},
            proposed,
            "self-test automation directory",
        ):
            failures.append(f"{label} was not rejected by tree validation")

    arm_target = f"build --target {TARGET}"
    shell_automation_escapes(
        "brace-delimited variable concatenation",
        f"x=cr\ny=oss\n${{x}}${{y}} {arm_target}",
    )
    shell_automation_escapes(
        "bare variable concatenation",
        f"x=cr\ny=oss\n$x$y {arm_target}",
    )
    shell_automation_escapes(
        "variable concatenation around a literal",
        f"x=cr\ny=ss\n${{x}}o${{y}} {arm_target}",
    )
    shell_automation_escapes(
        "mixed substitution concatenation",
        f"y=oss\n$(printf cr)${{y}} {arm_target}",
    )
    shell_automation_escapes(
        "one-line function body",
        f"f(){{ cross {arm_target}; }}\nf",
    )
    shell_automation_escapes(
        "spaced one-line function body",
        f"f() {{ cross {arm_target}; }}\nf",
    )
    shell_automation_escapes(
        "env with a separate option operand",
        f"env -u FOO cross {arm_target}",
    )
    shell_automation_escapes(
        "env with a long option operand",
        f"env --unset FOO cross {arm_target}",
    )
    shell_automation_escapes(
        "env chdir before Cross",
        f"env -C /tmp cross {arm_target}",
    )
    shell_automation_escapes(
        "sudo with a separate option operand",
        f"sudo -u builder cross {arm_target}",
    )
    shell_automation_escapes(
        "timeout wrapper before Cross",
        f"timeout 30 cross {arm_target}",
    )
    shell_automation_escapes(
        "background separator before Cross",
        f"echo start & cross {arm_target}",
    )
    shell_automation_escapes(
        "command substitution assignment",
        f"out=$(cross {arm_target})\necho \"$out\"",
    )
    shell_automation_escapes(
        "backtick substitution assignment",
        f"out=`cross {arm_target}`\necho \"$out\"",
    )
    shell_automation_escapes(
        "process substitution operand",
        f"diff <(cross {arm_target}) /dev/null",
    )
    shell_automation_escapes(
        "single-line case arm",
        f"case $t in *) cross {arm_target} ;; esac",
    )
    shell_automation_escapes(
        "alternate case arm after a terminator",
        f"case $t in x) echo x ;; *) cross {arm_target} ;; esac",
    )
    shell_automation_escapes(
        "nested shell wrapper",
        f"sh -c \"cross {arm_target}\"",
    )
    shell_automation_escapes(
        "login shell wrapper",
        f"bash -lc \"cross {arm_target}\"",
    )
    shell_automation_escapes(
        "absolute Cross path",
        f"/home/runner/.cargo/bin/cross {arm_target}",
    )
    shell_automation_escapes(
        "absolute Cargo path before Cross",
        f"/usr/bin/cargo cross {arm_target}",
    )
    shell_automation_escapes(
        "home-relative Cross path",
        f"~/.cargo/bin/cross {arm_target}",
    )
    shell_automation_escapes(
        "absolute Cargo path installing Cross",
        "/usr/bin/cargo install --version 0.2.5 cross",
    )
    shell_automation_escapes(
        "sudo end-of-options before Cross",
        f"sudo -- cross {arm_target}",
    )
    shell_automation_escapes(
        "command end-of-options before Cross",
        f"command -- cross {arm_target}",
    )
    shell_automation_escapes(
        "env end-of-options before Cross",
        f"env -- cross {arm_target}",
    )
    shell_automation_escapes(
        "expanded alias bound to Cross",
        f"shopt -s expand_aliases\nalias c=cross\nc {arm_target}",
    )
    shell_automation_escapes(
        "quoted alias body invoking Cross",
        f"shopt -s expand_aliases\nalias c='cross {arm_target}'\nc",
    )
    shell_automation_escapes(
        "alias chained after a separator",
        "shopt -s expand_aliases; "
        + f"alias c=cross\nc {arm_target}",
    )

    benign_shell = {
        "scripts/safe.sh": (
            "#!/bin/sh\n"
            "# builds are cross-checked against cross.example.invalid\n"
            "# see the handbook for cargo install cross guidance\n"
            "f() { echo safe; }\n"
            "env -u FOO cargo build --locked\n"
            "sudo -u builder cargo test\n"
            "sudo -- cargo build --locked\n"
            "/usr/bin/cargo build --locked\n"
            "sh -c 'cargo test --locked'\n"
            "case $t in *) echo safe ;; esac\n"
            'echo "run cargo install cross locally"\n'
            "out=$(cargo metadata --format-version 1)\n"
            "x=cr\ny=ate\n"
            "echo \"${x}${y}\"\n"
        )
    }
    if compare_pr_automation_collection(
        {"ci.yml": referenced_workflow},
        {"ci.yml": referenced_workflow},
        {"setup/action.yml": safe_action},
        {"setup/action.yml": safe_action},
        safe_automation,
        benign_shell,
        "self-test automation directory",
    ):
        failures.append("benign shell automation edit was rejected")

    def dispatcher_escapes(
        label: str,
        workflow_command: str,
        baseline: dict[str, str],
        proposed: dict[str, str],
    ) -> None:
        """A dispatcher manifest is followed, scanned, and frozen like a script."""

        dispatcher_workflow = referenced_workflow.replace(
            "bash scripts/safe.sh",
            workflow_command,
        )
        if validate_automation_collection(
            {"ci.yml": dispatcher_workflow},
            {"setup/action.yml": safe_action},
            baseline,
            "self-test automation directory",
        ):
            failures.append(f"benign {label} manifest was rejected")
        if not validate_automation_collection(
            {"ci.yml": dispatcher_workflow},
            {"setup/action.yml": safe_action},
            proposed,
            "self-test automation directory",
        ):
            failures.append(f"{label} Cross recipe was not rejected")
        if not compare_pr_automation_collection(
            {"ci.yml": dispatcher_workflow},
            {"ci.yml": dispatcher_workflow},
            {"setup/action.yml": safe_action},
            {"setup/action.yml": safe_action},
            baseline,
            proposed,
            "self-test automation directory",
        ):
            failures.append(f"{label} Cross recipe edit was not rejected")
        if not validate_automation_collection(
            {"ci.yml": dispatcher_workflow},
            {"setup/action.yml": safe_action},
            {},
            "self-test automation directory",
        ):
            failures.append(f"missing {label} manifest was not rejected")

    dispatcher_escapes(
        "make dispatcher",
        "make arm64",
        {"Makefile": "arm64:\n\tcargo build --locked\n"},
        {"Makefile": f"arm64:\n\t@cross {arm_target}\n"},
    )
    dispatcher_escapes(
        "relocated make dispatcher",
        "make -C tests/performance arm64",
        {"tests/performance/Makefile": "arm64:\n\tcargo build --locked\n"},
        {"tests/performance/Makefile": f"arm64:\n\tcross {arm_target}\n"},
    )
    dispatcher_escapes(
        "npm script dispatcher",
        "npm run arm64",
        {"package.json": json.dumps({"scripts": {"arm64": "cargo build --locked"}})},
        {"package.json": json.dumps({"scripts": {"arm64": f"cross {arm_target}"}})},
    )
    dispatcher_escapes(
        "just dispatcher",
        "just arm64",
        {"justfile": "arm64:\n    cargo build --locked\n"},
        {"justfile": f"arm64:\n    cross {arm_target}\n"},
    )

    folded_action = (
        "name: Folded\n"
        "runs:\n"
        "  using: composite\n"
        "  steps:\n"
        "    - run: >\n"
        "        cross\n"
        f"        {arm_target}\n"
        "      shell: bash\n"
    )
    if not validate_action_collection(
        {"folded/action.yml": folded_action},
        "self-test action directory",
    ):
        failures.append("folded local-action Cross invocation was not rejected")
    if not compare_pr_action_collection(
        {"folded/action.yml": safe_action},
        {"folded/action.yml": folded_action},
        "self-test action directory",
    ):
        failures.append("folded local-action Cross edit was not rejected")

    folded_workflow = (
        "name: Folded workflow\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: >\n"
        "          cross\n"
        f"          {arm_target}\n"
    )
    if not compare_pr_workflow_collection(
        {"safe.yml": referenced_workflow},
        {"safe.yml": folded_workflow},
        "self-test automation directory",
    ):
        failures.append("folded workflow Cross invocation was not rejected")

    benign_folded_action = (
        "name: Folded\n"
        "runs:\n"
        "  using: composite\n"
        "  steps:\n"
        "    - run: >\n"
        "        cargo\n"
        "        build --locked\n"
        "      shell: bash\n"
    )
    if validate_action_collection(
        {"folded/action.yml": benign_folded_action},
        "self-test action directory",
    ):
        failures.append("benign folded local action was rejected")

    # Cargo's global option layer precedes a Cargo-compatible subcommand.
    cargo_option_cross = (
        "cargo --config attacker.toml cross build "
        f"--target {TARGET}"
    )
    if not contains_literal_executable_cross(cargo_option_cross):
        failures.append("Cargo global options hid a Cross subcommand")
    if not contains_literal_executable_cross(
        f"cargo +stable --config attacker.toml cross build --target {TARGET}"
    ):
        failures.append("Cargo toolchain/global options hid a Cross subcommand")
    if contains_literal_executable_cross(
        f"echo 'cargo --config attacker.toml cross build --target {TARGET}'"
    ):
        failures.append("quoted Cargo/Cross prose was treated as executable")

    # Composite Python/custom-shell execution and Dockerfile instructions are
    # interpreted according to the action runtime, not as undifferentiated YAML.
    python_cross_action = (
        "name: Python action\n"
        "runs:\n"
        "  using: composite\n"
        "  steps:\n"
        "    - shell: python3 -I\n"
        "      run: |\n"
        "        import subprocess\n"
        "        subprocess.run(['cargo', 'cross', 'build', "
        f"'--target', '{TARGET}'])\n"
    )
    benign_python_action = python_cross_action.replace(
        "subprocess.run(['cargo', 'cross', 'build', "
        f"'--target', '{TARGET}'])",
        "print('cargo install cross locally')",
    )
    if not validate_action_collection(
        {"python/action.yml": python_cross_action},
        "self-test action directory",
    ):
        failures.append("Python composite-action Cross process was not rejected")
    if validate_action_collection(
        {"python/action.yml": benign_python_action},
        "self-test action directory",
    ):
        failures.append("benign Python composite action was rejected")
    unsupported_shell_action = safe_action.replace(
        "shell: bash",
        "shell: ./scripts/custom-shell {0}",
    )
    if not validate_action_collection(
        {"custom/action.yml": unsupported_shell_action},
        "self-test action directory",
    ):
        failures.append("unsupported composite-action shell was not rejected")

    docker_action = (
        "name: Docker action\n"
        "runs:\n"
        "  using: docker\n"
        "  image: Dockerfile\n"
    )
    hostile_dockerfile = f"FROM scratch\nRUN cross {arm_target}\n"
    benign_dockerfile = "FROM scratch\nRUN echo 'cargo install cross locally'\n"
    if not validate_action_collection(
        {
            "docker/action.yml": docker_action,
            "docker/Dockerfile": hostile_dockerfile,
        },
        "self-test action directory",
    ):
        failures.append("Docker action RUN Cross invocation was not rejected")
    if validate_action_collection(
        {
            "docker/action.yml": docker_action,
            "docker/Dockerfile": benign_dockerfile,
        },
        "self-test action directory",
    ):
        failures.append("benign Docker action was rejected")

    # npm workspace selection must resolve the selected nested package.json,
    # even when a harmless root manifest exists.
    workspace_workflow = referenced_workflow.replace(
        "bash scripts/safe.sh",
        "npm --workspace tools/evil run build",
    )
    root_manifest = json.dumps({"scripts": {"build": "cargo build --locked"}})
    benign_workspace_manifest = json.dumps(
        {"scripts": {"build": "cargo build --locked"}}
    )
    hostile_workspace_manifest = json.dumps(
        {"scripts": {"build": f"cross {arm_target}"}}
    )
    benign_workspace = {
        "package.json": root_manifest,
        "tools/evil/package.json": benign_workspace_manifest,
    }
    hostile_workspace = {
        "package.json": root_manifest,
        "tools/evil/package.json": hostile_workspace_manifest,
    }
    if validate_automation_collection(
        {"ci.yml": workspace_workflow},
        {"setup/action.yml": safe_action},
        benign_workspace,
        "self-test automation directory",
    ):
        failures.append("benign npm workspace manifest was rejected")
    if not validate_automation_collection(
        {"ci.yml": workspace_workflow},
        {"setup/action.yml": safe_action},
        hostile_workspace,
        "self-test automation directory",
    ):
        failures.append("selected npm workspace Cross script was not rejected")
    if not validate_automation_collection(
        {"ci.yml": workspace_workflow},
        {"setup/action.yml": safe_action},
        {"package.json": root_manifest},
        "self-test automation directory",
    ):
        failures.append("missing selected npm workspace manifest was not rejected")
    if not compare_pr_automation_collection(
        {"ci.yml": workspace_workflow},
        {"ci.yml": workspace_workflow},
        {"setup/action.yml": safe_action},
        {"setup/action.yml": safe_action},
        benign_workspace,
        hostile_workspace,
        "self-test automation directory",
    ):
        failures.append("npm workspace Cross script edit was not rejected")

    # Workflow prose and comments remain editable; executable commands and
    # environment tokens remain protected independently.
    benign_cross_prose_workflow = safe_extra_workflow.replace(
        "echo safe",
        "echo 'cargo install cross locally' # cross documentation",
    )
    if validate_workflow_collection(
        {"prose.yml": benign_cross_prose_workflow},
        "self-test workflow directory",
    ):
        failures.append("benign workflow Cross prose was rejected")
    double_quoted_cross_prose = safe_extra_workflow.replace(
        "echo safe",
        'echo "cargo install cross locally"',
    ) + "# cross; cross build is documentation only\n"
    if validate_workflow_collection(
        {"double-prose.yml": double_quoted_cross_prose},
        "self-test workflow directory",
    ):
        failures.append("double-quoted/commented workflow Cross prose was rejected")
    if not validate_workflow_collection(
        {"hostile.yml": added_cross_workflow},
        "self-test workflow directory",
    ):
        failures.append("command-anchored workflow Cross invocation was missed")
    cross_environment_workflow = safe_extra_workflow.replace(
        "    steps:\n",
        "    env:\n      CROSS_CONFIG: attacker.toml\n    steps:\n",
    )
    if not validate_workflow_collection(
        {"environment.yml": cross_environment_workflow},
        "self-test workflow directory",
    ):
        failures.append("workflow Cross environment token was missed")

    isolated_planner_workflow = (
        "name: Planner fixture\n"
        "jobs:\n"
        "  ci-plan:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: python3 -I \"$planner\" --self-test\n"
        "      - run: |\n"
        "          plan=\"$(python3 -I \"$planner\" \\\n"
        "            --event-name pull_request)\"\n"
    )
    if validate_ci_planner_isolation(
        isolated_planner_workflow,
        "self-test CI workflow",
    ):
        failures.append("isolated trusted planner fixture was rejected")
    poisoned_planner_workflow = isolated_planner_workflow.replace(
        'python3 -I "$planner" --self-test',
        'python3 "$planner" --self-test',
        1,
    )
    if not validate_ci_planner_isolation(
        poisoned_planner_workflow,
        "self-test CI workflow",
    ):
        failures.append("non-isolated trusted planner invocation was accepted")

    shell_automation_escapes(
        "literal eval Cross command",
        f"eval 'cross {arm_target}'",
    )
    shell_automation_escapes(
        "quoted env assignment before Cross",
        f"env FOO='a b' cross {arm_target}",
    )
    shell_automation_escapes(
        "bare env reset before Cross",
        f"env - cross {arm_target}",
    )
    shell_automation_escapes(
        "leading redirection before Cross",
        f">/tmp/cross-policy.log cross {arm_target}",
    )
    shell_automation_escapes(
        "xargs command operand",
        f"printf x | xargs -n 1 cross {arm_target}",
    )
    shell_automation_escapes(
        "find exec command operand",
        f"find . -exec cross {arm_target} ';'",
    )
    shell_automation_escapes(
        "literal pipeline shell stdin",
        f"printf 'cross {arm_target}' | bash",
    )
    shell_automation_escapes(
        "literal here-string shell stdin",
        f"bash <<< 'cross {arm_target}'",
    )
    shell_automation_escapes(
        "literal process-substitution shell stdin",
        f"bash < <(printf 'cross {arm_target}')",
    )

    benign_executor_lines = {
        "literal eval": "eval 'echo safe'",
        "quoted env assignment": "env FOO='a b' cargo build --locked",
        "leading redirection": ">/tmp/safe.log echo safe",
        "xargs command": "printf x | xargs -n 1 echo",
        "find exec command": "find . -exec echo safe ';'",
        "literal pipeline shell input": "printf 'cargo build --locked' | bash",
        "literal here-string shell input": "bash <<< 'cargo test --locked'",
        "literal process-substitution shell input": (
            "bash < <(printf 'cargo check --locked')"
        ),
    }
    for benign_label, benign_line in benign_executor_lines.items():
        benign_contents = f"#!/bin/sh\n{benign_line}\n"
        benign_errors = compare_pr_automation_collection(
            {"ci.yml": referenced_workflow},
            {"ci.yml": referenced_workflow},
            {"setup/action.yml": safe_action},
            {"setup/action.yml": safe_action},
            safe_automation,
            {"scripts/safe.sh": benign_contents},
            "self-test automation directory",
        )
        if benign_errors:
            logical_benign = re.sub(r"\\\r?\n[ \t]*", "", benign_contents)
            matching_variants = [
                variant
                for line in logical_scan_lines(logical_benign)
                for variant in scan_variants(
                    line,
                    include_opaque_shell_executable=True,
                )
                if has_cross_command_context(
                    variant,
                    include_opaque_shell_executable=True,
                )
                or CROSS_ENVIRONMENT.search(variant)
            ]
            runtime_sensitive, runtime_errors = action_file_runtime_surface(
                "scripts/safe.sh",
                benign_contents,
                include_opaque_shell_executable=True,
            )
            failures.append(
                f"benign {benign_label} was rejected: {'; '.join(benign_errors)}; "
                f"matching variants={matching_variants!r}; "
                f"runtime sensitive={runtime_sensitive!r}; "
                f"runtime errors={runtime_errors!r}; "
                f"opaque inline={bool(OPAQUE_INLINE_SHELL.search(logical_benign))!r}; "
                f"wrapped literal={bool(WRAPPED_LITERAL_CROSS.search(logical_benign))!r}"
            )

    python_automation_escapes(
        "literal subprocess shell input",
        "import subprocess\n"
        f"subprocess.run(['bash'], input='cross {arm_target}', text=True)\n",
    )
    python_automation_escapes(
        "literal getattr process alias",
        "import subprocess\n"
        "run = getattr(subprocess, 'run')\n"
        f"run(['cross', {arm_arguments}])\n",
    )
    python_automation_escapes(
        "literal dynamic-import process alias",
        "run = __import__('subprocess').run\n"
        f"run(['cross', {arm_arguments}])\n",
    )
    python_automation_escapes(
        "opaque dynamic process alias",
        "import subprocess\n"
        "name = 'run'\n"
        "run = getattr(subprocess, name)\n"
        f"run(['cross', {arm_arguments}])\n",
    )
    benign_python_alias_input = {
        "scripts/safe.py": (
            "import subprocess\n"
            "run = getattr(subprocess, 'run')\n"
            "run(['cargo', 'build', '--locked'])\n"
            "run(['bash'], input='cargo test --locked', text=True)\n"
        )
    }
    if compare_pr_automation_collection(
        {"ci.yml": python_workflow},
        {"ci.yml": python_workflow},
        {"setup/action.yml": safe_action},
        {"setup/action.yml": safe_action},
        python_baseline,
        benign_python_alias_input,
        "self-test automation directory",
    ):
        failures.append("benign Python alias/stdin automation was rejected")

    extensionless_workflow = referenced_workflow.replace(
        "bash scripts/safe.sh",
        "./scripts/build",
    )
    extensionless_baseline = {
        "scripts/build": "#!/usr/bin/env -S python3 -I\nprint('safe')\n"
    }
    extensionless_python_cross = {
        "scripts/build": (
            "#!/usr/bin/env -S python3 -I\n"
            "import subprocess\n"
            f"subprocess.run(['cross', {arm_arguments}])\n"
        )
    }
    extensionless_shell_cross = {
        "scripts/build": (
            "#!/usr/bin/env -S bash -eu\n"
            f"cross {arm_target}\n"
        )
    }
    unknown_shebang = {"scripts/build": "#!/usr/bin/env ruby\nputs 'safe'\n"}
    if validate_automation_collection(
        {"ci.yml": extensionless_workflow},
        {"setup/action.yml": safe_action},
        extensionless_baseline,
        "self-test automation directory",
    ):
        failures.append("benign extensionless Python automation was rejected")
    for label, proposed in (
        ("extensionless Python", extensionless_python_cross),
        ("extensionless shell", extensionless_shell_cross),
        ("unknown extensionless shebang", unknown_shebang),
    ):
        if not validate_automation_collection(
            {"ci.yml": extensionless_workflow},
            {"setup/action.yml": safe_action},
            proposed,
            "self-test automation directory",
        ):
            failures.append(f"{label} automation was not rejected")
        if not compare_pr_automation_collection(
            {"ci.yml": extensionless_workflow},
            {"ci.yml": extensionless_workflow},
            {"setup/action.yml": safe_action},
            {"setup/action.yml": safe_action},
            extensionless_baseline,
            proposed,
            "self-test automation directory",
        ):
            failures.append(f"{label} automation edit was not rejected")

    opaque_shell_stdin = {
        "scripts/safe.sh": (
            "#!/bin/sh\n"
            "printf '%s' \"$PROGRAM\" | bash\n"
        )
    }
    if not compare_pr_automation_collection(
        {"ci.yml": referenced_workflow},
        {"ci.yml": referenced_workflow},
        {"setup/action.yml": safe_action},
        {"setup/action.yml": safe_action},
        safe_automation,
        opaque_shell_stdin,
        "self-test automation directory",
    ):
        failures.append("opaque shell stdin program edit was not rejected")

    ci_publish_contract = PUBLISH_CONTROL_CONTRACTS["CI workflow"]
    publish_workflow = (
        "name: Publish fixture\n"
        "on: [push]\n"
        "jobs:\n"
        "  latest-release:\n"
        + ci_publish_contract["latest-release"]["needs"]
        + ci_publish_contract["latest-release"]["if"]
        + "    runs-on: ubuntu-latest\n"
        + "    steps:\n"
        + "      - run: echo latest\n"
        + "  docker:\n"
        + ci_publish_contract["docker"]["needs"]
        + ci_publish_contract["docker"]["if"]
        + "    runs-on: ubuntu-latest\n"
        + "    steps:\n"
        + "      - run: echo docker\n"
    )
    if validate_publish_control_contract(publish_workflow, "CI workflow"):
        failures.append("valid ARM64 publication dependency controls were rejected")

    benign_publish_edit = publish_workflow.replace("echo latest", "echo updated")
    if compare_pr_publish_control_contract(
        publish_workflow,
        benign_publish_edit,
        "CI workflow",
    ):
        failures.append("benign publishing job implementation edit was rejected")

    changed_publish_needs = publish_workflow.replace(
        ci_publish_contract["latest-release"]["needs"],
        "    needs: [test, build-binaries]\n",
        1,
    )
    if not validate_publish_control_contract(changed_publish_needs, "CI workflow"):
        failures.append("removed ARM64 publication dependency was not rejected")
    if not compare_pr_publish_control_contract(
        publish_workflow,
        changed_publish_needs,
        "CI workflow",
    ):
        failures.append(
            "merge-base comparison allowed an ARM64 publication dependency edit"
        )

    duplicate_publish_needs = publish_workflow.replace(
        ci_publish_contract["latest-release"]["needs"],
        ci_publish_contract["latest-release"]["needs"]
        + "    needs: [test, build-binaries]\n",
        1,
    )
    if not validate_publish_control_contract(duplicate_publish_needs, "CI workflow"):
        failures.append("duplicate publication needs field was not rejected")

    return failures


def load_workflow(path: Path, label: str) -> tuple[str | None, list[str]]:
    contents, failures = load_text(path)
    if failures:
        return None, failures
    assert contents is not None
    if "\x00" in contents:
        return None, [f"{label} contains a NUL byte"]
    return contents, []


def load_workflow_directory(
    path: Path,
    label: str,
) -> tuple[dict[str, str], list[str]]:
    """Load direct GitHub workflow files without following filesystem aliases."""

    if path.is_symlink() or not path.is_dir():
        return {}, [f"{label} must be a non-symlink directory"]

    workflows: dict[str, str] = {}
    errors: list[str] = []
    try:
        entries = sorted(path.iterdir(), key=lambda entry: entry.name)
    except OSError as error:
        return {}, [f"cannot list {label}: {error}"]

    for entry in entries:
        if entry.suffix not in {".yml", ".yaml"}:
            continue
        if WORKFLOW_FILENAME.fullmatch(entry.name) is None:
            errors.append(f"{label} contains unsupported workflow name {entry.name!r}")
            continue
        if entry.is_symlink() or not entry.is_file():
            errors.append(f"{label}/{entry.name} must be a non-symlink regular file")
            continue
        contents, failures = load_workflow(entry, f"{label}/{entry.name}")
        errors.extend(failures)
        if not failures:
            assert contents is not None
            workflows[entry.name] = contents
    return workflows, errors


def load_action_directory(
    path: Path,
    label: str,
    *,
    ignored_suffixes: frozenset[str] = frozenset(),
    ignored_directories: frozenset[str] = frozenset(),
) -> tuple[dict[str, str], list[str]]:
    """Load every repo-local action file without following filesystem aliases."""

    if path.is_symlink() or not path.is_dir():
        return {}, [f"{label} must be a non-symlink directory"]

    actions: dict[str, str] = {}
    errors: list[str] = []
    directories = [path]
    while directories:
        directory = directories.pop()
        try:
            entries = sorted(directory.iterdir(), key=lambda entry: entry.name)
        except OSError as error:
            errors.append(f"cannot list {label}: {error}")
            continue
        for entry in entries:
            relative = entry.relative_to(path).as_posix()
            if entry.is_symlink():
                errors.append(f"{label}/{relative} must not be a symlink")
            elif entry.is_dir():
                if entry.name not in ignored_directories:
                    directories.append(entry)
            elif entry.is_file():
                if entry.suffix.lower() in ignored_suffixes:
                    continue
                contents, failures = load_workflow(entry, f"{label}/{relative}")
                errors.extend(failures)
                if not failures:
                    assert contents is not None
                    actions[relative] = contents
            else:
                errors.append(f"{label}/{relative} must be a regular file or directory")
    return actions, errors


def load_automation_directory(
    path: Path,
    label: str,
) -> tuple[dict[str, str], list[str]]:
    """Load the approved repo-script roots with repository-relative keys."""

    if path.is_symlink() or not path.is_dir():
        return {}, [f"{label} must be a non-symlink directory"]
    automation: dict[str, str] = {}
    errors: list[str] = []
    for root_name in APPROVED_AUTOMATION_ROOTS:
        root = path / root_name.rstrip("/")
        loaded, failures = load_action_directory(
            root,
            f"{label}/{root_name}",
            ignored_suffixes=IGNORED_AUTOMATION_SUFFIXES,
            ignored_directories=IGNORED_AUTOMATION_DIRECTORIES,
        )
        errors.extend(failures)
        for name, contents in loaded.items():
            automation[f"{root_name}{name}"] = contents

    # Build-dispatcher manifests live at the repository root rather than in an
    # approved script root, but a workflow step reaches their recipes through
    # `make`/`npm run`, so they are scanned and frozen alongside the scripts.
    for manifest_name in sorted(DISPATCHER_MANIFEST_NAMES):
        manifest = path / manifest_name
        if manifest.is_symlink():
            errors.append(f"{label}/{manifest_name} must not be a symlink")
            continue
        if not manifest.is_file():
            continue
        contents, failures = load_workflow(manifest, f"{label}/{manifest_name}")
        errors.extend(failures)
        if not failures:
            assert contents is not None
            automation[manifest_name] = contents

    # npm/pnpm/yarn workspace selectors dispatch through the selected nested
    # package.json, not the root manifest. Load every available workspace
    # manifest so resolution can never silently fall back to package.json.
    try:
        workspace_manifests = sorted(path.rglob("package.json"))
    except OSError as error:
        errors.append(f"cannot enumerate {label} workspace manifests: {error}")
        workspace_manifests = []
    for manifest in workspace_manifests:
        relative = manifest.relative_to(path).as_posix()
        if relative == "package.json" or relative.startswith(".git/"):
            continue
        if manifest.is_symlink() or not manifest.is_file():
            errors.append(f"{label}/{relative} must be a non-symlink regular file")
            continue
        contents, failures = load_workflow(manifest, f"{label}/{relative}")
        errors.extend(failures)
        if not failures:
            assert contents is not None
            automation[relative] = contents
    return automation, errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=Path("Cross.toml"))
    parser.add_argument("--cargo-config", type=Path, default=Path("Cargo.toml"))
    parser.add_argument(
        "--cargo-tool-config",
        type=Path,
        default=Path(".cargo/config.toml"),
    )
    parser.add_argument(
        "--cargo-legacy-config",
        type=Path,
        default=Path(".cargo/config"),
    )
    parser.add_argument(
        "--ci-workflow", type=Path, default=Path(".github/workflows/ci.yml")
    )
    parser.add_argument(
        "--release-workflow",
        type=Path,
        default=Path(".github/workflows/release.yml"),
    )
    parser.add_argument("--merge-base-ci-workflow", type=Path)
    parser.add_argument("--proposed-ci-workflow", type=Path)
    parser.add_argument("--merge-base-release-workflow", type=Path)
    parser.add_argument("--proposed-release-workflow", type=Path)
    parser.add_argument(
        "--workflows-dir",
        type=Path,
        default=Path(".github/workflows"),
    )
    parser.add_argument(
        "--actions-dir",
        type=Path,
        default=Path(".github/actions"),
    )
    parser.add_argument("--automation-dir", type=Path, default=Path("."))
    parser.add_argument("--merge-base-workflows-dir", type=Path)
    parser.add_argument("--proposed-workflows-dir", type=Path)
    parser.add_argument("--merge-base-actions-dir", type=Path)
    parser.add_argument("--proposed-actions-dir", type=Path)
    parser.add_argument("--merge-base-automation-dir", type=Path)
    parser.add_argument("--proposed-automation-dir", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    failures = self_test() if args.self_test else []

    cross_config, cross_failures = load_toml(args.config)
    failures.extend(cross_failures)
    if not cross_failures:
        failures.extend(validate_cross_configuration(cross_config))

    cargo_config, cargo_failures = load_toml(args.cargo_config)
    failures.extend(cargo_failures)
    if not cargo_failures:
        failures.extend(validate_cargo_configuration(cargo_config))

    cargo_tool_config, cargo_tool_failures = load_toml(args.cargo_tool_config)
    failures.extend(cargo_tool_failures)
    if not cargo_tool_failures:
        failures.extend(validate_cargo_tool_configuration(cargo_tool_config))
    if args.cargo_legacy_config.exists():
        failures.append(
            f"legacy Cargo config {args.cargo_legacy_config} is forbidden; use only "
            "the allowlisted .cargo/config.toml"
        )

    workflow_inputs = (
        (args.ci_workflow, *WORKFLOW_CONTRACTS[0]),
        (args.release_workflow, *WORKFLOW_CONTRACTS[1]),
    )
    for (
        workflow_path,
        label,
        job_name,
        expected_hash,
        expected_env_hash,
        expected_trigger_hash,
    ) in workflow_inputs:
        contents, workflow_failures = load_workflow(workflow_path, label)
        failures.extend(workflow_failures)
        if not workflow_failures:
            assert contents is not None
            failures.extend(
                validate_workflow_contract(
                    contents,
                    label,
                    job_name,
                    expected_hash,
                    expected_env_hash,
                    expected_trigger_hash,
                )
            )

    workflows, workflow_directory_failures = load_workflow_directory(
        args.workflows_dir,
        "workflow directory",
    )
    failures.extend(workflow_directory_failures)
    if not workflow_directory_failures:
        failures.extend(validate_workflow_collection(workflows, "workflow directory"))

    actions, action_directory_failures = load_action_directory(
        args.actions_dir,
        "local-action directory",
    )
    failures.extend(action_directory_failures)
    if not action_directory_failures:
        failures.extend(validate_action_collection(actions, "local-action directory"))

    automation, automation_directory_failures = load_automation_directory(
        args.automation_dir,
        "automation directory",
    )
    failures.extend(automation_directory_failures)
    if (
        not workflow_directory_failures
        and not action_directory_failures
        and not automation_directory_failures
    ):
        failures.extend(
            validate_automation_collection(
                workflows,
                actions,
                automation,
                "automation directory",
            )
        )

    pr_paths = (
        args.merge_base_ci_workflow,
        args.proposed_ci_workflow,
        args.merge_base_release_workflow,
        args.proposed_release_workflow,
        args.merge_base_workflows_dir,
        args.proposed_workflows_dir,
        args.merge_base_actions_dir,
        args.proposed_actions_dir,
        args.merge_base_automation_dir,
        args.proposed_automation_dir,
    )
    if any(path is not None for path in pr_paths) and not all(
        path is not None for path in pr_paths
    ):
        failures.append(
            "all merge-base/proposed workflow, action, and automation arguments "
            "must be supplied together"
        )
    elif all(path is not None for path in pr_paths):
        comparisons = (
            (
                args.merge_base_ci_workflow,
                args.proposed_ci_workflow,
                WORKFLOW_CONTRACTS[0],
            ),
            (
                args.merge_base_release_workflow,
                args.proposed_release_workflow,
                WORKFLOW_CONTRACTS[1],
            ),
        )
        for baseline_path, proposed_path, contract in comparisons:
            assert baseline_path is not None and proposed_path is not None
            label, job_name, _, _, _ = contract
            baseline, baseline_failures = load_workflow(baseline_path, label)
            proposed, proposed_failures = load_workflow(proposed_path, label)
            failures.extend(baseline_failures)
            failures.extend(proposed_failures)
            if not baseline_failures and not proposed_failures:
                assert baseline is not None and proposed is not None
                failures.extend(
                    compare_pr_workflow_job(baseline, proposed, label, job_name)
                )

        assert args.merge_base_workflows_dir is not None
        assert args.proposed_workflows_dir is not None
        merge_base_workflows, merge_base_directory_failures = load_workflow_directory(
            args.merge_base_workflows_dir,
            "merge-base workflow directory",
        )
        proposed_workflows, proposed_directory_failures = load_workflow_directory(
            args.proposed_workflows_dir,
            "proposed workflow directory",
        )
        failures.extend(merge_base_directory_failures)
        failures.extend(proposed_directory_failures)
        if not merge_base_directory_failures and not proposed_directory_failures:
            failures.extend(
                compare_pr_workflow_collection(
                    merge_base_workflows,
                    proposed_workflows,
                    "workflow directory",
                )
            )

        assert args.merge_base_actions_dir is not None
        assert args.proposed_actions_dir is not None
        merge_base_actions, merge_base_action_failures = load_action_directory(
            args.merge_base_actions_dir,
            "merge-base local-action directory",
        )
        proposed_actions, proposed_action_failures = load_action_directory(
            args.proposed_actions_dir,
            "proposed local-action directory",
        )
        failures.extend(merge_base_action_failures)
        failures.extend(proposed_action_failures)
        if not merge_base_action_failures and not proposed_action_failures:
            failures.extend(
                compare_pr_action_collection(
                    merge_base_actions,
                    proposed_actions,
                    "local-action directory",
                )
            )

        assert args.merge_base_automation_dir is not None
        assert args.proposed_automation_dir is not None
        merge_base_automation, merge_base_automation_failures = (
            load_automation_directory(
                args.merge_base_automation_dir,
                "merge-base automation directory",
            )
        )
        proposed_automation, proposed_automation_failures = load_automation_directory(
            args.proposed_automation_dir,
            "proposed automation directory",
        )
        failures.extend(merge_base_automation_failures)
        failures.extend(proposed_automation_failures)
        if not any(
            (
                merge_base_directory_failures,
                proposed_directory_failures,
                merge_base_action_failures,
                proposed_action_failures,
                merge_base_automation_failures,
                proposed_automation_failures,
            )
        ):
            failures.extend(
                compare_pr_automation_collection(
                    merge_base_workflows,
                    proposed_workflows,
                    merge_base_actions,
                    proposed_actions,
                    merge_base_automation,
                    proposed_automation,
                    "automation directory",
                )
            )

    for failure in failures:
        print(f"::error::{failure}", file=sys.stderr)
    if failures:
        return 1

    print(
        "ARM64 Cross 0.2.5/Cargo configuration and isolated workflow, "
        "local-action, and referenced-script invocations match the complete "
        "trusted policy."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
