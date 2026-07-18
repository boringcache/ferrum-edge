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
ISOLATED_PLANNER_LAUNCHER = (
    "python3 -I -c 'import runpy, sys; "
    "sys.path.insert(0, sys.argv.pop(1)); "
    "sys.argv[0] = sys.argv.pop(1); "
    'runpy.run_path(sys.argv[0], run_name="__main__")\' '
    '"$planner_dir" "$planner"'
)
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
# pull_request_target guard compares those blocks with the current trusted base
# tip, so a stale branch cannot restore a removed Cross surface while unrelated
# workflow edits remain allowed. The guard separately uses HEAD...FETCH_HEAD
# only to decide whether the PR itself modified the protected policy files.
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

DOCKER_ARTIFACT_MATRIX = (
    "    strategy:\n"
    "      fail-fast: false\n"
    "      matrix:\n"
    "        include:\n"
    "          - platform: linux/amd64\n"
    "            binary_target: x86_64-unknown-linux-gnu\n"
    "            binary_asset: ferrum-edge-linux-x86_64\n"
    "            cni_asset: ferrum-cni-linux-x86_64\n"
    "            arch_dir: amd64\n"
    "          - platform: linux/arm64\n"
    "            binary_target: aarch64-unknown-linux-gnu\n"
    "            binary_asset: ferrum-edge-linux-aarch64\n"
    "            cni_asset: ferrum-cni-linux-aarch64\n"
    "            arch_dir: arm64\n"
)
DOCKER_CONTEXT_STEP = (
    "      - name: Prepare Docker context\n"
    "        run: |\n"
    "          mkdir -p docker-context/bin/${{ matrix.arch_dir }}\n"
    "          cp downloaded-artifacts/${{ matrix.binary_asset }} "
    "docker-context/bin/${{ matrix.arch_dir }}/ferrum-edge\n"
    "          cp downloaded-artifacts/${{ matrix.cni_asset }} "
    "docker-context/bin/${{ matrix.arch_dir }}/ferrum-cni\n"
    "          cp Dockerfile.release docker-context/Dockerfile\n"
)
# The Docker jobs never name the protected ARM64 artifact literally. They
# select it through matrix values that the download step and the context step
# interpolate, so freezing the job's `needs`/`if` alone would still let a pull
# request point the `linux/arm64` row at the x86_64 artifact and publish an
# ARM64 image containing the wrong binary. The matrix row and both consuming
# steps are therefore frozen as one artifact-selection contract.
PUBLISH_ARTIFACT_STEP_CONTRACTS = {
    "CI workflow": {
        "docker": {
            "Download Linux binary": (
                "      - name: Download Linux binary\n"
                "        uses: actions/download-artifact"
                "@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8\n"
                "        with:\n"
                "          name: binary-${{ matrix.binary_target }}\n"
                "          path: downloaded-artifacts\n"
            ),
            "Prepare Docker context": DOCKER_CONTEXT_STEP,
        },
    },
    "release workflow": {
        "docker": {
            "Download Linux binary": (
                "      - name: Download Linux binary\n"
                "        uses: actions/download-artifact"
                "@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8\n"
                "        with:\n"
                "          name: release-binaries-${{ matrix.binary_target }}\n"
                "          path: downloaded-artifacts\n"
            ),
            "Prepare Docker context": DOCKER_CONTEXT_STEP,
        },
    },
}

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
            "strategy": DOCKER_ARTIFACT_MATRIX,
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
            "strategy": DOCKER_ARTIFACT_MATRIX,
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
SHELL_INTERPRETER_NAMES = frozenset(
    {"ash", "bash", "busybox", "dash", "ksh", "pwsh", "powershell", "sh", "zsh"}
)
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
WORKFLOW_FILENAME = re.compile(r"^[A-Za-z0-9._+@~ -]+\.(?:yml|yaml)$")
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
# Directory prefixes whose contents are produced by a build rather than
# committed. None of them is ignored by git, so a pull request can commit a
# script under any of them. They therefore confer NO exemption on their own:
# only the exact build outputs enumerated in `GENERATED_COMMAND_PATHS` may run
# from outside the scanned automation roots. The tuple is retained so the
# self-test can assert that no prefix is silently promoted back into an
# open namespace.
GENERATED_SCRIPT_PREFIXES = (
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
    r"(?P<quote>['\"]?)(?P<path>\./[A-Za-z0-9._+@~ /-]+)"
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
    r"(?:(?:bash|sh|dash|zsh|ksh|ash|python(?:[0-9.]+)?|pypy[0-9]*|ruby|node|"
    r"perl|php|Rscript|deno|bun|pwsh|powershell|busybox\s+sh|awk\s+-f)"
    r"(?:\s+--?[^\s]+)*\s*(?:[0-9]+)?(?<!<)<(?![<&])\s*"
    r"(?P<redirected>(?:\$(?:[A-Za-z_][A-Za-z0-9_]*|"
    r"\{[A-Za-z_][A-Za-z0-9_]*\})/)?"
    r"(?:'[A-Za-z0-9._+@~ /-]+'|\"[A-Za-z0-9._+@~ /-]+\"|"
    r"[A-Za-z0-9._+@~-]+(?:/[A-Za-z0-9._+@~-]+)+|"
    r"[A-Za-z0-9._+@~-]+\.(?:sh|bash|py|rb|pl|awk|php|R|js|mjs|cjs|ts|ps1)))|"
    r"(?P<interpreter>bash|sh|dash|zsh|ksh|ash|python(?:[0-9.]+)?|pypy[0-9]*|"
    r"ruby|node|perl|php|Rscript|deno|bun|pwsh|powershell|busybox\s+sh|"
    r"awk\s+-f|source|\.)"
    r"(?P<interpreter_options>(?:\s+--?[^\s]+)*)\s+"
    r"(?P<interpreted>(?:\$(?:[A-Za-z_][A-Za-z0-9_]*|"
    r"\{[A-Za-z_][A-Za-z0-9_]*\})/)?"
    r"(?:'[A-Za-z0-9._+@~ /-]+'|\"[A-Za-z0-9._+@~ /-]+\"|"
    r"[A-Za-z0-9._+@~-]+(?:/[A-Za-z0-9._+@~-]+)+|"
    r"[A-Za-z0-9._+@~-]+\.(?:sh|bash|py|rb|pl|awk|php|R|js|mjs|cjs|ts|ps1)))|"
    r"(?P<direct>(?:'\./[A-Za-z0-9._+@~ /-]+'|"
    r"\"\./[A-Za-z0-9._+@~ /-]+\"|\./[A-Za-z0-9._+@~/-]+))|"
    r"(?P<bare>(?:'[A-Za-z0-9._+@~ /-]+\.(?:sh|bash|py|rb|pl|awk|php|R|"
    r"js|mjs|cjs|ts|ps1)'|\"[A-Za-z0-9._+@~ /-]+\.(?:sh|bash|py|rb|pl|"
    r"awk|php|R|js|mjs|cjs|ts|ps1)\"|[A-Za-z0-9._+@~-]+"
    r"(?:/[A-Za-z0-9._+@~-]+)+\.(?:sh|bash|py|rb|pl|awk|php|R|js|mjs|"
    r"cjs|ts|ps1))))"
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
    r"(?P<interpreter>bash|sh|dash|zsh|ksh|ash|python(?:[0-9.]+)?|"
    r"pypy[0-9]*|pwsh|powershell)\b"
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
    r"(?:(?:\bchild_process|require\(['\"](?:node:)?child_process['\"]\))\s*\.\s*"
    r"(?:exec|execFile|fork|spawn)(?:Sync)?\s*\(|"
    # A destructured or renamed binding — `const {execSync} = require(...)`,
    # `import {spawn as run} from 'node:child_process'` — reaches the same
    # dispatcher through a name the member-call form never sees. Importing the
    # module at all is therefore the dispatch surface.
    r"require\s*\(\s*['\"](?:node:)?child_process['\"]\s*\)|"
    r"(?:^|[\s;{(])(?:import|export)\b[^\n;]*?['\"](?:node:)?child_process['\"]|"
    r"\bawait\s+import\s*\(\s*['\"](?:node:)?child_process['\"]\s*\)|"
    # The bare dispatcher names a destructured binding introduces.
    r"(?<![A-Za-z0-9_$.])(?:exec|execFile|fork|spawn)(?:Sync)?\s*\(|"
    r"\b(?:Bun\.spawn|Deno\.Command)\s*\(|"
    r"\b(?:Process\.spawn|IO\.popen|Open3\.[A-Za-z_]+|system|exec)\s*\(|"
    r"\b(?:os\.execute|io\.popen)\s*\()",
    re.MULTILINE,
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
# `cross${IFS}build` and `cargo${IFS}+stable${IFS}cross` reach exactly the same
# executable and subcommand words as literal whitespace, because the shell
# splits the expanded word before it dispatches the command. Every expansion is
# therefore also evaluated as if it expanded to a word separator, which covers
# `$IFS`, `${IFS}`, `${IFS:0:1}`, a command substitution, and any other
# expansion placed at an executable or Cross-subcommand boundary.
WORD_SPLIT_EXPANSION = re.compile(
    r"\$\{[^{}\n]*\}|\$\([^()\n]*\)|`[^`\n]*`|"
    r"\$[A-Za-z_][A-Za-z0-9_]*|\$[0-9@*#?$!-]"
)
MAXIMUM_WORD_SPLIT_EXPANSIONS = 16
# An inline program handed to a non-shell interpreter dispatches commands the
# shell scanner never sees, such as `perl -e 'system("cross build ...")'` or
# `node -e ...`. Each interpreter is mapped to the options whose operand is
# program source. Python source is parsed by the existing AST reader; every
# other language's inline source is treated as opaque command text.
PYTHON_INLINE_SOURCE_OPTIONS = ("-c",)
INLINE_SOURCE_OPTIONS = {
    "awk": (),
    "bun": ("-e", "--eval"),
    "elixir": ("-e", "--eval"),
    "erl": ("-eval",),
    "gawk": (),
    "groovy": ("-e",),
    "julia": ("-e", "--eval"),
    "lua": ("-e",),
    "luajit": ("-e",),
    "mawk": (),
    "node": ("-e", "--eval", "-p", "--print"),
    "nodejs": ("-e", "--eval", "-p", "--print"),
    "osascript": ("-e",),
    "perl": ("-e", "-E"),
    "php": ("-r",),
    "R": ("-e",),
    "Rscript": ("-e",),
    "ruby": ("-e",),
    "scala": ("-e",),
    "tclsh": (),
}
# `deno eval '<source>'` takes the program as a subcommand operand rather than
# as the operand of an option.
INLINE_SOURCE_SUBCOMMANDS = {"deno": ("eval",)}
# awk-family and Tcl interpreters take the program as their first non-option
# operand unless a `-f` script file supplies it instead.
INLINE_OPERAND_INTERPRETERS = frozenset({"awk", "gawk", "mawk", "tclsh"})
FOREIGN_STRING_LITERAL = re.compile(
    r"'((?:[^'\\]|\\.)*)'|\"((?:[^\"\\]|\\.)*)\"|`((?:[^`\\]|\\.)*)`"
)
# Linking, copying, or moving the Cross binary under another name produces an
# executable that dispatches Cross without the literal token ever occupying an
# executable slot (`ln -s ~/.cargo/bin/cross bin/cr && cr build ...`). `cross`
# must be the final path component so `docs/cross.md` and `cross-notes.txt`
# remain ordinary data.
CROSS_ALIAS_COMMANDS = frozenset({"cp", "install", "link", "ln", "mv", "rsync"})
CROSS_PATH_COMPONENT = re.compile(r"(?<![A-Za-z0-9_.-])cross(?![A-Za-z0-9_.-])")
MAXIMUM_TRACKED_SHIMS = 64
MAXIMUM_INLINE_PROGRAM_DEPTH = 4
_inline_program_depth = 0
# A lowercase `$cmd` is exactly as executable as `$CMD` once the enclosing
# shell program assigns it, so the names a program binds are tracked while that
# program is scanned and consulted when inline interpreter source is read.
SHELL_PARAMETER_REFERENCE = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)")
SHELL_ASSIGNMENT_TOKEN = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)=.*", re.DOTALL)
WHOLE_SHELL_PARAMETER = re.compile(r"\s*\$[A-Za-z_][A-Za-z0-9_]*\s*")
_shell_assigned_names: frozenset[str] = frozenset()
# A remote `uses:` step runs code this repository does not own, so any remote
# action able to reach Cross is an unreviewable build-execution surface.
# `actions-rs/cargo` with `use-cross: true` documents that it runs the `cross`
# executable in place of `cargo`.
CROSS_CAPABLE_ACTION_INPUTS = frozenset(
    {
        "cross",
        "crossargs",
        "crossbuild",
        "crossimage",
        "crosstool",
        "crossversion",
        "usecross",
        "usecrossbuild",
    }
)
# Isolating a release download to an exact artifact name requires naming the
# protected target in that artifact name. `actions/upload-artifact` and
# `actions/download-artifact` only move files between jobs and cannot start a
# build, so — and only when pinned to a full commit SHA — the target string in
# an artifact `name`/`path`/`pattern` is not a build-execution surface. The
# Cross image, a `cross` executable token, and every Cross-enabling input key
# remain surfaces for these actions like any other.
ARTIFACT_TRANSFER_ACTION = re.compile(
    r"^actions/(?:up|down)load-artifact@[0-9a-f]{40}$"
)
ARTIFACT_INPUT_KEYS = frozenset({"name", "path", "pattern"})
# `with:` only introduces the input mapping, so it does not itself widen the
# closed artifact carve-out to a flow mapping's other keys.
ARTIFACT_CONTAINER_KEYS = frozenset({"with"})
WORKFLOW_EXPRESSION = re.compile(r"\$\{\{(?P<body>[^{}]*)\}\}")
# Only these expression scopes hold values a workflow author writes, so only
# these can smuggle the protected target into a remote-action input.
RESOLVABLE_EXPRESSION_SCOPES = (
    "matrix.",
    "env.",
    "inputs.",
    "github.event.inputs.",
)
TARGET_ARGUMENT_FLAG = re.compile(r"--target(?:\s|=|$)")
REMOTE_ACTION_FIELD = re.compile(
    r"^(?P<lead> *)(?P<dash>-\s+)?(?:uses|'uses'|\"uses\")\s*:\s*(?P<value>.*)$"
)
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
    r"(?P<path>'[^'\n;&|]+'|\"[^\"\n;&|]+\"|[^\s'\";&|]+)"
)
DISPATCHER_WORKSPACE = re.compile(
    r"(?:^|\s)(?:-w|--workspace)(?:=|\s+)"
    r"(?P<path>'[^'\n;&|]+'|\"[^\"\n;&|]+\"|[^\s'\";&|]+)"
)
DISPATCHER_WORKSPACE_OPTION = re.compile(
    r"(?:^|\s)(?:-w|--workspace)(?==|\s|$)|(?:^|\s)-w[^\s=]+"
)
DISPATCHER_ALL_WORKSPACES = re.compile(r"(?:^|\s)--workspaces(?:\s|$)")
DISPATCHER_MANIFEST_OPTION = re.compile(
    r"(?:^|\s)(?:-f|--file|--makefile|--justfile|--taskfile)(?:=|\s+)"
    r"(?P<path>'[^'\n;&|]+'|\"[^\"\n;&|]+\"|[^\s'\";&|]+)"
)
CD_COMMAND = re.compile(
    r"(?:^\s*|(?:&&|\|\||;;|;|&|\|)\s*|\{\s+|\b(?:then|do|else)\s+)"
    r"cd(?:\s+--)?\s+"
    r"(?P<path>'[^'\n;&|]+'|\"[^\"\n;&|]+\"|[^\s'\";&|]+)"
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


def extract_job_step_block(
    contents: str,
    source: str,
    job_name: str,
    step_name: str,
    *,
    required: bool,
) -> tuple[str | None, list[str]]:
    """Return the exact text of one named step inside a job's `steps:` list."""

    steps_block, failures = extract_job_field_block(
        contents,
        source,
        job_name,
        "steps",
        required=required,
    )
    if failures or steps_block is None:
        return None, failures

    lines = steps_block.splitlines(keepends=True)
    step_starts = [
        index for index, line in enumerate(lines) if re.match(r"^      - ", line)
    ]
    matches = [
        index
        for index in step_starts
        if lines[index].rstrip("\r\n") == f"      - name: {step_name}"
    ]
    if not matches and not required:
        return None, []
    if len(matches) != 1:
        return None, [
            f"{source} job {job_name!r} must contain step {step_name!r} "
            "exactly once"
        ]

    start = matches[0]
    end = next((index for index in step_starts if index > start), len(lines))
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
    for job_name, steps in PUBLISH_ARTIFACT_STEP_CONTRACTS.get(source, {}).items():
        for step_name, expected in steps.items():
            actual, failures = extract_job_step_block(
                contents,
                source,
                job_name,
                step_name,
                required=True,
            )
            errors.extend(failures)
            if not failures and actual != expected:
                errors.append(
                    f"{source} job {job_name!r} step {step_name!r} differs from "
                    "the trusted ARM64 publication artifact-selection contract"
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
    for job_name, steps in PUBLISH_ARTIFACT_STEP_CONTRACTS.get(source, {}).items():
        for step_name in steps:
            baseline, baseline_failures = extract_job_step_block(
                merge_base_contents,
                f"merge-base {source}",
                job_name,
                step_name,
                required=False,
            )
            proposed, proposed_failures = extract_job_step_block(
                proposed_contents,
                f"proposed {source}",
                job_name,
                step_name,
                required=False,
            )
            errors.extend(baseline_failures)
            errors.extend(proposed_failures)
            if not baseline_failures and not proposed_failures:
                if baseline != proposed:
                    errors.append(
                        f"{source} job {job_name!r} ARM64 artifact-selection step "
                        f"{step_name!r} cannot be changed by a pull request"
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


def word_splitting_variants(value: str) -> tuple[str, ...]:
    """Expose the words a shell builds when an expansion splits a command word.

    An unquoted expansion is subject to word splitting, so `cross${IFS}build`
    dispatches `cross` with a `build` operand even though the source contains
    no whitespace between them. Each expansion is therefore also read as a word
    separator, one at a time and then all together, which covers a split at the
    executable boundary, at the Cargo toolchain selector, and at the Cross
    subcommand boundary alike.
    """

    if "cross" not in value and "cargo" not in value:
        # Word splitting only matters here when it can assemble a Cross
        # executable or subcommand out of literal text that is already present.
        return ()
    spans = [match.span() for match in WORD_SPLIT_EXPANSION.finditer(value)]
    if not spans or len(spans) > MAXIMUM_WORD_SPLIT_EXPANSIONS:
        return ()
    variants = [value[:start] + " " + value[end:] for start, end in spans]
    if len(spans) > 1:
        parts: list[str] = []
        cursor = 0
        for start, end in spans:
            parts.extend((value[cursor:start], " "))
            cursor = end
        parts.append(value[cursor:])
        variants.append("".join(parts))
    return tuple(
        dict.fromkeys(variant for variant in variants if variant != value)
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


ENV_SPLIT_STRING_OPTIONS = ("--split-string", "-S")


def expand_env_split_strings(tokens: tuple[str, ...]) -> tuple[str, ...]:
    """Split `env -S`/`--split-string` operands into the argv they become.

    `env -S 'cross build --target ...'` is one shell word but a full argv by the
    time the kernel runs it, so discarding the operand as an ordinary option
    argument hides the executable. Joined (`-Scross build ...`,
    `--split-string=cross build ...`) and separated spellings all split here.
    """

    start = next(
        (
            index
            for index, token in enumerate(tokens)
            if tool_name(token) == "env"
        ),
        None,
    )
    if start is None:
        return tokens
    expanded = list(tokens[: start + 1])
    index = start + 1
    changed = False
    while index < len(tokens):
        token = tokens[index]
        operand: str | None = None
        consumed = 1
        for option in ENV_SPLIT_STRING_OPTIONS:
            if token == option:
                if index + 1 < len(tokens):
                    operand = tokens[index + 1]
                    consumed = 2
                break
            if token.startswith(f"{option}="):
                operand = token[len(option) + 1 :]
                break
            if option == "-S" and token.startswith("-S") and len(token) > 2:
                operand = token[2:]
                break
        if operand is None:
            expanded.append(token)
            index += 1
            continue
        words = shell_tokens(operand)
        # An untokenizable split string stays one word rather than vanishing.
        expanded.extend(words if words is not None else (operand,))
        changed = True
        index += consumed
    return tuple(expanded) if changed else tokens


COMMAND_OPERAND_WRAPPERS = {
    "flock": frozenset(
        {"-w", "-E", "--wait", "--timeout", "--conflict-exit-code"}
    ),
    "script": frozenset(
        {
            "-B",
            "-I",
            "-O",
            "-T",
            "-m",
            "-o",
            "-t",
            "--log-in",
            "--log-io",
            "--log-out",
            "--log-timing",
            "--logging-format",
            "--output-limit",
        }
    ),
}


def command_wrapper_operand(
    tokens: tuple[str, ...],
    index: int,
) -> tuple[int | None, str | None, bool]:
    """Return the process operand of a `flock`/`script`-style wrapper.

    Both run their operand as a real process, so nested Cross dispatch must be
    followed: `flock /tmp/lock cross build ...` hands over an argv after the
    lock operand, and `flock /tmp/lock -c '<script>'` or
    `script -c '<script>' /dev/null` hands over a shell program.
    """

    wrapper = tool_name(tokens[index])
    option_operands = COMMAND_OPERAND_WRAPPERS[wrapper]
    position = index + 1
    seen_lock = wrapper != "flock"
    while position < len(tokens):
        token = tokens[position]
        if token == "--":
            position += 1
            break
        if token in {"-c", "--command"}:
            if position + 1 >= len(tokens):
                return None, None, True
            return None, tokens[position + 1], False
        if token.startswith("--command="):
            return None, token[len("--command=") :], False
        if token.startswith("-c") and len(token) > 2:
            return None, token[2:], False
        if token in option_operands:
            position += 2
            continue
        if token.startswith("-"):
            position += 1
            continue
        if not seen_lock:
            # flock's first operand is the lock file, not the command.
            seen_lock = True
            position += 1
            continue
        break
    if wrapper == "script" or not seen_lock or position >= len(tokens):
        # A `script` positional operand is the typescript output file.
        return None, None, False
    return position, None, False


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


def interpreter_stdin_language(
    segment: tuple[str, ...],
    index: int,
) -> str | None:
    """Return the language a non-shell interpreter would read from stdin.

    Python and every other inline-source interpreter execute a program handed
    to them on stdin, so `python3 <<< '<source>'` is an executable surface in
    exactly the way `bash <<< '<script>'` is. Only an invocation that supplies
    no other program qualifies: inline source, a script operand, and `-m`
    all make stdin ordinary data instead of code.
    """

    executable = tool_name(segment[index])
    if PYTHON_INTERPRETER.fullmatch(executable):
        language = "python"
    elif executable in INLINE_SOURCE_OPTIONS or executable in (
        INLINE_SOURCE_SUBCOMMANDS
    ):
        language = "foreign"
    else:
        return None
    if executable in INLINE_OPERAND_INTERPRETERS:
        # An awk-family program is always an operand, never stdin.
        return None
    inline = inline_interpreter_programs(segment, index)
    if inline is not None and (inline[0] or inline[1]):
        return None
    for argument in segment[index + 1 :]:
        if argument == "-":
            return language
        if redirection_token(argument):
            break
        if argument.startswith("-"):
            if language == "python" and argument.lstrip("-").startswith("m"):
                return None
            continue
        if SHELL_ASSIGNMENT_TOKEN.fullmatch(argument):
            continue
        # A non-option operand names the script to run instead of stdin.
        return None
    return language


def shell_stdin_program(
    segment: tuple[str, ...],
) -> tuple[str | None, str | None, bool]:
    """Return the stdin program's language and source, or its opacity."""

    index, executes = executable_index(segment)
    if not executes or index >= len(segment):
        return None, None, False
    if tool_name(segment[index]) in SHELL_INTERPRETER_NAMES:
        language = "shell"
        command_program, option_opaque, reads_stdin = shell_invocation_mode(
            segment,
            index,
        )
        if command_program is not None or not reads_stdin:
            return None, None, False
        if option_opaque:
            return language, None, True
    else:
        stdin_language = interpreter_stdin_language(segment, index)
        if stdin_language is None:
            return None, None, False
        language = stdin_language

    arguments = segment[index + 1 :]
    for position, token in enumerate(arguments):
        if token == "<<<":
            if position + 1 >= len(arguments):
                return language, None, True
            program = arguments[position + 1]
            return (
                (language, None, True)
                if dynamic_shell_word(program)
                else (language, program, False)
            )
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
                    return language, None, True
                output = literal_producer_output(
                    tuple(arguments[body_start : end - 1])
                )
                return (language, output, output is None)

    return language, None, True


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


def shell_invocation_mode(
    tokens: tuple[str, ...],
    index: int,
) -> tuple[str | None, bool, bool]:
    """Return a shell `-c` program, option opacity, and stdin-code mode."""

    option_operands = {"-O", "-o", "--init-file", "--rcfile"}
    position = index + 1
    force_stdin = False
    while position < len(tokens):
        option = tokens[position]
        if option.isdigit() and position + 1 < len(tokens) and redirection_token(
            tokens[position + 1]
        ):
            position += 1
            option = tokens[position]
        if redirection_token(option):
            if position + 1 >= len(tokens):
                return None, True, False
            if "<" in option and (
                tokens[position + 1] == "<("
                or (
                    position + 2 < len(tokens)
                    and tokens[position + 1] == "<"
                    and tokens[position + 2] == "("
                )
            ):
                body_start = position + (
                    2 if tokens[position + 1] == "<(" else 3
                )
                depth = 1
                position = body_start
                while position < len(tokens) and depth:
                    if tokens[position] == "(":
                        depth += 1
                    elif tokens[position] == ")":
                        depth -= 1
                    position += 1
                if depth:
                    return None, True, False
                continue
            position += 2
            continue
        if option == "--":
            position += 1
            return None, False, force_stdin or position >= len(tokens)
        if option == "-":
            return None, False, True
        if not option.startswith("-"):
            # The first non-option is a script operand. Its later arguments
            # cannot turn an option-looking word such as `--locked` into `-c`.
            return None, False, force_stdin
        if option in option_operands:
            if position + 1 >= len(tokens):
                return None, True, False
            position += 2
            continue
        if not option.startswith("--") and "c" in option[1:]:
            if position + 1 >= len(tokens):
                return None, True, False
            return tokens[position + 1], False, False
        if not option.startswith("--") and "s" in option[1:]:
            force_stdin = True
        position += 1
    return None, False, True


def interpolated_inline_source(value: str) -> bool:
    """Return whether inline program source is assembled by the shell.

    Only the expansions a shell performs make the program unknown. A `$1`
    field reference in an awk program or a `$name` sigil in Perl or PHP source
    survives single quoting untouched, so an unqualified lowercase sigil alone
    is not treated as an expansion.

    Shell variables are case-sensitive but equally executable, so the uppercase
    convention cannot be the whole test. Two further forms are shell-generated
    whatever the name's case: source that is nothing but one parameter
    expansion (`python3 -c "$cmd"` carries no readable program at all), and a
    name the enclosing shell program itself assigns.
    """

    if re.search(r"\$\{|\$\(|`|\$[A-Z][A-Z0-9_]*(?![a-z])", value):
        return True
    if WHOLE_SHELL_PARAMETER.fullmatch(value):
        return True
    return any(
        name in _shell_assigned_names
        for name in SHELL_PARAMETER_REFERENCE.findall(value)
    )


def powershell_inline_program(
    tokens: tuple[str, ...],
    index: int,
) -> tuple[str | None, bool]:
    """Return a literal PowerShell inline program, or whether it is opaque.

    PowerShell accepts any unambiguous prefix of an option name, so `-c`,
    `-Comm`, and `-Command` all introduce inline source. An encoded command
    carries base64 source this scanner cannot read and therefore fails closed.
    """

    arguments = tokens[index + 1 :]
    position = 0
    while position < len(arguments):
        argument = arguments[position]
        if not argument.startswith(("-", "/")):
            break
        option = argument.lstrip("-/").split(":", maxsplit=1)[0].lower()
        if option and "encodedcommand".startswith(option):
            return None, True
        if option and "command".startswith(option):
            if position + 1 >= len(arguments):
                return None, True
            program = arguments[position + 1]
            return (
                (None, True)
                if interpolated_inline_source(program)
                else (program, False)
            )
        if option and "file".startswith(option):
            # A `-File` operand is a repository script resolved elsewhere.
            return None, False
        position += 1
    return None, False


POWERSHELL_CONTINUATION = re.compile(r"`\r?\n[ \t]*")
# PowerShell dispatches processes through cmdlets rather than through a bare
# command word, so the cmdlets that take a process operand are enumerated and
# their operand is read the way the shell scanner reads an executable word.
POWERSHELL_PROCESS_CMDLETS = frozenset(
    {"start-process", "start-job", "start-threadjob", "invoke-command"}
)
POWERSHELL_PROCESS_OPERAND_OPTIONS = frozenset(
    {"-filepath", "-scriptblock", "-command"}
)
# Source PowerShell assembles at runtime is unreadable here, exactly as
# `eval` is in a POSIX shell, so it fails closed instead of being skipped.
POWERSHELL_OPAQUE_DISPATCH = re.compile(
    r"(?<![A-Za-z0-9_-])(?:invoke-expression|iex)(?![A-Za-z0-9_-])"
    r"|\[(?:system\.)?diagnostics\.process\]\s*::\s*start"
    r"|new-object\s+[^\n]*?diagnostics\.process",
    re.IGNORECASE,
)
# PowerShell needs the `&` or `.` call operator to run a word it computed, so
# only those forms turn an expansion into an executable. A bare `$path` on its
# own is a value expression and must stay readable.
POWERSHELL_CALL_OPERATOR = re.compile(r"(?:^|[\s;({|])[&.]\s+(?P<target>\S+)")


def powershell_command_word_has_cross(
    words: tuple[str, ...],
) -> tuple[bool, bool]:
    """Read one PowerShell statement's command word. Returns (cross, opaque)."""

    index = 0
    while index < len(words) and words[index] in {
        "(",
        "{",
        "!",
        "if",
        "elseif",
        "else",
        "while",
        "foreach",
        "do",
        "try",
    }:
        index += 1
    if index >= len(words):
        return False, False
    if words[index].startswith("$") or "=" in words[index]:
        # A value expression or assignment dispatches nothing on its own;
        # PowerShell requires the `&`/`.` call operator to run a computed word.
        return False, False
    command = tool_name(words[index]).lower().strip("'\"")
    if command == "cross":
        return command_has_argument(words, index), False
    if command == "cargo":
        return cargo_cross_command(words, index), False
    if command not in POWERSHELL_PROCESS_CMDLETS:
        return False, False

    arguments = words[index + 1 :]
    position = 0
    operand: str | None = None
    while position < len(arguments):
        argument = arguments[position]
        if argument.lower() in POWERSHELL_PROCESS_OPERAND_OPTIONS:
            if position + 1 >= len(arguments):
                return False, True
            operand = arguments[position + 1]
            break
        if argument.startswith("-"):
            # Every other cmdlet parameter takes at most one operand.
            position += 2 if position + 1 < len(arguments) else 1
            continue
        operand = argument
        break
    if operand is None:
        return False, True
    if dynamic_shell_word(operand):
        return False, True
    return tool_name(operand).lower().strip("'\"") == "cross", False


def powershell_program_has_cross(
    program: str,
    source: str,
    *,
    include_opaque_shell_executable: bool,
) -> tuple[bool, list[str]]:
    """Inspect a PowerShell body for the Cross commands it can dispatch."""

    logical = POWERSHELL_CONTINUATION.sub(" ", program)
    errors: list[str] = []
    sensitive = False
    for raw_line in logical.splitlines():
        line = strip_shell_comment(raw_line)
        if not line.strip():
            continue
        if POWERSHELL_OPAQUE_DISPATCH.search(line):
            errors.append(
                f"{source} uses PowerShell dispatch this scanner cannot read"
            )
            continue
        call = POWERSHELL_CALL_OPERATOR.search(line)
        if call is not None:
            target = call.group("target")
            if dynamic_shell_word(target):
                errors.append(
                    f"{source} calls a computed PowerShell executable"
                )
                continue
            if tool_name(target).lower().strip("'\"") == "cross":
                sensitive = True
                continue
        for statement in re.split(r"[;|]|&&|\|\|", line):
            words = shell_tokens(statement)
            if words is None:
                if include_opaque_shell_executable and STANDALONE_CROSS.search(
                    statement
                ):
                    sensitive = True
                continue
            has_cross, opaque = powershell_command_word_has_cross(words)
            if has_cross:
                sensitive = True
            elif opaque:
                errors.append(
                    f"{source} has an unreadable PowerShell process operand"
                )
    return sensitive, errors


def inline_interpreter_programs(
    tokens: tuple[str, ...],
    index: int,
) -> tuple[tuple[tuple[str, str], ...], bool] | None:
    """Return the inline programs an interpreter executes, plus its opacity.

    Returns `None` when the command word is not a known inline-source
    interpreter, so ordinary commands keep their current handling. Otherwise
    every resolved `(language, source)` pair is returned together with a flag
    that is set when an inline-source operand is missing, dynamic, or in a form
    this scanner cannot resolve, which must fail closed.
    """

    executable = tool_name(tokens[index])
    if PYTHON_INTERPRETER.fullmatch(executable):
        options: tuple[str, ...] = PYTHON_INLINE_SOURCE_OPTIONS
        language = "python"
    elif executable in INLINE_SOURCE_OPTIONS or executable in (
        INLINE_SOURCE_SUBCOMMANDS
    ):
        options = INLINE_SOURCE_OPTIONS.get(executable, ())
        language = "foreign"
    else:
        return None

    arguments = list(tokens[index + 1 :])
    for terminator in ("|", "||", "&&", ";", ";;", "&", ")", "}"):
        if terminator in arguments:
            arguments = arguments[: arguments.index(terminator)]

    programs: list[tuple[str, str]] = []
    opaque = False

    def record(source: str, *, may_be_generated: bool = True) -> None:
        nonlocal opaque
        if may_be_generated and interpolated_inline_source(source):
            # A shell-generated inline program is an unknown executable surface.
            opaque = True
        else:
            programs.append((language, source))

    subcommands = INLINE_SOURCE_SUBCOMMANDS.get(executable, ())
    position = 0
    if subcommands:
        while position < len(arguments) and arguments[position].startswith("-"):
            position += 1
        if position < len(arguments) and arguments[position] in subcommands:
            position += 1
            while position < len(arguments) and arguments[position].startswith("-"):
                position += 1
            if position >= len(arguments):
                return (), True
            record(arguments[position])
            return tuple(programs), opaque

    if executable in INLINE_OPERAND_INTERPRETERS:
        if any(argument in {"-f", "--file", "--source"} for argument in arguments):
            # A `-f` script file is a repository path resolved elsewhere.
            return (), False
        operand = next(
            (
                argument
                for argument in arguments
                if not argument.startswith("-")
                and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", argument, re.DOTALL)
            ),
            None,
        )
        if operand is not None:
            # `$1` and `$NF` in an awk program are field references the shell
            # never expands, so an operand program is always read literally.
            record(operand, may_be_generated=False)
        return tuple(programs), opaque

    while position < len(arguments):
        argument = arguments[position]
        if argument in options:
            if position + 1 >= len(arguments):
                opaque = True
                break
            record(arguments[position + 1])
            position += 2
            continue
        joined = next(
            (
                option
                for option in options
                if option.startswith("--") and argument.startswith(f"{option}=")
            ),
            None,
        )
        if joined is not None:
            record(argument[len(joined) + 1 :])
            position += 1
            continue
        single_dash = [
            option
            for option in options
            if option.startswith("-") and not option.startswith("--")
        ]
        # A single-dash long option may carry its operand attached
        # (`erl -evalcode`), exactly as the double-dash form may with `=`.
        attached_long = next(
            (
                argument[len(option) :]
                for option in sorted(single_dash, key=len, reverse=True)
                if len(option) > 2
                and argument.startswith(option)
                and argument != option
            ),
            None,
        )
        if attached_long is not None:
            record(attached_long.removeprefix("="))
            position += 1
            continue
        letters = {option[1:] for option in single_dash if len(option) == 2}
        if letters and argument.startswith("-") and not argument.startswith("--"):
            cluster = argument[1:]
            offset = next(
                (
                    index
                    for index, letter in enumerate(cluster)
                    if letter in letters
                ),
                None,
            )
            if offset is not None:
                # A bundled short-option cluster such as `perl -we` ends with
                # the inline-source flag and takes the next word, but
                # `perl -e'print "safe"'` attaches its source to the same word.
                # Treating the attached form as a missing operand would freeze
                # ordinary inline programs instead of reading them.
                attached_source = cluster[offset + 1 :]
                if attached_source:
                    record(attached_source)
                    position += 1
                    continue
                if position + 1 >= len(arguments):
                    opaque = True
                    break
                record(arguments[position + 1])
                position += 2
                continue
        position += 1
    return tuple(programs), opaque


def foreign_inline_program_has_cross(
    source: str,
    *,
    include_opaque_shell_executable: bool,
) -> bool:
    """Inspect an inline non-Python program for the Cross commands it can run.

    The program's own language is not parsed. Instead every string literal it
    contains is read as command text, which resolves the ordinary
    `system("cross build ...")` shape, and any other process dispatch inside an
    inline program is treated as an unresolvable executable surface.
    """

    candidates = [source]
    for match in FOREIGN_STRING_LITERAL.finditer(source):
        literal = next(group for group in match.groups() if group is not None)
        candidates.append(literal)
        unescaped = re.sub(r"\\(.)", r"\1", literal)
        if unescaped != literal:
            candidates.append(unescaped)
    for candidate in candidates:
        if literal_command_text_has_cross(candidate) or (
            WRAPPED_LITERAL_CROSS.search(candidate)
        ):
            return True
    return include_opaque_shell_executable and bool(
        NON_PYTHON_PROCESS_DISPATCH.search(source)
    )


def inline_interpreter_has_cross(
    programs: tuple[tuple[str, str], ...],
    *,
    include_opaque_shell_executable: bool,
) -> bool:
    """Route each inline program through the reader that matches its language."""

    global _inline_program_depth

    if not programs:
        return False
    if _inline_program_depth >= MAXIMUM_INLINE_PROGRAM_DEPTH:
        # Inline programs may nest interpreters without bound, so a program
        # nested past this depth is an unresolvable executable surface.
        return include_opaque_shell_executable
    _inline_program_depth += 1
    try:
        for language, source in programs:
            if language == "python":
                commands, failures = python_command_scripts(
                    source,
                    "inline python program",
                    reject_dynamic_commands=True,
                )
                if any(
                    literal_command_text_has_cross(command) for command in commands
                ):
                    return True
                # Inline Python one-liners that shell scripts already use to
                # reshape JSON dispatch no processes at all, so an unresolvable
                # command only fails closed once the program itself mentions
                # Cross or the protected ARM64 target.
                if (
                    failures
                    and include_opaque_shell_executable
                    and (
                        STANDALONE_CROSS.search(source)
                        or TARGET in source
                        or CROSS_ENVIRONMENT.search(source)
                    )
                ):
                    return True
                continue
            if foreign_inline_program_has_cross(
                source,
                include_opaque_shell_executable=include_opaque_shell_executable,
            ):
                return True
    finally:
        _inline_program_depth -= 1
    return False


def token_command_has_cross(
    tokens: tuple[str, ...],
    *,
    include_opaque_shell_executable: bool,
    depth: int,
) -> bool:
    if depth > 8:
        return include_opaque_shell_executable
    tokens = expand_env_split_strings(tokens)
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
    if command in COMMAND_OPERAND_WRAPPERS:
        nested, program, opaque = command_wrapper_operand(tokens, index)
        if opaque:
            return include_opaque_shell_executable
        if program is not None:
            if dynamic_shell_word(program):
                return include_opaque_shell_executable
            return shell_program_has_cross(
                program,
                include_opaque_shell_executable=include_opaque_shell_executable,
                depth=depth + 1,
            )
        if nested is not None:
            return token_command_has_cross(
                tokens[nested:],
                include_opaque_shell_executable=include_opaque_shell_executable,
                depth=depth + 1,
            )
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
    if command.lower() in {"powershell", "pwsh"}:
        program, opaque = powershell_inline_program(tokens, index)
        if opaque:
            return include_opaque_shell_executable
        if program is None:
            return False
        # A PowerShell `-Command` operand is PowerShell, not POSIX shell.
        powershell_sensitive, powershell_errors = powershell_program_has_cross(
            program,
            "inline PowerShell program",
            include_opaque_shell_executable=include_opaque_shell_executable,
        )
        if powershell_sensitive:
            return True
        return bool(powershell_errors) and include_opaque_shell_executable
    if command in SHELL_INTERPRETER_NAMES:
        program, opaque, _ = shell_invocation_mode(tokens, index)
        if opaque:
            return include_opaque_shell_executable
        if program is not None:
            if dynamic_shell_word(program):
                return include_opaque_shell_executable
            return shell_program_has_cross(
                program,
                include_opaque_shell_executable=include_opaque_shell_executable,
                depth=depth + 1,
            )
        return False
    inline = inline_interpreter_programs(tokens, index)
    if inline is not None:
        programs, opaque = inline
        if opaque:
            return include_opaque_shell_executable
        return inline_interpreter_has_cross(
            programs,
            include_opaque_shell_executable=include_opaque_shell_executable,
        )
    return False


def shell_program_has_cross(
    value: str,
    *,
    include_opaque_shell_executable: bool = False,
    depth: int = 0,
    expand_word_splits: bool = True,
) -> bool:
    """Inspect literal shell command positions and nested stdin programs."""

    if expand_word_splits:
        # An expansion inside a command word splits into several words before
        # dispatch, so `cross${IFS}build` is read as `cross build` here too.
        for split_variant in word_splitting_variants(value):
            if shell_program_has_cross(
                split_variant,
                include_opaque_shell_executable=include_opaque_shell_executable,
                depth=depth,
                expand_word_splits=False,
            ):
                return True

    tokens = shell_tokens(value)
    if tokens is None:
        return include_opaque_shell_executable and bool(
            STANDALONE_CROSS.search(value) or CROSS_ENVIRONMENT.search(value)
        )
    yaml_shell_field = bool(tokens and tokens[0] == "shell:")
    if tokens and tokens[0] in {"run:", "shell:"}:
        tokens = tokens[1:]

    global _shell_assigned_names
    outer_assigned_names = _shell_assigned_names
    _shell_assigned_names = outer_assigned_names | frozenset(
        match.group(1)
        for match in (
            SHELL_ASSIGNMENT_TOKEN.fullmatch(token) for token in tokens
        )
        if match is not None
    )
    try:
        return shell_statements_have_cross(
            tokens,
            yaml_shell_field=yaml_shell_field,
            include_opaque_shell_executable=include_opaque_shell_executable,
            depth=depth,
        )
    finally:
        _shell_assigned_names = outer_assigned_names


def stdin_language_has_cross(
    language: str | None,
    program: str,
    *,
    include_opaque_shell_executable: bool,
    depth: int,
) -> bool:
    """Read a stdin program with the interpreter that actually executes it."""

    if language == "shell" or language is None:
        return shell_program_has_cross(
            program,
            include_opaque_shell_executable=include_opaque_shell_executable,
            depth=depth,
        )
    return inline_interpreter_has_cross(
        ((language, program),),
        include_opaque_shell_executable=include_opaque_shell_executable,
    )


def shell_statements_have_cross(
    tokens: tuple[str, ...],
    *,
    yaml_shell_field: bool,
    include_opaque_shell_executable: bool,
    depth: int,
) -> bool:
    """Dispatch every statement, pipeline segment, and stdin program."""

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
            language, stdin_program, opaque = shell_stdin_program(segment)
            if stdin_program is not None and stdin_language_has_cross(
                language,
                stdin_program,
                include_opaque_shell_executable=include_opaque_shell_executable,
                depth=depth + 1,
            ):
                return True
            if opaque and position > 0:
                producer = literal_producer_output(pipeline[position - 1])
                if producer is not None:
                    if stdin_language_has_cross(
                        language,
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
    variants.extend(word_splitting_variants(line))
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


def literal_command_text_has_cross(
    text: str,
    *,
    executable_only: bool = False,
) -> bool:
    """Scan literal command text without re-entering alias/shim expansion.

    Alias and shim expansion is derived from command text, so the readers that
    are themselves used to derive it must scan through this narrower entry
    point instead of `contains_literal_executable_cross`. With
    `executable_only`, a Cross environment token alone is not enough: binding a
    new name to Cross requires the Cross executable itself.
    """

    logical_text = re.sub(r"\\\r?\n[ \t]*", "", text)
    return any(
        has_cross_command_context(variant)
        or (not executable_only and CROSS_ENVIRONMENT.search(variant))
        for line in logical_text.splitlines()
        for variant in scan_variants(line)
    )


def shell_statement_segments(tokens: tuple[str, ...]) -> tuple[tuple[str, ...], ...]:
    """Split a token stream into the individual commands a shell dispatches."""

    statements: list[tuple[str, ...]] = []
    current: list[str] = []
    depth = 0
    for token in tokens:
        if token == "(":
            depth += 1
        elif token == ")" and depth:
            depth -= 1
        if token in {";", ";;", "&&", "||", "&"} and depth == 0:
            if current:
                statements.append(tuple(current))
            current = []
        else:
            current.append(token)
    if current:
        statements.append(tuple(current))
    return tuple(
        segment
        for statement in statements
        for segment in split_shell_pipeline(statement)
    )


def cross_shim_names(contents: str) -> tuple[tuple[str, ...], bool]:
    """Return executable names bound to Cross, and whether a binding is opaque.

    Linking, copying, or moving the Cross binary to another name, or writing a
    wrapper script whose body runs Cross, produces an executable that
    dispatches Cross through a word that is never literally `cross`. Both forms
    are collected here so the later dispatch is recognized as well.
    """

    shims: dict[str, None] = {}
    opaque = False

    def register(destination: str) -> None:
        nonlocal opaque
        if dynamic_shell_word(destination):
            # A generated shim name still binds Cross to a new executable.
            opaque = True
            return
        if destination.endswith("/"):
            # A trailing slash keeps the source name, so no alias is created.
            return
        name = tool_name(destination)
        if not name or name == "cross" or name in {"bin", "sbin", "usr", "local"}:
            return
        if not re.fullmatch(r"[A-Za-z0-9_.+-]+", name):
            opaque = True
            return
        if len(shims) >= MAXIMUM_TRACKED_SHIMS:
            opaque = True
            return
        shims[name] = None

    for line in contents.splitlines():
        # Every binding of the Cross executable names it, so a line that cannot
        # produce the token needs no tokenization. Quotes and escapes are
        # removed first because the shell removes them too: `cr"oss"` and
        # `cr\oss` are the same executable word as `cross`, and a raw substring
        # prefilter would let a split source slip past the tokenizer entirely.
        if "cross" not in re.sub(r"[\\'\"]", "", line).lower():
            continue
        tokens = shell_tokens(strip_shell_comment(line))
        if tokens is None:
            continue
        # An inline YAML `- run:` scalar puts the list marker and the key in
        # front of the command, exactly as the lexical scanners already allow.
        while tokens and tokens[0] in {"-", "run:", "shell:"}:
            tokens = tokens[1:]
        for segment in shell_statement_segments(tokens):
            index, executes = executable_index(segment)
            if not executes or index >= len(segment):
                continue
            arguments = segment[index + 1 :]

            if tool_name(segment[index]) in CROSS_ALIAS_COMMANDS:
                operands = [
                    token
                    for token in arguments
                    if not token.startswith("-") and not redirection_token(token)
                ]
                # The final operand is the destination; every earlier operand
                # is a source, which keeps `install -m 0755 <cross> bin/cx`
                # and multi-source copies on the same footing as `ln src dst`.
                if len(operands) >= 2 and any(
                    CROSS_PATH_COMPONENT.search(operand)
                    for operand in operands[:-1]
                ):
                    register(operands[-1])

            # `printf '#!/bin/sh\nexec cross "$@"\n' > bin/cr` writes a wrapper
            # whose body is command text even though the redirection target is
            # only ever created, never executed, on this line.
            target: str | None = None
            for position, token in enumerate(segment):
                if (
                    redirection_token(token)
                    and ">" in token
                    and position + 1 < len(segment)
                ):
                    target = segment[position + 1]
            if target is None:
                continue
            body = " ".join(
                decode_ansi_c_body(token)
                for position, token in enumerate(segment)
                if not redirection_token(token)
                and (position == 0 or not redirection_token(segment[position - 1]))
            )
            if any(
                literal_command_text_has_cross(body_line, executable_only=True)
                for body_line in body.split("\n")
            ):
                register(target)

    return tuple(shims), opaque


def cross_shim_variants(contents: str) -> tuple[str, ...]:
    """Expose Cross shim creation and every later dispatch through the shim."""

    shims, opaque = cross_shim_names(contents)
    if not shims and not opaque:
        return ()
    # Binding Cross to another executable name is itself a Cross surface, so a
    # dynamic or oversized binding still fails closed with no resolvable name.
    variants: list[str] = [f"cross build --target {TARGET}"]
    for name in shims:
        dispatch = re.compile(
            COMMAND_START_CONTEXT
            + WRAPPER_PREFIX
            # `PATH="$PWD/bin:$PATH" cr build ...` prepends the shim directory
            # in the same command, so the assignment layer must be consumed
            # before the shim name like any other executable word.
            + r"(?:[A-Za-z_][A-Za-z0-9_]*=[^\s]+\s+)*"
            + TOOL_PATH_PREFIX
            + re.escape(name)
            + r"(?![A-Za-z0-9_-])"
        )
        for line in contents.splitlines():
            # Replacing only the trailing shim name preserves the command-start
            # context and any `./bin/` or PATH-qualified prefix before it.
            expanded = dispatch.sub(
                lambda use, shim=name: use.group()[: -len(shim)] + "cross",
                line,
            )
            if expanded != line:
                variants.append(expanded)
    return tuple(dict.fromkeys(variants))


def logical_scan_lines(contents: str) -> tuple[str, ...]:
    """Return every command line to scan, including alias and shim expansions."""

    return (
        *contents.splitlines(),
        *shell_alias_variants(contents),
        *cross_shim_variants(contents),
    )


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


def step_block_bounds(
    lines: list[str],
    index: int,
    key_column: int,
    *,
    has_dash: bool,
) -> tuple[int, int]:
    """Return the half-open line range of the step mapping that holds `index`.

    A YAML step is one mapping, so its keys may appear in any order and `uses:`
    is not necessarily the first of them. Scanning forward from the reference
    alone would miss `with:` inputs written above it, so the whole mapping is
    located instead. When the reference itself carries the sequence dash it is
    already the first line of the step and no backward walk is needed.
    """

    start = index
    if not has_dash:
        for offset in range(index - 1, -1, -1):
            previous = lines[offset]
            if not previous.strip():
                continue
            indent = len(previous) - len(previous.lstrip(" "))
            stripped = previous.lstrip(" ")
            if indent == key_column - 2 and stripped.startswith("- "):
                # The sequence entry that opens this step.
                start = offset
                break
            if indent < key_column:
                break
            if indent == key_column and stripped.startswith("- "):
                break
            start = offset

    end = len(lines)
    for offset in range(index + 1, len(lines)):
        following = lines[offset]
        if not following.strip():
            continue
        indent = len(following) - len(following.lstrip(" "))
        stripped = following.lstrip(" ")
        if indent < key_column or (
            indent == key_column and stripped.startswith("- ")
        ):
            end = offset
            break
    return start, end


def step_input_keys(text: str) -> list[str]:
    """Return every mapping key on a step line, quoted or not.

    `'use-cross': true` and `"use-cross": true` are the same YAML key as the
    unquoted spelling, so an action input cannot be hidden behind quoting.
    """

    return re.findall(r"['\"]?([A-Za-z0-9_.+-]+)['\"]?\s*:", text)


def artifact_only_input_line(keys: list[str]) -> bool:
    """Return whether a line declares only closed artifact name/path inputs.

    Block (`name: ...`) and flow (`with: {name: ...}`) mappings are the same
    YAML, so the documented carve-out accepts both. A line that also carries
    any other key is not covered.
    """

    if not keys:
        return False
    contents = [
        key.lower() for key in keys if key.lower() not in ARTIFACT_CONTAINER_KEYS
    ]
    return bool(contents) and all(key in ARTIFACT_INPUT_KEYS for key in contents)


def literal_value_definitions(
    lines: list[str],
    start: int,
    end: int,
) -> dict[str, set[str]]:
    """Collect the literal value set each mapping key can take in a range."""

    definitions: dict[str, set[str]] = {}
    pending: tuple[str, int] | None = None
    for offset in range(start, end):
        line = lines[offset]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        text = re.sub(r"\s+#.*$", "", line)
        indent = len(text) - len(text.lstrip(" "))
        stripped = text.strip()
        if (
            pending is not None
            and stripped.startswith("- ")
            and indent > pending[1]
            and ":" not in stripped[2:]
        ):
            item = stripped[2:].strip().strip("'\"")
            if item:
                definitions.setdefault(pending[0], set()).add(item)
            continue
        entry = re.match(
            r"^\s*(?:-\s+)?['\"]?([A-Za-z0-9_.+-]+)['\"]?\s*:\s*(.*)$",
            text,
        )
        if entry is None:
            pending = None
            continue
        name, raw = entry.group(1), entry.group(2).strip()
        if raw in {"", "|", ">", "|-", ">-", "|+", ">+"}:
            pending = (name, indent)
            continue
        pending = None
        if raw.startswith("[") and raw.endswith("]"):
            for item in raw[1:-1].split(","):
                cleaned = item.strip().strip("'\"")
                if cleaned:
                    definitions.setdefault(name, set()).add(cleaned)
            continue
        definitions.setdefault(name, set()).add(raw.strip("'\""))
    return definitions


def workflow_scope_definitions(
    lines: list[str],
    index: int,
) -> dict[str, set[str]]:
    """Return the literal values a step's expressions can resolve to.

    Matrix and environment names are resolved in the enclosing job first so an
    unrelated job's identically named key cannot widen or narrow the result,
    with the workflow-level mapping merged in as a fallback.
    """

    jobs_index = next(
        (
            offset
            for offset, line in enumerate(lines)
            if decode_simple_yaml_key(line) == (0, "jobs")
        ),
        None,
    )
    start, end = 0, len(lines)
    if jobs_index is not None and index > jobs_index:
        job_starts = [
            offset
            for offset in range(jobs_index + 1, len(lines))
            if (decoded := decode_simple_yaml_key(lines[offset])) is not None
            and decoded[0] == 2
        ]
        enclosing = [offset for offset in job_starts if offset <= index]
        if enclosing:
            start = enclosing[-1]
            after = [offset for offset in job_starts if offset > index]
            end = min(
                after[0] if after else len(lines),
                next(
                    (
                        offset
                        for offset in range(start + 1, len(lines))
                        if (decoded := decode_simple_yaml_key(lines[offset]))
                        is not None
                        and decoded[0] == 0
                    ),
                    len(lines),
                ),
            )
    definitions = literal_value_definitions(lines, start, end)
    if start != 0:
        outer = literal_value_definitions(
            lines,
            0,
            jobs_index if jobs_index is not None else len(lines),
        )
        for name, values in outer.items():
            definitions.setdefault(name, set()).update(values)
    return definitions


def expression_candidates(
    body: str,
    definitions: dict[str, set[str]],
) -> set[str] | None:
    """Resolve one `${{ }}` body to its literal values, or None if unknown.

    Only the namespaces a workflow author populates can carry a build target.
    `secrets.*`, `runner.*`, `github.*`, `steps.*`, and `needs.*` are not
    workflow-authored value sets, so they resolve to nothing rather than
    failing closed on every ordinary credential input.
    """

    body = body.strip()
    lowered = body.lower()
    if not any(lowered.startswith(name) for name in RESOLVABLE_EXPRESSION_SCOPES):
        return set()
    name = body.split(".")[-1].strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]+", name):
        return None
    values = definitions.get(name)
    if values is None:
        return None
    if any("${{" in value for value in values):
        # The definition is itself an unresolved expression.
        return None
    return values


def expression_reaches_target(
    text: str,
    definitions: dict[str, set[str]],
) -> bool:
    """Return whether a workflow expression can deliver the protected target.

    `args: build --target ${{ matrix.target }}` hands the action the ARM64
    target without any physical line containing it, so the expression is
    resolved against the matrix rather than compared as literal text.
    """

    expressions = list(WORKFLOW_EXPRESSION.finditer(text))
    if not expressions:
        return False
    unresolved = False
    for expression in expressions:
        candidates = expression_candidates(expression.group("body"), definitions)
        if candidates is None:
            unresolved = True
            continue
        for candidate in candidates:
            expanded = WORKFLOW_EXPRESSION.sub(
                "",
                text[: expression.start()] + candidate + text[expression.end() :],
            )
            if (
                TARGET in expanded
                or EXPECTED_IMAGE in expanded
                or STANDALONE_CROSS.search(candidate)
            ):
                return True
    # A reference this workflow never defines cannot be shown to be free of the
    # protected target, so an input that already declares itself a build-target
    # argument fails closed rather than being read as benign.
    return unresolved and bool(
        TARGET_ARGUMENT_FLAG.search(WORKFLOW_EXPRESSION.sub("", text))
    )


def remote_action_surface_lines(
    contents: str,
    source: str = "",
) -> tuple[dict[int, str], list[str]]:
    """Map every line that starts a Cross-capable remote-action step.

    A remote `uses:` step runs code this repository does not own, so its
    reference and its declared inputs are the only visible evidence of what it
    executes. `actions-rs/cargo` with `use-cross: true` runs the Cross
    executable in place of Cargo, and a Cross-capable input or an ARM64 target
    argument reaches the same place through any other action. Such a step is
    therefore a build-execution surface, and a dynamic reference that cannot be
    resolved at all fails closed.

    The whole step mapping is scanned, in any key order, with quoted keys,
    flow mappings, folded double-quoted scalars, and matrix-derived target
    expressions all read the way the Actions runner reads them.
    """

    surfaces: dict[int, str] = {}
    errors: list[str] = []
    lines = contents.splitlines()
    for index, line in enumerate(lines):
        match = REMOTE_ACTION_FIELD.match(line)
        if match is None:
            continue
        value = re.sub(r"\s+#.*$", "", match.group("value")).strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1].strip()
        if not value or value.startswith("./"):
            # Local actions are extracted and scanned as files of their own.
            continue
        if "${{" in value or dynamic_shell_word(value):
            surfaces[index] = f"remote-action-dynamic:{index + 1}"
            errors.append(
                f"{source}:{index + 1} remote action references must be literal"
                if source
                else f"line {index + 1} remote action references must be literal"
            )
            continue

        reason: str | None = None
        if "cross" in re.split(r"[^A-Za-z0-9]+", value.lower()):
            reason = "reference"
        artifact_transfer = bool(ARTIFACT_TRANSFER_ACTION.match(value))

        key_column = len(match.group("lead")) + len(match.group("dash") or "")
        start, end = step_block_bounds(
            lines,
            index,
            key_column,
            has_dash=bool(match.group("dash")),
        )
        scanned: list[str] = []
        for offset in range(start, end):
            if offset == index:
                # The reference itself was already classified above.
                continue
            following = lines[offset]
            if not following.strip():
                continue
            stripped = following.lstrip(" ")
            if stripped.startswith("#"):
                continue
            text = re.sub(r"\s+#.*$", "", following)
            # Every key on the line is considered, so a flow mapping such as
            # `with: {use-cross: true}` is read like a block mapping.
            keys = step_input_keys(text)
            cross_input = next(
                (
                    key
                    for key in keys
                    if re.sub(r"[^a-z0-9]", "", key.lower())
                    in CROSS_CAPABLE_ACTION_INPUTS
                ),
                None,
            )
            if cross_input is not None:
                if reason is None:
                    reason = f"input:{cross_input}"
                continue
            if artifact_transfer and artifact_only_input_line(keys):
                # An artifact name or path is not an execution argument. These
                # two SHA-pinned first-party actions only move files between
                # jobs, so naming the protected target in an artifact name
                # cannot start a build. Everything else about them, including a
                # `cross` executable token and every Cross-enabling input key,
                # is still a surface.
                if reason is None and (
                    EXPECTED_IMAGE in text or STANDALONE_CROSS.search(text)
                ):
                    reason = "input-value"
                continue
            scanned.append(text)
        if reason is None and scanned:
            # A double-quoted YAML scalar continued with a trailing backslash
            # is delivered to the action as one string with the newline and the
            # following indentation removed, so the protected target can span
            # source lines that each look benign on their own.
            folded = re.sub(r"\\\r?\n[ \t]*", "", "\n".join(scanned))
            definitions = workflow_scope_definitions(lines, index)
            for text in (*scanned, *folded.splitlines()):
                if TARGET in text or EXPECTED_IMAGE in text or (
                    STANDALONE_CROSS.search(text)
                ):
                    reason = "input-value"
                    break
                if expression_reaches_target(text, definitions):
                    reason = "input-expression"
                    break
        if reason is not None:
            surfaces[index] = f"remote-action:{value}:{reason}"
    return surfaces, errors


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

    # A remote action is opaque code, so a Cross-capable one is attributed to
    # the job that runs it exactly like a literal Cross command would be.
    remote_surfaces, remote_errors = remote_action_surface_lines(
        "".join(lines),
        source,
    )

    top_level_surfaces: list[str] = []
    for index, line in enumerate(lines):
        line_surfaces: set[str] = set()
        if index in remote_surfaces:
            line_surfaces.add(remote_surfaces[index])
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
    return tuple([*top_level_surfaces, *job_surfaces]), remote_errors


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

    programs, interpreter_errors = workflow_run_programs(contents, source)
    runtime_sensitive, runtime_errors = runtime_program_cross_surface(
        programs,
        source,
        include_opaque_shell_executable=include_opaque_shell_executable,
    )
    remote_surfaces, remote_errors = remote_action_surface_lines(contents, source)
    errors = [*interpreter_errors, *runtime_errors, *remote_errors]

    # Avoid imposing a YAML layout contract on unrelated workflows. As soon as
    # a Cross token is exposed, however, parse the job layout conservatively so
    # malformed, duplicate, and alias-shaped jobs fail closed.
    if not runtime_sensitive and not remote_surfaces and not contains_cross_surface(
        yaml_command_augmented(contents),
        include_opaque_shell_executable=include_opaque_shell_executable,
    ):
        return (), errors
    surfaces, surface_errors = unprotected_cross_surfaces(
        contents,
        source,
        "__no_unprotected_cross_job__",
        required_job=False,
        include_opaque_shell_executable=include_opaque_shell_executable,
    )
    if runtime_sensitive and not surfaces:
        surfaces = (f"runtime:{hashlib.sha256(contents.encode()).hexdigest()}",)
    if remote_surfaces and not surfaces:
        surfaces = tuple(sorted(remote_surfaces.values()))
    return surfaces, list(dict.fromkeys([*errors, *surface_errors]))


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
    # A composite action can also delegate to a remote action that reaches
    # Cross, so the same remote-action policy applies to action files. Only
    # YAML carries `uses:` steps, so other automation is left untouched.
    if name.lower().endswith((".yml", ".yaml")):
        remote_surfaces, remote_errors = remote_action_surface_lines(contents, name)
    else:
        remote_surfaces, remote_errors = {}, []
    sensitive = (
        runtime_sensitive
        or bool(runtime_errors)
        or bool(remote_surfaces)
        or bool(remote_errors)
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


MAKE_MANIFEST_NAMES = frozenset({"Makefile", "makefile", "GNUmakefile"})
MAKE_ASSIGNMENT = re.compile(
    r"^(?:export\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_.-]*)\s*"
    r"(?P<operator>\+=|\?=|::=|:=|=)(?P<value>.*)$"
)
MAKE_VARIABLE_REFERENCE = re.compile(
    r"\$(?:\((?P<paren>[A-Za-z_][A-Za-z0-9_.-]*)\)|"
    r"\{(?P<brace>[A-Za-z_][A-Za-z0-9_.-]*)\})"
)
# `$(MAKE)` is make's own recursion handle, not a shell command substitution.
# It expands to the running make executable, so substituting `make` keeps the
# recipe readable and still routes it through the dispatcher machinery that
# follows and freezes recursive make. No other undefined variable is assumed
# safe: an unresolved expansion stays opaque and keeps failing closed.
MAKE_RECURSION_VARIABLES = frozenset({"MAKE", "MAKE_COMMAND"})
MAXIMUM_MAKE_VARIABLES = 64
MAXIMUM_MAKE_EXPANSIONS = 4


def make_variable_values(contents: str) -> dict[str, str]:
    """Collect the variables a makefile assigns, ignoring recipe lines."""

    values: dict[str, str] = {}
    for line in contents.splitlines():
        if line.startswith("\t") or not line.strip() or line.lstrip().startswith("#"):
            continue
        match = MAKE_ASSIGNMENT.match(line.strip())
        if match is None:
            continue
        if len(values) >= MAXIMUM_MAKE_VARIABLES:
            break
        name = match.group("name")
        value = match.group("value").strip()
        if match.group("operator") == "+=" and name in values:
            values[name] = f"{values[name]} {value}".strip()
        else:
            values[name] = value
    return values


def make_expanded_manifest(name: str, contents: str) -> str:
    """Expand make variables so recipes read as the shell text make emits.

    GNU make expands `$(VAR)` itself; the shell never sees a command
    substitution there. Treating every `$(...)` as one would freeze ordinary
    recursive-make recipes, so variables the makefile assigns are substituted
    with their real values — which also catches `CARGO = cross` followed by
    `$(CARGO) build ...` — and `$(MAKE)` resolves to the make executable.
    Anything else, including `$(shell ...)` and other make functions, is left
    intact for the existing opaque-substitution handling.
    """

    if PurePosixPath(name).name not in MAKE_MANIFEST_NAMES:
        return contents
    values = make_variable_values(contents)

    def substitute(match: re.Match[str]) -> str:
        variable = match.group("paren") or match.group("brace")
        if variable in values:
            return values[variable]
        if variable in MAKE_RECURSION_VARIABLES:
            return "make"
        return match.group()

    expanded = contents
    for _ in range(MAXIMUM_MAKE_EXPANSIONS):
        replaced = MAKE_VARIABLE_REFERENCE.sub(substitute, expanded)
        if replaced == expanded:
            break
        expanded = replaced
    return expanded


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
    # Make variables are expanded first so a recipe reads as the shell text make
    # actually emits.
    return (
        re.sub(
            r"(?m)^(\s+)[-@+]+",
            r"\1",
            make_expanded_manifest(name, contents),
        ),
    )


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
            # A makefile's raw text is not shell text; expanding its variables
            # first keeps `$(MAKE) -C sub all` from reading as an opaque
            # command substitution in an executable slot.
            make_expanded_manifest(name, contents),
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
    elif language == "powershell":
        powershell_sensitive, powershell_errors = powershell_program_has_cross(
            contents,
            name,
            include_opaque_shell_executable=True,
        )
        if powershell_sensitive:
            digest = hashlib.sha256(contents.encode("utf-8")).hexdigest()
            surfaces.append(f"literal-powershell-cross:{digest}")
        if powershell_errors:
            digest = hashlib.sha256(contents.encode("utf-8")).hexdigest()
            surfaces.append(f"opaque-powershell-process:{digest}")
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
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in {"'", '"'}:
        raw = raw[1:-1]
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


def repository_path_has_dot_dot(raw: str) -> bool:
    """Return whether a possibly quoted repository path contains `..`."""

    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in {"'", '"'}:
        raw = raw[1:-1]
    variable_prefix = re.match(
        r"^\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[A-Za-z_][A-Za-z0-9_]*\})/",
        raw,
    )
    if variable_prefix is not None:
        raw = raw[variable_prefix.end() :]
    return ".." in PurePosixPath(raw).parts


def repository_command_line(line: str) -> str:
    """Reduce only the trusted workspace expression to its repository-relative form."""

    return re.sub(
        r"\$\{\{\s*github\.workspace\s*\}\}/?",
        "",
        line,
        flags=re.IGNORECASE,
    )


def quote_aware_heredoc_starts(line: str) -> tuple[tuple[int, str], ...]:
    """Find real shell heredoc openers without matching quoted prose."""

    starts: list[tuple[int, str]] = []
    quote: str | None = None
    escaped = False
    index = 0
    while index < len(line):
        character = line[index]
        if escaped:
            escaped = False
            index += 1
            continue
        if character == "\\" and quote != "'":
            escaped = True
            index += 1
            continue
        if quote is not None:
            if character == quote:
                quote = None
            index += 1
            continue
        if character in {"'", '"'}:
            quote = character
            index += 1
            continue
        if not line.startswith("<<", index) or line.startswith("<<<", index):
            index += 1
            continue

        cursor = index + 2
        if cursor < len(line) and line[cursor] == "-":
            cursor += 1
        while cursor < len(line) and line[cursor] in " \t":
            cursor += 1
        delimiter_quote = (
            line[cursor]
            if cursor < len(line) and line[cursor] in {"'", '"'}
            else None
        )
        if delimiter_quote is not None:
            cursor += 1
        delimiter = re.match(r"[A-Za-z_][A-Za-z0-9_]*", line[cursor:])
        if delimiter is None:
            index += 2
            continue
        value = delimiter.group(0)
        cursor += len(value)
        if delimiter_quote is not None:
            if cursor >= len(line) or line[cursor] != delimiter_quote:
                index += 2
                continue
            cursor += 1
        starts.append((index, value))
        index = cursor
    return tuple(starts)


def shell_command_lines(
    contents: str,
    source: str,
) -> tuple[tuple[str, ...], list[str]]:
    """Return commands outside heredoc bodies and reject unterminated input."""

    logical_contents = re.sub(r"\\\r?\n[ \t]*", "", contents)
    commands: list[str] = []
    heredoc_delimiters: list[str] = []
    for line in logical_contents.splitlines():
        if heredoc_delimiters:
            if line.strip() == heredoc_delimiters[0]:
                heredoc_delimiters.pop(0)
            continue
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        commands.append(line)
        heredoc_delimiters.extend(
            delimiter for _, delimiter in quote_aware_heredoc_starts(line)
        )
    errors = (
        [f"{source} has an unterminated heredoc {heredoc_delimiters[0]!r}"]
        if heredoc_delimiters
        else []
    )
    return tuple(commands), errors


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


def workflow_run_programs(
    contents: str,
    source: str,
) -> tuple[list[tuple[str, str]], list[str]]:
    """Resolve each workflow run body through its effective interpreter."""

    lines = contents.splitlines()
    fields = yaml_command_fields(contents)

    def step_start(line_number: int, field_indent: int) -> tuple[int, int] | None:
        for candidate in range(line_number, -1, -1):
            match = re.match(r"^(?P<indent> *)-\s+", lines[candidate])
            if match is None:
                continue
            indent = len(match.group("indent"))
            if indent <= field_indent:
                if any(
                    intervening.strip()
                    and len(intervening) - len(intervening.lstrip(" ")) <= indent
                    for intervening in lines[candidate + 1 : line_number]
                ):
                    return None
                return candidate, indent
        return None

    grouped: dict[tuple[int, int], list[tuple[str, str, int]]] = {}
    for line_number, field_indent, _, key, _, rendered in fields:
        step = step_start(line_number, field_indent)
        if step is not None:
            grouped.setdefault(step, []).append((key, rendered, line_number))

    default_shells: list[tuple[int, int, int, str]] = []
    for index, line in enumerate(lines):
        defaults = re.match(r"^(?P<indent> *)defaults\s*:\s*(?:#.*)?$", line)
        if defaults is None:
            continue
        defaults_indent = len(defaults.group("indent"))
        end = len(lines)
        for candidate in range(index + 1, len(lines)):
            if not lines[candidate].strip():
                continue
            indentation = len(lines[candidate]) - len(lines[candidate].lstrip(" "))
            if indentation < defaults_indent:
                end = candidate
                break
        run_mapping = next(
            (
                candidate
                for candidate in range(index + 1, end)
                if re.match(
                    rf"^ {{{defaults_indent + 2}}}run\s*:\s*(?:#.*)?$",
                    lines[candidate],
                )
            ),
            None,
        )
        if run_mapping is None:
            continue
        shell_match: re.Match[str] | None = None
        for candidate in range(run_mapping + 1, end):
            shell_match = re.match(
                rf"^ {{{defaults_indent + 4}}}shell\s*:\s*(?P<value>.+?)\s*$",
                lines[candidate],
            )
            if shell_match is not None:
                break
        if shell_match is not None:
            value = shell_match.group("value").split(" #", maxsplit=1)[0].strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
                value = value[1:-1]
            default_shells.append((index, end, defaults_indent, value))

    programs: list[tuple[str, str]] = []
    errors: list[str] = []
    for step, step_fields in sorted(grouped.items()):
        run_values = [
            (value, line_number)
            for key, value, line_number in step_fields
            if key == "run" and value
        ]
        if not run_values:
            continue
        shell_values = [value for key, value, _ in step_fields if key == "shell"]
        if len(run_values) != 1 or len(shell_values) > 1:
            errors.append(
                f"{source}:{step[0] + 1} workflow steps require one literal run "
                "and at most one shell scalar"
            )
            continue
        run_value, run_line = run_values[0]
        if shell_values:
            shell_value = shell_values[0]
        else:
            matching_defaults = [
                (indent, value)
                for start, end, indent, value in default_shells
                if start < run_line < end
            ]
            shell_value = max(matching_defaults, default=(0, "bash"))[1]
        language = interpreter_kind(shell_tokens(shell_value))
        if language is None:
            errors.append(
                f"{source}:{step[0] + 1} uses an unsupported or dynamic workflow shell"
            )
            continue
        programs.append((language, run_value))
    return programs, errors


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
    if executable == "busybox":
        return (
            "shell"
            if index + 1 < len(words) and tool_name(words[index + 1]) == "sh"
            else None
        )
    if executable.lower() in {"pwsh", "powershell"}:
        # A PowerShell body is not POSIX shell: its dispatch is cmdlet-shaped,
        # so reading it as `sh` would miss `Start-Process cross ...` entirely.
        return "powershell"
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


def executable_heredocs(
    contents: str,
    source: str,
) -> tuple[tuple[tuple[str, str], ...], list[str]]:
    """Return executable heredocs and reject an unterminated program."""

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

        heredocs = quote_aware_heredoc_starts(line)
        if not heredocs:
            continue
        _, delimiter = heredocs[0]
        interpreters = [
            match.group("interpreter")
            for match in HEREDOC_EXECUTABLE.finditer(line[: heredocs[0][0]])
        ]
        if interpreters:
            executable = tool_name(interpreters[-1])
            if PYTHON_INTERPRETER.fullmatch(executable):
                interpreter = "python"
            elif executable.lower() in {"pwsh", "powershell"}:
                interpreter = "powershell"
            else:
                interpreter = "shell"
    errors = (
        [f"{source} has an unterminated executable heredoc {delimiter!r}"]
        if delimiter is not None
        else []
    )
    return tuple(programs), errors


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
        # asyncio dispatches processes through its own entry points, which
        # reach exactly the same executables as `subprocess`.
        "asyncio.create_subprocess_shell",
        "asyncio.create_subprocess_exec",
        "asyncio.subprocess.create_subprocess_shell",
        "asyncio.subprocess.create_subprocess_exec",
    }
    # `os.execl*`, `os.spawnl*`, and `create_subprocess_exec` spread argv across
    # their positional arguments, so the executable alone is not the command.
    variadic_argv_calls = {
        "asyncio.create_subprocess_exec",
        "asyncio.subprocess.create_subprocess_exec",
        "os.execl",
        "os.execle",
        "os.execlp",
        "os.execlpe",
        "os.spawnl",
        "os.spawnle",
        "os.spawnlp",
        "os.spawnlpe",
    }
    process_modules = {"os", "subprocess", "asyncio"}
    imported_names: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in process_modules or alias.name == "asyncio.subprocess":
                    imported_names[alias.asname or alias.name] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module in (
            process_modules | {"asyncio.subprocess"}
        ):
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
            ) in process_modules:
                return True
            if isinstance(descendant, ast.Call) and static_name(
                descendant.func
            ) == "__import__" and descendant.args:
                if literal_string(descendant.args[0]) in process_modules:
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
            if aliased not in process_calls and aliased not in process_modules:
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
            elif resolved_name.endswith("create_subprocess_shell"):
                keyword_names = {"cmd"}
            elif resolved_name.endswith("create_subprocess_exec"):
                keyword_names = {"program"}
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
        if command is not None and resolved_name in variadic_argv_calls:
            # `create_subprocess_exec('cross', 'build', ...)` and
            # `os.execlp('cross', 'cross', 'build', ...)` spell one argv across
            # the positional arguments, so the executable word alone would look
            # like a bare noun rather than a command with operands.
            spread = [
                literal_string(argument)
                for argument in node.args[positional_index:]
            ]
            if spread and all(word is not None for word in spread):
                command_words = tuple(
                    word for word in spread if word is not None
                )
                command_text = " ".join(command_words)
        if command is not None and command_text is None:
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
            heredoc_programs, heredoc_failures = executable_heredocs(
                program,
                source,
            )
            errors.extend(heredoc_failures)
            if heredoc_programs:
                nested_sensitive, nested_failures = runtime_program_cross_surface(
                    list(heredoc_programs),
                    f"{source} executable heredoc",
                    include_opaque_shell_executable=include_opaque_shell_executable,
                )
                sensitive = sensitive or nested_sensitive
                errors.extend(nested_failures)
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
        if language == "powershell":
            powershell_sensitive, powershell_errors = powershell_program_has_cross(
                program,
                source,
                include_opaque_shell_executable=include_opaque_shell_executable,
            )
            sensitive = sensitive or powershell_sensitive
            errors.extend(powershell_errors)
            continue
        errors.append(f"{source} uses an unsupported executable interpreter")
    return sensitive, errors


def literal_nested_shell_programs(value: str) -> tuple[str, ...]:
    """Return literal programs passed to sh-family `-c` command modes."""

    tokens = shell_tokens(value)
    if tokens is None:
        return ()
    statements: list[tuple[str, ...]] = []
    current: list[str] = []
    depth = 0
    for token in tokens:
        if token == "(":
            depth += 1
        elif token == ")" and depth:
            depth -= 1
        if token in {";", ";;", "&&", "||", "&"} and depth == 0:
            if current:
                statements.append(tuple(current))
            current = []
        else:
            current.append(token)
    if current:
        statements.append(tuple(current))

    programs: list[str] = []
    for statement in statements:
        for segment in split_shell_pipeline(statement):
            index, executes = executable_index(segment)
            if not executes or index >= len(segment):
                continue
            if tool_name(segment[index]) not in {
                "ash",
                "bash",
                "dash",
                "ksh",
                "sh",
                "zsh",
            }:
                continue
            program, opaque, _ = shell_invocation_mode(segment, index)
            if program is not None and not opaque and not dynamic_shell_word(program):
                programs.append(program)
    return tuple(programs)


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
    elif basename == "dockerfile" or basename.startswith("dockerfile."):
        if re.search(r"(?im)^\s*FROM\s+", contents) is None:
            return False, [f"{name} Dockerfile input has no FROM instruction"]
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
) -> tuple[list[tuple[str, str]], list[str]]:
    if workflow_source:
        return workflow_run_programs(contents, source)
    if is_dispatcher_manifest(source):
        # Recipes are shell, so a manifest can chain into scripts and further
        # dispatchers exactly like any other reached automation file.
        return [
            ("shell", script)
            for script in dispatcher_manifest_scripts(source, contents)
        ], []
    language = automation_language(source, contents)
    if language == "python":
        commands, errors = python_command_scripts(contents, source)
        return [("shell", command) for command in commands], errors
    if language == "shell":
        return [("shell", contents)], []
    if language == "powershell":
        return [("powershell", contents)], []
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

    Only the exact build outputs in `GENERATED_COMMAND_PATHS` are exempt from
    the scanned automation roots. A generated-looking directory prefix confers
    no exemption of its own: `tmp/`, `results/`, and the rest are ordinary
    committable paths, so a pull request could otherwise add `tmp/run.sh` with
    a Cross invocation and have it neither scanned nor reported.
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
                if repository_path_has_dot_dot(match.group("path")):
                    errors.append(
                        f"{source}:{line_number} local action paths must not "
                        "contain '..'"
                    )
                    continue
                action_path = normalize_repository_path(match.group("path"))
                if action_path is None or not action_path.startswith(
                    ".github/actions/"
                ):
                    errors.append(
                        f"{source}:{line_number} local actions must be under "
                        ".github/actions"
                    )

    command_programs, command_failures = automation_command_scripts(
        contents,
        source,
        workflow_source=workflow_source,
    )
    errors.extend(command_failures)
    for initial_program in command_programs:
        pending_programs: list[tuple[str, str]] = [initial_program]
        command_lines: list[str] = []
        while pending_programs:
            language, program = pending_programs.pop()
            if language == "python":
                python_commands, python_failures = python_command_scripts(
                    program,
                    f"{source} executable heredoc",
                )
                errors.extend(python_failures)
                pending_programs.extend(
                    ("shell", command) for command in python_commands
                )
                continue
            shell_lines, shell_failures = shell_command_lines(program, source)
            errors.extend(shell_failures)
            command_lines.extend(shell_lines)
            pending_programs.extend(
                ("shell", nested_program)
                for shell_line in shell_lines
                for nested_program in literal_nested_shell_programs(shell_line)
            )
            heredoc_programs, heredoc_failures = executable_heredocs(program, source)
            errors.extend(heredoc_failures)
            pending_programs.extend(heredoc_programs)

        working_directory: str | None = ""
        control_stack: list[str | None] = []
        for line_number, line in enumerate(command_lines, start=1):
            normalized_line = repository_command_line(line)
            directory_matches = list(CD_COMMAND.finditer(normalized_line))
            opened_controls = len(
                re.findall(r"\b(?:if|while|until|for|case)\b", normalized_line)
            )
            control_stack.extend([working_directory] * opened_controls)

            def directory_after(
                initial: str | None,
                matches: list[re.Match[str]],
            ) -> str | None:
                current = initial
                for directory_match in matches:
                    matched = directory_match.group(0)
                    path_offset = (
                        directory_match.start("path") - directory_match.start()
                    )
                    before_cd = matched[:path_offset].rsplit("cd", maxsplit=1)[0]
                    after_path = normalized_line[directory_match.end("path") :]
                    conditional = bool(
                        re.search(
                            r"(?:&&|\|\||\||\b(?:if|elif|while|until|for|case|"
                            r"then|do|else)\b)",
                            before_cd,
                        )
                        or re.match(r"\s*(?:&&|\|\||\|)", after_path)
                    )
                    directory_path = directory_match.group("path")
                    if (
                        current is None
                        or conditional
                        or dynamic_shell_word(directory_path)
                    ):
                        current = None
                        continue
                    current = normalize_repository_path(directory_path)
                return current

            def directory_before(position: int) -> str | None:
                return directory_after(
                    working_directory,
                    [match for match in directory_matches if match.start() < position],
                )

            for match in LOCAL_COMMAND_REFERENCE.finditer(normalized_line):
                inline_options = match.group("interpreter_options") or ""
                if match.group("interpreted") and re.search(
                    r"(?:^|\s)--?(?:c|lc|ec|e|[cC]ommand|[eE]val)(?:\s|$)",
                    inline_options,
                ):
                    # The following word is inline source code, not a repository
                    # path. Nested literal shell programs are queued separately.
                    continue
                raw_command_path = (
                    match.group("redirected")
                    or match.group("interpreted")
                    or match.group("direct")
                    or match.group("bare")
                )
                if raw_command_path.endswith("/"):
                    continue
                if repository_path_has_dot_dot(raw_command_path):
                    errors.append(
                        f"{source}:{line_number} repository command paths must not "
                        "contain '..'"
                    )
                    continue
                command_path = normalize_repository_path(raw_command_path)
                if command_path is None:
                    errors.append(
                        f"{source}:{line_number} has a non-canonical repository command"
                    )
                    continue
                if command_path in GENERATED_COMMAND_PATHS:
                    continue
                effective_directory = directory_before(match.start())
                if "/" not in command_path and effective_directory is None:
                    errors.append(
                        f"{source}:{line_number} repository command has ambiguous "
                        "working-directory state"
                    )
                    continue
                if "/" not in command_path and effective_directory:
                    command_path = (
                        PurePosixPath(effective_directory) / command_path
                    ).as_posix()
                if command_path in GENERATED_COMMAND_PATHS:
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
                effective_directory = directory_before(match.start())
                if effective_directory is None:
                    errors.append(
                        f"{source}:{line_number} build dispatcher has ambiguous "
                        "working-directory state"
                    )
                    continue
                base = effective_directory
                directory = DISPATCHER_DIRECTORY.search(arguments)
                if directory is not None:
                    if repository_path_has_dot_dot(directory.group("path")):
                        errors.append(
                            f"{source}:{line_number} build dispatcher directory "
                            "must not contain '..'"
                        )
                        continue
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
                    if repository_path_has_dot_dot(workspace_path):
                        errors.append(
                            f"{source}:{line_number} build dispatcher workspace "
                            "must not contain '..'"
                        )
                        continue
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
                    if repository_path_has_dot_dot(explicit.group("path")):
                        errors.append(
                            f"{source}:{line_number} build dispatcher manifest "
                            "must not contain '..'"
                        )
                        continue
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
            working_directory = directory_after(working_directory, directory_matches)
            if re.search(r"\b(?:else|elif)\b", normalized_line) and control_stack:
                branch_start = control_stack[-1]
                if working_directory != branch_start:
                    working_directory = None
            closed_controls = len(
                re.findall(r"\b(?:fi|done|esac)\b", normalized_line)
            )
            for _ in range(min(closed_controls, len(control_stack))):
                branch_start = control_stack.pop()
                working_directory = (
                    branch_start
                    if working_directory == branch_start
                    else None
                )
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
        elif contents is not None and language == "powershell":
            powershell_sensitive, powershell_errors = powershell_program_has_cross(
                contents,
                f"{source}/{name}",
                include_opaque_shell_executable=False,
            )
            errors.extend(powershell_errors)
            if powershell_sensitive:
                errors.append(
                    f"{source}/{name} contains an unprotected PowerShell Cross "
                    "dispatch"
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
        if ISOLATED_PLANNER_LAUNCHER not in invocation:
            errors.append(
                f"{source} trusted planner invocations must use the isolated "
                "trusted-directory launcher"
            )
    planner_dir_assignments = [
        line.strip()
        for line in block.splitlines()
        if re.match(r"^\s*planner_dir\s*=", line)
    ]
    expected_planner_dirs = [
        "planner_dir=.github/scripts",
        'planner_dir=".github/scripts"',
        'planner_dir="$trusted_dir"',
        'planner_dir="$trusted_dir"',
    ]
    if sorted(planner_dir_assignments) != sorted(expected_planner_dirs):
        errors.append(
            f"{source} ci-plan planner directories must resolve only to the "
            "repository bootstrap or extracted trusted directory"
        )
    trusted_dir_assignments = [
        line.strip()
        for line in block.splitlines()
        if re.match(r"^\s*trusted_dir\s*=", line)
    ]
    if sorted(trusted_dir_assignments) != sorted(
        [
            'trusted_dir="$RUNNER_TEMP/pr-ci-plan"',
            'trusted_dir="$RUNNER_TEMP/pr-ci-plan-self-test"',
        ]
    ):
        errors.append(
            f"{source} ci-plan must stage trusted planner modules only under "
            "RUNNER_TEMP"
        )
    if not any("--self-test" in invocation for invocation in invocations):
        errors.append(f"{source} ci-plan is missing the isolated planner self-test")
    if not any("--event-name" in invocation for invocation in invocations):
        errors.append(f"{source} ci-plan is missing the isolated planning invocation")
    return errors


def validate_trusted_policy_extraction(contents: str, source: str) -> list[str]:
    """Keep hostile-tree extraction fail-closed and on the live trusted base.

    `pull_request_target` checks out the event's base SHA, which goes stale as
    soon as `main` advances. The guard must therefore fetch the live base
    branch tip, authenticate it against the triggering base, pin it to one
    immutable SHA, and read every baseline from that SHA instead of from the
    event checkout.
    """

    errors: list[str] = []
    required_live_base_inputs = (
        '"+refs/heads/${BASE_REF}:refs/remotes/trusted-base"',
        'trusted_base="$(git rev-parse "refs/remotes/trusted-base^{commit}")"',
        'git merge-base --is-ancestor "$BASE_SHA" "$trusted_base"',
        'git show "$trusted_base:.github/workflows/ci.yml"',
        'git show "$trusted_base:.github/workflows/release.yml"',
        'extract_workflows "$trusted_base" "$merge_base_workflows"',
        'extract_actions "$trusted_base" "$merge_base_actions"',
        'extract_automation "$trusted_base" "$merge_base_automation"',
        # The verifier and every contract it reads must come from the same
        # pinned trusted tip as the baselines, never from the event checkout.
        'git show "$trusted_base:.github/scripts/verify_cross_build_policy.py"',
        'git show "$trusted_base:.github/workflows/cross-build-policy.yml"',
        'python3 -I "$trusted_verifier"',
        '--ci-workflow "$merge_base_ci"',
        '--release-workflow "$merge_base_release"',
        '--trusted-policy-workflow "$trusted_policy_workflow"',
        '--workflows-dir "$merge_base_workflows"',
        '--actions-dir "$merge_base_actions"',
        '--automation-dir "$merge_base_automation"',
        # GitHub loads this workflow from the event base, so the extraction
        # contract itself cannot be re-executed from the live tip and must
        # instead fail closed once the trusted tip has moved it.
        'git diff --no-ext-diff --quiet "$BASE_SHA" "$trusted_base" \\',
    )
    for required in required_live_base_inputs:
        if required not in contents:
            errors.append(
                f"{source} must authenticate and compare against the live trusted "
                f"base tip ({required!r} is missing)"
            )
    if re.search(r'git show "HEAD:', contents) or re.search(
        r"\bextract_(?:workflows|actions|automation) HEAD\b", contents
    ):
        errors.append(
            f"{source} must not read a Cross baseline from the stale event-base "
            "checkout"
        )
    if re.search(r"git merge-base(?!\s+--is-ancestor\b)", contents):
        errors.append(f"{source} must not use a stale merge-base Cross baseline")
    if re.search(
        r"python3[^\n]*\s\.github/scripts/verify_cross_build_policy\.py",
        contents,
    ):
        errors.append(
            f"{source} must execute the verifier from the pinned live trusted "
            "base, not from the stale event-base checkout"
        )

    checked_enumerations = re.findall(
        r"if ! git ls-tree -rz --name-only \"\$commit\"[^;]*> \"\$[a-z_]+\"; then",
        contents,
        re.DOTALL,
    )
    if len(checked_enumerations) != 4:
        errors.append(
            f"{source} must status-check all four hostile git tree enumerations "
            "before consuming materialized listings"
        )
    if re.search(r"<\s*<\(\s*git\s+ls-tree\b", contents):
        errors.append(
            f"{source} must not consume git ls-tree through process substitution"
        )
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

    # An inline program handed to a non-shell interpreter dispatches Cross
    # without any Cross word ever appearing in a shell command position.
    inline_interpreter_bypasses = {
        "perl inline program": (
            "perl -e 'system(\"cross build --target "
            "aarch64-unknown-linux-gnu\")'"
        ),
        "perl bundled inline flag": (
            "perl -we 'system(\"cross build --target "
            "aarch64-unknown-linux-gnu\")'"
        ),
        "node inline program": (
            "node -e 'require(\"child_process\").execSync(\"cross build "
            "--target aarch64-unknown-linux-gnu\")'"
        ),
        "node long inline flag": (
            "node --eval 'require(\"child_process\").execSync(\"cross build "
            "--target aarch64-unknown-linux-gnu\")'"
        ),
        "ruby inline program": (
            "ruby -e 'system(\"cross build --target "
            "aarch64-unknown-linux-gnu\")'"
        ),
        "php inline program": (
            "php -r 'exec(\"cross build --target aarch64-unknown-linux-gnu\");'"
        ),
        "deno inline subcommand": (
            "deno eval 'Deno.run({cmd: \"cross build --target "
            "aarch64-unknown-linux-gnu\"})'"
        ),
        "awk inline operand": (
            "awk 'BEGIN { system(\"cross build --target "
            "aarch64-unknown-linux-gnu\") }' /dev/null"
        ),
        "lua inline program": (
            "lua -e 'os.execute(\"cross build --target "
            "aarch64-unknown-linux-gnu\")'"
        ),
        "python inline program": (
            "python3 -c 'import subprocess; subprocess.run([\"cross\", "
            '"build", "--target", "aarch64-unknown-linux-gnu"])\''
        ),
        "powershell inline command": (
            "pwsh -Command 'cross build --target aarch64-unknown-linux-gnu'"
        ),
    }
    for label, command in inline_interpreter_bypasses.items():
        proposed = safe_extra_workflow.replace("echo safe", command)
        if not validate_workflow_collection(
            {"attacker.yml": proposed},
            "self-test workflow directory",
        ):
            failures.append(f"{label} was not rejected")
        if not compare_pr_workflow_collection(
            {"coverage.yml": safe_extra_workflow},
            {"coverage.yml": proposed},
            "self-test workflow directory",
        ):
            failures.append(f"merge-base comparison allowed {label}")

    inline_interpreter_fail_closed = {
        "generated perl program": 'perl -e "$PROGRAM"',
        "generated node program": "node -e \"${BUILD_SCRIPT}\"",
        "encoded powershell command": "pwsh -EncodedCommand YnVpbGQ=",
        "opaque node process dispatch": (
            "node -e 'require(\"child_process\").execSync(process.env.CMD)'"
        ),
        "opaque deno process dispatch": (
            "deno eval 'new Deno.Command(cmd, {args: argv})'"
        ),
    }
    for label, command in inline_interpreter_fail_closed.items():
        proposed = safe_extra_workflow.replace("echo safe", command)
        if not compare_pr_workflow_collection(
            {"coverage.yml": safe_extra_workflow},
            {"coverage.yml": proposed},
            "self-test workflow directory",
        ):
            failures.append(f"{label} was not rejected")

    benign_inline_interpreters = {
        "benign node inline program": "node -e 'console.log(1)'",
        "benign perl inline program": "perl -e 'print 1'",
        "benign python inline program": (
            "python3 -c 'import json; print(json.dumps({}))'"
        ),
        "benign awk program": "awk '{ print $1 }' report.txt",
    }
    for label, command in benign_inline_interpreters.items():
        proposed = safe_extra_workflow.replace("echo safe", command)
        if validate_workflow_collection(
            {"coverage.yml": proposed},
            "self-test workflow directory",
        ):
            failures.append(f"{label} was rejected")
        if compare_pr_workflow_collection(
            {"coverage.yml": proposed},
            {"coverage.yml": proposed.replace("name: Coverage", "name: Coverage 2")},
            "self-test workflow directory",
        ):
            failures.append(f"{label} blocked a benign edit")

    # An unquoted expansion splits into several words before dispatch, so
    # `cross${IFS}build` runs Cross with no literal source whitespace.
    word_splitting_bypasses = {
        "IFS-split subcommand": (
            "cross${IFS}build --target aarch64-unknown-linux-gnu"
        ),
        "bare IFS-split subcommand": (
            "cross$IFS build --target aarch64-unknown-linux-gnu"
        ),
        "IFS-split cargo subcommand": (
            "cargo${IFS}cross build --target aarch64-unknown-linux-gnu"
        ),
        "IFS-split toolchain selector": (
            "cargo${IFS}+stable${IFS}cross build --target "
            "aarch64-unknown-linux-gnu"
        ),
        "IFS-split cargo install": (
            "cargo${IFS}install${IFS}cross"
        ),
        "substring IFS-split subcommand": (
            "cross${IFS:0:1}build --target aarch64-unknown-linux-gnu"
        ),
        "command-substitution word split": (
            "cross$(printf ' ')build --target aarch64-unknown-linux-gnu"
        ),
    }
    for label, command in word_splitting_bypasses.items():
        proposed = safe_extra_workflow.replace("echo safe", command)
        if not validate_workflow_collection(
            {"attacker.yml": proposed},
            "self-test workflow directory",
        ):
            failures.append(f"{label} was not rejected")
        if not compare_pr_workflow_collection(
            {"coverage.yml": safe_extra_workflow},
            {"coverage.yml": proposed},
            "self-test workflow directory",
        ):
            failures.append(f"merge-base comparison allowed {label}")

    benign_expansion_workflow = safe_extra_workflow.replace(
        "echo safe",
        'echo "cargo${SUFFIX} finished for ${MATRIX} targets"',
    )
    if validate_workflow_collection(
        {"coverage.yml": benign_expansion_workflow},
        "self-test workflow directory",
    ):
        failures.append("benign expansion inside prose was rejected")

    # Linking, copying, or wrapping the Cross binary under another name runs
    # Cross through a word that is never literally `cross`.
    shim_bypasses = {
        "symlinked shim": (
            "ln -s /home/runner/.cargo/bin/cross bin/cr && "
            'PATH="$PWD/bin:$PATH" cr build --target aarch64-unknown-linux-gnu'
        ),
        "copied shim": (
            "cp /home/runner/.cargo/bin/cross bin/builder && "
            "./bin/builder build --target aarch64-unknown-linux-gnu"
        ),
        "moved shim": (
            "mv ~/.cargo/bin/cross /usr/local/bin/xb && "
            "xb build --target aarch64-unknown-linux-gnu"
        ),
        "installed shim": (
            "install -m 0755 ~/.cargo/bin/cross bin/cx && "
            "bin/cx build --target aarch64-unknown-linux-gnu"
        ),
        "hardlinked shim": (
            "ln ~/.cargo/bin/cross bin/cr2 && "
            "bin/cr2 build --target aarch64-unknown-linux-gnu"
        ),
        "resolved shim source": (
            'ln -s "$(command -v cross)" bin/cr3 && '
            "bin/cr3 build --target aarch64-unknown-linux-gnu"
        ),
        "wrapper script shim": (
            "printf '#!/bin/sh\\nexec cross \"$@\"\\n' > bin/cw && "
            "chmod +x bin/cw && "
            "./bin/cw build --target aarch64-unknown-linux-gnu"
        ),
        "dynamic shim name": (
            'ln -s ~/.cargo/bin/cross "$RUNNER_TEMP/$NAME"'
        ),
    }
    for label, command in shim_bypasses.items():
        proposed = safe_extra_workflow.replace("echo safe", command)
        if not validate_workflow_collection(
            {"attacker.yml": proposed},
            "self-test workflow directory",
        ):
            failures.append(f"{label} was not rejected")
        if not compare_pr_workflow_collection(
            {"coverage.yml": safe_extra_workflow},
            {"coverage.yml": proposed},
            "self-test workflow directory",
        ):
            failures.append(f"merge-base comparison allowed {label}")

    benign_shim_lookalikes = {
        "cross-named documentation": "cp docs/cross.md site/cross.md",
        "cross-prefixed artifact": "mv cross-report.json results/report.json",
        "same-name install": "cp bin/cross bin/cross",
    }
    for label, command in benign_shim_lookalikes.items():
        proposed = safe_extra_workflow.replace("echo safe", command)
        if validate_workflow_collection(
            {"coverage.yml": proposed},
            "self-test workflow directory",
        ):
            failures.append(f"{label} was rejected")

    # A remote action is code this repository does not own, so a Cross-capable
    # one restores unprotected ARM64 Cross execution with no Cross command.
    remote_action_step = (
        "      - uses: actions-rs/cargo@844f36862e911db73fe0815f00a4a2602c279505\n"
        "        with:\n"
        "          command: build\n"
        "          use-cross: true\n"
        "          args: --release --target aarch64-unknown-linux-gnu\n"
    )
    remote_action_workflow = safe_extra_workflow.replace(
        "      - run: echo safe\n",
        remote_action_step,
    )
    remote_action_bypasses = {
        "cross-capable action input": remote_action_workflow,
        "cross-named remote action": safe_extra_workflow.replace(
            "      - run: echo safe\n",
            "      - uses: houseabsolute/actions-rust-cross"
            "@9c74a0a6b7b6a8b7d0d1a7b9c0d1e2f3a4b5c6d7\n"
            "        with:\n"
            "          command: build\n",
        ),
        "cross-target action argument": safe_extra_workflow.replace(
            "      - run: echo safe\n",
            "      - uses: example/build-action"
            "@0f1e2d3c4b5a69788796a5b4c3d2e1f001122334\n"
            "        with:\n"
            "          args: --target aarch64-unknown-linux-gnu\n",
        ),
        "dynamic remote action reference": safe_extra_workflow.replace(
            "      - run: echo safe\n",
            "      - uses: ${{ matrix.action }}\n",
        ),
    }
    for label, proposed in remote_action_bypasses.items():
        if not validate_workflow_collection(
            {"attacker.yml": proposed},
            "self-test workflow directory",
        ):
            failures.append(f"{label} was not rejected")
        if not compare_pr_workflow_collection(
            {"coverage.yml": safe_extra_workflow},
            {"coverage.yml": proposed},
            "self-test workflow directory",
        ):
            failures.append(f"merge-base comparison allowed {label}")

    benign_remote_action_workflow = safe_extra_workflow.replace(
        "      - run: echo safe\n",
        "      - uses: actions/checkout"
        "@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0\n"
        "        with:\n"
        "          persist-credentials: false\n"
        "      - uses: actions/upload-artifact"
        "@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a\n"
        "        with:\n"
        "          name: report\n"
        "          path: results/\n",
    )
    if validate_workflow_collection(
        {"coverage.yml": benign_remote_action_workflow},
        "self-test workflow directory",
    ):
        failures.append("benign pinned remote actions were rejected")
    if compare_pr_workflow_collection(
        {"coverage.yml": safe_extra_workflow},
        {"coverage.yml": benign_remote_action_workflow},
        "self-test workflow directory",
    ):
        failures.append("adding benign pinned remote actions was rejected")

    remote_action_composite = (
        "name: Remote delegating action\n"
        "runs:\n"
        "  using: composite\n"
        "  steps:\n"
        "    - uses: actions-rs/cargo@844f36862e911db73fe0815f00a4a2602c279505\n"
        "      with:\n"
        "        command: build\n"
        "        use-cross: true\n"
    )
    if not validate_action_collection(
        {"setup/action.yml": remote_action_composite},
        "self-test local-action directory",
    ):
        failures.append("composite delegation to a Cross-capable action was allowed")

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

    interpreter_references = {
        "dash": "dash ci/unsafe.sh",
        "zsh": "zsh ci/unsafe.sh",
        "ksh": "ksh ci/unsafe.sh",
        "ash": "ash ci/unsafe.sh",
        "Perl": "perl ci/unsafe.pl",
        "awk file mode": "awk -f ci/unsafe.awk",
        "PowerShell Core": "pwsh ci/unsafe.ps1",
        "PHP": "php ci/unsafe.php",
        "Rscript": "Rscript ci/unsafe.R",
        "Deno": "deno ci/unsafe.ts",
        "Bun": "bun ci/unsafe.ts",
        "BusyBox shell": "busybox sh ci/unsafe.sh",
        "nested shell interpreter": "sh -c 'dash ci/unsafe.sh'",
    }
    for interpreter_label, command in interpreter_references.items():
        interpreter_workflow = referenced_workflow.replace(
            "bash scripts/safe.sh",
            command,
        )
        if not validate_automation_collection(
            {"ci.yml": interpreter_workflow},
            {"setup/action.yml": safe_action},
            safe_automation,
            "self-test automation directory",
        ):
            failures.append(
                f"{interpreter_label} repository command escaped automation scanning"
            )

    future_filename_workflow = referenced_workflow.replace(
        "bash scripts/safe.sh",
        "bash 'scripts/future +@~ name.sh'",
    )
    future_filename_automation = {
        "scripts/future +@~ name.sh": "#!/bin/sh\necho safe\n"
    }
    if validate_automation_collection(
        {"future +@~ workflow.yml": future_filename_workflow},
        {"setup/action.yml": safe_action},
        future_filename_automation,
        "self-test automation directory",
    ):
        failures.append("benign supported filename characters were rejected")
    if WORKFLOW_FILENAME.fullmatch("future +@~ workflow.yml") is None:
        failures.append("supported workflow filename characters were not accepted")

    dot_dot_workflow = referenced_workflow.replace(
        "bash scripts/safe.sh",
        "bash scripts/../ci/unsafe.sh",
    )
    if not validate_automation_collection(
        {"ci.yml": dot_dot_workflow},
        {"setup/action.yml": safe_action},
        safe_automation,
        "self-test automation directory",
    ):
        failures.append("dot-dot repository command path was not rejected")

    reference_before_cd = referenced_workflow.replace(
        "bash scripts/safe.sh",
        "bash scripts/safe.sh && cd scripts",
    )
    if validate_automation_collection(
        {"ci.yml": reference_before_cd},
        {"setup/action.yml": safe_action},
        safe_automation,
        "self-test automation directory",
    ):
        failures.append("a later same-line cd affected an earlier command")

    conditional_cd_workflow = referenced_workflow.replace(
        "run: bash scripts/safe.sh",
        "run: |\n"
        "          if test -d scripts; then\n"
        "            cd scripts\n"
        "          fi\n"
        "          bash safe.sh",
    )
    if not validate_automation_collection(
        {"ci.yml": conditional_cd_workflow},
        {"setup/action.yml": safe_action},
        safe_automation,
        "self-test automation directory",
    ):
        failures.append("conditional working-directory state was not rejected")

    loop_local_cd_workflow = referenced_workflow.replace(
        "run: bash scripts/safe.sh",
        "run: |\n"
        "          for item in one; do\n"
        "            cd scripts\n"
        "            bash safe.sh\n"
        "          done",
    )
    if validate_automation_collection(
        {"ci.yml": loop_local_cd_workflow},
        {"setup/action.yml": safe_action},
        safe_automation,
        "self-test automation directory",
    ):
        failures.append("known in-loop working-directory state was rejected")

    quoted_heredoc_prose = referenced_workflow.replace(
        "run: bash scripts/safe.sh",
        "run: |\n"
        "          echo \"usage: program <<EOF\"\n"
        "          bash scripts/safe.sh",
    )
    if validate_automation_collection(
        {"ci.yml": quoted_heredoc_prose},
        {"setup/action.yml": safe_action},
        safe_automation,
        "self-test automation directory",
    ):
        failures.append("quoted heredoc prose suppressed later command scanning")

    unterminated_heredoc = referenced_workflow.replace(
        "run: bash scripts/safe.sh",
        "run: |\n          bash <<'SHELL'\n          echo incomplete",
    )
    if not validate_automation_collection(
        {"ci.yml": unterminated_heredoc},
        {"setup/action.yml": safe_action},
        safe_automation,
        "self-test automation directory",
    ):
        failures.append("unterminated executable heredoc was not rejected")

    python_shell_cross = referenced_workflow.replace(
        "      - run: bash scripts/safe.sh\n",
        "      - shell: python\n"
        "        run: |\n"
        "          import subprocess\n"
        "          subprocess.run(['cross', 'build', '--target', "
        "'aarch64-unknown-linux-gnu'])\n",
    )
    if not validate_workflow_collection(
        {"python-shell.yml": python_shell_cross},
        "self-test workflow directory",
    ):
        failures.append("workflow Python shell Cross process was not rejected")

    default_python_shell_cross = (
        "name: Default Python shell\n"
        "defaults:\n"
        "  run:\n"
        "    shell: python3\n"
        "jobs:\n"
        "  unsafe:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: |\n"
        "          import subprocess\n"
        "          subprocess.run(['cross', 'build', '--target', "
        "'aarch64-unknown-linux-gnu'])\n"
    )
    if not validate_workflow_collection(
        {"default-python-shell.yml": default_python_shell_cross},
        "self-test workflow directory",
    ):
        failures.append("workflow default Python shell was not resolved")

    python_heredoc_cross = referenced_workflow.replace(
        "run: bash scripts/safe.sh",
        "run: |\n"
        "          python3 <<'PY'\n"
        "          import subprocess\n"
        "          subprocess.run(['cross', 'build', '--target', "
        "'aarch64-unknown-linux-gnu'])\n"
        "          PY",
    )
    if not validate_workflow_collection(
        {"python-heredoc.yml": python_heredoc_cross},
        "self-test workflow directory",
    ):
        failures.append("workflow Python heredoc Cross process was not rejected")

    ordinary_python_source = (
        "from subprocess import run\n"
        "run(['echo', 'safe'])\n"
    )
    ordinary_sensitive, ordinary_errors = action_file_runtime_surface(
        "scripts/ordinary.py",
        ordinary_python_source,
        include_opaque_shell_executable=True,
    )
    if ordinary_sensitive or ordinary_errors:
        failures.append("ordinary Python beginning with from was treated as Dockerfile")
    _, missing_from_errors = action_file_runtime_surface(
        "actions/example/Dockerfile",
        "RUN echo safe\n",
        include_opaque_shell_executable=True,
    )
    if not missing_from_errors:
        failures.append("Dockerfile without a FROM instruction was not rejected")

    aggregate_comparison_errors = compare_pr_automation_collection(
        {"ci.yml": referenced_workflow},
        {"ci.yml": referenced_workflow},
        {"setup/action.yml": safe_action},
        {"setup/action.yml": safe_action},
        {},
        {
            "scripts/safe.sh": (
                "#!/bin/sh\ncross build --target aarch64-unknown-linux-gnu\n"
            )
        },
        "self-test aggregate automation directory",
    )
    if not any(
        "references missing automation" in error
        for error in aggregate_comparison_errors
    ):
        failures.append("baseline automation errors were not reported")
    if not any(
        "cannot add or change Cross" in error
        for error in aggregate_comparison_errors
    ):
        failures.append("baseline errors suppressed proposed Cross comparison")

    if any(
        prefix in {"RUNNER_TEMP/", "trusted_dir/"}
        for prefix in GENERATED_SCRIPT_PREFIXES
    ):
        failures.append("unreachable variable-prefixed generated paths remain allowed")

    # A generated-looking directory prefix is not an exemption. None of these
    # prefixes is ignored by git, so a pull request can commit `tmp/run.sh`
    # with a Cross invocation; it must be reported as outside the scanned
    # automation roots rather than skipped unscanned.
    def generated_prefix_workflow(command_path: str) -> str:
        return (
            "name: Generated prefix\n"
            "on: [push]\n"
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            f"      - run: bash {command_path}\n"
        )

    for prefix in GENERATED_SCRIPT_PREFIXES:
        smuggled = f"{prefix}run.sh"
        if smuggled in GENERATED_COMMAND_PATHS:
            failures.append(f"{smuggled} must not be an exact generated command")
            continue
        if not any(
            "outside the scanned automation roots" in error
            for error in validate_automation_collection(
                {"ci.yml": generated_prefix_workflow(smuggled)},
                {},
                {},
                "self-test generated prefix",
            )
        ):
            failures.append(
                f"a committed script under {prefix!r} escaped the automation roots"
            )

    # The exact build outputs stay exempt, and an approved-root script is still
    # scanned rather than reported.
    for exempt_path in GENERATED_COMMAND_PATHS:
        if "/" not in exempt_path:
            continue
        if validate_automation_collection(
            {"ci.yml": generated_prefix_workflow(exempt_path)},
            {},
            {},
            "self-test generated prefix",
        ):
            failures.append(f"exact generated build output {exempt_path!r} was rejected")

    if not any(
        "references missing automation" in error
        for error in validate_automation_collection(
            {"ci.yml": generated_prefix_workflow("scripts/absent.sh")},
            {},
            {},
            "self-test generated prefix",
        )
    ):
        failures.append("an approved-root command was not followed into automation")

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
        "run: bash scripts/safe.sh",
        "run: |\n"
        "          python3 - <<'PY'\n"
        "          print('| GCP/Azure | src/plugins/mod.rs | n/a |')\n"
        "          print('attacker.sh is fixture data, not a command')\n"
        "          PY",
    )
    benign_heredoc_errors = validate_automation_collection(
        {"ci.yml": benign_heredoc_workflow},
        {"setup/action.yml": safe_action},
        safe_automation,
        "self-test automation directory",
    )
    if benign_heredoc_errors:
        failures.append(
            "benign inline-program data was treated as an executable path: "
            + "; ".join(benign_heredoc_errors)
        )

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
    # A make variable holding Cross is the make-native spelling of an aliased
    # executable, so expanding assignments must catch it rather than relying on
    # the blunt opaque-substitution rule that also freezes `$(MAKE)`.
    dispatcher_escapes(
        "make variable dispatcher",
        "make arm64",
        {"Makefile": "CARGO = cargo\narm64:\n\t$(CARGO) build --locked\n"},
        {"Makefile": f"CARGO = cross\narm64:\n\t$(CARGO) {arm_target}\n"},
    )
    dispatcher_escapes(
        "braced make variable dispatcher",
        "make arm64",
        {"Makefile": "CARGO := cargo\narm64:\n\t${CARGO} build --locked\n"},
        {"Makefile": f"CARGO := cross\narm64:\n\t${{CARGO}} {arm_target}\n"},
    )

    def benign_dispatcher(label: str, command: str, manifest: dict[str, str]) -> None:
        """An ordinary recipe must stay editable instead of freezing closed."""

        dispatcher_workflow = referenced_workflow.replace(
            "bash scripts/safe.sh",
            command,
        )
        tree_errors = validate_automation_collection(
            {"ci.yml": dispatcher_workflow},
            {"setup/action.yml": safe_action},
            manifest,
            "self-test automation directory",
        )
        if tree_errors:
            failures.append(
                f"benign {label} was rejected by tree validation: "
                f"{'; '.join(tree_errors)}"
            )
        comparison_errors = compare_pr_automation_collection(
            {"ci.yml": dispatcher_workflow},
            {"ci.yml": dispatcher_workflow},
            {"setup/action.yml": safe_action},
            {"setup/action.yml": safe_action},
            manifest,
            manifest,
            "self-test automation directory",
        )
        if comparison_errors:
            failures.append(
                f"benign {label} was rejected by PR comparison: "
                f"{'; '.join(comparison_errors)}"
            )

    # `$(MAKE)` is make's recursion handle, not a shell command substitution.
    benign_dispatcher(
        "recursive make recipe",
        "make arm64",
        {
            "Makefile": "arm64:\n\t$(MAKE) -C tests/performance all\n",
            "tests/performance/Makefile": "all:\n\tcargo build --locked\n",
        },
    )
    benign_dispatcher(
        "benign make variable recipe",
        "make arm64",
        {"Makefile": "CARGO = cargo\narm64:\n\t$(CARGO) build --locked\n"},
    )

    def opaque_shell_automation_escapes(label: str, body: str) -> None:
        """An unreadable executable surface must freeze the comparison."""

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

    # Shell variables are case-sensitive but equally executable, so a lowercase
    # name the same program assigns generates inline source just as an
    # uppercase one does.
    opaque_shell_automation_escapes(
        "lowercase generated inline python source",
        'cmd="import subprocess"\npython3 -c "$cmd"',
    )
    opaque_shell_automation_escapes(
        "lowercase generated inline perl source",
        "cmd='print 1'\nperl -e \"$cmd\"",
    )
    opaque_shell_automation_escapes(
        "whole-parameter inline source",
        'perl -e "$program"',
    )

    # A quote-split shim source never contains a raw `cross` token, so the
    # binding must be tokenized before the prefilter can reject the line.
    shell_automation_escapes(
        "quote-split Cross shim source",
        f'ln -s /home/runner/.cargo/bin/cr"oss" bin/cr\n./bin/cr {arm_target}',
    )
    shell_automation_escapes(
        "escape-split Cross shim source",
        f"cp /home/runner/.cargo/bin/cr\\oss bin/cx\n./bin/cx {arm_target}",
    )

    # `env -S` turns its operand into argv rather than discarding it.
    shell_automation_escapes(
        "env split-string Cross execution",
        f"env -S 'cross {arm_target}'",
    )
    shell_automation_escapes(
        "env joined split-string Cross execution",
        f"env --split-string='cross {arm_target}'",
    )
    shell_automation_escapes(
        "env attached split-string Cross execution",
        "env -Scross\\ build\\ --target\\ " + TARGET,
    )

    # `flock` and `script` run their operand as a real process.
    shell_automation_escapes(
        "flock command operand",
        f"flock /tmp/build.lock cross {arm_target}",
    )
    shell_automation_escapes(
        "flock shell command operand",
        f"flock /tmp/build.lock -c 'cross {arm_target}'",
    )
    shell_automation_escapes(
        "script command operand",
        f"script -c 'cross {arm_target}' /dev/null",
    )

    # An interpreter reading its program from stdin executes it exactly as a
    # shell does.
    shell_automation_escapes(
        "python here-string program",
        "python3 <<< 'import subprocess; subprocess.run([\"cross\", "
        f"\"build\", \"--target\", \"{TARGET}\"])'",
    )
    shell_automation_escapes(
        "python process-substitution program",
        "python3 < <(printf 'import os; os.system(\"cross "
        f"{arm_target}\")')",
    )

    # An attached short-option operand is ordinary inline source, not a missing
    # operand, so a benign program must stay readable while a Cross one is
    # still caught.
    benign_attached_option = {
        "scripts/safe.sh": "#!/bin/sh\nperl -e'print 1'\n"
    }
    attached_option_errors = compare_pr_automation_collection(
        {"ci.yml": referenced_workflow},
        {"ci.yml": referenced_workflow},
        {"setup/action.yml": safe_action},
        {"setup/action.yml": safe_action},
        safe_automation,
        benign_attached_option,
        "self-test automation directory",
    )
    if attached_option_errors:
        failures.append(
            "benign attached inline-source operand was rejected: "
            f"{'; '.join(attached_option_errors)}"
        )
    shell_automation_escapes(
        "attached inline-source Cross execution",
        f"perl -e'system(\"cross {arm_target}\")'",
    )

    # Node dispatchers bound by destructuring or import are invisible to a
    # member-call-only reader.
    node_alias_workflow = referenced_workflow.replace(
        "bash scripts/safe.sh",
        "node scripts/safe.js",
    )
    node_alias_baseline = {"scripts/safe.js": "console.log('safe');\n"}
    for alias_label, alias_body in {
        "destructured child_process alias": (
            "const {execSync} = require('child_process');\n"
            f"execSync('cross {arm_target}');\n"
        ),
        "imported child_process alias": (
            "import {spawnSync as run} from 'node:child_process';\n"
            f"run('cross', ['build', '--target', '{TARGET}']);\n"
        ),
    }.items():
        if not compare_pr_automation_collection(
            {"ci.yml": node_alias_workflow},
            {"ci.yml": node_alias_workflow},
            {"setup/action.yml": safe_action},
            {"setup/action.yml": safe_action},
            node_alias_baseline,
            {"scripts/safe.js": alias_body},
            "self-test automation directory",
        ):
            failures.append(f"{alias_label} was not rejected")

    # asyncio reaches the same executables as `subprocess`.
    python_automation_escapes(
        "asyncio shell process dispatch",
        "import asyncio\n"
        f"asyncio.run(asyncio.create_subprocess_shell('cross {arm_target}'))\n",
    )
    python_automation_escapes(
        "asyncio exec process dispatch",
        "import asyncio\n"
        "asyncio.run(asyncio.create_subprocess_exec(\n"
        f"    'cross', {arm_arguments}\n"
        "))\n",
    )
    python_automation_escapes(
        "aliased asyncio process dispatch",
        "from asyncio import create_subprocess_exec as run\n"
        f"run('cross', {arm_arguments})\n",
    )

    # The artifact-transfer carve-out must stay exactly as narrow as it claims.
    artifact_action = "actions/download-artifact@" + ("a" * 40)
    artifact_workflow = (
        "name: Artifacts\n"
        "on: [push]\n"
        "jobs:\n"
        "  publish:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: USES\n"
        "        with:\n"
        "          KEY: VALUE\n"
    )

    def artifact_surface(uses: str, key: str, value: str) -> dict[int, str]:
        surfaces, _ = remote_action_surface_lines(
            artifact_workflow.replace("USES", uses)
            .replace("KEY", key)
            .replace("VALUE", value),
            "self-test artifact workflow",
        )
        return surfaces

    if artifact_surface(artifact_action, "name", f"binary-{TARGET}"):
        failures.append("exact ARM64 artifact name was rejected")
    if artifact_surface(artifact_action, "path", f"downloaded/binary-{TARGET}"):
        failures.append("exact ARM64 artifact path was rejected")
    for carve_label, carve_uses, carve_key, carve_value in (
        ("unpinned artifact action", "actions/download-artifact@v8", "name", f"binary-{TARGET}"),
        ("non-artifact action", "some/other-action@" + ("b" * 40), "name", f"binary-{TARGET}"),
        ("artifact action Cross token", artifact_action, "name", "cross"),
        ("artifact action Cross image", artifact_action, "name", EXPECTED_IMAGE),
        ("artifact action non-artifact key", artifact_action, "args", TARGET),
        ("artifact action Cross input key", artifact_action, "use-cross", "true"),
    ):
        if not artifact_surface(carve_uses, carve_key, carve_value):
            failures.append(f"{carve_label} was not protected")

    # A YAML step is one mapping, so the reference, its inputs, and the matrix
    # that feeds them must be read the way the Actions runner reads them: in any
    # key order, through quoted and flow spellings, across folded scalars, and
    # with expressions resolved rather than compared as literal text.
    def step_surface(step_body: str, extra: str = "") -> dict[int, str]:
        surfaces, _ = remote_action_surface_lines(
            "name: Steps\n"
            "on: [push]\n"
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
            + extra
            + "    steps:\n"
            + step_body,
            "self-test step workflow",
        )
        return surfaces

    remote_action = "actions-rs/cargo@" + ("c" * 40)
    other_action = "some/other-action@" + ("d" * 40)
    literal_matrix = (
        "    strategy:\n"
        "      matrix:\n"
        f"        target: [{TARGET}]\n"
    )
    benign_matrix = (
        "    strategy:\n"
        "      matrix:\n"
        "        target: [x86_64-unknown-linux-gnu]\n"
    )
    dynamic_matrix = "    strategy:\n      matrix: ${{ fromJSON(needs.plan.outputs.m) }}\n"

    hidden_surfaces = {
        "inputs declared above the reference": (
            "      - with:\n"
            "          use-cross: true\n"
            f"        uses: {remote_action}\n",
            "",
        ),
        "named step with inputs above the reference": (
            "      - name: Build\n"
            "        with:\n"
            f"          args: build --target {TARGET}\n"
            f"        uses: {other_action}\n",
            "",
        ),
        "single-quoted input key": (
            f"      - uses: {remote_action}\n"
            "        with:\n"
            "          'use-cross': true\n",
            "",
        ),
        "double-quoted input key": (
            f"      - uses: {remote_action}\n"
            "        with:\n"
            '          "use-cross": true\n',
            "",
        ),
        "flow-mapping quoted input key": (
            f"      - uses: {remote_action}\n"
            "        with: {'use-cross': true}\n",
            "",
        ),
        "folded double-quoted target": (
            f"      - uses: {other_action}\n"
            "        with:\n"
            '          args: "build --target aarch64-\\\n'
            '            unknown-linux-gnu"\n',
            "",
        ),
        "matrix-derived target argument": (
            f"      - uses: {other_action}\n"
            "        with:\n"
            "          args: build --target ${{ matrix.target }}\n",
            literal_matrix,
        ),
        "unresolvable matrix target argument": (
            f"      - uses: {other_action}\n"
            "        with:\n"
            "          args: build --target ${{ matrix.target }}\n",
            dynamic_matrix,
        ),
        "matrix-derived artifact name on a non-artifact action": (
            f"      - uses: {other_action}\n"
            "        with:\n"
            "          name: binary-${{ matrix.target }}\n",
            literal_matrix,
        ),
    }
    for label, (body, extra) in hidden_surfaces.items():
        if not step_surface(body, extra):
            failures.append(f"{label} was not protected")

    benign_steps = {
        "flow-mapping artifact name": (
            f"      - uses: {artifact_action}\n"
            "        with: {name: binary-" + TARGET + "}\n",
            "",
        ),
        "flow-mapping artifact name and path": (
            f"      - uses: {artifact_action}\n"
            "        with: {name: binary-"
            + TARGET
            + ", path: downloaded/binary-"
            + TARGET
            + "}\n",
            "",
        ),
        "matrix-derived artifact name on a pinned artifact action": (
            f"      - uses: {artifact_action}\n"
            "        with:\n"
            "          name: binary-${{ matrix.target }}\n",
            literal_matrix,
        ),
        "matrix target that never selects ARM64": (
            f"      - uses: {other_action}\n"
            "        with:\n"
            "          args: build --target ${{ matrix.target }}\n",
            benign_matrix,
        ),
        "unresolvable matrix without a target argument": (
            f"      - uses: {other_action}\n"
            "        with:\n"
            "          targets: ${{ matrix.target }}\n",
            dynamic_matrix,
        ),
        "credential inputs": (
            f"      - uses: {other_action}\n"
            "        with:\n"
            "          password: ${{ secrets.GITHUB_TOKEN }}\n"
            "          username: ${{ github.actor }}\n",
            "",
        ),
    }
    for label, (body, extra) in benign_steps.items():
        if step_surface(body, extra):
            failures.append(f"{label} was rejected")

    # A flow mapping that also carries a non-artifact key is not covered by the
    # closed artifact carve-out.
    if not step_surface(
        f"      - uses: {artifact_action}\n"
        "        with: {name: binary-" + TARGET + ", args: --target " + TARGET + "}\n"
    ):
        failures.append("flow-mapping artifact carve-out leaked a build argument")

    # The step above a remote action belongs to that step, not to this one.
    if step_surface(
        "      - name: Unrelated\n"
        f"        run: echo {TARGET}\n"
        f"      - uses: {other_action}\n"
        "        with:\n"
        "          context: .\n"
    ):
        failures.append("a preceding step's contents leaked into the next step")

    # A `shell: pwsh` body is PowerShell, not POSIX shell.
    powershell_workflow = (
        "name: PowerShell\n"
        "on: [push]\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: windows-latest\n"
        "    steps:\n"
        "      - name: Windows step\n"
        "        shell: pwsh\n"
        "        run: |\n"
        "          BODY\n"
    )
    for powershell_label, powershell_body in {
        "PowerShell Start-Process Cross dispatch": (
            f"Start-Process cross -ArgumentList 'build','--target','{TARGET}'"
        ),
        "PowerShell call-operator Cross dispatch": f"& cross {arm_target}",
        "PowerShell direct Cross dispatch": f"cross {arm_target}",
        "PowerShell Invoke-Expression dispatch": (
            "Invoke-Expression $generatedCommand"
        ),
        "PowerShell computed call operator": "& $tool build",
    }.items():
        # Assert through the PowerShell reader itself, not through the
        # surrounding lexical rules, so the fixture cannot pass vacuously.
        powershell_programs, powershell_interpreter_errors = workflow_run_programs(
            powershell_workflow.replace("BODY", powershell_body),
            "self-test powershell workflow",
        )
        if [language for language, _ in powershell_programs] != ["powershell"]:
            failures.append(
                f"{powershell_label} body was not read as PowerShell: "
                f"{powershell_programs!r}"
            )
            continue
        powershell_sensitive, powershell_body_errors = runtime_program_cross_surface(
            powershell_programs,
            "self-test powershell workflow",
            include_opaque_shell_executable=True,
        )
        if not powershell_sensitive and not powershell_body_errors and not (
            powershell_interpreter_errors
        ):
            failures.append(f"{powershell_label} was not protected")
        surfaces, errors = generic_workflow_cross_surfaces(
            powershell_workflow.replace("BODY", powershell_body),
            "self-test powershell workflow",
            include_opaque_shell_executable=True,
        )
        if not surfaces and not errors:
            failures.append(f"{powershell_label} was not protected end to end")
    benign_powershell = (
        '$ErrorActionPreference = "Stop"\n'
        '          $root = Join-Path $env:RUNNER_TEMP "protoc"\n'
        '          Invoke-WebRequest -Uri "https://example.invalid/x.zip" '
        '-OutFile $zip\n'
        "          Expand-Archive -Path $zip -DestinationPath $root -Force\n"
        "          if (!(Test-Path $root)) {\n"
        '            throw "missing $root"\n'
        "          }\n"
        "          $root | Out-File -Append -FilePath $env:GITHUB_PATH "
        "-Encoding utf8"
    )
    # Assert on the interpreter itself. The surrounding lexical rule that
    # substitutes Cross into every opaque expansion is deliberately unchanged
    # here, so the PowerShell reader is what must stay quiet on an ordinary
    # body modelled on the real `shell: pwsh` steps in ci.yml/release.yml.
    benign_programs, benign_interpreter_errors = workflow_run_programs(
        powershell_workflow.replace("BODY", benign_powershell),
        "self-test powershell workflow",
    )
    if [language for language, _ in benign_programs] != ["powershell"]:
        failures.append(
            f"benign PowerShell body was not read as PowerShell: {benign_programs!r}"
        )
    benign_sensitive, benign_powershell_errors = runtime_program_cross_surface(
        benign_programs,
        "self-test powershell workflow",
        include_opaque_shell_executable=True,
    )
    if benign_sensitive or benign_interpreter_errors or benign_powershell_errors:
        failures.append(
            "benign PowerShell workflow body was rejected: "
            f"sensitive={benign_sensitive!r}; "
            f"errors={benign_interpreter_errors + benign_powershell_errors!r}"
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
        "      - run: |\n"
        "          planner_dir=.github/scripts\n"
        '          trusted_dir="$RUNNER_TEMP/pr-ci-plan-self-test"\n'
        '          planner_dir="$trusted_dir"\n'
        f"          {ISOLATED_PLANNER_LAUNCHER} --self-test\n"
        "      - run: |\n"
        '          planner_dir=".github/scripts"\n'
        '          trusted_dir="$RUNNER_TEMP/pr-ci-plan"\n'
        '          planner_dir="$trusted_dir"\n'
        f"          plan=\"$({ISOLATED_PLANNER_LAUNCHER} \\\n"
        "            --event-name pull_request)\"\n"
    )
    if validate_ci_planner_isolation(
        isolated_planner_workflow,
        "self-test CI workflow",
    ):
        failures.append("isolated trusted planner fixture was rejected")
    poisoned_planner_workflow = isolated_planner_workflow.replace(
        "python3 -I -c",
        "python3 -c",
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
        "literal pipeline shell stdin after shell options",
        f"printf 'cross {arm_target}' | bash --norc",
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
        "literal pipeline shell input after shell options": (
            "printf 'cargo build --locked' | bash --norc"
        ),
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
    ci_publish_steps = PUBLISH_ARTIFACT_STEP_CONTRACTS["CI workflow"]["docker"]
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
        + ci_publish_contract["docker"]["strategy"]
        + "    steps:\n"
        + ci_publish_steps["Download Linux binary"]
        + "\n"
        + ci_publish_steps["Prepare Docker context"]
        + "\n"
        + "      - run: echo docker\n"
    )
    if validate_publish_control_contract(publish_workflow, "CI workflow"):
        failures.append("valid ARM64 publication dependency controls were rejected")

    # The Docker jobs never name the ARM64 artifact literally, so repointing the
    # `linux/arm64` matrix row or rewriting either consuming step would publish
    # an ARM64 image built from the x86_64 binary.
    artifact_selection_edits = {
        "arm64 matrix row repointed at the x86_64 artifact": (
            "            binary_target: aarch64-unknown-linux-gnu\n"
            "            binary_asset: ferrum-edge-linux-aarch64\n",
            "            binary_target: x86_64-unknown-linux-gnu\n"
            "            binary_asset: ferrum-edge-linux-x86_64\n",
        ),
        "arm64 platform row bound to the x86_64 target": (
            "          - platform: linux/arm64\n"
            "            binary_target: aarch64-unknown-linux-gnu\n",
            "          - platform: linux/arm64\n"
            "            binary_target: x86_64-unknown-linux-gnu\n",
        ),
        "download step renamed to a fixed artifact": (
            "          name: binary-${{ matrix.binary_target }}\n",
            "          name: binary-x86_64-unknown-linux-gnu\n",
        ),
        "context step copies a fixed asset": (
            "cp downloaded-artifacts/${{ matrix.binary_asset }} ",
            "cp downloaded-artifacts/ferrum-edge-linux-x86_64 ",
        ),
    }
    for label, (original, replacement) in artifact_selection_edits.items():
        tampered = publish_workflow.replace(original, replacement, 1)
        if tampered == publish_workflow:
            failures.append(f"{label} fixture did not change the workflow")
            continue
        if not validate_publish_control_contract(tampered, "CI workflow"):
            failures.append(f"{label} was not rejected")
        if not compare_pr_publish_control_contract(
            publish_workflow,
            tampered,
            "CI workflow",
        ):
            failures.append(f"{label} was allowed by the merge-base comparison")

    duplicate_publish_step = publish_workflow.replace(
        ci_publish_steps["Prepare Docker context"],
        ci_publish_steps["Prepare Docker context"]
        + "\n"
        + ci_publish_steps["Prepare Docker context"],
        1,
    )
    if not validate_publish_control_contract(duplicate_publish_step, "CI workflow"):
        failures.append("duplicate artifact-selection step was not rejected")

    release_publish_steps = PUBLISH_ARTIFACT_STEP_CONTRACTS["release workflow"][
        "docker"
    ]
    if (
        release_publish_steps["Download Linux binary"]
        == ci_publish_steps["Download Linux binary"]
    ):
        failures.append(
            "release and CI artifact-selection contracts must name distinct "
            "artifacts"
        )

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

    trusted_extraction_fixture = (
        'git fetch --no-tags origin '
        '"+refs/heads/${BASE_REF}:refs/remotes/trusted-base"\n'
        'trusted_base="$(git rev-parse "refs/remotes/trusted-base^{commit}")"\n'
        'git merge-base --is-ancestor "$BASE_SHA" "$trusted_base"\n'
        'git show "$trusted_base:.github/workflows/ci.yml"\n'
        'git show "$trusted_base:.github/workflows/release.yml"\n'
        'extract_workflows "$trusted_base" "$merge_base_workflows"\n'
        'extract_actions "$trusted_base" "$merge_base_actions"\n'
        'extract_automation "$trusted_base" "$merge_base_automation"\n'
        'git show "$trusted_base:.github/scripts/verify_cross_build_policy.py"\n'
        'git show "$trusted_base:.github/workflows/cross-build-policy.yml"\n'
        'if ! git diff --no-ext-diff --quiet "$BASE_SHA" "$trusted_base" \\\n'
        '  -- ".github/workflows/cross-build-policy.yml"; then\n'
        "  exit 1\n"
        "fi\n"
        'python3 -I "$trusted_verifier" \\\n'
        '  --ci-workflow "$merge_base_ci" \\\n'
        '  --release-workflow "$merge_base_release" \\\n'
        '  --trusted-policy-workflow "$trusted_policy_workflow" \\\n'
        '  --workflows-dir "$merge_base_workflows" \\\n'
        '  --actions-dir "$merge_base_actions" \\\n'
        '  --automation-dir "$merge_base_automation"\n'
        'if ! git ls-tree -rz --name-only "$commit" -- workflows > "$listing"; then\n'
        "  return 1\n"
        "fi\n"
        'if ! git ls-tree -rz --name-only "$commit" -- actions > "$listing"; then\n'
        "  return 1\n"
        "fi\n"
        'if ! git ls-tree -rz --name-only "$commit" -- scripts > "$listing"; then\n'
        "  return 1\n"
        "fi\n"
        'if ! git ls-tree -rz --name-only "$commit" > "$workspace_listing"; then\n'
        "  return 1\n"
        "fi\n"
    )
    if validate_trusted_policy_extraction(
        trusted_extraction_fixture,
        "self-test trusted policy",
    ):
        failures.append("valid checked live-base extraction was rejected")
    stale_extraction_fixture = trusted_extraction_fixture.replace(
        'extract_workflows "$trusted_base" "$merge_base_workflows"',
        'extract_workflows "$merge_base" "$merge_base_workflows"',
    )
    if not validate_trusted_policy_extraction(
        stale_extraction_fixture,
        "self-test trusted policy",
    ):
        failures.append("stale merge-base extraction was not rejected")
    for extraction_label, unpinned_extraction in {
        "event-base verifier execution": trusted_extraction_fixture.replace(
            'python3 -I "$trusted_verifier"',
            "python3 -I .github/scripts/verify_cross_build_policy.py",
        ),
        "unauthenticated extraction contract": trusted_extraction_fixture.replace(
            'if ! git diff --no-ext-diff --quiet "$BASE_SHA" "$trusted_base" \\\n',
            "if false; then\n",
        ),
        "event-base trusted contract inputs": trusted_extraction_fixture.replace(
            '  --ci-workflow "$merge_base_ci" \\\n',
            "  --ci-workflow .github/workflows/ci.yml \\\n",
        ),
    }.items():
        if not validate_trusted_policy_extraction(
            unpinned_extraction,
            "self-test trusted policy",
        ):
            failures.append(f"{extraction_label} was not rejected")
    for label, stale_baseline in {
        "stale event-base workflow extraction": (
            'extract_workflows "$trusted_base" "$merge_base_workflows"',
            'extract_workflows HEAD "$merge_base_workflows"',
        ),
        "stale event-base CI baseline": (
            'git show "$trusted_base:.github/workflows/ci.yml"',
            'git show "HEAD:.github/workflows/ci.yml"',
        ),
        "unfetched live base": (
            'git fetch --no-tags origin '
            '"+refs/heads/${BASE_REF}:refs/remotes/trusted-base"\n',
            "",
        ),
        "unauthenticated live base": (
            'git merge-base --is-ancestor "$BASE_SHA" "$trusted_base"\n',
            "",
        ),
        "unpinned live base": (
            'trusted_base="$(git rev-parse "refs/remotes/trusted-base^{commit}")"\n',
            "",
        ),
    }.items():
        original, replacement = stale_baseline
        if not validate_trusted_policy_extraction(
            trusted_extraction_fixture.replace(original, replacement),
            "self-test trusted policy",
        ):
            failures.append(f"{label} was not rejected")
    process_substitution_fixture = trusted_extraction_fixture.replace(
        'if ! git ls-tree -rz --name-only "$commit" -- workflows > "$listing"; then',
        'done < <(git ls-tree -rz --name-only "$commit" -- workflows)',
    )
    if not validate_trusted_policy_extraction(
        process_substitution_fixture,
        "self-test trusted policy",
    ):
        failures.append("unchecked process-substitution extraction was not rejected")

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
    parser.add_argument(
        "--trusted-policy-workflow",
        type=Path,
        default=Path(".github/workflows/cross-build-policy.yml"),
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

    trusted_policy, trusted_policy_failures = load_workflow(
        args.trusted_policy_workflow,
        "trusted Cross policy workflow",
    )
    failures.extend(trusted_policy_failures)
    if not trusted_policy_failures:
        assert trusted_policy is not None
        failures.extend(
            validate_trusted_policy_extraction(
                trusted_policy,
                "trusted Cross policy workflow",
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
