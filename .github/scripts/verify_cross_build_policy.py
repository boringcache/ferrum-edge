#!/usr/bin/env python3
"""Enforce the complete trusted ARM64 Cross 0.2.5 policy boundary."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tomllib
from pathlib import Path
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
        "8ea20fea0ba8358c7e164bf3e2cdd67532b2a617fffe685d2dc5dace7c19a23d",
        "143872ebf5dd925529b785273f180671bcc3bbd612d74ef0b88e1b8dce86c774",
        "d775752cb399db3b0660e26e0d9bdb32d7d72cf4ed47694066ccbf629e87e80f",
    ),
    (
        "release workflow",
        "build-release-arm64-cross",
        "8cb2fed36e8e569eb51d3e3e285ec41b1cd1b6841a79392d6e9cb293df9297e7",
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
SHELL_INTERPOLATION = re.compile(
    r"\$\{[^{}\n]*\}|`[^`\n]*`|"
    r"\$[A-Za-z_][A-Za-z0-9_]*|\$[0-9@*#?$!-]"
)
WORKFLOW_FILENAME = re.compile(r"^[A-Za-z0-9._-]+\.(?:yml|yaml)$")
PROTECTED_WORKFLOW_FILENAMES = frozenset({"ci.yml", "release.yml"})


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


def opaque_command_completion_variants(line: str) -> tuple[str, ...]:
    """Expose opaque substitutions that can complete a literal Cross token."""

    variants: list[str] = []
    fragments = {
        "cross"[start:end]
        for start in range(len("cross"))
        for end in range(start + 1, len("cross") + 1)
    }
    for start, end in command_substitution_spans(line):
        prefix_match = re.search(r"[A-Za-z]+$", line[:start])
        suffix_match = re.match(r"[A-Za-z]+", line[end:])
        prefix = prefix_match.group() if prefix_match is not None else ""
        suffix = suffix_match.group() if suffix_match is not None else ""
        if not prefix and not suffix:
            continue
        for fragment in fragments:
            if f"{prefix}{fragment}{suffix}" == "cross":
                variants.append(line[:start] + fragment + line[end:])
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


def scan_variants(line: str) -> tuple[str, ...]:
    """Expose ordinary YAML/shell quoting variants to the lexical boundary."""

    variants = [line]
    variants.extend(opaque_command_completion_variants(line))
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
            variants.append(decoded)

    expanded_variants = [
        expanded
        for variant in variants
        for expanded in brace_expansion_variants(variant)
    ]
    return tuple(dict.fromkeys(expanded_variants))


def contains_cross_surface(contents: str) -> bool:
    """Return whether lexical normalization exposes a Cross-controlled input."""

    logical_contents = re.sub(r"\\\r?\n[ \t]*", "", contents)
    return any(
        STANDALONE_CROSS.search(variant) or CROSS_ENVIRONMENT.search(variant)
        for line in logical_contents.splitlines()
        for variant in scan_variants(line)
    )


def unprotected_cross_surfaces(
    contents: str,
    source: str,
    job_name: str,
    *,
    required_job: bool,
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

        logical_contents = re.sub(r"\\\r?\n[ \t]*", "", block_contents)
        for logical_line in logical_contents.splitlines():
            for variant in scan_variants(logical_line):
                if STANDALONE_CROSS.search(variant) or CROSS_ENVIRONMENT.search(variant):
                    sensitive_jobs.add(name)
                    break
            if name in sensitive_jobs:
                break

    top_level_surfaces: list[str] = []
    for index, line in enumerate(lines):
        line_surfaces: set[str] = set()
        for variant in scan_variants(line):
            normalized = re.sub(r"\s+", " ", variant).strip()
            if STANDALONE_CROSS.search(variant):
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


def generic_workflow_cross_surfaces(
    contents: str,
    source: str,
) -> tuple[tuple[str, ...], list[str]]:
    """Scan a workflow that must not contain any Cross-controlled surface."""

    # Avoid imposing a YAML layout contract on unrelated workflows. As soon as
    # a Cross token is exposed, however, parse the job layout conservatively so
    # malformed, duplicate, and alias-shaped jobs fail closed.
    if not contains_cross_surface(contents):
        return (), []
    return unprotected_cross_surfaces(
        contents,
        source,
        "__no_unprotected_cross_job__",
        required_job=False,
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
        )
        proposed_surfaces, proposed_failures = generic_workflow_cross_surfaces(
            proposed_contents,
            f"proposed {source}/{name}",
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
    )
    errors.extend(surface_failures)
    if surfaces:
        errors.append(
            f"{source} contains Cross executable or configuration input outside "
            f"protected job {job_name!r}"
        )
    errors.extend(validate_publish_control_contract(contents, source))
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
    )
    proposed_surfaces, proposed_surface_failures = unprotected_cross_surfaces(
        proposed_contents,
        f"proposed {source}",
        job_name,
        required_job=False,
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
        "unprotected GitHub interpolation": workflow.replace(
            "echo safe",
            "cr${{ 'o' }}ss build --target aarch64-unknown-linux-gnu",
        ),
        "unprotected GitHub format expression": workflow.replace(
            "echo safe",
            "${{ format('cr{0}ss', 'o') }} build "
            "--target aarch64-unknown-linux-gnu",
        ),
        "unprotected Bash brace expansion": workflow.replace(
            "echo safe",
            "cr{o,}ss build --target aarch64-unknown-linux-gnu",
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=Path("Cross.toml"))
    parser.add_argument("--cargo-config", type=Path, default=Path("Cargo.toml"))
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
    parser.add_argument("--merge-base-workflows-dir", type=Path)
    parser.add_argument("--proposed-workflows-dir", type=Path)
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

    pr_paths = (
        args.merge_base_ci_workflow,
        args.proposed_ci_workflow,
        args.merge_base_release_workflow,
        args.proposed_release_workflow,
        args.merge_base_workflows_dir,
        args.proposed_workflows_dir,
    )
    if any(path is not None for path in pr_paths) and not all(
        path is not None for path in pr_paths
    ):
        failures.append(
            "all merge-base/proposed workflow arguments must be supplied together"
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

    for failure in failures:
        print(f"::error::{failure}", file=sys.stderr)
    if failures:
        return 1

    print(
        "ARM64 Cross 0.2.5 configuration, Cargo metadata, and isolated "
        "workflow invocations match the complete trusted policy."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
