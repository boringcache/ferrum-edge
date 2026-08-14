#!/usr/bin/env python3
"""Record CI phase timings, cache restore evidence, and retry amplification.

Writes a bounded markdown summary. Never prints environment dumps, tokens,
secrets, or cache credentials. Unknown or malformed values fail closed to a
redacted placeholder rather than echoing raw runner state.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

SECRET_RE = re.compile(
    r"(?i)(token|secret|password|passwd|authorization|bearer|ghp_|github_pat_|ghs_|gho_|ghu_)"
)
SAFE_INT_RE = re.compile(r"^[0-9]+$")
SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,80}$")
MAX_STATE_BYTES = 64 * 1024
MAX_PHASES = 64


def state_path() -> Path:
    root = os.environ.get("RUNNER_TEMP") or os.environ.get("CI_RUNTIME_TELEMETRY_DIR")
    if root:
        return Path(root) / "ci-runtime-telemetry.json"
    return Path.cwd() / ".ci-runtime-telemetry.json"


def redact(value: str) -> str:
    text = value.replace("\r", " ").replace("\n", " ").strip()
    if SECRET_RE.search(text):
        return "<redacted>"
    if len(text) > 240:
        return text[:240] + "…"
    return text


def load_state(path: Path) -> dict:
    if not path.is_file():
        return {"phases": [], "caches": [], "meta": {}}
    raw = path.read_bytes()
    if len(raw) > MAX_STATE_BYTES:
        raise SystemExit("telemetry state exceeds the 64 KiB bound")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SystemExit(f"telemetry state is not valid JSON: {error}") from error
    if not isinstance(data, dict):
        raise SystemExit("telemetry state must be an object")
    data.setdefault("phases", [])
    data.setdefault("caches", [])
    data.setdefault("meta", {})
    return data


def save_state(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(data, indent=2, sort_keys=True) + "\n"
    if len(encoded.encode("utf-8")) > MAX_STATE_BYTES:
        raise SystemExit("telemetry state exceeds the 64 KiB bound")
    path.write_text(encoded, encoding="utf-8")


def require_name(value: str, label: str) -> str:
    if not SAFE_NAME_RE.fullmatch(value):
        raise SystemExit(f"invalid {label}")
    return value


def parse_attempt(raw: str | None) -> int:
    text = (raw or "").strip() or "1"
    if not SAFE_INT_RE.fullmatch(text):
        return 1
    return int(text)


def cmd_init(args: argparse.Namespace) -> int:
    path = state_path()
    data = load_state(path)
    attempt = parse_attempt(os.environ.get("GITHUB_RUN_ATTEMPT"))
    data["meta"] = {
        "run_attempt": attempt,
        "event_name": redact(os.environ.get("GITHUB_EVENT_NAME") or "unknown"),
        "job": redact(os.environ.get("GITHUB_JOB") or "unknown"),
        "force_cold_cache": os.environ.get("FERRUM_CI_FORCE_COLD_CACHE") == "true",
    }
    save_state(path, data)
    if args.quiet:
        return 0
    print(f"ci-runtime telemetry initialized (attempt={attempt})")
    return 0


def cmd_start(args: argparse.Namespace) -> int:
    name = require_name(args.phase, "phase")
    path = state_path()
    data = load_state(path)
    starts = data.setdefault("starts", {})
    starts[name] = time.monotonic()
    save_state(path, data)
    return 0


def cmd_end(args: argparse.Namespace) -> int:
    name = require_name(args.phase, "phase")
    path = state_path()
    data = load_state(path)
    starts = data.setdefault("starts", {})
    started = starts.pop(name, None)
    duration = None if started is None else max(0.0, time.monotonic() - float(started))
    if len(data["phases"]) >= MAX_PHASES:
        raise SystemExit("too many telemetry phases")
    data["phases"].append(
        {
            "name": name,
            "seconds": None if duration is None else round(duration, 1),
            "status": int(args.status),
        }
    )
    save_state(path, data)
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    name = require_name(args.phase, "phase")
    if not args.command:
        raise SystemExit("run requires a command after --")
    cmd_start(argparse.Namespace(phase=name))
    started = time.monotonic()
    try:
        completed = subprocess.run(args.command, check=False)
        status = int(completed.returncode)
    except OSError:
        status = 127
    duration = max(0.0, time.monotonic() - started)
    path = state_path()
    data = load_state(path)
    data.setdefault("starts", {}).pop(name, None)
    if len(data["phases"]) >= MAX_PHASES:
        raise SystemExit("too many telemetry phases")
    data["phases"].append(
        {
            "name": name,
            "seconds": round(duration, 1),
            "status": status,
        }
    )
    save_state(path, data)
    return status


def cmd_cache(args: argparse.Namespace) -> int:
    name = require_name(args.name, "cache name")
    path = state_path()
    data = load_state(path)
    hit_raw = (args.hit or "").strip().lower()
    if hit_raw in {"true", "yes", "1"}:
        hit = True
    elif hit_raw in {"false", "no", "0", ""}:
        hit = False
    else:
        hit = False
    restored_bytes = args.bytes
    if restored_bytes is None and args.path:
        cache_path = Path(args.path)
        restored_bytes = directory_size(cache_path) if cache_path.exists() else 0
    if len(data["caches"]) >= MAX_PHASES:
        raise SystemExit("too many telemetry cache rows")
    data["caches"].append(
        {
            "name": name,
            "hit": hit,
            "restored_bytes": int(restored_bytes or 0),
            "note": redact(args.note or ""),
        }
    )
    save_state(path, data)
    return 0


def directory_size(path: Path) -> int:
    total = 0
    if path.is_file():
        return path.stat().st_size
    if not path.is_dir():
        return 0
    for root, _dirs, files in os.walk(path, followlinks=False):
        for name in files:
            file_path = Path(root) / name
            try:
                if file_path.is_symlink():
                    continue
                total += file_path.stat().st_size
            except OSError:
                continue
    return total


def format_bytes(value: int) -> str:
    if value < 1024:
        return f"{value} B"
    if value < 1024 * 1024:
        return f"{value / 1024:.1f} KiB"
    if value < 1024 * 1024 * 1024:
        return f"{value / (1024 * 1024):.1f} MiB"
    return f"{value / (1024 * 1024 * 1024):.2f} GiB"


def cmd_summarize(args: argparse.Namespace) -> int:
    path = state_path()
    data = load_state(path)
    meta = data.get("meta") or {}
    attempt = int(meta.get("run_attempt") or parse_attempt(os.environ.get("GITHUB_RUN_ATTEMPT")))
    lines = [
        f"## {redact(args.title or 'CI runtime')}",
        "",
        f"- Event: `{redact(str(meta.get('event_name') or 'unknown'))}`",
        f"- Job: `{redact(str(meta.get('job') or 'unknown'))}`",
        f"- Run attempt: **{attempt}**",
    ]
    if attempt > 1:
        lines.append(
            "- Retry amplification: this is a hosted re-run; compare phase "
            "durations and cache hits against attempt 1 to measure lost compile work."
        )
    if meta.get("force_cold_cache"):
        lines.append(
            "- Cold cache: restore was disabled for this run to prove the live contracts."
        )
    lines.extend(["", "### Phases", ""])
    if data["phases"]:
        lines.append("| Phase | Duration | Status |")
        lines.append("|---|---:|---|")
        for phase in data["phases"]:
            seconds = phase.get("seconds")
            duration = "unknown" if seconds is None else f"{seconds:.1f}s"
            status = "ok" if int(phase.get("status") or 1) == 0 else "failed"
            lines.append(
                f"| `{redact(str(phase.get('name')))}` | {duration} | {status} |"
            )
    else:
        lines.append("No timed phases were recorded.")
    lines.extend(["", "### Caches", ""])
    if data["caches"]:
        lines.append("| Cache | Hit | Restored | Notes |")
        lines.append("|---|---|---:|---|")
        for cache in data["caches"]:
            hit = "hit" if cache.get("hit") else "miss"
            restored = format_bytes(int(cache.get("restored_bytes") or 0))
            note = redact(str(cache.get("note") or "")) or "—"
            lines.append(
                f"| `{redact(str(cache.get('name')))}` | {hit} | {restored} | {note} |"
            )
    else:
        lines.append("No cache restore rows were recorded.")
    lines.extend(
        [
            "",
            "Warm PR target: each production-image / FIPS gate <= 30 minutes, p95 <= 45 minutes.",
            "Hosted evidence: three consecutive warm `pull_request` runs after this change",
            "lands, plus one `workflow_dispatch` with `force_cold_cache=true`.",
            "",
        ]
    )
    summary = "\n".join(lines)
    if SECRET_RE.search(summary):
        raise SystemExit("refusing to write a summary that still looks like a secret")
    github_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if github_summary:
        with Path(github_summary).open("a", encoding="utf-8") as handle:
            handle.write(summary)
            if not summary.endswith("\n"):
                handle.write("\n")
    if not args.quiet:
        print(summary, end="" if summary.endswith("\n") else "\n")
    return 0


def self_test() -> int:
    failures: list[str] = []
    if redact("Authorization: Bearer ghp_example") != "<redacted>":
        failures.append("bearer tokens must be redacted")
    if redact("phase-compile") == "<redacted>":
        failures.append("ordinary phase names must not be redacted")
    if parse_attempt("3") != 3 or parse_attempt("nope") != 1:
        failures.append("run attempt parsing is wrong")
    previous = os.environ.get("CI_RUNTIME_TELEMETRY_DIR")
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        os.environ["CI_RUNTIME_TELEMETRY_DIR"] = tmp
        try:
            if cmd_init(argparse.Namespace(quiet=True)) != 0:
                failures.append("init failed")
            if cmd_cache(
                argparse.Namespace(
                    name="rust-cache",
                    hit="true",
                    bytes=2048,
                    path=None,
                    note="exact key",
                )
            ) != 0:
                failures.append("cache record failed")
            os.environ["GITHUB_STEP_SUMMARY"] = str(Path(tmp) / "summary.md")
            if cmd_summarize(argparse.Namespace(title="Test", quiet=True)) != 0:
                failures.append("summarize failed")
            written = Path(tmp).joinpath("summary.md").read_text(encoding="utf-8")
            if "ghp_" in written or "Bearer" in written:
                failures.append("summary leaked a secret")
            if "rust-cache" not in written or "hit" not in written:
                failures.append("summary omitted cache evidence")
            if "2.0 KiB" not in written:
                failures.append("summary omitted restored bytes")
        finally:
            if previous is None:
                os.environ.pop("CI_RUNTIME_TELEMETRY_DIR", None)
            else:
                os.environ["CI_RUNTIME_TELEMETRY_DIR"] = previous
            os.environ.pop("GITHUB_STEP_SUMMARY", None)
    for failure in failures:
        print(f"::error::{failure}", file=sys.stderr)
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command_name", required=True)

    init = sub.add_parser("init")
    init.add_argument("--quiet", action="store_true")
    init.set_defaults(func=cmd_init)

    start = sub.add_parser("start")
    start.add_argument("--phase", required=True)
    start.set_defaults(func=cmd_start)

    end = sub.add_parser("end")
    end.add_argument("--phase", required=True)
    end.add_argument("--status", type=int, default=0)
    end.set_defaults(func=cmd_end)

    run = sub.add_parser("run")
    run.add_argument("--phase", required=True)
    run.add_argument("command", nargs=argparse.REMAINDER)
    run.set_defaults(func=cmd_run)

    cache = sub.add_parser("cache")
    cache.add_argument("--name", required=True)
    cache.add_argument("--hit", default="")
    cache.add_argument("--bytes", type=int, default=None)
    cache.add_argument("--path", default=None)
    cache.add_argument("--note", default="")
    cache.set_defaults(func=cmd_cache)

    summarize = sub.add_parser("summarize")
    summarize.add_argument("--title", default="CI runtime")
    summarize.add_argument("--quiet", action="store_true")
    summarize.set_defaults(func=cmd_summarize)

    test = sub.add_parser("self-test")
    test.set_defaults(func=lambda _args: self_test())

    args = parser.parse_args()
    if args.command_name == "run" and args.command and args.command[0] == "--":
        args.command = args.command[1:]
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
