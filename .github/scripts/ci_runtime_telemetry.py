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
    # Explicit override must win over the hosted runner temp so a self-test
    # (or any isolated invocation) cannot mutate live job state.
    root = os.environ.get("CI_RUNTIME_TELEMETRY_DIR") or os.environ.get("RUNNER_TEMP")
    if root:
        return Path(root) / "ci-runtime-telemetry.json"
    return Path.cwd() / ".ci-runtime-telemetry.json"


def snapshot_env(names: tuple[str, ...]) -> dict[str, str | None]:
    return {name: os.environ.get(name) for name in names}


def restore_env(snapshot: dict[str, str | None]) -> None:
    for name, value in snapshot.items():
        if value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = value


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


def parse_cache_hit(raw: str | None) -> bool | None:
    text = (raw or "").strip().lower()
    if text in {"true", "yes", "1"}:
        return True
    if text in {"false", "no", "0"}:
        return False
    if text == "":
        return None
    raise SystemExit("invalid cache hit value")


def format_phase_status(status: object) -> str:
    """Render a recorded phase status without treating integer 0 as missing.

    `phase.get("status") or 1` is wrong: an explicit 0 is success. Missing or
    malformed values stay conservative (unknown) rather than looking like ok.
    """
    if status is None:
        return "unknown"
    if isinstance(status, bool):
        return "unknown"
    if isinstance(status, int):
        return "ok" if status == 0 else "failed"
    if isinstance(status, str) and SAFE_INT_RE.fullmatch(status.strip()):
        value = int(status.strip())
        return "ok" if value == 0 else "failed"
    return "unknown"


def classify_actions_cache_restore(
    hit_raw: str | None,
    matched_key: str | None,
    restored_path: str | None,
) -> str:
    """Classify actions/cache/restore v4 outputs.

    Semantics:
    - cache-hit == 'true' is an exact primary-key hit
    - cache-hit == 'false' is a restore-key partial match (still a hit)
    - empty cache-hit is an ordinary miss (first-run / no restore-keys)

    Exact and partial both require a nonempty matched key and an existing
    restored directory. Empty hit plus empty matched key is a miss.
    Contradictory or unknown combinations fail closed.
    """
    hit_text = (hit_raw or "").strip().lower()
    matched = (matched_key or "").strip()
    path = Path(restored_path) if restored_path else None
    exists = bool(path is not None and path.exists())

    if hit_text == "true":
        if not matched:
            raise SystemExit("exact cache hit requires a nonempty matched key")
        if not exists:
            raise SystemExit("exact cache hit requires an existing restored directory")
        return "exact"
    if hit_text == "false":
        if not matched:
            raise SystemExit("partial cache hit requires a nonempty matched key")
        if not exists:
            raise SystemExit("partial cache hit requires an existing restored directory")
        return "partial"
    if hit_text == "":
        if matched:
            raise SystemExit("cache miss cannot include a matched key")
        return "miss"
    raise SystemExit(
        "contradictory or unknown cache restore outputs; produced no hit/miss evidence"
    )


def resolve_restored_bytes(hit: bool | None, args: argparse.Namespace) -> int | None:
    if args.bytes is not None:
        return int(args.bytes)
    measured: int | None = None
    if args.path:
        cache_path = Path(args.path)
        if cache_path.exists():
            measured = directory_size(cache_path)
    if hit is True:
        if measured is None:
            raise SystemExit(
                "cache hit requires measured restored bytes (--bytes or an "
                "existing --path); refusing to invent 0 B"
            )
        return measured
    if hit is False:
        return 0 if measured is None else measured
    return measured


def cmd_cache(args: argparse.Namespace) -> int:
    name = require_name(args.name, "cache name")
    path = state_path()
    data = load_state(path)
    hit = parse_cache_hit(args.hit)
    restored_bytes = resolve_restored_bytes(hit, args)
    if len(data["caches"]) >= MAX_PHASES:
        raise SystemExit("too many telemetry cache rows")
    data["caches"].append(
        {
            "name": name,
            "hit": hit,
            "restored_bytes": restored_bytes,
            "note": redact(args.note or ""),
        }
    )
    save_state(path, data)
    return 0


def write_github_output(kind: str, publish: bool) -> None:
    output = os.environ.get("GITHUB_OUTPUT")
    if not output:
        return
    with Path(output).open("a", encoding="utf-8") as handle:
        handle.write(f"kind={kind}\n")
        handle.write(f"publish={'true' if publish else 'false'}\n")


def cmd_classify_restore(args: argparse.Namespace) -> int:
    kind = classify_actions_cache_restore(args.hit, args.matched, args.path)
    publish = kind in {"partial", "miss"}
    write_github_output(kind, publish)
    hit_for_row = "false" if kind == "miss" else "true"
    note_parts = [
        f"kind={kind}",
        f"publish={'true' if publish else 'false'}",
    ]
    if args.primary:
        note_parts.append(f"primary={redact(args.primary)}")
    if args.matched:
        note_parts.append(f"matched={redact(args.matched)}")
    if args.note:
        note_parts.append(args.note)
    cache_args = argparse.Namespace(
        name=args.name,
        hit=hit_for_row,
        bytes=0 if kind == "miss" else None,
        path=None if kind == "miss" else args.path,
        note=" ".join(note_parts),
    )
    if cmd_cache(cache_args) != 0:
        return 1
    if not args.quiet:
        print(kind)
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
            status = format_phase_status(phase.get("status"))
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
            hit_value = cache.get("hit")
            if hit_value is True:
                hit = "hit"
            elif hit_value is False:
                hit = "miss"
            else:
                hit = "unknown"
            restored_value = cache.get("restored_bytes")
            restored = (
                "unknown"
                if restored_value is None
                else format_bytes(int(restored_value))
            )
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
    if parse_cache_hit("") is not None or parse_cache_hit("true") is not True:
        failures.append("empty cache hit must stay unknown, not miss")
    if parse_cache_hit("false") is not False:
        failures.append("false cache hit must remain a miss")
    import tempfile

    touched = (
        "CI_RUNTIME_TELEMETRY_DIR",
        "RUNNER_TEMP",
        "GITHUB_STEP_SUMMARY",
        "GITHUB_RUN_ATTEMPT",
        "GITHUB_EVENT_NAME",
        "GITHUB_JOB",
        "FERRUM_CI_FORCE_COLD_CACHE",
    )
    previous = snapshot_env(touched)

    with tempfile.TemporaryDirectory() as tmp:
        isolated = Path(tmp) / "telemetry"
        isolated.mkdir()
        live_runner = Path(tmp) / "live-runner-temp"
        live_runner.mkdir()
        live_state = live_runner / "ci-runtime-telemetry.json"
        live_state.write_text('{"sentinel": true}\n', encoding="utf-8")
        live_summary = Path(tmp) / "live-summary.md"
        live_summary.write_text("pre-existing summary\n", encoding="utf-8")
        os.environ["CI_RUNTIME_TELEMETRY_DIR"] = str(isolated)
        os.environ["RUNNER_TEMP"] = str(live_runner)
        os.environ["GITHUB_STEP_SUMMARY"] = str(live_summary)
        try:
            if state_path() != isolated / "ci-runtime-telemetry.json":
                failures.append("explicit telemetry dir must beat RUNNER_TEMP")
            if cmd_init(argparse.Namespace(quiet=True)) != 0:
                failures.append("init failed")
            if cmd_start(argparse.Namespace(phase="compile")) != 0:
                failures.append("start failed")
            if cmd_end(argparse.Namespace(phase="compile", status=0)) != 0:
                failures.append("end of successful phase failed")
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
            if cmd_cache(
                argparse.Namespace(
                    name="unknown-cache",
                    hit="",
                    bytes=None,
                    path=None,
                    note="no evidence",
                )
            ) != 0:
                failures.append("unknown cache record failed")
            test_summary = isolated / "summary.md"
            os.environ["GITHUB_STEP_SUMMARY"] = str(test_summary)
            if cmd_summarize(argparse.Namespace(title="Test", quiet=True)) != 0:
                failures.append("summarize failed")
            written = test_summary.read_text(encoding="utf-8")
            if "ghp_" in written or "Bearer" in written:
                failures.append("summary leaked a secret")
            if "rust-cache" not in written or "| hit |" not in written:
                failures.append("summary omitted cache evidence")
            if "| `compile` |" not in written or "| ok |" not in written:
                failures.append("successful status 0 must render as ok, not failed")
            if "| `compile` |" in written:
                compile_row = next(
                    (line for line in written.splitlines() if line.startswith("| `compile` |")),
                    "",
                )
                if "| failed |" in compile_row:
                    failures.append("status 0 was rendered as failed")
                if "| ok |" not in compile_row:
                    failures.append("status 0 row must say ok")
            if "2.0 KiB" not in written:
                failures.append("summary omitted restored bytes")
            if "`unknown-cache` | unknown | unknown |" not in written:
                failures.append("unknown cache evidence must not become miss / 0 B")
            if "| miss |" in written.split("unknown-cache", 1)[-1][:80]:
                failures.append("unknown cache row was rendered as a miss")
            if "0 B" in written:
                failures.append("unknown cache row invented 0 B")
            if live_state.read_text(encoding="utf-8") != '{"sentinel": true}\n':
                failures.append("self-test mutated live RUNNER_TEMP job state")
            if live_summary.read_text(encoding="utf-8") != "pre-existing summary\n":
                failures.append("self-test mutated the live GITHUB_STEP_SUMMARY")
            if (live_runner / "summary.md").exists():
                failures.append("self-test wrote a summary into RUNNER_TEMP")
        except SystemExit as error:
            failures.append(f"self-test aborted: {error}")
        finally:
            restore_env(previous)

    after = snapshot_env(touched)
    if after != previous:
        failures.append("self-test did not restore every touched environment variable")

    try:
        resolve_restored_bytes(
            True,
            argparse.Namespace(bytes=None, path="/nonexistent/ci-runtime-cache"),
        )
        failures.append("hit without measured bytes must fail rather than invent 0 B")
    except SystemExit:
        pass

    if format_phase_status(0) != "ok":
        failures.append("integer 0 must render as ok")
    if format_phase_status(1) != "failed":
        failures.append("nonzero status must render as failed")
    if format_phase_status(None) != "unknown":
        failures.append("missing status must render as unknown")
    if format_phase_status(True) != "unknown" or format_phase_status(False) != "unknown":
        failures.append("boolean status must not be treated as 0/1")
    if format_phase_status("nope") != "unknown":
        failures.append("malformed status must render as unknown")

    import tempfile as _tempfile

    with _tempfile.TemporaryDirectory() as restore_tmp:
        restored = Path(restore_tmp) / "cache"
        restored.mkdir()
        (restored / "index").write_text("x", encoding="utf-8")
        missing = Path(restore_tmp) / "missing"
        try:
            if classify_actions_cache_restore("true", "scope-v1-Linux-X64-abc", str(restored)) != "exact":
                failures.append("true + matched key + dir must be exact")
            if classify_actions_cache_restore("false", "scope-v1-Linux-X64-", str(restored)) != "partial":
                failures.append("false + matched key + dir must be partial (a hit)")
            if classify_actions_cache_restore("", "", None) != "miss":
                failures.append("empty hit + empty matched key must be an ordinary miss")
            if classify_actions_cache_restore("", "", str(missing)) != "miss":
                failures.append("first-run empty outputs must be a miss even without a directory")
        except SystemExit as error:
            failures.append(f"valid restore tuples must classify: {error}")
        for label, kwargs in (
            ("exact-no-key", ("true", "", str(restored))),
            ("exact-no-dir", ("true", "scope-v1-Linux-X64-abc", str(missing))),
            ("partial-no-key", ("false", "", str(restored))),
            ("partial-no-dir", ("false", "scope-v1-Linux-X64-", str(missing))),
            ("miss-with-key", ("", "scope-v1-Linux-X64-abc", str(restored))),
            ("unknown-hit", ("maybe", "scope-v1-Linux-X64-abc", str(restored))),
        ):
            try:
                classify_actions_cache_restore(*kwargs)
                failures.append(f"{label} must fail closed")
            except SystemExit:
                pass

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

    cache = sub.add_parser("cache")
    cache.add_argument("--name", required=True)
    cache.add_argument("--hit", default="")
    cache.add_argument("--bytes", type=int, default=None)
    cache.add_argument("--path", default=None)
    cache.add_argument("--note", default="")
    cache.set_defaults(func=cmd_cache)

    classify = sub.add_parser("classify-restore")
    classify.add_argument("--name", required=True)
    classify.add_argument("--hit", default="")
    classify.add_argument("--matched", default="")
    classify.add_argument("--primary", default="")
    classify.add_argument("--path", default=None)
    classify.add_argument("--note", default="")
    classify.add_argument("--quiet", action="store_true")
    classify.set_defaults(func=cmd_classify_restore)

    summarize = sub.add_parser("summarize")
    summarize.add_argument("--title", default="CI runtime")
    summarize.add_argument("--quiet", action="store_true")
    summarize.set_defaults(func=cmd_summarize)

    test = sub.add_parser("self-test")
    test.set_defaults(func=lambda _args: self_test())

    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
