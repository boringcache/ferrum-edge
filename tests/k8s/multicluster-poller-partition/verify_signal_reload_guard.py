#!/usr/bin/env python3
"""Static regression guard for signal_reload process selection in run.sh.

Locks in cmdline-based identity (not pidof or /proc/<pid>/exe), exact argv
matching, fail-closed uniqueness, and same-exec HUP signaling. Does not execute
run.sh or any cluster fixture.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

FIXTURE_DIR = Path(__file__).resolve().parent
DEFAULT_RUN_SH = FIXTURE_DIR / "run.sh"

FORBIDDEN_PATTERNS = (
    re.compile(r"pidof\s+ferrum-edge"),
    re.compile(r"readlink\s+[^\n]*/exe"),
    re.compile(r"/proc/\[0-9\]\*/exe"),
)

REQUIRED_INNER_PATTERNS = (
    re.compile(r"/proc/\[0-9\]\*/cmdline"),
    re.compile(r"\$\{argv0##\*/\}\s*=\s*\"ferrum-edge\""),
    re.compile(r'\[ "\$argv1" = "run" \]'),
    re.compile(r"multiple ferrum-edge run processes found"),
    re.compile(r"no ferrum-edge run process found"),
    re.compile(r"kill -HUP \"\$found\""),
)

INNER_SCRIPT_RE = re.compile(
    r"sh -eu -c '([^']*(?:''[^']*)*)'",
    re.DOTALL,
)

GOOD_INNER = """
    found=""
    for process_dir in /proc/[0-9]*; do
      [ -r "$process_dir/cmdline" ] || continue
      [ -s "$process_dir/cmdline" ] || continue
      argv0=""
      argv1=""
      pos=0
      while IFS= read -r -d "" arg || [ -n "$arg" ]; do
        case "$pos" in
          0) argv0="$arg" ;;
          1) argv1="$arg"; break ;;
        esac
        pos=$((pos + 1))
      done < "$process_dir/cmdline"
      [ -n "$argv0" ] || continue
      [ "${argv0##*/}" = "ferrum-edge" ] || continue
      [ "$argv1" = "run" ] || continue
      candidate="${process_dir##*/}"
      if [ -n "$found" ]; then
        echo "multiple ferrum-edge run processes found: $found $candidate" >&2
        exit 1
      fi
      found="$candidate"
    done
    [ -n "$found" ] || {
      echo "no ferrum-edge run process found" >&2
      exit 1
    }
    kill -HUP "$found"
"""


def fail(message: str) -> None:
    print(f"signal_reload guard: {message}", file=sys.stderr)
    raise SystemExit(1)


def extract_signal_reload_inner(text: str) -> str:
    start = text.find("signal_reload()")
    if start < 0:
        fail("signal_reload() is missing")
    block = text[start:]
    match = INNER_SCRIPT_RE.search(block)
    if match is None:
        fail("signal_reload inner sh -eu -c script is missing")
    return match.group(1).replace("''", "'")


def verify_inner(inner: str, function_block: str) -> None:
    for pattern in FORBIDDEN_PATTERNS:
        if pattern.search(inner):
            fail(f"forbidden pattern in signal_reload inner script: {pattern.pattern}")
    for pattern in REQUIRED_INNER_PATTERNS:
        if not pattern.search(inner):
            fail(f"missing required pattern in signal_reload inner script: {pattern.pattern}")
    if "sh -eu -c" not in function_block:
        fail("signal_reload must discover and signal in one kubectl exec")
    scan_at = inner.find("for process_dir")
    kill_at = inner.find("kill -HUP")
    if scan_at < 0 or kill_at < scan_at:
        fail("kill -HUP must stay inside the same inner exec script as the scan")


def verify_run_sh(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    start = text.find("signal_reload()")
    function_block = text[start:text.find("deploy_topology()", start)]
    verify_inner(extract_signal_reload_inner(text), function_block)


def self_test() -> None:
    good = (
        "signal_reload() {\n"
        "  kubectl exec pod/foo -c signal -- sh -eu -c '\n"
        + GOOD_INNER
        + "  '\n}\n"
    )
    verify_run_sh_from_text(good)

    bad_pidof = good.replace(
        '[ "${argv0##*/}" = "ferrum-edge" ] || continue',
        "pidof ferrum-edge",
        1,
    )
    if not rejects(bad_pidof):
        fail("self-test: pidof must be rejected")

    bad_exe = good.replace(
        '[ -s "$process_dir/cmdline" ] || continue',
        'executable="$(readlink "$process_dir/exe")"',
        1,
    )
    if not rejects(bad_exe):
        fail("self-test: /proc exe readlink must be rejected")

    bad_argv = good.replace('[ "$argv1" = "run" ]', '[ "$argv1" = "health" ]', 1)
    if not rejects(bad_argv):
        fail("self-test: exact run subcommand check must be required")


def rejects(text: str) -> bool:
    try:
        verify_run_sh_from_text(text)
    except SystemExit:
        return True
    return False


def verify_run_sh_from_text(text: str) -> None:
    start = text.find("signal_reload()")
    function_block = text[start:]
    verify_inner(extract_signal_reload_inner(text), function_block)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "run_sh",
        nargs="?",
        default=str(DEFAULT_RUN_SH),
        help="path to run.sh (default: fixture run.sh)",
    )
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        self_test()
        print("verify_signal_reload_guard self-test passed")
        return 0
    verify_run_sh(Path(args.run_sh))
    print(f"signal_reload guard ok: {args.run_sh}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
