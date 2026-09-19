"""Hosted-only supervisor: the COMPLETE diagnostic slice has one monotonic budget.

Every process dispatch is literal for immutable-base CI command-policy inspection.
Paths, deadlines and owned process/container identities travel only as data.
"""

import argparse
import json
import math
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[3]


def write_json(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


def process_identity(pid):
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return dict(pid=pid, session=int(fields[3]), start_ticks=int(fields[19]), state=fields[0])


def session_processes(session, start_ticks):
    try:
        leader = process_identity(session)
    except FileNotFoundError:
        pass  # surviving members still hold the old session identity
    else:
        if leader["start_ticks"] != start_ticks or leader["session"] != session:
            raise ValueError("diagnostic session leader identity changed")
    processes = []
    for entry in Path("/proc").iterdir():
        if entry.name.isdecimal():
            try:
                record = process_identity(int(entry.name))
                if record["session"] == session and record["start_ticks"] >= start_ticks and record["state"] != "Z":
                    processes.append(record)
            except (OSError, ValueError, IndexError):
                continue  # exited while enumerating
    return processes


def terminate_session(session, start_ticks, deadline):
    """Includes nested GNU timeout groups and sudo readers, not just the shell PGID.

    Runs as root only in the hosted cleanup helper; PID lifetime is checked again
    before each signal. No name/port-wide killing and no blocking wait/reap.
    """
    if session <= 1 or start_ticks <= 0 or session == os.getsid(0):
        raise ValueError("invalid owned diagnostic session")
    errors = []
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            records = session_processes(session, start_ticks)
        except (OSError, ValueError, IndexError) as error:
            return dict(complete=False, remaining=None, signal_errors=[type(error).__name__])
        for record in records:
            try:
                current = process_identity(record["pid"])
                if (current["start_ticks"], current["session"]) == (record["start_ticks"], session):
                    os.kill(record["pid"], sig)
            except ProcessLookupError:
                pass
            except (OSError, ValueError, IndexError) as error:
                errors.append(type(error).__name__)
        end = min(deadline, time.monotonic() + (0.2 if sig == signal.SIGTERM else 0.1))
        while time.monotonic() < end and session_processes(session, start_ticks):
            time.sleep(min(0.02, max(0, end - time.monotonic())))
    remaining = session_processes(session, start_ticks)
    return dict(complete=not remaining and not errors, remaining=remaining, signal_errors=errors)


def supervise(directory, budget):
    started = time.monotonic()
    if not math.isfinite(budget) or not 0 < budget <= 900:
        raise ValueError("diagnostic budget must be positive and at most 900 seconds")
    deadline = started + budget
    reserve = min(30.0, budget / 5)
    finalization_reserve = min(2.0, reserve / 5)
    work_deadline = deadline - reserve
    directory = Path(directory).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    if any(directory.iterdir()):
        raise ValueError("refusing to overwrite an earlier diagnostic campaign")
    state = dict(schema=1, status="running", budget_secs=budget, cleanup_reserve_secs=reserve,
                 campaign_exit_code=None, cleanup_complete=False, elapsed_secs=0,
                 work_limit_secs=budget - reserve)
    write_json(directory / "diagnostic_termination.json", state)
    # Before startup, retain all three failed rows. A supervisor/report crash or
    # SIGKILL leaves a truthful incomplete artifact, never a stale success.
    from h1_internal_profile import report_diagnostic
    report_diagnostic(directory)
    environment = dict(os.environ, H1_DIAGNOSTIC_OUTPUT=str(directory),
                       H1_DIAGNOSTIC_SUPERVISOR_PID=str(os.getpid()),
                       H1_DIAGNOSTIC_BUDGET=str(budget),
                       H1_DIAGNOSTIC_WORK_DEADLINE=str(work_deadline),
                       H1_DIAGNOSTIC_CONTAINER_PREFIX="ferrum-h1-diag-" + uuid.uuid4().hex)
    child = None
    interrupted = False

    def interrupt(signum, frame):
        nonlocal interrupted
        interrupted = True

    previous = {sig: signal.signal(sig, interrupt) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        with (directory / "campaign.log").open("w") as log:
            child = subprocess.Popen(
                ["bash", "tests/performance/multi_protocol/h1_diagnostic_campaign.sh"],
                cwd=ROOT, env=environment, start_new_session=True, stdout=log, stderr=subprocess.STDOUT)
            identity = process_identity(child.pid)
            if identity["session"] != child.pid:
                raise ValueError("campaign child did not own its session")
            environment.update(H1_DIAGNOSTIC_SESSION=str(child.pid),
                               H1_DIAGNOSTIC_START_TICKS=str(identity["start_ticks"]))
            state["session"] = identity
            write_json(directory / "diagnostic_termination.json", state)
            while child.poll() is None and not interrupted and time.monotonic() < work_deadline:
                time.sleep(min(0.05, max(0, work_deadline - time.monotonic())))
            state["campaign_exit_code"] = child.poll()
            state["status"] = ("interrupted" if interrupted else "budget_exhausted" if child.poll() is None
                               else "completed" if child.returncode == 0 else "campaign_failed")
    except (OSError, ValueError, IndexError) as error:
        state.update(status="supervisor_failed", error=type(error).__name__)
    finally:
        # This independent helper can kill a shell blocked in startup, docker,
        # a reader wait or cleanup. Its timeout includes its own force-kill.
        try:
            with (directory / "cleanup.log").open("w") as log:
                remaining = deadline - time.monotonic()
                if remaining <= reserve / 3:
                    raise subprocess.TimeoutExpired("cleanup", 0)
                cleanup_bound = min(20, remaining - reserve / 3)
                environment["H1_DIAGNOSTIC_CLEANUP_DEADLINE"] = str(time.monotonic() + cleanup_bound)
                cleanup = subprocess.run(
                    ["bash", "tests/performance/multi_protocol/h1_diagnostic_cleanup.sh"],
                    cwd=ROOT, env=environment, stdout=log, stderr=subprocess.STDOUT,
                    timeout=cleanup_bound, check=False)
                state["cleanup_complete"] = cleanup.returncode == 0
                state["cleanup_exit_code"] = cleanup.returncode
        except (OSError, subprocess.SubprocessError) as error:
            state.update(cleanup_complete=False, cleanup_error=type(error).__name__)
        # Fallback signals are nonblocking. Privileged/uninterruptible survivors
        # stay explicit when the bounded helper could not finish.
        if child is not None and "session" in state:
            try:
                cleanup = terminate_session(child.pid, state["session"]["start_ticks"], time.monotonic())
            except (OSError, ValueError, IndexError) as error:
                cleanup = dict(complete=False, remaining=None, signal_errors=[type(error).__name__])
            state["remaining_processes"] = cleanup["remaining"]
            state["fallback_signal_errors"] = cleanup["signal_errors"]
            state["cleanup_complete"] = state["cleanup_complete"] and cleanup["complete"]
            state["reaped_exit_code"] = child.poll()
            if child.returncode is None:
                state["cleanup_complete"] = False
        if not state["cleanup_complete"] and state["status"] == "completed":
            state["status"] = "cleanup_failed"
        state["elapsed_secs"] = time.monotonic() - started
        if state["elapsed_secs"] >= budget:
            state["status"] = "budget_exhausted"
        write_json(directory / "diagnostic_termination.json", state)
        # Bounded separate report process; the seeded failed report survives a
        # hang. The always() workflow step can regenerate it from raw evidence.
        try:
            remaining = deadline - time.monotonic() - finalization_reserve
            if remaining <= 0:
                raise subprocess.TimeoutExpired("report", 0)
            report = subprocess.run(
                ["bash", "tests/performance/multi_protocol/h1_diagnostic_report.sh"],
                cwd=ROOT, env=environment, timeout=remaining, check=False)
            state["report_exit_code"] = report.returncode
        except (OSError, subprocess.SubprocessError) as error:
            state.update(report_exit_code=None, report_error=type(error).__name__)
        state["elapsed_secs"] = time.monotonic() - started
        if state["elapsed_secs"] > budget or state.get("report_exit_code") is None:
            state["status"] = "budget_exhausted"
        write_json(directory / "diagnostic_termination.json", state)
        if state["status"] != "completed" or state.get("report_exit_code") != 0:
            # Invalidate even a report that finished just across the deadline.
            path = directory / "h1_diagnostic_report.json"
            failed = json.loads(path.read_text())
            failed.update(complete=False, termination=state)
            for row in failed["observations"]:
                row["issues"].append("campaign/report incomplete or failed; see termination evidence")
            write_json(path, failed)
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    return 0 if state["status"] == "completed" and state.get("report_exit_code") == 0 else 1


if __name__ == "__main__":
    if sys.argv[1:] == ["cleanup-processes"]:
        result = terminate_session(int(os.environ["H1_DIAGNOSTIC_SESSION"]),
                                   int(os.environ["H1_DIAGNOSTIC_START_TICKS"]), time.monotonic() + 1)
        print(json.dumps(result))
        sys.exit(0 if result["complete"] else 1)
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--budget", type=int, required=True)
    args = parser.parse_args()
    sys.exit(supervise(args.output_dir, args.budget))
