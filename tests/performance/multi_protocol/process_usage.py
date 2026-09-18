"""Linux /proc sampler for the hosted shared-runner benchmark.

CPU is a per-PID delta, never host utilization. Raw time series retain phase
boundaries; setup/warmup/drain costs remain visible beside measurement costs.
"""

import argparse
import json
import os
import resource
import subprocess
import time
from pathlib import Path


def parse_stat(contents, ticks, page_size):
    # comm can contain spaces and parentheses; fields follow its LAST ')'.
    fields = contents[contents.rfind(")") + 2:].split()
    return {"start_ticks": int(fields[19]),
            "cpu_seconds": (int(fields[11]) + int(fields[12])) / ticks,
            "rss_bytes": int(fields[21]) * page_size}


def capture(pid, ticks, page_size):
    try:
        return parse_stat(Path(f"/proc/{pid}/stat").read_text(), ticks, page_size)
    except (OSError, ValueError, IndexError):
        return None


def measurement_usage(usage, phases):
    """Bracket the common measured interval; expose sampling uncertainty."""
    start = phases.get("measurement_start_unix_secs")
    duration = phases.get("measurement_secs")
    if not isinstance(start, (int, float)) or not isinstance(duration, (int, float)):
        return []
    end = start + duration
    by_process = {}
    for snapshot in usage.get("timeline", []):
        for process in snapshot["processes"]:
            key = (process["pid"], process["start_ticks"])
            by_process.setdefault(key, []).append((snapshot["unix_secs"], process))
    result = []
    for values in by_process.values():
        before = [item for item in values if item[0] <= start]
        after = [item for item in values if item[0] >= end]
        within = [item for item in values if start <= item[0] <= end]
        identity = values[0][1]
        record = dict(pid=identity["pid"], role=identity["role"],
                      complete_bracket=bool(before and after),
                      peak_rss_bytes=max((item[1]["rss_bytes"] for item in within), default=None))
        if before and after:
            left, right = before[-1], after[0]
            record.update(cpu_seconds=right[1]["cpu_seconds"] - left[1]["cpu_seconds"],
                          bracket_secs=right[0] - left[0],
                          boundary_slack_secs=(start - left[0]) + (right[0] - end))
        result.append(record)
    return result


def run(command, backend, gateway_pids, output, timeout):
    ticks = os.sysconf("SC_CLK_TCK")
    page_size = os.sysconf("SC_PAGE_SIZE")
    roles = {pid: "gateway" for pid in gateway_pids}
    roles[backend] = "backend"
    records = {}
    timeline = []
    started = time.monotonic()

    def sample():
        snapshot = {"unix_secs": time.time(), "processes": []}
        for pid, role in roles.items():
            state = capture(pid, ticks, page_size)
            if state is None:
                continue
            key = (pid, state["start_ticks"])
            record = records.setdefault(key, dict(pid=pid, role=role, samples=0,
                                                 first_cpu_seconds=state["cpu_seconds"],
                                                 cpu_seconds=0, peak_rss_bytes=0))
            record["samples"] += 1
            record["cpu_seconds"] = state["cpu_seconds"] - record["first_cpu_seconds"]
            record["peak_rss_bytes"] = max(record["peak_rss_bytes"], state["rss_bytes"])
            snapshot["processes"].append(dict(state, pid=pid, role=role))
        timeline.append(snapshot)

    sample()
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    client = subprocess.Popen(command)
    roles[client.pid] = "client"
    timed_out = False
    while True:
        sample()
        if client.poll() is not None:
            break
        if time.monotonic() - started >= timeout:
            timed_out = True
            client.kill()
            client.wait()
            break
        time.sleep(0.1)
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    sample()
    report = {
        "scope": "whole client invocation including setup, warmup and drain",
        "interval_ms": 100,
        "elapsed_secs": time.monotonic() - started,
        "processes": list(records.values()),
        "missing_pids": sorted(set(roles) - {key[0] for key in records}),
        "client_cpu_seconds": after.ru_utime + after.ru_stime - before.ru_utime - before.ru_stime,
        "client_peak_rss_bytes": after.ru_maxrss * 1024,
        "timed_out": timed_out,
        "timeline": timeline,
    }
    Path(output).write_text(json.dumps(report) + "\n")
    return 124 if timed_out else client.returncode


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--backend", type=int, required=True)
    parser.add_argument("--gateway-pids", default="")
    parser.add_argument("--output", required=True)
    parser.add_argument("--timeout", type=int, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    raise SystemExit(run(command, args.backend,
                         [int(pid) for pid in args.gateway_pids.split()],
                         args.output, args.timeout))
