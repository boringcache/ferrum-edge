"""H1-only fixed metrics capture and conservative evidence validation.

No request labels, body capture, packet tracing or benchmark policy changes.
Use the existing CIDR-authenticated loopback endpoint on a disposable runner.
"""

import hashlib
import json
import math
import re
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SCHEMA = json.loads((ROOT / "h1_profile_schema.json").read_text())
MANIFEST = json.loads((ROOT / "h1_profile_manifest.json").read_text())
PREFIX = "ferrum_h1_profile_"
FIELDS = set(SCHEMA["counters"] + SCHEMA["metadata"])


def parse_metrics(text):
    counters = {}
    for line in text.splitlines():
        if not line.startswith(PREFIX):
            continue
        match = re.fullmatch(r"ferrum_h1_profile_([a-z0-9_]+) ([0-9]+)", line)
        if not match or match[1] not in FIELDS or match[1] in counters:
            raise ValueError("unknown, duplicate or malformed H1 profile metric")
        value = int(match[2])
        if value > 2**64 - 1:
            raise ValueError("H1 counter outside u64 range")
        counters[match[1]] = value
    if counters.keys() != FIELDS or counters["schema"] != SCHEMA["version"]:
        raise ValueError("missing or incompatible H1 profile schema")
    if counters["allocator_installed"] != 1:
        raise ValueError("gateway allocator observation not installed")
    return counters


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def snapshot(sample_id=0):
    row = dict(sample_id=sample_id, unix_secs=time.time(), monotonic_secs=time.monotonic(),
               sampler_cpu_start=time.process_time())
    try:
        # Fixed URL, no redirects/proxy environment, credentials or public path.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        with opener.open("http://127.0.0.1:9000/metrics", timeout=0.2) as response:
            raw = response.read(2 * 1024 * 1024 + 1)
        if len(raw) > 2 * 1024 * 1024:
            raise ValueError("oversized metrics capture")
        row["counters"] = parse_metrics(raw.decode("utf-8"))
    except (OSError, ValueError) as error:
        row["error"] = type(error).__name__
    row["capture_secs"] = time.monotonic() - row["monotonic_secs"]
    row["sampler_cpu_secs"] = time.process_time() - row["sampler_cpu_start"]
    return row


def profile_bracket(usage, phases):
    result = dict(complete=False, issues=[], publication_complete=False,
                  coverage="published Rust/source-site counts only; not native or syscall coverage")
    if not isinstance(usage, dict) or not isinstance(phases, dict):
        result["issues"].append("malformed capture or measurement boundaries")
        return result
    start = phases.get("measurement_start_unix_secs")
    duration = phases.get("measurement_secs")
    if (type(start) not in (float, int) or type(duration) not in (float, int)
            or not math.isfinite(start) or not math.isfinite(duration) or duration <= 0):
        result["issues"].append("missing measurement boundaries")
        return result
    timeline = usage.get("timeline", [])
    if not isinstance(timeline, list) or not timeline:
        result["issues"].append("missing or malformed capture timeline")
        return result
    for row in timeline:
        if (not isinstance(row, dict) or type(row.get("unix_secs")) not in (float, int)
                or not math.isfinite(row["unix_secs"]) or not isinstance(row.get("processes"), list)
                or any(not isinstance(p, dict) or not {"pid", "start_ticks", "role"} <= p.keys()
                       or type(p["pid"]) is not int or type(p["start_ticks"]) is not int
                       or p["pid"] <= 0 or p["start_ticks"] < 0 or not isinstance(p["role"], str)
                       for p in row["processes"])):
            result["issues"].append("malformed process capture")
            return result
        if "h1_profile" not in row:
            continue
        profile = row["h1_profile"]
        if (not isinstance(profile, dict) or type(profile.get("unix_secs")) not in (float, int)
                or not math.isfinite(profile["unix_secs"])
                or type(profile.get("capture_secs", 0)) not in (float, int)
                or not math.isfinite(profile.get("capture_secs", 0))
                or profile.get("capture_secs", 0) < 0):
            result["issues"].append("malformed profile capture")
            return result
        if "counters" in profile:
            counters = profile["counters"]
            if (not isinstance(counters, dict) or counters.keys() != FIELDS
                    or any(type(value) is not int or not 0 <= value <= 2**64 - 1
                           for value in counters.values())
                    or counters["schema"] != SCHEMA["version"]
                    or counters["allocator_installed"] != 1):
                result["issues"].append("malformed profile counters")
                return result
    if any(b["unix_secs"] < a["unix_secs"] for a, b in zip(timeline, timeline[1:])):
        result["issues"].append("capture clock moved backwards")
        return result
    before = [row for row in timeline if "h1_profile" in row and
              row["h1_profile"]["unix_secs"] + row["h1_profile"].get("capture_secs", 0) <= start]
    after = [row for row in timeline if "h1_profile" in row and
             row["h1_profile"]["unix_secs"] >= start + duration]
    if not before or not after or usage.get("capture_complete") is not True:
        result["issues"].append("missing or incomplete capture bracket")
        return result
    left, right = before[-1], after[0]
    rows = [row for row in timeline if left["unix_secs"] <= row["unix_secs"] <= right["unix_secs"]]
    profiles = [row.get("h1_profile", {}) for row in rows]
    identities = [{(p["pid"], p["start_ticks"]) for p in row["processes"]
                   if p["role"] == "gateway"} for row in rows]
    if not identities[0] or any(ids != identities[0] for ids in identities):
        result["issues"].append("missing or changed gateway process identity")
    if any("counters" not in profile for profile in profiles):
        result["issues"].append("missing profile snapshots (never zero-filled)")
        return result
    counters = [p["counters"] for p in profiles]
    if any(c["pid"] != counters[0]["pid"] for c in counters):
        result["issues"].append("changed container PID")
    for name in SCHEMA["counters"] + ["lost_events"]:
        if any(b[name] < a[name] for a, b in zip(counters, counters[1:])):
            result["issues"].append("counter reset or missed publication: " + name)
    for name in ("missing_slots", "lost_events", "counter_overflow",
                 "io_tls_wire_mixed_tls_faults", "io_tls_wire_mixed_tls_incomplete_terminal"):
        if any(c[name] != 0 for c in counters):
            result["issues"].append(name)
    result["unpublished_events_at_boundaries"] = [counters[0]["unpublished_events"],
                                                   counters[-1]["unpublished_events"]]
    result["publication_complete"] = all(c["unpublished_events"] == 0 for c in counters)
    if not result["publication_complete"]:
        result["issues"].append("unpublished thread tails; byte residual is not bounded")
    result["boundary_slack_secs"] = (start - left["h1_profile"]["unix_secs"] +
                                     right["h1_profile"]["unix_secs"] +
                                     right["h1_profile"].get("capture_secs", 0) - start - duration)
    result["sample_count"] = len(rows)
    result["sampler_cpu_secs"] = sum(p.get("sampler_cpu_secs", 0) for p in profiles)
    result["capture_secs"] = sum(p.get("capture_secs", 0) for p in profiles)
    result["start"] = counters[0]
    result["end"] = counters[-1]
    if not any("reset" in issue for issue in result["issues"]):
        result["published_delta"] = {name: counters[-1][name] - counters[0][name]
                                     for name in SCHEMA["counters"]}
    result["complete"] = not result["issues"]
    return result


def validate_selection(mode, protocol, pairs, duration, workers, gateways, sizes, baseline, extra):
    if mode == "diagnostic":
        if (protocol, pairs, duration, workers, gateways, sizes, baseline, extra) != (
                "http1-tls", "1", "30", "200", "ferrum", "5242880", "", ""):
            raise ValueError("H1 diagnostic requires one pass, 5 MiB, 50 scaled workers, 30 seconds")
        return
    if mode not in ("calibration", "cutoff", "trace-calibration") or protocol != "http1-tls":
        raise ValueError("H1-only calibration/cutoff selection required")
    if (pairs, duration, workers, gateways) != ("4", "15", "200", "ferrum") or extra:
        raise ValueError("H1 profile requires four pairs, 15 seconds, 200 scaled workers, ferrum only")
    selected = [int(size) for size in sizes.split()]
    if not selected or len(set(selected)) != len(selected) or any(
            size not in MANIFEST["payload_sizes"] for size in selected):
        raise ValueError("invalid H1 payload subset")
    if bool(baseline) != (mode in ("calibration", "trace-calibration")):
        raise ValueError("only calibration requires the identical-revision observer-off image")


def retain_runtime(destination, container, config_path):
    # Exact effective, non-secret benchmark settings. Source/config/build hashes
    # accompany this record; no arbitrary environment or credential values.
    keys = {"FERRUM_MODE", "FERRUM_FILE_CONFIG_PATH", "FERRUM_PROXY_HTTP_PORT",
            "FERRUM_PROXY_HTTPS_PORT", "FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES",
            "FERRUM_MAX_REQUEST_BODY_SIZE_BYTES", "FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES",
            "FERRUM_ADMIN_BIND_ADDRESS", "FERRUM_ADMIN_HTTP_PORT",
            "FERRUM_METRICS_ALLOWED_CIDRS", "FERRUM_POOL_ENABLE_HTTP_KEEP_ALIVE",
            "FERRUM_POOL_WARMUP_ENABLED", "FERRUM_LOG_LEVEL"}
    environment = dict(entry.split("=", 1) for entry in container["Config"]["Env"])
    result = dict(image_id=container["Image"], container_id=container["Id"],
                  config_sha256=hashlib.sha256(Path(config_path).read_bytes()).hexdigest(),
                  host_pid=container["State"]["Pid"], started_at=container["State"]["StartedAt"],
                  environment={key: environment.get(key) for key in sorted(keys)})
    Path(destination).write_text(json.dumps(result, indent=2) + "\n")


def report(directory, mode):
    from benchmark_validity import sample_issues
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    manifest_issues = []
    try:
        manifest = json.loads((directory / "manifest.json").read_text())
        if not isinstance(manifest, dict):
            raise ValueError("manifest must be an object")
    except (OSError, ValueError):
        manifest_issues.append("campaign manifest missing/malformed; retaining full expected matrix")
        manifest = dict(pairs=4, gateways=["direct"] + list(MANIFEST["campaigns"][mode]),
                        payload_sizes=MANIFEST["payload_sizes"])
    expected_gateways = ["direct"] + list(MANIFEST["campaigns"][mode])
    actual_gateways = manifest.get("gateways")
    if (not isinstance(actual_gateways, list) or
            any(not isinstance(gateway, str) for gateway in actual_gateways) or
            sorted(actual_gateways) != sorted(expected_gateways)):
        manifest_issues.append("missing or unexpected campaign arms")
    if manifest.get("pairs") != 4:
        manifest_issues.append("four complete pairs required")
    selected = manifest.get("payload_sizes", [])
    if (not isinstance(selected, list) or not selected or
            any(type(size) is not int or size not in MANIFEST["payload_sizes"] for size in selected) or
            len(set(selected)) != len(selected)):
        manifest_issues.append("invalid payload selection; retaining full expected matrix")
        manifest["payload_sizes"] = MANIFEST["payload_sizes"]
    manifest["pairs"] = 4
    manifest["gateways"] = expected_gateways
    report = dict(mode=mode, manifest_issues=manifest_issues, observations=[],
                  traffic_complete=True, profiles_complete=True,
                  actual_syscalls="separate trace manifest; never inferred from internal counters",
                  cpu_stacks="separate trace manifest; never inferred from process CPU",
                  overhead="raw same-revision on/off pairs; no guessed subtraction",
                  claims="no performance result asserted by this implementation")
    if manifest_issues:
        report["traffic_complete"] = False
        report["profiles_complete"] = False
    for pair in range(1, manifest["pairs"] + 1):
        folder = directory / "pairs" / f"pair_{pair:03d}"
        for gateway in manifest["gateways"]:
            for size in manifest["payload_sizes"]:
                path = folder / f"{gateway}_http1-tls_{size}.json"
                try:
                    sample = json.loads(path.read_text())
                    if not isinstance(sample, dict):
                        raise ValueError("sample must be an object")
                except (OSError, ValueError):
                    sample = {"error": "missing or malformed sample"}
                try:
                    traffic_issues = sample_issues(sample)
                except (ValueError, KeyError, TypeError, AttributeError):
                    traffic_issues = ["malformed sample fields"]
                row = dict(pair=pair, gateway=gateway, payload=size, sample=sample,
                           traffic_issues=traffic_issues)
                if row["traffic_issues"]:
                    report["traffic_complete"] = False
                expected = gateway != "direct" and not (mode == "calibration" and gateway == "ferrum-baseline")
                if expected:
                    try:
                        usage = json.loads((folder / "diagnostics" /
                                            f"{gateway}_{size}_process_usage.json").read_text())
                        row["profile"] = profile_bracket(usage, sample.get("phases") or {})
                    except (OSError, ValueError, KeyError):
                        row["profile"] = dict(complete=False, issues=["missing/malformed capture"])
                    if not row["profile"]["complete"]:
                        report["profiles_complete"] = False
                else:
                    row["profile"] = dict(expected=False, reason="direct or observer-off control")
                from h1_trace_contract import load_trace
                row["external_trace"] = load_trace(folder / "traces" / f"{gateway}_{size}" / "trace-manifest.json")
                report["observations"].append(row)
    report["internal_comparison_eligible"] = report["traffic_complete"] and report["profiles_complete"]
    report["fully_measured_comparison_eligible"] = False
    report["missing_dimensions_remain_open"] = ["complete native allocation/copy coverage", "separately calibrated syscall and CPU dimensions", "complete unwinding"]
    (directory / "h1_profile_report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def report_diagnostic(directory):
    from benchmark_validity import sample_issues
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    result = dict(mode="diagnostic", comparison_eligible=False,
                  cause="unproven; a clean slice does not resolve retained failures",
                  observations=[], complete=True)
    for gateway in ("direct", "ferrum", "ferrum-exp-cutoff-one"):
        path = directory / "pairs/pair_001" / f"{gateway}_http1-tls_5242880.json"
        issues = []
        try:
            sample = json.loads(path.read_text())
            issues.extend(sample_issues(sample))
            diagnostic = sample["phases"]["h1_diagnostic"]
            if diagnostic["clock_domain"] != "client_process_diagnostic_session_instant_microseconds":
                issues.append("missing named client clock domain")
            if any(diagnostic["loss"].values()):
                issues.append("diagnostic capture loss")
            if len(diagnostic["snapshots"][-1]["workers"]) != 50:
                issues.append("missing worker last state")
            retirement = diagnostic["retirement"]
            if retirement["timed_out"] or any(retirement[key] for key in (
                    "completed_error", "cancelled", "panicked", "capacity_rejections",
                    "unreaped_after_abort")):
                issues.append("driver retirement incomplete or failed (separate from request work)")
            if retirement["started"] < 50 or retirement["started"] != retirement["completed_ok"]:
                issues.append("driver completion accounting incomplete")
        except (OSError, ValueError, KeyError, TypeError, IndexError, AttributeError):
            issues.append("missing or malformed diagnostic sample")
        result["observations"].append(dict(gateway=gateway, path=str(path), issues=issues))
        result["complete"] = result["complete"] and not issues
    (directory / "h1_diagnostic_report.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


if __name__ == "__main__":
    command, *arguments = sys.argv[1:]
    if command == "validate-selection":
        validate_selection(*arguments)
    elif command == "report-diagnostic":
        sys.exit(0 if report_diagnostic(*arguments)["complete"] else 1)
    elif command == "runtime":
        retain_runtime(arguments[0], json.load(sys.stdin), arguments[1])
    elif command == "report":
        result = report(*arguments)
        # Retained partial profiles can guide follow-up coverage; never a win.
        sys.exit(0 if result["traffic_complete"] else 1)
    else:
        raise ValueError("unknown H1 profile command")
