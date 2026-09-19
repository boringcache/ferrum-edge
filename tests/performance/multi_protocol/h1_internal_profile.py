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
METRICS_ENDPOINT = "http://127.0.0.1:9000/metrics"
SLOT_CAPACITY = 128
# Fixed acceptance limits for the runner's 500 ms sampler / 200 ms HTTP timeout.
# Scheduling stalls are partial evidence, not grounds for expanding these limits.
MAX_BOUNDARY_SLACK_SECS = 2.0
MAX_SAMPLE_GAP_SECS = 1.0
CLOCK_TOLERANCE_SECS = 0.05


def finite_number(value):
    try:
        return type(value) in (int, float) and math.isfinite(value)
    except OverflowError:
        return False


def gateway_identity(runtime):
    """Select only the identity retained from the runner-owned docker inspect."""
    if (not isinstance(runtime, dict) or runtime.get("identity_error")
            or not isinstance(runtime.get("container_id"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", runtime["container_id"])
            or any(type(runtime.get(key)) is not int or runtime[key] <= 0
                   for key in ("host_pid", "start_ticks"))
            or runtime.get("network_mode") != "host"
            or runtime.get("metrics_endpoint") != METRICS_ENDPOINT):
        raise ValueError("missing or invalid owned gateway identity")
    return {key: runtime[key] for key in (
        "container_id", "host_pid", "start_ticks", "network_mode", "metrics_endpoint")}


def process_start_ticks(proc):
    stat = (proc / "stat").read_text()
    return int(stat[stat.rfind(")") + 2:].split()[19])


def gateway_binding(runtime, processes, proc_root=Path("/proc")):
    """Bind the fixed listener to the selected container process around a scrape.

    NSpid alone is insufficient: every private container can export PID 1.
    Require the unique loopback listener's inode in THIS process's fd table.
    No socket tracing, payload collection or arbitrary endpoint is involved.
    """
    owned = gateway_identity(runtime)
    gateways = [p for p in processes if p.get("role") == "gateway"]
    if (len(gateways) != 1 or gateways[0].get("pid") != owned["host_pid"]
            or gateways[0].get("start_ticks") != owned["start_ticks"]):
        raise ValueError("missing, reused or ambiguous owned gateway process")
    proc = proc_root / str(owned["host_pid"])
    if process_start_ticks(proc) != owned["start_ticks"]:
        raise ValueError("gateway process changed before identity capture")
    status = (proc / "status").read_text()
    lines = [line.split()[1:] for line in status.splitlines() if line.startswith("NSpid:")]
    if len(lines) != 1 or not lines[0]:
        raise ValueError("missing namespace PID mapping")
    namespace_pids = [int(pid) for pid in lines[0]]
    if namespace_pids[0] != owned["host_pid"] or any(pid <= 0 for pid in namespace_pids):
        raise ValueError("invalid host/namespace PID mapping")
    listeners = []
    for line in (proc / "net/tcp").read_text().splitlines()[1:]:
        fields = line.split()
        if fields[1] == "0100007F:2328" and fields[3] == "0A":
            listeners.append(int(fields[9]))
    sockets = set()
    for fd in (proc / "fd").iterdir():
        try:
            target = str(fd.readlink())
        except FileNotFoundError:
            continue  # an unrelated connection may close during fd enumeration
        match = re.fullmatch(r"socket:\[([0-9]+)\]", target)
        if match:
            sockets.add(int(match[1]))
    if len(listeners) != 1 or listeners[0] <= 0 or listeners[0] not in sockets:
        raise ValueError("fixed metrics listener is not uniquely owned by gateway")
    if process_start_ticks(proc) != owned["start_ticks"]:
        raise ValueError("gateway process changed during identity capture")
    return dict(host_pid=owned["host_pid"], start_ticks=owned["start_ticks"],
                namespace_pids=namespace_pids, listener_inode=listeners[0])


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


def snapshot(sample_id=0, processes=(), owned_gateway=None):
    row = dict(sample_id=sample_id, unix_secs=time.time(), monotonic_secs=time.monotonic(),
               sampler_cpu_start=time.process_time())
    row["gateway_binding"] = dict(endpoint=METRICS_ENDPOINT,
                                  container_id=(owned_gateway or {}).get("container_id"))
    try:
        row["gateway_binding"]["before"] = gateway_binding(owned_gateway, processes)
    except (OSError, ValueError, IndexError, KeyError, TypeError):
        row["identity_error"] = "owned gateway binding unavailable before scrape"
    try:
        # Fixed URL, no redirects/proxy environment, credentials or public path.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        with opener.open(METRICS_ENDPOINT, timeout=0.2) as response:
            raw = response.read(2 * 1024 * 1024 + 1)
        if len(raw) > 2 * 1024 * 1024:
            raise ValueError("oversized metrics capture")
        row["counters"] = parse_metrics(raw.decode("utf-8"))
    except (OSError, ValueError) as error:
        row["error"] = type(error).__name__
    try:
        row["gateway_binding"]["after"] = gateway_binding(owned_gateway, processes)
    except (OSError, ValueError, IndexError, KeyError, TypeError):
        row["identity_error"] = "owned gateway binding unavailable after scrape"
    row["capture_secs"] = time.monotonic() - row["monotonic_secs"]
    row["sampler_cpu_secs"] = time.process_time() - row["sampler_cpu_start"]
    return row


def profile_bracket(usage, phases, *, owned_gateway=None, successful_responses=0):
    result = dict(complete=False, issues=[], publication_complete=False,
                  coverage="published Rust/source-site counts only; not native or syscall coverage")
    if not isinstance(usage, dict) or not isinstance(phases, dict):
        result["issues"].append("malformed capture or measurement boundaries")
        return result
    start = phases.get("measurement_start_unix_secs")
    duration = phases.get("measurement_secs")
    if (not finite_number(start) or not finite_number(duration) or duration <= 0
            or not finite_number(start + duration)):
        result["issues"].append("missing measurement boundaries")
        return result
    timeline = usage.get("timeline", [])
    if not isinstance(timeline, list) or not timeline:
        result["issues"].append("missing or malformed capture timeline")
        return result
    for row in timeline:
        if (not isinstance(row, dict) or not finite_number(row.get("unix_secs"))
                or not isinstance(row.get("processes"), list)
                or any(not isinstance(p, dict) or not {"pid", "start_ticks", "role"} <= p.keys()
                       or type(p["pid"]) is not int or type(p["start_ticks"]) is not int
                       or p["pid"] <= 0 or p["start_ticks"] < 0 or not isinstance(p["role"], str)
                       for p in row["processes"])):
            result["issues"].append("malformed process capture")
            return result
        if "h1_profile" not in row:
            continue
        profile = row["h1_profile"]
        if (not isinstance(profile, dict) or not finite_number(profile.get("unix_secs"))
                or not finite_number(profile.get("capture_secs"))
                or profile["capture_secs"] < 0):
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
    captured = [row["h1_profile"] for row in timeline if "h1_profile" in row]
    for field in ("sample_id", "monotonic_secs", "unix_secs"):
        values = [p.get(field) for p in captured]
        if (any(not finite_number(value) for value in values)
                or any(b <= a for a, b in zip(values, values[1:]))):
            result["issues"].append("missing or non-increasing capture " + field)
    if any(type(p.get("sample_id")) is not int or p["sample_id"] < 0 for p in captured):
        result["issues"].append("invalid integer sample ID")
    if any(b["unix_secs"] < a["unix_secs"] for a, b in zip(timeline, timeline[1:])):
        result["issues"].append("capture clock moved backwards")
    before = [i for i, row in enumerate(timeline) if "h1_profile" in row and
              row["h1_profile"]["unix_secs"] + row["h1_profile"]["capture_secs"] <= start]
    after = [i for i, row in enumerate(timeline) if "h1_profile" in row and
             row["h1_profile"]["unix_secs"] >= start + duration]
    if not before or not after or before[-1] >= after[0]:
        result["issues"].append("missing or incomplete capture bracket")
        return result
    if usage.get("capture_complete") is not True:
        result["issues"].append("incomplete capture")
    rows = timeline[before[-1]:after[0] + 1]
    left, right = rows[0], rows[-1]
    profiles = [row.get("h1_profile", {}) for row in rows]
    identities = [{(p["pid"], p["start_ticks"]) for p in row["processes"]
                   if p["role"] == "gateway"} for row in rows]
    if not identities[0] or any(ids != identities[0] for ids in identities):
        result["issues"].append("missing or changed gateway process identity")
    if any("counters" not in profile for profile in profiles):
        result["issues"].append("missing profile snapshots (never zero-filled)")
        return result
    counters = [p["counters"] for p in profiles]
    try:
        owned = gateway_identity(owned_gateway)
        if gateway_identity(usage.get("h1_gateway")) != owned:
            raise ValueError("capture/runtime ownership differs")
    except ValueError:
        owned = None
        result["issues"].append("missing or mismatched owned gateway runtime")
    for profile, ids, row in zip(profiles, identities, rows):
        binding = profile.get("gateway_binding")
        valid = owned is not None and isinstance(binding, dict)
        if valid:
            endpoint = binding.get("before")
            valid = (binding.get("container_id") == owned["container_id"]
                     and binding.get("endpoint") == METRICS_ENDPOINT
                     and isinstance(endpoint, dict) and endpoint == binding.get("after"))
        if valid:
            for endpoint in (binding["before"], binding["after"]):
                nspids = endpoint.get("namespace_pids")
                valid = (valid and all(type(endpoint.get(key)) is int and endpoint[key] > 0
                                      for key in ("host_pid", "start_ticks", "listener_inode"))
                         and endpoint["host_pid"] == owned["host_pid"]
                         and endpoint["start_ticks"] == owned["start_ticks"]
                         and ids == {(owned["host_pid"], owned["start_ticks"])}
                         and len([p for p in row["processes"] if p["role"] == "gateway"]) == 1
                         and isinstance(nspids, list) and bool(nspids)
                         and all(type(pid) is int and pid > 0 for pid in nspids)
                         and nspids[0] == owned["host_pid"]
                         and nspids[-1] == profile["counters"]["pid"])
        if not valid or profile.get("identity_error"):
            result["issues"].append("metrics PID/listener is not bound to the owned gateway")
    if any(p.get("gateway_binding") != profiles[0].get("gateway_binding") for p in profiles):
        result["issues"].append("changed gateway namespace/listener binding")
    if any(p.get("error") for p in profiles):
        result["issues"].append("profile scrape failure")
    if any(not 0 <= p["unix_secs"] - row["unix_secs"] <= MAX_SAMPLE_GAP_SECS
           for p, row in zip(profiles, rows)):
        result["issues"].append("stale process observation at scrape")
    if all(type(p.get("sample_id")) is int for p in profiles) and any(
            b["sample_id"] != a["sample_id"] + 1 for a, b in zip(profiles, profiles[1:])):
        result["issues"].append("capture sample ID gap")
    if all(finite_number(p.get("monotonic_secs")) for p in profiles):
        if any(b["monotonic_secs"] - a["monotonic_secs"] > MAX_SAMPLE_GAP_SECS
               for a, b in zip(profiles, profiles[1:])):
            result["issues"].append("profile sampling gap exceeds one second")
        if any(abs((p["unix_secs"] - profiles[0]["unix_secs"]) -
                   (p["monotonic_secs"] - profiles[0]["monotonic_secs"])) > CLOCK_TOLERANCE_SECS
               for p in profiles):
            result["issues"].append("wall/monotonic clock discontinuity")
        if any(b["monotonic_secs"] < a["monotonic_secs"] + a["capture_secs"]
               for a, b in zip(profiles, profiles[1:])):
            result["issues"].append("overlapping profile captures")
    if not any(start <= p["unix_secs"] and p["unix_secs"] + p["capture_secs"] <= start + duration
               for p in profiles):
        result["issues"].append("no profile observation inside measurement")
    if any(c["pid"] <= 0 or c["slot_capacity"] != SLOT_CAPACITY
           or not 0 < c["registered_slots"] <= SLOT_CAPACITY for c in counters):
        result["issues"].append("invalid slot or process metadata")
    if any(c["pid"] != counters[0]["pid"] for c in counters):
        result["issues"].append("changed container PID")
    for name in SCHEMA["counters"] + ["lost_events", "registered_slots"]:
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
                                     right["h1_profile"]["capture_secs"] - start - duration)
    result["sample_count"] = len(rows)
    cpu_valid = all(finite_number(p.get("sampler_cpu_secs")) and p["sampler_cpu_secs"] >= 0
                    for p in profiles)
    cpu = sum(p["sampler_cpu_secs"] for p in profiles) if cpu_valid else None
    if not finite_number(cpu):
        result["issues"].append("missing/invalid sampler CPU evidence")
        cpu = None
    result["sampler_cpu_secs"] = cpu
    result["capture_secs"] = sum(p["capture_secs"] for p in profiles)
    result["start"] = counters[0]
    result["end"] = counters[-1]
    if not any("reset" in issue for issue in result["issues"]):
        result["published_delta"] = {name: counters[-1][name] - counters[0][name]
                                     for name in SCHEMA["counters"]}
    if result["boundary_slack_secs"] > MAX_BOUNDARY_SLACK_SECS:
        result["issues"].append("profile measurement bracket exceeds two-second slack")
    if (type(successful_responses) is int and successful_responses > 0
            and result.get("published_delta", {}).get("body_proxy_output_all_data_bytes", 0) <= 0):
        result["issues"].append("no observed H1 response DATA advancement for successful traffic")
    result["complete"] = not result["issues"]
    return result


def validate_selection(mode, protocol, pairs, duration, workers, gateways, sizes, baseline, extra):
    if mode == "diagnostic":
        if (protocol, pairs, duration, workers, gateways, sizes, baseline, extra) != (
                "http1-tls", "1", "30", "200", "ferrum", "5242880", "", ""):
            raise ValueError("H1 diagnostic requires one pass, 5 MiB, 50 scaled workers, 30 seconds")
        return
    if mode not in ("calibration", "cutoff") or protocol != "http1-tls":
        raise ValueError("H1-only calibration/cutoff selection required")
    if (pairs, duration, workers, gateways) != ("4", "15", "200", "ferrum") or extra:
        raise ValueError("H1 profile requires four pairs, 15 seconds, 200 scaled workers, ferrum only")
    selected = [int(size) for size in sizes.split()]
    if not selected or len(set(selected)) != len(selected) or any(
            size not in MANIFEST["payload_sizes"] for size in selected):
        raise ValueError("invalid H1 payload subset")
    if bool(baseline) != (mode == "calibration"):
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
    try:
        if (container["State"]["Running"] is not True
                or container["HostConfig"]["NetworkMode"] != "host"
                or environment.get("FERRUM_ADMIN_BIND_ADDRESS") != "127.0.0.1"
                or environment.get("FERRUM_ADMIN_HTTP_PORT") != "9000"
                or environment.get("FERRUM_METRICS_ALLOWED_CIDRS") != "127.0.0.1/32"):
            raise ValueError("owned container does not select the fixed metrics endpoint")
        result.update(start_ticks=process_start_ticks(Path(f"/proc/{result['host_pid']}")),
                      network_mode="host", metrics_endpoint=METRICS_ENDPOINT)
        gateway_identity(result)
    except (OSError, ValueError, KeyError, IndexError, TypeError):
        result["identity_error"] = "owned container identity unavailable"
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
    if type(manifest.get("pairs")) is not int or manifest["pairs"] != MANIFEST["pairs"]:
        manifest_issues.append("four complete pairs required")
    if not isinstance(manifest.get("host_id"), str) or not manifest["host_id"].strip():
        manifest_issues.append("missing same-host identity")
    if manifest.get("h1_diagnostic_enabled"):
        manifest_issues.append("diagnostic slice cannot enter profile comparisons")
    for key, expected in dict(sample_schema=2, protocol=MANIFEST["protocol"],
                              duration=MANIFEST["duration"], offered_workers=MANIFEST["offered_workers"],
                              h1_profile_mode=mode).items():
        if type(manifest.get(key)) is not type(expected) or manifest[key] != expected:
            manifest_issues.append("campaign workload mismatch: " + key)
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
                  actual_syscalls="unavailable: no collector implemented",
                  cpu_stacks="unavailable: no collector implemented",
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
                workers = MANIFEST["scaled_workers"][MANIFEST["payload_sizes"].index(size)]
                for key, expected_value in dict(
                        sample_schema=2, pair=pair, gateway=gateway, payload_size=size,
                        protocol="HTTP/1.1+TLS", duration_secs=MANIFEST["duration"],
                        concurrency=workers, effective_concurrency=workers,
                        host_id=manifest.get("host_id")).items():
                    if (type(sample.get(key)) is not type(expected_value)
                            or sample.get(key) != expected_value
                            or (key == "host_id" and (not isinstance(expected_value, str)
                                                     or not expected_value.strip()))):
                        traffic_issues.append("campaign sample mismatch: " + key)
                phases = sample.get("phases")
                if (not isinstance(phases, dict)
                        or not finite_number(phases.get("measurement_secs"))
                        or phases["measurement_secs"] != MANIFEST["duration"]):
                    traffic_issues.append("campaign measurement must be 15 seconds")
                if isinstance(phases, dict) and phases.get("h1_diagnostic") is not None:
                    traffic_issues.append("intrusive diagnostic sample cannot enter profile comparisons")
                if "samples" in sample:
                    traffic_issues.append("aggregate cannot replace a campaign observation")
                row = dict(pair=pair, gateway=gateway, payload=size, sample=sample,
                           traffic_issues=traffic_issues)
                if row["traffic_issues"]:
                    report["traffic_complete"] = False
                expected = gateway != "direct" and not (mode == "calibration" and gateway == "ferrum-baseline")
                if expected:
                    try:
                        usage = json.loads((folder / "diagnostics" /
                                            f"{gateway}_{size}_process_usage.json").read_text())
                        try:
                            runtime = json.loads((folder / "diagnostics" /
                                                  f"{gateway}_runtime.json").read_text())
                        except (OSError, ValueError):
                            runtime = None  # retain counter deltas even without ownership proof
                        row["profile"] = profile_bracket(
                            usage, phases, owned_gateway=runtime,
                            successful_responses=sample.get("total_requests"))
                    except (OSError, ValueError, KeyError, TypeError, AttributeError, IndexError, OverflowError):
                        row["profile"] = dict(complete=False, issues=["missing/malformed capture"])
                    if not row["profile"]["complete"]:
                        report["profiles_complete"] = False
                else:
                    row["profile"] = dict(expected=False, reason="direct or observer-off control")
                report["observations"].append(row)
    report["fully_measured_comparison_eligible"] = report["traffic_complete"] and report["profiles_complete"]
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
