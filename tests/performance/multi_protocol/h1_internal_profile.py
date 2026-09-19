"""H1-only fixed metrics capture and conservative evidence validation.

No request labels, body capture, packet tracing or benchmark policy changes.
Use the existing CIDR-authenticated loopback endpoint on a disposable runner.
"""

import datetime
import hashlib
import json
import math
import re
import subprocess
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
REVISION_LABEL = "org.opencontainers.image.revision"
OBSERVER_LABEL = "ferrum.h1-profile"
CONFIG_DESTINATION = "/etc/ferrum/config.yaml"
CUTOFF_ENV = "FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES"
# Dockerfile.release defaults plus start_ferrum's explicit settings. Unknown
# FERRUM_* settings (including secret-provider suffixes) fail closed without
# retaining their names/values. Non-Ferrum environment values are hash-only.
RUNTIME_ENV = {
    "FERRUM_MODE": "file", "FERRUM_FILE_CONFIG_PATH": CONFIG_DESTINATION,
    "FERRUM_PROXY_HTTP_PORT": None, "FERRUM_PROXY_HTTPS_PORT": None,
    "FERRUM_ADMIN_HTTPS_PORT": "9443", "FERRUM_LOG_LEVEL": None,
    "FERRUM_FRONTEND_TLS_CERT_PATH": "/etc/ferrum/tls/cert.pem",
    "FERRUM_FRONTEND_TLS_KEY_PATH": "/etc/ferrum/tls/key.pem",
    "FERRUM_DTLS_CERT_PATH": "/etc/ferrum/tls/cert.pem",
    "FERRUM_DTLS_KEY_PATH": "/etc/ferrum/tls/key.pem",
    "FERRUM_ADMIN_BIND_ADDRESS": "127.0.0.1", "FERRUM_ADMIN_HTTP_PORT": "9000",
    "FERRUM_METRICS_ALLOWED_CIDRS": "127.0.0.1/32",
    "FERRUM_ADD_VIA_HEADER": "false", "FERRUM_ADD_FORWARDED_HEADER": "false",
    "FERRUM_MAX_REQUEST_BODY_SIZE_BYTES": "0", "FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES": "0",
    "FERRUM_MAX_GRPC_RECV_SIZE_BYTES": "0", CUTOFF_ENV: None,
    "FERRUM_HTTP_HEADER_READ_TIMEOUT_SECONDS": "0", "FERRUM_MAX_CONNECTIONS": "0",
    "FERRUM_POOL_MAX_IDLE_PER_HOST": "200", "FERRUM_POOL_ENABLE_HTTP_KEEP_ALIVE": "true",
    "FERRUM_POOL_WARMUP_ENABLED": "true", "FERRUM_WEBSOCKET_TUNNEL_MODE": "true",
    "FERRUM_POOL_HTTP2_INITIAL_STREAM_WINDOW_SIZE": "8388608",
    "FERRUM_POOL_HTTP2_INITIAL_CONNECTION_WINDOW_SIZE": "33554432",
    "FERRUM_POOL_HTTP2_ADAPTIVE_WINDOW": "true", "FERRUM_POOL_HTTP2_MAX_FRAME_SIZE": "1048576",
    "FERRUM_POOL_HTTP2_MAX_CONCURRENT_STREAMS": "1000",
    "FERRUM_POOL_HTTP2_CONNECTIONS_PER_HOST": "16",
    "FERRUM_SERVER_HTTP2_MAX_CONCURRENT_STREAMS": "1000",
    "FERRUM_UDP_MAX_SESSIONS": "10000", "FERRUM_UDP_RECVMMSG_BATCH_SIZE": "64",
    "FERRUM_TCP_IDLE_TIMEOUT_SECONDS": "30", "FERRUM_TCP_HALF_CLOSE_MAX_WAIT_SECONDS": "30",
}


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


def matches(pattern, value):
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def data_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def safe_environment(environment):
    if (not isinstance(environment, dict) or environment.keys() != RUNTIME_ENV.keys()
            or any(not isinstance(value, str) for value in environment.values())):
        return False
    if any(expected is not None and environment[key] != expected
           for key, expected in RUNTIME_ENV.items()):
        return False
    return (environment[CUTOFF_ENV] in ("0", "1")
            and environment["FERRUM_LOG_LEVEL"] in ("error", "warn", "info", "debug", "trace", "off")
            and all(matches(r"[1-9][0-9]{0,4}", environment[key])
                    and int(environment[key]) <= 65535
                    for key in ("FERRUM_PROXY_HTTP_PORT", "FERRUM_PROXY_HTTPS_PORT")))


def retain_runtime(destination, container, config_path, pair, gateway, host_id, mode):
    """Retain safe evidence from actual container AND immutable-image inspect.

    Failed inspection is an artifact, never an excuse to erase an arm. Do not
    persist raw inspect output: it can contain arbitrary environment/labels.
    """
    result = dict(runtime_schema=1, pair=pair, gateway=gateway, host_id=host_id,
                  h1_profile_mode=mode, capture_issues=[])
    errors = (OSError, ValueError, KeyError, IndexError, TypeError, AttributeError)
    try:
        result.update(container_id=container["Id"], image_id=container["Image"],
                      host_pid=container["State"]["Pid"], started_at=container["State"]["StartedAt"],
                      running=container["State"]["Running"],
                      network_mode=container["HostConfig"]["NetworkMode"])
        config = container["Config"]
        entries = config["Env"]
        if not isinstance(entries, list):
            raise ValueError("invalid environment")
        environment = {}
        for entry in entries:
            if not isinstance(entry, str) or "=" not in entry:
                raise ValueError("invalid environment entry")
            key, value = entry.split("=", 1)
            if not key or key in environment:
                raise ValueError("duplicate environment entry")
            environment[key] = value
        selected = {key: value for key, value in environment.items() if key.startswith("FERRUM_")}
        if not safe_environment(selected):
            raise ValueError("unexpected benchmark environment")
        result["environment"] = selected
        # Docker may inject this per-container value; permit only its generated
        # short ID, never normalize an arbitrary user-supplied HOSTNAME override.
        if "HOSTNAME" in environment:
            if environment.pop("HOSTNAME") != result["container_id"][:12]:
                raise ValueError("unexpected hostname environment")
        result["other_environment_sha256"] = data_hash(
            {key: value for key, value in environment.items() if not key.startswith("FERRUM_")})
        if (config["Entrypoint"] != ["/app/ferrum-edge"] or config["Cmd"] != ["run"]
                or config["WorkingDir"] != "/app"):
            raise ValueError("unexpected command/config overrides")
        result["command"] = dict(entrypoint=config["Entrypoint"], cmd=config["Cmd"],
                                 working_dir=config["WorkingDir"])
    except errors:
        result["capture_issues"].append("invalid container metadata or safe environment/command")
    try:
        if not matches(r"sha256:[0-9a-f]{64}", result.get("image_id")):
            raise ValueError("immutable image ID required")
        raw = subprocess.run(["docker", "image", "inspect", result["image_id"],
                              "--format", "{{json .}}"], check=True, capture_output=True,
                             text=True, timeout=10)
        image = json.loads(raw.stdout)
        if image["Id"] != result["image_id"]:
            raise ValueError("image inspect identity mismatch")
        for name, inspected in (("container_labels", container), ("image_labels", image)):
            labels = inspected["Config"]["Labels"]
            result[name] = {key: labels.get(key) for key in (REVISION_LABEL, OBSERVER_LABEL)}
    except errors + (subprocess.SubprocessError,):
        result["capture_issues"].append("immutable image/container label capture unavailable")
    try:
        source = Path(config_path).resolve(strict=True)
        mounts = container["Mounts"]
        candidates = [mount for mount in mounts if mount["Destination"] == CONFIG_DESTINATION]
        if (len(candidates) != 1 or candidates[0]["Type"] != "bind"
                or candidates[0]["RW"] is not False
                or Path(candidates[0]["Source"]).resolve(strict=True) != source):
            raise ValueError("effective config is not the retained read-only bind")
        result["config_mount"] = dict(source=str(source), destination=CONFIG_DESTINATION,
                                       type="bind", read_only=True)
        result["config_sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
        # Include all other mounts in pairing, without exposing their paths.
        result["other_mounts_sha256"] = data_hash(
            sorted((mount for mount in mounts if mount["Destination"] != CONFIG_DESTINATION),
                   key=lambda mount: mount["Destination"]))
    except errors:
        result["capture_issues"].append("retained config mount/hash unavailable")
    try:
        if (result.get("running") is not True or result.get("network_mode") != "host"
                or not safe_environment(result.get("environment"))):
            raise ValueError("owned container does not select the fixed metrics endpoint")
        result.update(start_ticks=process_start_ticks(Path(f"/proc/{result['host_pid']}")),
                      metrics_endpoint=METRICS_ENDPOINT)
        gateway_identity(result)
    except errors:
        result["identity_error"] = "owned container identity unavailable"
    Path(destination).write_text(json.dumps(result, indent=2) + "\n")


def runtime_issues(runtime, config_path, pair, gateway, manifest, mode):
    if not isinstance(runtime, dict):
        return ["missing or malformed runtime record"]
    issues = []
    for key, expected in dict(runtime_schema=1, pair=pair, gateway=gateway,
                              host_id=manifest.get("host_id"), h1_profile_mode=mode).items():
        if type(runtime.get(key)) is not type(expected) or runtime.get(key) != expected:
            issues.append("runtime identity mismatch: " + key)
    if runtime.get("capture_issues") != []:
        issues.append("runtime capture incomplete")
    try:
        gateway_identity(runtime)
    except ValueError:
        issues.append("missing or invalid owned gateway identity")
    started = runtime.get("started_at")
    try:
        if not matches(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z", started):
            raise ValueError("invalid start timestamp")
        datetime.datetime.fromisoformat(started.replace("Z", "+00:00"))
    except ValueError:
        issues.append("invalid container start timestamp")
    if runtime.get("running") is not True:
        issues.append("container not running at capture")
    if not matches(r"sha256:[0-9a-f]{64}", runtime.get("image_id")):
        issues.append("missing or invalid immutable image ID")
    expected_observer = "off" if gateway == "ferrum-baseline" else "on"
    for key in ("container_labels", "image_labels"):
        labels = runtime.get(key)
        if (not isinstance(labels, dict) or labels.keys() != {REVISION_LABEL, OBSERVER_LABEL}
                or not matches(r"[0-9a-f]{40}", labels.get(REVISION_LABEL))
                or labels[REVISION_LABEL] != manifest.get("h1_revision")
                or labels.get(OBSERVER_LABEL) != expected_observer):
            issues.append("missing or mismatched revision/observer " + key)
    environment = runtime.get("environment")
    if not safe_environment(environment):
        issues.append("invalid safe runtime environment")
    elif environment[CUTOFF_ENV] != ("1" if gateway == "ferrum-exp-cutoff-one" else "0"):
        issues.append("runtime cutoff does not match arm")
    if runtime.get("command") != dict(entrypoint=["/app/ferrum-edge"], cmd=["run"], working_dir="/app"):
        issues.append("invalid runtime command/config binding")
    mount = runtime.get("config_mount")
    if (not isinstance(mount, dict) or mount.get("destination") != CONFIG_DESTINATION
            or mount.get("type") != "bind" or mount.get("read_only") is not True
            or not isinstance(mount.get("source"), str) or not mount["source"].startswith("/")):
        issues.append("invalid runtime config mount")
    for key in ("config_sha256", "other_environment_sha256", "other_mounts_sha256"):
        if not matches(r"[0-9a-f]{64}", runtime.get(key)):
            issues.append("missing or invalid runtime " + key)
    try:
        if hashlib.sha256(config_path.read_bytes()).hexdigest() != runtime.get("config_sha256"):
            issues.append("retained config content hash mismatch")
    except OSError:
        issues.append("missing retained config content")
    return issues


def runtime_process_issues(runtime, usage, sample):
    """Observer-off controls need the same owned process bracket as on arms.

    Metrics counters are intentionally unavailable in the off build; use the
    raw process timeline and embedded measurement PID, not a filename or PID 1.
    """
    try:
        owned = gateway_identity(runtime)
        if gateway_identity(usage["h1_gateway"]) != owned or usage["capture_complete"] is not True:
            raise ValueError("missing owned process capture")
        phases = sample["phases"]
        start, duration = phases["measurement_start_unix_secs"], phases["measurement_secs"]
        if not finite_number(start) or not finite_number(duration) or duration <= 0:
            raise ValueError("invalid process measurement boundaries")
        started = datetime.datetime.fromisoformat(runtime["started_at"].replace("Z", "+00:00"))
        if started.timestamp() > start:
            raise ValueError("container started after measurement began")
        timeline = usage["timeline"]
        if (not isinstance(timeline, list) or not timeline
                or any(not isinstance(row, dict) or not finite_number(row.get("unix_secs"))
                       for row in timeline)
                or any(b["unix_secs"] < a["unix_secs"] for a, b in zip(timeline, timeline[1:]))):
            raise ValueError("invalid process timeline")
        before = [i for i, row in enumerate(timeline) if row["unix_secs"] <= start]
        after = [i for i, row in enumerate(timeline) if row["unix_secs"] >= start + duration]
        if not before or not after or before[-1] >= after[0]:
            raise ValueError("missing process bracket")
        for row in timeline[before[-1]:after[0] + 1]:
            processes = row["processes"]
            if not isinstance(processes, list) or any(not isinstance(p, dict) for p in processes):
                raise ValueError("malformed processes")
            gateways = [p for p in processes if p.get("role") == "gateway"]
            if (len(gateways) != 1 or any(type(gateways[0].get(key)) is not int
                                        for key in ("pid", "start_ticks"))
                    or gateways[0]["pid"] != owned["host_pid"]
                    or gateways[0]["start_ticks"] != owned["start_ticks"]):
                raise ValueError("unowned/reused gateway process")
        measured = sample["process_usage"]["measurement"]
        gateways = [p for p in measured if p["role"] == "gateway"]
        if (len(gateways) != 1 or type(gateways[0].get("pid")) is not int
                or gateways[0]["pid"] != owned["host_pid"]
                or gateways[0].get("complete_bracket") is not True):
            raise ValueError("measurement is not bound to runtime")
    except (ValueError, KeyError, IndexError, TypeError, AttributeError, OverflowError):
        return ["missing/mismatched owned runtime process bracket"]
    return []


def campaign_runtimes(directory, manifest, mode):
    records = {}
    for pair in range(1, 5):
        folder = directory / "pairs" / f"pair_{pair:03d}" / "diagnostics"
        for gateway in MANIFEST["campaigns"][mode]:
            try:
                runtime = json.loads((folder / f"{gateway}_runtime.json").read_text())
            except (OSError, ValueError):
                runtime = None
            issues = runtime_issues(runtime, folder / f"{gateway}_config.yaml",
                                    pair, gateway, manifest, mode)
            records[pair, gateway] = dict(runtime=runtime, issues=issues)
    valid = [record for record in records.values() if not record["issues"]]
    # Compare every pair, not only the two arms within a pair. Calibration may
    # use different off/on images; each arm's immutable ID must remain stable.
    comparisons = {
        "config": lambda r: r["config_sha256"],
        "environment": lambda r: {k: v for k, v in r["environment"].items() if k != CUTOFF_ENV},
        "other environment": lambda r: r["other_environment_sha256"],
        "other mounts": lambda r: r["other_mounts_sha256"],
    }
    for label, select in comparisons.items():
        if valid and any(select(record["runtime"]) != select(valid[0]["runtime"]) for record in valid):
            for record in valid:
                record["issues"].append("campaign " + label + " pairing mismatch")
    groups = ([valid] if mode == "cutoff" else
              [[r for r in valid if r["runtime"]["gateway"] == gateway]
               for gateway in MANIFEST["campaigns"][mode]])
    for group in groups:
        if group and any(r["runtime"]["image_id"] != group[0]["runtime"]["image_id"] for r in group):
            for record in group:
                record["issues"].append("campaign immutable image pairing mismatch")
    if (mode == "calibration"
            and {r["runtime"]["gateway"] for r in valid} == set(MANIFEST["campaigns"][mode])
            and len({r["runtime"]["image_id"] for r in valid}) == 1):
        # The same content-addressed image cannot carry opposite observer labels.
        for record in valid:
            record["issues"].append("calibration off/on labels cannot share one image ID")
    return records


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
    if not matches(r"[0-9a-f]{40}", manifest.get("h1_revision")):
        manifest_issues.append("missing immutable campaign revision")
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
    runtimes = campaign_runtimes(directory, manifest, mode)
    report = dict(mode=mode, manifest_issues=manifest_issues, observations=[],
                  traffic_complete=True, profiles_complete=True, runtime_complete=True,
                  actual_syscalls="unavailable: no collector implemented",
                  cpu_stacks="unavailable: no collector implemented",
                  overhead="raw same-revision on/off pairs; no guessed subtraction",
                  claims="no performance result asserted by this implementation")
    if manifest_issues:
        report["traffic_complete"] = False
        report["profiles_complete"] = False
        report["runtime_complete"] = False
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
                except (ValueError, KeyError, TypeError, AttributeError, OverflowError):
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
                runtime, usage = None, None
                row["runtime_issues"] = []
                if gateway != "direct":
                    record = runtimes[pair, gateway]
                    runtime = record["runtime"]
                    row["runtime"] = runtime
                    row["runtime_issues"] = record["issues"].copy()
                    try:
                        usage = json.loads((folder / "diagnostics" /
                                            f"{gateway}_{size}_process_usage.json").read_text())
                    except (OSError, ValueError):
                        pass  # retain the observation and explicit ownership failure
                    row["runtime_issues"].extend(runtime_process_issues(runtime, usage, sample))
                if row["runtime_issues"]:
                    report["runtime_complete"] = False
                    report["traffic_complete"] = False
                    report["profiles_complete"] = False
                if row["traffic_issues"]:
                    report["traffic_complete"] = False
                expected = gateway != "direct" and not (mode == "calibration" and gateway == "ferrum-baseline")
                if expected:
                    try:
                        row["profile"] = profile_bracket(
                            usage, phases, owned_gateway=runtime,
                            successful_responses=sample.get("total_requests"))
                    except (OSError, ValueError, KeyError, TypeError, AttributeError, IndexError, OverflowError):
                        row["profile"] = dict(complete=False, issues=["missing/malformed capture"])
                    if row["runtime_issues"]:
                        row["profile"]["issues"].append("runtime pairing/ownership incomplete")
                        row["profile"]["complete"] = False
                    if not row["profile"]["complete"]:
                        report["profiles_complete"] = False
                else:
                    row["profile"] = dict(expected=False, reason="direct or observer-off control")
                report["observations"].append(row)
    report["fully_measured_comparison_eligible"] = (
        report["traffic_complete"] and report["profiles_complete"] and report["runtime_complete"])
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
        try:
            container = json.load(sys.stdin)
        except ValueError:
            container = None
        retain_runtime(arguments[0], container, arguments[1], int(arguments[2]), *arguments[3:])
    elif command == "report":
        result = report(*arguments)
        # Retained partial profiles can guide follow-up coverage; never a win.
        sys.exit(0 if result["traffic_complete"] else 1)
    else:
        raise ValueError("unknown H1 profile command")
