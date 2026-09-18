"""Read the diagnostic h2 crate's fixed numeric messages from Ferrum JSON logs.

IDs are local to one gateway process. Cumulative counters include earlier
payloads; phase annotation is of emission time, never a per-frame timeline.
"""
from datetime import datetime
import json
from pathlib import Path
import re
import sys

from h2_diagnostics import event_phase

FIELDS = """seq cid role event branch reason initial_max initial_available max available empty
send recv error_resets remote_resets initial_target target peak_target target_updates
initial_stream stream_window stream_updates wire_window byte_available in_flight frames bytes
zero small medium large final queued ignored_reset ignored_release empty_unqueued rejected
untracked polled cleared returned_credit last_stream trigger_stream last_len last_flow last_end disposition
suppressed_connections suppressed_lifecycle suppressed_failures""".split()
MAX_RECORDS = 4096 + 256 + 3 * 64
MAX_BYTES = 64 * 1024 * 1024
BRANCHES = {0: "none", 1: "small_nonfinal_credit", 2: "empty_nonfinal_lifetime",
            3: "send_internal_reset_limit", 4: "recv_internal_reset_limit",
            5: "pending_accept_remote_reset_limit"}


def parse_line(line):
    if "H2_GUARD_" not in line:
        return None
    if len(line) > 8192:
        raise ValueError("oversized guard record")
    # docker logs --timestamps prefixes the existing JSON logging envelope.
    _, separator, envelope = line.partition(" ")
    record = json.loads(envelope if separator and not line.startswith("{") else line)
    if not isinstance(record, dict):
        raise ValueError("invalid log envelope")
    if record.get("target") != "ferrum_h2_guard":
        return None
    message = record["fields"]["message"]
    if not isinstance(message, str):
        raise ValueError("invalid guard message")
    marker, *pairs = message.split(" ")
    names = FIELDS if marker == "H2_GUARD_V1" else ["seq", "scope", "suppressed"]
    if marker not in ("H2_GUARD_V1", "H2_GUARD_LIMIT_V1") or len(pairs) != len(names):
        raise ValueError("unknown guard schema")
    row = {}
    for name, pair in zip(names, pairs):
        key, eq, value = pair.partition("=")
        if key != name or eq != "=" or not re.fullmatch(r"-?[0-9]{1,20}", value):
            raise ValueError("invalid fixed guard field")
        number = int(value)
        if number > 2**64 - 1 or number < -(2**63) or (number < 0 and name != "byte_available"):
            raise ValueError("invalid guard counter")
        row[name] = number
    if row["seq"] < 1:
        raise ValueError("invalid guard sequence")
    if marker == "H2_GUARD_V1":
        if (not 1 <= row["cid"] <= 4096 or row["role"] not in (0, 1)
                or row["event"] not in (0, 1, 2) or row["branch"] not in BRANCHES
                or row["last_end"] not in (0, 1) or not 0 <= row["disposition"] <= 6
                or (row["event"] == 1 and (row["branch"] == 0 or row["reason"] != 11))):
            raise ValueError("invalid guard enum")
        row["branch_name"] = BRANCHES[row["branch"]]
    elif row["scope"] not in (1, 2, 3) or row["suppressed"] == 0:
        raise ValueError("invalid suppression notice")
    timestamp = record["timestamp"]
    if not isinstance(timestamp, str) or not timestamp.endswith("Z"):
        raise ValueError("missing UTC event timestamp")
    row["unix_secs"] = datetime.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()
    return row


def annotate(sample, usage, lines):
    result = dict(schema=1, diagnostic_only=True, events=[], suppression_notices=[], capture_errors=[],
                  id_scope="gateway process / h2 connection; no cross-hop or pool-family mapping",
                  counter_scope="connection lifetime, including earlier payloads",
                  phase_clock="gateway emission Unix time; cross-process skew unmeasured",
                  tail_scope="snapshot before forced container removal; live connections may have no terminal record",
                  suppression_counts_are_lower_bounds=True)
    sample["h2_guard_observation"] = result
    if sample.get("gateway") == "direct":
        result["not_applicable"] = "unpatched direct control"
        return
    phases = sample.get("phases") or {}
    seqs = set()
    size = 0
    for line in lines:
        size += len(line.encode("utf-8"))
        if size > MAX_BYTES:
            result["capture_errors"].append("log_parse_byte_bound")
            break
        try:
            row = parse_line(line.rstrip("\n"))
            if row is None:
                continue
            if len(seqs) >= MAX_RECORDS:
                result["capture_errors"].append("record_bound")
                break
            if row["seq"] in seqs:
                raise ValueError("duplicate sequence")
            seqs.add(row["seq"])
            row["phase"] = ("before_sample" if row["unix_secs"] < phases.get("setup_start_unix_secs", 0)
                            else event_phase(row["unix_secs"], phases))
            result["events" if "cid" in row else "suppression_notices"].append(row)
        except (ValueError, KeyError, TypeError, OverflowError):
            if "malformed_guard_record" not in result["capture_errors"]:
                result["capture_errors"].append("malformed_guard_record")
    result["missing_sequence_count"] = max(seqs, default=0) - len(seqs)
    if result["missing_sequence_count"]:
        result["capture_errors"].append("missing_log_sequence")
    if not any(row["role"] == 1 for row in result["events"]):
        result["capture_errors"].append("missing_client_role_observation")
    result["measurement_failures"] = [row["seq"] for row in result["events"]
                                      if row["event"] == 1 and row["phase"] == "measurement"]
    loss_keys = {f"log_dropped_{sink}_{reason}" for sink in ("stdout", "stderr")
                 for reason in ("saturation", "oversized", "closed")}
    snapshots = [row["h2_gauges"] for row in usage.get("timeline", []) if "h2_gauges" in row]
    result["sink_loss_samples"] = [dict(unix_secs=row["unix_secs"], **{
        key: value for key, value in row.get("gauges", {}).items() if key in loss_keys})
        for row in snapshots]
    if not snapshots or any(not loss_keys <= row.get("gauges", {}).keys() for row in snapshots):
        result["capture_errors"].append("missing_log_sink_loss_counters")
    result["sink_loss_observed"] = any(row.get(key, 0) > 0 for row in result["sink_loss_samples"]
                                        for key in loss_keys)
    result["suppression_observed"] = bool(result["suppression_notices"]) or any(
        row[key] > 0 for row in result["events"] for key in
        ("suppressed_connections", "suppressed_lifecycle", "suppressed_failures"))


def main():
    path, usage_path, log_path = map(Path, sys.argv[1:])
    sample = json.loads(path.read_text())
    errors = []
    try:
        usage = json.loads(usage_path.read_text())
    except (OSError, ValueError):
        usage = {}
        errors.append("missing_process_capture")
    try:
        with log_path.open() as stream:
            annotate(sample, usage, stream)
    except OSError:
        annotate(sample, usage, [])
        if sample.get("gateway") != "direct":
            errors.append("missing_gateway_log")
    sample["h2_guard_observation"]["capture_errors"].extend(errors)
    path.write_text(json.dumps(sample, indent=2) + "\n")


if __name__ == "__main__":
    main()
