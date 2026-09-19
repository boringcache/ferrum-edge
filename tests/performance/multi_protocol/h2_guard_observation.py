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
suppressed_connections suppressed_lifecycle suppressed_failures generation transitions tail_len wraps
overwritten overflow pending high_pending min_credit epoch memory_overflow""".split()
TAIL_FIELDS = "seq cid snapshot generation n epoch kind stream len flow end disposition consume before after delta pending target wire byte_available in_flight stream_window".split()
FENCE_FIELDS = "seq generation registered captured retired missed changed registry_loss memory_overflow suppressed closed ack".split()
MAX_RECORDS = (128 + 8) * 1024 * 1024 // 4096 + 3 * 64 + 16
MAX_BYTES = 144 * 1024 * 1024
BRANCHES = {0: "none", 1: "small_nonfinal_credit", 2: "empty_nonfinal_lifetime",
            3: "send_internal_reset_limit", 4: "recv_internal_reset_limit",
            5: "pending_accept_remote_reset_limit"}


def numeric_fields(pairs, names):
    if len(pairs) != len(names):
        raise ValueError("wrong field count")
    row = {}
    for name, pair in zip(names, pairs):
        key, eq, value = pair.partition("=")
        if key != name or eq != "=" or not re.fullmatch(r"-?[0-9]{1,20}", value):
            raise ValueError("invalid fixed guard field")
        number = int(value)
        if number > 2**64 - 1 or number < -(2**63) or (number < 0 and name != "byte_available"):
            raise ValueError("invalid guard counter")
        row[name] = number
    return row


def validate_fence(row):
    if (not 1 <= row["seq"] <= MAX_RECORDS or not 1 <= row["generation"] <= 16 or row["registered"] > 64
            or row["captured"] + row["retired"] + row["missed"] != row["registered"]
            or row["changed"] not in (0, 1) or row["closed"] != 0 or row["ack"] != 1):
        raise ValueError("invalid snapshot fence")


def parse_ack(raw):
    prefix = "# H2_GUARD_ACK_V2 "
    if not isinstance(raw, str) or not raw.startswith(prefix):
        raise ValueError("invalid snapshot acknowledgment")
    row = numeric_fields(raw[len(prefix):].split(" "), FENCE_FIELDS)
    validate_fence(row)
    return row


def sink_problems(gauges, drained=False):
    required = {f"log_dropped_{sink}_{reason}" for sink in ("stdout", "stderr")
                for reason in ("saturation", "record_too_large", "closed")}
    required |= {f"log_{sink}_{field}" for sink in ("stdout", "stderr") for field in (
        "healthy", "queued_records", "queued_bytes", "reserved_bytes", "shutdown_timeouts_total",
        "shutdown_incomplete_records_total", "io_write", "io_flush")}
    if not required <= gauges.keys():
        return ["missing_log_sink_health_counters"]
    errors = []
    for key in required:
        value = gauges[key]
        if not isinstance(value, (int, float)) or value < 0:
            errors.append("invalid_log_sink_counter")
        elif key.endswith("_healthy"):
            if value != 1:
                errors.append("unhealthy_log_sink")
        elif key.endswith(("_queued_records", "_queued_bytes", "_reserved_bytes")):
            if drained and value != 0:
                errors.append("undrained_log_sink")
        elif value != 0:
            errors.append("log_sink_loss")
    return sorted(set(errors))


def validate_capture(result, sample, boundaries, seqs):
    errors = result["capture_errors"]
    summaries = {row["seq"]: row for row in result["events"]}
    tails = {}
    for row in sorted(result["transitions"], key=lambda r: r["seq"]):
        tails.setdefault(row["snapshot"], []).append(row)
        parent = summaries.get(row["snapshot"])
        if (not parent or parent["cid"] != row["cid"] or parent["generation"] != row["generation"]
                or parent["event"] not in (1, 3)):
            errors.append("orphan_transition")
    for seq, summary in summaries.items():
        tail = tails.get(seq, [])
        expected = list(range(summary["transitions"] - summary["tail_len"] + 1,
                              summary["transitions"] + 1)) if summary["tail_len"] else []
        if [row["n"] for row in tail] != expected:
            errors.append("missing_or_misordered_transition_tail")
        if tail and (tail[-1]["pending"] != summary["pending"]
                     or tail[-1]["after"] != summary["available"]
                     or tail[-1]["epoch"] != summary["epoch"]):
            errors.append("tail_summary_mismatch")
        for row in tail:
            expected_after = row["before"]
            if row["kind"] == 1 and row["consume"] == 1 and row["len"]:
                expected_after = (row["before"] - (256 - row["len"]) if row["len"] < 256
                                  else min(summary["max"], row["before"] + row["len"] - 256))
            elif row["kind"] in (2, 3) and row["consume"] == 1 and 0 < row["len"] < 256:
                expected_after = min(summary["max"], row["before"] + 256 - row["len"])
            if (row["after"] != expected_after or not 0 <= row["before"] <= summary["max"]
                    or not summary["min_credit"] <= row["after"] <= summary["max"]
                    or (row["kind"] == 1 and row["flow"] < row["len"])
                    or (row["kind"] == 1 and row["end"] and row["consume"] != 0)
                    or (row["kind"] == 1 and row["consume"] == 2 and row["len"] > 0
                        and not (row["len"] < 256 and row["before"] < 256 - row["len"]))):
                errors.append("transition_credit_mismatch")
        for previous, current in zip(tail, tail[1:]):
            delta = (1 if current["kind"] == 1 and current["disposition"] == 1 and current["end"] == 0
                     else -1 if current["kind"] in (2, 3) and current["consume"] == 1 else 0)
            if (current["before"] != previous["after"] or current["epoch"] < previous["epoch"]
                    or current["pending"] != previous["pending"] + delta
                    or current["epoch"] != previous["epoch"] + int(current["kind"] == 6)):
                errors.append("transition_order_or_accounting_mismatch")
        if summary["overflow"] or summary["memory_overflow"]:
            errors.append("observation_overflow")
    fences = {row["generation"]: row for row in result["fences"]}
    if len(fences) != len(result["fences"]):
        errors.append("duplicate_snapshot_generation")
    result["boundaries"] = boundaries
    generations = []
    for label in ("smoke", "before", "after"):
        boundary = boundaries.get(label, {})
        try:
            ack = parse_ack(boundary["raw_ack"])
            if boundary["ack"] != ack:
                raise ValueError("changed ack")
            generation = ack["generation"]
            generations.append(generation)
            fence = fences.get(generation)
            if label == "after":
                result["final_issued_sequence"] = ack["seq"]
                result["final_fence_delivered"] = bool(fence) and all(fence[key] == ack[key] for key in FENCE_FIELDS)
            if not fence or any(fence[key] != ack[key] for key in FENCE_FIELDS):
                errors.append("unacknowledged_snapshot_delivery:" + label)
            # Fence returned over HTTP detects lost LAST log records as well as gaps.
            if sum(seq <= ack["seq"] for seq in seqs) != ack["seq"]:
                errors.append("incomplete_snapshot_prefix:" + label)
            if any(ack[key] for key in ("missed", "changed", "registry_loss", "memory_overflow", "suppressed")):
                errors.append("partial_live_snapshot:" + label)
            live = [row for row in result["events"] if row["event"] == 3 and row["generation"] == generation]
            live_ids = {row["cid"] for row in live}
            active = set()
            for row in sorted(result["events"], key=lambda r: r["seq"]):
                if row["seq"] >= ack["seq"]:
                    continue
                if row["event"] == 0:
                    active.add(row["cid"])
                elif row["event"] == 2:
                    active.discard(row["cid"])
            if len(live) != ack["captured"] or len(live_ids) != len(live) or not live or not active <= live_ids:
                errors.append("missing_live_snapshot:" + label)
            if label == "after" and not any(row["role"] == 1 and row["frames"] > 0 for row in live):
                errors.append("missing_successful_or_fixed_live_traffic_state")
            if boundary["errors"]:
                errors.append("boundary_capture_error:" + label)
            sink = boundary["sink_samples"][-1]
            errors.extend(sink_problems(sink["gauges"], drained=True))
            start = sample.get("phases", {}).get("setup_start_unix_secs")
            measurement = sample.get("phases", {}).get("measurement_start_unix_secs")
            if start is not None and label == "before" and boundary["end_unix_secs"] > start:
                errors.append("late_before_snapshot")
            if measurement is not None and label == "after" and boundary["start_unix_secs"] < (
                    measurement + sample["phases"]["measurement_secs"]):
                errors.append("early_after_snapshot")
        except (ValueError, KeyError, TypeError, IndexError):
            errors.append("missing_or_malformed_boundary:" + label)
    if len(generations) == 3 and not generations[0] < generations[1] < generations[2]:
        errors.append("invalid_boundary_generation_order")
    if len(generations) == 3:
        before = {row["cid"]: row["frames"] for row in result["events"]
                  if row["event"] == 3 and row["generation"] == generations[1] and row["role"] == 1}
        progress = {row["cid"]: row["frames"] - before.get(row["cid"], 0) for row in result["events"]
                    if row["event"] == 3 and row["generation"] == generations[2] and row["role"] == 1}
        result["live_client_frame_deltas"] = progress
        if not any(value > 0 for value in progress.values()) or any(value < 0 for value in progress.values()):
            errors.append("missing_live_client_progress")
    if result["suppression_observed"] or result["sink_loss_observed"]:
        errors.append("capture_loss")
    result["capture_errors"] = sorted(set(errors))
    result["bounded_capture_complete"] = not result["capture_errors"]
    result["capture_status"] = "acknowledged_bounded_snapshots" if result["bounded_capture_complete"] else "partial"
    retained = {}
    latest = {}
    for row in result["transitions"]:
        retained.setdefault(row["cid"], set()).add(row["n"])
    for row in result["events"]:
        latest[row["cid"]] = max(latest.get(row["cid"], 0), row["transitions"])
    result["full_transition_history_complete"] = (result["bounded_capture_complete"]
        and not any(row["overwritten"] for row in result["events"])
        and all(len(retained.get(cid, ())) == count for cid, count in latest.items()))
    result["process_capture_closed"] = False
    result["remaining_limits"] = ["no process shutdown acknowledgment", "no pool-family/cross-hop identity join"]
    if any(row["overwritten"] for row in result["events"]):
        result["remaining_limits"].append("transition ring overwrote earlier history; only retained tails are ordered")


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
    schemas = {"H2_GUARD_V2": FIELDS, "H2_GUARD_TAIL_V2": TAIL_FIELDS,
               "H2_GUARD_FENCE_V2": FENCE_FIELDS,
               "H2_GUARD_LIMIT_V1": ["seq", "scope", "suppressed"]}
    if marker not in schemas:
        raise ValueError("unknown guard schema")
    row = numeric_fields(pairs, schemas[marker])
    if not 1 <= row["seq"] <= MAX_RECORDS:
        raise ValueError("invalid guard sequence")
    row["record_type"] = marker
    if marker == "H2_GUARD_V2":
        if (not 1 <= row["cid"] <= 4096 or row["role"] not in (0, 1)
                or row["event"] not in (0, 1, 2, 3) or row["branch"] not in BRANCHES
                or row["last_end"] not in (0, 1) or not 0 <= row["disposition"] <= 6
                or (row["event"] == 1 and (row["branch"] == 0 or row["reason"] != 11))
                or (row["event"] == 3) != (row["generation"] > 0)
                or row["generation"] > 16 or row["pending"] > row["high_pending"]
                or not row["min_credit"] <= row["available"] <= row["max"]
                or row["tail_len"] != (min(512, row["transitions"]) if row["event"] in (1, 3) else 0)
                or row["overwritten"] != max(0, row["transitions"] - 512)
                or row["wraps"] != max(0, row["transitions"] - 1) // 512):
            raise ValueError("invalid guard enum/state")
        row["branch_name"] = BRANCHES[row["branch"]]
    elif marker == "H2_GUARD_TAIL_V2":
        if (not 1 <= row["cid"] <= 4096 or not 1 <= row["kind"] <= 8
                or row["end"] not in (0, 1) or not 0 <= row["disposition"] <= 6
                or row["consume"] not in (0, 1, 2) or row["n"] < 1
                or row["generation"] > 16 or row["snapshot"] >= row["seq"]
                or row["delta"] != abs(row["after"] - row["before"])):
            raise ValueError("invalid transition")
    elif marker == "H2_GUARD_FENCE_V2":
        validate_fence(row)
    elif row["scope"] not in (1, 2, 3) or row["suppressed"] == 0:
        raise ValueError("invalid suppression notice")
    timestamp = record["timestamp"]
    if not isinstance(timestamp, str) or not timestamp.endswith("Z"):
        raise ValueError("missing UTC event timestamp")
    row["unix_secs"] = datetime.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()
    return row


def annotate(sample, usage, lines, boundaries=None):
    result = dict(schema=2, diagnostic_only=True, events=[], transitions=[], fences=[], suppression_notices=[], capture_errors=[],
                  id_scope="gateway process / h2 connection; no cross-hop or pool-family mapping",
                  counter_scope="connection lifetime, including earlier payloads",
                  phase_clock="gateway emission Unix time; cross-process skew unmeasured",
                  tail_scope="bounded live boundary snapshots; process shutdown and overwritten history remain unclosed",
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
            bucket = {"H2_GUARD_V2": "events", "H2_GUARD_TAIL_V2": "transitions",
                      "H2_GUARD_FENCE_V2": "fences", "H2_GUARD_LIMIT_V1": "suppression_notices"}
            result[bucket[row["record_type"]]].append(row)
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
                 for reason in ("saturation", "record_too_large", "closed")}
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

    result["sink_health_samples"] = snapshots
    for snapshot in snapshots:
        result["capture_errors"].extend(sink_problems(snapshot.get("gauges", {})))
    validate_capture(result, sample, boundaries or {}, seqs)


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
            boundaries = {}
            for label in ("smoke", "before", "after"):
                stem = sample["gateway"] if label == "smoke" else log_path.stem
                boundary = log_path.with_name(stem + "_guard_" + label + ".json")
                try:
                    boundaries[label] = json.loads(boundary.read_text())
                except (OSError, ValueError):
                    pass
            annotate(sample, usage, stream, boundaries)
    except OSError:
        annotate(sample, usage, [])
        if sample.get("gateway") != "direct":
            errors.append("missing_gateway_log")
    sample["h2_guard_observation"]["capture_errors"].extend(errors)
    if errors and sample.get("gateway") != "direct":
        sample["h2_guard_observation"].update(bounded_capture_complete=False,
            full_transition_history_complete=False, capture_status="partial")
    path.write_text(json.dumps(sample, indent=2) + "\n")


if __name__ == "__main__":
    main()
