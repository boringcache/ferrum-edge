"""Typed admission for the versioned Rust H1 diagnostic producer (no legacy fallback)."""

import ipaddress
import math

CLOCK = "client_process_diagnostic_session_instant_microseconds"
ARMS = ["direct", "ferrum", "ferrum-exp-cutoff-one"]
LOSS = {"workers", "connections", "updates", "snapshots", "poisoned_locks"}
PHASES = {"setup", "warmup", "barrier", "measurement", "drain", "driver_retirement"}
STAGES = {"connect", "tls_handshake", "http_handshake", "next_request", "send_request", "response_body"}
ERRORS = {"tcp_connect", "tls_handshake", "driver_registration", "incomplete_message",
          "http_parse", "timeout", "cancelled", "closed", "body_write_aborted", "hyper_transport_or_body"}
ENDS = {"initial_end_stream", "end_stream_after_frame", "poll_none"}


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def fields(value, names):
    require(isinstance(value, dict) and value.keys() == set(names.split()), "missing/unknown typed fields")


def uint(value, positive=False):
    require(type(value) is int and int(positive) <= value <= 2**64 - 1, "invalid unsigned integer")


def number(value):
    require(type(value) in (int, float) and math.isfinite(value) and value >= 0, "invalid finite duration")


def stamp(value, ceiling):
    fields(value, "session_us phase phase_us")
    uint(value["session_us"])
    uint(value["phase_us"])
    require(value["phase"] in PHASES and value["phase_us"] <= value["session_us"] <= ceiling,
            "invalid session/phase timestamp")
    return value["session_us"]


def loss(value):
    fields(value, " ".join(LOSS))
    for count in value.values():
        uint(count)
        require(count == 0, "diagnostic capture loss")


def socket(value):
    if value is None:
        return  # producer may fail to observe either endpoint; never fabricate it
    require(isinstance(value, str), "invalid socket tuple")
    host, port = value.rsplit(":", 1)
    ipaddress.ip_address(host.strip("[]"))
    require(port.isdecimal() and 0 < int(port) <= 65535, "invalid socket port")


def request(value, ceiling, complete, payload):
    fields(value, "id offered body_first_poll body_bytes body_last_progress body_end body_end_signal "
           "headers status version content_length content_length_present transfer_encoding_present "
           "chunked connection_close response_bytes response_last_progress response_end response_end_signal "
           "error_class error_at validated completion")
    for key in ("id", "body_bytes", "response_bytes"):
        uint(value[key])
    for key in ("content_length_present", "transfer_encoding_present", "chunked", "connection_close"):
        require(type(value[key]) is bool, "invalid framing flag")
    times = {}
    for key in ("offered", "body_first_poll", "body_last_progress", "body_end", "headers",
                "response_last_progress", "response_end", "error_at", "completion"):
        if value[key] is not None:
            times[key] = stamp(value[key], ceiling)
    for key in ("body_end_signal", "response_end_signal"):
        require(value[key] is None or value[key] in ENDS, "invalid body end signal")
        require((value[key] is None) == (value[key.removesuffix("_signal")] is None), "unpaired body end")
    require(value["error_class"] is None or value["error_class"] in ERRORS, "invalid error class")
    require((value["error_class"] is None) == (value["error_at"] is None), "unpaired error timestamp")
    require(value["validated"] is None or type(value["validated"]) is bool, "invalid validation result")
    require((value["validated"] is None) == (value["completion"] is None), "unpaired completion")
    if value["status"] is not None:
        uint(value["status"], True)
        require(100 <= value["status"] <= 599, "invalid status")
    require(value["version"] is None or value["version"] in {"HTTP/1.0", "HTTP/1.1", "unexpected_version"},
            "invalid version")
    if value["content_length"] is not None:
        uint(value["content_length"])
        require(value["content_length_present"], "length without header")
    if times:
        require("offered" in times and all(t >= times["offered"] for t in times.values()),
                "request predates offer")
    if complete:
        require(set(times) == {"offered", "body_first_poll", "body_last_progress", "body_end", "headers",
                               "response_last_progress", "response_end", "completion"}, "missing request last state")
        require(value["id"] > 0 and value["validated"] is True and value["error_class"] is None
                and value["status"] == 200 and value["version"] == "HTTP/1.1"
                and value["body_bytes"] == payload and value["response_bytes"] == payload,
                "last request did not complete useful work")
        require(times["body_first_poll"] <= times["body_last_progress"] <= times["body_end"]
                and times["headers"] <= times["response_last_progress"] <= times["response_end"] <= times["completion"],
                "request progress chronology")


def diagnostic_issues(value, *, workers=50, payload=5242880):
    """Validate serialized producer state; test callers may use a smaller real H1 fixture."""
    try:
        fields(value, "schema clock_domain pid worker_capacity connection_capacity snapshot_capacity loss snapshots retirement")
        for key, expected in (("schema", 1), ("worker_capacity", 256),
                              ("connection_capacity", 512), ("snapshot_capacity", 4)):
            require(type(value[key]) is int and value[key] == expected, "diagnostic schema/capacity mismatch")
        uint(value["pid"], True)
        require(value["pid"] <= 2**32 - 1 and value["clock_domain"] == CLOCK, "client clock/PID mismatch")
        loss(value["loss"])
        snapshots = value["snapshots"]
        require(isinstance(snapshots, list) and 2 <= len(snapshots) <= 4, "missing bounded snapshots")
        reasons = [s["reason"] for s in snapshots]
        require(reasons in (["request_drain_complete", "driver_retirement_finished"],
                            ["delayed_warmup", "request_drain_complete", "driver_retirement_finished"]),
                "missing/out-of-order final retirement snapshot or retained abort")
        previous = 0
        for snapshot in snapshots:
            fields(snapshot, "clock_domain pid reason at workers connections loss")
            require(snapshot["clock_domain"] == CLOCK and type(snapshot["pid"]) is int
                    and snapshot["pid"] == value["pid"], "snapshot clock/PID mismatch")
            at = stamp(snapshot["at"], 2**64 - 1)
            require(at >= previous, "snapshot time reversal")
            previous = at
            loss(snapshot["loss"])
            final = snapshot["reason"] == "driver_retirement_finished"
            require(not final or snapshot["at"]["phase"] == "driver_retirement", "retirement phase mismatch")
            ws, cs = snapshot["workers"], snapshot["connections"]
            require(isinstance(ws, list) and len(ws) == workers, "missing worker last state")
            require(isinstance(cs, list) and len(cs) <= 512, "missing/beyond-capacity connections")
            ids, requests, connections = set(), set(), {}
            for c in cs:
                fields(c, "id worker_id local peer socket_at driver driver_at error_class")
                uint(c["id"], True)
                uint(c["worker_id"])
                require(c["id"] not in connections and c["worker_id"] < workers, "duplicate/foreign connection")
                connections[c["id"]] = c
                socket(c["local"])
                socket(c["peer"])
                opened = stamp(c["socket_at"], at)
                require(c["driver"] in {"not_started", "running", "completed_ok", "completed_error",
                                         "dropped_without_result", "capacity_rejected"}, "invalid driver state")
                if c["driver_at"] is not None:
                    require(stamp(c["driver_at"], at) >= opened, "driver precedes socket")
                require(c["error_class"] is None or c["error_class"] in ERRORS, "invalid driver error")
                require(not final or (c["driver"] == "completed_ok" and c["driver_at"] is not None
                                      and c["error_class"] is None), "driver last state incomplete")
            require(set(connections) == set(range(1, len(cs) + 1)), "missing connection records")
            for w in ws:
                fields(w, "id connection_id stage stage_since lifecycle requests_offered bodies_admitted completions errors request")
                uint(w["id"])
                require(w["id"] < workers and w["id"] not in ids, "duplicate/foreign worker")
                ids.add(w["id"])
                require(w["stage"] in STAGES and w["lifecycle"] in
                        {"running", "returned", "returned_error", "dropped_without_return"}, "invalid worker lifecycle")
                stamp(w["stage_since"], at)
                for key in ("requests_offered", "bodies_admitted", "completions", "errors"):
                    uint(w[key])
                if w["connection_id"] is not None:
                    uint(w["connection_id"], True)
                    require(w["connection_id"] in connections and
                            connections[w["connection_id"]]["worker_id"] == w["id"], "worker/connection mismatch")
                request(w["request"], at, final, payload)
                if w["request"]["id"]:
                    require(w["request"]["id"] not in requests, "copied request identity")
                    requests.add(w["request"]["id"])
                if final:
                    require(w["lifecycle"] == "returned" and w["stage"] == "next_request"
                            and w["connection_id"] is not None and w["errors"] == 0
                            and w["requests_offered"] == w["bodies_admitted"] == w["completions"] > 0,
                            "worker did not return with complete useful work")
        retirement = value["retirement"]
        fields(retirement, "started completed_ok completed_error cancelled panicked capacity_rejections "
               "pending_at_request_drain abort_requested unreaped_after_abort abort_reap_bound_secs timed_out elapsed_secs bound_secs")
        for key in ("started", "completed_ok", "completed_error", "cancelled", "panicked", "capacity_rejections",
                    "pending_at_request_drain", "abort_requested", "unreaped_after_abort"):
            uint(retirement[key])
        for key in ("abort_reap_bound_secs", "elapsed_secs", "bound_secs"):
            number(retirement[key])
        require(retirement["timed_out"] is False and retirement["bound_secs"] == 5
                and retirement["elapsed_secs"] <= 5 and retirement["abort_reap_bound_secs"] == 0
                and all(retirement[k] == 0 for k in ("completed_error", "cancelled", "panicked",
                                                      "capacity_rejections", "abort_requested", "unreaped_after_abort")),
                "driver retirement failed/incomplete")
        require(workers <= retirement["started"] == retirement["completed_ok"] == len(snapshots[-1]["connections"])
                and retirement["pending_at_request_drain"] <= retirement["started"], "driver accounting mismatch")
    except (ValueError, KeyError, TypeError, IndexError, AttributeError, OverflowError) as error:
        return ["missing/malformed diagnostic evidence: " + str(error)]
    return []


if __name__ == "__main__":
    import argparse
    import json
    import sys

    parser = argparse.ArgumentParser()
    parser.add_argument("--workers", type=int, default=50)
    parser.add_argument("--payload", type=int, default=5242880)
    args = parser.parse_args()
    issues = diagnostic_issues(json.load(sys.stdin), workers=args.workers, payload=args.payload)
    print(json.dumps(issues))
    sys.exit(bool(issues))
