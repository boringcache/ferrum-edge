"""Hosted boundary trigger: one request, bounded delivery observation, no retry of load."""
import argparse
import json
from pathlib import Path
import time
import urllib.request

from h2_diagnostics import parse_gauges
from h2_guard_observation import PROTOCOLS, parse_ack, sink_problems


def fetch(trigger=False):
    request = urllib.request.Request("http://127.0.0.1:9000/metrics", headers=(
        {"x-ferrum-h2-guard-snapshot": "1"} if trigger else {}))
    with urllib.request.urlopen(request, timeout=0.2) as response:
        raw = response.read(2 * 1024 * 1024 + 1)
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError("metrics byte bound")
    return raw.decode("utf-8")


def capture(path, identity):
    result = dict(schema=2, identity=identity, start_unix_secs=time.time(), errors=[], sink_samples=[])
    try:
        raw = fetch(True)  # Exactly one trigger; failed acknowledgment stays failed.
        acks = [line for line in raw.splitlines() if line.startswith("# H2_GUARD_ACK_")]
        if len(acks) != 1:
            raise ValueError("missing or duplicate acknowledgment")
        result["raw_ack"] = acks[0]
        result["ack"] = parse_ack(acks[0])
        deadline = time.monotonic() + 1.0
        # At most six observations; no indefinite drain or connection lifetime.
        for attempt in range(6):
            gauges = parse_gauges(raw)
            result["sink_samples"].append(dict(unix_secs=time.time(), gauges=gauges))
            if not sink_problems(gauges, drained=True):
                break
            if attempt == 5 or time.monotonic() >= deadline:
                break
            time.sleep(0.05)
            raw = fetch()
        result["errors"].extend(sink_problems(result["sink_samples"][-1]["gauges"], drained=True))
    except (OSError, ValueError) as error:
        result["errors"].append(type(error).__name__)
    result["end_unix_secs"] = time.time()
    path.write_text(json.dumps(result, indent=2) + "\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=Path)
    parser.add_argument("--identity", nargs=5, required=True,
                        metavar=("GATEWAY", "PROTOCOL", "PAYLOAD", "PAIR", "HOST"))
    parser.add_argument("--invocation", choices=("start", "end"))
    parser.add_argument("--exit-code", type=int)
    args = parser.parse_args()
    gateway, protocol, payload, pair, host = args.identity
    identity = dict(gateway=gateway, protocol=PROTOCOLS[protocol], payload_size=int(payload),
                    pair=int(pair), host_id=host)
    if args.invocation == "start":
        # Parent-shell launch/return envelope, not a claimed frame timestamp.
        args.path.write_text(json.dumps(dict(schema=2, identity=identity, start_unix_secs=time.time())) + "\n")
    elif args.invocation == "end":
        end = time.time()
        result = json.loads(args.path.read_text())
        if result["identity"] != identity or args.exit_code is None:
            parser.error("invocation identity/exit status missing or changed")
        result.update(end_unix_secs=end, exit_code=args.exit_code)
        args.path.write_text(json.dumps(result, indent=2) + "\n")
    else:
        capture(args.path, identity)
