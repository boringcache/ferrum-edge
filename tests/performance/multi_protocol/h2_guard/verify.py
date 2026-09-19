"""Hosted artifact checks; failed request samples are observations, never filtered."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from h2_guard_observation import FENCE_FIELDS, MAX_BYTES, annotate, parse_ack, parse_line, sink_problems


def verify_smoke(path):
    boundary = json.loads(path.read_text())
    ack = parse_ack(boundary["raw_ack"])
    if (boundary["errors"] or boundary["ack"] != ack or ack["generation"] != 1
            or not ack["captured"] or any(ack[key] for key in
                ("missed", "changed", "registry_loss", "memory_overflow", "suppressed"))
            or sink_problems(boundary["sink_samples"][-1]["gauges"], drained=True)):
        raise ValueError("snapshot trigger smoke is partial")
    log = path.with_suffix(".log")
    if log.stat().st_size > MAX_BYTES:
        raise ValueError("smoke log exceeds parse bound")
    rows = [row for line in log.read_text().splitlines() if (row := parse_line(line)) is not None]
    sequences = [row["seq"] for row in rows if row["seq"] <= ack["seq"]]
    fences = [row for row in rows if row["record_type"] == "H2_GUARD_FENCE_V2"]
    if (sorted(sequences) != list(range(1, ack["seq"] + 1)) or len(fences) != 1
            or any(fences[0][key] != ack[key] for key in FENCE_FIELDS)
            or not any(row.get("event") == 3 and row.get("generation") == 1 for row in rows)):
        raise ValueError("snapshot smoke log delivery not acknowledged")


def verify_graph(path):
    metadata = json.loads(path.read_text())
    packages = {p["id"]: p for p in metadata["packages"]}
    h2 = [p for p in packages.values() if p["name"] == "h2" and p["version"] == "0.4.19"]
    if len(h2) != 1 or h2[0]["source"] is not None or not h2[0]["manifest_path"].endswith(
            "/vendor/h2-0.4.19-observation/Cargo.toml"):
        raise ValueError("diagnostic graph must select exactly one patched h2 0.4.19")
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    root = metadata["resolve"]["root"]

    def path_through(start, names):
        if not names:
            return [start]
        for child in nodes[start]["dependencies"]:
            if packages[child]["name"] == names[0]:
                tail = path_through(child, names[1:])
                if tail:
                    return [start] + tail
        return None

    chains = {}
    for label, names in (("reqwest", ["reqwest", "hyper_util", "hyper", "h2"]),
                         ("native_grpc_hyper", ["hyper", "h2"])):
        names = [name.replace("_", "-") for name in names]
        chain = path_through(root, names)
        if not chain or chain[-1] != h2[0]["id"]:
            raise ValueError("transport no longer resolves to observed h2: " + label)
        chains[label] = chain
    return chains


def verify_campaign(root, protocol):
    sizes = [71680] if protocol == "http2" else [10240, 71680]
    rows = []
    problems = []
    for pair in range(1, 5):
        for gateway in ("direct", "ferrum", "ferrum-exp-fixed"):
            for size in sizes:
                path = root / "pairs" / f"pair_{pair:03d}" / f"{gateway}_{protocol}_{size}.json"
                if not path.is_file():
                    problems.append(f"missing_sample:{pair}:{gateway}:{size}")
                    continue
                sample = json.loads(path.read_text())
                observation = sample.get("h2_guard_observation", {})
                row = dict(path=str(path.relative_to(root)), sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                           total_errors=sample.get("total_errors"), error=sample.get("error"),
                           offered=sample.get("effective_concurrency"),
                           measurement_failures=observation.get("measurement_failures", []),
                           capture_errors=observation.get("capture_errors", []),
                           suppression_observed=observation.get("suppression_observed"),
                           sink_loss_observed=observation.get("sink_loss_observed"))
                row["bounded_capture_complete"] = observation.get("bounded_capture_complete")
                row["full_transition_history_complete"] = observation.get("full_transition_history_complete")
                row["process_capture_closed"] = observation.get("process_capture_closed")
                rows.append(row)
                if sample.get("effective_concurrency") != 200:
                    problems.append("wrong_offered_load:" + row["path"])
                if observation.get("schema") != 2:
                    problems.append("missing_observer_annotation:" + row["path"])
                if row["capture_errors"]:
                    problems.append("incomplete_capture:" + row["path"])
                if gateway != "direct" and (row["bounded_capture_complete"] is not True
                        or row["suppression_observed"] is not False or row["sink_loss_observed"] is not False):
                    problems.append("unacknowledged_or_lossy_capture:" + row["path"])
                if gateway != "direct":
                    # Reconcile annotation against the exact retained producer
                    # logs, HTTP acks and process capture. Flags alone cannot pass.
                    diagnostics = path.parent / "diagnostics"
                    prefix = f"{gateway}_{size}"
                    raw_paths = {"log": diagnostics / (prefix + ".log"),
                                 "usage": diagnostics / (prefix + "_process_usage.json")}
                    raw_paths.update({label: diagnostics / (
                        (gateway if label == "smoke" else prefix) + "_guard_" + label + ".json")
                        for label in ("smoke", "before", "after")})
                    row["raw_sha256"] = {}
                    try:
                        for label, raw_path in raw_paths.items():
                            if raw_path.stat().st_size > MAX_BYTES:
                                raise ValueError("raw artifact byte bound")
                            row["raw_sha256"][label] = hashlib.sha256(raw_path.read_bytes()).hexdigest()
                        usage = json.loads(raw_paths["usage"].read_text())
                        boundaries = {label: json.loads(raw_paths[label].read_text())
                                      for label in ("smoke", "before", "after")}
                        recomputed = dict(sample)
                        with raw_paths["log"].open() as stream:
                            annotate(recomputed, usage, stream, boundaries)
                        actual = json.loads(json.dumps(recomputed["h2_guard_observation"]))
                        if actual != observation or not actual["bounded_capture_complete"]:
                            raise ValueError("raw capture does not establish annotated completeness")
                    except (OSError, ValueError, KeyError, TypeError):
                        problems.append("raw_capture_reconciliation_failed:" + row["path"])
    report = dict(protocol=protocol, expected_samples=12 * len(sizes), samples=rows,
                  problems=problems, interpretation="diagnosis only; request failures retained; no repair/rate claim")
    (root / "guard-evidence-index.json").write_text(json.dumps(report, indent=2) + "\n")
    if problems:
        raise ValueError("campaign evidence incomplete; inspect guard-evidence-index.json")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("graph", "campaign", "smoke"))
    parser.add_argument("path", type=Path)
    parser.add_argument("--protocol", choices=("http2", "grpcs"))
    args = parser.parse_args()
    if args.mode == "graph":
        print(json.dumps(verify_graph(args.path), indent=2))
    elif args.mode == "smoke":
        verify_smoke(args.path)
    else:
        if not args.protocol:
            parser.error("campaign requires --protocol")
        verify_campaign(args.path, args.protocol)
