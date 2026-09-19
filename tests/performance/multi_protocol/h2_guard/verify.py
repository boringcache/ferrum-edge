"""Hosted artifact checks; failed request samples are observations, never filtered."""
import argparse
import hashlib
import json
from pathlib import Path


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
                rows.append(row)
                if sample.get("effective_concurrency") != 200:
                    problems.append("wrong_offered_load:" + row["path"])
                if observation.get("schema") != 1:
                    problems.append("missing_observer_annotation:" + row["path"])
                if row["capture_errors"]:
                    problems.append("incomplete_capture:" + row["path"])
    report = dict(protocol=protocol, expected_samples=12 * len(sizes), samples=rows,
                  problems=problems, interpretation="diagnosis only; request failures retained; no repair/rate claim")
    (root / "guard-evidence-index.json").write_text(json.dumps(report, indent=2) + "\n")
    if problems:
        raise ValueError("campaign evidence incomplete; inspect guard-evidence-index.json")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("graph", "campaign"))
    parser.add_argument("path", type=Path)
    parser.add_argument("--protocol", choices=("http2", "grpcs"))
    args = parser.parse_args()
    if args.mode == "graph":
        print(json.dumps(verify_graph(args.path), indent=2))
    else:
        if not args.protocol:
            parser.error("campaign requires --protocol")
        verify_campaign(args.path, args.protocol)
