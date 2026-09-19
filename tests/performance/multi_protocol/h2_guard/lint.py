"""Reject new diagnostics against the exact unmodified, same-toolchain h2 crate."""
import argparse
from collections import Counter
import json
from pathlib import Path


def diagnostics(path):
    if path.stat().st_size > 64 * 1024 * 1024:
        raise ValueError("lint evidence exceeds bound")
    counts = Counter()
    finished = []
    for line in path.read_text().splitlines():
        record = json.loads(line)
        if record.get("reason") == "build-finished":
            finished.append(record.get("success"))
        if record.get("reason") != "compiler-message":
            continue
        message = record["message"]
        level = message["level"]
        if level in ("error", "failure-note"):
            raise ValueError("compiler error in lint evidence")
        if level != "warning":
            continue
        code = (message.get("code") or {}).get("code", "")
        if not code.startswith("clippy::"):
            raise ValueError("non-Clippy warning in lint evidence")
        spans = []
        for span in message["spans"]:
            if span.get("is_primary"):
                spans.append((span["file_name"], tuple(
                    row["text"].strip() for row in span["text"])))
        if not spans:
            raise ValueError("lint diagnostic has no primary source span")
        # Positions move when observers are inserted. Match the lint identity,
        # message, source file and exact primary source text, retaining counts.
        key = json.dumps([code, message["message"], spans], sort_keys=True)
        counts[key] += 1
    if finished != [True]:
        raise ValueError("missing or unsuccessful lint build completion")
    return counts


def compare(baseline, observed):
    before, after = diagnostics(baseline), diagnostics(observed)
    added = after - before
    if added:
        raise ValueError("new/changed lint diagnostics: " + json.dumps(dict(added), sort_keys=True))
    return dict(upstream_diagnostics=dict(before), observed_diagnostics=dict(after),
                new_diagnostics=0, removed_diagnostics=dict(before - after))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("baseline", type=Path)
    parser.add_argument("observed", type=Path)
    args = parser.parse_args()
    print(json.dumps(compare(args.baseline, args.observed), indent=2))
