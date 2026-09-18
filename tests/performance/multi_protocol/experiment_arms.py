"""Data-only same-image Ferrum experiments; never execute manifest contents."""

import json
import re
from pathlib import Path


def load_experiment(path, protocol):
    plan = json.loads(Path(path).read_text())
    if set(plan) != {"enabled", "name", "protocol", "arms"}:
        raise ValueError("unexpected experiment fields")
    if not isinstance(plan["enabled"], bool):
        raise ValueError("enabled must be boolean")
    if not isinstance(plan["name"], str) or not re.fullmatch(r"[a-z0-9-]{1,80}", plan["name"]):
        raise ValueError("invalid experiment name")
    if plan["protocol"] not in ("http1-tls", "http2", "http3", "grpcs", "wss",
                                 "tcp-tls", "udp", "udp-dtls"):
        raise ValueError("invalid experiment protocol")
    arms = plan["arms"]
    if not isinstance(arms, list) or not 2 <= len(arms) <= 4:
        raise ValueError("declare two to four arms, including ferrum")
    names = set()
    for arm in arms:
        if not isinstance(arm, dict) or set(arm) != {"gateway", "FERRUM_EXTRA_ENV"}:
            raise ValueError("arms may change only FERRUM_EXTRA_ENV")
        name, env = arm["gateway"], arm["FERRUM_EXTRA_ENV"]
        if not isinstance(name, str) or not re.fullmatch(r"ferrum(?:-exp-[a-z0-9-]{1,40})?", name):
            raise ValueError("invalid Ferrum experiment arm")
        if name in names:
            raise ValueError("duplicate experiment arm")
        names.add(name)
        if not isinstance(env, str) or not re.fullmatch(
                r"FERRUM_[A-Z0-9_]+=[a-zA-Z0-9_.:/-]+(?: FERRUM_[A-Z0-9_]+=[a-zA-Z0-9_.:/-]+)*", env):
            raise ValueError("environment must contain literal space-separated KEY=VALUE entries")
        keys = [entry.split("=", 1)[0] for entry in env.split()]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate environment key")
    if arms[0]["gateway"] != "ferrum":
        raise ValueError("first arm must be the ferrum reference")
    return plan if plan["enabled"] and plan["protocol"] == protocol else None


if __name__ == "__main__":
    import sys

    command, path, protocol, *args = sys.argv[1:]
    plan = load_experiment(path, protocol)
    if command == "names":
        print(" ".join(arm["gateway"] for arm in plan["arms"][1:]) if plan else "")
    elif command == "env":
        matches = [arm for arm in plan["arms"] if arm["gateway"] == args[0]] if plan else []
        if len(matches) != 1:
            raise SystemExit("missing experiment arm")
        print(matches[0]["FERRUM_EXTRA_ENV"])
    else:
        raise SystemExit("unknown experiment command")
