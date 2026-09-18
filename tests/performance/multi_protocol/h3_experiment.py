"""Data-only H3 experiment configuration; never launches commands."""

import json
from pathlib import Path


def load_experiment(path):
    plan = json.loads(Path(path).read_text())
    if not isinstance(plan.get("enabled"), bool):
        raise ValueError("enabled must be boolean")
    if plan.get("envoy_stream_limits") != [100, 4]:
        raise ValueError("this experiment requires limits [100, 4]")
    if plan.get("socket_buffer_bytes") not in (212992, 4194304):
        raise ValueError("unsupported socket buffer budget")
    if plan.get("log_level") != "info":
        raise ValueError("startup diagnostics require info logging")
    return plan


def topology(workers, limit):
    connections = max(1, min(workers, workers // 10 + 1))
    return dict(offered_workers=workers, client_connections=connections,
                max_workers_per_connection=(workers + connections - 1) // connections,
                downstream_admission_ceiling=sum(
                    min(limit, (workers + connections - 1 - i) // connections)
                    for i in range(connections)))


def envoy_config(source, limit, budget):
    if limit not in (4, 100) or budget not in (212992, 4194304):
        raise ValueError("unsupported H3 experiment")
    marker = "max_concurrent_streams: { value: 100 }"
    if source.count(marker) != 2:
        raise ValueError("expected exactly two pinned Envoy stream limits")
    source = source.replace(marker, f"max_concurrent_streams: {{ value: {limit} }}")
    # Linux doubles SO_*BUF requests; kernel defaults are already effective bytes.
    options = ("socket_options:\n"
               f"        - {{ level: 1, name: 8, int_value: {budget // 2}, state: STATE_PREBIND }}\n"
               f"        - {{ level: 1, name: 7, int_value: {budget // 2}, state: STATE_PREBIND }}\n")
    source = source.replace("      udp_listener_config:",
                            "      " + options + "      udp_listener_config:", 1)
    upstream = "      upstream_bind_config:\n        " + options.replace("\n", "\n  ").rstrip() + "\n"
    source = source.replace("      type: STATIC\n", upstream + "      type: STATIC\n", 1)
    return source


if __name__ == "__main__":
    import sys

    command, *args = sys.argv[1:]
    if command == "settings":
        plan = load_experiment(args[0])
        print(plan["socket_buffer_bytes"] if plan["enabled"] else 0)
    elif command == "envoy":
        source, destination, limit, budget = args
        Path(destination).write_text(envoy_config(Path(source).read_text(), int(limit), int(budget)))
    else:
        raise SystemExit("unknown H3 experiment command")
