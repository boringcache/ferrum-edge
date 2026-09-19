"""Data-only campaign validation, calibration and process/cookie role joins."""
import json
import math
import statistics
import struct
import socket
from pathlib import Path

ARMS = ["direct", "ferrum", "envoy", "envoy-limit-4"]
PAYLOADS = [10240, 71680, 512000, 1048576, 5242880]
ENVOY = "docker.io/envoyproxy/envoy@sha256:79c4e987d386b176721638187b511fb4d7041695f7a78e422ed27edd707b3eeb"


def manifest(path):
    value = json.loads(Path(path).read_text())
    expected = dict(campaign="corrected-v1", arms=ARMS, payloads=PAYLOADS,
                    workers=[200, 200, 200, 100, 50], client_connections=[21, 21, 21, 11, 6],
                    measurement_seconds=30, pairs=4, main_samples=80,
                    downstream_stream_limit=100, upstream_stream_limits=[100, 4],
                    socket_buffer_bytes=4194304, envoy_image=ENVOY, pilots_per_arm=2)
    if any(value.get(k) != v for k, v in expected.items()):
        raise ValueError("campaign differs from the approved finite contract")
    if value["calibration"] != dict(useful_rps_tolerance=0.02, p99_tolerance=0.05, confidence=0.95):
        raise ValueError("calibration tolerance changed")
    return value


def config_difference(left, right, path=()):
    if type(left) is not type(right):
        return [(path, left, right)]
    if isinstance(left, dict):
        if left.keys() != right.keys():
            return [(path, left, right)]
        return [diff for key in left for diff in config_difference(left[key], right[key], path + (key,))]
    if isinstance(left, list) and len(left) == len(right):
        return [diff for i, (a, b) in enumerate(zip(left, right)) for diff in config_difference(a, b, path + (i,))]
    return [] if left == right else [(path, left, right)]


def assert_upstream_only(left, right):
    expected = ("static_resources", "clusters", 0, "typed_extension_protocol_options",
                "envoy.extensions.upstreams.http.v3.HttpProtocolOptions", "explicit_http_config",
                "http3_protocol_options", "quic_protocol_options", "max_concurrent_streams", "value")
    differences = config_difference(left, right)
    if differences != [(expected, 100, 4)]:
        raise ValueError("only upstream admission may differ")
    listener = left["static_resources"]["listeners"][0]
    if listener["udp_listener_config"]["quic_options"]["quic_protocol_options"]["max_concurrent_streams"]["value"] != 100:
        raise ValueError("downstream admission changed")
    return differences


def calibration(pairs):
    """Two paired pilots, 95% t interval (df=1). Missing data never passes."""
    result = dict(resolved=False, active_main=False, intervals={}, reason="missing_or_invalid_pilots")
    if len(pairs) != 2 or any(a.get("traffic_issues") or b.get("traffic_issues") or not b.get("observer_ok", False) for a, b in pairs):
        return result
    try:
        for field in ("rps", "p99_us"):
            ratios = [math.log(b[field] / a[field]) for a, b in pairs]
            if not all(math.isfinite(r) for r in ratios):
                return result
            mean = statistics.mean(ratios)
            margin = 12.706204736 * statistics.stdev(ratios) / math.sqrt(2)
            result["intervals"][field] = [math.exp(mean - margin), math.exp(mean + margin)]
        rps, p99 = result["intervals"]["rps"], result["intervals"]["p99_us"]
        passed = rps[0] >= 0.98 and rps[1] <= 1.02 and p99[0] >= 0.95 and p99[1] <= 1.05
        exceeds = rps[1] < 0.98 or rps[0] > 1.02 or p99[0] > 1.05 or p99[1] < 0.95
        result.update(resolved=passed or exceeds, active_main=passed,
                      reason="within_tolerance" if passed else "exceeds_tolerance" if exceeds else "unresolved_uncertainty")
    except (KeyError, ValueError, TypeError, ZeroDivisionError, OverflowError):
        pass
    return result


def ipv4(value):
    return socket.inet_ntop(socket.AF_INET, struct.pack("=I", value))


def owned_role(event, owners, bound, backend_peers, frontend=("127.0.0.1", 8443)):
    """Full endpoint + known process generation, never a port-only inference."""
    owner = next((o for o in owners if o["pid"] == event["pid"] and o["cgroup_id"] == event["cgroup"]
                  and abs(o["start_ticks"] / o["ticks"] - event["process_start_ns"] / 1e9) <= 1 / o["ticks"]), None)
    if not owner or event["family"] != 2 or not event["cookie"]:
        return None
    local = (ipv4(event["local_ipv4"]), event["local_port"])
    peer = (ipv4(event["peer_ipv4"]), event["peer_port"])
    role = owner["role"]
    if role == "backend" and local == ("127.0.0.1", 3445):
        return "backend"
    if role == "client" and peer in (("127.0.0.1", 3445), ("127.0.0.1", 8443)):
        return "client"
    if role == "gateway":
        if (event["cookie"], local) in bound and local == frontend:
            return "gateway_frontend"
        # Quinn's unconnected send destination plus backend's actual connection peer.
        if peer == ("127.0.0.1", 3445) and ("127.0.0.1", local[1]) in backend_peers:
            return "gateway_upstream"
    return None


def group_history(events):
    """Observed membership operations only; never infer a group from equal ports."""
    membership, generations, history, gaps = {}, {}, [], []
    for e in sorted(events, key=lambda row: row['at_ns']):
        kind, cookie = e['kind'], e.get('cookie', 0)
        if e.get('result') != 0 or not cookie:
            continue
        if kind == 23:  # successful allocation can also mean an existing group
            if cookie not in membership:
                membership[cookie] = f"observed-{cookie}-{e['at_ns']}"
        elif kind == 24:
            peer = e.get('peer_cookie')
            if peer not in membership:
                gaps.append(dict(at_ns=e['at_ns'], reason='missing_peer_group', cookie=cookie))
                continue
            membership[cookie] = membership[peer]
        elif kind == 25:
            membership.pop(cookie, None)
        elif (kind == 14 and e.get('attachment_generation', 0)) or kind == 26:
            group = membership.get(cookie)
            if group is None:
                gaps.append(dict(at_ns=e['at_ns'], reason='attachment_without_group_history', cookie=cookie))
                continue
            generations[group] = generations.get(group, 0) + 1
            history.append(dict(at_ns=e['at_ns'], group=group, generation=generations[group],
                                kind=kind, cookie=cookie,
                                members=sorted(k for k, v in membership.items() if v == group),
                                instruction_digest_fnv1a64=e.get('instruction_digest_fnv1a64') if e.get('digest_valid') else None,
                                digest_is_cryptographic=False))
    return dict(history=history, gaps=gaps, complete=False,
                reason='site_readiness_and_event_loss_must_also_be_assessed')


def socket_lifetimes(events, boot, namespace_lifetime):
    records = {}
    for e in sorted(events, key=lambda row: row['at_ns']):
        cookie = e.get('cookie', 0)
        if not cookie or e['kind'] not in (18, 19, 20, 21): continue
        record = records.setdefault(cookie, dict(boot=boot, namespace_lifetime=namespace_lifetime,
            cookie=cookie, birth_ns=None, first_observed_ns=e['at_ns'], retirement_ns=None,
            final_drops=None, final_so_rcvbuf=None, final_so_sndbuf=None))
        if e['kind'] == 18:
            record['birth_ns'] = e['at_ns']
        elif e['kind'] == 20:
            record.update(retirement_ns=e['at_ns'], final_drops=e['drops'],
                          final_so_rcvbuf=e['so_rcvbuf'], final_so_sndbuf=e['so_sndbuf'])
    return list(records.values())
