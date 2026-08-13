#!/usr/bin/env python3
"""Classify dedicated native MeshSubscribe negative probes from correlated evidence.

Client logs alone are not proof. `Connected to CP, subscribing for native mesh
config` is a transient transport-attempt signal: omit-client, foreign-client,
and invalid-JWT probes log it even when the CP has already rejected the
handshake or tenant subscription. Classification therefore consumes:

- client logs (slice delivery, SAN/trust failures, leaked material)
- the running probe pod's Kubernetes identity (name + podIP from the API)
- CP logs, accepting a TLS rejection only for that exact pod IP and a JWT
  rejection only for that exact node_id (the pod name) plus fixed reasons

Generic CP-log greps are rejected: kubelet TCP readiness and other probes can
produce unrelated handshake or tenant-subscription lines.

Rotation reconnect proof (`--rotation-count` / `--rotation-fresh`) counts the
structured CP `Tenant subscription accepted` audit (MeshConfigSync.MeshSubscribe,
result=success, exact node_id) and the client Connected-to-CP marker with that
same node_id. A later observation is fresh only when both counts strictly
exceed the pre-swap baseline. Reload and reconnect-attempt logs are ignored.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from pathlib import Path
from typing import Any

DNS1123_LABEL = re.compile(r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$")

SLICE_MARKER = "Mesh global plugin chain prepared from initial mesh slice"
CONNECTED_MARKER = "Connected to CP, subscribing for native mesh config"
CP_TLS_MESSAGE = "CP gRPC TLS handshake failed"
CP_JWT_MESSAGE = "Tenant subscription rejected"
CP_JWT_REASON = "Invalid token: authentication failed"
CP_JWT_SURFACE = "MeshConfigSync.MeshSubscribe"
# Structured CP success audit from MeshGrpcServer::mesh_subscribe after a
# valid-JWT MeshSubscribe is admitted (CpGrpcServer::audit_tenant_subscription
# with result="success"). Distinct from the client Connected-to-CP marker,
# which is only a post-TLS, pre-RPC transport signal.
CP_SUBSCRIBE_ACCEPTED_MESSAGE = "Tenant subscription accepted"
CP_SUBSCRIBE_ACCEPTED_RESULT = "success"
CP_SUBSCRIBE_AUDIT_EVENT = "tenant_subscription"
LEAKED_MATERIAL = re.compile(
    r"BEGIN ([A-Z0-9 ]*CERTIFICATE|PRIVATE KEY|RSA PRIVATE KEY|EC PRIVATE KEY)"
)

TLS_HANDSHAKE_REASONS = frozenset({"peer sent no certificates"})
TLS_VERIFY_REASONS = frozenset({"invalid peer certificate: UnknownIssuer"})
TLS_REASONS = TLS_HANDSHAKE_REASONS | TLS_VERIFY_REASONS

# Closed-set structured field emitted by the native MeshSubscribe client when
# the observing verifier saw CA verification fail vs hostname/SAN failure.
NATIVE_TLS_CLASS_FIELD = "native_tls_class"
NATIVE_TLS_CLASS_VERIFY = "client_tls_verify"
NATIVE_TLS_CLASS_NAME = "client_tls_name"

# Per-control evidence labels the live fixture must pin (not broad TLS classes).
CONTROL_EVIDENCE = {
    "omit-client": (
        "tls-handshake",
        "cp_tls_rejected ip=",
        "reason=peer sent no certificates",
    ),
    "foreign-client": (
        "tls-verify",
        "cp_tls_rejected ip=",
        "reason=invalid peer certificate: UnknownIssuer",
    ),
    "untrusted-server-ca": ("tls-verify", "client_tls_verify"),
    "wrong-san": ("tls-name", "client_tls_name"),
    "invalid-jwt": (
        "jwt",
        "cp_jwt_rejected node_id=",
        CP_JWT_REASON,
    ),
    "stale-client": (
        "tls-verify",
        "cp_tls_rejected ip=",
        "reason=invalid peer certificate: UnknownIssuer",
    ),
}

# Rotation reconnect proof: both halves plus a strictly increased post-swap
# count. Reload / reconnect-attempt logs are not accepted evidence.
ROTATION_ACCEPTED_EVIDENCE = {
    "cp_subscribe_accepted": (
        CP_SUBSCRIBE_ACCEPTED_MESSAGE,
        CP_JWT_SURFACE,
        CP_SUBSCRIBE_ACCEPTED_RESULT,
        CP_SUBSCRIBE_AUDIT_EVENT,
    ),
    "client_tls_connect": (CONNECTED_MARKER, "node_id"),
}

FIELD_TERMINATORS = frozenset(' ",}\n\r\t')


def is_dns1123_label(value: str) -> bool:
    return bool(value) and DNS1123_LABEL.fullmatch(value) is not None


def is_pod_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def exact_field_equals(line: str, field: str, value: str) -> bool:
    """True when `field` is bound to `value` as a closed token, not a prefix.

    `remote_addr=10.244.0.1` must not match `remote_addr=10.244.0.14`. Value is
    compared as a literal; it is never compiled as a regex.
    """
    if not field or not value:
        return False
    needles = (
        f'"{field}":"{value}"',
        f'"{field}": "{value}"',
        f"{field}={value}",
        f"{field} = {value}",
    )
    for needle in needles:
        start = 0
        while True:
            idx = line.find(needle, start)
            if idx < 0:
                break
            end = idx + len(needle)
            if end == len(line) or line[end] in FIELD_TERMINATORS:
                return True
            start = idx + 1
    return False


def json_fields(line: str) -> dict[str, str] | None:
    try:
        doc = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(doc, dict):
        return None
    out: dict[str, str] = {}

    def take(node: Any) -> None:
        if not isinstance(node, dict):
            return
        for key, raw in node.items():
            if key == "fields" and isinstance(raw, dict):
                take(raw)
                continue
            if isinstance(raw, (str, int)):
                out[str(key)] = str(raw)

    take(doc)
    return out


def _tls_class_for_reason(reason: str) -> str | None:
    if reason in TLS_HANDSHAKE_REASONS:
        return "tls-handshake"
    if reason in TLS_VERIFY_REASONS:
        return "tls-verify"
    return None


def cp_tls_rejection_for_pod(cp_logs: str, pod_ip: str) -> tuple[str, str] | None:
    """Return (class, reason) for a CP TLS rejection of this exact pod IP."""
    if not is_pod_ip(pod_ip):
        return None
    for line in cp_logs.splitlines():
        fields = json_fields(line)
        if fields is not None:
            if fields.get("message") != CP_TLS_MESSAGE:
                continue
            if fields.get("remote_addr") != pod_ip:
                continue
            reason = fields.get("error", "")
            cls = _tls_class_for_reason(reason)
            if cls is not None:
                return cls, reason
            continue
        if not exact_field_equals(line, "remote_addr", pod_ip):
            continue
        if CP_TLS_MESSAGE not in line:
            continue
        for reason in TLS_REASONS:
            if reason in line:
                cls = _tls_class_for_reason(reason)
                if cls is not None:
                    return cls, reason
    return None


def cp_jwt_rejection_for_node(cp_logs: str, node_id: str) -> bool:
    """True only for a tenant-subscription reject of this exact node_id."""
    if not is_dns1123_label(node_id):
        return False
    for line in cp_logs.splitlines():
        fields = json_fields(line)
        if fields is not None:
            if fields.get("message") != CP_JWT_MESSAGE:
                continue
            if fields.get("node_id") != node_id:
                continue
            if fields.get("reason") != CP_JWT_REASON:
                continue
            if fields.get("surface") != CP_JWT_SURFACE:
                continue
            return True
        if not exact_field_equals(line, "node_id", node_id):
            continue
        if CP_JWT_MESSAGE not in line:
            continue
        if CP_JWT_REASON not in line:
            continue
        if CP_JWT_SURFACE not in line:
            continue
        return True
    return False


def _compact_audit_event_equals(line: str, value: str) -> bool:
    return exact_field_equals(line, "audit.event", value)


def cp_subscribe_accepted_count(cp_logs: str, node_id: str) -> int:
    """Count CP MeshSubscribe accepts for this exact node_id.

    Requires the structured tenant_subscription success audit bound to
    MeshConfigSync.MeshSubscribe. Rejects JWT failures, other surfaces, and
    prefix-overlapping node ids.
    """
    if not is_dns1123_label(node_id):
        return 0
    count = 0
    for line in cp_logs.splitlines():
        fields = json_fields(line)
        if fields is not None:
            if fields.get("message") != CP_SUBSCRIBE_ACCEPTED_MESSAGE:
                continue
            if fields.get("node_id") != node_id:
                continue
            if fields.get("surface") != CP_JWT_SURFACE:
                continue
            if fields.get("result") != CP_SUBSCRIBE_ACCEPTED_RESULT:
                continue
            event = fields.get("audit.event") or fields.get("event")
            if event != CP_SUBSCRIBE_AUDIT_EVENT:
                continue
            count += 1
            continue
        if not exact_field_equals(line, "node_id", node_id):
            continue
        if CP_SUBSCRIBE_ACCEPTED_MESSAGE not in line:
            continue
        if not exact_field_equals(line, "surface", CP_JWT_SURFACE):
            continue
        if not exact_field_equals(line, "result", CP_SUBSCRIBE_ACCEPTED_RESULT):
            continue
        if not _compact_audit_event_equals(line, CP_SUBSCRIBE_AUDIT_EVENT):
            continue
        count += 1
    return count


def client_tls_connected_count(client_logs: str, node_id: str) -> int:
    """Count post-TLS native MeshSubscribe connect markers for this node_id.

    The Connected-to-CP line is emitted after endpoint.connect() succeeds and
    before mesh_subscribe is accepted. It is one half of rotation proof only
    when correlated to the exact pod/node identity.
    """
    if not is_dns1123_label(node_id):
        return 0
    count = 0
    for line in client_logs.splitlines():
        fields = json_fields(line)
        if fields is not None:
            if fields.get("message") != CONNECTED_MARKER:
                continue
            if fields.get("node_id") != node_id:
                continue
            count += 1
            continue
        if CONNECTED_MARKER not in line:
            continue
        if exact_field_equals(line, "node_id", node_id):
            count += 1
    return count


def rotation_observation_counts(
    client_logs: str, cp_logs: str, node_id: str
) -> tuple[int, int]:
    return (
        cp_subscribe_accepted_count(cp_logs, node_id),
        client_tls_connected_count(client_logs, node_id),
    )


def rotation_fresh_evidence(
    client_logs: str,
    cp_logs: str,
    node_id: str,
    baseline_cp: int,
    baseline_client: int,
) -> tuple[bool, str]:
    """True only when both halves strictly increased after the baseline."""
    if not is_dns1123_label(node_id):
        return False, "invalid-node-id"
    if baseline_cp < 0 or baseline_client < 0:
        return False, "invalid-baseline"
    cp_after, client_after = rotation_observation_counts(client_logs, cp_logs, node_id)
    evidence = (
        f"cp_subscribe_accepted node_id={node_id} before={baseline_cp} after={cp_after} "
        f"client_tls_connect before={baseline_client} after={client_after}"
    )
    ok = cp_after > baseline_cp and client_after > baseline_client
    return ok, evidence


def client_has_slice(client_logs: str) -> bool:
    return SLICE_MARKER in client_logs


def client_leaked_material(client_logs: str) -> bool:
    return LEAKED_MATERIAL.search(client_logs) is not None


def client_connected(client_logs: str) -> bool:
    return CONNECTED_MARKER in client_logs


def client_jwt(client_logs: str) -> bool:
    lowered = client_logs.lower()
    return (
        "unauthenticated" in lowered
        or "grpc-status: 16" in lowered
        or "grpc-status:16" in lowered
    )


def client_native_tls_class(client_logs: str) -> str | None:
    """Return the closed-set native MeshSubscribe TLS class from structured logs.

    JSON lines are trusted only via the `native_tls_class` field so an error
    string that happens to mention the label cannot relabel a generic handshake.
    Compact non-JSON lines use literal field equality.
    """
    found: str | None = None
    for line in client_logs.splitlines():
        fields = json_fields(line)
        if fields is not None:
            value = fields.get(NATIVE_TLS_CLASS_FIELD, "")
            if value in {NATIVE_TLS_CLASS_VERIFY, NATIVE_TLS_CLASS_NAME}:
                found = value
            continue
        if exact_field_equals(line, NATIVE_TLS_CLASS_FIELD, NATIVE_TLS_CLASS_NAME):
            found = NATIVE_TLS_CLASS_NAME
            continue
        if exact_field_equals(line, NATIVE_TLS_CLASS_FIELD, NATIVE_TLS_CLASS_VERIFY):
            found = NATIVE_TLS_CLASS_VERIFY
    return found


def client_tls_name(client_logs: str) -> bool:
    lowered = client_logs.lower()
    return (
        "notvalidforname" in lowered
        or "not valid for" in lowered
        or "dnsname" in lowered
        or "hostname mismatch" in lowered
        or "certificate is not valid for" in lowered
    )


def client_tls_verify(client_logs: str) -> bool:
    lowered = client_logs.lower()
    return (
        "unknownissuer" in lowered
        or "unknown issuer" in lowered
        or "certificate verify failed" in lowered
        or "unknownca" in lowered
        or "invalid peer certificate" in lowered
    )


def client_tls_handshake(client_logs: str) -> bool:
    lowered = client_logs.lower()
    return (
        "tls handshake" in lowered
        or "handshake failure" in lowered
        or "certificate required" in lowered
        or "peer did not present" in lowered
        or "bad certificate" in lowered
        or "certificaterequired" in lowered
        or "Native MeshSubscribe connection failed" in client_logs
    )


def classify_native_probe(
    client_logs: str,
    cp_logs: str,
    pod_ip: str,
    pod_name: str,
) -> tuple[str, str]:
    """Return (class, concise redacted server/client evidence).

    Evidence is assembled from closed-set labels plus API-validated identities.
    It never copies raw log bodies, tokens, or PEM. Client-side CA vs SAN proof
    prefers the structured `native_tls_class` field over generic handshake text.
    """
    if client_leaked_material(client_logs):
        return "leaked-material", "client_leaked_material"
    if client_has_slice(client_logs):
        return "slice-accepted", "client_slice_accepted"

    tls_hit = cp_tls_rejection_for_pod(cp_logs, pod_ip)
    if tls_hit is not None:
        cls, reason = tls_hit
        return cls, f"cp_tls_rejected ip={pod_ip} reason={reason}"

    if cp_jwt_rejection_for_node(cp_logs, pod_name):
        return (
            "jwt",
            f"cp_jwt_rejected node_id={pod_name} reason={CP_JWT_REASON}",
        )

    native_tls = client_native_tls_class(client_logs)
    if native_tls == NATIVE_TLS_CLASS_NAME:
        return "tls-name", "client_tls_name"
    if native_tls == NATIVE_TLS_CLASS_VERIFY:
        return "tls-verify", "client_tls_verify"

    if client_jwt(client_logs):
        return "jwt", "client_jwt"
    if client_tls_name(client_logs):
        return "tls-name", "client_tls_name"
    if client_tls_verify(client_logs):
        return "tls-verify", "client_tls_verify"
    if client_tls_handshake(client_logs):
        return "tls-handshake", "client_tls_handshake"
    if client_connected(client_logs):
        return "connected-without-jwt-class", "client_connected_without_class"
    return "noop", "none"


def running_pod_identity(doc: Any, deploy: str) -> tuple[str, str]:
    if not is_dns1123_label(deploy):
        raise ValueError("deploy name is not a Kubernetes DNS-1123 label")
    if not isinstance(doc, dict):
        raise ValueError("pod list is not a JSON object")
    for pod in doc.get("items") or []:
        if not isinstance(pod, dict):
            continue
        meta = pod.get("metadata") or {}
        if not isinstance(meta, dict) or meta.get("deletionTimestamp"):
            continue
        name = meta.get("name") or ""
        if not is_dns1123_label(name):
            continue
        labels = meta.get("labels") or {}
        if not isinstance(labels, dict) or labels.get("app") != deploy:
            continue
        status = pod.get("status") or {}
        if not isinstance(status, dict) or status.get("phase") != "Running":
            continue
        pod_ip = status.get("podIP") or ""
        if not is_pod_ip(pod_ip):
            continue
        for cs in status.get("containerStatuses") or []:
            if not isinstance(cs, dict) or cs.get("name") != "ferrum-edge":
                continue
            if (cs.get("state") or {}).get("running"):
                return name, pod_ip
    raise ValueError("no running ferrum-edge probe pod with a validated identity")


def _json_tls_line(ip: str, reason: str) -> str:
    return json.dumps(
        {
            "timestamp": "2026-08-13T13:12:00Z",
            "level": "DEBUG",
            "target": "ferrum_edge::modes::control_plane",
            "fields": {
                "message": CP_TLS_MESSAGE,
                "remote_addr": ip,
                "error": reason,
            },
        }
    )


def _json_client_connect_fail(tls_class: str | None, error: str) -> str:
    """Hosted-shaped native MeshSubscribe client failure (JSON tracing)."""
    fields: dict[str, str] = {
        "message": "Native MeshSubscribe connection failed",
        "cp_url": "https://ferrum-cp.ferrum.svc.cluster.local:50051",
        "error": error,
    }
    if tls_class is not None:
        fields[NATIVE_TLS_CLASS_FIELD] = tls_class
    return json.dumps(
        {
            "timestamp": "2026-08-13T16:52:06.594260Z",
            "level": "ERROR",
            "target": "ferrum_edge::modes::mesh::config_consumer::native_client",
            "fields": fields,
        }
    )


def _json_jwt_line(node_id: str, reason: str = CP_JWT_REASON) -> str:
    return json.dumps(
        {
            "timestamp": "2026-08-13T13:12:01Z",
            "level": "WARN",
            "target": "ferrum_edge::grpc::cp_server",
            "fields": {
                "message": CP_JWT_MESSAGE,
                "audit.event": "tenant_subscription",
                "surface": CP_JWT_SURFACE,
                "node_id": node_id,
                "namespace": "ferrum",
                "result": "failure",
                "reason": reason,
            },
        }
    )


def _json_subscribe_accepted_line(node_id: str) -> str:
    return json.dumps(
        {
            "timestamp": "2026-08-13T13:12:02Z",
            "level": "INFO",
            "target": "ferrum_edge::grpc::cp_server",
            "fields": {
                "message": CP_SUBSCRIBE_ACCEPTED_MESSAGE,
                "audit.event": CP_SUBSCRIBE_AUDIT_EVENT,
                "surface": CP_JWT_SURFACE,
                "node_id": node_id,
                "namespace": "ferrum",
                "result": CP_SUBSCRIBE_ACCEPTED_RESULT,
            },
        }
    )


def _json_client_connected_line(node_id: str) -> str:
    return json.dumps(
        {
            "timestamp": "2026-08-13T13:12:02Z",
            "level": "INFO",
            "target": "ferrum_edge::modes::mesh::config_consumer::native_client",
            "fields": {
                "message": CONNECTED_MARKER,
                "node_id": node_id,
                "namespace": "ferrum",
                "cp_url": "https://ferrum-cp.ferrum.svc.cluster.local:50051",
            },
        }
    )


def _assert_class(
    client_logs: str,
    cp_logs: str,
    pod_ip: str,
    pod_name: str,
    want_class: str,
    want_evidence_substr: str,
    case: str,
) -> None:
    got, evidence = classify_native_probe(client_logs, cp_logs, pod_ip, pod_name)
    if got != want_class:
        raise AssertionError(f"{case}: class {got!r} != {want_class!r}")
    if want_evidence_substr not in evidence:
        raise AssertionError(
            f"{case}: evidence {evidence!r} missing {want_evidence_substr!r}"
        )


def self_test() -> None:
    omit_ip = "10.244.0.14"
    foreign_ip = "10.244.0.15"
    kubelet_ip = "10.244.0.1"
    jwt_name = "native-jwt-invalid-7875c5c9d7-264bh"
    omit_name = "native-omit-client-6f9c8b7d5c-abcde"
    connected = f"info: {CONNECTED_MARKER}\n"
    failed = "error: Native MeshSubscribe connection failed\n"

    _assert_class(
        connected + failed,
        _json_tls_line(omit_ip, "peer sent no certificates"),
        omit_ip,
        omit_name,
        "tls-handshake",
        f"cp_tls_rejected ip={omit_ip} reason=peer sent no certificates",
        "connected-does-not-override-cp-tls",
    )
    _assert_class(
        connected + failed,
        _json_tls_line(foreign_ip, "invalid peer certificate: UnknownIssuer"),
        foreign_ip,
        "native-foreign-client-5d4c3b2a1e-fghij",
        "tls-verify",
        f"cp_tls_rejected ip={foreign_ip} reason=invalid peer certificate: UnknownIssuer",
        "connected-does-not-override-cp-foreign",
    )
    _assert_class(
        connected,
        _json_jwt_line(jwt_name),
        "10.244.0.16",
        jwt_name,
        "jwt",
        f"cp_jwt_rejected node_id={jwt_name} reason={CP_JWT_REASON}",
        "connected-does-not-override-cp-jwt",
    )

    _assert_class(
        connected,
        "\n".join(
            [
                _json_tls_line(kubelet_ip, "peer sent no certificates"),
                _json_tls_line(foreign_ip, "invalid peer certificate: UnknownIssuer"),
                _json_jwt_line("capp-7b8c9d6f5e-klmno"),
            ]
        ),
        omit_ip,
        omit_name,
        "connected-without-jwt-class",
        "client_connected_without_class",
        "reject-unrelated-cp-ip",
    )
    _assert_class(
        connected,
        "\n".join(
            [
                _json_jwt_line("capp-7b8c9d6f5e-klmno"),
                _json_jwt_line(
                    jwt_name,
                    "The presented credential is not authorized for any namespace "
                    "on this control plane",
                ),
            ]
        ),
        "10.244.0.16",
        jwt_name,
        "connected-without-jwt-class",
        "client_connected_without_class",
        "reject-unrelated-node-id",
    )

    jwt_without_surface = json.loads(_json_jwt_line(jwt_name))
    del jwt_without_surface["fields"]["surface"]
    _assert_class(
        connected,
        json.dumps(jwt_without_surface),
        "10.244.0.16",
        jwt_name,
        "connected-without-jwt-class",
        "client_connected_without_class",
        "reject-jwt-without-meshsubscribe-surface",
    )

    prefix_cp = (
        f'remote_addr=10.244.0.1 error="peer sent no certificates" '
        f'message="{CP_TLS_MESSAGE}"\n'
    )
    _assert_class(
        connected,
        prefix_cp,
        "10.244.0.14",
        omit_name,
        "connected-without-jwt-class",
        "client_connected_without_class",
        "reject-ip-prefix-false-match",
    )

    _assert_class(
        connected + f"info: {SLICE_MARKER}\n",
        _json_tls_line(omit_ip, "peer sent no certificates"),
        omit_ip,
        omit_name,
        "slice-accepted",
        "client_slice_accepted",
        "slice-accepted-overrides-cp-reject",
    )

    _assert_class(
        "warn: invalid peer certificate: UnknownIssuer\n",
        _json_tls_line(omit_ip, "peer sent no certificates"),
        "10.244.0.99",
        "native-untrusted-ca-aaaaaaa-bbbbb",
        "tls-verify",
        "client_tls_verify",
        "untrusted-ca-stays-client-side",
    )
    _assert_class(
        "warn: NotValidForName ferrum-cp-wrong-san.ferrum.svc.cluster.local\n",
        "",
        "10.244.0.98",
        "native-wrong-san-aaaaaaa-bbbbb",
        "tls-name",
        "client_tls_name",
        "wrong-san-stays-client-side",
    )

    flattened = "error trying to connect: connection closed"
    hosted_verify = connected + _json_client_connect_fail(
        NATIVE_TLS_CLASS_VERIFY, flattened
    ) + "\n"
    hosted_name = connected + _json_client_connect_fail(
        NATIVE_TLS_CLASS_NAME, flattened
    ) + "\n"
    hosted_flat = connected + _json_client_connect_fail(None, flattened) + "\n"
    _assert_class(
        hosted_verify,
        "",
        "10.244.0.97",
        "native-untrusted-ca-6fb89f87f5-2ls5k",
        "tls-verify",
        "client_tls_verify",
        "hosted-untrusted-ca-native-tls-class",
    )
    _assert_class(
        hosted_name,
        "",
        "10.244.0.98",
        "native-wrong-san-5c7fd9556f-xf64r",
        "tls-name",
        "client_tls_name",
        "hosted-wrong-san-native-tls-class",
    )
    _assert_class(
        hosted_flat,
        "",
        "10.244.0.97",
        "native-untrusted-ca-6fb89f87f5-2ls5k",
        "tls-handshake",
        "client_tls_handshake",
        "flattened-tonic-error-is-not-client-verify-proof",
    )
    _assert_class(
        hosted_flat,
        "",
        "10.244.0.98",
        "native-wrong-san-5c7fd9556f-xf64r",
        "tls-handshake",
        "client_tls_handshake",
        "flattened-tonic-error-is-not-client-name-proof",
    )
    mentioned = connected + _json_client_connect_fail(
        None, "wanted native_tls_class=client_tls_verify in evidence"
    ) + "\n"
    _assert_class(
        mentioned,
        "",
        "10.244.0.97",
        "native-untrusted-ca-6fb89f87f5-2ls5k",
        "tls-handshake",
        "client_tls_handshake",
        "json-error-text-is-not-native-tls-class",
    )
    _assert_class(
        hosted_verify,
        _json_tls_line(omit_ip, "peer sent no certificates"),
        omit_ip,
        omit_name,
        "tls-handshake",
        f"cp_tls_rejected ip={omit_ip} reason=peer sent no certificates",
        "cp-omit-still-wins-over-client-native-tls-class",
    )
    compact_name = (
        connected
        + f"{NATIVE_TLS_CLASS_FIELD}={NATIVE_TLS_CLASS_NAME} "
        + "Native MeshSubscribe connection failed\n"
    )
    _assert_class(
        compact_name,
        "",
        "10.244.0.98",
        "native-wrong-san-5c7fd9556f-xf64r",
        "tls-name",
        "client_tls_name",
        "compact-native-tls-class-name",
    )

    _assert_class(
        connected + "error: gRPC UNAUTHENTICATED\n",
        "",
        "10.244.0.16",
        jwt_name,
        "jwt",
        "client_jwt",
        "preserve-client-jwt-negative",
    )

    _assert_class(
        connected + failed,
        "",
        omit_ip,
        omit_name,
        "tls-handshake",
        "client_tls_handshake",
        "generic-client-handshake-is-not-cp-omit-proof",
    )
    _assert_class(
        connected + failed,
        "",
        foreign_ip,
        "native-foreign-client-5d4c3b2a1e-fghij",
        "tls-handshake",
        "client_tls_handshake",
        "generic-client-handshake-is-not-cp-foreign-proof",
    )
    _assert_class(
        connected + "error: gRPC UNAUTHENTICATED\n",
        "",
        "10.244.0.16",
        jwt_name,
        "jwt",
        "client_jwt",
        "client-jwt-alone-is-not-cp-meshsubscribe-proof",
    )

    for control, (want_class, *needles) in CONTROL_EVIDENCE.items():
        if want_class not in {"tls-handshake", "tls-verify", "tls-name", "jwt"}:
            raise AssertionError(f"{control}: unexpected class {want_class!r}")
        if not needles:
            raise AssertionError(f"{control}: missing evidence needles")

    compact = (
        f"remote_addr={omit_ip} error=peer sent no certificates "
        f"{CP_TLS_MESSAGE}\n"
    )
    _assert_class(
        connected,
        compact,
        omit_ip,
        omit_name,
        "tls-handshake",
        "cp_tls_rejected",
        "compact-cp-tls-line",
    )

    identity = running_pod_identity(
        {
            "items": [
                {
                    "metadata": {
                        "name": omit_name,
                        "labels": {"app": "native-omit-client"},
                    },
                    "status": {
                        "phase": "Running",
                        "podIP": omit_ip,
                        "containerStatuses": [
                            {
                                "name": "ferrum-edge",
                                "state": {"running": {"startedAt": "2026-08-13T13:00:00Z"}},
                            }
                        ],
                    },
                }
            ]
        },
        "native-omit-client",
    )
    if identity != (omit_name, omit_ip):
        raise AssertionError(f"running identity {identity!r}")

    try:
        running_pod_identity({"items": []}, "native-omit-client")
    except ValueError:
        pass
    else:
        raise AssertionError("empty pod list must fail closed")

    capp_name = "capp-7b8c9d6f5e-klmno"
    other_name = "capp-7b8c9d6f5e-klmnp"
    prefix_name = "capp-7b8c9d6f5e-klmnoextra"
    accepted = _json_subscribe_accepted_line(capp_name)
    connected_json = _json_client_connected_line(capp_name)
    compact_accepted = (
        f"audit.event={CP_SUBSCRIBE_AUDIT_EVENT} surface={CP_JWT_SURFACE} "
        f"node_id={capp_name} namespace=ferrum result={CP_SUBSCRIBE_ACCEPTED_RESULT} "
        f"{CP_SUBSCRIBE_ACCEPTED_MESSAGE}\n"
    )
    compact_connected = f"node_id={capp_name} namespace=ferrum {CONNECTED_MARKER}\n"
    reconnect_attempt = (
        "Mesh gRPC TLS source changed; reconnecting native MeshSubscribe stream\n"
    )
    reload_log = (
        "TLS material sources reloaded; new handshakes/connections will use rotated material\n"
    )

    if cp_subscribe_accepted_count(accepted, capp_name) != 1:
        raise AssertionError("exact-capp-node-id-accepted")
    if cp_subscribe_accepted_count(accepted, other_name) != 0:
        raise AssertionError("exact-capp-node-id-accepted other node")
    if cp_subscribe_accepted_count(accepted, prefix_name) != 0:
        raise AssertionError("prefix-node-id-is-not-accepted-proof")
    if cp_subscribe_accepted_count(_json_jwt_line(capp_name), capp_name) != 0:
        raise AssertionError("jwt-reject-is-not-accepted-proof")
    if cp_subscribe_accepted_count(reconnect_attempt + reload_log, capp_name) != 0:
        raise AssertionError("reconnect-attempt-is-not-accepted-proof")
    if client_tls_connected_count(reconnect_attempt + reload_log, capp_name) != 0:
        raise AssertionError("reload-log-is-not-accepted-proof")
    if client_tls_connected_count(f"info: {CONNECTED_MARKER}\n", capp_name) != 0:
        raise AssertionError("connected-without-node-id-is-not-tls-connect-proof")
    if client_tls_connected_count(connected_json, capp_name) != 1:
        raise AssertionError("connected json node_id")

    missing_surface = json.loads(accepted)
    del missing_surface["fields"]["surface"]
    if cp_subscribe_accepted_count(json.dumps(missing_surface), capp_name) != 0:
        raise AssertionError("accepted-without-meshsubscribe-surface-is-not-proof")

    if cp_subscribe_accepted_count(compact_accepted, capp_name) != 1:
        raise AssertionError("compact-subscribe-accepted-counts")
    if client_tls_connected_count(compact_connected, capp_name) != 1:
        raise AssertionError("compact-client-tls-connect-counts")

    pre_client = connected_json + "\n"
    pre_cp = accepted + "\n"
    ok, evidence = rotation_fresh_evidence(pre_client, pre_cp, capp_name, 1, 1)
    if ok:
        raise AssertionError("pre-rotation-count-is-not-post-proof")
    if "before=1 after=1" not in evidence:
        raise AssertionError(f"freshness evidence missing baseline compare: {evidence!r}")

    post_client = pre_client + _json_client_connected_line(capp_name) + "\n"
    post_cp = pre_cp + _json_subscribe_accepted_line(capp_name) + "\n"
    ok, evidence = rotation_fresh_evidence(post_client, post_cp, capp_name, 1, 1)
    if not ok:
        raise AssertionError(f"post-swap increase must pass: {evidence!r}")
    if "before=1 after=2" not in evidence:
        raise AssertionError(f"post-swap evidence must show increase: {evidence!r}")

    ok, _ = rotation_fresh_evidence(post_client, pre_cp, capp_name, 1, 1)
    if ok:
        raise AssertionError("one-half-increase-is-not-fresh-proof client-only")
    ok, _ = rotation_fresh_evidence(pre_client, post_cp, capp_name, 1, 1)
    if ok:
        raise AssertionError("one-half-increase-is-not-fresh-proof cp-only")

    ok, _ = rotation_fresh_evidence(
        post_client + reconnect_attempt,
        post_cp + reload_log,
        capp_name,
        1,
        1,
    )
    if not ok:
        raise AssertionError("reload lines must not hide a real post-swap increase")

    print("native_probe_classify.py --self-test: ok")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--running-identity", action="store_true")
    parser.add_argument("--classify", action="store_true")
    parser.add_argument("--rotation-count", action="store_true")
    parser.add_argument("--rotation-fresh", action="store_true")
    parser.add_argument("--deploy")
    parser.add_argument("--pod-name", default="")
    parser.add_argument("--pod-ip", default="")
    parser.add_argument("--client-log")
    parser.add_argument("--cp-log")
    parser.add_argument("--evidence-out")
    parser.add_argument("--baseline-cp", type=int)
    parser.add_argument("--baseline-client", type=int)
    args = parser.parse_args(argv)

    if args.self_test:
        self_test()
        return 0

    if args.running_identity:
        if not args.deploy:
            parser.error("--deploy is required with --running-identity")
        try:
            doc = json.load(sys.stdin)
            name, pod_ip = running_pod_identity(doc, args.deploy)
        except (ValueError, json.JSONDecodeError) as err:
            print(f"native probe identity: {err}", file=sys.stderr)
            return 1
        sys.stdout.write(f"{name}\t{pod_ip}\n")
        return 0

    if args.classify:
        if not args.client_log or not args.cp_log:
            parser.error("--client-log and --cp-log are required with --classify")
        client_logs = Path(args.client_log).read_text(encoding="utf-8", errors="replace")
        cp_logs = Path(args.cp_log).read_text(encoding="utf-8", errors="replace")
        cls, evidence = classify_native_probe(
            client_logs, cp_logs, args.pod_ip, args.pod_name
        )
        if args.evidence_out:
            Path(args.evidence_out).write_text(evidence + "\n", encoding="utf-8")
        sys.stdout.write(cls)
        return 0

    if args.rotation_count or args.rotation_fresh:
        if not args.client_log or not args.cp_log:
            parser.error("--client-log and --cp-log are required with rotation modes")
        if not is_dns1123_label(args.pod_name):
            print("native rotation identity: pod-name is not a DNS-1123 label", file=sys.stderr)
            return 1
        client_logs = Path(args.client_log).read_text(encoding="utf-8", errors="replace")
        cp_logs = Path(args.cp_log).read_text(encoding="utf-8", errors="replace")
        if args.rotation_count:
            cp_count, client_count = rotation_observation_counts(
                client_logs, cp_logs, args.pod_name
            )
            sys.stdout.write(f"{cp_count}\t{client_count}\n")
            return 0
        if args.baseline_cp is None or args.baseline_client is None:
            parser.error("--baseline-cp and --baseline-client are required with --rotation-fresh")
        ok, evidence = rotation_fresh_evidence(
            client_logs,
            cp_logs,
            args.pod_name,
            args.baseline_cp,
            args.baseline_client,
        )
        if args.evidence_out:
            Path(args.evidence_out).write_text(evidence + "\n", encoding="utf-8")
        sys.stdout.write(evidence)
        return 0 if ok else 1

    parser.error(
        "one of --self-test, --running-identity, --classify, "
        "--rotation-count, or --rotation-fresh is required"
    )
    return 2


if __name__ == "__main__":
    sys.exit(main())
