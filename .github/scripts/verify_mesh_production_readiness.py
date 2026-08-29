#!/usr/bin/env python3
"""Hosted CI checks for ferrum-mesh production-readiness (#4266, #4267, #4288).

Process launches (`helm template`) stay in `.github/workflows/ci.yml`. This
script only parses captured renders and expected-failure stderr.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

SERVING = (
    ("ferrum-mesh-control-plane", "Deployment"),
    ("ferrum-mesh-ca", "Deployment"),
    ("ferrum-mesh-east-west", "Deployment"),
    ("ferrum-mesh-ambient", "DaemonSet"),
)

RESTRICTED = (
    "ferrum-mesh-control-plane",
    "ferrum-mesh-ca",
    "ferrum-mesh-east-west",
)


def fail(title: str, detail: str) -> None:
    print(f"::error title={title}::{detail}")
    raise SystemExit(1)


def require_capture(results_dir: Path, relative: str) -> Path:
    path = results_dir / relative
    if not path.is_file():
        fail(
            "Missing mesh production-readiness capture",
            f"workflow must write {relative} under {results_dir} before this script",
        )
    return path


def split_documents(rendered: str) -> list[str]:
    return [doc for doc in re.split(r"(?m)^---\s*$", rendered) if doc.strip()]


def resource_document(rendered: str, name: str, kind: str) -> str:
    for doc in split_documents(rendered):
        if not re.search(rf"(?m)^kind:\s*{re.escape(kind)}\s*$", doc):
            continue
        if re.search(rf"(?m)^  name:\s*{re.escape(name)}\s*$", doc):
            return doc
    fail(
        "Mesh workload missing from render",
        f"{kind}/{name} must appear in the captured Helm render",
    )
    raise AssertionError("unreachable")


def require_text(doc: str, needle: str, title: str, detail: str) -> None:
    if needle not in doc:
        fail(title, detail)


def forbid_text(doc: str, needle: str, title: str, detail: str) -> None:
    if needle in doc:
        fail(title, detail)


def env_value(doc: str, name: str) -> str | None:
    match = re.search(
        rf"(?m)^\s+- name:\s*{re.escape(name)}\s*\n\s+value:\s*(\S+)",
        doc,
    )
    if match is None:
        return None
    return match.group(1).strip().strip('"').strip("'")


def validate_serving_podspecs(results_dir: Path) -> None:
    rendered = require_capture(results_dir, "mesh-probes-default.yaml").read_text(
        encoding="utf-8"
    )
    for name, kind in SERVING:
        doc = resource_document(rendered, name, kind)
        if not re.search(r"(?m)^\s+terminationGracePeriodSeconds:\s*110\s*$", doc):
            fail(
                "Serving grace period missing",
                f"{name} must render terminationGracePeriodSeconds: 110 "
                "(preStop 30 + full 78s post-SIGTERM budget, plus headroom)",
            )
        require_text(
            doc,
            "preStop:",
            "Serving preStop missing",
            f"{name} must render lifecycle.preStop (SleepAction) by default",
        )
        prestop = re.search(
            r"(?ms)^\s+preStop:\s*\n(?:\s+.*\n){0,6}",
            doc,
        )
        if prestop is None or "sleep:" not in prestop.group(0):
            fail(
                "preStop is not a SleepAction",
                f"{name}: distroless has no shell; preStop must use sleep",
            )
        if not re.search(r"seconds:\s*30", prestop.group(0)):
            fail(
                "preStop seconds missing",
                f"{name} must render shutdownPreStopSeconds (30)",
            )
        drain = env_value(doc, "FERRUM_SHUTDOWN_DRAIN_SECONDS")
        if drain != "30":
            fail(
                "Drain env missing",
                f"{name} must render FERRUM_SHUTDOWN_DRAIN_SECONDS=30, got {drain!r}",
            )
        if env_value(doc, "FERRUM_SHUTDOWN_PREDRAIN_SECONDS") != "0":
            fail(
                "Pre-drain env missing",
                f"{name} must render FERRUM_SHUTDOWN_PREDRAIN_SECONDS=0 by default",
            )
        if not re.search(r"(?m)^\s+cpu:\s*\S+", doc) or not re.search(
            r"(?m)^\s+memory:\s*\S+", doc
        ):
            fail(
                "Serving resources missing",
                f"{name} must render non-empty resources.requests.cpu and memory",
            )
        require_text(
            doc,
            "drop:",
            "capabilities.drop missing",
            f"{name} must drop ALL capabilities first",
        )
        require_text(
            doc,
            "- ALL",
            "capabilities.drop ALL missing",
            f"{name} must drop ALL capabilities",
        )
        if not re.search(r"(?m)^\s+failureThreshold:\s*3\s*$", doc):
            fail(
                "Readiness failureThreshold implicit",
                f"{name} must render readiness failureThreshold: 3 (endpoint-removal budget)",
            )

    for name in RESTRICTED:
        doc = resource_document(rendered, name, "Deployment")
        require_text(
            doc,
            "runAsNonRoot: true",
            "Restricted runAsNonRoot missing",
            f"{name} must run as non-root for PodSecurity restricted",
        )
        require_text(
            doc,
            "runAsUser: 65532",
            "Restricted runAsUser missing",
            f"{name} must use distroless nonroot uid 65532",
        )
        require_text(
            doc,
            "allowPrivilegeEscalation: false",
            "Restricted allowPrivilegeEscalation missing",
            f"{name} must set allowPrivilegeEscalation: false",
        )
        require_text(
            doc,
            "readOnlyRootFilesystem: true",
            "Restricted readOnlyRootFilesystem missing",
            f"{name} must set readOnlyRootFilesystem: true",
        )
        require_text(
            doc,
            "type: RuntimeDefault",
            "Restricted seccomp missing",
            f"{name} must set seccompProfile.type: RuntimeDefault",
        )
        forbid_text(
            doc,
            "priorityClassName:",
            "Deployment node-critical default",
            f"{name} must omit priorityClassName by default (empty string)",
        )
        forbid_text(
            doc,
            "NET_ADMIN",
            "Restricted cap regression",
            f"{name} must not add NET_ADMIN",
        )

    ambient = resource_document(rendered, "ferrum-mesh-ambient", "DaemonSet")
    require_text(
        ambient,
        "- NET_ADMIN",
        "Ambient NET_ADMIN missing",
        "ambient must retain NET_ADMIN for datapath capture",
    )
    require_text(
        ambient,
        "priorityClassName: system-node-critical",
        "Ambient priorityClass missing",
        "ambient must default to system-node-critical",
    )
    require_text(
        ambient,
        "hostNetwork: true",
        "Ambient hostNetwork missing",
        "ambient must keep hostNetwork",
    )

    node_agent = resource_document(rendered, "ferrum-mesh-node-agent", "DaemonSet")
    require_text(
        node_agent,
        "priorityClassName: system-node-critical",
        "Node-agent priorityClass missing",
        "nodeAgent must default to system-node-critical",
    )
    forbid_text(
        node_agent,
        "FERRUM_SHUTDOWN_DRAIN_SECONDS",
        "Node-agent serving drain",
        "node-agent is not a serving mode and must not receive the drain contract",
    )
    forbid_text(
        node_agent,
        "preStop:",
        "Node-agent preStop",
        "node-agent must not render serving preStop",
    )

    injector = resource_document(rendered, "ferrum-mesh-injector", "Deployment")
    forbid_text(
        injector,
        "FERRUM_SHUTDOWN_DRAIN_SECONDS",
        "Injector serving drain",
        "injector is a webhook, not a Ferrum serving mode; do not apply drain env",
    )
    forbid_text(
        injector,
        "preStop:",
        "Injector preStop",
        "injector must not render the serving SleepAction drain contract",
    )
    print("mesh serving podspecs ok")


def validate_cni_no_drain(results_dir: Path) -> None:
    hook = require_capture(results_dir, "cni-uninstall-hook.yaml").read_text(
        encoding="utf-8"
    )
    forbid_text(
        hook,
        "FERRUM_SHUTDOWN_DRAIN_SECONDS",
        "CNI hook serving drain",
        "one-shot CNI uninstall hooks must not receive the serving drain contract",
    )
    forbid_text(
        hook,
        "preStop:",
        "CNI hook preStop",
        "one-shot CNI uninstall hooks must not render serving preStop",
    )
    print("mesh cni hook no serving drain ok")


def validate_refusals(results_dir: Path) -> None:
    low = require_capture(results_dir, "mesh-prod-low-grace.err").read_text(
        encoding="utf-8"
    )
    if "terminationGracePeriodSeconds" not in low or "preStop 30s" not in low:
        fail(
            "Low grace refusal missing",
            "under-budget terminationGracePeriodSeconds must fail with the additive preStop budget",
        )
    kube = require_capture(results_dir, "mesh-prod-kube-1.28.err").read_text(
        encoding="utf-8"
    )
    if "SleepAction" not in kube or "1.29" not in kube:
        fail(
            "Old Kubernetes SleepAction guard missing",
            "--kube-version 1.28.0 must refuse SleepAction and tell operators to set shutdownPreStopSeconds=0 and raise shutdownPreDrainSeconds",
        )
    if "shutdownPreStopSeconds=0" not in kube or "shutdownPreDrainSeconds" not in kube:
        fail(
            "SleepAction remediation missing",
            "the <1.29 guard must name shutdownPreStopSeconds=0 and shutdownPreDrainSeconds",
        )
    empty = require_capture(results_dir, "mesh-prod-empty-resources.err").read_text(
        encoding="utf-8"
    )
    if "resources.requests.cpu" not in empty or "BestEffort" not in empty:
        fail(
            "Empty resources refusal missing",
            "empty serving requests.cpu/memory must fail closed (BestEffort QoS)",
        )
    print("mesh shutdown/resource refusals ok")


def validate_zero_drain(results_dir: Path) -> None:
    rendered = require_capture(results_dir, "mesh-prod-zero-drain.yaml").read_text(
        encoding="utf-8"
    )
    doc = resource_document(rendered, "ferrum-mesh-control-plane", "Deployment")
    if env_value(doc, "FERRUM_SHUTDOWN_DRAIN_SECONDS") != "0":
        fail(
            "Zero drain dropped",
            "shutdownDrainSeconds=0 must render FERRUM_SHUTDOWN_DRAIN_SECONDS=0",
        )
    forbid_text(
        doc,
        "preStop:",
        "preStop rendered at zero",
        "shutdownPreStopSeconds=0 must omit lifecycle.preStop entirely",
    )
    print("mesh zero-drain render ok")


def validate_optional_crds_off(results_dir: Path) -> None:
    rendered = require_capture(results_dir, "default-rendered.yaml").read_text(
        encoding="utf-8"
    )
    for kind in ("ServiceMonitor", "PodMonitor", "PrometheusRule"):
        if re.search(rf"(?m)^kind:\s*{re.escape(kind)}\s*$", rendered):
            fail(
                "Optional observability CRD rendered",
                f"{kind} must stay gated on observability.enabled (default false)",
            )
    if "FERRUM_METRICS_ALLOWED_CIDRS" in rendered or "FERRUM_METRICS_BEARER_TOKEN" in rendered:
        fail(
            "Metrics env rendered while observability is off",
            "FERRUM_METRICS_* must render only when observability.enabled=true",
        )
    print("mesh optional CRDs gated ok")


def validate_observability(results_dir: Path) -> None:
    no_cred = require_capture(results_dir, "mesh-prod-obs-no-cred.err").read_text(
        encoding="utf-8"
    )
    if "scrape credential" not in no_cred:
        fail(
            "Missing-credential refusal missing",
            "observability.alerts/monitors without bearer or allowedCidrs must fail closed",
        )
    inline = require_capture(results_dir, "mesh-prod-obs-inline-bearer.err").read_text(
        encoding="utf-8"
    )
    if "existingSecret.name" not in inline or "inline" not in inline.lower():
        fail(
            "Inline bearer monitor refusal missing",
            "ServiceMonitor without allowedCidrs requires bearerToken.existingSecret.name",
        )
    rendered = require_capture(results_dir, "mesh-prod-obs.yaml").read_text(
        encoding="utf-8"
    )
    sm = resource_document(rendered, "ferrum-mesh-metrics", "ServiceMonitor")
    require_text(
        sm,
        "app.kubernetes.io/component: mesh-metrics",
        "ServiceMonitor selector missing",
        "ServiceMonitor must select mesh-metrics Services",
    )
    require_text(
        sm,
        "port: admin-http",
        "ServiceMonitor port missing",
        "ServiceMonitor must scrape named port admin-http",
    )
    require_text(
        sm,
        "path: /metrics",
        "ServiceMonitor path missing",
        "ServiceMonitor must scrape /metrics",
    )
    for svc_name in (
        "ferrum-mesh-control-plane-metrics",
        "ferrum-mesh-ca-metrics",
        "ferrum-mesh-east-west-metrics",
    ):
        svc = resource_document(rendered, svc_name, "Service")
        require_text(
            svc,
            "targetPort: admin-http",
            "Metrics Service port missing",
            f"{svc_name} must target container port admin-http",
        )
        require_text(
            svc,
            "app.kubernetes.io/component: mesh-metrics",
            "Metrics Service label missing",
            f"{svc_name} must carry mesh-metrics for ServiceMonitor selection",
        )
    cp_svc = resource_document(rendered, "ferrum-mesh-control-plane", "Service")
    forbid_text(
        cp_svc,
        "admin-http",
        "Admin published on CP Service",
        "control-plane Service must stay gRPC-only; scrape via the dedicated metrics Service",
    )
    ew_svc = resource_document(rendered, "ferrum-mesh-east-west", "Service")
    forbid_text(
        ew_svc,
        "admin-http",
        "Admin published on east-west Service",
        "east-west Service must stay tls-passthru only; scrape via the dedicated metrics Service",
    )
    ambient_pm = resource_document(
        rendered, "ferrum-mesh-ambient-metrics", "PodMonitor"
    )
    require_text(
        ambient_pm,
        "app.kubernetes.io/name: ferrum-mesh-ambient",
        "Ambient PodMonitor selector missing",
        "ambient PodMonitor must select ferrum-mesh-ambient pods",
    )
    na_pm = resource_document(
        rendered, "ferrum-mesh-node-agent-metrics", "PodMonitor"
    )
    require_text(
        na_pm,
        "app.kubernetes.io/name: ferrum-mesh-node-agent",
        "Node-agent PodMonitor selector missing",
        "node-agent PodMonitor must select ferrum-mesh-node-agent pods",
    )
    cp = resource_document(rendered, "ferrum-mesh-control-plane", "Deployment")
    if env_value(cp, "FERRUM_METRICS_ALLOWED_CIDRS") is None:
        fail(
            "Metrics CIDR env missing",
            "observability.enabled must render FERRUM_METRICS_ALLOWED_CIDRS on serving pods",
        )
    if "value: " in cp and "change-me" in cp:
        fail(
            "Placeholder metrics token rendered",
            "do not render a default metrics bearer token value",
        )
    rule = resource_document(rendered, "ferrum-mesh-alerts", "PrometheusRule")
    for match in re.finditer(r"(?m)^\s+expr:\s*(.+)$", rule):
        if "absent(" in match.group(1):
            fail(
                "Impossible absent() alert",
                "shipped alert exprs must not use absent() for optional mesh emitters",
            )
    require_text(
        rule,
        "ferrum_mesh_config_last_received_timestamp_seconds",
        "Stale-config alert metric missing",
        "FerrumMeshControlPlaneConfigStale must still reference the freshness timestamp",
    )
    print("mesh observability scrape path ok")


def require_stderr(results_dir: Path, relative: str, needles: tuple[str, ...], title: str) -> None:
    text = require_capture(results_dir, relative).read_text(encoding="utf-8")
    missing = [needle for needle in needles if needle not in text]
    if missing:
        fail(title, f"{relative} must explain the refusal; missing {missing!r}")


def validate_strict_admin_validation(results_dir: Path) -> None:
    """Issue #4267: the mesh chart must reach the runtime's accept/reject line.

    Every capture below renders cleanly under a permissive approximation and
    then either CrashLoops the pod (`CidrSet::parse_strict`, the CP plaintext
    admin guard, `EnvConfig::validate`'s IP-literal bind requirement) or has the
    admin TCP accept loop silently drop the in-pod exec probes.
    """
    require_stderr(
        results_dir,
        "mesh-prod-bad-cidr.err",
        ("controlPlane.admin.allowedCidrs", "not a valid IP address or CIDR"),
        "Malformed admin CIDR refusal missing",
    )
    require_stderr(
        results_dir,
        "mesh-prod-catchall-cidr.err",
        ("permits every address in an IP family", "allowInsecureHttp"),
        "Catch-all admin allowlist refusal missing",
    )
    require_stderr(
        results_dir,
        "mesh-prod-hostname-bind.err",
        ("controlPlane.admin.bindAddress", "IP literal"),
        "Hostname admin bind refusal missing",
    )
    require_stderr(
        results_dir,
        "mesh-prod-probe-family.err",
        ("::1/128", "computed exec probes"),
        "Probe-source family refusal missing",
    )
    require_stderr(
        results_dir,
        "mesh-prod-bad-metrics-cidr.err",
        ("observability.metrics.allowedCidrs", "not a valid IP address or CIDR"),
        "Malformed metrics CIDR refusal missing",
    )
    require_stderr(
        results_dir,
        "mesh-prod-missing-ready-handler.err",
        ("eastWest.probes.readiness", "drain-aware readiness"),
        "Handler-less readiness refusal missing",
    )
    require_stderr(
        results_dir,
        "mesh-prod-ambient-drop.err",
        ("ambient.securityContext.capabilities.drop",),
        "Narrowed ambient capability drop refusal missing",
    )
    require_stderr(
        results_dir,
        "mesh-prod-ambient-unknown-sc.err",
        ("runAsUser",),
        "Unsupported ambient securityContext key refusal missing",
    )
    print("mesh strict admin/metrics validation ok")


def validate_narrow_ipv6_render(results_dir: Path) -> None:
    """A valid narrow IPv6 allowlist, the <1.29 pre-drain remediation, and an
    ambient capability merge must all still render."""
    rendered = require_capture(results_dir, "mesh-prod-narrow-ipv6.yaml").read_text(
        encoding="utf-8"
    )
    cp = resource_document(rendered, "ferrum-mesh-control-plane", "Deployment")
    cidrs = env_value(cp, "FERRUM_ADMIN_ALLOWED_CIDRS")
    if cidrs != "fd00::/8,::1/128":
        fail(
            "Narrow IPv6 allowlist dropped",
            f"controlPlane.admin.allowedCidrs must render verbatim, got {cidrs!r}",
        )
    if env_value(cp, "FERRUM_ADMIN_BIND_ADDRESS") != "::":
        fail(
            "IPv6 wildcard bind dropped",
            "controlPlane.admin.bindAddress=:: must render as a bare IPv6 literal",
        )
    require_text(
        cp,
        '"::1"',
        "IPv6 probe host missing",
        "the computed exec probes must dial ::1 for an IPv6 wildcard bind",
    )
    # Issue #4266: the <1.29 remediation the SleepAction guard recommends must be
    # a real runtime contract. `cp` mode honors FERRUM_SHUTDOWN_PREDRAIN_SECONDS
    # (EnvConfig::effective_shutdown_predrain_seconds), so the chart may budget it.
    if env_value(cp, "FERRUM_SHUTDOWN_PREDRAIN_SECONDS") != "30":
        fail(
            "Pre-drain remediation not rendered",
            "shutdownPreDrainSeconds=30 must render FERRUM_SHUTDOWN_PREDRAIN_SECONDS=30 on the cp-mode control plane",
        )
    forbid_text(
        cp,
        "preStop:",
        "preStop rendered with the pre-drain remediation",
        "shutdownPreStopSeconds=0 must omit lifecycle.preStop entirely",
    )
    ambient = resource_document(rendered, "ferrum-mesh-ambient", "DaemonSet")
    for cap in ("- NET_ADMIN", "- NET_RAW", "- SYS_RESOURCE"):
        require_text(
            ambient,
            cap,
            "Ambient capability merge broken",
            f"ambient.securityContext.capabilities.add must merge on top of the datapath minimum ({cap})",
        )
    require_text(
        ambient,
        "drop:",
        "Ambient capability drop missing",
        "ambient must keep dropping ALL even when extra capabilities are added",
    )
    print("mesh narrow-IPv6 / pre-drain / capability-merge render ok")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--results-dir",
        type=Path,
        required=True,
        help="Directory of helm template captures written by ci.yml",
    )
    args = parser.parse_args()
    results_dir = args.results_dir
    if not results_dir.is_dir():
        fail("Results dir missing", f"{results_dir} is not a directory")
    validate_serving_podspecs(results_dir)
    validate_cni_no_drain(results_dir)
    validate_refusals(results_dir)
    validate_zero_drain(results_dir)
    validate_optional_crds_off(results_dir)
    validate_observability(results_dir)
    validate_strict_admin_validation(results_dir)
    validate_narrow_ipv6_render(results_dir)
    print("mesh production-readiness ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
